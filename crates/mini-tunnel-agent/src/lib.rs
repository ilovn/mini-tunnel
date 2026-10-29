//! Local device identity and signing helpers used by the CLI and tunnel agent.

use std::{fs, io, path::PathBuf};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("no per-user configuration directory is available")]
    NoConfigDirectory,
    #[error("identity file has unsafe permissions; restrict it to the current user")]
    UnsafePermissions,
    #[error("identity file must contain exactly 32 bytes")]
    InvalidKey,
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("secure random generation failed")]
    Random,
}

pub struct Identity {
    signing_key: SigningKey,
}

impl Identity {
    /// Load the stable local identity or create it with user-only Unix permissions.
    pub fn load_or_create() -> Result<Self, IdentityError> {
        let dirs = directories::ProjectDirs::from("org", "ilovn", "mini-tunnel")
            .ok_or(IdentityError::NoConfigDirectory)?;
        Self::load_or_create_at(dirs.config_dir().join("device.key"))
    }

    pub fn load_or_create_at(path: PathBuf) -> Result<Self, IdentityError> {
        let parent = path.parent().ok_or(IdentityError::NoConfigDirectory)?;
        fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
            let _ = fs::DirBuilder::new()
                .mode(0o700)
                .recursive(true)
                .create(parent);
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        }
        if path.exists() {
            let metadata = fs::metadata(&path)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if metadata.permissions().mode() & 0o077 != 0 {
                    return Err(IdentityError::UnsafePermissions);
                }
            }
            let bytes = fs::read(path)?;
            let seed: [u8; 32] = bytes.try_into().map_err(|_| IdentityError::InvalidKey)?;
            return Ok(Self {
                signing_key: SigningKey::from_bytes(&seed),
            });
        }
        let mut seed = [0_u8; 32];
        getrandom::fill(&mut seed).map_err(|_| IdentityError::Random)?;
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        use std::io::Write;
        let mut file = match options.open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                let metadata = fs::metadata(&path)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if metadata.permissions().mode() & 0o077 != 0 {
                        return Err(IdentityError::UnsafePermissions);
                    }
                }
                let bytes = fs::read(path)?;
                let seed: [u8; 32] = bytes.try_into().map_err(|_| IdentityError::InvalidKey)?;
                return Ok(Self {
                    signing_key: SigningKey::from_bytes(&seed),
                });
            }
            Err(error) => return Err(error.into()),
        };
        file.write_all(&seed)?;
        file.sync_all()?;
        Ok(Self {
            signing_key: SigningKey::from_bytes(&seed),
        })
    }

    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    #[must_use]
    pub fn device_id(&self) -> String {
        mini_tunnel_protocol::device_id_from_public_key(&self.public_key())
    }

    #[must_use]
    pub fn public_key_encoded(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.public_key())
    }

    #[must_use]
    pub fn sign(&self, message: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(self.signing_key.sign(message).to_bytes())
    }
}

#[must_use]
pub fn default_identity_path() -> Option<PathBuf> {
    directories::ProjectDirs::from("org", "ilovn", "mini-tunnel")
        .map(|dirs| dirs.config_dir().join("device.key"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_is_stable_across_loads_and_private_file_is_created() {
        let dir =
            std::env::temp_dir().join(format!("mini-tunnel-identity-{}", uuid::Uuid::new_v4()));
        let path = dir.join("device.key");
        let first = Identity::load_or_create_at(path.clone()).expect("create identity");
        let id = first.device_id();
        drop(first);
        let second = Identity::load_or_create_at(path.clone()).expect("load identity");
        assert_eq!(id, second.device_id());
        assert_eq!(fs::metadata(&path).expect("key metadata").len(), 32);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path)
                    .expect("key metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        fs::remove_dir_all(dir).expect("remove test directory");
    }

    #[test]
    fn rejects_malformed_identity_file() {
        let dir =
            std::env::temp_dir().join(format!("mini-tunnel-identity-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).expect("create temp directory");
        let path = dir.join("device.key");
        fs::write(&path, b"short").expect("write malformed key");
        assert!(matches!(
            Identity::load_or_create_at(path),
            Err(IdentityError::InvalidKey)
        ));
        fs::remove_dir_all(dir).expect("remove test directory");
    }
}
