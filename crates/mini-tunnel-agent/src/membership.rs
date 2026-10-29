//! Secure local persistence for non-secret network membership settings.

use std::{
    fs,
    io::{self, Read, Write},
    net::Ipv4Addr,
    path::PathBuf,
};

use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

const MEMBERSHIP_SCHEMA_VERSION: u8 = 1;
const MAX_MEMBERSHIP_FILE_SIZE: u64 = 16 * 1024;

#[derive(Debug, Error)]
pub enum MembershipError {
    #[error("no per-user configuration directory is available")]
    NoConfigDirectory,
    #[error("network_id must be a UUID")]
    InvalidNetworkId,
    #[error("device_id must be 32 hexadecimal characters")]
    InvalidDeviceId,
    #[error("membership CIDR is invalid")]
    InvalidCidr,
    #[error("assigned IPv4 address is invalid or outside the network CIDR")]
    InvalidAssignedAddress,
    #[error("membership belongs to a different local device identity")]
    WrongDevice,
    #[error("membership file has unsafe permissions; restrict it to the current user")]
    UnsafePermissions,
    #[error("membership file has an unsupported schema version")]
    UnsupportedVersion,
    #[error("membership file is too large")]
    TooLarge,
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

/// Non-secret configuration returned by the coordinator after a device joins a network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkMembership {
    schema_version: u8,
    pub network_id: String,
    pub device_id: String,
    pub assigned_ipv4: String,
    pub cidr: String,
}

impl NetworkMembership {
    pub fn new(
        network_id: impl Into<String>,
        device_id: impl Into<String>,
        assigned_ipv4: impl Into<String>,
        cidr: impl Into<String>,
    ) -> Result<Self, MembershipError> {
        let membership = Self {
            schema_version: MEMBERSHIP_SCHEMA_VERSION,
            network_id: network_id.into(),
            device_id: device_id.into(),
            assigned_ipv4: assigned_ipv4.into(),
            cidr: cidr.into(),
        };
        membership.validate()?;
        Ok(membership)
    }

    pub fn prefix_len(&self) -> Result<u8, MembershipError> {
        self.validate()?;
        Ok(self
            .cidr
            .parse::<Ipv4Net>()
            .map_err(|_| MembershipError::InvalidCidr)?
            .prefix_len())
    }

    pub fn assigned_ip(&self) -> Result<Ipv4Addr, MembershipError> {
        self.validate()?;
        self.assigned_ipv4
            .parse()
            .map_err(|_| MembershipError::InvalidAssignedAddress)
    }

    fn canonical_network_id(&self) -> Result<String, MembershipError> {
        Uuid::parse_str(&self.network_id)
            .map(|id| id.hyphenated().to_string())
            .map_err(|_| MembershipError::InvalidNetworkId)
    }

    fn validate(&self) -> Result<(), MembershipError> {
        if self.schema_version != MEMBERSHIP_SCHEMA_VERSION {
            return Err(MembershipError::UnsupportedVersion);
        }
        self.canonical_network_id()?;
        if self.device_id.len() != 32
            || !self.device_id.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(MembershipError::InvalidDeviceId);
        }
        let cidr = self
            .cidr
            .parse::<Ipv4Net>()
            .map_err(|_| MembershipError::InvalidCidr)?;
        let assigned = self
            .assigned_ipv4
            .parse::<Ipv4Addr>()
            .map_err(|_| MembershipError::InvalidAssignedAddress)?;
        if !cidr.contains(&assigned) {
            return Err(MembershipError::InvalidAssignedAddress);
        }
        Ok(())
    }
}

/// Stores each network membership in an isolated, versioned JSON file.
#[derive(Debug, Clone)]
pub struct MembershipStore {
    root: PathBuf,
}

impl MembershipStore {
    #[must_use]
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn for_current_user() -> Result<Self, MembershipError> {
        let dirs = directories::ProjectDirs::from("org", "ilovn", "mini-tunnel")
            .ok_or(MembershipError::NoConfigDirectory)?;
        Ok(Self::new(dirs.config_dir().join("networks")))
    }

    pub fn save(&self, membership: &NetworkMembership) -> Result<(), MembershipError> {
        membership.validate()?;
        fs::create_dir_all(&self.root)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&self.root, fs::Permissions::from_mode(0o700))?;
        }

        let network_id = membership.canonical_network_id()?;
        let destination = self.root.join(format!("{network_id}.json"));
        let temporary = self
            .root
            .join(format!(".{network_id}.{}.tmp", Uuid::new_v4()));
        let bytes = serde_json::to_vec(membership)?;
        let result = (|| -> Result<(), MembershipError> {
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&temporary)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            fs::rename(&temporary, &destination)?;
            #[cfg(unix)]
            fs::File::open(&self.root)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(temporary);
        }
        result
    }

    pub fn load(
        &self,
        network_id: &str,
        expected_device_id: &str,
    ) -> Result<NetworkMembership, MembershipError> {
        let canonical_id = Uuid::parse_str(network_id)
            .map(|id| id.hyphenated().to_string())
            .map_err(|_| MembershipError::InvalidNetworkId)?;
        let path = self.root.join(format!("{canonical_id}.json"));
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err(MembershipError::UnsafePermissions);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(MembershipError::UnsafePermissions);
            }
        }
        if metadata.len() > MAX_MEMBERSHIP_FILE_SIZE {
            return Err(MembershipError::TooLarge);
        }
        let file = fs::File::open(path)?;
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.take(MAX_MEMBERSHIP_FILE_SIZE + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_MEMBERSHIP_FILE_SIZE {
            return Err(MembershipError::TooLarge);
        }
        let membership: NetworkMembership = serde_json::from_slice(&bytes)?;
        membership.validate()?;
        if membership.canonical_network_id()? != canonical_id {
            return Err(MembershipError::InvalidNetworkId);
        }
        if membership.device_id != expected_device_id {
            return Err(MembershipError::WrongDevice);
        }
        Ok(membership)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_membership() -> NetworkMembership {
        NetworkMembership::new(
            "3a50e2e2-037f-4e0f-9f5c-a0b23e3cf543",
            "0123456789abcdef0123456789abcdef",
            "10.77.0.2",
            "10.77.0.0/16",
        )
        .expect("valid membership")
    }

    #[test]
    fn membership_is_atomically_saved_and_loaded_with_private_permissions() {
        let root = std::env::temp_dir().join(format!("mini-tunnel-membership-{}", Uuid::new_v4()));
        let store = MembershipStore::new(root.clone());
        let membership = sample_membership();
        store.save(&membership).expect("save membership");
        assert_eq!(
            store
                .load(&membership.network_id, &membership.device_id)
                .expect("load membership"),
            membership
        );
        let stored_json = fs::read_to_string(root.join(format!("{}.json", membership.network_id)))
            .expect("read persisted membership");
        assert!(!stored_json.contains("token"));
        assert!(!stored_json.contains("private_key"));
        assert_eq!(membership.prefix_len().expect("prefix"), 16);
        assert_eq!(
            membership.assigned_ip().expect("assigned IP"),
            Ipv4Addr::new(10, 77, 0, 2)
        );
        let updated = NetworkMembership::new(
            membership.network_id.clone(),
            membership.device_id.clone(),
            "10.77.0.4",
            membership.cidr.clone(),
        )
        .expect("updated membership");
        store.save(&updated).expect("atomically replace membership");
        assert_eq!(
            store
                .load(&updated.network_id, &updated.device_id)
                .expect("load updated membership"),
            updated
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&root).expect("dir").permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(root.join(format!("{}.json", membership.network_id)))
                    .expect("membership file")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        fs::remove_dir_all(root).expect("remove membership directory");
    }

    #[test]
    fn membership_load_rejects_wrong_device_invalid_format_and_unsafe_permissions() {
        let root = std::env::temp_dir().join(format!("mini-tunnel-membership-{}", Uuid::new_v4()));
        let store = MembershipStore::new(root.clone());
        let membership = sample_membership();
        store.save(&membership).expect("save membership");
        assert!(matches!(
            store.load(&membership.network_id, "ffffffffffffffffffffffffffffffff"),
            Err(MembershipError::WrongDevice)
        ));
        assert!(matches!(
            NetworkMembership::new(
                "../escape",
                membership.device_id.clone(),
                "10.77.0.2",
                "10.77.0.0/16"
            ),
            Err(MembershipError::InvalidNetworkId)
        ));
        assert!(matches!(
            NetworkMembership::new(
                membership.network_id.clone(),
                membership.device_id.clone(),
                "10.78.0.2",
                "10.77.0.0/16"
            ),
            Err(MembershipError::InvalidAssignedAddress)
        ));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let path = root.join(format!("{}.json", membership.network_id));
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("unsafe mode");
            assert!(matches!(
                store.load(&membership.network_id, &membership.device_id),
                Err(MembershipError::UnsafePermissions)
            ));
        }
        fs::remove_dir_all(root).expect("remove membership directory");
    }

    #[test]
    fn membership_rejects_unknown_fields_and_future_versions() {
        let root = std::env::temp_dir().join(format!("mini-tunnel-membership-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).expect("create membership directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("private dir");
        }
        let membership = sample_membership();
        let path = root.join(format!("{}.json", membership.network_id));
        let mut bytes = serde_json::to_value(&membership).expect("serialize");
        bytes["schema_version"] = serde_json::json!(99);
        fs::write(&path, serde_json::to_vec(&bytes).expect("encode")).expect("write invalid");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("private file");
        }
        assert!(matches!(
            MembershipStore::new(root.clone()).load(&membership.network_id, &membership.device_id),
            Err(MembershipError::UnsupportedVersion)
        ));
        let mut bytes = serde_json::to_value(&membership).expect("serialize");
        bytes["invite_token"] = serde_json::json!("must-not-be-stored");
        fs::write(&path, serde_json::to_vec(&bytes).expect("encode")).expect("write unknown field");
        assert!(matches!(
            MembershipStore::new(root.clone()).load(&membership.network_id, &membership.device_id),
            Err(MembershipError::Json(_))
        ));
        fs::remove_dir_all(root).expect("remove membership directory");
    }
}
