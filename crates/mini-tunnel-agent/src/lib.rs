//! Local device identity and signing helpers used by the CLI and tunnel agent.

pub mod membership;
pub mod tun_device;
pub mod tunnel;

use std::{fs, io, net::SocketAddr, path::PathBuf, sync::Mutex, time::Duration};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use quinn::{Connection, Endpoint};
use rcgen::{CertificateParams, PKCS_ED25519};
use rustls::{
    DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
};
use sha2::{Digest, Sha256};
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
    #[error("peer identity does not match the authorized key")]
    UnauthorizedPeer,
    #[error("peer sent an invalid, oversized, or replayed frame")]
    InvalidFrame,
    #[error("peer transport failed: {0}")]
    Transport(String),
}

#[derive(Debug, Error)]
pub enum CandidateConnectError {
    #[error("peer has no advertised candidate addresses")]
    NoCandidates,
    #[error("peer has no usable candidate addresses")]
    NoUsableCandidates,
    #[error("peer advertised more than {MAX_PEER_CANDIDATES} candidate addresses")]
    TooManyCandidates,
    #[error("peer identity did not match the authorized identity")]
    UnauthorizedPeer,
    #[error("all peer candidate addresses were unreachable: {0}")]
    Unreachable(String),
}

pub struct Identity {
    signing_key: SigningKey,
    public_key: [u8; 32],
}

impl Identity {
    fn from_seed(seed: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(seed);
        let public_key = signing_key.verifying_key().to_bytes();
        Self {
            signing_key,
            public_key,
        }
    }

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
            return Ok(Self::from_seed(&seed));
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
                return Ok(Self::from_seed(&seed));
            }
            Err(error) => return Err(error.into()),
        };
        file.write_all(&seed)?;
        file.sync_all()?;
        Ok(Self::from_seed(&seed))
    }

    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        self.public_key
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

    fn pkcs8_seed(&self) -> Vec<u8> {
        // RFC 8410 PKCS#8 wrapper for an Ed25519 32-byte seed.
        let mut der = vec![
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
            0x04, 0x20,
        ];
        der.extend_from_slice(&self.signing_key.to_bytes());
        der
    }
}

struct IdentityCertificateKey<'a>(&'a Identity);

impl rcgen::PublicKeyData for IdentityCertificateKey<'_> {
    fn der_bytes(&self) -> &[u8] {
        &self.0.public_key
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &PKCS_ED25519
    }
}

impl rcgen::SigningKey for IdentityCertificateKey<'_> {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        Ok(self.0.signing_key.sign(message).to_bytes().to_vec())
    }
}

const MAX_PACKET_PAYLOAD: usize = 1175;
const FRAME_HEADER_LEN: usize = 25;
const PEER_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_PEER_CANDIDATES: usize = 8;

/// Authenticated QUIC connection to one authorized peer.
pub struct PeerChannel {
    connection: Connection,
    network_tag: [u8; 16],
    next_packet: Mutex<u64>,
    replay_window: Mutex<ReplayWindow>,
}

impl PeerChannel {
    #[must_use]
    pub fn remote_address(&self) -> SocketAddr {
        self.connection.remote_address()
    }

    /// Send one bounded, unreliable QUIC DATAGRAM.
    pub fn send_packet(&self, payload: &[u8]) -> Result<(), IdentityError> {
        if payload.len() > MAX_PACKET_PAYLOAD {
            return Err(IdentityError::InvalidFrame);
        }
        let mut next_packet = self
            .next_packet
            .lock()
            .map_err(|_| IdentityError::InvalidFrame)?;
        let sequence = *next_packet;
        *next_packet = sequence.checked_add(1).ok_or(IdentityError::InvalidFrame)?;
        drop(next_packet);
        let frame = encode_frame(self.network_tag, sequence, payload);
        if self
            .connection
            .max_datagram_size()
            .is_none_or(|max| frame.len() > max)
        {
            return Err(IdentityError::InvalidFrame);
        }
        self.connection
            .send_datagram(Bytes::from(frame))
            .map_err(|error| IdentityError::Transport(error.to_string()))
    }

    /// Receive one authenticated frame, rejecting malformed, cross-network, and replayed data.
    pub async fn recv_packet(&self) -> Result<Vec<u8>, IdentityError> {
        let frame = self
            .connection
            .read_datagram()
            .await
            .map_err(|error| IdentityError::Transport(error.to_string()))?;
        let (sequence, payload) =
            decode_frame(&frame, self.network_tag).ok_or(IdentityError::InvalidFrame)?;
        if !self
            .replay_window
            .lock()
            .map_err(|_| IdentityError::InvalidFrame)?
            .accept(sequence)
        {
            return Err(IdentityError::InvalidFrame);
        }
        Ok(payload.to_vec())
    }
}

/// Bind one QUIC endpoint. Its TLS certificate is derived from the stable device key.
pub fn peer_endpoint(
    identity: &Identity,
    bind_addr: SocketAddr,
) -> Result<Endpoint, IdentityError> {
    let params = CertificateParams::new(vec!["mini-tunnel".to_owned()])
        .map_err(|error| IdentityError::Transport(error.to_string()))?;
    let certificate = params
        .self_signed(&IdentityCertificateKey(identity))
        .map_err(|error| IdentityError::Transport(error.to_string()))?;
    let certificate_der = CertificateDer::from(certificate.der().to_vec());
    let mut pkcs8 = identity.pkcs8_seed();
    let server_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8.clone()));
    pkcs8.fill(0);
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let mut server_tls = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|error| IdentityError::Transport(error.to_string()))?
        .with_no_client_auth()
        .with_single_cert(vec![certificate_der], server_key)
        .map_err(|error| IdentityError::Transport(error.to_string()))?;
    server_tls.alpn_protocols = vec![b"mini-tunnel-peer/1".to_vec()];
    let server_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(server_tls)
        .map_err(|error| IdentityError::Transport(error.to_string()))?;
    let mut server_config = quinn::ServerConfig::with_crypto(std::sync::Arc::new(server_crypto));
    server_config.transport = std::sync::Arc::new(peer_transport_config());
    let endpoint = Endpoint::server(server_config, bind_addr)
        .map_err(|error| IdentityError::Transport(error.to_string()))?;
    Ok(endpoint)
}

fn peer_client_config(
    expected_key: [u8; 32],
    provider: std::sync::Arc<rustls::crypto::CryptoProvider>,
) -> Result<quinn::ClientConfig, IdentityError> {
    let mut tls = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|error| IdentityError::Transport(error.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(PinnedPeerVerifier {
            provider,
            expected_key,
        }))
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"mini-tunnel-peer/1".to_vec()];
    let mut config = quinn::ClientConfig::new(std::sync::Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls)
            .map_err(|error| IdentityError::Transport(error.to_string()))?,
    ));
    config.transport_config(std::sync::Arc::new(peer_transport_config()));
    Ok(config)
}

fn peer_transport_config() -> quinn::TransportConfig {
    let mut transport = quinn::TransportConfig::default();
    transport.datagram_receive_buffer_size(Some(64 * 1024));
    transport.datagram_send_buffer_size(64 * 1024);
    transport
}

/// Connect to a peer and pin its TLS certificate to the expected Ed25519 identity.
pub async fn connect_peer(
    endpoint: &Endpoint,
    remote_addr: SocketAddr,
    network_id: &str,
    identity: &Identity,
    expected_peer_id: &str,
    expected_peer_key: [u8; 32],
) -> Result<PeerChannel, IdentityError> {
    if expected_peer_id != mini_tunnel_protocol::device_id_from_public_key(&expected_peer_key) {
        return Err(IdentityError::UnauthorizedPeer);
    }
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let config = peer_client_config(expected_peer_key, provider)?;
    let connection = endpoint
        .connect_with(config, remote_addr, "mini-tunnel")
        .map_err(|error| IdentityError::Transport(error.to_string()))?
        .await
        .map_err(|error| IdentityError::Transport(error.to_string()))?;
    verify_connection_identity(&connection, &expected_peer_key)?;
    client_authenticate(&connection, network_id, identity, expected_peer_id).await?;
    Ok(new_channel(connection, network_id))
}

/// Try signed-discovery candidate addresses in order, bounding both attempts and total time.
pub async fn connect_peer_candidates(
    endpoint: &Endpoint,
    candidates: &[String],
    network_id: &str,
    identity: &Identity,
    expected_peer_id: &str,
    expected_peer_key: [u8; 32],
) -> Result<(PeerChannel, SocketAddr), CandidateConnectError> {
    if candidates.is_empty() {
        return Err(CandidateConnectError::NoCandidates);
    }
    if candidates.len() > MAX_PEER_CANDIDATES {
        return Err(CandidateConnectError::TooManyCandidates);
    }
    if expected_peer_id != mini_tunnel_protocol::device_id_from_public_key(&expected_peer_key) {
        return Err(CandidateConnectError::UnauthorizedPeer);
    }

    let mut usable = 0;
    let mut last_error = None;
    for candidate in candidates {
        let Ok(address) = candidate.parse::<SocketAddr>() else {
            continue;
        };
        if address.port() == 0 || address.ip().is_unspecified() {
            continue;
        }
        usable += 1;
        match tokio::time::timeout(
            PEER_HANDSHAKE_TIMEOUT,
            connect_peer(
                endpoint,
                address,
                network_id,
                identity,
                expected_peer_id,
                expected_peer_key,
            ),
        )
        .await
        {
            Ok(Ok(channel)) => return Ok((channel, address)),
            Ok(Err(IdentityError::UnauthorizedPeer)) => {
                return Err(CandidateConnectError::UnauthorizedPeer);
            }
            Ok(Err(error)) => last_error = Some(error.to_string()),
            Err(_) => last_error = Some(format!("connection to {address} timed out")),
        }
    }
    if usable == 0 {
        return Err(CandidateConnectError::NoUsableCandidates);
    }
    Err(CandidateConnectError::Unreachable(
        last_error.unwrap_or_else(|| "no connection attempt completed".to_owned()),
    ))
}

/// Accept exactly one configured peer; its Ed25519 challenge proof is checked before returning.
pub async fn accept_peer(
    endpoint: &Endpoint,
    network_id: &str,
    identity: &Identity,
    expected_peer_id: &str,
    expected_peer_key: [u8; 32],
) -> Result<PeerChannel, IdentityError> {
    if expected_peer_id != mini_tunnel_protocol::device_id_from_public_key(&expected_peer_key) {
        return Err(IdentityError::UnauthorizedPeer);
    }
    let incoming = tokio::time::timeout(PEER_HANDSHAKE_TIMEOUT, endpoint.accept())
        .await
        .map_err(|error| IdentityError::Transport(error.to_string()))?
        .ok_or_else(|| IdentityError::Transport("endpoint closed".to_owned()))?;
    let connection = tokio::time::timeout(PEER_HANDSHAKE_TIMEOUT, incoming)
        .await
        .map_err(|error| IdentityError::Transport(error.to_string()))?
        .map_err(|error| IdentityError::Transport(error.to_string()))?;
    server_authenticate(
        &connection,
        network_id,
        identity,
        expected_peer_id,
        &expected_peer_key,
    )
    .await?;
    Ok(new_channel(connection, network_id))
}

fn new_channel(connection: Connection, network_id: &str) -> PeerChannel {
    let hash = Sha256::digest(network_id.as_bytes());
    let mut network_tag = [0_u8; 16];
    network_tag.copy_from_slice(&hash[..16]);
    PeerChannel {
        connection,
        network_tag,
        next_packet: Mutex::new(0),
        replay_window: Mutex::new(ReplayWindow::default()),
    }
}

fn verify_connection_identity(
    connection: &Connection,
    expected_key: &[u8; 32],
) -> Result<(), IdentityError> {
    let identity = connection
        .peer_identity()
        .ok_or(IdentityError::UnauthorizedPeer)?;
    let certificates = identity
        .downcast::<Vec<CertificateDer<'static>>>()
        .map_err(|_| IdentityError::UnauthorizedPeer)?;
    let certificate = certificates
        .first()
        .ok_or(IdentityError::UnauthorizedPeer)?;
    let (_, parsed) = x509_parser::parse_x509_certificate(certificate.as_ref())
        .map_err(|_| IdentityError::UnauthorizedPeer)?;
    if parsed
        .tbs_certificate
        .subject_pki
        .subject_public_key
        .data
        .as_ref()
        != expected_key
    {
        return Err(IdentityError::UnauthorizedPeer);
    }
    Ok(())
}

#[derive(Debug)]
struct PinnedPeerVerifier {
    provider: std::sync::Arc<rustls::crypto::CryptoProvider>,
    expected_key: [u8; 32],
}

impl ServerCertVerifier for PinnedPeerVerifier {
    fn verify_server_cert(
        &self,
        cert: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let (_, parsed) = x509_parser::parse_x509_certificate(cert.as_ref()).map_err(|_| {
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
        })?;
        let public_key = &parsed.tbs_certificate.subject_pki.subject_public_key.data;
        if public_key.len() != 32 || public_key.as_ref() != self.expected_key {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::BadEncoding,
            ));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

async fn client_authenticate(
    connection: &Connection,
    network_id: &str,
    identity: &Identity,
    server_id: &str,
) -> Result<(), IdentityError> {
    let (mut send, mut recv) = tokio::time::timeout(PEER_HANDSHAKE_TIMEOUT, connection.open_bi())
        .await
        .map_err(|error| IdentityError::Transport(error.to_string()))?
        .map_err(|error| IdentityError::Transport(error.to_string()))?;
    let mut nonce = [0_u8; 32];
    getrandom::fill(&mut nonce).map_err(|_| IdentityError::Random)?;
    // Client sends the nonce first so the server can answer without waiting for a stream read.
    send.write_all(&nonce)
        .await
        .map_err(|error| IdentityError::Transport(error.to_string()))?;
    let mut server_nonce = [0_u8; 32];
    tokio::time::timeout(PEER_HANDSHAKE_TIMEOUT, recv.read_exact(&mut server_nonce))
        .await
        .map_err(|error| IdentityError::Transport(error.to_string()))?
        .map_err(|error| IdentityError::Transport(error.to_string()))?;
    let proof = auth_bytes(
        network_id,
        &identity.device_id(),
        server_id,
        &nonce,
        &server_nonce,
    );
    let signature = URL_SAFE_NO_PAD
        .decode(identity.sign(&proof))
        .map_err(|_| IdentityError::UnauthorizedPeer)?;
    send.write_all(&signature)
        .await
        .map_err(|error| IdentityError::Transport(error.to_string()))?;
    let mut accepted = [0_u8; 1];
    tokio::time::timeout(PEER_HANDSHAKE_TIMEOUT, recv.read_exact(&mut accepted))
        .await
        .map_err(|error| IdentityError::Transport(error.to_string()))?
        .map_err(|error| IdentityError::Transport(error.to_string()))?;
    if accepted[0] != 1 {
        return Err(IdentityError::UnauthorizedPeer);
    }
    Ok(())
}

async fn server_authenticate(
    connection: &Connection,
    network_id: &str,
    identity: &Identity,
    client_id: &str,
    client_key: &[u8; 32],
) -> Result<(), IdentityError> {
    let (mut send, mut recv) = tokio::time::timeout(PEER_HANDSHAKE_TIMEOUT, connection.accept_bi())
        .await
        .map_err(|error| IdentityError::Transport(error.to_string()))?
        .map_err(|error| IdentityError::Transport(error.to_string()))?;
    let mut client_nonce = [0_u8; 32];
    tokio::time::timeout(PEER_HANDSHAKE_TIMEOUT, recv.read_exact(&mut client_nonce))
        .await
        .map_err(|error| IdentityError::Transport(error.to_string()))?
        .map_err(|error| IdentityError::Transport(error.to_string()))?;
    let mut server_nonce = [0_u8; 32];
    getrandom::fill(&mut server_nonce).map_err(|_| IdentityError::Random)?;
    send.write_all(&server_nonce)
        .await
        .map_err(|error| IdentityError::Transport(error.to_string()))?;
    let mut signature = [0_u8; 64];
    tokio::time::timeout(PEER_HANDSHAKE_TIMEOUT, recv.read_exact(&mut signature))
        .await
        .map_err(|error| IdentityError::Transport(error.to_string()))?
        .map_err(|error| IdentityError::Transport(error.to_string()))?;
    let proof = auth_bytes(
        network_id,
        client_id,
        &identity.device_id(),
        &client_nonce,
        &server_nonce,
    );
    let key = VerifyingKey::from_bytes(client_key).map_err(|_| IdentityError::UnauthorizedPeer)?;
    key.verify_strict(&proof, &Signature::from_bytes(&signature))
        .map_err(|_| IdentityError::UnauthorizedPeer)?;
    send.write_all(&[1])
        .await
        .map_err(|error| IdentityError::Transport(error.to_string()))?;
    Ok(())
}

fn auth_bytes(
    network_id: &str,
    client_id: &str,
    server_id: &str,
    client_nonce: &[u8; 32],
    server_nonce: &[u8; 32],
) -> Vec<u8> {
    let mut out = b"mini-tunnel/quic-peer-auth/v1\0".to_vec();
    for part in [
        network_id.as_bytes(),
        client_id.as_bytes(),
        server_id.as_bytes(),
        client_nonce,
        server_nonce,
    ] {
        out.extend_from_slice(&(part.len() as u32).to_be_bytes());
        out.extend_from_slice(part);
    }
    out
}

fn encode_frame(network_tag: [u8; 16], sequence: u64, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(FRAME_HEADER_LEN + payload.len());
    frame.push(1);
    frame.extend_from_slice(&network_tag);
    frame.extend_from_slice(&sequence.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

fn decode_frame(frame: &[u8], network_tag: [u8; 16]) -> Option<(u64, &[u8])> {
    if frame.len() < FRAME_HEADER_LEN
        || frame.len() > FRAME_HEADER_LEN + MAX_PACKET_PAYLOAD
        || frame[0] != 1
        || frame[1..17] != network_tag
    {
        return None;
    }
    Some((
        u64::from_be_bytes(frame[17..25].try_into().ok()?),
        &frame[FRAME_HEADER_LEN..],
    ))
}

#[derive(Default)]
struct ReplayWindow {
    highest: Option<u64>,
    bits: u64,
}

impl ReplayWindow {
    fn accept(&mut self, sequence: u64) -> bool {
        match self.highest {
            None => {
                self.highest = Some(sequence);
                self.bits = 1;
                true
            }
            Some(highest) if sequence > highest => {
                let shift = sequence - highest;
                self.bits = if shift >= 64 {
                    1
                } else {
                    (self.bits << shift) | 1
                };
                self.highest = Some(sequence);
                true
            }
            Some(highest) => {
                let offset = highest - sequence;
                if offset >= 64 {
                    return false;
                }
                let bit = 1_u64 << offset;
                if self.bits & bit != 0 {
                    false
                } else {
                    self.bits |= bit;
                    true
                }
            }
        }
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
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

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

    #[tokio::test]
    async fn quic_peer_channel_authenticates_and_transfers_bounded_datagrams() {
        let temp = std::env::temp_dir().join(format!("mini-tunnel-quic-{}", uuid::Uuid::new_v4()));
        let a = Identity::load_or_create_at(temp.join("a/device.key")).expect("identity A");
        let b = Identity::load_or_create_at(temp.join("b/device.key")).expect("identity B");
        let endpoint_a = peer_endpoint(&a, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .expect("endpoint A");
        let endpoint_b = peer_endpoint(&b, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .expect("endpoint B");
        let addr_b = endpoint_b.local_addr().expect("endpoint B address");
        let b_id = b.device_id();
        let b_key = b.public_key();
        let a_id = a.device_id();
        let a_key = a.public_key();
        let server_endpoint = endpoint_b.clone();
        let accept =
            tokio::spawn(
                async move { accept_peer(&server_endpoint, "office", &b, &a_id, a_key).await },
            );
        let candidates = vec![
            "not-an-address".to_owned(),
            "127.0.0.1:0".to_owned(),
            addr_b.to_string(),
        ];
        let (channel_a, connected_addr) =
            connect_peer_candidates(&endpoint_a, &candidates, "office", &a, &b_id, b_key)
                .await
                .expect("authenticated QUIC peer from candidate list");
        assert_eq!(connected_addr, addr_b);
        let channel_b = accept
            .await
            .expect("accept task")
            .expect("accepted QUIC peer");
        channel_a
            .send_packet(b"overlay-ip-packet")
            .expect("send packet");
        assert_eq!(
            channel_b.recv_packet().await.expect("receive packet"),
            b"overlay-ip-packet"
        );
        assert!(matches!(
            channel_a.send_packet(&vec![0; MAX_PACKET_PAYLOAD + 1]),
            Err(IdentityError::InvalidFrame)
        ));
        endpoint_a.close(0_u32.into(), b"test complete");
        endpoint_b.close(0_u32.into(), b"test complete");
        fs::remove_dir_all(temp).expect("remove test identities");
    }

    #[tokio::test]
    async fn candidate_connection_reports_empty_unusable_and_wrong_identity() {
        let temp =
            std::env::temp_dir().join(format!("mini-tunnel-candidates-{}", uuid::Uuid::new_v4()));
        let local =
            Identity::load_or_create_at(temp.join("local/device.key")).expect("local identity");
        let remote =
            Identity::load_or_create_at(temp.join("remote/device.key")).expect("remote identity");
        let endpoint = peer_endpoint(&local, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .expect("local endpoint");

        assert!(matches!(
            connect_peer_candidates(
                &endpoint,
                &[],
                "office",
                &local,
                &remote.device_id(),
                remote.public_key()
            )
            .await,
            Err(CandidateConnectError::NoCandidates)
        ));
        assert!(matches!(
            connect_peer_candidates(
                &endpoint,
                &[
                    "bad".to_owned(),
                    "0.0.0.0:42000".to_owned(),
                    "127.0.0.1:0".to_owned()
                ],
                "office",
                &local,
                &remote.device_id(),
                remote.public_key()
            )
            .await,
            Err(CandidateConnectError::NoUsableCandidates)
        ));
        assert!(matches!(
            connect_peer_candidates(
                &endpoint,
                &["127.0.0.1:42000".to_owned()],
                "office",
                &local,
                "wrong-id",
                remote.public_key()
            )
            .await,
            Err(CandidateConnectError::UnauthorizedPeer)
        ));
        endpoint.close(0_u32.into(), b"test complete");
        fs::remove_dir_all(temp).expect("remove test identities");
    }

    #[test]
    fn frame_decoder_rejects_cross_network_invalid_and_replayed_sequences() {
        let tag = [7_u8; 16];
        let frame = encode_frame(tag, 42, b"packet");
        assert_eq!(
            decode_frame(&frame, tag).expect("valid frame"),
            (42, b"packet".as_slice())
        );
        assert!(decode_frame(&frame, [8_u8; 16]).is_none());
        assert!(decode_frame(&[0; FRAME_HEADER_LEN], tag).is_none());
        let mut window = ReplayWindow::default();
        assert!(window.accept(42));
        assert!(!window.accept(42));
        assert!(window.accept(44));
        assert!(window.accept(43));
        assert!(window.accept(200));
        assert!(!window.accept(44));
    }

    #[tokio::test]
    async fn rejects_cross_network_quic_authentication() {
        let temp =
            std::env::temp_dir().join(format!("mini-tunnel-quic-auth-{}", uuid::Uuid::new_v4()));
        let a = Identity::load_or_create_at(temp.join("a/device.key")).expect("identity A");
        let b = Identity::load_or_create_at(temp.join("b/device.key")).expect("identity B");
        let endpoint_a = peer_endpoint(&a, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .expect("endpoint A");
        let endpoint_b = peer_endpoint(&b, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .expect("endpoint B");
        let addr_b = endpoint_b.local_addr().expect("endpoint B address");
        let a_id = a.device_id();
        let a_key = a.public_key();
        let b_id = b.device_id();
        let b_key = b.public_key();
        let server_endpoint = endpoint_b.clone();
        let server =
            tokio::spawn(
                async move { accept_peer(&server_endpoint, "office", &b, &a_id, a_key).await },
            );
        let result = connect_peer(&endpoint_a, addr_b, "different-network", &a, &b_id, b_key).await;
        assert!(result.is_err());
        assert!(server.await.expect("server task").is_err());
        endpoint_a.close(0_u32.into(), b"test complete");
        endpoint_b.close(0_u32.into(), b"test complete");
        fs::remove_dir_all(temp).expect("remove test identities");
    }

    #[tokio::test]
    async fn rejects_unpinned_tls_peer_before_application_handshake() {
        let temp =
            std::env::temp_dir().join(format!("mini-tunnel-quic-pin-{}", uuid::Uuid::new_v4()));
        let a = Identity::load_or_create_at(temp.join("a/device.key")).expect("identity A");
        let b = Identity::load_or_create_at(temp.join("b/device.key")).expect("identity B");
        let c = Identity::load_or_create_at(temp.join("c/device.key")).expect("identity C");
        let endpoint_a = peer_endpoint(&a, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .expect("endpoint A");
        let endpoint_b = peer_endpoint(&b, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .expect("endpoint B");
        let server_addr = endpoint_b.local_addr().expect("server address");
        let server_endpoint = endpoint_b.clone();
        let a_id = a.device_id();
        let a_key = a.public_key();
        let server =
            tokio::spawn(
                async move { accept_peer(&server_endpoint, "office", &b, &a_id, a_key).await },
            );
        let client = connect_peer(
            &endpoint_a,
            server_addr,
            "office",
            &a,
            &c.device_id(),
            c.public_key(),
        )
        .await;
        assert!(client.is_err());
        assert!(server.await.expect("server task").is_err());
        endpoint_a.close(0_u32.into(), b"test complete");
        endpoint_b.close(0_u32.into(), b"test complete");
        fs::remove_dir_all(temp).expect("remove test identities");
    }
}
