//! Local device identity and signing helpers used by the CLI and tunnel agent.

pub mod candidate;
pub mod membership;
pub mod routing;
pub mod stun;
pub mod tun_device;
pub mod tunnel;

use std::{
    collections::HashMap,
    fs, io,
    net::SocketAddr,
    path::PathBuf,
    sync::Mutex,
    time::{Duration, Instant},
};

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
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};

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
const UDP_CANDIDATE_TIMEOUT: Duration = Duration::from_secs(2);
const TCP_CANDIDATE_TIMEOUT: Duration = Duration::from_secs(5);
const CANDIDATE_CONNECT_BUDGET: Duration = Duration::from_secs(30);
const MAX_PEER_CANDIDATES: usize = 8;

/// Return a full-jitter reconnect delay with exponential growth and a 30-second cap.
#[must_use]
pub fn reconnect_delay(attempt: u32) -> Duration {
    let exponent = attempt.min(6);
    let ceiling_ms = (500_u64.saturating_mul(1_u64 << exponent)).min(30_000);
    let mut random = [0_u8; 8];
    if getrandom::fill(&mut random).is_err() {
        return Duration::from_millis(ceiling_ms);
    }
    let sample = u64::from_be_bytes(random);
    Duration::from_millis(sample % (ceiling_ms + 1))
}

trait AsyncPeerIo: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> AsyncPeerIo for T {}

type BoxedPeerIo = Box<dyn AsyncPeerIo>;

struct TcpPeerTransport {
    sender: tokio::sync::Mutex<WriteHalf<BoxedPeerIo>>,
    receiver: tokio::sync::Mutex<ReadHalf<BoxedPeerIo>>,
    remote_address: SocketAddr,
}

enum PeerTransport {
    Quic(Connection),
    Tcp(TcpPeerTransport),
}

/// Authenticated QUIC or TLS/TCP connection to one authorized peer.
pub struct PeerChannel {
    transport: PeerTransport,
    relay: bool,
    network_tag: [u8; 16],
    next_packet: Mutex<u64>,
    replay_window: Mutex<ReplayWindow>,
    health: Mutex<PeerHealth>,
}

const HEALTH_PING: u8 = 0xf0;
const HEALTH_PONG: u8 = 0xf1;

#[derive(Debug, Clone, Copy, Default)]
pub struct PeerHealthSnapshot {
    pub rtt: Option<Duration>,
    pub probes_succeeded: u64,
    pub probes_missed: u64,
}

#[derive(Default)]
struct PeerHealth {
    rtt: Option<Duration>,
    outstanding: HashMap<u64, Instant>,
    probes_succeeded: u64,
    probes_missed: u64,
}

impl PeerChannel {
    #[must_use]
    pub fn remote_address(&self) -> SocketAddr {
        match &self.transport {
            PeerTransport::Quic(connection) => connection.remote_address(),
            PeerTransport::Tcp(transport) => transport.remote_address,
        }
    }

    #[must_use]
    pub fn transport_name(&self) -> &'static str {
        if self.relay {
            return "Relay/TLS";
        }
        match &self.transport {
            PeerTransport::Quic(_) => "QUIC/UDP",
            PeerTransport::Tcp(_) => "TLS/TCP",
        }
    }

    /// Close this peer session, for example after a simultaneous-connect probe loses election.
    pub fn close(&self) {
        if let PeerTransport::Quic(connection) = &self.transport {
            connection.close(0_u32.into(), b"peer path not selected");
        }
    }

    /// Send one bounded packet over QUIC DATAGRAM or a length-framed TLS/TCP stream.
    pub async fn send_packet(&self, payload: &[u8]) -> Result<(), IdentityError> {
        if payload.len() > MAX_PACKET_PAYLOAD {
            return Err(IdentityError::InvalidFrame);
        }
        let sequence = {
            let mut next_packet = self
                .next_packet
                .lock()
                .map_err(|_| IdentityError::InvalidFrame)?;
            let sequence = *next_packet;
            *next_packet = sequence.checked_add(1).ok_or(IdentityError::InvalidFrame)?;
            sequence
        };
        let frame = encode_frame(self.network_tag, sequence, payload);
        match &self.transport {
            PeerTransport::Quic(connection) => {
                if connection
                    .max_datagram_size()
                    .is_none_or(|max| frame.len() > max)
                {
                    return Err(IdentityError::InvalidFrame);
                }
                connection
                    .send_datagram(Bytes::from(frame))
                    .map_err(|error| IdentityError::Transport(error.to_string()))
            }
            PeerTransport::Tcp(transport) => {
                let mut sender = transport.sender.lock().await;
                sender
                    .write_u32(frame.len() as u32)
                    .await
                    .map_err(|error| IdentityError::Transport(error.to_string()))?;
                sender
                    .write_all(&frame)
                    .await
                    .map_err(|error| IdentityError::Transport(error.to_string()))
            }
        }
    }

    /// Send an authenticated transport keepalive; receivers consume it without exposing it to TUN.
    pub async fn send_keepalive(&self) -> Result<(), IdentityError> {
        let mut nonce_bytes = [0_u8; 8];
        getrandom::fill(&mut nonce_bytes).map_err(|_| IdentityError::Random)?;
        let nonce = u64::from_be_bytes(nonce_bytes);
        {
            let mut health = self
                .health
                .lock()
                .map_err(|_| IdentityError::InvalidFrame)?;
            let expired = health
                .outstanding
                .iter()
                .filter(|(_, sent_at)| sent_at.elapsed() >= Duration::from_secs(20))
                .map(|(nonce, _)| *nonce)
                .collect::<Vec<_>>();
            for expired_nonce in expired {
                health.outstanding.remove(&expired_nonce);
                health.probes_missed = health.probes_missed.saturating_add(1);
            }
            while health.outstanding.len() >= 8 {
                if let Some(oldest) = health
                    .outstanding
                    .iter()
                    .min_by_key(|(_, sent_at)| **sent_at)
                    .map(|(id, _)| *id)
                {
                    health.outstanding.remove(&oldest);
                    health.probes_missed = health.probes_missed.saturating_add(1);
                }
            }
            health.outstanding.insert(nonce, Instant::now());
        }
        let mut payload = [0_u8; 9];
        payload[0] = HEALTH_PING;
        payload[1..].copy_from_slice(&nonce_bytes);
        if let Err(error) = self.send_packet(&payload).await {
            if let Ok(mut health) = self.health.lock() {
                health.outstanding.remove(&nonce);
                health.probes_missed = health.probes_missed.saturating_add(1);
            }
            return Err(error);
        }
        Ok(())
    }

    #[must_use]
    pub fn health_snapshot(&self) -> PeerHealthSnapshot {
        self.health
            .lock()
            .map(|health| PeerHealthSnapshot {
                rtt: health.rtt,
                probes_succeeded: health.probes_succeeded,
                probes_missed: health.probes_missed,
            })
            .unwrap_or_default()
    }

    /// Validate a candidate path with authenticated ping/pong exchanges before it replaces a live path.
    pub async fn probe_health(
        &self,
        probes: u8,
        per_probe_timeout: Duration,
    ) -> Result<Duration, IdentityError> {
        if probes == 0 || probes > 8 || per_probe_timeout.is_zero() {
            return Err(IdentityError::InvalidFrame);
        }
        let mut maximum_rtt = Duration::ZERO;
        for _ in 0..probes {
            let succeeded_before = self.health_snapshot().probes_succeeded;
            self.send_keepalive().await?;
            let deadline = tokio::time::Instant::now() + per_probe_timeout;
            loop {
                let _packet = tokio::time::timeout_at(deadline, self.recv_packet())
                    .await
                    .map_err(|_| {
                        IdentityError::Transport("candidate path probe timed out".to_owned())
                    })??;
                let health = self.health_snapshot();
                if health.probes_succeeded > succeeded_before {
                    maximum_rtt = maximum_rtt.max(health.rtt.unwrap_or_default());
                    break;
                }
            }
        }
        Ok(maximum_rtt)
    }

    /// Receive one authenticated frame, rejecting malformed, cross-network, and replayed data.
    pub async fn recv_packet(&self) -> Result<Vec<u8>, IdentityError> {
        let frame = match &self.transport {
            PeerTransport::Quic(connection) => connection
                .read_datagram()
                .await
                .map_err(|error| IdentityError::Transport(error.to_string()))?
                .to_vec(),
            PeerTransport::Tcp(transport) => {
                let mut receiver = transport.receiver.lock().await;
                let frame_len = receiver
                    .read_u32()
                    .await
                    .map_err(|error| IdentityError::Transport(error.to_string()))?
                    as usize;
                if !(FRAME_HEADER_LEN..=FRAME_HEADER_LEN + MAX_PACKET_PAYLOAD).contains(&frame_len)
                {
                    return Err(IdentityError::InvalidFrame);
                }
                let mut frame = vec![0; frame_len];
                receiver
                    .read_exact(&mut frame)
                    .await
                    .map_err(|error| IdentityError::Transport(error.to_string()))?;
                frame
            }
        };
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
        if payload.len() == 9 && matches!(payload[0], HEALTH_PING | HEALTH_PONG) {
            let nonce = u64::from_be_bytes(
                payload[1..9]
                    .try_into()
                    .map_err(|_| IdentityError::InvalidFrame)?,
            );
            if payload[0] == HEALTH_PING {
                let mut pong = payload.to_vec();
                pong[0] = HEALTH_PONG;
                self.send_packet(&pong).await?;
            } else if let Ok(mut health) = self.health.lock()
                && let Some(sent_at) = health.outstanding.remove(&nonce)
            {
                health.rtt = Some(sent_at.elapsed());
                health.probes_succeeded = health.probes_succeeded.saturating_add(1);
            }
            return Ok(Vec::new());
        }
        Ok(payload.to_vec())
    }
}

/// Bind one QUIC endpoint. Its TLS certificate is derived from the stable device key.
pub fn peer_endpoint(
    identity: &Identity,
    bind_addr: SocketAddr,
) -> Result<Endpoint, IdentityError> {
    Endpoint::server(peer_server_config(identity)?, bind_addr)
        .map_err(|error| IdentityError::Transport(error.to_string()))
}

/// Discover the mapped address and pass the same bound UDP socket to the QUIC endpoint.
pub async fn peer_endpoint_with_stun(
    identity: &Identity,
    bind_addr: SocketAddr,
    stun_server: SocketAddr,
) -> Result<(Endpoint, SocketAddr), IdentityError> {
    let socket = tokio::net::UdpSocket::bind(bind_addr)
        .await
        .map_err(|error| IdentityError::Transport(error.to_string()))?;
    let mapped_address = stun::discover_mapped_address(&socket, stun_server)
        .await
        .map_err(|error| IdentityError::Transport(error.to_string()))?;
    let socket = socket
        .into_std()
        .map_err(|error| IdentityError::Transport(error.to_string()))?;
    let runtime = quinn::default_runtime()
        .ok_or_else(|| IdentityError::Transport("no QUIC runtime is available".to_owned()))?;
    let endpoint = Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(peer_server_config(identity)?),
        socket,
        runtime,
    )
    .map_err(|error| IdentityError::Transport(error.to_string()))?;
    Ok((endpoint, mapped_address))
}

fn peer_server_config(identity: &Identity) -> Result<quinn::ServerConfig, IdentityError> {
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
    server_tls.alpn_protocols = vec![b"mini-tunnel-peer/2".to_vec()];
    let server_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(server_tls)
        .map_err(|error| IdentityError::Transport(error.to_string()))?;
    let mut server_config = quinn::ServerConfig::with_crypto(std::sync::Arc::new(server_crypto));
    server_config.transport = std::sync::Arc::new(peer_transport_config());
    Ok(server_config)
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
    tls.alpn_protocols = vec![b"mini-tunnel-peer/2".to_vec()];
    let mut config = quinn::ClientConfig::new(std::sync::Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls)
            .map_err(|error| IdentityError::Transport(error.to_string()))?,
    ));
    config.transport_config(std::sync::Arc::new(peer_transport_config()));
    Ok(config)
}

fn peer_tcp_server_config(
    identity: &Identity,
) -> Result<std::sync::Arc<rustls::ServerConfig>, IdentityError> {
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
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| IdentityError::Transport(error.to_string()))?
        .with_no_client_auth()
        .with_single_cert(vec![certificate_der], server_key)
        .map_err(|error| IdentityError::Transport(error.to_string()))?;
    config.alpn_protocols = vec![b"mini-tunnel-peer-tcp/1".to_vec()];
    Ok(std::sync::Arc::new(config))
}

fn peer_tcp_client_config(
    expected_key: [u8; 32],
) -> Result<std::sync::Arc<rustls::ClientConfig>, IdentityError> {
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|error| IdentityError::Transport(error.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(PinnedPeerVerifier {
            provider,
            expected_key,
        }))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"mini-tunnel-peer-tcp/1".to_vec()];
    Ok(std::sync::Arc::new(config))
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

/// Connect to a peer using a TLS-pinned TCP stream for reliable fallback transport.
pub async fn connect_tcp_peer(
    remote_addr: SocketAddr,
    network_id: &str,
    identity: &Identity,
    expected_peer_id: &str,
    expected_peer_key: [u8; 32],
) -> Result<PeerChannel, IdentityError> {
    if expected_peer_id != mini_tunnel_protocol::device_id_from_public_key(&expected_peer_key) {
        return Err(IdentityError::UnauthorizedPeer);
    }
    let socket = tokio::time::timeout(
        PEER_HANDSHAKE_TIMEOUT,
        tokio::net::TcpStream::connect(remote_addr),
    )
    .await
    .map_err(|error| IdentityError::Transport(error.to_string()))?
    .map_err(|error| IdentityError::Transport(error.to_string()))?;
    connect_tcp_peer_over_stream(
        socket,
        remote_addr,
        network_id,
        identity,
        expected_peer_id,
        expected_peer_key,
    )
    .await
}

/// Establish the existing pinned TLS peer protocol over an already-connected stream.
pub async fn connect_tcp_peer_over_stream(
    socket: tokio::net::TcpStream,
    remote_addr: SocketAddr,
    network_id: &str,
    identity: &Identity,
    expected_peer_id: &str,
    expected_peer_key: [u8; 32],
) -> Result<PeerChannel, IdentityError> {
    if expected_peer_id != mini_tunnel_protocol::device_id_from_public_key(&expected_peer_key) {
        return Err(IdentityError::UnauthorizedPeer);
    }
    socket
        .set_nodelay(true)
        .map_err(|error| IdentityError::Transport(error.to_string()))?;
    let server_name = ServerName::try_from("mini-tunnel")
        .map_err(|error| IdentityError::Transport(error.to_string()))?;
    let connector = tokio_rustls::TlsConnector::from(peer_tcp_client_config(expected_peer_key)?);
    let mut stream = tokio::time::timeout(
        PEER_HANDSHAKE_TIMEOUT,
        connector.connect(server_name, socket),
    )
    .await
    .map_err(|error| IdentityError::Transport(error.to_string()))?
    .map_err(|error| IdentityError::Transport(error.to_string()))?;
    if stream.get_ref().1.alpn_protocol() != Some(b"mini-tunnel-peer-tcp/1") {
        return Err(IdentityError::UnauthorizedPeer);
    }
    tokio::time::timeout(
        PEER_HANDSHAKE_TIMEOUT,
        tcp_client_authenticate(&mut stream, network_id, identity, expected_peer_id),
    )
    .await
    .map_err(|error| IdentityError::Transport(error.to_string()))??;
    Ok(new_tcp_channel(Box::new(stream), remote_addr, network_id))
}

/// Connect through an authorized relay ticket, then negotiate pinned end-to-end peer TLS.
pub async fn connect_relay_peer(
    relay_addr: SocketAddr,
    ticket: &str,
    network_id: &str,
    identity: &Identity,
    expected_peer_id: &str,
    expected_peer_key: [u8; 32],
) -> Result<PeerChannel, IdentityError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    if expected_peer_id != mini_tunnel_protocol::device_id_from_public_key(&expected_peer_key)
        || ticket.is_empty()
        || ticket.len() > 2048
    {
        return Err(IdentityError::UnauthorizedPeer);
    }
    let mut socket = tokio::time::timeout(
        PEER_HANDSHAKE_TIMEOUT,
        tokio::net::TcpStream::connect(relay_addr),
    )
    .await
    .map_err(|error| IdentityError::Transport(error.to_string()))?
    .map_err(|error| IdentityError::Transport(error.to_string()))?;
    let ticket_len: u16 = ticket
        .len()
        .try_into()
        .map_err(|_| IdentityError::UnauthorizedPeer)?;
    socket.write_all(b"MTRELAY1").await?;
    socket.write_u16(ticket_len).await?;
    socket.write_all(ticket.as_bytes()).await?;
    let public_key = identity.public_key();
    socket.write_all(&public_key).await?;
    if socket.read_u8().await? != 1 {
        return Err(IdentityError::UnauthorizedPeer);
    }
    let mut challenge = [0_u8; 32];
    socket.read_exact(&mut challenge).await?;
    let proof = identity.sign(&mini_tunnel_protocol::relay_auth_signing_bytes(
        ticket,
        &challenge,
        &public_key,
    ));
    let proof = URL_SAFE_NO_PAD
        .decode(proof)
        .map_err(|_| IdentityError::UnauthorizedPeer)?;
    socket.write_all(&proof).await?;
    if socket.read_u8().await? != 2 {
        return Err(IdentityError::UnauthorizedPeer);
    }
    let remote = socket.peer_addr()?;
    if identity.device_id().as_str() < expected_peer_id {
        let mut channel = connect_tcp_peer_over_stream(
            socket,
            remote,
            network_id,
            identity,
            expected_peer_id,
            expected_peer_key,
        )
        .await?;
        channel.relay = true;
        Ok(channel)
    } else {
        let acceptor = tokio_rustls::TlsAcceptor::from(peer_tcp_server_config(identity)?);
        let mut stream = tokio::time::timeout(PEER_HANDSHAKE_TIMEOUT, acceptor.accept(socket))
            .await
            .map_err(|error| IdentityError::Transport(error.to_string()))?
            .map_err(|error| IdentityError::Transport(error.to_string()))?;
        if stream.get_ref().1.alpn_protocol() != Some(b"mini-tunnel-peer-tcp/1") {
            return Err(IdentityError::UnauthorizedPeer);
        }
        tokio::time::timeout(
            PEER_HANDSHAKE_TIMEOUT,
            tcp_server_authenticate(
                &mut stream,
                network_id,
                identity,
                &[(expected_peer_id.to_owned(), expected_peer_key)],
            ),
        )
        .await
        .map_err(|error| IdentityError::Transport(error.to_string()))??;
        let mut channel = new_tcp_channel(Box::new(stream), remote, network_id);
        channel.relay = true;
        Ok(channel)
    }
}

/// Bind a TCP listener for authenticated TCP fallback sessions.
pub async fn peer_tcp_listener(
    bind_addr: SocketAddr,
) -> Result<tokio::net::TcpListener, IdentityError> {
    tokio::net::TcpListener::bind(bind_addr)
        .await
        .map_err(|error| IdentityError::Transport(error.to_string()))
}

/// Accept and authenticate the next TCP member whose device identity is in the allowlist.
pub async fn accept_tcp_peer_any(
    listener: &tokio::net::TcpListener,
    network_id: &str,
    identity: &Identity,
    allowed_peers: &[(String, [u8; 32])],
) -> Result<(String, PeerChannel), IdentityError> {
    if allowed_peers.is_empty()
        || allowed_peers.iter().any(|(device_id, public_key)| {
            device_id != &mini_tunnel_protocol::device_id_from_public_key(public_key)
        })
    {
        return Err(IdentityError::UnauthorizedPeer);
    }
    let acceptor = tokio_rustls::TlsAcceptor::from(peer_tcp_server_config(identity)?);
    loop {
        let (socket, remote_addr) = tokio::time::timeout(PEER_HANDSHAKE_TIMEOUT, listener.accept())
            .await
            .map_err(|error| IdentityError::Transport(error.to_string()))?
            .map_err(|error| IdentityError::Transport(error.to_string()))?;
        let _ = socket.set_nodelay(true);
        let mut stream =
            match tokio::time::timeout(PEER_HANDSHAKE_TIMEOUT, acceptor.accept(socket)).await {
                Ok(Ok(stream)) => stream,
                Ok(Err(_)) | Err(_) => continue,
            };
        if stream.get_ref().1.alpn_protocol() != Some(b"mini-tunnel-peer-tcp/1") {
            continue;
        }
        match tokio::time::timeout(
            PEER_HANDSHAKE_TIMEOUT,
            tcp_server_authenticate(&mut stream, network_id, identity, allowed_peers),
        )
        .await
        {
            Ok(Ok(device_id)) => {
                return Ok((
                    device_id,
                    new_tcp_channel(Box::new(stream), remote_addr, network_id),
                ));
            }
            Ok(Err(_)) | Err(_) => continue,
        }
    }
}

/// Accept authenticated TLS/TCP peers using a runtime-refreshed allowlist.
pub async fn accept_tcp_peer_any_dynamic(
    listener: &tokio::net::TcpListener,
    network_id: &str,
    identity: &Identity,
    allowed_peers: tokio::sync::watch::Receiver<Vec<(String, [u8; 32])>>,
) -> Result<(String, PeerChannel), IdentityError> {
    let acceptor = tokio_rustls::TlsAcceptor::from(peer_tcp_server_config(identity)?);
    loop {
        let (socket, remote_addr) = tokio::time::timeout(PEER_HANDSHAKE_TIMEOUT, listener.accept())
            .await
            .map_err(|error| IdentityError::Transport(error.to_string()))?
            .map_err(|error| IdentityError::Transport(error.to_string()))?;
        let _ = socket.set_nodelay(true);
        let mut stream =
            match tokio::time::timeout(PEER_HANDSHAKE_TIMEOUT, acceptor.accept(socket)).await {
                Ok(Ok(stream)) => stream,
                Ok(Err(_)) | Err(_) => continue,
            };
        if stream.get_ref().1.alpn_protocol() != Some(b"mini-tunnel-peer-tcp/1") {
            continue;
        }
        let current = allowed_peers.borrow().clone();
        if current.is_empty() || !valid_peer_allowlist(&current) {
            continue;
        }
        match tokio::time::timeout(
            PEER_HANDSHAKE_TIMEOUT,
            tcp_server_authenticate(&mut stream, network_id, identity, &current),
        )
        .await
        {
            Ok(Ok(device_id)) => {
                return Ok((
                    device_id,
                    new_tcp_channel(Box::new(stream), remote_addr, network_id),
                ));
            }
            Ok(Err(_)) | Err(_) => continue,
        }
    }
}

/// Try signed-discovery candidates in order with shorter UDP probes and a bounded TCP fallback.
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

    let mut checklist =
        candidate::CandidateChecklist::from_signaled(candidates, MAX_PEER_CANDIDATES)
            .ok_or(CandidateConnectError::TooManyCandidates)?;
    if checklist.checks().is_empty() {
        return Err(CandidateConnectError::NoUsableCandidates);
    }
    let mut last_error = None;
    let deadline = tokio::time::Instant::now() + CANDIDATE_CONNECT_BUDGET;
    while let Some(index) = checklist.next_waiting() {
        checklist.mark_in_progress(index);
        let candidate = checklist.checks()[index].clone();
        let address = candidate.address;
        let is_tcp = candidate.transport == candidate::CandidateTransport::Tcp;
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            checklist.finish(index, false);
            break;
        }
        let attempt_timeout = if is_tcp {
            TCP_CANDIDATE_TIMEOUT.min(remaining)
        } else {
            UDP_CANDIDATE_TIMEOUT.min(remaining)
        };
        let connection = if is_tcp {
            tokio::time::timeout(
                attempt_timeout,
                connect_tcp_peer(
                    address,
                    network_id,
                    identity,
                    expected_peer_id,
                    expected_peer_key,
                ),
            )
            .await
        } else {
            tokio::time::timeout(
                attempt_timeout,
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
        };
        match connection {
            Ok(Ok(channel)) => {
                checklist.finish(index, true);
                return Ok((channel, address));
            }
            Ok(Err(IdentityError::UnauthorizedPeer)) => {
                return Err(CandidateConnectError::UnauthorizedPeer);
            }
            Ok(Err(error)) => {
                checklist.finish(index, false);
                last_error = Some(error.to_string());
            }
            Err(_) => {
                checklist.finish(index, false);
                last_error = Some(format!("connection to {address} timed out"));
            }
        }
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
        Some((expected_peer_id, expected_peer_key)),
        None,
    )
    .await?;
    Ok(new_channel(connection, network_id))
}

/// Accept the next authenticated member from an allowlist, returning its identity for demux.
pub async fn accept_peer_any(
    endpoint: &Endpoint,
    network_id: &str,
    identity: &Identity,
    allowed_peers: &[(String, [u8; 32])],
) -> Result<(String, PeerChannel), IdentityError> {
    if allowed_peers.is_empty()
        || allowed_peers.iter().any(|(device_id, public_key)| {
            device_id != &mini_tunnel_protocol::device_id_from_public_key(public_key)
        })
    {
        return Err(IdentityError::UnauthorizedPeer);
    }
    loop {
        let Some(incoming) = endpoint.accept().await else {
            return Err(IdentityError::Transport("endpoint closed".to_owned()));
        };
        let connection = match tokio::time::timeout(PEER_HANDSHAKE_TIMEOUT, incoming).await {
            Ok(Ok(connection)) => connection,
            Ok(Err(_)) | Err(_) => continue,
        };
        match server_authenticate(&connection, network_id, identity, None, Some(allowed_peers))
            .await
        {
            Ok((device_id, _)) => return Ok((device_id, new_channel(connection, network_id))),
            Err(_) => connection.close(0_u32.into(), b"peer authentication rejected"),
        }
    }
}

/// Accept authenticated peers using an allowlist that can be refreshed at runtime.
pub async fn accept_peer_any_dynamic(
    endpoint: &Endpoint,
    network_id: &str,
    identity: &Identity,
    allowed_peers: tokio::sync::watch::Receiver<Vec<(String, [u8; 32])>>,
) -> Result<(String, PeerChannel), IdentityError> {
    loop {
        let Some(incoming) = endpoint.accept().await else {
            return Err(IdentityError::Transport("endpoint closed".to_owned()));
        };
        let connection = match tokio::time::timeout(PEER_HANDSHAKE_TIMEOUT, incoming).await {
            Ok(Ok(connection)) => connection,
            Ok(Err(_)) | Err(_) => continue,
        };
        let current = allowed_peers.borrow().clone();
        if current.is_empty() || !valid_peer_allowlist(&current) {
            connection.close(0_u32.into(), b"peer is not currently authorized");
            continue;
        }
        match server_authenticate(&connection, network_id, identity, None, Some(&current)).await {
            Ok((device_id, _)) => return Ok((device_id, new_channel(connection, network_id))),
            Err(_) => connection.close(0_u32.into(), b"peer authentication rejected"),
        }
    }
}

fn valid_peer_allowlist(allowed_peers: &[(String, [u8; 32])]) -> bool {
    allowed_peers.iter().all(|(device_id, public_key)| {
        device_id == &mini_tunnel_protocol::device_id_from_public_key(public_key)
    })
}

fn new_channel(connection: Connection, network_id: &str) -> PeerChannel {
    let hash = Sha256::digest(network_id.as_bytes());
    let mut network_tag = [0_u8; 16];
    network_tag.copy_from_slice(&hash[..16]);
    PeerChannel {
        transport: PeerTransport::Quic(connection),
        relay: false,
        network_tag,
        next_packet: Mutex::new(0),
        replay_window: Mutex::new(ReplayWindow::default()),
        health: Mutex::new(PeerHealth::default()),
    }
}

fn new_tcp_channel(
    stream: BoxedPeerIo,
    remote_address: SocketAddr,
    network_id: &str,
) -> PeerChannel {
    let hash = Sha256::digest(network_id.as_bytes());
    let mut network_tag = [0_u8; 16];
    network_tag.copy_from_slice(&hash[..16]);
    let (receiver, sender) = tokio::io::split(stream);
    PeerChannel {
        transport: PeerTransport::Tcp(TcpPeerTransport {
            sender: tokio::sync::Mutex::new(sender),
            receiver: tokio::sync::Mutex::new(receiver),
            remote_address,
        }),
        relay: false,
        network_tag,
        next_packet: Mutex::new(0),
        replay_window: Mutex::new(ReplayWindow::default()),
        health: Mutex::new(PeerHealth::default()),
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
    // Announce the signing key so a multi-peer listener can demultiplex incoming connections.
    send.write_all(&identity.public_key())
        .await
        .map_err(|error| IdentityError::Transport(error.to_string()))?;
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
    expected_peer: Option<(&str, [u8; 32])>,
    allowed_peers: Option<&[(String, [u8; 32])]>,
) -> Result<(String, [u8; 32]), IdentityError> {
    let (mut send, mut recv) = tokio::time::timeout(PEER_HANDSHAKE_TIMEOUT, connection.accept_bi())
        .await
        .map_err(|error| IdentityError::Transport(error.to_string()))?
        .map_err(|error| IdentityError::Transport(error.to_string()))?;
    let mut client_key = [0_u8; 32];
    tokio::time::timeout(PEER_HANDSHAKE_TIMEOUT, recv.read_exact(&mut client_key))
        .await
        .map_err(|error| IdentityError::Transport(error.to_string()))?
        .map_err(|error| IdentityError::Transport(error.to_string()))?;
    let client_id = mini_tunnel_protocol::device_id_from_public_key(&client_key);
    if expected_peer.is_some_and(|(expected_id, expected_key)| {
        expected_id != client_id || expected_key != client_key
    }) || allowed_peers.is_some_and(|allowed| {
        !allowed
            .iter()
            .any(|(allowed_id, allowed_key)| allowed_id == &client_id && allowed_key == &client_key)
    }) {
        let _ = send.write_all(&[0]).await;
        return Err(IdentityError::UnauthorizedPeer);
    }
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
        &client_id,
        &identity.device_id(),
        &client_nonce,
        &server_nonce,
    );
    let key = VerifyingKey::from_bytes(&client_key).map_err(|_| IdentityError::UnauthorizedPeer)?;
    key.verify_strict(&proof, &Signature::from_bytes(&signature))
        .map_err(|_| IdentityError::UnauthorizedPeer)?;
    send.write_all(&[1])
        .await
        .map_err(|error| IdentityError::Transport(error.to_string()))?;
    Ok((client_id, client_key))
}

async fn tcp_client_authenticate<S>(
    stream: &mut S,
    network_id: &str,
    identity: &Identity,
    server_id: &str,
) -> Result<(), IdentityError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut nonce = [0_u8; 32];
    getrandom::fill(&mut nonce).map_err(|_| IdentityError::Random)?;
    stream
        .write_all(&identity.public_key())
        .await
        .map_err(|error| IdentityError::Transport(error.to_string()))?;
    stream
        .write_all(&nonce)
        .await
        .map_err(|error| IdentityError::Transport(error.to_string()))?;
    let mut server_nonce = [0_u8; 32];
    stream
        .read_exact(&mut server_nonce)
        .await
        .map_err(|error| IdentityError::Transport(error.to_string()))?;
    let proof = auth_bytes(
        network_id,
        &identity.device_id(),
        server_id,
        &nonce,
        &server_nonce,
    );
    let signature = identity.signing_key.sign(&proof).to_bytes();
    stream
        .write_all(&signature)
        .await
        .map_err(|error| IdentityError::Transport(error.to_string()))?;
    let mut accepted = [0_u8; 1];
    stream
        .read_exact(&mut accepted)
        .await
        .map_err(|error| IdentityError::Transport(error.to_string()))?;
    if accepted[0] != 1 {
        return Err(IdentityError::UnauthorizedPeer);
    }
    Ok(())
}

async fn tcp_server_authenticate<S>(
    stream: &mut S,
    network_id: &str,
    identity: &Identity,
    allowed_peers: &[(String, [u8; 32])],
) -> Result<String, IdentityError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut client_key = [0_u8; 32];
    stream
        .read_exact(&mut client_key)
        .await
        .map_err(|error| IdentityError::Transport(error.to_string()))?;
    let client_id = mini_tunnel_protocol::device_id_from_public_key(&client_key);
    if !allowed_peers
        .iter()
        .any(|(device_id, public_key)| device_id == &client_id && public_key == &client_key)
    {
        return Err(IdentityError::UnauthorizedPeer);
    }
    let mut client_nonce = [0_u8; 32];
    stream
        .read_exact(&mut client_nonce)
        .await
        .map_err(|error| IdentityError::Transport(error.to_string()))?;
    let mut server_nonce = [0_u8; 32];
    getrandom::fill(&mut server_nonce).map_err(|_| IdentityError::Random)?;
    stream
        .write_all(&server_nonce)
        .await
        .map_err(|error| IdentityError::Transport(error.to_string()))?;
    let mut signature = [0_u8; 64];
    stream
        .read_exact(&mut signature)
        .await
        .map_err(|error| IdentityError::Transport(error.to_string()))?;
    let proof = auth_bytes(
        network_id,
        &client_id,
        &identity.device_id(),
        &client_nonce,
        &server_nonce,
    );
    let key = VerifyingKey::from_bytes(&client_key).map_err(|_| IdentityError::UnauthorizedPeer)?;
    key.verify_strict(&proof, &Signature::from_bytes(&signature))
        .map_err(|_| IdentityError::UnauthorizedPeer)?;
    stream
        .write_all(&[1])
        .await
        .map_err(|error| IdentityError::Transport(error.to_string()))?;
    Ok(client_id)
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
    fn reconnect_backoff_is_bounded() {
        for attempt in 0..100 {
            assert!(reconnect_delay(attempt) <= Duration::from_secs(30));
        }
    }

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
        assert_eq!(channel_a.transport_name(), "QUIC/UDP");
        channel_a
            .send_packet(b"overlay-ip-packet")
            .await
            .expect("send packet");
        assert_eq!(
            channel_b.recv_packet().await.expect("receive packet"),
            b"overlay-ip-packet"
        );
        assert!(matches!(
            channel_a
                .send_packet(&vec![0; MAX_PACKET_PAYLOAD + 1])
                .await,
            Err(IdentityError::InvalidFrame)
        ));
        endpoint_a.close(0_u32.into(), b"test complete");
        endpoint_b.close(0_u32.into(), b"test complete");
        fs::remove_dir_all(temp).expect("remove test identities");
    }

    #[tokio::test]
    async fn tcp_peer_channel_authenticates_and_transfers_bounded_frames() {
        let temp = std::env::temp_dir().join(format!("mini-tunnel-tcp-{}", uuid::Uuid::new_v4()));
        let a = Identity::load_or_create_at(temp.join("a/device.key")).expect("identity A");
        let b = Identity::load_or_create_at(temp.join("b/device.key")).expect("identity B");
        let listener = peer_tcp_listener(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .expect("TCP listener");
        let remote_addr = listener.local_addr().expect("TCP listener address");
        let a_id = a.device_id();
        let expected_a_id = a_id.clone();
        let a_key = a.public_key();
        let b_id = b.device_id();
        let b_key = b.public_key();
        let udp_endpoint = peer_endpoint(&a, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .expect("UDP endpoint");
        let closed_udp =
            tokio::net::UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
                .await
                .expect("temporary UDP socket");
        let closed_udp_addr = closed_udp.local_addr().expect("temporary UDP address");
        drop(closed_udp);
        let accept = tokio::spawn(async move {
            accept_tcp_peer_any(&listener, "office", &b, &[(a_id, a_key)]).await
        });
        let (channel_a, connected_addr) = connect_peer_candidates(
            &udp_endpoint,
            &[closed_udp_addr.to_string(), format!("tcp://{remote_addr}")],
            "office",
            &a,
            &b_id,
            b_key,
        )
        .await
        .expect("candidate fallback to authenticated TCP peer");
        assert_eq!(connected_addr, remote_addr);
        let (accepted_id, channel_b) = accept
            .await
            .expect("accept task")
            .expect("accepted TCP peer");
        assert_eq!(accepted_id, expected_a_id);
        assert_eq!(channel_a.transport_name(), "TLS/TCP");
        channel_a.send_keepalive().await.expect("send keepalive");
        channel_a
            .send_packet(b"reliable overlay packet")
            .await
            .expect("send TCP frame");
        assert!(
            channel_b
                .recv_packet()
                .await
                .expect("receive TCP keepalive")
                .is_empty()
        );
        assert_eq!(
            channel_b.recv_packet().await.expect("receive TCP frame"),
            b"reliable overlay packet"
        );
        assert!(
            channel_a
                .recv_packet()
                .await
                .expect("receive TCP pong")
                .is_empty()
        );
        assert_eq!(channel_a.health_snapshot().probes_succeeded, 1);
        assert!(matches!(
            channel_a
                .send_packet(&vec![0; MAX_PACKET_PAYLOAD + 1])
                .await,
            Err(IdentityError::InvalidFrame)
        ));
        let PeerTransport::Tcp(transport) = &channel_a.transport else {
            unreachable!("TCP fallback candidate returns a TCP peer channel");
        };
        transport
            .sender
            .lock()
            .await
            .write_u32(u32::MAX)
            .await
            .expect("write oversized test frame length");
        assert!(matches!(
            channel_b.recv_packet().await,
            Err(IdentityError::InvalidFrame)
        ));
        fs::remove_dir_all(temp).expect("remove test identities");
        udp_endpoint.close(0_u32.into(), b"test complete");
    }

    #[tokio::test]
    async fn relay_path_establishes_pinned_tls_and_transfers_overlay_frames() {
        let temp =
            std::env::temp_dir().join(format!("mini-tunnel-relay-agent-{}", uuid::Uuid::new_v4()));
        let a = Identity::load_or_create_at(temp.join("a/device.key")).unwrap();
        let b = Identity::load_or_create_at(temp.join("b/device.key")).unwrap();
        let relay_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let relay_addr = relay_listener.local_addr().unwrap();
        let secret = [27_u8; 32];
        let server =
            mini_tunnel_relay::RelayServer::new(mini_tunnel_relay::RelayConfig::new(secret));
        let task = tokio::spawn(async move { server.run(relay_listener).await });
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let session_id = [4_u8; 16];
        let ticket = |source: &Identity, target: &Identity, id: u8| {
            mini_tunnel_protocol::issue_relay_ticket(
                &secret,
                &mini_tunnel_protocol::RelayTicketClaims {
                    version: mini_tunnel_protocol::RELAY_TICKET_VERSION,
                    network_id: "relay-test".into(),
                    source_device_id: source.device_id(),
                    target_device_id: target.device_id(),
                    session_id,
                    ticket_id: [id; 16],
                    expires_at_ms: now + 60_000,
                },
            )
            .unwrap()
        };
        let ticket_a = ticket(&a, &b, 1);
        let ticket_b = ticket(&b, &a, 2);
        let a_id = a.device_id();
        let b_id = b.device_id();
        let (result_a, result_b) = tokio::join!(
            connect_relay_peer(
                relay_addr,
                &ticket_a,
                "relay-test",
                &a,
                &b_id,
                b.public_key()
            ),
            connect_relay_peer(
                relay_addr,
                &ticket_b,
                "relay-test",
                &b,
                &a_id,
                a.public_key()
            ),
        );
        let channel_a = result_a.unwrap();
        let channel_b = result_b.unwrap();
        channel_a
            .send_packet(b"through opaque relay")
            .await
            .unwrap();
        assert_eq!(
            channel_b.recv_packet().await.unwrap(),
            b"through opaque relay"
        );
        task.abort();
        drop(channel_a);
        drop(channel_b);
        fs::remove_dir_all(temp).unwrap();
    }

    #[tokio::test]
    async fn tcp_authentication_rejects_cross_network_sessions() {
        let temp =
            std::env::temp_dir().join(format!("mini-tunnel-tcp-auth-{}", uuid::Uuid::new_v4()));
        let a = Identity::load_or_create_at(temp.join("a/device.key")).expect("identity A");
        let b = Identity::load_or_create_at(temp.join("b/device.key")).expect("identity B");
        let listener = peer_tcp_listener(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .expect("TCP listener");
        let remote_addr = listener.local_addr().expect("TCP listener address");
        let a_id = a.device_id();
        let a_key = a.public_key();
        let b_id = b.device_id();
        let b_key = b.public_key();
        let accept = tokio::spawn(async move {
            accept_tcp_peer_any(&listener, "office", &b, &[(a_id, a_key)]).await
        });
        let result = connect_tcp_peer(remote_addr, "guest", &a, &b_id, b_key).await;
        assert!(
            result.is_err(),
            "cross-network TCP authentication must fail"
        );
        accept.abort();
        let _ = accept.await;
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

    #[tokio::test]
    async fn accept_peer_any_demultiplexes_multiple_authenticated_members() {
        let temp =
            std::env::temp_dir().join(format!("mini-tunnel-accept-any-{}", uuid::Uuid::new_v4()));
        let a = Identity::load_or_create_at(temp.join("a/device.key")).expect("identity A");
        let b = Identity::load_or_create_at(temp.join("b/device.key")).expect("identity B");
        let c = Identity::load_or_create_at(temp.join("c/device.key")).expect("identity C");
        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let endpoint_a = peer_endpoint(&a, bind).expect("endpoint A");
        let endpoint_b = peer_endpoint(&b, bind).expect("endpoint B");
        let endpoint_c = peer_endpoint(&c, bind).expect("endpoint C");
        let a_id = a.device_id();
        let a_key = a.public_key();
        let b_id = b.device_id();
        let b_key = b.public_key();
        let c_id = c.device_id();
        let c_key = c.public_key();
        let allowed = vec![(a_id.clone(), a_key), (b_id.clone(), b_key)];
        let c_identity = std::sync::Arc::new(c);
        let accepting_endpoint = endpoint_c.clone();
        let accepting_identity = std::sync::Arc::clone(&c_identity);
        let allowed_first = allowed.clone();
        let accept_a = tokio::spawn(async move {
            accept_peer_any(
                &accepting_endpoint,
                "office",
                &accepting_identity,
                &allowed_first,
            )
            .await
        });
        let a_channel = connect_peer(
            &endpoint_a,
            endpoint_c.local_addr().expect("C address"),
            "office",
            &a,
            &c_id,
            c_key,
        )
        .await
        .expect("A connects to C");
        let (accepted_a, c_channel_a) = accept_a.await.expect("accept A task").expect("accept A");
        assert_eq!(accepted_a, a_id);
        a_channel.send_packet(b"from A").await.expect("send from A");
        assert_eq!(
            c_channel_a.recv_packet().await.expect("receive A"),
            b"from A"
        );

        let accepting_endpoint = endpoint_c.clone();
        let accepting_identity = std::sync::Arc::clone(&c_identity);
        let allowed_b = vec![(b_id.clone(), b_key)];
        let accept_b = tokio::spawn(async move {
            accept_peer_any(
                &accepting_endpoint,
                "office",
                &accepting_identity,
                &allowed_b,
            )
            .await
        });
        let b_channel = connect_peer(
            &endpoint_b,
            endpoint_c.local_addr().expect("C address"),
            "office",
            &b,
            &c_id,
            c_key,
        )
        .await
        .expect("B connects to C");
        let (accepted_b, c_channel_b) = accept_b.await.expect("accept B task").expect("accept B");
        assert_eq!(accepted_b, b_id);
        b_channel.send_packet(b"from B").await.expect("send from B");
        assert_eq!(
            c_channel_b.recv_packet().await.expect("receive B"),
            b"from B"
        );
        endpoint_a.close(0_u32.into(), b"test complete");
        endpoint_b.close(0_u32.into(), b"test complete");
        endpoint_c.close(0_u32.into(), b"test complete");
        fs::remove_dir_all(temp).expect("remove test identities");
    }

    #[tokio::test]
    async fn dynamic_accept_uses_the_latest_member_allowlist() {
        let temp = std::env::temp_dir().join(format!(
            "mini-tunnel-dynamic-accept-{}",
            uuid::Uuid::new_v4()
        ));
        let peer = Identity::load_or_create_at(temp.join("peer/device.key")).unwrap();
        let local = std::sync::Arc::new(
            Identity::load_or_create_at(temp.join("local/device.key")).unwrap(),
        );
        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let endpoint_peer = peer_endpoint(&peer, bind).unwrap();
        let local_endpoint = peer_endpoint(&local, bind).unwrap();
        let (allowed_tx, allowed_rx) = tokio::sync::watch::channel(Vec::new());
        let accepting_endpoint = local_endpoint.clone();
        let accepting_identity = std::sync::Arc::clone(&local);
        let accept = tokio::spawn(async move {
            accept_peer_any_dynamic(
                &accepting_endpoint,
                "dynamic-allowlist",
                &accepting_identity,
                allowed_rx,
            )
            .await
        });
        allowed_tx
            .send(vec![(peer.device_id(), peer.public_key())])
            .unwrap();
        let peer_channel = connect_peer(
            &endpoint_peer,
            local_endpoint.local_addr().unwrap(),
            "dynamic-allowlist",
            &peer,
            &local.device_id(),
            local.public_key(),
        )
        .await
        .unwrap();
        let (accepted_id, local_channel) = accept.await.unwrap().unwrap();
        assert_eq!(accepted_id, peer.device_id());
        peer_channel
            .send_packet(b"authorized after refresh")
            .await
            .unwrap();
        assert_eq!(
            local_channel.recv_packet().await.unwrap(),
            b"authorized after refresh"
        );
        endpoint_peer.close(0_u32.into(), b"test complete");
        local_endpoint.close(0_u32.into(), b"test complete");
        fs::remove_dir_all(temp).unwrap();
    }

    #[tokio::test]
    async fn simultaneous_udp_connects_are_authenticated_and_one_path_is_elected() {
        let temp = std::env::temp_dir().join(format!("mini-tunnel-punch-{}", uuid::Uuid::new_v4()));
        let a = std::sync::Arc::new(
            Identity::load_or_create_at(temp.join("a/device.key")).expect("identity A"),
        );
        let b = std::sync::Arc::new(
            Identity::load_or_create_at(temp.join("b/device.key")).expect("identity B"),
        );
        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let endpoint_a = peer_endpoint(&a, bind).expect("endpoint A");
        let endpoint_b = peer_endpoint(&b, bind).expect("endpoint B");
        let a_id = a.device_id();
        let b_id = b.device_id();
        let a_key = a.public_key();
        let b_key = b.public_key();
        let accept_a_endpoint = endpoint_a.clone();
        let accept_a_identity = std::sync::Arc::clone(&a);
        let accept_a_allowed = vec![(b_id.clone(), b_key)];
        let accept_a = tokio::spawn(async move {
            accept_peer_any(
                &accept_a_endpoint,
                "punch",
                &accept_a_identity,
                &accept_a_allowed,
            )
            .await
        });
        let accept_b_endpoint = endpoint_b.clone();
        let accept_b_identity = std::sync::Arc::clone(&b);
        let accept_b_allowed = vec![(a_id.clone(), a_key)];
        let accept_b = tokio::spawn(async move {
            accept_peer_any(
                &accept_b_endpoint,
                "punch",
                &accept_b_identity,
                &accept_b_allowed,
            )
            .await
        });

        let (outbound_a, outbound_b) = tokio::join!(
            connect_peer(
                &endpoint_a,
                endpoint_b.local_addr().expect("B address"),
                "punch",
                &a,
                &b_id,
                b_key,
            ),
            connect_peer(
                &endpoint_b,
                endpoint_a.local_addr().expect("A address"),
                "punch",
                &b,
                &a_id,
                a_key,
            ),
        );
        let outbound_a = outbound_a.expect("A's simultaneous UDP check");
        let outbound_b = outbound_b.expect("B's simultaneous UDP check");
        let (accepted_a_id, inbound_a) = accept_a.await.expect("accept A task").expect("accept A");
        let (accepted_b_id, inbound_b) = accept_b.await.expect("accept B task").expect("accept B");
        assert_eq!(accepted_a_id, b_id);
        assert_eq!(accepted_b_id, a_id);

        let (sender, receiver, discarded_a, discarded_b) = if a_id < b_id {
            (outbound_a, inbound_b, inbound_a, outbound_b)
        } else {
            (outbound_b, inbound_a, outbound_a, inbound_b)
        };
        discarded_a.close();
        discarded_b.close();
        sender
            .send_packet(b"authenticated hole-punch path")
            .await
            .expect("send packet");
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), receiver.recv_packet())
                .await
                .expect("packet timeout")
                .expect("receive packet"),
            b"authenticated hole-punch path"
        );

        endpoint_a.close(0_u32.into(), b"test complete");
        endpoint_b.close(0_u32.into(), b"test complete");
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
