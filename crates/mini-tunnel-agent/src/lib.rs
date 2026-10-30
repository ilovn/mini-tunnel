//! Local device identity and signing helpers used by the CLI and tunnel agent.

pub mod candidate;
pub mod ice;
pub mod membership;
pub mod routing;
pub mod stun;
pub mod tun_device;
pub mod tunnel;

use std::{
    collections::{HashMap, VecDeque},
    fs,
    io::{self, Read, Write},
    net::SocketAddr,
    path::PathBuf,
    sync::Mutex,
    time::{Duration, Instant},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use futures_util::{StreamExt, stream::FuturesUnordered};
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
    #[error("identity file path must be a regular file, not a symbolic link or reparse point")]
    UnsafePath,
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
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700).recursive(true).create(parent)?;
        }
        #[cfg(not(unix))]
        fs::create_dir_all(parent)?;

        match read_identity_seed(&path) {
            Ok(seed) => return Ok(Self::from_seed(&seed)),
            Err(IdentityError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }

        let mut seed = [0_u8; 32];
        getrandom::fill(&mut seed).map_err(|_| IdentityError::Random)?;
        match create_identity_no_clobber(&path, &seed) {
            Ok(()) => Ok(Self::from_seed(&seed)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                let winner = read_identity_seed(&path)?;
                Ok(Self::from_seed(&winner))
            }
            Err(error) => Err(error.into()),
        }
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

fn read_identity_seed(path: &std::path::Path) -> Result<[u8; 32], IdentityError> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    configure_identity_no_follow(&mut options);
    let file = options.open(path).map_err(normalize_identity_open_error)?;
    let metadata = file.metadata()?;
    reject_identity_reparse_point(&metadata)?;
    if !metadata.is_file() {
        return Err(IdentityError::UnsafePath);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(IdentityError::UnsafePermissions);
        }
    }
    let mut bytes = Vec::with_capacity(33);
    file.take(33).read_to_end(&mut bytes)?;
    bytes.try_into().map_err(|_| IdentityError::InvalidKey)
}

fn create_identity_no_clobber(path: &std::path::Path, seed: &[u8; 32]) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    let file_name = path.file_name().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "identity path has no filename")
    })?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let temporary = path.with_file_name(format!(
        ".{}.{}.tmp",
        file_name.to_string_lossy(),
        uuid::Uuid::new_v4()
    ));
    let result = (|| {
        let mut file = options.open(&temporary)?;
        file.write_all(seed)?;
        file.sync_all()?;
        drop(file);
        fs::hard_link(&temporary, path)?;
        // The final link is the no-clobber commit point. Directory sync is best effort once it
        // becomes visible so callers never report failure after a valid identity was published.
        sync_identity_parent(parent);
        Ok(())
    })();
    let _ = fs::remove_file(temporary);
    result
}

fn sync_identity_parent(parent: &std::path::Path) {
    #[cfg(unix)]
    {
        let _ = fs::File::open(parent).and_then(|directory| directory.sync_all());
    }
    #[cfg(not(unix))]
    let _ = parent;
}

#[cfg(unix)]
fn configure_identity_no_follow(options: &mut fs::OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
}

#[cfg(windows)]
fn configure_identity_no_follow(options: &mut fs::OpenOptions) {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
    options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
}

#[cfg(not(any(unix, windows)))]
fn configure_identity_no_follow(_options: &mut fs::OpenOptions) {}

fn reject_identity_reparse_point(metadata: &fs::Metadata) -> Result<(), IdentityError> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(IdentityError::UnsafePath);
        }
    }
    let _ = metadata;
    Ok(())
}

fn normalize_identity_open_error(error: io::Error) -> IdentityError {
    #[cfg(unix)]
    if error.raw_os_error() == Some(libc::ELOOP) {
        return IdentityError::UnsafePath;
    }
    IdentityError::Io(error)
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
const MAX_TUN_PACKET: usize = 9000;
const MAX_PENDING_PROBE_PACKETS: usize = 64;
const MAX_PENDING_PROBE_BYTES: usize = 512 * 1024;
const FRAME_HEADER_LEN: usize = 25;
const FRAGMENT_HEADER_LEN: usize = 16;
const MAX_PACKET_FRAGMENTS: usize = 64;
const MAX_INCOMPLETE_PACKETS: usize = 4;
const FRAGMENT_TTL: Duration = Duration::from_secs(5);
const PEER_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const TCP_PEER_FRAME_WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_PENDING_QUIC_HANDSHAKES: usize = 32;
const MAX_PENDING_TCP_HANDSHAKES: usize = 32;
const UDP_CANDIDATE_TIMEOUT: Duration = Duration::from_secs(2);
const TCP_CANDIDATE_TIMEOUT: Duration = Duration::from_secs(5);
const CANDIDATE_CONNECT_BUDGET: Duration = Duration::from_secs(30);
const UDP_CANDIDATE_PARALLELISM: usize = 4;
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
    send_lock: tokio::sync::Mutex<()>,
    replay_window: Mutex<ReplayWindow>,
    fragments: Mutex<FragmentReassembler>,
    pending_probe_packets: Mutex<PendingProbePackets>,
    health: Mutex<PeerHealth>,
    ice_consent: Option<ice::IceConsentMonitor>,
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

#[derive(Default)]
struct PendingProbePackets {
    packets: VecDeque<Vec<u8>>,
    bytes: usize,
}

impl PendingProbePackets {
    fn push(&mut self, packet: Vec<u8>) -> Result<(), IdentityError> {
        if self.packets.len() >= MAX_PENDING_PROBE_PACKETS
            || self.bytes.saturating_add(packet.len()) > MAX_PENDING_PROBE_BYTES
        {
            return Err(IdentityError::Transport(
                "candidate probe packet buffer is full".to_owned(),
            ));
        }
        self.bytes += packet.len();
        self.packets.push_back(packet);
        Ok(())
    }

    fn pop(&mut self) -> Option<Vec<u8>> {
        let packet = self.packets.pop_front()?;
        self.bytes = self.bytes.saturating_sub(packet.len());
        Some(packet)
    }
}

#[derive(Default)]
struct FragmentReassembler {
    packets: HashMap<u64, FragmentAssembly>,
}

struct FragmentAssembly {
    created: Instant,
    total_len: usize,
    chunk_size: usize,
    chunks: Vec<Option<Vec<u8>>>,
    received: usize,
}

struct DecodedFrame<'a> {
    sequence: u64,
    payload: &'a [u8],
    fragment: Option<DecodedFragment<'a>>,
}

#[derive(Clone, Copy)]
struct DecodedFragment<'a> {
    packet_id: u64,
    index: usize,
    count: usize,
    total_len: usize,
    chunk_size: usize,
    payload: &'a [u8],
}

impl FragmentReassembler {
    fn accept(&mut self, fragment: DecodedFragment<'_>) -> Result<Option<Vec<u8>>, IdentityError> {
        self.packets
            .retain(|_, packet| packet.created.elapsed() < FRAGMENT_TTL);
        let expected_count = fragment.total_len.div_ceil(fragment.chunk_size.max(1));
        let expected_len = if fragment.index + 1 == fragment.count {
            fragment
                .total_len
                .saturating_sub(fragment.chunk_size * fragment.index)
        } else {
            fragment.chunk_size
        };
        if fragment.count < 2
            || fragment.count > MAX_PACKET_FRAGMENTS
            || fragment.index >= fragment.count
            || fragment.total_len == 0
            || fragment.total_len > MAX_TUN_PACKET
            || fragment.chunk_size == 0
            || expected_count != fragment.count
            || fragment.payload.len() != expected_len
        {
            self.packets.remove(&fragment.packet_id);
            return Err(IdentityError::InvalidFrame);
        }
        if !self.packets.contains_key(&fragment.packet_id)
            && self.packets.len() >= MAX_INCOMPLETE_PACKETS
            && let Some(oldest) = self
                .packets
                .iter()
                .min_by_key(|(_, packet)| packet.created)
                .map(|(id, _)| *id)
        {
            self.packets.remove(&oldest);
        }
        let assembly = self
            .packets
            .entry(fragment.packet_id)
            .or_insert_with(|| FragmentAssembly {
                created: Instant::now(),
                total_len: fragment.total_len,
                chunk_size: fragment.chunk_size,
                chunks: vec![None; fragment.count],
                received: 0,
            });
        if assembly.total_len != fragment.total_len
            || assembly.chunk_size != fragment.chunk_size
            || assembly.chunks.len() != fragment.count
            || assembly.chunks[fragment.index].is_some()
        {
            self.packets.remove(&fragment.packet_id);
            return Err(IdentityError::InvalidFrame);
        }
        assembly.received += fragment.payload.len();
        assembly.chunks[fragment.index] = Some(fragment.payload.to_vec());
        if assembly.chunks.iter().any(Option::is_none) {
            return Ok(None);
        }
        let mut assembly = self
            .packets
            .remove(&fragment.packet_id)
            .ok_or(IdentityError::InvalidFrame)?;
        let mut packet = Vec::with_capacity(assembly.total_len);
        for chunk in assembly.chunks.drain(..) {
            packet.extend_from_slice(&chunk.ok_or(IdentityError::InvalidFrame)?);
        }
        if packet.len() != assembly.total_len || assembly.received != assembly.total_len {
            return Err(IdentityError::InvalidFrame);
        }
        Ok(Some(packet))
    }
}

impl PeerChannel {
    /// Attach the nominated ICE session whose consent lifetime follows this channel.
    pub fn set_ice_consent_monitor(&mut self, monitor: ice::IceConsentMonitor) {
        self.ice_consent = Some(monitor);
    }

    /// Resolve when ICE consent expires; channels without ICE consent remain pending.
    pub async fn wait_ice_consent_failure(&self) {
        let Some(monitor) = &self.ice_consent else {
            std::future::pending::<()>().await;
            return;
        };
        let mut failed = monitor.failure_receiver();
        loop {
            if *failed.borrow() {
                return;
            }
            if failed.changed().await.is_err() {
                return;
            }
        }
    }

    /// Stop this channel's ICE driver and wait for its router registration to be released.
    pub async fn stop_ice_consent_monitor(&self) {
        if let Some(monitor) = &self.ice_consent {
            monitor.stop().await;
        }
    }

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

    /// Close the peer transport, including the write half of a TLS/TCP session.
    pub async fn close_async(&self) {
        self.close();
        if let PeerTransport::Tcp(transport) = &self.transport {
            let mut sender = transport.sender.lock().await;
            let _ = sender.shutdown().await;
        }
    }

    /// Send one bounded packet, fragmenting it when the transport frame cannot carry it whole.
    pub async fn send_packet(&self, payload: &[u8]) -> Result<(), IdentityError> {
        let _send_guard = self.send_lock.lock().await;
        if payload.len() > MAX_TUN_PACKET {
            return Err(IdentityError::InvalidFrame);
        }
        let transport_limit = match &self.transport {
            PeerTransport::Quic(connection) => connection
                .max_datagram_size()
                .ok_or(IdentityError::InvalidFrame)?,
            PeerTransport::Tcp(_) => FRAME_HEADER_LEN + MAX_PACKET_PAYLOAD,
        };
        let single_capacity = single_frame_payload_limit(transport_limit);
        if payload.len() <= single_capacity {
            let sequence = self.reserve_sequences(1)?;
            let frame = encode_frame(self.network_tag, sequence, payload);
            return self.send_frame(frame).await;
        }
        let fragment_capacity = fragment_payload_limit(transport_limit);
        if fragment_capacity == 0 {
            return Err(IdentityError::InvalidFrame);
        }
        let count = payload.len().div_ceil(fragment_capacity);
        if count > MAX_PACKET_FRAGMENTS {
            return Err(IdentityError::InvalidFrame);
        }
        let first_sequence = self.reserve_sequences(count)?;
        let total_len = u16::try_from(payload.len()).map_err(|_| IdentityError::InvalidFrame)?;
        let chunk_size =
            u16::try_from(fragment_capacity).map_err(|_| IdentityError::InvalidFrame)?;
        for (index, chunk) in payload.chunks(fragment_capacity).enumerate() {
            let sequence = first_sequence + index as u64;
            let frame = encode_fragment_frame(
                self.network_tag,
                sequence,
                first_sequence,
                index,
                count,
                total_len,
                chunk_size,
                chunk,
            );
            self.send_frame(frame).await?;
        }
        Ok(())
    }

    fn reserve_sequences(&self, count: usize) -> Result<u64, IdentityError> {
        let mut next_packet = self
            .next_packet
            .lock()
            .map_err(|_| IdentityError::InvalidFrame)?;
        let first = *next_packet;
        *next_packet = next_packet
            .checked_add(count as u64)
            .ok_or(IdentityError::InvalidFrame)?;
        Ok(first)
    }

    async fn send_frame(&self, frame: Vec<u8>) -> Result<(), IdentityError> {
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
                write_tcp_peer_frame(transport, &frame, TCP_PEER_FRAME_WRITE_TIMEOUT).await
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
                let packet = tokio::time::timeout_at(deadline, self.recv_packet_from_transport())
                    .await
                    .map_err(|_| {
                        IdentityError::Transport("candidate path probe timed out".to_owned())
                    })??;
                if !packet.is_empty() {
                    self.pending_probe_packets
                        .lock()
                        .map_err(|_| IdentityError::InvalidFrame)?
                        .push(packet)?;
                }
                let health = self.health_snapshot();
                if health.probes_succeeded > succeeded_before {
                    maximum_rtt = maximum_rtt.max(health.rtt.unwrap_or_default());
                    break;
                }
            }
        }
        Ok(maximum_rtt)
    }

    /// Receive one authenticated packet, reassembling bounded transport fragments as needed.
    pub async fn recv_packet(&self) -> Result<Vec<u8>, IdentityError> {
        if let Some(packet) = self
            .pending_probe_packets
            .lock()
            .map_err(|_| IdentityError::InvalidFrame)?
            .pop()
        {
            return Ok(packet);
        }
        self.recv_packet_from_transport().await
    }

    async fn recv_packet_from_transport(&self) -> Result<Vec<u8>, IdentityError> {
        loop {
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
                    if !(FRAME_HEADER_LEN..=FRAME_HEADER_LEN + MAX_PACKET_PAYLOAD)
                        .contains(&frame_len)
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
            let decoded =
                decode_any_frame(&frame, self.network_tag).ok_or(IdentityError::InvalidFrame)?;
            let sequence = decoded.sequence;
            if !self
                .replay_window
                .lock()
                .map_err(|_| IdentityError::InvalidFrame)?
                .accept(sequence)
            {
                return Err(IdentityError::InvalidFrame);
            }
            let payload = match decoded.fragment {
                Some(fragment) => {
                    let packet = self
                        .fragments
                        .lock()
                        .map_err(|_| IdentityError::InvalidFrame)?
                        .accept(fragment)?;
                    let Some(packet) = packet else { continue };
                    packet
                }
                None => decoded.payload.to_vec(),
            };
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
            return Ok(payload);
        }
    }
}

async fn write_tcp_peer_frame(
    transport: &TcpPeerTransport,
    frame: &[u8],
    timeout: Duration,
) -> Result<(), IdentityError> {
    let write_result = tokio::time::timeout(timeout, async {
        let mut sender = transport.sender.lock().await;
        sender.write_u32(frame.len() as u32).await?;
        sender.write_all(frame).await
    })
    .await;
    match write_result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => {
            let mut sender = transport.sender.lock().await;
            let _ = sender.shutdown().await;
            Err(IdentityError::Transport(error.to_string()))
        }
        Err(error) => {
            let mut sender = transport.sender.lock().await;
            let _ = sender.shutdown().await;
            Err(IdentityError::Transport(error.to_string()))
        }
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
    let mut handshakes = FuturesUnordered::new();
    loop {
        tokio::select! {
            accepted = listener.accept(), if handshakes.len() < MAX_PENDING_TCP_HANDSHAKES => {
                let (socket, remote_addr) = accepted?;
                let _ = socket.set_nodelay(true);
                handshakes.push(authenticate_tcp_candidate(
                    socket,
                    remote_addr,
                    acceptor.clone(),
                    network_id,
                    identity,
                    allowed_peers,
                ));
            }
            result = handshakes.next(), if !handshakes.is_empty() => {
                if let Some(Some(peer)) = result {
                    return Ok(peer);
                }
            }
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
    let mut handshakes = FuturesUnordered::new();
    loop {
        tokio::select! {
            accepted = listener.accept(), if handshakes.len() < MAX_PENDING_TCP_HANDSHAKES => {
                let (socket, remote_addr) = accepted?;
                let _ = socket.set_nodelay(true);
                let network_id = network_id.to_owned();
                let acceptor = acceptor.clone();
                let allowed_peers = allowed_peers.clone();
                handshakes.push(async move {
                    authenticate_tcp_candidate_dynamic(
                        socket,
                        remote_addr,
                        acceptor,
                        &network_id,
                        identity,
                        &allowed_peers,
                    )
                    .await
                });
            }
            result = handshakes.next(), if !handshakes.is_empty() => {
                if let Some(Some(peer)) = result {
                    return Ok(peer);
                }
            }
        }
    }
}

async fn authenticate_tcp_candidate(
    socket: tokio::net::TcpStream,
    remote_addr: SocketAddr,
    acceptor: tokio_rustls::TlsAcceptor,
    network_id: &str,
    identity: &Identity,
    allowed_peers: &[(String, [u8; 32])],
) -> Option<(String, PeerChannel)> {
    let mut stream = tokio::time::timeout(PEER_HANDSHAKE_TIMEOUT, acceptor.accept(socket))
        .await
        .ok()?
        .ok()?;
    if stream.get_ref().1.alpn_protocol() != Some(b"mini-tunnel-peer-tcp/1") {
        return None;
    }
    let device_id = tokio::time::timeout(
        PEER_HANDSHAKE_TIMEOUT,
        tcp_server_authenticate(&mut stream, network_id, identity, allowed_peers),
    )
    .await
    .ok()?
    .ok()?;
    Some((
        device_id,
        new_tcp_channel(Box::new(stream), remote_addr, network_id),
    ))
}

async fn authenticate_tcp_candidate_dynamic(
    socket: tokio::net::TcpStream,
    remote_addr: SocketAddr,
    acceptor: tokio_rustls::TlsAcceptor,
    network_id: &str,
    identity: &Identity,
    allowed_peers: &tokio::sync::watch::Receiver<Vec<(String, [u8; 32])>>,
) -> Option<(String, PeerChannel)> {
    let mut stream = tokio::time::timeout(PEER_HANDSHAKE_TIMEOUT, acceptor.accept(socket))
        .await
        .ok()?
        .ok()?;
    if stream.get_ref().1.alpn_protocol() != Some(b"mini-tunnel-peer-tcp/1") {
        return None;
    }
    let current = allowed_peers.borrow().clone();
    if current.is_empty() || !valid_peer_allowlist(&current) {
        return None;
    }
    let device_id = tokio::time::timeout(
        PEER_HANDSHAKE_TIMEOUT,
        tcp_server_authenticate(&mut stream, network_id, identity, &current),
    )
    .await
    .ok()?
    .ok()?;
    let latest = allowed_peers.borrow().clone();
    if !valid_peer_allowlist(&latest)
        || !latest
            .iter()
            .any(|(allowed_id, _)| allowed_id == &device_id)
    {
        return None;
    }
    Some((
        device_id,
        new_tcp_channel(Box::new(stream), remote_addr, network_id),
    ))
}

/// Race bounded batches of signed UDP candidates, then try TCP with a bounded fallback.
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
    let udp_candidates: Vec<_> = checklist
        .checks()
        .iter()
        .enumerate()
        .filter(|(_, check)| check.transport == candidate::CandidateTransport::Udp)
        .map(|(index, check)| (index, check.address))
        .collect();
    for batch in udp_candidates.chunks(UDP_CANDIDATE_PARALLELISM) {
        let mut attempts = FuturesUnordered::new();
        for &(index, address) in batch {
            checklist.mark_in_progress(index);
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            let attempt_timeout = UDP_CANDIDATE_TIMEOUT.min(remaining);
            attempts.push(async move {
                let result = tokio::time::timeout(
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
                .await;
                (index, address, result)
            });
        }
        while let Some((index, address, connection)) = attempts.next().await {
            match connection {
                Ok(Ok(channel)) => {
                    checklist.finish(index, true);
                    return Ok((channel, address));
                }
                Ok(Err(error @ IdentityError::UnauthorizedPeer)) => {
                    checklist.finish(index, false);
                    last_error = Some(error.to_string());
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
        if tokio::time::Instant::now() >= deadline {
            break;
        }
    }

    while let Some(index) = checklist.next_waiting() {
        checklist.mark_in_progress(index);
        let candidate = checklist.checks()[index].clone();
        let address = candidate.address;
        debug_assert_eq!(candidate.transport, candidate::CandidateTransport::Tcp);
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            checklist.finish(index, false);
            break;
        }
        let attempt_timeout = TCP_CANDIDATE_TIMEOUT.min(remaining);
        let connection = tokio::time::timeout(
            attempt_timeout,
            connect_tcp_peer(
                address,
                network_id,
                identity,
                expected_peer_id,
                expected_peer_key,
            ),
        )
        .await;
        match connection {
            Ok(Ok(channel)) => {
                checklist.finish(index, true);
                return Ok((channel, address));
            }
            Ok(Err(error @ IdentityError::UnauthorizedPeer)) => {
                checklist.finish(index, false);
                last_error = Some(error.to_string());
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
    accept_peer_with_timeout(
        endpoint,
        network_id,
        identity,
        Some((expected_peer_id, expected_peer_key)),
        PEER_HANDSHAKE_TIMEOUT,
    )
    .await
}

async fn accept_peer_with_timeout(
    endpoint: &Endpoint,
    network_id: &str,
    identity: &Identity,
    expected_peer: Option<(&str, [u8; 32])>,
    timeout: Duration,
) -> Result<PeerChannel, IdentityError> {
    tokio::time::timeout(timeout, async {
        let incoming = endpoint
            .accept()
            .await
            .ok_or_else(|| IdentityError::Transport("endpoint closed".to_owned()))?;
        let connection = incoming
            .await
            .map_err(|error| IdentityError::Transport(error.to_string()))?;
        server_authenticate(&connection, network_id, identity, expected_peer, None).await?;
        Ok(new_channel(connection, network_id))
    })
    .await
    .map_err(|error| IdentityError::Transport(error.to_string()))?
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
    let mut handshakes = FuturesUnordered::new();
    loop {
        tokio::select! {
            incoming = endpoint.accept(), if handshakes.len() < MAX_PENDING_QUIC_HANDSHAKES => {
                let Some(incoming) = incoming else {
                    return Err(IdentityError::Transport("endpoint closed".to_owned()));
                };
                handshakes.push(authenticate_quic_candidate(
                    incoming,
                    network_id,
                    identity,
                    allowed_peers,
                ));
            }
            result = handshakes.next(), if !handshakes.is_empty() => {
                if let Some(Some(peer)) = result {
                    return Ok(peer);
                }
            }
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
    let mut handshakes = FuturesUnordered::new();
    loop {
        tokio::select! {
            incoming = endpoint.accept(), if handshakes.len() < MAX_PENDING_QUIC_HANDSHAKES => {
                let Some(incoming) = incoming else {
                    return Err(IdentityError::Transport("endpoint closed".to_owned()));
                };
                let network_id = network_id.to_owned();
                let allowed_peers = allowed_peers.clone();
                handshakes.push(async move {
                    authenticate_quic_candidate_dynamic(
                        incoming,
                        &network_id,
                        identity,
                        &allowed_peers,
                    )
                    .await
                });
            }
            result = handshakes.next(), if !handshakes.is_empty() => {
                if let Some(Some(peer)) = result {
                    return Ok(peer);
                }
            }
        }
    }
}

async fn authenticate_quic_candidate(
    incoming: quinn::Incoming,
    network_id: &str,
    identity: &Identity,
    allowed_peers: &[(String, [u8; 32])],
) -> Option<(String, PeerChannel)> {
    let connection = tokio::time::timeout(PEER_HANDSHAKE_TIMEOUT, incoming)
        .await
        .ok()?
        .ok()?;
    match server_authenticate(&connection, network_id, identity, None, Some(allowed_peers)).await {
        Ok((device_id, _)) => Some((device_id, new_channel(connection, network_id))),
        Err(_) => {
            connection.close(0_u32.into(), b"peer authentication rejected");
            None
        }
    }
}

async fn authenticate_quic_candidate_dynamic(
    incoming: quinn::Incoming,
    network_id: &str,
    identity: &Identity,
    allowed_peers: &tokio::sync::watch::Receiver<Vec<(String, [u8; 32])>>,
) -> Option<(String, PeerChannel)> {
    let connection = tokio::time::timeout(PEER_HANDSHAKE_TIMEOUT, incoming)
        .await
        .ok()?
        .ok()?;
    let current = allowed_peers.borrow().clone();
    if current.is_empty() || !valid_peer_allowlist(&current) {
        connection.close(0_u32.into(), b"peer is not currently authorized");
        return None;
    }
    match server_authenticate(&connection, network_id, identity, None, Some(&current)).await {
        Ok((device_id, public_key)) => {
            let latest = allowed_peers.borrow().clone();
            if !valid_peer_allowlist(&latest)
                || !latest.iter().any(|(allowed_id, allowed_key)| {
                    allowed_id == &device_id && allowed_key == &public_key
                })
            {
                connection.close(0_u32.into(), b"peer is not currently authorized");
                None
            } else {
                Some((device_id, new_channel(connection, network_id)))
            }
        }
        Err(_) => {
            connection.close(0_u32.into(), b"peer authentication rejected");
            None
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
        send_lock: tokio::sync::Mutex::new(()),
        replay_window: Mutex::new(ReplayWindow::default()),
        fragments: Mutex::new(FragmentReassembler::default()),
        pending_probe_packets: Mutex::new(PendingProbePackets::default()),
        health: Mutex::new(PeerHealth::default()),
        ice_consent: None,
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
        send_lock: tokio::sync::Mutex::new(()),
        replay_window: Mutex::new(ReplayWindow::default()),
        fragments: Mutex::new(FragmentReassembler::default()),
        pending_probe_packets: Mutex::new(PendingProbePackets::default()),
        health: Mutex::new(PeerHealth::default()),
        ice_consent: None,
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

fn single_frame_payload_limit(transport_limit: usize) -> usize {
    transport_limit
        .saturating_sub(FRAME_HEADER_LEN)
        .min(MAX_PACKET_PAYLOAD)
}

fn fragment_payload_limit(transport_limit: usize) -> usize {
    transport_limit
        .saturating_sub(FRAME_HEADER_LEN + FRAGMENT_HEADER_LEN)
        .min(MAX_PACKET_PAYLOAD - FRAGMENT_HEADER_LEN)
}

#[allow(clippy::too_many_arguments)]
fn encode_fragment_frame(
    network_tag: [u8; 16],
    sequence: u64,
    packet_id: u64,
    index: usize,
    count: usize,
    total_len: u16,
    chunk_size: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut frame = Vec::with_capacity(FRAME_HEADER_LEN + FRAGMENT_HEADER_LEN + payload.len());
    frame.push(2);
    frame.extend_from_slice(&network_tag);
    frame.extend_from_slice(&sequence.to_be_bytes());
    frame.extend_from_slice(&packet_id.to_be_bytes());
    frame.extend_from_slice(&(index as u16).to_be_bytes());
    frame.extend_from_slice(&(count as u16).to_be_bytes());
    frame.extend_from_slice(&total_len.to_be_bytes());
    frame.extend_from_slice(&chunk_size.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

fn decode_any_frame(frame: &[u8], network_tag: [u8; 16]) -> Option<DecodedFrame<'_>> {
    if frame.len() < FRAME_HEADER_LEN || frame[1..17] != network_tag {
        return None;
    }
    let sequence = u64::from_be_bytes(frame[17..25].try_into().ok()?);
    match frame[0] {
        1 if frame.len() <= FRAME_HEADER_LEN + MAX_PACKET_PAYLOAD => Some(DecodedFrame {
            sequence,
            payload: &frame[FRAME_HEADER_LEN..],
            fragment: None,
        }),
        2 if frame.len() > FRAME_HEADER_LEN + FRAGMENT_HEADER_LEN
            && frame.len() <= FRAME_HEADER_LEN + MAX_PACKET_PAYLOAD =>
        {
            let packet_id = u64::from_be_bytes(frame[25..33].try_into().ok()?);
            let index = usize::from(u16::from_be_bytes(frame[33..35].try_into().ok()?));
            let count = usize::from(u16::from_be_bytes(frame[35..37].try_into().ok()?));
            let total_len = usize::from(u16::from_be_bytes(frame[37..39].try_into().ok()?));
            let chunk_size = usize::from(u16::from_be_bytes(frame[39..41].try_into().ok()?));
            if packet_id.checked_add(index as u64)? != sequence {
                return None;
            }
            Some(DecodedFrame {
                sequence,
                payload: &[],
                fragment: Some(DecodedFragment {
                    packet_id,
                    index,
                    count,
                    total_len,
                    chunk_size,
                    payload: &frame[FRAME_HEADER_LEN + FRAGMENT_HEADER_LEN..],
                }),
            })
        }
        _ => None,
    }
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
    fn pending_probe_packet_buffer_is_ordered_and_bounded() {
        let mut pending = PendingProbePackets::default();
        pending.push(vec![1; MAX_TUN_PACKET]).expect("first packet");
        pending
            .push(vec![2; MAX_TUN_PACKET])
            .expect("second packet");
        assert_eq!(pending.bytes, 2 * MAX_TUN_PACKET);
        assert_eq!(pending.pop(), Some(vec![1; MAX_TUN_PACKET]));
        assert_eq!(pending.bytes, MAX_TUN_PACKET);
        assert_eq!(pending.pop(), Some(vec![2; MAX_TUN_PACKET]));

        for _ in 0..MAX_PENDING_PROBE_PACKETS {
            pending.push(vec![0]).expect("packet within item limit");
        }
        assert!(pending.push(vec![3]).is_err());

        let mut oversized = PendingProbePackets::default();
        assert!(
            oversized
                .push(vec![0; MAX_PENDING_PROBE_BYTES + 1])
                .is_err()
        );
    }

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
    fn identity_creation_does_not_change_existing_parent_permissions() {
        let dir = std::env::temp_dir().join(format!(
            "mini-tunnel-identity-parent-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&dir).expect("create parent directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o755))
                .expect("set existing parent permissions");
        }
        let path = dir.join("device.key");
        Identity::load_or_create_at(path).expect("create identity in existing parent");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&dir)
                    .expect("parent metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o755
            );
        }
        fs::remove_dir_all(dir).expect("remove parent directory");
    }

    #[cfg(unix)]
    #[test]
    fn identity_loader_rejects_symbolic_links_without_reading_the_target() {
        let dir = std::env::temp_dir().join(format!(
            "mini-tunnel-identity-symlink-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&dir).expect("create test directory");
        let target = dir.join("target.key");
        fs::write(&target, [17_u8; 32]).expect("write target seed");
        use std::os::unix::fs::{PermissionsExt, symlink};
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600))
            .expect("set target permissions");
        let path = dir.join("device.key");
        symlink(&target, &path).expect("create identity symlink");
        assert!(matches!(
            Identity::load_or_create_at(path),
            Err(IdentityError::UnsafePath)
        ));
        assert_eq!(
            fs::read(&target).expect("target remains intact"),
            [17_u8; 32]
        );
        fs::remove_dir_all(dir).expect("remove test directory");
    }

    #[test]
    fn concurrent_identity_creation_publishes_one_stable_seed_without_temp_files() {
        let dir = std::env::temp_dir().join(format!(
            "mini-tunnel-identity-race-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&dir).expect("create test directory");
        let path = dir.join("device.key");
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
        let workers = (0..8)
            .map(|_| {
                let path = path.clone();
                let barrier = std::sync::Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    Identity::load_or_create_at(path)
                        .expect("concurrent identity load or create")
                        .device_id()
                })
            })
            .collect::<Vec<_>>();
        let ids = workers
            .into_iter()
            .map(|worker| worker.join().expect("identity worker"))
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(ids.len(), 1);
        assert_eq!(fs::metadata(&path).expect("identity file").len(), 32);
        assert_eq!(
            fs::read_dir(&dir).expect("identity directory").count(),
            1,
            "temporary seed links are cleaned after publication"
        );
        fs::remove_dir_all(dir).expect("remove test directory");
    }

    #[tokio::test]
    async fn async_peer_close_terminates_a_tcp_peer_read_loop() {
        let (stream_a, stream_b) = tokio::io::duplex(128);
        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 42000);
        let channel_a = new_tcp_channel(Box::new(stream_a), address, "office");
        let channel_b = new_tcp_channel(Box::new(stream_b), address, "office");
        channel_a.close_async().await;
        assert!(
            tokio::time::timeout(Duration::from_secs(1), channel_b.recv_packet())
                .await
                .expect("TCP close reaches the peer")
                .is_err()
        );
    }

    #[test]
    fn rejects_malformed_identity_file() {
        let dir =
            std::env::temp_dir().join(format!("mini-tunnel-identity-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).expect("create temp directory");
        let path = dir.join("device.key");
        fs::write(&path, b"short").expect("write malformed key");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .expect("set safe test-key permissions");
        }
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
        let large_packet = (0..4096).map(|byte| (byte % 251) as u8).collect::<Vec<_>>();
        channel_a
            .send_packet(&large_packet)
            .await
            .expect("send fragmented IPv6-sized packet");
        assert_eq!(
            channel_b.recv_packet().await.expect("reassemble packet"),
            large_packet
        );
        assert!(matches!(
            channel_a.send_packet(&vec![0; MAX_TUN_PACKET + 1]).await,
            Err(IdentityError::InvalidFrame)
        ));
        endpoint_a.close(0_u32.into(), b"test complete");
        endpoint_b.close(0_u32.into(), b"test complete");
        fs::remove_dir_all(temp).expect("remove test identities");
    }

    #[tokio::test]
    async fn candidate_health_probe_preserves_payloads_for_the_tunnel_receiver() {
        let temp =
            std::env::temp_dir().join(format!("mini-tunnel-probe-buffer-{}", uuid::Uuid::new_v4()));
        let a = Identity::load_or_create_at(temp.join("a/device.key")).expect("identity A");
        let b = Identity::load_or_create_at(temp.join("b/device.key")).expect("identity B");
        let endpoint_a = peer_endpoint(&a, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .expect("endpoint A");
        let endpoint_b = peer_endpoint(&b, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .expect("endpoint B");
        let remote = endpoint_b.local_addr().expect("endpoint B address");
        let a_id = a.device_id();
        let a_key = a.public_key();
        let b_id = b.device_id();
        let b_key = b.public_key();
        let server_endpoint = endpoint_b.clone();
        let accept = tokio::spawn(async move {
            accept_peer(&server_endpoint, "probe-buffer", &b, &a_id, a_key).await
        });
        let channel_a = tokio::time::timeout(
            Duration::from_secs(3),
            connect_peer(&endpoint_a, remote, "probe-buffer", &a, &b_id, b_key),
        )
        .await
        .expect("connection handshake timed out")
        .expect("authenticated QUIC peer");
        let channel_b = accept.await.expect("accept task").expect("accepted peer");

        let payload = b"packet received while the candidate is being probed";
        channel_b
            .send_packet(payload)
            .await
            .expect("queue peer payload before health probe");
        let (release_server_tx, release_server_rx) = tokio::sync::oneshot::channel();
        let respond_to_probe = tokio::spawn(async move {
            let response = channel_b.recv_packet().await;
            let _ = release_server_rx.await;
            response
        });
        tokio::time::timeout(
            Duration::from_secs(3),
            channel_a.probe_health(1, Duration::from_secs(2)),
        )
        .await
        .expect("candidate health probe did not finish")
        .expect("candidate path health probe");
        release_server_tx
            .send(())
            .expect("release probe server after client completes");
        assert!(
            respond_to_probe
                .await
                .expect("probe response task")
                .expect("receive probe ping")
                .is_empty()
        );
        assert_eq!(
            channel_a.recv_packet().await.expect("buffered payload"),
            payload,
            "candidate probing must not consume peer data"
        );

        endpoint_a.close(0_u32.into(), b"test complete");
        endpoint_b.close(0_u32.into(), b"test complete");
        fs::remove_dir_all(temp).expect("remove test identities");
    }

    #[tokio::test]
    async fn reachable_udp_candidate_does_not_wait_for_blackholed_candidates() {
        let temp = std::env::temp_dir().join(format!("mini-tunnel-race-{}", uuid::Uuid::new_v4()));
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
        let accept = tokio::spawn(async move {
            accept_peer(&server_endpoint, "race-net", &b, &a_id, a_key).await
        });
        let blackholes = [
            tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("blackhole one"),
            tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("blackhole two"),
            tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("blackhole three"),
        ];
        let mut candidates: Vec<_> = blackholes
            .iter()
            .map(|socket| socket.local_addr().unwrap().to_string())
            .collect();
        candidates.push(addr_b.to_string());

        let (channel, connected_addr) = tokio::time::timeout(
            Duration::from_secs(1),
            connect_peer_candidates(&endpoint_a, &candidates, "race-net", &a, &b_id, b_key),
        )
        .await
        .expect("valid candidate should connect before blackhole timeout")
        .expect("connect to reachable candidate");
        assert_eq!(connected_addr, addr_b);
        let accepted = accept
            .await
            .expect("accept task")
            .expect("authenticated peer");
        assert_eq!(channel.transport_name(), "QUIC/UDP");
        drop(accepted);
        endpoint_a.close(0_u32.into(), b"test complete");
        endpoint_b.close(0_u32.into(), b"test complete");
        drop(blackholes);
        fs::remove_dir_all(temp).expect("remove test identities");
    }

    #[tokio::test]
    async fn udp_candidate_authentication_failure_does_not_block_later_candidate() {
        let temp = std::env::temp_dir().join(format!(
            "mini-tunnel-udp-candidate-retry-{}",
            uuid::Uuid::new_v4()
        ));
        let a = Identity::load_or_create_at(temp.join("a/device.key")).expect("identity A");
        let b = std::sync::Arc::new(
            Identity::load_or_create_at(temp.join("b/device.key")).expect("identity B"),
        );
        let endpoint_a = peer_endpoint(&a, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .expect("UDP endpoint A");
        let wrong_endpoint = peer_endpoint(&b, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .expect("wrong-network endpoint");
        let correct_endpoint =
            peer_endpoint(&b, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
                .expect("correct-network endpoint");
        let expected_a = a.device_id();
        let expected_a_key = a.public_key();
        let wrong_server = wrong_endpoint.clone();
        let wrong_identity = std::sync::Arc::clone(&b);
        let wrong_accept = tokio::spawn(async move {
            accept_peer(
                &wrong_server,
                "another-network",
                &wrong_identity,
                &expected_a,
                expected_a_key,
            )
            .await
        });
        let expected_a = a.device_id();
        let expected_a_key = a.public_key();
        let correct_server = correct_endpoint.clone();
        let correct_identity = std::sync::Arc::clone(&b);
        let correct_accept = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            accept_peer(
                &correct_server,
                "office",
                &correct_identity,
                &expected_a,
                expected_a_key,
            )
            .await
        });

        let wrong_address = wrong_endpoint.local_addr().expect("wrong endpoint address");
        let correct_address = correct_endpoint
            .local_addr()
            .expect("correct endpoint address");
        let (channel, connected_address) = connect_peer_candidates(
            &endpoint_a,
            &[wrong_address.to_string(), correct_address.to_string()],
            "office",
            &a,
            &b.device_id(),
            b.public_key(),
        )
        .await
        .expect("the later authorized candidate should connect");
        assert_eq!(connected_address, correct_address);
        let accepted = correct_accept
            .await
            .expect("correct accept task")
            .expect("correct peer accepted");
        assert!(matches!(
            wrong_accept.await.expect("wrong accept task"),
            Err(IdentityError::UnauthorizedPeer)
        ));

        channel.close_async().await;
        accepted.close_async().await;
        endpoint_a.close(0_u32.into(), b"test complete");
        wrong_endpoint.close(0_u32.into(), b"test complete");
        correct_endpoint.close(0_u32.into(), b"test complete");
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
        let large_packet = (0..4096).map(|byte| (byte % 239) as u8).collect::<Vec<_>>();
        channel_a
            .send_packet(&large_packet)
            .await
            .expect("send fragmented TCP packet");
        assert_eq!(
            channel_b
                .recv_packet()
                .await
                .expect("reassemble TCP packet"),
            large_packet
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
            channel_a.send_packet(&vec![0; MAX_TUN_PACKET + 1]).await,
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
    async fn stalled_tcp_frame_write_times_out_and_closes_the_stream() {
        let (local, mut remote) = tokio::io::duplex(1);
        let local: BoxedPeerIo = Box::new(local);
        let (receiver, sender) = tokio::io::split(local);
        let transport = TcpPeerTransport {
            sender: tokio::sync::Mutex::new(sender),
            receiver: tokio::sync::Mutex::new(receiver),
            remote_address: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1),
        };
        let result =
            write_tcp_peer_frame(&transport, &[0x5a; 128], Duration::from_millis(25)).await;
        assert!(matches!(result, Err(IdentityError::Transport(_))));
        let mut partial_frame = Vec::new();
        remote.read_to_end(&mut partial_frame).await.unwrap();
        assert!(partial_frame.len() <= 4);
    }

    #[tokio::test]
    async fn stalled_tcp_handshake_does_not_block_later_valid_peer() {
        let temp = std::env::temp_dir().join(format!(
            "mini-tunnel-tcp-stalled-handshake-{}",
            uuid::Uuid::new_v4()
        ));
        let a = Identity::load_or_create_at(temp.join("a/device.key")).expect("identity A");
        let b = std::sync::Arc::new(
            Identity::load_or_create_at(temp.join("b/device.key")).expect("identity B"),
        );
        let listener = peer_tcp_listener(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .expect("TCP listener");
        let remote_addr = listener.local_addr().expect("TCP listener address");
        let expected_peer = (a.device_id(), a.public_key());
        let accept_identity = std::sync::Arc::clone(&b);
        let accept = tokio::spawn(async move {
            accept_tcp_peer_any(&listener, "slow-accept", &accept_identity, &[expected_peer]).await
        });

        // Hold the first accepted socket before sending a TLS ClientHello.
        let stalled = tokio::net::TcpStream::connect(remote_addr)
            .await
            .expect("stalled TCP connection");
        tokio::time::sleep(Duration::from_millis(50)).await;

        let channel = tokio::time::timeout(
            Duration::from_secs(1),
            connect_tcp_peer(
                remote_addr,
                "slow-accept",
                &a,
                &b.device_id(),
                b.public_key(),
            ),
        )
        .await
        .expect("valid peer should not wait for stalled handshake")
        .expect("valid TCP peer connection");
        let (accepted_id, accepted) = tokio::time::timeout(Duration::from_secs(1), accept)
            .await
            .expect("listener should accept valid peer promptly")
            .expect("accept task")
            .expect("authenticated peer");
        assert_eq!(accepted_id, a.device_id());
        assert_eq!(channel.transport_name(), "TLS/TCP");
        channel.close_async().await;
        accepted.close_async().await;
        drop(stalled);
        fs::remove_dir_all(temp).expect("remove test identities");
    }

    #[tokio::test]
    async fn tcp_candidate_authentication_failure_does_not_block_later_candidate() {
        let temp = std::env::temp_dir().join(format!(
            "mini-tunnel-tcp-candidate-retry-{}",
            uuid::Uuid::new_v4()
        ));
        let a = Identity::load_or_create_at(temp.join("a/device.key")).expect("identity A");
        let b = std::sync::Arc::new(
            Identity::load_or_create_at(temp.join("b/device.key")).expect("identity B"),
        );
        let endpoint_a = peer_endpoint(&a, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .expect("UDP endpoint A");
        let wrong_listener = peer_tcp_listener(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .expect("wrong-network TCP listener");
        let wrong_address = wrong_listener.local_addr().expect("wrong listener address");
        let expected_a = (a.device_id(), a.public_key());
        let wrong_identity = std::sync::Arc::clone(&b);
        let wrong_accept = tokio::spawn(async move {
            accept_tcp_peer_any(
                &wrong_listener,
                "another-network",
                &wrong_identity,
                &[expected_a],
            )
            .await
        });

        let correct_listener =
            peer_tcp_listener(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
                .await
                .expect("correct-network TCP listener");
        let correct_address = correct_listener
            .local_addr()
            .expect("correct listener address");
        let expected_a = (a.device_id(), a.public_key());
        let correct_identity = std::sync::Arc::clone(&b);
        let b_accept = tokio::spawn(async move {
            accept_tcp_peer_any(
                &correct_listener,
                "office",
                &correct_identity,
                &[expected_a],
            )
            .await
        });

        let (channel, connected_address) = connect_peer_candidates(
            &endpoint_a,
            &[
                format!("tcp://{wrong_address}"),
                format!("tcp://{correct_address}"),
            ],
            "office",
            &a,
            &b.device_id(),
            b.public_key(),
        )
        .await
        .expect("the later authorized candidate should connect");
        assert_eq!(connected_address, correct_address);
        assert_eq!(channel.transport_name(), "TLS/TCP");
        let (_, accepted) = b_accept.await.expect("accept task").expect("accept peer");

        channel.close_async().await;
        accepted.close_async().await;
        wrong_accept.abort();
        let _ = wrong_accept.await;
        endpoint_a.close(0_u32.into(), b"test complete");
        fs::remove_dir_all(temp).expect("remove test identities");
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
    async fn stalled_quic_authentication_does_not_block_later_valid_peer() {
        let temp = std::env::temp_dir().join(format!(
            "mini-tunnel-quic-stalled-handshake-{}",
            uuid::Uuid::new_v4()
        ));
        let a = Identity::load_or_create_at(temp.join("a/device.key")).expect("identity A");
        let b = std::sync::Arc::new(
            Identity::load_or_create_at(temp.join("b/device.key")).expect("identity B"),
        );
        let c = Identity::load_or_create_at(temp.join("c/device.key")).expect("identity C");
        let endpoint_a = peer_endpoint(&a, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .expect("endpoint A");
        let endpoint_b = peer_endpoint(&b, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .expect("endpoint B");
        let endpoint_c = peer_endpoint(&c, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .expect("endpoint C");
        let remote_addr = endpoint_b.local_addr().expect("B address");
        let expected_peer = (a.device_id(), a.public_key());
        let accept_identity = std::sync::Arc::clone(&b);
        let accepting_endpoint = endpoint_b.clone();
        let accept = tokio::spawn(async move {
            accept_peer_any(
                &accepting_endpoint,
                "slow-quic-accept",
                &accept_identity,
                &[expected_peer],
            )
            .await
        });

        // Complete the QUIC transport handshake, then stall before opening the auth stream.
        let stalled_connection = endpoint_c
            .connect_with(
                peer_client_config(
                    b.public_key(),
                    std::sync::Arc::new(rustls::crypto::ring::default_provider()),
                )
                .expect("stalled peer client config"),
                remote_addr,
                "mini-tunnel",
            )
            .expect("start stalled peer connection")
            .await
            .expect("complete QUIC handshake");
        tokio::time::sleep(Duration::from_millis(50)).await;

        let channel = tokio::time::timeout(
            Duration::from_secs(1),
            connect_peer(
                &endpoint_a,
                remote_addr,
                "slow-quic-accept",
                &a,
                &b.device_id(),
                b.public_key(),
            ),
        )
        .await
        .expect("valid peer should not wait for stalled authentication")
        .expect("valid QUIC peer connection");
        let (accepted_id, accepted) = tokio::time::timeout(Duration::from_secs(1), accept)
            .await
            .expect("listener should accept valid peer promptly")
            .expect("accept task")
            .expect("authenticated peer");
        assert_eq!(accepted_id, a.device_id());
        channel.close_async().await;
        accepted.close_async().await;
        stalled_connection.close(0_u32.into(), b"test complete");
        endpoint_a.close(0_u32.into(), b"test complete");
        endpoint_b.close(0_u32.into(), b"test complete");
        endpoint_c.close(0_u32.into(), b"test complete");
        fs::remove_dir_all(temp).expect("remove test identities");
    }

    #[tokio::test]
    async fn single_peer_accept_uses_one_total_authentication_deadline() {
        let temp = std::env::temp_dir().join(format!(
            "mini-tunnel-quic-total-deadline-{}",
            uuid::Uuid::new_v4()
        ));
        let b = std::sync::Arc::new(
            Identity::load_or_create_at(temp.join("b/device.key")).expect("identity B"),
        );
        let c = Identity::load_or_create_at(temp.join("c/device.key")).expect("identity C");
        let endpoint_b = peer_endpoint(&b, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .expect("endpoint B");
        let endpoint_c = peer_endpoint(&c, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .expect("endpoint C");
        let remote_addr = endpoint_b.local_addr().expect("B address");
        let expected_peer_id = c.device_id();
        let expected_peer_key = c.public_key();
        let accept_endpoint = endpoint_b.clone();
        let accept_identity = std::sync::Arc::clone(&b);
        let started = tokio::time::Instant::now();
        let accept = tokio::spawn(async move {
            accept_peer_with_timeout(
                &accept_endpoint,
                "deadline-net",
                &accept_identity,
                Some((&expected_peer_id, expected_peer_key)),
                Duration::from_millis(300),
            )
            .await
        });
        let stalled_connection = endpoint_c
            .connect_with(
                peer_client_config(
                    b.public_key(),
                    std::sync::Arc::new(rustls::crypto::ring::default_provider()),
                )
                .expect("peer client config"),
                remote_addr,
                "mini-tunnel",
            )
            .expect("start peer connection")
            .await
            .expect("complete QUIC handshake");

        let result = accept.await.expect("accept task");
        assert!(result.is_err(), "stalled authentication must time out");
        assert!(started.elapsed() < Duration::from_secs(2));

        stalled_connection.close(0_u32.into(), b"test complete");
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
    async fn dynamic_accept_rechecks_membership_after_pending_authentication() {
        let temp = std::env::temp_dir().join(format!(
            "mini-tunnel-dynamic-revoke-pending-{}",
            uuid::Uuid::new_v4()
        ));
        let peer = Identity::load_or_create_at(temp.join("peer/device.key")).unwrap();
        let local = std::sync::Arc::new(
            Identity::load_or_create_at(temp.join("local/device.key")).unwrap(),
        );
        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let endpoint_peer = peer_endpoint(&peer, bind).unwrap();
        let local_endpoint = peer_endpoint(&local, bind).unwrap();
        let peer_id = peer.device_id();
        let local_id = local.device_id();
        let (allowed_tx, allowed_rx) =
            tokio::sync::watch::channel(vec![(peer_id.clone(), peer.public_key())]);
        let accepting_endpoint = local_endpoint.clone();
        let accepting_identity = std::sync::Arc::clone(&local);
        let quic_accept = tokio::spawn(async move {
            let incoming = accepting_endpoint.accept().await.expect("QUIC incoming");
            authenticate_quic_candidate_dynamic(
                incoming,
                "dynamic-revoke",
                &accepting_identity,
                &allowed_rx,
            )
            .await
        });
        let quic_connection = endpoint_peer
            .connect_with(
                peer_client_config(
                    local.public_key(),
                    std::sync::Arc::new(rustls::crypto::ring::default_provider()),
                )
                .unwrap(),
                local_endpoint.local_addr().unwrap(),
                "mini-tunnel",
            )
            .unwrap()
            .await
            .unwrap();
        let (mut quic_send, mut quic_recv) = quic_connection.open_bi().await.unwrap();
        let quic_nonce = [7_u8; 32];
        quic_send.write_all(&peer.public_key()).await.unwrap();
        quic_send.write_all(&quic_nonce).await.unwrap();
        let mut quic_server_nonce = [0_u8; 32];
        quic_recv.read_exact(&mut quic_server_nonce).await.unwrap();
        allowed_tx.send(Vec::new()).unwrap();
        let quic_proof = auth_bytes(
            "dynamic-revoke",
            &peer_id,
            &local_id,
            &quic_nonce,
            &quic_server_nonce,
        );
        quic_send
            .write_all(&peer.signing_key.sign(&quic_proof).to_bytes())
            .await
            .unwrap();
        assert!(quic_accept.await.unwrap().is_none());
        quic_connection.close(0_u32.into(), b"test complete");
        endpoint_peer.close(0_u32.into(), b"test complete");
        local_endpoint.close(0_u32.into(), b"test complete");

        let tcp_listener = peer_tcp_listener(bind).await.unwrap();
        let tcp_addr = tcp_listener.local_addr().unwrap();
        let (allowed_tx, allowed_rx) =
            tokio::sync::watch::channel(vec![(peer_id.clone(), peer.public_key())]);
        let tcp_acceptor = tokio_rustls::TlsAcceptor::from(peer_tcp_server_config(&local).unwrap());
        let tcp_identity = std::sync::Arc::clone(&local);
        let tcp_accept = tokio::spawn(async move {
            let (socket, remote_addr) = tcp_listener.accept().await.unwrap();
            authenticate_tcp_candidate_dynamic(
                socket,
                remote_addr,
                tcp_acceptor,
                "dynamic-revoke",
                &tcp_identity,
                &allowed_rx,
            )
            .await
        });
        let socket = tokio::net::TcpStream::connect(tcp_addr).await.unwrap();
        let connector =
            tokio_rustls::TlsConnector::from(peer_tcp_client_config(local.public_key()).unwrap());
        let server_name = rustls::pki_types::ServerName::try_from("mini-tunnel").unwrap();
        let mut tcp_stream = connector.connect(server_name, socket).await.unwrap();
        let tcp_nonce = [9_u8; 32];
        tcp_stream.write_all(&peer.public_key()).await.unwrap();
        tcp_stream.write_all(&tcp_nonce).await.unwrap();
        let mut tcp_server_nonce = [0_u8; 32];
        tcp_stream.read_exact(&mut tcp_server_nonce).await.unwrap();
        allowed_tx.send(Vec::new()).unwrap();
        let tcp_proof = auth_bytes(
            "dynamic-revoke",
            &peer_id,
            &local_id,
            &tcp_nonce,
            &tcp_server_nonce,
        );
        tcp_stream
            .write_all(&peer.signing_key.sign(&tcp_proof).to_bytes())
            .await
            .unwrap();
        assert!(tcp_accept.await.unwrap().is_none());

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
        let decoded = decode_any_frame(&frame, tag).expect("valid frame");
        assert_eq!(decoded.sequence, 42);
        assert_eq!(decoded.payload, b"packet");
        assert!(decode_any_frame(&frame, [8_u8; 16]).is_none());
        assert!(decode_any_frame(&[0; FRAME_HEADER_LEN], tag).is_none());
        let mut window = ReplayWindow::default();
        assert!(window.accept(42));
        assert!(!window.accept(42));
        assert!(window.accept(44));
        assert!(window.accept(43));
        assert!(window.accept(200));
        assert!(!window.accept(44));
    }

    #[test]
    fn payload_fragment_limits_respect_wire_cap_and_small_path_sizes() {
        assert_eq!(single_frame_payload_limit(65_535), MAX_PACKET_PAYLOAD);
        assert_eq!(
            fragment_payload_limit(65_535),
            MAX_PACKET_PAYLOAD - FRAGMENT_HEADER_LEN
        );
        assert_eq!(single_frame_payload_limit(FRAME_HEADER_LEN + 900), 900);
        assert_eq!(
            fragment_payload_limit(FRAME_HEADER_LEN + FRAGMENT_HEADER_LEN + 700),
            700
        );
        assert_eq!(
            fragment_payload_limit(FRAME_HEADER_LEN + FRAGMENT_HEADER_LEN),
            0
        );
    }

    #[test]
    fn fragment_reassembly_is_bounded_and_rejects_duplicate_or_malformed_parts() {
        let payload = (0..1280).map(|byte| (byte % 251) as u8).collect::<Vec<_>>();
        let chunk_size = 700;
        let chunks = payload.chunks(chunk_size).collect::<Vec<_>>();
        let mut reassembler = FragmentReassembler::default();
        let last = DecodedFragment {
            packet_id: 100,
            index: 1,
            count: 2,
            total_len: payload.len(),
            chunk_size,
            payload: chunks[1],
        };
        assert!(reassembler.accept(last).unwrap().is_none());
        let first = DecodedFragment {
            packet_id: 100,
            index: 0,
            count: 2,
            total_len: payload.len(),
            chunk_size,
            payload: chunks[0],
        };
        assert_eq!(reassembler.accept(first).unwrap().unwrap(), payload);

        let duplicate = DecodedFragment {
            packet_id: 101,
            index: 0,
            count: 2,
            total_len: payload.len(),
            chunk_size,
            payload: chunks[0],
        };
        reassembler.accept(duplicate).unwrap();
        assert!(reassembler.accept(duplicate).is_err());
        assert!(reassembler.packets.is_empty());

        let oversized = DecodedFragment {
            packet_id: 102,
            index: 0,
            count: 2,
            total_len: MAX_TUN_PACKET + 1,
            chunk_size,
            payload: chunks[0],
        };
        assert!(reassembler.accept(oversized).is_err());
        assert!(reassembler.packets.is_empty());
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
