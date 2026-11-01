//! Bounded ticket-authorized UDP relay for opaque QUIC datagrams.

use std::{
    collections::HashMap,
    io,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use ed25519_dalek::{Signature, Signer, VerifyingKey};
use mini_tunnel_protocol::{
    RelayTicketClaims, UDP_RELAY_DATA_HEADER_LEN, UDP_RELAY_MAX_DATAGRAM_LEN,
    decode_udp_relay_datagram, relay_auth_signing_bytes, verify_relay_ticket,
};
use tokio::{
    net::UdpSocket,
    sync::{Mutex, watch},
};

const HELLO: &[u8; 8] = b"MTUHELLO";
const CHALLENGE: &[u8; 8] = b"MTUCHAL1";
const PROOF: &[u8; 8] = b"MTUPROOF";
const READY: &[u8; 8] = b"MTUREADY";
const MAX_TICKET_LENGTH: usize = 2048;
const MAX_PENDING: usize = 1024;
const MAX_SESSIONS: usize = 4096;
const MAX_USED_TICKETS: usize = 16_384;
const CHALLENGE_TTL: Duration = Duration::from_secs(5);
const PAIR_TIMEOUT: Duration = Duration::from_secs(35);
const MAX_TICKET_LIFETIME_MS: u64 = 120_000;
const MAX_SESSION_BYTES: u64 = 1024 * 1024 * 1024;
const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(600);
const MAX_UDP_PACKET: usize = 64 * 1024;
const MAX_AUTH_RATE_SOURCES: usize = 4096;
const AUTH_RATE_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const AUTH_RATE_BURST: u32 = 20;
const AUTH_RATE_PER_SECOND: u32 = 10;
const AUTH_RATE_TOKEN_MILLI: u32 = 1000;

#[derive(Debug, Clone)]
pub struct UdpRelayConfig {
    pub ticket_key: [u8; 32],
    pub previous_ticket_key: Option<[u8; 32]>,
    pub max_sessions: usize,
    pub max_pending: usize,
    pub auth_burst: u32,
    pub auth_per_second: u32,
}

impl UdpRelayConfig {
    #[must_use]
    pub fn new(ticket_key: [u8; 32]) -> Self {
        Self {
            ticket_key,
            previous_ticket_key: None,
            max_sessions: MAX_SESSIONS,
            max_pending: MAX_PENDING,
            auth_burst: AUTH_RATE_BURST,
            auth_per_second: AUTH_RATE_PER_SECOND,
        }
    }

    #[must_use]
    pub fn with_previous_ticket_key(mut self, key: [u8; 32]) -> Self {
        if key != self.ticket_key {
            self.previous_ticket_key = Some(key);
        }
        self
    }

    #[must_use]
    pub fn with_auth_rate(mut self, burst: u32, per_second: u32) -> Self {
        self.auth_burst = burst.clamp(1, 1_000_000);
        self.auth_per_second = per_second.clamp(1, 1_000_000);
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpRelayStats {
    pub active_sessions: usize,
    pub pending_authentications: usize,
    pub forwarded_datagrams_total: u64,
    pub dropped_datagrams_total: u64,
    pub auth_rate_limited_total: u64,
}

#[derive(Clone)]
pub struct UdpRelayServer {
    inner: Arc<Inner>,
}

struct Inner {
    config: UdpRelayConfig,
    state: Mutex<State>,
    forwarded: AtomicU64,
    dropped: AtomicU64,
    auth_rate_limited: AtomicU64,
    shutdown: watch::Sender<bool>,
}

#[derive(Default)]
struct State {
    pending: HashMap<SocketAddr, Pending>,
    used_tickets: HashMap<[u8; 16], u64>,
    accepted_proofs: HashMap<[u8; 16], AcceptedProof>,
    sessions: HashMap<[u8; 16], Session>,
    auth_rate_limits: HashMap<IpAddr, AuthRateLimit>,
}

struct Pending {
    claims: RelayTicketClaims,
    public_key: [u8; 32],
    challenge: [u8; 32],
    expires_at: tokio::time::Instant,
}

struct AcceptedProof {
    expires_at_ms: u64,
    packet: Vec<u8>,
}

struct AuthRateLimit {
    tokens_milli: u32,
    last_refill: tokio::time::Instant,
    last_seen: tokio::time::Instant,
}

#[derive(Clone)]
struct Session {
    expires_at_ms: u64,
    created_at: tokio::time::Instant,
    last_activity: tokio::time::Instant,
    bytes_forwarded: u64,
    endpoints: [Option<SocketAddr>; 2],
}

impl UdpRelayServer {
    #[must_use]
    pub fn new(config: UdpRelayConfig) -> Self {
        let (shutdown, _) = watch::channel(false);
        Self {
            inner: Arc::new(Inner {
                config,
                state: Mutex::new(State::default()),
                forwarded: AtomicU64::new(0),
                dropped: AtomicU64::new(0),
                auth_rate_limited: AtomicU64::new(0),
                shutdown,
            }),
        }
    }

    pub async fn stats(&self) -> UdpRelayStats {
        let state = self.inner.state.lock().await;
        UdpRelayStats {
            active_sessions: state.sessions.len(),
            pending_authentications: state.pending.len(),
            forwarded_datagrams_total: self.inner.forwarded.load(Ordering::Relaxed),
            dropped_datagrams_total: self.inner.dropped.load(Ordering::Relaxed),
            auth_rate_limited_total: self.inner.auth_rate_limited.load(Ordering::Relaxed),
        }
    }

    /// Serve a bound UDP socket until shutdown. Malformed and unauthorized packets are dropped.
    pub async fn run(&self, socket: UdpSocket) -> io::Result<()> {
        let mut shutdown = self.inner.shutdown.subscribe();
        let mut buffer = vec![0; MAX_UDP_PACKET];
        loop {
            let (length, source) = tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() { return Ok(()); }
                    continue;
                }
                received = socket.recv_from(&mut buffer) => received?,
            };
            if !self
                .handle_packet(&socket, source, &buffer[..length])
                .await?
            {
                self.inner.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn shutdown(&self) {
        self.inner.shutdown.send_replace(true);
    }

    async fn handle_packet(
        &self,
        socket: &UdpSocket,
        source: SocketAddr,
        packet: &[u8],
    ) -> io::Result<bool> {
        if packet.starts_with(HELLO) {
            if !self.admit_auth_attempt(source.ip()).await {
                return Ok(false);
            }
            return self.handle_hello(socket, source, packet).await;
        }
        if packet.starts_with(PROOF) {
            if !self.admit_auth_attempt(source.ip()).await {
                return Ok(false);
            }
            return self.handle_proof(socket, source, packet).await;
        }
        let Ok((session_id, _)) = decode_udp_relay_datagram(packet) else {
            return Ok(false);
        };
        let target = {
            let mut state = self.inner.state.lock().await;
            let now = tokio::time::Instant::now();
            let stale = state.sessions.get(&session_id).is_some_and(|session| {
                if session.endpoints.iter().all(Option::is_some) {
                    now.duration_since(session.last_activity) >= SESSION_IDLE_TIMEOUT
                        || session.bytes_forwarded >= MAX_SESSION_BYTES
                } else {
                    unix_time_ms().unwrap_or(0) >= session.expires_at_ms
                        || now.duration_since(session.created_at) >= PAIR_TIMEOUT
                }
            });
            if stale {
                state.sessions.remove(&session_id);
                None
            } else if let Some(session) = state.sessions.get_mut(&session_id) {
                let target = if session.endpoints[0] == Some(source) {
                    session.endpoints[1]
                } else if session.endpoints[1] == Some(source) {
                    session.endpoints[0]
                } else {
                    None
                };
                if target.is_some() {
                    session.last_activity = now;
                    session.bytes_forwarded =
                        session.bytes_forwarded.saturating_add(packet.len() as u64);
                }
                target
            } else {
                None
            }
        };
        let Some(target) = target else {
            return Ok(false);
        };
        socket.send_to(packet, target).await?;
        self.inner.forwarded.fetch_add(1, Ordering::Relaxed);
        Ok(true)
    }

    async fn admit_auth_attempt(&self, source_ip: IpAddr) -> bool {
        let mut state = self.inner.state.lock().await;
        let allowed = allow_auth_attempt_with_rate(
            &mut state,
            source_ip,
            tokio::time::Instant::now(),
            self.inner.config.auth_burst,
            self.inner.config.auth_per_second,
        );
        if !allowed {
            self.inner.auth_rate_limited.fetch_add(1, Ordering::Relaxed);
        }
        allowed
    }

    async fn handle_hello(
        &self,
        socket: &UdpSocket,
        source: SocketAddr,
        packet: &[u8],
    ) -> io::Result<bool> {
        if packet.len() < 8 + 2 + 1 + 32 || packet.get(..8) != Some(HELLO.as_slice()) {
            return Ok(false);
        }
        let ticket_length = usize::from(u16::from_be_bytes([packet[8], packet[9]]));
        if ticket_length == 0
            || ticket_length > MAX_TICKET_LENGTH
            || packet.len() != 10 + ticket_length + 32
        {
            return Ok(false);
        }
        let ticket_bytes = &packet[10..10 + ticket_length];
        let Ok(ticket) = std::str::from_utf8(ticket_bytes) else {
            return Ok(false);
        };
        let now_ms =
            unix_time_ms().ok_or_else(|| io::Error::other("system clock is before epoch"))?;
        let claims =
            verify_relay_ticket(&self.inner.config.ticket_key, ticket, now_ms).or_else(|error| {
                self.inner
                    .config
                    .previous_ticket_key
                    .as_ref()
                    .ok_or(error)
                    .and_then(|key| verify_relay_ticket(key, ticket, now_ms))
            });
        let Ok(claims) = claims else {
            return Ok(false);
        };
        if claims.expires_at_ms.saturating_sub(now_ms) > MAX_TICKET_LIFETIME_MS {
            return Ok(false);
        }
        let public_key: [u8; 32] = packet[10 + ticket_length..]
            .try_into()
            .map_err(|_| io::Error::other("invalid public key length"))?;
        if mini_tunnel_protocol::device_id_from_public_key(&public_key) != claims.source_device_id {
            return Ok(false);
        }
        let mut state = self.inner.state.lock().await;
        let now_ms = unix_time_ms().unwrap_or(0);
        state.sessions.retain(|_, session| {
            if session.endpoints.iter().all(Option::is_some) {
                session.last_activity.elapsed() < SESSION_IDLE_TIMEOUT
                    && session.bytes_forwarded < MAX_SESSION_BYTES
            } else {
                session.expires_at_ms > now_ms && session.created_at.elapsed() < PAIR_TIMEOUT
            }
        });
        let now = tokio::time::Instant::now();
        state.pending.retain(|_, pending| pending.expires_at > now);
        state
            .used_tickets
            .retain(|_, expires_at_ms| *expires_at_ms > now_ms);
        state
            .accepted_proofs
            .retain(|_, proof| proof.expires_at_ms > now_ms);
        if state.used_tickets.contains_key(&claims.ticket_id) {
            return Ok(false);
        }
        if let Some(pending) = state.pending.get(&source)
            && pending.claims == claims
            && pending.public_key == public_key
            && pending.expires_at > tokio::time::Instant::now()
        {
            let mut response = Vec::with_capacity(40);
            response.extend_from_slice(CHALLENGE);
            response.extend_from_slice(&pending.challenge);
            drop(state);
            socket.send_to(&response, source).await?;
            return Ok(true);
        }
        let mut challenge = [0; 32];
        getrandom::fill(&mut challenge).map_err(io::Error::other)?;
        if !state.pending.contains_key(&source)
            && state.pending.len() >= self.inner.config.max_pending.max(1)
        {
            return Ok(false);
        }
        state.pending.insert(
            source,
            Pending {
                claims,
                public_key,
                challenge,
                expires_at: now + CHALLENGE_TTL,
            },
        );
        drop(state);
        let mut response = Vec::with_capacity(40);
        response.extend_from_slice(CHALLENGE);
        response.extend_from_slice(&challenge);
        socket.send_to(&response, source).await?;
        Ok(true)
    }

    async fn handle_proof(
        &self,
        socket: &UdpSocket,
        source: SocketAddr,
        packet: &[u8],
    ) -> io::Result<bool> {
        if packet.len() < 8 + 2 + 1 + 32 + 64 || packet.get(..8) != Some(PROOF.as_slice()) {
            return Ok(false);
        }
        let ticket_length = usize::from(u16::from_be_bytes([packet[8], packet[9]]));
        if ticket_length == 0
            || ticket_length > MAX_TICKET_LENGTH
            || packet.len() != 10 + ticket_length + 32 + 64
        {
            return Ok(false);
        }
        let ticket = std::str::from_utf8(&packet[10..10 + ticket_length]).ok();
        let Some(ticket) = ticket else {
            return Ok(false);
        };
        let mut state = self.inner.state.lock().await;
        let now_ms =
            unix_time_ms().ok_or_else(|| io::Error::other("system clock is before epoch"))?;
        state
            .used_tickets
            .retain(|_, expires_at_ms| *expires_at_ms > now_ms);
        state
            .accepted_proofs
            .retain(|_, proof| proof.expires_at_ms > now_ms);
        let ticket_id = match verify_relay_ticket(&self.inner.config.ticket_key, ticket, now_ms)
            .or_else(|error| {
                self.inner
                    .config
                    .previous_ticket_key
                    .as_ref()
                    .ok_or(error)
                    .and_then(|key| verify_relay_ticket(key, ticket, now_ms))
            }) {
            Ok(claims) => claims.ticket_id,
            Err(_) => return Ok(false),
        };
        if let Some(existing) = state.accepted_proofs.get(&ticket_id) {
            let session_id =
                match verify_relay_ticket(&self.inner.config.ticket_key, ticket, now_ms).or_else(
                    |error| {
                        self.inner
                            .config
                            .previous_ticket_key
                            .as_ref()
                            .ok_or(error)
                            .and_then(|key| verify_relay_ticket(key, ticket, now_ms))
                    },
                ) {
                    Ok(claims) => claims.session_id,
                    Err(_) => return Ok(false),
                };
            let paired = state.sessions.get(&session_id).is_some_and(|session| {
                session.endpoints.iter().all(Option::is_some)
                    && session.endpoints.contains(&Some(source))
            });
            if existing.packet.as_slice() != packet || !paired {
                return Ok(false);
            }
            drop(state);
            let mut response = Vec::with_capacity(24);
            response.extend_from_slice(READY);
            response.extend_from_slice(&session_id);
            socket.send_to(&response, source).await?;
            return Ok(true);
        }
        let Some(pending) = state.pending.remove(&source) else {
            return Ok(false);
        };
        let public_key: [u8; 32] = packet[10 + ticket_length..10 + ticket_length + 32]
            .try_into()
            .map_err(|_| io::Error::other("invalid public key length"))?;
        let signature: [u8; 64] = packet[10 + ticket_length + 32..]
            .try_into()
            .map_err(|_| io::Error::other("invalid signature length"))?;
        if pending.expires_at <= tokio::time::Instant::now()
            || public_key != pending.public_key
            || state.used_tickets.contains_key(&pending.claims.ticket_id)
            || !matches!(verify_relay_ticket(&self.inner.config.ticket_key, ticket, now_ms)
                .or_else(|error| {
                    self.inner
                        .config
                        .previous_ticket_key
                        .as_ref()
                        .ok_or(error)
                        .and_then(|key| verify_relay_ticket(key, ticket, now_ms))
                }), Ok(ref claims) if claims == &pending.claims)
        {
            return Ok(false);
        }
        let verifying_key = match VerifyingKey::from_bytes(&public_key) {
            Ok(key) => key,
            Err(_) => return Ok(false),
        };
        if verifying_key
            .verify_strict(
                &relay_auth_signing_bytes(ticket, &pending.challenge, &public_key),
                &Signature::from_bytes(&signature),
            )
            .is_err()
        {
            return Ok(false);
        }
        if state.used_tickets.len() >= MAX_USED_TICKETS {
            return Ok(false);
        }
        let claims = pending.claims;
        let session_id = claims.session_id;
        let now = tokio::time::Instant::now();
        state.sessions.retain(|_, session| {
            if session.endpoints.iter().all(Option::is_some) {
                now.duration_since(session.last_activity) < SESSION_IDLE_TIMEOUT
                    && session.bytes_forwarded < MAX_SESSION_BYTES
            } else {
                session.expires_at_ms > now_ms
                    && now.duration_since(session.created_at) < PAIR_TIMEOUT
            }
        });
        let target_index = if claims.source_device_id < claims.target_device_id {
            0
        } else {
            1
        };
        if !state.sessions.contains_key(&session_id)
            && state.sessions.len() >= self.inner.config.max_sessions.max(1)
        {
            return Ok(false);
        }
        let session = state.sessions.entry(session_id).or_insert_with(|| Session {
            expires_at_ms: claims.expires_at_ms,
            created_at: now,
            last_activity: now,
            bytes_forwarded: 0,
            endpoints: [None, None],
        });
        if session.endpoints[target_index].is_some() {
            return Ok(false);
        }
        session.expires_at_ms = session.expires_at_ms.min(claims.expires_at_ms);
        session.endpoints[target_index] = Some(source);
        let ready_endpoints = if session.endpoints.iter().all(Option::is_some) {
            session.endpoints
        } else {
            [None, None]
        };
        state
            .used_tickets
            .insert(claims.ticket_id, claims.expires_at_ms);
        state.accepted_proofs.insert(
            claims.ticket_id,
            AcceptedProof {
                expires_at_ms: claims.expires_at_ms,
                packet: packet.to_vec(),
            },
        );
        drop(state);
        if ready_endpoints.iter().all(Option::is_some) {
            let mut response = Vec::with_capacity(24);
            response.extend_from_slice(READY);
            response.extend_from_slice(&session_id);
            for address in ready_endpoints.into_iter().flatten() {
                socket.send_to(&response, address).await?;
            }
        }
        Ok(true)
    }
}

fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4),
        IpAddr::V4(ip) => IpAddr::V4(ip),
    }
}

#[cfg(test)]
fn allow_auth_attempt(state: &mut State, source_ip: IpAddr, now: tokio::time::Instant) -> bool {
    allow_auth_attempt_with_rate(state, source_ip, now, AUTH_RATE_BURST, AUTH_RATE_PER_SECOND)
}

fn allow_auth_attempt_with_rate(
    state: &mut State,
    source_ip: IpAddr,
    now: tokio::time::Instant,
    burst: u32,
    per_second: u32,
) -> bool {
    let burst = burst.clamp(1, 1_000_000);
    let per_second = per_second.clamp(1, 1_000_000);
    state
        .auth_rate_limits
        .retain(|_, bucket| now.duration_since(bucket.last_seen) < AUTH_RATE_IDLE_TIMEOUT);
    let source_ip = normalize_ip(source_ip);
    let capacity_milli = burst.saturating_mul(AUTH_RATE_TOKEN_MILLI);
    if let Some(bucket) = state.auth_rate_limits.get_mut(&source_ip) {
        let elapsed_ms = now.duration_since(bucket.last_refill).as_millis();
        let refill_milli = elapsed_ms
            .saturating_mul(u128::from(per_second))
            .min(u128::from(capacity_milli)) as u32;
        bucket.tokens_milli = bucket
            .tokens_milli
            .saturating_add(refill_milli)
            .min(capacity_milli);
        bucket.last_refill = now;
        bucket.last_seen = now;
        if bucket.tokens_milli < AUTH_RATE_TOKEN_MILLI {
            return false;
        }
        bucket.tokens_milli -= AUTH_RATE_TOKEN_MILLI;
        return true;
    }
    if state.auth_rate_limits.len() >= MAX_AUTH_RATE_SOURCES {
        return false;
    }
    state.auth_rate_limits.insert(
        source_ip,
        AuthRateLimit {
            tokens_milli: (burst - 1) * AUTH_RATE_TOKEN_MILLI,
            last_refill: now,
            last_seen: now,
        },
    );
    true
}

fn unix_time_ms() -> Option<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
}

/// Build the UDP relay hello frame for a short-lived Coordinator ticket.
pub fn udp_relay_hello(ticket: &str, public_key: &[u8; 32]) -> io::Result<Vec<u8>> {
    if ticket.is_empty() || ticket.len() > MAX_TICKET_LENGTH {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid relay ticket length",
        ));
    }
    let ticket_len = u16::try_from(ticket.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "relay ticket is too long"))?;
    let mut frame = Vec::with_capacity(10 + ticket.len() + public_key.len());
    frame.extend_from_slice(HELLO);
    frame.extend_from_slice(&ticket_len.to_be_bytes());
    frame.extend_from_slice(ticket.as_bytes());
    frame.extend_from_slice(public_key);
    Ok(frame)
}

/// Build an authenticated proof frame after receiving the relay challenge.
pub fn udp_relay_proof(
    ticket: &str,
    challenge: &[u8; 32],
    identity: &ed25519_dalek::SigningKey,
) -> io::Result<Vec<u8>> {
    if ticket.is_empty() || ticket.len() > MAX_TICKET_LENGTH {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid relay ticket length",
        ));
    }
    let ticket_len = u16::try_from(ticket.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "relay ticket is too long"))?;
    let public_key = identity.verifying_key().to_bytes();
    let signature = identity.sign(&relay_auth_signing_bytes(ticket, challenge, &public_key));
    let mut frame = Vec::with_capacity(10 + ticket.len() + 32 + 64);
    frame.extend_from_slice(PROOF);
    frame.extend_from_slice(&ticket_len.to_be_bytes());
    frame.extend_from_slice(ticket.as_bytes());
    frame.extend_from_slice(&public_key);
    frame.extend_from_slice(&signature.to_bytes());
    Ok(frame)
}

/// Return whether this is a correctly sized relay payload packet.
pub fn is_udp_relay_datagram(frame: &[u8]) -> bool {
    decode_udp_relay_datagram(frame).is_ok()
        && frame.len() <= UDP_RELAY_MAX_DATAGRAM_LEN
        && UDP_RELAY_DATA_HEADER_LEN < frame.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use mini_tunnel_protocol::{
        RELAY_TICKET_VERSION, RelayTicketClaims, UDP_RELAY_DATA_MAGIC, issue_relay_ticket,
    };
    use tokio::{net::UdpSocket, time::timeout};

    fn identity(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn device_id(identity: &SigningKey) -> String {
        mini_tunnel_protocol::device_id_from_public_key(&identity.verifying_key().to_bytes())
    }

    #[test]
    fn authentication_rate_limit_bounds_burst_and_refills() {
        let mut state = State::default();
        let source_ip = "192.0.2.10".parse().expect("source IP");
        let now = tokio::time::Instant::now();
        for _ in 0..AUTH_RATE_BURST {
            assert!(allow_auth_attempt(&mut state, source_ip, now));
        }
        assert!(!allow_auth_attempt(&mut state, source_ip, now));
        assert!(allow_auth_attempt(
            &mut state,
            source_ip,
            now + Duration::from_millis(100)
        ));
    }

    #[test]
    fn auth_rate_configuration_is_bounded() {
        let config = UdpRelayConfig::new([1; 32]).with_auth_rate(0, u32::MAX);
        assert_eq!(config.auth_burst, 1);
        assert_eq!(config.auth_per_second, 1_000_000);
    }

    #[test]
    fn authentication_rate_limit_normalizes_mapped_ipv4() {
        let mut state = State::default();
        let now = tokio::time::Instant::now();
        let ipv4 = "192.0.2.10".parse().expect("source IPv4");
        let mapped_ipv6 = "::ffff:192.0.2.10".parse().expect("mapped source IPv6");
        for _ in 0..AUTH_RATE_BURST {
            assert!(allow_auth_attempt(&mut state, ipv4, now));
        }
        assert!(!allow_auth_attempt(&mut state, mapped_ipv6, now));
        assert_eq!(state.auth_rate_limits.len(), 1);
    }

    #[test]
    fn authentication_rate_limit_allows_udp_retry_load_and_caps_sources() {
        let mut state = State::default();
        let source_ip = "192.0.2.10".parse().expect("source IP");
        let mut now = tokio::time::Instant::now();
        for _ in 0..140 {
            now += Duration::from_millis(250);
            assert!(allow_auth_attempt(&mut state, source_ip, now));
        }

        for index in 0..MAX_AUTH_RATE_SOURCES - 1 {
            let ip = IpAddr::V4(std::net::Ipv4Addr::from(index as u32));
            assert!(allow_auth_attempt(&mut state, ip, now));
        }
        assert_eq!(state.auth_rate_limits.len(), MAX_AUTH_RATE_SOURCES);
        let new_ip = IpAddr::V4(std::net::Ipv4Addr::from(u32::MAX));
        assert!(!allow_auth_attempt(&mut state, new_ip, now));
        assert_eq!(state.auth_rate_limits.len(), MAX_AUTH_RATE_SOURCES);

        now += AUTH_RATE_IDLE_TIMEOUT;
        assert!(allow_auth_attempt(&mut state, new_ip, now));
        assert_eq!(state.auth_rate_limits.len(), 1);
    }

    fn ticket(
        key: &[u8; 32],
        source: &SigningKey,
        target: &SigningKey,
        salt: u8,
        lifetime_ms: u64,
    ) -> String {
        issue_relay_ticket(
            key,
            &RelayTicketClaims {
                version: RELAY_TICKET_VERSION,
                network_id: "network-test".to_owned(),
                source_device_id: device_id(source),
                target_device_id: device_id(target),
                session_id: [9; 16],
                ticket_id: [salt; 16],
                expires_at_ms: unix_time_ms().expect("time") + lifetime_ms,
            },
        )
        .expect("issue relay ticket")
    }

    async fn authenticate(
        socket: &UdpSocket,
        relay: SocketAddr,
        ticket: &str,
        identity: &SigningKey,
    ) -> Vec<u8> {
        let hello = udp_relay_hello(ticket, &identity.verifying_key().to_bytes()).expect("hello");
        socket.send_to(&hello, relay).await.expect("send hello");
        let mut response = [0; 64];
        let length = timeout(Duration::from_secs(1), socket.recv(&mut response))
            .await
            .expect("challenge timeout")
            .expect("challenge");
        assert_eq!(&response[..8], CHALLENGE);
        let challenge: [u8; 32] = response[8..length].try_into().expect("challenge bytes");
        let proof = udp_relay_proof(ticket, &challenge, identity).expect("proof");
        socket.send_to(&proof, relay).await.expect("send proof");
        let length = timeout(Duration::from_secs(1), socket.recv(&mut response))
            .await
            .expect("ready timeout")
            .expect("ready");
        assert_eq!(
            &response[..length],
            b"MTUREADY\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09"
        );
        proof
    }

    #[tokio::test]
    async fn pairs_ticketed_udp_peers_and_forwards_only_session_datagrams() {
        let key = [44; 32];
        let alice = identity(1);
        let bob = identity(2);
        let alice_ticket = ticket(&key, &alice, &bob, 3, 1_000);
        let bob_ticket = ticket(&key, &bob, &alice, 4, 1_000);
        let relay = UdpRelayServer::new(UdpRelayConfig::new(key));
        let relay_socket = UdpSocket::bind("127.0.0.1:0").await.expect("relay socket");
        let relay_address = relay_socket.local_addr().expect("relay address");
        let runner = {
            let relay = relay.clone();
            tokio::spawn(async move { relay.run(relay_socket).await.expect("run relay") })
        };
        let alice_socket = UdpSocket::bind("127.0.0.1:0").await.expect("alice socket");
        let bob_socket = UdpSocket::bind("127.0.0.1:0").await.expect("bob socket");
        let (alice_proof, _bob_proof) = tokio::join!(
            authenticate(&alice_socket, relay_address, &alice_ticket, &alice),
            authenticate(&bob_socket, relay_address, &bob_ticket, &bob),
        );
        alice_socket
            .send_to(&alice_proof, relay_address)
            .await
            .expect("retry alice proof");
        let mut ready = [0; 64];
        let (ready_length, _) = timeout(Duration::from_secs(1), alice_socket.recv_from(&mut ready))
            .await
            .expect("retry ready timeout")
            .expect("retry ready");
        assert_eq!(
            &ready[..ready_length],
            b"MTUREADY\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09"
        );
        tokio::time::sleep(Duration::from_millis(1_050)).await;

        let fresh_ticket = ticket(&key, &alice, &bob, 5, 1_000);
        let fresh_hello =
            udp_relay_hello(&fresh_ticket, &alice.verifying_key().to_bytes()).expect("hello");
        alice_socket
            .send_to(&fresh_hello, relay_address)
            .await
            .expect("send fresh hello");
        let _ = timeout(Duration::from_secs(1), alice_socket.recv(&mut ready))
            .await
            .expect("fresh challenge timeout")
            .expect("fresh challenge");
        assert!(relay.inner.state.lock().await.accepted_proofs.is_empty());

        let mut datagram = Vec::from(UDP_RELAY_DATA_MAGIC.as_slice());
        datagram.extend_from_slice(&[9; 16]);
        datagram.extend_from_slice(b"opaque quic payload");
        alice_socket
            .send_to(&datagram, relay_address)
            .await
            .expect("send data");
        let mut received = [0; 1200];
        let (length, _) = timeout(Duration::from_secs(1), bob_socket.recv_from(&mut received))
            .await
            .expect("forward timeout")
            .expect("forwarded data");
        assert_eq!(&received[..length], datagram);

        let replay = UdpSocket::bind("127.0.0.1:0").await.expect("replay socket");
        let replay_hello =
            udp_relay_hello(&alice_ticket, &alice.verifying_key().to_bytes()).expect("hello");
        replay
            .send_to(&replay_hello, relay_address)
            .await
            .expect("send replay");
        assert!(
            timeout(Duration::from_millis(50), replay.recv(&mut received))
                .await
                .is_err()
        );

        let unregistered = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("unregistered socket");
        unregistered
            .send_to(&datagram, relay_address)
            .await
            .expect("send unauthorized datagram");
        assert!(
            timeout(Duration::from_millis(50), bob_socket.recv(&mut received))
                .await
                .is_err()
        );
        assert_eq!(relay.stats().await.forwarded_datagrams_total, 1);

        relay.shutdown();
        runner.await.expect("relay task");
    }
}
