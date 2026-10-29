//! Ticket-authorized opaque TCP relay for end-to-end TLS peer streams.

use std::{
    collections::HashMap,
    future::Future,
    io,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use ed25519_dalek::{Signature, VerifyingKey};
use mini_tunnel_protocol::{
    RelayTicketClaims, RelayTicketError, relay_auth_signing_bytes, verify_relay_ticket,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Mutex, OwnedSemaphorePermit, Semaphore, mpsc, watch},
};

pub use mini_tunnel_protocol as protocol;

const RELAY_PREFACE: &[u8; 8] = b"MTRELAY1";
const RELAY_CHALLENGE: u8 = 1;
const RELAY_READY: u8 = 2;
const MAX_TICKET_LENGTH: usize = 2048;
const MAX_CONNECTIONS: usize = 256;
const MAX_CONNECTIONS_PER_SOURCE_IP: usize = 32;
const MAX_PENDING_SESSIONS: usize = 128;
const MAX_USED_TICKETS: usize = 16_384;
const MAX_SESSION_BYTES: u64 = 1024 * 1024 * 1024;
const AUTH_TIMEOUT: Duration = Duration::from_secs(5);
const PAIR_TIMEOUT: Duration = Duration::from_secs(25);
const SHUTDOWN_GRACE: Duration = Duration::from_secs(15);
const MAX_TICKET_LIFETIME_MS: u64 = 120_000;
const COPY_BUFFER_SIZE: usize = 16 * 1024;

#[derive(Debug, Clone)]
pub struct RelayConfig {
    pub ticket_key: [u8; 32],
    /// Optional overlap key accepted for tickets issued before a key rotation.
    pub previous_ticket_key: Option<[u8; 32]>,
    pub max_connections: usize,
    /// Maximum accepted relay handshakes and sessions held by one source IP.
    pub max_connections_per_source_ip: usize,
    pub max_pending_sessions: usize,
    pub pair_timeout: Duration,
    /// Aggregate bytes forwarded in both directions before a paired session is closed.
    pub max_session_bytes: u64,
    /// Time to let established sessions finish after stopping new accepts.
    pub shutdown_grace: Duration,
}

impl RelayConfig {
    #[must_use]
    pub fn new(ticket_key: [u8; 32]) -> Self {
        Self {
            ticket_key,
            previous_ticket_key: None,
            max_connections: MAX_CONNECTIONS,
            max_connections_per_source_ip: MAX_CONNECTIONS_PER_SOURCE_IP,
            max_pending_sessions: MAX_PENDING_SESSIONS,
            pair_timeout: PAIR_TIMEOUT,
            max_session_bytes: MAX_SESSION_BYTES,
            shutdown_grace: SHUTDOWN_GRACE,
        }
    }

    /// Accept tickets authenticated by the previous key until their short expiry.
    #[must_use]
    pub fn with_previous_ticket_key(mut self, key: [u8; 32]) -> Self {
        if key != self.ticket_key {
            self.previous_ticket_key = Some(key);
        }
        self
    }

    /// Set the aggregate bidirectional byte budget for each paired session.
    #[must_use]
    pub fn with_max_session_bytes(mut self, max_bytes: u64) -> Self {
        self.max_session_bytes = max_bytes.max(1);
        self
    }

    /// Limit how many relay handshakes and sessions one source IP can occupy.
    #[must_use]
    pub fn with_max_connections_per_source_ip(mut self, max_connections: usize) -> Self {
        self.max_connections_per_source_ip = max_connections.max(1);
        self
    }

    /// Set the global concurrent relay connection limit.
    #[must_use]
    pub fn with_max_connections(mut self, max_connections: usize) -> Self {
        self.max_connections = max_connections.max(1);
        self
    }
}

#[derive(Clone)]
pub struct RelayServer {
    inner: Arc<RelayInner>,
}

struct RelayInner {
    config: RelayConfig,
    state: Mutex<RelayState>,
    next_generation: AtomicU64,
    connections: Arc<Semaphore>,
    source_connections: Arc<SourceConnectionTracker>,
    shutdown: watch::Sender<bool>,
}

struct SourceConnectionTracker {
    active: StdMutex<HashMap<IpAddr, usize>>,
    limit: usize,
}

struct SourceConnectionPermit {
    tracker: Arc<SourceConnectionTracker>,
    source: IpAddr,
}

impl SourceConnectionTracker {
    fn try_acquire(self: &Arc<Self>, source: IpAddr) -> Option<SourceConnectionPermit> {
        let source = normalize_source_ip(source);
        let mut active = self.active.lock().expect("source connection lock poisoned");
        let count = active.entry(source).or_default();
        if *count >= self.limit {
            return None;
        }
        *count += 1;
        Some(SourceConnectionPermit {
            tracker: Arc::clone(self),
            source,
        })
    }
}

impl Drop for SourceConnectionPermit {
    fn drop(&mut self) {
        let mut active = self
            .tracker
            .active
            .lock()
            .expect("source connection lock poisoned");
        if let Some(count) = active.get_mut(&self.source) {
            *count -= 1;
            if *count == 0 {
                active.remove(&self.source);
            }
        }
    }
}

fn normalize_source_ip(source: IpAddr) -> IpAddr {
    match source {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map_or(IpAddr::V6(address), IpAddr::V4),
        source => source,
    }
}

#[derive(Default)]
struct RelayState {
    used_tickets: HashMap<[u8; 16], u64>,
    sessions: HashMap<SessionKey, SessionEntry>,
}

struct SessionEntry {
    generation: u64,
    sender: mpsc::Sender<PendingConnection>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct SessionKey {
    network_id: String,
    session_id: [u8; 16],
    first_device_id: String,
    second_device_id: String,
}

struct PendingConnection {
    claims: RelayTicketClaims,
    stream: TcpStream,
    _connection_permit: OwnedSemaphorePermit,
    _source_permit: SourceConnectionPermit,
}

impl RelayServer {
    #[must_use]
    pub fn new(config: RelayConfig) -> Self {
        let max_connections = config.max_connections.max(1);
        let source_limit = config
            .max_connections_per_source_ip
            .max(1)
            .min(max_connections);
        let (shutdown, _) = watch::channel(false);
        Self {
            inner: Arc::new(RelayInner {
                config,
                state: Mutex::new(RelayState::default()),
                next_generation: AtomicU64::new(1),
                connections: Arc::new(Semaphore::new(max_connections)),
                source_connections: Arc::new(SourceConnectionTracker {
                    active: StdMutex::new(HashMap::new()),
                    limit: source_limit,
                }),
                shutdown,
            }),
        }
    }

    /// Serve an already-bound TCP listener. Each accepted relay handshake is bounded by a permit.
    pub async fn run(&self, listener: TcpListener) -> io::Result<()> {
        self.run_until(listener, std::future::pending::<()>()).await
    }

    /// Stop accepting when `shutdown` completes, then drain paired sessions for the configured
    /// grace period before cancelling any that remain.
    pub async fn run_until<F>(&self, listener: TcpListener, shutdown: F) -> io::Result<()>
    where
        F: Future<Output = ()> + Send,
    {
        tokio::pin!(shutdown);
        let mut handlers = tokio::task::JoinSet::new();
        let mut accept_error = None;
        'accept: loop {
            tokio::select! {
                _ = &mut shutdown => break,
                Some(_) = handlers.join_next(), if !handlers.is_empty() => {},
                accepted = listener.accept() => {
                    let (stream, remote) = match accepted {
                        Ok(accepted) => accepted,
                        Err(error) => {
                            accept_error = Some(error);
                            break 'accept;
                        }
                    };
                    let Ok(permit) = Arc::clone(&self.inner.connections).try_acquire_owned() else {
                        drop(stream);
                        continue;
                    };
                    let Some(source_permit) = self
                        .inner
                        .source_connections
                        .try_acquire(remote.ip())
                    else {
                        drop(stream);
                        drop(permit);
                        continue;
                    };
                    let server = self.clone();
                    handlers.spawn(async move {
                        let _ = tokio::time::timeout(
                            AUTH_TIMEOUT,
                            server.handle_connection(stream, permit, source_permit),
                        )
                        .await;
                    });
                }
            }
        }

        let handlers_done = tokio::time::timeout(AUTH_TIMEOUT + Duration::from_secs(1), async {
            while handlers.join_next().await.is_some() {}
        })
        .await;
        if handlers_done.is_err() {
            handlers.abort_all();
        }

        let drain_deadline = tokio::time::Instant::now() + self.inner.config.shutdown_grace;
        loop {
            if self.inner.state.lock().await.sessions.is_empty()
                || tokio::time::Instant::now() >= drain_deadline
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }

        self.inner.shutdown.send_replace(true);
        let cancel_deadline = tokio::time::Instant::now() + AUTH_TIMEOUT;
        while !self.inner.state.lock().await.sessions.is_empty()
            && tokio::time::Instant::now() < cancel_deadline
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        accept_error.map_or(Ok(()), Err)
    }

    async fn handle_connection(
        &self,
        mut stream: TcpStream,
        connection_permit: OwnedSemaphorePermit,
        source_permit: SourceConnectionPermit,
    ) -> Result<(), RelayError> {
        stream.set_nodelay(true)?;
        let mut preface = [0; 8];
        stream.read_exact(&mut preface).await?;
        if &preface != RELAY_PREFACE {
            return Err(RelayError::Protocol);
        }
        let ticket_length = stream.read_u16().await? as usize;
        if ticket_length == 0 || ticket_length > MAX_TICKET_LENGTH {
            return Err(RelayError::Protocol);
        }
        let mut ticket_bytes = vec![0; ticket_length];
        stream.read_exact(&mut ticket_bytes).await?;
        let ticket = std::str::from_utf8(&ticket_bytes).map_err(|_| RelayError::Protocol)?;
        let now_ms = unix_time_ms().ok_or(RelayError::Protocol)?;
        let claims = verify_relay_ticket(&self.inner.config.ticket_key, ticket, now_ms).or_else(
            |current_error| {
                self.inner
                    .config
                    .previous_ticket_key
                    .as_ref()
                    .ok_or(current_error)
                    .and_then(|key| verify_relay_ticket(key, ticket, now_ms))
            },
        )?;
        if claims.expires_at_ms.saturating_sub(now_ms) > MAX_TICKET_LIFETIME_MS {
            return Err(RelayError::InvalidTicket);
        }
        let mut public_key = [0; 32];
        stream.read_exact(&mut public_key).await?;
        if mini_tunnel_protocol::device_id_from_public_key(&public_key) != claims.source_device_id {
            return Err(RelayError::Unauthorized);
        }

        let mut challenge = [0; 32];
        getrandom::fill(&mut challenge).map_err(|_| RelayError::Entropy)?;
        stream.write_u8(RELAY_CHALLENGE).await?;
        stream.write_all(&challenge).await?;
        let mut signature = [0; 64];
        stream.read_exact(&mut signature).await?;
        let verifying_key =
            VerifyingKey::from_bytes(&public_key).map_err(|_| RelayError::Unauthorized)?;
        verifying_key
            .verify_strict(
                &relay_auth_signing_bytes(ticket, &challenge, &public_key),
                &Signature::from_bytes(&signature),
            )
            .map_err(|_| RelayError::Unauthorized)?;

        let pending = PendingConnection {
            claims,
            stream,
            _connection_permit: connection_permit,
            _source_permit: source_permit,
        };
        self.register_connection(pending).await
    }

    async fn register_connection(&self, pending: PendingConnection) -> Result<(), RelayError> {
        let now_ms = unix_time_ms().ok_or(RelayError::Protocol)?;
        let key = session_key(&pending.claims);
        let sender = {
            let mut state = self.inner.state.lock().await;
            state
                .used_tickets
                .retain(|_, expires_at| *expires_at > now_ms);
            if state.used_tickets.contains_key(&pending.claims.ticket_id) {
                return Err(RelayError::Replay);
            }
            if state.used_tickets.len() >= MAX_USED_TICKETS {
                return Err(RelayError::Busy);
            }
            if !state.sessions.contains_key(&key)
                && state.sessions.len() >= self.inner.config.max_pending_sessions.max(1)
            {
                return Err(RelayError::Busy);
            }
            let sender = if let Some(entry) = state.sessions.get(&key) {
                entry.sender.clone()
            } else {
                let generation = self.inner.next_generation.fetch_add(1, Ordering::Relaxed);
                let (sender, receiver) = mpsc::channel(2);
                state.sessions.insert(
                    key.clone(),
                    SessionEntry {
                        generation,
                        sender: sender.clone(),
                    },
                );
                let inner = Arc::clone(&self.inner);
                let key = key.clone();
                tokio::spawn(async move {
                    pair_session(inner, key, generation, receiver).await;
                });
                sender
            };
            state
                .used_tickets
                .insert(pending.claims.ticket_id, pending.claims.expires_at_ms);
            sender
        };
        sender.try_send(pending).map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => RelayError::Busy,
            mpsc::error::TrySendError::Closed(_) => RelayError::Busy,
        })?;
        Ok(())
    }
}

async fn pair_session(
    inner: Arc<RelayInner>,
    key: SessionKey,
    generation: u64,
    mut receiver: mpsc::Receiver<PendingConnection>,
) {
    let mut shutdown = inner.shutdown.subscribe();
    let first = tokio::select! {
        _ = wait_for_shutdown(&mut shutdown) => None,
        result = tokio::time::timeout(inner.config.pair_timeout, receiver.recv()) => result.ok().flatten(),
    };
    let mut first = match first {
        Some(first) => first,
        None => {
            remove_session(&inner, &key, generation).await;
            return;
        }
    };
    let pair_deadline = tokio::time::Instant::now() + inner.config.pair_timeout;
    let second = 'wait: loop {
        let mut probe = [0; 1];
        tokio::select! {
            candidate = receiver.recv() => {
                let Some(candidate) = candidate else { break 'wait None; };
                if are_pair_claims_inverse(&first.claims, &candidate.claims) {
                    break 'wait Some(candidate);
                }
                // A session cannot be joined by two connections claiming the same side.
                drop(candidate);
            }
            result = first.stream.peek(&mut probe) => {
                match result {
                    Ok(0) | Err(_) => break 'wait None,
                    Ok(_) => break 'wait None,
                }
            }
            _ = wait_for_shutdown(&mut shutdown) => break 'wait None,
            _ = tokio::time::sleep_until(pair_deadline) => break 'wait None,
        }
    };
    let mut second = match second {
        Some(second) => second,
        None => {
            remove_session(&inner, &key, generation).await;
            return;
        }
    };

    let ready = tokio::try_join!(
        first.stream.write_u8(RELAY_READY),
        second.stream.write_u8(RELAY_READY),
    );
    if ready.is_ok() {
        let total_bytes = AtomicU64::new(0);
        let copy = async {
            let (mut first_reader, mut first_writer) = tokio::io::split(&mut first.stream);
            let (mut second_reader, mut second_writer) = tokio::io::split(&mut second.stream);
            tokio::try_join!(
                copy_session_bytes(
                    &mut first_reader,
                    &mut second_writer,
                    &total_bytes,
                    inner.config.max_session_bytes,
                ),
                copy_session_bytes(
                    &mut second_reader,
                    &mut first_writer,
                    &total_bytes,
                    inner.config.max_session_bytes,
                ),
            )
        };
        tokio::select! {
            _ = wait_for_shutdown(&mut shutdown) => {},
            _ = tokio::time::timeout(Duration::from_secs(24 * 60 * 60), copy) => {},
        }
    }
    remove_session(&inner, &key, generation).await;
}

async fn wait_for_shutdown(shutdown: &mut watch::Receiver<bool>) {
    while !*shutdown.borrow() {
        if shutdown.changed().await.is_err() {
            return;
        }
    }
}

async fn copy_session_bytes<R, W>(
    reader: &mut R,
    writer: &mut W,
    total_bytes: &AtomicU64,
    max_bytes: u64,
) -> io::Result<u64>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut buffer = vec![0; COPY_BUFFER_SIZE];
    let mut copied = 0_u64;
    loop {
        let remaining = max_bytes.saturating_sub(total_bytes.load(Ordering::Relaxed));
        if remaining == 0 {
            return Err(io::Error::other("relay session byte limit reached"));
        }
        let read_limit = remaining.min(buffer.len() as u64) as usize;
        let length = tokio::io::AsyncReadExt::read(reader, &mut buffer[..read_limit]).await?;
        if length == 0 {
            tokio::io::AsyncWriteExt::shutdown(writer).await?;
            return Ok(copied);
        }
        let allowed = reserve_session_bytes(total_bytes, length as u64, max_bytes);
        if allowed > 0 {
            tokio::io::AsyncWriteExt::write_all(writer, &buffer[..allowed]).await?;
            copied = copied.saturating_add(allowed as u64);
        }
        if allowed < length {
            return Err(io::Error::other("relay session byte limit reached"));
        }
    }
}

fn reserve_session_bytes(total_bytes: &AtomicU64, requested: u64, limit: u64) -> usize {
    let mut current = total_bytes.load(Ordering::Relaxed);
    loop {
        let reserved = requested.min(limit.saturating_sub(current));
        match total_bytes.compare_exchange_weak(
            current,
            current + reserved,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => return reserved as usize,
            Err(actual) => current = actual,
        }
    }
}

async fn remove_session(inner: &RelayInner, key: &SessionKey, generation: u64) {
    let mut state = inner.state.lock().await;
    if state
        .sessions
        .get(key)
        .is_some_and(|entry| entry.generation == generation)
    {
        state.sessions.remove(key);
    }
}

fn session_key(claims: &RelayTicketClaims) -> SessionKey {
    let (first_device_id, second_device_id) = if claims.source_device_id < claims.target_device_id {
        (
            claims.source_device_id.clone(),
            claims.target_device_id.clone(),
        )
    } else {
        (
            claims.target_device_id.clone(),
            claims.source_device_id.clone(),
        )
    };
    SessionKey {
        network_id: claims.network_id.clone(),
        session_id: claims.session_id,
        first_device_id,
        second_device_id,
    }
}

fn are_pair_claims_inverse(left: &RelayTicketClaims, right: &RelayTicketClaims) -> bool {
    left.network_id == right.network_id
        && left.session_id == right.session_id
        && left.source_device_id == right.target_device_id
        && left.target_device_id == right.source_device_id
}

pub fn unix_time_ms() -> Option<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_millis()
        .try_into()
        .ok()
}

#[derive(Debug, thiserror::Error)]
enum RelayError {
    #[error("invalid relay protocol preface")]
    Protocol,
    #[error("invalid or expired relay ticket")]
    InvalidTicket,
    #[error("relay ticket verification failed: {0}")]
    Ticket(#[from] RelayTicketError),
    #[error("relay client identity is not authorized by ticket")]
    Unauthorized,
    #[error("relay ticket has already been used")]
    Replay,
    #[error("relay capacity is full")]
    Busy,
    #[error("secure random generation failed")]
    Entropy,
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Bind and run a relay process.
pub async fn serve(address: SocketAddr, ticket_key: [u8; 32]) -> io::Result<()> {
    let listener = TcpListener::bind(address).await?;
    RelayServer::new(RelayConfig::new(ticket_key))
        .run(listener)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use mini_tunnel_protocol::{RELAY_TICKET_VERSION, RelayTicketClaims, issue_relay_ticket};

    fn identity(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn claims(source: &SigningKey, target: &SigningKey, ticket_id: u8) -> RelayTicketClaims {
        RelayTicketClaims {
            version: RELAY_TICKET_VERSION,
            network_id: "relay-test-net".to_owned(),
            source_device_id: mini_tunnel_protocol::device_id_from_public_key(
                &source.verifying_key().to_bytes(),
            ),
            target_device_id: mini_tunnel_protocol::device_id_from_public_key(
                &target.verifying_key().to_bytes(),
            ),
            session_id: [9; 16],
            ticket_id: [ticket_id; 16],
            expires_at_ms: unix_time_ms().unwrap() + 30_000,
        }
    }

    async fn connect_and_authenticate(
        relay: SocketAddr,
        ticket: &str,
        identity: &SigningKey,
    ) -> TcpStream {
        let mut stream = TcpStream::connect(relay).await.expect("connect relay");
        stream
            .write_all(RELAY_PREFACE)
            .await
            .expect("write preface");
        stream
            .write_u16(ticket.len() as u16)
            .await
            .expect("write ticket length");
        stream
            .write_all(ticket.as_bytes())
            .await
            .expect("write ticket");
        let public_key = identity.verifying_key().to_bytes();
        stream
            .write_all(&public_key)
            .await
            .expect("write public key");
        assert_eq!(
            stream.read_u8().await.expect("challenge status"),
            RELAY_CHALLENGE
        );
        let mut challenge = [0; 32];
        stream
            .read_exact(&mut challenge)
            .await
            .expect("read challenge");
        let mut message = relay_auth_signing_bytes(ticket, &challenge, &public_key);
        let signature = identity.sign(&message).to_bytes();
        message.fill(0);
        stream.write_all(&signature).await.expect("write proof");
        stream
    }

    #[tokio::test]
    async fn pairs_only_ticketed_members_and_forwards_opaque_bytes_bidirectionally() {
        let old_key = [4; 32];
        let current_key = [6; 32];
        let a = identity(1);
        let b = identity(2);
        let claims_a = claims(&a, &b, 10);
        let claims_b = claims(&b, &a, 11);
        let ticket_a = issue_relay_ticket(&old_key, &claims_a).expect("ticket A");
        let ticket_b = issue_relay_ticket(&old_key, &claims_b).expect("ticket B");
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind relay");
        let address = listener.local_addr().expect("relay address");
        let mut config = RelayConfig::new(current_key).with_previous_ticket_key(old_key);
        config.pair_timeout = Duration::from_secs(2);
        let relay = RelayServer::new(config);
        let relay_task = tokio::spawn(async move { relay.run(listener).await });

        let mut stream_a = connect_and_authenticate(address, &ticket_a, &a).await;
        let mut stream_b = connect_and_authenticate(address, &ticket_b, &b).await;
        assert_eq!(stream_a.read_u8().await.expect("A ready"), RELAY_READY);
        assert_eq!(stream_b.read_u8().await.expect("B ready"), RELAY_READY);
        stream_a.write_all(b"opaque-from-A").await.expect("write A");
        let mut from_a = [0; 13];
        stream_b.read_exact(&mut from_a).await.expect("read A");
        assert_eq!(&from_a, b"opaque-from-A");
        stream_b.write_all(b"opaque-from-B").await.expect("write B");
        let mut from_b = [0; 13];
        stream_a.read_exact(&mut from_b).await.expect("read B");
        assert_eq!(&from_b, b"opaque-from-B");
        stream_a.shutdown().await.expect("half-close A write side");
        let mut eof = [0; 1];
        assert_eq!(stream_b.read(&mut eof).await.expect("observe A EOF"), 0);
        stream_b
            .write_all(b"response-after-half-close")
            .await
            .expect("B can still send after A half-close");
        let mut response = [0; 25];
        stream_a
            .read_exact(&mut response)
            .await
            .expect("A receives response after half-close");
        assert_eq!(&response, b"response-after-half-close");
        drop(stream_a);
        drop(stream_b);
        relay_task.abort();
    }

    #[tokio::test]
    async fn rejects_replayed_tickets_and_a_key_that_does_not_match_ticket_source() {
        let key = [5; 32];
        let a = identity(3);
        let b = identity(4);
        let wrong = identity(5);
        let ticket_a = issue_relay_ticket(&key, &claims(&a, &b, 20)).expect("ticket A");
        let ticket_b = issue_relay_ticket(&key, &claims(&b, &a, 21)).expect("ticket B");
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind relay");
        let address = listener.local_addr().expect("relay address");
        let mut config = RelayConfig::new(key);
        config.pair_timeout = Duration::from_secs(2);
        let relay = RelayServer::new(config);
        let relay_task = tokio::spawn(async move { relay.run(listener).await });

        let mut first = connect_and_authenticate(address, &ticket_a, &a).await;
        let mut unauthorized = TcpStream::connect(address)
            .await
            .expect("connect unauthorized client");
        unauthorized
            .write_all(RELAY_PREFACE)
            .await
            .expect("write preface");
        unauthorized
            .write_u16(ticket_b.len() as u16)
            .await
            .expect("write ticket length");
        unauthorized
            .write_all(ticket_b.as_bytes())
            .await
            .expect("write ticket");
        unauthorized
            .write_all(&wrong.verifying_key().to_bytes())
            .await
            .expect("write wrong public key");
        assert!(
            tokio::time::timeout(Duration::from_secs(1), unauthorized.read_u8())
                .await
                .expect("unauthorized peer rejected promptly")
                .is_err()
        );

        let mut legitimate_b = connect_and_authenticate(address, &ticket_b, &b).await;
        assert_eq!(legitimate_b.read_u8().await.expect("B ready"), RELAY_READY);
        assert_eq!(first.read_u8().await.expect("A ready"), RELAY_READY);
        let mut replay = connect_and_authenticate(address, &ticket_a, &a).await;
        assert!(
            tokio::time::timeout(Duration::from_secs(1), replay.read_u8())
                .await
                .expect("replay rejected promptly")
                .is_err()
        );
        drop(legitimate_b);
        relay_task.abort();
    }

    #[tokio::test]
    async fn source_connection_limit_rejects_excess_and_releases_slots() {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind relay");
        let address = listener.local_addr().expect("relay address");
        let relay = RelayServer::new(
            RelayConfig::new([11; 32])
                .with_max_connections(4)
                .with_max_connections_per_source_ip(1),
        );
        let observed_relay = relay.clone();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let relay_task = tokio::spawn(async move {
            relay
                .run_until(listener, async {
                    let _ = shutdown_rx.await;
                })
                .await
        });

        let mut first = TcpStream::connect(address).await.expect("first connection");
        first.write_all(b"M").await.expect("hold first handshake");
        let source = normalize_source_ip(address.ip());
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if observed_relay
                    .inner
                    .source_connections
                    .active
                    .lock()
                    .expect("source lock")
                    .get(&source)
                    == Some(&1)
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("first connection should hold the source slot");

        let mut excess = TcpStream::connect(address)
            .await
            .expect("excess connection");
        let mut byte = [0; 1];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), excess.read(&mut byte))
                .await
                .expect("excess source should be rejected promptly")
                .expect("read excess close"),
            0
        );

        drop(first);
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if !observed_relay
                    .inner
                    .source_connections
                    .active
                    .lock()
                    .expect("source lock")
                    .contains_key(&source)
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("source slot should be released after disconnect");

        let mut replacement = TcpStream::connect(address)
            .await
            .expect("replacement connection");
        replacement
            .write_all(b"M")
            .await
            .expect("replacement handshake");
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if observed_relay
                    .inner
                    .source_connections
                    .active
                    .lock()
                    .expect("source lock")
                    .get(&source)
                    == Some(&1)
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("source should be able to reconnect after release");

        drop(replacement);
        let _ = shutdown_tx.send(());
        relay_task
            .await
            .expect("relay task")
            .expect("relay shutdown");
    }

    #[tokio::test]
    async fn global_and_source_permits_cover_established_sessions() {
        let key = [12; 32];
        let a = identity(10);
        let b = identity(11);
        let ticket_a = issue_relay_ticket(&key, &claims(&a, &b, 50)).expect("ticket A");
        let ticket_b = issue_relay_ticket(&key, &claims(&b, &a, 51)).expect("ticket B");
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind relay");
        let address = listener.local_addr().expect("relay address");
        let relay = RelayServer::new(
            RelayConfig::new(key)
                .with_max_connections(4)
                .with_max_connections_per_source_ip(2),
        );
        let observed_relay = relay.clone();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let relay_task = tokio::spawn(async move {
            relay
                .run_until(listener, async {
                    let _ = shutdown_rx.await;
                })
                .await
        });

        let mut stream_a = connect_and_authenticate(address, &ticket_a, &a).await;
        let mut stream_b = connect_and_authenticate(address, &ticket_b, &b).await;
        assert_eq!(stream_a.read_u8().await.expect("A ready"), RELAY_READY);
        assert_eq!(stream_b.read_u8().await.expect("B ready"), RELAY_READY);
        let source = normalize_source_ip(address.ip());
        assert_eq!(
            observed_relay
                .inner
                .source_connections
                .active
                .lock()
                .expect("source lock")
                .get(&source),
            Some(&2),
            "paired sessions retain both connection permits"
        );

        let mut excess = TcpStream::connect(address)
            .await
            .expect("excess connection");
        let mut byte = [0; 1];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), excess.read(&mut byte))
                .await
                .expect("source cap applies to established sessions")
                .expect("read rejected connection"),
            0
        );

        drop(stream_a);
        drop(stream_b);
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if !observed_relay
                    .inner
                    .source_connections
                    .active
                    .lock()
                    .expect("source lock")
                    .contains_key(&source)
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("session closure releases source slots");

        let mut replacement = TcpStream::connect(address)
            .await
            .expect("replacement connection");
        replacement
            .write_all(b"M")
            .await
            .expect("replacement accepted");
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if observed_relay
                    .inner
                    .source_connections
                    .active
                    .lock()
                    .expect("source lock")
                    .get(&source)
                    == Some(&1)
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("released source can reconnect");

        drop(replacement);
        let _ = shutdown_tx.send(());
        relay_task
            .await
            .expect("relay task")
            .expect("relay shutdown");
    }

    #[tokio::test]
    async fn enforces_one_aggregate_byte_budget_across_both_directions() {
        let key = [7; 32];
        let a = identity(6);
        let b = identity(7);
        let ticket_a = issue_relay_ticket(&key, &claims(&a, &b, 30)).expect("ticket A");
        let ticket_b = issue_relay_ticket(&key, &claims(&b, &a, 31)).expect("ticket B");
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind relay");
        let address = listener.local_addr().expect("relay address");
        let mut config = RelayConfig::new(key).with_max_session_bytes(8);
        config.pair_timeout = Duration::from_secs(2);
        let relay = RelayServer::new(config);
        let relay_task = tokio::spawn(async move { relay.run(listener).await });

        let mut stream_a = connect_and_authenticate(address, &ticket_a, &a).await;
        let mut stream_b = connect_and_authenticate(address, &ticket_b, &b).await;
        assert_eq!(stream_a.read_u8().await.expect("A ready"), RELAY_READY);
        assert_eq!(stream_b.read_u8().await.expect("B ready"), RELAY_READY);
        stream_a.write_all(b"four").await.expect("A writes four");
        let mut from_a = [0; 4];
        stream_b
            .read_exact(&mut from_a)
            .await
            .expect("B reads four");
        assert_eq!(&from_a, b"four");
        stream_b.write_all(b"also").await.expect("B writes four");
        let mut from_b = [0; 4];
        stream_a
            .read_exact(&mut from_b)
            .await
            .expect("A reads four");
        assert_eq!(&from_b, b"also");

        stream_a.write_all(b"x").await.expect("A writes over limit");
        let mut over_limit = [0; 1];
        let result =
            tokio::time::timeout(Duration::from_secs(1), stream_b.read_exact(&mut over_limit))
                .await
                .expect("relay should close when shared budget is exhausted");
        assert!(result.is_err());
        relay_task.abort();
    }

    #[tokio::test]
    async fn shutdown_stops_accepting_but_drains_established_sessions() {
        let key = [8; 32];
        let a = identity(8);
        let b = identity(9);
        let ticket_a = issue_relay_ticket(&key, &claims(&a, &b, 40)).expect("ticket A");
        let ticket_b = issue_relay_ticket(&key, &claims(&b, &a, 41)).expect("ticket B");
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind relay");
        let address = listener.local_addr().expect("relay address");
        let mut config = RelayConfig::new(key);
        config.shutdown_grace = Duration::from_secs(2);
        config.pair_timeout = Duration::from_secs(2);
        let relay = RelayServer::new(config);
        let relay_for_task = relay.clone();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let relay_task = tokio::spawn(async move {
            relay_for_task
                .run_until(listener, async {
                    let _ = shutdown_rx.await;
                })
                .await
        });

        let mut stream_a = connect_and_authenticate(address, &ticket_a, &a).await;
        let mut stream_b = connect_and_authenticate(address, &ticket_b, &b).await;
        assert_eq!(stream_a.read_u8().await.expect("A ready"), RELAY_READY);
        assert_eq!(stream_b.read_u8().await.expect("B ready"), RELAY_READY);
        shutdown_tx.send(()).expect("signal shutdown");
        tokio::time::sleep(Duration::from_millis(25)).await;
        assert!(!relay_task.is_finished(), "active session is being drained");

        stream_a
            .write_all(b"draining-session")
            .await
            .expect("session remains usable during drain");
        let mut forwarded = [0; 16];
        stream_b
            .read_exact(&mut forwarded)
            .await
            .expect("draining session forwards data");
        assert_eq!(&forwarded, b"draining-session");
        drop(stream_a);
        drop(stream_b);
        tokio::time::timeout(Duration::from_secs(1), relay_task)
            .await
            .expect("server exits after session drain")
            .expect("relay task")
            .expect("clean shutdown");

        assert!(TcpStream::connect(address).await.is_err());
    }

    #[tokio::test]
    async fn shutdown_cancels_unpaired_sessions_after_grace() {
        let key = [10; 32];
        let a = identity(10);
        let b = identity(11);
        let ticket_a = issue_relay_ticket(&key, &claims(&a, &b, 50)).expect("ticket A");
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind relay");
        let address = listener.local_addr().expect("relay address");
        let config = RelayConfig {
            shutdown_grace: Duration::ZERO,
            ..RelayConfig::new(key)
        };
        let relay = RelayServer::new(config);
        let relay_for_task = relay.clone();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let relay_task = tokio::spawn(async move {
            relay_for_task
                .run_until(listener, async {
                    let _ = shutdown_rx.await;
                })
                .await
        });
        let mut stream = connect_and_authenticate(address, &ticket_a, &a).await;
        shutdown_tx.send(()).expect("signal shutdown");
        tokio::time::timeout(Duration::from_secs(1), relay_task)
            .await
            .expect("unpaired session is cancelled")
            .expect("relay task")
            .expect("clean shutdown");
        let mut byte = [0; 1];
        let result = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut byte))
            .await
            .expect("client observes shutdown");
        assert!(result.is_err() || result.as_ref().is_ok_and(|bytes| *bytes == 0));
    }
}
