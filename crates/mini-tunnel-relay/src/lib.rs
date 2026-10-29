//! Ticket-authorized opaque TCP relay for end-to-end TLS peer streams.

use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    sync::{
        Arc,
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
    sync::{Mutex, Semaphore, mpsc},
};

pub use mini_tunnel_protocol as protocol;

const RELAY_PREFACE: &[u8; 8] = b"MTRELAY1";
const RELAY_CHALLENGE: u8 = 1;
const RELAY_READY: u8 = 2;
const MAX_TICKET_LENGTH: usize = 2048;
const MAX_CONNECTIONS: usize = 256;
const MAX_PENDING_SESSIONS: usize = 128;
const MAX_USED_TICKETS: usize = 16_384;
const AUTH_TIMEOUT: Duration = Duration::from_secs(5);
const PAIR_TIMEOUT: Duration = Duration::from_secs(25);
const MAX_TICKET_LIFETIME_MS: u64 = 120_000;
const COPY_BUFFER_SIZE: usize = 16 * 1024;

#[derive(Debug, Clone)]
pub struct RelayConfig {
    pub ticket_key: [u8; 32],
    pub max_connections: usize,
    pub max_pending_sessions: usize,
    pub pair_timeout: Duration,
}

impl RelayConfig {
    #[must_use]
    pub fn new(ticket_key: [u8; 32]) -> Self {
        Self {
            ticket_key,
            max_connections: MAX_CONNECTIONS,
            max_pending_sessions: MAX_PENDING_SESSIONS,
            pair_timeout: PAIR_TIMEOUT,
        }
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
}

impl RelayServer {
    #[must_use]
    pub fn new(config: RelayConfig) -> Self {
        let max_connections = config.max_connections.max(1);
        Self {
            inner: Arc::new(RelayInner {
                config,
                state: Mutex::new(RelayState::default()),
                next_generation: AtomicU64::new(1),
                connections: Arc::new(Semaphore::new(max_connections)),
            }),
        }
    }

    /// Serve an already-bound TCP listener. Each accepted relay handshake is bounded by a permit.
    pub async fn run(&self, listener: TcpListener) -> io::Result<()> {
        loop {
            let (stream, _remote) = listener.accept().await?;
            let Ok(permit) = Arc::clone(&self.inner.connections).try_acquire_owned() else {
                drop(stream);
                continue;
            };
            let server = self.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let _ = tokio::time::timeout(AUTH_TIMEOUT, server.handle_connection(stream)).await;
            });
        }
    }

    async fn handle_connection(&self, mut stream: TcpStream) -> Result<(), RelayError> {
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
        let claims = verify_relay_ticket(&self.inner.config.ticket_key, ticket, now_ms)?;
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

        let pending = PendingConnection { claims, stream };
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
    let mut first = match tokio::time::timeout(inner.config.pair_timeout, receiver.recv()).await {
        Ok(Some(first)) => first,
        Ok(None) | Err(_) => {
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
        let _ = tokio::time::timeout(
            Duration::from_secs(24 * 60 * 60),
            tokio::io::copy_bidirectional_with_sizes(
                &mut first.stream,
                &mut second.stream,
                COPY_BUFFER_SIZE,
                COPY_BUFFER_SIZE,
            ),
        )
        .await;
    }
    remove_session(&inner, &key, generation).await;
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
        let key = [4; 32];
        let a = identity(1);
        let b = identity(2);
        let claims_a = claims(&a, &b, 10);
        let claims_b = claims(&b, &a, 11);
        let ticket_a = issue_relay_ticket(&key, &claims_a).expect("ticket A");
        let ticket_b = issue_relay_ticket(&key, &claims_b).expect("ticket B");
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind relay");
        let address = listener.local_addr().expect("relay address");
        let mut config = RelayConfig::new(key);
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
}
