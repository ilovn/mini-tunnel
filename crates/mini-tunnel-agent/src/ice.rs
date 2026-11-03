//! Bounded adapter between the Sans-I/O ICE agent and the shared UDP socket driver.

use std::{
    collections::{HashMap, VecDeque},
    future::Future,
    io::{self, IoSliceMut},
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::{Duration, Instant},
};

use bytes::BytesMut;
use rtc_ice::Agent;
use rtc_shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use sansio::Protocol;
use thiserror::Error;
use tokio::{
    io::Interest,
    net::UdpSocket,
    sync::{mpsc, oneshot, watch},
};

use mini_tunnel_protocol::IceCredentials;

use crate::candidate::{CandidateType as SignaledCandidateType, SignaledCandidate};
use crate::stun::is_stun_datagram;

/// Maximum ICE checks drained during one socket-driver turn.
pub const MAX_ICE_TRANSMITS_PER_TURN: usize = 64;
const MAX_SOCKET_QUEUE_CAPACITY: usize = 128;
const MAX_UDP_DATAGRAM_SIZE: usize = u16::MAX as usize;
const MAX_ICE_SESSIONS: usize = 1024;
const MAX_SESSION_PEER_ADDRESSES: usize = 16;
const MAX_PENDING_STUN_QUERIES: usize = 8;
const MAX_PENDING_ICE_TRANSACTIONS: usize = 4096;
const ICE_TRANSACTION_TTL: Duration = Duration::from_secs(30);
const ICE_CONSENT_INTERVAL: Duration = Duration::from_secs(5);
#[cfg(test)]
pub(crate) const ICE_CONSENT_MAX_INTERVAL: Duration = Duration::from_secs(6);
pub(crate) const ICE_DISCONNECTED_TIMEOUT: Duration = Duration::from_secs(15);
const ICE_FAILED_TIMEOUT: Duration = Duration::from_secs(30);
pub(crate) const ICE_DISCONNECTED_RECOVERY_GRACE: Duration = Duration::from_secs(5);

/// Generate an ephemeral ICE credential pair suitable for both rtc-ice and coordinator signaling.
/// The coordinator accepts the RFC 8445 alphanumeric, `+`, and `/` alphabet; credentials are
/// intentionally returned to the caller and are never persisted by the agent.
pub fn generate_ice_credentials(generation: u64) -> Result<IceCredentials, crate::IdentityError> {
    if generation == 0 {
        return Err(crate::IdentityError::Transport(
            "ICE generation must be greater than zero".to_owned(),
        ));
    }
    let mut ufrag = [0_u8; 18];
    let mut password = [0_u8; 24];
    getrandom::fill(&mut ufrag).map_err(|_| crate::IdentityError::Random)?;
    getrandom::fill(&mut password).map_err(|_| crate::IdentityError::Random)?;
    use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
    Ok(IceCredentials {
        ufrag: STANDARD_NO_PAD.encode(ufrag),
        password: STANDARD_NO_PAD.encode(password),
        generation,
    })
}

/// Create the rtc-ice configuration using the exact credentials published to peers.
#[must_use]
pub fn agent_config(credentials: &IceCredentials) -> rtc_ice::AgentConfig {
    rtc_ice::AgentConfig {
        local_ufrag: credentials.ufrag.clone(),
        local_pwd: credentials.password.clone(),
        keepalive_interval: Some(ICE_CONSENT_INTERVAL),
        disconnected_timeout: Some(ICE_DISCONNECTED_TIMEOUT),
        failed_timeout: Some(ICE_FAILED_TIMEOUT),
        ..Default::default()
    }
}

#[derive(Debug, Clone)]
pub struct IceDatagram {
    pub local_addr: SocketAddr,
    pub peer_addr: SocketAddr,
    pub payload: Vec<u8>,
}

#[derive(Debug)]
struct QuinnDatagram {
    peer_addr: SocketAddr,
    payload: Vec<u8>,
}

#[derive(Debug, Default)]
struct SharedSocket {
    socket: Mutex<Option<Arc<UdpSocket>>>,
}

/// A handle to the UDP socket shared by Quinn and the ICE driver.
#[derive(Clone, Debug, Default)]
pub struct IceSocketHandle {
    shared: Arc<SharedSocket>,
}

impl IceSocketHandle {
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket()?.local_addr()
    }

    pub async fn send_to(&self, payload: &[u8], peer: SocketAddr) -> io::Result<usize> {
        self.socket()?.send_to(payload, peer).await
    }

    fn socket(&self) -> io::Result<Arc<UdpSocket>> {
        self.shared
            .socket
            .lock()
            .map_err(|_| io::Error::other("ICE socket handle lock is poisoned"))?
            .clone()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "ICE socket is not bound"))
    }
}

/// The Quinn endpoint and ICE socket/receive channel that share one bound UDP port.
pub struct IcedPeerEndpoint {
    pub endpoint: quinn::Endpoint,
    pub socket: IceSocketHandle,
    pub ice_router: IceDatagramRouterHandle,
}

/// Cloneable registration handle for the endpoint's live ICE datagram dispatcher.
#[derive(Clone, Default)]
pub struct IceDatagramRouterHandle {
    router: Arc<Mutex<IceDatagramRouter>>,
}

impl IceDatagramRouterHandle {
    pub fn register(
        &self,
        local_ufrag: String,
        remote_ufrag: String,
        queue_capacity: usize,
    ) -> Result<mpsc::Receiver<IceDatagram>, IceRouterError> {
        self.router
            .lock()
            .map_err(|_| IceRouterError::Poisoned)?
            .register(local_ufrag, remote_ufrag, queue_capacity)
    }

    pub fn associate_authenticated_peer(
        &self,
        local_ufrag: &str,
        remote_ufrag: &str,
        peer_addr: SocketAddr,
    ) -> Result<(), IceRouterError> {
        self.router
            .lock()
            .map_err(|_| IceRouterError::Poisoned)?
            .associate_authenticated_peer(local_ufrag, remote_ufrag, peer_addr)
    }

    fn register_ice_request(
        &self,
        local_ufrag: &str,
        remote_ufrag: &str,
        peer_addr: SocketAddr,
        payload: &[u8],
    ) -> Result<(), IceRouterError> {
        let Some(transaction_id) = crate::stun::binding_request_transaction_id(payload) else {
            return Ok(());
        };
        self.router
            .lock()
            .map_err(|_| IceRouterError::Poisoned)?
            .register_ice_transaction(
                local_ufrag,
                remote_ufrag,
                peer_addr,
                transaction_id,
                Instant::now(),
            )
    }

    /// Deliver a routed datagram to its ICE agent and bind the source address only when the
    /// agent accepts the authenticated STUN check.
    pub fn handle_datagram(
        &self,
        local_ufrag: &str,
        remote_ufrag: &str,
        driver: &mut IceAgentDriver,
        datagram: IceDatagram,
        now: Instant,
    ) -> Result<bool, IceRouterError> {
        let accepted = driver
            .handle_datagram(now, datagram.peer_addr, None, &datagram.payload)
            .map_err(|error| IceRouterError::AgentRejected(error.to_string()))?;
        if accepted {
            self.associate_authenticated_peer(local_ufrag, remote_ufrag, datagram.peer_addr)?;
        }
        Ok(accepted)
    }

    /// Query a STUN mapping through the same UDP socket used by Quinn and ICE.
    ///
    /// The sole socket receiver routes this request's Binding success response by transaction ID;
    /// the response is never consumed by Quinn or delivered as a peer ICE check.
    pub async fn discover_mapped_address(
        &self,
        socket: &IceSocketHandle,
        server: SocketAddr,
    ) -> Result<SocketAddr, crate::stun::StunError> {
        for _ in 0..crate::stun::RETRIES {
            let transaction_id = crate::stun::new_transaction_id()?;
            let (sender, receiver) = oneshot::channel();
            {
                let mut router = self.router.lock().map_err(|_| {
                    crate::stun::StunError::Io(io::Error::other("ICE router lock is poisoned"))
                })?;
                router.register_stun_query(transaction_id, server, sender)?;
            }
            if let Err(error) = socket
                .send_to(&crate::stun::binding_request(transaction_id), server)
                .await
            {
                self.remove_pending_stun_query(transaction_id);
                return Err(error.into());
            }
            match tokio::time::timeout(crate::stun::RESPONSE_TIMEOUT, receiver).await {
                Ok(Ok(result)) => return result,
                Ok(Err(_)) => self.remove_pending_stun_query(transaction_id),
                Err(_) => self.remove_pending_stun_query(transaction_id),
            }
        }
        Err(crate::stun::StunError::Timeout)
    }

    fn remove_pending_stun_query(&self, transaction_id: [u8; 12]) {
        if let Ok(mut router) = self.router.lock() {
            router.pending_stun.remove(&transaction_id);
        }
    }

    pub fn unregister(
        &self,
        local_ufrag: &str,
        remote_ufrag: &str,
    ) -> Result<bool, IceRouterError> {
        Ok(self
            .router
            .lock()
            .map_err(|_| IceRouterError::Poisoned)?
            .unregister(local_ufrag, remote_ufrag))
    }

    fn route(&self, datagram: IceDatagram) {
        if let Ok(mut router) = self.router.lock() {
            let _ = router.route(datagram);
        }
    }
}

struct IceRoute {
    sender: mpsc::Sender<IceDatagram>,
    peer_addresses: VecDeque<SocketAddr>,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct IceSessionKey {
    local_ufrag: String,
    remote_ufrag: String,
}

/// Bounded dispatcher for the STUN receive queue of one shared Quinn socket.
///
/// Binding requests are routed by both ufrags in USERNAME, which allows one local ufrag to serve
/// multiple peer sessions. Responses without USERNAME are routed only after the owning agent
/// confirms an authenticated request via `associate_authenticated_peer`.
struct PendingStunQuery {
    server: SocketAddr,
    response: oneshot::Sender<Result<SocketAddr, crate::stun::StunError>>,
}

struct PendingIceTransaction {
    session: IceSessionKey,
    peer_addr: SocketAddr,
    expires_at: Instant,
}

#[derive(Default)]
pub struct IceDatagramRouter {
    sessions: HashMap<IceSessionKey, IceRoute>,
    peer_sessions: HashMap<SocketAddr, IceSessionKey>,
    pending_stun: HashMap<[u8; 12], PendingStunQuery>,
    pending_ice: HashMap<[u8; 12], PendingIceTransaction>,
}

impl IceDatagramRouter {
    fn ufrag_registration_presence(&self, key: &IceSessionKey) -> (bool, bool) {
        let local_known = self
            .sessions
            .keys()
            .any(|session| session.local_ufrag == key.local_ufrag);
        let remote_known = self
            .sessions
            .keys()
            .any(|session| session.remote_ufrag == key.remote_ufrag);
        (local_known, remote_known)
    }

    fn register_stun_query(
        &mut self,
        transaction_id: [u8; 12],
        server: SocketAddr,
        response: oneshot::Sender<Result<SocketAddr, crate::stun::StunError>>,
    ) -> Result<(), crate::stun::StunError> {
        if self.pending_stun.len() >= MAX_PENDING_STUN_QUERIES
            || self.pending_stun.contains_key(&transaction_id)
        {
            return Err(crate::stun::StunError::Io(io::Error::other(
                "too many pending STUN mapping queries",
            )));
        }
        self.pending_stun
            .insert(transaction_id, PendingStunQuery { server, response });
        Ok(())
    }

    pub fn register(
        &mut self,
        local_ufrag: String,
        remote_ufrag: String,
        queue_capacity: usize,
    ) -> Result<mpsc::Receiver<IceDatagram>, IceRouterError> {
        if !valid_ice_ufrag(&local_ufrag)
            || !valid_ice_ufrag(&remote_ufrag)
            || !(1..=MAX_SOCKET_QUEUE_CAPACITY).contains(&queue_capacity)
        {
            return Err(IceRouterError::InvalidRegistration);
        }
        let key = IceSessionKey {
            local_ufrag,
            remote_ufrag,
        };
        if self.sessions.contains_key(&key) {
            return Err(IceRouterError::DuplicateSession);
        }
        if self.sessions.len() >= MAX_ICE_SESSIONS {
            return Err(IceRouterError::SessionLimit);
        }
        let (sender, receiver) = mpsc::channel(queue_capacity);
        self.sessions.insert(
            key,
            IceRoute {
                sender,
                peer_addresses: VecDeque::new(),
            },
        );
        Ok(receiver)
    }

    /// Associate an address only after the ICE agent accepted an authenticated check from it.
    pub fn associate_authenticated_peer(
        &mut self,
        local_ufrag: &str,
        remote_ufrag: &str,
        peer_addr: SocketAddr,
    ) -> Result<(), IceRouterError> {
        if peer_addr.port() == 0 || peer_addr.ip().is_unspecified() || peer_addr.ip().is_multicast()
        {
            return Err(IceRouterError::InvalidPeerAddress);
        }
        let key = IceSessionKey {
            local_ufrag: local_ufrag.to_owned(),
            remote_ufrag: remote_ufrag.to_owned(),
        };
        if !self.sessions.contains_key(&key) {
            return Err(IceRouterError::UnknownUfrag);
        }
        if let Some(previous) = self.peer_sessions.get(&peer_addr).cloned()
            && previous != key
            && let Some(previous_route) = self.sessions.get_mut(&previous)
        {
            previous_route
                .peer_addresses
                .retain(|address| *address != peer_addr);
        }

        let route = self
            .sessions
            .get_mut(&key)
            .ok_or(IceRouterError::UnknownUfrag)?;
        route.peer_addresses.retain(|address| *address != peer_addr);
        let evicted = if route.peer_addresses.len() >= MAX_SESSION_PEER_ADDRESSES {
            route.peer_addresses.pop_front()
        } else {
            None
        };
        if let Some(evicted) = evicted
            && self.peer_sessions.get(&evicted) == Some(&key)
        {
            self.peer_sessions.remove(&evicted);
        }
        route.peer_addresses.push_back(peer_addr);
        self.peer_sessions.insert(peer_addr, key);
        Ok(())
    }

    fn register_ice_transaction(
        &mut self,
        local_ufrag: &str,
        remote_ufrag: &str,
        peer_addr: SocketAddr,
        transaction_id: [u8; 12],
        now: Instant,
    ) -> Result<(), IceRouterError> {
        self.pending_ice
            .retain(|_, pending| pending.expires_at > now);
        let session = IceSessionKey {
            local_ufrag: local_ufrag.to_owned(),
            remote_ufrag: remote_ufrag.to_owned(),
        };
        if !self.sessions.contains_key(&session) {
            return Err(IceRouterError::UnknownUfrag);
        }
        if !self.pending_ice.contains_key(&transaction_id)
            && self.pending_ice.len() >= MAX_PENDING_ICE_TRANSACTIONS
        {
            return Err(IceRouterError::TransactionLimit);
        }
        self.pending_ice.insert(
            transaction_id,
            PendingIceTransaction {
                session,
                peer_addr,
                expires_at: now + ICE_TRANSACTION_TTL,
            },
        );
        Ok(())
    }

    /// Remove a peer session and all authenticated address bindings it owned.
    pub fn unregister(&mut self, local_ufrag: &str, remote_ufrag: &str) -> bool {
        let key = IceSessionKey {
            local_ufrag: local_ufrag.to_owned(),
            remote_ufrag: remote_ufrag.to_owned(),
        };
        let Some(route) = self.sessions.remove(&key) else {
            return false;
        };
        self.pending_ice.retain(|_, pending| pending.session != key);
        for address in route.peer_addresses {
            if self
                .peer_sessions
                .get(&address)
                .is_some_and(|owner| owner == &key)
            {
                self.peer_sessions.remove(&address);
            }
        }
        true
    }

    /// Route one demultiplexed STUN datagram without blocking the shared UDP receive loop.
    pub fn route(&mut self, datagram: IceDatagram) -> bool {
        if let Some(transaction_id) = crate::stun::binding_success_transaction_id(&datagram.payload)
            && self
                .pending_stun
                .get(&transaction_id)
                .is_some_and(|query| query.server == datagram.peer_addr)
        {
            if let Some(query) = self.pending_stun.remove(&transaction_id) {
                let result = crate::stun::parse_binding_response(&datagram.payload, transaction_id);
                let _ = query.response.send(result);
            }
            return true;
        }
        let route = if let Some(username) = crate::stun::ice_username(&datagram.payload) {
            let Some(key) = ice_session_key(username) else {
                tracing::debug!(
                    peer = %datagram.peer_addr,
                    route_miss = "malformed_ice_username",
                    "dropping STUN datagram with malformed ICE username"
                );
                return false;
            };
            let route = self.sessions.get(&key);
            if route.is_none() {
                let (local_ufrag_known, remote_ufrag_known) =
                    self.ufrag_registration_presence(&key);
                tracing::debug!(
                    peer = %datagram.peer_addr,
                    route_miss = "unknown_ice_session",
                    local_ufrag_known,
                    remote_ufrag_known,
                    active_ice_sessions = self.sessions.len(),
                    "dropping STUN datagram because its ICE session is not registered"
                );
            }
            route
        } else if let Some(transaction_id) =
            crate::stun::binding_response_transaction_id(&datagram.payload)
        {
            if let Some(pending) = self.pending_ice.get(&transaction_id) {
                if pending.peer_addr != datagram.peer_addr || pending.expires_at <= Instant::now() {
                    tracing::debug!(
                        peer = %datagram.peer_addr,
                        route_miss = "ice_response_peer_or_transaction_mismatch",
                        "dropping STUN response that does not match a live ICE transaction"
                    );
                    return false;
                }
                let key = pending.session.clone();
                self.pending_ice.remove(&transaction_id);
                self.sessions.get(&key)
            } else {
                self.peer_sessions
                    .get(&datagram.peer_addr)
                    .and_then(|key| self.sessions.get(key))
            }
        } else {
            self.peer_sessions
                .get(&datagram.peer_addr)
                .and_then(|key| self.sessions.get(key))
        };
        let Some(route) = route else {
            if !crate::stun::is_stun_datagram(&datagram.payload) {
                tracing::trace!(
                    peer = %datagram.peer_addr,
                    route_miss = "unassociated_non_stun_datagram",
                    "dropping non-STUN datagram without an authenticated peer binding"
                );
            } else {
                tracing::debug!(
                    peer = %datagram.peer_addr,
                    route_miss = "unmatched_stun_response_or_peer",
                    "dropping STUN datagram without a registered transaction or peer binding"
                );
            }
            return false;
        };
        match route.sender.try_send(datagram) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(datagram)) => {
                tracing::warn!(peer = %datagram.peer_addr, "dropping ICE datagram because the session queue is full");
                false
            }
            Err(mpsc::error::TrySendError::Closed(datagram)) => {
                tracing::debug!(peer = %datagram.peer_addr, "dropping ICE datagram because the session is closed");
                false
            }
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum IceRouterError {
    #[error("ICE route registration is invalid")]
    InvalidRegistration,
    #[error("maximum ICE session count reached")]
    SessionLimit,
    #[error("ICE peer session is already registered")]
    DuplicateSession,
    #[error("ICE ufrag is not registered")]
    UnknownUfrag,
    #[error("maximum authenticated peer addresses reached for ICE session")]
    PeerAddressLimit,
    #[error("maximum pending ICE transaction count reached")]
    TransactionLimit,
    #[error("peer address is not usable")]
    InvalidPeerAddress,
    #[error("ICE datagram router lock is poisoned")]
    Poisoned,
    #[error("ICE agent rejected routed datagram: {0}")]
    AgentRejected(String),
}

fn ice_session_key(username: &str) -> Option<IceSessionKey> {
    let (local_ufrag, remote_ufrag) = username.split_once(':')?;
    (valid_ice_ufrag(local_ufrag) && valid_ice_ufrag(remote_ufrag) && !remote_ufrag.contains(':'))
        .then(|| IceSessionKey {
            local_ufrag: local_ufrag.to_owned(),
            remote_ufrag: remote_ufrag.to_owned(),
        })
}

fn valid_ice_ufrag(ufrag: &str) -> bool {
    (4..=256).contains(&ufrag.len())
        && ufrag
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/')
}

/// Construct a server endpoint whose UDP socket demultiplexes ICE STUN and QUIC datagrams.
///
/// The ICE queue is bounded and uses `try_send`; overloaded ICE checks are dropped so the Quinn
/// receive loop remains responsive. The regular peer endpoint constructor remains unchanged until
/// credential signaling and the ICE driver are wired into peer setup.
pub fn peer_endpoint_with_ice(
    identity: &crate::Identity,
    bind_addr: SocketAddr,
    queue_capacity: usize,
) -> Result<IcedPeerEndpoint, crate::IdentityError> {
    if !(1..=MAX_SOCKET_QUEUE_CAPACITY).contains(&queue_capacity) {
        return Err(crate::IdentityError::Transport(format!(
            "ICE socket queue capacity must be between 1 and {MAX_SOCKET_QUEUE_CAPACITY}"
        )));
    }
    let socket = std::net::UdpSocket::bind(bind_addr)
        .map_err(|error| crate::IdentityError::Transport(error.to_string()))?;
    iced_endpoint_from_socket(identity, socket, queue_capacity)
}

/// Probe a STUN server and create the ICE/QUIC endpoint from that exact UDP socket.
pub async fn peer_endpoint_with_ice_and_stun(
    identity: &crate::Identity,
    bind_addr: SocketAddr,
    stun_server: SocketAddr,
    queue_capacity: usize,
) -> Result<(IcedPeerEndpoint, SocketAddr), crate::IdentityError> {
    if !(1..=MAX_SOCKET_QUEUE_CAPACITY).contains(&queue_capacity) {
        return Err(crate::IdentityError::Transport(format!(
            "ICE socket queue capacity must be between 1 and {MAX_SOCKET_QUEUE_CAPACITY}"
        )));
    }
    let socket = UdpSocket::bind(bind_addr)
        .await
        .map_err(|error| crate::IdentityError::Transport(error.to_string()))?;
    let mapped_address = crate::stun::discover_mapped_address(&socket, stun_server)
        .await
        .map_err(|error| crate::IdentityError::Transport(error.to_string()))?;
    let socket = socket
        .into_std()
        .map_err(|error| crate::IdentityError::Transport(error.to_string()))?;
    let endpoint = iced_endpoint_from_socket(identity, socket, queue_capacity)?;
    Ok((endpoint, mapped_address))
}

fn iced_endpoint_from_socket(
    identity: &crate::Identity,
    socket: std::net::UdpSocket,
    queue_capacity: usize,
) -> Result<IcedPeerEndpoint, crate::IdentityError> {
    if !(1..=MAX_SOCKET_QUEUE_CAPACITY).contains(&queue_capacity) {
        return Err(crate::IdentityError::Transport(format!(
            "ICE socket queue capacity must be between 1 and {MAX_SOCKET_QUEUE_CAPACITY}"
        )));
    }
    socket
        .set_nonblocking(true)
        .map_err(|error| crate::IdentityError::Transport(error.to_string()))?;
    let (runtime, socket_handle, mut ice_datagrams) = IcedQuinnRuntime::new(queue_capacity);
    let endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(super::peer_server_config(identity)?),
        socket,
        Arc::new(runtime),
    )
    .map_err(|error| crate::IdentityError::Transport(error.to_string()))?;
    let ice_router = IceDatagramRouterHandle::default();
    let dispatch_router = ice_router.clone();
    tokio::spawn(async move {
        while let Some(datagram) = ice_datagrams.recv().await {
            dispatch_router.route(datagram);
        }
    });
    Ok(IcedPeerEndpoint {
        endpoint,
        socket: socket_handle,
        ice_router,
    })
}

#[derive(Debug)]
struct IcedQuinnRuntime {
    inner: quinn::TokioRuntime,
    shared_socket: IceSocketHandle,
    quinn_rx: Arc<Mutex<Option<mpsc::Receiver<QuinnDatagram>>>>,
    ice_tx: mpsc::Sender<IceDatagram>,
    quinn_tx: mpsc::Sender<QuinnDatagram>,
}

impl IcedQuinnRuntime {
    fn new(queue_capacity: usize) -> (Self, IceSocketHandle, mpsc::Receiver<IceDatagram>) {
        let (quinn_tx, quinn_rx) = mpsc::channel(queue_capacity);
        let (ice_tx, ice_rx) = mpsc::channel(queue_capacity);
        let shared_socket = IceSocketHandle::default();
        (
            Self {
                inner: quinn::TokioRuntime,
                shared_socket: shared_socket.clone(),
                quinn_rx: Arc::new(Mutex::new(Some(quinn_rx))),
                ice_tx,
                quinn_tx,
            },
            shared_socket,
            ice_rx,
        )
    }
}

impl quinn::Runtime for IcedQuinnRuntime {
    fn new_timer(&self, instant: std::time::Instant) -> Pin<Box<dyn quinn::AsyncTimer>> {
        self.inner.new_timer(instant)
    }

    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        self.inner.spawn(future);
    }

    fn wrap_udp_socket(
        &self,
        socket: std::net::UdpSocket,
    ) -> io::Result<Arc<dyn quinn::AsyncUdpSocket>> {
        let socket = Arc::new(UdpSocket::from_std(socket)?);
        let local_addr = socket.local_addr()?;
        {
            let mut shared = self
                .shared_socket
                .shared
                .socket
                .lock()
                .map_err(|_| io::Error::other("ICE socket handle lock is poisoned"))?;
            if shared.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "ICE runtime supports exactly one UDP socket",
                ));
            }
            *shared = Some(Arc::clone(&socket));
        }
        let quinn_rx = self
            .quinn_rx
            .lock()
            .map_err(|_| io::Error::other("QUIC receive queue lock is poisoned"))?
            .take()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "ICE runtime supports exactly one UDP socket",
                )
            })?;
        // The socket task is the sole receiver. Each datagram occupies one queue entry, so GRO
        // segments never need to be compacted or reconstructed in Quinn's RecvMeta array.
        let receive_socket = Arc::clone(&socket);
        let ice_tx = self.ice_tx.clone();
        let quinn_tx = self.quinn_tx.clone();
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
        tokio::spawn(async move {
            let mut buffer = vec![0; MAX_UDP_DATAGRAM_SIZE];
            loop {
                let (length, peer_addr) = tokio::select! {
                    changed = shutdown_rx.changed() => {
                        if changed.is_err() || *shutdown_rx.borrow() {
                            break;
                        }
                        continue;
                    }
                    result = receive_socket.recv_from(&mut buffer) => match result {
                        Ok(result) => result,
                        Err(_) => break,
                    }
                };
                let payload = buffer[..length].to_vec();
                if crate::stun::is_stun_datagram(&payload) {
                    let _ = ice_tx.try_send(IceDatagram {
                        local_addr,
                        peer_addr,
                        payload,
                    });
                } else {
                    let _ = quinn_tx.try_send(QuinnDatagram { peer_addr, payload });
                }
            }
        });
        Ok(Arc::new(IcedQuinnUdpSocket {
            socket,
            receiver: Mutex::new(quinn_rx),
            shutdown: shutdown_tx,
        }))
    }

    fn now(&self) -> std::time::Instant {
        self.inner.now()
    }
}

#[derive(Debug)]
struct IcedQuinnUdpSocket {
    socket: Arc<UdpSocket>,
    receiver: Mutex<mpsc::Receiver<QuinnDatagram>>,
    shutdown: tokio::sync::watch::Sender<bool>,
}

impl Drop for IcedQuinnUdpSocket {
    fn drop(&mut self) {
        self.shutdown.send_replace(true);
    }
}

impl quinn::AsyncUdpSocket for IcedQuinnUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        Box::pin(IcedUdpPoller {
            socket: Arc::clone(&self.socket),
        })
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit<'_>) -> io::Result<()> {
        if transmit.segment_size.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "ICE socket does not support UDP segmentation",
            ));
        }
        self.socket.try_io(Interest::WRITABLE, || {
            let sent = self
                .socket
                .try_send_to(transmit.contents, transmit.destination)?;
            if sent != transmit.contents.len() {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "incomplete UDP datagram send",
                ));
            }
            Ok(())
        })
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        buffers: &mut [IoSliceMut<'_>],
        metadata: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut receiver = match self.receiver.lock() {
            Ok(receiver) => receiver,
            Err(_) => {
                return Poll::Ready(Err(io::Error::other("QUIC receive queue lock is poisoned")));
            }
        };
        let limit = buffers.len().min(metadata.len());
        let mut received = 0;
        while received < limit {
            match receiver.poll_recv(cx) {
                Poll::Ready(Some(datagram)) => {
                    if datagram.payload.len() > buffers[received].len() {
                        continue;
                    }
                    buffers[received][..datagram.payload.len()].copy_from_slice(&datagram.payload);
                    metadata[received] = quinn::udp::RecvMeta {
                        addr: datagram.peer_addr,
                        len: datagram.payload.len(),
                        stride: datagram.payload.len(),
                        ecn: None,
                        dst_ip: None,
                    };
                    received += 1;
                }
                Poll::Ready(None) => {
                    if received == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "UDP socket receive task stopped",
                        )));
                    }
                    break;
                }
                Poll::Pending => {
                    if received == 0 {
                        return Poll::Pending;
                    }
                    break;
                }
            }
        }
        Poll::Ready(Ok(received))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }

    fn may_fragment(&self) -> bool {
        true
    }
}

#[derive(Debug)]
struct IcedUdpPoller {
    socket: Arc<UdpSocket>,
}

impl quinn::UdpPoller for IcedUdpPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.socket.poll_send_ready(cx)
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum IceDriverError {
    #[error("datagram is not a valid STUN envelope")]
    InvalidDatagram,
    #[error("ICE agent rejected an input: {0}")]
    Agent(String),
    #[error("ICE connectivity checks timed out")]
    Timeout,
    #[error("shared UDP socket failed: {0}")]
    Socket(String),
    #[error("ICE datagram router failed: {0}")]
    Router(String),
}

/// Drives an RFC 8445 agent without owning its UDP socket or clock.
///
/// The caller supplies the same local socket address used by Quinn, forwards only validated STUN
/// datagrams to `handle_datagram`, sends values from `poll_transmits` on that socket, and calls
/// `handle_timeout` at `next_timeout`. Non-STUN datagrams must remain on Quinn's receive path.
pub struct IceAgentDriver {
    agent: Agent,
    local_addr: SocketAddr,
    local_candidate_count: usize,
    remote_candidate_count: usize,
}

/// Return whether a failed datagram send is specific to this candidate and should not stop the
/// rest of the ICE checklist from trying other addresses.
pub(crate) fn is_candidate_send_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::NetworkUnreachable
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::AddrNotAvailable
            | io::ErrorKind::PermissionDenied
            | io::ErrorKind::InvalidInput
            | io::ErrorKind::Unsupported
    )
}

fn is_authenticated_peer_rebound(
    selected_pair: Option<(SocketAddr, SocketAddr)>,
    observed_peer: SocketAddr,
    authenticated: bool,
) -> bool {
    authenticated && selected_pair.is_some_and(|(_, selected_peer)| selected_peer != observed_peer)
}

fn signal_authenticated_peer_rebound(
    degraded: &watch::Sender<bool>,
    selected_pair: Option<(SocketAddr, SocketAddr)>,
    observed_peer: SocketAddr,
    authenticated: bool,
) -> bool {
    let rebound = is_authenticated_peer_rebound(selected_pair, observed_peer, authenticated);
    if rebound {
        degraded.send_replace(true);
    }
    rebound
}

/// Channel-owned cancellation and failure signal for a nominated ICE consent session.
pub struct IceConsentMonitor {
    cancel: watch::Sender<bool>,
    degraded: watch::Sender<bool>,
    failed: watch::Receiver<bool>,
    task: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

/// Driver-side signals that track the nominated pair's consent and shutdown lifecycle.
pub struct IceConsentSignals {
    cancel: watch::Receiver<bool>,
    degraded: watch::Sender<bool>,
}

impl IceConsentSignals {
    #[must_use]
    pub fn new(cancel: watch::Receiver<bool>, degraded: watch::Sender<bool>) -> Self {
        Self { cancel, degraded }
    }
}

impl IceConsentMonitor {
    /// Create a monitor handle and the receivers/sender consumed by its driver task.
    pub fn new() -> (Self, watch::Receiver<bool>, watch::Sender<bool>) {
        let (cancel, cancel_receiver) = watch::channel(false);
        let (degraded, _) = watch::channel(false);
        let (failure_sender, failed) = watch::channel(false);
        (
            Self {
                cancel,
                degraded,
                failed,
                task: tokio::sync::Mutex::new(None),
            },
            cancel_receiver,
            failure_sender,
        )
    }

    pub(crate) fn failure_receiver(&self) -> watch::Receiver<bool> {
        self.failed.clone()
    }

    pub(crate) fn degraded_receiver(&self) -> watch::Receiver<bool> {
        self.degraded.subscribe()
    }

    /// Signal early that the nominated pair has lost consent but is still within ICE's
    /// disconnected grace period. The owner can prepare a reliable fallback before failure.
    pub fn degraded_sender(&self) -> watch::Sender<bool> {
        self.degraded.clone()
    }

    pub async fn set_task(&self, task: tokio::task::JoinHandle<()>) {
        *self.task.lock().await = Some(task);
    }

    pub async fn stop(&self) {
        self.cancel.send_replace(true);
        if let Some(task) = self.task.lock().await.take() {
            let _ = task.await;
        }
    }
}

impl Drop for IceConsentMonitor {
    fn drop(&mut self) {
        self.cancel.send_replace(true);
    }
}

impl IceAgentDriver {
    #[must_use]
    pub fn new(agent: Agent, local_addr: SocketAddr) -> Self {
        Self {
            agent,
            local_addr,
            local_candidate_count: 0,
            remote_candidate_count: 0,
        }
    }

    /// Build an ICE connectivity-check session for one peer.
    ///
    /// Candidate gathering remains the caller's responsibility; this constructor refuses empty
    /// candidate sets so it cannot silently start an agent that has no viable path to check.
    pub fn for_peer(
        local_credentials: &IceCredentials,
        remote_credentials: &IceCredentials,
        local_candidates: &[SocketAddr],
        remote_candidates: &[SocketAddr],
        controlling: bool,
        now: Instant,
    ) -> Result<Self, IceDriverError> {
        let local_candidates: Vec<_> = local_candidates
            .iter()
            .copied()
            .map(|address| SignaledCandidate {
                address,
                transport: crate::candidate::CandidateTransport::Udp,
                candidate_type: SignaledCandidateType::Host,
            })
            .collect();
        let remote_candidates: Vec<_> = remote_candidates
            .iter()
            .copied()
            .map(|address| SignaledCandidate {
                address,
                transport: crate::candidate::CandidateTransport::Udp,
                candidate_type: SignaledCandidateType::Host,
            })
            .collect();
        Self::for_peer_with_candidates(
            local_credentials,
            remote_credentials,
            &local_candidates,
            &remote_candidates,
            controlling,
            now,
        )
    }

    /// Build a session while preserving host/server-reflexive candidate metadata.
    pub fn for_peer_with_candidates(
        local_credentials: &IceCredentials,
        remote_credentials: &IceCredentials,
        local_candidates: &[SignaledCandidate],
        remote_candidates: &[SignaledCandidate],
        controlling: bool,
        now: Instant,
    ) -> Result<Self, IceDriverError> {
        let local_socket_addr = local_candidates
            .first()
            .map(|candidate| candidate.address)
            .ok_or_else(|| {
                IceDriverError::Agent("local and remote ICE candidates are required".to_owned())
            })?;
        Self::for_peer_with_candidates_on_socket(
            local_socket_addr,
            local_credentials,
            remote_credentials,
            local_candidates,
            remote_candidates,
            controlling,
            now,
        )
    }

    /// Build a session using an explicit bound socket address distinct from advertised candidates.
    pub fn for_peer_with_candidates_on_socket(
        local_socket_addr: SocketAddr,
        local_credentials: &IceCredentials,
        remote_credentials: &IceCredentials,
        local_candidates: &[SignaledCandidate],
        remote_candidates: &[SignaledCandidate],
        controlling: bool,
        now: Instant,
    ) -> Result<Self, IceDriverError> {
        if local_credentials.generation == 0 || remote_credentials.generation == 0 {
            return Err(IceDriverError::Agent(
                "ICE credential generations must be greater than zero".to_owned(),
            ));
        }
        if local_candidates.is_empty() || remote_candidates.is_empty() {
            return Err(IceDriverError::Agent(
                "local and remote ICE candidates are required".to_owned(),
            ));
        }
        let crypto = rtc_ice::crypto::default_provider()
            .map_err(|error| IceDriverError::Agent(error.to_string()))?;
        let mut agent = Agent::new(now, Arc::new(agent_config(local_credentials)), crypto)
            .map_err(|error| IceDriverError::Agent(error.to_string()))?;
        if !local_candidates
            .iter()
            .any(|candidate| candidate.address == local_socket_addr)
        {
            // The socket wrapper currently reports one local address for every received packet.
            // Keep an internal bind-address candidate so rtc-ice can associate inbound checks even
            // when the socket is wildcard-bound; this address is never signaled to remote peers.
            agent
                .add_local_candidate(host_candidate(local_socket_addr)?)
                .map_err(|error| IceDriverError::Agent(error.to_string()))?;
        }
        for candidate in local_candidates {
            agent
                .add_local_candidate(ice_candidate(*candidate)?)
                .map_err(|error| IceDriverError::Agent(error.to_string()))?;
        }
        for candidate in remote_candidates {
            agent
                .add_remote_candidate(ice_candidate(*candidate)?)
                .map_err(|error| IceDriverError::Agent(error.to_string()))?;
        }
        agent
            .start_connectivity_checks(
                now,
                controlling,
                remote_credentials.ufrag.clone(),
                remote_credentials.password.clone(),
            )
            .map_err(|error| IceDriverError::Agent(error.to_string()))?;
        let mut driver = Self::new(agent, local_socket_addr);
        driver.local_candidate_count = local_candidates.len();
        driver.remote_candidate_count = remote_candidates.len();
        Ok(driver)
    }

    /// Feed one datagram to ICE. `false` means it was not STUN or rtc-ice rejected the message.
    pub fn handle_datagram(
        &mut self,
        now: Instant,
        peer_addr: SocketAddr,
        ecn: Option<rtc_shared::EcnCodepoint>,
        message: &[u8],
    ) -> Result<bool, IceDriverError> {
        if !is_stun_datagram(message) {
            return Ok(false);
        }
        match self.agent.handle_read(TaggedBytesMut {
            now,
            transport: TransportContext {
                local_addr: self.local_addr,
                peer_addr,
                transport_protocol: TransportProtocol::UDP,
                ecn,
            },
            message: BytesMut::from(message),
        }) {
            Ok(()) => Ok(true),
            Err(error) => {
                // Incoming STUN is untrusted network input. rtc-ice can update role or checklist
                // state while still returning a per-message error (for example after rejecting a
                // conflicting or unauthenticated request); that must not abort the whole ICE session.
                tracing::trace!(peer = %peer_addr, %error, "discarded ICE datagram");
                Ok(false)
            }
        }
    }

    /// Advance ICE retransmission and state timers to `now`.
    pub fn handle_timeout(&mut self, now: Instant) -> Result<(), IceDriverError> {
        self.agent
            .handle_timeout(now)
            .map_err(|error| IceDriverError::Agent(error.to_string()))
    }

    /// Return the next ICE deadline, if the agent has one.
    pub fn next_timeout(&mut self) -> Option<Instant> {
        self.agent.poll_timeout()
    }

    /// Drain at most one driver's work budget of connectivity checks for transmission.
    pub fn poll_transmits(&mut self) -> Vec<TaggedBytesMut> {
        let mut transmits = Vec::with_capacity(MAX_ICE_TRANSMITS_PER_TURN);
        for _ in 0..MAX_ICE_TRANSMITS_PER_TURN {
            let Some(transmit) = self.agent.poll_write() else {
                break;
            };
            transmits.push(transmit);
        }
        transmits
    }

    /// Drain at most one driver's work budget of connection and selected-pair events.
    pub fn poll_events(&mut self) -> Vec<rtc_ice::Event> {
        let mut events = Vec::with_capacity(MAX_ICE_TRANSMITS_PER_TURN);
        for _ in 0..MAX_ICE_TRANSMITS_PER_TURN {
            let Some(event) = self.agent.poll_event() else {
                break;
            };
            events.push(event.event);
        }
        events
    }

    /// Drain state and selection events while running an initial or recovery checklist.
    ///
    /// Keeping these events visible makes a failed checklist distinguishable from one that
    /// reached a connected state but never completed nomination, without logging ICE secrets
    /// or candidate addresses.
    fn log_check_events(&mut self) {
        for event in self.poll_events() {
            match event {
                rtc_ice::Event::ConnectionStateChange(state) => {
                    tracing::debug!(?state, "ICE connectivity state changed during checks");
                }
                rtc_ice::Event::SelectedCandidatePairChange(_, _) => {
                    tracing::debug!("ICE selected a candidate pair during checks");
                }
                rtc_ice::Event::RoleChange(controlling) => {
                    tracing::debug!(controlling, "ICE role changed during checks");
                }
                _ => {}
            }
        }
    }

    /// Read the ICE-selected local/remote socket pair, if nomination has completed.
    pub fn selected_pair(&self) -> Option<(SocketAddr, SocketAddr)> {
        self.agent
            .get_selected_candidate_pair()
            .map(|(local, remote)| (local.addr(), remote.addr()))
    }

    /// Run checks over the endpoint's shared UDP socket until nomination or timeout.
    pub async fn run_checks(
        &mut self,
        socket: &IceSocketHandle,
        router: &IceDatagramRouterHandle,
        local_ufrag: &str,
        remote_ufrag: &str,
        datagrams: &mut mpsc::Receiver<IceDatagram>,
        timeout: Duration,
    ) -> Result<(SocketAddr, SocketAddr), IceDriverError> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(IceDriverError::Timeout)?;
        let mut outbound_datagrams = 0_u64;
        let mut candidate_send_errors = 0_u64;
        let mut inbound_stun_datagrams = 0_u64;
        let mut agent_accepted_datagrams = 0_u64;
        loop {
            let now = Instant::now();
            self.handle_timeout(now)?;
            self.log_check_events();
            for transmit in self.poll_transmits() {
                outbound_datagrams = outbound_datagrams.saturating_add(1);
                router
                    .register_ice_request(
                        local_ufrag,
                        remote_ufrag,
                        transmit.transport.peer_addr,
                        &transmit.message,
                    )
                    .map_err(|error| IceDriverError::Router(error.to_string()))?;
                if let Err(error) = socket
                    .send_to(&transmit.message, transmit.transport.peer_addr)
                    .await
                {
                    if !is_candidate_send_error(&error) {
                        return Err(IceDriverError::Socket(error.to_string()));
                    }
                    candidate_send_errors = candidate_send_errors.saturating_add(1);
                    // A candidate-specific routing error must not abort the checklist: another
                    // address family or server-reflexive candidate may still be reachable.
                    tracing::debug!(
                        %error,
                        "ICE candidate send failed; continuing connectivity checks"
                    );
                }
            }
            if let Some(pair) = self.selected_pair() {
                tracing::debug!(
                    local_candidates = self.local_candidate_count,
                    remote_candidates = self.remote_candidate_count,
                    outbound_datagrams,
                    candidate_send_errors,
                    inbound_stun_datagrams,
                    agent_accepted_datagrams,
                    nominated = true,
                    "ICE checklist summary"
                );
                return Ok(pair);
            }
            if now >= deadline {
                tracing::debug!(
                    local_candidates = self.local_candidate_count,
                    remote_candidates = self.remote_candidate_count,
                    outbound_datagrams,
                    candidate_send_errors,
                    inbound_stun_datagrams,
                    agent_accepted_datagrams,
                    nominated = false,
                    "ICE checklist summary"
                );
                return Err(IceDriverError::Timeout);
            }
            let next_deadline = self.next_timeout().unwrap_or(deadline).min(deadline);
            tokio::select! {
                datagram = datagrams.recv() => {
                    let datagram = datagram.ok_or_else(|| IceDriverError::Router("peer datagram queue closed".to_owned()))?;
                    inbound_stun_datagrams = inbound_stun_datagrams.saturating_add(1);
                    let accepted = router
                        .handle_datagram(local_ufrag, remote_ufrag, self, datagram, Instant::now())
                        .map_err(|error| IceDriverError::Router(error.to_string()))?;
                    if accepted {
                        agent_accepted_datagrams = agent_accepted_datagrams.saturating_add(1);
                    }
                    self.log_check_events();
                }
                () = tokio::time::sleep_until(tokio::time::Instant::from_std(next_deadline)) => {
                    if Instant::now() >= deadline {
                        tracing::debug!(
                            local_candidates = self.local_candidate_count,
                            remote_candidates = self.remote_candidate_count,
                            outbound_datagrams,
                            candidate_send_errors,
                            inbound_stun_datagrams,
                            agent_accepted_datagrams,
                            nominated = false,
                            "ICE checklist summary"
                        );
                        return Err(IceDriverError::Timeout);
                    }
                    self.log_check_events();
                }
            }
        }
    }

    /// Keep a nominated pair's RFC 7675 consent fresh until cancellation or consent loss.
    pub async fn monitor_consent(
        &mut self,
        socket: &IceSocketHandle,
        router: &IceDatagramRouterHandle,
        local_ufrag: &str,
        remote_ufrag: &str,
        datagrams: &mut mpsc::Receiver<IceDatagram>,
        signals: &mut IceConsentSignals,
    ) -> Result<(), IceDriverError> {
        let mut disconnected_since = None;
        loop {
            if *signals.cancel.borrow() {
                return Ok(());
            }
            let now = Instant::now();
            self.handle_timeout(now)?;
            for transmit in self.poll_transmits() {
                router
                    .register_ice_request(
                        local_ufrag,
                        remote_ufrag,
                        transmit.transport.peer_addr,
                        &transmit.message,
                    )
                    .map_err(|error| IceDriverError::Router(error.to_string()))?;
                socket
                    .send_to(&transmit.message, transmit.transport.peer_addr)
                    .await
                    .map_err(|error| IceDriverError::Socket(error.to_string()))?;
            }
            let mut disconnected = false;
            let mut failed = false;
            for event in self.poll_events() {
                if let rtc_ice::Event::ConnectionStateChange(state) = event {
                    match state {
                        rtc_ice::state::ConnectionState::Disconnected => disconnected = true,
                        rtc_ice::state::ConnectionState::Failed
                        | rtc_ice::state::ConnectionState::Closed => failed = true,
                        rtc_ice::state::ConnectionState::Connected => {
                            disconnected_since = None;
                            signals.degraded.send_replace(false);
                        }
                        _ => {}
                    }
                }
            }
            if disconnected {
                signals.degraded.send_replace(true);
                disconnected_since.get_or_insert(now);
            }
            if failed || (self.selected_pair().is_none() && disconnected_since.is_none()) {
                return Err(IceDriverError::Timeout);
            }
            if disconnected_since.is_some_and(|since| {
                now.saturating_duration_since(since) >= ICE_DISCONNECTED_RECOVERY_GRACE
            }) {
                return Err(IceDriverError::Timeout);
            }
            let next_deadline = self
                .next_timeout()
                .unwrap_or_else(|| now + Duration::from_secs(1))
                .min(
                    disconnected_since
                        .map(|since| since + ICE_DISCONNECTED_RECOVERY_GRACE)
                        .unwrap_or_else(|| now + Duration::from_secs(1)),
                );
            tokio::select! {
                changed = signals.cancel.changed() => {
                    if changed.is_err() || *signals.cancel.borrow() {
                        return Ok(());
                    }
                }
                datagram = datagrams.recv() => {
                    let datagram = datagram.ok_or_else(|| IceDriverError::Router("peer datagram queue closed".to_owned()))?;
                    let observed_peer = datagram.peer_addr;
                    let previous_pair = self.selected_pair();
                    let accepted = router
                        .handle_datagram(local_ufrag, remote_ufrag, self, datagram, Instant::now())
                        .map_err(|error| IceDriverError::Router(error.to_string()))?;
                    if signal_authenticated_peer_rebound(
                        &signals.degraded,
                        previous_pair,
                        observed_peer,
                        accepted,
                    ) {
                        tracing::warn!(
                            "authenticated ICE peer address changed; preparing reliable fallback"
                        );
                    }
                }
                () = tokio::time::sleep_until(tokio::time::Instant::from_std(next_deadline)) => {}
            }
        }
    }
}

fn host_candidate(address: SocketAddr) -> Result<rtc_ice::candidate::Candidate, IceDriverError> {
    use rtc_ice::candidate::{CandidateConfig, candidate_host::CandidateHostConfig};
    CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: address.ip().to_string(),
            port: address.port(),
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()
    .map_err(|error| IceDriverError::Agent(error.to_string()))
}

fn ice_candidate(
    candidate: SignaledCandidate,
) -> Result<rtc_ice::candidate::Candidate, IceDriverError> {
    if candidate.transport != crate::candidate::CandidateTransport::Udp {
        return Err(IceDriverError::Agent(
            "ICE connectivity checks require UDP candidates".to_owned(),
        ));
    }
    match candidate.candidate_type {
        SignaledCandidateType::Host => host_candidate(candidate.address),
        SignaledCandidateType::ServerReflexive { related_address } => {
            use rtc_ice::candidate::{
                CandidateConfig, candidate_server_reflexive::CandidateServerReflexiveConfig,
            };
            CandidateServerReflexiveConfig {
                base_config: CandidateConfig {
                    network: "udp".to_owned(),
                    address: candidate.address.ip().to_string(),
                    port: candidate.address.port(),
                    component: 1,
                    ..Default::default()
                },
                rel_addr: related_address.ip().to_string(),
                rel_port: related_address.port(),
                ..Default::default()
            }
            .new_candidate_server_reflexive()
            .map_err(|error| IceDriverError::Agent(error.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        thread,
        time::Duration,
    };

    use super::*;

    #[tokio::test]
    async fn shared_socket_stun_refresh_observes_nat_mapping_changes() {
        let temp =
            std::env::temp_dir().join(format!("mini-tunnel-stun-refresh-{}", uuid::Uuid::new_v4()));
        let identity = crate::Identity::load_or_create_at(temp.join("device.key")).unwrap();
        let endpoint = peer_endpoint_with_ice(&identity, "127.0.0.1:0".parse().unwrap(), 16)
            .expect("create shared ICE/QUIC endpoint");
        let mut ice_receiver = endpoint
            .ice_router
            .register("local".to_owned(), "remote".to_owned(), 2)
            .expect("register an ICE route during STUN refresh");
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_address = server.local_addr().unwrap();
        let mappings = [
            "198.51.100.10:41000".parse::<SocketAddr>().unwrap(),
            "198.51.100.11:52000".parse::<SocketAddr>().unwrap(),
        ];
        let (request_seen, request_seen_rx) = oneshot::channel();
        let (release_response_tx, release_response) = oneshot::channel();
        let responder = tokio::spawn(async move {
            let mut request_seen = Some(request_seen);
            let mut release_response = Some(release_response);
            for (index, mapping) in mappings.into_iter().enumerate() {
                let mut request = [0; 1500];
                let (length, source) = server.recv_from(&mut request).await.unwrap();
                assert_eq!(length, 20);
                let transaction: [u8; 12] = request[8..20].try_into().unwrap();
                if index == 0 {
                    request_seen
                        .take()
                        .unwrap()
                        .send(())
                        .expect("test is waiting for the pending STUN request");
                    release_response
                        .take()
                        .unwrap()
                        .await
                        .expect("release the first STUN response after the ICE packet");
                }
                server
                    .send_to(&binding_success(mapping, transaction), source)
                    .await
                    .unwrap();
            }
        });
        let local = endpoint.socket.local_addr().unwrap();
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let router = endpoint.ice_router.clone();
        let socket = endpoint.socket.clone();
        let first_query = tokio::spawn(async move {
            router
                .discover_mapped_address(&socket, server_address)
                .await
        });
        request_seen_rx
            .await
            .expect("STUN request is in flight before sending ICE");
        peer.send_to(&ice_packet("local:remote", local).payload, local)
            .await
            .expect("send ICE datagram while mapping query is pending");
        let routed = tokio::time::timeout(Duration::from_secs(1), ice_receiver.recv())
            .await
            .expect("ICE datagram is routed before the pending STUN response")
            .expect("ICE route remains open");
        assert_eq!(routed.peer_addr, peer.local_addr().unwrap());
        release_response_tx
            .send(())
            .expect("allow the pending STUN query to complete");
        let first = first_query
            .await
            .expect("join initial mapping query")
            .expect("initial mapping discovery over shared socket");
        let second = endpoint
            .ice_router
            .discover_mapped_address(&endpoint.socket, server_address)
            .await
            .expect("mapping refresh over shared socket");
        responder.await.unwrap();
        assert_eq!(first, "198.51.100.10:41000".parse().unwrap());
        assert_eq!(second, "198.51.100.11:52000".parse().unwrap());
        assert_eq!(endpoint.socket.local_addr().unwrap(), local);
        endpoint.endpoint.close(0_u32.into(), b"test complete");
        std::fs::remove_dir_all(temp).unwrap();
    }

    fn binding_success(address: SocketAddr, transaction: [u8; 12]) -> Vec<u8> {
        let mut response = vec![0; 20];
        response[..2].copy_from_slice(&crate::stun::BINDING_SUCCESS.to_be_bytes());
        response[2..4].copy_from_slice(&12_u16.to_be_bytes());
        response[4..8].copy_from_slice(&0x2112_A442_u32.to_be_bytes());
        response[8..20].copy_from_slice(&transaction);
        response.extend_from_slice(&0x0020_u16.to_be_bytes());
        response.extend_from_slice(&8_u16.to_be_bytes());
        response.extend_from_slice(&[0, 1]);
        let port = address.port() ^ 0x2112;
        response.extend_from_slice(&port.to_be_bytes());
        let ip = match address.ip() {
            std::net::IpAddr::V4(ip) => ip.octets(),
            std::net::IpAddr::V6(_) => panic!("test expects IPv4 mapping"),
        };
        response.extend(
            ip.into_iter()
                .zip(0x2112_A442_u32.to_be_bytes())
                .map(|(a, b)| a ^ b),
        );
        response
    }

    #[test]
    fn generated_credentials_match_the_agent_config_and_are_valid_for_signaling() {
        let credentials = generate_ice_credentials(1).expect("generate ICE credentials");
        assert_eq!(credentials.ufrag.len(), 24);
        assert_eq!(credentials.password.len(), 32);
        assert!(credentials.ufrag.bytes().all(valid_ice_char));
        assert!(credentials.password.bytes().all(valid_ice_char));
        let config = agent_config(&credentials);
        assert_eq!(config.local_ufrag, credentials.ufrag);
        assert_eq!(config.local_pwd, credentials.password);
        assert_eq!(config.keepalive_interval, Some(ICE_CONSENT_INTERVAL));
        assert_eq!(config.disconnected_timeout, Some(ICE_DISCONNECTED_TIMEOUT));
        assert_eq!(config.failed_timeout, Some(ICE_FAILED_TIMEOUT));
        assert_eq!(ICE_CONSENT_INTERVAL, Duration::from_secs(5));
        assert!(ICE_CONSENT_INTERVAL >= Duration::from_secs(4));
        assert_eq!(ICE_FAILED_TIMEOUT, Duration::from_secs(30));
        assert!(ICE_CONSENT_INTERVAL < ICE_DISCONNECTED_TIMEOUT);
        assert!(ICE_DISCONNECTED_TIMEOUT < ICE_FAILED_TIMEOUT);
    }

    #[test]
    fn generated_credentials_are_fresh_and_generation_must_be_nonzero() {
        let first = generate_ice_credentials(1).expect("first credentials");
        let second = generate_ice_credentials(2).expect("second credentials");
        assert_ne!(first.ufrag, second.ufrag);
        assert_ne!(first.password, second.password);
        assert!(generate_ice_credentials(0).is_err());
    }

    #[test]
    fn builds_server_reflexive_candidate_with_related_address() {
        let candidate = SignaledCandidate {
            address: "203.0.113.7:5000".parse().unwrap(),
            transport: crate::candidate::CandidateTransport::Udp,
            candidate_type: SignaledCandidateType::ServerReflexive {
                related_address: "192.168.1.4:4000".parse().unwrap(),
            },
        };
        let built = ice_candidate(candidate).expect("build srflx candidate");
        assert_eq!(
            built.candidate_type(),
            rtc_ice::candidate::CandidateType::ServerReflexive
        );
        let related = built.related_address().expect("related address");
        assert_eq!(related.address, "192.168.1.4");
        assert_eq!(related.port, 4000);
    }

    #[test]
    fn typed_candidates_use_the_actual_socket_address_for_datagram_context() {
        let local_credentials = generate_ice_credentials(1).expect("local credentials");
        let remote_credentials = generate_ice_credentials(1).expect("remote credentials");
        let local_candidate = SignaledCandidate {
            address: "127.0.0.1:4000".parse().unwrap(),
            transport: crate::candidate::CandidateTransport::Udp,
            candidate_type: SignaledCandidateType::Host,
        };
        let remote_candidate = SignaledCandidate {
            address: "127.0.0.1:5000".parse().unwrap(),
            transport: crate::candidate::CandidateTransport::Udp,
            candidate_type: SignaledCandidateType::Host,
        };
        let driver = IceAgentDriver::for_peer_with_candidates_on_socket(
            "0.0.0.0:4000".parse().unwrap(),
            &local_credentials,
            &remote_credentials,
            &[local_candidate],
            &[remote_candidate],
            true,
            Instant::now(),
        )
        .expect("create ICE driver");
        assert_eq!(driver.local_addr, "0.0.0.0:4000".parse().unwrap());
        assert!(
            driver
                .agent
                .get_local_candidates()
                .iter()
                .any(|candidate| { candidate.addr() == "0.0.0.0:4000".parse().unwrap() })
        );
        assert!(
            driver
                .agent
                .get_local_candidates()
                .iter()
                .any(|candidate| { candidate.addr() == "127.0.0.1:4000".parse().unwrap() })
        );
    }

    fn valid_ice_char(byte: u8) -> bool {
        byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/'
    }

    fn driver() -> IceAgentDriver {
        let crypto = rtc_ice::crypto::default_provider().expect("ring ICE crypto provider");
        let agent = Agent::new(
            Instant::now(),
            Arc::new(rtc_ice::AgentConfig::default()),
            crypto,
        )
        .expect("construct ICE agent");
        IceAgentDriver::new(agent, "127.0.0.1:4000".parse().expect("local address"))
    }

    #[test]
    fn non_stun_datagrams_are_left_for_quinn() {
        let mut driver = driver();
        assert_eq!(
            driver.handle_datagram(
                Instant::now(),
                "127.0.0.1:4001".parse().expect("peer address"),
                None,
                &[0xc0; 24],
            ),
            Ok(false)
        );
        assert!(driver.poll_transmits().is_empty());
        assert!(driver.selected_pair().is_none());
    }

    #[test]
    fn only_authenticated_source_changes_on_a_nominated_pair_mark_path_degraded() {
        let local: SocketAddr = "192.0.2.10:42000".parse().unwrap();
        let old_peer: SocketAddr = "198.51.100.10:42000".parse().unwrap();
        let rebound_peer: SocketAddr = "198.51.100.10:52000".parse().unwrap();
        let pair = Some((local, old_peer));
        let (degraded, receiver) = watch::channel(false);
        assert!(signal_authenticated_peer_rebound(
            &degraded,
            pair,
            rebound_peer,
            true
        ));
        assert!(*receiver.borrow());

        let (degraded, receiver) = watch::channel(false);
        assert!(!signal_authenticated_peer_rebound(
            &degraded,
            pair,
            rebound_peer,
            false
        ));
        assert!(!*receiver.borrow());
        assert!(!signal_authenticated_peer_rebound(
            &degraded, pair, old_peer, true
        ));
        assert!(!signal_authenticated_peer_rebound(
            &degraded,
            None,
            rebound_peer,
            true
        ));
    }

    #[test]
    fn two_sans_io_agents_authenticate_checks_and_nominate_a_candidate_pair() {
        let now = Instant::now();
        let address_a: SocketAddr = "127.0.0.1:41001".parse().unwrap();
        let address_b: SocketAddr = "127.0.0.1:41002".parse().unwrap();
        let advertised_a = generate_ice_credentials(1).expect("A signaling credentials");
        let advertised_b = generate_ice_credentials(1).expect("B signaling credentials");
        let mut driver_a = IceAgentDriver::for_peer(
            &advertised_a,
            &advertised_b,
            &[address_a],
            &[address_b],
            true,
            now,
        )
        .expect("construct controlling peer session");
        let mut driver_b = IceAgentDriver::for_peer(
            &advertised_b,
            &advertised_a,
            &[address_b],
            &[address_a],
            false,
            now,
        )
        .expect("construct controlled peer session");

        for _ in 0..250 {
            let now = Instant::now();
            driver_a.handle_timeout(now).expect("tick A");
            driver_b.handle_timeout(now).expect("tick B");
            let from_a = driver_a.poll_transmits();
            let from_b = driver_b.poll_transmits();
            for message in from_a {
                assert!(
                    driver_b
                        .handle_datagram(now, address_a, message.transport.ecn, &message.message,)
                        .expect("deliver A check")
                );
            }
            for message in from_b {
                assert!(
                    driver_a
                        .handle_datagram(now, address_b, message.transport.ecn, &message.message,)
                        .expect("deliver B check")
                );
            }
            if driver_a.selected_pair().is_some() && driver_b.selected_pair().is_some() {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }

        assert_eq!(driver_a.selected_pair(), Some((address_a, address_b)));
        assert_eq!(driver_b.selected_pair(), Some((address_b, address_a)));
    }

    #[test]
    fn simultaneous_controlling_roles_resolve_conflict_and_nominate() {
        let now = Instant::now();
        let address_a: SocketAddr = "127.0.0.1:41101".parse().unwrap();
        let address_b: SocketAddr = "127.0.0.1:41102".parse().unwrap();
        let credentials_a = generate_ice_credentials(1).expect("A signaling credentials");
        let credentials_b = generate_ice_credentials(1).expect("B signaling credentials");
        let mut driver_a = IceAgentDriver::for_peer(
            &credentials_a,
            &credentials_b,
            &[address_a],
            &[address_b],
            true,
            now,
        )
        .expect("construct A initially controlling");
        let mut driver_b = IceAgentDriver::for_peer(
            &credentials_b,
            &credentials_a,
            &[address_b],
            &[address_a],
            true,
            now,
        )
        .expect("construct B initially controlling");

        for _ in 0..250 {
            let now = Instant::now();
            driver_a.handle_timeout(now).expect("tick A");
            driver_b.handle_timeout(now).expect("tick B");
            let from_a = driver_a.poll_transmits();
            let from_b = driver_b.poll_transmits();
            for message in from_a {
                driver_b
                    .handle_datagram(now, address_a, message.transport.ecn, &message.message)
                    .expect("deliver A check");
            }
            for message in from_b {
                driver_a
                    .handle_datagram(now, address_b, message.transport.ecn, &message.message)
                    .expect("deliver B check");
            }
            if driver_a.selected_pair().is_some() && driver_b.selected_pair().is_some() {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }

        assert_eq!(driver_a.selected_pair(), Some((address_a, address_b)));
        assert_eq!(driver_b.selected_pair(), Some((address_b, address_a)));
    }

    #[test]
    fn learns_peer_reflexive_remote_candidate_from_a_mapped_source() {
        let now = Instant::now();
        let address_a: SocketAddr = "127.0.0.1:41301".parse().unwrap();
        let address_b: SocketAddr = "127.0.0.1:41302".parse().unwrap();
        let mapped_a: SocketAddr = "127.0.0.1:52301".parse().unwrap();
        let credentials_a = generate_ice_credentials(1).expect("A signaling credentials");
        let credentials_b = generate_ice_credentials(1).expect("B signaling credentials");
        let mut driver_a = IceAgentDriver::for_peer(
            &credentials_a,
            &credentials_b,
            &[address_a],
            &[address_b],
            true,
            now,
        )
        .expect("construct A session");
        let mut driver_b = IceAgentDriver::for_peer(
            &credentials_b,
            &credentials_a,
            &[address_b],
            &[address_a],
            false,
            now,
        )
        .expect("construct B session");

        driver_a.handle_timeout(now).expect("tick A");
        let checks = driver_a.poll_transmits();
        assert!(!checks.is_empty(), "A should start a connectivity check");
        for check in checks {
            assert!(
                driver_b
                    .handle_datagram(now, mapped_a, check.transport.ecn, &check.message)
                    .expect("deliver authenticated check through simulated NAT")
            );
        }

        let learned = driver_b
            .agent
            .get_remote_candidates()
            .iter()
            .find(|candidate| candidate.addr() == mapped_a)
            .expect("NAT-mapped address should be learned as a peer-reflexive candidate");
        assert_eq!(
            learned.candidate_type(),
            rtc_ice::candidate::CandidateType::PeerReflexive
        );
    }

    #[test]
    fn learns_authenticated_peer_reflexive_candidate_after_nat_rebinding() {
        let address_a: SocketAddr = "127.0.0.1:41401".parse().unwrap();
        let address_b: SocketAddr = "127.0.0.1:41402".parse().unwrap();
        let mapped_a_before: SocketAddr = "127.0.0.1:52401".parse().unwrap();
        let mapped_a_after: SocketAddr = "127.0.0.1:52402".parse().unwrap();
        let credentials_a = generate_ice_credentials(1).expect("A signaling credentials");
        let credentials_b = generate_ice_credentials(1).expect("B signaling credentials");
        let start = Instant::now();
        let mut driver_a = IceAgentDriver::for_peer(
            &credentials_a,
            &credentials_b,
            &[address_a],
            &[address_b],
            true,
            start,
        )
        .expect("construct controlling peer session");
        let mut driver_b = IceAgentDriver::for_peer(
            &credentials_b,
            &credentials_a,
            &[address_b],
            &[address_a],
            false,
            start,
        )
        .expect("construct controlled peer session");

        // Model a stateful NAT: A's packets to B arrive from its current public mapping,
        // while replies addressed to that mapping return to A's original UDP socket.
        let exchange = |driver_a: &mut IceAgentDriver,
                        driver_b: &mut IceAgentDriver,
                        mapped_a: SocketAddr,
                        start: Instant,
                        ticks: u64| {
            let mut rebound_authenticated = false;
            for tick in 0..ticks {
                let now = start + Duration::from_millis(tick * 20);
                driver_a.handle_timeout(now).expect("tick A");
                driver_b.handle_timeout(now).expect("tick B");
                for transmit in driver_a.poll_transmits() {
                    if transmit.transport.peer_addr == address_b {
                        let previous_pair = driver_b.selected_pair();
                        let accepted = driver_b
                            .handle_datagram(
                                now,
                                mapped_a,
                                transmit.transport.ecn,
                                &transmit.message,
                            )
                            .expect("deliver A check through the current NAT mapping");
                        rebound_authenticated |=
                            is_authenticated_peer_rebound(previous_pair, mapped_a, accepted);
                    }
                }
                for transmit in driver_b.poll_transmits() {
                    if transmit.transport.peer_addr == mapped_a {
                        driver_a
                            .handle_datagram(
                                now,
                                address_b,
                                transmit.transport.ecn,
                                &transmit.message,
                            )
                            .expect("deliver response through the current NAT mapping");
                    }
                }
            }
            rebound_authenticated
        };

        assert!(!exchange(
            &mut driver_a,
            &mut driver_b,
            mapped_a_before,
            start,
            500,
        ));
        assert!(
            driver_a.selected_pair().is_some(),
            "initial ICE path nominates"
        );
        assert!(
            driver_b.selected_pair().is_some(),
            "peer nominates initial mapping"
        );
        assert!(
            driver_b
                .agent
                .get_remote_candidates()
                .iter()
                .any(|candidate| candidate.addr() == mapped_a_before)
        );

        // Keep both ICE generations and the local socket addresses unchanged; only the NAT's
        // public source port changes before its next authenticated consent check.
        let rebound_at = start + Duration::from_secs(11);
        assert!(exchange(
            &mut driver_a,
            &mut driver_b,
            mapped_a_after,
            rebound_at,
            500,
        ));
        assert!(
            driver_a.selected_pair().is_some(),
            "A retains an authenticated ICE path"
        );
        assert!(
            driver_b.selected_pair().is_some(),
            "B retains an authenticated ICE path"
        );
        assert!(
            driver_b
                .agent
                .get_remote_candidates()
                .iter()
                .any(|candidate| candidate.addr() == mapped_a_after
                    && candidate.candidate_type()
                        == rtc_ice::candidate::CandidateType::PeerReflexive),
            "the peer must learn the rebound mapping only from an authenticated ICE check"
        );
        assert_eq!(
            driver_b.selected_pair(),
            Some((address_b, mapped_a_before)),
            "ICE keeps the old nomination while the rebound path is checked"
        );
    }

    #[test]
    fn peer_session_allows_independent_generations_and_rejects_empty_candidates() {
        let local = generate_ice_credentials(1).expect("local credentials");
        let mut remote = generate_ice_credentials(1).expect("remote credentials");
        let now = Instant::now();
        assert!(IceAgentDriver::for_peer(&local, &remote, &[], &[], true, now).is_err());
        remote.generation = 2;
        assert!(
            IceAgentDriver::for_peer(
                &local,
                &remote,
                &["0.0.0.0:41001".parse().unwrap()],
                &["127.0.0.1:41002".parse().unwrap()],
                true,
                now,
            )
            .is_ok()
        );
        remote.generation = 0;
        assert!(
            IceAgentDriver::for_peer(
                &local,
                &remote,
                &["127.0.0.1:41001".parse().unwrap()],
                &["127.0.0.1:41002".parse().unwrap()],
                true,
                now,
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn ice_router_dispatches_by_recipient_ufrag_and_authenticated_peer_address() {
        let mut router = IceDatagramRouter::default();
        let mut session_a = router
            .register("localA".to_owned(), "remoteA".to_owned(), 2)
            .unwrap();
        let mut session_b = router
            .register("localB".to_owned(), "remoteB".to_owned(), 2)
            .unwrap();
        let mut session_a_peer_c = router
            .register("localA".to_owned(), "remoteC".to_owned(), 2)
            .unwrap();
        let peer_a: SocketAddr = "127.0.0.1:42001".parse().unwrap();
        let peer_b: SocketAddr = "127.0.0.1:42002".parse().unwrap();

        assert!(router.route(ice_packet("localA:remoteA", peer_a)));
        assert!(router.route(ice_packet("localB:remoteB", peer_b)));
        assert_eq!(session_a.recv().await.unwrap().peer_addr, peer_a);
        assert_eq!(session_b.recv().await.unwrap().peer_addr, peer_b);

        let peer_c: SocketAddr = "127.0.0.1:42004".parse().unwrap();
        assert!(router.route(ice_packet("localA:remoteC", peer_c)));
        assert_eq!(session_a_peer_c.recv().await.unwrap().peer_addr, peer_c);

        assert!(!router.route(ice_packet_without_username(peer_a)));
        router
            .associate_authenticated_peer("localA", "remoteA", peer_a)
            .unwrap();
        assert!(router.route(ice_packet_without_username(peer_a)));
        assert_eq!(session_a.recv().await.unwrap().peer_addr, peer_a);
        assert!(!router.route(ice_packet("localB:unknownR", peer_a)));
        assert!(router.unregister("localA", "remoteA"));
        assert!(!router.route(ice_packet_without_username(peer_a)));
    }

    #[test]
    fn ice_route_diagnostics_report_ufrag_presence_without_values() {
        let mut router = IceDatagramRouter::default();
        router
            .register("localA".to_owned(), "remoteA".to_owned(), 2)
            .expect("register a peer ICE session");

        assert_eq!(
            router.ufrag_registration_presence(&IceSessionKey {
                local_ufrag: "localA".to_owned(),
                remote_ufrag: "unknownR".to_owned(),
            }),
            (true, false)
        );
        assert_eq!(
            router.ufrag_registration_presence(&IceSessionKey {
                local_ufrag: "unknownL".to_owned(),
                remote_ufrag: "remoteA".to_owned(),
            }),
            (false, true)
        );
        assert_eq!(
            router.ufrag_registration_presence(&IceSessionKey {
                local_ufrag: "unknownL".to_owned(),
                remote_ufrag: "unknownR".to_owned(),
            }),
            (false, false)
        );
    }

    #[tokio::test]
    async fn ice_router_evicts_old_authenticated_addresses_after_repeated_nat_rebinding() {
        let mut router = IceDatagramRouter::default();
        let credentials_a = generate_ice_credentials(1).unwrap();
        let credentials_b = generate_ice_credentials(1).unwrap();
        let mut session_a = router
            .register(credentials_b.ufrag.clone(), credentials_a.ufrag.clone(), 4)
            .unwrap();
        let mut session_b = router
            .register("localB".to_owned(), "remoteB".to_owned(), 4)
            .unwrap();
        let address_a: SocketAddr = "198.18.0.1:42000".parse().unwrap();
        let address_b: SocketAddr = "198.18.0.2:42000".parse().unwrap();
        let mut driver_b = IceAgentDriver::for_peer(
            &credentials_b,
            &credentials_a,
            &[address_b],
            &[address_a],
            false,
            Instant::now(),
        )
        .expect("construct the stable peer ICE session");
        let addresses = (0..=MAX_SESSION_PEER_ADDRESSES)
            .map(|offset| {
                format!("198.51.100.10:{}", 42_000 + offset)
                    .parse::<SocketAddr>()
                    .unwrap()
            })
            .collect::<Vec<_>>();

        let authenticate_source = |router: &mut IceDatagramRouter,
                                   driver_b: &mut IceAgentDriver,
                                   source: SocketAddr| {
            let now = Instant::now();
            let mut driver_a = IceAgentDriver::for_peer(
                &credentials_a,
                &credentials_b,
                &[address_a],
                &[address_b],
                true,
                now,
            )
            .expect("construct fresh check sender with stable ICE credentials");
            driver_a
                .handle_timeout(now)
                .expect("start connectivity check");
            let check = driver_a
                .poll_transmits()
                .into_iter()
                .find(|transmit| transmit.transport.peer_addr == address_b)
                .expect("ICE check to the stable peer");
            assert!(
                driver_b
                    .handle_datagram(now, source, check.transport.ecn, &check.message)
                    .expect("authenticated checks from successive NAT mappings are accepted")
            );
            router
                .associate_authenticated_peer(&credentials_b.ufrag, &credentials_a.ufrag, source)
                .expect("associate only after ICE authentication");
        };
        for address in &addresses[..MAX_SESSION_PEER_ADDRESSES] {
            authenticate_source(&mut router, &mut driver_b, *address);
        }
        // Re-authentication refreshes a live address so the LRU evicts the next oldest entry.
        authenticate_source(&mut router, &mut driver_b, addresses[0]);
        authenticate_source(
            &mut router,
            &mut driver_b,
            addresses[MAX_SESSION_PEER_ADDRESSES],
        );

        let key_a = IceSessionKey {
            local_ufrag: credentials_b.ufrag.clone(),
            remote_ufrag: credentials_a.ufrag.clone(),
        };
        assert_eq!(
            router.sessions[&key_a].peer_addresses.len(),
            MAX_SESSION_PEER_ADDRESSES
        );
        assert_eq!(router.peer_sessions.len(), MAX_SESSION_PEER_ADDRESSES);
        assert!(!router.peer_sessions.contains_key(&addresses[1]));
        assert!(router.peer_sessions.contains_key(&addresses[0]));
        assert!(!router.route(ice_packet_without_username(addresses[1])));
        assert!(router.route(ice_packet_without_username(addresses[0])));
        assert_eq!(session_a.recv().await.unwrap().peer_addr, addresses[0]);
        let newest = addresses[MAX_SESSION_PEER_ADDRESSES];
        assert!(router.route(ice_packet_without_username(newest)));
        assert_eq!(session_a.recv().await.unwrap().peer_addr, newest);

        // A socket address reassigned to another authenticated peer must have exactly one owner.
        router
            .associate_authenticated_peer("localB", "remoteB", addresses[0])
            .unwrap();
        let key_b = IceSessionKey {
            local_ufrag: "localB".to_owned(),
            remote_ufrag: "remoteB".to_owned(),
        };
        assert!(
            !router.sessions[&key_a]
                .peer_addresses
                .contains(&addresses[0])
        );
        assert_eq!(router.peer_sessions.get(&addresses[0]), Some(&key_b));
        assert!(router.route(ice_packet_without_username(addresses[0])));
        assert_eq!(session_b.recv().await.unwrap().peer_addr, addresses[0]);
        assert!(router.unregister("localB", "remoteB"));
        assert!(!router.route(ice_packet_without_username(addresses[0])));
    }

    #[tokio::test]
    async fn ice_router_routes_initial_responses_by_transaction_before_peer_authentication() {
        let mut router = IceDatagramRouter::default();
        let mut session_a = router
            .register("localA".to_owned(), "remoteA".to_owned(), 2)
            .unwrap();
        let mut session_b = router
            .register("localB".to_owned(), "remoteB".to_owned(), 2)
            .unwrap();
        let peer: SocketAddr = "198.51.100.7:42000".parse().unwrap();
        let stranger: SocketAddr = "198.51.100.8:42000".parse().unwrap();
        let mut request_a = ice_packet("remoteA:localA", peer);
        let mut request_b = ice_packet("remoteB:localB", peer);
        request_a.payload[8..20].copy_from_slice(&[1; 12]);
        request_b.payload[8..20].copy_from_slice(&[2; 12]);
        let transaction_a = crate::stun::binding_request_transaction_id(&request_a.payload)
            .expect("ICE request transaction A");
        let transaction_b = crate::stun::binding_request_transaction_id(&request_b.payload)
            .expect("ICE request transaction B");
        let now = Instant::now();
        router
            .register_ice_transaction("localA", "remoteA", peer, transaction_a, now)
            .unwrap();
        router
            .register_ice_transaction("localB", "remoteB", peer, transaction_b, now)
            .unwrap();

        assert!(!router.route(ice_response(transaction_b, stranger)));
        assert!(router.route(ice_response(transaction_b, peer)));
        assert_eq!(session_b.recv().await.unwrap().peer_addr, peer);
        assert!(session_a.try_recv().is_err());
        assert!(router.route(ice_response(transaction_a, peer)));
        assert_eq!(session_a.recv().await.unwrap().peer_addr, peer);
        assert!(!router.route(ice_response(transaction_a, peer)));
    }

    #[tokio::test]
    async fn ice_router_bounds_sessions_and_does_not_block_on_a_full_peer_queue() {
        let mut router = IceDatagramRouter::default();
        assert_eq!(
            router
                .register("bad-ufrag".to_owned(), "remote".to_owned(), 1)
                .err(),
            Some(IceRouterError::InvalidRegistration)
        );
        let mut receiver = router
            .register("local".to_owned(), "remote".to_owned(), 1)
            .unwrap();
        assert_eq!(
            router
                .register("local".to_owned(), "remote".to_owned(), 1)
                .err(),
            Some(IceRouterError::DuplicateSession)
        );
        let peer = "127.0.0.1:42003".parse().unwrap();
        assert!(router.route(ice_packet("local:remote", peer)));
        assert!(!router.route(ice_packet("local:remote", peer)));
        assert!(receiver.recv().await.is_some());
    }

    fn ice_packet(username: &str, peer_addr: SocketAddr) -> IceDatagram {
        let mut payload = ice_packet_without_username(peer_addr).payload;
        let length = username.len();
        let padded = (length + 3) & !3;
        payload[2..4].copy_from_slice(&((4 + padded) as u16).to_be_bytes());
        payload.extend_from_slice(&6_u16.to_be_bytes());
        payload.extend_from_slice(&(length as u16).to_be_bytes());
        payload.extend_from_slice(username.as_bytes());
        payload.resize(20 + 4 + padded, 0);
        IceDatagram {
            local_addr: "127.0.0.1:40000".parse().unwrap(),
            peer_addr,
            payload,
        }
    }

    fn ice_packet_without_username(peer_addr: SocketAddr) -> IceDatagram {
        let mut payload = vec![0; 20];
        payload[..2].copy_from_slice(&1_u16.to_be_bytes());
        payload[4..8].copy_from_slice(&0x2112_A442_u32.to_be_bytes());
        IceDatagram {
            local_addr: "127.0.0.1:40000".parse().unwrap(),
            peer_addr,
            payload,
        }
    }

    fn ice_response(transaction_id: [u8; 12], peer_addr: SocketAddr) -> IceDatagram {
        let mut payload = vec![0; 20];
        payload[..2].copy_from_slice(&crate::stun::BINDING_SUCCESS.to_be_bytes());
        payload[4..8].copy_from_slice(&0x2112_A442_u32.to_be_bytes());
        payload[8..20].copy_from_slice(&transaction_id);
        IceDatagram {
            local_addr: "127.0.0.1:40000".parse().unwrap(),
            peer_addr,
            payload,
        }
    }

    #[tokio::test]
    async fn iced_quinn_socket_demultiplexes_stun_and_keeps_quic_working() {
        let temp =
            std::env::temp_dir().join(format!("mini-tunnel-ice-socket-{}", uuid::Uuid::new_v4()));
        let identity_a =
            crate::Identity::load_or_create_at(temp.join("a/device.key")).expect("identity A");
        let identity_b =
            crate::Identity::load_or_create_at(temp.join("b/device.key")).expect("identity B");
        let endpoint_a =
            super::peer_endpoint_with_ice(&identity_a, "127.0.0.1:0".parse().unwrap(), 8)
                .expect("ICE endpoint A");
        let endpoint_b =
            super::peer_endpoint_with_ice(&identity_b, "127.0.0.1:0".parse().unwrap(), 8)
                .expect("ICE endpoint B");
        let address_b = endpoint_b
            .endpoint
            .local_addr()
            .expect("endpoint B address");
        let address_a = endpoint_a
            .endpoint
            .local_addr()
            .expect("endpoint A address");
        let credentials_a = generate_ice_credentials(1).expect("ICE credentials A");
        let credentials_b = generate_ice_credentials(1).expect("ICE credentials B");
        let mut ice_messages_a = endpoint_a
            .ice_router
            .register(credentials_a.ufrag.clone(), credentials_b.ufrag.clone(), 8)
            .expect("register A ICE session");
        let mut ice_messages = endpoint_b
            .ice_router
            .register(credentials_b.ufrag.clone(), credentials_a.ufrag.clone(), 8)
            .expect("register B ICE session");
        let mut driver_a = IceAgentDriver::for_peer(
            &credentials_a,
            &credentials_b,
            &[address_a],
            &[address_b],
            true,
            Instant::now(),
        )
        .expect("construct A ICE session");
        let mut driver_b = IceAgentDriver::for_peer(
            &credentials_b,
            &credentials_a,
            &[address_b],
            &[address_a],
            false,
            Instant::now(),
        )
        .expect("construct B ICE session");
        let (pair_a, pair_b) = tokio::join!(
            driver_a.run_checks(
                &endpoint_a.socket,
                &endpoint_a.ice_router,
                &credentials_a.ufrag,
                &credentials_b.ufrag,
                &mut ice_messages_a,
                Duration::from_secs(3),
            ),
            driver_b.run_checks(
                &endpoint_b.socket,
                &endpoint_b.ice_router,
                &credentials_b.ufrag,
                &credentials_a.ufrag,
                &mut ice_messages,
                Duration::from_secs(3),
            ),
        );
        assert_eq!(pair_a.expect("A nominates pair"), (address_a, address_b));
        assert_eq!(pair_b.expect("B nominates pair"), (address_b, address_a));

        let (monitor, cancel, failure_sender) = IceConsentMonitor::new();
        let degraded_sender = monitor.degraded_sender();
        let mut signals = IceConsentSignals::new(cancel, degraded_sender);
        let router = endpoint_a.ice_router.clone();
        let socket = endpoint_a.socket.clone();
        let local_ufrag = credentials_a.ufrag.clone();
        let remote_ufrag = credentials_b.ufrag.clone();
        let task = tokio::spawn(async move {
            if driver_a
                .monitor_consent(
                    &socket,
                    &router,
                    &local_ufrag,
                    &remote_ufrag,
                    &mut ice_messages_a,
                    &mut signals,
                )
                .await
                .is_err()
            {
                failure_sender.send_replace(true);
            }
            let _ = router.unregister(&local_ufrag, &remote_ufrag);
        });
        monitor.set_task(task).await;
        let (monitor_b, cancel_b, failure_sender_b) = IceConsentMonitor::new();
        let degraded_sender_b = monitor_b.degraded_sender();
        let mut signals_b = IceConsentSignals::new(cancel_b, degraded_sender_b);
        let router_b = endpoint_b.ice_router.clone();
        let socket_b = endpoint_b.socket.clone();
        let local_ufrag_b = credentials_b.ufrag.clone();
        let remote_ufrag_b = credentials_a.ufrag.clone();
        let task_b = tokio::spawn(async move {
            if driver_b
                .monitor_consent(
                    &socket_b,
                    &router_b,
                    &local_ufrag_b,
                    &remote_ufrag_b,
                    &mut ice_messages,
                    &mut signals_b,
                )
                .await
                .is_err()
            {
                failure_sender_b.send_replace(true);
            }
            let _ = router_b.unregister(&local_ufrag_b, &remote_ufrag_b);
        });
        monitor_b.set_task(task_b).await;

        tokio::time::sleep(Duration::from_secs(11)).await;
        assert!(
            !*monitor.failure_receiver().borrow() && !*monitor_b.failure_receiver().borrow(),
            "both nominated ICE sessions must maintain consent over the shared UDP sockets"
        );

        monitor_b.stop().await;
        let mut degraded = monitor.degraded_receiver();
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                if *degraded.borrow() {
                    break;
                }
                degraded.changed().await.expect("ICE degraded state sender");
            }
        })
        .await
        .expect("ICE disconnected state is reported before consent failure");
        assert!(
            !*monitor.failure_receiver().borrow(),
            "the consent monitor must allow time to prepare fallback after disconnection"
        );
        let mut failed = monitor.failure_receiver();
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                if *failed.borrow() {
                    break;
                }
                failed.changed().await.expect("consent failure sender");
            }
        })
        .await
        .expect("ICE consent loss is detected after the selected peer stops responding");
        monitor.stop().await;
        monitor_b.stop().await;

        let identity_a_id = identity_a.device_id();
        let identity_a_key = identity_a.public_key();
        let identity_b_id = identity_b.device_id();
        let identity_b_key = identity_b.public_key();
        let server_endpoint = endpoint_b.endpoint.clone();
        let accept = tokio::spawn(async move {
            crate::accept_peer(
                &server_endpoint,
                "ice-socket-test",
                &identity_b,
                &identity_a_id,
                identity_a_key,
            )
            .await
        });
        let channel_a = crate::connect_peer(
            &endpoint_a.endpoint,
            address_b,
            "ice-socket-test",
            &identity_a,
            &identity_b_id,
            identity_b_key,
        )
        .await
        .expect("QUIC handshake through demux socket");
        let channel_b = accept.await.expect("accept task").expect("accept QUIC");

        channel_a
            .send_packet(b"quic-survives-demux")
            .await
            .expect("send a QUIC datagram");
        assert_eq!(
            channel_b
                .recv_packet()
                .await
                .expect("receive QUIC datagram"),
            b"quic-survives-demux"
        );

        endpoint_a.endpoint.close(0_u32.into(), b"test complete");
        endpoint_b.endpoint.close(0_u32.into(), b"test complete");
        let _ = fs::remove_dir_all(temp);
    }

    #[tokio::test]
    async fn ice_and_quic_recover_from_nat_rebinding_through_mapping_proxies() {
        let temp =
            std::env::temp_dir().join(format!("mini-tunnel-ice-nat-{}", uuid::Uuid::new_v4()));
        let identity_a =
            crate::Identity::load_or_create_at(temp.join("a/device.key")).expect("identity A");
        let identity_b =
            crate::Identity::load_or_create_at(temp.join("b/device.key")).expect("identity B");
        let endpoint_a =
            super::peer_endpoint_with_ice(&identity_a, "127.0.0.1:0".parse().unwrap(), 8)
                .expect("ICE endpoint A");
        let endpoint_b =
            super::peer_endpoint_with_ice(&identity_b, "127.0.0.1:0".parse().unwrap(), 8)
                .expect("ICE endpoint B");
        let address_a = endpoint_a.endpoint.local_addr().expect("A address");
        let address_b = endpoint_b.endpoint.local_addr().expect("B address");

        // Each proxy exposes a different UDP port. Packets sent to B's mapping are forwarded to
        // B from A's mapping, and vice versa, so the endpoints see translated source addresses.
        let mapping_a = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("mapping A"));
        let mapping_a_rebound = Arc::new(
            UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("rebound mapping A"),
        );
        let mapping_b = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("mapping B"));
        let drop_first_mapped_datagram = Arc::new(AtomicBool::new(true));
        let use_rebound_mapping = Arc::new(AtomicBool::new(false));
        let mapped_a = mapping_a.local_addr().expect("mapped A address");
        let mapped_a_rebound = mapping_a_rebound
            .local_addr()
            .expect("rebound mapped A address");
        assert_ne!(
            mapped_a_rebound, mapped_a,
            "the test must change the NAT mapping"
        );
        let mapped_b = mapping_b.local_addr().expect("mapped B address");
        let proxy_a = {
            let mapping_a = Arc::clone(&mapping_a);
            let mapping_b = Arc::clone(&mapping_b);
            let drop_first_mapped_datagram = Arc::clone(&drop_first_mapped_datagram);
            let use_rebound_mapping = Arc::clone(&use_rebound_mapping);
            tokio::spawn(async move {
                let mut packet = vec![0; 65_535];
                while let Ok((length, _source)) = mapping_a.recv_from(&mut packet).await {
                    if use_rebound_mapping.load(Ordering::Relaxed) {
                        continue;
                    }
                    if drop_first_mapped_datagram.swap(false, Ordering::Relaxed) {
                        continue;
                    }
                    if mapping_b
                        .send_to(&packet[..length], address_a)
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            })
        };
        let proxy_a_rebound = {
            let mapping_a_rebound = Arc::clone(&mapping_a_rebound);
            let mapping_b = Arc::clone(&mapping_b);
            let use_rebound_mapping = Arc::clone(&use_rebound_mapping);
            tokio::spawn(async move {
                let mut packet = vec![0; 65_535];
                while let Ok((length, _source)) = mapping_a_rebound.recv_from(&mut packet).await {
                    if use_rebound_mapping.load(Ordering::Relaxed)
                        && mapping_b
                            .send_to(&packet[..length], address_a)
                            .await
                            .is_err()
                    {
                        break;
                    }
                }
            })
        };
        let proxy_b = {
            let mapping_a = Arc::clone(&mapping_a);
            let mapping_a_rebound = Arc::clone(&mapping_a_rebound);
            let mapping_b = Arc::clone(&mapping_b);
            let use_rebound_mapping = Arc::clone(&use_rebound_mapping);
            tokio::spawn(async move {
                let mut packet = vec![0; 65_535];
                while let Ok((length, _source)) = mapping_b.recv_from(&mut packet).await {
                    let source_mapping = if use_rebound_mapping.load(Ordering::Relaxed) {
                        &mapping_a_rebound
                    } else {
                        &mapping_a
                    };
                    if source_mapping
                        .send_to(&packet[..length], address_b)
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            })
        };

        let credentials_a = generate_ice_credentials(1).expect("credentials A");
        let credentials_b = generate_ice_credentials(1).expect("credentials B");
        let mut messages_a = endpoint_a
            .ice_router
            .register(credentials_a.ufrag.clone(), credentials_b.ufrag.clone(), 8)
            .expect("register A session");
        let mut messages_b = endpoint_b
            .ice_router
            .register(credentials_b.ufrag.clone(), credentials_a.ufrag.clone(), 8)
            .expect("register B session");
        let mut driver_a = IceAgentDriver::for_peer(
            &credentials_a,
            &credentials_b,
            &[mapped_a],
            &[mapped_b],
            true,
            Instant::now(),
        )
        .expect("construct A ICE session");
        let mut driver_b = IceAgentDriver::for_peer(
            &credentials_b,
            &credentials_a,
            &[mapped_b],
            &[mapped_a],
            false,
            Instant::now(),
        )
        .expect("construct B ICE session");
        let (pair_a, pair_b) = tokio::join!(
            driver_a.run_checks(
                &endpoint_a.socket,
                &endpoint_a.ice_router,
                &credentials_a.ufrag,
                &credentials_b.ufrag,
                &mut messages_a,
                Duration::from_secs(3),
            ),
            driver_b.run_checks(
                &endpoint_b.socket,
                &endpoint_b.ice_router,
                &credentials_b.ufrag,
                &credentials_a.ufrag,
                &mut messages_b,
                Duration::from_secs(3),
            ),
        );
        assert_eq!(pair_a.expect("A nominates mapped pair").1, mapped_b);
        assert_eq!(pair_b.expect("B nominates mapped pair").1, mapped_a);
        assert!(
            !drop_first_mapped_datagram.load(Ordering::Relaxed),
            "the simulated NAT must discard one datagram before nomination succeeds"
        );
        assert_eq!(mapping_a.local_addr().unwrap(), mapped_a);
        assert_eq!(mapping_b.local_addr().unwrap(), mapped_b);

        let peer_a_id = identity_a.device_id();
        let peer_a_key = identity_a.public_key();
        let peer_b_id = identity_b.device_id();
        let peer_b_key = identity_b.public_key();
        let server = endpoint_b.endpoint.clone();
        let identity_b_path = temp.join("b/device.key");
        let accept = tokio::spawn(async move {
            let identity_b =
                crate::Identity::load_or_create_at(identity_b_path).expect("reload identity B");
            crate::accept_peer(&server, "ice-nat-test", &identity_b, &peer_a_id, peer_a_key).await
        });
        let channel_a = crate::connect_peer(
            &endpoint_a.endpoint,
            mapped_b,
            "ice-nat-test",
            &identity_a,
            &peer_b_id,
            peer_b_key,
        )
        .await
        .expect("QUIC handshake through mapped UDP path");
        let channel_b = accept.await.expect("accept task").expect("accept QUIC");
        channel_a
            .send_packet(b"ice-over-mapped-udp")
            .await
            .expect("send through NAT mapping proxies");
        assert_eq!(
            channel_b
                .recv_packet()
                .await
                .expect("receive tunneled payload"),
            b"ice-over-mapped-udp"
        );

        let (monitor_a, cancel_a, failure_sender_a) = IceConsentMonitor::new();
        let mut signals_a = IceConsentSignals::new(cancel_a, monitor_a.degraded_sender());
        let router_a = endpoint_a.ice_router.clone();
        let socket_a = endpoint_a.socket.clone();
        let local_ufrag_a = credentials_a.ufrag.clone();
        let remote_ufrag_a = credentials_b.ufrag.clone();
        monitor_a
            .set_task(tokio::spawn(async move {
                if driver_a
                    .monitor_consent(
                        &socket_a,
                        &router_a,
                        &local_ufrag_a,
                        &remote_ufrag_a,
                        &mut messages_a,
                        &mut signals_a,
                    )
                    .await
                    .is_err()
                {
                    failure_sender_a.send_replace(true);
                }
                let _ = router_a.unregister(&local_ufrag_a, &remote_ufrag_a);
            }))
            .await;
        let (monitor_b, cancel_b, failure_sender_b) = IceConsentMonitor::new();
        let mut signals_b = IceConsentSignals::new(cancel_b, monitor_b.degraded_sender());
        let router_b = endpoint_b.ice_router.clone();
        let socket_b = endpoint_b.socket.clone();
        let local_ufrag_b = credentials_b.ufrag.clone();
        let remote_ufrag_b = credentials_a.ufrag.clone();
        monitor_b
            .set_task(tokio::spawn(async move {
                if driver_b
                    .monitor_consent(
                        &socket_b,
                        &router_b,
                        &local_ufrag_b,
                        &remote_ufrag_b,
                        &mut messages_b,
                        &mut signals_b,
                    )
                    .await
                    .is_err()
                {
                    failure_sender_b.send_replace(true);
                }
                let _ = router_b.unregister(&local_ufrag_b, &remote_ufrag_b);
            }))
            .await;
        let mut degraded_b = monitor_b.degraded_receiver();
        use_rebound_mapping.store(true, Ordering::Relaxed);
        channel_a
            .send_packet(b"ice-after-nat-rebinding")
            .await
            .expect("send QUIC payload after NAT source-port change");
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(3), channel_b.recv_packet())
                .await
                .expect("receive payload after QUIC path migration")
                .expect("receive QUIC data"),
            b"ice-after-nat-rebinding"
        );
        tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                if *degraded_b.borrow() {
                    break;
                }
                degraded_b
                    .changed()
                    .await
                    .expect("ICE monitor reports authenticated rebinding");
            }
        })
        .await
        .expect("authenticated rebinding signals reliable fallback preparation");
        assert!(
            !*monitor_b.failure_receiver().borrow(),
            "the old nominated ICE pair remains inside its consent grace period"
        );
        monitor_a.stop().await;
        monitor_b.stop().await;
        channel_a.close();
        channel_b.close();
        endpoint_a.endpoint.close(0_u32.into(), b"test complete");
        endpoint_b.endpoint.close(0_u32.into(), b"test complete");
        proxy_a.abort();
        proxy_a_rebound.abort();
        proxy_b.abort();
        drop(mapping_a);
        drop(mapping_a_rebound);
        drop(mapping_b);
        let _ = fs::remove_dir_all(temp);
    }

    #[tokio::test]
    async fn ice_credentials_can_restart_on_the_same_udp_socket() {
        let temp =
            std::env::temp_dir().join(format!("mini-tunnel-ice-restart-{}", uuid::Uuid::new_v4()));
        let identity_a =
            crate::Identity::load_or_create_at(temp.join("a/device.key")).expect("identity A");
        let identity_b =
            crate::Identity::load_or_create_at(temp.join("b/device.key")).expect("identity B");
        let endpoint_a =
            super::peer_endpoint_with_ice(&identity_a, "127.0.0.1:0".parse().unwrap(), 8)
                .expect("ICE endpoint A");
        let endpoint_b =
            super::peer_endpoint_with_ice(&identity_b, "127.0.0.1:0".parse().unwrap(), 8)
                .expect("ICE endpoint B");
        let address_a = endpoint_a.endpoint.local_addr().expect("A address");
        let address_b = endpoint_b.endpoint.local_addr().expect("B address");
        type CredentialPair = (String, String);
        let (mut previous_a, mut previous_b): (Option<CredentialPair>, Option<CredentialPair>) =
            (None, None);

        for generation in 1..=2 {
            let credentials_a = generate_ice_credentials(generation).expect("credentials A");
            let credentials_b = generate_ice_credentials(generation).expect("credentials B");
            if let Some((ufrag_a, ufrag_b)) = previous_a.take() {
                assert!(
                    endpoint_a
                        .ice_router
                        .unregister(&ufrag_a, &ufrag_b)
                        .unwrap()
                );
            }
            if let Some((ufrag_b, ufrag_a)) = previous_b.take() {
                assert!(
                    endpoint_b
                        .ice_router
                        .unregister(&ufrag_b, &ufrag_a)
                        .unwrap()
                );
            }
            let mut messages_a = endpoint_a
                .ice_router
                .register(credentials_a.ufrag.clone(), credentials_b.ufrag.clone(), 8)
                .expect("register A session");
            let mut messages_b = endpoint_b
                .ice_router
                .register(credentials_b.ufrag.clone(), credentials_a.ufrag.clone(), 8)
                .expect("register B session");
            let mut driver_a = IceAgentDriver::for_peer(
                &credentials_a,
                &credentials_b,
                &[address_a],
                &[address_b],
                true,
                Instant::now(),
            )
            .expect("construct A ICE session");
            let mut driver_b = IceAgentDriver::for_peer(
                &credentials_b,
                &credentials_a,
                &[address_b],
                &[address_a],
                false,
                Instant::now(),
            )
            .expect("construct B ICE session");
            let (pair_a, pair_b) = tokio::join!(
                driver_a.run_checks(
                    &endpoint_a.socket,
                    &endpoint_a.ice_router,
                    &credentials_a.ufrag,
                    &credentials_b.ufrag,
                    &mut messages_a,
                    Duration::from_secs(3),
                ),
                driver_b.run_checks(
                    &endpoint_b.socket,
                    &endpoint_b.ice_router,
                    &credentials_b.ufrag,
                    &credentials_a.ufrag,
                    &mut messages_b,
                    Duration::from_secs(3),
                ),
            );
            assert_eq!(pair_a.expect("A nominates pair"), (address_a, address_b));
            assert_eq!(pair_b.expect("B nominates pair"), (address_b, address_a));
            assert_eq!(endpoint_a.endpoint.local_addr().unwrap(), address_a);
            assert_eq!(endpoint_b.endpoint.local_addr().unwrap(), address_b);

            let peer_a_id = identity_a.device_id();
            let peer_a_key = identity_a.public_key();
            let peer_b_id = identity_b.device_id();
            let peer_b_key = identity_b.public_key();
            let server = endpoint_b.endpoint.clone();
            let identity_b_path = temp.join("b/device.key");
            let accept = tokio::spawn(async move {
                let accept_identity =
                    crate::Identity::load_or_create_at(identity_b_path).expect("reload identity B");
                crate::accept_peer(
                    &server,
                    "ice-restart-test",
                    &accept_identity,
                    &peer_a_id,
                    peer_a_key,
                )
                .await
            });
            let channel_a = crate::connect_peer(
                &endpoint_a.endpoint,
                address_b,
                "ice-restart-test",
                &identity_a,
                &peer_b_id,
                peer_b_key,
            )
            .await
            .expect("connect with current ICE generation");
            let channel_b = accept.await.expect("accept task").expect("accept QUIC");
            let payload = format!("ice-generation-{generation}");
            channel_a
                .send_packet(payload.as_bytes())
                .await
                .expect("send through restarted tunnel");
            assert_eq!(
                channel_b
                    .recv_packet()
                    .await
                    .expect("receive tunnel packet"),
                payload.as_bytes()
            );
            channel_a.close();
            channel_b.close();
            previous_a = Some((credentials_a.ufrag.clone(), credentials_b.ufrag.clone()));
            previous_b = Some((credentials_b.ufrag, credentials_a.ufrag));
        }

        endpoint_a.endpoint.close(0_u32.into(), b"test complete");
        endpoint_b.endpoint.close(0_u32.into(), b"test complete");
        let _ = fs::remove_dir_all(temp);
    }

    #[tokio::test]
    async fn iced_socket_drops_stun_when_the_bounded_ice_queue_is_full() {
        let temp =
            std::env::temp_dir().join(format!("mini-tunnel-ice-queue-{}", uuid::Uuid::new_v4()));
        let identity =
            crate::Identity::load_or_create_at(temp.join("device.key")).expect("identity");
        let endpoint = super::peer_endpoint_with_ice(&identity, "127.0.0.1:0".parse().unwrap(), 1)
            .expect("ICE endpoint");
        let address = endpoint.endpoint.local_addr().expect("endpoint address");
        let sender = UdpSocket::bind("127.0.0.1:0").await.expect("sender socket");
        let mut ice_messages = endpoint
            .ice_router
            .register("localq".to_owned(), "remoteq".to_owned(), 1)
            .expect("register ICE test session");
        let first_request = ice_packet(
            "localq:remoteq",
            sender.local_addr().expect("sender address"),
        )
        .payload;
        let second_request = ice_packet(
            "localq:remoteq",
            sender.local_addr().expect("sender address"),
        )
        .payload;
        sender
            .send_to(&first_request, address)
            .await
            .expect("send first STUN datagram");
        sender
            .send_to(&second_request, address)
            .await
            .expect("send second STUN datagram");
        tokio::time::sleep(Duration::from_millis(30)).await;

        let first = ice_messages
            .recv()
            .await
            .expect("first STUN datagram queued");
        assert_eq!(first.payload, first_request);
        assert!(ice_messages.try_recv().is_err());
        endpoint.endpoint.close(0_u32.into(), b"test complete");
        let _ = fs::remove_dir_all(temp);
    }
}
