//! Bounded adapter between the Sans-I/O ICE agent and the shared UDP socket driver.

use std::{
    future::Future,
    io::{self, IoSliceMut},
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Instant,
};

use bytes::BytesMut;
use rtc_ice::Agent;
use rtc_shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use sansio::Protocol;
use thiserror::Error;
use tokio::{io::Interest, net::UdpSocket, sync::mpsc};

use crate::stun::is_stun_datagram;

/// Maximum ICE checks drained during one socket-driver turn.
pub const MAX_ICE_TRANSMITS_PER_TURN: usize = 64;
const MAX_SOCKET_QUEUE_CAPACITY: usize = 128;
const MAX_UDP_DATAGRAM_SIZE: usize = u16::MAX as usize;

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
    pub ice_datagrams: mpsc::Receiver<IceDatagram>,
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
    socket
        .set_nonblocking(true)
        .map_err(|error| crate::IdentityError::Transport(error.to_string()))?;
    let (runtime, socket_handle, ice_datagrams) = IcedQuinnRuntime::new(queue_capacity);
    let endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(super::peer_server_config(identity)?),
        socket,
        Arc::new(runtime),
    )
    .map_err(|error| crate::IdentityError::Transport(error.to_string()))?;
    Ok(IcedPeerEndpoint {
        endpoint,
        socket: socket_handle,
        ice_datagrams,
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
}

/// Drives an RFC 8445 agent without owning its UDP socket or clock.
///
/// The caller supplies the same local socket address used by Quinn, forwards only validated STUN
/// datagrams to `handle_datagram`, sends values from `poll_transmits` on that socket, and calls
/// `handle_timeout` at `next_timeout`. Non-STUN datagrams must remain on Quinn's receive path.
pub struct IceAgentDriver {
    agent: Agent,
    local_addr: SocketAddr,
}

impl IceAgentDriver {
    #[must_use]
    pub fn new(agent: Agent, local_addr: SocketAddr) -> Self {
        Self { agent, local_addr }
    }

    /// Feed one datagram to ICE. `false` means it was not a complete STUN message envelope.
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
        self.agent
            .handle_read(TaggedBytesMut {
                now,
                transport: TransportContext {
                    local_addr: self.local_addr,
                    peer_addr,
                    transport_protocol: TransportProtocol::UDP,
                    ecn,
                },
                message: BytesMut::from(message),
            })
            .map_err(|error| IceDriverError::Agent(error.to_string()))?;
        Ok(true)
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

    /// Read the ICE-selected local/remote socket pair, if nomination has completed.
    pub fn selected_pair(&self) -> Option<(SocketAddr, SocketAddr)> {
        self.agent
            .get_selected_candidate_pair()
            .map(|(local, remote)| (local.addr(), remote.addr()))
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, sync::Arc, thread, time::Duration};

    use super::*;
    use rtc_ice::candidate::{CandidateConfig, candidate_host::CandidateHostConfig};

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
    fn two_sans_io_agents_authenticate_checks_and_nominate_a_candidate_pair() {
        let provider = rtc_ice::crypto::default_provider().expect("ring ICE crypto provider");
        let mut agent_a = Agent::new(
            Instant::now(),
            Arc::new(rtc_ice::AgentConfig::default()),
            Arc::clone(&provider),
        )
        .expect("construct A ICE agent");
        let mut agent_b = Agent::new(
            Instant::now(),
            Arc::new(rtc_ice::AgentConfig::default()),
            provider,
        )
        .expect("construct B ICE agent");
        let address_a: SocketAddr = "127.0.0.1:41001".parse().unwrap();
        let address_b: SocketAddr = "127.0.0.1:41002".parse().unwrap();
        let candidate = |address: SocketAddr| {
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
            .expect("construct loopback host candidate")
        };
        let candidate_a = candidate(address_a);
        let candidate_b = candidate(address_b);
        agent_a
            .add_local_candidate(candidate_a.clone())
            .expect("add A local candidate");
        agent_a
            .add_remote_candidate(candidate_b.clone())
            .expect("add A remote candidate");
        agent_b
            .add_local_candidate(candidate_b)
            .expect("add B local candidate");
        agent_b
            .add_remote_candidate(candidate_a)
            .expect("add B remote candidate");

        let credentials_a = agent_a.get_local_credentials().clone();
        let credentials_b = agent_b.get_local_credentials().clone();
        let now = Instant::now();
        agent_a
            .start_connectivity_checks(now, true, credentials_b.ufrag, credentials_b.pwd)
            .expect("start controlling agent");
        agent_b
            .start_connectivity_checks(now, false, credentials_a.ufrag, credentials_a.pwd)
            .expect("start controlled agent");
        let mut driver_a = IceAgentDriver::new(agent_a, address_a);
        let mut driver_b = IceAgentDriver::new(agent_b, address_b);

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

    fn binding_request(transaction: u8) -> [u8; 20] {
        let mut request = [0; 20];
        request[..2].copy_from_slice(&1_u16.to_be_bytes());
        request[4..8].copy_from_slice(&0x2112_A442_u32.to_be_bytes());
        request[8..].fill(transaction);
        request
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
        let mut endpoint_b =
            super::peer_endpoint_with_ice(&identity_b, "127.0.0.1:0".parse().unwrap(), 8)
                .expect("ICE endpoint B");
        let address_b = endpoint_b
            .endpoint
            .local_addr()
            .expect("endpoint B address");
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

        let request = binding_request(42);
        endpoint_a
            .socket
            .send_to(&request, address_b)
            .await
            .expect("send an ICE STUN datagram");
        let ice_message =
            tokio::time::timeout(Duration::from_secs(1), endpoint_b.ice_datagrams.recv())
                .await
                .expect("STUN reaches ICE queue")
                .expect("ICE queue remains open");
        assert_eq!(ice_message.local_addr, address_b);
        assert_eq!(
            ice_message.peer_addr,
            endpoint_a.socket.local_addr().unwrap()
        );
        assert_eq!(ice_message.payload, request);

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
    async fn iced_socket_drops_stun_when_the_bounded_ice_queue_is_full() {
        let temp =
            std::env::temp_dir().join(format!("mini-tunnel-ice-queue-{}", uuid::Uuid::new_v4()));
        let identity =
            crate::Identity::load_or_create_at(temp.join("device.key")).expect("identity");
        let mut endpoint =
            super::peer_endpoint_with_ice(&identity, "127.0.0.1:0".parse().unwrap(), 1)
                .expect("ICE endpoint");
        let address = endpoint.endpoint.local_addr().expect("endpoint address");
        let sender = UdpSocket::bind("127.0.0.1:0").await.expect("sender socket");
        sender
            .send_to(&binding_request(1), address)
            .await
            .expect("send first STUN datagram");
        sender
            .send_to(&binding_request(2), address)
            .await
            .expect("send second STUN datagram");
        tokio::time::sleep(Duration::from_millis(30)).await;

        let first = endpoint
            .ice_datagrams
            .recv()
            .await
            .expect("first STUN datagram queued");
        assert_eq!(first.payload, binding_request(1));
        assert!(endpoint.ice_datagrams.try_recv().is_err());
        endpoint.endpoint.close(0_u32.into(), b"test complete");
        let _ = fs::remove_dir_all(temp);
    }
}
