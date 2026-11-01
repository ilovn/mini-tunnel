//! Quinn UDP socket adapter for the ticket-authorized datagram relay.

use std::{
    future::Future,
    io::{self, IoSliceMut},
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use quinn::Endpoint;
use tokio::{net::UdpSocket, sync::mpsc};

use crate::{Identity, IdentityError, PeerChannel, peer_server_config_with_udp_relay};

const HELLO: &[u8; 8] = b"MTUHELLO";
const CHALLENGE: &[u8; 8] = b"MTUCHAL1";
const PROOF: &[u8; 8] = b"MTUPROOF";
const READY: &[u8; 8] = b"MTUREADY";
const MAX_TICKET_LENGTH: usize = 2048;
const MAX_DATAGRAM: usize = mini_tunnel_protocol::UDP_RELAY_MAX_DATAGRAM_LEN;
const HEADER_LENGTH: usize = mini_tunnel_protocol::UDP_RELAY_DATA_HEADER_LEN;
const INNER_MAX_DATAGRAM: usize = MAX_DATAGRAM - HEADER_LENGTH;
const QUEUE_CAPACITY: usize = 256;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const PAIR_TIMEOUT: Duration = Duration::from_secs(35);
const RETRY_INTERVAL: Duration = Duration::from_millis(500);

#[derive(Debug)]
struct RelayDatagram {
    payload: Vec<u8>,
}

#[derive(Debug)]
struct UdpRelayRuntime {
    inner: quinn::TokioRuntime,
    relay_address: SocketAddr,
    session_id: [u8; 16],
    receiver: Arc<Mutex<Option<mpsc::Receiver<RelayDatagram>>>>,
    sender: mpsc::Sender<RelayDatagram>,
}

impl UdpRelayRuntime {
    fn new(relay_address: SocketAddr, session_id: [u8; 16]) -> Self {
        let (sender, receiver) = mpsc::channel(QUEUE_CAPACITY);
        Self {
            inner: quinn::TokioRuntime,
            relay_address,
            session_id,
            receiver: Arc::new(Mutex::new(Some(receiver))),
            sender,
        }
    }
}

impl quinn::Runtime for UdpRelayRuntime {
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
        let receiver = self
            .receiver
            .lock()
            .map_err(|_| io::Error::other("UDP relay receive queue lock is poisoned"))?
            .take()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "UDP relay runtime supports one socket",
                )
            })?;
        let sender = self.sender.clone();
        let session_id = self.session_id;
        let receive_socket = Arc::clone(&socket);
        tokio::spawn(async move {
            let mut buffer = vec![0; u16::MAX as usize];
            loop {
                let Ok(length) = receive_socket.recv(&mut buffer).await else {
                    break;
                };
                let Ok((received_session, payload)) =
                    mini_tunnel_protocol::decode_udp_relay_datagram(&buffer[..length])
                else {
                    continue;
                };
                if received_session != session_id {
                    continue;
                }
                if sender
                    .try_send(RelayDatagram {
                        payload: payload.to_vec(),
                    })
                    .is_err()
                {
                    continue;
                }
            }
        });
        Ok(Arc::new(UdpRelayQuinnSocket {
            socket,
            relay_address: self.relay_address,
            session_id: self.session_id,
            receiver: Mutex::new(receiver),
        }))
    }

    fn now(&self) -> std::time::Instant {
        self.inner.now()
    }
}

#[derive(Debug)]
struct UdpRelayQuinnSocket {
    socket: Arc<UdpSocket>,
    relay_address: SocketAddr,
    session_id: [u8; 16],
    receiver: Mutex<mpsc::Receiver<RelayDatagram>>,
}

impl quinn::AsyncUdpSocket for UdpRelayQuinnSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        Box::pin(RelayUdpPoller {
            socket: Arc::clone(&self.socket),
        })
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit<'_>) -> io::Result<()> {
        if transmit.segment_size.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "UDP relay does not support UDP segmentation",
            ));
        }
        if transmit.destination != self.relay_address {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "UDP relay socket only supports its configured relay address",
            ));
        }
        let frame =
            mini_tunnel_protocol::encode_udp_relay_datagram(&self.session_id, transmit.contents)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        self.socket.try_io(tokio::io::Interest::WRITABLE, || {
            let sent = self.socket.try_send(&frame)?;
            if sent != frame.len() {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "incomplete UDP relay datagram send",
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
                return Poll::Ready(Err(io::Error::other(
                    "UDP relay Quinn receive queue is already polled",
                )));
            }
        };
        let limit = buffers.len().min(metadata.len());
        let mut received = 0;
        while received < limit {
            match receiver.poll_recv(cx) {
                Poll::Ready(Some(datagram)) => {
                    if datagram.payload.len() > buffers[received].len()
                        || datagram.payload.len() > INNER_MAX_DATAGRAM
                    {
                        continue;
                    }
                    buffers[received][..datagram.payload.len()].copy_from_slice(&datagram.payload);
                    metadata[received] = quinn::udp::RecvMeta {
                        addr: self.relay_address,
                        len: datagram.payload.len(),
                        stride: datagram.payload.len(),
                        ecn: None,
                        dst_ip: None,
                    };
                    received += 1;
                }
                Poll::Ready(None) => {
                    return if received == 0 {
                        Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "UDP relay receive task stopped",
                        )))
                    } else {
                        Poll::Ready(Ok(received))
                    };
                }
                Poll::Pending => {
                    return if received == 0 {
                        Poll::Pending
                    } else {
                        Poll::Ready(Ok(received))
                    };
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
struct RelayUdpPoller {
    socket: Arc<UdpSocket>,
}

impl quinn::UdpPoller for RelayUdpPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.socket.poll_send_ready(cx)
    }
}

/// Connect through the ticket-authorized UDP relay and pin peer TLS to its Ed25519 key.
pub async fn connect_udp_relay_peer(
    relay_address: SocketAddr,
    ticket: &str,
    session_id: [u8; 16],
    network_id: &str,
    identity: &Identity,
    expected_peer_id: &str,
    expected_peer_key: [u8; 32],
) -> Result<PeerChannel, IdentityError> {
    if expected_peer_id != mini_tunnel_protocol::device_id_from_public_key(&expected_peer_key)
        || session_id == [0; 16]
        || ticket.is_empty()
        || ticket.len() > MAX_TICKET_LENGTH
    {
        return Err(IdentityError::UnauthorizedPeer);
    }
    let socket = UdpSocket::bind(if relay_address.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .await?;
    socket.connect(relay_address).await?;
    authenticate_udp_relay(&socket, ticket, session_id, identity).await?;
    let std_socket = socket.into_std()?;
    let runtime = UdpRelayRuntime::new(relay_address, session_id);
    let server_config = peer_server_config_with_udp_relay(identity)?;
    let endpoint = Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(server_config),
        std_socket,
        Arc::new(runtime),
    )
    .map_err(|error| IdentityError::Transport(error.to_string()))?;
    let mut channel = if identity.device_id().as_str() < expected_peer_id {
        tokio::time::timeout(
            PAIR_TIMEOUT,
            crate::connect_peer_with_udp_relay_transport(
                &endpoint,
                relay_address,
                network_id,
                identity,
                expected_peer_id,
                expected_peer_key,
            ),
        )
        .await
        .map_err(|error| IdentityError::Transport(error.to_string()))??
    } else {
        let incoming = tokio::time::timeout(PAIR_TIMEOUT, endpoint.accept())
            .await
            .map_err(|error| IdentityError::Transport(error.to_string()))?
            .ok_or_else(|| {
                IdentityError::Transport(
                    "UDP relay endpoint closed before peer connected".to_owned(),
                )
            })?;
        let connection = tokio::time::timeout(HANDSHAKE_TIMEOUT, incoming)
            .await
            .map_err(|error| IdentityError::Transport(error.to_string()))?
            .map_err(|error| IdentityError::Transport(error.to_string()))?;
        let allowed = [(expected_peer_id.to_owned(), expected_peer_key)];
        tokio::time::timeout(
            HANDSHAKE_TIMEOUT,
            super::server_authenticate(&connection, network_id, identity, None, Some(&allowed)),
        )
        .await
        .map_err(|error| IdentityError::Transport(error.to_string()))??;
        super::new_channel(connection, network_id)
    };
    channel.relay = true;
    channel.retain_relay_endpoint(endpoint);
    Ok(channel)
}

async fn authenticate_udp_relay(
    socket: &UdpSocket,
    ticket: &str,
    expected_session_id: [u8; 16],
    identity: &Identity,
) -> Result<(), IdentityError> {
    let ticket_length = u16::try_from(ticket.len()).map_err(|_| IdentityError::UnauthorizedPeer)?;
    let public_key = identity.public_key();
    let mut hello = Vec::with_capacity(10 + ticket.len() + 32);
    hello.extend_from_slice(HELLO);
    hello.extend_from_slice(&ticket_length.to_be_bytes());
    hello.extend_from_slice(ticket.as_bytes());
    hello.extend_from_slice(&public_key);
    let mut response = [0; 64];
    let deadline = tokio::time::Instant::now() + HANDSHAKE_TIMEOUT;
    let length = loop {
        socket.send(&hello).await?;
        match tokio::time::timeout(RETRY_INTERVAL, socket.recv(&mut response)).await {
            Ok(result) => break result?,
            Err(_) if tokio::time::Instant::now() < deadline => continue,
            Err(error) => return Err(IdentityError::Transport(error.to_string())),
        }
    };
    if length != 40 || response[..8] != CHALLENGE[..] {
        return Err(IdentityError::UnauthorizedPeer);
    }
    let challenge: [u8; 32] = response[8..40]
        .try_into()
        .map_err(|_| IdentityError::UnauthorizedPeer)?;
    let signature = identity.sign(&mini_tunnel_protocol::relay_auth_signing_bytes(
        ticket,
        &challenge,
        &public_key,
    ));
    let signature = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| IdentityError::UnauthorizedPeer)?;
    if signature.len() != 64 {
        return Err(IdentityError::UnauthorizedPeer);
    }
    let mut proof = Vec::with_capacity(10 + ticket.len() + 32 + signature.len());
    proof.extend_from_slice(PROOF);
    proof.extend_from_slice(&ticket_length.to_be_bytes());
    proof.extend_from_slice(ticket.as_bytes());
    proof.extend_from_slice(&public_key);
    proof.extend_from_slice(&signature);
    let deadline = tokio::time::Instant::now() + PAIR_TIMEOUT;
    let length = loop {
        socket.send(&proof).await?;
        match tokio::time::timeout(RETRY_INTERVAL, socket.recv(&mut response)).await {
            Ok(result) => break result?,
            Err(_) if tokio::time::Instant::now() < deadline => continue,
            Err(error) => return Err(IdentityError::Transport(error.to_string())),
        }
    };
    if length != 24 || response[..8] != READY[..] || response[8..24] != expected_session_id {
        return Err(IdentityError::UnauthorizedPeer);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mini_tunnel_protocol::{RELAY_TICKET_VERSION, RelayTicketClaims, issue_relay_ticket};
    use tokio::time::timeout;

    fn make_ticket(
        key: &[u8; 32],
        session_id: [u8; 16],
        source: &Identity,
        target: &Identity,
        ticket_id: [u8; 16],
    ) -> String {
        issue_relay_ticket(
            key,
            &RelayTicketClaims {
                version: RELAY_TICKET_VERSION,
                network_id: "udp-relay-test".to_owned(),
                source_device_id: source.device_id(),
                target_device_id: target.device_id(),
                session_id,
                ticket_id,
                expires_at_ms: unix_time_ms().expect("time") + 30_000,
            },
        )
        .expect("issue UDP relay ticket")
    }

    fn unix_time_ms() -> Option<u64> {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|duration| u64::try_from(duration.as_millis()).ok())
    }

    #[tokio::test]
    async fn quic_peer_channel_runs_through_ticketed_udp_relay() {
        let temp = std::env::temp_dir().join(format!(
            "mini-tunnel-agent-udp-relay-{}",
            uuid::Uuid::new_v4()
        ));
        let alice =
            Identity::load_or_create_at(temp.join("alice/device.key")).expect("Alice identity");
        let bob = Identity::load_or_create_at(temp.join("bob/device.key")).expect("Bob identity");
        let alice_id = alice.device_id();
        let bob_id = bob.device_id();
        let key = [81; 32];
        let session_id = [82; 16];
        let ticket_a = make_ticket(&key, session_id, &alice, &bob, [83; 16]);
        let ticket_b = make_ticket(&key, session_id, &bob, &alice, [84; 16]);
        let relay =
            mini_tunnel_relay::UdpRelayServer::new(mini_tunnel_relay::UdpRelayConfig::new(key));
        let relay_socket = UdpSocket::bind("127.0.0.1:0").await.expect("relay socket");
        let relay_address = relay_socket.local_addr().expect("relay address");
        let runner = {
            let relay = relay.clone();
            tokio::spawn(async move { relay.run(relay_socket).await.expect("run relay") })
        };
        let (alice_result, bob_result) = timeout(Duration::from_secs(10), async {
            tokio::join!(
                connect_udp_relay_peer(
                    relay_address,
                    &ticket_a,
                    session_id,
                    "udp-relay-test",
                    &alice,
                    &bob_id,
                    bob.public_key(),
                ),
                connect_udp_relay_peer(
                    relay_address,
                    &ticket_b,
                    session_id,
                    "udp-relay-test",
                    &bob,
                    &alice_id,
                    alice.public_key(),
                ),
            )
        })
        .await
        .expect("UDP relay QUIC handshake timeout");
        let alice_channel = alice_result.expect("Alice channel");
        let bob_channel = bob_result.expect("Bob channel");
        assert_eq!(alice_channel.transport_name(), "Relay/QUIC/UDP");
        alice_channel
            .send_packet(b"opaque datagram tunnel")
            .await
            .expect("send through UDP relay");
        assert_eq!(
            timeout(Duration::from_secs(2), bob_channel.recv_packet())
                .await
                .expect("packet timeout")
                .expect("receive tunneled packet"),
            b"opaque datagram tunnel"
        );
        assert!(relay.stats().await.forwarded_datagrams_total > 0);
        drop(alice_channel);
        drop(bob_channel);
        relay.shutdown();
        runner.await.expect("relay task");
        std::fs::remove_dir_all(temp).expect("remove test identities");
    }
}
