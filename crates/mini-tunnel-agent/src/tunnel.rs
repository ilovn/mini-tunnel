//! Bidirectional bridge between a validated L3 packet device and an authenticated peer channel.

use std::{
    collections::HashMap, future::Future, net::Ipv4Addr, pin::Pin, sync::Arc, time::Duration,
};

use thiserror::Error;

use crate::{IdentityError, PeerChannel, tun_device::TunError};

pub type PeerConnectFuture =
    Pin<Box<dyn Future<Output = Result<PeerChannel, IdentityError>> + Send>>;
pub type PeerConnector = Arc<dyn Fn(bool) -> PeerConnectFuture + Send + Sync>;

#[derive(Default)]
pub struct PathQualityTracker {
    last_successes: u64,
    last_missed: u64,
    window_probes: u64,
    window_missed: u64,
    bad_windows: u8,
    degraded: bool,
}

impl PathQualityTracker {
    /// Require three probes per window and three consecutive bad windows before degrading.
    pub fn observe(&mut self, snapshot: crate::PeerHealthSnapshot) -> bool {
        let successes = snapshot
            .probes_succeeded
            .saturating_sub(self.last_successes);
        let missed = snapshot.probes_missed.saturating_sub(self.last_missed);
        self.last_successes = snapshot.probes_succeeded;
        self.last_missed = snapshot.probes_missed;
        self.window_probes = self.window_probes.saturating_add(successes + missed);
        self.window_missed = self.window_missed.saturating_add(missed);
        if self.window_probes < 3 || self.degraded {
            return self.degraded;
        }
        let loss_ratio = self.window_missed as f64 / self.window_probes as f64;
        let bad = loss_ratio > 0.20
            || snapshot
                .rtt
                .is_some_and(|rtt| rtt > Duration::from_millis(350));
        self.bad_windows = if bad {
            self.bad_windows.saturating_add(1)
        } else {
            0
        };
        self.window_probes = 0;
        self.window_missed = 0;
        self.degraded = self.bad_windows >= 3;
        self.degraded
    }
}

pub struct ReconnectingPeer {
    pub address: Ipv4Addr,
    pub channel: Arc<PeerChannel>,
    pub connector: PeerConnector,
    /// Direct-only candidate probe used to migrate a healthy TCP/relay session back to UDP.
    pub probe: Option<PeerConnector>,
    /// Cooldown between path probes. Production callers should use at least 60 seconds.
    pub probe_cooldown: Duration,
}

/// Runtime membership changes consumed by the mesh packet pump.
pub enum MeshPeerUpdate {
    Add(ReconnectingPeer),
    Remove(Ipv4Addr),
}

struct MeshPeerRuntime {
    channel: Arc<tokio::sync::RwLock<Arc<PeerChannel>>>,
    connector: Option<PeerConnector>,
    probe: Option<PeerConnector>,
    probe_cooldown: Duration,
}

type MeshPeerInput = (
    Ipv4Addr,
    Arc<PeerChannel>,
    Option<PeerConnector>,
    Option<PeerConnector>,
    Duration,
);

#[derive(Debug, Error)]
pub enum PeerTunnelError {
    #[error(transparent)]
    Tun(#[from] TunError),
    #[error(transparent)]
    Peer(#[from] IdentityError),
    #[error("no authenticated peers remain connected")]
    NoPeers,
    #[error("multiple authenticated peers claim the same overlay IPv4 address")]
    DuplicatePeerAddress,
}

/// Injectable boundary that allows the packet pump to be tested without a privileged OS TUN.
#[allow(async_fn_in_trait)]
pub trait TunnelPacketIo: Sync {
    async fn read_outbound_packet(&self) -> Result<Vec<u8>, TunError>;
    async fn write_inbound_packet(
        &self,
        packet: &[u8],
        expected_peer_ipv4: Ipv4Addr,
    ) -> Result<(), TunError>;
}

impl TunnelPacketIo for crate::tun_device::TunDevice {
    async fn read_outbound_packet(&self) -> Result<Vec<u8>, TunError> {
        crate::tun_device::TunDevice::read_outbound_packet(self).await
    }

    async fn write_inbound_packet(
        &self,
        packet: &[u8],
        expected_peer_ipv4: Ipv4Addr,
    ) -> Result<(), TunError> {
        crate::tun_device::TunDevice::write_inbound_packet(self, packet, expected_peer_ipv4).await
    }
}

/// Forward validated IPv4 packets in both directions until the TUN or peer fails.
///
/// Calls `send_packet` only with local-originated packets. Incoming packets are revalidated by the
/// packet device against the authenticated peer's assigned address before entering the local stack.
pub async fn pump_peer_packets<T: TunnelPacketIo>(
    packet_io: &T,
    peer: &PeerChannel,
    peer_ipv4: Ipv4Addr,
) -> Result<(), PeerTunnelError> {
    let mut keepalive = tokio::time::interval(Duration::from_secs(10));
    keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    keepalive.tick().await;
    let mut last_received = tokio::time::Instant::now();
    let mut inbound = Box::pin(peer.recv_packet());
    loop {
        tokio::select! {
            outbound = packet_io.read_outbound_packet() => {
                peer.send_packet(&outbound?).await?;
            }
            result = tokio::time::timeout_at(last_received + Duration::from_secs(30), &mut inbound) => {
                let packet = result.map_err(|_| IdentityError::Transport("peer keepalive timed out".to_owned()))??;
                last_received = tokio::time::Instant::now();
                if !packet.is_empty() {
                    packet_io.write_inbound_packet(&packet, peer_ipv4).await?;
                }
                inbound = Box::pin(peer.recv_packet());
            }
            _ = keepalive.tick() => peer.send_keepalive().await?,
        }
    }
}

async fn receive_mesh_peer(
    address: Ipv4Addr,
    channel: Arc<tokio::sync::RwLock<Arc<PeerChannel>>>,
    connector: Option<PeerConnector>,
    probe: Option<PeerConnector>,
    probe_cooldown: Duration,
    event_tx: tokio::sync::mpsc::Sender<(Ipv4Addr, Result<Vec<u8>, IdentityError>)>,
) {
    loop {
        let active = Arc::clone(&*channel.read().await);
        let mut keepalive = tokio::time::interval(Duration::from_secs(10));
        keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        keepalive.tick().await;
        let mut last_received = tokio::time::Instant::now();
        let mut inbound = Box::pin(active.recv_packet());
        let mut quality = PathQualityTracker::default();
        let mut force_reliable = false;
        let mut probe_interval =
            tokio::time::interval_at(tokio::time::Instant::now() + probe_cooldown, probe_cooldown);
        probe_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let (probe_tx, mut probe_rx) = tokio::sync::mpsc::channel(1);
        let mut probe_task = None;
        let outcome = loop {
            tokio::select! {
                result = tokio::time::timeout_at(last_received + Duration::from_secs(30), &mut inbound) => {
                    let result = match result {
                        Ok(result) => result,
                        Err(_) => Err(IdentityError::Transport("peer keepalive timed out".to_owned())),
                    };
                    match result {
                        Ok(packet) => {
                            last_received = tokio::time::Instant::now();
                            inbound = Box::pin(active.recv_packet());
                            if !packet.is_empty() && event_tx.send((address, Ok(packet))).await.is_err() {
                                return;
                            }
                        }
                        Err(error) => break Err(error),
                    }
                }
                _ = keepalive.tick() => {
                    if active.transport_name() == "QUIC/UDP" && quality.observe(active.health_snapshot()) {
                        force_reliable = true;
                        break Err(IdentityError::Transport("peer path quality degraded".to_owned()));
                    }
                    if let Err(error) = active.send_keepalive().await {
                        break Err(error);
                    }
                }
                _ = probe_interval.tick(), if probe.is_some() && active.transport_name() != "QUIC/UDP" && probe_task.is_none() => {
                    let connector = Arc::clone(probe.as_ref().expect("guarded above"));
                    let sender = probe_tx.clone();
                    probe_task = Some(tokio::spawn(async move {
                        let result = connector(false).await;
                        let _ = sender.send(result).await;
                    }));
                }
                result = probe_rx.recv(), if probe_task.is_some() => {
                    probe_task = None;
                    if let Some(Ok(candidate)) = result
                        && path_rank(candidate.transport_name()) < path_rank(active.transport_name())
                    {
                        *channel.write().await = Arc::new(candidate);
                        break Ok(());
                    }
                }
            }
        };
        if let Some(task) = probe_task {
            task.abort();
        }
        let failure = match outcome {
            Ok(()) => continue,
            Err(failure) => failure,
        };
        if active.transport_name() == "QUIC/UDP"
            && matches!(&failure, IdentityError::Transport(message) if message.contains("keepalive timed out") || message.contains("path quality degraded"))
        {
            force_reliable = true;
        }
        if connector.is_none() {
            let _ = event_tx.send((address, Err(failure))).await;
            return;
        }
        let connector = connector.as_ref().expect("checked above");
        let mut attempt = 0_u32;
        loop {
            tokio::time::sleep(crate::reconnect_delay(attempt)).await;
            attempt = attempt.saturating_add(1);
            match (connector)(force_reliable).await {
                Ok(reconnected) => {
                    *channel.write().await = Arc::new(reconnected);
                    break;
                }
                Err(IdentityError::UnauthorizedPeer) => {
                    let _ = event_tx
                        .send((address, Err(IdentityError::UnauthorizedPeer)))
                        .await;
                    return;
                }
                Err(_) => continue,
            }
        }
    }
}

fn path_rank(transport: &str) -> u8 {
    match transport {
        "QUIC/UDP" => 0,
        "TLS/TCP" => 1,
        "Relay/TLS" => 2,
        _ => u8::MAX,
    }
}

/// Route packets across one TUN and multiple independently authenticated peer channels.
///
/// Packets with no matching peer destination are dropped. A failed peer is removed from the
/// forwarding table without stopping the other peer sessions.
pub async fn pump_peer_mesh<T: TunnelPacketIo>(
    packet_io: &T,
    peers: Vec<(Ipv4Addr, Arc<PeerChannel>)>,
) -> Result<(), PeerTunnelError> {
    pump_mesh(
        packet_io,
        peers
            .into_iter()
            .map(|(address, channel)| (address, channel, None, None, Duration::from_secs(3600)))
            .collect(),
        None,
    )
    .await
}

pub async fn pump_peer_mesh_reconnecting<T: TunnelPacketIo>(
    packet_io: &T,
    peers: Vec<ReconnectingPeer>,
) -> Result<(), PeerTunnelError> {
    pump_mesh(
        packet_io,
        peers
            .into_iter()
            .map(|peer| {
                (
                    peer.address,
                    peer.channel,
                    Some(peer.connector),
                    peer.probe,
                    peer.probe_cooldown,
                )
            })
            .collect(),
        None,
    )
    .await
}

/// Run a mesh whose peer set can change without recreating the TUN interface.
pub async fn pump_peer_mesh_dynamic<T: TunnelPacketIo>(
    packet_io: &T,
    peers: Vec<ReconnectingPeer>,
    updates: tokio::sync::mpsc::Receiver<MeshPeerUpdate>,
) -> Result<(), PeerTunnelError> {
    pump_mesh(
        packet_io,
        peers
            .into_iter()
            .map(|peer| {
                (
                    peer.address,
                    peer.channel,
                    Some(peer.connector),
                    peer.probe,
                    peer.probe_cooldown,
                )
            })
            .collect(),
        Some(updates),
    )
    .await
}

async fn pump_mesh<T: TunnelPacketIo>(
    packet_io: &T,
    peers: Vec<MeshPeerInput>,
    mut updates: Option<tokio::sync::mpsc::Receiver<MeshPeerUpdate>>,
) -> Result<(), PeerTunnelError> {
    if peers.is_empty() && updates.is_none() {
        return Err(PeerTunnelError::NoPeers);
    }
    let mut channels = HashMap::with_capacity(peers.len());
    for (address, channel, connector, probe, probe_cooldown) in peers {
        if channels
            .insert(
                address,
                MeshPeerRuntime {
                    channel: Arc::new(tokio::sync::RwLock::new(channel)),
                    connector,
                    probe,
                    probe_cooldown,
                },
            )
            .is_some()
        {
            return Err(PeerTunnelError::DuplicatePeerAddress);
        }
    }

    let (event_tx, mut event_rx) =
        tokio::sync::mpsc::channel(channels.len().saturating_mul(8).max(8));
    let mut receivers = HashMap::with_capacity(channels.len());
    for (&address, runtime) in &channels {
        receivers.insert(
            address,
            spawn_mesh_receiver(address, runtime, event_tx.clone()),
        );
    }

    while !channels.is_empty() || updates.is_some() {
        tokio::select! {
            outbound = packet_io.read_outbound_packet() => {
                let packet = outbound?;
                let Some(destination) = ipv4_destination(&packet) else {
                    continue;
                };
                if let Some(runtime) = channels.get(&destination) {
                    let current = Arc::clone(&*runtime.channel.read().await);
                    if current.send_packet(&packet).await.is_err() && runtime.connector.is_none() {
                        channels.remove(&destination);
                    }
                }
            }
            inbound = event_rx.recv() => {
                let Some((address, result)) = inbound else {
                    return Err(PeerTunnelError::NoPeers);
                };
                match result {
                    Ok(packet) => match packet_io.write_inbound_packet(&packet, address).await {
                        Ok(()) | Err(TunError::InvalidPacket(_)) => {}
                        Err(error) => return Err(error.into()),
                    },
                    Err(_) => {
                        if let Some(runtime) = channels.remove(&address) {
                            Arc::clone(&*runtime.channel.read().await).close();
                        }
                        if let Some(task) = receivers.remove(&address) {
                            task.abort();
                        }
                    }
                }
            }
            update = async {
                match updates.as_mut() {
                    Some(receiver) => receiver.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                match update {
                    Some(MeshPeerUpdate::Add(peer)) => {
                        let address = peer.address;
                        if channels.contains_key(&address) {
                            peer.channel.close();
                            continue;
                        }
                        let runtime = MeshPeerRuntime {
                            channel: Arc::new(tokio::sync::RwLock::new(peer.channel)),
                            connector: Some(peer.connector),
                            probe: peer.probe,
                            probe_cooldown: peer.probe_cooldown,
                        };
                        receivers.insert(address, spawn_mesh_receiver(address, &runtime, event_tx.clone()));
                        channels.insert(address, runtime);
                    }
                    Some(MeshPeerUpdate::Remove(address)) => {
                        if let Some(runtime) = channels.remove(&address) {
                            Arc::clone(&*runtime.channel.read().await).close();
                        }
                        if let Some(task) = receivers.remove(&address) {
                            task.abort();
                        }
                    }
                    None => {
                        updates = None;
                        if channels.is_empty() {
                            break;
                        }
                    }
                }
            }
        }
    }
    for task in receivers.into_values() {
        task.abort();
    }
    Err(PeerTunnelError::NoPeers)
}

fn spawn_mesh_receiver(
    address: Ipv4Addr,
    runtime: &MeshPeerRuntime,
    event_tx: tokio::sync::mpsc::Sender<(Ipv4Addr, Result<Vec<u8>, IdentityError>)>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(receive_mesh_peer(
        address,
        Arc::clone(&runtime.channel),
        runtime.connector.clone(),
        runtime.probe.clone(),
        runtime.probe_cooldown,
        event_tx,
    ))
}

fn ipv4_destination(packet: &[u8]) -> Option<Ipv4Addr> {
    let octets: [u8; 4] = packet.get(16..20)?.try_into().ok()?;
    Some(Ipv4Addr::from(octets))
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        net::{IpAddr, Ipv4Addr, SocketAddr},
        time::Duration,
    };

    use tokio::sync::{Mutex, mpsc};

    use super::*;
    use crate::{
        Identity, accept_peer, accept_tcp_peer_any, connect_peer, connect_tcp_peer, peer_endpoint,
        peer_tcp_listener,
    };

    #[test]
    fn path_quality_requires_three_bad_windows_and_resets_after_a_healthy_window() {
        let mut tracker = PathQualityTracker::default();
        let mut snapshot = crate::PeerHealthSnapshot {
            rtt: Some(Duration::from_millis(500)),
            probes_succeeded: 0,
            probes_missed: 0,
        };
        for window in 0..2 {
            snapshot.probes_succeeded += 3;
            assert!(
                !tracker.observe(snapshot),
                "window {window} must not trigger a switch"
            );
        }
        snapshot.rtt = Some(Duration::from_millis(50));
        snapshot.probes_succeeded += 3;
        assert!(
            !tracker.observe(snapshot),
            "healthy window resets the hysteresis counter"
        );
        snapshot.rtt = Some(Duration::from_millis(500));
        for _ in 0..2 {
            snapshot.probes_succeeded += 3;
            assert!(!tracker.observe(snapshot));
        }
        snapshot.probes_succeeded += 3;
        assert!(tracker.observe(snapshot));
    }

    struct MockPacketIo {
        outbound: Mutex<mpsc::Receiver<Vec<u8>>>,
        inbound: mpsc::Sender<Vec<u8>>,
        local_ipv4: Ipv4Addr,
        mtu: usize,
    }

    impl TunnelPacketIo for MockPacketIo {
        async fn read_outbound_packet(&self) -> Result<Vec<u8>, TunError> {
            let packet = self.outbound.lock().await.recv().await.ok_or_else(|| {
                TunError::Io(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "mock TUN closed",
                ))
            })?;
            crate::tun_device::validate_outbound_ipv4(&packet, self.local_ipv4, self.mtu)?;
            Ok(packet)
        }

        async fn write_inbound_packet(
            &self,
            packet: &[u8],
            expected_peer_ipv4: Ipv4Addr,
        ) -> Result<(), TunError> {
            crate::tun_device::validate_inbound_ipv4(
                packet,
                self.local_ipv4,
                expected_peer_ipv4,
                self.mtu,
            )?;
            self.inbound.send(packet.to_vec()).await.map_err(|_| {
                TunError::Io(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "mock TUN receiver closed",
                ))
            })
        }
    }

    fn packet(source: Ipv4Addr, destination: Ipv4Addr, size: usize) -> Vec<u8> {
        let mut packet = vec![0; size];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(size as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&source.octets());
        packet[16..20].copy_from_slice(&destination.octets());
        packet
    }

    #[tokio::test]
    async fn mesh_reconnects_peer_after_tcp_disconnect() {
        async fn tcp_pair(a: Arc<Identity>, b: Arc<Identity>) -> (PeerChannel, PeerChannel) {
            let listener = peer_tcp_listener(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
                .await
                .unwrap();
            let address = listener.local_addr().unwrap();
            let allowed = vec![(a.device_id(), a.public_key())];
            let peer_id = b.device_id();
            let accept = accept_tcp_peer_any(&listener, "mesh-reconnect", &b, &allowed);
            let connect = connect_tcp_peer(address, "mesh-reconnect", &a, &peer_id, b.public_key());
            let (accepted, connected) = tokio::join!(accept, connect);
            (connected.unwrap(), accepted.unwrap().1)
        }

        let temp = std::env::temp_dir().join(format!(
            "mini-tunnel-mesh-reconnect-{}",
            uuid::Uuid::new_v4()
        ));
        let a = Arc::new(Identity::load_or_create_at(temp.join("a/key")).unwrap());
        let b = Arc::new(Identity::load_or_create_at(temp.join("b/key")).unwrap());
        let (initial, remote_initial) = tcp_pair(Arc::clone(&a), Arc::clone(&b)).await;
        let remote_channel = Arc::new(Mutex::new(None));
        let remote_notify = Arc::new(tokio::sync::Notify::new());
        let connector: PeerConnector = {
            let a = Arc::clone(&a);
            let b = Arc::clone(&b);
            let remote_channel = Arc::clone(&remote_channel);
            let remote_notify = Arc::clone(&remote_notify);
            Arc::new(move |_force_reliable| -> PeerConnectFuture {
                let a = Arc::clone(&a);
                let b = Arc::clone(&b);
                let remote_channel = Arc::clone(&remote_channel);
                let remote_notify = Arc::clone(&remote_notify);
                Box::pin(async move {
                    let (local, remote) = tcp_pair(a, b).await;
                    *remote_channel.lock().await = Some(remote);
                    remote_notify.notify_one();
                    Ok(local)
                })
            })
        };
        let local_ip = Ipv4Addr::new(10, 0, 0, 1);
        let peer_ip = Ipv4Addr::new(10, 0, 0, 2);
        let (outbound_tx, outbound_rx) = mpsc::channel(4);
        let (inbound_tx, _inbound_rx) = mpsc::channel(4);
        let io = Arc::new(MockPacketIo {
            outbound: Mutex::new(outbound_rx),
            inbound: inbound_tx,
            local_ipv4: local_ip,
            mtu: 1500,
        });
        let pump_io = Arc::clone(&io);
        let pump = tokio::spawn(async move {
            pump_peer_mesh_reconnecting(
                &*pump_io,
                vec![ReconnectingPeer {
                    address: peer_ip,
                    channel: Arc::new(initial),
                    connector,
                    probe: None,
                    probe_cooldown: Duration::from_secs(3600),
                }],
            )
            .await
        });
        drop(remote_initial);
        tokio::time::timeout(Duration::from_secs(3), remote_notify.notified())
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await;
        outbound_tx
            .send(packet(local_ip, peer_ip, 28))
            .await
            .unwrap();
        let recovered = remote_channel.lock().await.take().unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(3), recovered.recv_packet())
                .await
                .unwrap()
                .unwrap()
                .len(),
            28
        );
        pump.abort();
        drop(recovered);
        fs::remove_dir_all(temp).unwrap();
    }

    #[tokio::test]
    async fn mesh_promotes_reliable_session_after_healthy_direct_udp_probe() {
        async fn tcp_pair(a: Arc<Identity>, b: Arc<Identity>) -> (PeerChannel, PeerChannel) {
            let listener = peer_tcp_listener(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
                .await
                .unwrap();
            let address = listener.local_addr().unwrap();
            let allowed = vec![(a.device_id(), a.public_key())];
            let peer_id = b.device_id();
            let accept = accept_tcp_peer_any(&listener, "mesh-promotion", &b, &allowed);
            let connect = connect_tcp_peer(address, "mesh-promotion", &a, &peer_id, b.public_key());
            let (accepted, connected) = tokio::join!(accept, connect);
            (connected.unwrap(), accepted.unwrap().1)
        }

        let temp = std::env::temp_dir().join(format!(
            "mini-tunnel-mesh-promotion-{}",
            uuid::Uuid::new_v4()
        ));
        let a = Arc::new(Identity::load_or_create_at(temp.join("a/key")).unwrap());
        let b = Arc::new(Identity::load_or_create_at(temp.join("b/key")).unwrap());
        let (initial, _remote_initial) = tcp_pair(Arc::clone(&a), Arc::clone(&b)).await;
        let endpoint_a =
            peer_endpoint(&a, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap();
        let endpoint_b =
            peer_endpoint(&b, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap();
        let remote_addr = endpoint_b.local_addr().unwrap();
        let a_id = a.device_id();
        let b_id = b.device_id();
        let a_key = a.public_key();
        let b_key = b.public_key();
        let (accepted_tx, mut accepted_rx) = mpsc::channel(1);
        let server_endpoint = endpoint_b.clone();
        let server_identity = Arc::clone(&b);
        let server_task = tokio::spawn(async move {
            let channel = Arc::new(
                accept_peer(
                    &server_endpoint,
                    "mesh-promotion",
                    &server_identity,
                    &a_id,
                    a_key,
                )
                .await
                .unwrap(),
            );
            accepted_tx.send(Arc::clone(&channel)).await.unwrap();
            for _ in 0..3 {
                channel.recv_packet().await.unwrap();
            }
        });
        let connector: PeerConnector = Arc::new(|_| -> PeerConnectFuture {
            Box::pin(async {
                Err(IdentityError::Transport(
                    "reconnect path should not run during promotion".to_owned(),
                ))
            })
        });
        let probe_endpoint = endpoint_a.clone();
        let probe_identity = Arc::clone(&a);
        let probe: PeerConnector = Arc::new(move |_| -> PeerConnectFuture {
            let endpoint = probe_endpoint.clone();
            let identity = Arc::clone(&probe_identity);
            let peer_id = b_id.clone();
            Box::pin(async move {
                let channel = connect_peer(
                    &endpoint,
                    remote_addr,
                    "mesh-promotion",
                    &identity,
                    &peer_id,
                    b_key,
                )
                .await?;
                let rtt = channel.probe_health(3, Duration::from_secs(2)).await?;
                if rtt > Duration::from_millis(350) {
                    return Err(IdentityError::Transport(
                        "direct probe RTT exceeded threshold".to_owned(),
                    ));
                }
                Ok(channel)
            })
        });
        let local_ip = Ipv4Addr::new(10, 0, 0, 1);
        let peer_ip = Ipv4Addr::new(10, 0, 0, 2);
        let (outbound_tx, outbound_rx) = mpsc::channel(2);
        let (inbound_tx, _inbound_rx) = mpsc::channel(2);
        let io = Arc::new(MockPacketIo {
            outbound: Mutex::new(outbound_rx),
            inbound: inbound_tx,
            local_ipv4: local_ip,
            mtu: 1500,
        });
        let pump_io = Arc::clone(&io);
        let pump = tokio::spawn(async move {
            pump_peer_mesh_reconnecting(
                &*pump_io,
                vec![ReconnectingPeer {
                    address: peer_ip,
                    channel: Arc::new(initial),
                    connector,
                    probe: Some(probe),
                    probe_cooldown: Duration::from_millis(25),
                }],
            )
            .await
        });
        let remote = tokio::time::timeout(Duration::from_secs(3), accepted_rx.recv())
            .await
            .unwrap()
            .unwrap();
        server_task.await.unwrap();
        tokio::time::sleep(Duration::from_millis(25)).await;
        outbound_tx
            .send(packet(local_ip, peer_ip, 28))
            .await
            .unwrap();
        let received = tokio::time::timeout(Duration::from_secs(3), remote.recv_packet())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received.len(), 28);
        pump.abort();
        endpoint_a.close(0_u32.into(), b"test complete");
        endpoint_b.close(0_u32.into(), b"test complete");
        fs::remove_dir_all(temp).unwrap();
    }

    #[tokio::test]
    async fn packet_pump_forwards_both_directions_and_stops_on_disconnect() {
        let temp = std::env::temp_dir().join(format!("mini-tunnel-pump-{}", uuid::Uuid::new_v4()));
        let a = Identity::load_or_create_at(temp.join("a/device.key")).expect("identity A");
        let b = Identity::load_or_create_at(temp.join("b/device.key")).expect("identity B");
        let addr_a = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let endpoint_a = peer_endpoint(&a, addr_a).expect("endpoint A");
        let endpoint_b = peer_endpoint(&b, addr_a).expect("endpoint B");
        let a_ip = Ipv4Addr::new(10, 77, 0, 2);
        let b_ip = Ipv4Addr::new(10, 77, 0, 3);
        let a_id = a.device_id();
        let a_key = a.public_key();
        let b_id = b.device_id();
        let b_key = b.public_key();
        let server_endpoint = endpoint_b.clone();
        let accept =
            tokio::spawn(
                async move { accept_peer(&server_endpoint, "office", &b, &a_id, a_key).await },
            );
        let channel_a = connect_peer(
            &endpoint_a,
            endpoint_b.local_addr().expect("endpoint B address"),
            "office",
            &a,
            &b_id,
            b_key,
        )
        .await
        .expect("connect peer");
        let channel_b = accept.await.expect("accept task").expect("accept peer");

        let (a_out_tx, a_out_rx) = mpsc::channel(2);
        let (a_in_tx, mut a_in_rx) = mpsc::channel(2);
        let (b_out_tx, b_out_rx) = mpsc::channel(2);
        let (b_in_tx, mut b_in_rx) = mpsc::channel(2);
        let io_a = MockPacketIo {
            outbound: Mutex::new(a_out_rx),
            inbound: a_in_tx,
            local_ipv4: a_ip,
            mtu: 1150,
        };
        let io_b = MockPacketIo {
            outbound: Mutex::new(b_out_rx),
            inbound: b_in_tx,
            local_ipv4: b_ip,
            mtu: 1150,
        };
        let pump_a = tokio::spawn(async move { pump_peer_packets(&io_a, &channel_a, b_ip).await });
        let pump_b = tokio::spawn(async move { pump_peer_packets(&io_b, &channel_b, a_ip).await });

        let packet_a = packet(a_ip, b_ip, 28);
        a_out_tx
            .send(packet_a.clone())
            .await
            .expect("inject A packet");
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_secs(2), b_in_rx.recv())
                .await
                .expect("B receive timeout")
                .expect("B received packet"),
            packet_a
        );
        let packet_b = packet(b_ip, a_ip, 28);
        b_out_tx
            .send(packet_b.clone())
            .await
            .expect("inject B packet");
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_secs(2), a_in_rx.recv())
                .await
                .expect("A receive timeout")
                .expect("A received packet"),
            packet_b
        );

        endpoint_a.close(0_u32.into(), b"test disconnect");
        let result = tokio::time::timeout(std::time::Duration::from_secs(2), pump_a)
            .await
            .expect("packet pump exits after disconnect")
            .expect("pump task joins");
        assert!(result.is_err());
        pump_b.abort();
        endpoint_b.close(0_u32.into(), b"test complete");
        fs::remove_dir_all(temp).expect("remove test identities");
    }

    #[tokio::test]
    async fn mesh_routes_by_destination_drops_unknown_and_isolates_peer_disconnect() {
        let temp = std::env::temp_dir().join(format!("mini-tunnel-mesh-{}", uuid::Uuid::new_v4()));
        let a = Identity::load_or_create_at(temp.join("a/device.key")).expect("identity A");
        let b = Identity::load_or_create_at(temp.join("b/device.key")).expect("identity B");
        let c = Identity::load_or_create_at(temp.join("c/device.key")).expect("identity C");
        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let endpoint_a = peer_endpoint(&a, bind).expect("endpoint A");
        let endpoint_b = peer_endpoint(&b, bind).expect("endpoint B");
        let endpoint_c = peer_endpoint(&c, bind).expect("endpoint C");
        let b_id = b.device_id();
        let b_key = b.public_key();
        let c_id = c.device_id();
        let c_key = c.public_key();
        let a_id = a.device_id();
        let a_key = a.public_key();
        let endpoint_b_accept = endpoint_b.clone();
        let accept_b =
            tokio::spawn(
                async move { accept_peer(&endpoint_b_accept, "mesh", &b, &a_id, a_key).await },
            );
        let a_id = a.device_id();
        let a_key = a.public_key();
        let endpoint_c_accept = endpoint_c.clone();
        let accept_c =
            tokio::spawn(
                async move { accept_peer(&endpoint_c_accept, "mesh", &c, &a_id, a_key).await },
            );
        let channel_b = connect_peer(
            &endpoint_a,
            endpoint_b.local_addr().expect("B address"),
            "mesh",
            &a,
            &b_id,
            b_key,
        )
        .await
        .expect("connect B");
        let remote_b = accept_b.await.expect("B task").expect("accept B");
        let channel_c = connect_peer(
            &endpoint_a,
            endpoint_c.local_addr().expect("C address"),
            "mesh",
            &a,
            &c_id,
            c_key,
        )
        .await
        .expect("connect C");
        let remote_c = accept_c.await.expect("C task").expect("accept C");

        let a_ip = Ipv4Addr::new(10, 88, 0, 2);
        let b_ip = Ipv4Addr::new(10, 88, 0, 3);
        let c_ip = Ipv4Addr::new(10, 88, 0, 4);
        let (outbound_tx, outbound_rx) = mpsc::channel(8);
        let (inbound_tx, _inbound_rx) = mpsc::channel(8);
        let io = MockPacketIo {
            outbound: Mutex::new(outbound_rx),
            inbound: inbound_tx,
            local_ipv4: a_ip,
            mtu: 1150,
        };
        let pump = tokio::spawn(async move {
            pump_peer_mesh(
                &io,
                vec![(b_ip, Arc::new(channel_b)), (c_ip, Arc::new(channel_c))],
            )
            .await
        });

        let to_b = packet(a_ip, b_ip, 28);
        outbound_tx
            .send(to_b.clone())
            .await
            .expect("inject B packet");
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), remote_b.recv_packet())
                .await
                .expect("B packet timeout")
                .expect("receive B packet"),
            to_b
        );

        outbound_tx
            .send(packet(a_ip, Ipv4Addr::new(10, 88, 0, 99), 28))
            .await
            .expect("inject unknown packet");
        assert!(
            tokio::time::timeout(Duration::from_millis(100), remote_c.recv_packet())
                .await
                .is_err()
        );

        endpoint_b.close(0_u32.into(), b"mesh peer disconnected");
        tokio::time::sleep(Duration::from_millis(100)).await;
        let to_c = packet(a_ip, c_ip, 28);
        outbound_tx
            .send(to_c.clone())
            .await
            .expect("inject C packet");
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), remote_c.recv_packet())
                .await
                .expect("C packet timeout")
                .expect("receive C packet"),
            to_c
        );

        endpoint_a.close(0_u32.into(), b"mesh test complete");
        endpoint_c.close(0_u32.into(), b"mesh test complete");
        let result = tokio::time::timeout(Duration::from_secs(2), pump)
            .await
            .expect("mesh stops when all peers disconnect")
            .expect("mesh task joins");
        assert!(matches!(result, Err(PeerTunnelError::NoPeers)));
        fs::remove_dir_all(temp).expect("remove test identities");
    }

    #[tokio::test]
    async fn dynamic_mesh_adds_and_removes_peers_without_restarting_packet_pump() {
        let temp =
            std::env::temp_dir().join(format!("mini-tunnel-dynamic-{}", uuid::Uuid::new_v4()));
        let identity = Arc::new(Identity::load_or_create_at(temp.join("a/device.key")).unwrap());
        let remote_identity =
            Arc::new(Identity::load_or_create_at(temp.join("b/device.key")).unwrap());
        let endpoint_a = peer_endpoint(
            &identity,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        )
        .unwrap();
        let endpoint_b = peer_endpoint(
            &remote_identity,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        )
        .unwrap();
        let remote_id = identity.device_id();
        let remote_key = identity.public_key();
        let accept_endpoint = endpoint_b.clone();
        let accept_identity = Arc::clone(&remote_identity);
        let accept = tokio::spawn(async move {
            crate::accept_peer(
                &accept_endpoint,
                "dynamic-mesh",
                &accept_identity,
                &remote_id,
                remote_key,
            )
            .await
        });
        let local_channel = crate::connect_peer(
            &endpoint_a,
            endpoint_b.local_addr().unwrap(),
            "dynamic-mesh",
            &identity,
            &remote_identity.device_id(),
            remote_identity.public_key(),
        )
        .await
        .unwrap();
        let remote_channel = accept.await.unwrap().unwrap();

        let local_ip = Ipv4Addr::new(10, 71, 0, 1);
        let peer_ip = Ipv4Addr::new(10, 71, 0, 2);
        let (outbound_tx, outbound_rx) = mpsc::channel(2);
        let (inbound_tx, _inbound_rx) = mpsc::channel(2);
        let io = MockPacketIo {
            outbound: Mutex::new(outbound_rx),
            inbound: inbound_tx,
            local_ipv4: local_ip,
            mtu: 1150,
        };
        let (update_tx, update_rx) = mpsc::channel(2);
        let pump =
            tokio::spawn(async move { pump_peer_mesh_dynamic(&io, Vec::new(), update_rx).await });
        let connector: PeerConnector =
            Arc::new(|_| Box::pin(async { Err(IdentityError::UnauthorizedPeer) }));
        update_tx
            .send(MeshPeerUpdate::Add(ReconnectingPeer {
                address: peer_ip,
                channel: Arc::new(local_channel),
                connector,
                probe: None,
                probe_cooldown: Duration::from_secs(3600),
            }))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        outbound_tx
            .send(packet(local_ip, peer_ip, 28))
            .await
            .unwrap();
        assert_eq!(remote_channel.recv_packet().await.unwrap().len(), 28);

        update_tx
            .send(MeshPeerUpdate::Remove(peer_ip))
            .await
            .unwrap();
        drop(update_tx);
        let result = tokio::time::timeout(Duration::from_secs(2), pump)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(result, Err(PeerTunnelError::NoPeers)));
        endpoint_a.close(0_u32.into(), b"test complete");
        endpoint_b.close(0_u32.into(), b"test complete");
        fs::remove_dir_all(temp).unwrap();
    }
}
