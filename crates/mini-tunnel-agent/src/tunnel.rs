//! Bidirectional bridge between a validated L3 packet device and an authenticated peer channel.

use std::{
    collections::HashMap,
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ops::{Deref, DerefMut},
    pin::Pin,
    sync::Arc,
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
    time::{Duration, Instant},
};

use thiserror::Error;

use crate::{IdentityError, PeerChannel, tun_device::TunError};

static MESH_DROPPED_PACKETS: AtomicU64 = AtomicU64::new(0);
const MESH_EVENT_QUEUE_PER_PEER: usize = 8;
// At the maximum 9000-byte packet size, this caps queued payloads at about 8.8 MiB.
const MAX_MESH_EVENT_QUEUE_CAPACITY: usize = 1024;
// One 9000-byte outbound packet per each of 4096 peers caps this queue at about 35.2 MiB.
const MESH_OUTBOUND_QUEUE_PER_PEER: usize = 1;
const MESH_OUTBOUND_PACKET_TTL: Duration = Duration::from_secs(5);

fn mesh_event_queue_capacity(peer_count: usize) -> usize {
    peer_count
        .saturating_mul(MESH_EVENT_QUEUE_PER_PEER)
        .clamp(MESH_EVENT_QUEUE_PER_PEER, MAX_MESH_EVENT_QUEUE_CAPACITY)
}

/// Total mesh packets dropped because a global or per-peer bounded queue was full.
#[must_use]
pub fn mesh_dropped_packets_total() -> u64 {
    MESH_DROPPED_PACKETS.load(Ordering::Relaxed)
}

struct MeshEvent {
    address: Ipv4Addr,
    result: Result<Vec<u8>, IdentityError>,
    pending: Option<Arc<AtomicUsize>>,
}

#[derive(Debug, PartialEq, Eq)]
enum MeshPacketDelivery {
    Queued,
    Dropped,
    ReceiverClosed,
}

fn try_deliver_mesh_packet(
    sender: &tokio::sync::mpsc::Sender<MeshEvent>,
    address: Ipv4Addr,
    packet: Vec<u8>,
    pending: &Arc<AtomicUsize>,
) -> MeshPacketDelivery {
    let reserved = loop {
        let current = pending.load(Ordering::Relaxed);
        if current >= MESH_EVENT_QUEUE_PER_PEER {
            break false;
        }
        if pending
            .compare_exchange_weak(current, current + 1, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            break true;
        }
    };
    if !reserved {
        MESH_DROPPED_PACKETS.fetch_add(1, Ordering::Relaxed);
        tracing::debug!(peer_address = %address, "dropping inbound mesh packet because the peer event quota is full");
        return MeshPacketDelivery::Dropped;
    }
    let event = MeshEvent {
        address,
        result: Ok(packet),
        pending: Some(Arc::clone(pending)),
    };
    match sender.try_send(event) {
        Ok(()) => MeshPacketDelivery::Queued,
        Err(tokio::sync::mpsc::error::TrySendError::Full(event)) => {
            if let Some(pending) = event.pending {
                pending.fetch_sub(1, Ordering::Relaxed);
            }
            MESH_DROPPED_PACKETS.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(peer_address = %address, "dropping inbound mesh packet because the TUN event queue is full");
            MeshPacketDelivery::Dropped
        }
        Err(tokio::sync::mpsc::error::TrySendError::Closed(event)) => {
            if let Some(pending) = event.pending {
                pending.fetch_sub(1, Ordering::Relaxed);
            }
            MeshPacketDelivery::ReceiverClosed
        }
    }
}

fn release_mesh_event_quota(event: &MeshEvent) {
    if let Some(pending) = &event.pending {
        pending.fetch_sub(1, Ordering::Relaxed);
    }
}

fn try_queue_mesh_packet(
    sender: &tokio::sync::mpsc::Sender<QueuedMeshPacket>,
    address: Ipv4Addr,
    packet: Vec<u8>,
) -> MeshPacketDelivery {
    match sender.try_send(QueuedMeshPacket {
        payload: packet,
        queued_at: Instant::now(),
    }) {
        Ok(()) => MeshPacketDelivery::Queued,
        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
            MESH_DROPPED_PACKETS.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(peer_address = %address, "dropping outbound mesh packet because the peer send queue is full");
            MeshPacketDelivery::Dropped
        }
        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
            MeshPacketDelivery::ReceiverClosed
        }
    }
}

struct QueuedMeshPacket {
    payload: Vec<u8>,
    queued_at: Instant,
}

fn mesh_packet_expired(queued_at: Instant, now: Instant) -> bool {
    now.saturating_duration_since(queued_at) >= MESH_OUTBOUND_PACKET_TTL
}

fn discard_queued_mesh_packets(
    receiver: &mut tokio::sync::mpsc::Receiver<QueuedMeshPacket>,
    address: Ipv4Addr,
) -> usize {
    let mut dropped = 0_u64;
    while receiver.try_recv().is_ok() {
        dropped = dropped.saturating_add(1);
    }
    if dropped > 0 {
        MESH_DROPPED_PACKETS.fetch_add(dropped, Ordering::Relaxed);
        tracing::debug!(peer_address = %address, dropped, "discarding queued mesh packets after path failure");
    }
    usize::try_from(dropped).unwrap_or(usize::MAX)
}

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
    pub ipv6_address: Option<Ipv6Addr>,
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
    ipv6_address: Option<Ipv6Addr>,
    channel: Arc<tokio::sync::RwLock<Arc<PeerChannel>>>,
    connector: Option<PeerConnector>,
    probe: Option<PeerConnector>,
    probe_cooldown: Duration,
    pending_events: Arc<AtomicUsize>,
    outbound: tokio::sync::mpsc::Sender<QueuedMeshPacket>,
}

struct MeshPeerReceiver {
    address: Ipv4Addr,
    channel: Arc<tokio::sync::RwLock<Arc<PeerChannel>>>,
    connector: Option<PeerConnector>,
    probe: Option<PeerConnector>,
    probe_cooldown: Duration,
    pending_events: Arc<AtomicUsize>,
    outbound_rx: tokio::sync::mpsc::Receiver<QueuedMeshPacket>,
    event_tx: tokio::sync::mpsc::Sender<MeshEvent>,
    quality_interval: Duration,
}

fn new_mesh_peer_runtime(
    ipv6_address: Option<Ipv6Addr>,
    channel: Arc<PeerChannel>,
    connector: Option<PeerConnector>,
    probe: Option<PeerConnector>,
    probe_cooldown: Duration,
) -> (
    MeshPeerRuntime,
    tokio::sync::mpsc::Receiver<QueuedMeshPacket>,
) {
    let (outbound, outbound_rx) = tokio::sync::mpsc::channel(MESH_OUTBOUND_QUEUE_PER_PEER);
    (
        MeshPeerRuntime {
            ipv6_address,
            channel: Arc::new(tokio::sync::RwLock::new(channel)),
            connector,
            probe,
            probe_cooldown,
            pending_events: Arc::new(AtomicUsize::new(0)),
            outbound,
        },
        outbound_rx,
    )
}

struct MeshReceiverTasks(HashMap<Ipv4Addr, tokio::task::JoinHandle<()>>);

impl Deref for MeshReceiverTasks {
    type Target = HashMap<Ipv4Addr, tokio::task::JoinHandle<()>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for MeshReceiverTasks {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Drop for MeshReceiverTasks {
    fn drop(&mut self) {
        for task in self.0.values() {
            task.abort();
        }
    }
}

type MeshPeerInput = (
    Ipv4Addr,
    Option<Ipv6Addr>,
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
    #[error("multiple authenticated peers claim the same overlay IP address")]
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

    async fn write_inbound_ip_packet(
        &self,
        packet: &[u8],
        expected_peer_ipv4: Ipv4Addr,
        expected_peer_ipv6: Option<Ipv6Addr>,
    ) -> Result<(), TunError> {
        let (source, _) = crate::tun_device::packet_addresses(packet)?;
        match source {
            IpAddr::V4(source) if source == expected_peer_ipv4 => {
                self.write_inbound_packet(packet, expected_peer_ipv4).await
            }
            IpAddr::V6(source) if Some(source) == expected_peer_ipv6 => {
                Err(crate::tun_device::IpPacketError::UnexpectedSource.into())
            }
            _ => Err(crate::tun_device::IpPacketError::UnexpectedSource.into()),
        }
    }
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

    async fn write_inbound_ip_packet(
        &self,
        packet: &[u8],
        expected_peer_ipv4: Ipv4Addr,
        expected_peer_ipv6: Option<Ipv6Addr>,
    ) -> Result<(), TunError> {
        let (source, _) = crate::tun_device::packet_addresses(packet)?;
        let expected_peer = match source {
            IpAddr::V4(source) if source == expected_peer_ipv4 => IpAddr::V4(source),
            IpAddr::V6(source) if Some(source) == expected_peer_ipv6 => IpAddr::V6(source),
            _ => return Err(crate::tun_device::IpPacketError::UnexpectedSource.into()),
        };
        crate::tun_device::TunDevice::write_inbound_ip_packet(self, packet, expected_peer).await
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
    peer_ipv6: Option<Ipv6Addr>,
) -> Result<(), PeerTunnelError> {
    let mut keepalive = tokio::time::interval(Duration::from_secs(10));
    keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    keepalive.tick().await;
    let mut last_received = tokio::time::Instant::now();
    let mut inbound = Box::pin(peer.recv_packet());
    let outcome = loop {
        tokio::select! {
            _ = peer.wait_ice_consent_failure() => {
                break Err(IdentityError::Transport("ICE consent expired".to_owned()).into());
            }
            outbound = packet_io.read_outbound_packet() => {
                let packet = match outbound {
                    Ok(packet) => packet,
                    Err(TunError::InvalidPacket(_)) => continue,
                    Err(error) => break Err(error.into()),
                };
                if let Err(error) = peer.send_packet(&packet).await {
                    break Err(error.into());
                }
            }
            result = tokio::time::timeout_at(last_received + Duration::from_secs(30), &mut inbound) => {
                let packet = match result {
                    Ok(Ok(packet)) => packet,
                    Ok(Err(error)) => break Err(error.into()),
                    Err(_) => break Err(IdentityError::Transport("peer keepalive timed out".to_owned()).into()),
                };
                last_received = tokio::time::Instant::now();
                if !packet.is_empty()
                    && let Err(error) = packet_io
                        .write_inbound_ip_packet(&packet, peer_ipv4, peer_ipv6)
                        .await
                {
                    break Err(error.into());
                }
                inbound = Box::pin(peer.recv_packet());
            }
            _ = keepalive.tick() => {
                if let Err(error) = peer.send_keepalive().await {
                    break Err(error.into());
                }
            },
        }
    };
    peer.stop_ice_consent_monitor().await;
    outcome
}

async fn receive_mesh_peer(receiver: MeshPeerReceiver) {
    let MeshPeerReceiver {
        address,
        channel,
        connector,
        probe,
        probe_cooldown,
        pending_events,
        mut outbound_rx,
        event_tx,
        quality_interval,
    } = receiver;
    loop {
        let active = Arc::clone(&*channel.read().await);
        let mut keepalive = tokio::time::interval(quality_interval);
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
                            if !packet.is_empty()
                                && try_deliver_mesh_packet(&event_tx, address, packet, &pending_events)
                                    == MeshPacketDelivery::ReceiverClosed
                            {
                                return;
                            }
                        }
                        Err(error) => break Err(error),
                    }
                }
                _ = active.wait_ice_consent_failure() => {
                    break Err(IdentityError::Transport("ICE consent expired".to_owned()));
                }
                outbound = outbound_rx.recv() => {
                    let Some(packet) = outbound else { return };
                    if mesh_packet_expired(packet.queued_at, Instant::now()) {
                        MESH_DROPPED_PACKETS.fetch_add(1, Ordering::Relaxed);
                        tracing::debug!(peer_address = %address, "dropping expired queued mesh packet");
                        continue;
                    }
                    if let Err(error) = active.send_packet(&packet.payload).await {
                        break Err(error);
                    }
                }
                _ = keepalive.tick() => {
                    let health = active.health_snapshot();
                    if active.transport_name() == "QUIC/UDP" && quality.observe(health) {
                        tracing::warn!(
                            peer_address = %address,
                            path = active.transport_name(),
                            rtt_ms = health.rtt.map(|rtt| rtt.as_millis() as u64),
                            probes_succeeded = health.probes_succeeded,
                            probes_missed = health.probes_missed,
                            reason = "quality_threshold",
                            "peer path quality degraded; switching to reliable fallback"
                        );
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
                        let previous_path = active.transport_name();
                        let promoted_path = candidate.transport_name();
                        tracing::info!(
                            peer_address = %address,
                            from_path = previous_path,
                            to_path = promoted_path,
                            reason = "healthy_direct_probe",
                            "peer path promoted"
                        );
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
            Ok(()) => {
                active.stop_ice_consent_monitor().await;
                continue;
            }
            Err(failure) => failure,
        };
        active.stop_ice_consent_monitor().await;
        discard_queued_mesh_packets(&mut outbound_rx, address);
        if active.transport_name() == "QUIC/UDP" && matches!(&failure, IdentityError::Transport(_))
        {
            force_reliable = true;
        }
        tracing::warn!(
            peer_address = %address,
            path = active.transport_name(),
            reason = %failure,
            reliable_fallback = force_reliable,
            "peer path failed; reconnecting"
        );
        if connector.is_none() {
            let _ = event_tx
                .send(MeshEvent {
                    address,
                    result: Err(failure),
                    pending: None,
                })
                .await;
            return;
        }
        let connector = connector.as_ref().expect("checked above");
        let mut attempt = 0_u32;
        loop {
            tokio::time::sleep(crate::reconnect_delay(attempt)).await;
            attempt = attempt.saturating_add(1);
            match (connector)(force_reliable).await {
                Ok(reconnected) => {
                    tracing::info!(
                        peer_address = %address,
                        from_path = active.transport_name(),
                        to_path = reconnected.transport_name(),
                        attempt,
                        reliable_fallback = force_reliable,
                        "peer path reconnected"
                    );
                    *channel.write().await = Arc::new(reconnected);
                    break;
                }
                Err(IdentityError::UnauthorizedPeer) => {
                    tracing::error!(
                        peer_address = %address,
                        attempt,
                        "peer identity authorization failed during reconnect"
                    );
                    let _ = event_tx
                        .send(MeshEvent {
                            address,
                            result: Err(IdentityError::UnauthorizedPeer),
                            pending: None,
                        })
                        .await;
                    return;
                }
                Err(error) => {
                    tracing::warn!(
                        peer_address = %address,
                        attempt,
                        error = %error,
                        "peer reconnect attempt failed"
                    );
                }
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
            .map(|(address, channel)| {
                (
                    address,
                    None,
                    channel,
                    None,
                    None,
                    Duration::from_secs(3600),
                )
            })
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
                    peer.ipv6_address,
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
                    peer.ipv6_address,
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
    updates: Option<tokio::sync::mpsc::Receiver<MeshPeerUpdate>>,
) -> Result<(), PeerTunnelError> {
    pump_mesh_with_quality_interval(packet_io, peers, updates, Duration::from_secs(10)).await
}

async fn pump_mesh_with_quality_interval<T: TunnelPacketIo>(
    packet_io: &T,
    peers: Vec<MeshPeerInput>,
    mut updates: Option<tokio::sync::mpsc::Receiver<MeshPeerUpdate>>,
    quality_interval: Duration,
) -> Result<(), PeerTunnelError> {
    if peers.is_empty() && updates.is_none() {
        return Err(PeerTunnelError::NoPeers);
    }
    let mut channels = HashMap::with_capacity(peers.len());
    let mut outbound_receivers = HashMap::with_capacity(peers.len());
    let mut ipv6_routes = HashMap::new();
    for (address, ipv6_address, channel, connector, probe, probe_cooldown) in peers {
        if let Some(ipv6_address) = ipv6_address
            && ipv6_routes.insert(ipv6_address, address).is_some()
        {
            return Err(PeerTunnelError::DuplicatePeerAddress);
        }
        let (runtime, outbound_rx) =
            new_mesh_peer_runtime(ipv6_address, channel, connector, probe, probe_cooldown);
        if channels.insert(address, runtime).is_some() {
            return Err(PeerTunnelError::DuplicatePeerAddress);
        }
        outbound_receivers.insert(address, outbound_rx);
    }

    let (event_tx, mut event_rx) =
        tokio::sync::mpsc::channel(mesh_event_queue_capacity(channels.len()));
    let mut receivers = MeshReceiverTasks(HashMap::with_capacity(channels.len()));
    for (&address, runtime) in &channels {
        let outbound_rx = outbound_receivers
            .remove(&address)
            .expect("every initial peer has an outbound queue");
        receivers.insert(
            address,
            spawn_mesh_receiver(
                address,
                runtime,
                outbound_rx,
                event_tx.clone(),
                quality_interval,
            ),
        );
    }

    while !channels.is_empty() || updates.is_some() {
        tokio::select! {
            outbound = packet_io.read_outbound_packet() => {
                let packet = match outbound {
                    Ok(packet) => packet,
                    Err(TunError::InvalidPacket(_)) => continue,
                    Err(error) => return Err(error.into()),
                };
                let Ok((_, destination)) = crate::tun_device::packet_addresses(&packet) else {
                    continue;
                };
                let peer_key = match destination {
                    IpAddr::V4(address) => Some(address),
                    IpAddr::V6(address) => ipv6_routes.get(&address).copied(),
                };
                if let Some(peer_key) = peer_key
                    && let Some(runtime) = channels.get(&peer_key)
                    && try_queue_mesh_packet(&runtime.outbound, peer_key, packet)
                        == MeshPacketDelivery::ReceiverClosed
                {
                    tracing::debug!(peer_address = %peer_key, "dropping packet because the peer send task stopped");
                }
            }
            inbound = event_rx.recv() => {
                let Some(event) = inbound else {
                    return Err(PeerTunnelError::NoPeers);
                };
                release_mesh_event_quota(&event);
                let address = event.address;
                let result = event.result;
                match result {
                    Ok(packet) => {
                        let Some(runtime) = channels.get(&address) else { continue };
                        match packet_io.write_inbound_ip_packet(
                            &packet,
                            address,
                            runtime.ipv6_address,
                        ).await {
                        Ok(()) | Err(TunError::InvalidPacket(_)) => {}
                        Err(error) => return Err(error.into()),
                        }
                    }
                    Err(_) => {
                        if let Some(runtime) = channels.remove(&address) {
                            if let Some(ipv6_address) = runtime.ipv6_address {
                                ipv6_routes.remove(&ipv6_address);
                            }
                            Arc::clone(&*runtime.channel.read().await)
                                .close_async()
                                .await;
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
                        if channels.contains_key(&address)
                            || peer.ipv6_address.is_some_and(|ipv6| ipv6_routes.contains_key(&ipv6))
                        {
                            peer.channel.close_async().await;
                            return Err(PeerTunnelError::DuplicatePeerAddress);
                        }
                        if let Some(ipv6_address) = peer.ipv6_address {
                            ipv6_routes.insert(ipv6_address, address);
                        }
                        if channels.contains_key(&address) {
                            peer.channel.close_async().await;
                            continue;
                        }
                        let (runtime, outbound_rx) = new_mesh_peer_runtime(
                            peer.ipv6_address,
                            peer.channel,
                            Some(peer.connector),
                            peer.probe,
                            peer.probe_cooldown,
                        );
                        receivers.insert(
                            address,
                            spawn_mesh_receiver(
                                address,
                                &runtime,
                                outbound_rx,
                                event_tx.clone(),
                                quality_interval,
                            ),
                        );
                        channels.insert(address, runtime);
                    }
                    Some(MeshPeerUpdate::Remove(address)) => {
                        if let Some(runtime) = channels.remove(&address) {
                            if let Some(ipv6_address) = runtime.ipv6_address {
                                ipv6_routes.remove(&ipv6_address);
                            }
                            Arc::clone(&*runtime.channel.read().await)
                                .close_async()
                                .await;
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
    for task in receivers.values() {
        task.abort();
    }
    Err(PeerTunnelError::NoPeers)
}

fn spawn_mesh_receiver(
    address: Ipv4Addr,
    runtime: &MeshPeerRuntime,
    outbound_rx: tokio::sync::mpsc::Receiver<QueuedMeshPacket>,
    event_tx: tokio::sync::mpsc::Sender<MeshEvent>,
    quality_interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(receive_mesh_peer(MeshPeerReceiver {
        address,
        channel: Arc::clone(&runtime.channel),
        connector: runtime.connector.clone(),
        probe: runtime.probe.clone(),
        probe_cooldown: runtime.probe_cooldown,
        pending_events: Arc::clone(&runtime.pending_events),
        outbound_rx,
        event_tx,
        quality_interval,
    }))
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

    #[cfg(target_os = "linux")]
    struct TestVethPair {
        left: String,
        right: String,
        loss_active: bool,
    }

    #[cfg(target_os = "linux")]
    impl TestVethPair {
        fn create() -> (Self, SocketAddr, SocketAddr) {
            fn run(command: &str, args: &[&str]) {
                let output = std::process::Command::new(command)
                    .args(args)
                    .output()
                    .unwrap_or_else(|error| panic!("run {command}: {error}"));
                assert!(
                    output.status.success(),
                    "{command} {args:?} failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }

            let pid = std::process::id();
            let left = format!("mtl{}", pid % 10_000_000);
            let right = format!("mtr{}", pid % 10_000_000);
            let subnet = (pid % 250 + 1) as u8;
            let local: SocketAddr = format!("198.18.{subnet}.1:0").parse().unwrap();
            let remote: SocketAddr = format!("198.18.{subnet}.2:0").parse().unwrap();
            run(
                "ip",
                &["link", "add", &left, "type", "veth", "peer", "name", &right],
            );
            let pair = Self {
                left: left.clone(),
                right: right.clone(),
                loss_active: false,
            };
            run(
                "ip",
                &[
                    "address",
                    "add",
                    &format!("198.18.{subnet}.1/30"),
                    "dev",
                    &left,
                ],
            );
            run(
                "ip",
                &[
                    "address",
                    "add",
                    &format!("198.18.{subnet}.2/30"),
                    "dev",
                    &right,
                ],
            );
            run("ip", &["link", "set", "dev", &left, "up"]);
            run("ip", &["link", "set", "dev", &right, "up"]);
            (pair, local, remote)
        }

        fn set_mtu(&self, mtu: &str) {
            for device in [&self.left, &self.right] {
                let output = std::process::Command::new("ip")
                    .args(["link", "set", "dev", device, "mtu", mtu])
                    .output()
                    .expect("set veth MTU");
                assert!(
                    output.status.success(),
                    "could not set veth MTU: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }

        fn drop_left_egress(&mut self) {
            let output = std::process::Command::new("tc")
                .args([
                    "qdisc", "replace", "dev", &self.left, "root", "netem", "loss", "100%",
                ])
                .output()
                .expect("run tc to drop QUIC datagrams on veth egress");
            assert!(
                output.status.success(),
                "tc netem loss failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            self.loss_active = true;
        }

        fn restore_left_egress(&mut self) {
            if !self.loss_active {
                return;
            }
            let output = std::process::Command::new("tc")
                .args(["qdisc", "del", "dev", &self.left, "root"])
                .output()
                .expect("remove tc loss qdisc from veth egress");
            assert!(
                output.status.success(),
                "could not remove tc loss qdisc: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            self.loss_active = false;
        }
    }

    #[cfg(target_os = "linux")]
    impl Drop for TestVethPair {
        fn drop(&mut self) {
            let _ = std::process::Command::new("tc")
                .args(["qdisc", "del", "dev", &self.left, "root"])
                .output();
            let _ = std::process::Command::new("ip")
                .args(["link", "del", "dev", &self.left])
                .output();
        }
    }

    #[test]
    fn mesh_event_queue_capacity_is_bounded_at_maximum_network_size() {
        assert_eq!(mesh_event_queue_capacity(0), MESH_EVENT_QUEUE_PER_PEER);
        assert_eq!(mesh_event_queue_capacity(1), MESH_EVENT_QUEUE_PER_PEER);
        assert_eq!(mesh_event_queue_capacity(4), 32);
        assert_eq!(
            mesh_event_queue_capacity(4096),
            MAX_MESH_EVENT_QUEUE_CAPACITY
        );
        assert_eq!(
            MAX_MESH_EVENT_QUEUE_CAPACITY * crate::MAX_TUN_PACKET,
            9_216_000
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires root privileges, iproute2, and tc netem"]
    async fn privileged_linux_veth_quic_probe_loss_and_recovery() {
        let (mut link, local_address, remote_address) = TestVethPair::create();
        let temp =
            std::env::temp_dir().join(format!("mini-tunnel-veth-loss-{}", uuid::Uuid::new_v4()));
        let identity_a = Identity::load_or_create_at(temp.join("a/device.key")).unwrap();
        let identity_b = Identity::load_or_create_at(temp.join("b/device.key")).unwrap();
        let endpoint_a = peer_endpoint(&identity_a, local_address).expect("endpoint A");
        let endpoint_b = peer_endpoint(&identity_b, remote_address).expect("endpoint B");
        let peer_id = identity_a.device_id();
        let peer_key = identity_a.public_key();
        let accept_endpoint = endpoint_b.clone();
        let accept_identity = Arc::new(identity_b);
        let accept_peer_identity = Arc::clone(&accept_identity);
        let accept = tokio::spawn(async move {
            accept_peer(
                &accept_endpoint,
                "veth-loss-test",
                &accept_peer_identity,
                &peer_id,
                peer_key,
            )
            .await
        });
        let channel_a = connect_peer(
            &endpoint_a,
            endpoint_b.local_addr().expect("endpoint B socket address"),
            "veth-loss-test",
            &identity_a,
            &accept_identity.device_id(),
            accept_identity.public_key(),
        )
        .await
        .expect("establish QUIC over veth before loss");
        let channel_b = accept
            .await
            .expect("join accept task")
            .expect("accept peer");
        assert_eq!(channel_a.transport_name(), "QUIC/UDP");
        let (received_tx, mut received_rx) = mpsc::channel(1);
        let responder = Arc::new(channel_b);
        let responder_task = {
            let responder = Arc::clone(&responder);
            tokio::spawn(async move {
                while let Ok(packet) = responder.recv_packet().await {
                    if !packet.is_empty() && received_tx.send(packet).await.is_err() {
                        break;
                    }
                }
            })
        };
        let missed_before = channel_a.health_snapshot().probes_missed;
        link.drop_left_egress();
        for _ in 0..24 {
            channel_a
                .send_keepalive()
                .await
                .expect("QUIC accepts probe before network egress loss");
            if channel_a.health_snapshot().probes_missed > missed_before {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        let lost = channel_a.health_snapshot();
        assert!(
            lost.probes_missed > missed_before,
            "real veth loss did not increase missed probes: {lost:?}"
        );
        link.restore_left_egress();

        let succeeded_before = channel_a.health_snapshot().probes_succeeded;
        channel_a
            .probe_health(3, Duration::from_secs(2))
            .await
            .expect("authenticated probes recover after removing network loss");
        let recovered = channel_a.health_snapshot();
        assert!(recovered.probes_succeeded >= succeeded_before + 3);
        assert_eq!(channel_a.transport_name(), "QUIC/UDP");

        link.set_mtu("1280");
        let large_packet = (0..crate::MAX_TUN_PACKET)
            .map(|byte| (byte % 251) as u8)
            .collect::<Vec<_>>();
        channel_a
            .send_packet(&large_packet)
            .await
            .expect("fragment maximum-sized overlay packet after reducing veth MTU");
        let received = tokio::time::timeout(Duration::from_secs(3), received_rx.recv())
            .await
            .expect("receive reassembled packet over constrained veth")
            .expect("responder receives reassembled packet");
        assert_eq!(received, large_packet);

        responder_task.abort();
        endpoint_a.close(0_u32.into(), b"veth test complete");
        endpoint_b.close(0_u32.into(), b"veth test complete");
        drop(link);
        fs::remove_dir_all(temp).expect("remove test identities");
    }

    #[tokio::test]
    async fn mesh_packet_delivery_drops_on_full_queue_and_reports_closed_receiver() {
        let address = Ipv4Addr::new(10, 77, 0, 2);
        let (sender, mut receiver) = mpsc::channel(16);
        let peer_a_pending = Arc::new(AtomicUsize::new(0));
        let peer_b_pending = Arc::new(AtomicUsize::new(0));
        let before = mesh_dropped_packets_total();

        for packet in 0..MESH_EVENT_QUEUE_PER_PEER {
            assert_eq!(
                try_deliver_mesh_packet(&sender, address, vec![packet as u8], &peer_a_pending),
                MeshPacketDelivery::Queued
            );
        }
        assert_eq!(
            try_deliver_mesh_packet(&sender, address, vec![99], &peer_a_pending),
            MeshPacketDelivery::Dropped
        );
        assert!(mesh_dropped_packets_total() > before);
        assert_eq!(
            peer_a_pending.load(Ordering::Relaxed),
            MESH_EVENT_QUEUE_PER_PEER
        );
        assert_eq!(
            try_deliver_mesh_packet(
                &sender,
                Ipv4Addr::new(10, 77, 0, 3),
                vec![10],
                &peer_b_pending,
            ),
            MeshPacketDelivery::Queued,
            "another peer still gets queue capacity during peer A's burst"
        );
        assert_eq!(peer_b_pending.load(Ordering::Relaxed), 1);
        let first = receiver.recv().await.expect("queued event");
        assert_eq!(
            first.result.as_ref().expect("queued packet payload"),
            &vec![0]
        );
        release_mesh_event_quota(&first);
        assert_eq!(
            peer_a_pending.load(Ordering::Relaxed),
            MESH_EVENT_QUEUE_PER_PEER - 1
        );
        assert_eq!(
            try_deliver_mesh_packet(&sender, address, vec![11], &peer_a_pending),
            MeshPacketDelivery::Queued,
            "consuming an event releases capacity for its peer"
        );

        drop(receiver);
        let peer_c_pending = Arc::new(AtomicUsize::new(0));
        assert_eq!(
            try_deliver_mesh_packet(&sender, address, vec![4], &peer_c_pending),
            MeshPacketDelivery::ReceiverClosed
        );

        let (small_sender, _small_receiver) = mpsc::channel(1);
        let small_peer_a_pending = Arc::new(AtomicUsize::new(0));
        let global_full_pending = Arc::new(AtomicUsize::new(0));
        assert_eq!(
            try_deliver_mesh_packet(&small_sender, address, vec![5], &small_peer_a_pending),
            MeshPacketDelivery::Queued
        );
        assert_eq!(
            try_deliver_mesh_packet(
                &small_sender,
                Ipv4Addr::new(10, 77, 0, 3),
                vec![6],
                &global_full_pending,
            ),
            MeshPacketDelivery::Dropped
        );
        assert_eq!(global_full_pending.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn mesh_outbound_queue_isolates_a_full_peer_queue() {
        let peer_a = Ipv4Addr::new(10, 77, 0, 2);
        let peer_b = Ipv4Addr::new(10, 77, 0, 3);
        let (slow_sender, mut slow_receiver) = mpsc::channel(MESH_OUTBOUND_QUEUE_PER_PEER);
        let (fast_sender, mut fast_receiver) = mpsc::channel(MESH_OUTBOUND_QUEUE_PER_PEER);
        let before = mesh_dropped_packets_total();

        assert_eq!(
            try_queue_mesh_packet(&slow_sender, peer_a, vec![1]),
            MeshPacketDelivery::Queued
        );
        assert_eq!(
            try_queue_mesh_packet(&slow_sender, peer_a, vec![2]),
            MeshPacketDelivery::Dropped
        );
        assert!(mesh_dropped_packets_total() > before);
        assert_eq!(
            try_queue_mesh_packet(&fast_sender, peer_b, vec![3]),
            MeshPacketDelivery::Queued,
            "a slow peer's full queue does not consume another peer's capacity"
        );
        assert_eq!(
            fast_receiver
                .recv()
                .await
                .expect("fast peer packet")
                .payload,
            vec![3]
        );
        assert_eq!(
            slow_receiver
                .recv()
                .await
                .expect("slow peer packet")
                .payload,
            vec![1]
        );
    }

    #[test]
    fn queued_mesh_packets_expire_after_the_recovery_window() {
        let now = Instant::now();
        assert!(!mesh_packet_expired(now, now));
        assert!(mesh_packet_expired(
            now.checked_sub(MESH_OUTBOUND_PACKET_TTL)
                .expect("subtract packet lifetime"),
            now
        ));
    }

    #[tokio::test]
    async fn path_failure_discards_already_queued_mesh_packets() {
        let address = Ipv4Addr::new(10, 77, 0, 2);
        let (sender, mut receiver) = mpsc::channel(MESH_OUTBOUND_QUEUE_PER_PEER);
        let before = mesh_dropped_packets_total();
        assert_eq!(
            try_queue_mesh_packet(&sender, address, vec![1]),
            MeshPacketDelivery::Queued
        );
        assert_eq!(discard_queued_mesh_packets(&mut receiver, address), 1);
        assert!(receiver.try_recv().is_err());
        assert!(mesh_dropped_packets_total() > before);
    }

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

    #[test]
    fn path_quality_uses_packet_loss_threshold_with_three_window_hysteresis() {
        let mut tracker = PathQualityTracker::default();
        let mut snapshot = crate::PeerHealthSnapshot {
            rtt: Some(Duration::from_millis(50)),
            probes_succeeded: 0,
            probes_missed: 0,
        };

        // Exactly 20% loss is not above the configured degradation threshold.
        snapshot.probes_succeeded += 4;
        snapshot.probes_missed += 1;
        assert!(!tracker.observe(snapshot));

        // 1/3 loss is poor, but must persist for three consecutive windows.
        for window in 0..2 {
            snapshot.probes_succeeded += 2;
            snapshot.probes_missed += 1;
            assert!(
                !tracker.observe(snapshot),
                "packet loss window {window} must not trigger a switch"
            );
        }

        // One healthy window clears the accumulated bad-window count.
        snapshot.probes_succeeded += 5;
        assert!(!tracker.observe(snapshot));

        for window in 0..2 {
            snapshot.probes_succeeded += 2;
            snapshot.probes_missed += 1;
            assert!(
                !tracker.observe(snapshot),
                "packet loss window {window} after reset must not trigger a switch"
            );
        }
        snapshot.probes_succeeded += 2;
        snapshot.probes_missed += 1;
        assert!(tracker.observe(snapshot));
    }

    #[tokio::test]
    async fn mesh_switches_to_tcp_after_sustained_udp_quality_degradation() {
        let temp = std::env::temp_dir().join(format!(
            "mini-tunnel-quality-fallback-{}",
            uuid::Uuid::new_v4()
        ));
        let a = Arc::new(Identity::load_or_create_at(temp.join("a/key")).unwrap());
        let b = Arc::new(Identity::load_or_create_at(temp.join("b/key")).unwrap());
        let endpoint_a =
            peer_endpoint(&a, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap();
        let endpoint_b =
            peer_endpoint(&b, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap();
        let network = "mesh-quality-fallback";
        let peer_socket = endpoint_b.local_addr().unwrap();
        let a_id = a.device_id();
        let a_key = a.public_key();
        let b_id = b.device_id();
        let b_key = b.public_key();
        let server_endpoint = endpoint_b.clone();
        let server_identity = Arc::clone(&b);
        let accept_udp = tokio::spawn(async move {
            accept_peer(&server_endpoint, network, &server_identity, &a_id, a_key).await
        });
        let initial = Arc::new(
            connect_peer(&endpoint_a, peer_socket, network, &a, &b_id, b_key)
                .await
                .unwrap(),
        );
        let remote_initial = accept_udp.await.unwrap().unwrap();
        // Seed a high-RTT window, then drive >20% loss with healthy RTT so recovery covers both
        // quality signals without waiting through production's 90-second hysteresis.
        {
            let mut health = initial.health.lock().unwrap();
            health.rtt = Some(Duration::from_millis(500));
            health.probes_succeeded = 3;
        }

        let tcp_listener = peer_tcp_listener(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .unwrap();
        let tcp_address = tcp_listener.local_addr().unwrap();
        let allowed = vec![(a.device_id(), a.public_key())];
        let accept_identity = Arc::clone(&b);
        let accept_tcp = tokio::spawn(async move {
            accept_tcp_peer_any(&tcp_listener, network, &accept_identity, &allowed).await
        });
        let requested_reliable = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let connector: PeerConnector = {
            let a = Arc::clone(&a);
            let b_id = b.device_id();
            let b_key = b.public_key();
            let requested_reliable = Arc::clone(&requested_reliable);
            Arc::new(move |force_reliable| -> PeerConnectFuture {
                let a = Arc::clone(&a);
                let b_id = b_id.clone();
                let requested_reliable = Arc::clone(&requested_reliable);
                Box::pin(async move {
                    requested_reliable.store(force_reliable, Ordering::SeqCst);
                    connect_tcp_peer(tcp_address, network, &a, &b_id, b_key).await
                })
            })
        };

        let local_ip = Ipv4Addr::new(10, 0, 0, 1);
        let peer_ip = Ipv4Addr::new(10, 0, 0, 2);
        let (outbound_tx, outbound_rx) = mpsc::channel(2);
        let (inbound_tx, _inbound_rx) = mpsc::channel(2);
        let io = MockPacketIo {
            outbound: Mutex::new(outbound_rx),
            inbound: inbound_tx,
            local_ipv4: local_ip,
            local_ipv6: None,
            mtu: 1500,
        };
        let health_channel = Arc::clone(&initial);
        let health_driver = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(150)).await;
            if let Ok(mut health) = health_channel.health.lock() {
                health.rtt = Some(Duration::from_millis(50));
            }
            for _ in 0..32 {
                tokio::time::sleep(Duration::from_millis(20)).await;
                if let Ok(mut health) = health_channel.health.lock() {
                    health.probes_succeeded = health.probes_succeeded.saturating_add(2);
                    health.probes_missed = health.probes_missed.saturating_add(1);
                }
            }
        });
        let pump = tokio::spawn(async move {
            pump_mesh_with_quality_interval(
                &io,
                vec![(
                    peer_ip,
                    None,
                    initial,
                    Some(connector),
                    None,
                    Duration::from_secs(3600),
                )],
                None,
                Duration::from_millis(100),
            )
            .await
        });

        let recovered_remote = tokio::time::timeout(Duration::from_secs(4), accept_tcp)
            .await
            .expect("quality fallback did not establish TCP")
            .unwrap()
            .unwrap()
            .1;
        assert!(requested_reliable.load(Ordering::SeqCst));
        outbound_tx
            .send(packet(local_ip, peer_ip, 28))
            .await
            .unwrap();
        let forwarded =
            tokio::time::timeout(Duration::from_secs(3), recovered_remote.recv_packet())
                .await
                .expect("recovered TCP path did not forward the packet")
                .unwrap();
        assert_eq!(forwarded, packet(local_ip, peer_ip, 28));

        health_driver.abort();
        pump.abort();
        endpoint_a.close(0_u32.into(), b"test complete");
        endpoint_b.close(0_u32.into(), b"test complete");
        drop(recovered_remote);
        drop(remote_initial);
        fs::remove_dir_all(temp).unwrap();
    }

    struct MockPacketIo {
        outbound: Mutex<mpsc::Receiver<Vec<u8>>>,
        inbound: mpsc::Sender<Vec<u8>>,
        local_ipv4: Ipv4Addr,
        local_ipv6: Option<Ipv6Addr>,
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
            crate::tun_device::validate_outbound_packet(
                &packet,
                self.local_ipv4,
                self.local_ipv6,
                self.mtu,
            )?;
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

        async fn write_inbound_ip_packet(
            &self,
            packet: &[u8],
            expected_peer_ipv4: Ipv4Addr,
            expected_peer_ipv6: Option<Ipv6Addr>,
        ) -> Result<(), TunError> {
            let expected_peer = match crate::tun_device::packet_addresses(packet)?.0 {
                IpAddr::V4(address) if address == expected_peer_ipv4 => IpAddr::V4(address),
                IpAddr::V6(address) if Some(address) == expected_peer_ipv6 => IpAddr::V6(address),
                _ => return Err(crate::tun_device::IpPacketError::UnexpectedSource.into()),
            };
            crate::tun_device::validate_inbound_packet(
                packet,
                IpAddr::V4(self.local_ipv4),
                self.local_ipv6.map(IpAddr::V6),
                expected_peer,
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

    fn ipv6_packet(source: Ipv6Addr, destination: Ipv6Addr, payload_length: usize) -> Vec<u8> {
        let mut packet = vec![0; 40 + payload_length];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(payload_length as u16).to_be_bytes());
        packet[6] = 17;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&source.octets());
        packet[24..40].copy_from_slice(&destination.octets());
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
        let local_ipv6: Ipv6Addr = "fd00::1".parse().unwrap();
        let peer_ipv6: Ipv6Addr = "fd00::2".parse().unwrap();
        let (outbound_tx, outbound_rx) = mpsc::channel(4);
        let (inbound_tx, _inbound_rx) = mpsc::channel(4);
        let io = Arc::new(MockPacketIo {
            outbound: Mutex::new(outbound_rx),
            inbound: inbound_tx,
            local_ipv4: local_ip,
            local_ipv6: Some(local_ipv6),
            mtu: 1500,
        });
        let pump_io = Arc::clone(&io);
        let pump = tokio::spawn(async move {
            pump_peer_mesh_reconnecting(
                &*pump_io,
                vec![ReconnectingPeer {
                    address: peer_ip,
                    ipv6_address: Some(peer_ipv6),
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
        let outbound_ipv6 = ipv6_packet(local_ipv6, peer_ipv6, 8);
        outbound_tx.send(outbound_ipv6.clone()).await.unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(3), recovered.recv_packet())
                .await
                .unwrap()
                .unwrap(),
            outbound_ipv6
        );
        pump.abort();
        drop(recovered);
        fs::remove_dir_all(temp).unwrap();
    }

    #[tokio::test]
    async fn mesh_uses_reliable_fallback_after_ice_consent_expiry() {
        async fn tcp_pair(a: Arc<Identity>, b: Arc<Identity>) -> (PeerChannel, PeerChannel) {
            let listener = peer_tcp_listener(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
                .await
                .unwrap();
            let address = listener.local_addr().unwrap();
            let allowed = vec![(a.device_id(), a.public_key())];
            let peer_id = b.device_id();
            let accept = accept_tcp_peer_any(&listener, "mesh-udp-fallback", &b, &allowed);
            let connect =
                connect_tcp_peer(address, "mesh-udp-fallback", &a, &peer_id, b.public_key());
            let (accepted, connected) = tokio::join!(accept, connect);
            (connected.unwrap(), accepted.unwrap().1)
        }

        let temp = std::env::temp_dir().join(format!(
            "mini-tunnel-mesh-udp-fallback-{}",
            uuid::Uuid::new_v4()
        ));
        let a = Arc::new(Identity::load_or_create_at(temp.join("a/key")).unwrap());
        let b = Arc::new(Identity::load_or_create_at(temp.join("b/key")).unwrap());
        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let endpoint_a = peer_endpoint(&a, bind).unwrap();
        let endpoint_b = peer_endpoint(&b, bind).unwrap();
        let a_id = a.device_id();
        let a_key = a.public_key();
        let b_id = b.device_id();
        let b_key = b.public_key();
        let server_endpoint = endpoint_b.clone();
        let server_identity = Arc::clone(&b);
        let accept = tokio::spawn(async move {
            accept_peer(
                &server_endpoint,
                "mesh-udp-fallback",
                &server_identity,
                &a_id,
                a_key,
            )
            .await
        });
        let mut initial = connect_peer(
            &endpoint_a,
            endpoint_b.local_addr().unwrap(),
            "mesh-udp-fallback",
            &a,
            &b_id,
            b_key,
        )
        .await
        .unwrap();
        let _remote_initial = accept.await.unwrap().unwrap();
        let (monitor, mut cancel, consent_failed) = crate::ice::IceConsentMonitor::new();
        monitor
            .set_task(tokio::spawn(async move {
                let _ = cancel.changed().await;
            }))
            .await;
        initial.set_ice_consent_monitor(monitor);

        let reliable_requested = Arc::new(Mutex::new(None));
        let reliable_notify = Arc::new(tokio::sync::Notify::new());
        let remote_channel = Arc::new(Mutex::new(None));
        let connector: PeerConnector = {
            let a = Arc::clone(&a);
            let b = Arc::clone(&b);
            let reliable_requested = Arc::clone(&reliable_requested);
            let reliable_notify = Arc::clone(&reliable_notify);
            let remote_channel = Arc::clone(&remote_channel);
            Arc::new(move |force_reliable| -> PeerConnectFuture {
                let a = Arc::clone(&a);
                let b = Arc::clone(&b);
                let reliable_requested = Arc::clone(&reliable_requested);
                let reliable_notify = Arc::clone(&reliable_notify);
                let remote_channel = Arc::clone(&remote_channel);
                Box::pin(async move {
                    *reliable_requested.lock().await = Some(force_reliable);
                    reliable_notify.notify_one();
                    let (local, remote) = tcp_pair(a, b).await;
                    *remote_channel.lock().await = Some(remote);
                    Ok(local)
                })
            })
        };
        let local_ip = Ipv4Addr::new(10, 80, 0, 1);
        let peer_ip = Ipv4Addr::new(10, 80, 0, 2);
        let (outbound_tx, outbound_rx) = mpsc::channel(4);
        let (inbound_tx, _inbound_rx) = mpsc::channel(4);
        let io = Arc::new(MockPacketIo {
            outbound: Mutex::new(outbound_rx),
            inbound: inbound_tx,
            local_ipv4: local_ip,
            local_ipv6: None,
            mtu: 1500,
        });
        let pump_io = Arc::clone(&io);
        let pump = tokio::spawn(async move {
            pump_peer_mesh_reconnecting(
                &*pump_io,
                vec![ReconnectingPeer {
                    address: peer_ip,
                    ipv6_address: None,
                    channel: Arc::new(initial),
                    connector,
                    probe: None,
                    probe_cooldown: Duration::from_secs(3600),
                }],
            )
            .await
        });
        consent_failed.send_replace(true);
        tokio::time::timeout(Duration::from_secs(3), reliable_notify.notified())
            .await
            .expect("reconnect requested");
        assert_eq!(*reliable_requested.lock().await, Some(true));

        let recovered = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if let Some(channel) = remote_channel.lock().await.take() {
                    break channel;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("reliable peer channel established");
        assert_eq!(recovered.transport_name(), "TLS/TCP");
        outbound_tx
            .send(packet(local_ip, peer_ip, 28))
            .await
            .unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(3), recovered.recv_packet())
                .await
                .unwrap()
                .unwrap()
                .len(),
            28
        );

        pump.abort();
        recovered.close_async().await;
        endpoint_a.close(0_u32.into(), b"test complete");
        endpoint_b.close(0_u32.into(), b"test complete");
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
            local_ipv6: None,
            mtu: 1500,
        });
        let pump_io = Arc::clone(&io);
        let pump = tokio::spawn(async move {
            pump_peer_mesh_reconnecting(
                &*pump_io,
                vec![ReconnectingPeer {
                    address: peer_ip,
                    ipv6_address: None,
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
            local_ipv6: None,
            mtu: 1150,
        };
        let io_b = MockPacketIo {
            outbound: Mutex::new(b_out_rx),
            inbound: b_in_tx,
            local_ipv4: b_ip,
            local_ipv6: None,
            mtu: 1150,
        };
        let pump_a =
            tokio::spawn(async move { pump_peer_packets(&io_a, &channel_a, b_ip, None).await });
        let pump_b =
            tokio::spawn(async move { pump_peer_packets(&io_b, &channel_b, a_ip, None).await });

        a_out_tx
            .send(packet(b_ip, b_ip, 28))
            .await
            .expect("inject invalid source packet");
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
        let a_ipv6: Ipv6Addr = "fd88::2".parse().unwrap();
        let b_ipv6: Ipv6Addr = "fd88::3".parse().unwrap();
        let c_ipv6: Ipv6Addr = "fd88::4".parse().unwrap();
        let (outbound_tx, outbound_rx) = mpsc::channel(8);
        let (inbound_tx, mut inbound_rx) = mpsc::channel(8);
        let io = MockPacketIo {
            outbound: Mutex::new(outbound_rx),
            inbound: inbound_tx,
            local_ipv4: a_ip,
            local_ipv6: Some(a_ipv6),
            mtu: 1150,
        };
        let pump = tokio::spawn(async move {
            pump_mesh(
                &io,
                vec![
                    (
                        b_ip,
                        Some(b_ipv6),
                        Arc::new(channel_b),
                        None,
                        None,
                        Duration::from_secs(3600),
                    ),
                    (
                        c_ip,
                        Some(c_ipv6),
                        Arc::new(channel_c),
                        None,
                        None,
                        Duration::from_secs(3600),
                    ),
                ],
                None,
            )
            .await
        });

        outbound_tx
            .send(packet(b_ip, b_ip, 28))
            .await
            .expect("inject invalid source packet");
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

        let to_b_ipv6 = ipv6_packet(a_ipv6, b_ipv6, 8);
        outbound_tx
            .send(to_b_ipv6.clone())
            .await
            .expect("inject B IPv6 packet");
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), remote_b.recv_packet())
                .await
                .expect("B IPv6 packet timeout")
                .expect("receive B IPv6 packet"),
            to_b_ipv6
        );
        let inbound_ipv6 = ipv6_packet(b_ipv6, a_ipv6, 8);
        remote_b
            .send_packet(&inbound_ipv6)
            .await
            .expect("send inbound IPv6");
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), inbound_rx.recv())
                .await
                .expect("inbound IPv6 TUN write timeout")
                .expect("inbound IPv6 packet"),
            inbound_ipv6
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

        let to_c_ipv6 = ipv6_packet(a_ipv6, c_ipv6, 8);
        outbound_tx
            .send(to_c_ipv6.clone())
            .await
            .expect("inject C IPv6 packet");
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), remote_c.recv_packet())
                .await
                .expect("C IPv6 packet timeout")
                .expect("receive C IPv6 packet"),
            to_c_ipv6
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
            local_ipv6: None,
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
                ipv6_address: None,
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

    #[tokio::test]
    async fn dynamic_mesh_remove_closes_tcp_peer_transport() {
        let temp = std::env::temp_dir().join(format!(
            "mini-tunnel-dynamic-tcp-remove-{}",
            uuid::Uuid::new_v4()
        ));
        let identity = Arc::new(Identity::load_or_create_at(temp.join("a/device.key")).unwrap());
        let remote_identity =
            Arc::new(Identity::load_or_create_at(temp.join("b/device.key")).unwrap());
        let listener = peer_tcp_listener(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let allowed = vec![(identity.device_id(), identity.public_key())];
        let peer_id = remote_identity.device_id();
        let accept =
            accept_tcp_peer_any(&listener, "dynamic-tcp-remove", &remote_identity, &allowed);
        let connect = connect_tcp_peer(
            address,
            "dynamic-tcp-remove",
            &identity,
            &peer_id,
            remote_identity.public_key(),
        );
        let (remote_channel, local_channel) = tokio::join!(accept, connect);
        let remote_channel = remote_channel.unwrap().1;
        let local_channel = Arc::new(local_channel.unwrap());

        let local_ip = Ipv4Addr::new(10, 72, 0, 1);
        let peer_ip = Ipv4Addr::new(10, 72, 0, 2);
        let (_outbound_tx, outbound_rx) = mpsc::channel(1);
        let (inbound_tx, _inbound_rx) = mpsc::channel(1);
        let io = MockPacketIo {
            outbound: Mutex::new(outbound_rx),
            inbound: inbound_tx,
            local_ipv4: local_ip,
            local_ipv6: None,
            mtu: 1150,
        };
        let connector: PeerConnector =
            Arc::new(|_| Box::pin(async { Err(IdentityError::UnauthorizedPeer) }));
        let (update_tx, update_rx) = mpsc::channel(1);
        let pump = tokio::spawn(async move {
            pump_peer_mesh_dynamic(
                &io,
                vec![ReconnectingPeer {
                    address: peer_ip,
                    ipv6_address: None,
                    channel: local_channel,
                    connector,
                    probe: None,
                    probe_cooldown: Duration::from_secs(3600),
                }],
                update_rx,
            )
            .await
        });
        update_tx
            .send(MeshPeerUpdate::Remove(peer_ip))
            .await
            .unwrap();
        drop(update_tx);
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(2), pump)
                .await
                .unwrap()
                .unwrap(),
            Err(PeerTunnelError::NoPeers)
        ));
        assert!(
            tokio::time::timeout(Duration::from_secs(2), remote_channel.recv_packet())
                .await
                .unwrap()
                .is_err()
        );
        fs::remove_dir_all(temp).unwrap();
    }
}
