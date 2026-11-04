//! In-process live peer status, intentionally limited to non-secret diagnostics.
use std::{
    collections::BTreeMap,
    sync::{
        Arc, OnceLock, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

const MAX_STATUS_PEERS: usize = 4096;
static PEERS: OnceLock<RwLock<BTreeMap<String, PeerStatus>>> = OnceLock::new();
static TRAFFIC: OnceLock<RwLock<BTreeMap<String, Arc<PeerTrafficCounters>>>> = OnceLock::new();

#[derive(Default)]
struct PeerTrafficCounters {
    sent: AtomicU64,
    received: AtomicU64,
    dropped: AtomicU64,
    rejected: AtomicU64,
}

#[derive(Clone)]
pub(crate) struct PeerTrafficCounter(Arc<PeerTrafficCounters>);

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PeerStatus {
    pub peer: String,
    pub online: bool,
    pub active_path: String,
    pub rtt_ms: Option<u64>,
    pub loss_percent: Option<u8>,
    #[serde(default)]
    pub packets_sent_total: u64,
    #[serde(default)]
    pub packets_received_total: u64,
    #[serde(default)]
    pub packets_dropped_total: u64,
    #[serde(default)]
    pub packets_rejected_total: u64,
    pub last_switch_reason: Option<String>,
    pub updated_at_unix_ms: u128,
}

fn peers() -> &'static RwLock<BTreeMap<String, PeerStatus>> {
    PEERS.get_or_init(|| RwLock::new(BTreeMap::new()))
}

fn traffic() -> &'static RwLock<BTreeMap<String, Arc<PeerTrafficCounters>>> {
    TRAFFIC.get_or_init(|| RwLock::new(BTreeMap::new()))
}

/// Return the current live peer snapshot. It contains no identity or transport credentials.
#[must_use]
pub fn snapshot() -> Vec<PeerStatus> {
    let mut snapshot: Vec<PeerStatus> = peers()
        .read()
        .map(|peers| peers.values().cloned().collect())
        .unwrap_or_default();
    if let Ok(counters) = traffic().read() {
        for peer in &mut snapshot {
            if let Some(counters) = counters.get(&peer.peer) {
                peer.packets_sent_total = counters.sent.load(Ordering::Relaxed);
                peer.packets_received_total = counters.received.load(Ordering::Relaxed);
                peer.packets_dropped_total = counters.dropped.load(Ordering::Relaxed);
                peer.packets_rejected_total = counters.rejected.load(Ordering::Relaxed);
            }
        }
    }
    snapshot
}

/// Render bounded-cardinality Prometheus metrics for the current peer snapshot.
///
/// Metrics are intentionally aggregate-only: device identifiers, overlay and
/// transport addresses, and change reasons are exposed by `/status` on the
/// loopback listener but are not used as metric labels.
#[must_use]
pub fn prometheus() -> String {
    let snapshot = snapshot();
    prometheus_for_snapshot(&snapshot)
}

fn prometheus_for_snapshot(snapshot: &[PeerStatus]) -> String {
    let online = snapshot.iter().filter(|peer| peer.online).count();
    let offline = snapshot.len().saturating_sub(online);
    let mut rtt_count = 0_u64;
    let mut rtt_sum = 0_u64;
    let mut rtt_max = 0_u64;
    let mut loss_count = 0_u64;
    let mut loss_sum = 0_u64;
    let mut loss_max = 0_u64;
    let mut packets_sent = 0_u64;
    let mut packets_received = 0_u64;
    let mut packets_dropped = 0_u64;
    let mut packets_rejected = 0_u64;
    for peer in snapshot {
        if let Some(rtt) = peer.rtt_ms {
            rtt_count = rtt_count.saturating_add(1);
            rtt_sum = rtt_sum.saturating_add(rtt);
            rtt_max = rtt_max.max(rtt);
        }
        if let Some(loss) = peer.loss_percent {
            let loss = u64::from(loss);
            loss_count = loss_count.saturating_add(1);
            loss_sum = loss_sum.saturating_add(loss);
            loss_max = loss_max.max(loss);
        }
        packets_sent = packets_sent.saturating_add(peer.packets_sent_total);
        packets_received = packets_received.saturating_add(peer.packets_received_total);
        packets_dropped = packets_dropped.saturating_add(peer.packets_dropped_total);
        packets_rejected = packets_rejected.saturating_add(peer.packets_rejected_total);
    }
    format!(
        "# HELP mini_tunnel_peer_online_count Number of currently online peers.\n\
         # TYPE mini_tunnel_peer_online_count gauge\n\
         mini_tunnel_peer_online_count {online}\n\
         # HELP mini_tunnel_peer_offline_count Number of currently offline peers.\n\
         # TYPE mini_tunnel_peer_offline_count gauge\n\
         mini_tunnel_peer_offline_count {offline}\n\
         # HELP mini_tunnel_peer_rtt_measurements Peers with a current RTT measurement.\n\
         # TYPE mini_tunnel_peer_rtt_measurements gauge\n\
         mini_tunnel_peer_rtt_measurements {rtt_count}\n\
         # HELP mini_tunnel_peer_rtt_ms_total Sum of current peer RTT measurements in milliseconds.\n\
         # TYPE mini_tunnel_peer_rtt_ms_total gauge\n\
         mini_tunnel_peer_rtt_ms_total {rtt_sum}\n\
         # HELP mini_tunnel_peer_rtt_ms_max Maximum current peer RTT in milliseconds.\n\
         # TYPE mini_tunnel_peer_rtt_ms_max gauge\n\
         mini_tunnel_peer_rtt_ms_max {rtt_max}\n\
         # HELP mini_tunnel_peer_loss_measurements Peers with a current probe loss measurement.\n\
         # TYPE mini_tunnel_peer_loss_measurements gauge\n\
         mini_tunnel_peer_loss_measurements {loss_count}\n\
         # HELP mini_tunnel_peer_loss_percent_total Sum of current peer probe loss percentages.\n\
         # TYPE mini_tunnel_peer_loss_percent_total gauge\n\
         mini_tunnel_peer_loss_percent_total {loss_sum}\n\
         # HELP mini_tunnel_peer_loss_percent_max Maximum current peer probe loss percentage.\n\
         # TYPE mini_tunnel_peer_loss_percent_max gauge\n\
         mini_tunnel_peer_loss_percent_max {loss_max}\n\
         # HELP mini_tunnel_peer_packets_sent_total Overlay IP packets successfully sent to peers.\n\
         # TYPE mini_tunnel_peer_packets_sent_total counter\n\
         mini_tunnel_peer_packets_sent_total {packets_sent}\n\
         # HELP mini_tunnel_peer_packets_received_total Overlay IP packets accepted from peers.\n\
         # TYPE mini_tunnel_peer_packets_received_total counter\n\
         mini_tunnel_peer_packets_received_total {packets_received}\n\
         # HELP mini_tunnel_peer_packets_dropped_total Overlay packets dropped by bounded per-peer queues.\n\
         # TYPE mini_tunnel_peer_packets_dropped_total counter\n\
         mini_tunnel_peer_packets_dropped_total {packets_dropped}\n\
         # HELP mini_tunnel_peer_packets_rejected_total Inbound overlay packets rejected by TUN validation.\n\
         # TYPE mini_tunnel_peer_packets_rejected_total counter\n\
         mini_tunnel_peer_packets_rejected_total {packets_rejected}\n"
    )
}

/// Update one peer's live status from the tunnel data plane.
pub fn update(
    peer: impl Into<String>,
    online: bool,
    active_path: impl Into<String>,
    rtt_ms: Option<u64>,
    probes_succeeded: u64,
    probes_missed: u64,
    switch_reason: Option<&str>,
) {
    let peer = peer.into();
    let active_path = active_path.into();
    let total = probes_succeeded.saturating_add(probes_missed);
    let loss_percent =
        (total > 0).then(|| u8::try_from(probes_missed.saturating_mul(100) / total).unwrap_or(100));
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    if let Ok(mut peers) = peers().write() {
        if !peers.contains_key(&peer) && peers.len() >= MAX_STATUS_PEERS {
            if let Some(stale) = peers
                .iter()
                .find_map(|(key, status)| (!status.online).then(|| key.clone()))
            {
                peers.remove(&stale);
                if let Ok(mut counters) = traffic().write() {
                    counters.remove(&stale);
                }
            } else {
                return;
            }
        }
        let _ = traffic_counter(&peer);
        let previous_reason = peers
            .get(&peer)
            .and_then(|status| status.last_switch_reason.clone());
        peers.insert(
            peer.clone(),
            PeerStatus {
                peer,
                online,
                active_path,
                rtt_ms,
                loss_percent,
                packets_sent_total: 0,
                packets_received_total: 0,
                packets_dropped_total: 0,
                packets_rejected_total: 0,
                last_switch_reason: switch_reason.map(str::to_owned).or(previous_reason),
                updated_at_unix_ms: now,
            },
        );
    }
}

#[derive(Clone, Copy)]
pub(crate) enum PacketCounter {
    Sent,
    Received,
    Dropped,
    Rejected,
}

/// Record an overlay data-plane packet event independently from transport health probes.
pub(crate) fn record_packet(peer: &str, counter: PacketCounter) {
    let counters = traffic()
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(counters) = counters.get(peer) {
        PeerTrafficCounter(Arc::clone(counters)).record(counter);
    }
}

pub(crate) fn traffic_counter(peer: &str) -> PeerTrafficCounter {
    let counters = traffic();
    let read = counters
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(counters) = read.get(peer) {
        return PeerTrafficCounter(Arc::clone(counters));
    }
    drop(read);
    let mut write = counters
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if write.len() >= MAX_STATUS_PEERS {
        return PeerTrafficCounter(Arc::new(PeerTrafficCounters::default()));
    }
    PeerTrafficCounter(Arc::clone(
        write
            .entry(peer.to_owned())
            .or_insert_with(|| Arc::new(PeerTrafficCounters::default())),
    ))
}

impl PeerTrafficCounter {
    pub(crate) fn record(&self, counter: PacketCounter) {
        let value = match counter {
            PacketCounter::Sent => &self.0.sent,
            PacketCounter::Received => &self.0.received,
            PacketCounter::Dropped => &self.0.dropped,
            PacketCounter::Rejected => &self.0.rejected,
        };
        let mut current = value.load(Ordering::Relaxed);
        loop {
            match value.compare_exchange_weak(
                current,
                current.saturating_add(1),
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(observed) => current = observed,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_snapshot_reports_quality_and_preserves_last_switch_reason() {
        let key = format!("status-test-{}", std::process::id());
        update(
            &key,
            true,
            "TCP/TLS",
            Some(42),
            8,
            2,
            Some("quality_threshold"),
        );
        update(&key, true, "QUIC/UDP", Some(18), 18, 2, None);
        record_packet(&key, PacketCounter::Sent);
        record_packet(&key, PacketCounter::Received);
        record_packet(&key, PacketCounter::Dropped);
        record_packet(&key, PacketCounter::Rejected);
        let status = snapshot()
            .into_iter()
            .find(|status| status.peer == key)
            .unwrap();
        assert!(status.online);
        assert_eq!(status.active_path, "QUIC/UDP");
        assert_eq!(status.rtt_ms, Some(18));
        assert_eq!(status.loss_percent, Some(10));
        assert_eq!(status.packets_sent_total, 1);
        assert_eq!(status.packets_received_total, 1);
        assert_eq!(status.packets_dropped_total, 1);
        assert_eq!(status.packets_rejected_total, 1);
        assert_eq!(
            status.last_switch_reason.as_deref(),
            Some("quality_threshold")
        );
        let json = serde_json::to_string(&status).unwrap();
        assert!(!json.contains("token"));
        assert!(!json.contains("credential"));
        let legacy: PeerStatus = serde_json::from_str(
            r#"{"peer":"legacy","online":true,"active_path":"QUIC/UDP","rtt_ms":7,"loss_percent":0,"last_switch_reason":null,"updated_at_unix_ms":1}"#,
        )
        .expect("deserialize a pre-counter status response");
        assert_eq!(legacy.packets_sent_total, 0);
        assert_eq!(legacy.packets_received_total, 0);
        assert_eq!(legacy.packets_dropped_total, 0);
        assert_eq!(legacy.packets_rejected_total, 0);
    }

    #[test]
    fn prometheus_metrics_are_aggregate_only_and_report_current_peers() {
        let metrics = prometheus_for_snapshot(&[
            PeerStatus {
                peer: "private-device-a".to_owned(),
                online: true,
                active_path: "QUIC/UDP".to_owned(),
                rtt_ms: Some(18),
                loss_percent: Some(10),
                packets_sent_total: 3,
                packets_received_total: 4,
                packets_dropped_total: 1,
                packets_rejected_total: 2,
                last_switch_reason: Some("quality_threshold".to_owned()),
                updated_at_unix_ms: 1,
            },
            PeerStatus {
                peer: "private-device-b".to_owned(),
                online: false,
                active_path: "TLS/TCP".to_owned(),
                rtt_ms: Some(50),
                loss_percent: Some(50),
                packets_sent_total: 7,
                packets_received_total: 8,
                packets_dropped_total: 0,
                packets_rejected_total: 0,
                last_switch_reason: None,
                updated_at_unix_ms: 2,
            },
        ]);
        assert!(metrics.contains("mini_tunnel_peer_online_count 1\n"));
        assert!(metrics.contains("mini_tunnel_peer_offline_count 1\n"));
        assert!(metrics.contains("mini_tunnel_peer_rtt_measurements 2\n"));
        assert!(metrics.contains("mini_tunnel_peer_rtt_ms_total 68\n"));
        assert!(metrics.contains("mini_tunnel_peer_rtt_ms_max 50\n"));
        assert!(metrics.contains("mini_tunnel_peer_loss_measurements 2\n"));
        assert!(metrics.contains("mini_tunnel_peer_loss_percent_total 60\n"));
        assert!(metrics.contains("mini_tunnel_peer_loss_percent_max 50\n"));
        assert!(metrics.contains("mini_tunnel_peer_packets_sent_total 10\n"));
        assert!(metrics.contains("mini_tunnel_peer_packets_received_total 12\n"));
        assert!(metrics.contains("mini_tunnel_peer_packets_dropped_total 1\n"));
        assert!(metrics.contains("mini_tunnel_peer_packets_rejected_total 2\n"));
        assert!(!metrics.contains("private-device"));
        assert!(!metrics.contains("QUIC/UDP"));
        assert!(!metrics.contains("TLS/TCP"));
        assert!(!metrics.contains("quality_threshold"));
    }
}
