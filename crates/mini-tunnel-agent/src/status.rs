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
static PROBE_BASELINES: OnceLock<RwLock<BTreeMap<String, ProbeBaseline>>> = OnceLock::new();

#[derive(Clone)]
struct ProbeBaseline {
    active_path: String,
    succeeded: u64,
    missed: u64,
}

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
    /// Loss in the most recent non-empty probe sample for `active_path`.
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

fn probe_baselines() -> &'static RwLock<BTreeMap<String, ProbeBaseline>> {
    PROBE_BASELINES.get_or_init(|| RwLock::new(BTreeMap::new()))
}

fn probe_loss_percent(succeeded: u64, missed: u64) -> Option<u8> {
    let total = u128::from(succeeded) + u128::from(missed);
    (total > 0).then(|| (u128::from(missed) * 100 / total) as u8)
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
         # HELP mini_tunnel_peer_loss_percent_total Sum of most recent peer probe loss percentages.\n\
         # TYPE mini_tunnel_peer_loss_percent_total gauge\n\
         mini_tunnel_peer_loss_percent_total {loss_sum}\n\
         # HELP mini_tunnel_peer_loss_percent_max Maximum most recent peer probe loss percentage.\n\
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
                if let Ok(mut baselines) = probe_baselines().write() {
                    baselines.remove(&stale);
                }
            } else {
                return;
            }
        }
        let previous_loss = peers.get(&peer).and_then(|status| {
            (status.active_path == active_path)
                .then_some(status.loss_percent)
                .flatten()
        });
        let loss_percent = if let Ok(mut baselines) = probe_baselines().write() {
            let previous = baselines.get(&peer);
            let same_path_and_monotonic = previous.is_some_and(|baseline| {
                baseline.active_path == active_path
                    && probes_succeeded >= baseline.succeeded
                    && probes_missed >= baseline.missed
            });
            let (sample_succeeded, sample_missed) = if let Some(baseline) = previous
                && same_path_and_monotonic
            {
                (
                    probes_succeeded - baseline.succeeded,
                    probes_missed - baseline.missed,
                )
            } else {
                (probes_succeeded, probes_missed)
            };
            let had_previous_baseline = previous.is_some();
            baselines.insert(
                peer.clone(),
                ProbeBaseline {
                    active_path: active_path.clone(),
                    succeeded: probes_succeeded,
                    missed: probes_missed,
                },
            );
            if !same_path_and_monotonic && had_previous_baseline {
                // A new transport or recreated channel may have accumulated standby or
                // probation probes; establish a baseline and wait for a fresh sample.
                None
            } else if sample_succeeded == 0 && sample_missed == 0 {
                previous_loss
            } else {
                probe_loss_percent(sample_succeeded, sample_missed)
            }
        } else {
            probe_loss_percent(probes_succeeded, probes_missed)
        };
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
        // A path transition resets the measurement until the new path yields samples.
        assert_eq!(status.loss_percent, None);
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
    fn status_loss_percent_tracks_new_probe_samples_and_resets_on_path_change() {
        let key = format!("status-probe-window-{}", std::process::id());
        update(&key, true, "QUIC/UDP", Some(20), 3, 1, None);
        assert_eq!(get_status(&key).loss_percent, Some(25));

        // Historical misses must not be diluted by later successful probes.
        update(&key, true, "QUIC/UDP", Some(20), 6, 1, None);
        assert_eq!(get_status(&key).loss_percent, Some(0));

        // An update without new probes retains the most recent measured interval.
        update(&key, true, "QUIC/UDP", Some(20), 6, 1, None);
        assert_eq!(get_status(&key).loss_percent, Some(0));

        // A new transport may have accumulated standby probes; wait for a fresh sample.
        update(&key, true, "Relay/TLS", Some(30), 1, 1, None);
        assert_eq!(get_status(&key).loss_percent, None);
        update(&key, true, "Relay/TLS", Some(30), 2, 2, None);
        assert_eq!(get_status(&key).loss_percent, Some(50));

        // Recreated channels can reset counters without changing the transport name.
        update(&key, true, "Relay/TLS", Some(30), 1, 0, None);
        assert_eq!(get_status(&key).loss_percent, None);
        update(&key, true, "Relay/TLS", Some(30), 1, 1, None);
        assert_eq!(get_status(&key).loss_percent, Some(100));
    }

    fn get_status(peer: &str) -> PeerStatus {
        snapshot()
            .into_iter()
            .find(|status| status.peer == peer)
            .unwrap()
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
