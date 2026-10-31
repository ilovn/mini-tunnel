//! In-process live peer status, intentionally limited to non-secret diagnostics.
use std::{
    collections::BTreeMap,
    sync::{OnceLock, RwLock},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

const MAX_STATUS_PEERS: usize = 4096;
static PEERS: OnceLock<RwLock<BTreeMap<String, PeerStatus>>> = OnceLock::new();

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PeerStatus {
    pub peer: String,
    pub online: bool,
    pub active_path: String,
    pub rtt_ms: Option<u64>,
    pub loss_percent: Option<u8>,
    pub last_switch_reason: Option<String>,
    pub updated_at_unix_ms: u128,
}

fn peers() -> &'static RwLock<BTreeMap<String, PeerStatus>> {
    PEERS.get_or_init(|| RwLock::new(BTreeMap::new()))
}

/// Return the current live peer snapshot. It contains no identity or transport credentials.
#[must_use]
pub fn snapshot() -> Vec<PeerStatus> {
    peers()
        .read()
        .map(|peers| peers.values().cloned().collect())
        .unwrap_or_default()
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
            } else {
                return;
            }
        }
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
                last_switch_reason: switch_reason.map(str::to_owned).or(previous_reason),
                updated_at_unix_ms: now,
            },
        );
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
        let status = snapshot()
            .into_iter()
            .find(|status| status.peer == key)
            .unwrap();
        assert!(status.online);
        assert_eq!(status.active_path, "QUIC/UDP");
        assert_eq!(status.rtt_ms, Some(18));
        assert_eq!(status.loss_percent, Some(10));
        assert_eq!(
            status.last_switch_reason.as_deref(),
            Some("quality_threshold")
        );
        let json = serde_json::to_string(&status).unwrap();
        assert!(!json.contains("token"));
        assert!(!json.contains("credential"));
    }
}
