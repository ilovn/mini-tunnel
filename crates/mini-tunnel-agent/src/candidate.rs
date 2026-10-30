//! Bounded candidate checklist and deterministic path preference.
//!
//! This is an ICE-inspired dial checklist, not an RFC 8445 implementation.

use std::net::SocketAddr;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidateTransport {
    Udp,
    Tcp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidateType {
    Host,
    ServerReflexive { related_address: SocketAddr },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignaledCandidate {
    pub address: SocketAddr,
    pub transport: CandidateTransport,
    pub candidate_type: CandidateType,
}

/// Parse the stable candidate string forms used by candidate publication.
/// Bare socket addresses are UDP host candidates for wire compatibility.
pub fn parse_signaled_candidate(value: &str) -> Option<SignaledCandidate> {
    let (address, transport, candidate_type) = if let Some(value) = value.strip_prefix("tcp://") {
        (
            value.parse::<SocketAddr>().ok()?,
            CandidateTransport::Tcp,
            CandidateType::Host,
        )
    } else if let Some(value) = value.strip_prefix("srflx://") {
        let (mapped, related) = value.split_once('|')?;
        (
            mapped.parse::<SocketAddr>().ok()?,
            CandidateTransport::Udp,
            CandidateType::ServerReflexive {
                related_address: related.parse::<SocketAddr>().ok()?,
            },
        )
    } else {
        (
            value.parse::<SocketAddr>().ok()?,
            CandidateTransport::Udp,
            CandidateType::Host,
        )
    };
    if !usable_candidate_address(address) {
        return None;
    }
    if let CandidateType::ServerReflexive { related_address } = candidate_type
        && !usable_candidate_address(related_address)
    {
        return None;
    }
    Some(SignaledCandidate {
        address,
        transport,
        candidate_type,
    })
}

fn usable_candidate_address(address: SocketAddr) -> bool {
    if address.port() == 0 || address.ip().is_unspecified() || address.ip().is_multicast() {
        return false;
    }
    !matches!(address.ip(), std::net::IpAddr::V4(ip) if ip == std::net::Ipv4Addr::BROADCAST)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidateCheckState {
    Waiting,
    InProgress,
    Succeeded,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateCheck {
    pub address: SocketAddr,
    pub transport: CandidateTransport,
    pub state: CandidateCheckState,
}

/// A bounded candidate list, ordered by transport preference and stable input order.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CandidateChecklist {
    checks: Vec<CandidateCheck>,
}

impl CandidateChecklist {
    pub fn from_signaled(candidates: &[String], max_candidates: usize) -> Option<Self> {
        if candidates.len() > max_candidates {
            return None;
        }

        let mut checks = Vec::with_capacity(candidates.len());
        for candidate in candidates {
            let Some(parsed) = parse_signaled_candidate(candidate) else {
                continue;
            };
            let address = parsed.address;
            let transport = parsed.transport;
            if checks.iter().any(|check: &CandidateCheck| {
                check.address == address && check.transport == transport
            }) {
                continue;
            }
            checks.push(CandidateCheck {
                address,
                transport,
                state: CandidateCheckState::Waiting,
            });
        }
        checks.sort_by_key(|check| match check.transport {
            CandidateTransport::Udp => 0,
            CandidateTransport::Tcp => 1,
        });
        Some(Self { checks })
    }

    pub fn checks(&self) -> &[CandidateCheck] {
        &self.checks
    }

    pub fn next_waiting(&self) -> Option<usize> {
        self.checks
            .iter()
            .position(|check| check.state == CandidateCheckState::Waiting)
    }

    pub fn mark_in_progress(&mut self, index: usize) {
        if let Some(check) = self.checks.get_mut(index) {
            debug_assert_eq!(check.state, CandidateCheckState::Waiting);
            check.state = CandidateCheckState::InProgress;
        }
    }

    pub fn finish(&mut self, index: usize, succeeded: bool) {
        if let Some(check) = self.checks.get_mut(index) {
            debug_assert_eq!(check.state, CandidateCheckState::InProgress);
            check.state = if succeeded {
                CandidateCheckState::Succeeded
            } else {
                CandidateCheckState::Failed
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checklist_deduplicates_and_prefers_udp_stably() {
        let candidates = [
            "tcp://198.51.100.2:443".to_owned(),
            "198.51.100.3:42000".to_owned(),
            "198.51.100.3:42000".to_owned(),
            "tcp://198.51.100.4:443".to_owned(),
        ];
        let checklist = CandidateChecklist::from_signaled(&candidates, 8).expect("valid list");
        assert_eq!(checklist.checks().len(), 3);
        assert_eq!(
            checklist.checks()[0].address,
            "198.51.100.3:42000".parse().unwrap()
        );
        assert_eq!(
            checklist.checks()[1].address,
            "198.51.100.2:443".parse().unwrap()
        );
        assert_eq!(
            checklist.checks()[2].address,
            "198.51.100.4:443".parse().unwrap()
        );
    }

    #[test]
    fn checklist_enforces_candidate_limit_and_state_transitions() {
        let candidates = [
            "198.51.100.1:1".to_owned(),
            "tcp://198.51.100.2:2".to_owned(),
        ];
        assert!(CandidateChecklist::from_signaled(&candidates, 1).is_none());

        let mut checklist = CandidateChecklist::from_signaled(&candidates, 2).expect("valid list");
        let first = checklist.next_waiting().expect("first candidate");
        checklist.mark_in_progress(first);
        checklist.finish(first, false);
        assert_eq!(checklist.checks()[first].state, CandidateCheckState::Failed);
        assert_eq!(checklist.next_waiting(), Some(1));
        checklist.mark_in_progress(1);
        checklist.finish(1, true);
        assert_eq!(checklist.checks()[1].state, CandidateCheckState::Succeeded);
        assert_eq!(checklist.next_waiting(), None);
    }

    #[test]
    fn checklist_skips_unusable_and_malformed_addresses() {
        let unusable = ["0.0.0.0:42000".to_owned(), "224.0.0.1:42000".to_owned()];
        assert!(
            CandidateChecklist::from_signaled(&unusable, 2)
                .expect("well formed list")
                .checks()
                .is_empty()
        );
        let mixed = ["not-an-address".to_owned(), "198.51.100.9:443".to_owned()];
        let checklist = CandidateChecklist::from_signaled(&mixed, 8).expect("bounded list");
        assert_eq!(checklist.checks().len(), 1);
        assert_eq!(
            checklist.checks()[0].address,
            "198.51.100.9:443".parse().unwrap()
        );
    }

    #[test]
    fn parses_server_reflexive_candidates_with_ipv4_ipv6_and_legacy_forms() {
        let candidate = parse_signaled_candidate("srflx://203.0.113.7:5000|192.168.1.4:4000")
            .expect("IPv4 srflx candidate");
        assert_eq!(candidate.address, "203.0.113.7:5000".parse().unwrap());
        assert_eq!(candidate.transport, CandidateTransport::Udp);
        assert_eq!(
            candidate.candidate_type,
            CandidateType::ServerReflexive {
                related_address: "192.168.1.4:4000".parse().unwrap(),
            }
        );
        let ipv6 = parse_signaled_candidate("srflx://[2001:db8::1]:5000|[2001:db8::2]:4000")
            .expect("IPv6 srflx candidate");
        assert_eq!(ipv6.address, "[2001:db8::1]:5000".parse().unwrap());
        assert_eq!(
            parse_signaled_candidate("198.51.100.8:42000")
                .unwrap()
                .candidate_type,
            CandidateType::Host
        );
        assert!(parse_signaled_candidate("srflx://203.0.113.7:5000|bad").is_none());
        let checklist = CandidateChecklist::from_signaled(
            &["srflx://203.0.113.7:5000|192.168.1.4:4000".to_owned()],
            8,
        )
        .unwrap();
        assert_eq!(
            checklist.checks()[0].address,
            "203.0.113.7:5000".parse().unwrap()
        );
    }

    #[test]
    fn rejects_broadcast_and_unusable_server_reflexive_related_addresses() {
        for candidate in [
            "255.255.255.255:42000",
            "srflx://203.0.113.7:5000|0.0.0.0:4000",
            "srflx://203.0.113.7:5000|255.255.255.255:4000",
            "srflx://203.0.113.7:5000|224.0.0.1:4000",
            "srflx://203.0.113.7:5000|[::]:4000",
            "srflx://203.0.113.7:5000|192.168.1.4:0",
        ] {
            assert!(
                parse_signaled_candidate(candidate).is_none(),
                "accepted unusable candidate {candidate}"
            );
        }
    }
}
