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
            let (address, transport) = match candidate.strip_prefix("tcp://") {
                Some(value) => {
                    let Ok(address) = value.parse::<SocketAddr>() else {
                        continue;
                    };
                    (address, CandidateTransport::Tcp)
                }
                None => {
                    let Ok(address) = candidate.parse::<SocketAddr>() else {
                        continue;
                    };
                    (address, CandidateTransport::Udp)
                }
            };
            if address.port() == 0 || address.ip().is_unspecified() || address.ip().is_multicast() {
                continue;
            }
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
}
