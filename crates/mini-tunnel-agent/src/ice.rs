//! Bounded adapter between the Sans-I/O ICE agent and the shared UDP socket driver.

use std::{net::SocketAddr, time::Instant};

use bytes::BytesMut;
use rtc_ice::Agent;
use rtc_shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use sansio::Protocol;
use thiserror::Error;

use crate::stun::is_stun_datagram;

/// Maximum ICE checks drained during one socket-driver turn.
pub const MAX_ICE_TRANSMITS_PER_TURN: usize = 64;

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
    use std::{sync::Arc, thread, time::Duration};

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
}
