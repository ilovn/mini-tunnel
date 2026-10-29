//! Bidirectional bridge between a validated L3 packet device and an authenticated peer channel.

use std::net::Ipv4Addr;

use thiserror::Error;

use crate::{IdentityError, PeerChannel, tun_device::TunError};

#[derive(Debug, Error)]
pub enum PeerTunnelError {
    #[error(transparent)]
    Tun(#[from] TunError),
    #[error(transparent)]
    Peer(#[from] IdentityError),
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
    loop {
        tokio::select! {
            outbound = packet_io.read_outbound_packet() => {
                peer.send_packet(&outbound?)?;
            }
            inbound = peer.recv_packet() => {
                packet_io.write_inbound_packet(&inbound?, peer_ipv4).await?;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        net::{IpAddr, Ipv4Addr, SocketAddr},
    };

    use tokio::sync::{Mutex, mpsc};

    use super::*;
    use crate::{Identity, accept_peer, connect_peer, peer_endpoint};

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
}
