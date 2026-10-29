//! Platform TUN adapter and the IPv4 boundary used by peer packet forwarding.

use std::{io, net::Ipv4Addr};

use thiserror::Error;

const IPV4_MIN_HEADER_LEN: usize = 20;
const IPV4_MAX_PACKET_LEN: usize = u16::MAX as usize;
const DEFAULT_TUN_MTU: u16 = (super::MAX_PACKET_PAYLOAD - super::FRAME_HEADER_LEN) as u16;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Ipv4PacketError {
    #[error("IPv4 packet is shorter than its minimum header")]
    TruncatedHeader,
    #[error("packet is not IPv4")]
    WrongVersion,
    #[error("IPv4 header length is invalid")]
    InvalidHeaderLength,
    #[error("IPv4 total length does not match the packet length")]
    InvalidTotalLength,
    #[error("IPv4 packet exceeds the configured MTU")]
    MtuExceeded,
    #[error("IPv4 source address does not match the authenticated peer")]
    UnexpectedSource,
    #[error("IPv4 destination address does not match this device")]
    UnexpectedDestination,
}

#[derive(Debug, Error)]
pub enum TunError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    InvalidPacket(#[from] Ipv4PacketError),
    #[error("TUN device wrote an incomplete packet")]
    IncompleteWrite,
}

/// Parameters for creating a Layer 3 IPv4 TUN interface.
#[derive(Debug, Clone)]
pub struct TunConfig {
    pub name: Option<String>,
    pub local_ipv4: Ipv4Addr,
    pub prefix_len: u8,
    pub mtu: u16,
}

impl TunConfig {
    /// Build a config with an MTU that fits the current bounded QUIC packet framing.
    #[must_use]
    pub fn ipv4(local_ipv4: Ipv4Addr, prefix_len: u8) -> Self {
        Self {
            name: None,
            local_ipv4,
            prefix_len,
            mtu: DEFAULT_TUN_MTU,
        }
    }

    pub fn validate(&self) -> io::Result<()> {
        if self.prefix_len > 32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "IPv4 prefix length must be between 0 and 32",
            ));
        }
        if !(576..=DEFAULT_TUN_MTU).contains(&self.mtu) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TUN MTU must be between 576 and the current QUIC packet limit",
            ));
        }
        Ok(())
    }
}

/// Async L3 TUN interface. Route installation is intentionally left to a later, explicit step.
pub struct TunDevice {
    device: tun_rs::AsyncDevice,
    local_ipv4: Ipv4Addr,
    mtu: usize,
}

impl TunDevice {
    /// Create a TUN device and assign its local overlay IPv4 address.
    ///
    /// This requires platform permission to create/configure network interfaces. It does not
    /// install the overlay CIDR route. macOS/BSD library-level automatic route management is
    /// explicitly disabled.
    pub fn create(config: TunConfig) -> io::Result<Self> {
        config.validate()?;
        let mut builder = tun_rs::DeviceBuilder::new()
            .layer(tun_rs::Layer::L3)
            .ipv4(config.local_ipv4, config.prefix_len, None)
            .mtu(config.mtu);
        if let Some(name) = config.name {
            builder = builder.name(name);
        }
        #[cfg(any(
            target_os = "macos",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd"
        ))]
        {
            builder = builder.associate_route(false);
        }
        #[cfg(any(
            target_os = "macos",
            target_os = "linux",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd"
        ))]
        {
            // macOS utun otherwise prepends a four-byte address-family header.
            builder = builder.packet_information(false);
        }
        Ok(Self {
            device: builder.build_async()?,
            local_ipv4: config.local_ipv4,
            mtu: usize::from(config.mtu),
        })
    }

    #[must_use]
    pub fn local_ipv4(&self) -> Ipv4Addr {
        self.local_ipv4
    }

    #[must_use]
    pub fn mtu(&self) -> usize {
        self.mtu
    }

    /// Read one local-originated IPv4 packet, rejecting malformed packets and spoofed sources.
    pub async fn read_outbound_packet(&self) -> Result<Vec<u8>, TunError> {
        let mut packet = vec![0; self.mtu];
        let length = self.device.recv(&mut packet).await?;
        packet.truncate(length);
        validate_outbound_ipv4(&packet, self.local_ipv4, self.mtu)?;
        Ok(packet)
    }

    /// Write a peer packet into the local stack after checking its peer and destination addresses.
    pub async fn write_inbound_packet(
        &self,
        packet: &[u8],
        expected_peer_ipv4: Ipv4Addr,
    ) -> Result<(), TunError> {
        validate_inbound_ipv4(packet, self.local_ipv4, expected_peer_ipv4, self.mtu)?;
        if self.device.send(packet).await? != packet.len() {
            return Err(TunError::IncompleteWrite);
        }
        Ok(())
    }
}

fn validate_ipv4_header(packet: &[u8], mtu: usize) -> Result<(), Ipv4PacketError> {
    if packet.len() < IPV4_MIN_HEADER_LEN {
        return Err(Ipv4PacketError::TruncatedHeader);
    }
    if packet[0] >> 4 != 4 {
        return Err(Ipv4PacketError::WrongVersion);
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if !(IPV4_MIN_HEADER_LEN..=packet.len()).contains(&header_len) {
        return Err(Ipv4PacketError::InvalidHeaderLength);
    }
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_len != packet.len() || total_len < header_len || total_len > IPV4_MAX_PACKET_LEN {
        return Err(Ipv4PacketError::InvalidTotalLength);
    }
    if total_len > mtu {
        return Err(Ipv4PacketError::MtuExceeded);
    }
    Ok(())
}

pub fn validate_outbound_ipv4(
    packet: &[u8],
    local_ipv4: Ipv4Addr,
    mtu: usize,
) -> Result<(), Ipv4PacketError> {
    validate_ipv4_header(packet, mtu)?;
    if ipv4_source(packet) != local_ipv4 {
        return Err(Ipv4PacketError::UnexpectedSource);
    }
    Ok(())
}

pub fn validate_inbound_ipv4(
    packet: &[u8],
    local_ipv4: Ipv4Addr,
    expected_peer_ipv4: Ipv4Addr,
    mtu: usize,
) -> Result<(), Ipv4PacketError> {
    validate_ipv4_header(packet, mtu)?;
    if ipv4_source(packet) != expected_peer_ipv4 {
        return Err(Ipv4PacketError::UnexpectedSource);
    }
    if ipv4_destination(packet) != local_ipv4 {
        return Err(Ipv4PacketError::UnexpectedDestination);
    }
    Ok(())
}

fn ipv4_source(packet: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15])
}

fn ipv4_destination(packet: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(source: Ipv4Addr, destination: Ipv4Addr, total_len: usize) -> Vec<u8> {
        let mut packet = vec![0; total_len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&source.octets());
        packet[16..20].copy_from_slice(&destination.octets());
        packet
    }

    #[test]
    fn ipv4_packet_boundary_checks_header_mtu_and_peer_addresses() {
        let local = Ipv4Addr::new(10, 77, 0, 2);
        let peer = Ipv4Addr::new(10, 77, 0, 3);
        let valid = packet(peer, local, 28);
        validate_ipv4_header(&valid, 1280).expect("valid IPv4 packet");
        validate_outbound_ipv4(&packet(local, peer, 28), local, 1280)
            .expect("valid local-originated packet");
        validate_inbound_ipv4(&valid, local, peer, 1280).expect("valid peer packet");
        assert_eq!(ipv4_source(&valid), peer);
        assert_eq!(ipv4_destination(&valid), local);

        assert_eq!(
            validate_ipv4_header(&[0; 19], 1280),
            Err(Ipv4PacketError::TruncatedHeader)
        );
        let mut wrong_version = valid.clone();
        wrong_version[0] = 0x65;
        assert_eq!(
            validate_ipv4_header(&wrong_version, 1280),
            Err(Ipv4PacketError::WrongVersion)
        );
        let mut bad_ihl = valid.clone();
        bad_ihl[0] = 0x44;
        assert_eq!(
            validate_ipv4_header(&bad_ihl, 1280),
            Err(Ipv4PacketError::InvalidHeaderLength)
        );
        let mut bad_length = valid.clone();
        bad_length[3] = 27;
        assert_eq!(
            validate_ipv4_header(&bad_length, 1280),
            Err(Ipv4PacketError::InvalidTotalLength)
        );
        assert_eq!(
            validate_ipv4_header(&valid, 27),
            Err(Ipv4PacketError::MtuExceeded)
        );
        assert_eq!(
            validate_outbound_ipv4(&valid, local, 1280),
            Err(Ipv4PacketError::UnexpectedSource)
        );
        assert_eq!(
            validate_inbound_ipv4(&packet(local, local, 28), local, peer, 1280),
            Err(Ipv4PacketError::UnexpectedSource)
        );
        assert_eq!(
            validate_inbound_ipv4(&packet(peer, peer, 28), local, peer, 1280),
            Err(Ipv4PacketError::UnexpectedDestination)
        );
    }

    #[test]
    fn tun_configuration_rejects_invalid_prefix_and_mtu() {
        let mut config = TunConfig::ipv4(Ipv4Addr::LOCALHOST, 24);
        config.prefix_len = 33;
        assert_eq!(
            config.validate().expect_err("bad prefix").kind(),
            io::ErrorKind::InvalidInput
        );
        config.prefix_len = 24;
        config.mtu = 1151;
        assert_eq!(
            config
                .validate()
                .expect_err("MTU exceeds current QUIC limit")
                .kind(),
            io::ErrorKind::InvalidInput
        );
        config.mtu = 575;
        assert_eq!(
            config.validate().expect_err("bad MTU").kind(),
            io::ErrorKind::InvalidInput
        );
    }
}
