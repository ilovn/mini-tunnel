//! Platform TUN adapter and the dual-stack IP boundary used by peer packet forwarding.

use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use thiserror::Error;

const IPV4_MIN_HEADER_LEN: usize = 20;
const IPV6_MIN_HEADER_LEN: usize = 40;
const IPV4_MAX_PACKET_LEN: usize = u16::MAX as usize;
const DEFAULT_TUN_MTU: u16 = 1280;
const MAX_TUN_MTU: u16 = super::MAX_TUN_PACKET as u16;

pub type Ipv4PacketError = IpPacketError;

#[derive(Debug, Error)]
pub enum TunError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    InvalidPacket(#[from] Ipv4PacketError),
    #[error("TUN device wrote an incomplete packet")]
    IncompleteWrite,
}

/// Parameters for creating a Layer 3 IPv4 TUN interface with an optional IPv6 overlay address.
#[derive(Debug, Clone)]
pub struct TunConfig {
    pub name: Option<String>,
    pub local_ipv4: Ipv4Addr,
    pub prefix_len: u8,
    pub local_ipv6: Option<Ipv6Addr>,
    pub ipv6_prefix_len: u8,
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
            local_ipv6: None,
            ipv6_prefix_len: 64,
            mtu: DEFAULT_TUN_MTU,
        }
    }

    #[must_use]
    pub fn with_ipv6(mut self, local_ipv6: Ipv6Addr, prefix_len: u8) -> Self {
        self.local_ipv6 = Some(local_ipv6);
        self.ipv6_prefix_len = prefix_len;
        self
    }

    pub fn validate(&self) -> io::Result<()> {
        if self.prefix_len > 32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "IPv4 prefix length must be between 0 and 32",
            ));
        }
        if self.local_ipv6.is_some() && self.ipv6_prefix_len > 128 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "IPv6 prefix length must be between 0 and 128",
            ));
        }
        if !(576..=MAX_TUN_MTU).contains(&self.mtu) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TUN MTU must be between 576 and 9000 bytes",
            ));
        }
        if self.local_ipv6.is_some() && self.mtu < 1280 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "IPv6 TUN MTU must be at least 1280 bytes",
            ));
        }
        Ok(())
    }
}

/// Async L3 TUN interface. Explicit overlay route management is left to a later step.
pub struct TunDevice {
    device: tun_rs::AsyncDevice,
    local_ipv4: Ipv4Addr,
    local_ipv6: Option<Ipv6Addr>,
    mtu: usize,
}

impl TunDevice {
    /// Create a TUN device and assign its local overlay IPv4 and optional IPv6 addresses.
    ///
    /// This requires platform permission to create/configure network interfaces. It does not call
    /// an explicit route-management API; the OS may create a connected route from the assigned
    /// address and prefix. macOS/BSD library-level automatic route management is disabled.
    pub fn create(config: TunConfig) -> io::Result<Self> {
        config.validate()?;
        let mut builder = tun_rs::DeviceBuilder::new()
            .layer(tun_rs::Layer::L3)
            .ipv4(config.local_ipv4, config.prefix_len, None)
            .mtu(config.mtu);
        if let Some(local_ipv6) = config.local_ipv6 {
            builder = builder.ipv6(local_ipv6, config.ipv6_prefix_len);
        }
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
            local_ipv6: config.local_ipv6,
            mtu: usize::from(config.mtu),
        })
    }

    #[must_use]
    pub fn local_ipv4(&self) -> Ipv4Addr {
        self.local_ipv4
    }

    #[must_use]
    pub fn local_ipv6(&self) -> Option<Ipv6Addr> {
        self.local_ipv6
    }

    #[must_use]
    pub fn mtu(&self) -> usize {
        self.mtu
    }

    pub fn name(&self) -> io::Result<String> {
        self.device.name()
    }

    /// Read one local-originated IPv4 or IPv6 packet, rejecting malformed packets and spoofed sources.
    pub async fn read_outbound_packet(&self) -> Result<Vec<u8>, TunError> {
        let mut packet = vec![0; self.mtu];
        let length = self.device.recv(&mut packet).await?;
        packet.truncate(length);
        validate_outbound_packet(&packet, self.local_ipv4, self.local_ipv6, self.mtu)?;
        Ok(packet)
    }

    /// Write a peer packet into the local stack after checking its peer and destination addresses.
    pub async fn write_inbound_packet(
        &self,
        packet: &[u8],
        expected_peer_ipv4: Ipv4Addr,
    ) -> Result<(), TunError> {
        self.write_inbound_ip_packet(packet, IpAddr::V4(expected_peer_ipv4))
            .await
    }

    pub async fn write_inbound_ip_packet(
        &self,
        packet: &[u8],
        expected_peer: IpAddr,
    ) -> Result<(), TunError> {
        validate_inbound_packet(
            packet,
            IpAddr::V4(self.local_ipv4),
            self.local_ipv6.map(IpAddr::V6),
            expected_peer,
            self.mtu,
        )?;
        if self.device.send(packet).await? != packet.len() {
            return Err(TunError::IncompleteWrite);
        }
        Ok(())
    }
}

/// IPv4 and IPv6 packet boundary errors.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum IpPacketError {
    #[error("IP packet is shorter than its minimum header")]
    TruncatedHeader,
    #[error("packet has an unsupported IP version")]
    WrongVersion,
    #[error("IPv4 header length is invalid")]
    InvalidHeaderLength,
    #[error("IP packet length does not match its header")]
    InvalidTotalLength,
    #[error("IP packet exceeds the configured MTU")]
    MtuExceeded,
    #[error("IP source address does not match the authenticated peer or local device")]
    UnexpectedSource,
    #[error("IP destination address does not match this device")]
    UnexpectedDestination,
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
    validate_outbound_packet(packet, local_ipv4, None, mtu)
}

pub fn validate_inbound_ipv4(
    packet: &[u8],
    local_ipv4: Ipv4Addr,
    expected_peer_ipv4: Ipv4Addr,
    mtu: usize,
) -> Result<(), Ipv4PacketError> {
    validate_inbound_packet(
        packet,
        IpAddr::V4(local_ipv4),
        None,
        IpAddr::V4(expected_peer_ipv4),
        mtu,
    )
}

pub fn validate_outbound_packet(
    packet: &[u8],
    local_ipv4: Ipv4Addr,
    local_ipv6: Option<Ipv6Addr>,
    mtu: usize,
) -> Result<(), IpPacketError> {
    validate_ip_header(packet, mtu)?;
    let (source, _) = packet_addresses(packet)?;
    let local_matches = match source {
        IpAddr::V4(source) => source == local_ipv4,
        IpAddr::V6(source) => Some(source) == local_ipv6,
    };
    if !local_matches {
        return Err(IpPacketError::UnexpectedSource);
    }
    Ok(())
}

pub fn validate_inbound_packet(
    packet: &[u8],
    local_ipv4: IpAddr,
    local_ipv6: Option<IpAddr>,
    expected_peer: IpAddr,
    mtu: usize,
) -> Result<(), IpPacketError> {
    validate_ip_header(packet, mtu)?;
    let (source, destination) = packet_addresses(packet)?;
    if source != expected_peer {
        return Err(IpPacketError::UnexpectedSource);
    }
    let expected_local = match destination {
        IpAddr::V4(_) => Some(local_ipv4),
        IpAddr::V6(_) => local_ipv6,
    };
    if expected_local != Some(destination) {
        return Err(IpPacketError::UnexpectedDestination);
    }
    Ok(())
}

pub fn packet_addresses(packet: &[u8]) -> Result<(IpAddr, IpAddr), IpPacketError> {
    match packet.first().map(|version| version >> 4) {
        Some(4) if packet.len() >= IPV4_MIN_HEADER_LEN => Ok((
            IpAddr::V4(ipv4_source(packet)),
            IpAddr::V4(ipv4_destination(packet)),
        )),
        Some(6) if packet.len() >= IPV6_MIN_HEADER_LEN => Ok((
            IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&packet[8..24]).map_err(|_| IpPacketError::TruncatedHeader)?,
            )),
            IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&packet[24..40])
                    .map_err(|_| IpPacketError::TruncatedHeader)?,
            )),
        )),
        Some(4 | 6) => Err(IpPacketError::TruncatedHeader),
        _ => Err(IpPacketError::WrongVersion),
    }
}

fn validate_ip_header(packet: &[u8], mtu: usize) -> Result<(), IpPacketError> {
    match packet.first().map(|version| version >> 4) {
        Some(4) => validate_ipv4_header(packet, mtu),
        Some(6) => {
            if packet.len() < IPV6_MIN_HEADER_LEN {
                return Err(IpPacketError::TruncatedHeader);
            }
            let payload_length = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
            let total_length = IPV6_MIN_HEADER_LEN + payload_length;
            if total_length != packet.len() {
                return Err(IpPacketError::InvalidTotalLength);
            }
            if total_length > mtu {
                return Err(IpPacketError::MtuExceeded);
            }
            Ok(())
        }
        _ => Err(IpPacketError::WrongVersion),
    }
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

    fn ipv6_packet(source: Ipv6Addr, destination: Ipv6Addr, payload_length: usize) -> Vec<u8> {
        let mut packet = vec![0; IPV6_MIN_HEADER_LEN + payload_length];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(payload_length as u16).to_be_bytes());
        packet[6] = 17;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&source.octets());
        packet[24..40].copy_from_slice(&destination.octets());
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
        config.mtu = 9001;
        assert_eq!(
            config
                .validate()
                .expect_err("MTU exceeds packet safety limit")
                .kind(),
            io::ErrorKind::InvalidInput
        );
        config.mtu = 575;
        assert_eq!(
            config.validate().expect_err("bad MTU").kind(),
            io::ErrorKind::InvalidInput
        );
        config.mtu = 1280;
        let config = config.with_ipv6("fd12:3456::1".parse().unwrap(), 129);
        assert_eq!(
            config.validate().expect_err("bad IPv6 prefix").kind(),
            io::ErrorKind::InvalidInput
        );
        let config =
            TunConfig::ipv4(Ipv4Addr::LOCALHOST, 24).with_ipv6("fd12:3456::1".parse().unwrap(), 64);
        let mut config = config;
        config.mtu = 1279;
        assert_eq!(
            config
                .validate()
                .expect_err("IPv6 MTU below minimum")
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[tokio::test]
    #[ignore = "requires permission to create and configure an OS TUN interface"]
    async fn privileged_linux_tun_assigns_addresses_mtu_and_cleans_up() {
        let pid = std::process::id();
        let subnet = (pid % 250 + 1) as u8;
        let address_a = Ipv4Addr::new(10, 253, subnet, 1);
        let address_a_v6 = Ipv6Addr::new(0xfd18, 0x253, u16::from(subnet), 0, 0, 0, 0, 1);
        let interface_name = format!("mtun{}", pid % 100_000);
        let mut config = TunConfig::ipv4(address_a, 32).with_ipv6(address_a_v6, 128);
        config.name = Some(interface_name.clone());
        let device = TunDevice::create(config).expect("create privileged Linux TUN interface");
        assert_eq!(device.local_ipv4(), address_a);
        assert_eq!(device.local_ipv6(), Some(address_a_v6));
        assert_eq!(device.mtu(), usize::from(DEFAULT_TUN_MTU));
        assert_eq!(device.name().expect("read TUN name"), interface_name);

        let up = std::process::Command::new("ip")
            .args(["link", "set", "dev", &interface_name, "up"])
            .output()
            .expect("bring TUN interface up");
        assert!(
            up.status.success(),
            "unable to bring TUN interface up: {}",
            String::from_utf8_lossy(&up.stderr)
        );

        let addresses = std::process::Command::new("ip")
            .args(["-o", "address", "show", "dev", &interface_name])
            .output()
            .expect("inspect assigned TUN addresses with iproute2");
        assert!(
            addresses.status.success(),
            "iproute2 address inspection failed: {}",
            String::from_utf8_lossy(&addresses.stderr)
        );
        let addresses = String::from_utf8_lossy(&addresses.stdout);
        assert!(addresses.contains(&format!("{address_a}/32")));
        assert!(addresses.contains(&format!("{address_a_v6}/128")));

        let link = std::process::Command::new("ip")
            .args(["-o", "link", "show", "dev", &interface_name])
            .output()
            .expect("inspect TUN MTU with iproute2");
        assert!(link.status.success());
        assert!(String::from_utf8_lossy(&link.stdout).contains("mtu 1280"));

        let peer_address = Ipv4Addr::new(10, 253, subnet, 2);
        device
            .write_inbound_packet(&packet(peer_address, address_a, 28), peer_address)
            .await
            .expect("write authenticated peer packet to the OS TUN interface");

        let peer_address_v6 = Ipv6Addr::new(0xfd18, 0x253, u16::from(subnet), 0, 0, 0, 0, 2);
        let runner = crate::routing::SystemRouteRunner;
        let ipv4_lease = crate::routing::install_peer_route(
            &runner,
            crate::routing::RoutingPlatform::Linux,
            &interface_name,
            peer_address,
        )
        .await
        .expect("install IPv4 peer host route");
        let ipv6_lease = crate::routing::install_peer_ipv6_route(
            &runner,
            crate::routing::RoutingPlatform::Linux,
            &interface_name,
            peer_address_v6,
        )
        .await
        .expect("install IPv6 peer host route");

        let overlay_socket = tokio::net::UdpSocket::bind((address_a, 0))
            .await
            .expect("bind UDP socket to assigned TUN address");
        overlay_socket
            .send_to(b"outbound through peer route", (peer_address, 4242))
            .await
            .expect("send UDP datagram to peer overlay address");
        let mut outbound = vec![0; device.mtu()];
        let outbound_len = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            device.device.recv(&mut outbound),
        )
        .await
        .expect("kernel-routed datagram reaches the TUN")
        .expect("read packet from the TUN");
        outbound.truncate(outbound_len);
        let (outbound_source, outbound_destination) =
            packet_addresses(&outbound).expect("parse outbound TUN packet addresses");
        assert_eq!(
            outbound_source,
            IpAddr::V4(address_a),
            "unexpected kernel-generated TUN packet: {outbound:02x?}"
        );
        assert_eq!(outbound_destination, IpAddr::V4(peer_address));
        assert_eq!(outbound[9], 17, "expected an IPv4 UDP packet");
        validate_outbound_packet(&outbound, address_a, Some(address_a_v6), device.mtu())
            .expect("validate local-originated TUN packet");

        for (family, peer) in [
            ("-4", peer_address.to_string()),
            ("-6", peer_address_v6.to_string()),
        ] {
            let route = std::process::Command::new("ip")
                .args([
                    family,
                    "route",
                    "show",
                    &format!("{peer}/{}", if family == "-4" { 32 } else { 128 }),
                ])
                .output()
                .expect("inspect installed peer route");
            assert!(route.status.success());
            let route = String::from_utf8_lossy(&route.stdout);
            assert!(
                route.contains(&format!("dev {interface_name}")),
                "unexpected route: {route}"
            );
        }

        ipv4_lease
            .remove(&runner)
            .await
            .expect("remove IPv4 peer route");
        ipv6_lease
            .remove(&runner)
            .await
            .expect("remove IPv6 peer route");
        for (family, prefix) in [
            ("-4", format!("{peer_address}/32")),
            ("-6", format!("{peer_address_v6}/128")),
        ] {
            let route = std::process::Command::new("ip")
                .args([family, "route", "show", &prefix])
                .output()
                .expect("verify peer route cleanup");
            assert!(route.status.success());
            assert!(
                route.stdout.is_empty(),
                "route still exists after lease removal: {}",
                String::from_utf8_lossy(&route.stdout)
            );
        }

        drop(device);
        let removed = std::process::Command::new("ip")
            .args(["link", "show", "dev", &interface_name])
            .output()
            .expect("verify TUN interface cleanup");
        assert!(
            !removed.status.success(),
            "dropping TunDevice should remove its kernel interface"
        );
    }

    #[test]
    fn ipv6_packet_boundary_checks_length_mtu_and_peer_addresses() {
        let local: Ipv6Addr = "fd12:3456::2".parse().unwrap();
        let peer: Ipv6Addr = "fd12:3456::3".parse().unwrap();
        let valid = ipv6_packet(peer, local, 8);
        validate_outbound_packet(
            &ipv6_packet(local, peer, 8),
            Ipv4Addr::LOCALHOST,
            Some(local),
            1280,
        )
        .expect("valid local IPv6 packet");
        validate_inbound_packet(
            &valid,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            Some(IpAddr::V6(local)),
            IpAddr::V6(peer),
            1280,
        )
        .expect("valid peer IPv6 packet");
        assert_eq!(
            packet_addresses(&valid).unwrap(),
            (IpAddr::V6(peer), IpAddr::V6(local))
        );
        assert_eq!(
            validate_ip_header(&valid, 40),
            Err(IpPacketError::MtuExceeded)
        );
        let mut bad_length = valid.clone();
        bad_length[5] = 7;
        assert_eq!(
            validate_ip_header(&bad_length, 1280),
            Err(IpPacketError::InvalidTotalLength)
        );
        assert_eq!(
            validate_outbound_packet(
                &ipv6_packet(peer, local, 8),
                Ipv4Addr::LOCALHOST,
                Some(local),
                1280
            ),
            Err(IpPacketError::UnexpectedSource)
        );
        assert_eq!(
            validate_inbound_packet(
                &ipv6_packet(local, peer, 8),
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                Some(IpAddr::V6(local)),
                IpAddr::V6(peer),
                1280,
            ),
            Err(IpPacketError::UnexpectedSource)
        );
    }
}
