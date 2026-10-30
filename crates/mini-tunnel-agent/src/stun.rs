//! Minimal RFC 8489 STUN Binding client for server-reflexive candidate discovery.

use std::{net::SocketAddr, time::Duration};

use thiserror::Error;
use tokio::net::UdpSocket;

const HEADER_LEN: usize = 20;
const MAGIC_COOKIE: u32 = 0x2112_A442;
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS: u16 = 0x0101;
const MAPPED_ADDRESS: u16 = 0x0001;
const XOR_MAPPED_ADDRESS: u16 = 0x0020;
const USERNAME: u16 = 0x0006;
const MAX_STUN_MESSAGE: usize = 1500;
const RETRIES: usize = 3;
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Debug, Error)]
pub enum StunError {
    #[error("STUN I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("STUN server did not respond after {RETRIES} attempts")]
    Timeout,
    #[error("invalid STUN response: {0}")]
    InvalidResponse(&'static str),
    #[error("secure random generation failed")]
    Random,
}

/// Return whether a UDP payload has a complete RFC 8489 STUN message envelope.
///
/// This classifier is deliberately stricter than checking only the STUN magic cookie: it also
/// validates the reserved top bits and exact padded message length so malformed packets are not
/// diverted away from Quinn by a future shared-socket demultiplexer.
pub(crate) fn is_stun_datagram(message: &[u8]) -> bool {
    message.len() >= HEADER_LEN
        && message[0] & 0b1100_0000 == 0
        && usize::from(u16::from_be_bytes([message[2], message[3]])) == message.len() - HEADER_LEN
        && message[2] & 0b0000_0011 == 0
        && message[4..8] == MAGIC_COOKIE.to_be_bytes()
}

/// Extract the ICE USERNAME attribute from a complete STUN message.
/// The caller uses the recipient ufrag after the colon to route a request to one peer agent.
pub(crate) fn ice_username(message: &[u8]) -> Option<&str> {
    if !is_stun_datagram(message) {
        return None;
    }
    let mut offset = HEADER_LEN;
    let mut username = None;
    let mut username_seen = false;
    while offset < message.len() {
        let attribute_type = u16::from_be_bytes([message[offset], message[offset + 1]]);
        let length = usize::from(u16::from_be_bytes([
            message[offset + 2],
            message[offset + 3],
        ]));
        let value_start = offset + 4;
        let value_end = value_start.checked_add(length)?;
        let padded_end = value_start.checked_add((length + 3) & !3)?;
        if value_end > message.len() || padded_end > message.len() {
            return None;
        }
        if attribute_type == USERNAME {
            if username_seen {
                return None;
            }
            username_seen = true;
            username = std::str::from_utf8(&message[value_start..value_end]).ok();
        }
        offset = padded_end;
    }
    username
}

/// Ask a STUN server for the address mapped from this UDP socket.
///
/// The socket is borrowed and remains bound to the same port for its caller to hand to QUIC.
pub async fn discover_mapped_address(
    socket: &UdpSocket,
    server: SocketAddr,
) -> Result<SocketAddr, StunError> {
    let mut transaction_id = [0_u8; 12];
    getrandom::fill(&mut transaction_id).map_err(|_| StunError::Random)?;
    let request = binding_request(transaction_id);
    let mut response = [0_u8; MAX_STUN_MESSAGE];

    for _ in 0..RETRIES {
        socket.send_to(&request, server).await?;
        let attempt = tokio::time::timeout(RESPONSE_TIMEOUT, async {
            loop {
                let (length, source) = socket.recv_from(&mut response).await?;
                if source != server {
                    continue;
                }
                return parse_binding_response(&response[..length], transaction_id)
                    .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error));
            }
        })
        .await;
        match attempt {
            Ok(Ok(address)) => return Ok(address),
            Ok(Err(error)) if error.kind() == std::io::ErrorKind::InvalidData => {
                return Err(StunError::InvalidResponse("response failed validation"));
            }
            Ok(Err(error)) => return Err(error.into()),
            Err(_) => continue,
        }
    }
    Err(StunError::Timeout)
}

fn binding_request(transaction_id: [u8; 12]) -> [u8; HEADER_LEN] {
    let mut request = [0_u8; HEADER_LEN];
    request[..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
    request[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    request[8..].copy_from_slice(&transaction_id);
    request
}

fn parse_binding_response(
    message: &[u8],
    expected_transaction_id: [u8; 12],
) -> Result<SocketAddr, StunError> {
    if message.len() < HEADER_LEN {
        return Err(StunError::InvalidResponse("truncated header"));
    }
    if u16::from_be_bytes([message[0], message[1]]) != BINDING_SUCCESS {
        return Err(StunError::InvalidResponse("not a Binding success response"));
    }
    if !is_stun_datagram(message) {
        return Err(StunError::InvalidResponse("invalid STUN message envelope"));
    }
    if message[8..20] != expected_transaction_id {
        return Err(StunError::InvalidResponse("transaction ID mismatch"));
    }

    let mut mapped = None;
    let mut xor_mapped = None;
    let mut offset = HEADER_LEN;
    while offset < message.len() {
        if message.len() - offset < 4 {
            return Err(StunError::InvalidResponse("truncated attribute header"));
        }
        let attribute_type = u16::from_be_bytes([message[offset], message[offset + 1]]);
        let attribute_len = usize::from(u16::from_be_bytes([
            message[offset + 2],
            message[offset + 3],
        ]));
        let value_start = offset + 4;
        let value_end = value_start
            .checked_add(attribute_len)
            .ok_or(StunError::InvalidResponse("attribute length overflow"))?;
        let padded_end = value_start
            .checked_add((attribute_len + 3) & !3)
            .ok_or(StunError::InvalidResponse("attribute padding overflow"))?;
        if value_end > message.len() || padded_end > message.len() {
            return Err(StunError::InvalidResponse("truncated attribute value"));
        }
        let value = &message[value_start..value_end];
        match attribute_type {
            MAPPED_ADDRESS => mapped = Some(parse_address(value, false, expected_transaction_id)?),
            XOR_MAPPED_ADDRESS => {
                xor_mapped = Some(parse_address(value, true, expected_transaction_id)?)
            }
            _ => {}
        }
        offset = padded_end;
    }
    let address = xor_mapped.or(mapped).ok_or(StunError::InvalidResponse(
        "missing mapped address attribute",
    ))?;
    if address.port() == 0 || address.ip().is_unspecified() || address.ip().is_multicast() {
        return Err(StunError::InvalidResponse("mapped address is not usable"));
    }
    Ok(address)
}

fn parse_address(
    value: &[u8],
    xor: bool,
    transaction_id: [u8; 12],
) -> Result<SocketAddr, StunError> {
    if value.len() < 4 || value[0] != 0 {
        return Err(StunError::InvalidResponse("invalid mapped address"));
    }
    let family = value[1];
    let mut port = u16::from_be_bytes([value[2], value[3]]);
    if xor {
        port ^= (MAGIC_COOKIE >> 16) as u16;
    }
    match (family, value.len()) {
        (0x01, 8) => {
            let mut octets: [u8; 4] = value[4..8]
                .try_into()
                .map_err(|_| StunError::InvalidResponse("invalid IPv4 mapped address"))?;
            if xor {
                for (byte, mask) in octets.iter_mut().zip(MAGIC_COOKIE.to_be_bytes()) {
                    *byte ^= mask;
                }
            }
            Ok(SocketAddr::from((octets, port)))
        }
        (0x02, 20) => {
            let mut octets: [u8; 16] = value[4..20]
                .try_into()
                .map_err(|_| StunError::InvalidResponse("invalid IPv6 mapped address"))?;
            if xor {
                for (byte, mask) in octets
                    .iter_mut()
                    .zip(MAGIC_COOKIE.to_be_bytes().into_iter().chain(transaction_id))
                {
                    *byte ^= mask;
                }
            }
            Ok(SocketAddr::from((octets, port)))
        }
        _ => Err(StunError::InvalidResponse(
            "unsupported mapped address family",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    fn bind_udp_in_namespace(namespace: &str, address: SocketAddr) -> UdpSocket {
        use std::os::fd::AsRawFd;

        let namespace = namespace.to_owned();
        let socket = std::thread::spawn(move || {
            let original = std::fs::File::open("/proc/self/ns/net").expect("open original netns");
            let target = std::fs::File::open(format!("/var/run/netns/{namespace}"))
                .expect("open target netns");
            // Keep setns off Tokio worker threads; only this short-lived setup thread changes ns.
            let result = unsafe { libc::setns(target.as_raw_fd(), libc::CLONE_NEWNET) };
            assert_eq!(
                result,
                0,
                "enter {namespace}: {}",
                std::io::Error::last_os_error()
            );
            let socket = std::net::UdpSocket::bind(address).expect("bind namespaced UDP socket");
            socket.set_nonblocking(true).expect("set nonblocking");
            let result = unsafe { libc::setns(original.as_raw_fd(), libc::CLONE_NEWNET) };
            assert_eq!(
                result,
                0,
                "restore netns: {}",
                std::io::Error::last_os_error()
            );
            socket
        })
        .join()
        .expect("namespace socket setup thread");
        UdpSocket::from_std(socket).expect("adopt namespaced UDP socket")
    }

    #[cfg(target_os = "linux")]
    struct SnatTopology {
        client: String,
        router: String,
        server: String,
    }

    #[cfg(target_os = "linux")]
    impl SnatTopology {
        fn create() -> Self {
            fn run(args: &[&str]) {
                let output = std::process::Command::new("ip")
                    .args(args)
                    .output()
                    .expect("run iproute2");
                assert!(
                    output.status.success(),
                    "ip {args:?}: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }

            fn router(namespace: &str, command: &str, args: &[&str]) {
                let output = std::process::Command::new("ip")
                    .args(["netns", "exec", namespace, command])
                    .args(args)
                    .output()
                    .expect("run NAT router command");
                assert!(
                    output.status.success(),
                    "{command} {args:?}: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }

            let suffix = format!("{}", std::process::id() % 10_000_000);
            let client = format!("mtc{suffix}");
            let router_ns = format!("mtr{suffix}");
            let server = format!("mts{suffix}");
            let client_if = format!("mc{}", suffix.get(..5).unwrap_or(&suffix));
            let router_in = format!("ri{}", suffix.get(..5).unwrap_or(&suffix));
            let router_out = format!("ro{}", suffix.get(..5).unwrap_or(&suffix));
            let server_if = format!("ms{}", suffix.get(..5).unwrap_or(&suffix));
            let topology = Self {
                client: client.clone(),
                router: router_ns.clone(),
                server: server.clone(),
            };
            run(&["netns", "add", &client]);
            run(&["netns", "add", &router_ns]);
            run(&["netns", "add", &server]);
            run(&[
                "link", "add", &client_if, "type", "veth", "peer", "name", &router_in,
            ]);
            run(&[
                "link",
                "add",
                &router_out,
                "type",
                "veth",
                "peer",
                "name",
                &server_if,
            ]);
            run(&["link", "set", &client_if, "netns", &client]);
            run(&["link", "set", &router_in, "netns", &router_ns]);
            run(&["link", "set", &router_out, "netns", &router_ns]);
            run(&["link", "set", &server_if, "netns", &server]);

            for namespace in [&client, &router_ns, &server] {
                run(&["-n", namespace, "link", "set", "lo", "up"]);
            }
            let addresses = [
                (&client, &client_if, "10.77.0.2/24"),
                (&router_ns, &router_in, "10.77.0.1/24"),
                (&router_ns, &router_out, "198.18.0.1/24"),
                (&server, &server_if, "198.18.0.2/24"),
            ];
            for (namespace, device, address) in addresses {
                run(&["-n", namespace, "address", "add", address, "dev", device]);
                run(&["-n", namespace, "link", "set", "dev", device, "up"]);
            }
            run(&["-n", &client, "route", "add", "default", "via", "10.77.0.1"]);
            router(&router_ns, "sysctl", &["-w", "net.ipv4.ip_forward=1"]);
            router(
                &router_ns,
                "iptables",
                &[
                    "-t",
                    "nat",
                    "-A",
                    "POSTROUTING",
                    "-o",
                    &router_out,
                    "-j",
                    "MASQUERADE",
                ],
            );
            router(
                &router_ns,
                "iptables",
                &[
                    "-A",
                    "FORWARD",
                    "-i",
                    &router_in,
                    "-o",
                    &router_out,
                    "-j",
                    "ACCEPT",
                ],
            );
            router(
                &router_ns,
                "iptables",
                &[
                    "-A",
                    "FORWARD",
                    "-i",
                    &router_out,
                    "-o",
                    &router_in,
                    "-m",
                    "conntrack",
                    "--ctstate",
                    "RELATED,ESTABLISHED",
                    "-j",
                    "ACCEPT",
                ],
            );
            topology
        }
    }

    #[cfg(target_os = "linux")]
    impl Drop for SnatTopology {
        fn drop(&mut self) {
            for namespace in [&self.client, &self.router, &self.server] {
                let _ = std::process::Command::new("ip")
                    .args(["netns", "del", namespace])
                    .status();
            }
        }
    }

    #[cfg(target_os = "linux")]
    struct DualSnatTopology {
        client_a: String,
        router_a: String,
        client_b: String,
        router_b: String,
        bridge: String,
    }

    #[cfg(target_os = "linux")]
    impl DualSnatTopology {
        fn create() -> Self {
            fn run(args: &[&str]) {
                let output = std::process::Command::new("ip")
                    .args(args)
                    .output()
                    .expect("run iproute2");
                assert!(
                    output.status.success(),
                    "ip {args:?}: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }

            fn router(namespace: &str, command: &str, args: &[&str]) {
                let output = std::process::Command::new("ip")
                    .args(["netns", "exec", namespace, command])
                    .args(args)
                    .output()
                    .expect("run NAT router command");
                assert!(
                    output.status.success(),
                    "{command} {args:?}: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }

            let suffix = uuid::Uuid::new_v4().simple().to_string();
            let suffix = &suffix[..8];
            let client_a = format!("mda{suffix}");
            let router_a = format!("mdra{suffix}");
            let client_b = format!("mdb{suffix}");
            let router_b = format!("mdrb{suffix}");
            let bridge = format!("mbr{suffix}");
            let client_a_if = format!("ca{suffix}");
            let router_a_lan = format!("al{suffix}");
            let router_a_wan = format!("aw{suffix}");
            let bridge_a_if = format!("ba{suffix}");
            let client_b_if = format!("cb{suffix}");
            let router_b_lan = format!("bl{suffix}");
            let router_b_wan = format!("bw{suffix}");
            let bridge_b_if = format!("bb{suffix}");
            let topology = Self {
                client_a: client_a.clone(),
                router_a: router_a.clone(),
                client_b: client_b.clone(),
                router_b: router_b.clone(),
                bridge: bridge.clone(),
            };

            run(&["netns", "add", &client_a]);
            run(&["netns", "add", &router_a]);
            run(&["netns", "add", &client_b]);
            run(&["netns", "add", &router_b]);
            run(&["link", "add", &bridge, "type", "bridge"]);
            run(&["address", "add", "198.18.0.254/24", "dev", &bridge]);
            run(&["link", "set", &bridge, "up"]);

            for (client_if, router_lan) in
                [(&client_a_if, &router_a_lan), (&client_b_if, &router_b_lan)]
            {
                run(&[
                    "link", "add", client_if, "type", "veth", "peer", "name", router_lan,
                ]);
            }
            for (bridge_if, router_wan) in
                [(&bridge_a_if, &router_a_wan), (&bridge_b_if, &router_b_wan)]
            {
                run(&[
                    "link", "add", bridge_if, "type", "veth", "peer", "name", router_wan,
                ]);
            }
            for (device, namespace) in [
                (&client_a_if, &client_a),
                (&router_a_lan, &router_a),
                (&router_a_wan, &router_a),
                (&client_b_if, &client_b),
                (&router_b_lan, &router_b),
                (&router_b_wan, &router_b),
            ] {
                run(&["link", "set", device, "netns", namespace]);
            }
            for bridge_if in [&bridge_a_if, &bridge_b_if] {
                run(&["link", "set", bridge_if, "master", &bridge]);
                run(&["link", "set", bridge_if, "up"]);
            }

            for namespace in [&client_a, &router_a, &client_b, &router_b] {
                run(&["-n", namespace, "link", "set", "lo", "up"]);
            }
            for (namespace, device, address) in [
                (&client_a, &client_a_if, "10.77.1.2/24"),
                (&router_a, &router_a_lan, "10.77.1.1/24"),
                (&router_a, &router_a_wan, "198.18.0.1/24"),
                (&client_b, &client_b_if, "10.78.1.2/24"),
                (&router_b, &router_b_lan, "10.78.1.1/24"),
                (&router_b, &router_b_wan, "198.18.0.2/24"),
            ] {
                run(&["-n", namespace, "address", "add", address, "dev", device]);
                run(&["-n", namespace, "link", "set", "dev", device, "up"]);
            }
            run(&[
                "-n",
                &client_a,
                "route",
                "add",
                "default",
                "via",
                "10.77.1.1",
            ]);
            run(&[
                "-n",
                &client_b,
                "route",
                "add",
                "default",
                "via",
                "10.78.1.1",
            ]);
            run(&[
                "-n",
                &client_a,
                "route",
                "add",
                "unreachable",
                "10.78.1.0/24",
            ]);
            run(&[
                "-n",
                &client_b,
                "route",
                "add",
                "unreachable",
                "10.77.1.0/24",
            ]);

            for (namespace, inside, outside) in [
                (&router_a, &router_a_lan, &router_a_wan),
                (&router_b, &router_b_lan, &router_b_wan),
            ] {
                router(namespace, "sysctl", &["-w", "net.ipv4.ip_forward=1"]);
                router(
                    namespace,
                    "iptables",
                    &[
                        "-t",
                        "nat",
                        "-A",
                        "POSTROUTING",
                        "-o",
                        outside,
                        "-j",
                        "MASQUERADE",
                    ],
                );
                router(
                    namespace,
                    "iptables",
                    &["-A", "FORWARD", "-i", inside, "-o", outside, "-j", "ACCEPT"],
                );
                router(
                    namespace,
                    "iptables",
                    &[
                        "-A",
                        "FORWARD",
                        "-i",
                        outside,
                        "-o",
                        inside,
                        "-m",
                        "conntrack",
                        "--ctstate",
                        "RELATED,ESTABLISHED",
                        "-j",
                        "ACCEPT",
                    ],
                );
            }
            topology
        }
    }

    #[cfg(target_os = "linux")]
    impl Drop for DualSnatTopology {
        fn drop(&mut self) {
            for namespace in [
                &self.client_a,
                &self.router_a,
                &self.client_b,
                &self.router_b,
            ] {
                let _ = std::process::Command::new("ip")
                    .args(["netns", "del", namespace])
                    .status();
            }
            let _ = std::process::Command::new("ip")
                .args(["link", "del", &self.bridge])
                .status();
        }
    }

    fn mapped_response(address: SocketAddr, transaction_id: [u8; 12]) -> Vec<u8> {
        let mut value = vec![0, if address.is_ipv4() { 1 } else { 2 }];
        let port = address.port() ^ (MAGIC_COOKIE >> 16) as u16;
        value.extend_from_slice(&port.to_be_bytes());
        match address.ip() {
            std::net::IpAddr::V4(ip) => {
                value.extend(
                    ip.octets()
                        .into_iter()
                        .zip(MAGIC_COOKIE.to_be_bytes())
                        .map(|(byte, mask)| byte ^ mask),
                );
            }
            std::net::IpAddr::V6(ip) => {
                value.extend(
                    ip.octets()
                        .into_iter()
                        .zip(MAGIC_COOKIE.to_be_bytes().into_iter().chain(transaction_id))
                        .map(|(byte, mask)| byte ^ mask),
                );
            }
        }
        let mut response = vec![0; HEADER_LEN];
        response[..2].copy_from_slice(&BINDING_SUCCESS.to_be_bytes());
        response[2..4].copy_from_slice(&(4_u16 + value.len() as u16).to_be_bytes());
        response[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
        response[8..20].copy_from_slice(&transaction_id);
        response.extend_from_slice(&XOR_MAPPED_ADDRESS.to_be_bytes());
        response.extend_from_slice(&(value.len() as u16).to_be_bytes());
        response.extend(value);
        response
    }

    #[test]
    fn parses_xor_mapped_ipv4_and_ipv6_addresses() {
        let transaction = [9; 12];
        for expected in [
            "198.51.100.4:45678".parse().expect("IPv4 address"),
            "[2001:db8::42]:45678".parse().expect("IPv6 address"),
        ] {
            let response = mapped_response(expected, transaction);
            assert_eq!(
                parse_binding_response(&response, transaction).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn stun_demux_classifier_accepts_complete_envelopes_only() {
        let request = binding_request([7; 12]);
        assert!(is_stun_datagram(&request));

        let mut malformed_cookie = request;
        malformed_cookie[4] ^= 0xff;
        assert!(!is_stun_datagram(&malformed_cookie));

        let mut malformed_length = request;
        malformed_length[3] = 4;
        assert!(!is_stun_datagram(&malformed_length));

        let mut reserved_bits = request;
        reserved_bits[0] = 0x40;
        assert!(!is_stun_datagram(&reserved_bits));
        assert!(!is_stun_datagram(&[0xc0; HEADER_LEN]));
        assert!(!is_stun_datagram(&request[..HEADER_LEN - 1]));
    }

    #[test]
    fn rejects_wrong_transaction_truncated_attributes_and_bad_lengths() {
        let transaction = [9; 12];
        let address = "198.51.100.4:45678".parse().expect("IPv4 address");
        let response = mapped_response(address, transaction);
        assert!(matches!(
            parse_binding_response(&response, [8; 12]),
            Err(StunError::InvalidResponse("transaction ID mismatch"))
        ));
        assert!(parse_binding_response(&response[..response.len() - 1], transaction).is_err());
        let mut bad_length = response;
        bad_length[2..4].copy_from_slice(&0_u16.to_be_bytes());
        assert!(parse_binding_response(&bad_length, transaction).is_err());
    }

    #[tokio::test]
    async fn binding_request_discovers_mapping_using_existing_socket() {
        let server = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind fake STUN");
        let server_address = server.local_addr().expect("STUN address");
        let responder = tokio::spawn(async move {
            let mut request = [0; HEADER_LEN];
            let (length, peer) = server
                .recv_from(&mut request)
                .await
                .expect("receive request");
            assert_eq!(length, HEADER_LEN);
            assert_eq!(
                u16::from_be_bytes([request[0], request[1]]),
                BINDING_REQUEST
            );
            let transaction: [u8; 12] = request[8..20].try_into().expect("transaction ID");
            let mapped = SocketAddr::from(([198, 51, 100, 8], peer.port()));
            server
                .send_to(&mapped_response(mapped, transaction), peer)
                .await
                .expect("send STUN response");
            (peer.port(), mapped)
        });
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind client");
        let local_port = socket.local_addr().expect("local address").port();
        let mapped = discover_mapped_address(&socket, server_address)
            .await
            .expect("discover mapping");
        let (server_seen_port, expected) = responder.await.expect("STUN responder");
        assert_eq!(server_seen_port, local_port);
        assert_eq!(mapped, expected);
        assert_eq!(
            socket.local_addr().expect("socket remains bound").port(),
            local_port
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires root privileges, iproute2, iptables, and network namespaces"]
    async fn privileged_linux_snat_discovers_server_reflexive_address_on_same_socket() {
        let _topology = SnatTopology::create();
        let server = bind_udp_in_namespace(
            &_topology.server,
            "198.18.0.2:3478".parse().expect("server address"),
        );
        let peer = bind_udp_in_namespace(
            &_topology.server,
            "198.18.0.2:0".parse().expect("peer address"),
        );
        let client = bind_udp_in_namespace(
            &_topology.client,
            "0.0.0.0:0".parse().expect("client bind address"),
        );
        let server_address = server.local_addr().expect("server socket address");
        let peer_address = peer.local_addr().expect("peer socket address");
        let responder = tokio::spawn(async move {
            let mut request = [0; HEADER_LEN];
            let (length, peer) =
                tokio::time::timeout(Duration::from_secs(5), server.recv_from(&mut request))
                    .await
                    .expect("NAT forwarded STUN request")
                    .expect("receive STUN request");
            assert_eq!(length, HEADER_LEN);
            assert_eq!(peer.ip(), "198.18.0.1".parse::<std::net::IpAddr>().unwrap());
            let transaction = request[8..20].try_into().expect("transaction ID");
            server
                .send_to(&mapped_response(peer, transaction), peer)
                .await
                .expect("send mapped response through NAT");
            peer
        });

        let local = client.local_addr().expect("client local address");
        let mapped = discover_mapped_address(&client, server_address)
            .await
            .expect("discover translated mapping");
        let server_observed = responder.await.expect("STUN server response");
        assert_eq!(mapped, server_observed);
        assert_eq!(
            mapped.ip(),
            "198.18.0.1".parse::<std::net::IpAddr>().unwrap()
        );
        assert_ne!(mapped.port(), 0);
        assert_eq!(client.local_addr().expect("socket remains bound"), local);

        let private_candidate: SocketAddr = format!("10.77.0.2:{}", local.port())
            .parse()
            .expect("private host candidate");
        let host_candidate = crate::candidate::SignaledCandidate {
            address: private_candidate,
            transport: crate::candidate::CandidateTransport::Udp,
            candidate_type: crate::candidate::CandidateType::Host,
        };
        let mapped_candidate = crate::candidate::SignaledCandidate {
            address: mapped,
            transport: crate::candidate::CandidateTransport::Udp,
            candidate_type: crate::candidate::CandidateType::ServerReflexive {
                related_address: private_candidate,
            },
        };
        let peer_candidate = crate::candidate::SignaledCandidate {
            address: peer_address,
            transport: crate::candidate::CandidateTransport::Udp,
            candidate_type: crate::candidate::CandidateType::Host,
        };
        let private_route_error = peer
            .send_to(b"x", private_candidate)
            .await
            .expect_err("public peer has no route to the private candidate");
        assert_eq!(
            private_route_error.kind(),
            std::io::ErrorKind::NetworkUnreachable
        );
        let credentials_client = crate::ice::generate_ice_credentials(1).unwrap();
        let credentials_peer = crate::ice::generate_ice_credentials(1).unwrap();
        let mut driver_client = crate::ice::IceAgentDriver::for_peer_with_candidates_on_socket(
            local,
            &credentials_client,
            &credentials_peer,
            &[host_candidate, mapped_candidate],
            &[peer_candidate],
            true,
            std::time::Instant::now(),
        )
        .expect("construct ICE client behind SNAT");
        let mut driver_peer = crate::ice::IceAgentDriver::for_peer_with_candidates_on_socket(
            peer_address,
            &credentials_peer,
            &credentials_client,
            &[peer_candidate],
            &[host_candidate, mapped_candidate],
            false,
            std::time::Instant::now(),
        )
        .expect("construct public ICE peer");

        let mut failed_candidates = Vec::new();
        for _ in 0..600 {
            let now = std::time::Instant::now();
            driver_client.handle_timeout(now).expect("tick client ICE");
            driver_peer
                .handle_timeout(now)
                .expect("tick public peer ICE");
            for transmit in driver_client.poll_transmits() {
                client
                    .send_to(&transmit.message, transmit.transport.peer_addr)
                    .await
                    .expect("send client ICE check");
            }
            for transmit in driver_peer.poll_transmits() {
                if let Err(error) = peer
                    .send_to(&transmit.message, transmit.transport.peer_addr)
                    .await
                {
                    assert!(crate::ice::is_candidate_send_error(&error));
                    failed_candidates.push(transmit.transport.peer_addr);
                }
            }

            let mut packet = [0; MAX_STUN_MESSAGE];
            while let Ok((length, source)) = client.try_recv_from(&mut packet) {
                assert!(
                    driver_client
                        .handle_datagram(now, source, None, &packet[..length])
                        .expect("handle client ICE check")
                );
            }
            while let Ok((length, source)) = peer.try_recv_from(&mut packet) {
                assert!(
                    driver_peer
                        .handle_datagram(now, source, None, &packet[..length])
                        .expect("handle public peer ICE check")
                );
            }
            if driver_client.selected_pair().is_some() && driver_peer.selected_pair().is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let client_pair = driver_client
            .selected_pair()
            .expect("client nominates a path through SNAT");
        let peer_pair = driver_peer
            .selected_pair()
            .expect("public peer nominates the SNAT mapping");
        assert_eq!(client_pair.1, peer_address);
        assert_eq!(peer_pair.1, mapped);
        assert!(failed_candidates.contains(&private_candidate));
        client
            .send_to(b"overlay-through-snat", client_pair.1)
            .await
            .expect("send overlay payload through SNAT");
        let mut payload = [0; 64];
        let (length, source) =
            tokio::time::timeout(Duration::from_secs(1), peer.recv_from(&mut payload))
                .await
                .expect("public peer receives overlay payload")
                .expect("read overlay payload");
        assert_eq!(&payload[..length], b"overlay-through-snat");
        assert_eq!(source, mapped);
        run_dual_snat_ice_scenario().await;
    }

    #[cfg(target_os = "linux")]
    async fn run_dual_snat_ice_scenario() {
        let _topology = DualSnatTopology::create();
        let stun_server = UdpSocket::bind("198.18.0.254:3478")
            .await
            .expect("bind transit STUN server");
        let stun_address = stun_server.local_addr().expect("STUN server address");
        let responder = tokio::spawn(async move {
            for _ in 0..2 {
                let mut request = [0; HEADER_LEN];
                let (length, source) = tokio::time::timeout(
                    Duration::from_secs(5),
                    stun_server.recv_from(&mut request),
                )
                .await
                .expect("both NAT clients reach the STUN server")
                .expect("receive STUN request");
                assert_eq!(length, HEADER_LEN);
                let transaction = request[8..20].try_into().expect("transaction ID");
                stun_server
                    .send_to(&mapped_response(source, transaction), source)
                    .await
                    .expect("send mapped address response");
            }
        });

        let socket_a = bind_udp_in_namespace(
            &_topology.client_a,
            "0.0.0.0:0".parse().expect("client A wildcard address"),
        );
        let socket_b = bind_udp_in_namespace(
            &_topology.client_b,
            "0.0.0.0:0".parse().expect("client B wildcard address"),
        );
        let local_a = socket_a.local_addr().expect("client A socket address");
        let local_b = socket_b.local_addr().expect("client B socket address");
        let (mapped_a, mapped_b) = tokio::try_join!(
            discover_mapped_address(&socket_a, stun_address),
            discover_mapped_address(&socket_b, stun_address),
        )
        .expect("both clients discover NAT mappings on their tunnel sockets");
        responder.await.expect("join STUN responder");
        assert_eq!(
            mapped_a.ip(),
            "198.18.0.1".parse::<std::net::IpAddr>().unwrap()
        );
        assert_eq!(
            mapped_b.ip(),
            "198.18.0.2".parse::<std::net::IpAddr>().unwrap()
        );

        let host_a: SocketAddr = format!("10.77.1.2:{}", local_a.port())
            .parse()
            .expect("client A host candidate");
        let host_b: SocketAddr = format!("10.78.1.2:{}", local_b.port())
            .parse()
            .expect("client B host candidate");
        let candidates_a = [
            crate::candidate::SignaledCandidate {
                address: host_a,
                transport: crate::candidate::CandidateTransport::Udp,
                candidate_type: crate::candidate::CandidateType::Host,
            },
            crate::candidate::SignaledCandidate {
                address: mapped_a,
                transport: crate::candidate::CandidateTransport::Udp,
                candidate_type: crate::candidate::CandidateType::ServerReflexive {
                    related_address: host_a,
                },
            },
        ];
        let candidates_b = [
            crate::candidate::SignaledCandidate {
                address: host_b,
                transport: crate::candidate::CandidateTransport::Udp,
                candidate_type: crate::candidate::CandidateType::Host,
            },
            crate::candidate::SignaledCandidate {
                address: mapped_b,
                transport: crate::candidate::CandidateTransport::Udp,
                candidate_type: crate::candidate::CandidateType::ServerReflexive {
                    related_address: host_b,
                },
            },
        ];
        let credentials_a = crate::ice::generate_ice_credentials(1).unwrap();
        let credentials_b = crate::ice::generate_ice_credentials(1).unwrap();
        let mut driver_a = crate::ice::IceAgentDriver::for_peer_with_candidates_on_socket(
            host_a,
            &credentials_a,
            &credentials_b,
            &candidates_a,
            &candidates_b,
            true,
            std::time::Instant::now(),
        )
        .expect("construct client A ICE agent");
        let mut driver_b = crate::ice::IceAgentDriver::for_peer_with_candidates_on_socket(
            host_b,
            &credentials_b,
            &credentials_a,
            &candidates_b,
            &candidates_a,
            false,
            std::time::Instant::now(),
        )
        .expect("construct client B ICE agent");

        let mut sent_a = 0_usize;
        let mut sent_b = 0_usize;
        let mut failed_candidates_a = Vec::new();
        let mut failed_candidates_b = Vec::new();
        let mut targets_a = Vec::new();
        let mut targets_b = Vec::new();
        let mut received_a = Vec::new();
        let mut received_b = Vec::new();
        let mut receive_errors_a = Vec::new();
        let mut receive_errors_b = Vec::new();
        for _ in 0..900 {
            let now = std::time::Instant::now();
            driver_a.handle_timeout(now).expect("tick client A ICE");
            driver_b.handle_timeout(now).expect("tick client B ICE");
            for transmit in driver_a.poll_transmits() {
                if let Err(error) = socket_a
                    .send_to(&transmit.message, transmit.transport.peer_addr)
                    .await
                {
                    assert!(crate::ice::is_candidate_send_error(&error));
                    failed_candidates_a.push(transmit.transport.peer_addr);
                } else {
                    sent_a += 1;
                    targets_a.push(transmit.transport.peer_addr);
                }
            }
            for transmit in driver_b.poll_transmits() {
                if let Err(error) = socket_b
                    .send_to(&transmit.message, transmit.transport.peer_addr)
                    .await
                {
                    assert!(crate::ice::is_candidate_send_error(&error));
                    failed_candidates_b.push(transmit.transport.peer_addr);
                } else {
                    sent_b += 1;
                    targets_b.push(transmit.transport.peer_addr);
                }
            }

            let mut packet = [0; MAX_STUN_MESSAGE];
            for _ in 0..128 {
                match socket_a.try_recv_from(&mut packet) {
                    Ok((length, source)) => {
                        received_a.push(source);
                        assert!(
                            driver_a
                                .handle_datagram(now, source, None, &packet[..length])
                                .expect("handle client A ICE check")
                        );
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(error) if receive_errors_a.len() < 32 => {
                        receive_errors_a.push(error.kind());
                    }
                    Err(_) => {}
                }
            }
            for _ in 0..128 {
                match socket_b.try_recv_from(&mut packet) {
                    Ok((length, source)) => {
                        received_b.push(source);
                        assert!(
                            driver_b
                                .handle_datagram(now, source, None, &packet[..length])
                                .expect("handle client B ICE check")
                        );
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(error) if receive_errors_b.len() < 32 => {
                        receive_errors_b.push(error.kind());
                    }
                    Err(_) => {}
                }
            }
            if driver_a.selected_pair().is_some() && driver_b.selected_pair().is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let selected_a = driver_a.selected_pair();
        let selected_b = driver_b.selected_pair();
        eprintln!(
            "dual-SNAT ICE: mapped A={mapped_a} B={mapped_b}, host A={host_a} B={host_b}, sent A={sent_a} targets={targets_a:?} B={sent_b} targets={targets_b:?}, failed A={failed_candidates_a:?} B={failed_candidates_b:?}, received A={received_a:?} B={received_b:?}, receive errors A={receive_errors_a:?} B={receive_errors_b:?}, selected A={selected_a:?} B={selected_b:?}"
        );
        if selected_a.is_none() || selected_b.is_none() {
            for namespace in [&_topology.router_a, &_topology.router_b] {
                for (command, args) in [
                    ("ip", &["route", "show"][..]),
                    ("iptables", &["-nvx", "-L", "FORWARD"][..]),
                    ("iptables", &["-t", "nat", "-nvx", "-L", "POSTROUTING"][..]),
                ] {
                    let result = std::process::Command::new("ip")
                        .args(["netns", "exec", namespace, command])
                        .args(args)
                        .output()
                        .expect("inspect dual-SNAT routing and firewall counters");
                    eprintln!(
                        "dual-SNAT diagnostic {namespace} {command} {args:?}: {}{}",
                        String::from_utf8_lossy(&result.stdout),
                        String::from_utf8_lossy(&result.stderr)
                    );
                }
            }
        }
        assert!(failed_candidates_a.contains(&host_b));
        assert!(failed_candidates_b.contains(&host_a));
        let pair_a = selected_a.expect("client A nominates direct pair through both NATs");
        let pair_b = selected_b.expect("client B nominates direct pair through both NATs");
        assert_eq!(pair_a.1, mapped_b);
        assert_eq!(pair_b.1, mapped_a);
        socket_a
            .send_to(b"overlay-through-dual-snat", pair_a.1)
            .await
            .expect("send overlay payload through both NATs");
        let mut payload = [0; 64];
        let (length, source) =
            tokio::time::timeout(Duration::from_secs(1), socket_b.recv_from(&mut payload))
                .await
                .expect("client B receives overlay payload")
                .expect("read client B overlay payload");
        assert_eq!(&payload[..length], b"overlay-through-dual-snat");
        assert_eq!(source, mapped_a);
    }

    #[tokio::test]
    async fn quic_endpoint_keeps_the_same_socket_that_was_probed_by_stun() {
        let dir = std::env::temp_dir().join(format!("mini-tunnel-stun-{}", uuid::Uuid::new_v4()));
        let identity = crate::Identity::load_or_create_at(dir.join("device.key"))
            .expect("create test identity");
        let server = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind fake STUN");
        let server_address = server.local_addr().expect("STUN address");
        let responder = tokio::spawn(async move {
            let mut request = [0; HEADER_LEN];
            let (length, peer) = server
                .recv_from(&mut request)
                .await
                .expect("receive request");
            assert_eq!(length, HEADER_LEN);
            let transaction: [u8; 12] = request[8..20].try_into().expect("transaction ID");
            let mapped = SocketAddr::from(([198, 51, 100, 9], peer.port()));
            server
                .send_to(&mapped_response(mapped, transaction), peer)
                .await
                .expect("send STUN response");
            peer.port()
        });
        let (endpoint, mapped) = crate::peer_endpoint_with_stun(
            &identity,
            "127.0.0.1:0".parse().expect("bind address"),
            server_address,
        )
        .await
        .expect("create STUN-enabled peer endpoint");
        let queried_port = responder.await.expect("STUN responder");
        assert_eq!(
            endpoint.local_addr().expect("QUIC local address").port(),
            queried_port
        );
        assert_eq!(mapped.port(), queried_port);
        endpoint.close(0_u32.into(), b"test complete");
        std::fs::remove_dir_all(dir).expect("remove test identity");
    }

    #[tokio::test]
    async fn iced_endpoint_keeps_the_same_socket_that_was_probed_by_stun() {
        let dir =
            std::env::temp_dir().join(format!("mini-tunnel-ice-stun-{}", uuid::Uuid::new_v4()));
        let identity = crate::Identity::load_or_create_at(dir.join("device.key"))
            .expect("create test identity");
        let server = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind fake STUN");
        let server_address = server.local_addr().expect("STUN address");
        let responder = tokio::spawn(async move {
            let mut request = [0; HEADER_LEN];
            let (length, peer) = server
                .recv_from(&mut request)
                .await
                .expect("receive request");
            assert_eq!(length, HEADER_LEN);
            let transaction = request[8..20].try_into().expect("transaction ID");
            let mapped = SocketAddr::from(([198, 51, 100, 10], peer.port()));
            server
                .send_to(&mapped_response(mapped, transaction), peer)
                .await
                .expect("send STUN response");
            peer.port()
        });
        let (endpoint, mapped) = crate::ice::peer_endpoint_with_ice_and_stun(
            &identity,
            "127.0.0.1:0".parse().unwrap(),
            server_address,
            8,
        )
        .await
        .expect("create ICE/STUN endpoint");
        let queried_port = responder.await.expect("STUN responder");
        assert_eq!(endpoint.socket.local_addr().unwrap().port(), queried_port);
        assert_eq!(endpoint.endpoint.local_addr().unwrap().port(), queried_port);
        assert_eq!(mapped.port(), queried_port);
        endpoint.endpoint.close(0_u32.into(), b"test complete");
        std::fs::remove_dir_all(dir).expect("remove test identity");
    }

    #[tokio::test]
    async fn binding_retries_with_the_same_transaction_id_after_timeout() {
        let server = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind fake STUN");
        let server_address = server.local_addr().expect("STUN address");
        let responder = tokio::spawn(async move {
            let mut requests = Vec::new();
            let mut buffer = [0; HEADER_LEN];
            for _ in 0..RETRIES {
                let (length, _) =
                    tokio::time::timeout(Duration::from_secs(4), server.recv_from(&mut buffer))
                        .await
                        .expect("retry arrived")
                        .expect("receive request");
                requests.push(buffer[..length].to_vec());
            }
            requests
        });
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind client");
        assert!(matches!(
            discover_mapped_address(&socket, server_address).await,
            Err(StunError::Timeout)
        ));
        let requests = responder.await.expect("STUN responder");
        assert_eq!(requests.len(), RETRIES);
        assert!(requests.windows(2).all(|pair| pair[0] == pair[1]));
    }
}
