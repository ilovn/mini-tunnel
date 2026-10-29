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
    let message_len = usize::from(u16::from_be_bytes([message[2], message[3]]));
    if message_len % 4 != 0 || message_len != message.len() - HEADER_LEN {
        return Err(StunError::InvalidResponse("invalid message length"));
    }
    if u32::from_be_bytes(message[4..8].try_into().expect("fixed header slice")) != MAGIC_COOKIE {
        return Err(StunError::InvalidResponse("invalid magic cookie"));
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
