//! Shared, versioned control-plane types.
//!
//! These types are an initial API contract, not yet a stable public wire
//! protocol. Breaking changes are expected until protocol version 1 is frozen.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::{Ipv4Addr, Ipv6Addr};
use uuid::Uuid;

/// Current version of the control message envelope.
pub const PROTOCOL_VERSION: u16 = 1;

/// Stable, non-secret identifier derived from the Ed25519 public key.
#[must_use]
pub fn device_id_from_public_key(public_key: &[u8; 32]) -> String {
    let digest = Sha256::digest(public_key);
    digest[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Derive a stable locally administered ULA /64 prefix from a coordinator network UUID.
///
/// The coordinator checks that derived prefixes are unique among its networks. This pure mapping
/// lets existing IPv4 lease responses remain wire-compatible while every member derives IPv6.
#[must_use]
pub fn overlay_ipv6_prefix(network_id: &str) -> Option<Ipv6Addr> {
    let network_id = Uuid::parse_str(network_id).ok()?;
    let mut octets = [0_u8; 16];
    octets[0] = 0xfd;
    octets[1..8].copy_from_slice(&network_id.as_bytes()[..7]);
    Some(Ipv6Addr::from(octets))
}

/// Derive a member's stable ULA from its network UUID and unique IPv4 lease.
#[must_use]
pub fn overlay_ipv6_address(network_id: &str, assigned_ipv4: Ipv4Addr) -> Option<Ipv6Addr> {
    let mut octets = overlay_ipv6_prefix(network_id)?.octets();
    octets[12..16].copy_from_slice(&assigned_ipv4.octets());
    Some(Ipv6Addr::from(octets))
}

fn signing_bytes(domain: &[u8], fields: &[&[u8]]) -> Vec<u8> {
    let mut bytes =
        Vec::with_capacity(domain.len() + fields.iter().map(|f| f.len() + 4).sum::<usize>());
    bytes.extend_from_slice(domain);
    bytes.push(0);
    for field in fields {
        bytes.extend_from_slice(&(field.len() as u32).to_be_bytes());
        bytes.extend_from_slice(field);
    }
    bytes
}

#[must_use]
pub fn join_signing_bytes(
    network_id: &str,
    device_id: &str,
    public_key: &[u8],
    invite_token: &str,
) -> Vec<u8> {
    signing_bytes(
        b"mini-tunnel/join/v1",
        &[
            network_id.as_bytes(),
            device_id.as_bytes(),
            public_key,
            invite_token.as_bytes(),
        ],
    )
}

#[must_use]
pub fn candidate_signing_bytes(
    network_id: &str,
    device_id: &str,
    timestamp_ms: u64,
    candidates: &[String],
) -> Vec<u8> {
    let timestamp_bytes = timestamp_ms.to_be_bytes();
    let mut fields = vec![
        network_id.as_bytes(),
        device_id.as_bytes(),
        &timestamp_bytes,
    ];
    fields.extend(candidates.iter().map(String::as_bytes));
    signing_bytes(b"mini-tunnel/candidates/v1", &fields)
}

#[must_use]
pub fn candidate_signing_bytes_with_ice(
    network_id: &str,
    device_id: &str,
    timestamp_ms: u64,
    candidates: &[String],
    credentials: &IceCredentials,
) -> Vec<u8> {
    let timestamp_bytes = timestamp_ms.to_be_bytes();
    let generation_bytes = credentials.generation.to_be_bytes();
    let mut fields = vec![
        network_id.as_bytes(),
        device_id.as_bytes(),
        &timestamp_bytes,
    ];
    fields.extend(candidates.iter().map(String::as_bytes));
    fields.extend([
        credentials.ufrag.as_bytes(),
        credentials.password.as_bytes(),
        &generation_bytes,
    ]);
    signing_bytes(b"mini-tunnel/candidates-ice/v1", &fields)
}

#[must_use]
pub fn peers_signing_bytes(network_id: &str, device_id: &str, timestamp_ms: u64) -> Vec<u8> {
    signing_bytes(
        b"mini-tunnel/peers/v1",
        &[
            network_id.as_bytes(),
            device_id.as_bytes(),
            &timestamp_ms.to_be_bytes(),
        ],
    )
}

pub const RELAY_TICKET_VERSION: u16 = 1;
const RELAY_TICKET_DOMAIN: &[u8] = b"mini-tunnel/relay-ticket/v1\0";
const RELAY_AUTH_DOMAIN: &[u8] = b"mini-tunnel/relay-auth/v1\0";
const MAX_RELAY_TICKET_BYTES: usize = 2048;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayTicketRequest {
    pub device_id: String,
    pub peer_id: String,
    pub timestamp_ms: u64,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayTicketResponse {
    pub ticket: String,
    pub expires_at_ms: u64,
}

/// MAC-authenticated claim carried from the coordinator to one relay node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayTicketClaims {
    pub version: u16,
    pub network_id: String,
    pub source_device_id: String,
    pub target_device_id: String,
    pub session_id: [u8; 16],
    pub ticket_id: [u8; 16],
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RelayTicketError {
    #[error("relay ticket is malformed or has an unsupported version")]
    Invalid,
    #[error("relay ticket has expired")]
    Expired,
}

#[must_use]
pub fn relay_ticket_request_signing_bytes(
    network_id: &str,
    device_id: &str,
    peer_id: &str,
    timestamp_ms: u64,
) -> Vec<u8> {
    signing_bytes(
        b"mini-tunnel/relay-ticket-request/v1",
        &[
            network_id.as_bytes(),
            device_id.as_bytes(),
            peer_id.as_bytes(),
            &timestamp_ms.to_be_bytes(),
        ],
    )
}

/// Issue a compact ticket authenticated by the coordinator/relay shared secret.
pub fn issue_relay_ticket(
    secret: &[u8; 32],
    claims: &RelayTicketClaims,
) -> Result<String, RelayTicketError> {
    validate_relay_ticket_claims(claims)?;
    let payload = serde_json::to_vec(claims).map_err(|_| RelayTicketError::Invalid)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).map_err(|_| RelayTicketError::Invalid)?;
    mac.update(RELAY_TICKET_DOMAIN);
    mac.update(&payload);
    let mut token = payload;
    token.extend_from_slice(&mac.finalize().into_bytes());
    let encoded = URL_SAFE_NO_PAD.encode(token);
    if encoded.len() > MAX_RELAY_TICKET_BYTES {
        return Err(RelayTicketError::Invalid);
    }
    Ok(encoded)
}

/// Verify MAC, claim structure and expiry before a relay allocates a session.
pub fn verify_relay_ticket(
    secret: &[u8; 32],
    token: &str,
    now_ms: u64,
) -> Result<RelayTicketClaims, RelayTicketError> {
    if token.len() > MAX_RELAY_TICKET_BYTES {
        return Err(RelayTicketError::Invalid);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|_| RelayTicketError::Invalid)?;
    if bytes.len() <= 32 {
        return Err(RelayTicketError::Invalid);
    }
    let (payload, tag) = bytes.split_at(bytes.len() - 32);
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).map_err(|_| RelayTicketError::Invalid)?;
    mac.update(RELAY_TICKET_DOMAIN);
    mac.update(payload);
    mac.verify_slice(tag)
        .map_err(|_| RelayTicketError::Invalid)?;
    let claims: RelayTicketClaims =
        serde_json::from_slice(payload).map_err(|_| RelayTicketError::Invalid)?;
    validate_relay_ticket_claims(&claims)?;
    if claims.expires_at_ms <= now_ms {
        return Err(RelayTicketError::Expired);
    }
    Ok(claims)
}

#[must_use]
pub fn relay_auth_signing_bytes(
    ticket: &str,
    challenge: &[u8; 32],
    public_key: &[u8; 32],
) -> Vec<u8> {
    signing_bytes(
        RELAY_AUTH_DOMAIN,
        &[ticket.as_bytes(), challenge, public_key],
    )
}

fn validate_relay_ticket_claims(claims: &RelayTicketClaims) -> Result<(), RelayTicketError> {
    let valid_device_id = |id: &str| {
        id.len() == 32
            && id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    };
    if claims.version != RELAY_TICKET_VERSION
        || claims.network_id.is_empty()
        || claims.network_id.len() > 128
        || !valid_device_id(&claims.source_device_id)
        || !valid_device_id(&claims.target_device_id)
        || claims.source_device_id == claims.target_device_id
        || claims.expires_at_ms == 0
    {
        return Err(RelayTicketError::Invalid);
    }
    Ok(())
}

#[must_use]
pub fn encode_signature(signature: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(signature)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    pub version: u16,
    pub request_id: String,
    pub message: ControlMessage,
}

impl Envelope {
    #[must_use]
    pub fn new(request_id: impl Into<String>, message: ControlMessage) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            request_id: request_id.into(),
            message,
        }
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.version != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion(self.version));
        }
        if self.request_id.trim().is_empty() {
            return Err(ProtocolError::MissingRequestId);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload", rename_all = "snake_case")]
pub enum ControlMessage {
    RegisterDevice {
        device_id: String,
        public_key: String,
    },
    Heartbeat {
        device_id: String,
    },
    ListPeers {
        network_id: String,
    },
    CandidateUpdate {
        device_id: String,
        candidates: Vec<String>,
    },
    RevokeDevice {
        device_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateNetworkRequest {
    pub name: String,
    pub cidr: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateNetworkResponse {
    pub network_id: String,
    pub name: String,
    pub cidr: String,
    /// One-time display of a high-entropy capability. Never log this value.
    pub admin_token: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateInviteRequest {
    pub admin_token: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeMemberRequest {
    pub admin_token: String,
    pub device_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevokeMemberResponse {
    pub revoked: bool,
    pub released_ipv4: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateInviteResponse {
    /// One-time display of a high-entropy token that can enroll one device.
    pub invite_token: String,
    pub expires_in_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinNetworkRequest {
    pub invite_token: String,
    pub device_id: String,
    pub public_key: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateUpdateRequest {
    pub device_id: String,
    pub timestamp_ms: u64,
    pub candidates: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ice_credentials: Option<IceCredentials>,
    pub signature: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IceCredentials {
    pub ufrag: String,
    pub password: String,
    pub generation: u64,
}

impl std::fmt::Debug for IceCredentials {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IceCredentials")
            .field("ufrag", &self.ufrag)
            .field("password", &"[REDACTED]")
            .field("generation", &self.generation)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateUpdateResponse {
    pub accepted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerListRequest {
    pub device_id: String,
    pub timestamp_ms: u64,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerInfo {
    pub device_id: String,
    pub assigned_ipv4: String,
    pub public_key: String,
    pub candidates: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ice_credentials: Option<IceCredentials>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerListResponse {
    pub peers: Vec<PeerInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinNetworkResponse {
    pub network_id: String,
    pub device_id: String,
    pub assigned_ipv4: String,
    pub cidr: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiErrorResponse {
    pub error: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProtocolError {
    #[error("unsupported protocol version {0}")]
    UnsupportedVersion(u16),
    #[error("request_id must not be empty")]
    MissingRequestId,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlay_ipv6_addresses_are_stable_unique_ula_members() {
        let network = "123e4567-e89b-42d3-a456-426614174000";
        let first = overlay_ipv6_address(network, "10.77.0.1".parse().unwrap()).unwrap();
        let second = overlay_ipv6_address(network, "10.77.0.2".parse().unwrap()).unwrap();
        assert_eq!(
            first,
            "fd12:3e45:67e8:9b42::a4d:1".parse::<Ipv6Addr>().unwrap()
        );
        assert_ne!(first, second);
        assert_eq!(
            first,
            overlay_ipv6_address(network, "10.77.0.1".parse().unwrap()).unwrap()
        );
        assert_ne!(
            overlay_ipv6_prefix(network),
            overlay_ipv6_prefix("223e4567-e89b-42d3-a456-426614174000")
        );
        assert!(overlay_ipv6_prefix("not-a-uuid").is_none());
    }

    fn claims() -> RelayTicketClaims {
        RelayTicketClaims {
            version: RELAY_TICKET_VERSION,
            network_id: "network-1".to_owned(),
            source_device_id: "0123456789abcdef0123456789abcdef".to_owned(),
            target_device_id: "fedcba9876543210fedcba9876543210".to_owned(),
            session_id: [7; 16],
            ticket_id: [8; 16],
            expires_at_ms: 5000,
        }
    }

    #[test]
    fn ice_credentials_are_bound_into_signature_and_redacted_from_debug() {
        let candidates = ["198.51.100.4:42000".to_owned()];
        let credentials = IceCredentials {
            ufrag: "abcdefghijklmnop".to_owned(),
            password: "abcdefghijklmnopqrstuvwxyzABCDEF".to_owned(),
            generation: 1,
        };
        let signature = candidate_signing_bytes_with_ice(
            "network-1",
            "device-1",
            42,
            &candidates,
            &credentials,
        );
        let mut changed = credentials.clone();
        changed.password.push('A');
        assert_ne!(
            signature,
            candidate_signing_bytes_with_ice("network-1", "device-1", 42, &candidates, &changed,)
        );
        assert!(!format!("{credentials:?}").contains(&credentials.password));
        assert!(format!("{credentials:?}").contains("[REDACTED]"));
    }

    #[test]
    fn old_candidate_updates_without_ice_credentials_still_deserialize() {
        let request: CandidateUpdateRequest = serde_json::from_str(
            r#"{"device_id":"device-1","timestamp_ms":42,"candidates":[],"signature":"sig"}"#,
        )
        .expect("legacy candidate update");
        assert!(request.ice_credentials.is_none());
        let serialized = serde_json::to_string(&request).expect("serialize legacy update");
        assert!(!serialized.contains("ice_credentials"));
    }

    #[test]
    fn relay_ticket_authenticates_claims_and_expiry() {
        let secret = [3; 32];
        let ticket = issue_relay_ticket(&secret, &claims()).expect("issue ticket");
        let verified = verify_relay_ticket(&secret, &ticket, 4999).expect("verify ticket");
        assert_eq!(verified, claims());
        assert_eq!(
            verify_relay_ticket(&secret, &ticket, 5000),
            Err(RelayTicketError::Expired)
        );
        assert_eq!(
            verify_relay_ticket(&[4; 32], &ticket, 4999),
            Err(RelayTicketError::Invalid)
        );
        let mut tampered = ticket.into_bytes();
        let last = tampered.len() - 1;
        tampered[last] = if tampered[last] == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(tampered).expect("base64 token is utf8");
        assert_eq!(
            verify_relay_ticket(&secret, &tampered, 4999),
            Err(RelayTicketError::Invalid)
        );
    }

    #[test]
    fn relay_ticket_rejects_invalid_pair_and_unknown_fields() {
        let secret = [3; 32];
        let mut invalid = claims();
        invalid.target_device_id = invalid.source_device_id.clone();
        assert_eq!(
            issue_relay_ticket(&secret, &invalid),
            Err(RelayTicketError::Invalid)
        );
        let future = br#"{"version":1,"network_id":"network-1","source_device_id":"0123456789abcdef0123456789abcdef","target_device_id":"fedcba9876543210fedcba9876543210","session_id":[7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7],"ticket_id":[8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8],"expires_at_ms":5000,"admin":true}"#;
        let mut mac = Hmac::<Sha256>::new_from_slice(&secret).expect("HMAC key");
        mac.update(RELAY_TICKET_DOMAIN);
        mac.update(future);
        let mut bytes = future.to_vec();
        bytes.extend_from_slice(&mac.finalize().into_bytes());
        assert_eq!(
            verify_relay_ticket(&secret, &URL_SAFE_NO_PAD.encode(bytes), 4999),
            Err(RelayTicketError::Invalid)
        );
    }
}
