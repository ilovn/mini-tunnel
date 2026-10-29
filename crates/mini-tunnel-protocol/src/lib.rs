//! Shared, versioned control-plane types.
//!
//! These types are an initial API contract, not yet a stable public wire
//! protocol. Breaking changes are expected until protocol version 1 is frozen.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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
    pub signature: String,
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
