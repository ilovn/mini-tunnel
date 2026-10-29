//! Shared, versioned control-plane types.
//!
//! These types are an initial API contract, not yet a stable public wire
//! protocol. Breaking changes are expected until protocol version 1 is frozen.

use serde::{Deserialize, Serialize};

/// Current version of the control message envelope.
pub const PROTOCOL_VERSION: u16 = 1;

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
