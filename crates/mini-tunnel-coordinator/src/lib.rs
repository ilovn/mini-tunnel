use std::{
    collections::{HashMap, HashSet},
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use getrandom::fill as random_fill;
use ipnet::Ipv4Net;
use mini_tunnel_protocol::{
    ApiErrorResponse, CreateInviteRequest, CreateInviteResponse, CreateNetworkRequest,
    CreateNetworkResponse, JoinNetworkRequest, JoinNetworkResponse,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::{net::TcpListener, sync::RwLock};
use uuid::Uuid;

pub const SERVICE_VERSION: &str = env!("CARGO_PKG_VERSION");
const MAX_NETWORKS: usize = 128;
const MAX_INVITES_PER_NETWORK: usize = 1024;
const MAX_DEVICE_ID_BYTES: usize = 128;
const INVITE_TTL: Duration = Duration::from_secs(60 * 60);

#[derive(Debug, Clone, Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub service: &'static str,
    pub version: &'static str,
}

#[derive(Clone, Default)]
pub struct CoordinatorState {
    inner: Arc<RwLock<Store>>,
}

#[derive(Default)]
struct Store {
    networks: HashMap<Uuid, Network>,
}

struct Network {
    cidr: Ipv4Net,
    admin_token_hash: [u8; 32],
    invites: HashMap<[u8; 32], Invite>,
    members: HashMap<String, Ipv4Addr>,
    assigned_addresses: HashSet<Ipv4Addr>,
}

struct Invite {
    consumed_by: Option<String>,
    expires_at: Instant,
}

#[derive(Debug)]
enum ApiError {
    InvalidRequest(&'static str),
    NotFound,
    Unauthorized,
    Conflict(&'static str),
    Internal,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, error, message) = match self {
            Self::InvalidRequest(message) => (StatusCode::BAD_REQUEST, "invalid_request", message),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found", "network not found"),
            Self::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "token is invalid, expired, or already used",
            ),
            Self::Conflict(message) => (StatusCode::CONFLICT, "conflict", message),
            Self::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "secure random number generation failed",
            ),
        };
        (
            status,
            Json(ApiErrorResponse {
                error: error.into(),
                message: message.into(),
            }),
        )
            .into_response()
    }
}

impl CoordinatorState {
    async fn create_network(
        &self,
        request: CreateNetworkRequest,
    ) -> Result<CreateNetworkResponse, ApiError> {
        let name = request.name.trim();
        if name.is_empty() || name.len() > 64 || name.chars().any(char::is_control) {
            return Err(ApiError::InvalidRequest(
                "name must be 1-64 bytes and contain no control characters",
            ));
        }
        let cidr = request
            .cidr
            .parse::<Ipv4Net>()
            .map_err(|_| ApiError::InvalidRequest("cidr must be a valid IPv4 network"))?;
        if !(16..=30).contains(&cidr.prefix_len())
            || !cidr.network().is_private()
            || !cidr.broadcast().is_private()
        {
            return Err(ApiError::InvalidRequest(
                "cidr must be an RFC1918 IPv4 network with prefix length /16 through /30",
            ));
        }

        let (admin_token, admin_token_hash) = create_token()?;
        let mut store = self.inner.write().await;
        if store.networks.len() >= MAX_NETWORKS {
            return Err(ApiError::Conflict("coordinator network capacity reached"));
        }
        if store
            .networks
            .values()
            .any(|existing| cidrs_overlap(cidr, existing.cidr))
        {
            return Err(ApiError::Conflict("cidr overlaps an existing network"));
        }
        let network_id = loop {
            let id = Uuid::new_v4();
            if !store.networks.contains_key(&id) {
                break id;
            }
        };
        store.networks.insert(
            network_id,
            Network {
                cidr,
                admin_token_hash,
                invites: HashMap::new(),
                members: HashMap::new(),
                assigned_addresses: HashSet::new(),
            },
        );

        Ok(CreateNetworkResponse {
            network_id: network_id.to_string(),
            name: name.to_owned(),
            cidr: cidr.to_string(),
            admin_token,
        })
    }

    async fn create_invite(
        &self,
        network_id: Uuid,
        request: CreateInviteRequest,
    ) -> Result<CreateInviteResponse, ApiError> {
        let mut store = self.inner.write().await;
        let network = store
            .networks
            .get_mut(&network_id)
            .ok_or(ApiError::NotFound)?;
        if !constant_time_equal(&network.admin_token_hash, &token_hash(&request.admin_token)) {
            return Err(ApiError::Unauthorized);
        }
        let now = Instant::now();
        network.invites.retain(|_, invite| invite.expires_at > now);
        if network.invites.len() >= MAX_INVITES_PER_NETWORK {
            return Err(ApiError::Conflict("network invitation capacity reached"));
        }
        let (invite_token, invite_hash) = create_token()?;
        network.invites.insert(
            invite_hash,
            Invite {
                consumed_by: None,
                expires_at: now + INVITE_TTL,
            },
        );
        Ok(CreateInviteResponse {
            invite_token,
            expires_in_seconds: INVITE_TTL.as_secs(),
        })
    }

    async fn join_network(
        &self,
        network_id: Uuid,
        request: JoinNetworkRequest,
    ) -> Result<JoinNetworkResponse, ApiError> {
        if request.device_id.trim().is_empty()
            || request.device_id.len() > MAX_DEVICE_ID_BYTES
            || request.device_id.chars().any(char::is_control)
        {
            return Err(ApiError::InvalidRequest(
                "device_id must be 1-128 bytes and contain no control characters",
            ));
        }

        let requested_hash = token_hash(&request.invite_token);
        let mut store = self.inner.write().await;
        let network = store
            .networks
            .get_mut(&network_id)
            .ok_or(ApiError::NotFound)?;
        let invite_hash = network
            .invites
            .keys()
            .find(|stored_hash| constant_time_equal(stored_hash, &requested_hash))
            .copied()
            .ok_or(ApiError::Unauthorized)?;
        let invite = network
            .invites
            .get_mut(&invite_hash)
            .ok_or(ApiError::Unauthorized)?;
        if invite.expires_at <= Instant::now() {
            return Err(ApiError::Unauthorized);
        }

        if let Some(accepted_device) = &invite.consumed_by {
            if accepted_device != &request.device_id {
                return Err(ApiError::Unauthorized);
            }
            let assigned_ipv4 = network
                .members
                .get(&request.device_id)
                .ok_or(ApiError::Unauthorized)?;
            return Ok(JoinNetworkResponse {
                network_id: network_id.to_string(),
                device_id: request.device_id,
                assigned_ipv4: assigned_ipv4.to_string(),
                cidr: network.cidr.to_string(),
            });
        }
        if network.members.contains_key(&request.device_id) {
            return Err(ApiError::Conflict("device_id is already enrolled"));
        }

        let assigned_ipv4 = network
            .cidr
            .hosts()
            .find(|address| !network.assigned_addresses.contains(address))
            .ok_or(ApiError::Conflict("network has no free IPv4 addresses"))?;
        network.assigned_addresses.insert(assigned_ipv4);
        network
            .members
            .insert(request.device_id.clone(), assigned_ipv4);
        invite.consumed_by = Some(request.device_id.clone());

        Ok(JoinNetworkResponse {
            network_id: network_id.to_string(),
            device_id: request.device_id,
            assigned_ipv4: assigned_ipv4.to_string(),
            cidr: network.cidr.to_string(),
        })
    }
}

pub fn router() -> Router {
    router_with_state(CoordinatorState::default())
}

pub fn router_with_state(state: CoordinatorState) -> Router {
    Router::new()
        .route("/healthz", get(health))
        .route("/v1/networks", post(create_network))
        .route("/v1/networks/{network_id}/invites", post(create_invite))
        .route("/v1/networks/{network_id}/join", post(join_network))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .with_state(state)
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        service: "coordinator",
        version: SERVICE_VERSION,
    })
}

async fn create_network(
    State(state): State<CoordinatorState>,
    Json(request): Json<CreateNetworkRequest>,
) -> Result<Json<CreateNetworkResponse>, ApiError> {
    state.create_network(request).await.map(Json)
}

async fn create_invite(
    State(state): State<CoordinatorState>,
    Path(network_id): Path<String>,
    Json(request): Json<CreateInviteRequest>,
) -> Result<Json<CreateInviteResponse>, ApiError> {
    let network_id = Uuid::parse_str(&network_id)
        .map_err(|_| ApiError::InvalidRequest("network_id must be a UUID"))?;
    state.create_invite(network_id, request).await.map(Json)
}

async fn join_network(
    State(state): State<CoordinatorState>,
    Path(network_id): Path<String>,
    Json(request): Json<JoinNetworkRequest>,
) -> Result<Json<JoinNetworkResponse>, ApiError> {
    let network_id = Uuid::parse_str(&network_id)
        .map_err(|_| ApiError::InvalidRequest("network_id must be a UUID"))?;
    state.join_network(network_id, request).await.map(Json)
}

pub async fn serve(address: SocketAddr) -> std::io::Result<()> {
    let listener = TcpListener::bind(address).await?;
    tracing::info!(address = %listener.local_addr()?, "coordinator listening");
    axum::serve(listener, router())
        .with_graceful_shutdown(shutdown_signal())
        .await
}

fn create_token() -> Result<(String, [u8; 32]), ApiError> {
    let mut bytes = [0_u8; 32];
    random_fill(&mut bytes).map_err(|_| ApiError::Internal)?;
    let token = URL_SAFE_NO_PAD.encode(bytes);
    Ok((token.clone(), token_hash(&token)))
}

fn token_hash(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

fn constant_time_equal(left: &[u8; 32], right: &[u8; 32]) -> bool {
    bool::from(left.ct_eq(right))
}

fn cidrs_overlap(left: Ipv4Net, right: Ipv4Net) -> bool {
    let left_start = u32::from(left.network());
    let left_end = u32::from(left.broadcast());
    let right_start = u32::from(right.network());
    let right_end = u32::from(right.broadcast());
    left_start <= right_end && right_start <= left_end
}

async fn shutdown_signal() {
    if let Err(error) = tokio::signal::ctrl_c().await {
        tracing::error!(%error, "failed to listen for shutdown signal");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_request(name: &str, cidr: &str) -> CreateNetworkRequest {
        CreateNetworkRequest {
            name: name.to_owned(),
            cidr: cidr.to_owned(),
        }
    }

    fn network_uuid(response: &CreateNetworkResponse) -> Uuid {
        Uuid::parse_str(&response.network_id).expect("coordinator returns a UUID")
    }

    #[tokio::test]
    async fn enrolls_members_allocates_unique_addresses_and_allows_retry() {
        let state = CoordinatorState::default();
        let network = state
            .create_network(create_request("lab", "10.77.0.0/16"))
            .await
            .expect("network should be created");
        let network_id = network_uuid(&network);
        let admin = CreateInviteRequest {
            admin_token: network.admin_token.clone(),
        };
        let first_invite = state
            .create_invite(network_id, admin.clone())
            .await
            .expect("admin can issue invite");
        let first_join = JoinNetworkRequest {
            invite_token: first_invite.invite_token.clone(),
            device_id: "device-a".to_owned(),
        };
        let first = state
            .join_network(network_id, first_join.clone())
            .await
            .expect("invite should enroll a device");
        let retry = state
            .join_network(network_id, first_join)
            .await
            .expect("same device retry should be idempotent");
        assert_eq!(first.assigned_ipv4, "10.77.0.1");
        assert_eq!(retry.assigned_ipv4, first.assigned_ipv4);

        let second_invite = state
            .create_invite(network_id, admin)
            .await
            .expect("admin can issue another invite");
        let second = state
            .join_network(
                network_id,
                JoinNetworkRequest {
                    invite_token: second_invite.invite_token,
                    device_id: "device-b".to_owned(),
                },
            )
            .await
            .expect("second device should enroll");
        assert_eq!(second.assigned_ipv4, "10.77.0.2");
    }

    #[tokio::test]
    async fn invite_is_single_device_and_admin_token_is_required() {
        let state = CoordinatorState::default();
        let network = state
            .create_network(create_request("lab", "10.78.0.0/16"))
            .await
            .expect("network should be created");
        let network_id = network_uuid(&network);
        let invite = state
            .create_invite(
                network_id,
                CreateInviteRequest {
                    admin_token: "wrong-token".to_owned(),
                },
            )
            .await
            .expect_err("wrong admin token must fail");
        assert!(matches!(invite, ApiError::Unauthorized));

        let invite = state
            .create_invite(
                network_id,
                CreateInviteRequest {
                    admin_token: network.admin_token,
                },
            )
            .await
            .expect("valid admin token should issue invite");
        state
            .join_network(
                network_id,
                JoinNetworkRequest {
                    invite_token: invite.invite_token.clone(),
                    device_id: "device-a".to_owned(),
                },
            )
            .await
            .expect("first use should succeed");
        let replay = state
            .join_network(
                network_id,
                JoinNetworkRequest {
                    invite_token: invite.invite_token,
                    device_id: "device-b".to_owned(),
                },
            )
            .await
            .expect_err("an invite must not enroll a second device");
        assert!(matches!(replay, ApiError::Unauthorized));
    }

    #[tokio::test]
    async fn rejects_public_invalid_and_overlapping_cidrs() {
        let state = CoordinatorState::default();
        let public = state
            .create_network(create_request("public", "8.8.8.0/24"))
            .await
            .expect_err("public ranges must not be accepted");
        assert!(matches!(public, ApiError::InvalidRequest(_)));

        state
            .create_network(create_request("one", "10.79.0.0/16"))
            .await
            .expect("first private network should be created");
        let overlap = state
            .create_network(create_request("two", "10.79.1.0/24"))
            .await
            .expect_err("overlapping networks must be rejected");
        assert!(matches!(overlap, ApiError::Conflict(_)));
    }
}
