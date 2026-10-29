use std::{
    collections::{HashMap, HashSet},
    fs,
    io::{self, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path as FsPath, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::{
    Json, Router,
    extract::{ConnectInfo, DefaultBodyLimit, Path, Request, State},
    http::{HeaderValue, StatusCode},
    middleware::{Next, from_fn_with_state},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, VerifyingKey};
use getrandom::fill as random_fill;
use ipnet::Ipv4Net;
use mini_tunnel_protocol::{
    ApiErrorResponse, CandidateUpdateRequest, CandidateUpdateResponse, CreateInviteRequest,
    CreateInviteResponse, CreateNetworkRequest, CreateNetworkResponse, JoinNetworkRequest,
    JoinNetworkResponse, PeerInfo, PeerListRequest, PeerListResponse, RELAY_TICKET_VERSION,
    RelayTicketClaims, RelayTicketRequest, RelayTicketResponse, RevokeMemberRequest,
    RevokeMemberResponse, candidate_signing_bytes, device_id_from_public_key, issue_relay_ticket,
    join_signing_bytes, peers_signing_bytes, relay_ticket_request_signing_bytes,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::{net::TcpListener, sync::RwLock};
use uuid::Uuid;

pub const SERVICE_VERSION: &str = env!("CARGO_PKG_VERSION");
const MAX_NETWORKS: usize = 128;
const MAX_INVITES_PER_NETWORK: usize = 1024;
const MAX_DEVICE_ID_BYTES: usize = 128;
const INVITE_TTL: Duration = Duration::from_secs(60 * 60);
const SIGNATURE_CLOCK_SKEW_MS: u64 = 5 * 60 * 1000;
const MAX_CANDIDATES: usize = 8;
const MAX_REQUESTS_PER_MINUTE_PER_IP: usize = 600;
const MAX_RATE_LIMIT_CLIENTS: usize = 8192;
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub service: &'static str,
    pub version: &'static str,
}

#[derive(Clone, Default)]
pub struct CoordinatorState {
    inner: Arc<RwLock<Store>>,
    persistence: Option<Arc<PathBuf>>,
    request_limiter: RequestRateLimiter,
    relay_ticket_key: Option<Arc<[u8; 32]>>,
    relay_pairs: Arc<Mutex<RelayPairStore>>,
}

type RelayPairStore = HashMap<(Uuid, String, String), RelayPair>;

#[derive(Clone)]
struct RelayPair {
    session_id: [u8; 16],
    expires_at_ms: u64,
    first_device: String,
}

#[derive(Clone)]
struct RequestRateLimiter {
    max_requests: usize,
    window: Duration,
    clients: Arc<Mutex<HashMap<IpAddr, RequestWindow>>>,
}

#[derive(Clone, Copy)]
struct RequestWindow {
    started_at: Instant,
    request_count: usize,
}

impl Default for RequestRateLimiter {
    fn default() -> Self {
        Self::new(MAX_REQUESTS_PER_MINUTE_PER_IP, RATE_LIMIT_WINDOW)
    }
}

impl RequestRateLimiter {
    fn new(max_requests: usize, window: Duration) -> Self {
        Self {
            max_requests,
            window,
            clients: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn allow(&self, client: IpAddr, now: Instant) -> bool {
        let Ok(mut clients) = self.clients.lock() else {
            return false;
        };
        if !clients.contains_key(&client) && clients.len() >= MAX_RATE_LIMIT_CLIENTS {
            clients
                .retain(|_, bucket| now.saturating_duration_since(bucket.started_at) < self.window);
            if clients.len() >= MAX_RATE_LIMIT_CLIENTS {
                return false;
            }
        }
        let bucket = clients.entry(client).or_insert(RequestWindow {
            started_at: now,
            request_count: 0,
        });
        if now.saturating_duration_since(bucket.started_at) >= self.window {
            bucket.started_at = now;
            bucket.request_count = 0;
        }
        if bucket.request_count >= self.max_requests {
            return false;
        }
        bucket.request_count += 1;
        true
    }
}

#[derive(Clone, Default)]
struct Store {
    networks: HashMap<Uuid, Network>,
}

#[derive(Clone)]
struct Network {
    cidr: Ipv4Net,
    admin_token_hash: [u8; 32],
    invites: HashMap<[u8; 32], Invite>,
    members: HashMap<String, Member>,
    assigned_addresses: HashSet<Ipv4Addr>,
}

#[derive(Clone)]
struct Member {
    address: Ipv4Addr,
    public_key: [u8; 32],
    candidates: Vec<String>,
    last_candidate_timestamp_ms: u64,
}

#[derive(Clone)]
struct Invite {
    consumed_by: Option<String>,
    expires_at_ms: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StateSnapshot {
    schema_version: u32,
    networks: Vec<PersistedNetwork>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedNetwork {
    id: Uuid,
    cidr: String,
    admin_token_hash: [u8; 32],
    invites: Vec<PersistedInvite>,
    members: Vec<PersistedMember>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedInvite {
    token_hash: [u8; 32],
    consumed_by: Option<String>,
    expires_at_ms: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedMember {
    device_id: String,
    address: Ipv4Addr,
    public_key: [u8; 32],
    candidates: Vec<String>,
    last_candidate_timestamp_ms: u64,
}

#[derive(Debug)]
enum ApiError {
    InvalidRequest(&'static str),
    NotFound,
    Unauthorized,
    Conflict(&'static str),
    Internal,
    Persistence,
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
                "coordinator operation failed",
            ),
            Self::Persistence => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "persistence_error",
                "coordinator state could not be persisted",
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
    /// Enable ticket issuance with the secret shared only with trusted relay nodes.
    #[must_use]
    pub fn with_relay_ticket_key(mut self, key: [u8; 32]) -> Self {
        self.relay_ticket_key = Some(Arc::new(key));
        self
    }

    /// Load persisted state, or start with an empty store when the file does not exist.
    pub fn load(path: impl Into<PathBuf>) -> io::Result<Self> {
        let path = path.into();
        let store = match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_file() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "coordinator state path must be a regular non-symlink file",
                    ));
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if metadata.permissions().mode() & 0o077 != 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "coordinator state file permissions must be 0600 or stricter",
                        ));
                    }
                }
                let bytes = fs::read(&path)?;
                let snapshot: StateSnapshot = serde_json::from_slice(&bytes).map_err(|error| {
                    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
                })?;
                Store::from_snapshot(snapshot)?
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Store::default(),
            Err(error) => return Err(error),
        };
        Ok(Self {
            inner: Arc::new(RwLock::new(store)),
            persistence: Some(Arc::new(path)),
            request_limiter: RequestRateLimiter::default(),
            ..Self::default()
        })
    }

    async fn relay_ticket(
        &self,
        network_id: Uuid,
        request: RelayTicketRequest,
    ) -> Result<RelayTicketResponse, ApiError> {
        let key = self.relay_ticket_key.as_ref().ok_or(ApiError::Internal)?;
        let now = unix_time_ms().ok_or(ApiError::Internal)?;
        if request.device_id == request.peer_id
            || request.timestamp_ms.abs_diff(now) > SIGNATURE_CLOCK_SKEW_MS
        {
            return Err(ApiError::InvalidRequest("invalid peer or timestamp"));
        }
        let store = self.inner.read().await;
        let network = store.networks.get(&network_id).ok_or(ApiError::NotFound)?;
        let source = network
            .members
            .get(&request.device_id)
            .ok_or(ApiError::Unauthorized)?;
        network
            .members
            .get(&request.peer_id)
            .ok_or(ApiError::Unauthorized)?;
        if !verify_signature(
            &source.public_key,
            &relay_ticket_request_signing_bytes(
                &network_id.to_string(),
                &request.device_id,
                &request.peer_id,
                request.timestamp_ms,
            ),
            &request.signature,
        ) {
            return Err(ApiError::Unauthorized);
        }
        drop(store);
        let mut pair_key = (
            network_id,
            request.device_id.clone(),
            request.peer_id.clone(),
        );
        if pair_key.1 > pair_key.2 {
            std::mem::swap(&mut pair_key.1, &mut pair_key.2);
        }
        let expires_at_ms = now.saturating_add(45_000);
        let session_id = {
            let mut pairs = self.relay_pairs.lock().map_err(|_| ApiError::Internal)?;
            pairs.retain(|_, pair| pair.expires_at_ms > now);
            if pairs.len() >= 8192 && !pairs.contains_key(&pair_key) {
                return Err(ApiError::Conflict("relay pairing capacity reached"));
            }
            if let Some(pair) = pairs.get(&pair_key) {
                if pair.first_device != request.device_id {
                    let id = pair.session_id;
                    pairs.remove(&pair_key);
                    id
                } else {
                    pair.session_id
                }
            } else {
                let mut session_id = [0_u8; 16];
                random_fill(&mut session_id).map_err(|_| ApiError::Internal)?;
                pairs.insert(
                    pair_key,
                    RelayPair {
                        session_id,
                        expires_at_ms,
                        first_device: request.device_id.clone(),
                    },
                );
                session_id
            }
        };
        let mut ticket_id = [0_u8; 16];
        random_fill(&mut ticket_id).map_err(|_| ApiError::Internal)?;
        let claims = RelayTicketClaims {
            version: RELAY_TICKET_VERSION,
            network_id: network_id.to_string(),
            source_device_id: request.device_id,
            target_device_id: request.peer_id,
            session_id,
            ticket_id,
            expires_at_ms,
        };
        let ticket = issue_relay_ticket(key, &claims).map_err(|_| ApiError::Internal)?;
        Ok(RelayTicketResponse {
            ticket,
            expires_at_ms,
        })
    }

    fn persist_or_restore(&self, store: &mut Store, previous: Store) -> Result<(), ApiError> {
        let Some(path) = &self.persistence else {
            return Ok(());
        };
        if persist_store(path, store).is_err() {
            *store = previous;
            return Err(ApiError::Persistence);
        }
        Ok(())
    }

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
        let previous = store.clone();
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
        self.persist_or_restore(&mut store, previous)?;

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
        let previous = store.clone();
        let network = store
            .networks
            .get_mut(&network_id)
            .ok_or(ApiError::NotFound)?;
        if !constant_time_equal(&network.admin_token_hash, &token_hash(&request.admin_token)) {
            return Err(ApiError::Unauthorized);
        }
        let now_ms = unix_time_ms().ok_or(ApiError::Internal)?;
        network
            .invites
            .retain(|_, invite| invite.expires_at_ms > now_ms);
        if network.invites.len() >= MAX_INVITES_PER_NETWORK {
            return Err(ApiError::Conflict("network invitation capacity reached"));
        }
        let (invite_token, invite_hash) = create_token()?;
        network.invites.insert(
            invite_hash,
            Invite {
                consumed_by: None,
                expires_at_ms: now_ms.saturating_add(INVITE_TTL.as_millis() as u64),
            },
        );
        self.persist_or_restore(&mut store, previous)?;
        Ok(CreateInviteResponse {
            invite_token,
            expires_in_seconds: INVITE_TTL.as_secs(),
        })
    }

    async fn revoke_member(
        &self,
        network_id: Uuid,
        request: RevokeMemberRequest,
    ) -> Result<RevokeMemberResponse, ApiError> {
        if request.device_id.trim().is_empty()
            || request.device_id.len() > MAX_DEVICE_ID_BYTES
            || request.device_id.chars().any(char::is_control)
        {
            return Err(ApiError::InvalidRequest(
                "device_id must be 1-128 bytes and contain no control characters",
            ));
        }
        let mut store = self.inner.write().await;
        let previous = store.clone();
        let network = store
            .networks
            .get_mut(&network_id)
            .ok_or(ApiError::NotFound)?;
        if !constant_time_equal(&network.admin_token_hash, &token_hash(&request.admin_token)) {
            return Err(ApiError::Unauthorized);
        }
        let member = network
            .members
            .remove(&request.device_id)
            .ok_or(ApiError::NotFound)?;
        network.assigned_addresses.remove(&member.address);
        self.persist_or_restore(&mut store, previous)?;
        Ok(RevokeMemberResponse {
            revoked: true,
            released_ipv4: member.address.to_string(),
        })
    }

    async fn join_network(
        &self,
        network_id: Uuid,
        request: JoinNetworkRequest,
    ) -> Result<JoinNetworkResponse, ApiError> {
        let public_key = decode_exact::<32>(&request.public_key).ok_or(ApiError::Unauthorized)?;
        if request.device_id != device_id_from_public_key(&public_key)
            || !verify_signature(
                &public_key,
                &join_signing_bytes(
                    &network_id.to_string(),
                    &request.device_id,
                    &public_key,
                    &request.invite_token,
                ),
                &request.signature,
            )
        {
            return Err(ApiError::Unauthorized);
        }
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
        let previous = store.clone();
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
        if invite.expires_at_ms <= unix_time_ms().ok_or(ApiError::Internal)? {
            return Err(ApiError::Unauthorized);
        }

        if let Some(accepted_device) = &invite.consumed_by {
            if accepted_device != &request.device_id {
                return Err(ApiError::Unauthorized);
            }
            let assigned_ipv4 = network
                .members
                .get(&request.device_id)
                .filter(|member| member.public_key == public_key)
                .map(|member| member.address)
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
        network.members.insert(
            request.device_id.clone(),
            Member {
                address: assigned_ipv4,
                public_key,
                candidates: Vec::new(),
                last_candidate_timestamp_ms: 0,
            },
        );
        invite.consumed_by = Some(request.device_id.clone());
        let cidr = network.cidr.to_string();
        self.persist_or_restore(&mut store, previous)?;

        Ok(JoinNetworkResponse {
            network_id: network_id.to_string(),
            device_id: request.device_id,
            assigned_ipv4: assigned_ipv4.to_string(),
            cidr,
        })
    }

    async fn update_candidates(
        &self,
        network_id: Uuid,
        request: CandidateUpdateRequest,
    ) -> Result<CandidateUpdateResponse, ApiError> {
        let now = unix_time_ms().ok_or(ApiError::Internal)?;
        if request.timestamp_ms.abs_diff(now) > SIGNATURE_CLOCK_SKEW_MS
            || request.candidates.len() > MAX_CANDIDATES
        {
            return Err(ApiError::InvalidRequest(
                "timestamp is outside the allowed window or too many candidates",
            ));
        }
        let mut canonical = request.candidates.clone();
        canonical.sort();
        if canonical.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(ApiError::InvalidRequest(
                "candidate addresses must be unique",
            ));
        }
        for candidate in &canonical {
            let address = candidate_socket_address(candidate).ok_or(ApiError::InvalidRequest(
                "candidate must be a socket address",
            ))?;
            if address.port() == 0 || address.ip().is_unspecified() || address.ip().is_multicast() {
                return Err(ApiError::InvalidRequest("candidate address is not usable"));
            }
        }
        let mut store = self.inner.write().await;
        let previous = store.clone();
        let network = store
            .networks
            .get_mut(&network_id)
            .ok_or(ApiError::NotFound)?;
        let member = network
            .members
            .get_mut(&request.device_id)
            .ok_or(ApiError::Unauthorized)?;
        if request.timestamp_ms <= member.last_candidate_timestamp_ms {
            return Err(ApiError::Conflict("candidate update replay detected"));
        }
        if !verify_signature(
            &member.public_key,
            &candidate_signing_bytes(
                &network_id.to_string(),
                &request.device_id,
                request.timestamp_ms,
                &canonical,
            ),
            &request.signature,
        ) {
            return Err(ApiError::Unauthorized);
        }
        member.candidates = canonical;
        member.last_candidate_timestamp_ms = request.timestamp_ms;
        self.persist_or_restore(&mut store, previous)?;
        Ok(CandidateUpdateResponse { accepted: true })
    }

    async fn list_peers(
        &self,
        network_id: Uuid,
        request: PeerListRequest,
    ) -> Result<PeerListResponse, ApiError> {
        let now = unix_time_ms().ok_or(ApiError::Internal)?;
        if request.timestamp_ms.abs_diff(now) > SIGNATURE_CLOCK_SKEW_MS {
            return Err(ApiError::InvalidRequest(
                "timestamp is outside the allowed window",
            ));
        }
        let store = self.inner.read().await;
        let network = store.networks.get(&network_id).ok_or(ApiError::NotFound)?;
        let requester = network
            .members
            .get(&request.device_id)
            .ok_or(ApiError::Unauthorized)?;
        if !verify_signature(
            &requester.public_key,
            &peers_signing_bytes(
                &network_id.to_string(),
                &request.device_id,
                request.timestamp_ms,
            ),
            &request.signature,
        ) {
            return Err(ApiError::Unauthorized);
        }
        let peers = network
            .members
            .iter()
            .filter(|(id, _)| *id != &request.device_id)
            .map(|(device_id, member)| PeerInfo {
                device_id: device_id.clone(),
                assigned_ipv4: member.address.to_string(),
                public_key: URL_SAFE_NO_PAD.encode(member.public_key),
                candidates: member.candidates.clone(),
            })
            .collect();
        Ok(PeerListResponse { peers })
    }
}

impl Store {
    fn snapshot(&self) -> StateSnapshot {
        StateSnapshot {
            schema_version: 1,
            networks: self
                .networks
                .iter()
                .map(|(id, network)| PersistedNetwork {
                    id: *id,
                    cidr: network.cidr.to_string(),
                    admin_token_hash: network.admin_token_hash,
                    invites: network
                        .invites
                        .iter()
                        .map(|(token_hash, invite)| PersistedInvite {
                            token_hash: *token_hash,
                            consumed_by: invite.consumed_by.clone(),
                            expires_at_ms: invite.expires_at_ms,
                        })
                        .collect(),
                    members: network
                        .members
                        .iter()
                        .map(|(device_id, member)| PersistedMember {
                            device_id: device_id.clone(),
                            address: member.address,
                            public_key: member.public_key,
                            candidates: member.candidates.clone(),
                            last_candidate_timestamp_ms: member.last_candidate_timestamp_ms,
                        })
                        .collect(),
                })
                .collect(),
        }
    }

    fn from_snapshot(snapshot: StateSnapshot) -> io::Result<Self> {
        if snapshot.schema_version != 1 || snapshot.networks.len() > MAX_NETWORKS {
            return Err(invalid_state(
                "unsupported state version or network capacity",
            ));
        }
        let mut store = Store::default();
        for persisted in snapshot.networks {
            let cidr = persisted
                .cidr
                .parse::<Ipv4Net>()
                .map_err(|_| invalid_state("invalid network CIDR"))?;
            if !valid_network_cidr(cidr)
                || store
                    .networks
                    .values()
                    .any(|network| cidrs_overlap(cidr, network.cidr))
                || persisted.invites.len() > MAX_INVITES_PER_NETWORK
            {
                return Err(invalid_state("invalid or overlapping persisted network"));
            }
            let mut invites = HashMap::new();
            for invite in persisted.invites {
                if invites
                    .insert(
                        invite.token_hash,
                        Invite {
                            consumed_by: invite.consumed_by,
                            expires_at_ms: invite.expires_at_ms,
                        },
                    )
                    .is_some()
                {
                    return Err(invalid_state("duplicate persisted invitation"));
                }
            }
            let mut members = HashMap::new();
            let mut assigned_addresses = HashSet::new();
            for member in persisted.members {
                if member.device_id != device_id_from_public_key(&member.public_key)
                    || member.candidates.len() > MAX_CANDIDATES
                    || member.candidates.iter().any(|candidate| {
                        candidate_socket_address(candidate)
                            .map(|address| {
                                address.port() == 0
                                    || address.ip().is_unspecified()
                                    || address.ip().is_multicast()
                            })
                            .unwrap_or(true)
                    })
                    || !cidr.hosts().any(|address| address == member.address)
                    || !assigned_addresses.insert(member.address)
                    || members
                        .insert(
                            member.device_id,
                            Member {
                                address: member.address,
                                public_key: member.public_key,
                                candidates: member.candidates,
                                last_candidate_timestamp_ms: member.last_candidate_timestamp_ms,
                            },
                        )
                        .is_some()
                {
                    return Err(invalid_state("invalid persisted member"));
                }
            }
            if invites.values().any(|invite| {
                invite
                    .consumed_by
                    .as_ref()
                    .is_some_and(|device_id| !members.contains_key(device_id))
            }) {
                return Err(invalid_state(
                    "persisted invitation references an unknown member",
                ));
            }
            store.networks.insert(
                persisted.id,
                Network {
                    cidr,
                    admin_token_hash: persisted.admin_token_hash,
                    invites,
                    members,
                    assigned_addresses,
                },
            );
        }
        Ok(store)
    }
}

fn valid_network_cidr(cidr: Ipv4Net) -> bool {
    (16..=30).contains(&cidr.prefix_len())
        && cidr.network().is_private()
        && cidr.broadcast().is_private()
}

fn invalid_state(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_owned())
}

fn persist_store(path: &FsPath, store: &Store) -> io::Result<()> {
    let bytes = serde_json::to_vec(&store.snapshot())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(FsPath::new("."));
    fs::create_dir_all(parent)?;
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "coordinator state path must be a regular non-symlink file",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "coordinator state file permissions must be 0600 or stricter",
                ));
            }
        }
    }
    let file_name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "state path has no filename"))?;
    let temporary = path.with_file_name(format!(
        ".{}.{}.tmp",
        file_name.to_string_lossy(),
        Uuid::new_v4()
    ));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let write_result = (|| {
        let mut file = options.open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        // The rename is the commit point. A directory sync failure must not report a failed
        // mutation after the new snapshot became visible and cause memory/disk divergence.
        let _ = fs::File::open(parent).and_then(|directory| directory.sync_all());
        Ok(())
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    write_result
}

pub fn router() -> Router {
    router_with_state(CoordinatorState::default())
}

pub fn router_with_state(state: CoordinatorState) -> Router {
    Router::new()
        .route("/healthz", get(health))
        .route("/v1/networks", post(create_network))
        .route("/v1/networks/{network_id}/invites", post(create_invite))
        .route(
            "/v1/networks/{network_id}/members/revoke",
            post(revoke_member),
        )
        .route("/v1/networks/{network_id}/join", post(join_network))
        .route(
            "/v1/networks/{network_id}/candidates",
            post(update_candidates),
        )
        .route("/v1/networks/{network_id}/peers", post(list_peers))
        .route("/v1/networks/{network_id}/relay-ticket", post(relay_ticket))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .layer(from_fn_with_state(state.clone(), limit_requests))
        .with_state(state)
}

async fn limit_requests(
    State(state): State<CoordinatorState>,
    request: Request,
    next: Next,
) -> Response {
    if let Some(ConnectInfo(remote)) = request.extensions().get::<ConnectInfo<SocketAddr>>()
        && !state.request_limiter.allow(remote.ip(), Instant::now())
    {
        let mut response = (
            StatusCode::TOO_MANY_REQUESTS,
            Json(ApiErrorResponse {
                error: "rate_limited".to_owned(),
                message: "request rate limit exceeded".to_owned(),
            }),
        )
            .into_response();
        response
            .headers_mut()
            .insert("retry-after", HeaderValue::from_static("60"));
        return response;
    }
    next.run(request).await
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

async fn revoke_member(
    State(state): State<CoordinatorState>,
    Path(network_id): Path<String>,
    Json(request): Json<RevokeMemberRequest>,
) -> Result<Json<RevokeMemberResponse>, ApiError> {
    let network_id = Uuid::parse_str(&network_id)
        .map_err(|_| ApiError::InvalidRequest("network_id must be a UUID"))?;
    state.revoke_member(network_id, request).await.map(Json)
}

async fn update_candidates(
    State(state): State<CoordinatorState>,
    Path(network_id): Path<String>,
    Json(request): Json<CandidateUpdateRequest>,
) -> Result<Json<CandidateUpdateResponse>, ApiError> {
    let network_id = Uuid::parse_str(&network_id)
        .map_err(|_| ApiError::InvalidRequest("network_id must be a UUID"))?;
    state.update_candidates(network_id, request).await.map(Json)
}

async fn list_peers(
    State(state): State<CoordinatorState>,
    Path(network_id): Path<String>,
    Json(request): Json<PeerListRequest>,
) -> Result<Json<PeerListResponse>, ApiError> {
    let network_id = Uuid::parse_str(&network_id)
        .map_err(|_| ApiError::InvalidRequest("network_id must be a UUID"))?;
    state.list_peers(network_id, request).await.map(Json)
}

async fn relay_ticket(
    State(state): State<CoordinatorState>,
    Path(network_id): Path<String>,
    Json(request): Json<RelayTicketRequest>,
) -> Result<Json<RelayTicketResponse>, ApiError> {
    let network_id = Uuid::parse_str(&network_id)
        .map_err(|_| ApiError::InvalidRequest("network_id must be a UUID"))?;
    state.relay_ticket(network_id, request).await.map(Json)
}

fn decode_exact<const N: usize>(encoded: &str) -> Option<[u8; N]> {
    URL_SAFE_NO_PAD.decode(encoded).ok()?.try_into().ok()
}

fn candidate_socket_address(candidate: &str) -> Option<SocketAddr> {
    candidate
        .strip_prefix("tcp://")
        .unwrap_or(candidate)
        .parse::<SocketAddr>()
        .ok()
}

fn verify_signature(public_key: &[u8; 32], message: &[u8], signature: &str) -> bool {
    let Ok(key) = VerifyingKey::from_bytes(public_key) else {
        return false;
    };
    let Some(signature) = decode_exact::<64>(signature) else {
        return false;
    };
    key.verify_strict(message, &Signature::from_bytes(&signature))
        .is_ok()
}

fn unix_time_ms() -> Option<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_millis()
        .try_into()
        .ok()
}

pub async fn serve(address: SocketAddr) -> std::io::Result<()> {
    serve_with_state(address, CoordinatorState::default()).await
}

pub async fn serve_with_state_file(
    address: SocketAddr,
    state_file: impl Into<PathBuf>,
) -> std::io::Result<()> {
    serve_with_state(address, CoordinatorState::load(state_file)?).await
}

pub async fn serve_with_state_file_and_relay_key(
    address: SocketAddr,
    state_file: impl Into<PathBuf>,
    relay_ticket_key: Option<[u8; 32]>,
) -> std::io::Result<()> {
    let mut state = CoordinatorState::load(state_file)?;
    if let Some(key) = relay_ticket_key {
        state = state.with_relay_ticket_key(key);
    }
    serve_with_state(address, state).await
}

async fn serve_with_state(address: SocketAddr, state: CoordinatorState) -> std::io::Result<()> {
    let listener = TcpListener::bind(address).await?;
    tracing::info!(address = %listener.local_addr()?, "coordinator listening");
    axum::serve(
        listener,
        router_with_state(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
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
    use axum::{body::Body, extract::connect_info::ConnectInfo, http::Request as HttpRequest};
    use ed25519_dalek::{Signer, SigningKey};
    use tower::ServiceExt;

    #[test]
    fn request_limiter_is_per_ip_bounded_and_recovers_after_window() {
        let limiter = RequestRateLimiter::new(2, Duration::from_secs(10));
        let first_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let second_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
        let start = Instant::now();
        assert!(limiter.allow(first_ip, start));
        assert!(limiter.allow(first_ip, start));
        assert!(!limiter.allow(first_ip, start));
        assert!(limiter.allow(second_ip, start));
        assert!(limiter.allow(first_ip, start + Duration::from_secs(10)));
    }

    #[test]
    fn request_limiter_caps_source_table_and_reclaims_expired_entries() {
        let limiter = RequestRateLimiter::new(1, Duration::from_secs(10));
        let start = Instant::now();
        for address in 0..MAX_RATE_LIMIT_CLIENTS as u32 {
            assert!(limiter.allow(IpAddr::V4(Ipv4Addr::from(address)), start,));
        }
        let next_ip = IpAddr::V4(Ipv4Addr::from(MAX_RATE_LIMIT_CLIENTS as u32));
        assert!(!limiter.allow(next_ip, start));
        assert!(limiter.allow(next_ip, start + Duration::from_secs(10)));
        assert_eq!(limiter.clients.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn router_returns_429_with_retry_after_for_over_limit_source() {
        let state = CoordinatorState {
            request_limiter: RequestRateLimiter::new(1, Duration::from_secs(60)),
            ..CoordinatorState::default()
        };
        let app = router_with_state(state);
        let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 12345);
        let make_request = || {
            let mut request = HttpRequest::builder()
                .uri("/healthz")
                .body(Body::empty())
                .expect("valid request");
            request.extensions_mut().insert(ConnectInfo(source));
            request
        };
        assert_eq!(
            app.clone()
                .oneshot(make_request())
                .await
                .expect("first response")
                .status(),
            StatusCode::OK
        );
        let limited = app
            .clone()
            .oneshot(make_request())
            .await
            .expect("limited response");
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(limited.headers().get("retry-after").unwrap(), "60");

        let mut other_request = HttpRequest::builder()
            .uri("/healthz")
            .body(Body::empty())
            .expect("valid request");
        other_request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
                12346,
            )));
        assert_eq!(
            app.oneshot(other_request)
                .await
                .expect("independent source response")
                .status(),
            StatusCode::OK
        );
    }

    fn create_request(name: &str, cidr: &str) -> CreateNetworkRequest {
        CreateNetworkRequest {
            name: name.to_owned(),
            cidr: cidr.to_owned(),
        }
    }

    fn network_uuid(response: &CreateNetworkResponse) -> Uuid {
        Uuid::parse_str(&response.network_id).expect("coordinator returns a UUID")
    }

    fn signed_join(network_id: Uuid, invite_token: String, seed: u8) -> JoinNetworkRequest {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let public_key = key.verifying_key().to_bytes();
        let device_id = device_id_from_public_key(&public_key);
        let signature = key.sign(&join_signing_bytes(
            &network_id.to_string(),
            &device_id,
            &public_key,
            &invite_token,
        ));
        JoinNetworkRequest {
            invite_token,
            device_id,
            public_key: URL_SAFE_NO_PAD.encode(public_key),
            signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        }
    }

    #[tokio::test]
    async fn relay_tickets_require_network_members_and_pair_opposite_requests() {
        let key_a = SigningKey::from_bytes(&[31; 32]);
        let key_b = SigningKey::from_bytes(&[32; 32]);
        let id_a = device_id_from_public_key(&key_a.verifying_key().to_bytes());
        let id_b = device_id_from_public_key(&key_b.verifying_key().to_bytes());
        let network_id = Uuid::new_v4();
        let mut network = Network {
            cidr: "10.8.0.0/24".parse().unwrap(),
            admin_token_hash: [0; 32],
            invites: HashMap::new(),
            members: HashMap::new(),
            assigned_addresses: HashSet::new(),
        };
        network.members.insert(
            id_a.clone(),
            Member {
                address: "10.8.0.1".parse().unwrap(),
                public_key: key_a.verifying_key().to_bytes(),
                candidates: Vec::new(),
                last_candidate_timestamp_ms: 0,
            },
        );
        network.members.insert(
            id_b.clone(),
            Member {
                address: "10.8.0.2".parse().unwrap(),
                public_key: key_b.verifying_key().to_bytes(),
                candidates: Vec::new(),
                last_candidate_timestamp_ms: 0,
            },
        );
        let state = CoordinatorState::default().with_relay_ticket_key([9; 32]);
        state
            .inner
            .write()
            .await
            .networks
            .insert(network_id, network);
        let now = unix_time_ms().unwrap();
        let make = |signer: &SigningKey, source: &str, target: &str| {
            let sig = signer.sign(&relay_ticket_request_signing_bytes(
                &network_id.to_string(),
                source,
                target,
                now,
            ));
            RelayTicketRequest {
                device_id: source.to_owned(),
                peer_id: target.to_owned(),
                timestamp_ms: now,
                signature: URL_SAFE_NO_PAD.encode(sig.to_bytes()),
            }
        };
        let ticket_a = state
            .relay_ticket(network_id, make(&key_a, &id_a, &id_b))
            .await
            .unwrap();
        let ticket_b = state
            .relay_ticket(network_id, make(&key_b, &id_b, &id_a))
            .await
            .unwrap();
        let claims_a =
            mini_tunnel_protocol::verify_relay_ticket(&[9; 32], &ticket_a.ticket, now).unwrap();
        let claims_b =
            mini_tunnel_protocol::verify_relay_ticket(&[9; 32], &ticket_b.ticket, now).unwrap();
        assert_eq!(claims_a.session_id, claims_b.session_id);
        assert_ne!(claims_a.ticket_id, claims_b.ticket_id);
        assert!(matches!(
            state
                .relay_ticket(network_id, make(&key_a, &id_a, &"f".repeat(32)))
                .await,
            Err(ApiError::Unauthorized)
        ));
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
        let first_join = signed_join(network_id, first_invite.invite_token.clone(), 1);
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
                signed_join(network_id, second_invite.invite_token, 2),
            )
            .await
            .expect("second device should enroll");
        assert_eq!(second.assigned_ipv4, "10.77.0.2");
    }

    #[tokio::test]
    async fn admin_revocation_removes_member_and_releases_its_ipv4_address() {
        let state = CoordinatorState::default();
        let network = state
            .create_network(create_request("lab", "10.79.0.0/16"))
            .await
            .unwrap();
        let network_id = network_uuid(&network);
        let invite = state
            .create_invite(
                network_id,
                CreateInviteRequest {
                    admin_token: network.admin_token.clone(),
                },
            )
            .await
            .unwrap();
        let member = state
            .join_network(network_id, signed_join(network_id, invite.invite_token, 1))
            .await
            .unwrap();
        assert_eq!(member.assigned_ipv4, "10.79.0.1");

        assert!(matches!(
            state
                .revoke_member(
                    network_id,
                    RevokeMemberRequest {
                        admin_token: "wrong".to_owned(),
                        device_id: member.device_id.clone(),
                    },
                )
                .await,
            Err(ApiError::Unauthorized)
        ));
        let revoked = state
            .revoke_member(
                network_id,
                RevokeMemberRequest {
                    admin_token: network.admin_token.clone(),
                    device_id: member.device_id,
                },
            )
            .await
            .unwrap();
        assert!(revoked.revoked);
        assert_eq!(revoked.released_ipv4, "10.79.0.1");

        let next_invite = state
            .create_invite(
                network_id,
                CreateInviteRequest {
                    admin_token: network.admin_token,
                },
            )
            .await
            .unwrap();
        let next = state
            .join_network(
                network_id,
                signed_join(network_id, next_invite.invite_token, 2),
            )
            .await
            .unwrap();
        assert_eq!(next.assigned_ipv4, "10.79.0.1");
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
                signed_join(network_id, invite.invite_token.clone(), 3),
            )
            .await
            .expect("first use should succeed");
        let replay = state
            .join_network(network_id, signed_join(network_id, invite.invite_token, 4))
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

    #[tokio::test]
    async fn signed_candidates_reject_replay_and_peer_queries_are_network_scoped() {
        let state = CoordinatorState::default();
        let one = state
            .create_network(create_request("one", "10.80.0.0/16"))
            .await
            .expect("network");
        let two = state
            .create_network(create_request("two", "10.81.0.0/16"))
            .await
            .expect("network");
        let network_id = network_uuid(&one);
        let invite_a = state
            .create_invite(
                network_id,
                CreateInviteRequest {
                    admin_token: one.admin_token.clone(),
                },
            )
            .await
            .expect("invite");
        let invite_b = state
            .create_invite(
                network_id,
                CreateInviteRequest {
                    admin_token: one.admin_token,
                },
            )
            .await
            .expect("invite");
        let join_a = signed_join(network_id, invite_a.invite_token, 11);
        let join_b = signed_join(network_id, invite_b.invite_token, 12);
        state
            .join_network(network_id, join_a.clone())
            .await
            .expect("join A");
        state
            .join_network(network_id, join_b.clone())
            .await
            .expect("join B");
        let key_a = SigningKey::from_bytes(&[11; 32]);
        let mut candidates = vec![
            "198.51.100.8:42000".to_owned(),
            "tcp://198.51.100.8:42001".to_owned(),
        ];
        candidates.sort();
        let timestamp_ms = unix_time_ms().expect("clock");
        let signature = key_a.sign(&candidate_signing_bytes(
            &network_id.to_string(),
            &join_a.device_id,
            timestamp_ms,
            &candidates,
        ));
        let update = CandidateUpdateRequest {
            device_id: join_a.device_id.clone(),
            timestamp_ms,
            candidates,
            signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        };
        state
            .update_candidates(network_id, update.clone())
            .await
            .expect("signed candidate update");
        assert!(matches!(
            state.update_candidates(network_id, update).await,
            Err(ApiError::Conflict(_))
        ));

        let timestamp_ms = unix_time_ms().expect("clock");
        let key_b = SigningKey::from_bytes(&[12; 32]);
        let signature = key_b.sign(&peers_signing_bytes(
            &network_id.to_string(),
            &join_b.device_id,
            timestamp_ms,
        ));
        let snapshot = state
            .list_peers(
                network_id,
                PeerListRequest {
                    device_id: join_b.device_id.clone(),
                    timestamp_ms,
                    signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
                },
            )
            .await
            .expect("same-network peers");
        assert_eq!(snapshot.peers.len(), 1);
        assert_eq!(
            snapshot.peers[0].candidates,
            ["198.51.100.8:42000", "tcp://198.51.100.8:42001"]
        );

        let timestamp_ms = unix_time_ms().expect("clock");
        let signature = key_b.sign(&peers_signing_bytes(
            &two.network_id,
            &join_b.device_id,
            timestamp_ms,
        ));
        let cross_network = state
            .list_peers(
                network_uuid(&two),
                PeerListRequest {
                    device_id: join_b.device_id,
                    timestamp_ms,
                    signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
                },
            )
            .await;
        assert!(matches!(cross_network, Err(ApiError::Unauthorized)));
    }

    #[tokio::test]
    async fn rejects_invalid_candidate_and_forged_enrollment_proof() {
        let state = CoordinatorState::default();
        let network = state
            .create_network(create_request("lab", "10.82.0.0/16"))
            .await
            .expect("network");
        let network_id = network_uuid(&network);
        let invite = state
            .create_invite(
                network_id,
                CreateInviteRequest {
                    admin_token: network.admin_token,
                },
            )
            .await
            .expect("invite");
        let mut forged = signed_join(network_id, invite.invite_token, 21);
        forged.signature = URL_SAFE_NO_PAD.encode([0_u8; 64]);
        assert!(matches!(
            state.join_network(network_id, forged).await,
            Err(ApiError::Unauthorized)
        ));
        let invalid = CandidateUpdateRequest {
            device_id: "unknown".into(),
            timestamp_ms: unix_time_ms().expect("clock"),
            candidates: vec!["0.0.0.0:0".into()],
            signature: String::new(),
        };
        assert!(matches!(
            state.update_candidates(network_id, invalid).await,
            Err(ApiError::InvalidRequest(_))
        ));
    }

    #[tokio::test]
    async fn persisted_state_restores_members_candidates_and_single_use_invites() {
        let dir = std::env::temp_dir().join(format!("mini-tunnel-state-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).expect("create test directory");
        let path = dir.join("coordinator.json");
        let state = CoordinatorState::load(&path).expect("open empty persistent state");
        let network = state
            .create_network(create_request("lab", "10.83.0.0/16"))
            .await
            .expect("create network");
        let network_id = network_uuid(&network);
        let invite_a = state
            .create_invite(
                network_id,
                CreateInviteRequest {
                    admin_token: network.admin_token.clone(),
                },
            )
            .await
            .expect("invite A");
        let invite_b = state
            .create_invite(
                network_id,
                CreateInviteRequest {
                    admin_token: network.admin_token.clone(),
                },
            )
            .await
            .expect("invite B");
        let join_a = signed_join(network_id, invite_a.invite_token.clone(), 31);
        let join_b = signed_join(network_id, invite_b.invite_token.clone(), 32);
        let enrolled_a = state
            .join_network(network_id, join_a.clone())
            .await
            .expect("enroll A");
        let enrolled_b = state
            .join_network(network_id, join_b.clone())
            .await
            .expect("enroll B");
        assert_eq!(enrolled_b.assigned_ipv4, "10.83.0.2");

        let key_b = SigningKey::from_bytes(&[32; 32]);
        let timestamp_ms = unix_time_ms().expect("clock");
        let candidates = vec!["198.51.100.22:42000".to_owned()];
        let signature = key_b.sign(&candidate_signing_bytes(
            &network_id.to_string(),
            &join_b.device_id,
            timestamp_ms,
            &candidates,
        ));
        state
            .update_candidates(
                network_id,
                CandidateUpdateRequest {
                    device_id: join_b.device_id.clone(),
                    timestamp_ms,
                    candidates,
                    signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
                },
            )
            .await
            .expect("publish B candidates");
        drop(state);

        let contents = fs::read_to_string(&path).expect("read persisted snapshot");
        assert!(!contents.contains(&network.admin_token));
        assert!(!contents.contains(&invite_a.invite_token));
        assert!(!contents.contains(&invite_b.invite_token));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path)
                    .expect("state metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }

        let restored = CoordinatorState::load(&path).expect("restore state");
        let timestamp_ms = unix_time_ms().expect("clock");
        let signature = SigningKey::from_bytes(&[31; 32]).sign(&peers_signing_bytes(
            &network_id.to_string(),
            &join_a.device_id,
            timestamp_ms,
        ));
        let peers = restored
            .list_peers(
                network_id,
                PeerListRequest {
                    device_id: join_a.device_id.clone(),
                    timestamp_ms,
                    signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
                },
            )
            .await
            .expect("list restored peers");
        assert_eq!(peers.peers.len(), 1);
        assert_eq!(peers.peers[0].candidates, ["198.51.100.22:42000"]);
        assert_eq!(peers.peers[0].assigned_ipv4, enrolled_b.assigned_ipv4);
        assert_eq!(enrolled_a.assigned_ipv4, "10.83.0.1");
        assert_eq!(
            restored
                .join_network(network_id, join_a)
                .await
                .expect("same-device join retry")
                .assigned_ipv4,
            enrolled_a.assigned_ipv4
        );
        assert!(matches!(
            restored
                .join_network(
                    network_id,
                    signed_join(network_id, invite_b.invite_token, 33)
                )
                .await,
            Err(ApiError::Unauthorized)
        ));
        fs::remove_dir_all(dir).expect("remove test directory");
    }

    #[tokio::test]
    async fn expired_invites_remain_expired_after_restart() {
        let dir = std::env::temp_dir().join(format!("mini-tunnel-state-expiry-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).expect("create test directory");
        let path = dir.join("coordinator.json");
        let state = CoordinatorState::load(&path).expect("open state");
        let network = state
            .create_network(create_request("lab", "10.84.0.0/16"))
            .await
            .expect("create network");
        let network_id = network_uuid(&network);
        let invite = state
            .create_invite(
                network_id,
                CreateInviteRequest {
                    admin_token: network.admin_token,
                },
            )
            .await
            .expect("create invite");
        {
            let mut store = state.inner.write().await;
            store
                .networks
                .get_mut(&network_id)
                .expect("network")
                .invites
                .values_mut()
                .next()
                .expect("invite")
                .expires_at_ms = 0;
            persist_store(&path, &store).expect("persist expired invite");
        }
        drop(state);
        let restored = CoordinatorState::load(&path).expect("restore state");
        assert!(matches!(
            restored
                .join_network(network_id, signed_join(network_id, invite.invite_token, 34))
                .await,
            Err(ApiError::Unauthorized)
        ));
        fs::remove_dir_all(dir).expect("remove test directory");
    }

    #[test]
    fn corrupt_state_and_unsafe_file_permissions_are_rejected() {
        let dir =
            std::env::temp_dir().join(format!("mini-tunnel-state-invalid-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).expect("create test directory");
        let path = dir.join("coordinator.json");
        fs::write(&path, b"not json").expect("write corrupt state");
        let error = match CoordinatorState::load(&path) {
            Ok(_) => panic!("corrupt state must not silently reset"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::write(&path, br#"{"schema_version":1,"networks":[]}"#).expect("write valid state");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
                .expect("make permissions unsafe");
            let error = match CoordinatorState::load(&path) {
                Ok(_) => panic!("unsafe permissions must be rejected"),
                Err(error) => error,
            };
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            fs::remove_file(&path).expect("remove state file");
            let target = dir.join("target.json");
            fs::write(&target, br#"{"schema_version":1,"networks":[]}"#)
                .expect("write symlink target");
            std::os::unix::fs::symlink(&target, &path).expect("create state symlink");
            let error = match CoordinatorState::load(&path) {
                Ok(_) => panic!("state symlink must be rejected"),
                Err(error) => error,
            };
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        }
        fs::remove_dir_all(dir).expect("remove test directory");
    }

    #[tokio::test]
    async fn failed_snapshot_write_rolls_back_in_memory_mutation() {
        let dir =
            std::env::temp_dir().join(format!("mini-tunnel-state-rollback-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).expect("create test directory");
        let path = dir.join("state-path");
        let state = CoordinatorState::load(&path).expect("open state");
        fs::create_dir(&path).expect("make destination unwritable as a state file");
        assert!(matches!(
            state
                .create_network(create_request("lab", "10.85.0.0/16"))
                .await,
            Err(ApiError::Persistence)
        ));
        assert!(state.inner.read().await.networks.is_empty());
        fs::remove_dir_all(dir).expect("remove test directory");
    }
}
