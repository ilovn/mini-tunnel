use std::{
    collections::{HashMap, HashSet},
    fs,
    io::{self, Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path as FsPath, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use axum::{
    Json, Router,
    extract::{ConnectInfo, DefaultBodyLimit, Path, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    middleware::{Next, from_fn_with_state},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, VerifyingKey};
use getrandom::fill as random_fill;
use ipnet::{IpNet, Ipv4Net};
use mini_tunnel_protocol::{
    ApiErrorResponse, CandidateUpdateRequest, CandidateUpdateResponse, CreateInviteRequest,
    CreateInviteResponse, CreateNetworkRequest, CreateNetworkResponse, IceCredentials,
    JoinNetworkRequest, JoinNetworkResponse, MAX_NETWORK_MEMBERS, PeerInfo, PeerListRequest,
    PeerListResponse, RELAY_TICKET_VERSION, RelayTicketClaims, RelayTicketRequest,
    RelayTicketResponse, RevokeMemberRequest, RevokeMemberResponse, candidate_signing_bytes,
    candidate_signing_bytes_with_ice, device_id_from_public_key, issue_relay_ticket,
    join_signing_bytes, overlay_ipv6_prefix, peers_signing_bytes,
    relay_ticket_request_signing_bytes,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::{io::AsyncReadExt, net::TcpListener, sync::RwLock};
use uuid::Uuid;

pub const SERVICE_VERSION: &str = env!("CARGO_PKG_VERSION");
const MAX_NETWORKS: usize = 128;
const MAX_INVITES_PER_NETWORK: usize = 1024;
const MAX_TOTAL_MEMBERS: usize = 16_384;
const MAX_STATE_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_TLS_FILE_BYTES: u64 = 1024 * 1024;
const COORDINATOR_SHUTDOWN_GRACE: Duration = Duration::from_secs(15);
const MAX_DEVICE_ID_BYTES: usize = 128;
const INVITE_TTL: Duration = Duration::from_secs(60 * 60);
const SIGNATURE_CLOCK_SKEW_MS: u64 = 5 * 60 * 1000;
const MAX_CANDIDATES: usize = 8;
const MAX_REQUESTS_PER_MINUTE_PER_IP: usize = 600;
const MAX_RATE_LIMIT_CLIENTS: usize = 8192;
const MAX_CONCURRENT_API_REQUESTS: usize = 256;
const API_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
const ICE_CREDENTIAL_TTL_MS: u64 = 120_000;
const MAX_EPHEMERAL_ICE_CREDENTIALS: usize = 8192;

#[derive(Debug, Clone, Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub service: &'static str,
    pub version: &'static str,
}

/// Aggregate counts from a validated coordinator snapshot. Contains no credentials or tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateSnapshotSummary {
    pub networks: usize,
    pub members: usize,
    pub invites: usize,
}

#[derive(Clone, Default)]
pub struct CoordinatorState {
    inner: Arc<RwLock<Store>>,
    persistence: Option<Arc<PathBuf>>,
    _state_lock: Option<Arc<fs::File>>,
    request_limiter: RequestRateLimiter,
    request_slots: RequestSlots,
    request_timeout: RequestTimeout,
    concurrency_rejections_total: Arc<AtomicU64>,
    request_timeouts_total: Arc<AtomicU64>,
    trusted_proxies: Arc<Vec<IpNet>>,
    relay_ticket_key: Option<Arc<[u8; 32]>>,
    relay_pairs: Arc<Mutex<RelayPairStore>>,
    ice_credentials: Arc<RwLock<HashMap<(Uuid, String), EphemeralIceCredentials>>>,
}

#[derive(Clone)]
struct RequestSlots(Arc<tokio::sync::Semaphore>);

#[derive(Clone)]
struct RequestTimeout(Duration);

impl Default for RequestTimeout {
    fn default() -> Self {
        Self(API_REQUEST_TIMEOUT)
    }
}

impl Default for RequestSlots {
    fn default() -> Self {
        Self(Arc::new(tokio::sync::Semaphore::new(
            MAX_CONCURRENT_API_REQUESTS,
        )))
    }
}

#[derive(Clone)]
struct EphemeralIceCredentials {
    credentials: IceCredentials,
    updated_at_ms: u64,
    request_timestamp_ms: u64,
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
    rejected_total: Arc<AtomicU64>,
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
            rejected_total: Arc::new(AtomicU64::new(0)),
        }
    }

    fn allow(&self, client: IpAddr, now: Instant) -> bool {
        let client = match client {
            IpAddr::V6(address) => address
                .to_ipv4_mapped()
                .map(IpAddr::V4)
                .unwrap_or(IpAddr::V6(address)),
            address => address,
        };
        let mut clients = lock_recover(&self.clients);
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

const MAX_FORWARDED_FOR_BYTES: usize = 1024;
const MAX_FORWARDED_FOR_HOPS: usize = 16;

fn client_ip_for_request(
    remote: SocketAddr,
    headers: &HeaderMap,
    trusted_proxies: &[IpNet],
) -> IpAddr {
    if !trusted_proxies
        .iter()
        .any(|network| network.contains(&remote.ip()))
    {
        return remote.ip();
    }
    let mut values = headers.get_all("x-forwarded-for").iter();
    let Some(value) = values.next() else {
        return remote.ip();
    };
    if values.next().is_some() {
        return remote.ip();
    }
    let Ok(value) = value.to_str() else {
        return remote.ip();
    };
    if value.len() > MAX_FORWARDED_FOR_BYTES {
        return remote.ip();
    }
    let forwarded = value.split(',').map(str::trim).collect::<Vec<_>>();
    if forwarded.is_empty() || forwarded.len() > MAX_FORWARDED_FOR_HOPS {
        return remote.ip();
    }
    let Ok(addresses) = forwarded
        .iter()
        .map(|address| address.parse::<IpAddr>())
        .collect::<Result<Vec<_>, _>>()
    else {
        return remote.ip();
    };

    // X-Forwarded-For is ordered client-to-proxy. Walk back from the trusted socket peer and
    // return the first address that is not in the trusted proxy set.
    addresses
        .iter()
        .rev()
        .find(|address| {
            !trusted_proxies
                .iter()
                .any(|network| network.contains(*address))
        })
        .copied()
        .unwrap_or(remote.ip())
}

fn lock_recover<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[derive(Clone, Default)]
struct Store {
    networks: HashMap<Uuid, Network>,
}

#[derive(Clone)]
struct Network {
    cidr: Ipv4Net,
    next_address: Ipv4Addr,
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
    /// Validate and atomically copy a snapshot while holding source and destination locks.
    ///
    /// This operation supports both creating backups and restoring them into a stopped state path.
    pub async fn copy_persistent_state_snapshot(
        source: impl Into<PathBuf>,
        destination: impl Into<PathBuf>,
    ) -> io::Result<StateSnapshotSummary> {
        let source = source.into();
        let destination = destination.into();
        let source_metadata = fs::symlink_metadata(&source)?;
        if source_metadata.file_type().is_symlink() || !source_metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "coordinator backup source must be a regular non-symlink file",
            ));
        }
        let source_path = fs::canonicalize(&source)?;
        let source_state = Self::load(&source_path)?;
        let destination_parent = destination
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(FsPath::new("."));
        fs::create_dir_all(destination_parent)?;
        let destination_path = canonical_parented_path(&destination)?;
        let source_lock_path = canonical_parented_path(&state_lock_path(&source_path)?)?;
        let destination_lock_path = canonical_parented_path(&state_lock_path(&destination_path)?)?;
        if source_path == destination_path
            || source_path == destination_lock_path
            || source_lock_path == destination_path
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "coordinator backup source and destination paths overlap",
            ));
        }
        let _destination_lock = acquire_state_file_lock(&destination_path)?;
        let store = source_state.inner.read().await;
        let summary = StateSnapshotSummary {
            networks: store.networks.len(),
            members: store
                .networks
                .values()
                .map(|network| network.members.len())
                .sum(),
            invites: store
                .networks
                .values()
                .map(|network| network.invites.len())
                .sum(),
        };
        persist_store(&destination_path, &store)?;
        Ok(summary)
    }

    /// Validate an existing snapshot while holding its process lock, then return aggregate counts.
    pub async fn verify_persistent_state(
        path: impl Into<PathBuf>,
    ) -> io::Result<StateSnapshotSummary> {
        let path = path.into();
        fs::symlink_metadata(&path)?;
        let state = Self::load(path)?;
        let store = state.inner.read().await;
        Ok(StateSnapshotSummary {
            networks: store.networks.len(),
            members: store
                .networks
                .values()
                .map(|network| network.members.len())
                .sum(),
            invites: store
                .networks
                .values()
                .map(|network| network.invites.len())
                .sum(),
        })
    }

    /// Enable ticket issuance with the secret shared only with trusted relay nodes.
    #[must_use]
    pub fn with_relay_ticket_key(mut self, key: [u8; 32]) -> Self {
        self.relay_ticket_key = Some(Arc::new(key));
        self
    }

    /// Trust forwarded client addresses only from these explicitly configured proxy networks.
    #[must_use]
    pub fn with_trusted_proxies(mut self, networks: Vec<IpNet>) -> Self {
        self.trusted_proxies = Arc::new(networks);
        self
    }

    /// Load persisted state, or start with an empty store when the file does not exist.
    pub fn load(path: impl Into<PathBuf>) -> io::Result<Self> {
        let path = path.into();
        let state_lock = acquire_state_file_lock(&path)?;
        let store = match fs::symlink_metadata(&path) {
            Ok(_) => {
                let state_file = open_regular_state_file(&path)?;
                validate_state_file_size(state_file.metadata()?.len())?;
                let mut bytes = Vec::new();
                state_file
                    .take(MAX_STATE_FILE_BYTES + 1)
                    .read_to_end(&mut bytes)?;
                if bytes.len() as u64 > MAX_STATE_FILE_BYTES {
                    return Err(invalid_state("coordinator state file exceeds size limit"));
                }
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
            _state_lock: Some(state_lock),
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
            let mut pairs = lock_recover(&self.relay_pairs);
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
            if !store.networks.contains_key(&id) && ipv6_prefix_available(&store, id) {
                break id;
            }
        };
        let previous = store.clone();
        store.networks.insert(
            network_id,
            Network {
                cidr,
                next_address: first_host(cidr),
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
        network.next_address = member.address;
        self.persist_or_restore(&mut store, previous)?;
        drop(store);
        self.ice_credentials
            .write()
            .await
            .remove(&(network_id, request.device_id));
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
        let total_members = store
            .networks
            .values()
            .map(|network| network.members.len())
            .sum::<usize>();
        let network = store.networks.get(&network_id).ok_or(ApiError::NotFound)?;
        let invite_hash = network
            .invites
            .keys()
            .find(|stored_hash| constant_time_equal(stored_hash, &requested_hash))
            .copied()
            .ok_or(ApiError::Unauthorized)?;
        let invite = network
            .invites
            .get(&invite_hash)
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
        if member_capacity_reached(network.members.len(), total_members) {
            return Err(ApiError::Conflict("coordinator member capacity reached"));
        }

        let (assigned_ipv4, next_address) = find_available_address(network)
            .ok_or(ApiError::Conflict("network has no free IPv4 addresses"))?;
        let cidr = network.cidr.to_string();
        let previous = store.clone();
        let network = store
            .networks
            .get_mut(&network_id)
            .ok_or(ApiError::NotFound)?;
        network.next_address = next_address;
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
        network
            .invites
            .get_mut(&invite_hash)
            .ok_or(ApiError::Unauthorized)?
            .consumed_by = Some(request.device_id.clone());
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
        if request
            .ice_credentials
            .as_ref()
            .is_some_and(|credentials| !valid_ice_credentials(credentials))
        {
            return Err(ApiError::InvalidRequest("invalid ICE credentials"));
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
        let signing_bytes = match request.ice_credentials.as_ref() {
            Some(credentials) => candidate_signing_bytes_with_ice(
                &network_id.to_string(),
                &request.device_id,
                request.timestamp_ms,
                &canonical,
                credentials,
            ),
            None => candidate_signing_bytes(
                &network_id.to_string(),
                &request.device_id,
                request.timestamp_ms,
                &canonical,
            ),
        };
        if !verify_signature(&member.public_key, &signing_bytes, &request.signature) {
            return Err(ApiError::Unauthorized);
        }
        member.candidates = canonical;
        member.last_candidate_timestamp_ms = request.timestamp_ms;
        self.persist_or_restore(&mut store, previous)?;
        drop(store);

        let key = (network_id, request.device_id);
        let mut ephemeral = self.ice_credentials.write().await;
        ephemeral
            .retain(|_, value| value.updated_at_ms.saturating_add(ICE_CREDENTIAL_TTL_MS) > now);
        match request.ice_credentials {
            Some(credentials) => {
                if let Some(existing) = ephemeral.get(&key)
                    && existing.request_timestamp_ms >= request.timestamp_ms
                {
                    return Ok(CandidateUpdateResponse { accepted: true });
                }
                if !ephemeral.contains_key(&key)
                    && ephemeral.len() >= MAX_EPHEMERAL_ICE_CREDENTIALS
                    && let Some(oldest) = ephemeral
                        .iter()
                        .min_by_key(|(_, value)| value.updated_at_ms)
                        .map(|(key, _)| key.clone())
                {
                    ephemeral.remove(&oldest);
                }
                ephemeral.insert(
                    key,
                    EphemeralIceCredentials {
                        credentials,
                        updated_at_ms: now,
                        request_timestamp_ms: request.timestamp_ms,
                    },
                );
            }
            None => {
                if ephemeral
                    .get(&key)
                    .is_some_and(|value| value.request_timestamp_ms < request.timestamp_ms)
                {
                    ephemeral.remove(&key);
                }
            }
        }
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
        let mut ephemeral = self.ice_credentials.write().await;
        ephemeral
            .retain(|_, value| value.updated_at_ms.saturating_add(ICE_CREDENTIAL_TTL_MS) > now);
        let peers = network
            .members
            .iter()
            .filter(|(id, _)| *id != &request.device_id)
            .map(|(device_id, member)| PeerInfo {
                device_id: device_id.clone(),
                assigned_ipv4: member.address.to_string(),
                public_key: URL_SAFE_NO_PAD.encode(member.public_key),
                candidates: member.candidates.clone(),
                ice_credentials: ephemeral
                    .get(&(network_id, device_id.clone()))
                    .map(|entry| entry.credentials.clone()),
            })
            .collect();
        Ok(PeerListResponse { peers })
    }
}

fn acquire_state_file_lock(path: &FsPath) -> io::Result<Arc<fs::File>> {
    let lock_path = state_lock_path(path)?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(FsPath::new("."));
    fs::create_dir_all(parent)?;
    if let Ok(metadata) = fs::symlink_metadata(&lock_path) {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "coordinator state lock path must be a regular non-symlink file",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "coordinator state lock permissions must be 0600 or stricter",
                ));
            }
        }
    }
    let mut options = fs::OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    configure_no_follow(&mut options);
    let lock = options
        .open(&lock_path)
        .map_err(|error| normalize_no_follow_error(error, "coordinator state lock path"))?;
    let metadata = lock.metadata()?;
    reject_reparse_point(&metadata, "coordinator state lock path")?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "coordinator state lock path must be a regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "coordinator state lock permissions must be 0600 or stricter",
            ));
        }
    }
    lock.try_lock().map_err(|error| match error {
        std::fs::TryLockError::WouldBlock => io::Error::new(
            io::ErrorKind::WouldBlock,
            "coordinator state is already locked by another process",
        ),
        std::fs::TryLockError::Error(error) => error,
    })?;
    Ok(Arc::new(lock))
}

fn state_lock_path(path: &FsPath) -> io::Result<PathBuf> {
    let file_name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "coordinator state path has no filename",
        )
    })?;
    let mut lock_name = file_name.to_os_string();
    lock_name.push(".lock");
    Ok(path.with_file_name(lock_name))
}

fn canonical_parented_path(path: &FsPath) -> io::Result<PathBuf> {
    let file_name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "coordinator state path has no filename",
        )
    })?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(FsPath::new("."));
    Ok(fs::canonicalize(parent)?.join(file_name))
}

fn open_regular_state_file(path: &FsPath) -> io::Result<fs::File> {
    #[cfg(not(unix))]
    {
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "coordinator state path must be a regular non-symlink file",
            ));
        }
    }
    let mut options = fs::OpenOptions::new();
    options.read(true);
    configure_no_follow(&mut options);
    let file = options
        .open(path)
        .map_err(|error| normalize_no_follow_error(error, "coordinator state path"))?;
    let metadata = file.metadata()?;
    reject_reparse_point(&metadata, "coordinator state path")?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "coordinator state path must be a regular file",
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
    Ok(file)
}

#[cfg(unix)]
fn configure_no_follow(options: &mut fs::OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
}

#[cfg(windows)]
fn configure_no_follow(options: &mut fs::OpenOptions) {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
    options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
}

#[cfg(not(any(unix, windows)))]
fn configure_no_follow(_options: &mut fs::OpenOptions) {}

fn reject_reparse_point(metadata: &fs::Metadata, description: &'static str) -> io::Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{description} must not be a reparse point"),
            ));
        }
    }
    let _ = (metadata, description);
    Ok(())
}

fn normalize_no_follow_error(error: io::Error, description: &'static str) -> io::Error {
    #[cfg(unix)]
    if error.raw_os_error() == Some(libc::ELOOP) {
        return io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{description} must not be a symbolic link"),
        );
    }
    let _ = description;
    error
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
        let mut total_members = 0_usize;
        for persisted in snapshot.networks {
            total_members = total_members
                .checked_add(persisted.members.len())
                .ok_or_else(|| invalid_state("persisted member count overflow"))?;
            let cidr = persisted
                .cidr
                .parse::<Ipv4Net>()
                .map_err(|_| invalid_state("invalid network CIDR"))?;
            if !valid_network_cidr(cidr)
                || store
                    .networks
                    .values()
                    .any(|network| cidrs_overlap(cidr, network.cidr))
                || persisted.members.len() > MAX_NETWORK_MEMBERS
                || total_members > MAX_TOTAL_MEMBERS
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
                    next_address: cidr
                        .hosts()
                        .find(|address| !assigned_addresses.contains(address))
                        .unwrap_or_else(|| first_host(cidr)),
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

fn first_host(cidr: Ipv4Net) -> Ipv4Addr {
    Ipv4Addr::from(u32::from(cidr.network()) + 1)
}

fn find_available_address(network: &Network) -> Option<(Ipv4Addr, Ipv4Addr)> {
    let first = u32::from(network.cidr.network()) + 1;
    let last = u32::from(network.cidr.broadcast()) - 1;
    let cursor = u32::from(network.next_address).clamp(first, last);
    for bits in (cursor..=last).chain(first..cursor) {
        let address = Ipv4Addr::from(bits);
        if !network.assigned_addresses.contains(&address) {
            let next = if bits == last { first } else { bits + 1 };
            return Some((address, Ipv4Addr::from(next)));
        }
    }
    None
}

fn invalid_state(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_owned())
}

fn member_capacity_reached(network_members: usize, total_members: usize) -> bool {
    network_members >= MAX_NETWORK_MEMBERS || total_members >= MAX_TOTAL_MEMBERS
}

fn validate_state_file_size(length: u64) -> io::Result<()> {
    if length > MAX_STATE_FILE_BYTES {
        return Err(invalid_state("coordinator state file exceeds size limit"));
    }
    Ok(())
}

fn persist_store(path: &FsPath, store: &Store) -> io::Result<()> {
    let bytes = serde_json::to_vec(&store.snapshot())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
    validate_state_file_size(bytes.len() as u64).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "coordinator state snapshot exceeds size limit",
        )
    })?;
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
        replace_state_file(&temporary, path)?;
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

#[cfg(not(windows))]
fn replace_state_file(temporary: &FsPath, path: &FsPath) -> io::Result<()> {
    fs::rename(temporary, path)
}

#[cfg(windows)]
fn replace_state_file(temporary: &FsPath, path: &FsPath) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };

    let temporary = temporary
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let path = path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    // Both paths are in the same directory, so replacement is atomic on the same volume.
    let replaced = unsafe {
        MoveFileExW(
            temporary.as_ptr(),
            path.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if replaced == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn router() -> Router {
    router_with_state(CoordinatorState::default())
}

pub fn router_with_state(state: CoordinatorState) -> Router {
    Router::new()
        .route("/healthz", get(health))
        .route("/metrics", get(metrics))
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
    let remote = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(remote)| *remote);
    let Some(remote) = remote else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiErrorResponse {
                error: "client_address_unavailable".to_owned(),
                message: "request source address is unavailable".to_owned(),
            }),
        )
            .into_response();
    };
    let loopback_metrics = request.uri().path() == "/metrics" && remote.ip().is_loopback();
    let client_ip = client_ip_for_request(remote, request.headers(), &state.trusted_proxies);
    if !loopback_metrics && !state.request_limiter.allow(client_ip, Instant::now()) {
        state
            .request_limiter
            .rejected_total
            .fetch_add(1, Ordering::Relaxed);
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
    let _permit = if matches!(request.uri().path(), "/healthz" | "/metrics") {
        None
    } else {
        match state.request_slots.0.clone().try_acquire_owned() {
            Ok(permit) => Some(permit),
            Err(_) => {
                state
                    .concurrency_rejections_total
                    .fetch_add(1, Ordering::Relaxed);
                let mut response = (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(ApiErrorResponse {
                        error: "server_busy".to_owned(),
                        message: "coordinator request capacity is temporarily full".to_owned(),
                    }),
                )
                    .into_response();
                response
                    .headers_mut()
                    .insert("retry-after", HeaderValue::from_static("1"));
                return response;
            }
        }
    };
    run_with_timeout(state.request_timeout.0, next.run(request), || {
        state.request_timeouts_total.fetch_add(1, Ordering::Relaxed);
    })
    .await
}

async fn run_with_timeout<F, C>(timeout: Duration, request: F, on_timeout: C) -> Response
where
    F: std::future::Future<Output = Response>,
    C: FnOnce(),
{
    match tokio::time::timeout(timeout, request).await {
        Ok(response) => response,
        Err(_) => {
            on_timeout();
            (
                StatusCode::REQUEST_TIMEOUT,
                Json(ApiErrorResponse {
                    error: "request_timeout".to_owned(),
                    message: "coordinator request exceeded the processing time limit".to_owned(),
                }),
            )
                .into_response()
        }
    }
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        service: "coordinator",
        version: SERVICE_VERSION,
    })
}

async fn metrics(State(state): State<CoordinatorState>, request: Request) -> Response {
    let loopback = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .is_some_and(|ConnectInfo(remote)| remote.ip().is_loopback());
    if !loopback {
        return StatusCode::NOT_FOUND.into_response();
    }
    let store = state.inner.read().await;
    let networks = store.networks.len();
    let members: usize = store
        .networks
        .values()
        .map(|network| network.members.len())
        .sum();
    let body = format!(
        "# HELP mini_tunnel_coordinator_networks Configured overlay networks.\n# TYPE mini_tunnel_coordinator_networks gauge\nmini_tunnel_coordinator_networks {networks}\n# HELP mini_tunnel_coordinator_members Enrolled devices across all networks.\n# TYPE mini_tunnel_coordinator_members gauge\nmini_tunnel_coordinator_members {members}\n# HELP mini_tunnel_coordinator_rate_limited_total Requests rejected by the source IP rate limiter.\n# TYPE mini_tunnel_coordinator_rate_limited_total counter\nmini_tunnel_coordinator_rate_limited_total {}\n# HELP mini_tunnel_coordinator_concurrency_rejected_total API requests rejected because the global in-flight limit was reached.\n# TYPE mini_tunnel_coordinator_concurrency_rejected_total counter\nmini_tunnel_coordinator_concurrency_rejected_total {}\n# HELP mini_tunnel_coordinator_request_timeouts_total API requests that exceeded the processing time limit.\n# TYPE mini_tunnel_coordinator_request_timeouts_total counter\nmini_tunnel_coordinator_request_timeouts_total {}\n",
        state.request_limiter.rejected_total.load(Ordering::Relaxed),
        state.concurrency_rejections_total.load(Ordering::Relaxed),
        state.request_timeouts_total.load(Ordering::Relaxed),
    );
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
        .into_response()
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
    let value = if let Some(value) = candidate.strip_prefix("srflx://") {
        let (mapped, related) = value.split_once('|')?;
        let related = related.parse::<SocketAddr>().ok()?;
        if related.port() == 0 || related.ip().is_multicast() {
            return None;
        }
        mapped
    } else {
        candidate.strip_prefix("tcp://").unwrap_or(candidate)
    };
    let address = value.parse::<SocketAddr>().ok()?;
    (address.port() != 0 && !address.ip().is_unspecified() && !address.ip().is_multicast())
        .then_some(address)
}

fn valid_ice_credentials(credentials: &IceCredentials) -> bool {
    let valid_chars = |value: &str| {
        value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/')
    };
    (4..=256).contains(&credentials.ufrag.len())
        && (22..=256).contains(&credentials.password.len())
        && credentials.generation > 0
        && valid_chars(&credentials.ufrag)
        && valid_chars(&credentials.password)
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

pub async fn serve_with_state_file_and_relay_key_tls(
    address: SocketAddr,
    state_file: impl Into<PathBuf>,
    relay_ticket_key: Option<[u8; 32]>,
    tls_files: Option<(PathBuf, PathBuf)>,
) -> std::io::Result<()> {
    serve_with_state_file_and_relay_key_tls_and_reload_interval(
        address,
        state_file,
        relay_ticket_key,
        tls_files,
        Duration::from_secs(30),
    )
    .await
}

pub async fn serve_with_state_file_and_relay_key_tls_and_reload_interval(
    address: SocketAddr,
    state_file: impl Into<PathBuf>,
    relay_ticket_key: Option<[u8; 32]>,
    tls_files: Option<(PathBuf, PathBuf)>,
    tls_reload_interval: Duration,
) -> std::io::Result<()> {
    serve_with_state_file_and_relay_key_tls_and_reload_interval_and_trusted_proxies(
        address,
        state_file,
        relay_ticket_key,
        tls_files,
        tls_reload_interval,
        Vec::new(),
    )
    .await
}

pub async fn serve_with_state_file_and_relay_key_tls_and_reload_interval_and_trusted_proxies(
    address: SocketAddr,
    state_file: impl Into<PathBuf>,
    relay_ticket_key: Option<[u8; 32]>,
    tls_files: Option<(PathBuf, PathBuf)>,
    tls_reload_interval: Duration,
    trusted_proxies: Vec<IpNet>,
) -> std::io::Result<()> {
    let mut state = CoordinatorState::load(state_file)?;
    if let Some(key) = relay_ticket_key {
        state = state.with_relay_ticket_key(key);
    }
    state = state.with_trusted_proxies(trusted_proxies);
    serve_with_state_and_tls(address, state, tls_files, tls_reload_interval).await
}

async fn serve_with_state(address: SocketAddr, state: CoordinatorState) -> std::io::Result<()> {
    validate_listener_security(address, false)?;
    let listener = TcpListener::bind(address).await?;
    tracing::info!(address = %listener.local_addr()?, "coordinator listening");
    let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel();
    let server = axum::serve(
        listener,
        router_with_state(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        let _ = shutdown_receiver.await;
    })
    .into_future();
    run_http_until_shutdown(
        server,
        shutdown_sender,
        shutdown_signal(),
        COORDINATOR_SHUTDOWN_GRACE,
    )
    .await
}

async fn run_http_until_shutdown<F, S>(
    server: F,
    shutdown_sender: tokio::sync::oneshot::Sender<()>,
    shutdown_signal: S,
    grace: Duration,
) -> io::Result<()>
where
    F: std::future::Future<Output = io::Result<()>>,
    S: std::future::Future<Output = ()>,
{
    tokio::pin!(server);
    tokio::pin!(shutdown_signal);
    tokio::select! {
        result = &mut server => result,
        _ = &mut shutdown_signal => {
            let _ = shutdown_sender.send(());
            match tokio::time::timeout(grace, &mut server).await {
                Ok(result) => result,
                Err(_) => Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "coordinator HTTP server exceeded graceful shutdown deadline",
                )),
            }
        }
    }
}

async fn serve_with_state_and_tls(
    address: SocketAddr,
    state: CoordinatorState,
    tls_files: Option<(PathBuf, PathBuf)>,
    tls_reload_interval: Duration,
) -> std::io::Result<()> {
    validate_listener_security(address, tls_files.is_some())?;
    let Some((certificate, private_key)) = tls_files else {
        return serve_with_state(address, state).await;
    };
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (loaded_fingerprint, certificate_pem, private_key_pem) =
        read_tls_pair(&certificate, &private_key).await?;
    let config = axum_server::tls_rustls::RustlsConfig::from_pem(certificate_pem, private_key_pem)
        .await
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
    let reloader = tokio::spawn(reload_tls_certificate(
        config.clone(),
        certificate,
        private_key,
        tls_reload_interval,
        loaded_fingerprint,
    ));
    let handle = axum_server::Handle::new();
    let shutdown_handle = handle.clone();
    let shutdown = tokio::spawn(async move {
        shutdown_signal().await;
        shutdown_handle.graceful_shutdown(Some(COORDINATOR_SHUTDOWN_GRACE));
    });
    let result = axum_server::bind_rustls(address, config)
        .handle(handle)
        .serve(router_with_state(state).into_make_service_with_connect_info::<SocketAddr>())
        .await;
    shutdown.abort();
    reloader.abort();
    result
}

async fn reload_tls_certificate(
    config: axum_server::tls_rustls::RustlsConfig,
    certificate: PathBuf,
    private_key: PathBuf,
    interval: Duration,
    mut loaded_fingerprint: [u8; 32],
) {
    loop {
        tokio::time::sleep(interval).await;
        let (fingerprint, certificate_pem, private_key_pem) = match read_tls_pair(
            &certificate,
            &private_key,
        )
        .await
        {
            Ok(pair) => pair,
            Err(error) => {
                tracing::warn!(%error, "could not read coordinator TLS certificate files; keeping current certificate");
                continue;
            }
        };
        if fingerprint == loaded_fingerprint {
            continue;
        }
        match config
            .reload_from_pem(certificate_pem, private_key_pem)
            .await
        {
            Ok(()) => {
                loaded_fingerprint = fingerprint;
                tracing::info!("reloaded coordinator TLS certificate");
            }
            Err(error) => {
                tracing::warn!(%error, "could not reload coordinator TLS certificate; keeping current certificate")
            }
        }
    }
}

async fn read_tls_pair(
    certificate: &FsPath,
    private_key: &FsPath,
) -> io::Result<([u8; 32], Vec<u8>, Vec<u8>)> {
    let certificate_pem = read_bounded_tls_file(certificate, false).await?;
    let private_key_pem = read_bounded_tls_file(private_key, true).await?;
    let mut hasher = Sha256::new();
    hasher.update((certificate_pem.len() as u64).to_be_bytes());
    hasher.update(&certificate_pem);
    hasher.update(&private_key_pem);
    Ok((hasher.finalize().into(), certificate_pem, private_key_pem))
}

async fn read_bounded_tls_file(path: &FsPath, private_key: bool) -> io::Result<Vec<u8>> {
    let file = tokio::fs::File::open(path).await?;
    let metadata = file.metadata().await?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "coordinator TLS input must be a regular file",
        ));
    }
    #[cfg(unix)]
    if private_key {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o007 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "coordinator TLS private key must not be world-accessible",
            ));
        }
    }
    #[cfg(not(unix))]
    let _ = private_key;
    let mut bytes = Vec::new();
    file.take(MAX_TLS_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .await?;
    if bytes.len() as u64 > MAX_TLS_FILE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "coordinator TLS input exceeds the 1 MiB size limit",
        ));
    }
    Ok(bytes)
}

fn validate_listener_security(address: SocketAddr, tls_enabled: bool) -> io::Result<()> {
    if !address.ip().is_loopback() && !tls_enabled {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "non-loopback coordinator listeners require TLS; configure both certificate and private key",
        ));
    }
    Ok(())
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

fn ipv6_prefix_available(store: &Store, candidate: Uuid) -> bool {
    let candidate = overlay_ipv6_prefix(&candidate.to_string());
    store
        .networks
        .keys()
        .all(|existing| overlay_ipv6_prefix(&existing.to_string()) != candidate)
}

async fn shutdown_signal() {
    #[cfg(unix)]
    let result = {
        let terminate = async {
            let mut signal =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
            signal.recv().await;
            Ok::<(), io::Error>(())
        };
        select_shutdown_signal(tokio::signal::ctrl_c(), terminate).await
    };
    #[cfg(not(unix))]
    let result = select_shutdown_signal(
        tokio::signal::ctrl_c(),
        std::future::pending::<io::Result<()>>(),
    )
    .await;

    if let Err(error) = result {
        tracing::error!(%error, "failed to listen for shutdown signal");
    }
}

async fn select_shutdown_signal<C, T>(ctrl_c: C, terminate: T) -> io::Result<()>
where
    C: std::future::Future<Output = io::Result<()>>,
    T: std::future::Future<Output = io::Result<()>>,
{
    tokio::select! {
        result = ctrl_c => result,
        result = terminate => result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, extract::connect_info::ConnectInfo, http::Request as HttpRequest};
    use ed25519_dalek::{Signer, SigningKey};
    use tower::ServiceExt;

    async fn block_until_released(
        State((entered, release)): State<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>,
    ) -> StatusCode {
        entered.notify_one();
        release.notified().await;
        StatusCode::OK
    }

    async fn hold_until_cancelled(
        State((_, entered, cancelled)): State<(
            CoordinatorState,
            Arc<tokio::sync::Notify>,
            Arc<AtomicU64>,
        )>,
    ) -> StatusCode {
        struct CancellationSignal(Arc<AtomicU64>);
        impl Drop for CancellationSignal {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }

        let _signal = CancellationSignal(cancelled);
        entered.notify_one();
        std::future::pending::<()>().await;
        StatusCode::OK
    }

    async fn metrics_for_timeout_test(
        State((state, _, _)): State<(CoordinatorState, Arc<tokio::sync::Notify>, Arc<AtomicU64>)>,
        request: Request,
    ) -> Response {
        metrics(State(state), request).await
    }

    #[tokio::test]
    async fn coordinator_bounds_in_flight_api_work_and_keeps_health_available() {
        let state = CoordinatorState {
            request_slots: RequestSlots(Arc::new(tokio::sync::Semaphore::new(1))),
            ..CoordinatorState::default()
        };
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let hold_route = Router::new()
            .route("/blocked", get(block_until_released))
            .with_state((entered.clone(), release.clone()));
        let app = Router::new()
            .merge(hold_route)
            .route("/healthz", get(health))
            .route("/metrics", get(metrics))
            .layer(from_fn_with_state(state.clone(), limit_requests))
            .with_state(state.clone());
        let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 88)), 12345);
        let make_request = |path: &str, source: SocketAddr| {
            let mut request = HttpRequest::builder()
                .uri(path)
                .body(Body::empty())
                .expect("valid request");
            request.extensions_mut().insert(ConnectInfo(source));
            request
        };

        let active_app = app.clone();
        let active_request = make_request("/blocked", source);
        let active = tokio::spawn(async move { active_app.oneshot(active_request).await });
        entered.notified().await;

        let rejected = app
            .clone()
            .oneshot(make_request("/blocked", source))
            .await
            .expect("over-capacity response");
        assert_eq!(rejected.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(rejected.headers()["retry-after"], "1");

        let healthy = app
            .clone()
            .oneshot(make_request("/healthz", source))
            .await
            .expect("health response while saturated");
        assert_eq!(healthy.status(), StatusCode::OK);
        let metrics = app
            .oneshot(make_request(
                "/metrics",
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12346),
            ))
            .await
            .expect("metrics response while saturated");
        assert_eq!(metrics.status(), StatusCode::OK);
        let metrics_body = axum::body::to_bytes(metrics.into_body(), 16 * 1024)
            .await
            .expect("metrics body");
        assert!(
            String::from_utf8_lossy(&metrics_body)
                .contains("mini_tunnel_coordinator_concurrency_rejected_total 1\n")
        );
        assert_eq!(
            state.concurrency_rejections_total.load(Ordering::Relaxed),
            1
        );

        release.notify_one();
        assert_eq!(
            active
                .await
                .expect("active request task")
                .expect("response")
                .status(),
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn coordinator_times_out_slow_requests_and_releases_capacity() {
        let state = CoordinatorState {
            request_slots: RequestSlots(Arc::new(tokio::sync::Semaphore::new(1))),
            request_timeout: RequestTimeout(Duration::from_millis(10)),
            ..CoordinatorState::default()
        };
        let entered = Arc::new(tokio::sync::Notify::new());
        let cancelled = Arc::new(AtomicU64::new(0));
        let app_state = (state.clone(), entered.clone(), cancelled.clone());
        let app = Router::new()
            .route("/slow", get(hold_until_cancelled))
            .route("/fast", get(|| async { StatusCode::OK }))
            .route("/metrics", get(metrics_for_timeout_test))
            .layer(from_fn_with_state(state.clone(), limit_requests))
            .with_state(app_state);
        let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12347);
        let make_request = |path: &str| {
            let mut request = HttpRequest::builder()
                .uri(path)
                .body(Body::empty())
                .expect("valid request");
            request.extensions_mut().insert(ConnectInfo(source));
            request
        };

        let slow_app = app.clone();
        let slow_request = make_request("/slow");
        let slow = tokio::spawn(async move { slow_app.oneshot(slow_request).await });
        entered.notified().await;
        let timed_out = slow
            .await
            .expect("slow request task")
            .expect("timeout response");
        assert_eq!(timed_out.status(), StatusCode::REQUEST_TIMEOUT);
        assert_eq!(cancelled.load(Ordering::Relaxed), 1);

        let fast = app
            .clone()
            .oneshot(make_request("/fast"))
            .await
            .expect("fast request after timeout");
        assert_eq!(fast.status(), StatusCode::OK);
        assert_eq!(state.request_timeouts_total.load(Ordering::Relaxed), 1);

        let metrics = app
            .oneshot(make_request("/metrics"))
            .await
            .expect("metrics response");
        let body = axum::body::to_bytes(metrics.into_body(), 16 * 1024)
            .await
            .expect("metrics body");
        assert!(
            String::from_utf8_lossy(&body)
                .contains("mini_tunnel_coordinator_request_timeouts_total 1\n")
        );
    }

    #[tokio::test]
    async fn coordinator_shutdown_accepts_either_signal_source() {
        let result = select_shutdown_signal(
            std::future::pending(),
            std::future::ready(Ok::<(), io::Error>(())),
        )
        .await;
        assert!(result.is_ok());

        let result = select_shutdown_signal(
            std::future::ready(Ok::<(), io::Error>(())),
            std::future::pending(),
        )
        .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn plain_http_shutdown_drains_server_until_completion() {
        let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel();
        let server = async move {
            shutdown_receiver
                .await
                .map_err(|_| io::Error::other("shutdown signal was dropped"))?;
            Ok(())
        };

        let result = run_http_until_shutdown(
            server,
            shutdown_sender,
            std::future::ready(()),
            Duration::from_secs(1),
        )
        .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn plain_http_shutdown_ends_after_grace_deadline() {
        let (shutdown_sender, _shutdown_receiver) = tokio::sync::oneshot::channel();
        let result = run_http_until_shutdown(
            std::future::pending::<io::Result<()>>(),
            shutdown_sender,
            std::future::ready(()),
            Duration::from_millis(10),
        )
        .await;

        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
    }

    fn persisted_network(id: Uuid, cidr: &str, member_count: usize) -> PersistedNetwork {
        PersistedNetwork {
            id,
            cidr: cidr.to_owned(),
            admin_token_hash: [0; 32],
            invites: Vec::new(),
            members: (0..member_count)
                .map(|_| PersistedMember {
                    device_id: String::new(),
                    address: Ipv4Addr::UNSPECIFIED,
                    public_key: [0; 32],
                    candidates: Vec::new(),
                    last_candidate_timestamp_ms: 0,
                })
                .collect(),
        }
    }

    #[test]
    fn coordinator_network_and_global_member_caps_have_exact_boundaries() {
        assert!(!member_capacity_reached(
            MAX_NETWORK_MEMBERS - 1,
            MAX_TOTAL_MEMBERS - 1
        ));
        assert!(member_capacity_reached(MAX_NETWORK_MEMBERS, 0));
        assert!(member_capacity_reached(0, MAX_TOTAL_MEMBERS));
        assert!(validate_state_file_size(MAX_STATE_FILE_BYTES).is_ok());
        assert_eq!(
            validate_state_file_size(MAX_STATE_FILE_BYTES + 1)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn persisted_snapshot_rejects_per_network_and_global_member_overflow() {
        let over_network_limit = StateSnapshot {
            schema_version: 1,
            networks: vec![persisted_network(
                Uuid::from_u128(1),
                "10.1.0.0/16",
                MAX_NETWORK_MEMBERS + 1,
            )],
        };
        assert!(Store::from_snapshot(over_network_limit).is_err());

        let networks = (0..4)
            .map(|index| {
                persisted_network(
                    Uuid::from_u128(index + 1),
                    &format!("10.{}.0.0/16", index + 1),
                    MAX_NETWORK_MEMBERS,
                )
            })
            .chain(std::iter::once(persisted_network(
                Uuid::from_u128(5),
                "10.5.0.0/16",
                1,
            )))
            .collect();
        assert!(
            Store::from_snapshot(StateSnapshot {
                schema_version: 1,
                networks,
            })
            .is_err()
        );
    }

    #[test]
    fn coordinator_load_rejects_oversized_state_file_before_deserialization() {
        let dir = std::env::temp_dir().join(format!("mini-tunnel-state-large-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).expect("create state directory");
        let path = dir.join("coordinator.json");
        let file = fs::File::create(&path).expect("create sparse state file");
        file.set_len(MAX_STATE_FILE_BYTES + 1)
            .expect("set oversized sparse file length");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .expect("set secure sparse-state permissions");
        }
        let error = match CoordinatorState::load(&path) {
            Ok(_) => panic!("oversized state must be rejected"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        drop(file);
        fs::remove_dir_all(dir).expect("remove state directory");
    }

    #[test]
    fn network_ids_with_colliding_ula_prefixes_are_rejected() {
        let existing = Uuid::parse_str("123e4567-e89b-42d3-a456-426614174000").unwrap();
        let collision = Uuid::parse_str("123e4567-e89b-42d3-b456-426614174000").unwrap();
        let unique = Uuid::parse_str("223e4567-e89b-42d3-a456-426614174000").unwrap();
        let network = Network {
            cidr: "10.77.0.0/24".parse().unwrap(),
            next_address: "10.77.0.1".parse::<Ipv4Addr>().unwrap(),
            admin_token_hash: [0; 32],
            invites: HashMap::new(),
            members: HashMap::new(),
            assigned_addresses: HashSet::new(),
        };
        let store = Store {
            networks: HashMap::from([(existing, network)]),
        };
        assert!(!ipv6_prefix_available(&store, collision));
        assert!(ipv6_prefix_available(&store, unique));
    }

    #[test]
    fn address_cursor_allocates_sequentially_and_reuses_freed_addresses_after_wrap() {
        let cidr = "10.77.0.0/29".parse().unwrap();
        let mut network = Network {
            cidr,
            next_address: first_host(cidr),
            admin_token_hash: [0; 32],
            invites: HashMap::new(),
            members: HashMap::new(),
            assigned_addresses: HashSet::new(),
        };
        for expected in ["10.77.0.1", "10.77.0.2", "10.77.0.3"] {
            let (address, next) = find_available_address(&network).unwrap();
            assert_eq!(address.to_string(), expected);
            network.assigned_addresses.insert(address);
            network.next_address = next;
        }
        network
            .assigned_addresses
            .remove(&"10.77.0.1".parse::<Ipv4Addr>().unwrap());
        let (reused, _) = find_available_address(&network).unwrap();
        assert_eq!(reused, "10.77.0.4".parse::<Ipv4Addr>().unwrap());
        network.assigned_addresses.insert(reused);
        network
            .assigned_addresses
            .insert("10.77.0.5".parse().unwrap());
        network
            .assigned_addresses
            .insert("10.77.0.6".parse().unwrap());
        let (reused, _) = find_available_address(&Network {
            next_address: "10.77.0.6".parse().unwrap(),
            ..network
        })
        .unwrap();
        assert_eq!(reused, "10.77.0.1".parse::<Ipv4Addr>().unwrap());
    }

    #[test]
    fn candidate_address_accepts_srflx_and_rejects_invalid_related_address() {
        assert_eq!(
            candidate_socket_address("srflx://203.0.113.7:5000|192.168.1.4:4000"),
            Some("203.0.113.7:5000".parse().unwrap())
        );
        assert_eq!(
            candidate_socket_address("198.51.100.8:42000"),
            Some("198.51.100.8:42000".parse().unwrap())
        );
        assert_eq!(
            candidate_socket_address("tcp://198.51.100.8:443"),
            Some("198.51.100.8:443".parse().unwrap())
        );
        assert!(candidate_socket_address("srflx://203.0.113.7:5000|broken").is_none());
    }

    #[test]
    fn plaintext_coordinator_listeners_are_loopback_only() {
        assert!(validate_listener_security("127.0.0.1:8080".parse().unwrap(), false).is_ok());
        assert!(validate_listener_security("[::1]:8080".parse().unwrap(), false).is_ok());
        assert!(validate_listener_security("0.0.0.0:8080".parse().unwrap(), false).is_err());
        assert!(validate_listener_security("[::]:8080".parse().unwrap(), false).is_err());
        assert!(validate_listener_security("0.0.0.0:8080".parse().unwrap(), true).is_ok());
    }

    #[tokio::test]
    async fn tls_file_reader_caps_input_and_requires_a_regular_file() {
        let temporary = std::env::temp_dir().join(format!(
            "mini-tunnel-coordinator-tls-bound-{}",
            Uuid::new_v4()
        ));
        fs::create_dir_all(&temporary).unwrap();
        let path = temporary.join("input.pem");
        tokio::fs::write(&path, vec![b'x'; MAX_TLS_FILE_BYTES as usize])
            .await
            .unwrap();
        assert_eq!(
            read_bounded_tls_file(&path, false).await.unwrap().len() as u64,
            MAX_TLS_FILE_BYTES
        );

        tokio::fs::write(&path, vec![b'x'; MAX_TLS_FILE_BYTES as usize + 1])
            .await
            .unwrap();
        let error = read_bounded_tls_file(&path, false)
            .await
            .expect_err("oversized TLS file must be rejected");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(read_bounded_tls_file(&temporary, false).await.is_err());
        fs::remove_dir_all(temporary).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn tls_private_key_must_not_be_world_accessible() {
        use std::os::unix::fs::PermissionsExt;

        let temporary = std::env::temp_dir().join(format!(
            "mini-tunnel-coordinator-tls-key-mode-{}",
            Uuid::new_v4()
        ));
        fs::create_dir_all(&temporary).unwrap();
        let path = temporary.join("private-key.pem");
        tokio::fs::write(&path, b"key").await.unwrap();

        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(read_bounded_tls_file(&path, true).await.is_ok());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(read_bounded_tls_file(&path, true).await.is_ok());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let error = read_bounded_tls_file(&path, true)
            .await
            .expect_err("world-readable private keys must be rejected");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        fs::remove_dir_all(temporary).unwrap();
    }

    #[tokio::test]
    async fn configured_tls_serves_health_with_certificate_validation() {
        let temporary =
            std::env::temp_dir().join(format!("mini-tunnel-coordinator-tls-{}", Uuid::new_v4()));
        fs::create_dir_all(&temporary).unwrap();
        let certified = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_owned()]).unwrap();
        let certificate_pem = certified.cert.pem();
        let private_key_pem = certified.signing_key.serialize_pem();
        let certificate_path = temporary.join("certificate.pem");
        let key_path = temporary.join("private-key.pem");
        fs::write(&certificate_path, &certificate_pem).unwrap();
        fs::write(&key_path, &private_key_pem).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let state_path = temporary.join("state.json");
        let address = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap();
        let listener = TcpListener::bind(address).await.unwrap();
        drop(listener);

        let server = tokio::spawn(serve_with_state_file_and_relay_key_tls_and_reload_interval(
            address,
            state_path,
            None,
            Some((certificate_path, key_path)),
            Duration::from_millis(25),
        ));
        let root = reqwest::Certificate::from_pem(certificate_pem.as_bytes()).unwrap();
        let client = reqwest::Client::builder()
            .add_root_certificate(root)
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        let url = format!("https://{address}/healthz");
        let mut response = None;
        for _ in 0..40 {
            if let Ok(result) = client.get(&url).send().await {
                response = Some(result);
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        let response = response.expect("TLS coordinator should start and serve health");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.json::<serde_json::Value>().await.unwrap()["status"],
            "ok"
        );
        assert!(reqwest::Client::new().get(&url).send().await.is_err());

        fs::write(temporary.join("certificate.pem"), "invalid certificate").unwrap();
        tokio::time::sleep(Duration::from_millis(75)).await;
        let still_old_client = reqwest::Client::builder()
            .add_root_certificate(
                reqwest::Certificate::from_pem(certificate_pem.as_bytes()).unwrap(),
            )
            .build()
            .unwrap();
        assert_eq!(
            still_old_client.get(&url).send().await.unwrap().status(),
            StatusCode::OK,
            "a failed rotation must keep serving the currently loaded certificate"
        );

        let renewed = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_owned()]).unwrap();
        let renewed_certificate_pem = renewed.cert.pem();
        fs::write(temporary.join("certificate.pem"), &renewed_certificate_pem).unwrap();
        fs::write(
            temporary.join("private-key.pem"),
            renewed.signing_key.serialize_pem(),
        )
        .unwrap();
        let renewed_client = reqwest::Client::builder()
            .add_root_certificate(
                reqwest::Certificate::from_pem(renewed_certificate_pem.as_bytes()).unwrap(),
            )
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        let mut renewed_response = None;
        for _ in 0..40 {
            if let Ok(result) = renewed_client.get(&url).send().await
                && result.status() == StatusCode::OK
            {
                renewed_response = Some(result);
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(
            renewed_response.is_some(),
            "the running server should serve the rotated certificate without restart"
        );
        let old_client_after_rotation = reqwest::Client::builder()
            .add_root_certificate(
                reqwest::Certificate::from_pem(certificate_pem.as_bytes()).unwrap(),
            )
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        assert!(old_client_after_rotation.get(&url).send().await.is_err());
        server.abort();
        fs::remove_dir_all(temporary).unwrap();
    }

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
    fn request_limiter_recovers_after_its_table_mutex_is_poisoned() {
        let limiter = RequestRateLimiter::new(1, Duration::from_secs(10));
        let clients = Arc::clone(&limiter.clients);
        assert!(
            std::thread::spawn(move || {
                let _guard = clients.lock().unwrap();
                panic!("simulate a panic while holding the rate-limit table");
            })
            .join()
            .is_err()
        );

        assert!(limiter.allow(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 19)), Instant::now()));
    }

    #[test]
    fn request_limiter_unifies_ipv4_mapped_ipv6_source_addresses() {
        let limiter = RequestRateLimiter::new(1, Duration::from_secs(10));
        let now = Instant::now();
        let ipv4 = Ipv4Addr::new(192, 0, 2, 17);
        let mapped_ipv6 = IpAddr::V6(ipv4.to_ipv6_mapped());
        assert!(limiter.allow(IpAddr::V4(ipv4), now));
        assert!(!limiter.allow(mapped_ipv6, now));
        assert_eq!(limiter.clients.lock().unwrap().len(), 1);
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

    #[test]
    fn forwarded_client_ip_requires_a_trusted_socket_peer() {
        let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 443);
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "198.51.100.25".parse().expect("forwarded header"),
        );
        let trusted = ["203.0.113.0/24".parse::<IpNet>().unwrap()];
        assert_eq!(
            client_ip_for_request(remote, &headers, &trusted),
            remote.ip()
        );
    }

    #[test]
    fn forwarded_client_ip_walks_back_through_trusted_proxies() {
        let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "198.51.100.25, 10.20.0.8"
                .parse()
                .expect("forwarded header"),
        );
        let trusted = [
            "127.0.0.0/8".parse::<IpNet>().unwrap(),
            "10.20.0.0/16".parse::<IpNet>().unwrap(),
        ];
        assert_eq!(
            client_ip_for_request(remote, &headers, &trusted),
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 25))
        );

        headers.insert(
            "x-forwarded-for",
            "192.0.2.10, 203.0.113.11"
                .parse()
                .expect("forwarded header"),
        );
        assert_eq!(
            client_ip_for_request(remote, &headers, &trusted),
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 11)),
            "stop at the first untrusted proxy so a client cannot spoof earlier hops"
        );
    }

    #[test]
    fn malformed_oversized_and_excessive_forwarded_chains_fall_back_to_socket_peer() {
        let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
        let trusted = ["127.0.0.0/8".parse::<IpNet>().unwrap()];
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "not-an-ip".parse().expect("forwarded header"),
        );
        assert_eq!(
            client_ip_for_request(remote, &headers, &trusted),
            remote.ip()
        );
        headers.insert(
            "x-forwarded-for",
            "198.51.100.25".parse().expect("forwarded header"),
        );
        headers.append(
            "x-forwarded-for",
            "203.0.113.10".parse().expect("second forwarded header"),
        );
        assert_eq!(
            client_ip_for_request(remote, &headers, &trusted),
            remote.ip()
        );
        headers.insert(
            "x-forwarded-for",
            "1".repeat(MAX_FORWARDED_FOR_BYTES + 1)
                .parse()
                .expect("forwarded header"),
        );
        assert_eq!(
            client_ip_for_request(remote, &headers, &trusted),
            remote.ip()
        );
        headers.insert(
            "x-forwarded-for",
            (0..=MAX_FORWARDED_FOR_HOPS)
                .map(|_| "198.51.100.25")
                .collect::<Vec<_>>()
                .join(",")
                .parse()
                .expect("forwarded header"),
        );
        assert_eq!(
            client_ip_for_request(remote, &headers, &trusted),
            remote.ip()
        );
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

    #[tokio::test]
    async fn router_uses_forwarded_addresses_only_for_trusted_proxies() {
        let state = CoordinatorState {
            request_limiter: RequestRateLimiter::new(1, Duration::from_secs(60)),
            ..CoordinatorState::default()
        }
        .with_trusted_proxies(vec!["127.0.0.0/8".parse().unwrap()]);
        let app = router_with_state(state);
        let make_request = |source: SocketAddr, forwarded: &str| {
            let mut request = HttpRequest::builder()
                .uri("/healthz")
                .body(Body::empty())
                .expect("valid request");
            request.extensions_mut().insert(ConnectInfo(source));
            request.headers_mut().insert(
                "x-forwarded-for",
                forwarded.parse().expect("forwarded header"),
            );
            request
        };
        let untrusted_a = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 12345);
        let untrusted_b = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)), 12346);
        assert_eq!(
            app.clone()
                .oneshot(make_request(untrusted_a, "198.51.100.9"))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            app.clone()
                .oneshot(make_request(untrusted_b, "198.51.100.9"))
                .await
                .unwrap()
                .status(),
            StatusCode::OK,
            "untrusted peers must not be able to choose the limiter identity"
        );

        let trusted_proxy = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8443);
        assert_eq!(
            app.clone()
                .oneshot(make_request(trusted_proxy, "198.51.100.9"))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            app.clone()
                .oneshot(make_request(trusted_proxy, "198.51.100.9"))
                .await
                .unwrap()
                .status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            app.oneshot(make_request(trusted_proxy, "198.51.100.10"))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn router_rejects_request_without_source_address() {
        let app = router_with_state(CoordinatorState::default());
        let request = HttpRequest::builder()
            .uri("/healthz")
            .body(Body::empty())
            .expect("valid request");
        let response = app.oneshot(request).await.expect("response");
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn metrics_are_loopback_only_and_report_basic_service_totals() {
        let state = CoordinatorState {
            request_limiter: RequestRateLimiter::new(1, Duration::from_secs(60)),
            ..CoordinatorState::default()
        };
        state
            .create_network(create_request("metrics", "10.88.0.0/24"))
            .await
            .expect("create test network");
        let app = router_with_state(state);
        let public_source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 44)), 12345);
        let request_from = |path: &str, source| {
            let mut request = HttpRequest::builder()
                .uri(path)
                .body(Body::empty())
                .expect("valid request");
            request.extensions_mut().insert(ConnectInfo(source));
            request
        };

        let response = app
            .clone()
            .oneshot(request_from("/healthz", public_source))
            .await
            .expect("initial request");
        assert_eq!(response.status(), StatusCode::OK);
        let limited = app
            .clone()
            .oneshot(request_from("/healthz", public_source))
            .await
            .expect("limited request");
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);

        let remote_metrics = app
            .clone()
            .oneshot(request_from(
                "/metrics",
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 45)), 12346),
            ))
            .await
            .expect("remote metrics request");
        assert_eq!(remote_metrics.status(), StatusCode::NOT_FOUND);

        let loopback = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 54321);
        let metrics = app
            .oneshot(request_from("/metrics", loopback))
            .await
            .expect("loopback metrics request");
        assert_eq!(metrics.status(), StatusCode::OK);
        assert_eq!(
            metrics
                .headers()
                .get(axum::http::header::CONTENT_TYPE)
                .unwrap(),
            "text/plain; version=0.0.4; charset=utf-8"
        );
        let body = axum::body::to_bytes(metrics.into_body(), 16 * 1024)
            .await
            .expect("metrics body");
        let body = String::from_utf8(body.to_vec()).expect("UTF-8 metrics");
        assert!(body.contains("mini_tunnel_coordinator_networks 1\n"));
        assert!(body.contains("mini_tunnel_coordinator_members 0\n"));
        assert!(body.contains("mini_tunnel_coordinator_rate_limited_total 1\n"));
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
            next_address: "10.8.0.1".parse().unwrap(),
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
        let relay_pairs = Arc::clone(&state.relay_pairs);
        assert!(
            std::thread::spawn(move || {
                let _guard = relay_pairs.lock().unwrap();
                panic!("simulate a panic while holding the relay-pair table");
            })
            .join()
            .is_err()
        );
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
    async fn join_rejects_enrollment_when_network_member_capacity_is_reached() {
        let state = CoordinatorState::default();
        let network_id = Uuid::new_v4();
        let invite_token = "capacity-invite-token".to_owned();
        let now = unix_time_ms().expect("system clock");
        let members = (0..MAX_NETWORK_MEMBERS)
            .map(|index| {
                (
                    format!("existing-{index}"),
                    Member {
                        address: Ipv4Addr::UNSPECIFIED,
                        public_key: [0; 32],
                        candidates: Vec::new(),
                        last_candidate_timestamp_ms: 0,
                    },
                )
            })
            .collect();
        state.inner.write().await.networks.insert(
            network_id,
            Network {
                cidr: "10.90.0.0/16".parse().unwrap(),
                next_address: "10.90.0.1".parse().unwrap(),
                admin_token_hash: [0; 32],
                invites: HashMap::from([(
                    token_hash(&invite_token),
                    Invite {
                        consumed_by: None,
                        expires_at_ms: now + 60_000,
                    },
                )]),
                members,
                assigned_addresses: HashSet::new(),
            },
        );
        let key = SigningKey::from_bytes(&[99; 32]);
        let public_key = key.verifying_key().to_bytes();
        let device_id = device_id_from_public_key(&public_key);
        let signature = key.sign(&join_signing_bytes(
            &network_id.to_string(),
            &device_id,
            &public_key,
            &invite_token,
        ));
        let error = state
            .join_network(
                network_id,
                JoinNetworkRequest {
                    invite_token,
                    device_id,
                    public_key: URL_SAFE_NO_PAD.encode(public_key),
                    signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
                },
            )
            .await
            .expect_err("network member cap must reject new enrollment");
        assert!(matches!(
            error,
            ApiError::Conflict("coordinator member capacity reached")
        ));
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
            ice_credentials: None,
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

        let ice_credentials = IceCredentials {
            ufrag: "abcdefghijklmnop".to_owned(),
            password: "abcdefghijklmnopqrstuvwxyzABCDEF".to_owned(),
            generation: 1,
        };
        let timestamp_ms = unix_time_ms().expect("clock");
        let signature = key_a.sign(&candidate_signing_bytes_with_ice(
            &network_id.to_string(),
            &join_a.device_id,
            timestamp_ms,
            &[
                "198.51.100.8:42000".to_owned(),
                "tcp://198.51.100.8:42001".to_owned(),
            ],
            &ice_credentials,
        ));
        let mut forged_ice_credentials = ice_credentials.clone();
        forged_ice_credentials.password.push('A');
        assert!(matches!(
            state
                .update_candidates(
                    network_id,
                    CandidateUpdateRequest {
                        device_id: join_a.device_id.clone(),
                        timestamp_ms,
                        candidates: vec![
                            "198.51.100.8:42000".to_owned(),
                            "tcp://198.51.100.8:42001".to_owned(),
                        ],
                        ice_credentials: Some(forged_ice_credentials),
                        signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
                    },
                )
                .await,
            Err(ApiError::Unauthorized)
        ));
        state
            .update_candidates(
                network_id,
                CandidateUpdateRequest {
                    device_id: join_a.device_id.clone(),
                    timestamp_ms,
                    candidates: vec![
                        "198.51.100.8:42000".to_owned(),
                        "tcp://198.51.100.8:42001".to_owned(),
                    ],
                    ice_credentials: Some(ice_credentials.clone()),
                    signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
                },
            )
            .await
            .expect("publish signed ephemeral ICE credentials");
        let timestamp_ms = unix_time_ms().expect("clock");
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
            .expect("read ICE credentials from same-network peer list");
        assert_eq!(snapshot.peers[0].ice_credentials, Some(ice_credentials));
        if let Some(credentials) = state
            .ice_credentials
            .write()
            .await
            .get_mut(&(network_id, join_a.device_id.clone()))
        {
            credentials.updated_at_ms = unix_time_ms()
                .expect("clock")
                .saturating_sub(ICE_CREDENTIAL_TTL_MS + 1);
        }
        let timestamp_ms = unix_time_ms().expect("clock");
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
            .expect("read peers after ICE credential expiry");
        assert!(snapshot.peers[0].ice_credentials.is_none());

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
            ice_credentials: None,
            signature: String::new(),
        };
        assert!(matches!(
            state.update_candidates(network_id, invalid).await,
            Err(ApiError::InvalidRequest(_))
        ));
        let invalid_ice = CandidateUpdateRequest {
            device_id: "unknown".into(),
            timestamp_ms: unix_time_ms().expect("clock"),
            candidates: Vec::new(),
            ice_credentials: Some(IceCredentials {
                ufrag: "x".into(),
                password: "short".into(),
                generation: 0,
            }),
            signature: String::new(),
        };
        assert!(matches!(
            state.update_candidates(network_id, invalid_ice).await,
            Err(ApiError::InvalidRequest("invalid ICE credentials"))
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
        let ice_credentials = IceCredentials {
            ufrag: "qrstuvwxyzABCDEF".to_owned(),
            password: "ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvu".to_owned(),
            generation: 1,
        };
        let signature = key_b.sign(&candidate_signing_bytes_with_ice(
            &network_id.to_string(),
            &join_b.device_id,
            timestamp_ms,
            &candidates,
            &ice_credentials,
        ));
        state
            .update_candidates(
                network_id,
                CandidateUpdateRequest {
                    device_id: join_b.device_id.clone(),
                    timestamp_ms,
                    candidates,
                    ice_credentials: Some(ice_credentials.clone()),
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
        assert!(!contents.contains(&ice_credentials.password));
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
        let invite_c = restored
            .create_invite(
                network_id,
                CreateInviteRequest {
                    admin_token: network.admin_token.clone(),
                },
            )
            .await
            .expect("invite C after restore");
        let enrolled_c = restored
            .join_network(
                network_id,
                signed_join(network_id, invite_c.invite_token, 34),
            )
            .await
            .expect("enroll C after restore");
        assert_eq!(enrolled_c.assigned_ipv4, "10.83.0.3");
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
        assert_eq!(peers.peers.len(), 2);
        let peer_b = peers
            .peers
            .iter()
            .find(|peer| peer.device_id == join_b.device_id)
            .expect("peer B is restored");
        assert_eq!(peer_b.candidates, ["198.51.100.22:42000"]);
        assert!(peer_b.ice_credentials.is_none());
        assert_eq!(peer_b.assigned_ipv4, enrolled_b.assigned_ipv4);
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
        drop(restored);
        fs::remove_dir_all(dir).expect("remove test directory");
    }

    #[tokio::test]
    async fn snapshot_verification_validates_existing_state_and_requires_exclusive_lock() {
        let dir = std::env::temp_dir().join(format!("mini-tunnel-state-verify-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).expect("create test directory");
        let path = dir.join("coordinator.json");
        fs::write(&path, br#"{"schema_version":1,"networks":[]}"#).expect("write snapshot");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .expect("restrict snapshot permissions");
        }

        let summary = CoordinatorState::verify_persistent_state(&path)
            .await
            .expect("verify snapshot");
        assert_eq!(
            summary,
            StateSnapshotSummary {
                networks: 0,
                members: 0,
                invites: 0
            }
        );

        let state = CoordinatorState::load(&path).expect("acquire state lock");
        let error = CoordinatorState::verify_persistent_state(&path)
            .await
            .expect_err("verification must reject a live state file");
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        drop(state);

        fs::write(&path, b"not json").expect("corrupt snapshot");
        assert_eq!(
            CoordinatorState::verify_persistent_state(&path)
                .await
                .expect_err("reject corrupt state")
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            CoordinatorState::verify_persistent_state(dir.join("missing.json"))
                .await
                .expect_err("missing state is not a valid backup")
                .kind(),
            io::ErrorKind::NotFound
        );
        fs::remove_dir_all(dir).expect("remove test directory");
    }

    #[tokio::test]
    async fn snapshot_copy_supports_backup_restore_and_rejects_unsafe_paths() {
        let dir = std::env::temp_dir().join(format!("mini-tunnel-state-backup-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).expect("create test directory");
        let source = dir.join("coordinator.json");
        let destination = dir.join("backups/coordinator.json");
        let source_state = CoordinatorState::load(&source).expect("open source state");
        source_state
            .create_network(create_request("source network", "10.83.0.0/16"))
            .await
            .expect("create source network");
        drop(source_state);

        let summary = CoordinatorState::copy_persistent_state_snapshot(&source, &destination)
            .await
            .expect("create backup");
        assert_eq!(
            summary,
            StateSnapshotSummary {
                networks: 1,
                members: 0,
                invites: 0
            }
        );
        assert_eq!(
            CoordinatorState::verify_persistent_state(&destination)
                .await
                .expect("verify backup"),
            summary
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&destination)
                    .expect("backup metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }

        let restore_target = dir.join("restored/coordinator.json");
        let old_target = CoordinatorState::load(&restore_target).expect("open old restore target");
        old_target
            .create_network(create_request("old target", "10.84.0.0/16"))
            .await
            .expect("create old target network");
        drop(old_target);
        assert_eq!(
            CoordinatorState::copy_persistent_state_snapshot(&destination, &restore_target)
                .await
                .expect("restore backup over old state"),
            summary
        );
        let restored = CoordinatorState::load(&restore_target).expect("load restored state");
        let restored_store = restored.inner.read().await;
        assert_eq!(restored_store.networks.len(), 1);
        assert_eq!(
            restored_store
                .networks
                .values()
                .next()
                .expect("network")
                .cidr,
            "10.83.0.0/16".parse().expect("CIDR")
        );
        drop(restored_store);
        drop(restored);

        assert_eq!(
            CoordinatorState::copy_persistent_state_snapshot(&source, &source)
                .await
                .expect_err("reject source/destination alias")
                .kind(),
            io::ErrorKind::InvalidInput
        );
        let source_lock_path = state_lock_path(&source).expect("source lock path");
        assert_eq!(
            CoordinatorState::copy_persistent_state_snapshot(&source, source_lock_path)
                .await
                .expect_err("reject a destination that aliases the source lock")
                .kind(),
            io::ErrorKind::InvalidInput
        );
        let live_source = CoordinatorState::load(&source).expect("lock source");
        assert_eq!(
            CoordinatorState::copy_persistent_state_snapshot(&source, &destination)
                .await
                .expect_err("refuse a running source")
                .kind(),
            io::ErrorKind::WouldBlock
        );
        drop(live_source);

        let live_destination = CoordinatorState::load(&destination).expect("lock destination");
        assert_eq!(
            CoordinatorState::copy_persistent_state_snapshot(&source, &destination)
                .await
                .expect_err("refuse to replace a running coordinator state")
                .kind(),
            io::ErrorKind::WouldBlock
        );
        drop(live_destination);

        #[cfg(unix)]
        {
            let target = dir.join("linked-target.json");
            let symlink = dir.join("linked-backup.json");
            fs::write(&target, b"preserve target").expect("write symlink target");
            std::os::unix::fs::symlink(&target, &symlink).expect("create destination symlink");
            assert_eq!(
                CoordinatorState::copy_persistent_state_snapshot(&source, &symlink)
                    .await
                    .expect_err("refuse symlink backup destination")
                    .kind(),
                io::ErrorKind::InvalidInput
            );
            assert_eq!(
                fs::read(&target).expect("target remains unchanged"),
                b"preserve target"
            );
        }

        fs::write(&source, b"corrupt").expect("corrupt source snapshot");
        assert_eq!(
            CoordinatorState::copy_persistent_state_snapshot(&source, &destination)
                .await
                .expect_err("reject corrupt source")
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            CoordinatorState::copy_persistent_state_snapshot(
                dir.join("missing.json"),
                &destination,
            )
            .await
            .expect_err("reject missing source")
            .kind(),
            io::ErrorKind::NotFound
        );
        fs::remove_dir_all(dir).expect("remove test directory");
    }

    #[test]
    fn persistent_state_lock_rejects_a_second_process_and_releases_on_drop() {
        let dir = std::env::temp_dir().join(format!("mini-tunnel-state-lock-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).expect("create test directory");
        let path = dir.join("coordinator.json");
        let state = CoordinatorState::load(&path).expect("first process acquires lock");
        let child = std::process::Command::new(std::env::current_exe().expect("test executable"))
            .arg("--exact")
            .arg("tests::persistent_state_lock_child_process")
            .env("MINI_TUNNEL_STATE_LOCK_CHILD", &path)
            .status()
            .expect("start lock verification process");
        assert!(child.success(), "child process must observe the held lock");
        let error = match CoordinatorState::load(&path) {
            Ok(_) => panic!("second process must be rejected"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        assert!(error.to_string().contains("already locked"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let lock_path = dir.join("coordinator.json.lock");
            assert_eq!(
                fs::metadata(lock_path)
                    .expect("lock metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        drop(state);
        let restarted = CoordinatorState::load(&path).expect("lock releases when state drops");
        drop(restarted);
        fs::remove_dir_all(dir).expect("remove test directory");
    }

    #[test]
    fn persistent_state_lock_child_process() {
        let Ok(path) = std::env::var("MINI_TUNNEL_STATE_LOCK_CHILD") else {
            return;
        };
        let error = match CoordinatorState::load(path) {
            Ok(_) => panic!("another process must not acquire the held state lock"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
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
        drop(restored);
        fs::remove_dir_all(dir).expect("remove test directory");
    }

    #[test]
    fn corrupt_state_and_unsafe_file_permissions_are_rejected() {
        let dir =
            std::env::temp_dir().join(format!("mini-tunnel-state-invalid-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).expect("create test directory");
        let path = dir.join("coordinator.json");
        fs::write(&path, b"not json").expect("write corrupt state");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .expect("set secure corrupt-state permissions");
        }
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
            fs::remove_file(&path).expect("remove state symlink");
            let lock_path = dir.join("coordinator.json.lock");
            fs::remove_file(&lock_path).expect("remove state lock file");
            std::os::unix::fs::symlink(&target, &lock_path).expect("create lock symlink");
            let error = match CoordinatorState::load(&path) {
                Ok(_) => panic!("state lock symlink must be rejected"),
                Err(error) => error,
            };
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        }
        fs::remove_dir_all(dir).expect("remove test directory");
    }

    #[test]
    fn persisted_snapshot_atomically_replaces_an_existing_file() {
        let dir =
            std::env::temp_dir().join(format!("mini-tunnel-state-replace-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).expect("create test directory");
        let path = dir.join("coordinator.json");
        let empty = Store {
            networks: HashMap::new(),
        };
        persist_store(&path, &empty).expect("write initial snapshot");
        let initial = fs::read(&path).expect("read initial snapshot");
        let cidr = "10.91.0.0/24".parse().unwrap();
        let populated = Store {
            networks: HashMap::from([(
                Uuid::new_v4(),
                Network {
                    cidr,
                    next_address: first_host(cidr),
                    admin_token_hash: [7; 32],
                    invites: HashMap::new(),
                    members: HashMap::new(),
                    assigned_addresses: HashSet::new(),
                },
            )]),
        };
        persist_store(&path, &populated).expect("replace existing snapshot");
        let replaced = fs::read(&path).expect("read replaced snapshot");
        assert_ne!(initial, replaced);
        assert!(replace_state_file(&dir.join("missing.tmp"), &path).is_err());
        assert_eq!(fs::read(&path).expect("old snapshot remains"), replaced);
        let snapshot: StateSnapshot =
            serde_json::from_slice(&replaced).expect("decode replaced snapshot");
        assert_eq!(snapshot.networks.len(), 1);
        assert_eq!(Store::from_snapshot(snapshot).unwrap().networks.len(), 1);
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
        drop(state);
        fs::remove_dir_all(dir).expect("remove test directory");
    }
}
