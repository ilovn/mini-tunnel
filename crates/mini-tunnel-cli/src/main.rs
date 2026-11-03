use std::{
    fs::File,
    future::Future,
    io::{self, Read},
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    process::ExitCode,
    time::Duration,
};

use axum::{
    Router,
    extract::State,
    http::{StatusCode, header},
    response::IntoResponse,
    routing::get,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::{Parser, Subcommand};
use futures_util::future::join_all;
use mini_tunnel_protocol::{
    ApiErrorResponse, CandidateUpdateRequest, CandidateUpdateResponse, CreateInviteRequest,
    CreateInviteResponse, CreateNetworkRequest, CreateNetworkResponse, IceCredentials,
    JoinNetworkRequest, JoinNetworkResponse, PeerInfo, PeerListRequest, PeerListResponse,
    RelayTicketRequest, RelayTicketResponse, RevokeMemberRequest, RevokeMemberResponse,
    candidate_signing_bytes, candidate_signing_bytes_with_ice, join_signing_bytes,
    peers_signing_bytes, relay_ticket_request_signing_bytes,
};
use serde::Deserialize;

const PEER_DIAGNOSTIC_TIMEOUT: Duration = Duration::from_secs(5);
const ICE_PATH_PROMOTION_PROBATION: Duration = Duration::from_secs(31);
const COORDINATOR_CA_CERT_FILE_ENV: &str = "MINI_TUNNEL_COORDINATOR_CA_CERT_FILE";
const MAX_COORDINATOR_CA_BUNDLE_BYTES: u64 = 1024 * 1024;
const ICE_PATH_PROBATION_HEALTH_INTERVAL: Duration = Duration::from_secs(10);
const DIRECT_PATH_PROMOTION_PROBATION: Duration = Duration::from_secs(31);

#[derive(Debug, Parser)]
#[command(name = "mini-tunnel", version, about = "A minimal peer-to-peer tunnel")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run or inspect the coordination service.
    Coordinator {
        #[command(subcommand)]
        command: CoordinatorCommand,
    },
    /// Run the opaque ticket-authorized TCP relay service.
    Relay {
        #[command(subcommand)]
        command: RelayCommand,
    },
    /// Create a virtual network, issue an invite, or join with an invite.
    Network {
        #[command(subcommand)]
        command: NetworkCommand,
    },
    /// Display this device's stable public identity.
    Identity,
    /// Run a low-level authenticated UDP/QUIC peer diagnostic.
    Peer {
        #[command(subcommand)]
        command: PeerCommand,
    },
}

#[derive(Debug, Subcommand)]
enum CoordinatorCommand {
    /// Start the coordinator HTTP service.
    Serve {
        /// Listen address. Use 0.0.0.0 only when intentionally exposing the service.
        #[arg(
            long,
            env = "MINI_TUNNEL_COORDINATOR_LISTEN",
            default_value = "127.0.0.1:8080"
        )]
        listen: SocketAddr,
        /// Coordinator state snapshot path.
        #[arg(long, env = "MINI_TUNNEL_COORDINATOR_STATE")]
        state_file: Option<PathBuf>,
        /// PEM certificate chain used to serve HTTPS. Required with --tls-key.
        #[arg(long, env = "MINI_TUNNEL_COORDINATOR_TLS_CERT")]
        tls_cert: Option<PathBuf>,
        /// PEM private key used to serve HTTPS. Required with --tls-cert.
        #[arg(long, env = "MINI_TUNNEL_COORDINATOR_TLS_KEY")]
        tls_key: Option<PathBuf>,
        /// Seconds between checking the certificate and private key for rotation.
        #[arg(
            long,
            env = "MINI_TUNNEL_COORDINATOR_TLS_RELOAD_INTERVAL_SECONDS",
            default_value_t = 30,
            value_parser = clap::value_parser!(u64).range(1..)
        )]
        tls_reload_interval_seconds: u64,
        /// Trusted reverse proxy CIDRs; only these peers may supply X-Forwarded-For.
        #[arg(
            long,
            env = "MINI_TUNNEL_COORDINATOR_TRUSTED_PROXIES",
            value_delimiter = ','
        )]
        trusted_proxies: Vec<ipnet::IpNet>,
    },
    /// Validate an existing coordinator snapshot without starting the service.
    VerifyState {
        /// Coordinator state snapshot path.
        #[arg(
            long,
            env = "MINI_TUNNEL_COORDINATOR_STATE",
            default_value_os_t = default_coordinator_state_path()
        )]
        state_file: PathBuf,
    },
    /// Validate and atomically back up a coordinator snapshot while the service is stopped.
    BackupState {
        /// Source coordinator state snapshot path.
        #[arg(
            long,
            env = "MINI_TUNNEL_COORDINATOR_STATE",
            default_value_os_t = default_coordinator_state_path()
        )]
        state_file: PathBuf,
        /// Destination snapshot path. Existing safe snapshots are atomically replaced.
        #[arg(long)]
        output: PathBuf,
    },
    /// Restore a validated snapshot into a stopped coordinator state path.
    RestoreState {
        /// Existing coordinator state path to replace.
        #[arg(
            long,
            env = "MINI_TUNNEL_COORDINATOR_STATE",
            default_value_os_t = default_coordinator_state_path()
        )]
        state_file: PathBuf,
        /// Backup snapshot to restore.
        #[arg(long)]
        backup: PathBuf,
    },
    /// Import a validated JSON snapshot into an empty PostgreSQL store.
    ImportStateToPostgres {
        /// Source coordinator state snapshot path.
        #[arg(
            long,
            env = "MINI_TUNNEL_COORDINATOR_STATE",
            default_value_os_t = default_coordinator_state_path()
        )]
        state_file: PathBuf,
    },
    /// Export a consistent PostgreSQL state snapshot to the protected JSON format.
    ExportStateFromPostgres {
        /// Destination JSON snapshot path.
        #[arg(long)]
        output: PathBuf,
    },
    /// Apply additive PostgreSQL schema migrations using a database-owner role.
    MigratePostgres,
    /// Check a running coordinator's health endpoint.
    Health {
        /// Coordinator base URL.
        #[arg(
            long,
            env = "MINI_TUNNEL_COORDINATOR_URL",
            default_value = "http://127.0.0.1:8080"
        )]
        url: String,
    },
}

#[derive(Debug, Subcommand)]
enum RelayCommand {
    Serve {
        #[arg(
            long,
            env = "MINI_TUNNEL_RELAY_LISTEN",
            default_value = "0.0.0.0:42001"
        )]
        listen: SocketAddr,
        /// UDP listener for ticket-authorized opaque QUIC datagrams.
        #[arg(
            long,
            env = "MINI_TUNNEL_UDP_RELAY_LISTEN",
            default_value = "0.0.0.0:42003"
        )]
        udp_listen: SocketAddr,
        /// Loopback-only HTTP health and Prometheus metrics listener.
        #[arg(
            long,
            env = "MINI_TUNNEL_RELAY_METRICS_LISTEN",
            default_value = "127.0.0.1:42002"
        )]
        metrics_listen: SocketAddr,
        /// Maximum concurrent connections and sessions across all sources.
        #[arg(
            long,
            env = "MINI_TUNNEL_RELAY_MAX_CONNECTIONS",
            default_value_t = 256,
            value_parser = parse_positive_usize
        )]
        max_connections: usize,
        /// Maximum concurrent relay connections held by one source IP.
        #[arg(
            long,
            env = "MINI_TUNNEL_RELAY_MAX_CONNECTIONS_PER_SOURCE_IP",
            default_value_t = 32,
            value_parser = parse_positive_usize
        )]
        max_connections_per_source_ip: usize,
        /// UDP authentication burst allowed from one source IP.
        #[arg(
            long,
            env = "MINI_TUNNEL_UDP_RELAY_AUTH_BURST",
            default_value_t = 20,
            value_parser = clap::value_parser!(u32).range(1..=1_000_000)
        )]
        udp_auth_burst: u32,
        /// Sustained UDP authentication packets per second allowed from one source IP.
        #[arg(
            long,
            env = "MINI_TUNNEL_UDP_RELAY_AUTH_RATE_PER_SECOND",
            default_value_t = 10,
            value_parser = clap::value_parser!(u32).range(1..=1_000_000)
        )]
        udp_auth_rate_per_second: u32,
        /// Previous ticket key accepted during rotation. Tickets still expire normally.
        #[arg(long, env = "MINI_TUNNEL_RELAY_PREVIOUS_TICKET_KEY")]
        previous_ticket_key: Option<String>,
        /// Maximum aggregate bytes forwarded in both directions per relay session.
        #[arg(
            long,
            env = "MINI_TUNNEL_RELAY_MAX_SESSION_BYTES",
            default_value_t = 1_073_741_824
        )]
        max_session_bytes: u64,
        /// Maximum time to drain active sessions after Ctrl-C before closing them.
        #[arg(
            long,
            env = "MINI_TUNNEL_RELAY_SHUTDOWN_GRACE_SECONDS",
            default_value_t = 15
        )]
        shutdown_grace_seconds: u64,
    },
}

#[derive(Debug, Subcommand)]
enum NetworkCommand {
    /// Create a network and display its one-time admin capability token.
    Create {
        #[arg(long)]
        name: String,
        #[arg(long)]
        cidr: String,
        #[arg(
            long,
            env = "MINI_TUNNEL_COORDINATOR_URL",
            default_value = "http://127.0.0.1:8080"
        )]
        coordinator_url: String,
    },
    /// Issue a one-time join token. Reads MINI_TUNNEL_ADMIN_TOKEN from the environment.
    Invite {
        #[arg(long)]
        network_id: String,
        #[arg(
            long,
            env = "MINI_TUNNEL_COORDINATOR_URL",
            default_value = "http://127.0.0.1:8080"
        )]
        coordinator_url: String,
    },
    /// Revoke a device from the network and release its assigned IPv4 address.
    /// Reads MINI_TUNNEL_ADMIN_TOKEN from the environment.
    Revoke {
        #[arg(long)]
        network_id: String,
        #[arg(long)]
        device_id: String,
        #[arg(
            long,
            env = "MINI_TUNNEL_COORDINATOR_URL",
            default_value = "http://127.0.0.1:8080"
        )]
        coordinator_url: String,
    },
    /// Consume a one-time join token and allocate a virtual IPv4 address.
    /// Reads MINI_TUNNEL_INVITE_TOKEN from the environment.
    Join {
        #[arg(long)]
        network_id: String,
        #[arg(long)]
        device_id: Option<String>,
        #[arg(
            long,
            env = "MINI_TUNNEL_COORDINATOR_URL",
            default_value = "http://127.0.0.1:8080"
        )]
        coordinator_url: String,
    },
    /// Publish signed direct-connect candidates for this device.
    Advertise {
        #[arg(long)]
        network_id: String,
        #[arg(long = "candidate", required = true)]
        candidates: Vec<String>,
        #[arg(
            long,
            env = "MINI_TUNNEL_COORDINATOR_URL",
            default_value = "http://127.0.0.1:8080"
        )]
        coordinator_url: String,
    },
    /// List peers and candidates from the same-network Coordinator snapshot.
    Peers {
        #[arg(long)]
        network_id: String,
        #[arg(
            long,
            env = "MINI_TUNNEL_COORDINATOR_URL",
            default_value = "http://127.0.0.1:8080"
        )]
        coordinator_url: String,
    },
    /// Check coordinator peer discovery and summarize direct-connect readiness.
    Diagnose {
        #[arg(long)]
        network_id: String,
        #[arg(
            long,
            env = "MINI_TUNNEL_COORDINATOR_URL",
            default_value = "http://127.0.0.1:8080"
        )]
        coordinator_url: String,
    },
}

#[derive(Debug, Subcommand)]
enum PeerCommand {
    /// Create a TUN and keep a bidirectional authenticated peer tunnel running.
    Tunnel {
        #[command(subcommand)]
        command: TunnelCommand,
    },
    /// Query the running tunnel process live peer status over loopback HTTP.
    Status {
        #[arg(long, default_value = "http://127.0.0.1:42003")]
        url: String,
    },
    /// Discover an authorized peer from the signed snapshot and send one diagnostic datagram.
    Connect {
        #[arg(long, default_value = "0.0.0.0:0")]
        bind: SocketAddr,
        #[arg(long)]
        network_id: String,
        #[arg(long)]
        peer_id: String,
        #[arg(long)]
        message: String,
        #[arg(
            long,
            env = "MINI_TUNNEL_COORDINATOR_URL",
            default_value = "http://127.0.0.1:8080"
        )]
        coordinator_url: String,
    },
    /// Listen for one authenticated peer and receive one test datagram.
    Listen {
        #[arg(long, default_value = "127.0.0.1:42000")]
        bind: SocketAddr,
        #[arg(long)]
        network_id: String,
        #[arg(long)]
        peer_id: String,
        /// URL-safe base64 encoded 32-byte Ed25519 public key.
        #[arg(long)]
        peer_key: String,
    },
    /// Send one UTF-8 diagnostic datagram to an authenticated peer.
    Send {
        #[arg(long, default_value = "127.0.0.1:0")]
        bind: SocketAddr,
        #[arg(long)]
        remote: SocketAddr,
        #[arg(long)]
        network_id: String,
        #[arg(long)]
        peer_id: String,
        /// URL-safe base64 encoded 32-byte Ed25519 public key.
        #[arg(long)]
        peer_key: String,
        #[arg(long)]
        message: String,
    },
}

#[derive(Debug, Subcommand)]
enum TunnelCommand {
    /// Discover and connect to a peer, then pump IPv4 packets over QUIC.
    Connect {
        #[arg(long, default_value = "0.0.0.0:0")]
        bind: SocketAddr,
        /// Optional ticket-authorized relay TCP endpoint used after direct UDP/TCP attempts fail.
        #[arg(long, env = "MINI_TUNNEL_RELAY_SERVER")]
        relay_server: Option<SocketAddr>,
        /// Optional ticket-authorized UDP relay endpoint tried before TCP relay.
        #[arg(long, env = "MINI_TUNNEL_UDP_RELAY_SERVER")]
        udp_relay_server: Option<SocketAddr>,
        /// RFC 8489 STUN server used to discover this UDP socket's mapped address; may be repeated (up to four).
        #[arg(long = "stun-server", action = clap::ArgAction::Append)]
        stun_servers: Vec<SocketAddr>,
        /// Enable experimental RFC 8445 checks over the same UDP socket as QUIC.
        #[arg(long)]
        ice: bool,
        /// Additional candidate address to publish; may be repeated.
        #[arg(long = "candidate")]
        candidates: Vec<String>,
        #[arg(long)]
        network_id: String,
        #[arg(long)]
        peer_id: String,
        #[arg(long)]
        local_ipv4: Option<Ipv4Addr>,
        #[arg(long)]
        prefix_len: Option<u8>,
        #[arg(long, default_value_t = 1280)]
        mtu: u16,
        /// Install and clean up /32 IPv4 and /128 IPv6 routes for the authenticated peer.
        #[arg(long)]
        manage_route: bool,
        #[arg(
            long,
            env = "MINI_TUNNEL_COORDINATOR_URL",
            default_value = "http://127.0.0.1:8080"
        )]
        coordinator_url: String,
    },
    /// Accept one authorized peer over UDP/QUIC or optional TLS/TCP fallback.
    Listen {
        #[arg(long, default_value = "0.0.0.0:42000")]
        bind: SocketAddr,
        /// Optional ticket-authorized relay TCP endpoint used when no direct peer connects.
        #[arg(long, env = "MINI_TUNNEL_RELAY_SERVER")]
        relay_server: Option<SocketAddr>,
        /// Optional ticket-authorized UDP relay endpoint tried before TCP relay.
        #[arg(long, env = "MINI_TUNNEL_UDP_RELAY_SERVER")]
        udp_relay_server: Option<SocketAddr>,
        /// Optional TLS/TCP listener for fallback candidates such as tcp://198.51.100.2:443.
        #[arg(long)]
        tcp_bind: Option<SocketAddr>,
        /// RFC 8489 STUN server used to discover this UDP socket's mapped address; may be repeated (up to four).
        #[arg(long = "stun-server", action = clap::ArgAction::Append)]
        stun_servers: Vec<SocketAddr>,
        /// Enable experimental RFC 8445 checks over the same UDP socket as QUIC.
        #[arg(long)]
        ice: bool,
        /// Additional candidate address to publish; may be repeated.
        #[arg(long = "candidate")]
        candidates: Vec<String>,
        #[arg(long)]
        network_id: String,
        #[arg(long)]
        peer_id: String,
        #[arg(long)]
        local_ipv4: Option<Ipv4Addr>,
        #[arg(long)]
        prefix_len: Option<u8>,
        #[arg(long, default_value_t = 1280)]
        mtu: u16,
        /// Install and clean up /32 IPv4 and /128 IPv6 routes for the authenticated peer.
        #[arg(long)]
        manage_route: bool,
        #[arg(
            long,
            env = "MINI_TUNNEL_COORDINATOR_URL",
            default_value = "http://127.0.0.1:8080"
        )]
        coordinator_url: String,
    },
    /// Connect all currently discoverable members into one dual-stack IPv4/IPv6 L3 mesh.
    Mesh {
        #[arg(long, default_value = "0.0.0.0:42000")]
        bind: SocketAddr,
        /// Optional TLS/TCP listener for fallback candidates such as tcp://198.51.100.2:443.
        #[arg(long)]
        tcp_bind: Option<SocketAddr>,
        /// Optional ticket-authorized relay TCP endpoint used after direct UDP/TCP attempts fail.
        #[arg(long, env = "MINI_TUNNEL_RELAY_SERVER")]
        relay_server: Option<SocketAddr>,
        /// Optional ticket-authorized UDP relay endpoint tried before TCP relay.
        #[arg(long, env = "MINI_TUNNEL_UDP_RELAY_SERVER")]
        udp_relay_server: Option<SocketAddr>,
        /// RFC 8489 STUN server used to discover this UDP socket's mapped address; may be repeated (up to four).
        #[arg(long = "stun-server", action = clap::ArgAction::Append)]
        stun_servers: Vec<SocketAddr>,
        /// Enable experimental RFC 8445 checks for mesh peer sessions.
        #[arg(long)]
        ice: bool,
        /// Additional candidate address to publish; may be repeated.
        #[arg(long = "candidate")]
        candidates: Vec<String>,
        #[arg(long)]
        network_id: String,
        #[arg(long)]
        local_ipv4: Option<Ipv4Addr>,
        #[arg(long)]
        prefix_len: Option<u8>,
        #[arg(long, default_value_t = 1280)]
        mtu: u16,
        /// Install and clean up /32 IPv4 and /128 IPv6 routes for every authenticated peer.
        #[arg(long)]
        manage_route: bool,
        #[arg(
            long,
            env = "MINI_TUNNEL_COORDINATOR_URL",
            default_value = "http://127.0.0.1:8080"
        )]
        coordinator_url: String,
    },
}

#[derive(Debug, Deserialize)]
struct HealthResponse {
    status: String,
    service: String,
    version: String,
}

async fn peer_status() -> axum::Json<Vec<mini_tunnel_agent::status::PeerStatus>> {
    axum::Json(mini_tunnel_agent::status::snapshot())
}

async fn peer_metrics() -> impl IntoResponse {
    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        mini_tunnel_agent::status::prometheus(),
    )
}

fn validate_status_address(address: SocketAddr) -> Result<(), &'static str> {
    if address.ip().is_loopback() {
        Ok(())
    } else {
        Err("peer status listener must use a loopback address")
    }
}

async fn spawn_peer_status_server()
-> Result<tokio::task::JoinHandle<()>, Box<dyn std::error::Error + Send + Sync>> {
    let address = std::env::var("MINI_TUNNEL_STATUS_LISTEN")
        .unwrap_or_else(|_| "127.0.0.1:42003".to_owned())
        .parse::<SocketAddr>()?;
    validate_status_address(address)?;
    let listener = tokio::net::TcpListener::bind(address).await?;
    let address = listener.local_addr()?;
    println!("Live peer status available at http://{address}/status and /metrics");
    let app = Router::new()
        .route("/status", get(peer_status))
        .route("/metrics", get(peer_metrics));
    Ok(tokio::spawn(async move {
        if let Err(error) = axum::serve(listener, app).await {
            tracing::error!(%error, "peer status listener stopped");
        }
    }))
}

#[tokio::main]
async fn main() -> ExitCode {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();
    if let Err(error) = run(Cli::parse()).await {
        eprintln!("error: {error}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

fn parse_positive_usize(value: &str) -> Result<usize, String> {
    let parsed = value
        .parse::<usize>()
        .map_err(|_| "value must be a positive integer".to_owned())?;
    if parsed == 0 {
        return Err("value must be greater than zero".to_owned());
    }
    Ok(parsed)
}

fn validate_relay_metrics_address(address: SocketAddr) -> std::io::Result<()> {
    if address.ip().is_loopback() {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "relay metrics listener must use a loopback address",
        ))
    }
}

#[derive(Clone)]
struct RelayMetricsState {
    tcp: mini_tunnel_relay::RelayServer,
    udp: mini_tunnel_relay::UdpRelayServer,
}

fn relay_metrics_router(
    tcp: mini_tunnel_relay::RelayServer,
    udp: mini_tunnel_relay::UdpRelayServer,
) -> Router {
    Router::new()
        .route("/healthz", get(relay_health))
        .route("/metrics", get(relay_metrics))
        .with_state(RelayMetricsState { tcp, udp })
}

async fn relay_health() -> impl IntoResponse {
    (StatusCode::OK, "ok\n")
}

async fn relay_metrics(State(relay): State<RelayMetricsState>) -> impl IntoResponse {
    let stats = relay.tcp.stats().await;
    let udp_stats = relay.udp.stats().await;
    let body = format!(
        "# HELP mini_tunnel_relay_active_connections Accepted relay connections, including pending and active sessions.\n\
         # TYPE mini_tunnel_relay_active_connections gauge\n\
         mini_tunnel_relay_active_connections {}\n\
         # HELP mini_tunnel_relay_max_connections Configured global connection limit.\n\
         # TYPE mini_tunnel_relay_max_connections gauge\n\
         mini_tunnel_relay_max_connections {}\n\
         # HELP mini_tunnel_relay_max_connections_per_source_ip Configured source IP connection limit.\n\
         # TYPE mini_tunnel_relay_max_connections_per_source_ip gauge\n\
         mini_tunnel_relay_max_connections_per_source_ip {}\n\
         # HELP mini_tunnel_relay_active_sessions Pending or established relay sessions.\n\
         # TYPE mini_tunnel_relay_active_sessions gauge\n\
         mini_tunnel_relay_active_sessions {}\n\
         # HELP mini_tunnel_relay_accepted_connections_total TCP connections accepted by the listener.\n\
         # TYPE mini_tunnel_relay_accepted_connections_total counter\n\
         mini_tunnel_relay_accepted_connections_total {}\n\
         # HELP mini_tunnel_relay_capacity_rejections_total Connections rejected by global or source IP limits.\n\
         # TYPE mini_tunnel_relay_capacity_rejections_total counter\n\
         mini_tunnel_relay_capacity_rejections_total {}\n\
         # HELP mini_tunnel_relay_handshake_failures_total Relay protocol or identity handshakes that failed or timed out.\n\
         # TYPE mini_tunnel_relay_handshake_failures_total counter\n\
         mini_tunnel_relay_handshake_failures_total {}\n\
         # HELP mini_tunnel_relay_bytes_forwarded_total Bytes forwarded across all sessions.\n\
         # TYPE mini_tunnel_relay_bytes_forwarded_total counter\n\
         mini_tunnel_relay_bytes_forwarded_total {}\n\
         # HELP mini_tunnel_udp_relay_active_sessions Paired UDP relay sessions.\n\
         # TYPE mini_tunnel_udp_relay_active_sessions gauge\n\
         mini_tunnel_udp_relay_active_sessions {}\n\
         # HELP mini_tunnel_udp_relay_pending_authentications UDP relay challenges awaiting proof.\n\
         # TYPE mini_tunnel_udp_relay_pending_authentications gauge\n\
         mini_tunnel_udp_relay_pending_authentications {}\n\
         # HELP mini_tunnel_udp_relay_forwarded_datagrams_total Opaque datagrams forwarded by UDP relay.\n\
         # TYPE mini_tunnel_udp_relay_forwarded_datagrams_total counter\n\
         mini_tunnel_udp_relay_forwarded_datagrams_total {}\n\
         # HELP mini_tunnel_udp_relay_auth_rate_limited_total UDP relay authentication packets rejected by per-source rate limits.\n\
         # TYPE mini_tunnel_udp_relay_auth_rate_limited_total counter\n\
         mini_tunnel_udp_relay_auth_rate_limited_total {}\n\
         # HELP mini_tunnel_udp_relay_dropped_datagrams_total Invalid or unauthorized UDP relay packets dropped.\n\
         # TYPE mini_tunnel_udp_relay_dropped_datagrams_total counter\n\
         mini_tunnel_udp_relay_dropped_datagrams_total {}\n",
        stats.active_connections,
        stats.max_connections,
        stats.max_connections_per_source_ip,
        stats.active_sessions,
        stats.accepted_connections_total,
        stats.capacity_rejections_total,
        stats.handshake_failures_total,
        stats.bytes_forwarded_total,
        udp_stats.active_sessions,
        udp_stats.pending_authentications,
        udp_stats.forwarded_datagrams_total,
        udp_stats.auth_rate_limited_total,
        udp_stats.dropped_datagrams_total,
    );
    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
}

fn default_coordinator_state_path() -> PathBuf {
    directories::ProjectDirs::from("org", "ilovn", "mini-tunnel")
        .map(|dirs| dirs.data_local_dir().join("coordinator-state.json"))
        .unwrap_or_else(|| PathBuf::from("mini-tunnel-state.json"))
}

fn decode_ticket_key(value: &str, source: &str) -> Result<[u8; 32], String> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value.trim())
        .map_err(|_| format!("{source} must be base64url encoding of exactly 32 bytes"))?;
    <[u8; 32]>::try_from(bytes)
        .map_err(|_| format!("{source} must be base64url encoding of exactly 32 bytes"))
}

fn load_ticket_key(
    encoded_environment_value: Option<&str>,
    credential_file: Option<&Path>,
    environment_name: &str,
    file_environment_name: &str,
) -> Result<Option<[u8; 32]>, String> {
    if let Some(path) = credential_file {
        let contents = std::fs::read_to_string(path).map_err(|_| {
            format!("could not read the ticket key credential named by {file_environment_name}")
        })?;
        return decode_ticket_key(&contents, file_environment_name).map(Some);
    }

    encoded_environment_value
        .map(|value| decode_ticket_key(value, environment_name))
        .transpose()
}

fn ticket_key_file_from_env(name: &str) -> Option<PathBuf> {
    std::env::var_os(name).map(PathBuf::from)
}

async fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match cli.command {
        Command::Coordinator { command } => match command {
            CoordinatorCommand::Serve {
                listen,
                state_file,
                tls_cert,
                tls_key,
                tls_reload_interval_seconds,
                trusted_proxies,
            } => {
                let relay_key = load_ticket_key(
                    std::env::var("MINI_TUNNEL_RELAY_TICKET_KEY")
                        .ok()
                        .as_deref(),
                    ticket_key_file_from_env("MINI_TUNNEL_RELAY_TICKET_KEY_FILE").as_deref(),
                    "MINI_TUNNEL_RELAY_TICKET_KEY",
                    "MINI_TUNNEL_RELAY_TICKET_KEY_FILE",
                )?;
                let tls_files = match (tls_cert, tls_key) {
                    (Some(certificate), Some(private_key)) => Some((certificate, private_key)),
                    (None, None) => None,
                    _ => return Err("--tls-cert and --tls-key must be provided together".into()),
                };
                if !listen.ip().is_loopback() && tls_files.is_none() {
                    return Err(
                        "non-loopback coordinator listeners require TLS; configure --tls-cert and --tls-key".into(),
                    );
                }
                let database_url = std::env::var("MINI_TUNNEL_COORDINATOR_DATABASE_URL").ok();
                if database_url.is_some() && state_file.is_some() {
                    return Err(
                        "choose either MINI_TUNNEL_COORDINATOR_DATABASE_URL or --state-file, not both".into(),
                    );
                }
                let reload_interval = Duration::from_secs(tls_reload_interval_seconds);
                if let Some(database_url) = database_url {
                    mini_tunnel_coordinator::serve_with_postgres_url_and_relay_key_tls_and_reload_interval_and_trusted_proxies(
                        listen,
                        &database_url,
                        relay_key,
                        tls_files,
                        reload_interval,
                        trusted_proxies,
                    )
                    .await?;
                } else {
                    mini_tunnel_coordinator::serve_with_state_file_and_relay_key_tls_and_reload_interval_and_trusted_proxies(
                        listen,
                        state_file.unwrap_or_else(default_coordinator_state_path),
                        relay_key,
                        tls_files,
                        reload_interval,
                        trusted_proxies,
                    )
                    .await?;
                }
            }
            CoordinatorCommand::VerifyState { state_file } => {
                let summary =
                    mini_tunnel_coordinator::CoordinatorState::verify_persistent_state(&state_file)
                        .await?;
                println!(
                    "valid coordinator snapshot: {} networks, {} members, {} invites",
                    summary.networks, summary.members, summary.invites
                );
            }
            CoordinatorCommand::BackupState { state_file, output } => {
                let summary =
                    mini_tunnel_coordinator::CoordinatorState::copy_persistent_state_snapshot(
                        &state_file,
                        &output,
                    )
                    .await?;
                println!(
                    "backed up {} networks, {} members, {} invites to {}",
                    summary.networks,
                    summary.members,
                    summary.invites,
                    output.display()
                );
            }
            CoordinatorCommand::RestoreState { state_file, backup } => {
                let summary =
                    mini_tunnel_coordinator::CoordinatorState::copy_persistent_state_snapshot(
                        &backup,
                        &state_file,
                    )
                    .await?;
                println!(
                    "restored {} networks, {} members, {} invites from {}",
                    summary.networks,
                    summary.members,
                    summary.invites,
                    backup.display()
                );
            }
            CoordinatorCommand::ImportStateToPostgres { state_file } => {
                let database_url = std::env::var("MINI_TUNNEL_COORDINATOR_DATABASE_URL")
                    .map_err(|_| "MINI_TUNNEL_COORDINATOR_DATABASE_URL is required")?;
                let summary =
                    mini_tunnel_coordinator::CoordinatorState::import_snapshot_to_postgres(
                        &state_file,
                        &database_url,
                    )
                    .await?;
                println!(
                    "imported {} networks, {} members, {} invites into PostgreSQL",
                    summary.networks, summary.members, summary.invites
                );
            }
            CoordinatorCommand::ExportStateFromPostgres { output } => {
                let database_url = std::env::var("MINI_TUNNEL_COORDINATOR_DATABASE_URL")
                    .map_err(|_| "MINI_TUNNEL_COORDINATOR_DATABASE_URL is required")?;
                let summary =
                    mini_tunnel_coordinator::CoordinatorState::export_postgres_to_snapshot(
                        &database_url,
                        &output,
                    )
                    .await?;
                println!(
                    "exported {} networks, {} members, {} invites to {}",
                    summary.networks,
                    summary.members,
                    summary.invites,
                    output.display()
                );
            }
            CoordinatorCommand::MigratePostgres => {
                let database_url = std::env::var("MINI_TUNNEL_COORDINATOR_DATABASE_URL")
                    .map_err(|_| "MINI_TUNNEL_COORDINATOR_DATABASE_URL is required")?;
                mini_tunnel_coordinator::CoordinatorState::migrate_postgres_database(&database_url)
                    .await?;
                println!("Coordinator PostgreSQL schema is up to date");
            }
            CoordinatorCommand::Health { url } => {
                let endpoint = format!("{}/healthz", url.trim_end_matches('/'));
                let response = coordinator_http_client(Duration::from_secs(3))?
                    .get(endpoint)
                    .send()
                    .await?
                    .error_for_status()?
                    .json::<HealthResponse>()
                    .await?;
                if response.status != "ok" || response.service != "coordinator" {
                    return Err(format!("unexpected health response: {response:?}").into());
                }
                println!(
                    "{} {}: {}",
                    response.service, response.version, response.status
                );
            }
        },
        Command::Relay { command } => match command {
            RelayCommand::Serve {
                listen,
                udp_listen,
                metrics_listen,
                max_connections,
                max_connections_per_source_ip,
                udp_auth_burst,
                udp_auth_rate_per_second,
                previous_ticket_key,
                max_session_bytes,
                shutdown_grace_seconds,
            } => {
                let key = load_ticket_key(
                    std::env::var("MINI_TUNNEL_RELAY_TICKET_KEY").ok().as_deref(),
                    ticket_key_file_from_env("MINI_TUNNEL_RELAY_TICKET_KEY_FILE").as_deref(),
                    "MINI_TUNNEL_RELAY_TICKET_KEY",
                    "MINI_TUNNEL_RELAY_TICKET_KEY_FILE",
                )?
                .ok_or_else(|| {
                    "MINI_TUNNEL_RELAY_TICKET_KEY or MINI_TUNNEL_RELAY_TICKET_KEY_FILE is required for relay service".to_owned()
                })?;
                let previous_key = load_ticket_key(
                    previous_ticket_key.as_deref(),
                    ticket_key_file_from_env("MINI_TUNNEL_RELAY_PREVIOUS_TICKET_KEY_FILE")
                        .as_deref(),
                    "MINI_TUNNEL_RELAY_PREVIOUS_TICKET_KEY",
                    "MINI_TUNNEL_RELAY_PREVIOUS_TICKET_KEY_FILE",
                )?;
                let mut config = mini_tunnel_relay::RelayConfig::new(key)
                    .with_max_session_bytes(max_session_bytes)
                    .with_max_connections(max_connections)
                    .with_max_connections_per_source_ip(max_connections_per_source_ip);
                config.shutdown_grace = Duration::from_secs(shutdown_grace_seconds);
                if let Some(previous) = previous_key {
                    config = config.with_previous_ticket_key(previous);
                }
                validate_relay_metrics_address(metrics_listen)?;
                let listener = tokio::net::TcpListener::bind(listen).await?;
                eprintln!("relay listening on {}", listener.local_addr()?);
                let udp_socket = tokio::net::UdpSocket::bind(udp_listen).await?;
                eprintln!("UDP relay listening on {}", udp_socket.local_addr()?);
                let metrics_listener = tokio::net::TcpListener::bind(metrics_listen).await?;
                let relay = mini_tunnel_relay::RelayServer::new(config);
                let mut udp_config = mini_tunnel_relay::UdpRelayConfig::new(key)
                    .with_auth_rate(udp_auth_burst, udp_auth_rate_per_second);
                if let Some(previous) = previous_key {
                    udp_config = udp_config.with_previous_ticket_key(previous);
                }
                let udp_relay = mini_tunnel_relay::UdpRelayServer::new(udp_config);
                let metrics_router = relay_metrics_router(relay.clone(), udp_relay.clone());
                let (metrics_shutdown_tx, mut metrics_shutdown_rx) =
                    tokio::sync::watch::channel(false);
                let metrics_task = tokio::spawn(async move {
                    axum::serve(metrics_listener, metrics_router)
                        .with_graceful_shutdown(async move {
                            while !*metrics_shutdown_rx.borrow() {
                                if metrics_shutdown_rx.changed().await.is_err() {
                                    break;
                                }
                            }
                        })
                        .await
                });
                eprintln!("relay metrics listening on {metrics_listen}");
                let udp_server = udp_relay.clone();
                let udp_task = tokio::spawn(async move { udp_server.run(udp_socket).await });
                let (shutdown_tx, _) = tokio::sync::watch::channel(false);
                let signal_tx = shutdown_tx.clone();
                let signal_udp_relay = udp_relay.clone();
                tokio::spawn(async move {
                    if let Err(error) = shutdown_signal().await {
                        eprintln!("could not listen for shutdown signal: {error}");
                    }
                    signal_tx.send_replace(true);
                    signal_udp_relay.shutdown();
                });
                let mut shutdown_rx = shutdown_tx.subscribe();
                let result = relay
                    .run_until(listener, async {
                        while !*shutdown_rx.borrow() {
                            if shutdown_rx.changed().await.is_err() {
                                break;
                            }
                        }
                    })
                    .await;
                udp_relay.shutdown();
                let udp_result = udp_task.await?;
                metrics_shutdown_tx.send_replace(true);
                let metrics_result = metrics_task.await?;
                result?;
                udp_result?;
                metrics_result?;
            }
        },
        Command::Identity => {
            let identity = mini_tunnel_agent::Identity::load_or_create()?;
            println!("Device ID: {}", identity.device_id());
            println!("Public key: {}", identity.public_key_encoded());
            if let Some(path) = mini_tunnel_agent::default_identity_path() {
                println!("Private key: {}", path.display());
            }
        }
        Command::Peer { command } => match command {
            PeerCommand::Tunnel { command } => match command {
                TunnelCommand::Connect {
                    bind,
                    relay_server,
                    udp_relay_server,
                    stun_servers,
                    ice,
                    candidates,
                    network_id,
                    peer_id,
                    local_ipv4,
                    prefix_len,
                    mtu,
                    manage_route,
                    coordinator_url,
                } => {
                    let relay_endpoints = RelayEndpoints {
                        tcp: relay_server,
                        udp: udp_relay_server,
                    };
                    let _status_server = spawn_peer_status_server().await?;
                    let identity =
                        std::sync::Arc::new(mini_tunnel_agent::Identity::load_or_create()?);
                    let (local_ipv4, prefix_len) =
                        resolve_tun_parameters(&network_id, &identity, local_ipv4, prefix_len)?;
                    let endpoint = create_tunnel_endpoint(
                        &identity,
                        bind,
                        stun_servers,
                        ice,
                        &candidates,
                        &network_id,
                        &coordinator_url,
                    )
                    .await?;
                    let tun = create_tun(&network_id, local_ipv4, prefix_len, mtu)?;
                    endpoint.exclude_tun_interface(&tun)?;
                    let mut attempt = 0_u32;
                    loop {
                        let result = async {
                            let peer =
                                discover_peer(&coordinator_url, &network_id, &peer_id, &identity)
                                    .await?;
                            let peer_key = decode_peer_key(&peer.public_key)?;
                            let (channel, remote) = connect_tunnel_peer(
                                &endpoint,
                                &peer,
                                &network_id,
                                &identity,
                                peer_key,
                                relay_endpoints,
                                &coordinator_url,
                            )
                            .await?;
                            let (connector, probe, accepted_tx) = build_mesh_peer_connectors(
                                endpoint.clone(),
                                std::sync::Arc::clone(&identity),
                                network_id.clone(),
                                coordinator_url.clone(),
                                peer.clone(),
                                relay_endpoints,
                            );
                            let accept_tasks = spawn_single_peer_acceptors(
                                endpoint.clone(),
                                std::sync::Arc::clone(&identity),
                                network_id.clone(),
                                peer.device_id.clone(),
                                peer_key,
                                None,
                                accepted_tx,
                            );
                            run_peer_tunnel(
                                &tun,
                                PeerSessionControl {
                                    coordinator_url: &coordinator_url,
                                    network_id: &network_id,
                                    identity: &identity,
                                },
                                PeerSessionRuntime {
                                    channel: std::sync::Arc::new(channel),
                                    peer: &peer,
                                    remote,
                                    connector,
                                    probe,
                                    accept_tasks,
                                },
                                manage_route,
                            )
                            .await
                        }
                        .await;
                        match result {
                            Ok(()) => break,
                            Err(error) => eprintln!("Peer session ended: {error}"),
                        }
                        if !wait_reconnect(attempt).await {
                            break;
                        }
                        attempt = attempt.saturating_add(1);
                    }
                }
                TunnelCommand::Listen {
                    bind,
                    relay_server,
                    udp_relay_server,
                    tcp_bind,
                    stun_servers,
                    ice,
                    candidates,
                    network_id,
                    peer_id,
                    local_ipv4,
                    prefix_len,
                    mtu,
                    manage_route,
                    coordinator_url,
                } => {
                    let relay_endpoints = RelayEndpoints {
                        tcp: relay_server,
                        udp: udp_relay_server,
                    };
                    let _status_server = spawn_peer_status_server().await?;
                    let identity =
                        std::sync::Arc::new(mini_tunnel_agent::Identity::load_or_create()?);
                    let (local_ipv4, prefix_len) =
                        resolve_tun_parameters(&network_id, &identity, local_ipv4, prefix_len)?;
                    let tcp_listener = match tcp_bind {
                        Some(address) => Some(std::sync::Arc::new(
                            mini_tunnel_agent::peer_tcp_listener(address).await?,
                        )),
                        None => None,
                    };
                    let endpoint = create_tunnel_endpoint(
                        &identity,
                        bind,
                        stun_servers,
                        ice,
                        &candidates,
                        &network_id,
                        &coordinator_url,
                    )
                    .await?;
                    let tun = create_tun(&network_id, local_ipv4, prefix_len, mtu)?;
                    endpoint.exclude_tun_interface(&tun)?;
                    println!(
                        "Waiting for authenticated peer on {}",
                        endpoint.local_addr()?
                    );
                    let mut attempt = 0_u32;
                    loop {
                        let result = async {
                            let peer = discover_peer(&coordinator_url, &network_id, &peer_id, &identity).await?;
                            let peer_key = decode_peer_key(&peer.public_key)?;
                            let nominated = select_ice_peer_address(&endpoint, &peer, &identity).await;
                            let accept_direct = async {
                                let channel = mini_tunnel_agent::accept_peer(
                                    &endpoint, &network_id, &identity, &peer.device_id, peer_key,
                                );
                                if let Some(listener) = &tcp_listener {
                                    let allowed = vec![(peer.device_id.clone(), peer_key)];
                                    tokio::select! {
                                        result = channel => result,
                                        result = mini_tunnel_agent::accept_tcp_peer_any(listener, &network_id, &identity, &allowed) => result.map(|(_, channel)| channel),
                                    }
                                } else {
                                    channel.await
                                }
                            };
                            let mut channel = if relay_endpoints.tcp.is_some() || relay_endpoints.udp.is_some() {
                                match tokio::time::timeout(Duration::from_secs(35), accept_direct).await {
                                    Ok(result) => result?,
                                    Err(_) => {
                                        if let Some(relay) = relay_endpoints.udp {
                                            match connect_peer_via_udp_relay(relay, &coordinator_url, &network_id, &identity, &peer).await {
                                                Ok(channel) => channel,
                                                Err(error) => {
                                                    eprintln!("UDP relay failed, trying TCP relay: {error}");
                                                    if let Some(relay) = relay_endpoints.tcp {
                                                        connect_peer_via_relay(relay, &coordinator_url, &network_id, &identity, &peer).await?
                                                    } else { return Err(error.into()); }
                                                }
                                            }
                                        } else if let Some(relay) = relay_endpoints.tcp {
                                            connect_peer_via_relay(relay, &coordinator_url, &network_id, &identity, &peer).await?
                                        } else { return Err("no peer accepted before timeout".into()); }
                                    }
                                }
                            } else {
                                accept_direct.await?
                            };
                            let remote = channel.remote_address();
                            if let Some((nominated_remote, monitor)) = nominated {
                                if remote == nominated_remote
                                    && channel.transport_name() == "QUIC/UDP"
                                {
                                    tracing::debug!(
                                        peer_id = %peer.device_id,
                                        remote = %remote,
                                        "attaching ICE consent monitor to accepted peer"
                                    );
                                    channel.set_ice_consent_monitor(monitor);
                                } else {
                                    tracing::warn!(
                                        peer_id = %peer.device_id,
                                        nominated_remote = %nominated_remote,
                                        quic_remote = %remote,
                                        transport = channel.transport_name(),
                                        "stopping ICE consent monitor because accepted path differs from nominated path"
                                    );
                                    monitor.stop().await;
                                }
                            }
                            let (connector, probe, accepted_tx) = build_mesh_peer_connectors(
                                endpoint.clone(),
                                std::sync::Arc::clone(&identity),
                                network_id.clone(),
                                coordinator_url.clone(),
                                peer.clone(),
                                relay_endpoints,
                            );
                            let accept_tasks = spawn_single_peer_acceptors(
                                endpoint.clone(),
                                std::sync::Arc::clone(&identity),
                                network_id.clone(),
                                peer.device_id.clone(),
                                peer_key,
                                tcp_listener.clone(),
                                accepted_tx,
                            );
                            run_peer_tunnel(
                                &tun,
                                PeerSessionControl {
                                    coordinator_url: &coordinator_url,
                                    network_id: &network_id,
                                    identity: &identity,
                                },
                                PeerSessionRuntime {
                                    channel: std::sync::Arc::new(channel),
                                    peer: &peer,
                                    remote,
                                    connector,
                                    probe,
                                    accept_tasks,
                                },
                                manage_route,
                            )
                            .await
                        }.await;
                        match result {
                            Ok(()) => break,
                            Err(error) => eprintln!("Peer session ended: {error}"),
                        }
                        if !wait_reconnect(attempt).await {
                            break;
                        }
                        attempt = attempt.saturating_add(1);
                    }
                }
                TunnelCommand::Mesh {
                    bind,
                    tcp_bind,
                    relay_server,
                    udp_relay_server,
                    stun_servers,
                    ice,
                    candidates,
                    network_id,
                    local_ipv4,
                    prefix_len,
                    mtu,
                    manage_route,
                    coordinator_url,
                } => {
                    let relay_endpoints = RelayEndpoints {
                        tcp: relay_server,
                        udp: udp_relay_server,
                    };
                    let _status_server = spawn_peer_status_server().await?;
                    let identity = mini_tunnel_agent::Identity::load_or_create()?;
                    let (local_ipv4, prefix_len) =
                        resolve_tun_parameters(&network_id, &identity, local_ipv4, prefix_len)?;
                    let tcp_listener = match tcp_bind {
                        Some(address) => Some(mini_tunnel_agent::peer_tcp_listener(address).await?),
                        None => None,
                    };
                    let endpoint = create_tunnel_endpoint(
                        &identity,
                        bind,
                        stun_servers,
                        ice,
                        &candidates,
                        &network_id,
                        &coordinator_url,
                    )
                    .await?;
                    if let Some(listener) = &tcp_listener {
                        println!("TCP fallback listening on {}", listener.local_addr()?);
                    }
                    let peers = discover_peers(&coordinator_url, &network_id, &identity).await?;
                    let local_device_id = identity.device_id();
                    let identity = std::sync::Arc::new(identity);
                    let mut attempts = tokio::task::JoinSet::new();
                    let mut peer_connectors = std::collections::HashMap::new();
                    let mut peer_probes = std::collections::HashMap::new();
                    let mut accepted_peer_senders = std::collections::HashMap::new();
                    for peer in peers.iter().cloned() {
                        let keep_outbound = local_device_id < peer.device_id;
                        let (connector, probe, accepted_peer_tx) = build_mesh_peer_connectors(
                            endpoint.clone(),
                            std::sync::Arc::clone(&identity),
                            network_id.clone(),
                            coordinator_url.clone(),
                            peer.clone(),
                            relay_endpoints,
                        );
                        accepted_peer_senders.insert(peer.device_id.clone(), accepted_peer_tx);
                        peer_connectors.insert(peer.device_id.clone(), connector);
                        peer_probes.insert(peer.device_id.clone(), probe);
                        let endpoint = endpoint.clone();
                        let identity = std::sync::Arc::clone(&identity);
                        let network_id = network_id.clone();
                        let coordinator_url = coordinator_url.clone();
                        attempts.spawn(async move {
                            let result = connect_mesh_peer(
                                &endpoint,
                                &network_id,
                                &coordinator_url,
                                &identity,
                                &peer,
                                relay_endpoints,
                                false,
                            )
                            .await;
                            (peer, keep_outbound, result)
                        });
                    }
                    let (accepted_tx, mut accepted_rx) = tokio::sync::mpsc::channel(64);
                    let require_ice_consent = endpoint.ice.is_some();
                    let allowed_members = peers
                        .iter()
                        .map(|peer| {
                            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((
                                peer.device_id.clone(),
                                decode_peer_key(&peer.public_key)?,
                            ))
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    let (allowlist_tx, allowlist_rx) = tokio::sync::watch::channel(allowed_members);
                    let (snapshot_tx, snapshot_rx) = tokio::sync::watch::channel(peers.clone());
                    let mut accept_tasks = vec![{
                        let endpoint = endpoint.clone();
                        let identity = std::sync::Arc::clone(&identity);
                        let network_id = network_id.clone();
                        let local_device_id = local_device_id.clone();
                        let accepted_tx = accepted_tx.clone();
                        let allowlist_rx = allowlist_rx.clone();
                        let snapshot_rx = snapshot_rx.clone();
                        tokio::spawn(async move {
                            loop {
                                let Ok((device_id, channel)) =
                                    mini_tunnel_agent::accept_peer_any_dynamic(
                                        &endpoint,
                                        &network_id,
                                        &identity,
                                        allowlist_rx.clone(),
                                    )
                                    .await
                                else {
                                    break;
                                };
                                let current_peers = snapshot_rx.borrow().clone();
                                if let Some(peer) = current_peers
                                    .iter()
                                    .find(|peer| peer.device_id == device_id)
                                    .cloned()
                                {
                                    if peer.device_id < local_device_id {
                                        let remote = channel.remote_address();
                                        if accepted_tx.send((peer, channel, remote)).await.is_err()
                                        {
                                            break;
                                        }
                                    } else {
                                        // The smaller device owns the data session. This reverse
                                        // connection is only a simultaneous UDP hole-punch probe.
                                        channel.close();
                                    }
                                }
                            }
                            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
                        })
                    }];
                    if let Some(listener) = tcp_listener {
                        let identity = std::sync::Arc::clone(&identity);
                        let network_id = network_id.clone();
                        let local_device_id = local_device_id.clone();
                        let accepted_tx = accepted_tx.clone();
                        let allowlist_rx = allowlist_rx.clone();
                        let snapshot_rx = snapshot_rx.clone();
                        accept_tasks.push(tokio::spawn(async move {
                            loop {
                                let Ok((device_id, channel)) =
                                    mini_tunnel_agent::accept_tcp_peer_any_dynamic(
                                        &listener,
                                        &network_id,
                                        &identity,
                                        allowlist_rx.clone(),
                                    )
                                    .await
                                else {
                                    break;
                                };
                                let current_peers = snapshot_rx.borrow().clone();
                                if let Some(peer) = current_peers
                                    .iter()
                                    .find(|peer| peer.device_id == device_id)
                                    .cloned()
                                {
                                    if peer.device_id < local_device_id {
                                        let remote = channel.remote_address();
                                        if accepted_tx.send((peer, channel, remote)).await.is_err()
                                        {
                                            break;
                                        }
                                    } else {
                                        channel.close();
                                    }
                                }
                            }
                            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
                        }));
                    }
                    drop(accepted_tx);
                    let mut connected: Vec<(
                        PeerInfo,
                        mini_tunnel_agent::PeerChannel,
                        SocketAddr,
                        mini_tunnel_agent::tunnel::PeerConnector,
                        mini_tunnel_agent::tunnel::PeerConnector,
                    )> = Vec::new();
                    let mut pending_accepted_channels = std::collections::HashMap::new();
                    let mut pending_ice_monitors = std::collections::HashMap::<
                        String,
                        (SocketAddr, mini_tunnel_agent::ice::IceConsentMonitor),
                    >::new();
                    let mut accept_finished = accept_tasks.is_empty();
                    let startup_deadline = tokio::time::Instant::now() + Duration::from_secs(45);
                    let mut first_peer_at = None;
                    loop {
                        if attempts.is_empty() && peers.is_empty() {
                            break;
                        }
                        if attempts.is_empty() && accept_finished {
                            break;
                        }
                        let settle_deadline = mesh_startup_settle_deadline(
                            first_peer_at,
                            !attempts.is_empty(),
                            startup_deadline,
                            Duration::from_secs(1),
                        );
                        tokio::select! {
                            accepted = accepted_rx.recv(), if !accept_finished => {
                                match accepted {
                                    Some((peer, mut channel, remote)) => {
                                        tracing::debug!(
                                            peer_id = %peer.device_id,
                                            path = channel.transport_name(),
                                            has_ice_consent = channel.has_ice_consent_monitor(),
                                            "accepted authenticated mesh channel"
                                        );
                                        if connected.iter().any(|known| {
                                            known.0.device_id == peer.device_id
                                                && known.1.transport_name() == "QUIC/UDP"
                                        }) {
                                            tracing::debug!(
                                                peer_id = %peer.device_id,
                                                path = channel.transport_name(),
                                                reason = "direct_path_already_connected",
                                                "closing duplicate accepted mesh channel"
                                            );
                                            channel.close();
                                        } else if require_ice_consent && channel.transport_name() == "QUIC/UDP" {
                                            if let Some((nominated_remote, monitor)) = pending_ice_monitors.remove(&peer.device_id) {
                                                if attach_nominated_ice_monitor(
                                                    &mut channel,
                                                    nominated_remote,
                                                    monitor,
                                                ).await {
                                                    install_mesh_peer_channel(
                                                        &mut connected,
                                                        peer,
                                                        channel,
                                                        remote,
                                                        &mut peer_connectors,
                                                        &mut peer_probes,
                                                    );
                                                    first_peer_at.get_or_insert_with(tokio::time::Instant::now);
                                                } else {
                                                    if let Some((_, duplicate, _)) = pending_accepted_channels.insert(peer.device_id.clone(), (peer, channel, remote)) {
                                                        tracing::debug!(
                                                            path = duplicate.transport_name(),
                                                            reason = "superseded_pending_accepted_channel",
                                                            "closing superseded pending mesh channel"
                                                        );
                                                        duplicate.close();
                                                    }
                                                }
                                            } else if let Some((_, duplicate, _)) = pending_accepted_channels.insert(peer.device_id.clone(), (peer, channel, remote)) {
                                                tracing::debug!(
                                                    path = duplicate.transport_name(),
                                                    reason = "superseded_pending_accepted_channel",
                                                    "closing superseded pending mesh channel"
                                                );
                                                duplicate.close();
                                            }
                                        } else {
                                            println!("Connected mesh peer {} at {remote}", peer.device_id);
                                            let connector = peer_connectors.remove(&peer.device_id).expect("peer connector exists");
                                            let probe = peer_probes.remove(&peer.device_id).expect("peer probe exists");
                                            connected.push((peer, channel, remote, connector, probe));
                                            first_peer_at.get_or_insert_with(tokio::time::Instant::now);
                                        }
                                    }
                                    None => accept_finished = true,
                                }
                            }
                            result = attempts.join_next(), if !attempts.is_empty() => {
                                let Some(result) = result else { continue; };
                                let (peer, keep_outbound, result) = result?;
                                match result {
                                    Ok(mut connection) => {
                                        tracing::debug!(
                                            peer_id = %peer.device_id,
                                            outbound_elected = keep_outbound,
                                            path = connection.channel.transport_name(),
                                            has_ice_consent = connection.channel.has_ice_consent_monitor(),
                                            "mesh outbound connection completed"
                                        );
                                        let remote = connection.remote;
                                        if let Some(nominated) = connection.nominated_ice_monitor.take()
                                            && let Some((_, old)) = pending_ice_monitors.insert(peer.device_id.clone(), nominated)
                                        {
                                            old.stop().await;
                                        }
                                        let mut channel = connection.channel;
                                        if !keep_outbound && require_ice_consent && channel.transport_name() == "QUIC/UDP" {
                                            if let Some((accepted_peer, mut accepted_channel, accepted_remote)) = pending_accepted_channels.remove(&peer.device_id) {
                                                if accepted_remote == remote && transfer_peer_ice_consent_monitor(&mut channel, &mut accepted_channel) {
                                                    tracing::debug!(
                                                        peer_id = %accepted_peer.device_id,
                                                        path = accepted_channel.transport_name(),
                                                        has_ice_consent = accepted_channel.has_ice_consent_monitor(),
                                                        "selected accepted mesh channel after transferring ICE consent"
                                                    );
                                                    println!("Connected mesh peer {} at {accepted_remote}", accepted_peer.device_id);
                                                    let connector = peer_connectors.remove(&accepted_peer.device_id).expect("peer connector exists");
                                                    let probe = peer_probes.remove(&accepted_peer.device_id).expect("peer probe exists");
                                                    connected.push((accepted_peer, accepted_channel, accepted_remote, connector, probe));
                                                    first_peer_at.get_or_insert_with(tokio::time::Instant::now);
                                                } else {
                                                    tracing::debug!(
                                                        peer_id = %peer.device_id,
                                                        accepted_path = accepted_channel.transport_name(),
                                                        accepted_remote_matches = accepted_remote == remote,
                                                        probe_has_ice_consent = channel.has_ice_consent_monitor(),
                                                        "discarding unmatched accepted ICE channel"
                                                    );
                                                    accepted_channel.close();
                                                    eprintln!("Peer {} direct ICE session had no consent monitor; waiting for reliable fallback", peer.device_id);
                                                }
                                            } else if let Some(monitor) = channel.take_ice_consent_monitor() {
                                                channel.close();
                                                pending_ice_monitors.insert(peer.device_id.clone(), (remote, monitor));
                                            } else {
                                                channel.close();
                                                eprintln!("Peer {} direct ICE session had no consent monitor; waiting for reliable fallback", peer.device_id);
                                            }
                                        } else if mesh_channel_is_elected(
                                            keep_outbound,
                                            channel.transport_name(),
                                        ) {
                                            if connected.iter().any(|known| known.0.device_id == peer.device_id) {
                                                tracing::debug!(
                                                    peer_id = %peer.device_id,
                                                    path = channel.transport_name(),
                                                    reason = "peer_path_already_connected",
                                                    "closing duplicate outbound mesh channel"
                                                );
                                                channel.close();
                                            } else {
                                                println!("Connected mesh peer {} at {remote}", peer.device_id);
                                                let connector = peer_connectors.remove(&peer.device_id).expect("peer connector exists");
                                                let probe = peer_probes.remove(&peer.device_id).expect("peer probe exists");
                                                connected.push((peer, channel, remote, connector, probe));
                                                first_peer_at.get_or_insert_with(tokio::time::Instant::now);
                                            }
                                        } else {
                                            // This authenticated reverse connection opened the
                                            // NAT mapping; keep the elected inbound session instead.
                                            tracing::debug!(
                                                peer_id = %peer.device_id,
                                                path = channel.transport_name(),
                                                outbound_elected = keep_outbound,
                                                reason = "outbound_path_lost_deterministic_election",
                                                "closing non-elected outbound mesh channel"
                                            );
                                            channel.close();
                                        }
                                    }
                                    Err(error) => eprintln!("Peer {} UDP probe unavailable: {error}", peer.device_id),
                                }
                            }
                            _ = tokio::time::sleep_until(settle_deadline), if first_peer_at.is_some() => break,
                            _ = tokio::time::sleep_until(startup_deadline), if first_peer_at.is_none() => break,
                        }
                    }
                    for (device_id, (peer, mut channel, remote)) in
                        pending_accepted_channels.drain()
                    {
                        if let Some((nominated_remote, monitor)) =
                            pending_ice_monitors.remove(&device_id)
                            && attach_nominated_ice_monitor(&mut channel, nominated_remote, monitor)
                                .await
                        {
                            install_mesh_peer_channel(
                                &mut connected,
                                peer,
                                channel,
                                remote,
                                &mut peer_connectors,
                                &mut peer_probes,
                            );
                            continue;
                        }
                        channel.close();
                    }
                    for (_, (_, monitor)) in pending_ice_monitors.drain() {
                        monitor.stop().await;
                    }
                    if connected.is_empty() {
                        println!(
                            "No mesh peers are connected yet; waiting for membership updates."
                        );
                    }
                    let tun = create_tun(&network_id, local_ipv4, prefix_len, mtu)?;
                    endpoint.exclude_tun_interface(&tun)?;
                    let initially_connected = connected
                        .iter()
                        .map(|(peer, _, _, _, _)| peer.clone())
                        .collect::<Vec<_>>();
                    let (mesh_updates_tx, mesh_updates_rx) = tokio::sync::mpsc::channel(64);
                    let registry =
                        std::sync::Arc::new(tokio::sync::RwLock::new(accepted_peer_senders));
                    let accepted_registry = std::sync::Arc::clone(&registry);
                    let accepted_dispatcher = tokio::spawn(async move {
                        while let Some((peer, channel, _remote)) = accepted_rx.recv().await {
                            let registry = accepted_registry.read().await;
                            if let Some(sender) = registry.get(&peer.device_id) {
                                let path = channel.transport_name();
                                tracing::debug!(
                                    peer_id = %peer.device_id,
                                    path,
                                    has_ice_consent = channel.has_ice_consent_monitor(),
                                    "dispatching accepted mesh channel to peer connector"
                                );
                                if let Err(error) = sender.try_send(channel) {
                                    let reason = if matches!(
                                        &error,
                                        tokio::sync::mpsc::error::TrySendError::Full(_)
                                    ) {
                                        "peer_accept_queue_full"
                                    } else {
                                        "peer_accept_queue_closed"
                                    };
                                    tracing::debug!(
                                        peer_id = %peer.device_id,
                                        path,
                                        reason,
                                        "closing accepted mesh channel that could not be dispatched"
                                    );
                                    error.into_inner().close();
                                }
                            } else {
                                tracing::debug!(
                                    peer_id = %peer.device_id,
                                    path = channel.transport_name(),
                                    reason = "peer_accept_queue_missing",
                                    "closing accepted mesh channel without a peer dispatcher"
                                );
                                channel.close();
                            }
                        }
                    });
                    let refresh = spawn_mesh_membership_refresh(MeshMembershipRefresh {
                        coordinator_url: coordinator_url.clone(),
                        network_id: network_id.clone(),
                        identity: std::sync::Arc::clone(&identity),
                        endpoint: endpoint.clone(),
                        relay_endpoints,
                        snapshot_tx,
                        allowlist_tx,
                        registry,
                        updates_tx: mesh_updates_tx,
                        initial_peers: initially_connected,
                    });
                    let result =
                        run_peer_mesh(&tun, &network_id, connected, manage_route, mesh_updates_rx)
                            .await;
                    refresh.abort();
                    accepted_dispatcher.abort();
                    for task in accept_tasks {
                        task.abort();
                    }
                    result?;
                }
            },
            PeerCommand::Status { url } => {
                let response = reqwest::get(format!("{}/status", url.trim_end_matches('/')))
                    .await?
                    .error_for_status()?;
                let peers: Vec<mini_tunnel_agent::status::PeerStatus> = response.json().await?;
                println!("{}", serde_json::to_string_pretty(&peers)?);
            }
            PeerCommand::Connect {
                bind,
                network_id,
                peer_id,
                message,
                coordinator_url,
            } => {
                let identity = mini_tunnel_agent::Identity::load_or_create()?;
                let device_id = identity.device_id();
                let timestamp_ms = now_ms()?;
                let request = PeerListRequest {
                    device_id: device_id.clone(),
                    timestamp_ms,
                    signature: identity.sign(&peers_signing_bytes(
                        &network_id,
                        &device_id,
                        timestamp_ms,
                    )),
                };
                let path = format!("/v1/networks/{network_id}/peers");
                let snapshot: PeerListResponse =
                    post_json(&coordinator_url, &path, &request).await?;
                let peer = snapshot
                    .peers
                    .into_iter()
                    .find(|peer| peer.device_id == peer_id)
                    .ok_or("peer is not present in the signed same-network snapshot")?;
                let peer_key = decode_peer_key(&peer.public_key)?;
                let endpoint = mini_tunnel_agent::peer_endpoint(&identity, bind)?;
                let (channel, remote) = mini_tunnel_agent::connect_peer_candidates(
                    &endpoint,
                    &peer.candidates,
                    &network_id,
                    &identity,
                    &peer.device_id,
                    peer_key,
                )
                .await?;
                channel.send_packet(message.as_bytes()).await?;
                println!(
                    "Connected to {} at {} and sent authenticated packet ({} bytes)",
                    peer.device_id,
                    remote,
                    message.len()
                );
                endpoint.close(0_u32.into(), b"diagnostic complete");
            }
            PeerCommand::Listen {
                bind,
                network_id,
                peer_id,
                peer_key,
            } => {
                let identity = mini_tunnel_agent::Identity::load_or_create()?;
                let peer_key = decode_peer_key(&peer_key)?;
                let endpoint = mini_tunnel_agent::peer_endpoint(&identity, bind)?;
                println!("Listening on {}", endpoint.local_addr()?);
                let channel = mini_tunnel_agent::accept_peer(
                    &endpoint,
                    &network_id,
                    &identity,
                    &peer_id,
                    peer_key,
                )
                .await?;
                let packet =
                    receive_and_echo_peer_diagnostic(&channel, PEER_DIAGNOSTIC_TIMEOUT).await?;
                println!(
                    "Received and echoed authenticated datagram ({} bytes)",
                    packet.len()
                );
            }
            PeerCommand::Send {
                bind,
                remote,
                network_id,
                peer_id,
                peer_key,
                message,
            } => {
                let identity = mini_tunnel_agent::Identity::load_or_create()?;
                let peer_key = decode_peer_key(&peer_key)?;
                let endpoint = mini_tunnel_agent::peer_endpoint(&identity, bind)?;
                let channel = mini_tunnel_agent::connect_peer(
                    &endpoint,
                    remote,
                    &network_id,
                    &identity,
                    &peer_id,
                    peer_key,
                )
                .await?;
                send_peer_diagnostic_and_wait_for_echo(&channel, message.as_bytes()).await?;
                println!(
                    "Peer confirmed authenticated datagram ({} bytes)",
                    message.len()
                );
            }
        },
        Command::Network { command } => match command {
            NetworkCommand::Create {
                name,
                cidr,
                coordinator_url,
            } => {
                let request = CreateNetworkRequest { name, cidr };
                let response: CreateNetworkResponse =
                    post_json(&coordinator_url, "/v1/networks", &request).await?;
                println!("Network: {} ({})", response.name, response.network_id);
                println!("IPv4 range: {}", response.cidr);
                println!(
                    "Admin token (save now; shown once): {}",
                    response.admin_token
                );
            }
            NetworkCommand::Invite {
                network_id,
                coordinator_url,
            } => {
                let admin_token = std::env::var("MINI_TUNNEL_ADMIN_TOKEN")
                    .map_err(|_| "set MINI_TUNNEL_ADMIN_TOKEN before issuing an invite")?;
                let request = CreateInviteRequest { admin_token };
                let path = format!("/v1/networks/{network_id}/invites");
                let response: CreateInviteResponse =
                    post_json(&coordinator_url, &path, &request).await?;
                println!(
                    "Invite token (one device, expires in {} seconds): {}",
                    response.expires_in_seconds, response.invite_token
                );
            }
            NetworkCommand::Revoke {
                network_id,
                device_id,
                coordinator_url,
            } => {
                let admin_token = std::env::var("MINI_TUNNEL_ADMIN_TOKEN")
                    .map_err(|_| "set MINI_TUNNEL_ADMIN_TOKEN before revoking a member")?;
                let request = RevokeMemberRequest {
                    admin_token,
                    device_id: device_id.clone(),
                };
                let path = format!("/v1/networks/{network_id}/members/revoke");
                let response: RevokeMemberResponse =
                    post_json(&coordinator_url, &path, &request).await?;
                println!(
                    "Revoked device {device_id}; released IPv4 {}",
                    response.released_ipv4
                );
            }
            NetworkCommand::Join {
                network_id,
                device_id,
                coordinator_url,
            } => {
                let invite_token = std::env::var("MINI_TUNNEL_INVITE_TOKEN")
                    .map_err(|_| "set MINI_TUNNEL_INVITE_TOKEN before joining")?;
                let identity = mini_tunnel_agent::Identity::load_or_create()?;
                let device_id = device_id.unwrap_or_else(|| identity.device_id());
                if device_id != identity.device_id() {
                    return Err("device_id must match this device's public key".into());
                }
                let public_key = identity.public_key();
                let signature = identity.sign(&join_signing_bytes(
                    &network_id,
                    &device_id,
                    &public_key,
                    &invite_token,
                ));
                let request = JoinNetworkRequest {
                    invite_token,
                    device_id,
                    public_key: URL_SAFE_NO_PAD.encode(public_key),
                    signature,
                };
                let path = format!("/v1/networks/{network_id}/join");
                let response: JoinNetworkResponse =
                    post_json(&coordinator_url, &path, &request).await?;
                let membership = mini_tunnel_agent::membership::NetworkMembership::new(
                    response.network_id.clone(),
                    response.device_id.clone(),
                    response.assigned_ipv4.clone(),
                    response.cidr.clone(),
                )?;
                mini_tunnel_agent::membership::MembershipStore::for_current_user()?
                    .save(&membership)
                    .map_err(|error| {
                        format!("joined the network, but couldn't save local membership: {error}")
                    })?;
                println!("Joined network {}", response.network_id);
                println!("Device: {}", response.device_id);
                println!("Virtual IPv4: {}/{}", response.assigned_ipv4, response.cidr);
                if let Some(address) = mini_tunnel_protocol::overlay_ipv6_address(
                    &response.network_id,
                    response.assigned_ipv4.parse()?,
                ) {
                    println!("Virtual IPv6: {address}/64");
                }
            }
            NetworkCommand::Advertise {
                network_id,
                mut candidates,
                coordinator_url,
            } => {
                candidates.sort();
                let identity = mini_tunnel_agent::Identity::load_or_create()?;
                let timestamp_ms = now_ms()?;
                let request = CandidateUpdateRequest {
                    device_id: identity.device_id(),
                    timestamp_ms,
                    candidates: candidates.clone(),
                    ice_credentials: None,
                    signature: identity.sign(&candidate_signing_bytes(
                        &network_id,
                        &identity.device_id(),
                        timestamp_ms,
                        &candidates,
                    )),
                };
                let path = format!("/v1/networks/{network_id}/candidates");
                let _: CandidateUpdateResponse =
                    post_json(&coordinator_url, &path, &request).await?;
                println!("Published {} candidate address(es)", candidates.len());
            }
            NetworkCommand::Peers {
                network_id,
                coordinator_url,
            } => {
                let identity = mini_tunnel_agent::Identity::load_or_create()?;
                let timestamp_ms = now_ms()?;
                let device_id = identity.device_id();
                let request = PeerListRequest {
                    device_id: device_id.clone(),
                    timestamp_ms,
                    signature: identity.sign(&peers_signing_bytes(
                        &network_id,
                        &device_id,
                        timestamp_ms,
                    )),
                };
                let path = format!("/v1/networks/{network_id}/peers");
                let response: PeerListResponse =
                    post_json(&coordinator_url, &path, &request).await?;
                for peer in response.peers {
                    println!(
                        "{} {} key={} candidates={}",
                        peer.device_id,
                        peer.assigned_ipv4,
                        peer.public_key,
                        peer.candidates.join(",")
                    );
                }
            }
            NetworkCommand::Diagnose {
                network_id,
                coordinator_url,
            } => {
                let identity = mini_tunnel_agent::Identity::load_or_create()?;
                let timestamp_ms = now_ms()?;
                let device_id = identity.device_id();
                let request = PeerListRequest {
                    device_id: device_id.clone(),
                    timestamp_ms,
                    signature: identity.sign(&peers_signing_bytes(
                        &network_id,
                        &device_id,
                        timestamp_ms,
                    )),
                };
                let path = format!("/v1/networks/{network_id}/peers");
                let response: PeerListResponse =
                    post_json(&coordinator_url, &path, &request).await?;
                println!("Coordinator peer discovery: reachable");
                println!("Local device: {device_id}");
                print!("{}", format_peer_diagnostics(&response.peers));
                println!(
                    "Candidate presence does not prove reachability or report an active tunnel path."
                );
            }
        },
    }
    Ok(())
}

async fn receive_and_echo_peer_diagnostic(
    channel: &mini_tunnel_agent::PeerChannel,
    linger: Duration,
) -> Result<Vec<u8>, mini_tunnel_agent::IdentityError> {
    let packet = tokio::time::timeout(PEER_DIAGNOSTIC_TIMEOUT, channel.recv_packet())
        .await
        .map_err(|_| {
            mini_tunnel_agent::IdentityError::Transport(
                "peer diagnostic receive timed out".to_owned(),
            )
        })??;
    channel.send_packet(&packet).await?;
    tokio::time::sleep(linger).await;
    Ok(packet)
}

async fn send_peer_diagnostic_and_wait_for_echo(
    channel: &mini_tunnel_agent::PeerChannel,
    message: &[u8],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    channel.send_packet(message).await?;
    let echoed = tokio::time::timeout(PEER_DIAGNOSTIC_TIMEOUT, channel.recv_packet()).await??;
    if echoed != message {
        return Err("peer diagnostic echo did not match the sent message".into());
    }
    channel.close();
    Ok(())
}

fn format_peer_diagnostics(peers: &[PeerInfo]) -> String {
    let mut output = format!("Same-network peers: {}\n", peers.len());
    if peers.is_empty() {
        output.push_str("No other enrolled peers were returned.\n");
        return output;
    }
    for peer in peers {
        let tcp_candidates = peer
            .candidates
            .iter()
            .filter(|candidate| candidate.starts_with("tcp://"))
            .count();
        let udp_candidates = peer.candidates.len().saturating_sub(tcp_candidates);
        output.push_str(&format!(
            "Peer {} ({}): UDP candidates={}, TCP candidates={}, ICE credentials={}\n",
            peer.device_id,
            peer.assigned_ipv4,
            udp_candidates,
            tcp_candidates,
            if peer.ice_credentials.is_some() {
                "published"
            } else {
                "missing"
            }
        ));
    }
    output
}

fn decode_peer_key(encoded: &str) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
    use base64::Engine as _;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)?
        .try_into()
        .map_err(|_| "peer key must decode to exactly 32 bytes")?)
}

fn now_ms() -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis()
        .try_into()?)
}

async fn shutdown_signal() -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        let terminate_received = async move {
            terminate.recv().await;
            Ok(())
        };
        select_shutdown_signal(tokio::signal::ctrl_c(), terminate_received).await
    }
    #[cfg(not(unix))]
    {
        select_shutdown_signal(
            tokio::signal::ctrl_c(),
            std::future::pending::<std::io::Result<()>>(),
        )
        .await
    }
}

async fn select_shutdown_signal<C, T>(ctrl_c: C, terminate: T) -> std::io::Result<()>
where
    C: Future<Output = std::io::Result<()>>,
    T: Future<Output = std::io::Result<()>>,
{
    tokio::select! {
        result = ctrl_c => result,
        result = terminate => result,
    }
}

async fn wait_reconnect(attempt: u32) -> bool {
    let delay = mini_tunnel_agent::reconnect_delay(attempt);
    eprintln!("Retrying peer connection in {:.2}s", delay.as_secs_f32());
    tokio::select! {
        _ = shutdown_signal() => false,
        _ = tokio::time::sleep(delay) => true,
    }
}

async fn post_json<Request, Response>(
    base_url: &str,
    path: &str,
    request: &Request,
) -> Result<Response, Box<dyn std::error::Error + Send + Sync>>
where
    Request: serde::Serialize + ?Sized,
    Response: for<'de> Deserialize<'de>,
{
    let url = format!("{}{path}", base_url.trim_end_matches('/'));
    let response = coordinator_http_client(Duration::from_secs(5))?
        .post(url)
        .json(request)
        .send()
        .await?;
    let status = response.status();
    if status.is_success() {
        return Ok(response.json::<Response>().await?);
    }
    let error = response
        .json::<ApiErrorResponse>()
        .await
        .unwrap_or(ApiErrorResponse {
            error: "http_error".to_owned(),
            message: format!("coordinator returned HTTP {status}"),
        });
    Err(Box::new(CoordinatorApiError {
        code: error.error,
        message: error.message,
    }))
}

fn coordinator_http_client(
    timeout: Duration,
) -> Result<reqwest::Client, Box<dyn std::error::Error + Send + Sync>> {
    let ca_bundle_path = std::env::var_os(COORDINATOR_CA_CERT_FILE_ENV).map(PathBuf::from);
    coordinator_http_client_with_ca_bundle(timeout, ca_bundle_path.as_deref())
}

fn coordinator_http_client_with_ca_bundle(
    timeout: Duration,
    ca_bundle_path: Option<&Path>,
) -> Result<reqwest::Client, Box<dyn std::error::Error + Send + Sync>> {
    let mut builder = reqwest::Client::builder().timeout(timeout);
    if let Some(ca_bundle_path) = ca_bundle_path {
        let certificates = read_coordinator_ca_bundle(ca_bundle_path)?;
        builder = builder.tls_certs_merge(certificates);
    }
    Ok(builder.build()?)
}

fn read_coordinator_ca_bundle(path: &Path) -> Result<Vec<reqwest::Certificate>, io::Error> {
    let file = File::open(path).map_err(|error| {
        io::Error::new(
            error.kind(),
            "could not open Coordinator CA certificate bundle",
        )
    })?;
    let metadata = file.metadata().map_err(|error| {
        io::Error::new(
            error.kind(),
            "could not inspect Coordinator CA certificate bundle",
        )
    })?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Coordinator CA certificate bundle must be a regular file",
        ));
    }
    if metadata.len() > MAX_COORDINATOR_CA_BUNDLE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Coordinator CA certificate bundle exceeds the 1 MiB limit",
        ));
    }

    let mut contents = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_COORDINATOR_CA_BUNDLE_BYTES + 1)
        .read_to_end(&mut contents)
        .map_err(|error| {
            io::Error::new(
                error.kind(),
                "could not read Coordinator CA certificate bundle",
            )
        })?;
    if contents.len() as u64 > MAX_COORDINATOR_CA_BUNDLE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Coordinator CA certificate bundle exceeds the 1 MiB limit",
        ));
    }
    if contents.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Coordinator CA certificate bundle is empty",
        ));
    }

    let certificates = reqwest::Certificate::from_pem_bundle(&contents).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Coordinator CA certificate bundle is not valid PEM",
        )
    })?;
    if certificates.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Coordinator CA certificate bundle contains no certificates",
        ));
    }
    Ok(certificates)
}

#[derive(Debug)]
struct CoordinatorApiError {
    code: String,
    message: String,
}

impl std::fmt::Display for CoordinatorApiError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for CoordinatorApiError {}

struct PeerSessionControl<'a> {
    coordinator_url: &'a str,
    network_id: &'a str,
    identity: &'a mini_tunnel_agent::Identity,
}

struct PeerSessionRuntime<'a> {
    channel: std::sync::Arc<mini_tunnel_agent::PeerChannel>,
    peer: &'a PeerInfo,
    remote: SocketAddr,
    connector: mini_tunnel_agent::tunnel::PeerConnector,
    probe: mini_tunnel_agent::tunnel::PeerConnector,
    accept_tasks: Vec<tokio::task::JoinHandle<()>>,
}

type PeerPacketPump<'a> = std::pin::Pin<
    Box<
        dyn std::future::Future<Output = Result<(), mini_tunnel_agent::tunnel::PeerTunnelError>>
            + Send
            + 'a,
    >,
>;

struct AbortTasksOnDrop(Vec<tokio::task::JoinHandle<()>>);

impl Drop for AbortTasksOnDrop {
    fn drop(&mut self) {
        for task in &self.0 {
            task.abort();
        }
    }
}

async fn run_peer_tunnel(
    tun: &mini_tunnel_agent::tun_device::TunDevice,
    control: PeerSessionControl<'_>,
    session: PeerSessionRuntime<'_>,
    manage_route: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use mini_tunnel_agent::routing::{
        RouteLease, RoutingPlatform, SystemRouteRunner, install_peer_ipv6_route, install_peer_route,
    };

    let PeerSessionRuntime {
        channel,
        peer,
        remote,
        connector,
        probe,
        accept_tasks,
    } = session;
    let mut accept_tasks = AbortTasksOnDrop(accept_tasks);
    let peer_ipv4 = peer.assigned_ipv4.parse()?;
    let peer_ipv6 = mini_tunnel_protocol::overlay_ipv6_address(control.network_id, peer_ipv4)
        .ok_or("could not derive peer IPv6 overlay address")?;
    let runner = SystemRouteRunner;
    let (route, route_v6): (Option<RouteLease>, Option<RouteLease>) = if manage_route {
        let interface = tun.name()?;
        let route =
            install_peer_route(&runner, RoutingPlatform::current(), &interface, peer_ipv4).await?;
        match install_peer_ipv6_route(&runner, RoutingPlatform::current(), &interface, peer_ipv6)
            .await
        {
            Ok(route_v6) => (Some(route), Some(route_v6)),
            Err(error) => {
                let _ = route.remove(&runner).await;
                return Err(error.into());
            }
        }
    } else {
        (None, None)
    };
    print_tunnel_ready(
        tun,
        peer,
        control.network_id,
        remote,
        channel.transport_name(),
        manage_route,
    );
    let (shutdown_tx, shutdown_rx) = tokio::sync::mpsc::channel(1);
    let pump: PeerPacketPump<'_> = Box::pin(mini_tunnel_agent::tunnel::pump_peer_mesh_dynamic(
        tun,
        vec![mini_tunnel_agent::tunnel::ReconnectingPeer {
            address: peer_ipv4,
            ipv6_address: Some(peer_ipv6),
            channel: std::sync::Arc::clone(&channel),
            connector,
            probe: Some(probe),
            probe_cooldown: Duration::from_secs(60),
        }],
        shutdown_rx,
    ));
    tokio::pin!(pump);
    let revocation = wait_for_peer_revocation(
        control.coordinator_url.to_owned(),
        control.network_id.to_owned(),
        peer.device_id.clone(),
        control.identity,
    );
    tokio::pin!(revocation);
    let tunnel_result: Result<(), Box<dyn std::error::Error + Send + Sync>> = tokio::select! {
        result = &mut pump => result.map_err(Into::into),
        signal = shutdown_signal() => {
            let result = signal.map_err(Into::into);
            let _ = shutdown_tx.send(mini_tunnel_agent::tunnel::MeshPeerUpdate::Remove(peer_ipv4)).await;
            drop(shutdown_tx);
            let _ = (&mut pump).await;
            result
        },
        () = &mut revocation => {
            tracing::warn!(peer_id = %peer.device_id, "peer authorization was revoked; closing tunnel");
            let shutdown_tx = shutdown_tx;
            let _ = shutdown_tx.send(mini_tunnel_agent::tunnel::MeshPeerUpdate::Remove(peer_ipv4)).await;
            drop(shutdown_tx);
            let _ = (&mut pump).await;
            Ok(())
        },
    };
    let mut cleanup_error = None;
    if let Some(route_v6) = route_v6
        && let Err(error) = route_v6.remove(&runner).await
    {
        cleanup_error = Some(error);
    }
    if let Some(route) = route
        && let Err(error) = route.remove(&runner).await
    {
        cleanup_error.get_or_insert(error);
    }
    if let Some(error) = cleanup_error {
        return Err(error.into());
    }
    for task in accept_tasks.0.drain(..) {
        task.abort();
        let _ = task.await;
    }
    tunnel_result
}

#[derive(Debug, Clone, Copy, Default)]
struct RelayEndpoints {
    tcp: Option<SocketAddr>,
    udp: Option<SocketAddr>,
}

fn mesh_reconnect_direct_wait(relay_endpoints: RelayEndpoints, force_reliable: bool) -> Duration {
    if force_reliable && relay_endpoints.tcp.is_some() {
        // Both peers commonly request fallback together. Keep this accept grace
        // short so they do not wait in lockstep before pairing their relay tickets.
        Duration::from_millis(250)
            .min(mini_tunnel_relay::DEFAULT_PAIR_TIMEOUT.saturating_sub(Duration::from_millis(250)))
    } else if !force_reliable && relay_endpoints.udp.is_some() {
        Duration::from_secs(10)
    } else if force_reliable {
        Duration::from_secs(35)
    } else {
        Duration::from_secs(65)
    }
}

async fn connect_tunnel_peer(
    endpoint: &TunnelEndpoint,
    peer: &PeerInfo,
    network_id: &str,
    identity: &mini_tunnel_agent::Identity,
    peer_key: [u8; 32],
    relay_endpoints: RelayEndpoints,
    coordinator_url: &str,
) -> Result<(mini_tunnel_agent::PeerChannel, SocketAddr), mini_tunnel_agent::IdentityError> {
    if let Some((remote, monitor)) = select_ice_peer_address(endpoint, peer, identity).await {
        match mini_tunnel_agent::connect_peer(
            &endpoint.endpoint,
            remote,
            network_id,
            identity,
            &peer.device_id,
            peer_key,
        )
        .await
        {
            Ok(mut channel) => {
                channel.set_ice_consent_monitor(monitor);
                return Ok((channel, remote));
            }
            Err(mini_tunnel_agent::IdentityError::UnauthorizedPeer) => {
                monitor.stop().await;
                return Err(mini_tunnel_agent::IdentityError::UnauthorizedPeer);
            }
            Err(error) => {
                monitor.stop().await;
                eprintln!("ICE selected {remote}, retrying advertised candidates: {error}")
            }
        }
    }
    let direct_result = mini_tunnel_agent::connect_peer_candidates(
        &endpoint.endpoint,
        &peer.candidates,
        network_id,
        identity,
        &peer.device_id,
        peer_key,
    )
    .await;
    match direct_result {
        Ok(connection) => Ok(connection),
        Err(mini_tunnel_agent::CandidateConnectError::UnauthorizedPeer) => {
            Err(mini_tunnel_agent::IdentityError::UnauthorizedPeer)
        }
        Err(direct_error) => {
            let channel = if let Some(relay) = relay_endpoints.udp {
                match connect_peer_via_udp_relay(relay, coordinator_url, network_id, identity, peer)
                    .await
                {
                    Ok(channel) => channel,
                    Err(udp_error) => {
                        tracing::warn!(%udp_error, "UDP relay failed; trying TCP relay");
                        if let Some(relay) = relay_endpoints.tcp {
                            connect_peer_via_relay(
                                relay,
                                coordinator_url,
                                network_id,
                                identity,
                                peer,
                            )
                            .await?
                        } else {
                            return Err(udp_error);
                        }
                    }
                }
            } else if let Some(relay) = relay_endpoints.tcp {
                connect_peer_via_relay(relay, coordinator_url, network_id, identity, peer).await?
            } else {
                return Err(mini_tunnel_agent::IdentityError::Transport(
                    direct_error.to_string(),
                ));
            };
            let remote = channel.remote_address();
            Ok((channel, remote))
        }
    }
}

async fn select_ice_peer_address(
    endpoint: &TunnelEndpoint,
    peer: &PeerInfo,
    identity: &mini_tunnel_agent::Identity,
) -> Option<(SocketAddr, mini_tunnel_agent::ice::IceConsentMonitor)> {
    select_ice_peer_address_with_timeout(endpoint, peer, identity, Duration::from_secs(5)).await
}

async fn select_ice_peer_address_with_timeout(
    endpoint: &TunnelEndpoint,
    peer: &PeerInfo,
    identity: &mini_tunnel_agent::Identity,
    check_timeout: Duration,
) -> Option<(SocketAddr, mini_tunnel_agent::ice::IceConsentMonitor)> {
    let local = endpoint.ice.as_ref()?;
    let remote = peer.ice_credentials.as_ref()?;
    let remote_candidates = udp_ice_candidates(&peer.candidates);
    let local_candidates = local.local_candidates.read().await.clone();
    if remote_candidates.is_empty() || local_candidates.is_empty() {
        return None;
    }
    let mut datagrams = match local.router.register(
        local.credentials.ufrag.clone(),
        remote.ufrag.clone(),
        32,
    ) {
        Ok(datagrams) => datagrams,
        Err(error) => {
            tracing::warn!(peer_id = %peer.device_id, %error, "could not start peer ICE session");
            return None;
        }
    };
    let local_ufrag = local.credentials.ufrag.clone();
    let controlling = identity.device_id() < peer.device_id;
    let mut driver =
        match mini_tunnel_agent::ice::IceAgentDriver::for_peer_with_candidates_on_socket(
            local.local_socket_addr,
            &local.credentials,
            remote,
            &local_candidates,
            &remote_candidates,
            controlling,
            std::time::Instant::now(),
        ) {
            Ok(driver) => driver,
            Err(error) => {
                let _ = local.router.unregister(&local_ufrag, &remote.ufrag);
                tracing::debug!(peer_id = %peer.device_id, %error, "could not initialize ICE checks");
                return None;
            }
        };
    let nominated = driver
        .run_checks(
            &local.socket,
            &local.router,
            &local_ufrag,
            &remote.ufrag,
            &mut datagrams,
            check_timeout,
        )
        .await
        .map(|(_, remote)| remote);
    match nominated {
        Ok(remote_address) => {
            tracing::info!(peer_id = %peer.device_id, remote = %remote_address, "ICE nominated a direct peer path");
            let socket = local.socket.clone();
            let router = local.router.clone();
            let local_ufrag = local_ufrag.clone();
            let remote_ufrag = remote.ufrag.clone();
            let (monitor, cancel, failure_sender) =
                mini_tunnel_agent::ice::IceConsentMonitor::new();
            let degraded_sender = monitor.degraded_sender();
            let mut signals =
                mini_tunnel_agent::ice::IceConsentSignals::new(cancel, degraded_sender);
            let task = tokio::spawn(async move {
                tracing::debug!("ICE consent monitor started");
                if let Err(error) = driver
                    .monitor_consent(
                        &socket,
                        &router,
                        &local_ufrag,
                        &remote_ufrag,
                        &mut datagrams,
                        &mut signals,
                    )
                    .await
                {
                    tracing::warn!(%error, "nominated ICE consent expired");
                    failure_sender.send_replace(true);
                } else {
                    tracing::debug!("ICE consent monitor stopped");
                }
                let _ = router.unregister(&local_ufrag, &remote_ufrag);
            });
            monitor.set_task(task).await;
            Some((remote_address, monitor))
        }
        Err(error) => {
            let _ = local.router.unregister(&local_ufrag, &remote.ufrag);
            tracing::debug!(peer_id = %peer.device_id, %error, "ICE checks failed; using transport fallback");
            None
        }
    }
}

/// A peer list can race another agent's startup credential publication. If that happens, the
/// first checklist uses the peer's previous ufrag and cannot authenticate its checks. Refresh
/// once after a failed initial checklist and retry only when the peer snapshot actually changed.
async fn select_ice_peer_address_with_snapshot_refresh(
    endpoint: &TunnelEndpoint,
    coordinator_url: &str,
    network_id: &str,
    peer: &mut PeerInfo,
    identity: &mini_tunnel_agent::Identity,
    check_timeout: Duration,
) -> Option<(SocketAddr, mini_tunnel_agent::ice::IceConsentMonitor)> {
    if let Some(selected) =
        select_ice_peer_address_with_timeout(endpoint, peer, identity, check_timeout).await
    {
        return Some(selected);
    }
    endpoint.ice.as_ref()?;

    let previous_credentials = peer.ice_credentials.clone();
    let previous_candidates = peer.candidates.clone();
    let refreshed = refresh_peer_snapshot_for_ice(coordinator_url, network_id, peer, identity)
        .await
        .ok()?;
    if refreshed.ice_credentials == previous_credentials
        && refreshed.candidates == previous_candidates
    {
        return None;
    }

    tracing::debug!(
        peer_id = %peer.device_id,
        "peer ICE snapshot changed during initial checks; retrying with refreshed credentials and candidates"
    );
    *peer = refreshed;
    select_ice_peer_address_with_timeout(endpoint, peer, identity, check_timeout).await
}

async fn refresh_peer_snapshot_for_ice(
    coordinator_url: &str,
    network_id: &str,
    expected_peer: &PeerInfo,
    identity: &mini_tunnel_agent::Identity,
) -> Result<PeerInfo, Box<dyn std::error::Error + Send + Sync>> {
    let current = discover_peer(
        coordinator_url,
        network_id,
        &expected_peer.device_id,
        identity,
    )
    .await?;
    if current.public_key != expected_peer.public_key
        || current.assigned_ipv4 != expected_peer.assigned_ipv4
    {
        return Err("peer identity or overlay address changed during ICE recovery".into());
    }
    Ok(current)
}

async fn select_current_ice_peer_address(
    endpoint: &TunnelEndpoint,
    coordinator_url: &str,
    network_id: &str,
    expected_peer: &PeerInfo,
    identity: &mini_tunnel_agent::Identity,
) -> Option<(SocketAddr, mini_tunnel_agent::ice::IceConsentMonitor)> {
    match refresh_peer_snapshot_for_ice(coordinator_url, network_id, expected_peer, identity).await
    {
        Ok(current) => select_ice_peer_address(endpoint, &current, identity).await,
        Err(error) => {
            tracing::warn!(peer_id = %expected_peer.device_id, %error, "could not refresh peer credentials for ICE recovery");
            None
        }
    }
}

struct MeshPeerConnection {
    channel: mini_tunnel_agent::PeerChannel,
    remote: SocketAddr,
    nominated_ice_monitor: Option<(SocketAddr, mini_tunnel_agent::ice::IceConsentMonitor)>,
}

async fn connect_mesh_peer(
    endpoint: &TunnelEndpoint,
    network_id: &str,
    coordinator_url: &str,
    identity: &mini_tunnel_agent::Identity,
    peer: &PeerInfo,
    relay_endpoints: RelayEndpoints,
    reliable_only: bool,
) -> Result<MeshPeerConnection, mini_tunnel_agent::IdentityError> {
    let mut peer = peer.clone();
    if let Ok(current) = discover_peer(coordinator_url, network_id, &peer.device_id, identity).await
    {
        if current.public_key != peer.public_key || current.assigned_ipv4 != peer.assigned_ipv4 {
            return Err(mini_tunnel_agent::IdentityError::UnauthorizedPeer);
        }
        peer = current;
    }
    for _ in 0..10 {
        if !peer.candidates.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
        peer = discover_peer(coordinator_url, network_id, &peer.device_id, identity)
            .await
            .map_err(|error| mini_tunnel_agent::IdentityError::Transport(error.to_string()))?;
    }
    let peer_key = decode_peer_key(&peer.public_key)
        .map_err(|_| mini_tunnel_agent::IdentityError::UnauthorizedPeer)?;
    let mut nominated_ice_monitor = None;
    let initial_ice_selection = if reliable_only {
        None
    } else {
        select_ice_peer_address_with_snapshot_refresh(
            endpoint,
            coordinator_url,
            network_id,
            &mut peer,
            identity,
            Duration::from_secs(5),
        )
        .await
    };
    if let Some((remote, monitor)) = initial_ice_selection {
        match mini_tunnel_agent::connect_peer(
            &endpoint.endpoint,
            remote,
            network_id,
            identity,
            &peer.device_id,
            peer_key,
        )
        .await
        {
            Ok(mut channel) => {
                channel.set_ice_consent_monitor(monitor);
                return Ok(MeshPeerConnection {
                    channel,
                    remote,
                    nominated_ice_monitor: None,
                });
            }
            Err(mini_tunnel_agent::IdentityError::UnauthorizedPeer) => {
                monitor.stop().await;
                return Err(mini_tunnel_agent::IdentityError::UnauthorizedPeer);
            }
            Err(error) => {
                nominated_ice_monitor = Some((remote, monitor));
                tracing::debug!(peer_id = %peer.device_id, %error, "ICE nominated path failed QUIC setup; trying candidates")
            }
        }
    }
    let candidates = candidates_for_path(&peer.candidates, reliable_only);
    let direct_result = mini_tunnel_agent::connect_peer_candidates(
        &endpoint.endpoint,
        &candidates,
        network_id,
        identity,
        &peer.device_id,
        peer_key,
    )
    .await;
    let direct_result = match direct_result {
        Ok((channel, _remote))
            if endpoint.ice.is_some()
                && channel.transport_name() == "QUIC/UDP"
                && !channel.has_ice_consent_monitor() =>
        {
            channel.close();
            Err(mini_tunnel_agent::CandidateConnectError::Unreachable(
                "ICE-enabled UDP candidate was not nominated and has no consent monitor".into(),
            ))
        }
        result => result,
    };
    match direct_result {
        Ok((mut channel, remote)) => {
            if let Some((nominated_remote, monitor)) = nominated_ice_monitor.take() {
                if channel.transport_name() == "QUIC/UDP" && remote == nominated_remote {
                    channel.set_ice_consent_monitor(monitor);
                } else {
                    nominated_ice_monitor = Some((nominated_remote, monitor));
                }
            }
            Ok(MeshPeerConnection {
                channel,
                remote,
                nominated_ice_monitor,
            })
        }
        Err(direct_error) => {
            if matches!(
                direct_error,
                mini_tunnel_agent::CandidateConnectError::UnauthorizedPeer
            ) {
                return Err(mini_tunnel_agent::IdentityError::UnauthorizedPeer);
            }
            let channel = if !reliable_only && let Some(relay) = relay_endpoints.udp {
                match connect_peer_via_udp_relay(
                    relay,
                    coordinator_url,
                    network_id,
                    identity,
                    &peer,
                )
                .await
                {
                    Ok(channel) => channel,
                    Err(udp_error) => {
                        tracing::warn!(peer_id = %peer.device_id, %udp_error, "UDP relay failed; trying TCP relay");
                        if let Some(relay) = relay_endpoints.tcp {
                            connect_peer_via_relay(
                                relay,
                                coordinator_url,
                                network_id,
                                identity,
                                &peer,
                            )
                            .await?
                        } else {
                            return Err(udp_error);
                        }
                    }
                }
            } else if let Some(relay) = relay_endpoints.tcp {
                connect_peer_via_relay(relay, coordinator_url, network_id, identity, &peer).await?
            } else {
                if let Some((_, monitor)) = nominated_ice_monitor.take() {
                    monitor.stop().await;
                }
                return Err(mini_tunnel_agent::IdentityError::Transport(
                    direct_error.to_string(),
                ));
            };
            let remote = channel.remote_address();
            Ok(MeshPeerConnection {
                channel,
                remote,
                nominated_ice_monitor,
            })
        }
    }
}

fn transfer_peer_ice_consent_monitor(
    probe_channel: &mut mini_tunnel_agent::PeerChannel,
    accepted_channel: &mut mini_tunnel_agent::PeerChannel,
) -> bool {
    let Some(monitor) = probe_channel.take_ice_consent_monitor() else {
        return false;
    };
    accepted_channel.set_ice_consent_monitor(monitor);
    probe_channel.close();
    true
}

async fn attach_nominated_ice_monitor(
    channel: &mut mini_tunnel_agent::PeerChannel,
    nominated_remote: SocketAddr,
    monitor: mini_tunnel_agent::ice::IceConsentMonitor,
) -> bool {
    if channel.transport_name() == "QUIC/UDP" && channel.remote_address() == nominated_remote {
        channel.set_ice_consent_monitor(monitor);
        true
    } else {
        monitor.stop().await;
        false
    }
}

fn install_mesh_peer_channel(
    connected: &mut Vec<(
        PeerInfo,
        mini_tunnel_agent::PeerChannel,
        SocketAddr,
        mini_tunnel_agent::tunnel::PeerConnector,
        mini_tunnel_agent::tunnel::PeerConnector,
    )>,
    peer: PeerInfo,
    channel: mini_tunnel_agent::PeerChannel,
    remote: SocketAddr,
    connectors: &mut std::collections::HashMap<String, mini_tunnel_agent::tunnel::PeerConnector>,
    probes: &mut std::collections::HashMap<String, mini_tunnel_agent::tunnel::PeerConnector>,
) {
    if let Some(index) = connected
        .iter()
        .position(|known| known.0.device_id == peer.device_id)
    {
        if channel.transport_name() == "QUIC/UDP"
            && connected[index].1.transport_name() != "QUIC/UDP"
        {
            let old = std::mem::replace(&mut connected[index].1, channel);
            old.close();
            connected[index].2 = remote;
        } else {
            channel.close();
        }
        return;
    }
    let Some(connector) = connectors.remove(&peer.device_id) else {
        channel.close();
        return;
    };
    let Some(probe) = probes.remove(&peer.device_id) else {
        channel.close();
        return;
    };
    tracing::info!(
        peer_id = %peer.device_id,
        path = channel.transport_name(),
        has_ice_consent = channel.has_ice_consent_monitor(),
        "installing elected mesh peer path"
    );
    println!("Connected mesh peer {} at {remote}", peer.device_id);
    connected.push((peer, channel, remote, connector, probe));
}

fn build_mesh_peer_connectors(
    endpoint: TunnelEndpoint,
    identity: std::sync::Arc<mini_tunnel_agent::Identity>,
    network_id: String,
    coordinator_url: String,
    peer: PeerInfo,
    relay_endpoints: RelayEndpoints,
) -> (
    mini_tunnel_agent::tunnel::PeerConnector,
    mini_tunnel_agent::tunnel::PeerConnector,
    tokio::sync::mpsc::Sender<mini_tunnel_agent::PeerChannel>,
) {
    let keep_outbound = identity.device_id() < peer.device_id;
    let require_ice_consent = endpoint.ice.is_some();
    let (accepted_tx, accepted_rx) =
        tokio::sync::mpsc::channel::<mini_tunnel_agent::PeerChannel>(2);
    let receiver = std::sync::Arc::new(tokio::sync::Mutex::new(accepted_rx));
    let connector: mini_tunnel_agent::tunnel::PeerConnector = if keep_outbound {
        let endpoint = endpoint.clone();
        let identity = std::sync::Arc::clone(&identity);
        let network_id = network_id.clone();
        let coordinator_url = coordinator_url.clone();
        let peer = peer.clone();
        std::sync::Arc::new(
            move |force_reliable| -> mini_tunnel_agent::tunnel::PeerConnectFuture {
                let endpoint = endpoint.clone();
                let identity = std::sync::Arc::clone(&identity);
                let network_id = network_id.clone();
                let coordinator_url = coordinator_url.clone();
                let peer = peer.clone();
                Box::pin(async move {
                    connect_mesh_peer(
                        &endpoint,
                        &network_id,
                        &coordinator_url,
                        &identity,
                        &peer,
                        relay_endpoints,
                        force_reliable,
                    )
                    .await
                    .map(|connection| connection.channel)
                })
            },
        )
    } else {
        let receiver = std::sync::Arc::clone(&receiver);
        let endpoint = endpoint.clone();
        let identity = std::sync::Arc::clone(&identity);
        let coordinator_url = coordinator_url.clone();
        let network_id = network_id.clone();
        let peer = peer.clone();
        std::sync::Arc::new(
            move |force_reliable| -> mini_tunnel_agent::tunnel::PeerConnectFuture {
                let receiver = std::sync::Arc::clone(&receiver);
                let endpoint = endpoint.clone();
                let identity = std::sync::Arc::clone(&identity);
                let coordinator_url = coordinator_url.clone();
                let network_id = network_id.clone();
                let peer = peer.clone();
                Box::pin(async move {
                    let mut monitor = if !force_reliable {
                        select_current_ice_peer_address(
                            &endpoint,
                            &coordinator_url,
                            &network_id,
                            &peer,
                            &identity,
                        )
                        .await
                        .map(|(_, monitor)| monitor)
                    } else {
                        None
                    };
                    if let Some(mut channel) = receive_reconnect_channel(
                        receiver,
                        force_reliable,
                        mesh_reconnect_direct_wait(relay_endpoints, force_reliable),
                        |channel: &mini_tunnel_agent::PeerChannel| {
                            matches!(channel.transport_name(), "TLS/TCP" | "Relay/TLS")
                        },
                    )
                    .await
                    {
                        if let Some(monitor) = monitor.take() {
                            channel.set_ice_consent_monitor(monitor);
                        }
                        return Ok(channel);
                    }
                    if let Some(monitor) = monitor {
                        monitor.stop().await;
                    }
                    if !force_reliable && let Some(relay) = relay_endpoints.udp {
                        match connect_peer_via_udp_relay(
                            relay,
                            &coordinator_url,
                            &network_id,
                            &identity,
                            &peer,
                        )
                        .await
                        {
                            Ok(channel) => Ok(channel),
                            Err(udp_error) => {
                                tracing::warn!(%udp_error, "UDP relay failed; trying TCP relay");
                                if let Some(relay) = relay_endpoints.tcp {
                                    connect_peer_via_relay(
                                        relay,
                                        &coordinator_url,
                                        &network_id,
                                        &identity,
                                        &peer,
                                    )
                                    .await
                                } else {
                                    Err(udp_error)
                                }
                            }
                        }
                    } else if let Some(relay) = relay_endpoints.tcp {
                        connect_peer_via_relay(
                            relay,
                            &coordinator_url,
                            &network_id,
                            &identity,
                            &peer,
                        )
                        .await
                    } else {
                        Err(mini_tunnel_agent::IdentityError::Transport(
                            "timed out waiting for peer redial".to_owned(),
                        ))
                    }
                })
            },
        )
    };

    let probe: mini_tunnel_agent::tunnel::PeerConnector = if keep_outbound {
        let endpoint = endpoint.clone();
        let identity = std::sync::Arc::clone(&identity);
        let network_id = network_id.clone();
        let coordinator_url = coordinator_url.clone();
        let peer = peer.clone();
        std::sync::Arc::new(move |_| -> mini_tunnel_agent::tunnel::PeerConnectFuture {
            let endpoint = endpoint.clone();
            let identity = std::sync::Arc::clone(&identity);
            let network_id = network_id.clone();
            let coordinator_url = coordinator_url.clone();
            let peer = peer.clone();
            Box::pin(async move {
                let connection = match connect_mesh_peer(
                    &endpoint,
                    &network_id,
                    &coordinator_url,
                    &identity,
                    &peer,
                    RelayEndpoints::default(),
                    false,
                )
                .await
                {
                    Ok(connection) => connection,
                    Err(error) => {
                        tracing::warn!(
                            peer_id = %peer.device_id,
                            stage = "outbound_recovery_connection",
                            %error,
                            "direct recovery candidate connection failed"
                        );
                        return Err(error);
                    }
                };
                tracing::debug!(
                    peer_id = %peer.device_id,
                    path = connection.channel.transport_name(),
                    has_ice_consent = connection.channel.has_ice_consent_monitor(),
                    "direct recovery outbound candidate channel established"
                );
                validate_udp_probe(connection.channel, require_ice_consent, &peer.device_id).await
            })
        })
    } else {
        let receiver = std::sync::Arc::clone(&receiver);
        let endpoint = endpoint.clone();
        let identity = std::sync::Arc::clone(&identity);
        let coordinator_url = coordinator_url.clone();
        let network_id = network_id.clone();
        let peer = peer.clone();
        std::sync::Arc::new(move |_| -> mini_tunnel_agent::tunnel::PeerConnectFuture {
            let receiver = std::sync::Arc::clone(&receiver);
            let endpoint = endpoint.clone();
            let identity = std::sync::Arc::clone(&identity);
            let coordinator_url = coordinator_url.clone();
            let network_id = network_id.clone();
            let peer = peer.clone();
            Box::pin(async move {
                let mut monitor = select_current_ice_peer_address(
                    &endpoint,
                    &coordinator_url,
                    &network_id,
                    &peer,
                    &identity,
                )
                .await
                .map(|(_, monitor)| monitor);
                tracing::debug!(
                    peer_id = %peer.device_id,
                    nominated = monitor.is_some(),
                    "direct recovery accepted-side ICE checklist completed"
                );
                let deadline = tokio::time::Instant::now() + Duration::from_secs(35);
                let mut channel = match tokio::time::timeout_at(deadline, async {
                    receiver.lock().await.recv().await
                })
                .await
                {
                    Ok(Some(channel)) => channel,
                    Ok(None) => {
                        let error = mini_tunnel_agent::IdentityError::Transport(
                            "peer accept dispatcher stopped".to_owned(),
                        );
                        tracing::warn!(
                            peer_id = %peer.device_id,
                            stage = "accepted_recovery_channel_wait",
                            %error,
                            "direct recovery candidate connection failed"
                        );
                        return Err(error);
                    }
                    Err(_) => {
                        let error = mini_tunnel_agent::IdentityError::Transport(
                            "timed out waiting for direct probe".to_owned(),
                        );
                        tracing::warn!(
                            peer_id = %peer.device_id,
                            stage = "accepted_recovery_channel_wait",
                            %error,
                            "direct recovery candidate connection failed"
                        );
                        return Err(error);
                    }
                };
                tracing::debug!(
                    peer_id = %peer.device_id,
                    path = channel.transport_name(),
                    has_ice_consent = channel.has_ice_consent_monitor(),
                    "direct recovery accepted candidate channel received"
                );
                if let Some(monitor) = monitor.take() {
                    channel.set_ice_consent_monitor(monitor);
                }
                tracing::debug!(
                    peer_id = %peer.device_id,
                    path = channel.transport_name(),
                    has_ice_consent = channel.has_ice_consent_monitor(),
                    "direct recovery accepted candidate consent attached"
                );
                validate_udp_probe(channel, require_ice_consent, &peer.device_id).await
            })
        })
    };
    (connector, probe, accepted_tx)
}

async fn receive_reconnect_channel<T, IsReliable>(
    receiver: std::sync::Arc<tokio::sync::Mutex<tokio::sync::mpsc::Receiver<T>>>,
    force_reliable: bool,
    wait: Duration,
    is_reliable: IsReliable,
) -> Option<T>
where
    IsReliable: Fn(&T) -> bool,
{
    tokio::time::timeout(wait, async move {
        loop {
            let channel = receiver.lock().await.recv().await?;
            if !force_reliable || is_reliable(&channel) {
                return Some(channel);
            }
            // Discard stale UDP sessions from the shared accept queue while a reliable
            // replacement is being established.
        }
    })
    .await
    .ok()
    .flatten()
}

fn spawn_single_peer_acceptors(
    endpoint: TunnelEndpoint,
    identity: std::sync::Arc<mini_tunnel_agent::Identity>,
    network_id: String,
    expected_peer_id: String,
    expected_peer_key: [u8; 32],
    tcp_listener: Option<std::sync::Arc<tokio::net::TcpListener>>,
    accepted: tokio::sync::mpsc::Sender<mini_tunnel_agent::PeerChannel>,
) -> Vec<tokio::task::JoinHandle<()>> {
    let allowed = vec![(expected_peer_id.clone(), expected_peer_key)];
    let mut tasks = Vec::with_capacity(1 + usize::from(tcp_listener.is_some()));
    {
        let endpoint = endpoint.clone();
        let identity = std::sync::Arc::clone(&identity);
        let network_id = network_id.clone();
        let expected_peer_id = expected_peer_id.clone();
        let accepted = accepted.clone();
        let allowed = allowed.clone();
        tasks.push(tokio::spawn(async move {
            loop {
                let result =
                    mini_tunnel_agent::accept_peer_any(&endpoint, &network_id, &identity, &allowed)
                        .await;
                match result {
                    Ok((device_id, channel)) if device_id == expected_peer_id => {
                        if let Err(error) = accepted.send(channel).await {
                            error.0.close_async().await;
                            break;
                        }
                    }
                    Ok((_, channel)) => channel.close_async().await,
                    Err(error) => {
                        tracing::debug!(%error, "single-peer UDP acceptor stopped");
                        break;
                    }
                }
            }
        }));
    }
    if let Some(listener) = tcp_listener {
        let identity = std::sync::Arc::clone(&identity);
        tasks.push(tokio::spawn(async move {
            loop {
                let result = mini_tunnel_agent::accept_tcp_peer_any(
                    &listener,
                    &network_id,
                    &identity,
                    &allowed,
                )
                .await;
                match result {
                    Ok((device_id, channel)) if device_id == expected_peer_id => {
                        if let Err(error) = accepted.send(channel).await {
                            error.0.close_async().await;
                            break;
                        }
                    }
                    Ok((_, channel)) => channel.close_async().await,
                    Err(error) => {
                        tracing::debug!(%error, "single-peer TCP acceptor stopped");
                        break;
                    }
                }
            }
        }));
    }
    tasks
}

type AcceptedPeerRegistry = std::sync::Arc<
    tokio::sync::RwLock<
        std::collections::HashMap<
            String,
            tokio::sync::mpsc::Sender<mini_tunnel_agent::PeerChannel>,
        >,
    >,
>;

fn mesh_membership_diff(
    known: &std::collections::HashMap<String, PeerInfo>,
    snapshot: &[PeerInfo],
) -> (Vec<(String, String)>, Vec<PeerInfo>) {
    let next = snapshot
        .iter()
        .map(|peer| (peer.device_id.as_str(), peer))
        .collect::<std::collections::HashMap<_, _>>();
    let mut removed: Vec<(String, String)> = known
        .iter()
        .filter(|(device_id, peer)| {
            next.get(device_id.as_str())
                .is_none_or(|current| current.assigned_ipv4 != peer.assigned_ipv4)
        })
        .map(|(device_id, peer)| (device_id.clone(), peer.assigned_ipv4.clone()))
        .collect();
    removed.sort_by(|left, right| left.0.cmp(&right.0));
    let added = snapshot
        .iter()
        .filter(|peer| {
            known
                .get(&peer.device_id)
                .is_none_or(|previous| previous.assigned_ipv4 != peer.assigned_ipv4)
        })
        .cloned()
        .collect();
    (removed, added)
}

async fn stop_mesh_after_membership_revocation(
    error: &CoordinatorApiError,
    known: &std::collections::HashMap<String, PeerInfo>,
    pending: &mut std::collections::HashMap<String, tokio::task::JoinHandle<()>>,
    registry: &AcceptedPeerRegistry,
    snapshot_tx: &tokio::sync::watch::Sender<Vec<PeerInfo>>,
    allowlist_tx: &tokio::sync::watch::Sender<Vec<(String, [u8; 32])>>,
    updates_tx: &tokio::sync::mpsc::Sender<mini_tunnel_agent::tunnel::MeshPeerUpdate>,
) -> bool {
    if !coordinator_error_revokes_member(error) {
        return false;
    }
    tracing::error!(code = %error.code, "local mesh membership is no longer authorized; closing all peers");
    for (_, task) in pending.drain() {
        task.abort();
        let _ = task.await;
    }
    registry.write().await.clear();
    let _ = snapshot_tx.send(Vec::new());
    let _ = allowlist_tx.send(Vec::new());
    let addresses = known
        .values()
        .filter_map(|peer| peer.assigned_ipv4.parse::<Ipv4Addr>().ok())
        .collect::<std::collections::BTreeSet<_>>();
    for address in addresses {
        if updates_tx
            .send(mini_tunnel_agent::tunnel::MeshPeerUpdate::Remove(address))
            .await
            .is_err()
        {
            break;
        }
    }
    true
}

struct MeshMembershipRefresh {
    coordinator_url: String,
    network_id: String,
    identity: std::sync::Arc<mini_tunnel_agent::Identity>,
    endpoint: TunnelEndpoint,
    relay_endpoints: RelayEndpoints,
    snapshot_tx: tokio::sync::watch::Sender<Vec<PeerInfo>>,
    allowlist_tx: tokio::sync::watch::Sender<Vec<(String, [u8; 32])>>,
    registry: AcceptedPeerRegistry,
    updates_tx: tokio::sync::mpsc::Sender<mini_tunnel_agent::tunnel::MeshPeerUpdate>,
    initial_peers: Vec<PeerInfo>,
}

fn spawn_mesh_membership_refresh(config: MeshMembershipRefresh) -> tokio::task::JoinHandle<()> {
    let MeshMembershipRefresh {
        coordinator_url,
        network_id,
        identity,
        endpoint,
        relay_endpoints,
        snapshot_tx,
        allowlist_tx,
        registry,
        updates_tx,
        initial_peers,
    } = config;
    tokio::spawn(async move {
        let mut known = initial_peers
            .into_iter()
            .map(|peer| (peer.device_id.clone(), peer))
            .collect::<std::collections::HashMap<_, _>>();
        let mut pending = std::collections::HashMap::<String, tokio::task::JoinHandle<()>>::new();
        let period = Duration::from_secs(30);
        let mut refresh = tokio::time::interval(period);
        refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            refresh.tick().await;
            let discovered = tokio::time::timeout(
                Duration::from_secs(8),
                discover_peers(&coordinator_url, &network_id, &identity),
            )
            .await;
            let peers = match discovered {
                Ok(Ok(peers)) => peers,
                Ok(Err(error)) => {
                    if let Some(api_error) = error.downcast_ref::<CoordinatorApiError>()
                        && stop_mesh_after_membership_revocation(
                            api_error,
                            &known,
                            &mut pending,
                            &registry,
                            &snapshot_tx,
                            &allowlist_tx,
                            &updates_tx,
                        )
                        .await
                    {
                        return;
                    }
                    eprintln!("mesh membership refresh failed; keeping current peers: {error}");
                    continue;
                }
                Err(_) => {
                    eprintln!("mesh membership refresh timed out; keeping current peers");
                    continue;
                }
            };
            if peers.len() > mini_tunnel_protocol::MAX_NETWORK_MEMBERS {
                eprintln!("mesh membership snapshot exceeds the local peer limit; ignoring it");
                continue;
            }
            let allowed = peers
                .iter()
                .map(|peer| {
                    decode_peer_key(&peer.public_key).map(|key| (peer.device_id.clone(), key))
                })
                .collect::<Result<Vec<_>, _>>();
            let Ok(allowed) = allowed else {
                eprintln!("mesh membership snapshot contains an invalid peer key; ignoring it");
                continue;
            };

            let (removed, added) = mesh_membership_diff(&known, &peers);
            let next = peers
                .iter()
                .map(|peer| (peer.device_id.clone(), peer.clone()))
                .collect::<std::collections::HashMap<_, _>>();
            for (device_id, address) in removed {
                if let Some(task) = pending.remove(&device_id) {
                    task.abort();
                }
                registry.write().await.remove(&device_id);
                if let Ok(address) = address.parse() {
                    let _ = updates_tx
                        .send(mini_tunnel_agent::tunnel::MeshPeerUpdate::Remove(address))
                        .await;
                }
                eprintln!("mesh peer {device_id} was removed or its address changed");
            }

            let mut additions = Vec::with_capacity(added.len());
            for peer in added {
                let address = match peer.assigned_ipv4.parse::<Ipv4Addr>() {
                    Ok(address) => address,
                    Err(_) => continue,
                };
                let (connector, probe, accepted_tx) = build_mesh_peer_connectors(
                    endpoint.clone(),
                    std::sync::Arc::clone(&identity),
                    network_id.clone(),
                    coordinator_url.clone(),
                    peer.clone(),
                    relay_endpoints,
                );
                registry
                    .write()
                    .await
                    .insert(peer.device_id.clone(), accepted_tx);
                additions.push((peer, address, connector, probe));
            }

            if snapshot_tx.send(peers.clone()).is_err() || allowlist_tx.send(allowed).is_err() {
                eprintln!("mesh membership dispatcher stopped");
                return;
            }
            for (peer, address, connector, probe) in additions {
                let ipv6_address = mini_tunnel_protocol::overlay_ipv6_address(&network_id, address);
                let Some(ipv6_address) = ipv6_address else {
                    eprintln!(
                        "could not derive IPv6 overlay address for peer {}",
                        peer.device_id
                    );
                    continue;
                };
                let connect = std::sync::Arc::clone(&connector);
                let updates = updates_tx.clone();
                let device_id = peer.device_id.clone();
                let probe = Some(probe);
                pending.insert(
                    device_id.clone(),
                    tokio::spawn(async move {
                        let mut attempt = 0_u32;
                        loop {
                            match connect(false).await {
                                Ok(channel) => {
                                    let update = mini_tunnel_agent::tunnel::MeshPeerUpdate::Add(
                                        mini_tunnel_agent::tunnel::ReconnectingPeer {
                                            address,
                                            ipv6_address: Some(ipv6_address),
                                            channel: std::sync::Arc::new(channel),
                                            connector,
                                            probe,
                                            probe_cooldown: Duration::from_secs(60),
                                        },
                                    );
                                    if let Err(error) = updates.send(update).await
                                        && let mini_tunnel_agent::tunnel::MeshPeerUpdate::Add(
                                            peer,
                                        ) = error.0
                                    {
                                        peer.channel.close();
                                    }
                                    return;
                                }
                                Err(error) => {
                                    eprintln!(
                                        "new mesh peer {device_id} connection failed: {error}"
                                    );
                                    tokio::time::sleep(mini_tunnel_agent::reconnect_delay(attempt))
                                        .await;
                                    attempt = attempt.saturating_add(1);
                                }
                            }
                        }
                    }),
                );
                eprintln!("discovered new mesh peer {} at {address}", peer.device_id);
            }
            known = next;
        }
    })
}

async fn validate_udp_probe(
    channel: mini_tunnel_agent::PeerChannel,
    require_ice_consent: bool,
    peer_id: &str,
) -> Result<mini_tunnel_agent::PeerChannel, mini_tunnel_agent::IdentityError> {
    let probation = if require_ice_consent {
        ICE_PATH_PROMOTION_PROBATION
    } else {
        DIRECT_PATH_PROMOTION_PROBATION
    };
    validate_udp_probe_with_context(
        channel,
        require_ice_consent,
        probation,
        ICE_PATH_PROBATION_HEALTH_INTERVAL,
        Some(peer_id),
    )
    .await
}

#[cfg(test)]
async fn validate_udp_probe_with_window(
    channel: mini_tunnel_agent::PeerChannel,
    require_ice_consent: bool,
    consent_window: Duration,
) -> Result<mini_tunnel_agent::PeerChannel, mini_tunnel_agent::IdentityError> {
    validate_udp_probe_with_context(
        channel,
        require_ice_consent,
        consent_window,
        ICE_PATH_PROBATION_HEALTH_INTERVAL,
        None,
    )
    .await
}

#[cfg(test)]
async fn validate_udp_probe_with_timing(
    channel: mini_tunnel_agent::PeerChannel,
    require_ice_consent: bool,
    consent_window: Duration,
    health_interval: Duration,
) -> Result<mini_tunnel_agent::PeerChannel, mini_tunnel_agent::IdentityError> {
    validate_udp_probe_with_context(
        channel,
        require_ice_consent,
        consent_window,
        health_interval,
        None,
    )
    .await
}

async fn validate_udp_probe_with_context(
    channel: mini_tunnel_agent::PeerChannel,
    require_ice_consent: bool,
    consent_window: Duration,
    health_interval: Duration,
    peer_id: Option<&str>,
) -> Result<mini_tunnel_agent::PeerChannel, mini_tunnel_agent::IdentityError> {
    // Recovery from a reliable path needs more evidence than initial direct dialing:
    // several clean probes plus a probation window prevent a lucky short burst from
    // promoting a lossy UDP candidate.
    let initial_probes = if require_ice_consent { 3 } else { 8 };
    tracing::debug!(
        peer_id = peer_id.unwrap_or("test"),
        path = channel.transport_name(),
        has_ice_consent = channel.has_ice_consent_monitor(),
        initial_probes,
        probation_ms = consent_window.as_millis() as u64,
        "starting direct candidate authenticated health validation"
    );
    let rtt = match channel
        .probe_health(initial_probes, Duration::from_secs(2))
        .await
    {
        Ok(rtt) => rtt,
        Err(error) => {
            tracing::warn!(
                peer_id = peer_id.unwrap_or("test"),
                path = channel.transport_name(),
                stage = "initial_authenticated_health_probes",
                %error,
                "direct candidate health validation failed"
            );
            return Err(error);
        }
    };
    tracing::debug!(
        peer_id = peer_id.unwrap_or("test"),
        path = channel.transport_name(),
        rtt_ms = rtt.as_millis() as u64,
        "direct candidate initial authenticated health probes passed"
    );
    if !mini_tunnel_agent::tunnel::path_quality_rtt_is_acceptable(rtt) {
        tracing::warn!(
            peer_id = peer_id.unwrap_or("test"),
            path = channel.transport_name(),
            stage = "initial_rtt_threshold",
            rtt_ms = rtt.as_millis() as u64,
            "direct candidate health validation failed"
        );
        return Err(mini_tunnel_agent::IdentityError::Transport(
            "direct path probe exceeded RTT threshold".to_owned(),
        ));
    }
    if require_ice_consent {
        if !channel.has_ice_consent_monitor() {
            tracing::warn!(
                peer_id = peer_id.unwrap_or("test"),
                path = channel.transport_name(),
                stage = "consent_presence_check",
                "direct candidate health validation failed"
            );
            return Err(mini_tunnel_agent::IdentityError::Transport(
                "direct candidate is missing ICE consent".to_owned(),
            ));
        }
        let deadline = tokio::time::Instant::now() + consent_window;
        let mut health_probes = tokio::time::interval(health_interval);
        health_probes.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        health_probes.tick().await;
        loop {
            tokio::select! {
                () = channel.wait_ice_consent_failure() => {
                    tracing::warn!(
                        peer_id = peer_id.unwrap_or("test"),
                        path = channel.transport_name(),
                        stage = "ice_consent_probation",
                        "direct candidate health validation failed"
                    );
                    return Err(mini_tunnel_agent::IdentityError::Transport(
                        "ICE consent expired during direct path probation".to_owned(),
                    ));
                }
                _ = tokio::time::sleep_until(deadline) => break,
                _ = health_probes.tick() => {
                    let rtt = match channel.probe_health(1, Duration::from_secs(2)).await {
                        Ok(rtt) => rtt,
                        Err(error) => {
                            tracing::warn!(
                                peer_id = peer_id.unwrap_or("test"),
                                path = channel.transport_name(),
                                stage = "ice_probation_authenticated_health_probe",
                                %error,
                                "direct candidate health validation failed"
                            );
                            return Err(error);
                        }
                    };
                    if !mini_tunnel_agent::tunnel::path_quality_rtt_is_acceptable(rtt) {
                        tracing::warn!(
                            peer_id = peer_id.unwrap_or("test"),
                            path = channel.transport_name(),
                            stage = "ice_probation_rtt_threshold",
                            rtt_ms = rtt.as_millis() as u64,
                            "direct candidate health validation failed"
                        );
                        return Err(mini_tunnel_agent::IdentityError::Transport(
                            "direct path RTT exceeded threshold during probation".to_owned(),
                        ));
                    }
                }
            }
        }
    } else {
        let deadline = tokio::time::Instant::now() + consent_window;
        let mut health_probes = tokio::time::interval(health_interval);
        health_probes.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        health_probes.tick().await;
        loop {
            tokio::select! {
                _ = tokio::time::sleep_until(deadline) => break,
                _ = health_probes.tick() => {
                    let rtt = match channel.probe_health(1, Duration::from_secs(2)).await {
                        Ok(rtt) => rtt,
                        Err(error) => {
                            tracing::warn!(
                                peer_id = peer_id.unwrap_or("test"),
                                path = channel.transport_name(),
                                stage = "probation_authenticated_health_probe",
                                %error,
                                "direct candidate health validation failed"
                            );
                            return Err(error);
                        }
                    };
                    if !mini_tunnel_agent::tunnel::path_quality_rtt_is_acceptable(rtt) {
                        tracing::warn!(
                            peer_id = peer_id.unwrap_or("test"),
                            path = channel.transport_name(),
                            stage = "probation_rtt_threshold",
                            rtt_ms = rtt.as_millis() as u64,
                            "direct candidate health validation failed"
                        );
                        return Err(mini_tunnel_agent::IdentityError::Transport(
                            "direct path RTT exceeded threshold during probation".to_owned(),
                        ));
                    }
                }
            }
        }
    }
    tracing::info!(
        peer_id = peer_id.unwrap_or("test"),
        path = channel.transport_name(),
        has_ice_consent = channel.has_ice_consent_monitor(),
        stage = "probation_completed",
        "direct candidate health validation passed"
    );
    Ok(channel)
}

fn candidates_for_path(candidates: &[String], reliable_only: bool) -> Vec<String> {
    if reliable_only {
        candidates
            .iter()
            .filter(|candidate| candidate.starts_with("tcp://"))
            .cloned()
            .collect()
    } else {
        candidates.to_vec()
    }
}

async fn connect_peer_via_relay(
    relay: SocketAddr,
    coordinator_url: &str,
    network_id: &str,
    identity: &mini_tunnel_agent::Identity,
    peer: &PeerInfo,
) -> Result<mini_tunnel_agent::PeerChannel, mini_tunnel_agent::IdentityError> {
    let ticket = request_peer_relay_ticket(coordinator_url, network_id, identity, peer).await?;
    let peer_key = decode_peer_key(&peer.public_key)
        .map_err(|_| mini_tunnel_agent::IdentityError::UnauthorizedPeer)?;
    mini_tunnel_agent::connect_relay_peer(
        relay,
        &ticket.ticket,
        network_id,
        identity,
        &peer.device_id,
        peer_key,
    )
    .await
}

async fn connect_peer_via_udp_relay(
    relay: SocketAddr,
    coordinator_url: &str,
    network_id: &str,
    identity: &mini_tunnel_agent::Identity,
    peer: &PeerInfo,
) -> Result<mini_tunnel_agent::PeerChannel, mini_tunnel_agent::IdentityError> {
    let ticket = request_peer_relay_ticket(coordinator_url, network_id, identity, peer).await?;
    if ticket.session_id == [0; 16] {
        return Err(mini_tunnel_agent::IdentityError::Transport(
            "Coordinator does not expose UDP relay session IDs; use TCP relay or upgrade it"
                .to_owned(),
        ));
    }
    let peer_key = decode_peer_key(&peer.public_key)
        .map_err(|_| mini_tunnel_agent::IdentityError::UnauthorizedPeer)?;
    mini_tunnel_agent::connect_udp_relay_peer(
        relay,
        &ticket.ticket,
        ticket.session_id,
        network_id,
        identity,
        &peer.device_id,
        peer_key,
    )
    .await
}

async fn request_peer_relay_ticket(
    coordinator_url: &str,
    network_id: &str,
    identity: &mini_tunnel_agent::Identity,
    peer: &PeerInfo,
) -> Result<RelayTicketResponse, mini_tunnel_agent::IdentityError> {
    let device_id = identity.device_id();
    let timestamp_ms =
        now_ms().map_err(|error| mini_tunnel_agent::IdentityError::Transport(error.to_string()))?;
    let request = RelayTicketRequest {
        device_id: device_id.clone(),
        peer_id: peer.device_id.clone(),
        timestamp_ms,
        signature: identity.sign(&relay_ticket_request_signing_bytes(
            network_id,
            &device_id,
            &peer.device_id,
            timestamp_ms,
        )),
    };
    post_json(
        coordinator_url,
        &format!("/v1/networks/{network_id}/relay-ticket"),
        &request,
    )
    .await
    .map_err(|error| mini_tunnel_agent::IdentityError::Transport(error.to_string()))
}

async fn run_peer_mesh(
    tun: &mini_tunnel_agent::tun_device::TunDevice,
    network_id: &str,
    peers: Vec<(
        PeerInfo,
        mini_tunnel_agent::PeerChannel,
        SocketAddr,
        mini_tunnel_agent::tunnel::PeerConnector,
        mini_tunnel_agent::tunnel::PeerConnector,
    )>,
    manage_routes: bool,
    mut updates: tokio::sync::mpsc::Receiver<mini_tunnel_agent::tunnel::MeshPeerUpdate>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use mini_tunnel_agent::routing::{
        RouteLease, RoutingPlatform, SystemRouteRunner, install_peer_ipv6_route, install_peer_route,
    };

    let prepared = peers
        .into_iter()
        .map(|(peer, channel, remote, connector, probe)| {
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((
                peer.device_id,
                peer.assigned_ipv4.parse::<Ipv4Addr>()?,
                mini_tunnel_protocol::overlay_ipv6_address(
                    network_id,
                    peer.assigned_ipv4.parse::<Ipv4Addr>()?,
                )
                .ok_or("could not derive peer IPv6 address")?,
                channel,
                remote,
                connector,
                probe,
            ))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let interface = tun.name()?;
    let ipv6_enabled = tun.local_ipv6().is_some();
    let runner = SystemRouteRunner;
    let mut routes: std::collections::HashMap<Ipv4Addr, RouteLease> =
        std::collections::HashMap::new();
    let mut routes_v6: std::collections::HashMap<std::net::Ipv6Addr, RouteLease> =
        std::collections::HashMap::new();
    let mut reconnecting_peers = Vec::with_capacity(prepared.len());
    for (device_id, peer_ipv4, peer_ipv6, channel, remote, connector, probe) in prepared {
        if manage_routes {
            match install_peer_route(&runner, RoutingPlatform::current(), &interface, peer_ipv4)
                .await
            {
                Ok(route) => {
                    routes.insert(peer_ipv4, route);
                }
                Err(error) => {
                    for route in routes_v6.drain().map(|(_, route)| route) {
                        let _ = route.remove(&runner).await;
                    }
                    for route in routes.drain().map(|(_, route)| route) {
                        let _ = route.remove(&runner).await;
                    }
                    return Err(error.into());
                }
            }
            if let Some(peer_ipv6) = mesh_peer_ipv6_address(ipv6_enabled, peer_ipv6) {
                match install_peer_ipv6_route(
                    &runner,
                    RoutingPlatform::current(),
                    &interface,
                    peer_ipv6,
                )
                .await
                {
                    Ok(route) => {
                        routes_v6.insert(peer_ipv6, route);
                    }
                    Err(error) => {
                        if let Some(route) = routes.remove(&peer_ipv4) {
                            let _ = route.remove(&runner).await;
                        }
                        for route in routes_v6.drain().map(|(_, route)| route) {
                            let _ = route.remove(&runner).await;
                        }
                        for route in routes.drain().map(|(_, route)| route) {
                            let _ = route.remove(&runner).await;
                        }
                        return Err(error.into());
                    }
                }
            }
        }
        let peer_ipv6 = mesh_peer_ipv6_address(ipv6_enabled, peer_ipv6);
        if let Some(peer_ipv6) = peer_ipv6 {
            println!(
                "Mesh peer {device_id} {peer_ipv4} ({peer_ipv6}) via {} at {remote}",
                channel.transport_name()
            );
        } else {
            println!(
                "Mesh peer {device_id} {peer_ipv4} via {} at {remote}",
                channel.transport_name()
            );
        }
        reconnecting_peers.push(mini_tunnel_agent::tunnel::ReconnectingPeer {
            address: peer_ipv4,
            ipv6_address: peer_ipv6,
            channel: std::sync::Arc::new(channel),
            connector,
            probe: Some(probe),
            probe_cooldown: Duration::from_secs(60),
        });
    }
    println!(
        "Mesh established on TUN interface {interface} ({})",
        mesh_address_family_label(ipv6_enabled)
    );
    let (pump_updates_tx, pump_updates_rx) = tokio::sync::mpsc::channel(64);
    let pump =
        mini_tunnel_agent::tunnel::pump_peer_mesh_dynamic(tun, reconnecting_peers, pump_updates_rx);
    tokio::pin!(pump);
    let mut updates_open = true;
    let tunnel_result: Result<(), Box<dyn std::error::Error + Send + Sync>> = loop {
        tokio::select! {
            result = &mut pump => break result.map_err(Into::into),
            signal = shutdown_signal() => break signal.map_err(Into::into),
            update = async {
                match updates_open {
                    true => updates.recv().await,
                    false => std::future::pending().await,
                }
            } => match update {
                Some(mini_tunnel_agent::tunnel::MeshPeerUpdate::Add(peer)) => {
                    let address = peer.address;
                    let peer_ipv6 = peer.ipv6_address;
                    if routes.contains_key(&address)
                        || peer_ipv6.is_some_and(|ipv6| routes_v6.contains_key(&ipv6))
                    {
                        peer.channel.close();
                        continue;
                    }
                    if manage_routes {
                        match install_peer_route(&runner, RoutingPlatform::current(), &interface, address).await {
                            Ok(route) => { routes.insert(address, route); }
                            Err(error) => {
                                eprintln!("could not add route for dynamic mesh peer {address}: {error}");
                                peer.channel.close();
                                continue;
                            }
                        }
                        if let Some(peer_ipv6) = peer_ipv6 {
                            match install_peer_ipv6_route(&runner, RoutingPlatform::current(), &interface, peer_ipv6).await {
                                Ok(route) => { routes_v6.insert(peer_ipv6, route); }
                                Err(error) => {
                                    if let Some(route) = routes.remove(&address) {
                                        let _ = route.remove(&runner).await;
                                    }
                                    eprintln!("could not add IPv6 route for dynamic mesh peer {peer_ipv6}: {error}");
                                    peer.channel.close();
                                    continue;
                                }
                            }
                        }
                    }
                    if let Err(error) = pump_updates_tx.send(mini_tunnel_agent::tunnel::MeshPeerUpdate::Add(peer)).await {
                        if let Some(route) = routes.remove(&address) {
                            let _ = route.remove(&runner).await;
                        }
                        if let Some(peer_ipv6) = peer_ipv6
                            && let Some(route) = routes_v6.remove(&peer_ipv6)
                        {
                            let _ = route.remove(&runner).await;
                        }
                        eprintln!("mesh packet pump stopped before peer {address} could be added: {error}");
                    }
                }
                Some(mini_tunnel_agent::tunnel::MeshPeerUpdate::Remove(address)) => {
                    let _ = pump_updates_tx.send(mini_tunnel_agent::tunnel::MeshPeerUpdate::Remove(address)).await;
                    if let Some(route) = routes.remove(&address)
                        && let Err(error) = route.remove(&runner).await
                    {
                        eprintln!("could not remove route for mesh peer {address}: {error}");
                    }
                    if let Some(peer_ipv6) = mini_tunnel_protocol::overlay_ipv6_address(
                        network_id,
                        address,
                    ) && let Some(route) = routes_v6.remove(&peer_ipv6)
                        && let Err(error) = route.remove(&runner).await
                    {
                        eprintln!("could not remove IPv6 route for mesh peer {peer_ipv6}: {error}");
                    }
                }
                None => updates_open = false,
            }
        }
    };
    let mut cleanup_error = None;
    for route in routes.into_values() {
        if let Err(error) = route.remove(&runner).await {
            cleanup_error.get_or_insert(error);
        }
    }
    for route in routes_v6.into_values() {
        if let Err(error) = route.remove(&runner).await {
            cleanup_error.get_or_insert(error);
        }
    }
    if let Some(error) = cleanup_error {
        return Err(error.into());
    }
    tunnel_result
}

fn mesh_peer_ipv6_address(
    local_ipv6_enabled: bool,
    peer_ipv6: std::net::Ipv6Addr,
) -> Option<std::net::Ipv6Addr> {
    local_ipv6_enabled.then_some(peer_ipv6)
}

fn mesh_address_family_label(ipv6_enabled: bool) -> &'static str {
    if ipv6_enabled {
        "IPv4/IPv6"
    } else {
        "IPv4 only"
    }
}

fn mesh_startup_settle_deadline(
    first_peer_at: Option<tokio::time::Instant>,
    attempts_pending: bool,
    startup_deadline: tokio::time::Instant,
    settle_window: Duration,
) -> tokio::time::Instant {
    if attempts_pending {
        startup_deadline
    } else {
        first_peer_at
            .map(|at| at + settle_window)
            .unwrap_or(startup_deadline)
    }
}

fn mesh_channel_is_elected(keep_outbound: bool, transport: &str) -> bool {
    keep_outbound || matches!(transport, "Relay/TLS" | "Relay/QUIC/UDP")
}

#[derive(Clone)]
struct TunnelEndpoint {
    endpoint: quinn::Endpoint,
    ice: Option<TunnelIceState>,
    excluded_candidate_interfaces:
        std::sync::Arc<std::sync::RwLock<std::collections::HashSet<String>>>,
}

impl TunnelEndpoint {
    fn exclude_tun_interface(
        &self,
        tun: &mini_tunnel_agent::tun_device::TunDevice,
    ) -> std::io::Result<()> {
        self.exclude_candidate_interface(tun.name()?)
    }

    fn exclude_candidate_interface(&self, name: String) -> std::io::Result<()> {
        self.excluded_candidate_interfaces
            .write()
            .map_err(|_| std::io::Error::other("candidate interface exclusion lock poisoned"))?
            .insert(name);
        Ok(())
    }
}

#[derive(Clone)]
struct TunnelIceState {
    credentials: mini_tunnel_protocol::IceCredentials,
    socket: mini_tunnel_agent::ice::IceSocketHandle,
    router: mini_tunnel_agent::ice::IceDatagramRouterHandle,
    local_socket_addr: SocketAddr,
    local_candidates:
        std::sync::Arc<tokio::sync::RwLock<Vec<mini_tunnel_agent::candidate::SignaledCandidate>>>,
}

const MAX_PEER_CANDIDATES: usize = 8;
const MAX_STUN_SERVERS: usize = 4;

#[derive(Clone, Debug, PartialEq, Eq)]
struct StunMapping {
    server: SocketAddr,
    mapped: SocketAddr,
    related: SocketAddr,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StunMappingObservation {
    Unavailable,
    SingleDestination,
    ConsistentSample,
    VaryingSample,
}

fn observe_stun_mappings(mappings: &[StunMapping]) -> StunMappingObservation {
    match mappings {
        [] => StunMappingObservation::Unavailable,
        [_] => StunMappingObservation::SingleDestination,
        [first, rest @ ..] if rest.iter().all(|mapping| mapping.mapped == first.mapped) => {
            StunMappingObservation::ConsistentSample
        }
        _ => StunMappingObservation::VaryingSample,
    }
}

fn normalize_stun_servers(
    servers: Vec<SocketAddr>,
) -> Result<Vec<SocketAddr>, Box<dyn std::error::Error + Send + Sync>> {
    let mut unique = Vec::new();
    for server in servers {
        if !unique.contains(&server) {
            unique.push(server);
        }
    }
    if unique.len() > MAX_STUN_SERVERS {
        return Err(format!("at most {MAX_STUN_SERVERS} STUN servers may be configured").into());
    }
    Ok(unique)
}

async fn gather_stun_mappings(
    router: &mini_tunnel_agent::ice::IceDatagramRouterHandle,
    socket: &mini_tunnel_agent::ice::IceSocketHandle,
    servers: &[SocketAddr],
    related: SocketAddr,
) -> Vec<StunMapping> {
    let results = join_all(servers.iter().copied().map(|server| async move {
        (server, router.discover_mapped_address(socket, server).await)
    }))
    .await;
    results
        .into_iter()
        .filter_map(|(server, result)| match result {
            Ok(mapped) => Some(StunMapping {
                server,
                mapped,
                related,
            }),
            Err(error) => {
                tracing::warn!(%error, %server, "STUN discovery failed; retaining other available candidates and retrying periodically");
                None
            }
        })
        .collect()
}

fn update_mapping_related_addresses(
    mappings: &mut [StunMapping],
    bound: SocketAddr,
    host_candidates: &[SocketAddr],
) {
    for mapping in mappings {
        mapping.related = if bound.ip().is_unspecified() {
            route_selected_local_address(mapping.server, bound.port())
                .ok()
                .or_else(|| {
                    host_candidates
                        .iter()
                        .copied()
                        .find(|host| host.is_ipv4() == mapping.server.is_ipv4())
                })
                .unwrap_or(bound)
        } else {
            bound
        };
    }
}

fn current_primary_host(
    bound: SocketAddr,
    mappings: &[StunMapping],
    host_candidates: &[SocketAddr],
) -> Option<SocketAddr> {
    if !bound.ip().is_unspecified() {
        return Some(bound);
    }
    mappings
        .iter()
        .map(|mapping| mapping.related)
        .find(|related| host_candidates.contains(related))
        .or_else(|| host_candidates.first().copied())
}

fn merge_stun_mappings(current: &mut Vec<StunMapping>, refreshed: Vec<StunMapping>) -> bool {
    let mut changed = false;
    for mapping in refreshed {
        if let Some(previous) = current
            .iter_mut()
            .find(|previous| previous.server == mapping.server)
        {
            if *previous != mapping {
                *previous = mapping;
                changed = true;
            }
        } else {
            current.push(mapping);
            changed = true;
        }
    }
    changed
}

async fn peer_endpoint_with_optional_stun(
    identity: &mini_tunnel_agent::Identity,
    bind: SocketAddr,
    stun_servers: &[SocketAddr],
    queue_capacity: usize,
) -> Result<
    (mini_tunnel_agent::ice::IcedPeerEndpoint, Vec<StunMapping>),
    mini_tunnel_agent::IdentityError,
> {
    let endpoint = mini_tunnel_agent::ice::peer_endpoint_with_ice(identity, bind, queue_capacity)?;
    let bound = endpoint.socket.local_addr()?;
    let mappings =
        gather_stun_mappings(&endpoint.ice_router, &endpoint.socket, stun_servers, bound).await;
    if !stun_servers.is_empty() {
        let observation = observe_stun_mappings(&mappings);
        tracing::info!(
            configured_servers = stun_servers.len(),
            successful_servers = mappings.len(),
            observation = ?observation,
            "STUN mapping sample collected; this is not a NAT type determination"
        );
    }
    Ok((endpoint, mappings))
}

impl std::ops::Deref for TunnelEndpoint {
    type Target = quinn::Endpoint;

    fn deref(&self) -> &Self::Target {
        &self.endpoint
    }
}

async fn create_tunnel_endpoint(
    identity: &mini_tunnel_agent::Identity,
    bind: SocketAddr,
    stun_servers: Vec<SocketAddr>,
    enable_ice: bool,
    extra_candidates: &[String],
    network_id: &str,
    coordinator_url: &str,
) -> Result<TunnelEndpoint, Box<dyn std::error::Error + Send + Sync>> {
    let stun_servers = normalize_stun_servers(stun_servers)?;
    let excluded_candidate_interfaces =
        std::sync::Arc::new(std::sync::RwLock::new(std::collections::HashSet::new()));
    if enable_ice {
        let (iced, mut mappings) =
            peer_endpoint_with_optional_stun(identity, bind, &stun_servers, 64).await?;
        let bound_address = iced.socket.local_addr()?;
        let gathered_hosts = if bound_address.ip().is_unspecified() {
            local_interface_host_candidates(bound_address, &std::collections::HashSet::new())?
        } else {
            Vec::new()
        };
        update_mapping_related_addresses(&mut mappings, bound_address, &gathered_hosts);
        let primary_host = current_primary_host(bound_address, &mappings, &gathered_hosts);
        let candidates = compose_ice_candidates(
            extra_candidates,
            primary_host,
            &mappings,
            gathered_hosts,
            stun_reservation(unique_candidate_count(extra_candidates), stun_servers.len()),
        )?;
        if candidates.is_empty() {
            return Err("ICE needs a usable local interface, --stun-server, or --candidate".into());
        }
        if candidates.len() > MAX_PEER_CANDIDATES {
            return Err("at most eight peer candidates can be published".into());
        }
        let local_candidates = udp_ice_candidates(&candidates);
        let credentials = mini_tunnel_agent::ice::generate_ice_credentials(1)?;
        let device_id = identity.device_id();
        let timestamp_ms = now_ms()?;
        let request = CandidateUpdateRequest {
            device_id: device_id.clone(),
            timestamp_ms,
            signature: sign_candidate_update(
                identity,
                network_id,
                &device_id,
                timestamp_ms,
                &candidates,
                Some(&credentials),
            ),
            candidates,
            ice_credentials: Some(credentials.clone()),
        };
        let path = format!("/v1/networks/{network_id}/candidates");
        let _: CandidateUpdateResponse = post_json(coordinator_url, &path, &request).await?;
        println!(
            "Published ICE credentials and {} peer candidate(s)",
            request.candidates.len()
        );
        let refresh_network = network_id.to_owned();
        let refresh_url = coordinator_url.to_owned();
        let refresh_candidates =
            std::sync::Arc::new(tokio::sync::RwLock::new(request.candidates.clone()));
        let refresh_local_candidates =
            std::sync::Arc::new(tokio::sync::RwLock::new(local_candidates));
        let refresh_device_id = device_id.clone();
        let refresh_socket = iced.socket.clone();
        let refresh_router = iced.ice_router.clone();
        let refresh_bound_address = bound_address;
        let refresh_stun_servers = stun_servers.clone();
        let initial_host_candidates = if bound_address.ip().is_unspecified() {
            local_interface_host_candidates(bound_address, &std::collections::HashSet::new())?
        } else {
            Vec::new()
        };
        let refresh_explicit = extra_candidates.to_vec();
        let refresh_reservation =
            stun_reservation(unique_candidate_count(extra_candidates), stun_servers.len());
        let refresh_credentials = credentials.clone();
        let task_candidates = std::sync::Arc::clone(&refresh_candidates);
        let task_local_candidates = std::sync::Arc::clone(&refresh_local_candidates);
        let task_excluded_candidate_interfaces =
            std::sync::Arc::clone(&excluded_candidate_interfaces);
        tokio::spawn(async move {
            let mut active_mappings = mappings;
            let mut active_host_candidates = initial_host_candidates;
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                let observed_hosts = if refresh_bound_address.ip().is_unspecified() {
                    let excluded = task_excluded_candidate_interfaces
                        .read()
                        .map(|names| names.clone())
                        .unwrap_or_default();
                    local_interface_host_candidates(refresh_bound_address, &excluded)
                } else {
                    Ok(Vec::new())
                };
                active_host_candidates =
                    refreshed_host_candidate_snapshot(&active_host_candidates, observed_hosts);
                let mut refreshed = gather_stun_mappings(
                    &refresh_router,
                    &refresh_socket,
                    &refresh_stun_servers,
                    refresh_bound_address,
                )
                .await;
                update_mapping_related_addresses(
                    &mut refreshed,
                    refresh_bound_address,
                    &active_host_candidates,
                );
                let mapping_set_changed = merge_stun_mappings(&mut active_mappings, refreshed);
                let primary_host = current_primary_host(
                    refresh_bound_address,
                    &active_mappings,
                    &active_host_candidates,
                );
                match compose_ice_candidates(
                    &refresh_explicit,
                    primary_host,
                    &active_mappings,
                    active_host_candidates.clone(),
                    refresh_reservation,
                ) {
                    Ok(next_candidates) => {
                        let changed = {
                            let mut current = task_candidates.write().await;
                            if *current == next_candidates {
                                false
                            } else {
                                *current = next_candidates;
                                true
                            }
                        };
                        if changed || mapping_set_changed {
                            *task_local_candidates.write().await =
                                udp_ice_candidates(&task_candidates.read().await);
                            tracing::info!(
                                reason = "nat_mapping_changed",
                                "refreshed ICE server-reflexive candidates"
                            );
                        }
                    }
                    Err(error) => {
                        tracing::warn!(%error, "could not compose refreshed ICE candidates")
                    }
                }
                let identity = match mini_tunnel_agent::Identity::load_or_create() {
                    Ok(identity) if identity.device_id() == refresh_device_id => identity,
                    Ok(_) => {
                        tracing::error!("device identity changed; stopping ICE credential refresh");
                        break;
                    }
                    Err(error) => {
                        tracing::warn!(%error, "could not load identity for ICE credential refresh");
                        continue;
                    }
                };
                let timestamp_ms = match now_ms() {
                    Ok(timestamp_ms) => timestamp_ms,
                    Err(error) => {
                        tracing::warn!(%error, "could not timestamp ICE credential refresh");
                        continue;
                    }
                };
                let refresh_candidates = task_candidates.read().await.clone();
                let request = CandidateUpdateRequest {
                    device_id: refresh_device_id.clone(),
                    timestamp_ms,
                    signature: sign_candidate_update(
                        &identity,
                        &refresh_network,
                        &refresh_device_id,
                        timestamp_ms,
                        &refresh_candidates,
                        Some(&refresh_credentials),
                    ),
                    candidates: refresh_candidates,
                    ice_credentials: Some(refresh_credentials.clone()),
                };
                let path = format!("/v1/networks/{refresh_network}/candidates");
                if let Err(error) =
                    post_json::<_, CandidateUpdateResponse>(&refresh_url, &path, &request).await
                {
                    tracing::warn!(%error, "ICE credential refresh failed; peer fallback remains available");
                }
            }
        });
        return Ok(TunnelEndpoint {
            endpoint: iced.endpoint,
            excluded_candidate_interfaces,
            ice: Some(TunnelIceState {
                credentials,
                socket: iced.socket,
                router: iced.ice_router,
                local_socket_addr: bound_address,
                local_candidates: refresh_local_candidates,
            }),
        });
    }
    if stun_servers.is_empty() && extra_candidates.is_empty() {
        return Ok(TunnelEndpoint {
            endpoint: mini_tunnel_agent::peer_endpoint(identity, bind)?,
            excluded_candidate_interfaces,
            ice: None,
        });
    }
    let (endpoint, mut mappings, stun_refresh) = if !stun_servers.is_empty() {
        // Use the same shared-socket dispatcher as ICE so periodic STUN refresh responses
        // cannot race Quinn's receive loop or be mistaken for tunnel data.
        let (iced, mappings) =
            peer_endpoint_with_optional_stun(identity, bind, &stun_servers, 64).await?;
        let bound = iced.socket.local_addr()?;
        (
            iced.endpoint,
            mappings,
            Some((iced.socket, iced.ice_router, bound)),
        )
    } else {
        (
            mini_tunnel_agent::peer_endpoint(identity, bind)?,
            Vec::new(),
            None,
        )
    };
    let (related_host, gathered_hosts) = if !stun_servers.is_empty() {
        let bound = stun_refresh
            .as_ref()
            .map(|(socket, _, _)| socket.local_addr())
            .transpose()?;
        match bound {
            Some(bound) if bound.ip().is_unspecified() => {
                let hosts =
                    local_interface_host_candidates(bound, &std::collections::HashSet::new())?;
                update_mapping_related_addresses(&mut mappings, bound, &hosts);
                (current_primary_host(bound, &mappings, &hosts), hosts)
            }
            Some(bound) => {
                update_mapping_related_addresses(&mut mappings, bound, &[]);
                (current_primary_host(bound, &mappings, &[]), Vec::new())
            }
            None => (None, Vec::new()),
        }
    } else {
        (None, Vec::new())
    };
    let device_id = identity.device_id();
    let timestamp_ms = now_ms()?;
    let explicit_candidate_count = unique_candidate_count(extra_candidates);
    let reserve_mapping_slots = stun_reservation(explicit_candidate_count, stun_servers.len());
    let candidates = compose_non_ice_candidates(
        extra_candidates,
        related_host,
        &mappings,
        gathered_hosts,
        reserve_mapping_slots,
    )?;
    if candidates.is_empty() {
        return Err(
            "no usable peer candidates; configure --candidate or an active network interface"
                .into(),
        );
    }
    let candidate_count = candidates.len();
    let request = CandidateUpdateRequest {
        device_id: device_id.clone(),
        timestamp_ms,
        signature: sign_candidate_update(
            identity,
            network_id,
            &device_id,
            timestamp_ms,
            &candidates,
            None,
        ),
        candidates,
        ice_credentials: None,
    };
    let path = format!("/v1/networks/{network_id}/candidates");
    let _: CandidateUpdateResponse = post_json(coordinator_url, &path, &request).await?;
    println!("Published {candidate_count} peer candidate(s)");
    if let Some((socket, router, bound)) = stun_refresh {
        let refresh_network = network_id.to_owned();
        let refresh_url = coordinator_url.to_owned();
        let refresh_device_id = device_id.clone();
        let refresh_explicit = extra_candidates.to_vec();
        let refresh_stun_servers = stun_servers.clone();
        let initial_host_candidates = if bound.ip().is_unspecified() {
            local_interface_host_candidates(bound, &std::collections::HashSet::new())?
        } else {
            Vec::new()
        };
        let refresh_reservation = reserve_mapping_slots;
        let candidates = std::sync::Arc::new(tokio::sync::RwLock::new(request.candidates));
        let refresh_candidates = std::sync::Arc::clone(&candidates);
        let task_excluded_candidate_interfaces =
            std::sync::Arc::clone(&excluded_candidate_interfaces);
        tokio::spawn(async move {
            let mut active_mappings = mappings;
            let mut active_host_candidates = initial_host_candidates;
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                let observed_hosts = if bound.ip().is_unspecified() {
                    let excluded = task_excluded_candidate_interfaces
                        .read()
                        .map(|names| names.clone())
                        .unwrap_or_default();
                    local_interface_host_candidates(bound, &excluded)
                } else {
                    Ok(Vec::new())
                };
                active_host_candidates =
                    refreshed_host_candidate_snapshot(&active_host_candidates, observed_hosts);
                let mut refreshed =
                    gather_stun_mappings(&router, &socket, &refresh_stun_servers, bound).await;
                update_mapping_related_addresses(&mut refreshed, bound, &active_host_candidates);
                let mapping_set_changed = merge_stun_mappings(&mut active_mappings, refreshed);
                let related =
                    current_primary_host(bound, &active_mappings, &active_host_candidates);
                let next_candidates = compose_non_ice_candidates(
                    &refresh_explicit,
                    related,
                    &active_mappings,
                    active_host_candidates.clone(),
                    refresh_reservation,
                );
                match next_candidates {
                    Ok(next_candidates) => {
                        let mut current = refresh_candidates.write().await;
                        if *current != next_candidates || mapping_set_changed {
                            *current = next_candidates;
                            tracing::info!(
                                reason = "nat_mapping_changed",
                                "refreshed server-reflexive candidates"
                            );
                        }
                    }
                    Err(error) => tracing::warn!(%error, "could not compose refreshed candidates"),
                }
                let identity = match mini_tunnel_agent::Identity::load_or_create() {
                    Ok(identity) if identity.device_id() == refresh_device_id => identity,
                    Ok(_) => {
                        tracing::error!("device identity changed; stopping candidate refresh");
                        break;
                    }
                    Err(error) => {
                        tracing::warn!(%error, "could not load identity for candidate refresh");
                        continue;
                    }
                };
                let timestamp_ms = match now_ms() {
                    Ok(timestamp_ms) => timestamp_ms,
                    Err(error) => {
                        tracing::warn!(%error, "could not timestamp candidate refresh");
                        continue;
                    }
                };
                let candidates = refresh_candidates.read().await.clone();
                let request = CandidateUpdateRequest {
                    device_id: refresh_device_id.clone(),
                    timestamp_ms,
                    signature: sign_candidate_update(
                        &identity,
                        &refresh_network,
                        &refresh_device_id,
                        timestamp_ms,
                        &candidates,
                        None,
                    ),
                    candidates,
                    ice_credentials: None,
                };
                let path = format!("/v1/networks/{refresh_network}/candidates");
                if let Err(error) =
                    post_json::<_, CandidateUpdateResponse>(&refresh_url, &path, &request).await
                {
                    tracing::warn!(%error, "server-reflexive candidate refresh failed");
                }
            }
        });
    }
    Ok(TunnelEndpoint {
        endpoint,
        excluded_candidate_interfaces,
        ice: None,
    })
}

fn route_selected_local_address(
    remote: SocketAddr,
    port: u16,
) -> Result<SocketAddr, std::io::Error> {
    let bind_address = if remote.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let probe = std::net::UdpSocket::bind(bind_address)?;
    probe.connect(remote)?;
    let selected = probe.local_addr()?;
    Ok(SocketAddr::new(selected.ip(), port))
}

fn local_interface_host_candidates(
    bound_address: SocketAddr,
    excluded_interfaces: &std::collections::HashSet<String>,
) -> std::io::Result<Vec<SocketAddr>> {
    let interfaces = if_addrs::get_if_addrs()?;
    let addresses = interfaces
        .into_iter()
        .filter(|interface| interface.is_oper_up() && !interface.is_loopback())
        .filter_map(|interface| match (bound_address, interface.addr) {
            (SocketAddr::V4(_), if_addrs::IfAddr::V4(address)) => {
                Some((interface.name, address.ip.into()))
            }
            (SocketAddr::V6(_), if_addrs::IfAddr::V6(address)) => {
                Some((interface.name, address.ip.into()))
            }
            _ => None,
        });
    Ok(filtered_interface_host_candidates(
        addresses,
        bound_address.port(),
        excluded_interfaces,
    ))
}

fn filtered_interface_host_candidates(
    interfaces: impl IntoIterator<Item = (String, std::net::IpAddr)>,
    port: u16,
    excluded_interfaces: &std::collections::HashSet<String>,
) -> Vec<SocketAddr> {
    filtered_host_candidates(
        interfaces
            .into_iter()
            .filter(|(name, _)| !excluded_interfaces.contains(name))
            .map(|(_, address)| address),
        port,
    )
}

fn refreshed_host_candidate_snapshot(
    previous: &[SocketAddr],
    observed: std::io::Result<Vec<SocketAddr>>,
) -> Vec<SocketAddr> {
    match observed {
        Ok(mut candidates) => {
            candidates.sort();
            candidates.dedup();
            candidates
        }
        Err(error) => {
            tracing::warn!(%error, "could not refresh active interface host candidates; retaining previous candidates");
            previous.to_vec()
        }
    }
}

fn filtered_host_candidates(
    addresses: impl IntoIterator<Item = std::net::IpAddr>,
    port: u16,
) -> Vec<SocketAddr> {
    let mut candidates = addresses
        .into_iter()
        .filter(|address| {
            !address.is_unspecified()
                && !address.is_loopback()
                && !address.is_multicast()
                && match address {
                    std::net::IpAddr::V4(address) => !address.is_broadcast(),
                    std::net::IpAddr::V6(address) => !address.is_unicast_link_local(),
                }
        })
        .map(|address| SocketAddr::new(address, port))
        .collect::<Vec<_>>();
    candidates.sort();
    candidates.dedup();
    candidates
}

fn sign_candidate_update(
    identity: &mini_tunnel_agent::Identity,
    network_id: &str,
    device_id: &str,
    timestamp_ms: u64,
    candidates: &[String],
    ice_credentials: Option<&IceCredentials>,
) -> String {
    // The Coordinator verifies and stores candidate lists in sorted order.
    // Keep the advertised order intact, but sign that canonical ordering.
    let mut canonical_candidates = candidates.to_vec();
    canonical_candidates.sort();
    let bytes = match ice_credentials {
        Some(credentials) => candidate_signing_bytes_with_ice(
            network_id,
            device_id,
            timestamp_ms,
            &canonical_candidates,
            credentials,
        ),
        None => candidate_signing_bytes(network_id, device_id, timestamp_ms, &canonical_candidates),
    };
    identity.sign(&bytes)
}

fn compose_ice_candidates(
    explicit: &[String],
    primary_host: Option<SocketAddr>,
    mapped: &[StunMapping],
    other_hosts: Vec<SocketAddr>,
    reserve_mapped_slots: usize,
) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
    let mut candidates = Vec::new();
    for candidate in explicit {
        if !candidates.contains(candidate) {
            candidates.push(candidate.clone());
        }
    }
    if candidates.len() > MAX_PEER_CANDIDATES {
        return Err("at most eight explicit peer candidates can be published".into());
    }
    if reserve_mapped_slots > 0 && candidates.len() == MAX_PEER_CANDIDATES {
        return Err("explicit candidates leave no room for a STUN mapped candidate".into());
    }
    let mut mapped_count = 0;
    for mapping in mapped {
        let srflx = format!("srflx://{}|{}", mapping.mapped, mapping.related);
        if !candidates.contains(&srflx) {
            if mapped_count >= reserve_mapped_slots || candidates.len() == MAX_PEER_CANDIDATES {
                continue;
            }
            candidates.push(srflx);
            mapped_count += 1;
        }
    }
    let mut hosts = Vec::new();
    if let Some(primary_host) = primary_host {
        hosts.push(primary_host);
    }
    let mut other_hosts = other_hosts;
    other_hosts.sort();
    other_hosts.dedup();
    hosts.extend(other_hosts);
    let mut seen_hosts = std::collections::HashSet::new();
    let candidate_limit = MAX_PEER_CANDIDATES - reserve_mapped_slots.saturating_sub(mapped_count);
    for host in hosts {
        if !seen_hosts.insert(host) {
            continue;
        }
        let signal = host.to_string();
        if !candidates.contains(&signal) && candidates.len() < candidate_limit {
            candidates.push(signal);
        }
    }
    Ok(candidates)
}

fn unique_candidate_count(candidates: &[String]) -> usize {
    candidates
        .iter()
        .enumerate()
        .filter(|(index, candidate)| !candidates[..*index].contains(candidate))
        .count()
}

fn stun_reservation(explicit_candidate_count: usize, server_count: usize) -> usize {
    server_count
        .min(MAX_PEER_CANDIDATES.saturating_sub(explicit_candidate_count))
        .max(usize::from(server_count > 0))
}

fn compose_non_ice_candidates(
    explicit: &[String],
    primary_host: Option<SocketAddr>,
    mapped: &[StunMapping],
    other_hosts: Vec<SocketAddr>,
    reserve_mapped_slots: usize,
) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
    let mut candidates = Vec::new();
    for candidate in explicit {
        if !candidates.contains(candidate) {
            candidates.push(candidate.clone());
        }
    }
    if candidates.len() > MAX_PEER_CANDIDATES {
        return Err("at most eight explicit peer candidates can be published".into());
    }
    if reserve_mapped_slots > 0 && candidates.len() == MAX_PEER_CANDIDATES {
        return Err("explicit candidates leave no room for a STUN mapped candidate".into());
    }
    let mut mapped_count = 0;
    for mapping in mapped {
        let signal = mapping.mapped.to_string();
        if !candidates.contains(&signal) {
            if mapped_count >= reserve_mapped_slots || candidates.len() == MAX_PEER_CANDIDATES {
                continue;
            }
            candidates.push(signal);
            mapped_count += 1;
        }
    }
    let candidate_limit = MAX_PEER_CANDIDATES - reserve_mapped_slots.saturating_sub(mapped_count);
    let mut hosts = Vec::new();
    if let Some(primary_host) = primary_host {
        hosts.push(primary_host);
    }
    hosts.extend(other_hosts);
    let mut seen_hosts = std::collections::HashSet::new();
    for host in hosts {
        if !seen_hosts.insert(host) {
            continue;
        }
        let signal = host.to_string();
        if !candidates.contains(&signal) && candidates.len() < candidate_limit {
            candidates.push(signal);
        }
    }
    Ok(candidates)
}

fn udp_ice_candidates(
    candidates: &[String],
) -> Vec<mini_tunnel_agent::candidate::SignaledCandidate> {
    candidates
        .iter()
        .filter_map(|candidate| {
            let parsed = mini_tunnel_agent::candidate::parse_signaled_candidate(candidate)?;
            (parsed.transport == mini_tunnel_agent::candidate::CandidateTransport::Udp)
                .then_some(parsed)
        })
        .collect()
}

fn create_tun(
    network_id: &str,
    local_ipv4: Ipv4Addr,
    prefix_len: u8,
    mtu: u16,
) -> Result<mini_tunnel_agent::tun_device::TunDevice, Box<dyn std::error::Error + Send + Sync>> {
    let local_ipv6 = mini_tunnel_protocol::overlay_ipv6_address(network_id, local_ipv4)
        .ok_or("network ID must be a UUID to derive the IPv6 overlay address")?;
    let mut config = mini_tunnel_agent::tun_device::TunConfig::ipv4(local_ipv4, prefix_len);
    config = config.with_ipv6(local_ipv6, 64);
    config.mtu = mtu;
    let (device, ipv6_enabled, ipv6_error) = create_tun_with_ipv6_fallback(config, |config| {
        mini_tunnel_agent::tun_device::TunDevice::create(config)
    })?;
    if !ipv6_enabled {
        tracing::warn!(
            error = %ipv6_error.expect("IPv4-only fallback retains the IPv6 setup error"),
            "IPv6 overlay setup is unavailable; continuing with IPv4-only TUN"
        );
    }
    Ok(device)
}

fn create_tun_with_ipv6_fallback<T>(
    mut config: mini_tunnel_agent::tun_device::TunConfig,
    mut create: impl FnMut(mini_tunnel_agent::tun_device::TunConfig) -> std::io::Result<T>,
) -> std::io::Result<(T, bool, Option<std::io::Error>)> {
    if config.local_ipv6.is_none() {
        return create(config).map(|device| (device, false, None));
    }
    match create(config.clone()) {
        Ok(device) => Ok((device, true, None)),
        Err(ipv6_error) if ipv6_tun_setup_may_be_unsupported(&ipv6_error) => {
            config.local_ipv6 = None;
            match create(config) {
                Ok(device) => Ok((device, false, Some(ipv6_error))),
                Err(ipv4_error) => Err(std::io::Error::new(
                    ipv4_error.kind(),
                    format!(
                        "IPv6 TUN setup failed ({ipv6_error}); IPv4-only TUN fallback also failed ({ipv4_error})"
                    ),
                )),
            }
        }
        Err(error) => Err(error),
    }
}

fn ipv6_tun_setup_may_be_unsupported(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::PermissionDenied
            | std::io::ErrorKind::Unsupported
            | std::io::ErrorKind::AddrNotAvailable
    )
}

fn resolve_tun_parameters(
    network_id: &str,
    identity: &mini_tunnel_agent::Identity,
    local_ipv4_override: Option<Ipv4Addr>,
    prefix_override: Option<u8>,
) -> Result<(Ipv4Addr, u8), Box<dyn std::error::Error + Send + Sync>> {
    use mini_tunnel_agent::membership::MembershipError;

    let store = mini_tunnel_agent::membership::MembershipStore::for_current_user()?;
    match store.load(network_id, &identity.device_id()) {
        Ok(membership) => {
            resolve_saved_tun_parameters(&membership, local_ipv4_override, prefix_override)
        }
        Err(MembershipError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            match (local_ipv4_override, prefix_override) {
                (Some(address), Some(prefix)) => Ok((address, prefix)),
                _ => Err(
                    "no saved membership found; run network join again or supply both --local-ipv4 and --prefix-len".into(),
                ),
            }
        }
        Err(error) => Err(error.into()),
    }
}

fn resolve_saved_tun_parameters(
    membership: &mini_tunnel_agent::membership::NetworkMembership,
    local_ipv4_override: Option<Ipv4Addr>,
    prefix_override: Option<u8>,
) -> Result<(Ipv4Addr, u8), Box<dyn std::error::Error + Send + Sync>> {
    let saved_ip = membership.assigned_ip()?;
    let saved_prefix = membership.prefix_len()?;
    if local_ipv4_override.is_some_and(|address| address != saved_ip)
        || prefix_override.is_some_and(|prefix| prefix != saved_prefix)
    {
        return Err(
            "explicit TUN address/prefix conflicts with the saved network membership".into(),
        );
    }
    Ok((saved_ip, saved_prefix))
}

async fn discover_peer(
    coordinator_url: &str,
    network_id: &str,
    peer_id: &str,
    identity: &mini_tunnel_agent::Identity,
) -> Result<PeerInfo, Box<dyn std::error::Error + Send + Sync>> {
    discover_peers(coordinator_url, network_id, identity)
        .await?
        .into_iter()
        .find(|peer| peer.device_id == peer_id)
        .ok_or_else(|| "peer is not present in the signed same-network snapshot".into())
}

async fn discover_peers(
    coordinator_url: &str,
    network_id: &str,
    identity: &mini_tunnel_agent::Identity,
) -> Result<Vec<PeerInfo>, Box<dyn std::error::Error + Send + Sync>> {
    let device_id = identity.device_id();
    let timestamp_ms = now_ms()?;
    let request = PeerListRequest {
        device_id: device_id.clone(),
        timestamp_ms,
        signature: identity.sign(&peers_signing_bytes(network_id, &device_id, timestamp_ms)),
    };
    let path = format!("/v1/networks/{network_id}/peers");
    let snapshot: PeerListResponse = post_json(coordinator_url, &path, &request).await?;
    Ok(snapshot.peers)
}

async fn wait_for_peer_revocation(
    coordinator_url: String,
    network_id: String,
    peer_id: String,
    identity: &mini_tunnel_agent::Identity,
) {
    let mut refresh = tokio::time::interval(Duration::from_secs(30));
    refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    refresh.tick().await;
    loop {
        refresh.tick().await;
        match discover_peers(&coordinator_url, &network_id, identity).await {
            Ok(peers) if peer_snapshot_revokes_peer(&peers, &peer_id) => return,
            Ok(_) => {}
            Err(error)
                if error
                    .downcast_ref::<CoordinatorApiError>()
                    .is_some_and(coordinator_error_revokes_member) =>
            {
                return;
            }
            Err(error) => {
                tracing::warn!(%error, "peer authorization refresh failed; keeping current session");
            }
        }
    }
}

fn peer_snapshot_revokes_peer(peers: &[PeerInfo], peer_id: &str) -> bool {
    !peers.iter().any(|peer| peer.device_id == peer_id)
}

fn coordinator_error_revokes_member(error: &CoordinatorApiError) -> bool {
    matches!(error.code.as_str(), "invalid_token" | "not_found")
}

fn print_tunnel_ready(
    tun: &mini_tunnel_agent::tun_device::TunDevice,
    peer: &PeerInfo,
    network_id: &str,
    remote: SocketAddr,
    transport: &str,
    managed_route: bool,
) {
    match tun.name() {
        Ok(name) => println!("TUN interface: {name}"),
        Err(error) => eprintln!("could not query TUN interface name: {error}"),
    }
    println!(
        "Tunnel established: local {} -> peer {} ({}, {transport} {remote})",
        tun.local_ipv4(),
        peer.device_id,
        peer.assigned_ipv4
    );
    if let Some(local_ipv6) = tun.local_ipv6() {
        let peer_ipv6 = peer
            .assigned_ipv4
            .parse::<Ipv4Addr>()
            .ok()
            .and_then(|peer_ipv4| {
                mini_tunnel_protocol::overlay_ipv6_address(network_id, peer_ipv4)
            });
        println!(
            "IPv6 overlay: local {local_ipv6} -> peer {}",
            peer_ipv6.map_or_else(|| "(unavailable)".to_owned(), |address| address.to_string())
        );
    }
    if managed_route {
        println!(
            "Managed /32 IPv4 and /128 IPv6 routes installed for peer {}.",
            peer.assigned_ipv4
        );
    } else {
        println!(
            "No explicit peer route was added; check whether the OS routed {} and its derived IPv6 address through this TUN interface.",
            peer.assigned_ipv4
        );
        println!("If needed, add a host route for this peer and remove it manually when stopping.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coordinator_ca_bundle_rejects_empty_non_pem_and_oversized_files_safely() {
        let directory = std::env::temp_dir().join(format!(
            "mini-tunnel-coordinator-ca-bundle-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&directory).expect("create temporary directory");

        let empty = directory.join("empty.pem");
        std::fs::write(&empty, []).expect("write empty CA bundle");
        let error = read_coordinator_ca_bundle(&empty).expect_err("empty bundle must be rejected");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("is empty"));

        let malformed = directory.join("malformed.pem");
        std::fs::write(&malformed, "PRIVATE_TEST_SENTINEL").expect("write malformed CA bundle");
        let error =
            read_coordinator_ca_bundle(&malformed).expect_err("malformed bundle must be rejected");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(
            error
                .to_string()
                .contains("Coordinator CA certificate bundle")
        );
        assert!(!error.to_string().contains("PRIVATE_TEST_SENTINEL"));

        let oversized = directory.join("oversized.pem");
        std::fs::write(
            &oversized,
            vec![b'A'; MAX_COORDINATOR_CA_BUNDLE_BYTES as usize + 1],
        )
        .expect("write oversized CA bundle");
        let error =
            read_coordinator_ca_bundle(&oversized).expect_err("oversized bundle must be rejected");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("1 MiB limit"));

        let error = read_coordinator_ca_bundle(&directory)
            .expect_err("directories must not be accepted as CA bundles");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("regular file"));
        std::fs::remove_dir_all(directory).expect("remove temporary directory");
    }

    #[test]
    fn mesh_uses_only_ip_families_available_on_its_tun() {
        let peer_ipv6 = "fd00::2".parse().unwrap();

        assert_eq!(mesh_address_family_label(true), "IPv4/IPv6");
        assert_eq!(mesh_peer_ipv6_address(true, peer_ipv6), Some(peer_ipv6));
        assert_eq!(mesh_address_family_label(false), "IPv4 only");
        assert_eq!(mesh_peer_ipv6_address(false, peer_ipv6), None);
    }

    #[test]
    fn mesh_elects_udp_relay_channel_on_both_peer_roles() {
        assert!(mesh_channel_is_elected(true, "Relay/QUIC/UDP"));
        assert!(mesh_channel_is_elected(false, "Relay/QUIC/UDP"));
        assert!(mesh_channel_is_elected(false, "Relay/TLS"));
        assert!(!mesh_channel_is_elected(false, "QUIC/UDP"));
        assert!(mesh_channel_is_elected(true, "QUIC/UDP"));
    }

    #[test]
    fn reliable_mesh_reconnect_starts_tcp_relay_before_pair_timeout() {
        let tcp_relay = RelayEndpoints {
            tcp: Some("127.0.0.1:45573".parse().unwrap()),
            udp: None,
        };
        let wait = mesh_reconnect_direct_wait(tcp_relay, true);
        assert_eq!(wait, Duration::from_millis(250));
        assert!(wait < mini_tunnel_relay::DEFAULT_PAIR_TIMEOUT);

        let both_relays = RelayEndpoints {
            tcp: tcp_relay.tcp,
            udp: Some("127.0.0.1:45574".parse().unwrap()),
        };
        assert_eq!(
            mesh_reconnect_direct_wait(both_relays, true),
            Duration::from_millis(250),
            "reliable fallback must not wait for UDP relay candidates"
        );
        assert_eq!(
            mesh_reconnect_direct_wait(both_relays, false),
            Duration::from_secs(10),
            "normal recovery still allows the direct/UDP relay grace"
        );

        assert_eq!(
            mesh_reconnect_direct_wait(RelayEndpoints::default(), true),
            Duration::from_secs(35),
            "without a relay, retain the longer direct TCP accept window"
        );
        assert_eq!(
            mesh_reconnect_direct_wait(tcp_relay, false),
            Duration::from_secs(65),
            "normal reconnect retains its direct-path grace"
        );
    }

    #[test]
    fn tun_uses_ipv4_only_when_optional_ipv6_setup_is_denied() {
        let config =
            mini_tunnel_agent::tun_device::TunConfig::ipv4(Ipv4Addr::new(10, 77, 0, 2), 24)
                .with_ipv6("fd00::2".parse().unwrap(), 64);
        let mut attempts = 0;
        let (device, ipv6_enabled, ipv6_error) = create_tun_with_ipv6_fallback(config, |config| {
            attempts += 1;
            if config.local_ipv6.is_some() {
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "IPv6 disabled by host",
                ))
            } else {
                Ok(config.local_ipv4)
            }
        })
        .expect("IPv4-only fallback succeeds");

        assert_eq!(attempts, 2);
        assert_eq!(device, Ipv4Addr::new(10, 77, 0, 2));
        assert!(!ipv6_enabled);
        assert_eq!(
            ipv6_error.expect("fallback records the IPv6 error").kind(),
            std::io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn tun_does_not_fallback_for_unrelated_creation_errors() {
        let config =
            mini_tunnel_agent::tun_device::TunConfig::ipv4(Ipv4Addr::new(10, 77, 0, 2), 24)
                .with_ipv6("fd00::2".parse().unwrap(), 64);
        let mut attempts = 0;
        let error = create_tun_with_ipv6_fallback(config, |_| {
            attempts += 1;
            Err::<(), _>(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "TUN device is unavailable",
            ))
        })
        .expect_err("unrelated TUN error remains fatal");

        assert_eq!(attempts, 1);
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn tun_reports_both_errors_when_ipv4_fallback_also_fails() {
        let config =
            mini_tunnel_agent::tun_device::TunConfig::ipv4(Ipv4Addr::new(10, 77, 0, 2), 24)
                .with_ipv6("fd00::2".parse().unwrap(), 64);
        let mut attempts = 0;
        let error = create_tun_with_ipv6_fallback(config, |_| {
            attempts += 1;
            let message = if attempts == 1 {
                "IPv6 disabled"
            } else {
                "TUN permission denied"
            };
            Err::<(), _>(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                message,
            ))
        })
        .expect_err("failed fallback is returned");

        assert_eq!(attempts, 2);
        assert!(error.to_string().contains("IPv6 disabled"));
        assert!(error.to_string().contains("TUN permission denied"));
    }

    #[test]
    fn ipv6_fallback_error_classifier_is_limited_to_host_capability_errors() {
        for kind in [
            std::io::ErrorKind::PermissionDenied,
            std::io::ErrorKind::Unsupported,
            std::io::ErrorKind::AddrNotAvailable,
        ] {
            assert!(ipv6_tun_setup_may_be_unsupported(&std::io::Error::from(
                kind
            )));
        }
        for kind in [
            std::io::ErrorKind::NotFound,
            std::io::ErrorKind::InvalidInput,
            std::io::ErrorKind::ConnectionRefused,
        ] {
            assert!(!ipv6_tun_setup_may_be_unsupported(&std::io::Error::from(
                kind
            )));
        }
    }

    #[test]
    fn candidate_update_signatures_use_coordinator_canonical_order() {
        let temp = std::env::temp_dir().join(format!(
            "mini-tunnel-candidate-signature-{}",
            uuid::Uuid::new_v4()
        ));
        let identity = mini_tunnel_agent::Identity::load_or_create_at(temp.join("device.key"))
            .expect("test identity");
        let device_id = identity.device_id();
        let candidates = vec!["198.51.100.9:42000".to_owned(), "10.0.0.2:42000".to_owned()];
        let mut canonical = candidates.clone();
        canonical.sort();
        assert_ne!(candidates, canonical);

        let signature =
            sign_candidate_update(&identity, "test-network", &device_id, 42, &candidates, None);
        assert_eq!(
            signature,
            identity.sign(&candidate_signing_bytes(
                "test-network",
                &device_id,
                42,
                &canonical,
            ))
        );

        let credentials = IceCredentials {
            ufrag: "local-ufrag".to_owned(),
            password: "local-password".to_owned(),
            generation: 1,
        };
        let ice_signature = sign_candidate_update(
            &identity,
            "test-network",
            &device_id,
            42,
            &candidates,
            Some(&credentials),
        );
        assert_eq!(
            ice_signature,
            identity.sign(&candidate_signing_bytes_with_ice(
                "test-network",
                &device_id,
                42,
                &canonical,
                &credentials,
            ))
        );
        std::fs::remove_dir_all(temp).expect("remove test identity");
    }

    fn secret_fixture(contents: &str) -> (PathBuf, PathBuf) {
        let directory = std::env::temp_dir().join(format!(
            "mini-tunnel-secret-test-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("ticket-key");
        std::fs::write(&path, contents).unwrap();
        (directory, path)
    }

    #[tokio::test]
    async fn peer_diagnostic_waits_for_authenticated_echo_before_succeeding() {
        let directory = std::env::temp_dir().join(format!(
            "mini-tunnel-peer-diagnostic-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let identity_a =
            mini_tunnel_agent::Identity::load_or_create_at(directory.join("a/device.key"))
                .expect("create first identity");
        let identity_b =
            mini_tunnel_agent::Identity::load_or_create_at(directory.join("b/device.key"))
                .expect("create second identity");
        let endpoint_a = mini_tunnel_agent::peer_endpoint(
            &identity_a,
            "127.0.0.1:0".parse().expect("parse bind address"),
        )
        .expect("bind client endpoint");
        let endpoint_b = mini_tunnel_agent::peer_endpoint(
            &identity_b,
            "127.0.0.1:0".parse().expect("parse bind address"),
        )
        .expect("bind server endpoint");
        let address_b = endpoint_b.local_addr().expect("read server endpoint");
        let network_id = format!("peer-diagnostic-{}", uuid::Uuid::new_v4());
        let expected_client_id = identity_a.device_id();
        let expected_client_key = identity_a.public_key();
        let expected_server_id = identity_b.device_id();
        let expected_server_key = identity_b.public_key();
        let server_network_id = network_id.clone();
        let server_task = tokio::spawn(async move {
            let channel = mini_tunnel_agent::accept_peer(
                &endpoint_b,
                &server_network_id,
                &identity_b,
                &expected_client_id,
                expected_client_key,
            )
            .await?;
            receive_and_echo_peer_diagnostic(&channel, Duration::from_millis(100)).await
        });

        let channel = mini_tunnel_agent::connect_peer(
            &endpoint_a,
            address_b,
            &network_id,
            &identity_a,
            &expected_server_id,
            expected_server_key,
        )
        .await
        .expect("connect authenticated peer");
        let message = b"diagnostic echo confirms delivery";
        send_peer_diagnostic_and_wait_for_echo(&channel, message)
            .await
            .expect("wait for peer echo");
        assert_eq!(
            server_task
                .await
                .expect("join server task")
                .expect("receive and echo"),
            message
        );

        channel.close();
        endpoint_a.close(0_u32.into(), b"diagnostic complete");
        std::fs::remove_dir_all(directory).expect("remove identities");
    }

    #[test]
    fn ticket_key_credential_file_takes_precedence_and_trims_whitespace() {
        let expected = [0x42; 32];
        let (directory, path) =
            secret_fixture(&format!(" \n{}\n\t", URL_SAFE_NO_PAD.encode(expected)));
        let actual = load_ticket_key(
            Some("this environment value must not be used"),
            Some(&path),
            "TICKET_KEY",
            "TICKET_KEY_FILE",
        )
        .unwrap();
        assert_eq!(actual, Some(expected));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn ticket_key_environment_value_remains_supported_and_trims_whitespace() {
        let expected = [0x24; 32];
        let encoded = format!("\n{} \t", URL_SAFE_NO_PAD.encode(expected));
        assert_eq!(
            load_ticket_key(Some(&encoded), None, "TICKET_KEY", "TICKET_KEY_FILE").unwrap(),
            Some(expected)
        );
    }

    #[test]
    fn ticket_key_credential_file_errors_do_not_disclose_secret_contents() {
        let (directory, missing_path) = secret_fixture("unused");
        std::fs::remove_file(&missing_path).unwrap();
        let missing_error =
            load_ticket_key(None, Some(&missing_path), "TICKET_KEY", "TICKET_KEY_FILE")
                .unwrap_err();
        assert!(missing_error.contains("TICKET_KEY_FILE"));

        std::fs::write(&missing_path, "not-a-ticket-key").unwrap();
        let malformed_error =
            load_ticket_key(None, Some(&missing_path), "TICKET_KEY", "TICKET_KEY_FILE")
                .unwrap_err();
        assert!(malformed_error.contains("TICKET_KEY_FILE"));
        assert!(!malformed_error.contains("not-a-ticket-key"));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn ticket_key_environment_value_is_optional_for_coordinator() {
        assert_eq!(
            load_ticket_key(None, None, "TICKET_KEY", "TICKET_KEY_FILE").unwrap(),
            None
        );
    }

    #[test]
    fn stun_mapping_observation_summarizes_only_the_sample() {
        let server_a: SocketAddr = "192.0.2.10:3478".parse().unwrap();
        let server_b: SocketAddr = "192.0.2.11:3478".parse().unwrap();
        let mapped_a: SocketAddr = "198.51.100.20:50000".parse().unwrap();
        let mapped_b: SocketAddr = "198.51.100.20:50001".parse().unwrap();
        let mapping = |server, mapped| StunMapping {
            server,
            mapped,
            related: "10.0.0.2:40000".parse().unwrap(),
        };

        assert_eq!(
            observe_stun_mappings(&[]),
            StunMappingObservation::Unavailable
        );
        assert_eq!(
            observe_stun_mappings(&[mapping(server_a, mapped_a)]),
            StunMappingObservation::SingleDestination
        );
        assert_eq!(
            observe_stun_mappings(&[mapping(server_a, mapped_a), mapping(server_b, mapped_a),]),
            StunMappingObservation::ConsistentSample
        );
        assert_eq!(
            observe_stun_mappings(&[mapping(server_a, mapped_a), mapping(server_b, mapped_b),]),
            StunMappingObservation::VaryingSample
        );
    }

    #[test]
    fn stun_servers_are_deduplicated_and_bounded() {
        let first: SocketAddr = "192.0.2.10:3478".parse().unwrap();
        let second: SocketAddr = "192.0.2.11:3478".parse().unwrap();
        assert_eq!(
            normalize_stun_servers(vec![first, first, second]).unwrap(),
            vec![first, second]
        );
        let too_many = (0..=MAX_STUN_SERVERS)
            .map(|index| SocketAddr::new("192.0.2.10".parse().unwrap(), 3478 + index as u16))
            .collect();
        assert!(normalize_stun_servers(too_many).is_err());
    }

    #[test]
    fn divergent_stun_mappings_are_published_and_refresh_replaces_only_that_server() {
        let related: SocketAddr = "10.0.0.4:42000".parse().unwrap();
        let server_a: SocketAddr = "192.0.2.10:3478".parse().unwrap();
        let server_b: SocketAddr = "192.0.2.11:3478".parse().unwrap();
        let mapping_a = StunMapping {
            server: server_a,
            mapped: "198.51.100.10:40000".parse().unwrap(),
            related,
        };
        let mapping_b = StunMapping {
            server: server_b,
            mapped: "198.51.100.11:41000".parse().unwrap(),
            related,
        };
        let mapping_c = StunMapping {
            server: "192.0.2.12:3478".parse().unwrap(),
            mapped: "198.51.100.12:42000".parse().unwrap(),
            related,
        };
        let mapping_d = StunMapping {
            server: "192.0.2.13:3478".parse().unwrap(),
            mapped: "198.51.100.13:43000".parse().unwrap(),
            related,
        };
        let mut mappings = vec![
            mapping_a.clone(),
            mapping_b.clone(),
            mapping_c.clone(),
            mapping_d.clone(),
        ];
        let mut candidates = compose_ice_candidates(
            &["tcp://203.0.113.9:443".to_owned()],
            Some(related),
            &mappings,
            (1..=12)
                .map(|last| SocketAddr::new(Ipv4Addr::new(10, 0, 1, last).into(), 42000))
                .collect(),
            4,
        )
        .unwrap();
        assert_eq!(candidates.len(), MAX_PEER_CANDIDATES);
        assert_eq!(candidates[0], "tcp://203.0.113.9:443");
        assert!(candidates.contains(&format!("srflx://{}|{related}", mapping_a.mapped)));
        assert!(candidates.contains(&format!("srflx://{}|{related}", mapping_b.mapped)));
        assert!(candidates.contains(&format!("srflx://{}|{related}", mapping_c.mapped)));
        assert!(candidates.contains(&format!("srflx://{}|{related}", mapping_d.mapped)));

        let changed_a = StunMapping {
            mapped: "198.51.100.20:42000".parse().unwrap(),
            ..mapping_a.clone()
        };
        assert!(merge_stun_mappings(&mut mappings, vec![changed_a.clone()]));
        assert!(!merge_stun_mappings(&mut mappings, Vec::new()));
        candidates = compose_ice_candidates(
            &["tcp://203.0.113.9:443".to_owned()],
            Some(related),
            &mappings,
            Vec::new(),
            4,
        )
        .unwrap();
        assert!(candidates.contains(&format!("srflx://{}|{related}", changed_a.mapped)));
        assert!(!candidates.contains(&format!("srflx://{}|{related}", mapping_a.mapped)));
        assert!(candidates.contains(&format!("srflx://{}|{related}", mapping_b.mapped)));
    }

    #[test]
    fn host_candidate_refresh_replaces_old_addresses_and_retains_snapshot_on_error() {
        let old_host: SocketAddr = "10.0.0.4:42000".parse().unwrap();
        let current_host: SocketAddr = "10.1.0.4:42000".parse().unwrap();
        let explicit = vec!["tcp://203.0.113.9:443".to_owned()];
        let current_hosts =
            refreshed_host_candidate_snapshot(&[old_host], Ok(vec![current_host, current_host]));
        assert_eq!(current_hosts, vec![current_host]);
        let mapping = StunMapping {
            server: "192.0.2.53:3478".parse().unwrap(),
            mapped: "198.51.100.25:52000".parse().unwrap(),
            related: old_host,
        };
        let wildcard: SocketAddr = "0.0.0.0:42000".parse().unwrap();
        let primary_host =
            current_primary_host(wildcard, std::slice::from_ref(&mapping), &current_hosts);
        assert_eq!(primary_host, Some(current_host));
        let ice_candidates = compose_ice_candidates(
            &explicit,
            primary_host,
            std::slice::from_ref(&mapping),
            current_hosts.clone(),
            1,
        )
        .unwrap();
        assert_eq!(ice_candidates[0], explicit[0]);
        assert!(ice_candidates.contains(&current_host.to_string()));
        assert!(!ice_candidates.contains(&old_host.to_string()));

        let failed_refresh = refreshed_host_candidate_snapshot(
            &current_hosts,
            Err(std::io::Error::other("interface enumeration unavailable")),
        );
        assert_eq!(failed_refresh, current_hosts);
        let non_ice_candidates = compose_non_ice_candidates(
            &explicit,
            current_primary_host(wildcard, std::slice::from_ref(&mapping), &failed_refresh),
            std::slice::from_ref(&mapping),
            failed_refresh,
            1,
        )
        .unwrap();
        assert_eq!(non_ice_candidates[0], explicit[0]);
        assert!(non_ice_candidates.contains(&current_host.to_string()));
        assert!(!non_ice_candidates.contains(&old_host.to_string()));
    }

    #[tokio::test]
    async fn gathers_multiple_stun_servers_when_one_server_is_silent() {
        let temp =
            std::env::temp_dir().join(format!("mini-tunnel-multi-stun-{}", uuid::Uuid::new_v4()));
        let identity = mini_tunnel_agent::Identity::load_or_create_at(temp.join("device.key"))
            .expect("load identity");
        let responder = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind responsive STUN endpoint");
        let responder_address = responder.local_addr().unwrap();
        let silent = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind silent STUN endpoint");
        let silent_address = silent.local_addr().unwrap();
        let mapped: SocketAddr = "198.51.100.31:53000".parse().unwrap();
        let responder_task = tokio::spawn(async move {
            let mut request = [0; 128];
            let (length, peer) = responder.recv_from(&mut request).await.unwrap();
            assert_eq!(length, 20);
            let cookie: [u8; 4] = request[4..8].try_into().unwrap();
            let mut response = vec![0; 32];
            response[..2].copy_from_slice(&0x0101_u16.to_be_bytes());
            response[2..4].copy_from_slice(&12_u16.to_be_bytes());
            response[4..8].copy_from_slice(&cookie);
            response[8..20].copy_from_slice(&request[8..20]);
            response[20..22].copy_from_slice(&0x0020_u16.to_be_bytes());
            response[22..24].copy_from_slice(&8_u16.to_be_bytes());
            response[25] = 1;
            response[26..28].copy_from_slice(&(mapped.port() ^ 0x2112_u16).to_be_bytes());
            let std::net::IpAddr::V4(mapped_ip) = mapped.ip() else {
                unreachable!()
            };
            for (target, (address, mask)) in response[28..32]
                .iter_mut()
                .zip(mapped_ip.octets().into_iter().zip(cookie))
            {
                *target = address ^ mask;
            }
            responder.send_to(&response, peer).await.unwrap();
        });
        let (endpoint, mappings) = tokio::time::timeout(
            Duration::from_secs(5),
            peer_endpoint_with_optional_stun(
                &identity,
                "127.0.0.1:0".parse().unwrap(),
                &[silent_address, responder_address],
                8,
            ),
        )
        .await
        .expect("parallel discovery is bounded")
        .expect("endpoint starts despite a failed STUN server");
        responder_task.await.expect("join STUN responder");
        assert_eq!(mappings.len(), 1);
        assert_eq!(mappings[0].server, responder_address);
        assert_eq!(mappings[0].mapped, mapped);
        endpoint.endpoint.close(0_u32.into(), b"test complete");
        std::fs::remove_dir_all(temp).expect("remove test identity");
    }

    #[tokio::test]
    async fn tunnel_endpoint_publishes_divergent_stun_mappings_from_same_socket() {
        let requests = std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let coordinator_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock coordinator");
        let coordinator = coordinator_listener.local_addr().unwrap();
        let app = Router::new()
            .route(
                "/v1/networks/multi-stun/candidates",
                axum::routing::post(capture_candidate_update),
            )
            .with_state(std::sync::Arc::clone(&requests));
        let coordinator_task =
            tokio::spawn(async move { axum::serve(coordinator_listener, app).await });
        let responder_a = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind STUN server A");
        let responder_b = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind STUN server B");
        let server_a = responder_a.local_addr().unwrap();
        let server_b = responder_b.local_addr().unwrap();
        let mapped_a: SocketAddr = "198.51.100.41:51001".parse().unwrap();
        let mapped_b: SocketAddr = "198.51.100.42:51002".parse().unwrap();
        let responder_task_a = spawn_stun_mapping_responder(responder_a, mapped_a);
        let responder_task_b = spawn_stun_mapping_responder(responder_b, mapped_b);
        let temp = std::env::temp_dir().join(format!(
            "mini-tunnel-publish-multi-stun-{}",
            uuid::Uuid::new_v4()
        ));
        let identity = mini_tunnel_agent::Identity::load_or_create_at(temp.join("device.key"))
            .expect("load identity");
        let endpoint = create_tunnel_endpoint(
            &identity,
            "127.0.0.1:0".parse().unwrap(),
            vec![server_a, server_b],
            true,
            &[],
            "multi-stun",
            &format!("http://{coordinator}"),
        )
        .await
        .expect("create tunnel with two STUN servers");
        responder_task_a.await.expect("join STUN responder A");
        responder_task_b.await.expect("join STUN responder B");
        let published = requests.lock().await;
        assert_eq!(published.len(), 1);
        let candidates = &published[0].candidates;
        let related = endpoint.ice.as_ref().unwrap().local_socket_addr;
        assert!(candidates.contains(&format!("srflx://{mapped_a}|{related}")));
        assert!(candidates.contains(&format!("srflx://{mapped_b}|{related}")));
        assert_eq!(
            endpoint.ice.as_ref().unwrap().local_socket_addr,
            endpoint.ice.as_ref().unwrap().socket.local_addr().unwrap()
        );
        drop(published);
        endpoint.endpoint.close(0_u32.into(), b"test complete");
        coordinator_task.abort();
        std::fs::remove_dir_all(temp).expect("remove test identity");
    }

    #[tokio::test]
    async fn tunnel_endpoint_survives_initial_stun_failure_for_later_mapping_refresh() {
        let temp = std::env::temp_dir().join(format!(
            "mini-tunnel-stun-recovery-{}",
            uuid::Uuid::new_v4()
        ));
        let identity = mini_tunnel_agent::Identity::load_or_create_at(temp.join("device.key"))
            .expect("load identity");
        let unavailable_stun = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind silent STUN endpoint");
        let (endpoint, initial_mapping) = tokio::time::timeout(
            Duration::from_secs(10),
            peer_endpoint_with_optional_stun(
                &identity,
                "127.0.0.1:0".parse().unwrap(),
                &[unavailable_stun.local_addr().unwrap()],
                8,
            ),
        )
        .await
        .expect("initial STUN retries are bounded")
        .expect("STUN failure does not prevent endpoint startup");
        assert!(initial_mapping.is_empty());
        let local_address = endpoint.socket.local_addr().expect("tunnel UDP socket");

        let recovery_stun = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind recovery STUN endpoint");
        let recovery_address = recovery_stun.local_addr().expect("STUN address");
        let responder = tokio::spawn(async move {
            let mut request = [0; 128];
            let (length, peer) = recovery_stun
                .recv_from(&mut request)
                .await
                .expect("receive later STUN refresh");
            assert_eq!(length, 20);
            let transaction: [u8; 12] = request[8..20].try_into().expect("transaction ID");
            let mapped: SocketAddr = "198.51.100.50:52345".parse().unwrap();
            let cookie = 0x2112_A442_u32;
            let mut response = vec![0; 32];
            response[..2].copy_from_slice(&0x0101_u16.to_be_bytes());
            response[2..4].copy_from_slice(&12_u16.to_be_bytes());
            response[4..8].copy_from_slice(&cookie.to_be_bytes());
            response[8..20].copy_from_slice(&transaction);
            response[20..22].copy_from_slice(&0x0020_u16.to_be_bytes());
            response[22..24].copy_from_slice(&8_u16.to_be_bytes());
            response[25] = 1;
            response[26..28]
                .copy_from_slice(&(mapped.port() ^ (cookie >> 16) as u16).to_be_bytes());
            let mapped_ip = match mapped.ip() {
                std::net::IpAddr::V4(address) => address.octets(),
                std::net::IpAddr::V6(_) => unreachable!("test mapping is IPv4"),
            };
            for (target, (address, mask)) in response[28..32]
                .iter_mut()
                .zip(mapped_ip.into_iter().zip(cookie.to_be_bytes()))
            {
                *target = address ^ mask;
            }
            recovery_stun
                .send_to(&response, peer)
                .await
                .expect("send later mapping response");
            mapped
        });
        let recovered_mapping = endpoint
            .ice_router
            .discover_mapped_address(&endpoint.socket, recovery_address)
            .await
            .expect("later STUN refresh succeeds on the surviving tunnel socket");
        assert_eq!(
            recovered_mapping,
            responder.await.expect("join STUN responder")
        );
        assert_eq!(
            endpoint.socket.local_addr().expect("same tunnel socket"),
            local_address
        );
        endpoint.endpoint.close(0_u32.into(), b"test complete");
        std::fs::remove_dir_all(temp).expect("remove test identity");
    }

    #[test]
    fn ice_candidate_refresh_recovers_mapping_and_updates_changed_related_address() {
        let server: SocketAddr = "192.0.2.53:3478".parse().unwrap();
        let mapping: SocketAddr = "203.0.113.9:52000".parse().unwrap();
        let new_mapping: SocketAddr = "203.0.113.10:53000".parse().unwrap();
        let old_related: SocketAddr = "10.0.0.4:42000".parse().unwrap();
        let new_related: SocketAddr = "10.1.0.4:42000".parse().unwrap();
        let explicit = vec!["tcp://198.51.100.9:443".to_owned()];
        let old = StunMapping {
            server,
            mapped: mapping,
            related: old_related,
        };
        let mut mappings = Vec::new();
        assert!(merge_stun_mappings(&mut mappings, vec![old.clone()]));
        let candidates = compose_ice_candidates(
            &explicit,
            Some(old_related),
            &mappings,
            vec![old_related],
            1,
        )
        .unwrap();
        assert_eq!(candidates[1], format!("srflx://{mapping}|{old_related}"));

        assert!(merge_stun_mappings(
            &mut mappings,
            vec![StunMapping {
                related: new_related,
                ..old.clone()
            }]
        ));
        assert!(merge_stun_mappings(
            &mut mappings,
            vec![StunMapping {
                mapped: new_mapping,
                related: new_related,
                ..old
            }]
        ));
        let candidates = compose_ice_candidates(
            &explicit,
            Some(new_related),
            &mappings,
            vec![new_related],
            1,
        )
        .unwrap();
        assert_eq!(
            candidates[1],
            format!("srflx://{new_mapping}|{new_related}")
        );
        assert!(!candidates.contains(&format!("srflx://{mapping}|{old_related}")));
        let full_explicit = (1..=MAX_PEER_CANDIDATES)
            .map(|port| format!("10.0.0.1:{port}"))
            .collect::<Vec<_>>();
        assert!(compose_ice_candidates(&full_explicit, None, &[], Vec::new(), 1).is_err());
    }

    #[test]
    fn peer_status_listener_refuses_non_loopback_addresses() {
        assert!(validate_status_address("127.0.0.1:42003".parse().unwrap()).is_ok());
        assert!(validate_status_address("[::1]:42003".parse().unwrap()).is_ok());
        assert!(validate_status_address("0.0.0.0:42003".parse().unwrap()).is_err());
        assert!(validate_status_address("192.0.2.1:42003".parse().unwrap()).is_err());
    }

    #[test]
    fn peer_status_command_is_available_without_network_credentials() {
        let cli = Cli::try_parse_from(["mini-tunnel", "peer", "status"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Peer {
                command: PeerCommand::Status { .. }
            }
        ));
    }

    #[tokio::test]
    async fn expired_ice_candidate_is_rejected_while_reliable_channel_keeps_carrying_packets() {
        let temp = std::env::temp_dir().join(format!(
            "mini-tunnel-ice-promotion-probation-{}",
            uuid::Uuid::new_v4()
        ));
        let a = std::sync::Arc::new(
            mini_tunnel_agent::Identity::load_or_create_at(temp.join("a/key"))
                .expect("local identity"),
        );
        let b = std::sync::Arc::new(
            mini_tunnel_agent::Identity::load_or_create_at(temp.join("b/key"))
                .expect("peer identity"),
        );

        let listener = mini_tunnel_agent::peer_tcp_listener("127.0.0.1:0".parse().unwrap())
            .await
            .expect("bind reliable path");
        let allowed = vec![(a.device_id(), a.public_key())];
        let accepted = mini_tunnel_agent::accept_tcp_peer_any(
            &listener,
            "ice-promotion-probation",
            &b,
            &allowed,
        );
        let b_id = b.device_id();
        let connected = mini_tunnel_agent::connect_tcp_peer(
            listener.local_addr().unwrap(),
            "ice-promotion-probation",
            &a,
            &b_id,
            b.public_key(),
        );
        let (active_remote, active) = tokio::join!(accepted, connected);
        let active_remote = active_remote.expect("accept reliable peer").1;
        let active = active.expect("connect reliable peer");

        let endpoint_a = mini_tunnel_agent::peer_endpoint(&a, "127.0.0.1:0".parse().unwrap())
            .expect("bind candidate endpoint");
        let endpoint_b = mini_tunnel_agent::peer_endpoint(&b, "127.0.0.1:0".parse().unwrap())
            .expect("bind candidate accept endpoint");
        let accepting = {
            let endpoint = endpoint_b.clone();
            let identity = std::sync::Arc::clone(&b);
            let peer_id = a.device_id();
            let peer_key = a.public_key();
            tokio::spawn(async move {
                mini_tunnel_agent::accept_peer(
                    &endpoint,
                    "ice-promotion-probation",
                    &identity,
                    &peer_id,
                    peer_key,
                )
                .await
                .expect("accept provisional UDP channel")
            })
        };
        let mut candidate = mini_tunnel_agent::connect_peer(
            &endpoint_a,
            endpoint_b.local_addr().unwrap(),
            "ice-promotion-probation",
            &a,
            &b.device_id(),
            b.public_key(),
        )
        .await
        .expect("connect provisional UDP channel");
        let candidate_remote = accepting.await.expect("join accept task");
        let candidate_responder =
            tokio::spawn(async move { while candidate_remote.recv_packet().await.is_ok() {} });
        let (monitor, mut cancel, failure_sender) =
            mini_tunnel_agent::ice::IceConsentMonitor::new();
        monitor
            .set_task(tokio::spawn(async move {
                tokio::select! {
                    () = tokio::time::sleep(Duration::from_millis(250)) => {
                        failure_sender.send_replace(true);
                    }
                    _ = cancel.changed() => {}
                }
            }))
            .await;
        candidate.set_ice_consent_monitor(monitor);
        let validation = tokio::spawn(validate_udp_probe_with_window(
            candidate,
            true,
            Duration::from_secs(1),
        ));

        let before_expiry = vec![1, 2, 3, 4];
        active
            .send_packet(&before_expiry)
            .await
            .expect("incumbent path should remain active during probation");
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), active_remote.recv_packet())
                .await
                .expect("reliable packet timeout")
                .expect("receive over incumbent reliable path"),
            before_expiry
        );

        let rejected = match validation.await.expect("join candidate validation") {
            Ok(_) => panic!("expired consent must reject the UDP candidate"),
            Err(error) => error,
        };
        assert!(rejected.to_string().contains("ICE consent expired"));

        let after_expiry = vec![5, 6, 7, 8];
        active
            .send_packet(&after_expiry)
            .await
            .expect("incumbent path should survive rejected candidate");
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), active_remote.recv_packet())
                .await
                .expect("post-expiry reliable packet timeout")
                .expect("receive after candidate rejection"),
            after_expiry
        );
        candidate_responder.abort();
        active.close_async().await;
        active_remote.close_async().await;
        endpoint_a.close(0_u32.into(), b"test complete");
        endpoint_b.close(0_u32.into(), b"test complete");
        std::fs::remove_dir_all(temp).expect("remove test identities");
    }

    #[tokio::test]
    async fn elected_inbound_channel_inherits_monitor_from_reverse_probe() {
        let temp = std::env::temp_dir().join(format!(
            "mini-tunnel-ice-monitor-transfer-{}",
            uuid::Uuid::new_v4()
        ));
        let a = std::sync::Arc::new(
            mini_tunnel_agent::Identity::load_or_create_at(temp.join("a/key"))
                .expect("local identity"),
        );
        let b = std::sync::Arc::new(
            mini_tunnel_agent::Identity::load_or_create_at(temp.join("b/key"))
                .expect("peer identity"),
        );
        let local_endpoint =
            mini_tunnel_agent::peer_endpoint(&a, "127.0.0.1:0".parse().expect("local address"))
                .expect("local endpoint");
        let peer_endpoint =
            mini_tunnel_agent::peer_endpoint(&b, "127.0.0.1:0".parse().expect("peer address"))
                .expect("peer endpoint");
        let local_peer_id = a.device_id();
        let local_peer_key = a.public_key();
        let peer_id = b.device_id();
        let peer_key = b.public_key();
        let accept_probe = {
            let endpoint = peer_endpoint.clone();
            let identity = std::sync::Arc::clone(&b);
            let expected_peer_id = local_peer_id.clone();
            tokio::spawn(async move {
                mini_tunnel_agent::accept_peer(
                    &endpoint,
                    "ice-monitor-transfer",
                    &identity,
                    &expected_peer_id,
                    local_peer_key,
                )
                .await
                .expect("accept reverse probe")
            })
        };
        let mut probe = mini_tunnel_agent::connect_peer(
            &local_endpoint,
            peer_endpoint.local_addr().expect("peer socket"),
            "ice-monitor-transfer",
            &a,
            &peer_id,
            peer_key,
        )
        .await
        .expect("connect reverse probe");
        let probe_remote = accept_probe.await.expect("join probe accept task");
        let accept_winner = {
            let endpoint = peer_endpoint.clone();
            let identity = std::sync::Arc::clone(&b);
            let expected_peer_id = local_peer_id.clone();
            tokio::spawn(async move {
                mini_tunnel_agent::accept_peer(
                    &endpoint,
                    "ice-monitor-transfer",
                    &identity,
                    &expected_peer_id,
                    local_peer_key,
                )
                .await
                .expect("accept elected inbound channel")
            })
        };
        let mut winner = mini_tunnel_agent::connect_peer(
            &local_endpoint,
            peer_endpoint.local_addr().expect("peer socket"),
            "ice-monitor-transfer",
            &a,
            &peer_id,
            peer_key,
        )
        .await
        .expect("connect elected data path");
        let winner_remote = accept_winner.await.expect("join winner accept task");

        let (monitor, mut cancel, failure_sender) =
            mini_tunnel_agent::ice::IceConsentMonitor::new();
        monitor
            .set_task(tokio::spawn(async move {
                tokio::select! {
                    () = tokio::time::sleep(Duration::from_millis(100)) => {
                        failure_sender.send_replace(true);
                    }
                    _ = cancel.changed() => {}
                }
            }))
            .await;
        probe.set_ice_consent_monitor(monitor);

        assert!(transfer_peer_ice_consent_monitor(&mut probe, &mut winner));
        assert!(!probe.has_ice_consent_monitor());
        assert!(winner.has_ice_consent_monitor());
        assert!(
            tokio::time::timeout(Duration::from_secs(1), winner.wait_ice_consent_failure())
                .await
                .is_ok()
        );

        winner.stop_ice_consent_monitor().await;
        winner.close_async().await;
        winner_remote.close_async().await;
        probe_remote.close_async().await;
        local_endpoint.close(0_u32.into(), b"test complete");
        peer_endpoint.close(0_u32.into(), b"test complete");
        std::fs::remove_dir_all(temp).expect("remove test identities");
    }

    #[tokio::test]
    async fn non_ice_direct_candidate_requires_sustained_health_probation() {
        let temp = std::env::temp_dir().join(format!(
            "mini-tunnel-direct-promotion-probation-{}",
            uuid::Uuid::new_v4()
        ));
        let a = std::sync::Arc::new(
            mini_tunnel_agent::Identity::load_or_create_at(temp.join("a/key"))
                .expect("local identity"),
        );
        let b = std::sync::Arc::new(
            mini_tunnel_agent::Identity::load_or_create_at(temp.join("b/key"))
                .expect("peer identity"),
        );
        let endpoint_a = mini_tunnel_agent::peer_endpoint(&a, "127.0.0.1:0".parse().unwrap())
            .expect("bind local UDP endpoint");
        let endpoint_b = mini_tunnel_agent::peer_endpoint(&b, "127.0.0.1:0".parse().unwrap())
            .expect("bind peer UDP endpoint");
        let accepting = {
            let endpoint = endpoint_b.clone();
            let identity = std::sync::Arc::clone(&b);
            let peer_id = a.device_id();
            let peer_key = a.public_key();
            tokio::spawn(async move {
                mini_tunnel_agent::accept_peer(
                    &endpoint,
                    "direct-promotion-probation",
                    &identity,
                    &peer_id,
                    peer_key,
                )
                .await
                .expect("accept provisional UDP channel")
            })
        };
        let candidate = mini_tunnel_agent::connect_peer(
            &endpoint_a,
            endpoint_b.local_addr().unwrap(),
            "direct-promotion-probation",
            &a,
            &b.device_id(),
            b.public_key(),
        )
        .await
        .expect("connect provisional UDP channel");
        let candidate_remote = accepting.await.expect("join accept task");
        let responder =
            tokio::spawn(async move { while candidate_remote.recv_packet().await.is_ok() {} });

        let started = tokio::time::Instant::now();
        let candidate = validate_udp_probe_with_timing(
            candidate,
            false,
            Duration::from_millis(300),
            Duration::from_millis(50),
        )
        .await
        .expect("healthy non-ICE candidate survives probation");
        assert!(started.elapsed() >= Duration::from_millis(300));
        assert!(candidate.health_snapshot().probes_succeeded >= 9);

        candidate.close_async().await;
        responder.abort();
        endpoint_a.close(0_u32.into(), b"test complete");
        endpoint_b.close(0_u32.into(), b"test complete");
        std::fs::remove_dir_all(temp).expect("remove test identities");
    }

    #[tokio::test]
    async fn non_ice_candidate_failure_during_probation_leaves_reliable_path_usable() {
        let temp = std::env::temp_dir().join(format!(
            "mini-tunnel-direct-promotion-failure-{}",
            uuid::Uuid::new_v4()
        ));
        let a = std::sync::Arc::new(
            mini_tunnel_agent::Identity::load_or_create_at(temp.join("a/key"))
                .expect("local identity"),
        );
        let b = std::sync::Arc::new(
            mini_tunnel_agent::Identity::load_or_create_at(temp.join("b/key"))
                .expect("peer identity"),
        );

        let listener = mini_tunnel_agent::peer_tcp_listener("127.0.0.1:0".parse().unwrap())
            .await
            .expect("bind reliable path");
        let allowed = [(a.device_id(), a.public_key())];
        let b_id = b.device_id();
        let accepted = mini_tunnel_agent::accept_tcp_peer_any(
            &listener,
            "direct-promotion-failure",
            &b,
            &allowed,
        );
        let connected = mini_tunnel_agent::connect_tcp_peer(
            listener.local_addr().unwrap(),
            "direct-promotion-failure",
            &a,
            &b_id,
            b.public_key(),
        );
        let (active_remote, active) = tokio::join!(accepted, connected);
        let active_remote = active_remote.expect("accept reliable peer").1;
        let active = active.expect("connect reliable peer");

        let endpoint_a = mini_tunnel_agent::peer_endpoint(&a, "127.0.0.1:0".parse().unwrap())
            .expect("bind local UDP endpoint");
        let endpoint_b = mini_tunnel_agent::peer_endpoint(&b, "127.0.0.1:0".parse().unwrap())
            .expect("bind peer UDP endpoint");
        let accepting = {
            let endpoint = endpoint_b.clone();
            let identity = std::sync::Arc::clone(&b);
            let peer_id = a.device_id();
            let peer_key = a.public_key();
            tokio::spawn(async move {
                mini_tunnel_agent::accept_peer(
                    &endpoint,
                    "direct-promotion-failure",
                    &identity,
                    &peer_id,
                    peer_key,
                )
                .await
                .expect("accept provisional UDP channel")
            })
        };
        let candidate = mini_tunnel_agent::connect_peer(
            &endpoint_a,
            endpoint_b.local_addr().unwrap(),
            "direct-promotion-failure",
            &a,
            &b.device_id(),
            b.public_key(),
        )
        .await
        .expect("connect provisional UDP channel");
        let candidate_remote = accepting.await.expect("join accept task");
        let responder =
            tokio::spawn(async move { while candidate_remote.recv_packet().await.is_ok() {} });
        let failed_endpoint = endpoint_b.clone();
        let close_candidate = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(150)).await;
            failed_endpoint.close(0_u32.into(), b"simulated UDP path loss");
        });

        let result = validate_udp_probe_with_timing(
            candidate,
            false,
            Duration::from_millis(500),
            Duration::from_millis(50),
        )
        .await;
        assert!(result.is_err(), "failed candidate must not pass probation");
        close_candidate.await.expect("close direct candidate");

        let packet = vec![1, 2, 3, 4];
        active
            .send_packet(&packet)
            .await
            .expect("reliable path remains active after candidate rejection");
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), active_remote.recv_packet())
                .await
                .expect("reliable packet timeout")
                .expect("receive on reliable path"),
            packet
        );

        responder.abort();
        active.close_async().await;
        active_remote.close_async().await;
        endpoint_a.close(0_u32.into(), b"test complete");
        endpoint_b.close(0_u32.into(), b"test complete");
        std::fs::remove_dir_all(temp).expect("remove test identities");
    }

    #[tokio::test]
    async fn ice_candidate_promotes_only_after_consent_probation_window() {
        let temp = std::env::temp_dir().join(format!(
            "mini-tunnel-ice-promotion-healthy-{}",
            uuid::Uuid::new_v4()
        ));
        let a = std::sync::Arc::new(
            mini_tunnel_agent::Identity::load_or_create_at(temp.join("a/key"))
                .expect("local identity"),
        );
        let b = std::sync::Arc::new(
            mini_tunnel_agent::Identity::load_or_create_at(temp.join("b/key"))
                .expect("peer identity"),
        );
        let endpoint_a = mini_tunnel_agent::peer_endpoint(&a, "127.0.0.1:0".parse().unwrap())
            .expect("bind candidate endpoint");
        let endpoint_b = mini_tunnel_agent::peer_endpoint(&b, "127.0.0.1:0".parse().unwrap())
            .expect("bind candidate accept endpoint");
        let accepting = {
            let endpoint = endpoint_b.clone();
            let identity = std::sync::Arc::clone(&b);
            let peer_id = a.device_id();
            let peer_key = a.public_key();
            tokio::spawn(async move {
                mini_tunnel_agent::accept_peer(
                    &endpoint,
                    "ice-promotion-healthy",
                    &identity,
                    &peer_id,
                    peer_key,
                )
                .await
                .expect("accept provisional UDP channel")
            })
        };
        let mut candidate = mini_tunnel_agent::connect_peer(
            &endpoint_a,
            endpoint_b.local_addr().unwrap(),
            "ice-promotion-healthy",
            &a,
            &b.device_id(),
            b.public_key(),
        )
        .await
        .expect("connect provisional UDP channel");
        let candidate_remote = accepting.await.expect("join accept task");
        let candidate_responder =
            tokio::spawn(async move { while candidate_remote.recv_packet().await.is_ok() {} });
        let (monitor, mut cancel, _failure_sender) =
            mini_tunnel_agent::ice::IceConsentMonitor::new();
        monitor
            .set_task(tokio::spawn(async move {
                let _ = cancel.changed().await;
            }))
            .await;
        candidate.set_ice_consent_monitor(monitor);
        let started = tokio::time::Instant::now();
        let candidate = validate_udp_probe_with_timing(
            candidate,
            true,
            Duration::from_millis(400),
            Duration::from_millis(40),
        )
        .await
        .expect("candidate with live consent survives probation");
        assert!(started.elapsed() >= Duration::from_millis(400));
        assert!(candidate.has_ice_consent_monitor());
        assert!(candidate.health_snapshot().probes_succeeded >= 4);
        candidate.stop_ice_consent_monitor().await;
        candidate_responder.abort();
        endpoint_a.close(0_u32.into(), b"test complete");
        endpoint_b.close(0_u32.into(), b"test complete");
        std::fs::remove_dir_all(temp).expect("remove test identities");
    }

    #[tokio::test]
    async fn peer_status_http_endpoint_returns_live_quality_without_credentials() {
        let peer = format!("status-http-{}", uuid::Uuid::new_v4());
        mini_tunnel_agent::status::update(
            peer.clone(),
            true,
            "TLS/TCP",
            Some(57),
            18,
            2,
            Some("quality_threshold"),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind status listener");
        let address = listener.local_addr().expect("status listener address");
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new()
                    .route("/status", get(peer_status))
                    .route("/metrics", get(peer_metrics)),
            )
            .await
        });
        let response = reqwest::get(format!("http://{address}/status"))
            .await
            .expect("query live peer status")
            .error_for_status()
            .expect("status response");
        let body = response.text().await.expect("status body");
        let peers: Vec<mini_tunnel_agent::status::PeerStatus> =
            serde_json::from_str(&body).expect("deserialize status response");
        let status = peers
            .into_iter()
            .find(|status| status.peer == peer)
            .expect("test peer is present in live status response");
        assert!(status.online);
        assert_eq!(status.active_path, "TLS/TCP");
        assert_eq!(status.rtt_ms, Some(57));
        assert_eq!(status.loss_percent, Some(10));
        assert_eq!(
            status.last_switch_reason.as_deref(),
            Some("quality_threshold")
        );
        assert!(!body.contains("credential"));
        assert!(!body.contains("candidate"));

        let metrics_response = reqwest::get(format!("http://{address}/metrics"))
            .await
            .expect("query aggregate peer metrics")
            .error_for_status()
            .expect("metrics response");
        assert_eq!(
            metrics_response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("text/plain; version=0.0.4; charset=utf-8")
        );
        let metrics = metrics_response.text().await.expect("metrics body");
        assert!(metrics.contains("mini_tunnel_peer_online_count"));
        assert!(metrics.contains("mini_tunnel_peer_rtt_ms_max"));
        assert!(!metrics.contains(&peer));
        server.abort();
    }

    #[test]
    fn peer_diagnostics_summarize_candidates_without_exposing_addresses_or_keys() {
        let peers = vec![PeerInfo {
            device_id: "device-1".to_owned(),
            assigned_ipv4: "10.42.0.2".to_owned(),
            public_key: "private-looking-public-key".to_owned(),
            candidates: vec![
                "192.0.2.10:42000".to_owned(),
                "srflx://198.51.100.20:53000|10.0.0.2:42000".to_owned(),
                "tcp://203.0.113.5:443".to_owned(),
            ],
            ice_credentials: Some(mini_tunnel_protocol::IceCredentials {
                ufrag: "secret-fragment".to_owned(),
                password: "secret-password".to_owned(),
                generation: 7,
            }),
        }];

        let output = format_peer_diagnostics(&peers);
        assert!(output.contains("Same-network peers: 1"));
        assert!(output.contains("UDP candidates=2, TCP candidates=1, ICE credentials=published"));
        assert!(!output.contains("192.0.2.10"));
        assert!(!output.contains("private-looking-public-key"));
        assert!(!output.contains("secret-fragment"));
        assert!(!output.contains("secret-password"));
    }

    async fn ice_peer_snapshot_handler(
        axum::extract::State(peers): axum::extract::State<Vec<PeerInfo>>,
    ) -> axum::Json<PeerListResponse> {
        axum::Json(PeerListResponse { peers })
    }

    #[tokio::test]
    async fn shutdown_signal_accepts_either_signal_source() {
        let result = select_shutdown_signal(
            std::future::pending(),
            std::future::ready(Ok::<(), std::io::Error>(())),
        )
        .await;
        assert!(result.is_ok());

        let result = select_shutdown_signal(
            std::future::ready(Ok::<(), std::io::Error>(())),
            std::future::pending(),
        )
        .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn mesh_recovery_connector_uses_fresh_ice_credentials_and_checks_member_identity() {
        let temp =
            std::env::temp_dir().join(format!("mini-tunnel-refresh-ice-{}", uuid::Uuid::new_v4()));
        let identity = mini_tunnel_agent::Identity::load_or_create_at(temp.join("device.key"))
            .expect("local identity");
        let mut peer_identity =
            mini_tunnel_agent::Identity::load_or_create_at(temp.join("peer.key"))
                .expect("peer identity");
        let mut identity_paths = vec![temp.join("peer.key")];
        while identity.device_id() > peer_identity.device_id() {
            let path = temp.join(format!("peer-{}.key", identity_paths.len()));
            peer_identity = mini_tunnel_agent::Identity::load_or_create_at(path.clone())
                .expect("peer identity with outbound recovery ordering");
            identity_paths.push(path);
        }
        let local_credentials =
            mini_tunnel_agent::ice::generate_ice_credentials(1).expect("local ICE credentials");
        let old_credentials =
            mini_tunnel_agent::ice::generate_ice_credentials(1).expect("old peer ICE credentials");
        let fresh_credentials = mini_tunnel_agent::ice::generate_ice_credentials(2)
            .expect("fresh peer ICE credentials");
        let make_endpoint =
            |identity: &mini_tunnel_agent::Identity,
             credentials: mini_tunnel_protocol::IceCredentials| {
                let iced = mini_tunnel_agent::ice::peer_endpoint_with_ice(
                    identity,
                    "127.0.0.1:0".parse().unwrap(),
                    16,
                )
                .expect("create test ICE endpoint");
                let address = iced.endpoint.local_addr().expect("endpoint address");
                (
                    TunnelEndpoint {
                        endpoint: iced.endpoint,
                        excluded_candidate_interfaces: std::sync::Arc::new(std::sync::RwLock::new(
                            std::collections::HashSet::new(),
                        )),
                        ice: Some(TunnelIceState {
                            credentials,
                            socket: iced.socket,
                            router: iced.ice_router,
                            local_socket_addr: address,
                            local_candidates: std::sync::Arc::new(tokio::sync::RwLock::new(vec![
                                mini_tunnel_agent::candidate::SignaledCandidate {
                                    address,
                                    transport:
                                        mini_tunnel_agent::candidate::CandidateTransport::Udp,
                                    candidate_type:
                                        mini_tunnel_agent::candidate::CandidateType::Host,
                                },
                            ])),
                        }),
                    },
                    address,
                )
            };
        let (local_endpoint, local_address) = make_endpoint(&identity, local_credentials.clone());
        let (peer_endpoint, peer_address) =
            make_endpoint(&peer_identity, fresh_credentials.clone());
        let expected_peer = PeerInfo {
            device_id: peer_identity.device_id(),
            assigned_ipv4: "10.77.0.2".to_owned(),
            public_key: peer_identity.public_key_encoded(),
            candidates: vec![peer_address.to_string()],
            ice_credentials: Some(old_credentials),
        };
        let current_peer = PeerInfo {
            ice_credentials: Some(fresh_credentials.clone()),
            candidates: vec![peer_address.to_string()],
            ..expected_peer.clone()
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock coordinator");
        let coordinator = listener.local_addr().expect("coordinator address");
        let app = Router::new()
            .route(
                "/v1/networks/restart-net/peers",
                axum::routing::post(ice_peer_snapshot_handler),
            )
            .with_state(vec![current_peer.clone()]);
        let server = tokio::spawn(async move { axum::serve(listener, app).await });
        let base_url = format!("http://{coordinator}");

        let mut startup_peer = expected_peer.clone();
        assert!(
            select_ice_peer_address_with_snapshot_refresh(
                &local_endpoint,
                &base_url,
                "restart-net",
                &mut startup_peer,
                &identity,
                Duration::from_millis(50),
            )
            .await
            .is_none(),
            "the peer endpoint is not running an ICE checklist in this refresh-only assertion"
        );
        assert_eq!(
            startup_peer.ice_credentials,
            Some(fresh_credentials.clone()),
            "a failed initial checklist must refresh a stale peer snapshot before falling back"
        );

        let refreshed =
            refresh_peer_snapshot_for_ice(&base_url, "restart-net", &expected_peer, &identity)
                .await
                .expect("refresh peer snapshot");
        assert_eq!(refreshed.ice_credentials, Some(fresh_credentials));
        assert_eq!(refreshed.candidates, current_peer.candidates);

        let local_peer = PeerInfo {
            device_id: identity.device_id(),
            assigned_ipv4: "10.77.0.1".to_owned(),
            public_key: identity.public_key_encoded(),
            candidates: vec![local_address.to_string()],
            ice_credentials: Some(local_credentials),
        };
        let (recovery_connector, _, _) = build_mesh_peer_connectors(
            local_endpoint.clone(),
            std::sync::Arc::new(
                mini_tunnel_agent::Identity::load_or_create_at(temp.join("device.key"))
                    .expect("reload local identity"),
            ),
            "restart-net".to_owned(),
            base_url.clone(),
            expected_peer.clone(),
            RelayEndpoints::default(),
        );
        let local_id = identity.device_id();
        let local_key = identity.public_key();
        let server_endpoint = peer_endpoint.endpoint.clone();
        let peer_identity_path = identity_paths.last().expect("peer identity path").clone();
        let accept = tokio::spawn(async move {
            let peer_identity = mini_tunnel_agent::Identity::load_or_create_at(peer_identity_path)
                .expect("reload peer identity");
            mini_tunnel_agent::accept_peer(
                &server_endpoint,
                "restart-net",
                &peer_identity,
                &local_id,
                local_key,
            )
            .await
        });
        let (peer_selected_address, recovered) = tokio::join!(
            select_ice_peer_address(&peer_endpoint, &local_peer, &peer_identity),
            recovery_connector(false),
        );
        assert_eq!(
            peer_selected_address.map(|(address, monitor)| {
                drop(monitor);
                address
            }),
            Some(local_address)
        );
        let channel_local =
            recovered.expect("mesh recovery connector reconnects from fresh snapshot");
        let channel_peer = accept.await.expect("accept task").expect("accept peer");
        channel_local
            .send_packet(b"coordinator-refreshed-ice")
            .await
            .expect("send over recovered channel");
        assert_eq!(
            channel_peer
                .recv_packet()
                .await
                .expect("receive over recovered channel"),
            b"coordinator-refreshed-ice"
        );
        channel_local.close();
        channel_peer.close();

        let mut changed_member = expected_peer.clone();
        changed_member.assigned_ipv4 = "10.77.0.9".to_owned();
        assert!(
            refresh_peer_snapshot_for_ice(&base_url, "restart-net", &changed_member, &identity,)
                .await
                .is_err()
        );
        let mut changed_key = expected_peer.clone();
        changed_key.public_key =
            mini_tunnel_agent::Identity::load_or_create_at(temp.join("other-member.key"))
                .expect("other member identity")
                .public_key_encoded();
        assert!(
            refresh_peer_snapshot_for_ice(&base_url, "restart-net", &changed_key, &identity,)
                .await
                .is_err()
        );

        server.abort();
        local_endpoint
            .endpoint
            .close(0_u32.into(), b"test complete");
        peer_endpoint.endpoint.close(0_u32.into(), b"test complete");
        std::fs::remove_dir_all(temp).expect("remove test identities");
    }

    #[test]
    fn single_peer_tunnel_commands_accept_optional_relay_endpoint() {
        for args in [
            [
                "mini-tunnel",
                "peer",
                "tunnel",
                "connect",
                "--network-id",
                "office",
                "--peer-id",
                "peer-a",
                "--relay-server",
                "127.0.0.1:42001",
                "--udp-relay-server",
                "127.0.0.1:42003",
            ],
            [
                "mini-tunnel",
                "peer",
                "tunnel",
                "listen",
                "--network-id",
                "office",
                "--peer-id",
                "peer-a",
                "--relay-server",
                "127.0.0.1:42001",
                "--udp-relay-server",
                "127.0.0.1:42003",
            ],
        ] {
            let cli = Cli::try_parse_from(args).expect("valid relay-enabled tunnel command");
            let Command::Peer {
                command: PeerCommand::Tunnel { command },
            } = cli.command
            else {
                panic!("expected peer tunnel command");
            };
            match command {
                TunnelCommand::Connect {
                    relay_server,
                    udp_relay_server,
                    ..
                }
                | TunnelCommand::Listen {
                    relay_server,
                    udp_relay_server,
                    ..
                } => {
                    assert_eq!(relay_server, Some("127.0.0.1:42001".parse().unwrap()));
                    assert_eq!(udp_relay_server, Some("127.0.0.1:42003".parse().unwrap()));
                }
                _ => panic!("expected connect or listen command"),
            }
        }
    }

    #[test]
    fn relay_command_accepts_udp_auth_rate_overrides() {
        let cli = Cli::try_parse_from([
            "mini-tunnel",
            "relay",
            "serve",
            "--udp-auth-burst",
            "32",
            "--udp-auth-rate-per-second",
            "16",
        ])
        .expect("UDP authentication rate options parse");
        let Command::Relay {
            command:
                RelayCommand::Serve {
                    udp_auth_burst,
                    udp_auth_rate_per_second,
                    ..
                },
        } = cli.command
        else {
            panic!("expected relay serve command");
        };
        assert_eq!(udp_auth_burst, 32);
        assert_eq!(udp_auth_rate_per_second, 16);
    }

    #[test]
    fn tunnel_commands_accept_repeated_stun_servers() {
        let cli = Cli::try_parse_from([
            "mini-tunnel",
            "peer",
            "tunnel",
            "mesh",
            "--network-id",
            "office",
            "--stun-server",
            "192.0.2.10:3478",
            "--stun-server",
            "192.0.2.11:3478",
        ])
        .expect("repeated STUN server arguments are accepted");
        let Command::Peer {
            command:
                PeerCommand::Tunnel {
                    command: TunnelCommand::Mesh { stun_servers, .. },
                },
        } = cli.command
        else {
            panic!("expected mesh tunnel command");
        };
        assert_eq!(stun_servers.len(), 2);
    }

    #[test]
    fn ipv4_host_candidate_filter_is_usable_sorted_and_deduplicated() {
        let candidates = filtered_host_candidates(
            [
                Ipv4Addr::new(10, 0, 0, 9).into(),
                Ipv4Addr::new(192, 168, 1, 2).into(),
                Ipv4Addr::new(10, 0, 0, 9).into(),
                Ipv4Addr::LOCALHOST.into(),
                Ipv4Addr::UNSPECIFIED.into(),
                Ipv4Addr::new(224, 0, 0, 1).into(),
                Ipv4Addr::BROADCAST.into(),
            ],
            42000,
        );
        assert_eq!(
            candidates,
            vec![
                "10.0.0.9:42000".parse().unwrap(),
                "192.168.1.2:42000".parse().unwrap(),
            ]
        );
    }

    #[test]
    fn refreshed_host_candidates_exclude_only_the_local_tunnel_interface() {
        let excluded = std::collections::HashSet::from(["tun0".to_owned()]);
        let candidates = filtered_interface_host_candidates(
            [
                ("eth0".to_owned(), Ipv4Addr::new(192, 0, 2, 10).into()),
                ("tun0".to_owned(), Ipv4Addr::new(10, 239, 242, 1).into()),
                ("wg0".to_owned(), Ipv4Addr::new(198, 51, 100, 7).into()),
                (
                    "eth0".to_owned(),
                    "2001:db8::10".parse::<std::net::Ipv6Addr>().unwrap().into(),
                ),
                (
                    "tun0".to_owned(),
                    "fdf6:7977:99c1:dd4b::aef:f201"
                        .parse::<std::net::Ipv6Addr>()
                        .unwrap()
                        .into(),
                ),
                (
                    "wg0".to_owned(),
                    "2001:db8::70".parse::<std::net::Ipv6Addr>().unwrap().into(),
                ),
            ],
            42000,
            &excluded,
        );

        assert_eq!(
            candidates,
            vec![
                "192.0.2.10:42000".parse().unwrap(),
                "198.51.100.7:42000".parse().unwrap(),
                "[2001:db8::10]:42000".parse().unwrap(),
                "[2001:db8::70]:42000".parse().unwrap(),
            ]
        );
    }

    #[test]
    fn ipv6_host_candidate_filter_excludes_scoped_and_non_unicast_addresses() {
        let candidates = filtered_host_candidates(
            [
                "2001:db8::2".parse().unwrap(),
                "fd00::2".parse().unwrap(),
                "2001:db8::2".parse().unwrap(),
                "::1".parse().unwrap(),
                "::".parse().unwrap(),
                "ff02::1".parse().unwrap(),
                "fe80::1".parse().unwrap(),
            ],
            42000,
        );
        assert_eq!(
            candidates,
            vec![
                "[2001:db8::2]:42000".parse().unwrap(),
                "[fd00::2]:42000".parse().unwrap(),
            ]
        );
    }

    #[test]
    fn ice_candidate_composition_preserves_priority_and_enforces_limit() {
        let candidates = compose_ice_candidates(
            &["198.51.100.9:42000".to_owned()],
            Some("192.168.1.4:42000".parse().unwrap()),
            &[StunMapping {
                server: "198.51.100.1:3478".parse().unwrap(),
                mapped: "203.0.113.7:5000".parse().unwrap(),
                related: "192.168.1.4:42000".parse().unwrap(),
            }],
            vec![
                "192.168.1.3:42000".parse().unwrap(),
                "192.168.1.5:42000".parse().unwrap(),
            ],
            1,
        )
        .unwrap();
        assert_eq!(
            candidates,
            vec![
                "198.51.100.9:42000",
                "srflx://203.0.113.7:5000|192.168.1.4:42000",
                "192.168.1.4:42000",
                "192.168.1.3:42000",
                "192.168.1.5:42000",
            ]
        );
        let many = (1..=12)
            .map(|last| Ipv4Addr::new(10, 0, 0, last))
            .collect::<Vec<_>>();
        let truncated = compose_ice_candidates(
            &[],
            None,
            &[],
            filtered_host_candidates(many.into_iter().map(Into::into), 42000),
            0,
        )
        .unwrap();
        assert_eq!(truncated.len(), MAX_PEER_CANDIDATES);
        let hosts = (1..=12)
            .map(|last| Ipv4Addr::new(10, 0, 1, last))
            .collect::<Vec<_>>();
        let reserved = compose_ice_candidates(
            &["198.51.100.9:42000".to_owned()],
            None,
            &[],
            filtered_host_candidates(hosts.into_iter().map(Into::into), 42000),
            1,
        )
        .unwrap();
        assert_eq!(reserved.len(), MAX_PEER_CANDIDATES - 1);
        assert_eq!(reserved.len(), MAX_PEER_CANDIDATES - 1);
        let nine_explicit = (1..=9)
            .map(|port| format!("192.0.2.1:{port}"))
            .collect::<Vec<_>>();
        assert!(compose_ice_candidates(&nine_explicit, None, &[], Vec::new(), 0).is_err());
        let eight_explicit = (1..=8)
            .map(|port| format!("192.0.2.1:{port}"))
            .collect::<Vec<_>>();
        assert!(compose_ice_candidates(&eight_explicit, None, &[], Vec::new(), 1).is_err());
        assert_eq!(
            compose_ice_candidates(
                &[
                    "198.51.100.9:42000".to_owned(),
                    "198.51.100.9:42000".to_owned()
                ],
                None,
                &[],
                Vec::new(),
                0,
            )
            .unwrap(),
            vec!["198.51.100.9:42000"]
        );
    }

    #[test]
    fn non_ice_candidate_composition_reserves_slot_for_recovered_mapping() {
        let explicit = vec!["tcp://198.51.100.8:443".to_owned()];
        let hosts = (1..=12)
            .map(|last| Ipv4Addr::new(10, 0, 2, last))
            .collect::<Vec<_>>();
        let mapping = StunMapping {
            server: "192.0.2.53:3478".parse().unwrap(),
            mapped: "203.0.113.2:52000".parse().unwrap(),
            related: "10.0.2.1:42000".parse().unwrap(),
        };
        let candidates = compose_non_ice_candidates(
            &explicit,
            None,
            std::slice::from_ref(&mapping),
            hosts
                .into_iter()
                .map(|address| SocketAddr::new(address.into(), 42000))
                .collect(),
            1,
        )
        .unwrap();
        assert_eq!(candidates.len(), MAX_PEER_CANDIDATES);
        assert_eq!(candidates[0], explicit[0]);
        assert_eq!(candidates[1], mapping.mapped.to_string());
    }

    #[test]
    fn route_probe_selects_local_interface_and_preserves_tunnel_port() {
        let selected = route_selected_local_address("127.0.0.1:3478".parse().unwrap(), 42000)
            .expect("select route address");
        assert_eq!(selected, "127.0.0.1:42000".parse().unwrap());
    }

    async fn capture_candidate_update(
        State(requests): State<std::sync::Arc<tokio::sync::Mutex<Vec<CandidateUpdateRequest>>>>,
        axum::Json(request): axum::Json<CandidateUpdateRequest>,
    ) -> axum::Json<CandidateUpdateResponse> {
        requests.lock().await.push(request);
        axum::Json(CandidateUpdateResponse { accepted: true })
    }

    fn spawn_stun_mapping_responder(
        socket: tokio::net::UdpSocket,
        mapped: SocketAddr,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut request = [0; 128];
            let (length, peer) = socket.recv_from(&mut request).await.unwrap();
            assert_eq!(length, 20);
            let cookie: [u8; 4] = request[4..8].try_into().unwrap();
            let mut response = vec![0; 32];
            response[..2].copy_from_slice(&0x0101_u16.to_be_bytes());
            response[2..4].copy_from_slice(&12_u16.to_be_bytes());
            response[4..8].copy_from_slice(&cookie);
            response[8..20].copy_from_slice(&request[8..20]);
            response[20..22].copy_from_slice(&0x0020_u16.to_be_bytes());
            response[22..24].copy_from_slice(&8_u16.to_be_bytes());
            response[25] = 1;
            response[26..28].copy_from_slice(&(mapped.port() ^ 0x2112_u16).to_be_bytes());
            let std::net::IpAddr::V4(mapped_ip) = mapped.ip() else {
                unreachable!()
            };
            for (target, (address, mask)) in response[28..32]
                .iter_mut()
                .zip(mapped_ip.octets().into_iter().zip(cookie))
            {
                *target = address ^ mask;
            }
            socket.send_to(&response, peer).await.unwrap();
        })
    }

    #[tokio::test]
    async fn tunnel_cli_publishes_ice_credentials_and_connects_over_nominated_path() {
        let requests = std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock coordinator");
        let coordinator = listener.local_addr().expect("coordinator address");
        let app = Router::new()
            .route(
                "/v1/networks/test-network/candidates",
                axum::routing::post(capture_candidate_update),
            )
            .with_state(std::sync::Arc::clone(&requests));
        let coordinator_task = tokio::spawn(async move { axum::serve(listener, app).await });
        let temp =
            std::env::temp_dir().join(format!("mini-tunnel-cli-ice-{}", uuid::Uuid::new_v4()));
        let identity_a = mini_tunnel_agent::Identity::load_or_create_at(temp.join("a/device.key"))
            .expect("identity A");
        let identity_b = mini_tunnel_agent::Identity::load_or_create_at(temp.join("b/device.key"))
            .expect("identity B");
        let endpoint_a = create_tunnel_endpoint(
            &identity_a,
            "127.0.0.1:0".parse().unwrap(),
            Vec::new(),
            true,
            &[],
            "test-network",
            &format!("http://{coordinator}"),
        )
        .await
        .expect("create ICE tunnel endpoint A");
        let endpoint_b = create_tunnel_endpoint(
            &identity_b,
            "127.0.0.1:0".parse().unwrap(),
            Vec::new(),
            true,
            &[],
            "test-network",
            &format!("http://{coordinator}"),
        )
        .await
        .expect("create ICE tunnel endpoint B");
        let published = requests.lock().await.clone();
        assert_eq!(published.len(), 2);
        for (identity, request) in [(&identity_a, &published[0]), (&identity_b, &published[1])] {
            let credentials = request.ice_credentials.as_ref().expect("ICE credentials");
            let mut canonical_candidates = request.candidates.clone();
            canonical_candidates.sort();
            assert_eq!(
                request.signature,
                identity.sign(&candidate_signing_bytes_with_ice(
                    "test-network",
                    &request.device_id,
                    request.timestamp_ms,
                    &canonical_candidates,
                    credentials,
                ))
            );
        }
        let peer_a = PeerInfo {
            device_id: identity_a.device_id(),
            assigned_ipv4: "10.70.0.1".to_owned(),
            public_key: identity_a.public_key_encoded(),
            candidates: published[0].candidates.clone(),
            ice_credentials: published[0].ice_credentials.clone(),
        };
        let peer_b = PeerInfo {
            device_id: identity_b.device_id(),
            assigned_ipv4: "10.70.0.2".to_owned(),
            public_key: identity_b.public_key_encoded(),
            candidates: published[1].candidates.clone(),
            ice_credentials: published[1].ice_credentials.clone(),
        };
        let server_endpoint = endpoint_b.endpoint.clone();
        let peer_id_a = peer_a.device_id.clone();
        let peer_key_a = identity_a.public_key();
        let peer_key_b = identity_b.public_key();
        let accept = mini_tunnel_agent::accept_peer(
            &server_endpoint,
            "test-network",
            &identity_b,
            &peer_id_a,
            peer_key_a,
        );
        let (connected, selected_b, accepted) = tokio::join!(
            connect_tunnel_peer(
                &endpoint_a,
                &peer_b,
                "test-network",
                &identity_a,
                peer_key_b,
                RelayEndpoints::default(),
                "http://127.0.0.1:1",
            ),
            select_ice_peer_address(&endpoint_b, &peer_a, &identity_b),
            accept,
        );
        let (channel_a, remote) = connected.expect("connect via ICE-nominated path");
        let (selected_address_b, monitor_b) = selected_b.expect("peer B ICE nomination");
        assert_eq!(
            selected_address_b,
            endpoint_a.endpoint.local_addr().unwrap()
        );
        assert_eq!(remote, endpoint_b.endpoint.local_addr().unwrap());
        let mut channel_b = accepted.expect("accept peer");
        let (stale_monitor, _, _) = mini_tunnel_agent::ice::IceConsentMonitor::new();
        let mismatched_remote = SocketAddr::new(
            selected_address_b.ip(),
            selected_address_b.port().wrapping_add(1),
        );
        assert!(
            !attach_nominated_ice_monitor(&mut channel_b, mismatched_remote, stale_monitor).await,
            "a consent monitor for another candidate must not be attached"
        );
        assert!(
            attach_nominated_ice_monitor(&mut channel_b, selected_address_b, monitor_b).await,
            "retain the accepted authenticated direct channel only with consent for its nominated remote"
        );
        channel_a
            .send_packet(b"cli-ice-e2e")
            .await
            .expect("send tunnel payload");
        assert_eq!(
            channel_b
                .recv_packet()
                .await
                .expect("receive tunnel payload"),
            b"cli-ice-e2e"
        );
        channel_a.close();
        channel_b.close();
        endpoint_a.endpoint.close(0_u32.into(), b"test complete");
        endpoint_b.endpoint.close(0_u32.into(), b"test complete");
        coordinator_task.abort();
        std::fs::remove_dir_all(temp).expect("remove test identities");
    }

    #[tokio::test]
    async fn mesh_ice_routes_two_peer_sessions_and_transfers_over_both_quic_channels() {
        let temp =
            std::env::temp_dir().join(format!("mini-tunnel-mesh-ice-{}", uuid::Uuid::new_v4()));
        let identity_a = mini_tunnel_agent::Identity::load_or_create_at(temp.join("a/device.key"))
            .expect("identity A");
        let identity_b = mini_tunnel_agent::Identity::load_or_create_at(temp.join("b/device.key"))
            .expect("identity B");
        let identity_c = mini_tunnel_agent::Identity::load_or_create_at(temp.join("c/device.key"))
            .expect("identity C");
        let create_endpoint = |identity: &mini_tunnel_agent::Identity| {
            mini_tunnel_agent::ice::peer_endpoint_with_ice(
                identity,
                "127.0.0.1:0".parse().unwrap(),
                16,
            )
            .expect("create mesh ICE endpoint")
        };
        let iced_a = create_endpoint(&identity_a);
        let iced_b = create_endpoint(&identity_b);
        let iced_c = create_endpoint(&identity_c);
        let address_a = iced_a.endpoint.local_addr().unwrap();
        let address_b = iced_b.endpoint.local_addr().unwrap();
        let address_c = iced_c.endpoint.local_addr().unwrap();
        let credentials_a = mini_tunnel_agent::ice::generate_ice_credentials(1).unwrap();
        let credentials_b = mini_tunnel_agent::ice::generate_ice_credentials(1).unwrap();
        let credentials_c = mini_tunnel_agent::ice::generate_ice_credentials(1).unwrap();
        let endpoint = |iced: mini_tunnel_agent::ice::IcedPeerEndpoint,
                        credentials: mini_tunnel_protocol::IceCredentials,
                        local: SocketAddr| TunnelEndpoint {
            endpoint: iced.endpoint,
            excluded_candidate_interfaces: std::sync::Arc::new(std::sync::RwLock::new(
                std::collections::HashSet::new(),
            )),
            ice: Some(TunnelIceState {
                credentials,
                socket: iced.socket,
                router: iced.ice_router,
                local_socket_addr: local,
                local_candidates: std::sync::Arc::new(tokio::sync::RwLock::new(vec![
                    mini_tunnel_agent::candidate::SignaledCandidate {
                        address: local,
                        transport: mini_tunnel_agent::candidate::CandidateTransport::Udp,
                        candidate_type: mini_tunnel_agent::candidate::CandidateType::Host,
                    },
                ])),
            }),
        };
        let endpoint_a = endpoint(iced_a, credentials_a.clone(), address_a);
        let endpoint_b = endpoint(iced_b, credentials_b.clone(), address_b);
        let endpoint_c = endpoint(iced_c, credentials_c.clone(), address_c);
        let peer = |identity: &mini_tunnel_agent::Identity,
                    address: SocketAddr,
                    credentials: &mini_tunnel_protocol::IceCredentials,
                    assigned_ipv4: &str| PeerInfo {
            device_id: identity.device_id(),
            assigned_ipv4: assigned_ipv4.to_owned(),
            public_key: identity.public_key_encoded(),
            candidates: vec![address.to_string()],
            ice_credentials: Some(credentials.clone()),
        };
        let peer_a = peer(&identity_a, address_a, &credentials_a, "10.71.0.1");
        let peer_b = peer(&identity_b, address_b, &credentials_b, "10.71.0.2");
        let peer_c = peer(&identity_c, address_c, &credentials_c, "10.71.0.3");
        let (a_to_b, a_to_c, b_to_a, c_to_a) = tokio::join!(
            select_ice_peer_address(&endpoint_a, &peer_b, &identity_a),
            select_ice_peer_address(&endpoint_a, &peer_c, &identity_a),
            select_ice_peer_address(&endpoint_b, &peer_a, &identity_b),
            select_ice_peer_address(&endpoint_c, &peer_a, &identity_c),
        );
        let (a_to_b_address, a_to_b_monitor) = a_to_b.expect("ICE peer B");
        let (a_to_c_address, a_to_c_monitor) = a_to_c.expect("ICE peer C");
        assert_eq!(a_to_b_address, address_b);
        assert_eq!(a_to_c_address, address_c);
        assert_eq!(
            b_to_a.map(|(address, monitor)| {
                drop(monitor);
                address
            }),
            Some(address_a)
        );
        assert_eq!(
            c_to_a.map(|(address, monitor)| {
                drop(monitor);
                address
            }),
            Some(address_a)
        );

        let accept_b = mini_tunnel_agent::accept_peer(
            &endpoint_b.endpoint,
            "mesh-ice-test",
            &identity_b,
            &peer_a.device_id,
            identity_a.public_key(),
        );
        let accept_c = mini_tunnel_agent::accept_peer(
            &endpoint_c.endpoint,
            "mesh-ice-test",
            &identity_c,
            &peer_a.device_id,
            identity_a.public_key(),
        );
        let (connect_b, connect_c, channel_b, channel_c) = tokio::join!(
            mini_tunnel_agent::connect_peer(
                &endpoint_a.endpoint,
                a_to_b_address,
                "mesh-ice-test",
                &identity_a,
                &peer_b.device_id,
                identity_b.public_key(),
            ),
            mini_tunnel_agent::connect_peer(
                &endpoint_a.endpoint,
                a_to_c_address,
                "mesh-ice-test",
                &identity_a,
                &peer_c.device_id,
                identity_c.public_key(),
            ),
            accept_b,
            accept_c,
        );
        let mut channel_a_b = connect_b.expect("QUIC peer B");
        channel_a_b.set_ice_consent_monitor(a_to_b_monitor);
        let mut channel_a_c = connect_c.expect("QUIC peer C");
        channel_a_c.set_ice_consent_monitor(a_to_c_monitor);
        let channel_b = channel_b.expect("accept peer B");
        let channel_c = channel_c.expect("accept peer C");
        channel_a_b.send_packet(b"mesh-peer-b").await.unwrap();
        channel_a_c.send_packet(b"mesh-peer-c").await.unwrap();
        assert_eq!(channel_b.recv_packet().await.unwrap(), b"mesh-peer-b");
        assert_eq!(channel_c.recv_packet().await.unwrap(), b"mesh-peer-c");
        for tunnel_endpoint in [&endpoint_a, &endpoint_b, &endpoint_c] {
            tunnel_endpoint
                .endpoint
                .close(0_u32.into(), b"test complete");
        }
        std::fs::remove_dir_all(temp).expect("remove test identities");
    }

    #[test]
    fn relay_connection_limits_require_positive_values() {
        assert_eq!(parse_positive_usize("1").unwrap(), 1);
        assert_eq!(parse_positive_usize("256").unwrap(), 256);
        assert!(parse_positive_usize("0").is_err());
        assert!(parse_positive_usize("nope").is_err());
    }

    #[test]
    fn relay_metrics_listener_rejects_non_loopback_addresses() {
        assert!(validate_relay_metrics_address("127.0.0.1:0".parse().unwrap()).is_ok());
        assert!(validate_relay_metrics_address("[::1]:0".parse().unwrap()).is_ok());
        assert!(validate_relay_metrics_address("0.0.0.0:42002".parse().unwrap()).is_err());
        assert!(validate_relay_metrics_address("[::]:42002".parse().unwrap()).is_err());
    }

    #[tokio::test]
    async fn relay_metrics_http_endpoint_reports_health_and_counters() {
        let relay =
            mini_tunnel_relay::RelayServer::new(mini_tunnel_relay::RelayConfig::new([21; 32]));
        let udp_relay = mini_tunnel_relay::UdpRelayServer::new(
            mini_tunnel_relay::UdpRelayConfig::new([21; 32]).with_auth_rate(1, 1),
        );
        let udp_listener = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind UDP relay listener");
        let udp_address = udp_listener.local_addr().expect("UDP relay address");
        let udp_server = {
            let udp_relay = udp_relay.clone();
            tokio::spawn(async move { udp_relay.run(udp_listener).await.expect("UDP relay") })
        };
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind UDP client");
        client
            .send_to(b"MTUHELLO", udp_address)
            .await
            .expect("send first auth packet");
        client
            .send_to(b"MTUHELLO", udp_address)
            .await
            .expect("send rate-limited auth packet");
        tokio::time::timeout(Duration::from_secs(1), async {
            while udp_relay.stats().await.auth_rate_limited_total == 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("rate-limit metric counter timeout");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind metrics listener");
        let address = listener.local_addr().expect("metrics address");
        let metrics_udp_relay = udp_relay.clone();
        let server = tokio::spawn(async move {
            axum::serve(listener, relay_metrics_router(relay, metrics_udp_relay)).await
        });
        let client = reqwest::Client::new();
        let health = client
            .get(format!("http://{address}/healthz"))
            .send()
            .await
            .expect("health response");
        assert_eq!(health.status(), StatusCode::OK);
        assert_eq!(health.text().await.expect("health body"), "ok\n");

        let metrics = client
            .get(format!("http://{address}/metrics"))
            .send()
            .await
            .expect("metrics response");
        assert_eq!(metrics.status(), StatusCode::OK);
        assert_eq!(
            metrics.headers()[header::CONTENT_TYPE],
            "text/plain; version=0.0.4; charset=utf-8"
        );
        let body = metrics.text().await.expect("metrics body");
        assert!(body.contains("mini_tunnel_relay_active_connections 0"));
        assert!(body.contains("mini_tunnel_relay_active_sessions 0"));
        assert!(body.contains("mini_tunnel_relay_bytes_forwarded_total 0"));
        assert!(body.contains("mini_tunnel_udp_relay_active_sessions 0"));
        assert!(body.contains("mini_tunnel_udp_relay_forwarded_datagrams_total 0"));
        assert!(body.contains("mini_tunnel_udp_relay_auth_rate_limited_total 1"));
        udp_relay.shutdown();
        udp_server.await.expect("UDP relay task");
        server.abort();
    }

    #[test]
    fn reliable_path_preference_excludes_udp_candidates() {
        let candidates = vec![
            "203.0.113.1:42000".to_owned(),
            "tcp://203.0.113.1:443".to_owned(),
        ];
        assert_eq!(
            candidates_for_path(&candidates, true),
            vec!["tcp://203.0.113.1:443"]
        );
        assert_eq!(candidates_for_path(&candidates, false), candidates);
    }

    #[tokio::test]
    async fn reliable_reconnect_skips_queued_udp_until_tcp_arrives() {
        #[derive(Debug, PartialEq, Eq)]
        enum TestPath {
            Udp,
            Tcp,
        }

        let (sender, receiver) = tokio::sync::mpsc::channel(2);
        sender.send(TestPath::Udp).await.unwrap();
        sender.send(TestPath::Tcp).await.unwrap();
        let receiver = std::sync::Arc::new(tokio::sync::Mutex::new(receiver));

        let selected = receive_reconnect_channel(receiver, true, Duration::from_secs(1), |path| {
            matches!(path, TestPath::Tcp)
        })
        .await;
        assert_eq!(selected, Some(TestPath::Tcp));
    }

    #[tokio::test]
    async fn normal_reconnect_accepts_udp_and_reliable_reconnect_times_out_on_udp_only() {
        #[derive(Debug, PartialEq, Eq)]
        enum TestPath {
            Udp,
        }

        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        sender.send(TestPath::Udp).await.unwrap();
        let receiver = std::sync::Arc::new(tokio::sync::Mutex::new(receiver));
        let selected =
            receive_reconnect_channel(receiver, false, Duration::from_secs(1), |_| false).await;
        assert_eq!(selected, Some(TestPath::Udp));

        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        sender.send(TestPath::Udp).await.unwrap();
        let receiver = std::sync::Arc::new(tokio::sync::Mutex::new(receiver));
        let selected =
            receive_reconnect_channel(receiver, true, Duration::from_millis(10), |_| false).await;
        assert_eq!(selected, None);
    }

    #[test]
    fn explicit_tun_overrides_must_match_saved_membership() {
        let membership = mini_tunnel_agent::membership::NetworkMembership::new(
            "3a50e2e2-037f-4e0f-9f5c-a0b23e3cf543",
            "0123456789abcdef0123456789abcdef",
            "10.77.0.2",
            "10.77.0.0/16",
        )
        .expect("valid membership");
        assert_eq!(
            resolve_saved_tun_parameters(&membership, Some(Ipv4Addr::new(10, 77, 0, 2)), Some(16))
                .expect("matching overrides"),
            (Ipv4Addr::new(10, 77, 0, 2), 16)
        );
        assert!(
            resolve_saved_tun_parameters(&membership, Some(Ipv4Addr::new(10, 77, 0, 99)), Some(16))
                .is_err()
        );
        assert!(resolve_saved_tun_parameters(&membership, None, Some(24)).is_err());
    }

    #[test]
    fn mesh_membership_diff_is_idempotent_and_reports_add_remove_and_address_change() {
        let peer = |device_id: &str, assigned_ipv4: &str| PeerInfo {
            device_id: device_id.to_owned(),
            assigned_ipv4: assigned_ipv4.to_owned(),
            public_key: URL_SAFE_NO_PAD.encode([1_u8; 32]),
            candidates: Vec::new(),
            ice_credentials: None,
        };
        let first = peer("peer-a", "10.77.0.2");
        let second = peer("peer-b", "10.77.0.3");
        let known = [
            (first.device_id.clone(), first.clone()),
            (second.device_id.clone(), second.clone()),
        ]
        .into_iter()
        .collect::<std::collections::HashMap<_, _>>();

        let (removed, added) = mesh_membership_diff(&known, &[first.clone(), second.clone()]);
        assert!(removed.is_empty());
        assert!(added.is_empty());

        let replacement = peer("peer-b", "10.77.0.9");
        let newcomer = peer("peer-c", "10.77.0.4");
        let (removed, added) =
            mesh_membership_diff(&known, &[replacement.clone(), newcomer.clone()]);
        assert_eq!(
            removed,
            vec![
                ("peer-a".to_owned(), "10.77.0.2".to_owned()),
                ("peer-b".to_owned(), "10.77.0.3".to_owned())
            ]
        );
        assert_eq!(added, vec![replacement, newcomer]);
    }

    #[test]
    fn mesh_startup_keeps_collecting_until_pending_peer_attempts_finish() {
        let started = tokio::time::Instant::now();
        let startup_deadline = started + Duration::from_secs(45);
        let first_peer_at = started + Duration::from_millis(250);

        assert_eq!(
            mesh_startup_settle_deadline(
                Some(first_peer_at),
                true,
                startup_deadline,
                Duration::from_secs(1),
            ),
            startup_deadline,
            "a connected peer must not cancel other in-flight peer attempts"
        );
        assert_eq!(
            mesh_startup_settle_deadline(
                Some(first_peer_at),
                false,
                startup_deadline,
                Duration::from_secs(1),
            ),
            first_peer_at + Duration::from_secs(1),
            "once attempts finish, allow a short window to collect simultaneous accepts"
        );
        assert_eq!(
            mesh_startup_settle_deadline(None, false, startup_deadline, Duration::from_secs(1),),
            startup_deadline,
            "when no peer connects, preserve the bounded startup deadline"
        );
    }

    #[test]
    fn single_peer_revocation_requires_authoritative_membership_failure() {
        let peer = PeerInfo {
            device_id: "peer-a".to_owned(),
            assigned_ipv4: "10.77.0.2".to_owned(),
            public_key: URL_SAFE_NO_PAD.encode([1_u8; 32]),
            candidates: Vec::new(),
            ice_credentials: None,
        };
        assert!(!peer_snapshot_revokes_peer(
            std::slice::from_ref(&peer),
            "peer-a"
        ));
        assert!(peer_snapshot_revokes_peer(
            std::slice::from_ref(&peer),
            "peer-b"
        ));
        let invalid_token = CoordinatorApiError {
            code: "invalid_token".to_owned(),
            message: "member revoked".to_owned(),
        };
        let network_removed = CoordinatorApiError {
            code: "not_found".to_owned(),
            message: "network removed".to_owned(),
        };
        let transient = CoordinatorApiError {
            code: "persistence_error".to_owned(),
            message: "storage unavailable".to_owned(),
        };
        assert!(coordinator_error_revokes_member(&invalid_token));
        assert!(coordinator_error_revokes_member(&network_removed));
        assert!(!coordinator_error_revokes_member(&transient));
    }

    #[tokio::test]
    async fn mesh_authoritative_revocation_clears_sessions_but_transient_errors_do_not() {
        let peer = |device_id: &str, assigned_ipv4: &str| PeerInfo {
            device_id: device_id.to_owned(),
            assigned_ipv4: assigned_ipv4.to_owned(),
            public_key: URL_SAFE_NO_PAD.encode([1_u8; 32]),
            candidates: Vec::new(),
            ice_credentials: None,
        };
        let peers = vec![peer("peer-a", "10.77.0.2"), peer("peer-b", "10.77.0.3")];
        let known = peers
            .iter()
            .cloned()
            .map(|peer| (peer.device_id.clone(), peer))
            .collect::<std::collections::HashMap<_, _>>();
        let (accepted_a, _accepted_a_rx) = tokio::sync::mpsc::channel(1);
        let (accepted_b, _accepted_b_rx) = tokio::sync::mpsc::channel(1);
        let registry =
            std::sync::Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::from([
                ("peer-a".to_owned(), accepted_a),
                ("peer-b".to_owned(), accepted_b),
            ])));
        let mut pending = std::collections::HashMap::new();
        pending.insert(
            "peer-pending".to_owned(),
            tokio::spawn(std::future::pending::<()>()),
        );
        let (snapshot_tx, snapshot_rx) = tokio::sync::watch::channel(peers.clone());
        let (allowlist_tx, allowlist_rx) =
            tokio::sync::watch::channel(vec![("peer-a".to_owned(), [1_u8; 32])]);
        let (updates_tx, mut updates_rx) = tokio::sync::mpsc::channel(4);

        let transient = CoordinatorApiError {
            code: "persistence_error".to_owned(),
            message: "temporary coordinator failure".to_owned(),
        };
        assert!(
            !stop_mesh_after_membership_revocation(
                &transient,
                &known,
                &mut pending,
                &registry,
                &snapshot_tx,
                &allowlist_tx,
                &updates_tx,
            )
            .await
        );
        assert_eq!(registry.read().await.len(), 2);
        assert_eq!(pending.len(), 1);
        assert!(!snapshot_rx.borrow().is_empty());
        assert!(updates_rx.try_recv().is_err());

        let revoked = CoordinatorApiError {
            code: "invalid_token".to_owned(),
            message: "local member revoked".to_owned(),
        };
        assert!(
            stop_mesh_after_membership_revocation(
                &revoked,
                &known,
                &mut pending,
                &registry,
                &snapshot_tx,
                &allowlist_tx,
                &updates_tx,
            )
            .await
        );
        assert!(registry.read().await.is_empty());
        assert!(pending.is_empty());
        assert!(snapshot_rx.borrow().is_empty());
        assert!(allowlist_rx.borrow().is_empty());
        let removed = [
            updates_rx.recv().await.expect("peer A removal"),
            updates_rx.recv().await.expect("peer B removal"),
        ];
        let removed = removed
            .into_iter()
            .map(|update| match update {
                mini_tunnel_agent::tunnel::MeshPeerUpdate::Remove(address) => address,
                mini_tunnel_agent::tunnel::MeshPeerUpdate::Add(_) => panic!("unexpected peer add"),
            })
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            removed,
            [Ipv4Addr::new(10, 77, 0, 2), Ipv4Addr::new(10, 77, 0, 3)]
                .into_iter()
                .collect()
        );
    }
}
