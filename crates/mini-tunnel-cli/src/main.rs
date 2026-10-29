use std::{
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
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
use mini_tunnel_protocol::{
    ApiErrorResponse, CandidateUpdateRequest, CandidateUpdateResponse, CreateInviteRequest,
    CreateInviteResponse, CreateNetworkRequest, CreateNetworkResponse, JoinNetworkRequest,
    JoinNetworkResponse, PeerInfo, PeerListRequest, PeerListResponse, RelayTicketRequest,
    RelayTicketResponse, RevokeMemberRequest, RevokeMemberResponse, candidate_signing_bytes,
    candidate_signing_bytes_with_ice, join_signing_bytes, peers_signing_bytes,
    relay_ticket_request_signing_bytes,
};
use serde::Deserialize;

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
        #[arg(
            long,
            env = "MINI_TUNNEL_COORDINATOR_STATE",
            default_value_os_t = default_coordinator_state_path()
        )]
        state_file: PathBuf,
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
    },
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
    /// List signed same-network peer snapshots.
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
}

#[derive(Debug, Subcommand)]
enum PeerCommand {
    /// Create a TUN and keep a bidirectional authenticated peer tunnel running.
    Tunnel {
        #[command(subcommand)]
        command: TunnelCommand,
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
        /// Optional RFC 8489 STUN server used to discover and publish this UDP socket's mapped address.
        #[arg(long)]
        stun_server: Option<SocketAddr>,
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
        #[arg(long, default_value_t = 1150)]
        mtu: u16,
        /// Install and clean up a /32 route for the authenticated peer.
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
        /// Optional TLS/TCP listener for fallback candidates such as tcp://198.51.100.2:443.
        #[arg(long)]
        tcp_bind: Option<SocketAddr>,
        /// Optional RFC 8489 STUN server used to discover and publish this UDP socket's mapped address.
        #[arg(long)]
        stun_server: Option<SocketAddr>,
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
        #[arg(long, default_value_t = 1150)]
        mtu: u16,
        /// Install and clean up a /32 route for the authenticated peer.
        #[arg(long)]
        manage_route: bool,
        #[arg(
            long,
            env = "MINI_TUNNEL_COORDINATOR_URL",
            default_value = "http://127.0.0.1:8080"
        )]
        coordinator_url: String,
    },
    /// Connect all currently discoverable members into one IPv4 L3 mesh.
    Mesh {
        #[arg(long, default_value = "0.0.0.0:42000")]
        bind: SocketAddr,
        /// Optional TLS/TCP listener for fallback candidates such as tcp://198.51.100.2:443.
        #[arg(long)]
        tcp_bind: Option<SocketAddr>,
        /// Optional ticket-authorized relay TCP endpoint used after direct UDP/TCP attempts fail.
        #[arg(long, env = "MINI_TUNNEL_RELAY_SERVER")]
        relay_server: Option<SocketAddr>,
        /// Optional RFC 8489 STUN server used to discover and publish this UDP socket's mapped address.
        #[arg(long)]
        stun_server: Option<SocketAddr>,
        /// Additional candidate address to publish; may be repeated.
        #[arg(long = "candidate")]
        candidates: Vec<String>,
        #[arg(long)]
        network_id: String,
        #[arg(long)]
        local_ipv4: Option<Ipv4Addr>,
        #[arg(long)]
        prefix_len: Option<u8>,
        #[arg(long, default_value_t = 1150)]
        mtu: u16,
        /// Install and clean up one /32 route for every authenticated peer.
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

fn relay_metrics_router(relay: mini_tunnel_relay::RelayServer) -> Router {
    Router::new()
        .route("/healthz", get(relay_health))
        .route("/metrics", get(relay_metrics))
        .with_state(relay)
}

async fn relay_health() -> impl IntoResponse {
    (StatusCode::OK, "ok\n")
}

async fn relay_metrics(State(relay): State<mini_tunnel_relay::RelayServer>) -> impl IntoResponse {
    let stats = relay.stats().await;
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
         mini_tunnel_relay_bytes_forwarded_total {}\n",
        stats.active_connections,
        stats.max_connections,
        stats.max_connections_per_source_ip,
        stats.active_sessions,
        stats.accepted_connections_total,
        stats.capacity_rejections_total,
        stats.handshake_failures_total,
        stats.bytes_forwarded_total,
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

async fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match cli.command {
        Command::Coordinator { command } => match command {
            CoordinatorCommand::Serve {
                listen,
                state_file,
                tls_cert,
                tls_key,
                tls_reload_interval_seconds,
            } => {
                let relay_key = std::env::var("MINI_TUNNEL_RELAY_TICKET_KEY")
                    .ok()
                    .map(|value| {
                        URL_SAFE_NO_PAD.decode(value).ok()
                            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
                            .ok_or_else(|| "MINI_TUNNEL_RELAY_TICKET_KEY must be base64url encoding of exactly 32 bytes".to_owned())
                    })
                    .transpose()?;
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
                mini_tunnel_coordinator::serve_with_state_file_and_relay_key_tls_and_reload_interval(
                    listen,
                    state_file,
                    relay_key,
                    tls_files,
                    Duration::from_secs(tls_reload_interval_seconds),
                )
                .await?;
            }
            CoordinatorCommand::Health { url } => {
                let endpoint = format!("{}/healthz", url.trim_end_matches('/'));
                let response = reqwest::Client::builder()
                    .timeout(Duration::from_secs(3))
                    .build()?
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
                metrics_listen,
                max_connections,
                max_connections_per_source_ip,
                previous_ticket_key,
                max_session_bytes,
                shutdown_grace_seconds,
            } => {
                let key = std::env::var("MINI_TUNNEL_RELAY_TICKET_KEY")
                    .map_err(|_| "MINI_TUNNEL_RELAY_TICKET_KEY is required for relay service")?;
                let key = URL_SAFE_NO_PAD.decode(key)?;
                let key: [u8; 32] = key
                    .try_into()
                    .map_err(|_| "relay ticket key must decode to exactly 32 bytes")?;
                let mut config = mini_tunnel_relay::RelayConfig::new(key)
                    .with_max_session_bytes(max_session_bytes)
                    .with_max_connections(max_connections)
                    .with_max_connections_per_source_ip(max_connections_per_source_ip);
                config.shutdown_grace = Duration::from_secs(shutdown_grace_seconds);
                if let Some(previous) = previous_ticket_key {
                    let previous = URL_SAFE_NO_PAD.decode(previous)?;
                    let previous: [u8; 32] = previous
                        .try_into()
                        .map_err(|_| "previous relay ticket key must decode to exactly 32 bytes")?;
                    config = config.with_previous_ticket_key(previous);
                }
                validate_relay_metrics_address(metrics_listen)?;
                let listener = tokio::net::TcpListener::bind(listen).await?;
                eprintln!("relay listening on {}", listener.local_addr()?);
                let metrics_listener = tokio::net::TcpListener::bind(metrics_listen).await?;
                let relay = mini_tunnel_relay::RelayServer::new(config);
                let metrics_relay = relay.clone();
                let metrics_router = relay_metrics_router(metrics_relay);
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
                let result = relay
                    .run_until(listener, async {
                        if let Err(error) = tokio::signal::ctrl_c().await {
                            eprintln!("could not listen for shutdown signal: {error}");
                        }
                    })
                    .await;
                metrics_shutdown_tx.send_replace(true);
                let metrics_result = metrics_task.await?;
                result?;
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
                    stun_server,
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
                    let identity = mini_tunnel_agent::Identity::load_or_create()?;
                    let (local_ipv4, prefix_len) =
                        resolve_tun_parameters(&network_id, &identity, local_ipv4, prefix_len)?;
                    let endpoint = create_tunnel_endpoint(
                        &identity,
                        bind,
                        stun_server,
                        ice,
                        &candidates,
                        &network_id,
                        &coordinator_url,
                    )
                    .await?;
                    let tun = create_tun(local_ipv4, prefix_len, mtu)?;
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
                            )
                            .await?;
                            run_peer_tunnel(&tun, &channel, &peer, remote, manage_route).await
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
                    tcp_bind,
                    stun_server,
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
                        stun_server,
                        ice,
                        &candidates,
                        &network_id,
                        &coordinator_url,
                    )
                    .await?;
                    let tun = create_tun(local_ipv4, prefix_len, mtu)?;
                    println!(
                        "Waiting for authenticated peer on {}",
                        endpoint.local_addr()?
                    );
                    let mut attempt = 0_u32;
                    loop {
                        let result = async {
                            let peer = discover_peer(&coordinator_url, &network_id, &peer_id, &identity).await?;
                            let peer_key = decode_peer_key(&peer.public_key)?;
                            let _ = select_ice_peer_address(&endpoint, &peer, &identity).await;
                            let channel = mini_tunnel_agent::accept_peer(
                                &endpoint, &network_id, &identity, &peer.device_id, peer_key,
                            );
                            let channel = if let Some(listener) = &tcp_listener {
                                let allowed = vec![(peer.device_id.clone(), peer_key)];
                                tokio::select! {
                                    result = channel => result?,
                                    result = mini_tunnel_agent::accept_tcp_peer_any(listener, &network_id, &identity, &allowed) => result?.1,
                                }
                            } else { channel.await? };
                            let remote = channel.remote_address();
                            run_peer_tunnel(&tun, &channel, &peer, remote, manage_route).await
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
                    stun_server,
                    candidates,
                    network_id,
                    local_ipv4,
                    prefix_len,
                    mtu,
                    manage_route,
                    coordinator_url,
                } => {
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
                        stun_server,
                        false,
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
                            endpoint.endpoint.clone(),
                            std::sync::Arc::clone(&identity),
                            network_id.clone(),
                            coordinator_url.clone(),
                            peer.clone(),
                            relay_server,
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
                                relay_server,
                                false,
                            )
                            .await;
                            (peer, keep_outbound, result)
                        });
                    }
                    let (accepted_tx, mut accepted_rx) = tokio::sync::mpsc::channel(64);
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
                        let settle_deadline = first_peer_at
                            .map(|at| at + Duration::from_secs(1))
                            .unwrap_or(startup_deadline);
                        tokio::select! {
                            accepted = accepted_rx.recv(), if !accept_finished => {
                                match accepted {
                                    Some((peer, channel, remote)) => {
                                        if connected.iter().any(|known| known.0.device_id == peer.device_id) {
                                            channel.close();
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
                                    Ok((channel, remote)) => {
                                        if keep_outbound || channel.transport_name() == "Relay/TLS" {
                                            if connected.iter().any(|known| known.0.device_id == peer.device_id) {
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
                    if connected.is_empty() {
                        println!(
                            "No mesh peers are connected yet; waiting for membership updates."
                        );
                    }
                    let tun = create_tun(local_ipv4, prefix_len, mtu)?;
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
                                if let Err(error) = sender.try_send(channel) {
                                    error.into_inner().close();
                                }
                            } else {
                                channel.close();
                            }
                        }
                    });
                    let refresh = spawn_mesh_membership_refresh(MeshMembershipRefresh {
                        coordinator_url: coordinator_url.clone(),
                        network_id: network_id.clone(),
                        identity: std::sync::Arc::clone(&identity),
                        endpoint: endpoint.endpoint.clone(),
                        relay_server,
                        snapshot_tx,
                        allowlist_tx,
                        registry,
                        updates_tx: mesh_updates_tx,
                        initial_peers: initially_connected,
                    });
                    let result =
                        run_peer_mesh(&tun, connected, manage_route, mesh_updates_rx).await;
                    refresh.abort();
                    accepted_dispatcher.abort();
                    for task in accept_tasks {
                        task.abort();
                    }
                    result?;
                }
            },
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
                let packet = channel.recv_packet().await?;
                println!("Received authenticated datagram ({} bytes)", packet.len());
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
                channel.send_packet(message.as_bytes()).await?;
                println!("Sent authenticated datagram ({} bytes)", message.len());
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
        },
    }
    Ok(())
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

async fn wait_reconnect(attempt: u32) -> bool {
    let delay = mini_tunnel_agent::reconnect_delay(attempt);
    eprintln!("Retrying peer connection in {:.2}s", delay.as_secs_f32());
    tokio::select! {
        _ = tokio::signal::ctrl_c() => false,
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
    let response = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?
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
    Err(format!("{}: {}", error.error, error.message).into())
}

async fn run_peer_tunnel(
    tun: &mini_tunnel_agent::tun_device::TunDevice,
    channel: &mini_tunnel_agent::PeerChannel,
    peer: &PeerInfo,
    remote: SocketAddr,
    manage_route: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use mini_tunnel_agent::routing::{
        RouteLease, RoutingPlatform, SystemRouteRunner, install_peer_route,
    };

    let peer_ipv4 = peer.assigned_ipv4.parse()?;
    let runner = SystemRouteRunner;
    let route: Option<RouteLease> = if manage_route {
        let interface = tun.name()?;
        Some(install_peer_route(&runner, RoutingPlatform::current(), &interface, peer_ipv4).await?)
    } else {
        None
    };
    print_tunnel_ready(tun, peer, remote, channel.transport_name(), manage_route);
    let pump = mini_tunnel_agent::tunnel::pump_peer_packets(tun, channel, peer_ipv4);
    tokio::pin!(pump);
    let tunnel_result: Result<(), Box<dyn std::error::Error + Send + Sync>> = tokio::select! {
        result = &mut pump => result.map_err(Into::into),
        signal = tokio::signal::ctrl_c() => signal.map_err(Into::into),
    };
    if let Some(route) = route {
        route.remove(&runner).await?;
    }
    tunnel_result
}

async fn connect_tunnel_peer(
    endpoint: &TunnelEndpoint,
    peer: &PeerInfo,
    network_id: &str,
    identity: &mini_tunnel_agent::Identity,
    peer_key: [u8; 32],
) -> Result<(mini_tunnel_agent::PeerChannel, SocketAddr), mini_tunnel_agent::IdentityError> {
    if let Some(remote) = select_ice_peer_address(endpoint, peer, identity).await {
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
            Ok(channel) => return Ok((channel, remote)),
            Err(mini_tunnel_agent::IdentityError::UnauthorizedPeer) => {
                return Err(mini_tunnel_agent::IdentityError::UnauthorizedPeer);
            }
            Err(error) => {
                eprintln!("ICE selected {remote}, retrying advertised candidates: {error}")
            }
        }
    }
    mini_tunnel_agent::connect_peer_candidates(
        &endpoint.endpoint,
        &peer.candidates,
        network_id,
        identity,
        &peer.device_id,
        peer_key,
    )
    .await
    .map_err(|error| match error {
        mini_tunnel_agent::CandidateConnectError::UnauthorizedPeer => {
            mini_tunnel_agent::IdentityError::UnauthorizedPeer
        }
        other => mini_tunnel_agent::IdentityError::Transport(other.to_string()),
    })
}

async fn select_ice_peer_address(
    endpoint: &TunnelEndpoint,
    peer: &PeerInfo,
    identity: &mini_tunnel_agent::Identity,
) -> Option<SocketAddr> {
    let local = endpoint.ice.as_ref()?;
    let remote = peer.ice_credentials.as_ref()?;
    let remote_candidates = udp_candidate_addresses(&peer.candidates);
    if remote_candidates.is_empty() || local.local_candidates.is_empty() {
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
    let result = async {
        let mut driver = mini_tunnel_agent::ice::IceAgentDriver::for_peer(
            &local.credentials,
            remote,
            &local.local_candidates,
            &remote_candidates,
            controlling,
            std::time::Instant::now(),
        )
        .map_err(|error| error.to_string())?;
        driver
            .run_checks(
                &local.socket,
                &local.router,
                &local_ufrag,
                &remote.ufrag,
                &mut datagrams,
                Duration::from_secs(5),
            )
            .await
            .map(|(_, remote)| remote)
            .map_err(|error| error.to_string())
    }
    .await;
    let _ = local.router.unregister(&local_ufrag, &remote.ufrag);
    match result {
        Ok(remote) => {
            tracing::info!(peer_id = %peer.device_id, %remote, "ICE nominated a direct peer path");
            Some(remote)
        }
        Err(error) => {
            tracing::debug!(peer_id = %peer.device_id, %error, "ICE checks failed; using transport fallback");
            None
        }
    }
}

async fn connect_mesh_peer(
    endpoint: &quinn::Endpoint,
    network_id: &str,
    coordinator_url: &str,
    identity: &mini_tunnel_agent::Identity,
    peer: &PeerInfo,
    relay_server: Option<SocketAddr>,
    reliable_only: bool,
) -> Result<(mini_tunnel_agent::PeerChannel, SocketAddr), mini_tunnel_agent::IdentityError> {
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
    let candidates = candidates_for_path(&peer.candidates, reliable_only);
    match mini_tunnel_agent::connect_peer_candidates(
        endpoint,
        &candidates,
        network_id,
        identity,
        &peer.device_id,
        peer_key,
    )
    .await
    {
        Ok(connection) => Ok(connection),
        Err(direct_error) => {
            if matches!(
                direct_error,
                mini_tunnel_agent::CandidateConnectError::UnauthorizedPeer
            ) {
                return Err(mini_tunnel_agent::IdentityError::UnauthorizedPeer);
            }
            let relay = relay_server.ok_or_else(|| {
                mini_tunnel_agent::IdentityError::Transport(direct_error.to_string())
            })?;
            let channel =
                connect_mesh_peer_via_relay(relay, coordinator_url, network_id, identity, &peer)
                    .await?;
            let remote = channel.remote_address();
            Ok((channel, remote))
        }
    }
}

fn build_mesh_peer_connectors(
    endpoint: quinn::Endpoint,
    identity: std::sync::Arc<mini_tunnel_agent::Identity>,
    network_id: String,
    coordinator_url: String,
    peer: PeerInfo,
    relay_server: Option<SocketAddr>,
) -> (
    mini_tunnel_agent::tunnel::PeerConnector,
    mini_tunnel_agent::tunnel::PeerConnector,
    tokio::sync::mpsc::Sender<mini_tunnel_agent::PeerChannel>,
) {
    let keep_outbound = identity.device_id() < peer.device_id;
    let (accepted_tx, accepted_rx) = tokio::sync::mpsc::channel(2);
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
                        relay_server,
                        force_reliable,
                    )
                    .await
                    .map(|(channel, _)| channel)
                })
            },
        )
    } else {
        let receiver = std::sync::Arc::clone(&receiver);
        let identity = std::sync::Arc::clone(&identity);
        let coordinator_url = coordinator_url.clone();
        let network_id = network_id.clone();
        let peer = peer.clone();
        std::sync::Arc::new(
            move |force_reliable| -> mini_tunnel_agent::tunnel::PeerConnectFuture {
                let receiver = std::sync::Arc::clone(&receiver);
                let identity = std::sync::Arc::clone(&identity);
                let coordinator_url = coordinator_url.clone();
                let network_id = network_id.clone();
                let peer = peer.clone();
                Box::pin(async move {
                    let direct_wait = if force_reliable { 35 } else { 65 };
                    if let Ok(Some(channel)) =
                        tokio::time::timeout(Duration::from_secs(direct_wait), async {
                            receiver.lock().await.recv().await
                        })
                        .await
                    {
                        return Ok(channel);
                    }
                    let relay = relay_server.ok_or_else(|| {
                        mini_tunnel_agent::IdentityError::Transport(
                            "timed out waiting for peer redial".to_owned(),
                        )
                    })?;
                    connect_mesh_peer_via_relay(
                        relay,
                        &coordinator_url,
                        &network_id,
                        &identity,
                        &peer,
                    )
                    .await
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
                let (channel, _) = connect_mesh_peer(
                    &endpoint,
                    &network_id,
                    &coordinator_url,
                    &identity,
                    &peer,
                    None,
                    false,
                )
                .await?;
                validate_udp_probe(channel).await
            })
        })
    } else {
        let receiver = std::sync::Arc::clone(&receiver);
        std::sync::Arc::new(move |_| -> mini_tunnel_agent::tunnel::PeerConnectFuture {
            let receiver = std::sync::Arc::clone(&receiver);
            Box::pin(async move {
                let deadline = tokio::time::Instant::now() + Duration::from_secs(35);
                loop {
                    let channel = tokio::time::timeout_at(deadline, async {
                        receiver.lock().await.recv().await
                    })
                    .await
                    .map_err(|_| {
                        mini_tunnel_agent::IdentityError::Transport(
                            "timed out waiting for direct probe".to_owned(),
                        )
                    })?
                    .ok_or_else(|| {
                        mini_tunnel_agent::IdentityError::Transport(
                            "peer accept dispatcher stopped".to_owned(),
                        )
                    })?;
                    if let Ok(channel) = validate_udp_probe(channel).await {
                        return Ok(channel);
                    }
                }
            })
        })
    };
    (connector, probe, accepted_tx)
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

struct MeshMembershipRefresh {
    coordinator_url: String,
    network_id: String,
    identity: std::sync::Arc<mini_tunnel_agent::Identity>,
    endpoint: quinn::Endpoint,
    relay_server: Option<SocketAddr>,
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
        relay_server,
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
                    eprintln!("mesh membership refresh failed; keeping current peers: {error}");
                    continue;
                }
                Err(_) => {
                    eprintln!("mesh membership refresh timed out; keeping current peers");
                    continue;
                }
            };
            if peers.len() > 4096 {
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
                    relay_server,
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
) -> Result<mini_tunnel_agent::PeerChannel, mini_tunnel_agent::IdentityError> {
    let rtt = channel.probe_health(3, Duration::from_secs(2)).await?;
    if rtt > Duration::from_millis(350) {
        return Err(mini_tunnel_agent::IdentityError::Transport(
            "direct path probe exceeded RTT threshold".to_owned(),
        ));
    }
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

async fn connect_mesh_peer_via_relay(
    relay: SocketAddr,
    coordinator_url: &str,
    network_id: &str,
    identity: &mini_tunnel_agent::Identity,
    peer: &PeerInfo,
) -> Result<mini_tunnel_agent::PeerChannel, mini_tunnel_agent::IdentityError> {
    let peer_key = decode_peer_key(&peer.public_key)
        .map_err(|_| mini_tunnel_agent::IdentityError::UnauthorizedPeer)?;
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
    let ticket: RelayTicketResponse = post_json(
        coordinator_url,
        &format!("/v1/networks/{network_id}/relay-ticket"),
        &request,
    )
    .await
    .map_err(|error| mini_tunnel_agent::IdentityError::Transport(error.to_string()))?;
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

async fn run_peer_mesh(
    tun: &mini_tunnel_agent::tun_device::TunDevice,
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
        RouteLease, RoutingPlatform, SystemRouteRunner, install_peer_route,
    };

    let prepared = peers
        .into_iter()
        .map(|(peer, channel, remote, connector, probe)| {
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((
                peer.device_id,
                peer.assigned_ipv4.parse::<Ipv4Addr>()?,
                channel,
                remote,
                connector,
                probe,
            ))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let interface = tun.name()?;
    let runner = SystemRouteRunner;
    let mut routes: std::collections::HashMap<Ipv4Addr, RouteLease> =
        std::collections::HashMap::new();
    let mut reconnecting_peers = Vec::with_capacity(prepared.len());
    for (device_id, peer_ipv4, channel, remote, connector, probe) in prepared {
        if manage_routes {
            match install_peer_route(&runner, RoutingPlatform::current(), &interface, peer_ipv4)
                .await
            {
                Ok(route) => {
                    routes.insert(peer_ipv4, route);
                }
                Err(error) => {
                    for route in routes.drain().map(|(_, route)| route) {
                        let _ = route.remove(&runner).await;
                    }
                    return Err(error.into());
                }
            }
        }
        println!(
            "Mesh peer {device_id} {peer_ipv4} via {} at {remote}",
            channel.transport_name()
        );
        reconnecting_peers.push(mini_tunnel_agent::tunnel::ReconnectingPeer {
            address: peer_ipv4,
            channel: std::sync::Arc::new(channel),
            connector,
            probe: Some(probe),
            probe_cooldown: Duration::from_secs(60),
        });
    }
    println!("Mesh established on TUN interface {interface}");
    let (pump_updates_tx, pump_updates_rx) = tokio::sync::mpsc::channel(64);
    let pump =
        mini_tunnel_agent::tunnel::pump_peer_mesh_dynamic(tun, reconnecting_peers, pump_updates_rx);
    tokio::pin!(pump);
    let mut updates_open = true;
    let tunnel_result: Result<(), Box<dyn std::error::Error + Send + Sync>> = loop {
        tokio::select! {
            result = &mut pump => break result.map_err(Into::into),
            signal = tokio::signal::ctrl_c() => break signal.map_err(Into::into),
            update = async {
                match updates_open {
                    true => updates.recv().await,
                    false => std::future::pending().await,
                }
            } => match update {
                Some(mini_tunnel_agent::tunnel::MeshPeerUpdate::Add(peer)) => {
                    let address = peer.address;
                    if routes.contains_key(&address) {
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
                    }
                    if let Err(error) = pump_updates_tx.send(mini_tunnel_agent::tunnel::MeshPeerUpdate::Add(peer)).await {
                        if let Some(route) = routes.remove(&address) {
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
    if let Some(error) = cleanup_error {
        return Err(error.into());
    }
    tunnel_result
}

#[derive(Clone)]
struct TunnelEndpoint {
    endpoint: quinn::Endpoint,
    ice: Option<TunnelIceState>,
}

#[derive(Clone)]
struct TunnelIceState {
    credentials: mini_tunnel_protocol::IceCredentials,
    socket: mini_tunnel_agent::ice::IceSocketHandle,
    router: mini_tunnel_agent::ice::IceDatagramRouterHandle,
    local_candidates: Vec<SocketAddr>,
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
    stun_server: Option<SocketAddr>,
    enable_ice: bool,
    extra_candidates: &[String],
    network_id: &str,
    coordinator_url: &str,
) -> Result<TunnelEndpoint, Box<dyn std::error::Error + Send + Sync>> {
    if enable_ice {
        let (iced, mapped_address) = match stun_server {
            Some(server) => {
                let (endpoint, mapped) = mini_tunnel_agent::ice::peer_endpoint_with_ice_and_stun(
                    identity, bind, server, 64,
                )
                .await?;
                (endpoint, Some(mapped))
            }
            None => (
                mini_tunnel_agent::ice::peer_endpoint_with_ice(identity, bind, 64)?,
                None,
            ),
        };
        let bound_address = iced.socket.local_addr()?;
        let mut candidates = extra_candidates.to_vec();
        if !bound_address.ip().is_unspecified() {
            candidates.push(bound_address.to_string());
        }
        if let Some(mapped_address) = mapped_address {
            candidates.push(mapped_address.to_string());
        }
        candidates.sort();
        candidates.dedup();
        if candidates.is_empty() {
            return Err(
                "ICE needs --stun-server, an explicit --candidate, or a concrete --bind address"
                    .into(),
            );
        }
        if candidates.len() > 8 {
            return Err("at most eight peer candidates can be published".into());
        }
        let mut local_candidates = vec![bound_address];
        local_candidates.extend(udp_candidate_addresses(&candidates));
        local_candidates.sort();
        local_candidates.dedup();
        // Keep the socket's local address first; rtc-ice uses this address to match inbound checks
        // against the local host candidate while the public mapping remains an additional pair.
        local_candidates.sort_by_key(|address| *address != bound_address);
        let credentials = mini_tunnel_agent::ice::generate_ice_credentials(1)?;
        let device_id = identity.device_id();
        let timestamp_ms = now_ms()?;
        let request = CandidateUpdateRequest {
            device_id: device_id.clone(),
            timestamp_ms,
            signature: identity.sign(&candidate_signing_bytes_with_ice(
                network_id,
                &device_id,
                timestamp_ms,
                &candidates,
                &credentials,
            )),
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
        let refresh_candidates = request.candidates.clone();
        let refresh_credentials = credentials.clone();
        let refresh_device_id = device_id.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
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
                let request = CandidateUpdateRequest {
                    device_id: refresh_device_id.clone(),
                    timestamp_ms,
                    signature: identity.sign(&candidate_signing_bytes_with_ice(
                        &refresh_network,
                        &refresh_device_id,
                        timestamp_ms,
                        &refresh_candidates,
                        &refresh_credentials,
                    )),
                    candidates: refresh_candidates.clone(),
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
            ice: Some(TunnelIceState {
                credentials,
                socket: iced.socket,
                router: iced.ice_router,
                local_candidates,
            }),
        });
    }
    if stun_server.is_none() && extra_candidates.is_empty() {
        return Ok(TunnelEndpoint {
            endpoint: mini_tunnel_agent::peer_endpoint(identity, bind)?,
            ice: None,
        });
    }
    let (endpoint, mapped_address) = match stun_server {
        Some(server) => {
            let (endpoint, mapped) =
                mini_tunnel_agent::peer_endpoint_with_stun(identity, bind, server).await?;
            (endpoint, Some(mapped))
        }
        None => (mini_tunnel_agent::peer_endpoint(identity, bind)?, None),
    };
    let device_id = identity.device_id();
    let timestamp_ms = now_ms()?;
    let mut candidates = extra_candidates.to_vec();
    if let Some(mapped_address) = mapped_address {
        candidates.push(mapped_address.to_string());
    }
    candidates.sort();
    candidates.dedup();
    if candidates.len() > 8 {
        return Err("at most eight peer candidates can be published".into());
    }
    let candidate_count = candidates.len();
    let request = CandidateUpdateRequest {
        device_id: device_id.clone(),
        timestamp_ms,
        signature: identity.sign(&candidate_signing_bytes(
            network_id,
            &device_id,
            timestamp_ms,
            &candidates,
        )),
        candidates,
        ice_credentials: None,
    };
    let path = format!("/v1/networks/{network_id}/candidates");
    let _: CandidateUpdateResponse = post_json(coordinator_url, &path, &request).await?;
    println!("Published {candidate_count} peer candidate(s)");
    Ok(TunnelEndpoint {
        endpoint,
        ice: None,
    })
}

fn udp_candidate_addresses(candidates: &[String]) -> Vec<SocketAddr> {
    mini_tunnel_agent::candidate::CandidateChecklist::from_signaled(candidates, 8)
        .map(|checklist| {
            checklist
                .checks()
                .iter()
                .filter(|check| {
                    check.transport == mini_tunnel_agent::candidate::CandidateTransport::Udp
                })
                .map(|check| check.address)
                .collect()
        })
        .unwrap_or_default()
}

fn create_tun(
    local_ipv4: Ipv4Addr,
    prefix_len: u8,
    mtu: u16,
) -> Result<mini_tunnel_agent::tun_device::TunDevice, Box<dyn std::error::Error + Send + Sync>> {
    let mut config = mini_tunnel_agent::tun_device::TunConfig::ipv4(local_ipv4, prefix_len);
    config.mtu = mtu;
    Ok(mini_tunnel_agent::tun_device::TunDevice::create(config)?)
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

fn print_tunnel_ready(
    tun: &mini_tunnel_agent::tun_device::TunDevice,
    peer: &PeerInfo,
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
    if managed_route {
        println!(
            "Managed /32 route installed for peer {}.",
            peer.assigned_ipv4
        );
    } else {
        println!(
            "No explicit peer route was added; check whether the OS routed {} through this TUN interface.",
            peer.assigned_ipv4
        );
        println!("If needed, add a host route for this peer and remove it manually when stopping.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn capture_candidate_update(
        State(requests): State<std::sync::Arc<tokio::sync::Mutex<Vec<CandidateUpdateRequest>>>>,
        axum::Json(request): axum::Json<CandidateUpdateRequest>,
    ) -> axum::Json<CandidateUpdateResponse> {
        requests.lock().await.push(request);
        axum::Json(CandidateUpdateResponse { accepted: true })
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
            None,
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
            None,
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
            assert_eq!(
                request.signature,
                identity.sign(&candidate_signing_bytes_with_ice(
                    "test-network",
                    &request.device_id,
                    request.timestamp_ms,
                    &request.candidates,
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
            ),
            select_ice_peer_address(&endpoint_b, &peer_a, &identity_b),
            accept,
        );
        let (channel_a, remote) = connected.expect("connect via ICE-nominated path");
        assert_eq!(Some(endpoint_a.endpoint.local_addr().unwrap()), selected_b);
        assert_eq!(remote, endpoint_b.endpoint.local_addr().unwrap());
        let channel_b = accepted.expect("accept peer");
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
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind metrics listener");
        let address = listener.local_addr().expect("metrics address");
        let server =
            tokio::spawn(async move { axum::serve(listener, relay_metrics_router(relay)).await });
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
}
