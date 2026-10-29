use std::{
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    process::ExitCode,
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::{Parser, Subcommand};
use mini_tunnel_protocol::{
    ApiErrorResponse, CandidateUpdateRequest, CandidateUpdateResponse, CreateInviteRequest,
    CreateInviteResponse, CreateNetworkRequest, CreateNetworkResponse, JoinNetworkRequest,
    JoinNetworkResponse, PeerInfo, PeerListRequest, PeerListResponse, candidate_signing_bytes,
    join_signing_bytes, peers_signing_bytes,
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
    /// Accept one authorized peer, then pump IPv4 packets over QUIC.
    Listen {
        #[arg(long, default_value = "0.0.0.0:42000")]
        bind: SocketAddr,
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
}

#[derive(Debug, Deserialize)]
struct HealthResponse {
    status: String,
    service: String,
    version: String,
}

#[tokio::main]
async fn main() -> ExitCode {
    if let Err(error) = run(Cli::parse()).await {
        eprintln!("error: {error}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

fn default_coordinator_state_path() -> PathBuf {
    directories::ProjectDirs::from("org", "ilovn", "mini-tunnel")
        .map(|dirs| dirs.data_local_dir().join("coordinator-state.json"))
        .unwrap_or_else(|| PathBuf::from("mini-tunnel-state.json"))
}

async fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match cli.command {
        Command::Coordinator { command } => match command {
            CoordinatorCommand::Serve { listen, state_file } => {
                tracing_subscriber::fmt()
                    .with_env_filter(
                        tracing_subscriber::EnvFilter::try_from_default_env()
                            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
                    )
                    .init();
                mini_tunnel_coordinator::serve_with_state_file(listen, state_file).await?;
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
                    let peer =
                        discover_peer(&coordinator_url, &network_id, &peer_id, &identity).await?;
                    let peer_key = decode_peer_key(&peer.public_key)?;
                    let tun = create_tun(local_ipv4, prefix_len, mtu)?;
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
                    run_peer_tunnel(&tun, &channel, &peer, remote, manage_route).await?;
                }
                TunnelCommand::Listen {
                    bind,
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
                    let peer =
                        discover_peer(&coordinator_url, &network_id, &peer_id, &identity).await?;
                    let peer_key = decode_peer_key(&peer.public_key)?;
                    let tun = create_tun(local_ipv4, prefix_len, mtu)?;
                    let endpoint = mini_tunnel_agent::peer_endpoint(&identity, bind)?;
                    println!(
                        "Waiting for authenticated peer on {}",
                        endpoint.local_addr()?
                    );
                    let channel = mini_tunnel_agent::accept_peer(
                        &endpoint,
                        &network_id,
                        &identity,
                        &peer.device_id,
                        peer_key,
                    )
                    .await?;
                    let remote = channel.remote_address();
                    run_peer_tunnel(&tun, &channel, &peer, remote, manage_route).await?;
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
                channel.send_packet(message.as_bytes())?;
                println!(
                    "Connected to {} at {} and sent authenticated datagram ({} bytes)",
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
                channel.send_packet(message.as_bytes())?;
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
    print_tunnel_ready(tun, peer, remote, manage_route);
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
    let device_id = identity.device_id();
    let timestamp_ms = now_ms()?;
    let request = PeerListRequest {
        device_id: device_id.clone(),
        timestamp_ms,
        signature: identity.sign(&peers_signing_bytes(network_id, &device_id, timestamp_ms)),
    };
    let path = format!("/v1/networks/{network_id}/peers");
    let snapshot: PeerListResponse = post_json(coordinator_url, &path, &request).await?;
    snapshot
        .peers
        .into_iter()
        .find(|peer| peer.device_id == peer_id)
        .ok_or_else(|| "peer is not present in the signed same-network snapshot".into())
}

fn print_tunnel_ready(
    tun: &mini_tunnel_agent::tun_device::TunDevice,
    peer: &PeerInfo,
    remote: SocketAddr,
    managed_route: bool,
) {
    match tun.name() {
        Ok(name) => println!("TUN interface: {name}"),
        Err(error) => eprintln!("could not query TUN interface name: {error}"),
    }
    println!(
        "Tunnel established: local {} -> peer {} ({}, UDP {})",
        tun.local_ipv4(),
        peer.device_id,
        peer.assigned_ipv4,
        remote
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
}
