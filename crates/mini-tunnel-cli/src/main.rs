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
        /// Optional RFC 8489 STUN server used to discover and publish this UDP socket's mapped address.
        #[arg(long)]
        stun_server: Option<SocketAddr>,
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
                    stun_server,
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
                        &candidates,
                        &network_id,
                        &coordinator_url,
                    )
                    .await?;
                    let peer =
                        discover_peer(&coordinator_url, &network_id, &peer_id, &identity).await?;
                    let peer_key = decode_peer_key(&peer.public_key)?;
                    let tun = create_tun(local_ipv4, prefix_len, mtu)?;
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
                    tcp_bind,
                    stun_server,
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
                        &candidates,
                        &network_id,
                        &coordinator_url,
                    )
                    .await?;
                    let peer =
                        discover_peer(&coordinator_url, &network_id, &peer_id, &identity).await?;
                    let peer_key = decode_peer_key(&peer.public_key)?;
                    let tun = create_tun(local_ipv4, prefix_len, mtu)?;
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
                    );
                    let channel = if let Some(listener) = &tcp_listener {
                        let allowed = vec![(peer.device_id.clone(), peer_key)];
                        tokio::select! {
                            result = channel => result?,
                            result = mini_tunnel_agent::accept_tcp_peer_any(
                                listener,
                                &network_id,
                                &identity,
                                &allowed,
                            ) => result?.1,
                        }
                    } else {
                        channel.await?
                    };
                    let remote = channel.remote_address();
                    run_peer_tunnel(&tun, &channel, &peer, remote, manage_route).await?;
                }
                TunnelCommand::Mesh {
                    bind,
                    tcp_bind,
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
                        &candidates,
                        &network_id,
                        &coordinator_url,
                    )
                    .await?;
                    if let Some(listener) = &tcp_listener {
                        println!("TCP fallback listening on {}", listener.local_addr()?);
                    }
                    let peers = discover_peers(&coordinator_url, &network_id, &identity).await?;
                    if peers.is_empty() {
                        return Err("no other enrolled peers are available in this network".into());
                    }
                    let local_device_id = identity.device_id();
                    let identity = std::sync::Arc::new(identity);
                    let mut attempts = tokio::task::JoinSet::new();
                    let mut inbound_peers = peers.clone();
                    for peer in peers.iter().cloned() {
                        let keep_outbound = local_device_id < peer.device_id;
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
                            )
                            .await;
                            (peer, keep_outbound, result)
                        });
                    }
                    let (accepted_tx, mut accepted_rx) = tokio::sync::mpsc::channel(64);
                    let mut accept_tasks = vec![{
                        let endpoint = endpoint.clone();
                        let identity = std::sync::Arc::clone(&identity);
                        let network_id = network_id.clone();
                        let local_device_id = local_device_id.clone();
                        let accepted_tx = accepted_tx.clone();
                        tokio::spawn(async move {
                            let deadline = tokio::time::Instant::now() + Duration::from_secs(45);
                            while !inbound_peers.is_empty() {
                                let allowed = inbound_peers
                                    .iter()
                                    .map(|peer| {
                                        Ok::<_, Box<dyn std::error::Error + Send + Sync>>((
                                            peer.device_id.clone(),
                                            decode_peer_key(&peer.public_key)?,
                                        ))
                                    })
                                    .collect::<Result<Vec<_>, _>>()?;
                                let accepted = tokio::time::timeout_at(
                                    deadline,
                                    mini_tunnel_agent::accept_peer_any(
                                        &endpoint,
                                        &network_id,
                                        &identity,
                                        &allowed,
                                    ),
                                )
                                .await;
                                let Ok(Ok((device_id, channel))) = accepted else {
                                    break;
                                };
                                if let Some(index) = inbound_peers
                                    .iter()
                                    .position(|peer| peer.device_id == device_id)
                                {
                                    let peer = inbound_peers.remove(index);
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
                        let mut tcp_inbound_peers = peers.clone();
                        let identity = std::sync::Arc::clone(&identity);
                        let network_id = network_id.clone();
                        let local_device_id = local_device_id.clone();
                        let accepted_tx = accepted_tx.clone();
                        accept_tasks.push(tokio::spawn(async move {
                            let deadline = tokio::time::Instant::now() + Duration::from_secs(45);
                            while !tcp_inbound_peers.is_empty() {
                                let allowed = tcp_inbound_peers
                                    .iter()
                                    .map(|peer| {
                                        Ok::<_, Box<dyn std::error::Error + Send + Sync>>((
                                            peer.device_id.clone(),
                                            decode_peer_key(&peer.public_key)?,
                                        ))
                                    })
                                    .collect::<Result<Vec<_>, _>>()?;
                                let accepted = tokio::time::timeout_at(
                                    deadline,
                                    mini_tunnel_agent::accept_tcp_peer_any(
                                        &listener,
                                        &network_id,
                                        &identity,
                                        &allowed,
                                    ),
                                )
                                .await;
                                let Ok(Ok((device_id, channel))) = accepted else {
                                    break;
                                };
                                if let Some(index) = tcp_inbound_peers
                                    .iter()
                                    .position(|peer| peer.device_id == device_id)
                                {
                                    let peer = tcp_inbound_peers.remove(index);
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
                    let mut connected: Vec<(PeerInfo, mini_tunnel_agent::PeerChannel, SocketAddr)> =
                        Vec::new();
                    let mut accept_finished = accept_tasks.is_empty();
                    let startup_deadline = tokio::time::Instant::now() + Duration::from_secs(45);
                    let mut first_peer_at = None;
                    loop {
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
                                            connected.push((peer, channel, remote));
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
                                        if keep_outbound {
                                            if connected.iter().any(|known| known.0.device_id == peer.device_id) {
                                                channel.close();
                                            } else {
                                                println!("Connected mesh peer {} at {remote}", peer.device_id);
                                                connected.push((peer, channel, remote));
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
                    for task in accept_tasks.drain(..) {
                        task.abort();
                        let _ = task.await;
                    }
                    if connected.is_empty() {
                        return Err(
                            "no authenticated peer connected before the 45-second startup timeout"
                                .into(),
                        );
                    }
                    let tun = create_tun(local_ipv4, prefix_len, mtu)?;
                    run_peer_mesh(&tun, connected, manage_route).await?;
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

async fn connect_mesh_peer(
    endpoint: &quinn::Endpoint,
    network_id: &str,
    coordinator_url: &str,
    identity: &mini_tunnel_agent::Identity,
    peer: &PeerInfo,
) -> Result<(mini_tunnel_agent::PeerChannel, SocketAddr), String> {
    let mut peer = peer.clone();
    for _ in 0..10 {
        if !peer.candidates.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
        peer = discover_peer(coordinator_url, network_id, &peer.device_id, identity)
            .await
            .map_err(|error| error.to_string())?;
    }
    let peer_key = decode_peer_key(&peer.public_key).map_err(|error| error.to_string())?;
    mini_tunnel_agent::connect_peer_candidates(
        endpoint,
        &peer.candidates,
        network_id,
        identity,
        &peer.device_id,
        peer_key,
    )
    .await
    .map_err(|error| error.to_string())
}

async fn run_peer_mesh(
    tun: &mini_tunnel_agent::tun_device::TunDevice,
    peers: Vec<(PeerInfo, mini_tunnel_agent::PeerChannel, SocketAddr)>,
    manage_routes: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use mini_tunnel_agent::routing::{
        RouteLease, RoutingPlatform, SystemRouteRunner, install_peer_route,
    };

    let prepared = peers
        .into_iter()
        .map(|(peer, channel, remote)| {
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((
                peer.device_id,
                peer.assigned_ipv4.parse::<Ipv4Addr>()?,
                channel,
                remote,
            ))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let interface = tun.name()?;
    let runner = SystemRouteRunner;
    let mut routes: Vec<RouteLease> = Vec::new();
    let mut channels = Vec::with_capacity(prepared.len());
    for (device_id, peer_ipv4, channel, remote) in prepared {
        if manage_routes {
            match install_peer_route(&runner, RoutingPlatform::current(), &interface, peer_ipv4)
                .await
            {
                Ok(route) => routes.push(route),
                Err(error) => {
                    for route in routes.drain(..).rev() {
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
        channels.push((peer_ipv4, std::sync::Arc::new(channel)));
    }
    println!("Mesh established on TUN interface {interface}");
    let pump = mini_tunnel_agent::tunnel::pump_peer_mesh(tun, channels);
    tokio::pin!(pump);
    let tunnel_result: Result<(), Box<dyn std::error::Error + Send + Sync>> = tokio::select! {
        result = &mut pump => result.map_err(Into::into),
        signal = tokio::signal::ctrl_c() => signal.map_err(Into::into),
    };
    let mut cleanup_error = None;
    for route in routes.into_iter().rev() {
        if let Err(error) = route.remove(&runner).await {
            cleanup_error.get_or_insert(error);
        }
    }
    if let Some(error) = cleanup_error {
        return Err(error.into());
    }
    tunnel_result
}

async fn create_tunnel_endpoint(
    identity: &mini_tunnel_agent::Identity,
    bind: SocketAddr,
    stun_server: Option<SocketAddr>,
    extra_candidates: &[String],
    network_id: &str,
    coordinator_url: &str,
) -> Result<quinn::Endpoint, Box<dyn std::error::Error + Send + Sync>> {
    if stun_server.is_none() && extra_candidates.is_empty() {
        return Ok(mini_tunnel_agent::peer_endpoint(identity, bind)?);
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
    };
    let path = format!("/v1/networks/{network_id}/candidates");
    let _: CandidateUpdateResponse = post_json(coordinator_url, &path, &request).await?;
    println!("Published {candidate_count} peer candidate(s)");
    Ok(endpoint)
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
