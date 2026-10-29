use std::{net::SocketAddr, process::ExitCode, time::Duration};

use clap::{Parser, Subcommand};
use mini_tunnel_protocol::{
    ApiErrorResponse, CreateInviteRequest, CreateInviteResponse, CreateNetworkRequest,
    CreateNetworkResponse, JoinNetworkRequest, JoinNetworkResponse,
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

async fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match cli.command {
        Command::Coordinator { command } => match command {
            CoordinatorCommand::Serve { listen } => {
                tracing_subscriber::fmt()
                    .with_env_filter(
                        tracing_subscriber::EnvFilter::try_from_default_env()
                            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
                    )
                    .init();
                mini_tunnel_coordinator::serve(listen).await?;
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
                let device_id = device_id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
                let request = JoinNetworkRequest {
                    invite_token,
                    device_id,
                };
                let path = format!("/v1/networks/{network_id}/join");
                let response: JoinNetworkResponse =
                    post_json(&coordinator_url, &path, &request).await?;
                println!("Joined network {}", response.network_id);
                println!("Device: {}", response.device_id);
                println!("Virtual IPv4: {}/{}", response.assigned_ipv4, response.cidr);
            }
        },
    }
    Ok(())
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
