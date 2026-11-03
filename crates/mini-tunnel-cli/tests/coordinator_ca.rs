use std::process::Command;

use axum::{Json, Router, extract::State, routing::get, routing::post};
use mini_tunnel_protocol::{CreateNetworkRequest, CreateNetworkResponse};
use serde_json::json;
use tokio::net::TcpListener;
use uuid::Uuid;

#[derive(Clone)]
struct TestCoordinatorState {
    network_id: String,
}

async fn health() -> Json<serde_json::Value> {
    Json(json!({
        "status": "ok",
        "service": "coordinator",
        "version": "test"
    }))
}

async fn create_network(
    State(state): State<TestCoordinatorState>,
    Json(request): Json<CreateNetworkRequest>,
) -> Json<CreateNetworkResponse> {
    Json(CreateNetworkResponse {
        network_id: state.network_id,
        name: request.name,
        cidr: request.cidr,
        admin_token: "test-only-admin-token".to_owned(),
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_accepts_private_coordinator_ca_for_health_and_rest_without_tls_bypass() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let temporary =
        std::env::temp_dir().join(format!("mini-tunnel-coordinator-ca-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&temporary).expect("create temporary test directory");
    let certified = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_owned()])
        .expect("generate test certificate");
    let certificate_pem = certified.cert.pem();
    let certificate_path = temporary.join("coordinator-ca.pem");
    std::fs::write(&certificate_path, &certificate_pem).expect("write test CA bundle");

    let tls_config = axum_server::tls_rustls::RustlsConfig::from_pem(
        certificate_pem.into_bytes(),
        certified.signing_key.serialize_pem().into_bytes(),
    )
    .await
    .expect("configure test HTTPS server");
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test HTTPS server");
    let address = listener.local_addr().expect("test HTTPS address");
    let std_listener = listener.into_std().expect("convert test listener");
    std_listener
        .set_nonblocking(true)
        .expect("make test listener nonblocking");

    let network_id = Uuid::new_v4().to_string();
    let app = Router::new()
        .route("/healthz", get(health))
        .route("/v1/networks", post(create_network))
        .with_state(TestCoordinatorState {
            network_id: network_id.clone(),
        });
    let server = axum_server::from_tcp_rustls(std_listener, tls_config)
        .expect("create test HTTPS server")
        .serve(app.into_make_service());
    let server_task = tokio::spawn(server);
    let coordinator_url = format!("https://{address}");
    let binary = env!("CARGO_BIN_EXE_mini-tunnel");

    let default_trust = Command::new(binary)
        .args(["coordinator", "health", "--url", &coordinator_url])
        .env_remove("MINI_TUNNEL_COORDINATOR_CA_CERT_FILE")
        .output()
        .expect("run Coordinator health command with default trust");
    assert!(
        !default_trust.status.success(),
        "default trust must reject the self-signed test certificate"
    );

    let custom_ca_health = Command::new(binary)
        .args(["coordinator", "health", "--url", &coordinator_url])
        .env("MINI_TUNNEL_COORDINATOR_CA_CERT_FILE", &certificate_path)
        .output()
        .expect("run Coordinator health command with custom CA");
    assert!(
        custom_ca_health.status.success(),
        "private-CA health request failed: {}",
        String::from_utf8_lossy(&custom_ca_health.stderr)
    );
    assert!(String::from_utf8_lossy(&custom_ca_health.stdout).contains("coordinator test: ok"));

    let custom_ca_rest = Command::new(binary)
        .args([
            "network",
            "create",
            "--name",
            "private-ca-test",
            "--cidr",
            "10.211.0.0/24",
            "--coordinator-url",
            &coordinator_url,
        ])
        .env("MINI_TUNNEL_COORDINATOR_CA_CERT_FILE", &certificate_path)
        .output()
        .expect("run REST command with custom CA");
    assert!(
        custom_ca_rest.status.success(),
        "private-CA REST request failed: {}",
        String::from_utf8_lossy(&custom_ca_rest.stderr)
    );
    let stdout = String::from_utf8_lossy(&custom_ca_rest.stdout);
    assert!(stdout.contains(&network_id));
    assert!(stdout.contains("10.211.0.0/24"));

    let invalid_bundle = temporary.join("invalid-ca.pem");
    std::fs::write(&invalid_bundle, "INVALID_CA_SENTINEL").expect("write invalid test bundle");
    let invalid_ca = Command::new(binary)
        .args(["coordinator", "health", "--url", &coordinator_url])
        .env("MINI_TUNNEL_COORDINATOR_CA_CERT_FILE", &invalid_bundle)
        .output()
        .expect("run health command with invalid CA");
    assert!(!invalid_ca.status.success());
    let stderr = String::from_utf8_lossy(&invalid_ca.stderr);
    assert!(stderr.contains("Coordinator CA certificate bundle"));
    assert!(!stderr.contains("INVALID_CA_SENTINEL"));

    let missing_bundle = temporary.join("missing-ca.pem");
    let unreadable_ca = Command::new(binary)
        .args(["coordinator", "health", "--url", &coordinator_url])
        .env("MINI_TUNNEL_COORDINATOR_CA_CERT_FILE", &missing_bundle)
        .output()
        .expect("run health command with missing CA file");
    assert!(!unreadable_ca.status.success());
    let stderr = String::from_utf8_lossy(&unreadable_ca.stderr);
    assert!(stderr.contains("could not inspect Coordinator CA certificate bundle"));
    assert!(!stderr.contains(missing_bundle.to_string_lossy().as_ref()));

    server_task.abort();
    let _ = server_task.await;
    std::fs::remove_dir_all(temporary).expect("remove temporary test directory");
}
