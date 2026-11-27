use std::{
    net::{SocketAddr, TcpListener},
    process::{Child, Command, Stdio},
    time::Duration,
};

use mini_tunnel_protocol::{
    CreateInviteRequest, CreateInviteResponse, CreateNetworkRequest, CreateNetworkResponse,
    DeleteNetworkRequest, DeleteNetworkResponse,
};
use uuid::Uuid;

struct CoordinatorProcess(Child);

impl CoordinatorProcess {
    fn start(address: SocketAddr, database_url: &str) -> Self {
        let child = Command::new(env!("CARGO_BIN_EXE_mini-tunnel"))
            .args(["coordinator", "serve", "--listen", &address.to_string()])
            .env("MINI_TUNNEL_COORDINATOR_DATABASE_URL", database_url)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start Coordinator process");
        Self(child)
    }
}

impl Drop for CoordinatorProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn unused_loopback_address() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("reserve a loopback port");
    listener
        .local_addr()
        .expect("read reserved loopback address")
}

async fn wait_until_healthy(client: &reqwest::Client, address: SocketAddr) {
    let url = format!("http://{address}/healthz");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        if let Ok(response) = client.get(&url).send().await
            && response.status().is_success()
        {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "Coordinator process at {address} did not become healthy"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires MINI_TUNNEL_TEST_APP_DATABASE_URL and a disposable PostgreSQL service"]
async fn postgres_state_is_shared_between_coordinator_processes() {
    let database_url = std::env::var("MINI_TUNNEL_TEST_APP_DATABASE_URL")
        .expect("set MINI_TUNNEL_TEST_APP_DATABASE_URL to a least-privilege runtime role");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .expect("build Coordinator test client");
    let first_address = unused_loopback_address();
    let second_address = unused_loopback_address();
    let first = CoordinatorProcess::start(first_address, &database_url);
    let second = CoordinatorProcess::start(second_address, &database_url);

    wait_until_healthy(&client, first_address).await;
    wait_until_healthy(&client, second_address).await;

    let network_id = Uuid::new_v4();
    let octets = network_id.as_bytes();
    let cidr = format!("10.{}.{}.0/24", octets[0], octets[1]);
    let first_url = format!("http://{first_address}");
    let second_url = format!("http://{second_address}");
    let created = client
        .post(format!("{first_url}/v1/networks"))
        .json(&CreateNetworkRequest {
            name: "process-level postgres test".to_owned(),
            cidr,
            network_id: Some(network_id),
        })
        .send()
        .await
        .expect("create network through first Coordinator");
    assert!(
        created.status().is_success(),
        "first Coordinator rejected test network creation: {}",
        created.status()
    );
    let created: CreateNetworkResponse = created
        .json()
        .await
        .expect("decode network creation response");

    let invite_result = client
        .post(format!("{second_url}/v1/networks/{network_id}/invites"))
        .json(&CreateInviteRequest {
            admin_token: created.admin_token.clone(),
        })
        .send()
        .await
        .expect("create invite through second Coordinator");
    let invite_is_shared = if invite_result.status().is_success() {
        let invite: CreateInviteResponse = invite_result
            .json()
            .await
            .expect("decode invite response from second Coordinator");
        !invite.invite_token.is_empty() && invite.expires_in_seconds > 0
    } else {
        false
    };

    drop(first);
    let restarted_address = unused_loopback_address();
    let restarted = CoordinatorProcess::start(restarted_address, &database_url);
    wait_until_healthy(&client, restarted_address).await;
    let restarted_url = format!("http://{restarted_address}");
    let restarted_invite_result = client
        .post(format!("{restarted_url}/v1/networks/{network_id}/invites"))
        .json(&CreateInviteRequest {
            admin_token: created.admin_token.clone(),
        })
        .send()
        .await
        .expect("create invite through restarted Coordinator");
    let restart_preserved_state = if restarted_invite_result.status().is_success() {
        let invite: CreateInviteResponse = restarted_invite_result
            .json()
            .await
            .expect("decode invite response from restarted Coordinator");
        !invite.invite_token.is_empty() && invite.expires_in_seconds > 0
    } else {
        false
    };

    let deleted = client
        .post(format!("{second_url}/v1/networks/{network_id}/delete"))
        .json(&DeleteNetworkRequest {
            admin_token: created.admin_token,
            confirm_network_id: network_id.to_string(),
        })
        .send()
        .await
        .expect("clean up test network through second Coordinator");
    assert!(
        deleted.status().is_success(),
        "second Coordinator could not delete test network: {}",
        deleted.status()
    );
    let deleted: DeleteNetworkResponse = deleted
        .json()
        .await
        .expect("decode network deletion response");
    assert!(
        deleted.deleted,
        "test network cleanup must delete one network"
    );
    assert!(
        invite_is_shared,
        "second Coordinator must read the network created by the first process"
    );
    assert!(
        restart_preserved_state,
        "a fresh Coordinator process must read the network persisted by its predecessor"
    );

    drop(restarted);
    drop(second);
}
