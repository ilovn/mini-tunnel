# Linux systemd deployment templates

The Coordinator and opaque Relay templates run as unprivileged server services; the separate peer template grants only the TUN/route privileges required by a client mesh. All templates require systemd 247 or newer for the complete sandbox profile. They do not configure a firewall, TLS proxy, certificate renewal, or secret distribution. Review those choices for your host before enabling the units.

## Quick install for a Linux peer

`deploy/install-peer.sh` installs an already-built Linux binary and enrolls one systemd peer. It never compiles or downloads code, creates a Coordinator network, or issues an invite. Create the network and a one-use invite on the Coordinator first, then copy the invite to the peer over a protected channel with mode `0600`. The Coordinator must be reachable over HTTPS in normal deployments; use `--coordinator-ca` when it uses a private CA.

For a bounded first-install acceptance procedure, including artifact checksums, startup/status checks, bidirectional overlay traffic, evidence capture, and rollback, see the [peer deployment acceptance runbook](../../docs/deployment-acceptance.md).

From a checkout containing the deployment scripts and unit template, run one command to download the prebuilt release and install/enroll the peer. Create the network and one-use invite on the Coordinator first; the invite file must already have mode `0600`:

```sh
deploy/quick-install-peer.sh --release latest --arch auto -- \
  --network-id 00000000-0000-0000-0000-000000000000 \
  --coordinator-url https://coordinator.example:8443 \
  --invite-token-file ./invite.token \
  --instance office \
  --stun-server 111.206.174.2:3478 \
  --relay-server relay.example:42001 \
  --udp-relay-server relay.example:42003
```

The wrapper downloads a release artifact through `download-peer.sh`, which checks its published digests and fails closed unless GitHub CLI (`gh`) verifies the Sigstore attestation against the expected repository, workflow, source ref, and commit. It fetches the public attestation bundle anonymously; no `gh auth login` is needed for a public release. It never builds on the peer. Install a recent GitHub CLI with `attestation verify` support before running it. The wrapper then invokes `install-peer.sh`, using `sudo` only for installation when needed. Download options go before `--`; all remaining options are passed to the installer after `--`. For example, to install an exact successful CI commit before it has a published release:

```sh
export GITHUB_TOKEN # provide a read-only Actions token through your secret manager
deploy/quick-install-peer.sh \
  --commit <full-40-character-commit-sha> --arch x86_64 -- \
  --network-id 00000000-0000-0000-0000-000000000000 \
  --coordinator-url https://coordinator.example:8443 \
  --invite-token-file ./invite.token --instance office
```

The CI artifact mode requires `GITHUB_TOKEN` with Actions artifact read access; the token is only read from the process environment. Published release downloads do not require a token. For reproducibility, pass a fixed `--release vX.Y.Z`. The standalone `download-peer.sh` and `install-peer.sh` remain available when you want to inspect or verify the downloaded artifact before installing it.

Omit either Relay option if that transport is not configured. For a private CA, add `--coordinator-ca ./coordinator-ca.pem`. Before installing, `--validate-only` checks the binary, UUID, endpoint syntax, invite-file type/permissions, and presence of the unit template without changing the machine. The installer copies the invite into `/var/lib/mini-tunnel` with mode `0600`, consumes it for enrollment, and removes the temporary copy. It does not delete the source invite file. It refuses to overwrite an existing peer instance config; use a new `--instance` for another network. After installation, inspect it with:

```sh
sudo systemctl status mini-tunnel-peer@office.service
sudo journalctl -fu mini-tunnel-peer@office.service
sudo -u mini-tunnel /usr/local/bin/mini-tunnel peer status --url http://127.0.0.1:42003
```

The script requires Linux, systemd 247+, `/dev/net/tun`, and a binary for the target CPU architecture. It does not open firewall ports. For multiple networks on one host, use a distinct `--instance`, `--bind-address`, and `--status-listen` port for each instance. For rollback, stop/disable the instance with `sudo systemctl disable --now mini-tunnel-peer@office.service`; its identity and membership remain under `/var/lib/mini-tunnel`, and its config remains under `/etc/mini-tunnel` so a stopped deployment can be inspected or restarted.

## Linux peer mesh service

`mini-tunnel-peer@.service` runs one mesh network per systemd instance under the dedicated `mini-tunnel` account. It enables ICE, configures the selected STUN service, installs only authenticated peer host routes, and restarts the foreground CLI after an unexpected exit. It grants `CAP_NET_ADMIN`, access to `/dev/net/tun`, and the `AF_NETLINK` family required for TUN and route setup. It explicitly removes Coordinator admin, invite, and Relay signing-key variables before starting the peer process.

Install the account if it is not already present from a Coordinator/Relay deployment, then install the binary. The peer service keeps its identity and joined-network membership beneath `/var/lib/mini-tunnel`; systemd creates that state directory with mode `0700`:

```sh
getent passwd mini-tunnel >/dev/null || \
  sudo useradd --system --home-dir /var/lib/mini-tunnel --create-home \
    --shell /usr/sbin/nologin mini-tunnel
sudo install -m 0755 mini-tunnel /usr/local/bin/mini-tunnel
sudo install -d -o root -g root -m 0755 /etc/mini-tunnel
sudo install -d -o mini-tunnel -g mini-tunnel -m 0700 /var/lib/mini-tunnel
sudo install -m 0644 mini-tunnel-peer@.service /etc/systemd/system/mini-tunnel-peer@.service
```

Create a root-owned per-network environment file. Values must not contain whitespace; `BIND_ADDRESS` is the local UDP socket, and `STUN_SERVER` is one numeric `host:port` endpoint. If running more than one network on a host, assign a distinct UDP bind port and status port to each instance:

```sh
sudo install -o root -g root -m 0600 /dev/null /etc/mini-tunnel/peer-office.env
sudoedit /etc/mini-tunnel/peer-office.env
```

The file contains non-secret connection settings:

```ini
NETWORK_ID=00000000-0000-0000-0000-000000000000
BIND_ADDRESS=0.0.0.0:42000
STUN_SERVER=111.206.174.3:3478
MINI_TUNNEL_COORDINATOR_URL=https://coordinator.example:8443
MINI_TUNNEL_RELAY_SERVER=relay.example:42001
MINI_TUNNEL_STATUS_LISTEN=127.0.0.1:42003
```

For a private Coordinator CA, configure `MINI_TUNNEL_COORDINATOR_CA_CERT_FILE` in the environment file and install a readable CA bundle outside the protected state directory. The listener for the peer status endpoint must remain loopback-only. If running more than one instance, assign a distinct `MINI_TUNNEL_STATUS_LISTEN` port to each.

Enroll the service identity once before starting the unit. Transfer the one-use invite token in a protected file; never put it in the environment file or command arguments. Join as the same service account and with the same XDG paths the unit uses:

```sh
sudo install -o mini-tunnel -g mini-tunnel -m 0600 invite.token \
  /var/lib/mini-tunnel/invite.token
sudo -u mini-tunnel env \
  HOME=/var/lib/mini-tunnel \
  XDG_CONFIG_HOME=/var/lib/mini-tunnel/.config \
  XDG_DATA_HOME=/var/lib/mini-tunnel/.local/share \
  MINI_TUNNEL_COORDINATOR_URL=https://coordinator.example:8443 \
  MINI_TUNNEL_COORDINATOR_CA_CERT_FILE=/etc/mini-tunnel/tls/coordinator-ca.pem \
  /usr/local/bin/mini-tunnel network join \
    --network-id 00000000-0000-0000-0000-000000000000 \
    --invite-token-file /var/lib/mini-tunnel/invite.token
sudo rm -f /var/lib/mini-tunnel/invite.token
```

If the Coordinator uses a publicly trusted certificate, omit the `MINI_TUNNEL_COORDINATOR_CA_CERT_FILE` line from the enrollment command. After the one-time join succeeds, delete the token file; the running peer unit strips admin tokens, invite tokens, database URLs, and Relay signing keys from its environment.

Then start and inspect the instance:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now mini-tunnel-peer@office.service
sudo systemctl status mini-tunnel-peer@office.service
sudo journalctl -fu mini-tunnel-peer@office.service
mini-tunnel peer status --url http://127.0.0.1:42003
```

The device private key is stored by the application with user-only permissions. `StateDirectory` persists it across service restarts. The unit is intentionally not installed or enabled by package scripts; administrators opt in after enrolling the device. To stop one network, run `sudo systemctl disable --now mini-tunnel-peer@office.service`. Keep `/var/lib/mini-tunnel` while any instance uses the identity or memberships. Replacing the binary can be rolled back by restoring the previous binary and restarting the unit; membership state is not migrated by a binary update.

The unit's `ProtectSystem=strict`, `ProtectHome`, `NoNewPrivileges`, private temporary directory, capability bounding set, device policy, address-family allowlist, and process/kernel protections constrain the peer. The service cannot create arbitrary devices or access network administration without `CAP_NET_ADMIN`; that capability is required to create TUN and install the explicit peer routes. Do not add `CAP_NET_RAW`, disable `NoNewPrivileges`, or expose the status endpoint publicly.

## Network exposure

Apply host and cloud firewall rules with this exposure model; do not expose service health or metrics endpoints:

| Listener | Transport | Public ingress | Purpose |
| --- | --- | --- | --- |
| Reverse proxy (example: 443) | TCP | Yes | Coordinator HTTPS API; allow the chosen proxy port only. |
| Relay `42001` | TCP | Yes, when TCP relay fallback is offered | Opaque relayed peer stream. |
| UDP Relay `42003` | UDP | Yes, when UDP relay fallback is offered | Ticket-authorized opaque QUIC datagrams. |
| Coordinator `127.0.0.1:8443` | TCP | No | TLS backend reachable only by the local proxy. |
| Relay metrics `127.0.0.1:42002` | TCP | No | Local health and Prometheus scrape. |
| Peer tunnel `--bind` | UDP, and optional TCP | As configured per device | Direct peer path. Open/forward the selected ports on the peer host/router; there is no single server-side peer port because each device chooses its bind address. |

If serving Coordinator HTTPS directly, expose its configured TLS listener instead of the reverse proxy, and bind it to the public interface with a valid certificate. Do not expose the JSON state file or PostgreSQL. Restrict database ingress to Coordinator hosts. Prometheus can scrape loopback endpoints locally; for remote monitoring, use authenticated `remote_write` rather than opening the metrics ports.

Clients initiating connections need outbound HTTPS to the Coordinator, UDP to STUN (if configured), UDP to peer candidates, and TCP to peer candidates or the Relay as used. UDP NAT traversal usually requires no inbound firewall pinhole on the client, but symmetric/firewall-restricted NATs can prevent direct paths; configure relay fallback for those networks. If a peer accepts direct connections behind a router, forward the selected UDP/TCP bind port to that device and advertise the matching public candidate.

## Install

Build a release binary and install it at `/usr/local/bin/mini-tunnel`. Create a dedicated account and configuration directories:

```sh
sudo useradd --system --home-dir /var/lib/mini-tunnel --shell /usr/sbin/nologin mini-tunnel
sudo install -d -o root -g mini-tunnel -m 0750 /etc/mini-tunnel
sudo install -d -o root -g mini-tunnel -m 0750 /etc/mini-tunnel/tls
sudo install -d -o mini-tunnel -g mini-tunnel -m 0700 /var/lib/mini-tunnel
```

Install TLS files readable by the service account and not writable by it. Put environment files in `/etc/mini-tunnel`, owned by `root:mini-tunnel` with mode `0640`. The units load the Relay ticket signing key through systemd credentials from `/etc/mini-tunnel/relay-ticket-key`; its contents must be URL-safe base64 without padding for a random 32-byte value. Create the same credential file on the Coordinator and Relay hosts, with ownership `root:root` and mode `0600`:

```sh
sudo install -o root -g root -m 0600 /dev/null /etc/mini-tunnel/relay-ticket-key
python3 -c 'import base64,secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("="))' | sudo tee /etc/mini-tunnel/relay-ticket-key >/dev/null
```

Transfer the generated value securely to the other host without printing it in a shared terminal or shell history. The services receive a private runtime copy under systemd's credential directory; their environments contain only its path. Do not put key values in environment files, unit files, command-line arguments, source control, or logs. Environment-based key configuration remains supported for non-systemd deployments.

During key rotation, provision `/etc/mini-tunnel/previous-relay-ticket-key` on each Relay host with root ownership and mode `0600`, add `LoadCredential=previous-relay-ticket-key:/etc/mini-tunnel/previous-relay-ticket-key` and `Environment=MINI_TUNNEL_RELAY_PREVIOUS_TICKET_KEY_FILE=%d/previous-relay-ticket-key` to the Relay unit, and restart it with the new current key credential while the Coordinator still uses the old key. Then switch the Coordinator credential to the new key, wait at least the maximum ticket lifetime (currently two minutes) plus deployment margin, remove the previous-key unit directives and file, and restart the Relay. Protect and transfer both files as secrets.

For PostgreSQL mode, add `MINI_TUNNEL_COORDINATOR_DATABASE_URL` to the protected `coordinator.env` file and use `mini-tunnel-coordinator-postgres.service` instead of the JSON-file unit. Non-loopback database hosts must use `sslmode=verify-full` with a trusted CA; the Coordinator rejects weaker modes before connecting. Loopback and Unix-socket URLs remain available for local development. Do not set `MINI_TUNNEL_COORDINATOR_STATE` or pass `--state-file` in this mode. First run `mini-tunnel coordinator migrate-postgres` with a separate schema-owner environment file. Then change `coordinator.env` to the restricted runtime database role that has only schema usage and table DML rights (including `UPDATE` on the transaction-lock row and DML on `mini_tunnel_rate_limit_buckets`). Keep migration credentials out of the running service environment. The shared per-source request limiter fails closed when PostgreSQL is unavailable.

Copy the unit files to `/etc/systemd/system/`, then:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now mini-tunnel-relay.service
```

Enable exactly one Coordinator unit, matching the selected state backend:

```sh
# Single-node JSON snapshot mode
sudo systemctl enable --now mini-tunnel-coordinator.service

# Or shared PostgreSQL mode
sudo systemctl enable --now mini-tunnel-coordinator-postgres.service
```

Check the selected Coordinator unit and relay with `systemctl status` and `journalctl`.

## Monitoring and alerts

`deploy/prometheus/mini-tunnel.yml` is a complete Prometheus configuration for a local scraper. Install it as `/etc/prometheus/prometheus.yml` (or merge its `rule_files` and `scrape_configs` into the existing file), install `deploy/prometheus/mini-tunnel-alerts.yml` at `/etc/prometheus/mini-tunnel-alerts.yml`, and set the Coordinator certificate authority file and DNS SAN to match the host certificate. Keep Prometheus in the host network namespace: Coordinator `/metrics` accepts loopback connections only, and both configured targets use `127.0.0.1`. For a remote monitoring server, forward these metrics through Prometheus `remote_write`; do not expose the Coordinator metrics route publicly.

Before reload, run `promtool check config /etc/prometheus/prometheus.yml`, `promtool check rules /etc/prometheus/mini-tunnel-alerts.yml`, and from the repository root `promtool test rules deploy/prometheus/mini-tunnel-alerts.test.yml`. The rule tests cover sustained slow Coordinator requests, admission pressure, Relay handshake failures, UDP Relay authentication rate limiting, and quiet cases below their thresholds. Verify health and metrics locally with certificate validation:

```sh
curl --fail --cacert /etc/mini-tunnel/tls/coordinator-ca.pem \
  --resolve coordinator.internal:8443:127.0.0.1 \
  https://coordinator.internal:8443/healthz
curl --fail http://127.0.0.1:42002/healthz
curl --fail --cacert /etc/mini-tunnel/tls/coordinator-ca.pem \
  --resolve coordinator.internal:8443:127.0.0.1 \
  https://coordinator.internal:8443/metrics
curl --fail http://127.0.0.1:42002/metrics
```

The alerts cover loss of either scrape endpoint, Coordinator requests taking longer than five seconds, request timeouts, concurrency rejection, more than 100 Coordinator or UDP Relay rate-limited requests in five minutes sustained for two minutes, more than 10 failed Coordinator administrator-token checks in five minutes sustained for two minutes, 10 Coordinator HTTP connection-capacity rejections in five minutes sustained for two minutes, Relay connection-capacity rejection, and more than 20 failed Relay handshakes in five minutes sustained for two minutes. For a scrape alert, check `systemctl status`, the service journal, certificate expiry/trust, and whether the local Prometheus process can reach loopback. For a slow-request or saturation alert, inspect the Coordinator request-duration histogram, database health/latency, and API load before raising limits. For Coordinator rate limiting behind a reverse proxy, confirm the configured trusted proxy CIDRs and that the proxy appends the immediate client address; do not raise limits until normal client traffic is distinguished from a spoofed or malformed forwarded chain. For an administrator-authentication alert, inspect `invite_issue_denied` and `member_revoke_denied` audit records plus reverse-proxy access logs; application records intentionally omit submitted tokens and attempted device IDs. For HTTP connection-capacity rejection, compare connection churn and host resources with the 512 active connection limit before raising it. For Relay capacity rejection, compare active connections with `mini_tunnel_relay_max_connections` and the per-source limit; investigate connection churn before increasing caps. For repeated UDP Relay authentication limits, inspect the unlabeled `mini_tunnel_udp_relay_auth_rate_limited_total` and aggregate drops. The Relay also exports disjoint, unlabeled `mini_tunnel_udp_relay_malformed_datagrams_total`, `mini_tunnel_udp_relay_authentication_rejections_total`, `mini_tunnel_udp_relay_session_rejections_total`, and `mini_tunnel_udp_relay_capacity_rejections_total` counters. When traffic is quiescent, their sum plus the rate-limit counter equals `mini_tunnel_udp_relay_dropped_datagrams_total`; a scrape during packet handling may briefly observe the counters at adjacent update points. Use the breakdown to distinguish malformed traffic, failed ticket/proof authorization, unknown sessions or unregistered sources, resource caps, and rate limiting before adjusting limits. For TCP handshake failures, inspect Relay service logs and firewall/connection activity around the alert window; the counter has no source labels, so use host/network logs to identify the source before changing credentials or limits. The Coordinator's `/healthz` returns `503` while the configured PostgreSQL store is unavailable.

The coordinator template binds HTTPS to loopback for a local reverse proxy and trusts only `127.0.0.1/32` to supply `X-Forwarded-For` for per-client rate limiting. The example [`deploy/nginx/mini-tunnel-coordinator.conf.example`](../nginx/mini-tunnel-coordinator.conf.example) forwards only `/v1/`, appends the actual client address, verifies the backend certificate, and rejects public `/healthz` and `/metrics`. Configure the backend certificate with the `coordinator.internal` SAN and install its CA at the configured path. If the proxy connects from a different address, update `--trusted-proxies` and the systemd regression check to match that exact proxy CIDR; never trust an untrusted client network. The relay serves TCP on port `42001` and UDP on port `42003`; permit each only when offered to clients. Override UDP with `MINI_TUNNEL_UDP_RELAY_LISTEN`. Its health and Prometheus endpoints stay bound to loopback at `127.0.0.1:42002`.

UDP Relay authentication control packets are limited per normalized source IP with a default burst of 20 and sustained rate of 10 packets/second. For high-churn deployments, tune `MINI_TUNNEL_UDP_RELAY_AUTH_BURST` and `MINI_TUNNEL_UDP_RELAY_AUTH_RATE_PER_SECOND` in `relay.env`; the limiter retains at most 4096 source entries and removes entries idle for 60 seconds. Keep rate overrides finite and monitor the aggregate and reason-specific drop counters when changing them.

## Administrative audit events

The Coordinator writes structured `INFO` audit records after successful network creation, invite issuance, member enrollment, and member revocation, and `WARN` denial records for invalid administrator tokens used to issue invitations or revoke members. Records include an `audit_event`, `network_id`, and `outcome`; successful enrollment/revocation also include the affected `device_id`. Denial records omit the submitted token and attempted device ID. All audit records exclude tokens, signatures, public keys, and candidate addresses. On systemd deployments, inspect or forward these records through the journal:

```sh
sudo journalctl -u mini-tunnel-coordinator.service -u mini-tunnel-coordinator-postgres.service \
  -g 'coordinator audit event'
```

Configure journald retention or authenticated log forwarding to match the deployment's incident-response and privacy requirements. These application records are not a tamper-evident ledger and do not include source IP labels; correlate denial events with reverse-proxy access logs when investigating an alert.

## Certificate renewal

The Coordinator checks its configured certificate and key every 30 seconds and reloads a valid matching pair without restarting. Renew the backend certificate and key at the configured paths, preserve the `coordinator.internal` DNS SAN used by Nginx, and ensure the service account can read the files but cannot modify them. Write renewed files to temporary paths, set ownership/mode, then atomically rename them into place so the watcher never sees a half-written pair. A mismatched or invalid pair leaves the current certificate active; inspect the Coordinator journal for reload errors and correct the files before the next poll. For a custom interval, set `MINI_TUNNEL_COORDINATOR_TLS_RELOAD_INTERVAL_SECONDS` in `coordinator.env` and restart the service once to apply it.

For a publicly terminated certificate in Nginx, validate and reload Nginx after renewal (the example path uses Certbot):

```sh
sudo nginx -t
sudo systemctl reload nginx
```

Then verify the public endpoint against the expected hostname and trust chain, and verify the backend locally using its CA and SAN as shown in the Monitoring section. Check `systemctl status` and `journalctl -u mini-tunnel-coordinator.service` (or the PostgreSQL unit) if the proxy reports TLS errors. Schedule renewal hooks to reload Nginx only after `nginx -t` succeeds.

Enable either `mini-tunnel-coordinator.service` for a single-node JSON snapshot or `mini-tunnel-coordinator-postgres.service` for shared PostgreSQL state, not both. For JSON mode, continue protecting `/var/lib/mini-tunnel/coordinator-state.json`. For PostgreSQL mode, back up the database with `pg_dump`/PITR and periodically export a verified JSON recovery snapshot with `mini-tunnel coordinator export-state-from-postgres --output <path>`.

PostgreSQL stores short-lived ICE credentials and relay pairing metadata alongside durable network state. Restrict database access and protect database disks and backups accordingly; ICE passwords are ephemeral credentials, not long-term secrets.

On Unix, the services treat systemd's default `SIGTERM` and `Ctrl+C` as graceful shutdown signals. The peer mesh stops forwarding and removes its managed peer routes and TUN; the Relay waits up to its configured shutdown grace period for paired sessions to finish; the Coordinator stops accepting new requests and completes in-flight requests.

`ProtectSystem=strict`, `NoNewPrivileges`, and the dedicated account limit service access. The Coordinator and Relay units drop all Linux capabilities and hide device nodes; neither needs TUN or network-administration rights. They protect kernel control interfaces, the system clock, and other processes in procfs. Namespace creation and writable-executable memory are disabled. The peer unit has a separate, narrow exception for `CAP_NET_ADMIN`, `/dev/net/tun`, and `AF_NETLINK` because the TUN and explicit host-route lifecycle requires those privileges.

## Upgrade and rollback

Keep the previous binary and a backup of `/var/lib/mini-tunnel/coordinator-state.json` before replacing the executable. Install a new binary atomically, run `systemctl restart` for the changed service, and inspect `systemctl status` and its journal. To roll back, restore the prior binary and, only if the new version migrated state, restore the matching state backup while the coordinator is stopped. The current JSON state is versioned but does not have an automated downgrade migration.
