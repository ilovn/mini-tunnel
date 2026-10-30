# Linux systemd deployment templates

These templates install the coordinator and opaque TCP relay as separate, unprivileged services. They require systemd 247 or newer for the complete sandbox profile. They do not configure a firewall, TLS proxy, certificate renewal, or secret distribution. Review those choices for your host before enabling the units.

## Install

Build a release binary and install it at `/usr/local/bin/mini-tunnel`. Create a dedicated account and configuration directories:

```sh
sudo useradd --system --home-dir /var/lib/mini-tunnel --shell /usr/sbin/nologin mini-tunnel
sudo install -d -o root -g mini-tunnel -m 0750 /etc/mini-tunnel
sudo install -d -o root -g mini-tunnel -m 0750 /etc/mini-tunnel/tls
sudo install -d -o mini-tunnel -g mini-tunnel -m 0700 /var/lib/mini-tunnel
```

Install TLS files readable by the service account and not writable by it. Put environment files in `/etc/mini-tunnel`, owned by `root:mini-tunnel` with mode `0640`. `coordinator.env` should contain `MINI_TUNNEL_RELAY_TICKET_KEY` with a URL-safe base64 encoded random 32-byte value. `relay.env` must contain the same key. Do not put secrets in unit files, command-line arguments, source control, or logs. During key rotation, set the relay's `MINI_TUNNEL_RELAY_PREVIOUS_TICKET_KEY` as described in the main README.

For PostgreSQL mode, add `MINI_TUNNEL_COORDINATOR_DATABASE_URL` to the protected `coordinator.env` file and use `mini-tunnel-coordinator-postgres.service` instead of the JSON-file unit. The URL should use `sslmode=verify-full`; do not set `MINI_TUNNEL_COORDINATOR_STATE` or pass `--state-file` in this mode. First run `mini-tunnel coordinator migrate-postgres` with a separate schema-owner environment file. Then change `coordinator.env` to the restricted runtime database role that has only schema usage and table DML rights (including `UPDATE` on the transaction-lock row and DML on `mini_tunnel_rate_limit_buckets`). Keep migration credentials out of the running service environment. The shared per-source request limiter fails closed when PostgreSQL is unavailable.

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

Before reload, run `promtool check config /etc/prometheus/prometheus.yml` and `promtool check rules /etc/prometheus/mini-tunnel-alerts.yml`. Verify health and metrics locally with certificate validation:

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

The alerts cover loss of either scrape endpoint, Coordinator request timeouts or concurrency rejection, and Relay connection-capacity rejection. For a scrape alert, check `systemctl status`, the service journal, certificate expiry/trust, and whether the local Prometheus process can reach loopback. For a Coordinator saturation alert, inspect database health/latency and API load before raising limits. For Relay capacity rejection, compare active connections with `mini_tunnel_relay_max_connections` and the per-source limit; investigate connection churn before increasing caps. The Coordinator's `/healthz` returns `503` while the configured PostgreSQL store is unavailable.

The coordinator template binds HTTPS to loopback for a local reverse proxy. Configure the proxy to validate the coordinator certificate and expose only the API routes required by clients; keep `/metrics` private. The relay serves TCP on port `42001`; permit that port in the host/network firewall. Its health and Prometheus endpoints stay bound to loopback at `127.0.0.1:42002`.

Enable either `mini-tunnel-coordinator.service` for a single-node JSON snapshot or `mini-tunnel-coordinator-postgres.service` for shared PostgreSQL state, not both. For JSON mode, continue protecting `/var/lib/mini-tunnel/coordinator-state.json`. For PostgreSQL mode, back up the database with `pg_dump`/PITR and periodically export a verified JSON recovery snapshot with `mini-tunnel coordinator export-state-from-postgres --output <path>`.

PostgreSQL stores short-lived ICE credentials and relay pairing metadata alongside durable network state. Restrict database access and protect database disks and backups accordingly; ICE passwords are ephemeral credentials, not long-term secrets.

On Unix, both services treat systemd's default `SIGTERM` and `Ctrl+C` as graceful shutdown signals. The relay waits up to its configured shutdown grace period for paired sessions to finish; the coordinator stops accepting new requests and completes in-flight requests.

`ProtectSystem=strict`, `NoNewPrivileges`, and the dedicated account limit service access. Both units drop all Linux capabilities, hide device nodes, and protect kernel control interfaces, the system clock, and other processes in procfs. Namespace creation and writable-executable memory are disabled. The relay does not need TUN or network-administration capabilities. These services do not run the peer TUN client; client-side interface and route setup requires a separate, explicit privilege model.

## Upgrade and rollback

Keep the previous binary and a backup of `/var/lib/mini-tunnel/coordinator-state.json` before replacing the executable. Install a new binary atomically, run `systemctl restart` for the changed service, and inspect `systemctl status` and its journal. To roll back, restore the prior binary and, only if the new version migrated state, restore the matching state backup while the coordinator is stopped. The current JSON state is versioned but does not have an automated downgrade migration.
