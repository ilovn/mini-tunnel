# Linux systemd deployment templates

These templates install the coordinator and opaque TCP relay as separate, unprivileged services. They do not configure a firewall, TLS proxy, certificate renewal, or secret distribution. Review those choices for your host before enabling the units.

## Install

Build a release binary and install it at `/usr/local/bin/mini-tunnel`. Create a dedicated account and configuration directories:

```sh
sudo useradd --system --home-dir /var/lib/mini-tunnel --shell /usr/sbin/nologin mini-tunnel
sudo install -d -o root -g mini-tunnel -m 0750 /etc/mini-tunnel
sudo install -d -o root -g mini-tunnel -m 0750 /etc/mini-tunnel/tls
sudo install -d -o mini-tunnel -g mini-tunnel -m 0700 /var/lib/mini-tunnel
```

Install TLS files readable by the service account and not writable by it. Put environment files in `/etc/mini-tunnel`, owned by `root:mini-tunnel` with mode `0640`. `coordinator.env` should contain `MINI_TUNNEL_RELAY_TICKET_KEY` with a URL-safe base64 encoded random 32-byte value. `relay.env` must contain the same key. Do not put secrets in unit files, command-line arguments, source control, or logs. During key rotation, set the relay's `MINI_TUNNEL_RELAY_PREVIOUS_TICKET_KEY` as described in the main README.

Copy the unit files to `/etc/systemd/system/`, then:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now mini-tunnel-coordinator.service
sudo systemctl enable --now mini-tunnel-relay.service
systemctl status mini-tunnel-coordinator mini-tunnel-relay
journalctl -u mini-tunnel-coordinator -u mini-tunnel-relay
```

The coordinator template binds HTTPS to loopback for a local reverse proxy. Configure the proxy to validate the coordinator certificate and expose only the API routes required by clients; keep `/metrics` private. The relay serves TCP on port `42001`; permit that port in the host/network firewall. Its health and Prometheus endpoints stay bound to loopback at `127.0.0.1:42002`.

On Unix, both services treat systemd's default `SIGTERM` and `Ctrl+C` as graceful shutdown signals. The relay waits up to its configured shutdown grace period for paired sessions to finish; the coordinator stops accepting new requests and completes in-flight requests.

`ProtectSystem=strict`, `NoNewPrivileges`, and the dedicated account limit service access. The relay does not need TUN or network-administration capabilities. These services do not run the peer TUN client; client-side interface and route setup requires a separate, explicit privilege model.

## Upgrade and rollback

Keep the previous binary and a backup of `/var/lib/mini-tunnel/coordinator-state.json` before replacing the executable. Install a new binary atomically, run `systemctl restart` for the changed service, and inspect `systemctl status` and its journal. To roll back, restore the prior binary and, only if the new version migrated state, restore the matching state backup while the coordinator is stopped. The current JSON state is versioned but does not have an automated downgrade migration.
