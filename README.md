# mini-tunnel

A minimal, peer-to-peer virtual network tunnel. The design baseline is in [`docs/architecture.md`](docs/architecture.md).

## Current status

Implemented: coordinator health/state and enrollment, stable Ed25519 identities, signed discovery candidates, authenticated QUIC/UDP and TLS/TCP peer channels, STUN mapped candidates, IPv4/IPv6 L3 TUN mesh with bounded packet fragmentation, and an optional ticket-authorized opaque TCP relay with end-to-end pinned TLS. Each network derives a stable ULA `/64` from its network UUID and each member's unique IPv4 lease; no extra coordinator wire field is required. The default TUN MTU is 1280 bytes; QUIC datagrams remain bounded by path size and larger packets are split into authenticated frames then reassembled under per-peer count, byte, and expiry limits.

Still in progress: full ICE interoperability, privileged cross-platform TUN testing, privileged Windows TUN runtime validation, real-network validation of path-MTU variation and fragment loss, and production operational hardening. Coordinator rate limits normalize IPv4-mapped IPv6 source addresses so dual-stack clients share one request bucket. IPv6 overlay packet validation/routing and Linux/macOS/Windows `/128` route management are implemented; real OS TUN integration has not yet been exercised in this environment. Single-peer tunnel Connect/Listen and mesh have an opt-in `--ice` path using an RFC 8445 agent over the same UDP socket as QUIC, signed ephemeral credentials refreshed every 60 seconds, and fallback to the existing candidate path when checks fail. Mesh routes checks to independent peer sessions by both ufrags. After nomination, ICE consent checks remain active for the channel lifetime; consent loss enters the normal path recovery loop and releases the session registration. ICE remains experimental and has loopback multi-peer coverage, not a public NAT matrix. Peer sessions exchange encrypted RTT probes every 10 seconds and detect 30 seconds of receive silence. After three consecutive poor quality windows (initially RTT above 350 ms or probe loss above 20%), mesh and single-peer sessions reconnect over direct TLS/TCP then relay while filtering UDP candidates. While on a reliable path, the elected dialer probes for direct UDP every 60 seconds; both peers authenticate and validate the candidate before promotion, without first dropping the existing path. Single-peer tunnel commands reconnect with capped full-jitter backoff; mesh reconnects each lost peer independently while other peers continue forwarding. An optional coordinator-authorized relay handles restrictive NATs; the relay sees only ticket metadata and TLS ciphertext. The control API has built-in HTTPS, a bounded 600-request/minute per-source-IP limiter, and a 64 KiB body cap, but remains a development prototype without distributed abuse controls. Remote plaintext binds are rejected; use a trusted certificate or keep the service behind a TLS-terminating proxy.

## Quick start

Start the coordinator:

```sh
cargo run -p mini-tunnel -- coordinator serve
```

The coordinator serves HTTP only on loopback. To bind a remote interface, configure a trusted PEM certificate chain and private key; non-loopback plaintext listeners are rejected:

```sh
MINI_TUNNEL_COORDINATOR_TLS_CERT='/etc/letsencrypt/live/tunnel.example/fullchain.pem' \
MINI_TUNNEL_COORDINATOR_TLS_KEY='/etc/letsencrypt/live/tunnel.example/privkey.pem' \
cargo run -p mini-tunnel -- coordinator serve --listen '0.0.0.0:8443'
```

The Coordinator checks the configured certificate and private key every 30 seconds and reloads them without restarting when either file changes. Set `MINI_TUNNEL_COORDINATOR_TLS_RELOAD_INTERVAL_SECONDS` or pass `--tls-reload-interval-seconds` to change the interval (minimum 1 second). If a renewal temporarily leaves the files mismatched or invalid, the running server keeps its current certificate and retries on the next check.

On Unix, the private-key file must not be world-accessible; use mode `0600` or a group-restricted mode such as `0640` when the service account belongs to the trusted key-reading group.

On clients, set `MINI_TUNNEL_COORDINATOR_URL='https://tunnel.example:8443'`. Clients validate the certificate chain and hostname; the CLI has no insecure TLS bypass. A reverse proxy that terminates TLS is also supported while the coordinator remains bound to loopback.

When the coordinator is behind a reverse proxy, set `--trusted-proxy` to the proxy's source CIDR (repeat the option for multiple proxies), or provide comma-separated CIDRs through `MINI_TUNNEL_COORDINATOR_TRUSTED_PROXIES`. Only requests whose direct TCP peer matches a configured CIDR use `X-Forwarded-For` for per-client rate limiting. The proxy must append the immediate downstream address; malformed chains are ignored. Keep `/metrics` off public proxy routes.

Coordinator exposes basic Prometheus metrics at `/metrics` for loopback scrapes only. The endpoint reports configured networks, enrolled members, rate-limited requests, API concurrency rejections, and API request timeouts; when using a reverse proxy, keep `/metrics` off its public routes. Control API work is capped at 256 in-flight requests globally; excess requests receive HTTP 503 with `Retry-After: 1`. Requests that take longer than 30 seconds are cancelled and receive HTTP 408. Health and metrics endpoints remain available while the API is at capacity.

CLI commands emit structured logs to stderr. Peer path degradation, reconnect attempts, relay/TCP fallback, and healthy UDP promotion include the peer overlay address, path, and reason. Set `RUST_LOG` to adjust verbosity, for example `RUST_LOG=mini_tunnel_agent=debug`.

Create a network and save the admin token in a secret manager. The token is displayed only once:

```sh
cargo run -p mini-tunnel -- network create --name office --cidr 10.77.0.0/16
```

Issue an invite from the administrator's shell. The admin token is read from the environment, not a command-line argument:

```sh
export MINI_TUNNEL_ADMIN_TOKEN='<admin-token>'
cargo run -p mini-tunnel -- network invite --network-id '<network-id>'
```

Join from another device with the one-time invite token:

```sh
export MINI_TUNNEL_INVITE_TOKEN='<invite-token>'
cargo run -p mini-tunnel -- network join --network-id '<network-id>'
```

The CLI creates a stable Ed25519 identity at the OS user configuration directory (`device.key`; Unix permissions are restricted to the current user). Inspect the public identity with `cargo run -p mini-tunnel -- identity`. Joining signs the invite proof with this key; the private key is never sent. After a successful join, the CLI atomically saves the network ID, device ID, assigned IPv4 address, and CIDR under the user's configuration directory (`networks/<network-id>.json`, mode 0600 on Unix). Invite tokens, admin tokens, and private keys are not included. Existing members can run `network join` again with a valid invite to create/update the local copy; or pass both local IPv4 and prefix explicitly to tunnel commands until a membership file exists.

The coordinator persists network/member/address/candidate/invite state at the per-user data directory's `coordinator-state.json`. Override it with `--state-file <path>` or `MINI_TUNNEL_COORDINATOR_STATE`. Run `mini-tunnel coordinator backup-state --state-file <path> --output <backup-path>` while the coordinator is stopped to validate and atomically back up the snapshot; it locks both paths, writes mode 0600, and reports aggregate counts only. Restore with `mini-tunnel coordinator restore-state --state-file <path> --backup <backup-path>` while the coordinator is stopped; it validates the backup and atomically replaces the state snapshot under both locks. `mini-tunnel coordinator verify-state --state-file <path>` validates a snapshot without starting the service. A network supports at most 4096 members, with a 16384-member coordinator-wide cap to bound mesh and snapshot state. State snapshots are limited to 64 MiB. The file is written atomically with Unix mode 0600; startup rejects symlinks, unsafe permissions, corrupt content, oversized snapshots, and unknown schema versions instead of silently resetting state. An OS-level exclusive lock prevents two local Coordinator processes from opening the same state path. Only hashes of admin and invite tokens are stored. Back up this file before moving or upgrading the coordinator. This is a single-process snapshot store, not a multi-region database.

Members publish socket candidates and request same-network peers:

```sh
cargo run -p mini-tunnel -- network advertise --network-id '<network-id>' --candidate '203.0.113.10:42000'
cargo run -p mini-tunnel -- network peers --network-id '<network-id>'
MINI_TUNNEL_ADMIN_TOKEN='<admin-token>' cargo run -p mini-tunnel -- network revoke --network-id '<network-id>' --device-id '<device-id>'
```

Candidate updates are signed, limited to eight usable socket addresses, and reject timestamps outside a five-minute window or replayed updates. This only exchanges control-plane information; it does not open a tunnel or prove that a candidate is reachable. Each invite expires after one hour and can enroll one device. Network admins can revoke a member with `network revoke`; the assigned address is released for later enrollment.

Tunnel commands can optionally discover and publish a server-reflexive UDP candidate using STUN. Pass `--stun-server '<stun-ip>:3478'`; the STUN request uses the same UDP socket later handed to QUIC. With a wildcard IPv4 or IPv6 bind, the CLI gathers usable same-family addresses from active local interfaces and advertises them on the bound UDP port. IPv6 link-local addresses are omitted because candidate signaling does not yet carry interface scope IDs. ICE candidate updates encode mapped candidates as `srflx://<mapped-address>|<related-local-address>`; old bare UDP socket candidates and `tcp://` candidates remain accepted. Candidate publication is capped at eight: explicit candidates and the STUN mapping take precedence, followed by local host candidates. Add `--ice` to single-peer `connect`, `listen`, or `mesh` to run authenticated RFC 8445 connectivity checks and nominate candidate pairs on that shared socket; both peers must enable ICE and have published current credentials. Checks time out after five seconds and then use the existing candidate dialer, including TCP fallback where configured. Mesh peers route sessions using both ufrags and retain per-peer TCP/relay recovery. Device ID ordering elects one data connection. Successful QUIC/TLS handshakes authenticate the peer before path selection. The `--ice` path is experimental and does not yet have public NAT matrix coverage. See [RFC 8489](https://www.rfc-editor.org/rfc/rfc8489.html) and [RFC 8445](https://www.rfc-editor.org/rfc/rfc8445.html).

The low-level authenticated QUIC/UDP diagnostic can verify a reachable peer address without creating a TUN. Each side needs the other device's ID and URL-safe base64 public key shown by the identity command. On the receiving side:

```sh
cargo run -p mini-tunnel -- peer listen --bind 0.0.0.0:42000 --network-id '<network-id>' --peer-id '<sender-device-id>' --peer-key '<sender-public-key>'
```

On the sending side:

```sh
cargo run -p mini-tunnel -- peer send --remote '<receiver-ip>:42000' --network-id '<network-id>' --peer-id '<receiver-device-id>' --peer-key '<receiver-public-key>' --message 'hello'
```

This diagnostic requires a directly reachable UDP address and an explicitly opened inbound UDP port. QUIC encrypts the datagram; TLS pins the receiver key and the receiver verifies a fresh Ed25519 proof from the sender. Datagrams are bounded and have an application replay window. It is not NAT traversal and does not use advertised candidates automatically; use `peer tunnel` below for a sustained TUN data path.

With both devices enrolled and their reachable UDP addresses advertised, the sender can fetch the signed same-network peer snapshot and try the selected peer's candidates automatically:

```sh
cargo run -p mini-tunnel -- peer connect --network-id '<network-id>' --peer-id '<receiver-device-id>' --message 'hello'
```

The command checks the peer key from that signed snapshot, tries at most eight candidates in order (two seconds per UDP candidate, five seconds per TCP candidate, 30 seconds total), then sends one authenticated datagram. It reports a missing peer, absent/unusable candidates, identity mismatch, and unreachable candidates as separate errors. The coordinator supplies discovery data only; the QUIC datagram travels directly between the devices.

The agent crate exposes an async Layer 3 IPv4/IPv6 TUN adapter (`mini_tunnel_agent::tun_device::TunDevice`) with a default MTU of 1280 bytes and a configured maximum of 9000 bytes. It validates packet headers/length/MTU and enforces the local and authenticated peer IP boundary. Before every send, the agent reads Quinn's current maximum datagram size, which may change with the path MTU estimate; larger packets are split into bounded chunks. Loss of a chunk drops that packet after the five-second reassembly expiry. This has loopback coverage, but changing real path MTUs still needs network testing. Creating a TUN assigns its local address and requires OS network-interface privileges; Linux may require the `tun` module and root or `CAP_NET_ADMIN`, macOS/BSD may require elevated permissions, and Windows requires Administrator privileges plus the matching `wintun.dll`. The adapter does not call an explicit route-management API and disables tun-rs automatic route management on macOS/BSD; the OS may still create a connected route from the configured interface address and prefix. Tunnel commands can use this adapter for one peer or a multi-peer mesh.

## Run a two-device IPv4 tunnel

The tunnel commands keep one authenticated peer session open and pump IP packets both ways. The listener must advertise its reachable UDP address first and start before the connector:

```sh
# Peer B: publish the listener's reachable UDP candidate, then wait for peer A
cargo run -p mini-tunnel -- network advertise --network-id '<network-id>' --candidate '203.0.113.20:42000'
cargo run -p mini-tunnel -- peer tunnel listen --network-id '<network-id>' --peer-id '<peer-a-device-id>' --bind 0.0.0.0:42000 --manage-route

# Peer A: discover B from the signed snapshot and connect
cargo run -p mini-tunnel -- peer tunnel connect --network-id '<network-id>' --peer-id '<peer-b-device-id>' --manage-route
```

Both commands use the membership saved by `network join`; optional `--local-ipv4` and `--prefix-len` values are accepted only if they match that saved configuration. Without a saved membership, provide both values explicitly. Both commands require TUN privileges. By default, the program leaves system routes untouched; inspect the OS route table and add a host route manually if needed. On Linux, macOS, and Windows you can opt in to managing exactly the authenticated peer IPv4 `/32` and IPv6 `/128` routes with `--manage-route` on tunnel commands. Windows uses `netsh interface ipv4/ipv6` active-store routes scoped to the TUN interface alias; it requires an elevated Administrator process. The route is added only after peer authentication and before forwarding starts; an existing-route conflict, unsupported platform, missing route utility, or insufficient privileges aborts startup. A successfully added route is removed when the peer disconnects or you press Ctrl-C. Other platforms are not supported by `--manage-route`. Abrupt termination (for example, SIGKILL or power loss) cannot run cleanup; check the route table and remove a leftover route manually. The option never replaces or flushes routes.

For multiple enrolled devices, run `peer tunnel mesh` on each device with the same mini-tunnel protocol version. Each process fetches the same-network peer snapshot and uses device ID ordering to choose one QUIC dialer per pair. One TUN routes each IPv4 or IPv6 packet to the authenticated peer matching its destination address. Pass `--stun-server` or publish manual candidates first. Example on each device:

```sh
cargo run -p mini-tunnel -- peer tunnel mesh --network-id '<network-id>' --bind 0.0.0.0:42000 --stun-server '<stun-ip>:3478' --tcp-bind 0.0.0.0:443 --candidate 'tcp://<public-ip>:443' --manage-route
```

For direct TCP fallback, configure forwarding for the advertised TCP port. `--tcp-bind` starts the TLS/TCP listener; publish its reachable address as a `tcp://` candidate. For relay fallback, configure the same random 32-byte key on coordinator and relay as URL-safe base64 without padding, then start the relay:

```sh
export MINI_TUNNEL_RELAY_TICKET_KEY='<base64url-32-byte-secret>'
cargo run -p mini-tunnel -- coordinator serve
cargo run -p mini-tunnel -- relay serve --listen 0.0.0.0:42001
```

For a single peer, configure `--relay-server '<relay-host>:42001'` on both `peer tunnel connect` and `peer tunnel listen` (or set `MINI_TUNNEL_RELAY_SERVER`). Connect tries ICE/UDP and advertised UDP/TCP candidates first, then requests a short-lived signed-member ticket if direct connection fails. Listen keeps accepting direct UDP/TCP for 35 seconds before requesting its matching relay ticket. The relay challenge proves possession of the device key; tickets are one use, and the devices negotiate their own certificate-pinned TLS session through the opaque byte broker. For mesh mode, set the same option on each mesh device; it requests a relay ticket only after direct candidates fail. Use HTTPS for a remotely hosted coordinator. Mesh refreshes its same-network peer snapshot every 30 seconds; single-peer tunnels also recheck member authorization every 30 seconds. New mesh members join without restarting, and removed peers are disconnected on the next successful refresh. If the local mesh device is revoked or its network is deleted, an authoritative `invalid_token`/`not_found` response immediately closes all mesh peers; transient coordinator errors keep established sessions alive. Snapshot timeouts and other transient failures leave existing peer sessions running. UDP quality degradation, reliable fallback, and cooled-down recovery to a healthy UDP path are implemented per peer in both mesh and single-peer tunnel modes.

Relay ticket keys support a short overlap during rotation. Generate a new random 32-byte key. First deploy relays with the new key in `MINI_TUNNEL_RELAY_TICKET_KEY` and the old key in `MINI_TUNNEL_RELAY_PREVIOUS_TICKET_KEY`, while the coordinator continues signing with the old key. Then switch the coordinator to the new key and wait at least the maximum ticket lifetime (currently two minutes) plus deployment margin. Finally restart relays with the new key and unset the previous-key variable. Both variables use URL-safe base64 without padding. Keep their values in a secret manager; do not put key values in command-line arguments or logs.

Each paired relay session has a default aggregate traffic budget of 1 GiB shared between both directions. Set `MINI_TUNNEL_RELAY_MAX_SESSION_BYTES` to change the limit; once exhausted, the relay closes the session.

The relay accepts at most 256 concurrent connections globally and 32 from one source IP by default. Configure `MINI_TUNNEL_RELAY_MAX_CONNECTIONS` and `MINI_TUNNEL_RELAY_MAX_CONNECTIONS_PER_SOURCE_IP` (or the matching `--max-connections` and `--max-connections-per-source-ip` options); the per-source cap is clamped to the global cap. Connections held during authentication and established sessions both consume these limits. Source addresses are normalized so IPv4-mapped IPv6 cannot bypass the per-source cap.

Relay health and Prometheus metrics are available at `/healthz` and `/metrics` on the loopback listener `127.0.0.1:42002` by default. Set `MINI_TUNNEL_RELAY_METRICS_LISTEN` or `--metrics-listen` to choose another loopback port. The listener rejects non-loopback addresses. Metrics include active connections/sessions, capacity rejections, handshake failures, and aggregate forwarded bytes.

Linux systemd service templates for the coordinator and relay, including secret file permissions and upgrade notes, are in [`deploy/systemd`](deploy/systemd/README.md). They do not configure the host firewall, reverse proxy, or certificate renewal.

On Ctrl-C, the relay stops accepting new connections and lets paired sessions drain for up to 15 seconds by default. Set `MINI_TUNNEL_RELAY_SHUTDOWN_GRACE_SECONDS` to change that window; remaining sessions are then closed.

## Development

Requirements: stable Rust and Cargo (see `rust-toolchain.toml`).

```sh
cargo run -p mini-tunnel -- --help
cargo run -p mini-tunnel -- coordinator health
cargo fmt --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```
