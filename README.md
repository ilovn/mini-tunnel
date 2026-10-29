# mini-tunnel

A minimal, peer-to-peer virtual network tunnel. The design baseline is in [`docs/architecture.md`](docs/architecture.md).

## Current status

Implemented: a Rust workspace, coordinator health endpoint and atomic state, network creation/invites/IPv4 allocation, stable Ed25519 device identities, signed discovery candidates, authenticated QUIC/UDP peer channels, STUN mapped-candidate discovery, and a multi-peer IPv4 TUN mesh.

Not implemented yet: full ICE connectivity checks, adaptive QoS-driven path switching, and packet relay. Mesh peers make simultaneous authenticated QUIC/UDP connection attempts to open NAT mappings, then elect one data connection by stable device ID. When a member advertises `tcp://` candidates and runs a TCP listener, peers fall back to TLS/TCP after UDP candidates fail. This best-effort hole-punch strategy is not full ICE; restrictive/symmetric NATs and UDP-blocking firewalls may still need a relay. The control API has a bounded 600-request/minute per-source-IP limiter and a 64 KiB body cap, but remains a development prototype without TLS termination or distributed abuse controls. **Do not expose it directly to untrusted networks.** The coordinator binds to loopback by default; use a hardened TLS reverse proxy for remote clients.

## Quick start

Start the coordinator:

```sh
cargo run -p mini-tunnel -- coordinator serve
```

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

The coordinator persists network/member/address/candidate/invite state at the per-user data directory's `coordinator-state.json`. Override it with `--state-file <path>` or `MINI_TUNNEL_COORDINATOR_STATE`. The file is written atomically with Unix mode 0600; startup rejects symlinks, unsafe permissions, corrupt content, and unknown schema versions instead of silently resetting state. Only hashes of admin and invite tokens are stored. Back up this file before moving or upgrading the coordinator. This is a single-process snapshot store; do not share it among multiple coordinator processes or use it as a multi-region database.

Members publish socket candidates and request same-network peers:

```sh
cargo run -p mini-tunnel -- network advertise --network-id '<network-id>' --candidate '203.0.113.10:42000'
cargo run -p mini-tunnel -- network peers --network-id '<network-id>'
```

Candidate updates are signed, limited to eight usable socket addresses, and reject timestamps outside a five-minute window or replayed updates. This only exchanges control-plane information; it does not open a tunnel or prove that a candidate is reachable. Each invite expires after one hour and can enroll one device.

Tunnel commands can optionally discover and publish a server-reflexive UDP candidate using a STUN Binding server. Pass `--stun-server '<stun-ip>:3478'`; the STUN request uses the same bound UDP socket later handed to QUIC. Additional addresses can be repeated as `--candidate '<ip>:<port>'`. The STUN option is off by default and an enabled candidate update replaces this device's previous candidate list. Mesh peers attempt QUIC connections simultaneously over advertised candidates; device ID ordering elects one data connection while the reverse connection is discarded after authentication. This can open mappings on some NATs, but does not implement the complete ICE candidate checklist, keepalive, or nomination procedure. Symmetric NAT/firewall behavior may still prevent direct connectivity. TURN/relay and TCP fallback are not implemented. See [RFC 8489](https://www.rfc-editor.org/rfc/rfc8489.html) and [RFC 8445](https://www.rfc-editor.org/rfc/rfc8445.html) for STUN's scope and ICE connectivity checks.

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

The agent crate exposes an async Layer 3 IPv4 TUN adapter (`mini_tunnel_agent::tun_device::TunDevice`) with a default MTU of 1150 bytes, capped to fit the current QUIC datagram framing. It validates IPv4 header/length/MTU and enforces the local and authenticated peer IP boundary on packets. Creating a TUN assigns its local address and requires OS network-interface privileges; Linux may require the `tun` module and root or `CAP_NET_ADMIN`, macOS/BSD may require elevated permissions, and Windows requires Administrator privileges plus the matching `wintun.dll`. The adapter does not call an explicit route-management API and disables tun-rs automatic route management on macOS/BSD; the OS may still create a connected route from the configured interface address and prefix. Tunnel commands can use this adapter for one peer or a multi-peer mesh.

## Run a two-device IPv4 tunnel

The tunnel commands keep one authenticated peer session open and pump IPv4 packets both ways. The listener must advertise its reachable UDP address first and start before the connector:

```sh
# Peer B: publish the listener's reachable UDP candidate, then wait for peer A
cargo run -p mini-tunnel -- network advertise --network-id '<network-id>' --candidate '203.0.113.20:42000'
cargo run -p mini-tunnel -- peer tunnel listen --network-id '<network-id>' --peer-id '<peer-a-device-id>' --bind 0.0.0.0:42000 --manage-route

# Peer A: discover B from the signed snapshot and connect
cargo run -p mini-tunnel -- peer tunnel connect --network-id '<network-id>' --peer-id '<peer-b-device-id>' --manage-route
```

Both commands use the membership saved by `network join`; optional `--local-ipv4` and `--prefix-len` values are accepted only if they match that saved configuration. Without a saved membership, provide both values explicitly. Both commands require TUN privileges. By default, the program leaves system routes untouched; inspect the OS route table and add a host route manually if needed. On Linux and macOS you can opt in to managing exactly the authenticated peer IPv4 `/32` route with `--manage-route` on either tunnel command. The route is added only after peer authentication and before forwarding starts; an existing-route conflict, unsupported platform, missing route utility, or insufficient privileges aborts startup. A successfully added route is removed when the peer disconnects or you press Ctrl-C. Other platforms are not supported by `--manage-route`. Abrupt termination (for example, SIGKILL or power loss) cannot run cleanup; check the route table and remove a leftover route manually. The option never replaces or flushes routes.

For multiple enrolled devices, run `peer tunnel mesh` on each device with the same mini-tunnel protocol version. Each process fetches the same-network peer snapshot and uses device ID ordering to choose one QUIC dialer per pair. One TUN routes each IPv4 packet to the authenticated peer matching its destination address. Pass `--stun-server` or publish manual candidates first. Example on each device:

```sh
cargo run -p mini-tunnel -- peer tunnel mesh --network-id '<network-id>' --bind 0.0.0.0:42000 --stun-server '<stun-ip>:3478' --tcp-bind 0.0.0.0:443 --candidate 'tcp://<public-ip>:443' --manage-route
```

Configure firewall/NAT forwarding for the UDP and TCP ports you advertise. `--tcp-bind` starts the TLS/TCP fallback listener; publish its externally reachable address as a `tcp://` candidate with `--candidate`. Mesh keeps reachable authenticated peers and reports unavailable ones; at least one peer must connect. Each pair probes UDP from both ends and elects one data connection using device ID ordering. TCP is reliable and encrypted, but currently serves as connect-time fallback only; it does not switch paths after a live UDP session degrades. The peer list is a startup snapshot, so newly joined devices require restarting mesh. Simultaneous UDP probing may establish direct paths through common NATs, but restrictive or symmetric NATs can still require a relay; full ICE checks and relay forwarding are not implemented.

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
