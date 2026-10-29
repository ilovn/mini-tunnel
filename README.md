# mini-tunnel

A minimal, peer-to-peer virtual network tunnel. The design baseline is in [`docs/architecture.md`](docs/architecture.md).

## Current status

Implemented: a Rust workspace, local coordinator health endpoint, in-memory network creation, admin capability tokens, one-time join invites, IPv4 allocation, stable Ed25519 device identities, signed enrollment and peer discovery, candidate publication, and authenticated encrypted QUIC/UDP peer datagrams.

Not implemented yet: persistent coordinator storage, NAT traversal, TCP fallback, and packet relay. The current tunnel command supports one directly reachable peer session at a time. The control API is a local development prototype and has no production rate limiting. **Do not expose it to untrusted networks.** The coordinator binds to loopback by default.

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

Members publish socket candidates and request same-network peers:

```sh
cargo run -p mini-tunnel -- network advertise --network-id '<network-id>' --candidate '203.0.113.10:42000'
cargo run -p mini-tunnel -- network peers --network-id '<network-id>'
```

Candidate updates are signed, limited to eight usable socket addresses, and reject timestamps outside a five-minute window or replayed updates. This only exchanges control-plane information; it does not open a tunnel or prove that a candidate is reachable. The current coordinator state is in memory. Restarting it removes networks, tokens, identities, candidates, and address assignments. Each invite expires after one hour and can enroll one device.

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

The command checks the peer key from that signed snapshot, tries at most eight candidates in order (five seconds per attempt), then sends one authenticated datagram. It reports a missing peer, absent/unusable candidates, identity mismatch, and unreachable candidates as separate errors. The coordinator supplies discovery data only; the QUIC datagram travels directly between the devices.

The agent crate exposes an async Layer 3 IPv4 TUN adapter (`mini_tunnel_agent::tun_device::TunDevice`) with a default MTU of 1150 bytes, capped to fit the current QUIC datagram framing. It validates IPv4 header/length/MTU and enforces the local and authenticated peer IP boundary on packets. Creating a TUN assigns its local address and requires OS network-interface privileges; Linux may require the `tun` module and root or `CAP_NET_ADMIN`, macOS/BSD may require elevated permissions, and Windows requires Administrator privileges plus the matching `wintun.dll`. The adapter does not call an explicit route-management API and disables tun-rs automatic route management on macOS/BSD; the OS may still create a connected route from the configured interface address and prefix. The tunnel CLI below uses this adapter and pumps packets over one authenticated peer session.

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
