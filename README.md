# mini-tunnel

A minimal, peer-to-peer virtual network tunnel. The design baseline is in [`docs/architecture.md`](docs/architecture.md).

## Current status

Implemented: a Rust workspace, local coordinator health endpoint, in-memory network creation, admin capability tokens, one-time join invites, IPv4 allocation, stable Ed25519 device identities, signed enrollment and peer discovery, candidate publication, and authenticated encrypted QUIC/UDP peer datagrams.

Not implemented yet: persistent storage, connecting TUN packets to long-running peer sessions, overlay route installation, NAT traversal, TCP fallback, and packet relay. The control API is a local development prototype and has no production rate limiting. **Do not expose it to untrusted networks.** The coordinator binds to loopback by default.

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

The CLI creates a stable Ed25519 identity at the OS user configuration directory (`device.key`; Unix permissions are restricted to the current user). Inspect the public identity with `cargo run -p mini-tunnel -- identity`. Joining signs the invite proof with this key; the private key is never sent.

Members publish socket candidates and request same-network peers:

```sh
cargo run -p mini-tunnel -- network advertise --network-id '<network-id>' --candidate '203.0.113.10:42000'
cargo run -p mini-tunnel -- network peers --network-id '<network-id>'
```

Candidate updates are signed, limited to eight usable socket addresses, and reject timestamps outside a five-minute window or replayed updates. This only exchanges control-plane information; it does not open a tunnel or prove that a candidate is reachable. The current coordinator state is in memory. Restarting it removes networks, tokens, identities, candidates, and address assignments. Each invite expires after one hour and can enroll one device.

An authenticated QUIC/UDP diagnostic can verify a reachable peer address before TUN support exists. Each side needs the other device's ID and URL-safe base64 public key shown by the identity command. On the receiving side:

```sh
cargo run -p mini-tunnel -- peer listen --bind 0.0.0.0:42000 --network-id '<network-id>' --peer-id '<sender-device-id>' --peer-key '<sender-public-key>'
```

On the sending side:

```sh
cargo run -p mini-tunnel -- peer send --remote '<receiver-ip>:42000' --network-id '<network-id>' --peer-id '<receiver-device-id>' --peer-key '<receiver-public-key>' --message 'hello'
```

This diagnostic requires a directly reachable UDP address and an explicitly opened inbound UDP port. QUIC encrypts the datagram; TLS pins the receiver key and the receiver verifies a fresh Ed25519 proof from the sender. Datagrams are bounded and have an application replay window. It is not NAT traversal, does not use advertised candidates automatically, and does not yet carry IP packets from a TUN interface.

With both devices enrolled and their reachable UDP addresses advertised, the sender can fetch the signed same-network peer snapshot and try the selected peer's candidates automatically:

```sh
cargo run -p mini-tunnel -- peer connect --network-id '<network-id>' --peer-id '<receiver-device-id>' --message 'hello'
```

The command checks the peer key from that signed snapshot, tries at most eight candidates in order (five seconds per attempt), then sends one authenticated datagram. It reports a missing peer, absent/unusable candidates, identity mismatch, and unreachable candidates as separate errors. The coordinator supplies discovery data only; the QUIC datagram travels directly between the devices.

The agent crate now exposes an async Layer 3 IPv4 TUN adapter (`mini_tunnel_agent::tun_device::TunDevice`) with a default MTU of 1150 bytes, capped to fit the current QUIC datagram framing. It validates IPv4 header/length/MTU and enforces the local and authenticated peer IP boundary on packets. Creating a TUN assigns its local address and requires OS network-interface privileges; Linux may require the `tun` module and root or `CAP_NET_ADMIN`, macOS/BSD may require elevated permissions, and Windows requires Administrator privileges plus the matching `wintun.dll`. The adapter deliberately does not install the overlay CIDR route, and disables tun-rs automatic route management on macOS/BSD. This is a library API only: the CLI does not yet create a TUN or pump packets through peer sessions.

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
