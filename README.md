# mini-tunnel

A minimal, peer-to-peer virtual network tunnel. The design baseline is in [`docs/architecture.md`](docs/architecture.md).

## Current status

Implemented: a Rust workspace, local coordinator health endpoint, in-memory network creation, admin capability tokens, one-time join invites, and IPv4 allocation.

Not implemented yet: persistent storage, device-key authentication, peer discovery, TUN devices, encrypted peer transport, UDP/QUIC direct links, TCP fallback, and packet relay. The control API is a local development prototype and has no production authentication or rate limiting. **Do not expose it to untrusted networks.** The coordinator binds to loopback by default.

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

The current coordinator state is in memory. Restarting it removes networks, tokens, and address assignments. Each invite expires after one hour and can enroll one device. The CLI prints a generated device ID and assigned address, but does not yet configure an OS interface.

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
