# TCP Relay handshake failure classification smoke (2026-11-27)

## Artifact

- Source: `44c550c55fdf8a49d910bfd8d80c75ae79cc6763` (`main`), CI run [46058689561](https://github.com/ilovn/mini-tunnel/actions/runs/46058689561), which completed successfully across Linux, macOS, Windows, PostgreSQL, and Linux x86_64/ARM64 artifact jobs.
- Linux x86_64 archive SHA-256: `2ef5576916ae57d44db2d6ebe1442dc9c5c95b51a6767fa0e1ba3f91b5f9d153`.
- The GitHub artifact attestation was verified against this repository, the CI workflow, `refs/heads/main`, and the exact source digest. Archive checksum also passed.
- Extracted binary SHA-256: `f46e08e569a38b7ccef35362c100f1a3fdd91ac939bd50aca2f1e264f049b753`.

## Runtime check

- Ran the prebuilt binary on the Guangzhou Ubuntu host as a separate transient systemd service with a five-minute maximum runtime, 256 MiB memory cap, strict system filesystem protection, and no-new-privileges.
- All three sockets were bound to loopback only: TCP Relay `127.0.0.1:44543`, UDP Relay `127.0.0.1:44544`, and HTTP health/metrics `127.0.0.1:44542`. No public listener or route was added.
- `/healthz` returned `ok`. Three local clients sent an eight-byte malformed Relay preface. The metrics endpoint reported aggregate handshake failures `3`, malformed-protocol failures `3`, and `0` for ticket rejection, identity rejection, pairing rejection, authentication timeout, client disconnect, I/O failure, and internal failure.
- This exercises the release binary's service startup, loopback metrics endpoint, and protocol-failure counter path. The unit and CLI tests separately cover classification mappings and the remaining counters; this smoke does not claim a valid authenticated Relay pairing.

## Cleanup and limits

- Stopped the transient service and verified it inactive; removed its temporary binary and ticket-key file; verified TCP/UDP test ports had no listeners.
- The independent long-running domestic NAT soak's peer, monitor, Coordinator, and Relay services remained active throughout. No production service, route, firewall rule, or public port was changed.
- This is a focused metrics runtime check, not a public-listener abuse test or NAT/QoS validation.
