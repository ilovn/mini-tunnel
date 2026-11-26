# Coordinated direct recovery across Guangzhou and domestic NAT

Date: 2026-11-27 (China Standard Time)

## Build provenance

- Source: `ad66f478021aed9dab094c42813b66a3d6bf266a` (`test(agent): use reliable channel for veth readiness`).
- CI: [run 45902770807](https://github.com/ilovn/mini-tunnel/actions/runs/45902770807), all jobs successful, including privileged Linux veth/TUN, Windows Wintun, macOS utun, PostgreSQL, Linux x86_64, and ARM64.
- Release staging: [run 45903709913](https://github.com/ilovn/mini-tunnel/actions/runs/45903709913). The publish job was skipped. No field machine compiled source.
- Linux x86_64 archive SHA-256: `3cdd300f8c93e716ddf9aa88e87791d2c8bdf5abf0bb7e4c49121b6d07e71440`.
- Extracted executable SHA-256: `324f653eff2f2875e7b89daaf243d74a6be8fcbf096ea4ef87cd00c168fea266`.
- `deploy/verify-peer-attestation.sh` verified the artifact against repository `ilovn/mini-tunnel`, workflow `release.yml`, `refs/heads/main`, and the source SHA above.

## Test topology and procedure

Two Linux x86_64 peers joined a fresh, isolated two-member Coordinator network: the Guangzhou public VPS and the domestic NAT Ubuntu host. The test used subnet `10.244.211.0/24`, distinct temporary Coordinator/Relay/peer ports, fresh TLS and Relay ticket keys, and transient systemd services. The existing production Coordinator/Relay, host routes, and interfaces were not used for test traffic.

Both peers enabled ICE and a prepared TCP Relay standby. After direct UDP was stable, a temporary nftables output rule on the NAT host dropped only UDP addressed to the Guangzhou test IP on the test UDP Relay and peer ports. A 180-second rollback timer was armed before adding the rule. The rule was removed manually after fallback traffic was verified; its timer was then stopped.

## Results

- Baseline: both peers nominated authenticated ICE/QUIC paths and reported online `QUIC/UDP`. Bidirectional overlay ping passed 10/10 each way with 0% loss; RTT was about 12 ms. Relay metrics showed two active connections, one paired session, and no handshake failures.
- Fallback: both peers stayed online and switched to `Relay/TLS` (`quality_threshold` on Guangzhou, `transport_failure` on NAT). The exact drop counter advanced. While the rule was active, overlay ping passed 15/15 in both directions with 0% loss. Relay metrics showed one paired session and zero handshake failures.
- Recovery: after the rule was removed, both peer processes stayed online over Relay while ICE recovery retried. They later nominated a direct pair, completed authenticated UDP probation, and each logged promotion to `QUIC/UDP` with reason `healthy_direct_probe`. Both status endpoints reported online, 0% loss, and zero drops/rejections.
- Post-recovery: overlay ping passed 20/20 and then 60/60 in each direction, all with 0% loss. Mean RTT in the 60-packet samples was about 12 ms. The prepared Relay standby remained available; the Relay recorded zero handshake failures.

Direct recovery took several minutes and included multiple failed ICE attempts and UDP health probation. Logs show the internal recovery cooldown state grew to 300 seconds, while subsequent probes were aligned to 30-second UTC rendezvous intervals; this run does not isolate the cooldown as the sole cause of the observed delay. The reliable Relay path carried traffic throughout. Follow-up work should inspect retry timing and candidate freshness to reduce recovery time. This test proves eventual fallback and coordinated direct recovery for this one topology, not fast recovery across other NATs.

## Cleanup

Both temporary memberships were revoked; Coordinator state showed one test network with zero members and zero invites before teardown. The test services, timers, nftables table, temporary certificates, tokens, binaries, listeners, routes, and TUNs were removed. No test-specific systemd units or listeners remained. Guangzhou retained its original default route via `10.0.20.1`, `tun0`/`tun1`, and production Relay PID `17770` on TCP `42001`, UDP `42003`, and metrics `42002`. The NAT host retained its default route via `172.16.16.172`; no nftables table or tunnel interface remained. Private raw logs and scripts are retained under the local ignored Harness task `complex-006db3894c` and are not committed.

## Scope limits

This verifies one domestic NAT route with direct UDP initially available and TCP Relay reachable. It does not establish a broad NAT/firewall/QoS matrix, direct connectivity when UDP is blocked upstream, or recovery timing across different NAT mappings. Windows CI and binary smoke checks remain separate from this Linux field result.
