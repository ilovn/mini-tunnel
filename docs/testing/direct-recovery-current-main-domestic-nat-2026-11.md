# Direct recovery after controlled UDP impairment on current main

Date: 2026-11-27 (China Standard Time)
Source: `2c726add6f3b8ac6cf32effd39b71a76d8cff6a5`
Release staging: [run 45987845710](https://github.com/ilovn/mini-tunnel/actions/runs/45987845710)

## Artifact and setup

The Linux x86_64 archive checksum sidecar and GitHub Sigstore provenance passed verification for `ilovn/mini-tunnel`, `.github/workflows/release.yml`, `refs/heads/main`, and the exact source SHA above. Both Linux peers used that same prebuilt artifact. The isolated network used Guangzhou `10.244.156.1`, domestic NAT `10.244.156.2`, and temporary Coordinator/Relay services.

| Artifact | SHA-256 |
| --- | --- |
| Linux x86_64 archive | `d849a95205a14fea35873fe5baecb04e63992775972d1de58ca1cc3fee0d3cfb` |
| Extracted Linux executable | `6e0bbbd485161b2ba62d6a35ecbeaf2d347e0330a01b0c72256c61f8b8b3e0aa` |

## Results

- Baseline authenticated direct `QUIC/UDP` was online at both peers. Guangzhou→NAT and NAT→Guangzhou each passed 20/20 pings with 0% loss and approximately 9–10 ms average RTT.
- A 600-second automatic rollback was armed before adding one NAT OUTPUT rule limited to UDP destination `193.112.165.176:44445`. After impairment, both peers remained online and switched to `Relay/TLS`. Relay metrics showed two connections and one session. Both ping directions passed 20/20 with 0% loss; observed RTT averaged approximately 14–17 ms.
- Both peer logs showed the shared 15-second direct recovery rendezvous. With the rule active, direct checks failed while the reliable path continued carrying traffic. The exact nftables table was then deleted and verified absent before disarming the rollback timer.
- Direct recovery was attempted after rule removal, but repeated UDP candidates failed the probation health threshold. Logs recorded 377–455 ms RTT samples, connection loss, and packet loss above the configured limit. Both peers correctly stayed on `Relay/TLS` and remained online; the current-main direct recovery acceptance was **not met in this run**.

## Cleanup

Both temporary members were submitted for revocation by the test Coordinator cleanup. Temporary peer, Coordinator, and Relay services, timers, routes, test state, and binaries were removed. The dedicated nftables table was absent. Guangzhou default route remained via `10.0.20.1`; production Relay PID `17770` remained on TCP `42001`, metrics `42002`, and UDP `42003`. The NAT host default route remained via `172.16.16.172`. Raw logs and host diagnostics remain private under the ignored Harness evidence directory.

The result confirms safe fallback and continuity under the injected UDP loss. It does not confirm that direct UDP recovers on this current path after impairment; the candidate path remained too lossy/high-latency for probation, so the implementation deliberately retained Relay.

## Retest on current main `b930a7c` (shared rendezvous and recovery)

Date: 2026-11-27 (China Standard Time). Release staging workflow [run 46019245852](https://github.com/ilovn/mini-tunnel/actions/runs/46019245852) completed its Linux x86_64 build and attestation; desktop staging builds also succeeded, and publication was skipped. The Linux archive checksum sidecar and GitHub Sigstore provenance matched `ilovn/mini-tunnel`, `.github/workflows/release.yml`, `refs/heads/main`, and exact source `b930a7cad37bdeac6f9bc2dc7c7ba4e2fbe36caa`. No endpoint built the binary.

| Artifact | SHA-256 |
| --- | --- |
| Linux x86_64 Ubuntu 20.04 archive | `88f06f6f78e3324001c05a7ac41109c8548ee0554f826336e461d645cd08da2c` |
| Extracted Linux executable | `6933681828a94382e15a458f6abe16bdff298142ac07eddc709193d5071fde4e` |

The isolated network used Guangzhou `10.245.127.1` and domestic NAT `10.245.127.2`. Both peers used the per-process `MINI_TUNNEL_QUALITY_RTT_THRESHOLD_MS=1000` setting to keep a slow candidate eligible during the controlled recovery check; the product default was not changed. With this setting both peers selected direct `QUIC/UDP`; the baseline passed 20/20 pings in each direction at about 9–10 ms average RTT.

A 10-minute SYSTEM rollback timer was verified before inserting an OUTPUT drop rule on the NAT host. The rule matched only UDP from the test peer's `172.16.11.231:44445` socket to Guangzhou `193.112.165.176:44445`. Both endpoints switched to `Relay/TLS` and stayed online. During impairment, ping passed 20/20 in each direction (0% loss; averages 13.951 ms Guangzhou→NAT and 16.252 ms NAT→Guangzhou). The exact rule counter reached 493 packets / 75,920 bytes. Relay metrics showed one active session, zero handshake failures, 675,608 forwarded bytes, and no UDP Relay session.

Both logs reported the same 15-second UTC rendezvous. For example, both peers started ICE checks at `15:10:00Z` and `15:10:15Z`, within about 20 ms of each other. While the rule was active, unsuccessful probes logged `rendezvous_interval_ms=15000` and approximately 2998 ms until the next shared slot. The current implementation uses this fixed shared cadence; this field run does not show an exponentially increasing wait and does not claim one.

After deleting the exact nftables table and verifying it absent, the automatic timer was disarmed. Both peers promoted back to `QUIC/UDP` within about 30 seconds, with `healthy_direct_probe`, 9 ms status RTT, and 0% reported loss. Post-recovery overlay ping passed 20/20 in both directions (means 10.042 ms and 10.206 ms).

Cleanup deleted the temporary network, removing both members and both invitations, stopped the exact peer/Coordinator/Relay units, and removed task-owned state and keys. The nftables table and timer were absent; neither host retained a test route/address/listener. Guangzhou default route remained via `10.0.20.1`, domestic NAT via `172.16.16.172`, and production Relay PID `17770` retained TCP `42001`, loopback metrics `42002`, and UDP `42003`. Private raw logs are under `.harness/tasks/quick-2519311139/evidence/private/` and are not committed.

This verifies synchronized recovery probing, Relay continuity, and direct-path recovery on one domestic NAT topology. It is not a test of the default RTT policy: the 1000 ms per-process override was required to establish the controlled direct baseline. It also does not demonstrate exponential retry delays; the current shared-cadence implementation was verified instead.
