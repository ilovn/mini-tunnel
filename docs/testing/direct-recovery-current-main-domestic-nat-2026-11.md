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
