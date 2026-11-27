# 15-second direct recovery cadence on domestic NAT

Date: 2026-11-27 (UTC)  
Source: `c7163a5132bc8c068a21ed591b0862503626030e`  
CI: [run 45941162083](https://github.com/ilovn/mini-tunnel/actions/runs/45941162083)  
Release staging: [run 45941208114](https://github.com/ilovn/mini-tunnel/actions/runs/45941208114)  
Harness task: `complex-e6511eef67`

## Artifact provenance

Both Linux x86_64 peers used the same release-staging artifact. Its checksum sidecar matched, and `deploy/verify-peer-attestation.sh` accepted the GitHub Sigstore provenance for `ilovn/mini-tunnel`, `release.yml`, `refs/heads/main`, and the exact source commit above. No test host built from source.

| Artifact | SHA-256 |
| --- | --- |
| Linux x86_64 archive | `7453379d4dce8006408437eb6a56b3ceb1bfcec7b3f6c1d97a28a64304ea4a05` |
| Extracted Linux executable | `ecf7c7dc72db3bbab303e59b4185db5b5fdf4086d924feec0e43fdc2c926930a` |

## Results

- Guangzhou's default route was via `10.0.20.1`; the domestic NAT peer's was via `172.16.16.172`. Both joined a fresh `10.244.238.0/24` overlay and reported online `QUIC/UDP` at about 9 ms RTT. The first baseline passed 10/10 pings in each direction with 0% loss; a second baseline passed 5/5 each way.
- For each impairment trial, a six-minute automatic rollback timer was confirmed active before installing one NAT-side OUTPUT drop rule restricted to UDP destination `193.112.165.176:44445`. The first rule counter recorded 29 packets/3,505 bytes; the second recorded 28 packets/3,411 bytes. Both peers changed to `Relay/TLS` (`quality_threshold` at Guangzhou and `transport_failure` at the NAT peer) and stayed online. The first trial passed 15/15 overlay pings each way with 0% loss; the second passed 5/5 each way. TCP Relay metrics showed one active session, zero handshake failures, and forwarded bytes.
- The first rule was verified absent at `2026-11-27T04:49:30.215Z`; the second at `04:56:53.556Z`. The rollback timer was stopped only after absence was confirmed. Both peers promoted to authenticated direct `QUIC/UDP`: at `04:50:17.231Z`/`04:50:17.273Z` in the first trial (about 47.0 seconds after removal), and `04:58:01.417Z`/`04:58:02.244Z` in the second (about 67.9–68.7 seconds after removal). These are two samples, not a recovery-time guarantee.
- The previous 60-second cadence run recorded direct promotion at `00:04:31.806Z` after removing its rule at `00:03:17Z` (about 74.8 seconds). Both 15-second-cadence samples recovered sooner by about 6–28 seconds. The observed range shows improvement on this topology but also varies with ICE nomination and probation timing; more NAT types and repetitions are needed before setting an operational bound.
- After recovery, the first trial passed 20/20 pings per direction and the second passed 10/10, all with 0% loss. Both status endpoints reported `online=true`, `QUIC/UDP`, and `healthy_direct_probe`.
- In the second trial, the Coordinator returned successful revocation results for both test members and released their overlay leases; its journal recorded two `member_revoked` success events. Temporary peers, Coordinator, Relay, TUNs/routes, firewall table, rollback/cleanup timers, listeners, credentials, binaries, and state were then removed. Verification found no task units, timers, test listeners, overlay routes, test files, or firewall table. Both default routes and Guangzhou's production Relay listeners on ports 42001–42003 remained intact.

This confirms the new cadence reduced recovery time on one domestic NAT topology while preserving Relay traffic during direct-path impairment. Public NAT/QoS interoperability, symmetric NAT, and congestion/restart behavior remain unverified. Raw logs and test credentials are retained only in the ignored private Harness evidence directory.
