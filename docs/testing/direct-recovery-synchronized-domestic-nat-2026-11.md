# Synchronized direct recovery on domestic NAT

Date: 2026-11-27 (China Standard Time)  
Source: `a5617cf5b726f428fdf2d2ba61add61cee1bbe2a`  
Main CI: [run 45913101406](https://github.com/ilovn/mini-tunnel/actions/runs/45913101406)  
Release staging: [run 45913832760](https://github.com/ilovn/mini-tunnel/actions/runs/45913832760)  
Harness task: `bugfix-1d86704ae5`

## Artifact provenance

The Linux x86_64 archive came from the successful Linux x86_64 release staging job in run `45913832760`. Its SHA-256 sidecar matched, and `deploy/verify-peer-attestation.sh` verified the GitHub Sigstore attestation for repository `ilovn/mini-tunnel`, workflow `release.yml`, ref `refs/heads/main`, and source commit `a5617cf5b726f428fdf2d2ba61add61cee1bbe2a`. The same archive was used on both VPSs; neither endpoint built from source.

| Artifact | SHA-256 |
| --- | --- |
| Linux x86_64 archive | `62e20b1fe9934fc3ae8f409b6275d392338fd32fd13d7c0def28346ae9fefdc1` |
| Extracted Linux executable | `88d8b2a26c25d8d2e381b32ccecfccf36a06309eaa88ccf3170dcc7fb74585a0` |

## Results

- Guangzhou and the domestic NAT peer joined an isolated `10.244.224.0/24` overlay and selected authenticated `QUIC/UDP`. Baseline overlay pings passed 10/10 in both directions, 0% loss, averaging about 10 ms.
- A watchdog was armed before installing one NAT-side nftables OUTPUT rule limited to UDP destination `193.112.165.176:44445`. Its counter recorded 48 packets / 6,392 bytes. Both peers moved to `Relay/TLS`, stayed online, and passed 15/15 overlay pings in each direction with 0% loss.
- The rule was removed at `2026-11-27T00:03:17Z`; its absence was verified before stopping the rollback timer. Direct probes that began while the loss rule was active failed as expected. Both peers then retried on the shared UTC rendezvous at `00:04:00Z`; Guangzhou's accepted-side ICE checklist nominated the direct candidate, and each side passed 31-second authenticated UDP health validation. Both status endpoints reported `online=true`, `QUIC/UDP`, and `healthy_direct_probe` by `00:04:51Z`.
- Post-recovery overlay pings passed 20/20 in both directions with 0% loss and about 9.7–10 ms average RTT. This validates direct baseline, controlled-loss fallback, reliable-path continuity, and direct UDP recovery using the attested `a5617cf` artifact.

## Cleanup

Both test memberships were revoked and the Coordinator confirmed release of `10.244.224.1` and `.2` in successful audit events. Both peer processes, the temporary Coordinator and Relay, timers, nftables table, test routes, test ports, keys, certificates, state, binaries, and temporary files were removed. Final checks found no test listeners, overlay route, firewall table, or active test unit. Guangzhou's default route remained via `10.0.20.1`; production Relay PID `17770` continued listening on TCP `42001`, TCP metrics `42002`, and UDP `42003`. The NAT default route remained via `172.16.16.172`. Timestamped private logs and command outputs are retained under the ignored Harness evidence directory `.harness/tasks/bugfix-1d86704ae5/evidence/private/` and are not committed.

At the default 60-second rendezvous cadence, recovery waits for the next common UTC slot and then completes the configured UDP probation. In this run, direct UDP was promoted about 75 seconds after loss removal.
