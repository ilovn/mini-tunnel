# Guangzhou–Hong Kong ICE probation field check

Date: 2026-11-27 (China Standard Time)
Source: `c72a255d5b881d316abafca6279e6fdf1eae15ed`
Harness task: `complex-79cbab0dd0`
Release staging run: `45886332907` (all build jobs succeeded; publish job skipped)

## Build provenance

The Linux x86_64 archive used on both VPSs was downloaded from the staging workflow. Its SHA-256 sidecar matched, and `deploy/verify-peer-attestation.sh` verified the Sigstore attestation against `.github/workflows/release.yml`, `refs/heads/main`, and the source SHA above. No endpoint was built locally.

| Artifact | SHA-256 |
| --- | --- |
| Linux x86_64 archive | `1b31cd3c8f6540d4135ed7ba1f021ea6affbe54cfd6a21119278ef3262656260` |
| Extracted Linux executable | `603cfe499f22759354d6129d538c278b565eea1d3dbf8dfb1dec445e1547e6e8` |

## Test and observations

An isolated Coordinator and Relay ran on Guangzhou ports TCP `43141` (Coordinator), TCP `43143`, UDP `43144` (Relay), with metrics bound to loopback `43142`. Both peers joined a temporary `10.246.79.0/24` network, used ICE, and bound peer UDP port `42000`. No firewall rule, default route, or production service was changed.

Both sides nominated a direct ICE pair: Hong Kong accepted 46 ICE STUN datagrams and Guangzhou accepted 23 in its successful checklist. Guangzhou's initial authenticated UDP health probes passed at about 315 ms RTT. Its five-second probation then failed at 4 successful and 5 missed health probes; the new structured field reported `timed_out_probe_attempts=0`. The available logs therefore show health loss, but do not show an individual probation probe timeout being classified by the timeout handler. Hong Kong's elected accepted path closed when Guangzhou rejected the direct path.

Both peers switched to `Relay/TLS` and stayed online. Their live status reported about 320 ms RTT, 0% loss, 0 drops/rejections, and 20 packets sent and received per peer after the two-way ICMP run. Guangzhou→Hong Kong and Hong Kong→Guangzhou each completed 10/10 pings (0% loss, approximately 320 ms RTT). During the following recovery window, Hong Kong attempted direct UDP recovery but logged `connection lost`; both peers remained on Relay/TLS. No packet impairment was applied because the direct path did not pass probation.

## Cleanup and conclusion

Both test devices were revoked and their `.1`/`.2` IPv4 leases released. The exact test peer, Coordinator, and Relay services were stopped, and `/tmp/mini-tunnel-79cbab0dd0-c72a255` was removed from both hosts. No test listener, route, or TUN remained. Guangzhou's existing `tun0` and `tun1` remained; Hong Kong had no TUN. Guangzhou's default route remained via `10.0.20.1`; production Relay PID `17770` remained on TCP `42001`, UDP `42003`, and loopback metrics `42002`. Hong Kong's default route remained via `151.243.38.1`. No test-specific firewall rule was present after cleanup, and this run did not execute firewall mutation commands. Private logs and credentials are not committed.

This run verifies direct ICE nomination, probation loss detection, fallback to Relay/TLS, bidirectional overlay traffic, and a failed later direct recovery attempt. It does **not** verify the timeout-specific probation behavior or healthy UDP recovery on this Guangzhou–Hong Kong path. The timeout test remains open; current evidence does not justify injecting packet loss because the direct path is already unhealthy.

Private raw logs are retained under `.harness/tasks/complex-79cbab0dd0/evidence/private/raw/`.
