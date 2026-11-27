# Bounded direct-recovery dial on domestic NAT

Date: 2026-11-27 UTC  
Code: `6bbffe498857ed71e7031c33cd395c6d34e4b807`  
CI: [run 45945837070](https://github.com/ilovn/mini-tunnel/actions/runs/45945837070)

## Setup

Guangzhou x86_64 and the domestic NAT Ubuntu host ran the CI-built Linux x86_64 artifact. Its SHA-256 sidecar and Sigstore provenance were verified for the exact commit, `ci.yml`, and `refs/heads/main`; the archive hash was `6eef9c57f86aced8a207ebd373aa9cd92d253a2ca8cd4afd9b53a6b961f0ed22`. Neither host built from source. The peers used an isolated Coordinator/Relay and temporary overlay `10.244.239.0/24`.

An nftables output rule on the NAT peer dropped only UDP packets to the Guangzhou test peer and UDP Relay ports. A timed rollback was armed before applying the rule. Coordinator HTTPS and TCP Relay remained available.

## Results

- Before impairment, the peers selected authenticated QUIC/UDP and passed overlay traffic.
- The targeted UDP loss moved the peers online to Relay/TLS. Ten overlay pings passed in each direction with 0% loss. Relay metrics showed an active TCP pair and no UDP Relay session, as expected for this impairment.
- At `05:39:25.095Z`, Guangzhou began a recovery attempt. At `05:39:37.099Z`, its outbound candidate connection failed with `direct recovery dial exceeded 12000 ms`: 12.004 seconds by the log timestamps. Later blocked attempts were also canceled at the configured 12-second bound. The peer retained Relay/TLS and continued carrying traffic.
- The drop was removed at approximately `05:40:32Z`. Both peers subsequently established direct candidates and passed the existing authenticated 31-second probation. The first promotion attempt was rejected by peer path election and retried; both endpoints then reported QUIC/UDP with `healthy_direct_probe` at approximately `05:42:17Z`.
- More than two minutes later, both peers remained online on QUIC/UDP. Each direction passed 20/20 overlay pings with 0% loss; average RTT was about 10 ms. Both final status snapshots reported zero packet drops/rejections and 0% measured loss.

The run validates that a blocked recovery connection attempt is canceled within the recovery-only 12-second budget while the reliable path remains usable. It also observed eventual direct recovery after retries. It does not establish a recovery-time SLA, explain the first rejected promotion, or complete the public NAT/QoS interoperability matrix.

## Cleanup

Both temporary network members were revoked; the Coordinator recorded two successful revocation audit events and its member/invite snapshot returned to zero. Temporary peers, Coordinator and Relay services, routes, test files, timers and firewall state were removed. Verification found no test route, test listeners, or task-specific nftables table. The hosts' default routes remained via `10.0.20.1` on Guangzhou and `172.16.16.172` on the NAT host. Guangzhou's existing production Relay listeners on TCP 42001, UDP 42003, and local metrics TCP 42002 remained active. No credentials or private keys are included in this report.

Raw logs and snapshots are retained in the local ignored Harness evidence directory for task `bugfix-4676cc95b1`.
