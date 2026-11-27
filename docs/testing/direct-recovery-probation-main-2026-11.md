# Direct recovery probation after transient-health fix

Date: 2026-11-27 (China Standard Time)
Source: `b1c823a79e34730a1f8381996d90be115460e7a5`
Release staging: [run 45994745767](https://github.com/ilovn/mini-tunnel/actions/runs/45994745767)

## Artifact and test setup

The Linux x86_64 staging archive passed GitHub Sigstore provenance verification for `ilovn/mini-tunnel`, `.github/workflows/release.yml`, `refs/heads/main`, and the exact source SHA above. The archive sidecar checksum also passed. Both Linux peers ran the same prebuilt binary; no target machine performed a build.

| Artifact | SHA-256 |
| --- | --- |
| Linux x86_64 archive | `79d8bb4e64580090550198dcefaadd949f59e8a6c3910018cb6bf0880356fd5f` |
| Extracted executable | `11ed6244c1f11978eebfc461722e68b840b7303963c7d6a1ad9fda5e342dea29` |

The isolated test network used Guangzhou `10.244.156.1`, domestic NAT `10.244.156.2`, and temporary Coordinator/Relay services. The fix samples authenticated candidate health every two seconds during the 31-second probation and uses the configured consecutive bad-RTT window limit.

## Results

- Baseline direct QUIC/UDP passed 20/20 pings in both directions with 0% loss and approximately 9.6–9.9 ms average RTT.
- A temporary NAT OUTPUT rule dropped UDP to the Guangzhou peer endpoint. Its counter reached 61 packets. Both peers selected `Relay/TLS`; 20/20 pings passed in each direction with no loss. The Relay path stayed online.
- After the rule was deleted and verified absent, ICE nominated direct candidates on repeated recovery attempts. Candidates did not complete health probation: logs recorded a 401 ms RTT after two consecutive over-limit samples, and another candidate ended with a lost authenticated probe. Both peers correctly retained `Relay/TLS` with 0% measured tunnel loss.
- Direct recovery acceptance was **not met** in this run. The change now tolerates one RTT outlier and evaluates a denser sample window, but this particular post-impairment candidate path remained degraded. Do not lower the safety threshold based on this result; the path failed the configured quality policy.

## Cleanup

Both test members were revoked through the temporary Coordinator cleanup. Test peer, Coordinator, Relay, and rollback timer units were stopped; temporary directories, test binaries, and the nftables impairment table were removed. Guangzhou production Relay PID `17770` remained listening on TCP `42001`, metrics `42002`, and UDP `42003`. Guangzhou default route remained via `10.0.20.1`; NAT default route remained via `172.16.16.172`. No test interface or route remained.

Raw output and logs remain in the ignored private Harness evidence directory for task `bugfix-f589c310d5`.
