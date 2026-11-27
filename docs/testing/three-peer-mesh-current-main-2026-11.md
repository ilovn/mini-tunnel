# Three-peer mesh validation on current main

Date: 2026-11-27 (China Standard Time)
Source: `37745e42f815e0e6c6f2a128463a2f25a67ac29f`
Release staging: [run 46025278542](https://github.com/ilovn/mini-tunnel/actions/runs/46025278542)

## Artifact and setup

The Linux x86_64 Ubuntu 20.04 artifact checksum and GitHub Sigstore provenance passed verification for `ilovn/mini-tunnel`, `.github/workflows/release.yml`, `refs/heads/main`, and the exact source SHA above. The release staging workflow completed successfully for all Linux and desktop targets; its GitHub Release publish job was skipped. All three peers used the same prebuilt Linux x86_64 executable; no endpoint built the binary.

| Artifact | SHA-256 |
| --- | --- |
| Linux x86_64 archive | `310f6457f19f886d1b82c1fccaa80d56d05845f40916bd3ff08ef732df66dedf` |
| Extracted Linux executable | `6933681828a94382e15a458f6abe16bdff298142ac07eddc709193d5071fde4e` |

The isolated IPv4 overlay was `10.249.88.0/24`: Guangzhou `.1`, Docker-hosted endpoint `.2`, and domestic NAT VPS `.3`. A temporary TLS Coordinator and authenticated TCP Relay ran on the Guangzhou VPS. Peers bound UDP port `44445` to their physical interfaces and queried two STUN servers. Standard mode used UDP candidates with TCP Relay fallback; experimental `--ice` was disabled for the acceptance run. No firewall rule or production route was changed.

## Results

Each directed overlay ping sample passed 20/20 with 0% packet loss:

| Pair | Selected path | RTT, direction 1 | RTT, direction 2 |
| --- | --- | ---: | ---: |
| Guangzhou ↔ Docker NAT | QUIC/UDP | 18.645 ms | 18.875 ms |
| Guangzhou ↔ domestic NAT | QUIC/UDP | 10.294 ms | 10.331 ms |
| Docker NAT ↔ domestic NAT | Relay/TLS | 24.866 ms | 24.270 ms |

All three endpoints reported both peers online at the final observation. Per-peer tunnel status reported 0% probe loss and zero dropped or rejected overlay packets. Coordinator candidate snapshots were captured from all three endpoints; each peer appeared with two or three UDP candidate addresses across those observations. The link between the two NAT-side endpoints used the authenticated TCP Relay while the Guangzhou links used direct QUIC/UDP.

An initial optional ICE trial did not establish a usable path for the Docker-hosted endpoint; its container also could not configure IPv6 on its TUN interface. That trial was stopped and excluded from the acceptance run. This report therefore validates IPv4 mesh behavior and the standard UDP/Relay path, not ICE interoperability or IPv6 inside that container. No UDP impairment was applied, so this run does not measure failover timing or packet-loss recovery.

## Cleanup and limits

The temporary network was deleted, removing all three members and invalidating all three invitations. All three peers, the temporary Coordinator and Relay, their test routes, listeners, credentials, and remote test directories were removed. No temporary 10.249.88.0/24 route or test TUN remained. The Docker host's pre-existing EasyTier `tun0` remained at `10.126.126.110/24`; it was not stopped or changed. Guangzhou's default route remained via `10.0.20.1`; production Coordinator PID `5656` and Relay PID `17770` remained running with their original listeners. The Docker and domestic NAT default routes were unchanged.

This validates a three-node IPv4 mesh on these specific Guangzhou, Docker-hosted, and domestic NAT endpoints. It does not establish performance across independent international networks, validate experimental ICE, or cover UDP impairment/recovery. Raw endpoint addresses and logs remain in the ignored, access-restricted Harness evidence directory; credentials and temporary private keys were deleted after cleanup.
