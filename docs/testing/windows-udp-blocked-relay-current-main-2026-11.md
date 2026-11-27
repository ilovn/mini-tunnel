# Windows UDP-blocked TCP Relay fallback on current main

Date: 2026-11-27 (China Standard Time)
Source: `14ecdca2429893d913625747d59377208c9e16b9`
Release staging: [run 46015015506](https://github.com/ilovn/mini-tunnel/actions/runs/46015015506)

## Artifacts and topology

The Windows x64 and Linux x86_64 staging archives passed their SHA-256 sidecars and `deploy/verify-peer-attestation.sh` for `ilovn/mini-tunnel`, `.github/workflows/release.yml`, `refs/heads/main`, and the exact source SHA above. Neither endpoint compiled source. The workflow completed successfully; its GitHub release publish job was skipped because the run targeted `main`.

| Artifact | SHA-256 |
| --- | --- |
| Windows x64 archive | `a35799c0993c5571269ab31195c4d3b7986c1ae713f442438b6b9c1bca8e6707` |
| Windows `mini-tunnel.exe` | `33e55775f5497bb21d544acfd495b437f0f074169dfc081f527b9f16d42c43d2` |
| Linux x86_64 Ubuntu 20.04 archive | `d450b93e9e229bbedad5f9c5122cc4e0b6bfafa700bd2521979c15e48c88d0b1` |
| Linux `mini-tunnel` | `6933681828a94382e15a458f6abe16bdff298142ac07eddc709193d5071fde4e` |
| Official Wintun 0.14.1 archive | `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51` |
| Wintun x64 DLL | `e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce` |

The test used Windows 10 x64 VM `192.168.196.130` and Guangzhou VPS `193.112.165.176`, with a temporary Coordinator and TCP Relay on task-specific ports. Both joined isolated overlay `10.249.87.0/24` (Windows `.2`, Guangzhou `.1`). No UDP Relay endpoint was configured. The Windows peer ran under a temporary SYSTEM scheduled task. Before it started, a bounded automatic rollback task was armed; inbound and outbound UDP block rules matched only the test executable. TCP remained available.

## Results

| Check | Observation | Result |
| --- | --- | --- |
| Artifact provenance | Both archive checksums and attestations matched the exact source SHA | Passed |
| Selected transport | Windows log reported `Relay/TLS`; Guangzhou reported the peer via `Relay/TLS` | Passed |
| Guangzhou to Windows overlay | `ping -c 20` received 20/20; 0% loss; mean 16.585 ms | Passed |
| Windows to Guangzhou overlay | `ping -n 20` received 20/20; 0% loss; mean 13 ms | Passed |
| TCP Relay counters | 5 accepted TCP connections, 0 handshake failures, 118,548 forwarded bytes, 1 active session at capture | Passed |
| UDP Relay | 0 active sessions; the peer was not configured with a UDP Relay endpoint | Passed |
| Automatic rollback | SYSTEM scheduled task was armed before the scoped UDP rules and had a bounded 15-minute deadline | Passed |

The Windows and Guangzhou peers remained online while the Windows executable could not use UDP. This demonstrates the authenticated TCP/TLS Relay fallback and overlay traffic on this topology. It is a single UDP-blocked sample, not a general Windows NAT result or a long-duration reliability claim.

## Cleanup and limits

Both peer memberships were revoked; the temporary Coordinator snapshot validated with one network, zero members, and zero invites. The Windows peer process and `mtun` adapter/address disappeared. Its exact firewall rules and both temporary scheduled tasks were removed, along with its executable, Wintun DLL, CA, tokens, state, and logs. `YunShuService` remained Stopped / Automatic, its task remained Disabled, and the Windows default route remained Ethernet0 via `192.168.196.2`.

The Guangzhou Coordinator, Relay, state, credentials, binary, and TUN were removed. Its default route remained via `10.0.20.1`; production Relay PID `17770` remained on TCP `42001`, loopback metrics `42002`, and UDP `42003`. No task listener remained on ports `43141`–`43145`.

The Windows VM's public egress was previously observed as the Hong Kong VPS address `151.243.38.115`. This run therefore cannot count as an independent NAT topology, and the public NAT/QoS matrix remains incomplete. Private raw logs and task evidence are kept outside the repository's tracked files.
