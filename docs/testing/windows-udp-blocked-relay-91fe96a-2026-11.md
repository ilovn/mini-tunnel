# Windows UDP-blocked TCP Relay fallback on current main (91fe96a)

Date: 2026-11-28 (China Standard Time)
Source: `91fe96a010ec6a3608b5a1e7c8a3cb08bd052f0f`
Release staging: [run 46075694945](https://github.com/ilovn/mini-tunnel/actions/runs/46075694945)

## Artifacts and topology

The Linux x86_64 and Windows x64 artifacts passed SHA-256 sidecar and `deploy/verify-peer-attestation.sh` checks for `ilovn/mini-tunnel`, `release.yml`, `refs/heads/main`, and the exact source SHA. No endpoint compiled source and no release was published.

| Artifact | SHA-256 |
| --- | --- |
| Linux x86_64 archive | `99efc09fd6bb0bb478839822df1c530b60e98f4b371d5f5d8871a610c13c7b23` |
| Linux `mini-tunnel` | `f46e08e569a38b7ccef35362c100f1a3fdd91ac939bd50aca2f1e264f049b753` |
| Windows x64 archive | `b88cc4d98044d5e2f20014749328d066c26160d544ed8bf49f348cfd6de17959` |
| Windows `mini-tunnel.exe` | `43b9ba8a5e55b4a19ac3a4b9bbea3bcd8f02f466e5bd710b3080b1a9f5f5738e` |
| Wintun x64 DLL | `e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce` |

The test used the Windows 10 x64 VM (`192.168.196.130`) and Guangzhou VPS (`193.112.165.176`) on an isolated `10.249.88.0/24` overlay. The temporary Coordinator and TCP Relay used dedicated ports. The Relay's UDP listener bound only to loopback on an ephemeral port, and neither peer received a UDP Relay endpoint. Windows inbound and outbound UDP firewall blocks matched only the exact test executable path; TCP remained available. A 30-minute GZ cleanup timer and a 30-minute SYSTEM Windows cleanup task were verified before the test firewall rules or TUN were activated.

## Results

| Check | Observation | Result |
| --- | --- | --- |
| Artifact provenance | Both release archives and extracted binaries matched checksums and attestations for the exact source SHA | Passed |
| Selected path | Both peer status endpoints reported online over `Relay/TLS` while the Windows UDP block rules were enabled | Passed |
| Guangzhou to Windows | 20/20 ICMP replies; 0% loss; mean 18.007 ms (max 29.902 ms) | Passed |
| Windows to Guangzhou | 20/20 ICMP replies; 0% loss; mean about 13 ms (13–16 ms observed) | Passed |
| Peer packet counters | Each side recorded 40 sent and 40 received packets; zero drops and rejects | Passed |
| TCP Relay | 2 active TCP connections and 1 session; forwarded bytes rose from 97,364 to 152,506 during the sample | Passed |
| Relay failures | Handshake failures, pairing rejections, and handshake timeouts remained at 0 | Passed |
| UDP Relay | 0 active UDP Relay sessions; no UDP Relay endpoint was configured | Passed |

This confirms authenticated TCP/TLS Relay fallback and bidirectional overlay traffic for this Windows test path with UDP blocked for the tunnel executable. It is one interoperability sample and does not complete the public NAT/QoS matrix or establish long-duration reliability.

## Cleanup and execution note

Both test members were revoked; the temporary Coordinator state reported zero members and zero invites. The Windows test processes, TUN adapter, overlay routes, exact firewall rules, scheduled tasks, deployment files, and staging files were removed. Its default route remained Ethernet0 via `192.168.196.2`; `YunShuService` remained Stopped / Automatic. On GZ, the temporary processes, listeners, routes, systemd units, timer, root, stage, and helper files were removed. The existing domestic soak's GZ and NAT peer/monitor services, cleanup timers, and `10.252.45.0/24` routes were still active after cleanup.

The initial Windows setup helper timed out because its status waiter expected a `.peers` property, while the current status endpoint returns a list. The peer task itself remained active; direct status API checks on both peers confirmed `Relay/TLS`, and both ping directions and Relay counters were then measured with the UDP rules still enabled. The helper was not used as the acceptance evidence.

Private raw logs and temporary credentials are kept only in the ignored Harness evidence directory; no tokens or private keys are included in this report.
