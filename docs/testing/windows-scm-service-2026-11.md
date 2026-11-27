# Windows SCM peer service field check

Date: 2026-11-27 (China Standard Time)
Source: `2c726add6f3b8ac6cf32effd39b71a76d8cff6a5`
Release staging: [run 45987845710](https://github.com/ilovn/mini-tunnel/actions/runs/45987845710)

## Artifacts and setup

The x64 Windows archive was built from the exact `main` source SHA above. Its checksum sidecar matched and `deploy/verify-peer-attestation.sh` accepted the GitHub Sigstore provenance for `ilovn/mini-tunnel`, `.github/workflows/release.yml`, `refs/heads/main`, and that source SHA. The Windows 10 x64 VM (`192.168.196.130`) did not build from source.

| Artifact | SHA-256 |
| --- | --- |
| Windows x64 archive | `5e177a75cc6588f6fa5bb5ba9489fece37128bb552d307662fc9e2eded12e754` |
| Extracted `mini-tunnel.exe` | `d86f2d73ef1c6e6f59c05399a73adec1757267f2e647a5d2acf55af9aa996b7f` |
| Official Wintun 0.14.1 archive | `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51` |

The test used a short-lived isolated Guangzhou Coordinator and Relay, plus a Windows SCM peer. Enrollment allocated `10.244.156.2`; the Guangzhou Linux peer used `10.244.156.1`. The Windows service ran under the LocalSystem default, stored its identity/configuration under the protected ProgramData directory, and exposed status only on loopback.

## Results

| Check | Observation | Result |
| --- | --- | --- |
| Windows binary | `mini-tunnel.exe --version` and `windows-service-host --help` ran on the VM | Passed |
| SCM start | Service reached `Running`; peer status reported online over `Relay/TLS` | Passed |
| Windows to Guangzhou | 20/20 baseline replies, 0% loss, 13 ms average; after restart 10/10, 0% loss, 12 ms average | Passed |
| Guangzhou to Windows | 20/20 baseline replies, 0% loss; one transient 441 ms peak. After restart 10/10, 0% loss, 16.1 ms average | Passed, transient latency spike observed |
| SCM restart recovery | Peer became online 31.2 seconds after `Restart-Service`; the device-key SHA-256 was unchanged | Passed within the 45-second observation window |
| Recovery policy | `sc.exe qfailure` reported restart delays of 5, 15, and 60 seconds | Passed |
| VPN / management access | `YunShuService` remained stopped; Windows SSH stayed reachable and Ethernet0 default gateway remained `192.168.196.2` | Passed |

The live direct UDP candidate was not healthy on this VM path: probation observed high RTT or packet loss, so the peer retained the reliable Relay path. The observed online service path was `Relay/TLS`; this report does not claim stable direct P2P from this Windows NAT.

## Cleanup and limits

The one-use member was revoked by the temporary Coordinator cleanup. The SCM service, test identity/configuration, executable, Wintun DLL, token, CA, temporary files, and overlay route/interface were removed. No task service or port remained on Guangzhou; its default route stayed via `10.0.20.1`, and production Relay PID `17770` remained on ports `42001/42002/42003`. Windows retained its Ethernet0 default route; `YunShuService` stayed stopped and `sshd` stayed running.

This validates the exact-main Windows service-host binary and a manually staged SCM lifecycle over a real overlay. The normal generated installer downloads only published release tags, while this artifact was intentionally unpublished staging. Published-release download/provenance flow and Windows-native automated SCM integration remain to be verified before removing the Windows Beta label. Raw logs and credentials remain private under the ignored Harness evidence directory.
