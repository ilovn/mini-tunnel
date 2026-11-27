# Linux systemd peer restart on the Windows overlay

Date: 2026-11-27 (UTC)
Source: `fb5a7c667f1cb635790b7e37864439e0c75f4a7a`
Harness task: `complex-e70a2977b6`

## Build provenance

Used the exact-main staging artifacts from [Release workflow run 45982267060](https://github.com/ilovn/mini-tunnel/actions/runs/45982267060). The run built Linux x86_64 and Windows x64 artifacts; publishing was skipped because this was a `main` dispatch, not a version tag. Sidecars and Sigstore attestations were verified for `ilovn/mini-tunnel`, `.github/workflows/release.yml`, `refs/heads/main`, and the source SHA above. Neither endpoint built the application from source.

| Artifact | SHA-256 |
| --- | --- |
| Linux x86_64 Ubuntu 20.04 archive | `9c0a21055e164576c642ae638c165b9b7d377ccb085149b1c4ca30bd76a58999` |
| Linux x86_64 executable | `6e0bbbd485161b2ba62d6a35ecbeaf2d347e0330a01b0c72256c61f8b8b3e0aa` |
| Windows x86_64 archive | `1367dd5aa0278a49e14921e9f23c0f51948a954bcb6c1880b2faa0ff42ce24fa` |
| Windows x86_64 executable | `af6ca5d923bfef0f56cc026e287195952cae1610528809bc106924822ca69e21` |
| Wintun 0.14.1 package | `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51` |

## Field results

The isolated network used a temporary Guangzhou Coordinator and Relay and two temporary peers: the Guangzhou Linux VPS and the Windows 10 VM on VMware NAT (`192.168.196.130`, gateway `192.168.196.2`). The network was `10.249.11.0/24`; Linux retained `10.249.11.1` and Windows retained `10.249.11.2`. Both peer processes were started only after bounded cleanup was armed. The service restart affected only the task-owned Linux peer unit.

| Check | Observation | Result |
| --- | --- | --- |
| Baseline Windows → Linux | 20/20 replies, 0% loss, average 12 ms | Passed |
| Baseline Linux → Windows | 20/20 replies, 0% loss, average 15.2 ms | Passed |
| Restart recovery, third measured run | Linux peer status returned online 17.32 seconds after restart. Linux → Windows then returned 5/5 replies within 18.15 seconds. The Windows timestamped monitor recorded a successful probe 6.61 seconds after restart and another at 20.77 seconds. | Passed within 30 seconds |
| Identity and lease | The Linux device-key SHA-256 was unchanged before and after restart; the Linux TUN address remained `10.249.11.1`, and Windows remained `10.249.11.2`. | Passed |
| Post-recovery | Windows → Linux returned 10/10 replies, 0% loss. Status showed the peers online on Relay/TLS with 0% rolling loss; two packets were dropped during path transition. | Passed; brief transition loss observed |

The tested path used the temporary Relay (`Relay/QUIC/UDP` before restart, then the peer selected the reliable `Relay/TLS` path during recovery). This validates restart recovery over the Relay-backed overlay. It does not claim a direct peer-to-peer path or an independent public NAT traversal result. One Windows probe immediately before the measured restart was lost; subsequent timestamped probes recovered inside the 30-second window.

## Cleanup and host-state check

- Revoked both temporary member IDs; Coordinator output confirmed release of `10.249.11.1` and `.2`.
- Windows peer and cleanup scheduled tasks were removed. The test adapter, overlay route, executable, state, certificate, invite token, and task directory were absent afterward.
- Linux test peer, Coordinator, Relay, and watchdog units were stopped; the temporary TUN address, test listeners, and `/tmp/mini-tunnel-e70a2977b6` directory were absent afterward.
- Guangzhou default route remained via `10.0.20.1`. Production Relay PID `17770` remained on TCP `42001`, UDP `42003`, and loopback metrics `42002`.
- Windows default route remained Ethernet0 via `192.168.196.2`; `YunShuService` remained stopped with Automatic start type.
- Raw peer logs, private keys, invitation material, and host diagnostics remain private under `.harness/tasks/complex-e70a2977b6/evidence/private/` and are not committed.

## Conclusion

This field run meets the Linux systemd peer restart criterion on the Windows overlay: the peer reused its identity and address and restored two-way traffic within 30 seconds. The observed transition dropped two packets before the stable Relay/TLS path carried subsequent probes without loss. Direct peer-to-peer recovery and other Windows NAT topologies remain outside this test.
