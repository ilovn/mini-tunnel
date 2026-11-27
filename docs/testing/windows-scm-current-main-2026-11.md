# Windows SCM peer check on current main

Date: 2026-11-27 (China Standard Time)
Source: `b1c823a79e34730a1f8381996d90be115460e7a5`
Release staging: [run 45994745767](https://github.com/ilovn/mini-tunnel/actions/runs/45994745767)

## Artifacts and test setup

The Windows x64 archive passed GitHub Sigstore provenance verification for `ilovn/mini-tunnel`, `.github/workflows/release.yml`, `refs/heads/main`, and the exact source SHA above. The archive was not published as a release and the VM did not build from source.

| Artifact | SHA-256 |
| --- | --- |
| Windows x64 archive | `1585af026448cd70a90c167594c7c7fc8db1301675e9c89fccf1d9fff84d802a` |
| Extracted `mini-tunnel.exe` | `a429c4a6a2475e17499359d6443616fbe8dd3db423a7664681d7278244542a20` |
| Official Wintun 0.14.1 archive | `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51` |
| Extracted Wintun x64 DLL | `e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce` |

The test used the Windows 10 x64 VM `192.168.196.130`, a temporary Guangzhou Coordinator/Relay, and an isolated overlay with Windows at `10.244.156.2` and Guangzhou at `10.244.156.1`. The peer ran as a LocalSystem SCM service. The Windows service exposed status only on loopback and used protected ProgramData state.

## Results

| Check | Observation | Result |
| --- | --- | --- |
| Windows binary | `--version` and `windows-service-host --help` ran on the VM | Passed |
| SCM start | Service reached `Running`; peer reported online over `Relay/TLS` | Passed |
| Windows to Guangzhou | 20/20 baseline and 10/10 after restart, 0% loss | Passed |
| Guangzhou to Windows | 20/20 baseline and 10/10 after restart, 0% loss | Passed |
| SCM restart recovery | Peer returned online in 17 seconds; device-key SHA-256 stayed unchanged | Passed within 45 seconds |
| UDP quality fallback | A nominated UDP candidate measured 222 ms RTT and 66% probe loss; the peer retained `Relay/TLS` and continued passing overlay pings | Passed; direct UDP stability not demonstrated on this VM path |
| SCM recovery policy | Restart delays of 5, 15, and 60 seconds were configured and queried with `sc.exe qfailure` | Passed |

## Cleanup and limits

The temporary Windows member was revoked and its SCM service, ProgramData state, executable, Wintun DLL, staging files, test adapter, and overlay route were removed. `YunShuService` remained stopped, `sshd` remained running, and the Windows default gateway remained `192.168.196.2`. Guangzhou test services, timers, state, and binaries were removed; production Relay PID `17770` remained on TCP `42001`, metrics `42002`, and UDP `42003`, with default route via `10.0.20.1`.

This validates the current-main Windows SCM lifecycle and safe retention of Relay when the direct candidate is unhealthy. It does not show stable Windows direct P2P on this network path. The normal generated installer still needs a published Windows release and an unmodified published-download acceptance before Windows Beta can be removed.
