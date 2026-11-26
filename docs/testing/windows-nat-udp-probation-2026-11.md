# Windows NAT UDP probation field check

Date: 2026-11-27 (China Standard Time)
Source: `1ff65b45e6f4a7d83185713740c7d0f3cef5dc6b`
Harness task: `complex-fe2e6b84e9`

## Build provenance

Used the staging artifacts from GitHub Release workflow run `45874299516`; the staging workflow did not publish a release. The artifacts were built from the source SHA above. SHA-256 sidecars matched the downloaded archives, and Sigstore attestations were verified against `.github/workflows/release.yml` and `refs/heads/main`.

| Artifact | SHA-256 |
| --- | --- |
| Linux x86_64 Ubuntu 20.04 archive | `a64439be49537201e2ae158d4252f9552cbbfb53bd258d5682bc10b298e3ed62` |
| Windows x86_64 archive | `b5bd2d5db5e9c47519fe0ec1ac675cf0fcd9a51133e0c93ce40450c5afd751e6` |
| Extracted Linux executable | `9296bdee1801716dde09c5b4d3397605cfb1b4c0d80a6140fede416ead5de54c` |
| Extracted Windows executable | `9974eed644ee172a7d5c3538a8dc09a2544c8db1034689b71961f91842b57ed4` |
| Wintun 0.14.1 package | `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51` |

No endpoint built the binaries locally.

## Field results

The Windows 10 VM used VMware NAT (`192.168.196.130`, default gateway `192.168.196.2`). It joined an isolated three-member test network with Guangzhou and Hong Kong. The peers used the staging binaries, ICE, and the temporary Coordinator/Relay; production services and default routes were left alone.

| Pair / check | Observation | Result |
| --- | --- | --- |
| Windows ↔ Guangzhou | Windows had an online Relay/TLS path (about 15 ms). Overlay ping succeeded in both directions during the run (Windows→Guangzhou: 5/5; Guangzhou→Windows: 10/10). Guangzhou's repeated Windows ICE checklists ended `nominated=false`, with zero accepted peer datagrams. | Windows peer and authenticated fallback worked; direct Windows↔Guangzhou ICE was not established. |
| Windows ↔ Hong Kong | Hong Kong's log recorded a nominated QUIC/UDP pair to the Windows peer, passed the initial authenticated probes, and completed its five-second probation. | Confirms a direct UDP path from the Windows NAT VM to another public peer. No probation timeout was recorded for this pair. |
| Guangzhou ↔ Hong Kong | ICE nominated a QUIC/UDP pair and initial authenticated probes passed. The probation ended at 4 successes / 4 misses, above the configured loss threshold, and the peer moved to Relay/TLS. | Confirms fallback under observed high UDP loss. Logs do not preserve an explicit per-probe timeout message, so this does not prove the timeout-specific regression by itself. |

The Windows status and Guangzhou peer logs showed the tunnel remained online over Relay while direct recovery attempts failed. Raw logs and Windows diagnostics are retained locally under `.harness/tasks/complex-fe2e6b84e9/evidence/private/`; they contain operational details and are intentionally not committed.

## Cleanup and host-state check

- Revoked all three test member IDs; the Coordinator released `10.244.37.1`, `.2`, and `.3`.
- Stopped the test Coordinator, Relay, and peer units and removed the exact `/tmp/mini-tunnel-fe2e6b84e9` directories on Guangzhou and Hong Kong. No test ports remained.
- Windows test peer and cleanup tasks were removed; the test executable, Wintun DLL, state, certificate, invite token, staging directory, adapter, route, process, and listener were absent after cleanup.
- Windows default route remained via `192.168.196.2`. `YunShuService` remained stopped (Automatic), and `YunShu Service Task Scheduler` remained disabled.
- Guangzhou default route remained via `10.0.20.1`. Production Relay PID `17770` remained on TCP `42001`, UDP `42003`, and loopback metrics `42002`.
- Hong Kong default route remained via `151.243.38.1`. No test route or port remained.
- The Guangzhou peer process exited with status 1 because SIGINT interrupted its managed-route deletion. Follow-up inspection found no `10.244.37.*` route or address and no test interface; existing unrelated `tun0` and `tun1` were left untouched.

## Conclusion

This run verifies the Windows peer on VMware NAT, direct Windows-to-Hong Kong UDP, stable Windows-to-Guangzhou Relay fallback, and safe fallback when a separate direct UDP path has high loss. It does **not** meet the specific acceptance criterion for direct Windows↔Guangzhou ICE or capture of a probation probe timeout followed by later samples. The timeout-handling change remains covered by workspace tests, but field validation of that exact regression is still pending.

For a conclusive retest, first establish and record a nominated Windows↔Guangzhou pair, then capture per-probe debug logs while applying a narrowly scoped, automatically reverted loss interval to that pair. Keep the same verified CI artifacts and cleanup checks.

## Retest on main `68d62ac`

Date: 2026-11-27 (China Standard Time). Release staging workflow run: `45883051511`; the publish job was skipped because this was a branch build. Both artifacts were built from `68d62ac408f089fe6c0223811b66ebb3c3ae3249`. SHA-256 sidecars matched and `deploy/verify-peer-attestation.sh` passed against `.github/workflows/release.yml` and `refs/heads/main`.

| Artifact | SHA-256 |
| --- | --- |
| Linux x86_64 archive | `231c6fa717d8afedfaf681fd3792503697cea20b57ee0e53483325f58e51a76f` |
| Windows x86_64 archive | `6ccb0e81779438db4e5a1c35427b817bebd592bf683b027af150c77fc7fd510e` |
| Extracted Linux executable | `de237a4d0ec4f59148c7e2fee3b9f293a40c50fdb9e68733ec0db93ae7afd4e7` |
| Extracted Windows executable | `bc9c8ae90e8830664913e395a797321a6264e912afa2cf82f2b55379d8232b82` |
| Wintun x64 DLL | `e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce` |

This isolated two-peer run used a temporary Coordinator/Relay on Guangzhou and UDP/42000 for the peer. Windows VMware NAT and Guangzhou both nominated the direct ICE pair. Windows accepted 15 STUN datagrams and Guangzhou accepted 17. Guangzhou logged three successful authenticated initial health probes, then ended its five-second probation at 5 successes / 6 misses and rejected the direct path. Windows independently logged that QUIC setup lost the connection, then closed the elected path with 0 successful and 0 missed probation probes. Both peers remained online through Relay; their final status snapshots had zero overlay packets sent or received. Thus the new port produced ICE nomination, but not a stable direct data path or successful overlay transfer.

The available raw logs do not include a per-probe `timeout` event or prove that an individual timeout was counted by the intended handler. No packet impairment was applied because a stable direct baseline and overlay transfer were prerequisites. The timeout-specific field criterion remains open.

Cleanup evidence: both test members were revoked and their `10.244.37.1`/`.2` leases released. The test Coordinator, Relay, and peer services and `/tmp/mini-tunnel-fe2e6b84e9` were removed. Windows FE2 tasks, routes, adapter, process, test files, and staging directory were absent. Windows default route remained on `Ethernet0` via `192.168.196.2`; `YunShuService` remained stopped (Automatic), and its scheduled task remained disabled. Guangzhou default route remained via `10.0.20.1`; production Relay PID `17770` retained TCP `42001`, UDP `42003`, and loopback metrics `42002`. No test ports or `tun2` remained; existing `tun0` and `tun1` were preserved. Private raw logs remain local and are not committed.
