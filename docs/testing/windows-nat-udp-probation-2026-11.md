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

## Retest on main `c72a255`

Date: 2026-11-27 (China Standard Time). Release staging workflow run: `45886332907`; Linux x86_64 and Windows x86_64 build jobs succeeded and the publish job was skipped. SHA-256 sidecars matched, and `deploy/verify-peer-attestation.sh` verified both Sigstore attestations against `.github/workflows/release.yml`, `refs/heads/main`, and source `c72a255d5b881d316abafca6279e6fdf1eae15ed`.

| Artifact | SHA-256 |
| --- | --- |
| Linux x86_64 archive | `1b31cd3c8f6540d4135ed7ba1f021ea6affbe54cfd6a21119278ef3262656260` |
| Windows x86_64 archive | `9f87d1a8fed8a21e510d352462003438481dbe0fe959c534ef8d9f5d47585228` |
| Extracted Linux executable | `603cfe499f22759354d6129d538c278b565eea1d3dbf8dfb1dec445e1547e6e8` |
| Extracted Windows executable | `1ff19ae398943d881e90b9e632a6a428eeb1f02a31082c9fc8f3ecc290614182` |
| Wintun x64 DLL | `e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce` |

This isolated two-peer retest paired Guangzhou with Windows 10 behind VMware NAT (`192.168.196.130`, gateway `192.168.196.2`). The Windows public egress observed before the run was `151.242.172.39`; `YunShuService` was stopped. Both endpoints used attested CI artifacts; neither built source locally. Guangzhou nominated the Windows UDP candidate and its initial authenticated health probes passed, but five-second probation ended at 4 successes / 5 misses with `timed_out_probe_attempts=0`. The direct path was rejected and both peer status snapshots showed `Relay/QUIC/UDP`. No firewall impairment was applied. Overlay ping then passed 5/5 Guangzhou→Windows and 3/3 Windows→Guangzhou, both with 0% loss, over the Relay path.

This confirms that the Windows peer joins and carries overlay traffic through Relay after an unstable direct UDP candidate. It does not establish a stable direct Windows↔Guangzhou path or exercise controlled loss, a nonzero timeout counter, or recovery from Relay to direct UDP. Private raw peer/service logs and Relay metrics are retained under `.harness/tasks/complex-fe2e6b84e9/evidence/private/retest-c72/` and are not committed.

Cleanup revoked both test memberships and released `10.244.218.1` and `.2`. The temporary Windows peer process, scheduled task, route, interface, status listener, and `C:\ProgramData\MiniTunnel\R27` directory were removed. The temporary Guangzhou services and `/tmp/mini-tunnel-windows-retest-20261127` directory were removed; no test route, listener, or process remained. Guangzhou default route stayed via `10.0.20.1`; production Relay PID `17770` retained TCP `42001`, UDP `42003`, and metrics `42002`; existing `tun0`, `tun1`, and `iwan0` remained. Windows default route stayed via `192.168.196.2`; `YunShuService` remained stopped (Automatic), and `YunShu Service Task Scheduler` remained disabled. No firewall rule/table was installed or changed.

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

After cleanup, a read-only Windows egress check returned public IP `151.243.38.115`, the same address used by the Hong Kong VPS. The guest default route still pointed to VMware NAT gateway `192.168.196.2`; traceroute then showed private hops `172.16.16.170` and `198.18.0.1`. `YunShuService` was stopped during these checks. This establishes that the guest's observed public egress was the Hong Kong VPS address, but does not identify which host or upstream device provides that forwarding. The tested route therefore cannot be treated as an ordinary direct Windows NAT path.

## Retest on main `a2a30e8` (Windows current-ejection path)

Date: 2026-11-27 (China Standard Time). Release staging workflow run `45916756125` built Linux x86_64 and Windows x86_64 artifacts from `a2a30e8cb8e994e0eef792c88806c9a480c9e287`; the build jobs succeeded. Archive SHA-256 sidecars matched, and `deploy/verify-peer-attestation.sh` verified both attestations against `.github/workflows/release.yml`, `refs/heads/main`, and that exact source SHA. No endpoint built the binaries. Wintun 0.14.1 package SHA-256 was `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`; the deployed x64 DLL SHA-256 was `e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce`.

| Artifact | SHA-256 |
| --- | --- |
| Linux x86_64 Ubuntu 20.04 archive | `919107bb57ec380ec14d4b5e46257338a399510e9b1266c6174cb8e05b7dbfac` |
| Windows x86_64 archive | `1c4638204ba3179591dd4056a32c4ed280eba4c2460605f3e488e5e428996ee1` |
| Windows executable | `d10ff39f873dbfd5ef3c9e184caed031a22fb518b080d577f1d5edf41acc259a` |
| Wintun x64 DLL | `e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce` |

The Windows 10 guest used VMware NAT at `192.168.196.130`, default gateway `192.168.196.2`; its observed public egress was `151.243.38.115`, the same public address observed on the Hong Kong VPS. YunShu remained stopped and its repair task disabled. This is a shared-Hong-Kong-egress topology, not an independent ordinary Windows NAT path. The isolated two-member network used a temporary Coordinator and Relay on Guangzhou.

Windows joined as `117b65c14876f11658f06cba95707d2b` (`10.244.226.2`); Guangzhou used `d4a55fccfa4923621b0748ff4d36a90f` (`10.244.226.1`). ICE nominated the Windows candidate pair, but Windows logged 4 successful and 5 missed initial UDP health probes and rejected the path during its initial health probation. It then connected over authenticated `Relay/TLS`. No controlled packet-loss rule was applied because the direct authenticated baseline did not pass. Guangzhou-to-Windows overlay ping then passed 10/10 over Relay (about 16 ms); Windows status showed the peer online over Relay with 21 sent and 21 received overlay packets. Thus the run verifies fallback and Relay-carried traffic, not a stable direct Windows↔Guangzhou baseline, controlled-loss failover, or direct recovery.

Cleanup revoked both members and released `10.244.226.2` and `.1`. Windows service, cleanup scheduled task, test root and staged files were removed. Guangzhou temporary peer, Coordinator, Relay, timer, credentials, binaries, files and `10.244.226.0/24` route were removed. No task loss rule/table was installed. Windows default route remained via `192.168.196.2`; YunShu remained stopped and its repair task disabled. Guangzhou default route remained via `10.0.20.1`; production Relay PID `17770` remained on TCP `42001`, UDP `42003`, and metrics `42002`. Private evidence remains under `.harness/tasks/complex-6746184f96/evidence/private/` and is not committed.

## Follow-up egress diagnosis (2026-11-27)

At 01:20 UTC, read-only checks from both the Windows guest and its Mac host returned public egress `151.243.38.115`, the same address used by the Hong Kong VPS. The Mac had multiple default routes: `route -n get default` selected `en0` through a private gateway, while the route to `151.243.38.115` selected `utun7`. Panabit iWAN was connected on `utun7`; EasyTier was also running on a separate `utun5`. Windows routed through VMware NAT gateway `192.168.196.2`, and `YunShuService` was stopped. No state was changed during this first check.

In a later bounded route check, Panabit iWAN was stopped. The route to `151.243.38.115` changed from `utun7` to `en0`, but both the Mac and Windows guest continued to report `151.243.38.115` as their public egress. Thus iWAN is not the sole cause of the shared Hong Kong exit; the checks do not identify the upstream forwarding device. Reopening the installed `/Applications/iWAN.app` restored its Connected state and the route through `utun7`; EasyTier remained running throughout. The Windows VM therefore still lacks an independent ordinary NAT egress for direct-path acceptance. A future retest requires a separately confirmed WAN or network segment.

## Retest on main `1d39ee3` (Windows direct probation and fallback)

Date: 2026-11-27 (China Standard Time). Release staging workflow run `45926183517` completed successfully for all Linux, Windows, and macOS build jobs; the publish job was skipped for this branch run. Linux x86_64 and Windows x86_64 staging archive sidecars matched, and `deploy/verify-peer-attestation.sh` verified both Sigstore attestations against `.github/workflows/release.yml`, `refs/heads/main`, and source `1d39ee37329c4f94657bd557434850085f87ce06`. No endpoint built the binaries.

| Artifact | SHA-256 |
| --- | --- |
| Linux x86_64 Ubuntu 20.04 archive | `7f48d95e7ce0446a43c1c9faf53ee2c07e63fb25dd731f5a9676fe87b4ca29aa` |
| Windows x86_64 archive | `b4a131e5bf1820398c7c5a2b986da69cbaf9f944f52e0d2abfe1547b706a5299` |
| Extracted Linux executable | `88d8b2a26c25d8d2e381b32ccecfccf36a06309eaa88ccf3170dcc7fb74585a0` |
| Extracted Windows executable | `93c89f75be2d6174f8117aef24ec3924de6e535e963583f381465c6b83d68887` |
| Wintun 0.14.1 package | `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51` |
| Wintun x64 DLL | `e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce` |

Windows used VMware NAT at `192.168.196.130` via `192.168.196.2`. Its observed public egress remained `151.243.38.115`, the same Hong Kong VPS address recorded in the earlier route diagnosis, so this is not independent-NAT acceptance. `YunShuService` was stopped and its repair task disabled. Guangzhou's default route remained via `10.0.20.1`; the temporary Coordinator and Relay used only test ports and an isolated two-member network. The Guangzhou peer ran in a 20-minute hard-TTL Docker container because non-interactive sudo was unavailable; no production Relay, host firewall policy, or default route was changed.

Windows joined as `15443db4a0ba25906ae5ca1a37521d7c` (`10.244.228.2`) and Guangzhou as `72931a0de9da7c710a359bd166c607ce` (`10.244.228.1`). Windows nominated a direct ICE candidate, but its initial UDP probation recorded 3 successful and 6 missed probes, including one timed-out probe. The peer rejected that path and selected authenticated `Relay/TLS`. Windows-to-Guangzhou overlay ping returned successfully at about 12 ms. At capture, both peer status endpoints reported 7 sent and 7 received overlay packets with zero dropped or rejected packets; Windows status remained online over Relay/TLS at about 14 ms. Guangzhou logs also show that authenticated UDP Relay health probes passed, while the active path remained TLS Relay.

The direct UDP baseline did not pass, so no packet-loss impairment was applied. Later direct recovery checks did not nominate a path and the peers remained on Relay/TLS. This run verifies Windows service installation, overlay data transfer, UDP probation rejection, and reliable Relay fallback under the current shared-egress topology. It does not verify a stable Windows↔Guangzhou direct path, controlled-loss failover, or direct-path recovery; those remain open for a Windows VM on a separately confirmed WAN.

Cleanup revoked both test members and released `10.244.228.2` and `.1`. The Windows service, watchdog task, test root, staged binaries, certificate, and invite token were removed; no test address or route remained. The Guangzhou test container, temporary Coordinator/Relay, credentials, binaries, test route, and listeners were removed. No test firewall rule was installed. Windows default route remained via `192.168.196.2`; `YunShuService` remained stopped. Guangzhou default route remained via `10.0.20.1`; production Relay PID `17770` remained on TCP `42001`, UDP `42003`, and loopback metrics `42002`. Hong Kong's default route was only read and remained via `151.243.38.1`. Private raw peer logs and status snapshots are retained under `.harness/tasks/complex-6746184f96/evidence/private/retest-1d39ee3/` and are not committed.

## Candidate-channel binding check on Windows (`aef3d5b`, 2026-11-27)

Release staging run [45953596363](https://github.com/ilovn/mini-tunnel/actions/runs/45953596363) built the Linux x86_64 Ubuntu 20.04 and Windows x86_64 archives from `aef3d5b75b7e45fd9f3177433a52081d94a163fa`; both SHA-256 sidecars and Sigstore attestations were verified. No endpoint built from source. Windows executable SHA-256 was `eec60349cf8eefe1b0f72fb4155978ec39265311da509b2d57375963791c0a02`; Wintun 0.14.1 x64 DLL SHA-256 was `e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce`.

The Windows 10 VM used VMware NAT (`192.168.196.130`, gateway `192.168.196.2`) with YunShu stopped. It joined a fresh two-member network on a temporary Guangzhou Coordinator and Relay using the exact staged Windows binary. Both peers stayed online on `Relay/QUIC/UDP`. Windows→Guangzhou overlay ping passed 5/5 at 14–16 ms; Guangzhou→Windows passed 5/5 at 17–18 ms, with 0% loss in both directions.

This run did **not** exercise candidate-channel promotion: Windows ICE logged no nominated pair and zero successful candidate pairs (all checked pairs failed); both configured STUN endpoints were also reported silent after retries. The peers therefore retained the Relay path, and the direct promotion handshake was never reached. No firewall impairment or rule change was applied. The run demonstrates Windows membership and overlay traffic over UDP Relay, but provides no field evidence for direct Windows↔Guangzhou promotion or the new channel binding.

Cleanup revoked both members and released `10.244.219.1` and `.2`. Windows peer process/task, Wintun interface, route, status listener, staged program directory, and uploaded invite were absent afterward; its default route remained via `192.168.196.2` and YunShu remained stopped. Guangzhou temporary peer, Coordinator, Relay, listeners, state, keys, and directory were removed; its default route remained via `10.0.20.1`, production Relay PID `17770` retained TCP `42001`, UDP `42003`, and metrics `42002`, and no `10.244.219.0/24` route/address remained. Windows firewall settings were not changed. Private raw logs are retained in `.harness/tasks/bugfix-61423ba497/evidence/windows-aef3d5b/` and are not committed.

## Direct Windows↔Guangzhou ICE, fallback, and recovery (`f0a378c`, 2026-11-27)

- Used Linux x86_64 and Windows x86_64 archives from successful Release staging run [45960969396](https://github.com/ilovn/mini-tunnel/actions/runs/45960969396), exact source `f0a378c85b070a46f19d71878b688810658142ef`. SHA-256 sidecars and Sigstore provenance matched `release.yml`, `refs/heads/main`, and that source. Archive hashes: Linux `3d11102de671ca20ff25110d9b2986f5395816dae0a7cc0751b1b71327bb4bb4`; Windows `17d21111835fe8bbe4b8618c3fdc39aab1e6bc8a067954bfe7a0a9790b33ec08`. Wintun 0.14.1 archive and DLL hashes matched the pinned release. Neither endpoint built from source.
- Windows UDP STUN queries to Guangzhou returned a server-reflexive mapping on `163.125.189.109`; queries to a second IP returned a different mapping, so the sample was classified as varying and is not a NAT-type determination. ICE nominated a direct candidate pair and both peers passed authenticated UDP probation. After an initial short direct-path degradation, recovery passed its 31-second probation and became active `QUIC/UDP` at 08:17:32Z. It stayed direct for about five minutes, with health snapshots around 9–11 ms and no missed probes. Initial overlay ICMP samples passed in both directions: Guangzhou→Windows 5/5 and Windows→Guangzhou 3/3.
- After the stable direct interval, a temporary `iptables-legacy` OUTPUT rule configured 35% random drops only for UDP traffic to the Windows mapped candidate `163.125.189.109:18596`. A one-shot systemd rollback was armed before insertion and removed the rule after 25 seconds; the exact rule was absent afterward. At 08:22:32Z the peer moved from `QUIC/UDP` to authenticated `Relay/TLS` with `transport_failure`. During the impairment, Guangzhou overlay ping passed 90/90, with queuing spikes up to about 815 ms. The kernel rule counter was not captured before the timer expired, so this is a qualitative bounded impairment/fallback observation, not a measured 35% end-to-end packet-loss result.
- After rollback, ICE nominated again, authenticated probation passed, and `QUIC/UDP` was promoted at 08:23:32Z. A post-recovery Guangzhou→Windows overlay sample passed 100/100 (mean 11.354 ms, max 18.048 ms); endpoint status returned to online `QUIC/UDP`, 0% probe loss, and 230 sent/230 received packets with zero dropped or rejected. Windows→Guangzhou pings also replied after recovery.
- Both members were revoked and leases `10.249.7.1` and `.2` released. All task-owned Coordinator, Relay, peer, and STUN services, rollback/cleanup timers, overlay route, listener ports, temporary credentials, and test files were removed. Production Guangzhou Relay PID `17770` remained on TCP `42001`, UDP `42003`, and loopback metrics `42002`; default routes were unchanged. `YunShuService` remained stopped with StartType Automatic as authorized. The test adapter marker `mtun696`, route, scheduled tasks, process, and status listener are absent. The peer log reported its TUN interface as `tun0`, while the wrapper's cleanup marker said `mtun696`; an active Wintun `tun0` had been visible before the run but was no longer an active adapter after peer shutdown (PnP later reported it as `Unknown`). No explicit device-removal command targeted `tun0`, but the peer itself used that name, so this run cannot claim it preserved or safely isolated the prior device. Its owner and lifecycle must be investigated before another Windows run. Default routes and firewall policy were unchanged.
- Private Windows and Guangzhou peer logs are retained under `.harness/tasks/complex-cfc6201d3c/evidence/private/field-f0a378c/windows-vmware-nat-20261127/`; they are not committed. This run confirms this guest can establish direct ICE, carry bidirectional overlay traffic, fall back to Relay under bounded UDP impairment, and recover to direct UDP. It does not establish the full NAT/QoS matrix or quantitatively confirm the configured impairment rate.

## Windows adapter-name fix retest (`5c6c0ff`, 2026-11-27)

Release staging run [45969011024](https://github.com/ilovn/mini-tunnel/actions/runs/45969011024) built the Windows x86_64 and Linux x86_64 artifacts from exact `main` source `5c6c0ff51defcc08359dc3cb14c3ce2da2473b62`. Archive checksums and Sigstore attestations passed for repository `ilovn/mini-tunnel`, `refs/heads/main`, and that source commit. No endpoint built from source.

| Artifact | SHA-256 |
| --- | --- |
| Windows x86_64 archive | `4d2ac95a1547f82289820ae2b0110ef24aef4124b83d418a797265b7db0c3e65` |
| Windows x86_64 executable | `241c4843b82e77529f84edb9d0d83b905135da53c65d14b5b2110de2ffd5f9f7` |
| Linux x86_64 archive | `c7f16786ffa55cd94e85e577c2fb4e0ee4a125cfc0212ad1d5814728309ced2a` |
| Linux x86_64 executable | `0a79853035cc842de72dcbf28fdd975b3fab8355efed9112b7657d9c345ecd56` |

The isolated network used the temporary Guangzhou Coordinator/Relay and STUN listeners in Guangzhou/Hong Kong. Both peers joined successfully; three STUN servers answered and Windows logged `Mesh established on TUN interface mtun8500`. This verifies the new binary uses the per-process `mtun<PID>` adapter namespace and no longer selects the previously ambiguous `tun0` name. The prior Windows active-adapter list had no `mtun*` device; post-cleanup it again had no `mtun*` device.

The data plane did **not** pass this retest. Both ICE agents sent checks but reported zero received requests/responses and no nominated pair. Logs showed repeated `ICE checks timed out` and transport fallback attempts, but no successful Relay path or overlay ping result was captured. Therefore this run verifies the adapter-name fix and Windows process startup only; it does not verify Windows↔Guangzhou direct ICE, Relay fallback, or bidirectional tunnel traffic. The cause of ICE/Relay non-connectivity remains open and must be isolated in a follow-up before claiming Windows validation complete.

Both temporary members were revoked and both leases released. Windows peer/task, `mtun8500` interface, test route, and test directory were removed. Windows default route remained Ethernet0 via `192.168.196.2`; `YunShuService` remained stopped with Automatic start type, as requested for testing. Guangzhou/Hong Kong test services, listeners, systemd units, and temporary credentials were removed; Guangzhou production Relay PID `17770` remained on TCP `42001`, UDP `42003`, and loopback metrics `42002`. Private logs and CI artifacts remain only under `.harness/tasks/complex-cfc6201d3c/evidence/private/field-5c6c0ff/` and are not committed.

## ICE startup timing diagnosis and fix in progress (2026-11-27)

The captured sequence shows Windows began connectivity checks at `09:09:27Z`. Guangzhou's peer process refreshed membership at `09:09:25Z`, before the Windows join completed, then did not discover the new member until the next 30-second refresh at `09:09:55Z`. That was later than Windows' initial set of four five-second ICE checklists. Guangzhou started its own checks only after discovery, so the two check windows did not overlap. This is a concrete startup timing race consistent with both peers reporting zero accepted checks; it is not proven to be the only cause. The same Guangzhou connection-failure log records direct candidate timeout, UDP Relay deadline, and TCP Relay unexpected EOF, which remain to be isolated if they persist after ICE starts in sync.

The code changed mesh membership/candidate polling to a five-second interval, bounds each request at eight seconds, and adds a regression assertion that the worst-case bounded discovery duration remains shorter than the initial ICE retry window. The follow-up exact-main field verification is below.

## ICE startup timing fix field verification (`716f906`, 2026-11-27)

Release staging run [45973939104](https://github.com/ilovn/mini-tunnel/actions/runs/45973939104) produced Linux x86_64 Ubuntu 20.04 and Windows x86_64 artifacts from exact source `716f906df931d4d94e0251508a6563a299ea42ee`. Archive SHA-256 sidecars and Sigstore attestations passed verification for `ilovn/mini-tunnel`, `.github/workflows/release.yml`, `refs/heads/main`, and the exact source commit. Neither endpoint compiled source.

| Artifact | SHA-256 |
| --- | --- |
| Linux x86_64 Ubuntu 20.04 archive | `c7f16786ffa55cd94e85e577c2fb4e0ee4a125cfc0212ad1d5814728309ced2a` |
| Linux x86_64 executable | `4e1682559a2f693f3e71eb25e0389e0655727f0fcdf66447aabca87c65fa43bb` |
| Windows x86_64 archive | verified by its CI checksum sidecar and Sigstore attestation |
| Windows x86_64 executable | `b851112ae099ce1c22b221874b0a581b2aa2def912f0dd12427d2845749c6d45` |
| Wintun x64 DLL | `e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce` |

Windows used VMware NAT at `192.168.196.130` via `192.168.196.2`. `YunShuService` was Stopped / Automatic. The isolated network was `7ab54e33-6291-4d91-9e3a-4901ca9cb251`, overlay `10.249.9.0/24`; Guangzhou used `.1` and Windows `.2`. Guangzhou started first, and discovered the Windows member at its next five-second mesh refresh, within about one second of the Windows join. Both sides then nominated direct ICE candidates. Windows logged 9 delivered/accepted ICE STUN datagrams and `nominated=true`; Guangzhou also logged a nominated pair. This is field confirmation that the previous 30-second membership discovery race is narrowed on this run.

The first authenticated direct QUIC health probe timed out on Windows. The peers fell back to authenticated `Relay/TLS`; both remained online, and Guangzhou's Relay counters showed the paired TCP session forwarding traffic. Direct recovery later succeeded. Before applying impairment, the active path had promoted to `QUIC/UDP`, with both status endpoints reporting 0% loss and zero drops/rejections. A task-specific OUTPUT rule configured 35% random drops only for UDP from Guangzhou's test source to Windows' mapped candidate `163.125.189.109:19034`. A systemd one-shot rollback was armed before insertion and removed the exact rule after 25 seconds; its counter showed 21 matching dropped packets. During impairment, concurrent overlay pings passed 16/16 in both directions while Guangzhou switched from `QUIC/UDP` to `Relay/TLS`. After rollback, Guangzhou selected `Relay/QUIC/UDP`, then recovered direct `QUIC/UDP` with `healthy_direct_probe` as the reason.

At final observation both status endpoints were online on direct QUIC/UDP, at 9–10 ms reported RTT, 0% probe loss, and zero dropped or rejected packets. Guangzhou→Windows post-recovery overlay ping passed 10/10 (mean 11.660 ms, max 12.165 ms). The Windows→Guangzhou post-recovery ping command was cut off by the SSH session after seven successful replies; a complete post-recovery sample in that direction is not claimed. Its concurrent impairment sample had passed 16/16. The configured 35% random probability is not a measured end-to-end loss rate; only the exact rule's 21 packet matches were captured.

Both members were revoked and leases `10.249.9.1` and `.2` released. The Windows cleanup task removed its peer process, `mtun` adapter, route, scheduled tasks and test directory. Its default route remained Ethernet0→`192.168.196.2`; `YunShuService` remained Stopped / Automatic. Guangzhou task files, Coordinator/Relay/peer/STUN services, units and listeners were removed. Its default route remained via `10.0.20.1`; production Relay PID `17770` remained on TCP `42001`, UDP `42003`, and loopback metrics `42002`. The loss rule was absent after rollback. Private evidence is retained under `.harness/tasks/complex-cfc6201d3c/evidence/private/field-716f906/` and is not committed.

This run verifies Windows membership discovery, direct UDP promotion, relay fallback under bounded UDP impairment, recovery to direct UDP, and traffic continuity on this VMware/shared-egress topology. It does not provide an independent Windows NAT sample, a measured 35% packet-loss result, a complete post-recovery Windows→Guangzhou ping sample, or completion of the broader NAT/QoS interoperability matrix.
