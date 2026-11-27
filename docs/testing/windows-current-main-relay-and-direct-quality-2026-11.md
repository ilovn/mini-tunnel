# Windows current-main UDP and Relay path validation

Date: 2026-11-28 (China Standard Time)
Source: `37745e42f815e0e6c6f2a128463a2f25a67ac29f`
Release staging: [run 46025278542](https://github.com/ilovn/mini-tunnel/actions/runs/46025278542)

## Artifact and topology

The Windows x86_64 archive checksum and GitHub Sigstore provenance passed verification for `ilovn/mini-tunnel`, `.github/workflows/release.yml`, `refs/heads/main`, and the exact source SHA above. The release staging workflow completed all Linux and desktop builds; the GitHub Release publish job was skipped. The Windows endpoint used the staged artifact, with no endpoint build. Official Wintun 0.14.1 was pinned and verified by SHA-256.

| Artifact | SHA-256 |
| --- | --- |
| Windows x86_64 archive | `2bee1cdda6843139239908577a6ec89f9f2f67f36cb256402e4da69e9392d2ef` |
| Extracted `mini-tunnel.exe` | `4af4b28651040cb449ead7628833a0826f582fa4a28c89c1150455fc801b5361` |
| Official Wintun 0.14.1 archive | `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51` |
| Wintun x64 DLL | `e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce` |

The isolated overlay connected the Windows 10 VMware NAT guest (`10.251.100.2`) to a temporary Guangzhou peer (`10.251.100.1`) through a TLS Coordinator and authenticated TCP Relay. Windows was bound to its Ethernet0 address, and Guangzhou to its physical interface. The Windows public egress matched the Hong Kong VPS egress observed in earlier diagnostics; this is a shared-egress topology, not an independent Windows NAT sample. Before testing, `YunShuService` was already Stopped/Automatic and its repair task Disabled. Neither was changed.

## Results

Two path modes were observed:

- With experimental ICE enabled, both sides nominated a direct UDP candidate. The elected QUIC channel then closed with `peer path not selected`; its first reliable fallback attempt ended with EOF. A subsequent authenticated `Relay/TLS` connection became active. Later direct recovery attempts timed out or failed RTT probation while Relay stayed online.
- With ICE disabled, standard UDP candidate dialing briefly established a `QUIC/UDP` path. The link then moved to `Relay/TLS` after natural transport/quality degradation. The path status on the Windows side recorded `quality_threshold`; Guangzhou recorded a transport failure. The direct path did not remain healthy long enough to provide a direct overlay ping baseline.

On the stable `Relay/TLS` path, Guangzhou→Windows and Windows→Guangzhou overlay ping each passed 20/20 with 0% packet loss. The measured averages were 15.4 ms and 12 ms respectively. Both peer statuses reported online, about 13 ms probe RTT, 0% probe loss, and zero dropped or rejected packets.

No UDP firewall impairment was applied because a stable direct baseline was not established. This run verifies current-main Windows Relay fallback and bidirectional traffic continuity, but not direct-path quality, direct recovery, or controlled-loss recovery. The shared Hong Kong egress may affect candidate reachability or quality; this run does not isolate the exact cause, so it makes no general claim about Windows NAT interoperability.

## Cleanup

The temporary network was deleted; the Coordinator confirmed removal of both members and invalidation of both invitations. Bounded Windows peer/rollback tasks, the peer process, Wintun adapter, overlay route, uploaded files and test directory were removed. Guangzhou temporary peer, Coordinator, Relay, routes, listeners and files were removed. Windows Ethernet0 default route remained via `192.168.196.2`; YunShu remained Stopped and its repair task remained Disabled. Guangzhou default route remained via `10.0.20.1`; production Coordinator PID `5656` and Relay PID `17770` remained running with their original ports.

Private raw candidate snapshots, logs, statuses and ping output remain under the ignored Harness evidence directory. Temporary CA/signing keys and network admin/invite tokens were deleted after cleanup.

## ICE close diagnosis

Follow-up review on 2026-11-28 compared the private peer logs with the ICE election and consent-monitor transfer code. The Windows peer ID sorts before the Guangzhou peer ID, so Windows owns the elected outbound session. Both peers logged a nominated candidate. Guangzhou logged the elected path entering health probation at 15:59:15.143 and then received `peer path not selected` about 330 ms later; Windows had already ended up on Relay/TLS.

In the tested build, the same close reason was used both for intentionally discarding a losing duplicate path and for generic channel cleanup. Field logs also lacked per-connection IDs on close, so the remote address alone cannot establish whether the closed QUIC session was the elected data channel or the reverse probe. This run therefore does not prove a deterministic election/monitor-transfer race or identify the exact closer-side decision.

The existing two-peer mesh ICE integration test, `mesh_ice_routes_two_peer_sessions_and_transfers_over_both_quic_channels`, passed once and then passed five consecutive repetitions (one test executed per repetition; each exercised two elected peer sessions, monitor transfer, and authenticated health probation). This did not reproduce the field close. The code path has no confirmed defect from this evidence; reproducing the close will require connection-instance/election tracing or a network topology that independently reproduces it. The Windows public egress matched the Hong Kong Relay egress, so the field run remains topology-specific and does not isolate independent NAT behavior.

The follow-up diagnostics change assigns each local authenticated peer channel a unique process-local ID and records it in acceptance, election, probation, local close, and remote QUIC close logs. Close reasons now distinguish normal shutdown, duplicate-path cleanup, probation failure, and deterministic election loss. The next field run must use the new artifact to determine which per-peer channel instance closed; this change improves diagnosis and does not alter path selection.
