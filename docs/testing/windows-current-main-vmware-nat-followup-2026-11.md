# Windows current-main VMware NAT follow-up (`6e25b22`)

Date: 2026-11-28 (China Standard Time)

Source: `6e25b22cfdd75f187f88e87b8b998e84275935cd`

Release staging: [run 46050575089](https://github.com/ilovn/mini-tunnel/actions/runs/46050575089)

## Artifact and topology

- The Windows x86_64 staging archive passed its SHA-256 sidecar and `deploy/verify-peer-attestation.sh` checks for `ilovn/mini-tunnel`, `.github/workflows/release.yml`, `refs/heads/main`, and the exact source SHA above. The release workflow completed successfully; its publish job was skipped for `main`. The VM did not build source.
- Windows archive SHA-256: `9b1c0b7c894671fd21a4569a1591d679818c4382f07afccd31bdaa1fec2def7b`.
- Extracted `mini-tunnel.exe` SHA-256: `d079be4be7fc1b6800b69af55be670554262f01ad50b667e79477b133473c9dd`.
- The official Wintun 0.14.1 archive matched the pinned SHA-256 `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`; the x64 DLL SHA-256 was `e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce`.
- The Windows 10 x64 VM used VMware NAT (`192.168.196.130`, gateway `192.168.196.2`). `YunShuService` was stopped before the test and remained stopped. A separate, temporary Coordinator, Relay, and two-member overlay ran on Guangzhou so the active domestic Linux soak was not joined to the Windows network.

## Results

- On the initial unfiltered run, both peers selected `QUIC/UDP`, reported 0% peer-health probe loss, and had a 12 ms reported RTT. Overlay ICMP passed Guangzhou→Windows 20/20 (mean 13.689 ms) and Windows→Guangzhou 20/20 (mean 14.2 ms).
- The nominated ICE candidates were RFC1918 addresses in `10.0.0.0/8`. Guangzhou's route lookup for the Windows candidate used its pre-existing `tun0`. This direct path therefore traversed an existing private overlay; it is **not** an independent public NAT result. The existing interface was not modified.
- With the path on authenticated `Relay/TLS`, a later stable sample passed 10/10 overlay pings in each direction. Guangzhou Relay metrics showed one active session and zero handshake failures. An earlier sample during the forced path transition dropped 6/20 Guangzhou→Windows and 16/20 Windows→Guangzhou packets; after restarting the peers and allowing the Relay path to settle, both 10-packet samples passed. Treat the transient loss as a path-transition issue requiring follow-up, not as a clean zero-loss fallback result.
- An app-scoped RFC1918 candidate restriction did not establish a public direct candidate: later ICE logs still showed private nominated candidates. No public direct-path claim is made from this VM topology.

## Cleanup

The temporary Coordinator network removed both members and invalidated both invitations. Windows test processes, firewall rules, tasks, route, Wintun adapter, and test directory were removed. `YunShuService` remained stopped and the default route remained `Ethernet0 → 192.168.196.2`. Guangzhou's test units, ports, files, and route were removed; its default route still used `eth0`, and production Coordinator/Relay PIDs `5656`/`17770` remained. The independent Linux domestic NAT soak and its cleanup timers remained active.

Raw logs and credentials remain only in the ignored, private Harness evidence directory. No private tokens, candidate addresses, or test credentials are included in this report.
