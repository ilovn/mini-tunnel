# Windows current-main field check over existing private overlay (`7801be8`)

Date: 2026-11-28 (China Standard Time)

## Artifacts

- Release staging run [46044205395](https://github.com/ilovn/mini-tunnel/actions/runs/46044205395) built the Linux x86_64 and Windows x86_64 archives from exact main source `7801be85443118c302f141bb84c16d6780113719`. The run did not publish a release.
- Both archive SHA-256 sidecars matched. Linux archive: `fafa1aef448ef0d9650895f52f81989b9417bcefcc195adcf91a67897945c4dd`; Windows archive: `0466b426d743aa4ca9562ee0ee3498d060957c88afa7f65644f309ad43c37c24`.
- GitHub Sigstore provenance verification passed for both archives against `ilovn/mini-tunnel`, `.github/workflows/release.yml`, `refs/heads/main`, and the exact source SHA. The Linux and Windows endpoints used these prebuilt artifacts and did not compile source.
- Extracted Windows executable SHA-256: `b87afeb0c0cb37a240b7d6096a75c08c3e5bc8b70f618a6aa7943998157921c6`. Wintun 0.14.1 archive SHA-256: `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`; deployed x64 DLL SHA-256: `e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce`.

## Topology and observations

- The Windows 10 x64 VM used VMware NAT (`192.168.196.130`, default gateway `192.168.196.2`). `YunShuService` was already `Stopped / Automatic`; this run did not change its configuration.
- A temporary Coordinator and Relay ran on Guangzhou with a new two-member network. The Windows peer joined using the attested x64 executable and Wintun. ICE nominated a QUIC/UDP path; Windows channel 1 closed with `peer_application_close`, application code `1297350657`, and remote reason `peer channel closed`. Windows subsequently nominated another direct candidate; channel 4 passed authenticated health probation. Both final status endpoints reported `QUIC/UDP`, `healthy_direct_probe`, 0% probe loss, zero drops/rejections, and 75 packets sent/received. Final reported RTT was 13 ms on both peers.
- Overlay ICMP passed Guangzhou→Windows 20/20 (0% loss; mean 16.163 ms) and Windows→Guangzhou 10/10 (0% loss; mean 11 ms). No firewall or QoS impairment was applied.
- This was **not an independent public NAT sample**. Both ICE candidates were in `10.126.126.0/24`; Guangzhou's read-only route lookup showed traffic to the Windows candidate using its pre-existing `tun0` route. That interface, along with the other pre-existing tunnel interfaces, was left untouched. The run confirms Windows enrollment, Wintun packet exchange, direct QUIC/UDP selection, probation, and the new close diagnostic on this private overlay path. It does not establish direct reachability across the public Internet, TCP Relay fallback, or behavior after removing the host-side VPN/overlay route.

## Cleanup and host-state check

- The temporary Coordinator network was deleted; the API removed two members and invalidated three invitations. The pre-armed Windows SYSTEM rollback task stopped the peer and removed its Wintun interface, overlay address/route, scheduled tasks, ProgramData state, and staged files. Follow-up checks found no test process, test route, Wintun adapter, test directory, or test task. The Windows default route remained `Ethernet0 → 192.168.196.2`; `YunShuService` remained `Stopped`.
- The Guangzhou cleanup script was run under the pre-armed systemd timer; after cleanup, the timer was stopped and verified inactive. All temporary processes, files, ports, and routes were removed. Guangzhou's default route remained via `10.0.20.1`; production Coordinator PID `5656` and Relay PID `17770` remained running with TCP `42001`, UDP `42003`, and loopback metrics `42002` intact. Existing `tun0`, `tun1`, and `iwan0` were not changed.
- Raw logs and status snapshots remain only in the ignored private Harness evidence directory. Test certificates, private keys, ticket keys, and invitation tokens were removed from both endpoints and local test state.
