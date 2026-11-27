# Windows ICE channel diagnostics (`0e1eebe`, 2026-11-28)

## Setup

- Tested the exact-main Windows x86_64 staging artifact from [run 46035111008](https://github.com/ilovn/mini-tunnel/actions/runs/46035111008), built from `0e1eebe517b81cc701afb38f2418e766d267e8d5`. The ZIP SHA-256 was `92bf9cc0a3c72bbcc70d83075f9ccedd2604a7d4a5022d70268e1061b5cbe67d`; its Sigstore provenance was verified against the repository, workflow, ref, and source commit. The Linux x86_64 endpoint used the same run's Ubuntu 20.04 artifact, also checksum- and provenance-verified.
- Windows 10 ran behind VMware NAT with `YunShuService` stopped. The VM's observed egress is shared with the Hong Kong VPS, so this is a shared-egress NAT topology rather than an independent Windows NAT sample.
- Used a temporary Coordinator and Relay on Guangzhou and an isolated two-member network. No production Coordinator/Relay, default route, Windows default route, firewall, or YunShu repair task was changed. An automatic cleanup timer and Windows SYSTEM rollback tasks were armed before starting the peer.

## Observations

- Initial ICE checks timed out repeatedly. The Windows peer elected `Relay/TLS` as `channel_id=2`; both endpoints joined and the relay path carried overlay packets. The first 20-packet ping in each direction passed with 0% loss (40 overlay packets total).
- Later ICE checks nominated a direct QUIC/UDP candidate. The Windows log records the candidate channel as `channel_id=3`, authenticated initial health probes passing, then health probation completing after 31 seconds. The Guangzhou log independently records channel 3 entering and passing the same probation. Both status endpoints subsequently reported `QUIC/UDP`, 40 packets sent and received, and zero loss/drop/reject counters.
- The Guangzhou log also records an earlier `channel_id=1` QUIC receive failure (`peer_application_close`, code 0) followed by reconnect. This field run did not attribute that peer close to a specific local close reason. The new channel ID made subsequent candidate probation and elected Relay path events traceable.
- The path recovered naturally while the test was running; no firewall or QoS impairment was applied. Therefore this run verifies startup Relay fallback, later direct ICE recovery, and bidirectional overlay traffic, but does not verify path degradation under controlled loss/QoS or a mid-session firewall change.

## Cleanup and host-state check

- Deleted the temporary Coordinator network, revoked its two members and invitations, stopped the Windows peer through the pre-armed SYSTEM rollback task, removed the Windows peer/rollback tasks and test directory, and removed the GZ test peer, Relay, Coordinator, route, files, and cleanup timer.
- Windows `YunShuService` remained Stopped / Automatic; its repair task remained disabled. Windows default route remained `Ethernet0 → 192.168.196.2`; no test overlay route remained.
- Guangzhou default route remained via `10.0.20.1`. Production Coordinator PID `5656` and Relay PID `17770` remained running; production Relay continued listening on TCP `42001` and UDP `42003`.

Raw endpoint logs and command outputs are retained in the local ignored Harness evidence directory for this task and are not committed.
