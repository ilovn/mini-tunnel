# Domestic NAT direct fallback and recovery (2026-11-28)

## Result

The exact-main Linux x86_64 artifact from source `91fe96a010ec6a3608b5a1e7c8a3cb08bd052f0f` completed a controlled `QUIC/UDP` → authenticated `Relay/TLS` → `QUIC/UDP` cycle between the Guangzhou VPS and the domestic NAT VPS. The artifact was staged from the attested release run [46075694945](https://github.com/ilovn/mini-tunnel/actions/runs/46075694945); endpoints did not build from source.

This was a nested-underlay validation. Both VPSes had the existing 12-hour soak tunnel active, and the test peer candidate selected through that overlay (`10.252.45.1:44945` from the NAT peer). The result verifies path switching and recovery while carried over that existing underlay; it is not evidence of independent public-NAT traversal.

## Procedure and observations

- Created a fresh overlay (`10.249.90.0/24`) with isolated Coordinator, TCP Relay, peer state, and ports. Relay UDP was bound to loopback and no UDP Relay endpoint was configured.
- Armed 30-minute task-specific cleanup timers on both hosts before peer TUN setup. Used the existing prebuilt binary only.
- Baseline: both peers reported online `QUIC/UDP`. Overlay ping passed 20/20 in both directions (0% loss; averages 10.93 ms and 10.66 ms).
- Impairment: installed one NAT `OUTPUT` drop rule matching only destination `10.252.45.1`, UDP source port `44945`, and destination port `44945`. Its counter reached 8 packets. The production soak's UDP port `44445` and its routes/services were untouched.
- Fallback: both peers reported online `Relay/TLS`; `last_switch_reason` on Guangzhou was `quality_threshold`. Bidirectional overlay ping passed 20/20 each (0% loss; averages 10.95 ms and 10.87 ms).
- Relay metrics while on fallback: 2 accepted TCP connections, 1 active session, 32,088 forwarded bytes; handshake failures, pairing rejections, and handshake timeouts all 0. UDP Relay active sessions and forwarded datagrams both remained 0.
- Recovery: deleted the exact test nftables table and verified it absent. Both peers returned to online `QUIC/UDP` with `healthy_direct_probe`. A further 20/20 pings each direction passed (0% loss; averages 10.94 ms and 10.99 ms). Relay metrics drained to 0 active connections/sessions; cumulative forwarded bytes reached 34,992.
- Revoked both temporary network members and removed test peers, Coordinator, Relay, routes, files, listeners, and nftables state. Both pre-existing soak cleanup timers remained active; GZ and NAT soak peers remained running, and the original `10.252.45.0/24` routes remained present.

## Limits

This is one controlled sample using the exact-main Linux artifact on this nested domestic topology. It does not measure an independent NAT path, establish a general recovery-time SLA, or complete the broader NAT/QoS matrix. The public matrix remains incomplete.

Private raw metrics and process logs were retained only in the ignored Harness evidence directory for task `complex-7f99d3bdb8`; credentials and raw identifiers are not part of this report.
