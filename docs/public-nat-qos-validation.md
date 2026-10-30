# Public NAT and QoS interoperability validation

Status: **not yet executed**. The loopback ICE mapping proxy verifies packet rewriting and session behavior, but it does not establish interoperability across public NATs. Do not mark this matrix complete until the evidence below is collected from two independent, real client networks.

## Prerequisites

- Two Linux devices, A and B, each behind a different physical NAT and public egress address. A cloud VM pair on the same virtual network does not count as two independent NATs.
- A reachable Coordinator over HTTPS, a reachable RFC 8489 STUN service, and a reachable Relay when testing relay recovery. Use an isolated test network and short lived enrollment credentials.
- Both client builds use the same protocol revision. Install `iproute2`, `ping`, `tcpdump`, and `tc` on Linux clients. Tunnel startup requires permission to create TUN interfaces and install routes.
- Record the client OS/kernel, mini-tunnel commit, Coordinator/STUN/Relay versions, NAT/router model and firmware, ISP/access type, public IPv4/IPv6 addresses (redacted in shared reports), and UTC test interval. Do not record admin, invite, ICE password, or private-key values.
- Preserve access to each router/firewall for packet capture and targeted UDP impairment. Keep Coordinator HTTPS and Relay TCP reachable while impairing peer UDP.

Create the network and enroll both devices using the [Quick start](../README.md#quick-start). Confirm each device appears in the same signed peer snapshot before testing.

## Start the two peers

On both clients, set the Coordinator URL and start a mesh with ICE, STUN, route management, and the deployed Relay endpoint. Use real numeric STUN and Relay addresses because the CLI accepts `SocketAddr` values for both.

```sh
export MINI_TUNNEL_COORDINATOR_URL='https://coordinator.example:8443'
export MINI_TUNNEL_RELAY_SERVER='<relay-ip>:443'
RUST_LOG=mini_tunnel_agent=debug \
  mini-tunnel peer tunnel mesh \
    --network-id '<network-id>' \
    --bind '0.0.0.0:42000' \
    --stun-server '<stun-ip>:3478' \
    --manage-route \
    --ice
```

If direct TCP listener testing is part of the environment, add `--tcp-bind '0.0.0.0:443' --candidate 'tcp://<public-ip>:443'` on both peers and configure each router's TCP port forward. Do not publish an unreachable private listener address as public. Wait until both peers report the authenticated mesh peer and record the selected transport from structured logs. Send a continuous overlay probe between the assigned overlay IPs (for Linux, `ping -D -i 0.2 <peer-overlay-ip>`). Preserve the log and packet captures for each phase.

## Matrix

Run each topology from a clean peer start, then repeat with A and B roles reversed. Record the observed UDP mapping from STUN and the network's firewall policy; do not infer a NAT type from router marketing labels.

| Case | Network setup | Expected result |
|---|---|---|
| Open/reachable UDP | At least one peer has a reachable UDP mapping or explicit port forward | Authenticated direct QUIC/UDP; overlay probe succeeds; Coordinator and Relay carry no peer payload |
| One-sided endpoint-independent mapping | One client behind a NAT that reuses its UDP mapping across destinations, other client reachable or similarly permissive | ICE nominates a direct pair and overlay traffic continues over UDP |
| Address-dependent mapping/filter | Both clients behind NATs that restrict a mapping/filter by remote IP | Record whether ICE succeeds directly; otherwise authenticated TCP/Relay recovery succeeds within configured attempt bounds |
| Address-and-port-dependent mapping/filter | Both clients behind restrictive NATs whose mappings/filtering depend on remote address and port | Do not require direct UDP; verify bounded recovery to TCP or Relay and continued overlay reachability |
| Symmetric/restrictive NAT | At least one endpoint has destination-dependent mappings and no inbound UDP mapping | Direct UDP may fail; require safe fallback to an authorized TCP/Relay path, with no unauthenticated TUN packet accepted |
| UDP blocked after connection | Block only peer UDP at one router after direct path is established; preserve HTTPS and Relay TCP | ICE/QUIC path fails closed, the session recovers over TCP/Relay, and overlay probes resume without restarting the mesh process |
| NAT rebinding | Change the client uplink or force its UDP mapping to expire while the process remains alive | Old path is abandoned; a newly authenticated path is selected or authorized fallback is used; stale candidates do not receive overlay payload |

For NAT behavior, capture the same bound UDP socket's STUN mapping against at least two independently operated STUN destinations where available. Use the router mapping/filter observations and packet captures as evidence. This remains an observed network behavior, not a guaranteed portable label.

## QoS cases

Apply impairment to the peer UDP path only. A dedicated test router or network emulator is preferred. If `tc netem` is used, isolate its qdisc to the peer UDP interface/flow and verify Coordinator HTTPS and Relay TCP remain reachable. Save the original qdisc and restore it after every case.

On a dedicated Linux router egress interface that carries peer UDP but not Coordinator/Relay control traffic, the profiles can be applied with `tc netem`:

```sh
sudo tc qdisc replace dev "$PEER_EGRESS_IFACE" root netem delay 80ms 20ms loss 2%
# Replace the profile for the next case, for example:
sudo tc qdisc replace dev "$PEER_EGRESS_IFACE" root netem delay 200ms 30ms loss 10%
# Remove the impairment during recovery and during cleanup:
sudo tc qdisc del dev "$PEER_EGRESS_IFACE" root
```

Do not apply these root qdiscs to a shared client interface carrying the Coordinator or Relay connection; that would confound the peer-path result.

| Profile | Impairment | Expected result |
|---|---|---|
| Baseline | No added loss/delay | Direct UDP remains selected; record RTT, loss, throughput, and overlay probe loss for at least 5 minutes |
| Mild | 80 ms added RTT, 20 ms jitter, 2% random UDP loss | Hysteresis prevents one-window flapping; report quality and selected path |
| Degraded | 200 ms added RTT, 30 ms jitter, 10% random UDP loss | Once configured bad windows are reached, move to TCP/Relay and keep overlay connectivity |
| Reordering | 50 ms delay with 5% packet reordering and 2% loss | Session remains authenticated; record packet loss, recovery time, and path changes |
| Recovery | Remove impairment after reliable fallback | Direct UDP is reprobed and promoted only after successful authenticated checks and the configured healthy period |

The current quality thresholds and hold-down values are implementation defaults; this runbook measures behavior and does not redefine them. TCP can perform worse under congestion and is not itself a congestion remedy. Record results rather than treating a path switch as proof of improved throughput.

## Pass/fail and evidence

A case passes when its expected path behavior occurs, overlay probes reach the intended peer, packet source/destination validation remains enforced, and the selected transport is visible in logs. For fallback cases, record impairment start, fallback start, first successful reliable probe, and any data loss window. A test fails if the process accepts an unauthenticated peer, writes a packet from the wrong overlay source, loops between paths without respecting hysteresis, or leaves peer routes after clean shutdown.

For every case, save a sanitized report row with: case ID, client network/NAT description, mapping observations, selected path sequence, start/end UTC, p50/p95 RTT, sent/received/lost probes, traffic throughput, reconnect count, fallback/recovery time, route cleanup result, and links or hashes for logs/pcaps. Redact public IPs and all credentials before sharing.

After each phase, stop both clients cleanly, verify their peer routes are gone, remove any test `tc` rules, and revoke/delete the temporary network and enrollment credentials. A `SIGKILL` may bypass route cleanup; inspect and remove only the test peer host routes if that occurs.

## Current evidence

- Linux, macOS, Windows, and PostgreSQL CI passed in [run 41115115196](https://github.com/ilovn/mini-tunnel/actions/runs/41115115196). It includes privileged Linux TUN lifecycle checks and all platform workspace gates.
- [Linux CI run 41112768590](https://github.com/ilovn/mini-tunnel/actions/runs/41112768590) placed each QUIC peer in a separate network namespace joined by a veth pair. It verified authenticated probe loss and recovery, delivery of a 9000-byte overlay packet after lowering both veth MTUs to 1280, and mesh fallback to authenticated TCP after UDP egress loss. This is controlled virtual-link evidence, not public NAT interoperability.
- [Linux CI run 41122764687](https://github.com/ilovn/mini-tunnel/actions/runs/41122764687) placed a STUN client and server on opposite sides of an isolated Linux MASQUERADE router. The client received the translated source address as its server-reflexive candidate while retaining the original bound UDP socket. This verifies one controlled SNAT mapping only; it does not test two independent NATs, public STUN services, or direct peer connectivity.
- [Linux CI run 41125932610](https://github.com/ilovn/mini-tunnel/actions/runs/41125932610) extended that isolated topology with a public peer. The peers completed authenticated ICE checks through the stateful MASQUERADE mapping and exchanged an overlay UDP payload on the nominated path. This is one-sided controlled NAT evidence; it does not establish simultaneous hole punching through two independent NATs or public NAT interoperability.
- The privileged Linux STUN/SNAT CI test now also creates two client namespaces behind separate Linux MASQUERADE routers on an isolated transit bridge. On a green run, its dual-SNAT phase provides repeatable controlled evidence that both peers can nominate and exchange an overlay UDP payload through independent endpoint-independent mappings. It does not model symmetric NAT, CGNAT, commercial firewalls, or public Internet policy; it does not complete the public matrix.
- [Linux CI run 41115115196](https://github.com/ilovn/mini-tunnel/actions/runs/41115115196) also verified promotion from TLS/TCP to an authenticated direct QUIC/UDP candidate over the isolated veth pair, followed by overlay packet delivery on the promoted path.
- Earlier veth runs before commit `6cfdc66` configured both veth addresses in one network namespace, so Linux routed peer traffic over loopback. Those runs are not evidence of veth packet loss or constrained-veth behavior and are superseded by the isolated-namespace runs above.
- ICE loopback mapping, same-socket checks, pinned QUIC, mesh, restart, consent-loss, and TCP fallback are covered by workspace tests.
- No case in the public NAT or QoS matrix above has been executed. Public ICE interoperability remains unverified until a sanitized report is attached to this runbook or a linked test artifact.
