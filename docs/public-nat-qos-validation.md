# Public NAT and QoS interoperability validation

Status: **public NAT/QoS matrix incomplete**. The loopback ICE mapping proxy verifies packet rewriting and session behavior, but it does not establish interoperability across public NATs. The VPS smoke test and the RouterOS/office fallback observation below are additional runtime evidence; neither completes a matrix case.

## Preliminary single-client observation (not matrix evidence)

On 2026-11-01, one UDP socket on the development host sent STUN Binding requests to `stun.l.google.com:19302` and `global.stun.twilio.com:3478`. Both returned valid responses with the same XOR-MAPPED IPv4 address and port. The mapped endpoint is intentionally omitted. This only records the mapping seen by one client for those two STUN destinations at that time; it does not classify the NAT, establish behavior toward a peer destination, or prove ICE/direct tunnel connectivity. It does not satisfy any matrix case above, and the matrix remains unexecuted.

## Prerequisites

- Two Linux devices, A and B, each behind a different physical NAT and public egress address. A cloud VM pair on the same virtual network does not count as two independent NATs.
- A reachable Coordinator over HTTPS, a reachable RFC 8489 STUN service, and a reachable Relay when testing relay recovery. Use an isolated test network and short lived enrollment credentials.
- Both client builds use the same protocol revision. Install `iproute2`, `ping`, `tcpdump`, and `tc` on Linux clients. Tunnel startup requires permission to create TUN interfaces and install routes.
- Record the client OS/kernel, mini-tunnel commit, Coordinator/STUN/Relay versions, NAT/router model and firmware, ISP/access type, public IPv4/IPv6 addresses (redacted in shared reports), and UTC test interval. Do not record admin, invite, ICE password, or private-key values.
- Preserve access to each router/firewall for packet capture and targeted UDP impairment. Keep Coordinator HTTPS and Relay TCP reachable while impairing peer UDP.

Create the network and enroll both devices using the [Quick start](../README.md#quick-start). Confirm each device appears in the same-network peer snapshot returned for the enrolled device's identity-signed request before testing.

## Start the two peers

Record the path-quality policy used for every test. Defaults are RTT threshold `350 ms`, loss threshold `20%`, and `3` consecutive poor windows; each quality window requires at least three probes. These values can be overridden on both peers with `MINI_TUNNEL_QUALITY_RTT_THRESHOLD_MS` (`1`–`60000`), `MINI_TUNNEL_QUALITY_LOSS_THRESHOLD_PERCENT` (`0`–`100`), and `MINI_TUNNEL_QUALITY_BAD_WINDOWS` (`1`–`30`). Invalid values fall back to defaults with a warning. The settings are loaded once per process when its first quality check or recovery probe runs, so set them before launching either peer.

For example, to use a 250 ms RTT threshold and two poor windows on both peers:

```sh
export MINI_TUNNEL_QUALITY_RTT_THRESHOLD_MS=250
export MINI_TUNNEL_QUALITY_BAD_WINDOWS=2
```

The packet-loss comparison is strictly greater than the configured percentage. After a reliable fallback, the peer probes for a better direct path every 60 seconds by default. A candidate must pass three authenticated health probes and meet the configured RTT threshold before promotion. With ICE enabled, it must then preserve consent for 31 seconds while authenticated health probes keep the provisional QUIC channel active every 10 seconds. Non-ICE candidates keep the existing faster promotion path.

On both clients, set the Coordinator URL and start a mesh with ICE, STUN, route management, and the deployed Relay endpoint. Use real numeric STUN and Relay addresses because the CLI accepts `SocketAddr` values for both.

```sh
export MINI_TUNNEL_COORDINATOR_URL='https://coordinator.example:8443'
export MINI_TUNNEL_RELAY_SERVER='<relay-ip>:443'
RUST_LOG=mini_tunnel_agent=debug \
  mini-tunnel peer tunnel mesh \
    --network-id '<network-id>' \
    --bind '0.0.0.0:42000' \
    --stun-server '<stun-ip>:3478' \
    --stun-server '<independent-stun-ip>:3478' \
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

For NAT behavior, configure at least two independently operated STUN destinations where available and record each mapping returned for the same bound UDP socket. Use the router mapping/filter observations and packet captures as evidence. Multiple STUN results help expose destination-dependent mapping but cannot establish mapping behavior for every peer destination; this remains an observed network behavior, not a guaranteed portable label.

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
| Recovery | Remove impairment after reliable fallback | The peer probes every 60 seconds by default; direct UDP is promoted only after three authenticated health probes meet the configured RTT threshold |

The 60-second recovery probe interval is the current implementation default. Record each peer's effective RTT, loss, and bad-window settings when reporting results. TCP can perform worse under congestion and is not itself a congestion remedy. Record results rather than treating a path switch as proof of improved throughput.

## Pass/fail and evidence

A case passes when its expected path behavior occurs, overlay probes reach the intended peer, packet source/destination validation remains enforced, and the selected transport is visible in logs. For fallback cases, record impairment start, fallback start, first successful reliable probe, and any data loss window. A test fails if the process accepts an unauthenticated peer, writes a packet from the wrong overlay source, loops between paths without respecting hysteresis, or leaves peer routes after clean shutdown.

For every case, save a sanitized report row with: case ID, client network/NAT description, mapping observations, effective RTT/loss/bad-window settings, selected path sequence, start/end UTC, p50/p95 RTT, sent/received/lost probes, traffic throughput, reconnect count, fallback/recovery time, route cleanup result, and links or hashes for logs/pcaps. Redact public IPs and all credentials before sharing.

After each phase, stop both clients cleanly, verify their peer routes are gone, remove any test `tc` rules, and revoke/delete the temporary network and enrollment credentials. A `SIGKILL` may bypass route cleanup; inspect and remove only the test peer host routes if that occurs.

## Current evidence

- Linux, macOS, Windows, and PostgreSQL CI passed in [run 41115115196](https://github.com/ilovn/mini-tunnel/actions/runs/41115115196). It includes privileged Linux TUN lifecycle checks and all platform workspace gates.
- [Linux CI run 41112768590](https://github.com/ilovn/mini-tunnel/actions/runs/41112768590) placed each QUIC peer in a separate network namespace joined by a veth pair. It verified authenticated probe loss and recovery, delivery of a 9000-byte overlay packet after lowering both veth MTUs to 1280, and mesh fallback to authenticated TCP after UDP egress loss. This is controlled virtual-link evidence, not public NAT interoperability.
- [Linux CI run 41122764687](https://github.com/ilovn/mini-tunnel/actions/runs/41122764687) placed a STUN client and server on opposite sides of an isolated Linux MASQUERADE router. The client received the translated source address as its server-reflexive candidate while retaining the original bound UDP socket. This verifies one controlled SNAT mapping only; it does not test two independent NATs, public STUN services, or direct peer connectivity.
- [Linux CI run 41125932610](https://github.com/ilovn/mini-tunnel/actions/runs/41125932610) extended that isolated topology with a public peer. The peers completed authenticated ICE checks through the stateful MASQUERADE mapping and exchanged an overlay UDP payload on the nominated path. This is one-sided controlled NAT evidence; it does not establish simultaneous hole punching through two independent NATs or public NAT interoperability.
- [Linux CI run 41145503387](https://github.com/ilovn/mini-tunnel/actions/runs/41145503387) creates two client namespaces behind separate Linux routers on an isolated transit bridge. The dual-NAT phase uses 1:1 NETMAP address translation with stateful inbound filtering: each peer first discovers its mapping through STUN, then both nominate the direct UDP pair and exchange UDP plus overlay payloads without preinstalled peer-specific port mappings. This is controlled evidence for that endpoint-independent mapping/filtering behavior only. It does not model symmetric NAPT, CGNAT, commercial firewalls, or public Internet policy and does not complete the public matrix.
- [Linux CI run 41149650890](https://github.com/ilovn/mini-tunnel/actions/runs/41149650890) extends the same dual-router topology with destination-dependent source ports: STUN maps each endpoint to UDP `41000`, while peer-directed packets map to `41001`. Both peers discover the STUN candidates, but ICE does not nominate the STUN-only ports and inbound peer payloads are filtered; the endpoint-independent profile in the same test still nominates and exchanges payloads. This validates the controlled behavior and the test receiver, not the range of mapping/filter policies found in public symmetric NAT or CGNAT.
- [Linux CI run 41115115196](https://github.com/ilovn/mini-tunnel/actions/runs/41115115196) also verified promotion from TLS/TCP to an authenticated direct QUIC/UDP candidate over the isolated veth pair, followed by overlay packet delivery on the promoted path.
- Earlier veth runs before commit `6cfdc66` configured both veth addresses in one network namespace, so Linux routed peer traffic over loopback. Those runs are not evidence of veth packet loss or constrained-veth behavior and are superseded by the isolated-namespace runs above.
- ICE loopback mapping, same-socket checks, pinned QUIC, mesh, restart, consent-loss, and TCP fallback are covered by workspace tests.
- [Main CI run 41292578439](https://github.com/ilovn/mini-tunnel/actions/runs/41292578439) for commit `dab309f2a6859c04884c3a3a1886a9f9346abc91` passed workspace tests, Clippy, the Linux privileged veth tests for probe loss/recovery, degraded UDP to TCP fallback and TCP to direct UDP promotion, and the Ubuntu 20.04 baseline release build. Its release artifact SHA-256 is `65511438e7df2bc9cca5ab4a4f93f096dccae99071e304a18c1a009e3347add2`.
- On 2026-11-01, that exact release artifact was run on a Japan Ubuntu 26.04 VPS (kernel `7.0.0-30-generic`) and Hong Kong Ubuntu 20.04 VPS (kernel `5.4.0-29-generic`). The peers first reported `QUIC/UDP`. A temporary OUTPUT rule matching only each test peer's IPv4 address and UDP destination port `42521` induced a QUIC socket failure; both peers remained online and reconnected over `TLS/TCP`. Each side delivered three of three overlay pings in both directions (about 60 ms RTT, zero loss). After removing the two exact-match rules, the peers promoted back to `QUIC/UDP` with `healthy_direct_probe`; the bidirectional three-ping checks again had zero loss. The temporary Coordinator, SSH forwards, tunnel processes, TUN devices, overlay routes, rules and files were removed and checked absent. No firewall default policy or existing interface was changed.
- That VPS run demonstrates runtime transport fallback and recovery between two directly addressed cloud VPS clients. It did not exercise clients behind physical NATs or measure sustained random QoS loss: the targeted drop caused a QUIC I/O error after one matching packet per host, so this is not evidence for the configured multi-window loss threshold. The isolated Linux veth test in the CI run above remains the controlled evidence for sustained UDP impairment triggering TCP fallback. The VPS smoke test does not complete the public NAT/QoS matrix; public ICE interoperability remains unverified.
- On 2026-11-01, the ARM64 Ubuntu 22.04 client in the RouterOS NAT container and an Ubuntu 24.04 cloud VPS joined an isolated test network using the prebuilt ARM64 and x86_64 artifacts from [CI run 41299528268](https://github.com/ilovn/mini-tunnel/actions/runs/41299528268). With STUN enabled and `--ice` omitted, both peers reported `QUIC/UDP`; the VPS observed a server-reflexive candidate for the NAT client, and each side delivered 120 of 120 overlay pings over 60 seconds (0% loss; average RTT about 10 ms). Public addresses and credentials are omitted. This is one NATed client reaching a public VPS, not a classification of the RouterOS mapping or a completed independent-NAT matrix case. With `--ice` enabled on both peers, the initial authenticated session came up, then the NAT-side peer repeatedly reported `ICE consent expired` and went offline; overlay pings failed. Thus the tested legacy STUN-candidate UDP path passed this short smoke test, while ICE consent interoperability failed in this topology and remains experimental. The temporary coordinator, peer processes, routes, TUN devices, SSH forwards, state, and test credentials were removed; the verified ARM64 binary remains installed in the test container for follow-up. No RouterOS firewall policy or existing interface was changed.
- Follow-up on 2026-11-01 with commit `4a84892` used the prebuilt ARM64 and x86_64 artifacts from [CI run 41305033296](https://github.com/ilovn/mini-tunnel/actions/runs/41305033296). ICE responses are now dispatched by their STUN transaction ID to the requesting peer session before an authenticated source-address mapping exists; after ICE verifies a response, the observed peer-reflexive address is associated with that session. The RouterOS NAT client and public VPS both nominated the direct ICE path and kept their consent monitors alive for more than three minutes. Each direction delivered 120 of 120 overlay pings over 60 seconds (0% loss; average RTT about 11.6 ms). This verifies one NATed RouterOS client to one public VPS after the fix. It does not classify the RouterOS mapping or complete any two-independent-NAT public matrix case.
- Follow-up regression check on 2026-11-01 with commit `4a4d75e` used the CI-built ARM64 Ubuntu 22.04 and x86_64 Ubuntu 20.04 artifacts from [CI run 41309634014](https://github.com/ilovn/mini-tunnel/actions/runs/41309634014). The clients ran in the RouterOS NAT container and behind the separate office gateway, with a local temporary Coordinator and TCP Relay exposed only through SSH reverse forwards. Both stayed online on `Relay/TLS` throughout a 120-second bidirectional run: RouterOS-to-office delivered 239/240 pings (0.42% loss), office-to-RouterOS delivered 240/240 (0% loss), and Relay reported zero handshake failures. No one-sided UDP promotion followed by an immediate disconnect recurred. No ICE candidate completed promotion in this observation, so this verifies reliable fallback stability rather than a direct ICE path across these two NATs. The clients, temporary network membership, TUN devices, overlay routes, reverse forwards, services, and temporary files were removed; no router firewall or traffic-shaping policy was changed.
- Follow-up on 2026-11-01 with commit `2737dfa` used the CI-built ARM64 Ubuntu 22.04 and x86_64 Ubuntu 20.04 artifacts from [CI run 41314074976](https://github.com/ilovn/mini-tunnel/actions/runs/41314074976). The ARM64 client in the RouterOS NAT container and the Hong Kong public VPS both nominated the direct ICE `QUIC/UDP` path and remained online for the complete 180-second bidirectional run. No consent-expiry, path-failure, or relay-session event occurred; Relay recorded zero active sessions and zero handshake failures. RouterOS-to-VPS delivered 335/360 pings (6.94% loss; average RTT 259.0 ms), and VPS-to-RouterOS delivered 330/360 (8.33% loss; average RTT 259.4 ms). This verifies that the elected inbound session retains its ICE consent monitor in this one NAT-to-public-VPS topology; the measured loss means this run does not establish a low-loss QoS guarantee. It does not characterize the NAT mapping or complete the independent-NAT public matrix. Temporary membership was revoked, both clients stopped cleanly, TUN devices/routes were removed, reverse SSH forwards and local services were stopped, and temporary credentials/files were deleted. No router firewall or traffic-shaping policy was changed.
- An independent-NAT follow-up on 2026-11-01 with the CI artifacts from [run 41315490819](https://github.com/ilovn/mini-tunnel/actions/runs/41315490819) placed clients in the RouterOS ARM64 container and the office x86_64 NAT host. Both initially used Relay/TLS. At the first 60-second candidate refresh, the clients published their newly created overlay TUN addresses as host candidates and nominated those addresses. One endpoint promoted to QUIC/UDP; consent expired about 14 seconds later, and both endpoints reconnected on Relay/TLS. Each direction delivered 209/240 pings over 120 seconds (12.92% loss, including the outage and recovery). The relay reported zero handshake failures. This run exposed a refresh bug and does not count as successful two-NAT direct ICE verification. Both clients, membership, TUN devices/routes, reverse forwards, services, and temporary files were removed; no firewall, QoS, or production routes were changed.
- Retest on 2026-11-01 with the interface-filter fix in commit `8a1b4ae` used ARM64 and x86_64 CI artifacts from [run 41317365351](https://github.com/ilovn/mini-tunnel/actions/runs/41317365351). Over both 60-second candidate refreshes, the coordinator's candidate snapshots contained the physical host and STUN server-reflexive candidates but no `10.239.243.1`/`.2` overlay TUN address; neither client logged an ICE nomination or path promotion. Both stayed online on Relay/TLS for 180 seconds. Each direction delivered 360/360 overlay pings (0% loss; average RTT 55.3 ms RouterOS-to-office and 26.1 ms office-to-RouterOS); Relay recorded one active session and zero handshake failures. This verifies the refresh fix and reliable fallback for this topology, but direct ICE across these two NATs remains unverified. Temporary membership was revoked, clients stopped cleanly, TUN devices/routes were removed, reverse SSH forwards and local services were stopped, and temporary files/credentials were deleted. No firewall, QoS, or production routes were changed.
- The RouterOS/office topology did not produce a successful direct ICE path after the fix; NAT mapping/filter behavior was not characterized and endpoint roles were not reversed. No public NAT matrix case is complete. Attach a sanitized report from independently NATed client networks before treating public ICE interoperability as verified.
