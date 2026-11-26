# Direct recovery backoff on domestic NAT

Date: 2026-11-27 (China Standard Time)  
Source: `3d3a46e7356c2bbee58802180d051122feaed0b8`  
Main CI: [run 45908257370](https://github.com/ilovn/mini-tunnel/actions/runs/45908257370)  
Release staging: [run 45909142789](https://github.com/ilovn/mini-tunnel/actions/runs/45909142789)  
Harness task: `quick-2519311139`

## Artifact provenance

The Linux x86_64 archive came from release staging run `45909142789`. Its SHA-256 sidecar matched, and `deploy/verify-peer-attestation.sh` verified the Sigstore attestation for repository `ilovn/mini-tunnel`, workflow `release.yml`, ref `refs/heads/main`, and source commit `3d3a46e7356c2bbee58802180d051122feaed0b8`.

| Artifact | SHA-256 |
| --- | --- |
| Linux x86_64 archive | `b68879cbd5fc187031293c76071f5da54cd9df498b6ce015d042c8aa68d36bd9` |
| Extracted Linux executable | `57e498633bd1b7e77d9543d72e7a9e0b6683d64f7857b351c103c3b52e54f73f` |

The same executable ran on Guangzhou and the domestic NAT VPS. Neither endpoint built from source. The staging workflow completed successfully and skipped publication.

## Results

- Guangzhou and the domestic NAT peer joined an isolated `10.244.223.0/24` overlay. Both selected authenticated `QUIC/UDP`; baseline overlay pings passed 10/10 in each direction (0% loss, about 11.5 ms average RTT).
- A watchdog was armed before installing one NAT-side nftables OUTPUT rule limited to UDP destination `193.112.165.176:44445`. During the impairment both peers remained online on `Relay/TLS`; Guangzhou reported `quality_threshold`, NAT reported `transport_failure`. The rule counter recorded 11 packets / 886 bytes. Overlay pings passed 15/15 in both directions over Relay/TLS (0% loss).
- The exact rule was removed at `2026-11-26T23:17:02.451944Z`. The automatic rollback timer was stopped only after confirming the rule absent. Both peers remained online over Relay/TLS; post-removal pings passed 20/20 in each direction (0% loss), with another 10/10 each in a later sample.
- The test exercised the new minimum-cooldown scheduling branch. Guangzhou logged a failed direct probe at `23:16:37.404Z`, increased the cooldown from 60 to 120 seconds, and chose a shared UTC slot 142.595 seconds later. NAT's independent failure state was already at 120 seconds; it failed at `23:18:03.323Z`, increased its cooldown to 240 seconds, and scheduled its next attempt 266.676 seconds later. Guangzhou's direct recovery attempt at `23:19:10Z` timed out waiting for the peer. Later attempts continued to land in different slots; both status endpoints remained `online=true`, `Relay/TLS`, and 0% loss. No direct UDP re-promotion was observed before cleanup.
- This run therefore verifies direct baseline, loss-triggered reliable fallback, overlay continuity, and that each endpoint applies its local cooldown before retry. It **does not pass direct recovery**: independent local cooldown stages can schedule the two peers in different rendezvous slots, so their ICE checks miss each other. The implementation needs shared recovery scheduling or a common fixed rendezvous cadence before this behavior is accepted.

## Cleanup

Both test memberships were revoked; the Coordinator released `10.244.223.1` and `.2`. Test peers, Coordinator, Relay, cleanup timers, the exact nftables table, test routes, addresses, listeners, state, keys, certificate, invite, binary, and temporary directories were removed. Final checks found no test ports, test overlay routes/addresses, or impairment table. Guangzhou's default route remained via `10.0.20.1`; its production Relay PID `17770` continued listening on TCP `42001`, TCP metrics `42002`, and UDP `42003`. The NAT default route remained via `172.16.16.172`. Raw timestamped logs and command outputs are retained locally under the ignored Harness evidence directory `.harness/tasks/quick-2519311139/evidence/private/` and are not committed.
