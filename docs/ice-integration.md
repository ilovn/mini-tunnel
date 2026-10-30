# ICE integration decision

Status: experimental ICE checks are integrated for single-peer and mesh tunnels. Public NAT interoperability is not verified; keep the feature opt-in and retain TCP/relay fallback.

Prototype progress: `mini_tunnel_agent::ice::IceAgentDriver` wraps the Sans-I/O agent and `peer_endpoint_with_ice` provides a Quinn endpoint using a same-socket demultiplexer. Its bounded router dispatches requests by both local and remote ufrags, allowing several peer sessions to share an endpoint; responses route only to addresses accepted by the matching ICE agent. Loopback tests nominate pairs over real shared UDP sockets and establish pinned QUIC channels, including two concurrent mesh peer sessions. Single-peer tunnel Connect/Listen and mesh offer opt-in `--ice`, publish member-signed ephemeral credentials, refresh them every 60 seconds, run checks before QUIC setup, and fall back to the candidate dialer when ICE is unavailable or fails. The default remains on the legacy path; public NAT traversal is not verified.

## Selected ICE engine

Use [`rtc-ice`](https://docs.rs/rtc-ice/latest/rtc_ice/) as the ICE state machine. Version 0.21.1 exposes an RFC 8445 Sans-I/O `Agent`: the caller supplies local/remote candidates, authenticated STUN datagrams, and clock ticks; the agent emits checks, state events, and a nominated candidate pair. It includes controlling/controlled roles, peer-reflexive candidates, and nomination. The crate handles ICE semantics; mini-tunnel retains its existing QUIC/TLS channel for overlay data.

Do not use `webrtc-ice`'s socket-owning `Conn` as the integration boundary. It obscures the requirement that ICE checks and QUIC use the same UDP socket and mapped port. `str0m` is also outside scope because its user-facing transport is a WebRTC media stack.

## UDP socket integration

Quinn 0.11.12 supports a custom `Runtime` and `AsyncUdpSocket`. A wrapper around Quinn's Tokio UDP socket can classify incoming datagrams using the STUN message framing before passing the remaining datagrams to Quinn. RFC 7983 defines the STUN/DTLS/RTP/RTCP/other demultiplexing ranges; this product only needs STUN versus QUIC, so classification must additionally validate STUN's top bits, magic cookie, and declared length before interception. A malformed datagram must not starve QUIC or reach the ICE state machine.

The ICE driver sends its outbound checks through the same underlying bound socket, with a bounded queue and a per-peer candidate/check limit. It owns the ICE agent and clock; the Quinn socket wrapper transfers only validated STUN-shaped datagrams to that driver. Per-datagram ICE parsing/authentication errors are dropped and traced instead of aborting the full ICE session, since a role-conflict request can update agent state while returning a message-level error. Mapped candidates are signaled as `srflx://<mapped>|<related>` and instantiated as server-reflexive candidates; older bare UDP and `tcp://` addresses remain accepted. For wildcard IPv4 and IPv6 binds, the CLI gathers same-family addresses from active interfaces and uses the tunnel socket's port. IPv6 link-local candidates are skipped because this signal format has no interface scope ID. With STUN enabled, a route probe selects the related address for the mapped candidate; the actual socket bind address is passed separately to ICE. Candidate publication is capped at eight, with explicit candidates and the STUN mapping taking precedence over additional interface addresses. IPv6 overlay/TUN addressing is not implemented by this candidate-gathering change. The current prototype uses a single receive task and one bounded datagram queue per protocol, with UDP segmentation disabled and ECN metadata not propagated. These limitations must be measured before making it the default. Do not bind a second tunnel socket and advertise it as the QUIC candidate: NAT mapping behavior can differ by local port and destination.

The socket adapter must preserve Quinn's packet metadata and readiness behavior. Intercepting one packet in a batched receive must compact the remaining datagrams and metadata correctly. ICE queue saturation drops the check input and lets the agent retransmit according to its bounded timer schedule; it must never block Quinn's receive path.

## Signaling and compatibility

ICE credentials (ufrag/password) and candidate generation are ephemeral per endpoint generation. They are authenticated by the enrolled device key and returned only in the same-network peer view. The coordinator keeps them in a bounded in-memory map for at most two minutes; ICE-enabled CLI endpoints refresh at 60-second intervals. Never write passwords to logs. Persist candidate addresses as today, but keep ICE credentials out of the coordinator's durable snapshot; restart requires peers to publish fresh credentials.

The opt-in CLI uses ICE only when both same-network peer snapshots contain current credentials and usable UDP candidates; otherwise it falls back to the current candidate dialer. Keep TCP and ticket-authorized relay selection after ICE failure. Device-ID ordering provides the deterministic ICE role proposal, while RFC 8445 role-conflict handling remains enabled because both processes can restart or observe stale state. Real NAT, IPv6 interface gathering, and Windows TUN configuration remain open.

## Required verification before enabling by default

- Deterministic Sans-I/O tests cover authenticated checks, controlling/controlled roles, simultaneous-controlling role-conflict recovery, and nomination. Peer-reflexive candidates, restart, and longer consent/timeout behavior still need dedicated tests.
- Same-socket UDP demultiplexer tests for valid STUN, QUIC-shaped datagrams, malformed packets, multi-datagram batches and a full bounded ICE queue.
- End-to-end CLI loopback coverage publishes signed credentials, runs checks over the shared socket, nominates a pair, then transfers a packet over the pinned QUIC connection.
- Regression tests proving older peers continue using the existing UDP/TCP/relay path.
- A real NAT matrix covering endpoint-independent, address-dependent and address-and-port-dependent mappings, plus one-sided and symmetric NAT. Loopback tests cannot establish public NAT traversal success.

## References

- [RFC 8445: Interactive Connectivity Establishment](https://www.rfc-editor.org/rfc/rfc8445)
- [RFC 8489: Session Traversal Utilities for NAT](https://www.rfc-editor.org/rfc/rfc8489)
- [RFC 7983: RTP and RTCP Multiplexing](https://www.rfc-editor.org/rfc/rfc7983)
- [Quinn 0.11.12 runtime socket traits](https://docs.rs/crate/quinn/0.11.12/source/src/runtime.rs)
- [`rtc-ice` API](https://docs.rs/rtc-ice/latest/rtc_ice/)
