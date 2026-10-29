# ICE integration decision

Status: implementation in progress. The current peer path remains the existing bounded UDP candidate dialer with TCP and relay fallback; it must not be described as RFC 8445 ICE until the checks below are integrated and verified.

Prototype progress: `mini-tunnel-agent::ice::IceAgentDriver` wraps the Sans-I/O agent and `peer_endpoint_with_ice` provides an optional Quinn endpoint using a same-socket demultiplexer. Loopback tests verify authenticated nomination in the driver, STUN queue bounds, and QUIC/TLS peer data over the demultiplexed endpoint. The default peer endpoint and coordinator signaling do not use this prototype yet.

## Selected ICE engine

Use [`rtc-ice`](https://docs.rs/rtc-ice/latest/rtc_ice/) as the ICE state machine. Version 0.21.1 exposes an RFC 8445 Sans-I/O `Agent`: the caller supplies local/remote candidates, authenticated STUN datagrams, and clock ticks; the agent emits checks, state events, and a nominated candidate pair. It includes controlling/controlled roles, peer-reflexive candidates, and nomination. The crate handles ICE semantics; mini-tunnel retains its existing QUIC/TLS channel for overlay data.

Do not use `webrtc-ice`'s socket-owning `Conn` as the integration boundary. It obscures the requirement that ICE checks and QUIC use the same UDP socket and mapped port. `str0m` is also outside scope because its user-facing transport is a WebRTC media stack.

## UDP socket integration

Quinn 0.11.12 supports a custom `Runtime` and `AsyncUdpSocket`. A wrapper around Quinn's Tokio UDP socket can classify incoming datagrams using the STUN message framing before passing the remaining datagrams to Quinn. RFC 7983 defines the STUN/DTLS/RTP/RTCP/other demultiplexing ranges; this product only needs STUN versus QUIC, so classification must additionally validate STUN's top bits, magic cookie, and declared length before interception. A malformed datagram must not starve QUIC or reach the ICE state machine.

The ICE driver sends its outbound checks through the same underlying bound socket, with a bounded queue and a per-peer candidate/check limit. It owns the ICE agent and clock; the Quinn socket wrapper transfers only validated STUN-shaped datagrams to that driver. The current prototype uses a single receive task and one bounded datagram queue per protocol, with UDP segmentation disabled and ECN metadata not propagated. These limitations must be measured before making it the default. Do not bind a second ICE socket and advertise it as the QUIC candidate: NAT mapping behavior can differ by local port and destination.

The socket adapter must preserve Quinn's packet metadata and readiness behavior. Intercepting one packet in a batched receive must compact the remaining datagrams and metadata correctly. ICE queue saturation drops the check input and lets the agent retransmit according to its bounded timer schedule; it must never block Quinn's receive path.

## Signaling and compatibility

ICE credentials (ufrag/password) and candidate generation are ephemeral per endpoint generation. They must be authenticated by the enrolled device key and returned only in the same-network peer view. Never write passwords to logs. Persist candidate addresses as today, but keep ICE credentials out of the coordinator's durable snapshot; restart requires peers to publish fresh credentials.

Negotiate ICE capability during the authenticated peer handshake. A peer pair uses ICE only when both endpoints advertise the same supported capability and valid generation; otherwise it falls back to the current candidate dialer. Keep TCP and ticket-authorized relay selection after ICE failure. Device-ID ordering provides the deterministic ICE role proposal, while RFC 8445 role-conflict handling remains enabled because both processes can restart or observe stale state.

## Required verification before enabling by default

- Deterministic Sans-I/O tests for authenticated checks, controlling/controlled roles, conflict handling, peer-reflexive candidates, nomination, timeout and ICE restart.
- Same-socket UDP demultiplexer tests for valid STUN, QUIC-shaped datagrams, malformed packets, multi-datagram batches and a full bounded ICE queue.
- End-to-end loopback QUIC through the wrapped socket, proving existing peer identity/TLS pinning remains active after nomination.
- Regression tests proving older peers continue using the existing UDP/TCP/relay path.
- A real NAT matrix covering endpoint-independent, address-dependent and address-and-port-dependent mappings, plus one-sided and symmetric NAT. Loopback tests cannot establish public NAT traversal success.

## References

- [RFC 8445: Interactive Connectivity Establishment](https://www.rfc-editor.org/rfc/rfc8445)
- [RFC 8489: Session Traversal Utilities for NAT](https://www.rfc-editor.org/rfc/rfc8489)
- [RFC 7983: RTP and RTCP Multiplexing](https://www.rfc-editor.org/rfc/rfc7983)
- [Quinn 0.11.12 runtime socket traits](https://docs.rs/crate/quinn/0.11.12/source/src/runtime.rs)
- [`rtc-ice` API](https://docs.rs/rtc-ice/latest/rtc_ice/)
