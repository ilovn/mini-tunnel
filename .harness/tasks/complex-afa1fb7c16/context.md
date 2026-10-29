# 上下文

- Mesh already reconciles signed same-network peer snapshots every 30 seconds, but established single-peer Connect/Listen sessions had no membership recheck.
- Single-peer sessions now query a signed peer snapshot every 30 seconds. A successful snapshot without the authenticated peer, or authoritative `invalid_token`/`not_found` response for the local member/network, closes the session. Transient API/transport errors log and preserve the session.
- Coordinator API errors remain typed at the HTTP boundary, so revocation decisions inspect the error code rather than parsing display text.
- `PeerChannel::close_async` half-closes TLS/TCP as well as closing QUIC, so revocation terminates both transport types. Existing route leases are cleaned up by the normal `run_peer_tunnel` exit path.
- Tests cover revocation classification and TCP close propagation; full workspace gates pending.
