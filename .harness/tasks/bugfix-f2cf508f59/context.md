# 上下文

- Coordinator request limiter keyed directly on `IpAddr`; dual-stack stacks can represent one IPv4 peer as an IPv4-mapped IPv6 address and receive a separate bucket.
- `RequestRateLimiter::allow` now canonicalizes mapped addresses to `IpAddr::V4` before bucket lookup. Relay already applies equivalent source normalization.
- Regression test exhausts the IPv4 bucket then verifies the mapped IPv6 source is rejected and does not add a second table entry.
