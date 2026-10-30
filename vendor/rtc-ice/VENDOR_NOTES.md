# Local `rtc-ice` patch

This directory contains the upstream `rtc-ice` 0.21.1 crate (MIT OR Apache-2.0), with one local change: consent checks independently randomize the next interval to 0.8–1.2 of the configured base interval using the agent's cryptographic random provider, as required by RFC 7675.

Keep the diff against the upstream crate narrow. Recheck this patch when updating `rtc-ice`.
