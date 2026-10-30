# Local `rtc-ice` patch

This directory contains the upstream `rtc-ice` 0.21.1 crate (MIT OR Apache-2.0), with local changes: consent checks independently randomize the next interval to 0.8–1.2 of the configured base interval using the agent's cryptographic random provider, as required by RFC 7675; the `ping_pong` example's development-only HTTP signaling dependencies were migrated from Hyper 0.14 to Hyper 1 to remove a vulnerable HTTP/2 dependency from the lockfile.

Keep the diff against the upstream crate narrow. Recheck this patch when updating `rtc-ice`.
