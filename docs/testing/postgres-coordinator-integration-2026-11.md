# PostgreSQL Coordinator integration check (2026-11-27)

The previously ignored PostgreSQL integration test was run against a fresh, disposable PostgreSQL 17.11 cluster on `127.0.0.1:55432`. The cluster directory was created under a temporary path and removed after `pg_ctl` reported a clean shutdown. No shared or production database was used.

The test used separate owner and runtime connection strings. The owner connection applied migrations and reset only the disposable test database. The `mini_tunnel_runtime` login received schema usage and table DML grants; the test asserted that this role had no `CREATE` privilege on the schema.

Command:

```sh
MINI_TUNNEL_TEST_DATABASE_URL='postgresql://postgres@127.0.0.1:55432/mini_tunnel_test' \
MINI_TUNNEL_TEST_APP_DATABASE_URL='postgresql://mini_tunnel_runtime@127.0.0.1:55432/mini_tunnel_test' \
cargo test -p mini-tunnel-coordinator \
  postgres_coordinator_instances_serialize_join_and_restore_state \
  -- --ignored --nocapture
```

Result: **1 passed, 0 failed, 0 ignored** (0.35 seconds; test binary already built). The test exercises two Coordinator state/router instances against one PostgreSQL database and checks shared per-IP rate limiting, concurrent overlapping network creation, single-use invite and unique address allocation, shared peer candidates and ICE credentials, consistent Relay ticket pairing, state restoration in a newly connected instance, PostgreSQL-to-JSON export and JSON-to-PostgreSQL import, revocation propagation, and fail-closed writes/readiness after closing the database pool.

This is real PostgreSQL integration coverage, not a separate-process or production failover test. It does not establish cross-host TLS/connection-pool behavior, database failover, rolling schema upgrades, or production write throughput. The sanitized command result is retained in the local Harness evidence directory and is not committed.
