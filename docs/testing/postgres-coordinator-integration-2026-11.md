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

The exact report commit `44b5d73da1ea86fa39bb0275db0263724ba6002d` also passed the complete GitHub Actions [CI run 45980301165](https://github.com/ilovn/mini-tunnel/actions/runs/45980301165): Ubuntu, Windows, and macOS verification; Linux x86_64 and ARM64 release staging builds; and the dedicated PostgreSQL integration job with its own disposable database and restricted runtime role.

The dedicated PostgreSQL CI job also runs an ignored process-level test from `crates/mini-tunnel-cli/tests/postgres_processes.rs`. It starts two actual Coordinator CLI server processes with the least-privilege runtime role, creates a network through one process, then creates an invite through the other. After the creator exits, the test starts a fresh process and creates another invite for the same network. This verifies shared state across independently running servers and persistence across a process restart. It then deletes the network and terminates the remaining child processes.

The local result above still covers two Coordinator state/router instances within one process; the process-level assertions, including restart persistence, run in the dedicated PostgreSQL CI job and were also exercised locally against a disposable PostgreSQL cluster. Neither test establishes cross-host TLS/connection-pool behavior, database failover, rolling schema upgrades, or production write throughput. The sanitized command result is retained in the local Harness evidence directory and is not committed.
