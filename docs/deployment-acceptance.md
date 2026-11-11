# Linux peer deployment acceptance

This runbook validates one release binary on one Linux peer. Complete it before relying on the peer. Keep the commands and outputs in a timestamped evidence directory. Do not paste invite tokens, device keys, database URLs, Relay signing keys, or public mapped addresses into shared evidence.

## Release selection

Use the matching Linux archive from a published GitHub Release. For the earlier pre-release CI validation, commit `4ac3ef96e66d4566b8204a3ce71e8ac83d54cd71` and CI run `42806196808` produced:

| Artifact | Archive SHA-256 |
| --- | --- |
| `mini-tunnel-linux-x86_64-ubuntu20.04` | `3071c72819d61e5ea3923b563520c122297b31d0a4c045f09fa41d323c88a3a0` |
| `mini-tunnel-linux-aarch64-ubuntu22.04` | `ac6633a1d40db961ef54945ae4005a5c74ffc1af113711e0eaa3e5f99e523f9c` |

The archives contain one `mini-tunnel` binary with these expected SHA-256 values:

| Target | Binary SHA-256 |
| --- | --- |
| x86_64 | `c76038bf4edd4ce442be53a13295e6ccb656391988476edcf7deead1335bdda7` |
| aarch64 | `90887c822be27b9ed27a38249e02ac0230e1f1674b498313c423fbb89a87fc6c` |

On a Linux peer, `deploy/download-peer.sh --release vX.Y.Z` obtains a published GitHub Release asset without setting `GITHUB_TOKEN` and verifies its GitHub asset digest, published SHA-256 file, tag source commit, archive layout, and GitHub Sigstore provenance. Install a recent GitHub CLI (`gh`) with `attestation verify` support first; the downloader fetches the public attestation bundle anonymously and fails closed if provenance cannot be verified. No `gh auth login` is required for public releases. It pins the expected `ilovn/mini-tunnel` release workflow, tag, and source commit. Without a source option, the downloader selects the newest stable release. For reproducible release acceptance, use a fixed release tag:

```sh
deploy/download-peer.sh \
  --release v0.1.0 \
  --output-dir ./mini-tunnel-download
```

For a pre-release CI artifact, the script can obtain an artifact from a successful CI run and verifies its ZIP structure, successful main-branch run, archive checksum, and GitHub Sigstore provenance from the expected CI workflow. Always pass a full commit SHA:

```sh
GITHUB_TOKEN='...' deploy/download-peer.sh \
  --commit 4ac3ef96e66d4566b8204a3ce71e8ac83d54cd71 \
  --output-dir ./mini-tunnel-download
```

GitHub requires an authenticated API request for Actions artifact ZIP downloads. To avoid placing the token in a permanent shell file, read it into the current shell first:

```sh
read -rs GITHUB_TOKEN && export GITHUB_TOKEN
deploy/download-peer.sh \
  --commit 4ac3ef96e66d4566b8204a3ce71e8ac83d54cd71 \
  --output-dir ./mini-tunnel-download
```

The script writes `download.json` with the source mode, commit, release or CI provenance, archive checksum, binary checksum, and verification list. For a published Release it resolves `commit_sha` from the release tag's Git reference, including annotated tags; for a CI artifact it uses the successful workflow run's `head_sha`. It does not use the current `main` branch as the Release source. Record this file with the deployment evidence.

On the peer, confirm the CPU and OS before selecting the archive:

```sh
uname -m
uname -s
```

Pass: `x86_64` uses the x86_64 archive; `aarch64` uses the aarch64 archive; `uname -s` is `Linux`.

Extract the archive into a directory readable only by the administrator, then compare the extracted binary checksum with the checksum recorded for this run before installation. Record both values.

## Installation preflight

Create a one-use invite on the Coordinator and transfer it as a regular file with mode `0600`. Then run the installer in validation mode first:

```sh
sudo deploy/install-peer.sh \
  --binary ./mini-tunnel \
  --network-id '<network UUID>' \
  --coordinator-url 'https://coordinator.example:8443' \
  --invite-token-file ./invite.token \
  --instance office \
  --stun-server '<host:port>' \
  --relay-server '<host:42001>' \
  --udp-relay-server '<host:42003>' \
  --validate-only
```

Omit a Relay option only when that transport is not configured. Add `--coordinator-ca ./coordinator-ca.pem` for a private Coordinator CA.

Pass: the target is Linux with systemd 247+, `/dev/net/tun` is available, the binary executes on the target CPU, the invite is a non-symlink regular file with mode `0600`, and the command prints `Inputs valid. No files changed`.

Fail: any required-argument, architecture, token-permission, endpoint-syntax, or unit-template error. Resolve it before installation; the preflight must not create state.

## Enroll and start

Run the same command without `--validate-only`. The installer joins once as the `mini-tunnel` account, removes its temporary invite copy, installs the unit, and starts the instance.

After installation, record all of the following:

```sh
sudo systemctl status mini-tunnel-peer@office.service --no-pager
sudo journalctl -u mini-tunnel-peer@office.service -b --no-pager -n 200
sudo -u mini-tunnel /usr/local/bin/mini-tunnel peer status --url http://127.0.0.1:42003
ip address show
ip route show table main
```

Pass:

- `systemctl is-active mini-tunnel-peer@office.service` prints `active`.
- `peer status` reports the expected network, local overlay address, peer session, active transport, recent health probes, and no persistent error state.
- The TUN address matches the Coordinator lease, and only authenticated peer host routes were added.
- Logs contain successful enrollment and no panic, backtrace, repeated reconnect storm, token material, or unexpected authentication failure.

Fail: the unit enters a restart loop, status cannot report a peer session, the lease does not match the TUN address, routes leak beyond the expected peer addresses, or logs expose secrets.

## Bidirectional baseline

From each peer, send at least 20 ICMP pings to the other peer's overlay address. Prefer `ping -c 20 <peer-overlay-ip>` and run both directions concurrently only after each direction has passed independently.

Pass: both directions return 20/20 replies with 0% loss, no duplicate replies, and plausible RTT for the underlay. Record minimum, average, and maximum RTT.

Fail: any missing reply, duplicate reply, persistent source/destination mismatch, or route pointing through an unexpected interface. Stop and collect status and logs before changing configuration.

## Operational checks

Restart the peer once and repeat the status and bidirectional baseline:

```sh
sudo systemctl restart mini-tunnel-peer@office.service
sudo systemctl is-active mini-tunnel-peer@office.service
sudo -u mini-tunnel /usr/local/bin/mini-tunnel peer status --url http://127.0.0.1:42003
ping -c 20 <peer-overlay-ip>
```

Pass: the service reuses persisted identity and membership, returns to a healthy peer session, and both directions again pass 20/20.

Fail: loss of persisted identity, a new overlay lease, failure to reconnect after bounded retries, or a restart loop.

## Evidence and rollback

Save a timestamped evidence directory containing:

- archive and extracted binary SHA-256 values;
- `uname -a`, installer arguments with secrets redacted, and installer output;
- preflight, installation, startup, status, route, and journal outputs;
- both ping directions and restart results;
- Coordinator membership/lease state before and after;
- cleanup or rollback confirmation.

To roll back a failed enrollment, stop and disable the instance first:

```sh
sudo systemctl disable --now mini-tunnel-peer@office.service
```

Revoke the member on the Coordinator so the invite/device identity cannot be reused. Keep `/etc/mini-tunnel/peer-office.env` and `/var/lib/mini-tunnel` until the evidence review is complete. Remove instance-specific files only after confirming no other instance shares them. If the Coordinator or Relay was also part of the test, restore its exact prior configuration and verify unrelated services remain active.

## Boundary

This runbook proves one installation and one peer pair on the tested network at one point in time. It does not prove cross-region NAT interoperability, sustained QoS behavior, UDP-to-TCP fallback, Relay recovery, production throughput, or multi-peer scaling. Record those scenarios separately with the existing controlled-impairment procedures.
