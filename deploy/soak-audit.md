# Soak evidence audit

`analyze_soak.py` reads the JSONL emitted by the soak monitor. It prints only aggregate
measurements and stable failure codes; it does not print raw error strings, peer
addresses, tokens, or record contents.

## Collect a run

`soak_monitor.py` is the Linux collector for a peer and its optional local Relay. Run it as
the peer service account so it can inspect the peer process under `/proc`; the status and
metrics listeners must remain loopback-only. The monitor accepts only loopback HTTP URLs
and RFC1918/ULA overlay probe destinations. It writes a private, no-follow JSONL file
(mode `0600`); it refuses to overwrite or append to an existing path so sample sequence
numbers cannot silently restart in the middle of a run. HMAC-anonymizes peer IDs with an
in-memory per-run salt, and stores only
allowlisted status fields, parsed ping counts, process resource counts, and selected Relay
metrics. Raw HTTP responses, command output, endpoint URLs, and error details are never
written. Collection failures become stable error codes in the sample and sampling continues.

For one Linux `systemd` peer and its local Relay, start the 12-hour collector with:

```sh
sudo -u mini-tunnel python3 deploy/soak_monitor.py \
  --side gz \
  --status-url http://127.0.0.1:42003/status \
  --systemd-unit mini-tunnel-peer@office.service \
  --probe-destination 10.248.0.2 \
  --relay-metrics-url http://127.0.0.1:42002/metrics \
  --sample-interval-seconds 10 \
  --probe-interval-seconds 300 \
  --probe-count 5 \
  --duration-seconds 43200 \
  --output /var/lib/mini-tunnel/soak-office.jsonl
```

Choose the peer's actual status port, local Relay metrics port (omit `--relay-metrics-url`
if none), and a remote overlay address. Keep the JSONL private because it contains path,
health, and resource measurements. `Ctrl-C` or `SIGTERM` appends a `monitor_stopped` record;
without that marker the analyzer derives duration from sample timestamps. `--samples` can
bound a short collection for a smoke check.

Before starting a long soak, verify that the output is being updated and run a short
collection through the analyzer. Do not infer long-run stability from a short smoke run.

For a 12-hour run sampled every 10 seconds, with five-packet probes every five minutes:

```sh
python3 deploy/analyze_soak.py \
  --input gz-status.jsonl \
  --input arm-status.jsonl \
  --sample-interval-seconds 10 \
  --max-sample-gap-seconds 15 \
  --probe-interval-seconds 300 \
  --probe-jitter-seconds 10 \
  --max-probe-loss-percent 0 \
  --minimum-duration-seconds 43200 \
  --minimum-probe-rounds 144
```

Set the jitter to one sample interval for `soak_monitor.py`; probe work is picked up on
the next sampler tick after its fixed deadline. Use zero only when another collector
records the actual probe time independently of the status sampling loop. For older monitor runs that rebase the next probe deadline
on each sample, use a 10-second jitter allowance and a minimum of 140 rounds for a
12-hour run. The run fails on offline peer samples, status errors, configured Relay
metrics errors, malformed records, sample gaps, missing scheduled probes, invalid probe
records, or packet loss above the configured threshold. `failed_probe_rounds` counts invalid probe
records (missing, non-finite, or inconsistent sent/received counts); `probe_loss_rounds`
reports valid probe rounds that lost one or more packets. The configured packet-loss
threshold controls whether those valid losses fail the run, and defaults to strict zero
loss. Sample sequence gaps fail the run; `nominal_sample_deficit` is informational because
small clock/scheduler delays can produce fewer samples than the ideal interval estimate
without missing sequence numbers or an excessive sample gap. A healthy path transition between
`QUIC/UDP` and `Relay/TLS` is reported but is not itself a failure.

When Relay metrics are present in the JSONL, the report summarizes active connection
and session peaks, bytes forwarded, the aggregate handshake-failure increase, and any
classified failure deltas. With the classified metrics, pairing/state rejections and
server I/O/internal failures gate the run; malformed requests, ticket/identity rejects,
client disconnects, and authentication timeouts remain visible diagnostics because a
public listener can receive unrelated Internet probes.

Older JSONL files with only the aggregate counter do not identify the failure source.
An increase gates the run only when a Relay path was observed or an active Relay session
was present. If all recorded paths are direct and the maximum Relay session count is
zero, the increase is reported as an unattributed diagnostic rather than a peer outage.
This does not hide whether the Relay was used: path transitions, session peaks, and the
raw counter delta remain in the report. Counter resets are handled by summing positive
steps between adjacent samples; the first value is a baseline and is not counted as a
new failure.

Set `--max-rss-kib`, `--max-fds`, or `--max-threads` to enforce local resource ceilings.
The report includes first/last values and min/max ranges even when no ceiling is set.
It also lists consecutive offline sample intervals (start/end timestamps, sample counts,
offline-peer counts, and the observed span between the first and last sample) and exact
path-transition timestamps. These event details omit peer IDs; a one-sample offline
interval has an observed span of zero because the report does not infer duration beyond
the samples it received.

The exit status is zero only when every input passes. Preserve the original JSONL
privately; the report is suitable for sharing after checking that the supplied side
labels are non-sensitive.
