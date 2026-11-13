# Soak evidence audit

`analyze_soak.py` reads the JSONL emitted by the soak monitor. It prints only aggregate
measurements and stable failure codes; it does not print raw error strings, peer
addresses, tokens, or record contents.

For a 12-hour run sampled every 10 seconds, with five-packet probes every five minutes:

```sh
python3 deploy/analyze_soak.py \
  --input gz-status.jsonl \
  --input arm-status.jsonl \
  --sample-interval-seconds 10 \
  --max-sample-gap-seconds 15 \
  --probe-interval-seconds 300 \
  --probe-jitter-seconds 0 \
  --max-probe-loss-percent 0 \
  --minimum-duration-seconds 43200 \
  --minimum-probe-rounds 144
```

Set the jitter to one sample interval when auditing logs from a monitor that triggers
work only from its periodic sampling loop. Use zero when the monitor schedules probes
against a fixed cadence. For older monitor runs that rebase the next probe deadline
on each sample, use a 10-second jitter allowance and a minimum of 140 rounds for a
12-hour run. The run fails on offline peer samples, status errors,
malformed records, sample gaps, missing scheduled probes, failed probe rounds, or
packet loss above the configured threshold. A healthy path transition between
`QUIC/UDP` and `Relay/TLS` is reported but is not itself a failure.

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
