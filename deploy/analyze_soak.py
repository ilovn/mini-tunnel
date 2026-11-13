#!/usr/bin/env python3
"""Summarize and gate mini-tunnel JSONL soak monitor logs without echoing raw data."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import math
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


def parse_timestamp(value: Any) -> dt.datetime | None:
    if not isinstance(value, str):
        return None
    try:
        timestamp = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if timestamp.tzinfo is None:
        return None
    return timestamp.astimezone(dt.timezone.utc)


def number(value: Any) -> float | None:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        parsed = float(value)
        return parsed if math.isfinite(parsed) else None
    return None


def load_records(path: Path) -> tuple[list[dict[str, Any]], int, int]:
    records: list[dict[str, Any]] = []
    malformed = 0
    non_object = 0
    with path.open(encoding="utf-8") as source:
        for line in source:
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                malformed += 1
                continue
            if not isinstance(value, dict):
                non_object += 1
                continue
            records.append(value)
    return records, malformed, non_object


def analyze_file(
    path: Path,
    *,
    sample_interval_seconds: float,
    max_sample_gap_seconds: float,
    probe_interval_seconds: float,
    probe_jitter_seconds: float,
    max_probe_loss_percent: float,
    minimum_duration_seconds: float,
    minimum_probe_rounds: int,
) -> dict[str, Any]:
    records, malformed, non_object = load_records(path)
    samples = [record for record in records if type(record.get("sample")) is int]
    sample_numbers = sorted({record["sample"] for record in samples})
    duplicate_samples = len(samples) - len(sample_numbers)
    timestamps: list[tuple[dt.datetime, dict[str, Any]]] = []
    invalid_timestamps = 0
    for record in samples:
        timestamp = parse_timestamp(record.get("timestamp_utc"))
        if timestamp is None:
            invalid_timestamps += 1
        else:
            timestamps.append((timestamp, record))
    timestamps.sort(key=lambda item: item[0])

    side_counts = Counter(
        record["side"] for record in samples if isinstance(record.get("side"), str)
    )
    side = side_counts.most_common(1)[0][0] if side_counts else path.stem
    timestamp_values = [timestamp for timestamp, _ in timestamps]
    sample_gaps = [
        (right - left).total_seconds()
        for left, right in zip(timestamp_values, timestamp_values[1:])
    ]
    max_gap = max(sample_gaps, default=0.0)
    gap_count = sum(gap > max_sample_gap_seconds for gap in sample_gaps)

    stopped = next(
        (
            record
            for record in reversed(records)
            if record.get("event") == "monitor_stopped"
        ),
        None,
    )
    explicit_duration = number(stopped.get("elapsed_seconds")) if stopped else None
    duration = explicit_duration
    if duration is None:
        duration = (
            (timestamp_values[-1] - timestamp_values[0]).total_seconds()
            if len(timestamp_values) > 1
            else 0.0
        )

    status_errors = 0
    offline_peers = 0
    offline_observations: list[tuple[dt.datetime, int, int]] = []
    path_transitions = 0
    path_transition_events: list[dict[str, str]] = []
    observed_paths: set[str] = set()
    previous_paths: dict[str, str] = {}
    process_values: dict[str, list[float]] = defaultdict(list)
    missing_process_samples = 0
    relay_values: dict[str, list[float]] = defaultdict(list)
    relay_sample_count = 0
    for timestamp, record in timestamps:
        status_error = bool(record.get("status_error"))
        if status_error:
            status_errors += 1
        status = record.get("status")
        if not isinstance(status, list) or not status:
            if not status_error:
                status_errors += 1
            continue
        offline_count = 0
        for peer in status:
            if not isinstance(peer, dict):
                status_errors += 1
                continue
            peer_id = peer.get("peer")
            identity = peer_id if isinstance(peer_id, str) else "<unknown-peer>"
            if peer.get("online") is not True:
                offline_peers += 1
                offline_count += 1
            active_path = peer.get("active_path")
            if isinstance(active_path, str) and active_path:
                observed_paths.add(active_path)
                if identity in previous_paths and previous_paths[identity] != active_path:
                    path_transitions += 1
                    path_transition_events.append(
                        {
                            "timestamp_utc": timestamp.isoformat(),
                            "from_path": previous_paths[identity],
                            "to_path": active_path,
                        }
                    )
                previous_paths[identity] = active_path
        if offline_count:
            offline_observations.append((timestamp, record["sample"], offline_count))
        relay = record.get("relay")
        if isinstance(relay, dict):
            relay_sample_count += 1
            for field in (
                "mini_tunnel_relay_active_connections",
                "mini_tunnel_relay_active_sessions",
                "mini_tunnel_relay_handshake_failures_total",
                "mini_tunnel_relay_bytes_forwarded_total",
            ):
                value = number(relay.get(field))
                if value is not None and value >= 0:
                    relay_values[field].append(value)
        process = record.get("peer_process")
        if (
            not isinstance(process, dict)
            or type(process.get("pid")) is not int
            or process["pid"] <= 0
        ):
            missing_process_samples += 1
            continue
        for field in ("rss_kib", "threads", "fds"):
            value = number(process.get(field))
            if value is not None and math.isfinite(value) and value >= 0:
                process_values[field].append(value)
    def counter_increase(values: list[float]) -> float:
        """Sum observed positive counter steps while tolerating process resets."""
        return sum(max(0.0, right - left) for left, right in zip(values, values[1:]))

    handshake_failures = relay_values[
        "mini_tunnel_relay_handshake_failures_total"
    ]
    relay_handshake_failure_increase = counter_increase(handshake_failures)
    relay_metrics = {
        "samples": relay_sample_count,
        "handshake_failures_first": handshake_failures[0]
        if handshake_failures
        else None,
        "handshake_failures_last": handshake_failures[-1]
        if handshake_failures
        else None,
        "handshake_failures_increase": relay_handshake_failure_increase,
        "active_connections_max": max(
            relay_values["mini_tunnel_relay_active_connections"], default=None
        ),
        "active_sessions_max": max(
            relay_values["mini_tunnel_relay_active_sessions"], default=None
        ),
        "bytes_forwarded_increase": counter_increase(
            relay_values["mini_tunnel_relay_bytes_forwarded_total"]
        ),
    }

    offline_intervals: list[dict[str, Any]] = []
    current_interval: dict[str, Any] | None = None
    previous_offline_timestamp: dt.datetime | None = None
    previous_offline_sample: int | None = None
    for timestamp, sample_number, offline_count in offline_observations:
        contiguous = (
            current_interval is not None
            and previous_offline_timestamp is not None
            and previous_offline_sample is not None
            and sample_number == previous_offline_sample + 1
            and (timestamp - previous_offline_timestamp).total_seconds()
            <= max_sample_gap_seconds
        )
        if not contiguous:
            current_interval = {
                "start_timestamp_utc": timestamp.isoformat(),
                "end_timestamp_utc": timestamp.isoformat(),
                "sample_count": 0,
                "offline_peer_samples": 0,
                "max_offline_peers": 0,
                "observed_span_seconds": 0.0,
            }
            offline_intervals.append(current_interval)
        assert current_interval is not None
        current_interval["end_timestamp_utc"] = timestamp.isoformat()
        current_interval["sample_count"] += 1
        current_interval["offline_peer_samples"] += offline_count
        current_interval["max_offline_peers"] = max(
            current_interval["max_offline_peers"], offline_count
        )
        current_interval["observed_span_seconds"] = round(
            (
                timestamp
                - dt.datetime.fromisoformat(
                    current_interval["start_timestamp_utc"]
                )
            ).total_seconds(),
            3,
        )
        previous_offline_timestamp = timestamp
        previous_offline_sample = sample_number

    probes: list[tuple[dt.datetime, dict[str, Any]]] = [
        (timestamp, record)
        for timestamp, record in timestamps
        if isinstance(record.get("probe"), dict)
    ]
    probe_sent = 0
    probe_received = 0
    failed_probe_rounds = 0
    probe_loss_rounds = 0
    for _, record in probes:
        probe = record["probe"]
        sent = number(probe.get("sent"))
        received = number(probe.get("received"))
        if sent is None or received is None or sent <= 0 or received < 0 or received > sent:
            failed_probe_rounds += 1
            continue
        probe_sent += int(sent)
        probe_received += int(received)
        if received < sent:
            probe_loss_rounds += 1
    probe_loss_percent = (
        (probe_sent - probe_received) * 100 / probe_sent if probe_sent else None
    )
    probe_gaps = [
        (right[0] - left[0]).total_seconds()
        for left, right in zip(probes, probes[1:])
    ]
    max_probe_gap = max(probe_gaps, default=0.0)
    expected_probe_rounds = (
        math.floor(
            max(0.0, duration - 0.001)
            / (probe_interval_seconds + probe_jitter_seconds)
        )
        + 1
        if probe_interval_seconds > 0 and timestamps
        else 0
    )
    expected_samples = (
        math.floor(max(0.0, duration - 0.001) / sample_interval_seconds) + 1
        if sample_interval_seconds > 0 and timestamps
        else 0
    )
    sequence_gaps = sum(
        max(0, right - left - 1)
        for left, right in zip(sample_numbers, sample_numbers[1:])
    )
    if sample_numbers and sample_numbers[0] > 1:
        sequence_gaps += sample_numbers[0] - 1
    # Timestamp-derived sample counts are only nominal: a periodic sampler's
    # work and scheduler add small delays to each interval. Use explicit sample
    # sequence numbers to detect missing records; max_sample_gap_seconds checks
    # whether the observed cadence itself stopped for too long.
    missing_samples = sequence_gaps
    nominal_sample_deficit = max(0, expected_samples - len(samples))

    resources = {}
    for field, values in sorted(process_values.items()):
        resources[field] = {
            "min": min(values) if values else None,
            "max": max(values) if values else None,
            "first": values[0] if values else None,
            "last": values[-1] if values else None,
            "delta": values[-1] - values[0] if values else None,
        }
    failures: list[str] = []
    if not samples:
        failures.append("no_samples")
    if malformed:
        failures.append("malformed_json_lines")
    if non_object:
        failures.append("non_object_json_lines")
    if invalid_timestamps:
        failures.append("invalid_sample_timestamps")
    if status_errors:
        failures.append("status_errors")
    if missing_process_samples:
        failures.append("missing_process_samples")
    if relay_handshake_failure_increase > 0:
        failures.append("relay_handshake_failures")
    if offline_peers:
        failures.append("offline_peer_samples")
    if gap_count:
        failures.append("sample_gaps")
    if missing_samples:
        failures.append("missing_samples")
    if duplicate_samples:
        failures.append("duplicate_samples")
    if duration < minimum_duration_seconds:
        failures.append("insufficient_duration")
    if len(probes) < minimum_probe_rounds:
        failures.append("insufficient_probe_rounds")
    if expected_probe_rounds > len(probes):
        failures.append("missing_probe_rounds")
    if failed_probe_rounds:
        failures.append("failed_probe_rounds")
    if probe_loss_percent is not None and probe_loss_percent > max_probe_loss_percent:
        failures.append("probe_packet_loss")
    if len(probes) > 1 and max_probe_gap > probe_interval_seconds + probe_jitter_seconds + 2:
        failures.append("probe_schedule_gap")

    return {
        "side": side,
        "samples": len(samples),
        "expected_samples": expected_samples,
        "missing_samples": missing_samples,
        "nominal_sample_deficit": nominal_sample_deficit,
        "sequence_gaps": sequence_gaps,
        "duplicate_samples": duplicate_samples,
        "duration_seconds": round(duration, 3),
        "timestamp_start_utc": timestamp_values[0].isoformat() if timestamp_values else None,
        "timestamp_end_utc": timestamp_values[-1].isoformat() if timestamp_values else None,
        "malformed_lines": malformed,
        "non_object_lines": non_object,
        "invalid_timestamps": invalid_timestamps,
        "status_errors": status_errors,
        "missing_process_samples": missing_process_samples,
        "offline_peer_samples": offline_peers,
        "sample_gaps": gap_count,
        "max_sample_gap_seconds": round(max_gap, 3),
        "probe_rounds": len(probes),
        "expected_probe_rounds": expected_probe_rounds,
        "probe_packets_sent": probe_sent,
        "probe_packets_received": probe_received,
        "probe_loss_percent": round(probe_loss_percent, 3)
        if probe_loss_percent is not None
        else None,
        "probe_loss_rounds": probe_loss_rounds,
        "failed_probe_rounds": failed_probe_rounds,
        "max_probe_gap_seconds": round(max_probe_gap, 3),
        "path_transitions": path_transitions,
        "path_transition_events": path_transition_events,
        "observed_paths": sorted(observed_paths),
        "offline_intervals": offline_intervals,
        "peer_process_resources": resources,
        "relay_metrics": relay_metrics,
        "failures": failures,
        "passed": not failures,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, action="append", required=True)
    parser.add_argument("--sample-interval-seconds", type=float, default=10.0)
    parser.add_argument("--max-sample-gap-seconds", type=float, default=15.0)
    parser.add_argument("--probe-interval-seconds", type=float, default=300.0)
    parser.add_argument(
        "--probe-jitter-seconds",
        type=float,
        help="allowed schedule delay; defaults to one sample interval",
    )
    parser.add_argument("--max-probe-loss-percent", type=float, default=0.0)
    parser.add_argument("--minimum-duration-seconds", type=float, default=0.0)
    parser.add_argument("--minimum-probe-rounds", type=int, default=0)
    parser.add_argument("--max-rss-kib", type=float)
    parser.add_argument("--max-fds", type=float)
    parser.add_argument("--max-threads", type=float)
    args = parser.parse_args(argv)
    if args.probe_jitter_seconds is None:
        args.probe_jitter_seconds = args.sample_interval_seconds
    if (
        any(
            not math.isfinite(value)
            for value in (
                args.sample_interval_seconds,
                args.max_sample_gap_seconds,
                args.probe_interval_seconds,
                args.probe_jitter_seconds,
                args.max_probe_loss_percent,
                args.minimum_duration_seconds,
            )
        )
        or args.sample_interval_seconds <= 0
        or args.max_sample_gap_seconds < args.sample_interval_seconds
        or args.probe_interval_seconds <= 0
        or args.probe_jitter_seconds < 0
        or not 0 <= args.max_probe_loss_percent <= 100
        or args.minimum_duration_seconds < 0
        or args.minimum_probe_rounds < 0
        or any(
            value is not None and (not math.isfinite(value) or value <= 0)
            for value in (args.max_rss_kib, args.max_fds, args.max_threads)
        )
    ):
        parser.error("intervals and thresholds are outside their valid ranges")

    resource_limits = {
        "rss_kib": args.max_rss_kib,
        "fds": args.max_fds,
        "threads": args.max_threads,
    }
    reports = []
    for path in args.input:
        report = analyze_file(
            path,
            sample_interval_seconds=args.sample_interval_seconds,
            max_sample_gap_seconds=args.max_sample_gap_seconds,
            probe_interval_seconds=args.probe_interval_seconds,
            probe_jitter_seconds=args.probe_jitter_seconds,
            max_probe_loss_percent=args.max_probe_loss_percent,
            minimum_duration_seconds=args.minimum_duration_seconds,
            minimum_probe_rounds=args.minimum_probe_rounds,
        )
        for resource, limit in resource_limits.items():
            maximum = report["peer_process_resources"].get(resource, {}).get("max")
            if limit is not None and (maximum is None or maximum > limit):
                report["failures"].append(f"max_{resource}_exceeded")
        report["passed"] = not report["failures"]
        reports.append(report)
    output = {"passed": all(report["passed"] for report in reports), "sides": reports}
    json.dump(output, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0 if output["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
