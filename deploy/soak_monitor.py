#!/usr/bin/env python3
"""Collect privacy-minimized Linux tunnel soak samples as JSONL."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import hmac
import ipaddress
import json
import math
import os
import re
import signal
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

MAX_HTTP_BYTES = 1_048_576
MAX_STATUS_PEERS = 4096
RELAY_REQUIRED_METRIC_NAMES = (
    "mini_tunnel_relay_active_connections",
    "mini_tunnel_relay_active_sessions",
    "mini_tunnel_relay_handshake_failures_total",
    "mini_tunnel_relay_bytes_forwarded_total",
)
RELAY_DIAGNOSTIC_METRIC_NAMES = (
    "mini_tunnel_relay_malformed_protocol_failures_total",
    "mini_tunnel_relay_ticket_rejections_total",
    "mini_tunnel_relay_identity_rejections_total",
    "mini_tunnel_relay_pairing_rejections_total",
    "mini_tunnel_relay_handshake_timeouts_total",
    "mini_tunnel_relay_client_disconnects_total",
    "mini_tunnel_relay_io_failures_total",
    "mini_tunnel_relay_internal_failures_total",
)
RELAY_METRIC_NAMES = RELAY_REQUIRED_METRIC_NAMES + RELAY_DIAGNOSTIC_METRIC_NAMES
_NO_REDIRECT = urllib.request.build_opener(
    urllib.request.ProxyHandler({}),
    type(
        "NoRedirectHandler",
        (urllib.request.HTTPRedirectHandler,),
        {"redirect_request": lambda *args, **kwargs: None},
    )(),
)


class MonitorError(Exception):
    """An expected collection failure represented by a safe stable code."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def validate_loopback_url(value: str, expected_path: str) -> str:
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        loopback = hostname == "localhost" or (
            hostname is not None and ipaddress.ip_address(hostname).is_loopback
        )
        valid_port = parsed.port is None or 1 <= parsed.port <= 65535
    except (ValueError, UnicodeError):
        raise ValueError("endpoint_invalid") from None
    if (
        parsed.scheme != "http"
        or not loopback
        or not valid_port
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path != expected_path
    ):
        raise ValueError("endpoint_must_be_loopback_http")
    return value


def read_http_body(url: str, timeout_seconds: float = 1.0) -> bytes:
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/json, text/plain", "User-Agent": "mini-tunnel-soak/1"},
        method="GET",
    )
    try:
        with _NO_REDIRECT.open(request, timeout=timeout_seconds) as response:
            body = response.read(MAX_HTTP_BYTES + 1)
    except (OSError, urllib.error.URLError, TimeoutError, ValueError):
        raise MonitorError("http_unavailable") from None
    if len(body) > MAX_HTTP_BYTES:
        raise MonitorError("http_body_too_large")
    return body


def anonymize_peer_id(value: str, salt: bytes) -> str:
    return hmac.new(
        salt, value.encode("utf-8", errors="replace"), hashlib.sha256
    ).hexdigest()[:16]


def fetch_status(
    url: str,
    salt: bytes,
    *,
    timeout_seconds: float = 1.0,
    body_reader: Callable[[str, float], bytes] = read_http_body,
) -> tuple[list[dict[str, Any]], str | None]:
    try:
        payload = json.loads(body_reader(url, timeout_seconds))
    except MonitorError as error:
        return [], error.code
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError):
        return [], "invalid_status"
    if not isinstance(payload, list) or not payload or len(payload) > MAX_STATUS_PEERS:
        return [], "invalid_status"

    peers: list[dict[str, Any]] = []
    for entry in payload:
        if not isinstance(entry, dict):
            return [], "invalid_status"
        peer_id = entry.get("peer")
        online = entry.get("online")
        path = entry.get("active_path")
        if not isinstance(peer_id, str) or not peer_id or not isinstance(online, bool):
            return [], "invalid_status"
        if not isinstance(path, str) or not re.fullmatch(r"[A-Za-z0-9/_-]{1,64}", path):
            return [], "invalid_status"
        peers.append(
            {
                "peer": anonymize_peer_id(peer_id, salt),
                "online": online,
                "active_path": path,
            }
        )
    return (peers, None) if peers else ([], "invalid_status")


def parse_prometheus_metrics(text: str) -> dict[str, int | float]:
    values: dict[str, int | float] = {}
    names = set(RELAY_METRIC_NAMES)
    for line in text.splitlines():
        match = re.match(
            r"^([a-zA-Z_:][a-zA-Z0-9_:]*)\s+([-+]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][-+]?\d+)?)\s*$",
            line,
        )
        if not match or match.group(1) not in names:
            continue
        value = float(match.group(2))
        if math.isfinite(value) and value >= 0:
            values[match.group(1)] = int(value) if value.is_integer() else value
    return values


def fetch_relay_metrics(
    url: str,
    *,
    timeout_seconds: float = 1.0,
    body_reader: Callable[[str, float], bytes] = read_http_body,
) -> tuple[dict[str, int | float] | None, str | None]:
    try:
        body = body_reader(url, timeout_seconds)
        text = body.decode("utf-8")
    except MonitorError as error:
        return None, error.code
    except UnicodeDecodeError:
        return None, "invalid_metrics"
    metrics = parse_prometheus_metrics(text)
    return (
        (metrics, None)
        if all(name in metrics for name in RELAY_REQUIRED_METRIC_NAMES)
        else (None, "invalid_metrics")
    )


def parse_ping_output(output: str, sent: int) -> dict[str, int]:
    summary = re.search(
        r"\b(\d+)\s+packets transmitted,\s*(\d+)\s+(?:packets\s+)?received\b",
        output,
    )
    if summary:
        transmitted = min(sent, int(summary.group(1)))
        received = int(summary.group(2))
        return {"sent": transmitted, "received": min(transmitted, received)}
    replies = sum(
        1
        for line in output.splitlines()
        if re.search(r"\bbytes from\b", line, flags=re.IGNORECASE)
    )
    return {"sent": sent, "received": min(sent, replies)}


def run_ping(destination: str, count: int, timeout_seconds: float = 1.0) -> dict[str, int]:
    per_packet_timeout = max(1, math.ceil(timeout_seconds))
    deadline = max(per_packet_timeout + 2, count * per_packet_timeout + 2)
    command = [
        "ping",
        "-n",
        "-c",
        str(count),
        "-W",
        str(per_packet_timeout),
        "-w",
        str(deadline),
        destination,
    ]
    environment = {"PATH": os.defpath, "LC_ALL": "C", "LANG": "C"}
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=deadline + 2,
            check=False,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {"sent": 0, "received": 0}
    if result.returncode not in (0, 1):
        return {"sent": 0, "received": 0}
    return parse_ping_output(result.stdout, count)


def read_process_resources(pid: int, proc_root: Path = Path("/proc")) -> dict[str, Any]:
    result: dict[str, Any] = {"pid": pid, "rss_kib": None, "threads": None, "fds": None}
    try:
        contents = (proc_root / str(pid) / "status").read_text(encoding="ascii")
        for line in contents.splitlines():
            if line.startswith("VmRSS:"):
                result["rss_kib"] = int(line.split()[1])
            elif line.startswith("Threads:"):
                result["threads"] = int(line.split()[1])
        result["fds"] = len(list((proc_root / str(pid) / "fd").iterdir()))
        if result["rss_kib"] is None or result["threads"] is None:
            raise ValueError("required_proc_field_missing")
    except (OSError, ValueError, IndexError):
        return {"pid": 0, "rss_kib": None, "threads": None, "fds": None}
    return result


def resolve_systemd_pid(unit: str, timeout_seconds: float = 1.0) -> int:
    if not re.fullmatch(r"[A-Za-z0-9_.@:-]{1,128}", unit):
        return 0
    try:
        result = subprocess.run(
            ["systemctl", "show", "--property=MainPID", "--value", unit],
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
            env={"PATH": os.defpath, "LC_ALL": "C", "LANG": "C"},
        )
    except (OSError, subprocess.TimeoutExpired):
        return 0
    value = result.stdout.strip()
    if result.returncode != 0 or not value.isdecimal():
        return 0
    pid = int(value)
    return pid if pid > 0 else 0


def validate_probe_destination(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise ValueError("probe_destination_invalid") from None
    if (
        not address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
    ):
        raise ValueError("probe_destination_must_be_private_overlay_ip")
    return str(address)


def open_private_output(path: Path):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise OSError("output_must_be_single_link_regular_file")
        if hasattr(os, "getuid") and info.st_uid != os.getuid():
            raise OSError("output_owner_mismatch")
        os.fchmod(descriptor, 0o600)
        return os.fdopen(descriptor, "a", encoding="utf-8", buffering=1)
    except Exception:
        os.close(descriptor)
        raise


def utc_timestamp() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def build_sample(
    sample: int,
    side: str,
    status_url: str,
    destination: str,
    probe_count: int,
    probe_timeout: float,
    salt: bytes,
    *,
    pid: int,
    relay_metrics_url: str | None,
    body_reader: Callable[[str, float], bytes] = read_http_body,
    ping_runner: Callable[[str, int, float], dict[str, int]] = run_ping,
    process_reader: Callable[[int], dict[str, Any]] = read_process_resources,
    timestamp: str | None = None,
    probe_due: bool = True,
    http_timeout_seconds: float = 1.0,
) -> dict[str, Any]:
    status, status_error = fetch_status(
        status_url,
        salt,
        timeout_seconds=http_timeout_seconds,
        body_reader=body_reader,
    )
    row: dict[str, Any] = {
        "timestamp_utc": timestamp or utc_timestamp(),
        "sample": sample,
        "side": side,
        "status": status,
        "status_error": status_error,
        "peer_process": process_reader(pid) if pid > 0 else {"pid": 0},
    }
    row["probe"] = (
        ping_runner(destination, probe_count, probe_timeout) if probe_due else None
    )
    if relay_metrics_url:
        relay, relay_error = fetch_relay_metrics(
            relay_metrics_url,
            timeout_seconds=http_timeout_seconds,
            body_reader=body_reader,
        )
        row["relay"] = relay
        row["relay_error"] = relay_error
    else:
        row["relay"] = None
    return row


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--side", required=True, help="non-sensitive label, e.g. gz or arm64")
    parser.add_argument("--status-url", required=True, help="loopback peer /status URL")
    parser.add_argument("--relay-metrics-url", help="optional loopback Relay /metrics URL")
    process = parser.add_mutually_exclusive_group(required=True)
    process.add_argument("--pid", type=int)
    process.add_argument("--systemd-unit")
    parser.add_argument("--probe-destination", required=True, help="private overlay IP only")
    parser.add_argument("--probe-count", type=int, default=5)
    parser.add_argument("--probe-timeout-seconds", type=float, default=1.0)
    parser.add_argument("--probe-interval-seconds", type=float, default=300.0)
    parser.add_argument("--sample-interval-seconds", type=float, default=10.0)
    parser.add_argument("--duration-seconds", type=float, default=0.0, help="0 runs until Ctrl-C")
    parser.add_argument("--samples", type=int, default=0, help="optional deterministic sample limit")
    parser.add_argument("--http-timeout-seconds", type=float, default=1.0)
    parser.add_argument("--output", required=True, type=Path, help="private JSONL output path")
    args = parser.parse_args(argv)

    if not re.fullmatch(r"[A-Za-z0-9._-]{1,32}", args.side):
        parser.error("--side must be 1-32 letters, digits, dot, underscore, or dash")
    try:
        args.status_url = validate_loopback_url(args.status_url, "/status")
        if args.relay_metrics_url:
            args.relay_metrics_url = validate_loopback_url(args.relay_metrics_url, "/metrics")
        args.probe_destination = validate_probe_destination(args.probe_destination)
    except ValueError as error:
        parser.error(error.args[0])
    if (
        args.pid is not None and args.pid <= 0
        or args.probe_count <= 0
        or args.probe_count > 100
        or not math.isfinite(args.probe_timeout_seconds)
        or args.probe_timeout_seconds <= 0
        or not math.isfinite(args.probe_interval_seconds)
        or args.probe_interval_seconds <= 0
        or not math.isfinite(args.sample_interval_seconds)
        or args.sample_interval_seconds < 1
        or not math.isfinite(args.duration_seconds)
        or args.duration_seconds < 0
        or args.samples < 0
        or not math.isfinite(args.http_timeout_seconds)
        or not 0.1 <= args.http_timeout_seconds <= 30
    ):
        parser.error("interval, count, duration, or PID is outside its valid range")
    return args


def collect(args: argparse.Namespace) -> int:
    if sys.platform != "linux":
        print("soak_monitor_requires_linux", file=sys.stderr)
        return 2
    if args.systemd_unit:
        unit = args.systemd_unit
        if not re.fullmatch(r"[A-Za-z0-9_.@:-]{1,128}", unit):
            print("systemd_unit_invalid", file=sys.stderr)
            return 2
    try:
        output = open_private_output(args.output)
    except OSError:
        print("output_unavailable_or_unsafe", file=sys.stderr)
        return 2

    start = time.monotonic()
    next_probe = start
    next_sample = start
    salt = os.urandom(32)
    sample = 0
    stopped_by_signal = False
    prior_handlers = {
        signum: signal.getsignal(signum) for signum in (signal.SIGINT, signal.SIGTERM)
    }

    def stop(_signum: int, _frame: Any) -> None:
        nonlocal stopped_by_signal
        stopped_by_signal = True

    for signum in prior_handlers:
        signal.signal(signum, stop)
    try:
        while True:
            now = time.monotonic()
            if args.duration_seconds and now - start >= args.duration_seconds:
                break
            if args.samples and sample >= args.samples:
                break
            sample += 1
            probe_due = now >= next_probe
            if probe_due:
                next_probe += args.probe_interval_seconds
                while next_probe <= now:
                    next_probe += args.probe_interval_seconds
            pid = args.pid if args.pid is not None else resolve_systemd_pid(args.systemd_unit)
            row = build_sample(
                sample,
                args.side,
                args.status_url,
                args.probe_destination,
                args.probe_count,
                args.probe_timeout_seconds,
                salt,
                pid=pid,
                relay_metrics_url=args.relay_metrics_url,
                timestamp=utc_timestamp(),
                probe_due=probe_due,
                http_timeout_seconds=args.http_timeout_seconds,
                ping_runner=run_ping,
                process_reader=read_process_resources,
            )
            output.write(json.dumps(row, separators=(",", ":"), sort_keys=True) + "\n")
            output.flush()
            if (args.samples and sample >= args.samples) or stopped_by_signal:
                break
            next_sample += args.sample_interval_seconds
            delay = next_sample - time.monotonic()
            if args.duration_seconds:
                delay = min(delay, max(0.0, args.duration_seconds - (time.monotonic() - start)))
            if delay > 0 and not stopped_by_signal:
                time.sleep(delay)
            elif delay <= 0:
                next_sample = time.monotonic() + args.sample_interval_seconds
            if stopped_by_signal:
                break
    except KeyboardInterrupt:
        stopped_by_signal = True
    finally:
        elapsed = max(0.0, time.monotonic() - start)
        output.write(
            json.dumps(
                {"event": "monitor_stopped", "elapsed_seconds": round(elapsed, 3)},
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        )
        output.close()
        for signum, handler in prior_handlers.items():
            signal.signal(signum, handler)
    return 0


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    return collect(args)


if __name__ == "__main__":
    raise SystemExit(main())
