from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from unittest.mock import patch

from analyze_soak import analyze_file
import soak_monitor
from soak_monitor import (
    MonitorError,
    anonymize_peer_id,
    build_sample,
    fetch_relay_metrics,
    fetch_status,
    open_private_output,
    parse_args,
    parse_ping_output,
    parse_prometheus_metrics,
    read_process_resources,
    validate_loopback_url,
    validate_probe_destination,
)


ROOT = Path(__file__).resolve().parent


class SoakMonitorTests(unittest.TestCase):
    def test_loopback_endpoints_and_private_overlay_targets_are_enforced(self) -> None:
        self.assertEqual(
            validate_loopback_url("http://127.0.0.1:42003/status", "/status"),
            "http://127.0.0.1:42003/status",
        )
        self.assertEqual(
            validate_loopback_url("http://[::1]:42003/status", "/status"),
            "http://[::1]:42003/status",
        )
        for value in (
            "https://127.0.0.1:42003/status",
            "http://192.168.1.2:42003/status",
            "http://127.0.0.1:42003/status?token=secret",
            "http://127.0.0.1:42003/metrics",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_loopback_url(value, "/status")
        self.assertEqual(validate_probe_destination("10.10.10.2"), "10.10.10.2")
        self.assertEqual(validate_probe_destination("fd00::2"), "fd00::2")
        for value in ("8.8.8.8", "127.0.0.1", "169.254.1.2", "bad-ip"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_probe_destination(value)

    def test_status_is_whitelisted_and_peer_id_is_anonymized(self) -> None:
        raw = json.dumps(
            [
                {
                    "peer": "sensitive-peer-id",
                    "online": True,
                    "active_path": "Relay/TLS",
                    "remote_address": "203.0.113.4:42000",
                    "last_switch_reason": "private diagnostic",
                }
            ]
        ).encode()
        peers, error = fetch_status(
            "http://127.0.0.1:42003/status",
            b"test-only-salt",
            body_reader=lambda _url, _timeout: raw,
        )
        self.assertIsNone(error)
        self.assertEqual(
            peers,
            [
                {
                    "peer": anonymize_peer_id("sensitive-peer-id", b"test-only-salt"),
                    "online": True,
                    "active_path": "Relay/TLS",
                }
            ],
        )
        serialized = json.dumps(peers)
        self.assertNotIn("sensitive-peer-id", serialized)
        self.assertNotIn("203.0.113.4", serialized)
        self.assertNotIn("private diagnostic", serialized)

    def test_failed_http_response_records_only_stable_error_code(self) -> None:
        def failing_reader(_url: str, _timeout: float) -> bytes:
            raise MonitorError("http_unavailable")

        peers, error = fetch_status(
            "http://127.0.0.1:42003/status",
            b"salt",
            body_reader=failing_reader,
        )
        self.assertEqual(peers, [])
        self.assertEqual(error, "http_unavailable")

        metrics, metrics_error = fetch_relay_metrics(
            "http://127.0.0.1:42002/metrics",
            body_reader=failing_reader,
        )
        self.assertIsNone(metrics)
        self.assertEqual(metrics_error, "http_unavailable")

    def test_malformed_status_is_not_partially_accepted(self) -> None:
        peers, error = fetch_status(
            "http://127.0.0.1:42003/status",
            b"salt",
            body_reader=lambda _url, _timeout: json.dumps(
                [
                    {"peer": "good", "online": True, "active_path": "QUIC/UDP"},
                    {"peer": "bad", "online": "yes", "active_path": "QUIC/UDP"},
                ]
            ).encode(),
        )
        self.assertEqual(peers, [])
        self.assertEqual(error, "invalid_status")

    def test_ping_and_prometheus_parsers_keep_only_expected_values(self) -> None:
        self.assertEqual(
            parse_ping_output(
                "5 packets transmitted, 4 received, 20% packet loss, time 4000ms", 5
            ),
            {"sent": 5, "received": 4},
        )
        self.assertEqual(
            parse_ping_output("3 packets transmitted, 2 received, 33% packet loss", 5),
            {"sent": 3, "received": 2},
        )
        self.assertEqual(
            parse_ping_output("64 bytes from 10.10.10.2: icmp_seq=1 ttl=64", 5),
            {"sent": 5, "received": 1},
        )
        metrics = parse_prometheus_metrics(
            "mini_tunnel_relay_active_connections 2\n"
            "mini_tunnel_relay_active_sessions 1\n"
            "mini_tunnel_relay_handshake_failures_total 3\n"
            "mini_tunnel_relay_bytes_forwarded_total 1024\n"
            "private_metric{peer=\"secret\"} 99\n"
            "mini_tunnel_relay_active_sessions NaN\n"
        )
        self.assertEqual(
            metrics,
            {
                "mini_tunnel_relay_active_connections": 2,
                "mini_tunnel_relay_active_sessions": 1,
                "mini_tunnel_relay_handshake_failures_total": 3,
                "mini_tunnel_relay_bytes_forwarded_total": 1024,
            },
        )
        partial, error = fetch_relay_metrics(
            "http://127.0.0.1:42002/metrics",
            body_reader=lambda _url, _timeout: b"mini_tunnel_relay_active_sessions 1\n",
        )
        self.assertIsNone(partial)
        self.assertEqual(error, "invalid_metrics")

    def test_ping_command_errors_are_invalid_probe_rounds_not_remote_output(self) -> None:
        with patch.object(
            soak_monitor.subprocess,
            "run",
            return_value=soak_monitor.subprocess.CompletedProcess(
                args=[], returncode=2, stdout="secret command output", stderr="private error"
            ),
        ) as run:
            result = soak_monitor.run_ping("10.10.10.2", 5, 1.0)
        self.assertEqual(result, {"sent": 0, "received": 0})
        self.assertEqual(run.call_args.args[0][-1], "10.10.10.2")
        self.assertNotIn("secret", json.dumps(result))

    def test_process_resources_read_from_proc_without_copying_process_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            process = root / "42"
            (process / "fd").mkdir(parents=True)
            (process / "status").write_text(
                "Name:\tmini-tunnel\nVmRSS:\t4096 kB\nThreads:\t7\n",
                encoding="ascii",
            )
            (process / "fd" / "0").touch()
            (process / "fd" / "1").touch()
            self.assertEqual(
                read_process_resources(42, root),
                {"pid": 42, "rss_kib": 4096, "threads": 7, "fds": 2},
            )
            self.assertEqual(
                read_process_resources(43, root),
                {"pid": 0, "rss_kib": None, "threads": None, "fds": None},
            )
            incomplete = root / "44"
            (incomplete / "fd").mkdir(parents=True)
            (incomplete / "status").write_text("Threads:\t1\n", encoding="ascii")
            self.assertEqual(
                read_process_resources(44, root),
                {"pid": 0, "rss_kib": None, "threads": None, "fds": None},
            )

    @unittest.skipUnless(hasattr(os, "getuid"), "private owner check requires Unix")
    def test_output_is_private_and_refuses_symlink_or_hard_link(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "soak.jsonl"
            with open_private_output(path) as output:
                output.write("{}\n")
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            with self.assertRaises(OSError):
                open_private_output(path)

            link = Path(directory) / "symlink.jsonl"
            link.symlink_to(path)
            with self.assertRaises(OSError):
                open_private_output(link)

            second = Path(directory) / "hardlink.jsonl"
            os.link(path, second)
            with self.assertRaises(OSError):
                open_private_output(second)

    def test_emitted_jsonl_round_trips_through_soak_analyzer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "gz.jsonl"
            salt = b"per-run-test-salt"
            statuses = json.dumps(
                [{"peer": "peer-secret", "online": True, "active_path": "Relay/TLS"}]
            ).encode()
            metrics = (
                "mini_tunnel_relay_active_connections 2\n"
                "mini_tunnel_relay_active_sessions 1\n"
                "mini_tunnel_relay_handshake_failures_total 0\n"
                "mini_tunnel_relay_bytes_forwarded_total 1024\n"
            ).encode()

            def body_reader(url: str, _timeout: float) -> bytes:
                return metrics if url.endswith("/metrics") else statuses

            rows = []
            for sample in range(1, 4):
                rows.append(
                    build_sample(
                        sample,
                        "gz",
                        "http://127.0.0.1:42003/status",
                        "10.10.10.2",
                        5,
                        1.0,
                        salt,
                        pid=42,
                        relay_metrics_url="http://127.0.0.1:42002/metrics",
                        body_reader=body_reader,
                        ping_runner=lambda _destination, count, _timeout: {
                            "sent": count,
                            "received": count,
                        },
                        process_reader=lambda pid: {
                            "pid": pid,
                            "rss_kib": 2048,
                            "threads": 3,
                            "fds": 12,
                        },
                        timestamp=f"2026-01-01T00:00:{(sample - 1) * 10:02d}Z",
                    )
                )

            with open_private_output(path) as output:
                for row in rows:
                    output.write(json.dumps(row) + "\n")
                output.write(json.dumps({"event": "monitor_stopped", "elapsed_seconds": 30}) + "\n")

            report = analyze_file(
                path,
                sample_interval_seconds=10,
                max_sample_gap_seconds=15,
                probe_interval_seconds=10,
                probe_jitter_seconds=0,
                max_probe_loss_percent=0,
                minimum_duration_seconds=30,
                minimum_probe_rounds=3,
            )
            self.assertTrue(report["passed"], report["failures"])
            self.assertEqual(report["probe_packets_received"], 15)
            self.assertEqual(report["relay_metrics"]["bytes_forwarded_increase"], 0)
            saved = path.read_text(encoding="utf-8")
            self.assertNotIn("peer-secret", saved)
            self.assertNotIn("127.0.0.1:42003", saved)

    def test_collector_writes_private_stopped_jsonl_record(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "run.jsonl"
            status_body = json.dumps(
                [
                    {
                        "peer": "peer-secret",
                        "online": True,
                        "active_path": "Relay/TLS",
                        "remote_address": "198.51.100.9:42000",
                    }
                ]
            ).encode()
            metrics_body = (
                "mini_tunnel_relay_active_connections 2\n"
                "mini_tunnel_relay_active_sessions 1\n"
                "mini_tunnel_relay_handshake_failures_total 0\n"
                "mini_tunnel_relay_bytes_forwarded_total 1024\n"
            ).encode()

            class Handler(BaseHTTPRequestHandler):
                def do_GET(self) -> None:
                    body = {
                        "/status": status_body,
                        "/metrics": metrics_body,
                    }.get(self.path)
                    if body is None:
                        self.send_error(404)
                        return
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

                def log_message(self, _format: str, *_args: object) -> None:
                    return

            server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            port = server.server_address[1]
            args = parse_args(
                [
                    "--side",
                    "gz",
                    "--status-url",
                    f"http://127.0.0.1:{port}/status",
                    "--relay-metrics-url",
                    f"http://127.0.0.1:{port}/metrics",
                    "--pid",
                    "42",
                    "--probe-destination",
                    "10.10.10.2",
                    "--samples",
                    "1",
                    "--output",
                    str(path),
                ]
            )
            with (
                patch.object(soak_monitor.sys, "platform", "linux"),
                patch.object(
                    soak_monitor,
                    "run_ping",
                    return_value={"sent": 5, "received": 5},
                ),
                patch.object(
                    soak_monitor,
                    "read_process_resources",
                    return_value={"pid": 42, "rss_kib": 2048, "threads": 3, "fds": 12},
                ),
            ):
                try:
                    self.assertEqual(soak_monitor.collect(args), 0)
                finally:
                    server.shutdown()
                    server.server_close()
                    thread.join(timeout=2)

            records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
            self.assertIsNone(records[0]["status_error"])
            self.assertEqual(records[0]["status"][0]["active_path"], "Relay/TLS")
            self.assertEqual(records[0]["probe"], {"sent": 5, "received": 5})
            self.assertEqual(
                records[0]["relay"]["mini_tunnel_relay_active_sessions"], 1
            )
            self.assertEqual(records[-1]["event"], "monitor_stopped")
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            report = analyze_file(
                path,
                sample_interval_seconds=1,
                max_sample_gap_seconds=2,
                probe_interval_seconds=300,
                probe_jitter_seconds=0,
                max_probe_loss_percent=0,
                minimum_duration_seconds=0,
                minimum_probe_rounds=1,
            )
            self.assertTrue(report["passed"], report["failures"])
            serialized = path.read_text(encoding="utf-8")
            self.assertNotIn("peer-secret", serialized)
            self.assertNotIn("198.51.100.9", serialized)
            self.assertNotIn(f"127.0.0.1:{port}", serialized)


if __name__ == "__main__":
    unittest.main()
