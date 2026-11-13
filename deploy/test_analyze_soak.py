from __future__ import annotations

import datetime as dt
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from analyze_soak import analyze_file


ROOT = Path(__file__).resolve().parent
TOOL = ROOT / "analyze_soak.py"
UTC = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)


def row(
    sample: int,
    seconds: int,
    *,
    online: bool = True,
    path: str = "QUIC/UDP",
    probe: dict[str, int] | None = None,
    status_error: str | None = None,
) -> dict[str, object]:
    result: dict[str, object] = {
        "timestamp_utc": (UTC + dt.timedelta(seconds=seconds)).isoformat(),
        "sample": sample,
        "side": "gz",
        "status": [
            {
                "peer": "private-peer-id",
                "online": online,
                "active_path": path,
            }
        ],
        "status_error": status_error,
        "probe": probe,
        "peer_process": {"pid": 123, "rss_kib": 2048, "threads": 3, "fds": 12},
    }
    return result


def write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.write_text("".join(json.dumps(item) + "\n" for item in rows), encoding="utf-8")


class AnalyzeSoakTests(unittest.TestCase):
    def analyze(
        self,
        path: Path,
        *,
        min_duration: float = 0,
        min_probes: int = 0,
        probe_jitter: float = 10,
    ):
        return analyze_file(
            path,
            sample_interval_seconds=10,
            max_sample_gap_seconds=15,
            probe_interval_seconds=10,
            probe_jitter_seconds=probe_jitter,
            max_probe_loss_percent=0,
            minimum_duration_seconds=min_duration,
            minimum_probe_rounds=min_probes,
        )

    def test_accepts_complete_clean_run_and_reports_resources(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "clean.jsonl"
            write_jsonl(
                path,
                [
                    row(1, 0, probe={"sent": 5, "received": 5}),
                    row(2, 10, probe={"sent": 5, "received": 5}),
                    row(3, 20, probe={"sent": 5, "received": 5}),
                    {"event": "monitor_stopped", "elapsed_seconds": 30},
                ],
            )
            report = self.analyze(path, min_duration=30, min_probes=3)
        self.assertTrue(report["passed"])
        self.assertEqual(report["expected_samples"], 3)
        self.assertEqual(report["probe_packets_received"], 15)
        self.assertEqual(
            report["peer_process_resources"]["rss_kib"],
            {"min": 2048, "max": 2048, "first": 2048, "last": 2048, "delta": 0},
        )

    def test_rejects_offline_probe_loss_sample_gap_and_status_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "failed.jsonl"
            write_jsonl(
                path,
                [
                    row(1, 0, online=False, probe={"sent": 5, "received": 0}),
                    row(3, 20, status_error="sensitive token should not be echoed"),
                    {"event": "monitor_stopped", "elapsed_seconds": 30},
                ],
            )
            report = self.analyze(path, min_duration=30, min_probes=2)
            result = subprocess.run(
                [sys.executable, str(TOOL), "--input", str(path)],
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertFalse(report["passed"])
        self.assertEqual(report["status_errors"], 1)
        self.assertIn("offline_peer_samples", report["failures"])
        self.assertIn("probe_packet_loss", report["failures"])
        self.assertIn("missing_samples", report["failures"])
        self.assertIn("status_errors", report["failures"])
        self.assertNotIn("sensitive token", result.stdout)
        self.assertNotIn("private-peer-id", result.stdout)

    def test_counts_path_transition_without_failing_healthy_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "paths.jsonl"
            write_jsonl(
                path,
                [
                    row(1, 0, path="QUIC/UDP", probe={"sent": 5, "received": 5}),
                    row(2, 10, path="Relay/TLS", probe={"sent": 5, "received": 5}),
                    row(3, 20, path="QUIC/UDP", probe={"sent": 5, "received": 5}),
                    {"event": "monitor_stopped", "elapsed_seconds": 30},
                ],
            )
            report = self.analyze(path, min_duration=30, min_probes=3)
        self.assertTrue(report["passed"])
        self.assertEqual(report["path_transitions"], 2)
        self.assertEqual(report["observed_paths"], ["QUIC/UDP", "Relay/TLS"])
        self.assertEqual(
            report["path_transition_events"],
            [
                {
                    "timestamp_utc": (UTC + dt.timedelta(seconds=10)).isoformat(),
                    "from_path": "QUIC/UDP",
                    "to_path": "Relay/TLS",
                },
                {
                    "timestamp_utc": (UTC + dt.timedelta(seconds=20)).isoformat(),
                    "from_path": "Relay/TLS",
                    "to_path": "QUIC/UDP",
                },
            ],
        )

    def test_reports_consecutive_offline_intervals_without_peer_ids(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "offline-intervals.jsonl"
            multiple_offline_peers = row(2, 10, online=False)
            multiple_status = multiple_offline_peers["status"]
            assert isinstance(multiple_status, list)
            multiple_status.append(
                {
                    "peer": "another-private-peer-id",
                    "online": False,
                    "active_path": "QUIC/UDP",
                }
            )
            write_jsonl(
                path,
                [
                    row(1, 0),
                    multiple_offline_peers,
                    row(3, 20, online=False),
                    row(4, 30, path="Relay/TLS"),
                    row(5, 40, online=False),
                    row(7, 60, online=False),
                    row(8, 70, path="QUIC/UDP"),
                    {"event": "monitor_stopped", "elapsed_seconds": 80},
                ],
            )
            report = self.analyze(path, min_duration=80)
            result = subprocess.run(
                [sys.executable, str(TOOL), "--input", str(path)],
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertEqual(
            report["offline_intervals"],
            [
                {
                    "start_timestamp_utc": (UTC + dt.timedelta(seconds=10)).isoformat(),
                    "end_timestamp_utc": (UTC + dt.timedelta(seconds=20)).isoformat(),
                    "sample_count": 2,
                    "offline_peer_samples": 3,
                    "max_offline_peers": 2,
                    "observed_span_seconds": 10.0,
                },
                {
                    "start_timestamp_utc": (UTC + dt.timedelta(seconds=40)).isoformat(),
                    "end_timestamp_utc": (UTC + dt.timedelta(seconds=40)).isoformat(),
                    "sample_count": 1,
                    "offline_peer_samples": 1,
                    "max_offline_peers": 1,
                    "observed_span_seconds": 0.0,
                },
                {
                    "start_timestamp_utc": (UTC + dt.timedelta(seconds=60)).isoformat(),
                    "end_timestamp_utc": (UTC + dt.timedelta(seconds=60)).isoformat(),
                    "sample_count": 1,
                    "offline_peer_samples": 1,
                    "max_offline_peers": 1,
                    "observed_span_seconds": 0.0,
                },
            ],
        )
        self.assertNotIn("private-peer-id", result.stdout)
        self.assertNotIn("another-private-peer-id", result.stdout)

    def test_counts_malformed_and_non_object_lines(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "malformed.jsonl"
            path.write_text(
                json.dumps(row(1, 0, probe={"sent": 5, "received": 5}))
                + "\nsecret-token=do-not-print\n[]\n",
                encoding="utf-8",
            )
            report = self.analyze(path)
            result = subprocess.run(
                [sys.executable, str(TOOL), "--input", str(path)],
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertEqual(report["malformed_lines"], 1)
        self.assertEqual(report["non_object_lines"], 1)
        self.assertFalse(report["passed"])
        self.assertNotIn("secret-token", result.stdout)
        self.assertEqual(result.returncode, 1)

    def test_rejects_empty_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "empty.jsonl"
            path.write_text("", encoding="utf-8")
            report = self.analyze(path)
        self.assertEqual(report["samples"], 0)
        self.assertIn("no_samples", report["failures"])

    def test_rejects_missing_round_with_fixed_probe_schedule(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "missing-probe.jsonl"
            write_jsonl(
                path,
                [
                    row(1, 0, probe={"sent": 5, "received": 5}),
                    row(2, 10),
                    row(3, 20, probe={"sent": 5, "received": 5}),
                    {"event": "monitor_stopped", "elapsed_seconds": 30},
                ],
            )
            report = self.analyze(path, min_duration=30, probe_jitter=0)
        self.assertIn("missing_probe_rounds", report["failures"])

    def test_rejects_duplicate_sample_numbers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.jsonl"
            write_jsonl(
                path,
                [
                    row(1, 0, probe={"sent": 5, "received": 5}),
                    row(1, 10),
                    row(3, 20),
                    {"event": "monitor_stopped", "elapsed_seconds": 30},
                ],
            )
            report = self.analyze(path, min_duration=30)
        self.assertEqual(report["duplicate_samples"], 1)
        self.assertIn("duplicate_samples", report["failures"])

    def test_rejects_non_finite_json_numbers_without_crashing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "non-finite.jsonl"
            write_jsonl(
                path,
                [
                    row(1, 0, probe={"sent": float("nan"), "received": 0}),
                    {"event": "monitor_stopped", "elapsed_seconds": float("inf")},
                ],
            )
            result = subprocess.run(
                [sys.executable, str(TOOL), "--input", str(path)],
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn("failed_probe_rounds", result.stdout)
        self.assertNotIn("Traceback", result.stderr)

    def test_allows_probe_tick_jitter_from_ten_second_sampler(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "probe-jitter.jsonl"
            rows = [
                row(index + 1, index * 10, probe={"sent": 5, "received": 5} if index in (0, 31) else None)
                for index in range(63)
            ]
            rows.append({"event": "monitor_stopped", "elapsed_seconds": 620})
            write_jsonl(path, rows)
            report = analyze_file(
                path,
                sample_interval_seconds=10,
                max_sample_gap_seconds=15,
                probe_interval_seconds=300,
                probe_jitter_seconds=10,
                max_probe_loss_percent=0,
                minimum_duration_seconds=620,
                minimum_probe_rounds=2,
            )
        self.assertTrue(report["passed"], report["failures"])
        self.assertEqual(report["expected_probe_rounds"], 2)

    def test_rejects_missing_process_and_configured_resource_limit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "resource.jsonl"
            sample = row(1, 0, probe={"sent": 5, "received": 5})
            del sample["peer_process"]
            write_jsonl(path, [sample])
            report = self.analyze(path)
            limited = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--input",
                    str(path),
                    "--max-rss-kib",
                    "1",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertIn("missing_process_samples", report["failures"])
        self.assertEqual(limited.returncode, 1)
        self.assertIn("max_rss_kib_exceeded", limited.stdout)


if __name__ == "__main__":
    unittest.main()
