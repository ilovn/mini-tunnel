from __future__ import annotations

import fcntl
import json
import os
import signal
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import upgrade_peer
from upgrade_peer import UpgradeConfig, UpgradeError, upgrade


class UpgradePeerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="mini-tunnel-upgrade-test-")
        self.root = Path(self.temp.name)
        self.bin_dir = self.root / "bin"
        self.bin_dir.mkdir()
        self.target = self.bin_dir / "mini-tunnel"
        self.target.write_text("old-binary", encoding="ascii")
        self.target.chmod(0o755)
        self.candidate = self.root / "downloaded-mini-tunnel"
        self.candidate.write_text("new-binary", encoding="ascii")
        self.candidate.chmod(0o755)
        self.config_dir = self.root / "etc"
        self.config_dir.mkdir()
        self.env_file = self.config_dir / "peer-office.env"
        self.env_file.write_text(
            "NETWORK_ID=00000000-0000-0000-0000-000000000000\n"
            "MINI_TUNNEL_STATUS_LISTEN=127.0.0.1:42123\n",
            encoding="ascii",
        )
        self.env_file.chmod(0o640)
        self.backup_dir = self.root / "backups"
        self.staging_dir = self.root / "staging"
        self.lock_dir = self.root / "locks"
        self.commands: list[list[str]] = []
        self.restarts = 0
        self.restart_failures: set[int] = set()
        self.fail_new_health = False
        self.interrupt_on_restart = False

        def runner(command: list[str], *, timeout: float) -> subprocess.CompletedProcess[str]:
            del timeout
            self.commands.append(command)
            if command[:3] == ["systemctl", "is-active", "--quiet"]:
                return subprocess.CompletedProcess(command, 0, "active\n", "")
            if command[:2] == ["systemctl", "restart"]:
                self.restarts += 1
                if self.interrupt_on_restart and self.restarts == 1:
                    os.kill(os.getpid(), signal.SIGTERM)
                if self.restarts in self.restart_failures:
                    return subprocess.CompletedProcess(command, 1, "", "restart failed")
                return subprocess.CompletedProcess(command, 0, "", "")
            if command[-1:] == ["--help"]:
                return subprocess.CompletedProcess(command, 0, "help", "")
            if command[-3:-1] == ["status", "--url"]:
                if self.fail_new_health and self.target.read_text(encoding="ascii") == "new-binary":
                    return subprocess.CompletedProcess(command, 1, "", "health failed")
                return subprocess.CompletedProcess(command, 0, json.dumps([]), "")
            raise AssertionError(f"unexpected command: {command}")

        self.runner = runner
        self.config = UpgradeConfig(
            instance="office",
            binary=self.candidate,
            binary_path=self.target,
            config_dir=self.config_dir,
            backup_dir=self.backup_dir,
            staging_dir=self.staging_dir,
            lock_dir=self.lock_dir,
            health_timeout_seconds=0.01,
            poll_interval_seconds=0.001,
            require_root_ownership=False,
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def run_upgrade(self) -> Path:
        return upgrade(self.config, self.runner, sleep=lambda _delay: None)

    def test_success_installs_candidate_and_preserves_previous_binary(self) -> None:
        backup = self.run_upgrade()
        self.assertEqual(self.target.read_text(encoding="ascii"), "new-binary")
        self.assertEqual(backup.read_text(encoding="ascii"), "old-binary")
        self.assertFalse(any(backup.parent.glob("candidate-*")))
        self.assertEqual(self.restarts, 1)
        self.assertTrue(self.env_file.exists())
        user_commands = [command for command in self.commands if command[0] == "runuser"]
        self.assertTrue(user_commands)
        self.assertTrue(all(command[1:4] == ["-u", "mini-tunnel", "--"] for command in user_commands))

    def test_failed_health_check_restores_previous_binary(self) -> None:
        self.fail_new_health = True
        with self.assertRaisesRegex(UpgradeError, "was rolled back"):
            self.run_upgrade()
        self.assertEqual(self.target.read_text(encoding="ascii"), "old-binary")
        self.assertEqual(self.restarts, 2)
        self.assertTrue(any(self.backup_dir.rglob("mini-tunnel-20*")))
        self.assertFalse(any(self.backup_dir.rglob("candidate-*")))

    def test_restart_failure_restores_previous_binary(self) -> None:
        self.restart_failures.add(1)
        with self.assertRaisesRegex(UpgradeError, "was rolled back"):
            self.run_upgrade()
        self.assertEqual(self.target.read_text(encoding="ascii"), "old-binary")
        self.assertEqual(self.restarts, 2)

    def test_failure_after_atomic_replace_still_rolls_back(self) -> None:
        original_install = upgrade_peer._atomic_install

        def replace_then_fail(source: Path, target: Path, metadata: os.stat_result) -> None:
            original_install(source, target, metadata)
            if source.read_text(encoding="ascii") == "new-binary":
                raise OSError("simulated directory fsync failure after replacement")

        with patch("upgrade_peer._atomic_install", side_effect=replace_then_fail):
            with self.assertRaisesRegex(UpgradeError, "was rolled back"):
                self.run_upgrade()
        self.assertEqual(self.target.read_text(encoding="ascii"), "old-binary")
        self.assertEqual(self.restarts, 1)

    def test_interruption_during_restart_restores_previous_binary(self) -> None:
        prior_handler = signal.getsignal(signal.SIGTERM)
        self.interrupt_on_restart = True
        with self.assertRaisesRegex(UpgradeError, "was rolled back"):
            self.run_upgrade()
        self.assertIs(signal.getsignal(signal.SIGTERM), prior_handler)
        self.assertEqual(self.target.read_text(encoding="ascii"), "old-binary")
        self.assertEqual(self.restarts, 2)

    def test_rollback_failure_preserves_old_and_candidate_binaries(self) -> None:
        self.fail_new_health = True
        self.restart_failures.update({1, 2})
        with self.assertRaisesRegex(UpgradeError, "automatic rollback also failed") as error:
            self.run_upgrade()
        self.assertEqual(self.target.read_text(encoding="ascii"), "old-binary")
        self.assertIn("candidate retained at", str(error.exception))
        self.assertTrue(any(self.backup_dir.rglob("mini-tunnel-20*")))
        self.assertTrue(any(self.backup_dir.rglob("candidate-*")))

    def test_refuses_stopped_or_unknown_instance_before_replacing(self) -> None:
        self.config = UpgradeConfig(**{**self.config.__dict__, "instance": "missing"})
        with self.assertRaisesRegex(UpgradeError, "not installed"):
            self.run_upgrade()
        self.assertEqual(self.target.read_text(encoding="ascii"), "old-binary")
        self.assertEqual(self.restarts, 0)

    def test_rejects_invalid_instance_candidate_and_non_loopback_status(self) -> None:
        invalid = UpgradeConfig(**{**self.config.__dict__, "instance": "../office"})
        with self.assertRaisesRegex(UpgradeError, "invalid instance"):
            upgrade(invalid, self.runner)

        non_executable = self.root / "not-executable"
        non_executable.write_text("x", encoding="ascii")
        non_executable.chmod(0o644)
        bad_candidate = UpgradeConfig(**{**self.config.__dict__, "binary": non_executable})
        with self.assertRaisesRegex(UpgradeError, "executable regular file"):
            upgrade(bad_candidate, self.runner)

        self.env_file.write_text("MINI_TUNNEL_STATUS_LISTEN=0.0.0.0:42123\n", encoding="ascii")
        with self.assertRaisesRegex(UpgradeError, "loopback"):
            self.run_upgrade()

    def test_refuses_inactive_service_without_creating_backups(self) -> None:
        original = self.runner

        def stopped_runner(command: list[str], *, timeout: float) -> subprocess.CompletedProcess[str]:
            if command[:3] == ["systemctl", "is-active", "--quiet"]:
                return subprocess.CompletedProcess(command, 3, "inactive\n", "")
            return original(command, timeout=timeout)

        with self.assertRaisesRegex(UpgradeError, "command failed"):
            upgrade(self.config, stopped_runner)
        self.assertEqual(self.target.read_text(encoding="ascii"), "old-binary")
        self.assertFalse(self.backup_dir.exists())

    def test_refuses_concurrent_upgrade_for_same_instance(self) -> None:
        self.lock_dir.mkdir(mode=0o755)
        lock_path = self.lock_dir / "mini-tunnel-upgrade-office.lock"
        descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(UpgradeError, "another upgrade is running"):
                self.run_upgrade()
        finally:
            os.close(descriptor)
        self.assertEqual(self.target.read_text(encoding="ascii"), "old-binary")
        self.assertEqual(self.restarts, 0)


if __name__ == "__main__":
    unittest.main()
