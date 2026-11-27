from __future__ import annotations

import os
import platform
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("uninstall-peer.sh")
NETWORK_ID = "81af0d3b-be18-4b8f-976e-2b2a37ddfbc9"


class UninstallPeerPlanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="mini-tunnel-uninstall-test-")
        self.root = Path(self.temp.name)
        self.etc = self.root / "etc"
        self.state = self.root / "state"
        self.etc.mkdir()
        self.environment = os.environ.copy()
        self.environment["MINI_TUNNEL_UNINSTALL_ETC_DIR"] = str(self.etc)
        self.environment["MINI_TUNNEL_UNINSTALL_STATE_DIR"] = str(self.state)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def run_plan(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(SCRIPT), *arguments, "--dry-run"],
            check=False,
            capture_output=True,
            text=True,
            env=self.environment,
        )

    def test_default_plan_is_scoped_and_preserves_shared_state(self) -> None:
        result = self.run_plan("--instance", "office")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("mini-tunnel-peer@office.service", result.stdout)
        self.assertIn(str(self.etc / "peer-office.env"), result.stdout)
        self.assertIn("preserve shared binary, service account, device identity and network memberships", result.stdout)
        self.assertNotIn("Would remove only", result.stdout)

    def test_membership_plan_removes_only_selected_network_record(self) -> None:
        (self.etc / "peer-office.env").write_text(f"NETWORK_ID={NETWORK_ID}\n", encoding="ascii")
        result = self.run_plan("--instance", "office", "--remove-membership")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(str(self.state / "networks" / f"{NETWORK_ID}.json"), result.stdout)
        self.assertNotIn("Would permanently remove", result.stdout)

    def test_membership_removal_refuses_another_configured_instance_on_same_network(self) -> None:
        (self.etc / "peer-office.env").write_text(f"NETWORK_ID={NETWORK_ID}\n", encoding="ascii")
        (self.etc / "peer-backup.env").write_text(f"NETWORK_ID={NETWORK_ID.upper()}\n", encoding="ascii")
        result = self.run_plan("--instance", "office", "--remove-membership")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("another configured instance", result.stderr)

    def test_invalid_instance_and_unscoped_yes_are_rejected(self) -> None:
        invalid = self.run_plan("--instance", "../office")
        self.assertNotEqual(invalid.returncode, 0)
        self.assertIn("invalid instance name", invalid.stderr)

        unscoped_yes = subprocess.run(
            ["bash", str(SCRIPT), "--yes", "--dry-run"],
            check=False,
            capture_output=True,
            text=True,
            env=self.environment,
        )
        self.assertNotEqual(unscoped_yes.returncode, 0)
        self.assertIn("only valid with --remove-membership", unscoped_yes.stderr)

    def test_script_has_valid_bash_syntax(self) -> None:
        result = subprocess.run(
            ["bash", "-n", str(SCRIPT)], check=False, capture_output=True, text=True
        )
        self.assertEqual(result.returncode, 0, result.stderr)


@unittest.skipUnless(platform.system() == "Linux", "requires Linux path semantics")
class UninstallPeerExecutionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.sudo = shutil.which("sudo")
        if os.geteuid() != 0:
            if not cls.sudo:
                raise unittest.SkipTest("sudo is unavailable")
            probe = subprocess.run([cls.sudo, "-n", "true"], check=False)
            if probe.returncode:
                raise unittest.SkipTest("passwordless sudo is unavailable")

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="mini-tunnel-uninstall-exec-")
        self.root = Path(self.temp.name)
        self.etc = self.root / "etc"
        self.state = self.root / "state"
        self.systemd = self.root / "run" / "systemd" / "system"
        self.bin_dir = self.root / "fake-bin"
        for directory in (self.etc, self.state / "networks", self.systemd, self.bin_dir):
            directory.mkdir(parents=True, exist_ok=True)
        fake_systemctl = self.bin_dir / "systemctl"
        fake_systemctl.write_text(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$SYSTEMCTL_LOG\"\nexit 0\n",
            encoding="ascii",
        )
        fake_systemctl.chmod(0o755)
        source = SCRIPT.read_text(encoding="utf-8")
        source = source.replace("/etc/mini-tunnel", str(self.etc))
        source = source.replace("/var/lib/mini-tunnel", str(self.state))
        source = source.replace("/run/systemd/system", str(self.systemd))
        self.test_script = self.root / "uninstall-peer.sh"
        self.test_script.write_text(source, encoding="utf-8")
        self.test_script.chmod(0o755)
        self.systemctl_log = self.root / "systemctl.log"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def run_uninstaller(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        command = [
            "env",
            f"PATH={self.bin_dir}:/usr/bin:/bin",
            f"SYSTEMCTL_LOG={self.systemctl_log}",
            "bash",
            str(self.test_script),
            *arguments,
        ]
        if os.geteuid() == 0:
            argv = command
        else:
            assert self.sudo
            argv = [self.sudo, "-n", *command]
        return subprocess.run(argv, check=False, capture_output=True, text=True)

    def write_instance(self, name: str, network_id: str = NETWORK_ID) -> None:
        (self.etc / f"peer-{name}.env").write_text(
            f"NETWORK_ID={network_id}\n", encoding="ascii"
        )
        (self.etc / f"coordinator-ca-{name}.pem").write_text(
            "test ca\n", encoding="ascii"
        )

    def test_default_uninstall_keeps_all_shared_state_and_only_disables_target_instance(self) -> None:
        self.write_instance("office")
        self.write_instance("backup", "3c61c999-d5a3-4d33-a73a-23887e8fcacf")
        membership = self.state / "networks" / f"{NETWORK_ID}.json"
        membership.write_text("office membership\n", encoding="ascii")
        (self.state / "device.key").write_text("identity\n", encoding="ascii")
        (self.state / "coordinator-state.json").write_text("coordinator\n", encoding="ascii")

        result = self.run_uninstaller("--instance", "office")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.etc / "peer-office.env").exists())
        self.assertFalse((self.etc / "coordinator-ca-office.pem").exists())
        self.assertTrue((self.etc / "peer-backup.env").exists())
        self.assertTrue(membership.exists())
        self.assertTrue((self.state / "device.key").exists())
        self.assertTrue((self.state / "coordinator-state.json").exists())
        self.assertEqual(
            self.systemctl_log.read_text(encoding="ascii").splitlines(),
            ["disable --now mini-tunnel-peer@office.service", "daemon-reload"],
        )

    def test_opt_in_removes_only_selected_membership_and_preserves_coordinator_state(
        self,
    ) -> None:
        self.write_instance("office")
        self.write_instance("backup", "3c61c999-d5a3-4d33-a73a-23887e8fcacf")
        selected = self.state / "networks" / f"{NETWORK_ID}.json"
        unrelated = self.state / "networks" / "3c61c999-d5a3-4d33-a73a-23887e8fcacf.json"
        selected.write_text("office membership\n", encoding="ascii")
        unrelated.write_text("other membership\n", encoding="ascii")
        (self.state / "device.key").write_text("identity\n", encoding="ascii")
        (self.state / "coordinator-state.json").write_text("coordinator\n", encoding="ascii")

        result = self.run_uninstaller("--instance", "office", "--remove-membership", "--yes")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(selected.exists())
        self.assertTrue(unrelated.exists())
        self.assertTrue((self.state / "device.key").exists())
        self.assertTrue((self.state / "coordinator-state.json").exists())

    def test_same_network_conflict_leaves_service_config_and_membership_untouched(self) -> None:
        self.write_instance("office")
        self.write_instance("backup", NETWORK_ID.upper())
        membership = self.state / "networks" / f"{NETWORK_ID}.json"
        membership.write_text("office membership\n", encoding="ascii")

        result = self.run_uninstaller("--instance", "office", "--remove-membership", "--yes")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("another configured instance", result.stderr)
        self.assertTrue((self.etc / "peer-office.env").exists())
        self.assertTrue(membership.exists())
        self.assertFalse(self.systemctl_log.exists())


if __name__ == "__main__":
    unittest.main()
