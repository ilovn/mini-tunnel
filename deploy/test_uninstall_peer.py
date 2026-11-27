from __future__ import annotations

import os
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


if __name__ == "__main__":
    unittest.main()
