from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent
SCRIPT = ROOT / "quick-install-peer.sh"


class QuickInstallPeerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="mini-tunnel-quick-install-test-")
        self.root = Path(self.temp.name)
        self.fake_deploy = self.root / "deploy"
        self.fake_deploy.mkdir()
        shutil.copy2(SCRIPT, self.fake_deploy / SCRIPT.name)
        self.download_log = self.root / "download.json"
        self.install_log = self.root / "install.json"
        (self.fake_deploy / "download-peer.sh").write_text(
            """#!/usr/bin/env python3
import json, os, pathlib, sys
args = sys.argv[1:]
pathlib.Path(os.environ["DOWNLOAD_LOG"]).write_text(json.dumps(args))
output = pathlib.Path(args[args.index("--output-dir") + 1])
output.mkdir(parents=True)
binary = output / "mini-tunnel"
binary.write_text("#!/bin/sh\\nexit 0\\n")
binary.chmod(0o755)
if os.environ.get("FAIL_DOWNLOAD") == "1":
    raise SystemExit(23)
""",
            encoding="utf-8",
        )
        (self.fake_deploy / "install-peer.sh").write_text(
            """#!/usr/bin/env python3
import json, os, pathlib, sys
args = sys.argv[1:]
binary = pathlib.Path(args[args.index("--binary") + 1])
assert binary.is_file() and os.access(binary, os.X_OK)
pathlib.Path(os.environ["INSTALL_LOG"]).write_text(json.dumps(args))
""",
            encoding="utf-8",
        )
        for path in self.fake_deploy.iterdir():
            path.chmod(0o755)
        self.fake_bin = self.root / "bin"
        self.fake_bin.mkdir()
        sudo = self.fake_bin / "sudo"
        sudo.write_text("#!/bin/sh\nexec \"$@\"\n", encoding="utf-8")
        sudo.chmod(0o755)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def run_script(self, *args: str, **extra_env: str) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env["PATH"] = f"{self.fake_bin}{os.pathsep}{env['PATH']}"
        env["DOWNLOAD_LOG"] = str(self.download_log)
        env["INSTALL_LOG"] = str(self.install_log)
        env.update(extra_env)
        return subprocess.run(
            [str(self.fake_deploy / SCRIPT.name), *args],
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )

    def test_download_and_installer_arguments_are_forwarded_without_reordering(self) -> None:
        result = self.run_script(
            "--repo",
            "ilovn/mini-tunnel",
            "--arch",
            "aarch64",
            "--commit",
            "0" * 40,
            "--",
            "--network-id",
            "00000000-0000-0000-0000-000000000000",
            "--coordinator-url",
            "https://coordinator.example",
            "--invite-token-file",
            "/tmp/invite.token",
            "--instance",
            "office",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        download_args = json.loads(self.download_log.read_text(encoding="utf-8"))
        self.assertEqual(download_args[0], "--output-dir")
        self.assertEqual(
            download_args[2:],
            ["--repo", "ilovn/mini-tunnel", "--arch", "aarch64", "--commit", "0" * 40],
        )
        install_args = json.loads(self.install_log.read_text(encoding="utf-8"))
        self.assertEqual(install_args[0], "--binary")
        self.assertTrue(install_args[1].endswith("/download/mini-tunnel"))
        self.assertEqual(
            install_args[2:],
            [
                "--network-id",
                "00000000-0000-0000-0000-000000000000",
                "--coordinator-url",
                "https://coordinator.example",
                "--invite-token-file",
                "/tmp/invite.token",
                "--instance",
                "office",
            ],
        )
        self.assertFalse(Path(install_args[1]).exists(), "temporary download is removed")

    def test_failed_download_never_invokes_the_installer_or_prints_token(self) -> None:
        result = self.run_script(
            "--release",
            "v1.2.3",
            "--",
            "--network-id",
            "00000000-0000-0000-0000-000000000000",
            FAIL_DOWNLOAD="1",
            GITHUB_TOKEN="secret-token-must-not-be-printed",
        )
        self.assertEqual(result.returncode, 23)
        self.assertFalse(self.install_log.exists())
        self.assertNotIn("secret-token-must-not-be-printed", result.stdout + result.stderr)

    def test_rejects_installer_binary_override_before_download(self) -> None:
        result = self.run_script("--", "--binary", "/tmp/attacker-binary")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.download_log.exists())
        self.assertFalse(self.install_log.exists())


if __name__ == "__main__":
    unittest.main()
