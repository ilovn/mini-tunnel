from __future__ import annotations

import os
import json
import plistlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent
INSTALLER = ROOT / "install-peer-macos.sh"
PLIST_WRITER = ROOT / "macos" / "write_launchd_plist.py"


class MacOSInstallerTests(unittest.TestCase):
    def test_scripts_parse_as_bash(self) -> None:
        for script in (INSTALLER, ROOT / "uninstall-peer-macos.sh", ROOT / "quick-install-peer.sh", ROOT / "download-peer.sh"):
            result = subprocess.run(["bash", "-n", str(script)], check=False, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, f"{script}: {result.stderr}")

    def test_downloader_requires_published_release_for_macos(self) -> None:
        result = subprocess.run(
            ["bash", str(ROOT / "download-peer.sh"), "--platform", "macos", "--commit", "0" * 40],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("CI artifacts are not published for macOS", result.stderr)

    def test_plist_writer_escapes_values_and_omits_invite_material(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mini-tunnel-plist-test-") as temp:
            output = Path(temp) / "peer.plist"
            subprocess.run(
                [
                    "python3", str(PLIST_WRITER), "--output", str(output),
                    "--label", "net.ilovn.mini-tunnel.office",
                    "--binary", "/usr/local/libexec/mini-tunnel/office/mini-tunnel",
                    "--state-dir", "/var/db/mini-tunnel/office",
                    "--network-id", "00000000-0000-0000-0000-000000000000",
                    "--coordinator-url", "https://coord.example/a%26b",
                    "--bind-address", "0.0.0.0:42000",
                    "--stun-server", "stun.example:3478",
                    "--status-listen", "127.0.0.1:42003",
                    "--log-dir", "/var/log/mini-tunnel/office",
                    "--relay-server", "relay.example:42001",
                ],
                check=True,
            )
            data = plistlib.loads(output.read_bytes())
        self.assertEqual(data["Label"], "net.ilovn.mini-tunnel.office")
        self.assertTrue(data["KeepAlive"])
        self.assertTrue(data["RunAtLoad"])
        self.assertEqual(data["ThrottleInterval"], 10)
        self.assertEqual(data["EnvironmentVariables"]["HOME"], "/var/root")
        self.assertEqual(data["EnvironmentVariables"]["MINI_TUNNEL_RELAY_SERVER"], "relay.example:42001")
        self.assertFalse(any("invite" in argument.lower() or "token" in argument.lower() for argument in data["ProgramArguments"]))
        self.assertNotIn("token", str(data["EnvironmentVariables"]).lower())

    @unittest.skipUnless(os.uname().sysname == "Darwin", "validation preflight requires macOS stat semantics")
    def test_validate_only_checks_inputs_without_installing(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mini-tunnel-macos-validate-") as temp:
            root = Path(temp)
            binary = root / "mini-tunnel"
            binary.write_text("#!/bin/sh\n[ \"$1\" = --help ]\n", encoding="utf-8")
            binary.chmod(0o755)
            invite = root / "invite.token"
            invite.write_text("placeholder-one-use-invite", encoding="utf-8")
            invite.chmod(0o600)
            result = subprocess.run(
                [
                    str(INSTALLER), "--binary", str(binary),
                    "--network-id", "00000000-0000-0000-0000-000000000000",
                    "--coordinator-url", "https://coord.example",
                    "--invite-token-file", str(invite), "--instance", "office",
                    "--validate-only",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("No files changed", result.stdout)
        self.assertNotIn("placeholder-one-use-invite", result.stdout + result.stderr)

    def test_install_uninstall_and_reinstall_reuse_state_without_reenrollment(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mini-tunnel-macos-lifecycle-") as temp:
            root = Path(temp) / "root"
            deploy = Path(temp) / "deploy"
            fake_bin = Path(temp) / "bin"
            deploy.mkdir()
            fake_bin.mkdir()
            macos_dir = deploy / "macos"
            macos_dir.mkdir()

            replacements = {
                "/usr/local/libexec/mini-tunnel": str(root / "usr/local/libexec/mini-tunnel"),
                "/var/db/mini-tunnel": str(root / "var/db/mini-tunnel"),
                "/Library/LaunchDaemons": str(root / "Library/LaunchDaemons"),
                "/var/log/mini-tunnel": str(root / "var/log/mini-tunnel"),
            }
            script = INSTALLER.read_text(encoding="utf-8")
            for source, destination in replacements.items():
                script = script.replace(source, destination)
            test_installer = deploy / "install-peer-macos.sh"
            test_installer.write_text(script, encoding="utf-8")
            test_installer.chmod(0o755)
            shutil.copy2(PLIST_WRITER, macos_dir / PLIST_WRITER.name)

            fixture_binary = Path(temp) / "mini-tunnel-fixture"
            fixture_binary.write_text(
                "#!/usr/bin/env python3\n"
                "import os, pathlib, sys\n"
                "if sys.argv[1:] == ['--help']: raise SystemExit(0)\n"
                "if sys.argv[1:3] == ['network', 'join']:\n"
                " p = pathlib.Path(os.environ['MINI_TUNNEL_STATE_DIR']) / 'device.key'\n"
                " p.write_text('test-device-key', encoding='utf-8'); p.chmod(0o600)\n"
                " with open(os.environ['JOIN_LOG'],'a',encoding='utf-8') as f: f.write('joined\\n')\n"
                " print('enrolled')\n"
                " raise SystemExit(0)\n"
                "raise SystemExit(2)\n",
                encoding="utf-8",
            )
            fixture_binary.chmod(0o755)
            invite = Path(temp) / "invite.token"
            invite.write_text("do-not-log-this-invite", encoding="utf-8")
            invite.chmod(0o600)
            install_log = Path(temp) / "install.jsonl"
            launchctl_log = Path(temp) / "launchctl.jsonl"
            join_log = Path(temp) / "join.log"

            (fake_bin / "id").write_text("#!/bin/sh\necho 0\n", encoding="utf-8")
            (fake_bin / "id").chmod(0o755)
            (fake_bin / "install").write_text(
                "#!/usr/bin/env python3\n"
                "import json, os, pathlib, shutil, sys\n"
                "args=sys.argv[1:]; directory='-d' in args; mode='755'; values=[]; i=0\n"
                "while i < len(args):\n"
                " a=args[i]\n"
                " if a in ('-o','-g','-m'):\n"
                "  if a == '-m': mode=args[i+1]\n"
                "  i += 2; continue\n"
                " if a == '-d': i += 1; continue\n"
                " values.append(a); i += 1\n"
                "if directory:\n"
                " for value in values: pathlib.Path(value).mkdir(parents=True, exist_ok=True); pathlib.Path(value).chmod(int(mode,8))\n"
                "else:\n"
                " src,dst=map(pathlib.Path, values[-2:]); dst.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(src,dst); dst.chmod(int(mode,8))\n"
                "with open(os.environ['INSTALL_LOG'],'a',encoding='utf-8') as f: f.write(json.dumps(args)+'\\n')\n",
                encoding="utf-8",
            )
            (fake_bin / "install").chmod(0o755)
            (fake_bin / "launchctl").write_text(
                "#!/usr/bin/env python3\n"
                "import json, os, sys\n"
                "with open(os.environ['LAUNCHCTL_LOG'],'a',encoding='utf-8') as f: f.write(json.dumps(sys.argv[1:])+'\\n')\n"
                "if os.environ.get('FAIL_BOOTSTRAP') == '1' and sys.argv[1:2] == ['bootstrap']: raise SystemExit(1)\n",
                encoding="utf-8",
            )
            (fake_bin / "launchctl").chmod(0o755)

            env = os.environ.copy()
            env.update({
                "PATH": f"{fake_bin}{os.pathsep}{env['PATH']}",
                "INSTALL_LOG": str(install_log),
                "LAUNCHCTL_LOG": str(launchctl_log),
                "JOIN_LOG": str(join_log),
            })
            common = [
                "--binary", str(fixture_binary),
                "--network-id", "00000000-0000-0000-0000-000000000000",
                "--coordinator-url", "https://coord.example",
                "--invite-token-file", str(invite), "--instance", "office",
            ]
            env["FAIL_BOOTSTRAP"] = "1"
            failed = subprocess.run([str(test_installer), *common], env=env, capture_output=True, text=True)
            self.assertNotEqual(failed.returncode, 0)
            self.assertFalse((root / "usr/local/libexec/mini-tunnel/office").exists())
            self.assertFalse((root / "Library/LaunchDaemons/net.ilovn.mini-tunnel.office.plist").exists())
            state = root / "var/db/mini-tunnel/office"
            self.assertTrue((state / "device.key").is_file(), "enrolled identity survives rollback for retry")
            env.pop("FAIL_BOOTSTRAP")
            first = subprocess.run([str(test_installer), *common], env=env, capture_output=True, text=True)
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertTrue((state / "device.key").is_file())
            self.assertEqual((state / "device.key").stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads((state / "install.json").read_text())['network_id'], common[3])
            self.assertNotIn("do-not-log-this-invite", first.stdout + first.stderr)

            uninstaller = ROOT / "uninstall-peer-macos.sh"
            uninstaller_test = deploy / "uninstall-peer-macos.sh"
            uninstall_script = uninstaller.read_text(encoding="utf-8")
            for source, destination in replacements.items():
                uninstall_script = uninstall_script.replace(source, destination)
            uninstaller_test.write_text(uninstall_script, encoding="utf-8")
            uninstaller_test.chmod(0o755)
            stopped = subprocess.run([str(uninstaller_test), "--instance", "office"], env=env, capture_output=True, text=True)
            self.assertEqual(stopped.returncode, 0, stopped.stderr)
            self.assertTrue((state / "device.key").exists(), "default uninstall keeps the device identity")

            second = subprocess.run([str(test_installer), *common], env=env, capture_output=True, text=True)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertEqual(join_log.read_text(encoding="utf-8").count("joined"), 1)
            self.assertNotIn("do-not-log-this-invite", launchctl_log.read_text(encoding="utf-8"))

            rejoin_invite = Path(temp) / "rejoin.token"
            rejoin_invite.write_text("fresh-one-use-invite", encoding="utf-8")
            rejoin_invite.chmod(0o600)
            rejoin = subprocess.run(
                [str(uninstaller_test), "--instance", "office"], env=env,
                capture_output=True, text=True,
            )
            self.assertEqual(rejoin.returncode, 0, rejoin.stderr)
            rejoined = subprocess.run(
                [str(test_installer), *common[:6], "--invite-token-file", str(rejoin_invite), "--instance", "office", "--rejoin"],
                env=env, capture_output=True, text=True,
            )
            self.assertEqual(rejoined.returncode, 0, rejoined.stderr)
            self.assertEqual(join_log.read_text(encoding="utf-8").count("joined"), 2)
            self.assertNotIn("fresh-one-use-invite", rejoined.stdout + rejoined.stderr)


if __name__ == "__main__":
    unittest.main()
