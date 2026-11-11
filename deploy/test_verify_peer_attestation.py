from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent
SCRIPT = ROOT / "verify-peer-attestation.sh"
COMMIT = "0123456789abcdef0123456789abcdef01234567"


class VerifyPeerAttestationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="mini-tunnel-attestation-test-")
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.archive = self.root / "peer.tar.gz"
        self.archive.write_bytes(b"test archive")
        self.arguments_file = self.root / "gh-arguments"
        python = self.bin / "python3"
        python.write_text(
            "#!/bin/sh\nprintf '{}' > \"$4\"\n",
            encoding="utf-8",
        )
        python.chmod(0o755)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def add_fake_gh(self, exit_code: int = 0) -> None:
        gh = self.bin / "gh"
        gh.write_text(
            "#!/bin/sh\nprintf '%s\\0' \"$@\" > \"$ARGUMENTS_FILE\"\n"
            f"exit {exit_code}\n",
            encoding="utf-8",
        )
        gh.chmod(0o755)

    def run_helper(
        self, workflow: str, source_ref: str, *, exit_code: int = 0, with_gh: bool = True
    ) -> subprocess.CompletedProcess[str]:
        if with_gh:
            self.add_fake_gh(exit_code)
        env = os.environ.copy()
        env["PATH"] = os.pathsep.join((str(self.bin), "/usr/bin", "/bin"))
        env["ARGUMENTS_FILE"] = str(self.arguments_file)
        env["GITHUB_TOKEN"] = "private-token"
        env["GH_PROMPT_DISABLED"] = "caller-value"
        return subprocess.run(
            [
                str(SCRIPT),
                str(self.archive),
                "ilovn/mini-tunnel",
                workflow,
                source_ref,
                COMMIT,
            ],
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )

    def test_release_verification_pins_release_workflow_tag_and_commit(self) -> None:
        result = self.run_helper("release.yml", "refs/tags/v1.2.3")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            self.arguments_file.read_bytes().split(b"\0")[:-1],
            [
                b"attestation",
                b"verify",
                str(self.archive).encode(),
                b"--bundle",
                self._bundle_arg(),
                b"--repo",
                b"ilovn/mini-tunnel",
                b"--signer-workflow",
                b"ilovn/mini-tunnel/.github/workflows/release.yml",
                b"--source-ref",
                b"refs/tags/v1.2.3",
                b"--source-digest",
                COMMIT.encode(),
                b"--deny-self-hosted-runners",
            ],
        )

    def test_ci_verification_pins_main_workflow_and_commit(self) -> None:
        result = self.run_helper("ci.yml", "refs/heads/main")
        self.assertEqual(result.returncode, 0, result.stderr)
        args = self.arguments_file.read_bytes().split(b"\0")[:-1]
        self.assertIn(b"ilovn/mini-tunnel/.github/workflows/ci.yml", args)
        self.assertIn(b"refs/heads/main", args)
        self.assertIn(COMMIT.encode(), args)
        self.assertIn(b"--deny-self-hosted-runners", args)
        self.assertIn(b"--bundle", args)

    def _bundle_arg(self) -> bytes:
        args = self.arguments_file.read_bytes().split(b"\0")[:-1]
        return args[args.index(b"--bundle") + 1]

    def test_rejects_unknown_workflow_or_unapproved_source_ref(self) -> None:
        for workflow, source_ref in (
            ("ci.yml", "refs/heads/attacker"),
            ("release.yml", "refs/heads/main"),
            ("other.yml", "refs/tags/v1.2.3"),
        ):
            with self.subTest(workflow=workflow, source_ref=source_ref):
                result = self.run_helper(workflow, source_ref)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.arguments_file.exists())

    def test_missing_gh_fails_closed(self) -> None:
        result = self.run_helper("ci.yml", "refs/heads/main", with_gh=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("GitHub CLI (gh) is required", result.stderr)
        self.assertFalse(self.arguments_file.exists())

    def test_rejected_attestation_fails_closed_without_printing_token(self) -> None:
        result = self.run_helper("ci.yml", "refs/heads/main", exit_code=1)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("rejected the archive provenance", result.stderr)
        self.assertNotIn("private-token", result.stdout + result.stderr)
        self.assertNotIn(b"private-token", self.arguments_file.read_bytes())


if __name__ == "__main__":
    unittest.main()
