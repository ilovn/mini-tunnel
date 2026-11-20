from __future__ import annotations

import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent


class ReleaseArtifactTests(unittest.TestCase):
    def artifact(self, platform: str, architecture: str) -> str:
        result = subprocess.run(
            ["python3", str(ROOT / "release_artifact.py"), platform, architecture],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def test_linux_artifact_names_remain_unchanged(self) -> None:
        self.assertEqual(self.artifact("linux", "x86_64"), "mini-tunnel-linux-x86_64-ubuntu20.04")
        self.assertEqual(self.artifact("linux", "aarch64"), "mini-tunnel-linux-aarch64-ubuntu22.04")

    def test_macos_artifact_names_match_release_workflow(self) -> None:
        self.assertEqual(self.artifact("macos", "x86_64"), "mini-tunnel-macos-x86_64")
        self.assertEqual(self.artifact("macos", "aarch64"), "mini-tunnel-macos-aarch64")

    def test_unsupported_pair_fails_closed(self) -> None:
        result = subprocess.run(
            ["python3", str(ROOT / "release_artifact.py"), "windows", "x86_64"],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("unsupported", result.stderr)


if __name__ == "__main__":
    unittest.main()
