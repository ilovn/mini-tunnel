#!/usr/bin/env python3
"""Map a supported platform/architecture pair to its published artifact stem."""

from __future__ import annotations

import sys


ARTIFACTS = {
    ("linux", "x86_64"): "mini-tunnel-linux-x86_64-ubuntu20.04",
    ("linux", "aarch64"): "mini-tunnel-linux-aarch64-ubuntu22.04",
    ("macos", "x86_64"): "mini-tunnel-macos-x86_64",
    ("macos", "aarch64"): "mini-tunnel-macos-aarch64",
}


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: release_artifact.py <linux|macos> <x86_64|aarch64>", file=sys.stderr)
        return 2
    name = ARTIFACTS.get((sys.argv[1], sys.argv[2]))
    if name is None:
        print("unsupported platform and architecture", file=sys.stderr)
        return 2
    print(name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
