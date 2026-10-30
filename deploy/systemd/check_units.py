#!/usr/bin/env python3
"""Static regression checks for the shipped systemd service sandbox settings."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
UNITS = (
    "mini-tunnel-coordinator.service",
    "mini-tunnel-coordinator-postgres.service",
    "mini-tunnel-relay.service",
)
REQUIRED = {
    "User": "mini-tunnel",
    "Group": "mini-tunnel",
    "Restart": "on-failure",
    "UMask": "0077",
    "NoNewPrivileges": "true",
    "PrivateTmp": "true",
    "ProtectHome": "true",
    "ProtectSystem": "strict",
    "CapabilityBoundingSet": "",
    "AmbientCapabilities": "",
    "PrivateDevices": "true",
    "ProtectKernelTunables": "true",
    "ProtectKernelModules": "true",
    "ProtectControlGroups": "true",
    "ProtectKernelLogs": "true",
    "ProtectHostname": "true",
    "LockPersonality": "true",
    "RestrictSUIDSGID": "true",
    "RestrictRealtime": "true",
    "RestrictAddressFamilies": "AF_UNIX AF_INET AF_INET6",
}


def read_service(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    section = ""
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            continue
        key, separator, value = line.partition("=")
        if separator and section == "Service":
            values[key.strip()] = value.strip()
    return values


def main() -> None:
    for unit in UNITS:
        values = read_service(ROOT / "deploy" / "systemd" / unit)
        missing = {
            key: expected
            for key, expected in REQUIRED.items()
            if values.get(key) != expected
        }
        if missing:
            details = ", ".join(f"{key}={value!r}" for key, value in missing.items())
            raise SystemExit(f"{unit}: missing or incorrect service settings: {details}")
        print(f"{unit}: sandbox settings verified")


if __name__ == "__main__":
    main()
