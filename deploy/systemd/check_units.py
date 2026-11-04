#!/usr/bin/env python3
"""Static regression checks for the shipped systemd service sandbox settings."""

import shutil
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SERVER_UNITS = (
    "mini-tunnel-coordinator.service",
    "mini-tunnel-coordinator-postgres.service",
    "mini-tunnel-relay.service",
)
PEER_UNIT = "mini-tunnel-peer@.service"
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
    "ProtectClock": "true",
    "ProtectProc": "invisible",
    "ProcSubset": "pid",
    "LockPersonality": "true",
    "RestrictSUIDSGID": "true",
    "RestrictRealtime": "true",
    "RestrictNamespaces": "true",
    "MemoryDenyWriteExecute": "true",
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


def service_directives(path: Path, wanted_key: str) -> list[str]:
    values = []
    section = ""
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            continue
        key, separator, value = line.partition("=")
        if separator and section == "Service" and key.strip() == wanted_key:
            values.append(value.strip())
    return values


def main() -> None:
    for unit in SERVER_UNITS:
        values = read_service(ROOT / "deploy" / "systemd" / unit)
        missing = {
            key: expected
            for key, expected in REQUIRED.items()
            if values.get(key) != expected
        }
        if missing:
            details = ", ".join(f"{key}={value!r}" for key, value in missing.items())
            raise SystemExit(f"{unit}: missing or incorrect service settings: {details}")
        if unit.startswith("mini-tunnel-coordinator"):
            command = values.get("ExecStart", "")
            if "--listen 127.0.0.1:8443" not in command:
                raise SystemExit(f"{unit}: coordinator must stay bound to loopback")
            if "--trusted-proxies 127.0.0.1/32" not in command:
                raise SystemExit(
                    f"{unit}: local reverse proxy CIDR must be trusted for client rate limits"
                )
        credentials = values.get("LoadCredential", "")
        if credentials != "relay-ticket-key:/etc/mini-tunnel/relay-ticket-key":
            raise SystemExit(f"{unit}: relay signing key must use a systemd credential")
        if values.get("Environment") != "MINI_TUNNEL_RELAY_TICKET_KEY_FILE=%d/relay-ticket-key":
            raise SystemExit(f"{unit}: relay signing key credential path must be configured")
        print(f"{unit}: sandbox settings verified")

    peer_path = ROOT / "deploy" / "systemd" / PEER_UNIT
    peer = read_service(peer_path)
    peer_required = {
        "User": "mini-tunnel",
        "Group": "mini-tunnel",
        "Restart": "on-failure",
        "RestartSec": "3s",
        "TimeoutStopSec": "20s",
        "KillSignal": "SIGTERM",
        "UMask": "0077",
        "NoNewPrivileges": "true",
        "PrivateTmp": "true",
        "ProtectHome": "true",
        "ProtectSystem": "strict",
        "StateDirectory": "mini-tunnel",
        "StateDirectoryMode": "0700",
        "CapabilityBoundingSet": "CAP_NET_ADMIN",
        "AmbientCapabilities": "CAP_NET_ADMIN",
        "PrivateDevices": "false",
        "DevicePolicy": "closed",
        "DeviceAllow": "/dev/net/tun rw",
        "ProtectKernelTunables": "true",
        "ProtectKernelModules": "true",
        "ProtectControlGroups": "true",
        "ProtectKernelLogs": "true",
        "ProtectHostname": "true",
        "ProtectClock": "true",
        "ProtectProc": "invisible",
        "ProcSubset": "pid",
        "LockPersonality": "true",
        "RestrictSUIDSGID": "true",
        "RestrictRealtime": "true",
        "RestrictNamespaces": "true",
        "MemoryDenyWriteExecute": "true",
        "RestrictAddressFamilies": "AF_UNIX AF_INET AF_INET6 AF_NETLINK",
        "UnsetEnvironment": "MINI_TUNNEL_ADMIN_TOKEN MINI_TUNNEL_INVITE_TOKEN MINI_TUNNEL_COORDINATOR_DATABASE_URL MINI_TUNNEL_RELAY_TICKET_KEY MINI_TUNNEL_RELAY_TICKET_KEY_FILE MINI_TUNNEL_RELAY_PREVIOUS_TICKET_KEY MINI_TUNNEL_RELAY_PREVIOUS_TICKET_KEY_FILE",
    }
    missing = {
        key: expected
        for key, expected in peer_required.items()
        if peer.get(key) != expected
    }
    if missing:
        details = ", ".join(f"{key}={value!r}" for key, value in missing.items())
        raise SystemExit(f"{PEER_UNIT}: missing or incorrect peer sandbox settings: {details}")
    if peer.get("EnvironmentFile") != "/etc/mini-tunnel/peer-%i.env":
        raise SystemExit(f"{PEER_UNIT}: per-instance environment file must be root-managed")
    for key in (
        "EnvironmentFile",
        "CapabilityBoundingSet",
        "AmbientCapabilities",
        "PrivateDevices",
        "DevicePolicy",
        "DeviceAllow",
        "RestrictAddressFamilies",
        "UnsetEnvironment",
    ):
        if len(service_directives(peer_path, key)) != 1:
            raise SystemExit(f"{PEER_UNIT}: {key} must appear exactly once to keep its policy bounded")
    if "SupplementaryGroups" in peer:
        raise SystemExit(f"{PEER_UNIT}: supplementary groups must not broaden the service identity")
    command = peer.get("ExecStart", "")
    for required in (
        "peer tunnel mesh",
        "--bind ${BIND_ADDRESS}",
        "--network-id ${NETWORK_ID}",
        "--stun-server ${STUN_SERVER}",
        "--ice",
        "--manage-route",
    ):
        if required not in command:
            raise SystemExit(f"{PEER_UNIT}: ExecStart must include {required!r}")
    if "invite" in command.lower() or "token" in command.lower():
        raise SystemExit(f"{PEER_UNIT}: join tokens must not be passed to the running service")
    if "LoadCredential" in peer or "LoadCredentialEncrypted" in peer:
        raise SystemExit(f"{PEER_UNIT}: the peer must not load server signing credentials")
    print(f"{PEER_UNIT}: sandbox settings verified")

    systemd_analyze = shutil.which("systemd-analyze")
    if systemd_analyze is None:
        print("systemd-analyze unavailable; unit syntax verification is delegated to Linux CI")
        return
    unit_path = ROOT / "deploy" / "systemd" / PEER_UNIT
    contents = unit_path.read_text(encoding="utf-8")
    if "/usr/local/bin/mini-tunnel" not in contents:
        raise SystemExit(f"{PEER_UNIT}: expected ExecStart binary path was not found")
    # systemd-analyze checks that ExecStart is executable. Use a standard, harmless binary in
    # the temporary copy while leaving the shipped unit and the static ExecStart checks intact.
    with tempfile.TemporaryDirectory(prefix="mini-tunnel-systemd-verify-") as directory:
        temporary_unit = Path(directory) / PEER_UNIT
        temporary_unit.write_text(
            contents.replace("/usr/local/bin/mini-tunnel", "/usr/bin/true"),
            encoding="utf-8",
        )
        subprocess.run(
            [systemd_analyze, "verify", str(temporary_unit)],
            check=True,
            cwd=ROOT,
            timeout=30,
        )
    print(f"{PEER_UNIT}: systemd syntax verified")


if __name__ == "__main__":
    main()
