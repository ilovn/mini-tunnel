#!/usr/bin/env python3
"""Write a LaunchDaemon plist without interpolating shell or XML fragments."""

from __future__ import annotations

import argparse
import plistlib
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--label", required=True)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--state-dir", required=True)
    parser.add_argument("--network-id", required=True)
    parser.add_argument("--coordinator-url", required=True)
    parser.add_argument("--bind-address", required=True)
    parser.add_argument("--stun-server", required=True)
    parser.add_argument("--status-listen", required=True)
    parser.add_argument("--log-dir", required=True)
    parser.add_argument("--relay-server", default="")
    parser.add_argument("--udp-relay-server", default="")
    parser.add_argument("--coordinator-ca", default="")
    args = parser.parse_args()

    environment = {
        "HOME": "/var/root",
        "XDG_CONFIG_HOME": f"{args.state_dir}/.config",
        "XDG_DATA_HOME": f"{args.state_dir}/.local/share",
        "MINI_TUNNEL_STATE_DIR": args.state_dir,
        "MINI_TUNNEL_COORDINATOR_URL": args.coordinator_url,
        "MINI_TUNNEL_STATUS_LISTEN": args.status_listen,
        "RUST_LOG": "mini_tunnel_agent=info",
    }
    if args.relay_server:
        environment["MINI_TUNNEL_RELAY_SERVER"] = args.relay_server
    if args.udp_relay_server:
        environment["MINI_TUNNEL_UDP_RELAY_SERVER"] = args.udp_relay_server
    if args.coordinator_ca:
        environment["MINI_TUNNEL_COORDINATOR_CA_CERT_FILE"] = args.coordinator_ca

    document = {
        "Label": args.label,
        "ProgramArguments": [
            args.binary,
            "peer",
            "tunnel",
            "mesh",
            "--bind",
            args.bind_address,
            "--network-id",
            args.network_id,
            "--stun-server",
            args.stun_server,
            "--ice",
            "--manage-route",
        ],
        "EnvironmentVariables": environment,
        "RunAtLoad": True,
        "KeepAlive": True,
        "ThrottleInterval": 10,
        "ExitTimeOut": 20,
        "StandardOutPath": f"{args.log_dir}/stdout.log",
        "StandardErrorPath": f"{args.log_dir}/stderr.log",
    }
    args.output.write_bytes(plistlib.dumps(document, fmt=plistlib.FMT_XML, sort_keys=True))


if __name__ == "__main__":
    main()
