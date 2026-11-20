#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Install a prebuilt macOS peer as a system LaunchDaemon.

Usage:
  sudo deploy/install-peer-macos.sh --binary ./mini-tunnel \
    --network-id <uuid> --coordinator-url <https://host:port> \
    --invite-token-file <0600-file> [--instance office] \
    [--bind-address 0.0.0.0:42000] [--stun-server host:port] \
    [--relay-server host:port] [--udp-relay-server host:port] \
    [--status-listen 127.0.0.1:42003] [--coordinator-ca <pem-file>] [--rejoin]

Use --validate-only for a read-only preflight. This script does not download
or build binaries, create a Coordinator network, or issue an invite.
EOF
}

die() { printf 'error: %s\n' "$*" >&2; exit 1; }

binary=
network_id=
coordinator_url=
invite_file=
instance=default
bind_address=0.0.0.0:42000
status_listen=127.0.0.1:42003
stun_server=111.206.174.2:3478
relay_server=
udp_relay_server=
coordinator_ca=
validate_only=false
rejoin=false

while (($#)); do
  case "$1" in
    --binary) (($# >= 2)) || die "--binary needs a value"; binary=$2; shift 2 ;;
    --network-id) (($# >= 2)) || die "--network-id needs a value"; network_id=$2; shift 2 ;;
    --coordinator-url) (($# >= 2)) || die "--coordinator-url needs a value"; coordinator_url=$2; shift 2 ;;
    --invite-token-file) (($# >= 2)) || die "--invite-token-file needs a value"; invite_file=$2; shift 2 ;;
    --instance) (($# >= 2)) || die "--instance needs a value"; instance=$2; shift 2 ;;
    --bind-address) (($# >= 2)) || die "--bind-address needs a value"; bind_address=$2; shift 2 ;;
    --status-listen) (($# >= 2)) || die "--status-listen needs a value"; status_listen=$2; shift 2 ;;
    --stun-server) (($# >= 2)) || die "--stun-server needs a value"; stun_server=$2; shift 2 ;;
    --relay-server) (($# >= 2)) || die "--relay-server needs a value"; relay_server=$2; shift 2 ;;
    --udp-relay-server) (($# >= 2)) || die "--udp-relay-server needs a value"; udp_relay_server=$2; shift 2 ;;
    --coordinator-ca) (($# >= 2)) || die "--coordinator-ca needs a value"; coordinator_ca=$2; shift 2 ;;
    --rejoin) rejoin=true; shift ;;
    --validate-only) validate_only=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1 (see --help)" ;;
  esac
done

[[ "$(uname -s)" == Darwin ]] || die "this installer requires macOS"
[[ -n "$binary" && -n "$network_id" && -n "$coordinator_url" && -n "$invite_file" ]] || {
  usage >&2
  die "--binary, --network-id, --coordinator-url, and --invite-token-file are required"
}
[[ "$instance" =~ ^[a-zA-Z0-9_-]{1,48}$ ]] || die "invalid instance name"
[[ "$network_id" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]] || die "network ID must be a UUID"
command -v python3 >/dev/null || die "python3 is required"
python3 - "$coordinator_url" <<'PY' || die "Coordinator URL must be HTTPS without credentials, query, or fragment"
import sys
from urllib.parse import urlsplit

try:
    parsed = urlsplit(sys.argv[1])
    valid = parsed.scheme == "https" and bool(parsed.hostname) and (parsed.port is None or 1 <= parsed.port <= 65535) and not parsed.username and not parsed.password and not parsed.query and not parsed.fragment
except ValueError:
    valid = False
raise SystemExit(0 if valid else 1)
PY

for value_name in bind_address status_listen stun_server relay_server udp_relay_server; do
  value=${!value_name}
  [[ -z "$value" || "$value" =~ ^[a-zA-Z0-9._:/-]+$ || "$value" =~ ^\[[a-fA-F0-9:]+\]:[0-9]{1,5}$ ]] || die "$value_name has unsupported characters"
done
[[ "$bind_address" == *:* ]] || die "bind address must include a port"
[[ "$status_listen" =~ ^127\.0\.0\.1:[0-9]{1,5}$ || "$status_listen" =~ ^\[::1\]:[0-9]{1,5}$ ]] || die "status listener must use loopback"
[[ "$stun_server" == *:* ]] || die "STUN server must include a port"
[[ -z "$relay_server" || "$relay_server" == *:* ]] || die "relay server must include a port"
[[ -z "$udp_relay_server" || "$udp_relay_server" == *:* ]] || die "UDP relay server must include a port"
for value_name in bind_address status_listen stun_server relay_server udp_relay_server; do
  value=${!value_name}
  [[ -z "$value" ]] && continue
  port=${value##*:}
  [[ "$port" =~ ^[0-9]{1,5}$ ]] && ((10#$port >= 1 && 10#$port <= 65535)) || die "$value_name port must be between 1 and 65535"
done

[[ -f "$binary" && -x "$binary" && ! -L "$binary" ]] || die "binary must be an executable regular file: $binary"
"$binary" --help >/dev/null || die "binary cannot run on this machine or is not a mini-tunnel CLI"
[[ -f "$invite_file" && ! -L "$invite_file" ]] || die "invite token must be a regular file, not a symlink"
invite_mode=$(stat -f '%Lp' "$invite_file") || die "cannot read invite token permissions"
(( (8#$invite_mode & 077) == 0 )) || die "invite token file must deny group/other access (chmod 600)"
[[ -s "$invite_file" ]] || die "invite token file is empty"
if [[ -n "$coordinator_ca" ]]; then
  [[ -f "$coordinator_ca" && ! -L "$coordinator_ca" ]] || die "Coordinator CA must be a regular file, not a symlink"
fi

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
plist_writer="$script_dir/macos/write_launchd_plist.py"
[[ -r "$plist_writer" ]] || die "LaunchDaemon plist generator not found: $plist_writer"

if [[ "$validate_only" == true ]]; then
  printf 'Inputs valid. No files changed; binary=%s network=%s instance=%s\n' "$binary" "$network_id" "$instance"
  exit 0
fi

[[ $(id -u) -eq 0 ]] || die "run as root (for example, sudo deploy/install-peer-macos.sh ...)"
for command in install launchctl plutil python3; do
  command -v "$command" >/dev/null || die "$command is required"
done

label="net.ilovn.mini-tunnel.$instance"
state_dir="/var/db/mini-tunnel/$instance"
binary_dir="/usr/local/libexec/mini-tunnel/$instance"
binary_path="$binary_dir/mini-tunnel"
plist_path="/Library/LaunchDaemons/$label.plist"
log_dir="/var/log/mini-tunnel/$instance"
state_marker="$state_dir/install.json"
[[ ! -e "$binary_dir" && ! -e "$plist_path" ]] || die "instance service already exists; refusing to overwrite it"
reuse_state=false
if [[ -e "$state_dir" ]]; then
  [[ -d "$state_dir" && ! -L "$state_dir" ]] || die "state path exists but is not a directory"
  [[ -f "$state_dir/device.key" && ! -L "$state_dir/device.key" && -f "$state_marker" && ! -L "$state_marker" ]] || die "existing state is incomplete; refusing to create another enrollment"
  python3 - "$state_marker" "$network_id" "$coordinator_url" <<'PY' || die "existing state belongs to a different network or Coordinator"
import json
import sys

with open(sys.argv[1], encoding="utf-8") as marker_file:
    marker = json.load(marker_file)
if marker.get("network_id") != sys.argv[2] or marker.get("coordinator_url") != sys.argv[3]:
    raise SystemExit(1)
PY
  reuse_state=true
fi

plist_tmp=$(mktemp "${TMPDIR:-/tmp}/mini-tunnel-launchd.XXXXXX")
install_complete=false
cleanup_install() {
  rm -f -- "$plist_tmp"
  if [[ "$install_complete" != true ]]; then
    launchctl bootout "system/$label" >/dev/null 2>&1 || true
    rm -f -- "$plist_path"
    rm -rf -- "$binary_dir"
    if [[ "$reuse_state" == false && ! -e "$state_marker" ]]; then
      rm -rf -- "$state_dir"
    fi
  fi
}
trap cleanup_install EXIT

install -d -o root -g wheel -m 0755 /usr/local/libexec/mini-tunnel
install -d -o root -g wheel -m 0755 "$binary_dir"
install -d -o root -g wheel -m 0700 "$state_dir"
install -d -o root -g wheel -m 0755 "$state_dir/.config" "$state_dir/.local/share"
install -d -o root -g wheel -m 0750 "$log_dir"
install -m 0755 -o root -g wheel "$binary" "$binary_path"

ca_runtime_path=
if [[ -n "$coordinator_ca" ]]; then
  ca_runtime_path="$state_dir/coordinator-ca.pem"
  install -m 0644 -o root -g wheel "$coordinator_ca" "$ca_runtime_path"
fi

join_env=(
  HOME=/var/root
  XDG_CONFIG_HOME="$state_dir/.config"
  XDG_DATA_HOME="$state_dir/.local/share"
  MINI_TUNNEL_STATE_DIR="$state_dir"
  MINI_TUNNEL_COORDINATOR_URL="$coordinator_url"
)
[[ -z "$ca_runtime_path" ]] || join_env+=(MINI_TUNNEL_COORDINATOR_CA_CERT_FILE="$ca_runtime_path")
if [[ "$reuse_state" == false ]]; then
  if ! env "${join_env[@]}" "$binary_path" network join --network-id "$network_id" --invite-token-file "$invite_file"; then
    die "network enrollment failed; inspect $state_dir before retrying"
  fi
  python3 - "$state_marker" "$network_id" "$coordinator_url" <<'PY'
import json
import os
import sys

destination, network_id, coordinator_url = sys.argv[1:]
temporary = destination + ".new"
descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(descriptor, "w", encoding="utf-8") as marker_file:
    json.dump({"network_id": network_id, "coordinator_url": coordinator_url}, marker_file)
    marker_file.write("\n")
os.replace(temporary, destination)
PY
elif [[ "$rejoin" == true ]]; then
  if ! env "${join_env[@]}" "$binary_path" network join --network-id "$network_id" --invite-token-file "$invite_file"; then
    die "network re-enrollment failed; inspect $state_dir before retrying"
  fi
fi

plist_args=(
  --output "$plist_tmp" --label "$label" --binary "$binary_path"
  --state-dir "$state_dir" --network-id "$network_id"
  --coordinator-url "$coordinator_url" --bind-address "$bind_address"
  --stun-server "$stun_server" --status-listen "$status_listen" --log-dir "$log_dir"
)
[[ -z "$relay_server" ]] || plist_args+=(--relay-server "$relay_server")
[[ -z "$udp_relay_server" ]] || plist_args+=(--udp-relay-server "$udp_relay_server")
[[ -z "$ca_runtime_path" ]] || plist_args+=(--coordinator-ca "$ca_runtime_path")
python3 "$plist_writer" "${plist_args[@]}"
plutil -lint "$plist_tmp" >/dev/null || die "generated LaunchDaemon plist is invalid"
install -m 0644 -o root -g wheel "$plist_tmp" "$plist_path"
launchctl bootstrap system "$plist_path"
install_complete=true

cat <<EOF

Peer installed and started: $label
Status: $binary_path peer status --url http://$status_listen
Logs:   $log_dir
Restart: sudo launchctl kickstart -k system/$label
Uninstall: sudo deploy/uninstall-peer-macos.sh --instance $instance
State (preserved on uninstall): $state_dir
EOF
