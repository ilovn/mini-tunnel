#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Install a prebuilt mini-tunnel Linux peer as a systemd service.

Usage:
  sudo deploy/install-peer.sh \
    --binary ./mini-tunnel \
    --network-id <uuid> \
    --coordinator-url <https://host:port> \
    --invite-token-file <0600-file> \
    [--instance office] [--bind-address 0.0.0.0:42000] \
    [--status-listen 127.0.0.1:42003] \
    [--stun-server host:port] [--relay-server host:port] \
    [--udp-relay-server host:port] [--coordinator-ca <pem-file>]

Use --validate-only to check inputs without root or making changes. This script
does not download/build binaries, create networks, or issue invites.
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
    --validate-only) validate_only=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1 (see --help)" ;;
  esac
done

[[ -n "$binary" && -n "$network_id" && -n "$coordinator_url" && -n "$invite_file" ]] || {
  usage >&2
  die "--binary, --network-id, --coordinator-url, and --invite-token-file are required"
}
[[ "$instance" =~ ^[a-zA-Z0-9_-]{1,48}$ ]] || die "invalid instance name"
[[ "$network_id" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]] || die "network ID must be a UUID"
[[ "$coordinator_url" =~ ^https?://[^[:space:]]+$ ]] || die "Coordinator URL must start with http:// or https:// and contain no whitespace"
[[ "$coordinator_url" != *'#'* && "$coordinator_url" != *'"'* && "$coordinator_url" != *'\'* ]] || die "Coordinator URL contains unsupported characters"

for value_name in bind_address status_listen stun_server relay_server udp_relay_server; do
  value=${!value_name}
  [[ -z "$value" || "$value" =~ ^[a-zA-Z0-9._:/-]+$ || "$value" =~ ^\[[a-fA-F0-9:]+\]:[0-9]{1,5}$ ]] || die "$value_name has unsupported characters"
done
[[ "$bind_address" == *:* ]] || die "bind address must include a port"
[[ "$status_listen" =~ ^127\.0\.0\.1:[0-9]{1,5}$ || "$status_listen" =~ ^\[::1\]:[0-9]{1,5}$ ]] || die "status listener must use loopback"
[[ "$stun_server" == *:* ]] || die "STUN server must include a port"
[[ -z "$relay_server" || "$relay_server" == *:* ]] || die "relay server must include a port"
[[ -z "$udp_relay_server" || "$udp_relay_server" == *:* ]] || die "UDP relay server must include a port"

[[ -f "$binary" && -x "$binary" ]] || die "binary must be an executable regular file: $binary"
"$binary" --help >/dev/null || die "binary cannot run on this machine or is not a mini-tunnel CLI"
[[ ! -L "$invite_file" && -f "$invite_file" ]] || die "invite token must be a regular file, not a symlink"
invite_mode=$(stat -c '%a' -- "$invite_file" 2>/dev/null || stat -f '%Lp' "$invite_file") || die "cannot read invite token permissions"
(( (8#$invite_mode & 077) == 0 )) || die "invite token file must deny group/other access (chmod 600)"
[[ -s "$invite_file" ]] || die "invite token file is empty"
if [[ -n "$coordinator_ca" ]]; then
  [[ -f "$coordinator_ca" && ! -L "$coordinator_ca" ]] || die "Coordinator CA must be a regular file, not a symlink"
fi

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
unit_source="$script_dir/systemd/mini-tunnel-peer@.service"
[[ -r "$unit_source" ]] || die "peer systemd unit not found next to installer: $unit_source"

if [[ "$validate_only" == true ]]; then
  printf 'Inputs valid. No files changed; binary=%s network=%s instance=%s\n' "$binary" "$network_id" "$instance"
  exit 0
fi

[[ ${EUID:-$(id -u)} -eq 0 ]] || die "run as root (for example, sudo deploy/install-peer.sh ...)"
command -v systemctl >/dev/null || die "systemctl is required"
systemctl is-system-running >/dev/null 2>&1 || [[ -d /run/systemd/system ]] || die "systemd is not running"
systemd_version=$(systemctl --version | awk 'NR == 1 { print $2 }')
[[ "$systemd_version" =~ ^[0-9]+$ ]] && ((systemd_version >= 247)) || die "systemd 247 or newer is required (found ${systemd_version:-unknown})"
[[ -c /dev/net/tun ]] || die "/dev/net/tun is unavailable"

config_path="/etc/mini-tunnel/peer-${instance}.env"
service_name="mini-tunnel-peer@${instance}.service"
[[ ! -e "$config_path" ]] || die "$config_path already exists; refusing to overwrite an enrolled peer configuration"
[[ -x "$binary" ]] || die "binary is not executable"

if ! getent passwd mini-tunnel >/dev/null; then
  useradd --system --home-dir /var/lib/mini-tunnel --create-home --shell /usr/sbin/nologin mini-tunnel
fi
install -d -o root -g mini-tunnel -m 0750 /etc/mini-tunnel
install -d -o mini-tunnel -g mini-tunnel -m 0700 /var/lib/mini-tunnel
install -m 0755 -- "$binary" /usr/local/bin/mini-tunnel.new
mv -f /usr/local/bin/mini-tunnel.new /usr/local/bin/mini-tunnel
install -m 0644 -- "$unit_source" /etc/systemd/system/mini-tunnel-peer@.service

ca_runtime_path=
if [[ -n "$coordinator_ca" ]]; then
  ca_runtime_path=/etc/mini-tunnel/coordinator-ca-${instance}.pem
  install -o root -g mini-tunnel -m 0640 -- "$coordinator_ca" "$ca_runtime_path"
fi

invite_runtime_path=/var/lib/mini-tunnel/invite-${instance}.token
install -o mini-tunnel -g mini-tunnel -m 0600 -- "$invite_file" "$invite_runtime_path"
cleanup_invite() { rm -f -- "$invite_runtime_path"; }
trap cleanup_invite EXIT

join_env=(
  HOME=/var/lib/mini-tunnel
  XDG_CONFIG_HOME=/var/lib/mini-tunnel/.config
  XDG_DATA_HOME=/var/lib/mini-tunnel/.local/share
  MINI_TUNNEL_STATE_DIR=/var/lib/mini-tunnel
  MINI_TUNNEL_COORDINATOR_URL="$coordinator_url"
)
[[ -z "$ca_runtime_path" ]] || join_env+=(MINI_TUNNEL_COORDINATOR_CA_CERT_FILE="$ca_runtime_path")
runuser -u mini-tunnel -- env "${join_env[@]}" /usr/local/bin/mini-tunnel network join \
  --network-id "$network_id" --invite-token-file "$invite_runtime_path"
cleanup_invite
trap - EXIT

config_tmp=$(mktemp /etc/mini-tunnel/.peer-${instance}.env.XXXXXX)
chmod 0600 "$config_tmp"
{
  printf 'NETWORK_ID=%s\nBIND_ADDRESS=%s\nSTUN_SERVER=%s\n' "$network_id" "$bind_address" "$stun_server"
  printf 'MINI_TUNNEL_COORDINATOR_URL=%s\nMINI_TUNNEL_STATE_DIR=/var/lib/mini-tunnel\nMINI_TUNNEL_STATUS_LISTEN=%s\nRUST_LOG=mini_tunnel_agent=info\n' "$coordinator_url" "$status_listen"
  [[ -z "$relay_server" ]] || printf 'MINI_TUNNEL_RELAY_SERVER=%s\n' "$relay_server"
  [[ -z "$udp_relay_server" ]] || printf 'MINI_TUNNEL_UDP_RELAY_SERVER=%s\n' "$udp_relay_server"
  [[ -z "$ca_runtime_path" ]] || printf 'MINI_TUNNEL_COORDINATOR_CA_CERT_FILE=%s\n' "$ca_runtime_path"
} >"$config_tmp"
chown root:mini-tunnel "$config_tmp"
chmod 0640 "$config_tmp"
mv -- "$config_tmp" "$config_path"

systemctl daemon-reload
systemctl enable --now "$service_name"
systemctl --no-pager --full status "$service_name"
cat <<EOF

Peer installed and started: $service_name
Live status: sudo -u mini-tunnel /usr/local/bin/mini-tunnel peer status --url http://${status_listen}
Logs:        sudo journalctl -fu $service_name
Stop:        sudo systemctl disable --now $service_name
Config:      $config_path
EOF
