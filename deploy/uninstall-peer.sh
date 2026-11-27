#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Uninstall one mini-tunnel Linux systemd peer instance.

Usage:
  sudo deploy/uninstall-peer.sh [--instance <name>] [--dry-run]
  sudo deploy/uninstall-peer.sh [--instance <name>] --remove-membership [--yes]

By default, only the selected instance's service, config and Coordinator CA are
removed. The shared binary, service account, device identity and network
memberships are preserved. Revoke the device on the Coordinator separately.

--remove-membership deletes only this instance's local membership record. It
keeps the shared device identity and other networks' memberships. The shared
state directory can also contain Coordinator data, so it is never recursively
removed. The shared binary and service account are never removed by this command.
EOF
}

die() { printf 'error: %s\n' "$*" >&2; exit 1; }

instance=default
dry_run=false
remove_membership=false
yes=false

while (($#)); do
  case "$1" in
    --instance) (($# >= 2)) || die "--instance needs a value"; instance=$2; shift 2 ;;
    --dry-run) dry_run=true; shift ;;
    --remove-membership) remove_membership=true; shift ;;
    --yes) yes=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1 (see --help)" ;;
  esac
done

[[ "$instance" =~ ^[a-zA-Z0-9_-]{1,48}$ ]] || die "invalid instance name"
[[ "$yes" == false || "$remove_membership" == true ]] || die "--yes is only valid with --remove-membership"
[[ "$dry_run" == false || "$yes" == false ]] || die "--dry-run and --yes cannot be combined"
[[ "$dry_run" == true || ! -L /etc/mini-tunnel ]] || die "refusing unsafe configuration directory: /etc/mini-tunnel"

config_path="/etc/mini-tunnel/peer-${instance}.env"
ca_path="/etc/mini-tunnel/coordinator-ca-${instance}.pem"
service_name="mini-tunnel-peer@${instance}.service"
state_dir=/var/lib/mini-tunnel
etc_dir=/etc/mini-tunnel

# Alternate paths are accepted only for a read-only dry run, which also makes
# the plan and conflict checks testable without touching the host.
if [[ "$dry_run" == true ]]; then
  etc_dir=${MINI_TUNNEL_UNINSTALL_ETC_DIR:-$etc_dir}
  state_dir=${MINI_TUNNEL_UNINSTALL_STATE_DIR:-$state_dir}
fi
config_path="$etc_dir/peer-${instance}.env"
ca_path="$etc_dir/coordinator-ca-${instance}.pem"
membership_file=

read_network_id() {
  local file=$1 count value
  [[ ! -L "$file" && -f "$file" ]] || die "peer config is missing or unsafe: $file"
  count=$(awk -F= '$1 == "NETWORK_ID" { n++ } END { print n+0 }' "$file")
  [[ "$count" == 1 ]] || die "expected exactly one NETWORK_ID in $file"
  value=$(awk -F= '$1 == "NETWORK_ID" { print $2; exit }' "$file")
  [[ "$value" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]] || die "invalid NETWORK_ID in $file"
  printf '%s\n' "${value,,}"
}

if [[ "$remove_membership" == true ]]; then
  network_id=$(read_network_id "$config_path")
  membership_file="$state_dir/networks/${network_id}.json"
  other_configs=()
  shopt -s nullglob
  for candidate in "$etc_dir"/peer-*.env; do
    if [[ "$candidate" != "$config_path" ]]; then
      candidate_network=$(awk -F= '$1 == "NETWORK_ID" { print $2; exit }' "$candidate")
      [[ "${candidate_network,,}" == "$network_id" ]] && other_configs+=("$candidate")
    fi
  done
  shopt -u nullglob
  ((${#other_configs[@]} == 0)) || die "refusing to remove membership while another configured instance uses network $network_id: ${other_configs[*]}"
  [[ ! -L "$state_dir" && ( ! -e "$state_dir" || -d "$state_dir" ) ]] || die "refusing unsafe state directory: $state_dir"
  [[ ! -L "$state_dir/networks" && ( ! -e "$state_dir/networks" || -d "$state_dir/networks" ) ]] || die "refusing unsafe membership directory: $state_dir/networks"
fi

if [[ "$dry_run" == true ]]; then
  printf 'Would stop and disable %s\n' "$service_name"
  printf 'Would remove %s and %s\n' "$config_path" "$ca_path"
  if [[ "$remove_membership" == true ]]; then
    printf 'Would remove only %s\n' "$membership_file"
  else
    printf 'Would preserve shared binary, service account, device identity and network memberships\n'
  fi
  exit 0
fi

[[ ${EUID:-$(id -u)} -eq 0 ]] || die "run as root (for example, sudo deploy/uninstall-peer.sh)"
command -v systemctl >/dev/null || die "systemctl is required"
[[ -d /run/systemd/system ]] || die "systemd is not running"
if [[ "$remove_membership" == true && "$yes" != true ]]; then
  [[ -t 0 ]] || die "--remove-membership requires an interactive confirmation or --yes"
  printf 'This deletes the local membership record for network %s. Type DELETE to continue: ' "$network_id" >&2
  IFS= read -r confirmation
  [[ "$confirmation" == DELETE ]] || die "membership removal cancelled"
fi

systemctl disable --now "$service_name" >/dev/null 2>&1 || {
  if systemctl is-enabled "$service_name" >/dev/null 2>&1 || systemctl is-active "$service_name" >/dev/null 2>&1; then
    die "failed to stop or disable $service_name"
  fi
}
rm -f -- "$config_path" "$ca_path"
systemctl daemon-reload

if [[ "$remove_membership" == true ]]; then
  if [[ -e "$membership_file" || -L "$membership_file" ]]; then
    [[ ! -d "$membership_file" ]] || die "refusing unexpected membership directory: $membership_file"
    rm -f -- "$membership_file"
  fi
fi

printf 'Uninstalled %s.\n' "$service_name"
if [[ "$remove_membership" != true ]]; then
  printf 'Shared identity and network memberships were preserved. Revoke the device in the Coordinator separately.\n'
else
  printf 'Local membership for %s was removed; shared identity and other memberships were preserved. Revoke the device in the Coordinator separately.\n' "$network_id"
fi
printf 'Shared binary and mini-tunnel service account were preserved.\n'
