#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Unload a mini-tunnel macOS LaunchDaemon and remove its executable.

Usage: sudo deploy/uninstall-peer-macos.sh --instance <name> [--remove-state]

By default, the enrolled identity and state are preserved under /var/db/mini-tunnel.
Revoke the device in the Coordinator before explicitly removing that state.
EOF
}

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
instance=
remove_state=false
while (($#)); do
  case "$1" in
    --instance) (($# >= 2)) || die "--instance needs a value"; instance=$2; shift 2 ;;
    --remove-state) remove_state=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done
[[ "$(uname -s)" == Darwin ]] || die "this uninstaller requires macOS"
[[ "$instance" =~ ^[a-zA-Z0-9_-]{1,48}$ ]] || die "provide a valid --instance name"
[[ $(id -u) -eq 0 ]] || die "run as root (for example, sudo deploy/uninstall-peer-macos.sh ...)"
command -v launchctl >/dev/null || die "launchctl is required"

label="net.ilovn.mini-tunnel.$instance"
plist_path="/Library/LaunchDaemons/$label.plist"
binary_dir="/usr/local/libexec/mini-tunnel/$instance"
state_dir="/var/db/mini-tunnel/$instance"
launchctl bootout "system/$label" >/dev/null 2>&1 || true
rm -f -- "$plist_path"
rm -rf -- "$binary_dir"
if [[ "$remove_state" == true ]]; then
  rm -rf -- "$state_dir"
  printf 'Removed service, binary, and state for %s. Revoke the Coordinator membership separately if not already revoked.\n' "$instance"
else
  printf 'Removed service and binary for %s; enrolled identity/state were preserved at %s.\n' "$instance" "$state_dir"
fi
