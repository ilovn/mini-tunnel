#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Download a prebuilt Linux binary and install/enroll one systemd peer.

Usage:
  deploy/quick-install-peer.sh [download options] -- [peer install options]

Download options (choose at most one source):
  --release <tag>        Published release (default: latest)
  --commit <full-sha>    Successful CI artifact for a source commit
  --run-id <id>          Successful CI artifact for a workflow run
  --arch <auto|x86_64|aarch64>
  --repo <owner/name>

Peer install options are forwarded to deploy/install-peer.sh, for example:
  --network-id <uuid> --coordinator-url <url> --invite-token-file <0600-file>
  --instance <name> [--stun-server host:port] [--relay-server host:port]

The script downloads a prebuilt artifact only. It does not compile binaries,
create networks, or issue invites. CI artifact mode requires GITHUB_TOKEN in the
environment; the token is not put in arguments or written to disk.
EOF
}

die() { printf 'error: %s\n' "$*" >&2; exit 1; }

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
download_args=()
install_args=()
after_separator=false

while (($#)); do
  if [[ "$after_separator" == true ]]; then
    install_args+=("$1")
    shift
    continue
  fi
  case "$1" in
    --)
      after_separator=true
      shift
      ;;
    --release|--commit|--run-id|--arch|--repo)
      (($# >= 2)) || die "$1 needs a value"
      download_args+=("$1" "$2")
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown download option: $1 (put peer installation options after --)"
      ;;
  esac
done

[[ "$after_separator" == true ]] || die "missing -- separator before peer installation options"
((${#install_args[@]} > 0)) || die "peer installation options are required after --"
for argument in "${install_args[@]}"; do
  [[ "$argument" != "--binary" ]] || die "--binary is selected by this script"
done

temp_dir=$(mktemp -d "${TMPDIR:-/tmp}/mini-tunnel-quick-install.XXXXXX")
cleanup() { rm -rf -- "$temp_dir"; }
trap cleanup EXIT

binary_dir="$temp_dir/download"
"$script_dir/download-peer.sh" --output-dir "$binary_dir" "${download_args[@]}"
binary="$binary_dir/mini-tunnel"
[[ -f "$binary" && -x "$binary" ]] || die "download did not produce an executable mini-tunnel binary"

if [[ ${EUID:-$(id -u)} -eq 0 ]]; then
  "$script_dir/install-peer.sh" --binary "$binary" "${install_args[@]}"
else
  command -v sudo >/dev/null || die "sudo is required to install the systemd peer service"
  sudo "$script_dir/install-peer.sh" --binary "$binary" "${install_args[@]}"
fi
