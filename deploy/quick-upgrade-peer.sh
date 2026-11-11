#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Download, verify, and atomically upgrade one installed Linux systemd peer.

Usage:
  deploy/quick-upgrade-peer.sh [download options] --instance <name> [--health-timeout <integer-seconds>]

Download options (choose exactly one source):
  --release <tag>        Exact published release
  --commit <full-sha>    Successful CI artifact for a source commit
  --run-id <id>          Successful CI artifact for a workflow run
  --arch <auto|x86_64|aarch64>
  --repo <owner/name>

CI artifact mode requires GITHUB_TOKEN in the environment. The downloader
verifies the artifact checksum and Sigstore provenance before installation.
The previous binary is retained under /usr/local/lib/mini-tunnel/backups.
EOF
}

die() { printf 'error: %s\n' "$*" >&2; exit 1; }

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
download_args=()
upgrade_args=()
instance=
health_timeout=30
source_count=0

while (($#)); do
  case "$1" in
    --release|--commit|--run-id|--arch|--repo)
      (($# >= 2)) || die "$1 needs a value"
      case "$1" in
        --release|--commit|--run-id) source_count=$((source_count + 1)) ;;
      esac
      if [[ "$1" == --release && "$2" == latest ]]; then
        die "peer upgrades require a fixed release tag; 'latest' may be older than the installed build"
      fi
      download_args+=("$1" "$2")
      shift 2
      ;;
    --instance|--health-timeout)
      (($# >= 2)) || die "$1 needs a value"
      upgrade_args+=("$1" "$2")
      [[ "$1" != --instance ]] || instance=$2
      [[ "$1" != --health-timeout ]] || health_timeout=$2
      shift 2
      ;;
    --binary) die "--binary is selected by the verified downloader" ;;
    -h|--help)
      usage
      exit 0
      ;;
    *) die "unknown option: $1" ;;
  esac
done

[[ -n "$instance" ]] || die "--instance is required"
[[ "$instance" =~ ^[A-Za-z0-9_-]{1,48}$ ]] || die "invalid instance name"
[[ "$health_timeout" =~ ^[1-9][0-9]{0,2}$ ]] || die "--health-timeout must be a positive integer"
(( health_timeout <= 300 )) || die "--health-timeout must not exceed 300 seconds"
(( source_count == 1 )) || die "select exactly one explicit source: --release, --commit, or --run-id"
[[ "$(uname -s)" == Linux ]] || die "systemd peer upgrades require Linux"
for argument in "${upgrade_args[@]}"; do
  [[ "$argument" != "--binary" ]] || die "--binary is selected by the verified downloader"
done

temp_dir=$(mktemp -d "${TMPDIR:-/tmp}/mini-tunnel-quick-upgrade.XXXXXX")
cleanup() { rm -rf -- "$temp_dir"; }
trap cleanup EXIT

binary_dir="$temp_dir/download"
"$script_dir/download-peer.sh" --output-dir "$binary_dir" "${download_args[@]}"
binary="$binary_dir/mini-tunnel"
[[ -f "$binary" && -x "$binary" ]] || die "download did not produce an executable mini-tunnel binary"
unset GITHUB_TOKEN GH_TOKEN

if [[ ${EUID:-$(id -u)} -eq 0 ]]; then
  python3 "$script_dir/upgrade_peer.py" --binary "$binary" "${upgrade_args[@]}"
else
  command -v sudo >/dev/null || die "sudo is required to upgrade the systemd peer service"
  sudo python3 "$script_dir/upgrade_peer.py" --binary "$binary" "${upgrade_args[@]}"
fi
