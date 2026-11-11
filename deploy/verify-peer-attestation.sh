#!/usr/bin/env bash
set -Eeuo pipefail

die() {
  printf 'attestation verification failed: %s\n' "$*" >&2
  exit 1
}

[[ $# == 5 ]] || die "usage: verify-peer-attestation.sh <archive> <repository> <ci.yml|release.yml> <source-ref> <source-commit>"
archive=$1
repository=$2
workflow=$3
source_ref=$4
source_commit=$5

[[ -f "$archive" && ! -L "$archive" ]] || die "archive must be a regular file"
[[ "$repository" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || die "invalid repository"
[[ "$source_commit" =~ ^[0-9a-fA-F]{40}$ ]] || die "invalid source commit"

case "$workflow:$source_ref" in
  ci.yml:refs/heads/main) ;;
  release.yml:refs/tags/v[A-Za-z0-9._/-]*) ;;
  *) die "workflow and source ref are not an approved peer build identity" ;;
esac

command -v gh >/dev/null || die "GitHub CLI (gh) is required to verify Sigstore provenance"
command -v python3 >/dev/null || die "python3 is required to fetch public Sigstore provenance"
normalized_source_commit=$(printf '%s' "$source_commit" | tr '[:upper:]' '[:lower:]')
temp_dir=$(mktemp -d "${TMPDIR:-/tmp}/mini-tunnel-attestation.XXXXXX")
cleanup() { rm -rf -- "$temp_dir"; }
trap cleanup EXIT
bundle_path="$temp_dir/bundles.jsonl"
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
python3 "$script_dir/sigstore_bundle.py" \
  "$repository" "$archive" "$bundle_path"

if ! GH_PROMPT_DISABLED=1 gh attestation verify "$archive" \
  --bundle "$bundle_path" \
  --repo "$repository" \
  --signer-workflow "$repository/.github/workflows/$workflow" \
  --source-ref "$source_ref" \
  --source-digest "$normalized_source_commit" \
  --deny-self-hosted-runners; then
  die "GitHub CLI rejected the archive provenance"
fi
