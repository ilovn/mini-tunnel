#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Download a mini-tunnel Linux peer binary from a successful GitHub CI run.

Usage:
  deploy/download-peer.sh [--output-dir ./mini-tunnel-download] \
    [--arch auto|x86_64|aarch64] [--commit <full-sha>] [--run-id <id>] \
    [--repo owner/name] [--force]

The default discovers the newest successful main-branch CI run with a usable
artifact. Prefer --commit for reproducible deployments. GitHub CI artifacts are
retained for 30 days; this script does not create or install services.

Set GITHUB_TOKEN to use an authenticated GitHub API request. The token is read
only from the environment and is never written to disk or output.
EOF
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

usage_error() {
  usage >&2
  die "$*"
}

repository=ilovn/mini-tunnel
architecture=auto
commit=
run_id=
output_dir=./mini-tunnel-download
force=false

while (($#)); do
  case "$1" in
    --repo) (($# >= 2)) || usage_error "--repo needs a value"; repository=$2; shift 2 ;;
    --arch) (($# >= 2)) || usage_error "--arch needs a value"; architecture=$2; shift 2 ;;
    --commit) (($# >= 2)) || usage_error "--commit needs a value"; commit=$2; shift 2 ;;
    --run-id) (($# >= 2)) || usage_error "--run-id needs a value"; run_id=$2; shift 2 ;;
    --output-dir) (($# >= 2)) || usage_error "--output-dir needs a value"; output_dir=$2; shift 2 ;;
    --force) force=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage_error "unknown argument: $1" ;;
  esac
done

[[ "$repository" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || die "invalid repository: $repository"
[[ -z "$run_id" || "$run_id" =~ ^[0-9]+$ ]] || die "run ID must be numeric"
[[ -z "$commit" || "$commit" =~ ^[0-9a-fA-F]{40}$ ]] || die "commit must be a full 40-character SHA-1"
case "$architecture" in
  auto|x86_64|aarch64) ;;
  *) die "architecture must be auto, x86_64, or aarch64" ;;
esac
[[ -n "$output_dir" ]] || die "output directory must not be empty"

command -v curl >/dev/null || die "curl is required"
command -v python3 >/dev/null || die "python3 is required for safe archive handling"
command -v tar >/dev/null || die "tar is required"
command -v gzip >/dev/null || die "gzip is required"
[[ -n "${GITHUB_TOKEN:-}" ]] || die "GITHUB_TOKEN is required because GitHub Actions artifact ZIP downloads require authentication"

case "$(uname -s)" in
  Linux|Darwin) ;;
  *) die "unsupported host operating system: $(uname -s)" ;;
esac

if [[ "$architecture" == auto ]]; then
  machine=$(uname -m)
  case "$machine" in
    x86_64|amd64) architecture=x86_64 ;;
    aarch64|arm64) architecture=aarch64 ;;
    *) die "unsupported machine architecture: $machine" ;;
  esac
fi

case "$architecture" in
  x86_64) artifact_name="mini-tunnel-linux-x86_64-ubuntu20.04" ;;
  aarch64) artifact_name="mini-tunnel-linux-aarch64-ubuntu22.04" ;;
esac

api_base=https://api.github.com
auth_header=(--header "Authorization: Bearer $GITHUB_TOKEN")

temp_dir=$(mktemp -d "${TMPDIR:-/tmp}/mini-tunnel-download.XXXXXX")
metadata_tmp=
binary_tmp=
cleanup() {
  rm -rf -- "$temp_dir"
  [[ -z "$metadata_tmp" || ! -e "$metadata_tmp" ]] || rm -f -- "$metadata_tmp"
  [[ -z "$binary_tmp" || ! -e "$binary_tmp" ]] || rm -f -- "$binary_tmp"
}
trap cleanup EXIT

api_get() {
  local path=$1 output=$2
  path="/repos/$repository$path"
  if ! curl --silent --show-error --fail --location --retry 3 --retry-delay 2 \
    --connect-timeout 15 --max-time 60 \
    --header 'Accept: application/vnd.github+json' \
    --header 'X-GitHub-Api-Version: 2022-11-28' \
    "${auth_header[@]}" \
    --output "$output" "$api_base$path"; then
    printf 'GitHub API request failed: %s\n' "$api_base$path" >&2
    if [[ -s "$output" ]]; then
      python3 - "$output" <<'PY' >&2
import json
import sys

try:
    response = json.load(open(sys.argv[1], encoding="utf-8"))
    print(response.get("message", "GitHub returned an unreadable error response"))
except Exception:
    print("GitHub returned an unreadable error response")
PY
    fi
    return 1
  fi
}

run_field() {
  RUN_JSON=$1 FIELD=$2 python3 - <<'PY'
import json
import os
import sys

field = os.environ["FIELD"]
run = json.loads(os.environ["RUN_JSON"])
value = run.get(field)
print("" if value is None else str(value))
PY
}

if [[ -n "$run_id" ]]; then
  run_json_file="$temp_dir/selected-run.json"
  api_get "/actions/runs/$run_id" "$run_json_file"
  run_json=$(cat "$run_json_file")
  status=$(run_field "$run_json" status)
  conclusion=$(run_field "$run_json" conclusion)
  [[ "$status" == completed && "$conclusion" == success ]] || {
    die "CI run $run_id is not completed successfully (status=$status, conclusion=$conclusion)"
  }
elif [[ -n "$commit" ]]; then
  printf 'Looking up CI run for commit %s...\n' "$commit" >&2
  runs_file="$temp_dir/runs.json"
  api_get "/actions/workflows/ci.yml/runs?head_sha=$commit&status=success&per_page=100" "$runs_file"
  run_id=$(RUNS_JSON=$(cat "$runs_file") COMMIT_SHA=$commit python3 - <<'PY'
import json
import os
import sys

runs = json.loads(os.environ["RUNS_JSON"]).get("workflow_runs", [])
successful = [run for run in runs if run.get("head_sha", "").lower() == os.environ.get("COMMIT_SHA", "").lower()]
if not successful:
    sys.exit(2)
successful.sort(key=lambda run: run.get("created_at") or "", reverse=True)
print(successful[0]["id"])
PY
) || die "no successful CI workflow run found for commit $commit"
else
  printf 'Discovering successful main-branch CI runs...\n' >&2
  runs_file="$temp_dir/runs.json"
  api_get "/actions/workflows/ci.yml/runs?branch=main&status=success&per_page=100" "$runs_file"
  candidate_run_ids=$(RUNS_JSON=$(cat "$runs_file") python3 - <<'PY'
import json
import os

runs = json.loads(os.environ["RUNS_JSON"]).get("workflow_runs", [])
runs.sort(key=lambda run: run.get("created_at") or "", reverse=True)
for run in runs:
    if run.get("conclusion") == "success" and run.get("event") != "pull_request":
        print(run["id"])
PY
)
  [[ -n "$candidate_run_ids" ]] || die "no successful main-branch CI runs were found"
fi

select_artifact() {
  local selected_run_id=$1 artifacts_file
  printf 'Looking for %s in CI run %s...\n' "$artifact_name" "$selected_run_id" >&2
  artifacts_file="$temp_dir/artifacts-$selected_run_id.json"
  api_get "/actions/runs/$selected_run_id/artifacts?per_page=100" "$artifacts_file"
  ARTIFACTS_JSON=$(cat "$artifacts_file") ARTIFACT_NAME=$artifact_name python3 - <<'PY'
import json
import os

artifacts = json.loads(os.environ["ARTIFACTS_JSON"]).get("artifacts", [])
for artifact in artifacts:
    if artifact.get("name") == os.environ["ARTIFACT_NAME"] and not artifact.get("expired", False):
        print(artifact["id"])
        break
PY
}

if [[ -z "$run_id" ]]; then
  while IFS= read -r candidate_run_id; do
    [[ -n "$candidate_run_id" ]] || continue
    run_id=$(select_artifact "$candidate_run_id") && [[ -n "$run_id" ]] && break
    run_id=
  done <<EOF
$candidate_run_ids
EOF
  [[ -n "$run_id" ]] || die "no non-expired $artifact_name artifact was found in recent successful runs; artifacts are retained for 30 days"
else
  artifact_id=$(select_artifact "$run_id")
  [[ -n "$artifact_id" ]] || die "CI run $run_id has no non-expired $artifact_name artifact"
fi

run_json_file="$temp_dir/run-$run_id.json"
api_get "/actions/runs/$run_id" "$run_json_file"
run_json=$(cat "$run_json_file")
status=$(run_field "$run_json" status)
conclusion=$(run_field "$run_json" conclusion)
head_sha=$(run_field "$run_json" head_sha)
created_at=$(run_field "$run_json" created_at)
[[ "$status" == completed && "$conclusion" == success ]] || die "CI run $run_id is not completed successfully"
[[ "$head_sha" =~ ^[0-9a-fA-F]{40}$ ]] || die "CI run $run_id did not return a valid source commit"

artifact_json_file="$temp_dir/artifact-$artifact_id.json"
printf 'Validating artifact %s...\n' "$artifact_id" >&2
api_get "/actions/artifacts/$artifact_id" "$artifact_json_file"
artifact_json=$(cat "$artifact_json_file")
returned_name=$(run_field "$artifact_json" name)
[[ "$returned_name" == "$artifact_name" ]] || die "GitHub returned unexpected artifact name: $returned_name"

artifact_zip="$temp_dir/artifact.zip"
printf 'Downloading artifact ZIP...\n' >&2
curl --silent --show-error --fail --location --retry 3 --retry-delay 2 \
  --connect-timeout 15 --max-time 600 \
  "${auth_header[@]}" \
  --output "$artifact_zip" \
  "$api_base/repos/$repository/actions/artifacts/$artifact_id/zip"

extract_zip() {
  ZIP_PATH=$1 DESTINATION=$2 python3 - <<'PY'
import os
import pathlib
import zipfile

maximum_member_bytes = 128 * 1024 * 1024
source = pathlib.Path(os.environ["ZIP_PATH"])
destination = pathlib.Path(os.environ["DESTINATION"])
destination.mkdir(mode=0o700, parents=True, exist_ok=True)

with zipfile.ZipFile(source) as archive:
    members = archive.infolist()
    names = [member.filename for member in members]
    if len(names) != 2 or any("/" in name or "\\" in name for name in names):
        raise ValueError(f"artifact ZIP must contain exactly two flat members, got {names!r}")
    archive_members = [name for name in names if name.endswith(".tar.gz")]
    checksum_members = [name for name in names if name == archive_members[0] + ".sha256"] if archive_members else []
    if len(archive_members) != 1 or len(checksum_members) != 1:
        raise ValueError("artifact ZIP must contain one .tar.gz archive and its .sha256 file")
    for member in members:
        if member.is_dir() or member.file_size > maximum_member_bytes:
            raise ValueError(f"unsafe or oversized ZIP member: {member.filename}")
        if member.filename == archive_members[0] and not member.filename.startswith("mini-tunnel-linux-"):
            raise ValueError(f"unexpected archive name: {member.filename}")
        target = destination / member.filename
        with archive.open(member) as input_file, target.open("xb") as output_file:
            while chunk := input_file.read(1024 * 1024):
                output_file.write(chunk)
        target.chmod(0o644)
PY
}

extract_zip "$artifact_zip" "$temp_dir/extracted"
printf 'Verifying inner archive checksum...\n' >&2
archive_path="$temp_dir/extracted/$artifact_name.tar.gz"
checksum_path="$temp_dir/extracted/$artifact_name.tar.gz.sha256"
[[ -f "$archive_path" && ! -L "$archive_path" ]] || die "extracted archive is missing or unsafe"
[[ -f "$checksum_path" && ! -L "$checksum_path" ]] || die "extracted checksum file is missing or unsafe"

checksum_fields=$(CHECKSUM_PATH=$checksum_path ARCHIVE_NAME=$artifact_name.tar.gz python3 - <<'PY'
import os
import pathlib
import re

line = pathlib.Path(os.environ["CHECKSUM_PATH"]).read_text(encoding="utf-8").strip()
if "\n" in line:
    raise ValueError("checksum file must contain exactly one line")
match = re.fullmatch(r"([0-9a-fA-F]{64})[ \t]+\*?(.+)", line)
if not match:
    raise ValueError("checksum file is not in the expected SHA-256 format")
if match.group(2) != os.environ["ARCHIVE_NAME"]:
    raise ValueError(f"checksum names {match.group(2)!r}, expected {os.environ['ARCHIVE_NAME']!r}")
print(os.environ["ARCHIVE_NAME"], match.group(1).lower())
PY
)
read -r archive_name expected_checksum <<<"$checksum_fields"

sha256_file() {
  FILE_PATH=$1 python3 - <<'PY'
import hashlib
import os

digest = hashlib.sha256()
with open(os.environ["FILE_PATH"], "rb") as input_file:
    while chunk := input_file.read(1024 * 1024):
        digest.update(chunk)
print(digest.hexdigest())
PY
}

actual_checksum=$(sha256_file "$archive_path")
[[ "$actual_checksum" == "$expected_checksum" ]] || die "archive checksum mismatch: expected $expected_checksum, got $actual_checksum"

tar_listing=$(tar -tzf "$archive_path")
[[ "$tar_listing" == "mini-tunnel" ]] || die "release archive must contain only mini-tunnel; got: $tar_listing"
staging_dir="$temp_dir/binary"
mkdir -p -- "$staging_dir"
tar -xzf "$archive_path" -C "$staging_dir" mini-tunnel
staged_binary="$staging_dir/mini-tunnel"
[[ -f "$staged_binary" && ! -L "$staged_binary" ]] || die "extracted binary is missing or not a regular file"

binary_sha256=$(sha256_file "$staged_binary")
case "$(uname -s)" in
  Linux)
    "$staged_binary" --help >/dev/null || die "downloaded binary cannot execute on this machine"
    ;;
  Darwin)
    printf 'warning: skipped Linux binary execution preflight on Darwin\n' >&2
    ;;
esac

mkdir -p -- "$output_dir"
final_binary="$output_dir/mini-tunnel"
if [[ -e "$final_binary" && "$force" != true ]]; then
  die "output already exists: $final_binary (use --force to replace it)"
fi
binary_tmp="$output_dir/.mini-tunnel.$$.tmp"
cp -- "$staged_binary" "$binary_tmp"
chmod 0755 "$binary_tmp"
mv -f -- "$binary_tmp" "$final_binary"
binary_tmp=

generated_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
metadata_path="$output_dir/download.json"
metadata_tmp="$output_dir/.download.$$.json"
METADATA_PATH=$metadata_tmp \
REPOSITORY=$repository \
COMMIT_SHA=$head_sha \
RUN_ID=$run_id \
ARTIFACT_ID=$artifact_id \
ARTIFACT_NAME=$artifact_name \
ARCHIVE_SHA256=$actual_checksum \
BINARY_SHA256=$binary_sha256 \
CREATED_AT=$created_at \
GENERATED_AT=$generated_at \
python3 - <<'PY'
import json
import os

metadata = {
    "repository": os.environ["REPOSITORY"],
    "commit_sha": os.environ["COMMIT_SHA"],
    "ci_run_id": int(os.environ["RUN_ID"]),
    "artifact_id": int(os.environ["ARTIFACT_ID"]),
    "artifact_name": os.environ["ARTIFACT_NAME"],
    "archive_sha256": os.environ["ARCHIVE_SHA256"],
    "binary_sha256": os.environ["BINARY_SHA256"],
    "ci_created_at": os.environ["CREATED_AT"],
    "downloaded_at": os.environ["GENERATED_AT"],
    "verified": ["artifact_zip_crc", "inner_archive_sha256", "single_regular_binary"],
}
with open(os.environ["METADATA_PATH"], "w", encoding="utf-8") as output_file:
    json.dump(metadata, output_file, indent=2, sort_keys=True)
    output_file.write("\n")
PY
mv -f -- "$metadata_tmp" "$metadata_path"
metadata_tmp=

printf 'Downloaded %s\n' "$final_binary"
printf 'Commit: %s\n' "$head_sha"
printf 'CI run: %s\n' "$run_id"
printf 'Artifact: %s (%s)\n' "$artifact_name" "$artifact_id"
printf 'Binary SHA-256: %s\n' "$binary_sha256"
printf 'Provenance: %s\n' "$metadata_path"
