#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Download a mini-tunnel Linux peer binary from GitHub.

Usage:
  deploy/download-peer.sh [--output-dir ./mini-tunnel-download] \
    [--arch auto|x86_64|aarch64] [--release vX.Y.Z] \
    [--repo owner/name] [--force]

  deploy/download-peer.sh [--output-dir ./mini-tunnel-download] \
    [--arch auto|x86_64|aarch64] [--commit <full-sha>|--run-id <id>] \
    [--repo owner/name] [--force]

With no source option, fetch the newest stable published GitHub Release asset
without a token. Pass --release for a reproducible deployment. Use --commit or
--run-id only for pre-release validation of a successful CI run. GitHub CI
artifacts are retained for 30 days; this script does not create or install
services.

For the CI artifact mode, set GITHUB_TOKEN because Actions artifact ZIP
downloads require authentication. The token is read only from the environment
and is never written to disk or output. A recent GitHub CLI (gh) with artifact
attestation support is required to verify the archive's Sigstore provenance
against the repository, workflow, source ref, and source commit before use.
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
artifact_id=
release=
attestation_workflow=
attestation_source_ref=
output_dir=./mini-tunnel-download
force=false
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

while (($#)); do
  case "$1" in
    --repo) (($# >= 2)) || usage_error "--repo needs a value"; repository=$2; shift 2 ;;
    --arch) (($# >= 2)) || usage_error "--arch needs a value"; architecture=$2; shift 2 ;;
    --commit) (($# >= 2)) || usage_error "--commit needs a value"; commit=$2; shift 2 ;;
    --run-id) (($# >= 2)) || usage_error "--run-id needs a value"; run_id=$2; shift 2 ;;
    --release) (($# >= 2)) || usage_error "--release needs a value"; release=$2; shift 2 ;;
    --output-dir) (($# >= 2)) || usage_error "--output-dir needs a value"; output_dir=$2; shift 2 ;;
    --force) force=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage_error "unknown argument: $1" ;;
  esac
done

[[ "$repository" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || die "invalid repository: $repository"
[[ -z "$run_id" || "$run_id" =~ ^[0-9]+$ ]] || die "run ID must be numeric"
[[ -z "$commit" || "$commit" =~ ^[0-9a-fA-F]{40}$ ]] || die "commit must be a full 40-character SHA-1"
[[ -z "$release" || "$release" =~ ^[A-Za-z0-9][A-Za-z0-9._/-]*$ ]] || die "invalid release tag: $release"
selected=0
[[ -n "$release" ]] && selected=$((selected + 1))
[[ -n "$commit" ]] && selected=$((selected + 1))
[[ -n "$run_id" ]] && selected=$((selected + 1))
((selected <= 1)) || die "use only one of --release, --commit, or --run-id"
if [[ -z "$release" && -z "$commit" && -z "$run_id" ]]; then
  release=latest
fi
[[ -n "$release" || -n "${GITHUB_TOKEN:-}" ]] || die "GITHUB_TOKEN is required for the CI artifact mode"
case "$architecture" in
  auto|x86_64|aarch64) ;;
  *) die "architecture must be auto, x86_64, or aarch64" ;;
esac
[[ -n "$output_dir" ]] || die "output directory must not be empty"

command -v curl >/dev/null || die "curl is required"
command -v python3 >/dev/null || die "python3 is required for safe archive handling"
command -v tar >/dev/null || die "tar is required"
command -v gzip >/dev/null || die "gzip is required"
command -v gh >/dev/null || die "GitHub CLI (gh) is required to verify Sigstore provenance"

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
auth_header=()
[[ -z "${GITHUB_TOKEN:-}" ]] || auth_header=(--header "Authorization: Bearer $GITHUB_TOKEN")

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

release_field() {
  RELEASE_JSON=$1 FIELD=$2 python3 - <<'PY'
import json
import os

field = os.environ["FIELD"]
release = json.loads(os.environ["RELEASE_JSON"])
value = release.get(field)
print("" if value is None else str(value))
PY
}

asset_field() {
  ASSET_JSON=$1 FIELD=$2 python3 - <<'PY'
import json
import os

field = os.environ["FIELD"]
asset = json.loads(os.environ["ASSET_JSON"])
value = asset.get(field)
print("" if value is None else str(value))
PY
}

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

if [[ -n "$release" ]]; then
  requested_release=$release
  release_json_file="$temp_dir/release.json"
  if [[ "$requested_release" == latest ]]; then
    printf 'Looking up the latest stable release...\n' >&2
    api_get "/releases/latest" "$release_json_file"
  else
    printf 'Looking up release %s...\n' "$requested_release" >&2
    api_get "/releases/tags/$requested_release" "$release_json_file"
  fi
  release_json=$(cat "$release_json_file")
  release=$(release_field "$release_json" tag_name)
  [[ "$release" =~ ^[A-Za-z0-9][A-Za-z0-9._/-]*$ ]] || die "GitHub returned an invalid release tag: $release"
  [[ "$requested_release" == latest || "$requested_release" == "$release" ]] || die "GitHub returned unexpected release tag: $release"
  [[ "$(release_field "$release_json" draft)" == False ]] || die "release $release is a draft, not a published release"
  assets_json=$(RELEASE_JSON=$release_json python3 - <<'PY'
import json
import os

assets = json.loads(os.environ["RELEASE_JSON"]).get("assets", [])
print(json.dumps(assets))
PY
)
  archive_asset=$(ASSETS_JSON=$assets_json ARCHIVE_NAME=$artifact_name.tar.gz python3 - <<'PY'
import json
import os

name = os.environ["ARCHIVE_NAME"]
for asset in json.loads(os.environ["ASSETS_JSON"]):
    if asset.get("name") == name and asset.get("state") == "uploaded":
        print(json.dumps(asset, separators=(",", ":")))
        break
PY
)
  [[ -n "$archive_asset" ]] || die "release $release has no uploaded archive named $artifact_name.tar.gz"
  checksum_asset=$(ASSETS_JSON=$assets_json ARCHIVE_NAME=$artifact_name.tar.gz.sha256 python3 - <<'PY'
import json
import os

name = os.environ["ARCHIVE_NAME"]
for asset in json.loads(os.environ["ASSETS_JSON"]):
    if asset.get("name") == name and asset.get("state") == "uploaded":
        print(json.dumps(asset, separators=(",", ":")))
        break
PY
)
  [[ -n "$checksum_asset" ]] || die "release $release has no uploaded checksum named $artifact_name.tar.gz.sha256"

  archive_path="$temp_dir/$artifact_name.tar.gz"
  checksum_path="$temp_dir/$artifact_name.tar.gz.sha256"
  archive_url=$(asset_field "$archive_asset" browser_download_url)
  checksum_url=$(asset_field "$checksum_asset" browser_download_url)
  printf 'Downloading release archive...\n' >&2
  curl --silent --show-error --fail --location --retry 3 --retry-delay 2 \
    --connect-timeout 15 --max-time 600 \
    --output "$archive_path" "$archive_url"
  curl --silent --show-error --fail --location --retry 3 --retry-delay 2 \
    --connect-timeout 15 --max-time 60 \
    --output "$checksum_path" "$checksum_url"
  archive_sha256=$(asset_field "$archive_asset" digest)
  [[ "$archive_sha256" =~ ^sha256:[0-9a-fA-F]{64}$ ]] || die "GitHub did not return a valid release asset digest"
  archive_sha256=${archive_sha256#sha256:}

  encoded_release=$(RELEASE_TAG=$release python3 - <<'PY'
import os
from urllib.parse import quote

print(quote(os.environ["RELEASE_TAG"], safe=""))
PY
)
  tag_ref_file="$temp_dir/tag-ref.json"
  api_get "/git/ref/tags/$encoded_release" "$tag_ref_file"
  object_ref=$(python3 "$script_dir/release_source.py" ref "$release" "$tag_ref_file") || die "could not resolve release tag $release"
  read -r object_type object_sha <<<"$object_ref"
  tag_depth=0
  while [[ "$object_type" == tag ]]; do
    ((tag_depth < 8)) || die "release tag $release exceeds the supported annotated-tag depth"
    tag_object_file="$temp_dir/tag-object-$tag_depth.json"
    api_get "/git/tags/$object_sha" "$tag_object_file"
    object_ref=$(python3 "$script_dir/release_source.py" tag "$object_sha" "$tag_object_file") || die "could not resolve annotated release tag $release"
    read -r object_type object_sha <<<"$object_ref"
    tag_depth=$((tag_depth + 1))
  done
  [[ "$object_type" == commit && "$object_sha" =~ ^[0-9a-fA-F]{40}$ ]] || die "release tag $release did not resolve to a commit"
  head_sha=$(printf '%s' "$object_sha" | tr '[:upper:]' '[:lower:]')
  attestation_workflow=release.yml
  attestation_source_ref="refs/tags/$release"
  commit_json_file="$temp_dir/commit.json"
  api_get "/commits/$head_sha" "$commit_json_file"
  commit_json=$(cat "$commit_json_file")
  commit_api_sha=$(COMMIT_JSON=$commit_json python3 - <<'PY'
import json
import os

print(json.loads(os.environ["COMMIT_JSON"]).get("sha", ""))
PY
)
  normalized_commit_api_sha=$(printf '%s' "$commit_api_sha" | tr '[:upper:]' '[:lower:]')
  [[ "$normalized_commit_api_sha" == "$head_sha" ]] || die "GitHub commit response did not match the resolved release tag"
  created_at=$(COMMIT_JSON=$commit_json python3 - <<'PY'
import json
import os

print(json.loads(os.environ["COMMIT_JSON"]).get("commit", {}).get("committer", {}).get("date", ""))
PY
)
fi

if [[ -z "$release" ]]; then
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
  # List recent runs and select the exact successful commit client-side. The
  # workflow-runs endpoint does not support a head_sha filter.
  api_get "/actions/workflows/ci.yml/runs?per_page=100" "$runs_file"
  run_id=$(RUNS_FILE=$runs_file COMMIT_SHA=$commit python3 - <<'PY'
import json
import os
import sys

runs = json.load(open(os.environ["RUNS_FILE"], encoding="utf-8")).get("workflow_runs", [])
successful = [
    run for run in runs
    if run.get("status") == "completed"
    and run.get("conclusion") == "success"
    and run.get("event") != "pull_request"
    and run.get("head_sha", "").lower() == os.environ.get("COMMIT_SHA", "").lower()
]
if not successful:
    sys.exit(2)
successful.sort(key=lambda run: run.get("created_at") or "", reverse=True)
print(successful[0]["id"])
PY
) || die "no successful CI workflow run found for commit $commit"
else
  printf 'Discovering successful main-branch CI runs...\n' >&2
  runs_file="$temp_dir/runs.json"
  api_get "/actions/workflows/ci.yml/runs?per_page=100" "$runs_file"
  candidate_run_ids=$(RUNS_FILE=$runs_file python3 - <<'PY'
import json
import os

runs = json.load(open(os.environ["RUNS_FILE"], encoding="utf-8")).get("workflow_runs", [])
runs.sort(key=lambda run: run.get("created_at") or "", reverse=True)
for run in runs:
    if (run.get("status") == "completed" and run.get("conclusion") == "success"
            and run.get("event") != "pull_request" and run.get("head_branch") == "main"):
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
event=$(run_field "$run_json" event)
head_branch=$(run_field "$run_json" head_branch)
[[ "$status" == completed && "$conclusion" == success ]] || die "CI run $run_id is not completed successfully"
[[ "$head_sha" =~ ^[0-9a-fA-F]{40}$ ]] || die "CI run $run_id did not return a valid source commit"
[[ "$event" != pull_request && "$head_branch" == main ]] || die "CI run $run_id is not a main-branch build"
attestation_workflow=ci.yml
attestation_source_ref=refs/heads/main

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
fi

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

actual_checksum=$(sha256_file "$archive_path")
[[ "$actual_checksum" == "$expected_checksum" ]] || die "archive checksum mismatch: expected $expected_checksum, got $actual_checksum"
if [[ -n "$release" ]]; then
  [[ "$actual_checksum" == "$archive_sha256" ]] || die "GitHub release digest does not match downloaded archive"
fi

printf 'Verifying GitHub Sigstore provenance...\n' >&2
"$script_dir/verify-peer-attestation.sh" \
  "$archive_path" "$repository" "$attestation_workflow" \
  "$attestation_source_ref" "$head_sha"

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
MODE=$([[ -n "$release" ]] && printf release || printf ci-artifact) \
RELEASE_TAG=$release \
SOURCE_RESOLUTION=$([[ -n "$release" ]] && printf git-tag-ref || printf ci-workflow-run) \
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
    "mode": os.environ["MODE"],
    "commit_sha": os.environ["COMMIT_SHA"],
    "source_commit_resolution": os.environ["SOURCE_RESOLUTION"],
    "artifact_name": os.environ["ARTIFACT_NAME"],
    "archive_sha256": os.environ["ARCHIVE_SHA256"],
    "binary_sha256": os.environ["BINARY_SHA256"],
    "downloaded_at": os.environ["GENERATED_AT"],
}
if os.environ["MODE"] == "ci-artifact":
    metadata["ci_run_id"] = int(os.environ["RUN_ID"])
    metadata["artifact_id"] = int(os.environ["ARTIFACT_ID"])
    metadata["ci_created_at"] = os.environ["CREATED_AT"]
    metadata["verified"] = ["artifact_zip_crc", "inner_archive_sha256", "single_regular_binary", "sigstore_provenance"]
else:
    metadata["release"] = os.environ["RELEASE_TAG"]
    metadata["created_at"] = os.environ["CREATED_AT"]
    metadata["verified"] = ["asset_digest", "published_sha256", "tag_ref_commit", "single_regular_binary", "sigstore_provenance"]
with open(os.environ["METADATA_PATH"], "w", encoding="utf-8") as output_file:
    json.dump(metadata, output_file, indent=2, sort_keys=True)
    output_file.write("\n")
PY
mv -f -- "$metadata_tmp" "$metadata_path"
metadata_tmp=

printf 'Downloaded %s\n' "$final_binary"
printf 'Commit: %s\n' "$head_sha"
if [[ -n "$release" ]]; then
  printf 'Release: %s\n' "$release"
else
  printf 'CI run: %s\n' "$run_id"
  printf 'Artifact: %s (%s)\n' "$artifact_name" "$artifact_id"
fi
printf 'Binary SHA-256: %s\n' "$binary_sha256"
printf 'Provenance: %s\n' "$metadata_path"
