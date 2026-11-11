#!/usr/bin/env python3
"""Fetch GitHub's public attestation bundle and decode its Snappy block."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlparse
from urllib.request import Request, urlopen


MAX_API_BYTES = 4 * 1024 * 1024
MAX_BUNDLE_BYTES = 16 * 1024 * 1024
MAX_UNCOMPRESSED_BYTES = 16 * 1024 * 1024


class BundleError(ValueError):
    pass


def decode_snappy_block(data: bytes) -> bytes:
    """Decode one Snappy raw block with strict length and offset bounds."""
    position = 0
    expected = 0
    shift = 0
    while True:
        if position >= len(data) or shift > 28:
            raise BundleError("invalid Snappy length prefix")
        byte = data[position]
        position += 1
        expected |= (byte & 0x7F) << shift
        if byte < 0x80:
            break
        shift += 7
    if expected > MAX_UNCOMPRESSED_BYTES:
        raise BundleError("Snappy output exceeds the allowed size")

    output = bytearray()
    while position < len(data):
        tag = data[position]
        position += 1
        kind = tag & 0x03
        if kind == 0:
            encoded_length = tag >> 2
            if encoded_length < 60:
                length = encoded_length + 1
            else:
                extra_bytes = encoded_length - 59
                if extra_bytes > 4 or position + extra_bytes > len(data):
                    raise BundleError("invalid Snappy literal length")
                length = int.from_bytes(data[position : position + extra_bytes], "little") + 1
                position += extra_bytes
            end = position + length
            if end > len(data) or len(output) + length > expected:
                raise BundleError("Snappy literal exceeds input or output length")
            output.extend(data[position:end])
            position = end
            continue

        if kind == 1:
            if position >= len(data):
                raise BundleError("truncated Snappy copy-1 command")
            length = 4 + ((tag >> 2) & 0x07)
            offset = ((tag & 0xE0) << 3) | data[position]
            position += 1
        elif kind == 2:
            if position + 2 > len(data):
                raise BundleError("truncated Snappy copy-2 command")
            length = 1 + (tag >> 2)
            offset = int.from_bytes(data[position : position + 2], "little")
            position += 2
        else:
            if position + 4 > len(data):
                raise BundleError("truncated Snappy copy-4 command")
            length = 1 + (tag >> 2)
            offset = int.from_bytes(data[position : position + 4], "little")
            position += 4

        if offset == 0 or offset > len(output) or len(output) + length > expected:
            raise BundleError("invalid Snappy copy offset or output length")
        for _ in range(length):
            output.append(output[-offset])

    if len(output) != expected:
        raise BundleError("Snappy output length does not match its prefix")
    return bytes(output)


def read_limited(response, maximum: int) -> bytes:
    data = response.read(maximum + 1)
    if len(data) > maximum:
        raise BundleError("GitHub response exceeds the allowed size")
    return data


def get_json(url: str) -> dict:
    request = Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "mini-tunnel-attestation-verifier",
        },
    )
    with urlopen(request, timeout=30) as response:
        payload = read_limited(response, MAX_API_BYTES)
    value = json.loads(payload)
    if not isinstance(value, dict):
        raise BundleError("GitHub returned an unexpected attestation response")
    return value


def download_bundle(url: str) -> dict:
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname or not parsed.hostname.endswith(
        ".blob.core.windows.net"
    ):
        raise BundleError("GitHub returned an untrusted bundle URL")
    request = Request(url, headers={"User-Agent": "mini-tunnel-attestation-verifier"})
    with urlopen(request, timeout=30) as response:
        payload = read_limited(response, MAX_BUNDLE_BYTES)
        content_type = response.headers.get("Content-Type", "").lower()
    if "snappy" in content_type or payload[:1] != b"{":
        payload = decode_snappy_block(payload)
    value = json.loads(payload)
    if not isinstance(value, dict) or not value.get("mediaType", "").startswith(
        "application/vnd.dev.sigstore.bundle.v0."
    ):
        raise BundleError("GitHub returned an unexpected Sigstore bundle")
    return value


def fetch_bundles(repository: str, archive: Path, output: Path) -> int:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise BundleError("invalid repository")
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    subject_digest = quote(f"sha256:{digest}", safe="")
    query = urlencode({"per_page": "100", "predicate_type": "provenance"})
    api_url = f"https://api.github.com/repos/{repository}/attestations/{subject_digest}?{query}"
    response = get_json(api_url)
    entries = response.get("attestations", [])
    if not isinstance(entries, list) or not entries:
        raise BundleError("no public provenance bundle exists for this archive")

    bundles: list[dict] = []
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("bundle_url"), str):
            raise BundleError("GitHub returned a malformed attestation entry")
        bundles.append(download_bundle(entry["bundle_url"]))

    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(output, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        for bundle in bundles:
            stream.write(json.dumps(bundle, separators=(",", ":")))
            stream.write("\n")
    return len(bundles)


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: sigstore_bundle.py <repository> <archive> <output-jsonl>", file=sys.stderr)
        return 2
    try:
        count = fetch_bundles(sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3]))
    except (BundleError, HTTPError, URLError, OSError, json.JSONDecodeError) as error:
        print(f"could not fetch public Sigstore provenance: {error}", file=sys.stderr)
        return 1
    print(f"Fetched {count} public Sigstore bundle(s)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
