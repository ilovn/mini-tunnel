#!/usr/bin/env python3
"""Validate GitHub Git ref/tag API objects used for release source metadata."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any, List, Optional, Sequence, Tuple

SHA1 = re.compile(r"^[0-9a-fA-F]{40}$")
MAX_ANNOTATED_TAG_DEPTH = 8


class ReleaseSourceError(ValueError):
    """Raised when a release tag response cannot be safely resolved."""


def _object(payload: Any, *, expected_tag_sha: Optional[str] = None) -> Tuple[str, str]:
    if not isinstance(payload, dict):
        raise ReleaseSourceError("Git ref/tag response must be a JSON object")
    if expected_tag_sha is not None:
        actual_tag_sha = payload.get("sha")
        if not isinstance(actual_tag_sha, str) or not SHA1.fullmatch(actual_tag_sha):
            raise ReleaseSourceError("annotated tag response has an invalid tag object SHA")
        if actual_tag_sha.lower() != expected_tag_sha.lower():
            raise ReleaseSourceError("annotated tag response SHA does not match the requested object")
    target = payload.get("object")
    if not isinstance(target, dict):
        raise ReleaseSourceError("Git ref/tag response has no target object")
    object_type = target.get("type")
    object_sha = target.get("sha")
    if object_type not in {"commit", "tag"}:
        raise ReleaseSourceError(f"unsupported Git object type: {object_type!r}")
    if not isinstance(object_sha, str) or not SHA1.fullmatch(object_sha):
        raise ReleaseSourceError("Git ref/tag response has an invalid target SHA")
    return object_type, object_sha


def ref_target(payload: Any, expected_tag: Optional[str] = None) -> Tuple[str, str]:
    """Return the type and SHA named by a GitHub refs/tags response."""
    if not isinstance(payload, dict) or not isinstance(payload.get("ref"), str):
        raise ReleaseSourceError("Git ref response has no ref name")
    if not payload["ref"].startswith("refs/tags/"):
        raise ReleaseSourceError("Git ref response is not a tag ref")
    if expected_tag is not None and payload["ref"] != f"refs/tags/{expected_tag}":
        raise ReleaseSourceError("Git ref response names a different release tag")
    return _object(payload)


def annotated_tag_target(expected_tag_sha: str, payload: Any) -> Tuple[str, str]:
    """Return the target of an annotated tag, checking the response object ID."""
    return _object(payload, expected_tag_sha=expected_tag_sha)


def resolve_tag_commit(
    ref_payload: Any,
    annotated_tags: Sequence[Any],
    expected_tag: Optional[str] = None,
) -> str:
    """Resolve a lightweight or annotated tag using its API object chain."""
    object_type, object_sha = ref_target(ref_payload, expected_tag)
    index = 0
    while object_type == "tag":
        if index >= MAX_ANNOTATED_TAG_DEPTH:
            raise ReleaseSourceError("annotated tag chain exceeds the supported depth")
        if index >= len(annotated_tags):
            raise ReleaseSourceError("annotated tag response chain is incomplete")
        object_type, object_sha = annotated_tag_target(object_sha, annotated_tags[index])
        index += 1
    if index != len(annotated_tags):
        raise ReleaseSourceError("annotated tag response chain has unexpected extra objects")
    return object_sha.lower()


def _read(path: str) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def main(argv: List[str]) -> int:
    try:
        if len(argv) == 4 and argv[1] == "ref":
            object_type, object_sha = ref_target(_read(argv[3]), argv[2])
        elif len(argv) == 4 and argv[1] == "tag":
            object_type, object_sha = annotated_tag_target(argv[2], _read(argv[3]))
        else:
            raise ReleaseSourceError("usage: release_source.py ref <expected-tag> <json-file> | tag <expected-sha> <json-file>")
    except (OSError, json.JSONDecodeError, ReleaseSourceError) as error:
        print(f"release source error: {error}", file=sys.stderr)
        return 1
    print(object_type, object_sha.lower())
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
