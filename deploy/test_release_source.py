from __future__ import annotations

import unittest

from release_source import ReleaseSourceError, resolve_tag_commit


COMMIT = "20abe0c9e798b43c171be65699b36824e20a82e0"
TAG_OBJECT = "a9c71f44d0670a948f27d8f66addef3f59bcd455"
NESTED_TAG_OBJECT = "1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d"


def ref(object_type: str, object_sha: str, tag: str = "v0.1.0") -> dict:
    return {
        "ref": f"refs/tags/{tag}",
        "object": {"type": object_type, "sha": object_sha},
    }


def annotated_tag(tag_sha: str, object_type: str, object_sha: str) -> dict:
    return {"sha": tag_sha, "object": {"type": object_type, "sha": object_sha}}


class ReleaseSourceTests(unittest.TestCase):
    def test_resolves_lightweight_tag(self) -> None:
        self.assertEqual(resolve_tag_commit(ref("commit", COMMIT), [], "v0.1.0"), COMMIT)

    def test_resolves_annotated_tag(self) -> None:
        self.assertEqual(
            resolve_tag_commit(
                ref("tag", TAG_OBJECT),
                [annotated_tag(TAG_OBJECT, "commit", COMMIT)],
                "v0.1.0",
            ),
            COMMIT,
        )

    def test_resolves_nested_annotated_tags(self) -> None:
        self.assertEqual(
            resolve_tag_commit(
                ref("tag", TAG_OBJECT),
                [
                    annotated_tag(TAG_OBJECT, "tag", NESTED_TAG_OBJECT),
                    annotated_tag(NESTED_TAG_OBJECT, "commit", COMMIT),
                ],
                "v0.1.0",
            ),
            COMMIT,
        )

    def test_rejects_wrong_tag_ref(self) -> None:
        with self.assertRaisesRegex(ReleaseSourceError, "different release tag"):
            resolve_tag_commit(ref("commit", COMMIT, "v9.9.9"), [], "v0.1.0")

    def test_rejects_mismatched_annotated_tag_response(self) -> None:
        with self.assertRaisesRegex(ReleaseSourceError, "does not match"):
            resolve_tag_commit(
                ref("tag", TAG_OBJECT),
                [annotated_tag(NESTED_TAG_OBJECT, "commit", COMMIT)],
                "v0.1.0",
            )

    def test_rejects_incomplete_chain(self) -> None:
        with self.assertRaisesRegex(ReleaseSourceError, "incomplete"):
            resolve_tag_commit(ref("tag", TAG_OBJECT), [], "v0.1.0")

    def test_rejects_unexpected_tag_object_after_commit(self) -> None:
        with self.assertRaisesRegex(ReleaseSourceError, "extra objects"):
            resolve_tag_commit(
                ref("commit", COMMIT),
                [annotated_tag(TAG_OBJECT, "commit", COMMIT)],
                "v0.1.0",
            )

    def test_rejects_invalid_commit_sha(self) -> None:
        with self.assertRaisesRegex(ReleaseSourceError, "invalid target SHA"):
            resolve_tag_commit(ref("commit", "not-a-sha"), [], "v0.1.0")

    def test_rejects_excessive_annotated_tag_depth(self) -> None:
        hashes = [f"{index:040x}" for index in range(1, 11)]
        tag_objects = [
            annotated_tag(hashes[index], "tag", hashes[index + 1])
            for index in range(9)
        ]
        with self.assertRaisesRegex(ReleaseSourceError, "exceeds the supported depth"):
            resolve_tag_commit(ref("tag", hashes[0]), tag_objects, "v0.1.0")


if __name__ == "__main__":
    unittest.main()
