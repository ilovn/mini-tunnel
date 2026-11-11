from __future__ import annotations

import unittest
from unittest.mock import patch

from sigstore_bundle import BundleError, decode_snappy_block, download_bundle


class SigstoreBundleTests(unittest.TestCase):
    def test_decodes_snappy_literal_block(self) -> None:
        self.assertEqual(decode_snappy_block(b"\x0b\x28hello world"), b"hello world")

    def test_decodes_overlapping_snappy_copy(self) -> None:
        self.assertEqual(decode_snappy_block(b"\x05\x00a\x0e\x01\x00"), b"aaaaa")

    def test_rejects_invalid_copy_offset(self) -> None:
        with self.assertRaisesRegex(BundleError, "copy offset"):
            decode_snappy_block(b"\x02\x06\x00\x00")

    def test_rejects_truncated_literal(self) -> None:
        with self.assertRaisesRegex(BundleError, "literal exceeds"):
            decode_snappy_block(b"\x03\x08ab")

    def test_rejects_untrusted_bundle_host(self) -> None:
        with self.assertRaisesRegex(BundleError, "untrusted bundle URL"):
            download_bundle("https://example.com/attestation.json.sn")

    def test_decodes_and_parses_public_snappy_bundle(self) -> None:
        raw_json = b'{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}'
        # A Snappy literal block is sufficient to exercise the real response path.
        length = len(raw_json)
        self.assertLess(length, 256)
        compressed = bytes((length, 240, length - 1)) + raw_json

        class Response:
            headers = {"Content-Type": "application/x-snappy"}

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return None

            def read(self, _maximum: int) -> bytes:
                return compressed

        with patch("sigstore_bundle.urlopen", return_value=Response()):
            self.assertEqual(
                download_bundle("https://tmaproduction.blob.core.windows.net/path/object.json.sn"),
                {"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json"},
            )


if __name__ == "__main__":
    unittest.main()
