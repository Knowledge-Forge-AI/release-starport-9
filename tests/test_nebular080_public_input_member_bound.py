"""Public-repository regression for the Nebular 0.8 input member bound.

Run this module from the composed source tree with its ``src`` directory on
``PYTHONPATH``.  It imports the maintained rs9 modules directly; it does not
patch constants, construct a fake reader, or download release bodies.
"""

from __future__ import annotations

import unittest
from unittest import mock

from rs9 import nebular080_publication_coordinates as coordinates
from rs9 import nebular080_universal_publication as publication
from rs9.errors import ContractError


PAYLOAD_ROWS = (
    (
        "theme-forge-nebular-fusion-v0.8.0-aarch64-apple-darwin.app.tar.gz",
        49_769_994,
        "0a7ab188afc4660f68bd6dabfda96309a348108a8d77a4786df1731cddaf6896",
    ),
    (
        "theme-forge-nebular-fusion-v0.8.0-aarch64-unknown-linux-gnu.tar.gz",
        57_038_323,
        "4bbc40f180d954e1ca496606da9b63d7ce0f49dd29e802893aabc4aa0e859e94",
    ),
    (
        "theme-forge-nebular-fusion-v0.8.0-x86_64-unknown-linux-gnu.tar.gz",
        56_825_312,
        "498f0f6ff81c32200843e04016f86f7733905df0b0712c3f3639162ad5655abc",
    ),
)


def _row(size: int, digest: str = "a" * 64) -> dict[str, object]:
    return {"size": size, "sha256": digest}


def _artifact(files: dict[str, dict[str, object]]) -> dict[str, object]:
    return {
        "id": 1,
        "size_in_bytes": sum(int(row["size"]) for row in files.values()),
        "archive_sha256": "c" * 64,
        "files": files,
    }


def _public_payload_artifact() -> tuple[dict[str, object], dict[str, dict[str, object]]]:
    rows = {
        "raw-release/payloads/" + name: _row(size, digest)
        for name, size, digest in PAYLOAD_ROWS
    }
    files = {coordinates.DESCRIPTOR_MEMBER: _row(1, "b" * 64)}
    files.update(rows)
    return _artifact(files), rows


class PublicInputMemberBoundTests(unittest.TestCase):
    def test_actual_three_payload_rows_use_candidate_bound(self) -> None:
        artifact, payload_rows = _public_payload_artifact()
        old_limit = 32 * 1024 * 1024
        self.assertEqual(coordinates.MAX_INPUTS_MEMBER_BYTES, 64 * 1024 * 1024)
        self.assertEqual(publication.MAX_INPUTS_MEMBER_BYTES, coordinates.MAX_INPUTS_MEMBER_BYTES)
        for row in payload_rows.values():
            with self.assertRaises(ContractError):
                publication._file_record(row, old_limit)

        observed_limits: list[int] = []
        original_file_record = publication._file_record

        def observe_file_record(row: dict[str, object], limit: int) -> None:
            observed_limits.append(limit)
            original_file_record(row, limit)

        with mock.patch.object(publication, "_file_record", side_effect=observe_file_record):
            publication._artifact(coordinates.PUBLIC_INPUTS, artifact)
        self.assertEqual(set(observed_limits), {64 * 1024 * 1024})

    def test_candidate_ceiling_and_nonpublic_limits_remain_closed(self) -> None:
        over_candidate = {
            coordinates.DESCRIPTOR_MEMBER: _row(1, "b" * 64),
            "raw-release/payloads/over-64m.tar.gz": _row(
                coordinates.MAX_INPUTS_MEMBER_BYTES + 1,
            ),
        }
        with self.assertRaises(ContractError):
            publication._artifact(coordinates.PUBLIC_INPUTS, _artifact(over_candidate))

        small_ok = {
            coordinates.DESCRIPTOR_MEMBER: _row(1, "b" * 64),
            "small/member.bin": _row(coordinates.MAX_SMALL_MEMBER_BYTES, "d" * 64),
        }
        publication._artifact("non-public-artifact", _artifact(small_ok))
        small_over = dict(small_ok)
        small_over["small/over.bin"] = _row(coordinates.MAX_SMALL_MEMBER_BYTES + 1)
        with self.assertRaises(ContractError):
            publication._artifact("non-public-artifact", _artifact(small_over))

        self.assertEqual(coordinates.PUBLIC_INPUTS_ARTIFACT_MAX_BYTES, 1_140_850_688)
        self.assertEqual(coordinates.MAX_INPUTS_ARCHIVE_BYTES, 1_140_850_688)
        self.assertEqual(coordinates.MAX_INPUTS_FILES, 4096)
        self.assertEqual(coordinates.MAX_SMALL_ARCHIVE_BYTES, 32 * 1024 * 1024)
        self.assertEqual(coordinates.MAX_SMALL_MEMBER_BYTES, 8 * 1024 * 1024)


if __name__ == "__main__":
    unittest.main()
