"""Admission regression tests for the coordinate-derived Python floor."""

from __future__ import annotations

import importlib
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


REPOSITORY = Path(__file__).resolve().parents[1]
SOURCE_ROOT = REPOSITORY / "src"
sys.path.insert(0, str(SOURCE_ROOT))

from rs9.errors import ContractError


class ExactPythonMinorGateTests(unittest.TestCase):
    def _matrix(self, coordinate: str, versions: dict[tuple[str, str], dict[str, int]]):
        universal = importlib.import_module("rs9.tf_pypi_nebular080_universal")
        consumer = importlib.import_module("rs9.nebular080_universal_consumer")
        profile = importlib.import_module("rs9.nebular080_universal_profile")
        builder = importlib.import_module("rs9.wheel_nebular080_universal")
        coordinates = importlib.import_module("rs9.nebular080_publication_coordinates")
        source = {"commit": "a" * 40, "tree": "b" * 40}
        snapshot = {
            "wheel": {"filename": "held.whl", "sha256": "c" * 64},
            "runtime_inputs_sha256": "d" * 64,
            "runtime_index_sha256": "e" * 64,
        }
        captures = {
            target: {"payload_sha256": f"{index:064x}", "manifest_sha256": f"{index + 10:064x}"}
            for index, target in enumerate(builder.LAYOUTS, 1)
        }
        lanes = {(target, "newer") for target in builder.LAYOUTS} | {
            (target, "floor") for target in profile.LINUX_TARGETS
        }
        positives = {lane: {} for lane in lanes}
        negatives = {target: {} for target in profile.LINUX_TARGETS}

        def fake_consumer(*_args, target, role, **_kwargs):
            return {
                "identity": "f" * 64,
                "python_version": consumer._validate_python_version(versions[target, role]),
                "host_observation": {"identity": "1" * 64},
            }

        def fake_missing(*_args, **_kwargs):
            minimum = consumer._minimum_python_version()
            return {
                "identity": "0" * 64,
                "python_version": consumer._validate_python_version(
                    {"major": minimum[0], "minor": minimum[1]}),
            }

        with patch.object(coordinates, "EXPECTED_REQUIRES_PYTHON", coordinate), \
                patch.object(universal.consumer, "validate_universal_consumer",
                             side_effect=fake_consumer), \
                patch("rs9.nebular080_universal_missing.validate_missing_runtime",
                      side_effect=fake_missing):
            return universal.validate_matrix_receipts(
                snapshot, captures, positives, negatives,
                source=source, run_id="1", run_attempt="1",
            )

    @staticmethod
    def _versions(lanes, exact_minor: int, newer_minor: int) -> dict[tuple[str, str], dict[str, int]]:
        ordered = sorted(lanes)
        return {
            lane: {"major": 3, "minor": exact_minor if index == 0 else newer_minor}
            for index, lane in enumerate(ordered)
        }

    def test_coordinate_310_requires_one_310_row_but_allows_newer_rows(self) -> None:
        profile = importlib.import_module("rs9.nebular080_universal_profile")
        builder = importlib.import_module("rs9.wheel_nebular080_universal")
        lanes = {(target, "newer") for target in builder.LAYOUTS} | {
            (target, "floor") for target in profile.LINUX_TARGETS
        }
        result = self._matrix(">=3.10", self._versions(lanes, 10, 13))
        self.assertEqual(len(result["lanes"]), 5)

        for rejected_minor in (11, 13):
            with self.subTest(rejected_minor=rejected_minor):
                with self.assertRaisesRegex(ContractError, "NEBULAR_UNIVERSAL_PYTHON_FLOOR"):
                    self._matrix(">=3.10", self._versions(lanes, rejected_minor, rejected_minor))

    def test_coordinate_311_requires_one_311_row_but_rejects_all_313(self) -> None:
        profile = importlib.import_module("rs9.nebular080_universal_profile")
        builder = importlib.import_module("rs9.wheel_nebular080_universal")
        lanes = {(target, "newer") for target in builder.LAYOUTS} | {
            (target, "floor") for target in profile.LINUX_TARGETS
        }
        result = self._matrix(">=3.11", self._versions(lanes, 11, 13))
        self.assertEqual(len(result["lanes"]), 5)
        with self.assertRaisesRegex(ContractError, "NEBULAR_UNIVERSAL_PYTHON_FLOOR"):
            self._matrix(">=3.11", self._versions(lanes, 13, 13))


if __name__ == "__main__":
    unittest.main()
