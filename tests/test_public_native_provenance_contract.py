"""Portable contract tests for the public native-CI provenance schema."""
from __future__ import annotations

import copy
import json
from pathlib import Path
from types import SimpleNamespace
import unittest

from rs9.errors import ContractError
from rs9.profiles import (
    CURRENT_NATIVE_PROVENANCE_SCHEMA,
    _validate_current_native_provenance,
)


FIXTURE = Path(__file__).parent / "fixtures" / "public-native-provenance-v1.json"


class PublicNativeProvenanceContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture = json.loads(FIXTURE.read_bytes())
        cls.capture_record = cls.fixture["capture"]["record"]

    def _validate(self, provenance=None, *, inputs=None, metadata=None):
        fixture = self.fixture
        capture = SimpleNamespace(record=fixture["capture"]["record"])
        return _validate_current_native_provenance(
            provenance if provenance is not None else fixture["provenance"],
            normalized=fixture["normalized"],
            capture=capture,
            repository=self.capture_record["repository"],
            obj={"sha": self.capture_record["tag"]["commit"]},
            tree_sha=self.capture_record["tag"]["tree"],
            inputs=inputs if inputs is not None else fixture["capture"]["inputs"],
            metadata=metadata if metadata is not None else fixture["capture"]["metadata"],
            roles=fixture["roles"],
        )

    def test_current_public_fixture_passes(self) -> None:
        self._validate()
        self.assertEqual(
            self.fixture["provenance"]["schema"], CURRENT_NATIVE_PROVENANCE_SCHEMA
        )

    def test_release_id_mismatch_rejects(self) -> None:
        provenance = copy.deepcopy(self.fixture["provenance"])
        provenance["release"] += 1
        with self.assertRaisesRegex(ContractError, "PROVENANCE_MISMATCH"):
            self._validate(provenance)

    def test_release_commit_mismatch_rejects(self) -> None:
        provenance = copy.deepcopy(self.fixture["provenance"])
        provenance["releaseCommit"] = "a" * 40
        with self.assertRaisesRegex(ContractError, "PROVENANCE_MISMATCH"):
            self._validate(provenance)

    def test_tested_tree_mismatch_rejects(self) -> None:
        provenance = copy.deepcopy(self.fixture["provenance"])
        provenance["testedTree"] = "b" * 40
        with self.assertRaisesRegex(ContractError, "PROVENANCE_MISMATCH"):
            self._validate(provenance)

    def test_selected_artifact_hash_mismatch_rejects(self) -> None:
        provenance = copy.deepcopy(self.fixture["provenance"])
        selected_name = next(iter(self.fixture["capture"]["metadata"]))
        row = next(row for row in provenance["assets"] if row["name"] == selected_name)
        row["sha256"] = "0" * 64
        with self.assertRaisesRegex(ContractError, "PROVENANCE_MISMATCH"):
            self._validate(provenance)

    def test_unknown_schema_integer_release_rejects(self) -> None:
        provenance = copy.deepcopy(self.fixture["provenance"])
        provenance["schema"] = "nebular.unknown-provenance.v1"
        with self.assertRaisesRegex(ContractError, "INVALID_EVIDENCE"):
            self._validate(provenance)

    def test_malformed_executable_hash_rejects(self) -> None:
        inputs = copy.deepcopy(self.fixture["capture"]["inputs"])
        command_name = next(iter(inputs[0]["commands"]))
        inputs[0]["commands"][command_name]["sha256"] = "not-a-sha"
        with self.assertRaisesRegex(ContractError, "INVALID_EVIDENCE"):
            self._validate(inputs=inputs)


if __name__ == "__main__":
    unittest.main()
