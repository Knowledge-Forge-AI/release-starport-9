"""Synthetic closed-input tests for the isolated Stage-A producer.

These tests exercise file custody, joins, identity, and output collision handling.
They do not claim native qualification or hosted admission.
"""
from __future__ import annotations

import json
import unittest
from pathlib import Path

from rs9.errors import ContractError
from rs9.nebular070_evidence import (
    ARTIFACT_METADATA_SCHEMA,
    BODY_KINDS,
    assemble_payload_portability,
)
from rs9.nebular070_manylinux import (
    ARCHIVE_PORTABILITY_INPUT_SCHEMA,
    PORTABILITY_INPUT_SCHEMA,
    _digest,
    load_payload_portability_bundle,
)
from rs9.nebular070_payload import MAX_INPUT_BYTES
from rs9.scratch import canonical
from tests.test_nebular070_manylinux import Nebular070ManylinuxContractTests


class Nebular070EvidenceProducerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = Nebular070ManylinuxContractTests("runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.root = self.fixture.root / "producer"
        self.root.mkdir()
        self.record, self.bodies = self.fixture._stage_a_inputs()
        self.tf_source = {"commit": "a" * 40, "tree": "b" * 40}
        self.rs9_source = {"commit": "1" * 40, "tree": "2" * 40}
        self.snapshot = self.record["source_input_snapshot_sha256"]
        self.body_paths: dict[str, dict[str, Path]] = {}
        self.metadata_paths: dict[str, Path] = {}
        for target, triple in (
            ("linux-arm64-gnu", "aarch64-unknown-linux-gnu"),
            ("linux-x64-gnu", "x86_64-unknown-linux-gnu"),
        ):
            target_dir = self.root / target
            target_dir.mkdir()
            paths: dict[str, Path] = {}
            for kind in BODY_KINDS:
                path = target_dir / f"{kind}.json"
                path.write_bytes(canonical(self.bodies[f"{target}:{kind}"]))
                paths[kind] = path
            self.body_paths[target] = paths
            row = next(row for row in self.record["targets"] if row["target"] == target)
            metadata_path = target_dir / "artifact-metadata.json"
            metadata_path.write_bytes(canonical({
                "schema": ARTIFACT_METADATA_SCHEMA,
                "target": target,
                "triple": triple,
                "payload_archive": {
                    "sha256": row["payload_archive_sha256"],
                    "bytes": len(self.fixture.archive),
                },
                "package_manifest": {
                    "sha256": row["manifest_sha256"],
                    "bytes": len(canonical(self.fixture.manifest)),
                },
            }))
            self.metadata_paths[target] = metadata_path
        self.output = self.root / "payload_portability.json"

    def _assemble(self, **kwargs):
        target_archive_paths = kwargs.pop("target_archive_paths", None)
        return assemble_payload_portability(
            self.body_paths,
            self.metadata_paths,
            kwargs.pop("tf_producer_source", self.tf_source),
            kwargs.pop("rs9_tool_source", self.rs9_source),
            kwargs.pop("source_input_snapshot_sha256", self.snapshot),
            kwargs.pop("output_path", self.output),
            target_archive_paths=target_archive_paths,
        )

    def test_archive_aware_metadata_joins_complete_archive_domain(self) -> None:
        archive_paths = {}
        for target in self.body_paths:
            archive_path = self.root / target / "payload.tar.gz"
            archive_path.write_bytes(self.fixture.archive)
            archive_paths[target] = archive_path
            metadata_path = self.metadata_paths[target]
            metadata = json.loads(metadata_path.read_bytes())
            metadata["schema"] = "rs9.nebular070-stage-a-artifact-metadata.v2"
            metadata["payload_archive"] = {
                "sha256": __import__("hashlib").sha256(self.fixture.archive).hexdigest(),
                "bytes": len(self.fixture.archive),
            }
            metadata["archive_member_manifest_sha256"] = self.fixture.manifest["manifest_sha256"]
            metadata_path.write_bytes(canonical(metadata))
        result = self._assemble(target_archive_paths=archive_paths)
        self.assertEqual(result["record"]["schema"], "rs9.nebular070-payload-portability.v3")
        self.assertTrue(all("archive_member_manifest_sha256" in row for row in result["record"]["targets"]))

    def test_actual_writer_emits_closed_bundle_and_receipt(self) -> None:
        result = self._assemble()
        loaded = load_payload_portability_bundle(
            self.output,
            expected_tf_producer_source=self.tf_source,
            expected_rs9_tool_source=self.rs9_source,
        )
        self.assertEqual(loaded.record, result["record"])
        envelope = json.loads(self.output.read_bytes())
        self.assertEqual(envelope["schema"], PORTABILITY_INPUT_SCHEMA)
        self.assertEqual(envelope["record"]["identity"], result["record"]["identity"])
        self.assertEqual(set(envelope["record"]["targets"][0]), {
            "target", "triple", "payload_archive_sha256", "manifest_sha256",
            "native_payload_inventory_identity", "runtime_material_digest",
            "source_candidate", "source_input_snapshot_sha256",
            "qualification_sha256", "portability_observation_sha256",
            "runtime_receipt_sha256", "runtime_floor_observation_sha256",
            "host_floor_observation_sha256", "host_newer_observation_sha256",
            "cpu_baseline_sha256",
        })
        self.assertEqual(set(envelope["bodies"]), {
            f"{target}:{kind}"
            for target in self.body_paths
            for kind in BODY_KINDS
        })
        unsigned = dict(envelope["record"])
        identity = unsigned.pop("identity")
        self.assertEqual(identity, _digest(unsigned))
        receipt = json.loads((self.output.parent / "payload_portability.receipt.json").read_bytes())
        self.assertEqual(receipt["record_identity"], identity)
        self.assertEqual(
            receipt["output"]["sha256"],
            __import__("hashlib").sha256(self.output.read_bytes()).hexdigest(),
        )

    def test_loader_refuses_missing_and_extra_envelope_fields(self) -> None:
        self._assemble()
        original = json.loads(self.output.read_bytes())
        variants = []
        for missing in ("schema", "record", "bodies"):
            malformed = dict(original)
            malformed.pop(missing)
            variants.append(("missing-" + missing, malformed))
        variants.append(("extra-field", {**original, "unexpected": True}))
        for label, malformed in variants:
            with self.subTest(label=label):
                path = self.root / (label + ".json")
                path.write_bytes(canonical(malformed))
                with self.assertRaises(ContractError) as context:
                    load_payload_portability_bundle(
                        path,
                        expected_tf_producer_source=self.tf_source,
                        expected_rs9_tool_source=self.rs9_source,
                    )
                self.assertEqual(context.exception.code, "NEBULAR_MANYLINUX_INPUT")

    def test_loader_rejects_archive_envelope_for_package_record(self) -> None:
        self._assemble()
        envelope = json.loads(self.output.read_bytes())
        envelope["schema"] = ARCHIVE_PORTABILITY_INPUT_SCHEMA
        mixed = self.root / "mixed-archive-envelope.json"
        mixed.write_bytes(canonical(envelope))
        with self.assertRaises(ContractError) as context:
            load_payload_portability_bundle(
                mixed,
                expected_tf_producer_source=self.tf_source,
                expected_rs9_tool_source=self.rs9_source,
            )
        self.assertEqual(context.exception.code, "NEBULAR_MANYLINUX_SCHEMA")

    def test_loader_rejects_package_envelope_for_archive_record(self) -> None:
        archive_paths = {}
        for target in self.body_paths:
            archive_path = self.root / target / "payload.tar.gz"
            archive_path.write_bytes(self.fixture.archive)
            archive_paths[target] = archive_path
            metadata_path = self.metadata_paths[target]
            metadata = json.loads(metadata_path.read_bytes())
            metadata["schema"] = "rs9.nebular070-stage-a-artifact-metadata.v2"
            metadata["payload_archive"] = {
                "sha256": __import__("hashlib").sha256(self.fixture.archive).hexdigest(),
                "bytes": len(self.fixture.archive),
            }
            metadata["archive_member_manifest_sha256"] = self.fixture.manifest["manifest_sha256"]
            metadata_path.write_bytes(canonical(metadata))
        self._assemble(target_archive_paths=archive_paths)
        envelope = json.loads(self.output.read_bytes())
        envelope["schema"] = PORTABILITY_INPUT_SCHEMA
        mixed = self.root / "mixed-package-envelope.json"
        mixed.write_bytes(canonical(envelope))
        with self.assertRaises(ContractError) as context:
            load_payload_portability_bundle(
                mixed,
                expected_tf_producer_source=self.tf_source,
                expected_rs9_tool_source=self.rs9_source,
            )
        self.assertEqual(context.exception.code, "NEBULAR_MANYLINUX_SCHEMA")

    def test_mixed_artifact_metadata_schemas_refuse_before_archive_lookup(self) -> None:
        metadata_path = self.metadata_paths["linux-arm64-gnu"]
        metadata = json.loads(metadata_path.read_bytes())
        metadata["schema"] = "rs9.nebular070-stage-a-artifact-metadata.v2"
        metadata["archive_member_manifest_sha256"] = "a" * 64
        metadata_path.write_bytes(canonical(metadata))
        with self.assertRaises(ContractError) as context:
            self._assemble()
        self.assertEqual(context.exception.code, "NEBULAR_STAGE_A_SCHEMA")

    def test_nonstring_artifact_metadata_schema_is_a_coded_refusal(self) -> None:
        metadata_path = self.metadata_paths["linux-arm64-gnu"]
        metadata = json.loads(metadata_path.read_bytes())
        metadata["schema"] = {}
        metadata_path.write_bytes(canonical(metadata))
        with self.assertRaises(ContractError) as context:
            self._assemble()
        self.assertEqual(context.exception.code, "NEBULAR_STAGE_A_INPUT")

    def test_loader_nonstring_schemas_are_coded_refusals(self) -> None:
        self._assemble()
        envelope = json.loads(self.output.read_bytes())
        for field, value in (("schema", []), ("record.schema", {})):
            with self.subTest(field=field):
                candidate = json.loads(self.output.read_bytes())
                if field == "schema":
                    candidate["schema"] = value
                else:
                    candidate["record"]["schema"] = value
                mixed = self.root / f"malformed-{field.replace('.', '-')}.json"
                mixed.write_bytes(canonical(candidate))
                with self.assertRaises(ContractError) as context:
                    load_payload_portability_bundle(
                        mixed,
                        expected_tf_producer_source=self.tf_source,
                        expected_rs9_tool_source=self.rs9_source,
                    )
                self.assertIn(context.exception.code, {
                    "NEBULAR_MANYLINUX_INPUT", "NEBULAR_MANYLINUX_SCHEMA",
                })

    def test_missing_body_refuses_before_output(self) -> None:
        self.body_paths["linux-x64-gnu"]["cpu"].unlink()
        with self.assertRaises(ContractError):
            self._assemble()
        self.assertFalse(self.output.exists())
        self.assertFalse((self.output.parent / "payload_portability.metadata.json").exists())
        self.assertFalse((self.output.parent / "payload_portability.receipt.json").exists())

    def test_individually_bounded_bodies_refuse_oversized_bundle_before_output(self) -> None:
        for target in self.body_paths:
            path = self.body_paths[target]["cpu"]
            body = json.loads(path.read_bytes())
            body["properties"]["retained_detail"] = "x" * (MAX_INPUT_BYTES // 2)
            body["identity"] = _digest({key: value for key, value in body.items() if key != "identity"})
            encoded = canonical(body)
            self.assertLess(len(encoded), MAX_INPUT_BYTES)
            path.write_bytes(encoded)
        with self.assertRaises(ContractError) as context:
            self._assemble()
        self.assertEqual(context.exception.code, "NEBULAR_STAGE_A_INPUT")
        self.assertFalse(self.output.exists())
        self.assertFalse((self.output.parent / "payload_portability.metadata.json").exists())
        self.assertFalse((self.output.parent / "payload_portability.receipt.json").exists())

    def test_unknown_cpu_refuses_through_shared_validator(self) -> None:
        for target in self.body_paths:
            path = self.body_paths[target]["cpu"]
            body = json.loads(path.read_bytes())
            body["baseline"] = "unknown"
            body["properties"] = {"isa": "unresolved"}
            unsigned = {key: value for key, value in body.items() if key != "identity"}
            body["identity"] = _digest(unsigned)
            path.write_bytes(canonical(body))
        with self.assertRaises(ContractError):
            self._assemble()
        self.assertFalse(self.output.exists())
        self.assertFalse((self.output.parent / "payload_portability.metadata.json").exists())
        self.assertFalse((self.output.parent / "payload_portability.receipt.json").exists())

    def test_separate_git_sources_are_preserved(self) -> None:
        result = self._assemble(
            tf_producer_source={"commit": "c" * 40, "tree": "d" * 40},
            rs9_tool_source={"commit": "e" * 40, "tree": "f" * 40},
        )
        self.assertEqual(result["record"]["tf_producer_source"], {"commit": "c" * 40, "tree": "d" * 40})
        self.assertEqual(result["record"]["rs9_tool_source"], {"commit": "e" * 40, "tree": "f" * 40})
        self.assertNotEqual(
            result["record"]["tf_producer_source"],
            result["record"]["rs9_tool_source"],
        )

    def test_tampered_source_metadata_refuses(self) -> None:
        source_path = self.body_paths["linux-arm64-gnu"]["source"]
        source = json.loads(source_path.read_bytes())
        source["manifestSha256"] = "f" * 64
        source_path.write_bytes(canonical(source))
        with self.assertRaises(ContractError):
            self._assemble()
        self.assertFalse(self.output.exists())

    def test_existing_output_collision_refuses_without_replacement(self) -> None:
        self._assemble()
        before = self.output.read_bytes()
        with self.assertRaises(ContractError):
            self._assemble()
        self.assertEqual(self.output.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
