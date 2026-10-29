"""Pure tests for the public Stage-A input assembler.

The bodies below are controlled actual-shaped records.  They exercise the
connected assembler and the maintained validator, but are not native or
hosted qualification evidence.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import subprocess
import unittest
from pathlib import Path

from rs9.errors import ContractError
from rs9.nebular070_payload import _digest, validate_nebular070_payload_portability
from rs9.nebular070_public_payload import (
    ARCHIVE_ARTIFACT_METADATA_SCHEMA,
    ARTIFACT_METADATA_SCHEMA,
    BODY_KINDS,
    PRODUCT_COMMIT,
    PRODUCT_TREE,
    assemble_public_payload,
    compute_source_input_snapshot,
)
from rs9.scratch import canonical
import tests.test_nebular070_manylinux as manylinux_fixtures


class PublicStageAAssemblerTests(unittest.TestCase):
    def setUp(self) -> None:
        fixture = manylinux_fixtures.Nebular070ManylinuxContractTests("runTest")
        fixture.setUp()
        self.addCleanup(fixture.tearDown)
        self.fixture = fixture
        self.product_source = {"commit": PRODUCT_COMMIT, "tree": PRODUCT_TREE}
        self.producer_source = {
            "commit": os.environ.get("RS9_W4_PRODUCER_COMMIT", "a" * 40),
            "tree": os.environ.get("RS9_W4_PRODUCER_TREE", "b" * 40),
        }
        self.rs9_source = {"commit": "1" * 40, "tree": "2" * 40}
        self.w4_cli_bound = False
        if all(os.environ.get(name) for name in (
            "RS9_W4_NODE", "RS9_W4_PRODUCER", "RS9_W4_MANIFEST",
        )):
            self.inputs = self._inputs_from_w4()
            self.w4_cli_bound = True
        else:
            self.inputs = self._inputs()

    @staticmethod
    def _js_digest(value: object) -> str:
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        return hashlib.sha256(raw).hexdigest()

    @classmethod
    def _w4_manifest_identity(cls, manifest: dict) -> str:
        """Match W4 ``validateRuntimeManifest``'s target-bearing projection."""
        normalized = dict(manifest)
        normalized["assets"] = {
            triple: {"target": triple, **dict(asset)}
            for triple, asset in manifest["assets"].items()
        }
        return cls._js_digest(normalized)

    def _runtime_manifest(self) -> tuple[dict, dict[str, dict], dict[str, dict]]:
        manifest = {
            "schema": "nebular.public-pypi-runtime-input-manifest-v2",
            "version": "0.7.0",
            "repository": "Knowledge-Forge-AI/theme-forge-nebular-fusion",
            "sourceContract": "public-source-first-v6",
            "runtimeToolSha256": "7" * 64,
            "assets": {},
        }
        runtime_inputs: dict[str, dict] = {}
        for index, (target, (triple, _tag)) in enumerate((
            ("linux-arm64-gnu", ("aarch64-unknown-linux-gnu", "")),
            ("linux-x64-gnu", ("x86_64-unknown-linux-gnu", "")),
        ), start=1):
            archive_sha = ("a" if index == 1 else "b") * 64
            manifest_sha = ("c" if index == 1 else "d") * 64
            material = ("2" if index == 1 else "3") * 64
            archive = {
                "assetId": 100 + index,
                "name": f"runtime-input-{triple}.tar.gz",
                "bytes": 1,
                "sha256": archive_sha,
                "integrity": "sha256-" + base64.b64encode(bytes.fromhex(archive_sha)).decode(),
            }
            manifest["assets"][triple] = {
                "archive": archive,
                "expectedMemberListSha256": ("4" if index == 1 else "5") * 64,
                "expectedManifestSha256": manifest_sha,
                "expectedMaterialDigest": material,
                "correspondingSourceSha256": ("6" if index == 1 else "8") * 64,
                "releaseAssetSha256": ("9" if index == 1 else "e") * 64,
            }
            descriptor_sha = ("f" if index == 1 else "0") * 64
            closed = {
                "schema": "nebular070-public-hosted-runtime-input-closed-manifest-v2",
                "target": triple,
                "runtimePrefix": "opt/nebular-private",
                "archive": {
                    "filename": archive["name"], "bytes": 1, "sha256": archive_sha,
                    "expectedBytes": 1, "expectedSha256": archive_sha, "memberCount": 1,
                    "memberListSha256": manifest["assets"][triple]["expectedMemberListSha256"],
                    "expectedMemberListSha256": manifest["assets"][triple]["expectedMemberListSha256"],
                    "paxHeadersRejected": True,
                },
                "materialManifest": {
                    "path": "source/native-runtime.json", "bytes": 1,
                    "sha256": manifest_sha, "materialDigest": material,
                },
                "descriptor": {"path": "input/native-runtime-input.json", "bytes": 1, "sha256": descriptor_sha},
                "sourceRootRelative": "source",
                "maintainedRuntimeToolSha256": manifest["runtimeToolSha256"],
                "authenticated": True,
                "productPayloadIncluded": False,
                "nativeExecution": False,
            }
            receipt = {
                "schema": "nebular070-public-hosted-runtime-input-receipt-v2",
                "status": "runtime-only-input-authenticated",
                "target": triple,
                "archive": {
                    "filename": archive["name"], "bytes": 1,
                    "expectedBytesSha256Verified": True, "sha256": archive_sha,
                    "memberCount": 1, "memberListSha256": manifest["assets"][triple]["expectedMemberListSha256"],
                    "paxHeadersRejected": True,
                },
                "descriptor": closed["descriptor"],
                "material": {
                    "path": "source/native-runtime.json", "bytes": 1, "sha256": manifest_sha,
                    "materialDigest": material, "regulars": 1, "aliases": 0, "directories": 1,
                },
                "evidence": {
                    "correspondingSourceCustody": manifest["assets"][triple]["correspondingSourceSha256"],
                    "releaseAsset": manifest["assets"][triple]["releaseAssetSha256"],
                    "runtimeMaterialArchive": archive_sha, "runtimeMaterialManifest": manifest_sha,
                },
                "sourceRootRelative": "source",
                "maintainedRuntimeToolSha256": manifest["runtimeToolSha256"],
                "authentication": {"sourceSnapshotVerified": True, "privateGraphicsSourceVerified": True},
                "productPayloadIncluded": False,
                "nativeExecution": False,
                "buildOrQualificationClaim": False,
            }
            runtime_inputs[target] = {"closed_manifest": closed, "runtime_receipt": receipt}
        return manifest, runtime_inputs, {target: value["closed_manifest"] for target, value in runtime_inputs.items()}

    @staticmethod
    def _normalized_manifest(manifest: dict) -> dict:
        normalized = copy.deepcopy(manifest)
        normalized["assets"] = {
            triple: {"target": triple, **dict(asset)}
            for triple, asset in manifest["assets"].items()
        }
        return normalized

    def _inputs(self) -> dict:
        fixture_record, fixture_bodies = self.fixture._stage_a_inputs()
        manifest, runtime_inputs, closed = self._runtime_manifest()
        closed_digests = {
            "aarch64-unknown-linux-gnu": hashlib.sha256(canonical(closed["linux-arm64-gnu"])).hexdigest(),
            "x86_64-unknown-linux-gnu": hashlib.sha256(canonical(closed["linux-x64-gnu"])).hexdigest(),
        }
        snapshot = compute_source_input_snapshot(
            self.product_source, self.producer_source, self._normalized_manifest(manifest), closed_digests,
        )
        origins = {}
        bodies: dict[str, dict] = {}
        metadata = {}
        for target, (triple, _tag) in (
            ("linux-arm64-gnu", ("aarch64-unknown-linux-gnu", "")),
            ("linux-x64-gnu", ("x86_64-unknown-linux-gnu", "")),
        ):
            runtime = runtime_inputs[target]["closed_manifest"]
            asset = manifest["assets"][triple]
            descriptor = runtime["descriptor"]
            origin = {
                "schema": "nebular.public-pypi-source-origin-v2", "status": "pass",
                "contract": "public-source-first-v6", "repository": "Knowledge-Forge-AI/theme-forge-nebular-fusion",
                "version": "0.7.0", "source": self.product_source, "producer": self.producer_source,
                "ci": {
                    "provider": "github-actions", "origin": "public-hosted-runner", "workflow": "native-pypi-runtime",
                    "workflowPath": ".github/workflows/native-pypi-runtime.yml", "runId": "40792039041",
                    "runAttempt": "1", "event": "workflow_dispatch", "ref": "refs/heads/main",
                },
                "runtime": {
                    "target": triple, "manifestSha256": hashlib.sha256(canonical(manifest)).hexdigest(),
                    "manifestIdentity": self._w4_manifest_identity(manifest), "runtimeToolSha256": manifest["runtimeToolSha256"],
                    "archiveAssetId": asset["archive"]["assetId"], "archiveAssetName": asset["archive"]["name"],
                    "archiveSha256": asset["archive"]["sha256"], "archiveBytes": asset["archive"]["bytes"],
                    "expectedMemberListSha256": asset["expectedMemberListSha256"],
                    "expectedManifestSha256": asset["expectedManifestSha256"],
                    "expectedMaterialDigest": asset["expectedMaterialDigest"],
                    "descriptorSha256": descriptor["sha256"], "descriptorBytes": descriptor["bytes"],
                    "evidence": {
                        "correspondingSourceCustody": asset["correspondingSourceSha256"],
                        "releaseAsset": asset["releaseAssetSha256"],
                        "runtimeMaterialArchive": asset["archive"]["sha256"],
                        "runtimeMaterialManifest": asset["expectedManifestSha256"],
                    },
                },
            }
            origin["identity"] = self._js_digest(origin)
            origins[target] = origin
            lane: dict[str, dict] = {}
            for kind in BODY_KINDS:
                lane[kind] = copy.deepcopy(fixture_bodies[f"{target}:{kind}"])
            source = lane["source"]
            source["sourceCandidate"] = origin["identity"]
            source["sourceInputSnapshotSha256"] = snapshot
            source["identity"] = _digest({key: value for key, value in source.items() if key != "identity"})
            lane["runtime"]["sourceCandidate"] = origin["identity"]
            lane["runtime"]["inputSha256"] = descriptor["sha256"]
            bodies[target] = lane
            row = next(row for row in fixture_record["targets"] if row["target"] == target)
            metadata[target] = {
                "schema": ARTIFACT_METADATA_SCHEMA, "target": target, "triple": triple,
                "payload_archive": {"sha256": row["payload_archive_sha256"], "bytes": 1},
                "package_manifest": {"sha256": row["manifest_sha256"], "bytes": 1},
            }
        return {
            "product_source": self.product_source,
            "producer_source": self.producer_source,
            "rs9_tool_source": self.rs9_source,
            "runtime_manifest": manifest,
            "runtime_inputs": runtime_inputs,
            "source_origins": origins,
            "bodies": bodies,
            "artifact_metadata": metadata,
        }

    def _inputs_from_w4(self) -> dict:
        """Bind fixture bodies to W4's actual manifest/source-origin CLI seam.

        The CLI invocation is source-only: it reads the canonical manifest and
        controlled closed/receipt JSON, then emits source-origin JSON.  No
        runtime archive, native executable, or hosted job is executed here.
        """
        manifest_path = Path(os.environ["RS9_W4_MANIFEST"])
        manifest_bytes = manifest_path.read_bytes()
        manifest = json.loads(manifest_bytes)
        runtime_inputs: dict[str, dict] = {}
        origins: dict[str, dict] = {}
        closed_digests: dict[str, str] = {}
        node = os.environ["RS9_W4_NODE"]
        producer = os.environ["RS9_W4_PRODUCER"]
        for target, triple in (
            ("linux-arm64-gnu", "aarch64-unknown-linux-gnu"),
            ("linux-x64-gnu", "x86_64-unknown-linux-gnu"),
        ):
            asset = manifest["assets"][triple]
            archive = asset["archive"]
            descriptor_sha = ("f" if target == "linux-arm64-gnu" else "0") * 64
            member_count = asset.get("memberCount", 1)
            manifest_bytes_count = asset.get("manifestBytes", 1)
            closed = {
                "schema": "nebular070-public-hosted-runtime-input-closed-manifest-v2",
                "target": triple,
                "runtimePrefix": "opt/nebular-private",
                "archive": {
                    "filename": archive["name"], "bytes": archive["bytes"],
                    "sha256": archive["sha256"], "expectedBytes": archive["bytes"],
                    "expectedSha256": archive["sha256"], "memberCount": member_count,
                    "memberListSha256": asset["expectedMemberListSha256"],
                    "expectedMemberListSha256": asset["expectedMemberListSha256"],
                    "paxHeadersRejected": True,
                },
                "materialManifest": {
                    "path": "source/native-runtime.json", "bytes": manifest_bytes_count,
                    "sha256": asset["expectedManifestSha256"],
                    "materialDigest": asset["expectedMaterialDigest"],
                },
                "descriptor": {
                    "path": "input/native-runtime-input.json", "bytes": 1,
                    "sha256": descriptor_sha,
                },
                "sourceRootRelative": "source",
                "maintainedRuntimeToolSha256": manifest["runtimeToolSha256"],
                "authenticated": True,
                "productPayloadIncluded": False,
                "nativeExecution": False,
            }
            receipt = {
                "schema": "nebular070-public-hosted-runtime-input-receipt-v2",
                "status": "runtime-only-input-authenticated", "target": triple,
                "archive": {
                    "filename": archive["name"], "bytes": archive["bytes"],
                    "expectedBytesSha256Verified": True, "sha256": archive["sha256"],
                    "memberCount": member_count,
                    "memberListSha256": asset["expectedMemberListSha256"],
                    "paxHeadersRejected": True,
                },
                "descriptor": closed["descriptor"],
                "material": {
                    "path": "source/native-runtime.json", "bytes": manifest_bytes_count,
                    "sha256": asset["expectedManifestSha256"],
                    "materialDigest": asset["expectedMaterialDigest"],
                    "regulars": 1, "aliases": 0, "directories": 1,
                },
                "evidence": {
                    "correspondingSourceCustody": asset["correspondingSourceSha256"],
                    "releaseAsset": asset["releaseAssetSha256"],
                    "runtimeMaterialArchive": archive["sha256"],
                    "runtimeMaterialManifest": asset["expectedManifestSha256"],
                },
                "sourceRootRelative": "source",
                "maintainedRuntimeToolSha256": manifest["runtimeToolSha256"],
                "authentication": {"sourceSnapshotVerified": True, "privateGraphicsSourceVerified": True},
                "productPayloadIncluded": False, "nativeExecution": False,
                "buildOrQualificationClaim": False,
            }
            runtime_inputs[target] = {"closed_manifest": closed, "runtime_receipt": receipt}
            closed_digests[triple] = hashlib.sha256(canonical(closed)).hexdigest()
            closed_path = self.fixture.root / f"{target}-closed.json"
            receipt_path = self.fixture.root / f"{target}-receipt.json"
            origin_path = self.fixture.root / f"{target}-source-origin.json"
            closed_path.write_bytes(canonical(closed))
            receipt_path.write_bytes(canonical(receipt))
            command = [
                node, producer, "source-origin",
                "--manifest", str(manifest_path),
                "--manifest-sha256", hashlib.sha256(manifest_bytes).hexdigest(),
                "--closed", str(closed_path), "--receipt", str(receipt_path),
                "--source-commit", self.product_source["commit"],
                "--source-tree", self.product_source["tree"],
                "--producer-commit", self.producer_source["commit"],
                "--producer-tree", self.producer_source["tree"],
                "--output", str(origin_path),
            ]
            env = os.environ.copy()
            env.update({
                "GITHUB_REPOSITORY": "Knowledge-Forge-AI/theme-forge-nebular-fusion",
                "GITHUB_WORKFLOW": "nebular-public-runtime",
                "GITHUB_RUN_ID": "40792039041", "GITHUB_RUN_ATTEMPT": "1",
                "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF": "refs/heads/main",
            })
            completed = subprocess.run(
                command, check=True, capture_output=True, text=True,
                timeout=30, env=env,
            )
            self.assertTrue(completed.stdout.strip())
            origins[target] = json.loads(origin_path.read_bytes())

        fixture_record, fixture_bodies = self.fixture._stage_a_inputs()
        snapshot = compute_source_input_snapshot(
            self.product_source, self.producer_source, self._normalized_manifest(manifest), closed_digests,
        )
        bodies: dict[str, dict] = {}
        metadata: dict[str, dict] = {}
        for target, (triple, _tag) in (
            ("linux-arm64-gnu", ("aarch64-unknown-linux-gnu", "")),
            ("linux-x64-gnu", ("x86_64-unknown-linux-gnu", "")),
        ):
            lane = {
                kind: copy.deepcopy(fixture_bodies[f"{target}:{kind}"])
                for kind in BODY_KINDS
            }
            origin = origins[target]
            source = lane["source"]
            source["sourceCandidate"] = origin["identity"]
            source["sourceInputSnapshotSha256"] = snapshot
            source["identity"] = _digest({key: value for key, value in source.items() if key != "identity"})
            lane["runtime"]["sourceCandidate"] = origin["identity"]
            lane["runtime"]["inputSha256"] = origin["runtime"]["descriptorSha256"]
            bodies[target] = lane
            row = next(row for row in fixture_record["targets"] if row["target"] == target)
            metadata[target] = {
                "schema": ARTIFACT_METADATA_SCHEMA, "target": target, "triple": triple,
                "payload_archive": {"sha256": row["payload_archive_sha256"], "bytes": 1},
                "package_manifest": {"sha256": row["manifest_sha256"], "bytes": 1},
            }
        return {
            "product_source": self.product_source,
            "producer_source": self.producer_source,
            "rs9_tool_source": self.rs9_source,
            "runtime_manifest": manifest_bytes,
            "runtime_inputs": runtime_inputs,
            "source_origins": origins,
            "bodies": bodies,
            "artifact_metadata": metadata,
        }

    def _assemble(self, inputs=None):
        return assemble_public_payload(
            inputs or self.inputs,
            expected_tf_producer_source=self.producer_source,
            expected_rs9_tool_source=self.rs9_source,
        )

    def test_roundtrip_real_validator_and_shared_snapshot(self) -> None:
        envelope = self._assemble()
        validated = validate_nebular070_payload_portability(
            envelope["record"], envelope["bodies"],
            expected_tf_producer_source=self.producer_source,
            expected_rs9_tool_source=self.rs9_source,
        )
        self.assertEqual(validated.record, envelope["record"])
        self.assertEqual({row["source_input_snapshot_sha256"] for row in envelope["record"]["targets"]}, {
            envelope["record"]["source_input_snapshot_sha256"]
        })
        self.assertEqual(envelope["schema"], "rs9.nebular070-payload-portability-input.v2")

    def test_archive_domain_derives_v3_without_relabeling_package_manifest(self) -> None:
        inputs = copy.deepcopy(self.inputs)
        archive_sha = hashlib.sha256(self.fixture.archive).hexdigest()
        complete_sha = self.fixture.manifest["manifest_sha256"]
        for target in ("linux-arm64-gnu", "linux-x64-gnu"):
            metadata = inputs["artifact_metadata"][target]
            metadata["schema"] = ARCHIVE_ARTIFACT_METADATA_SCHEMA
            metadata["payload_archive"] = {"sha256": archive_sha, "bytes": len(self.fixture.archive)}
            metadata["archive_member_manifest_sha256"] = complete_sha
        inputs["payload_archives"] = {
            "linux-arm64-gnu": self.fixture.archive,
            "linux-x64-gnu": self.fixture.archive,
        }
        envelope = self._assemble(inputs)
        self.assertEqual(envelope["schema"], "rs9.nebular070-payload-portability-input.v3")
        self.assertEqual(envelope["record"]["schema"], "rs9.nebular070-payload-portability.v3")
        for target in ("linux-arm64-gnu", "linux-x64-gnu"):
            row = next(item for item in envelope["record"]["targets"] if item["target"] == target)
            source = envelope["bodies"][f"{target}:source"]
            self.assertEqual(row["archive_member_manifest_sha256"], complete_sha)
            self.assertEqual(row["manifest_sha256"], source["manifestSha256"])

        tampered = copy.deepcopy(inputs)
        tampered["payload_archives"]["linux-x64-gnu"] = b"not-the-authenticated-archive"
        with self.assertRaises(ContractError):
            self._assemble(tampered)

        tampered_metadata = copy.deepcopy(inputs)
        tampered_metadata["artifact_metadata"]["linux-x64-gnu"][
            "archive_member_manifest_sha256"
        ] = "0" * 64
        with self.assertRaises(ContractError):
            self._assemble(tampered_metadata)

    def test_nonstring_schema_values_refuse_with_contract_errors(self) -> None:
        envelope = self._assemble()
        malformed_record = copy.deepcopy(envelope["record"])
        malformed_record["schema"] = []
        with self.assertRaises(ContractError):
            validate_nebular070_payload_portability(
                malformed_record,
                envelope["bodies"],
                expected_tf_producer_source=self.producer_source,
                expected_rs9_tool_source=self.rs9_source,
            )

        malformed_metadata = copy.deepcopy(self.inputs)
        malformed_metadata["artifact_metadata"]["linux-arm64-gnu"]["schema"] = {}
        with self.assertRaises(ContractError):
            self._assemble(malformed_metadata)

    def test_wrong_product_source_refuses(self) -> None:
        inputs = copy.deepcopy(self.inputs)
        inputs["source_origins"]["linux-arm64-gnu"]["source"]["commit"] = "c" * 40
        with self.assertRaises(ContractError):
            self._assemble(inputs)

    def test_wrong_runtime_manifest_join_refuses(self) -> None:
        inputs = copy.deepcopy(self.inputs)
        inputs["runtime_inputs"]["linux-x64-gnu"]["closed_manifest"]["archive"]["sha256"] = "f" * 64
        with self.assertRaises(ContractError):
            self._assemble(inputs)

    def test_wrong_payload_metadata_join_refuses(self) -> None:
        inputs = copy.deepcopy(self.inputs)
        inputs["artifact_metadata"]["linux-arm64-gnu"]["payload_archive"]["sha256"] = "f" * 64
        with self.assertRaises(ContractError):
            self._assemble(inputs)

    def test_wrong_host_body_refuses_through_shared_validator(self) -> None:
        inputs = copy.deepcopy(self.inputs)
        body = inputs["bodies"]["linux-x64-gnu"]["host_floor"]
        body["glibc"] = "2.37"
        body["identity"] = _digest({key: value for key, value in body.items() if key != "identity"})
        with self.assertRaises(ContractError):
            self._assemble(inputs)

    def test_missing_cpu_body_refuses_closed_input(self) -> None:
        inputs = copy.deepcopy(self.inputs)
        del inputs["bodies"]["linux-arm64-gnu"]["cpu"]
        with self.assertRaises(ContractError):
            self._assemble(inputs)

    @unittest.skipUnless(
        all(os.environ.get(name) for name in ("RS9_W4_NODE", "RS9_W4_PRODUCER", "RS9_W4_MANIFEST")),
        "connected W4 source-origin fixture requires pinned W4 paths",
    )
    def test_w4_source_origin_cli_binds_target_normalized_manifest(self) -> None:
        envelope = self._assemble()
        self.assertTrue(self.w4_cli_bound)
        self.assertEqual(len(envelope["record"]["targets"]), 2)

    @unittest.skipUnless(
        all(os.environ.get(name) for name in ("RS9_W4_NODE", "RS9_W4_PRODUCER", "RS9_W4_MANIFEST")),
        "connected W4 source-origin fixture requires pinned W4 paths",
    )
    def test_w4_raw_manifest_identity_cannot_replace_normalized_identity(self) -> None:
        inputs = copy.deepcopy(self.inputs)
        raw_manifest = json.loads(Path(os.environ["RS9_W4_MANIFEST"]).read_bytes())
        target = "linux-arm64-gnu"
        triple = "aarch64-unknown-linux-gnu"
        origin = inputs["source_origins"][target]
        origin["runtime"]["manifestIdentity"] = self._js_digest(raw_manifest)
        origin["identity"] = self._js_digest({key: value for key, value in origin.items() if key != "identity"})
        with self.assertRaises(ContractError):
            self._assemble(inputs)

    @unittest.skipUnless(
        all(os.environ.get(name) for name in ("RS9_W4_NODE", "RS9_W4_PRODUCER", "RS9_W4_MANIFEST")),
        "connected W4 source-origin fixture requires pinned W4 paths",
    )
    def test_w4_receipt_source_custody_and_release_asset_are_required(self) -> None:
        for field in ("correspondingSourceCustody", "releaseAsset"):
            inputs = copy.deepcopy(self.inputs)
            inputs["runtime_inputs"]["linux-x64-gnu"]["runtime_receipt"]["evidence"][field] = "f" * 64
            with self.subTest(field=field), self.assertRaises(ContractError):
                self._assemble(inputs)


if __name__ == "__main__":
    unittest.main()
