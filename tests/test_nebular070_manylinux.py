"""Synthetic closed-graph tests for the 0.7.0 manylinux A/B boundary.

These fixtures exercise schema joins and wheel readback only.  They are not
native portability or hosted-consumer qualification evidence.
"""
from __future__ import annotations

import copy
import io
import json
import tempfile
import unittest
import zipfile
from unittest import mock
from pathlib import Path

from rs9.archives import inspect_archive
from rs9.errors import ContractError
from rs9.release_core import digest as bytes_digest
from rs9.tf_pypi_archive import canonical as archive_canonical
from rs9.wheel import format_record
from rs9.wheel_nebular_successor import GATE1_PROFILE, build_gate1_successor_wheel
from rs9.tf_pypi_nebular070_publish import (
    APPROVAL_SCHEMA,
    DESCRIPTION_PATH,
    EXPECTED_COMMAND,
    EXPECTED_LICENSE_EXPRESSION,
    EXPECTED_REQUIRES_PYTHON,
    WORKFLOW,
    compute_admission_sha256,
    compute_set_sha256,
    main as publish_main,
)
import rs9.nebular070_manylinux as manylinux
import rs9.tf_pypi_nebular070_publish as publish_module
from tests.test_nebular070_gate1_roundtrip import _darwin_payload
from tests.test_wheel_nebular_successor import _legal, _linux_archive


class Nebular070ManylinuxContractTests(unittest.TestCase):
    """Bounded synthetic tests; no native command or network is used."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(
            prefix="rs9-nebular070-manylinux-",
            dir=str(Path(__file__).resolve().parents[1]),
        )
        self.root = Path(self.tmp.name)
        self.archive = _linux_archive()
        archive_path = self.root / "payload.tgz"
        archive_path.write_bytes(self.archive)
        self.manifest = inspect_archive(archive_path, commands={})
        self.tf_source = {"commit": "a" * 40, "tree": "b" * 40}
        self.rs9_source = {"commit": "1" * 40, "tree": "2" * 40}
        self.stage_a_record, self.receipt_bodies = self._stage_a_inputs()
        self.stage_a = manylinux.validate_nebular070_payload_portability(
            self.stage_a_record,
            self.receipt_bodies,
            expected_tf_producer_source=self.tf_source,
            expected_rs9_tool_source=self.rs9_source,
            allow_fixture=True,
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _stage_a_inputs(self):
        payload = {
            "archive_sha256": bytes_digest(self.archive),
            "manifest_sha256": self.manifest["manifest_sha256"],
            "inventory_identity": "1" * 64,
        }
        runtime = {"material_digest": "2" * 64}
        rows = []
        bodies = {}
        for target, (triple, _tag) in manylinux.LINUX_TARGETS.items():
            source_candidate = "9" * 64
            source_snapshot = "a" * 64
            portability = {
                "schema": manylinux.ELF_PORTABILITY_SCHEMA,
                "target": triple,
                "expectedNativePayload": payload["inventory_identity"],
                "readelfArgs": ["-h", "-l", "-d", "-V", "-n", "-A", "--wide"],
                "records": [{
                    "schema": "nebular-native-elf-portability-observation-v1",
                    "target": triple,
                    "elf": {
                        "class": "ELF64", "machine": "AArch64" if target == "linux-arm64-gnu" else "X86-64",
                        "elfType": "DYN", "soname": None, "needed": [], "interpreters": [], "rpaths": [],
                        "versionDefinitions": [], "versionNeeds": [],
                    },
                    "versionNeeds": [],
                    "glibcPrivateVersionNeeds": [],
                    "gnuProperty": {},
                    "attributes": {},
                    "cpuBaseline": {"admission": "not-claimed"},
                    "relativePath": "bin/theme-forge-nebular-fusion",
                    "aliases": [], "bytes": 1, "sha256": "a" * 64,
                    "readelf": {
                        "args": ["-h", "-l", "-d", "-V", "-n", "-A", "--wide"],
                        "streamSha256": "b" * 64, "stdoutBytes": 1, "stderrBytes": 0,
                        "notesPresent": False, "notesStatus": "absent",
                    },
                }],
                "admission": "not-claimed",
            }
            portability["identity"] = manylinux._digest(portability)
            qualification = {
                "schema": manylinux.ACTUAL_QUALIFICATION_SCHEMA,
                "platform": "linux-arm64" if target == "linux-arm64-gnu" else "linux-x64",
                "status": "pass",
                "executableSha256": "c" * 64,
                "glibcMinimum": "2.35" if target == "linux-arm64-gnu" else "2.36",
                "nativePayload": {"identity": payload["inventory_identity"], "files": 1},
                "materialDigest": runtime["material_digest"],
                "checks": [],
            }
            for check_id in ("mode:gui", "mode:sidecar", "mode:launcher", "glibc:gui", "glibc:sidecar", "glibc-floor", "linkage"):
                qualification["checks"].append({"id": check_id, "ok": True, "detail": "observed"})
            qualification["checks"].append({
                "id": "private-runtime-closure", "ok": True,
                "detail": {"portabilityObservation": portability},
            })
            runtime_receipt = {
                "schema": manylinux.RUNTIME_RECEIPT_SCHEMA,
                "target": triple,
                "materialDigest": runtime["material_digest"],
                "sourceCandidate": source_candidate,
                "nativePayload": payload["inventory_identity"],
                "inputSha256": "d" * 64,
            }
            runtime_floor = {
                "schema": manylinux.RUNTIME_FLOOR_SCHEMA,
                "target": triple,
                "materialDigest": runtime["material_digest"],
                "expectedNativePayload": payload["inventory_identity"],
                "observedProviderRows": [{
                    "soname": "libc.so.6",
                    "classification": "external-floor",
                    "requestedPath": "/lib/aarch64-linux-gnu/libc.so.6" if target == "linux-arm64-gnu" else "/lib/x86_64-linux-gnu/libc.so.6",
                    "terminalPath": "/lib/aarch64-linux-gnu/libc.so.6" if target == "linux-arm64-gnu" else "/lib/x86_64-linux-gnu/libc.so.6",
                    "aliasChain": [],
                    "terminalFull9": ["dev", "ino", 1, 33188, "uid", "gid", "size", "mtime", "ctime"],
                    "bytes": 1,
                    "sha256": "e" * 64,
                    "elfMachine": "AArch64" if target == "linux-arm64-gnu" else "X86-64",
                    "elfClass": "ELF64",
                    "versionDefinitions": ["GLIBC_2.2.5"],
                    "readelfEvidenceSha256": "f" * 64,
                }],
                "subjectResolutionRows": [],
                "toolEvidence": {
                    "readelfRole": "actual-provider-terminal-readelf",
                    "resolutionToolRole": "actual-consumer-ldd",
                    "boundedResults": [{
                        "role": "provider-readelf", "command": "readelf", "args": ["-h", "-V", "--wide"],
                        "status": 0, "stdoutBytes": 1, "stderrBytes": 0, "cleanupKnown": True,
                    }],
                    "cleanupFacts": {"allCommandsBounded": True, "noSurvivingProcessFamily": True},
                },
            }
            runtime_floor["observationIdentity"] = manylinux._digest(runtime_floor)
            host_floor = {
                "schema": manylinux.HOST_FLOOR_SCHEMA, "target": triple, "role": "floor",
                "status": "observed", "glibc": "2.36", "loader": "/lib64/ld-linux.so.2",
            }
            host_floor["identity"] = manylinux._digest(host_floor)
            host_newer = {
                "schema": manylinux.HOST_FLOOR_SCHEMA, "target": triple, "role": "newer",
                "status": "observed", "glibc": "2.39", "loader": "/lib64/ld-linux.so.2",
            }
            host_newer["identity"] = manylinux._digest(host_newer)
            cpu = {
                "schema": manylinux.CPU_SCHEMA, "target": triple, "status": "observed",
                "baseline": "generic-64", "properties": {"source": "fixture"},
            }
            cpu["identity"] = manylinux._digest(cpu)
            source = {
                "schema": "rs9.nebular070-source-input-binding.v1", "target": triple,
                "sourceCandidate": source_candidate, "sourceInputSnapshotSha256": source_snapshot,
                "payloadArchiveSha256": payload["archive_sha256"], "manifestSha256": payload["manifest_sha256"],
                "nativePayloadIdentity": payload["inventory_identity"], "materialDigest": runtime["material_digest"],
                "status": "verified",
            }
            source["identity"] = manylinux._digest(source)
            row = {
                "target": target,
                "triple": triple,
                "payload_archive_sha256": payload["archive_sha256"],
                "manifest_sha256": payload["manifest_sha256"],
                "native_payload_inventory_identity": payload["inventory_identity"],
                "runtime_material_digest": runtime["material_digest"],
                "source_candidate": source_candidate,
                "source_input_snapshot_sha256": source_snapshot,
                "qualification_sha256": manylinux._digest(qualification),
                "portability_observation_sha256": manylinux._digest(portability),
                "runtime_receipt_sha256": manylinux._digest(runtime_receipt),
                "runtime_floor_observation_sha256": manylinux._digest(runtime_floor),
                "host_floor_observation_sha256": manylinux._digest(host_floor),
                "host_newer_observation_sha256": manylinux._digest(host_newer),
                "cpu_baseline_sha256": manylinux._digest(cpu),
            }
            bodies.update({
                f"{target}:source": source, f"{target}:qualification": qualification,
                f"{target}:portability": portability, f"{target}:runtime": runtime_receipt,
                f"{target}:runtime_floor": runtime_floor, f"{target}:host_floor": host_floor,
                f"{target}:host_newer": host_newer, f"{target}:cpu": cpu,
            })
            rows.append(row)
        record = {
            "schema": manylinux.PORTABILITY_SCHEMA,
            "version": "0.7.0",
            "claim": "manylinux_2_36",
            "construction_status": "payload-qualified",
            "tf_producer_source": self.tf_source,
            "rs9_tool_source": self.rs9_source,
            "evidence_mode": "fixture",
            "source_input_snapshot_sha256": "a" * 64,
            "targets": rows,
        }
        record["identity"] = manylinux._digest(record)
        return record, bodies

    def _build_linux_wheels(self, stage_a=None):
        stage_a = stage_a or self.stage_a
        wheels = {}
        for target, system, triple in (
            ("linux-arm64-gnu", "aarch64-linux", "aarch64-unknown-linux-gnu"),
            ("linux-x64-gnu", "x86_64-linux", "x86_64-unknown-linux-gnu"),
        ):
            result = build_gate1_successor_wheel(
                "theme-forge-nebular-fusion",
                application_version="0.7.0",
                distribution_version="0.7.0",
                archive_bytes=self.archive,
                manifest=self.manifest,
                output_dir=self.root / system,
                license_files={name: _legal()[name] for name in ("LICENSE", "NOTICE")},
                launcher_path="theme-forge-nebular-fusion/bin/tfnf",
                gui_path="theme-forge-nebular-fusion/bin/theme-forge-nebular-fusion",
                fixture_only=True,
                candidate_only=True,
                candidate_profile=GATE1_PROFILE,
                system=system,
                target_platform=triple,
                payload_portability=stage_a,
                rs9_source_commit=self.rs9_source["commit"],
                rs9_source_tree=self.rs9_source["tree"],
            )
            wheels[target] = self._bind_fixture_source_identity(result.wheel_bytes)
        return wheels

    def _bind_fixture_source_identity(self, wheel: bytes) -> bytes:
        """Complete the fixture-only builder output for the real verifier seam."""
        with zipfile.ZipFile(io.BytesIO(wheel), "r") as archive:
            entries = {name: archive.read(name) for name in archive.namelist()}
        provenance_name = "theme_forge_nebular_fusion/_rs9/provenance.json"
        record_name = next(name for name in entries if name.endswith("/RECORD"))
        dist_info = record_name.rsplit("/", 1)[0]
        provenance = json.loads(entries[provenance_name])
        provenance["source_identity"] = {
            "repository": "fixture/theme-forge-nebular-fusion",
            "tag": "v0.7.0",
            "commit": "9" * 40,
            "tree": "a" * 40,
        }
        entries[provenance_name] = archive_canonical(provenance)
        entries[record_name] = format_record(entries, dist_info)
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name in sorted(entries):
                archive.writestr(name, entries[name])
        return output.getvalue()

    def _build_darwin_wheel(self) -> bytes:
        """Build the real third fixture wheel needed by verify-upload's closed set."""
        archive = _darwin_payload()
        archive_path = self.root / "darwin-payload.tgz"
        archive_path.write_bytes(archive)
        manifest = inspect_archive(archive_path, commands={})
        result = build_gate1_successor_wheel(
            "theme-forge-nebular-fusion",
            application_version="0.7.0",
            distribution_version="0.7.0",
            archive_bytes=archive,
            manifest=manifest,
            output_dir=self.root / "aarch64-darwin",
            license_files={name: _legal()[name] for name in ("LICENSE", "NOTICE")},
            launcher_path="Theme Forge Nebular Fusion.app/Contents/Resources/bin/tfnf",
            gui_path="Theme Forge Nebular Fusion.app/Contents/MacOS/theme-forge-nebular-fusion",
            fixture_only=True,
            candidate_only=True,
            candidate_profile=GATE1_PROFILE,
            system="aarch64-darwin",
            target_platform="aarch64-apple-darwin",
            rs9_source_commit=self.rs9_source["commit"],
            rs9_source_tree=self.rs9_source["tree"],
        )
        return self._bind_fixture_source_identity(result.wheel_bytes)

    def _bind_darwin_fixture(
        self,
        admission: dict,
        approval: dict,
        matrix: dict,
        wheel: bytes,
    ) -> str:
        """Bind Darwin bytes into the existing synthetic approval/matrix graph."""
        with zipfile.ZipFile(io.BytesIO(wheel), "r") as archive:
            entries = {name: archive.read(name) for name in archive.namelist()}
        payload_member = next(
            name for name in entries if name.startswith("theme_forge_nebular_fusion/payload/")
            and name.endswith((".tar.gz", ".tgz"))
        )
        manifest_member = next(name for name in entries if name.endswith("/payload/manifest.json"))
        manifest_doc = json.loads(entries[manifest_member])
        name = "theme_forge_nebular_fusion-0.7.0-py3-none-macosx_13_0_arm64.whl"
        archive_sha = bytes_digest(wheel)
        darwin_row = next(row for row in approval["files"] if row["target"] == "darwin-arm64")
        darwin_row.update({
            "size": len(wheel),
            "sha256": archive_sha,
            "payload_archive_name": payload_member.rsplit("/", 1)[1],
            "payload_archive_sha256": bytes_digest(entries[payload_member]),
            "manifest_sha256": manifest_doc["manifest_sha256"],
        })
        approval["license_files"] = {
            name: {"path": name, "size": len(data), "sha256": bytes_digest(data)}
            for name, data in _legal().items()
            if name in ("LICENSE", "NOTICE")
        }
        description = (Path(__file__).resolve().parents[1] / DESCRIPTION_PATH).read_bytes()
        approval["readme"] = {
            "path": str(DESCRIPTION_PATH),
            "size": len(description),
            "sha256": bytes_digest(description),
        }
        wheel_ref = matrix["receipts"]["darwin-arm64"]["consumer"]["wheel"]
        wheel_ref.update({"size": len(wheel), "sha256": archive_sha})
        matrix_sha = manylinux._admission_digest(matrix)
        approval["matrix_receipt_sha256"] = matrix_sha
        approval["qualification"]["matrix_receipt_sha256"] = matrix_sha
        approval["set_sha256"] = compute_set_sha256(approval)
        approval["admission_sha256"] = compute_admission_sha256(approval)
        admission["existing_three_target_approval_sha256"] = approval["admission_sha256"]
        admission["darwin_release_row"]["wheel_archive_sha256"] = archive_sha
        admission["darwin_release_row"]["receipt_sha256"] = manylinux._admission_digest(
            matrix["receipts"]["darwin-arm64"]
        )
        admission["legal_readme_description_digests"] = {
            "license": approval["license_files"]["LICENSE"]["sha256"],
            "notice": approval["license_files"]["NOTICE"]["sha256"],
            "readme": approval["readme"]["sha256"],
            "description": approval["readme"]["sha256"],
        }
        admission["final_wheel_set_sha256"] = manylinux._admission_digest({
            "linux": sorted(admission["targets"], key=lambda row: row["target"]),
            "darwin": admission["darwin_release_row"],
        })
        unsigned = dict(admission)
        unsigned.pop("identity", None)
        admission["identity"] = manylinux._admission_digest(unsigned)
        return name

    def _consumer(self, target: str, wheel: dict[str, object], kind: str, glibc: str):
        body = {
            "schema": manylinux.CONSUMER_RECEIPT_SCHEMA,
            "kind": kind,
            "status": "pass",
            "target": target,
            "wheel_sha256": wheel["archive_sha256"],
            "wheel_tag": wheel["tag"],
            "host": {"glibc": glibc, "loader": "/lib64/ld-linux.so"},
        }
        body["identity"] = manylinux._digest(body)
        return body

    def _filenames(self, wheels):
        return {
            target: f"theme_forge_nebular_fusion-0.7.0-{manylinux.manylinux_tag_for_target(target)}.whl"
            for target in wheels
        }

    def _stage_b_record(self, wheels, stage_a=None):
        stage_a = stage_a or self.stage_a
        rows = []
        consumers = {}
        approval_files = []
        target_systems = {
            "darwin-arm64": "aarch64-darwin",
            "linux-arm64-gnu": "aarch64-linux",
            "linux-x64-gnu": "x86_64-linux",
        }
        for target, raw in wheels.items():
            snapshot = manylinux._wheel_snapshot(raw, target, stage_a.digest)
            with zipfile.ZipFile(io.BytesIO(raw), "r") as archive:
                payload_name = next(
                    name.rsplit("/", 1)[1]
                    for name in archive.namelist()
                    if name.startswith("theme_forge_nebular_fusion/payload/")
                    and name.endswith((".tar.gz", ".tgz"))
                )
            consumers[target] = {
                "floor": self._consumer(target, snapshot, "floor", "2.36"),
                "newer": self._consumer(target, snapshot, "newer", "2.39"),
            }
            rows.append({
                "target": target,
                "tag": snapshot["tag"],
                "wheel_archive_sha256": snapshot["archive_sha256"],
                "wheel_size": snapshot["size"],
                "wheel_member_sha256": snapshot["wheel_member_sha256"],
                "record_member_sha256": snapshot["record_member_sha256"],
                "provenance_member_sha256": snapshot["provenance_member_sha256"],
                "payload_archive_sha256": snapshot["payload_archive_sha256"],
                "manifest_sha256": snapshot["manifest_sha256"],
                "embedded_stage_a_digest": stage_a.digest,
                "installed_floor_consumer_receipt_sha256": consumers[target]["floor"]["identity"],
                "installed_newer_consumer_receipt_sha256": consumers[target]["newer"]["identity"],
            })
            approval_files.append({
                "target": target,
                "system": target_systems[target],
                "filename": self._filenames({target: raw})[target],
                "size": snapshot["size"],
                "sha256": snapshot["archive_sha256"],
                "tag": snapshot["tag"],
                "version": "0.7.0",
                "payload_archive_name": payload_name,
                "payload_archive_sha256": snapshot["payload_archive_sha256"],
                "manifest_sha256": snapshot["manifest_sha256"],
            })
        approval_files.insert(0, {
            "target": "darwin-arm64",
            "system": "aarch64-darwin",
            "filename": "theme_forge_nebular_fusion-0.7.0-py3-none-macosx_13_0_arm64.whl",
            "size": 1,
            "sha256": "a" * 64,
            "tag": "py3-none-macosx_13_0_arm64",
            "version": "0.7.0",
            "payload_archive_name": "payload.tgz",
            "payload_archive_sha256": "b" * 64,
            "manifest_sha256": "c" * 64,
        })
        candidate_source = {"commit": "1" * 40, "tree": "2" * 40}
        qualification_source = {"commit": "3" * 40, "tree": "4" * 40}
        qualification = {
            "candidate_source_commit": candidate_source["commit"],
            "candidate_source_tree": candidate_source["tree"],
            "qualification_source_commit": qualification_source["commit"],
            "qualification_source_tree": qualification_source["tree"],
            "qualification_run_id": "1",
            "qualification_run_attempt": "1",
            "candidate_receipt_sha256": "5" * 64,
            "expected_artifact_record_sha256": "6" * 64,
            "profile_sha256": "7" * 64,
            "matrix_receipt_sha256": "0" * 64,
            "release_tag_commit": "8" * 40,
            "target_qualification_sources": {
                target: {
                    "commit": qualification_source["commit"],
                    "tree": qualification_source["tree"],
                    "status": "verified-hosted-checkout",
                    "verified": True,
                }
                for target in ("darwin-arm64", "linux-arm64-gnu", "linux-x64-gnu")
            },
        }
        matrix = {
            "schema": "rs9.nebular070-hosted-matrix.v1",
            "status": "native-matrix-passed",
            "fixture_only": False,
            "native_qualified": True,
            "candidate_receipt_sha256": qualification["candidate_receipt_sha256"],
            "expected_artifact_record_sha256": qualification["expected_artifact_record_sha256"],
            "candidate_rs9_source": candidate_source,
            "qualification_rs9_source": {
                target: {
                    "status": "executing-qualification-source",
                    "commit": qualification_source["commit"],
                    "tree": qualification_source["tree"],
                    "run_id": "1",
                    "run_attempt": "1",
                    "profile_sha256": qualification["profile_sha256"],
                }
                for target in ("darwin-arm64", "linux-arm64-gnu", "linux-x64-gnu")
            },
            "targets": ["darwin-arm64", "linux-arm64-gnu", "linux-x64-gnu"],
            "receipts": {},
            "run_id": "1",
            "run_attempt": "1",
            "publication_admitted": False,
            "public_writes": 0,
        }
        for target in ("darwin-arm64", "linux-arm64-gnu", "linux-x64-gnu"):
            file_row = next(row for row in approval_files if row["target"] == target)
            matrix["receipts"][target] = {
                "schema": "rs9.nebular070-hosted-consumer.v1",
                "status": "native-consumer-passed",
                "fixture_only": False,
                "native_qualified": True,
                "candidate_receipt_sha256": qualification["candidate_receipt_sha256"],
                "expected_artifact_record_sha256": qualification["expected_artifact_record_sha256"],
                "candidate_rs9_source": candidate_source,
                "qualification_rs9_source": matrix["qualification_rs9_source"][target],
                "target": target,
                "consumer": {
                    "fixture_only": False,
                    "native_qualified": True,
                    "process_observer": {"orphan_count": 0},
                    "user_state": {"unchanged": True},
                    "sandbox": {"network_disabled": True},
                    "provider_closure": {"status": "verified"},
                    "wheel": {
                        "target": target,
                        "filename": file_row["filename"],
                        "size": file_row["size"],
                        "sha256": file_row["sha256"],
                        "tag": file_row["tag"],
                        "version": "0.7.0",
                    },
                },
                "publication_admitted": False,
                "public_writes": 0,
            }
        matrix_sha = manylinux._admission_digest(matrix)
        qualification["matrix_receipt_sha256"] = matrix_sha
        approval = {
            "schema": APPROVAL_SCHEMA,
            "project": "theme-forge-nebular-fusion",
            "distribution": "theme-forge-nebular-fusion",
            "version": "0.7.0",
            "distribution_version": "0.7.0",
            "workflow": WORKFLOW,
            "environment": "pypi",
            "requires_python": EXPECTED_REQUIRES_PYTHON,
            "command": EXPECTED_COMMAND,
            "license_expression": EXPECTED_LICENSE_EXPRESSION,
            "license_files": {
                "LICENSE": {"path": "LICENSE", "size": 1, "sha256": "d" * 64},
                "NOTICE": {"path": "NOTICE", "size": 1, "sha256": "e" * 64},
            },
            "readme": {"path": str(DESCRIPTION_PATH), "size": 1, "sha256": "f" * 64},
            "candidate_receipt_sha256": qualification["candidate_receipt_sha256"],
            "expected_artifact_record_sha256": qualification["expected_artifact_record_sha256"],
            "profile_sha256": qualification["profile_sha256"],
            "matrix_receipt_sha256": matrix_sha,
            "qualification": qualification,
            "files": approval_files,
            "builder_can_publish": False,
            "publication_admitted": True,
            "set_sha256": "0" * 64,
            "manylinux_stage_a_sha256": stage_a.digest,
        }
        approval["set_sha256"] = compute_set_sha256(approval)
        approval["admission_sha256"] = compute_admission_sha256(approval)
        record = {
            "schema": manylinux.ADMISSION_SCHEMA,
            "version": "0.7.0",
            "claim": "manylinux_2_36",
            "stage_a_sha256": stage_a.digest,
            "rs9_release_source": candidate_source,
            "tf_producer_source": self.tf_source,
            "targets": rows,
            "darwin_release_row": {
                "target": "darwin-arm64",
                "tag": "py3-none-macosx_13_0_arm64",
                "wheel_archive_sha256": "a" * 64,
                "receipt_sha256": manylinux._admission_digest(matrix["receipts"]["darwin-arm64"]),
            },
            "existing_three_target_approval_sha256": approval["admission_sha256"],
            "legal_readme_description_digests": {
                "license": "d" * 64,
                "notice": "e" * 64,
                "readme": "f" * 64,
                "description": "f" * 64,
            },
            "final_wheel_set_sha256": "0" * 64,
            "manylinux_claim": True,
            "publication_admitted": True,
        }
        record["final_wheel_set_sha256"] = manylinux._admission_digest({
            "linux": sorted(rows, key=lambda row: row["target"]),
            "darwin": record["darwin_release_row"],
        })
        record["identity"] = manylinux._admission_digest(record)
        return record, consumers, approval, matrix

    def test_stage_a_builds_manylinux_wheels_and_stage_b_reads_real_record(self) -> None:
        wheels = self._build_linux_wheels()
        self.assertEqual(
            sorted(Path(self.root / "x86_64-linux").iterdir())[0].name,
            "theme_forge_nebular_fusion-0.7.0-py3-none-manylinux_2_36_x86_64.whl",
        )
        admission, consumers, approval, matrix = self._stage_b_record(wheels)
        validated = manylinux.validate_nebular070_release_admission(
            admission,
            stage_a=self.stage_a,
            wheel_bytes_by_target=wheels,
            wheel_filenames_by_target=self._filenames(wheels),
            installed_consumer_bodies=consumers,
            existing_three_target_approval=approval,
            existing_matrix_receipt=matrix,
            expected_rs9_release_source=admission["rs9_release_source"],
        )
        self.assertEqual(validated.digest, admission["identity"])
        self.assertTrue(validated.record["publication_admitted"])
        renamed = {target: name.replace("manylinux_2_36", "manylinux_2_28")
                   for target, name in self._filenames(wheels).items()}
        with self.assertRaises(ContractError):
            manylinux.validate_nebular070_release_admission(
                admission,
                stage_a=self.stage_a,
                wheel_bytes_by_target=wheels,
                wheel_filenames_by_target=renamed,
                installed_consumer_bodies=consumers,
                existing_three_target_approval=approval,
                existing_matrix_receipt=matrix,
                expected_rs9_release_source=admission["rs9_release_source"],
            )

    def test_stage_a_refuses_unknown_or_crosswired_evidence(self) -> None:
        unknown = copy.deepcopy(self.stage_a_record)
        unknown["unexpected"] = True
        with self.assertRaises(ContractError):
            manylinux.validate_nebular070_payload_portability(
                unknown,
                self.receipt_bodies,
                expected_tf_producer_source=self.tf_source,
                expected_rs9_tool_source=self.rs9_source,
            )
        wrong_source = copy.deepcopy(self.stage_a_record)
        wrong_source["tf_producer_source"] = {"commit": "e" * 40, "tree": "f" * 40}
        wrong_source["identity"] = manylinux._digest({k: v for k, v in wrong_source.items() if k != "identity"})
        with self.assertRaises(ContractError):
            manylinux.validate_nebular070_payload_portability(
                wrong_source,
                self.receipt_bodies,
                expected_tf_producer_source=self.tf_source,
                expected_rs9_tool_source=self.rs9_source,
            )
        wrong_body = copy.deepcopy(self.receipt_bodies)
        wrong_body["linux-x64-gnu:cpu"]["target"] = "linux-arm64-gnu"
        with self.assertRaises(ContractError):
            manylinux.validate_nebular070_payload_portability(
                self.stage_a_record,
                wrong_body,
                expected_tf_producer_source=self.tf_source,
                expected_rs9_tool_source=self.rs9_source,
            )

        # Maintained JS runtime receipts use compact identity bytes; the
        # Python admission envelope may still hash the received body with its
        # own canonical record digest.  Keep that boundary explicit.
        compact_floor = copy.deepcopy(self.receipt_bodies["linux-arm64-gnu:runtime_floor"])
        compact_unsigned = dict(compact_floor)
        compact_unsigned.pop("observationIdentity")
        compact_floor["observationIdentity"] = manylinux._maintained_identity(compact_unsigned)
        compact_bodies = copy.deepcopy(self.receipt_bodies)
        compact_bodies["linux-arm64-gnu:runtime_floor"] = compact_floor
        compact_record = copy.deepcopy(self.stage_a_record)
        compact_row = next(row for row in compact_record["targets"] if row["target"] == "linux-arm64-gnu")
        compact_row["runtime_floor_observation_sha256"] = manylinux._digest(compact_floor)
        compact_unsigned_record = dict(compact_record)
        compact_unsigned_record.pop("identity")
        compact_record["identity"] = manylinux._digest(compact_unsigned_record)
        self.assertTrue(
            manylinux.validate_nebular070_payload_portability(
                compact_record,
                compact_bodies,
                expected_tf_producer_source=self.tf_source,
                expected_rs9_tool_source=self.rs9_source,
                allow_fixture=True,
            ).fixture_only
        )

    def test_stage_a_cpu_requires_concrete_baseline_and_property(self) -> None:
        def variant(*, baseline=None, properties=None):
            record = copy.deepcopy(self.stage_a_record)
            bodies = copy.deepcopy(self.receipt_bodies)
            for target, (triple, _tag) in manylinux.LINUX_TARGETS.items():
                body = bodies[f"{target}:cpu"]
                if baseline is not None:
                    body["baseline"] = baseline
                if properties is not None:
                    body["properties"] = copy.deepcopy(properties)
                body["identity"] = manylinux._digest({k: v for k, v in body.items() if k != "identity"})
                row = next(item for item in record["targets"] if item["target"] == target)
                row["cpu_baseline_sha256"] = manylinux._digest(body)
            record["identity"] = manylinux._digest({k: v for k, v in record.items() if k != "identity"})
            return record, bodies

        for bad_baseline in ("unknown", " UnKnOwN ", "unresolved", "   ", "not_claimed"):
            record, bodies = variant(baseline=bad_baseline)
            with self.assertRaises(ContractError):
                manylinux.validate_nebular070_payload_portability(
                    record, bodies, expected_tf_producer_source=self.tf_source,
                    expected_rs9_tool_source=self.rs9_source, allow_fixture=True,
                )
        for bad_properties in ({}, {"isa": "unknown"}, {"isa": " UNRESOLVED "}, {"isa": "not-claimed"}):
            record, bodies = variant(properties=bad_properties)
            with self.assertRaises(ContractError):
                manylinux.validate_nebular070_payload_portability(
                    record, bodies, expected_tf_producer_source=self.tf_source,
                    expected_rs9_tool_source=self.rs9_source, allow_fixture=True,
                )

        for concrete in ({"count": 0}, {"feature": False}, {"isa": "generic"}):
            record, bodies = variant(properties=concrete)
            self.assertTrue(
                manylinux.validate_nebular070_payload_portability(
                    record, bodies, expected_tf_producer_source=self.tf_source,
                    expected_rs9_tool_source=self.rs9_source, allow_fixture=True,
                ).fixture_only
            )

    def test_stage_b_refuses_stale_consumer_and_wheel_hash_or_claim_shortcut(self) -> None:
        wheels = self._build_linux_wheels()
        admission, consumers, approval, matrix = self._stage_b_record(wheels)
        stale_consumer = copy.deepcopy(consumers)
        stale_consumer["linux-x64-gnu"]["newer"]["wheel_sha256"] = "f" * 64
        with self.assertRaises(ContractError):
            manylinux.validate_nebular070_release_admission(
                admission, stage_a=self.stage_a, wheel_bytes_by_target=wheels,
                wheel_filenames_by_target=self._filenames(wheels),
                installed_consumer_bodies=stale_consumer,
                existing_three_target_approval=approval,
                existing_matrix_receipt=matrix,
                expected_rs9_release_source=admission["rs9_release_source"],
            )
        bad_floor = copy.deepcopy(consumers)
        bad_floor_body = bad_floor["linux-x64-gnu"]["floor"]
        bad_floor_body["host"]["glibc"] = "2.37"
        bad_floor_body["identity"] = manylinux._digest({
            k: v for k, v in bad_floor_body.items() if k != "identity"
        })
        bad_floor_admission = copy.deepcopy(admission)
        bad_floor_row = next(
            row for row in bad_floor_admission["targets"]
            if row["target"] == "linux-x64-gnu"
        )
        bad_floor_row["installed_floor_consumer_receipt_sha256"] = bad_floor_body["identity"]
        bad_floor_admission["identity"] = manylinux._digest({
            k: v for k, v in bad_floor_admission.items() if k != "identity"
        })
        with self.assertRaises(ContractError):
            manylinux.validate_nebular070_release_admission(
                bad_floor_admission, stage_a=self.stage_a, wheel_bytes_by_target=wheels,
                wheel_filenames_by_target=self._filenames(wheels),
                installed_consumer_bodies=bad_floor,
                existing_three_target_approval=approval,
                existing_matrix_receipt=matrix,
                expected_rs9_release_source=admission["rs9_release_source"],
            )
        stale_wheel = copy.deepcopy(admission)
        stale_wheel["targets"][0]["wheel_archive_sha256"] = "f" * 64
        stale_wheel["identity"] = manylinux._digest({k: v for k, v in stale_wheel.items() if k != "identity"})
        with self.assertRaises(ContractError):
            manylinux.validate_nebular070_release_admission(
                stale_wheel, stage_a=self.stage_a, wheel_bytes_by_target=wheels,
                wheel_filenames_by_target=self._filenames(wheels),
                installed_consumer_bodies=consumers,
                existing_three_target_approval=approval,
                existing_matrix_receipt=matrix,
                expected_rs9_release_source=admission["rs9_release_source"],
            )
        shortcut = copy.deepcopy(admission)
        shortcut["publication_admitted"] = False
        shortcut["identity"] = manylinux._digest({k: v for k, v in shortcut.items() if k != "identity"})
        with self.assertRaises(ContractError):
            manylinux.validate_nebular070_release_admission(
                shortcut, stage_a=self.stage_a, wheel_bytes_by_target=wheels,
                wheel_filenames_by_target=self._filenames(wheels),
                installed_consumer_bodies=consumers,
                existing_three_target_approval=approval,
                existing_matrix_receipt=matrix,
                expected_rs9_release_source=admission["rs9_release_source"],
            )

    def test_main_cli_validates_external_stage_a_bundle_and_rejects_rehashed_facts(self) -> None:
        input_path = self.root / "payload-portability.json"
        actual_record = copy.deepcopy(self.stage_a_record)
        actual_record["evidence_mode"] = "actual"
        actual_record["identity"] = manylinux._digest({k: v for k, v in actual_record.items() if k != "identity"})
        input_path.write_bytes(manylinux.canonical({
            "schema": manylinux.PORTABILITY_INPUT_SCHEMA,
            "record": actual_record,
            "bodies": self.receipt_bodies,
        }))
        self.assertEqual(
            publish_main([
                "validate-portability", "--input", str(input_path),
                "--tf-producer-commit", self.tf_source["commit"],
                "--tf-producer-tree", self.tf_source["tree"],
                "--rs9-commit", self.rs9_source["commit"],
                "--rs9-tree", self.rs9_source["tree"],
            ]),
            0,
        )
        tampered = copy.deepcopy(actual_record)
        tampered["targets"][0]["source_candidate"] = "f" * 64
        tampered["identity"] = manylinux._digest({k: v for k, v in tampered.items() if k != "identity"})
        input_path.write_bytes(manylinux.canonical({
            "schema": manylinux.PORTABILITY_INPUT_SCHEMA,
            "record": tampered,
            "bodies": self.receipt_bodies,
        }))
        self.assertEqual(
            publish_main([
                "validate-portability", "--input", str(input_path),
                "--tf-producer-commit", self.tf_source["commit"],
                "--tf-producer-tree", self.tf_source["tree"],
                "--rs9-commit", self.rs9_source["commit"],
                "--rs9-tree", self.rs9_source["tree"],
            ]),
            1,
        )
        wf_text = publish_module.workflow_070_jobs_text(require_manylinux=True)
        self.assertNotIn("steps.manylinux_inputs.outputs.stage_b", wf_text)
        self.assertIn('STAGE_B_PATH="$(printf \'%s\\n\' "$MANYLINUX_OUT" | sed -n \'s/^stage_b=//p\')"', wf_text)

    def test_main_cli_admits_stage_b_only_with_actual_approval_matrix_and_wheel_bytes(self) -> None:
        actual_record = copy.deepcopy(self.stage_a_record)
        actual_record["evidence_mode"] = "actual"
        actual_record["identity"] = manylinux._digest({k: v for k, v in actual_record.items() if k != "identity"})
        actual_stage_a = manylinux.validate_nebular070_payload_portability(
            actual_record,
            self.receipt_bodies,
            expected_tf_producer_source=self.tf_source,
            expected_rs9_tool_source=self.rs9_source,
        )
        wheels = self._build_linux_wheels(actual_stage_a)
        darwin_wheel = self._build_darwin_wheel()
        admission, consumers, approval, matrix = self._stage_b_record(wheels, actual_stage_a)
        darwin_filename = self._bind_darwin_fixture(admission, approval, matrix, darwin_wheel)
        dist = self.root / "dist"
        dist.mkdir()
        for target, wheel in wheels.items():
            (dist / self._filenames(wheels)[target]).write_bytes(wheel)
        (dist / darwin_filename).write_bytes(darwin_wheel)
        approval_path = self.root / "theme-forge-nebular-fusion-0.7.0-artifacts.json"
        approval_path.write_bytes(manylinux.canonical(approval))
        stage_a_path = self.root / "payload-portability.json"
        stage_a_path.write_bytes(manylinux.canonical({
            "schema": manylinux.PORTABILITY_INPUT_SCHEMA,
            "record": actual_record,
            "bodies": self.receipt_bodies,
        }))
        consumer_dir = self.root / "consumers"
        captured_consumers = {}
        for target in ("linux-arm64-gnu", "linux-x64-gnu"):
            captured_consumers[target] = {}
            for kind in ("floor", "newer"):
                member = f"consumers/{target}/{kind}.json"
                raw = archive_canonical(consumers[target][kind])
                member_path = consumer_dir / member
                member_path.parent.mkdir(parents=True, exist_ok=True)
                member_path.write_bytes(raw)
                captured_consumers[target][kind] = {
                    "member": member,
                    "sha256": bytes_digest(raw),
                    "source": admission["rs9_release_source"],
                }
        admission_path = self.root / "manylinux-admission.json"
        admission_path.write_bytes(manylinux.canonical({
            "schema": "rs9.nebular070-manylinux-admission-input.v1",
            "record": admission,
            "consumers": consumers,
            "approval": approval,
            "matrix": matrix,
            "captured_consumer_receipts": captured_consumers,
        }))
        materialized_consumer_dir = self.root / "materialized-consumers"
        self.assertEqual(
            publish_main([
                "materialize-manylinux-consumers", "--admission", str(admission_path),
                "--output", str(materialized_consumer_dir),
            ]),
            0,
        )
        output = self.root / "admitted.json"
        self.assertEqual(
            publish_main([
                "admit-manylinux", "--approval", str(approval_path), "--dist", str(dist),
                "--payload-portability", str(stage_a_path), "--manylinux-admission", str(admission_path),
                "--manylinux-consumer-receipts", str(materialized_consumer_dir),
                "--tf-producer-commit", self.tf_source["commit"], "--tf-producer-tree", self.tf_source["tree"],
                "--output", str(output),
            ]),
            0,
        )
        self.assertEqual(json.loads(output.read_bytes())["identity"], admission["identity"])
        captured_tamper = json.loads(admission_path.read_text(encoding="utf-8"))
        captured_tamper["captured_consumer_receipts"]["linux-x64-gnu"]["floor"]["sha256"] = "f" * 64
        admission_path.write_bytes(manylinux.canonical(captured_tamper))
        self.assertEqual(
            publish_main([
                "admit-manylinux", "--approval", str(approval_path), "--dist", str(dist),
                "--payload-portability", str(stage_a_path), "--manylinux-admission", str(admission_path),
                "--manylinux-consumer-receipts", str(materialized_consumer_dir),
                "--tf-producer-commit", self.tf_source["commit"], "--tf-producer-tree", self.tf_source["tree"],
                "--output", str(self.root / "captured-tampered.json"),
            ]),
            1,
        )

        admission_path.write_bytes(manylinux.canonical({
            "schema": "rs9.nebular070-manylinux-admission-input.v1",
            "record": admission,
            "consumers": consumers,
            "approval": approval,
            "matrix": matrix,
            "captured_consumer_receipts": captured_consumers,
        }))
        upload_dir = self.root / "upload"
        upload_dir.mkdir()
        for name in [*self._filenames(wheels).values(), darwin_filename]:
            (upload_dir / name).write_bytes((dist / name).read_bytes())
        matrix_path = self.root / "matrix_receipt.json"
        matrix_path.write_bytes(manylinux.canonical(matrix))
        original_verify_upload = publish_module.verify_upload_dir

        def verify_with_fixture(*args, **kwargs):
            kwargs["approval"] = approval
            return original_verify_upload(*args, **kwargs)

        verify_args = [
            "verify-upload", "--dist", str(dist), "--upload-dir", str(upload_dir),
            "--manylinux-admission", str(admission_path),
            "--manylinux-consumer-receipts", str(materialized_consumer_dir),
            "--matrix-receipt", str(matrix_path),
            "--payload-portability", str(stage_a_path),
            "--tf-producer-commit", self.tf_source["commit"],
            "--tf-producer-tree", self.tf_source["tree"],
        ]
        with mock.patch.object(publish_module, "verify_upload_dir", side_effect=verify_with_fixture):
            self.assertEqual(publish_main(verify_args), 0)
            missing_matrix_args = [
                arg for arg in verify_args
                if arg not in ("--matrix-receipt", str(matrix_path))
            ]
            self.assertEqual(publish_main(missing_matrix_args), 1)
            tampered_matrix = copy.deepcopy(matrix)
            tampered_matrix["run_id"] = "tampered"
            matrix_path.write_bytes(manylinux.canonical(tampered_matrix))
            self.assertEqual(publish_main(verify_args), 1)
        admission_path.write_bytes(manylinux.canonical({
            "schema": "rs9.nebular070-manylinux-admission-input.v1",
            "record": admission,
            "consumers": consumers,
            "approval": approval,
            "matrix": matrix,
            "captured_consumer_receipts": captured_consumers,
        }))
        tampered = json.loads(admission_path.read_text(encoding="utf-8"))
        tampered["record"]["final_wheel_set_sha256"] = "f" * 64
        admission_path.write_bytes(manylinux.canonical(tampered))
        self.assertEqual(
            publish_main([
                "admit-manylinux", "--approval", str(approval_path), "--dist", str(dist),
                "--payload-portability", str(stage_a_path), "--manylinux-admission", str(admission_path),
                "--manylinux-consumer-receipts", str(materialized_consumer_dir),
                "--tf-producer-commit", self.tf_source["commit"], "--tf-producer-tree", self.tf_source["tree"],
                "--output", str(self.root / "rejected.json"),
            ]),
            1,
        )


if __name__ == "__main__":
    unittest.main()
