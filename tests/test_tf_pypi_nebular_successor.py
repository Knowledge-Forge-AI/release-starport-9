"""Candidate-only integration tests for the Nebular post1 adapter."""
from __future__ import annotations

import copy
import dataclasses
import json
import shutil
import tarfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

import rs9.nebular_lineage as lineage
from rs9.errors import ContractError
from rs9.operator import BOOTSTRAP
from rs9.profiles import selection_for_intent
from rs9.release_core import authenticate_release, digest
from rs9.scratch import canonical
from rs9.tf_pypi_nebular_successor import (
    authenticate_gate1_capture,
    authenticate_successor_capture,
    build_successor_candidates,
    main,
    validate_candidate_receipt,
    write_candidate_receipt,
)
from rs9.wheel import format_record
from rs9.wheel_nebular_successor import (
    DESCRIPTION_070_PATH,
    DISTRIBUTION_VERSION,
    SUCCESSOR_RELEASES,
    _wheel_archive,
    build_successor_wheel,
    successor_release,
)
from tests.test_nebular070_gate1_roundtrip import _prepare_fixture
from tests.test_nebular_lineage import NebularLineageTests
from tests.test_wheel_native import make_darwin_archive, make_standard_darwin_entries

LICENSE = b"Synthetic license text for offline fixture only.\n"
NOTICE = b"Synthetic AGPL-3.0-or-later declaration.\n"
RS9_COMMIT = "a" * 40
RS9_TREE = "b" * 40


def _darwin_archive() -> bytes:
    entries = []
    for path, data, mode, kind, link in make_standard_darwin_entries():
        if path.endswith("/LICENSE"):
            data = LICENSE
        elif path.endswith("/NOTICE"):
            data = NOTICE
        entries.append((path, data, mode, kind, link))
    return make_darwin_archive(entries)


def _linux_archive() -> bytes:
    root = "theme-forge-nebular-fusion"
    return make_darwin_archive([
        (root, b"", 0o755, tarfile.DIRTYPE, ""),
        (f"{root}/bin", b"", 0o755, tarfile.DIRTYPE, ""),
        (f"{root}/bin/tfnf", b"#!/bin/sh\nexit 0\n", 0o755, tarfile.REGTYPE, ""),
        (f"{root}/bin/theme-forge-nebular-fusion", b"#!/bin/sh\nexit 0\n", 0o755, tarfile.REGTYPE, ""),
        (f"{root}/LICENSE", LICENSE, 0o644, tarfile.REGTYPE, ""),
        (f"{root}/NOTICE", NOTICE, 0o644, tarfile.REGTYPE, ""),
    ])


class NebularSuccessorIntegrationTests(unittest.TestCase):
    """Use the existing authenticated lineage fixture, with valid native payloads."""

    def setUp(self) -> None:
        self.lineage_case = NebularLineageTests()
        self.lineage_case.setUp()
        self.addCleanup(self.lineage_case.tearDown)
        self.fixture = self.lineage_case.fixture
        self.root = self.lineage_case.root
        self._prepare_current_capture()

    def _prepare_current_capture(self) -> None:
        fixture = self.fixture
        evidence = fixture["evidence"]
        intent = fixture["intent"]
        archives = {
            "darwin-arm64": _darwin_archive(),
            "linux-arm64": _linux_archive(),
            "linux-x64": _linux_archive(),
        }
        for asset in intent["assets"]:
            (evidence / "assets" / asset["name"]).write_bytes(archives[asset["id"]])
        staged = {
            path.name: path.read_bytes()
            for path in (evidence / "assets").iterdir()
            if path.name != "SHA256SUMS"
        }
        checksums = "".join(
            digest(data) + "  " + name + "\n"
            for name, data in sorted(staged.items())
        ).encode()
        (evidence / "assets/SHA256SUMS").write_bytes(checksums)
        release_path = evidence / "api/release.json"
        release = json.loads(release_path.read_bytes())
        release["immutable"] = False
        for row in release["assets"]:
            data = staged.get(row["name"])
            if data is not None:
                row["size"] = len(data)
                row["digest"] = "sha256:" + digest(data)
            elif row["name"] == "SHA256SUMS":
                row["size"] = len(checksums)
                row["digest"] = "sha256:" + digest(checksums)
        release_path.write_bytes(canonical(release))
        capture = authenticate_release(selection_for_intent(intent), evidence)
        fixture["capture"] = capture
        actual = {
            row["name"]: {
                "id": row["github_asset_id"],
                "name": row["name"],
                "size": row["size"],
                "sha256": row["sha256"],
            }
            for row in capture.record["assets"]
        }
        record = copy.deepcopy(fixture["record"])
        record["asset_inventory"] = sorted(
            [actual.get(row["name"], row) for row in record["asset_inventory"]],
            key=lambda row: row["name"],
        )
        record["provenance_asset"] = next(
            row for row in record["asset_inventory"]
            if row["name"] == lineage.PROVENANCE_NAME
        )
        fixture["record"] = record
        fixture["record_sha"] = digest(canonical(record))
        (fixture["repo"] / lineage.FORWARD_RECORD_PATH).write_bytes(canonical(record))

        source_root = Path(__file__).resolve().parents[1]
        shutil.copytree(source_root / "bootstrap", fixture["repo"] / "bootstrap")
        expectations_dir = fixture["repo"] / "operators/live1"
        expectations_dir.mkdir(parents=True)
        expectations = json.loads((source_root / "operators/live1/expectations.json").read_bytes())
        current = next(
            row for row in expectations["projects"]
            if row["repository"] == lineage.CURRENT_REPOSITORY
        )
        payload_names = {row["name"] for row in capture.record["payloads"]}
        current["assets"] = [
            {
                "name": row["name"],
                "size": row["size"],
                "sha256": row["sha256"],
                "id": row["github_asset_id"],
            }
            for row in capture.record["assets"]
            if row["name"] in payload_names
        ]
        (expectations_dir / "expectations.json").write_bytes(
            canonical({"projects": [current]})
        )

    def _authenticate(self):
        return authenticate_successor_capture(
            self.fixture["repo"],
            self.fixture["evidence"],
            approved_bootstrap_sha256=digest(
                (self.fixture["repo"] / BOOTSTRAP).read_bytes()
            ),
        )

    def _build(self):
        return build_successor_candidates(
            self._authenticate(),
            self.root / "candidates",
            rs9_source_commit=RS9_COMMIT,
            rs9_source_tree=RS9_TREE,
            deterministic_timestamp=(2026, 1, 1, 0, 0, 0),
        )

    def _with_pins(self):
        return (
            self.lineage_case._pins()[0],
            self.lineage_case._pins()[1],
            self.lineage_case._pins()[2],
        )

    def _rewrite_wheel(self, wheel_path: Path, mutate, *, replacement_tag: str | None = None) -> str:
        with zipfile.ZipFile(wheel_path, "r") as archive:
            entries = {name: archive.read(name) for name in archive.namelist()}
            modes = {name: (archive.getinfo(name).external_attr >> 16) & 0o7777 for name in entries}
        dist_info = next(name.split("/", 1)[0] for name in entries if name.endswith(".dist-info/METADATA"))
        provenance_member = "theme_forge_nebular_fusion/_rs9/provenance.json"
        provenance = json.loads(entries[provenance_member])
        mutate(entries, provenance)
        if replacement_tag is not None:
            wheel_member = f"{dist_info}/WHEEL"
            wheel_info = entries[wheel_member].decode("utf-8")
            wheel_info = "\n".join(
                f"Tag: {replacement_tag}" if line.startswith("Tag: ") else line
                for line in wheel_info.split("\n")
            )
            entries[wheel_member] = wheel_info.encode("utf-8")
            provenance["wheel_tag"] = replacement_tag
        entries[provenance_member] = canonical(provenance)
        record_member = f"{dist_info}/RECORD"
        entries[record_member] = format_record(entries, dist_info)
        modes[record_member] = 0o644
        wheel_bytes = _wheel_archive(entries, modes, (2026, 1, 1, 0, 0, 0))
        wheel_path.write_bytes(wheel_bytes)
        return wheel_path.name

    def _refresh_wheel_row(self, row: dict, wheel_path: Path, *, filename: str | None = None) -> None:
        raw = wheel_path.read_bytes()
        row["wheel"]["filename"] = filename or wheel_path.name
        row["wheel"]["sha256"] = digest(raw)
        row["wheel"]["size"] = len(raw)

    def test_current_equal_tree_capture_builds_exact_three_candidate_rows(self) -> None:
        with self._with_pins()[0], self._with_pins()[1], self._with_pins()[2]:
            authenticated = self._authenticate()
            receipt = build_successor_candidates(
                authenticated,
                self.root / "candidates",
                rs9_source_commit=RS9_COMMIT,
                rs9_source_tree=RS9_TREE,
                deterministic_timestamp=(2026, 1, 1, 0, 0, 0),
            )
        self.assertEqual(
            [row["system"] for row in receipt["rows"]],
            ["aarch64-darwin", "aarch64-linux", "x86_64-linux"],
        )
        self.assertEqual(receipt["forward_lineage"]["current"]["commit"], lineage.CURRENT_COMMIT)
        self.assertEqual(receipt["forward_lineage"]["historical"]["commit"], lineage.HISTORICAL_COMMIT)
        self.assertEqual(receipt["asset_facts"]["selected_asset_ids"], [
            "darwin-arm64", "linux-arm64", "linux-x64",
        ])
        self.assertEqual(receipt["rs9_source"]["commit"], RS9_COMMIT)
        self.assertEqual(receipt["license"]["expression"], "AGPL-3.0-or-later OR LicenseRef-Commercial")
        self.assertFalse(receipt["flags"]["builder_can_publish"])
        self.assertFalse(receipt["flags"]["can_publish"])
        self.assertFalse(receipt["flags"]["publication_admitted"])
        self.assertFalse(receipt["flags"]["manylinux_proven"])
        self.assertEqual(
            validate_candidate_receipt(receipt, authenticated, output_dir=self.root / "candidates"),
            receipt,
        )
        receipt_path = self.root / "candidate-receipt.json"
        write_candidate_receipt(
            receipt_path,
            receipt,
            authenticated=authenticated,
            output_dir=self.root / "candidates",
        )
        self.assertEqual(json.loads(receipt_path.read_bytes()), receipt)
        for row in receipt["rows"]:
            self.assertTrue((self.root / "candidates" / row["system"] / row["wheel"]["filename"]).is_file())

    def test_missing_forward_proof_keeps_current_capture_blocked(self) -> None:
        with (
            self._with_pins()[0],
            self._with_pins()[1],
            self._with_pins()[2],
            patch(
                "rs9.tf_pypi_nebular_successor.select_forward_lineage_proof",
                return_value=None,
            ),
            self.assertRaises(ContractError) as caught,
        ):
            self._authenticate()
        self.assertEqual(caught.exception.code, "LINEAGE_REQUIRED")

    def test_tampered_or_cross_capture_proof_is_rejected_by_builder(self) -> None:
        with (
            self._with_pins()[0],
            self._with_pins()[1],
            self._with_pins()[2],
            self.assertRaises(ContractError) as caught,
        ):
            authenticated = self._authenticate()
            build_successor_wheel(
                "theme-forge-nebular-fusion",
                capture=authenticated.capture,
                profile_result=authenticated.profile,
                lineage_proof=object(),
                lineage_intent=authenticated.intent,
                output_dir=self.root / "bad-proof",
                system="aarch64-darwin",
                target_platform="aarch64-apple-darwin",
                rs9_source_commit=RS9_COMMIT,
                rs9_source_tree=RS9_TREE,
            )
        self.assertEqual(caught.exception.code, "LINEAGE_PROOF")

        record_path = self.fixture["repo"] / lineage.FORWARD_RECORD_PATH
        record_path.write_bytes(record_path.read_bytes() + b" ")
        with (
            self._with_pins()[0],
            self._with_pins()[1],
            self._with_pins()[2],
            self.assertRaises(ContractError) as caught,
        ):
            build_successor_wheel(
                "theme-forge-nebular-fusion",
                capture=authenticated.capture,
                profile_result=authenticated.profile,
                lineage_proof=authenticated.lineage_proof,
                lineage_intent=authenticated.intent,
                output_dir=self.root / "bad-record",
                system="aarch64-darwin",
                target_platform="aarch64-apple-darwin",
                rs9_source_commit=RS9_COMMIT,
                rs9_source_tree=RS9_TREE,
            )
        self.assertEqual(caught.exception.code, "LINEAGE_RECORD")

    def test_receipt_rejects_target_and_asset_cross_wires(self) -> None:
        with self._with_pins()[0], self._with_pins()[1], self._with_pins()[2]:
            authenticated = self._authenticate()
            receipt = build_successor_candidates(
                authenticated,
                self.root / "cross-wire",
                rs9_source_commit=RS9_COMMIT,
                rs9_source_tree=RS9_TREE,
                deterministic_timestamp=(2026, 1, 1, 0, 0, 0),
            )
        target_tamper = copy.deepcopy(receipt)
        target_tamper["rows"][0]["target_triple"] = "x86_64-unknown-linux-gnu"
        with self.assertRaises(ContractError) as caught:
            validate_candidate_receipt(target_tamper, authenticated, output_dir=self.root / "cross-wire")
        self.assertEqual(caught.exception.code, "RECEIPT_TARGET")
        asset_tamper = copy.deepcopy(receipt)
        asset_tamper["rows"][0]["selected_asset_id"] = "linux-x64"
        with self.assertRaises(ContractError) as caught:
            validate_candidate_receipt(asset_tamper, authenticated, output_dir=self.root / "cross-wire")
        self.assertEqual(caught.exception.code, "RECEIPT_BINDING")

    def _build_for_receipt_validation(self, name: str = "receipt-artifacts"):
        output = self.root / name
        with self._with_pins()[0], self._with_pins()[1], self._with_pins()[2]:
            authenticated = self._authenticate()
            receipt = build_successor_candidates(
                authenticated,
                output,
                rs9_source_commit=RS9_COMMIT,
                rs9_source_tree=RS9_TREE,
                deterministic_timestamp=(2026, 1, 1, 0, 0, 0),
            )
        return authenticated, receipt, output

    def test_receipt_rejects_wheel_digest_size_and_tag_tampering(self) -> None:
        authenticated, receipt, output = self._build_for_receipt_validation()
        for field, value in (("sha256", "0" * 64), ("size", receipt["rows"][0]["wheel"]["size"] + 1),
                             ("tag", "py3-none-any")):
            tampered = copy.deepcopy(receipt)
            tampered["rows"][0]["wheel"][field] = value
            with self.subTest(field=field), self.assertRaises(ContractError) as caught:
                validate_candidate_receipt(tampered, authenticated, output_dir=output)
            self.assertIn(caught.exception.code, {"RECEIPT_ARTIFACT", "RECEIPT_BINDING", "RECEIPT_TARGET"})

    def test_receipt_rejects_joint_readme_legal_and_source_tampering(self) -> None:
        authenticated, receipt, output = self._build_for_receipt_validation("receipt-joint-tamper")
        cases = {
            "readme": {"path": "other.md", "sha256": "1" * 64},
            "legal": {name: {"path": name, "size": 1, "sha256": "2" * 64}
                      for name in ("LICENSE", "NOTICE", "COMMERCIAL-LICENSE.md")},
            "source": {"repository": "Knowledge-Forge-AI/other", "tag": "v0.6.1",
                       "commit": "c" * 40, "tree": "d" * 40,
                       "release_record_sha256": "3" * 64},
        }
        for name, value in cases.items():
            tampered = copy.deepcopy(receipt)
            if name == "readme":
                tampered["readme"] = value
                for row in tampered["rows"]:
                    row["readme"] = copy.deepcopy(value)
            elif name == "legal":
                tampered["legal_files"] = value
                tampered["license"]["files"] = copy.deepcopy(value)
                for row in tampered["rows"]:
                    row["legal_files"] = copy.deepcopy(value)
            else:
                tampered["source_identity"] = value
                for row in tampered["rows"]:
                    row["source_identity"] = copy.deepcopy(value)
            with self.subTest(name=name), self.assertRaises(ContractError) as caught:
                validate_candidate_receipt(tampered, authenticated, output_dir=output)
            self.assertIn(caught.exception.code, {"RECEIPT_ARTIFACT", "RECEIPT_BINDING"})

    def test_receipt_rejects_admission_and_asset_fact_tampering(self) -> None:
        authenticated, receipt, output = self._build_for_receipt_validation("receipt-policy-tamper")
        cases = []
        flags = copy.deepcopy(receipt)
        flags["flags"]["candidate_only"] = False
        cases.append(("candidate-only", flags))
        closure = copy.deepcopy(receipt)
        closure["source_closure"]["admitted"] = True
        cases.append(("source-closure", closure))
        policy = copy.deepcopy(receipt)
        policy["policy"]["manylinux_proven"] = True
        cases.append(("policy", policy))
        assets = copy.deepcopy(receipt)
        assets["asset_facts"]["selected_asset_ids"][0] = "linux-x64"
        cases.append(("asset-facts", assets))
        for name, tampered in cases:
            with self.subTest(name=name), self.assertRaises(ContractError) as caught:
                validate_candidate_receipt(tampered, authenticated, output_dir=output)
            self.assertIn(caught.exception.code, {"PUBLICATION_HOLD", "RECEIPT_BINDING"})

    def test_receipt_writing_requires_authenticated_artifacts(self) -> None:
        authenticated, receipt, output = self._build_for_receipt_validation("receipt-write-authority")
        with self.assertRaises(TypeError):
            write_candidate_receipt(self.root / "unbound.json", receipt)  # type: ignore[call-arg]
        target = self.root / "bound.json"
        write_candidate_receipt(target, receipt, authenticated=authenticated, output_dir=output)
        self.assertEqual(json.loads(target.read_bytes()), receipt)

    def test_receipt_rejects_tampered_wheel_bytes_and_record(self) -> None:
        authenticated, receipt, output = self._build_for_receipt_validation("receipt-wheel-tamper")
        row = receipt["rows"][0]
        wheel_path = output / row["system"] / row["wheel"]["filename"]
        wheel_path.write_bytes(wheel_path.read_bytes() + b"tampered")
        with self.assertRaises(ContractError) as caught:
            validate_candidate_receipt(receipt, authenticated, output_dir=output)
        self.assertEqual(caught.exception.code, "RECEIPT_ARTIFACT")

    def test_receipt_rejects_coordinated_payload_manifest_helper_and_launcher_changes(self) -> None:
        mutations = {
            "payload-member-only": lambda entries, provenance: entries.__setitem__(
                f"theme_forge_nebular_fusion/payload/{provenance['payload_archive_name']}",
                entries[f"theme_forge_nebular_fusion/payload/{provenance['payload_archive_name']}"] + b"tampered",
            ),
            "manifest-member-only": lambda entries, provenance: entries.__setitem__(
                "theme_forge_nebular_fusion/payload/manifest.json",
                canonical({"members": list(reversed(json.loads(entries["theme_forge_nebular_fusion/payload/manifest.json"])["members"])),
                           "manifest_sha256": digest(canonical(list(reversed(json.loads(entries["theme_forge_nebular_fusion/payload/manifest.json"])["members"]))))}),
            ),
            "helper-member-only": lambda entries, provenance: entries.__setitem__(
                "theme_forge_nebular_fusion/_isolated/rs9/materialize.py",
                entries["theme_forge_nebular_fusion/_isolated/rs9/materialize.py"] + b"\n# tampered\n",
            ),
            "launcher-member-only": lambda entries, provenance: entries.__setitem__(
                "theme_forge_nebular_fusion/launcher.py",
                entries["theme_forge_nebular_fusion/launcher.py"] + b"\n# tampered\n",
            ),
            "extra-member": lambda entries, provenance: entries.__setitem__(
                "theme_forge_nebular_fusion/evil.pth", b"import evil\n"
            ),
            "metadata": lambda entries, provenance: (
                entries.__setitem__(
                    next(name for name in entries if name.endswith(".dist-info/METADATA")),
                    entries[next(name for name in entries if name.endswith(".dist-info/METADATA"))].replace(
                        b"License-Expression: AGPL-3.0-or-later OR LicenseRef-Commercial",
                        b"License-Expression: MIT",
                    ),
                ),
                provenance.__setitem__(
                    "metadata_sha256",
                    digest(entries[next(name for name in entries if name.endswith(".dist-info/METADATA"))]),
                ),
            ),
            "provenance": lambda entries, provenance: provenance.__setitem__("unexpected", True),
            "readme-authority-extra-key": lambda entries, provenance: provenance["readme_authority"].__setitem__("admitted", True),
            "promotability": lambda entries, provenance: provenance.__setitem__("promotability", "promotable"),
        }
        for name, mutate in mutations.items():
            authenticated, receipt, output = self._build_for_receipt_validation(f"receipt-{name}-tamper")
            row = receipt["rows"][0]
            wheel_path = output / row["system"] / row["wheel"]["filename"]
            mutate_receipt = copy.deepcopy(receipt)
            self._rewrite_wheel(wheel_path, mutate)
            self._refresh_wheel_row(mutate_receipt["rows"][0], wheel_path)
            with self.subTest(name=name), self.assertRaises(ContractError) as caught:
                validate_candidate_receipt(mutate_receipt, authenticated, output_dir=output)
            self.assertEqual(caught.exception.code, "RECEIPT_ARTIFACT")

    def test_receipt_rejects_coordinated_wrong_platform_tag(self) -> None:
        authenticated, receipt, output = self._build_for_receipt_validation("receipt-tag-tamper")
        tampered = copy.deepcopy(receipt)
        row = tampered["rows"][0]
        wheel_path = output / row["system"] / row["wheel"]["filename"]
        old_name = wheel_path.name
        replacement_tag = "py3-none-linux_aarch64"
        replacement_name = old_name[:old_name.index("-py3-none-")] + f"-{replacement_tag}.whl"
        self._rewrite_wheel(wheel_path, lambda entries, provenance: None, replacement_tag=replacement_tag)
        replacement_path = wheel_path.with_name(replacement_name)
        wheel_path.rename(replacement_path)
        self._refresh_wheel_row(row, replacement_path, filename=replacement_name)
        row["wheel"]["tag"] = replacement_tag
        with self.assertRaises(ContractError) as caught:
            validate_candidate_receipt(tampered, authenticated, output_dir=output)
        self.assertEqual(caught.exception.code, "RECEIPT_TARGET")

    def test_adapter_has_no_publication_command(self) -> None:
        with self.assertRaises(SystemExit):
            main(["publish"])

    def test_release_selector_is_closed_and_defaults_to_historical(self) -> None:
        self.assertEqual(tuple(SUCCESSOR_RELEASES), ("0.6.1.post1", "0.7.0"))
        with self._with_pins()[0], self._with_pins()[1], self._with_pins()[2]:
            authenticated = self._authenticate()
        self.assertEqual(authenticated.release, SUCCESSOR_RELEASES[DISTRIBUTION_VERSION])
        with self.assertRaises(SystemExit):
            main([
                "build-candidate",
                "--release",
                "0.8.0",
                "--repository",
                str(self.fixture["repo"]),
                "--evidence",
                str(self.fixture["evidence"]),
                "--output",
                str(self.root / "bad-cli-release"),
                "--receipt",
                str(self.root / "bad-cli-receipt.json"),
                "--approved-bootstrap-sha256",
                "0" * 64,
                "--rs9-source-commit",
                RS9_COMMIT,
                "--rs9-source-tree",
                RS9_TREE,
            ])
        recorded_kwargs: dict[str, object] = {}

        def _sentinel(*args, **kwargs):
            recorded_kwargs.update(kwargs)
            raise RuntimeError("sentinel")

        with (
            patch("rs9.tf_pypi_nebular_successor.authenticate_successor_capture", side_effect=_sentinel),
            self.assertRaises(RuntimeError),
        ):
            main([
                "build-candidate",
                "--repository",
                str(self.fixture["repo"]),
                "--evidence",
                str(self.fixture["evidence"]),
                "--output",
                str(self.root / "default-cli-release"),
                "--receipt",
                str(self.root / "default-cli-receipt.json"),
                "--approved-bootstrap-sha256",
                "0" * 64,
                "--rs9-source-commit",
                RS9_COMMIT,
                "--rs9-source-tree",
                RS9_TREE,
            ])
        self.assertEqual(recorded_kwargs.get("release"), "0.6.1.post1")

        recorded_kwargs.clear()
        with (
            patch("rs9.tf_pypi_nebular_successor.authenticate_successor_capture", side_effect=_sentinel),
            self.assertRaises(RuntimeError),
        ):
            main([
                "build-candidate",
                "--release",
                "0.7.0",
                "--repository",
                str(self.fixture["repo"]),
                "--evidence",
                str(self.fixture["evidence"]),
                "--output",
                str(self.root / "selected-cli-release"),
                "--receipt",
                str(self.root / "selected-cli-receipt.json"),
                "--approved-bootstrap-sha256",
                "0" * 64,
                "--rs9-source-commit",
                RS9_COMMIT,
                "--rs9-source-tree",
                RS9_TREE,
            ])
        self.assertEqual(recorded_kwargs.get("release"), "0.7.0")

    def test_selected_070_release_rejects_historical_capture(self) -> None:
        with (
            self._with_pins()[0],
            self._with_pins()[1],
            self._with_pins()[2],
            self.assertRaises(ContractError) as caught,
        ):
            authenticate_successor_capture(
                self.fixture["repo"],
                self.fixture["evidence"],
                approved_bootstrap_sha256=digest(
                    (self.fixture["repo"] / BOOTSTRAP).read_bytes()
                ),
                release="0.7.0",
            )
        self.assertEqual(caught.exception.code, "TAG_MISMATCH")

        authenticated, receipt, output = self._build_for_receipt_validation("receipt-version-tamper")
        version_tampered = copy.deepcopy(receipt)
        version_tampered["distribution_version"] = "0.7.0"
        with self.assertRaises(ContractError) as caught:
            validate_candidate_receipt(version_tampered, authenticated, output_dir=output)
        self.assertEqual(caught.exception.code, "RECEIPT_VERSION")

        readme_070_bytes = (
            Path(__file__).resolve().parents[1] / DESCRIPTION_070_PATH
        ).read_bytes()
        readme_070_entry = {
            "path": DESCRIPTION_070_PATH,
            "sha256": digest(readme_070_bytes),
        }
        readme_tampered = copy.deepcopy(receipt)
        readme_tampered["readme"] = copy.deepcopy(readme_070_entry)
        for row in readme_tampered["rows"]:
            row["readme"] = copy.deepcopy(readme_070_entry)
        with self.assertRaises(ContractError) as caught:
            validate_candidate_receipt(readme_tampered, authenticated, output_dir=output)
        self.assertEqual(caught.exception.code, "DESCRIPTION_VERSION")

        cross_wired_auth = dataclasses.replace(
            authenticated, release=successor_release("0.7.0")
        )
        with self.assertRaises(ContractError) as caught:
            validate_candidate_receipt(receipt, cross_wired_auth, output_dir=output)
        self.assertEqual(caught.exception.code, "RECEIPT_VERSION")

        three_file_070_receipt = copy.deepcopy(receipt)
        three_file_070_receipt["application_version"] = "0.7.0"
        three_file_070_receipt["distribution_version"] = "0.7.0"
        with self.assertRaises(ContractError) as caught:
            validate_candidate_receipt(three_file_070_receipt, cross_wired_auth, output_dir=output)
        self.assertEqual(caught.exception.code, "RECEIPT_BINDING")

        tag_mismatch_receipt = copy.deepcopy(three_file_070_receipt)
        tag_mismatch_receipt["legal_files"] = {
            name: receipt["legal_files"][name] for name in ("LICENSE", "NOTICE")
        }
        commercial_license_070_receipt = copy.deepcopy(tag_mismatch_receipt)
        commercial_license_070_receipt["license"] = {
            "expression": "AGPL-3.0-or-later OR LicenseRef-Commercial",
            "files": tag_mismatch_receipt["legal_files"],
        }
        with self.assertRaises(ContractError) as caught:
            validate_candidate_receipt(
                commercial_license_070_receipt, cross_wired_auth, output_dir=output
            )
        self.assertEqual(caught.exception.code, "RECEIPT_BINDING")

        tag_mismatch_receipt["license"] = {
            "expression": "AGPL-3.0-or-later",
            "files": tag_mismatch_receipt["legal_files"],
        }
        with self.assertRaises(ContractError) as caught:
            validate_candidate_receipt(tag_mismatch_receipt, cross_wired_auth, output_dir=output)
        self.assertEqual(caught.exception.code, "TAG_MISMATCH")

        repo_070, evidence_070, _intent_070, binding_070 = _prepare_fixture(
            self.root / "generic-070-roundtrip"
        )
        gate1_auth = authenticate_gate1_capture(
            repo_070,
            evidence_070,
            release_binding=binding_070,
            approved_bootstrap_sha256=binding_070["expected"]["bootstrap_sha256"],
        )
        generic_070_auth = dataclasses.replace(
            gate1_auth,
            lineage_proof=authenticated.lineage_proof,
        )
        output_070 = self.root / "candidates-070"
        with patch(
            "rs9.wheel_nebular_successor.verify_forward_lineage_proof",
            return_value=gate1_auth.lineage_facts,
        ):
            receipt_070 = build_successor_candidates(
                generic_070_auth,
                output_070,
                rs9_source_commit=RS9_COMMIT,
                rs9_source_tree=RS9_TREE,
                deterministic_timestamp=(2026, 1, 1, 0, 0, 0),
            )
        self.assertEqual(receipt_070["application_version"], "0.7.0")
        self.assertEqual(receipt_070["distribution_version"], "0.7.0")
        self.assertEqual(receipt_070["license"]["expression"], "AGPL-3.0-or-later")
        self.assertEqual(set(receipt_070["legal_files"]), {"LICENSE", "NOTICE"})
        self.assertEqual(
            receipt_070["readme"],
            {
                "path": DESCRIPTION_070_PATH,
                "sha256": "19961e11514340f8a87d17688d938b606304f5b5734d7158ef97aad9580886ee",
            },
        )
        self.assertEqual(
            validate_candidate_receipt(receipt_070, generic_070_auth, output_dir=output_070),
            receipt_070,
        )
        tampered_070 = copy.deepcopy(receipt_070)
        row_070 = tampered_070["rows"][0]
        wheel_070_path = output_070 / row_070["system"] / row_070["wheel"]["filename"]
        self._rewrite_wheel(
            wheel_070_path,
            lambda entries, provenance: (
                entries.__setitem__(
                    next(name for name in entries if name.endswith(".dist-info/METADATA")),
                    entries[next(name for name in entries if name.endswith(".dist-info/METADATA"))].replace(
                        b"License-Expression: AGPL-3.0-or-later\n",
                        b"License-Expression: AGPL-3.0-or-later OR LicenseRef-Commercial\n",
                    ),
                ),
                provenance.__setitem__(
                    "metadata_sha256",
                    digest(entries[next(name for name in entries if name.endswith(".dist-info/METADATA"))]),
                ),
            ),
        )
        self._refresh_wheel_row(row_070, wheel_070_path)
        with self.assertRaises(ContractError) as caught:
            validate_candidate_receipt(tampered_070, generic_070_auth, output_dir=output_070)
        self.assertEqual(caught.exception.code, "RECEIPT_ARTIFACT")


if __name__ == "__main__":
    unittest.main()
