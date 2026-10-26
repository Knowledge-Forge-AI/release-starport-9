"""Connected fixture-only Gate1 candidate/receipt roundtrip evidence.

The fixture is deliberately synthetic: it uses the existing authenticated
release-capture machinery against temporary bytes, not a real 0.7.0 release.
No fixture wheel escapes the temporary directory.
"""
from __future__ import annotations

import base64
import copy
import csv
import hashlib
import io
import json
import plistlib
import struct
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from typing import Callable

from rs9.bootstrap import configuration_inventory
from rs9.errors import ContractError
from rs9.profiles import selection_for_intent
from rs9.records import record_sha256
from rs9.release_core import authenticate_release, digest
from rs9.scratch import canonical
from rs9.wheel import _record_digest
from rs9.tf_pypi_nebular_successor import (
    authenticate_gate1_capture,
    build_gate1_candidates,
    validate_gate1_receipt,
    write_gate1_receipt,
)
from rs9.operator import release_bindings, validate_release_binding
from tests.shadow_fixtures import fixture_evidence


REPOSITORY = "Knowledge-Forge-AI/theme-forge-nebular-fusion"
COMMIT = "a" * 40
TREE = "b" * 40
LICENSE = b"Synthetic AGPL-3.0-or-later license text for fixture-only evidence.\n"
NOTICE = b"Synthetic AGPL-3.0-or-later notice for fixture-only evidence.\n"
COMMERCIAL = b"Synthetic AGPL-3.0-or-later commercial companion for fixture-only evidence.\n"
PACKAGE_NAME = "@knowledge-forge-ai/theme-forge-nebular-fusion"


def _blob_sha(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def _macho_13() -> bytes:
    minimum = (13 << 16) | (0 << 8) | 0
    header = struct.pack("<IIIIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 1, 24, 0, 0)
    command = struct.pack("<IIIIII", 0x32, 24, 1, minimum, minimum, 0)
    return header + command


def _tar(entries: list[tuple[str, bytes, int, int]]) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for path, data, mode, kind in entries:
            info = tarfile.TarInfo(path)
            info.mode = mode
            info.type = kind
            info.size = len(data) if kind == tarfile.REGTYPE else 0
            archive.addfile(info, io.BytesIO(data) if kind == tarfile.REGTYPE else None)
    return output.getvalue()


def _darwin_payload() -> bytes:
    root = "Theme Forge Nebular Fusion.app"
    plist = plistlib.dumps({"LSMinimumSystemVersion": "13.0", "CFBundleIdentifier": "ai.fixture.nebular"})
    entries = [
        (root, b"", 0o755, tarfile.DIRTYPE),
        (f"{root}/Contents", b"", 0o755, tarfile.DIRTYPE),
        (f"{root}/Contents/Info.plist", plist, 0o644, tarfile.REGTYPE),
        (f"{root}/Contents/MacOS", b"", 0o755, tarfile.DIRTYPE),
        (f"{root}/Contents/MacOS/tfsb-studio-service", _macho_13(), 0o755, tarfile.REGTYPE),
        (f"{root}/Contents/MacOS/theme-forge-nebular-fusion", _macho_13(), 0o755, tarfile.REGTYPE),
        (f"{root}/Contents/Resources", b"", 0o755, tarfile.DIRTYPE),
        (f"{root}/Contents/Resources/bin", b"", 0o755, tarfile.DIRTYPE),
        (f"{root}/Contents/Resources/bin/tfnf", b"#!/bin/sh\nexit 0\n", 0o755, tarfile.REGTYPE),
        (f"{root}/Contents/Resources/sidecar-payload", b"", 0o755, tarfile.DIRTYPE),
        (f"{root}/Contents/Resources/sidecar-payload/native-addon.node", _macho_13(), 0o644, tarfile.REGTYPE),
        (f"{root}/Contents/Resources/LICENSE", LICENSE, 0o644, tarfile.REGTYPE),
        (f"{root}/Contents/Resources/NOTICE", NOTICE, 0o644, tarfile.REGTYPE),
        (f"{root}/Contents/Resources/COMMERCIAL-LICENSE.md", COMMERCIAL, 0o644, tarfile.REGTYPE),
    ]
    return _tar(entries)


def _linux_payload() -> bytes:
    root = "theme-forge-nebular-fusion"
    entries = [
        (root, b"", 0o755, tarfile.DIRTYPE),
        (f"{root}/bin", b"", 0o755, tarfile.DIRTYPE),
        (f"{root}/bin/tfnf", b"#!/bin/sh\nexit 0\n", 0o755, tarfile.REGTYPE),
        (f"{root}/bin/theme-forge-nebular-fusion", b"#!/bin/sh\nexit 0\n", 0o755, tarfile.REGTYPE),
        (f"{root}/LICENSE", LICENSE, 0o644, tarfile.REGTYPE),
        (f"{root}/NOTICE", NOTICE, 0o644, tarfile.REGTYPE),
        (f"{root}/COMMERCIAL-LICENSE.md", COMMERCIAL, 0o644, tarfile.REGTYPE),
    ]
    return _tar(entries)


def _npm_wrapper() -> bytes:
    package_json = canonical({"name": PACKAGE_NAME, "version": "0.7.0", "license": "AGPL-3.0-or-later"})
    return _tar([("package", b"", 0o755, tarfile.DIRTYPE), ("package/package.json", package_json, 0o644, tarfile.REGTYPE)])


def _replace_version(value: str) -> str:
    return value.replace("v0.6.1", "v0.7.0").replace("-0.6.1", "-0.7.0")


def _rewrite_wheel(wheel_path: Path, mutate: Callable[[dict[str, bytes]], None]) -> bytes:
    """Rewrite one fixture wheel and refresh its authenticated RECORD bytes."""
    with zipfile.ZipFile(wheel_path, "r") as archive:
        entries = {name: archive.read(name) for name in archive.namelist()}
    mutate(entries)
    record_name = next(name for name in entries if name.endswith("/RECORD"))
    records = io.StringIO(newline="")
    writer = csv.writer(records, lineterminator="\n")
    for name in sorted(entries):
        if name == record_name:
            writer.writerow((name, "", ""))
        else:
            writer.writerow((name, _record_digest(entries[name]), len(entries[name])))
    entries[record_name] = records.getvalue().encode("utf-8")
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in sorted(entries):
            archive.writestr(name, entries[name])
    wheel_path.write_bytes(output.getvalue())
    return output.getvalue()


def _wheel_entries(wheel_path: Path) -> list[str]:
    with zipfile.ZipFile(wheel_path, "r") as archive:
        return archive.namelist()


def _rewrite_info_plist(payload: bytes, version: str) -> bytes:
    """Change only the fixture bundle Info.plist while preserving tar members."""
    source = io.BytesIO(payload)
    output = io.BytesIO()
    with tarfile.open(fileobj=source, mode="r:gz") as source_archive, tarfile.open(
        fileobj=output, mode="w:gz"
    ) as target_archive:
        for member in source_archive:
            item = copy.copy(member)
            data = source_archive.extractfile(member).read() if member.isfile() else b""
            if member.name.endswith("/Contents/Info.plist"):
                data = plistlib.dumps({"LSMinimumSystemVersion": version, "CFBundleIdentifier": "ai.fixture.nebular"})
                item.size = len(data)
            target_archive.addfile(item, io.BytesIO(data) if item.isfile() else None)
    return output.getvalue()


def _prepare_fixture(root: Path) -> tuple[Path, Path, dict, dict]:
    evidence = root / "evidence"
    intent = fixture_evidence(evidence)
    intent = copy.deepcopy(intent)
    intent["version"] = "0.7.0"
    intent["tag"] = "v0.7.0"
    intent["release"]["tag"] = "v0.7.0"
    intent["license"]["files"] = ["LICENSE", "NOTICE", "COMMERCIAL-LICENSE.md"]
    intent["checks"][0]["expect-stdout-contains"] = "theme-forge-nebular-fusion 0.7.0"
    for asset in intent["assets"]:
        asset["name"] = _replace_version(asset["name"])
    for row in intent["release"]["evidence"]["assets"]:
        row["name"] = _replace_version(row["name"])

    source_values = {
        "LICENSE": LICENSE,
        "NOTICE": NOTICE,
        "COMMERCIAL-LICENSE.md": COMMERCIAL,
        "package.json": canonical({"name": PACKAGE_NAME, "version": "0.7.0", "license": "AGPL-3.0-or-later"}),
        "src-tauri/Cargo.toml": b'[package]\nname = "theme-forge-nebular-fusion"\nlicense = "AGPL-3.0-or-later"\n',
        "src-tauri/tauri.conf.json": canonical({"productName": "Theme Forge Nebular Fusion"}),
    }
    source_dir = evidence / "source"
    source_values["src-tauri/icons/icon.png"] = (source_dir / "src-tauri/icons/icon.png").read_bytes()
    for path, data in source_values.items():
        target = source_dir / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)

    wrapper = _npm_wrapper()
    payload_by_id = {
        "darwin-arm64": _darwin_payload(),
        "linux-arm64": _linux_payload(),
        "linux-x64": _linux_payload(),
    }
    raw_assets = {asset["name"]: payload_by_id[asset["id"]] for asset in intent["assets"]}
    wrapper_name = next(row["name"] for row in intent["release"]["evidence"]["assets"] if row["role"] == "npm-wrapper")
    raw_assets[wrapper_name] = wrapper
    raw_assets["PROVENANCE.json"] = canonical({
        "release": {
            "repository": REPOSITORY,
            "tag": "v0.7.0",
            "tagTarget": COMMIT,
            "mergedMainCommit": COMMIT,
            "mergedMainTree": TREE,
            "tagCommit": COMMIT,
            "tagTree": TREE,
        }
    })
    raw_assets["nebular.spdx.json"] = canonical({"packages": []})
    raw_assets["THIRD_PARTY_NOTICES.md"] = b"Synthetic third-party notices.\n"
    raw_assets["SHA256SUMS"] = "".join(
        digest(data) + "  " + name + "\n" for name, data in sorted(raw_assets.items())
    ).encode()
    assets_dir = evidence / "assets"
    for path in assets_dir.iterdir():
        if path.is_file():
            path.unlink()
    for name, data in raw_assets.items():
        (assets_dir / name).write_bytes(data)

    tree_entries = [
        {"path": path, "type": "blob", "mode": "100644", "sha": _blob_sha(data)}
        for path, data in sorted(source_values.items())
    ]
    repo_api = {"id": 123, "full_name": REPOSITORY}
    ref_api = {"ref": "refs/tags/v0.7.0", "object": {"type": "commit", "sha": COMMIT}}
    commit_api = {"sha": COMMIT, "tree": {"sha": TREE}}
    tree_api = {"sha": TREE, "truncated": False, "tree": tree_entries}
    release_rows = []
    for index, (name, data) in enumerate(sorted(raw_assets.items()), start=1):
        release_rows.append({"id": index, "name": name, "size": len(data), "digest": "sha256:" + digest(data), "state": "uploaded"})
    release_api = {
        "id": 456,
        "tag_name": "v0.7.0",
        "target_commitish": COMMIT,
        "draft": False,
        "prerelease": False,
        "immutable": True,
        "created_at": "2026-10-01T00:00:00Z",
        "published_at": "2026-10-01T00:00:00Z",
        "assets": release_rows,
    }
    api_dir = evidence / "api"
    for name, value in {
        "repository": repo_api, "ref": ref_api, "tags": [], "commit": commit_api,
        "tree": tree_api, "release": release_api,
    }.items():
        (api_dir / (name + ".json")).write_bytes(canonical(value))
    npm_dir = evidence / "npm"
    (npm_dir / "package.tgz").write_bytes(wrapper)
    (npm_dir / "metadata.json").write_bytes(canonical({
        "name": PACKAGE_NAME,
        "version": "0.7.0",
        "license": "AGPL-3.0-or-later",
        "dist": {
            "integrity": "sha512-" + base64.b64encode(hashlib.sha512(wrapper).digest()).decode(),
            "tarball": "https://registry.npmjs.org/@knowledge-forge-ai%2Ftheme-forge-nebular-fusion/-/theme-forge-nebular-fusion-0.7.0.tgz",
        },
    }))

    capture = authenticate_release(selection_for_intent(intent), evidence)
    expectations = {
        "projects": [{
            "repository": REPOSITORY,
            "repository_id": 123,
            "tag": "v0.7.0",
            "release_id": 456,
            "commit": COMMIT,
            "tree": TREE,
            "immutable": True,
            "published_at": "2026-10-01T00:00:00Z",
            "contains_rs9": False,
            "truncated": False,
            "assets": [
                {"name": row["name"], "size": row["size"], "sha256": row["sha256"], "id": row["github_asset_id"]}
                for row in capture.record["assets"] if row["role"] == "payload"
            ],
        }]
    }
    repo_root = root / "repository"
    config_dir = repo_root / "bootstrap/pre-rs9/theme-forge-nebular-0.7.0/theme-forge-nebular-fusion"
    config_dir.mkdir(parents=True)
    (config_dir / "intent.json").write_bytes(canonical(intent))
    manifest = {
        "schema": "rs9.bootstrap-tenant-manifest.v1alpha1",
        "bootstrap-pre-rs9": True,
        "release-contains-rs9": False,
        "scope": "exact-generation",
        "future-releases": "forbidden",
        "projects": [{
            "repository": REPOSITORY,
            "repository_id": 123,
            "tag": "v0.7.0",
            "version": "0.7.0",
            "release_id": 456,
            "tag_commit": COMMIT,
            "tag_tree": TREE,
            "configuration": "theme-forge-nebular-fusion",
            "config_sha256": record_sha256(configuration_inventory(config_dir)),
            "license_authority": {
                "expression": "AGPL-3.0-or-later",
                "basis": "fixture-only-authenticated-tagged-repository",
                "files": ["LICENSE", "NOTICE", "COMMERCIAL-LICENSE.md", "package.json"],
            },
        }],
    }
    manifest_path = config_dir.parent / "manifest.json"
    manifest_path.write_bytes(canonical(manifest))
    expectations_path = repo_root / "operators/tf-pypi/nebular-0.7.0/expectations.json"
    expectations_path.parent.mkdir(parents=True)
    expectations_path.write_bytes(canonical(expectations))
    binding = release_bindings("0.7.0")
    binding.update({
        "status": "ready",
        "expected": {
            "repository_id": 123,
            "release_id": 456,
            "tag_commit": COMMIT,
            "tag_tree": TREE,
            "bootstrap_sha256": digest(manifest_path.read_bytes()),
            "expectations_sha256": digest(expectations_path.read_bytes()),
        },
    })
    validate_release_binding(binding)
    return repo_root, evidence, intent, binding


class Nebular070Gate1RoundtripTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(
            prefix="rs9-nebular070-gate1-roundtrip-",
            dir=str(Path(__file__).resolve().parents[1]),
        )
        self.root = Path(self.tmp.name)
        self.repository, self.evidence, self.intent, self.binding = _prepare_fixture(self.root)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _build_fixture_candidates(self):
        authenticated = authenticate_gate1_capture(
            self.repository,
            self.evidence,
            release_binding=self.binding,
            approved_bootstrap_sha256=self.binding["expected"]["bootstrap_sha256"],
        )
        output = self.root / "gate1-candidates"
        receipt = build_gate1_candidates(
            authenticated,
            output,
            rs9_source_commit="c" * 40,
            rs9_source_tree="d" * 40,
            deterministic_timestamp=(2026, 10, 1, 0, 0, 0),
        )
        return authenticated, output, receipt

    def test_fixture_capture_build_validate_write_roundtrip_three_targets(self) -> None:
        authenticated = authenticate_gate1_capture(
            self.repository,
            self.evidence,
            release_binding=self.binding,
            approved_bootstrap_sha256=self.binding["expected"]["bootstrap_sha256"],
        )
        output = self.root / "gate1-candidates"
        receipt = build_gate1_candidates(
            authenticated,
            output,
            rs9_source_commit="c" * 40,
            rs9_source_tree="d" * 40,
            deterministic_timestamp=(2026, 10, 1, 0, 0, 0),
        )
        self.assertEqual([row["system"] for row in receipt["rows"]], ["aarch64-darwin", "aarch64-linux", "x86_64-linux"])
        self.assertEqual(receipt["schema"], "rs9.nebular-successor-candidate.v2alpha1")
        self.assertEqual(receipt["license"]["expression"], "AGPL-3.0-or-later")
        self.assertEqual(set(receipt["legal_files"]), {"LICENSE", "NOTICE", "COMMERCIAL-LICENSE.md"})
        self.assertFalse(receipt["flags"]["publication_admitted"])
        self.assertFalse(receipt["flags"]["manylinux_proven"])
        self.assertEqual(receipt["qualification_rs9_source"], {"status": "not-run", "reason": "gate1-only"})
        self.assertEqual(receipt["direct_lineage"]["tag_commit"], COMMIT)
        self.assertEqual(receipt["direct_lineage"]["provenance_source_kind"], "asset")
        self.assertEqual(receipt["profile"]["darwin_floor"], {"major": 13, "minor": 0})
        self.assertFalse(receipt["profile"]["linux_runtime_policy"]["manylinux_claim"])
        floor = receipt["darwin_floor_evidence"]
        self.assertEqual({row["role"] for row in floor["macho"]}, {"macos-executable", "embedded-native"})
        self.assertIn({"path": "Theme Forge Nebular Fusion.app/Contents/Resources/bin/tfnf", "role": "script"}, floor["scripts"])
        self.assertEqual(validate_gate1_receipt(receipt, authenticated, output_dir=output), receipt)
        receipt_path = self.root / "gate1-receipt.json"
        write_gate1_receipt(receipt_path, receipt, authenticated=authenticated, output_dir=output)
        persisted = json.loads(receipt_path.read_bytes())
        self.assertEqual(persisted, receipt)
        self.assertEqual(validate_gate1_receipt(persisted, authenticated, output_dir=output), receipt)
        self.assertEqual(len(list(output.glob("*/*.whl"))), 3)

    def test_fixture_negative_cross_binding_fails_closed(self) -> None:
        authenticated = authenticate_gate1_capture(
            self.repository,
            self.evidence,
            release_binding=self.binding,
            approved_bootstrap_sha256=self.binding["expected"]["bootstrap_sha256"],
        )
        output = self.root / "gate1-candidates"
        receipt = build_gate1_candidates(
            authenticated,
            output,
            rs9_source_commit="c" * 40,
            rs9_source_tree="d" * 40,
            deterministic_timestamp=(2026, 10, 1, 0, 0, 0),
        )
        tampered = copy.deepcopy(receipt)
        tampered["rows"][0]["readme"]["sha256"] = "e" * 64
        with self.assertRaises(ContractError) as ctx:
            validate_gate1_receipt(tampered, authenticated, output_dir=output)
        self.assertIn("RECEIPT_", str(ctx.exception))

    def test_fixture_negative_expectations_digest_mismatch_fails_before_parse(self) -> None:
        tampered_binding = copy.deepcopy(self.binding)
        tampered_binding["expected"]["expectations_sha256"] = "e" * 64
        with self.assertRaises(ContractError) as ctx:
            authenticate_gate1_capture(
                self.repository,
                self.evidence,
                release_binding=tampered_binding,
                approved_bootstrap_sha256=tampered_binding["expected"]["bootstrap_sha256"],
            )
        self.assertIn("EXPECTATIONS_APPROVAL", str(ctx.exception))

    def test_fixture_negative_forged_darwin_floor_evidence_fails_closed(self) -> None:
        authenticated, output, receipt = self._build_fixture_candidates()
        row = receipt["rows"][0]
        wheel_path = output / "aarch64-darwin" / row["wheel"]["filename"]
        provenance_member = next(name for name in _wheel_entries(wheel_path) if name.endswith("/_rs9/provenance.json"))

        def forge_floor(entries):
            provenance = json.loads(entries[provenance_member])
            provenance["darwin_floor_evidence"]["macho"][0]["path"] = "forged/path"
            entries[provenance_member] = canonical(provenance)

        raw = _rewrite_wheel(wheel_path, forge_floor)
        row["wheel"]["sha256"] = digest(raw)
        row["wheel"]["size"] = len(raw)
        with self.assertRaises(ContractError) as ctx:
            validate_gate1_receipt(receipt, authenticated, output_dir=output)
        self.assertIn("RECEIPT_ARTIFACT", str(ctx.exception))

    def test_fixture_negative_payload_info_plist_mismatch_fails_closed(self) -> None:
        authenticated, output, receipt = self._build_fixture_candidates()
        row = receipt["rows"][0]
        wheel_path = output / "aarch64-darwin" / row["wheel"]["filename"]
        payload_member = next(
            name for name in _wheel_entries(wheel_path)
            if name.endswith("/payload/" + row["payload_archive_name"])
        )

        def forge_payload(entries):
            entries[payload_member] = _rewrite_info_plist(entries[payload_member], "12.0")

        raw = _rewrite_wheel(wheel_path, forge_payload)
        row["wheel"]["sha256"] = digest(raw)
        row["wheel"]["size"] = len(raw)
        with self.assertRaises(ContractError) as ctx:
            validate_gate1_receipt(receipt, authenticated, output_dir=output)
        self.assertIn("RECEIPT_ARTIFACT", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
