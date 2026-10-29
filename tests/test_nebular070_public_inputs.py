"""Focused contract tests for the generic Nebular public-input transport."""

from __future__ import annotations

import copy
import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from rs9.errors import ContractError
from rs9.nebular070_public_inputs import (
    _archive_members,
    REPOSITORY,
    SCHEMA,
    VERSION,
    materialize_public_inputs,
    validate_manifest,
)


class FakeClient:
    def __init__(self, bodies, fail_name=None):
        self.bodies = dict(bodies)
        self.fail_name = fail_name
        self.calls = []

    def get(self, url, *, request_class, limit, expected_size):
        self.calls.append((url, request_class, limit, expected_size))
        name = url.rsplit("/", 1)[-1]
        if name == self.fail_name:
            raise ContractError("FETCH_FAILED", "bounded fixture fetch failed")
        body = self.bodies[url]
        if len(body) != expected_size:
            raise ContractError("SIZE_MISMATCH", "bounded fixture size mismatch")
        return body


def _url(name):
    return f"https://github.com/{REPOSITORY}/releases/download/v{VERSION}/{name}"


def _tar(files, *, mode="w:gz"):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode=mode) as archive:
        for name, body, member_type, member_mode in files:
            member = tarfile.TarInfo(name)
            member.mode = member_mode
            if member_type == "file":
                member.size = len(body)
                archive.addfile(member, io.BytesIO(body))
            else:
                member.type = member_type
                member.linkname = body
                archive.addfile(member)
    return output.getvalue()


def _manifest(metadata, payloads):
    return {
        "schema": SCHEMA,
        "repository": REPOSITORY,
        "version": VERSION,
        "release_id": 426333162,
        "metadata": {
            "asset_id": 9001,
            "name": "qualification-inputs.tar.gz",
            "url": _url("qualification-inputs.tar.gz"),
            "bytes": len(metadata),
            "sha256": hashlib.sha256(metadata).hexdigest(),
        },
        "payloads": [
            {
                "asset_id": 9002 + index,
                "name": name,
                "url": _url(name),
                "path": path,
                "bytes": len(body),
                "sha256": hashlib.sha256(body).hexdigest(),
            }
            for index, (name, path, body) in enumerate(payloads)
        ],
    }


class PublicInputTransportTests(unittest.TestCase):
    def setUp(self):
        self.payloads = [
            ("theme-forge-nebular-fusion-v0.7.0-darwin-arm64.tar.gz", "raw-release/darwin-arm64/payload.tar.gz", b"darwin"),
            ("theme-forge-nebular-fusion-v0.7.0-aarch64-unknown-linux-gnu.tar.gz", "raw-release/linux-arm64-gnu/payload.tar.gz", b"arm"),
            ("theme-forge-nebular-fusion-v0.7.0-x86_64-unknown-linux-gnu.tar.gz", "raw-release/linux-x64-gnu/payload.tar.gz", b"x64"),
            ("theme-forge-nebular-fusion-v0.7.0.tgz", "evidence/public-release/npm/package.tgz", b"wrapper"),
        ]
        descriptor = {
            "schema": "rs9.tf-pypi-nebular070-qualification-inputs.v1",
            "project": "theme-forge-nebular-fusion",
            "version": VERSION,
            "evidence": {"source_root": "evidence/public-release", "npm": {"path": "npm/package.tgz"}},
            "raw_release": {"source_root": "raw-release", "targets": {
                "darwin-arm64": {"payload": self.payloads[0][1]},
                "linux-arm64-gnu": {"payload": self.payloads[1][1]},
                "linux-x64-gnu": {"payload": self.payloads[2][1]},
            }},
        }
        descriptor_bytes = json.dumps(descriptor, sort_keys=True).encode()
        self.metadata = _tar([("qualification-inputs.json", descriptor_bytes, "file", 0o644)])
        self.manifest = _manifest(self.metadata, self.payloads)
        self.bodies = {_url(self.manifest["metadata"]["name"]): self.metadata}
        self.bodies.update({_url(name): body for name, _path, body in self.payloads})

    def test_positive_materializes_descriptor_shared_paths_and_receipt(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp).resolve() / ".scratch" / "nebular070-inputs"
            output.parent.mkdir()
            receipt = materialize_public_inputs(self.manifest, output, client=FakeClient(self.bodies))
            self.assertEqual(receipt["release_id"], 426333162)
            self.assertEqual((output / "qualification-inputs.json").read_bytes(), json.dumps({
                "schema": "rs9.tf-pypi-nebular070-qualification-inputs.v1",
                "project": "theme-forge-nebular-fusion",
                "version": VERSION,
                "evidence": {"source_root": "evidence/public-release", "npm": {"path": "npm/package.tgz"}},
                "raw_release": {"source_root": "raw-release", "targets": {
                    "darwin-arm64": {"payload": self.payloads[0][1]},
                    "linux-arm64-gnu": {"payload": self.payloads[1][1]},
                    "linux-x64-gnu": {"payload": self.payloads[2][1]},
                }},
            }, sort_keys=True).encode())
            self.assertEqual((output / self.payloads[0][1]).read_bytes(), b"darwin")
            self.assertEqual((output / self.payloads[3][1]).read_bytes(), b"wrapper")
            self.assertEqual(json.loads((output / "fetch-receipt.json").read_text())["metadata"]["descriptor_sha256"],
                             hashlib.sha256((output / "qualification-inputs.json").read_bytes()).hexdigest())

    def test_manifest_closed_shape_and_exact_four_payload_roles(self):
        bad = copy.deepcopy(self.manifest)
        bad["unexpected"] = True
        with self.assertRaises(ContractError) as ctx:
            validate_manifest(bad)
        self.assertEqual(ctx.exception.code, "INVALID_MANIFEST")
        bad = copy.deepcopy(self.manifest)
        bad["payloads"] = bad["payloads"][:3]
        with self.assertRaises(ContractError) as ctx:
            validate_manifest(bad)
        self.assertEqual(ctx.exception.code, "PAYLOAD_SHAPE")

    def test_manifest_rejects_traversal_collision_and_wrong_asset_authority(self):
        for mutation, code in (
            (lambda row: row.update(path="source/raw/../escape.tar.gz"), "UNSAFE_PATH"),
            (lambda row: row.update(path=self.payloads[1][1]), "DUPLICATE_ASSET"),
            (lambda row: row.update(url="https://example.invalid/payload.tar.gz"), "ASSET_AUTHORITY"),
        ):
            bad = copy.deepcopy(self.manifest)
            mutation(bad["payloads"][0])
            with self.subTest(code=code), self.assertRaises(ContractError) as ctx:
                validate_manifest(bad)
            self.assertEqual(ctx.exception.code, code)

    def test_archive_rejects_links_and_executable_metadata(self):
        for member_type, mode, expected in ((tarfile.SYMTYPE, 0o644, "UNSAFE_MEMBER"), (tarfile.REGTYPE, 0o755, "UNSAFE_MODE")):
            descriptor = json.dumps({"schema": "rs9.tf-pypi-nebular070-qualification-inputs.v1", "project": "theme-forge-nebular-fusion", "version": VERSION,
                                     "evidence": {"source_root": "evidence/public-release"}, "raw_release": {"source_root": "raw-release"}}).encode()
            bad_body = b"executable" if member_type == tarfile.REGTYPE else "qualification-inputs.json"
            bad_kind = "file" if member_type == tarfile.REGTYPE else member_type
            bad_metadata = _tar([("qualification-inputs.json", descriptor, "file", 0o644), ("bad", bad_body, bad_kind, mode)])
            bad = _manifest(bad_metadata, self.payloads)
            with tempfile.TemporaryDirectory() as temp:
                output = Path(temp).resolve() / "out"
                with self.subTest(expected=expected), self.assertRaises(ContractError) as ctx:
                    materialize_public_inputs(bad, output, client=FakeClient({**self.bodies, _url(bad["metadata"]["name"]): bad_metadata}))
                self.assertEqual(ctx.exception.code, expected)
                self.assertFalse(output.exists())

    def test_digest_failure_cleans_only_owned_partial_root(self):
        bad = copy.deepcopy(self.manifest)
        bad["payloads"][2]["sha256"] = "0" * 64
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp).resolve() / "out"
            with self.assertRaises(ContractError) as ctx:
                materialize_public_inputs(bad, output, client=FakeClient(self.bodies))
            self.assertEqual(ctx.exception.code, "DIGEST_MISMATCH")
            self.assertFalse(output.exists())

    def test_metadata_descriptor_path_must_bind_payload_paths(self):
        descriptor = json.dumps({"schema": "rs9.tf-pypi-nebular070-qualification-inputs.v1", "project": "theme-forge-nebular-fusion", "version": VERSION,
                                 "evidence": {"source_root": "evidence/public-release"}, "raw_release": {"source_root": "raw-release"}}).encode()
        bad_metadata = _tar([("qualification-inputs.json", descriptor, "file", 0o644)])
        bad = _manifest(bad_metadata, self.payloads)
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp).resolve() / "out"
            with self.assertRaises(ContractError) as ctx:
                materialize_public_inputs(bad, output, client=FakeClient({**self.bodies, _url(bad["metadata"]["name"]): bad_metadata}))
            self.assertEqual(ctx.exception.code, "DESCRIPTOR_JOIN")
            self.assertFalse(output.exists())

    def test_gzip_expansion_is_bounded_before_tar_parser(self):
        compressed_bomb = gzip.compress(b"0" * 2048)
        with patch("rs9.nebular070_public_inputs.MAX_TAR_BYTES", 1024):
            with self.assertRaises(ContractError) as ctx:
                _archive_members(compressed_bomb)
        self.assertEqual(ctx.exception.code, "METADATA_LIMIT")

    def test_large_pax_extension_is_rejected_by_expanded_tar_bound(self):
        body = json.dumps({"schema": "rs9.tf-pypi-nebular070-qualification-inputs.v1", "project": "theme-forge-nebular-fusion", "version": VERSION,
                           "evidence": {"source_root": "evidence/public-release"}, "raw_release": {"source_root": "raw-release"}}).encode()
        expanded = io.BytesIO()
        with tarfile.open(fileobj=expanded, mode="w:") as archive:
            member = tarfile.TarInfo("qualification-inputs.json")
            member.mode = 0o644
            member.size = len(body)
            member.pax_headers = {"comment": "x" * 2048}
            archive.addfile(member, io.BytesIO(body))
        with patch("rs9.nebular070_public_inputs.MAX_TAR_BYTES", 1024):
            with self.assertRaises(ContractError) as ctx:
                _archive_members(gzip.compress(expanded.getvalue()))
        self.assertEqual(ctx.exception.code, "METADATA_LIMIT")

    def test_nonzero_directory_body_is_rejected(self):
        expanded = io.BytesIO()
        with tarfile.open(fileobj=expanded, mode="w:") as archive:
            member = tarfile.TarInfo("metadata-dir")
            member.mode = 0o755
            member.type = tarfile.DIRTYPE
            member.size = 1
            archive.addfile(member, io.BytesIO(b"x"))
        with self.assertRaises(ContractError) as ctx:
            _archive_members(gzip.compress(expanded.getvalue()))
        self.assertEqual(ctx.exception.code, "UNSAFE_MEMBER")


if __name__ == "__main__":
    unittest.main()
    _archive_members,
