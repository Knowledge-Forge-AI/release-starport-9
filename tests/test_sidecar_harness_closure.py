"""Authentic module closure and import gate, independent of payload verification."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from rs9.errors import ContractError
from rs9.hosted_smoke import (VERIFIER_SUPPORT, prepare_smoke, tagged_files,
    verifier_import_preflight, verify_nebular_runtime, expected_runtime_members)
from rs9.release_core import digest
from rs9.scratch import canonical


def entry(path, data, mode="100644"):
    return {"path": path, "type": "blob", "mode": mode, "size": len(data),
            "sha": hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()}


class ClosureTests(unittest.TestCase):
    def test_complete_tools_and_reviewed_support_are_blob_authenticated_and_recorded(self):
        data = {"tools/sidecar-common.mjs": b"export function verifyDistribution(){}",
                "tools/sidecar-verify.mjs": b"export function verifySidecar(){}",
                "tools/native-rc-smoke.mjs": b"export const smoke=true;",
                "tools/sibling.mjs": b"export const sibling=true;",
                "package.json": b'{"version":"0.6.1"}',
                "docs/examples/v0.4/brand-system/core-minimal/project.toml": b"fixture=true"}
        tag = next(iter(VERIFIER_SUPPORT))
        capture = SimpleNamespace(record={"repository": {"full_name": "fixture/nebular"}, "tag": {"commit": tag}})
        fixture = SimpleNamespace(record={"repository": {"full_name": "fixture/burst"}, "tag": {"commit": "a" * 40}})
        client = SimpleNamespace(get=lambda url, **kw: data[url.split("/", 6)[-1]])
        tree = {"tree": [entry(p, v) for p, v in data.items()]}
        with tempfile.TemporaryDirectory() as tmp, patch("rs9.hosted_smoke.authenticated_record_hash"), \
                patch("rs9.hosted_smoke.authenticated_tree", return_value=tree):
            result = prepare_smoke(capture, [(fixture, {"project": {"id": "theme-forge-stellar-burst"}}, {})],
                                   client, Path(tmp).resolve() / "smoke-wheel", label="wheel")
            rows = json.loads((result["scratch"] / "source-bindings.json").read_bytes())
            self.assertEqual({r["path"] for r in rows}, set(data))
            roles = {r["path"]: r["role"] for r in rows}
            self.assertEqual(roles["package.json"], "verifier-support")
            self.assertEqual(roles["tools/native-rc-smoke.mjs"], "application-smoke")
            for row in rows:
                self.assertEqual(row["blob"], entry(row["path"], data[row["path"]])["sha"])
                self.assertEqual(row["sha256"], digest(data[row["path"]]))
                self.assertEqual(row["tag_commit"], fixture.record["tag"]["commit"] if row["role"] == "fixture" else tag)

    def test_changed_blob_missing_support_and_nonregular_support_fail_closed(self):
        capture = SimpleNamespace(record={"repository": {"full_name": "fixture/nebular"}, "tag": {"commit": "a" * 40}})
        with tempfile.TemporaryDirectory() as tmp, patch("rs9.hosted_smoke.authenticated_record_hash"):
            out = Path(tmp).resolve()
            for entries, body, code in [([entry("package.json", b"bound")], b"changed", "SMOKE_SOURCE"),
                    ([], b"", "SIDECAR_HARNESS_IMPORT"),
                    ([entry("package.json", b"bound", "120000")], b"bound", "SMOKE_SOURCE")]:
                with self.subTest(code=code), patch("rs9.hosted_smoke.authenticated_tree", return_value={"tree": entries}):
                    with self.assertRaises(ContractError) as caught:
                        tagged_files(capture, SimpleNamespace(get=lambda *a, **k: body), out, (), paths=("package.json",))
                    self.assertEqual(caught.exception.code, code)
            with self.assertRaises(ContractError) as caught:
                prepare_smoke(capture, [], None, out / "unknown")
            self.assertEqual(caught.exception.details["reason"], "unknown-tag-closure")

    def test_transported_members_are_bound_before_runtime_evidence(self):
        members = [{"path": "app", "type": "directory", "mode": 0o755}]
        prepared = {"expected_members": members, "manifest_sha256": digest(canonical(members))}
        self.assertEqual(expected_runtime_members(prepared, "x86_64-linux"), members)
        prepared["expected_members"] = []
        with self.assertRaises(ContractError) as caught:
            expected_runtime_members(prepared, "x86_64-linux")
        self.assertEqual(caught.exception.code, "SIDECAR_MANIFEST_BINDING")


@unittest.skipUnless(shutil.which("node"), "Node required for ESM import gate")
class ImportTests(unittest.TestCase):
    def setup_source(self, work):
        source, scratch = work / "source", work / "smoke"
        tools = source / "tools"
        tools.mkdir(parents=True)
        scratch.mkdir()
        (tools / "sidecar-common.mjs").write_text("import {v} from './platform-targets.mjs'; export function verifyDistribution(){}")
        (tools / "platform-targets.mjs").write_text("import {readFileSync} from 'node:fs'; export const v=JSON.parse(readFileSync(new URL('../package.json',import.meta.url))).version;")
        (tools / "sidecar-verify.mjs").write_text("export {verifyDistribution as verifySidecar} from './sidecar-common.mjs';")
        (tools / "native-rc-smoke.mjs").write_text("export const smoke=true;")
        return {"source": source, "tools": tools, "scratch": scratch, "records": []}

    def test_missing_support_preflight_precedes_runtime_and_preserves_safe_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp).resolve()
            prepared = self.setup_source(work)
            with patch("rs9.hosted_smoke.runtime_evidence") as runtime:
                with self.assertRaises(ContractError) as caught:
                    verify_nebular_runtime(work / "missing-runtime", prepared, "x86_64-linux")
            runtime.assert_not_called()
            self.assertEqual(caught.exception.code, "SIDECAR_HARNESS_IMPORT")
            self.assertEqual(caught.exception.details["missing_path"], "package.json")
            self.assertEqual(caught.exception.details["code"], "ENOENT")
            diagnostic = json.loads((work / "diagnostics/sidecar-verifier.json").read_bytes())
            self.assertEqual(diagnostic["verifier"]["phase"], "import")
            self.assertNotIn(str(work), json.dumps(diagnostic))
            (prepared["source"] / "package.json").write_text('{"version":"0.6.1"}')
            self.assertEqual(verifier_import_preflight(prepared, "x86_64-linux")["status"], "pass")
            (prepared["tools"] / "platform-targets.mjs").unlink()
            with self.assertRaises(ContractError) as caught:
                verifier_import_preflight(prepared, "x86_64-linux")
            self.assertEqual(caught.exception.details["code"], "ERR_MODULE_NOT_FOUND")

    def test_source_readback_rejects_changed_module_before_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp).resolve()
            prepared = self.setup_source(work)
            name = "tools/sidecar-common.mjs"
            body = (prepared["source"] / name).read_bytes()
            prepared["records"] = [{"path": name, "blob": entry(name, body)["sha"], "sha256": digest(body), "size": len(body)}]
            (prepared["source"] / name).write_bytes(b"changed")
            with patch("rs9.hosted_smoke.subprocess.run") as run:
                with self.assertRaises(ContractError) as caught:
                    verifier_import_preflight(prepared, "x86_64-linux")
            run.assert_not_called()
            self.assertEqual(caught.exception.details["substage"], "verifier-source-readback")

    def test_import_time_spawn_failure_stops_without_fabricating_git_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp).resolve()
            prepared = self.setup_source(work)
            (prepared["tools"] / "sidecar-common.mjs").write_text(
                "import {spawnSync} from 'node:child_process'; const r=spawnSync('rs9-unavailable-import-probe'); throw r.error;")
            with self.assertRaises(ContractError) as caught:
                verifier_import_preflight(prepared, "x86_64-linux")
            self.assertEqual(caught.exception.code, "SIDECAR_HARNESS_IMPORT")
            self.assertEqual(caught.exception.details["diagnostic_token"], "spawn-unavailable")
            self.assertFalse((prepared["source"] / ".git").exists())
