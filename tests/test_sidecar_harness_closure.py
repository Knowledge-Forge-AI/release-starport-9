"""Authentic module closure and import gate, independent of payload verification."""
import hashlib
import copy
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from rs9.errors import ContractError
from rs9.hosted_smoke import (
    VERIFIER_SUPPORT,
    CURRENT070_COMMIT,
    VERIFIER_SUPPORT_TREES,
    expected_runtime_members,
    prepare_smoke,
    tagged_files,
    verifier_import_preflight,
    verify_nebular_runtime,
)
from rs9.release_core import digest
from rs9.scratch import canonical
from rs9 import hosted_smoke as smoke


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
        capture = SimpleNamespace(record={"repository": {"full_name": "fixture/nebular"},
                                          "tag": {"commit": tag, "tree": VERIFIER_SUPPORT_TREES[tag]}})
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

    def test_current_and_historical_support_require_the_reviewed_tree(self):
        data = {"tools/sidecar-common.mjs": b"export function verifyDistribution(){}",
                "tools/sidecar-verify.mjs": b"export function verifySidecar(){}",
                "tools/native-rc-smoke.mjs": b"export const smoke=true;",
                "package.json": b'{"version":"0.6.1"}',
                "docs/examples/v0.4/brand-system/core-minimal/project.toml": b"fixture=true"}
        fixture = SimpleNamespace(record={"repository": {"full_name": "fixture/burst"},
                                          "tag": {"commit": "a" * 40}})
        client = SimpleNamespace(get=lambda url, **kw: data[url.split("/", 6)[-1]])
        tree_rows = {"tree": [entry(path, value) for path, value in data.items()]}
        for commit, expected_tree in VERIFIER_SUPPORT_TREES.items():
            if commit in (CURRENT070_COMMIT, smoke.CURRENT071_COMMIT):
                continue  # Current 0.7 uses the separately authenticated closure tests below.
            with self.subTest(commit=commit):
                capture = SimpleNamespace(record={"repository": {"full_name": "fixture/nebular"},
                                                  "tag": {"commit": commit, "tree": expected_tree}})
                with tempfile.TemporaryDirectory() as tmp, patch("rs9.hosted_smoke.authenticated_record_hash"), \
                        patch("rs9.hosted_smoke.authenticated_tree", return_value=tree_rows):
                    result = prepare_smoke(capture, [(fixture, {"project": {"id": "theme-forge-stellar-burst"}}, {})],
                                           client, Path(tmp) / "smoke")
                    rows = json.loads((result["scratch"] / "source-bindings.json").read_bytes())
                    support_rows = [row for row in rows if row["role"] == "verifier-support"]
                    self.assertEqual([row["path"] for row in support_rows], ["package.json"])
                    self.assertEqual(support_rows[0]["tag_commit"], commit)

    def test_known_commit_with_wrong_tree_and_tampered_support_fail_closed(self):
        for commit, expected_tree in VERIFIER_SUPPORT_TREES.items():
            if commit in (CURRENT070_COMMIT, smoke.CURRENT071_COMMIT):
                continue  # Current 0.7 uses the separately authenticated closure tests below.
            with self.subTest(commit=commit), tempfile.TemporaryDirectory() as tmp:
                capture = SimpleNamespace(record={"repository": {"full_name": "fixture/nebular"},
                                                  "tag": {"commit": commit, "tree": "0" * 40}})
                with self.assertRaises(ContractError) as caught:
                    prepare_smoke(capture, [], None, Path(tmp) / "wrong-tree")
                self.assertEqual(caught.exception.details["reason"], "tag-tree-mismatch")

                data = {"tools/sidecar-common.mjs": b"export function verifyDistribution(){}",
                        "tools/sidecar-verify.mjs": b"export function verifySidecar(){}",
                        "tools/native-rc-smoke.mjs": b"export const smoke=true;",
                        "package.json": b'{"version":"forged"}'}
                fixture = SimpleNamespace(record={"repository": {"full_name": "fixture/burst"},
                                                  "tag": {"commit": "a" * 40}})
                tree_data = {"tools/sidecar-common.mjs": b"export function verifyDistribution(){}",
                             "tools/sidecar-verify.mjs": b"export function verifySidecar(){}",
                             "tools/native-rc-smoke.mjs": b"export const smoke=true;",
                             "package.json": b'{"version":"0.6.1"}',
                             "docs/examples/v0.4/brand-system/core-minimal/project.toml": b"fixture=true"}
                capture.record["tag"]["tree"] = expected_tree
                client = SimpleNamespace(get=lambda url, **kw: data[url.split("/", 6)[-1]])
                tree = {"tree": [entry(path, value) for path, value in tree_data.items()]}
                with patch("rs9.hosted_smoke.authenticated_record_hash"), \
                        patch("rs9.hosted_smoke.authenticated_tree", return_value=tree):
                    with self.assertRaises(ContractError) as caught:
                        prepare_smoke(capture, [(fixture, {"project": {"id": "theme-forge-stellar-burst"}}, {})],
                                      client, Path(tmp) / "tampered")
                self.assertEqual(caught.exception.code, "SMOKE_SOURCE")

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

    def test_historical_preflight_accepts_unresolved_symlinked_ancestor(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            prepared = self.setup_source(root / "physical")
            (prepared["source"] / "package.json").write_text('{"version":"0.6.1"}')
            prepared["records"] = [{"path": path.relative_to(prepared["source"]).as_posix(),
                "blob": entry(path.name, path.read_bytes())["sha"], "sha256": digest(path.read_bytes()),
                "size": path.stat().st_size} for path in prepared["source"].rglob("*") if path.is_file()]
            alias = root / "ancestor"
            alias.symlink_to(root / "physical", target_is_directory=True)
            prepared.update(source=alias / "source", tools=alias / "source/tools", scratch=alias / "smoke")
            self.assertFalse(prepared["source"].is_symlink())
            self.assertTrue(alias.is_symlink())
            self.assertEqual(verifier_import_preflight(prepared, "aarch64-darwin")["status"], "pass")

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


def current_import_fixture(root, nebular_version="0.7.0"):
    """Controlled real core captures; synthetic source bytes never qualify apps."""
    from rs9.release_core import authenticate_release
    from rs9.profiles import selection_for_intent
    from tests.release_fixtures import package_evidence
    from rs9.nebular_callers import CURRENT070_CONTRACT_PATH
    if nebular_version not in ("0.7.0", "0.7.1"):
        raise ValueError("unknown fixture generation")
    current071 = nebular_version == "0.7.1"
    source = {}
    imports = smoke.CURRENT071_VERIFIER_IMPORTS if current071 else smoke.CURRENT070_VERIFIER_IMPORTS
    for name, edges in imports.items():
        text = "".join("import './" + path.rsplit("/", 1)[-1] + "';\n" for path in edges)
        if name == "tools/sidecar-common.mjs":
            text += "export function verifyDistribution(){}\n"
        elif name == "tools/sidecar-verify.mjs":
            text += "export function verifySidecar(){}\n"
        elif name == "tools/platform-targets.mjs":
            text += "import {readFileSync} from 'node:fs'; export const version=JSON.parse(readFileSync(new URL('../package.json',import.meta.url))).version;\n"
        else:
            text += "export const fixtureModule=true;\n"
        source[name] = text.encode()
    source["package.json"] = canonical({"version": nebular_version, "type": "module"})
    fixtures = {path: ("controlled fixture " + path + "\n").encode() for path in smoke.CURRENT070_FIXTURE_FILES}

    def pins(data):
        return {path: {"blob": entry(path, body)["sha"], "sha256": digest(body), "size": len(body)}
                for path, body in data.items()}

    def capture(name, repository, repository_id, release_id, commit, tree_sha, data):
        directory = root / name
        directory.mkdir()
        intent = package_evidence(directory)
        intent["project"]["repository"] = repository
        selected_tag = "v" + nebular_version if name == "nebular" else "v0.7.0"
        intent["tag"] = selected_tag
        package = data.get("package.json", (directory / "source/package.json").read_bytes())
        (directory / "source/package.json").write_bytes(package)
        api = directory / "api"
        (api / "repository.json").write_bytes(canonical({"id": repository_id, "full_name": repository}))
        (api / "ref.json").write_bytes(canonical({"ref": "refs/tags/" + selected_tag, "object": {"type": "commit", "sha": commit}}))
        (api / "commit.json").write_bytes(canonical({"sha": commit, "tree": {"sha": tree_sha}}))
        (api / "tree.json").write_bytes(canonical({"sha": tree_sha, "truncated": False,
            "tree": [entry(path, body) for path, body in {"package.json": package, **data}.items()]}))
        release = json.loads((api / "release.json").read_bytes())
        release.update(id=release_id, tag_name=selected_tag, target_commitish=commit)
        (api / "release.json").write_bytes(canonical(release))
        return authenticate_release(selection_for_intent(intent), directory), intent

    nebular, intent = capture("nebular", "Knowledge-Forge-AI/theme-forge-nebular-fusion", 1358643872,
        429782340 if current071 else 426333162,
        smoke.CURRENT071_COMMIT if current071 else smoke.CURRENT070_COMMIT,
        smoke.CURRENT071_TREE if current071 else smoke.CURRENT070_TREE, source)
    burst, burst_intent = capture("burst", "Knowledge-Forge-AI/theme-forge-stellar-burst", 1342490027,
        424873797, smoke.CURRENT070_FIXTURE_COMMIT, smoke.CURRENT070_FIXTURE_TREE, fixtures)
    contract = json.loads(CURRENT070_CONTRACT_PATH.read_bytes())
    if current071:
        contract["identity"].update(commit=smoke.CURRENT071_COMMIT, tree=smoke.CURRENT071_TREE,
                                    tag="v0.7.1", release_id=429782340)
    asset = next(row for row in nebular.record["assets"] if row["role"] == "payload")
    for platform in contract["platforms"].values():
        platform["asset"] = {**platform["asset"], **asset}

    class Client:
        def get(self, url, **kwargs):
            for selected, data in ((nebular, source), (burst, fixtures)):
                prefix = "https://raw.githubusercontent.com/" + selected.record["repository"]["full_name"] + "/" + selected.record["tag"]["commit"] + "/"
                if url.startswith(prefix):
                    return data[url.removeprefix(prefix)]
            raise AssertionError("Unexpected source identity")
    captures = [(nebular, intent, {}), (burst, {**burst_intent, "project": {"id": "theme-forge-stellar-burst"}}, {})]
    return nebular, captures, Client(), contract, pins(source), pins(fixtures)


class CurrentClosureTests(unittest.TestCase):
    def fixture(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        capture, captures, client, contract, source_pins, fixture_pins = current_import_fixture(root)
        for target, value in (("rs9.nebular_callers._load_current_contract", contract),
                              ("rs9.hosted_smoke.CURRENT070_VERIFIER_FILES", source_pins),
                              ("rs9.hosted_smoke.CURRENT070_FIXTURE_FILES", fixture_pins)):
            patcher = (patch(target, return_value=value) if target.endswith("_load_current_contract")
                       else patch(target, value))
            patcher.start()
            self.addCleanup(patcher.stop)
        prepared = prepare_smoke(capture, captures, client, root / "prepared")
        return prepared

    def reject_before_import(self, prepared):
        with patch("rs9.hosted_smoke._run_verifier") as run, self.assertRaises(ContractError):
            verifier_import_preflight(prepared, "x86_64-linux")
        run.assert_not_called()

    def test_current_support_table_is_exact_and_old_entries_remain(self):
        self.assertEqual(len(VERIFIER_SUPPORT), 4)
        self.assertEqual(VERIFIER_SUPPORT[smoke.HISTORICAL_COMMIT], ("package.json",))
        self.assertEqual(VERIFIER_SUPPORT[smoke.CURRENT_COMMIT], ("package.json",))
        self.assertEqual(VERIFIER_SUPPORT[smoke.CURRENT070_COMMIT], ("package.json",))
        self.assertEqual(VERIFIER_SUPPORT[smoke.CURRENT071_COMMIT], ("package.json",))
        self.assertEqual(VERIFIER_SUPPORT_TREES[smoke.CURRENT071_COMMIT], smoke.CURRENT071_TREE)
        self.assertEqual(VERIFIER_SUPPORT_TREES[smoke.CURRENT070_COMMIT], "27c643b6375c2aafde314799c4f08e844c14992c")
        self.assertEqual(set(smoke.CURRENT070_VERIFIER_IMPORTS), set(smoke.CURRENT070_VERIFIER_FILES) - {"package.json"})
        self.assertEqual(len(smoke.CURRENT070_VERIFIER_FILES), 14)
        self.assertEqual(len(smoke.CURRENT070_FIXTURE_FILES), 14)
        self.assertTrue(all(set(paths) <= set(smoke.CURRENT070_VERIFIER_IMPORTS)
                            for paths in smoke.CURRENT070_VERIFIER_IMPORTS.values()))

    def test_real_caller_smoke_pins_and_adapter_relationships_remain_consistent(self):
        from rs9 import nebular_callers as callers
        contract = callers._load_current_contract()
        shared = set(smoke.CURRENT070_VERIFIER_FILES) & set(contract["source_files"])
        self.assertEqual(shared, {"tools/sidecar-common.mjs", "tools/sidecar-verify.mjs", "tools/node-runtime-authority.mjs"})
        for name in shared:
            self.assertEqual(smoke.CURRENT070_VERIFIER_FILES[name], contract["source_files"][name])
        self.assertEqual(callers.CURRENT070_ASSET_SHA256S,
                         {platform["asset"]["sha256"] for platform in contract["platforms"].values()})
        for platform in contract["platforms"].values():
            for member, source in ((callers.PAYLOAD + "/loom-adapter/theme-adapter.mjs", "src-tauri/loom-adapter/theme-adapter.mjs"),
                                   (callers.PAYLOAD + "/solar-sail-adapter/solar-sail-adapter.mjs", "src-tauri/solar-sail-adapter/solar-sail-adapter.mjs")):
                self.assertEqual(platform["members"][member]["sha256"], contract["source_files"][source]["sha256"])

    def test_current_contract_io_and_parse_errors_are_classified(self):
        for error in (FileNotFoundError("missing"), OSError("unreadable"), ValueError("malformed")):
            with patch("rs9.hosted_smoke.current_contract_for_capture", side_effect=error), self.assertRaises(ContractError) as caught:
                smoke._current_smoke_capture(None)
            self.assertEqual(caught.exception.code, "SIDECAR_HARNESS_IMPORT")
            self.assertEqual(caught.exception.details["reason"], "current-capture-binding")

    def test_malformed_record_tag_and_rows_fail_without_raw_attribute_errors(self):
        prepared = self.fixture()
        for record in (None, [], {"tag": None}):
            self.reject_before_import({**prepared, "capture": SimpleNamespace(record=record)})
        for rows in (None, ["not-a-record"], [{"path": []}], [{"path": "package.json"}]):
            self.reject_before_import({**prepared, "records": rows})

    def test_mixed_generation_has_distinct_diagnostic(self):
        capture = SimpleNamespace(record={"tag": {"commit": smoke.CURRENT_COMMIT, "tree": smoke.CURRENT_TREE},
                                          "release": {"tag": "v0.7.0"}})
        with self.assertRaises(ContractError) as caught:
            smoke._reviewed_verifier_support(capture)
        self.assertEqual(caught.exception.details["reason"], "mixed-generation")

    def test_current_collection_has_closed_member_set_and_live_captures(self):
        prepared = self.fixture()
        smoke.verify_source_readback(prepared)
        self.assertEqual(len(prepared["records"]), 28)
        self.assertEqual(prepared["source_generation"], "theme-forge-current-202610")
        self.assertEqual({row["tag_commit"] for row in prepared["records"]},
                         {smoke.CURRENT070_COMMIT, smoke.CURRENT070_FIXTURE_COMMIT})

    @unittest.skipUnless(shutil.which("node"), "System Node required for non-native ESM import gate")
    def test_maintained_current_import_only_preflight(self):
        prepared = self.fixture()
        with patch("rs9.hosted_smoke.runtime_evidence") as runtime:
            self.assertEqual(verifier_import_preflight(prepared, "x86_64-linux")["status"], "pass")
        runtime.assert_not_called()

    @unittest.skipUnless(shutil.which("node"), "System Node required for non-native ESM import gate")
    def test_current_preflight_allows_ancestor_alias_but_not_source_alias(self):
        prepared = self.fixture()
        alias = prepared["scratch"].parent / "ancestor-alias"
        alias.symlink_to(prepared["scratch"].parent, target_is_directory=True)
        aliased = {**prepared, "source": alias / "prepared/source", "tools": alias / "prepared/source/tools"}
        smoke.verify_source_readback(aliased)
        self.assertEqual(verifier_import_preflight(aliased, "x86_64-linux")["status"], "pass")
        root_alias = prepared["scratch"].parent / "source-alias"
        root_alias.symlink_to(prepared["source"], target_is_directory=True)
        self.reject_before_import({**prepared, "source": root_alias, "tools": root_alias / "tools"})

    def test_current_source_bindings_are_written_only_after_successful_readback(self):
        prepared = self.fixture()
        output = prepared["scratch"].parent / "blocked-preparation"
        with patch("rs9.hosted_smoke.verify_source_readback", side_effect=ContractError("SIDECAR_HARNESS_IMPORT", "changed")):
            with self.assertRaises(ContractError):
                prepare_smoke(prepared["capture"], [(prepared["fixture_capture"],
                    {"project": {"id": "theme-forge-stellar-burst"}}, {})],
                    SimpleNamespace(get=lambda url, **kwargs: (prepared["source"] / url.split("/", 5)[-1].split("/", 1)[-1]).read_bytes()), output)
        self.assertFalse((output / "source-bindings.json").exists())

    def test_missing_and_extra_records_refused_before_import(self):
        prepared = self.fixture()
        original = prepared["records"]
        for rows in (original[:-1], original + [dict(original[0])]):
            self.reject_before_import({**prepared, "records": rows})

    def test_missing_extra_and_changed_source_files_refused_before_import(self):
        prepared = self.fixture()
        path = prepared["source"] / "package.json"
        original = path.read_bytes()
        path.unlink()
        self.reject_before_import(prepared)
        path.write_bytes(original)
        extra = prepared["source"] / "tools/extra.mjs"
        extra.write_text("export const unexpected=true;")
        self.reject_before_import(prepared)
        extra.unlink()
        path.write_bytes(b'{"version":"0.6.1"}')
        self.reject_before_import(prepared)
        # Recomputed row digests cannot change the independently reviewed pins.
        changed = dict(prepared, records=copy.deepcopy(prepared["records"]))
        row = next(row for row in changed["records"] if row["path"] == "package.json")
        row.update(blob=entry("package.json", path.read_bytes())["sha"], sha256=digest(path.read_bytes()), size=path.stat().st_size)
        self.reject_before_import(changed)

    def test_cross_generation_producers_and_roles_refused(self):
        prepared = self.fixture()
        for key, value in (("tag_commit", smoke.CURRENT_COMMIT), ("role", "fixture")):
            changed = dict(prepared, records=copy.deepcopy(prepared["records"]))
            changed["records"][0][key] = value
            self.reject_before_import(changed)
        self.reject_before_import({**prepared, "fixture_capture": prepared["capture"]})
        self.reject_before_import({**prepared, "capture": prepared["fixture_capture"]})
        self.reject_before_import({**prepared, "capture": None})
        self.reject_before_import({**prepared, "source_generation": "theme-forge-live1"})
        self.reject_before_import({**prepared, "tools": prepared["scratch"] / "unreviewed-tools"})

    def test_current_wrong_tree_and_unknown_identity_refused(self):
        prepared = self.fixture()
        capture = prepared["capture"]
        capture.record["tag"]["tree"] = "0" * 40
        with self.assertRaises(ContractError):
            smoke._reviewed_verifier_support(capture)
        capture.record["tag"]["commit"] = "a" * 40
        with self.assertRaises(ContractError):
            smoke._reviewed_verifier_support(capture)

    def test_nonregular_current_source_and_lost_record_marker_refused(self):
        prepared = self.fixture()
        path = prepared["source"] / "package.json"
        target = prepared["scratch"] / "outside.json"
        target.write_bytes(path.read_bytes())
        path.unlink()
        path.symlink_to(target)
        self.reject_before_import(prepared)
        # A missing explicit generation marker still cannot downgrade a current capture.
        changed = dict(prepared)
        changed.pop("source_generation")
        self.reject_before_import(changed)
