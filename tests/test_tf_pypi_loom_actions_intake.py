"""Synthetic transport contracts; no native qualification or remote actions."""
import base64
import copy
import hashlib
import io
import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from rs9 import tf_pypi_loom_actions_intake as a
from rs9.tf_pypi_loom_actions_workflow import workflow_text
from rs9.tf_pypi_publish import build, _native_qualify_job
from tests.tf_pypi_fixtures import fixture


def encoded(value):
    return json.dumps(value).encode()


def body_fixture():
    s = json.loads(a.SELECTION.read_text())
    pin, pack = fixture(a.PROJECT)
    pin["source_status"] = "BLOCKED"; pin["qualified_platforms"] = []
    def receipt(job, role):
        e = {"name": "pull_request", "action": "synchronize", "number": 6, "repository": a.REPO, "headRepository": a.REPO, "baseRepository": a.REPO, "headRef": "staging", "baseRef": "main", "headSha": s["run"]["head_sha"], "baseSha": s["baseCommit"]}
        return encoded({"schema": "tfsb.ci-exact-head-receipt", "schemaVersion": 1, "status": "pass", "event": e, "workflow": {"job": job, "runId": str(s["run"]["id"]), "runAttempt": "1", "matrix": {}}, "checkout": {"role": role, "clean": True, "tree": s["headTree"], "commit": s["run"]["head_sha"] if role == "staging-head" else s["ciMergeCommit"], "parents": [] if role == "staging-head" else [s["baseCommit"], s["run"]["head_sha"]]}, "identities": {"stagingHead": {"commit": s["run"]["head_sha"], "tree": s["headTree"], "repository": a.REPO}}})
    root = {"receipt.json": receipt("root-package", "merge-candidate"), "pack-manifest.json": encoded([{"name": pin["npm_name"], "version": pin["version"], "size": len(pack), "integrity": "sha512-" + base64.b64encode(hashlib.sha512(pack).digest()).decode()}]), "test-report.json": b"{}", "audit-result.json": b"{}", "root-package.tgz": pack}
    source = {"receipt.json": receipt("source-policy", "staging-head")}
    for job, files in [("root-package", root), ("source-policy", source)]:
        files["artifact-manifest.json"] = encoded({"schema": "tfsb.ci-job-artifact-manifest", "schemaVersion": 1, "status": "pass", "job": job, "matrix": {}, "artifacts": [{"path": p, "size": len(b), "sha256": a.digest(b)} for p, b in files.items()]})
    rows = [{"path": name + "/" + p, "size": len(b), "sha256": a.digest(b)} for name, files in [("root-package-artifacts", root), ("source-policy-receipt", source)] for p, b in files.items()]
    rows.extend({"path": f"supply-chain-artifacts/synthetic-{i}.json", "size": 2, "sha256": a.digest(b"{} ".strip())} for i in range(27))
    s["aggregateArtifacts"] = copy.deepcopy(rows)
    aggregate = {"receipt.json": receipt("evidence-aggregate", "merge-candidate"), "ci-evidence-summary.md": b"synthetic", "ci-evidence-manifest.json": encoded({"schema": "tfsb.ci-aggregate-evidence-manifest", "schemaVersion": 3, "status": "pass", "errors": [], "product": "stellar-loom", "headSha": s["run"]["head_sha"], "headTree": s["headTree"], "dependencyResults": {k: "success" for k in ["source-policy", "root-package", "consumer-fixture", "codeql", "supply-chain"]}, "artifacts": rows})}
    return s, pin, {"root-package-artifacts": root, "source-policy-receipt": source, "evidence-aggregate-artifacts": aggregate}


def zip_bytes(files, mode=None):
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        for name, data in files.items():
            info = zipfile.ZipInfo(name)
            if mode is not None:
                info.external_attr = mode << 16
            z.writestr(info, data)
    return out.getvalue()


def live_fixture(s):
    run = copy.deepcopy(s["run"])
    run.update(repository={"full_name": a.REPO, "id": s["repositoryId"]}, head_repository={"id": s["repositoryId"]})
    pr = {"number": 6, "merged": True, "merge_commit_sha": s["mainCommit"], "head": {"sha": s["run"]["head_sha"], "ref": "staging", "repo": {"id": s["repositoryId"]}}, "base": {"ref": "main", "repo": {"id": s["repositoryId"]}}}
    values = {"/actions/runs/40238216121/attempts/1": run, "/actions/workflows/353226742": s["workflow"], "/pulls/6": pr}
    for sha in [s["run"]["head_sha"], s["ciMergeCommit"], s["mainCommit"]]:
        values["/git/commits/" + sha] = {"sha": sha, "tree": {"sha": s["headTree"]}, "parents": [{"sha": p} for p in [s["baseCommit"], s["run"]["head_sha"]]]}
    for artifact in s["artifacts"]:
        values["/actions/artifacts/" + str(artifact["id"])] = artifact
    class Client:
        def json(self, suffix):
            return values[suffix]
    return Client(), values


def full_transport_fixture():
    """Synthetic valid package and actual producer wire shapes, no native claims."""
    import random
    import gzip
    from rs9.tf_pypi_backend import write_tar
    s, _, files = body_fixture()
    pin = json.loads(a.PIN.read_text())
    pkg = {"name": pin["npm_name"], "version": pin["version"], "license": pin["license"], "engines": {"node": ">=22"}, "bin": pin["bins"]}
    base = {"package.json": (encoded(pkg), 0o644), "LICENSE": (b"Synthetic legal fixture, not upstream license.\n", 0o644), "NOTICE": (b"Synthetic fixture.\n", 0o644), "COMMERCIAL-LICENSE.md": (b"Synthetic fixture.\n", 0o644), **{target: (b"process.stdout.write('synthetic\\n');\n", 0o755) for target in pin["bins"].values()}}
    padding = random.Random(0).randbytes(280000)
    n = 272000; tried = set(); pack = None
    for _ in range(64):
        trial = gzip.compress(gzip.decompress(write_tar({**base, "fixture-padding.txt": (padding[:n], 0o644)}, "package")), mtime=0)
        if len(trial) == 272836:
            pack = trial; break
        tried.add(n); delta = 272836 - len(trial); n += delta
        if n in tried:
            for candidate in range(max(0, n - 64), min(len(padding), n + 65)):
                trial = gzip.compress(gzip.decompress(write_tar({**base, "fixture-padding.txt": (padding[:candidate], 0o644)}, "package")), mtime=0)
                if len(trial) == 272836:
                    pack = trial; break
            break
    if pack is None:
        raise AssertionError("deterministic fixture could not match the fixed package-size contract")
    pin["sha256"] = a.digest(pack)
    s["pack"] = {"bytes": len(pack), "sha256": a.digest(pack)}
    root = files["root-package-artifacts"]
    root["root-package.tgz"] = pack
    root["pack-manifest.json"] = encoded([{"name": pin["npm_name"], "version": pin["version"], "size": len(pack), "integrity": "sha512-" + base64.b64encode(hashlib.sha512(pack).digest()).decode()}])
    root["artifact-manifest.json"] = encoded({"schema": "tfsb.ci-job-artifact-manifest", "schemaVersion": 1, "status": "pass", "job": "root-package", "matrix": {}, "artifacts": [{"path": p, "size": len(b), "sha256": a.digest(b)} for p, b in root.items() if p != "artifact-manifest.json"]})
    agg = a.decode(files["evidence-aggregate-artifacts"]["ci-evidence-manifest.json"])
    agg["artifacts"] = [r for r in agg["artifacts"] if not r["path"].startswith("root-package-artifacts/")]
    agg["artifacts"].extend({"path": "root-package-artifacts/" + p, "size": len(b), "sha256": a.digest(b)} for p, b in root.items())
    s["aggregateArtifacts"] = copy.deepcopy(agg["artifacts"])
    files["evidence-aggregate-artifacts"]["ci-evidence-manifest.json"] = encoded(agg)
    archives = {}
    for artifact in s["artifacts"]:
        members = files[artifact["name"]]; raw = zip_bytes(members)
        artifact.update(size_in_bytes=len(raw), digest="sha256:" + a.digest(raw), members=[{"name": p, "bytes": len(b), "sha256": a.digest(b)} for p, b in members.items()])
        archives["/actions/artifacts/" + str(artifact["id"]) + "/zip"] = raw
    return s, pin, archives, pack


class ActionsIntakeTests(unittest.TestCase):
    def test_exact_measured_selection_and_ready_source_pin(self):
        s = json.loads(a.SELECTION.read_text()); pin = json.loads(a.PIN.read_text())
        a.validate_selection(s, pin)
        self.assertEqual(pin["source_status"], "READY")
        self.assertEqual(pin["qualified_platforms"], [])
        self.assertEqual(s["artifactDownloadHosts"], [a.ARTIFACT_HOST])

    def test_selection_substitution_refusals(self):
        s = json.loads(a.SELECTION.read_text()); pin = json.loads(a.PIN.read_text())
        changes = [("repository", "attacker/repo"), ("pr", 5), ("mainCommit", "0" * 40), ("artifactDownloadHosts", ["example.com"])]
        for key, value in changes:
            with self.subTest(key=key), self.assertRaises(ValueError):
                bad = copy.deepcopy(s); bad[key] = value; a.validate_selection(bad, pin)
        for key, value in [("id", 1), ("run_attempt", 2), ("conclusion", "failure"), ("path", ".github/workflows/other.yml")]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                bad = copy.deepcopy(s); bad["run"][key] = value; a.validate_selection(bad, pin)

    def test_live_pr_join_accepts_empty_run_pull_requests(self):
        s = json.loads(a.SELECTION.read_text()); c, values = live_fixture(s)
        self.assertEqual(values["/actions/runs/40238216121/attempts/1"]["pull_requests"], [])
        self.assertEqual(a.authenticate(s, c)["pr"]["number"], 6)

    def test_live_metadata_substitution_refusals(self):
        s = json.loads(a.SELECTION.read_text())
        changes = [("/actions/runs/40238216121/attempts/1", "conclusion", "failure"), ("/pulls/6", "merged", False), ("/git/commits/" + s["mainCommit"], "tree", {"sha": "0" * 40}), ("/actions/artifacts/12615945391", "expired", True), ("/actions/artifacts/12615945391", "digest", "sha256:" + "0" * 64)]
        for path, key, value in changes:
            with self.subTest(path=path, key=key), self.assertRaises(ValueError):
                c, values = live_fixture(copy.deepcopy(s)); values[path][key] = value; a.authenticate(s, c)

    def test_selected_zip_and_link_path_cap_refusals(self):
        _, _, files = body_fixture(); root = files["root-package-artifacts"]
        self.assertEqual(a.unpack(zip_bytes(root), "root-package-artifacts"), root)
        bad = dict(root); bad["../outside"] = bad.pop("receipt.json")
        for data in [zip_bytes(bad), zip_bytes(root, stat.S_IFLNK | 0o777), zip_bytes({**root, "extra": b"x"}), zip_bytes({**root, "root-package.tgz": b"x" * 272837})]:
            with self.assertRaises(ValueError):
                a.unpack(data, "root-package-artifacts")

    def test_zip_nul_original_name_refused(self):
        _, _, files = body_fixture()
        root = dict(files["root-package-artifacts"])
        root["receipt.jsonX"] = root.pop("receipt.json")
        raw = zip_bytes(root).replace(b"receipt.jsonX", b"receipt.json\x00")
        with self.assertRaises(ValueError): a.unpack(raw, "root-package-artifacts")

    def test_selected_inner_hashes_refuse_substitution(self):
        _, _, files = body_fixture(); root = files["root-package-artifacts"]
        artifact = {"members": [{"name": p, "bytes": len(b), "sha256": a.digest(b)} for p, b in root.items()]}
        a.selected_members(artifact, root)
        tampered = dict(root); tampered["receipt.json"] += b" "
        with self.assertRaises(ValueError): a.selected_members(artifact, tampered)
        artifact["members"][0]["sha256"] = "0" * 64
        with self.assertRaises(ValueError): a.selected_members(artifact, root)

    def test_body_joins_and_existing_offline_blocked_build(self):
        s, pin, files = body_fixture()
        pack = a.validate_bodies(s, pin, files)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); inputs = root / "inputs"; inputs.mkdir()
            (inputs / pin["asset"]).write_bytes(pack)
            result = build(pin, root / "dist", inputs=inputs)
            self.assertEqual(len(result["files"]), 4)
            self.assertFalse(result["publication_admitted"])

    def test_manifest_receipt_aggregate_and_pack_tampers(self):
        for artifact, member in [("root-package-artifacts", "root-package.tgz"), ("root-package-artifacts", "receipt.json"), ("source-policy-receipt", "receipt.json"), ("evidence-aggregate-artifacts", "ci-evidence-manifest.json")]:
            with self.subTest(member=member), self.assertRaises((ValueError, KeyError)):
                s, pin, files = body_fixture(); files[artifact][member] += b"tampered"; a.validate_bodies(s, pin, files)
        s, pin, files = body_fixture()
        aggregate = a.decode(files["evidence-aggregate-artifacts"]["ci-evidence-manifest.json"])
        aggregate["dependencyResults"]["codeql"] = "failure"
        files["evidence-aggregate-artifacts"]["ci-evidence-manifest.json"] = encoded(aggregate)
        with self.assertRaises(ValueError): a.validate_bodies(s, pin, files)

    def test_output_refuses_existing_or_symlink_and_retains_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); out = root / "out"; out.mkdir()
            with self.assertRaises(FileExistsError): a.transport(out, object())
            alias = root / "alias"; alias.symlink_to(out, target_is_directory=True)
            with self.assertRaises(FileExistsError): a.transport(alias, object())
            with self.assertRaises(AttributeError): a.transport(root / "new", object())
            self.assertEqual(json.loads((root / "new/failure.json").read_text())["status"], "failed")
            self.assertFalse((root / "new/transport-receipt.json").exists())

    def test_regular_input_symlink_hardlink_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); leaf = root / "leaf"; leaf.write_bytes(b"x")
            alias = root / "alias"; alias.symlink_to(leaf)
            with self.assertRaises(ValueError): a.regular(alias, 10)
            import os
            os.link(leaf, root / "hard")
            with self.assertRaises(ValueError): a.regular(leaf, 10)

    def test_json_duplicate_keys_refused(self):
        with self.assertRaises(ValueError): a.decode(b'{"x":1,"x":2}')

    def test_pending_redirect_is_fail_closed_and_auth_not_forwarded(self):
        import urllib.error
        s = json.loads(a.SELECTION.read_text()); c = a.Client(s)
        requests = []
        class Opener:
            def open(self, request, timeout):
                requests.append(request)
                raise urllib.error.HTTPError(request.full_url, 302, "redirect", {"Location": "https://unreviewed.blob.core.windows.net/path?signature=opaque"}, None)
        c.opener = Opener()
        with patch.dict("os.environ", {"GH_TOKEN": "synthetic-test-token"}), self.assertRaises(ValueError):
            c.get("/actions/artifacts/12615945391/zip", 10, archive=True)
        self.assertEqual(len(requests), 1)
        self.assertIn("Authorization", requests[0].headers)

    def test_allowed_redirect_drops_auth_and_enforces_stream_cap(self):
        import urllib.error
        s = json.loads(a.SELECTION.read_text()); s["artifactDownloadHosts"] = [a.ARTIFACT_HOST]
        c = a.Client(s); requests = []
        class Response:
            status = 200
            def __init__(self, url): self.url = url; self.body = io.BytesIO(b"package")
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def geturl(self): return self.url
            def read1(self, n): return self.body.read(n)
        class Opener:
            def open(self, request, timeout):
                requests.append(request)
                if len(requests) == 1:
                    raise urllib.error.HTTPError(request.full_url, 302, "redirect", {"Location": "https://productionresultssa9.blob.core.windows.net/object?signed=opaque"}, None)
                return Response(request.full_url)
        c.opener = Opener()
        with patch.dict("os.environ", {"GH_TOKEN": "synthetic-token"}):
            self.assertEqual(c.get("/actions/artifacts/12615945391/zip", 10, archive=True), b"package")
        self.assertIn("Authorization", requests[0].headers)
        self.assertNotIn("Authorization", requests[1].headers)
        requests.clear()
        with self.assertRaises(ValueError): c.get("/actions/artifacts/12615945391/zip", 2, archive=True)

    def test_controls_checked_on_primary_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); selection = root / "selection.json"; pin = root / "pin.json"
            selection.write_bytes(a.SELECTION.read_bytes()); pin.write_bytes(a.PIN.read_bytes())
            def fail(*args):
                selection.write_bytes(selection.read_bytes() + b" ")
                raise RuntimeError("synthetic-primary")
            with patch.object(a, "SELECTION", selection), patch.object(a, "PIN", pin), patch.object(a, "authenticate", side_effect=fail):
                with self.assertRaises(RuntimeError): a.transport(root / "output", object())
            failure = json.loads((root / "output/failure.json").read_text())
            self.assertEqual(failure["error_class"], "RuntimeError")
            self.assertEqual(failure["control_postguard_errors"], ["ValueError"])
            self.assertFalse((root / "output/transport-receipt.json").exists())

    def test_complete_offline_transport_emits_exact_pack_and_receipt(self):
        s, pin, archives, pack = full_transport_fixture()
        a.validate_selection(s, pin)
        client, _ = live_fixture(s); calls = []
        def get(suffix, limit, archive=False):
            self.assertTrue(archive); self.assertEqual(limit, a.MAX_ZIP)
            calls.append(suffix)
            return archives[suffix]
        client.get = get
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); selection = root / "selection.json"; pin_path = root / "pin.json"
            selection.write_bytes(encoded(s)); pin_path.write_bytes(encoded(pin))
            out = root / "transport"
            with patch.object(a, "SELECTION", selection), patch.object(a, "PIN", pin_path):
                result = a.transport(out, client)
            self.assertEqual(len(calls), 3)
            self.assertEqual((out / "inputs" / pin["asset"]).read_bytes(), pack)
            self.assertEqual(json.loads((out / "transport-receipt.json").read_text()), result)
            self.assertFalse(result["publication_admitted"])
            self.assertFalse(result["native_qualification"])
            self.assertEqual(result["public_writes"], 0)
            self.assertEqual(result["package_sha256"], a.digest(pack))
            expected = {"producer/selection.json", "producer/api-metadata.json", "transport-receipt.json", "inputs/" + pin["asset"]} | {"producer/" + str(r["id"]) + ".zip" for r in s["artifacts"]}
            self.assertEqual({p.relative_to(out).as_posix() for p in out.rglob("*") if p.is_file()}, expected)
            self.assertFalse((out / "failure.json").exists())

    def test_aggregate_complete_row_closure_refusals(self):
        mutations = [lambda rows: rows.append({"path": "extra.json", "size": 1, "sha256": "0" * 64}), lambda rows: rows.__setitem__(-1, copy.deepcopy(rows[0])), lambda rows: rows[-1].update(sha256="0" * 64), lambda rows: rows[-1].update(size=True), lambda rows: rows[-1].update(path="../escape"), lambda rows: rows[-1].update(sha256="bad"), lambda rows: rows[-1].update(extra=True)]
        for mutate in mutations:
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                s, pin, files = body_fixture()
                aggregate = a.decode(files["evidence-aggregate-artifacts"]["ci-evidence-manifest.json"])
                mutate(aggregate["artifacts"])
                files["evidence-aggregate-artifacts"]["ci-evidence-manifest.json"] = encoded(aggregate)
                a.validate_bodies(s, pin, files)

    def test_primary_preserved_when_output_removed_or_replaced(self):
        for replace_root in (False, True):
            with self.subTest(replaced=replace_root), tempfile.TemporaryDirectory() as temp:
                root = Path(temp); out = root / "output"
                def fail(*args):
                    if replace_root:
                        out.rename(root / "original-owned-root")
                        out.mkdir(mode=0o700)
                        (out / "foreign.txt").write_bytes(b"foreign")
                    else:
                        out.rmdir()
                    raise RuntimeError("synthetic-primary")
                with patch.object(a, "authenticate", side_effect=fail):
                    with self.assertRaisesRegex(RuntimeError, "synthetic-primary") as caught:
                        a.transport(out, object())
                failure = caught.exception.transport_failure
                self.assertEqual(failure["error_class"], "RuntimeError")
                self.assertTrue(failure["failurePersistenceUnknown"])
                self.assertEqual(failure["retention_errors"][0]["role"], "output-owner")
                self.assertFalse((out / "failure.json").exists())
                if replace_root:
                    self.assertEqual({p.name for p in out.iterdir()}, {"foreign.txt"})

    def test_owned_failure_receipt_write_error_stays_nonzero(self):
        import contextlib
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp) / "output"; stdout = io.StringIO()
            original = a.write_new
            def write(path, data):
                if path.name == "failure.json": raise OSError("synthetic-write-error")
                return original(path, data)
            with patch.object(a, "authenticate", side_effect=RuntimeError("synthetic-primary")), patch.object(a, "write_new", side_effect=write), contextlib.redirect_stdout(stdout):
                self.assertEqual(a.main(["--output", str(out)]), 1)
            result = json.loads(stdout.getvalue())
            self.assertEqual(result["error_class"], "RuntimeError")
            self.assertTrue(result["failurePersistenceUnknown"])
            self.assertEqual(result["retention_errors"], [{"role": "failure-receipt", "error_class": "OSError"}])
            self.assertEqual(list(out.iterdir()), [])

    def test_cli_reports_unknown_persistence_nonzero(self):
        import contextlib
        primary = RuntimeError("synthetic-primary")
        primary.transport_failure = {"status": "failed", "error_class": "RuntimeError", "failurePersistenceUnknown": True, "retention_errors": [{"role": "output-owner", "error_class": "ValueError"}], "publication_admitted": False}
        stdout = io.StringIO()
        with patch.object(a, "transport", side_effect=primary), contextlib.redirect_stdout(stdout):
            self.assertEqual(a.main(["--output", "unused-synthetic"]), 1)
        self.assertEqual(json.loads(stdout.getvalue()), primary.transport_failure)

    def test_qualification_only_workflow_and_native_commands_exact(self):
        from rs9.tf_pypi_loom_actions_workflow import SELECTOR, PROJECT, EXECUTION_REPOSITORY, TOOLING_REPOSITORY
        commit = "1" * 40  # Synthetic rendering input, never an accepted source receipt.
        text = workflow_text(commit)
        self.assertFalse((a.ROOT / ".github/workflows/rs9-tfsl-pypi-actions-qualify.yml").exists())
        self.assertEqual(text.count("          repository: " + TOOLING_REPOSITORY), 5)
        self.assertEqual(text.count("ref: '" + commit + "'"), 5)
        self.assertEqual(text.count("QUALIFY_COMMIT: '" + commit + "'"), 4)
        self.assertEqual(text.count("QUALIFY_RUN_ID: '${{ github.run_id }}'"), 4)
        self.assertEqual(text.count("QUALIFY_RUN_ATTEMPT: '${{ github.run_attempt }}'"), 4)
        self.assertEqual(text.count("if: ${{ github.repository == '" + EXECUTION_REPOSITORY + "' }}"), 5)
        self.assertNotIn("${{ github.sha }}", text)
        for job, name, runner, target, sandbox in [("native_darwin_arm64", "Native macOS ARM64 installed consumer", "macos-15", "darwin-arm64", True), ("native_linux_arm64", "Native Linux ARM64 GNU installed consumer", "ubuntu-24.04-arm", "linux-arm64-gnu", False), ("native_linux_x64", "Native Linux x86_64 GNU installed consumer", "ubuntu-24.04", "linux-x64-gnu", False)]:
            original = _native_qualify_job(job, name, runner, PROJECT, target, sandbox=sandbox, selector=SELECTOR)
            expected = original.replace("          ref: '${{ github.sha }}'", "          repository: " + TOOLING_REPOSITORY + "\n          ref: '" + commit + "'").replace("QUALIFY_COMMIT: '${{ github.sha }}'", "QUALIFY_COMMIT: '" + commit + "'")
            expected = expected.replace("  " + job + ":\n", "  " + job + ":\n    if: ${{ github.repository == '" + EXECUTION_REPOSITORY + "' }}\n")
            self.assertIn(expected, text)
        for forbidden in ["id-token:", "environment:", "select-missing", "pypa/", "  publish:", "--url", "--selection", "workflow_call:"]:
            self.assertNotIn(forbidden, text)
        self.assertIn("rs9.tf_pypi_hosted admit", text)
        self.assertIn("--inputs transport/inputs --output dist", text)
        self.assertIn("GH_TOKEN: '${{ github.token }}'", text)
        self.assertIn("      actions: read", text)
        self.assertEqual(text.count("persist-credentials: false"), 5)
        self.assertIn("Execution/token repository: " + EXECUTION_REPOSITORY, text)

    def test_workflow_renderer_requires_full_commit_and_cli_argument(self):
        import contextlib
        from rs9.tf_pypi_loom_actions_workflow import main
        for bad in [None, "", "main", "1" * 39, "1" * 41, "A" * 40, "1" * 40 + "\n", "x'\nrun: bad"]:
            with self.subTest(value=bad), self.assertRaises(ValueError):
                workflow_text(bad)
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as missing:
                main([])
            self.assertEqual(missing.exception.code, 2)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(main(["--rs9-commit", "2" * 40]), 0)
        self.assertEqual(output.getvalue(), workflow_text("2" * 40))


    def test_solar_defaults_and_loom_cross_selection_remain_separate(self):
        from rs9 import tf_pypi_actions_intake as solar
        from rs9.tf_pypi_actions_workflow import workflow_text as solar_workflow
        selection = json.loads(a.SELECTION.read_text())
        pin = json.loads(a.PIN.read_text())
        self.assertEqual(solar.PROJECT, "theme-forge-solar-sail")
        self.assertEqual(solar.ARTIFACT_HOST, "productionresultssa14.blob.core.windows.net")
        self.assertEqual(a.PROJECT, "theme-forge-stellar-loom")
        self.assertIn("Solar 0.3.0", solar_workflow("1" * 40))
        self.assertIn("Loom 0.5.0", workflow_text("1" * 40))
        with self.assertRaises(ValueError): solar.validate_selection(selection, pin)
        with self.assertRaises(ValueError):
            a.validate_selection(json.loads(solar.SELECTION.read_text()), json.loads(solar.PIN.read_text()))


if __name__ == "__main__":
    unittest.main()
