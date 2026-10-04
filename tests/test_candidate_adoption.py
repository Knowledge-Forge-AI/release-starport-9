"""Exact source/hosted bindings and stopped adoption safety."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from rs9.adopt_candidate import adopt, validate_receipts
from rs9.candidate_inventory import MANIFEST, file_inventory, git_oid, operational_path, source_tree
from rs9.errors import ContractError
from rs9.hosted_candidate import REQUIRED_RECEIPTS
from rs9.scratch import canonical
from rs9.signing_preflight import PRIMARY, SIGNING, inspect_listing


def _create_valid_receipt_fixture(root: Path, commit: str, workflow_hash: str):
    files = []
    outcomes = []
    for lane, system in REQUIRED_RECEIPTS:
        fname = f"{lane}-{system}.json"
        doc = {
            "schema": "rs9.hosted-candidate-diagnostic.v1alpha1",
            "source_commit": commit,
            "trust_root": "hosted-candidate-unattested",
            "lane": lane,
            "system": system,
            "status": "blocked",
            "production_enabled": False,
            "publication_authority": False,
            "mandatory_gates_satisfied": False,
            "artifacts": [],
        }
        raw = canonical(doc)
        (root / fname).write_bytes(raw)
        files.append({"path": fname, "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
        outcomes.append({"lane": lane, "system": system, "status": "blocked", "mandatory_gates_satisfied": False})

    manifest = {
        "schema": "rs9.hosted-candidate-receipts.v1alpha1",
        "commit": commit,
        "workflow_sha256": workflow_hash,
        "production_enabled": False,
        "status": "incomplete-candidate",
        "outcomes": outcomes,
        "files": files,
    }
    (root / "receipts-manifest.json").write_bytes(canonical(manifest))
    return manifest


class CandidateAdoptionTests(unittest.TestCase):
    def test_operational_metadata_cannot_enter_reviewed_product_inventory(self):
        for path in (".serena/state.json", "tests/.pytest_cache/state", "src/__pycache__/test.pyc", "src/old.pyc"):
            self.assertTrue(operational_path(path))
            with tempfile.TemporaryDirectory() as tmp, self.assertRaises(ContractError):
                file_inventory(Path(tmp).resolve(), [path])
        self.assertFalse(operational_path("src/rs9/candidate_inventory.py"))

    def test_hosted5_wrapper_binds_public_parent_and_only_prints_log_status_packet(self):
        import contextlib
        import importlib.util
        import io
        import subprocess
        path = Path(__file__).resolve().parents[1] / "operators/live1/run-hosted5.py"
        spec = importlib.util.spec_from_file_location("rs9_hosted5_wrapper", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            (root / MANIFEST).parent.mkdir(parents=True)
            raw = b"{}"
            (root / MANIFEST).write_bytes(raw)
            out = root / "out"
            out.mkdir()
            stdout = io.StringIO()
            with patch.object(module, "ROOT", root), \
                 patch.object(module, "dependencies", return_value=(MANIFEST, lambda *a, **k: "a" * 40, lambda p: out, ContractError)), \
                 patch.object(module.subprocess, "check_output", side_effect=[b"main", module.PARENT.encode(), module.PARENT.encode()]), \
                 patch.object(module.subprocess, "run", return_value=subprocess.CompletedProcess([], 2)) as run, \
                 contextlib.redirect_stdout(stdout):
                code = module.main(["--reviewed-tree", "a" * 40, "--manifest-sha256", hashlib.sha256(raw).hexdigest(), "--output", str(out)])
            self.assertEqual(module.PARENT, "e2c6cb5fcc55462e2e28e889a6c9f3ed60c9d131")
            self.assertEqual(code, 2)
            self.assertEqual([r.split("=", 1)[0] for r in stdout.getvalue().splitlines()], ["LOG", "RC", "MANAGER_PACKET"])
            argv = run.call_args.args[0]
            self.assertEqual(argv[argv.index("--reviewed-parent") + 1], module.PARENT)
            self.assertIs(run.call_args.kwargs["stdout"], run.call_args.kwargs["stderr"])

    def test_blocked_candidate_cannot_stage_commit_or_push(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            repo, out = root / "repository", root / "results"
            (repo / "operators/live1").mkdir(parents=True)
            out.mkdir()
            raw = canonical({"candidate_adoption_ready": False})
            (repo / MANIFEST).write_bytes(raw)
            with patch("rs9.adopt_candidate.run") as command:
                with self.assertRaises(ContractError) as raised:
                    adopt(repo, out, reviewed_parent="1" * 40, reviewed_tree="2" * 40, manifest_sha256=hashlib.sha256(raw).hexdigest())
                self.assertEqual(raised.exception.code, "ADOPTION_NOT_READY")
                command.assert_not_called()

    def test_adopt_stages_exactly_changed_paths_and_verifies_cached_set(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            repo, out = root / "repository", root / "results"
            (repo / "operators/live1").mkdir(parents=True)
            out.mkdir()
            manifest_doc = {
                "candidate_adoption_ready": True,
                "adoption_scope": "hosted-candidate-qualification-only",
                "production_enabled": False,
                "changed_paths": ["src/changed.py"],
                "files": [{"path": "src/changed.py", "size": 1, "sha256": "0" * 64, "mode": "100644", "git_blob": "0" * 40}],
            }
            raw = canonical(manifest_doc)
            (repo / "src").mkdir(parents=True)
            (repo / "src/changed.py").write_bytes(b"data")
            (repo / MANIFEST).write_bytes(raw)
            parent = "1" * 40
            tree = "2" * 40
            manifest_sha = hashlib.sha256(raw).hexdigest()

            added = False
            def mock_git(r, args):
                nonlocal added
                cmd = args[1:]
                if cmd == ["branch", "--show-current"]:
                    return "main"
                if cmd == ["rev-parse", "HEAD"] or cmd == ["rev-parse", "origin/main"]:
                    return parent
                if cmd == ["diff", "--cached", "--name-only"]:
                    return "src/changed.py\nsrc/unexpected.py" if added else ""
                if cmd == ["remote", "get-url", "origin"]:
                    return "https://github.com/Knowledge-Forge-AI/release-starport-9.git"
                if cmd == ["ls-files", "-z"]:
                    return "src/changed.py\0operators/live1/candidate-manifest.json"
                if cmd[:2] == ["ls-files", "--others"]:
                    return ""
                if cmd[:2] == ["fetch", "origin"]:
                    return ""
                if cmd[:3] == ["add", "-A", "--"]:
                    added = True
                    return ""
                if cmd == ["write-tree"]:
                    return tree
                return ""

            with patch("rs9.adopt_candidate.run", side_effect=mock_git), \
                 patch("rs9.adopt_candidate.verify_inventory", return_value=tree), \
                 patch("rs9.collect_candidate.output_directory", return_value=out):
                with self.assertRaises(ContractError) as caught:
                    adopt(repo, out, reviewed_parent=parent, reviewed_tree=tree, manifest_sha256=manifest_sha)
                self.assertEqual(caught.exception.code, "ADOPTION_REVIEW")

    def test_tree_calculation_uses_directory_sorting_and_mode(self):
        blob = git_oid("blob", b"data")
        subtree = git_oid("tree", b"100644 a\0" + bytes.fromhex(blob))
        expected = git_oid("tree", b"100644 foo.bar\0" + bytes.fromhex(blob) + b"40000 foo\0" + bytes.fromhex(subtree))
        self.assertEqual(source_tree([{"path": "foo/a", "mode": "100644", "git_blob": blob},
                                     {"path": "foo.bar", "mode": "100644", "git_blob": blob}]), expected)

    def test_hosted_receipt_tamper_or_commit_mismatch_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            commit = "a" * 40
            workflow_hash = "b" * 64
            manifest = _create_valid_receipt_fixture(root, commit, workflow_hash)

            self.assertEqual(validate_receipts(root, commit, workflow_hash), manifest)

            # Commit mismatch rejected
            with self.assertRaises(ContractError):
                validate_receipts(root, "c" * 40, workflow_hash)

            # Content tamper rejected
            first_fname = f"{REQUIRED_RECEIPTS[0][0]}-{REQUIRED_RECEIPTS[0][1]}.json"
            (root / first_fname).write_bytes(b'{"tampered":true}')
            with self.assertRaises(ContractError):
                validate_receipts(root, commit, workflow_hash)

    def test_hosted_receipts_rejects_missing_unexpected_or_malformed(self):
        commit = "a" * 40
        workflow_hash = "b" * 64

        # Missing receipt file from disk
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            manifest = _create_valid_receipt_fixture(root, commit, workflow_hash)
            (root / f"{REQUIRED_RECEIPTS[0][0]}-{REQUIRED_RECEIPTS[0][1]}.json").unlink()
            with self.assertRaises(ContractError):
                validate_receipts(root, commit, workflow_hash)

        # Unexpected file on disk
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            manifest = _create_valid_receipt_fixture(root, commit, workflow_hash)
            (root / "unexpected.json").write_bytes(b"{}")
            with self.assertRaises(ContractError):
                validate_receipts(root, commit, workflow_hash)

        # Production enabled receipt rejected
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            manifest = _create_valid_receipt_fixture(root, commit, workflow_hash)
            bad_doc = {
                "schema": "rs9.hosted-candidate-diagnostic.v1alpha1",
                "source_commit": commit,
                "lane": REQUIRED_RECEIPTS[0][0],
                "system": REQUIRED_RECEIPTS[0][1],
                "status": "blocked",
                "production_enabled": True,
                "publication_authority": False,
                "mandatory_gates_satisfied": False,
                "artifacts": [],
            }
            bad_raw = canonical(bad_doc)
            target = root / f"{REQUIRED_RECEIPTS[0][0]}-{REQUIRED_RECEIPTS[0][1]}.json"
            target.write_bytes(bad_raw)
            # Update manifest row digest
            for r in manifest["files"]:
                if r["path"] == target.name:
                    r["sha256"] = hashlib.sha256(bad_raw).hexdigest()
                    r["size"] = len(bad_raw)
            (root / "receipts-manifest.json").write_bytes(canonical(manifest))
            with self.assertRaises(ContractError):
                validate_receipts(root, commit, workflow_hash)

    def test_summary_cannot_override_actual_receipt_outcome(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            manifest = _create_valid_receipt_fixture(root, "a" * 40, "b" * 64)
            manifest["outcomes"][0]["status"] = "diagnostic-pass"
            (root / "receipts-manifest.json").write_bytes(canonical(manifest))
            with self.assertRaises(ContractError) as raised:
                validate_receipts(root, "a" * 40, "b" * 64)
            self.assertEqual(raised.exception.code, "HOSTED_RECEIPTS")

    def test_signing_preflight_checks_bound_local_secret_and_expiry(self):
        def key(kind, capabilities, token="+", expiry="0"):
            fields = [kind, "u", "", "", "", "", expiry, "", "", "", "", capabilities, "", "", token]
            return ":".join(fields)
        fpr = lambda value: "fpr:::::::::" + value + ":"
        text = "\n".join((key("sec", "cSC"), fpr(PRIMARY), key("ssb", "s"), fpr(SIGNING)))
        facts = inspect_listing(text, now=100)
        self.assertTrue(facts["signing_bound_to_primary"] and facts["secret_available"] and facts["signing_usable"])
        for token in ("#", "card-serial", ""):
            changed = "\n".join((key("sec", "cSC"), fpr(PRIMARY), key("ssb", "s", token), fpr(SIGNING)))
            self.assertFalse(inspect_listing(changed, now=100)["secret_available"])
        expired = "\n".join((key("sec", "cSC"), fpr(PRIMARY), key("ssb", "s", expiry="99"), fpr(SIGNING)))
        self.assertFalse(inspect_listing(expired, now=100)["signing_usable"])


if __name__ == "__main__":
    unittest.main()
