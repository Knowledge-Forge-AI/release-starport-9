"""Exact source/hosted bindings and stopped adoption safety."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from rs9.adopt_candidate import (COMMIT_OWNER_EMAIL, COMMIT_OWNER_NAME, _validate_commit_identity,
                                 adopt, run, validate_receipts)
from rs9.candidate_readiness import readiness_record
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

    def test_commit_command_overrides_all_git_identity_fields_in_a_copy(self):
        completed = type("Completed", (), {"returncode": 0, "stdout": b"ok\n"})()
        ambient = {
            "GIT_AUTHOR_NAME": "Ambient Author",
            "GIT_AUTHOR_EMAIL": "ambient-author@example.invalid",
            "GIT_COMMITTER_NAME": "Ambient Committer",
            "GIT_COMMITTER_EMAIL": "ambient-committer@example.invalid",
        }
        with patch.dict(os.environ, ambient), patch("rs9.adopt_candidate.subprocess.run", return_value=completed) as command:
            self.assertEqual(run(Path("/tmp/repository"), ["git", "commit", "-m", "message"]), "ok")
        commit_env = command.call_args.kwargs["env"]
        self.assertIsNot(commit_env, os.environ)
        self.assertEqual(
            {key: commit_env[key] for key in ambient},
            {
                "GIT_AUTHOR_NAME": COMMIT_OWNER_NAME,
                "GIT_AUTHOR_EMAIL": COMMIT_OWNER_EMAIL,
                "GIT_COMMITTER_NAME": COMMIT_OWNER_NAME,
                "GIT_COMMITTER_EMAIL": COMMIT_OWNER_EMAIL,
            },
        )

    def test_raw_commit_identity_requires_one_exact_owner_header_per_role(self):
        valid = (
            "tree " + "1" * 40 + "\n"
            "parent " + "2" * 40 + "\n"
            f"author {COMMIT_OWNER_NAME} <{COMMIT_OWNER_EMAIL}> 1700000000 +0000\n"
            f"committer {COMMIT_OWNER_NAME} <{COMMIT_OWNER_EMAIL}> 1700000001 -0400\n"
            "\nmessage\n"
        )
        _validate_commit_identity(valid)
        for invalid in (
            valid.replace("committer ", "committer Wrong <wrong@example.invalid>\ncommitter ", 1),
            valid.replace("+0000", "+00:00", 1),
            valid.replace(COMMIT_OWNER_EMAIL, "wrong@example.invalid", 1),
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ContractError) as raised:
                _validate_commit_identity(invalid)
            self.assertEqual(raised.exception.code, "ADOPTION_IDENTITY")

    def test_real_commit_uses_owner_identity_and_exact_raw_headers(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            subprocess.run(["git", "init", "-b", "main"], cwd=root, check=True, capture_output=True)
            (root / "file.txt").write_text("data\n")
            run(root, ["git", "add", "file.txt"])
            run(root, ["git", "commit", "-m", "identity fixture"])
            commit = run(root, ["git", "rev-parse", "HEAD"])
            raw = run(root, ["git", "cat-file", "commit", commit])
            _validate_commit_identity(raw)
            headers = raw.split("\n\n", 1)[0].splitlines()
            self.assertEqual(sum(line.startswith("author ") for line in headers), 1)
            self.assertEqual(sum(line.startswith("committer ") for line in headers), 1)

    def test_identity_mismatch_stops_before_push(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            repo, out = root / "repository", root / "results"
            (repo / "operators/live1").mkdir(parents=True)
            out.mkdir()
            manifest_doc = {
                "candidate_adoption_ready": False,
                "adoption_scope": "partial-diagnostic", "readiness": readiness_record(), "publication_authority": False,
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
            commit = "3" * 40
            manifest_sha = hashlib.sha256(raw).hexdigest()
            attestation = root / "manager-acceptance.json"
            attestation.write_bytes(canonical({
                "schema": "rs9.manager-source-adoption-attestation.v1alpha1",
                "decision": "accept", "source_adoption_scope": "partial-diagnostic",
                "reviewed_parent": parent, "reviewed_tree": tree, "manifest_sha256": manifest_sha,
                "full_live1_qualification": False, "production_enabled": False,
                "publication_authority": False}))
            attestation_sha = hashlib.sha256(attestation.read_bytes()).hexdigest()
            added = False
            calls = []
            wrong_identity = (
                f"tree {tree}\nparent {parent}\n"
                "author Wrong <wrong@example.invalid> 1700000000 +0000\n"
                "committer Wrong <wrong@example.invalid> 1700000000 +0000\n\nmessage\n"
            )

            def mock_git(r, args):
                nonlocal added
                calls.append(args)
                cmd = args[1:]
                if cmd == ["branch", "--show-current"]:
                    return "main"
                if cmd in (["rev-parse", "HEAD"], ["rev-parse", "origin/main"]):
                    return parent if cmd[-1] != "HEAD" or not added else commit
                if cmd == ["diff", "--cached", "--name-only"]:
                    return ""
                if cmd == ["remote", "get-url", "origin"]:
                    return "https://github.com/Knowledge-Forge-AI/release-starport-9.git"
                if cmd[:2] == ["ls-files", "-z"] or cmd[:2] == ["ls-files", "--others"]:
                    return ""
                if cmd[:3] == ["fetch", "origin", "main"]:
                    return ""
                if cmd[:3] == ["add", "-A", "--"]:
                    added = True
                    return ""
                if cmd[:2] == ["diff", "--cached"] and "--no-renames" in cmd:
                    return "src/changed.py\n"
                if cmd == ["write-tree"]:
                    return tree
                if cmd[:1] == ["commit"]:
                    return ""
                if cmd == ["rev-parse", "HEAD"]:
                    return commit
                if cmd == ["rev-parse", f"{commit}^{{tree}}"]:
                    return tree
                if cmd == ["rev-parse", f"{commit}^"]:
                    return parent
                if cmd == ["cat-file", "commit", commit]:
                    return wrong_identity
                if cmd[:1] == ["push"]:
                    raise AssertionError("identity mismatch must stop before push")
                return ""

            with patch("rs9.adopt_candidate.run", side_effect=mock_git), \
                 patch("rs9.hosted_contract.load_hosted_lanes", return_value={"lanes": [
                     {"lane": "nix", "system": s, "module": "rs9.hosted_nix"}
                     for s in ("x86_64-linux", "aarch64-linux")]}), \
                 patch("rs9.adopt_candidate.verify_inventory", return_value=tree), \
                 patch("rs9.collect_candidate.output_directory", return_value=out):
                with self.assertRaises(ContractError) as raised:
                    adopt(repo, out, reviewed_parent=parent, reviewed_tree=tree, manifest_sha256=manifest_sha,
                          manager_attestation=attestation, manager_attestation_sha256=attestation_sha)
            self.assertEqual(raised.exception.code, "ADOPTION_IDENTITY")
            self.assertIn(["git", "cat-file", "commit", commit], calls)
            self.assertFalse(any(call[1] == "push" for call in calls))

    def test_captured_commit_sha_binds_checks_and_push_when_head_moves(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            repo, out = root / "repository", root / "results"
            (repo / "operators/live1").mkdir(parents=True)
            out.mkdir()
            manifest_doc = {
                "candidate_adoption_ready": False,
                "adoption_scope": "partial-diagnostic", "readiness": readiness_record(), "publication_authority": False,
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
            commit = "3" * 40
            drift = "4" * 40
            manifest_sha = hashlib.sha256(raw).hexdigest()
            attestation = root / "manager-acceptance.json"
            attestation.write_bytes(canonical({
                "schema": "rs9.manager-source-adoption-attestation.v1alpha1",
                "decision": "accept", "source_adoption_scope": "partial-diagnostic",
                "reviewed_parent": parent, "reviewed_tree": tree, "manifest_sha256": manifest_sha,
                "full_live1_qualification": False, "production_enabled": False,
                "publication_authority": False}))
            attestation_sha = hashlib.sha256(attestation.read_bytes()).hexdigest()
            head_queries = 0
            pushed = []
            valid_identity = (
                f"tree {tree}\nparent {parent}\n"
                f"author {COMMIT_OWNER_NAME} <{COMMIT_OWNER_EMAIL}> 1700000000 +0000\n"
                f"committer {COMMIT_OWNER_NAME} <{COMMIT_OWNER_EMAIL}> 1700000000 +0000\n\nmessage\n"
            )

            def mock_git(r, args):
                nonlocal head_queries
                cmd = args[1:]
                if cmd == ["branch", "--show-current"]:
                    return "main"
                if cmd == ["rev-parse", "HEAD"]:
                    head_queries += 1
                    if head_queries <= 2:
                        return parent
                    if head_queries == 3:
                        return commit
                    return drift
                if cmd == ["rev-parse", "origin/main"]:
                    return parent
                if cmd == ["diff", "--cached", "--name-only"]:
                    return ""
                if cmd == ["remote", "get-url", "origin"]:
                    return "https://github.com/Knowledge-Forge-AI/release-starport-9.git"
                if cmd[:2] == ["ls-files", "-z"] or cmd[:2] == ["ls-files", "--others"]:
                    return ""
                if cmd[:3] == ["fetch", "origin", "main"]:
                    return ""
                if cmd[:3] == ["add", "-A", "--"]:
                    return ""
                if cmd[:2] == ["diff", "--cached"] and "--no-renames" in cmd:
                    return "src/changed.py\n"
                if cmd == ["write-tree"]:
                    return tree
                if cmd[:1] == ["commit"]:
                    return ""
                if cmd == ["rev-parse", f"{commit}^{{tree}}"]:
                    return tree
                if cmd == ["rev-parse", f"{commit}^"]:
                    return parent
                if cmd == ["cat-file", "commit", commit]:
                    return valid_identity
                if cmd[:1] == ["push"]:
                    pushed.append(args)
                    return ""
                return ""

            with patch("rs9.adopt_candidate.run", side_effect=mock_git), \
                 patch("rs9.hosted_contract.load_hosted_lanes", return_value={"lanes": [
                     {"lane": "nix", "system": s, "module": "rs9.hosted_nix"}
                     for s in ("x86_64-linux", "aarch64-linux")] }), \
                 patch("rs9.adopt_candidate.verify_inventory", return_value=tree), \
                 patch("rs9.collect_candidate.output_directory", return_value=out), \
                 patch("rs9.collect_candidate.collect", return_value={
                     "status": "not-qualified", "run_id": 1, "validation": {"status": "fail"}
                 }), \
                 patch("rs9.collect_candidate.write_packet"):
                result = adopt(repo, out, reviewed_parent=parent, reviewed_tree=tree, manifest_sha256=manifest_sha,
                               manager_attestation=attestation, manager_attestation_sha256=attestation_sha)
            self.assertEqual(result["status"], "not-qualified")
            self.assertEqual(head_queries, 3)
            self.assertEqual(pushed, [["git", "push", "origin", f"{commit}:refs/heads/main"]])

    def test_adopt_stages_exactly_changed_paths_and_verifies_cached_set(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            repo, out = root / "repository", root / "results"
            (repo / "operators/live1").mkdir(parents=True)
            out.mkdir()
            manifest_doc = {
                "candidate_adoption_ready": False,
                "adoption_scope": "partial-diagnostic", "readiness": readiness_record(), "publication_authority": False,
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
            attestation = root / "manager-acceptance.json"
            attestation.write_bytes(canonical({
                "schema": "rs9.manager-source-adoption-attestation.v1alpha1",
                "decision": "accept", "source_adoption_scope": "partial-diagnostic",
                "reviewed_parent": parent, "reviewed_tree": tree, "manifest_sha256": manifest_sha,
                "full_live1_qualification": False, "production_enabled": False,
                "publication_authority": False}))
            attestation_sha = hashlib.sha256(attestation.read_bytes()).hexdigest()

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
                 patch("rs9.hosted_contract.load_hosted_lanes", return_value={"lanes": [
                     {"lane": "nix", "system": s, "module": "rs9.hosted_nix"}
                     for s in ("x86_64-linux", "aarch64-linux")]}), \
                 patch("rs9.adopt_candidate.verify_inventory", return_value=tree), \
                 patch("rs9.collect_candidate.output_directory", return_value=out):
                with self.assertRaises(ContractError) as caught:
                    adopt(repo, out, reviewed_parent=parent, reviewed_tree=tree, manifest_sha256=manifest_sha,
                          manager_attestation=attestation, manager_attestation_sha256=attestation_sha)
                self.assertEqual(caught.exception.code, "ADOPTION_REVIEW")
                self.assertTrue(added)

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
