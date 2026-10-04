import json
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from rs9.adopt_candidate import adopt, staging_paths
from rs9.collect_candidate import collect, gh_read, REPOSITORY, WORKFLOW
from rs9.errors import ContractError


class CollectionTests(unittest.TestCase):
    def test_summary_retains_all_reported_blockers_before_validation_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp).resolve()
            out = home / "Documents/agent/outbox/release-starport-9_dev/packet"
            out.mkdir(parents=True)
            commit = "a" * 40
            blockers = ["container-pins-run-resolved-not-source-reproducible",
                        "nebular-linux-wheel-promotion-policy-pending"]
            def run(root, argv):
                if argv[1:3] == ["run", "download"]:
                    (Path(argv[-1]) / "hosted-summary.json").write_text(json.dumps({
                        "qualification_verdict": "not-qualified", "blocking_reasons": blockers}))
                    return ""
                endpoint = argv[-1]
                if "/jobs?" in endpoint:
                    return json.dumps({"total_count": 0, "jobs": []})
                if "/artifacts?" in endpoint:
                    return json.dumps({"total_count": 1, "artifacts": [{"id": 9, "name": "hosted-summary",
                        "digest": "sha256:" + "b" * 64, "expired": False}]})
                return json.dumps({"id": 3, "head_sha": commit, "event": "push", "head_branch": "main",
                    "path": ".github/workflows/" + WORKFLOW, "run_attempt": 1, "status": "completed",
                    "conclusion": "failure", "repository": {"full_name": REPOSITORY}})
            with patch("rs9.collect_candidate.Path.home", return_value=home):
                result = collect(home, out, commit=commit, run_id=3, timeout=30, runner=run)
            self.assertEqual(result["validation"]["reasons"], ["HOSTED_SUMMARY"])
            self.assertEqual(result["reported_summary"]["blocking_reasons"], blockers)
            self.assertFalse(result["reported_summary"]["qualification_authority"])
            self.assertEqual(json.loads((out / "manager-packet.json").read_bytes()), result)

    def test_collection_failure_preserves_job_steps_and_artifact_custody(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp).resolve()
            out = home / "Documents/agent/outbox/release-starport-9_dev/packet"
            out.mkdir(parents=True)
            commit = "a" * 40
            calls = []
            def run(root, argv):
                calls.append(argv)
                endpoint = argv[-1]
                if "/jobs?" in endpoint:
                    return json.dumps({"total_count": 1, "jobs": [{"id": 1, "name": "rpm", "status": "completed",
                        "conclusion": "failure", "steps": [{"name": "qualify", "conclusion": "failure"}]}]})
                if "/artifacts?" in endpoint:
                    return json.dumps({"total_count": 1, "artifacts": [{"id": 9, "name": "rpm-custody",
                        "digest": "sha256:" + "b" * 64, "expired": False, "expires_at": "2027-01-01T00:00:00Z"}]})
                return json.dumps({"id": 3, "head_sha": commit, "event": "push", "head_branch": "main",
                    "path": ".github/workflows/" + WORKFLOW, "run_attempt": 1, "status": "completed",
                    "conclusion": "failure", "repository": {"full_name": REPOSITORY}})
            with patch("rs9.collect_candidate.Path.home", return_value=home):
                result = collect(home, out, commit=commit, run_id=3, timeout=30, runner=run)
            packet = json.loads((out / "manager-packet.json").read_bytes())
            self.assertEqual(packet, result)
            self.assertEqual(packet["validation"]["reasons"], ["HOSTED_ARTIFACTS"])
            self.assertEqual(packet["jobs"][0]["steps"][0]["conclusion"], "failure")
            self.assertEqual(packet["artifacts"][0]["id"], 9)
            self.assertTrue(all(c[:3] == ["gh", "api", "--method"] for c in calls))

    def test_github_write_verbs_are_refused(self):
        for argv in (["run", "rerun", "1"], ["api", "--method", "POST", "endpoint"],
                     ["api", "--method", "GET", "endpoint", "-f", "field=value"], ["release", "upload"]):
            with self.subTest(argv=argv), self.assertRaises(ContractError):
                gh_read(Path("."), argv, runner=lambda *a: self.fail("called write command"))

    def test_reviewed_deletions_staged_and_caches_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "kept.py").write_text("pass\n")
            manifest = {"files": [{"path": "kept.py"}], "deleted_paths": ["deleted.py"]}
            def git(*args):
                if "-z" in args:
                    return "kept.py" + chr(0) + "deleted.py" + chr(0)
                return ".serena/local\n.pytest_cache/cache\ncache/__pycache__/module.pyc"
            paths = staging_paths(root, manifest, git)
            self.assertIn("deleted.py", paths)
            self.assertNotIn(".serena/local", paths)
            manifest["deleted_paths"] = []
            with self.assertRaises(ContractError):
                staging_paths(root, manifest, git)

    def test_adoption_binds_repair_message_new_commit_and_v2_collector(self):
        for advanced in (False, True):
            with self.subTest(remote_advanced=advanced), tempfile.TemporaryDirectory() as tmp:
                base = Path(tmp).resolve(); root = base / "repo"; root.mkdir(); out = base / "out"; out.mkdir()
                parent, tree, commit = "a" * 40, "b" * 40, "c" * 40
                manifest = root / "operators/live1/candidate-manifest.json"
                manifest.parent.mkdir(parents=True)
                raw = json.dumps({"candidate_adoption_ready": True, "adoption_scope": "hosted-candidate-qualification-only",
                                  "production_enabled": False, "files": []}).encode()
                manifest.write_bytes(raw)
                calls = []; committed = False
                def run(repository, argv):
                    nonlocal committed
                    calls.append(argv)
                    args = argv[1:]
                    if args == ["branch", "--show-current"]: return "main"
                    if args[:2] == ["remote", "get-url"]: return "https://github.com/" + REPOSITORY + ".git"
                    if args[:1] == ["rev-parse"]:
                        return {"HEAD": commit if committed else parent, "origin/main": "d" * 40 if advanced else parent,
                                "HEAD^{tree}": tree, "HEAD^": parent}[args[1]]
                    if args == ["write-tree"]: return tree
                    if args[:1] == ["commit"]: committed = True
                    return ""
                packet = {"status": "not-qualified", "run_id": 999, "production_enabled": False,
                          "publication_authority": False, "validation": {"status": "fail"}}
                with patch("rs9.adopt_candidate.run", side_effect=run), patch("rs9.adopt_candidate.verify_inventory", return_value=tree), \
                     patch("rs9.adopt_candidate.staging_paths", return_value=["reviewed.py"]), \
                     patch("rs9.collect_candidate.output_directory", return_value=out), \
                     patch("rs9.collect_candidate.collect", return_value=packet) as collect_v2, \
                     patch("rs9.adopt_candidate.validate_receipts", side_effect=AssertionError("legacy collector reached")):
                    kwargs = dict(reviewed_parent=parent, reviewed_tree=tree, manifest_sha256=hashlib.sha256(raw).hexdigest(),
                                  commit_message="Repair hosted command authentication and hermetic source contracts")
                    if advanced:
                        with self.assertRaises(ContractError) as caught: adopt(root, out, **kwargs)
                        self.assertEqual(caught.exception.code, "ADOPTION_PARENT")
                        collect_v2.assert_not_called()
                        self.assertFalse(any(c[1] in {"add", "commit", "push"} for c in calls))
                    else:
                        result = adopt(root, out, **kwargs)
                        self.assertEqual(result["reviewed_tree"], tree)
                        self.assertIn(["git", "commit", "-m", kwargs["commit_message"]], calls)
                        self.assertIn(["git", "push", "origin", "HEAD:main"], calls)
                        self.assertEqual(collect_v2.call_args.kwargs["commit"], commit)
                        self.assertFalse(any("rerun" in c for c in calls))
