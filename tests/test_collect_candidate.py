import hashlib
import io
import json
from datetime import datetime, timezone, timedelta
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from rs9.adopt_candidate import adopt, staging_paths, main as adopt_main
from rs9.collect_candidate import (
    collect, gh_read, gh_stream_artifact, extract_safe_zip,
    REPOSITORY, WORKFLOW, _run_identity, main as collect_main
)
from rs9.errors import ContractError
from rs9.scratch import canonical


def make_custody_zip(commit, lane="wheels", system="x86_64-linux", tamper=False):
    buf = io.BytesIO()
    receipt_name = f"{lane}-{system}.json"
    receipt_bytes = json.dumps({
        "schema": "rs9.hosted-candidate-diagnostic.v1alpha1",
        "lane": lane,
        "system": system,
        "status": "diagnostic-pass"
    }).encode("utf-8")
    wheel_bytes = b"real-wheel-data-content"
    actual_file_bytes = b"tampered-wheel-data-content" if tamper else wheel_bytes
    manifest = {
        "schema": "rs9.hosted-artifact-set.v1alpha2",
        "source_commit": commit,
        "lane": lane,
        "system": system,
        "production_enabled": False,
        "publication_authority": False,
        "runner": {},
        "files": [{
            "path": "objects/wheel.whl",
            "size": len(wheel_bytes),
            "sha256": hashlib.sha256(wheel_bytes).hexdigest(),
            "kind": "custody",
            "promotion": "candidate-only"
        }],
        "qualification_receipt_hashes": {
            receipt_name: hashlib.sha256(receipt_bytes).hexdigest()
        }
    }
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(receipt_name, receipt_bytes)
        zf.writestr("objects/wheel.whl", actual_file_bytes)
        zf.writestr("artifact-manifest.json", canonical(manifest))
    return buf.getvalue()


def make_summary_zip(verdict="qualified", blockers=None):
    buf = io.BytesIO()
    summary_data = {
        "qualification_verdict": verdict,
        "blocking_reasons": blockers or []
    }
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("hosted-summary.json", json.dumps(summary_data).encode("utf-8"))
    return buf.getvalue()


class CollectionTests(unittest.TestCase):
    def test_new_push_filter_and_all_jobs_steps_artifacts_are_collected(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp).resolve()
            out = home / "Documents/agent/outbox/release-starport-9_dev/new-push"
            out.mkdir(parents=True)
            commit = "a" * 40
            started = datetime(2026, 10, 4, 14, tzinfo=timezone.utc)
            calls = []
            jobs = [{"id": index, "name": name, "status": "completed", "conclusion": "success",
                     "steps": [{"name": "execute", "conclusion": "success"}]}
                    for index, name in enumerate(("wheels-x86_64-linux", "config", "unit", "summary"), 1)]
            wheels_zip = make_custody_zip(commit)
            summary_zip = make_summary_zip("qualified", [])
            artifacts = [
                {"id": 1, "name": "candidate-wheels", "digest": "sha256:" + hashlib.sha256(wheels_zip).hexdigest(), "expired": False},
                {"id": 2, "name": "hosted-summary", "digest": "sha256:" + hashlib.sha256(summary_zip).hexdigest(), "expired": False}
            ]
            def run(root, argv):
                calls.append(argv)
                if argv[1:3] == ["run", "list"]:
                    return json.dumps([{"databaseId": 1, "headSha": commit, "event": "push", "createdAt": "2026-10-04T13:00:00Z"},
                                       {"databaseId": 2, "headSha": commit, "event": "workflow_dispatch", "createdAt": "2026-10-04T14:00:01Z"},
                                       {"databaseId": 3, "headSha": "c" * 40, "event": "push", "createdAt": "2026-10-04T14:00:01Z"},
                                       {"databaseId": 4, "headSha": commit, "event": "push", "createdAt": "2026-10-04T14:00:01Z"}])
                endpoint = argv[-1]
                if "/artifacts/1/zip" in endpoint:
                    return wheels_zip
                if "/artifacts/2/zip" in endpoint:
                    return summary_zip
                if "/jobs?" in endpoint:
                    return json.dumps({"total_count": len(jobs), "jobs": jobs})
                if "/artifacts?" in endpoint:
                    return json.dumps({"total_count": len(artifacts), "artifacts": artifacts})
                self.assertTrue(endpoint.endswith("/4"))
                return json.dumps({"id": 4, "head_sha": commit, "event": "push", "head_branch": "main",
                                   "path": ".github/workflows/" + WORKFLOW, "run_attempt": 1,
                                   "repository": {"full_name": REPOSITORY}, "created_at": "2026-10-04T14:00:01Z",
                                   "status": "completed", "conclusion": "success"})
            with patch("rs9.collect_candidate.Path.home", return_value=home), \
                 patch("rs9.hosted_contract.validate_hosted_summary", return_value={"qualification_verdict": "qualified"}), \
                 patch("rs9.hosted_contract.load_hosted_lanes", return_value={"lanes": [{"lane": "wheels", "system": "x86_64-linux", "artifact_name": "candidate-wheels"}]}):
                result = collect(home, out, commit=commit, started_at=started, timeout=30, runner=run)
            self.assertEqual(result["validation"]["status"], "pass")
            self.assertEqual(result["run_id"], 4)
            self.assertEqual(result["jobs"], [{**j, "started_at": None, "completed_at": None} for j in jobs])
            self.assertEqual(len(result["artifacts"]), 2)
            self.assertEqual(len(result["summary_files"]), 1)
            self.assertFalse(any("rerun" in c or "dispatch" in c for c in calls))
            self.assertTrue((out / "candidate-wheels" / "artifact-manifest.json").is_file())
            self.assertTrue((out / "candidate-wheels" / "objects" / "wheel.whl").is_file())
            self.assertTrue(result["artifacts"][0]["zip_digest_verified"])
            self.assertEqual(result["artifacts"][0]["manifest_sha256"], hashlib.sha256((out / "candidate-wheels/artifact-manifest.json").read_bytes()).hexdigest())

    def test_api_run_identity_rejects_reruns_and_old_pushes(self):
        commit = "a" * 40
        doc = {"head_sha": commit, "event": "push", "head_branch": "main", "path": ".github/workflows/" + WORKFLOW,
               "run_attempt": 1, "repository": {"full_name": REPOSITORY}, "created_at": "2026-10-04T13:00:00Z"}
        with self.assertRaises(ContractError):
            _run_identity(doc, commit, datetime(2026, 10, 4, 14, tzinfo=timezone.utc))
        doc["run_attempt"] = 2
        with self.assertRaises(ContractError):
            _run_identity(doc, commit)

    def test_api_run_identity_rejects_old_sha_run(self):
        commit = "a" * 40
        doc = {"head_sha": "b" * 40, "event": "push", "head_branch": "main", "path": ".github/workflows/" + WORKFLOW,
               "run_attempt": 1, "repository": {"full_name": REPOSITORY}, "created_at": "2026-10-04T14:00:01Z"}
        with self.assertRaises(ContractError) as caught:
            _run_identity(doc, commit, datetime(2026, 10, 4, 14, tzinfo=timezone.utc))
        self.assertEqual(caught.exception.code, "HOSTED_BINDING")

    def test_api_run_identity_rejects_workflow_dispatch(self):
        commit = "a" * 40
        doc = {"head_sha": commit, "event": "workflow_dispatch", "head_branch": "main", "path": ".github/workflows/" + WORKFLOW,
               "run_attempt": 1, "repository": {"full_name": REPOSITORY}, "created_at": "2026-10-04T14:00:01Z"}
        with self.assertRaises(ContractError) as caught:
            _run_identity(doc, commit, datetime(2026, 10, 4, 14, tzinfo=timezone.utc))
        self.assertEqual(caught.exception.code, "HOSTED_BINDING")

    def test_api_run_identity_clock_skew_tolerance(self):
        commit = "a" * 40
        started = datetime(2026, 10, 4, 14, 0, 0, tzinfo=timezone.utc)
        # 30 seconds before started_at is accepted due to 60s bounded clock skew tolerance
        doc = {"head_sha": commit, "event": "push", "head_branch": "main", "path": ".github/workflows/" + WORKFLOW,
               "run_attempt": 1, "repository": {"full_name": REPOSITORY}, "created_at": "2026-10-04T13:59:35Z"}
        _run_identity(doc, commit, started)
        # 61 seconds before started_at is rejected as stale
        doc["created_at"] = "2026-10-04T13:58:59Z"
        with self.assertRaises(ContractError) as caught:
            _run_identity(doc, commit, started)
        self.assertEqual(caught.exception.code, "HOSTED_BINDING")

    def test_summary_retains_all_reported_blockers_before_validation_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp).resolve()
            out = home / "Documents/agent/outbox/release-starport-9_dev/packet"
            out.mkdir(parents=True)
            commit = "a" * 40
            started = datetime(2026, 10, 4, 14, tzinfo=timezone.utc)
            blockers = ["container-pins-run-resolved-not-source-reproducible",
                        "nebular-linux-wheel-promotion-policy-pending"]
            summary_zip = make_summary_zip("not-qualified", blockers)
            def run(root, argv):
                endpoint = argv[-1]
                if "/artifacts/9/zip" in endpoint:
                    return summary_zip
                if argv[1:3] == ["run", "download"]:
                    (Path(argv[-1]) / "hosted-summary.json").write_text(json.dumps({
                        "qualification_verdict": "not-qualified", "blocking_reasons": blockers}))
                    return ""
                if "/jobs?" in endpoint:
                    return json.dumps({"total_count": 0, "jobs": []})
                if "/artifacts?" in endpoint:
                    return json.dumps({"total_count": 1, "artifacts": [{"id": 9, "name": "hosted-summary",
                        "digest": "sha256:" + hashlib.sha256(summary_zip).hexdigest(), "expired": False}]})
                return json.dumps({"id": 3, "head_sha": commit, "event": "push", "head_branch": "main",
                    "path": ".github/workflows/" + WORKFLOW, "run_attempt": 1, "status": "completed",
                    "conclusion": "failure", "repository": {"full_name": REPOSITORY},
                    "created_at": "2026-10-04T14:00:01Z"})
            with patch("rs9.collect_candidate.Path.home", return_value=home):
                result = collect(home, out, commit=commit, started_at=started, run_id=3, timeout=30, runner=run)
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
            started = datetime(2026, 10, 4, 14, tzinfo=timezone.utc)
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
                    "conclusion": "failure", "repository": {"full_name": REPOSITORY},
                    "created_at": "2026-10-04T14:00:01Z"})
            with patch("rs9.collect_candidate.Path.home", return_value=home):
                result = collect(home, out, commit=commit, started_at=started, run_id=3, timeout=30, runner=run)
            packet = json.loads((out / "manager-packet.json").read_bytes())
            self.assertEqual(packet, result)
            self.assertEqual(packet["validation"]["reasons"], ["HOSTED_ARTIFACTS"])
            self.assertEqual(packet["jobs"][0]["steps"][0]["conclusion"], "failure")
            self.assertEqual(packet["artifacts"][0]["id"], 9)
            self.assertTrue(all(c[:3] == ["gh", "api", "--method"] for c in calls))

    def test_digest_mismatch_fails_collection(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp).resolve()
            out = home / "Documents/agent/outbox/release-starport-9_dev/digest-mismatch"
            out.mkdir(parents=True)
            commit = "a" * 40
            started = datetime(2026, 10, 4, 14, tzinfo=timezone.utc)
            summary_zip = make_summary_zip("qualified", [])
            # Expected digest does not match actual zip hash
            artifacts = [{"id": 9, "name": "hosted-summary", "digest": "sha256:" + "0" * 64, "expired": False}]
            def run(root, argv):
                endpoint = argv[-1]
                if "/artifacts/9/zip" in endpoint:
                    return summary_zip
                if "/jobs?" in endpoint:
                    return json.dumps({"total_count": 0, "jobs": []})
                if "/artifacts?" in endpoint:
                    return json.dumps({"total_count": 1, "artifacts": artifacts})
                return json.dumps({"id": 3, "head_sha": commit, "event": "push", "head_branch": "main",
                    "path": ".github/workflows/" + WORKFLOW, "run_attempt": 1, "status": "completed",
                    "conclusion": "success", "repository": {"full_name": REPOSITORY},
                    "created_at": "2026-10-04T14:00:01Z"})
            with patch("rs9.collect_candidate.Path.home", return_value=home):
                result = collect(home, out, commit=commit, started_at=started, run_id=3, timeout=30, runner=run)
            self.assertEqual(result["validation"]["status"], "fail")
            self.assertEqual(result["validation"]["reasons"], ["HOSTED_ARTIFACTS"])

    def test_missing_required_lane_artifact_fails_completeness(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp).resolve()
            out = home / "Documents/agent/outbox/release-starport-9_dev/missing-art"
            out.mkdir(parents=True)
            commit = "a" * 40
            started = datetime(2026, 10, 4, 14, tzinfo=timezone.utc)
            summary_zip = make_summary_zip("qualified", [])
            # Only hosted-summary provided; candidate-wheels required by lane contract is missing
            artifacts = [{"id": 9, "name": "hosted-summary",
                          "digest": "sha256:" + hashlib.sha256(summary_zip).hexdigest(), "expired": False}]
            def run(root, argv):
                endpoint = argv[-1]
                if "/artifacts/9/zip" in endpoint:
                    return summary_zip
                if "/jobs?" in endpoint:
                    return json.dumps({"total_count": 0, "jobs": []})
                if "/artifacts?" in endpoint:
                    return json.dumps({"total_count": 1, "artifacts": artifacts})
                return json.dumps({"id": 3, "head_sha": commit, "event": "push", "head_branch": "main",
                    "path": ".github/workflows/" + WORKFLOW, "run_attempt": 1, "status": "completed",
                    "conclusion": "success", "repository": {"full_name": REPOSITORY},
                    "created_at": "2026-10-04T14:00:01Z"})
            with patch("rs9.collect_candidate.Path.home", return_value=home), \
                 patch("rs9.hosted_contract.validate_hosted_summary", return_value={"qualification_verdict": "qualified"}), \
                 patch("rs9.hosted_contract.load_hosted_lanes", return_value={"lanes": [{"lane": "wheels", "system": "x86_64-linux", "artifact_name": "candidate-wheels"}]}):
                result = collect(home, out, commit=commit, started_at=started, run_id=3, timeout=30, runner=run)
            self.assertEqual(result["validation"]["reasons"], ["HOSTED_COMPLETENESS"])

    def test_safe_zip_security_checks(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp).resolve() / "extract"
            dest.mkdir()

            # Test 1: path traversal
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as zf:
                zf.writestr("../escape.txt", b"escaped")
            zip_path = Path(tmp).resolve() / "traversal.zip"
            zip_path.write_bytes(buf.getvalue())
            with self.assertRaises(ContractError) as caught:
                extract_safe_zip(zip_path, dest)
            self.assertEqual(caught.exception.code, "HOSTED_ARTIFACTS")

            # Test 2: backslash
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as zf:
                zf.writestr("sub\\file.txt", b"backslash")
            zip_path.write_bytes(buf.getvalue())
            with self.assertRaises(ContractError) as caught:
                extract_safe_zip(zip_path, dest)
            self.assertEqual(caught.exception.code, "HOSTED_ARTIFACTS")

            # Test 3: NUL byte
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as zf:
                zf.writestr("sub_file.txt", b"nul")
            raw = bytearray(buf.getvalue())
            while True:
                idx = raw.find(b"sub_file.txt")
                if idx == -1:
                    break
                raw[idx + 3] = 0
            zip_path.write_bytes(raw)
            with self.assertRaises(ContractError) as caught:
                extract_safe_zip(zip_path, dest)
            self.assertEqual(caught.exception.code, "HOSTED_ARTIFACTS")

            # Test 4: symlink
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as zf:
                zinfo = zipfile.ZipInfo("symlink.txt")
                zinfo.create_system = 3
                zinfo.external_attr = (stat.S_IFLNK | 0o777) << 16
                zf.writestr(zinfo, b"/etc/passwd")
            zip_path.write_bytes(buf.getvalue())
            with self.assertRaises(ContractError) as caught:
                extract_safe_zip(zip_path, dest)
            self.assertEqual(caught.exception.code, "HOSTED_ARTIFACTS")

            # Test 5: duplicate member
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as zf:
                zf.writestr("dup.txt", b"first")
                zf.writestr("dup.txt", b"second")
            zip_path.write_bytes(buf.getvalue())
            with self.assertRaises(ContractError) as caught:
                extract_safe_zip(zip_path, dest)
            self.assertEqual(caught.exception.code, "HOSTED_ARTIFACTS")

            # Test 6: symlink ancestor write refused
            symlink_parent = dest / "link_dir"
            real_target = Path(tmp) / "outside"
            real_target.mkdir()
            symlink_parent.symlink_to(real_target)
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as zf:
                zf.writestr("link_dir/payload.txt", b"attack")
            zip_path.write_bytes(buf.getvalue())
            with self.assertRaises(ContractError) as caught:
                extract_safe_zip(zip_path, dest)
            self.assertEqual(caught.exception.code, "HOSTED_ARTIFACTS")

    def test_custody_verify_set_catches_tampered_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp).resolve()
            out = home / "Documents/agent/outbox/release-starport-9_dev/tamper"
            out.mkdir(parents=True)
            commit = "a" * 40
            started = datetime(2026, 10, 4, 14, tzinfo=timezone.utc)
            # Make tampered custody zip (file content doesn't match manifested sha256)
            tampered_wheels_zip = make_custody_zip(commit, tamper=True)
            summary_zip = make_summary_zip("qualified", [])
            artifacts = [
                {"id": 1, "name": "candidate-wheels", "digest": "sha256:" + hashlib.sha256(tampered_wheels_zip).hexdigest(), "expired": False},
                {"id": 2, "name": "hosted-summary", "digest": "sha256:" + hashlib.sha256(summary_zip).hexdigest(), "expired": False}
            ]
            def run(root, argv):
                endpoint = argv[-1]
                if "/artifacts/1/zip" in endpoint:
                    return tampered_wheels_zip
                if "/artifacts/2/zip" in endpoint:
                    return summary_zip
                if "/jobs?" in endpoint:
                    return json.dumps({"total_count": 0, "jobs": []})
                if "/artifacts?" in endpoint:
                    return json.dumps({"total_count": len(artifacts), "artifacts": artifacts})
                return json.dumps({"id": 4, "head_sha": commit, "event": "push", "head_branch": "main",
                                   "path": ".github/workflows/" + WORKFLOW, "run_attempt": 1,
                                   "repository": {"full_name": REPOSITORY}, "created_at": "2026-10-04T14:00:01Z",
                                   "status": "completed", "conclusion": "success"})
            with patch("rs9.collect_candidate.Path.home", return_value=home):
                result = collect(home, out, commit=commit, started_at=started, run_id=4, timeout=30, runner=run)
            self.assertEqual(result["validation"]["status"], "fail")
            self.assertEqual(result["validation"]["reasons"], ["CUSTODY_HASH"])
            self.assertTrue((out / "hosted-summary/hosted-summary.json").is_file())
            self.assertEqual(result["artifacts"][1]["collection"], "verified")

    def test_stream_bounded_limits_enforced(self):
        with tempfile.TemporaryDirectory() as tmp:
            zip_target = Path(tmp).resolve() / "artifact.zip"
            # Simulate a 100-byte stream with a max_artifact_bytes limit of 50 bytes
            data = b"x" * 100
            with self.assertRaises(ContractError) as caught:
                gh_stream_artifact(Path("."), 1, zip_target, "sha256:" + "0" * 64,
                                   runner=lambda root, argv: data, max_artifact_bytes=50)
            self.assertEqual(caught.exception.code, "HOSTED_ARTIFACTS")
            self.assertFalse(zip_target.exists())

    def test_production_stream_does_not_buffer_or_deadlock_on_stderr(self):
        real_popen = subprocess.Popen
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            data = b"x" * (192 * 1024)
            def launch(argv, **kwargs):
                self.assertEqual(kwargs["stderr"], subprocess.DEVNULL)
                return real_popen([sys.executable, "-c", "import sys; sys.stderr.buffer.write(b'e'*200000); sys.stdout.buffer.write(b'x'*196608)"], **kwargs)
            with patch("rs9.collect_candidate.subprocess.Popen", side_effect=launch):
                count = gh_stream_artifact(root, 1, root / "artifact.zip", "sha256:" + hashlib.sha256(data).hexdigest())
            self.assertEqual(count, len(data))
            self.assertEqual((root / "artifact.zip").read_bytes(), data)

    def test_production_stream_timeout_kills_process_and_cleans_partial_file(self):
        real_popen, processes = subprocess.Popen, []
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            def launch(argv, **kwargs):
                process = real_popen([sys.executable, "-c", "import sys,time; sys.stdout.buffer.write(b'x'); sys.stdout.flush(); time.sleep(30)"], **kwargs)
                processes.append(process)
                return process
            with patch("rs9.collect_candidate.subprocess.Popen", side_effect=launch), self.assertRaises(ContractError) as caught:
                gh_stream_artifact(root, 1, root / "artifact.zip", "sha256:" + "0" * 64, download_timeout=0.1)
            self.assertEqual(caught.exception.code, "HOSTED_READ")
            self.assertIsNotNone(processes[0].poll())
            self.assertFalse((root / "artifact.zip").exists())

    def test_zip_rejects_nonempty_destination_and_declared_expansion_before_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            archive = root / "input.zip"
            archive.write_bytes(make_summary_zip())
            destination = root / "output"
            destination.mkdir()
            (destination / "keep").write_bytes(b"preserved")
            with self.assertRaises(ContractError): extract_safe_zip(archive, destination)
            self.assertEqual((destination / "keep").read_bytes(), b"preserved")
            empty = root / "empty"
            with self.assertRaises(ContractError): extract_safe_zip(archive, empty, max_artifact_bytes=1)
            self.assertEqual(list(empty.iterdir()), [])

    def test_standalone_cli_requires_timezone_aware_not_before(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            # Missing --not-before
            with self.assertRaises(SystemExit):
                collect_main(["--output", str(out), "--commit", "a" * 40])
            with self.assertRaises(SystemExit):
                adopt_main(["collect", "--output", str(out), "--commit", "a" * 40])
            # Naive timestamp (no Z) stopped with exit code 2
            self.assertEqual(collect_main(["--output", str(out), "--commit", "a" * 40, "--not-before", "2026-10-04T14:00:00"]), 2)
            self.assertEqual(adopt_main(["collect", "--output", str(out), "--commit", "a" * 40, "--not-before", "2026-10-04T14:00:00"]), 2)
            # Direct collect() call rejects non-timezone-aware started_at
            with self.assertRaises(ContractError) as caught:
                collect(Path("."), out, commit="a" * 40, started_at="2026-10-04T14:00:00")
            self.assertEqual(caught.exception.code, "HOSTED_ARGUMENT")
            with self.assertRaises(ContractError) as caught:
                collect(Path("."), out, commit="a" * 40, started_at=None)
            self.assertEqual(caught.exception.code, "HOSTED_ARGUMENT")

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
                                  "production_enabled": False, "files": [], "parent": parent, "changed_paths": ["reviewed.py"]}).encode()
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
                    if args[:3] == ["diff", "--cached", "--name-only"] and parent in args: return "reviewed.py"
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
                                  commit_message="Recover hosted matrix boundaries and platform-specific Burst candidates")
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
                        self.assertNotIn("runner", collect_v2.call_args.kwargs)
                        self.assertFalse(any("rerun" in c for c in calls))
