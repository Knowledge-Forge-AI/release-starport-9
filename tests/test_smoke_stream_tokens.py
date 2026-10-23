"""Closed first-failure tokens, privacy and descriptor-only artifact observations."""
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from typing import ClassVar
from unittest.mock import patch

from rs9.release_core import digest
from rs9.smoke_stream_tokens import (
    collect_failure_diagnostics, evidence_inventory, stream_tokens,
    validate_inventory, validate_stream_tokens,
)


class StreamTests(unittest.TestCase):
    def test_closed_tokens_and_original_identity(self):
        raw = b"EACCES: permission denied, mkdir '/tmp/guest-work'\n"
        doc = stream_tokens(raw, complete=True)
        self.assertEqual(doc["tokens"], ["node-errno-eacces", "node-syscall-mkdir"])
        self.assertEqual(doc["sha256"], digest(raw))
        self.assertEqual(doc["bytes"], len(raw))
        self.assertNotIn("guest-work", json.dumps(doc))
        self.assertEqual(validate_stream_tokens(doc, sha256=digest(raw), byte_count=len(raw), complete=True), doc)

    def test_withhold_empty_garbled_unterminated_private_and_incomplete(self):
        cases = [(b"", True, "empty"), (b"TypeError: unterminated", True, "unterminated"),
                 (b"TypeError: \xff\n", True, "invalid-utf8"),
                 (b"TypeError: nul\0\n", True, "control-bytes"),
                 (b"TypeError: /" + b"home/" + b"private-user/data\n", True, "private"),
                 (b"TypeError: /" + b"home/" + b"runner/work/source\n", True, "private"),
                 (b"TypeError: password=redacted\n", True, "private"),
                 (("TypeError: " + "ghp_" + "x" * 36 + "\n").encode(), True, "private"),
                 (b"TypeError: ordinary\n", False, "incomplete"),
                 (b"x" * 65537, True, "oversize")]
        for raw, complete, reason in cases:
            with self.subTest(reason=reason):
                doc = stream_tokens(raw, complete=complete)
                self.assertEqual(doc["tokens"], [])
                self.assertEqual(doc["withheld_reason"], reason)
                self.assertNotIn("private-user", json.dumps(doc))
                projected = validate_stream_tokens(doc, sha256=digest(raw), byte_count=len(raw), complete=complete)
                self.assertEqual(projected, doc)
                if reason in {"incomplete", "oversize"}:
                    self.assertIsNone(doc["line_count"])
                    self.assertIsNone(doc["utf8_valid"])

    def test_token_overflow_is_explicit_and_projection_preserves_it(self):
        raw = (b"TypeError: ordinary\nReferenceError: ordinary\nSyntaxError: ordinary\n"
               b"candidate executable is not executable\n"
               b"maintained core fixture project name changed\n"
               b"maintained core fixture brand changed\n"
               b"ENOENT: no such file, open '/tmp/fixture'\n"
               b"EACCES: permission denied, mkdir '/tmp/fixture'\n")
        doc = stream_tokens(raw, complete=True)
        self.assertEqual(len(doc["tokens"]), 8)
        self.assertEqual(doc["tokens_omitted"], 2)
        self.assertEqual(validate_stream_tokens(doc, sha256=digest(raw),
            byte_count=len(raw), complete=True), doc)
        for count in (-1, True, "private", 100, 1):
            hostile = {**doc, "tokens_omitted": count}
            if count == 1 and type(count) is int:
                hostile["tokens"] = ["node-type-error"]
            projected = validate_stream_tokens(hostile, sha256=digest(raw),
                byte_count=len(raw), complete=True)
            self.assertEqual(projected["withheld_reason"], "invalid-observation")
            self.assertEqual(projected["tokens"], [])
            self.assertEqual(projected["tokens_omitted"], 0)
        duplicate = {**doc, "tokens": ["node-type-error"] * 8}
        projected = validate_stream_tokens(duplicate, sha256=digest(raw),
            byte_count=len(raw), complete=True)
        self.assertEqual(projected["withheld_reason"], "invalid-observation")
        self.assertEqual(validate_stream_tokens(projected, sha256=digest(raw),
            byte_count=len(raw), complete=True), projected)

    def test_fixed_release_message_and_untrusted_prose(self):
        doc = stream_tokens(b"candidate executable is not executable\n", complete=True)
        self.assertEqual(doc["tokens"], ["release-executable-not-executable"])
        self.assertEqual(stream_tokens(b"please report node-errno-eacces\n", complete=True)["tokens"], [])

    def test_projection_rejects_hash_size_stage_and_unknown_token(self):
        raw = b"TypeError: ordinary\n"
        doc = stream_tokens(raw, complete=True)
        for key, value in (("sha256", "f" * 64), ("bytes", len(raw) - 1),
                           ("stage", "replay"), ("tokens", ["node-type-error", "/home/private"]),
                           ("tokens", {"private": "response"}), ("withheld_reason", [])):
            with self.subTest(key=key):
                projected = validate_stream_tokens({**doc, key: value}, sha256=digest(raw),
                    byte_count=len(raw), complete=True)
                self.assertEqual(projected["tokens"], [])
                self.assertEqual(projected["withheld_reason"], "invalid-observation")
                self.assertEqual(validate_stream_tokens(projected, sha256=digest(raw),
                    byte_count=len(raw), complete=True), projected)

    def test_each_diagnostic_exception_is_independent(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("rs9.smoke_stream_tokens.stream_tokens", side_effect=OSError):
                doc = collect_failure_diagnostics(b"bad\n", {"stream_capture_complete": True}, Path(tmp), "linux-x64", "C")
            self.assertIn("evidence_inventory", doc)
            with patch("rs9.smoke_stream_tokens.evidence_inventory", side_effect=OSError):
                doc = collect_failure_diagnostics(b"bad\n", {"stream_capture_complete": True}, Path(tmp), "linux-x64", "C")
            self.assertIn("stderr_diagnostic", doc)


class InventoryTests(unittest.TestCase):
    def test_no_follow_no_private_names_or_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            private = root / "private-name"
            private.write_text("private-content")
            (root / "linux-x64-C.stdout.log").write_bytes(b"secret content")
            (root / "linux-x64-C.run.json").symlink_to(private)
            doc = evidence_inventory(root, "linux-x64", "C")
            self.assertEqual(doc["entries_observed"], 3)
            self.assertEqual(doc["unlisted"], 1)
            run = next(x for x in doc["artifacts"] if x["kind"] == "run.json")
            self.assertTrue(run["symlink"])
            self.assertFalse(run["regular"])
            self.assertNotIn("private-name", json.dumps(doc))
            self.assertNotIn("secret content", json.dumps(doc))
            self.assertEqual(validate_inventory(doc), doc)

    def test_bound_entries_and_symlink_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            directory = root / "evidence"
            directory.mkdir()
            for i in range(40):
                (directory / str(i)).touch()
            doc = evidence_inventory(directory, "linux-arm64", "B")
            self.assertEqual(doc["entries_observed"], 32)
            self.assertEqual(doc["status"], "limit-exceeded")
            self.assertEqual(validate_inventory(doc), doc)
            link = root / "link"
            link.symlink_to(directory)
            self.assertEqual(evidence_inventory(link, "linux-arm64", "B")["status"], "unavailable")

    def test_hostile_inventory_values_withheld(self):
        with tempfile.TemporaryDirectory() as tmp:
            doc = evidence_inventory(Path(tmp), "linux-x64", "C")
        for key, value in (("status", []), ("artifacts", [{"kind": "private-name"}]),
                           ("entries_observed", True), ("unlisted", 33)):
            result = validate_inventory({**doc, key: value})
            self.assertEqual(result["status"], "unavailable")
            self.assertEqual(validate_inventory(result), result)


class RunRecordAndInnerStderrTests(unittest.TestCase):
    def test_project_run_record_step_states_strict_booleans_duplicates_and_overflow(self):
        from rs9.smoke_stream_tokens import (
            MAX_STEP_ENTRIES, RUN_STAGE, SCENARIO_A_STEPS,
            project_run_record, validate_run_record,
        )

        raw_steps = [
            {"id": "app-shell", "ok": True, "via": "ipc-bridge", "detail": "SENTINEL_STEP_DETAIL"},
            {"id": "host-start", "ok": False, "via": "sidecar", "detail": "/" + "Users/" + "private/path"},
            {"id": "host-status", "ok": 1, "detail": "int-not-bool"},
            {"id": "project-open", "ok": "true"},
            {"id": "brand-read"},
            {"id": "theme-lab-compile", "ok": True},
            {"id": "theme-lab-compile", "ok": False},
            {"id": "dynamic-unlisted-step", "ok": True},
            {"id": "/" + "Users/" + "secret-step", "ok": True},
            {"id": 999, "ok": True},
            "not-a-dict-step",
        ]
        record = {"status": "fail", "receipt": {"steps": raw_steps}, "problems": []}
        identity = {"present": True, "bytes": 1779, "sha256": "a" * 64}
        projected = project_run_record(record, identity)
        self.assertEqual(projected["stage"], RUN_STAGE)
        self.assertEqual(projected["status"], "observed")
        self.assertIsNone(projected["withheld_reason"])
        self.assertEqual(projected["bytes"], 1779)
        self.assertEqual(projected["sha256"], "a" * 64)
        self.assertEqual(projected["steps_entries_observed"], 11)
        self.assertEqual(projected["steps_unlisted"], 4)
        self.assertEqual(projected["steps_omitted"], 0)
        self.assertEqual([s["id"] for s in projected["steps"]], list(SCENARIO_A_STEPS))
        state_by_id = {s["id"]: s["state"] for s in projected["steps"]}
        self.assertEqual(state_by_id, {
            "app-shell": "pass",
            "host-start": "fail",
            "host-status": "unknown",
            "project-open": "unknown",
            "brand-read": "unknown",
            "theme-lab-compile": "duplicate",
            "app-theme-status": "missing",
            "app-theme-compile": "missing",
            "brand-system-view": "missing",
            "host-status-final": "missing",
        })
        serialized = json.dumps(projected)
        for forbidden in ("SENTINEL_STEP_DETAIL", "ipc-bridge", "dynamic-unlisted-step", "secret-step"):
            self.assertNotIn(forbidden, serialized)
        self.assertEqual(validate_run_record(projected), projected)

        # Wrong-type steps (dict keyed by ID, string, None, int) -> all 10 states unknown
        for bad_steps in ({"app-shell": {"ok": True}}, "steps-string", None, 42):
            with self.subTest(bad_steps=type(bad_steps).__name__):
                doc = project_run_record({"receipt": {"steps": bad_steps}}, identity)
                self.assertEqual(doc["status"], "observed")
                self.assertEqual(doc["steps_entries_observed"], 0)
                self.assertEqual(doc["steps_unlisted"], 0)
                self.assertEqual(doc["steps_omitted"], 0)
                self.assertTrue(all(s["state"] == "unknown" for s in doc["steps"]))
                self.assertEqual(validate_run_record(doc), doc)

        # Empty list steps -> all 10 states missing
        empty_doc = project_run_record({"receipt": {"steps": []}}, identity)
        self.assertTrue(all(s["state"] == "missing" for s in empty_doc["steps"]))
        self.assertEqual(validate_run_record(empty_doc), empty_doc)

        # >64 entries: required IDs past MAX_STEP_ENTRIES become unknown (not missing)
        overflow_steps = [{"id": "app-shell", "ok": True}] + [
            {"id": f"unlisted-{i}", "ok": True} for i in range(MAX_STEP_ENTRIES)
        ] + [{"id": "host-start", "ok": True}]
        over_doc = project_run_record({"receipt": {"steps": overflow_steps}}, identity)
        self.assertEqual(over_doc["steps_entries_observed"], MAX_STEP_ENTRIES)
        self.assertEqual(over_doc["steps_unlisted"], MAX_STEP_ENTRIES - 1)
        self.assertEqual(over_doc["steps_omitted"], 2)
        over_states = {s["id"]: s["state"] for s in over_doc["steps"]}
        self.assertEqual(over_states["app-shell"], "pass")
        self.assertTrue(all(over_states[s] == "unknown" for s in SCENARIO_A_STEPS[1:]))
        self.assertEqual(validate_run_record(over_doc), over_doc)

    def test_project_run_record_problem_categories_private_suffixes_and_bounds(self):
        from rs9.smoke_stream_tokens import (
            MAX_PROBLEMS, PROBLEM_CATEGORIES, project_run_record, validate_run_record,
        )

        priv_path = "/" + "Users/" + "private-operator/Library/secret"
        priv_email = "private.user@example.com"
        priv_tok = "ghp" + "_" + "p" * 36
        # Independent literal examples from authenticated runSmoke / judgeReceipt contract
        problems = [
            "no receipt was written",
            f"receipt mode 644 {priv_path}",
            "receipt schema",
            f"receipt scenario B {priv_email}",
            f"receipt status fail: {priv_path} {priv_tok}",
            "receipt pid 4242 is not the launched process 4100",
            "receipt target x86_64-unknown-linux-gnu",
            "the running executable is not the candidate executable",
            f"required step project-open failed: {priv_path} {priv_email} {priv_tok}",
            "receipt signal expectation",
            "the application did not exit within its bound and was killed",
            "orphan candidate processes remained: 5001, 5002",
            "the signal scenario never reached its signal point",
            "no sidecar was running when the application was terminated",
            "application ended by exit 1 instead of SIGTERM",
            "application exit code 1 signal null",
            "the derived asset was not written to the case-exact project",
            "the case-distinct sibling project was modified",
            f"read-only fixture core-minimal-{priv_email} was modified",
            f"persistent user state changed: {priv_path}",
            "the candidate executable changed during the smoke run",
            f"harness error: candidate processes already running: {priv_path} {priv_tok}",
            "unrecognized problem with " + priv_path,
            12345,
            {"code": "object-problem"},
        ]
        expected_category_counts = {
            "application-bound-killed": 1,
            "application-exit-nonzero": 1,
            "candidate-executable-changed": 1,
            "derived-asset-not-written": 1,
            "harness-error": 1,
            "orphan-candidate-processes": 1,
            "persistent-user-state-changed": 1,
            "read-only-fixture-modified": 1,
            "receipt-mode-mismatch": 1,
            "receipt-not-written": 1,
            "receipt-pid-mismatch": 1,
            "receipt-scenario-mismatch": 1,
            "receipt-schema": 1,
            "receipt-signal-expectation": 1,
            "receipt-status": 1,
            "receipt-target-mismatch": 1,
            "required-step": 1,
            "running-executable-mismatch": 1,
            "sibling-project-modified": 1,
            "signal-point-not-reached": 1,
            "signal-sidecar-not-running": 1,
            "signal-termination-mismatch": 1,
        }
        self.assertEqual(set(PROBLEM_CATEGORIES.values()), set(expected_category_counts))
        identity = {"present": True, "bytes": 1779, "sha256": "b" * 64}
        doc = project_run_record({"receipt": None, "problems": problems}, identity)
        self.assertEqual(doc["status"], "observed")
        self.assertEqual(doc["problems"]["total"], len(problems))
        self.assertEqual(doc["problems"]["scanned"], len(problems))
        self.assertEqual(doc["problems"]["unrecognized"], 1)
        self.assertEqual(doc["problems"]["non_string"], 2)
        self.assertEqual(doc["problems"]["unavailable"], 0)
        self.assertEqual(
            doc["problems"]["categories"],
            [{"category": c, "count": n} for c, n in sorted(expected_category_counts.items())],
        )
        serialized = json.dumps(doc)
        for sentinel in (priv_path, priv_email, priv_tok, "unrecognized problem", "object-problem", "core-minimal"):
            self.assertNotIn(sentinel, serialized)
        self.assertEqual(validate_run_record(doc), doc)

        # Removed legacy forms, missing suffixes, missing trailing space, and appended text on exact constants
        negative_forms = [
            "candidate executable is not executable",
            "application timed out after 420000ms",
            "application process error: EACCES",
            "expected signal exit or receipt pass, got code 1",
            "expected receipt status pass, got fail",
            "receipt missing after clean signal exit",
            "partial receipt did not record host-start before signal",
            "receipt missing: receipt.json",
            "receipt platform darwin-arm64",
            "receipt steps must be an array",
            "signal cleanup left live descendants: 1234",
            "host-status-final reported live descendants",
            "host-status-final reported active host",
            "live descendants remained after exit: 1234",
            "maintained core fixture project name changed",
            "maintained core fixture brand changed",
            "read-only fixture core-minimal",
            "read-only fixture  was modified",
            "application ended by SIGKILL",
            "application ended by  instead of SIGTERM",
            "receipt statusX",
            "receipt mode644",
            "no receipt was written: extra",
            "receipt schema v2",
            "the running executable is not the candidate executable!",
            "receipt signal expectation failed",
            "the application did not exit within its bound and was killed after 420s",
            "the candidate executable changed during the smoke run!",
        ]
        neg_doc = project_run_record({"receipt": None, "problems": negative_forms}, identity)
        self.assertEqual(neg_doc["problems"]["categories"], [])
        self.assertEqual(neg_doc["problems"]["unrecognized"], len(negative_forms))
        self.assertEqual(neg_doc["problems"]["non_string"], 0)
        self.assertEqual(neg_doc["problems"]["unavailable"], 0)
        self.assertEqual(validate_run_record(neg_doc), neg_doc)

        # Empty list vs absent/non-list problems
        zero_prob_doc = project_run_record({"problems": []}, identity)
        self.assertEqual(zero_prob_doc["problems"], {
            "total": 0, "scanned": 0, "categories": [], "unrecognized": 0, "non_string": 0, "unavailable": 0,
        })
        self.assertEqual(validate_run_record(zero_prob_doc), zero_prob_doc)
        for bad_probs in (None, "not-a-list", {"a": 1}, 42):
            unavail_prob_doc = project_run_record({"problems": bad_probs}, identity)
            self.assertEqual(unavail_prob_doc["problems"], {
                "total": None, "scanned": 0, "categories": [], "unrecognized": 0, "non_string": 0, "unavailable": 1,
            })
            self.assertNotEqual(unavail_prob_doc["problems"], zero_prob_doc["problems"])
            self.assertEqual(validate_run_record(unavail_prob_doc), unavail_prob_doc)

        # Overflow >64 problems
        many_problems = ["receipt schema"] * (MAX_PROBLEMS + 10)
        many_doc = project_run_record({"problems": many_problems}, identity)
        self.assertEqual(many_doc["problems"]["total"], MAX_PROBLEMS + 10)
        self.assertEqual(many_doc["problems"]["scanned"], MAX_PROBLEMS)
        self.assertEqual(many_doc["problems"]["unavailable"], 0)
        self.assertEqual(many_doc["problems"]["categories"], [{"category": "receipt-schema", "count": MAX_PROBLEMS}])
        self.assertEqual(validate_run_record(many_doc), many_doc)

        # Unavailable run records and strict null bytes/sha256 for receipt-missing / receipt-invalid
        for err_code in ("receipt-missing", "receipt-invalid", "receipt-oversize", "receipt-corrupt", "receipt-malformed"):
            unavail = project_run_record(None, {"present": False}, receipt_error=err_code)
            self.assertEqual(unavail["status"], "unavailable")
            self.assertEqual(unavail["withheld_reason"], err_code)
            self.assertTrue(all(s["state"] == "unknown" for s in unavail["steps"]))
            self.assertIsNone(unavail["problems"]["total"])
            self.assertEqual(unavail["problems"]["unavailable"], 1)
            self.assertEqual(validate_run_record(unavail), unavail)
            if err_code in ("receipt-missing", "receipt-invalid"):
                for bad_field, bad_val in (("bytes", 10), ("sha256", "a" * 64)):
                    rejected = validate_run_record({**unavail, bad_field: bad_val})
                    self.assertEqual(rejected["withheld_reason"], "invalid-observation")
                    self.assertIsNone(rejected["bytes"])
                    self.assertIsNone(rejected["sha256"])

    def test_read_inner_stderr_physical_nofollow_and_withholding(self):
        from rs9.smoke_stream_tokens import (
            INNER_STAGE, MAX_BYTES, read_inner_stderr, validate_inner_stream_tokens,
        )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            ev = root / "evidence"
            ev.mkdir()

            # 1. Missing file
            missing = read_inner_stderr(ev, "darwin-arm64", "A")
            self.assertEqual(missing["stage"], INNER_STAGE)
            self.assertEqual(missing["read_error"], "missing")
            self.assertEqual(missing["withheld_reason"], "missing")
            self.assertIsNone(missing["bytes"])
            self.assertIsNone(missing["sha256"])
            self.assertFalse(missing["complete"])
            self.assertEqual(validate_inner_stream_tokens(missing), missing)

            # 2. Empty regular file (0 bytes)
            log_path = ev / "darwin-arm64-A.stderr.log"
            log_path.write_bytes(b"")
            empty = read_inner_stderr(ev, "darwin-arm64", "A")
            self.assertTrue(empty["complete"])
            self.assertIsNone(empty["read_error"])
            self.assertEqual(empty["bytes"], 0)
            self.assertEqual(empty["sha256"], digest(b""))
            self.assertEqual(empty["withheld_reason"], "empty")
            self.assertEqual(validate_inner_stream_tokens(empty), empty)

            # 3. Valid recognized token content
            valid_raw = b"TypeError: inner failure\nEACCES: permission denied, open '/tmp/work'\n"
            log_path.write_bytes(valid_raw)
            observed = read_inner_stderr(ev, "darwin-arm64", "A")
            self.assertTrue(observed["complete"])
            self.assertIsNone(observed["read_error"])
            self.assertEqual(observed["bytes"], len(valid_raw))
            self.assertEqual(observed["sha256"], digest(valid_raw))
            self.assertEqual(observed["tokens"], ["node-errno-eacces", "node-syscall-open", "node-type-error"])
            self.assertIsNone(observed["withheld_reason"])
            self.assertEqual(validate_inner_stream_tokens(observed), observed)

            # 4. 44-byte private inner stderr (modeled on observed 44-byte artifact)
            priv_raw = ("Error: /" + "Users/" + "op/secret-inner-token-value!!\n").encode("utf-8")
            self.assertEqual(len(priv_raw), 44)
            log_path.write_bytes(priv_raw)
            priv_doc = read_inner_stderr(ev, "darwin-arm64", "A")
            self.assertTrue(priv_doc["complete"])
            self.assertEqual(priv_doc["bytes"], 44)
            self.assertEqual(priv_doc["sha256"], digest(priv_raw))
            self.assertEqual(priv_doc["tokens"], [])
            self.assertEqual(priv_doc["withheld_reason"], "private")
            self.assertNotIn("secret-inner-token", json.dumps(priv_doc))
            self.assertEqual(validate_inner_stream_tokens(priv_doc), priv_doc)

            # 5. Invalid UTF-8 and unterminated
            for raw_bytes, expected_reason in ((b"TypeError: \xff\n", "invalid-utf8"), (b"TypeError: no-newline", "unterminated")):
                log_path.write_bytes(raw_bytes)
                doc = read_inner_stderr(ev, "darwin-arm64", "A")
                self.assertEqual(doc["withheld_reason"], expected_reason)
                self.assertEqual(doc["tokens"], [])
                self.assertEqual(validate_inner_stream_tokens(doc), doc)

            # 6. Oversize (>64 KiB)
            log_path.write_bytes(b"z" * (MAX_BYTES + 5))
            over = read_inner_stderr(ev, "darwin-arm64", "A")
            self.assertFalse(over["complete"])
            self.assertEqual(over["read_error"], "oversize")
            self.assertEqual(over["withheld_reason"], "oversize")
            self.assertEqual(over["bytes"], MAX_BYTES + 5)
            self.assertIsNone(over["sha256"])
            self.assertEqual(validate_inner_stream_tokens(over), over)

            # 7. Symlink file
            log_path.unlink()
            secret_target = root / "secret-target.txt"
            secret_target.write_text("SECRET_TARGET_CONTENT\n")
            log_path.symlink_to(secret_target)
            sym = read_inner_stderr(ev, "darwin-arm64", "A")
            self.assertEqual(sym["read_error"], "symlink")
            self.assertEqual(sym["withheld_reason"], "symlink")
            self.assertIsNone(sym["bytes"])
            self.assertIsNone(sym["sha256"])
            self.assertNotIn("SECRET_TARGET_CONTENT", json.dumps(sym))
            self.assertEqual(validate_inner_stream_tokens(sym), sym)

            # 8. Non-regular file (directory and FIFO)
            log_path.unlink()
            log_path.mkdir()
            nonreg_dir = read_inner_stderr(ev, "darwin-arm64", "A")
            self.assertEqual(nonreg_dir["read_error"], "nonregular")
            self.assertEqual(nonreg_dir["withheld_reason"], "nonregular")
            self.assertEqual(validate_inner_stream_tokens(nonreg_dir), nonreg_dir)
            log_path.rmdir()
            if hasattr(os, "mkfifo"):
                os.mkfifo(log_path)
                nonreg_fifo = read_inner_stderr(ev, "darwin-arm64", "A")
                self.assertEqual(nonreg_fifo["read_error"], "nonregular")
                self.assertEqual(nonreg_fifo["withheld_reason"], "nonregular")
                self.assertEqual(validate_inner_stream_tokens(nonreg_fifo), nonreg_fifo)
                log_path.unlink()

            # 9. Symlinked evidence directory
            ev_link = root / "evidence-link"
            ev_link.symlink_to(ev)
            sym_dir = read_inner_stderr(ev_link, "darwin-arm64", "A")
            self.assertEqual(sym_dir["read_error"], "symlink")
            self.assertEqual(sym_dir["withheld_reason"], "symlink")
            self.assertEqual(validate_inner_stream_tokens(sym_dir), sym_dir)

    def test_validators_reject_stage_relabel_binding_mismatch_and_preserve_idempotence(self):
        from rs9.smoke_stream_tokens import (
            INNER_STAGE, RUN_STAGE, project_run_record, read_inner_stderr,
            validate_inner_stream_tokens, validate_run_record,
        )

        with tempfile.TemporaryDirectory() as tmp:
            ev = Path(tmp).resolve()
            run_bytes = b'{"status":"fail","receipt":{"steps":[{"id":"app-shell","ok":true}]},"problems":["receipt schema"]}'
            inner_bytes = b"TypeError: inner error\n"
            (ev / "darwin-arm64-A.run.json").write_bytes(run_bytes)
            (ev / "darwin-arm64-A.stderr.log").write_bytes(inner_bytes)
            inv = validate_inventory(evidence_inventory(ev, "darwin-arm64", "A"))
            run_doc = project_run_record(
                json.loads(run_bytes), {"present": True, "bytes": len(run_bytes), "sha256": digest(run_bytes)}
            )
            inner_doc = read_inner_stderr(ev, "darwin-arm64", "A")

            # Valid bound projection is a 3-pass fixed point
            for fn, doc in ((validate_run_record, run_doc), (validate_inner_stream_tokens, inner_doc)):
                p1 = fn(doc, inventory=inv)
                p2 = fn(p1, inventory=inv)
                p3 = fn(p2, inventory=inv)
                self.assertEqual(p1, doc)
                self.assertEqual(p2, p1)
                self.assertEqual(p3, p2)

            # Outer stderr relabelled or passed as inner stderr is rejected as invalid-observation
            outer_doc = stream_tokens(inner_bytes, complete=True)
            relabelled = validate_inner_stream_tokens(outer_doc, inventory=inv)
            self.assertEqual(relabelled["stage"], INNER_STAGE)
            self.assertEqual(relabelled["withheld_reason"], "invalid-observation")
            self.assertEqual(relabelled["tokens"], [])
            self.assertEqual(validate_inner_stream_tokens(relabelled, inventory=inv), relabelled)

            # Inner stderr passed to outer validator is rejected
            outer_relabelled = validate_stream_tokens(
                inner_doc, sha256=digest(inner_bytes), byte_count=len(inner_bytes), complete=True
            )
            self.assertEqual(outer_relabelled["withheld_reason"], "invalid-observation")

            # Inventory byte mismatch produces persistent binding-mismatch fixed point
            bad_inv_run = validate_run_record({**run_doc, "bytes": len(run_bytes) + 1}, inventory=inv)
            self.assertEqual(bad_inv_run["status"], "unavailable")
            self.assertEqual(bad_inv_run["withheld_reason"], "binding-mismatch")
            self.assertTrue(all(s["state"] == "unknown" for s in bad_inv_run["steps"]))
            self.assertIsNone(bad_inv_run["problems"]["total"])
            self.assertEqual(bad_inv_run["problems"]["unavailable"], 1)
            self.assertEqual(validate_run_record(bad_inv_run, inventory=inv), bad_inv_run)

            bad_inv_inner = validate_inner_stream_tokens({**inner_doc, "bytes": len(inner_bytes) + 1}, inventory=inv)
            self.assertEqual(bad_inv_inner["withheld_reason"], "binding-mismatch")
            self.assertEqual(bad_inv_inner["tokens"], [])
            self.assertEqual(validate_inner_stream_tokens(bad_inv_inner, inventory=inv), bad_inv_inner)

            # Extra or unknown fields produce persistent invalid-observation fixed point
            extra_run = validate_run_record({**run_doc, "extra": "field"}, inventory=inv)
            self.assertEqual(extra_run["stage"], RUN_STAGE)
            self.assertEqual(extra_run["status"], "unavailable")
            self.assertEqual(extra_run["withheld_reason"], "invalid-observation")
            self.assertEqual(validate_run_record(extra_run, inventory=inv), extra_run)

            extra_inner = validate_inner_stream_tokens({**inner_doc, "extra": "field"}, inventory=inv)
            self.assertEqual(extra_inner["withheld_reason"], "invalid-observation")
            self.assertEqual(validate_inner_stream_tokens(extra_inner, inventory=inv), extra_inner)

    def test_collect_failure_diagnostics_darwin_isolation_and_linux_non_emission(self):
        with tempfile.TemporaryDirectory() as tmp:
            ev = Path(tmp).resolve()
            (ev / "darwin-arm64-A.stderr.log").write_bytes(b"TypeError: inner\n")
            fields = {
                "stream_capture_complete": True,
                "receipt": {"present": True, "bytes": 2, "sha256": digest(b"{}")},
                "receipt_error": "receipt-malformed",
            }
            full = collect_failure_diagnostics(b"", fields, ev, "darwin-arm64", "A", record={})
            self.assertEqual(
                set(full.keys()),
                {"stderr_diagnostic", "evidence_inventory", "harness_run_record", "inner_stderr_diagnostic"},
            )
            for target in ("stream_tokens", "evidence_inventory", "project_run_record", "read_inner_stderr"):
                with self.subTest(target=target), patch(f"rs9.smoke_stream_tokens.{target}", side_effect=RuntimeError("boom")):
                    partial = collect_failure_diagnostics(b"", fields, ev, "darwin-arm64", "A", record={})
                    self.assertEqual(len(partial), 3)

            linux_doc = collect_failure_diagnostics(b"", fields, ev, "linux-x64", "C", record={})
            self.assertEqual(set(linux_doc.keys()), {"stderr_diagnostic", "evidence_inventory"})


class LinuxProblemCategoryTests(unittest.TestCase):
    PRIV_PATH = "/" + "Users/" + "private-operator/Library/secret"
    PRIV_EMAIL = "private.user@example.com"
    PRIV_TOK = "ghp" + "_" + "p" * 36
    BINDINGS = (("x86_64-linux", "linux-x64", "C"), ("x86_64-linux", "linux-x64", "C-signal"),
                ("aarch64-linux", "linux-arm64", "B"))
    EXPECTED: ClassVar[list[dict[str, str | int]]] = [
        {"category": "application-exit-nonzero", "count": 1},
        {"category": "harness-error", "count": 1},
        {"category": "read-only-fixture-modified", "count": 1},
        {"category": "receipt-not-written", "count": 1},
        {"category": "receipt-status", "count": 1},
        {"category": "required-step", "count": 2},
        {"category": "signal-termination-mismatch", "count": 1},
    ]

    def identity(self):
        # Same-read descriptor summary exactly as sanitize_receipt_summary leaves it.
        return {"present": True, "bytes": 1779, "sha256": "c" * 64, "status": "fail",
                "problem_codes": ["withheld-token"], "problem_count": 11}

    def problems(self):
        return [
            "no receipt was written",
            f"receipt status fail: {self.PRIV_PATH} {self.PRIV_TOK}",
            f"required step project-open failed: {self.PRIV_PATH} {self.PRIV_EMAIL}",
            "application ended by exit 1 instead of SIGTERM",
            f"read-only fixture core-minimal-{self.PRIV_EMAIL} was modified",
            f"harness error: candidate processes already running: {self.PRIV_PATH}",
            "application exit code 1 signal null",
            "required step host-start failed",
            "unrecognized problem with " + self.PRIV_PATH,
            12345,
            {"code": "object-problem"},
        ]

    def project(self, record, identity=None, binding=("x86_64-linux", "linux-x64", "C")):
        from rs9.smoke_stream_tokens import project_problem_categories
        system, platform, scenario = binding
        return project_problem_categories(record, self.identity() if identity is None else identity,
                                          system=system, platform=platform, scenario=scenario)

    def validate(self, raw, *, system="x86_64-linux", scenario="C", receipt=None, receipt_error="receipt-failed",
                 raw_inventory="default-observed", mismatch=False):
        from rs9.smoke_stream_tokens import INVENTORY_STAGE, validate_problem_categories
        if raw_inventory == "default-observed":
            raw_inventory = {"stage": INVENTORY_STAGE, "status": "observed", "artifacts": [
                {"kind": "run.json", "bytes": 1779, "regular": True, "symlink": False}],
                "entries_observed": 1, "unlisted": 0}
        return validate_problem_categories(
            raw, system=system, scenario=scenario, receipt=self.identity() if receipt is None else receipt,
            receipt_error=receipt_error, inventory=validate_inventory(raw_inventory) if raw_inventory is not None else None,
            raw_inventory=raw_inventory, mismatch=mismatch)

    def small(self):
        return self.project({"problems": ["receipt schema", "required step a", "receipt schema", "unknown"]})

    def test_producer_selects_only_linux_bindings_and_reduces_private_suffixes(self):
        from rs9.smoke_stream_tokens import (
            CATEGORY_SCHEMA,
            CATEGORY_STAGE,
            project_run_record,
        )
        record = {"status": "fail", "problems": self.problems(),
                  "receipt": {"steps": [{"id": "app-shell", "ok": True, "detail": "SENTINEL_STEP"}]}}
        for binding in self.BINDINGS:
            system, _, scenario = binding
            with self.subTest(system=system, scenario=scenario):
                doc = self.project(record, binding=binding)
                self.assertEqual(doc, {
                    "schema": CATEGORY_SCHEMA, "stage": CATEGORY_STAGE, "system": system, "scenario": scenario,
                    "receipt": {"bytes": 1779, "sha256": "c" * 64},
                    "problems": {"total": 11, "scanned": 11, "categories": self.EXPECTED, "unrecognized": 1,
                                 "non_string": 2, "omitted": 0, "unavailable": 0},
                })
                # The exact existing vocabulary and matching policy, not a parallel classifier.
                self.assertEqual(doc["problems"]["categories"],
                                 project_run_record(record, self.identity())["problems"]["categories"])
                serialized = json.dumps(doc)
                for sentinel in (self.PRIV_PATH, self.PRIV_EMAIL, self.PRIV_TOK, "private-operator", "core-minimal",
                                 "unrecognized problem", "object-problem", "project-open", "host-start",
                                 "SENTINEL_STEP", "app-shell", "steps", "withheld-token", "present"):
                    self.assertNotIn(sentinel, serialized)
                self.assertEqual(self.validate(doc, system=system, scenario=scenario), doc)
        for binding in (("aarch64-darwin", "darwin-arm64", "A"), ("x86_64-linux", "linux-x64", "B"),
                        ("x86_64-linux", "linux-x64", "A"), ("aarch64-linux", "linux-arm64", "C"),
                        ("aarch64-linux", "linux-x64", "C"), ("x86_64-linux", "linux-arm64", "B"),
                        (None, "linux-x64", "C"), ("unexpected", "linux-x64", "C"),
                        (["x86_64-linux"], "linux-x64", "C"), ("x86_64-linux", "linux-x64", None)):
            with self.subTest(binding=repr(binding)):
                self.assertIsNone(self.project(record, binding=binding))

    def test_producer_requires_same_read_identity_and_dict_record(self):
        record = {"problems": ["receipt schema"]}
        good = self.identity()
        for identity in (None, {}, "1779", {"present": False}, {"present": True},
                         {"bytes": 1779, "sha256": "c" * 64},
                         {**good, "present": 1}, {**good, "present": "true"},
                         {**good, "bytes": True}, {**good, "bytes": 0}, {**good, "bytes": -1},
                         {**good, "bytes": 1024 * 1024 + 1}, {**good, "bytes": 1779.0}, {**good, "bytes": "1779"},
                         {k: v for k, v in good.items() if k != "sha256"}, {**good, "sha256": "C" * 64},
                         {**good, "sha256": "c" * 63}, {**good, "sha256": None}):
            with self.subTest(identity=repr(identity)):
                if identity is None:
                    from rs9.smoke_stream_tokens import project_problem_categories
                    self.assertIsNone(project_problem_categories(record, None, system="x86_64-linux",
                                                                 platform="linux-x64", scenario="C"))
                else:
                    self.assertIsNone(self.project(record, identity=identity))
        for record in (None, [], "record", 42, [{"problems": []}]):
            with self.subTest(record=repr(record)):
                self.assertIsNone(self.project(record))

    def test_unknown_near_match_multiline_and_non_string_forms(self):
        negative = [
            "candidate executable is not executable",
            "maintained core fixture brand changed",
            "receipt statusX", "receipt mode644", "Receipt status fail", " receipt status fail",
            "no receipt was written: extra", "no receipt was written\n", "receipt schema v2",
            "read-only fixture  was modified", "read-only fixture core-minimal",
            "application ended by SIGKILL", "application ended by  instead of SIGTERM",
            "application ended by exit 1 instead of SIGTERM\nsecond line",
            "harness error:", "", "node-errno-eacces", "receipt-status",
        ]
        doc = self.project({"problems": negative})
        self.assertEqual(doc["problems"], {"total": len(negative), "scanned": len(negative), "categories": [],
                                           "unrecognized": len(negative), "non_string": 0, "omitted": 0,
                                           "unavailable": 0})
        self.assertEqual(self.validate(doc), doc)
        multiline = ["receipt status fail\n" + self.PRIV_PATH, "read-only fixture x\ny was modified"]
        doc = self.project({"problems": multiline})
        self.assertEqual(doc["problems"]["categories"], [{"category": "read-only-fixture-modified", "count": 1},
                                                         {"category": "receipt-status", "count": 1}])
        self.assertNotIn(self.PRIV_PATH, json.dumps(doc))
        non_strings = [1, None, True, ["receipt schema"], {"code": "receipt schema"}, 1.5]
        doc = self.project({"problems": non_strings})
        self.assertEqual(doc["problems"]["non_string"], len(non_strings))
        self.assertEqual(doc["problems"]["categories"], [])
        self.assertEqual(doc["problems"]["unrecognized"], 0)
        self.assertEqual(self.validate(doc), doc)

    def test_empty_list_is_distinct_from_unavailable_problems(self):
        empty = self.project({"problems": []})
        self.assertEqual(empty["problems"], {"total": 0, "scanned": 0, "categories": [], "unrecognized": 0,
                                             "non_string": 0, "omitted": 0, "unavailable": 0})
        self.assertEqual(self.validate(empty), empty)
        for record in ({"problems": None}, {"problems": "receipt schema"}, {"problems": {"a": "receipt schema"}},
                       {"problems": 42}, {"problems": True}, {}):
            with self.subTest(record=repr(record)):
                doc = self.project(record)
                self.assertEqual(doc["problems"], {"total": None, "scanned": 0, "categories": [], "unrecognized": 0,
                                                   "non_string": 0, "omitted": 0, "unavailable": 1})
                self.assertNotEqual(doc["problems"], empty["problems"])
                self.assertEqual(self.validate(doc), doc)

    def test_scan_overflow_reports_omitted_and_ignores_items_past_window(self):
        from rs9.smoke_stream_tokens import MAX_PROBLEMS
        problems = ["receipt schema"] * MAX_PROBLEMS + ["required step " + self.PRIV_PATH] * 10
        doc = self.project({"problems": problems})
        self.assertEqual(doc["problems"], {"total": MAX_PROBLEMS + 10, "scanned": MAX_PROBLEMS,
                                           "categories": [{"category": "receipt-schema", "count": MAX_PROBLEMS}],
                                           "unrecognized": 0, "non_string": 0, "omitted": 10, "unavailable": 0})
        self.assertNotIn(self.PRIV_PATH, json.dumps(doc))
        self.assertEqual(self.validate(doc), doc)

    def test_validator_fixed_point_and_withheld_idempotence(self):
        from rs9.smoke_stream_tokens import CATEGORY_SCHEMA, CATEGORY_STAGE
        doc = self.small()
        p1 = self.validate(doc)
        p2 = self.validate(p1, receipt=dict(p1["receipt"]))
        p3 = self.validate(p2, receipt=dict(p2["receipt"]))
        self.assertEqual(p1, doc)
        self.assertEqual(p2, p1)
        self.assertEqual(p3, p2)
        self.assertIsNone(self.validate(None))
        for reason in ("invalid-observation", "binding-mismatch"):
            withheld = {"schema": CATEGORY_SCHEMA, "stage": CATEGORY_STAGE, "withheld_reason": reason}
            self.assertEqual(self.validate(withheld), withheld)
            self.assertEqual(self.validate(withheld, mismatch=True)["withheld_reason"], "binding-mismatch")
        for hostile in ({"schema": CATEGORY_SCHEMA, "stage": CATEGORY_STAGE, "withheld_reason": self.PRIV_PATH},
                        {"schema": CATEGORY_SCHEMA, "stage": CATEGORY_STAGE, "withheld_reason": "receipt-missing"},
                        {"schema": CATEGORY_SCHEMA, "stage": CATEGORY_STAGE, "withheld_reason": None},
                        {"schema": CATEGORY_SCHEMA, "stage": CATEGORY_STAGE, "withheld_reason": "binding-mismatch",
                         "system": "x86_64-linux"}):
            with self.subTest(hostile=repr(hostile)):
                projected = self.validate(hostile)
                self.assertEqual(projected, {"schema": CATEGORY_SCHEMA, "stage": CATEGORY_STAGE,
                                             "withheld_reason": "invalid-observation"})
                self.assertNotIn(self.PRIV_PATH, json.dumps(projected))

    def test_validator_rejects_structural_forgeries_as_invalid_observation(self):
        from rs9.smoke_stream_tokens import CATEGORY_SCHEMA, CATEGORY_STAGE, RUN_STAGE

        def edit(path, value=None, *, delete=False):
            doc = copy.deepcopy(self.small())
            target = doc
            for key in path[:-1]:
                target = target[key]
            if delete:
                del target[path[-1]]
            else:
                target[path[-1]] = value
            return doc

        good = self.small()
        self.assertEqual(good["problems"], {
            "total": 4, "scanned": 4, "categories": [{"category": "receipt-schema", "count": 2},
                                                     {"category": "required-step", "count": 1}],
            "unrecognized": 1, "non_string": 0, "omitted": 0, "unavailable": 0})
        cats = good["problems"]["categories"]
        unavailable = {"total": None, "scanned": 0, "categories": [], "unrecognized": 0, "non_string": 0,
                       "omitted": 0, "unavailable": 1}
        cases = {
            "not-dict-list": [], "not-dict-str": "receipt schema", "not-dict-int": 3,
            "extra-top": {**good, "raw": "receipt schema"}, "missing-receipt": edit(("receipt",), delete=True),
            "darwin-record-shape": {**good, "stage": RUN_STAGE}, "wrong-schema": edit(("schema",), "v2"),
            "wrong-stage": edit(("stage",), "original-smoke-process-stderr"),
            "darwin-system": edit(("system",), "aarch64-darwin"), "unknown-system": edit(("system",), "unexpected"),
            "list-system": edit(("system",), ["x86_64-linux"]), "unknown-scenario": edit(("scenario",), "A"),
            "cross-scenario": edit(("scenario",), "B"), "list-scenario": edit(("scenario",), ["C"]),
            "receipt-extra": edit(("receipt", "present"), True), "receipt-missing-sha": edit(("receipt", "sha256"), delete=True),
            "receipt-bool-bytes": edit(("receipt", "bytes"), True), "receipt-zero-bytes": edit(("receipt", "bytes"), 0),
            "receipt-upper-sha": edit(("receipt", "sha256"), "C" * 64), "receipt-list": edit(("receipt",), [1779]),
            "problems-extra": edit(("problems", "raw"), "receipt schema"),
            "problems-missing-omitted": edit(("problems", "omitted"), delete=True),
            "problems-list": edit(("problems",), [4]),
            "duplicate-category": edit(("problems", "categories"), [{"category": "receipt-schema", "count": 1},
                                                                     {"category": "receipt-schema", "count": 1},
                                                                     {"category": "required-step", "count": 1}]),
            "unsorted-categories": edit(("problems", "categories"), list(reversed(cats))),
            "unknown-category": edit(("problems", "categories"), [cats[0], {"category": "node-type-error", "count": 1}]),
            "raw-text-category": edit(("problems", "categories"), [cats[0], {"category": "required step a", "count": 1}]),
            "category-extra-key": edit(("problems", "categories"), [{**cats[0], "text": "receipt schema"}, cats[1]]),
            "category-dict": edit(("problems", "categories"), {"receipt-schema": 2, "required-step": 1}),
            "zero-count": edit(("problems",), {**good["problems"], "unrecognized": 2,
                                               "categories": [cats[0], {"category": "required-step", "count": 0}]}),
            "bool-count": edit(("problems", "categories"), [cats[0], {"category": "required-step", "count": True}]),
            "count-over-scanned": edit(("problems", "categories"), [{"category": "receipt-schema", "count": 5}]),
            "bool-total": edit(("problems", "total"), True),
            "bool-scanned": edit(("problems",), {**good["problems"], "total": 1, "scanned": True,
                                                 "categories": [{"category": "receipt-schema", "count": 1}],
                                                 "unrecognized": 0}),
            "bool-unavailable": edit(("problems", "unavailable"), False),
            "bool-unrecognized": edit(("problems",), {**good["problems"], "unrecognized": True}),
            "bool-non-string": edit(("problems",), {**good["problems"], "unrecognized": 0, "non_string": True}),
            "unavailable-two": edit(("problems", "unavailable"), 2),
            "sum-not-closed": edit(("problems", "unrecognized"), 2),
            "false-scanned": edit(("problems",), {**good["problems"], "scanned": 3, "omitted": 1, "unrecognized": 0}),
            "false-omitted": edit(("problems", "omitted"), 1),
            "negative-omitted": edit(("problems", "omitted"), -1),
            "total-over-bound": edit(("problems",), {**good["problems"], "total": 1024 * 1024 + 1}),
            "string-total": edit(("problems", "total"), "4"),
            "available-null-total": edit(("problems", "total"), None),
            "unavailable-with-total": edit(("problems",), {**unavailable, "total": 0}),
            "unavailable-with-categories": edit(("problems",), {**unavailable,
                                                                "categories": [{"category": "receipt-schema", "count": 1}]}),
            "unavailable-with-omitted": edit(("problems",), {**unavailable, "omitted": 1}),
            "unavailable-with-scanned": edit(("problems",), {**unavailable, "scanned": 1, "unrecognized": 1}),
        }
        for name, hostile in cases.items():
            with self.subTest(case=name):
                projected = self.validate(hostile)
                self.assertEqual(projected, {"schema": CATEGORY_SCHEMA, "stage": CATEGORY_STAGE,
                                             "withheld_reason": "invalid-observation"})
                self.assertEqual(self.validate(projected), projected)
                self.assertEqual(self.validate(hostile, mismatch=True)["withheld_reason"], "binding-mismatch")

    def test_validator_binding_receipt_and_inventory(self):
        from rs9.smoke_stream_tokens import (
            CATEGORY_SCHEMA,
            CATEGORY_STAGE,
            INVENTORY_STAGE,
            MAX_ENTRIES,
        )
        doc = self.small()
        mismatch = {"schema": CATEGORY_SCHEMA, "stage": CATEGORY_STAGE, "withheld_reason": "binding-mismatch"}
        row = {"kind": "run.json", "bytes": 1779, "regular": True, "symlink": False}

        def inventory(status="observed", artifacts=(row,), entries=None, unlisted=0):
            artifacts = [dict(a) for a in artifacts]
            entries = len(artifacts) + unlisted if entries is None else entries
            return {"stage": INVENTORY_STAGE, "status": status, "artifacts": artifacts,
                    "entries_observed": entries, "unlisted": unlisted}

        identity = self.identity()
        rejected = {
            "other-linux-system": {"system": "aarch64-linux"},
            "darwin-system": {"system": "aarch64-darwin"},
            "no-system": {"system": None},
            "other-scenario": {"scenario": "C-signal"},
            "unknown-scenario": {"scenario": "unknown"},
            "mismatch-flag": {"mismatch": True},
            "forged-length": {"receipt": {**identity, "bytes": 1780}},
            "forged-sha": {"receipt": {**identity, "sha256": "d" * 64}},
            "absent-receipt": {"receipt": {}},
            "not-present": {"receipt": {**identity, "present": False}},
            "present-not-bool": {"receipt": {**identity, "present": 1}},
            "no-bytes": {"receipt": {"present": True, "sha256": "c" * 64}},
            "bool-bytes": {"receipt": {**identity, "bytes": True}},
            "summary-extra-key": {"receipt": {**identity, "path": self.PRIV_PATH}},
            "projection-extra-key": {"receipt": {"bytes": 1779, "sha256": "c" * 64, "status": "fail"}},
            "string-receipt": {"receipt": "c" * 64},
            "receipt-missing": {"receipt_error": "receipt-missing"},
            "receipt-invalid": {"receipt_error": "receipt-invalid"},
            "receipt-oversize": {"receipt_error": "receipt-oversize"},
            "receipt-corrupt": {"receipt_error": "receipt-corrupt"},
            "inventory-absent": {"raw_inventory": None},
            "inventory-genuine-unavailable": {"raw_inventory": inventory(status="unavailable", artifacts=())},
            "inventory-limit-without-row": {"raw_inventory": inventory(
                status="limit-exceeded", artifacts=(), unlisted=MAX_ENTRIES)},
            "inventory-no-run-json": {"raw_inventory": inventory(artifacts=())},
            "inventory-other-kinds-only": {"raw_inventory": inventory(artifacts=(
                {"kind": "stderr.log", "bytes": 1779, "regular": True, "symlink": False},))},
            "inventory-byte-mismatch": {"raw_inventory": inventory(artifacts=({**row, "bytes": 1780},))},
            "inventory-symlink": {"raw_inventory": inventory(artifacts=({**row, "regular": False, "symlink": True},))},
            "inventory-nonregular": {"raw_inventory": inventory(artifacts=({**row, "regular": False},))},
            "inventory-duplicate-row": {"raw_inventory": inventory(artifacts=(row, row))},
            "inventory-hostile-fallback": {"raw_inventory": inventory(status="unavailable", artifacts=(), entries=False)},
            "inventory-wrong-stage": {"raw_inventory": {**inventory(), "stage": "replay"}},
            "inventory-limit-row-mismatch": {"raw_inventory": inventory(
                status="limit-exceeded", artifacts=({**row, "bytes": 1780},), unlisted=MAX_ENTRIES - 1)},
        }
        for name, kwargs in rejected.items():
            with self.subTest(case=name):
                projected = self.validate(doc, **kwargs)
                self.assertEqual(projected, mismatch)
                self.assertEqual(self.validate(projected, **kwargs), mismatch)
                self.assertNotIn(self.PRIV_PATH, json.dumps(projected))
        for name, raw in (("list", [row]), ("string", "observed")):
            with self.subTest(case="non-dict-inventory-" + name):
                from rs9.smoke_stream_tokens import validate_problem_categories
                self.assertEqual(validate_problem_categories(
                    doc, system="x86_64-linux", scenario="C", receipt=identity, receipt_error="receipt-failed",
                    inventory=validate_inventory(raw), raw_inventory=raw), mismatch)
        accepted = {
            "receipt-failed": {"receipt_error": "receipt-failed"},
            "receipt-malformed": {"receipt_error": "receipt-malformed"},
            "no-receipt-error": {"receipt_error": None},
            "prior-projection-receipt": {"receipt": {"bytes": 1779, "sha256": "c" * 64}},
            "inventory-observed": {"raw_inventory": inventory(unlisted=3)},
            "inventory-limit-with-row": {"raw_inventory": inventory(
                status="limit-exceeded", unlisted=MAX_ENTRIES - 1)},
        }
        for name, kwargs in accepted.items():
            with self.subTest(case=name):
                self.assertEqual(self.validate(doc, **kwargs), doc)
        aarch = self.project({"problems": ["receipt schema"]}, binding=("aarch64-linux", "linux-arm64", "B"))
        self.assertEqual(self.validate(aarch, system="aarch64-linux", scenario="B"), aarch)
        self.assertEqual(self.validate(aarch, system="x86_64-linux", scenario="B"), mismatch)
        self.assertEqual(self.validate(aarch, system="x86_64-linux", scenario="C"), mismatch)

    def test_collect_failure_diagnostics_emits_categories_only_for_bound_linux(self):
        from rs9.smoke_stream_tokens import project_problem_categories
        with tempfile.TemporaryDirectory() as tmp:
            ev = Path(tmp).resolve()
            fields = {"stream_capture_complete": True, "receipt": self.identity(), "receipt_error": "receipt-failed"}
            record = {"status": "fail", "problems": ["receipt schema", self.PRIV_PATH]}
            for system, platform, scenario in self.BINDINGS:
                with self.subTest(system=system, scenario=scenario):
                    doc = collect_failure_diagnostics(b"", fields, ev, platform, scenario, record=record, system=system)
                    self.assertEqual(set(doc), {"stderr_diagnostic", "evidence_inventory", "harness_problem_categories"})
                    self.assertEqual(doc["harness_problem_categories"], project_problem_categories(
                        record, fields["receipt"], system=system, platform=platform, scenario=scenario))
                    self.assertNotIn(self.PRIV_PATH, json.dumps(doc))
                    missing = collect_failure_diagnostics(b"", {**fields, "receipt": {"present": False},
                                                               "receipt_error": "receipt-missing"},
                                                          ev, platform, scenario, record=None, system=system)
                    self.assertEqual(set(missing), {"stderr_diagnostic", "evidence_inventory"})
            # Callers that do not pass the system keep the exact previous key set.
            legacy = collect_failure_diagnostics(b"", fields, ev, "linux-x64", "C", record=record)
            self.assertEqual(set(legacy), {"stderr_diagnostic", "evidence_inventory"})
            with patch("rs9.smoke_stream_tokens.project_problem_categories", side_effect=RuntimeError("private boom")):
                faulted = collect_failure_diagnostics(b"", fields, ev, "linux-x64", "C", record=record,
                                                      system="x86_64-linux")
            self.assertEqual(set(faulted), {"stderr_diagnostic", "evidence_inventory"})
            self.assertNotIn("private boom", json.dumps(faulted))
            (ev / "darwin-arm64-A.stderr.log").write_bytes(b"TypeError: inner\n")
            darwin = collect_failure_diagnostics(b"", fields, ev, "darwin-arm64", "A", record=record,
                                                 system="aarch64-darwin")
            self.assertEqual(set(darwin), {"stderr_diagnostic", "evidence_inventory", "harness_run_record",
                                           "inner_stderr_diagnostic"})
            # Darwin problem projection keeps its six-key shape after the shared classifier refactor.
            self.assertEqual(darwin["harness_run_record"]["problems"], {
                "total": 2, "scanned": 2, "categories": [{"category": "receipt-schema", "count": 1}],
                "unrecognized": 1, "non_string": 0, "unavailable": 0})
