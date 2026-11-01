"""Focused unit tests for the proposed current-Linux-Nix bounded inner-stderr text policy."""
import copy
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from rs9 import application_smoke_diagnostic as diagnostic, signing_fixture, smoke_stream_tokens as sst
from rs9.current_os071 import CURRENT071_REPLAY_PROGRESS_PROFILE
from rs9.errors import ContractError
from rs9.pages_smoke_diagnostic import validate_smoke_observation
from rs9.release_core import digest
from rs9.scratch import canonical
from rs9.smoke_stream_tokens import (
    CURRENT_NIX_INNER_TEXT_MAX_BYTES, CURRENT_NIX_INNER_TEXT_SCHEMA,
    CURRENT_NIX_INNER_TOKENS_SCHEMA, INVENTORY_STAGE, MAX_BYTES,
    collect_failure_diagnostics, read_inner_stderr, validate_inner_stream_tokens,
)

LINUX_BINDINGS = (
    ("x86_64-linux", "linux-x64", "C"),
    ("x86_64-linux", "linux-x64", "C-signal"),
    ("aarch64-linux", "linux-arm64", "B"),
)


def _expected_tokens_envelope(tokens, omitted=0):
    return {
        "schema": CURRENT_NIX_INNER_TOKENS_SCHEMA, "tokens": list(tokens), "tokens_omitted": omitted,
        "non_admitting": True, "native_qualified": False, "causal_attribution_proven": False,
    }


def _expected_text_envelope(text):
    return {
        "schema": CURRENT_NIX_INNER_TEXT_SCHEMA, "text": text,
        "non_admitting": True, "native_qualified": False, "causal_attribution_proven": False,
    }


def _inventory_for_stderr(byte_count, *, regular=True, symlink=False, status="observed"):
    row = {"kind": "stderr.log", "bytes": byte_count, "regular": regular, "symlink": symlink}
    artifacts = [row] if status == "observed" else []
    return {
        "stage": INVENTORY_STAGE, "status": status, "artifacts": artifacts,
        "entries_observed": len(artifacts), "unlisted": 0,
    }


class CurrentNixBoundedStderrTextTests(unittest.TestCase):
    def setUp(self):
        for target, attr in ((signing_fixture, "find_gpg_binary"), (diagnostic.subprocess, "Popen")):
            patcher = patch.object(target, attr, side_effect=AssertionError(f"Forbidden: {attr}"))
            patcher.start()
            self.addCleanup(patcher.stop)
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        self.root = Path(temp_dir.name).resolve()
        self.ev = self.root / "evidence"
        self.ev.mkdir()

    def _write_inner(self, raw, platform="linux-x64", scenario="C"):
        path = self.ev / f"{platform}-{scenario}.stderr.log"
        path.write_bytes(raw)
        return path

    def test_envelope_strict_optin_and_preservation_of_tokens_and_base(self):
        text = "TypeError: inner error\ndbus: machine-id reference\nordinary diagnostic line\n"
        self._write_inner(text.encode("utf-8"))
        base_doc = read_inner_stderr(self.ev, "linux-x64", "C")
        tok_doc = read_inner_stderr(self.ev, "linux-x64", "C", current_nix_tokens=True)
        text_only = read_inner_stderr(self.ev, "linux-x64", "C", current_nix_text=True)
        both_doc = read_inner_stderr(self.ev, "linux-x64", "C", current_nix_tokens=True, current_nix_text=True)
        self.assertNotIn("current_nix_tokens", base_doc)
        self.assertNotIn("current_nix_text", base_doc)
        self.assertNotIn("current_nix_text", tok_doc)
        self.assertNotIn("current_nix_tokens", text_only)
        self.assertEqual(both_doc["tokens"], ["node-type-error"])
        self.assertEqual(both_doc["current_nix_tokens"], _expected_tokens_envelope(["dbus-machine-id-reference"]))
        self.assertEqual(both_doc["current_nix_text"], _expected_text_envelope(text))
        self.assertEqual({k: v for k, v in both_doc.items() if k != "current_nix_text"}, tok_doc)
        self.assertEqual({k: v for k, v in text_only.items() if k != "current_nix_text"}, base_doc)
        for non_bool in (False, None, 1, "true", ["true"]):
            doc = read_inner_stderr(self.ev, "linux-x64", "C", current_nix_tokens=True, current_nix_text=non_bool)
            self.assertEqual(doc, tok_doc)

    def test_byte_boundaries_and_utf8_byte_vs_character_caps(self):
        self.assertEqual(CURRENT_NIX_INNER_TEXT_MAX_BYTES, 16384)
        for length, expect_text in ((16383, True), (16384, True), (16385, False), (MAX_BYTES, False)):
            raw = b"dbus machine-id " + b"a" * (length - 17) + b"\n"
            self.assertEqual(len(raw), length)
            self._write_inner(raw)
            doc = read_inner_stderr(self.ev, "linux-x64", "C", current_nix_tokens=True, current_nix_text=True)
            self.assertEqual((doc["withheld_reason"], doc["bytes"]), (None, length))
            self.assertEqual(doc["current_nix_tokens"], _expected_tokens_envelope(["dbus-machine-id-reference"]))
            self.assertEqual("current_nix_text" in doc, expect_text)
            if expect_text:
                self.assertEqual(doc["current_nix_text"], _expected_text_envelope(raw.decode("utf-8")))
        exact_utf8_text = ("\u00e9" * 8191) + "a\n"
        over_utf8_text = ("\u00e9" * 8192) + "\u00e9\n"
        self.assertEqual((len(exact_utf8_text), len(exact_utf8_text.encode("utf-8"))), (8193, 16384))
        self.assertEqual((len(over_utf8_text), len(over_utf8_text.encode("utf-8"))), (8194, 16387))
        self._write_inner(exact_utf8_text.encode("utf-8"))
        exact_doc = read_inner_stderr(self.ev, "linux-x64", "C", current_nix_tokens=True, current_nix_text=True)
        self.assertEqual(exact_doc["current_nix_text"], _expected_text_envelope(exact_utf8_text))
        self._write_inner(over_utf8_text.encode("utf-8"))
        over_doc = read_inner_stderr(self.ev, "linux-x64", "C", current_nix_tokens=True, current_nix_text=True)
        self.assertEqual((over_doc["withheld_reason"], "current_nix_text" in over_doc), (None, False))
        self.assertEqual(over_doc["current_nix_tokens"], _expected_tokens_envelope([]))

    def test_full_stream_withholding_guards_and_late_violation_suppression(self):
        priv_path = "/" + "Users/" + "operator/secret-dbus-path"
        cred_tok = "ghp_" + "x" * 36
        cases = (
            (b"", "empty"), (b"dbus machine-id \xff\n", "invalid-utf8"),
            (b"dbus machine-id \x00\n", "control-bytes"), (b"dbus machine-id without newline", "unterminated"),
            (f"dbus machine-id {priv_path}\n".encode("utf-8"), "private"),
            (f"dbus machine-id {cred_tok}\n".encode("utf-8"), "private"),
            (b"dbus machine-id password=secretvalue\n", "private"),
            (f"clean first line\n{priv_path}\n".encode("utf-8"), "private"),
            (f"clean first line\n{cred_tok}\n".encode("utf-8"), "private"),
            (b"clean first line\nlate control \x07\n", "control-bytes"),
            (b"dbus machine-id " + b"a" * MAX_BYTES + b"\n", "oversize"),
        )
        for raw, expected_reason in cases:
            self._write_inner(raw)
            doc = read_inner_stderr(self.ev, "linux-x64", "C", current_nix_tokens=True, current_nix_text=True)
            self.assertEqual(doc["withheld_reason"], expected_reason)
            self.assertNotIn("current_nix_tokens", doc)
            self.assertNotIn("current_nix_text", doc)
            serialized = json.dumps(doc)
            self.assertNotIn("secret-dbus-path", serialized)
            self.assertNotIn(cred_tok, serialized)

    def test_descriptor_errors_single_held_snapshot_and_independent_fault_isolation(self):
        log_path = self.ev / "linux-x64-C.stderr.log"
        doc = read_inner_stderr(self.ev, "linux-x64", "C", current_nix_tokens=True, current_nix_text=True)
        self.assertEqual((doc["withheld_reason"], "current_nix_text" in doc), ("missing", False))
        target = self.root / "target.txt"
        target.write_text("dbus machine-id\n", encoding="utf-8")
        log_path.symlink_to(target)
        doc = read_inner_stderr(self.ev, "linux-x64", "C", current_nix_tokens=True, current_nix_text=True)
        self.assertEqual((doc["withheld_reason"], "current_nix_text" in doc), ("symlink", False))
        log_path.unlink()
        log_path.mkdir()
        doc = read_inner_stderr(self.ev, "linux-x64", "C", current_nix_tokens=True, current_nix_text=True)
        self.assertEqual((doc["withheld_reason"], "current_nix_text" in doc), ("nonregular", False))
        log_path.rmdir()
        held_raw = b"dbus: machine-id reference\n"
        log_path.write_bytes(held_raw)
        with patch("rs9.smoke_stream_tokens.os.fstat", side_effect=PermissionError("denied")):
            doc = read_inner_stderr(self.ev, "linux-x64", "C", current_nix_tokens=True, current_nix_text=True)
        self.assertEqual((doc["withheld_reason"], "current_nix_text" in doc), ("read-error", False))
        real_open, orig_classify, stderr_opens = os.open, sst._classify_stream, []

        def spy_open(path, flags, *args, **kwargs):
            if str(path).endswith(".stderr.log"):
                stderr_opens.append(str(path))
            return real_open(path, flags, *args, **kwargs)

        def mutate_after_read(raw, *, stage, complete):
            log_path.write_bytes(b"org.freedesktop.portal.desktop\n/" + b"Users/leaked\n")
            return orig_classify(raw, stage=stage, complete=complete)

        with patch("rs9.smoke_stream_tokens.os.open", side_effect=spy_open), \
             patch("rs9.smoke_stream_tokens._classify_stream", side_effect=mutate_after_read):
            doc = read_inner_stderr(self.ev, "linux-x64", "C", current_nix_tokens=True, current_nix_text=True)
        self.assertEqual((len(stderr_opens), doc["bytes"], doc["sha256"]), (1, len(held_raw), digest(held_raw)))
        self.assertEqual(doc["current_nix_tokens"], _expected_tokens_envelope(["dbus-machine-id-reference"]))
        self.assertEqual(doc["current_nix_text"], _expected_text_envelope(held_raw.decode("utf-8")))
        log_path.write_bytes(held_raw)
        with patch("rs9.smoke_stream_tokens._classify_current_nix_inner_text", side_effect=RuntimeError("text boom")):
            text_faulted = read_inner_stderr(self.ev, "linux-x64", "C", current_nix_tokens=True, current_nix_text=True)
        self.assertEqual(text_faulted, read_inner_stderr(self.ev, "linux-x64", "C", current_nix_tokens=True))
        with patch("rs9.smoke_stream_tokens._classify_current_nix_inner_tokens", side_effect=RuntimeError("tok boom")):
            tok_faulted = read_inner_stderr(self.ev, "linux-x64", "C", current_nix_tokens=True, current_nix_text=True)
        self.assertEqual(tok_faulted, read_inner_stderr(self.ev, "linux-x64", "C", current_nix_text=True))

    def test_validator_idempotence_and_independent_extension_dropping(self):
        raw = b"TypeError: inner\ndbus: machine-id reference\n"
        self._write_inner(raw)
        both_doc = read_inner_stderr(self.ev, "linux-x64", "C", current_nix_tokens=True, current_nix_text=True)
        tok_only = {k: v for k, v in both_doc.items() if k != "current_nix_text"}
        text_only = {k: v for k, v in both_doc.items() if k != "current_nix_tokens"}
        inv = _inventory_for_stderr(len(raw))
        for doc in (both_doc, tok_only, text_only):
            validated = validate_inner_stream_tokens(doc, inventory=inv, require_inventory=True, current_nix_text=True)
            self.assertEqual(validated, doc)
            self.assertEqual(validate_inner_stream_tokens(validated, inventory=inv, require_inventory=True, current_nix_text=True), doc)
        ext = both_doc["current_nix_text"]
        invalid_text_exts = (
            None, [], "text", 123, {}, {k: v for k, v in ext.items() if k != "schema"},
            {**ext, "extra": True}, {**ext, "schema": "rs9.current-nix-inner-stderr-text.v0"},
            {**ext, "non_admitting": False}, {**ext, "non_admitting": 1},
            {**ext, "native_qualified": True}, {**ext, "native_qualified": 0},
            {**ext, "causal_attribution_proven": True}, {**ext, "causal_attribution_proven": 0},
            {**ext, "text": b"bytes\n"}, {**ext, "text": ""},
            {**ext, "text": "unterminated line"}, {**ext, "text": "control\x00byte\n"},
            {**ext, "text": "surrogate\ud800\n"}, {**ext, "text": "Error: /" + "Users/op/secret\n"},
            {**ext, "text": "token=" + "ghp_" + "x" * 36 + "\n"}, {**ext, "text": "password=secret\n"},
            {**ext, "text": "a" * 16384 + "\n"}, {**ext, "text": ("\u00e9" * 8192) + "\u00e9\n"},
            {**ext, "text": "different valid text\n"},
            {**ext, "text": "TypeError: inner\ndbus: machine-id referencX\n"},
            {**ext, "text": "TypeError: inner\r\ndbus: machine-id reference\n"},
        )
        for bad_text in invalid_text_exts:
            self.assertEqual(
                validate_inner_stream_tokens({**both_doc, "current_nix_text": bad_text}, inventory=inv, require_inventory=True, current_nix_text=True),
                tok_only,
            )
        self.assertEqual(
            validate_inner_stream_tokens({**both_doc, "current_nix_tokens": {"schema": "bad"}}, inventory=inv, require_inventory=True, current_nix_text=True),
            text_only,
        )

    def test_validator_withheld_base_inventory_mismatch_and_extra_keys(self):
        raw = b"dbus: machine-id reference\n"
        self._write_inner(raw)
        both_doc = read_inner_stderr(self.ev, "linux-x64", "C", current_nix_tokens=True, current_nix_text=True)
        inv = _inventory_for_stderr(len(raw))
        for bad_count in (len(raw) - 1, len(raw) + 1):
            res = validate_inner_stream_tokens({**both_doc, "bytes": bad_count}, inventory=_inventory_for_stderr(bad_count), require_inventory=True, current_nix_text=True)
            self.assertNotIn("current_nix_text", res)
        self.assertNotIn("current_nix_text", validate_inner_stream_tokens({**both_doc, "line_count": 2}, inventory=inv, require_inventory=True, current_nix_text=True))
        priv_raw = ("Error: /" + "Users/op/secret\n").encode("utf-8")
        self._write_inner(priv_raw)
        priv_base = read_inner_stderr(self.ev, "linux-x64", "C")
        priv_inv = _inventory_for_stderr(len(priv_raw))
        forged_priv = {**priv_base, "current_nix_text": _expected_text_envelope("clean\n")}
        self.assertEqual(validate_inner_stream_tokens(forged_priv, inventory=priv_inv, require_inventory=True, current_nix_text=True), priv_base)
        refused = validate_inner_stream_tokens({**both_doc, "extra_key": 1}, inventory=inv, require_inventory=True, current_nix_text=True)
        self.assertEqual((refused["withheld_reason"], "current_nix_text" in refused), ("invalid-observation", False))
        mismatched = validate_inner_stream_tokens(both_doc, inventory=inv, mismatch=True, require_inventory=True, current_nix_text=True)
        self.assertEqual((mismatched["withheld_reason"], "current_nix_text" in mismatched), ("binding-mismatch", False))
        wrong_inv = validate_inner_stream_tokens(both_doc, inventory=_inventory_for_stderr(len(raw) + 3), require_inventory=True, current_nix_text=True)
        self.assertEqual((wrong_inv["withheld_reason"], "current_nix_text" in wrong_inv), ("binding-mismatch", False))

    def test_collector_scoping_strict_booleans_and_non_linux_exclusions(self):
        text = "dbus-daemon: Failed to activate service 'org.freedesktop.portal.Desktop'\n"
        raw = text.encode("utf-8")
        fields = {
            "stream_capture_complete": True,
            "receipt": {"present": True, "bytes": 2, "sha256": digest(b"{}")},
            "receipt_error": "receipt-failed",
        }
        record = {"status": "fail", "problems": ["receipt schema"]}
        for system, platform, scenario in LINUX_BINDINGS:
            self._write_inner(raw, platform=platform, scenario=scenario)
            default_diag = collect_failure_diagnostics(b"", fields, self.ev, platform, scenario, record=record, system=system)
            cur_only = collect_failure_diagnostics(b"", fields, self.ev, platform, scenario, record=record, system=system, current071=True)
            both_diag = collect_failure_diagnostics(
                b"", fields, self.ev, platform, scenario, record=record, system=system, current071=True, current_nix_text=True
            )
            self.assertNotIn("current_nix_text", default_diag["inner_stderr_diagnostic"])
            self.assertNotIn("current_nix_text", cur_only["inner_stderr_diagnostic"])
            self.assertIn("current_nix_tokens", cur_only["inner_stderr_diagnostic"])
            self.assertEqual(both_diag["inner_stderr_diagnostic"]["current_nix_text"], _expected_text_envelope(text))
            for kwargs, expected_doc in (
                ({"current_nix_text": True}, default_diag["inner_stderr_diagnostic"]),
                ({"current071_problems": True, "current_nix_text": True}, default_diag["inner_stderr_diagnostic"]),
                ({"current071": True, "current_nix_text": 1}, cur_only["inner_stderr_diagnostic"]),
            ):
                diag = collect_failure_diagnostics(b"", fields, self.ev, platform, scenario, record=record, system=system, **kwargs)
                self.assertEqual(diag["inner_stderr_diagnostic"], expected_doc)
        self._write_inner(raw, platform="darwin-arm64", scenario="A")
        darwin_default = collect_failure_diagnostics(b"", fields, self.ev, "darwin-arm64", "A", record=record, system="aarch64-darwin")
        darwin_both = collect_failure_diagnostics(
            b"", fields, self.ev, "darwin-arm64", "A", record=record, system="aarch64-darwin", current071=True, current_nix_text=True
        )
        self.assertEqual(darwin_both["inner_stderr_diagnostic"], darwin_default["inner_stderr_diagnostic"])

    def _prepared_smoke_fixture(self):
        scratch = self.root / "scratch"
        ev = scratch / "evidence"
        ev.mkdir(parents=True)
        return {
            "source_generation": "theme-forge-current-202610", "source": self.root / "source",
            "checkout": self.root / "source", "tools": self.root / "source/tools", "scratch": scratch,
        }, ev

    def test_execute_application_smoke_caller_gates_and_60kib_shedding_order(self):
        prepared, ev = self._prepared_smoke_fixture()
        inner_text = "dbus: failed to open session.conf\nWebKitWebProcess started\n"

        def fake_run(_argv, **_kwargs):
            (ev / "linux-x64-C.run.json").write_bytes(
                canonical({"status": "fail", "problems": ["no receipt was written"], "executable": {"sha256": "a" * 64}})
            )
            (ev / "linux-x64-C.stderr.log").write_bytes(inner_text.encode("utf-8"))
            return SimpleNamespace(returncode=1, stdout=b"", stderr=b"dbus-daemon: error\n")

        for bad_kwargs in (
            {"current_nix_environment_transform": 1}, {"diagnostic_current_nix_environment_transform": "true"},
            {"current_nix_environment_transform": True}, {"diagnostic_current_nix_environment_transform": True},
        ):
            with patch.object(diagnostic, "_replay_progress_wrapper", return_value=self.root / "wrapper.mjs"), \
                 patch.object(diagnostic, "_current_replay_progress_profile", return_value=diagnostic.CURRENT_REPLAY_PROGRESS_PROFILE), \
                 self.assertRaises(ContractError):
                diagnostic.execute_application_smoke(
                    prepared=prepared, system="x86_64-linux", launch_root=self.root / "launch",
                    diagnostic_initial_observation=True, **bad_kwargs,
                )
        self.assertEqual(diagnostic._failure_diagnostic_options(
            prepared, "linux-x64", {"environment_transform": diagnostic.CURRENT_NIX_ENVIRONMENT_TRANSFORM_ID}, current_nix_text=True,
        ), {})
        for profile, extra_kwargs, expect_tokens, expect_text in (
            (diagnostic.CURRENT_REPLAY_PROGRESS_PROFILE, {}, False, False),
            (CURRENT071_REPLAY_PROGRESS_PROFILE, {}, True, False),
            (CURRENT071_REPLAY_PROGRESS_PROFILE, {"diagnostic_current_nix_environment_transform": True}, True, False),
            (CURRENT071_REPLAY_PROGRESS_PROFILE, {"current_nix_environment_transform": True}, True, True),
        ):
            with patch.object(diagnostic, "_replay_progress_wrapper", return_value=self.root / "wrapper.mjs"), \
                 patch.object(diagnostic, "_current_replay_progress_profile", return_value=profile), \
                 patch.object(diagnostic.subprocess, "run", side_effect=fake_run), \
                 self.assertRaises(ContractError) as caught:
                diagnostic.execute_application_smoke(
                    prepared=prepared, system="x86_64-linux", launch_root=self.root / "launch",
                    diagnostic_initial_observation=True, **extra_kwargs,
                )
            obs = caught.exception.smoke_observation
            self.assertEqual("current_nix_tokens" in obs["inner_stderr_diagnostic"], expect_tokens)
            self.assertNotIn("current_nix_text", obs["inner_stderr_diagnostic"])
            retained_inner = json.loads((self.root / "diagnostics/application-smoke-diagnostic.json").read_text())["initial_run"]["inner_stderr_diagnostic"]
            self.assertEqual("current_nix_text" in retained_inner, expect_text)
            self.assertEqual(validate_smoke_observation(obs, system="x86_64-linux"), obs)
        self.assertEqual(retained_inner["current_nix_text"], _expected_text_envelope(inner_text))
        self._assert_size_cap_shedding_order(prepared)


    def test_general_observation_projection_drops_free_text_by_default(self):
        raw = b"dbus machine-id fixture\n"
        self._write_inner(raw)
        doc = read_inner_stderr(self.ev, "linux-x64", "C", current_nix_tokens=True, current_nix_text=True)
        token_only = {key: value for key, value in doc.items() if key != "current_nix_text"}
        inv = _inventory_for_stderr(len(raw))
        for selector in (False, None, 1, "true"):
            result = validate_inner_stream_tokens(
                doc, inventory=inv, require_inventory=True, current_nix_text=selector)
            self.assertEqual(result, token_only)
        for system, scenario in (("x86_64-linux", "C"), ("aarch64-linux", "B"),
                                  ("aarch64-darwin", "A"), (None, "A")):
            observed = validate_smoke_observation(
                {"scenario": scenario, "inner_stderr_diagnostic": doc, "evidence_inventory": inv},
                system=system)
            self.assertEqual(observed["inner_stderr_diagnostic"], token_only)

    def test_hidden_display_controls_omit_only_new_text(self):
        for control in ("\r", "\u0085", "\u009b", "\u202e", "\u2066", "\u200d"):
            raw = ("dbus machine-id fixture " + control + "\n").encode("utf-8")
            self._write_inner(raw)
            base = read_inner_stderr(self.ev, "linux-x64", "C", current_nix_tokens=True)
            both = read_inner_stderr(
                self.ev, "linux-x64", "C", current_nix_tokens=True, current_nix_text=True)
            self.assertIsNone(base["withheld_reason"])
            self.assertEqual(both, base)
            forged = {**base, "current_nix_text": _expected_text_envelope(raw.decode("utf-8"))}
            self.assertEqual(
                validate_inner_stream_tokens(forged, inventory=_inventory_for_stderr(len(raw)),
                                             require_inventory=True, current_nix_text=True), base)

    def _assert_size_cap_shedding_order(self, prepared):
        diag_path = self.root / "diagnostics/application-smoke-diagnostic.json"
        retained = json.loads(diag_path.read_text(encoding="utf-8"))
        without_text = copy.deepcopy(retained)
        without_text["initial_run"]["inner_stderr_diagnostic"].pop("current_nix_text")
        without_both = copy.deepcopy(without_text)
        without_both["initial_run"]["inner_stderr_diagnostic"].pop("current_nix_tokens")
        caller_fields = copy.deepcopy(retained["initial_run"])
        caller_snapshot = copy.deepcopy(caller_fields)
        for cap_target in (without_text, without_both):
            with patch.object(diagnostic, "MAX_DIAGNOSTIC", len(canonical(cap_target)) + 5):
                sha = diagnostic._retain_failure(
                    prepared, "x86_64-linux", "linux-x64", "C", self.root / "launch", (), {},
                    caller_fields, ["C-signal"], include_replay=False, replay_skip_reason="boundary-probe-only",
                )
            self.assertEqual((digest(diag_path.read_bytes()), diag_path.read_bytes()), (sha, canonical(cap_target)))
            self.assertEqual(caller_fields, caller_snapshot)
