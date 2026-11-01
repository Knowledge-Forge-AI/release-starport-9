"""Focused unit tests for the proposed current-Linux-Nix inner-stderr token policy."""
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
    CURRENT_NIX_INNER_TOKEN_RULES, CURRENT_NIX_INNER_TOKENS, CURRENT_NIX_INNER_TOKENS_SCHEMA,
    INVENTORY_STAGE, MAX_BYTES, MAX_TOKENS, TOKENS,
    collect_failure_diagnostics, read_inner_stderr, validate_inner_stream_tokens,
)

LINUX_BINDINGS = (
    ("x86_64-linux", "linux-x64", "C"),
    ("x86_64-linux", "linux-x64", "C-signal"),
    ("aarch64-linux", "linux-arm64", "B"),
)
SINGLE_CLASS_SAMPLES = (
    ("dbus-config-read-failed", "DBus daemon: Failed to open configuration /etc/dbus-1\n"),
    ("dbus-config-read-failed", "dbus-daemon: failed to load session.conf in container\n"),
    ("dbus-config-read-failed", "dbus: failed to open system.conf during init\n"),
    ("dbus-service-activation-failed", "dbus-daemon: Failed to activate service 'org.a11y.Bus'\n"),
    ("dbus-program-exec-failed", "dbus-daemon: Failed to execute program org.freedesktop.portal\n"),
    ("dbus-program-exec-failed", "dbus-run-session: failed to exec child helper\n"),
    ("dbus-address-connect-failed", "DBus client: failed to connect to socket address\n"),
    ("dbus-address-connect-failed", "dbus: Could not connect to session bus\n"),
    ("dbus-machine-id-reference", "dbus[99]: machine-id was referenced during startup\n"),
    ("portal-desktop-reference", "proxy lookup for org.freedesktop.portal.Desktop interface\n"),
    ("portal-settings-reference", "calling org.freedesktop.portal.Settings.ReadAll\n"),
    ("webkit-webprocess-reference", "spawned WebKitWebProcess helper for view\n"),
    ("webkit-networkprocess-reference", "spawned WebKitNetworkProcess helper for view\n"),
    ("sandbox-helper-reference", "launching bwrap sandbox helper\n"),
    ("sandbox-helper-reference", "launching xdg-dbus-proxy helper\n"),
    ("gsettings-schema-reference", "GLib-GIO: gsettings backend initialized\n"),
    ("gsettings-schema-reference", "GLib-GIO: Settings schema lookup observed\n"),
)
CROSS_LINE_NEGATIVES = (
    b"dbus daemon notice\nfailed to open session.conf\n",
    b"dbus: failed to open\nsession.conf on next line\n",
    b"dbus daemon notice\nfailed to activate service org.example\n",
    b"dbus daemon notice\nfailed to execute program helper\n",
    b"dbus daemon notice\nfailed to exec helper\n",
    b"dbus daemon notice\nfailed to connect to bus\n",
    b"dbus daemon notice\ncould not connect to bus\n",
    b"dbus daemon notice\nmachine-id missing on separate line\n",
)


def _expected_nix_envelope(tokens, omitted=0):
    return {
        "schema": CURRENT_NIX_INNER_TOKENS_SCHEMA,
        "tokens": list(tokens),
        "tokens_omitted": omitted,
        "non_admitting": True,
        "native_qualified": False,
        "causal_attribution_proven": False,
    }


def _inventory_for_stderr(byte_count, *, regular=True, symlink=False, status="observed"):
    row = {"kind": "stderr.log", "bytes": byte_count, "regular": regular, "symlink": symlink}
    artifacts = [row] if status == "observed" else []
    return {
        "stage": INVENTORY_STAGE,
        "status": status,
        "artifacts": artifacts,
        "entries_observed": len(artifacts),
        "unlisted": 0,
    }


class CurrentNixInnerStderrTokenTests(unittest.TestCase):
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

    def test_literal_classes_same_line_constraints_and_legacy_disjointness(self):
        self.assertEqual(len(CURRENT_NIX_INNER_TOKEN_RULES), 11)
        self.assertEqual(len(CURRENT_NIX_INNER_TOKENS), 11)
        self.assertTrue(CURRENT_NIX_INNER_TOKENS.isdisjoint(TOKENS))
        seen_classes = set()
        for expected_token, sample_line in SINGLE_CLASS_SAMPLES:
            seen_classes.add(expected_token)
            self._write_inner(sample_line.encode("utf-8"))
            default_doc = read_inner_stderr(self.ev, "linux-x64", "C")
            optin_doc = read_inner_stderr(self.ev, "linux-x64", "C", current_nix_tokens=True)
            self.assertNotIn("current_nix_tokens", default_doc)
            self.assertEqual(optin_doc["tokens"], [])
            self.assertEqual(optin_doc["current_nix_tokens"], _expected_nix_envelope([expected_token]))
            self.assertEqual({k: v for k, v in optin_doc.items() if k != "current_nix_tokens"}, default_doc)
        self.assertEqual(seen_classes, set(CURRENT_NIX_INNER_TOKENS))
        for raw_negative in CROSS_LINE_NEGATIVES:
            self._write_inner(raw_negative)
            doc = read_inner_stderr(self.ev, "linux-x64", "C", current_nix_tokens=True)
            self.assertEqual(doc["current_nix_tokens"], _expected_nix_envelope([]))

    def test_empty_eligible_duplicates_sorting_cap_and_omitted_count(self):
        self._write_inner(b"ordinary line one\nordinary line two\n")
        empty_match = read_inner_stderr(self.ev, "linux-x64", "C", current_nix_tokens=True)
        self.assertIsNone(empty_match["withheld_reason"])
        self.assertEqual(empty_match["current_nix_tokens"], _expected_nix_envelope([], 0))
        self._write_inner(
            b"TypeError: inner error\nspawning WebKitWebProcess and bwrap\n"
            b"dbus machine-id check and WebKitWebProcess retry\n"
        )
        dup_doc = read_inner_stderr(self.ev, "linux-x64", "C", current_nix_tokens=True)
        self.assertEqual(dup_doc["tokens"], ["node-type-error"])
        expected_dup = ["dbus-machine-id-reference", "sandbox-helper-reference", "webkit-webprocess-reference"]
        self.assertEqual(dup_doc["current_nix_tokens"], _expected_nix_envelope(expected_dup, 0))
        self._write_inner("".join(line for _, line in SINGLE_CLASS_SAMPLES).encode("utf-8"))
        capped = read_inner_stderr(self.ev, "linux-x64", "C", current_nix_tokens=True)
        all_sorted = sorted(CURRENT_NIX_INNER_TOKENS)
        self.assertEqual(
            capped["current_nix_tokens"],
            _expected_nix_envelope(all_sorted[:MAX_TOKENS], len(all_sorted) - MAX_TOKENS),
        )
        self.assertEqual(capped["current_nix_tokens"]["tokens_omitted"], 3)
        with patch("rs9.smoke_stream_tokens._classify_current_nix_inner_tokens", side_effect=RuntimeError("boom")):
            self.assertEqual(read_inner_stderr(self.ev, "linux-x64", "C", current_nix_tokens=True),
                             read_inner_stderr(self.ev, "linux-x64", "C"))

    def test_withholding_guards_suppress_extension_on_all_ineligible_inputs(self):
        priv_path = "/" + "Users/" + "operator/secret-dbus-path"
        cred_tok = "ghp_" + "x" * 36
        content_cases = (
            (b"", "empty"),
            (b"dbus machine-id \xff\n", "invalid-utf8"),
            (b"dbus machine-id \x00\n", "control-bytes"),
            (b"dbus machine-id without newline", "unterminated"),
            (f"dbus machine-id {priv_path}\n".encode("utf-8"), "private"),
            (f"dbus machine-id {cred_tok}\n".encode("utf-8"), "private"),
            (b"dbus machine-id password=secretvalue\n", "private"),
            (b"dbus machine-id " + b"a" * MAX_BYTES + b"\n", "oversize"),
        )
        for raw, expected_reason in content_cases:
            self._write_inner(raw)
            doc = read_inner_stderr(self.ev, "linux-x64", "C", current_nix_tokens=True)
            self.assertEqual(doc["withheld_reason"], expected_reason)
            self.assertNotIn("current_nix_tokens", doc)
            self.assertNotIn("secret-dbus-path", json.dumps(doc))
            self.assertNotIn(cred_tok, json.dumps(doc))

    def test_descriptor_errors_single_held_read_and_changed_byte_withholding(self):
        log_path = self.ev / "linux-x64-C.stderr.log"
        doc = read_inner_stderr(self.ev, "linux-x64", "C", current_nix_tokens=True)
        self.assertEqual((doc["withheld_reason"], "current_nix_tokens" in doc), ("missing", False))
        target = self.root / "target.txt"
        target.write_text("dbus machine-id\n", encoding="utf-8")
        log_path.symlink_to(target)
        doc = read_inner_stderr(self.ev, "linux-x64", "C", current_nix_tokens=True)
        self.assertEqual((doc["withheld_reason"], "current_nix_tokens" in doc), ("symlink", False))
        log_path.unlink()
        log_path.mkdir()
        doc = read_inner_stderr(self.ev, "linux-x64", "C", current_nix_tokens=True)
        self.assertEqual((doc["withheld_reason"], "current_nix_tokens" in doc), ("nonregular", False))
        log_path.rmdir()
        held_raw = b"dbus: machine-id reference\n"
        log_path.write_bytes(held_raw)
        with patch("rs9.smoke_stream_tokens.os.fstat", side_effect=PermissionError("denied")):
            doc = read_inner_stderr(self.ev, "linux-x64", "C", current_nix_tokens=True)
        self.assertEqual((doc["withheld_reason"], "current_nix_tokens" in doc), ("read-error", False))
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
            doc = read_inner_stderr(self.ev, "linux-x64", "C", current_nix_tokens=True)
        self.assertEqual((len(stderr_opens), doc["bytes"], doc["sha256"]), (1, len(held_raw), digest(held_raw)))
        self.assertEqual(doc["current_nix_tokens"], _expected_nix_envelope(["dbus-machine-id-reference"]))
        doc = validate_inner_stream_tokens(doc, inventory=_inventory_for_stderr(len(held_raw) + 5), require_inventory=True)
        self.assertEqual((doc["withheld_reason"], "current_nix_tokens" in doc), ("binding-mismatch", False))

    def test_validator_idempotence_drops_invalid_extension_and_refuses_bad_base(self):
        raw = b"TypeError: inner\ndbus: machine-id reference\n"
        self._write_inner(raw)
        valid_doc = read_inner_stderr(self.ev, "linux-x64", "C", current_nix_tokens=True)
        base_only = {k: v for k, v in valid_doc.items() if k != "current_nix_tokens"}
        inv = _inventory_for_stderr(len(raw))
        p1 = validate_inner_stream_tokens(valid_doc, inventory=inv, require_inventory=True)
        self.assertEqual(p1, valid_doc)
        self.assertEqual(validate_inner_stream_tokens(p1, inventory=inv, require_inventory=True), valid_doc)
        ext = valid_doc["current_nix_tokens"]
        all_eight = sorted(CURRENT_NIX_INNER_TOKENS)[:MAX_TOKENS]
        invalid_extensions = (
            None,
            [],
            "tokens",
            123,
            {},
            {k: v for k, v in ext.items() if k != "schema"},
            {**ext, "extra": True},
            {**ext, "schema": "rs9.current-nix-inner-stderr-tokens.v0"},
            {**ext, "non_admitting": False},
            {**ext, "non_admitting": 1},
            {**ext, "native_qualified": True},
            {**ext, "native_qualified": 0},
            {**ext, "causal_attribution_proven": True},
            {**ext, "tokens": "dbus-machine-id-reference"},
            {**ext, "tokens": [123]},
            {**ext, "tokens": [{}]},
            {**ext, "tokens": ["node-type-error"]},
            {**ext, "tokens": ["/Users/private/path"]},
            {**ext, "tokens": ["dbus-machine-id-reference", "dbus-machine-id-reference"]},
            {**ext, "tokens": ["webkit-webprocess-reference", "dbus-machine-id-reference"]},
            {**ext, "tokens": sorted(CURRENT_NIX_INNER_TOKENS)[:MAX_TOKENS + 1]},
            {**ext, "tokens_omitted": True},
            {**ext, "tokens_omitted": -1},
            {**ext, "tokens_omitted": 1},
            {**ext, "tokens": all_eight, "tokens_omitted": 4},
        )
        for bad_ext in invalid_extensions:
            dropped = validate_inner_stream_tokens(
                {**base_only, "current_nix_tokens": bad_ext}, inventory=inv, require_inventory=True
            )
            self.assertEqual(dropped, base_only)
            self.assertEqual(validate_inner_stream_tokens(dropped, inventory=inv, require_inventory=True), base_only)

    def test_validator_drops_extension_on_withheld_base_and_refuses_extra_base_keys(self):
        priv_raw = ("Error: /" + "Users/" + "op/secret\n").encode("utf-8")
        self._write_inner(priv_raw)
        priv_base = read_inner_stderr(self.ev, "linux-x64", "C")
        inv = _inventory_for_stderr(len(priv_raw))
        forged_priv = {**priv_base, "current_nix_tokens": _expected_nix_envelope(["dbus-machine-id-reference"])}
        cleaned = validate_inner_stream_tokens(forged_priv, inventory=inv, require_inventory=True)
        self.assertEqual(cleaned, priv_base)
        self.assertNotIn("current_nix_tokens", cleaned)
        extra_base = {**priv_base, "current_nix_tokens": _expected_nix_envelope([]), "extra_key": 1}
        refused = validate_inner_stream_tokens(extra_base, inventory=inv, require_inventory=True)
        self.assertEqual((refused["withheld_reason"], "current_nix_tokens" in refused), ("invalid-observation", False))
        mismatched = validate_inner_stream_tokens(forged_priv, inventory=inv, mismatch=True, require_inventory=True)
        self.assertEqual((mismatched["withheld_reason"], "current_nix_tokens" in mismatched), ("binding-mismatch", False))

    def test_caller_scoping_current071_linux_only_and_legacy_equality(self):
        raw = b"dbus-daemon: Failed to activate service 'org.freedesktop.portal.Desktop'\n"
        fields = {
            "stream_capture_complete": True,
            "receipt": {"present": True, "bytes": 2, "sha256": digest(b"{}")},
            "receipt_error": "receipt-failed",
        }
        record = {"status": "fail", "problems": ["receipt schema"]}
        for system, platform, scenario in LINUX_BINDINGS:
            self._write_inner(raw, platform=platform, scenario=scenario)
            default_diag = collect_failure_diagnostics(
                b"", fields, self.ev, platform, scenario, record=record, system=system
            )
            prob_only_diag = collect_failure_diagnostics(
                b"", fields, self.ev, platform, scenario, record=record, system=system, current071_problems=True
            )
            nonbool_diag = collect_failure_diagnostics(
                b"", fields, self.ev, platform, scenario, record=record, system=system, current071=1
            )
            cur_diag = collect_failure_diagnostics(
                b"", fields, self.ev, platform, scenario, record=record, system=system, current071=True
            )
            self.assertNotIn("current_nix_tokens", default_diag["inner_stderr_diagnostic"])
            self.assertEqual(prob_only_diag["inner_stderr_diagnostic"], default_diag["inner_stderr_diagnostic"])
            self.assertEqual(nonbool_diag["inner_stderr_diagnostic"], default_diag["inner_stderr_diagnostic"])
            self.assertEqual(
                cur_diag["inner_stderr_diagnostic"]["current_nix_tokens"],
                _expected_nix_envelope(["dbus-service-activation-failed", "portal-desktop-reference"]),
            )
        self._write_inner(raw, platform="darwin-arm64", scenario="A")
        darwin_default = collect_failure_diagnostics(
            b"", fields, self.ev, "darwin-arm64", "A", record=record, system="aarch64-darwin"
        )
        darwin_cur = collect_failure_diagnostics(
            b"", fields, self.ev, "darwin-arm64", "A", record=record, system="aarch64-darwin", current071=True
        )
        self.assertNotIn("current_nix_tokens", darwin_default["inner_stderr_diagnostic"])
        self.assertEqual(darwin_cur["inner_stderr_diagnostic"], darwin_default["inner_stderr_diagnostic"])

    def test_execute_application_smoke_and_60kib_shedding_drops_new_extension_first(self):
        scratch = self.root / "scratch"
        ev = scratch / "evidence"
        ev.mkdir(parents=True)
        prepared = {
            "source_generation": "theme-forge-current-202610",
            "source": self.root / "source",
            "checkout": self.root / "source",
            "tools": self.root / "source/tools",
            "scratch": scratch,
        }

        def fake_run(_argv, **_kwargs):
            (ev / "linux-x64-C.run.json").write_bytes(
                canonical({"status": "fail", "problems": ["no receipt was written"],
                           "executable": {"sha256": "a" * 64}})
            )
            (ev / "linux-x64-C.stderr.log").write_bytes(b"dbus: failed to open session.conf\nWebKitWebProcess started\n")
            return SimpleNamespace(returncode=1, stdout=b"", stderr=b"dbus-daemon: error\n")

        for profile, expect_present in (
            (diagnostic.CURRENT_REPLAY_PROGRESS_PROFILE, False),
            (CURRENT071_REPLAY_PROGRESS_PROFILE, True),
        ):
            with patch.object(diagnostic, "_replay_progress_wrapper", return_value=self.root / "wrapper.mjs"), \
                 patch.object(diagnostic, "_current_replay_progress_profile", return_value=profile), \
                 patch.object(diagnostic.subprocess, "run", side_effect=fake_run), \
                 self.assertRaises(ContractError) as caught:
                diagnostic.execute_application_smoke(
                    prepared=prepared, system="x86_64-linux", launch_root=self.root / "launch",
                    diagnostic_initial_observation=True,
                )
            obs = caught.exception.smoke_observation
            self.assertEqual("current_nix_tokens" in obs["inner_stderr_diagnostic"], expect_present)
            self.assertEqual(validate_smoke_observation(obs, system="x86_64-linux"), obs)
        expected_ext = _expected_nix_envelope(["dbus-config-read-failed", "webkit-webprocess-reference"])
        self.assertEqual(obs["inner_stderr_diagnostic"]["current_nix_tokens"], expected_ext)
        diag_path = self.root / "diagnostics/application-smoke-diagnostic.json"
        retained = json.loads(diag_path.read_text(encoding="utf-8"))
        self.assertEqual(retained["initial_run"]["inner_stderr_diagnostic"]["current_nix_tokens"], expected_ext)
        without_ext = copy.deepcopy(retained)
        without_ext["initial_run"]["inner_stderr_diagnostic"].pop("current_nix_tokens")
        with patch.object(diagnostic, "MAX_DIAGNOSTIC", len(canonical(without_ext)) + 10):
            sha = diagnostic._retain_failure(
                prepared, "x86_64-linux", "linux-x64", "C", self.root / "launch", (), {},
                copy.deepcopy(retained["initial_run"]), ["C-signal"],
                include_replay=False, replay_skip_reason="boundary-probe-only",
            )
        self.assertEqual((digest(diag_path.read_bytes()), diag_path.read_bytes()), (sha, canonical(without_ext)))
