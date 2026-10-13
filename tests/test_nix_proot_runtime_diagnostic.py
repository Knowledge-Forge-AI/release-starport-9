"""Signals retain raw statuses; WebKit consistency remains a failing predicate."""
import unittest
from unittest.mock import Mock, patch

from rs9.errors import ContractError
from rs9.nix_proot import Run, probe_bwrap_mechanism, probe_verifier_and_smoke, probe_webkit_sandbox_state
from rs9.nix_proot_runtime_diagnostic import signal_observations


class SignalObservationTests(unittest.TestCase):
    def details(self):
        return {"stages": [{"stage": "wait-signal-death", "details": {"raw_returncode": 255,
            "wait": {"status": "valid", "signal_status_collapsed": True, "status_mapped": False,
                     "record": {"kind": "signaled", "signal": 15}}}}],
            "external_sigterm": {"delivery_scope": "outer-process", "guest_handler_observed": False,
                "observed_layers": {"status": "observed", "scan_incomplete": False, "limit_exceeded": False,
                    "layers": [{"pid": 10, "basename_class": "proot", "sigterm": {"ignored": True}}]},
                "layer_survival": {"status": "completed", "records": [{"pid": 10, "survived": True}]},
                "process_group_control": {"delivery_scope": "process-group", "guest_handler_observed": True}}}

    def test_observed_ignore_and_survival_do_not_assign_forwarding_cause(self):
        doc = signal_observations(self.details())
        self.assertIn("validated-guest-sigterm-host-exit-255", doc["observations"])
        self.assertIn("proot-sigterm-ignored-and-surviving", doc["observations"])
        self.assertIn("outer-delivery-handler-unobserved", doc["observations"])
        self.assertIn("group-control-handler-observed", doc["observations"])
        self.assertEqual(doc["forwarding_cause"], "unresolved")
        self.assertIs(doc["status_mapped"], False)
        self.assertIs(doc["qualification_authority"], False)
        self.assertNotIn("pid", str(doc))

    def test_exit_255_and_incomplete_layers_cannot_prove_signal_collapse(self):
        for kind, valid in (("exited", True), ("signaled", False)):
            details = self.details()
            wait = details["stages"][0]["details"]["wait"]
            wait["record"]["kind"] = kind
            wait["status"] = "valid" if valid else "invalid"
            details["external_sigterm"]["observed_layers"]["scan_incomplete"] = True
            doc = signal_observations(details)
            self.assertNotIn("validated-guest-sigterm-host-exit-255", doc["observations"])
            self.assertNotIn("proot-sigterm-ignored-and-surviving", doc["observations"])


class WebKitObservationTests(unittest.TestCase):
    def main(self, *, parent="other", nnp=1, seccomp=2):
        return {"status": "observed", "root_pid": 1, "processes": [
            {"pid": 1, "comm": parent, "no_new_privs": 1, "seccomp": 2},
            {"pid": 2, "ppid": 1, "comm": "WebKitWebProcess", "no_new_privs": nnp, "seccomp": seccomp}]}

    def test_missing_parent_and_confounded_flags_stay_failed(self):
        gate = probe_webkit_sandbox_state(Mock(), self.main(), {"diagnostic_token": "userns-denied"})
        self.assertEqual(gate["status"], "fail")
        self.assertEqual(gate["reason"], "webkit-sandbox-not-observed-enabled")
        self.assertEqual(gate["details"]["failed_conditions"], ["web-process-not-bwrap-child"])
        self.assertEqual(gate["details"]["sandbox_cause"], "unresolved")
        self.assertIs(gate["details"]["helper_probe_is_application_spawn"], False)
        self.assertIs(gate["details"]["nnp_seccomp_confounded"], True)

    def test_bwrap_parent_with_inconsistent_flags_fails_and_passing_control(self):
        for nnp, seccomp, expected in ((0, 2, ["no-new-privs-not-1"]),
                                      (1, 0, ["seccomp-not-2"]), (1, 2, [])):
            gate = probe_webkit_sandbox_state(Mock(), self.main(parent="bwrap", nnp=nnp, seccomp=seccomp))
            self.assertEqual(gate["details"]["failed_conditions"], expected)
            self.assertEqual(gate["status"], "fail" if expected else "pass")

    def test_standalone_bwrap_control_never_becomes_app_spawn_cause(self):
        rt = Mock()
        rt.facts = {"bwrap": "/guest/bwrap", "python": "/guest/python"}
        rt.run.return_value = Run(1, b"", b"bwrap: Creating new namespace failed: Operation not permitted\n", 0.1, None)
        doc = probe_bwrap_mechanism(rt)
        rt.run.assert_called_once()
        self.assertEqual(doc["probe_scope"], "standalone-bwrap-control")
        self.assertIs(doc["qualification_authority"], False)
        self.assertEqual(doc["stderr_observation"]["stage"], "standalone-bwrap-control-stderr")
        self.assertEqual(doc["stderr_observation"]["tokens"], ["bwrap-namespace-denied"])

    def test_original_proot_smoke_observation_keeps_original_error(self):
        error = ContractError("APPLICATION_SMOKE", "smoke failed", details={"exit_code": 1})
        error.smoke_observation = {"scenario": "C", "raw_returncode": 1, "cause": "process-nonzero"}
        smoke = Mock(side_effect=error)
        gate = probe_verifier_and_smoke(smoke, system="aarch64-linux")
        smoke.assert_called_once()
        self.assertEqual(gate["status"], "fail")
        self.assertEqual(gate["reason"], "APPLICATION_SMOKE")
        self.assertEqual(gate["details"]["original_smoke_observation"]["scenario"], "unknown")
        with patch("rs9.pages_smoke_diagnostic.validate_smoke_observation", side_effect=RuntimeError):
            self.assertEqual(probe_verifier_and_smoke(smoke)["reason"], "APPLICATION_SMOKE")
