"""Closed wrapper labels annotate failures without changing their admission."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from rs9.nebular080_installed_smoke import _native_execution_failure_code


class WrapperFailureDiagnosticsTests(unittest.TestCase):
    def test_wrapper_stderr_maps_to_closed_labels_without_values(self):
        samples = (
            ("xvfb-run: error: Xvfb failed to start", "WRAPPER_XVFB"),
            ("dbus-run-session: failed to exec helper: rejected", "WRAPPER_DBUS_SESSION"),
            ("sudo: a password is required", "WRAPPER_PRIVILEGE"),
            ("unshare: unshare failed: Operation not permitted", "WRAPPER_PRIVILEGE"),
            ("setpriv: rejected invocation", "WRAPPER_PRIVILEGE"),
        )
        for text, category in samples:
            with self.subTest(category=category, wrapper=text.split(":", 1)[0]):
                process = {"exit_code": 1, "stderr_token": text, "stdout_token": ""}
                before = dict(process)
                self.assertEqual(_native_execution_failure_code(process),
                                 "NEBULAR_NATIVE_EXECUTION_" + category)
                self.assertEqual(process, before)

    def test_only_line_start_stderr_markers_refine_fallback(self):
        for process in (
            {"exit_code": 1, "stderr_token": "unclassified runtime refusal"},
            {"exit_code": 1, "stderr_token": "app payload mentions xvfb-run: error:"},
            {"exit_code": 1, "stdout_token": "xvfb-run: error: ignored stdout"},
            {"exit_code": 1, "stderr_token": None},
        ):
            with self.subTest(process=process):
                self.assertEqual(_native_execution_failure_code(process),
                                 "NEBULAR_NATIVE_EXECUTION_EXIT_NONZERO")
        self.assertEqual(_native_execution_failure_code({
            "exit_code": 1, "stderr_token": "unclassified\nxvfb-run: error: startup refused"}),
            "NEBULAR_NATIVE_EXECUTION_WRAPPER_XVFB")

    def test_existing_failure_categories_keep_precedence(self):
        cases = (
            ({"timed_out": True}, "TIMEOUT"),
            ({"output_limit_exceeded": True}, "OUTPUT_LIMIT"),
            ({"stderr_token": "ERR_MODULE_NOT_FOUND\nxvfb-run: error: startup refused"}, "NODE_MODULE"),
            ({"exit_code": 126}, "EXIT_PERMISSION"),
            ({"exit_code": 127}, "EXIT_COMMAND_NOT_FOUND"),
            ({"forced_cleanup": True}, "FORCED_CLEANUP"),
            ({"cleanup_known": False}, "CLEANUP_UNOBSERVED"),
            ({"output_complete": False}, "OUTPUT_INCOMPLETE"),
            ({"exit_code": -15}, "SIGNAL"),
        )
        for override, category in cases:
            with self.subTest(category=category):
                process = {"exit_code": 1, "stderr_token": "xvfb-run: error: startup refused", **override}
                self.assertEqual(_native_execution_failure_code(process),
                                 "NEBULAR_NATIVE_EXECUTION_" + category)

    def test_success_exit_does_not_get_wrapper_fallback(self):
        self.assertEqual(_native_execution_failure_code({
            "exit_code": 0, "stderr_token": "xvfb-run: error: untrusted text"}),
            "NEBULAR_NATIVE_EXECUTION")


if __name__ == "__main__":
    unittest.main()
