"""Focused [SYNTHETIC] checks for the explicit system-WebKit workflow route."""

from __future__ import annotations

import unittest

from rs9.tf_pypi_nebular070_publish import workflow_070_jobs_text, workflow_text


class SystemWebKitWorkflowTests(unittest.TestCase):
    def test_profile_is_selected_from_validated_descriptor_in_each_gate(self) -> None:
        text = workflow_070_jobs_text()

        self.assertEqual(
            text.count("- name: Validate explicit 0.7.0 runtime profile\n"), 1
        )
        self.assertEqual(
            text.count("Validate explicit 0.7.0 runtime profile for matrix"), 1
        )
        self.assertEqual(
            text.count("descriptor = load_qualification_inputs_descriptor("), 7
        )
        self.assertIn('elif "manylinux" in descriptor:', text)
        self.assertIn('print(SYSTEM_WEBKIT_RUNTIME_PROFILE)', text)
        self.assertIn("manylinux|system-webkitgtk-4.1", text)
        self.assertNotIn('${"{{"}', text)

    def test_system_route_omits_manylinux_stage_and_preserves_portable_branch(self) -> None:
        text = workflow_070_jobs_text()

        self.assertIn('if [[ "${{ steps.runtime_profile.outputs.profile }}" == "manylinux" ]]', text)
        self.assertIn("--require-manylinux", text)
        self.assertIn("--tf-producer-commit", text)
        self.assertIn("if: steps.runtime_profile.outputs.profile == 'manylinux'", text)
        self.assertIn(
            "if: steps.runtime_profile.outputs.profile == 'system-webkitgtk-4.1'",
            text,
        )
        self.assertIn("system profile unexpectedly has Stage-A payload", text)
        self.assertIn("system profile unexpectedly has Stage-A receipt", text)
        self.assertEqual(text.count("\n  native_consumer_070_"), 5)

    def test_current_workflow_selects_universal_system_route_and_keeps_legacy_release(self) -> None:
        generated = workflow_text("0.7.0")
        legacy = workflow_text("0.6.1")

        self.assertIn("Build and verify one universal launcher wheel", generated)
        self.assertNotIn("Validate explicit 0.7.0 runtime profile\n", generated)
        self.assertIn("system-webkitgtk-4.1", generated)
        # The combined workflow now carries the registered universal 0.7 jobs; the
        # legacy release selector remains independent of this route.
        self.assertIn("universal_build_verify_070:", legacy)
        self.assertIn("universal_build_verify_070:", generated)
        self.assertIn("universal_qualification_gate_070:", generated)
        self.assertNotIn("publication_resume_070:", generated)


if __name__ == "__main__":
    unittest.main()
