"""Universal qualification reuses the approved native runner policies."""
import re
import unittest

from rs9 import nebular070_universal_workflow as workflow
from rs9 import tf_pypi_nebular070_publish as legacy


class UniversalWorkflowTests(unittest.TestCase):
    def test_exact_five_native_lanes_keep_their_runner_and_permission_policy(self):
        old = workflow._split_jobs(legacy.workflow_070_qualify_jobs_text())
        new = workflow._split_jobs(workflow.qualify_jobs_text())
        self.assertEqual(len(new), 9)
        self.assertIn("reject_unsupported_dispatch", new)
        native = [name for name in old if name.startswith("native_consumer_070_")]
        self.assertEqual(len(native), 5)
        for name in native:
            before, after = old[name], new["universal_" + name]
            for pattern in (r"(?m)^    runs-on:.*$", r"(?m)^    timeout-minutes:.*$",
                            r"(?ms)^    permissions:\n.*?(?=    [a-z]|\Z)",
                            r"(?ms)^    container:\n.*?(?=    [a-z]|\Z)"):
                self.assertEqual(re.findall(pattern, before), re.findall(pattern, after))
            self.assertIn("inputs.mode == 'universal-qualify'", after)
            self.assertNotIn("refs/heads/" + legacy.QUALIFY_BRANCH, after)
            self.assertNotIn("id-token: write", after)
            self.assertIn("rs9.tf_pypi_nebular070_universal qualify-native", after)

    def test_new_bundle_and_matrix_use_the_universal_domain(self):
        text = workflow.qualify_jobs_text()
        self.assertIn("rs9.tf_pypi_nebular070_universal build-bundle", text)
        self.assertIn("rs9.tf_pypi_nebular070_universal admit-matrix", text)
        self.assertNotIn("build-candidates", text)
        self.assertNotIn("assemble-stage-b", text)
        self.assertNotIn("--require-manylinux", text)
        self.assertNotIn("consumer-capture-output", text)
        self.assertEqual(text.count("rs9.tf_pypi_nebular070_universal check-system-webkit-missing"), 2)

    def test_host_runtime_and_display_package_installations_are_unchanged(self):
        old = legacy.workflow_070_qualify_jobs_text()
        new = workflow.qualify_jobs_text()
        for name, job in workflow._split_jobs(new).items():
            if not name.startswith("universal_native_consumer"):
                continue
            prior = workflow._split_jobs(old)[name.removeprefix("universal_")]
            self.assertEqual([line for line in job.splitlines() if "apt-get" in line or "apt-cache" in line],
                             [line for line in prior.splitlines() if "apt-get" in line or "apt-cache" in line])
            self.assertEqual([line for line in job.splitlines() if "uses:" in line],
                             [line for line in prior.splitlines() if "uses:" in line])

    def test_unknown_or_drifted_step_replacement_fails_closed(self):
        with self.assertRaises(ValueError):
            workflow._replace_step("", "missing", "")

    def test_universal_publication_keeps_the_registered_oidc_identity_and_two_checkouts(self):
        text = workflow.publication_job_text()
        self.assertIn("inputs.mode == 'universal-publish'", text)
        self.assertIn("name: pypi", text)
        self.assertIn("id-token: write", text)
        self.assertIn(legacy.PYPA_PUBLISH_ACTION, text)
        self.assertIn("path: publisher-authority", text)
        self.assertIn("path: qualification-source", text)
        self.assertIn("--attempt-marker", text)
        self.assertIn("verify-upload", text)
        self.assertIn("skip-existing: false", text)
        self.assertNotIn("rs9.tf_pypi_nebular070_publish select-missing", text)
        readback = text.partition("- name: Read back exact universal PyPI bytes and metadata")[2]
        # A published-exact selection creates no upload directory. Readback
        # authenticates held bytes directly and must support that read-only path.
        self.assertNotIn("--upload-dir", readback)
        bootstrap = text.partition("- name: Checkout exact qualified source commit")[0]
        self.assertNotIn("publisher-authority/src", bootstrap)
        self.assertNotIn("-m rs9.", bootstrap)
        self.assertIn(' -I -B - ', bootstrap)
        self.assertIn("packages-dir: tfnf-070-universal-upload/", text)
        self.assertEqual(text.count('--upload-dir "${{ github.workspace }}/tfnf-070-universal-upload"'), 2)
        self.assertNotIn("${{ runner.temp }}/tfnf-070-universal-upload/", text)

    def test_unsupported_release_mode_pairs_are_closed_before_publication(self):
        from rs9.tf_pypi_archive import AdmissionError
        for pair in (("0.6.1", "universal-publish"), ("0.7.0", "publish"),
                     ("0.7.0", "resume"), ("0.7.0", "qualify")):
            with self.subTest(pair=pair), self.assertRaises(AdmissionError):
                workflow.validate_workflow_dispatch(*pair)
        for pair in (("0.6.1", "qualify"), ("0.6.1", "publish"),
                     ("0.7.0", "universal-qualify"), ("0.7.0", "universal-publish")):
            self.assertEqual(workflow.validate_workflow_dispatch(*pair)["mode"], pair[1])
