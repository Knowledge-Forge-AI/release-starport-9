"""Policy lookup must follow the active test scope, regardless of import order."""
import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from rs9 import rpm_lint_policy
from rs9.release_core import digest
from rs9.scratch import canonical
from tests.test_hosted_summary import _make_synthetic_rpm

HELPER = Path(__file__).with_name("rpm_summary_fixtures.py")
PRODUCT = "theme-forge-stellar-loom"


class SummaryFixturePolicyScopeTests(unittest.TestCase):
    def load_helper(self):
        spec = importlib.util.spec_from_file_location("_fixture_policy_scope_probe", HELPER)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def annex_hash(self, module):
        with tempfile.TemporaryDirectory() as temporary:
            scratch = Path(temporary)
            package = scratch / (PRODUCT + "-0.6.1-1.noarch.rpm")
            package.write_bytes(_make_synthetic_rpm(PRODUCT))
            receipt = {"system": "x86_64-linux"}
            module.add_rpm_annex(scratch, receipt, [package])
            return receipt["details"]["rpm_lint_policy"][PRODUCT]["policy_sha256"]

    def test_import_under_patch_does_not_retain_mock_policy(self):
        actual = rpm_lint_policy.load_policy()
        overlay = copy.deepcopy(actual)
        overlay["test_only_scope"] = "temporary"
        with patch.object(rpm_lint_policy, "load_policy", return_value=overlay):
            module = self.load_helper()
        self.assertEqual(self.annex_hash(module), digest(canonical(actual)))

    def test_existing_helper_observes_only_the_active_policy_patch(self):
        actual = rpm_lint_policy.load_policy()
        overlay = copy.deepcopy(actual)
        overlay["test_only_scope"] = "temporary"
        module = self.load_helper()
        with patch.object(rpm_lint_policy, "load_policy", return_value=overlay):
            self.assertEqual(self.annex_hash(module), digest(canonical(overlay)))
        self.assertEqual(self.annex_hash(module), digest(canonical(actual)))


if __name__ == "__main__":
    unittest.main()
