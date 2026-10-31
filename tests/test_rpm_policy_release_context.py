"""Fixed070 policy replay is distinct from admission of current071 inputs."""
import copy
import unittest
from unittest.mock import patch
from rs9 import rpm_lint_policy as policy
from rs9.current_generation import CURRENT_GENERATION
from rs9.errors import ContractError
from tests.test_current_rpm_preservation_policy import actual_case, blocked_policy

class PolicyReleaseContextTests(unittest.TestCase):
    def test_fixed070_policy_parses_without_changing_active071_identity(self):
        value=policy.load_policy(generation=CURRENT_GENERATION)
        self.assertEqual(value["projects"]["theme-forge-nebular-fusion"]["version"],"0.7.0")
        self.assertEqual(policy.CURRENT_GENERATION_VERSIONS["theme-forge-nebular-fusion"],"0.7.1")
        self.assertEqual(policy._validate_policy(blocked_policy(),generation=CURRENT_GENERATION)["status"],"blocked")

    def test071_cannot_inherit070_even_with_old_native_inventory_and_both_architectures(self):
        for system in ("x86_64-linux","aarch64-linux"):
            case=actual_case("theme-forge-nebular-fusion",system)
            for status in ("fail","pass"):
                raw=copy.deepcopy(case["raw"]);raw["status"]=status
                inputs={**case["inputs"],"version":"0.7.1"}
                result=policy.evaluate_policy(raw,case["inventory"],inputs,generation=CURRENT_GENERATION)
                self.assertFalse(result["accepted"])
                self.assertIn("project-version-platform-mismatch",result["blockers"])
                self.assertEqual(result["accepted_findings"],[])

    def test_version_relabel_of_policy_does_not_create071_authorization(self):
        value=policy.load_policy(generation=CURRENT_GENERATION)
        value["projects"]["theme-forge-nebular-fusion"]["version"]="0.7.1"
        with self.assertRaises(ContractError):policy._validate_policy(value,generation=CURRENT_GENERATION)

    def test_070_policy_uses_frozen070_caller_loader_and_failure_refuses(self):
        with patch("rs9.nebular_callers._load_current071_contract",side_effect=AssertionError("active071 caller is irrelevant")):
            self.assertEqual(policy.load_policy(generation=CURRENT_GENERATION)["status"],"authorized")
        with patch("rs9.nebular_callers._load_current_contract",side_effect=ContractError("CALLER_SOURCE_IDENTITY","changed frozen bytes")),self.assertRaises(ContractError):
            policy.load_policy(generation=CURRENT_GENERATION)
