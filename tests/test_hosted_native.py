"""Native preparation cannot manufacture a container digest or signing proof."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from rs9.errors import ContractError
from rs9.hosted_native import provision, get_signing_authority, compare_inventories, execute_probes
from rs9.build_native import CommandReceipt

class NativeHelpersTests(unittest.TestCase):
    def test_missing_digest_refused_before_tool_execution(self):
        with self.assertRaises(ContractError):
            provision("rpm","x86_64-linux",{"rpm":{}},runner=object())

    def test_unsigned_inventory_difference_detected(self):
        self.assertTrue(compare_inventories({"file":"a"},{"file":"a"})["clean"])
        self.assertFalse(compare_inventories({"file":"a"},{"file":"b"})["clean"])

    def test_signing_failure_has_no_synthetic_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("rs9.signing_fixture.SigningFixture",side_effect=ContractError("GPG_NOT_AVAILABLE","Unavailable")):
                with self.assertRaises(ContractError):
                    get_signing_authority({},Path(tmp))

    def test_service_uses_protocol_implementation_with_runner_wrapper(self):
        with patch("rs9.hosted_commands.run_probes",return_value=[{"status":"pass"}]) as probe:
            execute_probes("tfsb-studio-service","/usr/bin/tfsb-studio-service",prefix=["docker","exec","-i"],runner=object())
            self.assertEqual(probe.call_args.kwargs["prefix"],["docker","exec","-i"])
