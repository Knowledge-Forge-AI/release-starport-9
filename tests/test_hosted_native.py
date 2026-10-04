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

    def test_empty_architecture_output_raises_contract_error_not_index_error(self):
        class EmptyArchRunner:
            def run(self, argv, **kw):
                if argv[1] == "pull":
                    return CommandReceipt(argv, 0, b"", b"", executed=True)
                if argv[1] == "run":
                    # Empty output or whitespace-only output must fail closed with CONTAINER_ARCH, never IndexError
                    return CommandReceipt(argv, 0, b"   \n\n", b"", executed=True)
                return CommandReceipt(argv, 0, b"", b"", executed=True)

        pins = {"pacman": {"container_digest": "docker.io/library/archlinux@sha256:" + "a" * 64}}
        with self.assertRaises(ContractError) as caught:
            provision("pacman", "x86_64-linux", pins, runner=EmptyArchRunner())
        self.assertEqual(caught.exception.code, "CONTAINER_ARCH")
        self.assertEqual(caught.exception.details.get("substage"), "architecture")
        self.assertEqual(caught.exception.details.get("tool"), "uname")

    def test_container_provision_failures_have_safe_context_details(self):
        from rs9.errors import safe_details
        class FailingPullRunner:
            def run(self, argv, **kw):
                if argv[1] == "pull":
                    return CommandReceipt(argv, 1, b"error stdout", b"pull failed", executed=True)
                return CommandReceipt(argv, 0, b"", b"", executed=True)

        pins = {"pacman": {"container_digest": "docker.io/library/archlinux@sha256:" + "b" * 64}}
        with self.assertRaises(ContractError) as caught:
            provision("pacman", "x86_64-linux", pins, runner=FailingPullRunner())
        self.assertEqual(caught.exception.code, "CONTAINER_PULL")
        details = caught.exception.details
        self.assertEqual(details.get("substage"), "pull")
        self.assertEqual(details.get("tool"), "docker")
        self.assertEqual(details.get("exit_code"), 1)
        safe = safe_details(details)
        self.assertEqual(safe.get("substage"), "pull")
        self.assertEqual(safe.get("tool"), "docker")
        self.assertEqual(safe.get("exit_code"), 1)
