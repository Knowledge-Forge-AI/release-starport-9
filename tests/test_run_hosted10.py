"""Run-10 handoff retains exact adoption, collection and diagnostic boundaries."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from tests import test_run_hosted9 as previous

SCRIPT = Path(__file__).resolve().parents[1] / "operators/live1/run-hosted10.py"
spec = importlib.util.spec_from_file_location("rs9_run_hosted10", SCRIPT)
operator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(operator)


class Run10Tests(unittest.TestCase):
    def check_previous_boundary(self, method):
        with patch.object(previous, "operator", operator):
            getattr(previous.Run9Tests, method)(self)

    def test_exact_external_acceptance_and_false_readiness(self):
        self.check_previous_boundary("test_external_acceptance_is_forwarded_once_without_readiness_flag_edit")

    def test_no_acceptance_no_child(self):
        self.check_previous_boundary("test_unaccepted_operator_never_invokes_child_and_prints_only_four_keys")

    def test_collection_binding_and_physical_empty_packet(self):
        self.check_previous_boundary("test_collect_only_passes_exact_time_run_commit_without_adoption")

    def test_committed_inventory_and_ignored_scratch_preservation(self):
        self.check_previous_boundary("test_collect_only_verifies_real_inventory_after_fixture_commit")

    def test_upload_retains_raw_policy_and_both_apt_receipts(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp).resolve() / "packet"
            output.mkdir()
            (output / "manager-packet.json").write_text('{"qualified":false}')
            paths = ["candidate-rpm-x86_64-linux/objects/lane-work/diagnostics/rpmlint-burst.json",
                     "candidate-rpm-x86_64-linux/objects/lane-work/diagnostics/rpm-lint-policy-burst.json",
                     "candidate-deb-amd64/deb-amd64.json",
                     "candidate-deb-arm64/deb-arm64.json"]
            for relative in paths:
                path = output / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps({"fixture": True}))
            (output / "large.rpm").write_bytes(b"separate-custody")
            with zipfile.ZipFile(operator.small_result_zip(output)) as archive:
                self.assertTrue(set(paths) <= set(archive.namelist()))
                self.assertNotIn("large.rpm", archive.namelist())
                selection = json.loads(archive.read("result-selection.json"))
                self.assertFalse(selection["large_packages_embedded"])
