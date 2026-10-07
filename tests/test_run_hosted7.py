"""The attended operator stops before mutation unless exact acceptance matches."""
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
from subprocess import CompletedProcess
import tempfile
import unittest
from unittest.mock import patch

from rs9.candidate_readiness import readiness_record
from rs9.candidate_inventory import MANIFEST

SCRIPT = Path(__file__).resolve().parents[1] / "operators/live1/run-hosted7.py"
spec = importlib.util.spec_from_file_location("rs9_run_hosted7", SCRIPT)
operator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(operator)


class Run7Tests(unittest.TestCase):
    def test_missing_exact_review_arguments_stops(self):
        with patch.object(operator.subprocess, "run") as child, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(operator.main([]), 2)
        child.assert_not_called()

    def _attempt(self, ready=True, wrong_digest=False, collision=False, attested=False, attestation_drift=False):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve()
            path = root / MANIFEST
            path.parent.mkdir(parents=True)
            raw = json.dumps({"candidate_adoption_ready": ready, "production_enabled": False,
                              "publication_authority": False, "adoption_scope": "partial-diagnostic", "readiness": readiness_record()}).encode()
            path.write_bytes(raw)
            output = root / "packet"
            output.mkdir()
            if collision:
                output.with_name("packet.operator.log").write_bytes(b"retained-log")
            digest = "0" * 64 if wrong_digest else hashlib.sha256(raw).hexdigest()
            extra = []
            if attested:
                with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as stream:
                    attestation_path = Path(stream.name).resolve()
                    attestation = {"schema": "rs9.manager-source-adoption-attestation.v1alpha1",
                        "decision": "accept", "source_adoption_scope": "partial-diagnostic",
                        "reviewed_parent": "b" * 40, "reviewed_tree": ("c" if attestation_drift else "a") * 40,
                        "manifest_sha256": digest, "full_live1_qualification": False,
                        "production_enabled": False, "publication_authority": False}
                    stream.write(json.dumps(attestation))
                self.addCleanup(attestation_path.unlink)
                extra = ["--manager-attestation", str(attestation_path), "--manager-attestation-sha256",
                         hashlib.sha256(attestation_path.read_bytes()).hexdigest()]
            with patch.object(operator, "ROOT", root), \
                    patch("rs9.collect_candidate.output_directory", return_value=output), \
                    patch("rs9.hosted_contract.load_hosted_lanes", return_value={"lanes": [{"lane": "nix", "system": s, "module": "rs9.hosted_nix"} for s in ("x86_64-linux", "aarch64-linux")]}), \
                    patch("rs9.candidate_inventory.verify_inventory", return_value="a" * 40) as verify, \
                    patch.object(operator.subprocess, "run", return_value=CompletedProcess([], 0)) as child, \
                    contextlib.redirect_stdout(io.StringIO()):
                code = operator.main(["--reviewed-parent", "b" * 40, "--reviewed-tree", "a" * 40,
                                      "--manifest-sha256", digest, "--output", str(output), *extra])
            if collision:
                self.assertEqual(output.with_name("packet.operator.log").read_bytes(), b"retained-log")
            return code, child.call_args, verify.call_args

    def test_incomplete_and_wrong_hash_candidates_stop_before_child(self):
        for kwargs in ({"ready": False}, {"wrong_digest": True}, {"collision": True}):
            with self.subTest(kwargs=kwargs):
                code, child, _ = self._attempt(**kwargs)
                self.assertEqual(code, 2)
                self.assertIsNone(child)

    def test_accepted_binding_passes_once_to_shared_adoption_and_separate_streams(self):
        code, child, verify = self._attempt()
        self.assertEqual(code, 0)
        self.assertEqual(verify.kwargs["parent"], "b" * 40)
        argv = child.args[0]
        self.assertIn("adopt", argv)
        self.assertEqual(argv[argv.index("--reviewed-tree") + 1], "a" * 40)
        self.assertEqual(argv[argv.index("--reviewed-parent") + 1], "b" * 40)
        self.assertIs(child.kwargs["stdout"], child.kwargs["stderr"])
        self.assertEqual(child.kwargs["env"]["PYTHONDONTWRITEBYTECODE"], "1")

    def test_external_manager_acceptance_unblocks_unchanged_source_only(self):
        code, child, _ = self._attempt(ready=False, attested=True)
        self.assertEqual(code, 0)
        self.assertIn("--manager-attestation", child.args[0])
        self.assertIn("--manager-attestation-sha256", child.args[0])
        code, child, _ = self._attempt(ready=False, attested=True, attestation_drift=True)
        self.assertEqual(code, 2)
        self.assertIsNone(child)


if __name__ == "__main__":
    unittest.main()
