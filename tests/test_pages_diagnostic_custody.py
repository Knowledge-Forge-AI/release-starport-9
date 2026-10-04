"""Pages diagnostics survive client failure with bounded, private-safe custody."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from rs9.errors import ContractError
from rs9.hosted_custody import retain, verify_set
from rs9.hosted_pipeline import run_lane
from rs9.scratch import canonical

ROOT = Path(__file__).resolve().parents[1]


class PagesDiagnosticCustodyTests(unittest.TestCase):
    def record(self, error=None):
        return {"lane": "pages", "system": "generation", "execution_error": error,
                "provenance": {"source_commit": "a" * 40}, "runner": {}}

    def test_safe_diagnostic_is_bound_to_lane_system_and_commit(self):
        with tempfile.TemporaryDirectory() as td:
            scratch, output = Path(td).resolve() / "scratch", Path(td).resolve() / "output"
            source = scratch / "lane-work/pages-client/diagnostics/client.json"
            source.parent.mkdir(parents=True)
            source.write_bytes(canonical({"reason": "fixture-client-failed", "exit_code": 2}))
            manifest = retain(scratch, output, [source], self.record("CLIENT_FAILURE"))
            self.assertEqual(verify_set(output), manifest)
            self.assertEqual(manifest["source_commit"], "a" * 40)
            self.assertEqual((manifest["lane"], manifest["system"]), ("pages", "generation"))
            self.assertEqual((output / manifest["files"][0]["path"]).read_bytes(), source.read_bytes())

    def test_unsafe_or_oversize_diagnostic_is_hashes_only_and_preserves_primary(self):
        values = [({"path": "/" + "Users" + "/fixture/private"}, "PRIVATE_PATH"),
                  ({"value": "ghp_" + "X" * 36}, "CREDENTIAL_DETECTED"),
                  ({"value": "X" * (64 * 1024)}, "DIAGNOSTIC_LIMIT")]
        for value, reason in values:
            with self.subTest(reason=reason), tempfile.TemporaryDirectory() as td:
                scratch, output = Path(td).resolve() / "scratch", Path(td).resolve() / "output"
                source = scratch / "lane-work/pages-client/diagnostics/client.json"
                source.parent.mkdir(parents=True)
                source.write_bytes(canonical(value))
                record = self.record("PRIMARY_CLIENT_FAILURE")
                manifest = retain(scratch, output, [source], record)
                self.assertEqual(record["execution_error"], "PRIMARY_CLIENT_FAILURE")
                self.assertEqual(record["diagnostic_scan_failures"][0]["reason"], reason)
                substitute = json.loads((output / manifest["files"][0]["path"]).read_bytes())
                self.assertEqual(substitute["status"], "withheld")
                self.assertEqual(set(substitute), {"schema", "status", "path", "reason", "sha256", "size"})
                self.assertLess(len(canonical(substitute)), 1024)
                verify_set(output)

    def test_unsafe_diagnostic_alone_fails_lane(self):
        with tempfile.TemporaryDirectory() as td:
            scratch, output = Path(td).resolve() / "scratch", Path(td).resolve() / "output"
            source = scratch / "diagnostics/client.json"
            source.parent.mkdir(parents=True)
            source.write_text('{"path":"~/' + 'private"}')
            record = self.record()
            retain(scratch, output, [source], record)
            self.assertEqual(record["execution_error"], "DIAGNOSTIC_CUSTODY")

    def test_non_json_diagnostic_substitute_has_exact_custody_path(self):
        with tempfile.TemporaryDirectory() as td:
            scratch, output = Path(td).resolve() / "scratch", Path(td).resolve() / "output"
            source = scratch / "lane-work/pages-client/diagnostics/client.txt"
            source.parent.mkdir(parents=True)
            source.write_bytes(b"untrusted client output")
            manifest = retain(scratch, output, [source], self.record("PRIMARY_CLIENT_FAILURE"))
            self.assertTrue(manifest["files"][0]["path"].endswith(".txt.withheld.json"))
            self.assertEqual(verify_set(output), manifest)

    def test_pipeline_sweeps_failed_pages_client_diagnostics(self):
        with tempfile.TemporaryDirectory() as td:
            scratch, output = Path(td).resolve() / "scratch", Path(td).resolve() / "output"
            scratch.mkdir()
            def capture(repository, root, **kwargs):
                (root / "summary").mkdir()
                (root / "summary/authentication.json").write_bytes(canonical({"projects": []}))
                return []
            def execute(context):
                path = context["scratch"] / "pages-client/diagnostics/client.json"
                path.parent.mkdir(parents=True)
                path.write_bytes(canonical({"reason": "client-probe-failed"}))
                raise ContractError("CLIENT_FAILURE", "Synthetic client failure")
            auth = Path(td).resolve() / "auth"
            auth.mkdir()
            auth_manifest = {"release_ingestion_sha256": __import__("hashlib").sha256(canonical({"projects": []})).hexdigest()}
            (auth / "artifact-manifest.json").write_bytes(canonical(auth_manifest))
            with patch("rs9.hosted_pipeline.capture_generation", side_effect=capture), \
                 patch("rs9.hosted_pipeline._inputs", return_value={("authenticate", "generation"): auth}), \
                 patch("rs9.hosted_pipeline.bind_commands", return_value=scratch / "authentication-projection.json"), \
                 patch("rs9.hosted_pipeline.report_generation", return_value={}), \
                 patch("rs9.hosted_pipeline.runner_facts", return_value={}), \
                 patch("rs9.hosted_pipeline.importlib.import_module", return_value=Mock(execute=execute)):
                self.assertEqual(run_lane(ROOT, scratch, output, "pages", "generation", client=Mock(receipts=[])), 2)
            retained = output / "objects/lane-work/pages-client/diagnostics/client.json"
            self.assertTrue(retained.is_file())
            receipt = json.loads((output / "pages-generation.json").read_bytes())
            self.assertEqual(receipt["execution_error"], "CLIENT_FAILURE")
            verify_set(output)

    def test_multi_family_pages_client_sidecar_diagnostics_survive_and_retain_identity(self):
        with tempfile.TemporaryDirectory() as td:
            scratch, output = Path(td).resolve() / "scratch", Path(td).resolve() / "output"
            diag_dir = scratch / "lane-work/pages-client/diagnostics"
            diag_dir.mkdir(parents=True)

            families = ["apt", "dnf", "pacman"]
            family_reasons = {
                "apt": "payload-inventory",
                "dnf": "runtime-identity",
                "pacman": "tool-timeout",
            }
            files = []
            for fam in families:
                diag_path = diag_dir / f"sidecar-verifier-{fam}.json"
                diag_data = {
                    "schema": "rs9.sidecar-verifier-diagnostic.v1alpha1",
                    "system": "x86_64-linux",
                    "product": "theme-forge-nebular-fusion",
                    "substage": "released-sidecar-verifier",
                    "family": fam,
                    "invocation": fam,
                    "classification": "manifest" if fam == "apt" else "verifier-rejected" if fam == "dnf" else "harness/import/execution",
                    "verifier": {
                        "status": "fail",
                        "phase": "verify" if fam != "pacman" else "execution",
                        "reason_token": family_reasons[fam],
                        "exit_code": 2 if fam != "pacman" else -15,
                    },
                }
                diag_path.write_bytes(canonical(diag_data))
                files.append(diag_path)

            record = self.record("CLIENT_FAILURE")
            manifest = retain(scratch, output, files, record)
            self.assertEqual(verify_set(output), manifest)

            # Assert all files remain and each retains its distinct failure identity
            manifest_files = {f["path"]: f for f in manifest["files"]}
            self.assertEqual(len(manifest_files), len(families))
            for fam in families:
                rel_path = f"objects/lane-work/pages-client/diagnostics/sidecar-verifier-{fam}.json"
                self.assertIn(rel_path, manifest_files)
                retained_content = json.loads((output / rel_path).read_bytes())
                self.assertEqual(retained_content["family"], fam)
                self.assertEqual(retained_content["invocation"], fam)
                self.assertEqual(retained_content["verifier"]["reason_token"], family_reasons[fam])

