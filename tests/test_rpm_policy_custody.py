"""Complete retained evaluations cross the real collection and packaging boundary."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from rs9.collect_candidate import diagnostic_scope
from rs9.errors import ContractError
from rs9.hosted_custody import diagnostic_bytes, provenance, retain, verify_set
from rs9.hosted_summary import validate_rpm_policy_custody, rpm_lint_results
from rs9.scratch import canonical

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures/run10/rpm"


class RpmPolicyCustodyTests(unittest.TestCase):
    def setUp(self):
        env = patch.dict("os.environ", {"GITHUB_SHA": "0" * 40, "GITHUB_REF": "refs/heads/main",
                         "GITHUB_EVENT_NAME": "push", "GITHUB_RUN_ATTEMPT": "1"})
        env.start()
        self.addCleanup(env.stop)

    def make_packet(self, root, system):
        from rs9.rpm_evidence import write_policy_evidence
        evaluation = json.loads((FIXTURES / system / "policy-evaluation.json").read_bytes())
        raw = json.loads((FIXTURES / system / "raw-lint.json").read_bytes())
        self.assertGreater(len(canonical(evaluation)), 108 * 1024 - 2048)
        scratch = root / system / "lane-work"
        scratch.mkdir(parents=True)
        summary, files = write_policy_evidence(scratch / "diagnostics", evaluation)
        for path in files:
            self.assertEqual(diagnostic_bytes(path), path.read_bytes())
            self.assertLessEqual(path.stat().st_size, 64 * 1024)
        raw_path = scratch / "diagnostics" / "rpmlint-theme-forge-nebular-fusion.json"
        raw_path.write_bytes(canonical(raw))
        product = evaluation["inputs"]["project_id"]
        record = {"schema": "rs9.hosted-candidate-diagnostic.v1alpha2", "lane": "rpm",
                  "system": system, "production_enabled": False, "publication_authority": False,
                  "execution_error": None, "policy_blockers": [], "runner": {},
                  "provenance": provenance(ROOT, "a" * 64),
                  "gates": [{"name": "rpm-lint-policy-accepted", "status": "fail"},
                            {"name": "rpm-client-qualification", "status": "not-run",
                             "reason": "blocked-by:rpm-lint-policy-accepted"}],
                  "details": {"rpm_evidence_contract": "rs9.rpm-evidence-contract.v2",
                              "rpm_lint_raw": {product: raw}, "rpm_lint_policy": {product: summary}}}
        output = root / "packet" / ("candidate-rpm-" + system)
        manifest = retain(scratch, output, [*files, raw_path], record)
        self.assertNotIn("diagnostic_scan_failures", record)
        self.assertIsNone(record["execution_error"])
        self.assertEqual(verify_set(output), manifest)
        validate_rpm_policy_custody(output, manifest, record)
        return output, manifest, record, evaluation

    def test_actual_run10_evaluations_collector_and_manager_zip(self):
        spec = importlib.util.spec_from_file_location("run11_custody", ROOT / "operators/live1/run-hosted11.py")
        operator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(operator)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            artifacts, lanes = [], []
            for system in ("x86_64-linux", "aarch64-linux"):
                output, manifest, receipt, evaluation = self.make_packet(root, system)
                artifacts.append({"name": output.name, "collection": "verified"})
                lanes.append({"lane": "rpm", "system": system, "module": "rs9.hosted_packaging",
                              "artifact_name": output.name,
                              "required_gates": ["rpm-lint-policy-accepted", "rpm-client-qualification"]})
                view = rpm_lint_results([receipt])[0]
                self.assertFalse(view["raw_clean"])
                self.assertEqual(view["raw_exit_code"], 64)
                self.assertFalse(view["policy"]["accepted"])
                self.assertEqual(view["downstream_dnf"]["status"], "not-run")
            jobs = [{"name": name, "status": "completed", "conclusion": "success", "steps": []}
                    for name in ("config", "unit", "rpm-x86_64-linux", "rpm-aarch64-linux")]
            packet = {"source_commit": "0" * 40, "artifacts": artifacts, "jobs": jobs}
            scope = diagnostic_scope(ROOT, root / "packet", packet, {"lanes": lanes})
            self.assertFalse(scope["partial_diagnostic_lanes_all_pass"])
            for lane in scope["required_lanes"]:
                self.assertEqual(lane["integrity"], "verified")
                self.assertNotIn("rpm-policy-custody-invalid", lane["reasons"])
            (root / "packet/manager-packet.json").write_bytes(canonical(packet))
            with zipfile.ZipFile(operator.small_result_zip(root / "packet")) as archive:
                selection = json.loads(archive.read("result-selection.json"))
                names = [row["path"] for row in selection["files"]]
                for artifact in artifacts:
                    self.assertTrue(any(name.startswith(artifact["name"] + "/") and ".part-" in name for name in names))
                self.assertFalse(selection["large_packages_embedded"])

    def test_selected_summary_identity_must_match_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            output, manifest, receipt, _ = self.make_packet(Path(tmp).resolve(), "x86_64-linux")
            changed = copy.deepcopy(receipt)
            changed["system"] = "aarch64-linux"
            with self.assertRaises(ContractError):
                validate_rpm_policy_custody(output, manifest, changed)

    def test_missing_selected_chunk_is_custody_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            output, manifest, receipt, _ = self.make_packet(Path(tmp).resolve(), "x86_64-linux")
            chunk = next(row for row in manifest["files"] if ".part-" in row["path"])
            (output / chunk["path"]).unlink()
            with self.assertRaises((ContractError, OSError)):
                validate_rpm_policy_custody(output, manifest, receipt)

    def test_downgraded_summary_cannot_bypass_chunk_verification(self):
        with tempfile.TemporaryDirectory() as tmp:
            output, manifest, receipt, _ = self.make_packet(Path(tmp).resolve(), "x86_64-linux")
            summary = next(iter(receipt["details"]["rpm_lint_policy"].values()))
            summary["schema"] = "rs9.rpm-lint-policy-evaluation.v1"
            with self.assertRaises(ContractError):
                validate_rpm_policy_custody(output, manifest, receipt)

    def test_unknown_contract_marker_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            output, manifest, receipt, _ = self.make_packet(Path(tmp).resolve(), "x86_64-linux")
            receipt["details"]["rpm_evidence_contract"] = "rs9.rpm-evidence-contract.unknown"
            with self.assertRaises(ContractError):
                validate_rpm_policy_custody(output, manifest, receipt)

    def test_historical_contract_is_explicit_and_has_no_qualification_authority(self):
        from rs9.rpm_evidence import historical_policy_diagnostic
        evaluation = json.loads((FIXTURES / "x86_64-linux/policy-evaluation.json").read_bytes())
        receipt = {"production_enabled": False, "publication_authority": False,
                   "details": {"rpm_lint_policy": {evaluation["inputs"]["project_id"]: evaluation}}}
        view = historical_policy_diagnostic(receipt, contract="cont12-inline")
        self.assertFalse(view["qualification_authority"])
        self.assertEqual(next(iter(view["evaluations"].values())), evaluation)
        with self.assertRaises(ContractError):
            historical_policy_diagnostic(receipt, contract="automatic")
        receipt["details"]["rpm_evidence_contract"] = "rs9.rpm-evidence-contract.v2"
        with self.assertRaises(ContractError):
            historical_policy_diagnostic(receipt, contract="cont12-inline")

    def test_tampered_raw_lint_fails_custody(self):
        with tempfile.TemporaryDirectory() as tmp:
            output, manifest, receipt, _ = self.make_packet(Path(tmp).resolve(), "x86_64-linux")
            raw_file = next(row for row in manifest["files"] if "rpmlint-" in row["path"])
            (output / raw_file["path"]).write_bytes(b'{"tampered": true}')
            with self.assertRaises((ContractError, OSError)):
                validate_rpm_policy_custody(output, manifest, receipt)

    def test_surplus_raw_file_on_disk_fails_custody(self):
        with tempfile.TemporaryDirectory() as tmp:
            output, manifest, receipt, _ = self.make_packet(Path(tmp).resolve(), "x86_64-linux")
            raw_file = next(row for row in manifest["files"] if "rpmlint-" in row["path"])
            surplus = (output / raw_file["path"]).parent / "rpmlint-theme-forge-nebular-fusion.surplus.json"
            surplus.write_bytes(b"{}")
            with self.assertRaises(ContractError):
                validate_rpm_policy_custody(output, manifest, receipt)
