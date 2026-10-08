"""Failed A/experiment/custody evidence must not hide independently verified Q."""
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from rs9.collect_candidate import collect, REPOSITORY, WORKFLOW
from rs9.hosted_custody import provenance
from rs9.scratch import canonical


def archive(files):
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as stream:
        for name, data in files.items():
            stream.writestr(name, data)
    return out.getvalue()


class DiagnosticCollectionTests(unittest.TestCase):
    def attempt(self, *, a_fail=True, tamper_experiment=False, bad_summary=False,
                experiment_skipped=False, experiment_pass=False, q_fail=False, surplus=False, rpm_gate=None):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve(); out = root / "out"; out.mkdir()
            for path, content in ((".github/workflows/rs9-candidate-tests.yml", "jobs: {}"),
                                  ("flake.nix", "{}"), ("operators/live1/targets.json", "{}"),
                                  ("operators/live1/command-contracts.json", "{}")):
                p = root / path; p.parent.mkdir(parents=True, exist_ok=True); p.write_text(content)
            lanes = [{"lane": lane, "system": system, "module": "rs9.hosted_" + lane,
                      "artifact_name": "candidate-" + lane + "-" + system, "required_gates": ["runtime"]}
                     for lane, system in (("deb", "amd64"), ("nix", "x86_64-linux"))]
            if rpm_gate is not None:
                lanes.append({"lane": "rpm", "system": "x86_64-linux", "module": "rs9.hosted_packaging",
                              "artifact_name": "candidate-rpm-x86_64-linux",
                              "required_gates": ["rpm-lint-policy-accepted"]})
            exp = {"lane": "nix-proot", "system": "x86_64-linux", "module": "rs9.hosted_nix_proot",
                   "artifact_name": "experiment-nix-proot-x86_64-linux", "experiment_gates": ["runtime"], "qualification_authority": False}
            contract = {"schema": "rs9.hosted-lanes.v1alpha1", "production_enabled": False, "lanes": lanes, "experiments": [exp], "required_jobs": ["config", "unit", "deb", "nix", "summary"]}
            if rpm_gate is not None:
                contract["required_jobs"].append("rpm")
            (root / "operators/live1/hosted-lanes.json").write_bytes(canonical(contract))
            commit = "a" * 40
            prov = provenance(root, "b" * 64)
            prov.update(source_commit=commit, event="push", ref="refs/heads/main", attempt=1)
            blobs, receipts, manifests = {}, [], []
            for lane in lanes + ([] if experiment_skipped else [exp]):
                experimental = lane is exp
                failed = (experimental and not experiment_pass) or (lane["lane"] == "nix" and a_fail) or (lane["lane"] == "deb" and q_fail)
                name = lane["lane"] + "-" + lane["system"] + ".json"
                row = {"schema": "rs9.hosted-experiment-diagnostic.v1alpha1" if experimental else "rs9.hosted-candidate-diagnostic.v1alpha2",
                       "lane": lane["lane"], "system": lane["system"], "production_enabled": False,
                       "publication_authority": False, "qualification_authority": False,
                       "application_qualified": False, "mandatory_gates_satisfied": False,
                       "provenance": prov, "network": {"runtime_offline_status": "not-run" if experimental and not experiment_pass else "pass"},
                       "policy_blockers": [], "production_promotion_blockers": ["experimental-unqualified"] if experimental else [],
                       "gates": [{"name": "runtime", "status": "fail" if failed else "pass"}]}
                if lane["lane"] == "rpm":
                    row["gates"] = [{"name": rpm_gate, "status": "pass"}]
                    row["details"] = {"rpm_lint_raw": {"fixture": {"status": "fail", "clean": False,
                        "tool_receipt": {"exit_code": 64}, "findings_summary": {"errors": 1, "filtered": 8}}},
                        "rpm_lint_policy": {"fixture": {"accepted": True, "accepted_findings": []}}}
                if experimental and experiment_pass:
                    row["gates"].append({"name": "proot-in-guest-offline", "status": "pass",
                                         "runtime_offline_status": "pass"})
                raw = canonical(row); payload = b"retained-native-evidence"
                manifest = {"schema": "rs9.hosted-artifact-set.v1alpha2", **prov,
                            "lane": lane["lane"], "system": lane["system"], "production_enabled": False,
                            "publication_authority": False, "runner": {},
                            "qualification_receipt_hashes": {name: hashlib.sha256(raw).hexdigest()},
                            "files": [{"path": "objects/evidence.json", "size": len(payload),
                                       "sha256": hashlib.sha256(payload).hexdigest(), "kind": "evidence", "promotion": "candidate-only"}]}
                blobs[lane["artifact_name"]] = archive({name: raw, "artifact-manifest.json": canonical(manifest),
                    "objects/evidence.json": b"tampered-native-evidence" if experimental and tamper_experiment else payload})
                if not experimental:
                    receipts.append(row); manifests.append(manifest)
            summary = {"schema": "rs9.hosted-candidate-summary.v1alpha2", **prov,
                       "production_enabled": False, "publication_authority": False,
                       "adoptable": True, "receipts": receipts, "artifact_manifests": manifests,
                       "qualification_verdict": "not-qualified" if a_fail or q_fail else "qualified",
                       "blocking_reasons": ["nix-failed"] if a_fail else [],
                       "production_promotion_blockers": [], "production_promotion_blocked": False,
                       "job_conclusions": {k: "failure" if k == "nix" and a_fail else "success" for k in contract["required_jobs"] if k != "summary"}}
            blobs["hosted-summary"] = archive({"hosted-summary.json": b"{bad" if bad_summary else canonical(summary)})
            if surplus:
                blobs["undeclared"] = blobs[lanes[0]["artifact_name"]]
            artifacts = [{"id": i, "name": n, "digest": "sha256:" + hashlib.sha256(b).hexdigest(), "expired": False}
                         for i, (n, b) in enumerate(blobs.items(), 1)]
            jobs = [{"id": i, "name": n, "status": "completed",
                     "conclusion": "skipped" if n.startswith("nix-proot") and experiment_skipped else
                        "failure" if n.startswith("nix-proot") and not experiment_pass or n == "nix-x86_64-linux" and a_fail else "success",
                     "steps": [{"conclusion": "failure" if n.startswith("nix-proot") and not experiment_pass else "success"}]}
                    for i, n in enumerate(["deb-amd64", "nix-x86_64-linux", "config", "unit", "summary", "nix-proot-x86_64-linux"] + (["rpm-x86_64-linux"] if rpm_gate is not None else []), 1)]
            def runner(_, argv):
                endpoint = argv[-1]
                if "/jobs?" in endpoint: return json.dumps({"total_count": len(jobs), "jobs": jobs})
                if "/artifacts?" in endpoint: return json.dumps({"total_count": len(artifacts), "artifacts": artifacts})
                if endpoint.endswith("/zip"):
                    identity = int(endpoint.split("/")[-2]); return blobs[artifacts[identity - 1]["name"]]
                return json.dumps({"id": 7, "head_sha": commit, "event": "push", "head_branch": "main",
                    "path": ".github/workflows/" + WORKFLOW, "run_attempt": 1,
                    "repository": {"full_name": REPOSITORY}, "status": "completed", "conclusion": "failure",
                    "created_at": "2026-10-07T14:00:01Z"})
            with patch("rs9.collect_candidate.output_directory", return_value=out):
                packet = collect(root, out, commit=commit, run_id=7, timeout=30,
                                 started_at=datetime(2026, 10, 7, 14, tzinfo=timezone.utc), runner=runner)
            self.assertEqual(packet, json.loads((out / "manager-packet.json").read_bytes()))
            return packet

    def test_a_failure_retains_verified_q_and_not_qualified_verdict(self):
        packet = self.attempt()
        self.assertEqual(packet["classification"], "a-only-unqualified")
        self.assertEqual(packet["status"], "not-qualified")
        self.assertTrue(packet["diagnostic_scope"]["partial_diagnostic_lanes_all_pass"])
        self.assertFalse(packet["diagnostic_scope"]["full_live1_qualification"])
        self.assertEqual(packet["diagnostic_scope"]["experiments"][0]["status"], "fail")

    def test_passing_experiment_is_visible_without_qualifying_legacy_a(self):
        packet = self.attempt(experiment_pass=True)
        self.assertEqual(packet["diagnostic_scope"]["experiments"][0]["status"], "pass")
        self.assertEqual(packet["classification"], "a-only-unqualified")
        self.assertFalse(packet["diagnostic_scope"]["full_live1_qualification"])
        self.assertFalse(packet["diagnostic_scope"]["published_linux_nix_ready"])

    def test_experiment_custody_and_invalid_summary_do_not_hide_q(self):
        for options in ({"tamper_experiment": True}, {"bad_summary": True}):
            with self.subTest(options=options):
                packet = self.attempt(**options)
                self.assertEqual(packet["classification"], "collection-failure")
                self.assertTrue(packet["diagnostic_scope"]["partial_diagnostic_lanes_all_pass"])
                self.assertFalse(packet["diagnostic_scope"]["full_live1_qualification"])

    def test_q_failure_is_distinct(self):
        self.assertEqual(self.attempt(q_fail=True)["classification"], "b-e-unqualified")

    def test_failed_non_authoritative_experiment_does_not_replace_required_gates(self):
        for skipped in (False, True):
            packet = self.attempt(a_fail=False, experiment_skipped=skipped)
            self.assertEqual(packet["validation"]["status"], "pass")
            self.assertTrue(packet["diagnostic_scope"]["full_live1_qualification"])
            self.assertFalse(packet["diagnostic_scope"]["published_linux_nix_ready"])
        packet = self.attempt(a_fail=False, surplus=True)
        self.assertEqual(packet["validation"]["status"], "fail")

    def test_rpm_policy_gate_migration_and_raw_evidence_survive_real_collection(self):
        for name, expected in (("rpm-lint-policy-accepted", "pass"), ("rpm-rpmlint-clean", "fail")):
            with self.subTest(name=name):
                packet = self.attempt(rpm_gate=name)
                rpm = next(r for r in packet["diagnostic_scope"]["required_lanes"] if r["lane"] == "rpm")
                self.assertEqual(rpm["status"], expected)
                self.assertEqual(rpm["rpm_lint_results"][0]["raw_status"], "fail")
                self.assertEqual(rpm["rpm_lint_results"][0]["raw_exit_code"], 64)
                if expected == "fail":
                    self.assertIn("missing-or-duplicate-gate:rpm-lint-policy-accepted", rpm["reasons"])
