"""Fixture custody exercises source-defined completeness and fail-closed summary semantics."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from rs9.errors import ContractError
from rs9.hosted_custody import provenance, retain
from rs9.hosted_summary import contract, required, summarize, validate_summary, LINUX_WHEEL_PROMOTION_BLOCKER
from rs9.scratch import canonical
ROOT=Path(__file__).resolve().parents[1]

class HostedSummaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name).resolve()
        self.inputs=self.root / "inputs"; self.inputs.mkdir()
        self.output=self.root / "summary"
        jobs={j:{"result":"success"} for j in contract(ROOT)["required_jobs"] if j!="summary"}
        env=patch.dict("os.environ",{"GITHUB_SHA":"1"*40,"GITHUB_REF":"refs/heads/main",
            "GITHUB_EVENT_NAME":"push","GITHUB_RUN_ATTEMPT":"1","RS9_JOB_CONCLUSIONS":json.dumps(jobs)})
        env.start();self.addCleanup(env.stop)
        for row in required(ROOT):
            scratch=self.root / row["artifact_name"];scratch.mkdir()
            files=[]
            if row.get("custody_required"):
                for product in row["required_products"]:
                    from rs9.product_classes import is_pure_js_cli
                    pure = is_pure_js_cli(product)
                    if row["lane"] == "wheels":
                        tag = "any" if pure else {"aarch64-darwin": "macosx_11_0_arm64", "x86_64-linux": "linux_x86_64", "aarch64-linux": "linux_aarch64"}[row["system"]]
                        name = product.replace("-", "_") + "-0.6.1-py3-none-" + tag + ".whl"
                    elif row["lane"] == "deb":
                        name = product + "_0.6.1_" + ("all" if pure else row["system"]) + ".deb"
                    elif row["lane"] == "rpm":
                        arch = "noarch" if pure else {"x86_64-linux": "x86_64", "aarch64-linux": "aarch64"}[row["system"]]
                        name = product + "-0.6.1-1." + arch + ".rpm"
                    else:
                        name = product + "-0.6.1-1-" + ("any" if pure else "x86_64") + ".pkg.tar.zst"
                    path=scratch / "unsigned" / name;path.parent.mkdir(exist_ok=True);path.write_bytes(b"fixture-custody")
                    files.append(path)
            else:
                path=scratch / "fixture-evidence.json";path.write_bytes(b"{}");files.append(path)
            receipt={"schema":"rs9.hosted-candidate-diagnostic.v1alpha2","lane":row["lane"],"system":row["system"],
                "production_enabled":False,"publication_authority":False,"attended_gates_satisfied":False,
                "execution_error":None,"policy_blockers":[],"runner":{},"provenance":provenance(ROOT,"a"*64),
                "production_promotion_blockers": [LINUX_WHEEL_PROMOTION_BLOCKER] if row["lane"] == "wheels" and row["system"].endswith("linux") else [],
                "gates":[{"name":g,"status":"pass"} for g in row["required_gates"]]}
            retain(scratch,self.inputs / row["artifact_name"],files,receipt)

    def test_burst_architecture_independent_custody_is_rejected(self):
        from rs9.hosted_summary import validate_product_architectures
        for family, system, name in (
            ("wheels", "x86_64-linux", "theme_forge_stellar_burst-0.6.1-py3-none-any.whl"),
            ("pacman", "x86_64-linux", "theme-forge-stellar-burst-0.6.1-1-any.pkg.tar.zst"),
            ("rpm", "x86_64-linux", "theme-forge-stellar-burst-0.6.1-1.noarch.rpm"),
            ("deb", "amd64", "theme-forge-stellar-burst_0.6.1_all.deb"),
        ):
            with self.subTest(family=family):
                lane = {"lane": family, "system": system, "required_products": ["theme-forge-stellar-burst"]}
                with self.assertRaises(ContractError) as caught:
                    validate_product_architectures(lane, [{"path": "objects/" + name, "kind": "custody"}])
                self.assertEqual(caught.exception.code, "CUSTODY_ARCHITECTURE")

    def mutate_receipt(self,lane,system,change):
        directory=self.inputs / ("candidate-"+lane+"-"+system)
        path=directory / (lane+"-"+system+".json")
        row=json.loads(path.read_bytes());change(row);path.write_bytes(canonical(row))
        import hashlib
        mp=directory / "artifact-manifest.json";manifest=json.loads(mp.read_bytes())
        manifest["qualification_receipt_hashes"]={path.name:hashlib.sha256(path.read_bytes()).hexdigest()}
        mp.write_bytes(canonical(manifest))

    def finish(self):
        code=summarize(ROOT,self.inputs,self.output)
        return code,json.loads((self.output / "hosted-summary.json").read_bytes())

    def test_complete_fixture_can_qualify_without_publication_authority(self):
        code,row=self.finish()
        self.assertEqual(code,0)
        self.assertTrue(row["lanes_executed_ok"])
        self.assertFalse(row["publication_authority"])
        self.assertTrue(row["production_promotion_blocked"])
        self.assertEqual(row["production_promotion_blockers"], [LINUX_WHEEL_PROMOTION_BLOCKER])
        self.assertEqual(validate_summary(row,ROOT,"1"*40)["qualification_verdict"],"qualified")

    def test_missing_artifact_preserves_bounded_failed_summary(self):
        import shutil
        shutil.rmtree(self.inputs / "candidate-deb-arm64")
        code,row=self.finish()
        self.assertEqual(code,2);self.assertFalse(row["lanes_executed_ok"])
        self.assertTrue(row["blocking_reasons"])

    def test_tampered_object_fails(self):
        next(self.inputs.rglob("*.deb")).write_bytes(b"tampered")
        self.assertEqual(self.finish()[0],2)

    def test_mixed_commit_fails(self):
        path=self.inputs / "candidate-pins-generation/artifact-manifest.json"
        row=json.loads(path.read_bytes());row["source_commit"]="2"*40;path.write_bytes(canonical(row))
        self.assertEqual(self.finish()[0],2)

    def test_required_not_run_fails(self):
        self.mutate_receipt("nix","x86_64-linux",lambda r:r["gates"][0].update(status="not-run",reason="unavailable"))
        self.assertEqual(self.finish()[0],2)

    def test_allowed_darwin_offline_not_run_is_truthful(self):
        def change(r):
            next(g for g in r["gates"] if g["name"]=="wheel-offline-isolation").update(
                status="not-run",reason="darwin-offline-isolation-unsupported")
        self.mutate_receipt("wheels","aarch64-darwin",change)
        self.assertEqual(self.finish()[0],0)

    def test_missing_one_product_fails_despite_other_custody(self):
        import hashlib
        directory=self.inputs / "candidate-deb-amd64"
        manifest=json.loads((directory / "artifact-manifest.json").read_bytes())
        row=manifest["files"].pop();(directory / row["path"]).unlink()
        (directory / "artifact-manifest.json").write_bytes(canonical(manifest))
        self.assertEqual(self.finish()[0],2)

    def test_policy_blocker_separate_from_lane_execution_health(self):
        self.mutate_receipt("pins","generation",lambda r:r["policy_blockers"].append("run-resolved"))
        code,row=self.finish()
        self.assertEqual(code,2);self.assertTrue(row["lanes_executed_ok"])

    def test_duplicate_or_surplus_artifacts_fail(self):
        (self.inputs / "surplus").mkdir()
        self.assertEqual(self.finish()[0],2)

    def test_failure_in_source_test_job_prevents_qualification(self):
        with patch.dict("os.environ",{"RS9_JOB_CONCLUSIONS":"{}"}):
            self.assertEqual(self.finish()[0],2)

    def test_operator_rejects_forged_qualified_receipt(self):
        _,row=self.finish()
        row["receipts"][0]["policy_blockers"]=["pending"]
        with self.assertRaises(ContractError):
            validate_summary(row,ROOT,"1"*40)

    def test_linux_promotion_blocker_cannot_be_omitted(self):
        self.mutate_receipt("wheels", "x86_64-linux", lambda r: r.update(production_promotion_blockers=[]))
        code, row = self.finish()
        self.assertEqual(code, 2)
        with self.assertRaises(ContractError) as caught:
            validate_summary(row, ROOT, "1" * 40)
        self.assertEqual(caught.exception.code, "HOSTED_POLICY")

    def test_summary_cannot_strip_promotion_blockers(self):
        _, row = self.finish()
        row.update(production_promotion_blockers=[], production_promotion_blocked=False)
        with self.assertRaises(ContractError) as caught:
            validate_summary(row, ROOT, "1" * 40)
        self.assertEqual(caught.exception.code, "HOSTED_POLICY")

    def test_destination_details_surfaced_in_summary_independently_of_pages_unknown(self):
        """WP-DEST: per-destination satisfied/exact/noops surfaced in summary while aggregate is blocked for unknown Pages."""
        npm_noops = ["theme-forge-stellar-burst", "theme-forge-stellar-loom", "theme-forge-solar-sail", "theme-forge-nebular-fusion"]
        brew_noops = ["theme-forge-stellar-burst", "theme-forge-stellar-loom", "theme-forge-solar-sail", "theme-forge-nebular-fusion"]
        all_8_noops = [p + ":npm" for p in npm_noops] + [p + ":homebrew" for p in brew_noops]
        all_8_exact = all_8_noops
        all_12_satisfied = [p + ":pypi" for p in npm_noops] + all_8_noops
        destinations = {
            "pypi": {"satisfied": True, "satisfied_count": 4, "total_count": 4, "exact": [], "exact_count": 0, "planner_noops": [], "states": {p: "absent" for p in npm_noops}},
            "npm": {"satisfied": True, "satisfied_count": 4, "total_count": 4, "exact": npm_noops, "exact_count": 4, "planner_noops": npm_noops, "states": {p: "exact" for p in npm_noops}},
            "homebrew": {"satisfied": True, "satisfied_count": 4, "total_count": 4, "exact": brew_noops, "exact_count": 4, "planner_noops": brew_noops, "states": {p: "exact" for p in brew_noops}},
            "pages": {"satisfied": False, "satisfied_count": 0, "total_count": 1, "exact": [], "exact_count": 0, "planner_noops": [], "states": {"generation": "unknown"}},
        }
        def update_observe(r):
            # Pages unknown blocks the gate
            next(g for g in r["gates"] if g["name"] == "readback-byte-comparison").update(
                status="not-run", reason="observations-recorded-with-unknown-or-metadata-only-states"
            )
            r["details"] = {
                "destinations": destinations,
                "planner_noops": all_8_noops,
                "satisfied_observations": all_12_satisfied,
                "exact_observations": all_8_exact,
            }
        self.mutate_receipt("observe", "generation", update_observe)
        code, row = self.finish()

        # Aggregate qualification is blocked
        self.assertEqual(code, 2)
        self.assertEqual(row["qualification_verdict"], "not-qualified")
        self.assertIn("candidate-observe-generation:not-run:readback-byte-comparison", row["blocking_reasons"])

        # Per-destination observations and 8 noops are exposed in summary independently of Pages unknown
        self.assertEqual(row["destinations"]["npm"]["satisfied"], True)
        self.assertEqual(row["destinations"]["npm"]["exact_count"], 4)
        self.assertEqual(row["destinations"]["homebrew"]["satisfied"], True)
        self.assertEqual(row["destinations"]["homebrew"]["exact_count"], 4)
        self.assertEqual(row["destinations"]["pages"]["satisfied"], False)
        self.assertEqual(len(row["destination_planner_noops"]), 8)
        self.assertEqual(row["destination_planner_noops"], all_8_noops)
        self.assertEqual(len(row["destination_exact"]), 8)
        self.assertEqual(len(row["destination_satisfied"]), 12)
