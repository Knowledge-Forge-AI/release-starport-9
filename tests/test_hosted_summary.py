"""Fixture custody exercises source-defined completeness and fail-closed summary semantics."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from rs9.errors import ContractError
from rs9.hosted_custody import provenance, retain
from rs9.hosted_summary import contract, required, summarize, validate_summary
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
                    name=product.replace("-","_")+"-0.6.1-py3-none-any.whl" if row["lane"]=="wheels" else product+"_0.6.1_all.deb" if row["lane"]=="deb" else product+"-0.6.1-1.rpm" if row["lane"]=="rpm" else product+"-0.6.1-1.pkg.tar.zst"
                    path=scratch / "unsigned" / name;path.parent.mkdir(exist_ok=True);path.write_bytes(b"fixture-custody")
                    files.append(path)
            else:
                path=scratch / "fixture-evidence.json";path.write_bytes(b"{}");files.append(path)
            receipt={"schema":"rs9.hosted-candidate-diagnostic.v1alpha2","lane":row["lane"],"system":row["system"],
                "production_enabled":False,"publication_authority":False,"attended_gates_satisfied":False,
                "execution_error":None,"policy_blockers":[],"runner":{},"provenance":provenance(ROOT,"a"*64),
                "gates":[{"name":g,"status":"pass"} for g in row["required_gates"]]}
            retain(scratch,self.inputs / row["artifact_name"],files,receipt)

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
