"""Final reuse joins use real custody/ZIP validators and original-run seams."""
import copy
import hashlib
import json
from pathlib import Path
import shutil
import unittest
from tests import test_current_pacman_any as fixtures
from rs9.current_generation import CURRENT_GENERATION
from rs9.current_pacman_reuse import candidate_reuse, original_reuse, ARM_ARTIFACT, WITNESS_PATH
from rs9.errors import ContractError
from rs9.hosted_custody import retain
from rs9.scratch import canonical


class ReuseJoinTests(unittest.TestCase):
    def setUp(self):
        f = self.f = fixtures.WitnessValidationTests()
        f.setUp()
        self.addCleanup(f.doCleanups)
        self.inputs = f.canonical_directory.parent
        scratch = f.fresh("arm-producer")
        lane = scratch / "lane-work"
        files = []
        doc = json.loads(f.witness)
        for product, source in f.replicas.items():
            target = lane / doc["files"][product]["replica_path"]
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source,target)
            files.append(target)
        witness = lane / "canonical-any-witness.json"
        witness.write_bytes(f.witness)
        files.append(witness)
        declared = {"role":"reuse-witness","construction_on_this_lane":False,
                    "construction_authority":{"family":"pacman","system":"x86_64-linux"},
                    "witness_file":witness.name,"witness_sha256":hashlib.sha256(f.witness).hexdigest(),
                    "replicas":{p:{"file":d["replica_path"],"sha256":d["sha256"],"size":d["size"]}
                                for p,d in doc["files"].items()}}
        receipt = {"lane":"pacman","system":"aarch64-linux","provenance":f.source,"runner":{},
                   "execution_error":None,"gates":[],"details":{"canonical_any_reuse":declared}}
        self.manifest=retain(scratch,self.inputs / ARM_ARTIFACT,files,receipt)
        self.packet=copy.deepcopy(f.packet)
        self.packet["artifacts"].append({"name":ARM_ARTIFACT,"collection":"verified","zip_digest_verified":True,
            "manifest_sha256":hashlib.sha256((self.inputs/ARM_ARTIFACT/"artifact-manifest.json").read_bytes()).hexdigest()})

    def candidate(self):
        return candidate_reuse(fixtures.ROOT,self.inputs,self.f.source)

    def original(self):
        return original_reuse(fixtures.ROOT,self.inputs,self.packet,self.f.original_run,self.f.source)

    def test_candidate_consistency_and_final_original_join(self):
        result=self.candidate()
        self.assertEqual(set(result["replicas"]),set(fixtures.any_mod.ANY_PRODUCTS))
        result=self.original()
        self.assertEqual(result["construction_authority"],"pacman/x86_64-linux")
        self.assertTrue(all(ARM_ARTIFACT not in str(p) for p in result["custody_paths"].values()))

    def test_substituted_replica_stops_both_boundaries(self):
        target=next((self.inputs/ARM_ARTIFACT/"objects/lane-work/canonical-any/files").iterdir())
        target.write_bytes(b"substitution")
        for call in (self.candidate,self.original):
            with self.subTest(boundary=call.__name__),self.assertRaises(ContractError):
                call()

    def test_original_join_requires_original_importer_artifact_readback(self):
        for field,value in (("collection","pending"),("zip_digest_verified",False),("manifest_sha256","0"*64)):
            saved=copy.deepcopy(self.packet)
            self.packet["artifacts"][-1][field]=value
            with self.subTest(field=field),self.assertRaises(ContractError):
                self.original()
            self.packet=saved

    def test_closed_witness_receipt_cannot_declare_arm_construction(self):
        path=self.inputs/ARM_ARTIFACT/"pacman-aarch64-linux.json"
        receipt=json.loads(path.read_bytes())
        receipt["details"]["canonical_any_reuse"]["construction_on_this_lane"]=True
        path.write_bytes(canonical(receipt))
        manifest=self.inputs/ARM_ARTIFACT/"artifact-manifest.json"
        doc=json.loads(manifest.read_bytes())
        doc["qualification_receipt_hashes"][path.name]=hashlib.sha256(path.read_bytes()).hexdigest()
        manifest.write_bytes(canonical(doc))
        with self.assertRaises(ContractError):
            self.candidate()

    def test_final_provider_refusal_remains_distinct_from_candidate_consistency(self):
        self.candidate()
        for field,value in (("run_id",self.f.packet["run_id"]+1),("source_commit","0"*40)):
            saved=copy.deepcopy(self.packet)
            self.packet[field]=value
            with self.subTest(field=field),self.assertRaises(ContractError):
                self.original()
            self.packet=saved
