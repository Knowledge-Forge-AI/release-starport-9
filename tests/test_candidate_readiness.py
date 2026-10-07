import copy
import hashlib
import json
from pathlib import Path
import unittest
import tempfile

from rs9.candidate_readiness import readiness_record, validate_readiness, validate_adoption_authority
from rs9.errors import ContractError
from rs9.operator import preparation_status


class ReadinessTests(unittest.TestCase):
    def fixture(self):
        return {"adoption_scope": "partial-diagnostic", "candidate_adoption_ready": True,
                "production_enabled": False, "publication_authority": False,
                "readiness": readiness_record()}

    def test_ready_source_remains_unqualified_and_unpublished(self):
        result = validate_readiness(self.fixture())
        self.assertFalse(result["full_live1_qualification"])
        self.assertFalse(result["published_linux_nix_ready"])
        self.assertEqual(len(result["known_unqualified_lanes"]), 2)

    def test_types_scope_gates_and_unknown_keys_fail_closed(self):
        for key, value in (("full_live1_qualification", True), ("production_enabled", 0),
                           ("publication_authority", True), ("source_adoption_scope", "full"),
                           ("known_unqualified_lanes", []), ("surplus", False)):
            doc = self.fixture()
            doc["readiness"][key] = value
            with self.subTest(key=key), self.assertRaises(ContractError):
                validate_readiness(doc)
        for key, value in (("publication_authority", True), ("candidate_adoption_ready", 1),
                           ("adoption_scope", "hosted-candidate-qualification-only")):
            doc = self.fixture(); doc[key] = value
            with self.assertRaises(ContractError):
                validate_readiness(doc)
        with self.assertRaises(ContractError):
            validate_readiness(self.fixture(), {"lanes": []})

    def test_operator_emits_aligned_live_readiness(self):
        root = Path(__file__).resolve().parents[1]
        manifest = json.loads((root / "operators/live1/candidate-manifest.json").read_bytes())
        emitted = preparation_status(root)["readiness"]
        self.assertEqual(emitted["readiness"], manifest["readiness"])
        self.assertEqual(emitted["candidate_adoption_ready"], manifest["candidate_adoption_ready"])
        validate_readiness(emitted, require_ready=False)

    def test_external_acceptance_binds_unmodified_unready_source_and_rejects_drift(self):
        binding = {"reviewed_parent": "a" * 40, "reviewed_tree": "b" * 40,
                   "manifest_sha256": "c" * 64}
        doc = {"schema": "rs9.manager-source-adoption-attestation.v1alpha1",
               "decision": "accept", "source_adoption_scope": "partial-diagnostic",
               **binding, "full_live1_qualification": False,
               "production_enabled": False, "publication_authority": False}
        manifest = self.fixture(); manifest["candidate_adoption_ready"] = False
        original = copy.deepcopy(manifest)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve(); repo = root / "repo"; repo.mkdir()
            path = root / "acceptance.json"
            def check(record, digest=None, target=path):
                raw = json.dumps(record).encode(); target.write_bytes(raw)
                return validate_adoption_authority(manifest, repo, binding,
                    manager_attestation=target,
                    manager_attestation_sha256=digest or hashlib.sha256(raw).hexdigest())
            self.assertEqual(check(doc), doc)
            self.assertEqual(manifest, original)
            for key, value in (("reviewed_tree", "d" * 40), ("reviewed_parent", "d" * 40),
                               ("manifest_sha256", "d" * 64), ("decision", "defer"),
                               ("source_adoption_scope", "full"), ("production_enabled", True),
                               ("publication_authority", 0), ("full_live1_qualification", True),
                               ("extra", "ignored")):
                with self.subTest(key=key), self.assertRaises(ContractError):
                    check({**doc, key: value})
            with self.assertRaises(ContractError):
                check(doc, digest="0" * 64)
            with self.assertRaises(ContractError):
                check(doc, target=repo / "acceptance.json")
            link = root / "link.json"; link.symlink_to(path)
            with self.assertRaises(ContractError):
                validate_adoption_authority(manifest, repo, binding, manager_attestation=link,
                    manager_attestation_sha256=hashlib.sha256(path.read_bytes()).hexdigest())
            for args in ({"manager_attestation": path}, {"manager_attestation_sha256": "c" * 64}, {}):
                with self.assertRaises(ContractError):
                    validate_adoption_authority(manifest, repo, binding, **args)
            raw = json.dumps(doc)[:-1] + ', "decision": "accept"}'
            path.write_text(raw)
            with self.assertRaises(ContractError):
                validate_adoption_authority(manifest, repo, binding, manager_attestation=path,
                    manager_attestation_sha256=hashlib.sha256(raw.encode()).hexdigest())
