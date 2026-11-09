"""Unit-only 0.8 paired-consumer proof tests; no native or publication claim."""
import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from rs9 import own_repository_admission as own071
from rs9 import own_repository_admission080 as own080
from rs9.current_generation import CURRENT_GENERATION, CURRENT080_POLICY_VARIANT
from rs9.errors import ContractError
from rs9.qualified_distribution_inputs import SourceBoundConfiguration
from rs9.scratch import canonical


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = Path(__file__).resolve().parent / "fixtures/own-repository-admission080/consumer"
OLD_FIXTURE = Path(__file__).resolve().parent / "fixtures/own-repository-admission071/p-source"
OLD_IMPORTER = Path(__file__).resolve().parent / "fixtures/own-repository-admission071/paired-importer.py"
COMMIT, TREE, PCOMMIT, PTREE = "1" * 40, "2" * 40, "f" * 40, "e" * 40
START = datetime(2026, 10, 29, tzinfo=timezone.utc)


class Own080SourceFixtures(unittest.TestCase):
    """Synthetic Git/API/run values exercise real source and custody checks."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.config = SourceBoundConfiguration(ROOT, COMMIT, TREE, 7, START, *(["a" * 64] * 5))
        self.p = self.root / "p"
        shutil.copytree(FIXTURE, self.p)
        self.descriptor = {
            "schema": "theme-forge.current-rs9-input-source.v1",
            "generation": CURRENT_GENERATION,
            "status": "qualified-original-run-inputs",
            "production_enabled": False,
            "publication_authority": False,
            "rs9": {**self.config.expected(), "not_before": START.isoformat()},
        }
        self.write_descriptor()
        self.rebuild_tree()

    def write_descriptor(self):
        path = self.p / own080.DESCRIPTOR
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(canonical(self.descriptor))

    def rebuild_tree(self):
        self.rows = []
        for name in sorted(set(own080.CONSUMER_FILE_HASHES_080) | {own080.DESCRIPTOR}):
            data = (self.p / name).read_bytes()
            self.rows.append({
                "path": name,
                "type": "blob",
                "mode": "100644",
                "sha": hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest(),
            })

    def api(self, root, argv):
        endpoint = argv[-1]
        self.assertTrue(endpoint.startswith("repos/" + own080.TARGET + "/"))
        if endpoint.endswith("git/ref/heads/main"):
            return json.dumps({"object": {"type": "commit", "sha": PCOMMIT}})
        if "/git/commits/" in endpoint:
            return json.dumps({"sha": PCOMMIT, "tree": {"sha": PTREE}})
        return json.dumps({"sha": PTREE, "truncated": False, "tree": self.rows})

    def verify(self):
        with patch.object(own080, "source_tree_identity", return_value=PTREE), \
                patch.object(own080, "gh_read", side_effect=self.api):
            return own080.consumer_source_080(self.config, self.p, PCOMMIT, PTREE)

    def test_exact_proposed_body_pins_and_descriptor_are_source_bound(self):
        actual = {name: hashlib.sha256((self.p / name).read_bytes()).hexdigest()
                  for name in own080.CONSUMER_FILE_HASHES_080}
        self.assertEqual(actual, own080.CONSUMER_FILE_HASHES_080)
        proof = self.verify()
        self.addCleanup(own080.release_consumer_080, proof)
        self.assertEqual(proof.record["admission_profile"], CURRENT080_POLICY_VARIANT)
        self.assertEqual(proof.record["repository"], own080.TARGET)
        self.assertEqual(proof.record["files"][own080.IMPORTER], own080.CONSUMER_FILE_HASHES_080[own080.IMPORTER])
        self.assertEqual(own080.VERSIONS_080["theme-forge-nebular-fusion"], "0.8.0")

    def test_each_changed_071_body_refuses_under_080_profile(self):
        changed = {
            ".github/workflows/publish.yml",
            "package-matrix.json",
            "release-lock.json",
            "tools/verification/current_import_routing.py",
        }
        for name in sorted(changed):
            with self.subTest(path=name):
                current = (self.p / name).read_bytes()
                old_path = OLD_IMPORTER if name == own080.IMPORTER else OLD_FIXTURE / name
                (self.p / name).write_bytes(old_path.read_bytes())
                self.rebuild_tree()
                try:
                    with self.assertRaises(ContractError) as error:
                        self.verify()
                    self.assertEqual(error.exception.code, "OWN_REPOSITORY_SOURCE")
                finally:
                    (self.p / name).write_bytes(current)
                    self.rebuild_tree()

    def test_tracked_blob_descriptor_and_main_ref_mutations_refuse(self):
        self.rows[0]["sha"] = "0" * 40
        with self.assertRaises(ContractError):
            self.verify()
        self.rebuild_tree()
        self.descriptor["unexpected"] = True
        self.write_descriptor()
        self.rebuild_tree()
        with self.assertRaises(ContractError):
            self.verify()
        del self.descriptor["unexpected"]
        self.write_descriptor()
        self.rebuild_tree()

        def wrong_api(root, argv):
            value = json.loads(self.api(root, argv))
            if argv[-1].endswith("git/ref/heads/main"):
                value["object"]["sha"] = "0" * 40
            return json.dumps(value)

        with patch.object(own080, "gh_read", side_effect=wrong_api), \
                patch.object(own080, "source_tree_identity", return_value=PTREE), \
                self.assertRaises(ContractError):
            own080.consumer_source_080(self.config, self.p, PCOMMIT, PTREE)

        def wrong_tree_api(root, argv):
            value = json.loads(self.api(root, argv))
            if "/git/commits/" in argv[-1]:
                value["tree"]["sha"] = "0" * 40
            elif "/git/trees/" in argv[-1]:
                value["sha"] = "0" * 40
            return json.dumps(value)

        with patch.object(own080, "gh_read", side_effect=wrong_tree_api), \
                patch.object(own080, "source_tree_identity", return_value=PTREE), \
                self.assertRaises(ContractError):
            own080.consumer_source_080(self.config, self.p, PCOMMIT, PTREE)

    def test_071_proof_forgery_cross_use_release_and_tamper_refuse(self):
        legacy = own071._Consumer({}, "", own071._PROOF)
        with self.assertRaises(ContractError):
            own080.check_lane_080(legacy, {}, {}, {})
        with self.assertRaises(ContractError):
            own080.admit_080(self.root, self.root, {}, self.config.expected(), legacy)
        with self.assertRaises(ContractError):
            own080.check_lane_080(object(), {}, {}, {})
        proof = self.verify()
        proof.record["tree"] = "0" * 40
        with self.assertRaises(ContractError):
            own080.admit_080(self.root, self.root, {}, self.config.expected(), proof)
        own080.release_consumer_080(proof)
        with self.assertRaises(ContractError):
            own080.admit_080(self.root, self.root, {}, self.config.expected(), proof)

    def test_held_and_wrong_version_policy_refuse_without_fallback(self):
        proof = self.verify()
        self.addCleanup(own080.release_consumer_080, proof)
        held = json.loads((ROOT / "tests/fixtures/current080-rpm-policy-held.json").read_text())
        with patch.object(own080, "load_policy", return_value=held), self.assertRaises(ContractError) as error:
            own080.admit_080(self.root, self.root, {}, self.config.expected(), proof)
        self.assertEqual(error.exception.code, "CURRENT_RPM_POLICY_HELD")

        wrong = copy.deepcopy(held)
        wrong["status"] = "authorized"
        wrong["blocking"] = False
        wrong["projects"] = {name: {**entry} for name, entry in wrong.get("projects", {}).items()}
        wrong["projects"].setdefault("theme-forge-nebular-fusion", {})["version"] = "0.7.1"
        with patch.object(own080, "load_policy", return_value=wrong), self.assertRaises(ContractError) as error:
            own080.admit_080(self.root, self.root, {}, self.config.expected(), proof)
        self.assertEqual(error.exception.code, "CURRENT_RPM_POLICY_HELD")

