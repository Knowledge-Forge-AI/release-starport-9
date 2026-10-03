"""Corrections from the supplied LIVE1 work review; no live qualification."""
import copy
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import Mock, patch

from rs9.bootstrap import require_configuration_authority, require_release_configuration
from rs9.errors import ContractError
from rs9.ingestion import authenticate
from rs9.operator import authenticate_generation, assert_release_expectations, checked_checkout
from rs9.profiles import selection_for_intent
from rs9.release_core import authenticate_release, digest
from rs9.scratch import canonical
from tests.publication_fixtures import fixture, make_plan


class CloseoutAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.bundle = fixture(self.root)

    def test_normal_ingestion_and_planning_refuse_missing_release_configuration(self):
        intent, capture, *_ = self.bundle
        with self.assertRaises(ContractError) as caught:
            authenticate(intent, self.root)
        self.assertEqual(caught.exception.code, "RELEASE_CONFIG_REQUIRED")
        capture._bootstrap_authority = None
        with self.assertRaises(ContractError) as caught:
            make_plan(self.bundle)
        self.assertEqual(caught.exception.code, "RELEASE_CONFIG_REQUIRED")

    def test_asserted_or_different_intent_bootstrap_capability_is_rejected(self):
        intent, capture, *_ = self.bundle
        authority = capture._bootstrap_authority
        capture._bootstrap_authority = (object(), *authority[1:])
        with self.assertRaises(ContractError):
            make_plan(self.bundle)
        capture._bootstrap_authority = authority
        changed = copy.deepcopy(intent)
        changed["version"] = "0.6.2"
        with self.assertRaises(ContractError):
            require_configuration_authority(capture, changed)

    def test_bootstrap_is_rechecked_at_planning(self):
        (self.root / "fixture-bootstrap/project/intent.json").write_bytes(b"{}")
        with self.assertRaises(ContractError) as caught:
            make_plan(self.bundle)
        self.assertEqual(caught.exception.code, "BOOTSTRAP_CONFIG")

    def test_release_configuration_must_be_captured_and_bind_intent_inputs(self):
        intent, _, *_ = self.bundle
        intent = copy.deepcopy(intent)
        configuration = {"project.toml": b'# synthetic project-owned fixture\n',
                         "releases.toml": b'# synthetic release-owned fixture\n'}
        intent["evidence"] = {"inputs": [{"filename": name, "sha256": digest(data)}
                                          for name, data in configuration.items()]}
        tree_path = self.root / "api/tree.json"
        tree = json.loads(tree_path.read_bytes())
        (self.root / "source/.rs9").mkdir()
        for name, data in configuration.items():
            path = ".rs9/" + name
            (self.root / "source" / path).write_bytes(data)
            tree["tree"].append({"path": path, "type": "blob", "mode": "100644",
                                 "sha": hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()})
        tree_path.write_bytes(canonical(tree))
        incomplete = authenticate_release(selection_for_intent(intent), self.root)
        with self.assertRaises(ContractError):
            require_release_configuration(incomplete)
        capture = authenticate_release(selection_for_intent(intent, include_configuration=True), self.root)
        require_configuration_authority(capture, intent)
        intent["evidence"]["inputs"][0]["sha256"] = "0" * 64
        with self.assertRaises(ContractError) as caught:
            require_configuration_authority(capture, intent)
        self.assertEqual(caught.exception.code, "RELEASE_CONFIG_BINDING")

    def test_modified_bootstrap_cannot_select_network_or_output_paths(self):
        source = Path(__file__).resolve().parents[1]
        repository = self.root / "repository"
        shutil.copytree(source / "bootstrap", repository / "bootstrap")
        manifest_path = repository / "bootstrap/pre-rs9/theme-forge-live1/manifest.json"
        row = json.loads(manifest_path.read_bytes())["projects"][0]
        intent_path = manifest_path.parent / row["configuration"] / "intent.json"
        changed = json.loads(intent_path.read_bytes())
        changed["project"]["id"] = "../../escape"
        intent_path.write_bytes(canonical(changed))
        output = self.root / "output"
        output.mkdir()
        client = Mock()
        with self.assertRaises(ContractError) as caught:
            authenticate_generation(repository, output,
                approved_bootstrap_sha256=digest(manifest_path.read_bytes()), client=client)
        self.assertEqual(caught.exception.code, "BOOTSTRAP_CONFIG")
        self.assertEqual(client.mock_calls, [])
        self.assertEqual(list(output.iterdir()), [])

    def expected_release(self):
        intent, _, *_ = self.bundle
        release_path = self.root / "api/release.json"
        release = json.loads(release_path.read_bytes())
        release.update(immutable=False, published_at="2026-10-03T12:00:00Z")
        release_path.write_bytes(canonical(release))
        capture = authenticate_release(selection_for_intent(intent), self.root)
        record = capture.record
        return capture, {"repository": record["repository"]["full_name"],
            "repository_id": record["repository"]["id"], "tag": record["release"]["tag"],
            "release_id": record["release"]["id"], "commit": record["tag"]["commit"],
            "tree": record["tag"]["tree"], "immutable": False, "contains_rs9": False,
            "truncated": False, "published_at": "2026-10-03T12:00:00Z",
            "assets": [{"name": a["name"], "id": a["github_asset_id"], "size": a["size"], "sha256": a["sha256"]}
                        for a in record["assets"]]}

    def test_release_expectations_include_state_times_and_asset_ids(self):
        capture, expected = self.expected_release()
        assert_release_expectations(capture, expected)
        for key, value in (("immutable", True), ("contains_rs9", True),
                           ("truncated", True), ("published_at", "2026-10-02T12:00:00Z")):
            changed = copy.deepcopy(expected)
            changed[key] = value
            with self.subTest(key=key), self.assertRaises(ContractError):
                assert_release_expectations(capture, changed)
        expected["assets"][0]["id"] += 1
        with self.assertRaises(ContractError):
            assert_release_expectations(capture, expected)

    def test_release_metadata_cannot_change_after_authentication(self):
        capture, expected = self.expected_release()
        release_path = self.root / "api/release.json"
        release = json.loads(release_path.read_bytes())
        release["immutable"] = True
        release_path.write_bytes(canonical(release))
        expected["immutable"] = True
        with self.assertRaises(ContractError) as caught:
            assert_release_expectations(capture, expected)
        self.assertEqual(caught.exception.code, "INPUT_CHANGED")

    def test_attended_checkout_rejects_ignored_inputs(self):
        def git(command, **kwargs):
            args = command[3:]
            if args == ["rev-parse", "HEAD"]: return "a" * 40
            if args == ["rev-parse", "HEAD^{tree}"]: return "b" * 40
            if args == ["branch", "--show-current"]: return "main"
            if "--ignored" in args: return "src/rs9/__pycache__/operator.pyc\n"
            return ""
        with patch("rs9.operator.subprocess.check_output", side_effect=git):
            with self.assertRaises(ContractError) as caught:
                checked_checkout(self.root, "a" * 40, "b" * 40)
        self.assertEqual(caught.exception.code, "OPERATOR_REVIEW")
