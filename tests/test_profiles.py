import copy
import json
from pathlib import Path
import tempfile
import unittest

from rs9.errors import ContractError
from rs9.ingestion import authenticate
from rs9.profiles import evidence_policy, selection_for_intent, evaluate_profile, PACKAGE_PROFILE
from rs9.release_core import authenticate_release
from rs9.scratch import canonical
from tests.release_fixtures import package_evidence
from tests.shadow_fixtures import fixture_evidence


class ProfileTests(unittest.TestCase):
    def test_explicit_profile_and_closed_role_selection(self):
        with tempfile.TemporaryDirectory() as tmp:
            intent = package_evidence(Path(tmp).resolve())
            for policy, code in ((None, "EVIDENCE_PROFILE_REQUIRED"),
                                 ({"profile": "external-module"}, "EVIDENCE_PROFILE"),
                                 ({"profile": PACKAGE_PROFILE, "assets": []}, "EVIDENCE_ROLES")):
                altered = copy.deepcopy(intent)
                altered["release"]["evidence"] = policy
                with self.assertRaises(ContractError) as caught:
                    selection_for_intent(altered)
                self.assertEqual(caught.exception.code, code)

    def test_second_profile_records_metadata_and_bins_without_renderer(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            intent = package_evidence(root)
            capture = authenticate_release(selection_for_intent(intent), root)
            result = evaluate_profile(capture, PACKAGE_PROFILE, intent)
            self.assertEqual(result["sections"]["package"]["commands"][0]["path"], "package/bin/run.js")
            self.assertEqual(result["sections"]["license"]["status"], "consistent")
            self.assertNotIn("legacy_ingestion", result["sections"])
            self.assertEqual(canonical(result), canonical(evaluate_profile(capture, PACKAGE_PROFILE, intent)))

    def test_unselected_tgz_does_not_select_or_confuse_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            intent = fixture_evidence(root)
            before = canonical(authenticate(intent, root).record)
            p = root / "api/release.json"; api = json.loads(p.read_bytes())
            api["assets"].append({"name": "other-archive.tgz"})
            p.write_bytes(canonical(api))
            self.assertEqual(before, canonical(authenticate(intent, root).record))

    def test_profile_role_cannot_bind_a_different_authenticated_asset(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            intent = package_evidence(root)
            capture = authenticate_release(selection_for_intent(intent), root)
            with self.assertRaises(ContractError):
                evaluate_profile(capture, PACKAGE_PROFILE, intent, roles={"notice": "PROVENANCE.json", "provenance": "NOTICE"})
