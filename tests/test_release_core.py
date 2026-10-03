import copy
import json
from pathlib import Path
import tempfile
import unittest

from rs9.errors import ContractError
from rs9.profiles import selection_for_intent
from rs9.release_core import authenticate_release, capture_release, digest, validate_selection
from rs9.scratch import canonical
from tests.release_fixtures import package_evidence
from tests.shadow_fixtures import fixture_evidence, ROOT
from tests.test_fetch import FixtureClient


class ReleaseCoreTests(unittest.TestCase):
    def test_two_profiles_use_same_capture_and_authentication(self):
        for builder in (fixture_evidence, package_evidence):
            with self.subTest(builder=builder.__name__), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve()
                source, target = root / "source", root / "target"
                source.mkdir(); target.mkdir()
                intent = builder(source)
                selection = selection_for_intent(intent)
                capture_release(selection, target, client=FixtureClient(source, intent))
                original = authenticate_release(selection, source)
                repeated = authenticate_release(selection, target)
                self.assertEqual(canonical(original.record), canonical(repeated.record))
                self.assertEqual(original.manifests, repeated.manifests)
                receipt = json.loads((target / "fetch-receipt.json").read_bytes())
                self.assertEqual(receipt["selection_sha256"], digest(canonical(selection)))
                self.assertFalse((target / "npm").exists())

    def test_core_has_no_project_or_profile_specific_rules(self):
        text = (ROOT / "src/rs9/release_core.py").read_text().lower()
        for term in ("nebular", "stellar", "theme-forge", "tauri", "npm", "cargo"):
            self.assertNotIn(term, text)

    def test_closed_selection_and_narrow_limits(self):
        with tempfile.TemporaryDirectory() as tmp:
            selection = selection_for_intent(package_evidence(Path(tmp).resolve()))
            for change in (lambda s: s.update(hook="run"), lambda s: s.update(limits={"capture_bytes": 0}),
                           lambda s: s["payload_assets"][0].update(name="../bad"),
                           lambda s: s["evidence_assets"].append(copy.deepcopy(s["evidence_assets"][0]))):
                value = copy.deepcopy(selection); change(value)
                with self.assertRaises(ContractError):
                    validate_selection(value)

    def test_missing_checksum_requires_explicit_coverage_exemption(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            selection = selection_for_intent(package_evidence(root))
            data = (root / "assets/SHA256SUMS").read_bytes()
            data = b"\n".join(row for row in data.splitlines() if not row.endswith(b"  NOTICE")) + b"\n"
            (root / "assets/SHA256SUMS").write_bytes(data)
            api = json.loads((root / "api/release.json").read_bytes())
            for asset in api["assets"]:
                if asset["name"] == "SHA256SUMS":
                    asset.update(size=len(data), digest="sha256:" + digest(data))
            (root / "api/release.json").write_bytes(canonical(api))
            with self.assertRaises(ContractError) as caught:
                authenticate_release(selection, root)
            self.assertEqual(caught.exception.code, "CHECKSUM_MISMATCH")
            next(row for row in selection["evidence_assets"] if row["name"] == "NOTICE")["checksum_covered"] = False
            capture = authenticate_release(selection, root)
            self.assertFalse(next(row for row in capture.record["assets"] if row["name"] == "NOTICE")["checksum_covered"])

    def test_aggregate_capture_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            selection = selection_for_intent(package_evidence(root))
            selection["limits"] = {"capture_bytes": 1}
            with self.assertRaises(ContractError) as caught:
                authenticate_release(selection, root)
            self.assertEqual(caught.exception.code, "FETCH_LIMIT")
