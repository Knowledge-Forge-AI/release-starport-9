"""Offline legal-boundary regression tests for real checked-in Nebular intent and v1alpha2 authority."""
import base64
import copy
import hashlib
import json
from pathlib import Path
import shutil
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from rs9.bootstrap import checked_bootstrap_configurations, configuration_inventory
from rs9.errors import ContractError
from rs9.hosted_custody import verify_set
from rs9.hosted_pipeline import run_lane
from rs9.ingestion import authenticate_shadow
from rs9.profiles import (TAURI_AUTHORITY_PROFILE, TAURI_PROFILE, TAURI_SOURCES,
                          evaluate_profile, selection_for_intent)
from rs9.records import record_sha256
from rs9.release_core import authenticate_release, digest
from rs9.scratch import canonical
from tests.shadow_fixtures import fixture_evidence, tar_bytes
from tests.test_npm_transport import TOKEN, transport

ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP_DIR = ROOT / "bootstrap/pre-rs9/theme-forge-live1/theme-forge-nebular-fusion"
BOOTSTRAP_MANIFEST = ROOT / "bootstrap/pre-rs9/theme-forge-live1/manifest.json"
NAME = "@knowledge-forge-ai/theme-forge-nebular-fusion"
PACKUMENT = "https://registry.npmjs.org/@knowledge-forge-ai%2Ftheme-forge-nebular-fusion"
TARBALL = "https://registry.npmjs.org/@knowledge-forge-ai/theme-forge-nebular-fusion/-/theme-forge-nebular-fusion-0.6.1.tgz"


class NebularLegalBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.real_intent = json.loads((BOOTSTRAP_DIR / "intent.json").read_bytes())

    def assert_fixture_guard(self, fixture_intent):
        """Guard that synthetic offline fixtures accurately reflect checked-in Nebular intent identities."""
        self.assertEqual(fixture_intent["project"]["repository"], self.real_intent["project"]["repository"])
        self.assertEqual(fixture_intent["project"]["id"], self.real_intent["project"]["id"])
        self.assertEqual(fixture_intent["tag"], self.real_intent["tag"])
        self.assertEqual(fixture_intent["version"], self.real_intent["version"])
        self.assertEqual(fixture_intent["desktop"]["icon"], self.real_intent["desktop"]["icon"])
        self.assertEqual(fixture_intent["assets"], self.real_intent["assets"])
        self.assertEqual(fixture_intent["release"]["evidence"]["checksums"], self.real_intent["release"]["evidence"]["checksums"])
        self.assertEqual({a["role"]: a["name"] for a in fixture_intent["release"]["evidence"]["assets"]},
                         {a["role"]: a["name"] for a in self.real_intent["release"]["evidence"]["assets"]})

    # 1. exact list
    def test_01_exact_list(self):
        legal_files = self.real_intent["license"]["files"]
        self.assertEqual(legal_files, ["LICENSE", "NOTICE"])
        self.assertNotIn("COMMERCIAL-LICENSE.md", legal_files)
        self.assertIn("COMMERCIAL-LICENSE.md", TAURI_SOURCES)
        self.assertEqual(self.real_intent["license"]["expression"], "AGPL-3.0-or-later")
        self.assertEqual(self.real_intent["license"]["source"], "tagged-repository")
        self.assertEqual(self.real_intent["release"]["evidence"]["profile"], TAURI_AUTHORITY_PROFILE)

    # 2. recomputed config/manifest hash bindings + rejects old approval and tampered config
    def test_02_config_manifest_hash_bindings_and_tamper_rejection(self):
        manifest_raw = BOOTSTRAP_MANIFEST.read_bytes()
        manifest_digest = digest(manifest_raw)
        manifest = json.loads(manifest_raw)
        nebular_row = next(r for r in manifest["projects"] if r["configuration"] == "theme-forge-nebular-fusion")

        # Verify inventory hash matches manifest
        inv = configuration_inventory(BOOTSTRAP_DIR)
        config_hash = record_sha256(inv)
        self.assertEqual(config_hash, nebular_row["config_sha256"])
        self.assertEqual(config_hash, "b985546482cfff16436d166ff3ba175b54b4afc03b35c48e4310cf070690c27f")
        candidate = json.loads((ROOT / "operators/live1/candidate-manifest.json").read_bytes())
        self.assertEqual(candidate["bootstrap_manifest_sha256"], manifest_digest)
        self.assertEqual(candidate["configuration_hashes"], [
            {"project": row["configuration"], "config_sha256": row["config_sha256"]}
            for row in manifest["projects"]])

        # Allowlisted manifest succeeds
        configs = checked_bootstrap_configurations(BOOTSTRAP_MANIFEST, approved_manifests=[manifest_digest])
        self.assertEqual(len(configs), 4)

        # Rejects old approval
        with self.assertRaises(ContractError) as caught:
            checked_bootstrap_configurations(BOOTSTRAP_MANIFEST, approved_manifests=[
                "dd99580fbcacd5f3c87b99d2e0cb0f28f835a44c46505a197295fdb3951a951f"])
        self.assertEqual(caught.exception.code, "BOOTSTRAP_APPROVAL")

        with self.assertRaises(ContractError) as caught:
            checked_bootstrap_configurations(BOOTSTRAP_MANIFEST, approved_manifests=[])
        self.assertEqual(caught.exception.code, "BOOTSTRAP_APPROVAL")

        # Rejects tampered config
        temp_dir = self.root / "tampered_bootstrap"
        shutil.copytree(BOOTSTRAP_MANIFEST.parent, temp_dir)
        tampered_intent_path = temp_dir / "theme-forge-nebular-fusion/intent.json"
        tampered = json.loads(tampered_intent_path.read_bytes())
        tampered["license"]["files"].append("COMMERCIAL-LICENSE.md")
        tampered_intent_path.write_bytes(canonical(tampered))
        temp_manifest_path = temp_dir / "manifest.json"
        with self.assertRaises(ContractError) as caught:
            checked_bootstrap_configurations(temp_manifest_path, approved_manifests=[digest(temp_manifest_path.read_bytes())])
        self.assertEqual(caught.exception.code, "BOOTSTRAP_CONFIG")

    # 3. selection still commercial & same as pre-fix
    def test_03_selection_still_commercial_and_same_as_pre_fix(self):
        current_selection = selection_for_intent(self.real_intent)
        self.assertIn("COMMERCIAL-LICENSE.md", current_selection["source_paths"])

        old_intent = copy.deepcopy(self.real_intent)
        old_intent["license"]["files"] = ["LICENSE", "NOTICE", "COMMERCIAL-LICENSE.md"]
        old_selection = selection_for_intent(old_intent)

        self.assertEqual(current_selection, old_selection)
        self.assertEqual(record_sha256(current_selection), record_sha256(old_selection))
        row = next(r for r in json.loads(BOOTSTRAP_MANIFEST.read_bytes())["projects"]
                   if r["configuration"] == "theme-forge-nebular-fusion")
        self.assertLessEqual(set(row["license_authority"]["files"]), set(current_selection["source_paths"]))

    # 4. missing commercial source MISSING_EVIDENCE and corrupted blob SOURCE_BLOB_MISMATCH
    def test_04_missing_commercial_source_and_corrupted_blob(self):
        ev_dir = self.root / "ev_test_04"
        fixture_intent = fixture_evidence(ev_dir)
        self.assert_fixture_guard(fixture_intent)

        # Missing commercial source
        (ev_dir / "source/COMMERCIAL-LICENSE.md").unlink()
        with self.assertRaises(ContractError) as caught:
            authenticate_release(selection_for_intent(self.real_intent), ev_dir)
        self.assertEqual(caught.exception.code, "MISSING_EVIDENCE")

        # Corrupted blob
        ev_dir2 = self.root / "ev_test_04_corrupt"
        fixture_evidence(ev_dir2)
        (ev_dir2 / "source/COMMERCIAL-LICENSE.md").write_bytes(b"corrupted commercial license bytes\n")
        with self.assertRaises(ContractError) as caught:
            authenticate_release(selection_for_intent(self.real_intent), ev_dir2)
        self.assertEqual(caught.exception.code, "SOURCE_BLOB_MISMATCH")

    # 5. absent AGPL commercial declaration LICENSE_EVIDENCE
    def test_05_absent_agpl_commercial_declaration(self):
        ev_dir = self.root / "ev_test_05"
        fixture_intent = fixture_evidence(ev_dir)
        self.assert_fixture_guard(fixture_intent)

        # Absent AGPL declaration in commercial license
        commercial_path = ev_dir / "source/COMMERCIAL-LICENSE.md"
        data = b"Commercial licenses are available without AGPL-3.0 terms.\n"
        commercial_path.write_bytes(data)
        blob_sha = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()

        tree_path = ev_dir / "api/tree.json"
        tree = json.loads(tree_path.read_bytes())
        for elem in tree["tree"]:
            if elem["path"] == "COMMERCIAL-LICENSE.md":
                elem["sha"] = blob_sha
        tree_path.write_bytes(canonical(tree))

        with self.assertRaises(ContractError) as caught:
            authenticate_shadow(self.real_intent, ev_dir)
        self.assertEqual(caught.exception.code, "LICENSE_EVIDENCE")

        # But valid AGPL prose succeeds
        data_prose = b"Licensed under the GNU Affero General Public License v3.0 or later.\n"
        commercial_path.write_bytes(data_prose)
        blob_sha_prose = hashlib.sha1(b"blob " + str(len(data_prose)).encode() + b"\0" + data_prose).hexdigest()
        for elem in tree["tree"]:
            if elem["path"] == "COMMERCIAL-LICENSE.md":
                elem["sha"] = blob_sha_prose
        tree_path.write_bytes(canonical(tree))
        auth = authenticate_shadow(self.real_intent, ev_dir)
        self.assertEqual(auth.profile_result["profile"], TAURI_AUTHORITY_PROFILE)

    # 6. Darwin and both Linux exact legal copies pass without commercial
    def test_06_darwin_and_both_linux_exact_legal_copies_pass_without_commercial(self):
        ev_dir = self.root / "ev_test_06"
        fixture_intent = fixture_evidence(ev_dir)
        self.assert_fixture_guard(fixture_intent)

        auth = authenticate_shadow(self.real_intent, ev_dir)
        self.assertEqual(auth.profile_result["profile"], TAURI_AUTHORITY_PROFILE)
        self.assertEqual(auth.record["schema"], "rs9.ingestion.v1alpha1")

        # Exact legal copies recorded for all 3 assets
        copies = auth.record["payload_license_copies"]
        self.assertEqual(len(copies), 6)
        assets_seen = {c["asset"] for c in copies}
        self.assertEqual(assets_seen, {"darwin-arm64", "linux-arm64", "linux-x64"})
        sources_seen = {c["source"] for c in copies}
        self.assertEqual(sources_seen, {"LICENSE", "NOTICE"})
        self.assertNotIn("COMMERCIAL-LICENSE.md", sources_seen)
        for asset in self.real_intent["assets"]:
            with tarfile.open(ev_dir / "assets" / asset["name"], "r:gz") as archive:
                self.assertFalse(any(m.name.endswith("/COMMERCIAL-LICENSE.md") for m in archive))

    def test_07_each_missing_and_mismatched_legal_file_fails_per_asset(self):
        for asset in self.real_intent["assets"]:
            asset_id = asset["id"]
            archive_root = next(iter(asset["commands"].values())).split("/")[0]
            base = archive_root + ("/Contents/Resources/" if archive_root.endswith(".app") else "/")
            cases = [({name: None}, "PAYLOAD_LICENSE_MISSING", {
                "expected_legal_files": "LICENSE NOTICE",
                "observed_legal_files": "NOTICE" if name == "LICENSE" else "LICENSE"})
                for name in ("LICENSE", "NOTICE")]
            cases.append(({"LICENSE": None, "NOTICE": None}, "PAYLOAD_LICENSE_MISSING", {
                "expected_legal_files": "LICENSE NOTICE", "observed_legal_files": "none"}))
            cases.append(({"NOTICE": None, "elsewhere/NOTICE": b"misplaced notice\n"}, "PAYLOAD_LICENSE_MISSING", {
                "expected_legal_files": "LICENSE NOTICE", "observed_legal_files": "LICENSE"}))
            cases.extend(({name: b"mismatched legal copy\n"}, "PAYLOAD_LICENSE_MISMATCH",
                          {"archive_path": base + name}) for name in ("LICENSE", "NOTICE"))
            for index, (overrides, code, details) in enumerate(cases):
                with self.subTest(asset=asset_id, code=code, files=sorted(overrides)):
                    ev_dir = self.root / f"ev_07_{asset_id}_{index}"
                    fixture_evidence(ev_dir, payload_legal={asset_id: overrides})
                    with self.assertRaises(ContractError) as caught:
                        authenticate_shadow(self.real_intent, ev_dir)
                    self.assertEqual(caught.exception.code, code)
                    self.assertEqual(caught.exception.details, {
                        "asset": asset_id, "profile": TAURI_AUTHORITY_PROFILE, **details})

    # 8. empty/duplicate list guard
    def test_08_empty_duplicate_and_invalid_license_files_guard(self):
        ev_dir = self.root / "ev_test_08"
        fixture_evidence(ev_dir)
        capture = authenticate_release(selection_for_intent(self.real_intent), ev_dir)

        policy_cases = [
            ([], "empty-list"),
            (["LICENSE", "NOTICE", "LICENSE"], "duplicate-list"),
            ("LICENSE", "string-non-list"),
            (None, "none-non-list"),
            (["LICENSE", 123], "non-string-item"),
        ]
        for val, desc in policy_cases:
            with self.subTest(case=desc):
                bad_intent = copy.deepcopy(self.real_intent)
                bad_intent["license"]["files"] = val
                with self.assertRaises(ContractError) as caught:
                    evaluate_profile(capture, TAURI_AUTHORITY_PROFILE, bad_intent)
                self.assertEqual(caught.exception.code, "PAYLOAD_LICENSE_POLICY")
                self.assertEqual(caught.exception.details, {"profile": TAURI_AUTHORITY_PROFILE})

        with self.subTest(case="path-escape"):
            bad_intent = copy.deepcopy(self.real_intent)
            bad_intent["license"]["files"] = ["../escape"]
            with self.assertRaises(ContractError) as caught:
                evaluate_profile(capture, TAURI_AUTHORITY_PROFILE, bad_intent)
            self.assertEqual(caught.exception.code, "UNSAFE_PATH")

        # Also verify empty-list and duplicate-list reject under authenticate_shadow end-to-end
        for val, desc in [([], "empty-list-shadow"), (["LICENSE", "NOTICE", "LICENSE"], "duplicate-list-shadow")]:
            with self.subTest(case=desc):
                bad_intent = copy.deepcopy(self.real_intent)
                bad_intent["license"]["files"] = val
                with self.assertRaises(ContractError) as caught:
                    authenticate_shadow(bad_intent, ev_dir)
                self.assertEqual(caught.exception.code, "PAYLOAD_LICENSE_POLICY")
                self.assertEqual(caught.exception.details, {"profile": TAURI_AUTHORITY_PROFILE})

    # 9. unexpected payload commercial cannot override tagged declaration (including tagged malformed despite payload declaration)
    def test_09_unexpected_payload_commercial_cannot_override_tagged_declaration(self):
        # Conflicting extra payload bytes cannot replace tagged declarations.
        payload_with_commercial = {
            asset["id"]: {"COMMERCIAL-LICENSE.md": b"AGPL-3.0-or-later OR Commercial\n"}
            for asset in self.real_intent["assets"]
        }
        ev_dir = self.root / "ev_test_09"
        fixture_evidence(ev_dir, payload_legal=payload_with_commercial)
        auth = authenticate_shadow(self.real_intent, ev_dir)
        self.assertEqual({r["source"] for r in auth.record["payload_license_copies"]}, {"LICENSE", "NOTICE"})
        declarations = auth.record["license"]["declarations"]
        self.assertEqual([d["expression"] for d in declarations if d["source"] == "tagged:COMMERCIAL-LICENSE.md"],
                         ["AGPL-3.0-or-later"])
        self.assertFalse(any(d["source"].startswith("payload:") for d in declarations))
        self.assertEqual(auth.record["license"]["status"], "consistent")

        # 1. Tagged commercial license malformed in source (no AGPL statement)
        commercial_path = ev_dir / "source/COMMERCIAL-LICENSE.md"
        malformed = b"Commercial licenses are available upon request.\n"
        commercial_path.write_bytes(malformed)
        blob_sha = hashlib.sha1(b"blob " + str(len(malformed)).encode() + b"\0" + malformed).hexdigest()
        tree_path = ev_dir / "api/tree.json"
        tree = json.loads(tree_path.read_bytes())
        for elem in tree["tree"]:
            if elem["path"] == "COMMERCIAL-LICENSE.md":
                elem["sha"] = blob_sha
        tree_path.write_bytes(canonical(tree))

        # Payload commercial does NOT rescue malformed tagged declaration
        with self.assertRaises(ContractError) as caught:
            authenticate_shadow(self.real_intent, ev_dir)
        self.assertEqual(caught.exception.code, "LICENSE_EVIDENCE")

        # 2. Tagged commercial license missing in source entirely
        commercial_path.unlink()
        with self.assertRaises(ContractError) as caught:
            authenticate_shadow(self.real_intent, ev_dir)
        self.assertEqual(caught.exception.code, "MISSING_EVIDENCE")

    # 10. actual inventory paths/hashes
    def test_10_actual_inventory_paths_and_hashes(self):
        ev_dir = self.root / "ev_test_10"
        fixture_evidence(ev_dir)
        auth = authenticate_shadow(self.real_intent, ev_dir)
        source_hashes = {r["path"]: r["sha256"] for r in auth.record["source_files"]}
        expected = []
        for asset in sorted(self.real_intent["assets"], key=lambda a: a["id"]):
            root = next(iter(asset["commands"].values())).split("/")[0]
            base = root + ("/Contents/Resources/" if root.endswith(".app") else "/")
            for name in ("LICENSE", "NOTICE"):
                self.assertEqual(source_hashes[name], digest((ev_dir / "source" / name).read_bytes()))
                expected.append({"asset": asset["id"], "path": base + name,
                                 "source": name, "sha256": source_hashes[name]})
        self.assertEqual(auth.record["payload_license_copies"], expected)

    # 11. npm metadata AND wrapper OR Commercial yields consistent tagged AGPL authority with retained downstream conflicts
    def test_11_npm_metadata_and_wrapper_or_commercial_yields_consistent_authority(self):
        ev_dir = self.root / "ev_test_11"
        fixture_evidence(ev_dir)

        # Wrapper tarball with OR Commercial in package/package.json
        pkg_json = canonical({"name": NAME, "version": "0.6.1", "license": "AGPL-3.0-or-later OR Commercial"})
        wrapper = tar_bytes([("package/package.json", pkg_json, 0o644, tarfile.REGTYPE, "")])
        (ev_dir / "npm/package.tgz").write_bytes(wrapper)
        (ev_dir / "assets/knowledge-forge-ai-theme-forge-nebular-fusion-0.6.1.tgz").write_bytes(wrapper)

        # npm metadata with OR Commercial
        metadata = json.loads((ev_dir / "npm/metadata.json").read_bytes())
        metadata["license"] = "AGPL-3.0-or-later OR Commercial"
        metadata["dist"]["integrity"] = "sha512-" + base64.b64encode(hashlib.sha512(wrapper).digest()).decode()
        (ev_dir / "npm/metadata.json").write_bytes(canonical(metadata))

        # Recompute SHA256SUMS and api/release.json
        sums = (ev_dir / "assets/SHA256SUMS").read_text()
        wrapper_digest = hashlib.sha256(wrapper).hexdigest()
        wrapper_name = "knowledge-forge-ai-theme-forge-nebular-fusion-0.6.1.tgz"
        lines = [wrapper_digest + "  " + wrapper_name if wrapper_name in line else line for line in sums.splitlines()]
        (ev_dir / "assets/SHA256SUMS").write_bytes(("\n".join(lines) + "\n").encode())

        release = json.loads((ev_dir / "api/release.json").read_bytes())
        for asset in release["assets"]:
            if asset["name"] == wrapper_name:
                asset.update(size=len(wrapper), digest="sha256:" + wrapper_digest)
            elif asset["name"] == "SHA256SUMS":
                body = (ev_dir / "assets/SHA256SUMS").read_bytes()
                asset.update(size=len(body), digest="sha256:" + hashlib.sha256(body).hexdigest())
        (ev_dir / "api/release.json").write_bytes(canonical(release))

        # Under v1alpha2 authority profile, tagged repository authority is consistent
        auth = authenticate_shadow(self.real_intent, ev_dir)
        lic = auth.record["license"]
        self.assertEqual(lic["status"], "consistent")
        self.assertEqual(lic["authority"], "tagged-repository")
        self.assertEqual(lic["comparison"], "tagged-authority; downstream conflicts retained")

        downstream_conflicts = lic["downstream_metadata_conflicts"]
        self.assertEqual(len(downstream_conflicts), 2)
        conflict_sources = {c["source"] for c in downstream_conflicts}
        self.assertEqual(conflict_sources, {"npm-registry:version-metadata", "npm-artifact:package/package.json"})
        for c in downstream_conflicts:
            self.assertEqual(c["expression"], "AGPL-3.0-or-later OR Commercial")

        # Contrast with v1alpha1 (legacy desktop profile): status would be conflict
        v1_intent = copy.deepcopy(self.real_intent)
        v1_intent["release"]["evidence"]["profile"] = TAURI_PROFILE
        auth_v1 = authenticate_shadow(v1_intent, ev_dir)
        self.assertEqual(auth_v1.record["license"]["status"], "conflict")

    # 12. profile/authentication do not modify any evidence bytes
    def test_12_profile_authentication_does_not_modify_evidence_bytes(self):
        ev_dir = self.root / "ev_test_12"
        fixture_evidence(ev_dir)

        before = {p.relative_to(ev_dir).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                  for p in ev_dir.rglob("*") if p.is_file()}

        auth = authenticate_shadow(self.real_intent, ev_dir)
        self.assertIsNotNone(auth)

        after = {p.relative_to(ev_dir).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                 for p in ev_dir.rglob("*") if p.is_file()}

        self.assertEqual(before.keys(), after.keys())
        self.assertEqual(before, after)

    # 13. pinned Nebular manifest identities/license authority remain
    def test_13_pinned_manifest_identities_and_license_authority_remain(self):
        manifest = json.loads(BOOTSTRAP_MANIFEST.read_bytes())
        nebular = next(r for r in manifest["projects"] if r["configuration"] == "theme-forge-nebular-fusion")

        self.assertEqual(nebular["repository"], "Knowledge-Forge-AI/theme-forge-nebular-fusion")
        self.assertEqual(nebular["repository_id"], 1358643872)
        self.assertEqual(nebular["tag"], "v0.6.1")
        self.assertEqual(nebular["version"], "0.6.1")
        self.assertEqual(nebular["release_id"], 400494635)
        self.assertEqual(nebular["tag_commit"], "49e2c4919b6b4ec9bd4ed5d7e7ced90921e00f5e")
        self.assertEqual(nebular["tag_tree"], "203a80b33fc94c776c9c184f8cac4f1609cb0f2b")
        self.assertEqual(nebular["configuration"], "theme-forge-nebular-fusion")

        lic_auth = nebular["license_authority"]
        self.assertEqual(lic_auth["expression"], "AGPL-3.0-or-later")
        self.assertEqual(lic_auth["basis"], "manager-direction-and-authenticated-tagged-repository")
        self.assertEqual(lic_auth["files"], ["LICENSE", "NOTICE", "COMMERCIAL-LICENSE.md", "package.json"])

    def test_14_authority_selection_subset_runtime_negative_test(self):
        temp_bootstrap = self.root / "bootstrap_copy"
        shutil.copytree(BOOTSTRAP_MANIFEST.parent, temp_bootstrap)
        manifest_path = temp_bootstrap / "manifest.json"
        manifest = json.loads(manifest_path.read_bytes())
        nebular = next(r for r in manifest["projects"] if r["configuration"] == "theme-forge-nebular-fusion")
        for files in (["LICENSE", "NOTICE", "COMMERCIAL-LICENSE.md", "package.json", "UNSELECTED-LICENSE.txt"],
                      [], "LICENSE", ["LICENSE", 42]):
            with self.subTest(files=files):
                nebular["license_authority"]["files"] = files
                manifest_path.write_bytes(canonical(manifest))
                with self.assertRaises(ContractError) as caught:
                    checked_bootstrap_configurations(manifest_path,
                                                     approved_manifests=[digest(manifest_path.read_bytes())])
                self.assertEqual(caught.exception.code, "BOOTSTRAP_LICENSE_AUTHORITY")
        nebular["license_authority"] = None
        manifest_path.write_bytes(canonical(manifest))
        with self.assertRaises(ContractError) as caught:
            checked_bootstrap_configurations(manifest_path,
                                             approved_manifests=[digest(manifest_path.read_bytes())])
        self.assertEqual(caught.exception.code, "BOOTSTRAP_LICENSE_AUTHORITY")

    # 15. Host integration
    def _run_hosted(self, evidence_dir, intent_to_use, suffix):
        scratch = self.root / ("work-" + suffix)
        out = self.root / ("out-" + suffix)
        scratch.mkdir()

        def copy_capture(selection, target, **kwargs):
            for folder in ("api", "source", "assets"):
                shutil.copytree(evidence_dir / folder, target / folder)

        rows = [({"repository": intent_to_use["project"]["repository"]}, intent_to_use)]

        body = (evidence_dir / "npm/package.tgz").read_bytes()
        metadata = json.loads((evidence_dir / "npm/metadata.json").read_bytes())
        metadata["dist"]["tarball"] = TARBALL
        packument = {"name": NAME, "dist-tags": {"latest": "99.0.0"}, "versions": {"0.6.1": metadata}}
        client, _ = transport({PACKUMENT: (200, canonical(packument)), TARBALL: (200, body)})

        with patch("rs9.candidate.configuration_rows", return_value=rows), \
             patch("rs9.candidate.capture_release", side_effect=copy_capture), \
             patch("rs9.candidate.assert_release_expectations"), \
             patch("rs9.candidate.load_bootstrap", return_value=intent_to_use), \
             patch("rs9.candidate.require_configuration_authority"), \
             patch("rs9.hosted_pipeline.runner_facts", return_value={}):
            code = run_lane(ROOT, scratch, out, "authenticate", "generation", client=client)
        verify_set(out)
        receipt = json.loads((out / "authenticate-generation.json").read_bytes())
        return code, receipt, scratch, out

    def test_15_hosted_integration_missing_notice_success_and_old_intent(self):
        # 1. Missing linux-x64 NOTICE
        ev_dir_missing = self.root / "ev_hosted_missing"
        fixture_evidence(ev_dir_missing, payload_legal={"linux-x64": {"NOTICE": None}})
        code, receipt, scratch, out = self._run_hosted(ev_dir_missing, self.real_intent, "missing-notice")
        self.assertEqual(code, 2)
        self.assertEqual(receipt["execution_error"], "PAYLOAD_LICENSE_MISSING")
        self.assertEqual(receipt["execution_error_detail"], {
            "stage": "profile",
            "project": "theme-forge-nebular-fusion",
            "asset": "linux-x64",
            "profile": TAURI_AUTHORITY_PROFILE,
            "expected_legal_files": "LICENSE NOTICE",
            "observed_legal_files": "LICENSE"
        })
        corroboration = receipt["npm_corroboration"][0]
        self.assertEqual(corroboration["npm_corroboration"], "blocked")
        self.assertFalse((scratch / "capture/summary/authentication.json").exists())
        self.assertNotIn(TOKEN, "".join(p.read_text() for p in out.rglob("*.json")))

        # 2. Checked-in intent success
        ev_dir_success = self.root / "ev_hosted_success"
        fixture_evidence(ev_dir_success)
        code, receipt, scratch, out = self._run_hosted(ev_dir_success, self.real_intent, "success")
        self.assertEqual(code, 0)
        self.assertIsNone(receipt["execution_error"])
        corroboration = receipt["npm_corroboration"][0]
        self.assertEqual(corroboration["npm_corroboration"], "pass")
        self.assertTrue((scratch / "capture/summary/authentication.json").exists())
        self.assertNotIn(TOKEN, "".join(p.read_text() for p in out.rglob("*.json")))

        # 3. Permanent old-intent reproduction expects missing commercial
        old_intent = copy.deepcopy(self.real_intent)
        old_intent["license"]["files"] = ["LICENSE", "NOTICE", "COMMERCIAL-LICENSE.md"]
        ev_dir_old = self.root / "ev_hosted_old"
        fixture_evidence(ev_dir_old)  # payload archives do not contain commercial license
        code, receipt, scratch, out = self._run_hosted(ev_dir_old, old_intent, "old-intent")
        self.assertEqual(code, 2)
        self.assertEqual(receipt["execution_error"], "PAYLOAD_LICENSE_MISSING")
        self.assertEqual(receipt["execution_error_detail"], {
            "stage": "profile",
            "project": "theme-forge-nebular-fusion",
            "asset": "darwin-arm64",
            "profile": TAURI_AUTHORITY_PROFILE,
            "expected_legal_files": "COMMERCIAL-LICENSE.md LICENSE NOTICE",
            "observed_legal_files": "LICENSE NOTICE"
        })
        corroboration = receipt["npm_corroboration"][0]
        self.assertEqual(corroboration["npm_corroboration"], "blocked")
        self.assertFalse((scratch / "capture/summary/authentication.json").exists())
        self.assertNotIn(TOKEN, "".join(p.read_text() for p in out.rglob("*.json")))
