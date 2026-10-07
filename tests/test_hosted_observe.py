"""Destination observations cannot promote diagnostic metadata to exact readback.

Verifies real release_core record shape regression, tap-head failure handling,
platform selection, and fail-closed schema boundaries.
"""
import base64
import copy
import hashlib
import json
import re
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError, URLError
import http.client

from rs9.errors import ContractError
from rs9.homebrew_formula import formula_class_name
from rs9.hosted_observe import authenticated_npm_projection, execute, homebrew_generation_facts, readback_satisfied, select_brew_payload
from rs9.profiles import selection_for_intent
from rs9.release_core import authenticate_release
from rs9.scratch import canonical
from tests.release_fixtures import package_evidence
from tests.shadow_fixtures import fixture_evidence
from tests.test_build_native import create_cli_fixture

ROOT = Path(__file__).resolve().parents[1]


class HostedReadbackTests(unittest.TestCase):
    def test_authenticated_four_product_readbacks_reach_real_foundation_planner_noop(self):
        from rs9.hosted_observe import reference_identity, reference_noop
        from rs9.profiles import evaluate_profile, evidence_policy
        from rs9.readers import read_homebrew, read_npm
        from rs9.records import record_sha256
        from tests.publication_fixtures import authorize_fixture_configuration
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            captures = HostedObserveExecutionTests()._create_real_captures(root)
            for capture, intent, _ in captures:
                project, version = intent["project"]["id"], intent["version"]
                with self.subTest(product=project):
                    authorize_fixture_configuration(root / "bindings" / project, intent, capture)
                    profile = evaluate_profile(capture, evidence_policy(intent)[0], intent)
                    projection = authenticated_npm_projection(capture, intent, profile)
                    if project != "theme-forge-nebular-fusion":
                        metadata = json.loads(capture.source["package.json"])
                        metadata["dist"] = {"tarball": projection["url"], "integrity": projection["integrity"]}
                        npm_identity = reference_identity(capture, intent, "npm")
                        def registry(url, *args, **kwargs):
                            return projection["body"] if url == projection["url"] else canonical({
                                "name": projection["package_name"], "versions": {version: metadata}})
                        with patch("rs9.readers._get", side_effect=registry):
                            npm = read_npm({"id": "npm", "adapter": "npm", "mode": "direct"},
                                {"package": projection["package_name"], "version": version, "revision": None},
                                desired_identity=record_sha256(npm_identity),
                                expected_hashes={projection["asset_name"]: projection["sha256"]},
                                expected_integrity=projection["integrity"], expected_commands=projection["commands"],
                                expected_license=projection["expected_license"])
                        self.assertEqual(npm["state"], "exact")
                        artifact = {"path": projection["asset_name"], "sha256": projection["sha256"], "size": len(projection["body"])}
                        self.assertEqual(reference_noop(capture, intent, profile, npm_identity, npm, [artifact])["planner_outcome"], "noop")
                    facts = homebrew_generation_facts(capture, intent, profile, npm_projection=projection, npm_state="exact")
                    template = (ROOT / "tests/fixtures/homebrew/Formula" / (project + ".rb")).read_text()
                    formula = re.sub(r'(?m)^  sha256 "[0-9a-f]{64}"$', lambda _: f'  sha256 "{facts["sha256"]}"', template).encode()
                    blob = hashlib.sha1(b"blob " + str(len(formula)).encode() + b"\0" + formula).hexdigest()
                    identity, artifact = reference_identity(capture, intent, "homebrew"), {}
                    with patch("rs9.readers._get", return_value=formula):
                        observation = read_homebrew({"id": "homebrew", "adapter": "homebrew", "mode": "projection"},
                            {"package": project, "version": version, "revision": None}, pinned_ref="c" * 40,
                            desired_identity=record_sha256(identity), expected_payload_url=facts["url"],
                            expected_payload_sha256=facts["sha256"], expected_license=facts["license"],
                            expected_commands=facts["commands"], expected_restrictions=facts["restrictions"],
                            expected_blob_sha=blob, evidence_sink=artifact)
                    self.assertEqual(observation["state"], "exact")
                    self.assertEqual(reference_noop(capture, intent, profile, identity, observation, [artifact])["planner_outcome"], "noop")

    def test_cli_facts_require_exact_npm_corroboration_and_same_projection(self):
        with tempfile.TemporaryDirectory() as tmp:
            capture, intent, _ = create_cli_fixture(Path(tmp).resolve())
            intent["commands"] = [{"name": name} for name in json.loads(capture.source["package.json"])["bin"]]
            projection = authenticated_npm_projection(capture, intent, {})
            for state in (None, "unknown", "absent", "conflict"):
                with self.subTest(state=state), self.assertRaises(ContractError):
                    homebrew_generation_facts(capture, intent, {}, npm_projection=projection, npm_state=state)
            with patch("rs9.hosted_observe.authenticated_npm_projection", side_effect=AssertionError("must reuse facts")):
                facts = homebrew_generation_facts(capture, intent, {}, npm_projection=projection, npm_state="exact")
            self.assertEqual(facts["sha256"], projection["sha256"])
            for changes in ({"url": "https://registry.npmjs.org/other/-/other-1.tgz"},
                            {"sha256": "0" * 64}, {"commands": {"other": "bin/run.js"}}):
                with self.subTest(changes=changes), self.assertRaises(ContractError):
                    homebrew_generation_facts(capture, intent, {}, npm_projection={**projection, **changes}, npm_state="exact")

    def test_cli_projection_rejects_changed_payload_and_noncanonical_supplement(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            capture, intent, _ = create_cli_fixture(root)
            intent["commands"] = [{"name": name} for name in json.loads(capture.source["package.json"])["bin"]]
            archive = next(iter(capture.archives.values()))
            body = archive.read_bytes()
            archive.write_bytes(body + b"changed")
            with self.assertRaises(ContractError) as caught:
                authenticated_npm_projection(capture, intent, {})
            self.assertEqual(caught.exception.code, "OBSERVATION_IDENTITY")
            archive.write_bytes(body)
            (root / "npm").mkdir()
            metadata = json.loads(capture.source["package.json"])
            metadata["dist"] = {"tarball": "https://registry.npmjs.org/other/-/other-1.tgz"}
            (root / "npm/metadata.json").write_bytes(canonical(metadata))
            (root / "npm/package.tgz").write_bytes(body)
            with self.assertRaises(ContractError) as caught:
                authenticated_npm_projection(capture, intent, {})
            self.assertEqual(caught.exception.code, "OBSERVATION_IDENTITY")

    def test_cli_projection_rejects_package_version_scope_and_command_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            capture, intent, _ = create_cli_fixture(Path(tmp).resolve())
            package = json.loads(capture.source["package.json"])
            intent["commands"] = [{"name": name} for name in package["bin"]]
            for changes in ({"version": "9.0.0"}, {"name": "unscoped"}, {"name": "@scope/other"}, {"bin": {"other": "bin/run.js"}}):
                with self.subTest(changes=changes), self.assertRaises(ContractError):
                    capture.source["package.json"] = canonical({**package, **changes})
                    authenticated_npm_projection(capture, intent, {})
            capture.source["package.json"] = canonical(package)

    def test_nebular_homebrew_uses_native_release_despite_supplemental_npm(self):
        from types import SimpleNamespace
        from rs9.hosted_observe import homebrew_generation_facts
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            (root / "npm").mkdir()
            (root / "npm/metadata.json").write_text(json.dumps({"dist": {"tarball": "https://registry.npmjs.org/supplemental.tgz"}, "license": "AGPL-3.0-or-later OR Commercial"}))
            payload = {"id": "darwin", "name": "nebular.app.tar.gz", "platforms": ["aarch64-darwin"], "sha256": "b" * 64}
            capture = SimpleNamespace(root=root,
                record={"repository": {"full_name": "Knowledge-Forge-AI/theme-forge-nebular-fusion"},
                        "release": {"tag": "v0.6.1"}, "payloads": [payload]})
            self.assertFalse(hasattr(capture, "normalized"))
            intent = {"project": {"id": "theme-forge-nebular-fusion"}, "commands": [{"name": "tfnf", "interface": "gui"}], "license": {"expression": "AGPL-3.0-or-later"}}
            profile = {"sections": {"legacy_ingestion": {"license": {"status": "consistent"}}}}
            facts = homebrew_generation_facts(capture, intent, profile)
            self.assertEqual(facts["restrictions"], "aarch64-darwin")
            self.assertEqual(facts["license"], "AGPL-3.0-or-later")
            self.assertEqual(facts["sha256"], payload["sha256"])
            self.assertTrue(facts["url"].endswith("/v0.6.1/nebular.app.tar.gz"))
            self.assertEqual(set(facts["commands"]), {"tfnf"})

            # Inconsistent profile status fails closed
            with self.assertRaises(ContractError) as caught:
                homebrew_generation_facts(capture, intent, {"sections": {"legacy_ingestion": {"license": {"status": "conflict"}}}})
            self.assertEqual(caught.exception.code, "LICENSE_AUTHORITY")

            # Mismatched profile license expression fails closed
            with self.assertRaises(ContractError) as caught:
                homebrew_generation_facts(capture, intent, {"sections": {"legacy_ingestion": {"license": {"status": "consistent", "expression": "MIT"}}}})
            self.assertEqual(caught.exception.code, "LICENSE_AUTHORITY")

            # Invalid SPDX expression in intent fails closed
            with self.assertRaises(ContractError) as caught:
                homebrew_generation_facts(capture, {**intent, "license": {"expression": "INVALID SPDX++"}}, profile)
            self.assertEqual(caught.exception.code, "INVALID_SPDX_EXPRESSION")

            # Missing license authority fails closed
            with self.assertRaises(ContractError) as caught:
                homebrew_generation_facts(capture, {"project": {"id": "theme-forge-nebular-fusion"}, "commands": [{"name": "tfnf", "interface": "gui"}]}, None)
            self.assertEqual(caught.exception.code, "LICENSE_AUTHORITY")

    def row(self, adapter, state):
        return {"adapter": adapter, "observation": {"state": state}}

    def test_existing_npm_and_homebrew_require_exact_byte_identity(self):
        for adapter in ("npm", "homebrew"):
            self.assertTrue(readback_satisfied(self.row(adapter, "exact")))
            for state in ("unknown", "incomplete", "absent", "conflict"):
                self.assertFalse(readback_satisfied(self.row(adapter, state)))

    def test_pypi_absence_does_not_attest_a_deployed_pages_site(self):
        self.assertTrue(readback_satisfied(self.row("pypi", "absent")))
        self.assertTrue(readback_satisfied(self.row("pages", "absent")))
        self.assertFalse(readback_satisfied(self.row("pages", "exact")))
        self.assertFalse(readback_satisfied(self.row("pypi", "incomplete")))

    def test_exact_reference_reaches_real_planner_noop_with_fresh_profile(self):
        from datetime import datetime, timezone
        from rs9.hosted_observe import reference_identity, reference_noop
        from rs9.observation import observe
        from rs9.records import record_sha256
        from tests.publication_fixtures import fixture
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            intent, capture, profile, *_ = fixture(root)
            for adapter in ("npm", "homebrew"):
                identity = reference_identity(capture, intent, adapter)
                artifact = {"path": "reference.json", "sha256": "a" * 64, "size": 2}
                observed = observe({"id": adapter, "adapter": adapter, "mode": "direct" if adapter == "npm" else "projection"},
                    {"package": intent["project"]["id"], "version": intent["version"], "revision": None},
                    {artifact["path"]: artifact["sha256"]}, record_sha256(identity),
                    readback={"authenticated": True, "transport": "ok", "presence": "present", "level": "full",
                              "components": {artifact["path"]: artifact["sha256"]}, "content_identity_sha256": record_sha256(identity)},
                    source="synthetic-fixture", observed_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"))
                result = reference_noop(capture, intent, profile, identity, observed, [artifact])
                self.assertEqual(result["planner_outcome"], "noop")
                self.assertRegex(result["plan_sha256"], r"^[0-9a-f]{64}$")
                with self.assertRaises(ContractError):
                    reference_noop(capture, intent, {**profile, "release_record_sha256": "0" * 64}, identity, observed, [artifact])


class HostedObserveExecutionTests(unittest.TestCase):
    def setUp(self):
        # Fresh planner binding is exercised separately with an authenticated profile/configuration.
        planner = patch("rs9.hosted_observe.reference_noop", return_value={"planner_outcome": "noop", "plan_sha256": "a" * 64})
        planner.start()
        self.addCleanup(planner.stop)

    def _create_real_captures(self, root, count=4, prefix="capture", cli_supplemental_npm=False):
        products = (
            "theme-forge-stellar-burst",
            "theme-forge-stellar-loom",
            "theme-forge-solar-sail",
            "theme-forge-nebular-fusion",
        )[:count]
        captures = []
        for product in products:
            c_root = root / f"{prefix}_{product}"
            if product == "theme-forge-nebular-fusion":
                c_root.mkdir(parents=True, exist_ok=True)
                neb_norm = fixture_evidence(c_root)
                intent = {
                    "project": {"id": product, "repository": neb_norm["project"]["repository"]},
                    "version": neb_norm["version"],
                    "tag": neb_norm["tag"],
                    "license": {"expression": "AGPL-3.0-or-later", "files": neb_norm["license"]["files"]},
                    "assets": neb_norm["assets"],
                    "commands": [{"name": "tfnf", "interface": "gui"}],
                    "release": neb_norm["release"],
                }
                capture = authenticate_release(selection_for_intent(intent), c_root)
                npm_data = json.loads((c_root / "npm/metadata.json").read_bytes())
                npm_data["dist"]["tarball"] = f"https://registry.npmjs.org/@knowledge-forge-ai/theme-forge-nebular-fusion/-/theme-forge-nebular-fusion-{neb_norm['version']}.tgz"
                (c_root / "npm/metadata.json").write_bytes(canonical(npm_data))
                profile = {"sections": {"license": {"status": "consistent", "expression": "AGPL-3.0-or-later"}}}
                captures.append((capture, intent, profile))
            else:
                capture, intent, _ = create_cli_fixture(c_root, product=product)
                intent["commands"] = [{"name": name} for name in json.loads(capture.source["package.json"])["bin"]]
                if cli_supplemental_npm:
                    npm_dir = c_root / "npm"
                    npm_dir.mkdir(parents=True, exist_ok=True)
                    payload = capture.record["payloads"][0]
                    archive_bytes = capture.archives[payload["id"]].read_bytes()
                    (npm_dir / "package.tgz").write_bytes(archive_bytes)
                    pkg_data = json.loads(capture.source["package.json"])
                    npm_url = f"https://registry.npmjs.org/@knowledge-forge-ai/{product}/-/{payload['name']}"
                    (npm_dir / "metadata.json").write_bytes(canonical({
                        "name": f"@knowledge-forge-ai/{product}",
                        "version": intent["version"],
                        "license": "AGPL-3.0-or-later",
                        "bin": pkg_data.get("bin", {}),
                        "dist": {
                            "tarball": npm_url,
                            "integrity": "sha512-" + base64.b64encode(hashlib.sha512(archive_bytes).digest()).decode()
                        }
                    }))
                profile = {"sections": {"license": {"status": "consistent", "expression": "AGPL-3.0-or-later"}}}
                captures.append((capture, intent, profile))
        return captures

    def test_homebrew_fact_failure_retains_safe_identity_diagnostics(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            scratch = root / "scratch"
            scratch.mkdir()
            captures = self._create_real_captures(root)
            captures[0][2]["sections"]["license"]["expression"] = "MIT"
            blobs = {f"Formula/{intent['project']['id']}.rb": "b" * 40 for _, intent, _ in captures}
            with patch("rs9.hosted_observe.tap_snapshot", return_value=("main", "c" * 40, blobs)), \
                 patch("rs9.hosted_observe.read_pypi_project", return_value={"state": "absent"}), \
                 patch("rs9.hosted_observe.read_npm", return_value={"state": "exact"}), \
                 self.assertRaises(ContractError) as caught:
                execute({"captures": captures, "scratch": scratch, "client": MagicMock()})
            expected = {"product": "theme-forge-stellar-burst", "destination": "homebrew",
                        "substage": "homebrew-generation-facts", "code": "LICENSE_AUTHORITY"}
            self.assertEqual(caught.exception.details, expected)
            diagnostics = json.loads((scratch / "diagnostics/observe-destinations.json").read_bytes())
            self.assertEqual(diagnostics[-1], expected)

    def test_failure_g_real_record_shape_regression(self):
        """Failure G regression: capture.record has record['release']['tag'], not tag['name']."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            scratch = root / "scratch"
            scratch.mkdir()
            captures = self._create_real_captures(root, count=4)

            # Assert real schema: tag has no 'name', release has 'tag'
            first_capture = captures[0][0]
            self.assertIn("tag", first_capture.record["release"])
            self.assertEqual(first_capture.record["release"]["tag"], "v0.6.1")
            self.assertNotIn("name", first_capture.record["tag"])

            client = MagicMock()
            client.json.return_value = {"sha": "c" * 40}
            context = {"captures": captures, "client": client, "scratch": scratch}

            formula_blobs = {
                f"Formula/{p}.rb": "b" * 40
                for p in ("theme-forge-stellar-burst", "theme-forge-stellar-loom", "theme-forge-solar-sail", "theme-forge-nebular-fusion")
            }

            with patch("rs9.hosted_observe.tap_snapshot", return_value=("main", "c" * 40, formula_blobs)), \
                 patch("rs9.hosted_observe.read_pypi_project") as pypi_mock, \
                 patch("rs9.hosted_observe.read_npm") as npm_mock, \
                 patch("rs9.hosted_observe.read_homebrew") as brew_mock, \
                 patch("rs9.hosted_observe.read_pages") as pages_mock:
                pypi_mock.return_value = {"state": "absent"}
                npm_mock.return_value = {"state": "exact"}
                brew_mock.return_value = {"state": "exact"}
                pages_mock.return_value = {"state": "absent"}

                result = execute(context)

            self.assertEqual(result["gates"][0]["status"], "pass")
            self.assertEqual(result["gates"][1]["status"], "pass")
            self.assertEqual(result["gates"][1]["reason"], "live-byte-readback")

            doc_path = scratch / "destination-observations.json"
            self.assertTrue(doc_path.is_file())
            doc = json.loads(doc_path.read_text())
            self.assertEqual(doc["schema"], "rs9.hosted-destination-observations.v1alpha1")
            self.assertEqual(len(doc["observations"]), 4 * 3 + 1)  # 4 * (pypi + npm + brew) + pages

            # Verify that read_homebrew received correct release download URL derived from record['release']['tag']
            expected_nebular_url = "https://github.com/Knowledge-Forge-AI/theme-forge-nebular-fusion/releases/download/v0.6.1/theme-forge-nebular-fusion-v0.6.1-aarch64-apple-darwin.app.tar.gz"
            neb_calls = [c for c in brew_mock.call_args_list if c.args[1]["package"] == "theme-forge-nebular-fusion"]
            self.assertEqual(len(neb_calls), 1)
            self.assertEqual(neb_calls[0].kwargs["expected_payload_url"], expected_nebular_url)
            self.assertEqual(neb_calls[0].kwargs["pinned_ref"], "c" * 40)

    def test_release_tag_identity_is_fail_closed(self):
        for tag in (None, 123, {"name": "v0.6.1"}, "v0.6.2", "0.6.1"):
            with self.subTest(tag=tag), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve()
                scratch = root / "scratch"
                scratch.mkdir()
                captures = self._create_real_captures(root)
                captures[0][0].record["release"]["tag"] = tag
                with self.assertRaises(ContractError) as caught:
                    execute({"captures": captures, "scratch": scratch, "client": MagicMock()})
                self.assertEqual(caught.exception.code, "OBSERVATION_RECORD")

    def test_unrelated_native_payload_does_not_force_cli_npm_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            scratch = root / "scratch"
            scratch.mkdir()
            captures = self._create_real_captures(root)
            for capture, _, _ in captures:
                capture.record["payloads"].append({
                    "id": "foreign",
                    "name": "foreign-x86_64.tar.gz",
                    "platforms": ["x86_64-linux"],
                    "sha256": "f" * 64,
                    "command_policy": "native-executable",
                    "root": "foreign",
                })
                if (capture.root / "npm/metadata.json").is_file():
                    (capture.root / "npm/metadata.json").unlink()
            client = MagicMock()
            client.json.return_value = None
            with patch("rs9.hosted_observe.read_pypi_project", return_value={"state": "absent"}), \
                 patch("rs9.hosted_observe.read_pages", return_value={"state": "absent"}), \
                 patch("rs9.hosted_observe.read_npm", return_value={"state": "exact"}) as npm:
                execute({"captures": captures, "scratch": scratch, "client": client})
            # 3 CLI packages performed npm readback despite unrelated native payload
            self.assertEqual(npm.call_count, 3)
            rows = json.loads((scratch / "destination-observations.json").read_bytes())["observations"]
            cli_npm_rows = [r for r in rows if r["adapter"] == "npm" and r["project"] != "theme-forge-nebular-fusion"]
            self.assertTrue(all(r["observation"] == {"state": "exact"} for r in cli_npm_rows))
            # Nebular desktop without supplemental npm correctly stays unknown
            neb_npm_row = [r for r in rows if r["adapter"] == "npm" and r["project"] == "theme-forge-nebular-fusion"][0]
            self.assertEqual(neb_npm_row["observation"], {"state": "unknown", "reason": "npm-identity-unavailable"})

    def test_ambiguous_matching_npm_rows_block_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            scratch = root / "scratch"
            scratch.mkdir()
            captures = self._create_real_captures(root)
            # Add duplicate matching npm payload to first capture
            first_capture = captures[0][0]
            duplicate_npm_payload = copy.deepcopy(first_capture.record["payloads"][0])
            duplicate_npm_payload["id"] = "package-dup"
            duplicate_npm_payload["name"] = "duplicate.tgz"
            first_capture.record["payloads"].append(duplicate_npm_payload)
            first_capture.archives["package-dup"] = first_capture.archives[first_capture.record["payloads"][0]["id"]]

            client = MagicMock()
            with patch("rs9.hosted_observe.read_pypi_project", return_value={"state": "absent"}), \
                 self.assertRaises(ContractError) as caught:
                execute({"captures": captures, "scratch": scratch, "client": client})
            self.assertEqual(caught.exception.code, "OBSERVATION_IDENTITY")
            diags = json.loads((scratch / "diagnostics/observe-destinations.json").read_bytes())
            self.assertEqual(diags[-1]["destination"], "npm")
            self.assertEqual(diags[-1]["substage"], "npm-projection")
            self.assertEqual(diags[-1]["code"], "OBSERVATION_IDENTITY")

    def test_same_class_npm_command_conflict_blocks_instead_of_unknown(self):
        for variant in ("wrong-target", "missing-commands", "extra-conflicting-payload"):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve()
                scratch = root / "scratch"
                scratch.mkdir()
                captures = self._create_real_captures(root)
                capture = captures[0][0]
                payload = capture.record["payloads"][0]
                if variant == "extra-conflicting-payload":
                    payload = copy.deepcopy(payload)
                    payload["id"] = "conflicting-npm"
                    capture.record["payloads"].append(payload)
                if variant == "missing-commands":
                    payload.pop("commands")
                else:
                    command = next(iter(payload["commands"]))
                    payload["commands"][command]["path"] = "package/bin/wrong.js"
                client = MagicMock()
                client.json.return_value = None
                with patch("rs9.hosted_observe.read_pypi_project", return_value={"state": "absent"}), \
                     patch("rs9.hosted_observe.read_pages", return_value={"state": "absent"}), \
                     patch("rs9.hosted_observe.read_npm", return_value={"state": "unknown"}) as npm, \
                     self.assertRaises(ContractError) as caught:
                    execute({"captures": captures, "scratch": scratch, "client": client})
                self.assertEqual(caught.exception.code, "OBSERVATION_IDENTITY")
                npm.assert_not_called()
                diagnostics = json.loads((scratch / "diagnostics/observe-destinations.json").read_bytes())
                self.assertEqual(diagnostics[-1]["code"], "OBSERVATION_IDENTITY")
                self.assertEqual(diagnostics[-1]["substage"], "npm-projection")

    def test_missing_homebrew_platform_payload_records_conflict_and_finishes_observations(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            scratch = root / "scratch"
            scratch.mkdir()
            captures = self._create_real_captures(root)
            for capture, _, _ in captures:
                for payload in capture.record["payloads"]:
                    payload["platforms"] = ["x86_64-linux"]
            formula_blobs = {
                f"Formula/{p}.rb": "d" * 40
                for p in ("theme-forge-stellar-burst", "theme-forge-stellar-loom", "theme-forge-solar-sail", "theme-forge-nebular-fusion")
            }
            with patch("rs9.hosted_observe.tap_snapshot", return_value=("main", "e" * 40, formula_blobs)), \
                 patch("rs9.hosted_observe.read_pypi_project", return_value={"state": "absent"}), \
                 patch("rs9.hosted_observe.read_npm", return_value={"state": "unknown"}), \
                 patch("rs9.hosted_observe.read_pages", return_value={"state": "absent"}), \
                 patch("rs9.hosted_observe.read_homebrew") as brew:
                result = execute({"captures": captures, "scratch": scratch, "client": MagicMock()})
            brew.assert_not_called()
            rows = json.loads((scratch / "destination-observations.json").read_bytes())["observations"]
            self.assertEqual(len(rows), 13)
            for row in rows:
                if row["adapter"] != "homebrew":
                    continue
                expected = ({"state": "conflict", "reason": "payload-unavailable"}
                            if row["project"] == "theme-forge-nebular-fusion"
                            else {"state": "unknown", "reason": "npm-readback-unknown"})
                self.assertEqual(row["observation"], expected)
            self.assertEqual(result["gates"][1]["status"], "fail")

    def test_real_homebrew_metadata_does_not_claim_exact_projection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            scratch = root / "scratch"
            scratch.mkdir()
            captures = self._create_real_captures(root)
            capture = captures[0][0]
            payload = capture.record["payloads"][0]
            url = "https://github.com/" + capture.record["repository"]["full_name"] + "/releases/download/v0.6.1/" + payload["name"]
            formula = ('class Example < Formula\n  url "' + url + '"\n  sha256 "' + payload["sha256"] + '"\n  version "0.6.1"\nend\n').encode()
            client = MagicMock()
            client.json.return_value = {"sha": "c" * 40}
            with patch("rs9.hosted_observe.read_pypi_project", return_value={"state": "absent"}), \
                 patch("rs9.hosted_observe.read_npm", return_value={"state": "exact"}), \
                 patch("rs9.hosted_observe.read_pages", return_value={"state": "absent"}), \
                 patch("rs9.readers._get", return_value=formula):
                result = execute({"captures": captures, "scratch": scratch, "client": client})
            rows = json.loads((scratch / "destination-observations.json").read_bytes())["observations"]
            self.assertTrue(all(r["observation"]["state"] == "unknown" for r in rows if r["adapter"] == "homebrew"))
            self.assertEqual(result["gates"][1]["status"], "not-run")

    def test_tap_head_error_shapes_map_to_unknown(self):
        """Tap head TypeError, non-dict, or invalid SHA all map to unknown state."""
        cases = [
            ("type-error", TypeError("'NoneType' object is not subscriptable")),
            ("non-dict-list", [{"sha": "a" * 40}]),
            ("non-dict-string", "raw string commit"),
            ("non-dict-int", 12345),
            ("invalid-sha-chars", {"sha": "g" * 40}),
            ("invalid-sha-length", {"sha": "a" * 39}),
            ("missing-sha", {"commit": "a" * 40}),
            ("http-exception", http.client.HTTPException("protocol error")),
        ]
        for name, failure in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve()
                scratch = root / "scratch"
                scratch.mkdir()
                captures = self._create_real_captures(root, count=4)

                client = MagicMock()
                if isinstance(failure, Exception):
                    client.json.side_effect = failure
                else:
                    client.json.return_value = failure
                context = {"captures": captures, "client": client, "scratch": scratch}

                with patch("rs9.hosted_observe.read_pypi_project", return_value={"state": "absent"}), \
                     patch("rs9.hosted_observe.read_npm", return_value={"state": "exact"}), \
                     patch("rs9.hosted_observe.read_pages", return_value={"state": "absent"}):
                    result = execute(context)

                brew_obs = [o for o in json.loads((scratch / "destination-observations.json").read_text())["observations"]
                            if o["adapter"] == "homebrew"]
                self.assertEqual(len(brew_obs), 4)
                for entry in brew_obs:
                    self.assertEqual(entry["observation"]["state"], "unknown")
                    self.assertEqual(entry["observation"]["reason"], "tap-snapshot-unavailable-or-drifted")
                    self.assertIsNone(entry["pinned_ref"])

                # Gate comparison must be not-run when observations have unknown state
                self.assertEqual(result["gates"][1]["status"], "not-run")
                self.assertEqual(result["gates"][1]["reason"], "observations-recorded-with-unknown-or-metadata-only-states")

    def test_select_brew_payload_is_strict_and_uses_only_declared_platforms(self):
        """Selects Darwin or any from the platform contract and rejects heuristic fallbacks."""
        mock_capture = MagicMock()
        mock_capture.record = {
            "payloads": [
                {"name": "second-x86_64-linux.tgz", "platforms": ["x86_64-linux"], "sha256": "1" * 64},
                {"name": "second-aarch64-darwin.tgz", "platforms": ["aarch64-darwin"], "sha256": "2" * 64},
                {"name": "second-any.tgz", "platforms": ["any"], "sha256": "3" * 64},
            ]
        }

        # 1. Fallback selects aarch64-darwin directly
        selected = select_brew_payload(mock_capture)
        self.assertEqual(selected["name"], "second-aarch64-darwin.tgz")

        # 2. If aarch64-darwin absent, fallback selects 'any'
        mock_capture.record["payloads"] = [
            {"name": "second-x86_64-linux.tgz", "platforms": ["x86_64-linux"], "sha256": "1" * 64},
            {"name": "second-any.tgz", "platforms": ["any"], "sha256": "3" * 64},
        ]
        selected_any = select_brew_payload(mock_capture)
        self.assertEqual(selected_any["name"], "second-any.tgz")

        # 3. If hosted_platforms.select_payload exists, delegates to it
        with patch("rs9.hosted_observe.select_payload", return_value={"name": "delegated.tgz"}):
            selected_delegated = select_brew_payload(mock_capture)
            self.assertEqual(selected_delegated["name"], "delegated.tgz")
        mock_capture.record["payloads"] = [{"name": "looks-aarch64-darwin.tgz", "platforms": ["x86_64-linux"]}]
        with self.assertRaises(ContractError):
            select_brew_payload(mock_capture)
        mock_capture.record["payloads"] = [{"name": "first.tgz", "platforms": ["any"]},
                                          {"name": "second.tgz", "platforms": ["any"]}]
        with self.assertRaises(ContractError):
            select_brew_payload(mock_capture)

    def test_schema_and_identity_gaps_fail_closed(self):
        """Malformed captures, missing release tag or repository fail closed with ContractError."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            scratch = root / "scratch"
            scratch.mkdir()

            # Captures count != 4
            context_bad_len = {"captures": [], "scratch": scratch}
            with self.assertRaises(ContractError) as caught:
                execute(context_bad_len)
            self.assertEqual(caught.exception.code, "OBSERVATION_CAPTURE")
            self.assertEqual(caught.exception.details.get("substage"), "capture-validation")

            # Missing release tag
            captures = self._create_real_captures(root, count=4, prefix="missing_tag")
            del captures[0][0].record["release"]["tag"]
            with self.assertRaises(ContractError) as caught:
                execute({"captures": captures, "scratch": scratch, "client": MagicMock()})
            self.assertEqual(caught.exception.code, "OBSERVATION_RECORD")
            self.assertEqual(caught.exception.details.get("substage"), "record-validation")

            # Missing repository full_name
            captures = self._create_real_captures(root, count=4, prefix="missing_repo")
            del captures[0][0].record["repository"]["full_name"]
            with self.assertRaises(ContractError) as caught:
                execute({"captures": captures, "scratch": scratch, "client": MagicMock()})
            self.assertEqual(caught.exception.code, "OBSERVATION_RECORD")
            self.assertEqual(caught.exception.details.get("substage"), "record-validation")

    def test_tap_default_branch_resolution_and_binding_four_blobs_to_one_commit(self):
        """Resolves actual tap default branch via public GitHub API and binds 4 formula blobs to 1 commit."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            scratch = root / "scratch"
            scratch.mkdir()
            captures = self._create_real_captures(root, count=4)
            for (_, intent, _), product in zip(captures, ("theme-forge-stellar-burst", "theme-forge-stellar-loom", "theme-forge-solar-sail", "theme-forge-nebular-fusion")):
                intent["project"]["id"] = product

            tap = "Knowledge-Forge-AI/homebrew-tap"
            commit_sha = "b8b695bbb27e607a181e8ddedc506a1235831484"
            tree_sha = "d0a4143bfce23567f9fbd25948335a95630918e4"
            blobs = {
                "Formula/theme-forge-stellar-burst.rb": "0a5cf66b85a7e88172bba72c6cbe2de65a888f48",
                "Formula/theme-forge-stellar-loom.rb": "a6ece55af3578e2c67cf4d794361684b4a25acd0",
                "Formula/theme-forge-solar-sail.rb": "5a607dbef7da39003db2bb7cbda2f7411cc50947",
                "Formula/theme-forge-nebular-fusion.rb": "9e1664b290dafaa377161e275b7f7d2116e65596",
            }

            def mock_client_json(url, request_class="github-api", **kwargs):
                if url == f"https://api.github.com/repos/{tap}":
                    return {"default_branch": "main", "name": "homebrew-tap"}
                if url == f"https://api.github.com/repos/{tap}/commits/main":
                    return {
                        "sha": commit_sha,
                        "commit": {"tree": {"sha": tree_sha}},
                    }
                if url == f"https://api.github.com/repos/{tap}/git/trees/{tree_sha}?recursive=1":
                    return {
                        "sha": tree_sha, "truncated": False,
                        "tree": [{"path": p, "sha": s, "type": "blob", "mode": "100644"} for p, s in blobs.items()],
                    }
                raise ValueError(f"Unexpected URL: {url}")

            client = MagicMock()
            client.json.side_effect = mock_client_json
            context = {"captures": captures, "client": client, "scratch": scratch}

            with patch("rs9.hosted_observe.read_pypi_project", return_value={"state": "absent"}), \
                 patch("rs9.hosted_observe.read_npm", return_value={"state": "exact"}), \
                 patch("rs9.hosted_observe.read_homebrew", return_value={"state": "exact"}), \
                 patch("rs9.hosted_observe.read_pages", return_value={"state": "absent"}):
                result = execute(context)

            self.assertEqual(result["gates"][0]["status"], "pass")
            self.assertEqual(result["gates"][1]["status"], "pass")
            self.assertEqual(result["gates"][1]["reason"], "live-byte-readback")

            details = result["details"]
            self.assertEqual(details["tap_default_branch"], "main")
            self.assertEqual(details["tap_commit_sha"], commit_sha)
            self.assertEqual(details["tap_tree_sha"], tree_sha)
            for path, blob in blobs.items():
                self.assertEqual(details["bound_formula_blobs"].get(path), blob)

            # Planner noop recorded for exact observations
            self.assertGreaterEqual(len(details["planner_noops"]), 8)  # 4 npm + 4 brew

            doc = json.loads((scratch / "destination-observations.json").read_bytes())
            brew_rows = [r for r in doc["observations"] if r["adapter"] == "homebrew"]
            self.assertEqual(len(brew_rows), 4)
            for r in brew_rows:
                self.assertEqual(r["pinned_ref"], commit_sha)
                self.assertEqual(r["observation"]["state"], "exact")
                self.assertEqual(r["planner_outcome"], "noop")

    def test_homebrew_full_agreement_end_to_end_with_real_fixtures(self):
        """End-to-end exact Homebrew and npm readback for all four formulas using real captures."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            scratch = root / "scratch"
            scratch.mkdir()
            captures = self._create_real_captures(root, count=4)

            formulas = {}
            blobs = {}
            for cap, itn, prof in captures:
                p = itn["project"]["id"]
                facts = homebrew_generation_facts(cap, itn, prof, npm_projection=authenticated_npm_projection(cap, itn, prof), npm_state="exact")
                # Exercise maintained formula syntax and command/restriction parsing.
                template = (Path(__file__).parent / "fixtures/homebrew/Formula" / (p + ".rb")).read_text()
                content = re.sub(r"(?m)^  sha256 \"[0-9a-f]{64}\"$", lambda _: f"  sha256 \"{facts['sha256']}\"", template).encode()
                self.assertIn(facts["url"], content.decode())
                rel_path = f"Formula/{p}.rb"
                formulas[rel_path] = content
                blobs[rel_path] = hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest()

            def mock_get(url, *args, **kwargs):
                for path, content in formulas.items():
                    if url.endswith(path):
                        return content
                raise ValueError(f"Unexpected raw GET URL: {url}")

            client = MagicMock()
            client.json.return_value = {"default_branch": "main", "sha": "e" * 40}

            with patch("rs9.hosted_observe.tap_snapshot", return_value=("main", "e" * 40, blobs)), \
                 patch("rs9.hosted_observe.read_pypi_project", return_value={"state": "absent"}), \
                 patch("rs9.hosted_observe.read_npm", return_value={"state": "exact"}), \
                 patch("rs9.hosted_observe.read_pages", return_value={"state": "absent"}), \
                 patch("rs9.readers._get", side_effect=mock_get):
                result = execute({"captures": captures, "scratch": scratch, "client": client})

            self.assertEqual(result["gates"][0]["status"], "pass")
            self.assertEqual(result["gates"][1]["status"], "pass")
            self.assertEqual(result["gates"][1]["reason"], "live-byte-readback")
            self.assertEqual(len(result["details"]["planner_noops"]), 8)  # 4 npm + 4 brew

            doc = json.loads((scratch / "destination-observations.json").read_bytes())
            brew_rows = [r for r in doc["observations"] if r["adapter"] == "homebrew"]
            self.assertEqual(len(brew_rows), 4)
            for brew_row in brew_rows:
                self.assertEqual(brew_row["observation"]["state"], "exact")
                self.assertEqual(brew_row["planner_outcome"], "noop")
                self.assertEqual(brew_row["pinned_ref"], "e" * 40)

    def test_homebrew_identity_mismatch_yields_conflict(self):
        """Mismatched license in a formula yields conflict."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            scratch = root / "scratch"
            scratch.mkdir()
            captures = self._create_real_captures(root, count=4)

            formulas = {}
            blobs = {}
            for i, (cap, itn, prof) in enumerate(captures):
                p = itn["project"]["id"]
                facts = homebrew_generation_facts(cap, itn, prof, npm_projection=authenticated_npm_projection(cap, itn, prof), npm_state="exact")
                lic = "GPL-3.0-only" if i == 0 else facts["license"]
                lines = [
                    f"class {formula_class_name(p)} < Formula",
                    f'  url "{facts["url"]}"',
                    f'  sha256 "{facts["sha256"]}"',
                    f'  license "{lic}"',
                ]
                if facts["restrictions"] == "aarch64-darwin":
                    lines += ["  depends_on arch: :arm64", "  depends_on :macos"]
                else:
                    lines += ['  depends_on "node"']
                lines.append("  def install")
                for cmd in facts["commands"]:
                    lines.append(f'    (bin/"{cmd}").write "exec"')
                lines += [
                    "  end",
                    "  test do",
                    "    assert_equal 1, 1",
                    "  end",
                    "end\n",
                ]
                content = "\n".join(lines).encode()
                rel_path = f"Formula/{p}.rb"
                formulas[rel_path] = content
                blobs[rel_path] = hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest()

            def mock_get(url, *args, **kwargs):
                for path, content in formulas.items():
                    if url.endswith(path):
                        return content
                raise ValueError(f"Unexpected raw GET URL: {url}")

            client = MagicMock()
            client.json.return_value = {"sha": "e" * 40}

            with patch("rs9.hosted_observe.tap_snapshot", return_value=("main", "e" * 40, blobs)), \
                 patch("rs9.hosted_observe.read_pypi_project", return_value={"state": "absent"}), \
                 patch("rs9.hosted_observe.read_npm", return_value={"state": "exact"}), \
                 patch("rs9.hosted_observe.read_pages", return_value={"state": "absent"}), \
                 patch("rs9.readers._get", side_effect=mock_get):
                result = execute({"captures": captures, "scratch": scratch, "client": client})

            doc = json.loads((scratch / "destination-observations.json").read_bytes())
            first_brew = [r for r in doc["observations"] if r["adapter"] == "homebrew"][0]
            self.assertEqual(first_brew["observation"]["state"], "conflict")
            self.assertNotIn("planner_outcome", first_brew)
            self.assertEqual(result["gates"][1]["status"], "fail")

    def test_failure_e_cli_homebrew_facts_without_supplemental_files(self):
        """All three CLI packages derive exact Homebrew facts without requiring capture.root/npm files."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            captures = self._create_real_captures(root, count=3, cli_supplemental_npm=False)
            for capture, intent, profile in captures:
                p = intent["project"]["id"]
                # Verify no supplemental files exist in capture.root
                self.assertFalse((capture.root / "npm").exists())
                self.assertFalse((capture.root / "npm/metadata.json").exists())
                self.assertFalse((capture.root / "npm/package.tgz").exists())

                facts = homebrew_generation_facts(capture, intent, profile, npm_projection=authenticated_npm_projection(capture, intent, profile), npm_state="exact")
                payload = capture.record["payloads"][0]
                archive_bytes = capture.archives[payload["id"]].read_bytes()
                pkg_data = json.loads(capture.source["package.json"])

                self.assertEqual(facts["restrictions"], "node")
                self.assertEqual(facts["license"], "AGPL-3.0-or-later")
                self.assertEqual(facts["sha256"], hashlib.sha256(archive_bytes).hexdigest())
                self.assertEqual(facts["commands"], pkg_data["bin"])
                expected_url = f"https://registry.npmjs.org/@knowledge-forge-ai/{p}/-/{payload['name']}"
                self.assertEqual(facts["url"], expected_url)

    def test_failure_e_cli_npm_unknown_yields_homebrew_unknown(self):
        """When CLI npm readback is unknown, Homebrew observation becomes unknown."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            scratch = root / "scratch"
            scratch.mkdir()
            captures = self._create_real_captures(root, count=4, cli_supplemental_npm=False)

            blobs = {f"Formula/{p}.rb": "a" * 40 for p in ("theme-forge-stellar-burst", "theme-forge-stellar-loom", "theme-forge-solar-sail", "theme-forge-nebular-fusion")}

            def mock_npm(dest, subj, **kwargs):
                if subj["package"] == "@knowledge-forge-ai/theme-forge-stellar-burst":
                    return {"state": "unknown", "reason": "npm-registry-timeout"}
                return {"state": "exact"}

            client = MagicMock()
            client.json.return_value = {"default_branch": "main", "sha": "a" * 40}

            with patch("rs9.hosted_observe.tap_snapshot", return_value=("main", "a" * 40, blobs)), \
                 patch("rs9.hosted_observe.read_pypi_project", return_value={"state": "absent"}), \
                 patch("rs9.hosted_observe.read_npm", side_effect=mock_npm), \
                 patch("rs9.hosted_observe.read_homebrew", return_value={"state": "exact"}), \
                 patch("rs9.hosted_observe.read_pages", return_value={"state": "absent"}):
                result = execute({"captures": captures, "scratch": scratch, "client": client})

            doc = json.loads((scratch / "destination-observations.json").read_bytes())
            burst_brew = [r for r in doc["observations"] if r["project"] == "theme-forge-stellar-burst" and r["adapter"] == "homebrew"][0]
            self.assertEqual(burst_brew["observation"]["state"], "unknown")
            self.assertEqual(burst_brew["observation"]["reason"], "npm-readback-unknown")
            self.assertNotIn("planner_outcome", burst_brew)
            # Gate comparison is not-run because of unknown state
            self.assertEqual(result["gates"][1]["status"], "not-run")
            self.assertEqual(result["gates"][1]["reason"], "observations-recorded-with-unknown-or-metadata-only-states")

            # Check safe diagnostics for npm-prerequisite unknown
            diags = json.loads((scratch / "diagnostics/observe-destinations.json").read_bytes())
            unknown_diags = [d for d in diags if d.get("code") == "npm-readback-unknown"]
            self.assertEqual(len(unknown_diags), 1)
            self.assertEqual(unknown_diags[0]["product"], "theme-forge-stellar-burst")
            self.assertEqual(unknown_diags[0]["destination"], "homebrew")
            self.assertEqual(unknown_diags[0]["substage"], "npm-prerequisite")

    def test_failure_e_cli_npm_conflict_or_absent_fails_closed_and_retains_static_formula_evidence(self):
        """When CLI npm readback is absent or conflict, Homebrew fails closed and retains static formula evidence."""
        for npm_fail_state in ("conflict", "absent"):
            with self.subTest(npm_fail_state=npm_fail_state), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve()
                scratch = root / "scratch"
                scratch.mkdir()
                captures = self._create_real_captures(root, count=4, cli_supplemental_npm=False)

                formulas = {}
                blobs = {}
                for cap, itn, prof in captures:
                    p = itn["project"]["id"]
                    facts = homebrew_generation_facts(cap, itn, prof, npm_projection=authenticated_npm_projection(cap, itn, prof), npm_state="exact")
                    template = (Path(__file__).parent / "fixtures/homebrew/Formula" / (p + ".rb")).read_text()
                    content = re.sub(r"(?m)^  sha256 \"[0-9a-f]{64}\"$", lambda _: f"  sha256 \"{facts['sha256']}\"", template).encode()
                    rel_path = f"Formula/{p}.rb"
                    formulas[rel_path] = content
                    blobs[rel_path] = hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest()

                def mock_get(url, *args, **kwargs):
                    for path, content in formulas.items():
                        if url.endswith(path):
                            return content
                    raise ValueError(f"Unexpected raw GET URL: {url}")

                def mock_npm(dest, subj, **kwargs):
                    if subj["package"] == "@knowledge-forge-ai/theme-forge-stellar-loom":
                        return {"state": npm_fail_state, "reason": "npm-failure"}
                    return {"state": "exact"}

                client = MagicMock()
                client.json.return_value = {"default_branch": "main", "sha": "b" * 40}

                with patch("rs9.hosted_observe.tap_snapshot", return_value=("main", "b" * 40, blobs)), \
                     patch("rs9.hosted_observe.read_pypi_project", return_value={"state": "absent"}), \
                     patch("rs9.hosted_observe.read_npm", side_effect=mock_npm), \
                     patch("rs9.hosted_observe.read_pages", return_value={"state": "absent"}), \
                     patch("rs9.readers._get", side_effect=mock_get):
                    result = execute({"captures": captures, "scratch": scratch, "client": client})

                doc = json.loads((scratch / "destination-observations.json").read_bytes())
                loom_brew = [r for r in doc["observations"] if r["project"] == "theme-forge-stellar-loom" and r["adapter"] == "homebrew"][0]
                self.assertEqual(loom_brew["observation"]["state"], "conflict")
                self.assertNotIn("planner_outcome", loom_brew)
                # Keep the formula blob bound to the tap snapshot without corroborating it.
                self.assertEqual(loom_brew["formula_blob_sha"], blobs["Formula/theme-forge-stellar-loom.rb"])
                # Gate status is fail
                self.assertEqual(result["gates"][1]["status"], "fail")
                self.assertEqual(result["gates"][1]["reason"], "identity-conflict-or-required-target-absent")

                # Diagnostic recorded
                diags = json.loads((scratch / "diagnostics/observe-destinations.json").read_bytes())
                conflict_diags = [d for d in diags if d.get("code") == "npm-readback-conflict"]
                self.assertEqual(len(conflict_diags), 1)
                self.assertEqual(conflict_diags[0]["product"], "theme-forge-stellar-loom")
                self.assertEqual(conflict_diags[0]["destination"], "homebrew")
                self.assertEqual(conflict_diags[0]["substage"], "npm-prerequisite")

    def test_failure_e_homebrew_command_and_hash_conflicts(self):
        """Formula hash conflict or command set mismatch causes closed Homebrew conflict."""
        # Case A: Formula hash mismatch
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            scratch = root / "scratch"
            scratch.mkdir()
            captures = self._create_real_captures(root, count=4, cli_supplemental_npm=False)

            formulas = {}
            blobs = {}
            for i, (cap, itn, prof) in enumerate(captures):
                p = itn["project"]["id"]
                facts = homebrew_generation_facts(cap, itn, prof, npm_projection=authenticated_npm_projection(cap, itn, prof), npm_state="exact")
                template = (Path(__file__).parent / "fixtures/homebrew/Formula" / (p + ".rb")).read_text()
                # Solar sail has wrong hash
                sha = "0" * 64 if p == "theme-forge-solar-sail" else facts["sha256"]
                content = re.sub(r"(?m)^  sha256 \"[0-9a-f]{64}\"$", lambda _: f"  sha256 \"{sha}\"", template).encode()
                rel_path = f"Formula/{p}.rb"
                formulas[rel_path] = content
                blobs[rel_path] = hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest()

            def mock_get(url, *args, **kwargs):
                for path, content in formulas.items():
                    if url.endswith(path):
                        return content
                raise ValueError(f"Unexpected raw GET URL: {url}")

            client = MagicMock()
            client.json.return_value = {"default_branch": "main", "sha": "c" * 40}

            with patch("rs9.hosted_observe.tap_snapshot", return_value=("main", "c" * 40, blobs)), \
                 patch("rs9.hosted_observe.read_pypi_project", return_value={"state": "absent"}), \
                 patch("rs9.hosted_observe.read_npm", return_value={"state": "exact"}), \
                 patch("rs9.hosted_observe.read_pages", return_value={"state": "absent"}), \
                 patch("rs9.readers._get", side_effect=mock_get):
                result = execute({"captures": captures, "scratch": scratch, "client": client})

            doc = json.loads((scratch / "destination-observations.json").read_bytes())
            sail_brew = [r for r in doc["observations"] if r["project"] == "theme-forge-solar-sail" and r["adapter"] == "homebrew"][0]
            self.assertEqual(sail_brew["observation"]["state"], "conflict")
            self.assertEqual(result["gates"][1]["status"], "fail")

        # Case B: Formula references unapproved command
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            scratch = root / "scratch"
            scratch.mkdir()
            captures = self._create_real_captures(root, count=4, cli_supplemental_npm=False)

            formulas = {}
            blobs = {}
            for cap, itn, prof in captures:
                p = itn["project"]["id"]
                facts = homebrew_generation_facts(cap, itn, prof, npm_projection=authenticated_npm_projection(cap, itn, prof), npm_state="exact")
                template = (Path(__file__).parent / "fixtures/homebrew/Formula" / (p + ".rb")).read_text()
                if p == "theme-forge-solar-sail":
                    template = template.replace('(bin/"tfss").write', '(bin/"unapproved-rogue-tool").write')
                content = re.sub(r"(?m)^  sha256 \"[0-9a-f]{64}\"$", lambda _: f"  sha256 \"{facts['sha256']}\"", template).encode()
                rel_path = f"Formula/{p}.rb"
                formulas[rel_path] = content
                blobs[rel_path] = hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest()

            def mock_get_b(url, *args, **kwargs):
                for path, content in formulas.items():
                    if url.endswith(path):
                        return content
                raise ValueError(f"Unexpected raw GET URL: {url}")

            client = MagicMock()
            client.json.return_value = {"default_branch": "main", "sha": "d" * 40}

            with patch("rs9.hosted_observe.tap_snapshot", return_value=("main", "d" * 40, blobs)), \
                 patch("rs9.hosted_observe.read_pypi_project", return_value={"state": "absent"}), \
                 patch("rs9.hosted_observe.read_npm", return_value={"state": "exact"}), \
                 patch("rs9.hosted_observe.read_pages", return_value={"state": "absent"}), \
                 patch("rs9.readers._get", side_effect=mock_get_b):
                result = execute({"captures": captures, "scratch": scratch, "client": client})

            doc = json.loads((scratch / "destination-observations.json").read_bytes())
            sail_brew = [r for r in doc["observations"] if r["project"] == "theme-forge-solar-sail" and r["adapter"] == "homebrew"][0]
            self.assertEqual(sail_brew["observation"]["state"], "conflict")
            self.assertEqual(result["gates"][1]["status"], "fail")

    def test_destination_observations_and_noops_exposed_when_pages_unknown(self):
        """Per-destination observations and 8 noops exposed independently when Pages is unknown, aggregate blocked."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            scratch = root / "scratch"
            scratch.mkdir()
            captures = self._create_real_captures(root, count=4)

            formulas = {}
            blobs = {}
            for cap, itn, prof in captures:
                p = itn["project"]["id"]
                facts = homebrew_generation_facts(cap, itn, prof, npm_projection=authenticated_npm_projection(cap, itn, prof), npm_state="exact")
                template = (Path(__file__).parent / "fixtures/homebrew/Formula" / (p + ".rb")).read_text()
                content = re.sub(r"(?m)^  sha256 \"[0-9a-f]{64}\"$", lambda _: f"  sha256 \"{facts['sha256']}\"", template).encode()
                rel_path = f"Formula/{p}.rb"
                formulas[rel_path] = content
                blobs[rel_path] = hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest()

            def mock_get(url, *args, **kwargs):
                for path, content in formulas.items():
                    if url.endswith(path):
                        return content
                raise ValueError(f"Unexpected raw GET URL: {url}")

            client = MagicMock()
            client.json.return_value = {"default_branch": "main", "sha": "e" * 40}

            pages_obs = {
                "state": "unknown",
                "diagnostics": [
                    {"code": "pages-tls-error", "message": "TLS verification failed: certificate-verify-failed"},
                    {"code": "pages-tls-certificate-verify-failed", "message": "TLS failure class certificate-verify-failed"},
                ],
            }

            with patch("rs9.hosted_observe.tap_snapshot", return_value=("main", "e" * 40, blobs)), \
                 patch("rs9.hosted_observe.read_pypi_project", return_value={"state": "absent"}), \
                 patch("rs9.hosted_observe.read_npm", return_value={"state": "exact"}), \
                 patch("rs9.hosted_observe.read_pages", return_value=pages_obs), \
                 patch("rs9.readers._get", side_effect=mock_get):
                result = execute({"captures": captures, "scratch": scratch, "client": client})

            # Gate 0 passes, but aggregate gate 1 remains blocked (not-run) because Pages is unknown
            self.assertEqual(result["gates"][0]["status"], "pass")
            self.assertEqual(result["gates"][1]["status"], "not-run")
            self.assertEqual(result["gates"][1]["reason"], "observations-recorded-with-unknown-or-metadata-only-states")

            details = result["details"]
            destinations = details["destinations"]

            # Pages destination is not satisfied
            self.assertFalse(destinations["pages"]["satisfied"])
            self.assertEqual(destinations["pages"]["states"]["generation"], "unknown")
            self.assertEqual(destinations["pages"]["planner_noops"], [])

            # npm destination is completely satisfied with 4 exact readbacks and planner noops
            self.assertTrue(destinations["npm"]["satisfied"])
            self.assertEqual(destinations["npm"]["exact_count"], 4)
            self.assertEqual(len(destinations["npm"]["planner_noops"]), 4)

            # Homebrew destination is completely satisfied with 4 exact readbacks and planner noops
            self.assertTrue(destinations["homebrew"]["satisfied"])
            self.assertEqual(destinations["homebrew"]["exact_count"], 4)
            self.assertEqual(len(destinations["homebrew"]["planner_noops"]), 4)

            # Total 8 npm/Homebrew planner noops preserved
            self.assertEqual(len(details["planner_noops"]), 8)
            self.assertEqual(len(details["exact_observations"]), 8)
            # 12 satisfied observations (4 pypi + 4 npm + 4 brew)
            self.assertEqual(len(details["satisfied_observations"]), 12)
