"""Exact npm corroboration and hosted diagnostic custody, entirely offline."""
import base64
import copy
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from rs9.errors import ContractError
from rs9.fetch import fetch
from rs9.hosted_custody import verify_set
from rs9.hosted_pipeline import run_lane
from rs9.profiles import (_npm_packument_url, _npm_tarball_url, capture_supplemental,
                          evaluate_profile, selection_for_intent)
from rs9.release_core import authenticate_release
from rs9.scratch import canonical
from tests.shadow_fixtures import fixture_evidence
from tests.test_fetch import FixtureClient
from tests.test_npm_transport import TOKEN, transport

ROOT = Path(__file__).resolve().parents[1]
NAME = "@knowledge-forge-ai/theme-forge-nebular-fusion"
PACKUMENT = "https://registry.npmjs.org/@knowledge-forge-ai%2Ftheme-forge-nebular-fusion"
TARBALL = "https://registry.npmjs.org/@knowledge-forge-ai/theme-forge-nebular-fusion/-/theme-forge-nebular-fusion-0.6.1.tgz"


class NpmSupplementalTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.source = self.root / "source"
        self.source.mkdir()
        self.intent = fixture_evidence(self.source)
        self.body = (self.source / "npm/package.tgz").read_bytes()
        self.metadata = json.loads((self.source / "npm/metadata.json").read_bytes())
        self.metadata["dist"]["tarball"] = TARBALL
        self.packument = {"name": NAME, "dist-tags": {"latest": "99.0.0"},
                          "versions": {"0.6.1": self.metadata}}
        self.output = self.root / "output"
        self.output.mkdir()
        shutil.copytree(self.source / "source", self.output / "source")

    def client(self, *, packument=None, tarball=None, metadata_status=200, tarball_status=200):
        data = canonical(self.packument if packument is None else packument)
        return transport({PACKUMENT: (metadata_status, data),
                          TARBALL: (tarball_status, self.body if tarball is None else tarball)})

    def test_scoped_registry_path_is_literal_at_and_uppercase_slash(self):
        self.assertEqual(_npm_packument_url(NAME), PACKUMENT)
        self.assertEqual(_npm_tarball_url(NAME, "0.6.1"), TARBALL)
        for name in ("..", "@a/b/c", "name?x", "name#x", "a\\b", "@a%2fb", "UPPER", "a\n", "a\x7f",
                     "@evil.com@x", "https://evil.example/a", "@a/b?auth=x"):
            with self.subTest(name=name), self.assertRaises(ContractError):
                _npm_packument_url(name)
        for version in ("latest", "^0.6.1", "0.6", "0.6.1/a", "0.6.1?x", "0.6.1#x", "0.6.1%2f", "0.6.1\n", "00.6.1", "0.6.1-01"):
            with self.subTest(version=version), self.assertRaises(ContractError):
                _npm_tarball_url(NAME, version)

    def test_exact_selection_ignores_latest_and_uses_correct_headers(self):
        client, handler = self.client()
        receipt = {}
        capture_supplemental(self.intent, self.output, client, corroboration=receipt, core_authenticated=True)
        self.assertEqual(json.loads((self.output / "npm/metadata.json").read_bytes()), self.metadata)
        self.assertEqual([r.full_url for r in handler.requests], [PACKUMENT, TARBALL])
        self.assertEqual([r.get_header("Accept") for r in handler.requests], ["application/json", "*/*"])
        self.assertTrue(all(r.get_header("Authorization") is None for r in handler.requests))
        self.assertEqual(receipt["npm_corroboration"], "pending")
        self.assertEqual(receipt["release_authentication"], "core-authenticated")
        self.assertEqual(receipt["packument"]["selected_version"], "0.6.1")
        self.assertNotIn(TOKEN, (self.output / "npm/profile-fetch-receipt.json").read_text())

    def test_missing_exact_version_has_no_latest_fallback_or_tarball_request(self):
        self.packument["versions"] = {"99.0.0": self.metadata}
        client, handler = self.client()
        with self.assertRaises(ContractError) as caught:
            capture_supplemental(self.intent, self.output, client)
        self.assertEqual(caught.exception.code, "NPM_IDENTITY")
        self.assertEqual(len(handler.requests), 1)

    def test_build_metadata_cannot_silently_normalize_tarball_identity(self):
        self.intent["version"] = "0.6.1+build"
        metadata = copy.deepcopy(self.metadata)
        metadata["version"] = self.intent["version"]
        client, handler = self.client(packument={"name": NAME, "versions": {self.intent["version"]: metadata}})
        with self.assertRaises(ContractError) as caught:
            capture_supplemental(self.intent, self.output, client)
        self.assertEqual(caught.exception.code, "NPM_IDENTITY")
        self.assertEqual(caught.exception.details["reason"], "npm-dist")
        self.assertEqual(len(handler.requests), 1)

    def test_malformed_packument_version_and_dist_fail_closed(self):
        values = [[], {}, {"name": "wrong", "versions": {}}, {"name": NAME, "versions": []}]
        for item in (None, [], {}, {"name": NAME, "version": "0.6.2", "dist": {}},
                     {"name": "wrong", "version": "0.6.1", "dist": {}},
                     {"name": NAME, "version": "0.6.1", "dist": []}):
            values.append({"name": NAME, "versions": {"0.6.1": item}})
        for dist in ({}, {"tarball": TARBALL}, {"integrity": self.metadata["dist"]["integrity"]},
                     {"tarball": [], "integrity": "sha512-bad"},
                     {"tarball": TARBALL, "integrity": "sha256-YQ=="},
                     {"tarball": TARBALL, "integrity": "sha512-YQ=="},
                     {"tarball": TARBALL, "integrity": "sha512-!!!!"}):
            item = copy.deepcopy(self.metadata)
            item["dist"] = dist
            values.append({"name": NAME, "versions": {"0.6.1": item}})
        for i, value in enumerate(values):
            with self.subTest(i=i):
                output = self.root / ("malformed-" + str(i))
                output.mkdir()
                shutil.copytree(self.source / "source", output / "source")
                client, handler = self.client(packument=value)
                with self.assertRaises(ContractError) as caught:
                    capture_supplemental(self.intent, output, client)
                self.assertEqual(caught.exception.code, "NPM_IDENTITY")
                self.assertEqual(len(handler.requests), 1)
                receipt = json.loads((output / "npm/profile-fetch-receipt.json").read_bytes())
                self.assertEqual(receipt["npm_corroboration"], "fail")

    def test_non_json_metadata_has_stable_operation_diagnostic(self):
        client, _ = transport({PACKUMENT: (200, b"not JSON " + TOKEN.encode())})
        with self.assertRaises(ContractError) as caught:
            capture_supplemental(self.intent, self.output, client)
        self.assertEqual(caught.exception.code, "INVALID_EVIDENCE")
        self.assertEqual(caught.exception.details["operation"], "npm-packument")
        self.assertNotIn(TOKEN, str(caught.exception) + json.dumps(caught.exception.details))

    def test_tarball_host_credentials_query_fragment_and_alternate_path_are_rejected(self):
        for i, url in enumerate(("https://evil.example/package.tgz", "https://github.com/package.tgz",
                                 "https://registry.npmjs.org.evil.example/package.tgz", "http://registry.npmjs.org/package.tgz",
                                 "https://user:pass@registry.npmjs.org/package.tgz", TARBALL + "?x=1", TARBALL + "#x",
                                 "https://registry.npmjs.org/alternate.tgz", TARBALL.replace("https://", "https://" + TOKEN + "@"))):
            with self.subTest(i=i):
                output = self.root / ("escape-" + str(i))
                output.mkdir()
                shutil.copytree(self.source / "source", output / "source")
                metadata = copy.deepcopy(self.metadata)
                metadata["dist"]["tarball"] = url
                client, handler = self.client(packument={"name": NAME, "versions": {"0.6.1": metadata}})
                with self.assertRaises(ContractError) as caught:
                    capture_supplemental(self.intent, output, client)
                self.assertEqual(caught.exception.code, "NPM_IDENTITY")
                self.assertEqual(len(handler.requests), 1)
                self.assertNotIn(TOKEN, (output / "npm/profile-fetch-receipt.json").read_text())

    def test_fetch_to_authenticated_profile_preserves_github_authority(self):
        output = self.root / "fetched"
        output.mkdir()
        fetch(self.intent, output, client=FixtureClient(self.source, self.intent))
        capture = authenticate_release(selection_for_intent(self.intent), output)
        receipt = {}
        result = evaluate_profile(capture, self.intent["release"]["evidence"]["profile"], self.intent, corroboration=receipt)
        self.assertTrue(result["sections"]["legacy_ingestion"]["npm_support"]["integrity_agrees"])
        self.assertEqual(receipt["npm_corroboration"], "pass")
        self.assertEqual(receipt["wrapper_bytes"], "pass")
        self.assertEqual(receipt["integrity"], "pass")
        self.assertEqual(receipt["release_wrapper"]["sha256"], hashlib.sha256(self.body).hexdigest())

    def test_wrapper_byte_mismatch_fails_closed(self):
        capture = authenticate_release(selection_for_intent(self.intent), self.source)
        (self.source / "npm/package.tgz").write_bytes(b"different")
        receipt = {}
        with self.assertRaises(ContractError) as caught:
            evaluate_profile(capture, self.intent["release"]["evidence"]["profile"], self.intent, corroboration=receipt)
        self.assertEqual(caught.exception.code, "NPM_RELEASE_MISMATCH")
        self.assertEqual(receipt["npm_corroboration"], "fail")
        self.assertEqual(receipt["wrapper_bytes"], "fail")
        self.assertEqual(receipt["error"], "NPM_RELEASE_MISMATCH")

    def test_independent_sri_mismatch_fails_closed_after_wrapper_equality(self):
        capture = authenticate_release(selection_for_intent(self.intent), self.source)
        self.metadata["dist"]["integrity"] = "sha512-" + base64.b64encode(hashlib.sha512(b"wrong").digest()).decode()
        (self.source / "npm/metadata.json").write_bytes(canonical(self.metadata))
        receipt = {}
        with self.assertRaises(ContractError) as caught:
            evaluate_profile(capture, self.intent["release"]["evidence"]["profile"], self.intent, corroboration=receipt)
        self.assertEqual(caught.exception.code, "NPM_INTEGRITY")
        self.assertEqual(receipt["wrapper_bytes"], "pass")
        self.assertEqual(receipt["integrity"], "fail")
        self.assertEqual(receipt["npm_corroboration"], "fail")

    def hosted(self, client, suffix):
        scratch, out = self.root / ("work-" + suffix), self.root / ("out-" + suffix)
        scratch.mkdir()
        def copy_capture(selection, target, **kwargs):
            for folder in ("api", "source", "assets"):
                shutil.copytree(self.source / folder, target / folder)
        rows = [({"repository": self.intent["project"]["repository"]}, self.intent)]
        with patch("rs9.candidate.configuration_rows", return_value=rows), \
             patch("rs9.candidate.capture_release", side_effect=copy_capture), \
             patch("rs9.candidate.assert_release_expectations"), \
             patch("rs9.candidate.load_bootstrap", return_value=self.intent), \
             patch("rs9.candidate.require_configuration_authority"), \
             patch("rs9.hosted_pipeline.runner_facts", return_value={}):
            code = run_lane(ROOT, scratch, out, "authenticate", "generation", client=client)
        verify_set(out)
        return code, json.loads((out / "authenticate-generation.json").read_bytes()), scratch, out

    def rebind_evidence(self, name, value):
        data = canonical(value)
        sums = (self.source / "assets/SHA256SUMS").read_text()
        digest = hashlib.sha256(data).hexdigest()
        lines = [digest + "  " + name if line.endswith("  " + name) else line for line in sums.splitlines()]
        updates = {name: data, "SHA256SUMS": ("\n".join(lines) + "\n").encode()}
        release = json.loads((self.source / "api/release.json").read_bytes())
        for asset in release["assets"]:
            if asset["name"] in updates:
                body = updates[asset["name"]]
                (self.source / "assets" / asset["name"]).write_bytes(body)
                asset.update(size=len(body), digest="sha256:" + hashlib.sha256(body).hexdigest())
        (self.source / "api/release.json").write_bytes(canonical(release))

    def test_hosted_provenance_failure_blocks_unreached_npm_comparison(self):
        self.rebind_evidence("PROVENANCE.json", {"release": {"tagTarget": "c" * 40}})
        client, _ = self.client()
        code, receipt, scratch, out = self.hosted(client, "provenance")
        self.assertEqual(code, 2)
        self.assertEqual(receipt["execution_error"], "PROVENANCE_MISMATCH")
        self.assertEqual(receipt["execution_error_detail"]["stage"], "profile")
        corroboration = receipt["npm_corroboration"][0]
        self.assertEqual(corroboration["release_authentication"], "core-authenticated")
        self.assertEqual(corroboration["packument"]["status"], "pass")
        self.assertEqual(corroboration["tarball"]["status"], "pass")
        self.assertEqual(corroboration["npm_corroboration"], "blocked")
        self.assertEqual(corroboration["wrapper_bytes"], "pending")
        self.assertEqual(corroboration["integrity"], "pending")
        self.assertFalse((scratch / "capture/summary/authentication.json").exists())
        self.assertNotIn(TOKEN, "".join(p.read_text() for p in out.rglob("*.json")))

    def test_hosted_later_profile_failure_preserves_completed_npm_comparison(self):
        self.rebind_evidence("nebular.spdx.json", {"packages": None})
        client, _ = self.client()
        code, receipt, scratch, out = self.hosted(client, "sbom")
        self.assertEqual(code, 2)
        self.assertEqual(receipt["execution_error"], "INVALID_EVIDENCE")
        corroboration = receipt["npm_corroboration"][0]
        self.assertEqual(corroboration["npm_corroboration"], "pass")
        self.assertEqual(corroboration["wrapper_bytes"], "pass")
        self.assertEqual(corroboration["integrity"], "pass")
        self.assertFalse((scratch / "capture/summary/authentication.json").exists())
        self.assertNotIn(TOKEN, "".join(p.read_text() for p in out.rglob("*.json")))

    def test_hosted_metadata_http_failure_retains_exact_safe_details_and_core_authentication_state(self):
        for status in (404, 406):
            client, _ = self.client(metadata_status=status)
            code, receipt, scratch, out = self.hosted(client, str(status))
            self.assertEqual(code, 2)
            self.assertEqual(receipt["execution_error"], "FETCH_FAILED")
            self.assertEqual(receipt["execution_error_detail"], {"stage": "supplemental", "project": self.intent["project"]["id"],
                "operation": "npm-packument", "host": "registry.npmjs.org", "http_status": status,
                "reason": "http-status", "redirect_hops": 0})
            corroboration = receipt["npm_corroboration"][0]
            self.assertEqual(corroboration["release_authentication"], "core-authenticated")
            self.assertEqual(corroboration["npm_corroboration"], "fail")
            self.assertEqual(corroboration["tarball"]["status"], "pending")
            self.assertFalse((scratch / "capture/summary/authentication.json").exists())
            self.assertNotIn(TOKEN, "".join(p.read_text() for p in out.rglob("*.json")))

    def test_hosted_tarball_failure_is_distinct_from_metadata_failure(self):
        client, _ = self.client(tarball_status=503)
        code, receipt, scratch, _ = self.hosted(client, "tarball")
        self.assertEqual(code, 2)
        self.assertEqual(receipt["execution_error_detail"]["operation"], "npm-tarball")
        self.assertEqual(receipt["execution_error_detail"]["http_status"], 503)
        corroboration = receipt["npm_corroboration"][0]
        self.assertEqual(corroboration["packument"]["status"], "pass")
        self.assertEqual(corroboration["tarball"]["status"], "fail")
        self.assertFalse((scratch / "capture/summary/authentication.json").exists())

    def test_hosted_wrapper_integrity_and_success_outcomes_are_retained(self):
        for case in ("wrapper", "integrity", "success"):
            with self.subTest(case=case):
                metadata = copy.deepcopy(self.metadata)
                if case == "integrity":
                    metadata["dist"]["integrity"] = "sha512-" + base64.b64encode(hashlib.sha512(b"wrong").digest()).decode()
                client, _ = self.client(packument={"name": NAME, "versions": {"0.6.1": metadata}},
                                        tarball=b"different" if case == "wrapper" else None)
                code, receipt, scratch, out = self.hosted(client, case)
                corroboration = receipt["npm_corroboration"][0]
                self.assertEqual(code, 0 if case == "success" else 2)
                self.assertEqual(corroboration["npm_corroboration"], "pass" if case == "success" else "fail")
                self.assertEqual(corroboration["wrapper_bytes"], "fail" if case == "wrapper" else "pass")
                self.assertEqual(corroboration["integrity"], "pending" if case == "wrapper" else "fail" if case == "integrity" else "pass")
                self.assertEqual(receipt["execution_error"], {"wrapper": "NPM_RELEASE_MISMATCH", "integrity": "NPM_INTEGRITY", "success": None}[case])
                self.assertEqual((scratch / "capture/summary/authentication.json").exists(), case == "success")
                self.assertNotIn(TOKEN, "".join(p.read_text() for p in out.rglob("*.json")))
                self.assertFalse(receipt["publication_authority"])
