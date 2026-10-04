"""Destination observations cannot promote diagnostic metadata to exact readback.

Verifies real release_core record shape regression, tap-head failure handling,
platform selection, and fail-closed schema boundaries.
"""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError, URLError
import http.client

from rs9.errors import ContractError
from rs9.hosted_observe import execute, readback_satisfied, select_brew_payload
from rs9.profiles import selection_for_intent
from rs9.release_core import authenticate_release
from tests.release_fixtures import package_evidence


class HostedReadbackTests(unittest.TestCase):
    def test_nebular_homebrew_uses_native_release_despite_supplemental_npm(self):
        from types import SimpleNamespace
        from rs9.hosted_observe import homebrew_generation_facts
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            (root / "npm").mkdir()
            (root / "npm/metadata.json").write_text(json.dumps({"dist": {"tarball": "https://registry.npmjs.org/supplemental.tgz"}, "license": "AGPL-3.0-or-later OR Commercial"}))
            payload = {"id": "darwin", "name": "nebular.app.tar.gz", "platforms": ["aarch64-darwin"], "sha256": "b" * 64}
            capture = SimpleNamespace(root=root, normalized={"license": {"expression": "AGPL-3.0-or-later"}},
                record={"repository": {"full_name": "Knowledge-Forge-AI/theme-forge-nebular-fusion"},
                        "release": {"tag": "v0.6.1"}, "payloads": [payload]})
            facts = homebrew_generation_facts(capture, {"project": {"id": "theme-forge-nebular-fusion"}, "commands": [{"name": "tfnf", "interface": "gui"}]})
            self.assertEqual(facts["restrictions"], "aarch64-darwin")
            self.assertEqual(facts["license"], "AGPL-3.0-or-later")
            self.assertEqual(facts["sha256"], payload["sha256"])
            self.assertTrue(facts["url"].endswith("/v0.6.1/nebular.app.tar.gz"))
            self.assertEqual(set(facts["commands"]), {"tfnf"})

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
        # These reader and tap seams use synthetic profiles; fresh planner binding
        # is exercised separately with an authenticated profile/configuration.
        planner = patch("rs9.hosted_observe.reference_noop", return_value={"planner_outcome": "noop", "plan_sha256": "a" * 64})
        planner.start()
        self.addCleanup(planner.stop)
        original = __import__("rs9.hosted_observe", fromlist=["homebrew_generation_facts"]).homebrew_generation_facts
        def fixture_facts(capture, intent):
            if capture.record["repository"]["full_name"] != "Example/second-project":
                return original(capture, intent)
            if (capture.root / "npm/metadata.json").is_file():
                meta = json.loads((capture.root / "npm/metadata.json").read_bytes())
                from rs9.release_core import digest
                return {"url": meta["dist"]["tarball"], "sha256": digest((capture.root / "npm/package.tgz").read_bytes()),
                        "license": "MIT", "commands": meta["bin"], "restrictions": "node"}
            payload = select_brew_payload(capture)
            return {"url": f"https://github.com/{capture.record['repository']['full_name']}/releases/download/{capture.record['release']['tag']}/{payload['name']}",
                    "sha256": payload["sha256"], "license": "MIT", "commands": {"second": "bin/second"}, "restrictions": None}
        facts = patch("rs9.hosted_observe.homebrew_generation_facts", side_effect=fixture_facts)
        facts.start()
        self.addCleanup(facts.stop)

    def _create_real_captures(self, root, count=4, prefix="capture"):
        captures = []
        for i in range(count):
            c_root = root / f"{prefix}_{i}"
            c_root.mkdir(parents=True, exist_ok=True)
            intent = package_evidence(c_root)
            selection = selection_for_intent(intent)
            capture = authenticate_release(selection, c_root)
            captures.append((capture, intent, {}))
        return captures

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

            with patch("rs9.hosted_observe.tap_snapshot", return_value=("main", "c" * 40, {"Formula/second-project.rb": "b" * 40})), \
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
            expected_brew_url = "https://github.com/Example/second-project/releases/download/v0.6.1/second-0.6.1.tgz"
            for call in brew_mock.call_args_list:
                self.assertEqual(call.kwargs["expected_payload_url"], expected_brew_url)
                self.assertEqual(call.kwargs["pinned_ref"], "c" * 40)

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

    def test_multiple_payloads_without_npm_identity_remain_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            scratch = root / "scratch"
            scratch.mkdir()
            captures = self._create_real_captures(root)
            for capture, _, _ in captures:
                capture.record["payloads"].append({"id": "foreign", "platforms": ["x86_64-linux"]})
            client = MagicMock()
            client.json.return_value = None
            with patch("rs9.hosted_observe.read_pypi_project", return_value={"state": "absent"}), \
                 patch("rs9.hosted_observe.read_pages", return_value={"state": "absent"}), \
                 patch("rs9.hosted_observe.read_npm") as npm:
                execute({"captures": captures, "scratch": scratch, "client": client})
            npm.assert_not_called()
            rows = json.loads((scratch / "destination-observations.json").read_bytes())["observations"]
            self.assertTrue(all(r["observation"] == {"state": "unknown", "reason": "npm-identity-unavailable"}
                                for r in rows if r["adapter"] == "npm"))

    def test_missing_homebrew_platform_payload_records_conflict_and_finishes_observations(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            scratch = root / "scratch"
            scratch.mkdir()
            captures = self._create_real_captures(root)
            for capture, _, _ in captures:
                for payload in capture.record["payloads"]:
                    payload["platforms"] = ["x86_64-linux"]
            with patch("rs9.hosted_observe.tap_snapshot", return_value=("main", "e" * 40, {"Formula/second-project.rb": "d" * 40})), \
                 patch("rs9.hosted_observe.read_pypi_project", return_value={"state": "absent"}), \
                 patch("rs9.hosted_observe.read_npm", return_value={"state": "unknown"}), \
                 patch("rs9.hosted_observe.read_pages", return_value={"state": "absent"}), \
                 patch("rs9.hosted_observe.read_homebrew") as brew:
                result = execute({"captures": captures, "scratch": scratch, "client": MagicMock()})
            brew.assert_not_called()
            rows = json.loads((scratch / "destination-observations.json").read_bytes())["observations"]
            self.assertEqual(len(rows), 13)
            self.assertTrue(all(r["observation"] == {"state": "conflict", "reason": "payload-unavailable"}
                                for r in rows if r["adapter"] == "homebrew"))
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
        """End-to-end exact Homebrew and npm readback using real formula fixtures."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            scratch = root / "scratch"
            scratch.mkdir()
            captures = self._create_real_captures(root, count=4)

            # Match first capture to second-project
            capture = captures[0][0]
            payload = capture.record["payloads"][0]
            url = f"https://github.com/{capture.record['repository']['full_name']}/releases/download/v0.6.1/{payload['name']}"

            npm_dir = capture.root / "npm"
            npm_dir.mkdir(exist_ok=True)
            (npm_dir / "metadata.json").write_text(json.dumps({"dist": {"tarball": url}, "license": "MIT", "bin": {"second": "bin/second"}}))
            (npm_dir / "package.tgz").write_bytes(capture.archives[payload["id"]].read_bytes())

            valid_formula = (
                f'class SecondProject < Formula\n'
                f'  desc "Second project CLI"\n'
                f'  homepage "https://github.com/Example/second-project"\n'
                f'  url "{url}"\n'
                f'  sha256 "{payload["sha256"]}"\n'
                f'  license "MIT"\n'
                f'  depends_on "node"\n'
                f'  def install\n'
                f'    bin.install "second"\n'
                f'  end\n'
                f'  test do\n'
                f'    assert_match "version", shell_output("#{{bin}}/second --version")\n'
                f'  end\n'
                f'end\n'
            ).encode()

            client = MagicMock()
            client.json.return_value = {"default_branch": "main", "sha": "e" * 40}

            with patch("rs9.hosted_observe.tap_snapshot", return_value=("main", "e" * 40, {"Formula/second-project.rb": __import__("hashlib").sha1(b"blob " + str(len(valid_formula)).encode() + b"\0" + valid_formula).hexdigest()})), \
                 patch("rs9.hosted_observe.read_pypi_project", return_value={"state": "absent"}), \
                 patch("rs9.hosted_observe.read_npm", return_value={"state": "exact"}), \
                 patch("rs9.hosted_observe.read_pages", return_value={"state": "absent"}), \
                 patch("rs9.readers._get", return_value=valid_formula):
                result = execute({"captures": captures, "scratch": scratch, "client": client})

            doc = json.loads((scratch / "destination-observations.json").read_bytes())
            first_brew = [r for r in doc["observations"] if r["adapter"] == "homebrew"][0]
            self.assertEqual(first_brew["observation"]["state"], "exact")
            self.assertEqual(first_brew["planner_outcome"], "noop")

    def test_homebrew_identity_mismatch_yields_conflict(self):
        """Mismatched license or class name in a complete formula yields conflict."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            scratch = root / "scratch"
            scratch.mkdir()
            captures = self._create_real_captures(root, count=4)

            capture = captures[0][0]
            payload = capture.record["payloads"][0]
            url = f"https://github.com/{capture.record['repository']['full_name']}/releases/download/v0.6.1/{payload['name']}"

            # Mismatched license (GPL-3.0 instead of MIT)
            conflict_formula = (
                f'class SecondProject < Formula\n'
                f'  desc "Second project CLI"\n'
                f'  url "{url}"\n'
                f'  sha256 "{payload["sha256"]}"\n'
                f'  license "GPL-3.0-only"\n'
                f'end\n'
            ).encode()

            client = MagicMock()
            client.json.return_value = {"sha": "e" * 40}

            with patch("rs9.hosted_observe.tap_snapshot", return_value=("main", "e" * 40, {"Formula/second-project.rb": "b" * 40})), \
                 patch("rs9.hosted_observe.read_pypi_project", return_value={"state": "absent"}), \
                 patch("rs9.hosted_observe.read_npm", return_value={"state": "exact"}), \
                 patch("rs9.hosted_observe.read_pages", return_value={"state": "absent"}), \
                 patch("rs9.readers._get", return_value=conflict_formula):
                result = execute({"captures": captures, "scratch": scratch, "client": client})

            doc = json.loads((scratch / "destination-observations.json").read_bytes())
            first_brew = [r for r in doc["observations"] if r["adapter"] == "homebrew"][0]
            self.assertEqual(first_brew["observation"]["state"], "conflict")
            self.assertNotIn("planner_outcome", first_brew)
            self.assertEqual(result["gates"][1]["status"], "fail")
