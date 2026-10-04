"""Comprehensive unit tests for candidate readers and live observation boundaries."""
import copy
import hashlib
import http.client
import json
from pathlib import Path
import socket
import ssl
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError

from rs9.errors import ContractError
from rs9.readers import (
    READERS,
    LiveObservation,
    has_live_proof,
    read_github,
    read_homebrew,
    read_npm,
    read_pages,
    read_pypi,
    read_pypi_project,
    read_signed_repo,
)
from rs9.scratch import canonical
from tests.publication_fixtures import fixture


class CandidateReadersTests(unittest.TestCase):
    def setUp(self):
        self.pypi_dest = {"id": "pypi", "adapter": "pypi", "mode": "direct"}
        self.pypi_subj = {"package": "theme-forge-stellar-loom", "version": "0.4.0", "revision": None}
        self.npm_dest = {"id": "npm", "adapter": "npm", "mode": "direct"}
        self.npm_subj = {"package": "@knowledge-forge-ai/theme-forge-stellar-loom", "version": "0.4.0", "revision": None}
        self.brew_dest = {"id": "homebrew", "adapter": "homebrew", "mode": "projection"}
        self.brew_subj = {"package": "theme-forge-stellar-loom", "version": "0.4.0", "revision": None}
        self.pages_dest = {"id": "pages", "adapter": "pages", "mode": "direct"}
        self.pages_subj = {"package": "theme-forge-stellar-loom", "version": "0.4.0", "revision": None}

    # ------------------------------------------------------------------
    # PyPI Project-Level Reader Tests
    # ------------------------------------------------------------------
    def test_pypi_project_called_without_artifacts(self):
        # Can be called with (dest, subj)
        url = "https://pypi.org/pypi/theme-forge-stellar-loom/json"
        with patch("rs9.readers._get", side_effect=HTTPError(url, 404, "Not Found", {}, None)):
            obs = read_pypi_project(self.pypi_dest, self.pypi_subj)
        self.assertEqual(obs["state"], "absent")
        self.assertTrue(has_live_proof(obs))

        # Can be called with package name string
        with patch("rs9.readers._get", side_effect=HTTPError(url, 404, "Not Found", {}, None)):
            obs_str = read_pypi_project("theme-forge-stellar-loom")
        self.assertEqual(obs_str["state"], "absent")
        self.assertTrue(has_live_proof(obs_str))

    def test_pypi_project_exact_404_yields_absent(self):
        url = "https://pypi.org/pypi/theme-forge-stellar-loom/json"
        with patch("rs9.readers._get", side_effect=HTTPError(url, 404, "Not Found", {}, None)):
            obs = read_pypi_project(self.pypi_dest, self.pypi_subj)
        self.assertEqual(obs["state"], "absent")
        self.assertEqual(obs["readback"]["presence"], "absent")
        self.assertTrue(has_live_proof(obs))

    def test_pypi_project_mismatched_url_404_stays_unknown(self):
        with patch("rs9.readers._get", side_effect=HTTPError("https://pypi.org/other", 404, "Not Found", {}, None)):
            obs = read_pypi_project(self.pypi_dest, self.pypi_subj)
        self.assertEqual(obs["state"], "unknown")
        self.assertTrue(has_live_proof(obs))

    def test_pypi_project_exact_match(self):
        whl_name = "theme_forge_stellar_loom-0.4.0-py3-none-any.whl"
        whl_sha = "a" * 64
        meta = {
            "info": {"name": "theme-forge-stellar-loom", "version": "0.4.0"},
            "last_serial": 42,
            "releases": {
                "0.4.0": [
                    {"filename": whl_name, "digests": {"sha256": whl_sha}}
                ]
            }
        }
        with patch("rs9.readers._get", return_value=canonical(meta)):
            obs = read_pypi_project(
                self.pypi_dest, self.pypi_subj,
                desired_identity="b" * 64,
                expected_hashes={whl_name: whl_sha}
            )
        self.assertEqual(obs["state"], "unknown")
        self.assertEqual(obs["remote"]["sequence"], 42)
        self.assertTrue(has_live_proof(obs))

    def test_pypi_project_conflict_ownership_unattested_when_files_differ(self):
        whl_name = "theme_forge_stellar_loom-0.4.0-py3-none-any.whl"
        meta = {
            "info": {"name": "theme-forge-stellar-loom", "version": "0.4.0"},
            "last_serial": 10,
            "releases": {
                "0.4.0": [
                    {"filename": whl_name, "digests": {"sha256": "c" * 64}}
                ]
            }
        }
        with patch("rs9.readers._get", return_value=canonical(meta)):
            obs = read_pypi_project(
                self.pypi_dest, self.pypi_subj,
                desired_identity="b" * 64,
                expected_hashes={whl_name: "a" * 64}
            )
        self.assertEqual(obs["state"], "conflict")
        diag_codes = [d["code"] for d in obs["diagnostics"]]
        self.assertIn("conflict-ownership-unattested", diag_codes)
        self.assertTrue(has_live_proof(obs))

    def test_pypi_project_conflict_ownership_unattested_when_version_missing(self):
        meta = {
            "info": {"name": "theme-forge-stellar-loom", "version": "0.3.0"},
            "last_serial": 5,
            "releases": {
                "0.3.0": [{"filename": "old.whl", "digests": {"sha256": "9" * 64}}]
            }
        }
        with patch("rs9.readers._get", return_value=canonical(meta)):
            obs = read_pypi_project(self.pypi_dest, self.pypi_subj, desired_identity="b" * 64)
        self.assertEqual(obs["state"], "conflict")
        diag_codes = [d["code"] for d in obs["diagnostics"]]
        self.assertIn("conflict-ownership-unattested", diag_codes)
        self.assertTrue(has_live_proof(obs))
        self.assertIsNone(obs["readback"]["content_identity_sha256"])
        self.assertEqual(obs["readback"]["level"], "metadata")
        self.assertEqual(obs["readback"]["components"], {
            "_pypi_project_metadata": hashlib.sha256(canonical(meta)).hexdigest()})

    def test_pypi_duplicate_registry_rows_are_unknown(self):
        row = {"filename": "fixture.whl", "digests": {"sha256": "a" * 64}}
        metadata = {"info": {"name": "theme-forge-stellar-loom"},
                    "releases": {"0.4.0": [row, row]}}
        with patch("rs9.readers._get", return_value=canonical(metadata)):
            observation = read_pypi_project(self.pypi_dest, self.pypi_subj)
        self.assertEqual(observation["state"], "unknown")

    def test_pypi_project_transport_and_rate_limit_fail_closed(self):
        for exc in (
            URLError("network down"),
            HTTPError("https://pypi.org/pypi/theme-forge-stellar-loom/json", 429, "Too Many Requests", {}, None),
            HTTPError("https://pypi.org/pypi/theme-forge-stellar-loom/json", 503, "Service Unavailable", {}, None),
            http.client.HTTPException("protocol error"),
            http.client.RemoteDisconnected("remote disconnected"),
            ContractError("READER_REDIRECT", "Redirect rejected"),
        ):
            with patch("rs9.readers._get", side_effect=exc):
                obs = read_pypi_project(self.pypi_dest, self.pypi_subj)
            self.assertEqual(obs["state"], "unknown")
            self.assertTrue(has_live_proof(obs))

    # ------------------------------------------------------------------
    # npm Reader Tests
    # ------------------------------------------------------------------
    def test_npm_observe_only_destination_required(self):
        bad_dest = {"id": "npm", "adapter": "pypi", "mode": "direct"}
        with self.assertRaises(ContractError) as ctx:
            read_npm(bad_dest, self.npm_subj)
        self.assertEqual(ctx.exception.code, "READER_DESTINATION")

    def test_npm_exact_404_yields_absent(self):
        url = "https://registry.npmjs.org/@knowledge-forge-ai%2Ftheme-forge-stellar-loom"
        with patch("rs9.readers._get", side_effect=HTTPError(url, 404, "Not Found", {}, None)):
            obs = read_npm(self.npm_dest, self.npm_subj)
        self.assertEqual(obs["state"], "absent")
        self.assertEqual(obs["readback"]["presence"], "absent")
        self.assertTrue(has_live_proof(obs))

    def test_npm_version_missing_yields_absent(self):
        doc = {
            "name": "@knowledge-forge-ai/theme-forge-stellar-loom",
            "versions": {
                "0.3.0": {
                    "dist": {"integrity": "sha512-" + "A" * 86 + "=="},
                    "license": "AGPL-3.0-or-later"
                }
            }
        }
        with patch("rs9.readers._get", return_value=canonical(doc)):
            obs = read_npm(self.npm_dest, self.npm_subj)
        self.assertEqual(obs["state"], "absent")
        self.assertTrue(has_live_proof(obs))

    def test_npm_metadata_returned_as_tarball_is_conflict(self):
        integrity = "sha512-" + "B" * 86 + "=="
        doc = {
            "name": "@knowledge-forge-ai/theme-forge-stellar-loom",
            "versions": {
                "0.4.0": {
                    "name": "@knowledge-forge-ai/theme-forge-stellar-loom",
                    "version": "0.4.0",
                    "dist": {
                        "integrity": integrity,
                        "tarball": "https://registry.npmjs.org/@knowledge-forge-ai/theme-forge-stellar-loom/-/theme-forge-stellar-loom-0.4.0.tgz"
                    },
                    "license": "AGPL-3.0-or-later",
                    "bin": {"tfsl": "bin/tfsl.js"}
                }
            }
        }
        with patch("rs9.readers._get", return_value=canonical(doc)):
            obs = read_npm(
                self.npm_dest, self.npm_subj,
                desired_identity="b" * 64,
                expected_integrity=integrity,
                expected_license="AGPL-3.0-or-later",
                expected_commands={"tfsl": "bin/tfsl.js"}
            )
        self.assertEqual(obs["state"], "conflict")
        self.assertTrue(has_live_proof(obs))

    def test_npm_conflict_on_integrity_or_license_or_commands(self):
        doc = {
            "name": "@knowledge-forge-ai/theme-forge-stellar-loom",
            "versions": {
                "0.4.0": {
                    "name": "@knowledge-forge-ai/theme-forge-stellar-loom",
                    "version": "0.4.0",
                    "dist": {"integrity": "sha512-" + "C" * 86 + "=="},
                    "license": "MIT",
                    "bin": {"wrong": "bin/wrong.js"}
                }
            }
        }
        with patch("rs9.readers._get", return_value=canonical(doc)):
            # Integrity conflict
            obs1 = read_npm(self.npm_dest, self.npm_subj, desired_identity="b" * 64,
                            expected_integrity="sha512-" + "D" * 86 + "==")
            self.assertEqual(obs1["state"], "conflict")
            self.assertIn("npm-conflict", [d["code"] for d in obs1["diagnostics"]])

            # License conflict
            obs2 = read_npm(self.npm_dest, self.npm_subj, desired_identity="b" * 64,
                            expected_license="AGPL-3.0-or-later")
            self.assertEqual(obs2["state"], "conflict")

            # Commands conflict
            obs3 = read_npm(self.npm_dest, self.npm_subj, desired_identity="b" * 64,
                            expected_commands={"tfsl": "bin/tfsl.js"})
            self.assertEqual(obs3["state"], "conflict")

    def test_npm_transport_rate_redirect_fail_closed(self):
        for exc in (
            URLError("connect timeout"),
            HTTPError("https://registry.npmjs.org/pkg", 429, "Rate limited", {}, None),
            HTTPError("https://registry.npmjs.org/pkg", 500, "Server Error", {}, None),
            http.client.HTTPException("protocol error"),
            ContractError("READER_REDIRECT", "No redirect"),
        ):
            with patch("rs9.readers._get", side_effect=exc):
                obs = read_npm(self.npm_dest, self.npm_subj)
            self.assertEqual(obs["state"], "unknown")
            self.assertTrue(has_live_proof(obs))

    def test_npm_same_command_name_with_changed_target_is_conflict(self):
        metadata = {"name": self.npm_subj["package"], "versions": {self.npm_subj["version"]: {
            "dist": {"integrity": "sha512-" + "C" * 86 + "==",
                     "tarball": "https://registry.npmjs.org/pkg/-/pkg.tgz"},
            "license": "MIT", "bin": {"tfsl": "bin/changed.js"}}}}
        with patch("rs9.readers._get", return_value=canonical(metadata)) as fetch:
            obs = read_npm(self.npm_dest, self.npm_subj, desired_identity="b" * 64,
                           expected_hashes={"pkg.tgz": "a" * 64}, expected_license="MIT",
                           expected_commands={"tfsl": "bin/tfsl.js"})
        self.assertEqual(obs["state"], "conflict")
        self.assertTrue(has_live_proof(obs))
        self.assertEqual(fetch.call_count, 1)
        self.assertIn("npm-conflict", [row["code"] for row in obs["diagnostics"]])

    def test_npm_received_tarball_integrity_drift_is_conflict(self):
        payload = b"payload differs from the declared integrity"
        metadata = {"name": self.npm_subj["package"], "versions": {self.npm_subj["version"]: {
            "dist": {"integrity": "sha512-" + "C" * 86 + "==",
                     "tarball": "https://registry.npmjs.org/pkg/-/pkg.tgz"},
            "license": "MIT", "bin": {"tfsl": "bin/tfsl.js"}}}}
        with patch("rs9.readers._get", side_effect=[canonical(metadata), payload]):
            obs = read_npm(self.npm_dest, self.npm_subj, desired_identity="b" * 64,
                           expected_hashes={"pkg.tgz": "a" * 64}, expected_license="MIT",
                           expected_commands={"tfsl": "bin/tfsl.js"})
        self.assertEqual(obs["state"], "conflict")
        self.assertTrue(has_live_proof(obs))
        self.assertEqual(obs["readback"]["components"], {"pkg.tgz": hashlib.sha256(payload).hexdigest()})
        self.assertIn("npm-conflict", [row["code"] for row in obs["diagnostics"]])

    # ------------------------------------------------------------------
    # Homebrew Reader Tests
    # ------------------------------------------------------------------
    def test_homebrew_requires_immutable_pinned_ref(self):
        for bad_ref in ("main", "master", "HEAD", "feature/branch"):
            with self.assertRaises(ContractError) as ctx:
                read_homebrew(self.brew_dest, self.brew_subj, pinned_ref=bad_ref)
            self.assertEqual(ctx.exception.code, "HOMEBREW_PIN")

    def test_homebrew_exact_404_yields_absent(self):
        url = f"https://raw.githubusercontent.com/Knowledge-Forge-AI/homebrew-tap/{'a' * 40}/Formula/theme-forge-stellar-loom.rb"
        with patch("rs9.readers._get", side_effect=HTTPError(url, 404, "Not Found", {}, None)):
            obs = read_homebrew(self.brew_dest, self.brew_subj, pinned_ref="a" * 40)
        self.assertEqual(obs["state"], "absent")
        self.assertTrue(has_live_proof(obs))

    def test_homebrew_exact_match(self):
        formula_bytes = b'url "https://registry.npmjs.org/pkg.tgz"\nsha256 "' + b"e" * 64 + b'"\n'
        with patch("rs9.readers._get", return_value=formula_bytes):
            obs = read_homebrew(
                self.brew_dest, self.brew_subj, pinned_ref="a" * 40,
                desired_identity="b" * 64,
                expected_payload_url="https://registry.npmjs.org/pkg.tgz",
                expected_payload_sha256="e" * 64
            )
        self.assertEqual(obs["state"], "conflict")
        self.assertTrue(has_live_proof(obs))

    def test_homebrew_full_agreement_yields_exact(self):
        formula_text = (
            'class ThemeForgeStellarLoom < Formula\n'
            '  desc "Theme builder"\n'
            '  homepage "https://github.com/Knowledge-Forge-AI/theme-forge-stellar-loom"\n'
            '  url "https://registry.npmjs.org/pkg.tgz"\n'
            '  sha256 "' + "e" * 64 + '"\n'
            '  license "AGPL-3.0-or-later"\n'
            '  depends_on "node"\n'
            '  def install\n'
            '    (bin/"tfsl").write "exec node"\n'
            '  end\n'
            '  test do\n'
            '    assert_match version.to_s, shell_output("#{bin}/tfsl --version")\n'
            '  end\n'
            'end\n'
        )
        formula_bytes = formula_text.encode()
        expected_blob = hashlib.sha1(f"blob {len(formula_bytes)}\0".encode() + formula_bytes).hexdigest()

        with patch("rs9.readers._get", return_value=formula_bytes):
            obs = read_homebrew(
                self.brew_dest, self.brew_subj, pinned_ref="a" * 40,
                desired_identity="b" * 64,
                expected_payload_url="https://registry.npmjs.org/pkg.tgz",
                expected_payload_sha256="e" * 64,
                expected_license="AGPL-3.0-or-later",
                expected_commands=["tfsl"],
                expected_restrictions="node",
                expected_blob_sha=expected_blob,
            )
        self.assertEqual(obs["state"], "exact")
        self.assertEqual(obs["readback"]["presence"], "present")
        self.assertEqual(obs["readback"]["level"], "full")
        self.assertEqual(obs["readback"]["content_identity_sha256"], "b" * 64)
        self.assertTrue(has_live_proof(obs))

    def test_homebrew_license_and_command_mismatches_yield_conflict(self):
        formula_text = (
            'class ThemeForgeStellarLoom < Formula\n'
            '  url "https://registry.npmjs.org/pkg.tgz"\n'
            '  sha256 "' + "e" * 64 + '"\n'
            '  license "MIT"\n'
            '  def install\n'
            '    (bin/"tfsl").write "exec node"\n'
            '  end\n'
            'end\n'
        )
        formula_bytes = formula_text.encode()

        with patch("rs9.readers._get", return_value=formula_bytes):
            # License mismatch
            obs_lic = read_homebrew(
                self.brew_dest, self.brew_subj, pinned_ref="a" * 40,
                desired_identity="b" * 64,
                expected_payload_url="https://registry.npmjs.org/pkg.tgz",
                expected_payload_sha256="e" * 64,
                expected_license="AGPL-3.0-or-later",
            )
            self.assertEqual(obs_lic["state"], "conflict")
            self.assertIn("homebrew-conflict", [d["code"] for d in obs_lic["diagnostics"]])

            # Command mismatch
            obs_cmd = read_homebrew(
                self.brew_dest, self.brew_subj, pinned_ref="a" * 40,
                desired_identity="b" * 64,
                expected_payload_url="https://registry.npmjs.org/pkg.tgz",
                expected_payload_sha256="e" * 64,
                expected_license="MIT",
                expected_commands=["other-command"],
            )
            self.assertEqual(obs_cmd["state"], "conflict")

            # Blob SHA mismatch
            obs_blob = read_homebrew(
                self.brew_dest, self.brew_subj, pinned_ref="a" * 40,
                desired_identity="b" * 64,
                expected_payload_url="https://registry.npmjs.org/pkg.tgz",
                expected_payload_sha256="e" * 64,
                expected_license="MIT",
                expected_commands=["tfsl"],
                expected_blob_sha="f" * 40,
            )
            self.assertEqual(obs_blob["state"], "conflict")

    def test_homebrew_conflict_on_mismatch(self):
        formula_bytes = b'url "https://registry.npmjs.org/pkg.tgz"\nsha256 "' + b"e" * 64 + b'"\n'
        with patch("rs9.readers._get", return_value=formula_bytes):
            obs = read_homebrew(
                self.brew_dest, self.brew_subj, pinned_ref="a" * 40,
                desired_identity="b" * 64,
                expected_payload_url="https://registry.npmjs.org/other.tgz",
                expected_payload_sha256="e" * 64
            )
        self.assertEqual(obs["state"], "conflict")
        self.assertIn("homebrew-conflict", [d["code"] for d in obs["diagnostics"]])

    def test_homebrew_transport_rate_redirect_fail_closed(self):
        for exc in (
            URLError("ref not reached"),
            HTTPError("https://raw.githubusercontent.com/", 429, "Rate limit", {}, None),
            http.client.HTTPException("protocol error"),
            ContractError("READER_REDIRECT", "Redirect"),
        ):
            with patch("rs9.readers._get", side_effect=exc):
                obs = read_homebrew(self.brew_dest, self.brew_subj, pinned_ref="a" * 40)
            self.assertEqual(obs["state"], "unknown")
            self.assertTrue(has_live_proof(obs))

    # ------------------------------------------------------------------
    # Pages Reader Tests
    # ------------------------------------------------------------------
    def test_pages_exact_404_with_tls_and_no_redirect_yields_absent(self):
        url = "https://rs9.knowledge-forge.ai/pool/main/t/pkg.deb"
        with patch("rs9.readers._get", side_effect=HTTPError(url, 404, "Not Found", {}, None)):
            obs = read_pages(self.pages_dest, self.pages_subj, path="pool/main/t/pkg.deb")
        self.assertEqual(obs["state"], "absent")
        self.assertEqual(obs["readback"]["presence"], "absent")
        self.assertTrue(has_live_proof(obs))

    def test_pages_dns_failure_yields_unknown_never_absent(self):
        dns_err = URLError(socket.gaierror(-2, "Name or service not known"))
        with patch("rs9.readers._get", side_effect=dns_err):
            obs = read_pages(self.pages_dest, self.pages_subj, path="pool/main/t/pkg.deb")
        self.assertEqual(obs["state"], "unknown")
        self.assertNotEqual(obs["readback"]["presence"], "absent")
        self.assertIn("pages-dns-unknown", [d["code"] for d in obs["diagnostics"]])
        self.assertTrue(has_live_proof(obs))

    def test_pages_tls_failure_yields_unknown(self):
        tls_err = URLError(ssl.SSLError("Certificate validation failed"))
        with patch("rs9.readers._get", side_effect=tls_err):
            obs = read_pages(self.pages_dest, self.pages_subj, path="pool/main/t/pkg.deb")
        self.assertEqual(obs["state"], "unknown")
        self.assertIn("pages-tls-error", [d["code"] for d in obs["diagnostics"]])
        self.assertTrue(has_live_proof(obs))

    def test_pages_redirect_yields_unknown_never_absent(self):
        with patch("rs9.readers._get", side_effect=ContractError("READER_REDIRECT", "Redirect rejected")):
            obs = read_pages(self.pages_dest, self.pages_subj, path="pool/main/t/pkg.deb")
        self.assertEqual(obs["state"], "unknown")
        self.assertNotEqual(obs["readback"]["presence"], "absent")
        self.assertTrue(has_live_proof(obs))

    def test_pages_200_exact_and_conflict(self):
        data = b"package-binary-bytes"
        expected_sha = hashlib.sha256(data).hexdigest()
        with patch("rs9.readers._get", return_value=data):
            obs_match = read_pages(self.pages_dest, self.pages_subj, path="pkg.deb",
                                   desired_identity="b" * 64, expected_sha256=expected_sha)
            self.assertEqual(obs_match["state"], "exact")

            obs_conflict = read_pages(self.pages_dest, self.pages_subj, path="pkg.deb",
                                      desired_identity="b" * 64, expected_sha256="0" * 64)
            self.assertEqual(obs_conflict["state"], "conflict")

    # ------------------------------------------------------------------
    # GitHub Reader Tests
    # ------------------------------------------------------------------
    def test_github_read_pages_state(self):
        doc = {"status": "built", "cname": "rs9.knowledge-forge.ai", "https_enforced": True}
        with patch("rs9.readers._get", return_value=canonical(doc)):
            obs = read_github("Knowledge-Forge-AI/release-starport-9", query_type="pages", desired_identity="b" * 64)
        self.assertEqual(obs["state"], "unknown")
        self.assertTrue(has_live_proof(obs))

        # 404 Pages absent
        url = "https://api.github.com/repos/Knowledge-Forge-AI/release-starport-9/pages"
        with patch("rs9.readers._get", side_effect=HTTPError(url, 404, "Not Found", {}, None)):
            obs_absent = read_github("Knowledge-Forge-AI/release-starport-9", query_type="pages")
        self.assertEqual(obs_absent["state"], "unknown")

    def test_github_read_ref(self):
        commit = "1" * 40
        doc = {"object": {"sha": commit, "type": "commit"}}
        with patch("rs9.readers._get", return_value=canonical(doc)):
            obs = read_github("Knowledge-Forge-AI/release-starport-9", query_type="ref",
                              ref="refs/tags/v0.6.1", expected_sha=commit, desired_identity="b" * 64)
        self.assertEqual(obs["state"], "unknown")

        # Ref mismatch yields conflict
        with patch("rs9.readers._get", return_value=canonical(doc)):
            obs_conflict = read_github("Knowledge-Forge-AI/release-starport-9", query_type="ref",
                                       ref="refs/tags/v0.6.1", expected_sha="2" * 40, desired_identity="b" * 64)
        self.assertEqual(obs_conflict["state"], "conflict")

    def test_github_never_secrets(self):
        # Passing credentials in repo or ref raises ContractError
        with self.assertRaises(ContractError) as ctx:
            read_github("Knowledge-Forge-AI/repo", ref="ghp_" + "a" * 36)
        self.assertEqual(ctx.exception.code, "CREDENTIAL_DETECTED")

    def test_github_rate_limit_fails_closed(self):
        url = "https://api.github.com/repos/Knowledge-Forge-AI/release-starport-9/pages"
        with patch("rs9.readers._get", side_effect=HTTPError(url, 403, "rate limit exceeded", {}, None)):
            obs = read_github("Knowledge-Forge-AI/release-starport-9", query_type="pages")
        self.assertEqual(obs["state"], "unknown")

    # ------------------------------------------------------------------
    # Signed Repository Reader Tests
    # ------------------------------------------------------------------
    def test_signed_repo_without_verifier_stays_unknown(self):
        # Must authenticate signatures through verifier or stay unknown!
        with patch("rs9.readers._get", return_value=b"index content"):
            obs = read_signed_repo("theme-forge", base_url="https://rs9.knowledge-forge.ai",
                                   index_path="InRelease", verifier=None)
        self.assertEqual(obs["state"], "unknown")
        self.assertIn("signature-unverified", [d["code"] for d in obs["diagnostics"]])
        self.assertTrue(has_live_proof(obs))

    def test_signed_repo_failing_verifier_stays_unknown(self):
        def bad_verifier(idx, sig=None):
            return False

        with patch("rs9.readers._get", return_value=b"index content"):
            obs = read_signed_repo("theme-forge", base_url="https://rs9.knowledge-forge.ai",
                                   index_path="InRelease", verifier=bad_verifier)
        self.assertEqual(obs["state"], "unknown")
        self.assertIn("signature-invalid", [d["code"] for d in obs["diagnostics"]])
        self.assertTrue(has_live_proof(obs))

    def test_signed_repo_boolean_verifier_cannot_prove_exact(self):
        idx_data = b"authenticated repository index"
        sig_data = b"pgp signature bytes"
        def good_verifier(idx, sig):
            assert idx == idx_data
            assert sig == sig_data
            return True

        with patch("rs9.readers._get", side_effect=[idx_data, sig_data]):
            obs = read_signed_repo("theme-forge", base_url="https://rs9.knowledge-forge.ai",
                                   index_path="Release", signature_path="Release.gpg",
                                   verifier=good_verifier, desired_identity="b" * 64)
        self.assertEqual(obs["state"], "unknown")
        self.assertEqual(obs["readback"]["presence"], "unknown")
        self.assertTrue(has_live_proof(obs))

    def test_signed_repo_exact_404_yields_absent(self):
        url = "https://rs9.knowledge-forge.ai/InRelease"
        with patch("rs9.readers._get", side_effect=HTTPError(url, 404, "Not Found", {}, None)):
            obs = read_signed_repo("theme-forge", base_url="https://rs9.knowledge-forge.ai",
                                   index_path="InRelease", verifier=lambda x: True)
        self.assertEqual(obs["state"], "absent")
        self.assertTrue(has_live_proof(obs))

    # ------------------------------------------------------------------
    # Live Observation Proof Immutability Tests
    # ------------------------------------------------------------------
    def test_live_proof_immutability(self):
        url = "https://pypi.org/pypi/theme-forge-stellar-loom/json"
        with patch("rs9.readers._get", side_effect=HTTPError(url, 404, "Not Found", {}, None)):
            obs = read_pypi_project(self.pypi_dest, self.pypi_subj)
        self.assertTrue(has_live_proof(obs))

        # Modifying record invalidates proof
        obs["state"] = "exact"
        self.assertFalse(has_live_proof(obs))

        # Serialized JSON loses proof
        raw_json = json.loads(canonical(obs))
        self.assertFalse(has_live_proof(raw_json))

    # ------------------------------------------------------------------
    # HTTPException and Identity Gap Closure Tests
    # ------------------------------------------------------------------
    def test_http_exception_and_protocol_errors_map_to_unknown_across_all_readers(self):
        from tests.test_live1_readers_operator import registry_fixture
        pypi_out, _, _ = registry_fixture()

        for exc in (
            http.client.HTTPException("protocol error"),
            http.client.RemoteDisconnected("remote disconnected"),
            http.client.IncompleteRead(b"partial bytes"),
        ):
            # 1. read_pypi
            with patch("rs9.readers._get", side_effect=exc):
                obs = read_pypi(pypi_out)
            self.assertEqual(obs["state"], "unknown")
            self.assertTrue(has_live_proof(obs))

            # 2. read_pypi_project
            with patch("rs9.readers._get", side_effect=exc):
                obs = read_pypi_project(self.pypi_dest, self.pypi_subj)
            self.assertEqual(obs["state"], "unknown")
            self.assertTrue(has_live_proof(obs))

            # 3. read_npm
            with patch("rs9.readers._get", side_effect=exc):
                obs = read_npm(self.npm_dest, self.npm_subj)
            self.assertEqual(obs["state"], "unknown")
            self.assertTrue(has_live_proof(obs))

            # 4. read_homebrew
            with patch("rs9.readers._get", side_effect=exc):
                obs = read_homebrew(self.brew_dest, self.brew_subj, pinned_ref="a" * 40)
            self.assertEqual(obs["state"], "unknown")
            self.assertTrue(has_live_proof(obs))

            # 5. read_pages
            with patch("rs9.readers._get", side_effect=exc):
                obs = read_pages(self.pages_dest, self.pages_subj, path="pool/main/t/pkg.deb")
            self.assertEqual(obs["state"], "unknown")
            self.assertTrue(has_live_proof(obs))
            self.assertIn("pages-protocol-error", [d["code"] for d in obs["diagnostics"]])

            # 6. read_github (pages query)
            with patch("rs9.readers._get", side_effect=exc):
                obs = read_github("Knowledge-Forge-AI/release-starport-9", query_type="pages")
            self.assertEqual(obs["state"], "unknown")
            self.assertTrue(has_live_proof(obs))

            # 7. read_github (ref query)
            with patch("rs9.readers._get", side_effect=exc):
                obs = read_github("Knowledge-Forge-AI/release-starport-9", query_type="ref", ref="refs/heads/main")
            self.assertEqual(obs["state"], "unknown")
            self.assertTrue(has_live_proof(obs))

            # 8. read_signed_repo
            with patch("rs9.readers._get", side_effect=exc):
                obs = read_signed_repo("theme-forge", base_url="https://rs9.knowledge-forge.ai",
                                       index_path="InRelease", verifier=lambda x: True)
            self.assertEqual(obs["state"], "unknown")
            self.assertTrue(has_live_proof(obs))

    def test_destination_adapter_identity_gaps_fail_closed(self):
        # Mismatched adapter must raise ContractError(READER_DESTINATION)
        bad_cases = [
            (read_pages, {"id": "pages", "adapter": "npm", "mode": "direct"}, {"path": "test"}),
            (read_github, {"id": "github", "adapter": "pages", "mode": "projection"}, {"repository": "repo/name"}),
            (read_signed_repo, {"id": "signed-store", "adapter": "pypi", "mode": "direct"},
             {"base_url": "https://rs9.knowledge-forge.ai", "index_path": "InRelease"}),
            (read_pypi_project, {"id": "pypi", "adapter": "npm", "mode": "direct"}, {}),
            (read_homebrew, {"id": "homebrew", "adapter": "pypi", "mode": "projection"}, {"pinned_ref": "a" * 40}),
        ]
        for fn, dest, kwargs in bad_cases:
            with self.assertRaises(ContractError) as caught:
                fn(dest, **kwargs)
            self.assertEqual(caught.exception.code, "READER_DESTINATION")

    def test_credentials_in_reader_inputs_fail_closed(self):
        token = "ghp_" + "a" * 36
        # Credentials in path or host for read_pages
        with self.assertRaises(ContractError):
            read_pages(self.pages_dest, self.pages_subj, path=f"sub/{token}")
        with self.assertRaises(ContractError):
            read_pages(self.pages_dest, self.pages_subj, path="sub/file", host=f"user:{token}@example.com")

        # Credentials in homebrew
        with self.assertRaises(ContractError):
            read_homebrew(self.brew_dest, self.brew_subj, pinned_ref="a" * 40,
                          expected_payload_url=f"https://user:{token}@github.com/file")

        # Credentials in signed repo
        with self.assertRaises(ContractError):
            read_signed_repo("theme-forge", base_url=f"https://user:{token}@rs9.knowledge-forge.ai",
                             index_path="InRelease")

    def test_pypi_metadata_404_only_absence_not_file_404(self):
        from tests.test_live1_readers_operator import registry_fixture
        pypi_out, metadata, _ = registry_fixture()
        meta_url = f"https://pypi.org/pypi/{pypi_out['subject']['package']}/{pypi_out['subject']['version']}/json"
        file_url = metadata["urls"][0]["url"]

        # Metadata 404 yields absent
        with patch("rs9.readers._get", side_effect=HTTPError(meta_url, 404, "Not Found", {}, None)):
            obs = read_pypi(pypi_out)
        self.assertEqual(obs["state"], "absent")
        self.assertTrue(has_live_proof(obs))

        # File 404 yields unknown, NOT absent
        def fake_get_file_404(url, hosts, limit):
            if url == meta_url:
                return canonical(metadata)
            if url == file_url:
                raise HTTPError(file_url, 404, "Not Found", {}, None)
            raise ValueError(url)

        with patch("rs9.readers._get", side_effect=fake_get_file_404):
            obs = read_pypi(pypi_out)
        self.assertEqual(obs["state"], "unknown")
        self.assertNotEqual(obs["readback"]["presence"], "absent")
        self.assertTrue(has_live_proof(obs))
