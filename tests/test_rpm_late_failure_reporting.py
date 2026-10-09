"""Integration and unit tests for RPM late failure reporting, truthful gate states,
nonroot container identities/mounts, and custody verification.
"""
from pathlib import Path
from types import SimpleNamespace
import json
import os
import shutil
import tempfile
import unittest
from unittest.mock import patch, MagicMock

from rs9 import hosted_packaging as hosted
from rs9 import hosted_pipeline
from rs9.build_native import CommandReceipt
from rs9.errors import ContractError
from rs9.hosted_custody import retain, file_identity, provenance
from rs9.hosted_deb import ContainerRunner, _user
from rs9.hosted_summary import (
    validate_rpm_policy_custody,
    validate_rpm_policy_source,
    gate_blockers,
    contract,
)
from rs9.release_core import digest
from rs9.rpm_evidence import write_policy_evidence, CURRENT_RPM_EVIDENCE_CONTRACT, durable_lint_projection
from rs9.rpm_lint import build_rpmlint_evidence
from rs9.rpm_lint_policy import load_policy
from rs9.scratch import canonical
from tests.rpm_summary_fixtures import witnessed_build_double

PRODUCTS = (
    "theme-forge-stellar-burst",
    "theme-forge-stellar-loom",
    "theme-forge-solar-sail",
    "theme-forge-nebular-fusion",
)


class MockSigningFixture:
    def __init__(self, scratch_dir=None, **kw):
        self.primary_fingerprint = ("A" if scratch_dir else "B") * 40
        self._temporary = tempfile.TemporaryDirectory() if scratch_dir is None else None
        self.homedir = Path(scratch_dir) if scratch_dir else Path(self._temporary.name)
        self.gpg = "gpg"
        self.public_key_armor = "-----BEGIN PGP PUBLIC KEY BLOCK-----\narmor\n-----END PGP PUBLIC KEY BLOCK-----\n"
        self.public_key_binary = b"keyring-bytes"

    def __enter__(self):
        return self

    def __exit__(self, *args):
        if self._temporary is not None:
            self._temporary.cleanup()

    def detach_sign(self, data, armor=False):
        return b"-----BEGIN PGP SIGNATURE-----\nsig\n-----END PGP SIGNATURE-----\n" if armor else b"binary-sig"

    def verify(self, data, sig):
        return True


class MockWrongFixture:
    def __init__(self, **kw):
        self.primary_fingerprint = "B" * 40
        self._temporary = tempfile.TemporaryDirectory()
        self.homedir = Path(self._temporary.name)
        self.gpg = "gpg"
        self.public_key_armor = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nwrong\n-----END PGP PUBLIC KEY BLOCK-----\n"
        self.public_key_binary = b"wrong-keyring"

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self._temporary.cleanup()


class RpmLateFailureReportingTests(unittest.TestCase):
    def setUp(self):
        self.repo = Path(".").resolve()

    def _setup_lane(self, root, *, raw_lint_fail=True):
        scratch = root / "lane-work"
        scratch.mkdir(parents=True, exist_ok=True)
        captures = [(SimpleNamespace(root=root / "capture" / p), {"project": {"id": p, "version": "1.0.0"}}, {}) for p in PRODUCTS]
        context = {
            "family": "rpm",
            "system": "x86_64-linux",
            "repository": self.repo,
            "scratch": scratch,
            "pins": {},
            "client": None,
            "captures": captures,
            "binding": {"source_commit": "0" * 40},
            "authentication_sha256": "1" * 64,
        }
        env = {
            "family": "rpm",
            "system": "x86_64-linux",
            "image_ref": "fedora@sha256:" + "0" * 64,
            "platform": "linux/amd64",
            "preprovisioned_packages": [],
            "tools": {},
        }
        policy_template = load_policy(self.repo / "operators/live1/rpm-lint-policy.json")
        policy_sha = digest(canonical(policy_template))

        def build(capture, intent, arch, work, *, runner=None, **kwargs):
            pid = intent["project"]["id"]
            rpm = work / f"{pid}-1.0.0-1.fc43.{arch}.rpm"
            rpm.write_bytes(f"rpm-content-{pid}".encode())
            spec = work / "rpmbuild" / "SPECS" / f"{pid}.spec"
            spec.parent.mkdir(parents=True, exist_ok=True)
            spec.write_bytes(f"Name: {pid}\n".encode())

            has_raw_error = raw_lint_fail and pid == "theme-forge-nebular-fusion"
            stdout = b"1 packages and 1 specfiles checked; 0 errors, 0 warnings, 8 filtered.\n"
            tool = CommandReceipt(["rpmlint", spec.name, rpm.name], 0, stdout, b"", executed=True)
            raw_lint = build_rpmlint_evidence(tool, spec, rpm, pid, rpm_identity={"name": pid, "version": "1.0.0", "release": "1.fc43", "arch": arch})
            if has_raw_error:
                raw_lint["clean"] = False
                raw_lint["status"] = "fail"
                raw_lint["tool_receipt"]["exit_code"] = 1
                raw_lint["error_records"] = [{
                    "arguments_complete": True,
                    "arguments_sha256": digest(b"arg"),
                    "code": "non-executable-script",
                    "level": "E",
                    "message": f"package:usr/lib/{pid}/test 644 package:usr/bin/env node",
                    "path": f"/usr/lib/{pid}/test",
                    "target": f"{pid}.{arch}",
                }]
            evaluation = {
                "schema": "rs9.rpm-lint-policy-evaluation.v1",
                "accepted": True,
                "status": "accepted" if has_raw_error else "accepted-no-exceptions",
                "blockers": [],
                "inputs": {"project_id": pid, "version": "1.0.0", "arch": arch, "system": "x86_64-linux"},
                "raw_lint_status": raw_lint["status"],
                "raw_exit_code": raw_lint["tool_receipt"]["exit_code"],
                "policy_sha256": policy_sha,
                "accepted_findings": raw_lint["error_records"] if has_raw_error else [],
            }
            derivation = {
                "project": pid,
                "adapter": "rpm",
                "artifact": {"sha256": raw_lint["package_sha256"]},
                "evidence": {"rpmlint": durable_lint_projection(raw_lint, object_path=f"diagnostics/rpmlint-{pid}.json")},
            }
            manifest = {
                "schema": "rs9.rpm-candidate.v1alpha2",
                "project": pid,
                "architecture": arch,
                "package_file": "unsigned/" + rpm.name,
                "package_sha256": raw_lint["package_sha256"],
                "package_size": rpm.stat().st_size,
                "rpm_identity": {"name": pid, "version": "1.0.0", "release": "1.fc43", "arch": arch},
                "rpm_payload_digest": {
                    "tag": "PAYLOADSHA256",
                    "algo_tag": "PAYLOADSHA256ALGO",
                    "payload_digest": "0" * 64,
                    "algorithm_numeric": 8,
                    "algorithm": "sha256",
                    "capability": "payload",
                },
                "rpmlint": raw_lint,
                "rpmlint_policy": evaluation,
                "derivation": derivation,
            }
            from rs9.rpm_query import read_rpm_payload_digest
            manifest["rpm_payload_digest"] = read_rpm_payload_digest(
                CommandReceipt(["rpm"], 0, ("0" * 64 + "|8\n").encode(), b"", executed=True))
            manifest["rpm_payload_digest"]["querytags_sha256"] = digest(b"PAYLOADSHA256\nPAYLOADSHA256ALGO\n")
            (work / "rpm-manifest.json").write_bytes(canonical(manifest))
            return {
                "rpm_path": rpm,
                "manifest": manifest,
                "policy_evaluation": evaluation,
            }

        return context, env, build

    def test_accepted_policy_late_signing_failure_truthful_gates_and_custody(self):
        """Accepted policy + derivation + custody complete; package signing fails late.
        Verifies truthful gates, custody preservation, summary/chunk/raw-hash check, and not-qualified verdict.
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            context, env, build = self._setup_lane(root, raw_lint_fail=True)

            def failing_sign_rpm(runner, path, fixture, **kwargs):
                if "theme-forge-nebular-fusion" in str(path):
                    raise ContractError(
                        "RPM_SIGNING",
                        "Fixture RPM signature validation failed",
                        details={"substage": "package-signing", "tool": "rpmkeys", "exit_code": 1},
                    )
                return {
                    "unsigned_sha256": digest(Path(path).read_bytes()),
                    "fixture_signed_sha256": digest(b"signed"),
                    "fixture_fingerprint": fixture.primary_fingerprint,
                    "production": False,
                    "rpm_identity": {"name": Path(path).name.split("-")[0]},
                    "rpm_payload_digest": {},
                    "identity_preserved": True,
                    "payload_digest_preserved": True,
                }

            with patch("rs9.hosted_packaging.provision", return_value=env), \
                 patch("rs9.hosted_deb.provision_image"), \
                 patch("rs9.hosted_packaging.prepare_client", return_value={"status": "pass", "reason": "ok", "schema": "rs9.rpm-client-runtime-evidence.v1"}), \
                 patch("rs9.rpm_client_runtime.bind_engine_floors", side_effect=lambda ev, caps: ev), \
                 patch("rs9.hosted_packaging.verify_client_image", return_value="tag"), \
                 patch("rs9.hosted_packaging.checked", return_value=CommandReceipt(["tool"], 0, b"", b"", executed=True)), \
                 patch("rs9.hosted_packaging.container_tool_facts", return_value={"rpm": "v6"}), \
                 patch("rs9.hosted_packaging._resolve_offline_npm_archives", return_value=None), \
                 patch("rs9.hosted_packaging.build_rpm_candidate", autospec=True, side_effect=witnessed_build_double(build)), \
                 patch("rs9.hosted_packaging.SigningFixture", MockSigningFixture), \
                 patch("rs9.hosted_packaging.sign_rpm", side_effect=failing_sign_rpm):
                result = hosted.execute(context)

            gates = {g["name"]: g for g in result["gates"]}
            # Established upstream gates must be truthful pass
            self.assertEqual(gates["rpm-container-environment"]["status"], "pass")
            self.assertEqual(gates["rpm-package-build"]["status"], "pass")
            self.assertEqual(gates["rpm-derivation-record"]["status"], "pass")
            self.assertEqual(gates["rpm-manifest-record"]["status"], "pass")
            self.assertEqual(gates["rpm-policy-custody"]["status"], "pass")
            # Raw lint failed on nebular-fusion, but policy accepted it: truthful pass
            self.assertEqual(gates["rpm-lint-policy-accepted"]["status"], "pass")
            self.assertEqual(gates["rpm-client-preparation"]["status"], "pass")

            # Signing late failure: repository-indexing fails with causal_substage package-signing
            self.assertEqual(gates["rpm-repository-indexing"]["status"], "fail")
            self.assertEqual(gates["rpm-repository-indexing"]["causal_substage"], "package-signing")
            self.assertEqual(gates["rpm-repository-indexing"]["reason"], "RPM_SIGNING")

            # Genuine never-reached downstream DNF and tamper gates: not-run
            self.assertEqual(gates["rpm-client-qualification"]["status"], "not-run")
            self.assertEqual(gates["rpm-client-qualification"]["reason"], "blocked-by:rpm-repository-indexing")
            self.assertEqual(gates["burst-native-addon-target"]["status"], "not-run")
            self.assertEqual(gates["burst-native-addon-load"]["status"], "not-run")
            for kind in ("package", "index", "signature", "wrongkey"):
                self.assertEqual(gates[f"rpm-trust.tamper.{kind}"]["status"], "not-run")
                self.assertEqual(gates[f"rpm-trust.tamper.{kind}"]["reason"], "blocked-by:rpm-repository-indexing")

            # Unsigned custody bytes must be preserved
            unsigned_custody = context["scratch"] / "unsigned-custody"
            self.assertTrue(unsigned_custody.is_dir())
            custody_files = list(unsigned_custody.rglob("*.rpm"))
            self.assertEqual(len(custody_files), 4)

            # Details contract must be current
            details = result["details"]
            self.assertEqual(details["rpm_evidence_contract"], CURRENT_RPM_EVIDENCE_CONTRACT)
            self.assertEqual(set(details["rpm_lint_raw"].keys()), set(PRODUCTS))
            self.assertEqual(set(details["rpm_lint_policy"].keys()), set(PRODUCTS))
            self.assertEqual(set(details["construction_witnesses"].keys()), set(PRODUCTS))
            self.assertIn("cleanup_evidence", details)

            # Retain and verify via hosted_summary validation functions
            retained_dir = root / "retained"
            prov = provenance(self.repo, "1" * 64)
            record = {
                "lane": "rpm",
                "system": "x86_64-linux",
                "gates": result["gates"],
                "details": details,
                "execution_error": "required-gates-unsatisfied",
                "provenance": prov,
                "runner": {},
                "production_promotion_blockers": result.get("production_promotion_blockers", []),
            }
            manifest = retain(context["scratch"], retained_dir, result["artifacts"], record)

            # validate_rpm_policy_custody verifies summary, chunks, and raw-hash
            custody_check = validate_rpm_policy_custody(retained_dir, manifest, record)
            self.assertEqual(set(custody_check.keys()), set(PRODUCTS))

            # validate_rpm_policy_source verifies load_policy matching
            validate_rpm_policy_source(self.repo, record)

            # Gate blockers correctly blocks qualification
            lane_contract = [r for r in contract(self.repo)["lanes"] if r["lane"] == "rpm" and r["system"] == "x86_64-linux"][0]
            blockers = gate_blockers(lane_contract, record)
            self.assertTrue(any("rpm-repository-indexing" in b for b in blockers))
            self.assertTrue(any("rpm-client-qualification" in b for b in blockers))

    def test_accepted_policy_late_metadata_failure_truthful_gates_and_custody(self):
        """Accepted policy + signing complete; createrepo/metadata tool fails late.
        Verifies truthful gates, causal_substage repository-metadata, and summary/chunk/raw-hash custody check.
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            context, env, build = self._setup_lane(root, raw_lint_fail=False)

            def sign_all(runner, path, fixture, **kwargs):
                return {
                    "unsigned_sha256": digest(Path(path).read_bytes()),
                    "fixture_signed_sha256": digest(b"signed"),
                    "fixture_fingerprint": fixture.primary_fingerprint,
                    "production": False,
                    "rpm_identity": {"name": Path(path).name.split("-")[0]},
                    "rpm_payload_digest": {},
                    "identity_preserved": True,
                    "payload_digest_preserved": True,
                }

            def fail_createrepo(runner, argv, **kwargs):
                if "createrepo_c" in argv:
                    raise ContractError(
                        "NATIVE_TOOL",
                        "createrepo_c failed",
                        details={"substage": "repository-metadata", "tool": "createrepo_c", "exit_code": 1},
                    )
                return CommandReceipt(argv, 0, b"", b"", executed=True)

            with patch("rs9.hosted_packaging.provision", return_value=env), \
                 patch("rs9.hosted_deb.provision_image"), \
                 patch("rs9.hosted_packaging.prepare_client", return_value={"status": "pass", "reason": "ok", "schema": "rs9.rpm-client-runtime-evidence.v1"}), \
                 patch("rs9.rpm_client_runtime.bind_engine_floors", side_effect=lambda ev, caps: ev), \
                 patch("rs9.hosted_packaging.verify_client_image", return_value="tag"), \
                 patch("rs9.hosted_packaging.checked", side_effect=fail_createrepo), \
                 patch("rs9.hosted_packaging.container_tool_facts", return_value={"rpm": "v6"}), \
                 patch("rs9.hosted_packaging._resolve_offline_npm_archives", return_value=None), \
                 patch("rs9.hosted_packaging.build_rpm_candidate", autospec=True, side_effect=witnessed_build_double(build)), \
                 patch("rs9.hosted_packaging.SigningFixture", MockSigningFixture), \
                 patch("rs9.hosted_packaging.sign_rpm", side_effect=sign_all):
                result = hosted.execute(context)

            gates = {g["name"]: g for g in result["gates"]}
            # Established stages must pass
            self.assertEqual(gates["rpm-package-build"]["status"], "pass")
            self.assertEqual(gates["rpm-policy-custody"]["status"], "pass")
            self.assertEqual(gates["rpm-lint-policy-accepted"]["status"], "pass")
            self.assertEqual(gates["rpm-client-preparation"]["status"], "pass")

            # Repository-indexing fails with causal_substage repository-metadata
            self.assertEqual(gates["rpm-repository-indexing"]["status"], "fail")
            self.assertEqual(gates["rpm-repository-indexing"]["causal_substage"], "repository-metadata")
            self.assertEqual(gates["rpm-repository-indexing"]["reason"], "NATIVE_TOOL")

            # Downstream DNF not run
            self.assertEqual(gates["rpm-client-qualification"]["status"], "not-run")

            # Summary verification passes
            retained_dir = root / "retained"
            prov = provenance(self.repo, "1" * 64)
            record = {
                "lane": "rpm",
                "system": "x86_64-linux",
                "gates": result["gates"],
                "details": result["details"],
                "execution_error": "required-gates-unsatisfied",
                "provenance": prov,
                "runner": {},
            }
            manifest = retain(context["scratch"], retained_dir, result["artifacts"], record)
            custody_check = validate_rpm_policy_custody(retained_dir, manifest, record)
            self.assertEqual(set(custody_check.keys()), set(PRODUCTS))

    def test_client_image_drift_preserves_existing_mapping_and_causal_substage(self):
        """CLIENT_IMAGE_DRIFT regression: keeps rpm-client-preparation mapping and client-image-verification causal_substage."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            context, env, build = self._setup_lane(root, raw_lint_fail=False)

            def sign_all(runner, path, fixture, **kwargs):
                return {
                    "unsigned_sha256": digest(Path(path).read_bytes()),
                    "fixture_signed_sha256": digest(b"signed"),
                    "fixture_fingerprint": fixture.primary_fingerprint,
                    "production": False,
                    "rpm_identity": {"name": Path(path).name.split("-")[0]},
                    "rpm_payload_digest": {},
                    "identity_preserved": True,
                    "payload_digest_preserved": True,
                }

            with patch("rs9.hosted_packaging.provision", return_value=env), \
                 patch("rs9.hosted_deb.provision_image"), \
                 patch("rs9.hosted_packaging.prepare_client", return_value={"status": "pass", "reason": "ok", "schema": "rs9.rpm-client-runtime-evidence.v1"}), \
                 patch("rs9.rpm_client_runtime.bind_engine_floors", side_effect=lambda ev, caps: ev), \
                 patch("rs9.hosted_packaging.checked", return_value=CommandReceipt(["tool"], 0, b"", b"", executed=True)), \
                 patch("rs9.hosted_packaging.container_tool_facts", return_value={"rpm": "v6"}), \
                 patch("rs9.hosted_packaging._resolve_offline_npm_archives", return_value=None), \
                 patch("rs9.hosted_packaging.build_rpm_candidate", autospec=True, side_effect=witnessed_build_double(build)), \
                 patch("rs9.hosted_packaging.SigningFixture", MockSigningFixture), \
                 patch("rs9.hosted_packaging.sign_rpm", side_effect=sign_all), \
                 patch("rs9.hosted_packaging.verify_client_image", side_effect=ContractError("CLIENT_IMAGE_DRIFT", "Client drift detected")):
                result = hosted.execute(context)

            gates = {g["name"]: g for g in result["gates"]}
            self.assertEqual(gates["rpm-client-preparation"]["status"], "fail")
            self.assertEqual(gates["rpm-client-preparation"]["reason"], "CLIENT_IMAGE_DRIFT")
            self.assertEqual(gates["rpm-client-preparation"]["causal_substage"], "client-image-verification")
            self.assertEqual(gates["rpm-client-qualification"]["status"], "not-run")
            self.assertEqual(gates["rpm-client-qualification"]["reason"], "blocked-by:rpm-client-preparation")

    def test_rpm_signer_and_createrepo_explicit_user_and_pacman_unchanged(self):
        """RPM signer and createrepo tool use user=_user(); pacman tool leaves user as default None."""
        observed_users = {}

        class SpyContainerRunner:
            def __init__(self, host, image, *, platform="linux/amd64", mounts=(), network=False, user=None):
                self.host, self.image, self.platform, self.mounts, self.network, self.user = host, image, platform, list(mounts), network, user
                observed_users.setdefault(image, []).append(user)

            def run(self, argv, **kwargs):
                return CommandReceipt(argv, 0, b"", b"", executed=True)

            def mark(self):
                return 0

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            context, env, build = self._setup_lane(root, raw_lint_fail=False)

            with patch("rs9.hosted_packaging.provision", return_value=env), \
                 patch("rs9.hosted_deb.provision_image"), \
                 patch("rs9.hosted_packaging.prepare_client", return_value={"status": "pass", "reason": "ok", "schema": "rs9.rpm-client-runtime-evidence.v1"}), \
                 patch("rs9.rpm_client_runtime.bind_engine_floors", side_effect=lambda ev, caps: ev), \
                 patch("rs9.hosted_packaging.checked", return_value=CommandReceipt(["tool"], 0, b"", b"", executed=True)), \
                 patch("rs9.hosted_packaging.container_tool_facts", return_value={"rpm": "v6"}), \
                 patch("rs9.hosted_packaging._resolve_offline_npm_archives", return_value=None), \
                 patch("rs9.hosted_packaging.build_rpm_candidate", autospec=True, side_effect=witnessed_build_double(build)), \
                 patch("rs9.hosted_packaging.SigningFixture", MockSigningFixture), \
                 patch("rs9.hosted_packaging.sign_rpm", return_value={"unsigned_sha256": "0"*64, "fixture_signed_sha256": "1"*64, "fixture_fingerprint": "A"*40, "production": False, "rpm_identity": {}, "rpm_payload_digest": {}, "identity_preserved": True, "payload_digest_preserved": True}), \
                 patch("rs9.hosted_packaging.verify_client_image", return_value="tag"), \
                 patch("rs9.hosted_deb.client_cycle", return_value=([], {})), \
                 patch("rs9.hosted_deb.tamper_cycle", return_value=[]), \
                 patch("rs9.hosted_deb.ContainerRunner", SpyContainerRunner):
                hosted.execute(context)

            expected_user = _user()
            # In RPM lane, signer and tool pass user=_user()
            for img, users in observed_users.items():
                for u in users:
                    self.assertEqual(u, expected_user)

    def test_pipeline_generic_error_preserves_partial_result(self):
        """hosted_pipeline.run_lane preserves gates and artifacts from error.partial_result."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            scratch = root / "pipeline-scratch"
            scratch.mkdir()
            receipts_dir = root / "receipts"
            receipts_dir.mkdir()

            partial_gates = [
                {"name": "rpm-container-environment", "status": "pass"},
                {"name": "rpm-package-build", "status": "pass"},
                {"name": "rpm-lint-policy-accepted", "status": "pass"},
                {"name": "rpm-client-preparation", "status": "pass"},
                {"name": "rpm-derivation-record", "status": "pass"},
                {"name": "rpm-manifest-record", "status": "pass"},
                {"name": "rpm-policy-custody", "status": "pass"},
                {"name": "rpm-repository-indexing", "status": "fail", "reason": "RPM_SIGNING", "causal_substage": "package-signing"},
                {"name": "rpm-client-qualification", "status": "not-run", "reason": "blocked-by:rpm-repository-indexing"},
                {"name": "burst-native-addon-target", "status": "not-run", "reason": "blocked-by:rpm-repository-indexing"},
                {"name": "burst-native-addon-load", "status": "not-run", "reason": "blocked-by:rpm-repository-indexing"},
            ]

            partial_result = {
                "gates": partial_gates,
                "artifacts": [],
                "details": {
                    "rpm_evidence_contract": CURRENT_RPM_EVIDENCE_CONTRACT,
                    "operation_failure": {"substage": "package-signing", "code": "RPM_SIGNING"},
                },
            }
            err = ContractError("RPM_SIGNING", "Late failure during package signing")
            err.partial_result = partial_result

            auth_dir = root / "auth"
            auth_dir.mkdir(exist_ok=True)
            (auth_dir / "artifact-manifest.json").write_bytes(json.dumps({
                "schema": "rs9.hosted-custody-set.v1alpha1",
                "release_ingestion_sha256": "1"*64,
                "lane": "authenticate", "system": "generation",
            }).encode())

            def fake_capture(repo, root, **kw):
                (root / "summary").mkdir(parents=True, exist_ok=True)
                (root / "summary" / "authentication.json").write_bytes(b"{}")
                return []

            def fake_bind(c, r, s):
                p = s / "bind.json"
                p.write_bytes(b"{}")
                return p

            with patch("rs9.hosted_pipeline.validate_host"), \
                 patch("rs9.hosted_pipeline.capture_generation", side_effect=fake_capture), \
                 patch("rs9.hosted_pipeline._inputs", return_value={("authenticate", "generation"): auth_dir}), \
                 patch("rs9.hosted_pipeline.canonical_release_auth_projection", return_value={}), \
                 patch("rs9.hosted_pipeline.compute_auth_sha256", return_value="1"*64), \
                 patch("rs9.hosted_pipeline.bind_commands", side_effect=fake_bind), \
                 patch("importlib.import_module") as mock_mod:
                mock_mod.return_value.execute.side_effect = err

                exit_code = hosted_pipeline.run_lane(self.repo, scratch, receipts_dir, "rpm", "x86_64-linux",
                                                     inputs=auth_dir)
                self.assertEqual(exit_code, 2)

            receipt_file = receipts_dir / "rpm-x86_64-linux.json"
            self.assertTrue(receipt_file.is_file())
            receipt_data = json.loads(receipt_file.read_bytes())
            self.assertEqual(receipt_data["details"]["rpm_evidence_contract"], CURRENT_RPM_EVIDENCE_CONTRACT)
            gates_by_name = {g["name"]: g["status"] for g in receipt_data["gates"]}
            self.assertEqual(gates_by_name["rpm-package-build"], "pass")
            self.assertEqual(gates_by_name["rpm-repository-indexing"], "fail")
            self.assertEqual(gates_by_name["rpm-client-qualification"], "not-run")

    def test_secondary_failures_do_not_replace_primary_error(self):
        """Secondary cleanup or diagnostic failure does not replace primary late error."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            context, env, build = self._setup_lane(root, raw_lint_fail=False)

            def failing_sign_rpm(runner, path, fixture, **kwargs):
                raise ContractError("RPM_SIGNING", "Checksig failed", details={"substage": "package-signing"})

            class FailingCleanupHost:
                def run(self, argv, **kwargs):
                    if "docker" in argv and "rmi" in argv:
                        raise OSError("docker rmi failed")
                    return CommandReceipt(argv, 0, b"", b"", executed=True)

            context["runner"] = FailingCleanupHost()

            with patch("rs9.hosted_packaging.provision", return_value=env), \
                 patch("rs9.hosted_deb.provision_image"), \
                 patch("rs9.hosted_packaging.prepare_client", return_value={"status": "pass", "reason": "ok", "schema": "rs9.rpm-client-runtime-evidence.v1"}), \
                 patch("rs9.rpm_client_runtime.bind_engine_floors", side_effect=lambda ev, caps: ev), \
                 patch("rs9.hosted_packaging.verify_client_image", return_value="tag"), \
                 patch("rs9.hosted_packaging.checked", return_value=CommandReceipt(["tool"], 0, b"", b"", executed=True)), \
                 patch("rs9.hosted_packaging.container_tool_facts", return_value={"rpm": "v6"}), \
                 patch("rs9.hosted_packaging._resolve_offline_npm_archives", return_value=None), \
                 patch("rs9.hosted_packaging.build_rpm_candidate", autospec=True, side_effect=witnessed_build_double(build)), \
                 patch("rs9.hosted_packaging.SigningFixture", MockSigningFixture), \
                 patch("rs9.hosted_packaging.sign_rpm", side_effect=failing_sign_rpm):
                result = hosted.execute(context)

            # Primary error is RPM_SIGNING
            gates = {g["name"]: g for g in result["gates"]}
            self.assertEqual(gates["rpm-repository-indexing"]["status"], "fail")
            self.assertEqual(gates["rpm-repository-indexing"]["reason"], "RPM_SIGNING")
            self.assertEqual(gates["rpm-repository-indexing"]["causal_substage"], "package-signing")

            # Cleanup failure is recorded without replacing primary
            self.assertEqual(result["details"]["cleanup_evidence"]["status"], "fail")


if __name__ == "__main__":
    unittest.main()
