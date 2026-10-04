"""Released runtime harnesses must not inherit capture or Actions credentials."""
from pathlib import Path
from types import SimpleNamespace
import json
import os
import shutil
import tempfile
import unittest
from unittest.mock import patch

from rs9.errors import ContractError
from rs9.hosted_smoke import (
    verify_nebular_runtime,
    runtime_evidence,
    snapshot_nebular_runtime,
    compare_drift,
    classify_diagnostic,
    bound_diagnostic,
    _control_verifier,
    _run_verifier,
    prepare_smoke,
)
from rs9.release_core import digest
from rs9.scratch import canonical


class SmokeEnvironmentTests(unittest.TestCase):
    def test_released_verifier_receives_only_runtime_environment(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            (root / "bin").mkdir()
            (root / "bin/tfsb-studio-service").write_bytes(b"fixture")
            (root / "lib/sidecar-payload").mkdir(parents=True)
            (root / "lib/sidecar-payload/manifest.json").write_text("{}")
            prepared = {"scratch": root, "tools": root}
            env = {"PATH": "/usr/bin", "HOME": str(root), "THEME_FORGE_CACHE_DIR": str(root / "cache"),
                   "RS9_GITHUB_READ_TOKEN": "fixture-read-token", "ACTIONS_RUNTIME_TOKEN": "fixture-actions-token"}
            with patch("rs9.hosted_smoke.subprocess.run", return_value=SimpleNamespace(returncode=1)) as run:
                with self.assertRaises(ContractError):
                    verify_nebular_runtime(root, prepared, "x86_64-linux", env=env)
            observed = run.call_args.kwargs["env"]
            self.assertEqual(observed, {k: env[k] for k in ("PATH", "HOME", "THEME_FORGE_CACHE_DIR")})

    def test_runtime_identity_classifies_manifest_drift_without_raw_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp).resolve() / "cache"
            entry = cache / "entries" / ("a" * 64)
            root = entry / "payload/app"
            root.mkdir(parents=True)
            binary = root / "binary"
            binary.write_bytes(b"changed")
            binary.chmod(0o555)
            manifest = root / "manifest.json"
            manifest.write_bytes(b"{}")
            (root / "link").symlink_to("binary")
            rows = [{"path": "app", "type": "directory", "mode": 0o755},
                    {"path": "app/binary", "type": "file", "mode": 0o755, "size": 8, "sha256": digest(b"original")},
                    {"path": "app/manifest.json", "type": "file", "mode": 0o644, "size": 2, "sha256": digest(b"{}")},
                    {"path": "app/link", "type": "symlink", "target": "missing", "mode": 0o777}]
            (entry / "manifest.json").write_bytes(canonical(rows))
            (entry / "meta.json").write_bytes(canonical({"manifest_sha256": "a" * 64, "source_is_store": True}))
            evidence = runtime_evidence(root, binary, manifest)
            self.assertEqual(evidence["expected_member_count"], 4)
            self.assertEqual(evidence["actual_member_count"], 4)
            self.assertEqual(evidence["materializer_source"], "nix-store-tree")
            self.assertEqual(evidence["mismatch_counts"]["bytes"], 1)
            self.assertEqual(evidence["mismatch_counts"]["file_mode"], 1)
            self.assertEqual(evidence["mismatch_counts"]["symlink"], 1)
            self.assertEqual(evidence["classification"], "bytes")
            self.assertEqual(evidence["mismatch_samples"]["file_mode"][0]["expected_mode"], 0o755)
            self.assertEqual(evidence["mismatch_samples"]["file_mode"][0]["actual_mode"], 0o555)
            self.assertNotIn(tmp, json.dumps(evidence))

    @unittest.skipUnless(shutil.which("node"), "Node required for released wrapper execution")
    def test_wrapper_distinguishes_import_and_verification_with_safe_evidence(self):
        for phase in ("import", "verify"):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as tmp:
                work = Path(tmp).resolve()
                root = work / "runtime"
                (root / "bin").mkdir(parents=True)
                (root / "bin/tfsb-studio-service").write_bytes(b"fixture")
                (root / "lib/sidecar-payload").mkdir(parents=True)
                (root / "lib/sidecar-payload/manifest.json").write_bytes(b"{}")
                scratch = work / "smoke"
                scratch.mkdir()
                if phase == "verify":
                    (scratch / "sidecar-common.mjs").write_text("export async function verifyDistribution(){throw new Error('sidecar payload inventory is invalid');}")
                prepared = {"scratch": scratch, "tools": scratch}
                with self.assertRaises(ContractError) as caught:
                    verify_nebular_runtime(root, prepared, "x86_64-linux")
                self.assertEqual(caught.exception.code, "SIDECAR_VERIFIER")
                diagnostic = json.loads((work / "diagnostics/sidecar-verifier.json").read_bytes())
                self.assertEqual(diagnostic["verifier"]["phase"], phase)
                if phase == "verify":
                    self.assertEqual(diagnostic["verifier"]["reason_token"], "payload-inventory")
                    self.assertEqual(diagnostic["classification"], "manifest")
                else:
                    self.assertEqual(diagnostic["classification"], "harness/import/execution")
                self.assertNotIn(tmp, json.dumps(diagnostic))

    def test_physical_evidence_mode_samples_flags_xattrs_and_ancestry(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp).resolve()
            root = work / "payload/app"
            root.mkdir(parents=True)
            (root / "dir").mkdir()
            (root / "dir").chmod(0o700)
            (root / "file.txt").write_bytes(b"hello")
            (root / "file.txt").chmod(0o600)
            manifest = root / "manifest.json"
            manifest.write_bytes(b"{}")
            binary = root / "file.txt"

            expected = [
                {"path": "app", "type": "directory", "mode": 0o755},
                {"path": "app/dir", "type": "directory", "mode": 0o755},
                {"path": "app/file.txt", "type": "file", "mode": 0o644, "size": 5, "sha256": digest(b"hello")},
                {"path": "app/manifest.json", "type": "file", "mode": 0o644, "size": 2, "sha256": digest(b"{}")},
            ]
            evidence = runtime_evidence(root, binary, manifest, expected_members=expected)
            self.assertEqual(evidence["mismatch_counts"]["file_mode"], 1)
            self.assertEqual(evidence["mismatch_counts"]["directory_mode"], 1)
            file_sample = evidence["mismatch_samples"]["file_mode"][0]
            self.assertEqual(file_sample["expected_mode"], 0o644)
            self.assertEqual(file_sample["actual_mode"], 0o600)
            dir_sample = evidence["mismatch_samples"]["directory_mode"][0]
            self.assertEqual(dir_sample["expected_mode"], 0o755)
            self.assertEqual(dir_sample["actual_mode"], 0o700)
            for ancestor in evidence["ancestor_modes"]:
                self.assertIn("uid_is_self", ancestor)
                self.assertIn("group_writable", ancestor)
                self.assertIn("other_writable", ancestor)

    def test_flag_and_xattr_bounded_allowlist_and_unknown_hashing(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp).resolve()
            root = work / "payload/app"
            root.mkdir(parents=True)
            (root / "manifest.json").write_bytes(b"{}")
            binary = root / "binary"
            binary.write_bytes(b"bin")

            with patch("os.listxattr", create=True, return_value=["com.apple.quarantine", "custom.secret.attribute", "user.mime_type"]):
                evidence = runtime_evidence(root, binary, root / "manifest.json")
                self.assertIn("com.apple.quarantine", evidence["extended_attributes"])
                self.assertIn("hash:" + digest(b"user.mime_type"), evidence["extended_attributes"])
                self.assertIn("names", evidence["condition_samples"]["xattrs"][0])
                self.assertIn("hash:" + digest(b"custom.secret.attribute"), evidence["extended_attributes"])
                self.assertNotIn("custom.secret.attribute", json.dumps(evidence))
                self.assertGreater(evidence["extended_attribute_count"], 0)

    def test_diagnostic_classification_precedence_all_ten_tiers(self):
        # 1. harness/import/execution
        v1 = {"status": "fail", "phase": "import", "reason_token": "unclassified-released-verifier-error"}
        e1 = {"mismatch_counts": {"missing": 5, "bytes": 2}}
        self.assertEqual(classify_diagnostic(e1, verifier=v1), "harness/import/execution")

        v1_exec = {"status": "fail", "phase": "execution", "reason_token": "tool-timeout"}
        self.assertEqual(classify_diagnostic(e1, verifier=v1_exec), "harness/import/execution")

        # 2. manifest
        v2 = {"status": "fail", "phase": "verify", "reason_token": "payload-inventory"}
        e2 = {"mismatch_counts": {"missing": 1, "bytes": 1}}
        self.assertEqual(classify_diagnostic(e2, verifier=v2), "manifest")

        # Manifest mismatch beats bytes mismatch
        v_verify = {"status": "fail", "phase": "verify", "reason_token": "runtime-identity"}
        e_manifest_bytes = {"mismatch_counts": {"extra": 1, "bytes": 1, "file_mode": 1}}
        self.assertEqual(classify_diagnostic(e_manifest_bytes, verifier=v_verify), "manifest")

        # 3. bytes
        e3 = {"mismatch_counts": {"bytes": 1, "file_mode": 1}}
        self.assertEqual(classify_diagnostic(e3, verifier=v_verify), "bytes")

        # 4. file_mode
        e4 = {"mismatch_counts": {"file_mode": 1, "directory_mode": 1}}
        self.assertEqual(classify_diagnostic(e4, verifier=v_verify), "file_mode")

        # 5. dir_mode
        e5 = {"mismatch_counts": {"directory_mode": 1, "symlink": 1}}
        self.assertEqual(classify_diagnostic(e5, verifier=v_verify), "dir_mode")

        # 6. symlink
        e6 = {"mismatch_counts": {"symlink": 1}}
        self.assertEqual(classify_diagnostic(e6, verifier=v_verify), "symlink")

        # 7. ancestry
        e7 = {"mismatch_counts": {}, "ancestor_modes": [{"symlink": True, "mode": 0o755, "uid_is_self": True, "group_writable": False, "other_writable": False}]}
        self.assertEqual(classify_diagnostic(e7, verifier=v_verify), "ancestry")

        # 8. flags/xattr
        e8 = {"mismatch_counts": {}, "extended_attribute_count": 1, "ancestor_modes": []}
        self.assertEqual(classify_diagnostic(e8, verifier=v_verify), "flags/xattr")

        # 9. post-probe-drift
        drift9 = {"has_drift": True, "drift_counts": {"modified": 1}, "drift_samples": {"modified": [{"path": "app/bin/service"}]}}
        e9 = {"mismatch_counts": {}, "ancestor_modes": [], "mismatch_samples": {"runtime": [{"path": "app/bin/service"}]}}
        self.assertEqual(classify_diagnostic(e9, verifier=v_verify, drift=drift9), "post-probe-drift")

        # 10. dedicated verifier-rejected when verify failed no specific cause
        e10 = {"mismatch_counts": {}, "ancestor_modes": []}
        self.assertEqual(classify_diagnostic(e10, verifier=v_verify), "verifier-rejected")

        # Pass: no issues
        v_pass = {"status": "pass"}
        self.assertIsNone(classify_diagnostic(e10, verifier=v_pass))

    def test_snapshot_nebular_runtime_and_drift_detection(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp).resolve()
            root = work / "runtime"
            (root / "bin").mkdir(parents=True)
            binary = root / "bin/tfsb-studio-service"
            binary.write_bytes(b"binary-content")
            binary.chmod(0o755)
            payload = root / "lib/sidecar-payload"
            payload.mkdir(parents=True)
            manifest = payload / "manifest.json"
            manifest.write_bytes(b"{}")
            (payload / "data.txt").write_bytes(b"data-v1")
            scratch = work / "scratch"
            scratch.mkdir()
            prepared = {"scratch": scratch, "tools": scratch}

            # Take baseline snapshot
            baseline = snapshot_nebular_runtime(root, prepared, "x86_64-linux")
            self.assertEqual(baseline["schema"], "rs9.nebular-runtime-baseline.v1alpha1")
            self.assertIn("runtime_root_sha256", baseline)
            self.assertIn("members", baseline)

            # Compare drift with no changes
            no_drift = compare_drift(baseline, root, baseline["evidence"])
            self.assertFalse(no_drift["has_drift"])
            self.assertEqual(no_drift["drift_counts"]["modified"], 0)

            # Introduce probe drift: modify a file and add a file
            (payload / "data.txt").write_bytes(b"data-v2-probed")
            (payload / "probe_output.tmp").write_bytes(b"probe-cache")

            curr_evidence, curr_members = runtime_evidence(root, binary, manifest, return_members=True)
            drift = compare_drift(baseline, root, curr_evidence, current_members=curr_members)
            self.assertTrue(drift["has_drift"])
            self.assertGreater(drift["drift_counts"]["modified"], 0)
            self.assertGreater(drift["drift_counts"]["added"], 0)
            self.assertEqual(classify_diagnostic(curr_evidence, drift=drift), "post-probe-drift")

    def test_control_verifier_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp).resolve()
            archive = work / "payload.tar.gz"
            import tarfile, io
            bio = io.BytesIO()
            with tarfile.open(fileobj=bio, mode="w:gz") as tar:
                app_info = tarfile.TarInfo("app")
                app_info.type = tarfile.DIRTYPE
                app_info.mode = 0o755
                tar.addfile(app_info)

                bin_dir = tarfile.TarInfo("app/bin")
                bin_dir.type = tarfile.DIRTYPE
                bin_dir.mode = 0o755
                tar.addfile(bin_dir)

                bin_info = tarfile.TarInfo("app/bin/tfsb-studio-service")
                bin_info.size = 6
                bin_info.mode = 0o755
                tar.addfile(bin_info, io.BytesIO(b"binary"))

                lib_dir = tarfile.TarInfo("app/lib")
                lib_dir.type = tarfile.DIRTYPE
                lib_dir.mode = 0o755
                tar.addfile(lib_dir)

                sidecar_dir = tarfile.TarInfo("app/lib/sidecar-payload")
                sidecar_dir.type = tarfile.DIRTYPE
                sidecar_dir.mode = 0o755
                tar.addfile(sidecar_dir)

                man_info = tarfile.TarInfo("app/lib/sidecar-payload/manifest.json")
                man_bytes = b"{}"
                man_info.size = len(man_bytes)
                man_info.mode = 0o644
                tar.addfile(man_info, io.BytesIO(man_bytes))

            archive_data = bio.getvalue()
            archive.write_bytes(archive_data)
            archive_sha = digest(archive_data)

            members = [
                {"path": "app", "type": "directory", "mode": 0o755},
                {"path": "app/bin", "type": "directory", "mode": 0o755},
                {"path": "app/bin/tfsb-studio-service", "type": "file", "mode": 0o755, "size": 6, "sha256": digest(b"binary")},
                {"path": "app/lib", "type": "directory", "mode": 0o755},
                {"path": "app/lib/sidecar-payload", "type": "directory", "mode": 0o755},
                {"path": "app/lib/sidecar-payload/manifest.json", "type": "file", "mode": 0o644, "size": 2, "sha256": digest(man_bytes)},
            ]
            man_sha = digest(canonical(members))
            manifest_doc = {"manifest_sha256": man_sha, "members": members}

            capture = SimpleNamespace(
                record={"payloads": [{"id": "asset-1", "platforms": ["x86_64-linux"], "sha256": archive_sha, "payload_manifest_sha256": man_sha}]},
                archives={"asset-1": archive},
                manifests={"asset-1": manifest_doc},
            )
            scratch = work / "scratch"
            scratch.mkdir()
            script = scratch / "verify.mjs"
            script.write_text("console.log(JSON.stringify({status:'pass',result:{verified:true}}));")
            prepared = {"scratch": scratch, "tools": scratch}

            fake_runtime_identity = {
                "actual_member_count": 6,
                "runtime_root_sha256": "0" * 64,
            }
            env = {"PATH": os.environ.get("PATH", "/usr/bin")}
            res = _control_verifier(capture, "x86_64-linux", prepared, script, prefix=(), env=env, runtime_identity=fake_runtime_identity)
            self.assertEqual(res["status"], "pass")
            self.assertIn("runtime_identity", res)
            self.assertIn("comparison_to_runtime", res)
            self.assertTrue(res["comparison_to_runtime"]["counts_equal"])
            self.assertFalse(res["comparison_to_runtime"]["hash_equal"])
            self.assertIn("mismatch_count_deltas", res["comparison_to_runtime"])
            # Control never satisfies installed gate:
            self.assertFalse(res["satisfies_installed_gate"])

    def test_pathological_bounds_and_sample_max_preserves_counts_and_classification(self):
        # Create diagnostic with pathological long paths (e.g. 5,000 chars) and max samples
        long_path = "nested/" * 250 + "very_deep_file.txt"
        self.assertGreater(len(long_path), 1500)

        samples = {
            "missing": [{"path": long_path, "expected": 1, "actual": 2} for _ in range(50)],
            "bytes": [{"path": long_path, "expected_size": 100, "actual_size": 200} for _ in range(50)],
            "file_mode": [{"path": long_path, "expected_mode": 0o644, "actual_mode": 0o777} for _ in range(50)],
            "directory_mode": [{"path": long_path, "expected_mode": 0o755, "actual_mode": 0o777} for _ in range(50)],
            "symlink": [{"path": long_path} for _ in range(50)],
            "extra": [{"path": long_path} for _ in range(50)],
            "type": [{"path": long_path} for _ in range(50)],
        }
        counts = {k: 50 for k in samples}
        drift_samples = {
            "modified": [{"path": long_path} for _ in range(50)],
            "added": [{"path": long_path} for _ in range(50)],
            "removed": [{"path": long_path} for _ in range(50)],
            "mode": [{"path": long_path, "baseline_mode": 0o644, "current_mode": 0o777} for _ in range(50)],
        }
        drift_counts = {k: 50 for k in drift_samples}

        diag = {
            "schema": "rs9.sidecar-verifier-diagnostic.v1alpha1",
            "system": "x86_64-linux",
            "product": "theme-forge-nebular-fusion",
            "substage": "released-sidecar-verifier",
            "runtime_root_sha256": "a" * 64,
            "actual_member_count": 500,
            "expected_member_count": 500,
            "materializer_source": "nix-store-tree",
            "mismatch_counts": counts,
            "mismatch_samples": samples,
            "ancestor_modes": [{"symlink": False, "mode": 0o755, "uid_is_self": True, "group_writable": False, "other_writable": False} for _ in range(20)],
            "nonzero_file_flags_count": 0,
            "extended_attribute_count": 10,
            "file_flags": [],
            "extended_attributes": ["hash:" + digest(f"attr{i}".encode()) for i in range(10)],
            "sidecar_binary_sha256": "b" * 64,
            "sidecar_manifest_sha256": "c" * 64,
            "verifier": {"status": "fail", "phase": "verify", "reason_token": "runtime-identity"},
            "drift": {
                "has_drift": True,
                "baseline_runtime_root_sha256": "1" * 64,
                "current_runtime_root_sha256": "2" * 64,
                "baseline_member_count": 500,
                "current_member_count": 500,
                "drift_counts": drift_counts,
                "drift_samples": drift_samples,
            },
            "classification": "manifest",
        }
        diag["archive_control"] = {"runtime_identity": {"mismatch_counts": counts, "mismatch_samples": samples},
                                   "satisfies_installed_gate": False}

        bounded = bound_diagnostic(diag, max_bytes=60 * 1024)
        encoded = canonical(bounded)
        self.assertLessEqual(len(encoded), 60 * 1024)
        # Counts and classification must be preserved
        self.assertEqual(bounded["mismatch_counts"], counts)
        self.assertEqual(bounded["drift"]["drift_counts"], drift_counts)
        self.assertEqual(bounded["classification"], "manifest")
        self.assertEqual(bounded["actual_member_count"], 500)
        self.assertFalse(bounded["archive_control"]["satisfies_installed_gate"])

    def test_minimal_diagnostic_retains_raw_verifier_phase(self):
        value = {"classification": "verifier-rejected", "mismatch_counts": {},
                 "verifier": {"status": "fail", "phase": "verify", "reason_token": "runtime-identity",
                              "stdout_sha256": "1" * 64, "stderr_sha256": "2" * 64, "exit_code": 2},
                 "padding": {str(i): "x" * 256 for i in range(100)}}
        result = bound_diagnostic(value, max_bytes=1024)
        self.assertEqual(result["classification"], "verifier-rejected")
        self.assertEqual(result["verifier"]["phase"], "verify")
        self.assertEqual(result["verifier"]["stderr_sha256"], "2" * 64)
        self.assertLessEqual(len(canonical(result)), 1024)

    def test_drift_precedence_and_verifier_rejected(self):
        # Case 1: Verifier rejected with no specific cause
        identity_clean = {"mismatch_counts": {}, "mismatch_samples": {}, "nonzero_file_flags_count": 0, "file_flags": []}
        verifier_fail_no_cause = {"status": "fail", "phase": "verify", "reason_token": "unknown-error"}
        self.assertEqual(classify_diagnostic(identity_clean, verifier=verifier_fail_no_cause), "verifier-rejected")

        # Case 2: Both flags and drift present; verifier failed with reason token "runtime-identity"
        identity_with_flags = {
            "mismatch_counts": {},
            "mismatch_samples": {},
            "nonzero_file_flags_count": 1,
            "file_flags": ["UF_HIDDEN"],
        }
        drift_active = {
            "has_drift": True,
            "drift_counts": {"modified": 1},
            "drift_samples": {"modified": [{"path": "app/bin/service"}]},
        }
        verifier_runtime = {"status": "fail", "phase": "verify", "reason_token": "runtime-identity"}
        # A broad runtime token alone cannot attribute unrelated drift to failure.
        self.assertEqual(classify_diagnostic(identity_with_flags, verifier=verifier_runtime, drift=drift_active), "flags/xattr")
        self.assertEqual(classify_diagnostic({"mismatch_counts": {}}, verifier=verifier_runtime, drift=drift_active), "verifier-rejected")

        # Case 3: Both flags and drift present; drift intersects mismatch samples
        identity_with_mismatch = {
            "mismatch_counts": {},
            "mismatch_samples": {"bytes": [{"path": "app/bin/service"}]},
            "nonzero_file_flags_count": 1,
            "file_flags": ["UF_HIDDEN"],
        }
        verifier_unknown = {"status": "fail", "phase": "verify", "reason_token": "unclassified-error"}
        # Drift takes precedence over flags because of path intersection
        self.assertEqual(classify_diagnostic(identity_with_mismatch, verifier=verifier_unknown, drift=drift_active), "post-probe-drift")

        # Case 4: Both flags and drift present; no correspondence (no intersection, unknown reason token)
        identity_disjoint = {
            "mismatch_counts": {},
            "mismatch_samples": {"bytes": [{"path": "app/other/file"}]},
            "nonzero_file_flags_count": 1,
            "file_flags": ["UF_HIDDEN"],
        }
        # Flags take precedence over drift when there is no correspondence
        self.assertEqual(classify_diagnostic(identity_disjoint, verifier=verifier_unknown, drift=drift_active), "flags/xattr")

    def test_multi_family_sidecar_verifier_retains_invocation_identities_and_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp).resolve()
            root = work / "runtime"
            (root / "bin").mkdir(parents=True)
            (root / "bin/tfsb-studio-service").write_bytes(b"fixture-binary")
            (root / "lib/sidecar-payload").mkdir(parents=True)
            (root / "lib/sidecar-payload/manifest.json").write_bytes(b"{}")

            families = ["apt", "dnf", "pacman"]
            tokens = {"apt": "payload-inventory", "dnf": "runtime-identity", "pacman": "tool-timeout"}
            for fam in families:
                scratch = work / f"smoke-{fam}"
                scratch.mkdir()
                (scratch / "sidecar-common.mjs").write_text(
                    f"export async function verifyDistribution(){{throw new Error('error for {fam}');}}"
                )
                prepared = {"scratch": scratch, "tools": scratch}
                with patch("rs9.hosted_smoke._run_verifier", return_value=(
                    {"status": "fail", "phase": "verify", "reason_token": tokens[fam], "exit_code": 2,
                     "stdout_sha256": digest(fam.encode()), "stderr_sha256": digest(b"err")}, None
                )):
                    with self.assertRaises(ContractError) as caught:
                        verify_nebular_runtime(root, prepared, "x86_64-linux")
                    self.assertEqual(caught.exception.code, "SIDECAR_VERIFIER")

            diag_dir = work / "diagnostics"
            self.assertTrue(diag_dir.is_dir())
            for fam in families:
                diag_file = diag_dir / f"sidecar-verifier-{fam}.json"
                self.assertTrue(diag_file.is_file(), f"Missing diagnostic for family {fam}")
                diag = json.loads(diag_file.read_bytes())
                self.assertEqual(diag["family"], fam)
                self.assertEqual(diag["invocation"], fam)
                self.assertEqual(diag["verifier"]["reason_token"], tokens[fam])
                self.assertEqual(diag["verifier"]["stdout_sha256"], digest(fam.encode()))

            # Single invocation layout with scratch "smoke" (no family prefix) writes sidecar-verifier.json
            single_scratch = work / "smoke"
            single_scratch.mkdir()
            (single_scratch / "sidecar-common.mjs").write_text("export async function verifyDistribution(){throw new Error('single');}")
            prepared_single = {"scratch": single_scratch, "tools": single_scratch}
            with patch("rs9.hosted_smoke._run_verifier", return_value=(
                {"status": "fail", "phase": "verify", "reason_token": "actual-input-identity", "exit_code": 2,
                 "stdout_sha256": digest(b"single"), "stderr_sha256": digest(b"err")}, None
            )):
                with self.assertRaises(ContractError):
                    verify_nebular_runtime(root, prepared_single, "x86_64-linux")
            single_file = diag_dir / "sidecar-verifier.json"
            self.assertTrue(single_file.is_file())
            single_diag = json.loads(single_file.read_bytes())
            self.assertNotIn("family", single_diag)
            self.assertEqual(single_diag["verifier"]["reason_token"], "actual-input-identity")

    def test_causal_drift_with_actual_runtime_evidence_and_flags_xattrs(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp).resolve()
            root = work / "runtime"
            (root / "bin").mkdir(parents=True)
            binary = root / "bin/tfsb-studio-service"
            binary.write_bytes(b"studio-binary")
            binary.chmod(0o755)
            payload = root / "lib/sidecar-payload"
            payload.mkdir(parents=True)
            manifest_file = payload / "manifest.json"
            manifest_file.write_bytes(b"{}")
            data_file = payload / "data.txt"
            data_file.write_bytes(b"original-data-v1")

            scratch = work / "scratch"
            scratch.mkdir()
            prepared = {"scratch": scratch, "tools": scratch}

            members = [
                {"path": "runtime", "type": "directory", "mode": 0o755},
                {"path": "runtime/bin", "type": "directory", "mode": 0o755},
                {"path": "runtime/bin/tfsb-studio-service", "type": "file", "mode": 0o755, "size": len(b"studio-binary"), "sha256": digest(b"studio-binary")},
                {"path": "runtime/lib", "type": "directory", "mode": 0o755},
                {"path": "runtime/lib/sidecar-payload", "type": "directory", "mode": 0o755},
                {"path": "runtime/lib/sidecar-payload/manifest.json", "type": "file", "mode": 0o644, "size": len(b"{}"), "sha256": digest(b"{}")},
                {"path": "runtime/lib/sidecar-payload/data.txt", "type": "file", "mode": 0o644, "size": len(b"original-data-v1"), "sha256": digest(b"original-data-v1")},
            ]

            # Snapshot baseline before mutation, with simulated flags/xattr
            with patch("os.listxattr", create=True, return_value=["com.apple.quarantine"]):
                baseline_evidence, baseline_members = runtime_evidence(root, binary, manifest_file, expected_members=members, return_members=True)
                baseline = {
                    "schema": "rs9.nebular-runtime-baseline.v1alpha1",
                    "system": "x86_64-linux",
                    "runtime_root_sha256": baseline_evidence["runtime_root_sha256"],
                    "actual_member_count": baseline_evidence["actual_member_count"],
                    "members": baseline_members,
                    "evidence": baseline_evidence,
                }
                self.assertEqual(baseline_evidence["mismatch_counts"]["bytes"], 0)
                self.assertGreater(baseline_evidence["extended_attribute_count"], 0)

                # Mutate data.txt (simulating probe runtime mutation)
                data_file.write_bytes(b"mutated-during-probe-run")

                # Run actual runtime_evidence post-mutation
                current_evidence, current_members = runtime_evidence(root, binary, manifest_file, expected_members=members, return_members=True)
                # Actual nonzero mismatch count:
                self.assertEqual(current_evidence["mismatch_counts"]["bytes"], 1)
                self.assertEqual(current_evidence["mismatch_samples"]["bytes"][0]["path"], "runtime/lib/sidecar-payload/data.txt")
                self.assertGreater(current_evidence["extended_attribute_count"], 0)

                # Run actual compare_drift
                drift = compare_drift(baseline, root, current_evidence, current_members=current_members)
                self.assertTrue(drift["has_drift"])
                self.assertEqual(drift["drift_counts"]["modified"], 1)
                self.assertEqual(drift["drift_samples"]["modified"][0]["path"], "runtime/lib/sidecar-payload/data.txt")

                # Verifier reports verify failure with runtime-identity reason
                verifier = {"status": "fail", "phase": "verify", "reason_token": "runtime-identity"}
                # Causal drift takes precedence over bytes and flags/xattr
                classification = classify_diagnostic(current_evidence, verifier=verifier, drift=drift)
                self.assertEqual(classification, "post-probe-drift")

    def test_unrelated_drift_does_not_override_established_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp).resolve()
            root = work / "runtime"
            (root / "bin").mkdir(parents=True)
            binary = root / "bin/tfsb-studio-service"
            # Binary has corrupted bytes from initial installation/materialization
            binary.write_bytes(b"corrupted-at-install")
            binary.chmod(0o755)
            payload = root / "lib/sidecar-payload"
            payload.mkdir(parents=True)
            manifest_file = payload / "manifest.json"
            manifest_file.write_bytes(b"{}")
            data_file = payload / "data.txt"
            data_file.write_bytes(b"original-data")

            # Expected manifest has original expected bytes for both files
            members = [
                {"path": "runtime", "type": "directory", "mode": 0o755},
                {"path": "runtime/bin", "type": "directory", "mode": 0o755},
                {"path": "runtime/bin/tfsb-studio-service", "type": "file", "mode": 0o755, "size": len(b"expected-clean-binary"), "sha256": digest(b"expected-clean-binary")},
                {"path": "runtime/lib", "type": "directory", "mode": 0o755},
                {"path": "runtime/lib/sidecar-payload", "type": "directory", "mode": 0o755},
                {"path": "runtime/lib/sidecar-payload/manifest.json", "type": "file", "mode": 0o644, "size": len(b"{}"), "sha256": digest(b"{}")},
                {"path": "runtime/lib/sidecar-payload/data.txt", "type": "file", "mode": 0o644, "size": len(b"original-data"), "sha256": digest(b"original-data")},
            ]

            with patch("os.listxattr", create=True, return_value=["com.apple.quarantine"]):
                baseline_evidence, baseline_members = runtime_evidence(root, binary, manifest_file, expected_members=members, return_members=True)
                baseline = {
                    "schema": "rs9.nebular-runtime-baseline.v1alpha1",
                    "system": "x86_64-linux",
                    "runtime_root_sha256": baseline_evidence["runtime_root_sha256"],
                    "actual_member_count": baseline_evidence["actual_member_count"],
                    "members": baseline_members,
                    "evidence": baseline_evidence,
                }
                # Already mismatched on binary before mutation:
                self.assertEqual(baseline_evidence["mismatch_counts"]["bytes"], 1)

                # Now probe mutates data.txt
                data_file.write_bytes(b"probe-modified-data")

                current_evidence, current_members = runtime_evidence(root, binary, manifest_file, expected_members=members, return_members=True)
                # Now 2 bytes mismatches: binary and data.txt
                self.assertEqual(current_evidence["mismatch_counts"]["bytes"], 2)

                drift = compare_drift(baseline, root, current_evidence, current_members=current_members)
                self.assertTrue(drift["has_drift"])
                # Only data.txt drifted:
                self.assertEqual(drift["drift_counts"]["modified"], 1)
                self.assertEqual(drift["drift_samples"]["modified"][0]["path"], "runtime/lib/sidecar-payload/data.txt")

                verifier = {"status": "fail", "phase": "verify", "reason_token": "runtime-identity"}
                # Unrelated drift of data.txt must NOT override established bytes mismatch on binary!
                classification = classify_diagnostic(current_evidence, verifier=verifier, drift=drift)
                self.assertEqual(classification, "bytes")

    def test_drift_on_already_corrupt_file_does_not_replace_existing_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve() / "runtime"
            root.mkdir()
            binary, manifest = root / "binary", root / "manifest.json"
            binary.write_bytes(b"authenticated-binary")
            manifest.write_bytes(b"{}")
            _, expected = runtime_evidence(root, binary, manifest, return_members=True)
            binary.write_bytes(b"corrupt-at-install")
            before, before_members = runtime_evidence(root, binary, manifest, list(expected.values()), return_members=True)
            self.assertEqual(before["mismatch_counts"]["bytes"], 1)
            baseline = {"runtime_root_sha256": before["runtime_root_sha256"],
                        "actual_member_count": before["actual_member_count"],
                        "members": before_members, "evidence": before}
            binary.write_bytes(b"changed-further-by-probe")
            after, after_members = runtime_evidence(root, binary, manifest, list(expected.values()), return_members=True)
            drift = compare_drift(baseline, root, after, current_members=after_members)
            self.assertTrue(drift["has_drift"])
            self.assertEqual(classify_diagnostic(after, {"status": "fail", "phase": "verify", "reason_token": "runtime-identity"}, drift), "bytes")

    def test_truncated_mismatch_samples_cannot_prove_causal_drift(self):
        identity = {"mismatch_counts": {"bytes": 11},
                    "mismatch_samples": {"bytes": [{"path": f"runtime/file-{i}"} for i in range(10)]}}
        drift = {"has_drift": True, "drift_counts": {"modified": 11},
                 "drift_samples": {"modified": [{"path": f"runtime/file-{i}"} for i in range(10)]}}
        verifier = {"status": "fail", "phase": "verify", "reason_token": "runtime-identity"}
        self.assertEqual(classify_diagnostic(identity, verifier, drift), "bytes")

    def test_unparseable_or_absent_verifier_output_retains_honest_raw_phase(self):
        script = Path("/fake/script.mjs")
        # 1. Unparseable stdout
        with patch("rs9.hosted_smoke.subprocess.run", return_value=SimpleNamespace(returncode=1, stdout=b"segmentation fault (core dumped)\n", stderr=b"crash log\n")):
            evidence, res = _run_verifier(script, "/fake/bin", "/fake/payload", (), {})
            self.assertIsNone(res)
            self.assertEqual(evidence["status"], "fail")
            self.assertIn(evidence["phase"], ("unavailable", "unknown"))
            self.assertEqual(evidence["phase"], "unknown")
            self.assertEqual(evidence["reason_token"], "unclassified-released-verifier-error")
            self.assertEqual(evidence["exit_code"], 1)
            self.assertEqual(evidence["stdout_sha256"], digest(b"segmentation fault (core dumped)\n"))
            self.assertEqual(evidence["stderr_sha256"], digest(b"crash log\n"))
            self.assertEqual(classify_diagnostic({}, verifier=evidence), "harness/import/execution")

        # 2. Absent (empty) stdout
        with patch("rs9.hosted_smoke.subprocess.run", return_value=SimpleNamespace(returncode=137, stdout=b"", stderr=b"killed\n")):
            evidence, res = _run_verifier(script, "/fake/bin", "/fake/payload", (), {})
            self.assertIsNone(res)
            self.assertEqual(evidence["status"], "fail")
            self.assertEqual(evidence["phase"], "unknown")
            self.assertEqual(evidence["exit_code"], 137)
            self.assertEqual(evidence["stdout_sha256"], digest(b""))
            self.assertEqual(evidence["stderr_sha256"], digest(b"killed\n"))
            self.assertEqual(classify_diagnostic({}, verifier=evidence), "harness/import/execution")

        # 3. Explicit phase preserved when doc is dict
        for test_phase in ("unavailable", "unknown", "import", "verify", "output"):
            doc_bytes = json.dumps({"status": "fail", "phase": test_phase, "reason_token": "tool-unavailable"}).encode()
            with patch("rs9.hosted_smoke.subprocess.run", return_value=SimpleNamespace(returncode=2, stdout=doc_bytes, stderr=b"")):
                evidence, _ = _run_verifier(script, "/fake/bin", "/fake/payload", (), {})
                self.assertEqual(evidence["phase"], test_phase)
