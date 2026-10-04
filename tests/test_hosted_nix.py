"""Nix candidate source binds real outputs and fails before a build without capture."""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from rs9.errors import ContractError
from rs9.hosted_nix import command, execute, prepare_input, SYSTEMS
from rs9.scratch import canonical

ROOT = Path(__file__).resolve().parents[1]


class NixHostedTests(unittest.TestCase):
    def test_real_tool_failure_is_not_an_output_digest(self):
        from subprocess import CompletedProcess
        with patch("rs9.hosted_nix.subprocess.run", return_value=CompletedProcess(["nix", "build"], 1, b"", b"error")):
            with self.assertRaises(ContractError):
                command(["nix", "build"])

    def test_unsupported_system_refused(self):
        with self.assertRaises(ContractError):
            execute({"system": "windows", "repository": ROOT, "scratch": ROOT})

    def test_source_has_real_build_and_path_info_contract(self):
        source = (ROOT / "src/rs9/hosted_nix.py").read_text()
        self.assertIn('"nix", "build"', source)
        self.assertIn('"nix", "path-info"', source)
        self.assertNotIn("compute_bounded_out_hash", source)
        self.assertEqual(SYSTEMS, {"aarch64-darwin", "x86_64-linux", "aarch64-linux"})

    def test_nix_uses_store_materializer_and_full_fhs_runtime(self):
        source = (ROOT / "nix/nebular.nix").read_text()
        self.assertIn("buildFHSEnv", source)
        self.assertIn("webkitgtk_4_1", source)
        self.assertIn("dontFixup = true", source)
        self.assertIn("runtime/launch.py", source)
        self.assertIn("${payload}/payload.tar.gz", source)

    def test_nebular_archive_in_store_materializer_contract(self):
        hosted_source = (ROOT / "src/rs9/hosted_nix.py").read_text()
        self.assertIn("payload.tar.gz", hosted_source)
        self.assertIn("source_is_store=False", hosted_source)
        self.assertIn("materialize_payload", hosted_source)

    def test_prepare_input_creates_archive_and_manifest_in_capture(self):
        with tempfile.TemporaryDirectory() as td:
            scratch = Path(td) / "scratch"
            scratch.mkdir()

            mock_archive = Path(td) / "nebular.tar.gz"
            mock_archive.write_bytes(b"dummy-nebular-tar-gz")
            from rs9.release_core import digest
            archive_digest = digest(mock_archive.read_bytes())
            manifest_members = [{"path": "theme-forge-nebular-fusion/bin/tfnf", "type": "file", "size": 10, "sha256": "abc", "mode": 0o755}]
            manifest_hash = "m" * 64

            mock_capture = Mock()
            mock_capture.record = {"payloads": [{
                "id": "theme-forge-nebular-fusion",
                "name": "theme-forge-nebular-fusion-0.6.1-x86_64-linux.tar.gz",
                "platforms": ["x86_64-linux"],
                "sha256": archive_digest,
                "payload_manifest_sha256": manifest_hash,
                "launchers": {"tfnf": {"path": "theme-forge-nebular-fusion/bin/tfnf"}},
            }]}
            mock_capture.archives = {"theme-forge-nebular-fusion": mock_archive}
            mock_capture.manifests = {"theme-forge-nebular-fusion": {"members": manifest_members, "manifest_sha256": manifest_hash, "root": "theme-forge-nebular-fusion"}}

            mock_node_archive = Path(td) / "node.tar.gz"
            mock_node_archive.write_bytes(b"dummy-node-tar-gz")
            node_digest = digest(mock_node_archive.read_bytes())

            captures = []
            for pid in ("theme-forge-stellar-burst", "theme-forge-stellar-loom", "theme-forge-solar-sail"):
                c = Mock()
                c.record = {"payloads": [{"id": pid, "name": f"{pid}-0.6.1.tgz", "sha256": node_digest}]}
                c.archives = {pid: mock_node_archive}
                c.manifests = {pid: {"members": [], "manifest_sha256": "h" * 64, "root": "package"}}
                captures.append((c, {"project": {"id": pid}}, {}))
            captures.append((mock_capture, {"project": {"id": "theme-forge-nebular-fusion"}}, {}))

            context = {
                "system": "x86_64-linux",
                "repository": ROOT,
                "scratch": scratch,
                "captures": captures,
                "client": Mock(),
            }

            with patch("rs9.hosted_nix.stage_payload"), patch("rs9.hosted_nix._resolve_offline_npm_archives", return_value=[]), patch("rs9.hosted_nix.stage_offline_npm_closure"):
                source, capture_input, products = prepare_input(context)

            neb_dir = capture_input / "payloads/theme-forge-nebular-fusion"
            self.assertTrue((neb_dir / "payload.tar.gz").is_file())
            self.assertTrue((neb_dir / "manifest.json").is_file())
            self.assertEqual((neb_dir / "payload.tar.gz").read_bytes(), b"dummy-nebular-tar-gz")

            launch_code = (capture_input / "runtime/launch.py").read_text()
            self.assertIn("source_is_store=False", launch_code)
            self.assertIn(repr(manifest_hash), launch_code)

    def test_prepare_input_rejects_nonmatching_platform(self):
        with tempfile.TemporaryDirectory() as td:
            scratch = Path(td) / "scratch"
            scratch.mkdir()

            mock_archive = Path(td) / "nebular.tar.gz"
            mock_archive.write_bytes(b"dummy-nebular-tar-gz")
            from rs9.release_core import digest
            archive_digest = digest(mock_archive.read_bytes())

            mock_capture = Mock()
            # Payload claims darwin only, but system requested is x86_64-linux
            mock_capture.record = {"payloads": [{
                "id": "theme-forge-nebular-fusion",
                "name": "theme-forge-nebular-fusion-0.6.1-x86_64-linux.tar.gz",
                "platforms": ["aarch64-darwin"],
                "sha256": archive_digest,
                "payload_manifest_sha256": "m" * 64,
                "launchers": {"tfnf": {"path": "theme-forge-nebular-fusion/bin/tfnf"}},
            }]}
            mock_capture.archives = {"theme-forge-nebular-fusion": mock_archive}
            mock_capture.manifests = {"theme-forge-nebular-fusion": {"members": [], "manifest_sha256": "m" * 64, "root": "root"}}

            context = {
                "system": "x86_64-linux",
                "repository": ROOT,
                "scratch": scratch,
                "captures": [
                    (mock_capture, {"project": {"id": "theme-forge-stellar-burst"}}, {}),
                    (mock_capture, {"project": {"id": "theme-forge-stellar-loom"}}, {}),
                    (mock_capture, {"project": {"id": "theme-forge-solar-sail"}}, {}),
                    (mock_capture, {"project": {"id": "theme-forge-nebular-fusion"}}, {}),
                ],
                "client": Mock(),
            }

            with patch("rs9.hosted_nix.stage_payload"), patch("rs9.hosted_nix._resolve_offline_npm_archives", return_value=[]), patch("rs9.hosted_nix.stage_offline_npm_closure"):
                with self.assertRaises(ContractError) as ctx:
                    prepare_input(context)
                self.assertEqual(ctx.exception.code, "MISSING_ASSET")

    def test_execute_checks_installer_failure_first_with_sanitized_errors(self):
        with tempfile.TemporaryDirectory() as td:
            scratch = Path(td) / "scratch"
            scratch.mkdir()
            runner_temp = Path(td) / "runner_temp"
            install_dir = runner_temp / "rs9-nix-install"
            install_dir.mkdir(parents=True)

            # Failure file exists, but installer-identity.json does NOT exist
            failure_doc = {
                "status": "fail",
                "code": "NIX_EXTRACT_UNSAFE",
                "detail": "Symlink traversal rejected",
                "secret_info": "should-not-leak",
            }
            (install_dir / "installer-failure.json").write_bytes(canonical(failure_doc))

            context = {
                "system": "x86_64-linux",
                "repository": ROOT,
                "scratch": scratch,
                "pins": {
                    "nix": {
                        "installer_version": "2.31.2",
                        "installer_sha256_by_system": {
                            "aarch64-darwin": "3baa0af88a1ef4e2cc82cb64cd384b1805ecc3771b574e97277ae213d52711d8",
                            "x86_64-linux": "d1f67c86eed016214864ba08bfb9529c307aea7e8fafb74853f96fcc3bfd8a60",
                            "aarch64-linux": "64db528412096d718b4bf8f78f85e5ac2b714b774e5005500dee37d23f560456",
                        },
                        "nixpkgs_revision": "0" * 40,
                        "nixpkgs_nar_hash": "sha256-hash",
                    }
                }
            }

            with patch.dict(os.environ, {"RUNNER_TEMP": str(runner_temp)}):
                with self.assertRaises(ContractError) as ctx:
                    execute(context)
                self.assertEqual(ctx.exception.code, "NIX_INSTALLER")
                self.assertEqual(ctx.exception.details.get("reason"), "NIX_EXTRACT_UNSAFE")
                self.assertNotIn("diagnostic_token", ctx.exception.details)
                self.assertEqual(ctx.exception.details.get("system"), "x86_64-linux")
                self.assertNotIn("secret_info", ctx.exception.details)
                # Failure must be copied into scratch
                self.assertTrue((scratch / "diagnostics/installer-failure.json").is_file())
                retained = (scratch / "diagnostics/installer-failure.json").read_text()
                self.assertNotIn("secret_info", retained)
                self.assertNotIn("should-not-leak", retained)

    def test_execute_retains_installer_identity_and_verifies_system_pin(self):
        with tempfile.TemporaryDirectory() as td:
            scratch = Path(td) / "scratch"
            scratch.mkdir()
            runner_temp = Path(td) / "runner_temp"
            install_dir = runner_temp / "rs9-nix-install"
            install_dir.mkdir(parents=True)

            pin_val = "d1f67c86eed016214864ba08bfb9529c307aea7e8fafb74853f96fcc3bfd8a60"
            identity_doc = {
                "version": "2.31.2",
                "system": "x86_64-linux",
                "sha256": pin_val,
                "pin_provenance": "source-pinned",
                "status": "pass",
            }
            (install_dir / "installer-identity.json").write_bytes(canonical(identity_doc))

            context = {
                "system": "x86_64-linux",
                "repository": ROOT,
                "scratch": scratch,
                "pins": {
                    "nix": {
                        "installer_version": "2.31.2",
                        "installer_sha256_by_system": {
                            "aarch64-darwin": "3baa0af88a1ef4e2cc82cb64cd384b1805ecc3771b574e97277ae213d52711d8",
                            "x86_64-linux": pin_val,
                            "aarch64-linux": "64db528412096d718b4bf8f78f85e5ac2b714b774e5005500dee37d23f560456",
                        },
                        "nixpkgs_revision": "0" * 40,
                        "nixpkgs_nar_hash": "sha256-hash",
                    }
                }
            }

            with patch.dict(os.environ, {"RUNNER_TEMP": str(runner_temp)}), patch("rs9.hosted_nix.prepare_input", return_value=(scratch, scratch, {})):
                # If command raises, verify installer-identity was already retained in scratch
                with patch("rs9.hosted_nix.command", side_effect=ContractError("NIX_EXECUTION", "fail")):
                    with self.assertRaises(ContractError) as ctx:
                        execute(context)
                    self.assertEqual(ctx.exception.code, "NIX_EXECUTION")
                    # Identity must be retained in scratch even on later execution error!
                    self.assertTrue((scratch / "diagnostics/installer-identity.json").is_file())
                    retained = json.loads((scratch / "diagnostics/installer-identity.json").read_bytes())
                    self.assertEqual(retained["sha256"], pin_val)

    def test_execute_verifies_postbuild_store_archive_sha256_readback(self):
        with tempfile.TemporaryDirectory() as td:
            scratch = Path(td) / "scratch"
            scratch.mkdir()
            runner_temp = Path(td) / "runner_temp"
            install_dir = runner_temp / "rs9-nix-install"
            install_dir.mkdir(parents=True)

            pin_val = "3baa0af88a1ef4e2cc82cb64cd384b1805ecc3771b574e97277ae213d52711d8"
            identity_doc = {
                "version": "2.31.2",
                "system": "aarch64-darwin",
                "sha256": pin_val,
                "pin_provenance": "source-pinned",
                "status": "pass",
            }
            (install_dir / "installer-identity.json").write_bytes(canonical(identity_doc))

            # Create mock store outputs for each product
            from rs9.release_core import digest
            mock_store = Path(td) / "nix_store"
            mock_store.mkdir()

            archive_bytes = b"real-nebular-payload-tar-gz"
            archive_sha = digest(archive_bytes)

            products = {
                "theme-forge-stellar-burst": {"commands": ["tfsb"], "asset_sha256": "burst-sha"},
                "theme-forge-stellar-loom": {"commands": ["tfsl"], "asset_sha256": "loom-sha"},
                "theme-forge-solar-sail": {"commands": ["tfss"], "asset_sha256": "sail-sha"},
                "theme-forge-nebular-fusion": {"commands": ["tfnf"], "asset_sha256": archive_sha},
            }

            for pid, pdata in products.items():
                p_out = mock_store / pid
                (p_out / "bin").mkdir(parents=True)
                (p_out / "bin" / pdata["commands"][0]).write_text("#!/bin/sh\nexit 0\n")
                if pid == "theme-forge-nebular-fusion":
                    payload_dir = p_out / "payload"
                    payload_dir.mkdir()
                    (payload_dir / "payload.tar.gz").write_bytes(archive_bytes)

            def mock_command(argv, **kwargs):
                if argv[0] != "nix":
                    return ""
                sub = argv[1]
                if sub == "flake" and argv[2] == "metadata":
                    return json.dumps({
                        "locks": {"nodes": {"nixpkgs": {"locked": {
                            "rev": "0" * 40,
                            "narHash": "sha256-hash",
                        }}}}
                    })
                if sub == "flake" and argv[2] == "check":
                    return ""
                if sub == "build":
                    attr = argv[-1]
                    pid = attr.split(".")[-1]
                    out_dir = str(mock_store / pid)
                    return json.dumps([{"drvPath": f"/nix/store/{pid}.drv", "outputs": {"out": out_dir}}])
                if sub == "path-info":
                    out_path = argv[-1]
                    return json.dumps([{"path": out_path, "narHash": "sha256-mock", "narSize": 1024}])
                raise ValueError(f"Unexpected mock_command argv: {argv}")

            context = {
                "system": "aarch64-darwin",
                "repository": ROOT,
                "scratch": scratch,
                "pins": {
                    "nix": {
                        "installer_version": "2.31.2",
                        "installer_sha256_by_system": {
                            "aarch64-darwin": pin_val,
                            "x86_64-linux": "d1f67c86eed016214864ba08bfb9529c307aea7e8fafb74853f96fcc3bfd8a60",
                            "aarch64-linux": "64db528412096d718b4bf8f78f85e5ac2b714b774e5005500dee37d23f560456",
                        },
                        "nixpkgs_revision": "0" * 40,
                        "nixpkgs_nar_hash": "sha256-hash",
                    }
                },
                "captures": [(Mock(), {"project": {"id": pid}}, {}) for pid in ("theme-forge-nebular-fusion", "theme-forge-stellar-burst")],
                "client": Mock(),
            }

            with patch.dict(os.environ, {"RUNNER_TEMP": str(runner_temp)}), \
                 patch("rs9.hosted_nix.prepare_input", return_value=(scratch, scratch, products)), \
                 patch("rs9.hosted_nix.command", side_effect=mock_command), \
                 patch("rs9.hosted_nix.release_load_record", return_value={"synthetic": True}), \
                 patch("rs9.hosted_nix.verify_burst_payload", return_value={"status": "pass"}) as burst_verifier, \
                 patch("rs9.hosted_nix.run_probes", side_effect=lambda *a, **k: (k.get("after_probe", lambda: None)() or [{"name": "probe", "status": "pass"}])), \
                 patch("rs9.hosted_nix.snapshot_nebular_runtime", return_value={"runtime_root_sha256": "a" * 64}) as snapshot, \
                 patch("rs9.hosted_nix.prepare_smoke", return_value={}), \
                 patch("rs9.hosted_nix.verify_nebular_runtime", return_value={"status": "pass"}) as verifier:

                # Ensure cache directory entry exists for nebular smoke materialization check
                cache_dir = scratch / "nix-runtime-cache"
                entry_payload = cache_dir / "entries/test/payload/app"
                entry_payload.mkdir(parents=True)

                result = execute(context)
                self.assertIn("outputs", result["details"])
                neb_paths = result["details"]["outputs"]["theme-forge-nebular-fusion"]
                self.assertEqual(neb_paths["store_archive_sha256"], archive_sha)
                self.assertEqual(neb_paths["asset_sha256"], archive_sha)
                gate_names = [g["name"] for g in result["gates"]]
                self.assertIn("nix-store-archive-readback", gate_names)
                self.assertIn("burst-native-addon-load", gate_names)
                self.assertIn("burst-native-addon-target", gate_names)
                self.assertEqual(burst_verifier.call_args.args[0], mock_store / "theme-forge-stellar-burst/lib/node_modules/theme-forge-stellar-burst")
                self.assertEqual(burst_verifier.call_args.kwargs["layout_prefix"], "")
                snapshot.assert_called_once()
                self.assertEqual(verifier.call_args.kwargs["baseline"], snapshot.return_value)

                # Receipt must carry the identities
                receipt_path = scratch / "nix-output-receipt.json"
                self.assertTrue(receipt_path.is_file())
                receipt_doc = json.loads(receipt_path.read_bytes())
                self.assertEqual(receipt_doc["outputs"]["theme-forge-nebular-fusion"]["store_archive_sha256"], archive_sha)

    def test_execute_fails_when_store_archive_sha256_mismatches_release(self):
        with tempfile.TemporaryDirectory() as td:
            scratch = Path(td) / "scratch"
            scratch.mkdir()
            runner_temp = Path(td) / "runner_temp"
            install_dir = runner_temp / "rs9-nix-install"
            install_dir.mkdir(parents=True)

            pin_val = "3baa0af88a1ef4e2cc82cb64cd384b1805ecc3771b574e97277ae213d52711d8"
            identity_doc = {
                "version": "2.31.2",
                "system": "aarch64-darwin",
                "sha256": pin_val,
                "pin_provenance": "source-pinned",
                "status": "pass",
            }
            (install_dir / "installer-identity.json").write_bytes(canonical(identity_doc))

            mock_store = Path(td) / "nix_store"
            mock_store.mkdir()

            archive_bytes = b"different-archive-bytes"

            products = {
                "theme-forge-stellar-burst": {"commands": ["tfsb"], "asset_sha256": "burst-sha"},
                "theme-forge-stellar-loom": {"commands": ["tfsl"], "asset_sha256": "loom-sha"},
                "theme-forge-solar-sail": {"commands": ["tfss"], "asset_sha256": "sail-sha"},
                "theme-forge-nebular-fusion": {"commands": ["tfnf"], "asset_sha256": "expected-release-sha"},
            }

            for pid, pdata in products.items():
                p_out = mock_store / pid
                (p_out / "bin").mkdir(parents=True)
                (p_out / "bin" / pdata["commands"][0]).write_text("#!/bin/sh\nexit 0\n")
                if pid == "theme-forge-nebular-fusion":
                    payload_dir = p_out / "payload"
                    payload_dir.mkdir()
                    (payload_dir / "payload.tar.gz").write_bytes(archive_bytes)

            def mock_command(argv, **kwargs):
                if argv[0] != "nix":
                    return ""
                sub = argv[1]
                if sub == "flake" and argv[2] == "metadata":
                    return json.dumps({
                        "locks": {"nodes": {"nixpkgs": {"locked": {
                            "rev": "0" * 40,
                            "narHash": "sha256-hash",
                        }}}}
                    })
                if sub == "flake" and argv[2] == "check":
                    return ""
                if sub == "build":
                    attr = argv[-1]
                    pid = attr.split(".")[-1]
                    out_dir = str(mock_store / pid)
                    return json.dumps([{"drvPath": f"/nix/store/{pid}.drv", "outputs": {"out": out_dir}}])
                if sub == "path-info":
                    out_path = argv[-1]
                    return json.dumps([{"path": out_path, "narHash": "sha256-mock", "narSize": 1024}])
                raise ValueError(f"Unexpected mock_command argv: {argv}")

            context = {
                "system": "aarch64-darwin",
                "repository": ROOT,
                "scratch": scratch,
                "pins": {
                    "nix": {
                        "installer_version": "2.31.2",
                        "installer_sha256_by_system": {
                            "aarch64-darwin": pin_val,
                            "x86_64-linux": "d1f67c86eed016214864ba08bfb9529c307aea7e8fafb74853f96fcc3bfd8a60",
                            "aarch64-linux": "64db528412096d718b4bf8f78f85e5ac2b714b774e5005500dee37d23f560456",
                        },
                        "nixpkgs_revision": "0" * 40,
                        "nixpkgs_nar_hash": "sha256-hash",
                    }
                },
                "captures": [(Mock(), {"project": {"id": pid}}, {}) for pid in ("theme-forge-nebular-fusion", "theme-forge-stellar-burst")],
                "client": Mock(),
            }

            with patch.dict(os.environ, {"RUNNER_TEMP": str(runner_temp)}), \
                 patch("rs9.hosted_nix.prepare_input", return_value=(scratch, scratch, products)), \
                 patch("rs9.hosted_nix.command", side_effect=mock_command), \
                 patch("rs9.hosted_nix.release_load_record", return_value={"synthetic": True}), \
                 patch("rs9.hosted_nix.verify_burst_payload", return_value={"status": "pass"}) as burst_verifier, \
                 patch("rs9.hosted_nix.run_probes", return_value=[{"name": "probe", "status": "pass"}]):

                with self.assertRaises(ContractError) as ctx:
                    execute(context)
                self.assertEqual(ctx.exception.code, "NIX_OUTPUT")
                self.assertIn("mismatch", ctx.exception.message)


if __name__ == "__main__":
    unittest.main()
