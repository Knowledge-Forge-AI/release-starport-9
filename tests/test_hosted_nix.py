"""Nix candidate source binds real outputs and fails before a build without capture."""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from rs9.errors import ContractError
from rs9.hosted_nix import (_pinned_session_bus_argv, command, execute, fhs_runtime_smoke,
                            prepare_input, record_direct_loader_evaluation, PRODUCTS, SYSTEMS)
from rs9.hosted_summary import contract, gate_blockers
from rs9.nix_gui_discovery import NODE_FS_SOURCE, _discovery_request, record_fhs_gui_discovery
from rs9.scratch import canonical

ROOT = Path(__file__).resolve().parents[1]


def _mock_dbus_loader_facts(source, system, overrides, scratch, neb, prefix, env, *, facts_out=None):
    if facts_out is not None:
        root = "/nix/store/" + "a" * 32 + "-dbus-1"
        facts_out.update({
            "dbus_run_session": root + "/bin/dbus-run-session",
            "dbus_daemon": root + "/bin/dbus-daemon",
            "dbus_session_config": root + "/share/dbus-1/session.conf",
        })
    return {"status": "pass", "application_qualified": False}


class NixHostedTests(unittest.TestCase):
    def test_linux_runtime_facts_require_strict_co_rooted_dbus_paths(self):
        root = "/nix/store/" + "a" * 32 + "-dbus-1"
        facts = {
            "dbus_run_session": root + "/bin/dbus-run-session",
            "dbus_daemon": root + "/bin/dbus-daemon",
            "dbus_session_config": root + "/share/dbus-1/session.conf",
        }
        self.assertEqual(_pinned_session_bus_argv(facts), [
            facts["dbus_run_session"],
            "--dbus-daemon=" + facts["dbus_daemon"],
            "--config-file=" + facts["dbus_session_config"],
            "--",
        ])
        for mutation in (
            {"dbus_daemon": "/nix/store/" + "b" * 32 + "-dbus-1/bin/dbus-daemon"},
            {"dbus_session_config": root + "/etc/dbus-1/session.conf"},
            {"dbus_run_session": None},
        ):
            with self.subTest(mutation=mutation), self.assertRaises(ContractError):
                _pinned_session_bus_argv({**facts, **mutation})

    def test_nix_runtime_facts_source_emits_dbus_bindings(self):
        source = (ROOT / "nix/nebular.nix").read_text()
        self.assertIn('dbus_run_session = "${pkgs.dbus}/bin/dbus-run-session";', source)
        self.assertIn('dbus_daemon = "${pkgs.dbus}/bin/dbus-daemon";', source)
        self.assertIn('dbus_session_config = "${pkgs.dbus}/share/dbus-1/session.conf";', source)

    def test_nix_runtime_facts_source_emits_only_existing_gui_store_roots(self):
        source = (ROOT / "nix/nebular.nix").read_text()
        self.assertIn('schema = "rs9.nix-fhs-gui-discovery.v1";', source)
        for package in ("glib", "gtk3", "webkitgtk_4_1", "gdk-pixbuf"):
            self.assertIn(f'"${{pkgs.{package}}}"', source)
        self.assertIn("closure_roots = lib.unique", source)
        self.assertIn('gui_discovery = guiDiscovery;', source)
        self.assertNotIn("GIO_EXTRA_MODULES", source)
        self.assertNotIn("GSETTINGS_SCHEMA_DIR", source)

    def test_gui_discovery_request_is_closed_and_bounded(self):
        root = "/nix/store/" + "a" * 32 + "-gui"
        facts = {
            "node": root + "/bin/node",
            "gui_discovery": {
                "schema": "rs9.nix-fhs-gui-discovery.v1",
                "roots": {role: "/nix/store/" + "a" * 32 + "-" + role
                          for role in ("glib", "gtk", "webkit", "pixbuf")},
                "closure_roots": ["/nix/store/" + "a" * 32 + "-" + role
                                  for role in ("glib", "gtk", "webkit", "pixbuf")],
                "max_entries": 4096,
                "max_bytes": 64 * 1024 * 1024,
                "max_file_bytes": 4 * 1024 * 1024,
                "max_symlink_hops": 16,
                "categories": ["helper", "libexec", "gio-module", "gsettings-schema",
                               "pixbuf-loader", "font", "data"],
            },
        }
        request = _discovery_request(facts)
        self.assertEqual(request["schema"], "rs9.nix-fhs-gui-discovery-request.v1")
        for mutation in (
            {"gui_discovery": {**facts["gui_discovery"], "max_entries": 4097}},
            {"gui_discovery": {**facts["gui_discovery"], "roots": {"glib": root}}},
            {"node": "/tmp/node"},
        ):
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                _discovery_request({**facts, **mutation})

    def test_gui_discovery_is_optional_diagnostic_and_never_a_gate(self):
        from subprocess import CompletedProcess
        root = "/nix/store/" + "b" * 32 + "-gui"
        facts = {
            "node": root + "/bin/node",
            "gui_discovery": {
                "schema": "rs9.nix-fhs-gui-discovery.v1",
                "roots": {role: "/nix/store/" + "b" * 32 + "-" + role
                          for role in ("glib", "gtk", "webkit", "pixbuf")},
                "closure_roots": ["/nix/store/" + "b" * 32 + "-" + role
                                  for role in ("glib", "gtk", "webkit", "pixbuf")],
                "max_entries": 4096,
                "max_bytes": 64 * 1024 * 1024,
                "max_file_bytes": 4 * 1024 * 1024,
                "max_symlink_hops": 16,
                "categories": ["helper", "libexec", "gio-module", "gsettings-schema",
                               "pixbuf-loader", "font", "data"],
            },
        }
        with tempfile.TemporaryDirectory() as td:
            destination = Path(td) / "nix-gui-discovery.json"
            with patch("rs9.nix_gui_discovery.subprocess.run", side_effect=OSError("fixture")):
                result = record_fhs_gui_discovery(facts, ["prefix"], ["runtime"], {}, destination)
            self.assertEqual(result["status"], "fail")
            self.assertTrue(result["diagnostic_only"])
            self.assertEqual(json.loads(destination.read_bytes())["status"], "fail")

    def test_gui_discovery_uses_node_fs_only_script_and_bound_input(self):
        from subprocess import CompletedProcess
        root = "/nix/store/" + "c" * 32 + "-gui"
        facts = {
            "node": root + "/bin/node",
            "gui_discovery": {
                "schema": "rs9.nix-fhs-gui-discovery.v1",
                "roots": {role: "/nix/store/" + "c" * 32 + "-" + role
                          for role in ("glib", "gtk", "webkit", "pixbuf")},
                "closure_roots": ["/nix/store/" + "c" * 32 + "-" + role
                                  for role in ("glib", "gtk", "webkit", "pixbuf")],
                "max_entries": 4096,
                "max_bytes": 64 * 1024 * 1024,
                "max_file_bytes": 4 * 1024 * 1024,
                "max_symlink_hops": 16,
                "categories": ["helper", "libexec", "gio-module", "gsettings-schema",
                               "pixbuf-loader", "font", "data"],
            },
        }
        response = json.dumps({
            "schema": "rs9.nix-fhs-gui-observation.v1", "status": "pass",
            "roots": {
                role: {
                    "path": "/nix/store/" + "c" * 32 + "-" + role,
                    "full9": {key: "0" if key in {"mtimeNs", "ctimeNs"} else 0 for key in ("dev", "ino", "size", "mode", "mtimeNs",
                                                  "ctimeNs", "uid", "gid", "nlink")},
                    "records": 0,
                }
                for role in ("glib", "gtk", "webkit", "pixbuf")
            },
            "totals": {"entries": 0, "read_bytes": 0, "skipped_uncategorized": 0,
                       "skipped_oversize": 0},
            "categories": ["helper", "libexec", "gio-module", "gsettings-schema",
                           "pixbuf-loader", "font", "data"],
            "records": [],
        }).encode()
        with tempfile.TemporaryDirectory() as td, patch(
                "rs9.nix_gui_discovery.subprocess.run",
                return_value=CompletedProcess([], 0, response, b"")) as run:
            result = record_fhs_gui_discovery(facts, ["prefix"], ["runtime"], {}, Path(td) / "out.json")
        self.assertEqual(result["status"], "pass")
        argv = run.call_args.args[0]
        self.assertEqual(argv[-2:], ["-e", NODE_FS_SOURCE])
        self.assertEqual(run.call_args.kwargs["input"], canonical(_discovery_request(facts)))
        self.assertIn("node:fs", NODE_FS_SOURCE)
        self.assertIn("node:crypto", NODE_FS_SOURCE)
        self.assertNotIn("child_process", NODE_FS_SOURCE)

    def test_loader_facts_capture_preserves_dbus_bindings_without_expanding_loader_contract(self):
        with tempfile.TemporaryDirectory() as td:
            scratch = Path(td)
            facts_path = scratch / "facts.json"
            root = "/nix/store/" + "a" * 32 + "-dbus-1"
            facts = {
                "loader": "/nix/store/" + "b" * 32 + "-glibc/lib/ld-linux-x86-64.so.2",
                "glibc_lib": "/nix/store/" + "b" * 32 + "-glibc/lib",
                "library_path": "/nix/store/" + "b" * 32 + "-glibc/lib",
                "python": "/nix/store/" + "c" * 32 + "-python/bin/python3",
                "node": "/nix/store/" + "d" * 32 + "-node/bin/node",
                "readelf": "/nix/store/" + "e" * 32 + "-binutils/bin/readelf",
                "dbus_run_session": root + "/bin/dbus-run-session",
                "dbus_daemon": root + "/bin/dbus-daemon",
                "dbus_session_config": root + "/share/dbus-1/session.conf",
            }
            facts_path.write_bytes(canonical(facts))
            facts_out = {}
            evaluation = {"schema": "rs9.nix-loader-evaluation.v1", "status": "fail",
                          "application_qualified": False}
            with patch("rs9.hosted_nix.command", return_value=json.dumps([{"outputs": {"out": str(facts_path)}}])), \
                 patch("rs9.hosted_nix.stage_payload"), \
                 patch("rs9.hosted_nix.select_payload", return_value={}), \
                 patch("rs9.hosted_nix.evaluate_direct_loader", return_value=evaluation) as evaluate:
                result = record_direct_loader_evaluation(
                    ROOT, "x86_64-linux", [], scratch, Mock(), [], {}, facts_out=facts_out)
            self.assertEqual(result, evaluation)
            self.assertEqual(facts_out, facts)
            self.assertEqual(evaluate.call_args.args[0], {key: facts[key] for key in (
                "loader", "glibc_lib", "library_path", "python", "node", "readelf")})
    def test_loader_facts_failures_remain_diagnostics_before_runtime_gate(self):
        for result in (ContractError("NIX_EXECUTION", "fixture build failed"),
                       "[]", "{}", '[{"outputs":{}}]', "[null]",
                       '[{"outputs":null}]', '[{"outputs":[]}]', "not-json"):
            with self.subTest(result=str(result)), tempfile.TemporaryDirectory() as td:
                scratch = Path(td)
                kwargs = {"side_effect": result} if isinstance(result, Exception) else {"return_value": result}
                with patch("rs9.hosted_nix.command", **kwargs), \
                     patch("rs9.hosted_nix.stage_payload") as stage:
                    evaluation = record_direct_loader_evaluation(
                        ROOT, "x86_64-linux", [], scratch, Mock(), [], {})
                stage.assert_not_called()
                self.assertEqual(evaluation["status"], "fail")
                self.assertFalse(evaluation["application_qualified"])
                self.assertEqual(json.loads((scratch / "nix-loader-evaluation.json").read_bytes()), evaluation)
                from subprocess import CompletedProcess
                with patch("rs9.hosted_nix.subprocess.run", return_value=CompletedProcess(
                        [], 1, b"", b"bwrap: Creating new namespace failed: Operation not permitted")), \
                     self.assertRaises(ContractError) as caught:
                    fhs_runtime_smoke("/fixture", "x86_64-linux", [], {})
                self.assertEqual(caught.exception.code, "NIX_FHS_USERNS")

    def test_disconnected_fhs_replay_identifies_user_namespace_failure(self):
        from subprocess import CompletedProcess
        for system in ("x86_64-linux", "aarch64-linux"):
            with self.subTest(system=system), patch("rs9.hosted_nix.subprocess.run", return_value=CompletedProcess(
                    [], 1, b"", b"bwrap: Creating new namespace failed: Operation not permitted")) as run:
                with self.assertRaises(ContractError) as caught:
                    fhs_runtime_smoke("/private/fixture/runtime", system, ["disconnected"], {"PATH": "fixture"})
            self.assertEqual(run.call_args.args[0], ["disconnected", "/private/fixture/runtime/bin/rs9-nebular-fhs", "true"])
            self.assertEqual(caught.exception.code, "NIX_FHS_USERNS")
            self.assertEqual(caught.exception.details["system"], system)
            self.assertEqual(caught.exception.details["substage"], "nix-fhs-runtime-smoke")
            self.assertNotIn("/private/", json.dumps(caught.exception.details))

    def test_fhs_success_does_not_waive_following_command_or_verifier(self):
        from subprocess import CompletedProcess
        with patch("rs9.hosted_nix.subprocess.run", return_value=CompletedProcess([], 0, b"", b"")):
            gate = fhs_runtime_smoke("/fixture", "x86_64-linux", [], {})
        self.assertEqual(gate["name"], "nix-fhs-runtime-smoke")
        self.assertEqual(gate["status"], "pass")
        self.assertNotIn("nix-native-closure", gate)

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
        self.assertIn('diagnostic_boundary_probes=system.endswith("-linux")', source)
        self.assertIn('diagnostic_replay=system.endswith("-linux")', source)
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
                 patch("rs9.hosted_nix.verifier_import_preflight", return_value={"status": "pass"}), \
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

    def test_execute_linux_nix_fhs_userns_partial_result_retention(self):
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

            mock_store = Path(td) / "nix_store"
            mock_store.mkdir()

            products = {
                "theme-forge-stellar-burst": {"commands": ["tfsb"], "asset_sha256": "burst-sha"},
                "theme-forge-stellar-loom": {"commands": ["tfsl"], "asset_sha256": "loom-sha"},
                "theme-forge-solar-sail": {"commands": ["tfss"], "asset_sha256": "sail-sha"},
                "theme-forge-nebular-fusion": {"commands": ["tfnf"], "asset_sha256": "nebular-sha"},
            }

            for pid, pdata in products.items():
                p_out = mock_store / pid
                (p_out / "bin").mkdir(parents=True)
                for cmd in pdata["commands"]:
                    (p_out / "bin" / cmd).write_text("#!/bin/sh\nexit 0\n")

            runtime_dir = mock_store / "theme-forge-nebular-fusion-runtime"
            (runtime_dir / "bin").mkdir(parents=True)
            (runtime_dir / "bin/rs9-nebular-fhs").write_text("#!/bin/sh\nexit 1\n")

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
                    if attr.endswith(".runtime"):
                        return json.dumps([{"drvPath": "/nix/store/runtime.drv", "outputs": {"out": str(runtime_dir)}}])
                    pid = attr.split(".")[-1]
                    out_dir = str(mock_store / pid)
                    return json.dumps([{"drvPath": f"/nix/store/{pid}.drv", "outputs": {"out": out_dir}}])
                if sub == "path-info":
                    out_path = argv[-1]
                    return json.dumps([{"path": out_path, "narHash": "sha256-mock", "narSize": 1024}])
                raise ValueError(f"Unexpected mock_command argv: {argv}")

            def mock_record_loader(source, system, overrides, scratch, neb, prefix, env, *, facts_out=None):
                if facts_out is not None:
                    facts_out.update({
                        "dbus_run_session": "/nix/store/" + "a" * 32 + "-dbus-1/bin/dbus-run-session",
                        "dbus_daemon": "/nix/store/" + "a" * 32 + "-dbus-1/bin/dbus-daemon",
                        "dbus_session_config": "/nix/store/" + "a" * 32 + "-dbus-1/share/dbus-1/session.conf",
                    })
                doc = {
                    "schema": "rs9.nix-loader-evaluation.v1",
                    "status": "fail",
                    "application_qualified": False,
                    "reason": "direct-loader-evaluation-mock",
                }
                (scratch / "nix-loader-evaluation.json").write_bytes(canonical(doc))
                return doc

            userns_error = ContractError(
                "NIX_FHS_USERNS",
                "Disconnected native FHS runtime failed",
                details={
                    "diagnostic_token": "userns-denied",
                    "system": "x86_64-linux",
                    "substage": "nix-fhs-runtime-smoke",
                    "userns_policy": "restricted",
                },
            )

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
                },
                "captures": [(Mock(), {"project": {"id": pid}}, {}) for pid in PRODUCTS],
                "client": Mock(),
            }

            with patch.dict(os.environ, {"RUNNER_TEMP": str(runner_temp)}), \
                 patch("rs9.hosted_nix.prepare_input", return_value=(scratch, scratch, products)), \
                 patch("rs9.hosted_nix.command", side_effect=mock_command), \
                 patch("rs9.hosted_nix.release_load_record", return_value={"synthetic": True}), \
                 patch("rs9.hosted_nix.verify_burst_payload", return_value={"status": "pass", "native_binding": "burst.node"}), \
                 patch("rs9.hosted_nix.run_probes", side_effect=lambda name, *a, **k: [{"name": f"command.{name}.supported-behavior", "status": "pass"}]), \
                 patch("rs9.hosted_nix.record_direct_loader_evaluation", side_effect=mock_record_loader), \
                 patch("rs9.hosted_nix.fhs_runtime_smoke", side_effect=userns_error):

                with self.assertRaises(ContractError) as ctx:
                    execute(context)

                err = ctx.exception
                self.assertEqual(err.code, "NIX_FHS_USERNS")
                self.assertEqual(err.message, "Disconnected native FHS runtime failed")
                self.assertEqual(err.details["diagnostic_token"], "userns-denied")
                self.assertEqual(err.details["system"], "x86_64-linux")
                self.assertEqual(err.details["substage"], "nix-fhs-runtime-smoke")
                self.assertEqual(err.details["userns_policy"], "restricted")

                self.assertTrue(hasattr(err, "partial_result"))
                partial = err.partial_result
                self.assertIsInstance(partial, dict)

                # Check gate rows and exact names
                gates = partial["gates"]
                gate_names = [g["name"] for g in gates]
                expected_gate_names = [
                    "nix-lock-pin",
                    "burst-native-addon-target",
                    "burst-native-addon-load",
                    "command.tfsb.supported-behavior",
                    "command.tfsl.supported-behavior",
                    "command.tfss.supported-behavior",
                    "nix-fhs-runtime-smoke",
                    "nix-store-archive-readback",
                    "command.tfnf.supported-behavior",
                    "nix-native-closure",
                    "nix-build-check-run",
                ]
                self.assertEqual(gate_names, expected_gate_names)
                # Ensure no wildcard names
                for name in gate_names:
                    self.assertNotIn("*", name)
                # Ensure no duplicate gate names
                self.assertEqual(len(gate_names), len(set(gate_names)))

                # Check statuses and reasons
                passed_gates = {g["name"] for g in gates if g["status"] == "pass"}
                self.assertEqual(passed_gates, {
                    "nix-lock-pin",
                    "burst-native-addon-target",
                    "burst-native-addon-load",
                    "command.tfsb.supported-behavior",
                    "command.tfsl.supported-behavior",
                    "command.tfss.supported-behavior",
                })

                failing_gates = [g for g in gates if g["status"] == "fail"]
                self.assertEqual(len(failing_gates), 1)
                self.assertEqual(failing_gates[0]["name"], "nix-fhs-runtime-smoke")
                self.assertEqual(failing_gates[0]["reason"], "NIX_FHS_USERNS")
                self.assertEqual(failing_gates[0]["details"], err.details)

                not_run_gates = [g for g in gates if g["status"] == "not-run"]
                expected_not_run = [
                    "nix-store-archive-readback",
                    "command.tfnf.supported-behavior",
                    "nix-native-closure",
                    "nix-build-check-run",
                ]
                self.assertEqual([g["name"] for g in not_run_gates], expected_not_run)
                for g in not_run_gates:
                    self.assertEqual(g["reason"], "blocked-by:nix-fhs-runtime-smoke")

                # Artifacts retention
                artifacts = partial["artifacts"]
                self.assertIn(scratch / "nix-loader-evaluation.json", artifacts)
                self.assertIn(scratch / "diagnostics/installer-identity.json", artifacts)

                # Output facts and completed vs unexecuted distinction
                outputs = partial["details"]["outputs"]
                self.assertEqual(partial["details"]["locked"], {"rev": "0" * 40, "narHash": "sha256-hash"})

                # Burst completed loader fact
                self.assertIn("theme-forge-stellar-burst", outputs)
                self.assertEqual(outputs["theme-forge-stellar-burst"]["native_loader"], {"status": "pass", "native_binding": "burst.node"})

                # Loom and sail stage facts
                self.assertIn("theme-forge-stellar-loom", outputs)
                self.assertIn("outPath", outputs["theme-forge-stellar-loom"])
                self.assertIn("theme-forge-solar-sail", outputs)
                self.assertIn("outPath", outputs["theme-forge-solar-sail"])

                # Nebular partial stage facts: drvPath, outPath, direct_loader_evaluation present,
                # but unexecuted post-build facts absent
                self.assertIn("theme-forge-nebular-fusion", outputs)
                neb_out = outputs["theme-forge-nebular-fusion"]
                self.assertIn("direct_loader_evaluation", neb_out)
                self.assertNotIn("store_archive_sha256", neb_out)
                self.assertNotIn("asset_sha256", neb_out)
                self.assertNotIn("native_smoke", neb_out)

                # Gate blockers integration: required gates still fail, no allowed_not_run waiver
                lanes = [l for l in contract(ROOT)["lanes"] if l.get("lane") == "nix" and l.get("system") == "x86_64-linux"]
                self.assertEqual(len(lanes), 1)
                nix_lane = lanes[0]
                blockers = gate_blockers(nix_lane, {"gates": gates})

                self.assertEqual(blockers, [
                    "not-run:nix-native-closure",
                    "not-run:nix-build-check-run",
                    "failed-gate:nix-fhs-runtime-smoke",
                ])
                self.assertNotIn("missing-or-duplicate-gate:nix-native-closure", blockers)
                self.assertNotIn("missing-or-duplicate-gate:nix-build-check-run", blockers)
                self.assertNotIn("duplicate-gates", blockers)

    def test_execute_linux_nix_other_error_does_not_attach_partial_result(self):
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

            mock_store = Path(td) / "nix_store"
            mock_store.mkdir()

            products = {
                "theme-forge-stellar-burst": {"commands": ["tfsb"], "asset_sha256": "burst-sha"},
                "theme-forge-stellar-loom": {"commands": ["tfsl"], "asset_sha256": "loom-sha"},
                "theme-forge-solar-sail": {"commands": ["tfss"], "asset_sha256": "sail-sha"},
                "theme-forge-nebular-fusion": {"commands": ["tfnf"], "asset_sha256": "nebular-sha"},
            }

            for pid, pdata in products.items():
                p_out = mock_store / pid
                (p_out / "bin").mkdir(parents=True)
                for cmd in pdata["commands"]:
                    (p_out / "bin" / cmd).write_text("#!/bin/sh\nexit 0\n")

            runtime_dir = mock_store / "theme-forge-nebular-fusion-runtime"
            (runtime_dir / "bin").mkdir(parents=True)
            (runtime_dir / "bin/rs9-nebular-fhs").write_text("#!/bin/sh\nexit 1\n")

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
                    if attr.endswith(".runtime"):
                        return json.dumps([{"drvPath": "/nix/store/runtime.drv", "outputs": {"out": str(runtime_dir)}}])
                    pid = attr.split(".")[-1]
                    out_dir = str(mock_store / pid)
                    return json.dumps([{"drvPath": f"/nix/store/{pid}.drv", "outputs": {"out": out_dir}}])
                if sub == "path-info":
                    out_path = argv[-1]
                    return json.dumps([{"path": out_path, "narHash": "sha256-mock", "narSize": 1024}])
                raise ValueError(f"Unexpected mock_command argv: {argv}")

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
                },
                "captures": [(Mock(), {"project": {"id": pid}}, {}) for pid in PRODUCTS],
                "client": Mock(),
            }

            with patch.dict(os.environ, {"RUNNER_TEMP": str(runner_temp)}), \
                 patch("rs9.hosted_nix.prepare_input", return_value=(scratch, scratch, products)), \
                 patch("rs9.hosted_nix.command", side_effect=mock_command), \
                 patch("rs9.hosted_nix.release_load_record", return_value={"synthetic": True}), \
                 patch("rs9.hosted_nix.verify_burst_payload", return_value={"status": "pass"}), \
                 patch("rs9.hosted_nix.run_probes", return_value=[{"name": "probe", "status": "pass"}]), \
                 patch("rs9.hosted_nix.record_direct_loader_evaluation", return_value={}), \
                 patch("rs9.hosted_nix.fhs_runtime_smoke", side_effect=ContractError("NIX_FHS_RUNTIME", "generic runtime smoke failure")):

                with self.assertRaises(ContractError) as ctx:
                    execute(context)

                err = ctx.exception
                self.assertEqual(err.code, "NIX_FHS_RUNTIME")
                self.assertFalse(hasattr(err, "partial_result"))

    def test_optional_discovery_success_retains_artifact_without_gate_admission(self):
        original_facts = _mock_dbus_loader_facts
        original_execute = execute
        captured = []
        def facts_with_gui(*args, **kwargs):
            result = original_facts(*args, **kwargs)
            kwargs["facts_out"]["gui_discovery"] = {}
            return result
        def observe(facts, prefix, runtime, env, destination):
            destination.write_bytes(canonical({"status": "pass", "diagnostic_only": True}))
            return {"status": "pass", "diagnostic_only": True}
        def capture(context):
            result = original_execute(context)
            captured.append(result)
            return result
        with patch(__name__ + "._mock_dbus_loader_facts", side_effect=facts_with_gui), patch(
                "rs9.hosted_nix.record_fhs_gui_discovery", side_effect=observe), patch(
                __name__ + ".execute", side_effect=capture):
            self.test_execute_linux_nix_fhs_success_unaltered()
        self.assertEqual(len(captured), 1)
        self.assertTrue(any(Path(path).name == "nix-gui-discovery.json" and Path(path).parent.name == "diagnostics"
                            for path in captured[0]["artifacts"]))
        self.assertFalse(any("discovery" in gate["name"] for gate in captured[0]["gates"]))

    def test_pipeline_failure_retains_gui_observation_through_existing_custody(self):
        from types import SimpleNamespace
        from rs9.hosted_pipeline import run_lane
        from rs9.hosted_custody import verify_set
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();scratch=root/'scratch';scratch.mkdir()
            inputs=root/'inputs';inputs.mkdir()
            (inputs/'artifact-manifest.json').write_bytes(canonical({'release_ingestion_sha256':'a'*64}))
            def capture(repository,output,**kwargs):
                (output/'summary').mkdir();(output/'summary/authentication.json').write_bytes(b'{}')
                return []
            def bind(captures,repository,output,*,generation):
                path=output/'command-bindings.json';path.write_bytes(b'{}');return path
            def fail_after_observation(context):
                destination=context['scratch']/'diagnostics/nix-gui-discovery.json'
                destination.parent.mkdir()
                record_fhs_gui_discovery({},[],[],{},destination)
                raise ContractError('APPLICATION_SMOKE','controlled later smoke failure')
            with patch('rs9.hosted_pipeline.validate_host'), patch('rs9.hosted_pipeline._inputs',
                    return_value={('authenticate','generation'):inputs}), patch('rs9.hosted_pipeline.capture_generation',side_effect=capture), patch(
                    'rs9.hosted_pipeline.canonical_release_auth_projection',return_value={}), patch(
                    'rs9.hosted_pipeline.compute_auth_sha256',return_value='a'*64), patch(
                    'rs9.hosted_pipeline.bind_commands',side_effect=bind), patch('rs9.hosted_pipeline.runner_facts',return_value={}), patch(
                    'rs9.hosted_pipeline.importlib.import_module',return_value=SimpleNamespace(execute=fail_after_observation)):
                self.assertEqual(run_lane(ROOT,scratch,root/'packet','nix','x86_64-linux',
                    client=SimpleNamespace(receipts=[]),inputs=inputs),2)
            manifest=verify_set(root/'packet')
            diagnostic=root/'packet/objects/lane-work/diagnostics/nix-gui-discovery.json'
            self.assertTrue(diagnostic.is_file())
            receipt=json.loads((root/'packet/nix-x86_64-linux.json').read_bytes())
            self.assertEqual(receipt['execution_error'],'APPLICATION_SMOKE')
            self.assertNotIn('diagnostic_scan_failures',receipt)
            self.assertTrue(json.loads(diagnostic.read_bytes())['diagnostic_only'])

    def test_optional_discovery_fault_cannot_preempt_required_flow(self):
        original = _mock_dbus_loader_facts
        def facts_with_gui(*args, **kwargs):
            result = original(*args, **kwargs)
            kwargs["facts_out"]["gui_discovery"] = {}
            return result
        with patch(__name__ + "._mock_dbus_loader_facts", side_effect=facts_with_gui), patch(
                "rs9.hosted_nix.record_fhs_gui_discovery", side_effect=OSError("controlled diagnostic custody fault")) as observe:
            self.test_execute_linux_nix_fhs_success_unaltered()
        observe.assert_called_once()

    def test_execute_linux_nix_fhs_success_unaltered(self):
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

            mock_store = Path(td) / "nix_store"
            mock_store.mkdir()

            from rs9.release_core import digest
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
                for cmd in pdata["commands"]:
                    (p_out / "bin" / cmd).write_text("#!/bin/sh\nexit 0\n")
                if pid == "theme-forge-nebular-fusion":
                    payload_dir = p_out / "payload"
                    payload_dir.mkdir()
                    (payload_dir / "payload.tar.gz").write_bytes(archive_bytes)

            runtime_dir = mock_store / "theme-forge-nebular-fusion-runtime"
            (runtime_dir / "bin").mkdir(parents=True)
            (runtime_dir / "bin/rs9-nebular-fhs").write_text("#!/bin/sh\nexit 0\n")

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
                    if attr.endswith(".runtime"):
                        return json.dumps([{"drvPath": "/nix/store/runtime.drv", "outputs": {"out": str(runtime_dir)}}])
                    pid = attr.split(".")[-1]
                    out_dir = str(mock_store / pid)
                    return json.dumps([{"drvPath": f"/nix/store/{pid}.drv", "outputs": {"out": out_dir}}])
                if sub == "path-info":
                    out_path = argv[-1]
                    return json.dumps([{"path": out_path, "narHash": "sha256-mock", "narSize": 1024}])
                raise ValueError(f"Unexpected mock_command argv: {argv}")

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
                },
                "captures": [(Mock(), {"project": {"id": pid}}, {}) for pid in PRODUCTS],
                "client": Mock(),
            }

            with patch.dict(os.environ, {"RUNNER_TEMP": str(runner_temp)}), \
                 patch("rs9.hosted_nix.prepare_input", return_value=(scratch, scratch, products)), \
                 patch("rs9.hosted_nix.command", side_effect=mock_command), \
                 patch("rs9.hosted_nix.release_load_record", return_value={"synthetic": True}), \
                 patch("rs9.hosted_nix.verify_burst_payload", return_value={"status": "pass"}), \
                 patch("rs9.hosted_nix.run_probes", side_effect=lambda name, *a, **k: (k.get("after_probe", lambda: None)() or [{"name": f"command.{name}.supported-behavior", "status": "pass"}])), \
                 patch("rs9.hosted_nix.record_direct_loader_evaluation", side_effect=_mock_dbus_loader_facts), \
                 patch("rs9.hosted_nix.fhs_runtime_smoke", return_value={"name": "nix-fhs-runtime-smoke", "status": "pass"}), \
                 patch("rs9.hosted_nix.snapshot_nebular_runtime", return_value={"runtime_root_sha256": "a" * 64}), \
                 patch("rs9.hosted_nix.prepare_smoke", return_value={}), \
                 patch("rs9.hosted_nix.verifier_import_preflight", return_value={"status": "pass"}), \
                 patch("rs9.hosted_nix.verify_nebular_runtime", return_value={"status": "pass"}) as verify_runtime:

                # Ensure cache directory entry exists for nebular smoke materialization check
                cache_dir = scratch / "nix-runtime-cache"
                entry_payload = cache_dir / "entries/test/payload/app"
                entry_payload.mkdir(parents=True)

                result = execute(context)
                self.assertIn("outputs", result["details"])
                gate_names = [g["name"] for g in result["gates"]]
                self.assertIn("nix-fhs-runtime-smoke", gate_names)
                self.assertIn("nix-store-archive-readback", gate_names)
                self.assertIn("nix-native-closure", gate_names)
                self.assertIn("nix-build-check-run", gate_names)
                self.assertEqual(verify_runtime.call_args.kwargs["session_bus_argv"], [
                    "/nix/store/" + "a" * 32 + "-dbus-1/bin/dbus-run-session",
                    "--dbus-daemon=/nix/store/" + "a" * 32 + "-dbus-1/bin/dbus-daemon",
                    "--config-file=/nix/store/" + "a" * 32 + "-dbus-1/share/dbus-1/session.conf",
                    "--",
                ])

                lanes = [l for l in contract(ROOT)["lanes"] if l.get("lane") == "nix" and l.get("system") == "x86_64-linux"]
                self.assertEqual(len(lanes), 1)
                blockers = gate_blockers(lanes[0], result)
                self.assertEqual(blockers, [])


if __name__ == "__main__":
    unittest.main()
