"""Static authenticated archive selection; released applications are never run."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from rs9.current_generation import (CURRENT_GENERATION, HISTORICAL_GENERATION,
    bind_catalog_product, catalog_path, command_contract_path)
from rs9.errors import ContractError
from rs9.hosted_commands import _BOUND, _CAPABILITIES, bind_commands, contracts, probes_for, run_probes
from rs9.hosted_native import execute_probes, get_command_probes
from rs9.hosted_nix import prepare_input
from tests.test_current_generation import current_fixture

ROOT = Path(__file__).resolve().parents[1]


class CurrentCatalogCommandsTests(unittest.TestCase):
    def tearDown(self):
        _BOUND.clear()
        _CAPABILITIES.clear()

    def test_closed_paths_and_historical_default(self):
        self.assertEqual(catalog_path(), "nix/candidate-products.json")
        self.assertEqual(command_contract_path(), "operators/live1/command-contracts.json")
        self.assertEqual(contracts(), contracts(generation=HISTORICAL_GENERATION))
        for invalid in (None, "latest", "../live1", {}):
            for function in (catalog_path, command_contract_path, contracts):
                with self.subTest(function=function.__name__, invalid=invalid), self.assertRaises(ContractError) as error:
                    function(generation=invalid)
                self.assertEqual(error.exception.code, "GENERATION_SELECTION")
            with self.assertRaises(ContractError) as error:
                prepare_input({"repository": ROOT, "generation": invalid})
            self.assertEqual(error.exception.code, "GENERATION_SELECTION")

    def test_current_contract_semantics_and_versions(self):
        for name, version in (("tfsb", "0.7.0"), ("tfsl", "0.5.0"), ("tfss", "0.3.0"), ("tfnf", "0.7.1")):
            self.assertEqual(probes_for(name, generation=CURRENT_GENERATION)[0]["stdout_contains"], [version])
        for name in ("tfsl-batch", "tfsb-studio-service"):
            self.assertEqual(probes_for(name), probes_for(name, generation=CURRENT_GENERATION))
        rows = contracts(generation=CURRENT_GENERATION)
        self.assertTrue(all(row["implementation_sha256"] for row in rows.values()))

    def fixture_catalog(self, root):
        capture, intent, _ = current_fixture(root, engine=">=22")
        intent["commands"] = [{"name": "second", "interface": "cli"}]
        payload = capture.record["payloads"][0]
        row = copy.deepcopy(json.loads((ROOT / catalog_path(CURRENT_GENERATION)).read_bytes())["products"][intent["project"]["id"]])
        row.update(commit=capture.record["tag"]["commit"], commands=["second"], command_paths={"second": "bin/run.js"})
        row["asset"] = {key: payload[key] for key in ("name", "sha256", "size", "root")}
        row["asset"]["url"] = "https://github.com/" + row["repository"] + "/releases/download/" + row["tag"] + "/" + payload["name"]
        row["node_engine"] = ">=22"
        return capture, intent, row

    def test_catalog_refuses_stale_coordinates_before_staging(self):
        with tempfile.TemporaryDirectory() as tmp:
            capture, intent, row = self.fixture_catalog(Path(tmp))
            bind_catalog_product(row, capture, intent, generation=CURRENT_GENERATION)
            # Every coordinate is checked against freshly authenticated fixture bytes.
            mutations = ({"version": "0.4.0"}, {"tag": "v0.4.0"}, {"commit": "d" * 40},
                         {"commands": ["tfsl"]}, {"repository": "other/repository"},
                         {"asset": {**row["asset"], "sha256": "0" * 64}})
            for mutation in mutations:
                with self.subTest(mutation=mutation), self.assertRaises(ContractError) as error:
                    bind_catalog_product({**row, **mutation}, capture, intent, generation=CURRENT_GENERATION)
                self.assertEqual(error.exception.code, "NIX_CATALOG_BINDING")
            document = json.loads((ROOT / catalog_path(CURRENT_GENERATION)).read_bytes())
            document["products"][intent["project"]["id"]] = {**row, "version": "stale"}
            location = Path(tmp) / catalog_path(CURRENT_GENERATION)
            location.parent.mkdir(parents=True)
            location.write_text(json.dumps(document))
            # Meet the complete-product precondition, then fail on the first stale binding.
            captures = [(capture, intent, {})] + [(None, {"project": {"id": pid}}, {})
                        for pid in document["products"] if pid != intent["project"]["id"]]
            with patch("rs9.hosted_nix.shutil.copyfile") as stage, self.assertRaises(ContractError) as error:
                prepare_input({"repository": Path(tmp), "scratch": Path(tmp) / "absent", "generation": CURRENT_GENERATION,
                               "captures": captures})
            self.assertEqual(error.exception.code, "NIX_CATALOG_BINDING")
            stage.assert_not_called()
            self.assertFalse((Path(tmp) / "absent").exists())

    def test_authenticated_binding_refuses_mixed_or_json_only_capability(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            capture, intent, _ = current_fixture(root)
            implementation = b"#!/usr/bin/env node\n"
            row = {"project": intent["project"]["id"], "implementation_paths": ["bin/run.js"],
                   "source_guards": ["#!/usr/bin/env node"],
                   "implementation_sha256": {"bin/run.js": hashlib.sha256(implementation).hexdigest()},
                   "evidence": {"repository": intent["project"]["repository"], "tag": intent["tag"],
                                "commit": capture.record["tag"]["commit"]},
                   "probes": [{"kind": "argv", "argv": [], "expect_exit": 0}]}
            location = root / command_contract_path(CURRENT_GENERATION)
            location.parent.mkdir(parents=True)
            location.write_text(json.dumps({"generation": CURRENT_GENERATION, "commands": {"second": row}}))
            bind_commands([(capture, intent, {})], root, root, generation=CURRENT_GENERATION)
            binding = json.loads((root / "command-bindings.json").read_bytes())
            self.assertEqual(binding["generation"], CURRENT_GENERATION)
            self.assertEqual(binding["commands"]["second"]["status"], "bound")
            with patch("rs9.hosted_commands.subprocess.run", return_value=subprocess.CompletedProcess([], 0, "", "")) as run:
                self.assertEqual(run_probes("second", "unused", root, generation=CURRENT_GENERATION)[0]["status"], "pass")
                run.assert_called_once()
            with patch("rs9.hosted_commands.subprocess.run") as run:
                self.assertEqual(run_probes("second", "unused", generation=HISTORICAL_GENERATION)[0]["status"], "not-run")
                _BOUND.clear()
                _BOUND.update(json.loads(json.dumps(binding["commands"])))
                self.assertEqual(run_probes("second", "unused", root, generation=CURRENT_GENERATION)[0]["status"], "not-run")
                run.assert_not_called()
            # Changed selected contract identity cannot reuse a still-live binding.
            bind_commands([(capture, intent, {})], root, root, generation=CURRENT_GENERATION)
            row["probes"][0]["argv"] = ["--changed"]
            location.write_text(json.dumps({"generation": CURRENT_GENERATION, "commands": {"second": row}}))
            with patch("rs9.hosted_commands.subprocess.run") as run:
                self.assertEqual(run_probes("second", "unused", root, generation=CURRENT_GENERATION)[0]["status"], "not-run")
                run.assert_not_called()

    def test_native_helpers_forward_selected_generation(self):
        self.assertEqual(get_command_probes("tfsl", generation=CURRENT_GENERATION), probes_for("tfsl", generation=CURRENT_GENERATION))
        with patch("rs9.hosted_commands.run_probes", return_value=[]) as run:
            execute_probes("tfsl", "unused", generation=CURRENT_GENERATION)
        self.assertEqual(run.call_args.kwargs["generation"], CURRENT_GENERATION)

    def test_generation_is_explicit_at_every_changed_probe_callsite(self):
        import ast
        targets = {"contracts", "run_probes", "probes_for", "bind_commands", "get_command_probes", "execute_probes", "command_diagnostic", "fhs_runtime_smoke", "client_cycle"}
        held = {("tf_pypi_nebular.py", "bind_commands"), ("tf_pypi_nebular.py", "run_probes")}
        for source in (ROOT / "src/rs9").glob("*.py"):
            filename = source.name
            tree = ast.parse(source.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and (name := getattr(node.func, "id", getattr(node.func, "attr", ""))) in targets:
                    with self.subTest(file=filename, line=node.lineno):
                        if (filename, name) not in held:
                            self.assertIn("generation", {kw.arg for kw in node.keywords})

    def test_unknown_generation_refuses_lane_and_child_actions(self):
        from rs9 import hosted_deb, hosted_native, hosted_nix, hosted_nix_proot, hosted_wheels, hosted_wheel_clients
        for function in (hosted_deb.execute, hosted_deb.execute_deb, hosted_deb.execute_pages,
                         hosted_native.execute, hosted_nix.execute, hosted_nix_proot.execute,
                         hosted_wheels.execute, hosted_wheel_clients.child):
            with self.subTest(function=function.__module__ + "." + function.__name__), self.assertRaises(ContractError) as error:
                function({"generation": "latest"})
            self.assertEqual(error.exception.code, "GENERATION_SELECTION")
        with self.assertRaises(ContractError) as error:
            hosted_wheel_clients.qualify({"generation": "latest"}, {}, {})
        self.assertEqual(error.exception.code, "GENERATION_SELECTION")

    def test_current_catalog_has_only_current_coordinates(self):
        catalog = json.loads((ROOT / catalog_path(CURRENT_GENERATION)).read_bytes())
        self.assertEqual(catalog["generation"], CURRENT_GENERATION)
        expected = {"theme-forge-stellar-burst": "0.7.0", "theme-forge-stellar-loom": "0.5.0",
                    "theme-forge-solar-sail": "0.3.0", "theme-forge-nebular-fusion": "0.7.1"}
        self.assertEqual({pid: row["version"] for pid, row in catalog["products"].items()}, expected)
        nebular = catalog["products"]["theme-forge-nebular-fusion"]
        self.assertIn(nebular["commit"], nebular["icon"]["url"])
        self.assertNotEqual(nebular["icon"]["sha256"], "pending")
        for row in catalog["products"].values():
            self.assertEqual(row["tag"], "v" + row["version"])
            for asset in row.get("assets", {"package": row.get("asset")}).values():
                self.assertIn(row["version"], asset["name"])
                self.assertIn("/" + row["tag"] + "/", asset["url"])

    def test_historical_unbound_never_reads_missing_contract(self):
        with tempfile.TemporaryDirectory() as tmp, patch("rs9.hosted_commands.contracts") as load:
            self.assertEqual(run_probes("second", "unused", Path(tmp))[0]["status"], "not-run")
            with self.assertRaises(ContractError) as error:
                run_probes("second", "unused", Path(tmp), generation="latest")
            self.assertEqual(error.exception.code, "GENERATION_SELECTION")
            load.assert_not_called()

    def recapture_payloads(self, capture, intent, payloads, *, tagged_implementation=None):
        """Authenticate synthetic multi-platform archives through the real release boundary."""
        from rs9.profiles import selection_for_intent
        from rs9.release_core import authenticate_release, digest
        from rs9.scratch import canonical
        selected = []
        for index, (data, platforms, commands, launchers) in enumerate(payloads):
            name = "synthetic-" + str(index) + ".tgz"
            (capture.root / "assets" / name).write_bytes(data)
            selected.append({"id": "payload-" + str(index), "name": name, "format": "tar.gz",
                             "platforms": platforms, "commands": commands, "launchers": launchers})
        intent["assets"] = selected
        assets = {path.name: path.read_bytes() for path in (capture.root / "assets").iterdir() if path.name != "SHA256SUMS"}
        (capture.root / "assets/SHA256SUMS").write_bytes("".join(digest(data) + "  " + name + "\n" for name, data in sorted(assets.items())).encode())
        assets["SHA256SUMS"] = (capture.root / "assets/SHA256SUMS").read_bytes()
        path = capture.root / "api/release.json"
        release = json.loads(path.read_bytes())
        release["assets"] = [{"id": index + 1, "name": name, "size": len(data), "digest": "sha256:" + digest(data), "state": "uploaded"}
                             for index, (name, data) in enumerate(sorted(assets.items()))]
        path.write_bytes(canonical(release))
        selection = selection_for_intent(intent)
        if tagged_implementation is not None:
            source_path = capture.root / "source/bin/run.js"
            source_path.parent.mkdir(parents=True, exist_ok=True)
            source_path.write_bytes(tagged_implementation)
            tree_path = capture.root / "api/tree.json"
            tree = json.loads(tree_path.read_bytes())
            blob = hashlib.sha1(b"blob " + str(len(tagged_implementation)).encode() + b"\0" + tagged_implementation).hexdigest()
            tree["tree"].append({"path": "bin/run.js", "sha": blob, "type": "blob", "mode": "100644"})
            tree_path.write_bytes(canonical(tree))
            selection["source_paths"].append("bin/run.js")
        for asset in selection["payload_assets"]:
            if asset["launchers"]:
                asset["command_policy"] = "native-executable"
        return authenticate_release(selection, capture.root)

    def test_cross_payload_implementation_conflicts_refuse_in_both_orders(self):
        import tarfile
        from tests.shadow_fixtures import tar_bytes
        for differing, reverse in ((False, False), (True, False), (True, True)):
            with self.subTest(differing=differing, reverse=reverse), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                capture, intent, _ = current_fixture(root)
                raw = capture.archives["package"].read_bytes()
                changed = tar_bytes([("package/package.json", capture.source["package.json"], 0o644, tarfile.REGTYPE, ""), ("package/bin/run.js", b"#!/usr/bin/env node\n// other architecture\n", 0o755, tarfile.REGTYPE, "")])
                payloads = [(raw, ["x86_64-linux"], {"second": "package/bin/run.js"}, {}),
                            (changed if differing else raw, ["aarch64-linux"], {"second": "package/bin/run.js"}, {})]
                if reverse:
                    payloads.reverse()
                capture = self.recapture_payloads(capture, intent, payloads, tagged_implementation=b"// Tagged source differs from packaged implementation\n")
                row = {"project": intent["project"]["id"], "implementation_paths": ["bin/run.js"],
                       "source_guards": ["#!/usr/bin/env node"],
                       "implementation_sha256": {"bin/run.js": hashlib.sha256(b"#!/usr/bin/env node\n").hexdigest()},
                       "evidence": {"repository": intent["project"]["repository"], "tag": intent["tag"], "commit": capture.record["tag"]["commit"]}, "probes": []}
                path = root / command_contract_path(CURRENT_GENERATION)
                path.parent.mkdir(parents=True)
                path.write_text(json.dumps({"generation": CURRENT_GENERATION, "commands": {"second": row}}))
                if differing:
                    with self.assertRaises(ContractError) as error:
                        bind_commands([(capture, intent, {})], root, root, generation=CURRENT_GENERATION)
                    self.assertEqual(error.exception.code, "COMMAND_BINDING")
                    self.assertIn("Released implementation differs between payloads", str(error.exception))
                    self.assertEqual(_BOUND, {})
                else:
                    bind_commands([(capture, intent, {})], root, root, generation=CURRENT_GENERATION)
                    self.assertEqual(_BOUND["second"]["status"], "bound")

    def test_native_catalog_requires_exact_authenticated_systems(self):
        with tempfile.TemporaryDirectory() as tmp:
            capture, intent, row = self.fixture_catalog(Path(tmp))
            raw = capture.archives["package"].read_bytes()
            capture = self.recapture_payloads(capture, intent, [(raw, [system], {"tfnf": "package/bin/run.js"}, {"tfnf": "package/bin/run.js"})
                for system in ("x86_64-linux", "aarch64-linux")])
            intent["commands"] = [{"name": "tfnf", "interface": "gui"}]
            intent["desktop"] = {"icon": {"path": "package.json"}}
            row.update(kind="materialized-desktop", commands=["tfnf"], assets={})
            row.pop("asset")
            for payload in capture.record["payloads"]:
                asset = {key: payload[key] for key in ("name", "sha256", "size", "root")}
                asset.update(url="https://github.com/" + row["repository"] + "/releases/download/" + row["tag"] + "/" + payload["name"],
                             executable_path=payload["commands"]["tfnf"]["path"], executable_sha256=payload["commands"]["tfnf"]["sha256"], launcher="bin/run.js")
                row["assets"][payload["platforms"][0]] = asset
            data = capture.source["package.json"]
            row["icon"] = {"path": "package.json", "sha256": hashlib.sha256(data).hexdigest(), "size": len(data),
                           "url": "https://raw.githubusercontent.com/" + row["repository"] + "/" + row["commit"] + "/package.json"}
            bind_catalog_product(row, capture, intent, generation=CURRENT_GENERATION)
            for missing in (True, False):
                changed = copy.deepcopy(row)
                if missing:
                    del changed["assets"]["aarch64-linux"]
                else:
                    changed["assets"]["stale-system"] = copy.deepcopy(changed["assets"]["x86_64-linux"])
                with self.subTest(missing=missing), self.assertRaises(ContractError) as error:
                    bind_catalog_product(changed, capture, intent, generation=CURRENT_GENERATION)
                self.assertEqual(error.exception.code, "NIX_CATALOG_BINDING")
                self.assertIn("Catalog requires exactly the authenticated payload systems", str(error.exception))

    def test_historical_audit_and_diagnostic_shapes_are_preserved(self):
        from rs9.hosted_commands import command_diagnostic
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            capture, intent, _ = current_fixture(root)
            row = {"project": intent["project"]["id"], "implementation_paths": ["bin/run.js"],
                   "source_guards": ["#!/usr/bin/env node"], "probes": []}
            path = root / command_contract_path(HISTORICAL_GENERATION)
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps({"commands": {"second": row}}))
            receipt = json.loads(bind_commands([(capture, intent, {})], root, root).read_bytes())
            self.assertEqual(set(receipt), {"schema", "production_enabled", "commands"})
            self.assertEqual(set(receipt["commands"]["second"]), {"status", "release_record_sha256", "asset_sha256", "implementation_sha256", "reason"})
            diagnostic = command_diagnostic("second", 0, {"kind": "argv"}, subprocess.CompletedProcess([], 1, "", ""), repository=root)
            self.assertEqual(set(diagnostic), {"product", "command", "probe_id", "substage", "exit_code", "stdout_sha256", "stderr_sha256", "diagnostic_token"})
