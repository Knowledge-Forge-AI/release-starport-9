"""Hosted PRoot experiment runner: pins, build scope, guest wiring and pipeline receipt semantics."""
import json
from pathlib import Path
import stat
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from rs9.errors import ContractError
from rs9.hosted_nix_proot import EXPERIMENT, SYSTEMS, execute
from rs9.nix_proot import GATES, GuestRuntime
from rs9.scratch import canonical
from tests.test_nix_proot import closure_for, make_facts

ROOT = Path(__file__).resolve().parents[1]
REV = "0921fdb3e13e40fe25fbc52b89661a9d6d32ac68"
NAR = "sha256-ESJ4VgytmAt+98YLM8466luln4HyEZ9Q36b9+Bb4P5w="
INSTALLER = "d1f67c86eed016214864ba08bfb9529c307aea7e8fafb74853f96fcc3bfd8a60"
PINS = {"nix": {"installer_version": "2.31.2",
                "installer_sha256_by_system": {"aarch64-darwin": "3baa0af88a1ef4e2cc82cb64cd384b1805ecc3771b574e97277ae213d52711d8",
                                               "x86_64-linux": INSTALLER,
                                               "aarch64-linux": "64db528412096d718b4bf8f78f85e5ac2b714b774e5005500dee37d23f560456"},
                "nixpkgs_revision": REV, "nixpkgs_nar_hash": NAR}}
OUT = "/nix/store/" + "9" * 32 + "-theme-forge-nebular-fusion-proot"


def passing_gates():
    gates = [{"name": name, "status": "pass"} for name in GATES]
    gates[GATES.index("proot-in-guest-offline")]["runtime_offline_status"] = "pass"
    return gates


class HostedNixProotInstallerTests(unittest.TestCase):
    def context(self, scratch, system="x86_64-linux"):
        return {"system": system, "repository": ROOT, "scratch": scratch, "pins": PINS, "captures": []}

    def install(self, runner_temp, **identity):
        directory = runner_temp / "rs9-nix-install"
        directory.mkdir(parents=True)
        (directory / "installer-identity.json").write_text(json.dumps(
            {"version": "2.31.2", "system": "x86_64-linux", "sha256": INSTALLER, "status": "pass", **identity}))

    def test_systems_only_linux(self):
        self.assertEqual(SYSTEMS, {"x86_64-linux", "aarch64-linux"})

    def test_darwin_system_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with self.assertRaises(ContractError) as exc:
                execute(self.context(Path(temp_dir), "aarch64-darwin"))
            self.assertEqual(exc.exception.code, "NIX_SYSTEM")

    def test_missing_installer_identity_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            scratch = Path(temp_dir)
            with patch.dict("os.environ", {"RUNNER_TEMP": str(scratch / "empty")}):
                with self.assertRaises(ContractError) as exc:
                    execute(self.context(scratch))
            self.assertEqual(exc.exception.code, "NIX_INSTALLER")

    def test_failed_prior_installer_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            scratch = Path(temp_dir)
            install_dir = scratch / "runner" / "rs9-nix-install"
            install_dir.mkdir(parents=True)
            (install_dir / "installer-failure.json").write_text(json.dumps({"code": "INSTALLER_FAILED"}))
            with patch.dict("os.environ", {"RUNNER_TEMP": str(scratch / "runner")}):
                with self.assertRaises(ContractError) as exc:
                    execute(self.context(scratch))
            self.assertEqual(exc.exception.code, "NIX_INSTALLER")

    def test_installer_identity_must_match_the_source_pinned_checksum(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            scratch = Path(temp_dir)
            self.install(scratch / "runner", sha256="0" * 64)
            with patch.dict("os.environ", {"RUNNER_TEMP": str(scratch / "runner")}):
                with self.assertRaises(ContractError) as exc:
                    execute(self.context(scratch))
            self.assertEqual(exc.exception.code, "NIX_INSTALLER")


class HostedNixProotExecuteTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.scratch = Path(self._tmp.name).resolve()
        runner = self.scratch / "runner" / "rs9-nix-install"
        runner.mkdir(parents=True)
        (runner / "installer-identity.json").write_text(json.dumps(
            {"version": "2.31.2", "system": "x86_64-linux", "sha256": INSTALLER, "status": "pass"}))
        self.work = self.scratch / "work"
        self.work.mkdir()
        self.facts = make_facts()
        self.closure = closure_for(self.facts)
        self.facts_file = self.scratch / "facts.json"
        self.facts_file.write_text(json.dumps(self.facts))
        self.commands = []
        self.locked = {"rev": REV, "narHash": NAR}
        self.captured = {}
        neb = SimpleNamespace(manifests={"payload-id": {"root": "theme-forge-nebular-fusion-0.6.1"}})
        self.neb = neb
        self.context = {"system": "x86_64-linux", "repository": ROOT, "scratch": self.work, "pins": PINS,
                        "captures": [(neb, {"project": {"id": "theme-forge-nebular-fusion"}}, None)], "client": object()}

    def command(self, argv, **kwargs):
        self.commands.append(list(argv))
        if "metadata" in argv:
            return json.dumps({"locks": {"nodes": {"nixpkgs": {"locked": self.locked}}}}).encode()
        if "path-info" in argv:
            if argv[-1] == OUT:
                return json.dumps([{"path": OUT, "narSize": 777, "narHash": "sha256-out"}]).encode()
            return json.dumps({p: {"narSize": 10} for p in argv[argv.index("--json") + 1:]}).encode()
        if "build" in argv and argv[-1].endswith(".runtimeFacts"):
            return json.dumps([{"outputs": {"out": str(self.facts_file)}}]).encode()
        if "build" in argv:
            return json.dumps([{"outputs": {"out": OUT}}]).encode()
        return b""

    def read_bounded(self, path, limit, code):
        return self.facts_file.read_bytes() if str(path) == str(self.facts_file) else b"pinned recipe bytes"

    def evaluation(self, runtime, recipe, **kwargs):
        self.captured.update(runtime=runtime, recipe=recipe, **kwargs)
        return {"schema": "rs9.nix-proot-evaluation.v2", "system": "x86_64-linux", "application_qualified": False,
                "qualification_authority": False, "status": "diagnostic-pass", "gates": passing_gates()}

    def run_execute(self, evaluate=None):
        env = {"RUNNER_TEMP": str(self.scratch / "runner")}
        with patch.dict("os.environ", env), \
                patch("rs9.hosted_nix_proot.command", side_effect=self.command), \
                patch("rs9.hosted_nix_proot.prepare_input", return_value=(self.work, self.work, {})), \
                patch("rs9.hosted_nix_proot._read_bounded", side_effect=self.read_bounded), \
                patch("rs9.hosted_nix_proot.read_closure", return_value=self.closure), \
                patch("rs9.hosted_nix_proot.linux_runtime_prefix", return_value=["netns-stub", "--"]), \
                patch("rs9.hosted_nix_proot.evaluate_proot_experiment", side_effect=evaluate or self.evaluation):
            return execute(self.context)

    def test_builds_only_the_experimental_output_and_never_checks_legacy_outputs(self):
        self.run_execute()
        flat = [" ".join(c) for c in self.commands]
        self.assertFalse([c for c in flat if " check" in c], flat)
        builds = [c for c in self.commands if "build" in c]
        self.assertEqual(len(builds), 2)
        attr = f"#experiments.x86_64-linux.{EXPERIMENT}"
        self.assertTrue(all(attr in c[-1] for c in builds))
        self.assertFalse([c for c in flat if "#candidates" in c or "#checks" in c])
        self.assertIn("github:NixOS/nixpkgs/" + REV, builds[0])

    def test_actual_pins_gate_the_run_before_any_build(self):
        self.locked = {"rev": REV, "narHash": "sha256-" + "A" * 43 + "="}
        with self.assertRaises(ContractError) as exc:
            self.run_execute()
        self.assertEqual(exc.exception.code, "NIX_PIN")
        self.assertFalse([c for c in self.commands if "build" in c])

    def test_facts_are_validated_against_the_pins_and_the_lane(self):
        for name, bad in (("proot-version", dict(self.facts, proot_version="5.3.0")),
                          ("other-system", make_facts("aarch64-linux")),
                          ("fabricated-hash", dict(self.facts, proot_source_hash="sha256-" + "A" * 43 + "="))):
            self.facts_file.write_text(json.dumps(bad))
            with self.subTest(name):
                with self.assertRaises(ContractError) as exc:
                    self.run_execute()
                self.assertEqual(exc.exception.code, "NIX_PROOT_FACTS")

    def test_experiment_receives_pinned_recipe_closure_measurement_and_netns_prefix(self):
        result = self.run_execute()
        runtime = self.captured["runtime"]
        self.assertIsInstance(runtime, GuestRuntime)
        self.assertEqual(self.captured["recipe"], b"pinned recipe bytes")
        self.assertEqual(self.captured["closure_size_bytes"], 10 * len(self.closure))
        self.assertEqual(runtime.closure, self.closure)
        self.assertEqual(runtime.prefix, ["netns-stub", "--"])
        self.assertEqual(runtime.layout.cache_dir, self.work / "nix-proot-cache")
        self.assertEqual(runtime.layout.workspaces, (self.work / "nix-smoke",))
        self.assertEqual(runtime.env["THEME_FORGE_CACHE_DIR"], str(runtime.layout.cache_dir))
        self.assertNotIn("LD_LIBRARY_PATH", runtime.env)
        self.assertEqual(result["gates"], passing_gates())
        details = result["details"]
        self.assertEqual((details["narSize"], details["closure_path_count"]), (777, len(self.closure)))
        self.assertIs(details["application_qualified"], False)
        self.assertIs(details["qualification_authority"], False)
        written = self.work / "nix-proot-evaluation.json"
        self.assertIn(written, result["artifacts"])
        self.assertEqual(json.loads(written.read_bytes())["system"], "x86_64-linux")
        self.assertNotIn(str(self.scratch).encode(), written.read_bytes())

    def release_tree(self):
        root = self.work / "nix-proot-cache" / "entries" / "entry" / "payload" / "theme-forge-nebular-fusion-0.6.1"
        (root / "bin").mkdir(parents=True)
        (root / "lib").mkdir()
        for name in ("bin/launcher", "bin/tfsb-studio-service", "lib/addon.node"):
            (root / name).write_bytes(b"\x7fELF" + b"\0" * 12)
        (root / "bin/launcher").chmod(0o755)
        (root / "README").write_text("not elf")
        (root / "lib/link.node").symlink_to(root / "lib/addon.node")
        return root

    def evaluation_with_hooks(self, runtime, recipe, **kwargs):
        self.captured.update(runtime=runtime, recipe=recipe, **kwargs)
        return {"gates": passing_gates()}

    def patched_hooks(self):
        wrapper_calls = []

        def run_probes(command, path, **kwargs):
            wrapper_calls.append((command, Path(path), kwargs))
            self.release_tree()
            kwargs["after_probe"]()
            return [{"name": "command.tfnf.supported-behavior", "status": "pass"}]

        patches = (
            patch("rs9.hosted_nix_proot.prepare_smoke", return_value={"scratch": self.work / "nix-smoke"}),
            patch("rs9.hosted_nix_proot.run_probes", side_effect=run_probes),
            patch("rs9.hosted_nix_proot.snapshot_nebular_runtime", return_value={"baseline": "yes"}),
            patch("rs9.hosted_nix_proot.select_payload", return_value={
                "id": "payload-id", "launchers": {"tfnf": {"path": "theme-forge-nebular-fusion-0.6.1/bin/launcher"}}}),
        )
        return patches, wrapper_calls

    def test_materialization_runs_the_unmodified_launcher_through_a_guest_wrapper(self):
        patches, calls = self.patched_hooks()
        with patches[0], patches[1], patches[2], patches[3]:
            self.run_execute(evaluate=self.evaluation_with_hooks)
            released = self.captured["materialize"]()
        command, wrapper, kwargs = calls[0]
        self.assertEqual((command, wrapper.name), ("tfnf", "tfnf"))
        self.assertEqual(kwargs["prefix"], ["netns-stub", "--"])
        self.assertEqual(kwargs["substage"], "nix-proot-command-probe")
        text = wrapper.read_text()
        self.assertTrue(text.startswith("#!/bin/sh\nexec "))
        self.assertIn(self.facts["launcher"], text)
        self.assertIn(self.facts["guest_root"], text)
        self.assertIn(" -w /tmp ", text)
        self.assertNotIn("/nix/store:/nix/store", text)
        self.assertTrue(text.endswith(' "$@"\n'))
        self.assertTrue(wrapper.stat().st_mode & stat.S_IXUSR)
        root = self.work / "nix-proot-cache" / "entries" / "entry" / "payload" / "theme-forge-nebular-fusion-0.6.1"
        self.assertEqual(released["elfs"], sorted(str(root / n) for n in ("bin/launcher", "bin/tfsb-studio-service", "lib/addon.node")))
        self.assertEqual(released["sea"], str(root / "bin/tfsb-studio-service"))
        self.assertEqual(released["launcher"], str(root / "bin/launcher"))
        self.assertTrue(released["launcher_is_elf"])

    def test_released_verifier_and_smoke_run_unchanged_with_only_the_guest_prefix(self):
        patches, _ = self.patched_hooks()
        with patches[0], patches[1], patches[2], patches[3]:
            self.run_execute(evaluate=self.evaluation_with_hooks)
            released = self.captured["materialize"]()
            with patch("rs9.hosted_nix_proot.verify_nebular_runtime", return_value={"sidecar": {"verified": True}}) as verify:
                evidence = self.captured["smoke"](released)
        self.assertEqual(evidence, {"sidecar": {"verified": True}})
        args, kwargs = verify.call_args
        root, prepared, system, prefix, env = args
        self.assertEqual((system, kwargs["baseline"]), ("x86_64-linux", {"baseline": "yes"}))
        self.assertEqual(prepared, {"scratch": self.work / "nix-smoke"})
        self.assertEqual(prefix[:2], ["netns-stub", "--"])
        self.assertEqual(prefix[2], self.facts["env"])
        self.assertNotIn("-w", prefix)
        self.assertEqual(prefix[prefix.index("-i") - 1], self.facts["env"])
        self.assertTrue(any(p.startswith("LD_LIBRARY_PATH=" + self.facts["library_path"]) for p in prefix))

    def test_smoke_without_a_pre_probe_baseline_fails_closed(self):
        patches, _ = self.patched_hooks()
        with patches[0], patches[1], patches[2], patches[3]:
            self.run_execute(evaluate=self.evaluation_with_hooks)
            with self.assertRaises(ContractError) as exc:
                self.captured["smoke"]({})
        self.assertEqual(exc.exception.code, "SIDECAR_BASELINE")

    def test_non_pass_command_probe_fails_materialization(self):
        patches, _ = self.patched_hooks()
        with patches[0], patches[2], patches[3], patch(
                "rs9.hosted_nix_proot.run_probes",
                return_value=[{"name": "command.tfnf.supported-behavior", "status": "not-run"}]):
            self.run_execute(evaluate=self.evaluation_with_hooks)
            with self.assertRaises(ContractError) as exc:
                self.captured["materialize"]()
        self.assertEqual(exc.exception.code, "NIX_COMMAND")

    def test_missing_nebular_capture_fails_materialization(self):
        self.context["captures"] = []
        self.run_execute(evaluate=self.evaluation_with_hooks)
        with self.assertRaises(ContractError) as exc:
            self.captured["materialize"]()
        self.assertEqual(exc.exception.code, "NIX_CAPTURE")


class PipelineReceiptTests(unittest.TestCase):
    """The experiment receipt carries offline status only from the gate's explicit in-guest result."""

    def run_lane(self, gates, error=None):
        from rs9.hosted_contract import canonical_release_auth_projection, compute_auth_sha256
        from rs9.hosted_pipeline import run_lane

        class Client:
            receipts = []

        authentication = canonical({"projects": []})
        ingestion = compute_auth_sha256(canonical_release_auth_projection({"projects": []}))

        def fake_capture(repository, root, **kwargs):
            (root / "summary").mkdir()
            (root / "summary/authentication.json").write_bytes(authentication)
            return []

        def execute(context):
            if error:
                raise error
            return {"gates": gates, "artifacts": [], "details": {}}

        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir).resolve()
            scratch, auth = base / "scratch", base / "auth"
            scratch.mkdir()
            auth.mkdir()
            (auth / "artifact-manifest.json").write_bytes(canonical({"release_ingestion_sha256": ingestion}))

            def bind(captures, repository, output):
                path = Path(output) / "command-bindings.json"
                path.write_bytes(b"{}")
                return path

            with patch("rs9.hosted_pipeline.capture_generation", side_effect=fake_capture), \
                    patch("rs9.hosted_pipeline.bind_commands", side_effect=bind), \
                    patch("rs9.hosted_pipeline.validate_host"), \
                    patch("rs9.hosted_pipeline.runner_facts", return_value={}), \
                    patch("rs9.hosted_pipeline.report_generation", return_value={}), \
                    patch("rs9.hosted_pipeline.provenance", return_value={}), \
                    patch("rs9.hosted_pipeline._inputs", return_value={("authenticate", "generation"): auth}), \
                    patch("rs9.hosted_pipeline.importlib", SimpleNamespace(import_module=lambda name: SimpleNamespace(execute=execute))), \
                    patch("rs9.hosted_pipeline.retain") as retain:
                code = run_lane(ROOT, scratch, base / "receipts", "nix-proot", "x86_64-linux", client=Client())
            record = retain.call_args.args[3]
        return code, record

    def test_offline_pass_requires_the_explicit_gate_field(self):
        explicit, record = self.run_lane(passing_gates())
        self.assertEqual(record["network"]["runtime_offline_status"], "pass")
        self.assertEqual(record["schema"], "rs9.hosted-experiment-diagnostic.v1alpha1")
        self.assertIs(record["qualification_authority"], False)
        self.assertIs(record["application_qualified"], False)
        self.assertIs(record["mandatory_gates_satisfied"], False)
        self.assertEqual(explicit, 0)
        self.assertEqual(record["policy_blockers"], [])
        self.assertTrue(record["production_promotion_blockers"])
        implicit = [dict(g) for g in passing_gates()]
        for gate in implicit:
            gate.pop("runtime_offline_status", None)
        _, record = self.run_lane(implicit)
        self.assertEqual(record["network"]["runtime_offline_status"], "not-run")

    def test_failed_and_not_run_offline_results_are_propagated_not_upgraded(self):
        for status in ("fail", "not-run"):
            gates = [dict(g) for g in passing_gates()]
            offline = gates[GATES.index("proot-in-guest-offline")]
            offline.update(status=status, runtime_offline_status=status, reason="network-denial-not-observed-in-guest")
            _, record = self.run_lane(gates)
            self.assertEqual(record["network"]["runtime_offline_status"], status)

    def test_execution_error_never_claims_offline(self):
        code, record = self.run_lane(None, error=ContractError("NIX_PIN", "pin"))
        self.assertEqual(code, 2)
        self.assertEqual(record["network"]["runtime_offline_status"], "not-run")
        self.assertTrue(all(g["status"] == "fail" for g in record["gates"]))


if __name__ == "__main__":
    unittest.main()
