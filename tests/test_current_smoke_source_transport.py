"""Current source transport fixtures; no Docker, Node, GUI or native execution."""
import copy
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from rs9 import hosted_smoke as smoke
from rs9 import hosted_container_smoke as container
from rs9 import smoke_source_envelope as envelope
from rs9.bootstrap import require_configuration_authority
from rs9.build_native import CommandReceipt
from rs9.errors import ContractError
from rs9.profiles import evaluate_profile, PACKAGE_PROFILE
from rs9.release_core import authenticated_record_hash, digest
from rs9.scratch import canonical
from tests.test_sidecar_harness_closure import current_import_fixture


class CurrentSourceTransportTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        capture, captures, client, contract, source_pins, fixture_pins = current_import_fixture(self.root)
        for target, value in (("rs9.nebular_callers._load_current_contract", contract),
                              ("rs9.hosted_smoke.CURRENT070_VERIFIER_FILES", source_pins),
                              ("rs9.hosted_smoke.CURRENT070_FIXTURE_FILES", fixture_pins)):
            patcher = patch(target, return_value=value) if target.endswith("_load_current_contract") else patch(target, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.prepared = smoke.prepare_smoke(capture, captures, client, self.root / "prepared")
        members = [{"path": "fixture", "type": "directory", "mode": 0o755}]
        self.prepared.update(expected_members=members, manifest_sha256=digest(canonical(members)))
        patcher = patch.object(container, "GUEST", self.root / "guest")
        patcher.start()
        self.addCleanup(patcher.stop)
        self.binding = container.prepare_container_smoke(self.prepared, "x86_64-linux", "pacman")
        for source, target, writable in self.binding["mounts"]:
            if writable:
                Path(target).mkdir(parents=True)
            else:
                shutil.copytree(source, target)
        self.request_path = container.GUEST / "input/request.json"

    def guest_prepared(self):
        request = json.loads(self.request_path.read_bytes())
        data = container._checked_current_request(request, canonical(request), self.binding["request_sha256"])
        source = container.GUEST / "source"
        prepared = {"source": source, "tools": source / "tools", "source_generation": envelope.GENERATION,
                    "records": request["records"], "source_readback": data, "container_client": True,
                    "expected_members": request["expected_members"], "manifest_sha256": request["manifest_sha256"]}
        prepared["_source_readback_proof"] = envelope.mint_guest_readback(data, source, source / "tools")
        return prepared

    def test_serialized_roundtrip_is_source_only_and_parent_still_requires_live_captures(self):
        guest = self.guest_prepared()
        sha = envelope.verify_guest_prepared(guest)
        self.assertEqual(sha, self.binding["source_readback_sha256"])
        smoke.verify_execution_source_readback(guest)
        with self.assertRaises(ContractError):
            smoke.verify_source_readback(guest)
        with self.assertRaises(ContractError):
            smoke.export_current_source_readback(guest)
        proof = guest["_source_readback_proof"]
        for check in (lambda: authenticated_record_hash(proof),
                      lambda: require_configuration_authority(proof, {}),
                      lambda: evaluate_profile(proof, PACKAGE_PROFILE, {})):
            with self.assertRaises(ContractError):
                check()
        plain = {key: value for key, value in guest.items() if key != "_source_readback_proof"}
        with self.assertRaises(ContractError):
            smoke.verify_execution_source_readback(plain)
        self.assertEqual(guest["source_readback"]["authority"], envelope.AUTHORITY)
        for field in ("capture", "fixture_capture"):
            with self.assertRaises(ContractError):
                envelope.verify_guest_prepared({**guest, field: self.prepared[field]})

    def test_fixed_import_graph_must_match_closure(self):
        with patch.object(smoke, "CURRENT070_VERIFIER_IMPORTS", {}):
            with self.assertRaises(ContractError):
                envelope.checked_envelope(self.binding["request"]["source_readback"])

    def test_closed_envelope_substitutions_refuse_before_import(self):
        data = self.binding["request"]["source_readback"]
        variants = []
        value = copy.deepcopy(data); value.pop("authority"); variants.append(value)
        value = copy.deepcopy(data); value["extra"] = True; variants.append(value)
        value = copy.deepcopy(data); value["authority"]["release_authentication"] = True; variants.append(value)
        value = copy.deepcopy(data); value["producers"]["nebular"]["commit"] = smoke.CURRENT_COMMIT; variants.append(value)
        value = copy.deepcopy(data); value["importer"] = "../tools"; variants.append(value)
        value = copy.deepcopy(data); value["records"].pop(); variants.append(value)
        value = copy.deepcopy(data); value["records"].append(dict(value["records"][0])); variants.append(value)
        for key, replacement in (("sha256", "0" * 64), ("role", "fixture"), ("tag_commit", smoke.CURRENT_COMMIT)):
            value = copy.deepcopy(data); value["records"][0][key] = replacement; variants.append(value)
        with patch("rs9.hosted_smoke._run_verifier") as run:
            for value in variants:
                with self.assertRaises(ContractError):
                    envelope.mint_guest_readback(json.loads(canonical(value)), container.GUEST / "source", container.GUEST / "source/tools")
            run.assert_not_called()

    def test_missing_extra_changed_and_symlink_files_refuse(self):
        data = self.binding["request"]["source_readback"]
        source = container.GUEST / "source"
        path = source / "package.json"
        original = path.read_bytes()
        for action in (lambda: path.unlink(), lambda: path.write_bytes(b"changed")):
            action()
            with self.assertRaises(ContractError):
                envelope.mint_guest_readback(data, source, source / "tools")
            path.write_bytes(original)
        extra = source / "extra.mjs"; extra.write_text("unlisted")
        with self.assertRaises(ContractError):
            envelope.mint_guest_readback(data, source, source / "tools")
        extra.unlink()
        target = self.root / "outside.json"; target.write_bytes(original)
        path.unlink(); path.symlink_to(target)
        with self.assertRaises(ContractError):
            envelope.mint_guest_readback(data, source, source / "tools")

    def test_checkout_rebases_both_readback_roots_and_preserves_importer(self):
        guest = self.guest_prepared()
        checkout = container.GUEST / "out/checkout"
        shutil.copytree(guest["source"], checkout)
        original = envelope.verify_members
        seen = []
        def readback(source, tools, records):
            seen.append((Path(source), Path(tools)))
            return original(source, tools, records)
        with patch.object(envelope, "verify_members", side_effect=readback):
            container._guest_checkout_readback(guest, checkout)
        self.assertEqual(seen, [(checkout, checkout / "tools")])
        self.assertEqual(guest["tools"], container.GUEST / "source/tools")
        with self.assertRaises(ContractError):
            envelope.verify_guest_prepared({**guest, "source": checkout, "tools": checkout / "tools"})

    def test_current_request_substitutions_refuse_before_guest_import(self):
        with patch("os.getuid", return_value=65534), patch.object(container, "verify_nebular_runtime") as runtime:
            self.assertEqual(container.guest_main(), 2)
            runtime.assert_not_called()
        shutil.rmtree(container.GUEST / "out")
        (container.GUEST / "out").mkdir()
        request = copy.deepcopy(self.binding["request"])
        request["family"] = "apt"
        self.request_path.write_bytes(canonical(request))
        with patch("os.getuid", return_value=65534), patch.object(container, "verify_nebular_runtime") as runtime:
            self.assertEqual(container.guest_main(expected_request_sha256=self.binding["request_sha256"]), 2)
            runtime.assert_not_called()
        for field, replacement in (("tools_relative", "../source/tools"), ("extra", True), ("source_readback", {})):
            changed = copy.deepcopy(self.binding["request"]); changed[field] = replacement
            raw = canonical(changed)
            with self.assertRaises(ContractError):
                container._checked_current_request(changed, raw, digest(raw))

    def test_real_runtime_verifier_and_application_orchestration_with_guest_proof(self):
        runtime = self.root / "static-runtime"
        (runtime / "bin").mkdir(parents=True)
        (runtime / "lib/sidecar-payload").mkdir(parents=True)
        (runtime / "bin/tfsb-studio-service").write_bytes(b"static fixture; never executed")
        (runtime / "lib/sidecar-payload/manifest.json").write_bytes(b"{}")
        members = smoke._inventory_runtime(runtime)[0]
        self.prepared.update(expected_members=members, manifest_sha256=digest(canonical(members)))
        self.binding = container.prepare_container_smoke(self.prepared, "x86_64-linux", "apt")
        shutil.copytree(self.binding["request_path"].parent, container.GUEST / "input", dirs_exist_ok=True)
        guest = self.guest_prepared()
        guest.update(scratch=container.GUEST / "out/work", probe=container.GUEST / "input/probe",
                     checkout=container.GUEST / "out/checkout", family="apt")
        guest["scratch"].mkdir()
        shutil.copytree(guest["source"], guest["checkout"])
        self.assertNotIn("capture", guest)
        self.assertEqual(smoke.expected_runtime_members(guest, "x86_64-linux"), members)
        imported = []
        def verifier(script, sidecar, payload, prefix, env, *, cwd):
            self.assertEqual(Path(cwd), guest["source"])
            self.assertEqual(script.parent, guest["probe"])
            expected = (smoke._import_preflight_script(guest["source"], guest["tools"])
                        if script.name == "verify-import-preflight.mjs" else
                        smoke._verifier_script(guest["tools"] / "sidecar-common.mjs"))
            self.assertEqual(script.read_text(), expected)
            imported.append(script.name)
            return {"status": "pass"}, {"verified": True}
        scenarios = []
        def child(argv, **kwargs):
            self.assertIn(str(guest["tools"] / "native-rc-smoke.mjs"), argv)
            self.assertEqual(argv[argv.index("--checkout") + 1], str(guest["checkout"]))
            evidence = Path(argv[argv.index("--evidence") + 1])
            self.assertEqual(evidence, guest["scratch"] / "evidence")
            label = argv[argv.index("--label") + 1]
            scenarios.append(argv[argv.index("--scenario") + 1])
            (evidence / (label + ".run.json")).write_bytes(canonical(
                {"status": "pass", "problems": [], "executable": {"sha256": "b" * 64}}))
            return subprocess.CompletedProcess(argv, 0, b"", b"")
        probe = guest["probe"] / "verify-import-preflight.mjs"
        original = probe.read_bytes()
        probe.write_bytes(b"substituted")
        with patch.object(smoke, "_run_verifier") as run, patch("rs9.application_smoke_diagnostic.subprocess.run") as native:
            with self.assertRaises(ContractError):
                smoke.verify_nebular_runtime(runtime, guest, "x86_64-linux")
            run.assert_not_called(); native.assert_not_called()
        probe.write_bytes(original)
        with patch.object(smoke, "_run_verifier", side_effect=verifier), patch(
                "rs9.application_smoke_diagnostic.subprocess.run", side_effect=child):
            result = smoke.verify_nebular_runtime(runtime, guest, "x86_64-linux")
        self.assertEqual(imported, ["verify-import-preflight.mjs", "verify-runtime.mjs"])
        self.assertEqual(scenarios, ["C", "C-signal"])
        self.assertEqual([row["scenario"] for row in result["scenarios"]], scenarios)
        for row in result["scenarios"]:
            self.assertRegex(row["receipt_sha256"], r"^[0-9a-f]{64}$")
            self.assertEqual(row["executable_sha256"], "b" * 64)
        container._guest_checkout_readback(guest, guest["checkout"])

    def test_parent_rechecks_live_source_request_and_wrapper_before_dispatch(self):
        class NeverClient:
            def exec(self, *args, **kwargs):
                raise AssertionError("A substituted parent binding dispatched")
        original = self.binding["request"]["tools_relative"]
        self.binding["request"]["tools_relative"] = "other"
        with self.assertRaises(ContractError):
            container.verify_container_nebular(NeverClient(), self.binding, user="65534:65534")
        self.binding["request"]["tools_relative"] = original
        probe = self.binding["request_path"].parent / "probe/verify-import-preflight.mjs"
        saved = probe.read_bytes(); probe.write_text("changed")
        with self.assertRaises(ContractError):
            container.verify_container_nebular(NeverClient(), self.binding, user="65534:65534")
        probe.write_bytes(saved)
        extra_probe = probe.parent / "extra.mjs"; extra_probe.write_text("unlisted")
        with self.assertRaises(ContractError):
            container.verify_container_nebular(NeverClient(), self.binding, user="65534:65534")
        extra_probe.unlink()
        raw = self.binding["request_path"].read_bytes()
        self.binding["request_path"].write_bytes(raw + b" ")
        with self.assertRaises(ContractError):
            container.verify_container_nebular(NeverClient(), self.binding, user="65534:65534")
        self.binding["request_path"].write_bytes(raw)
        self.binding["prepared"] = self.guest_prepared()
        with self.assertRaises(ContractError):
            container.verify_container_nebular(NeverClient(), self.binding, user="65534:65534")

    def test_source_only_guest_control_flow_and_output_digest_preserve_scenarios(self):
        case = self
        def source_only(runtime_root, prepared, system, **kwargs):
            envelope.verify_guest_prepared(prepared)
            self.assertEqual(prepared["tools"], container.GUEST / "source/tools")
            self.assertEqual(prepared["checkout"], container.GUEST / "out/checkout")
            return {"sidecar": {"verified": True}, "scenarios": [
                {"scenario": name, "receipt_sha256": "a" * 64, "executable_sha256": "b" * 64}
                for name in ("C", "C-signal")], "source_bindings": prepared["records"]}
        class PureClient:
            def exec(self, argv, *, user):
                case.assertEqual(user, "65534:65534")
                match = re.search(r"expected_request_sha256='([0-9a-f]{64})'", argv[-1])
                case.assertIsNotNone(match)
                with patch("os.getuid", return_value=65534), patch.object(container, "verify_nebular_runtime", side_effect=source_only):
                    code = container.guest_main(expected_request_sha256=match.group(1))
                shutil.copytree(container.GUEST / "out", case.binding["output"], dirs_exist_ok=True)
                return CommandReceipt(argv, code, b"", b"", executed=True)
        runtime = self.root / "installed-placeholder"; runtime.mkdir()
        with patch.object(container, "RUNTIME", str(runtime)):
            result = container.verify_container_nebular(PureClient(), self.binding, user="65534:65534")
        self.assertEqual(result["source_readback_sha256"], self.binding["source_readback_sha256"])
        self.assertEqual([row["scenario"] for row in result["scenarios"]], ["C", "C-signal"])
        self.assertEqual([rw for _, _, rw in self.binding["mounts"]], [False, False, True])
        output = self.binding["output"] / "result.json"
        original = json.loads(output.read_bytes())
        variants = []
        data = copy.deepcopy(original); data.pop("source_readback_sha256"); variants.append(data)
        data = copy.deepcopy(original); data["source_readback_sha256"] = "0" * 64; variants.append(data)
        data = copy.deepcopy(original); data["request_sha256"] = "0" * 64; variants.append(data)
        data = copy.deepcopy(original); data["result"]["scenarios"].pop(); variants.append(data)
        data = copy.deepcopy(original); data["result"]["scenarios"][0]["receipt_sha256"] = "invalid"; variants.append(data)
        for data in variants:
            output.write_bytes(canonical(data))
            with self.assertRaises(ContractError):
                container._accept_container_output(self.binding, CommandReceipt([], 0, b"", b"", executed=True))
        for include_digest in (False, True):
            data = {key: original[key] for key in ("schema", "request_sha256", "family", "system", "uid")}
            data.update(status="fail", code="SIDECAR_HARNESS_IMPORT", details={"substage": "verifier-source-readback"})
            if include_digest:
                data["source_readback_sha256"] = original["source_readback_sha256"]
            output.write_bytes(canonical(data))
            with self.assertRaises(ContractError) as caught:
                container._accept_container_output(self.binding, CommandReceipt([], 2, b"", b"", executed=True))
            self.assertEqual(caught.exception.code, "SIDECAR_HARNESS_IMPORT")
            self.assertEqual(caught.exception.details["substage"], "verifier-source-readback")
