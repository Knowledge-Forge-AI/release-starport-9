"""Source tests for fail-closed hosted execution, without external build facilities."""
import json
import hashlib
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from rs9.errors import ContractError
from rs9.hosted_pipeline import run_lane, validate_host
from rs9.hosted_custody import verify_set
from rs9.build_native import validate_scratch_root
from rs9.hosted_summary import required

ROOT = Path(__file__).resolve().parents[1]

class HostedExecutionTests(unittest.TestCase):
    def test_all_ten_lanes_share_only_immutable_inputs_and_fresh_work(self):
        def snapshot(root):
            return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                    for p in root.rglob("*") if p.is_file()}
        rows = {row["lane"]: row for row in required(ROOT)}
        self.assertEqual(set(rows), {"authenticate", "pins", "wheels", "nix", "pacman", "rpm", "deb", "pages", "observe", "foundation3"})
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            inputs = base / "inputs"
            inputs.mkdir()
            (inputs / "artifact-manifest.json").write_text(json.dumps({"release_ingestion_sha256": "a" * 64}))
            pins = json.loads((ROOT / "operators/live1/targets.json").read_bytes())
            (inputs / "pins.json").write_text(json.dumps({"pins": pins}))
            (inputs / "downloaded-artifact.tgz").write_bytes(b"immutable-downloaded-bytes")
            input_identity = snapshot(inputs)
            previous_work = []
            for lane, row in rows.items():
                with self.subTest(lane=lane):
                    scratch = base / lane
                    scratch.mkdir()
                    snapshots, calls = {}, []
                    def capture(repository, root, **kwargs):
                        (root / "summary").mkdir()
                        (root / "summary/authentication.json").write_bytes(b"{}")
                        (root / "archive.tgz").write_bytes(b"authenticated-payload")
                        snapshots["capture"] = snapshot(root)
                        return []
                    def bind(captures, repository, root):
                        path = root / "command-bindings.json"
                        path.write_bytes(b"bindings")
                        return path
                    def execute(context):
                        work = validate_scratch_root(context["scratch"])
                        self.assertEqual(work, scratch / "lane-work")
                        self.assertEqual(context["inputs"], inputs)
                        self.assertFalse(inputs.is_relative_to(work))
                        snapshots["auth"] = {p.name: p.read_bytes() for p in scratch.glob("authentication-*.json")}
                        path = work / "lane-result.json"
                        path.write_bytes(b"{}")
                        calls.append(work)
                        return {"gates": [{"name": name, "status": "pass"} for name in row["required_gates"]],
                                "artifacts": [path], "details": {"pins": {"all_source_pinned": True}}}
                    with patch("rs9.hosted_pipeline.validate_host"), \
                         patch("rs9.hosted_pipeline._inputs", return_value={("authenticate", "generation"): inputs, ("pins", "generation"): inputs}), \
                         patch("rs9.hosted_pipeline.capture_generation", side_effect=capture), \
                         patch("rs9.hosted_pipeline.canonical_release_auth_projection", return_value={}), \
                         patch("rs9.hosted_pipeline.compute_auth_sha256", return_value="a" * 64), \
                         patch("rs9.hosted_pipeline.bind_commands", side_effect=bind), \
                         patch("rs9.hosted_pipeline.runner_facts", return_value={}), \
                         patch("rs9.hosted_pipeline.importlib.import_module", return_value=SimpleNamespace(execute=execute)):
                        self.assertEqual(run_lane(ROOT, scratch, base / (lane + "-out"), lane, row["system"],
                                                  client=SimpleNamespace(receipts=[]), inputs=inputs), 0)
                    self.assertEqual(snapshot(inputs), input_identity)
                    self.assertEqual(snapshot(scratch / "capture"), snapshots["capture"])
                    if lane != "authenticate":
                        self.assertEqual(calls, [scratch / "lane-work"])
                        self.assertEqual({p.name: p.read_bytes() for p in scratch.glob("authentication-*.json")}, snapshots["auth"])
                    for directory, expected in previous_work:
                        self.assertEqual(snapshot(directory), expected)
                    previous_work.append((scratch / "lane-work", snapshot(scratch / "lane-work")))
                    with self.assertRaises(ContractError) as caught:
                        run_lane(ROOT, scratch, base / "unused", lane, row["system"], client=object())
                    self.assertEqual(caught.exception.code, "OUTPUT_NOT_EMPTY")

    def test_authentication_failure_retains_failure_custody_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            scratch,output = Path(tmp).resolve() / "work",Path(tmp).resolve() / "out"
            scratch.mkdir()
            with patch("rs9.hosted_pipeline.capture_generation",side_effect=ContractError("FETCH_FAILED","Unavailable")), patch("rs9.hosted_pipeline.runner_facts",return_value={}):
                code = run_lane(ROOT,scratch,output,"authenticate","generation",client=object())
            self.assertEqual(code,2)
            manifest = verify_set(output)
            self.assertEqual([r["path"] for r in manifest["files"]],["objects/command-report.json"])
            report = json.loads((output / "objects/command-report.json").read_bytes())
            self.assertEqual(report["commands"], [])
            self.assertEqual(len(report["unavailable"]), 6)
            receipt = json.loads((output / "authenticate-generation.json").read_bytes())
            self.assertEqual(receipt["execution_error"],"FETCH_FAILED")
            self.assertTrue(all(g["status"]=="fail" for g in receipt["gates"]))
            self.assertFalse(receipt["publication_authority"])

    def test_unknown_lane_and_dirty_scratch_fail_before_network(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve()
            with self.assertRaises(ContractError):
                run_lane(ROOT,root,root / "out","publish","generation",client=object())
            (root / "unrelated").write_text("state")
            with self.assertRaises(ContractError):
                run_lane(ROOT,root,root / "out","authenticate","generation",client=object())

    def test_architecture_mismatch_fails_before_release_fetch_and_retains_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            scratch, output = Path(tmp).resolve() / "work", Path(tmp).resolve() / "out"
            scratch.mkdir()
            with patch("rs9.hosted_pipeline.platform.system", return_value="Linux"), patch("rs9.hosted_pipeline.platform.machine", return_value="x86_64"), patch("rs9.hosted_pipeline.capture_generation") as capture, patch("rs9.hosted_pipeline.runner_facts", return_value={}):
                self.assertEqual(run_lane(ROOT, scratch, output, "wheels", "aarch64-linux", client=object()), 2)
            capture.assert_not_called()
            receipt = json.loads((output / "wheels-aarch64-linux.json").read_bytes())
            self.assertEqual(receipt["execution_error"], "HOSTED_ARCHITECTURE")

    def test_unexpected_builder_exception_preserves_bounded_failed_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            scratch, output = Path(tmp).resolve() / "work", Path(tmp).resolve() / "out"
            scratch.mkdir()
            with patch("rs9.hosted_pipeline.capture_generation", side_effect=RuntimeError("private diagnostic")), patch("rs9.hosted_pipeline.runner_facts", return_value={}):
                self.assertEqual(run_lane(ROOT, scratch, output, "authenticate", "generation", client=object()), 2)
            receipt = json.loads((output / "authenticate-generation.json").read_bytes())
            self.assertEqual(receipt["execution_error"], "hosted-execution-failed")
            self.assertNotIn("private diagnostic", json.dumps(receipt))
            detail = receipt["execution_error_detail"]
            self.assertEqual(detail["exception_type"], "RuntimeError")
            self.assertEqual(detail["module"], "rs9.hosted_candidate")
            self.assertEqual(len(detail["traceback_sha256"]), 64)
            self.assertTrue(detail["frame"].startswith("rs9/hosted_pipeline.py:"))
            self.assertNotIn(tmp, json.dumps(receipt))

    def test_lanes_receive_fresh_work_and_preserve_capture_and_custody(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            upstream = base / "upstream"
            upstream.mkdir()
            (upstream / "artifact-manifest.json").write_text(json.dumps({"release_ingestion_sha256": "a" * 64}))
            shared = upstream / "immutable-input.json"
            shared.write_bytes(b"custody-input")
            adapter_roots = []
            def capture(repository, root, **kwargs):
                (root / "summary").mkdir()
                (root / "summary/authentication.json").write_text("{}")
                (root / "immutable-capture.json").write_bytes(b"capture-input")
                return []
            def bind(captures, repository, root):
                path = root / "command-bindings.json"
                path.write_bytes(b"bindings")
                return path
            def execute(context):
                root = validate_scratch_root(context["scratch"])
                adapter_roots.append(root)
                self.assertEqual(root.name, "lane-work")
                self.assertEqual(list(root.iterdir()), [])
                (root / "command-bindings.json").write_bytes(b"lane-owned")
                diagnostic = root / "diagnostics"
                diagnostic.mkdir()
                (diagnostic / "failure.json").write_text('{"reason":"fixture-only"}')
                raise ContractError("FIXTURE_STOP", "Stop after proving scratch isolation")
            for lane, system in (("deb", "amd64"), ("pages", "generation")):
                scratch, output = base / lane, base / (lane + "-out")
                scratch.mkdir()
                with patch("rs9.hosted_pipeline.validate_host"), \
                     patch("rs9.hosted_pipeline._inputs", return_value={("authenticate", "generation"): upstream}), \
                     patch("rs9.hosted_pipeline.capture_generation", side_effect=capture), \
                     patch("rs9.hosted_pipeline.canonical_release_auth_projection", return_value={}), \
                     patch("rs9.hosted_pipeline.compute_auth_sha256", return_value="a" * 64), \
                     patch("rs9.hosted_pipeline.bind_commands", side_effect=bind), \
                     patch("rs9.hosted_pipeline.runner_facts", return_value={}), \
                     patch("rs9.hosted_pipeline.importlib.import_module", return_value=SimpleNamespace(execute=execute)):
                    self.assertEqual(run_lane(ROOT, scratch, output, lane, system,
                                              client=SimpleNamespace(receipts=[])), 2)
                self.assertEqual((scratch / "command-bindings.json").read_bytes(), b"bindings")
                self.assertEqual((scratch / "capture/immutable-capture.json").read_bytes(), b"capture-input")
                self.assertEqual(shared.read_bytes(), b"custody-input")
                self.assertTrue((output / "objects/lane-work/diagnostics/failure.json").is_file())
                receipt = json.loads((output / (lane + "-" + system + ".json")).read_bytes())
                self.assertEqual(receipt["execution_error"], "FIXTURE_STOP")
            self.assertNotEqual(*adapter_roots)
            self.assertEqual((adapter_roots[0] / "command-bindings.json").read_bytes(), b"lane-owned")
