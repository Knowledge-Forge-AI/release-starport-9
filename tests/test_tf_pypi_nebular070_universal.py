"""Pure bundle fixtures; no native application, network or registry writes."""
import contextlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from rs9 import tf_pypi_nebular070_universal as frontend
from rs9.errors import ContractError
import tests.test_wheel_nebular070_universal as fixtures


class UniversalBundleTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.UniversalWheelTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.spec.write_text(json.dumps(self.fixture.inputs))
        self.repository = Path(__file__).resolve().parents[1]
        self.source = {"commit": "a" * 40, "tree": "b" * 40}
        self.output = self.fixture.root / "bundle"
        self.descriptor = {"raw_release": {"targets": {
            target: {"payload": {"name": row["asset"]["name"], "path": row["asset"]["name"],
                                  "size": row["asset"]["size"], "sha256": row["asset"]["sha256"]}}
            for target, row in self.fixture.inputs["targets"].items()}}}
        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(patch.object(frontend, "RUNTIME_INPUTS", self.fixture.spec))
        stack.enter_context(patch.object(frontend, "DESCRIPTION", self.fixture.description))
        stack.enter_context(patch.object(frontend, "_source", return_value=self.source))
        stack.enter_context(patch.object(frontend, "_descriptor", return_value=self.descriptor))
        stack.enter_context(patch.object(frontend, "_release_root", return_value=self.fixture.archives))

    def build(self):
        return frontend.build_bundle(
            self.fixture.root / "synthetic-inputs.json", self.fixture.root, self.output,
            repository=self.repository, expected_commit=self.source["commit"], require_clean=True)

    def test_exact_one_wheel_bundle_reads_back_with_source_and_false_publication_flags(self):
        result = self.build()
        checked, snapshot = frontend.load_bundle(
            self.output, repository=self.repository, expected_source=self.source)
        self.assertEqual(checked, result)
        self.assertEqual(snapshot["wheel"]["tag"], "py3-none-any")
        self.assertFalse(checked["publication_admitted"])
        self.assertFalse(checked["builder_can_publish"])
        self.assertEqual({p.name for p in (self.output / "dist").iterdir()}, {snapshot["wheel"]["filename"]})

    def test_surplus_files_changed_wheel_and_wrong_source_are_refused(self):
        result = self.build()
        with self.assertRaises(ContractError):
            frontend.load_bundle(self.output, repository=self.repository,
                                 expected_source={"commit": "c" * 40, "tree": "b" * 40})
        surplus = self.output / "dist" / "extra.whl"
        surplus.write_bytes(b"synthetic")
        with self.assertRaises(ContractError):
            frontend.load_bundle(self.output, repository=self.repository)
        surplus.unlink()
        wheel = self.output / "dist" / result["wheel"]["filename"]
        wheel.write_bytes(wheel.read_bytes() + b"changed")
        with self.assertRaises(ContractError):
            frontend.load_bundle(self.output, repository=self.repository)

    def test_build_receipt_and_bundle_cannot_claim_publication(self):
        self.build()
        for filename in ("universal-build-receipt.json", "bundle.json"):
            path = self.output / filename
            original = path.read_bytes()
            value = json.loads(original)
            value["builder_can_publish"] = True
            path.write_text(json.dumps(value))
            with self.assertRaises(ContractError):
                frontend.load_bundle(self.output, repository=self.repository)
            path.write_bytes(original)


class UniversalQualificationCommandTests(unittest.TestCase):
    """Command orchestration fixtures never execute a product or a provider."""

    def setUp(self):
        self.bundle_fixture = UniversalBundleTests()
        self.bundle_fixture.setUp()
        self.addCleanup(self.bundle_fixture.doCleanups)
        self.bundle_fixture.build()
        self.root = self.bundle_fixture.fixture.root
        self.repository = self.bundle_fixture.repository
        self.source = self.bundle_fixture.source
        self.bundle = self.bundle_fixture.output
        self.env = {
            "GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "Knowledge-Forge-AI/release-starport-9",
            "GITHUB_REF": "refs/heads/main", "GITHUB_SHA": self.source["commit"],
            "GITHUB_RUN_ID": "37", "GITHUB_RUN_ATTEMPT": "1",
        }
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.dict("os.environ", self.env, clear=True))

    def test_hosted_coordinates_are_checked_before_handoff_or_native_execution(self):
        for change in ({"GITHUB_REF": "refs/heads/staging"}, {"GITHUB_RUN_ATTEMPT": "2"},
                       {"GITHUB_REPOSITORY": "other/repo"}, {"GITHUB_SHA": "c" * 40}):
            with self.subTest(change=change), patch.dict("os.environ", change), patch.object(
                    frontend.consumer, "materialize_universal_handoff") as stage, patch.object(
                    frontend.consumer, "consume_universal_wheel") as consume:
                with self.assertRaises(ContractError):
                    frontend.qualify_native(
                        self.bundle, self.root / "work", self.root / "receipt.json",
                        target="darwin-arm64", expected_commit=self.source["commit"],
                        run_id="37", run_attempt="1", qualification_inputs=self.root / "input.json",
                        inrun_root=self.root, raw_release_path=self.root / "handoff/raw_release.json",
                        repository=self.repository)
                stage.assert_not_called()
                consume.assert_not_called()

    def test_actual_wheel_and_descriptor_handoff_reach_the_native_owner(self):
        result = {"synthetic": "native owner result"}
        handoff = {"root": str(self.root / "handoff")}
        def materialize(*_args, **_kwargs):
            (self.root / "handoff").mkdir()
            return handoff
        with patch.object(frontend.consumer, "materialize_universal_handoff", side_effect=materialize) as stage, \
             patch.object(frontend.consumer, "consume_universal_wheel", return_value=result) as consume:
            output = self.root / "receipt.json"
            value = frontend.qualify_native(
                self.bundle, self.root / "work", output, target="linux-x64-gnu", consumer_host_role="floor",
                expected_commit=self.source["commit"], run_id="37", run_attempt="1",
                qualification_inputs=self.root / "input.json", inrun_root=self.root,
                raw_release_path=self.root / "handoff/raw_release.json", repository=self.repository)
            self.assertEqual(value, result)
            self.assertEqual(json.loads(output.read_bytes()), result)
            self.assertEqual(stage.call_args.kwargs["target"], "linux-x64-gnu")
            self.assertEqual(consume.call_args.args[0].parent, self.bundle / "dist")
            self.assertEqual(consume.call_args.args[3], handoff)
            self.assertEqual(consume.call_args.kwargs["consumer_host_role"], "floor")
            self.assertEqual(consume.call_args.kwargs["source"], self.source)

    def test_matrix_requires_exact_three_newer_and_two_floor_receipts(self):
        receipts = self.root / "receipts"
        floors = self.root / "floors"
        receipts.mkdir()
        floors.mkdir()
        for target in frontend.builder.LAYOUTS:
            (receipts / target).mkdir()
            (receipts / target / "result.json").write_text("{}")
        for target in ("linux-arm64-gnu", "linux-x64-gnu"):
            (floors / target).mkdir()
            (floors / target / "result.json").write_text("{}")
            (floors / target / "missing-runtime.json").write_text("{}")
        frontend._receipt_file_set(receipts, floors)
        for mutation in ("extra", "absent", "symlink"):
            with self.subTest(mutation=mutation):
                if mutation == "extra":
                    changed = floors / "extra.json"
                    changed.write_text("{}")
                elif mutation == "absent":
                    changed = floors / "linux-arm64-gnu/missing-runtime.json"
                    changed.unlink()
                else:
                    changed = receipts / "darwin-arm64/result.json"
                    changed.unlink()
                    changed.symlink_to(receipts / "linux-arm64-gnu/result.json")
                with self.assertRaises(ContractError):
                    frontend._receipt_file_set(receipts, floors)
                if mutation != "absent": changed.unlink()
                if mutation != "extra": changed.write_text("{}")

    def test_parser_exposes_only_the_new_distribution_commands(self):
        arguments = ["build-bundle", "--qualification-inputs", "inputs.json", "--inrun-root", ".",
                     "--output", "bundle", "--expected-commit", self.source["commit"], "--require-clean"]
        parsed = frontend.parser().parse_args(arguments)
        self.assertEqual(parsed.operation, "build-bundle")
        self.assertTrue(parsed.require_clean)
        for old in ("build-candidates", "publish-resume-070", "qualify"):
            with self.subTest(operation=old), contextlib.redirect_stderr(__import__("io").StringIO()):
                with self.assertRaises(SystemExit): frontend.parser().parse_args([old])
