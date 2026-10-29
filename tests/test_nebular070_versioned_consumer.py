"""Synthetic tests for the explicit 0.7.0 manylinux consumer bridge.

The Stage-A object is built through the maintained validator, but the body
contents and hosted consumer are controlled fixtures.  These tests prove
plumbing and refusal behavior; they are not native portability evidence.
"""
from __future__ import annotations

import ast
import copy
import contextlib
import io
import json
import shutil
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from rs9 import nebular070_manylinux as manylinux
from rs9 import tf_pypi_hosted as hosted
from rs9 import tf_pypi_nebular070_publish as publish
from rs9.tf_pypi_archive import AdmissionError, canonical, sha256
import tests.test_nebular070_manylinux as _manylinux_tests
import tests.test_nebular070_public_consumers as _public_consumers_tests
from tests.test_tf_pypi_nebular070_publish import _complete_smoke_summary
import tests.test_tf_pypi_nebular070_gate2 as _gate2_tests


TARGETS = ("linux-arm64-gnu", "linux-x64-gnu")
CONSTRUCTION = {
    "construction_stage": "payload-portability",
    "release_admission": "external",
}


def _actual_stage_a():
    """Create actual-shaped Stage-A data through its maintained validator."""
    source = _manylinux_tests.Nebular070ManylinuxContractTests(
        "test_stage_a_builds_manylinux_wheels_and_stage_b_reads_real_record"
    )
    source.setUp()
    try:
        record = copy.deepcopy(source.stage_a_record)
        record["schema"] = manylinux.ARCHIVE_PORTABILITY_SCHEMA
        for row in record["targets"]:
            row["archive_member_manifest_sha256"] = source.manifest["manifest_sha256"]
        record["evidence_mode"] = "actual"
        unsigned = dict(record)
        unsigned.pop("identity")
        record["identity"] = manylinux._digest(unsigned)
        return manylinux.validate_nebular070_payload_portability(
            record,
            source.receipt_bodies,
            expected_tf_producer_source=source.tf_source,
            expected_rs9_tool_source=source.rs9_source,
        )
    finally:
        source.tearDown()


def _fixture():
    fixture = _gate2_tests.NebularGate2Fixture(
        "test_connected_fixture_runs_post_path_native_probe_for_three_targets"
    )
    fixture.setUp()
    return fixture


def _manylinux_fixture(fixture, stage_a):
    """Bind controlled Linux fixture rows to a validated Stage-A digest."""
    digest = stage_a.digest
    for target in TARGETS:
        row = fixture._candidate_row_for(target)
        expected = next(item for item in fixture.expected["wheels"] if item["target"] == target)
        tag = manylinux.manylinux_tag_for_target(target)
        filename = f"theme_forge_nebular_fusion-0.7.0-{tag}.whl"

        def mutate(entries, tag=tag, digest=digest):
            wheel_name = next(name for name in entries if name.endswith("/WHEEL"))
            wheel_info = entries[wheel_name].decode("utf-8")
            old_tag = next(line for line in wheel_info.splitlines() if line.startswith("Tag: "))
            entries[wheel_name] = wheel_info.replace(old_tag, f"Tag: {tag}").encode()
            provenance_name = next(name for name in entries if name.endswith("/_rs9/provenance.json"))
            provenance = json.loads(entries[provenance_name])
            provenance.update({
                **CONSTRUCTION,
                "manylinux_construction_receipt_sha256": digest,
                "candidate_status": "payload-qualified",
                "promotability": "payload-qualified",
                "policy": {
                    "status": "payload-qualified",
                    "receipt_sha256": digest,
                    "manylinux_proven": False,
                },
                "wheel_tag": tag,
            })
            entries[provenance_name] = canonical(provenance)

        wheel_bytes = _gate2_tests._rewrite_wheel(fixture.wheels[target], mutate)
        wheel_path = fixture.wheels[target].with_name(filename)
        wheel_path.write_bytes(wheel_bytes)
        fixture.wheels[target] = wheel_path
        row["wheel"].update({
            "filename": filename,
            "size": len(wheel_bytes),
            "sha256": sha256(wheel_bytes),
            "tag": tag,
        })
        row.update({
            **CONSTRUCTION,
            "manylinux_construction_receipt_sha256": digest,
        })
        expected.update({
            "filename": filename,
            "size": len(wheel_bytes),
            "sha256": sha256(wheel_bytes),
            "tag": tag,
            **CONSTRUCTION,
            "manylinux_construction_receipt_sha256": digest,
        })
    fixture.expected["record_sha256"] = sha256(
        canonical(sorted(fixture.expected["wheels"], key=lambda item: item["target"]))
    )
    return fixture


def _candidate_bundle(fixture, stage_a):
    bundle = fixture.root / "candidate-bundle"
    (bundle / "dist").mkdir(parents=True)
    (bundle / "candidate_receipt.json").write_bytes(canonical(fixture.candidate))
    (bundle / "expected_artifacts.json").write_bytes(canonical(fixture.expected))
    for target in ("darwin-arm64", *TARGETS):
        shutil.copyfile(fixture.wheels[target], bundle / "dist" / fixture.wheels[target].name)
    (bundle / "payload_portability.json").write_bytes(b" " + canonical({
        "schema": manylinux.ARCHIVE_PORTABILITY_INPUT_SCHEMA,
        "record": stage_a.record,
        "bodies": stage_a.receipt_bodies,
    }))
    return bundle


def _stage_a_descriptor(bundle):
    stage_a_path = bundle / "payload_portability.json"
    captured = stage_a_path.read_bytes()
    return {"manylinux": {
        "tf_producer_source": {"commit": "a" * 40, "tree": "b" * 40},
        "stage_a": {"path": str(stage_a_path), "size": len(captured), "sha256": sha256(captured)},
    }}


class Nebular070VersionedConsumerTests(unittest.TestCase):
    def test_bundle_file_set_refuses_non_string_stage_a_schema(self):
        fixture = _fixture()
        self.addCleanup(fixture.tearDown)
        bundle = _candidate_bundle(fixture, _actual_stage_a())
        publish._validate_bundle_file_set(bundle)
        payload = bundle / "payload_portability.json"
        original = json.loads(payload.read_bytes())
        for schema in ([], {}, None, False, 0):
            with self.subTest(schema=schema):
                payload.write_bytes(canonical({**original, "schema": schema}))
                with self.assertRaises(AdmissionError) as context:
                    publish._validate_bundle_file_set(bundle)
                self.assertEqual(str(context.exception), "TF_PYPI_BUNDLE_MANYLINUX_INPUT")

    def test_consumer_floor_subset_parses_as_python311_and_has_closed_imports(self):
        """Bookworm's Python 3.11 floor must parse the consumer/helper subset."""
        root = Path(__file__).resolve().parents[1]
        relative = (
            "src/rs9/tf_pypi_consumer.py",
            "src/rs9/tf_pypi_hosted.py",
            "src/rs9/nebular070_payload.py",
            "src/rs9/nebular070_pip.py",
        )
        for name in relative:
            tree = ast.parse((root / name).read_text(encoding="utf-8"),
                             filename=name, feature_version=(3, 11))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for item in node.names:
                        self.assertIn(item.name.split(".")[0], sys.stdlib_module_names)
                elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                    if node.module.startswith("rs9."):
                        self.assertTrue((root / "src" / Path(*node.module.split(".")).with_suffix(".py")).is_file())
                    else:
                        self.assertIn(node.module.split(".")[0], sys.stdlib_module_names)

    def test_generic_route_is_unchanged_without_stage_a(self):
        fixture = _fixture()
        self.addCleanup(fixture.doCleanups)
        baseline = hosted._nebular_expected_artifacts(fixture.expected, fixture.candidate)
        self.assertEqual(baseline["record_sha256"], fixture.expected["record_sha256"])
        self.assertNotIn("manylinux_stage_a_sha256", baseline)

    def test_manylinux_rows_require_nonfixture_stage_a_and_exact_joins(self):
        stage_a = _actual_stage_a()
        fixture = _manylinux_fixture(_fixture(), stage_a)
        self.addCleanup(fixture.doCleanups)

        with self.assertRaises(AdmissionError):
            hosted._nebular_expected_artifacts(fixture.expected, fixture.candidate)

        changed = copy.deepcopy(fixture.candidate)
        changed["rows"][1]["manylinux_construction_receipt_sha256"] = "0" * 64
        with self.assertRaises(AdmissionError):
            hosted._nebular_expected_artifacts(fixture.expected, changed, stage_a)

        fixture_only = manylinux.ValidatedPayloadPortability(
            stage_a.record, stage_a.digest, stage_a.receipt_bodies, True
        )
        with self.assertRaises(AdmissionError):
            hosted._nebular_expected_artifacts(fixture.expected, fixture.candidate, fixture_only)

    def test_nonfixture_package_projection_stage_a_is_refused_by_hosted_gate(self):
        archive_stage_a = _actual_stage_a()
        record = copy.deepcopy(archive_stage_a.record)
        record["schema"] = manylinux.PORTABILITY_SCHEMA
        for row in record["targets"]:
            row.pop("archive_member_manifest_sha256")
        unsigned = dict(record)
        unsigned.pop("identity")
        record["identity"] = manylinux._digest(unsigned)
        package_stage_a = manylinux.validate_nebular070_payload_portability(
            record,
            archive_stage_a.receipt_bodies,
            expected_tf_producer_source={
                "commit": record["tf_producer_source"]["commit"],
                "tree": record["tf_producer_source"]["tree"],
            },
            expected_rs9_tool_source={
                "commit": record["rs9_tool_source"]["commit"],
                "tree": record["rs9_tool_source"]["tree"],
            },
        )
        with self.assertRaises(AdmissionError):
            hosted._nebular_stage_a_digest(package_stage_a)

    def test_generic_route_refuses_unsolicited_stage_a_fields(self):
        fixture = _fixture()
        self.addCleanup(fixture.doCleanups)
        for field, value in {**CONSTRUCTION, "manylinux_construction_receipt_sha256": "a" * 64}.items():
            with self.subTest(field=field, location="expected-wheel"):
                expected = copy.deepcopy(fixture.expected)
                expected["wheels"][0][field] = value
                expected["record_sha256"] = sha256(canonical(
                    sorted(expected["wheels"], key=lambda item: item["target"])
                ))
                with self.assertRaises(AdmissionError):
                    hosted._nebular_expected_artifacts(expected, fixture.candidate)
            with self.subTest(field=field, location="candidate-row"):
                candidate = copy.deepcopy(fixture.candidate)
                candidate["rows"][0][field] = value
                with self.assertRaises(AdmissionError):
                    hosted._nebular_expected_artifacts(fixture.expected, candidate)

    def test_real_cli_refuses_stage_a_bytes_outside_descriptor_capture(self):
        stage_a = _actual_stage_a()
        fixture = _manylinux_fixture(_fixture(), stage_a)
        self.addCleanup(fixture.doCleanups)
        fixture.candidate["profile_result_sha256"] = "c" * 64
        bundle = _candidate_bundle(fixture, stage_a)
        descriptor = _stage_a_descriptor(bundle)
        stage_path = bundle / "payload_portability.json"
        original = stage_path.read_bytes()
        (fixture.root / "release.json").write_bytes(b"{}")
        for command in ("qualify-native", "admit-matrix"):
            for mutation, changed in (
                ("size", original + b"\n"),
                ("same-size-sha", b"\n" + original[1:]),
            ):
                with self.subTest(command=command, mutation=mutation):
                    output = fixture.root / "refused" / f"{command}-{mutation}.json"
                    self.assertEqual(json.loads(changed), json.loads(original))
                    stage_path.write_bytes(changed)
                    argv = [
                        command, "--bundle", str(bundle), "--output", str(output),
                        "--expected-commit", "1" * 40, "--run-id", "1", "--run-attempt", "1",
                    ]
                    if command == "qualify-native":
                        argv += ["--target", "linux-arm64-gnu", "--work", str(fixture.root / "work"),
                                 "--raw-release", str(fixture.root / "release.json")]
                    else:
                        argv += ["--receipts-dir", str(fixture.root / "receipts"),
                                 "--qualification-inputs", str(fixture.root / "inputs.json")]
                    with (
                        patch.object(publish, "load_qualification_inputs_descriptor", return_value=descriptor),
                        patch.object(publish, "load_raw_release_handoff", return_value={}),
                        patch.object(publish, "_verify_handoff_matches_descriptor"),
                        patch.object(publish, "_git_output", return_value="2" * 40),
                        patch.object(publish, "_load_candidate_stage_a", wraps=publish._load_candidate_stage_a) as load_stage_a,
                        patch.object(publish, "qualify_nebular070", return_value={}) as qualify,
                        patch.object(publish, "admit_nebular070_matrix", return_value={}) as admit,
                        contextlib.redirect_stderr(io.StringIO()),
                    ):
                        code = publish.main(argv)
                    load_stage_a.assert_called_once()
                    self.assertNotEqual(code, 0)
                    self.assertFalse(output.exists())
                    qualify.assert_not_called()
                    admit.assert_not_called()
        stage_path.write_bytes(original)

    def test_candidate_stage_a_nonstring_schema_is_an_admission_error(self):
        stage_a = _actual_stage_a()
        fixture = _manylinux_fixture(_fixture(), stage_a)
        self.addCleanup(fixture.doCleanups)
        bundle = _candidate_bundle(fixture, stage_a)
        stage_path = bundle / "payload_portability.json"
        envelope = json.loads(stage_path.read_bytes())
        descriptor_source = stage_a.record["rs9_tool_source"]
        for field, value in (("schema", {}), ("record.schema", [])):
            with self.subTest(field=field):
                candidate = copy.deepcopy(envelope)
                if field == "schema":
                    candidate["schema"] = value
                else:
                    candidate["record"]["schema"] = value
                stage_path.write_bytes(canonical(candidate))
                descriptor = _stage_a_descriptor(bundle)
                with self.assertRaises(AdmissionError):
                    publish._load_candidate_stage_a(
                        bundle,
                        descriptor,
                        expected_commit=descriptor_source["commit"],
                        expected_tree=descriptor_source["tree"],
                    )

    def test_validated_stage_a_reaches_existing_consumer_boundary(self):
        stage_a = _actual_stage_a()
        fixture = _manylinux_fixture(_fixture(), stage_a)
        self.addCleanup(fixture.doCleanups)
        candidate_receipt = sha256(canonical(fixture.candidate))
        stub_consumer = {
            "candidate_rs9_source": fixture.candidate["candidate_rs9_source"],
            "probes": {"synthetic": True},
        }
        with patch.object(hosted, "consume_nebular_candidate", return_value=stub_consumer) as consume:
            result = hosted.qualify_nebular070(
                fixture.candidate,
                fixture.wheels["linux-arm64-gnu"],
                fixture.raw_for("linux-arm64-gnu"),
                fixture.root / "versioned-work",
                expected_artifacts=fixture.expected,
                expected_commit="1" * 40,
                expected_tree="b" * 40,
                profile_sha256="c" * 64,
                candidate_receipt_sha256=candidate_receipt,
                target="linux-arm64-gnu",
                host_identity=fixture.identity("linux-arm64-gnu"),
                fixture_only=True,
                manylinux_stage_a=stage_a,
            )
        self.assertTrue(consume.called)
        self.assertEqual(result["manylinux_stage_a_sha256"], stage_a.digest)
        self.assertEqual(result["consumer"]["manylinux_stage_a_sha256"], stage_a.digest)

    def test_publisher_qualify_native_loads_bundle_stage_a_before_consumer(self):
        stage_a = _actual_stage_a()
        fixture = _manylinux_fixture(_fixture(), stage_a)
        self.addCleanup(fixture.doCleanups)
        fixture.candidate["profile_result_sha256"] = "c" * 64
        bundle = _candidate_bundle(fixture, stage_a)
        raw_path = fixture.root / "raw-release.json"
        raw_path.write_bytes(b"{}")
        out_path = fixture.root / "qualification" / "result.json"
        descriptor = _stage_a_descriptor(bundle)
        with (
            patch.object(publish, "load_qualification_inputs_descriptor", return_value=descriptor),
            patch.object(publish, "load_raw_release_handoff", return_value={}),
            patch.object(publish, "_verify_handoff_matches_descriptor"),
            patch.object(publish, "_git_output", return_value="2" * 40),
            patch.object(publish, "qualify_nebular070", return_value={"status": "synthetic"}) as qualify,
        ):
            code = publish.main([
                "qualify-native",
                "--target", "linux-arm64-gnu",
                "--bundle", str(bundle),
                "--work", str(fixture.root / "native-work"),
                "--output", str(out_path),
                "--expected-commit", "1" * 40,
                "--run-id", "1",
                "--run-attempt", "1",
                "--raw-release", str(raw_path),
            ])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out_path.read_bytes()), {"status": "synthetic"})
        self.assertIs(qualify.call_args.kwargs["manylinux_stage_a"].__class__, stage_a.__class__)
        self.assertEqual(qualify.call_args.kwargs["manylinux_stage_a"].digest, stage_a.digest)

    def test_publisher_matrix_cli_forwards_same_stage_a_context(self):
        """Exercise qualify-shaped receipts through the maintained matrix CLI seam."""
        stage_a = _actual_stage_a()
        fixture = _manylinux_fixture(_fixture(), stage_a)
        self.addCleanup(fixture.doCleanups)
        fixture.candidate["profile_result_sha256"] = "c" * 64
        bundle = _candidate_bundle(fixture, stage_a)
        receipts = fixture.root / "receipts"
        candidate_receipt = sha256(canonical(fixture.candidate))
        expected_tree = "2" * 40
        actual_shape = _public_consumers_tests.PublicStageBConsumerTests(
            "test_actual_result_rejects_failed_consumer_network_and_cleanup"
        )
        actual_shape.setUp()
        self.addCleanup(actual_shape.doCleanups)

        consumer_shapes = {}
        for target in ("darwin-arm64", *TARGETS):
            expected_wheel = next(row for row in fixture.expected["wheels"] if row["target"] == target)
            if target == "darwin-arm64":
                shaped = hosted.qualify_nebular070(
                    fixture.candidate,
                    fixture.wheels[target],
                    fixture.raw_for(target),
                    fixture.root / "shape-darwin-arm64",
                    expected_artifacts=fixture.expected,
                    expected_commit="1" * 40,
                    expected_tree=expected_tree,
                    profile_sha256="c" * 64,
                    candidate_receipt_sha256=candidate_receipt,
                    target=target,
                    run_id="1",
                    run_attempt="1",
                    sandbox_probe=fixture.sandbox_probe,
                    host_identity=fixture.identity(target),
                    fixture_only=True,
                    real_user_state_snapshot=fixture.real_user_state_snapshot,
                    manylinux_stage_a=stage_a,
                )
                consumer = copy.deepcopy(shaped["consumer"])
            else:
                consumer = copy.deepcopy(actual_shape._actual_result(target)["consumer"])
            consumer["candidate_rs9_source"] = copy.deepcopy(fixture.candidate["candidate_rs9_source"])
            consumer["wheel"] = copy.deepcopy(expected_wheel)
            consumer["sandbox"]["method"] = "explicit-isolation-prefix"
            gui = consumer["gui"]
            scenarios = {
                "linux-arm64-gnu": ("B",),
                "linux-x64-gnu": ("C", "C-signal"),
                "darwin-arm64": ("A",),
            }[target]
            consumer["application_smoke"] = _complete_smoke_summary(
                target,
                scenarios,
                gui_path=gui["smoke_path"],
                gui_sha=gui["sha256"],
            )
            consumer["status"] = "native-consumer-passed"
            consumer["fixture_only"] = False
            consumer["native_qualified"] = True
            consumer_shapes[target] = consumer

        def fake_consumer(candidate, wheel_path, raw_release, work, **kwargs):
            target = kwargs["target"]
            # Reuse the maintained complete actual-shaped consumer record so
            # this matrix test exercises the same smoke/GUI contract as the
            # production validator.  Only the candidate and wheel identities
            # belong to this test's fixture and are rebound here.
            consumer = copy.deepcopy(consumer_shapes[target])
            consumer["candidate_rs9_source"] = copy.deepcopy(candidate["candidate_rs9_source"])
            return consumer

        with (
            patch.object(hosted, "consume_nebular_candidate", side_effect=fake_consumer),
            patch.object(hosted, "source_commit", return_value="1" * 40),
            patch.object(hosted, "_nebular_tree", return_value=expected_tree),
        ):
            for target in ("darwin-arm64", *TARGETS):
                result = hosted.qualify_nebular070(
                    fixture.candidate,
                    fixture.wheels[target],
                    fixture.raw_for(target),
                    fixture.root / f"work-{target}",
                    expected_artifacts=fixture.expected,
                    expected_commit="1" * 40,
                    expected_tree=expected_tree,
                    profile_sha256="c" * 64,
                    candidate_receipt_sha256=candidate_receipt,
                    target=target,
                    run_id="1",
                    run_attempt="1",
                    host_identity=fixture.identity(target),
                    fixture_only=False,
                    manylinux_stage_a=stage_a,
                )
                target_dir = receipts / target
                target_dir.mkdir(parents=True)
                (target_dir / "result.json").write_bytes(canonical(result))

            output = fixture.root / "matrix" / "matrix_receipt.json"
            output.parent.mkdir()
            descriptor = _stage_a_descriptor(bundle)
            with (
                patch.object(publish, "load_qualification_inputs_descriptor", return_value=descriptor),
                patch.object(publish, "_git_output", return_value=expected_tree),
            ):
                code = publish.main([
                    "admit-matrix",
                    "--bundle", str(bundle),
                    "--receipts-dir", str(receipts),
                    "--output", str(output),
                    "--expected-commit", "1" * 40,
                    "--qualification-inputs", str(fixture.root / "qualification-inputs.json"),
                    "--run-id", "1",
                    "--run-attempt", "1",
                ])
        self.assertEqual(code, 0)
        matrix = json.loads(output.read_bytes())
        self.assertEqual(matrix["status"], "native-matrix-passed")
        self.assertEqual(matrix["manylinux_stage_a_sha256"], stage_a.digest)


if __name__ == "__main__":
    unittest.main()
