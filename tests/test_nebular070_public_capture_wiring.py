"""Focused tests for the opt-in actual Stage-B capture wiring."""
from __future__ import annotations

import json
from contextlib import ExitStack
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from rs9 import nebular070_manylinux
from rs9 import nebular070_host_observation
from rs9 import nebular070_public_consumers
from rs9 import tf_pypi_nebular070_publish as publish
from rs9.tf_pypi_archive import AdmissionError, canonical


class PublicCaptureWiringTests(unittest.TestCase):
    def _fixture(self, root: Path) -> tuple[Path, Path, Path, Path]:
        bundle = root / "bundle"
        (bundle / "dist").mkdir(parents=True)
        (bundle / "candidate_receipt.json").write_bytes(
            canonical(
                {
                    "profile_result_sha256": "p" * 64,
                    "rows": [
                        {
                            "system": "aarch64-linux",
                            "wheel": {"filename": "nebular.whl"},
                        },
                    ],
                },
            ),
        )
        (bundle / "expected_artifacts.json").write_bytes(canonical({"schema": "expected"}))
        (bundle / "dist" / "nebular.whl").write_bytes(b"authenticated-wheel")
        raw_release = root / "raw-release.json"
        raw_release.write_bytes(b"{}")
        return bundle, root / "work", raw_release, root / "capture.json"

    def _patches(self, bundle: Path, raw_release: Path):
        candidate = {
            "profile_result_sha256": "p" * 64,
            "rows": [
                {
                    "system": "aarch64-linux",
                    "wheel": {"filename": "nebular.whl"},
                },
            ],
        }
        expected = {"schema": "expected"}
        qualification = {"status": "native-consumer-passed", "target": "linux-arm64-gnu"}
        host = {"schema": "host", "target": "aarch64-linux", "role": "floor"}
        wheel = {"archive_sha256": "w" * 64, "tag": "py3-none-linux_aarch64"}
        body = {"schema": "consumer", "status": "pass", "identity": "b" * 64}
        return (
            patch.object(publish, "_validate_bundle_file_set"),
            patch.object(publish, "_require_candidate_profile_sha", return_value="p" * 64),
            patch.object(publish, "repo_root", return_value=bundle),
            patch.object(publish, "validate_qualification_inputs_descriptor", return_value={}),
            patch.object(publish, "load_raw_release_handoff", return_value={}),
            patch.object(publish, "_verify_handoff_matches_descriptor"),
            patch.object(publish, "_git_output", return_value="t" * 40),
            patch.object(
                publish,
                "_load_candidate_stage_a",
                return_value=SimpleNamespace(digest="s" * 64),
            ),
            patch.object(publish, "qualify_nebular070", return_value=qualification),
            patch.object(
                nebular070_manylinux,
                "_wheel_snapshot",
                return_value=wheel,
            ),
            patch.object(
                nebular070_host_observation,
                "observe_host",
                return_value=(host, {"schema": "host-extras"}),
            ),
            patch.object(
                nebular070_public_consumers,
                "consumer_body_from_actual",
                return_value=body,
            ),
        )

    def test_paired_capture_reuses_one_qualification_and_writes_exact_envelope(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            bundle, work, raw_release, capture = self._fixture(Path(temp))
            output = Path(temp) / "qualification.json"
            patches = self._patches(bundle, raw_release)
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patches[7], patches[8] as qualify, patches[9] as wheel_snapshot, patches[10] as observe, patches[11] as project:
                result = publish.qualify_native_target(
                    bundle,
                    work,
                    output,
                    target="linux-arm64-gnu",
                    expected_commit="c" * 40,
                    run_id="run-1",
                    run_attempt="1",
                    raw_release_path=raw_release,
                    qualification_inputs={},
                    repository=bundle,
                    sandbox_prefix=("sandbox",),
                    real_user_state_snapshot=lambda _phase, _target: {},
                    consumer_host_role="floor",
                    consumer_capture_output=capture,
                )
            self.assertEqual(result, {"status": "native-consumer-passed", "target": "linux-arm64-gnu"})
            self.assertEqual(qualify.call_count, 1)
            observe.assert_called_once_with("floor")
            wheel_snapshot.assert_called_once()
            project.assert_called_once()
            self.assertEqual(json.loads(output.read_text()), result)
            envelope = json.loads(capture.read_text())
            self.assertEqual(
                set(envelope),
                {
                    "schema",
                    "evidence_mode",
                    "target",
                    "kind",
                    "body",
                    "qualification",
                    "host_observation",
                    "host_extras",
                },
            )
            self.assertEqual(envelope["schema"], "rs9.nebular070-public-consumer-capture.v1")
            self.assertEqual(envelope["evidence_mode"], "actual")
            self.assertEqual(envelope["target"], "linux-arm64-gnu")
            self.assertEqual(envelope["kind"], "floor")
            self.assertEqual(envelope["qualification"], result)
            self.assertEqual(envelope["body"], {"schema": "consumer", "status": "pass", "identity": "b" * 64})

    def test_no_opt_in_preserves_existing_single_receipt_path(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            bundle, work, raw_release, capture = self._fixture(Path(temp))
            output = Path(temp) / "qualification.json"
            patches = self._patches(bundle, raw_release)
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patches[7], patches[8] as qualify:
                result = publish.qualify_native_target(
                    bundle,
                    work,
                    output,
                    target="linux-arm64-gnu",
                    expected_commit="c" * 40,
                    run_id="run-1",
                    run_attempt="1",
                    raw_release_path=raw_release,
                    qualification_inputs={},
                    repository=bundle,
                    sandbox_prefix=("sandbox",),
                    real_user_state_snapshot=lambda _phase, _target: {},
                )
            self.assertEqual(result, {"status": "native-consumer-passed", "target": "linux-arm64-gnu"})
            self.assertEqual(qualify.call_count, 1)
            self.assertEqual(json.loads(output.read_text()), result)
            self.assertFalse(capture.exists())

    def test_invalid_pair_and_target_fail_before_bundle_or_native_work(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with patch.object(publish, "_require_real_directory") as require:
                with self.assertRaises(AdmissionError) as raised:
                    publish.qualify_native_target(
                        root / "missing-bundle",
                        root / "work",
                        root / "qualification.json",
                        target="linux-arm64-gnu",
                        expected_commit="c" * 40,
                        run_id="run-1",
                        run_attempt="1",
                        consumer_host_role="floor",
                    )
            self.assertEqual(raised.exception.code, "TF_PYPI_CONSUMER_CAPTURE_OPTIONS")
            require.assert_not_called()

            with patch.object(publish, "_require_real_directory") as require:
                with self.assertRaises(AdmissionError) as raised:
                    publish.qualify_native_target(
                        root / "missing-bundle",
                        root / "work",
                        root / "qualification.json",
                        target="darwin-arm64",
                        expected_commit="c" * 40,
                        run_id="run-1",
                        run_attempt="1",
                        consumer_host_role="floor",
                        consumer_capture_output=root / "capture.json",
                    )
            self.assertEqual(raised.exception.code, "TF_PYPI_CONSUMER_CAPTURE_TARGET")
            require.assert_not_called()

            existing = root / "existing-capture.json"
            existing.write_bytes(b"{}")
            with patch.object(publish, "_require_real_directory") as require:
                with self.assertRaises(AdmissionError) as raised:
                    publish.qualify_native_target(
                        root / "missing-bundle",
                        root / "work",
                        root / "qualification.json",
                        target="linux-arm64-gnu",
                        expected_commit="c" * 40,
                        run_id="run-1",
                        run_attempt="1",
                        consumer_host_role="floor",
                        consumer_capture_output=existing,
                    )
            self.assertEqual(raised.exception.code, "TF_PYPI_CONSUMER_CAPTURE_OUTPUT")
            require.assert_not_called()

            with patch.object(publish, "_require_real_directory") as require:
                with self.assertRaises(AdmissionError) as raised:
                    publish.qualify_native_target(
                        root / "missing-bundle",
                        root / "work",
                        root / "qualification.json",
                        target="linux-arm64-gnu",
                        expected_commit="c" * 40,
                        run_id="run-1",
                        run_attempt="1",
                        consumer_host_role="unknown",
                        consumer_capture_output=root / "capture.json",
                    )
            self.assertEqual(raised.exception.code, "TF_PYPI_CONSUMER_CAPTURE_ROLE")
            require.assert_not_called()

            same = root / "same.json"
            with patch.object(publish, "_require_real_directory") as require:
                with self.assertRaises(AdmissionError) as raised:
                    publish.qualify_native_target(
                        root / "missing-bundle",
                        root / "work",
                        same,
                        target="linux-arm64-gnu",
                        expected_commit="c" * 40,
                        run_id="run-1",
                        run_attempt="1",
                        consumer_host_role="floor",
                        consumer_capture_output=same,
                    )
            self.assertEqual(raised.exception.code, "TF_PYPI_CONSUMER_CAPTURE_OUTPUT")
            require.assert_not_called()


    def test_existing_qualification_output_fails_before_bundle_work(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output = root / "qualification.json"
            output.write_bytes(b"existing")
            with patch.object(publish, "_require_real_directory") as require:
                with self.assertRaises(AdmissionError) as raised:
                    publish.qualify_native_target(
                        root / "missing", root / "work", output,
                        target="linux-arm64-gnu", expected_commit="c" * 40,
                        run_id="run-1", run_attempt="1",
                        consumer_host_role="floor",
                        consumer_capture_output=root / "capture.json",
                    )
            self.assertEqual(raised.exception.code, "TF_PYPI_QUALIFY_OUTPUT")
            require.assert_not_called()
            self.assertEqual(output.read_bytes(), b"existing")

    def test_aliased_outputs_fail_before_bundle_work(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "nested").mkdir()
            with patch.object(publish, "_require_real_directory") as require:
                with self.assertRaises(AdmissionError) as raised:
                    publish.qualify_native_target(
                        root / "missing", root / "work", root / "qualification.json",
                        target="linux-arm64-gnu", expected_commit="c" * 40,
                        run_id="run-1", run_attempt="1",
                        consumer_host_role="floor",
                        consumer_capture_output=root / "nested" / ".." / "qualification.json",
                    )
            self.assertEqual(raised.exception.code, "TF_PYPI_CONSUMER_CAPTURE_OUTPUT")
            require.assert_not_called()

    def test_raw_release_collision_fails_before_materialization_or_native_work(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            bundle, work, raw_release, capture = self._fixture(root)
            future_raw = root / "future-raw.json"
            patches = self._patches(bundle, raw_release)
            with ExitStack() as stack:
                active = [stack.enter_context(item) for item in patches]
                materialize = stack.enter_context(
                    patch.object(publish, "materialize_raw_release_handoff")
                )
                with self.assertRaises(AdmissionError) as raised:
                    publish.qualify_native_target(
                        bundle, work, root / "qualification.json",
                        target="linux-arm64-gnu", expected_commit="c" * 40,
                        run_id="run-1", run_attempt="1",
                        raw_release_path=future_raw, qualification_inputs={},
                        repository=bundle, consumer_host_role="floor",
                        consumer_capture_output=future_raw,
                    )
            self.assertEqual(raised.exception.code, "TF_PYPI_CONSUMER_CAPTURE_OUTPUT")
            materialize.assert_not_called()
            active[8].assert_not_called()
            self.assertFalse(future_raw.exists())

    def test_parser_defaults_leave_capture_disabled(self) -> None:
        args = publish.parser().parse_args(
            [
                "qualify-native",
                "--target",
                "linux-arm64-gnu",
                "--bundle",
                "bundle",
                "--work",
                "work",
                "--output",
                "qualification.json",
                "--expected-commit",
                "c" * 40,
                "--run-id",
                "run-1",
                "--run-attempt",
                "1",
            ],
        )
        self.assertIsNone(args.consumer_host_role)
        self.assertIsNone(args.consumer_capture_output)


if __name__ == "__main__":
    unittest.main()
