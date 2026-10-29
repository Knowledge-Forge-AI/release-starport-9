"""Closed system-WebKit selection and held-input preparation, without native claims."""
from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rs9 import tf_pypi_nebular070_publish as publish
from rs9.tf_pypi_archive import AdmissionError, canonical, sha256


SPEC = {
    "schema": "rs9.tf-pypi-nebular070-public-inrun-system-webkit.v1",
    "origin_kind": "public-in-run",
    "profile_id": "nebular-fusion-0.7.0-system-webkitgtk-4.1-v1",
}


class SystemWebKitInputTests(unittest.TestCase):
    def test_release_paths_are_a_fixed_pair_and_native_provenance_fields_are_closed(self):
        from rs9.errors import ContractError
        from rs9.operator import release_bindings, validate_release_binding
        value = release_bindings("0.7.0")
        bootstrap = "bootstrap/pre-rs9/theme-forge-nebular-0.7.0-system-webkit/manifest.json"
        expectations = "operators/tf-pypi/nebular-0.7.0/system-webkit-expectations.json"
        selector = {"path": "nebular-v0.7.0-native-ci-provenance.json",
                    "commit_field": "releaseCommit", "tree_field": "testedTree"}
        selected = {**value, "bootstrap_path": bootstrap, "expectations_path": expectations,
                    "provenance": selector}
        self.assertEqual(validate_release_binding(selected), selected)
        mutations = (
            {**selected, "bootstrap_path": value["bootstrap_path"]},
            {**selected, "expectations_path": value["expectations_path"]},
            {**selected, "bootstrap_path": "arbitrary/manifest.json"},
            {**selected, "provenance": {**selector, "commit_field": "testedCommit"}},
            {**selected, "provenance": {**selector, "tree_field": "tagTree"}},
            {**selected, "provenance": {**selector, "extra": True}},
        )
        for changed in mutations:
            with self.subTest(changed=changed), self.assertRaises(ContractError):
                validate_release_binding(changed)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.repository = self.base / "repository"
        self.repository.mkdir(mode=0o700)
        self.output = self.base / "inputs"
        self.source = {"commit": "1" * 40, "tree": "2" * 40}

    def test_exact_profile_is_explicit_and_detached(self):
        value = dict(SPEC)
        result = publish._validate_system_webkit_input_spec(value)
        self.assertEqual(result, SPEC)
        self.assertIsNot(result, value)

    def test_unknown_missing_and_extra_profile_values_refuse(self):
        values = [None, [], {**SPEC, "extra": True}]
        for key in SPEC:
            missing = dict(SPEC)
            missing.pop(key)
            values.append(missing)
            for wrong in (None, [], {}, "other"):
                values.append({**SPEC, key: wrong})
        for value in values:
            with self.subTest(value=value):
                with self.assertRaises(AdmissionError) as context:
                    publish._validate_system_webkit_input_spec(value)
                self.assertEqual(str(context.exception), "TF_PYPI_SYSTEM_WEBKIT_INPUT")

    def test_external_root_requires_exact_explicit_profile(self):
        self.output.mkdir(mode=0o700)
        self.assertEqual(
            publish._resolve_inrun_artifact_root(
                self.repository, None, self.output, system_webkit_spec=SPEC,
            ),
            self.output,
        )
        with self.assertRaises(AdmissionError):
            publish._resolve_inrun_artifact_root(self.repository, None, self.output)
        with self.assertRaises(AdmissionError):
            publish._resolve_inrun_artifact_root(
                self.repository,
                {"schema": publish.PUBLIC_INRUN_MANYLINUX_SCHEMA,
                 "origin_kind": "public-in-run"},
                self.output,
                system_webkit_spec=SPEC,
            )
        self.output.chmod(0o777)
        with self.assertRaises(AdmissionError):
            publish._resolve_inrun_artifact_root(
                self.repository, None, self.output, system_webkit_spec=SPEC,
            )

    def _prepare(self, *, dirty=False, transport_digest=None, descriptor=None):
        descriptor = copy.deepcopy(descriptor or {"system_webkit": SPEC})
        raw = canonical(descriptor)

        def transport(_manifest, output, *, repository_root):
            self.assertEqual(repository_root, self.repository)
            output.mkdir(mode=0o700)
            (output / publish.PUBLIC_INPUTS_TEMPLATE_DESCRIPTOR).write_bytes(raw)
            return {
                "schema": "controlled-test-transport",
                "manifest_sha256": "a" * 64,
                "release_id": 426333162,
                "descriptor": {"path": publish.PUBLIC_INPUTS_TEMPLATE_DESCRIPTOR,
                               "bytes": len(raw), "sha256": transport_digest or sha256(raw)},
                "metadata": {},
                "payloads": [],
            }

        def git(_root, args, _code):
            if args == ["rev-parse", "HEAD^{commit}"]:
                return self.source["commit"]
            if args == ["rev-parse", "HEAD^{tree}"]:
                return self.source["tree"]
            if args == ["status", "--porcelain", "--untracked-files=all"]:
                return " M changed.py" if dirty else ""
            raise AssertionError(args)

        with patch("rs9.nebular070_public_inputs.materialize_public_inputs", side_effect=transport), \
                patch.object(publish, "_git_output", side_effect=git), \
                patch.object(publish, "validate_qualification_inputs_descriptor", return_value=descriptor) as validate, \
                patch.object(publish, "_load_public_stage_a_adapter") as adapter:
            result = publish.prepare_public_inputs_070(
                "operators/inputs.json", self.output,
                repository=self.repository, rs9_source=self.source,
            )
            adapter.assert_not_called()
            validate.assert_called_once_with(
                descriptor, repository=self.repository,
                phase=publish.QUALIFICATION_INPUT_PHASE_PREP, inrun_root=self.output,
            )
        return result, raw

    def test_system_preparation_holds_descriptor_without_stage_a(self):
        result, raw = self._prepare()
        self.assertEqual(result["schema"], "rs9.tf-pypi-nebular070-public-inputs-preparation.v2")
        self.assertEqual(result["runtime_profile"], "system-webkitgtk-4.1")
        self.assertNotIn("stage_a", result)
        self.assertNotIn("tf_producer", result["source"])
        self.assertEqual((self.output / publish.PUBLIC_INPUTS_DESCRIPTOR).read_bytes(), raw)
        self.assertEqual(result["descriptor"]["sha256"], sha256(raw))
        self.assertTrue((self.output / publish.PUBLIC_INPUTS_PREPARATION_RECEIPT).is_file())

    def test_dirty_source_and_changed_transport_descriptor_refuse_before_output(self):
        for dirty, digest in ((True, None), (False, "b" * 64)):
            with self.subTest(dirty=dirty, digest=digest):
                with self.assertRaises(AdmissionError):
                    self._prepare(dirty=dirty, transport_digest=digest)
                self.assertFalse((self.output / publish.PUBLIC_INPUTS_DESCRIPTOR).exists())
                self.assertFalse((self.output / publish.PUBLIC_INPUTS_PREPARATION_RECEIPT).exists())
                (self.output / publish.PUBLIC_INPUTS_TEMPLATE_DESCRIPTOR).unlink()
                self.output.rmdir()

    def test_mixed_runtime_profiles_refuse_before_output(self):
        with self.assertRaises(AdmissionError) as context:
            self._prepare(descriptor={"system_webkit": SPEC, "manylinux": {}})
        self.assertEqual(str(context.exception), "TF_PYPI_QUALIFICATION_INPUTS_RUNTIME_PROFILE")
        self.assertFalse((self.output / publish.PUBLIC_INPUTS_DESCRIPTOR).exists())


if __name__ == "__main__":
    unittest.main()
