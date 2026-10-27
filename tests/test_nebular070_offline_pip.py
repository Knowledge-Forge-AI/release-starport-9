"""Focused contract tests for the explicit retained-pip Linux bootstrap."""
import inspect
from pathlib import Path
import tempfile
import unittest

from rs9.tf_pypi_archive import AdmissionError
from rs9.tf_pypi_consumer import (
    _NEBULAR_PIP_MANIFEST,
    _NEBULAR_PIP_MANIFEST_SHA256,
    _NEBULAR_PIP_ROOT,
    _nebular_offline_pip_input,
    _nebular_pip_command,
    _nebular_require_pip_bootstrap,
    _nebular_validate_pip_source,
)
from rs9 import tf_pypi_consumer as consumer
from rs9 import tf_pypi_hosted as hosted


class Nebular070OfflinePipTests(unittest.TestCase):
    def test_default_public_seams_remain_disabled(self):
        self.assertIsNone(inspect.signature(consumer.consume_nebular_candidate)
                          .parameters["offline_pip_bootstrap"].default)
        self.assertIsNone(inspect.signature(hosted.qualify_nebular070)
                          .parameters["offline_pip_bootstrap"].default)
        python = Path("/tmp/owned-venv/bin/python")
        args = ["install", "--no-index", "--no-deps", "wheel.whl"]
        self.assertEqual(_nebular_pip_command(python, args, None),
                         [python, "-I", "-B", "-m", "pip", *args])

    def test_opt_in_uses_only_authenticated_external_runner(self):
        python = Path("/tmp/owned-venv/bin/python")
        runner = Path(_NEBULAR_PIP_ROOT) / "__pip-runner__.py"
        source = {
            "runner": runner,
            "version": "25.0.1",
            "manifest_bytes": 148305,
            "manifest_sha256": _NEBULAR_PIP_MANIFEST_SHA256,
            "regular_files": 438,
            "regular_bytes": 4958315,
        }
        command = _nebular_pip_command(python, ["--python", str(python), "--version"], source)
        self.assertEqual(command, [python, "-I", "-B", runner,
                                   "--python", str(python), "--version"])
        self.assertNotIn("-m", command)
        self.assertEqual(str(runner), "/inputs/consumer-tools/pip/__pip-runner__.py")

    def test_fixed_mount_and_manifest_are_not_caller_selected(self):
        with self.assertRaises(AdmissionError) as caught:
            _nebular_offline_pip_input(
                {"root": "/tmp/other-pip", "manifest": _NEBULAR_PIP_MANIFEST},
                "linux-x64-gnu",
            )
        self.assertEqual(caught.exception.code, "TF_PYPI_NEBULAR_PIP_BOOTSTRAP")
        with self.assertRaises(AdmissionError) as caught:
            _nebular_offline_pip_input(
                {"root": _NEBULAR_PIP_ROOT, "manifest": "/tmp/other.json"},
                "linux-x64-gnu",
            )
        self.assertEqual(caught.exception.code, "TF_PYPI_NEBULAR_PIP_BOOTSTRAP")
        self.assertEqual(
            _NEBULAR_PIP_MANIFEST_SHA256,
            "747d67c414904ef1969601125e5566c55df59f0fe87634da028ead6384c9c071",
        )

    def test_bootstrap_probe_requires_exact_pinned_version_and_cleanup(self):
        clean = {
            "exit_code": 0,
            "timed_out": False,
            "output_limit_exceeded": False,
            "cleanup_known": True,
            "output_complete": True,
            "stdout_token": "pip 25.0.1 from /inputs/consumer-tools/pip (python 3.11)\n",
        }
        _nebular_require_pip_bootstrap(clean)
        for version in ("25.0.0", "25.0.1.dev0"):
            bad = {**clean, "stdout_token": f"pip {version} from /inputs/consumer-tools/pip (python 3.11)\n"}
            with self.assertRaises(AdmissionError) as caught:
                _nebular_require_pip_bootstrap(bad)
            self.assertEqual(caught.exception.code, "TF_PYPI_NEBULAR_PIP_BOOTSTRAP")
        bad_cleanup = {**clean, "cleanup_known": False}
        with self.assertRaises(AdmissionError) as caught:
            _nebular_require_pip_bootstrap(bad_cleanup)
        self.assertEqual(caught.exception.code, "TF_PYPI_NEBULAR_PIP_BOOTSTRAP")

    def test_manifest_byte_mutation_is_rejected_before_tree_use(self):
        with tempfile.TemporaryDirectory() as temp:
            manifest = Path(temp) / "pip-source.json"
            manifest.write_bytes(b"{\"schema\":\"tampered\"}\n")
            with self.assertRaises(AdmissionError) as caught:
                _nebular_validate_pip_source(Path(temp), manifest)
        self.assertEqual(caught.exception.code, "TF_PYPI_NEBULAR_PIP_BOOTSTRAP")


if __name__ == "__main__":
    unittest.main()
