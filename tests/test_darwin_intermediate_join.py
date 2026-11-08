from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


REPOSITORY = Path(__file__).resolve().parents[1]
PACKET = REPOSITORY
FIXTURE_SOURCE = REPOSITORY / "tests/fixtures/native-rc-smoke-v0.8.0.mjs"
sys.path.insert(0, str(REPOSITORY / "src"))
from rs9 import nebular080_darwin_harness as HARNESS

from rs9 import nebular080_system_webkit as system_webkit  # noqa: E402
from rs9.current_os080 import CURRENT080_VERIFIER_FILES  # noqa: E402
from rs9.tf_pypi_archive import AdmissionError, sha256  # noqa: E402


def _fixture():
    source = FIXTURE_SOURCE.read_bytes()
    record = CURRENT080_VERIFIER_FILES["tools/native-rc-smoke.mjs"]
    if (len(CURRENT080_VERIFIER_FILES) != 15
            or record["size"] != len(source)
            or record["sha256"] != sha256(source)):
        raise AssertionError("the 080 fixture does not match its authenticated record")
    directory = tempfile.TemporaryDirectory(dir=PACKET)
    try:
        root = Path(directory.name)
        tools = root / "tools"
        tools.mkdir()
        (tools / "native-rc-smoke.mjs").write_bytes(source)
        command = root / "tfnf"
        command.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        command.chmod(0o700)
        prepared = {
            "tools": tools,
            "tool_root": "tools",
            "records": [dict(record, path="tools/native-rc-smoke.mjs")],
        }
        return directory, prepared, command, root
    except Exception:
        directory.cleanup()
        raise


class DarwinIntermediateJoinTests(unittest.TestCase):
    def test_untampered_intermediate_round_trip_reaches_final_output(self):
        directory, prepared, command, root = _fixture()
        self.addCleanup(directory.cleanup)
        output, _process_harness, adapter = HARNESS.prepare_darwin_installed_harness(
            prepared, command, cache_root=root / "cache",
        )
        self.assertTrue(output.is_file())
        self.assertEqual(
            adapter["source_sha256"],
            sha256((prepared["tools"] / "native-rc-smoke-installed.mjs").read_bytes()),
        )

    def test_intermediate_disk_tamper_fails_before_final_output(self):
        directory, prepared, command, root = _fixture()
        self.addCleanup(directory.cleanup)
        real_prepare = system_webkit.prepare_installed_harness

        def tampered_prepare(*args, **kwargs):
            installed_source, installed_adapter = real_prepare(*args, **kwargs)
            installed_source.write_bytes(installed_source.read_bytes() + b"intermediate-tamper")
            return installed_source, installed_adapter

        final_output = prepared["tools"] / "native-rc-smoke-darwin-installed.mjs"
        with patch.object(system_webkit, "prepare_installed_harness",
                          side_effect=tampered_prepare) as wrapped:
            with self.assertRaisesRegex(AdmissionError, "TF_PYPI_NEBULAR_DARWIN_HARNESS"):
                HARNESS.prepare_darwin_installed_harness(
                    prepared, command, cache_root=root / "cache",
                )
            wrapped.assert_called_once()
        self.assertFalse(final_output.exists())


if __name__ == "__main__":
    unittest.main()
