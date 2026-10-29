"""Live paths must fail before an alias can enter a protected directory."""

import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from rs9.nebular070_installed_smoke import run_installed_smoke
from rs9.nebular070_smoke_support import installed_runtime_root
from rs9.tf_pypi_archive import AdmissionError
from rs9.tf_pypi_consumer import _nebular_descriptor


class Nebular070LivePathTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()

    def test_runtime_root_rejects_ancestor_aliases(self):
        for component in ("DB", "RAW", ".serena", ".git"):
            with self.subTest(component=component):
                protected = self.root / component
                (protected / "bin").mkdir(parents=True)
                (protected / "bin/gui").write_text("fixture", encoding="utf-8")
                alias = self.root / ("alias-" + component.strip("."))
                alias.symlink_to(protected, target_is_directory=True)
                with self.assertRaises(AdmissionError):
                    installed_runtime_root(alias / "bin/gui", "linux-arm64-gnu")

    def test_runtime_root_stops_before_alias_target_metadata(self):
        protected = self.root / "DB"
        (protected / "bin").mkdir(parents=True)
        alias = self.root / "alias"
        alias.symlink_to(protected, target_is_directory=True)
        original = os.lstat

        def guarded(path, *args, **kwargs):
            if "DB" in Path(path).parts:
                raise AssertionError("protected target metadata was queried")
            return original(path, *args, **kwargs)

        with mock.patch("os.lstat", side_effect=guarded):
            with self.assertRaises(AdmissionError):
                installed_runtime_root(alias / "bin/gui", "linux-arm64-gnu")

    def test_physical_runtime_root_preserves_layout(self):
        runtime = self.root / "payload"
        (runtime / "bin").mkdir(parents=True)
        (runtime / "bin/gui").write_text("fixture", encoding="utf-8")
        self.assertEqual(installed_runtime_root(runtime / "bin/gui", "linux-arm64-gnu"), runtime)

    def test_descriptor_rejects_protected_components_and_aliases(self):
        content = b"hermetic descriptor fixture"
        protected = self.root / "DB"
        protected.mkdir()
        (protected / "record.json").write_bytes(content)
        alias = self.root / "alias"
        alias.symlink_to(protected, target_is_directory=True)
        for relative in ("DB/record.json", "alias/record.json"):
            with self.subTest(relative=relative):
                descriptor = {"path": relative, "size": len(content),
                              "sha256": hashlib.sha256(content).hexdigest()}
                with self.assertRaises(AdmissionError):
                    _nebular_descriptor(self.root, descriptor, "record")

    def test_descriptor_physical_target_preserves_content_binding(self):
        content = b"hermetic descriptor fixture"
        (self.root / "record.json").write_bytes(content)
        digest = hashlib.sha256(content).hexdigest()
        self.assertEqual(_nebular_descriptor(
            self.root, {"path": "record.json", "size": len(content), "sha256": digest}, "record"
        ), (content, digest))

    def test_embedded_nul_is_an_admission_error(self):
        with self.assertRaises(AdmissionError):
            installed_runtime_root(str(self.root) + "/invalid\x00/bin/gui", "linux-arm64-gnu")

    def test_driver_checks_all_live_inputs_before_creating_output_or_running(self):
        protected = self.root / "DB"
        protected.mkdir()
        alias = self.root / "alias"
        alias.symlink_to(protected, target_is_directory=True)
        source = self.root / "source"
        tools = source / "tools"
        tools.mkdir(parents=True)
        harness = tools / "native-rc-smoke.mjs"
        harness.write_text("// hermetic unit fixture\n", encoding="utf-8")
        runtime = self.root / "payload"
        runtime.mkdir()
        for role in ("source", "tools", "evidence", "runtime"):
            with self.subTest(role=role):
                evidence = self.root / ("output-" + role)
                paths = {"source": source, "tools": tools, "evidence": evidence, "runtime": runtime}
                paths[role] = alias / ("output" if role == "evidence" else "input")
                if role in ("source", "tools"):
                    target = protected / "input"
                    target.mkdir(exist_ok=True)
                    (target / "native-rc-smoke.mjs").write_bytes(harness.read_bytes())
                with mock.patch("rs9.tf_pypi_consumer._nebular_run") as runner:
                    with self.assertRaises(AdmissionError):
                        run_installed_smoke(
                            prepared={"source": paths["source"], "tools": paths["tools"],
                                      "records": [{"path": "tools/native-rc-smoke.mjs",
                                                   "sha256": hashlib.sha256(harness.read_bytes()).hexdigest()}]},
                            target="linux-arm64-gnu", runtime_root=paths["runtime"],
                            env={}, prefix=[], evidence=paths["evidence"],
                            native={"command": "tfnf", "scenario": "B"}, gui={},
                            runner=None, timeout=1,
                        )
                    runner.assert_not_called()
                self.assertFalse(evidence.exists())


if __name__ == "__main__":
    unittest.main()
