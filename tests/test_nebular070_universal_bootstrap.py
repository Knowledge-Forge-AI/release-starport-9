"""Exercise the workflow's isolated metadata reader without repository imports."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest

from rs9 import nebular070_universal_workflow as workflow


class UniversalBootstrapTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.path = self.root / "publisher-authority/operators/tf-pypi/nebular-fusion-0.7.0-universal-publication.json"
        self.path.parent.mkdir(parents=True)
        section = workflow.publication_job_text().partition("- name: Resolve pinned universal qualification commit")[2]
        section = section.partition("- name: Checkout exact qualified source commit")[0]
        self.script = textwrap.dedent(section.split("<<'PY' >> \"$GITHUB_OUTPUT\"\n", 1)[1].rsplit("\n          PY", 1)[0])
        self.value = {
            "schema": "rs9.nebular070-universal-publication.v1",
            "repository": "Knowledge-Forge-AI/release-starport-9",
            "workflow": "rs9-tfnf-pypi-publish.yml",
            "source": {"commit": "a" * 40, "tree": "b" * 40},
            "run": {"id": "37", "attempt": "1"},
        }

    def run_reader(self):
        return subprocess.run([sys.executable, "-I", "-B", "-c", self.script],
                              cwd=self.root, env={**os.environ, "PYTHONPATH": str(self.root / "publisher-authority/src")},
                              stdin=subprocess.DEVNULL, capture_output=True, timeout=10)

    def test_reads_only_coordinates_without_executing_publisher_or_cwd_python(self):
        self.path.write_text(json.dumps(self.value))
        marker = self.root / "executed"
        poison = "from pathlib import Path; Path(%r).write_text('unexpected execution')\n" % str(marker)
        source = self.root / "publisher-authority/src/rs9"
        source.mkdir(parents=True)
        (source / "__init__.py").write_text(poison)
        (self.root / "json.py").write_text(poison)
        result = self.run_reader()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, ("qualification_commit=" + "a" * 40 + "\nqualification_run_id=37\n").encode())
        self.assertFalse(marker.exists())

    def test_malformed_duplicate_oversized_and_linked_metadata_fail_with_safe_code(self):
        originals = json.dumps(self.value).encode()
        variants = [b"not JSON PRIVATE_MARKER", b"x" * (1024 * 1024 + 1),
                    originals[:-1] + b',"source":{"commit":"c","tree":"d"}}',
                    json.dumps({**self.value, "run": {"id": True, "attempt": "1"}}).encode(),
                    json.dumps({**self.value, "source": {"commit": "main", "tree": "b" * 40}}).encode()]
        for variant in variants:
            self.path.write_bytes(variant)
            with self.subTest(size=len(variant)):
                result = self.run_reader()
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, b"")
                self.assertEqual(result.stderr, b"NEBULAR_UNIVERSAL_AUTHORITY_COORDINATES\n")
        target = self.root / "unrelated-metadata"
        target.write_bytes(originals)
        self.path.unlink()
        self.path.symlink_to(target)
        result = self.run_reader()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, b"NEBULAR_UNIVERSAL_AUTHORITY_COORDINATES\n")
