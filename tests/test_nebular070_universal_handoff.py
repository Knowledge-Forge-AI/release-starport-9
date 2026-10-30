"""Static handoff IO uses separate validated evidence and release roots."""
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from rs9 import nebular070_universal_consumer as consumer
from rs9.errors import ContractError
from rs9.tf_pypi_archive import AdmissionError


class UniversalHandoffTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.release = self.root / "release-inputs"
        self.evidence = self.root / "support-evidence"
        self.release.mkdir()
        self.evidence.mkdir()
        self.output = self.root / "handoff"
        def entry(base, name, body):
            path = base / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(body)
            return {"path": name, "size": len(body), "sha256": hashlib.sha256(body).hexdigest()}
        row = {name: entry(self.release, name + ".json", b'{"fixture":true}')
               for name in ("record", "payload", "manifest", "provenance")}
        tool = entry(self.evidence, "only-evidence/tool.mjs", b"synthetic tool")
        archive = entry(self.evidence, "only-evidence/source.tar.gz", b"synthetic source")
        authority = entry(self.evidence, "only-evidence/authority.json", b'{"fixture":true}')
        self.support = {
            "root": "smoke-support",
            "files": [{**tool, "path": "tools/tool.mjs", "evidence_path": tool["path"],
                       "blob": "a" * 40, "role": "tool"}],
            "source_binding": {
                "archive": {**archive, "path": "sources/source.tar.gz", "evidence_path": archive["path"]},
                "authority": {**authority, "path": "sources/authority.json", "evidence_path": authority["path"]},
            },
        }
        row.update(root="/must-not-override-owned-root", readme={"unused": True},
                   legal_files={"unused": True},
                   native_consumer={"linux-x64-gnu": {"smoke_support": {"fixture": True}}})
        self.descriptor = {"raw_release": {"source_root": "release-inputs", "targets": {"linux-x64-gnu": row}},
                           "evidence": {"source_root": "support-evidence", "files": []}}

    def materialize(self, output=None):
        # Descriptor/schema validation has separate established owner tests.
        # This fixture tests only the new IO routing and normalization seam.
        with patch("rs9.tf_pypi_nebular070_publish.validate_qualification_inputs_descriptor",
                   return_value=self.descriptor), patch(
                   "rs9.tf_pypi_nebular070_publish._resolve_inrun_artifact_root", return_value=self.root), patch(
                   "rs9.nebular070_smoke_support.validate_smoke_support", return_value=self.support):
            return consumer.materialize_universal_handoff(
                self.descriptor, self.output if output is None else output,
                target="linux-x64-gnu", repository=self.root, inrun_root=self.root)

    def test_distinct_evidence_root_is_read_and_descriptor_paths_are_removed(self):
        result = self.materialize()
        self.assertEqual(Path(result["root"]), self.output)
        self.assertEqual((self.output / "smoke-support/tools/tool.mjs").read_bytes(), b"synthetic tool")
        self.assertEqual((self.output / "smoke-support/sources/source.tar.gz").read_bytes(), b"synthetic source")
        support = result["native_consumer"]["linux-x64-gnu"]["smoke_support"]
        self.assertNotIn("evidence_path", support["files"][0])
        self.assertNotIn("evidence_path", support["source_binding"]["archive"])
        self.assertNotIn("readme", result)
        self.assertNotIn("legal_files", result)

    def test_failed_copy_removes_only_owned_leaf_and_preserves_sources(self):
        (self.evidence / "only-evidence/tool.mjs").write_bytes(b"changed fixture")
        with self.assertRaises(AdmissionError):
            self.materialize()
        self.assertFalse(self.output.exists())
        self.assertTrue(self.release.is_dir())
        self.assertTrue(self.evidence.is_dir())

    def test_missing_parent_is_not_created(self):
        output = self.root / "absent-parent" / "handoff"
        with self.assertRaises(ContractError):
            self.materialize(output)
        self.assertFalse(output.parent.exists())
