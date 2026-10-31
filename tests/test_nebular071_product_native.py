"""Self-contained 071 reference, transport-bound and capability-refusal tests.

Genuine release-evidence audits run explicitly through
tools/verify_nebular071_public_inputs.py; no external fixture is loaded here.
"""
from __future__ import annotations
import copy
import gzip
import hashlib
import io
import os
import shutil
import tempfile
import json
from pathlib import Path
import sys
import tarfile
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests")]
from rs9 import nebular071_product_native as native
from rs9 import nebular071_public_inputs as transport
from rs9 import wheel_nebular071_universal as builder
from rs9 import nebular071_smoke_support as support
from rs9 import nebular071_universal_consumer as consumer
from rs9.release_core import authenticate_release
from rs9.errors import ContractError
from rs9.tf_pypi_archive import AdmissionError
from rs9.scratch import canonical



def metadata(members):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for path, body in {"qualification-inputs.json": b"{}", **members}.items():
            info = tarfile.TarInfo(path)
            info.size, info.mode = len(body), 0o644
            archive.addfile(info, io.BytesIO(body))
    return gzip.compress(stream.getvalue(), mtime=0)


class ProductNative071Tests(unittest.TestCase):

    def test_closed_reference_rejects_wrong_domain_and_coordinates(self):
        self.assertEqual(native.validate_reference(native.reference()), native.reference())
        for field, value in (("repository", "Knowledge-Forge-AI/release-starport-9"),
                             ("workflow", ".github/workflows/other.yml"),
                             ("run_id", 1), ("run_attempt", 2),
                             ("tested_commit", "0" * 40), ("tested_tree", "0" * 40)):
            with self.subTest(field=field):
                bad = native.reference()
                bad[field] = value
                with self.assertRaises(ContractError):
                    native.validate_reference(bad)
        for mutate in (lambda r: r["lanes"].append(r["lanes"][0]),
                       lambda r: r["lanes"].pop(),
                       lambda r: r["catalog"].update(sha256="0" * 64),
                       lambda r: r.update(admitted=True)):
            bad = native.reference()
            mutate(bad)
            with self.assertRaises(ContractError):
                native.validate_reference(bad)


    def test_json_and_unregistered_objects_cannot_mint_admission(self):
        for impostor in (native.reference(), {}, object(), native._NativePayloadAdmission.__new__(native._NativePayloadAdmission)):
            with self.assertRaises(ContractError):
                native.require_native_admission(impostor, object(), native.reference())
        with self.assertRaises(ContractError):
            native._NativePayloadAdmission()


    def test_ordinary_member_limit_remains_eight_mib_and_aggregate_32_mib(self):
        self.assertEqual(transport.MAX_METADATA_MEMBER_BYTES, 8 * 1024 * 1024)
        self.assertEqual(transport.MAX_METADATA_BYTES, 32 * 1024 * 1024)
        with self.assertRaises(ContractError):
            transport._archive_members(metadata({"evidence/ordinary.json": b"x" * (8 * 1024 * 1024 + 1)}))
        with self.assertRaises(ContractError):
            transport._archive_members(metadata({transport.SOURCE_ARCHIVE_PATH: b"x" * transport.SOURCE_ARCHIVE_SIZE}))
        with self.assertRaises(ContractError):
            transport._archive_members(metadata({"evidence/part" + str(i) + ".json": b"x" * (7 * 1024 * 1024)
                                                for i in range(5)}))
        with self.assertRaises(ContractError):
            transport._archive_members(metadata({"evidence/member" + str(i) + ".json": b"{}"
                                                for i in range(513)}))

    def test_launcher_has_no_actions_admission_dependency(self):
        for name in ("nebular071_universal_launcher.py", "nebular071_universal_fetch.py"):
            body = (ROOT / "src/rs9" / name).read_text()
            self.assertNotIn("product_native", body)
            self.assertNotIn("actions/runs", body)
            self.assertNotIn("actions/artifacts", body)




if __name__ == "__main__":
    unittest.main()
