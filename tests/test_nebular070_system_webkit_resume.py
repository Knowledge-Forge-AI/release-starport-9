"""Profile-specific public-input extraction at the publication resume boundary."""

from pathlib import Path
import tempfile
import unittest

from rs9.tf_pypi_archive import AdmissionError
from rs9.tf_pypi_nebular070_publish import (
    MANYLINUX_ADMISSION_ARTIFACT,
    PUBLIC_INPUTS_ARTIFACT,
    PUBLIC_INPUTS_DESCRIPTOR,
    PUBLIC_INPUTS_PREPARATION_RECEIPT,
    PUBLIC_INPUTS_TEMPLATE_DESCRIPTOR,
    PUBLIC_STAGE_A_OUTPUT,
    SYSTEM_WEBKIT_RUNTIME_PROFILE,
    extract_public_external_artifact,
)
from test_nebular070_public_input_workflow import _zip_bytes


class SystemWebKitResumeExtractionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.files = {name: b"{}" for name in (
            PUBLIC_INPUTS_TEMPLATE_DESCRIPTOR,
            PUBLIC_INPUTS_DESCRIPTOR,
            "fetch-receipt.json",
            PUBLIC_INPUTS_PREPARATION_RECEIPT,
        )}

    def extract(self, **kwargs):
        archive = self.root / "inputs.zip"
        archive.write_bytes(_zip_bytes(self.files))
        return extract_public_external_artifact(
            archive, self.root / "out", artifact_name=PUBLIC_INPUTS_ARTIFACT,
            **kwargs,
        )

    def test_system_profile_extracts_inputs_without_fabricated_stage_a(self):
        result = self.extract(runtime_profile=SYSTEM_WEBKIT_RUNTIME_PROFILE)
        self.assertEqual(set(result["members"]), set(self.files))
        self.assertEqual((self.root / "out" / PUBLIC_INPUTS_DESCRIPTOR).read_bytes(), b"{}")
        self.assertFalse((self.root / "out" / PUBLIC_STAGE_A_OUTPUT).exists())

    def test_default_manylinux_profile_still_requires_stage_a(self):
        with self.assertRaisesRegex(AdmissionError, "PUBLIC_EXTERNAL_ARTIFACT"):
            self.extract()

    def test_system_profile_rejects_stage_a_claims(self):
        self.files[f"{PUBLIC_STAGE_A_OUTPUT}/payload-portability.json"] = b"{}"
        self.files[f"{PUBLIC_STAGE_A_OUTPUT}/stage-a-receipt.json"] = b"{}"
        with self.assertRaisesRegex(AdmissionError, "PUBLIC_EXTERNAL_ARTIFACT"):
            self.extract(runtime_profile=SYSTEM_WEBKIT_RUNTIME_PROFILE)

    def test_unknown_runtime_profile_fails_closed(self):
        with self.assertRaisesRegex(AdmissionError, "PUBLIC_EXTERNAL_ARTIFACT"):
            self.extract(runtime_profile="unknown-runtime")
        self.assertFalse((self.root / "out").exists())

    def test_system_profile_rejects_manylinux_admission_artifact(self):
        archive = self.root / "stage-b.zip"
        archive.write_bytes(_zip_bytes(self.files))
        with self.assertRaisesRegex(AdmissionError, "PUBLIC_EXTERNAL_ARTIFACT"):
            extract_public_external_artifact(
                archive, self.root / "out",
                artifact_name=MANYLINUX_ADMISSION_ARTIFACT,
                runtime_profile=SYSTEM_WEBKIT_RUNTIME_PROFILE,
            )
        self.assertFalse((self.root / "out").exists())

    def test_system_profile_still_requires_common_authority_files(self):
        del self.files[PUBLIC_INPUTS_PREPARATION_RECEIPT]
        with self.assertRaisesRegex(AdmissionError, "PUBLIC_EXTERNAL_ARTIFACT"):
            self.extract(runtime_profile=SYSTEM_WEBKIT_RUNTIME_PROFILE)
