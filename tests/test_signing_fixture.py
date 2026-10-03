"""Tests for ephemeral GPG signing fixture (rs9.signing_fixture)."""

import os
from pathlib import Path
import shutil
import tempfile
import unittest

from rs9.errors import ContractError
from rs9.signed_store import (
    PRODUCTION_PRIMARY_FINGERPRINT,
    PRODUCTION_SIGNING_SUBKEY,
    SignedStore,
)
from rs9.signing_fixture import (
    SigningFixture,
    find_gpg_binary,
    is_production_fingerprint,
)


class SigningFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.gpg_binary = find_gpg_binary()
        if not cls.gpg_binary:
            raise unittest.SkipTest("GnuPG binary not available in environment")
        try:
            with SigningFixture(gpg_binary=cls.gpg_binary):
                pass
        except ContractError as error:
            if error.code == "GPG_AGENT_UNAVAILABLE":
                raise unittest.SkipTest("Fixture GPG agent cannot run in this environment") from None
            raise

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name).resolve()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_ephemeral_key_generated_in_scratch(self):
        with SigningFixture(gpg_binary=self.gpg_binary) as fixture:
            self.assertTrue(fixture.scratch_dir.exists())
            self.assertEqual(len(fixture.primary_fingerprint), 40)
            self.assertTrue(all(c in "0123456789ABCDEF" for c in fixture.primary_fingerprint))
            self.assertIn("-----BEGIN PGP PUBLIC KEY BLOCK-----", fixture.public_key_armor)
            self.assertIn("-----END PGP PUBLIC KEY BLOCK-----", fixture.public_key_armor)
            self.assertTrue(len(fixture.public_key_binary) > 0)
            self.assertEqual(fixture.trust_config["primary_fingerprint"], fixture.primary_fingerprint)
            self.assertIn(fixture.primary_fingerprint, fixture.trust_config["allowed_keys"])

            scratch_path = fixture.scratch_dir

        # Scratch directory cleaned up after context exit
        self.assertFalse(scratch_path.exists())

    def test_refuses_production_fingerprints(self):
        self.assertTrue(is_production_fingerprint(PRODUCTION_PRIMARY_FINGERPRINT))
        self.assertTrue(is_production_fingerprint(PRODUCTION_SIGNING_SUBKEY))
        self.assertTrue(is_production_fingerprint(PRODUCTION_PRIMARY_FINGERPRINT.lower()))
        self.assertFalse(is_production_fingerprint("0123456789ABCDEF0123456789ABCDEF01234567"))

        with SigningFixture(gpg_binary=self.gpg_binary) as fixture:
            self.assertFalse(is_production_fingerprint(fixture.primary_fingerprint))

    def test_actual_gpg_detached_signing_and_verification(self):
        with SigningFixture(gpg_binary=self.gpg_binary) as fixture:
            data = b"Hello release candidate 1.0.0"
            sig = fixture.detach_sign(data, armor=True)
            self.assertIn(b"-----BEGIN PGP SIGNATURE-----", sig)

            ver = fixture.verify(data, sig)
            self.assertEqual(ver["status"], "valid")
            self.assertEqual(ver["verified_issuer"], fixture.primary_fingerprint)
            self.assertEqual(ver["primary_key_id"], fixture.primary_fingerprint)

            # Binary signature
            bin_sig = fixture.detach_sign(data, armor=False)
            self.assertNotIn(b"-----BEGIN PGP SIGNATURE-----", bin_sig)
            ver_bin = fixture.verify(data, bin_sig)
            self.assertEqual(ver_bin["status"], "valid")

    def test_actual_gpg_clearsigning_and_verification(self):
        with SigningFixture(gpg_binary=self.gpg_binary) as fixture:
            data = b"Suite: resolute\nCodename: resolute\n"
            clearsigned = fixture.clearsign(data)
            self.assertIn(b"-----BEGIN PGP SIGNED MESSAGE-----", clearsigned)
            self.assertIn(b"-----BEGIN PGP SIGNATURE-----", clearsigned)

            ver = fixture.verify(clearsigned)
            self.assertEqual(ver["status"], "valid")
            self.assertEqual(ver["verified_issuer"], fixture.primary_fingerprint)

    def test_tamper_detected_in_detached_signature(self):
        with SigningFixture(gpg_binary=self.gpg_binary) as fixture:
            data = b"Original uncorrupted data"
            sig = fixture.detach_sign(data)

            # 1. Tamper signature bytes
            tampered_sig = sig.replace(b"a", b"b")
            with self.assertRaises(ContractError) as ctx:
                fixture.verify(data, tampered_sig)
            self.assertEqual(ctx.exception.code, "VERIFICATION_FAILED")

            # 2. Tamper data bytes
            tampered_data = b"Modified malicious data"
            with self.assertRaises(ContractError) as ctx:
                fixture.verify(tampered_data, sig)
            self.assertEqual(ctx.exception.code, "VERIFICATION_FAILED")

    def test_tamper_detected_in_clearsigned_text(self):
        with SigningFixture(gpg_binary=self.gpg_binary) as fixture:
            data = b"Suite: resolute\n"
            clearsigned = fixture.clearsign(data)

            tampered = clearsigned.replace(b"resolute", b"malicious")
            with self.assertRaises(ContractError) as ctx:
                fixture.verify(tampered)
            self.assertEqual(ctx.exception.code, "VERIFICATION_FAILED")

    def test_unpinned_foreign_signer_rejected(self):
        with SigningFixture(gpg_binary=self.gpg_binary) as fixture_a:
            with SigningFixture(gpg_binary=self.gpg_binary) as fixture_b:
                data = b"Payload to sign"
                # Signed by B
                sig_b = fixture_b.detach_sign(data)

                # Verified against A (pinned to A's primary fingerprint)
                with self.assertRaises(ContractError) as ctx:
                    fixture_a.verify(data, sig_b)
                self.assertIn(ctx.exception.code, ("UNPINNED_TRUST", "VERIFICATION_FAILED"))

    def test_signed_store_retention_and_replay_with_fixture(self):
        store_root = self.root / "signed_store"
        store_root.mkdir()

        with SigningFixture(gpg_binary=self.gpg_binary) as fixture:
            store = SignedStore(store_root, trust_config=fixture.trust_config)

            unsigned = b"Release file bytes"
            signed = fixture.detach_sign(unsigned)

            rec = store.retain(
                "dists/resolute/Release.gpg",
                signed_bytes=signed,
                unsigned_bytes=unsigned,
                issuer=fixture.issuer,
                evidence={"algo": "ed25519"},
                validator=fixture.store_validator,
            )
            self.assertEqual(rec["rel_path"], "dists/resolute/Release.gpg")
            self.assertEqual(rec["issuer"], fixture.primary_fingerprint)

            retrieved_rec, retrieved_bytes = store.get("dists/resolute/Release.gpg")
            self.assertEqual(retrieved_bytes, signed)

            # Replay does not fail and returns original
            rec2 = store.retain(
                "dists/resolute/Release.gpg",
                signed_bytes=signed,
                unsigned_bytes=unsigned,
                issuer=fixture.issuer,
                evidence={"algo": "ed25519"},
                validator=fixture.store_validator,
            )
            self.assertEqual(rec, rec2)

    def test_signed_store_refuses_reopen_under_production_trust(self):
        store_root = self.root / "signed_store_prod_refusal"
        store_root.mkdir()

        with SigningFixture(gpg_binary=self.gpg_binary) as fixture:
            store = SignedStore(store_root, trust_config=fixture.trust_config)
            unsigned = b"Release payload"
            signed = fixture.detach_sign(unsigned)

            store.retain(
                "dists/resolute/Release.gpg",
                signed_bytes=signed,
                unsigned_bytes=unsigned,
                issuer=fixture.issuer,
                evidence={"algo": "ed25519"},
                validator=fixture.store_validator,
            )

        # Attempting to reopen store without synthetic trust fails
        with self.assertRaises(ContractError) as ctx:
            SignedStore(store_root)
        self.assertEqual(ctx.exception.code, "UNPINNED_TRUST")

    def test_missing_gpg_binary_raises_contract_error(self):
        with self.assertRaises(ContractError) as ctx:
            SigningFixture(gpg_binary="/nonexistent/path/to/gpg_binary_12345")
        self.assertEqual(ctx.exception.code, "GPG_NOT_AVAILABLE")


if __name__ == "__main__":
    unittest.main()
