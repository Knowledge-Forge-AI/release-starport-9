"""Tests for retain-once signed object store (rs9.signed_store)."""

import json
import os
from pathlib import Path
import tempfile
import unittest

from rs9.errors import ContractError
from rs9.signed_store import SignedStore, _digest


class SignedStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name).resolve()
        self.synthetic_trust = {
            "allowed_keys": {"synthetic-primary", "0xPRIMARY123"},
        }
        self.store = SignedStore(self.root, trust_config=self.synthetic_trust)

        self.unsigned = b"Hello release candidate 1.0.0"
        self.signed = b"SIGNED-PAYLOAD-RS9-v1.0.0-ED25519-SIG"
        self.issuer = "test-authority-key-1"
        self.evidence = {"key_id": "key-001", "algorithm": "ed25519"}

    def tearDown(self):
        self.temp_dir.cleanup()

    def dummy_validator(self, unsigned, signed, evidence):
        return {"verified_issuer":self.issuer,"primary_key_id":"synthetic-primary"}

    def failing_validator(self, unsigned, signed, evidence):
        return False

    def test_retain_and_retrieve_success(self):
        rec = self.store.retain(
            "dists/stable/Release.gpg",
            self.signed,
            self.unsigned,
            self.issuer,
            self.evidence,
            validator=self.dummy_validator,
        )
        self.assertEqual(rec["rel_path"], "dists/stable/Release.gpg")
        self.assertEqual(rec["unsigned_sha256"], _digest(self.unsigned))
        self.assertEqual(rec["signed_sha256"], _digest(self.signed))
        self.assertEqual(rec["issuer"], self.issuer)
        self.assertEqual(rec["byte_size"], len(self.signed))

        # Check retrieval
        retrieved_rec, retrieved_bytes = self.store.get("dists/stable/Release.gpg")
        self.assertEqual(retrieved_rec, rec)
        self.assertEqual(retrieved_bytes, self.signed)

        # Check content-addressed file exists
        ca_file = self.root / "objects" / rec["signed_sha256"]
        self.assertTrue(ca_file.exists())
        self.assertEqual(ca_file.read_bytes(), self.signed)

    def test_synthetic_retained_store_cannot_reopen_under_production_trust(self):
        self.store.retain("dists/resolute/Release.gpg", self.signed, self.unsigned,
                          self.issuer, self.evidence, validator=self.dummy_validator)
        with self.assertRaises(ContractError) as caught:
            SignedStore(self.root)
        self.assertEqual(caught.exception.code, "UNPINNED_TRUST")

    def test_replay_is_byte_stable_and_does_not_call_validator(self):
        call_count = [0]

        def counting_validator(u, s, ev):
            call_count[0] += 1
            return {"verified_issuer":self.issuer,"primary_key_id":"synthetic-primary"}

        rec1 = self.store.retain(
            "dists/stable/Release.gpg",
            self.signed,
            self.unsigned,
            self.issuer,
            self.evidence,
            validator=counting_validator,
        )
        self.assertEqual(call_count[0], 1)

        # Replay exact same object
        rec2 = self.store.retain(
            "dists/stable/Release.gpg",
            self.signed,
            self.unsigned,
            self.issuer,
            self.evidence,
            validator=counting_validator,
        )
        # Validator should NOT be called again on replay
        self.assertEqual(call_count[0], 1)
        self.assertEqual(rec1, rec2)

        # File modification time should not change (not overwritten)
        ca_file = self.root / "objects" / rec1["signed_sha256"]
        mtime1 = ca_file.stat().st_mtime
        self.store.retain(
            "dists/stable/Release.gpg",
            self.signed,
            self.unsigned,
            self.issuer,
            self.evidence,
            validator=counting_validator,
        )
        self.assertEqual(ca_file.stat().st_mtime, mtime1)

    def test_replay_claim_mismatch_rejected(self):
        self.store.retain(
            "dists/stable/Release.gpg",
            self.signed,
            self.unsigned,
            self.issuer,
            self.evidence,
            validator=self.dummy_validator,
        )

        # Mismatched issuer claim
        with self.assertRaises(ContractError) as ctx:
            self.store.retain(
                "dists/stable/Release.gpg",
                self.signed,
                self.unsigned,
                "different-issuer",
                self.evidence,
                validator=self.dummy_validator,
            )
        self.assertEqual(ctx.exception.code, "OBJECT_CONFLICT")

        # Mismatched evidence claim
        with self.assertRaises(ContractError) as ctx:
            self.store.retain(
                "dists/stable/Release.gpg",
                self.signed,
                self.unsigned,
                self.issuer,
                {"key_id": "different-key"},
                validator=self.dummy_validator,
            )
        self.assertEqual(ctx.exception.code, "OBJECT_CONFLICT")

    def test_conflict_rejected_fail_closed(self):
        self.store.retain(
            "dists/stable/Release.gpg",
            self.signed,
            self.unsigned,
            self.issuer,
            self.evidence,
            validator=self.dummy_validator,
        )

        different_signed = b"DIFFERENT-SIGNATURE-BYTES"
        with self.assertRaises(ContractError) as ctx:
            self.store.retain(
                "dists/stable/Release.gpg",
                different_signed,
                self.unsigned,
                self.issuer,
                self.evidence,
                validator=self.dummy_validator,
            )
        self.assertEqual(ctx.exception.code, "OBJECT_CONFLICT")

    def test_persistence_restart(self):
        rec = self.store.retain(
            "dists/stable/Release.gpg",
            self.signed,
            self.unsigned,
            self.issuer,
            self.evidence,
            validator=self.dummy_validator,
        )
        # Create second store handle to simulate process restart
        restarted_store = SignedStore(self.root, trust_config=self.synthetic_trust)
        self.assertTrue(restarted_store.has("dists/stable/Release.gpg"))
        restarted_rec, restarted_bytes = restarted_store.get("dists/stable/Release.gpg")
        self.assertEqual(restarted_rec, rec)
        self.assertEqual(restarted_bytes, self.signed)
        restarted_store.verify_store_integrity()

    def test_two_paths_same_signed_bytes_no_overwrite(self):
        path1 = "dists/stable/Release.gpg"
        path2 = "dists/v1/Release.gpg"

        rec1 = self.store.retain(
            path1,
            self.signed,
            self.unsigned,
            self.issuer,
            self.evidence,
            validator=self.dummy_validator,
        )
        rec2 = self.store.retain(
            path2,
            self.signed,
            self.unsigned,
            self.issuer,
            self.evidence,
            validator=self.dummy_validator,
        )

        self.assertEqual(rec1["rel_path"], path1)
        self.assertEqual(rec2["rel_path"], path2)
        self.assertEqual(rec1["signed_sha256"], rec2["signed_sha256"])

        # Check retrieval returns correct rel_path for each
        got1, _ = self.store.get(path1)
        got2, _ = self.store.get(path2)
        self.assertEqual(got1["rel_path"], path1)
        self.assertEqual(got2["rel_path"], path2)

        # list_records contains both distinct records
        all_recs = self.store.list_records()
        self.assertEqual(len(all_recs), 2)
        paths = [r["rel_path"] for r in all_recs]
        self.assertIn(path1, paths)
        self.assertIn(path2, paths)

        # Restart and verify persistence of both paths
        restarted = SignedStore(self.root, trust_config=self.synthetic_trust)
        self.assertTrue(restarted.has(path1))
        self.assertTrue(restarted.has(path2))
        self.assertEqual(restarted.get(path1)[0]["rel_path"], path1)
        self.assertEqual(restarted.get(path2)[0]["rel_path"], path2)

    def test_forged_persisted_record_tamper_detected(self):
        rec = self.store.retain(
            "dists/stable/Release.gpg",
            self.signed,
            self.unsigned,
            self.issuer,
            self.evidence,
            validator=self.dummy_validator,
        )
        rec_hash = rec.sha256
        rec_file = self.root / "records" / f"{rec_hash}.json"
        self.assertTrue(rec_file.exists())

        # Forged record: alter unsigned_sha256 or issuer directly on disk
        rec_content = json.loads(rec_file.read_text())
        rec_content["issuer"] = "forged-attacker-key"
        rec_file.write_text(json.dumps(rec_content, indent=2))

        # Restarting store must detect tampered record against immutable manifest
        with self.assertRaises(ContractError) as ctx:
            SignedStore(self.root, trust_config=self.synthetic_trust)
        self.assertEqual(ctx.exception.code, "TAMPER_DETECTED")

    def test_tamper_detected_on_disk(self):
        rec = self.store.retain(
            "dists/stable/Release.gpg",
            self.signed,
            self.unsigned,
            self.issuer,
            self.evidence,
            validator=self.dummy_validator,
        )
        # Tamper the stored object on disk
        ca_file = self.root / "objects" / rec["signed_sha256"]
        ca_file.write_bytes(b"TAMPERED_BYTES")

        with self.assertRaises(ContractError) as ctx:
            self.store.get("dists/stable/Release.gpg")
        self.assertEqual(ctx.exception.code, "TAMPER_DETECTED")

        with self.assertRaises(ContractError) as ctx:
            self.store.verify_store_integrity()
        self.assertEqual(ctx.exception.code, "TAMPER_DETECTED")

    def test_issuer_binding_and_mismatch_rejected(self):
        def verifying_validator(u, s, ev):
            return {
                "verified_issuer": "verified-authority-primary",
                "primary_key_id": "0xPRIMARY123",
            }

        # Caller issuer mismatch against validator verified_issuer must fail
        with self.assertRaises(ContractError) as ctx:
            self.store.retain(
                "dists/stable/Release.gpg",
                self.signed,
                self.unsigned,
                "untrusted-input-issuer",
                self.evidence,
                validator=verifying_validator,
            )
        self.assertEqual(ctx.exception.code, "ISSUER_MISMATCH")

        # Matching caller issuer succeeds and binds
        rec = self.store.retain(
            "dists/stable/Release.gpg",
            self.signed,
            self.unsigned,
            "verified-authority-primary",
            self.evidence,
            validator=verifying_validator,
        )
        self.assertEqual(rec["issuer"], "verified-authority-primary")
        self.assertEqual(rec["evidence"]["verified_primary_key"], "0xPRIMARY123")

    def test_missing_or_failing_validator_rejected(self):
        # Missing validator
        with self.assertRaises(ContractError) as ctx:
            self.store.retain(
                "dists/stable/Release.gpg",
                self.signed,
                self.unsigned,
                self.issuer,
                self.evidence,
                validator=None,
            )
        self.assertEqual(ctx.exception.code, "VALIDATOR_REQUIRED")

        # Failing validator
        with self.assertRaises(ContractError) as ctx:
            self.store.retain(
                "dists/stable/Release.gpg",
                self.signed,
                self.unsigned,
                self.issuer,
                self.evidence,
                validator=self.failing_validator,
            )
        self.assertEqual(ctx.exception.code, "VERIFICATION_FAILED")
        for verdict in (True, {"verdict":"pass"}, {"verified_issuer":"asserted"}):
            with self.assertRaises(ContractError):
                self.store.retain("dists/stable/Release.gpg",self.signed,self.unsigned,
                    self.issuer,self.evidence,validator=lambda u,s,e:verdict)
        for evidence in ({"private_key":"forbidden"},{"credential":"forbidden"},{"path":"/"+"Users"+"/fixture/secret"}):
            with self.assertRaises(ContractError):
                self.store.retain("dists/stable/Release.gpg",self.signed,self.unsigned,
                    self.issuer,evidence,validator=self.dummy_validator)

    def test_record_hash_is_required_in_retained_manifest(self):
        path="dists/stable/Release.gpg"
        self.store.retain(path,self.signed,self.unsigned,self.issuer,self.evidence,validator=self.dummy_validator)
        manifest=json.loads(self.store.manifest_file.read_bytes())
        manifest["entries"][path]=manifest["entries"][path]["signed_sha256"]
        self.store.manifest_file.write_text(json.dumps(manifest))
        with self.assertRaises(ContractError):SignedStore(self.root, trust_config=self.synthetic_trust)

    def test_path_traversal_rejected(self):
        bad_paths = [
            "../etc/passwd",
            "/absolute/path",
            "dists/../../outside",
            "dists/stable\\backslash",
            "dists/\x00null",
        ]
        for bad_path in bad_paths:
            with self.subTest(path=bad_path):
                with self.assertRaises(ContractError) as ctx:
                    self.store.retain(
                        bad_path,
                        self.signed,
                        self.unsigned,
                        self.issuer,
                        self.evidence,
                        validator=self.dummy_validator,
                    )
                self.assertEqual(ctx.exception.code, "UNSAFE_PATH")

    def test_symlink_rejection(self):
        link_dir = self.root / "symlink_dir"
        real_target = self.root / "real_dir"
        real_target.mkdir()
        try:
            os.symlink(real_target, link_dir)
        except OSError:
            self.skipTest("Symlinks not supported on this filesystem")

        with self.assertRaises(ContractError) as ctx:
            SignedStore(link_dir, trust_config=self.synthetic_trust)
        self.assertEqual(ctx.exception.code, "SYMLINK_REJECTED")

    def test_destination_overwrite_denial_and_confined_writer(self):
        self.store.retain(
            "dists/stable/Release.gpg",
            self.signed,
            self.unsigned,
            self.issuer,
            self.evidence,
            validator=self.dummy_validator,
        )

        with tempfile.TemporaryDirectory() as deploy_temp:
            deploy_root = Path(deploy_temp).resolve()
            # Create a preexisting file in deploy_root
            (deploy_root / "preexisting.txt").write_text("already exists")

            # ConfinedWriter must deny overwrite because destination is not empty
            with self.assertRaises(ContractError) as ctx:
                self.store.assemble_deployment(deploy_root)
            self.assertEqual(ctx.exception.code, "OUTPUT_NOT_EMPTY")

    def test_assemble_deployment_and_rollback_protection(self):
        self.store.retain(
            "dists/stable/Release.gpg",
            self.signed,
            self.unsigned,
            self.issuer,
            self.evidence,
            validator=self.dummy_validator,
        )
        second_signed = b"SIGNED-INRELEASE-PAYLOAD"
        self.store.retain(
            "dists/stable/InRelease",
            second_signed,
            self.unsigned,
            self.issuer,
            self.evidence,
            validator=self.dummy_validator,
        )

        with tempfile.TemporaryDirectory() as deploy_temp:
            deploy_root = Path(deploy_temp).resolve()
            # Assemble without prior state into empty directory
            deployed = self.store.assemble_deployment(deploy_root)
            self.assertEqual(len(deployed), 2)
            self.assertTrue((deploy_root / "dists/stable/Release.gpg").exists())
            self.assertTrue((deploy_root / "dists/stable/InRelease").exists())

        # Unauthorized rollback attempt into a new empty directory
        with tempfile.TemporaryDirectory() as deploy_temp2:
            deploy_root2 = Path(deploy_temp2).resolve()
            prior_objects = ["dists/stable/Release.gpg", "dists/stable/InRelease", "dists/stable/OldPackage.deb"]
            with self.assertRaises(ContractError) as ctx:
                self.store.assemble_deployment(
                    deploy_root2,
                    current_objects=prior_objects,
                    reviewed_rollback=False,
                )
            self.assertEqual(ctx.exception.code, "UNAUTHORIZED_ROLLBACK")

        # Reviewed rollback succeeds into a new empty directory
        with tempfile.TemporaryDirectory() as deploy_temp3:
            deploy_root3 = Path(deploy_temp3).resolve()
            deployed3 = self.store.assemble_deployment(
                deploy_root3,
                current_objects=prior_objects,
                reviewed_rollback=True,
            )
            self.assertEqual(len(deployed3), 2)

    def test_cross_generation_retention_and_restart(self):
        # Two generations retain different signatures at identical deployment path without destructive conflict
        rel_path = "dists/stable/Release.gpg"
        sig_gen1 = b"SIGNATURE-GENERATION-1"
        unsigned_gen1 = b"RELEASE-DATA-GEN-1"
        sig_gen2 = b"SIGNATURE-GENERATION-2"
        unsigned_gen2 = b"RELEASE-DATA-GEN-2"

        store_gen1 = SignedStore(self.root, generation="gen-1", trust_config=self.synthetic_trust)
        rec1 = store_gen1.retain(
            rel_path,
            sig_gen1,
            unsigned_gen1,
            self.issuer,
            self.evidence,
            validator=self.dummy_validator,
        )

        store_gen2 = SignedStore(self.root, generation="gen-2", trust_config=self.synthetic_trust)
        rec2 = store_gen2.retain(
            rel_path,
            sig_gen2,
            unsigned_gen2,
            self.issuer,
            self.evidence,
            validator=self.dummy_validator,
        )

        self.assertEqual(rec1["signed_sha256"], _digest(sig_gen1))
        self.assertEqual(rec2["signed_sha256"], _digest(sig_gen2))
        self.assertNotEqual(rec1["signed_sha256"], rec2["signed_sha256"])

        # Both generation manifests exist independently
        manifest1_path = self.root / "generations" / "gen-1" / "manifest.json"
        manifest2_path = self.root / "generations" / "gen-2" / "manifest.json"
        self.assertTrue(manifest1_path.exists())
        self.assertTrue(manifest2_path.exists())

        m1 = json.loads(manifest1_path.read_text())
        m2 = json.loads(manifest2_path.read_text())
        self.assertEqual(m1["generation"], "gen-1")
        self.assertEqual(m2["generation"], "gen-2")
        self.assertEqual(m1["entries"][rel_path]["signed_sha256"], rec1["signed_sha256"])
        self.assertEqual(m2["entries"][rel_path]["signed_sha256"], rec2["signed_sha256"])

        # Immediate retrieval from separate handles
        self.assertEqual(store_gen1.get(rel_path)[1], sig_gen1)
        self.assertEqual(store_gen2.get(rel_path)[1], sig_gen2)

        # Restart simulation
        restarted_gen1 = SignedStore(self.root, generation="gen-1", trust_config=self.synthetic_trust)
        restarted_gen2 = SignedStore(self.root, generation="gen-2", trust_config=self.synthetic_trust)
        self.assertEqual(restarted_gen1.get(rel_path)[1], sig_gen1)
        self.assertEqual(restarted_gen2.get(rel_path)[1], sig_gen2)
        restarted_gen1.verify_store_integrity()
        restarted_gen2.verify_store_integrity()

        # Replay exact reuse on restarted handle does not invoke validator
        call_count = [0]

        def counting_validator(u, s, ev):
            call_count[0] += 1
            return {"verified_issuer": self.issuer, "primary_key_id": "synthetic-primary"}

        replayed_rec = restarted_gen1.retain(
            rel_path,
            sig_gen1,
            unsigned_gen1,
            self.issuer,
            self.evidence,
            validator=counting_validator,
        )
        self.assertEqual(call_count[0], 0)
        self.assertEqual(replayed_rec, rec1)

        # Destructive conflict rejected within generation
        with self.assertRaises(ContractError) as ctx:
            restarted_gen1.retain(
                rel_path,
                sig_gen2,
                unsigned_gen2,
                self.issuer,
                self.evidence,
                validator=self.dummy_validator,
            )
        self.assertEqual(ctx.exception.code, "OBJECT_CONFLICT")

        # Explicit generation selection from root store API
        root_store = SignedStore(self.root, trust_config=self.synthetic_trust)
        self.assertEqual(root_store.list_generations(), ["gen-1", "gen-2"])
        self.assertTrue(root_store.has_generation("gen-1"))
        self.assertTrue(root_store.has_generation("gen-2"))
        self.assertFalse(root_store.has_generation("gen-999"))

        self.assertEqual(root_store.get(rel_path, generation="gen-1")[1], sig_gen1)
        self.assertEqual(root_store.get(rel_path, generation="gen-2")[1], sig_gen2)
        self.assertTrue(root_store.has(rel_path, generation="gen-1"))
        self.assertTrue(root_store.has(rel_path, generation="gen-2"))

        # Assembly per generation deploys correct exact signature
        with tempfile.TemporaryDirectory() as d1, tempfile.TemporaryDirectory() as d2:
            deploy1 = Path(d1).resolve()
            deploy2 = Path(d2).resolve()
            root_store.assemble_deployment(deploy1, generation="gen-1")
            root_store.assemble_deployment(deploy2, generation="gen-2")
            self.assertEqual((deploy1 / rel_path).read_bytes(), sig_gen1)
            self.assertEqual((deploy2 / rel_path).read_bytes(), sig_gen2)

    def test_cross_generation_repo_db_signatures(self):
        # Multiple generations retain distinct Release.gpg, InRelease, and repo DB signatures
        files = {
            "dists/stable/Release.gpg": (b"REL-GPG-GEN1", b"REL-GPG-GEN2"),
            "dists/stable/InRelease": (b"INREL-GEN1", b"INREL-GEN2"),
            "dists/stable/main/binary-amd64/Packages.gpg": (b"PKG-SIG-GEN1", b"PKG-SIG-GEN2"),
        }
        unsigned_base = b"COMMON-OR-VARYING-METADATA"

        store_g1 = SignedStore(self.root, generation="2026.1", trust_config=self.synthetic_trust)
        store_g2 = SignedStore(self.root, generation="2026.2", trust_config=self.synthetic_trust)

        for path, (sig1, sig2) in files.items():
            store_g1.retain(path, sig1, unsigned_base + b"-1", self.issuer, self.evidence, validator=self.dummy_validator)
            store_g2.retain(path, sig2, unsigned_base + b"-2", self.issuer, self.evidence, validator=self.dummy_validator)

        root_store = SignedStore(self.root, trust_config=self.synthetic_trust)
        root_store.verify_store_integrity()

        for path, (sig1, sig2) in files.items():
            self.assertEqual(root_store.get(path, generation="2026.1")[1], sig1)
            self.assertEqual(root_store.get(path, generation="2026.2")[1], sig2)

    def test_production_fingerprint_pin_required_in_real_production(self):
        # A store initialized without synthetic trust configuration requires the approved production pin
        prod_store = SignedStore(self.root)  # trust_config=None -> real production

        # 1. Synthetic or unapproved primary key fails with UNPINNED_TRUST
        with self.assertRaises(ContractError) as ctx:
            prod_store.retain(
                "dists/stable/Release.gpg",
                self.signed,
                self.unsigned,
                self.issuer,
                self.evidence,
                validator=self.dummy_validator,  # returns primary_key_id="synthetic-primary"
            )
        self.assertEqual(ctx.exception.code, "UNPINNED_TRUST")

        # 2. Approved primary but unapproved subkey fails with UNPINNED_TRUST
        def subkey_mismatch_validator(u, s, ev):
            return {
                "verified_issuer": "production-signer",
                "primary_key_id": "7D03EE84F8C7025FD2F3D772BF89DF6643C2F1AF",
                "signing_subkey": "UNAPPROVED_SUBKEY_FINGERPRINT",
            }

        with self.assertRaises(ContractError) as ctx:
            prod_store.retain(
                "dists/stable/Release.gpg",
                self.signed,
                self.unsigned,
                "production-signer",
                self.evidence,
                validator=subkey_mismatch_validator,
            )
        self.assertEqual(ctx.exception.code, "UNPINNED_TRUST")

        # 3. Approved production primary and signing subkey succeeds
        def production_validator(u, s, ev):
            return {
                "verified_issuer": "production-signer",
                "primary_key_id": "7D03EE84F8C7025FD2F3D772BF89DF6643C2F1AF",
                "signing_subkey": "C021E00EE3D37C459B0E1CB3199F8028126E8A8C",
            }

        rec = prod_store.retain(
            "dists/stable/Release.gpg",
            self.signed,
            self.unsigned,
            "production-signer",
            self.evidence,
            validator=production_validator,
        )
        self.assertEqual(rec["issuer"], "production-signer")
        self.assertEqual(rec["evidence"]["verified_primary_key"], "7D03EE84F8C7025FD2F3D772BF89DF6643C2F1AF")
        self.assertEqual(rec["evidence"]["verified_signing_subkey"], "C021E00EE3D37C459B0E1CB3199F8028126E8A8C")

    def test_synthetic_trust_fixture_limits(self):
        # Explicit fixture limits: only configured synthetic keys pass; unconfigured fails
        scoped_trust = {"primary_key_id": "fixture-key-alpha"}
        scoped_store = SignedStore(self.root, trust_config=scoped_trust)

        def alpha_validator(u, s, ev):
            return {"verified_issuer": "alpha-issuer", "primary_key_id": "fixture-key-alpha"}

        def beta_validator(u, s, ev):
            return {"verified_issuer": "beta-issuer", "primary_key_id": "fixture-key-beta"}

        # Configured key succeeds
        rec = scoped_store.retain(
            "dists/stable/Release.gpg",
            self.signed,
            self.unsigned,
            "alpha-issuer",
            self.evidence,
            validator=alpha_validator,
        )
        self.assertEqual(rec["issuer"], "alpha-issuer")

        # Unconfigured key rejected with UNPINNED_TRUST
        with self.assertRaises(ContractError) as ctx:
            scoped_store.retain(
                "dists/stable/InRelease",
                b"INRELEASE-SIG",
                self.unsigned,
                "beta-issuer",
                self.evidence,
                validator=beta_validator,
            )
        self.assertEqual(ctx.exception.code, "UNPINNED_TRUST")

        # Empty trust config rejects everything
        empty_store = SignedStore(self.root / "empty", trust_config={})
        with self.assertRaises(ContractError) as ctx:
            empty_store.retain(
                "dists/stable/Release.gpg",
                self.signed,
                self.unsigned,
                "alpha-issuer",
                self.evidence,
                validator=alpha_validator,
            )
        self.assertEqual(ctx.exception.code, "UNPINNED_TRUST")

    def test_generation_manifest_tamper_detected(self):
        store_gen1 = SignedStore(self.root, generation="gen-1", trust_config=self.synthetic_trust)
        store_gen1.retain(
            "dists/stable/Release.gpg",
            self.signed,
            self.unsigned,
            self.issuer,
            self.evidence,
            validator=self.dummy_validator,
        )

        manifest_path = self.root / "generations" / "gen-1" / "manifest.json"
        manifest_data = json.loads(manifest_path.read_text())
        manifest_data["generation"] = "tampered-generation-name"
        manifest_path.write_text(json.dumps(manifest_data))

        with self.assertRaises(ContractError) as ctx:
            SignedStore(self.root, generation="gen-1", trust_config=self.synthetic_trust)
        self.assertEqual(ctx.exception.code, "TAMPER_DETECTED")

    def test_generation_identifier_safety(self):
        bad_generations = ["../escape", "sub/dir", "gen\\backslash", "", "gen\x00null"]
        for bad_gen in bad_generations:
            with self.subTest(gen=bad_gen):
                with self.assertRaises(ContractError):
                    SignedStore(self.root, generation=bad_gen, trust_config=self.synthetic_trust)


if __name__ == "__main__":
    unittest.main()
