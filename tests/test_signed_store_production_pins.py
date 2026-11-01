"""Tests for default-production SignedStore identity admission and persisted proof markers."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
from typing import Any
import unittest

from rs9.errors import ContractError
from rs9.records import record_sha256
from rs9.scratch import canonical
from rs9.signed_store import (
    PRODUCTION_PRIMARY_FINGERPRINT,
    PRODUCTION_SIGNING_SUBKEY,
    SCHEMA_SIGNED_OBJECT,
    SCHEMA_STORE_MANIFEST,
    SignedStore,
    _digest,
    _safe_write_file,
    _validate_trust,
)


def _prod_verdict(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "verified_issuer": "production-signer",
        "primary_key_id": PRODUCTION_PRIMARY_FINGERPRINT,
        "signing_subkey": PRODUCTION_SIGNING_SUBKEY,
    }
    base.update(overrides)
    return base


def _write_persisted_store(root: Path, evidence: dict[str, Any], signed: bytes, unsigned: bytes) -> dict[str, bytes]:
    store = SignedStore(root)
    rel_path = "dists/stable/Release.gpg"
    signed_sha = _digest(signed)
    _safe_write_file(store.objects_dir / signed_sha, signed)
    rec_data = {
        "schema": SCHEMA_SIGNED_OBJECT,
        "rel_path": rel_path,
        "unsigned_sha256": _digest(unsigned),
        "signed_sha256": signed_sha,
        "issuer": "production-signer",
        "evidence": evidence,
        "retained_at": "2026-10-31T00:00:00Z",
        "byte_size": len(signed),
    }
    rec_sha = record_sha256(rec_data)
    _safe_write_file(store.records_dir / f"{rec_sha}.json", canonical(rec_data))
    manifest = {
        "schema": SCHEMA_STORE_MANIFEST,
        "entries": {rel_path: {"record_sha256": rec_sha, "signed_sha256": signed_sha}},
    }
    _safe_write_file(store.manifest_file, canonical(manifest))
    return _tree_snapshot(root)


def _tree_snapshot(root: Path) -> dict[str, bytes]:
    return {
        p.relative_to(root).as_posix(): p.read_bytes()
        for p in sorted(root.rglob("*"))
        if p.is_file() and p.name != ".store.lock"
    }


class SignedStoreProductionPinTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name).resolve()
        self.unsigned = b"Release payload bytes v1"
        self.signed = b"DETACHED-SIGNATURE-BYTES-V1"
        self.issuer = "production-signer"
        self.nonidentity_evidence = {"key_id": "key-001", "algorithm": "ed25519"}

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _assert_retain_refused(
        self,
        verdict: dict[str, Any],
        evidence: dict[str, Any] | None = None,
        *,
        expected_code: str = "UNPINNED_TRUST",
    ) -> None:
        store_dir = self.root / f"refused_{len(list(self.root.iterdir()))}"
        store = SignedStore(store_dir)
        ev = self.nonidentity_evidence if evidence is None else evidence
        with self.assertRaises(ContractError) as ctx:
            store.retain(
                "dists/stable/Release.gpg",
                self.signed,
                self.unsigned,
                self.issuer,
                ev,
                validator=lambda u, s, e: verdict,
            )
        self.assertEqual(ctx.exception.code, expected_code)
        self.assertFalse(store.manifest_file.exists())
        self.assertEqual(list(store.records_dir.iterdir()), [])
        self.assertEqual(list(store.objects_dir.iterdir()), [])

    def test_baseline_defect_reproduction_closed(self) -> None:
        primary_only = {"verified_issuer": self.issuer, "primary_key_id": PRODUCTION_PRIMARY_FINGERPRINT}
        with self.assertRaises(ContractError) as c1:
            _validate_trust(primary_only, {}, None)
        self.assertEqual(c1.exception.code, "UNPINNED_TRUST")
        self._assert_retain_refused(primary_only, {})

        for ev_key in ("signing_subkey", "subkey_id", "verified_signing_subkey"):
            caller_ev = {ev_key: PRODUCTION_SIGNING_SUBKEY}
            with self.assertRaises(ContractError) as c2:
                _validate_trust(primary_only, caller_ev, None)
            self.assertEqual(c2.exception.code, "UNPINNED_TRUST")
            self._assert_retain_refused(primary_only, caller_ev)

        both_pins = _prod_verdict()
        _validate_trust(both_pins, {}, None)

    def test_production_validator_missing_invalid_and_short_pins_rejected(self) -> None:
        bad_verdicts = [
            _prod_verdict(primary_key_id=None),
            _prod_verdict(primary_key_id=""),
            _prod_verdict(primary_key_id="   "),
            _prod_verdict(primary_key_id="0" * 40),
            _prod_verdict(primary_key_id=PRODUCTION_SIGNING_SUBKEY),
            _prod_verdict(primary_key_id=PRODUCTION_PRIMARY_FINGERPRINT[-8:]),
            _prod_verdict(primary_key_id=PRODUCTION_PRIMARY_FINGERPRINT[-16:]),
            {"verified_issuer": self.issuer, "primary_key_id": PRODUCTION_PRIMARY_FINGERPRINT},
            _prod_verdict(signing_subkey=None),
            _prod_verdict(signing_subkey=""),
            _prod_verdict(signing_subkey="   "),
            _prod_verdict(signing_subkey="1" * 40),
            _prod_verdict(signing_subkey=PRODUCTION_PRIMARY_FINGERPRINT),
            _prod_verdict(signing_subkey=PRODUCTION_SIGNING_SUBKEY[-8:]),
            _prod_verdict(signing_subkey=PRODUCTION_SIGNING_SUBKEY[-16:]),
        ]
        for verdict in bad_verdicts:
            with self.subTest(verdict=verdict):
                self._assert_retain_refused(verdict)

        missing_primary_verdicts = [
            {"verified_issuer": self.issuer, "signing_subkey": PRODUCTION_SIGNING_SUBKEY},
            {
                "verified_issuer": self.issuer,
                "verified_primary_key": PRODUCTION_PRIMARY_FINGERPRINT,
                "verified_signing_subkey": PRODUCTION_SIGNING_SUBKEY,
            },
        ]
        for verdict in missing_primary_verdicts:
            with self.assertRaises(ContractError) as vt_ctx:
                _validate_trust(verdict, {}, None)
            self.assertEqual(vt_ctx.exception.code, "UNPINNED_TRUST")
            self._assert_retain_refused(verdict, expected_code="VERIFICATION_FAILED")

        for k in ("primary_key_id", "primary_fingerprint", "verified_primary_key"):
            caller_primary_ev = {k: PRODUCTION_PRIMARY_FINGERPRINT}
            with self.assertRaises(ContractError) as vt_ctx:
                _validate_trust(missing_primary_verdicts[0], caller_primary_ev, None)
            self.assertEqual(vt_ctx.exception.code, "UNPINNED_TRUST")
            self._assert_retain_refused(missing_primary_verdicts[0], caller_primary_ev, expected_code="VERIFICATION_FAILED")
            self._assert_retain_refused(_prod_verdict(primary_key_id=None), caller_primary_ev)

    def test_production_conflicting_aliases_and_caller_claims_rejected(self) -> None:
        conflicting_verdicts = [
            _prod_verdict(primary_fingerprint="0" * 40),
            _prod_verdict(primary_fingerprint=None),
            _prod_verdict(primary_fingerprint=""),
            _prod_verdict(primary_fingerprint=PRODUCTION_SIGNING_SUBKEY),
            _prod_verdict(subkey_id="1" * 40),
            _prod_verdict(subkey_id=None),
            _prod_verdict(subkey_id=""),
            _prod_verdict(subkey_id=PRODUCTION_PRIMARY_FINGERPRINT),
            _prod_verdict(verified_primary_key="0" * 40),
            _prod_verdict(verified_signing_subkey="1" * 40),
        ]
        for verdict in conflicting_verdicts:
            with self.subTest(verdict=verdict):
                self._assert_retain_refused(verdict)

        contradictory_caller_evidence = [
            {"primary_key_id": "0" * 40},
            {"primary_fingerprint": "0" * 40},
            {"verified_primary_key": "0" * 40},
            {"primary_key_id": PRODUCTION_SIGNING_SUBKEY},
            {"primary_key_id": None},
            {"signing_subkey": "1" * 40},
            {"subkey_id": "1" * 40},
            {"verified_signing_subkey": "1" * 40},
            {"signing_subkey": PRODUCTION_PRIMARY_FINGERPRINT},
            {"signing_subkey": None},
            {"verified_issuer": "different-issuer"},
        ]
        for bad_ev in contradictory_caller_evidence:
            with self.subTest(evidence=bad_ev):
                self._assert_retain_refused(_prod_verdict(), bad_ev)

    def test_accepted_validator_aliases_and_full_pin_normalization(self) -> None:
        spaced_primary = " ".join(
            PRODUCTION_PRIMARY_FINGERPRINT[i : i + 4] for i in range(0, len(PRODUCTION_PRIMARY_FINGERPRINT), 4)
        )
        spaced_subkey = " ".join(
            PRODUCTION_SIGNING_SUBKEY[i : i + 4] for i in range(0, len(PRODUCTION_SIGNING_SUBKEY), 4)
        )
        valid_cases = [
            {"verified_issuer": self.issuer, "primary_key_id": PRODUCTION_PRIMARY_FINGERPRINT, "signing_subkey": PRODUCTION_SIGNING_SUBKEY},
            {"verified_issuer": self.issuer, "primary_fingerprint": PRODUCTION_PRIMARY_FINGERPRINT, "subkey_id": PRODUCTION_SIGNING_SUBKEY},
            {
                "verified_issuer": self.issuer,
                "primary_fingerprint": "0x" + PRODUCTION_PRIMARY_FINGERPRINT.lower(),
                "signing_subkey": "  0X" + PRODUCTION_SIGNING_SUBKEY.lower() + "  ",
            },
            {"verified_issuer": self.issuer, "primary_key_id": spaced_primary, "subkey_id": spaced_subkey},
            {
                "verified_issuer": self.issuer,
                "primary_key_id": PRODUCTION_PRIMARY_FINGERPRINT,
                "primary_fingerprint": PRODUCTION_PRIMARY_FINGERPRINT,
                "signing_subkey": PRODUCTION_SIGNING_SUBKEY,
                "subkey_id": PRODUCTION_SIGNING_SUBKEY,
            },
        ]
        for idx, verdict in enumerate(valid_cases):
            with self.subTest(case=idx):
                store_dir = self.root / f"valid_alias_{idx}"
                store = SignedStore(store_dir)
                expected_p = verdict.get("primary_key_id") or verdict["primary_fingerprint"]
                expected_s = verdict.get("signing_subkey") or verdict["subkey_id"]
                ev = (
                    {**self.nonidentity_evidence, "primary_key_id": expected_p, "signing_subkey": expected_s}
                    if idx == 0
                    else self.nonidentity_evidence
                )
                rec = store.retain(
                    "dists/stable/Release.gpg",
                    self.signed,
                    self.unsigned,
                    self.issuer,
                    ev,
                    validator=lambda u, s, e, v=verdict: v,
                )
                self.assertEqual(rec["evidence"]["verified_primary_key"], expected_p)
                self.assertEqual(rec["evidence"]["verified_signing_subkey"], expected_s)
                self.assertEqual(rec["evidence"]["key_id"], "key-001")

                reopened = SignedStore(store_dir)
                got_rec, got_bytes = reopened.get("dists/stable/Release.gpg")
                self.assertEqual(got_rec, rec)
                self.assertEqual(got_bytes, self.signed)
                reopened.verify_store_integrity()

    def test_normalized_aliases_and_caller_claims_round_trip(self) -> None:
        cases = [
            (_prod_verdict(primary_fingerprint=PRODUCTION_PRIMARY_FINGERPRINT.lower()), {}),
            (_prod_verdict(subkey_id=PRODUCTION_SIGNING_SUBKEY.lower()), {}),
            (_prod_verdict(), {"primary_fingerprint": "0x" + PRODUCTION_PRIMARY_FINGERPRINT.lower()}),
            (_prod_verdict(), {"subkey_id": "0x" + PRODUCTION_SIGNING_SUBKEY.lower()}),
            (_prod_verdict(), {"primary_key_id": "0x" + PRODUCTION_PRIMARY_FINGERPRINT.lower()}),
            (_prod_verdict(), {"signing_subkey": "0x" + PRODUCTION_SIGNING_SUBKEY.lower()}),
        ]
        for index, (verdict, claims) in enumerate(cases):
            with self.subTest(case=index):
                directory = self.root / f"normalized_{index}"
                store = SignedStore(directory)
                record = store.retain(
                    "Release.gpg", self.signed, self.unsigned, self.issuer,
                    {**self.nonidentity_evidence, **claims},
                    validator=lambda *args, result=verdict: result,
                )
                reopened = SignedStore(directory)
                self.assertEqual(reopened.get("Release.gpg"), (record, self.signed))
                self.assertEqual(
                    reopened.retain(
                        "Release.gpg", self.signed, self.unsigned, self.issuer,
                        self.nonidentity_evidence, validator=None,
                    ), record,
                )

    def test_valid_production_retain_reopen_get_assemble_and_replay(self) -> None:
        store_dir = self.root / "prod_lifecycle"
        store = SignedStore(store_dir, generation="2026.10")
        calls = [0]

        def counting_validator(u: bytes, s: bytes, ev: dict[str, Any]) -> dict[str, Any]:
            calls[0] += 1
            return _prod_verdict()

        rec = store.retain(
            "dists/stable/InRelease",
            self.signed,
            self.unsigned,
            self.issuer,
            self.nonidentity_evidence,
            validator=counting_validator,
        )
        self.assertEqual(calls[0], 1)
        self.assertEqual(rec["evidence"]["verified_primary_key"], PRODUCTION_PRIMARY_FINGERPRINT)
        self.assertEqual(rec["evidence"]["verified_signing_subkey"], PRODUCTION_SIGNING_SUBKEY)
        self.assertEqual(rec["evidence"]["algorithm"], "ed25519")

        reopened = SignedStore(store_dir, generation="2026.10")
        reopened.verify_store_integrity()
        got_rec, got_bytes = reopened.get("dists/stable/InRelease")
        self.assertEqual(got_rec, rec)
        self.assertEqual(got_bytes, self.signed)

        deploy_dir = self.root / "deployed_tree"
        deploy_dir.mkdir()
        deployed = reopened.assemble_deployment(deploy_dir)
        self.assertEqual(len(deployed), 1)
        self.assertEqual((deploy_dir / "dists/stable/InRelease").read_bytes(), self.signed)

        before_files = _tree_snapshot(store_dir)
        replayed = reopened.retain(
            "dists/stable/InRelease",
            self.signed,
            self.unsigned,
            self.issuer,
            self.nonidentity_evidence,
            validator=lambda u, s, e: (_ for _ in ()).throw(AssertionError("validator called on replay")),
        )
        self.assertEqual(calls[0], 1)
        self.assertEqual(replayed, rec)
        self.assertEqual(_tree_snapshot(store_dir), before_files)

    def test_legacy_and_inconsistent_persisted_records_fail_closed_without_writes(self) -> None:
        base_ev = {
            "verified_issuer": self.issuer,
            "primary_key_id": PRODUCTION_PRIMARY_FINGERPRINT,
            "verified_primary_key": PRODUCTION_PRIMARY_FINGERPRINT,
            "signing_subkey": PRODUCTION_SIGNING_SUBKEY,
            "verified_signing_subkey": PRODUCTION_SIGNING_SUBKEY,
        }
        invalid_persisted_evidences = [
            {"verified_issuer": self.issuer, "primary_key_id": PRODUCTION_PRIMARY_FINGERPRINT, "verified_primary_key": PRODUCTION_PRIMARY_FINGERPRINT},
            {
                "verified_issuer": self.issuer,
                "primary_key_id": PRODUCTION_PRIMARY_FINGERPRINT,
                "verified_primary_key": PRODUCTION_PRIMARY_FINGERPRINT,
                "signing_subkey": PRODUCTION_SIGNING_SUBKEY,
            },
            {k: v for k, v in base_ev.items() if k != "verified_primary_key"},
            {k: v for k, v in base_ev.items() if k != "signing_subkey"},
            {k: v for k, v in base_ev.items() if k != "primary_key_id"},
            {**base_ev, "verified_signing_subkey": PRODUCTION_PRIMARY_FINGERPRINT},
            {**base_ev, "primary_fingerprint": "0" * 40},
            {**base_ev, "subkey_id": "1" * 40},
            {
                **base_ev,
                "signing_subkey": PRODUCTION_PRIMARY_FINGERPRINT,
                "verified_signing_subkey": PRODUCTION_PRIMARY_FINGERPRINT,
            },
        ]
        for idx, ev in enumerate(invalid_persisted_evidences):
            with self.subTest(case=idx):
                store_dir = self.root / f"legacy_{idx}"
                pre_handle = SignedStore(store_dir)
                snapshot_before = _write_persisted_store(store_dir, ev, self.signed, self.unsigned)

                with self.assertRaises(ContractError) as open_ctx:
                    SignedStore(store_dir)
                self.assertEqual(open_ctx.exception.code, "UNPINNED_TRUST")
                self.assertEqual(_tree_snapshot(store_dir), snapshot_before)

                with self.assertRaises(ContractError) as replay_ctx:
                    pre_handle.retain(
                        "dists/stable/Release.gpg",
                        self.signed,
                        self.unsigned,
                        self.issuer,
                        {},
                        validator=lambda u, s, e: _prod_verdict(),
                    )
                self.assertEqual(replay_ctx.exception.code, "UNPINNED_TRUST")
                with self.assertRaises(ContractError) as verify_ctx:
                    pre_handle.verify_store_integrity()
                self.assertEqual(verify_ctx.exception.code, "UNPINNED_TRUST")
                self.assertEqual(_tree_snapshot(store_dir), snapshot_before)

        residual_dir = self.root / "legacy_caller_marker_residual"
        _write_persisted_store(residual_dir, base_ev, self.signed, self.unsigned)
        reopened_residual = SignedStore(residual_dir)
        self.assertEqual(reopened_residual.get("dists/stable/Release.gpg")[1], self.signed)

    def test_persisted_normalized_markers_open_without_mutation(self) -> None:
        cases = [
            _prod_verdict(
                verified_primary_key="0x" + PRODUCTION_PRIMARY_FINGERPRINT.lower(),
                verified_signing_subkey=PRODUCTION_SIGNING_SUBKEY,
            ),
            _prod_verdict(
                verified_primary_key=PRODUCTION_PRIMARY_FINGERPRINT,
                verified_signing_subkey="0x" + PRODUCTION_SIGNING_SUBKEY.lower(),
            ),
        ]
        for index, evidence in enumerate(cases):
            with self.subTest(case=index):
                directory = self.root / f"normalized_markers_{index}"
                before = _write_persisted_store(directory, evidence, self.signed, self.unsigned)
                reopened = SignedStore(directory)
                self.assertEqual(reopened.get("dists/stable/Release.gpg")[1], self.signed)
                self.assertEqual(_tree_snapshot(directory), before)

    def test_synthetic_trust_configurations_preserved(self) -> None:
        configs: list[tuple[Any, dict[str, Any], dict[str, Any]]] = [
            ({"allowed_keys": {"syn-primary"}}, {"verified_issuer": "syn", "primary_key_id": "syn-primary"}, {}),
            (
                {"primary_fingerprint": "syn-primary", "signing_subkey": "syn-sub"},
                {"verified_issuer": "syn", "primary_key_id": "syn-primary", "subkey_id": "syn-sub"},
                {},
            ),
            (
                {"allowed_primary_keys": ["syn-p1"], "allowed_subkeys": ["syn-s1"]},
                {"verified_issuer": "syn", "primary_key_id": "syn-p1"},
                {"signing_subkey": "syn-s1"},
            ),
            ({"syn-primary", "syn-sub"}, {"verified_issuer": "syn", "primary_key_id": "syn-primary"}, {"subkey_id": "syn-sub"}),
            (["syn-primary"], {"verified_issuer": "syn", "primary_key_id": "syn-primary"}, {}),
            (("syn-primary", "syn-sub"), {"verified_issuer": "syn", "primary_key_id": "syn-primary", "signing_subkey": "syn-sub"}, {}),
        ]
        for idx, (trust_cfg, verdict, ev) in enumerate(configs):
            with self.subTest(config=idx):
                store_dir = self.root / f"syn_{idx}"
                store = SignedStore(store_dir, trust_config=trust_cfg)
                rec = store.retain("dists/stable/Release.gpg", self.signed, self.unsigned, "syn", ev, validator=lambda u, s, e, v=verdict: v)
                reopened = SignedStore(store_dir, trust_config=trust_cfg)
                self.assertEqual(reopened.get("dists/stable/Release.gpg")[0], rec)
                replayed = reopened.retain(
                    "dists/stable/Release.gpg",
                    self.signed,
                    self.unsigned,
                    "syn",
                    ev,
                    validator=lambda u, s, e: (_ for _ in ()).throw(AssertionError("validator called on synthetic replay")),
                )
                self.assertEqual(replayed, rec)

        syn_gate_store = SignedStore(self.root / "syn_gate", trust_config={"primary_fingerprint": "syn-primary"})
        for rejected_verdict in (
            {"verified_issuer": "syn", "primary_fingerprint": "syn-primary"},
            {"verified_issuer": "syn"},
        ):
            with self.assertRaises(ContractError) as syn_ctx:
                syn_gate_store.retain(
                    "dists/stable/Release.gpg",
                    self.signed,
                    self.unsigned,
                    "syn",
                    {},
                    validator=lambda u, s, e, v=rejected_verdict: v,
                )
            self.assertEqual(syn_ctx.exception.code, "VERIFICATION_FAILED")


if __name__ == "__main__":
    unittest.main()
