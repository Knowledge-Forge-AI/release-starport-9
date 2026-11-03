"""Unit tests for RS9 DNF production public-certificate parameterization.

These are pure Python/stdlib source and state verification tests using inert
command seams. They do not execute native DNF, Docker, or GnuPG processes and
do not claim native Fedora signature qualification.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import rs9

_CANDIDATE_DIR = Path(__file__).resolve().parent

from rs9 import apt_diagnostics as ad, dnf_diagnostics as dd, dnf_mutation as dm, hosted_deb as hd
from rs9.build_native import CommandReceipt
from rs9.errors import ContractError
from rs9.release_core import digest
from rs9.scratch import canonical

PRODUCT = "theme-forge-stellar-burst"
FIXTURE_FINGERPRINT = "A" * 40
ORIGINAL_SHA = "a" * 64
TAMPERED_SHA = "b" * 64


def _load_committed_public_cert() -> bytes:
    candidates = (
        _CANDIDATE_DIR / "fixtures/own-repository-admission/p-source/keys" / dd.PRODUCTION_KEY_FILENAME,
        _CANDIDATE_DIR / dd.PRODUCTION_KEY_FILENAME,
    )
    for path in candidates:
        if path.is_file() and not path.is_symlink():
            data = path.read_bytes()
            if digest(data) == dd.PRODUCTION_KEY_SHA256:
                return data
    raise AssertionError("Committed production public certificate fixture not found")


def _extract_openpgp_v4_primary_fingerprint(armored: bytes) -> str:
    lines = armored.strip().splitlines()
    assert lines[0] == b"-----BEGIN PGP PUBLIC KEY BLOCK-----"
    assert lines[-1] == b"-----END PGP PUBLIC KEY BLOCK-----"
    assert lines[1] == b""
    assert lines[-2].startswith(b"=")
    raw = base64.b64decode(b"".join(lines[2:-2]), validate=True)
    crc = base64.b64decode(lines[-2][1:], validate=True)
    assert crc == dm._crc24(raw)
    # Old-format tag 6 (public key) with 2-octet length: header is 0x99 + 2-byte big-endian length.
    assert raw[0] == 0x99
    pkt_len = int.from_bytes(raw[1:3], "big")
    pkt_body = raw[3 : 3 + pkt_len]
    assert len(pkt_body) == pkt_len and pkt_body[0] == 4
    return hashlib.sha1(b"\x99" + raw[1:3] + pkt_body).hexdigest().upper()


def _receipt(code=0, out=b"", err=b"", executed=True, stage=None):
    stage = stage or ("install" if b"checksum" in err or b"No match" in err else "refresh")
    return CommandReceipt(dd.stage_command(stage, PRODUCT), code, out, err, executed=executed)


def _absent(product=PRODUCT):
    return _receipt(1, f"package {product} is not installed\n".encode())


def _checksum_message(actual=TAMPERED_SHA, expected=ORIGINAL_SHA, product=PRODUCT, arch="x86_64", extra_line=""):
    return (
        f"[1/1] {product}-0:0.6.1\n"
        f"{extra_line}"
        f">>> Downloading successful, but checksum doesn't match. Calculated: {actual}(sha256)  Expected: {expected}(sha256) \n"
        f"Librepo error: Cannot download Packages/{product}-0.6.1-1.fc43.{arch}.rpm: All mirrors were tried\n"
    ).encode()


def _repo_message(reason="Bad PGP signature", *, arch="x86_64", key_uri=None, fingerprint=None):
    baseurl = f"file:///srv/rs9/rpm/fedora/43/{arch}"
    bootstrap = ""
    if key_uri is not None and fingerprint is not None:
        key_id = fingerprint[-16:]
        bootstrap = (
            ">>> repomd.xml GPG signature verification error: Signing key not found\n"
            f"Importing OpenPGP key 0x{key_id}:\n"
            ' UserID     : "Theme Forge Distribution Authority <packages@knowledgeforge.ai>"\n'
            f" Fingerprint: {fingerprint}\n"
            f" From       : {key_uri}\n"
            "The key was successfully imported.\n"
        )
    return (
        f"{bootstrap}"
        f">>> repomd.xml GPG signature verification error: {reason}\n"
        f'Failed to download metadata (baseurl: "{baseurl}") for repository "{dd.DNF_REPO_ID}": '
        f"repomd.xml GPG signature verification error: {reason}\n"
    ).encode()


class _ProbeClient:
    image = "sha256:" + "c" * 64
    platform = "linux/amd64"

    def __init__(self, spec, *, gpgkey_override=None, key_sha_override=None):
        self.spec = spec
        self.calls = []
        self.responses = {}
        gpgkey = gpgkey_override if gpgkey_override is not None else spec.get("key_uri", dd.KEY_URI)
        reported_sha = key_sha_override if key_sha_override is not None else spec["expected_key_sha256"]
        for stage, _command in spec.get("dnf_probe_commands", []):
            if stage.startswith("cache-"):
                data = json.dumps({"key_sha256": reported_sha, "candidate_cache_entries": 0}).encode()
            elif stage == "presentation":
                data = json.dumps(dd.DNF_PRESENTATION).encode() + b"\n"
            elif stage == "dnf-version":
                data = b"dnf5 version 5.2.18.0\nlibdnf5 version 5.2.18.0\n"
            elif stage == "rpm-version":
                data = b"RPM version 6.0.2\n"
            elif stage == "main-config":
                data = b"======== Main configuration: ========\nsystem_cachedir = /var/cache/libdnf5\ncacheonly = none\n"
            else:
                data = (
                    f'======== "{dd.DNF_REPO_ID}" repository configuration: ========\n'
                    f"enabled = 1\nbaseurl = {spec['source_uri']}\n"
                    f"gpgkey = {gpgkey}\npkg_gpgcheck = 1\nrepo_gpgcheck = 1\n"
                    "skip_if_unavailable = 0\nmetalink = \nmirrorlist = \n"
                ).encode()
            self.responses[stage] = _receipt(out=data)

    def exec(self, argv, **kwargs):
        self.calls.append(list(argv))
        stages = [stage for stage, command in self.spec.get("dnf_probe_commands", []) if command == argv]
        stage = (
            stages[-1]
            if stages and stages[0] == "cache-before" and len(self.calls) > 1
            else (stages[0] if stages else "unknown")
        )
        return self.responses.get(stage, _receipt())

    def dnf_image_identity_receipt(self):
        return _receipt(out=(self.image + "\n").encode())


class ProductionDnfTrustTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.prod_cert_bytes = _load_committed_public_cert()
        assert b"BEGIN PGP PUBLIC KEY BLOCK" in cls.prod_cert_bytes
        assert b"PRIVATE KEY" not in cls.prod_cert_bytes

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.keys_dir = self.root / "keys"
        self.keys_dir.mkdir()
        (self.keys_dir / dd.FIXTURE_KEY_FILENAME).write_bytes(b"public-key-fixture")
        (self.keys_dir / dd.PRODUCTION_KEY_FILENAME).write_bytes(self.prod_cert_bytes)

    def test_default_fixture_spec_command_and_identity_unchanged(self):
        default_spec = hd.dnf_spec(self.root / "rpm", self.keys_dir, "x86_64", public_fingerprint=FIXTURE_FINGERPRINT)
        explicit_fixture_spec = hd.dnf_spec(
            self.root / "rpm",
            self.keys_dir,
            "x86_64",
            public_fingerprint=FIXTURE_FINGERPRINT,
            public_key_filename=dd.FIXTURE_KEY_FILENAME,
        )
        self.assertNotIn("key_uri", default_spec)
        self.assertNotIn("key_uri", explicit_fixture_spec)
        self.assertEqual(set(default_spec), {
            "family", "arch", "public_fingerprint", "expected_key_sha256", "source_uri",
            "dnf_probe_commands", "mounts", "configure", "refresh", "install", "remove", "query",
        })
        for key in ("family", "arch", "public_fingerprint", "expected_key_sha256", "source_uri",
                    "dnf_probe_commands", "mounts", "configure", "refresh"):
            self.assertEqual(default_spec[key], explicit_fixture_spec[key])
        self.assertEqual(default_spec["expected_key_sha256"], digest(b"public-key-fixture"))
        self.assertIn(f"gpgkey={dd.KEY_URI}", default_spec["configure"][0][2])
        self.assertEqual(default_spec["dnf_probe_commands"], dd.probe_commands(dd.stage_command("refresh")[:-2]))
        for stage in ("cache-before", "cache-after"):
            argv = dict(default_spec["dnf_probe_commands"])[stage]
            self.assertEqual(argv[4], "/srv/rs9/keys/rs9-candidate-fixture-NONPRODUCTION.asc")

        # Missing fixture key file remains tolerated with expected_key_sha256=None at spec construction time.
        missing_spec = hd.dnf_spec(self.root / "rpm", self.root / "nonexistent-keys", "aarch64")
        self.assertIsNone(missing_spec["expected_key_sha256"])
        self.assertNotIn("key_uri", missing_spec)

        probe = dd.probe_dnf_client(_ProbeClient(default_spec), default_spec)
        self.assertEqual(probe["status"], "pass")
        self.assertTrue(dd.valid_identity(probe))
        self.assertEqual(probe["identity"]["key_uri"], dd.KEY_URI)

    def test_production_public_certificate_accepted_only_with_exact_tuple_and_unaliased_regular_file(self):
        self.assertEqual(digest(self.prod_cert_bytes), dd.PRODUCTION_KEY_SHA256)
        self.assertEqual(
            _extract_openpgp_v4_primary_fingerprint(self.prod_cert_bytes),
            dd.PRODUCTION_PUBLIC_FINGERPRINT,
        )
        for arch, platform in (("x86_64", "linux/amd64"), ("aarch64", "linux/arm64")):
            spec = hd.dnf_spec(
                self.root / "rpm",
                self.keys_dir,
                arch,
                public_fingerprint=dd.PRODUCTION_PUBLIC_FINGERPRINT,
                public_key_filename=dd.PRODUCTION_KEY_FILENAME,
            )
            self.assertEqual(spec["key_uri"], dd.PRODUCTION_KEY_URI)
            self.assertEqual(spec["expected_key_sha256"], dd.PRODUCTION_KEY_SHA256)
            self.assertEqual(spec["public_fingerprint"], dd.PRODUCTION_PUBLIC_FINGERPRINT)
            cfg_cmd = spec["configure"][0][2]
            self.assertIn(f"gpgkey={dd.PRODUCTION_KEY_URI}", cfg_cmd)
            self.assertNotIn(dd.FIXTURE_KEY_FILENAME, cfg_cmd)
            self.assertIn("gpgcheck=1", cfg_cmd)
            self.assertIn("repo_gpgcheck=1", cfg_cmd)
            self.assertIn("skip_if_unavailable=False", cfg_cmd)
            for stage in ("cache-before", "cache-after"):
                argv = dict(spec["dnf_probe_commands"])[stage]
                self.assertEqual(argv[4], "/srv/rs9/keys/knowledge-forge-ai-packages.asc")

            client = _ProbeClient(spec)
            client.platform = platform
            probe = dd.probe_dnf_client(client, spec)
            self.assertEqual(probe["status"], "pass")
            self.assertTrue(dd.valid_identity(probe))
            self.assertEqual(probe["identity"]["key_uri"], dd.PRODUCTION_KEY_URI)
            self.assertEqual(probe["identity"]["key_sha256"], dd.PRODUCTION_KEY_SHA256)
            self.assertEqual(probe["identity"]["public_fingerprint"], dd.PRODUCTION_PUBLIC_FINGERPRINT)

    def test_production_spec_rejects_bad_filenames_bytes_fingerprints_symlinks_and_aliases(self):
        for bad_name in (
            None,
            "",
            "other.asc",
            "keys/knowledge-forge-ai-packages.asc",
            "../knowledge-forge-ai-packages.asc",
            "/srv/rs9/keys/knowledge-forge-ai-packages.asc",
            dd.PRODUCTION_KEY_URI,
            Path(dd.PRODUCTION_KEY_FILENAME),
        ):
            with self.subTest(bad_name=bad_name), self.assertRaises(ContractError):
                hd.dnf_spec(
                    self.root / "rpm",
                    self.keys_dir,
                    "x86_64",
                    public_fingerprint=dd.PRODUCTION_PUBLIC_FINGERPRINT,
                    public_key_filename=bad_name,  # type: ignore[arg-type]
                )

        for bad_fp in (
            None,
            "",
            FIXTURE_FINGERPRINT,
            dd.PRODUCTION_PUBLIC_FINGERPRINT.lower(),
            "0x" + dd.PRODUCTION_PUBLIC_FINGERPRINT,
            dd.PRODUCTION_PUBLIC_FINGERPRINT[:-1] + "0",
            123,
        ):
            with self.subTest(bad_fp=bad_fp), self.assertRaises(ContractError):
                hd.dnf_spec(
                    self.root / "rpm",
                    self.keys_dir,
                    "x86_64",
                    public_fingerprint=bad_fp,
                    public_key_filename=dd.PRODUCTION_KEY_FILENAME,
                )

        # Missing production cert file rejected.
        empty_keys = self.root / "empty-keys"
        empty_keys.mkdir()
        with self.assertRaises(ContractError):
            hd.dnf_spec(
                self.root / "rpm",
                empty_keys,
                "x86_64",
                public_fingerprint=dd.PRODUCTION_PUBLIC_FINGERPRINT,
                public_key_filename=dd.PRODUCTION_KEY_FILENAME,
            )

        # Modified/wrong bytes rejected even with valid production fingerprint.
        wrong_bytes_keys = self.root / "wrong-bytes-keys"
        wrong_bytes_keys.mkdir()
        (wrong_bytes_keys / dd.PRODUCTION_KEY_FILENAME).write_bytes(self.prod_cert_bytes + b"\n")
        with self.assertRaises(ContractError):
            hd.dnf_spec(
                self.root / "rpm",
                wrong_bytes_keys,
                "x86_64",
                public_fingerprint=dd.PRODUCTION_PUBLIC_FINGERPRINT,
                public_key_filename=dd.PRODUCTION_KEY_FILENAME,
            )

        # Symlinked cert file rejected.
        symlink_keys = self.root / "symlink-keys"
        symlink_keys.mkdir()
        (symlink_keys / dd.PRODUCTION_KEY_FILENAME).symlink_to(self.keys_dir / dd.PRODUCTION_KEY_FILENAME)
        with self.assertRaises(ContractError):
            hd.dnf_spec(
                self.root / "rpm",
                symlink_keys,
                "x86_64",
                public_fingerprint=dd.PRODUCTION_PUBLIC_FINGERPRINT,
                public_key_filename=dd.PRODUCTION_KEY_FILENAME,
            )

        # Symlinked keys_dir rejected.
        symlink_dir = self.root / "keys-link"
        symlink_dir.symlink_to(self.keys_dir)
        with self.assertRaises(ContractError):
            hd.dnf_spec(
                self.root / "rpm",
                symlink_dir,
                "x86_64",
                public_fingerprint=dd.PRODUCTION_PUBLIC_FINGERPRINT,
                public_key_filename=dd.PRODUCTION_KEY_FILENAME,
            )

        # Hardlinked / aliased file (st_nlink > 1) rejected.
        hardlink_keys = self.root / "hardlink-keys"
        hardlink_keys.mkdir()
        os.link(self.keys_dir / dd.PRODUCTION_KEY_FILENAME, hardlink_keys / dd.PRODUCTION_KEY_FILENAME)
        try:
            with self.assertRaises(ContractError):
                hd.dnf_spec(
                    self.root / "rpm",
                    hardlink_keys,
                    "x86_64",
                    public_fingerprint=dd.PRODUCTION_PUBLIC_FINGERPRINT,
                    public_key_filename=dd.PRODUCTION_KEY_FILENAME,
                )
        finally:
            (hardlink_keys / dd.PRODUCTION_KEY_FILENAME).unlink()

        # Directory at cert path rejected.
        dir_keys = self.root / "dir-keys"
        (dir_keys / dd.PRODUCTION_KEY_FILENAME).mkdir(parents=True)
        with self.assertRaises(ContractError):
            hd.dnf_spec(
                self.root / "rpm",
                dir_keys,
                "x86_64",
                public_fingerprint=dd.PRODUCTION_PUBLIC_FINGERPRINT,
                public_key_filename=dd.PRODUCTION_KEY_FILENAME,
            )

        # Changed-during-read stat mismatch rejected.
        real_fstat = os.fstat
        fstat_calls = 0

        def mutated_second_fstat(fd):
            nonlocal fstat_calls
            fstat_calls += 1
            st = real_fstat(fd)
            if fstat_calls >= 2:
                return os.stat_result((
                    st.st_mode,
                    st.st_ino,
                    st.st_dev,
                    st.st_nlink,
                    st.st_uid,
                    st.st_gid,
                    st.st_size + 1,
                    st.st_atime,
                    st.st_mtime,
                    st.st_ctime,
                ))
            return st

        with patch("os.fstat", side_effect=mutated_second_fstat), self.assertRaises(ContractError) as cm:
            hd.dnf_spec(
                self.root / "rpm",
                self.keys_dir,
                "x86_64",
                public_fingerprint=dd.PRODUCTION_PUBLIC_FINGERPRINT,
                public_key_filename=dd.PRODUCTION_KEY_FILENAME,
            )
        self.assertIn("changed during read", str(cm.exception))

    def test_probe_commands_closed_uri_set_and_selected_cert_cache_probes(self):
        from rs9.dnf_commands import command_base
        base = command_base()
        fixture_cmds = dict(dd.probe_commands(base))
        prod_cmds = dict(dd.probe_commands(base, dd.PRODUCTION_KEY_URI))
        prod_kw_cmds = dict(dd.probe_commands(base, key_uri=dd.PRODUCTION_KEY_URI))
        self.assertEqual(prod_cmds, prod_kw_cmds)
        self.assertEqual(fixture_cmds["cache-before"][4], "/srv/rs9/keys/rs9-candidate-fixture-NONPRODUCTION.asc")
        self.assertEqual(fixture_cmds["cache-after"][4], "/srv/rs9/keys/rs9-candidate-fixture-NONPRODUCTION.asc")
        self.assertEqual(prod_cmds["cache-before"][4], "/srv/rs9/keys/knowledge-forge-ai-packages.asc")
        self.assertEqual(prod_cmds["cache-after"][4], "/srv/rs9/keys/knowledge-forge-ai-packages.asc")

        for bad_uri in (
            None,
            "",
            dd.PRODUCTION_KEY_FILENAME,
            "/srv/rs9/keys/knowledge-forge-ai-packages.asc",
            "file:///srv/rs9/keys/other.asc",
            "file:///srv/rs9/keys/sub/knowledge-forge-ai-packages.asc",
            "file:///srv/rs9/keys/../keys/knowledge-forge-ai-packages.asc",
            "https://rs9.knowledge-forge.ai/keys/knowledge-forge-ai-packages.asc",
            123,
        ):
            with self.subTest(bad_uri=bad_uri), self.assertRaises(ContractError):
                dd.probe_commands(base, bad_uri)  # type: ignore[arg-type]

    def test_probe_dnf_client_and_valid_identity_production_tuple_and_rehash(self):
        prod_spec = hd.dnf_spec(
            self.root / "rpm",
            self.keys_dir,
            "x86_64",
            public_fingerprint=dd.PRODUCTION_PUBLIC_FINGERPRINT,
            public_key_filename=dd.PRODUCTION_KEY_FILENAME,
        )
        prod_probe = dd.probe_dnf_client(_ProbeClient(prod_spec), prod_spec)
        self.assertEqual(prod_probe["status"], "pass")
        self.assertTrue(dd.valid_identity(prod_probe))

        # Config gpgkey readback mismatch fails closed.
        self.assertEqual(
            dd.probe_dnf_client(_ProbeClient(prod_spec, gpgkey_override=dd.KEY_URI), prod_spec)["status"],
            "fail",
        )
        fixture_spec = hd.dnf_spec(self.root / "rpm", self.keys_dir, "x86_64", public_fingerprint=FIXTURE_FINGERPRINT)
        self.assertEqual(
            dd.probe_dnf_client(_ProbeClient(fixture_spec, gpgkey_override=dd.PRODUCTION_KEY_URI), fixture_spec)["status"],
            "fail",
        )

        # Cache probe command mismatch with selected key_uri fails closed on both production and default paths.
        mismatched_cache_spec = dict(prod_spec, dnf_probe_commands=fixture_spec["dnf_probe_commands"])
        self.assertEqual(dd.probe_dnf_client(_ProbeClient(mismatched_cache_spec), mismatched_cache_spec)["status"], "fail")
        mismatched_default_cache_spec = dict(fixture_spec, dnf_probe_commands=prod_spec["dnf_probe_commands"])
        self.assertEqual(
            dd.probe_dnf_client(_ProbeClient(mismatched_default_cache_spec), mismatched_default_cache_spec)["status"],
            "fail",
        )

        # Claimed hash / fingerprint mismatch on production URI fails in probe_dnf_client even if guest reports same hash.
        bad_sha_spec = dict(prod_spec, expected_key_sha256="d" * 64)
        self.assertEqual(
            dd.probe_dnf_client(_ProbeClient(bad_sha_spec, key_sha_override="d" * 64), bad_sha_spec)["status"],
            "fail",
        )
        bad_fp_spec = dict(prod_spec, public_fingerprint=FIXTURE_FINGERPRINT)
        self.assertEqual(dd.probe_dnf_client(_ProbeClient(bad_fp_spec), bad_fp_spec)["status"], "fail")

        # Explicit None or unknown key_uri in spec fails without falling back to default fixture URI.
        for bad_uri in (None, "", "file:///srv/rs9/keys/other.asc"):
            bad_uri_spec = dict(fixture_spec, key_uri=bad_uri)
            self.assertEqual(dd.probe_dnf_client(_ProbeClient(bad_uri_spec), bad_uri_spec)["status"], "fail")

        # valid_identity / _identity_matches tuple & rehash enforcement.
        fixture_probe = dd.probe_dnf_client(_ProbeClient(fixture_spec), fixture_spec)
        self.assertTrue(dd.valid_identity(fixture_probe))

        # 1. Production URI with fixture SHA+fingerprint (rehashed) -> False
        p1 = copy.deepcopy(fixture_probe)
        p1["identity"]["key_uri"] = dd.PRODUCTION_KEY_URI
        p1["identity_sha256"] = digest(canonical(p1["identity"]))
        self.assertFalse(dd.valid_identity(p1))

        # 2. Production URI + production SHA + wrong fingerprint (rehashed) -> False
        p2 = copy.deepcopy(prod_probe)
        p2["identity"]["public_fingerprint"] = FIXTURE_FINGERPRINT
        p2["identity_sha256"] = digest(canonical(p2["identity"]))
        self.assertFalse(dd.valid_identity(p2))

        # 3. Production URI + wrong SHA + production fingerprint (rehashed) -> False
        p3 = copy.deepcopy(prod_probe)
        p3["identity"]["key_sha256"] = "e" * 64
        p3["identity_sha256"] = digest(canonical(p3["identity"]))
        self.assertFalse(dd.valid_identity(p3))

        # 4. Exact production tuple without rehash -> False
        p4 = copy.deepcopy(fixture_probe)
        p4["identity"]["key_uri"] = dd.PRODUCTION_KEY_URI
        p4["identity"]["key_sha256"] = dd.PRODUCTION_KEY_SHA256
        p4["identity"]["public_fingerprint"] = dd.PRODUCTION_PUBLIC_FINGERPRINT
        self.assertFalse(dd.valid_identity(p4))

        # 5. Exact production tuple WITH rehash -> True
        p4["identity_sha256"] = digest(canonical(p4["identity"]))
        self.assertTrue(dd.valid_identity(p4))

        # 6. Unknown URI with production SHA+fingerprint (rehashed) -> False
        p5 = copy.deepcopy(prod_probe)
        p5["identity"]["key_uri"] = "file:///srv/rs9/keys/unknown.asc"
        p5["identity_sha256"] = digest(canonical(p5["identity"]))
        self.assertFalse(dd.valid_identity(p5))

    def test_qualify_dnf_and_tamper_cycle_with_production_identity_and_uri_isolation(self):
        prod_spec = hd.dnf_spec(
            self.root / "rpm",
            self.keys_dir,
            "x86_64",
            public_fingerprint=dd.PRODUCTION_PUBLIC_FINGERPRINT,
            public_key_filename=dd.PRODUCTION_KEY_FILENAME,
        )
        prod_probe = dd.probe_dnf_client(_ProbeClient(prod_spec), prod_spec)
        fixture_spec = hd.dnf_spec(self.root / "rpm", self.keys_dir, "x86_64", public_fingerprint=FIXTURE_FINGERPRINT)
        fixture_probe = dd.probe_dnf_client(_ProbeClient(fixture_spec), fixture_spec)

        def make_context(probe, kind):
            fp = probe["identity"]["public_fingerprint"]
            mutation = {
                "kind": kind,
                "verified": True,
                "control_sha256": ORIGINAL_SHA,
                "tampered_sha256": TAMPERED_SHA,
                "target": (
                    f"fedora/43/x86_64/Packages/{PRODUCT}-0.6.1-1.fc43.x86_64.rpm"
                    if kind == "package"
                    else "fedora/43/x86_64/repodata/repomd.xml" + ("" if kind == "index" else ".asc")
                ),
            }
            if kind == "index":
                mutation["authentication_boundary"] = "repomd-signature"
            elif kind == "signature":
                mutation.update(armor_framing_preserved=True, packet_changed_offset=63, packet_length=64)
            elif kind == "wrongkey":
                mutation.update(
                    control_key_fingerprint=fp,
                    replacement_issuer="B" * 40,
                    replacement_signature_verified=True,
                )
            return {
                "product": PRODUCT,
                "arch": "x86_64",
                "probe": probe,
                "positive_control_valid": True,
                "positive_identity_sha256": probe["identity_sha256"],
                "mutation": mutation,
            }

        # Package tamper source URI check uses verified identity key_uri and rejects the other role's URI or foreign URI.
        prod_pkg_ctx = make_context(prod_probe, "package")
        ok_prod, cat_prod, reason_prod, _ = dd.qualify_dnf(
            "package",
            _receipt(0),
            _receipt(1, err=_checksum_message(extra_line=f"Key: {dd.PRODUCTION_KEY_URI}\n"), stage="install"),
            _absent(),
            configure=_receipt(0),
            context=prod_pkg_ctx,
        )
        self.assertTrue(ok_prod, reason_prod)
        self.assertEqual(cat_prod, "PACKAGE_HASH_MISMATCH")

        for bad_uri in (dd.KEY_URI, "file:///srv/rs9/keys/foreign.asc"):
            ok, _cat, reason, _ = dd.qualify_dnf(
                "package",
                _receipt(0),
                _receipt(1, err=_checksum_message(extra_line=f"Key: {bad_uri}\n"), stage="install"),
                _absent(),
                configure=_receipt(0),
                context=prod_pkg_ctx,
            )
            self.assertFalse(ok)
            self.assertEqual(reason, "dnf-package-source-unproven")

        fixture_pkg_ctx = make_context(fixture_probe, "package")
        ok_cross, _cat, reason_cross, _ = dd.qualify_dnf(
            "package",
            _receipt(0),
            _receipt(1, err=_checksum_message(extra_line=f"Key: {dd.PRODUCTION_KEY_URI}\n"), stage="install"),
            _absent(),
            configure=_receipt(0),
            context=fixture_pkg_ctx,
        )
        self.assertFalse(ok_cross)
        self.assertEqual(reason_cross, "dnf-package-source-unproven")

        # Metadata tamper kinds (index, signature, wrongkey) with bootstrap key import block under production identity.
        for kind in ("index", "signature", "wrongkey"):
            reason_text = "Signing key not found" if kind == "wrongkey" else "Bad PGP signature"
            ctx = make_context(prod_probe, kind)
            good_err = _repo_message(
                reason_text,
                key_uri=dd.PRODUCTION_KEY_URI,
                fingerprint=dd.PRODUCTION_PUBLIC_FINGERPRINT,
            )
            ok, cat, reason, diag = dd.qualify_dnf(
                kind,
                _receipt(1, err=good_err),
                _receipt(1, err=good_err, stage="install"),
                _absent(),
                configure=_receipt(0),
                context=ctx,
            )
            self.assertTrue(ok, (kind, reason))
            self.assertEqual(
                cat,
                {"index": "INDEX_CORRUPT", "signature": "SIGNATURE_REJECTED", "wrongkey": "KEY_MISMATCH"}[kind],
            )
            self.assertEqual(diag["bootstrap_categories"], ["KEY_MISMATCH"])

            # Foreign or fixture key URI in bootstrap under production identity is rejected.
            wrong_uri_err = _repo_message(
                reason_text,
                key_uri=dd.KEY_URI,
                fingerprint=dd.PRODUCTION_PUBLIC_FINGERPRINT,
            )
            ok_wrong, _, _, _ = dd.qualify_dnf(
                kind,
                _receipt(1, err=wrong_uri_err),
                _receipt(1, err=wrong_uri_err, stage="install"),
                _absent(),
                configure=_receipt(0),
                context=ctx,
            )
            self.assertFalse(ok_wrong)

    def test_production_tamper_cycle_and_positive_control_binding(self):
        import base64

        def synthetic_armor(seed=b"controlled synthetic signature"):
            body = b"\x04\x00\x01\x08\x00\x00" + seed
            packet = bytes([0xC2, len(body)]) + body
            encoded = base64.b64encode(packet)
            return (
                b"-----BEGIN PGP SIGNATURE-----\n\n"
                + encoded
                + b"\n="
                + base64.b64encode(dm._crc24(packet))
                + b"\n-----END PGP SIGNATURE-----\n"
            )

        class WrongSigner:
            primary_fingerprint = "B" * 40

            def detach_sign(self, data, **kwargs):
                return synthetic_armor(b"wrong synthetic signature")

            def verify(self, data, signature):
                if data != b"<repomd/>\n" or signature != self.detach_sign(data):
                    raise ContractError("INVALID_TAMPER_MUTATION", "Synthetic signature does not match")
                return {"status": "valid", "verified_issuer": self.primary_fingerprint}

        source = self.root / "rpm"
        base = source / "fedora/43/x86_64"
        (base / "Packages").mkdir(parents=True)
        (base / "Packages" / f"{PRODUCT}-0.6.1-1.fc43.x86_64.rpm").write_bytes(b"synthetic RPM payload")
        (base / "repodata").mkdir()
        (base / "repodata/repomd.xml").write_bytes(b"<repomd/>\n")
        (base / "repodata/repomd.xml.asc").write_bytes(synthetic_armor())

        spec_for = lambda dirs: hd.dnf_spec(
            dirs["rpm"],
            self.keys_dir,
            "x86_64",
            public_fingerprint=dd.PRODUCTION_PUBLIC_FINGERPRINT,
            public_key_filename=dd.PRODUCTION_KEY_FILENAME,
        )
        spec = spec_for({"rpm": source})
        probe = dd.probe_dnf_client(_ProbeClient(spec), spec)
        control = ad.build_positive_control(
            family="dnf",
            image=_ProbeClient.image,
            platform=_ProbeClient.platform,
            product=PRODUCT,
            setup_sha256=ad.trust_identity(spec),
            success=True,
            dnf_probe=probe,
            receipts={stage: _receipt(stage=stage) for stage in ("configure", "refresh", "install", "query")},
        )
        self.assertTrue(control["success"])
        valid_ctrl, reason_ctrl = ad.validate_positive_control(
            control,
            family="dnf",
            image=_ProbeClient.image,
            platform=_ProbeClient.platform,
            product=PRODUCT,
            setup_sha256=ad.trust_identity(spec),
            dnf_probe=probe,
        )
        self.assertTrue(valid_ctrl, reason_ctrl)

        # Positive control built for fixture spec does not validate against production spec/probe.
        fixture_spec = hd.dnf_spec(source, self.keys_dir, "x86_64", public_fingerprint=FIXTURE_FINGERPRINT)
        fixture_probe = dd.probe_dnf_client(_ProbeClient(fixture_spec), fixture_spec)
        self.assertFalse(
            ad.validate_positive_control(
                control,
                family="dnf",
                image=_ProbeClient.image,
                platform=_ProbeClient.platform,
                product=PRODUCT,
                setup_sha256=ad.trust_identity(spec),
                dnf_probe=fixture_probe,
            )[0]
        )

        keys_dir = self.keys_dir

        class Client(_ProbeClient):
            def __init__(self, host, image, platform, mounts, family):
                self.host = host
                self.kind = Path(mounts[0][0]).parent.name.removeprefix("tamper-dnf-")
                self.source = Path(mounts[0][0])
                super().__init__(spec_for({"rpm": self.source}))

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return None

            def exec(self, argv, **kwargs):
                reason_text = "Signing key not found" if self.kind == "wrongkey" else "Bad PGP signature"
                err_msg = _repo_message(
                    reason_text,
                    key_uri=dd.PRODUCTION_KEY_URI,
                    fingerprint=dd.PRODUCTION_PUBLIC_FINGERPRINT,
                )
                if argv == self.spec["refresh"]:
                    r = _receipt(0) if self.kind == "package" else _receipt(1, err=err_msg)
                elif argv == self.spec["install"](PRODUCT):
                    m = dm.verify_dnf_mutation(
                        source,
                        self.source,
                        arch="x86_64",
                        product=PRODUCT,
                        kind=self.kind,
                        wrong_signer=WrongSigner(),
                        public_fingerprint=dd.PRODUCTION_PUBLIC_FINGERPRINT,
                    )
                    r = _receipt(
                        1,
                        err=(
                            _checksum_message(
                                m["tampered_sha256"],
                                m["control_sha256"],
                                extra_line=f"Key: {dd.PRODUCTION_KEY_URI}\n",
                            )
                            if self.kind == "package"
                            else err_msg
                        ),
                        stage="install",
                    )
                elif argv == self.spec["query"](PRODUCT):
                    r = _absent()
                elif argv in self.spec["configure"]:
                    r = _receipt(0)
                else:
                    r = super().exec(argv, **kwargs)
                self.host.receipts.append(r)
                return r

        host = hd.RecordingRunner(None)
        with patch.object(hd, "ClientContainer", Client):
            rows = hd.tamper_cycle(
                host,
                spec_for,
                "dnf",
                {"rpm": source},
                image=_ProbeClient.image,
                platform=_ProbeClient.platform,
                product=PRODUCT,
                work=self.root,
                arch="x86_64",
                wrong_signer=WrongSigner(),
                kinds=hd.TAMPER_KINDS_ALL,
                prefix="prod-synthetic",
                positive_control=control,
            )
        self.assertEqual([r["status"] for r in rows], ["pass"] * 4)
        for row in rows:
            self.assertEqual(row["dnf_client"]["identity"]["key_uri"], dd.PRODUCTION_KEY_URI)
            self.assertEqual(row["dnf_client"]["identity"]["key_sha256"], dd.PRODUCTION_KEY_SHA256)
            self.assertEqual(row["dnf_client"]["identity"]["public_fingerprint"], dd.PRODUCTION_PUBLIC_FINGERPRINT)


if __name__ == "__main__":
    unittest.main()
