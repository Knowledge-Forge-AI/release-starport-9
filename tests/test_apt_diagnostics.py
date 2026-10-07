"""Tests for rs9.apt_diagnostics."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from rs9 import apt_diagnostics as ad
from rs9.build_native import CommandReceipt


class FakeReceipt(CommandReceipt):
    def __init__(self, code: int = 0, out: bytes = b"", err: bytes = b"", argv: list[str] | None = None):
        super().__init__(argv or ["cmd"], code, out, err, tool_name="fake")


class FakeClient:
    def __init__(self, probe_response: dict | None = None, exit_code: int = 0):
        self.probe_response = probe_response
        self.exit_code = exit_code
        self.calls: list[list[str]] = []

    def exec(self, argv: list[str], *, user: str | None = None) -> CommandReceipt:
        self.calls.append(list(argv))
        if self.probe_response is not None:
            out = json.dumps(self.probe_response).encode()
            return CommandReceipt(argv, self.exit_code, out, b"", tool_name="docker")
        return CommandReceipt(argv, self.exit_code, b"", b"", tool_name="docker")


class AptDiagnosticsTests(unittest.TestCase):
    def test_family_specific_tamper_wording_and_stages(self):
        # Representative diagnostic fixtures, not captured native qualification.
        rows = [
            ('apt', 'wrongkey', 'Missing key ABCDEF, which is needed to verify signature.', 'KEY_MISMATCH'),
            ('pacman', 'signature', 'signature from "Fixture" is invalid', 'SIGNATURE_REJECTED'),
            ('pacman', 'signature', 'invalid or corrupted database (PGP signature)', 'SIGNATURE_REJECTED'),
            ('pacman', 'wrongkey', 'signature from "Fixture" is unknown trust', 'KEY_MISMATCH'),
            ('dnf', 'signature', 'repomd.xml GPG signature verification error: Bad GPG signature', 'SIGNATURE_REJECTED'),
            ('dnf', 'wrongkey', 'Signing key not found', 'KEY_MISMATCH'),
            ('dnf', 'wrongkey', 'Public key is not installed', 'KEY_MISMATCH'),
            ('pacman', 'package', 'invalid or corrupted package (PGP signature)', 'SIGNATURE_REJECTED'),
            ('dnf', 'package', 'package.rpm: Bad GPG signature', 'SIGNATURE_REJECTED'),
        ]
        for family, kind, text, expected in rows:
            with self.subTest(family=family, kind=kind, text=text):
                failure = FakeReceipt(100, err=text.encode())
                refresh, install = (FakeReceipt(0), failure) if kind == 'package' else (failure, FakeReceipt(1))
                ok, category, reason, diag = ad.qualify_tamper_rejection(
                    kind, refresh, install, FakeReceipt(1), family=family)
                self.assertTrue(ok, reason)
                self.assertEqual(category, expected)
                self.assertEqual(diag['qualifying_stage'], 'install' if kind == 'package' else 'refresh')

    def test_family_wording_cannot_credit_other_causes_or_stages(self):
        for family in ('apt', 'pacman', 'dnf'):
            for text in (b'Permission denied', b'command not found', b'unrecognized refusal'):
                with self.subTest(family=family, text=text):
                    self.assertFalse(ad.qualify_tamper_rejection(
                        'signature', FakeReceipt(1, err=text), FakeReceipt(1), FakeReceipt(1), family=family)[0])
            self.assertFalse(ad.qualify_tamper_rejection(
                'wrongkey', FakeReceipt(1, err=b'Bad GPG signature'), FakeReceipt(1), FakeReceipt(1), family=family)[0])
        self.assertFalse(ad.qualify_tamper_rejection(
            'signature', FakeReceipt(1, err=b'Bad GPG signature'), None, FakeReceipt(1), family='apt')[0])
        self.assertFalse(ad.qualify_tamper_rejection(
            'package', FakeReceipt(1, err=b'invalid or corrupted database (PGP signature)'),
            FakeReceipt(1), FakeReceipt(1), family='pacman')[0])

    def test_classify_rejection_categories(self):
        self.assertEqual(ad.classify_rejection(FakeReceipt(0)), "COMMAND_SUCCESS")
        self.assertEqual(ad.classify_rejection(None), "UNCLASSIFIED_FAILURE")
        self.assertEqual(
            ad.classify_rejection(FakeReceipt(127, b"", b"sh: 1: apt-get: command not found")),
            "COMMAND_NOT_FOUND",
        )
        self.assertEqual(
            ad.classify_rejection(FakeReceipt(100, b"", b"E: Could not open lock file - Permission denied")),
            "PERMISSION_DENIED",
        )
        self.assertEqual(
            ad.classify_rejection(FakeReceipt(100, b"", b"W: GPG error: ... The following signatures couldn't be verified because the public key is not available: NO_PUBKEY 1234")),
            "KEY_MISMATCH",
        )
        self.assertEqual(
            ad.classify_rejection(FakeReceipt(100, b"", b"W: GPG error: ... BADSIG 5678 ... E: The repository is not signed")),
            "SIGNATURE_REJECTED",
        )
        self.assertEqual(
            ad.classify_rejection(FakeReceipt(100, b"", b"E: Failed to fetch http://.../sample.deb Hash Sum mismatch"), stage="install"),
            "PACKAGE_HASH_MISMATCH",
        )
        self.assertEqual(
            ad.classify_rejection(FakeReceipt(100, b"", b"E: Failed to fetch http://.../InRelease Hash Sum mismatch"), stage="refresh"),
            "INDEX_HASH_MISMATCH",
        )
        self.assertEqual(
            ad.classify_rejection(FakeReceipt(100, b"", b"E: Unable to locate package foo")),
            "PACKAGE_NOT_FOUND",
        )
        self.assertEqual(
            ad.classify_rejection(FakeReceipt(100, b"", b"Err:1 ... Could not connect to 127.0.0.1 - Network is unreachable")),
            "NETWORK_UNAVAILABLE",
        )
        self.assertEqual(
            ad.classify_rejection(FakeReceipt(100, b"", b"E: install rejected")),
            "UNCLASSIFIED_FAILURE",
        )

    def test_safe_sample_sanitizes_paths_and_caps_length(self):
        sample = ad.safe_sample("/srv/rs9/apt/dists/resolute/InRelease: error reading /etc/apt/trusted.gpg", max_chars=100)
        self.assertNotIn("/srv/rs9", sample)
        self.assertNotIn("/etc/apt", sample)
        self.assertIn("[PATH]", sample)
        self.assertLessEqual(len(sample), 100)

        # Non-printable bytes
        non_printable = ad.safe_sample(b"\x00\x01\x02\x03\x04")
        self.assertEqual(non_printable, "non-printable-stream-withheld")

    def test_record_command_diagnostics_structure(self):
        rcpt = FakeReceipt(100, b"Hit:1 repo\n", b"E: install rejected")
        diag = ad.record_command_diagnostics(
            stage="install",
            family="apt",
            product="theme-forge-stellar-loom",
            arch="amd64",
            receipt=rcpt,
            repo_identity="file:/srv/rs9/apt",
            public_fingerprint="A" * 40,
            verification={"signatures_ok": True},
        )
        self.assertEqual(diag["stage"], "install")
        self.assertEqual(diag["family"], "apt")
        self.assertEqual(diag["product"], "theme-forge-stellar-loom")
        self.assertEqual(diag["arch"], "amd64")
        self.assertEqual(diag["exit_code"], 100)
        self.assertEqual(diag["reason_category"], "UNCLASSIFIED_FAILURE")
        self.assertEqual(diag["repo_identity"], "file:/srv/rs9/apt")
        self.assertEqual(diag["public_fingerprint"], "A" * 40)
        self.assertEqual(diag["verification"], {"signatures_ok": True})
        self.assertIn("stdout_sha256", diag)
        self.assertIn("stderr_sha256", diag)

    def test_positive_control_lifecycle(self):
        ctrl = ad.build_positive_control(
            family="apt",
            image="ubuntu:26.04",
            platform="linux/amd64",
            product="theme-forge-stellar-loom",
            repository="/srv/rs9/apt",
            keyring="/usr/share/keyrings/key.gpg",
            setup_sha256="a"*64,
            receipts={stage:[FakeReceipt(0)] for stage in ("configure","refresh","install","query")},
            success=True,
        )
        self.assertTrue(ctrl["success"])

        # Matching validation passes
        ok, reason = ad.validate_positive_control(
            ctrl,
            family="apt",
            image="ubuntu:26.04",
            platform="linux/amd64",
            product="theme-forge-stellar-loom",
            dirs={"apt": Path("/srv/rs9/apt")},
            keyring="/usr/share/keyrings/key.gpg", setup_sha256="a"*64,
        )
        self.assertTrue(ok)
        self.assertIsNone(reason)

        # Mismatches fail validation
        self.assertFalse(ad.validate_positive_control(None, family="apt", image="img", platform="p", product="prod")[0])
        self.assertFalse(ad.validate_positive_control({"success": False}, family="apt", image="img", platform="p", product="prod")[0])
        self.assertFalse(ad.validate_positive_control(ctrl, family="dnf", image="ubuntu:26.04", platform="linux/amd64", product="theme-forge-stellar-loom")[0])
        self.assertFalse(ad.validate_positive_control(ctrl, family="apt", image="other:img", platform="linux/amd64", product="theme-forge-stellar-loom")[0])
        self.assertFalse(ad.validate_positive_control(ctrl, family="apt", image="ubuntu:26.04", platform="linux/amd64", product="other-product")[0])

    def test_qualify_tamper_rejection_boundary_and_wrong_reasons(self):
        # 1. Package tamper: refresh ok, install hash mismatch -> qualified
        ok, cat, reason, diag = ad.qualify_tamper_rejection(
            "package",
            refresh_rcpt=FakeReceipt(0),
            install_rcpt=FakeReceipt(100, b"", b"E: Failed to fetch .../pkg.deb Hash Sum mismatch"),
            query_rcpt=FakeReceipt(1),
        )
        self.assertTrue(ok)
        self.assertEqual(cat, "PACKAGE_HASH_MISMATCH")
        self.assertIsNone(reason)

        # Package tamper where refresh failed -> WRONG STAGE FAILURE
        ok, cat, reason, diag = ad.qualify_tamper_rejection(
            "package",
            refresh_rcpt=FakeReceipt(100, b"", b"W: GPG error: InRelease: BADSIG"),
            install_rcpt=FakeReceipt(100, b"", b"E: unable to install"),
            query_rcpt=FakeReceipt(1),
        )
        self.assertFalse(ok)
        self.assertIn("wrong-stage-failure", reason)

        # Package tamper where install failed due to command not found -> WRONG REASON
        ok, cat, reason, diag = ad.qualify_tamper_rejection(
            "package",
            refresh_rcpt=FakeReceipt(0),
            install_rcpt=FakeReceipt(127, b"", b"sh: 1: apt-get: command not found"),
            query_rcpt=FakeReceipt(1),
        )
        self.assertFalse(ok)
        self.assertIn("wrong-tamper-rejection-reason:COMMAND_NOT_FOUND", reason)

        # 2. Signature tamper: refresh failed with BADSIG -> qualified
        ok, cat, reason, diag = ad.qualify_tamper_rejection(
            "signature",
            refresh_rcpt=FakeReceipt(100, b"", b"W: GPG error: InRelease: BADSIG 1234\nE: The repository is not signed"),
            install_rcpt=FakeReceipt(100, b"", b"E: unable to locate package"),
            query_rcpt=FakeReceipt(1),
        )
        self.assertTrue(ok)
        self.assertEqual(cat, "SIGNATURE_REJECTED")

        # Signature tamper where refresh succeeded -> bypassed verification
        ok, cat, reason, diag = ad.qualify_tamper_rejection(
            "signature",
            refresh_rcpt=FakeReceipt(0),
            install_rcpt=FakeReceipt(100, b"", b"E: failed"),
            query_rcpt=FakeReceipt(1),
        )
        self.assertFalse(ok)
        self.assertEqual(reason, "bypassed-signature-verification-on-refresh")

        # 3. Wrong key tamper: refresh failed with NO_PUBKEY -> qualified
        ok, cat, reason, diag = ad.qualify_tamper_rejection(
            "wrongkey",
            refresh_rcpt=FakeReceipt(100, b"", b"W: GPG error: InRelease: NO_PUBKEY ABCD\nE: The repository is not signed"),
            install_rcpt=FakeReceipt(100, b"", b"E: unable to locate"),
            query_rcpt=FakeReceipt(1),
        )
        self.assertTrue(ok)
        self.assertEqual(cat, "KEY_MISMATCH")

        # 4. Tampered package accepted -> fail
        ok, cat, reason, diag = ad.qualify_tamper_rejection(
            "package",
            refresh_rcpt=FakeReceipt(0),
            install_rcpt=FakeReceipt(0),
            query_rcpt=FakeReceipt(0),
        )
        self.assertFalse(ok)
        self.assertEqual(reason, "tampered-content-accepted")

    def test_probe_runs_both_users_and_validates_hash_and_public_issuer(self):
        class Client:
            calls=[]
            def exec(self,argv,*,user=None):
                self.calls.append((argv,user))
                if argv[0]=='gpgv':
                    return FakeReceipt(0,('[GNUPG:] VALIDSIG '+'A'*40+' 0\n').encode())
                doc={'apt_user_present':True,'targets':[
                    {'target':target,'ancestors':[{'path':target,'type':'file','mode':0o644,'owner':'root',
                     'readable':True,'sha256':'1'*64}]} for target in argv[3:]],
                     'verifiers':{'apt-get':{'version':'apt 3.0.0'}}}
                return FakeReceipt(0,json.dumps(doc).encode())
        client=Client()
        probe=ad.probe_guest_trust(client,expected_key_sha256='1'*64,public_fingerprint='A'*40)
        self.assertEqual(probe['status'],'probed')
        self.assertEqual([u for a,u in client.calls[:2]],[None,'_apt'])
        self.assertTrue(probe['key_readback_matches'])
        self.assertEqual(probe['signature_verification']['status'],'pass')
        self.assertEqual(probe['users']['root']['verifiers']['apt-get']['version'],'apt 3.0.0')

    def test_empty_or_malformed_probe_never_invents_readability(self):
        for client in (FakeClient(None),FakeClient({'targets':[]}),
                       FakeClient({'targets':[None]*8})):
            probe=ad.probe_guest_trust(client)
            self.assertEqual(probe['status'],'incomplete')
            self.assertFalse(probe['key_readback_matches'])
            self.assertNotIn('targets',probe['users']['_apt'])

    def test_probe_version_fields_are_bounded_sanitized_and_type_checked(self):
        token = 'ghp_' + 'X' * 36
        class Client:
            def exec(self, argv, *, user=None):
                doc = {'targets': [{'target': target, 'ancestors': []} for target in argv[3:]],
                       'verifiers': {'apt-get': {'version': 'x'*100 + token,
                           'stdout_sha256': token, 'stderr_sha256': '/tmp/private-fixture',
                           'exit_code': token, 'status': token}}}
                return FakeReceipt(0, json.dumps(doc).encode())
        probe = ad.probe_guest_trust(Client())
        for user in ('root', '_apt'):
            self.assertEqual(probe['users'][user]['verifiers']['apt-get'],
                             {'version': 'credential-stream-withheld'})
        self.assertNotIn('ghp_', json.dumps(probe))

    def test_credential_and_private_path_samples_withheld_before_capping(self):
        token='ghp_'+'X'*36
        self.assertEqual(ad.safe_sample('x'*1000+token),'credential-stream-withheld')
        self.assertNotIn('secret.example',ad.safe_sample('https://alice:pass@secret.example/path'))
        self.assertNotIn('private-user',ad.safe_sample('/tmp/private-fixture/key.gpg token=fixture-secret'))

    def test_positive_control_requires_all_stages_and_exact_setup(self):
        ctrl=ad.build_positive_control(family='apt',image='img',platform='linux/amd64',product='p',
            setup_sha256='a'*64,success=True,receipts={'install':FakeReceipt(0)})
        self.assertFalse(ad.validate_positive_control(ctrl,family='apt',image='img',platform='linux/amd64',
            product='p',setup_sha256='a'*64)[0])
        self.assertNotIn('/tmp/private-fixture',json.dumps(ctrl))

    def test_unclassified_or_unsigned_wrong_key_is_never_a_pass(self):
        for text in (b'E: install rejected',b'E: command not found',b'E: repository is not signed'):
            ok,*rest=ad.qualify_tamper_rejection('wrongkey',FakeReceipt(100,err=text),FakeReceipt(100),FakeReceipt(1))
            self.assertFalse(ok)
        ok,*rest=ad.qualify_tamper_rejection('index',FakeReceipt(0),FakeReceipt(100,err=b'Hash Sum mismatch'),FakeReceipt(1))
        self.assertFalse(ok)
