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
        super().__init__(argv or ["cmd"], code, out, err, tool_name="fake", executed=True)


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
    def test_apt_readability_requires_complete_executed_guest_observations(self):
        import copy
        repo = '/srv/rs9/apt'
        targets = [repo, '/etc/apt/keyrings/rs9-nonproduction.gpg',
                   *[repo + '/dists/resolute/' + name for name in
                     ('InRelease', 'Release', 'Release.gpg',
                      'main/binary-amd64/Packages', 'main/binary-amd64/Packages.xz',
                      'main/binary-amd64/Packages.gz')]]
        rows = []
        for name in targets:
            path = Path(name)
            ancestors = [{'path': str(p), 'type': 'directory' if p != path or name == repo else 'file',
                          'readable': True, 'traversable': True}
                         for p in (path, *path.parents)]
            rows.append({'target': name, 'ancestors': ancestors})
        probe = {'status': 'probed', 'users': {'_apt': {'apt_user_present': True, 'targets': rows}}}
        self.assertEqual(ad.apt_readability(probe, executed=True), 'pass')
        self.assertEqual(ad.apt_readability(probe, executed=False), 'not-run')
        for mutation in ('missing-user', 'missing-target', 'empty-ancestors', 'missing-ancestor'):
            broken = copy.deepcopy(probe)
            user = broken['users']['_apt']
            if mutation == 'missing-user':
                user['apt_user_present'] = False
            elif mutation == 'missing-target':
                user['targets'].pop()
            elif mutation == 'empty-ancestors':
                user['targets'][0]['ancestors'] = []
            else:
                user['targets'][-1]['ancestors'].pop()
            self.assertEqual(ad.apt_readability(broken, executed=True), 'not-run', mutation)
        for mutation in ('unreadable-file', 'untraversable-parent', 'symlink'):
            broken = copy.deepcopy(probe)
            leaf = broken['users']['_apt']['targets'][-1]['ancestors'][0]
            if mutation == 'unreadable-file':
                leaf['readable'] = False
                leaf['error'] = 'permission-denied'
            elif mutation == 'symlink':
                leaf['type'] = 'symlink'
            else:
                broken['users']['_apt']['targets'][-1]['ancestors'][1]['traversable'] = False
            self.assertEqual(ad.apt_readability(broken, executed=True), 'fail', mutation)

    def test_exact_run8_pacman_wrongkey_and_signature_samples(self):
        # Manifest-selected run-8 stderr; a replay is source evidence only.
        fingerprint = "6F3F25BA5FD8853E81F8FF50D3C6424FD7907037"
        wrongkey = (f'error: rs9: key "{fingerprint}" is unknown\n'
                    f'error: key "{fingerprint}" could not be looked up remotely\n'
                    'error: failed to synchronize all databases (invalid or corrupted database (PGP signature))\n')
        import hashlib
        self.assertEqual(hashlib.sha256(wrongkey.encode()).hexdigest(),
                         "51733456b7771e5c221be5f6fcf2c687a7c6be7fe197691a0d849109e38c34a2")
        signature = ('error: rs9: signature from "RS9 NON-PRODUCTION CANDIDATE FIXTURE <nonproduction@invalid>" is invalid\n'
                     'error: failed to synchronize all databases (invalid or corrupted database (PGP signature))\n')
        for text in (wrongkey, wrongkey.lower()):
            receipt = CommandReceipt(['pacman', '-Sy'], 1, b'', text.encode(), executed=True)
            self.assertEqual(ad.classify_rejection(receipt, family='pacman'), 'KEY_MISMATCH')
            self.assertTrue(ad.qualify_tamper_rejection('wrongkey', receipt, FakeReceipt(1),
                                                       FakeReceipt(1), family='pacman')[0])
            self.assertFalse(ad.qualify_tamper_rejection('signature', receipt, FakeReceipt(1),
                                                        FakeReceipt(1), family='pacman')[0])
        receipt = CommandReceipt(['pacman', '-Sy'], 1, b'', signature.encode(), executed=True)
        self.assertEqual(ad.classify_rejection(receipt, family='pacman'), 'SIGNATURE_REJECTED')
        self.assertTrue(ad.qualify_tamper_rejection('signature', receipt, FakeReceipt(1),
                                                   FakeReceipt(1), family='pacman')[0])
        self.assertFalse(ad.qualify_tamper_rejection('wrongkey', receipt, FakeReceipt(1),
                                                    FakeReceipt(1), family='pacman')[0])

    def test_pacman_malformed_key_and_unrelated_causes_cannot_qualify_wrongkey(self):
        generic = 'invalid or corrupted database (PGP signature)'
        for text in ('error: rs9: key "not-hex" is unknown\n' + generic,
                     'error: rs9: key "1234" is unknown\n' + generic,
                     'error: key "' + 'A'*40 + '" could not be looked up remotely\n' + generic,
                     'error: unknown key "not-hex"\n' + generic,
                     'signature from "Fixture" is unknown trust\n' + generic,
                     'Permission denied\n' + generic,
                     'Network is unreachable\n' + generic,
                     'target not found: fixture\n' + generic):
            self.assertFalse(ad.qualify_tamper_rejection('wrongkey', FakeReceipt(1, err=text.encode()),
                             FakeReceipt(1), FakeReceipt(1), family='pacman')[0], text)
        for cause, category in [('Permission denied', 'PERMISSION_DENIED'),
                                ('Could not connect', 'NETWORK_UNAVAILABLE'),
                                ('target not found: fixture', 'PACKAGE_NOT_FOUND')]:
            text = cause + '\nerror: rs9: key "' + 'A'*40 + '" is unknown\n' + generic
            self.assertEqual(ad.classify_rejection(FakeReceipt(1, err=text.encode()), family='pacman'), category)

    def test_successful_install_is_accepted_even_when_query_fails(self):
        for kind in ('package', 'index', 'signature', 'wrongkey'):
            result = ad.qualify_tamper_rejection(kind, FakeReceipt(1, err=b'unknown key'),
                                                FakeReceipt(0), FakeReceipt(1), family='pacman')
            self.assertFalse(result[0])
            self.assertEqual(result[2], 'tampered-content-accepted')

    def test_modes_or_unexecuted_receipts_cannot_create_positive_control(self):
        for executed in (False, True):
            receipts = {s: CommandReceipt(['fixture', s], 0, b'', b'', executed=executed)
                        for s in ('configure', 'refresh', 'install', 'query')}
            ctrl = ad.build_positive_control(family='pacman', image='img', platform='linux/amd64',
                        product='fixture', setup_sha256='a'*64, success=True, receipts=receipts)
            ok, _ = ad.validate_positive_control(ctrl, family='pacman', image='img', platform='linux/amd64',
                                                 product='fixture', setup_sha256='a'*64)
            self.assertEqual(ok, executed)
        self.assertFalse(ad.validate_positive_control({'status':'pass', 'mode':0o644},
                            family='apt', image='img', platform='linux/amd64', product='fixture')[0])

    def test_family_specific_tamper_wording_and_stages(self):
        # Representative diagnostic fixtures, not captured native qualification.
        rows = [
            ('apt', 'wrongkey', 'Missing key ABCDEF, which is needed to verify signature.', 'KEY_MISMATCH'),
            ('pacman', 'signature', 'signature from "Fixture" is invalid', 'SIGNATURE_REJECTED'),
            ('pacman', 'signature', 'invalid or corrupted database (PGP signature)', 'SIGNATURE_REJECTED'),
            ('pacman', 'wrongkey', 'error: rs9: key "' + 'A'*40 + '" is unknown', 'KEY_MISMATCH'),
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

    def test_exact_run9_retained_signature_samples_reproduce_and_qualify(self):
        import hashlib
        fixture_path = Path(__file__).resolve().parent / "fixtures/run9/apt/apt-signature-samples.json"
        doc = json.loads(fixture_path.read_text())
        lane_path = Path(__file__).resolve().parent / "fixtures/run9/apt/lane-records.json"
        lane_doc = json.loads(lane_path.read_text())

        expected_sample_sha = "5a713ec83cd43eebc2cb66237e8286e1530b255070aa7839b738e6b74ffa5d22"
        expected_stderr_sha = "37390e5b7ae15abe2dc1c021291a40fe55391bc395847a95c9ba94c45ae8247f"

        raw_stderr = lane_doc["raw_stderr"]
        self.assertEqual(hashlib.sha256(raw_stderr.encode()).hexdigest(), expected_stderr_sha)

        for arch, row in doc["architectures"].items():
            with self.subTest(arch=arch):
                sample = row["sample"]
                self.assertEqual(hashlib.sha256(sample.encode()).hexdigest(), expected_sample_sha)

                # Receipts matching recorded hashes
                receipt_raw = CommandReceipt(["apt-get", "update"], 100, b"", raw_stderr.encode(), executed=True)
                self.assertEqual(receipt_raw.stderr_sha256, expected_stderr_sha)
                receipt_sanitized = CommandReceipt(["apt-get", "update"], 100, b"", sample.encode(), executed=True)

                # Raw reconstruction matches retained stderr; redacted samples alone cannot earn credit.
                self.assertEqual(ad.classify_rejection(receipt_raw, stage="refresh", family="apt", source_uri="file:/srv/rs9/apt", distribution="resolute"), "SIGNED_ENVELOPE_INVALID")
                self.assertEqual(ad.classify_rejection(receipt_sanitized, stage="refresh", family="apt"), "UNCLASSIFIED_FAILURE")

                # Bounded command diagnostics capture context consistently
                diag = ad.record_command_diagnostics(
                    stage="refresh", family="apt", product="theme-forge-stellar-burst", arch=arch, receipt=receipt_raw, source_uri="file:/srv/rs9/apt", distribution="resolute"
                )
                self.assertEqual(diag["reason_category"], "SIGNED_ENVELOPE_INVALID")
                self.assertEqual(diag["distribution"], "resolute")
                self.assertEqual(diag["source_context"], "file")
                self.assertEqual(diag["target_envelope"], "InRelease")
                self.assertEqual(diag["safe_sample"], sample)

                # Causal tamper qualification succeeds with exact qualifying stage and context
                ok, cat, reason, qual_diag = ad.qualify_tamper_rejection(
                    "signature", receipt_raw, FakeReceipt(100), FakeReceipt(1), family="apt", configure_rcpt=FakeReceipt(0),
                    signature_context={"source_uri":"file:/srv/rs9/apt", "distribution":"resolute",
                                       "mutation_verified":True, "network_disconnected":True, "positive_control_valid":True}
                )
                self.assertTrue(ok)
                self.assertEqual(cat, "SIGNED_ENVELOPE_INVALID")
                self.assertIsNone(reason)
                self.assertEqual(qual_diag["qualifying_stage"], "refresh")
                self.assertEqual(qual_diag["distribution"], "resolute")
                self.assertEqual(qual_diag["source_context"], "file")
                self.assertEqual(qual_diag["target_envelope"], "InRelease")
                self.assertEqual(qual_diag["sample"], sample)

        # Verify stdout byte availability limitation and exact SHA256 binding
        expected_stdout_sha = lane_doc["refresh_stdout_sha256"]
        self.assertEqual(expected_stdout_sha, "854b0b21ffc20fdc5c0ae47d27edcf977ab5c500a2d0390bb9c429ca9f45ba1c")
        # Retained evidence fixtures explicitly do not contain raw stdout bytes (original_stdout_reconstructed is false in evidence).
        # We perform a controlled reconstruction matching the recorded refresh_stdout_sha256.
        reconstructed_stdout = (
            "Get:1 file:/srv/rs9/apt resolute InRelease [1041 B]\n"
            "Get:1 file:/srv/rs9/apt resolute InRelease [1041 B]\n"
            "Err:1 file:/srv/rs9/apt resolute InRelease\n"
            "  Signed file isn't valid, got 'NODATA' (does the network require authentication?)\n"
            "Reading package lists...\n"
        )
        self.assertEqual(hashlib.sha256(reconstructed_stdout.encode()).hexdigest(), expected_stdout_sha)

        receipt_with_stdout = CommandReceipt(["apt-get", "update"], 100, reconstructed_stdout.encode(), raw_stderr.encode(), executed=True)
        self.assertEqual(receipt_with_stdout.stdout_sha256, expected_stdout_sha)
        self.assertEqual(receipt_with_stdout.stderr_sha256, expected_stderr_sha)
        self.assertEqual(
            ad.classify_rejection(receipt_with_stdout, stage="refresh", family="apt", source_uri="file:/srv/rs9/apt", distribution="resolute"),
            "SIGNED_ENVELOPE_INVALID",
        )
        diag_with_stdout = ad.record_command_diagnostics(
            stage="refresh", family="apt", product="theme-forge-stellar-burst", arch="amd64", receipt=receipt_with_stdout,
            source_uri="file:/srv/rs9/apt", distribution="resolute"
        )
        self.assertEqual(diag_with_stdout["reason_category"], "SIGNED_ENVELOPE_INVALID")
        self.assertEqual(diag_with_stdout["stdout_sha256"], expected_stdout_sha)
        self.assertTrue(diag_with_stdout["stream_shapes"]["stdout"]["complete"])
        self.assertEqual(diag_with_stdout["stream_shapes"]["stdout"]["line_count"], 5)
        self.assertTrue(diag_with_stdout["stream_shapes"]["stderr"]["complete"])
        self.assertEqual(diag_with_stdout["stream_shapes"]["stderr"]["line_count"], 1)

        ok, cat, reason, qual_diag = ad.qualify_tamper_rejection(
            "signature", receipt_with_stdout, FakeReceipt(100), FakeReceipt(1), family="apt", configure_rcpt=FakeReceipt(0),
            signature_context={"source_uri": "file:/srv/rs9/apt", "distribution": "resolute",
                               "mutation_verified": True, "network_disconnected": True, "positive_control_valid": True}
        )
        self.assertTrue(ok)
        self.assertEqual(cat, "SIGNED_ENVELOPE_INVALID")
        self.assertIsNone(reason)
        self.assertEqual(qual_diag["qualifying_stage"], "refresh")

    def test_signed_envelope_invalid_table_driven_negatives_and_precedence(self):
        valid_stderr = (
            "E: OpenPGP signature verification failed: file:/srv/rs9/apt resolute InRelease: "
            "Signed file isn't valid, got 'NODATA' (does the network require authentication?)\n"
        )
        cases = [
            # 1. Bare NODATA without OpenPGP signature envelope context
            ("bare_nodata", "E: Got 'NODATA' from repository", "refresh", "apt", 100, "UNCLASSIFIED_FAILURE"),
            # 2. HTTP URL instead of local file:
            ("http_source", valid_stderr.replace("file:/srv/rs9/apt", "http://archive.ubuntu.com/apt"), "refresh", "apt", 100, "UNCLASSIFIED_FAILURE"),
            # 3. HTTPS URL
            ("https_source", valid_stderr.replace("file:/srv/rs9/apt", "https://archive.ubuntu.com/apt"), "refresh", "apt", 100, "UNCLASSIFIED_FAILURE"),
            # 4. Captive portal HTML in stream
            ("captive_portal_html", valid_stderr + "<html><title>Hotspot Login</title></html>\n", "refresh", "apt", 100, "NETWORK_UNAVAILABLE"),
            # 5. Captive portal phrase
            ("captive_portal_text", valid_stderr + "captive portal authentication required\n", "refresh", "apt", 100, "NETWORK_UNAVAILABLE"),
            # 6. HTTP 302 Found
            ("http_redirect", valid_stderr + "HTTP/1.1 302 Found\n", "refresh", "apt", 100, "NETWORK_UNAVAILABLE"),
            # 7. Mixed permission error
            ("mixed_permission", "E: Could not open lock file - Permission denied\n" + valid_stderr, "refresh", "apt", 100, "PERMISSION_DENIED"),
            # 8. Mixed network unreachable
            ("mixed_network", "Err:1 ... Could not connect - Network is unreachable\n" + valid_stderr, "refresh", "apt", 100, "NETWORK_UNAVAILABLE"),
            # 9. Mixed DNS resolution failure
            ("mixed_dns", "Err:1 ... Temporary failure resolving 'archive.ubuntu.com'\n" + valid_stderr, "refresh", "apt", 100, "NETWORK_UNAVAILABLE"),
            # 10. Mixed tool missing
            ("mixed_tool", "sh: 1: gpgv: command not found\n" + valid_stderr, "refresh", "apt", 127, "COMMAND_NOT_FOUND"),
            # 11. Mixed package missing
            ("mixed_package", "E: Unable to locate package theme-forge-stellar-burst\n" + valid_stderr, "refresh", "apt", 100, "PACKAGE_NOT_FOUND"),
            # 12. Mixed source config error
            ("mixed_config", "E: Malformed entry 1 in sources file\n" + valid_stderr, "refresh", "apt", 100, "SOURCE_CONFIG_ERROR"),
            # 13. Other E: error line in stream
            ("other_e_error", valid_stderr + "E: Failed to fetch file:/srv/rs9/apt resolute InRelease Hash Sum mismatch\n", "refresh", "apt", 100, "INDEX_HASH_MISMATCH"),
            # 14. Other Err: error line in stream
            ("other_err_error", valid_stderr + "Err:1 file:/srv/rs9/apt resolute InRelease Sub-process returned an error code\n", "refresh", "apt", 100, "UNCLASSIFIED_FAILURE"),
            # 15. Wrong distribution (noble instead of resolute)
            ("wrong_dist", valid_stderr.replace("resolute", "noble"), "refresh", "apt", 100, "UNCLASSIFIED_FAILURE"),
            # 16. Wrong envelope file (Release instead of InRelease)
            ("wrong_file", valid_stderr.replace("InRelease", "Release"), "refresh", "apt", 100, "UNCLASSIFIED_FAILURE"),
            # 17. Wrong stage (install instead of refresh)
            ("wrong_stage", valid_stderr, "install", "apt", 100, "UNCLASSIFIED_FAILURE"),
            # 18. Wrong family (pacman)
            ("wrong_family_pacman", valid_stderr, "refresh", "pacman", 100, "UNCLASSIFIED_FAILURE"),
            # 19. Exit 0 is not a rejection
            ("exit_zero", valid_stderr, "refresh", "apt", 0, "COMMAND_SUCCESS"),
            # 20. Exit != 100
            ("exit_one", valid_stderr, "refresh", "apt", 1, "UNCLASSIFIED_FAILURE"),
        ]
        for name, text, stage, family, code, expected in cases:
            with self.subTest(case=name):
                rcpt = CommandReceipt(["tool"], code, b"", text.encode(), executed=True)
                category = ad.classify_rejection(rcpt, stage=stage, family=family, source_uri="file:/srv/rs9/apt", distribution="resolute")
                self.assertEqual(category, expected)
                if expected != "SIGNED_ENVELOPE_INVALID":
                    if stage == "install":
                        ok, cat, reason, diag = ad.qualify_tamper_rejection(
                            "signature", FakeReceipt(0), rcpt, FakeReceipt(1), family=family
                        )
                    else:
                        ok, cat, reason, diag = ad.qualify_tamper_rejection(
                            "signature", rcpt, FakeReceipt(100), FakeReceipt(1), family=family
                        )
                    self.assertFalse(ok)

    def test_causal_tamper_qualification_requirements(self):
        valid_stderr = (
            "E: OpenPGP signature verification failed: file:/srv/rs9/apt resolute InRelease: "
            "Signed file isn't valid, got 'NODATA' (does the network require authentication?)\n"
        )
        refresh_fail = CommandReceipt(["apt-get", "update"], 100, b"", valid_stderr.encode(), executed=True)

        # 1. Successful install means tamper accepted -> fails closed
        for install_rcpt, query_rcpt in [(FakeReceipt(0), FakeReceipt(1)), (FakeReceipt(100), FakeReceipt(0))]:
            ok, cat, reason, _ = ad.qualify_tamper_rejection("signature", refresh_fail, install_rcpt, query_rcpt, family="apt")
            self.assertFalse(ok)
            self.assertEqual(reason, "tampered-content-accepted")

        # 2. Refresh succeeding on signature tamper -> bypassed verification
        ok, cat, reason, _ = ad.qualify_tamper_rejection("signature", FakeReceipt(0), FakeReceipt(100), FakeReceipt(1), family="apt")
        self.assertFalse(ok)
        self.assertEqual(reason, "bypassed-signature-verification-on-refresh")

        # 3. Configure failing during tamper -> wrong stage failure
        cfg_fail = CommandReceipt(["cfg"], 1, b"", b"E: Malformed entry in sources", executed=True)
        ok, cat, reason, diag = ad.qualify_tamper_rejection("signature", refresh_fail, FakeReceipt(100), FakeReceipt(1), family="apt", configure_rcpt=cfg_fail)
        self.assertFalse(ok)
        self.assertEqual(diag.get("failed_stage"), "configure")

        # 4. Positive control validation requirements
        lane_doc = json.loads((Path(__file__).resolve().parent / "fixtures/run9/apt/lane-records.json").read_text())
        for arch, ctrl in lane_doc["positive_controls"].items():
            # Image mismatch fails validation
            ok, err = ad.validate_positive_control(
                ctrl, family=ctrl["family"], image="other-image", platform=ctrl["platform"], product=ctrl["product"],
                setup_sha256=ctrl["setup_sha256"]
            )
            self.assertFalse(ok)
            self.assertEqual(err, "positive-control-binding-mismatch")

            # Platform mismatch fails validation
            ok, err = ad.validate_positive_control(
                ctrl, family=ctrl["family"], image="img", platform="other/platform", product=ctrl["product"],
                setup_sha256=ctrl["setup_sha256"]
            )
            self.assertFalse(ok)
            self.assertEqual(err, "positive-control-binding-mismatch")

            # Setup mismatch fails validation
            ok, err = ad.validate_positive_control(
                ctrl, family=ctrl["family"], image="img", platform=ctrl["platform"], product=ctrl["product"],
                setup_sha256="wrong-setup-sha"
            )
            self.assertFalse(ok)
            self.assertEqual(err, "positive-control-binding-mismatch")

    def test_controlled_realistic_stdout_variations_and_regressions(self):
        valid_stderr = (
            "E: OpenPGP signature verification failed: file:/srv/rs9/apt resolute InRelease: "
            "Signed file isn't valid, got 'NODATA' (does the network require authentication?)\n"
        )
        variations = [
            (
                "standard_single_get_with_size",
                "Get:1 file:/srv/rs9/apt resolute InRelease [1041 B]\n"
                "Err:1 file:/srv/rs9/apt resolute InRelease\n"
                "  Signed file isn't valid, got 'NODATA' (does the network require authentication?)\n"
                "Reading package lists...\n"
            ),
            (
                "dual_get_with_size_as_in_run9",
                "Get:1 file:/srv/rs9/apt resolute InRelease [1041 B]\n"
                "Get:1 file:/srv/rs9/apt resolute InRelease [1041 B]\n"
                "Err:1 file:/srv/rs9/apt resolute InRelease\n"
                "  Signed file isn't valid, got 'NODATA' (does the network require authentication?)\n"
                "Reading package lists...\n"
            ),
            (
                "get_without_size",
                "Get:1 file:/srv/rs9/apt resolute InRelease\n"
                "Err:1 file:/srv/rs9/apt resolute InRelease\n"
                "  Signed file isn't valid, got 'NODATA'\n"
                "Reading package lists...\n"
            ),
            (
                "err_with_size",
                "Get:1 file:/srv/rs9/apt resolute InRelease [1041 B]\n"
                "Err:1 file:/srv/rs9/apt resolute InRelease [1041 B]\n"
                "  Signed file isn't valid, got 'NODATA' (does the network require authentication?)\n"
                "Reading package lists...\n"
            ),
            (
                "continuation_with_size",
                "Get:1 file:/srv/rs9/apt resolute InRelease [1041 B]\n"
                "Err:1 file:/srv/rs9/apt resolute InRelease\n"
                "  Signed file isn't valid, got 'NODATA' [1041 B]\n"
                "Reading package lists...\n"
            ),
            (
                "continuation_with_suffix_and_size",
                "Get:1 file:/srv/rs9/apt resolute InRelease [1041 B]\n"
                "Err:1 file:/srv/rs9/apt resolute InRelease\n"
                "  Signed file isn't valid, got 'NODATA' (does the network require authentication?) [1041 B]\n"
                "Reading package lists...\n"
            ),
            (
                "comma_formatted_size",
                "Get:1 file:/srv/rs9/apt resolute InRelease [1,041 B]\n"
                "Err:1 file:/srv/rs9/apt resolute InRelease\n"
                "  Signed file isn't valid, got 'NODATA' (does the network require authentication?)\n"
                "Reading package lists...\n"
            ),
            (
                "hit_progress_line",
                "Hit:1 file:/srv/rs9/apt resolute InRelease\n"
                "Err:1 file:/srv/rs9/apt resolute InRelease\n"
                "  Signed file isn't valid, got 'NODATA'\n"
                "Reading package lists...\n"
            ),
            (
                "ign_progress_line",
                "Ign:1 file:/srv/rs9/apt resolute InRelease\n"
                "Err:1 file:/srv/rs9/apt resolute InRelease\n"
                "  Signed file isn't valid, got 'NODATA'\n"
                "Reading package lists...\n"
            ),
            (
                "continuation_without_suffix",
                "Get:1 file:/srv/rs9/apt resolute InRelease [1041 B]\n"
                "Err:1 file:/srv/rs9/apt resolute InRelease\n"
                "  Signed file isn't valid, got 'NODATA'\n"
                "Reading package lists...\n"
            ),
            (
                "reading_package_lists_done",
                "Get:1 file:/srv/rs9/apt resolute InRelease [1041 B]\n"
                "Err:1 file:/srv/rs9/apt resolute InRelease\n"
                "  Signed file isn't valid, got 'NODATA'\n"
                "Reading package lists... Done\n"
            ),
            (
                "without_reading_package_lists",
                "Get:1 file:/srv/rs9/apt resolute InRelease [1041 B]\n"
                "Err:1 file:/srv/rs9/apt resolute InRelease\n"
                "  Signed file isn't valid, got 'NODATA' (does the network require authentication?)\n"
            ),
        ]
        for name, stdout_text in variations:
            with self.subTest(variation=name):
                rcpt = CommandReceipt(["apt-get", "update"], 100, stdout_text.encode(), valid_stderr.encode(), executed=True)
                category = ad.classify_rejection(rcpt, stage="refresh", family="apt", source_uri="file:/srv/rs9/apt", distribution="resolute")
                self.assertEqual(category, "SIGNED_ENVELOPE_INVALID")

                diag = ad.record_command_diagnostics(
                    stage="refresh", family="apt", product="theme-forge-stellar-burst", arch="amd64", receipt=rcpt,
                    source_uri="file:/srv/rs9/apt", distribution="resolute"
                )
                self.assertEqual(diag["reason_category"], "SIGNED_ENVELOPE_INVALID")
                self.assertEqual(diag["distribution"], "resolute")
                self.assertEqual(diag["source_context"], "file")
                self.assertEqual(diag["target_envelope"], "InRelease")
                self.assertTrue(diag["stream_shapes"]["stdout"]["complete"])
                self.assertEqual(diag["stream_shapes"]["stdout"]["line_count"], len(stdout_text.splitlines()))

                ok, cat, reason, qual_diag = ad.qualify_tamper_rejection(
                    "signature", rcpt, FakeReceipt(100), FakeReceipt(1), family="apt", configure_rcpt=FakeReceipt(0),
                    signature_context={"source_uri": "file:/srv/rs9/apt", "distribution": "resolute",
                                       "mutation_verified": True, "network_disconnected": True, "positive_control_valid": True}
                )
                self.assertTrue(ok)
                self.assertEqual(cat, "SIGNED_ENVELOPE_INVALID")
                self.assertIsNone(reason)
                self.assertEqual(qual_diag["qualifying_stage"], "refresh")
                self.assertEqual(qual_diag["distribution"], "resolute")
                self.assertEqual(qual_diag["source_context"], "file")
                self.assertEqual(qual_diag["target_envelope"], "InRelease")

    def test_nonempty_stdout_table_driven_negatives_and_blocking_exclusions(self):
        valid_stderr = (
            "E: OpenPGP signature verification failed: file:/srv/rs9/apt resolute InRelease: "
            "Signed file isn't valid, got 'NODATA' (does the network require authentication?)\n"
        )
        normal_stdout = (
            "Get:1 file:/srv/rs9/apt resolute InRelease [1041 B]\n"
            "Err:1 file:/srv/rs9/apt resolute InRelease\n"
            "  Signed file isn't valid, got 'NODATA' (does the network require authentication?)\n"
            "Reading package lists...\n"
        )
        cases = [
            # 1. Ambiguous NODATA in stdout without envelope context
            ("bare_nodata_in_stdout", "Get:1 file:/srv/rs9/apt resolute InRelease [1041 B]\nE: Got 'NODATA' from repository\n", "refresh", "apt", 100, "UNCLASSIFIED_FAILURE"),
            # 2. HTTP URL in stdout instead of local file:
            ("http_source_in_stdout", normal_stdout.replace("file:/srv/rs9/apt", "http://archive.ubuntu.com/apt"), "refresh", "apt", 100, "UNCLASSIFIED_FAILURE"),
            # 3. HTTPS URL in stdout
            ("https_source_in_stdout", normal_stdout.replace("file:/srv/rs9/apt", "https://archive.ubuntu.com/apt"), "refresh", "apt", 100, "UNCLASSIFIED_FAILURE"),
            # 4. Captive portal HTML in stdout
            ("captive_portal_html_in_stdout", normal_stdout + "<html><title>Hotspot Login</title></html>\n", "refresh", "apt", 100, "NETWORK_UNAVAILABLE"),
            # 5. Captive portal text in stdout
            ("captive_portal_text_in_stdout", normal_stdout + "captive portal authentication required\n", "refresh", "apt", 100, "NETWORK_UNAVAILABLE"),
            # 6. HTTP 302 Found in stdout
            ("http_redirect_in_stdout", normal_stdout + "HTTP/1.1 302 Found\n", "refresh", "apt", 100, "NETWORK_UNAVAILABLE"),
            # 7. HTTP 403 Forbidden in stdout
            ("http_forbidden_in_stdout", normal_stdout + "HTTP/1.1 403 Forbidden\n", "refresh", "apt", 100, "NETWORK_UNAVAILABLE"),
            # 8. Mixed permission error in stdout
            ("mixed_permission_in_stdout", "E: Could not open lock file - Permission denied\n" + normal_stdout, "refresh", "apt", 100, "PERMISSION_DENIED"),
            # 9. Mixed network unreachable in stdout
            ("mixed_network_in_stdout", "Err:1 ... Could not connect - Network is unreachable\n" + normal_stdout, "refresh", "apt", 100, "NETWORK_UNAVAILABLE"),
            # 10. Mixed DNS resolution failure in stdout
            ("mixed_dns_in_stdout", "Err:1 ... Temporary failure resolving 'archive.ubuntu.com'\n" + normal_stdout, "refresh", "apt", 100, "NETWORK_UNAVAILABLE"),
            # 11. Mixed tool missing in stdout (exit 127)
            ("mixed_tool_in_stdout", "sh: 1: gpgv: command not found\n" + normal_stdout, "refresh", "apt", 127, "COMMAND_NOT_FOUND"),
            # 12. Mixed package missing in stdout
            ("mixed_package_in_stdout", "E: Unable to locate package theme-forge-stellar-burst\n" + normal_stdout, "refresh", "apt", 100, "PACKAGE_NOT_FOUND"),
            # 13. Mixed source config error in stdout
            ("mixed_config_in_stdout", "E: Malformed entry 1 in sources file\n" + normal_stdout, "refresh", "apt", 100, "SOURCE_CONFIG_ERROR"),
            # 14. Other E: error line in stdout
            ("other_e_error_in_stdout", normal_stdout + "E: Failed to fetch file:/srv/rs9/apt resolute InRelease Hash Sum mismatch\n", "refresh", "apt", 100, "INDEX_HASH_MISMATCH"),
            # 15. Other Err: error line in stdout
            ("other_err_error_in_stdout", normal_stdout + "Err:1 file:/srv/rs9/apt resolute InRelease Sub-process returned an error code\n", "refresh", "apt", 100, "UNCLASSIFIED_FAILURE"),
            # 16. Unrelated repository error in stdout
            ("unrelated_repo_err_in_stdout", normal_stdout + "Err:2 http://security.ubuntu.com resolute InRelease Connection refused\n", "refresh", "apt", 100, "NETWORK_UNAVAILABLE"),
            # 17. Wrong distribution in stdout
            ("wrong_dist_in_stdout", normal_stdout.replace("resolute", "noble"), "refresh", "apt", 100, "UNCLASSIFIED_FAILURE"),
            # 18. Wrong envelope file in stdout
            ("wrong_file_in_stdout", normal_stdout.replace("InRelease", "Release"), "refresh", "apt", 100, "UNCLASSIFIED_FAILURE"),
            # 19. Wrong stage (install instead of refresh) with nonempty stdout
            ("wrong_stage_with_stdout", normal_stdout, "install", "apt", 100, "UNCLASSIFIED_FAILURE"),
            # 20. Wrong family (pacman) with nonempty stdout
            ("wrong_family_with_stdout", normal_stdout, "refresh", "pacman", 100, "UNCLASSIFIED_FAILURE"),
            # 21. Exit 0 is not a rejection
            ("exit_zero_with_stdout", normal_stdout, "refresh", "apt", 0, "COMMAND_SUCCESS"),
            # 22. Exit != 100 with nonempty stdout
            ("exit_one_with_stdout", normal_stdout, "refresh", "apt", 1, "UNCLASSIFIED_FAILURE"),
        ]
        for name, stdout_text, stage, family, code, expected in cases:
            with self.subTest(case=name):
                rcpt = CommandReceipt(["apt-get", "update"], code, stdout_text.encode(), valid_stderr.encode(), executed=True)
                category = ad.classify_rejection(rcpt, stage=stage, family=family, source_uri="file:/srv/rs9/apt", distribution="resolute")
                self.assertEqual(category, expected)
                if expected != "SIGNED_ENVELOPE_INVALID":
                    if stage == "install":
                        ok, cat, reason, diag = ad.qualify_tamper_rejection(
                            "signature", FakeReceipt(0), rcpt, FakeReceipt(1), family=family
                        )
                    else:
                        ok, cat, reason, diag = ad.qualify_tamper_rejection(
                            "signature", rcpt, FakeReceipt(100), FakeReceipt(1), family=family
                        )
                    self.assertFalse(ok)

    def test_full_stream_envelope_allowlist_large_stream_credit(self):
        # Many allowlisted progress lines with full streams > 64KiB + qualifying line earns credit
        progress_line = b"Get:1 file:/srv/rs9/apt resolute InRelease [1041 B]\n"
        # 1500 lines * 51 bytes = 76,500 bytes (> 64KiB = 65,536 bytes)
        stdout_bytes = progress_line * 1500
        self.assertGreater(len(stdout_bytes), 65536)
        valid_stderr = (
            b"E: OpenPGP signature verification failed: file:/srv/rs9/apt resolute InRelease: "
            b"Signed file isn't valid, got 'NODATA' (does the network require authentication?)\n"
        )
        rcpt = CommandReceipt(["apt-get", "update"], 100, stdout_bytes, valid_stderr, executed=True)

        # Classification succeeds on full stream
        self.assertEqual(
            ad.classify_rejection(rcpt, stage="refresh", family="apt", source_uri="file:/srv/rs9/apt", distribution="resolute"),
            "SIGNED_ENVELOPE_INVALID",
        )

        # Causal tamper qualification succeeds
        ok, cat, reason, qual_diag = ad.qualify_tamper_rejection(
            "signature", rcpt, FakeReceipt(100), FakeReceipt(1), family="apt", configure_rcpt=FakeReceipt(0),
            signature_context={"source_uri": "file:/srv/rs9/apt", "distribution": "resolute",
                               "mutation_verified": True, "network_disconnected": True, "positive_control_valid": True}
        )
        self.assertTrue(ok)
        self.assertEqual(cat, "SIGNED_ENVELOPE_INVALID")
        self.assertIsNone(reason)
        self.assertEqual(qual_diag["qualifying_stage"], "refresh")

        # Diagnostics: raw > 64KiB means stdout completeness metadata is truthful False, stderr is True
        diag = ad.record_command_diagnostics(
            stage="refresh", family="apt", product="theme-forge-stellar-burst", arch="amd64", receipt=rcpt,
            source_uri="file:/srv/rs9/apt", distribution="resolute"
        )
        self.assertEqual(diag["reason_category"], "SIGNED_ENVELOPE_INVALID")
        self.assertFalse(diag["stream_shapes"]["stdout"]["complete"])
        self.assertEqual(diag["stream_shapes"]["stdout"]["line_count"], 1500)
        self.assertTrue(diag["stream_shapes"]["stderr"]["complete"])
        self.assertEqual(diag["stream_shapes"]["stderr"]["line_count"], 1)

    def test_full_stream_envelope_late_bad_lines_no_credit(self):
        # Late network/HTTP/context bad line beyond 64KiB gets no credit
        progress_line = b"Get:1 file:/srv/rs9/apt resolute InRelease [1041 B]\n"
        base_stdout = progress_line * 1500  # > 64KiB
        valid_stderr = (
            b"E: OpenPGP signature verification failed: file:/srv/rs9/apt resolute InRelease: "
            b"Signed file isn't valid, got 'NODATA' (does the network require authentication?)\n"
        )
        bad_suffixes = [
            (b"Err:2 http://archive.ubuntu.com resolute InRelease Could not connect - Network is unreachable\n", "late_network"),
            (b"HTTP/1.1 500 Internal Server Error\n", "late_http"),
            (b"<html><title>504 Gateway Timeout</title></html>\n", "late_html"),
            (b"E: Malformed entry in sources file\n", "late_context_error"),
            (b"corrupt trailing late content\n", "late_corrupt_content"),
        ]
        for bad_line, name in bad_suffixes:
            with self.subTest(case=name):
                rcpt = CommandReceipt(["apt-get", "update"], 100, base_stdout + bad_line, valid_stderr, executed=True)
                cat = ad.classify_rejection(rcpt, stage="refresh", family="apt", source_uri="file:/srv/rs9/apt", distribution="resolute")
                self.assertNotEqual(cat, "SIGNED_ENVELOPE_INVALID", f"Case {name} must not earn SIGNED_ENVELOPE_INVALID credit")
                ok, _, reason, _ = ad.qualify_tamper_rejection(
                    "signature", rcpt, FakeReceipt(100), FakeReceipt(1), family="apt", configure_rcpt=FakeReceipt(0),
                    signature_context={"source_uri": "file:/srv/rs9/apt", "distribution": "resolute",
                                       "mutation_verified": True, "network_disconnected": True, "positive_control_valid": True}
                )
                self.assertFalse(ok, f"Case {name} must fail tamper qualification")

    def test_full_stream_envelope_invalid_utf8_and_incomplete_framing(self):
        # Invalid UTF8 and incomplete framing cannot receive credit
        valid_stdout = b"Get:1 file:/srv/rs9/apt resolute InRelease [1041 B]\n"
        valid_stderr = (
            b"E: OpenPGP signature verification failed: file:/srv/rs9/apt resolute InRelease: "
            b"Signed file isn't valid, got 'NODATA' (does the network require authentication?)\n"
        )
        # 3a. Invalid UTF-8 in stdout
        rcpt_bad_utf8_out = CommandReceipt(["apt-get", "update"], 100, b"\xff\xfe\x80\x81\n", valid_stderr, executed=True)
        self.assertNotEqual(
            ad.classify_rejection(rcpt_bad_utf8_out, stage="refresh", family="apt", source_uri="file:/srv/rs9/apt", distribution="resolute"),
            "SIGNED_ENVELOPE_INVALID",
        )
        self.assertFalse(ad.qualify_tamper_rejection(
            "signature", rcpt_bad_utf8_out, FakeReceipt(100), FakeReceipt(1), family="apt", configure_rcpt=FakeReceipt(0),
            signature_context={"source_uri": "file:/srv/rs9/apt", "distribution": "resolute",
                               "mutation_verified": True, "network_disconnected": True, "positive_control_valid": True}
        )[0])

        # 3b. Invalid UTF-8 in stderr
        rcpt_bad_utf8_err = CommandReceipt(["apt-get", "update"], 100, valid_stdout, b"\xff\xfe" + valid_stderr, executed=True)
        self.assertNotEqual(
            ad.classify_rejection(rcpt_bad_utf8_err, stage="refresh", family="apt", source_uri="file:/srv/rs9/apt", distribution="resolute"),
            "SIGNED_ENVELOPE_INVALID",
        )
        self.assertFalse(ad.qualify_tamper_rejection(
            "signature", rcpt_bad_utf8_err, FakeReceipt(100), FakeReceipt(1), family="apt", configure_rcpt=FakeReceipt(0),
            signature_context={"source_uri": "file:/srv/rs9/apt", "distribution": "resolute",
                               "mutation_verified": True, "network_disconnected": True, "positive_control_valid": True}
        )[0])

        # 3c. Incomplete framing: stdout missing trailing newline
        rcpt_no_nl_out = CommandReceipt(["apt-get", "update"], 100, valid_stdout.rstrip(b"\n"), valid_stderr, executed=True)
        self.assertNotEqual(
            ad.classify_rejection(rcpt_no_nl_out, stage="refresh", family="apt", source_uri="file:/srv/rs9/apt", distribution="resolute"),
            "SIGNED_ENVELOPE_INVALID",
        )
        self.assertFalse(ad.qualify_tamper_rejection(
            "signature", rcpt_no_nl_out, FakeReceipt(100), FakeReceipt(1), family="apt", configure_rcpt=FakeReceipt(0),
            signature_context={"source_uri": "file:/srv/rs9/apt", "distribution": "resolute",
                               "mutation_verified": True, "network_disconnected": True, "positive_control_valid": True}
        )[0])

        # 3d. Incomplete framing: stderr missing trailing newline
        rcpt_no_nl_err = CommandReceipt(["apt-get", "update"], 100, valid_stdout, valid_stderr.rstrip(b"\n"), executed=True)
        self.assertNotEqual(
            ad.classify_rejection(rcpt_no_nl_err, stage="refresh", family="apt", source_uri="file:/srv/rs9/apt", distribution="resolute"),
            "SIGNED_ENVELOPE_INVALID",
        )
        self.assertFalse(ad.qualify_tamper_rejection(
            "signature", rcpt_no_nl_err, FakeReceipt(100), FakeReceipt(1), family="apt", configure_rcpt=FakeReceipt(0),
            signature_context={"source_uri": "file:/srv/rs9/apt", "distribution": "resolute",
                               "mutation_verified": True, "network_disconnected": True, "positive_control_valid": True}
        )[0])

    def test_record_command_diagnostics_multibyte_preview_false_completeness(self):
        # 4. Multibyte preview false completeness prevention
        # Raw bytes <= 65536, lines <= 64, line <= 512, strict UTF-8 valid, but contains non-ASCII multibyte char
        multibyte_stdout = "Get:1 file:/srv/rs9/apt resolute InRelease [1041 B] \u2014 valid\n".encode("utf-8")
        valid_stderr = (
            b"E: OpenPGP signature verification failed: file:/srv/rs9/apt resolute InRelease: "
            b"Signed file isn't valid, got 'NODATA' (does the network require authentication?)\n"
        )
        rcpt = CommandReceipt(["apt-get", "update"], 100, multibyte_stdout, valid_stderr, executed=True)
        self.assertLessEqual(len(rcpt.stdout_bytes), 65536)

        diag = ad.record_command_diagnostics(
            stage="refresh", family="apt", product="theme-forge-stellar-burst", arch="amd64", receipt=rcpt,
            source_uri="file:/srv/rs9/apt", distribution="resolute"
        )
        # Safe sample replaces multibyte with "non-printable-stream-withheld"
        self.assertEqual(diag["stream_shapes"]["stdout"]["lines"], ["non-printable-stream-withheld"])
        # Complete MUST be False because safe preview withheld the content rather than showing exact preview
        self.assertFalse(diag["stream_shapes"]["stdout"]["complete"])
        # stderr has valid ASCII and ends with newline, so stderr is complete
        self.assertTrue(diag["stream_shapes"]["stderr"]["complete"])

    def test_machine_text_contract_error_returns_false(self):
        # Catches ContractError from machine_text -> returns False
        valid_stdout = b"Get:1 file:/srv/rs9/apt resolute InRelease [1041 B]\n"
        valid_stderr = (
            b"E: OpenPGP signature verification failed: file:/srv/rs9/apt resolute InRelease: "
            b"Signed file isn't valid, got 'NODATA' (does the network require authentication?)\n"
        )
        rcpt = CommandReceipt(["apt-get", "update"], 100, valid_stdout, valid_stderr, executed=True)
        from unittest.mock import patch
        from rs9.errors import ContractError
        with patch("rs9.apt_diagnostics.machine_text", side_effect=ContractError("STREAM_LIMIT_EXCEEDED", "error")):
            self.assertEqual(
                ad.classify_rejection(rcpt, stage="refresh", family="apt", source_uri="file:/srv/rs9/apt", distribution="resolute"),
                "UNCLASSIFIED_FAILURE",
            )


class EnvelopeContextTests(unittest.TestCase):
    def test_missing_or_wrong_context_and_mixed_stdout_cannot_qualify(self):
        message = b"E: OpenPGP signature verification failed: file:/srv/rs9/apt resolute InRelease: Signed file isn't valid, got 'NODATA' (does the network require authentication?)\n"
        for context in ({}, {"source_uri":"file:/srv/other", "distribution":"resolute"}, {"source_uri":"file:/srv/rs9/apt", "distribution":"noble"}):
            self.assertEqual(ad.classify_rejection(FakeReceipt(100,err=message),stage="refresh",**context),"UNCLASSIFIED_FAILURE")
        context={"source_uri":"file:/srv/rs9/apt","distribution":"resolute"}
        for stdout in (b"E: unrelated failure",b"Err:1 unrelated source"):
            self.assertEqual(ad.classify_rejection(FakeReceipt(100,out=stdout,err=message),stage="refresh",**context),"UNCLASSIFIED_FAILURE")
        proof=dict(context,mutation_verified=True,network_disconnected=True,positive_control_valid=True)
        for key in ("mutation_verified","network_disconnected","positive_control_valid"):
            broken=dict(proof,**{key:False})
            self.assertFalse(ad.qualify_tamper_rejection("signature",FakeReceipt(100,err=message),FakeReceipt(100),FakeReceipt(1),configure_rcpt=FakeReceipt(0),signature_context=broken)[0])
        for install,query in ((FakeReceipt(127),FakeReceipt(1)),(FakeReceipt(100),FakeReceipt(127)),
                              (FakeReceipt(100,err=b'Permission denied'),FakeReceipt(1)),
                              (FakeReceipt(100),FakeReceipt(1,err=b'command not found')),
                              (FakeReceipt(100,err=b'Could not connect'),FakeReceipt(1))):
            self.assertFalse(ad.qualify_tamper_rejection("signature",FakeReceipt(100,err=message),install,query,
                             configure_rcpt=FakeReceipt(0),signature_context=proof)[0])
        rcpt=FakeReceipt(100,err=message)
        rcpt.executed=False
        self.assertFalse(ad.qualify_tamper_rejection("signature",rcpt,FakeReceipt(100),FakeReceipt(1),configure_rcpt=FakeReceipt(0),signature_context=proof)[0])
        diagnostics=ad.record_command_diagnostics(stage="refresh",family="apt",product="p",arch="amd64",receipt=FakeReceipt(100,err=message),**context)
        self.assertTrue(diagnostics['stream_shapes']['stderr']['complete'])
        self.assertEqual(diagnostics['stream_shapes']['stderr']['line_count'],1)
