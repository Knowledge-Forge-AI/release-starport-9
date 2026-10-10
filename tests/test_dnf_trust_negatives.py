"""Synthetic receipt contracts and real fixture-signing checks, not native DNF.

Decision fixtures deliberately exceed preview bounds. The real GnuPG check
proves only mutation framing/signature rejection and never a Fedora pass.
"""
import base64
import copy
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from rs9 import apt_diagnostics as ad, dnf_diagnostics as dd, dnf_mutation as dm, hosted_deb as hd
from rs9.build_native import CommandReceipt
from rs9.errors import ContractError
from rs9.release_core import digest
from rs9.scratch import canonical

PRODUCT = "theme-forge-stellar-burst"
FINGERPRINT = "A" * 40
ORIGINAL = "a" * 64
CHANGED = "b" * 64


def receipt(code=0, out=b"", err=b"", executed=True, stage=None):
    stage = stage or ("install" if b"checksum" in err or b"No match" in err else "refresh")
    return CommandReceipt(dd.stage_command(stage, PRODUCT), code, out, err, executed=executed)


def absent(product=PRODUCT):
    return receipt(1, f"package {product} is not installed\n".encode())


def checksum_message(actual=CHANGED, expected=ORIGINAL, product=PRODUCT, arch="x86_64"):
    return (f"[1/1] {product}-0:0.6.1\n"
            f">>> Downloading successful, but checksum doesn't match. Calculated: {actual}(sha256)  Expected: {expected}(sha256) \n"
            f"Librepo error: Cannot download Packages/{product}-0.6.1-1.fc43.{arch}.rpm: All mirrors were tried\n").encode()


def repo_message(reason="Bad PGP signature"):
    return (f">>> repomd.xml GPG signature verification error: {reason}\n"
            f'Failed to download metadata (baseurl: "file:///srv/rs9/rpm/fedora/43/x86_64") for repository "{dd.DNF_REPO_ID}": repomd.xml GPG signature verification error: {reason}\n').encode()


def synthetic_armor(seed=b"controlled synthetic signature"):
    body = b"\x04\x00\x01\x08\x00\x00" + seed
    packet = bytes([0xC2, len(body)]) + body
    encoded = base64.b64encode(packet)
    return (b"-----BEGIN PGP SIGNATURE-----\n\n" + encoded + b"\n="
            + base64.b64encode(dm._crc24(packet)) + b"\n-----END PGP SIGNATURE-----\n")


class WrongSigner:
    """Signing/verification double; it does not establish native cryptography."""
    primary_fingerprint = "B" * 40

    def detach_sign(self, data, **kwargs):
        return synthetic_armor(b"wrong synthetic signature")

    def verify(self, data, signature):
        if data != b"<repomd/>\n" or signature != self.detach_sign(data):
            raise ContractError("INVALID_TAMPER_MUTATION", "Synthetic signature does not match")
        return {"status": "valid", "verified_issuer": self.primary_fingerprint}


class ProbeClient:
    image = "sha256:" + "c" * 64
    platform = "linux/amd64"

    def __init__(self, spec):
        self.spec, self.calls, self.responses = spec, [], {}
        for stage, command in spec.get("dnf_probe_commands", []):
            if stage.startswith("cache-"):
                data = json.dumps({"key_sha256": spec["expected_key_sha256"], "candidate_cache_entries": 0}).encode()
            elif stage == "presentation":
                data = json.dumps(dd.DNF_PRESENTATION).encode() + b"\n"
            elif stage == "dnf-version": data = b"dnf5 version 5.2.18.0\nlibdnf5 version 5.2.18.0\n"
            elif stage == "rpm-version": data = b"RPM version 6.0.2\n"
            elif stage == "main-config":
                data = b"======== Main configuration: ========\nsystem_cachedir = /var/cache/libdnf5\ncacheonly = none\noptional_unset\n"
            else:
                data = (f'======== "{dd.DNF_REPO_ID}" repository configuration: ========\nenabled = 1\nbaseurl = {spec["source_uri"]}\n'
                        f"gpgkey = {dd.KEY_URI}\npkg_gpgcheck = 1\nrepo_gpgcheck = 1\n"
                        "skip_if_unavailable = 0\nmetalink = \nmirrorlist = \n"
                        '======== "fedora" repository configuration: ========\nenabled = 0\noptional_unset\n').encode()
            self.responses[stage] = receipt(out=data)
        if "probe" in spec and isinstance(spec["probe"], Mapping):
            for stage, command in spec["probe"].items():
                if stage == "presentation" and stage not in self.responses:
                    self.responses[stage] = receipt(out=json.dumps(dd.DNF_PRESENTATION).encode() + b"\n")

    def exec(self, argv, **kwargs):
        self.calls.append(list(argv))
        # cache-before and cache-after intentionally use identical argv.
        stages = [stage for stage, command in self.spec.get("dnf_probe_commands", []) if command == argv]
        if not stages and "probe" in self.spec and isinstance(self.spec["probe"], Mapping):
            stages = [stage for stage, command in self.spec["probe"].items() if command == argv]
        stage = stages[-1] if stages and stages[0] == "cache-before" and len(self.calls) > 1 else (stages[0] if stages else "unknown")
        return self.responses.get(stage, receipt())

    def dnf_image_identity_receipt(self):
        return getattr(self, "image_receipt", receipt(out=(self.image + "\n").encode()))


class DnfTrustTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        keys = self.root / "keys"; keys.mkdir()
        (keys / "rs9-candidate-fixture-NONPRODUCTION.asc").write_bytes(b"public-key-fixture")
        self.spec = hd.dnf_spec(self.root / "rpm", keys, "x86_64", public_fingerprint=FINGERPRINT)

    def probe(self):
        return dd.probe_dnf_client(ProbeClient(self.spec), self.spec)

    def context(self, kind="signature"):
        probe = self.probe()
        self.assertEqual(probe["status"], "pass")
        mutation = {"kind": kind, "verified": True, "control_sha256": ORIGINAL, "tampered_sha256": CHANGED,
                    "target": "fedora/43/x86_64/Packages/" + PRODUCT + "-0.6.1-1.fc43.x86_64.rpm" if kind == "package" else "fedora/43/x86_64/repodata/repomd.xml" + ("" if kind == "index" else ".asc")}
        if kind == "index": mutation["authentication_boundary"] = "repomd-signature"
        if kind == "signature":
            mutation.update(armor_framing_preserved=True, packet_changed_offset=63, packet_length=64)
        if kind == "wrongkey":
            mutation.update(control_key_fingerprint=FINGERPRINT, replacement_issuer=WrongSigner.primary_fingerprint,
                            replacement_signature_verified=True)
        return {"product": PRODUCT, "arch": "x86_64", "probe": probe,
                "positive_control_valid": True, "positive_identity_sha256": probe["identity_sha256"],
                "mutation": mutation}

    def qualify(self, kind="signature", *, refresh=None, install=None, query=None, context=None, configure=None):
        if refresh is None: refresh = receipt(0) if kind == "package" else receipt(1, err=repo_message("Signing key not found" if kind == "wrongkey" else "Bad PGP signature"))
        if install is None: install = receipt(1, err=checksum_message() if kind == "package" else repo_message("Signing key not found" if kind == "wrongkey" else "Bad PGP signature"), stage="install")
        return ad.qualify_tamper_rejection(kind, refresh, install, query if query is not None else absent(), family="dnf",
                 configure_rcpt=configure if configure is not None else receipt(), dnf_context=context if context is not None else self.context(kind))

    def test_strict_spec_invocation_pages_and_removal_isolation(self):
        for argv in (self.spec["refresh"], self.spec["install"](PRODUCT), *[c for s, c in self.spec["dnf_probe_commands"] if s.endswith("config")]):
            self.assertIn("--disablerepo=*", argv)
            self.assertIn("--enablerepo=" + dd.DNF_REPO_ID, argv)
            self.assertIn("--setopt=" + dd.DNF_REPO_ID + ".skip_if_unavailable=False", argv)
            self.assertIn("--setopt=" + dd.DNF_REPO_ID + ".gpgcheck=1", argv)
            self.assertIn("--setopt=" + dd.DNF_REPO_ID + ".repo_gpgcheck=1", argv)
            for forbidden in ("--nogpgcheck", "--no-gpgchecks", "--skip-unavailable", "--skip-broken"):
                self.assertNotIn(forbidden, argv)
        self.assertIn("skip_if_unavailable=False", self.spec["configure"][0][-1])
        self.assertIn("--disablerepo=*", self.spec["remove"](PRODUCT))
        self.assertNotIn("--enablerepo=" + dd.DNF_REPO_ID, self.spec["remove"](PRODUCT))
        # Pages calls the same spec with the actual fixture fingerprint.
        source = (Path(hd.__file__)).read_text()
        self.assertIn('dnf_spec(d["rpm"], keys, "x86_64", public_fingerprint=fixture.primary_fingerprint)', source)

    def test_dnf_only_locale_and_width_pin_at_actual_exec_boundary(self):
        class Host:
            def run(self, argv): self.argv = argv; return receipt()
        for family in ("apt", "pacman", "dnf"):
            host = Host(); client = hd.ClientContainer(host, "image", "linux/amd64", [], family)
            client.exec(["rpm", "-q", PRODUCT])
            self.assertEqual("LC_ALL=C" in host.argv, family == "dnf")
            self.assertEqual("LANG=C" in host.argv, family == "dnf")
            if family == "dnf":
                client.dnf_image_identity_receipt()
                self.assertEqual(host.argv, ["docker", "inspect", "--format", "{{.Image}}", client.name])
        self.assertIn("FORCE_COLUMNS=512", self.spec["refresh"])
        self.assertIn("LC_ALL=C", self.spec["refresh"])
        self.assertIn("DNF5_FORCE_INTERACTIVE=0", self.spec["refresh"])
        self.assertIn("FORCE_COLUMNS=512", self.spec["install"](PRODUCT))
        self.assertIn("DNF5_FORCE_INTERACTIVE=0", self.spec["install"](PRODUCT))

    def test_actual_probe_binds_allowlisted_config_tools_key_and_image(self):
        client = ProbeClient(self.spec); result = dd.probe_dnf_client(client, self.spec)
        self.assertEqual(result["status"], "pass")
        identity = result["identity"]
        self.assertEqual(identity["repo_id"], dd.DNF_REPO_ID)
        self.assertEqual(identity["source_uri"], self.spec["source_uri"])
        self.assertEqual(identity["key_sha256"], self.spec["expected_key_sha256"])
        self.assertEqual(identity["image_sha256"], digest(client.image.encode()))
        self.assertEqual(identity["image_id"], client.image)
        self.assertEqual(identity["presentation"], dd.DNF_PRESENTATION)
        self.assertEqual(identity["version"], dd.DNF_VERSION)
        self.assertFalse(identity["configuration"]["skip_if_unavailable"])
        self.assertEqual(result["candidate_cache_before"], 0)
        self.assertEqual(result["candidate_cache_after"], 0)
        self.assertEqual(client.calls[0], client.calls[-1])
        self.assertNotIn("repo list", json.dumps(client.calls))
        text = json.dumps(result)
        self.assertNotIn(str(self.root), text)
        self.assertNotIn("public-key-fixture", text)

    def test_probe_rejects_each_trust_field_and_duplicate_dump(self):
        for old, new in ((b"enabled = 1", b"enabled = 0"), (b"pkg_gpgcheck = 1", b"pkg_gpgcheck = 0"),
                         (b"repo_gpgcheck = 1", b"repo_gpgcheck = 0"), (b"skip_if_unavailable = 0", b"skip_if_unavailable = 1"),
                         (b"file:///srv/rs9/rpm/fedora/43/x86_64", b"file:///elsewhere"),
                         (dd.KEY_URI.encode(), b"file:///wrong-key"), (b'"fedora" repository configuration: ========\nenabled = 0', b'"fedora" repository configuration: ========\nenabled = 1'),
                         (b"mirrorlist = ", b"mirrorlist = forbidden"), (b"enabled = 1", b"enabled = 1\nenabled = 1")):
            client = ProbeClient(self.spec)
            client.responses["repo-config"] = receipt(out=client.responses["repo-config"].stdout_bytes.replace(old, new))
            self.assertEqual(dd.probe_dnf_client(client, self.spec)["status"], "fail")
        for stage, data in (("main-config", b"======== Main configuration: ========\nsystem_cachedir=/wrong\ncacheonly=none\n"),
                            ("cache-before", b'{"key_sha256":"wrong","candidate_cache_entries":0}'),
                            ("cache-after", json.dumps({"key_sha256": self.spec["expected_key_sha256"], "candidate_cache_entries": 1}).encode()),
                            ("presentation", b'{"FORCE_COLUMNS":"80","LC_ALL":"C","LANG":"C"}\n'),
                            ("dnf-version", b"dnf5 version 5.3.0\n"),
                            ("repo-config", b"x" * (dd.CONFIG_LIMIT + 1)), ("repo-config", b"\xff")):
            client = ProbeClient(self.spec); client.responses[stage] = receipt(out=data)
            self.assertEqual(dd.probe_dnf_client(client, self.spec)["status"], "fail")
        client = ProbeClient(self.spec); client.responses["dnf-version"] = receipt(127)
        self.assertEqual(dd.probe_dnf_client(client, self.spec)["status"], "unavailable")
        for image_receipt in (receipt(1), receipt(out=b"tag\n"), receipt(out=b"sha256:" + b"d" * 64 + b"\n"),
                              receipt(out=(client.image + "\n").encode(), err=b"unexpected")):
            client = ProbeClient(self.spec); client.image_receipt = image_receipt
            self.assertEqual(dd.probe_dnf_client(client, self.spec)["status"], "fail")

    def test_mutable_pages_tag_binds_actual_container_image_and_drift(self):
        client = ProbeClient(self.spec); client.image = "rs9-pages-fedora:fixture"
        client.image_receipt = receipt(out=b"sha256:" + b"c" * 64 + b"\n")
        first = dd.probe_dnf_client(client, self.spec)
        self.assertEqual(first["status"], "pass")
        control = ad.build_positive_control(family="dnf", image=client.image, platform=client.platform,
            product=PRODUCT, setup_sha256="e" * 64,
            receipts={s: receipt(stage=s) for s in ("configure", "refresh", "install", "query")},
            success=True, dnf_probe=first)
        self.assertTrue(ad.validate_positive_control(control, family="dnf", image=client.image,
            platform=client.platform, product=PRODUCT, setup_sha256="e" * 64, dnf_probe=first)[0])
        client.image_receipt = receipt(out=b"sha256:" + b"d" * 64 + b"\n")
        changed = dd.probe_dnf_client(client, self.spec)
        self.assertEqual(changed["status"], "pass")
        self.assertFalse(ad.validate_positive_control(control, family="dnf", image=client.image,
            platform=client.platform, product=PRODUCT, setup_sha256="e" * 64, dnf_probe=changed)[0])
        for field in ("key_sha256", "image_id", "tools", "configuration", "presentation", "version"):
            malformed = copy.deepcopy(first); malformed["identity"][field] = 123
            malformed["identity_sha256"] = digest(canonical(malformed["identity"]))
            self.assertFalse(dd.valid_identity(malformed))

    def test_positive_control_vetoes_full_stream_environment_errors(self):
        probe = self.probe()
        for stage in ('configure', 'refresh', 'install', 'query'):
            for stream in ('stdout', 'stderr'):
                for message in (b'Could not resolve host\n', b'Permission denied\n', b'No match for argument: fixture\n'):
                    receipts = {s: receipt(stage=s) for s in ('configure', 'refresh', 'install', 'query')}
                    raw = b'x' * 70000 + b'\n' + message
                    receipts[stage] = receipt(stage=stage, **{'out' if stream == 'stdout' else 'err': raw})
                    control = ad.build_positive_control(family='dnf', image=ProbeClient.image,
                        platform=ProbeClient.platform, product=PRODUCT, setup_sha256='e' * 64,
                        success=True, dnf_probe=probe, receipts=receipts)
                    self.assertFalse(control['success'], (stage, stream, message))

    def test_dnf_missing_package_remains_a_veto_with_signature_text(self):
        combined = repo_message() + b"No match for argument: " + PRODUCT.encode() + b"\n"
        self.assertEqual(ad.classify_rejection(receipt(1, err=combined), stage="refresh", family="dnf"), "PACKAGE_NOT_FOUND")
        self.assertEqual(ad.classify_rejection(receipt(1, err=combined), stage="refresh", family="apt"), "PACKAGE_NOT_FOUND")
        for text, category in ((b"No match for argument: fixture\n", "PACKAGE_NOT_FOUND"),
                               (repo_message("Signing key not found"), "KEY_MISMATCH"),
                               (repo_message("Public key is not installed."), "UNCLASSIFIED_FAILURE"),
                               (repo_message("Bad GPG signature"), "SIGNATURE_REJECTED"),
                               (b"repomd.xml XML parse error\n", "INDEX_CORRUPT"),
                               (b"Bad PGP signature\n", "UNCLASSIFIED_FAILURE"),
                               (b"Signing key not found\n", "UNCLASSIFIED_FAILURE"),
                               (b"Curl error (37): Couldn't read a file\n", "SOURCE_CONFIG_ERROR")):
            self.assertEqual(ad.classify_rejection(receipt(1, err=text), stage="refresh", family="dnf"), category)

    def test_dnf5_banner_dump_rejects_ambiguity_and_unreadable_required_values(self):
        original = ProbeClient(self.spec).responses["repo-config"].stdout_bytes
        for data in (original + original, original + b"optional_unset = value\n",
                     original.replace(b"skip_if_unavailable = 0", b"skip_if_unavailable"),
                     original.replace(b"pkg_gpgcheck = 1", b"pkg_gpgcheck"),
                     original.replace(b"enabled = 0", b"enabled"),
                     original.replace(b'"fedora" repository', b'"bad/repo" repository'),
                     b"[main]\nenabled = 1\n", b"enabled = 1\n" + original,
                     original + b"======== Unknown configuration: ========\n"):
            with self.subTest(data_sha256=digest(data)):
                client = ProbeClient(self.spec); client.responses["repo-config"] = receipt(out=data)
                self.assertEqual(dd.probe_dnf_client(client, self.spec)["status"], "fail")
        client = ProbeClient(self.spec)
        # An unreadable optional option is distinct from an empty value. Neither
        # provides a mirror source, and unrelated unset options are harmless.
        client.responses["repo-config"] = receipt(out=original.replace(b"metalink = ", b"metalink"))
        self.assertEqual(dd.probe_dnf_client(client, self.spec)["status"], "pass")

    def test_repository_bad_pgp_suffix_is_explicit_and_environment_veto_stays_first(self):
        for suffix in ("Verifying a signature failed", "x" * 70000):
            command = receipt(1, err=repo_message("Bad PGP signature: " + suffix))
            self.assertEqual(dd.classify_dnf(command, stage="refresh"), "SIGNATURE_REJECTED")
            for kind in ("signature", "index"):
                self.assertTrue(self.qualify(kind, refresh=command)[0])
        for reason in ("Bad PGP signature:", "Bad PGP signature suffix", "Public key is not installed."):
            command = receipt(1, err=repo_message(reason))
            self.assertEqual(dd.classify_dnf(command, stage="refresh"), "UNCLASSIFIED_FAILURE")
            self.assertFalse(self.qualify(refresh=command)[0])
        for suffix, category in (("Permission denied", "PERMISSION_DENIED"),
                                 ("Curl error (6): Could not resolve host", "NETWORK_UNAVAILABLE"),
                                 ("unknown option", "SOURCE_CONFIG_ERROR")):
            command = receipt(1, err=repo_message("Bad PGP signature: " + suffix))
            self.assertEqual(dd.classify_dnf(command, stage="refresh"), category)
            self.assertFalse(self.qualify(refresh=command)[0])

    def test_full_bytes_veto_beyond_preview_lines_and_bytes(self):
        for padding in (b"benign\n" * 100, b"x" * 70000 + b"\n"):
            for cause, category in ((b"Network is unreachable\n", "NETWORK_UNAVAILABLE"),
                                    (b"Permission denied\n", "PERMISSION_DENIED"),
                                    (b"unknown argument\n", "SOURCE_CONFIG_ERROR"),
                                    (b"https://unrelated.invalid\n", "NETWORK_UNAVAILABLE")):
                command = receipt(1, err=repo_message() + padding + cause)
                self.assertEqual(ad.classify_rejection(command, stage="refresh", family="dnf"), category)
                self.assertFalse(self.qualify(refresh=command)[0])
        for data in (b"x" * (dd.STREAM_LIMIT + 1) + repo_message(), b"\xff" + repo_message()):
            self.assertEqual(ad.classify_rejection(receipt(1, err=data), stage="refresh", family="dnf"), "UNCLASSIFIED_FAILURE")

    def test_package_checksum_exact_complete_stage_and_bound_digests(self):
        good = receipt(1, err=b"x\n" * 100 + checksum_message())
        self.assertEqual(ad.classify_rejection(good, family="dnf", stage="install"), "PACKAGE_HASH_MISMATCH")
        self.assertTrue(self.qualify("package", install=good)[0])
        self.assertIsNone(dd.package_checksum(good, stage="refresh"))
        for text in (b"arbitrary checksum mismatch\n", checksum_message(ORIGINAL, ORIGINAL),
                     checksum_message().replace(CHANGED.encode(), b"b" * 12),
                     checksum_message() + b"Network is unreachable\n", checksum_message().replace(PRODUCT.encode(), b"foreign-package"),
                     checksum_message() + checksum_message("c" * 64)):
            self.assertFalse(self.qualify("package", install=receipt(1, err=text))[0])
        context = self.context("package"); context["mutation"]["tampered_sha256"] = "c" * 64
        self.assertFalse(self.qualify("package", context=context)[0])
        self.assertFalse(self.qualify("package", refresh=receipt(1, err=repo_message()))[0])

    def test_positive_control_and_all_four_source_owned_negatives(self):
        for kind in ("package", "index", "signature", "wrongkey"):
            okay, category, reason, diagnostic = self.qualify(kind)
            self.assertTrue(okay, (kind, reason))
            self.assertEqual(category, {"package": "PACKAGE_HASH_MISMATCH", "index": "INDEX_CORRUPT",
                                        "signature": "SIGNATURE_REJECTED", "wrongkey": "KEY_MISMATCH"}[kind])
            if kind == "index": self.assertEqual(diagnostic["boundary_rejection_category"], "SIGNATURE_REJECTED")
            self.assertEqual(diagnostic["qualifying_stage"], "install" if kind == "package" else "refresh")
            if kind != "package":
                self.assertFalse(self.qualify(kind, refresh=receipt())[0])
                self.assertEqual(self.qualify(kind, refresh=receipt())[2], f"bypassed-{kind}-verification-on-refresh")
            for query in (receipt(2, err=b"rpmdb error"), receipt(1, out=b"wrong message"), receipt(1, err=b"permission denied")):
                self.assertEqual(self.qualify(kind, query=query)[2], "candidate-absence-unproven")
            context = self.context(kind); context["positive_identity_sha256"] = "f" * 64
            self.assertFalse(self.qualify(kind, context=context)[0])
            context = self.context(kind); context["mutation"]["verified"] = False
            self.assertFalse(self.qualify(kind, context=context)[0])
            context = self.context(kind); context["positive_control_valid"] = False
            self.assertFalse(self.qualify(kind, context=context)[0])
            self.assertEqual(self.qualify(kind, context={}, install=receipt())[2], "tampered-content-accepted")
            self.assertEqual(self.qualify(kind, context={}, query=receipt())[2], "tampered-content-accepted")
        self.assertFalse(self.qualify("wrongkey", refresh=receipt(1, err=repo_message()))[0])
        self.assertFalse(self.qualify("signature", refresh=receipt(1, err=repo_message("Signing key not found")))[0])

    def test_index_and_wrongkey_need_causal_provenance_as_well_as_boundary_rejection(self):
        context = self.context("index"); context["mutation"].pop("authentication_boundary")
        self.assertEqual(self.qualify("index", context=context)[2], "dnf-index-provenance-unproven")
        context = self.context("signature"); context["mutation"].pop("armor_framing_preserved")
        self.assertEqual(self.qualify("signature", context=context)[2], "dnf-signature-provenance-unproven")
        context = self.context("signature"); context["mutation"]["packet_changed_offset"] = -1
        self.assertEqual(self.qualify("signature", context=context)[2], "dnf-signature-provenance-unproven")
        for field, value in (("replacement_signature_verified", False), ("replacement_issuer", FINGERPRINT),
                             ("replacement_issuer", "invalid"), ("control_key_fingerprint", "C" * 40)):
            context = self.context("wrongkey"); context["mutation"][field] = value
            self.assertEqual(self.qualify("wrongkey", context=context)[2], "dnf-wrong-key-issuer-unproven")

    def test_positive_control_requires_matching_actual_identity(self):
        probe = self.probe()
        kwargs = dict(family="dnf", image=ProbeClient.image, platform=ProbeClient.platform, product=PRODUCT,
                      setup_sha256="e" * 64)
        control = ad.build_positive_control(**kwargs, success=True, dnf_probe=probe,
                      receipts={stage: receipt(stage=stage) for stage in ("configure", "refresh", "install", "query")})
        self.assertTrue(ad.validate_positive_control(control, **kwargs, dnf_probe=probe)[0])
        missing = ad.build_positive_control(**kwargs, success=True)
        self.assertFalse(ad.validate_positive_control(missing, **kwargs)[0])
        for field, value in (("key_sha256", "d" * 64), ("public_fingerprint", "B" * 40),
                             ("source_uri", "file:///elsewhere"), ("image_sha256", "d" * 64)):
            other = copy.deepcopy(probe); other["identity"][field] = value
            other["identity_sha256"] = digest(canonical(other["identity"]))
            self.assertFalse(ad.validate_positive_control(control, **kwargs, dnf_probe=other)[0])

    def test_stage_records_keep_original_stream_identity_and_safe_separate_samples(self):
        command = receipt(1, out=b"normal\n" * 100, err=repo_message() + b"/private/operator/location\n")
        row = dd.record_dnf_stage(stage="refresh", product=PRODUCT, arch="x86_64", receipt=command)
        self.assertEqual(row["stdout_sha256"], command.stdout_sha256)
        self.assertEqual(row["stderr_sha256"], command.stderr_sha256)
        self.assertEqual(row["stdout_bytes"], len(command.stdout_bytes))
        self.assertTrue(row["stdout_truncated"])
        self.assertTrue(row["decision_stream_complete"])
        self.assertIn("Bad PGP signature", row["stderr_sample"])
        self.assertNotIn("/private/operator", json.dumps(row))
        unsafe = dd.record_dnf_stage(stage="refresh", product=PRODUCT, arch="x86_64", receipt=receipt(1, err=b"token=secret-value"))
        self.assertNotIn("secret-value", json.dumps(unsafe))

    def make_repository(self):
        base = self.root / "rpm/fedora/43/x86_64"
        (base / "Packages").mkdir(parents=True)
        (base / "Packages" / (PRODUCT + "-0.6.1-1.fc43.x86_64.rpm")).write_bytes(b"synthetic RPM payload")
        (base / "repodata").mkdir()
        (base / "repodata/repomd.xml").write_bytes(b"<repomd/>\n")
        (base / "repodata/repomd.xml.asc").write_bytes(synthetic_armor())
        return self.root / "rpm"

    def test_index_signature_wrongkey_and_package_mutations_have_exact_provenance(self):
        source = self.make_repository()
        snapshot = dm._snapshot(source)
        for kind in hd.TAMPER_KINDS_ALL:
            dest = self.root / ("copy-" + kind); dest.mkdir()
            changed = hd.tamper_family_copy("dnf", kind, {"rpm": source}, dest, arch="x86_64", product=PRODUCT, wrong_signer=WrongSigner())["rpm"]
            record = dm.verify_dnf_mutation(source, changed, arch="x86_64", product=PRODUCT, kind=kind,
                                             wrong_signer=WrongSigner(), public_fingerprint=FINGERPRINT)
            self.assertTrue(record["verified"])
            self.assertEqual(record["kind"], kind)
            self.assertNotEqual(record["control_sha256"], record["tampered_sha256"])
            if kind == "index": self.assertEqual(record["authentication_boundary"], "repomd-signature")
            if kind == "signature": self.assertTrue(record["armor_framing_preserved"])
            if kind == "wrongkey":
                self.assertTrue(record["replacement_signature_verified"])
                self.assertNotEqual(record["control_key_fingerprint"], record["replacement_issuer"])
            (changed / "unexpected").write_bytes(b"unrelated")
            with self.assertRaises(ContractError): dm.verify_dnf_mutation(source, changed, arch="x86_64", product=PRODUCT, kind=kind)
        self.assertEqual(dm._snapshot(source), snapshot)

    def test_wrongkey_mutation_rejects_same_issuer_missing_verifier_and_invalid_signature(self):
        source = self.make_repository(); dest = self.root / "wrongkey-control"; dest.mkdir()
        changed = hd.tamper_family_copy("dnf", "wrongkey", {"rpm": source}, dest,
                    arch="x86_64", product=PRODUCT, wrong_signer=WrongSigner())["rpm"]
        class SameSigner(WrongSigner): primary_fingerprint = FINGERPRINT
        class InvalidSigner(WrongSigner):
            def verify(self, data, signature): return {"status": "invalid", "verified_issuer": self.primary_fingerprint}
        class OtherIssuer(WrongSigner):
            def verify(self, data, signature): return {"status": "valid", "verified_issuer": "C" * 40}
        for signer in (None, SameSigner(), InvalidSigner(), OtherIssuer()):
            with self.assertRaises(ContractError):
                dm.verify_dnf_mutation(source, changed, arch="x86_64", product=PRODUCT, kind="wrongkey",
                                       wrong_signer=signer, public_fingerprint=FINGERPRINT)

    def test_tamper_cycle_retains_all_four_stage_records_and_acceptance_survives_exception(self):
        source = self.make_repository()
        spec_for = lambda dirs: hd.dnf_spec(dirs["rpm"], self.root / "keys", "x86_64", public_fingerprint=FINGERPRINT)
        spec = spec_for({"rpm": source}); probe = dd.probe_dnf_client(ProbeClient(spec), spec)
        control = ad.build_positive_control(family="dnf", image=ProbeClient.image, platform=ProbeClient.platform, product=PRODUCT,
                  setup_sha256=ad.trust_identity(spec), success=True, dnf_probe=probe,
                  receipts={stage: receipt(stage=stage) for stage in ("configure", "refresh", "install", "query")})
        outer = self
        class Client(ProbeClient):
            def __init__(self, host, image, platform, mounts, family):
                self.host = host; self.kind = Path(mounts[0][0]).parent.name.removeprefix("tamper-dnf-")
                self.source = Path(mounts[0][0]); self.accept = False
                super().__init__(spec_for({"rpm": self.source}))
            def __enter__(self): return self
            def __exit__(self, *args): return None
            def exec(self, argv, **kwargs):
                if argv == self.spec["refresh"]:
                    r = receipt(0) if self.kind == "package" else receipt(1, err=repo_message("Signing key not found" if self.kind == "wrongkey" else "Bad PGP signature"))
                elif argv == self.spec["install"](PRODUCT):
                    if self.accept: return receipt()
                    m = dm.verify_dnf_mutation(source, self.source, arch="x86_64", product=PRODUCT, kind=self.kind,
                                               wrong_signer=WrongSigner(), public_fingerprint=FINGERPRINT)
                    r = receipt(1, err=checksum_message(m["tampered_sha256"], m["control_sha256"]) if self.kind == "package" else repo_message("Signing key not found" if self.kind == "wrongkey" else "Bad PGP signature"), stage="install")
                elif argv == self.spec["query"](PRODUCT):
                    if self.accept: raise ContractError("QUERY_FAILED", "synthetic query failure")
                    r = absent()
                elif argv in self.spec["configure"]: r = receipt()
                else: r = super().exec(argv, **kwargs)
                self.host.receipts.append(r)
                return r
        host = hd.RecordingRunner(None)
        with patch.object(hd, "ClientContainer", Client):
            rows = hd.tamper_cycle(host, spec_for, "dnf", {"rpm": source}, image=ProbeClient.image,
                   platform=ProbeClient.platform, product=PRODUCT, work=self.root, arch="x86_64",
                   wrong_signer=WrongSigner(), kinds=hd.TAMPER_KINDS_ALL, prefix="synthetic", positive_control=control)
        self.assertEqual([r["status"] for r in rows], ["pass"] * 4)
        for row in rows:
            self.assertEqual([r["stage"] for r in row["negative_receipts"]], ["configure", "refresh", "install", "query"])
            self.assertTrue(all("stderr_sample" in r and "stdout_bytes" in r for r in row["negative_receipts"]))
            self.assertTrue(row["mutation"]["verified"])
        self.assertNotIn("BEGIN PGP", json.dumps(rows))
        self.assertNotIn(str(self.root), json.dumps(rows))
        class AcceptingClient(Client):
            def __enter__(self): self.accept = True; return self
        work = self.root / "accepted"; work.mkdir()
        with patch.object(hd, "ClientContainer", AcceptingClient):
            row = hd.tamper_cycle(host, spec_for, "dnf", {"rpm": source}, image=ProbeClient.image,
                   platform=ProbeClient.platform, product=PRODUCT, work=work, arch="x86_64",
                   wrong_signer=WrongSigner(), kinds=["package"], prefix="synthetic", positive_control=None)[0]
        self.assertEqual(row["reason"], "tampered-content-accepted")

    def test_real_gnupg_signature_value_mutation_if_available(self):
        from rs9.signing_fixture import SigningFixture, find_gpg_binary
        binary = find_gpg_binary()
        if not binary: self.skipTest("GnuPG unavailable; native DNF remains unavailable independently")
        try: fixture = SigningFixture(gpg_binary=binary)
        except ContractError as error:
            if error.code == "GPG_AGENT_UNAVAILABLE": self.skipTest("GnuPG agent unavailable")
            raise
        with fixture:
            data = b"<repomd/>\n"
            path = self.root / "repomd.xml.asc"; path.write_bytes(fixture.detach_sign(data, armor=True))
            original = path.read_bytes()
            fixture.verify(data, original)
            dm.corrupt_dnf_signature(path)
            self.assertEqual(dm._signature_armor(original)[-1][:-1], dm._signature_armor(path.read_bytes())[-1][:-1])
            with self.assertRaises(ContractError): fixture.verify(data, path.read_bytes())
