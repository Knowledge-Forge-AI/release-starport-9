"""Explicitly redacted run-13 display replays; these are not native receipts."""
from __future__ import annotations
import copy
import json
from pathlib import Path
import unittest

from rs9 import dnf_diagnostics as dd
from rs9.build_native import CommandReceipt
from rs9.release_core import digest
from rs9.scratch import canonical

PRODUCT = "theme-forge-stellar-burst"
FIXTURES = Path(__file__).parent / "fixtures/run13-dnf-display.json"


def receipt(stage="refresh", code=0, out="", err="", executed=True):
    return CommandReceipt(dd.stage_command(stage, PRODUCT) if stage in {"refresh", "install"} else ["rpm", "-q", PRODUCT],
                          code, out.encode(), err.encode(), executed=executed)


def make_valid_probe(arch="x86_64", fingerprint=None):
    fp = fingerprint or ("DDAFB2F6902280CB1DA5AACE323E71369379D13B" if arch == "x86_64" else "859F9995995DB0258A49060B019C516C1B9C2140")
    image = "sha256:" + "d" * 64
    identity = {"repo_id": dd.DNF_REPO_ID, "source_uri": f"file:///srv/rs9/rpm/fedora/43/{arch}",
                "key_uri": dd.KEY_URI, "key_sha256": "c" * 64, "public_fingerprint": fp,
                "image_id": image, "image_sha256": digest(image.encode()), "image_reference_sha256": digest(image.encode()),
                "platform": "linux/amd64" if arch == "x86_64" else "linux/arm64",
                "presentation": dict(dd.DNF_PRESENTATION), "commands": dd.command_identities(), "version": dd.DNF_VERSION,
                "configuration": {"enabled_repositories": [dd.DNF_REPO_ID], "gpgcheck": True, "repo_gpgcheck": True,
                                  "skip_if_unavailable": False, "system_cachedir": dd.CACHE_ROOT, "cacheonly": "none", "locale": "C"},
                "tools": {"dnf-version": {"stdout_sha256": "a" * 64, "version": "dnf5 version " + dd.DNF_VERSION},
                          "rpm-version": {"stdout_sha256": "b" * 64, "version": "RPM version 6.0.2"}}}
    return {"status": "pass", "identity": identity, "identity_sha256": digest(canonical(identity))}


def rebind_display(row, probe):
    """Replace each display token with a controlled URI for grammar tests only.

    Production rejects literal tokens. No original stream or receipt identity is
    recreated, and the historical checksum prefixes are never extended.
    """
    text = row["stderr_sample"]
    lines = []
    for line in text.splitlines(keepends=True):
        if line.lstrip().startswith("From"):
            line = line.replace("file:[PATH]", probe["identity"]["key_uri"])
        elif "baseurl:" in line:
            line = line.replace("file:[PATH]", probe["identity"]["source_uri"])
        lines.append(line)
    return "".join(lines)


class DnfRun13DiagnosticsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = json.loads(FIXTURES.read_text())

    def context(self, row):
        from rs9.apt_diagnostics import build_positive_control, validate_positive_control
        probe = make_valid_probe(row["arch"], row["fingerprint"])
        self.assertTrue(dd.valid_identity(probe))
        identity = probe["identity"]
        control = build_positive_control(family="dnf", image=identity["image_id"], platform=identity["platform"],
            product=PRODUCT, setup_sha256="f" * 64, success=True, dnf_probe=probe,
            receipts={stage: receipt(stage) for stage in ("configure", "refresh", "install", "query")})
        valid, reason = validate_positive_control(control, family="dnf", image=identity["image_id"],
            platform=identity["platform"], product=PRODUCT, setup_sha256="f" * 64, dnf_probe=probe)
        self.assertTrue(valid, reason)
        return {"arch": row["arch"], "product": PRODUCT, "probe": probe, "positive_control_valid": valid,
                "positive_identity_sha256": probe["identity_sha256"], "mutation": copy.deepcopy(row["mutation"])}

    def qualify(self, row, text=None, context=None, refresh_code=None, install_text=None):
        context = context or self.context(row)
        text = rebind_display(row, context["probe"]) if text is None else text
        package = row["kind"] == "package"
        refresh = receipt(code=(0 if package else 1) if refresh_code is None else refresh_code,
                          err="" if package else text)
        install = receipt("install", 1, err=text if install_text is None else install_text)
        query = receipt("query", 1, out=f"package {PRODUCT} is not installed\n")
        return dd.qualify_dnf(row["kind"], refresh, install, query, configure=receipt(), context=context)

    def test_fixture_scope_and_presentation(self):
        self.assertEqual(len(self.rows), 8)
        self.assertEqual({(r["arch"], r["kind"]) for r in self.rows},
                         {(a, k) for a in ("x86_64", "aarch64") for k in ("package", "index", "signature", "wrongkey")})
        self.assertEqual(dd.DNF_PRESENTATION, {"FORCE_COLUMNS": "512", "LC_ALL": "C", "LANG": "C", "DNF5_FORCE_INTERACTIVE": "0"})
        for row in self.rows:
            self.assertEqual(row["fixture_kind"], "redacted-run13-display")
            self.assertFalse(row["original_stream_bytes"])
            self.assertNotIn("/" + "Users/", json.dumps(row))
            self.assertNotIn("receipts", row)

    def test_both_architectures_terminal_categories_and_bootstrap_are_retained(self):
        for row in self.rows:
            if row["kind"] == "package":
                continue
            with self.subTest(arch=row["arch"], kind=row["kind"]):
                okay, category, reason, diag = self.qualify(row)
                self.assertTrue(okay, reason)
                self.assertEqual(category, {"index": "INDEX_CORRUPT", "signature": "SIGNATURE_REJECTED", "wrongkey": "KEY_MISMATCH"}[row["kind"]])
                self.assertEqual(diag["bootstrap_categories"], ["KEY_MISMATCH"])
                self.assertEqual(diag["rejection_sequence"][0], {"phase": "bootstrap", "category": "KEY_MISMATCH"})
                self.assertEqual(diag["rejection_sequence"][1]["fingerprint"], row["fingerprint"])

    def test_literal_redacted_uri_cannot_qualify_native_evidence(self):
        for row in self.rows:
            if row["kind"] != "package":
                self.assertFalse(self.qualify(row, row["stderr_sample"])[0])

    def test_original_clipped_package_samples_remain_unqualified(self):
        for row in self.rows:
            if row["kind"] == "package":
                self.assertTrue(row["fixed_unqualified"])
                self.assertFalse(self.qualify(row)[0])
                self.assertIsNone(dd.package_checksum(receipt("install", 1, err=row["stderr_sample"]), stage="install"))

    def test_terminal_adverse_sequences_after_64kib(self):
        row = next(r for r in self.rows if r["kind"] == "signature" and r["arch"] == "x86_64")
        context = self.context(row)
        text = rebind_display(row, context["probe"])
        fatal = text.splitlines(keepends=True)[-1]
        header = next(line for line in text.splitlines(keepends=True) if line.startswith("Importing"))
        variants = {
            "fingerprint": text.replace(row["fingerprint"], "F" * 40),
            "issuer": text.replace(header, "Issuer: unexpected\n" + header),
            "second-repo": text.replace('repository "rs9-fedora-nonproduction"', 'repository "other-repo"'),
            "second-repo-progress": 'repository "other-repo"\n' + text,
            "duplicate-summary": text + fatal,
            "contradictory-summary": text + fatal.replace("Bad PGP signature", "Signing key not found"),
            "unbound-uri": text.replace(context["probe"]["identity"]["source_uri"], "file:///srv/foreign"),
            "missing-fatal": text.removesuffix(fatal),
            "unknown-terminal": text.replace("Bad PGP signature", "Unknown verification error"),
            "double-import": text.replace("The key was successfully imported.\n", "The key was successfully imported.\n" + header),
            "missing-import-success": text.replace("The key was successfully imported.\n", ""),
            "key-header": text.replace(header, "Importing OpenPGP key 0xFFFFFFFF:\n"),
            "truncated-final-line": text.rstrip("\n"),
        }
        for name, bad in variants.items():
            with self.subTest(name=name):
                self.assertFalse(self.qualify(row, "x" * 70000 + "\n" + bad)[0])
        for veto in ("Permission denied", "Could not resolve host", "No match for argument: " + PRODUCT, "Skipping repository other", "Issuer: unexpected"):
            bad = text.replace(fatal, "x" * 70000 + "\n" + veto + "\n" + fatal)
            self.assertFalse(self.qualify(row, bad)[0], veto)
        valid = receipt(code=1, out="x" * 70000 + "\nSigning key not found\n", err=text)
        self.assertIsNone(dd.parse_repository_rejection(valid, stage="refresh", context=context))

    def test_positive_identity_stage_and_mutation_proofs_are_required(self):
        row = next(r for r in self.rows if r["kind"] == "signature")
        for field, value in (("positive_control_valid", False), ("positive_identity_sha256", "f" * 64)):
            context = self.context(row); context[field] = value
            self.assertFalse(self.qualify(row, context=context)[0])
        for field in ("armor_framing_preserved", "packet_changed_offset", "packet_length"):
            context = self.context(row); del context["mutation"][field]
            self.assertFalse(self.qualify(row, context=context)[0])
        self.assertFalse(self.qualify(row, refresh_code=0)[0])
        for field, value in (("version", "5.2.19.0"), ("presentation", {"LC_ALL": "C"}), ("commands", {})):
            context = self.context(row)
            context["probe"]["identity"][field] = value
            context["probe"]["identity_sha256"] = digest(canonical(context["probe"]["identity"]))
            context["positive_identity_sha256"] = context["probe"]["identity_sha256"]
            self.assertFalse(self.qualify(row, context=context)[0])
        context = self.context(row)
        text = rebind_display(row, context["probe"])
        wrong = receipt(code=1, err=text); wrong.command = ["dnf", "makecache"]
        self.assertIsNone(dd.parse_repository_rejection(wrong, stage="refresh", context=context))

    def test_full_checksum_same_install_path_and_adverse_cases(self):
        for row in (r for r in self.rows if r["kind"] == "package"):
            mutation = row["mutation"]
            path = mutation["target"].split("/", 3)[-1]
            full = ("Downloading successful, but checksum doesn't match. Calculated: " + mutation["tampered_sha256"]
                    + "(sha256)  Expected: " + mutation["control_sha256"] + "(sha256)\n"
                    + " Librepo error: Cannot download " + path + ": All mirrors were tried\n")
            self.assertTrue(self.qualify(row, full)[0])
            wrong_arch = "aarch64" if row["arch"] == "x86_64" else "x86_64"
            variants = [full.replace("(sha256)", "(sha512)"), full.replace(mutation["tampered_sha256"], mutation["tampered_sha256"][:12]),
                        full.split(" Expected:")[0] + "\n", full + full,
                        full.replace(path, Path(path).name), full.replace(path, "/cache/" + path),
                        full.replace(path, "file:///srv/foreign/" + path), full.replace(PRODUCT, "different-package"),
                        full.replace("." + row["arch"] + ".rpm", "." + wrong_arch + ".rpm"), full.rstrip("\n"),
                        full + "Downloading successful, but checksum doesn't match. Calculated: 123\n"]
            for bad in variants:
                self.assertFalse(self.qualify(row, bad)[0])
            for veto in ("Permission denied", "Could not resolve host", "No match for argument: " + PRODUCT):
                self.assertFalse(self.qualify(row, full + "x" * 70000 + "\n" + veto + "\n")[0])
            context = self.context(row); context["positive_control_valid"] = False
            self.assertFalse(self.qualify(row, full, context)[0])
            self.assertFalse(self.qualify(row, full, refresh_code=1)[0])


if __name__ == "__main__":
    unittest.main()
