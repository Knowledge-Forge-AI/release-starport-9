"""Real-byte readback contracts, exercised with bounded public transport fixtures."""
import base64
import hashlib
import io
import tarfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

from rs9.readers import read_npm, read_signed_repo
from rs9.scratch import canonical
from rs9.signed_store import PRODUCTION_PRIMARY_FINGERPRINT, PRODUCTION_SIGNING_SUBKEY


class ExactReadbackTests(unittest.TestCase):
    def signed_observation(self, object_bytes, *, issuer=PRODUCTION_SIGNING_SUBKEY):
        index, expected_object = b"signed fixture index", b"fixture package bytes"
        hashes = {"apt/InRelease": hashlib.sha256(index).hexdigest(),
                  "apt/pool/package.deb": hashlib.sha256(expected_object).hexdigest()}
        verifier = lambda value: {"status": "valid", "primary_key_id": PRODUCTION_PRIMARY_FINGERPRINT,
                                  "verified_issuer": issuer}
        with patch("rs9.readers._get", side_effect=[index, object_bytes]) as get:
            observation = read_signed_repo("fixture-project", base_url="https://rs9.knowledge-forge.ai",
                index_path="apt/InRelease", verifier=verifier,
                index_parser=lambda value: {"apt/pool/package.deb": hashes["apt/pool/package.deb"]},
                desired_identity="b" * 64, expected_hashes=hashes)
        return observation, get.call_count

    def test_signed_index_requires_actual_object_and_pinned_issuer(self):
        exact, count = self.signed_observation(b"fixture package bytes")
        self.assertEqual(exact["state"], "exact")
        self.assertEqual(count, 2)
        tampered, _ = self.signed_observation(b"tampered")
        self.assertEqual(tampered["state"], "unknown")
        foreign, count = self.signed_observation(b"fixture package bytes", issuer="1" * 40)
        self.assertEqual(foreign["state"], "unknown")
        self.assertEqual(count, 1)

    def test_object_download_404_is_unknown(self):
        url = "https://rs9.knowledge-forge.ai/apt/pool/package.deb"
        observation, _ = self.signed_observation(HTTPError(url, 404, "Not Found", {}, None))
        self.assertEqual(observation["state"], "unknown")
        self.assertNotEqual(observation["readback"]["presence"], "absent")

    def test_npm_exact_reads_packaged_metadata_and_tarball_bytes(self):
        package = {"name": "fixture-package", "version": "1.0.0", "license": "AGPL-3.0-or-later", "bin": {"fixture": "bin/main.mjs"}}
        metadata = canonical(package)
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            member = tarfile.TarInfo("package/package.json")
            member.size = len(metadata)
            archive.addfile(member, io.BytesIO(metadata))
        payload = buffer.getvalue()
        integrity = "sha512-" + base64.b64encode(hashlib.sha512(payload).digest()).decode()
        registry = {"name": package["name"], "versions": {"1.0.0": {**package, "dist": {
            "integrity": integrity, "tarball": "https://registry.npmjs.org/fixture-package/-/fixture-package-1.0.0.tgz"}}}}
        for body, expected_state in ((payload, "exact"), (b"changed", "conflict")):
            with patch("rs9.readers._get", side_effect=[canonical(registry), body]) as get:
                observation = read_npm("fixture-package", "1.0.0", expected_integrity=integrity,
                    expected_license=package["license"], expected_commands=package["bin"],
                    expected_hashes={"fixture-package-1.0.0.tgz": hashlib.sha256(payload).hexdigest()})
            self.assertEqual(observation["state"], expected_state)
            self.assertEqual(get.call_count, 2)

    def test_npm_normalized_commands_preserve_exact_payload_proof(self):
        for raw_bin, normalized in (("./bin/main.mjs", {"fixture-package": "bin/main.mjs"}),
                                    ({"fixture": "./bin/main.mjs"}, {"fixture": "bin/main.mjs"})):
            with self.subTest(raw_bin=raw_bin):
                package = {"name": "fixture-package", "version": "1.0.0", "license": "MIT", "bin": raw_bin}
                metadata = canonical(package)
                buffer = io.BytesIO()
                with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
                    member = tarfile.TarInfo("package/package.json")
                    member.size = len(metadata)
                    archive.addfile(member, io.BytesIO(metadata))
                payload = buffer.getvalue()
                integrity = "sha512-" + base64.b64encode(hashlib.sha512(payload).digest()).decode()
                url = "https://registry.npmjs.org/fixture-package/-/fixture-package-1.0.0.tgz"
                registry = {"name": package["name"], "versions": {"1.0.0": {
                    **package, "bin": normalized, "dist": {"integrity": integrity, "tarball": url}}}}
                with patch("rs9.readers._get", side_effect=[canonical(registry), payload]):
                    observation = read_npm("fixture-package", "1.0.0", expected_integrity=integrity,
                        expected_license="MIT", expected_commands=normalized,
                        expected_hashes={"fixture-package-1.0.0.tgz": hashlib.sha256(payload).hexdigest()})
                self.assertEqual(observation["state"], "exact")

                registry["versions"]["1.0.0"]["bin"] = {"other": "bin/main.mjs"}
                with patch("rs9.readers._get", side_effect=[canonical(registry), payload]):
                    observation = read_npm("fixture-package", "1.0.0", expected_integrity=integrity,
                        expected_license="MIT", expected_commands=normalized,
                        expected_hashes={"fixture-package-1.0.0.tgz": hashlib.sha256(payload).hexdigest()})
                self.assertEqual(observation["state"], "conflict")

    def test_signed_repo_error_without_url_does_not_prove_absence(self):
        error = HTTPError("https://other.example.com/InRelease", 404, "Not Found", {}, None)
        del error.url
        with patch("rs9.readers._get", side_effect=error):
            observation = read_signed_repo("fixture-project", base_url="https://rs9.knowledge-forge.ai",
                                           index_path="apt/InRelease")
        self.assertEqual(observation["state"], "unknown")


if __name__ == "__main__":
    unittest.main()
