import json
import subprocess
import unittest
from unittest.mock import Mock

from rs9.errors import ContractError
from rs9.hosted_pins import resolve_image


class PinTests(unittest.TestCase):
    def test_exact_architecture_digest_selected(self):
        doc = {"manifests": [{"digest": "sha256:" + "a" * 64, "platform": {"os": "linux", "architecture": "amd64"}},
                             {"digest": "sha256:" + "b" * 64, "platform": {"os": "linux", "architecture": "arm64"}}]}
        runner = Mock(return_value=subprocess.CompletedProcess([], 0, json.dumps(doc).encode(), b""))
        image = resolve_image("docker.io/library/ubuntu", "26.04", "arm64", runner)
        self.assertEqual(image, "docker.io/library/ubuntu@sha256:" + "b" * 64)

    def test_missing_architecture_and_transport_fail_closed(self):
        runner = Mock(return_value=subprocess.CompletedProcess([], 0, b'{"manifests":[]}', b""))
        with self.assertRaises(ContractError):
            resolve_image("registry.fedoraproject.org/fedora", "43", "aarch64", runner)

    def test_manifest_without_platform_proof_is_not_a_pin(self):
        runner = Mock(return_value=subprocess.CompletedProcess([], 0, b'{"schemaVersion":2,"config":{"digest":"sha256:unbound"}}', b""))
        with self.assertRaises(ContractError) as error:
            resolve_image("docker.io/library/ubuntu", "26.04", "arm64", runner)
        self.assertEqual(error.exception.code, "IMAGE_PLATFORM")
        runner.side_effect = subprocess.CalledProcessError(1, [])
        with self.assertRaises(subprocess.CalledProcessError):
            resolve_image("registry.fedoraproject.org/fedora", "43", "aarch64", runner)
