"""Offline client preparation with external command doubles, never native qualification."""
import copy
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

from rs9.build_native import CommandReceipt
from rs9.errors import ContractError
from rs9.rpm_client_runtime import (CLIENT_PACKAGES, prepare_client, validate_runtime_evidence,
                                    verify_client_image, source_base_ref, bind_engine_floors)


IMAGE = "sha256:" + "b" * 64
ENVIRONMENT = {"platform": "linux/amd64", "source_pinned": True,
               "image_ref": source_base_ref("x86_64"),
               "preprovisioned_packages": [p for p in CLIENT_PACKAGES
                                           if p not in {"xorg-x11-server-Xvfb", "dbus-daemon", "python3"}]}


class ClientHost:
    def __init__(self, *, version="22.23.0", epoch="1", owner="nodejs22", failure=None):
        self.version, self.epoch, self.owner, self.failure = version, epoch, owner, failure
        self.calls = []
        self.image = IMAGE

    def run(self, command, **kwargs):
        self.calls.append(command)
        out, err, exit_code, executed = b"", b"", 0, True
        if command[1:3] == ["image", "inspect"]:
            out = (self.image + "|amd64\n").encode()
        if "-qf" in command:
            if self.failure == "timeout":
                raise ContractError("TOOL_TIMEOUT", "Controlled test timeout")
            out = f"{self.owner}|{self.epoch}|{self.version}|1.fc43|x86_64\n".encode()
            if self.failure == "failed": exit_code = 1
            if self.failure == "unexecuted": executed = False
            if self.failure == "stderr": err = b"unexpected diagnostic"
            if self.failure == "wrong-arch": out = out.replace(b"x86_64", b"aarch64")
        elif "/usr/bin/node" in command and "--version" in command:
            out = f"v{self.version}\n".encode()
        if self.failure == "cleanup" and command[1:3] == ["rm", "-f"] and command[-1].startswith("rs9-nodeprobe-"):
            exit_code = 1
        return CommandReceipt(command, exit_code, out, err, executed=executed)


class ClientRuntimeTests(unittest.TestCase):
    def test_nebular_preserved_executable_floor_binds_to_actual_prepared_client(self):
        from rs9.nebular_callers import FLOOR_MEMBER, FLOOR_SHA256
        from tests.test_build_native import fixture_evidence, authenticate_release, selection_for_intent, authorize_fixture_configuration
        metadata = json.loads((Path(__file__).parent / 'fixtures/nebular-0.6.1/caller-payload-members.json').read_bytes())['loom:package/package.json']
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            intent = fixture_evidence(root, extra_linux=[
                (FLOOR_MEMBER.removeprefix('/usr/lib/'), metadata['content'].encode(), 0o644, tarfile.REGTYPE, '')])
            capture = authenticate_release(selection_for_intent(intent), root)
            authorize_fixture_configuration(root, intent, capture)
            for version, status in (('22.23.0', 'pass'), ('20.19.0', 'fail')):
                _, evidence = self.prepare(ClientHost(version=version))
                bound = bind_engine_floors(evidence, [(capture, intent, {})])
                self.assertEqual(bound['status'], status, bound)
                self.assertEqual(bound['engine_constraints'][0]['source_sha256'], FLOOR_SHA256)
                self.assertEqual(bound['engine_constraints'][0]['purpose'], 'preserved-executable-rpm-requires')

    def prepare(self, host=None):
        host = host or ClientHost()
        return host, prepare_client(host, ENVIRONMENT, arch="x86_64", system="x86_64-linux", tag="test-client")

    def test_versioned_owner_epoch_and_language_probe_use_inspected_image(self):
        host, evidence = self.prepare()
        self.assertEqual(evidence["status"], "pass")
        self.assertTrue(validate_runtime_evidence(evidence, system="x86_64-linux", arch="x86_64", floor=">=22"))
        self.assertEqual(evidence["rpm_query"]["identity"]["name"], "nodejs22")
        self.assertEqual(evidence["rpm_query"]["identity"]["epoch"], "1")
        probes = [c for c in host.calls if "-qf" in c or "/usr/bin/node" in c and "--version" in c]
        self.assertEqual(len(probes), 2)
        for command in probes:
            self.assertIn(IMAGE, command)
            self.assertEqual(command[command.index("--network") + 1], "none")
        self.assertLess(next(i for i,c in enumerate(host.calls) if c[1] == "commit"),
                        next(i for i,c in enumerate(host.calls) if "-qf" in c))
        self.assertEqual(verify_client_image(host, "test-client", evidence, environment=ENVIRONMENT,
                                            arch="x86_64", system="x86_64-linux"), IMAGE)

    def test_probe_failure_or_missing_execution_blocks_and_cleans(self):
        for failure in ("failed", "unexecuted", "stderr", "wrong-arch", "timeout", "cleanup"):
            with self.subTest(failure=failure):
                host, evidence = self.prepare(ClientHost(failure=failure))
                self.assertEqual(evidence["status"], "fail")
                self.assertFalse(validate_runtime_evidence(evidence, system="x86_64-linux", arch="x86_64", floor=">=22"))
                self.assertTrue(any(c[1:3] == ["rm", "-f"] and c[-1].startswith("rs9-nodeprobe-") for c in host.calls))

    def test_higher_epoch_does_not_mask_language_floor(self):
        _, evidence = self.prepare(ClientHost(version="20.19.0", epoch="9"))
        self.assertEqual(evidence["status"], "pass")
        self.assertFalse(validate_runtime_evidence(evidence, system="x86_64-linux", arch="x86_64", floor=">=22"))

    def test_wrong_binding_absent_probe_and_unparseable_floor(self):
        _, good = self.prepare()
        for key, value in (("rpm_query", {}), ("node_version", {}), ("arch", "aarch64"),
                           ("system", "aarch64-linux"), ("profile_sha256", "c" * 64),
                           ("preparation_source_sha256", "c" * 64),
                           ("derived_image_id", "sha256:" + "c" * 64), ("base_source_pinned", False)):
            with self.subTest(key=key):
                evidence = copy.deepcopy(good); evidence[key] = value
                self.assertFalse(validate_runtime_evidence(evidence, system="x86_64-linux", arch="x86_64", floor=">=22"))
        for floor in (">=22 || >=20", "^22", ">=22.0.0.1", None):
            self.assertFalse(validate_runtime_evidence(good, system="x86_64-linux", arch="x86_64", floor=floor))

    def test_tag_drift_profile_and_source_drift_cannot_reuse_probe(self):
        host, evidence = self.prepare()
        host.image = "sha256:" + "c" * 64
        with self.assertRaises(ContractError) as caught:
            verify_client_image(host, "test-client", evidence, environment=ENVIRONMENT, arch="x86_64", system="x86_64-linux")
        self.assertEqual(caught.exception.code, "CLIENT_IMAGE_DRIFT")
        for key, value in (("image_ref", "other@sha256:" + "a" * 64), ("source_pinned", False),
                           ("preprovisioned_packages", ["nodejs"]), ("platform", "linux/arm64")):
            env = dict(ENVIRONMENT); env[key] = value
            with self.subTest(key=key), self.assertRaises(ContractError):
                verify_client_image(ClientHost(), "test-client", evidence, environment=env, arch="x86_64", system="x86_64-linux")


if __name__ == "__main__":
    unittest.main()
