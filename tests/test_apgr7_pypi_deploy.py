"""Workflow deployment uses the owner identity before exposing a branch ref."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from rs9 import apgr7_pypi_deploy as deploy
from rs9.errors import ContractError


OWNER = {"name": "Samuel Leighton Lair", "email": "sam.lair@knowledge-forge.ai"}


class Journal:
    def unresolved(self, channel):
        return []

    def start(self, *args, **kwargs):
        pass

    def record_context(self, *args, **kwargs):
        pass

    def finish(self, *args, **kwargs):
        pass


class DeploymentIO:
    def __init__(self, altered_role=None, readback_role=None):
        self.requests = []
        self.altered_role = altered_role
        self.readback_role = readback_role
        self.commit = None

    def run(self, args):
        endpoint = args[args.index("--method") + 2] if "--method" in args else args[-1]
        document = None
        if "--input" in args:
            document = json.loads(Path(args[args.index("--input") + 1]).read_bytes())
        self.requests.append((endpoint, document))
        if endpoint.endswith("/git/trees"):
            result = {"sha": "b" * 40}
        elif endpoint.endswith("/git/commits"):
            self.commit = {"sha": "c" * 40, **{
                role: {**document.get(role, {}), "date": "2026-10-23T00:00:00Z"}
                for role in ("author", "committer")}}
            if self.altered_role:
                self.commit[self.altered_role] = {"name": "Release", "email": "release@example.invalid"}
            result = self.commit
        elif endpoint.endswith("/git/commits/" + "c" * 40):
            result = json.loads(json.dumps(self.commit))
            if self.readback_role:
                result[self.readback_role] = None
        else:
            result = {"object": {"sha": "c" * 40}}
        return {"returncode": 0, "stdout": json.dumps(result).encode()}


class WorkflowDeploymentIdentityTests(unittest.TestCase):
    def invoke(self, io):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            body = b"workflow"
            (root / "workflow.yml").write_bytes(body)
            closure = {"closure_sha256": "d" * 64, "files": [{
                "path": "workflow.yml", "size": len(body),
                "sha256": hashlib.sha256(body).hexdigest()}]}
            with patch.object(deploy, "readback_transitive_import_closure", return_value=closure), \
                 patch.object(deploy, "check_deployment_status", side_effect=[
                     {"deployment_state": "absent"}, {"deployment_state": "deployed-exact"}]), \
                 patch.object(deploy, "head", return_value=(
                     "a" * 40, {"commit": {"tree": {"sha": "e" * 40}}})):
                return deploy.deploy_workflow(io, root=root, execute=True, journal=Journal())

    def test_explicit_owner_both_roles_and_readback_precede_ref_update(self):
        io = DeploymentIO()
        self.assertTrue(self.invoke(io)["executed"])
        commit = next(document for endpoint, document in io.requests if endpoint.endswith("/git/commits"))
        for role in ("author", "committer"):
            self.assertEqual(commit[role], OWNER)
        endpoints = [endpoint for endpoint, _ in io.requests]
        read = next(i for i, endpoint in enumerate(endpoints) if endpoint.endswith("/git/commits/" + "c" * 40))
        write = next(i for i, endpoint in enumerate(endpoints) if endpoint.endswith("/git/refs/heads/main"))
        self.assertLess(read, write)

    def test_wrong_author_or_committer_blocks_ref_update(self):
        for role in ("author", "committer"):
            with self.subTest(role=role):
                io = DeploymentIO(role)
                with self.assertRaises(ContractError) as raised:
                    self.invoke(io)
                self.assertEqual(raised.exception.code, "APGR7_DEPLOY_IDENTITY")
                self.assertFalse(any(endpoint.endswith("/git/refs/heads/main") for endpoint, _ in io.requests))


    def test_good_creation_response_does_not_override_bad_readback(self):
        for role in ("author", "committer"):
            with self.subTest(role=role):
                io = DeploymentIO(readback_role=role)
                with self.assertRaises(ContractError) as raised:
                    self.invoke(io)
                self.assertEqual(raised.exception.code, "APGR7_DEPLOY_IDENTITY")
                self.assertEqual({key: io.commit[role][key] for key in OWNER}, OWNER)
                self.assertFalse(any(endpoint.endswith("/git/refs/heads/main") for endpoint, _ in io.requests))


if __name__ == "__main__":
    unittest.main()
