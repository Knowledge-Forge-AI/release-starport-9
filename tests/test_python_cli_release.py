from contextlib import redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import stat
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from rs9.errors import ContractError
from rs9.python_cli_release import inspect_python_cli_release, main
from rs9.release_core import digest
from rs9.wheel import format_record
from tests.shadow_fixtures import tar_bytes


REPOSITORY = "Example/example-cli"
STEM = "example_cli-1.2.3"
DIST_INFO = STEM + ".dist-info"
WHEEL = STEM + "-py3-none-any.whl"
SDIST = STEM + ".tar.gz"
METADATA = (b"Metadata-Version: 2.5\nName: example-cli\nVersion: 1.2.3\nRequires-Python: >=3.11\n"
            b"License-Expression: MIT\nLicense-File: LICENSE\nLicense-File: NOTICE\n"
            b"License-File: COMMERCIAL-LICENSE.md\n")
PROJECT = (b'[project]\nname = "example-cli"\nversion = "1.2.3"\nrequires-python = ">=3.11"\n'
           b'license = "MIT"\nlicense-files = ["LICENSE", "NOTICE", "COMMERCIAL-LICENSE.md"]\n'
           b'dependencies = []\n[project.scripts]\nexample = "example.cli:main"\n')


def write_evidence(root, *, new_metadata=b"", pyproject=PROJECT, different_source=False, bad_record=False):
    licenses = {name: b"Synthetic license fixture.\n" for name in ("LICENSE", "NOTICE", "COMMERCIAL-LICENSE.md")}
    source = {"pyproject.toml": PROJECT, **licenses}
    package = {"example/__init__.py": b"", "example/cli.py": b"def main(): return 0\n"}
    info = {"METADATA": METADATA + new_metadata,
            "WHEEL": b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
            "entry_points.txt": b"[console_scripts]\nexample=example.cli:main\n",
            **{"licenses/" + name: body for name, body in licenses.items()}}
    wheel_files = {**package, **{DIST_INFO + "/" + name: body for name, body in info.items()}}
    wheel_files[DIST_INFO + "/RECORD"] = b"invalid record\n" if bad_record else format_record(wheel_files, DIST_INFO)
    wheel_body = io.BytesIO()
    with zipfile.ZipFile(wheel_body, "w") as archive:
        for path, body in wheel_files.items():
            member = zipfile.ZipInfo(path)
            member.create_system = 3
            member.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(member, body)
    if different_source:
        package["example/cli.py"] = b"def main(): return 1\n"
    sdist_files = {"pyproject.toml": pyproject, "PKG-INFO": info["METADATA"], **licenses,
                   **{"src/" + name: body for name, body in package.items()}}
    sdist_body = tar_bytes([(STEM + "/" + path, body, 0o644, tarfile.REGTYPE, "")
                            for path, body in sdist_files.items()])
    assets = {WHEEL: wheel_body.getvalue(), SDIST: sdist_body}
    assets["SHA256SUMS"] = "".join(digest(body) + "  " + name + "\n" for name, body in assets.items()).encode()
    api = {
        "repository": {"id": 11, "full_name": REPOSITORY},
        "ref": {"ref": "refs/tags/v1.2.3", "object": {"type": "commit", "sha": "a" * 40}},
        "tags": [], "commit": {"sha": "a" * 40, "tree": {"sha": "b" * 40}},
        "tree": {"sha": "b" * 40, "truncated": False, "tree": [
            {"path": path, "type": "blob", "mode": "100644",
             "sha": hashlib.sha1(b"blob " + str(len(body)).encode() + b"\0" + body).hexdigest()}
            for path, body in source.items()]},
        "release": {"id": 22, "tag_name": "v1.2.3", "target_commitish": "a" * 40, "draft": False,
                    "prerelease": False, "assets": [
                        {"name": name, "size": len(body), "id": index, "state": "uploaded", "digest": "sha256:" + digest(body)}
                        for index, (name, body) in enumerate(assets.items(), 1)]},
    }
    for folder, contents in (("source", source), ("assets", assets),
                             ("api", {name + ".json": json.dumps(value).encode() for name, value in api.items()})):
        (root / folder).mkdir()
        for path, body in contents.items():
            (root / folder / path).write_bytes(body)


class PythonCliReleaseTests(unittest.TestCase):
    def fixture(self, **kwargs):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        write_evidence(root, **kwargs)
        return root

    def inspect(self, root):
        return inspect_python_cli_release(REPOSITORY, "1.2.3", "example-cli", "example", root)

    def test_inspect_admits_an_independent_pure_python_cli_through_normal_entrypoint(self):
        root = self.fixture()
        stream = io.StringIO()
        with redirect_stdout(stream):
            exit_code = main([REPOSITORY, "--version", "1.2.3",
                              "--distribution", "example-cli", "--command", "example", "--evidence", str(root)])
        self.assertEqual(exit_code, 0)
        envelope = json.loads(stream.getvalue())
        self.assertTrue(envelope["ok"])
        self.assertEqual(envelope["result"]["entryPoint"], "example.cli:main")
        self.assertEqual(envelope["result"]["packageMembers"], 2)
        self.assertEqual(envelope["result"]["wheelSha256"], digest((root / "assets" / WHEEL).read_bytes()))

    def test_changed_wheel_transport_is_refused(self):
        root = self.fixture()
        wheel = root / "assets" / WHEEL
        content = wheel.read_bytes()
        wheel.write_bytes(bytes([content[0] ^ 1]) + content[1:])
        with self.assertRaisesRegex(ContractError, "DIGEST_MISMATCH"):
            self.inspect(root)

    def test_capture_collects_the_same_release_coordinates_and_verifies_the_bytes(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        target = Path(temporary.name).resolve() / "capture"

        def provide(selection, output, *, asset_transport):
            self.assertEqual(selection["repository"], REPOSITORY)
            self.assertEqual(selection["tag"], "v1.2.3")
            self.assertEqual(selection["payload_assets"][0]["name"], SDIST)
            self.assertEqual(selection["evidence_assets"][0]["name"], WHEEL)
            self.assertEqual(asset_transport, "release-api")
            self.assertEqual(output, target)
            self.assertTrue(output.is_dir())
            self.assertEqual(list(output.iterdir()), [])
            write_evidence(output)

        with patch("rs9.python_cli_release.capture_release", side_effect=provide):
            fresh = inspect_python_cli_release(REPOSITORY, "1.2.3", "example-cli", "example", target, fresh_capture=True)
        self.assertEqual(fresh, self.inspect(target))

    def test_fresh_capture_refuses_a_preexisting_directory_before_network(self):
        evidence = self.fixture()
        with patch("rs9.python_cli_release.capture_release") as capture:
            with self.assertRaisesRegex(ContractError, "PYTHON_CLI_CAPTURE_EXISTS"):
                inspect_python_cli_release(REPOSITORY, "1.2.3", "example-cli", "example", evidence, fresh_capture=True)
            capture.assert_not_called()

    def test_dependency_record_payload_and_source_must_match_the_profile(self):
        cases = (({"new_metadata": b"Requires-Dist: different-dependency\n"}, "PYTHON_CLI_METADATA"),
                 ({"bad_record": True}, "PYTHON_CLI_ARCHIVE"),
                 ({"different_source": True}, "PYTHON_CLI_PAYLOAD"),
                 ({"pyproject": PROJECT.replace(b">=3.11", b">=3.12")}, "PYTHON_CLI_SOURCE"))
        for options, code in cases:
            with self.subTest(code=code):
                with self.assertRaisesRegex(ContractError, code):
                    self.inspect(self.fixture(**options))
