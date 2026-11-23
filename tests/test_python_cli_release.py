from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import stat
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch
import zipfile

from rs9.errors import ContractError
from rs9.cli import main as rs9_main
from rs9.github import ScopedGitHubAuthorization
from rs9.github_cli import inspect_homebrew_projection
from rs9.github_reader import GitHubReadTransport
from rs9.homebrew_renderer import render_python_wheel_formula
from rs9.installed_homebrew import apply_python_wheel_formula, write_python_wheel_formula
from rs9.instance import record_sha256
from rs9.python_cli_release import inspect_python_cli_release, main, verify_homebrew_plan_evidence
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


def normalized_homebrew_intent():
    return {
        "project": {"id": "example-cli", "name": "Example CLI", "repository": REPOSITORY},
        "tag": "v1.2.3",
        "version": "1.2.3",
        "release": {"prerelease": "reject"},
        "runtime": {"kind": "python", "constraint": ">=3.11"},
        "license": {"source": "tagged-repository", "expression": "MIT",
                    "files": ["COMMERCIAL-LICENSE.md", "LICENSE", "NOTICE"]},
        "commands": [{"interface": "cli", "name": "example"}],
        "checks": [{"id": "version", "argv": ["example", "--version"],
                    "requires-display": False, "expect-exit": 0, "expect-stdout-contains": "1.2.3"}],
        "assets": [
            {"id": "source", "name": SDIST, "format": "sdist", "platforms": ["any"]},
            {"id": "wheel", "name": WHEEL, "format": "wheel", "platforms": ["any"]},
        ],
        "targets": [{"adapter": "homebrew", "mode": "projection", "name": "example-cli",
                     "assets": ["source", "wheel"]}],
    }


def write_evidence(root, *, new_metadata=b"", pyproject=PROJECT, different_source=False, bad_record=False,
                   cli_source=b"def main(): return 0\n"):
    licenses = {name: b"Synthetic license fixture.\n" for name in ("LICENSE", "NOTICE", "COMMERCIAL-LICENSE.md")}
    source = {"pyproject.toml": PROJECT, **licenses}
    package = {"example/__init__.py": b"", "example/cli.py": cli_source}
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


def add_tagged_consumer(root, files):
    source = root / "source/.rs9"
    source.mkdir(exist_ok=True)
    tree_path = root / "api/tree.json"
    tree = json.loads(tree_path.read_bytes())
    tree_body = bytearray()
    for name, raw in sorted(files.items()):
        (source / name).write_bytes(raw)
        blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        tree["tree"].append({"path": f".rs9/{name}", "type": "blob", "mode": "100644", "sha": blob})
        tree_body.extend(b"100644 " + name.encode("ascii") + b"\0" + bytes.fromhex(blob))
    directory_sha = hashlib.sha1(b"tree " + str(len(tree_body)).encode("ascii") + b"\0" + tree_body).hexdigest()
    tree["tree"].append({"path": ".rs9", "type": "tree", "mode": "040000", "sha": directory_sha})
    tree_path.write_text(json.dumps(tree), encoding="utf-8")


class PythonCliReleaseTests(unittest.TestCase):
    def test_prepares_one_formula_with_both_verified_assets_without_clobber(self):
        root = self.fixture()
        intent = normalized_homebrew_intent()
        intent_sha = record_sha256(intent)
        plan = {
            "instance_id": "publisher", "consumer_id": "example",
            "inputs": {"normalized_sha256": intent_sha},
            "runtimeEngine": {"distribution": "release-starport-9", "version": "0.0.0.dev0"},
            "normalizedIntent": intent,
            "releaseEvidence": {**verify_homebrew_plan_evidence(intent, root), "normalizedSha256": intent_sha},
        }
        output = root / "formula-candidate"
        receipt = write_python_wheel_formula(plan, output)
        path = output / "Formula/example-cli.rb"
        body = path.read_bytes()
        self.assertIn(WHEEL.encode(), body)
        self.assertIn(SDIST.encode(), body)
        self.assertIn(digest((root / "assets" / WHEEL).read_bytes()).encode(), body)
        self.assertIn(digest((root / "assets" / SDIST).read_bytes()).encode(), body)
        self.assertEqual(receipt["files"][0]["sha256"], digest(body))
        self.assertFalse(receipt["publicationAuthority"])
        with self.assertRaisesRegex(ContractError, "HOMEBREW_OUTPUT_EXISTS"):
            write_python_wheel_formula(plan, output)
        self.assertEqual(path.read_bytes(), body)
        plan["normalizedIntent"]["checks"] = []
        with self.assertRaisesRegex(ContractError, "HOMEBREW_RENDER_PROVENANCE"):
            write_python_wheel_formula(plan, root / "refused")
        self.assertFalse((root / "refused").exists())

    def test_observes_only_the_registered_tap_and_refuses_mixed_snapshots(self):
        root = self.fixture()
        intent = normalized_homebrew_intent()
        tap = "Example/independent-tap"
        intent["targets"][0]["repository"] = tap
        intent_sha = record_sha256(intent)
        plan = {
            "instance_id": "publisher", "consumer_id": "example",
            "inputs": {"normalized_sha256": intent_sha}, "normalizedIntent": intent,
            "releaseEvidence": {**verify_homebrew_plan_evidence(intent, root), "normalizedSha256": intent_sha},
        }
        path, formula, _ = render_python_wheel_formula(plan)
        snapshot = {"commit": "a" * 40, "tree": "b" * 40,
                    "repository": {"full_name": tap, "private": False}, "metadata_sha256": "c" * 64}
        reader = Mock(spec=GitHubReadTransport)
        reader.read_branch.return_value = snapshot
        reader.read_parent.return_value = {
            **snapshot, "path": "Formula", "state": "present", "type": "tree", "mode": "040000",
        }
        matching = {
            **snapshot, "path": path, "state": "present", "type": "blob", "mode": "100644",
            "data": formula, "size": len(formula), "sha256": digest(formula),
        }
        reader.read_file.return_value = matching

        result = inspect_homebrew_projection(plan, "stable", _reader=reader)
        self.assertEqual(result["remote"]["state"], "match")
        self.assertFalse(result["publicationAuthority"])
        self.assertFalse(result["publicationEnabled"])
        self.assertFalse(result["taggedConsumerContractVerified"])
        reader.read_file.assert_called_once_with(tap, path, snapshot["commit"])
        self.assertNotIn("class ExampleCli", json.dumps(result))

        for override, expected in (
            ({"mode": "100755"}, "drift"),
            ({"state": "missing", "type": "missing", "data": None}, "missing"),
            ({"type": "symlink", "mode": "120000"}, "unsafe"),
        ):
            with self.subTest(expected=expected):
                reader.read_file.return_value = {**matching, **override}
                self.assertEqual(inspect_homebrew_projection(plan, "stable", _reader=reader)["remote"]["state"], expected)

        reader.read_file.return_value = {**matching, "tree": "d" * 40}
        with self.assertRaisesRegex(ContractError, "HOMEBREW_OBSERVATION_MISMATCH"):
            inspect_homebrew_projection(plan, "stable", _reader=reader)

        reader.read_file.return_value = matching
        reader.read_branch.side_effect = [snapshot, {**snapshot, "commit": "d" * 40}]
        result = inspect_homebrew_projection(plan, "stable", _reader=reader)
        self.assertEqual(result["remote"], {"state": "unknown", "reason": "branch-changed"})

    def test_binds_verified_artifacts_to_the_selected_homebrew_intent(self):
        root = self.fixture()
        with patch("rs9.python_cli_release.capture_release") as capture:
            evidence = verify_homebrew_plan_evidence(normalized_homebrew_intent(), root)
        capture.assert_not_called()
        self.assertFalse(evidence["taggedConsumerContractVerified"])
        self.assertEqual(evidence["distribution"], "example-cli")
        self.assertEqual(evidence["receipt"], self.inspect(root))
        self.assertEqual(evidence["assets"], [
            {"id": "source", "name": SDIST, "sha256": digest((root / "assets" / SDIST).read_bytes())},
            {"id": "wheel", "name": WHEEL, "sha256": digest((root / "assets" / WHEEL).read_bytes())},
        ])

    def test_refuses_evidence_for_a_different_plan(self):
        root = self.fixture()
        baseline = normalized_homebrew_intent()
        cases = (
            lambda intent: intent["targets"][0].update(assets=["wheel"]),
            lambda intent: intent["assets"][1].update(name="different-1.2.3-py3-none-any.whl"),
            lambda intent: intent["runtime"].update(constraint=">=3.12"),
            lambda intent: intent["license"].update(expression="BSD-3-Clause"),
            lambda intent: intent["release"].update(evidence={"profile": "different"}),
        )
        for change in cases:
            with self.subTest(change=change):
                intent = deepcopy(baseline)
                change(intent)
                with self.assertRaisesRegex(ContractError, "PYTHON_CLI_PLAN_MISMATCH"):
                    verify_homebrew_plan_evidence(intent, root)

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

    def test_tagged_contract_admission_binds_the_selected_configuration_bytes(self):
        root = self.fixture()
        files = {name: f'# fixture {name}\n'.encode()
                 for name in ("project.toml", "releases.toml", "homebrew.toml")}
        add_tagged_consumer(root, files)
        intent = normalized_homebrew_intent()
        intent["evidence"] = {"inputs": [
            {"filename": name, "sha256": digest(raw)} for name, raw in files.items()
        ]}
        ordinary = verify_homebrew_plan_evidence(intent, root)
        self.assertFalse(ordinary["taggedConsumerContractVerified"])
        strict = verify_homebrew_plan_evidence(intent, root, require_tagged_consumer_contract=True)
        self.assertTrue(strict["taggedConsumerContractVerified"])
        self.assertEqual(strict["receipt"]["taggedConsumerInputs"], {
            name: digest(raw) for name, raw in files.items()
        })
        drifted = deepcopy(intent)
        drifted["evidence"]["inputs"][0]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ContractError, "PYTHON_CLI_TAGGED_CONTRACT_MISMATCH"):
            verify_homebrew_plan_evidence(drifted, root, require_tagged_consumer_contract=True)
        drifted = deepcopy(intent)
        drifted["evidence"]["inputs"].append(drifted["evidence"]["inputs"][0])
        with self.assertRaisesRegex(ContractError, "PYTHON_CLI_TAGGED_CONTRACT_MISMATCH"):
            verify_homebrew_plan_evidence(drifted, root, require_tagged_consumer_contract=True)
        (root / "source/.rs9/homebrew.toml").write_bytes(b"# different captured bytes")
        with self.assertRaisesRegex(ContractError, "SOURCE_BLOB_MISMATCH"):
            verify_homebrew_plan_evidence(intent, root, require_tagged_consumer_contract=True)

    def test_applies_a_tagged_formula_atomically_and_protects_the_local_tap(self):
        root = self.fixture()
        tap_repository = "Example/independent-tap"
        files = {name: b"# test tagged content\n"
                 for name in ("homebrew.toml", "project.toml", "releases.toml")}
        add_tagged_consumer(root, files)
        intent = normalized_homebrew_intent()
        intent["targets"][0]["repository"] = tap_repository
        intent["evidence"] = {"inputs": [
            {"filename": name, "sha256": digest(raw)} for name, raw in files.items()
        ]}
        intent_sha = record_sha256(intent)
        plan = {
            "instance_id": "publisher", "consumer_id": "example",
            "inputs": {"normalized_sha256": intent_sha}, "normalizedIntent": intent,
            "releaseEvidence": {**verify_homebrew_plan_evidence(
                intent, root, require_tagged_consumer_contract=True,
            ), "normalizedSha256": intent_sha},
        }
        path, desired, _ = render_python_wheel_formula(plan)
        tap = root / "local-tap"
        (tap / "Formula").mkdir(parents=True)
        target = tap / path
        neighbor = tap / "Formula/another.rb"
        neighbor.write_bytes(b"# unrelated formula\n")

        def apply(**extra):
            options = {"tap_repository": tap_repository, "expected_sha256": digest(desired), **extra}
            return apply_python_wheel_formula(plan, tap, **options)

        with self.assertRaisesRegex(ContractError, "HOMEBREW_FORMULA_REVIEW_CHANGED"):
            apply(expected_sha256="0" * 64)
        with self.assertRaisesRegex(ContractError, "HOMEBREW_FORMULA_REVIEW_CHANGED"):
            apply(expected_sha256="0" * 64, dry_run=True)
        before = neighbor.stat()
        with patch("rs9.installed_homebrew._write_formula_bytes") as write:
            preview = apply(dry_run=True)
        write.assert_not_called()
        self.assertEqual(preview["status"], "ready")
        self.assertIs(preview["dryRun"], True)
        self.assertFalse(preview["publicationAuthority"])
        self.assertEqual(list((tap / "Formula").iterdir()), [neighbor])
        self.assertEqual(neighbor.stat(), before)
        with patch("rs9.installed_homebrew.os.link", side_effect=OSError("interrupted before link")):
            with self.assertRaisesRegex(ContractError, "HOMEBREW_TAP_CUSTODY"):
                apply()
        self.assertEqual(list((tap / "Formula").iterdir()), [neighbor])
        created = apply()
        self.assertEqual(created["status"], "created")
        self.assertEqual(target.read_bytes(), desired)
        self.assertFalse(created["publicationEnabled"])
        initial = target.stat()
        self.assertEqual(apply()["status"], "noop")
        self.assertEqual(target.stat(), initial)
        self.assertEqual(apply(dry_run=True)["status"], "noop")
        self.assertEqual(target.stat(), initial)
        self.assertNotIn("dryRun", created)
        target.write_bytes(b"# competing formula\n")
        for options in ({}, {"dry_run": True}):
            with self.assertRaisesRegex(ContractError, "HOMEBREW_FORMULA_DRIFT"):
                apply(**options)
        self.assertEqual(target.read_bytes(), b"# competing formula\n")
        self.assertEqual(neighbor.read_bytes(), b"# unrelated formula\n")
        self.assertEqual(set((tap / "Formula").iterdir()), {target, neighbor})

        target.unlink()
        def competing_writer(*args, **kwargs):
            target.write_bytes(b"# created during apply")
            raise FileExistsError
        with patch("rs9.installed_homebrew.os.link", side_effect=competing_writer):
            with self.assertRaisesRegex(ContractError, "HOMEBREW_FORMULA_DRIFT"):
                apply()
        self.assertEqual(target.read_bytes(), b"# created during apply")
        self.assertEqual(set((tap / "Formula").iterdir()), {target, neighbor})

    def test_tagged_contract_admission_rejects_legacy_or_unknown_layout(self):
        root = self.fixture()
        intent = normalized_homebrew_intent()
        with self.assertRaisesRegex(ContractError, "MISSING_EVIDENCE"):
            verify_homebrew_plan_evidence(intent, root, require_tagged_consumer_contract=True)
        files = {name: b"# fixture\n" for name in
                 ("homebrew.toml", "project.toml", "releases.toml", "unexpected.toml")}
        add_tagged_consumer(root, files)
        with self.assertRaisesRegex(ContractError, "PYTHON_CLI_TAGGED_CONTRACT_LAYOUT"):
            verify_homebrew_plan_evidence(intent, root, require_tagged_consumer_contract=True)

    def test_strict_inspection_requires_the_matching_git_consumer_subtree(self):
        root = self.fixture()
        files = {name: b"# fixture\n" for name in ("homebrew.toml", "project.toml", "releases.toml")}
        add_tagged_consumer(root, files)
        tree_path = root / "api/tree.json"
        tree = json.loads(tree_path.read_bytes())
        directory = next(entry for entry in tree["tree"] if entry["path"] == ".rs9")
        for changed in (None, {**directory, "sha": "0" * 40}, {**directory, "sha": "bad"}):
            rows = [entry for entry in tree["tree"] if entry["path"] != ".rs9"]
            if changed is not None:
                rows.append(changed)
            tree_path.write_text(json.dumps({**tree, "tree": rows}), encoding="utf-8")
            with self.subTest(directory=changed):
                self.assertFalse("taggedConsumerInputs" in self.inspect(root))
                with self.assertRaisesRegex(ContractError, "PYTHON_CLI_TAGGED_CONTRACT_LAYOUT"):
                    inspect_python_cli_release(
                        REPOSITORY, "1.2.3", "example-cli", "example", root,
                        require_tagged_consumer_contract=True,
                    )

    def test_changed_wheel_transport_is_refused(self):
        root = self.fixture()
        wheel = root / "assets" / WHEEL
        content = wheel.read_bytes()
        wheel.write_bytes(bytes([content[0] ^ 1]) + content[1:])
        with self.assertRaisesRegex(ContractError, "DIGEST_MISMATCH"):
            self.inspect(root)

    def test_rs9_release_inspect_authenticates_the_offline_pair_without_remote_access(self):
        root = self.fixture()
        stream = io.StringIO()
        with patch("rs9.python_cli_release.capture_release") as capture, redirect_stdout(stream):
            code = rs9_main(["release", "inspect", REPOSITORY, "--tag", "v1.2.3",
                             "--distribution", "example-cli", "--command", "example",
                             "--evidence", str(root), "--json"])
        capture.assert_not_called()
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(stream.getvalue()), {
            "schema": "rs9.cli.v1alpha1", "command": "release.inspect",
            "ok": True, "result": self.inspect(root),
        })

    def test_rs9_release_inspect_refuses_coordinates_before_creating_capture(self):
        parent = self.fixture()
        for repository, tag, expected in (("not-a-repo", "v1.2.3", "INVALID_REPOSITORY"),
                                          (REPOSITORY, "1.2.3", "PYTHON_CLI_COORDINATES")):
            with self.subTest(repository=repository, tag=tag):
                target = parent / "capture"
                stream = io.StringIO()
                with patch("rs9.python_cli_release.capture_release") as capture, redirect_stderr(stream):
                    code = rs9_main(["release", "inspect", repository, "--tag", tag,
                                     "--distribution", "example-cli", "--command", "example",
                                     "--capture", str(target), "--json"])
                self.assertEqual(code, 1)
                self.assertEqual(json.loads(stream.getvalue())["error"]["code"], expected)
                self.assertFalse(target.exists())
                capture.assert_not_called()

    def test_capture_collects_the_same_release_coordinates_and_verifies_the_bytes(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        target = Path(temporary.name).resolve() / "capture"

        def provide(selection, output, *, client, asset_transport):
            self.assertFalse(any(isinstance(handler, ScopedGitHubAuthorization)
                                 for handler in client.opener.handlers))
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
