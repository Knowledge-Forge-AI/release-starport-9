"""Focused boundary tests for the runtime Stage-A file adapter.

The maintained payload assembler is deliberately replaced by a recorder in
these tests.  Its independent contract tests remain the authority for the
actual body joins; this file tests that the new adapter supplies detached,
hash-bound bytes and never exposes unsafe input/output paths.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
import tempfile
import tarfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

from rs9.errors import ContractError
from rs9.nebular070_payload import LINUX_TARGETS
from rs9.nebular070_public_payload import BODY_KINDS, PRODUCT_COMMIT, PRODUCT_TREE
from rs9 import nebular070_public_stagea_files as adapter


class StageAFileAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve() / "inputs"
        self.root.mkdir(mode=0o700)
        self.producer = {"commit": "a" * 40, "tree": "b" * 40}
        self.rs9 = {"commit": "c" * 40, "tree": "d" * 40}
        self.files: dict[str, bytes] = {}

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _file(self, name: str, raw: bytes) -> dict[str, object]:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        self.files[name] = raw
        return {"path": name, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}

    def _spec(self) -> dict[str, object]:
        body = b'{"schema":"controlled"}'
        runtime = {}
        origins = {}
        metadata = {}
        bodies = {}
        for target in LINUX_TARGETS:
            runtime[target] = {
                "closed_manifest": self._file(f"{target}/closed.json", body),
                "runtime_receipt": self._file(f"{target}/receipt.json", body),
            }
            origins[target] = self._file(f"{target}/origin.json", body)
            metadata[target] = self._file(f"{target}/metadata.json", body)
            bodies[target] = {
                kind: self._file(f"{target}/{kind}.json", body) for kind in BODY_KINDS
            }
        manifest = self._file("runtime-manifest.json", body)
        return {
            "schema": adapter.SCHEMA,
            "version": adapter.VERSION,
            "product_source": {"commit": PRODUCT_COMMIT, "tree": PRODUCT_TREE},
            "producer_source": self.producer,
            "runtime_manifest": manifest,
            "runtime_inputs": runtime,
            "source_origins": origins,
            "bodies": bodies,
            "artifact_metadata": metadata,
        }

    def _write_spec(self, spec: dict[str, object], name: str = "spec.json") -> str:
        raw = json.dumps(spec, sort_keys=True, separators=(",", ":")).encode()
        (self.root / name).write_bytes(raw)
        return name

    def _run(self, spec_name: str = "spec.json", output: str = "out") -> dict[str, object]:
        recorded: dict[str, object] = {}

        def fake_assemble(inputs, *, expected_tf_producer_source, expected_rs9_tool_source):
            recorded["inputs"] = inputs
            recorded["tf"] = expected_tf_producer_source
            recorded["rs9"] = expected_rs9_tool_source
            return {"schema": "controlled", "record": {"status": "payload-qualified"}}

        with mock.patch.object(adapter, "assemble_public_payload", side_effect=fake_assemble), \
             mock.patch.object(adapter, "qualification_checked_checkout", return_value=None):
            result = adapter.assemble_stage_a_files(
                repository=self.root,
                input_root=self.root,
                spec=spec_name,
                output=output,
                expected_rs9_commit=self.rs9["commit"],
                expected_rs9_tree=self.rs9["tree"],
                expected_tf_producer_commit=self.producer["commit"],
                expected_tf_producer_tree=self.producer["tree"],
            )
        result["recorded"] = recorded
        return result

    def test_detaches_all_references_and_writes_fresh_receipt(self) -> None:
        spec = self._spec()
        spec_name = self._write_spec(spec)
        result = self._run(spec_name)
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["output"], "out")
        recorded = result["recorded"]
        self.assertEqual(recorded["rs9"], self.rs9)
        self.assertEqual(recorded["tf"], self.producer)
        inputs = recorded["inputs"]
        self.assertIsInstance(inputs["runtime_manifest"], bytes)
        self.assertIsInstance(inputs["bodies"]["linux-x64-gnu"]["cpu"], bytes)
        payload = json.loads((self.root / "out/payload-portability.json").read_text())
        receipt = json.loads((self.root / "out/stage-a-receipt.json").read_text())
        self.assertEqual(payload["schema"], "controlled")
        self.assertEqual(receipt["source"]["rs9"], self.rs9)
        self.assertEqual(receipt["payload"]["path"], "payload-portability.json")
        self.assertNotIn(str(self.root), json.dumps(receipt))

    def test_archive_aware_spec_detaches_both_bounded_archive_refs(self) -> None:
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w:gz") as archive:
            info = tarfile.TarInfo("payload-root/")
            info.type = tarfile.DIRTYPE
            info.mode = 0o755
            archive.addfile(info)
            info = tarfile.TarInfo("payload-root/LICENSE")
            content = b"AGPL-3.0-or-later\n"
            info.size = len(content)
            info.mode = 0o644
            archive.addfile(info, io.BytesIO(content))
        raw_archive = stream.getvalue()
        spec = self._spec()
        spec["schema"] = adapter.ARCHIVE_SCHEMA
        spec["payload_archives"] = {
            target: self._file(f"{target}/payload.tar.gz", raw_archive)
            for target in LINUX_TARGETS
        }
        spec_name = self._write_spec(spec, "archive-spec.json")
        result = self._run(spec_name, "archive-out")
        for target in LINUX_TARGETS:
            self.assertEqual(result["recorded"]["inputs"]["payload_archives"][target], raw_archive)

    def test_archive_ref_uses_archive_bound_above_manifest_default(self) -> None:
        raw_archive = b"a" * (adapter.MAX_MANIFEST_BYTES + 1)
        spec = self._spec()
        spec["schema"] = adapter.ARCHIVE_SCHEMA
        spec["payload_archives"] = {
            target: self._file(f"{target}/large-payload.tar.gz", raw_archive)
            for target in LINUX_TARGETS
        }
        spec_name = self._write_spec(spec, "large-archive-spec.json")
        result = self._run(spec_name, "large-archive-out")
        for target in LINUX_TARGETS:
            self.assertEqual(
                result["recorded"]["inputs"]["payload_archives"][target],
                raw_archive,
            )

    def test_nonstring_spec_schema_refuses_with_stage_a_error(self) -> None:
        spec = self._spec()
        spec["schema"] = []
        spec_name = self._write_spec(spec, "malformed-schema.json")
        with self.assertRaises(ContractError) as context:
            self._run(spec_name, "malformed-schema-out")
        self.assertEqual(context.exception.code, "STAGE_A_SCHEMA")

    def test_declared_digest_and_symlink_are_refused(self) -> None:
        spec = self._spec()
        spec_name = self._write_spec(spec)
        target = self.root / "linux-x64-gnu/cpu.json"
        original = target.read_bytes()
        target.write_bytes(original + b"x")
        with self.assertRaises(ContractError) as changed:
            self._run(spec_name, "changed")
        self.assertEqual(changed.exception.code, "STAGE_A_INPUT")

        target.unlink()
        target.symlink_to(self.root / "linux-arm64-gnu/cpu.json")
        with self.assertRaises(ContractError) as linked:
            self._run(spec_name, "linked")
        self.assertIn(linked.exception.code, {"STAGE_A_INPUT", "STAGE_A_PATH"})

    def test_spec_traversal_source_mismatch_and_existing_output_fail_closed(self) -> None:
        spec = self._spec()
        spec_name = self._write_spec(spec)
        with self.assertRaises(ContractError) as mismatch:
            self._run(spec_name, "../escape")
        self.assertIn(mismatch.exception.code, {"UNSAFE_PATH", "STAGE_A_PATH"})

        spec["producer_source"] = {"commit": "e" * 40, "tree": "f" * 40}
        mismatch_name = self._write_spec(spec, "mismatch.json")
        with self.assertRaises(ContractError) as wrong_source:
            self._run(mismatch_name, "wrong-source")
        self.assertEqual(wrong_source.exception.code, "STAGE_A_SOURCE")

        self._write_spec(self._spec(), "existing-spec.json")
        (self.root / "existing").mkdir()
        with self.assertRaises(ContractError) as existing:
            self._run("existing-spec.json", "existing")
        self.assertEqual(existing.exception.code, "STAGE_A_OUTPUT")

    def test_writer_failure_removes_only_owned_fresh_output(self) -> None:
        spec_name = self._write_spec(self._spec())

        class FailingWriter:
            def __init__(self, *_args, **_kwargs):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def write(self, *_args):
                raise OSError("controlled output failure")

        with mock.patch.object(adapter, "assemble_public_payload", return_value={"schema": "controlled"}), \
             mock.patch.object(adapter, "qualification_checked_checkout", return_value=None), \
             mock.patch.object(adapter, "ConfinedWriter", FailingWriter):
            with self.assertRaises(OSError):
                adapter.assemble_stage_a_files(
                    repository=self.root,
                    input_root=self.root,
                    spec=spec_name,
                    output="failed-output",
                    expected_rs9_commit=self.rs9["commit"],
                    expected_rs9_tree=self.rs9["tree"],
                    expected_tf_producer_commit=self.producer["commit"],
                    expected_tf_producer_tree=self.producer["tree"],
                )
        self.assertFalse((self.root / "failed-output").exists())

    def test_real_maintained_assembler_rejects_unqualified_records(self) -> None:
        spec_name = self._write_spec(self._spec())
        with mock.patch.object(adapter, "qualification_checked_checkout", return_value=None), self.assertRaises(ContractError) as rejected:
            adapter.assemble_stage_a_files(
                repository=self.root,
                input_root=self.root,
                spec=spec_name,
                output="real-assembler-reject",
                expected_rs9_commit=self.rs9["commit"],
                expected_rs9_tree=self.rs9["tree"],
                expected_tf_producer_commit=self.producer["commit"],
                expected_tf_producer_tree=self.producer["tree"],
            )
        self.assertIn(rejected.exception.code, {"NEBULAR_STAGE_A_INPUT", "NEBULAR_STAGE_A_SOURCE", "NEBULAR_STAGE_A_SCHEMA"})
        self.assertFalse((self.root / "real-assembler-reject").exists())

    @staticmethod
    def _git_result(stdout: str, returncode: int = 0) -> object:
        return subprocess.CompletedProcess(["git"], returncode, stdout=stdout, stderr="")

    def test_qualification_checkout_requires_exact_refs_and_clean_worktree(self) -> None:
        expected_commit = "c" * 40
        expected_tree = "d" * 40
        for results in (
            [self._git_result("x" * 40)],
            [self._git_result(expected_commit), self._git_result("x" * 40)],
            [self._git_result(expected_commit), self._git_result(expected_tree), self._git_result(" M file")],
        ):
            with self.subTest(results=len(results)), mock.patch.object(adapter.subprocess, "run", side_effect=results):
                with self.assertRaises(ContractError) as rejected:
                    adapter.qualification_checked_checkout(self.root, expected_commit, expected_tree)
                self.assertEqual(rejected.exception.code, "STAGE_A_SOURCE")

        with mock.patch.object(
            adapter.subprocess,
            "run",
            side_effect=[
                self._git_result(expected_commit),
                self._git_result(expected_tree),
                self._git_result(""),
            ],
        ) as git:
            adapter.qualification_checked_checkout(self.root, expected_commit, expected_tree)
        self.assertEqual(git.call_count, 3)
        self.assertFalse(any("branch" in call.args[0] for call in git.call_args_list))

    def test_qualification_git_queries_strip_selector_and_config_overrides(self) -> None:
        expected_commit = "c" * 40
        expected_tree = "d" * 40
        injected = {
            "GIT_DIR": "/foreign/git",
            "GIT_WORK_TREE": "/foreign/worktree",
            "GIT_COMMON_DIR": "/foreign/common",
            "GIT_INDEX_FILE": "/foreign/index",
            "GIT_OBJECT_DIRECTORY": "/foreign/objects",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES": "/foreign/alternate",
            "GIT_NAMESPACE": "foreign",
            "GIT_CONFIG": "/foreign/config",
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "core.repositoryformatversion",
            "GIT_CONFIG_VALUE_0": "99",
            "GIT_CONFIG_GLOBAL": "/foreign/global",
            "GIT_CONFIG_SYSTEM": "/foreign/system",
            "GIT_CONFIG_NOSYSTEM": "0",
            "GIT_CONFIG_PARAMETERS": "core.bare=true",
        }
        with mock.patch.dict(os.environ, injected, clear=False), mock.patch.object(
            adapter.subprocess,
            "run",
            side_effect=[
                self._git_result(expected_commit),
                self._git_result(expected_tree),
                self._git_result(""),
            ],
        ) as git:
            adapter.qualification_checked_checkout(self.root, expected_commit, expected_tree)
        self.assertEqual(git.call_count, 3)
        for call in git.call_args_list:
            child_env = call.kwargs["env"]
            self.assertEqual(child_env.get("PATH"), os.environ.get("PATH"))
            for name in injected:
                self.assertNotIn(name, child_env)

    def test_descriptor_binder_validates_then_writes_fresh_output(self) -> None:
        evidence = self.root / "evidence/manylinux"
        evidence.mkdir(parents=True)
        (evidence / "stage-a.json").write_bytes(b"stage-a-body\n")
        descriptor = {
            "schema": "rs9.tf-pypi-qualification-inputs.v1",
            "status": "ready",
            "evidence": {"source_root": "evidence", "files": {}},
            "manylinux": {
                "schema": "rs9.tf-pypi-nebular070-public-inrun-manylinux.v1",
                "origin_kind": "public-in-run",
                "tf_producer_source": {"commit": "a" * 40, "tree": "b" * 40},
            },
        }
        template = self.root / "template.json"
        template.write_bytes(json.dumps(descriptor).encode())
        seen: dict[str, object] = {}

        def validator(candidate, **kwargs):
            seen["candidate"] = candidate
            seen["kwargs"] = kwargs
            self.assertEqual(candidate["status"], "ready")
            self.assertEqual(candidate["manylinux"]["stage_a"]["path"], "manylinux/stage-a.json")
            self.assertIn("manylinux/stage-a.json", candidate["evidence"]["files"])
            return candidate

        import rs9.tf_pypi_nebular070_publish as publisher
        with mock.patch.object(publisher, "validate_qualification_inputs_descriptor", side_effect=validator):
            result = adapter.bind_descriptor_phase(
                descriptor_path=template,
                stage_file="manylinux/stage-a.json",
                output_path=self.root / "bound.json",
                repository=self.root,
                inrun_root=self.root,
                phase="qualification-prep",
            )
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["role"], "stage_a")
        self.assertTrue((self.root / "bound.json").is_file())
        self.assertNotIn("stage_a", json.loads(template.read_text())["manylinux"])
        self.assertEqual(seen["kwargs"]["inrun_root"], self.root)

    def test_descriptor_binder_rejects_invalid_phase_and_symlink_stage(self) -> None:
        descriptor = {
            "evidence": {"source_root": "evidence", "files": {}},
            "manylinux": {"schema": "rs9.tf-pypi-nebular070-public-inrun-manylinux.v1", "origin_kind": "public-in-run"},
        }
        template = self.root / "template.json"
        template.write_bytes(json.dumps(descriptor).encode())
        with self.assertRaises(ContractError) as invalid:
            adapter.bind_descriptor_phase(
                descriptor_path=template, stage_file="stage-a.json", output_path=self.root / "invalid.json",
                repository=self.root, inrun_root=self.root, phase="resume",
            )
        self.assertEqual(invalid.exception.code, "STAGE_A_PHASE")
        (self.root / "evidence").mkdir()
        (self.root / "outside.json").write_text("x")
        (self.root / "evidence/stage-a.json").symlink_to(self.root / "outside.json")
        with self.assertRaises(ContractError) as linked:
            adapter.bind_descriptor_phase(
                descriptor_path=template, stage_file="stage-a.json", output_path=self.root / "linked.json",
                repository=self.root, inrun_root=self.root, phase="qualification-prep",
            )
        self.assertIn(linked.exception.code, {"STAGE_A_INPUT", "STAGE_A_PATH"})

    def test_descriptor_binder_real_validator_resolves_both_phases_and_roots(self) -> None:
        import rs9.tf_pypi_nebular070_publish as publisher
        from rs9.operator import NEBULAR070_BOOTSTRAP, NEBULAR070_EXPECTATIONS, NEBULAR070_PROFILE

        # The temporary repository and both external roots are wholly local
        # fixtures.  No author checkout, scratch path, or external descriptor
        # is required for this real-validator/materializer integration.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            root.chmod(0o700)
            repository = root / "repository"
            repository.mkdir(mode=0o700)
            binding_files = {
                NEBULAR070_BOOTSTRAP: b"bootstrap-fixture\n",
                NEBULAR070_EXPECTATIONS: b"expectations-fixture\n",
                NEBULAR070_PROFILE: b"profile-fixture\n",
            }
            for rel_path, raw in binding_files.items():
                target = repository / rel_path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(raw)

            def digest_entry(path: str) -> dict[str, object]:
                return {"path": path, "size": 1, "sha256": "0" * 64}

            def evidence_entry(path: str) -> dict[str, object]:
                return {
                    "path": path,
                    "size": 1,
                    "sha256": hashlib.sha256(b"x").hexdigest(),
                }

            raw_targets: dict[str, object] = {}
            for target in publisher.TARGETS:
                raw_entry = digest_entry(f"raw/{target}/payload.bin")
                raw_targets[target] = {
                    "schema": publisher.RAW_RELEASE_HANDOFF_SCHEMA,
                    "target": target,
                    "record": raw_entry,
                    "readme": digest_entry(f"raw/{target}/README.md"),
                    "provenance": digest_entry(f"raw/{target}/provenance.json"),
                    "payload": raw_entry,
                    "manifest": digest_entry(f"raw/{target}/manifest.json"),
                    "legal_files": {
                        "LICENSE": digest_entry(f"raw/{target}/LICENSE"),
                        "NOTICE": digest_entry(f"raw/{target}/NOTICE"),
                        "COMMERCIAL-LICENSE.md": digest_entry(f"raw/{target}/COMMERCIAL-LICENSE.md"),
                    },
                    "native_consumer": {
                        target: {
                            "qualification": digest_entry(f"raw/{target}/qualification.json"),
                            "smoke": {
                                "raw-archive": {
                                    "run": digest_entry(f"raw/{target}/raw-run.json"),
                                    "receipt": digest_entry(f"raw/{target}/raw-receipt.json"),
                                },
                                "npm-package": {
                                    "run": digest_entry(f"raw/{target}/npm-run.json"),
                                    "receipt": digest_entry(f"raw/{target}/npm-receipt.json"),
                                },
                            },
                        }
                    },
                }

            bootstrap_sha = hashlib.sha256(binding_files[NEBULAR070_BOOTSTRAP]).hexdigest()
            expectations_sha = hashlib.sha256(binding_files[NEBULAR070_EXPECTATIONS]).hexdigest()
            binding = {
                "schema": "rs9.nebular-release-binding.v1alpha1",
                "release": publisher.VERSION,
                "application_version": publisher.VERSION,
                "distribution_version": publisher.DISTRIBUTION_VERSION,
                "repository": "Knowledge-Forge-AI/theme-forge-nebular-fusion",
                "tag": publisher.TAG,
                "bootstrap_path": NEBULAR070_BOOTSTRAP,
                "expectations_path": NEBULAR070_EXPECTATIONS,
                "profile_path": NEBULAR070_PROFILE,
                "status": "ready",
                "lineage": {
                    "mode": "direct-tag-provenance-equality",
                    "requires_historical_author_rewrite": False,
                },
                "provenance": {
                    "path": "PYPI-INTAKE-PROVENANCE.json",
                    "commit_field": "releaseCommit",
                    "tree_field": "testedTree",
                },
                "expected": {
                    "repository_id": 1,
                    "release_id": 1,
                    "tag_commit": "a" * 40,
                    "tag_tree": "b" * 40,
                    "bootstrap_sha256": bootstrap_sha,
                    "expectations_sha256": expectations_sha,
                },
            }
            evidence_names = (
                "api/release.json", "api/repository.json", "api/ref.json", "api/commit.json",
                "api/tree.json", "assets/SHA256SUMS", "assets/PROVENANCE.json",
                "npm/metadata.json", "npm/package.tgz", "source/LICENSE", "source/NOTICE",
            )
            stage_a = b"integration-stage-a\n"
            stage_b = b"integration-stage-b\n"
            evidence_files = {
                rel_path: evidence_entry(rel_path) for rel_path in evidence_names
            }
            stage_a_entry = {
                "path": "manylinux/stage-a.json",
                "size": len(stage_a),
                "sha256": hashlib.sha256(stage_a).hexdigest(),
            }
            evidence_files[stage_a_entry["path"]] = stage_a_entry
            descriptor = {
                "schema": publisher.QUALIFICATION_INPUTS_SCHEMA,
                "project": publisher.PROJECT,
                "version": publisher.VERSION,
                "distribution_version": publisher.DISTRIBUTION_VERSION,
                "workflow": publisher.WORKFLOW,
                "status": "ready",
                "upstream_origin": {
                    "repository": "Knowledge-Forge-AI/theme-forge-nebular-fusion",
                    "tag": publisher.TAG,
                    "release_url": "https://github.com/Knowledge-Forge-AI/theme-forge-nebular-fusion/releases/tag/v0.7.0",
                    "api_release_url": "https://api.github.com/repos/Knowledge-Forge-AI/theme-forge-nebular-fusion/releases/1",
                },
                "release_binding": binding,
                "release_binding_sha256": publisher.sha256(publisher.canonical(binding)),
                "evidence": {"source_root": "capture", "files": evidence_files},
                "raw_release": {"source_root": "raw-handoff", "targets": raw_targets},
                "manylinux": {
                    "schema": publisher.PUBLIC_INRUN_MANYLINUX_SCHEMA,
                    "origin_kind": publisher.PUBLIC_INRUN_MANYLINUX_ORIGIN_KIND,
                    "stage_a": stage_a_entry,
                    "tf_producer_source": {"commit": "7" * 40, "tree": "8" * 40},
                },
            }

            prep_root = root / "prep-root"
            publication_root = root / "publication-root"

            def populate(external_root: Path) -> None:
                (external_root / "capture").mkdir(parents=True, mode=0o700)
                (external_root / "raw-handoff").mkdir(mode=0o700)
                for rel_path in evidence_names:
                    raw = b"x"
                    target = external_root / "capture" / rel_path
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(raw)
                for rel_path, raw in (
                    ("manylinux/stage-a.json", stage_a),
                    ("manylinux/stage-b.json", stage_b),
                ):
                    target = external_root / "capture" / rel_path
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(raw)

            prep_root.mkdir(mode=0o700)
            publication_root.mkdir(mode=0o700)
            populate(prep_root)
            populate(publication_root)

            input_descriptor = root / "input-descriptor.json"
            input_descriptor.write_text(json.dumps(descriptor, sort_keys=True, separators=(",", ":")))
            prep_bound = root / "prep-bound.json"
            prep_result = adapter.bind_descriptor_phase(
                descriptor_path=input_descriptor,
                stage_file="manylinux/stage-a.json",
                output_path=prep_bound,
                repository=repository,
                inrun_root=prep_root,
                phase=publisher.QUALIFICATION_INPUT_PHASE_PREP,
            )
            self.assertEqual(prep_result["status"], "pass")
            self.assertEqual(prep_result["stage_file"]["path"], "manylinux/stage-a.json")

            publication_descriptor = json.loads(prep_bound.read_text())
            stage_b_entry = {
                "path": "manylinux/stage-b.json",
                "size": len(stage_b),
                "sha256": hashlib.sha256(stage_b).hexdigest(),
            }
            publication_descriptor["evidence"]["files"][stage_b_entry["path"]] = stage_b_entry
            publication_descriptor_path = root / "publication-input.json"
            publication_descriptor_path.write_text(
                json.dumps(publication_descriptor, sort_keys=True, separators=(",", ":"))
            )
            publication_bound = root / "publication-bound.json"
            publication_result = adapter.bind_descriptor_phase(
                descriptor_path=publication_descriptor_path,
                stage_file="manylinux/stage-b.json",
                output_path=publication_bound,
                repository=repository,
                inrun_root=publication_root,
                phase=publisher.QUALIFICATION_INPUT_PHASE_PUBLICATION,
            )
            self.assertEqual(publication_result["status"], "pass")
            self.assertEqual(publication_result["stage_file"]["path"], "manylinux/stage-b.json")

            # Exercise the real downstream materializer against the second,
            # disjoint root; this catches evidence-root/path namespace drift.
            materialized = publication_root / "materialized"
            publisher.materialize_manylinux_inputs(
                json.loads(publication_bound.read_text()),
                materialized,
                repository=repository,
                phase=publisher.QUALIFICATION_INPUT_PHASE_PUBLICATION,
                inrun_root=publication_root,
            )
            final_descriptor = json.loads(publication_bound.read_text())
            self.assertEqual(final_descriptor["manylinux"]["stage_a"]["path"], "manylinux/stage-a.json")
            self.assertEqual(final_descriptor["manylinux"]["stage_b"]["path"], "manylinux/stage-b.json")
            self.assertTrue((materialized / "manylinux/stage-a.json").is_file())
            self.assertTrue((materialized / "manylinux/stage-b.json").is_file())

    def test_descriptor_install_is_no_overwrite_and_concurrency_safe(self) -> None:
        output = self.root / "atomic-descriptor.json"
        output.write_bytes(b"foreign-output")
        with self.assertRaises(ContractError):
            adapter._atomic_descriptor_write(output, b"replacement")
        self.assertEqual(output.read_bytes(), b"foreign-output")

        output.unlink()
        temporary = self.root / f".{output.name}.stage-a-{os.getpid()}"
        temporary.write_bytes(b"foreign-temporary")
        with self.assertRaises(ContractError):
            adapter._atomic_descriptor_write(output, b"replacement")
        self.assertEqual(temporary.read_bytes(), b"foreign-temporary")
        temporary.unlink()

        def install() -> str:
            try:
                adapter._atomic_descriptor_write(output, b"concurrent")
            except ContractError:
                return "refused"
            return "installed"

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(lambda _unused: install(), (0, 1)))
        self.assertEqual(outcomes.count("installed"), 1)
        self.assertEqual(outcomes.count("refused"), 1)
        self.assertEqual(output.read_bytes(), b"concurrent")


if __name__ == "__main__":
    unittest.main()
