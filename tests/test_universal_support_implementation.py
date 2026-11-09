"""Focused source checks for the isolated 0.8 support seam."""

from __future__ import annotations

import ast
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


OUTPUT = Path(__file__).resolve().parents[1]
SRC = OUTPUT / "src"
ROUTE_OWNER = SRC / "rs9"
sys.path.insert(0, str(SRC))
import rs9  # noqa: E402

from rs9.tf_pypi_archive import AdmissionError, canonical, sha256  # noqa: E402
from rs9 import nebular080_public_inputs as inputs  # noqa: E402
from rs9 import nebular080_product_native as native_owner  # noqa: E402
from rs9 import nebular080_publication_coordinates as coords  # noqa: E402
from rs9 import nebular080_universal_publication as publication  # noqa: E402
from rs9 import nebular080_universal_workflow as workflow  # noqa: E402
from rs9 import tf_pypi_nebular080_publish as publish  # noqa: E402
from rs9 import wheel_nebular080_universal as wheel  # noqa: E402
from rs9 import tf_pypi_universal_support as support  # noqa: E402
from rs9.nebular080_smoke_support import (  # noqa: E402
    _REQUIRED_FIXTURES,
    _REQUIRED_SUPPORT,
    _REQUIRED_TOOLS,
    _closure_digest,
)


def _entry(path: str, digest: str = "a" * 64, size: int = 1) -> dict[str, object]:
    return {"path": path, "size": size, "sha256": digest}


def _support(target: str) -> tuple[dict[str, object], dict[str, dict[str, object]]]:
    source = {
        "authority": "authenticated-product-source",
        "repository": coords.REPOSITORY,
        "commit": "0" * 40,
        "tree": "1" * 40,
        "record_sha256": "2" * 64,
        "authority_identity": "3" * 64,
    }
    files: list[dict[str, object]] = []
    evidence: dict[str, dict[str, object]] = {}
    fixture_root = "docs/examples/v0.4/brand-system/core-minimal"
    paths = (["tools/" + name for name in sorted(_REQUIRED_TOOLS)]
             + sorted(_REQUIRED_FIXTURES) + sorted(_REQUIRED_SUPPORT))
    for path in paths:
        role = "application-smoke" if path == "tools/native-rc-smoke.mjs" else (
            "verifier-support" if path in _REQUIRED_SUPPORT else
            "fixture" if path.startswith(fixture_root + "/") else "verifier-module"
        )
        row = {"path": path, "size": 1, "sha256": "a" * 64, "blob": "b" * 40, "role": role,
               "evidence_path": "closure/" + path}
        files.append(row)
        evidence[row["evidence_path"]] = _entry(row["evidence_path"], "a" * 64)
    archive_ref = {
        "path": "archives/theme-forge-nebular-fusion-v0.8.0-source.tar.gz",
        "size": 1, "sha256": "c" * 64, "evidence_path": "closure/source.tar.gz",
    }
    authority_ref = {
        "path": "metadata/nebular-compiled-public-build-source-authority-v0.8.0.json",
        "size": 1, "sha256": "d" * 64, "evidence_path": "closure/source-authority.json",
    }
    evidence[archive_ref["evidence_path"]] = _entry(archive_ref["evidence_path"], "c" * 64)
    evidence[authority_ref["evidence_path"]] = _entry(authority_ref["evidence_path"], "d" * 64)
    value: dict[str, object] = {
        "schema": "rs9.nebular080-smoke-support.v1",
        "target": target,
        "source": source,
        "root": "closure",
        "tool_root": "tools",
        "fixture_root": fixture_root,
        "source_binding": {"archive": archive_ref, "authority": authority_ref},
        "files": files,
    }
    value["closure_sha256"] = _closure_digest(value)
    return value, evidence


class UniversalSupportTests(unittest.TestCase):
    def test_coordinates_are_closed_to_080(self):
        self.assertEqual(coords.VERSION, "0.8.0")
        self.assertEqual(coords.TAG, "v0.8.0")
        self.assertEqual(coords.WORKFLOW_PUSH_BRANCH, "rs9-tfnf-pypi-hostqual1")
        self.assertEqual(coords.NEBULAR080_COORDINATES.environment, "pypi")
        self.assertEqual(set(coords.TARGETS), {"darwin-arm64", "linux-arm64-gnu", "linux-x64-gnu"})
        self.assertEqual(coords.LICENSE_EXPRESSION, coords.EXPECTED_LICENSE_EXPRESSION)
        self.assertEqual(coords.REQUIRES_PYTHON, coords.EXPECTED_REQUIRES_PYTHON)
        self.assertEqual(coords.READBACK_SCHEDULE, coords.READBACK_SCHEDULE_SECONDS)

    def test_real_operator_readme_and_runtime_inputs_bind_builder_contract(self):
        description_path = OUTPUT / coords.DESCRIPTION
        runtime_path = OUTPUT / coords.RUNTIME_INPUTS
        self.assertTrue(description_path.is_file())
        self.assertTrue(runtime_path.is_file())

        description = publication._read(description_path, 262144, "DESCRIPTION")
        runtime_bytes = publication._read(runtime_path, 65536, "RUNTIME_INPUTS")
        runtime = wheel._inputs(runtime_bytes)
        self.assertEqual(len(description), 6764)
        self.assertEqual(len(runtime_bytes), 7436)
        self.assertEqual(sha256(description), "3dce6c6699bb471b05bc80a117a74a6a7df11418ea121ff965d11e5ff1d4c397")
        self.assertEqual(sha256(runtime_bytes), "2d972cd984233f732a3731b6c709846d5b6aefc1eb1d4715fd31848c89ada4d4")
        self.assertEqual(runtime["project"], coords.PROJECT)
        self.assertEqual(runtime["version"], coords.VERSION)
        self.assertEqual(set(runtime["targets"]), set(coords.TARGETS))
        self.assertEqual(
            runtime["upstream_release"],
            {
                "commit": "516f5a7d8a449946a0246ea23d37991f586dfc2c",
                "repository": "Knowledge-Forge-AI/theme-forge-nebular-fusion",
                "tag": "v0.8.0",
                "tree": "907163a09d2995c9080074294db54c54af626563",
            },
        )
        readme = description.decode("utf-8")
        self.assertIn(f"{coords.DISTRIBUTION_NAME}=={coords.VERSION}", readme)
        self.assertIn(coords.EXPECTED_LICENSE_EXPRESSION, readme)
        for target in coords.TARGETS:
            self.assertIn(runtime["targets"][target]["asset"]["name"], readme)

    def test_new_route_has_no_old_runtime_imports_or_forbidden_edges(self):
        active = sorted(
            path for path in (SRC / "rs9").glob("*.py")
            if path.name.startswith("nebular080_")
            or path.name.startswith("tf_pypi_nebular080_")
            or path.name in {
                "tf_pypi_universal_support.py",
                "nebular_history_guard.py",
                "nebular_history_profiles.py",
                "nebular_workflow_coexistence.py",
            }
        )
        self.assertTrue(active)
        for path in active:
            text = path.read_text()
            tree = ast.parse(text)
            for node in ast.walk(tree):
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    names = [alias.name for alias in node.names]
                    self.assertFalse(any("nebular071" in name for name in names))

    def test_digest_and_relative_path_bounds(self):
        checked = support.validate_file_digest_entry(_entry("evidence/a.json"))
        self.assertEqual(checked["path"], "evidence/a.json")
        with self.assertRaises(AdmissionError):
            support.validate_file_digest_entry(_entry("../a"))
        with self.assertRaises(AdmissionError):
            support.validate_file_digest_entry(_entry("a", size=0))
        with self.assertRaises(AdmissionError):
            support.validate_file_digest_entry(_entry("a", digest="G" * 64))

    def test_containment_and_symlink_checks_are_nofollow(self):
        with tempfile.TemporaryDirectory(dir=OUTPUT) as raw:
            root = Path(raw) / "repo"
            root.mkdir()
            (root / "evidence").mkdir()
            self.assertEqual(
                support.resolve_repo_contained_dir(root, "evidence").name,
                "evidence",
            )
            with self.assertRaises(AdmissionError):
                support.resolve_repo_contained_dir(root, "../evidence")
            outside = Path(raw) / "outside"
            outside.mkdir()
            (root / "alias").symlink_to(outside, target_is_directory=True)
            with self.assertRaises(AdmissionError):
                support.resolve_repo_contained_dir(root, "alias")

    def test_inrun_profile_is_exclusive_and_preserves_foreign_root(self):
        spec = {
            "schema": coords.SYSTEM_WEBKIT_INPUT_SCHEMA,
            "origin_kind": "public-in-run",
            "profile_id": coords.SYSTEM_WEBKIT_PROFILE_ID,
        }
        with tempfile.TemporaryDirectory(dir=OUTPUT) as raw:
            root = Path(raw) / "repo"
            root.mkdir()
            foreign = Path(raw) / "run"
            foreign.mkdir()
            self.assertEqual(
                support.resolve_inrun_artifact_root(root, None, foreign, system_webkit_spec=spec),
                foreign.resolve(),
            )
            with self.assertRaises(AdmissionError):
                support.resolve_inrun_artifact_root(root, None, foreign)
            with self.assertRaises(AdmissionError):
                support.resolve_inrun_artifact_root(root, spec, foreign, system_webkit_spec=spec)
            with self.assertRaises(AdmissionError):
                support.resolve_inrun_artifact_root(root, None, root / "child", system_webkit_spec=spec)

    def test_sandbox_prefix_and_user_state_snapshot_are_bounded(self):
        self.assertEqual(support.default_sandbox_prefix("darwin-arm64")[:2], ("/usr/bin/sandbox-exec", "-p"))
        with tempfile.TemporaryDirectory(dir=OUTPUT) as raw:
            home = Path(raw)
            target = home / "Library/Caches/theme-forge-nebular-fusion"
            target.parent.mkdir(parents=True)
            target.write_text("before")
            capture = support.make_real_user_state_snapshotter("darwin-arm64", home_dir=home)
            before = capture("before", "darwin-arm64")
            target.write_text("after")
            after = capture("after", "darwin-arm64")
            self.assertEqual(before["schema"], "nebular.native-rc-persistent-user-state-v1")
            self.assertTrue(after["changed"])

    def test_profile_validator_rejects_manylinux_and_wrong_phase(self):
        valid = {
            "schema": coords.SYSTEM_WEBKIT_INPUT_SCHEMA,
            "origin_kind": "public-in-run",
            "profile_id": coords.SYSTEM_WEBKIT_PROFILE_ID,
        }
        self.assertEqual(inputs.validate_system_webkit_input_spec(valid), valid)
        with self.assertRaises(AdmissionError):
            inputs.validate_system_webkit_input_spec({**valid, "profile_id": "manylinux"})
        with self.assertRaises(AdmissionError):
            inputs.validate_qualification_input_phase("other")

    def test_dispatch_pair_and_shared_guard_are_exact(self):
        self.assertEqual(publish.validate_workflow_dispatch("0.8.0", "universal-qualify")["mode"], "universal-qualify")
        self.assertEqual(publish.validate_workflow_dispatch("0.8.0", "universal-publish")["mode"], "universal-publish")
        for release, mode in (("0.7.1", "universal-qualify"), ("0.8.0", "qualify")):
            with self.assertRaises(AdmissionError):
                publish.validate_workflow_dispatch(release, mode)
        text = publish.workflow_080_qualify_jobs_text()
        self.assertIn("inputs.release == '0.8.0' && (inputs.mode == 'universal-qualify' || inputs.mode == 'universal-publish')", text)
        self.assertIn("environment:\n      name: pypi", text)
        self.assertEqual(publish.rendered_qualification_job_ids(text)[0], "reject_unsupported_dispatch")

    def test_workflow_generator_matches_public_baseline_and_publish_delegation(self):
        baseline_path = OUTPUT / "tests/fixtures/workflows/rs9-tfnf-pypi-publish-baseline.yml"
        committed_path = OUTPUT / ".github/workflows/rs9-tfnf-pypi-publish.yml"
        baseline = baseline_path.read_text(encoding="utf-8")
        committed = committed_path.read_text(encoding="utf-8")
        self.assertEqual(hashlib.sha256(baseline.encode()).hexdigest(), workflow.BASELINE_WORKFLOW_SHA256)
        generated = workflow.complete_workflow_text(baseline)
        self.assertEqual(generated, committed)
        self.assertEqual(generated.count("node-version: '22.23.3'"), 2)
        self.assertEqual(generated.count("node-version: '22.23.4'"), 2)

        qualification = workflow.workflow_080_qualify_jobs_text()
        self.assertEqual(qualification.count("node-version: '22.23.4'"), 2)
        self.assertEqual(qualification.count("node-version: '22.23.3'"), 0)
        self.assertIn(
            "--source-manifest operators/theme-forge-current-202610/nebular080-public-input-manifest.json",
            qualification,
        )
        self.assertIn(
            "--release-binding operators/theme-forge-current-202610/nebular080-release-binding.json",
            qualification,
        )
        self.assertIn(
            '            --repository "$GITHUB_WORKSPACE"\n\n      - name: Upload 0.8.0 public inputs',
            qualification,
        )
        for stale in (
            "--manifest operators/tf-pypi/theme-forge-nebular-fusion-0.8.0-public-inputs.json",
            "--stage-a-spec stage-a-files.json",
            '--rs9-commit "${{ github.sha }}"',
            '--rs9-tree "$(git rev-parse --verify',
        ):
            self.assertNotIn(stale, qualification)

        delegated = publish.workflow_080_qualify_jobs_text()
        self.assertEqual(
            delegated,
            workflow.dispatch_guard_text() + "\n" + qualification + workflow.publication_job_text(),
        )
        delegated_ids = publish.rendered_qualification_job_ids(delegated)
        self.assertEqual(delegated_ids[0], workflow.GUARD_JOB_ID)
        self.assertEqual(delegated_ids[-1], workflow.PUBLICATION_JOB_ID)
        self.assertEqual(
            tuple(job for job in delegated_ids if job in workflow.QUALIFICATION_JOB_IDS),
            workflow.QUALIFICATION_JOB_IDS,
        )

    def test_prepare_cli_binds_route_arguments_without_network_options(self):
        args = publish.parser().parse_args([
            "prepare-public-inputs-080",
            "--source-manifest", "operators/theme-forge-current-202610/nebular080-public-input-manifest.json",
            "--release-binding", "operators/theme-forge-current-202610/nebular080-release-binding.json",
            "--output", "/tmp/nebular080-public-inputs",
            "--repository", "/workspace/release-starport-9",
        ])
        self.assertEqual(args.operation, "prepare-public-inputs-080")
        self.assertEqual(args.repository, Path("/workspace/release-starport-9"))
        self.assertEqual(args.source_manifest, "operators/theme-forge-current-202610/nebular080-public-input-manifest.json")
        self.assertEqual(args.release_binding, "operators/theme-forge-current-202610/nebular080-release-binding.json")
        with self.assertRaises(SystemExit):
            publish.parser().parse_args([
                "prepare-public-inputs-080",
                "--manifest", "legacy-descriptor.json",
                "--output", "/tmp/nebular080-public-inputs",
                "--repository", "/workspace/release-starport-9",
            ])
        dispatch = publish.parser().parse_args([
            "validate-dispatch", "--release", "0.8.0", "--mode", "universal-qualify",
        ])
        self.assertEqual(publish.validate_workflow_dispatch(dispatch.release, dispatch.mode)["release"], "0.8.0")

    def test_cli_dispatch_emits_canonical_result(self):
        class _Stdout:
            def __init__(self):
                self.buffer = io.BytesIO()

        stdout = _Stdout()
        with mock.patch.object(publish.sys, "stdout", stdout):
            self.assertEqual(publish.main([
                "validate-dispatch", "--release", "0.8.0", "--mode", "universal-publish",
            ]), 0)
        self.assertEqual(json.loads(stdout.buffer.getvalue()), {
            "release": "0.8.0", "mode": "universal-publish",
        })

    def test_history_separates_predecessor_and_current_release(self):
        common = {
            "workflow_id": 1,
            "head_sha": "0" * 40,
            "head_branch": "main",
            "event": "workflow_dispatch",
            "status": "completed",
            "conclusion": "success",
            "run_attempt": 1,
            "path": ".github/workflows/rs9-tfnf-pypi-publish.yml",
        }
        rows = [
            {
                **common,
                "id": 1,
                "name": "RS9 theme-forge-nebular-fusion 0.7.1 universal-qualify / old",
                "inputs": {"release": "0.7.1", "mode": "universal-qualify", "dispatch_id": "old"},
            },
            {
                **common,
                "id": 2,
                "name": "RS9 theme-forge-nebular-fusion 0.8.0 universal-publish / new",
                "inputs": {"release": "0.8.0", "mode": "universal-publish", "dispatch_id": "new"},
            },
        ]
        self.assertEqual(
            publish.verify_history_fixture(
                rows,
                api_get=lambda url: (
                    {"total_count": len(rows), "workflow_runs": rows}
                    if "/actions/workflows/" in url else {}
                ),
                additional_run_validator=lambda _row, _api_get: True,
            ),
            {"080": 1, "predecessor": 1},
        )
        with self.assertRaises(TypeError):
            publish.check_prior_publish_runs(runs=[{**rows[1], "name": "malformed"}], environ={"GITHUB_RUN_ATTEMPT": "1"})

    def test_history_pagination_is_bounded_and_consistent(self):
        calls = []

        def client(url):
            calls.append(url)
            if "page=2" in url:
                return {"total_count": 2, "workflow_runs": [{"id": 2}]}
            return {"total_count": 2, "workflow_runs": [{"id": 1}]}

        self.assertEqual(
            publish._fetch_paginated_github_list("https://example.invalid/runs?per_page=1", "workflow_runs", client),
            [{"id": 1}, {"id": 2}],
        )
        self.assertEqual(calls, ["https://example.invalid/runs?per_page=1", "https://example.invalid/runs?per_page=1&page=2"])

        def changing_total(url):
            return {"total_count": 2 if "page=2" not in url else 1, "workflow_runs": [{"id": 1}]}

        with self.assertRaises(AdmissionError):
            publish._fetch_paginated_github_list("https://example.invalid/runs", "workflow_runs", changing_total)

    def test_route_owned_gates_are_not_reimplemented_in_publisher_seam(self):
        universal = (ROUTE_OWNER / "tf_pypi_nebular080_universal.py").read_text(encoding="utf-8")
        publication = (ROUTE_OWNER / "nebular080_universal_publication.py").read_text(encoding="utf-8")
        for name in ("build_bundle", "qualify_native", "check_system_webkit_missing", "admit_matrix", "read_matrix_inputs"):
            self.assertIn(f"def {name}(", universal)
            self.assertFalse(hasattr(publish, name), name)
        for name in ("verify_capture", "select_missing", "verify_upload", "readback"):
            self.assertIn(f"def {name}(", publication)
            self.assertFalse(hasattr(publish, name), name)

    def test_native_ci_evidence_paths_are_admitted_without_path_rewriting(self):
        support_value, evidence = _support("linux-x64-gnu")
        self.assertTrue(any(path.startswith("closure/") for path in evidence))
        evidence["native-ci/run.json"] = _entry("native-ci/run.json", "e" * 64)
        entry = {
            "schema": coords.RAW_RELEASE_HANDOFF_SCHEMA,
            "target": "linux-x64-gnu",
            "record": _entry("record.json"), "readme": _entry("README.md"),
            "payload": _entry("payload.tar.gz"), "manifest": _entry("manifest.json"),
            "provenance": _entry("provenance.json"),
            "legal_files": {name: _entry(name) for name in ("LICENSE", "NOTICE", "COMMERCIAL-LICENSE.md")},
            "native_consumer": {"linux-x64-gnu": {"smoke_support": support_value}},
            "product_source": support_value["source"],
        }
        inputs.validate_descriptor_target_raw_release(
            "linux-x64-gnu", entry, evidence_files=evidence,
            expected_product_source=support_value["source"],
        )

    def test_positive_descriptor_resolver_accepts_native_ci_rows(self):
        with tempfile.TemporaryDirectory(dir=OUTPUT) as raw:
            repository = Path(raw)
            evidence_root = repository / "evidence-root"
            raw_root = repository / "raw-root"
            evidence_root.mkdir()
            raw_root.mkdir()
            bootstrap = repository / "bootstrap.json"
            expectations = repository / "expectations.json"
            bootstrap.write_bytes(b"bootstrap")
            expectations.write_bytes(b"expectations")
            source_value, support_files = _support("linux-x64-gnu")
            evidence_files: dict[str, dict[str, object]] = {
                path: dict(value) for path, value in support_files.items()
            }
            for path in (
                "api/release.json", "api/repository.json", "api/ref.json", "api/commit.json",
                "api/tree.json", "assets/SHA256SUMS", "assets/PROVENANCE.json", "npm/metadata.json",
                "npm/package.tgz", "source/LICENSE", "source/NOTICE", "native-ci/run.json",
            ):
                evidence_files[path] = _entry(path, "e" * 64)
            for path in evidence_files:
                target = evidence_root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(b"x")
            binding = {
                "schema": "rs9.nebular080-release-binding.v1alpha1",
                "release": "0.8.0", "application_version": "0.8.0", "distribution_version": "0.8.0",
                "repository": coords.REPOSITORY, "tag": "v0.8.0",
                "bootstrap_path": "bootstrap.json", "expectations_path": "expectations.json",
                "profile_path": str(coords.GATE1_PROFILE_PATH), "status": "ready",
                "lineage": {"mode": "direct-tag-provenance-equality", "requires_historical_author_rewrite": False},
                "provenance": {"path": "PROVENANCE.json", "commit_field": "tagCommit", "tree_field": "tagTree"},
                "expected": {
                    "repository_id": 1, "release_id": 2, "tag_commit": "0" * 40, "tag_tree": "1" * 40,
                    "bootstrap_sha256": sha256(b"bootstrap"), "expectations_sha256": sha256(b"expectations"),
                },
            }
            entries = {}
            for target in coords.TARGETS:
                target_support, target_support_files = _support(target)
                entries[target] = {
                    "schema": coords.RAW_RELEASE_HANDOFF_SCHEMA, "target": target,
                    "record": _entry(f"{target}/record.json"), "readme": _entry(f"{target}/README.md"),
                    "payload": _entry(f"{target}/payload.tar.gz"), "manifest": _entry(f"{target}/manifest.json"),
                    "provenance": _entry(f"{target}/provenance.json"),
                    "legal_files": {name: _entry(f"{target}/{name}") for name in ("LICENSE", "NOTICE", "COMMERCIAL-LICENSE.md")},
                    "native_consumer": {target: {"smoke_support": target_support}},
                    "product_source": target_support["source"],
                }
                for path, value in target_support_files.items():
                    evidence_files.setdefault(path, dict(value))
            for path in evidence_files:
                target = evidence_root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                if not target.exists():
                    target.write_bytes(b"x")
            descriptor = {
                "schema": coords.QUALIFICATION_INPUTS_SCHEMA, "project": coords.PROJECT,
                "version": "0.8.0", "distribution_version": "0.8.0", "workflow": coords.WORKFLOW,
                "status": "ready",
                "upstream_origin": {
                    "repository": coords.REPOSITORY, "tag": "v0.8.0",
                    "release_url": "https://github.com/Knowledge-Forge-AI/theme-forge-nebular-fusion/releases/tag/v0.8.0",
                    "api_release_url": "https://api.github.com/repos/Knowledge-Forge-AI/theme-forge-nebular-fusion/releases/tags/v0.8.0",
                },
                "release_binding": binding,
                "release_binding_sha256": sha256(canonical(binding)),
                "system_webkit": {
                    "schema": coords.SYSTEM_WEBKIT_INPUT_SCHEMA,
                    "origin_kind": "public-in-run", "profile_id": coords.SYSTEM_WEBKIT_PROFILE_ID,
                },
                "evidence": {"source_root": "evidence-root", "files": evidence_files},
                "raw_release": {"source_root": "raw-root", "targets": entries},
            }
            checked = inputs.validate_qualification_inputs_descriptor(
                descriptor, repository=repository, phase=coords.QUALIFICATION_INPUT_PHASE_PREP,
            )
            self.assertEqual(checked["raw_release"]["targets"]["linux-x64-gnu"]["target"], "linux-x64-gnu")
            self.assertIn("native-ci/run.json", checked["evidence"]["files"])

    def test_native_ci_stager_binds_fixed_rows_and_rejects_missing_or_tampered_source(self):
        with tempfile.TemporaryDirectory(dir=OUTPUT) as raw:
            root = Path(raw)
            capsule = root / "capsule"
            run = root / "run"
            capsule.mkdir()
            run.mkdir()
            foreign = run / "evidence" / "public-release" / "foreign.json"
            foreign.parent.mkdir(parents=True)
            foreign.write_bytes(b"keep")
            rows = {}
            source_bodies = {}
            for name in sorted(native_owner._descriptor_names()):
                body = ("native-row:" + name).encode()
                source_path = capsule / name
                source_path.parent.mkdir(parents=True, exist_ok=True)
                source_path.write_bytes(body)
                source_bodies[name] = body
                rows["native-ci/" + name] = {
                    "path": "native-ci/" + name,
                    "size": len(body),
                    "sha256": hashlib.sha256(body).hexdigest(),
                }
            descriptor = {
                "evidence": {"source_root": "evidence/public-release", "files": rows},
            }
            result = inputs.stage_native_ci_evidence(capsule, run, descriptor)
            self.assertEqual(result["file_count"], len(rows))
            self.assertEqual(result["descriptor_sha256"], sha256(canonical(descriptor)))
            self.assertEqual(foreign.read_bytes(), b"keep")
            self.assertEqual(
                (run / "evidence" / "public-release" / "native-ci" / "native-reference.json").read_bytes(),
                source_bodies["native-reference.json"],
            )

            missing_run = root / "missing-run"
            missing_run.mkdir()
            missing_name = sorted(native_owner._descriptor_names())[0]
            (capsule / missing_name).unlink()
            with self.assertRaises(AdmissionError):
                inputs.stage_native_ci_evidence(capsule, missing_run, descriptor)
            self.assertFalse((missing_run / "evidence" / "public-release" / "native-ci").exists())
            (capsule / missing_name).write_bytes(source_bodies[missing_name])

            tampered_run = root / "tampered-run"
            tampered_run.mkdir()
            (capsule / missing_name).write_bytes(b"tampered")
            with self.assertRaises(AdmissionError):
                inputs.stage_native_ci_evidence(capsule, tampered_run, descriptor)
            self.assertFalse((tampered_run / "evidence" / "public-release" / "native-ci").exists())

            symlink_run = root / "symlink-run"
            symlink_run.mkdir()
            outside = root / "outside"
            outside.mkdir()
            (symlink_run / "evidence").symlink_to(outside, target_is_directory=True)
            (capsule / missing_name).write_bytes(source_bodies[missing_name])
            with self.assertRaises(AdmissionError):
                inputs.stage_native_ci_evidence(capsule, symlink_run, descriptor)

    def test_native_ci_stager_preserves_foreign_leaf_inserted_before_exclusive_write(self):
        with tempfile.TemporaryDirectory(dir=OUTPUT) as raw:
            root = Path(raw)
            capsule = root / "capsule"
            run = root / "run"
            capsule.mkdir()
            run.mkdir()
            rows = {}
            for name in sorted(native_owner._descriptor_names()):
                body = ("native-row:" + name).encode()
                source_path = capsule / name
                source_path.parent.mkdir(parents=True, exist_ok=True)
                source_path.write_bytes(body)
                rows["native-ci/" + name] = {
                    "path": "native-ci/" + name,
                    "size": len(body),
                    "sha256": hashlib.sha256(body).hexdigest(),
                }
            descriptor = {
                "evidence": {"source_root": "evidence/public-release", "files": rows},
            }
            real_writer = inputs.write_exclusive
            raced = False

            def insert_foreign_leaf(path, data, **kwargs):
                nonlocal raced
                if not raced:
                    Path(path).write_bytes(b"foreign-race")
                    raced = True
                return real_writer(path, data, **kwargs)

            with mock.patch.object(inputs, "write_exclusive", side_effect=insert_foreign_leaf):
                with self.assertRaises(AdmissionError):
                    inputs.stage_native_ci_evidence(capsule, run, descriptor)
            self.assertTrue(raced)
            target = run / "evidence" / "public-release" / "native-ci" / sorted(native_owner._descriptor_names())[0]
            self.assertEqual(target.read_bytes(), b"foreign-race")

    def test_descriptor_rejects_pending_or_mixed_profile_before_files(self):
        minimal = {
            "schema": coords.QUALIFICATION_INPUTS_SCHEMA,
            "project": coords.PROJECT, "version": "0.8.0", "distribution_version": "0.8.0",
            "workflow": coords.WORKFLOW, "status": "pending",
        }
        with self.assertRaises(AdmissionError):
            inputs.validate_qualification_inputs_descriptor(minimal, phase=coords.QUALIFICATION_INPUT_PHASE_PREP)
        with self.assertRaises(AdmissionError):
            inputs.validate_qualification_inputs_descriptor({**minimal, "status": "ready", "manylinux": {}}, phase=coords.QUALIFICATION_INPUT_PHASE_PREP)

    def test_prepared_module_hashes_are_bound_and_pending_rebind_is_explicit(self):
        expected = {
            "nebular080_universal_profile.py": "a967c0162f04e4e551a5c50bb2536fef6f5825327eab2b277cf48408eddb0f10",
            "nebular080_universal_fetch.py": "aaaeb29ed19e8675f1fe802a370dc05fb2d8398273530b0f395e823ba9e8deb8",
            "nebular080_universal_launcher.py": "7a0e235e3d750a21a77ce7b7a7dba15ee91e3414c9ab5ec27c8b001325d4cbfa",
            "wheel_nebular080_universal.py": "249c69fdf9960e5de89d487630e2e27428af8f976da7eac13b2f077fb88066b5",
            "nebular080_product_capture.py": "748837dab28413b365fda3277549974692fb112197bba0ecd3118a4e131a629c",
            "nebular080_smoke_support.py": "17f4180b47ca02898a51e7249a56841c7a687f7bb6ed827b0c2e2301f32a8290",
            "nebular080_universal_consumer.py": "c91c4b41c485b3758224337dff594bbb4c01e084818c0a3568ae6075b04449a6",
        }
        roots = {name: SRC / "rs9" / name for name in expected}
        for name, digest in expected.items():
            actual = hashlib.sha256(roots[name].read_bytes()).hexdigest()
            self.assertEqual(actual, digest, name)

    def test_support_output_is_exclusive_and_foreign_files_survive(self):
        with tempfile.TemporaryDirectory(dir=OUTPUT) as raw:
            root = Path(raw)
            foreign = root / "foreign.txt"
            foreign.write_text("keep")
            owned = root / "owned.json"
            support.write_exclusive(owned, b"{}")
            self.assertEqual(foreign.read_text(), "keep")
            with self.assertRaises(AdmissionError):
                support.write_exclusive(owned, b"changed")


if __name__ == "__main__":
    unittest.main()

