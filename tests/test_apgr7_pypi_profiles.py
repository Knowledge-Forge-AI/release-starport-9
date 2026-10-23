"""Focused contracts for the closed APGR PyPI release profiles."""
import base64
import hashlib
import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from rs9 import apgr7_pypi as pypi
from rs9 import apgr7_pypi_deploy as deploy
from rs9 import apgr7_pypi_runs as runs
from rs9 import apgr7_pypi_workflow as workflow
from rs9.apgr7_python import verify_artifact
from rs9.errors import ContractError
from tests.test_burst_platform_wheel import make_synthetic_macho

ROOT = Path(__file__).resolve().parents[1]
OLD_MANIFEST = ROOT / "operators/apgr-publication/pypi-artifacts.json"
OLD_MANIFEST_SHA256 = "ef5e96f5ffd45b10b85ee2db22cebc677d7027b79f5ba5a3247f52c55c76df8d"


def _v0131_manifest():
    profile = pypi.profile_for_version("0.13.1")
    return {
        "schema": "rs9.pypi-artifacts.v1alpha2",
        "project": pypi.PROJECT_NAME,
        "version": "0.13.1",
        "repository": "Knowledge-Forge-AI/agentic-praxis-grimoire",
        "release_tag": profile["release_tag"],
        "artifacts": [
            {
                "name": name,
                "size": 1,
                "sha256": "0" * 64,
                "url": "https://github.com/Knowledge-Forge-AI/agentic-praxis-grimoire/releases/download/"
                + profile["release_tag"] + "/" + name,
            }
            for name in profile["artifact_names"]
        ],
        "excluded": [],
    }


def _apgr_darwin_wheel(version: str, tag: str, minimum: tuple[int, int], *, malformed: bool = False) -> bytes:
    """Build a strict APGR wheel fixture around the maintained Mach-O builder."""
    dist_info = f"agentic_praxis_grimoire-{version}.dist-info"
    members = {
        "agentic_praxis_grimoire/__init__.py": b"__version__ = 'fixture'\n",
        "agentic_praxis_grimoire/bin/apgr": (
            make_synthetic_macho(arch="arm64", major=minimum[0], minor=minimum[1], omit_load_command=malformed)
        ),
        f"{dist_info}/METADATA": (
            f"Metadata-Version: 2.4\nName: agentic-praxis-grimoire\nVersion: {version}\n"
            "License-Expression: AGPL-3.0-or-later\nRequires-Python: >=3.12\n\n"
        ).encode(),
        f"{dist_info}/WHEEL": (
            f"Wheel-Version: 1.0\nGenerator: rs9-fixture\nRoot-Is-Purelib: false\nTag: py3-none-{tag}\n\n"
        ).encode(),
    }
    record_rows = []
    for name, data in sorted(members.items()):
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode("ascii").rstrip("=")
        record_rows.append(f"{name},sha256={digest},{len(data)}")
    record_rows.append(f"{dist_info}/RECORD,,")
    members[f"{dist_info}/RECORD"] = ("\n".join(record_rows) + "\n").encode("utf-8")

    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(members.items()):
            archive.writestr(name, data)
    return output.getvalue()


class APGRPyPIProfileTests(unittest.TestCase):
    def test_darwin_wheel_admission_closes_v0130_and_v0131_versions(self):
        old_name = "agentic_praxis_grimoire-0.13.0-py3-none-macosx_11_0_arm64.whl"
        old_info = verify_artifact(
            old_name,
            _apgr_darwin_wheel("0.13.0", "macosx_11_0_arm64", (11, 0)),
            expected_project="agentic-praxis-grimoire",
            expected_version="0.13.0",
            expected_license="AGPL-3.0-or-later",
        )
        self.assertEqual(old_info["tag"], "py3-none-macosx_11_0_arm64")

        new_name = "agentic_praxis_grimoire-0.13.1-py3-none-macosx_12_0_arm64.whl"
        new_info = verify_artifact(
            new_name,
            _apgr_darwin_wheel("0.13.1", "macosx_12_0_arm64", (12, 0)),
            expected_project="agentic-praxis-grimoire",
            expected_version="0.13.1",
            expected_license="AGPL-3.0-or-later",
        )
        self.assertEqual(new_info["tag"], "py3-none-macosx_12_0_arm64")

    def test_darwin_wheel_rejects_cross_version_tags_and_mislabeled_floors(self):
        cases = (
            (
                "agentic_praxis_grimoire-0.13.1-py3-none-macosx_11_0_arm64.whl",
                "0.13.1",
                "macosx_11_0_arm64",
                (11, 0),
                "APGR7_PYTHON_METADATA",
            ),
            (
                "agentic_praxis_grimoire-0.13.0-py3-none-macosx_12_0_arm64.whl",
                "0.13.0",
                "macosx_12_0_arm64",
                (12, 0),
                "APGR7_PYTHON_METADATA",
            ),
            (
                "agentic_praxis_grimoire-0.13.1-py3-none-macosx_12_0_arm64.whl",
                "0.13.1",
                "macosx_12_0_arm64",
                (11, 0),
                "APGR7_PYTHON_MACHO",
            ),
            (
                "agentic_praxis_grimoire-0.13.1-py3-none-macosx_12_0_arm64.whl",
                "0.13.1",
                "macosx_12_0_arm64",
                (13, 0),
                "APGR7_PYTHON_MACHO",
            ),
        )
        for name, version, tag, minimum, code in cases:
            with self.subTest(name=name, minimum=minimum):
                with self.assertRaises(ContractError) as raised:
                    verify_artifact(
                        name,
                        _apgr_darwin_wheel(version, tag, minimum),
                        expected_project="agentic-praxis-grimoire",
                        expected_version=version,
                        expected_license="AGPL-3.0-or-later",
                    )
                self.assertEqual(raised.exception.code, code)

        with self.assertRaises(ContractError) as raised:
            verify_artifact(
                "agentic_praxis_grimoire-0.13.1-py3-none-macosx_12_0_arm64.whl",
                _apgr_darwin_wheel("0.13.1", "macosx_12_0_arm64", (12, 0), malformed=True),
                expected_project="agentic-praxis-grimoire",
                expected_version="0.13.1",
                expected_license="AGPL-3.0-or-later",
            )
        self.assertEqual(raised.exception.code, "APGR7_PYTHON_MACHO")

    def test_historical_manifest_bytes_and_profile_remain_unchanged(self):
        self.assertEqual(hashlib.sha256(OLD_MANIFEST.read_bytes()).hexdigest(), OLD_MANIFEST_SHA256)
        self.assertEqual(pypi.manifest_path("0.13.0"), "operators/apgr-publication/pypi-artifacts.json")
        self.assertEqual(len(pypi.profile_for_version("0.13.0")["artifact_names"]), 3)
        self.assertEqual(len(pypi.profile_for_version("0.13.0")["excluded"]), 1)

    def test_only_two_closed_profiles_are_supported(self):
        self.assertEqual(pypi.SUPPORTED_VERSIONS, ("0.13.0", "0.13.1"))
        with self.assertRaises(ContractError) as raised:
            pypi.profile_for_version("0.14.0")
        self.assertEqual(raised.exception.code, "APGR7_PYPI_VERSION")

    def test_low_level_selectors_distinguish_omitted_from_empty_version(self):
        self.assertEqual(runs._selected_version(None), "0.13.0")
        self.assertEqual(deploy._selected_version(None), "0.13.0")
        for selector in (runs._selected_version, deploy._selected_version):
            with self.subTest(selector=selector.__module__):
                with self.assertRaises(ContractError) as raised:
                    selector("")
                self.assertEqual(raised.exception.code, "APGR7_PYPI_VERSION")
        with self.assertRaises(ContractError) as raised:
            runs._context_version({}, "")
        self.assertEqual(raised.exception.code, "APGR7_PYPI_VERSION")

    def test_dispatch_recovery_entry_points_reject_explicit_empty_version(self):
        with self.assertRaises(ContractError) as raised:
            runs.dispatch_workflow(object(), version="")
        self.assertEqual(raised.exception.code, "APGR7_PYPI_VERSION")

        with self.assertRaises(ContractError) as raised:
            deploy.check_deployment_status(object(), version="")
        self.assertEqual(raised.exception.code, "APGR7_PYPI_VERSION")

        class IO:
            pypi_run_version = ""

            def run(self, args):
                raise AssertionError("empty version must stop before API read")

        with self.assertRaises(ContractError) as raised:
            runs.bind_run_status(IO(), 1, expected_head="a" * 40)
        self.assertEqual(raised.exception.code, "APGR7_PYPI_VERSION")

        class Journal:
            def unresolved(self, channel):
                return ["pypi"]

            def context(self, channel, operation):
                return {"version": "0.13.0", "head_sha": "a" * 40}

        recovered = runs.recover_dispatch(IO(), Journal(), version="")
        self.assertEqual(recovered["state"], "reconcile-only")
        self.assertFalse(recovered["retry_safe"])

    def test_publish_rejects_explicit_empty_version_before_prepare_or_dispatch(self):
        class Binding:
            def __init__(self):
                self.sidecar = {"pypi": {"version": "0.13.1"}}

        for prepared_row in (None, {"version": "0.13.1"}):
            with self.subTest(prepared_row=prepared_row):
                with patch.object(pypi, "prepare", side_effect=AssertionError("prepare must not run")), \
                     patch.object(deploy, "dispatch_workflow", side_effect=AssertionError("dispatch must not run")), \
                     self.assertRaises(ContractError) as raised:
                    pypi.publish(Binding(), object(), prepared_row, version="")
                self.assertEqual(raised.exception.code, "APGR7_PYPI_VERSION")

    def test_v0131_manifest_is_fail_closed_until_real_pins_exist(self):
        with tempfile.TemporaryDirectory(prefix="rs9-missing-pins-") as directory:
            missing = Path(directory) / pypi.manifest_path("0.13.1")
            self.assertFalse(missing.exists())
            with self.assertRaises(ContractError) as raised:
                pypi.verify_pins(pins_doc=missing, version="0.13.1")
            self.assertEqual(raised.exception.code, "APGR7_PYPI_PINS_MISSING")

    def test_prepare_returns_blocked_without_dispatch_when_v0131_pins_are_missing(self):
        class Binding:
            def __init__(self):
                self.sidecar = {"pypi": {"version": "0.13.1"}}

        class IO:
            def __init__(self, missing):
                self.pypi_pins = missing

        with tempfile.TemporaryDirectory(prefix="rs9-missing-pins-") as directory:
            missing = Path(directory) / pypi.manifest_path("0.13.1")
            row = pypi.prepare(Binding(), IO(missing), version="0.13.1")
            self.assertEqual(row["state"], "blocked")
            self.assertEqual(row["version"], "0.13.1")
            self.assertEqual(row["stops"][0]["code"], "APGR7_PYPI_PINS_MISSING")
            self.assertNotIn("prepared_sha256", row)

    def test_prepare_keeps_unknown_declared_version_neutral(self):
        class Binding:
            def __init__(self):
                self.sidecar = {"pypi": {"version": "0.14.0"}}

        row = pypi.prepare(Binding(), object())
        self.assertIsNone(row["version"])
        self.assertEqual(row["stops"][0]["code"], "APGR7_PYPI_VERSION")

    def test_v0131_profile_accepts_only_exact_versioned_manifest_shape(self):
        pins = _v0131_manifest()
        self.assertEqual(pypi.verify_pins(pins_doc=pins, version="0.13.1"), pins)
        mismatched = json.loads(json.dumps(pins))
        mismatched["release_tag"] = "v0.13.0"
        with self.assertRaises(ContractError) as raised:
            pypi.verify_pins(pins_doc=mismatched, version="0.13.1")
        self.assertEqual(raised.exception.code, "APGR7_PYPI_PIN_DRIFT")

    def test_selected_deployment_closure_preserves_old_route_and_blocks_new_route(self):
        with tempfile.TemporaryDirectory(prefix="rs9-closure-fixture-") as directory:
            fixture = Path(directory)
            (fixture / "src").symlink_to(ROOT / "src", target_is_directory=True)
            workflow_dir = fixture / ".github/workflows"
            workflow_dir.mkdir(parents=True)
            (workflow_dir / "rs9-pypi-publish.yml").symlink_to(ROOT / ".github/workflows/rs9-pypi-publish.yml")
            manifest_dir = fixture / "operators/apgr-publication"
            manifest_dir.mkdir(parents=True)
            (manifest_dir / "pypi-artifacts.json").symlink_to(ROOT / "operators/apgr-publication/pypi-artifacts.json")

            closure = deploy.readback_transitive_import_closure(root=fixture, version="0.13.0")
            paths = {row["path"] for row in closure["files"]}
            self.assertIn("operators/apgr-publication/pypi-artifacts.json", paths)
            self.assertNotIn("operators/apgr-publication/pypi-artifacts-v0.13.1.json", paths)
            with self.assertRaises(ContractError) as raised:
                deploy.readback_transitive_import_closure(root=fixture, version="0.13.1")
            self.assertEqual(raised.exception.code, "APGR7_DEPLOY_CLOSURE")

    def test_handoff_contains_selected_version(self):
        handoff = runs.dispatch_workflow(
            object(), version="0.13.1", prepared_sha256="a" * 64,
        )
        self.assertEqual(handoff["state"], "handoff-emitted")
        command = handoff["handoff"]["command"]
        self.assertIn("release_version=0.13.1", command)
        self.assertNotIn("release_version=0.13.0", command)

        old_handoff = runs.dispatch_workflow(
            object(), version="0.13.0", prepared_sha256="b" * 64,
        )
        self.assertIn("release_version=0.13.0", old_handoff["handoff"]["command"])

    def test_legacy_and_versioned_journal_contexts_resolve_and_match_titles(self):
        legacy = {"head_sha": "a" * 40, "display_title": "RS9 PyPI " + "a" * 64 + " / legacy-id"}
        self.assertEqual(runs._context_version(legacy), "0.13.0")
        self.assertEqual(runs._context_version(legacy, "0.13.0"), "0.13.0")
        with self.assertRaises(ContractError) as raised:
            runs._context_version(legacy, "0.13.1")
        self.assertEqual(raised.exception.code, "APGR7_PYPI_VERSION")

        legacy_doc = {
            "head_sha": legacy["head_sha"],
            "event": "workflow_dispatch",
            "head_branch": "main",
            "path": ".github/workflows/rs9-pypi-publish.yml",
            "display_title": legacy["display_title"],
        }
        self.assertTrue(runs._matches(legacy_doc, legacy))

        versioned = {
            "version": "0.13.1",
            "head_sha": "b" * 40,
            "display_title": "RS9 PyPI 0.13.1 / " + "b" * 64 + " / versioned-id",
        }
        versioned_doc = {
            "head_sha": versioned["head_sha"],
            "event": "workflow_dispatch",
            "head_branch": "main",
            "path": ".github/workflows/rs9-pypi-publish.yml",
            "display_title": versioned["display_title"],
        }
        self.assertTrue(runs._matches(versioned_doc, versioned))
        versioned_doc["display_title"] = legacy["display_title"]
        self.assertFalse(runs._matches(versioned_doc, versioned))

    def test_bind_without_journal_refuses_unverified_version_title(self):
        class IO:
            pypi_run_version: str | None

            def __init__(self, title):
                self.title = title

            def run(self, args):
                return {
                    "returncode": 0,
                    "stdout": json.dumps({
                        "id": 1,
                        "head_sha": "a" * 40,
                        "event": "workflow_dispatch",
                        "head_branch": "main",
                        "path": ".github/workflows/rs9-pypi-publish.yml",
                        "display_title": self.title,
                        "status": "completed",
                        "conclusion": "success",
                    }).encode(),
                }

        legacy_title = "RS9 PyPI " + "a" * 64 + " / legacy-id"
        bound = runs.bind_run_status(IO(legacy_title), 1, expected_head="a" * 40, version="0.13.0")
        self.assertEqual(bound["version"], "0.13.0")

        with self.assertRaises(ContractError) as raised:
            runs.bind_run_status(IO("RS9 PyPI 0.13.1 / " + "a" * 64 + " / versioned-id"), 1,
                                 expected_head="a" * 40, version="0.13.0")
        self.assertEqual(raised.exception.code, "APGR7_RUN_BINDING")

    def test_deployment_reconciliation_refuses_missing_or_cross_version_journals(self):
        class Journal:
            def __init__(self, context):
                self._context = context
                self.finished = False

            def unresolved(self, channel):
                return ["workflow-deployment"]

            def context(self, channel, operation):
                return self._context

            def finish(self, *args):
                self.finished = True

            def record_reconciliation(self, *args):
                return "r" * 64

        observed = {"deployment_state": "absent", "transitive_closure": {"closure_sha256": "c" * 64}}
        for context in ({"version": "0.13.0"}, {"phase": "before-ref-request", "closure_sha256": "c" * 64}):
            with self.subTest(context=context):
                journal = Journal(context)
                with patch.object(deploy, "check_deployment_status", return_value=observed), \
                     self.assertRaises(ContractError) as raised:
                    deploy.deployment_reconciliation(object(), journal, version="0.13.1")
                self.assertEqual(raised.exception.code, "APGR7_PYPI_VERSION")
                self.assertFalse(journal.finished)

    def test_recover_dispatch_mismatched_context_is_uncertain(self):
        class Journal:
            def unresolved(self, channel):
                return ["pypi"]

            def context(self, channel, operation):
                return {"version": "0.13.0", "head_sha": "a" * 40}

        class IO:
            def run(self, args):
                raise AssertionError("mismatched context must stop before API read")

        observed = runs.recover_dispatch(IO(), Journal(), version="0.13.1")
        self.assertEqual(observed["state"], "reconcile-only")
        self.assertFalse(observed["retry_safe"])

    def test_workflow_rejects_manifest_version_mismatch_and_missing_future_manifest(self):
        with self.assertRaises(ContractError) as raised:
            workflow._selected_version(_v0131_manifest(), version="0.13.0")
        self.assertEqual(raised.exception.code, "APGR7_PYPI_VERSION")

        with tempfile.TemporaryDirectory(prefix="rs9-missing-pins-") as directory:
            missing = Path(directory) / pypi.manifest_path("0.13.1")
            with patch.object(workflow, "manifest_path", return_value=str(missing)):
                with self.assertRaises(ContractError) as raised:
                    workflow._load_manifest("0.13.1")
            self.assertEqual(raised.exception.code, "APGR7_PYPI_PINS_MISSING")

    def test_legacy_journal_defaults_to_v0130_but_cross_version_is_rejected(self):
        class Journal:
            def context(self, channel, operation):
                return {"version": "0.13.1", "head_sha": "a" * 40}

        with self.assertRaises(ContractError) as raised:
            runs.bind_run_status(object(), 1, journal=Journal(), version="0.13.0")
        self.assertEqual(raised.exception.code, "APGR7_PYPI_VERSION")

    def test_workflow_requires_and_forwards_release_version(self):
        workflow = (ROOT / ".github/workflows/rs9-pypi-publish.yml").read_text(encoding="utf-8")
        self.assertIn("release_version:", workflow)
        self.assertIn("required: true", workflow)
        self.assertIn("type: choice", workflow)
        self.assertIn("- '0.13.0'", workflow)
        self.assertIn("- '0.13.1'", workflow)
        self.assertIn("RELEASE_VERSION: ${{ inputs.release_version }}", workflow)
        self.assertIn("download --version \"$RELEASE_VERSION\"", workflow)
        self.assertIn("select-missing --version \"$RELEASE_VERSION\"", workflow)
        self.assertFalse(any(
            "${{ inputs.release_version }}" in line
            for line in workflow.splitlines()
            if line.lstrip().startswith("run:")
        ))
        self.assertIn("RS9 PyPI ${{ inputs.release_version }}", workflow)


if __name__ == "__main__":
    unittest.main()
