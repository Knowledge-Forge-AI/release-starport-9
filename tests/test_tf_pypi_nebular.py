"""Unit and contract tests for Theme Forge Nebular Fusion native Darwin PyPI publisher."""
from __future__ import annotations

import ast
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from rs9.tf_pypi_archive import AdmissionError, canonical, sha256
from rs9.tf_pypi_nebular import (
    APPROVAL_SCHEMA,
    DISTRIBUTION_NAME,
    ENVIRONMENT,
    EXPECTED_COMMAND,
    EXPECTED_LICENSE_EXPRESSION,
    EXPECTED_LICENSE_FILES,
    EXPECTED_MEMBER_COUNT,
    EXPECTED_REQUIRES_PYTHON,
    EXPECTED_WHEEL_FILENAME,
    EXPECTED_WHEEL_TAG,
    MAX_NON_PAYLOAD_MEMBER_BYTES,
    MAX_TOTAL_UNCOMPRESSED_BYTES,
    PACKAGE_NAME,
    PROJECT,
    PYPI_DEFAULT_FILE_LIMIT,
    QUALIFY_BRANCH,
    READBACK_SCHEDULE_SECONDS,
    SANDBOX_PROFILE,
    STELLAR_FIXTURE_PREFIX,
    SUPERSEDED_PRELIMINARY_SHA256,
    SYSTEM,
    VERSION,
    WORKFLOW,
    _check_orphan_processes,
    _extract_plist_from_payload_tar,
    _github_client,
    analyze_embedded_python_floor,
    approval_path,
    authenticate_captured,
    bind_prepared_closure,
    check_prior_publish_runs,
    compute_set_sha256,
    exact_state,
    inspect_candidate,
    load_approval,
    main,
    parser,
    probe_network_denial,
    project_state,
    readback,
    select_missing,
    source_tree_state,
    validate_approval_schema,
    verify_approved,
    verify_cross_zlib_wheel,
    verify_ps_observer,
    verify_python39_refusal,
    verify_upload_dir,
    workflow_text,
)
from tests.tf_pypi_fixtures import ROOT

EXPECTED_PINNED_ACTIONS = {
    "actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09",
    "actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1",
    "actions/setup-node@249970729cb0ef3589644e2896645e5dc5ba9c38",
    "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
    "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093",
    "pypa/gh-action-pypi-publish@ed0c53931b1dc9bd32cbe73a98c7f6766f8a527e",
}


def build_synthetic_approved_wheel(
    base_approval: dict,
    dest_dir: Path,
    *,
    requires_python: str = EXPECTED_REQUIRES_PYTHON,
    wheel_tag: str = EXPECTED_WHEEL_TAG,
    extra_entries: dict[str, bytes] | None = None,
    mutate_helper: bool = False,
    mutate_launcher: bool = False,
    bad_record: bool = False,
    bad_mode: bool = False,
) -> tuple[Path, dict]:
    """Build a synthetic small wheel and matching approval document for fast unit testing."""
    from rs9.wheel_native import (
         format_record,
        get_embedded_rs9_helpers,
        render_native_launcher,
    )
    from rs9.scratch import canonical as scratch_canonical
    from rs9.tf_pypi_model import logical_identity
    from tests.test_wheel_native import make_darwin_archive, make_standard_darwin_entries

    payload_bytes = make_darwin_archive(make_standard_darwin_entries(min_os="13.0.0"))
    payload_sha = sha256(payload_bytes)
    payload_name = base_approval["payload_asset"]["name"]
    manifest_sha = base_approval["payload_asset"]["payload_manifest_sha256"]
    launcher_rel = base_approval["payload_asset"]["launcher_path"]
    release_sha = base_approval["authentication"]["nebular"]["release_record_sha256"]
    dist_info = f"{PACKAGE_NAME}-{VERSION}.dist-info"
    helpers = get_embedded_rs9_helpers()

    launcher_bytes = render_native_launcher(
        payload_name,
        manifest_sha,
        payload_sha,
        launcher_rel,
        platform_family="darwin",
        target_arch="aarch64",
    ).encode("utf-8")
    if mutate_launcher:
        launcher_bytes += b"\n# mutated\n"

    lic_bytes = b"Synthetic AGPL-3.0-or-later license text.\n"
    notice_bytes = b"Synthetic notice.\n"
    prov_doc = {
        "schema": "rs9.wheel-provenance.v1alpha1",
        "product_id": PROJECT,
        "distribution_name": DISTRIBUTION_NAME,
        "version": VERSION,
        "wheel_tag": wheel_tag,
        "release_record_sha256": release_sha,
        "fixture_only": False,
        "candidate_only": False,
        "candidate_status": "candidate",
        "promotability": "candidate",
        "manylinux_proven": False,
        "helper_source_sha256": {k: sha256(v) for k, v in helpers.items()},
        "payload_archive_sha256": payload_sha,
        "manifest_sha256": manifest_sha,
        "can_publish": False,
    }
    meta_lines = [
        "Metadata-Version: 2.4",
        f"Name: {DISTRIBUTION_NAME}",
        f"Version: {VERSION}",
        "Summary: Theme Forge Nebular Fusion native Darwin application wheel",
        f"License-Expression: {EXPECTED_LICENSE_EXPRESSION}",
        "License-File: LICENSE",
        "License-File: NOTICE",
        f"Requires-Python: {requires_python}",
        "Description-Content-Type: text/plain",
        "",
        "Synthetic test wheel.",
    ]
    wheel_info = (
        f"Wheel-Version: 1.0\nGenerator: rs9-wheel (1.0)\nRoot-Is-Purelib: false\nTag: {wheel_tag}\n"
    ).encode("utf-8")
    entry_points = f"[console_scripts]\ntfnf = {PACKAGE_NAME}.launcher:main_tfnf\n".encode("utf-8")
    init_code = (
        f'"""Theme Forge Nebular Fusion native release package."""\n'
        f"__version__ = {VERSION!r}\n__product_id__ = {PROJECT!r}\n"
    ).encode("utf-8")

    entries: dict[str, bytes] = {
        f"{PACKAGE_NAME}/__init__.py": init_code,
        f"{PACKAGE_NAME}/launcher.py": launcher_bytes,
        f"{PACKAGE_NAME}/payload/{payload_name}": payload_bytes,
        f"{PACKAGE_NAME}/payload/manifest.json": scratch_canonical(
            {"manifest_sha256": manifest_sha, "root": "Theme Forge Nebular Fusion.app", "members": []}
        ),
        f"{PACKAGE_NAME}/_rs9/provenance.json": scratch_canonical(prov_doc),
        f"{dist_info}/METADATA": "\n".join(meta_lines).encode("utf-8"),
        f"{dist_info}/WHEEL": wheel_info,
        f"{dist_info}/entry_points.txt": entry_points,
        f"{dist_info}/licenses/LICENSE": lic_bytes,
        f"{dist_info}/licenses/NOTICE": notice_bytes,
    }
    for rel_h, h_bytes in sorted(helpers.items()):
        if mutate_helper and rel_h.endswith("scratch.py"):
            h_bytes = h_bytes + b"\n# drift\n"
        entries[f"{PACKAGE_NAME}/_isolated/{rel_h}"] = h_bytes
    if extra_entries:
        entries.update(extra_entries)

    rec_bytes = format_record(entries, dist_info)
    if bad_record:
        rec_bytes = rec_bytes.replace(b"sha256=", b"sha256=00")
    entries[f"{dist_info}/RECORD"] = rec_bytes

    buf = io.BytesIO()
    member_rows = []
    files_map = {}
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(entries):
            zi = zipfile.ZipInfo(filename=path, date_time=(2026, 1, 1, 0, 0, 0))
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.create_system = 3
            mode = 0o755 if (bad_mode and path.endswith("launcher.py")) else 0o644
            zi.external_attr = (mode | stat.S_IFREG) << 16
            zf.writestr(zi, entries[path], compresslevel=9)
            files_map[path] = (entries[path], 0o644)

    wheel_bytes = buf.getvalue()
    with zipfile.ZipFile(io.BytesIO(wheel_bytes), "r") as zf:
        for info in sorted(zf.infolist(), key=lambda i: i.filename):
            body = entries[info.filename]
            member_rows.append(
                {
                    "path": info.filename,
                    "size": len(body),
                    "compressed_size": info.compress_size,
                    "sha256": sha256(body),
                    "mode": 0o644,
                }
            )

    dest_dir.mkdir(parents=True, exist_ok=True)
    w_path = dest_dir / EXPECTED_WHEEL_FILENAME
    w_path.write_bytes(wheel_bytes)

    synth_approval = copy.deepcopy(base_approval)
    synth_approval["payload_asset"]["size"] = len(payload_bytes)
    synth_approval["payload_asset"]["sha256"] = payload_sha
    synth_approval["license_files"] = [
        {"path": "LICENSE", "size": len(lic_bytes), "sha256": sha256(lic_bytes)},
        {"path": "NOTICE", "size": len(notice_bytes), "sha256": sha256(notice_bytes)},
    ]
    synth_approval["files"] = [
        {
            "filename": EXPECTED_WHEEL_FILENAME,
            "size": len(wheel_bytes),
            "sha256": sha256(wheel_bytes),
            "logical_sha256": logical_identity(files_map),
        }
    ]
    synth_approval["members"] = member_rows
    synth_approval["pypi_size_limit"]["candidate_size_bytes"] = len(wheel_bytes)
    synth_approval["pypi_size_limit"]["headroom_bytes"] = PYPI_DEFAULT_FILE_LIMIT - len(wheel_bytes)
    synth_approval["set_sha256"] = compute_set_sha256(synth_approval)
    return w_path, synth_approval


class NebularPyPIContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.committed_approval = load_approval(ROOT)

    def test_static_contract_and_workflow_yaml_parity(self) -> None:
        for mod_name in ("tf_pypi_nebular.py", "nebular_host_state.py"):
            path = ROOT / "src/rs9" / mod_name
            tree = ast.parse(path.read_text(encoding="utf-8"), feature_version=(3, 12))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for item in node.names:
                        self.assertIn(item.name.split(".")[0], sys.stdlib_module_names)
                elif isinstance(node, ast.ImportFrom) and not node.level and node.module:
                    if node.module.startswith("rs9."):
                        helper = node.module.split(".")[1] + ".py"
                        self.assertTrue((ROOT / "src/rs9" / helper).is_file())
                    else:
                        self.assertIn(node.module.split(".")[0], sys.stdlib_module_names)
                elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    self.assertNotIn(node.func.attr, ("extract", "extractall"))

        wf_path = ROOT / ".github/workflows" / WORKFLOW
        self.assertTrue(wf_path.is_file())
        text = wf_path.read_text(encoding="utf-8")
        self.assertEqual(text, workflow_text())

        uses = {
            line.split("uses:", 1)[1].strip()
            for line in text.splitlines()
            if "uses:" in line
        }
        self.assertEqual(uses, EXPECTED_PINNED_ACTIONS)
        self.assertIn("runs-on: macos-15", text)
        self.assertIn("runs-on: ubuntu-24.04", text)
        self.assertIn("python-version: '3.13'", text)
        self.assertIn("name: pypi", text)
        self.assertIn("url: https://pypi.org/p/theme-forge-nebular-fusion", text)
        self.assertIn("id-token: write", text)
        self.assertIn("verify-metadata: true", text)
        self.assertIn("print-hash: true", text)
        self.assertIn("skip-existing: false", text)
        self.assertIn("attestations: false", text)
        self.assertIn(f"refs/heads/{QUALIFY_BRANCH}", text)
        self.assertIn(
            "if: always() && (steps.missing.outputs.upload == 'true' || steps.missing.outputs.state == 'published-exact')",
            text,
        )
        self.assertIn(SANDBOX_PROFILE, text)

        pre_publish_section, publish_section = text.split("\n  publish:\n", 1)
        build_section, native_consumer_section = pre_publish_section.split("\n  native_consumer:\n", 1)
        self.assertIn("path: '${{ runner.temp }}/tfnf-dist'", native_consumer_section)
        self.assertIn('--dist "$PHYSICAL_RUNNER_TEMP/tfnf-dist"', native_consumer_section)
        self.assertNotIn("path: dist/", native_consumer_section)
        self.assertNotIn('--dist "$GITHUB_WORKSPACE/dist"', native_consumer_section)
        self.assertNotIn("environment:\n      name: pypi", pre_publish_section)
        self.assertNotIn("id-token: write", pre_publish_section)
        self.assertIn("environment:\n      name: pypi", publish_section)
        self.assertIn("id-token: write", publish_section)
        self.assertIn("actions: read", publish_section)
        self.assertIn("RS9_GITHUB_READ_TOKEN: ${{ github.token }}", publish_section)
        self.assertIn("needs: [build_verify, native_consumer]", publish_section)

    def test_committed_approval_manifest_and_set_sha256_invariance(self) -> None:
        doc = self.committed_approval
        self.assertEqual(doc["schema"], APPROVAL_SCHEMA)
        self.assertEqual(doc["project"], PROJECT)
        self.assertEqual(doc["distribution"], DISTRIBUTION_NAME)
        self.assertEqual(doc["version"], VERSION)
        self.assertEqual(doc["workflow"], WORKFLOW)
        self.assertEqual(doc["environment"], ENVIRONMENT)
        self.assertEqual(doc["system"], SYSTEM)
        self.assertEqual(doc["wheel_tag"], EXPECTED_WHEEL_TAG)
        self.assertEqual(doc["macos_minimum_version"], "13.0")
        self.assertEqual(doc["requires_python"], EXPECTED_REQUIRES_PYTHON)
        self.assertEqual(doc["command"], EXPECTED_COMMAND)
        self.assertEqual(doc["license_expression"], EXPECTED_LICENSE_EXPRESSION)
        self.assertEqual([r["path"] for r in doc["license_files"]], list(EXPECTED_LICENSE_FILES))
        self.assertFalse(doc["commercial_license_authority"]["shipped_in_wheel"])
        self.assertFalse(doc["builder_can_publish"])
        self.assertFalse(doc["publication_admitted"])
        self.assertEqual(len(doc["files"]), 1)
        self.assertEqual(doc["files"][0]["filename"], EXPECTED_WHEEL_FILENAME)
        self.assertLess(doc["files"][0]["size"], PYPI_DEFAULT_FILE_LIMIT)
        self.assertEqual(len(doc["members"]), EXPECTED_MEMBER_COUNT)

        # set_sha256 is invariant when flipping publication_admitted
        admitted_copy = dict(doc, publication_admitted=True)
        self.assertEqual(compute_set_sha256(admitted_copy), doc["set_sha256"])
        validate_approval_schema(admitted_copy)

        # Superseded preliminary wheel SHA-256 is explicitly recorded and rejected as active
        self.assertEqual(
            doc["superseded_candidates"][0]["sha256"],
            SUPERSEDED_PRELIMINARY_SHA256,
        )
        bad_superseded = copy.deepcopy(doc)
        bad_superseded["files"][0]["sha256"] = SUPERSEDED_PRELIMINARY_SHA256
        bad_superseded["set_sha256"] = compute_set_sha256(bad_superseded)
        with self.assertRaises(AdmissionError) as ctx:
            validate_approval_schema(bad_superseded)
        self.assertEqual(ctx.exception.code, "TF_PYPI_APPROVAL_SCHEMA")

    def test_inspect_candidate_and_verify_approved_refusals(self) -> None:
        dist_dir = self.root / "dist"
        w_path, synth_app = build_synthetic_approved_wheel(self.committed_approval, dist_dir)

        # Valid candidate passes
        inspected = inspect_candidate(w_path, approval=synth_app)
        self.assertEqual(inspected["file"]["sha256"], synth_app["files"][0]["sha256"])
        verify_approved(dist_dir, approval=synth_app, require_admitted=False)

        # Refuses when require_admitted=True and publication_admitted is False
        with self.assertRaises(AdmissionError) as ctx:
            verify_approved(dist_dir, approval=synth_app, require_admitted=True)
        self.assertEqual(ctx.exception.code, "TF_PYPI_PUBLICATION_NOT_ADMITTED")

        # Refuses extra sdist or second file in dist/
        (dist_dir / "theme_forge_nebular_fusion-0.6.1.tar.gz").write_bytes(b"sdist")
        with self.assertRaises(AdmissionError) as ctx2:
            verify_approved(dist_dir, approval=synth_app)
        self.assertEqual(ctx2.exception.code, "TF_PYPI_FILE_SET")
        (dist_dir / "theme_forge_nebular_fusion-0.6.1.tar.gz").unlink()

        # Refuses Requires-Python: >=3.9
        w_39, app_39 = build_synthetic_approved_wheel(
            self.committed_approval, self.root / "dist_39", requires_python=">=3.9"
        )
        with self.assertRaises(AdmissionError) as ctx3:
            inspect_candidate(w_39, approval=app_39)
        self.assertEqual(ctx3.exception.code, "TF_PYPI_WHEEL_METADATA")

        # Refuses helper drift
        w_h, app_h = build_synthetic_approved_wheel(
            self.committed_approval, self.root / "dist_h", mutate_helper=True
        )
        with self.assertRaises(AdmissionError) as ctx4:
            inspect_candidate(w_h, approval=app_h)
        self.assertEqual(ctx4.exception.code, "TF_PYPI_WHEEL_HELPER_DRIFT")

        # Refuses launcher drift
        w_l, app_l = build_synthetic_approved_wheel(
            self.committed_approval, self.root / "dist_l", mutate_launcher=True
        )
        with self.assertRaises(AdmissionError) as ctx5:
            inspect_candidate(w_l, approval=app_l)
        self.assertEqual(ctx5.exception.code, "TF_PYPI_WHEEL_LAUNCHER_DRIFT")

        # Refuses RECORD mismatch
        w_r, app_r = build_synthetic_approved_wheel(
            self.committed_approval, self.root / "dist_r", bad_record=True
        )
        with self.assertRaises(AdmissionError) as ctx6:
            inspect_candidate(w_r, approval=app_r)
        self.assertEqual(ctx6.exception.code, "TF_PYPI_WHEEL_RECORD")

        # Refuses non-0644 zip member mode
        w_m, app_m = build_synthetic_approved_wheel(
            self.committed_approval, self.root / "dist_m", bad_mode=True
        )
        with self.assertRaises(AdmissionError) as ctx7:
            inspect_candidate(w_m, approval=app_m)
        self.assertEqual(ctx7.exception.code, "TF_PYPI_WHEEL_MEMBER_ATTR")

        # Refuses COMMERCIAL-LICENSE.md shipped in wheel
        w_c, app_c = build_synthetic_approved_wheel(
            self.committed_approval,
            self.root / "dist_c",
            extra_entries={f"{PACKAGE_NAME}-{VERSION}.dist-info/licenses/COMMERCIAL-LICENSE.md": b"comm"},
        )
        with self.assertRaises(AdmissionError) as ctx8:
            inspect_candidate(w_c, approval=app_c)
        self.assertIn(ctx8.exception.code, ("TF_PYPI_APPROVAL_SCHEMA", "TF_PYPI_WHEEL_STRUCTURE"))

    def test_select_missing_verify_upload_and_single_attempt_lock(self) -> None:
        dist_dir = self.root / "dist"
        w_path, synth_app = build_synthetic_approved_wheel(self.committed_approval, dist_dir)
        wheel_bytes = w_path.read_bytes()
        wheel_sha = sha256(wheel_bytes)
        admitted_app = dict(synth_app, publication_admitted=True)

        # 1. Withheld approval refuses before network call
        def forbidden_get(url: str) -> bytes:
            raise AssertionError(f"Unexpected network call to {url}")

        with self.assertRaises(AdmissionError) as ctx:
            select_missing(
                dist_dir,
                self.root / "upload_withheld",
                approval=synth_app,
                get=forbidden_get,
            )
        self.assertEqual(ctx.exception.code, "TF_PYPI_PUBLICATION_NOT_ADMITTED")

        # 2. Remote absent stages exact wheel and writes attempt marker
        def absent_get(url: str) -> bytes:
            raise AdmissionError("TF_PYPI_REMOTE_ABSENT")

        upload_dir = self.root / "upload_1"
        marker = self.root / "marker.json"
        res = select_missing(
            dist_dir,
            upload_dir,
            approval=admitted_app,
            get=absent_get,
            attempt_marker=marker,
            environ={},
        )
        self.assertEqual(
            res,
            {"upload": True, "state": "absent", "missing": [EXPECTED_WHEEL_FILENAME]},
        )
        self.assertTrue(marker.is_file())
        verify_upload_dir(dist_dir, upload_dir, approval=admitted_app)

        # 3. Second invocation with existing attempt_marker fails closed
        with self.assertRaises(AdmissionError) as ctx2:
            select_missing(
                dist_dir,
                self.root / "upload_2",
                approval=admitted_app,
                get=absent_get,
                attempt_marker=marker,
            )
        self.assertEqual(ctx2.exception.code, "TF_PYPI_PRIOR_ATTEMPT_UNCONFIRMED")

        # 4. Remote published-exact skips upload and leaves upload_dir empty
        file_url = f"https://files.pythonhosted.org/packages/ee/{EXPECTED_WHEEL_FILENAME}"

        def exact_get(url: str) -> bytes:
            if url == f"https://pypi.org/pypi/{PROJECT}/json":
                return canonical({"info": {"name": PROJECT}, "releases": {VERSION: [{}]}})
            if url == f"https://pypi.org/pypi/{PROJECT}/{VERSION}/json":
                return canonical(
                    {
                        "info": {"name": PROJECT, "version": VERSION},
                        "urls": [
                            {
                                "filename": EXPECTED_WHEEL_FILENAME,
                                "size": len(wheel_bytes),
                                "yanked": False,
                                "digests": {"sha256": wheel_sha},
                                "url": file_url,
                            }
                        ],
                    }
                )
            if url == file_url:
                return wheel_bytes
            raise AssertionError(url)

        upload_exact = self.root / "upload_exact"
        res_exact = select_missing(
            dist_dir,
            upload_exact,
            approval=admitted_app,
            get=exact_get,
            attempt_marker=self.root / "marker_exact.json",
        )
        self.assertEqual(
            res_exact,
            {"upload": False, "state": "published-exact", "missing": []},
        )
        self.assertFalse(upload_exact.exists())
        self.assertFalse((self.root / "marker_exact.json").exists())

    def test_finite_readback_schedule_convergence_conflict_and_exhaustion(self) -> None:
        dist_dir = self.root / "dist"
        w_path, synth_app = build_synthetic_approved_wheel(self.committed_approval, dist_dir)
        wheel_bytes = w_path.read_bytes()
        wheel_sha = sha256(wheel_bytes)
        file_url = f"https://files.pythonhosted.org/packages/ee/{EXPECTED_WHEEL_FILENAME}"

        self.assertEqual(READBACK_SCHEDULE_SECONDS, (0, 15, 30, 60, 120, 180))

        # 1. Converges on attempt 3 after 2 absent responses
        calls = 0
        sleeps: list[float] = []

        def converging_get(url: str) -> bytes:
            nonlocal calls
            if url == f"https://pypi.org/pypi/{PROJECT}/json":
                calls += 1
                if calls < 3:
                    raise AdmissionError("TF_PYPI_REMOTE_ABSENT")
                return canonical({"info": {"name": PROJECT}, "releases": {VERSION: [{}]}})
            if url == f"https://pypi.org/pypi/{PROJECT}/{VERSION}/json":
                return canonical(
                    {
                        "info": {"name": PROJECT, "version": VERSION},
                        "urls": [
                            {
                                "filename": EXPECTED_WHEEL_FILENAME,
                                "size": len(wheel_bytes),
                                "yanked": False,
                                "digests": {"sha256": wheel_sha},
                                "url": file_url,
                            }
                        ],
                    }
                )
            if url == file_url:
                return wheel_bytes
            raise AssertionError(url)

        res = readback(
            dist_dir,
            approval=synth_app,
            get=converging_get,
            sleep_fn=sleeps.append,
        )
        self.assertEqual(res["state"], "published-exact")
        self.assertEqual(len(res["attempts"]), 3)
        self.assertEqual(sleeps, [15.0, 30.0])

        # 2. Exhausts all 6 attempts on persistent absent without re-uploading
        sleeps_exhaust: list[float] = []

        def always_absent_get(url: str) -> bytes:
            raise AdmissionError("TF_PYPI_REMOTE_ABSENT")

        with self.assertRaises(AdmissionError) as ctx:
            readback(
                dist_dir,
                approval=synth_app,
                get=always_absent_get,
                sleep_fn=sleeps_exhaust.append,
            )
        self.assertEqual(ctx.exception.code, "TF_PYPI_READBACK_ABSENT")
        self.assertEqual(len(getattr(ctx.exception, "attempts")), 6)
        self.assertEqual(
            getattr(ctx.exception, "disposition"),
            "unconfirmed-no-redispatch-before-independent-readback",
        )
        self.assertEqual(sleeps_exhaust, [15.0, 30.0, 60.0, 120.0, 180.0])

        # 3. Aborts immediately on conflict (e.g. yanked or wrong digest)
        sleeps_conflict: list[float] = []

        def conflict_get(url: str) -> bytes:
            if url == f"https://pypi.org/pypi/{PROJECT}/json":
                return canonical({"info": {"name": PROJECT}, "releases": {VERSION: [{}]}})
            if url == f"https://pypi.org/pypi/{PROJECT}/{VERSION}/json":
                return canonical(
                    {
                        "info": {"name": PROJECT, "version": VERSION},
                        "urls": [
                            {
                                "filename": EXPECTED_WHEEL_FILENAME,
                                "size": len(wheel_bytes),
                                "yanked": True,
                                "digests": {"sha256": wheel_sha},
                                "url": file_url,
                            }
                        ],
                    }
                )
            raise AssertionError(url)

        with self.assertRaises(AdmissionError) as ctx2:
            readback(
                dist_dir,
                approval=synth_app,
                get=conflict_get,
                sleep_fn=sleeps_conflict.append,
            )
        self.assertEqual(ctx2.exception.code, "TF_PYPI_READBACK_CONFLICT")
        self.assertEqual(len(getattr(ctx2.exception, "attempts")), 1)
        self.assertEqual(getattr(ctx2.exception, "disposition"), "conflict-abort-immediately")
        self.assertEqual(sleeps_conflict, [])

    @unittest.skipUnless(sys.platform == "darwin", "Requires macOS /bin/ps")
    def test_verify_ps_observer_rejects_shadowed_or_untrusted_ps(self) -> None:
        import subprocess

        res = verify_ps_observer("/usr/bin:/bin", os.environ)
        self.assertEqual(res["path"], "/bin/ps")
        self.assertEqual(res["uid"], 0)
        self.assertIn(res["mode"], (0o4755, 0o0755))
        self.assertTrue(res["self_pid_probe_passed"])
        self.assertFalse(res["raw_process_output_retained"])

        # 1. Rejects PATH that resolves ps to a non-/bin/ps binary
        with self.assertRaises(AdmissionError) as ctx:
            verify_ps_observer(
                "/custom/bin:/bin",
                os.environ,
                which_fn=lambda cmd, path=None: "/custom/bin/ps",
            )
        self.assertEqual(ctx.exception.code, "TF_PYPI_PS_OBSERVER_RESOLUTION")

        real_st = os.lstat("/bin/ps")

        def make_stat(mode: int, uid: int = 0) -> os.stat_result:
            vals = list(real_st)
            vals[0] = mode
            vals[4] = uid
            return os.stat_result(vals)

        # 2. Rejects non-root uid
        with self.assertRaises(AdmissionError) as ctx_uid:
            verify_ps_observer(
                "/usr/bin:/bin",
                os.environ,
                lstat_fn=lambda _: make_stat(stat.S_IFREG | 0o4755, uid=501),
            )
        self.assertEqual(ctx_uid.exception.code, "TF_PYPI_PS_OBSERVER_OWNERSHIP")

        # 3. Rejects symlink
        with self.assertRaises(AdmissionError) as ctx_sym:
            verify_ps_observer(
                "/usr/bin:/bin",
                os.environ,
                lstat_fn=lambda _: make_stat(stat.S_IFLNK | 0o0777, uid=0),
            )
        self.assertEqual(ctx_sym.exception.code, "TF_PYPI_PS_OBSERVER_OWNERSHIP")

        # 4. Rejects group/other writable or non-(0o4755, 0o0755) mode
        for bad_mode in (0o4775, 0o0777, 0o0644, 0o0750):
            with self.assertRaises(AdmissionError) as ctx_mode:
                verify_ps_observer(
                    "/usr/bin:/bin",
                    os.environ,
                    lstat_fn=lambda _, m=bad_mode: make_stat(stat.S_IFREG | m, uid=0),
                )
            self.assertEqual(ctx_mode.exception.code, "TF_PYPI_PS_OBSERVER_OWNERSHIP")

        # 5. Rejects failed single-PID probe execution or non-exact PID substring matches (F6)
        with self.assertRaises(AdmissionError) as ctx_exec:
            verify_ps_observer(
                "/usr/bin:/bin",
                os.environ,
                run_fn=lambda *a, **kw: subprocess.CompletedProcess(a[0], 1, b"", b"err"),
            )
        self.assertEqual(ctx_exec.exception.code, "TF_PYPI_PS_OBSERVER_EXEC")

        for bad_stdout in (
            f"9{os.getpid()} /bin/ps\n".encode("utf-8"),
            f"99999 /tmp/{os.getpid()}/python\n".encode("utf-8"),
            f"{os.getpid()} /bin/ps\n99999 /bin/sh\n".encode("utf-8"),
            b"",
        ):
            with self.assertRaises(AdmissionError) as ctx_pid:
                verify_ps_observer(
                    "/usr/bin:/bin",
                    os.environ,
                    run_fn=lambda *a, out=bad_stdout, **kw: subprocess.CompletedProcess(a[0], 0, out, b""),
                )
            self.assertEqual(ctx_pid.exception.code, "TF_PYPI_PS_OBSERVER_EXEC")

    def test_zip_archive_safety_negatives_and_plist_anchoring(self) -> None:
        import gzip
        import tarfile

        dist_dir = self.root / "dist_base"
        w_path, synth_app = build_synthetic_approved_wheel(self.committed_approval, dist_dir)
        with zipfile.ZipFile(w_path, "r") as zf:
            base_items = [(i, zf.read(i.filename)) for i in zf.infolist()]

        def write_modified_zip(name: str, mutator) -> Path:
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as out:
                mutator(out, base_items)
            p = self.root / name / EXPECTED_WHEEL_FILENAME
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(buf.getvalue())
            return p

        app_wide = copy.deepcopy(synth_app)
        app_wide["files"][0]["size"] = synth_app["files"][0]["size"] + 512
        app_wide["set_sha256"] = compute_set_sha256(app_wide)

        # 1. ZIP traversal path
        def mut_traversal(out, items):
            for info, data in items:
                zi = zipfile.ZipInfo(
                    filename="../evil.py" if info.filename == f"{PACKAGE_NAME}/__init__.py" else info.filename,
                    date_time=(2026, 1, 1, 0, 0, 0),
                )
                zi.compress_type = zipfile.ZIP_DEFLATED
                zi.create_system = 3
                zi.external_attr = (0o644 | stat.S_IFREG) << 16
                out.writestr(zi, data, compresslevel=9)

        with self.assertRaises(AdmissionError) as ctx_trav:
            inspect_candidate(write_modified_zip("trav", mut_traversal), approval=app_wide)
        self.assertEqual(ctx_trav.exception.code, "TF_PYPI_WHEEL_PATH")

        # 2. Case-fold duplicate
        def mut_casefold(out, items):
            for info, data in items:
                fname = (
                    f"{PACKAGE_NAME}/__INIT__.py"
                    if info.filename.endswith("launcher.py")
                    else info.filename
                )
                zi = zipfile.ZipInfo(filename=fname, date_time=(2026, 1, 1, 0, 0, 0))
                zi.compress_type = zipfile.ZIP_DEFLATED
                zi.create_system = 3
                zi.external_attr = (0o644 | stat.S_IFREG) << 16
                out.writestr(zi, data, compresslevel=9)

        with self.assertRaises(AdmissionError) as ctx_dup:
            inspect_candidate(write_modified_zip("dup", mut_casefold), approval=app_wide)
        self.assertEqual(ctx_dup.exception.code, "TF_PYPI_WHEEL_DUPLICATE")

        # 3. Encrypted member flag_bits & 1 (set in central directory header PK\x01\x02 + 8)
        raw_enc = bytearray(w_path.read_bytes())
        cd_pos = raw_enc.find(b"PK\x01\x02")
        self.assertGreaterEqual(cd_pos, 0)
        raw_enc[cd_pos + 8] |= 0x1
        p_enc = self.root / "enc" / EXPECTED_WHEEL_FILENAME
        p_enc.parent.mkdir(parents=True, exist_ok=True)
        p_enc.write_bytes(bytes(raw_enc))

        with self.assertRaises(AdmissionError) as ctx_enc:
            inspect_candidate(p_enc, approval=synth_app)
        self.assertEqual(ctx_enc.exception.code, "TF_PYPI_WHEEL_MEMBER_ATTR")

        # 4. Oversize non-payload member (> 1 MiB)
        def mut_oversize_member(out, items):
            for info, data in items:
                zi = zipfile.ZipInfo(filename=info.filename, date_time=(2026, 1, 1, 0, 0, 0))
                zi.compress_type = zipfile.ZIP_DEFLATED
                zi.create_system = 3
                zi.external_attr = (0o644 | stat.S_IFREG) << 16
                body = b"x" * (MAX_NON_PAYLOAD_MEMBER_BYTES + 1) if info.filename == f"{PACKAGE_NAME}/__init__.py" else data
                out.writestr(zi, body, compresslevel=9)

        p_over = write_modified_zip("over_member", mut_oversize_member)
        app_over = copy.deepcopy(synth_app)
        app_over["files"][0]["size"] = p_over.stat().st_size + 1024
        app_over["set_sha256"] = compute_set_sha256(app_over)
        with self.assertRaises(AdmissionError) as ctx_over:
            inspect_candidate(p_over, approval=app_over)
        self.assertEqual(ctx_over.exception.code, "TF_PYPI_WHEEL_MEMBER_LIMIT")

        # 5. Total uncompressed size > MAX_TOTAL_UNCOMPRESSED_BYTES (50 MiB)
        payload_name = synth_app["payload_asset"]["name"]
        payload_member = f"{PACKAGE_NAME}/payload/{payload_name}"

        def mut_total_limit(out, items):
            for info, data in items:
                zi = zipfile.ZipInfo(filename=info.filename, date_time=(2026, 1, 1, 0, 0, 0))
                zi.compress_type = zipfile.ZIP_DEFLATED
                zi.create_system = 3
                zi.external_attr = (0o644 | stat.S_IFREG) << 16
                body = b"\x00" * (MAX_TOTAL_UNCOMPRESSED_BYTES + 1024) if info.filename == payload_member else data
                out.writestr(zi, body, compresslevel=9)

        p_tot = write_modified_zip("tot_limit", mut_total_limit)
        app_tot = copy.deepcopy(synth_app)
        app_tot["payload_asset"]["size"] = MAX_TOTAL_UNCOMPRESSED_BYTES + 1024
        app_tot["files"][0]["size"] = p_tot.stat().st_size + 1024
        app_tot["set_sha256"] = compute_set_sha256(app_tot)
        with self.assertRaises(AdmissionError) as ctx_tot:
            inspect_candidate(p_tot, approval=app_tot)
        self.assertEqual(ctx_tot.exception.code, "TF_PYPI_WHEEL_TOTAL_LIMIT")

        # 6. _extract_plist_from_payload_tar refuses nested framework Info.plist without top-level bundle Info.plist
        tar_buf = io.BytesIO()
        with gzip.GzipFile(fileobj=tar_buf, mode="wb") as gz, tarfile.open(fileobj=gz, mode="w") as tf:
            nested = tarfile.TarInfo("Theme Forge Nebular Fusion.app/Contents/Frameworks/Helper.framework/Contents/Info.plist")
            nested_bytes = b"<plist><dict></dict></plist>"
            nested.size = len(nested_bytes)
            tf.addfile(nested, io.BytesIO(nested_bytes))
        with self.assertRaises(AdmissionError) as ctx_plist:
            _extract_plist_from_payload_tar(tar_buf.getvalue())
        self.assertEqual(ctx_plist.exception.code, "TF_PYPI_WHEEL_PLIST_MISSING")

        # 7. Nested Info.plist before top-level Info.plist is ignored and top-level plist is returned (F3 / Amendment 7)
        tar_both = io.BytesIO()
        top_bytes = b"<plist><dict><key>LSMinimumSystemVersion</key><string>13.0</string></dict></plist>"
        with gzip.GzipFile(fileobj=tar_both, mode="wb") as gz, tarfile.open(fileobj=gz, mode="w") as tf:
            nested2 = tarfile.TarInfo("Theme Forge Nebular Fusion.app/Contents/Frameworks/Helper.framework/Contents/Info.plist")
            nested2.size = len(nested_bytes)
            tf.addfile(nested2, io.BytesIO(nested_bytes))
            top = tarfile.TarInfo("Theme Forge Nebular Fusion.app/Contents/Info.plist")
            top.size = len(top_bytes)
            tf.addfile(top, io.BytesIO(top_bytes))
        self.assertEqual(_extract_plist_from_payload_tar(tar_both.getvalue()), top_bytes)

        # 8. Duplicate top-level bundle Info.plist fails closed with TF_PYPI_WHEEL_PLIST_DUPLICATE (F3 / Amendment 7)
        tar_dup = io.BytesIO()
        with gzip.GzipFile(fileobj=tar_dup, mode="wb") as gz, tarfile.open(fileobj=gz, mode="w") as tf:
            for app_name in ("Theme Forge Nebular Fusion.app", "SecondBundle.app"):
                ti = tarfile.TarInfo(f"{app_name}/Contents/Info.plist")
                ti.size = len(top_bytes)
                tf.addfile(ti, io.BytesIO(top_bytes))
        with self.assertRaises(AdmissionError) as ctx_dup_plist:
            _extract_plist_from_payload_tar(tar_dup.getvalue())
        self.assertEqual(ctx_dup_plist.exception.code, "TF_PYPI_WHEEL_PLIST_DUPLICATE")

    def test_exact_state_negatives_and_durable_repeat_upload_guards(self) -> None:
        dist_dir = self.root / "dist"
        w_path, synth_app = build_synthetic_approved_wheel(self.committed_approval, dist_dir)
        wheel_bytes = w_path.read_bytes()
        wheel_sha = sha256(wheel_bytes)
        local = {EXPECTED_WHEEL_FILENAME: wheel_bytes}
        file_url = f"https://files.pythonhosted.org/packages/ee/{EXPECTED_WHEEL_FILENAME}"

        def make_get(*, size=None, digest_val=None, body=None, extra_file=False, version=VERSION, bad_json=False):
            def _get(url: str) -> bytes:
                if bad_json:
                    return b"{not-json"
                if url == f"https://pypi.org/pypi/{PROJECT}/json":
                    return canonical({"info": {"name": PROJECT}, "releases": {VERSION: [{}]}})
                if url == f"https://pypi.org/pypi/{PROJECT}/{VERSION}/json":
                    urls = [
                        {
                            "filename": EXPECTED_WHEEL_FILENAME,
                            "size": len(wheel_bytes) if size is None else size,
                            "yanked": False,
                            "digests": {"sha256": wheel_sha if digest_val is None else digest_val},
                            "url": file_url,
                        }
                    ]
                    if extra_file:
                        urls.append(
                            {
                                "filename": "theme_forge_nebular_fusion-0.6.1.tar.gz",
                                "size": 10,
                                "yanked": False,
                                "digests": {"sha256": "0" * 64},
                                "url": file_url,
                            }
                        )
                    return canonical({"info": {"name": PROJECT, "version": version}, "urls": urls})
                if url == file_url:
                    return wheel_bytes if body is None else body
                raise AssertionError(url)

            return _get

        # Changed size -> conflict
        self.assertEqual(
            exact_state(synth_app, local, get=make_get(size=len(wheel_bytes) + 1))["state"],
            "conflict",
        )
        # Changed digest -> conflict
        self.assertEqual(
            exact_state(synth_app, local, get=make_get(digest_val="a" * 64))["state"],
            "conflict",
        )
        # Changed downloaded body -> conflict
        self.assertEqual(
            exact_state(synth_app, local, get=make_get(body=wheel_bytes[:-1] + b"X"))["state"],
            "conflict",
        )
        # Extra unapproved file -> conflict
        self.assertEqual(
            exact_state(synth_app, local, get=make_get(extra_file=True))["state"],
            "conflict",
        )
        # Wrong version -> conflict
        self.assertEqual(
            exact_state(synth_app, local, get=make_get(version="0.6.2"))["state"],
            "conflict",
        )
        # Malformed JSON -> unknown
        self.assertEqual(
            exact_state(synth_app, local, get=make_get(bad_json=True))["state"],
            "unknown",
        )

        # Durable repeat-upload guards in select_missing / check_prior_publish_runs (F2 + Amendments 1 & 2)
        admitted_app = dict(synth_app, publication_admitted=True)

        def absent_get(url: str) -> bytes:
            raise AdmissionError("TF_PYPI_REMOTE_ABSENT")

        base_env = {
            "GITHUB_REPOSITORY": "Knowledge-Forge-AI/release-starport-9",
            "GITHUB_RUN_ID": "1002",
            "GITHUB_RUN_ATTEMPT": "1",
        }
        repo_slug = base_env["GITHUB_REPOSITORY"]
        expected_runs_url = (
            f"https://api.github.com/repos/{repo_slug}/actions/workflows/{WORKFLOW}/runs"
            "?branch=main&event=workflow_dispatch&per_page=100"
        )
        expected_runs_page2_url = f"{expected_runs_url}&page=2"
        expected_jobs_999_url = (
            f"https://api.github.com/repos/{repo_slug}/actions/runs/999/jobs"
            "?filter=all&per_page=100"
        )
        expected_jobs_1000_url = (
            f"https://api.github.com/repos/{repo_slug}/actions/runs/1000/jobs"
            "?filter=all&per_page=100"
        )
        expected_jobs_1001_url = (
            f"https://api.github.com/repos/{repo_slug}/actions/runs/1001/jobs"
            "?filter=all&per_page=100"
        )

        # 1. RS9_TFNF_PRIOR_UPLOAD_UNCONFIRMED refuses
        with self.assertRaises(AdmissionError) as ctx_env:
            select_missing(
                dist_dir,
                self.root / "up_env",
                approval=admitted_app,
                get=absent_get,
                environ={"RS9_TFNF_PRIOR_UPLOAD_UNCONFIRMED": "true"},
            )
        self.assertEqual(ctx_env.exception.code, "TF_PYPI_PRIOR_ATTEMPT_UNCONFIRMED")

        # 2. GITHUB_RUN_ATTEMPT > 1 refuses re-run while remote is absent
        with self.assertRaises(AdmissionError) as ctx_att:
            select_missing(
                dist_dir,
                self.root / "up_att",
                approval=admitted_app,
                get=absent_get,
                environ={"GITHUB_RUN_ATTEMPT": "2"},
            )
        self.assertEqual(ctx_att.exception.code, "TF_PYPI_PRIOR_ATTEMPT_UNCONFIRMED")

        # 3. Prior workflow run that executed 'Publish package distribution to PyPI' refuses
        seen_mock_urls: list[str] = []

        def mock_api_get(url: str):
            seen_mock_urls.append(url)
            if url.endswith("/runs?branch=main&event=workflow_dispatch&per_page=100"):
                return {"total_count": 2, "workflow_runs": [{"id": 1001}, {"id": 1002}]}
            if url.endswith("/runs/1001/jobs?filter=all&per_page=100"):
                return {
                    "total_count": 1,
                    "jobs": [
                        {
                            "name": "Trusted Publishing to PyPI",
                            "status": "completed",
                            "conclusion": "success",
                            "steps": [
                                {
                                    "name": "Publish package distribution to PyPI",
                                    "status": "completed",
                                    "conclusion": "success",
                                }
                            ],
                        }
                    ],
                }
            raise AssertionError(url)

        with self.assertRaises(AdmissionError) as ctx_api:
            select_missing(
                dist_dir,
                self.root / "up_api",
                approval=admitted_app,
                get=absent_get,
                api_get=mock_api_get,
                environ=base_env,
            )
        self.assertEqual(ctx_api.exception.code, "TF_PYPI_PRIOR_ATTEMPT_UNCONFIRMED")
        self.assertEqual(
            seen_mock_urls,
            [expected_runs_url, expected_jobs_1001_url],
        )

        # 4. Positive control: clean prior runs (qualify run with skipped publish job + pre-upload failure with skipped publish step) allow staging
        seen_clean_prior_urls: list[str] = []

        def clean_prior_api_get(url: str, **kwargs):
            seen_clean_prior_urls.append(url)
            if url.endswith("/runs?branch=main&event=workflow_dispatch&per_page=100"):
                return {"total_count": 3, "workflow_runs": [{"id": 1000}, {"id": 1001}, {"id": 1002}]}
            if url.endswith("/runs/1000/jobs?filter=all&per_page=100"):
                return {
                    "total_count": 1,
                    "jobs": [
                        {
                            "name": "Trusted Publishing to PyPI",
                            "status": "completed",
                            "conclusion": "skipped",
                            "steps": [],
                        }
                    ],
                }
            if url.endswith("/runs/1001/jobs?filter=all&per_page=100"):
                return {
                    "total_count": 1,
                    "jobs": [
                        {
                            "name": "Trusted Publishing to PyPI",
                            "status": "completed",
                            "conclusion": "failure",
                            "steps": [
                                {
                                    "name": "Verify artifact integrity and select only missing files",
                                    "status": "completed",
                                    "conclusion": "failure",
                                },
                                {
                                    "name": "Publish package distribution to PyPI",
                                    "status": "completed",
                                    "conclusion": "skipped",
                                },
                            ],
                        }
                    ],
                }
            raise AssertionError(url)

        res_clean_prior = select_missing(
            dist_dir,
            self.root / "up_clean_prior",
            approval=admitted_app,
            get=absent_get,
            api_get=clean_prior_api_get,
            environ=base_env,
        )
        self.assertTrue(res_clean_prior["upload"])
        self.assertEqual(
            seen_clean_prior_urls,
            [expected_runs_url, expected_jobs_1000_url, expected_jobs_1001_url],
        )

        # 5. Mandatory GITHUB_ACTIONS="true" path without RS9_TFNF_PRIOR_RUNS_CHECK queries PublicClient.json and fails closed on API error or prior upload
        seen_clean_prior_urls.clear()
        with patch("rs9.tf_pypi_nebular.PublicClient") as mock_pc_cls:
            mock_pc_cls.return_value.json.side_effect = clean_prior_api_get
            res_gha_clean = select_missing(
                dist_dir,
                self.root / "up_gha_clean",
                approval=admitted_app,
                get=absent_get,
                environ={
                    **base_env,
                    "GITHUB_ACTIONS": "true",
                    "RS9_GITHUB_READ_TOKEN": "ghs_tok",
                },
            )
            self.assertTrue(res_gha_clean["upload"])
            mock_pc_cls.assert_called_with(api_token="ghs_tok")
            self.assertEqual(
                [
                    (c.args, c.kwargs)
                    for c in mock_pc_cls.return_value.json.call_args_list
                ],
                [
                    ((expected_runs_url,), {"request_class": "github-api", "no_redirect": True}),
                    ((expected_jobs_1000_url,), {"request_class": "github-api", "no_redirect": True}),
                    ((expected_jobs_1001_url,), {"request_class": "github-api", "no_redirect": True}),
                ],
            )

        with patch("rs9.tf_pypi_nebular.PublicClient") as mock_pc_err:
            mock_pc_err.return_value.json.side_effect = RuntimeError("github api down")
            with self.assertRaises(AdmissionError) as ctx_gha_err:
                select_missing(
                    dist_dir,
                    self.root / "up_gha_err",
                    approval=admitted_app,
                    get=absent_get,
                    environ={
                        **base_env,
                        "GITHUB_ACTIONS": "true",
                        "RS9_GITHUB_READ_TOKEN": "ghs_tok",
                    },
                )
            self.assertEqual(ctx_gha_err.exception.code, "TF_PYPI_PRIOR_ATTEMPT_UNCONFIRMED")

        # 6. Earlier re-run attempt under filter=all with non-skipped publish step fails closed even if latest attempt was skipped
        seen_rerun_urls: list[str] = []

        def rerun_attempt_api_get(url: str):
            seen_rerun_urls.append(url)
            if url.endswith("/runs?branch=main&event=workflow_dispatch&per_page=100"):
                return {"total_count": 1, "workflow_runs": [{"id": 1001}]}
            if url.endswith("/runs/1001/jobs?filter=all&per_page=100"):
                return {
                    "total_count": 2,
                    "jobs": [
                        {
                            "name": "Trusted Publishing to PyPI",
                            "run_attempt": 1,
                            "status": "completed",
                            "conclusion": "failure",
                            "steps": [
                                {
                                    "name": "Publish package distribution to PyPI",
                                    "status": "completed",
                                    "conclusion": "failure",
                                }
                            ],
                        },
                        {
                            "name": "Trusted Publishing to PyPI",
                            "run_attempt": 2,
                            "status": "completed",
                            "conclusion": "failure",
                            "steps": [
                                {
                                    "name": "Publish package distribution to PyPI",
                                    "status": "completed",
                                    "conclusion": "skipped",
                                }
                            ],
                        },
                    ],
                }
            raise AssertionError(url)

        with self.assertRaises(AdmissionError) as ctx_rerun:
            select_missing(
                dist_dir,
                self.root / "up_rerun",
                approval=admitted_app,
                get=absent_get,
                api_get=rerun_attempt_api_get,
                environ=base_env,
            )
        self.assertEqual(ctx_rerun.exception.code, "TF_PYPI_PRIOR_ATTEMPT_UNCONFIRMED")
        self.assertEqual(
            seen_rerun_urls,
            [expected_runs_url, expected_jobs_1001_url],
        )

        # 7. Pagination across pages detects prior upload on page 2 and fails closed on truncated / missing total_count / in-progress step / missing job
        seen_paginated_urls: list[str] = []

        def paginated_api_get(url: str):
            seen_paginated_urls.append(url)
            if url.endswith("/runs?branch=main&event=workflow_dispatch&per_page=100"):
                return {"total_count": 2, "workflow_runs": [{"id": 1002}]}
            if url.endswith("/runs?branch=main&event=workflow_dispatch&per_page=100&page=2"):
                return {"total_count": 2, "workflow_runs": [{"id": 999}]}
            if url.endswith("/runs/999/jobs?filter=all&per_page=100"):
                return {
                    "total_count": 1,
                    "jobs": [
                        {
                            "name": "Trusted Publishing to PyPI",
                            "status": "completed",
                            "conclusion": "cancelled",
                            "steps": [],
                        }
                    ],
                }
            raise AssertionError(url)

        with self.assertRaises(AdmissionError) as ctx_page:
            select_missing(
                dist_dir,
                self.root / "up_page",
                approval=admitted_app,
                get=absent_get,
                api_get=paginated_api_get,
                environ=base_env,
            )
        self.assertEqual(ctx_page.exception.code, "TF_PYPI_PRIOR_ATTEMPT_UNCONFIRMED")
        self.assertEqual(
            seen_paginated_urls,
            [expected_runs_url, expected_runs_page2_url, expected_jobs_999_url],
        )

        # Prior run lacking 'Trusted Publishing to PyPI' job (e.g. job rename) fails closed
        seen_no_job_urls: list[str] = []

        def missing_publish_job_api_get(url: str):
            seen_no_job_urls.append(url)
            if url.endswith("/runs?branch=main&event=workflow_dispatch&per_page=100"):
                return {"total_count": 1, "workflow_runs": [{"id": 1001}]}
            if url.endswith("/runs/1001/jobs?filter=all&per_page=100"):
                return {
                    "total_count": 1,
                    "jobs": [
                        {
                            "name": "Build and Verify Native Darwin Wheel",
                            "status": "completed",
                            "conclusion": "success",
                            "steps": [],
                        }
                    ],
                }
            raise AssertionError(url)

        with self.assertRaises(AdmissionError) as ctx_no_job:
            select_missing(
                dist_dir,
                self.root / "up_no_job",
                approval=admitted_app,
                get=absent_get,
                api_get=missing_publish_job_api_get,
                environ=base_env,
            )
        self.assertEqual(ctx_no_job.exception.code, "TF_PYPI_PRIOR_ATTEMPT_UNCONFIRMED")
        self.assertEqual(
            seen_no_job_urls,
            [expected_runs_url, expected_jobs_1001_url],
        )

        for bad_runs_payload, expected_bad_urls in (
            ({"workflow_runs": []}, [expected_runs_url]),  # missing total_count
            ({"total_count": 5, "workflow_runs": []}, [expected_runs_url]),  # empty page before total_count
            (
                {
                    "total_count": 1,
                    "workflow_runs": [{"id": 1001}],
                    "_job_step_conclusion": None,
                },
                [expected_runs_url, expected_jobs_1001_url],
            ),
        ):
            seen_bad_urls: list[str] = []

            def make_bad_api(payload, seen_list):
                def _api(url: str):
                    seen_list.append(url)
                    if "/runs?" in url:
                        return {k: v for k, v in payload.items() if not k.startswith("_")}
                    return {
                        "total_count": 1,
                        "jobs": [
                            {
                                "name": "Trusted Publishing to PyPI",
                                "status": "in_progress",
                                "conclusion": None,
                                "steps": [
                                    {
                                        "name": "Publish package distribution to PyPI",
                                        "status": "in_progress",
                                        "conclusion": payload.get("_job_step_conclusion"),
                                    }
                                ],
                            }
                        ],
                    }
                return _api

            with self.assertRaises(AdmissionError) as ctx_bad_p:
                select_missing(
                    dist_dir,
                    self.root / "up_bad_p",
                    approval=admitted_app,
                    get=absent_get,
                    api_get=make_bad_api(bad_runs_payload, seen_bad_urls),
                    environ=base_env,
                )
            self.assertEqual(ctx_bad_p.exception.code, "TF_PYPI_PRIOR_ATTEMPT_UNCONFIRMED")
            self.assertEqual(seen_bad_urls, expected_bad_urls)

    def test_check_prior_publish_runs_maps_unexpected_client_failures(self) -> None:
        dist_dir = self.root / "dist_guard_err"
        _, synth_app = build_synthetic_approved_wheel(self.committed_approval, dist_dir)
        admitted_app = dict(synth_app, publication_admitted=True)

        def absent_get(url: str) -> bytes:
            raise AdmissionError("TF_PYPI_REMOTE_ABSENT")

        base_env = {
            "GITHUB_REPOSITORY": "Knowledge-Forge-AI/release-starport-9",
            "GITHUB_RUN_ID": "1002",
            "GITHUB_RUN_ATTEMPT": "1",
        }
        repo_slug = base_env["GITHUB_REPOSITORY"]
        expected_runs_url = (
            f"https://api.github.com/repos/{repo_slug}/actions/workflows/{WORKFLOW}/runs"
            "?branch=main&event=workflow_dispatch&per_page=100"
        )
        expected_jobs_1001_url = (
            f"https://api.github.com/repos/{repo_slug}/actions/runs/1001/jobs"
            "?filter=all&per_page=100"
        )
        secret_tok = "ghs_" + "SECRET"
        secret_path = "/" + "Users/" + "x"
        secret_msg = f"{secret_tok} {secret_path}"

        for idx, exc_cls in enumerate((AssertionError, RuntimeError, KeyError, TypeError)):
            # 1. Runs-list stage unexpected failure maps to TF_PYPI_PRIOR_ATTEMPT_UNCONFIRMED
            seen_runs_stage: list[str] = []

            def fail_on_runs(url: str, _cls=exc_cls, _seen=seen_runs_stage):
                _seen.append(url)
                raise _cls(secret_msg)

            with self.assertRaises(AdmissionError) as ctx_runs:
                check_prior_publish_runs(api_get=fail_on_runs, environ=base_env)
            self.assertEqual(ctx_runs.exception.code, "TF_PYPI_PRIOR_ATTEMPT_UNCONFIRMED")
            self.assertEqual(str(ctx_runs.exception), "TF_PYPI_PRIOR_ATTEMPT_UNCONFIRMED")
            self.assertEqual(ctx_runs.exception.args, ("TF_PYPI_PRIOR_ATTEMPT_UNCONFIRMED",))
            self.assertNotIn(secret_tok, str(ctx_runs.exception))
            self.assertNotIn(secret_path, str(ctx_runs.exception))
            self.assertIsInstance(ctx_runs.exception.__context__, exc_cls)
            self.assertEqual(seen_runs_stage, [expected_runs_url])

            # 2. Jobs-list stage unexpected failure maps to TF_PYPI_PRIOR_ATTEMPT_UNCONFIRMED
            seen_jobs_stage: list[str] = []

            def fail_on_jobs(url: str, _cls=exc_cls, _seen=seen_jobs_stage):
                _seen.append(url)
                if url == expected_runs_url:
                    return {"total_count": 1, "workflow_runs": [{"id": 1001}]}
                raise _cls(secret_msg)

            with self.assertRaises(AdmissionError) as ctx_jobs:
                check_prior_publish_runs(api_get=fail_on_jobs, environ=base_env)
            self.assertEqual(ctx_jobs.exception.code, "TF_PYPI_PRIOR_ATTEMPT_UNCONFIRMED")
            self.assertEqual(str(ctx_jobs.exception), "TF_PYPI_PRIOR_ATTEMPT_UNCONFIRMED")
            self.assertEqual(ctx_jobs.exception.args, ("TF_PYPI_PRIOR_ATTEMPT_UNCONFIRMED",))
            self.assertNotIn(secret_tok, str(ctx_jobs.exception))
            self.assertNotIn(secret_path, str(ctx_jobs.exception))
            self.assertIsInstance(ctx_jobs.exception.__context__, exc_cls)
            self.assertEqual(seen_jobs_stage, [expected_runs_url, expected_jobs_1001_url])

            # 3. Through select_missing: refuses before upload_dir creation or attempt_marker write
            up_fail_dir = self.root / f"up_fail_{idx}"
            marker_fail = self.root / f"marker_fail_{idx}.json"
            seen_sel_stage: list[str] = []

            def fail_in_select(url: str, _cls=exc_cls, _seen=seen_sel_stage):
                _seen.append(url)
                raise _cls(secret_msg)

            with self.assertRaises(AdmissionError) as ctx_sel:
                select_missing(
                    dist_dir,
                    up_fail_dir,
                    approval=admitted_app,
                    get=absent_get,
                    attempt_marker=marker_fail,
                    api_get=fail_in_select,
                    environ=base_env,
                )
            self.assertEqual(ctx_sel.exception.code, "TF_PYPI_PRIOR_ATTEMPT_UNCONFIRMED")
            self.assertFalse(up_fail_dir.exists())
            self.assertFalse(marker_fail.exists())
            self.assertEqual(seen_sel_stage, [expected_runs_url])

        # 4. GITHUB_ACTIONS="true" PublicClient.json raising AssertionError maps fail-closed before staging and CLI output is code-only
        gha_env = {
            **base_env,
            "GITHUB_ACTIONS": "true",
            "RS9_GITHUB_READ_TOKEN": "ghs_tok",
        }
        up_gha_assert = self.root / "up_gha_assert"
        marker_gha_assert = self.root / "marker_gha_assert.json"
        with patch("rs9.tf_pypi_nebular.PublicClient") as mock_pc_assert:
            mock_pc_assert.return_value.json.side_effect = AssertionError(secret_msg)
            with self.assertRaises(AdmissionError) as ctx_gha_assert:
                select_missing(
                    dist_dir,
                    up_gha_assert,
                    approval=admitted_app,
                    get=absent_get,
                    attempt_marker=marker_gha_assert,
                    environ=gha_env,
                )
            self.assertEqual(ctx_gha_assert.exception.code, "TF_PYPI_PRIOR_ATTEMPT_UNCONFIRMED")
            self.assertFalse(up_gha_assert.exists())
            self.assertFalse(marker_gha_assert.exists())
            self.assertEqual(
                [
                    (c.args, c.kwargs)
                    for c in mock_pc_assert.return_value.json.call_args_list
                ],
                [
                    ((expected_runs_url,), {"request_class": "github-api", "no_redirect": True}),
                ],
            )

        up_cli_assert = self.root / "up_cli_assert"
        marker_cli_assert = self.root / "marker_cli_assert.json"
        out_buf = io.StringIO()
        err_buf = io.StringIO()
        with (
            patch("rs9.tf_pypi_nebular.load_approval", return_value=admitted_app),
            patch("rs9.tf_pypi_nebular.PublicClient") as mock_pc_cli,
            patch.dict(os.environ, gha_env, clear=True),
            patch("sys.stdout", out_buf),
            patch("sys.stderr", err_buf),
        ):
            mock_pc_cli.return_value.json.side_effect = AssertionError(secret_msg)
            rc = main(
                [
                    "select-missing",
                    "--dist",
                    str(dist_dir),
                    "--upload-dir",
                    str(up_cli_assert),
                    "--attempt-marker",
                    str(marker_cli_assert),
                ],
                get=absent_get,
            )
        self.assertEqual(rc, 1)
        self.assertEqual(out_buf.getvalue(), "")
        self.assertEqual(err_buf.getvalue(), "TF_PYPI_PRIOR_ATTEMPT_UNCONFIRMED\n")
        self.assertNotIn(secret_tok, err_buf.getvalue())
        self.assertNotIn(secret_path, err_buf.getvalue())
        self.assertFalse(up_cli_assert.exists())
        self.assertFalse(marker_cli_assert.exists())

    def test_probe_network_denial_non_vacuous_tcp_and_dns(self) -> None:
        import errno
        import subprocess

        def make_run(py_out: dict, node_lines: list[str]):
            def _run(cmd, **kwargs):
                if "-c" in cmd:
                    return subprocess.CompletedProcess(cmd, 0, json.dumps(py_out).encode("utf-8"), b"")
                return subprocess.CompletedProcess(cmd, 0, ("\n".join(node_lines) + "\n").encode("utf-8"), b"")

            return _run

        host_eai_names = ("EAI_NONAME", "EAI_AGAIN", "EAI_FAIL", "EAI_NODATA")
        host_eai_values = [
            getattr(socket, name) for name in host_eai_names if hasattr(socket, name)
        ]
        self.assertTrue(host_eai_values)

        # 1. Valid TCP + DNS denial passes for every host-defined socket.EAI_* constant and Node DNS token
        for dns_errno in host_eai_values:
            with patch(
                "rs9.tf_pypi_nebular.subprocess.run",
                side_effect=make_run(
                    {"1.1.1.1": errno.EPERM, "registry.npmjs.org": dns_errno},
                    ["TCP:EPERM", "DNS:ENOTFOUND"],
                ),
            ):
                res = probe_network_denial("python3", "node", {})
            self.assertTrue(res["network_disabled"])
            self.assertEqual(res["python_tcp_errno"], errno.EPERM)
            self.assertEqual(res["python_dns_errno"], dns_errno)
            self.assertEqual(res["node_tcp_denials"], ["EPERM"])
            self.assertEqual(res["node_dns_denials"], ["ENOTFOUND"])

        with patch(
            "rs9.tf_pypi_nebular.subprocess.run",
            side_effect=make_run(
                {"1.1.1.1": errno.EACCES, "registry.npmjs.org": socket.EAI_NONAME},
                ["TCP:EACCES", "DNS:EAI_AGAIN"],
            ),
        ):
            res_again = probe_network_denial("python3", "node", {})
        self.assertTrue(res_again["network_disabled"])
        self.assertEqual(res_again["python_tcp_errno"], errno.EACCES)
        self.assertEqual(res_again["python_dns_errno"], socket.EAI_NONAME)
        self.assertEqual(res_again["node_tcp_denials"], ["EACCES"])
        self.assertEqual(res_again["node_dns_denials"], ["EAI_AGAIN"])

        # 2. Node TCP EPERM alone does NOT satisfy missing/connected Node DNS (fixes vacuous DNS check)
        for bad_node in (
            ["TCP:EPERM", "DNS:CONNECTED"],
            ["TCP:EPERM"],
            ["TCP:CONNECTED", "DNS:ENOTFOUND"],
            ["TCP:TIMEOUT", "DNS:ENOTFOUND"],
        ):
            with patch(
                "rs9.tf_pypi_nebular.subprocess.run",
                side_effect=make_run(
                    {"1.1.1.1": errno.EPERM, "registry.npmjs.org": socket.EAI_NONAME},
                    bad_node,
                ),
            ), self.assertRaises(AdmissionError) as ctx_n:
                probe_network_denial("python3", "node", {})
            self.assertEqual(ctx_n.exception.code, "TF_PYPI_OFFLINE_ISOLATION")

        # 3. Python TCP or DNS connection allowed, timeout (-1), or ECONNREFUSED fails closed
        for neg_dns in (0, -1, errno.ECONNREFUSED):
            self.assertNotIn(neg_dns, host_eai_values)

        for bad_py in (
            {"1.1.1.1": 0, "registry.npmjs.org": socket.EAI_NONAME},
            {"1.1.1.1": errno.EPERM, "registry.npmjs.org": 0},
            {"1.1.1.1": errno.EPERM, "registry.npmjs.org": -1},
            {"1.1.1.1": errno.EPERM, "registry.npmjs.org": errno.ECONNREFUSED},
        ):
            with patch(
                "rs9.tf_pypi_nebular.subprocess.run",
                side_effect=make_run(bad_py, ["TCP:EPERM", "DNS:ENOTFOUND"]),
            ), self.assertRaises(AdmissionError) as ctx_p:
                probe_network_denial("python3", "node", {})
            self.assertEqual(ctx_p.exception.code, "TF_PYPI_OFFLINE_ISOLATION")

    def test_probe_network_denial_tracks_host_eai_constants(self) -> None:
        import errno
        import subprocess

        def make_run(py_out: dict, node_lines: list[str]):
            def _run(cmd, **kwargs):
                if "-c" in cmd:
                    return subprocess.CompletedProcess(cmd, 0, json.dumps(py_out).encode("utf-8"), b"")
                return subprocess.CompletedProcess(cmd, 0, ("\n".join(node_lines) + "\n").encode("utf-8"), b"")

            return _run

        original_noname = socket.EAI_NONAME
        darwin_table = {
            "EAI_NONAME": 8,
            "EAI_AGAIN": 2,
            "EAI_FAIL": 4,
            "EAI_NODATA": 7,
        }
        glibc_table = {
            "EAI_NONAME": -2,
            "EAI_AGAIN": -3,
            "EAI_FAIL": -4,
            "EAI_NODATA": -5,
        }
        for table, foreign_noname in (
            (darwin_table, glibc_table["EAI_NONAME"]),
            (glibc_table, darwin_table["EAI_NONAME"]),
        ):
            with patch.multiple(socket, create=True, **table):
                for allowed_val in table.values():
                    with patch(
                        "rs9.tf_pypi_nebular.subprocess.run",
                        side_effect=make_run(
                            {"1.1.1.1": errno.EPERM, "registry.npmjs.org": allowed_val},
                            ["TCP:EPERM", "DNS:ENOTFOUND"],
                        ),
                    ):
                        res = probe_network_denial("python3", "node", {})
                    self.assertTrue(res["network_disabled"])
                    self.assertEqual(res["python_dns_errno"], allowed_val)

                with patch(
                    "rs9.tf_pypi_nebular.subprocess.run",
                    side_effect=make_run(
                        {"1.1.1.1": errno.EPERM, "registry.npmjs.org": foreign_noname},
                        ["TCP:EPERM", "DNS:ENOTFOUND"],
                    ),
                ), self.assertRaises(AdmissionError) as ctx_foreign:
                    probe_network_denial("python3", "node", {})
                self.assertEqual(ctx_foreign.exception.code, "TF_PYPI_OFFLINE_ISOLATION")

        self.assertEqual(socket.EAI_NONAME, original_noname)

    def test_verify_python39_refusal_and_orphan_process_checks(self) -> None:
        import subprocess

        fake_py39 = self.root / "fake_python39"
        fake_py39.write_bytes(b"#!/bin/sh\n")
        wheel_p = self.root / EXPECTED_WHEEL_FILENAME
        wheel_p.write_bytes(b"wheel")

        # 1. Absent interpreter returns blocked
        res_abs = verify_python39_refusal(wheel_p, self.root / "missing_py39", self.root / "w0", {})
        self.assertEqual(res_abs["status"], "blocked")

        # 2. Non-3.9 interpreter returns blocked
        with patch(
            "rs9.tf_pypi_nebular.subprocess.run",
            return_value=subprocess.CompletedProcess(
                [], 0, b'{"version":"3.13.12","major_minor":[3,13]}', b""
            ),
        ):
            res_ver = verify_python39_refusal(wheel_p, fake_py39, self.root / "w1", {})
        self.assertEqual(res_ver["status"], "blocked")

        # 3. Valid Requires-Python >=3.10 refusal passes, platform-tag failure fails closed
        def make_py39_run(stderr_msg: bytes, rc: int = 1, mutate_venv: bool = False):
            def _run(cmd, **kwargs):
                if "-c" in cmd:
                    return subprocess.CompletedProcess(
                        cmd, 0, b'{"version":"3.9.6","major_minor":[3,9]}', b""
                    )
                if "-m" in cmd and "venv" in cmd:
                    vdir = Path(cmd[-1])
                    (vdir / "bin").mkdir(parents=True, exist_ok=True)
                    (vdir / "bin/python").write_bytes(b"py")
                    return subprocess.CompletedProcess(cmd, 0, b"", b"")
                if mutate_venv:
                    vdir = Path(cmd[0]).parent.parent
                    (vdir / "bin/tfnf").write_bytes(b"leaked")
                return subprocess.CompletedProcess(cmd, rc, b"", stderr_msg)

            return _run

        with patch(
            "rs9.tf_pypi_nebular.subprocess.run",
            side_effect=make_py39_run(
                b"ERROR: Package 'theme-forge-nebular-fusion' requires a different Python: 3.9.6 not in '>=3.10'\n"
            ),
        ):
            gate = verify_python39_refusal(wheel_p, fake_py39, self.root / "w_pass", {})
        self.assertEqual(gate["status"], "pass")
        self.assertEqual(gate["client_python"], "3.9.6")

        # Platform tag error instead of Requires-Python fails closed
        with patch(
            "rs9.tf_pypi_nebular.subprocess.run",
            side_effect=make_py39_run(
                b"ERROR: theme_forge_nebular_fusion-0.6.1.whl is not a supported wheel on this platform.\n"
            ),
        ), self.assertRaises(AdmissionError) as ctx_plat:
            verify_python39_refusal(wheel_p, fake_py39, self.root / "w_plat", {})
        self.assertEqual(ctx_plat.exception.code, "TF_PYPI_PY39_REFUSAL_INVALID")

        # Venv mutated fails closed
        with patch(
            "rs9.tf_pypi_nebular.subprocess.run",
            side_effect=make_py39_run(
                b"ERROR: Package requires a different Python: 3.9.6 not in '>=3.10'\n",
                mutate_venv=True,
            ),
        ), self.assertRaises(AdmissionError) as ctx_mut:
            verify_python39_refusal(wheel_p, fake_py39, self.root / "w_mut", {})
        self.assertEqual(ctx_mut.exception.code, "TF_PYPI_PY39_REFUSAL_INVALID")

        # 4. _check_orphan_processes clean vs orphan present
        work_root = self.root / "consumer_work"
        work_root.mkdir()
        clean_ps = f"  1 /sbin/launchd\n  {os.getpid()} {work_root}/venv/bin/python\n".encode("utf-8")
        with patch(
            "rs9.tf_pypi_nebular.subprocess.run",
            return_value=subprocess.CompletedProcess([], 0, clean_ps, b""),
        ):
            orph = _check_orphan_processes(work_root, {})
        self.assertEqual(orph["orphan_processes"], 0)

        dirty_ps = f"  99999 {work_root}/cache/entries/x/payload/app/tfsb-studio-service\n".encode("utf-8")
        with patch(
            "rs9.tf_pypi_nebular.subprocess.run",
            return_value=subprocess.CompletedProcess([], 0, dirty_ps, b""),
        ), self.assertRaises(AdmissionError) as ctx_orph:
            _check_orphan_processes(work_root, {})
        self.assertEqual(ctx_orph.exception.code, "TF_PYPI_ORPHAN_PROCESSES_REMAIN")

    def test_bind_prepared_closure_and_authenticate_captured_negatives(self) -> None:
        from rs9.release_core import ReleaseCapture

        neb_commit = "49e2c4919b6b4ec9bd4ed5d7e7ced90921e00f5e"
        stl_commit = "a3e89683f92b8240c800ed303c866e7b12aa3277"
        closure_dir = self.root / "closure"
        src_dir = closure_dir / "source"
        (src_dir / "tools").mkdir(parents=True)
        files_spec = {
            "package.json": ("verifier-support", neb_commit, b'{"type":"module"}\n'),
            "tools/native-rc-smoke.mjs": ("application-smoke", neb_commit, b"// smoke\n"),
            "tools/sidecar-common.mjs": ("verifier-module", neb_commit, b"// common\n"),
            "tools/sidecar-verify.mjs": ("verifier-module", neb_commit, b"// verify\n"),
            f"{STELLAR_FIXTURE_PREFIX}manifest.json": ("fixture", stl_commit, b"{}\n"),
        }
        neb_tree_rows = []
        stl_tree_rows = []
        bindings = []
        for rel_p, (role, commit, data) in files_spec.items():
            full_p = src_dir / rel_p
            full_p.parent.mkdir(parents=True, exist_ok=True)
            full_p.write_bytes(data)
            git_blob = hashlib.sha1(f"blob {len(data)}\x00".encode("ascii") + data).hexdigest()
            row = {
                "path": rel_p,
                "blob": git_blob,
                "sha256": sha256(data),
                "size": len(data),
                "role": role,
                "tag_commit": commit,
            }
            bindings.append(row)
            tree_entry = {"path": rel_p, "type": "blob", "mode": "100644", "sha": git_blob, "size": len(data)}
            if commit == neb_commit:
                neb_tree_rows.append(tree_entry)
            else:
                stl_tree_rows.append(tree_entry)

        (closure_dir / "source-bindings.json").write_bytes(canonical(bindings))

        class DummyCap:
            def __init__(self, commit: str, tree_rows: list):
                self.record = {"tag": {"commit": commit}}
                self.tree_rows = tree_rows

        neb_cap = DummyCap(neb_commit, neb_tree_rows)
        stl_cap = DummyCap(stl_commit, stl_tree_rows)

        def fake_auth_tree(cap):
            return {"tree": cap.tree_rows}

        with patch("rs9.tf_pypi_nebular.authenticated_tree", side_effect=fake_auth_tree), patch(
            "rs9.tf_pypi_nebular.verify_source_readback"
        ):
            prep = bind_prepared_closure(closure_dir, neb_cap, stl_cap)  # type: ignore[arg-type]
            self.assertEqual(prep["file_count"], 5)

            # Role mismatch -> TF_PYPI_CLOSURE_ROLE_MISMATCH
            bad_role = copy.deepcopy(bindings)
            for r in bad_role:
                if r["path"] == "tools/native-rc-smoke.mjs":
                    r["role"] = "verifier-module"
            (closure_dir / "source-bindings.json").write_bytes(canonical(bad_role))
            with self.assertRaises(AdmissionError) as ctx_role:
                bind_prepared_closure(closure_dir, neb_cap, stl_cap)  # type: ignore[arg-type]
            self.assertEqual(ctx_role.exception.code, "TF_PYPI_CLOSURE_ROLE_MISMATCH")

            # Tree blob mismatch -> TF_PYPI_CLOSURE_TREE_MISMATCH
            bad_blob = copy.deepcopy(bindings)
            bad_blob[0]["blob"] = "f" * 40
            (closure_dir / "source-bindings.json").write_bytes(canonical(bad_blob))
            with self.assertRaises(AdmissionError) as ctx_tree:
                bind_prepared_closure(closure_dir, neb_cap, stl_cap)  # type: ignore[arg-type]
            self.assertEqual(ctx_tree.exception.code, "TF_PYPI_CLOSURE_TREE_MISMATCH")

            # Incomplete closure -> TF_PYPI_CLOSURE_INCOMPLETE
            (closure_dir / "source-bindings.json").write_bytes(canonical(bindings[:-1]))
            with self.assertRaises(AdmissionError) as ctx_inc:
                bind_prepared_closure(closure_dir, neb_cap, stl_cap)  # type: ignore[arg-type]
            self.assertEqual(ctx_inc.exception.code, "TF_PYPI_CLOSURE_INCOMPLETE")

        # authenticate_captured legal/icon refusals
        cap_dir = self.root / "cap_dir"
        cap_dir.mkdir()
        base_source = {
            "LICENSE": b"lic",
            "NOTICE": b"not",
            "COMMERCIAL-LICENSE.md": b"comm",
            "package.json": b"{}",
            "Cargo.toml": b"",
            "src-tauri/Cargo.toml": b"",
            "src-tauri/tauri.conf.json": b"{}",
            "src-tauri/icons/icon.png": b"png",
        }
        base_intent = {
            "project": {"id": PROJECT},
            "release": {"evidence": {"profile": "tauri-desktop-archive.v1alpha2"}},
            "desktop": {"icon": {"path": "src-tauri/icons/icon.png"}},
            "license": {"files": ["LICENSE", "NOTICE"]},
        }
        base_prof = {
            "sections": {
                "legacy_ingestion": {
                    "license": {
                        "status": "consistent",
                        "authority": "tagged-repository",
                        "declarations": [{"source": "tagged:LICENSE", "expression": "AGPL-3.0-or-later"}],
                    }
                }
            }
        }

        def run_auth_with(src_mod=None, intent_mod=None, prof_mod=None):
            src = copy.deepcopy(base_source)
            intent = copy.deepcopy(base_intent)
            prof = copy.deepcopy(base_prof)
            if src_mod:
                src_mod(src)
            if intent_mod:
                intent_mod(intent)
            if prof_mod:
                prof_mod(prof)
            dummy_capture = type("C", (), {"source": src})()
            with patch(
                "rs9.tf_pypi_nebular.checked_bootstrap_configurations",
                return_value=[({"repository": "r"}, intent)],
            ), patch("rs9.tf_pypi_nebular.selection_for_intent"), patch(
                "rs9.tf_pypi_nebular.authenticate_release", return_value=dummy_capture
            ), patch(
                "rs9.tf_pypi_nebular.assert_release_expectations"
            ), patch(
                "rs9.tf_pypi_nebular.load_bootstrap", return_value=intent
            ), patch(
                "rs9.tf_pypi_nebular.require_configuration_authority"
            ), patch(
                "rs9.tf_pypi_nebular.evaluate_profile", return_value=prof
            ), patch(
                "rs9.tf_pypi_nebular.strict_json", return_value={"projects": [{"repository": "r"}]}
            ):
                return authenticate_captured(cap_dir, project=PROJECT, repository=ROOT)

        # Missing COMMERCIAL-LICENSE.md -> TF_PYPI_MISSING_TAGGED_SOURCE
        with self.assertRaises(AdmissionError) as ctx_src:
            run_auth_with(src_mod=lambda s: s.pop("COMMERCIAL-LICENSE.md"))
        self.assertEqual(ctx_src.exception.code, "TF_PYPI_MISSING_TAGGED_SOURCE")

        # Missing tagged icon -> TF_PYPI_MISSING_TAGGED_ICON
        with self.assertRaises(AdmissionError) as ctx_ico:
            run_auth_with(src_mod=lambda s: s.pop("src-tauri/icons/icon.png"))
        self.assertEqual(ctx_ico.exception.code, "TF_PYPI_MISSING_TAGGED_ICON")

        # Legal file policy includes COMMERCIAL-LICENSE.md -> TF_PYPI_LEGAL_FILE_POLICY
        with self.assertRaises(AdmissionError) as ctx_pol:
            run_auth_with(intent_mod=lambda i: i["license"].update(files=["LICENSE", "NOTICE", "COMMERCIAL-LICENSE.md"]))
        self.assertEqual(ctx_pol.exception.code, "TF_PYPI_LEGAL_FILE_POLICY")

        # Inconsistent license authority -> TF_PYPI_LICENSE_INCONSISTENT
        with self.assertRaises(AdmissionError) as ctx_lic:
            run_auth_with(
                prof_mod=lambda p: p["sections"]["legacy_ingestion"]["license"].update(status="conflict")
            )
        self.assertEqual(ctx_lic.exception.code, "TF_PYPI_LICENSE_INCONSISTENT")

    def test_source_tree_state_github_token_and_in_repo_cross_zlib(self) -> None:
        import subprocess
        from rs9.tf_pypi_nebular import approval_document

        # 1. _github_client wires RS9_GITHUB_READ_TOKEN in GitHub Actions (LOW 3 / F2)
        with patch.dict(
            os.environ,
            {"GITHUB_ACTIONS": "true", "RS9_GITHUB_READ_TOKEN": "ghs_testToken123"},
            clear=False,
        ), patch("rs9.tf_pypi_nebular.PublicClient") as mock_pc:
            _github_client(None)
            mock_pc.assert_called_once_with(api_token="ghs_testToken123")

        # 2. source_tree_state enforces --require-clean when dirty and includes import-closure digest (MEDIUM 2 / Amendment 5)
        expected_sha = "a" * 40

        def fake_git_run(cmd, **kwargs):
            if "rev-parse" in cmd:
                return subprocess.CompletedProcess(cmd, 0, (expected_sha + "\n").encode("ascii"), b"")
            return subprocess.CompletedProcess(cmd, 0, b" M src/rs9/tf_pypi_nebular.py\n?? .serena/project.yml\n", b"")

        with patch("rs9.tf_pypi_nebular.subprocess.run", side_effect=fake_git_run):
            st = source_tree_state(expected_sha, repository=ROOT, require_clean=False)
            self.assertFalse(st["worktree_clean"])
            self.assertEqual(st["dirty_paths_count"], 1)
            self.assertEqual(st["closure_files_count"], 84)
            self.assertRegex(st["closure_files_sha256"], r"^[0-9a-f]{64}$")
            self.assertTrue(st["serena_excluded_from_dirty_check"])
            with self.assertRaises(AdmissionError) as ctx_dirty:
                source_tree_state(expected_sha, repository=ROOT, require_clean=True)
            self.assertEqual(ctx_dirty.exception.code, "TF_PYPI_HOSTED_WORKTREE_DIRTY")

        # 3. analyze_embedded_python_floor inspects package __init__.py and launcher.py alongside helpers (F5 / Amendment 6)
        floor = analyze_embedded_python_floor()
        self.assertEqual(floor["static_floor"], "3.10")
        self.assertIn("src/rs9/scratch.py:92", floor["decisive_construct"])

        with self.assertRaises(AdmissionError) as ctx_fl_syn:
            analyze_embedded_python_floor(
                extra_python_sources={
                    f"{PACKAGE_NAME}/launcher.py": b"try:\n    pass\nexcept* ValueError:\n    pass\n"
                }
            )
        self.assertEqual(ctx_fl_syn.exception.code, "TF_PYPI_PYTHON_FLOOR_SYNTAX")

        for py311_src in (
            b"import tomllib\n",
            b"import datetime\nx = datetime.UTC\n",
            b"raise ExceptionGroup('eg', [])\n",
            b"import contextlib\ncontextlib.chdir('.')\n",
            b"import asyncio\nasyncio.timeout(1)\n",
            b"from typing import LiteralString\n",
            b"from enum import ReprEnum\n",
            b"import operator\noperator.call(int)\n",
        ):
            with self.assertRaises(AdmissionError) as ctx_fl_std:
                analyze_embedded_python_floor(
                    extra_python_sources={f"{PACKAGE_NAME}/launcher.py": py311_src}
                )
            self.assertEqual(ctx_fl_std.exception.code, "TF_PYPI_PYTHON_FLOOR_STDLIB")

        # 4. verify_cross_zlib_wheel and approval_document cross-zlib enforcement (F4 / Amendment 3)
        dist_dir = self.root / "dist_zlib"
        w_path, synth_app = build_synthetic_approved_wheel(self.committed_approval, dist_dir)
        cross_self = verify_cross_zlib_wheel(w_path, alternate_python=sys.executable)
        self.assertTrue(cross_self["matches_primary"])
        self.assertEqual(cross_self["status"], "single-zlib-only")
        self.assertEqual(cross_self["sha256"], sha256(w_path.read_bytes()))

        cross_absent = verify_cross_zlib_wheel(w_path, alternate_python=self.root / "missing-python")
        self.assertEqual(cross_absent["status"], "alternate-interpreter-absent")
        self.assertIsNone(cross_absent["matches_primary"])
        self.assertIsNone(cross_absent["python_version"])
        self.assertIsNone(cross_absent["zlib_version"])

        with patch("rs9.tf_pypi_nebular.inspect_candidate", return_value={"file": synth_app["files"][0], "members": synth_app["members"], "macos_minimum_version": "13.0"}), patch(
            "rs9.tf_pypi_nebular.select_payload", return_value=synth_app["payload_asset"]
        ):
            dummy_neb = type("C", (), {"source": {"COMMERCIAL-LICENSE.md": b"c", "LICENSE": b"l", "NOTICE": b"n"}, "record": {}})()
            for bad_alt in (self.root / "missing-python", sys.executable):
                with self.assertRaises(AdmissionError) as ctx_cz:
                    approval_document(
                        w_path,
                        nebular_capture=dummy_neb,  # type: ignore[arg-type]
                        nebular_profile={},
                        stellar_capture=dummy_neb,  # type: ignore[arg-type]
                        stellar_profile={},
                        prepared_closure={},
                        repository=ROOT,
                        alternate_python=bad_alt,
                    )
                self.assertEqual(ctx_cz.exception.code, "TF_PYPI_CROSS_ZLIB_UNVERIFIED")

    def test_cli_forbids_upload_publish_dispatch_or_promote(self) -> None:
        for forbidden in ("publish", "upload", "dispatch", "promote", "admit"):
            with patch("sys.stderr", io.StringIO()), self.assertRaises(SystemExit):
                parser().parse_args([forbidden])


if __name__ == "__main__":
    unittest.main()
