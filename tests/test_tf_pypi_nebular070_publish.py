"""Unit and contract tests for the additive Nebular 0.7.0 three-wheel PyPI publisher seam."""
from __future__ import annotations

import copy
import io
import json
import os
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from rs9.profiles import selection_for_intent
from rs9.release_core import authenticate_release, digest
from rs9.scratch import canonical as gate1_canonical
from rs9.tf_pypi_archive import AdmissionError, canonical, sha256
from rs9.tf_pypi_hosted import (
    NEBULAR070_EXPECTED_ARTIFACT_SCHEMA,
    NEBULAR070_HOSTED_SCHEMA,
    admit_nebular070_matrix,
)
from rs9.tf_pypi_nebular070_publish import (
    ALL_KNOWN_WORKFLOW_JOB_NAMES,
    APPROVAL_BASENAME,
    APPROVAL_SCHEMA,
    BUILD_VERIFY_070_JOB_NAME,
    CANDIDATE_BUNDLE_ARTIFACT,
    CAPTURE_BASENAME,
    CAPTURE_SCHEMA,
    CURRENT_070_PROFILE_JOB_NAMES,
    DEFAULT_GITHUB_REPOSITORY,
    DESCRIPTION_PATH,
    DISPATCH_GUARD_070_JOB_NAME,
    DISTRIBUTION_NAME,
    DISTRIBUTION_VERSION,
    ENVIRONMENT,
    EXPECTED_COMMAND,
    EXPECTED_LICENSE_EXPRESSION,
    EXPECTED_OPTIONAL_LICENSE_FILES,
    EXPECTED_REQUIRED_LICENSE_FILES,
    EXPECTED_REQUIRES_PYTHON,
    EXPECTED_WHEEL_FILENAMES,
    LEGACY_061_BUILD_JOB_NAME,
    LEGACY_061_JOB_NAMES,
    MATRIX_RECEIPT_ARTIFACT,
    MAX_WHEEL_FILE_BYTES,
    PACKAGE_NAME,
    PIN_BASENAME,
    PIN_SCHEMA,
    PROJECT,
    QUALIFICATION_INPUTS_BASENAME,
    QUALIFICATION_INPUTS_PATH,
    QUALIFICATION_INPUTS_SCHEMA,
    QUALIFICATION_SOURCE_HELPERS,
    QUALIFY_070_JOB_NAMES,
    RAW_RELEASE_HANDOFF_SCHEMA,
    RESUME_070_JOB_NAME,
    SYSTEM_BY_TARGET,
    TAG,
    TAG_BY_TARGET,
    TARGETS,
    TARGET_QUALIFICATION_ARTIFACTS,
    VERSION,
    WORKFLOW,
    WORKFLOW_STEP_PROFILES,
    _validate_prior_run_jobs_map,
    Nebular070PublicReader,
    build_candidates_bundle,
    check_prior_publish_runs,
    compute_admission_sha256,
    compute_set_sha256,
    default_sandbox_prefix,
    exact_state,
    inspect_candidate_wheel,
    load_approval,
    load_pin,
    load_qualification_capture,
    load_qualification_inputs_descriptor,
    load_raw_release_handoff,
    main,
    make_real_user_state_snapshotter,
    materialize_qualification_evidence,
    materialize_raw_release_handoff,
    prepare_resume,
    project_state,
    publication_resume_job_text,
    qualify_native_target,
    readback,
    remote_state,
    select_missing,
    stage_metadata,
    validate_api_metadata,
    validate_approval,
    validate_archives,
    validate_pin,
    validate_qualification_capture,
    validate_qualification_inputs_descriptor,
    validate_raw_release_handoff_binding,
    validate_workflow_dispatch,
    verify_approved,
    verify_matrix_receipts,
    verify_source_lineage,
    verify_upload_dir,
    workflow_070_jobs_text,
    workflow_070_qualify_jobs_text,
    workflow_text,
)
from rs9.tf_pypi_nebular_successor import (
    authenticate_gate1_capture,
    build_gate1_candidates,
    write_gate1_receipt,
)
from rs9.wheel import _record_digest
from tests.test_nebular070_gate1_roundtrip import _macho_13, _prepare_fixture, _tar
from tests.tf_pypi_fixtures import ROOT


CANDIDATE_COMMIT = "c" * 40
CANDIDATE_TREE = "d" * 40
QUALIFICATION_COMMIT = subprocess.check_output(
    ["git", "-C", str(ROOT), "rev-parse", "HEAD^{commit}"], text=True
).strip()
QUALIFICATION_TREE = subprocess.check_output(
    ["git", "-C", str(ROOT), "rev-parse", "HEAD^{tree}"], text=True
).strip()
RUN_ID = "9007001"


def _fill_current_profile_steps(raw_jobs: list[dict]) -> list[dict]:
    """Give positive retained-job fixtures the explicit current-step evidence."""
    filled = copy.deepcopy(raw_jobs)
    for job in filled:
        if (
            job.get("name") in CURRENT_070_PROFILE_JOB_NAMES
            and job.get("conclusion") != "skipped"
            and job.get("steps") == []
        ):
            job["steps"] = [
                {
                    "name": step_name,
                    "status": "completed",
                    "conclusion": "success",
                }
                for step_name, _is_action in WORKFLOW_STEP_PROFILES[job["name"]]
            ]
    return filled


def _make_zip_bytes(files: dict[str, bytes], *, symlink_name: str | None = None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in sorted(files.items()):
            zi = zipfile.ZipInfo(name, date_time=(2026, 10, 1, 0, 0, 0))
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.create_system = 3
            zi.external_attr = (stat.S_IFREG | 0o644) << 16
            zf.writestr(zi, data)
        if symlink_name is not None:
            zi = zipfile.ZipInfo(symlink_name, date_time=(2026, 10, 1, 0, 0, 0))
            zi.create_system = 3
            zi.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(zi, b"target")
    return buf.getvalue()


def _macho_14() -> bytes:
    minimum = (14 << 16) | (0 << 8) | 0
    header = struct.pack("<IIIIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 1, 24, 0, 0)
    command = struct.pack("<IIIIII", 0x32, 24, 1, minimum, minimum, 0)
    return header + command


_RC_PLATFORMS = {
    "darwin-arm64": "darwin-arm64",
    "linux-arm64-gnu": "linux-arm64",
    "linux-x64-gnu": "linux-x64",
}
_RC_TRIPLES = {
    "darwin-arm64": "aarch64-apple-darwin",
    "linux-arm64-gnu": "aarch64-unknown-linux-gnu",
    "linux-x64-gnu": "x86_64-unknown-linux-gnu",
}
_RC_SCENARIOS = {
    "darwin-arm64": {"raw-archive": "A", "npm-package": "A"},
    "linux-arm64-gnu": {"raw-archive": "B", "npm-package": "B"},
    "linux-x64-gnu": {"raw-archive": "C", "npm-package": "C-signal"},
}
_RC_STEPS = {
    "A": (
        "app-shell",
        "host-start",
        "host-status",
        "project-open",
        "brand-read",
        "theme-lab-compile",
        "app-theme-status",
        "app-theme-compile",
        "brand-system-view",
        "host-status-final",
    ),
    "B": (
        "app-shell",
        "app-theme-status",
        "app-theme-compile",
        "theme-lab-compile",
        "brand-system-view",
        "host-start",
        "host-status",
        "project-open-upper",
        "brand-read-upper",
        "project-open-lower",
        "brand-read-lower",
        "host-status-final",
    ),
    "C": (
        "app-shell",
        "host-start",
        "host-start-idempotent",
        "host-stop",
        "host-start-again",
        "host-status",
        "project-open-case",
        "derive-plan-cancel",
        "derive-plan-apply",
        "host-status-final",
    ),
    "C-signal": (
        "app-shell",
        "host-start",
        "host-start-idempotent",
        "host-stop",
        "host-start-again",
        "host-status",
        "project-open-case",
        "derive-plan-cancel",
        "derive-plan-apply",
        "host-status-final",
    ),
}


def _rewrite_fixture_payload_distinct_executables(
    repo: Path,
    evidence: Path,
    intent: dict,
    binding: dict,
) -> None:
    """Ensure all 3 fixture payload archives contain distinct launcher, GUI, and sidecar executables."""
    import plistlib
    from tests.test_nebular070_gate1_roundtrip import COMMERCIAL, LICENSE, NOTICE

    darwin_root = "Theme Forge Nebular Fusion.app"
    plist = plistlib.dumps(
        {"LSMinimumSystemVersion": "13.0", "CFBundleIdentifier": "ai.fixture.nebular"}
    )
    darwin_bytes = _tar(
        [
            (darwin_root, b"", 0o755, tarfile.DIRTYPE),
            (f"{darwin_root}/Contents", b"", 0o755, tarfile.DIRTYPE),
            (f"{darwin_root}/Contents/Info.plist", plist, 0o644, tarfile.REGTYPE),
            (f"{darwin_root}/Contents/MacOS", b"", 0o755, tarfile.DIRTYPE),
            (
                f"{darwin_root}/Contents/MacOS/tfsb-studio-service",
                _macho_13() + b"\x00\x01",
                0o755,
                tarfile.REGTYPE,
            ),
            (
                f"{darwin_root}/Contents/MacOS/theme-forge-nebular-fusion",
                _macho_13(),
                0o755,
                tarfile.REGTYPE,
            ),
            (f"{darwin_root}/Contents/Resources", b"", 0o755, tarfile.DIRTYPE),
            (f"{darwin_root}/Contents/Resources/bin", b"", 0o755, tarfile.DIRTYPE),
            (
                f"{darwin_root}/Contents/Resources/bin/tfnf",
                b"#!/bin/sh\nprintf 'NEBULAR_SMOKE_DARWIN\\n'\n",
                0o755,
                tarfile.REGTYPE,
            ),
            (
                f"{darwin_root}/Contents/Resources/sidecar-payload",
                b"",
                0o755,
                tarfile.DIRTYPE,
            ),
            (
                f"{darwin_root}/Contents/Resources/sidecar-payload/native-addon.node",
                _macho_13(),
                0o644,
                tarfile.REGTYPE,
            ),
            (f"{darwin_root}/Contents/Resources/LICENSE", LICENSE, 0o644, tarfile.REGTYPE),
            (f"{darwin_root}/Contents/Resources/NOTICE", NOTICE, 0o644, tarfile.REGTYPE),
            (
                f"{darwin_root}/Contents/Resources/COMMERCIAL-LICENSE.md",
                COMMERCIAL,
                0o644,
                tarfile.REGTYPE,
            ),
        ]
    )

    def _linux_distinct(label: str) -> bytes:
        l_root = "theme-forge-nebular-fusion"
        return _tar(
            [
                (l_root, b"", 0o755, tarfile.DIRTYPE),
                (f"{l_root}/bin", b"", 0o755, tarfile.DIRTYPE),
                (
                    f"{l_root}/bin/tfnf",
                    f"#!/bin/sh\nprintf 'NEBULAR_SMOKE_{label}\\n'\n".encode(),
                    0o755,
                    tarfile.REGTYPE,
                ),
                (
                    f"{l_root}/bin/theme-forge-nebular-fusion",
                    f"#!/bin/sh\n# gui-{label}\nexit 0\n".encode(),
                    0o755,
                    tarfile.REGTYPE,
                ),
                (
                    f"{l_root}/bin/tfsb-studio-service",
                    f"#!/bin/sh\n# sidecar-{label}\nexit 0\n".encode(),
                    0o755,
                    tarfile.REGTYPE,
                ),
                (f"{l_root}/LICENSE", LICENSE, 0o644, tarfile.REGTYPE),
                (f"{l_root}/NOTICE", NOTICE, 0o644, tarfile.REGTYPE),
                (f"{l_root}/COMMERCIAL-LICENSE.md", COMMERCIAL, 0o644, tarfile.REGTYPE),
            ]
        )

    payload_by_id = {
        "darwin-arm64": darwin_bytes,
        "linux-arm64": _linux_distinct("LINUX_ARM64"),
        "linux-x64": _linux_distinct("LINUX_X64"),
    }
    assets_dir = evidence / "assets"
    raw_assets = {
        p.name: p.read_bytes()
        for p in sorted(assets_dir.iterdir())
        if p.is_file() and p.name != "SHA256SUMS"
    }
    for asset in intent["assets"]:
        raw_assets[asset["name"]] = payload_by_id[asset["id"]]
    raw_assets["SHA256SUMS"] = "".join(
        digest(data) + "  " + name + "\n" for name, data in sorted(raw_assets.items())
    ).encode()
    for name, data in raw_assets.items():
        (assets_dir / name).write_bytes(data)

    api_dir = evidence / "api"
    release_api = json.loads((api_dir / "release.json").read_bytes())
    release_api["assets"] = [
        {
            "id": idx,
            "name": name,
            "size": len(data),
            "digest": "sha256:" + digest(data),
            "state": "uploaded",
        }
        for idx, (name, data) in enumerate(sorted(raw_assets.items()), start=1)
    ]
    (api_dir / "release.json").write_bytes(gate1_canonical(release_api))

    capture = authenticate_release(selection_for_intent(intent), evidence)
    expectations_path = repo / binding["expectations_path"]
    expectations = json.loads(expectations_path.read_bytes())
    expectations["projects"][0]["assets"] = [
        {
            "name": row["name"],
            "size": row["size"],
            "sha256": row["sha256"],
            "id": row["github_asset_id"],
        }
        for row in capture.record["assets"]
        if row["role"] == "payload"
    ]
    expectations_path.write_bytes(gate1_canonical(expectations))
    binding["expected"]["expectations_sha256"] = digest(expectations_path.read_bytes())


def _build_qualification_inputs_descriptor_for_repo(
    base_dir: Path,
    repo: Path,
    evidence: Path,
    binding: dict,
) -> tuple[dict, Path]:
    """Construct a complete, digest-bound qualification-inputs descriptor and raw-release source tree."""
    from rs9.hosted_platforms import select_payload

    authenticated = authenticate_gate1_capture(
        repo,
        evidence,
        release_binding=binding,
        approved_bootstrap_sha256=binding["expected"]["bootstrap_sha256"],
    )
    ev_rel_root = "operators/tf-pypi/nebular-0.7.0-evidence"
    raw_rel_root = "operators/tf-pypi/nebular-0.7.0-raw-release"
    repo_ev_dir = repo / ev_rel_root
    if repo_ev_dir.exists():
        shutil.rmtree(repo_ev_dir)
    shutil.copytree(evidence, repo_ev_dir)
    raw_src = repo / raw_rel_root
    raw_src.mkdir(parents=True, exist_ok=True)

    record_bytes = gate1_canonical(authenticated.capture.record)
    (raw_src / "release.json").write_bytes(record_bytes)

    readme_rel = DESCRIPTION_PATH.as_posix()
    readme_bytes = (repo / DESCRIPTION_PATH).read_bytes()
    readme_dst = raw_src / DESCRIPTION_PATH
    readme_dst.parent.mkdir(parents=True, exist_ok=True)
    readme_dst.write_bytes(readme_bytes)

    legal_map = {}
    for leg_name in ("LICENSE", "NOTICE", "COMMERCIAL-LICENSE.md"):
        leg_bytes = authenticated.capture.source[leg_name]
        (raw_src / leg_name).write_bytes(leg_bytes)
        legal_map[leg_name] = {
            "path": leg_name,
            "size": len(leg_bytes),
            "sha256": sha256(leg_bytes),
        }

    prov_bytes = (evidence / "assets/PROVENANCE.json").read_bytes()
    (raw_src / "PROVENANCE.json").write_bytes(prov_bytes)

    targets_spec = {}
    for target in TARGETS:
        system = SYSTEM_BY_TARGET[target]
        selected = select_payload(authenticated.capture, system, allow_any=False)
        asset_id = selected["id"]
        payload_name = selected["name"]
        payload_bytes = authenticated.capture.archives[asset_id].read_bytes()
        (raw_src / payload_name).write_bytes(payload_bytes)

        manifest_obj = authenticated.capture.manifests[asset_id]
        members = manifest_obj["members"]
        manifest_bytes = gate1_canonical(members)
        manifest_filename = f"manifest-{target}.json"
        (raw_src / manifest_filename).write_bytes(manifest_bytes)

        by_path = {m["path"]: m for m in members if isinstance(m, dict) and "path" in m}
        if target == "darwin-arm64":
            gui_path = "Theme Forge Nebular Fusion.app/Contents/MacOS/theme-forge-nebular-fusion"
            launcher_path = "Theme Forge Nebular Fusion.app/Contents/Resources/bin/tfnf"
            sidecar_path = "Theme Forge Nebular Fusion.app/Contents/MacOS/tfsb-studio-service"
            smoke_gui_path = gui_path
        else:
            gui_path = "theme-forge-nebular-fusion/bin/theme-forge-nebular-fusion"
            launcher_path = "theme-forge-nebular-fusion/bin/tfnf"
            sidecar_path = "theme-forge-nebular-fusion/bin/tfsb-studio-service"
            smoke_gui_path = "bin/theme-forge-nebular-fusion"

        gui_entry = by_path[gui_path]
        launcher_entry = by_path[launcher_path]
        sidecar_entry = by_path[sidecar_path]
        executable_sha = gui_entry["sha256"]
        launcher_sha = launcher_entry["sha256"]
        sidecar_sha = sidecar_entry["sha256"]

        provider_obs = sha256(f"host-observed:{target}".encode())
        provider_detail = {
            "observationIdentity": provider_obs,
            "observedProviderRows": [
                {
                    "soname": "libc.so.6",
                    "classification": "external-floor",
                    "requestedPath": "/lib/libc.so.6",
                    "terminalPath": "/lib/libc.so.6",
                    "aliasChain": [],
                    "terminalFull9": ["fixture"],
                    "bytes": 1,
                    "sha256": "f" * 64,
                    "elfMachine": "fixture",
                    "elfClass": "ELF64",
                    "versionDefinitions": ["GLIBC_2.36"],
                    "readelfEvidenceSha256": "a" * 64,
                }
            ],
            "subjectResolutionRows": [
                {
                    "subjectRelativePath": "bin/theme-forge-nebular-fusion",
                    "neededSoname": "libc.so.6",
                    "resolvedPath": "/lib/libc.so.6",
                    "providerObservationIdentity": provider_obs,
                }
            ],
            "toolEvidence": {
                "readelfRole": "actual-provider-terminal-readelf",
                "resolutionToolRole": "actual-consumer-ldd",
                "cleanupFacts": {
                    "allCommandsBounded": True,
                    "noSurvivingProcessFamily": True,
                },
            },
        }
        checks = [
            {
                "id": "executable-header",
                "ok": True,
                "detail": "ELF64/Mach-O header verified",
            },
            {"id": "launcher", "ok": True, "detail": launcher_sha},
            {
                "id": "sidecar-runtime",
                "ok": True,
                "detail": f"node 22.23.3 {sidecar_sha}",
            },
        ]
        if target.startswith("linux"):
            checks.extend(
                [
                    {"id": "mode:gui", "ok": True, "detail": "0755"},
                    {"id": "mode:sidecar", "ok": True, "detail": "0755"},
                    {"id": "mode:launcher", "ok": True, "detail": "0755"},
                    {"id": "glibc:gui", "ok": True, "detail": "2.36"},
                    {"id": "glibc:sidecar", "ok": True, "detail": "2.36"},
                    {"id": "glibc-floor", "ok": True, "detail": "2.36"},
                    {"id": "linkage", "ok": True, "detail": "ldd closure"},
                    {
                        "id": "private-runtime-closure",
                        "ok": True,
                        "detail": provider_detail,
                    },
                ]
            )
        else:
            checks.extend(
                [
                    {"id": "legal-notices", "ok": True, "detail": "LICENSE, NOTICE"},
                    {"id": "codesign", "ok": True, "detail": "valid · Signature=adhoc"},
                ]
            )

        qual_doc = {
            "schema": "nebular.native-rc-qualification-v1",
            "platform": _RC_PLATFORMS[target],
            "status": "pass",
            "executableSha256": executable_sha,
            "glibcMinimum": "2.36" if target.startswith("linux") else None,
            "nativePayload": {
                "identity": sha256(f"payload:{target}".encode()),
                "files": 1,
            },
            "materialDigest": sha256(f"material:{target}".encode()),
            "checks": checks,
        }
        qual_bytes = canonical(qual_doc)
        qual_filename = f"qualification-{target}.json"
        (raw_src / qual_filename).write_bytes(qual_bytes)

        smoke = {}
        for smoke_source, smoke_scenario in _RC_SCENARIOS[target].items():
            smoke_receipt = {
                "schema": "nebular.release-smoke-receipt-v1",
                "scenario": smoke_scenario,
                "status": "pass",
                "target": _RC_TRIPLES[target],
                "awaitingSignal": smoke_scenario == "C-signal",
                "executable": {"sha256": executable_sha},
                "driver": {
                    "steps": [
                        {"id": step, "ok": True, "via": "controlled-driver", "ms": 1}
                        for step in _RC_STEPS[smoke_scenario]
                    ]
                },
            }
            s_rec_bytes = canonical(smoke_receipt)
            s_rec_name = f"smoke-receipt-{target}-{smoke_source}.json"
            (raw_src / s_rec_name).write_bytes(s_rec_bytes)
            s_rec_sha = sha256(s_rec_bytes)

            smoke_run = {
                "schema": "nebular.native-rc-smoke-run-v1",
                "label": f"{target}-{smoke_source}",
                "platform": _RC_PLATFORMS[target],
                "scenario": smoke_scenario,
                "source": smoke_source,
                "status": "pass",
                "problems": [],
                "executable": {
                    "path": smoke_gui_path,
                    "sha256": executable_sha,
                    "size": gui_entry["size"],
                },
                "checks": {
                    "orphans": [],
                    "persistentUserState": {"locations": 3, "changed": []},
                    "scratchHomeWrites": 1,
                },
                "finalization": {
                    "schema": "nebular.native-rc-finalization-v1",
                    "status": "complete",
                    "exitObserved": True,
                    "applicationReceiptObservation": "present-at-read",
                    "applicationReceiptCopy": "written",
                },
                "receipt": {
                    "sha256": s_rec_sha,
                    "status": "pass",
                    "steps": [
                        {"id": step, "ok": True, "via": "controlled-driver", "ms": 1}
                        for step in _RC_STEPS[smoke_scenario]
                    ],
                },
            }
            s_run_bytes = canonical(smoke_run)
            s_run_name = f"smoke-run-{target}-{smoke_source}.json"
            (raw_src / s_run_name).write_bytes(s_run_bytes)
            smoke[smoke_source] = {
                "run": {
                    "path": s_run_name,
                    "size": len(s_run_bytes),
                    "sha256": sha256(s_run_bytes),
                },
                "receipt": {
                    "path": s_rec_name,
                    "size": len(s_rec_bytes),
                    "sha256": s_rec_sha,
                },
            }

        provider_check_id = (
            "private-runtime-closure"
            if target.startswith("linux")
            else "sidecar-runtime"
        )
        provider_detail_for_digest = (
            provider_detail
            if target.startswith("linux")
            else f"node 22.23.3 {sidecar_sha}"
        )
        provider_evidence = {
            "qualification_sha256": sha256(qual_bytes),
            "qualification_check_id": provider_check_id,
            "qualification_detail_sha256": sha256(canonical(provider_detail_for_digest)),
            "smoke_receipts": {
                name: smoke[name]["receipt"]["sha256"] for name in sorted(smoke)
            },
        }
        native_scenario = _RC_SCENARIOS[target]["raw-archive"]
        targets_spec[target] = {
            "schema": RAW_RELEASE_HANDOFF_SCHEMA,
            "target": target,
            "record": {
                "path": "release.json",
                "size": len(record_bytes),
                "sha256": sha256(record_bytes),
            },
            "readme": {
                "path": readme_rel,
                "size": len(readme_bytes),
                "sha256": sha256(readme_bytes),
            },
            "legal_files": legal_map,
            "payload": {
                "path": payload_name,
                "name": payload_name,
                "size": len(payload_bytes),
                "sha256": sha256(payload_bytes),
            },
            "manifest": {
                "path": manifest_filename,
                "size": len(manifest_bytes),
                "sha256": sha256(manifest_bytes),
            },
            "provenance": {
                "path": "PROVENANCE.json",
                "size": len(prov_bytes),
                "sha256": sha256(prov_bytes),
            },
            "native_consumer": {
                target: {
                    "command": "tfnf",
                    "protocol": "nebular.native-rc-smoke",
                    "platform": _RC_PLATFORMS[target],
                    "scenario": native_scenario,
                    "argv": [f"--nebular-release-smoke={native_scenario}"],
                    "timeout_seconds": 20,
                    "state_paths": ["state/nebular"],
                    "user_state_protocol": {
                        "schema": "nebular.native-rc-persistent-user-state-v1",
                        "method": "native-rc-smoke.persistentStateLocations+snapshotLocations",
                        "scope": "real-user-state",
                    },
                    "qualification": {
                        "path": qual_filename,
                        "size": len(qual_bytes),
                        "sha256": sha256(qual_bytes),
                    },
                    "smoke": smoke,
                    "loader": {
                        "status": "verified",
                        "path": launcher_path,
                        "sha256": launcher_sha,
                        "qualification_check_id": "launcher",
                    },
                    "provider_closure": {
                        "status": "verified",
                        "target": target,
                        "mode": "host-observed",
                        "emulated": False,
                        "qualification_check_id": provider_check_id,
                        "evidence_sha256": sha256(canonical(provider_evidence)),
                    },
                }
            },
        }

    ev_files = {}
    for dirpath, _dirnames, filenames in os.walk(repo_ev_dir):
        dp = Path(dirpath)
        for fname in sorted(filenames):
            fpath = dp / fname
            if fpath.is_file():
                rel_p = fpath.relative_to(repo_ev_dir).as_posix()
                b_data = fpath.read_bytes()
                ev_files[rel_p] = {
                    "path": rel_p,
                    "size": len(b_data),
                    "sha256": sha256(b_data),
                }

    descriptor = {
        "schema": QUALIFICATION_INPUTS_SCHEMA,
        "project": PROJECT,
        "version": VERSION,
        "distribution_version": DISTRIBUTION_VERSION,
        "workflow": WORKFLOW,
        "status": "ready",
        "upstream_origin": {
            "repository": binding["repository"],
            "tag": TAG,
            "release_url": f"https://github.com/{binding['repository']}/releases/tag/{TAG}",
            "api_release_url": f"https://api.github.com/repos/{binding['repository']}/releases/tags/{TAG}",
        },
        "release_binding": binding,
        "release_binding_sha256": sha256(canonical(binding)),
        "evidence": {
            "source_root": ev_rel_root,
            "files": ev_files,
        },
        "raw_release": {
            "source_root": raw_rel_root,
            "targets": targets_spec,
        },
    }
    desc_path = repo / QUALIFICATION_INPUTS_PATH
    desc_path.parent.mkdir(parents=True, exist_ok=True)
    desc_path.write_bytes(canonical(descriptor))
    return descriptor, desc_path


@contextmanager
def _controlled_native_consumer_driver(
    target: str,
    clean_home: Path,
    observed_prefixes: list[tuple[str, ...]],
):
    """Controlled low-level driver for local test execution of qualify_nebular070 -> consume_nebular_candidate.

    Exercises the real qualify_nebular070, consume_nebular_candidate, _nebular_validate_capture,
    network_denial, _nebular_run, make_real_user_state_snapshotter, _nebular_process_snapshot,
    and embedded wheel launcher materialization without host network or root unshare privileges.
    """
    import errno
    import shlex

    expected_pfx = default_sandbox_prefix(target)
    real_popen = subprocess.Popen
    sys_name = "Darwin" if target == "darwin-arm64" else "Linux"
    machine_name = (
        "arm64"
        if target == "darwin-arm64"
        else ("aarch64" if target == "linux-arm64-gnu" else "x86_64")
    )
    sys_plat = "darwin" if target == "darwin-arm64" else "linux"

    def _fake_venv_create(self_builder, venv_dir):
        v_path = Path(venv_dir)
        (v_path / "bin").mkdir(parents=True, exist_ok=True)
        (v_path / "site").mkdir(parents=True, exist_ok=True)
        py_wrap = v_path / "bin" / "python"
        py_wrap.write_text(
            f"#!/bin/sh\nexec {shlex.quote(sys.executable)} \"$@\"\n",
            encoding="utf-8",
        )
        py_wrap.chmod(0o755)

    def _fake_success(cmd, env, prefix=()):
        observed_prefixes.append(tuple(prefix))
        cmd_strs = [str(c) for c in cmd]
        if "-c" in cmd_strs:
            out = json.dumps(
                {"1.1.1.1": errno.EPERM, "registry.npmjs.org": errno.EPERM}
            ).encode("utf-8")
            return subprocess.CompletedProcess(cmd, 0, stdout=out, stderr=b"")
        return subprocess.CompletedProcess(
            cmd, 0, stdout=b"EPERM\nENOTFOUND\n", stderr=b""
        )

    def _controlled_popen(command, *args, **kwargs):
        cmd_list = [str(c) for c in command]
        pfx_len = len(expected_pfx)
        assert tuple(cmd_list[:pfx_len]) == expected_pfx, (
            cmd_list[:pfx_len],
            expected_pfx,
        )
        observed_prefixes.append(tuple(cmd_list[:pfx_len]))
        inner = cmd_list[pfx_len:]
        cwd = Path(kwargs["cwd"])
        venv_root = cwd / "venv"
        site_dir = venv_root / "site"
        if len(inner) >= 5 and inner[3:6] == ["-m", "pip", "install"]:
            wheel_file = Path(inner[-1])
            with zipfile.ZipFile(wheel_file, "r") as zf:
                for info in zf.infolist():
                    if info.is_dir():
                        continue
                    dest = site_dir / info.filename
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    dest.write_bytes(zf.read(info))
            tfnf_bin = venv_root / "bin" / "tfnf"
            runner_code = (
                "import platform, sys; "
                f"sys.path.insert(0, {repr(str(site_dir))}); "
                f"sys.platform = {repr(sys_plat)}; "
                f"platform.machine = lambda: {repr(machine_name)}; "
                "platform.libc_ver = lambda *a, **k: ('glibc', '2.36'); "
                "from theme_forge_nebular_fusion.launcher import main_tfnf; "
                "main_tfnf()"
            )
            tfnf_bin.write_text(
                f"#!/bin/sh\nexec {shlex.quote(sys.executable)} -I -B -c {shlex.quote(runner_code)} \"$@\"\n",
                encoding="utf-8",
            )
            tfnf_bin.chmod(0o755)
            return real_popen(
                [sys.executable, "-I", "-B", "-c", "pass"], *args, **kwargs
            )
        if len(inner) >= 5 and inner[3:6] == ["-m", "pip", "uninstall"]:
            if site_dir.exists():
                shutil.rmtree(site_dir)
            tfnf_bin = venv_root / "bin" / "tfnf"
            if tfnf_bin.exists():
                tfnf_bin.unlink()
            return real_popen(
                [sys.executable, "-I", "-B", "-c", "pass"], *args, **kwargs
            )
        return real_popen(inner, *args, **kwargs)

    import re
    import rs9.tf_pypi_consumer as _consumer_mod
    import rs9.tf_pypi_hosted as _hosted_mod
    import rs9.tf_pypi_nebular070_publish as _pub070_mod

    real_source_commit = _hosted_mod.source_commit
    real_nebular_tree = _hosted_mod._nebular_tree

    def _repo_aware_source_commit(expected):
        cur_root = _pub070_mod.repo_root()
        if cur_root == ROOT:
            return real_source_commit(expected)
        if not re.fullmatch(r"[0-9a-f]{40}", expected or ""):
            from rs9.tf_pypi_archive import fail as _fail

            _fail("HOSTED_COMMIT")
        res = subprocess.run(
            ["git", "-C", str(cur_root), "rev-parse", "HEAD"],
            capture_output=True,
            timeout=15,
            check=False,
        )
        if res.returncode or res.stdout.decode("ascii", "replace").strip() != expected:
            from rs9.tf_pypi_archive import fail as _fail

            _fail("HOSTED_COMMIT")
        return expected

    def _repo_aware_nebular_tree(expected):
        cur_root = _pub070_mod.repo_root()
        if cur_root == ROOT:
            return real_nebular_tree(expected)
        if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{40}", expected):
            from rs9.tf_pypi_archive import fail as _fail

            _fail("NEBULAR_HOSTED_TREE")
        res = subprocess.run(
            ["git", "-C", str(cur_root), "rev-parse", "HEAD^{tree}"],
            capture_output=True,
            timeout=15,
            check=False,
        )
        if res.returncode or res.stdout.decode("ascii", "replace").strip() != expected:
            from rs9.tf_pypi_archive import fail as _fail

            _fail("NEBULAR_HOSTED_TREE")
        return expected

    with (
        patch("rs9.nebular_host_state.operator_home", return_value=clean_home),
        patch("rs9.tf_pypi_consumer.platform.system", return_value=sys_name),
        patch("rs9.tf_pypi_consumer.platform.machine", return_value=machine_name),
        patch(
            "rs9.tf_pypi_consumer.platform.libc_ver",
            return_value=("glibc", "2.36"),
        ),
        patch("rs9.tf_pypi_consumer.node_binary", return_value="/usr/bin/true"),
        patch("rs9.tf_pypi_consumer._success", side_effect=_fake_success),
        patch("rs9.tf_pypi_consumer.venv.EnvBuilder.create", _fake_venv_create),
        patch.dict(
            _consumer_mod.consume_nebular_candidate.__kwdefaults__,
            {"runner": _controlled_popen},
        ),
        patch("rs9.tf_pypi_hosted.source_commit", side_effect=_repo_aware_source_commit),
        patch("rs9.tf_pypi_hosted._nebular_tree", side_effect=_repo_aware_nebular_tree),
    ):
        yield


class Nebular070PublisherSeamTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._class_tmp = tempfile.TemporaryDirectory(prefix="rs9-neb070-pub-cls-")
        cls.fixture_root = Path(cls._class_tmp.name).resolve()
        repo, evidence, _intent, binding = _prepare_fixture(cls.fixture_root / "gate1")
        authenticated = authenticate_gate1_capture(
            repo,
            evidence,
            release_binding=binding,
            approved_bootstrap_sha256=binding["expected"]["bootstrap_sha256"],
        )
        cls.candidates_dir = cls.fixture_root / "candidates"
        cls.candidate_receipt = build_gate1_candidates(
            authenticated,
            cls.candidates_dir,
            rs9_source_commit=CANDIDATE_COMMIT,
            rs9_source_tree=CANDIDATE_TREE,
            deterministic_timestamp=(2026, 10, 1, 0, 0, 0),
        )
        cls.candidate_receipt_path = cls.fixture_root / "candidate_receipt.json"
        write_gate1_receipt(
            cls.candidate_receipt_path,
            cls.candidate_receipt,
            authenticated=authenticated,
            output_dir=cls.candidates_dir,
        )
        cls.candidate_receipt_bytes = cls.candidate_receipt_path.read_bytes()
        cls.candidate_receipt_sha = sha256(canonical(cls.candidate_receipt))

        cls.dist_dir = cls.fixture_root / "dist"
        cls.dist_dir.mkdir(parents=True, exist_ok=True)
        cls.wheel_bytes_by_name: dict[str, bytes] = {}
        wheels_list = []
        for row in cls.candidate_receipt["rows"]:
            target = next(t for t, s in SYSTEM_BY_TARGET.items() if s == row["system"])
            src_w = cls.candidates_dir / row["system"] / row["wheel"]["filename"]
            dst_w = cls.dist_dir / row["wheel"]["filename"]
            shutil.copyfile(src_w, dst_w)
            cls.wheel_bytes_by_name[row["wheel"]["filename"]] = dst_w.read_bytes()
            wheels_list.append({"target": target, **row["wheel"]})
        wheels_sorted = sorted(wheels_list, key=lambda r: r["target"])
        cls.expected_artifacts = {
            "schema": NEBULAR070_EXPECTED_ARTIFACT_SCHEMA,
            "candidate_rs9_source": cls.candidate_receipt["candidate_rs9_source"],
            "wheels": wheels_sorted,
            "record_sha256": sha256(canonical(wheels_sorted)),
        }
        cls.expected_artifacts_path = cls.fixture_root / "expected_artifacts.json"
        cls.expected_artifacts_bytes = canonical(cls.expected_artifacts)
        cls.expected_artifacts_path.write_bytes(cls.expected_artifacts_bytes)

        cls.profile_sha = cls.candidate_receipt["profile_result_sha256"]
        cls.receipts_dir = cls.fixture_root / "receipts"
        cls.target_receipt_bytes: dict[str, bytes] = {}
        for target in TARGETS:
            w_summary = next(w for w in wheels_sorted if w["target"] == target)
            qual_src = {
                "status": "executing-qualification-source",
                "commit": QUALIFICATION_COMMIT,
                "tree": QUALIFICATION_TREE,
                "run_id": RUN_ID,
                "run_attempt": "1",
                "profile_sha256": cls.profile_sha,
            }
            t_receipt = {
                "schema": NEBULAR070_HOSTED_SCHEMA,
                "status": "native-consumer-passed",
                "fixture_only": False,
                "native_qualified": True,
                "candidate_receipt_sha256": cls.candidate_receipt_sha,
                "expected_artifact_record_sha256": cls.expected_artifacts["record_sha256"],
                "candidate_rs9_source": cls.candidate_receipt["candidate_rs9_source"],
                "qualification_rs9_source": qual_src,
                "target": target,
                "run_id": RUN_ID,
                "run_attempt": "1",
                "consumer": {
                    "fixture_only": False,
                    "native_qualified": True,
                    "wheel": w_summary,
                    "process_observer": {"orphan_count": 0},
                    "user_state": {"unchanged": True},
                    "sandbox": {"network_disabled": True},
                    "provider_closure": {"status": "verified"},
                },
                "publication_admitted": False,
                "public_writes": 0,
            }
            t_dir = cls.receipts_dir / target
            t_dir.mkdir(parents=True, exist_ok=True)
            t_bytes = canonical(t_receipt)
            (t_dir / "result.json").write_bytes(t_bytes)
            cls.target_receipt_bytes[target] = t_bytes

        hosted_commit = subprocess.check_output(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD^{commit}"], text=True
        ).strip()
        hosted_tree = subprocess.check_output(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD^{tree}"], text=True
        ).strip()
        cls.matrix_receipt = admit_nebular070_matrix(
            cls.candidate_receipt,
            cls.expected_artifacts,
            cls.receipts_dir,
            expected_commit=hosted_commit,
            expected_tree=hosted_tree,
            profile_sha256=cls.profile_sha,
            candidate_receipt_sha256=cls.candidate_receipt_sha,
            run_id=RUN_ID,
            run_attempt="1",
        )
        cls.matrix_receipt_bytes = canonical(cls.matrix_receipt)
        cls.matrix_receipt_sha = sha256(cls.matrix_receipt_bytes)

        cls.base_pin, cls.base_approval = cls._build_pin_and_approval()
        cls.base_capture, cls.archives_dir, cls.api_dir = cls._build_capture_and_archives()

    @classmethod
    def tearDownClass(cls) -> None:
        cls._class_tmp.cleanup()

    @classmethod
    def _build_pin_and_approval(cls) -> tuple[dict, dict]:
        files = []
        for row in cls.candidate_receipt["rows"]:
            sys_name = row["system"]
            target = next(t for t, s in SYSTEM_BY_TARGET.items() if s == sys_name)
            files.append(
                {
                    "target": target,
                    "system": sys_name,
                    "filename": row["wheel"]["filename"],
                    "size": row["wheel"]["size"],
                    "sha256": row["wheel"]["sha256"],
                    "tag": row["wheel"]["tag"],
                    "version": VERSION,
                    "payload_archive_name": row["payload_archive_name"],
                    "payload_archive_sha256": row["payload_archive_sha256"],
                    "manifest_sha256": row["manifest_sha256"],
                }
            )
        files.sort(key=lambda r: r["target"])

        src_id = cls.candidate_receipt["source_identity"]
        qual_block = {
            "candidate_source_commit": CANDIDATE_COMMIT,
            "candidate_source_tree": CANDIDATE_TREE,
            "qualification_source_commit": QUALIFICATION_COMMIT,
            "qualification_source_tree": QUALIFICATION_TREE,
            "qualification_run_id": RUN_ID,
            "qualification_run_attempt": "1",
            "candidate_receipt_sha256": cls.candidate_receipt_sha,
            "expected_artifact_record_sha256": cls.expected_artifacts["record_sha256"],
            "profile_sha256": cls.profile_sha,
            "matrix_receipt_sha256": cls.matrix_receipt_sha,
            "release_tag_commit": src_id["commit"],
            "target_qualification_sources": {
                target: {
                    "commit": QUALIFICATION_COMMIT,
                    "tree": QUALIFICATION_TREE,
                    "status": "verified-hosted-checkout",
                    "verified": True,
                }
                for target in TARGETS
            },
        }
        pin = {
            "schema": PIN_SCHEMA,
            "project": PROJECT,
            "version": VERSION,
            "distribution_version": VERSION,
            "workflow": WORKFLOW,
            "environment": ENVIRONMENT,
            "license": EXPECTED_LICENSE_EXPRESSION,
            "description": str(DESCRIPTION_PATH),
            "candidate_platforms": list(TARGETS),
            "qualified_platforms": list(TARGETS),
            "source_status": "READY",
            "withheld": [],
            "artifacts_manifest": APPROVAL_BASENAME,
            "qualification_manifest": CAPTURE_BASENAME,
            "qualification": copy.deepcopy(qual_block),
            "publication_admitted": True,
        }
        approval = {
            "schema": APPROVAL_SCHEMA,
            "project": PROJECT,
            "distribution": DISTRIBUTION_NAME,
            "version": VERSION,
            "distribution_version": VERSION,
            "workflow": WORKFLOW,
            "environment": ENVIRONMENT,
            "requires_python": EXPECTED_REQUIRES_PYTHON,
            "command": EXPECTED_COMMAND,
            "license_expression": EXPECTED_LICENSE_EXPRESSION,
            "license_files": copy.deepcopy(cls.candidate_receipt["legal_files"]),
            "readme": dict(cls.candidate_receipt["readme"]),
            "candidate_receipt_sha256": cls.candidate_receipt_sha,
            "expected_artifact_record_sha256": cls.expected_artifacts["record_sha256"],
            "profile_sha256": cls.profile_sha,
            "matrix_receipt_sha256": cls.matrix_receipt_sha,
            "qualification": copy.deepcopy(qual_block),
            "files": files,
            "builder_can_publish": False,
            "publication_admitted": True,
            "set_sha256": "",
        }
        approval["set_sha256"] = compute_set_sha256(approval)
        approval["admission_sha256"] = compute_admission_sha256(approval)
        pin["admission_sha256"] = approval["admission_sha256"]
        return pin, approval

    @classmethod
    def _build_capture_and_archives(cls) -> tuple[dict, Path, Path]:
        archives_dir = cls.fixture_root / "archives"
        api_dir = cls.fixture_root / "api"
        archives_dir.mkdir(parents=True, exist_ok=True)
        api_dir.mkdir(parents=True, exist_ok=True)

        bundle_members = {
            "candidate_receipt.json": cls.candidate_receipt_bytes,
            "expected_artifacts.json": cls.expected_artifacts_bytes,
            **{
                f"dist/{name}": data
                for name, data in sorted(cls.wheel_bytes_by_name.items())
            },
        }
        artifact_payloads: dict[str, dict[str, bytes]] = {
            CANDIDATE_BUNDLE_ARTIFACT: bundle_members,
            MATRIX_RECEIPT_ARTIFACT: {"matrix_receipt.json": cls.matrix_receipt_bytes},
        }
        for target, art_name in TARGET_QUALIFICATION_ARTIFACTS.items():
            artifact_payloads[art_name] = {
                f"{target}/result.json": cls.target_receipt_bytes[target]
            }

        capture_artifacts = {}
        api_artifact_rows = []
        for idx, (art_name, members_map) in enumerate(sorted(artifact_payloads.items()), start=1001):
            zip_bytes = _make_zip_bytes(members_map)
            (archives_dir / f"{art_name}.zip").write_bytes(zip_bytes)
            url = f"https://api.github.com/repos/{DEFAULT_GITHUB_REPOSITORY}/actions/artifacts/{idx}/zip"
            capture_artifacts[art_name] = {
                "id": idx,
                "size_in_bytes": len(zip_bytes),
                "archive_download_url": url,
                "archive_sha256": sha256(zip_bytes),
                "files": {
                    m_name: {"size": len(m_data), "sha256": sha256(m_data)}
                    for m_name, m_data in sorted(members_map.items())
                },
            }
            api_artifact_rows.append(
                {
                    "id": idx,
                    "name": art_name,
                    "size_in_bytes": len(zip_bytes),
                    "archive_download_url": url,
                    "expired": False,
                    "digest": f"sha256:{sha256(zip_bytes)}",
                    "workflow_run": {
                        "id": int(RUN_ID),
                        "head_sha": QUALIFICATION_COMMIT,
                        "head_branch": "main",
                    },
                }
            )

        capture = {
            "schema": CAPTURE_SCHEMA,
            "project": PROJECT,
            "version": VERSION,
            "distribution_version": VERSION,
            "workflow": WORKFLOW,
            "repository": DEFAULT_GITHUB_REPOSITORY,
            "run_id": int(RUN_ID),
            "run_attempt": 1,
            "head_branch": "main",
            "event": "workflow_dispatch",
            "status": "completed",
            "conclusion": "success",
            "candidate_source_commit": CANDIDATE_COMMIT,
            "candidate_source_tree": CANDIDATE_TREE,
            "qualification_source_commit": QUALIFICATION_COMMIT,
            "qualification_source_tree": QUALIFICATION_TREE,
            "candidate_receipt_sha256": cls.candidate_receipt_sha,
            "expected_artifact_record_sha256": cls.expected_artifacts["record_sha256"],
            "profile_sha256": cls.profile_sha,
            "matrix_receipt_sha256": cls.matrix_receipt_sha,
            "artifacts": capture_artifacts,
        }
        run_doc = {
            "id": int(RUN_ID),
            "run_attempt": 1,
            "head_sha": QUALIFICATION_COMMIT,
            "head_branch": "main",
            "event": "workflow_dispatch",
            "status": "completed",
            "conclusion": "success",
            "path": f".github/workflows/{WORKFLOW}",
            "repository": {"full_name": DEFAULT_GITHUB_REPOSITORY},
        }
        (api_dir / "run.json").write_bytes(canonical(run_doc))
        (api_dir / "artifacts.json").write_bytes(canonical({"artifacts": api_artifact_rows}))
        return capture, archives_dir, api_dir

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="rs9-neb070-pub-test-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()

    def test_committed_repository_fails_closed_without_fabricated_pins_or_captures(self) -> None:
        desc_file = ROOT / DESCRIPTION_PATH
        self.assertTrue(desc_file.is_file())
        desc_bytes = desc_file.read_bytes()
        self.assertEqual(len(desc_bytes), 6796)
        self.assertEqual(
            sha256(desc_bytes),
            "6bd13e05b0ad87ef1c1c9635a320f2e1b9341577e81c42d78e61b6cb94a72dc3",
        )

        for absent_name in (PIN_BASENAME, APPROVAL_BASENAME, CAPTURE_BASENAME):
            self.assertFalse((ROOT / "operators/tf-pypi" / absent_name).exists())

        with self.assertRaises(AdmissionError) as ctx_pin:
            load_pin(ROOT)
        self.assertEqual(ctx_pin.exception.code, "TF_PYPI_PIN_ABSENT")

        with self.assertRaises(AdmissionError) as ctx_app:
            load_approval(ROOT)
        self.assertEqual(ctx_app.exception.code, "TF_PYPI_APPROVAL_ABSENT")

        with self.assertRaises(AdmissionError) as ctx_cap:
            load_qualification_capture(ROOT)
        self.assertEqual(ctx_cap.exception.code, "TF_PYPI_QUALIFICATION_CAPTURE_ABSENT")

        head_commit = subprocess.check_output(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD^{commit}"], text=True
        ).strip()
        with self.assertRaises(AdmissionError) as ctx_build:
            build_candidates_bundle(
                self.root / "bundle",
                expected_commit=head_commit,
                repository=ROOT,
                require_clean=False,
            )
        self.assertEqual(ctx_build.exception.code, "TF_PYPI_RELEASE_INPUTS_PENDING")

    def test_pin_schema_validation_positive_and_negatives(self) -> None:
        validated = validate_pin(copy.deepcopy(self.base_pin))
        self.assertEqual(validated["version"], "0.7.0")
        self.assertEqual(validated["qualified_platforms"], list(TARGETS))

        blocked_pin = copy.deepcopy(self.base_pin)
        blocked_pin["source_status"] = "BLOCKED"
        blocked_pin["publication_admitted"] = False
        blocked_pin.pop("admission_sha256", None)
        blocked_pin["qualified_platforms"] = []
        blocked_pin["withheld"] = ["awaiting v0.7.0 release tag and hosted Gate 2 matrix receipts"]
        blocked_pin["qualification"] = {}
        self.assertEqual(validate_pin(blocked_pin)["source_status"], "BLOCKED")

        # BLOCKED pin cannot have publication_admitted=True
        bad_blocked = copy.deepcopy(blocked_pin)
        bad_blocked["publication_admitted"] = True
        with self.assertRaises(AdmissionError) as ctx_blk:
            validate_pin(bad_blocked)
        self.assertEqual(ctx_blk.exception.code, "TF_PYPI_PIN_BLOCKED_INCONSISTENT")

        # 0.6.1 data refused
        pin_061 = copy.deepcopy(self.base_pin)
        pin_061["version"] = "0.6.1"
        with self.assertRaises(AdmissionError) as ctx_ver:
            validate_pin(pin_061)
        self.assertEqual(ctx_ver.exception.code, "TF_PYPI_PIN_SCHEMA")

        # Legacy commercial OR license expression refused
        pin_lic = copy.deepcopy(self.base_pin)
        pin_lic["license"] = "AGPL-3.0-or-later OR LicenseRef-Commercial"
        with self.assertRaises(AdmissionError) as ctx_lic:
            validate_pin(pin_lic)
        self.assertEqual(ctx_lic.exception.code, "TF_PYPI_PIN_LICENSE")

        # Missing platform in READY pin refused
        pin_2plat = copy.deepcopy(self.base_pin)
        pin_2plat["qualified_platforms"] = list(TARGETS[:2])
        with self.assertRaises(AdmissionError) as ctx_plat:
            validate_pin(pin_2plat)
        self.assertEqual(ctx_plat.exception.code, "TF_PYPI_PIN_READY_INCOMPLETE")

        # Conflated source identity refused
        pin_conf = copy.deepcopy(self.base_pin)
        pin_conf["qualification"]["release_tag_commit"] = CANDIDATE_COMMIT
        with self.assertRaises(AdmissionError) as ctx_conf:
            validate_pin(pin_conf)
        self.assertEqual(ctx_conf.exception.code, "TF_PYPI_SOURCE_IDENTITY_CONFLATED")

    def test_approval_manifest_validation_and_set_sha256_invariance(self) -> None:
        for admitted_state in (False, True):
            app_copy = copy.deepcopy(self.base_approval)
            app_copy["publication_admitted"] = admitted_state
            if admitted_state:
                app_copy["admission_sha256"] = compute_admission_sha256(app_copy)
            else:
                app_copy.pop("admission_sha256", None)
            self.assertEqual(compute_set_sha256(app_copy), self.base_approval["set_sha256"])
            validate_approval(app_copy)

        # 1, 2, or 4 wheel files refused
        for count in (1, 2, 4):
            bad_files = copy.deepcopy(self.base_approval)
            if count < 3:
                bad_files["files"] = bad_files["files"][:count]
            else:
                bad_files["files"].append(copy.deepcopy(bad_files["files"][0]))
            with self.assertRaises(AdmissionError) as ctx_cnt:
                validate_approval(bad_files)
            self.assertEqual(ctx_cnt.exception.code, "TF_PYPI_APPROVAL_FILES")

        # Sdist in files refused
        bad_sdist = copy.deepcopy(self.base_approval)
        bad_sdist["files"][0]["filename"] = "theme_forge_nebular_fusion-0.7.0.tar.gz"
        with self.assertRaises(AdmissionError) as ctx_sd:
            validate_approval(bad_sdist)
        self.assertEqual(ctx_sd.exception.code, "TF_PYPI_SDIST_FORBIDDEN")

        # builder_can_publish=True refused
        bad_bcp = copy.deepcopy(self.base_approval)
        bad_bcp["builder_can_publish"] = True
        with self.assertRaises(AdmissionError) as ctx_bcp:
            validate_approval(bad_bcp)
        self.assertEqual(ctx_bcp.exception.code, "TF_PYPI_APPROVAL_SCHEMA")

        # Legacy license expression refused
        bad_lic = copy.deepcopy(self.base_approval)
        bad_lic["license_expression"] = "AGPL-3.0-or-later OR LicenseRef-Commercial"
        with self.assertRaises(AdmissionError) as ctx_lic:
            validate_approval(bad_lic)
        self.assertEqual(ctx_lic.exception.code, "TF_PYPI_APPROVAL_LICENSE")

        # Conflated source identity refused
        bad_conf = copy.deepcopy(self.base_approval)
        bad_conf["qualification"]["release_tag_commit"] = QUALIFICATION_COMMIT
        with self.assertRaises(AdmissionError) as ctx_conf:
            validate_approval(bad_conf)
        self.assertEqual(ctx_conf.exception.code, "TF_PYPI_SOURCE_IDENTITY_CONFLATED")

        # Tampered set_sha256 refused
        bad_set = copy.deepcopy(self.base_approval)
        bad_set["set_sha256"] = "0" * 64
        with self.assertRaises(AdmissionError) as ctx_set:
            validate_approval(bad_set)
        self.assertEqual(ctx_set.exception.code, "TF_PYPI_APPROVAL_DIGEST")

    def test_inspect_candidate_wheel_and_verify_approved_three_wheels(self) -> None:
        verified = verify_approved(
            self.dist_dir,
            approval=self.base_approval,
            pin=self.base_pin,
            require_admitted=True,
        )
        self.assertEqual(verified["set_sha256"], self.base_approval["set_sha256"])

        # publication_admitted=False refused when require_admitted=True
        unadmitted = copy.deepcopy(self.base_approval)
        unadmitted["publication_admitted"] = False
        unadmitted.pop("admission_sha256", None)
        verify_approved(self.dist_dir, approval=unadmitted, require_admitted=False)
        with self.assertRaises(AdmissionError) as ctx_unadm:
            verify_approved(self.dist_dir, approval=unadmitted, require_admitted=True)
        self.assertEqual(ctx_unadm.exception.code, "TF_PYPI_PUBLICATION_NOT_ADMITTED")

        # Sdist or missing wheel in dist/ refused
        temp_dist = self.root / "dist_check"
        shutil.copytree(self.dist_dir, temp_dist)
        sdist_file = temp_dist / "theme_forge_nebular_fusion-0.7.0.tar.gz"
        sdist_file.write_bytes(b"sdist")
        with self.assertRaises(AdmissionError) as ctx_sd:
            verify_approved(temp_dist, approval=self.base_approval, pin=self.base_pin)
        self.assertEqual(ctx_sd.exception.code, "TF_PYPI_SDIST_FORBIDDEN")
        sdist_file.unlink()

        first_wheel = temp_dist / EXPECTED_WHEEL_FILENAMES["darwin-arm64"]
        first_wheel.unlink()
        with self.assertRaises(AdmissionError) as ctx_missing:
            verify_approved(temp_dist, approval=self.base_approval, pin=self.base_pin)
        self.assertEqual(ctx_missing.exception.code, "TF_PYPI_DIST_FILE_SET")

        # Helper drift, launcher drift, provenance tampering, metadata tampering, Darwin floor tampering
        darwin_rec = next(f for f in self.base_approval["files"] if f["target"] == "darwin-arm64")
        darwin_src = self.dist_dir / darwin_rec["filename"]

        def _make_mutated_wheel_and_rec(label: str, mutator) -> tuple[Path, dict]:
            d_sub = self.root / label
            d_sub.mkdir(parents=True, exist_ok=True)
            w_copy = d_sub / darwin_rec["filename"]
            shutil.copyfile(darwin_src, w_copy)
            with zipfile.ZipFile(w_copy, "r") as zf:
                entries = {name: zf.read(name) for name in zf.namelist()}
            mutator(entries)
            dist_info = f"{PACKAGE_NAME}-{VERSION}.dist-info"
            rec_name = f"{dist_info}/RECORD"
            lines = []
            for name in sorted(entries):
                if name == rec_name:
                    lines.append(f"{name},,\n")
                else:
                    lines.append(f"{name},{_record_digest(entries[name])},{len(entries[name])}\n")
            entries[rec_name] = "".join(lines).encode("utf-8")
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                for name in sorted(entries):
                    zi = zipfile.ZipInfo(name, date_time=(2026, 10, 1, 0, 0, 0))
                    zi.compress_type = zipfile.ZIP_DEFLATED
                    zi.create_system = 3
                    zi.external_attr = (stat.S_IFREG | 0o644) << 16
                    zf.writestr(zi, entries[name])
            raw_bytes = buf.getvalue()
            w_copy.write_bytes(raw_bytes)
            new_rec = copy.deepcopy(darwin_rec)
            new_rec["size"] = len(raw_bytes)
            new_rec["sha256"] = sha256(raw_bytes)
            return w_copy, new_rec

        # 1. Helper drift
        w_hlp, rec_hlp = _make_mutated_wheel_and_rec(
            "helper",
            lambda e: e.update(
                {f"{PACKAGE_NAME}/_isolated/rs9/scratch.py": e[f"{PACKAGE_NAME}/_isolated/rs9/scratch.py"] + b"\n# drift\n"}
            ),
        )
        with self.assertRaises(AdmissionError) as ctx_hlp:
            inspect_candidate_wheel(w_hlp, file_record=rec_hlp, approval=self.base_approval)
        self.assertEqual(ctx_hlp.exception.code, "TF_PYPI_WHEEL_HELPER_DRIFT")

        # 2. Launcher drift
        w_lch, rec_lch = _make_mutated_wheel_and_rec(
            "launcher",
            lambda e: e.update({f"{PACKAGE_NAME}/launcher.py": e[f"{PACKAGE_NAME}/launcher.py"] + b"\n# drift\n"}),
        )
        with self.assertRaises(AdmissionError) as ctx_lch:
            inspect_candidate_wheel(w_lch, file_record=rec_lch, approval=self.base_approval)
        self.assertEqual(ctx_lch.exception.code, "TF_PYPI_WHEEL_LAUNCHER")

        # 3. Provenance can_publish=True
        def _mutate_prov(entries: dict[str, bytes]) -> None:
            p_doc = json.loads(entries[f"{PACKAGE_NAME}/_rs9/provenance.json"])
            p_doc["can_publish"] = True
            entries[f"{PACKAGE_NAME}/_rs9/provenance.json"] = canonical(p_doc)

        w_prv, rec_prv = _make_mutated_wheel_and_rec("prov", _mutate_prov)
        with self.assertRaises(AdmissionError) as ctx_prv:
            inspect_candidate_wheel(w_prv, file_record=rec_prv, approval=self.base_approval)
        self.assertEqual(ctx_prv.exception.code, "TF_PYPI_WHEEL_PROVENANCE")

        # 4. METADATA header tamper (keeps readme body intact so WHEEL_METADATA triggers)
        w_meta, rec_meta = _make_mutated_wheel_and_rec(
            "meta",
            lambda e: e.update(
                {
                    f"{PACKAGE_NAME}-{VERSION}.dist-info/METADATA": e[
                        f"{PACKAGE_NAME}-{VERSION}.dist-info/METADATA"
                    ].replace(b"Requires-Python: >=3.10", b"Requires-Python: >=3.9")
                }
            ),
        )
        with self.assertRaises(AdmissionError) as ctx_meta:
            inspect_candidate_wheel(w_meta, file_record=rec_meta, approval=self.base_approval)
        self.assertEqual(ctx_meta.exception.code, "TF_PYPI_WHEEL_METADATA")

        # 5. Darwin Mach-O min_os floor 14.0 tamper
        def _mutate_darwin_floor(entries: dict[str, bytes]) -> None:
            p_key = next(k for k in entries if k.startswith(f"{PACKAGE_NAME}/payload/") and k.endswith(".tar.gz"))
            out_tar = io.BytesIO()
            with tarfile.open(fileobj=io.BytesIO(entries[p_key]), mode="r:gz") as src_t, tarfile.open(
                fileobj=out_tar, mode="w:gz"
            ) as dst_t:
                for member in src_t:
                    item = copy.copy(member)
                    data = src_t.extractfile(member).read() if member.isfile() else b""
                    if member.name.endswith("/Contents/MacOS/theme-forge-nebular-fusion"):
                        data = _macho_14()
                        item.size = len(data)
                    dst_t.addfile(item, io.BytesIO(data) if member.isfile() else None)
            new_payload = out_tar.getvalue()
            new_payload_sha = sha256(new_payload)
            entries[p_key] = new_payload
            p_doc = json.loads(entries[f"{PACKAGE_NAME}/_rs9/provenance.json"])
            old_payload_sha = p_doc["payload_archive_sha256"]
            p_doc["payload_archive_sha256"] = new_payload_sha
            new_launcher = entries[f"{PACKAGE_NAME}/launcher.py"].replace(
                old_payload_sha.encode("ascii"), new_payload_sha.encode("ascii")
            )
            entries[f"{PACKAGE_NAME}/launcher.py"] = new_launcher
            p_doc["launcher_sha256"] = sha256(new_launcher)
            entries[f"{PACKAGE_NAME}/_rs9/provenance.json"] = canonical(p_doc)

        w_flr, rec_flr = _make_mutated_wheel_and_rec("floor", _mutate_darwin_floor)
        rec_flr["payload_archive_sha256"] = sha256(
            zipfile.ZipFile(w_flr).read(
                next(k for k in zipfile.ZipFile(w_flr).namelist() if k.startswith(f"{PACKAGE_NAME}/payload/") and k.endswith(".tar.gz"))
            )
        )
        with self.assertRaises(AdmissionError) as ctx_flr:
            inspect_candidate_wheel(w_flr, file_record=rec_flr, approval=self.base_approval)
        self.assertEqual(ctx_flr.exception.code, "TF_PYPI_WHEEL_DARWIN_FLOOR")

    def test_verify_matrix_receipts_positive_and_negatives(self) -> None:
        matrix = verify_matrix_receipts(
            self.candidate_receipt_path,
            self.expected_artifacts_path,
            self.receipts_dir,
            dist=self.dist_dir,
            approval=self.base_approval,
            pin=self.base_pin,
        )
        self.assertEqual(sha256(canonical(matrix)), self.matrix_receipt_sha)

        # Missing one target receipt fails closed
        partial_receipts = self.root / "partial_receipts"
        shutil.copytree(self.receipts_dir, partial_receipts)
        shutil.rmtree(partial_receipts / "linux-arm64-gnu")
        with self.assertRaises(AdmissionError) as ctx_part:
            verify_matrix_receipts(
                self.candidate_receipt_path,
                self.expected_artifacts_path,
                partial_receipts,
                approval=self.base_approval,
                pin=self.base_pin,
            )
        self.assertEqual(ctx_part.exception.code, "TF_PYPI_NEBULAR_MATRIX_RECEIPTS")

        # fixture_only=True receipt fails closed
        fixture_receipts = self.root / "fixture_receipts"
        shutil.copytree(self.receipts_dir, fixture_receipts)
        r_file = fixture_receipts / "darwin-arm64" / "result.json"
        r_doc = json.loads(r_file.read_bytes())
        r_doc["fixture_only"] = True
        r_file.write_bytes(canonical(r_doc))
        with self.assertRaises(AdmissionError) as ctx_fix:
            verify_matrix_receipts(
                self.candidate_receipt_path,
                self.expected_artifacts_path,
                fixture_receipts,
                approval=self.base_approval,
                pin=self.base_pin,
            )
        self.assertEqual(ctx_fix.exception.code, "TF_PYPI_NEBULAR_MATRIX_RECEIPT")

        # Mismatched qualification_source_commit in target receipt fails closed
        mismatch_receipts = self.root / "mismatch_receipts"
        shutil.copytree(self.receipts_dir, mismatch_receipts)
        m_file = mismatch_receipts / "linux-x64-gnu" / "result.json"
        m_doc = json.loads(m_file.read_bytes())
        m_doc["qualification_rs9_source"]["commit"] = "9" * 40
        m_file.write_bytes(canonical(m_doc))
        bad_app = copy.deepcopy(self.base_approval)
        hosted_commit = subprocess.check_output(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD^{commit}"], text=True
        ).strip()
        hosted_tree = subprocess.check_output(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD^{tree}"], text=True
        ).strip()
        m_matrix = admit_nebular070_matrix(
            self.candidate_receipt,
            self.expected_artifacts,
            mismatch_receipts,
            expected_commit=hosted_commit,
            expected_tree=hosted_tree,
            profile_sha256=self.profile_sha,
            candidate_receipt_sha256=self.candidate_receipt_sha,
            run_id=RUN_ID,
            run_attempt="1",
        )
        bad_app["matrix_receipt_sha256"] = sha256(canonical(m_matrix))
        bad_app["qualification"]["matrix_receipt_sha256"] = bad_app["matrix_receipt_sha256"]
        bad_app["set_sha256"] = compute_set_sha256(bad_app)
        bad_app["admission_sha256"] = compute_admission_sha256(bad_app)
        with self.assertRaises(AdmissionError) as ctx_qsrc:
            verify_matrix_receipts(
                self.candidate_receipt_path,
                self.expected_artifacts_path,
                mismatch_receipts,
                approval=bad_app,
            )
        self.assertEqual(ctx_qsrc.exception.code, "TF_PYPI_QUALIFICATION_SOURCE_MISMATCH")

    def test_multi_wheel_remote_state_exact_state_and_reader_limits(self) -> None:
        self.assertEqual(MAX_WHEEL_FILE_BYTES, 512 * 1024 * 1024)

        # Nebular070PublicReader rejects unapproved hosts
        reader = Nebular070PublicReader(max_file_bytes=1024)
        with self.assertRaises(AdmissionError) as ctx_url:
            reader("https://evil.example.com/wheel.whl")
        self.assertEqual(ctx_url.exception.code, "TF_PYPI_REMOTE_UNKNOWN")

        files_by_name = {f["filename"]: f for f in self.base_approval["files"]}
        urls_by_name = {
            name: f"https://files.pythonhosted.org/packages/00/{name}"
            for name in files_by_name
        }

        def _make_pypi_json(present_names: list[str], *, extra_file: dict | None = None, yanked: bool = False) -> bytes:
            rel_rows = []
            for name in present_names:
                f_rec = files_by_name[name]
                rel_rows.append(
                    {
                        "filename": name,
                        "url": urls_by_name[name],
                        "packagetype": "bdist_wheel",
                        "size": f_rec["size"],
                        "digests": {"sha256": f_rec["sha256"]},
                        "yanked": yanked,
                    }
                )
            if extra_file is not None:
                rel_rows.append(extra_file)
            return canonical(
                {
                    "info": {"name": PROJECT, "version": VERSION, "yanked": False},
                    "releases": {"0.6.1": [], VERSION: rel_rows},
                    "urls": rel_rows,
                }
            )

        # 1. absent (404)
        def _get_404(_url: str) -> bytes:
            raise AdmissionError("TF_PYPI_REMOTE_ABSENT")

        self.assertEqual(project_state(get=_get_404), "absent")
        st_absent = exact_state(self.base_approval, self.wheel_bytes_by_name, get=_get_404)
        self.assertEqual(st_absent["state"], "absent")
        self.assertEqual(len(st_absent["missing"]), 3)

        # 2. version-absent (0.6.1 present, 0.7.0 absent)
        def _get_ver_absent(url: str) -> bytes:
            if url.endswith("/json"):
                return canonical({"info": {"name": PROJECT}, "releases": {"0.6.1": []}})
            raise AssertionError(f"unexpected wheel download: {url}")

        st_vabs = exact_state(self.base_approval, self.wheel_bytes_by_name, get=_get_ver_absent)
        self.assertEqual(st_vabs["state"], "version-absent")
        self.assertEqual(len(st_vabs["missing"]), 3)

        # 3. incomplete (2 wheels present and byte-verified, 1 wheel missing)
        all_names = [f["filename"] for f in self.base_approval["files"]]
        two_names = all_names[:2]
        missing_one = all_names[2]

        def _get_incomplete(url: str) -> bytes:
            if url.endswith("/json"):
                return _make_pypi_json(two_names)
            for name in two_names:
                if url == urls_by_name[name]:
                    return self.wheel_bytes_by_name[name]
            raise AssertionError(f"unexpected URL: {url}")

        st_inc = exact_state(self.base_approval, self.wheel_bytes_by_name, get=_get_incomplete)
        self.assertEqual(st_inc["state"], "incomplete")
        self.assertEqual(st_inc["matched"], two_names)
        self.assertEqual(st_inc["missing"], [missing_one])

        # 4. published-exact (all 3 wheels present and byte-verified)
        def _get_exact(url: str) -> bytes:
            if url.endswith("/json"):
                return _make_pypi_json(all_names)
            for name in all_names:
                if url == urls_by_name[name]:
                    return self.wheel_bytes_by_name[name]
            raise AssertionError(f"unexpected URL: {url}")

        st_exact = exact_state(self.base_approval, self.wheel_bytes_by_name, get=_get_exact)
        self.assertEqual(st_exact["state"], "published-exact")
        self.assertEqual(st_exact["matched"], all_names)
        self.assertEqual(st_exact["missing"], [])

        # 5. conflict on sdist, yanked wheel, or tampered wheel body
        sdist_json = _make_pypi_json(
            all_names,
            extra_file={
                "filename": "theme_forge_nebular_fusion-0.7.0.tar.gz",
                "url": "https://files.pythonhosted.org/packages/00/theme_forge_nebular_fusion-0.7.0.tar.gz",
                "packagetype": "sdist",
                "size": 100,
                "digests": {"sha256": "a" * 64},
                "yanked": False,
            },
        )
        self.assertEqual(
            remote_state(self.base_approval, get=lambda _u: sdist_json)["state"],
            "conflict",
        )
        self.assertEqual(
            remote_state(self.base_approval, get=lambda _u: _make_pypi_json(all_names, yanked=True))["state"],
            "conflict",
        )

        def _get_body_conflict(url: str) -> bytes:
            if url.endswith("/json"):
                return _make_pypi_json(all_names)
            return b"corrupted-wheel-body"

        self.assertEqual(
            exact_state(self.base_approval, self.wheel_bytes_by_name, get=_get_body_conflict)["state"],
            "conflict",
        )

    def test_select_missing_verify_upload_dir_prior_runs_and_readback(self) -> None:
        files_by_name = {f["filename"]: f for f in self.base_approval["files"]}
        all_names = sorted(files_by_name.keys())
        urls_by_name = {
            name: f"https://files.pythonhosted.org/packages/00/{name}"
            for name in all_names
        }

        def _make_pypi_json(present_names: list[str]) -> bytes:
            rows = [
                {
                    "filename": name,
                    "url": urls_by_name[name],
                    "packagetype": "bdist_wheel",
                    "size": files_by_name[name]["size"],
                    "digests": {"sha256": files_by_name[name]["sha256"]},
                    "yanked": False,
                }
                for name in present_names
            ]
            return canonical(
                {
                    "info": {"name": PROJECT, "version": VERSION, "yanked": False},
                    "releases": {VERSION: rows},
                    "urls": rows,
                }
            )

        # 1. Refuses before network call when publication_admitted=False
        unadmitted = copy.deepcopy(self.base_approval)
        unadmitted["publication_admitted"] = False
        unadmitted.pop("admission_sha256", None)
        unadm_pin = copy.deepcopy(self.base_pin)
        unadm_pin["publication_admitted"] = False
        unadm_pin.pop("admission_sha256", None)
        network_called = False

        def _forbid_net(_url: str) -> bytes:
            nonlocal network_called
            network_called = True
            raise AssertionError("network must not be called")

        with self.assertRaises(AdmissionError) as ctx_unadm:
            select_missing(
                self.dist_dir,
                self.root / "upload_unadm",
                candidate_receipt=self.candidate_receipt_path,
                expected_artifacts=self.expected_artifacts_path,
                receipts_dir=self.receipts_dir,
                approval=unadmitted,
                pin=unadm_pin,
                get=_forbid_net,
            )
        self.assertEqual(ctx_unadm.exception.code, "TF_PYPI_PUBLICATION_NOT_ADMITTED")
        self.assertFalse(network_called)

        # 2. Refuses on prior publish or publication_resume_070 run in GitHub Actions
        def _fake_api_get(url: str) -> dict:
            if "actions/workflows/" in url:
                return {
                    "total_count": 1,
                    "workflow_runs": [
                        {
                            "id": 999,
                            "workflow_id": 7001,
                            "path": f".github/workflows/{WORKFLOW}",
                            "event": "workflow_dispatch",
                            "head_branch": "main",
                            "head_sha": QUALIFICATION_COMMIT,
                            "run_attempt": 1,
                            "status": "completed",
                            "conclusion": "failure",
                            "display_title": f"RS9 {PROJECT} 0.7.0 resume / attempt-999",
                            "repository": {"full_name": DEFAULT_GITHUB_REPOSITORY},
                        },
                    ],
                }
            if "/runs/999/jobs" in url:
                raw_jobs_999 = [
                    {
                        "name": name,
                        "status": "completed",
                        "conclusion": "skipped",
                        "steps": [],
                    }
                    for name in sorted(
                        ALL_KNOWN_WORKFLOW_JOB_NAMES
                        - {"Attended Nebular 0.7.0 PyPI publication resume"}
                    )
                ] + [
                    {
                        "name": "Attended Nebular 0.7.0 PyPI publication resume",
                        "status": "completed",
                        "conclusion": "failure",
                        "steps": [
                            {
                                "name": "Publish package distribution to PyPI",
                                "status": "completed",
                                "conclusion": "failure",
                            }
                        ],
                    }
                ]
                jobs_999 = [
                    {
                        "id": 999000 + idx,
                        "run_id": 999,
                        "run_attempt": 1,
                        "head_sha": QUALIFICATION_COMMIT,
                        **j,
                    }
                    for idx, j in enumerate(raw_jobs_999, start=1)
                ]
                return {
                    "total_count": len(jobs_999),
                    "jobs": jobs_999,
                }
            raise AssertionError(url)

        with self.assertRaises(AdmissionError) as ctx_prior:
            check_prior_publish_runs(
                api_get=_fake_api_get,
                environ={"GITHUB_RUN_ID": "1000"},
            )
        self.assertEqual(ctx_prior.exception.code, "TF_PYPI_PRIOR_ATTEMPT_UNCONFIRMED")

        # 3. select_missing on version-absent stages all 3 wheels
        upload_all = self.root / "upload_all"
        marker_all = self.root / "marker_all.json"
        res_all = select_missing(
            self.dist_dir,
            upload_all,
            candidate_receipt=self.candidate_receipt_path,
            expected_artifacts=self.expected_artifacts_path,
            receipts_dir=self.receipts_dir,
            approval=self.base_approval,
            pin=self.base_pin,
            get=lambda _u: canonical({"info": {"name": PROJECT}, "releases": {"0.6.1": []}}),
            attempt_marker=marker_all,
        )
        self.assertTrue(res_all["upload"])
        self.assertEqual(res_all["state"], "version-absent")
        self.assertEqual(sorted(p.name for p in upload_all.iterdir()), all_names)
        verify_upload_dir(self.dist_dir, upload_all, approval=self.base_approval, pin=self.base_pin)

        # Second call with same attempt_marker fails closed
        with self.assertRaises(AdmissionError) as ctx_mkr:
            select_missing(
                self.dist_dir,
                self.root / "upload_dup",
                candidate_receipt=self.candidate_receipt_path,
                expected_artifacts=self.expected_artifacts_path,
                receipts_dir=self.receipts_dir,
                approval=self.base_approval,
                pin=self.base_pin,
                get=lambda _u: canonical({"info": {"name": PROJECT}, "releases": {"0.6.1": []}}),
                attempt_marker=marker_all,
            )
        self.assertEqual(ctx_mkr.exception.code, "TF_PYPI_PRIOR_ATTEMPT_UNCONFIRMED")

        # 4. select_missing on incomplete stages ONLY the 1 missing wheel
        two_names = all_names[:2]
        missing_one = all_names[2]

        def _get_inc(url: str) -> bytes:
            if url.endswith("/json"):
                return _make_pypi_json(two_names)
            for n in two_names:
                if url == urls_by_name[n]:
                    return self.wheel_bytes_by_name[n]
            raise AssertionError(url)

        upload_partial = self.root / "upload_partial"
        res_part = select_missing(
            self.dist_dir,
            upload_partial,
            candidate_receipt=self.candidate_receipt_path,
            expected_artifacts=self.expected_artifacts_path,
            receipts_dir=self.receipts_dir,
            approval=self.base_approval,
            pin=self.base_pin,
            get=_get_inc,
        )
        self.assertTrue(res_part["upload"])
        self.assertEqual(res_part["state"], "incomplete")
        self.assertEqual([p.name for p in upload_partial.iterdir()], [missing_one])
        verify_upload_dir(self.dist_dir, upload_partial, approval=self.base_approval, pin=self.base_pin)

        # 5. select_missing on published-exact stages 0 files and sets upload=False
        def _get_exact(url: str) -> bytes:
            if url.endswith("/json"):
                return _make_pypi_json(all_names)
            for n in all_names:
                if url == urls_by_name[n]:
                    return self.wheel_bytes_by_name[n]
            raise AssertionError(url)

        upload_none = self.root / "upload_none"
        res_none = select_missing(
            self.dist_dir,
            upload_none,
            candidate_receipt=self.candidate_receipt_path,
            expected_artifacts=self.expected_artifacts_path,
            receipts_dir=self.receipts_dir,
            approval=self.base_approval,
            pin=self.base_pin,
            get=_get_exact,
        )
        self.assertFalse(res_none["upload"])
        self.assertEqual(res_none["state"], "published-exact")
        self.assertFalse(upload_none.exists())

        # 6. readback positive, conflict immediate abort, and timeout unconfirmed disposition
        rb_ok = readback(
            self.dist_dir,
            approval=self.base_approval,
            pin=self.base_pin,
            get=_get_exact,
            schedule=(0, 1, 2),
            sleep_fn=lambda _s: None,
        )
        self.assertEqual(rb_ok["state"], "published-exact")
        self.assertEqual(len(rb_ok["attempts"]), 1)

        sleeps: list[float] = []
        with self.assertRaises(AdmissionError) as ctx_rb_conf:
            readback(
                self.dist_dir,
                approval=self.base_approval,
                pin=self.base_pin,
                get=lambda _u: canonical(
                    {
                        "info": {"name": PROJECT, "version": VERSION, "yanked": False},
                        "releases": {VERSION: [{"filename": "bad.whl", "packagetype": "bdist_wheel"}]},
                        "urls": [{"filename": "bad.whl", "packagetype": "bdist_wheel"}],
                    }
                ),
                schedule=(0, 5, 10),
                sleep_fn=sleeps.append,
            )
        self.assertEqual(ctx_rb_conf.exception.code, "TF_PYPI_READBACK_CONFLICT")
        self.assertEqual(getattr(ctx_rb_conf.exception, "disposition", None), "conflict-abort-immediately")
        self.assertEqual(sleeps, [])

        with self.assertRaises(AdmissionError) as ctx_rb_inc:
            readback(
                self.dist_dir,
                approval=self.base_approval,
                pin=self.base_pin,
                get=_get_inc,
                schedule=(0, 1, 2),
                sleep_fn=sleeps.append,
            )
        self.assertEqual(ctx_rb_inc.exception.code, "TF_PYPI_READBACK_INCOMPLETE")
        self.assertEqual(
            getattr(ctx_rb_inc.exception, "disposition", None),
            "unconfirmed-no-redispatch-before-independent-readback",
        )
        self.assertEqual(sleeps, [1.0, 2.0])

    def test_two_checkout_publication_resume_helpers_end_to_end(self) -> None:
        qual_repo = self.root / "qualification-source"
        pub_repo = self.root / "publisher-authority"
        qual_repo.mkdir()
        subprocess.run(["git", "-C", str(qual_repo), "init", "-q"], check=True)
        subprocess.run(["git", "-C", str(qual_repo), "config", "user.email", "test@example.com"], check=True)
        subprocess.run(["git", "-C", str(qual_repo), "config", "user.name", "Test"], check=True)

        for rel in QUALIFICATION_SOURCE_HELPERS:
            src_file = ROOT / rel
            dst_file = qual_repo / rel
            dst_file.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src_file, dst_file)
        (qual_repo / "operators/tf-pypi").mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "-C", str(qual_repo), "add", "."], check=True)
        subprocess.run(["git", "-C", str(qual_repo), "commit", "-q", "-m", "Qualification commit"], check=True)

        actual_qual_commit = subprocess.check_output(
            ["git", "-C", str(qual_repo), "rev-parse", "HEAD^{commit}"], text=True
        ).strip()
        actual_qual_tree = subprocess.check_output(
            ["git", "-C", str(qual_repo), "rev-parse", "HEAD^{tree}"], text=True
        ).strip()

        shutil.copytree(qual_repo, pub_repo)

        receipts_2c = self.root / "receipts_2c"
        target_bytes_2c = {}
        for target in TARGETS:
            t_rec = json.loads(self.target_receipt_bytes[target])
            t_rec["qualification_rs9_source"]["commit"] = actual_qual_commit
            t_rec["qualification_rs9_source"]["tree"] = actual_qual_tree
            t_dir = receipts_2c / target
            t_dir.mkdir(parents=True, exist_ok=True)
            b_data = canonical(t_rec)
            (t_dir / "result.json").write_bytes(b_data)
            target_bytes_2c[target] = b_data

        matrix_2c = admit_nebular070_matrix(
            self.candidate_receipt,
            self.expected_artifacts,
            receipts_2c,
            expected_commit=QUALIFICATION_COMMIT,
            expected_tree=QUALIFICATION_TREE,
            profile_sha256=self.profile_sha,
            candidate_receipt_sha256=self.candidate_receipt_sha,
            run_id=RUN_ID,
            run_attempt="1",
        )
        matrix_2c_bytes = canonical(matrix_2c)
        matrix_2c_sha = sha256(matrix_2c_bytes)

        target_q_sources_2c = {
            t: {
                "commit": actual_qual_commit,
                "tree": actual_qual_tree,
                "status": "verified-hosted-checkout",
                "verified": True,
            }
            for t in TARGETS
        }
        pin_2c = copy.deepcopy(self.base_pin)
        pin_2c["qualification"]["qualification_source_commit"] = actual_qual_commit
        pin_2c["qualification"]["qualification_source_tree"] = actual_qual_tree
        pin_2c["qualification"]["matrix_receipt_sha256"] = matrix_2c_sha
        pin_2c["qualification"]["target_qualification_sources"] = target_q_sources_2c

        app_2c = copy.deepcopy(self.base_approval)
        app_2c["matrix_receipt_sha256"] = matrix_2c_sha
        app_2c["qualification"]["qualification_source_commit"] = actual_qual_commit
        app_2c["qualification"]["qualification_source_tree"] = actual_qual_tree
        app_2c["qualification"]["matrix_receipt_sha256"] = matrix_2c_sha
        app_2c["qualification"]["target_qualification_sources"] = copy.deepcopy(target_q_sources_2c)
        app_2c["set_sha256"] = compute_set_sha256(app_2c)
        app_2c["admission_sha256"] = compute_admission_sha256(app_2c)
        pin_2c["admission_sha256"] = app_2c["admission_sha256"]

        archives_2c = self.root / "archives_2c"
        api_2c = self.root / "api_2c"
        archives_2c.mkdir()
        api_2c.mkdir()

        bundle_members = {
            "candidate_receipt.json": self.candidate_receipt_bytes,
            "expected_artifacts.json": self.expected_artifacts_bytes,
            **{f"dist/{n}": d for n, d in sorted(self.wheel_bytes_by_name.items())},
        }
        payloads_2c = {
            CANDIDATE_BUNDLE_ARTIFACT: bundle_members,
            MATRIX_RECEIPT_ARTIFACT: {"matrix_receipt.json": matrix_2c_bytes},
            **{
                art_name: {f"{t}/result.json": target_bytes_2c[t]}
                for t, art_name in TARGET_QUALIFICATION_ARTIFACTS.items()
            },
        }
        cap_arts = {}
        api_rows = []
        for idx, (art_name, m_map) in enumerate(sorted(payloads_2c.items()), start=2001):
            z_bytes = _make_zip_bytes(m_map)
            (archives_2c / f"{art_name}.zip").write_bytes(z_bytes)
            url = f"https://api.github.com/repos/{DEFAULT_GITHUB_REPOSITORY}/actions/artifacts/{idx}/zip"
            cap_arts[art_name] = {
                "id": idx,
                "size_in_bytes": len(z_bytes),
                "archive_download_url": url,
                "archive_sha256": sha256(z_bytes),
                "files": {k: {"size": len(v), "sha256": sha256(v)} for k, v in sorted(m_map.items())},
            }
            api_rows.append(
                {
                    "id": idx,
                    "name": art_name,
                    "size_in_bytes": len(z_bytes),
                    "archive_download_url": url,
                    "expired": False,
                    "digest": f"sha256:{sha256(z_bytes)}",
                    "workflow_run": {
                        "id": int(RUN_ID),
                        "head_sha": actual_qual_commit,
                        "head_branch": "main",
                    },
                }
            )
        cap_2c = copy.deepcopy(self.base_capture)
        cap_2c["qualification_source_commit"] = actual_qual_commit
        cap_2c["qualification_source_tree"] = actual_qual_tree
        cap_2c["matrix_receipt_sha256"] = matrix_2c_sha
        cap_2c["artifacts"] = cap_arts

        (api_2c / "run.json").write_bytes(
            canonical(
                {
                    "id": int(RUN_ID),
                    "run_attempt": 1,
                    "head_sha": actual_qual_commit,
                    "head_branch": "main",
                    "event": "workflow_dispatch",
                    "status": "completed",
                    "conclusion": "success",
                    "path": f".github/workflows/{WORKFLOW}",
                    "repository": {"full_name": DEFAULT_GITHUB_REPOSITORY},
                }
            )
        )
        (api_2c / "artifacts.json").write_bytes(canonical({"artifacts": api_rows}))

        # Commit the 3 operator 0.7.0 files in pub_repo
        (pub_repo / "operators/tf-pypi" / PIN_BASENAME).write_bytes(canonical(pin_2c))
        (pub_repo / "operators/tf-pypi" / APPROVAL_BASENAME).write_bytes(canonical(app_2c))
        (pub_repo / "operators/tf-pypi" / CAPTURE_BASENAME).write_bytes(canonical(cap_2c))
        subprocess.run(["git", "-C", str(pub_repo), "add", "operators/tf-pypi"], check=True)
        subprocess.run(["git", "-C", str(pub_repo), "commit", "-q", "-m", "Admit 0.7.0 metadata"], check=True)
        actual_pub_commit = subprocess.check_output(
            ["git", "-C", str(pub_repo), "rev-parse", "HEAD^{commit}"], text=True
        ).strip()

        # 1. verify_source_lineage positive
        lineage = verify_source_lineage(pub_repo, qual_repo, publisher_revision=actual_pub_commit)
        self.assertEqual(lineage["publisher_commit"], actual_pub_commit)
        self.assertEqual(lineage["qualification_commit"], actual_qual_commit)

        # 2. prepare_resume positive
        resume_out = self.root / "resume_out"
        prep = prepare_resume(
            api_2c,
            archives_2c,
            resume_out,
            publisher_dir=pub_repo,
            qualification_dir=qual_repo,
        )
        self.assertEqual(prep["set_sha256"], app_2c["set_sha256"])
        self.assertEqual(prep["matrix_receipt_sha256"], matrix_2c_sha)

        # 3. stage_metadata positive, and second call refuses overwrite
        staged = stage_metadata(pub_repo, qual_repo)
        self.assertEqual(len(staged["staged"]), 3)
        with self.assertRaises(AdmissionError) as ctx_stg_dup:
            stage_metadata(pub_repo, qual_repo)
        self.assertEqual(ctx_stg_dup.exception.code, "TF_PYPI_STAGE_METADATA")

        # 4. Negative: forbidden tree diff between qualification and publisher commits
        bad_pub_repo = self.root / "bad-publisher"
        shutil.copytree(pub_repo, bad_pub_repo)
        (bad_pub_repo / "src/rs9/tf_pypi_nebular070_publish.py").write_bytes(
            (bad_pub_repo / "src/rs9/tf_pypi_nebular070_publish.py").read_bytes() + b"\n# forbidden edit\n"
        )
        subprocess.run(["git", "-C", str(bad_pub_repo), "add", "."], check=True)
        subprocess.run(["git", "-C", str(bad_pub_repo), "commit", "-q", "-m", "Forbidden code edit"], check=True)
        bad_pub_commit = subprocess.check_output(
            ["git", "-C", str(bad_pub_repo), "rev-parse", "HEAD^{commit}"], text=True
        ).strip()
        for fn in (PIN_BASENAME, APPROVAL_BASENAME, CAPTURE_BASENAME):
            (qual_repo / "operators/tf-pypi" / fn).unlink()
        with self.assertRaises(AdmissionError) as ctx_diff:
            verify_source_lineage(bad_pub_repo, qual_repo, publisher_revision=bad_pub_commit)
        self.assertEqual(ctx_diff.exception.code, "TF_PYPI_FORBIDDEN_TREE_DIFF")

        # 5. Negative: zip symlink in archive refused
        bad_archives = self.root / "bad_archives"
        shutil.copytree(archives_2c, bad_archives)
        sym_zip = _make_zip_bytes({"matrix_receipt.json": matrix_2c_bytes}, symlink_name="evil_link")
        (bad_archives / f"{MATRIX_RECEIPT_ARTIFACT}.zip").write_bytes(sym_zip)
        bad_cap = copy.deepcopy(cap_2c)
        bad_cap["artifacts"][MATRIX_RECEIPT_ARTIFACT]["size_in_bytes"] = len(sym_zip)
        bad_cap["artifacts"][MATRIX_RECEIPT_ARTIFACT]["archive_sha256"] = sha256(sym_zip)
        with self.assertRaises(AdmissionError) as ctx_zip:
            validate_archives(bad_archives, capture=bad_cap)
        self.assertEqual(ctx_zip.exception.code, "TF_PYPI_QUALIFICATION_ARCHIVE")

    def test_workflow_rendering_and_cli_surface(self) -> None:
        wf_070 = workflow_text("0.7.0")
        wf_061 = workflow_text("0.6.1")
        self.assertEqual(wf_070, wf_061)
        self.assertIn("build_verify_070:", workflow_070_qualify_jobs_text())
        self.assertNotIn("id-token: write", workflow_070_qualify_jobs_text())
        self.assertIn("publication_resume_070:", publication_resume_job_text())
        self.assertIn("id-token: write", publication_resume_job_text())
        self.assertEqual(
            workflow_070_jobs_text(),
            workflow_070_qualify_jobs_text() + publication_resume_job_text(),
        )

        # CLI workflow subcommand succeeds
        stdout_buf = io.StringIO()
        with patch("sys.stdout", stdout_buf):
            rc = main(["workflow", "--release", "0.7.0"])
        self.assertEqual(rc, 0)
        self.assertEqual(stdout_buf.getvalue(), wf_070)

        # Forbidden CLI subcommands are rejected by argparse
        for forbidden in ("publish", "upload", "dispatch", "promote", "admit"):
            with patch("sys.stderr", io.StringIO()):
                with self.assertRaises(SystemExit) as ctx_exit:
                    main([forbidden])
                self.assertNotEqual(ctx_exit.exception.code, 0)

    def test_f1_f5_build_candidates_bundle_and_qualify_native_end_to_end(self) -> None:
        repo, evidence, intent, binding = _prepare_fixture(self.root / "gate1_bundle")
        # Copy 0.7.0 description and gate1 profile so repo is complete
        desc_dst = repo / DESCRIPTION_PATH
        desc_dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / DESCRIPTION_PATH, desc_dst)
        _rewrite_fixture_payload_distinct_executables(repo, evidence, intent, binding)
        descriptor, desc_path = _build_qualification_inputs_descriptor_for_repo(
            self.root / "gate1_bundle", repo, evidence, binding
        )
        subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.com"], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test"], check=True)
        subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
        subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "Init fixture repo"], check=True)
        repo_commit = subprocess.check_output(
            ["git", "-C", str(repo), "rev-parse", "HEAD^{commit}"], text=True
        ).strip()

        # F1(a) / F5: explicit release_binding mismatching descriptor fails closed with QUALIFICATION_INPUTS_BINDING
        bad_binding = copy.deepcopy(binding)
        bad_binding["expected"]["bootstrap_sha256"] = "0" * 64
        with self.assertRaises(AdmissionError) as ctx_bind_mis:
            build_candidates_bundle(
                self.root / "bad_binding_bundle",
                expected_commit=repo_commit,
                repository=repo,
                evidence_dir=evidence,
                release_binding=bad_binding,
                require_clean=True,
            )
        self.assertEqual(
            ctx_bind_mis.exception.code, "TF_PYPI_QUALIFICATION_INPUTS_BINDING"
        )

        # F1(a) / F5: descriptor with mismatched bootstrap_sha256 fails closed before wheel building
        bad_bsha_desc = copy.deepcopy(descriptor)
        bad_bsha_desc["release_binding"] = bad_binding
        bad_bsha_desc["release_binding_sha256"] = sha256(canonical(bad_binding))
        with self.assertRaises(AdmissionError) as ctx_bsha:
            build_candidates_bundle(
                self.root / "bad_bundle",
                expected_commit=repo_commit,
                repository=repo,
                evidence_dir=evidence,
                qualification_inputs=bad_bsha_desc,
                require_clean=True,
            )
        self.assertEqual(
            ctx_bsha.exception.code, "TF_PYPI_GATE1_BOOTSTRAP_DIGEST_MISMATCH"
        )

        # Gap 1: ready explicit/env/default release_binding + evidence_dir WITHOUT a descriptor fails closed with TF_PYPI_RELEASE_INPUTS_PENDING
        repo_no_desc = self.root / "repo_no_desc"
        shutil.copytree(repo, repo_no_desc)
        (repo_no_desc / QUALIFICATION_INPUTS_PATH).unlink()
        subprocess.run(["git", "-C", str(repo_no_desc), "add", "-A"], check=True)
        subprocess.run(
            ["git", "-C", str(repo_no_desc), "commit", "-q", "-m", "Remove descriptor"],
            check=True,
        )
        no_desc_commit = subprocess.check_output(
            ["git", "-C", str(repo_no_desc), "rev-parse", "HEAD^{commit}"],
            text=True,
        ).strip()
        ready_rb_file = self.root / "ready_release_binding.json"
        ready_rb_file.write_bytes(canonical(binding))
        with self.assertRaises(AdmissionError) as ctx_no_desc_api:
            build_candidates_bundle(
                self.root / "bundle_no_desc_api",
                expected_commit=no_desc_commit,
                repository=repo_no_desc,
                evidence_dir=evidence,
                release_binding=binding,
                require_clean=True,
            )
        self.assertEqual(
            ctx_no_desc_api.exception.code, "TF_PYPI_RELEASE_INPUTS_PENDING"
        )
        with (
            patch.dict(
                os.environ,
                {
                    "RS9_TFNF070_RELEASE_BINDING": str(ready_rb_file),
                    "RS9_TFNF070_EVIDENCE_DIR": str(evidence),
                },
                clear=False,
            ),
            self.assertRaises(AdmissionError) as ctx_no_desc_env,
        ):
            build_candidates_bundle(
                self.root / "bundle_no_desc_env",
                expected_commit=no_desc_commit,
                repository=repo_no_desc,
                require_clean=True,
            )
        self.assertEqual(
            ctx_no_desc_env.exception.code, "TF_PYPI_RELEASE_INPUTS_PENDING"
        )
        err_no_desc_cli = io.StringIO()
        with (
            patch("rs9.tf_pypi_nebular070_publish.repo_root", return_value=repo_no_desc),
            patch.dict(
                os.environ,
                {
                    "RS9_TFNF070_RELEASE_BINDING": str(ready_rb_file),
                    "RS9_TFNF070_EVIDENCE_DIR": str(evidence),
                },
                clear=False,
            ),
            patch("sys.stderr", err_no_desc_cli),
        ):
            rc_no_desc_cli = main(
                [
                    "build-candidates",
                    "--output",
                    str(self.root / "bundle_no_desc_cli"),
                    "--expected-commit",
                    no_desc_commit,
                ]
            )
        self.assertEqual(rc_no_desc_cli, 1)
        self.assertEqual(
            err_no_desc_cli.getvalue().strip(), "TF_PYPI_RELEASE_INPUTS_PENDING"
        )

        # F1(a) & F1(d): build_candidates_bundle succeeds with qualification_inputs and leaves only the 5 exact members
        bundle_out = self.root / "bundle_ok"
        staged_ev = self.root / "staged_evidence"
        res_bundle = build_candidates_bundle(
            bundle_out,
            expected_commit=repo_commit,
            repository=repo,
            evidence_dir=staged_ev,
            qualification_inputs=desc_path,
            require_clean=True,
        )
        self.assertIn("candidate_receipt_sha256", res_bundle)
        rel_members = {
            str(p.relative_to(bundle_out))
            for p in bundle_out.rglob("*")
            if p.is_file()
        }
        expected_members = {
            "candidate_receipt.json",
            "expected_artifacts.json",
            *(f"dist/{EXPECTED_WHEEL_FILENAMES[t]}" for t in TARGETS),
        }
        self.assertEqual(rel_members, expected_members)
        self.assertFalse((bundle_out / ".candidates-staging").exists())
        self.assertFalse((bundle_out / "candidates").exists())

        # F1(b)/(c) & F5: qualify_native_target fails closed when raw_release handoff is missing
        with self.assertRaises(AdmissionError) as ctx_raw:
            qualify_native_target(
                bundle_out,
                self.root / "work_missing_raw",
                self.root / "out_missing_raw/result.json",
                target="darwin-arm64",
                expected_commit=QUALIFICATION_COMMIT,
                run_id=RUN_ID,
                run_attempt="1",
                repository=ROOT,
            )
        self.assertEqual(ctx_raw.exception.code, "TF_PYPI_RAW_RELEASE_HANDOFF_PENDING")

        # F5: malformed candidate_receipt.json missing profile_result_sha256 fails closed via CLI with code-only stderr
        bad_bundle = self.root / "bad_cand_bundle"
        shutil.copytree(bundle_out, bad_bundle)
        bad_cand_doc = json.loads((bad_bundle / "candidate_receipt.json").read_bytes())
        bad_cand_doc.pop("profile_result_sha256", None)
        (bad_bundle / "candidate_receipt.json").write_bytes(canonical(bad_cand_doc))
        err_buf = io.StringIO()
        with patch("sys.stderr", err_buf):
            rc_bad_cand = main(
                [
                    "qualify-native",
                    "--bundle",
                    str(bad_bundle),
                    "--work",
                    str(self.root / "work_bad_cand"),
                    "--output",
                    str(self.root / "out_bad_cand/result.json"),
                    "--target",
                    "darwin-arm64",
                    "--expected-commit",
                    QUALIFICATION_COMMIT,
                    "--run-id",
                    RUN_ID,
                    "--run-attempt",
                    "1",
                ]
            )
        self.assertEqual(rc_bad_cand, 1)
        self.assertEqual(err_buf.getvalue().strip(), "TF_PYPI_CANDIDATE_RECEIPT_SCHEMA")

        # F1(c): default_sandbox_prefix and make_real_user_state_snapshotter
        darwin_pfx = default_sandbox_prefix("darwin-arm64")
        self.assertEqual(darwin_pfx[0], "/usr/bin/sandbox-exec")
        self.assertIn("deny network*", darwin_pfx[2])
        for l_target in ("linux-arm64-gnu", "linux-x64-gnu"):
            l_pfx = default_sandbox_prefix(l_target)
            self.assertEqual(l_pfx[:2], ("sudo", "-n"))
            self.assertIn("unshare", l_pfx)
            self.assertIn("--net", l_pfx)
            self.assertIn("setpriv", l_pfx)

        fake_home = self.root / "fake_home"
        fake_home.mkdir()
        darwin_snap = make_real_user_state_snapshotter("darwin-arm64", home_dir=fake_home)
        before_d = darwin_snap("before", "darwin-arm64")
        after_d = darwin_snap("after", "darwin-arm64")
        self.assertEqual(before_d["locations"], 63)
        self.assertEqual(after_d["changed"], [])
        self.assertEqual(before_d["snapshot_sha256"], after_d["snapshot_sha256"])

        # Mutate one canonical Darwin persistent state location and verify changed detection
        mutated_dir = fake_home / "Library/Application Support/theme-forge-nebular-fusion"
        mutated_dir.mkdir(parents=True, exist_ok=True)
        (mutated_dir / "state.json").write_bytes(b"{}")
        after_d_mut = darwin_snap("after", "darwin-arm64")
        self.assertEqual(
            after_d_mut["changed"],
            ["Library/Application Support/theme-forge-nebular-fusion"],
        )

        # Linux snapshotter inspects the 36 XDG locations without parent enumeration
        fake_linux_home = self.root / "fake_linux_home"
        fake_linux_home.mkdir()
        linux_snap = make_real_user_state_snapshotter("linux-x64-gnu", home_dir=fake_linux_home)
        before_l = linux_snap("before", "linux-x64-gnu")
        after_l = linux_snap("after", "linux-x64-gnu")
        self.assertEqual(before_l["locations"], 36)
        self.assertEqual(after_l["changed"], [])
        (fake_linux_home / ".config/theme-forge-nebular-fusion").mkdir(parents=True, exist_ok=True)
        after_l_mut = linux_snap("after", "linux-x64-gnu")
        self.assertEqual(after_l_mut["changed"], [".config/theme-forge-nebular-fusion"])

        # Empty/unvalidated raw_release handoff dict is rejected with TF_PYPI_RAW_RELEASE_HANDOFF_SCHEMA
        bad_raw_handoff_file = self.root / "bad_raw_release.json"
        bad_raw_handoff_file.write_bytes(
            canonical(
                {
                    key: {}
                    for key in (
                        "root",
                        "record",
                        "readme",
                        "legal_files",
                        "payload",
                        "manifest",
                        "provenance",
                        "native_consumer",
                    )
                }
            )
        )
        err_raw_buf = io.StringIO()
        with patch("sys.stderr", err_raw_buf):
            rc_bad_raw = main(
                [
                    "qualify-native",
                    "--bundle",
                    str(bundle_out),
                    "--work",
                    str(self.root / "work_bad_raw"),
                    "--output",
                    str(self.root / "out_bad_raw/result.json"),
                    "--target",
                    "darwin-arm64",
                    "--expected-commit",
                    QUALIFICATION_COMMIT,
                    "--run-id",
                    RUN_ID,
                    "--run-attempt",
                    "1",
                    "--raw-release",
                    str(bad_raw_handoff_file),
                ]
            )
        self.assertEqual(rc_bad_raw, 1)
        self.assertEqual(err_raw_buf.getvalue().strip(), "TF_PYPI_RAW_RELEASE_HANDOFF_SCHEMA")

        # Connected qualify-native CLI invocation materializes bound raw-release handoff and executes real qualify_nebular070 -> consume_nebular_candidate
        clean_home = self.root / "clean_home"
        clean_home.mkdir()
        observed_prefixes: list[tuple[str, ...]] = []
        raw_handoff_out = self.root / "tfnf-070-raw-release-darwin-arm64/raw_release.json"
        out_qual_path = self.root / "qual_out/darwin-arm64/result.json"
        with (
            patch("rs9.tf_pypi_nebular070_publish.repo_root", return_value=repo),
            _controlled_native_consumer_driver(
                "darwin-arm64", clean_home, observed_prefixes
            ),
        ):
            rc_qual = main(
                [
                    "qualify-native",
                    "--target",
                    "darwin-arm64",
                    "--qualification-inputs",
                    str(desc_path),
                    "--raw-release",
                    str(raw_handoff_out),
                    "--bundle",
                    str(bundle_out),
                    "--work",
                    str(self.root / "work_qual"),
                    "--output",
                    str(out_qual_path),
                    "--expected-commit",
                    repo_commit,
                    "--run-id",
                    RUN_ID,
                    "--run-attempt",
                    "1",
                ]
            )
        self.assertEqual(rc_qual, 0)
        self.assertTrue(raw_handoff_out.is_file())
        self.assertTrue(out_qual_path.is_file())
        self.assertIn(default_sandbox_prefix("darwin-arm64"), observed_prefixes)

    def test_f2_check_prior_publish_runs_ignores_061_and_blocks_070(self) -> None:
        # 1. Historical 0.6.1 publish run (both with skipped 0.7.0 jobs and legacy 3-job run) passes
        def _api_061_only(url: str) -> dict:
            if "actions/workflows/" in url:
                return {
                    "total_count": 2,
                    "workflow_runs": [
                        {
                            "id": 601,
                            "workflow_id": 7001,
                            "path": f".github/workflows/{WORKFLOW}",
                            "event": "workflow_dispatch",
                            "head_branch": "main",
                            "head_sha": QUALIFICATION_COMMIT,
                            "run_attempt": 1,
                            "status": "completed",
                            "conclusion": "success",
                            "display_title": f"RS9 {PROJECT} PyPI Publish",
                            "repository": {"full_name": DEFAULT_GITHUB_REPOSITORY},
                        },
                        {
                            "id": 602,
                            "workflow_id": 7001,
                            "path": f".github/workflows/{WORKFLOW}@main",
                            "event": "workflow_dispatch",
                            "head_branch": "main",
                            "head_sha": QUALIFICATION_COMMIT,
                            "run_attempt": 1,
                            "status": "completed",
                            "conclusion": "success",
                            "display_title": f"RS9 {PROJECT} 0.6.1 publish / rel061",
                            "repository": {"full_name": DEFAULT_GITHUB_REPOSITORY},
                        },
                    ],
                }
            if "/runs/601/jobs" in url:
                raw_jobs_601 = [
                    {"name": "Build and Verify Native Darwin Wheel", "status": "completed", "conclusion": "success", "steps": []},
                    {"name": "Native macOS ARM64 installed consumer and Scenario A", "status": "completed", "conclusion": "success", "steps": []},
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
                    },
                ]
                jobs_601 = [
                    {
                        "id": 601000 + idx,
                        "run_id": 601,
                        "run_attempt": 1,
                        "head_sha": QUALIFICATION_COMMIT,
                        **j,
                    }
                    for idx, j in enumerate(raw_jobs_601, start=1)
                ]
                return {
                    "total_count": len(jobs_601),
                    "jobs": jobs_601,
                }
            if "/runs/602/jobs" in url:
                raw_jobs_602 = [
                    {
                        "name": name,
                        "status": "completed",
                        "conclusion": "skipped",
                        "steps": [],
                    }
                    for name in sorted(ALL_KNOWN_WORKFLOW_JOB_NAMES - LEGACY_061_JOB_NAMES)
                ] + [
                    {"name": "Build and Verify Native Darwin Wheel", "status": "completed", "conclusion": "success", "steps": []},
                    {"name": "Native macOS ARM64 installed consumer and Scenario A", "status": "completed", "conclusion": "success", "steps": []},
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
                    },
                ]
                jobs_602 = [
                    {
                        "id": 602000 + idx,
                        "run_id": 602,
                        "run_attempt": 1,
                        "head_sha": QUALIFICATION_COMMIT,
                        **j,
                    }
                    for idx, j in enumerate(raw_jobs_602, start=1)
                ]
                return {
                    "total_count": len(jobs_602),
                    "jobs": jobs_602,
                }
            raise AssertionError(url)

        check_prior_publish_runs(api_get=_api_061_only, environ={"GITHUB_RUN_ID": "700"})
        upload_after_061 = self.root / "upload_after_061"
        res_061 = select_missing(
            self.dist_dir,
            upload_after_061,
            candidate_receipt=self.candidate_receipt_path,
            expected_artifacts=self.expected_artifacts_path,
            receipts_dir=self.receipts_dir,
            approval=self.base_approval,
            pin=self.base_pin,
            get=lambda _u: canonical({"info": {"name": PROJECT}, "releases": {"0.6.1": []}}),
            api_get=_api_061_only,
            environ={"GITHUB_RUN_ID": "700"},
        )
        self.assertTrue(res_061["upload"])
        self.assertEqual(len(res_061["missing"]), 3)

    def test_f3_verify_matrix_receipts_enforces_qualification_checkout_commit_and_tree(self) -> None:
        other_commit = "9" * 40
        other_tree = "8" * 40
        receipts_other = self.root / "receipts_other"
        for target in TARGETS:
            t_rec = json.loads(self.target_receipt_bytes[target])
            t_rec["qualification_rs9_source"]["commit"] = other_commit
            t_rec["qualification_rs9_source"]["tree"] = other_tree
            t_dir = receipts_other / target
            t_dir.mkdir(parents=True, exist_ok=True)
            (t_dir / "result.json").write_bytes(canonical(t_rec))

        app_other = copy.deepcopy(self.base_approval)
        app_other["qualification"]["qualification_source_commit"] = other_commit
        app_other["qualification"]["qualification_source_tree"] = other_tree
        for target in TARGETS:
            app_other["qualification"]["target_qualification_sources"][target]["commit"] = other_commit
            app_other["qualification"]["target_qualification_sources"][target]["tree"] = other_tree
        app_other["set_sha256"] = compute_set_sha256(app_other)
        app_other["admission_sha256"] = compute_admission_sha256(app_other)

        with self.assertRaises(AdmissionError) as ctx_f3:
            verify_matrix_receipts(
                self.candidate_receipt_path,
                self.expected_artifacts_path,
                receipts_other,
                approval=app_other,
                repository=ROOT,
            )
        self.assertEqual(ctx_f3.exception.code, "TF_PYPI_QUALIFICATION_SOURCE_MISMATCH")

    def test_f4_admission_sha256_binds_publication_admitted_state(self) -> None:
        # Flipping publication_admitted from False to True without admission_sha256 fails closed
        flipped_app = copy.deepcopy(self.base_approval)
        flipped_app.pop("admission_sha256", None)
        with self.assertRaises(AdmissionError) as ctx_app_no_adm:
            validate_approval(flipped_app)
        self.assertEqual(ctx_app_no_adm.exception.code, "TF_PYPI_APPROVAL_ADMISSION_DIGEST")

        flipped_pin = copy.deepcopy(self.base_pin)
        flipped_pin.pop("admission_sha256", None)
        with self.assertRaises(AdmissionError) as ctx_pin_no_adm:
            validate_pin(flipped_pin)
        self.assertEqual(ctx_pin_no_adm.exception.code, "TF_PYPI_PIN_ADMISSION_DIGEST")

        # Including admission_sha256 while publication_admitted=False fails closed
        unadm_with_digest = copy.deepcopy(self.base_approval)
        unadm_with_digest["publication_admitted"] = False
        with self.assertRaises(AdmissionError) as ctx_unadm_dig:
            validate_approval(unadm_with_digest)
        self.assertEqual(ctx_unadm_dig.exception.code, "TF_PYPI_APPROVAL_ADMISSION_DIGEST")

        # Mismatched pin vs approval admission_sha256 fails closed
        bad_pin = copy.deepcopy(self.base_pin)
        bad_pin["admission_sha256"] = "f" * 64
        with self.assertRaises(AdmissionError) as ctx_pin_mis:
            verify_approved(self.dist_dir, approval=self.base_approval, pin=bad_pin)
        self.assertEqual(ctx_pin_mis.exception.code, "TF_PYPI_PIN_APPROVAL_MISMATCH")

    def test_f5_target_qualification_schema_and_workflow_hardening(self) -> None:
        # 1. status=None or verified=None in target_qualification_sources fails closed
        for field, bad_val in (("status", None), ("verified", None), ("verified", False)):
            bad_pin = copy.deepcopy(self.base_pin)
            bad_pin["qualification"]["target_qualification_sources"]["darwin-arm64"][field] = bad_val
            with self.assertRaises(AdmissionError) as ctx_tq:
                validate_pin(bad_pin)
            self.assertEqual(ctx_tq.exception.code, "TF_PYPI_PIN_QUALIFICATION")

        # 2. validate_workflow_dispatch and CLI validate-dispatch reject 0.7.0+publish and 0.6.1+resume
        for valid_rel, valid_mode in (
            ("0.6.1", "qualify"),
            ("0.6.1", "publish"),
            ("0.7.0", "qualify"),
            ("0.7.0", "resume"),
        ):
            self.assertEqual(
                validate_workflow_dispatch(valid_rel, valid_mode),
                {"release": valid_rel, "mode": valid_mode},
            )
            with patch("sys.stdout", io.StringIO()):
                self.assertEqual(
                    main(["validate-dispatch", "--release", valid_rel, "--mode", valid_mode]),
                    0,
                )

        for invalid_rel, invalid_mode in (("0.7.0", "publish"), ("0.6.1", "resume")):
            with self.assertRaises(AdmissionError) as ctx_disp:
                validate_workflow_dispatch(invalid_rel, invalid_mode)
            self.assertEqual(ctx_disp.exception.code, "TF_PYPI_WORKFLOW_MODE_UNSUPPORTED")
            err_buf = io.StringIO()
            with patch("sys.stderr", err_buf):
                rc_disp = main(["validate-dispatch", "--release", invalid_rel, "--mode", invalid_mode])
            self.assertEqual(rc_disp, 1)
            self.assertEqual(err_buf.getvalue().strip(), "TF_PYPI_WORKFLOW_MODE_UNSUPPORTED")

        # 3. Workflow YAML hardening assertions
        wf = workflow_text("0.7.0")
        self.assertIn("reject_unsupported_dispatch:", wf)
        self.assertIn("retention-days: 14", workflow_070_qualify_jobs_text())
        self.assertNotIn("retention-days: 5", workflow_070_qualify_jobs_text())
        self.assertNotIn("Authorization: Bearer", publication_resume_job_text())
        self.assertIn("gh api --header 'X-GitHub-Api-Version: 2022-11-28'", publication_resume_job_text())

    def test_r1_rendered_resume_python_resolver_executes_under_selected_python313(self) -> None:
        # Extract the exact shell command from publication_resume_job_text() step "Resolve pinned qualification commit from publisher authority"
        resume_yaml = publication_resume_job_text()
        marker = "- name: Resolve pinned qualification commit from publisher authority"
        self.assertIn(marker, resume_yaml)
        after_marker = resume_yaml.split(marker, 1)[1]
        run_section = after_marker.split("run: |\n", 1)[1].split("\n      - name:", 1)[0]
        raw_lines = [
            line[10:] if line.startswith("          ") else line
            for line in run_section.splitlines()
            if line.strip()
        ]
        shell_cmd = "\n".join(raw_lines).replace(
            "${{ steps.setup_python.outputs.python-path }}",
            sys.executable,
        )

        work_dir = self.root / "r1_exec"
        pub_dir = work_dir / "publisher-authority"
        ops_dir = pub_dir / "operators/tf-pypi"
        ops_dir.mkdir(parents=True, exist_ok=True)
        for rel in ("src/rs9/__init__.py", *QUALIFICATION_SOURCE_HELPERS):
            src_f = ROOT / rel
            if src_f.is_file():
                dst_f = pub_dir / rel
                dst_f.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(src_f, dst_f)
        for p_src in (ROOT / "src/rs9").glob("*.py"):
            dst_f = pub_dir / "src/rs9" / p_src.name
            if not dst_f.exists():
                shutil.copyfile(p_src, dst_f)
        (ops_dir / PIN_BASENAME).write_bytes(canonical(self.base_pin))
        (ops_dir / APPROVAL_BASENAME).write_bytes(canonical(self.base_approval))
        (ops_dir / CAPTURE_BASENAME).write_bytes(canonical(self.base_capture))

        gh_out = work_dir / "github_output.txt"
        gh_out.write_text("", encoding="utf-8")
        proc = subprocess.run(
            ["bash", "-euo", "pipefail", "-c", shell_cmd],
            cwd=str(work_dir),
            env={
                **os.environ,
                "PYTHONPATH": "publisher-authority/src",
                "PYTHONDONTWRITEBYTECODE": "1",
                "GITHUB_OUTPUT": str(gh_out),
            },
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out_lines = gh_out.read_text(encoding="utf-8").strip().splitlines()
        self.assertEqual(
            out_lines,
            [
                f"qualification_commit={QUALIFICATION_COMMIT}",
                f"qualification_run_id={RUN_ID}",
            ],
        )

    def test_r2_r3_rendered_workflow_cli_end_to_end_and_handoff_negatives(self) -> None:
        # 1. Verify rendered workflow YAML wires --qualification-inputs, --evidence, and --raw-release on all 0.7.0 qualify jobs
        qual_yaml = workflow_070_qualify_jobs_text()
        self.assertIn(
            f"--qualification-inputs {QUALIFICATION_INPUTS_PATH.as_posix()}",
            qual_yaml,
        )
        self.assertIn('--evidence "${{ runner.temp }}/tfnf-070-evidence"', qual_yaml)
        for target in TARGETS:
            self.assertIn(
                f'--raw-release "${{{{ runner.temp }}}}/tfnf-070-raw-release-{target}/raw_release.json"',
                qual_yaml,
            )

        # 2. Missing qualification-inputs descriptor fails closed with TF_PYPI_RELEASE_INPUTS_PENDING before Gate 1 or consumer work
        err_missing = io.StringIO()
        with patch("sys.stderr", err_missing):
            rc_missing = main(
                [
                    "build-candidates",
                    "--qualification-inputs",
                    str(self.root / "nonexistent-inputs.json"),
                    "--evidence",
                    str(self.root / "ev_missing"),
                    "--output",
                    str(self.root / "bundle_missing"),
                    "--expected-commit",
                    QUALIFICATION_COMMIT,
                ]
            )
        self.assertEqual(rc_missing, 1)
        self.assertEqual(
            err_missing.getvalue().strip(), "TF_PYPI_RELEASE_INPUTS_PENDING"
        )

        # 3. Prepare a clean fixture repository with committed qualification-inputs descriptor
        fx_base = self.root / "r2_r3_e2e"
        repo, evidence, intent, binding = _prepare_fixture(fx_base)
        desc_dst = repo / DESCRIPTION_PATH
        desc_dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / DESCRIPTION_PATH, desc_dst)
        _rewrite_fixture_payload_distinct_executables(repo, evidence, intent, binding)
        descriptor, desc_path = _build_qualification_inputs_descriptor_for_repo(
            fx_base, repo, evidence, binding
        )
        subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
        subprocess.run(
            ["git", "-C", str(repo), "config", "user.email", "test@example.com"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(repo), "config", "user.name", "Test"],
            check=True,
        )
        subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
        subprocess.run(
            ["git", "-C", str(repo), "commit", "-q", "-m", "Commit ready inputs"],
            check=True,
        )
        repo_commit = subprocess.check_output(
            ["git", "-C", str(repo), "rev-parse", "HEAD^{commit}"], text=True
        ).strip()
        repo_tree = subprocess.check_output(
            ["git", "-C", str(repo), "rev-parse", "HEAD^{tree}"], text=True
        ).strip()

        # Pending status in descriptor fails closed with TF_PYPI_RELEASE_INPUTS_PENDING / TF_PYPI_RAW_RELEASE_HANDOFF_PENDING
        pending_desc = copy.deepcopy(descriptor)
        pending_desc["status"] = "pending"
        with self.assertRaises(AdmissionError) as ctx_pend_b:
            validate_qualification_inputs_descriptor(
                pending_desc, repository=repo, pending_code="RELEASE_INPUTS_PENDING"
            )
        self.assertEqual(
            ctx_pend_b.exception.code, "TF_PYPI_RELEASE_INPUTS_PENDING"
        )
        with self.assertRaises(AdmissionError) as ctx_pend_q:
            validate_qualification_inputs_descriptor(
                pending_desc,
                repository=repo,
                pending_code="RAW_RELEASE_HANDOFF_PENDING",
            )
        self.assertEqual(
            ctx_pend_q.exception.code, "TF_PYPI_RAW_RELEASE_HANDOFF_PENDING"
        )

        # Tampered evidence digest in descriptor fails closed with TF_PYPI_QUALIFICATION_INPUTS_DIGEST
        bad_ev_desc = copy.deepcopy(descriptor)
        bad_ev_desc["evidence"]["files"]["api/release.json"]["sha256"] = "0" * 64
        with self.assertRaises(AdmissionError) as ctx_ev_dig:
            materialize_qualification_evidence(
                bad_ev_desc, fx_base / "bad_ev_out", repository=repo
            )
        self.assertEqual(
            ctx_ev_dig.exception.code, "TF_PYPI_QUALIFICATION_INPUTS_DIGEST"
        )

        # 4. Execute build-candidates via CLI (matching build_verify_070 job)
        runner_temp = fx_base / "runner_temp"
        ev_out = runner_temp / "tfnf-070-evidence"
        bundle_out = runner_temp / "tfnf-070-bundle"
        with (
            patch("rs9.tf_pypi_nebular070_publish.repo_root", return_value=repo),
            patch("sys.stdout", io.StringIO()),
        ):
            rc_build = main(
                [
                    "build-candidates",
                    "--qualification-inputs",
                    str(desc_path),
                    "--evidence",
                    str(ev_out),
                    "--output",
                    str(bundle_out),
                    "--expected-commit",
                    repo_commit,
                    "--require-clean",
                ]
            )
        self.assertEqual(rc_build, 0)
        self.assertTrue(ev_out.is_dir())
        self.assertTrue((bundle_out / "candidate_receipt.json").is_file())
        self.assertTrue((bundle_out / "expected_artifacts.json").is_file())

        # Extra file inside bundle directory (such as bundle/raw_release.json) is rejected by _validate_bundle_file_set
        tainted_bundle = fx_base / "tainted_bundle"
        shutil.copytree(bundle_out, tainted_bundle)
        (tainted_bundle / "raw_release.json").write_bytes(b"{}")
        err_tainted = io.StringIO()
        with (
            patch("rs9.tf_pypi_nebular070_publish.repo_root", return_value=repo),
            patch("sys.stderr", err_tainted),
        ):
            rc_tainted = main(
                [
                    "qualify-native",
                    "--target",
                    "darwin-arm64",
                    "--qualification-inputs",
                    str(desc_path),
                    "--raw-release",
                    str(fx_base / "tainted_rr/raw_release.json"),
                    "--bundle",
                    str(tainted_bundle),
                    "--work",
                    str(fx_base / "tainted_work"),
                    "--output",
                    str(fx_base / "tainted_out/result.json"),
                    "--expected-commit",
                    repo_commit,
                    "--run-id",
                    RUN_ID,
                    "--run-attempt",
                    "1",
                ]
            )
        self.assertEqual(rc_tainted, 1)
        self.assertEqual(err_tainted.getvalue().strip(), "TF_PYPI_BUNDLE_FILE_SET")

        # 5. Execute qualify-native via CLI for all 3 targets (matching the 3 native_consumer_070_* jobs)
        qual_receipts_dir = runner_temp / "tfnf-070-receipts"
        clean_home = fx_base / "clean_operator_home"
        clean_home.mkdir()
        for target in TARGETS:
            observed_prefixes: list[tuple[str, ...]] = []
            rr_target_path = (
                runner_temp
                / f"tfnf-070-raw-release-{target}"
                / "raw_release.json"
            )
            work_target_dir = runner_temp / f"tfnf-070-work-{target}"
            out_target_file = qual_receipts_dir / target / "result.json"
            with (
                patch(
                    "rs9.tf_pypi_nebular070_publish.repo_root", return_value=repo
                ),
                _controlled_native_consumer_driver(
                    target, clean_home, observed_prefixes
                ),
            ):
                rc_q = main(
                    [
                        "qualify-native",
                        "--target",
                        target,
                        "--qualification-inputs",
                        str(desc_path),
                        "--raw-release",
                        str(rr_target_path),
                        "--bundle",
                        str(bundle_out),
                        "--work",
                        str(work_target_dir),
                        "--output",
                        str(out_target_file),
                        "--expected-commit",
                        repo_commit,
                        "--run-id",
                        RUN_ID,
                        "--run-attempt",
                        "1",
                    ]
                )
            self.assertEqual(rc_q, 0)
            self.assertTrue(rr_target_path.is_file())
            self.assertTrue(out_target_file.is_file())
            self.assertIn(default_sandbox_prefix(target), observed_prefixes)
            q_doc = json.loads(out_target_file.read_bytes())
            self.assertEqual(q_doc["status"], "native-consumer-passed")
            self.assertIs(q_doc["native_qualified"], True)
            self.assertEqual(
                q_doc["consumer"]["process_observer"]["orphan_count"], 0
            )
            self.assertIs(q_doc["consumer"]["user_state"]["unchanged"], True)

        # Negative handoff checks: mixed-target handoff, tampered file digest, descriptor-mismatched pre-existing handoff, and unclosed source_root/duplicate root
        for bad_src_root in ("/abs/path", "../escape", "a/../b"):
            bad_ev_root_desc = copy.deepcopy(descriptor)
            bad_ev_root_desc["evidence"]["source_root"] = bad_src_root
            with self.assertRaises(AdmissionError) as ctx_ev_root:
                validate_qualification_inputs_descriptor(
                    bad_ev_root_desc, repository=repo
                )
            self.assertEqual(
                ctx_ev_root.exception.code,
                "TF_PYPI_QUALIFICATION_INPUTS_EVIDENCE",
            )
            bad_rr_root_desc = copy.deepcopy(descriptor)
            bad_rr_root_desc["raw_release"]["source_root"] = bad_src_root
            with self.assertRaises(AdmissionError) as ctx_rr_root:
                validate_qualification_inputs_descriptor(
                    bad_rr_root_desc, repository=repo
                )
            self.assertEqual(
                ctx_rr_root.exception.code,
                "TF_PYPI_QUALIFICATION_INPUTS_RAW_RELEASE",
            )

        dup_root_desc = copy.deepcopy(descriptor)
        dup_root_desc["raw_release"]["targets"]["darwin-arm64"]["root"] = "dup"
        with self.assertRaises(AdmissionError) as ctx_dup_root:
            validate_qualification_inputs_descriptor(
                dup_root_desc, repository=repo
            )
        self.assertEqual(
            ctx_dup_root.exception.code,
            "TF_PYPI_QUALIFICATION_INPUTS_RAW_RELEASE",
        )

        darwin_rr_path = (
            runner_temp
            / "tfnf-070-raw-release-darwin-arm64"
            / "raw_release.json"
        )
        with self.assertRaises(AdmissionError) as ctx_mixed_target:
            load_raw_release_handoff(
                darwin_rr_path,
                target="linux-x64-gnu",
                bundle_dir=bundle_out,
            )
        self.assertEqual(
            ctx_mixed_target.exception.code, "TF_PYPI_RAW_RELEASE_HANDOFF_BINDING"
        )

        # Handoff relative-path binding: nested alias with identical basename and bytes is rejected against descriptor
        alias_rr_dir = fx_base / "alias_relpath_rr"
        shutil.copytree(darwin_rr_path.parent, alias_rr_dir)
        base_alias_doc = json.loads((alias_rr_dir / "raw_release.json").read_bytes())
        base_alias_doc["root"] = str((alias_rr_dir / "files").resolve())
        nested_alias_dir = alias_rr_dir / "files/nested"
        nested_alias_dir.mkdir(parents=True, exist_ok=True)
        for src_rel in (
            "release.json",
            "LICENSE",
            "qualification-darwin-arm64.json",
            "smoke-run-darwin-arm64-raw-archive.json",
        ):
            shutil.copyfile(
                alias_rr_dir / f"files/{src_rel}",
                nested_alias_dir / src_rel,
            )
        cand_for_alias = json.loads(
            (bundle_out / "candidate_receipt.json").read_bytes()
        )
        exp_for_alias = json.loads(
            (bundle_out / "expected_artifacts.json").read_bytes()
        )
        alias_record = copy.deepcopy(base_alias_doc)
        alias_record["record"]["path"] = "nested/release.json"
        alias_legal = copy.deepcopy(base_alias_doc)
        alias_legal["legal_files"]["LICENSE"]["path"] = "nested/LICENSE"
        alias_qual = copy.deepcopy(base_alias_doc)
        alias_qual["native_consumer"]["darwin-arm64"]["qualification"]["path"] = (
            "nested/qualification-darwin-arm64.json"
        )
        alias_smoke = copy.deepcopy(base_alias_doc)
        alias_smoke["native_consumer"]["darwin-arm64"]["smoke"]["raw-archive"][
            "run"
        ]["path"] = "nested/smoke-run-darwin-arm64-raw-archive.json"
        for alias_case in (alias_record, alias_legal, alias_qual, alias_smoke):
            with self.assertRaises(AdmissionError) as ctx_alias:
                validate_raw_release_handoff_binding(
                    alias_case,
                    target="darwin-arm64",
                    candidate=cand_for_alias,
                    expected_artifacts=exp_for_alias,
                    qualification_inputs=descriptor,
                    repository=repo,
                )
            self.assertEqual(
                ctx_alias.exception.code, "TF_PYPI_RAW_RELEASE_HANDOFF_BINDING"
            )

        tampered_rr_dir = fx_base / "tampered_rr"
        shutil.copytree(darwin_rr_path.parent, tampered_rr_dir)
        tampered_rr_doc = json.loads(
            (tampered_rr_dir / "raw_release.json").read_bytes()
        )
        tampered_rr_doc["root"] = str((tampered_rr_dir / "files").resolve())
        (tampered_rr_dir / "files/PROVENANCE.json").write_bytes(b'{"tampered":true}')
        (tampered_rr_dir / "raw_release.json").write_bytes(
            canonical(tampered_rr_doc)
        )
        with self.assertRaises(AdmissionError) as ctx_tampered_rr:
            load_raw_release_handoff(
                tampered_rr_dir / "raw_release.json",
                target="darwin-arm64",
                bundle_dir=bundle_out,
            )
        self.assertEqual(
            ctx_tampered_rr.exception.code, "TF_PYPI_RAW_RELEASE_HANDOFF_DIGEST"
        )

        # F2: Pre-existing handoff whose self-declared qualification digest + file on disk are both modified is refused against descriptor
        self_consistent_tampered_dir = fx_base / "self_consistent_tampered_rr"
        shutil.copytree(darwin_rr_path.parent, self_consistent_tampered_dir)
        sc_doc = json.loads(
            (self_consistent_tampered_dir / "raw_release.json").read_bytes()
        )
        sc_doc["root"] = str((self_consistent_tampered_dir / "files").resolve())
        alt_qual_bytes = b'{"tampered_self_consistent":true}\n'
        (
            self_consistent_tampered_dir / "files/qualification-darwin-arm64.json"
        ).write_bytes(alt_qual_bytes)
        sc_doc["native_consumer"]["darwin-arm64"]["qualification"] = {
            "path": "qualification-darwin-arm64.json",
            "size": len(alt_qual_bytes),
            "sha256": sha256(alt_qual_bytes),
        }
        sc_handoff_file = self_consistent_tampered_dir / "raw_release.json"
        sc_handoff_file.write_bytes(canonical(sc_doc))
        with self.assertRaises(AdmissionError) as ctx_sc_desc:
            qualify_native_target(
                bundle_out,
                fx_base / "sc_work",
                fx_base / "sc_out/result.json",
                target="darwin-arm64",
                expected_commit=repo_commit,
                run_id=RUN_ID,
                run_attempt="1",
                raw_release_path=sc_handoff_file,
                qualification_inputs=desc_path,
                repository=repo,
            )
        self.assertEqual(
            ctx_sc_desc.exception.code, "TF_PYPI_RAW_RELEASE_HANDOFF_DIGEST"
        )

        # F2: Passing a valid pre-existing --raw-release without a descriptor in repository fails closed with TF_PYPI_RAW_RELEASE_HANDOFF_PENDING
        with self.assertRaises(AdmissionError) as ctx_no_desc_rr:
            qualify_native_target(
                bundle_out,
                fx_base / "no_desc_work",
                fx_base / "no_desc_out/result.json",
                target="darwin-arm64",
                expected_commit=repo_commit,
                run_id=RUN_ID,
                run_attempt="1",
                raw_release_path=darwin_rr_path,
                repository=ROOT,
            )
        self.assertEqual(
            ctx_no_desc_rr.exception.code, "TF_PYPI_RAW_RELEASE_HANDOFF_PENDING"
        )

        # F5: Failed materialization cleans up staging directory and invalid candidate rows fail closed with CANDIDATE_RECEIPT_SCHEMA
        bad_stage_out = fx_base / "bad_stage_rr/raw_release.json"
        bad_rr_desc = copy.deepcopy(descriptor)
        bad_rr_desc["raw_release"]["targets"]["darwin-arm64"]["record"]["sha256"] = "0" * 64
        with self.assertRaises(AdmissionError) as ctx_stage_clean:
            materialize_raw_release_handoff(
                bad_rr_desc,
                bad_stage_out,
                target="darwin-arm64",
                candidate=json.loads((bundle_out / "candidate_receipt.json").read_bytes()),
                expected_artifacts=json.loads((bundle_out / "expected_artifacts.json").read_bytes()),
                repository=repo,
            )
        self.assertEqual(
            ctx_stage_clean.exception.code, "TF_PYPI_RAW_RELEASE_HANDOFF_DIGEST"
        )
        self.assertFalse((bad_stage_out.parent / "files").exists())
        self.assertFalse(bad_stage_out.exists())

        with self.assertRaises(AdmissionError) as ctx_empty_rows:
            materialize_raw_release_handoff(
                descriptor,
                fx_base / "empty_rows_rr/raw_release.json",
                target="darwin-arm64",
                candidate={"rows": []},
                expected_artifacts=json.loads((bundle_out / "expected_artifacts.json").read_bytes()),
                repository=repo,
            )
        self.assertEqual(
            ctx_empty_rows.exception.code, "TF_PYPI_CANDIDATE_RECEIPT_SCHEMA"
        )

        # 6. Execute admit-matrix via CLI (matching qualification_gate_070 job)
        matrix_out_file = runner_temp / "tfnf-070-matrix/matrix_receipt.json"
        with (
            patch("rs9.tf_pypi_nebular070_publish.repo_root", return_value=repo),
            patch(
                "rs9.tf_pypi_hosted.__file__",
                str(repo / "src/rs9/tf_pypi_hosted.py"),
            ),
        ):
            rc_mat = main(
                [
                    "admit-matrix",
                    "--bundle",
                    str(bundle_out),
                    "--receipts-dir",
                    str(qual_receipts_dir),
                    "--output",
                    str(matrix_out_file),
                    "--expected-commit",
                    repo_commit,
                    "--run-id",
                    RUN_ID,
                    "--run-attempt",
                    "1",
                ]
            )
        self.assertEqual(rc_mat, 0)
        self.assertTrue(matrix_out_file.is_file())
        matrix_bytes = matrix_out_file.read_bytes()
        matrix_sha = sha256(matrix_bytes)

        # 7. Package the 5 workflow artifacts and verify validate_qualification_capture + validate_archives accept them
        cand_bytes = (bundle_out / "candidate_receipt.json").read_bytes()
        exp_bytes = (bundle_out / "expected_artifacts.json").read_bytes()
        cand_doc = json.loads(cand_bytes)
        exp_doc = json.loads(exp_bytes)
        bundle_zip_members = {
            "candidate_receipt.json": cand_bytes,
            "expected_artifacts.json": exp_bytes,
            **{
                f"dist/{w['filename']}": (
                    bundle_out / "dist" / w["filename"]
                ).read_bytes()
                for w in exp_doc["wheels"]
            },
        }
        artifact_payloads = {
            CANDIDATE_BUNDLE_ARTIFACT: bundle_zip_members,
            MATRIX_RECEIPT_ARTIFACT: {"matrix_receipt.json": matrix_bytes},
            **{
                art_name: {
                    f"{t}/result.json": (
                        qual_receipts_dir / t / "result.json"
                    ).read_bytes()
                }
                for t, art_name in TARGET_QUALIFICATION_ARTIFACTS.items()
            },
        }
        archives_dir = fx_base / "retained_archives"
        archives_dir.mkdir()
        cap_artifacts = {}
        for idx, (art_name, m_map) in enumerate(
            sorted(artifact_payloads.items()), start=5001
        ):
            z_data = _make_zip_bytes(m_map)
            (archives_dir / f"{art_name}.zip").write_bytes(z_data)
            cap_artifacts[art_name] = {
                "id": idx,
                "size_in_bytes": len(z_data),
                "archive_download_url": f"https://api.github.com/repos/{DEFAULT_GITHUB_REPOSITORY}/actions/artifacts/{idx}/zip",
                "archive_sha256": sha256(z_data),
                "files": {
                    k: {"size": len(v), "sha256": sha256(v)}
                    for k, v in sorted(m_map.items())
                },
            }
        capture_doc = {
            "schema": CAPTURE_SCHEMA,
            "project": PROJECT,
            "version": VERSION,
            "distribution_version": DISTRIBUTION_VERSION,
            "workflow": WORKFLOW,
            "repository": DEFAULT_GITHUB_REPOSITORY,
            "run_id": int(RUN_ID),
            "run_attempt": 1,
            "head_branch": "main",
            "event": "workflow_dispatch",
            "status": "completed",
            "conclusion": "success",
            "candidate_source_commit": repo_commit,
            "candidate_source_tree": repo_tree,
            "qualification_source_commit": repo_commit,
            "qualification_source_tree": repo_tree,
            "candidate_receipt_sha256": sha256(cand_bytes),
            "expected_artifact_record_sha256": exp_doc["record_sha256"],
            "profile_sha256": cand_doc["profile_result_sha256"],
            "matrix_receipt_sha256": matrix_sha,
            "artifacts": cap_artifacts,
        }
        validated_cap = validate_qualification_capture(capture_doc)
        extracted_map = validate_archives(archives_dir, capture=validated_cap)
        self.assertEqual(
            set(extracted_map.keys()),
            set(artifact_payloads.keys()),
        )

    def test_r4_check_prior_publish_runs_admits_070_qualify_and_fails_closed_on_ambiguous_or_partial_runs(
        self,
    ) -> None:
        qualify_5_jobs = [
            {
                "name": name,
                "status": "completed",
                "conclusion": "success",
                "steps": [],
            }
            for name in sorted(QUALIFY_070_JOB_NAMES)
        ]
        skipped_non_qualify_jobs = [
            {
                "name": "Attended Nebular 0.7.0 PyPI publication resume",
                "status": "completed",
                "conclusion": "skipped",
                "steps": [],
            },
            {
                "name": DISPATCH_GUARD_070_JOB_NAME,
                "status": "completed",
                "conclusion": "skipped",
                "steps": [],
            },
            {
                "name": "Build and Verify Native Darwin Wheel",
                "status": "completed",
                "conclusion": "skipped",
                "steps": [],
            },
            {
                "name": "Native macOS ARM64 installed consumer and Scenario A",
                "status": "completed",
                "conclusion": "skipped",
                "steps": [],
            },
            {
                "name": "Trusted Publishing to PyPI",
                "status": "completed",
                "conclusion": "skipped",
                "steps": [],
            },
        ]
        qualify_10_all_success = qualify_5_jobs + skipped_non_qualify_jobs
        qualify_10_build_failed = [
            {
                "name": name,
                "status": "completed",
                "conclusion": (
                    "failure"
                    if name == "Build and Verify Nebular 0.7.0 Candidate Bundle"
                    else "skipped"
                ),
                "steps": [],
            }
            for name in sorted(QUALIFY_070_JOB_NAMES)
        ] + skipped_non_qualify_jobs
        qualify_10_native_failed = [
            {
                "name": name,
                "status": "completed",
                "conclusion": (
                    "failure"
                    if name == "Native consumer 0.7.0 (linux-x64-gnu)"
                    else (
                        "skipped"
                        if name == "Qualification matrix gate 0.7.0"
                        else "success"
                    )
                ),
                "steps": [],
            }
            for name in sorted(QUALIFY_070_JOB_NAMES)
        ] + skipped_non_qualify_jobs
        legacy_061_10_jobs = [
            {
                "name": name,
                "status": "completed",
                "conclusion": "skipped",
                "steps": [],
            }
            for name in sorted(QUALIFY_070_JOB_NAMES)
        ] + [
            {
                "name": "Attended Nebular 0.7.0 PyPI publication resume",
                "status": "completed",
                "conclusion": "skipped",
                "steps": [],
            },
            {
                "name": DISPATCH_GUARD_070_JOB_NAME,
                "status": "completed",
                "conclusion": "skipped",
                "steps": [],
            },
            {
                "name": "Build and Verify Native Darwin Wheel",
                "status": "completed",
                "conclusion": "success",
                "steps": [],
            },
            {
                "name": "Native macOS ARM64 installed consumer and Scenario A",
                "status": "completed",
                "conclusion": "success",
                "steps": [],
            },
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
            },
        ]
        resume_070_upload_skipped_10_jobs = [
            {
                "name": name,
                "status": "completed",
                "conclusion": "skipped",
                "steps": [],
            }
            for name in sorted(QUALIFY_070_JOB_NAMES)
        ] + [
            {
                "name": "Attended Nebular 0.7.0 PyPI publication resume",
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
            {
                "name": DISPATCH_GUARD_070_JOB_NAME,
                "status": "completed",
                "conclusion": "skipped",
                "steps": [],
            },
            {
                "name": "Build and Verify Native Darwin Wheel",
                "status": "completed",
                "conclusion": "skipped",
                "steps": [],
            },
            {
                "name": "Native macOS ARM64 installed consumer and Scenario A",
                "status": "completed",
                "conclusion": "skipped",
                "steps": [],
            },
            {
                "name": "Trusted Publishing to PyPI",
                "status": "completed",
                "conclusion": "skipped",
                "steps": [],
            },
        ]

        # 1. Positive: combined history of 10-job passing 0.7.0 qualify (including a dispatch_id containing 'resume'), failed-build 0.7.0 qualify, failed-native 0.7.0 qualify, failed-matrix 0.7.0 qualify, historical 0.6.1 qualify & publish, and failed pre-upload 0.7.0 resume
        qualify_10_matrix_failed = [
            {
                "name": name,
                "status": "completed",
                "conclusion": (
                    "failure"
                    if name == "Qualification matrix gate 0.7.0"
                    else "success"
                ),
                "steps": [],
            }
            for name in sorted(QUALIFY_070_JOB_NAMES)
        ] + skipped_non_qualify_jobs
        legacy_061_qualify_10_jobs = [
            {
                "name": name,
                "status": "completed",
                "conclusion": "skipped",
                "steps": [],
            }
            for name in sorted(QUALIFY_070_JOB_NAMES)
        ] + [
            {
                "name": "Attended Nebular 0.7.0 PyPI publication resume",
                "status": "completed",
                "conclusion": "skipped",
                "steps": [],
            },
            {
                "name": DISPATCH_GUARD_070_JOB_NAME,
                "status": "completed",
                "conclusion": "skipped",
                "steps": [],
            },
            {
                "name": "Build and Verify Native Darwin Wheel",
                "status": "completed",
                "conclusion": "success",
                "steps": [],
            },
            {
                "name": "Native macOS ARM64 installed consumer and Scenario A",
                "status": "completed",
                "conclusion": "success",
                "steps": [],
            },
            {
                "name": "Trusted Publishing to PyPI",
                "status": "completed",
                "conclusion": "skipped",
                "steps": [],
            },
        ]

        def _bind_jobs_for_run(
            raw_jobs: list[dict],
            *,
            run_id: int,
            run_attempt: int = 1,
            head_sha: str = QUALIFICATION_COMMIT,
            id_base: int | None = None,
            fill_profiles: bool = True,
        ) -> list[dict]:
            base = (
                id_base
                if id_base is not None
                else (run_id * 1000 + run_attempt * 100)
            )
            bound: list[dict] = []
            source_jobs = (
                _fill_current_profile_steps(raw_jobs)
                if fill_profiles
                else copy.deepcopy(raw_jobs)
            )
            for idx, j in enumerate(source_jobs, start=1):
                entry = copy.deepcopy(j)
                entry.setdefault("id", base + idx)
                entry.setdefault("run_id", run_id)
                entry.setdefault("run_attempt", run_attempt)
                entry.setdefault("head_sha", head_sha)
                bound.append(entry)
            return bound

        def _make_run_meta(
            rid: int,
            *,
            conclusion: str | None = "success",
            display_title: str | None = None,
            path: str | None = None,
            workflow_id: int | None = 7001,
            event: str = "workflow_dispatch",
            head_branch: str = "main",
            head_sha: str = QUALIFICATION_COMMIT,
            run_attempt: int | None = 1,
            status: str | None = "completed",
            inputs: Any = ...,
            repo_full_name: str = DEFAULT_GITHUB_REPOSITORY,
            head_repo_full_name: str | None = None,
        ) -> dict:
            meta: dict = {
                "id": rid,
                "workflow_id": workflow_id,
                "path": (
                    f".github/workflows/{WORKFLOW}" if path is None else path
                ),
                "event": event,
                "head_branch": head_branch,
                "head_sha": head_sha,
                "run_attempt": run_attempt,
                "status": status,
                "conclusion": conclusion,
                "display_title": (
                    f"RS9 {PROJECT} 0.7.0 qualify / q-{rid}"
                    if display_title is None
                    else display_title
                ),
                "repository": {"full_name": repo_full_name},
                "head_repository": {
                    "full_name": (
                        repo_full_name
                        if head_repo_full_name is None
                        else head_repo_full_name
                    )
                },
            }
            if inputs is not ...:
                meta["inputs"] = inputs
            return meta

        positive_runs_spec = {
            801: (
                _make_run_meta(
                    801,
                    conclusion="success",
                    display_title=f"RS9 {PROJECT} 0.7.0 qualify / resume-drill-801",
                    path=f".github/workflows/{WORKFLOW}@refs/heads/main",
                ),
                _bind_jobs_for_run(qualify_10_all_success, run_id=801),
            ),
            802: (
                _make_run_meta(
                    802,
                    conclusion="failure",
                    display_title=f"RS9 {PROJECT} 0.7.0 qualify / q-802",
                    path=f".github/workflows/{WORKFLOW}@{QUALIFICATION_COMMIT}",
                    inputs={"release": "0.7.0", "mode": "qualify"},
                ),
                _bind_jobs_for_run(qualify_10_build_failed, run_id=802),
            ),
            803: (
                _make_run_meta(
                    803,
                    conclusion="failure",
                    display_title=f"RS9 {PROJECT} 0.7.0 qualify / q-803",
                ),
                _bind_jobs_for_run(qualify_10_native_failed, run_id=803),
            ),
            804: (
                _make_run_meta(
                    804,
                    conclusion="success",
                    display_title=f"RS9 {PROJECT} 0.6.1 publish / pub-804",
                ),
                _bind_jobs_for_run(legacy_061_10_jobs, run_id=804),
            ),
            805: (
                _make_run_meta(
                    805,
                    conclusion="failure",
                    display_title=f"RS9 {PROJECT} 0.7.0 resume / pre-upload-fail",
                ),
                _bind_jobs_for_run(
                    resume_070_upload_skipped_10_jobs, run_id=805
                ),
            ),
            806: (
                _make_run_meta(
                    806,
                    conclusion="timed_out",
                    display_title=f"RS9 {PROJECT} 0.7.0 qualify / matrix-timeout-806",
                ),
                _bind_jobs_for_run(
                    [
                        (
                            {**j, "conclusion": "timed_out"}
                            if j["name"] == "Qualification matrix gate 0.7.0"
                            else dict(j)
                        )
                        for j in qualify_10_matrix_failed
                    ],
                    run_id=806,
                ),
            ),
            807: (
                _make_run_meta(
                    807,
                    conclusion="success",
                    display_title=f"RS9 {PROJECT} 0.6.1 qualify / q061-807",
                ),
                _bind_jobs_for_run(legacy_061_qualify_10_jobs, run_id=807),
            ),
            808: (
                _make_run_meta(
                    808,
                    conclusion="failure",
                    display_title=f"RS9 {PROJECT} 0.7.0 qualify / matrix-failure-808",
                ),
                _bind_jobs_for_run(qualify_10_matrix_failed, run_id=808),
            ),
            809: (
                _make_run_meta(
                    809,
                    conclusion="success",
                    run_attempt=2,
                    display_title=f"RS9 {PROJECT} 0.7.0 qualify / rerun-qualify-809",
                ),
                _bind_jobs_for_run(
                    qualify_10_build_failed, run_id=809, run_attempt=1
                )
                + _bind_jobs_for_run(
                    qualify_10_all_success, run_id=809, run_attempt=2
                ),
            ),
            810: (
                _make_run_meta(
                    810,
                    conclusion="success",
                    display_title=f"RS9 {PROJECT} 0.7.0 qualify / ",
                ),
                _bind_jobs_for_run(qualify_10_all_success, run_id=810),
            ),
            811: (
                _make_run_meta(
                    811,
                    conclusion="success",
                    display_title=f"RS9 {PROJECT} 0.7.0 qualify /",
                ),
                _bind_jobs_for_run(qualify_10_all_success, run_id=811),
            ),
            900: (
                _make_run_meta(
                    900,
                    status="in_progress",
                    conclusion=None,
                    display_title=f"RS9 {PROJECT} 0.7.0 resume / active-current-run",
                ),
                [],
            ),
        }

        def _api_qualify_ok(url: str) -> dict:
            if "actions/workflows/" in url:
                return {
                    "total_count": len(positive_runs_spec),
                    "workflow_runs": [
                        positive_runs_spec[rid][0]
                        for rid in sorted(positive_runs_spec)
                    ],
                }
            for rid, (_rmeta, r_jobs) in positive_runs_spec.items():
                if rid != 900 and f"/runs/{rid}/jobs" in url:
                    return {"total_count": len(r_jobs), "jobs": r_jobs}
            raise AssertionError(url)

        check_prior_publish_runs(
            api_get=_api_qualify_ok, environ={"GITHUB_RUN_ID": "900"}
        )
        upload_after_qual = self.root / "upload_after_qual"
        res_qual = select_missing(
            self.dist_dir,
            upload_after_qual,
            candidate_receipt=self.candidate_receipt_path,
            expected_artifacts=self.expected_artifacts_path,
            receipts_dir=self.receipts_dir,
            approval=self.base_approval,
            pin=self.base_pin,
            get=lambda _u: canonical(
                {"info": {"name": PROJECT}, "releases": {"0.6.1": []}}
            ),
            api_get=_api_qualify_ok,
            environ={"GITHUB_RUN_ID": "900"},
        )
        self.assertTrue(res_qual["upload"])
        self.assertEqual(len(res_qual["missing"]), 3)

        # 2. Negative cases that MUST fail closed with TF_PYPI_PRIOR_ATTEMPT_UNCONFIRMED (tested via both check_prior_publish_runs and select_missing):
        partial_qual_jobs = qualify_5_jobs[:-1] + skipped_non_qualify_jobs
        missing_non_qual_job = qualify_5_jobs + skipped_non_qualify_jobs[:-1]
        duplicate_job_names = qualify_10_all_success + [
            dict(skipped_non_qualify_jobs[0])
        ]
        in_progress_qual_jobs = copy.deepcopy(qualify_10_all_success)
        in_progress_qual_jobs[0]["status"] = "in_progress"
        in_progress_qual_jobs[0]["conclusion"] = None
        null_status_qual_jobs = copy.deepcopy(qualify_10_all_success)
        null_status_qual_jobs[0]["status"] = None
        unknown_conc_qual_jobs = copy.deepcopy(qualify_10_all_success)
        unknown_conc_qual_jobs[0]["conclusion"] = "neutral"
        contradictory_skipped_step_jobs = copy.deepcopy(qualify_10_all_success)
        for j_entry in contradictory_skipped_step_jobs:
            if j_entry["name"] == "Trusted Publishing to PyPI":
                j_entry["steps"] = [
                    {
                        "name": "Publish package distribution to PyPI",
                        "status": "completed",
                        "conclusion": "success",
                    }
                ]
        dag_build_failed_but_native_ran = [
            {
                "name": name,
                "status": "completed",
                "conclusion": (
                    "failure"
                    if name == "Build and Verify Nebular 0.7.0 Candidate Bundle"
                    else (
                        "success"
                        if name == "Native consumer 0.7.0 (darwin-arm64)"
                        else "skipped"
                    )
                ),
                "steps": [],
            }
            for name in sorted(QUALIFY_070_JOB_NAMES)
        ] + skipped_non_qualify_jobs
        dag_native_failed_but_matrix_ran = [
            {
                "name": name,
                "status": "completed",
                "conclusion": (
                    "failure"
                    if name == "Native consumer 0.7.0 (linux-x64-gnu)"
                    else "success"
                ),
                "steps": [],
            }
            for name in sorted(QUALIFY_070_JOB_NAMES)
        ] + skipped_non_qualify_jobs
        dag_build_ok_but_native_skipped = [
            {
                "name": name,
                "status": "completed",
                "conclusion": (
                    "skipped"
                    if name in (
                        "Native consumer 0.7.0 (darwin-arm64)",
                        "Qualification matrix gate 0.7.0",
                    )
                    else "success"
                ),
                "steps": [],
            }
            for name in sorted(QUALIFY_070_JOB_NAMES)
        ] + skipped_non_qualify_jobs
        dag_natives_ok_but_matrix_skipped = [
            {
                "name": name,
                "status": "completed",
                "conclusion": (
                    "skipped"
                    if name == "Qualification matrix gate 0.7.0"
                    else "success"
                ),
                "steps": [],
            }
            for name in sorted(QUALIFY_070_JOB_NAMES)
        ] + skipped_non_qualify_jobs
        mixed_active_jobs = qualify_5_jobs + [
            {
                "name": "Trusted Publishing to PyPI",
                "status": "completed",
                "conclusion": "success",
                "steps": [],
            }
        ] + skipped_non_qualify_jobs[:-1]
        unknown_job_list = qualify_5_jobs[:-1] + [
            {
                "name": "Unknown rogue job",
                "status": "completed",
                "conclusion": "success",
                "steps": [],
            }
        ] + skipped_non_qualify_jobs
        all_skipped_jobs = [
            {
                "name": name,
                "status": "completed",
                "conclusion": "skipped",
                "steps": [],
            }
            for name in sorted(QUALIFY_070_JOB_NAMES)
        ] + skipped_non_qualify_jobs
        resume_missing_steps = copy.deepcopy(resume_070_upload_skipped_10_jobs)
        for j_entry in resume_missing_steps:
            if j_entry["name"] == "Attended Nebular 0.7.0 PyPI publication resume":
                j_entry["steps"] = []
        resume_job_in_progress = copy.deepcopy(resume_070_upload_skipped_10_jobs)
        for j_entry in resume_job_in_progress:
            if j_entry["name"] == "Attended Nebular 0.7.0 PyPI publication resume":
                j_entry["status"] = "in_progress"
                j_entry["conclusion"] = None
        resume_step_in_progress = copy.deepcopy(resume_070_upload_skipped_10_jobs)
        for j_entry in resume_step_in_progress:
            if j_entry["name"] == "Attended Nebular 0.7.0 PyPI publication resume":
                j_entry["steps"] = [
                    {
                        "name": "Publish package distribution to PyPI",
                        "status": "in_progress",
                        "conclusion": None,
                    }
                ]
        resume_step_null_status_skipped = copy.deepcopy(
            resume_070_upload_skipped_10_jobs
        )
        for j_entry in resume_step_null_status_skipped:
            if j_entry["name"] == "Attended Nebular 0.7.0 PyPI publication resume":
                j_entry["steps"] = [
                    {
                        "name": "Publish package distribution to PyPI",
                        "status": None,
                        "conclusion": "skipped",
                    }
                ]
        resume_step_failed = copy.deepcopy(resume_070_upload_skipped_10_jobs)
        for j_entry in resume_step_failed:
            if j_entry["name"] == "Attended Nebular 0.7.0 PyPI publication resume":
                j_entry["steps"] = [
                    {
                        "name": "Publish package distribution to PyPI",
                        "status": "completed",
                        "conclusion": "failure",
                    }
                ]
        resume_upload_ran = copy.deepcopy(resume_070_upload_skipped_10_jobs)
        for j_entry in resume_upload_ran:
            if j_entry["name"] == "Attended Nebular 0.7.0 PyPI publication resume":
                j_entry["conclusion"] = "success"
                j_entry["steps"] = [
                    {
                        "name": "Publish package distribution to PyPI",
                        "status": "completed",
                        "conclusion": "success",
                    }
                ]

        negative_cases: list[tuple[str, dict, list[dict]]] = [
            (
                "partial-qualify-4-of-5",
                _make_run_meta(850),
                partial_qual_jobs,
            ),
            (
                "missing-non-qualify-job",
                _make_run_meta(850),
                missing_non_qual_job,
            ),
            (
                "duplicate-job-name",
                _make_run_meta(850),
                duplicate_job_names,
            ),
            (
                "incomplete-qualify-in-progress",
                _make_run_meta(850),
                in_progress_qual_jobs,
            ),
            (
                "job-status-none",
                _make_run_meta(850),
                null_status_qual_jobs,
            ),
            (
                "job-unknown-conclusion",
                _make_run_meta(850),
                unknown_conc_qual_jobs,
            ),
            (
                "contradictory-active-step-in-skipped-job",
                _make_run_meta(850),
                contradictory_skipped_step_jobs,
            ),
            (
                "dag-build-failed-but-native-ran",
                _make_run_meta(850, conclusion="failure"),
                dag_build_failed_but_native_ran,
            ),
            (
                "dag-native-failed-but-matrix-ran",
                _make_run_meta(850, conclusion="failure"),
                dag_native_failed_but_matrix_ran,
            ),
            (
                "dag-build-ok-but-native-skipped",
                _make_run_meta(850, conclusion="failure"),
                dag_build_ok_but_native_skipped,
            ),
            (
                "dag-natives-ok-but-matrix-skipped",
                _make_run_meta(850, conclusion="failure"),
                dag_natives_ok_but_matrix_skipped,
            ),
            (
                "dag-matrix-ok-but-run-failed",
                _make_run_meta(850, conclusion="failure"),
                qualify_10_all_success,
            ),
            (
                "mixed-070-qualify-and-061-publish",
                _make_run_meta(850),
                mixed_active_jobs,
            ),
            (
                "unknown-job-name",
                _make_run_meta(850),
                unknown_job_list,
            ),
            (
                "all-jobs-skipped",
                _make_run_meta(850),
                all_skipped_jobs,
            ),
            (
                "resume-missing-steps",
                _make_run_meta(
                    850,
                    conclusion="failure",
                    display_title=f"RS9 {PROJECT} 0.7.0 resume / r-850",
                ),
                resume_missing_steps,
            ),
            (
                "resume-job-in-progress",
                _make_run_meta(
                    850,
                    conclusion="failure",
                    display_title=f"RS9 {PROJECT} 0.7.0 resume / r-850",
                ),
                resume_job_in_progress,
            ),
            (
                "resume-step-in-progress",
                _make_run_meta(
                    850,
                    conclusion="failure",
                    display_title=f"RS9 {PROJECT} 0.7.0 resume / r-850",
                ),
                resume_step_in_progress,
            ),
            (
                "resume-step-null-status-with-skipped-conclusion",
                _make_run_meta(
                    850,
                    conclusion="failure",
                    display_title=f"RS9 {PROJECT} 0.7.0 resume / r-850",
                ),
                resume_step_null_status_skipped,
            ),
            (
                "resume-step-failed",
                _make_run_meta(
                    850,
                    conclusion="failure",
                    display_title=f"RS9 {PROJECT} 0.7.0 resume / r-850",
                ),
                resume_step_failed,
            ),
            (
                "resume-upload-succeeded",
                _make_run_meta(
                    850,
                    conclusion="success",
                    display_title=f"RS9 {PROJECT} 0.7.0 resume / r-850",
                ),
                resume_upload_ran,
            ),
            (
                "resume-prior-run-attempt-2",
                _make_run_meta(
                    850,
                    conclusion="failure",
                    run_attempt=2,
                    display_title=f"RS9 {PROJECT} 0.7.0 resume / r-850",
                ),
                _bind_jobs_for_run(
                    resume_070_upload_skipped_10_jobs,
                    run_id=850,
                    run_attempt=1,
                )
                + _bind_jobs_for_run(
                    resume_070_upload_skipped_10_jobs,
                    run_id=850,
                    run_attempt=2,
                ),
            ),
            (
                "run-status-none",
                _make_run_meta(850, status=None),
                qualify_10_all_success,
            ),
            (
                "run-status-in-progress",
                _make_run_meta(850, status="in_progress"),
                qualify_10_all_success,
            ),
            (
                "run-conclusion-unknown",
                _make_run_meta(850, conclusion="neutral"),
                qualify_10_all_success,
            ),
            (
                "run-wrong-event",
                _make_run_meta(850, event="push"),
                qualify_10_all_success,
            ),
            (
                "run-wrong-branch",
                _make_run_meta(850, head_branch="feature"),
                qualify_10_all_success,
            ),
            (
                "run-wrong-sha",
                _make_run_meta(850, head_sha="not-a-sha"),
                qualify_10_all_success,
            ),
            (
                "run-wrong-workflow-path",
                _make_run_meta(850, path=".github/workflows/other.yml"),
                qualify_10_all_success,
            ),
            (
                "run-wrong-workflow-path-ref",
                _make_run_meta(
                    850, path=f".github/workflows/{WORKFLOW}@refs/heads/dev"
                ),
                qualify_10_all_success,
            ),
            (
                "run-wrong-repository-body",
                _make_run_meta(850, repo_full_name="Other-Org/other-repo"),
                qualify_10_all_success,
            ),
            (
                "run-blank-inputs-mapping",
                _make_run_meta(850, inputs={}),
                qualify_10_all_success,
            ),
            (
                "run-contradictory-inputs-mode",
                _make_run_meta(
                    850, inputs={"release": "0.7.0", "mode": "resume"}
                ),
                qualify_10_all_success,
            ),
            (
                "run-title-mode-mismatch-job-shape",
                _make_run_meta(
                    850,
                    display_title=f"RS9 {PROJECT} 0.7.0 resume / q-jobs",
                    conclusion="failure",
                ),
                qualify_10_build_failed,
            ),
            (
                "run-unanchored-title",
                _make_run_meta(850, display_title="Nebular workflow run 850"),
                qualify_10_all_success,
            ),
        ]

        for idx_case, (label, bad_run_meta, raw_bad_jobs) in enumerate(negative_cases):
            with self.subTest(case=label):
                eff_attempt = (
                    bad_run_meta["run_attempt"]
                    if isinstance(bad_run_meta.get("run_attempt"), int)
                    and bad_run_meta["run_attempt"] >= 1
                    else 1
                )
                bad_jobs = _bind_jobs_for_run(
                    raw_bad_jobs,
                    run_id=bad_run_meta["id"],
                    run_attempt=eff_attempt,
                    head_sha=(
                        bad_run_meta["head_sha"]
                        if isinstance(bad_run_meta.get("head_sha"), str)
                        else QUALIFICATION_COMMIT
                    ),
                    fill_profiles=label != "resume-missing-steps",
                )

                def _api_bad(
                    url: str,
                    run_payload=bad_run_meta,
                    jobs_payload=bad_jobs,
                ) -> dict:
                    if "actions/workflows/" in url:
                        return {
                            "total_count": 1,
                            "workflow_runs": [run_payload],
                        }
                    if f"/runs/{run_payload['id']}/jobs" in url:
                        return {
                            "total_count": len(jobs_payload),
                            "jobs": jobs_payload,
                        }
                    raise AssertionError(url)

                with self.assertRaises(AdmissionError) as ctx_bad:
                    check_prior_publish_runs(
                        api_get=_api_bad, environ={"GITHUB_RUN_ID": "900"}
                    )
                self.assertEqual(
                    ctx_bad.exception.code, "TF_PYPI_PRIOR_ATTEMPT_UNCONFIRMED"
                )

                with self.assertRaises(AdmissionError) as ctx_sm_bad:
                    select_missing(
                        self.dist_dir,
                        self.root / f"upload_neg_{idx_case}",
                        candidate_receipt=self.candidate_receipt_path,
                        expected_artifacts=self.expected_artifacts_path,
                        receipts_dir=self.receipts_dir,
                        approval=self.base_approval,
                        pin=self.base_pin,
                        get=lambda _u: canonical(
                            {"info": {"name": PROJECT}, "releases": {"0.6.1": []}}
                        ),
                        api_get=_api_bad,
                        environ={"GITHUB_RUN_ID": "900"},
                    )
                self.assertEqual(
                    ctx_sm_bad.exception.code,
                    "TF_PYPI_PRIOR_ATTEMPT_UNCONFIRMED",
                )

        # 3. Additional env, workflow_id consistency, pagination, and handoff relative-path binding checks
        def _api_inconsistent_wf_id(url: str) -> dict:
            if "actions/workflows/" in url:
                return {
                    "total_count": 2,
                    "workflow_runs": [
                        _make_run_meta(801, workflow_id=7001),
                        _make_run_meta(802, workflow_id=7002),
                    ],
                }
            if "/runs/801/jobs" in url:
                bound_801 = _bind_jobs_for_run(
                    qualify_10_all_success, run_id=801
                )
                return {
                    "total_count": len(bound_801),
                    "jobs": bound_801,
                }
            raise AssertionError(url)

        with self.assertRaises(AdmissionError) as ctx_wf_id:
            check_prior_publish_runs(
                api_get=_api_inconsistent_wf_id, environ={"GITHUB_RUN_ID": "900"}
            )
        self.assertEqual(
            ctx_wf_id.exception.code, "TF_PYPI_PRIOR_ATTEMPT_UNCONFIRMED"
        )

        for bad_env in (
            {"GITHUB_REPOSITORY": "Other-Org/release-starport-9", "GITHUB_RUN_ID": "900"},
            {"GITHUB_RUN_ID": "not-an-int"},
            {"GITHUB_ACTIONS": "true"},
            {"RS9_TFNF_PRIOR_UPLOAD_UNCONFIRMED": "1", "GITHUB_RUN_ID": "900"},
        ):
            with self.assertRaises(AdmissionError) as ctx_env_bad:
                check_prior_publish_runs(api_get=_api_qualify_ok, environ=bad_env)
            self.assertEqual(
                ctx_env_bad.exception.code, "TF_PYPI_PRIOR_ATTEMPT_UNCONFIRMED"
            )

    def test_r5_prior_run_attempts_job_bindings_and_envelope_negatives(self) -> None:
        qualify_10_all_success = [
            {
                "name": name,
                "status": "completed",
                "conclusion": (
                    "success" if name in QUALIFY_070_JOB_NAMES else "skipped"
                ),
                "steps": [],
            }
            for name in sorted(ALL_KNOWN_WORKFLOW_JOB_NAMES)
        ]
        guard_only_failed_10 = [
            {
                "name": name,
                "status": "completed",
                "conclusion": (
                    "failure"
                    if name == DISPATCH_GUARD_070_JOB_NAME
                    else "skipped"
                ),
                "steps": [],
            }
            for name in sorted(ALL_KNOWN_WORKFLOW_JOB_NAMES)
        ]

        def _bind_jobs(
            raw_jobs: list[dict],
            *,
            run_id: int = 860,
            run_attempt: int = 1,
            head_sha: str = QUALIFICATION_COMMIT,
            id_base: int | None = None,
            fill_profiles: bool = True,
        ) -> list[dict]:
            base = (
                id_base
                if id_base is not None
                else (run_id * 1000 + run_attempt * 100)
            )
            source_jobs = (
                _fill_current_profile_steps(raw_jobs)
                if fill_profiles
                else copy.deepcopy(raw_jobs)
            )
            return [
                {
                    "id": base + idx,
                    "run_id": run_id,
                    "run_attempt": run_attempt,
                    "head_sha": head_sha,
                    **copy.deepcopy(j),
                }
                for idx, j in enumerate(source_jobs, start=1)
            ]

        def _run_meta(
            rid: int = 860,
            *,
            workflow_id: Any = 7001,
            run_attempt: Any = 1,
            conclusion: str = "success",
            display_title: str = f"RS9 {PROJECT} 0.7.0 qualify / q-860",
            head_repo: str = DEFAULT_GITHUB_REPOSITORY,
        ) -> dict:
            meta: dict = {
                "id": rid,
                "path": f".github/workflows/{WORKFLOW}",
                "event": "workflow_dispatch",
                "head_branch": "main",
                "head_sha": QUALIFICATION_COMMIT,
                "status": "completed",
                "conclusion": conclusion,
                "display_title": display_title,
                "repository": {"full_name": DEFAULT_GITHUB_REPOSITORY},
                "head_repository": {"full_name": head_repo},
            }
            if workflow_id is not ...:
                meta["workflow_id"] = workflow_id
            if run_attempt is not ...:
                meta["run_attempt"] = run_attempt
            return meta

        base_bound_jobs = _bind_jobs(qualify_10_all_success)

        jobs_missing_id = copy.deepcopy(base_bound_jobs)
        jobs_missing_id[0].pop("id", None)

        jobs_zero_id = copy.deepcopy(base_bound_jobs)
        jobs_zero_id[0]["id"] = 0

        jobs_dup_id = copy.deepcopy(base_bound_jobs)
        jobs_dup_id[1]["id"] = jobs_dup_id[0]["id"]

        jobs_wrong_run_id = copy.deepcopy(base_bound_jobs)
        jobs_wrong_run_id[0]["run_id"] = 999999

        jobs_wrong_attempt = copy.deepcopy(base_bound_jobs)
        jobs_wrong_attempt[0]["run_attempt"] = 2

        jobs_missing_attempt = copy.deepcopy(base_bound_jobs)
        jobs_missing_attempt[0].pop("run_attempt", None)

        jobs_wrong_sha = copy.deepcopy(base_bound_jobs)
        jobs_wrong_sha[0]["head_sha"] = "a" * 40

        jobs_missing_sha = copy.deepcopy(base_bound_jobs)
        jobs_missing_sha[0].pop("head_sha", None)

        bad_attempt_1_active_publish = copy.deepcopy(qualify_10_all_success)
        for j in bad_attempt_1_active_publish:
            if j["name"] == "Trusted Publishing to PyPI":
                j["conclusion"] = "success"

        envelope_and_binding_cases: list[tuple[str, list[dict], list[dict]]] = [
            (
                "run-attempt-zero",
                [_run_meta(run_attempt=0)],
                base_bound_jobs,
            ),
            (
                "run-attempt-missing",
                [_run_meta(run_attempt=...)],
                base_bound_jobs,
            ),
            (
                "workflow-id-missing",
                [_run_meta(workflow_id=...)],
                base_bound_jobs,
            ),
            (
                "workflow-id-zero",
                [_run_meta(workflow_id=0)],
                base_bound_jobs,
            ),
            (
                "workflow-id-negative",
                [_run_meta(workflow_id=-5)],
                base_bound_jobs,
            ),
            (
                "duplicate-run-ids",
                [_run_meta(rid=860), _run_meta(rid=860)],
                base_bound_jobs,
            ),
            (
                "wrong-head-repository",
                [_run_meta(head_repo="Other-Org/fork-repo")],
                base_bound_jobs,
            ),
            (
                "061-title-with-active-070-jobs",
                [
                    _run_meta(
                        display_title=f"RS9 {PROJECT} 0.6.1 publish / pub-860"
                    )
                ],
                base_bound_jobs,
            ),
            (
                "061-static-title-with-active-070-jobs",
                [_run_meta(display_title=f"RS9 {PROJECT} PyPI Publish")],
                base_bound_jobs,
            ),
            (
                "guarded-misdispatch-070-publish",
                [
                    _run_meta(
                        conclusion="failure",
                        display_title=f"RS9 {PROJECT} 0.7.0 publish / mis-860",
                    )
                ],
                _bind_jobs(guard_only_failed_10),
            ),
            (
                "guarded-misdispatch-061-resume",
                [
                    _run_meta(
                        conclusion="failure",
                        display_title=f"RS9 {PROJECT} 0.6.1 resume / mis-860",
                    )
                ],
                _bind_jobs(guard_only_failed_10),
            ),
            (
                "title-leading-whitespace",
                [
                    _run_meta(
                        display_title=f" RS9 {PROJECT} 0.7.0 qualify / q-860"
                    )
                ],
                base_bound_jobs,
            ),
            (
                "title-extra-trailing-whitespace",
                [
                    _run_meta(
                        display_title=f"RS9 {PROJECT} 0.7.0 qualify / q-860 "
                    )
                ],
                base_bound_jobs,
            ),
            (
                "title-double-space-empty-dispatch-id",
                [_run_meta(display_title=f"RS9 {PROJECT} 0.7.0 qualify /  ")],
                base_bound_jobs,
            ),
            (
                "job-id-missing",
                [_run_meta()],
                jobs_missing_id,
            ),
            (
                "job-id-zero",
                [_run_meta()],
                jobs_zero_id,
            ),
            (
                "job-id-duplicate",
                [_run_meta()],
                jobs_dup_id,
            ),
            (
                "job-run-id-mismatch",
                [_run_meta()],
                jobs_wrong_run_id,
            ),
            (
                "job-run-attempt-mismatch",
                [_run_meta()],
                jobs_wrong_attempt,
            ),
            (
                "job-run-attempt-missing",
                [_run_meta()],
                jobs_missing_attempt,
            ),
            (
                "job-head-sha-mismatch",
                [_run_meta()],
                jobs_wrong_sha,
            ),
            (
                "job-head-sha-missing",
                [_run_meta()],
                jobs_missing_sha,
            ),
            (
                "qualify-attempt-2-missing-attempt-1-jobs",
                [_run_meta(run_attempt=2)],
                _bind_jobs(qualify_10_all_success, run_attempt=2),
            ),
            (
                "qualify-attempt-2-bad-attempt-1-profile",
                [_run_meta(run_attempt=2)],
                _bind_jobs(bad_attempt_1_active_publish, run_attempt=1)
                + _bind_jobs(qualify_10_all_success, run_attempt=2),
            ),
        ]

        for idx, (label, runs_list, jobs_list) in enumerate(
            envelope_and_binding_cases
        ):
            with self.subTest(case=label):

                def _api_neg(
                    url: str,
                    r_list=runs_list,
                    j_list=jobs_list,
                ) -> dict:
                    if "actions/workflows/" in url:
                        return {
                            "total_count": len(r_list),
                            "workflow_runs": r_list,
                        }
                    if "/runs/860/jobs" in url:
                        return {
                            "total_count": len(j_list),
                            "jobs": j_list,
                        }
                    raise AssertionError(url)

                with self.assertRaises(AdmissionError) as ctx_cp:
                    check_prior_publish_runs(
                        api_get=_api_neg, environ={"GITHUB_RUN_ID": "900"}
                    )
                self.assertEqual(
                    ctx_cp.exception.code, "TF_PYPI_PRIOR_ATTEMPT_UNCONFIRMED"
                )

                with self.assertRaises(AdmissionError) as ctx_sm:
                    select_missing(
                        self.dist_dir,
                        self.root / f"upload_r5_{idx}",
                        candidate_receipt=self.candidate_receipt_path,
                        expected_artifacts=self.expected_artifacts_path,
                        receipts_dir=self.receipts_dir,
                        approval=self.base_approval,
                        pin=self.base_pin,
                        get=lambda _u: canonical(
                            {"info": {"name": PROJECT}, "releases": {"0.6.1": []}}
                        ),
                        api_get=_api_neg,
                        environ={"GITHUB_RUN_ID": "900"},
                    )
                self.assertEqual(
                    ctx_sm.exception.code, "TF_PYPI_PRIOR_ATTEMPT_UNCONFIRMED"
                )

    def test_prior_step_profiles_match_generated_jobs_and_reject_unknown_active_steps(
        self,
    ) -> None:
        def _generated_steps(
            text: str,
        ) -> dict[str, tuple[tuple[str, bool], ...]]:
            result: dict[str, list[tuple[str, bool]]] = {}
            current_key: str | None = None
            current_name: str | None = None
            pending_step_name: str | None = None
            for line in text.splitlines():
                if (
                    line.startswith("  ")
                    and not line.startswith("    ")
                    and line.rstrip().endswith(":")
                ):
                    self.assertIsNone(pending_step_name)
                    current_key = line.strip()[:-1]
                    current_name = None
                    continue
                if current_key is not None and line.startswith("    name: "):
                    self.assertIsNone(pending_step_name)
                    current_name = line[len("    name: ") :].strip().strip("'\"")
                    result[current_name] = []
                    continue
                if current_name is not None and line.startswith("      - name: "):
                    self.assertIsNone(pending_step_name)
                    pending_step_name = (
                        line[len("      - name: ") :].strip().strip("'\"")
                    )
                    continue
                if pending_step_name is not None and line.startswith("        uses: "):
                    result[current_name].append((pending_step_name, True))
                    pending_step_name = None
                    continue
                if pending_step_name is not None and (
                    line.startswith("        run: ") or line == "        run: |"
                ):
                    result[current_name].append((pending_step_name, False))
                    pending_step_name = None
            self.assertIsNone(pending_step_name)
            return {name: tuple(steps) for name, steps in result.items()}

        generated_current = _generated_steps(workflow_070_jobs_text())
        self.assertEqual(set(generated_current), CURRENT_070_PROFILE_JOB_NAMES)
        for job_name in CURRENT_070_PROFILE_JOB_NAMES:
            self.assertEqual(
                generated_current[job_name],
                WORKFLOW_STEP_PROFILES[job_name],
            )

        generated_combined = _generated_steps(workflow_text("0.6.1"))
        for job_name in LEGACY_061_JOB_NAMES:
            self.assertEqual(
                generated_combined[job_name],
                WORKFLOW_STEP_PROFILES[job_name],
            )

        def _job(
            job_name: str,
            *,
            conclusion: str = "success",
            steps: list[dict] | None = None,
        ) -> dict:
            record = {
                "id": 1,
                "run_id": 2,
                "run_attempt": 1,
                "head_sha": "a" * 40,
                "name": job_name,
                "status": "completed",
                "conclusion": conclusion,
            }
            if steps is not None:
                record["steps"] = steps
            return record

        def _step(name: str, conclusion: str = "success") -> dict:
            return {
                "name": name,
                "status": "completed",
                "conclusion": conclusion,
            }

        # Known generated steps plus runner-owned and declared-action post steps pass.
        _validate_prior_run_jobs_map(
            [
                _job(
                    BUILD_VERIFY_070_JOB_NAME,
                    steps=[
                        _step("Set up job"),
                        _step("Checkout repository"),
                        _step("Post Checkout repository"),
                        _step("Complete job"),
                    ],
                )
            ],
            run_id=2,
            run_attempt=1,
            head_sha="a" * 40,
        )
        # Historical 0.6.1 records may omit or empty steps, or carry their
        # maintained profile names; supplied active names are checked.
        _validate_prior_run_jobs_map(
            [_job(LEGACY_061_BUILD_JOB_NAME, steps=None)],
            run_id=2,
            run_attempt=1,
            head_sha="a" * 40,
        )
        _validate_prior_run_jobs_map(
            [_job(LEGACY_061_BUILD_JOB_NAME, steps=[])],
            run_id=2,
            run_attempt=1,
            head_sha="a" * 40,
        )
        _validate_prior_run_jobs_map(
            [
                _job(
                    LEGACY_061_BUILD_JOB_NAME,
                    steps=[
                        _step("Set up job"),
                        *[
                            _step(step_name)
                            for step_name, _is_action in WORKFLOW_STEP_PROFILES[
                                LEGACY_061_BUILD_JOB_NAME
                            ]
                        ],
                        _step("Post Checkout repository"),
                        _step("Complete job"),
                    ],
                )
            ],
            run_id=2,
            run_attempt=1,
            head_sha="a" * 40,
        )
        # Skipped current jobs may omit or empty steps, and a skipped unknown
        # step is explicitly unexecuted and safe to retain.
        _validate_prior_run_jobs_map(
            [
                _job(
                    BUILD_VERIFY_070_JOB_NAME,
                    conclusion="skipped",
                    steps=None,
                )
            ],
            run_id=2,
            run_attempt=1,
            head_sha="a" * 40,
        )
        _validate_prior_run_jobs_map(
            [
                _job(
                    BUILD_VERIFY_070_JOB_NAME,
                    conclusion="skipped",
                    steps=[],
                )
            ],
            run_id=2,
            run_attempt=1,
            head_sha="a" * 40,
        )
        _validate_prior_run_jobs_map(
            [
                _job(
                    BUILD_VERIFY_070_JOB_NAME,
                    conclusion="skipped",
                    steps=[_step("Unknown historical step", "skipped")],
                )
            ],
            run_id=2,
            run_attempt=1,
            head_sha="a" * 40,
        )

        for job_name, steps in (
            (
                BUILD_VERIFY_070_JOB_NAME,
                [_step("Upload package distribution to PyPI")],
            ),
            (
                RESUME_070_JOB_NAME,
                [_step("Upload package distribution to PyPI")],
            ),
            (
                LEGACY_061_BUILD_JOB_NAME,
                [_step("Upload package distribution to PyPI")],
            ),
            (
                BUILD_VERIFY_070_JOB_NAME,
                [_step("Post Build and verify 0.7.0 candidate bundle")],
            ),
            (
                BUILD_VERIFY_070_JOB_NAME,
                None,
            ),
            (
                BUILD_VERIFY_070_JOB_NAME,
                [],
            ),
        ):
            with self.subTest(job=job_name, steps=steps):
                with self.assertRaises(AdmissionError) as ctx:
                    _validate_prior_run_jobs_map(
                        [_job(job_name, steps=steps)],
                        run_id=2,
                        run_attempt=1,
                        head_sha="a" * 40,
                    )
                self.assertEqual(
                    ctx.exception.code,
                    "TF_PYPI_PRIOR_ATTEMPT_UNCONFIRMED",
                )


if __name__ == "__main__":
    unittest.main()
