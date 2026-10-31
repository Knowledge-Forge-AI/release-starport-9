"""End-to-end synthetic chain tests for the 0.7.1 universal owner repair (R1-R4).

Exercises the real producer (`prepare_public_inputs_071`), bundle builder
(`build_bundle`), native handoff/consumer (`qualify_native`,
`materialize_universal_handoff`, `capture_universal_runtime`,
`consume_universal_wheel`, `_nebular_installed_consumer`,
`materialize_smoke_support`), matrix readback (`read_matrix_inputs`), and
8-artifact publication capture verifier (`publication.verify_capture`) using
inert synthetic fixtures only. No network, native execution, Git mutations, or
publication admission are performed or claimed.
"""
from __future__ import annotations

import copy
import hashlib
import io
import json
import os
from pathlib import Path
import shlex
import shutil
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
import zipfile


_CANDIDATE = Path(__file__).resolve().parents[1]
tempfile.tempdir = str(Path(tempfile.gettempdir()).resolve())
sys.path.insert(0, str(_CANDIDATE / "src"))
sys.path.insert(0, str(_CANDIDATE / "tests"))
import rs9  # noqa: E402

from rs9 import nebular071_consumer_core as consumer_core  # noqa: E402
from rs9 import nebular071_product_capture as product_capture_mod  # noqa: E402
from rs9 import nebular071_public_inputs as public_inputs  # noqa: E402
from rs9 import nebular071_smoke_support as smoke_support  # noqa: E402
from rs9 import nebular071_universal_consumer as consumer  # noqa: E402
from rs9 import nebular071_universal_profile as profile  # noqa: E402
from rs9 import nebular071_universal_publication as publication  # noqa: E402
from rs9 import nebular071_universal_workflow as workflow  # noqa: E402
from rs9 import tf_pypi_nebular071_publish as publisher  # noqa: E402
from rs9 import tf_pypi_nebular071_universal as universal  # noqa: E402
from rs9 import wheel_nebular071_universal as wheel_builder  # noqa: E402
from rs9.archives import inspect_archive  # noqa: E402
from rs9.errors import ContractError  # noqa: E402
from rs9.release_core import capture_release  # noqa: E402
from rs9.scratch import canonical  # noqa: E402
from rs9.tf_pypi_archive import AdmissionError  # noqa: E402


class _SandboxStopSentinel(Exception):
    """Raised at the network_denial seam after materialize_smoke_support."""


def _generated_command(document: str, marker: str) -> list[str]:
    lines = document.splitlines()
    for index, line in enumerate(lines):
        if marker not in line:
            continue
        parts = []
        while index < len(lines):
            part = lines[index].strip()
            if not part:
                break
            continued = part.endswith("\\")
            parts.append(part[:-1].rstrip() if continued else part)
            if not continued:
                return shlex.split(" ".join(parts))
            index += 1
    raise AssertionError(f"rendered command not found: {marker}")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _git_blob(data: bytes) -> str:
    header = b"blob " + str(len(data)).encode("ascii") + b"\0"
    return hashlib.sha1(header + data).hexdigest()


def _payload_tar_bytes(target: str) -> bytes:
    if target == "darwin-arm64":
        root = "Theme Forge Nebular Fusion.app"
        directories = (
            root,
            f"{root}/Contents",
            f"{root}/Contents/Resources",
            f"{root}/Contents/Resources/bin",
            f"{root}/Contents/MacOS",
        )
        files = {
            f"{root}/Contents/Resources/bin/tfnf": f"#!/bin/sh\n# launcher {target}\nexit 0\n".encode("utf-8"),
            f"{root}/Contents/MacOS/theme-forge-nebular-fusion": f"#!/bin/sh\n# gui {target}\nexit 0\n".encode("utf-8"),
            f"{root}/Contents/MacOS/tfsb-studio-service": f"#!/bin/sh\n# sidecar {target}\nexit 0\n".encode("utf-8"),
        }
    else:
        root = "theme-forge-nebular-fusion"
        directories = (root, f"{root}/bin")
        files = {
            f"{root}/bin/tfnf": f"#!/bin/sh\n# launcher {target}\nexit 0\n".encode("utf-8"),
            f"{root}/bin/theme-forge-nebular-fusion": f"#!/bin/sh\n# gui {target}\nexit 0\n".encode("utf-8"),
            f"{root}/bin/tfsb-studio-service": f"#!/bin/sh\n# sidecar {target}\nexit 0\n".encode("utf-8"),
        }
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz", format=tarfile.USTAR_FORMAT) as archive:
        for name in directories:
            info = tarfile.TarInfo(name)
            info.type = tarfile.DIRTYPE
            info.mode = 0o755
            info.mtime = 0
            archive.addfile(info)
        for name, data in sorted(files.items()):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o755
            info.mtime = 0
            archive.addfile(info, io.BytesIO(data))
    return stream.getvalue()


def _build_source_archive_and_authority() -> tuple[bytes, bytes, list[dict], dict[str, bytes]]:
    paths = sorted(
        {f"tools/{name}" for name in smoke_support._REQUIRED_TOOLS}
        | set(smoke_support._REQUIRED_FIXTURES)
    )
    bodies = {path: ("071-chain-source:" + path + "\n").encode("utf-8") for path in paths}
    archive_stream = io.BytesIO()
    with tarfile.open(fileobj=archive_stream, mode="w:gz", format=tarfile.USTAR_FORMAT) as archive:
        for path in paths:
            info = tarfile.TarInfo(path)
            info.size = len(bodies[path])
            info.mode = 0o644
            info.mtime = 0
            archive.addfile(info, io.BytesIO(bodies[path]))
    archive_body = archive_stream.getvalue()
    inventory = [
        {
            "path": path,
            "bytes": len(bodies[path]),
            "mode": 0o644,
            "sha256": _sha(bodies[path]),
        }
        for path in paths
    ]
    composition = smoke_support._js_identity(inventory)
    authority_unsigned = {
        "schema": "nebular-public-build-source-v1",
        "version": "0.7.1",
        "composition": composition,
        "locks": {"cargo": "1" * 64, "frontend": "2" * 64},
        "components": {"burst": "3" * 64, "loom": "4" * 64, "solar": "5" * 64},
        "recipe": "6" * 64,
        "resourcePlans": {
            triple: {"resources": ["release-notices"], "externalBin": ["binaries/service"]}
            for triple in smoke_support._SOURCE_TRIPLES
        },
    }
    authority = {
        **authority_unsigned,
        "identity": smoke_support._js_identity(authority_unsigned),
    }
    authority_body = canonical(authority)
    source_files = [
        {
            "path": path,
            "size": len(bodies[path]),
            "sha256": _sha(bodies[path]),
            "blob": _git_blob(bodies[path]),
            "role": (
                "application-smoke"
                if path == "tools/native-rc-smoke.mjs"
                else "verifier-module"
                if path.startswith("tools/")
                else "fixture"
            ),
        }
        for path in paths
    ]
    return archive_body, authority_body, source_files, bodies


class _SyntheticGitHubClient:
    """In-memory read-only client serving both product-capture and public-inputs."""

    def __init__(self, api_map: dict[str, object], asset_map: dict[str, bytes]):
        self.api_map = dict(api_map)
        self.asset_map = dict(asset_map)
        self.receipts: list[dict[str, object]] = []
        self.get_calls: list[str] = []

    def json(self, url: str, *, request_class: str = "github-api", **_kwargs):
        if url not in self.api_map:
            raise AssertionError(f"unexpected json URL: {url}")
        value = copy.deepcopy(self.api_map[url])
        raw = canonical(value)
        self.receipts.append(
            {
                "url": url.split("?", 1)[0],
                "final_url": url.split("?", 1)[0],
                "status": 200,
                "operation": request_class,
                "size": len(raw),
                "sha256": _sha(raw),
                "collected_at": "2026-10-31T00:00:00+00:00",
            }
        )
        return value

    def get(self, url: str, *, request_class: str = "github-asset", **_kwargs) -> bytes:
        if url not in self.asset_map:
            raise AssertionError(f"unexpected get URL: {url}")
        self.get_calls.append(url)
        data = self.asset_map[url]
        self.receipts.append(
            {
                "url": url.split("?", 1)[0],
                "final_url": url.split("?", 1)[0],
                "status": 200,
                "operation": request_class,
                "size": len(data),
                "sha256": _sha(data),
                "collected_at": "2026-10-31T00:00:00+00:00",
            }
        )
        return data


def _build_complete_fixture(base_dir: Path) -> dict:
    """Build a complete, self-consistent synthetic 0.7.1 fixture in base_dir."""
    repo_name = "Knowledge-Forge-AI/theme-forge-nebular-fusion"
    repo_id = 42071
    release_id = 71071
    product_commit = "a" * 40
    product_tree = "b" * 40
    compiler_commit = "f" * 40  # testedCommit != releaseCommit, testedTree == tag.tree
    rs9_source = {"commit": "c" * 40, "tree": "d" * 40}
    run_id = "9101"

    scratch_setup = base_dir / "setup"
    scratch_setup.mkdir(parents=True, mode=0o700)

    payload_bytes_by_target: dict[str, bytes] = {}
    manifests_by_target: dict[str, dict] = {}
    manifest_bytes_by_target: dict[str, bytes] = {}
    payload_rows: list[dict] = []
    asset_map: dict[str, bytes] = {}
    api_assets: list[dict] = []

    for index, (target, triple) in enumerate(sorted(product_capture_mod.RAW_PAYLOAD_TRIPLES.items()), 1):
        name = f"theme-forge-nebular-fusion-v0.7.1-{triple}.tar.gz"
        body = _payload_tar_bytes(target)
        tmp_tar = scratch_setup / name
        tmp_tar.write_bytes(body)
        manifest = inspect_archive(tmp_tar, commands={})
        raw_manifest = canonical(manifest["members"])
        payload_bytes_by_target[target] = body
        manifests_by_target[target] = manifest
        manifest_bytes_by_target[target] = raw_manifest
        asset_id = 5000 + index
        dl_url = f"https://github.com/{repo_name}/releases/download/v0.7.1/{name}"
        api_url = f"https://api.github.com/repos/{repo_name}/releases/assets/{asset_id}"
        payload_rows.append(
            {
                "target": target,
                "triple": triple,
                "id": asset_id,
                "name": name,
                "bytes": len(body),
                "sha256": _sha(body),
                "url": dl_url,
                "api_url": api_url,
            }
        )
        asset_map[dl_url] = body
        asset_map[api_url] = body
        api_assets.append(
            {
                "id": asset_id,
                "name": name,
                "size": len(body),
                "state": "uploaded",
                "url": api_url,
                "browser_download_url": dl_url,
                "digest": "sha256:" + _sha(body),
            }
        )

    source_archive_body, source_authority_body, source_files, source_bodies = _build_source_archive_and_authority()
    provenance_doc = {
        "schema": "nebular.public-native-ci-release-provenance.v1",
        "repository": repo_name,
        "version": "0.7.1",
        "release": release_id,
        "releaseCommit": product_commit,
        "testedCommit": compiler_commit,
        "testedTree": product_tree,
        "nativeCiRun": 8101,
        "nativeCiAttempt": 1,
        "sourceCiRun": 8102,
        "assets": [
            {
                "id": row["id"],
                "name": row["name"],
                "role": "raw-archive",
                "bytes": row["bytes"],
                "sha256": row["sha256"],
                "url": row["url"],
                "httpStatus": 200,
                "unauthenticatedReadback": True,
            }
            for row in payload_rows
        ],
    }
    provenance_body = canonical(provenance_doc)
    checksums_body = "".join(
        f"{row['sha256']}  {row['name']}\n" for row in payload_rows
    ).encode("utf-8")

    for offset, (name, body) in enumerate(
        (
            ("theme-forge-nebular-fusion-v0.7.1-source.tar.gz", source_archive_body),
            ("nebular-compiled-public-build-source-authority-v0.7.1.json", source_authority_body),
            ("nebular-v0.7.1-native-ci-provenance.json", provenance_body),
            ("SHA256SUMS", checksums_body),
        ),
        10,
    ):
        asset_id = 5000 + offset
        dl_url = f"https://github.com/{repo_name}/releases/download/v0.7.1/{name}"
        api_url = f"https://api.github.com/repos/{repo_name}/releases/assets/{asset_id}"
        asset_map[dl_url] = body
        asset_map[api_url] = body
        api_assets.append(
            {
                "id": asset_id,
                "name": name,
                "size": len(body),
                "state": "uploaded",
                "url": api_url,
                "browser_download_url": dl_url,
                "digest": "sha256:" + _sha(body),
            }
        )

    api_base = f"https://api.github.com/repos/{repo_name}"
    api_map = {
        api_base: {"id": repo_id, "full_name": repo_name, "private": False},
        f"{api_base}/releases/tags/v0.7.1": {
            "id": release_id,
            "tag_name": "v0.7.1",
            "target_commitish": product_commit,
            "draft": False,
            "prerelease": False,
            "assets": api_assets,
        },
        f"{api_base}/git/ref/tags/v0.7.1": {
            "ref": "refs/tags/v0.7.1",
            "object": {"type": "commit", "sha": product_commit},
        },
        f"{api_base}/git/commits/{product_commit}": {
            "sha": product_commit,
            "tree": {"sha": product_tree},
        },
        f"{api_base}/git/trees/{product_tree}?recursive=1": {
            "sha": product_tree,
            "truncated": False,
            "tree": [{"path": "README.md", "mode": "100644", "type": "blob", "sha": "e" * 40}],
        },
    }

    pre_client = _SyntheticGitHubClient(api_map, asset_map)
    pre_capture = product_capture_mod.capture_product_release(
        scratch_setup,
        client=pre_client,
    )
    product_source = consumer.authenticated_product_source(pre_capture)
    record_bytes = canonical(pre_capture.record)

    # Set up synthetic repository root with required checkout files
    repo_dir = base_dir / "repo"
    (repo_dir / "src/rs9").mkdir(parents=True, mode=0o700)
    for helper_name in ("nebular071_universal_launcher.py", "nebular071_universal_fetch.py"):
        shutil.copy2(_CANDIDATE / "src/rs9" / helper_name, repo_dir / "src/rs9" / helper_name)

    legal_bodies = {
        "LICENSE": b"AGPL-3.0-or-later\n",
        "NOTICE": b"Theme Forge Nebular Fusion 0.7.1 notice\n",
        "COMMERCIAL-LICENSE.md": b"Commercial license terms\n",
    }
    for name, body in legal_bodies.items():
        (repo_dir / name).write_bytes(body)

    description_bytes = b"# Theme Forge Nebular Fusion 0.7.1\n\nSynthetic universal launcher description.\n"
    desc_path = repo_dir / universal.DESCRIPTION
    desc_path.parent.mkdir(parents=True, exist_ok=True)
    desc_path.write_bytes(description_bytes)

    bootstrap_bytes = canonical({"schema": "rs9.bootstrap.v1", "version": "0.7.1"})
    expectations_bytes = canonical({"schema": "rs9.expectations.v1", "version": "0.7.1"})
    gate1_profile_bytes = canonical({"schema": "rs9.gate1-profile.v1", "version": "0.7.1"})
    (repo_dir / "operators/tf-pypi/bootstrap.json").write_bytes(bootstrap_bytes)
    (repo_dir / "operators/tf-pypi/expectations.json").write_bytes(expectations_bytes)
    (repo_dir / publisher.GATE1_PROFILE_PATH).write_bytes(gate1_profile_bytes)

    # Write runtime_inputs.json for build_bundle
    runtime_targets = {}
    for row in payload_rows:
        target = row["target"]
        manifest = manifests_by_target[target]
        if target == "darwin-arm64":
            root_name = "Theme Forge Nebular Fusion.app"
            shell = root_name + "/Contents/Resources/bin/tfnf"
            gui = root_name + "/Contents/MacOS/theme-forge-nebular-fusion"
            family, arch, minimum_os, minimum_glibc = "darwin", "aarch64", "13.0", None
        else:
            root_name = "theme-forge-nebular-fusion"
            shell = root_name + "/bin/tfnf"
            gui = root_name + "/bin/theme-forge-nebular-fusion"
            family, arch, minimum_os, minimum_glibc = (
                "linux",
                "aarch64" if "arm64" in target else "x86_64",
                None,
                "2.36",
            )
        runtime_targets[target] = {
            "family": family,
            "arch": arch,
            "minimum_os": minimum_os,
            "minimum_glibc": minimum_glibc,
            "asset": {
                "id": row["id"],
                "name": row["name"],
                "size": row["bytes"],
                "sha256": row["sha256"],
                "url": row["url"],
            },
            "manifest_sha256": manifest["manifest_sha256"],
            "root": root_name,
            "shell_target": shell,
            "gui_target": gui,
        }

    runtime_inputs_doc = {
        "schema": profile.SCHEMAS["runtime_inputs"],
        "project": profile.PRODUCT,
        "version": profile.VERSION,
        "upstream_release": {
            "repository": repo_name,
            "tag": "v0.7.1",
            "commit": product_commit,
            "tree": product_tree,
        },
        "product_native_reference": __import__("rs9.nebular071_product_native", fromlist=["reference"]).reference(),
        "targets": runtime_targets,
    }
    runtime_inputs_bytes = canonical(runtime_inputs_doc)
    (repo_dir / universal.RUNTIME_INPUTS).write_bytes(runtime_inputs_bytes)

    # Build metadata tar.gz and qualification-inputs.json
    npm_wrapper_bytes = b"synthetic-npm-wrapper-071"
    notices_tar_bytes = b"synthetic-third-party-notices-071\n"
    readme_bytes = b"# Theme Forge Nebular Fusion 0.7.1\n"

    evidence_body_map: dict[str, bytes] = {
        "api/release.json": canonical(api_map[f"{api_base}/releases/tags/v0.7.1"]),
        "api/repository.json": canonical(api_map[api_base]),
        "api/ref.json": canonical(api_map[f"{api_base}/git/ref/tags/v0.7.1"]),
        "api/commit.json": canonical(api_map[f"{api_base}/git/commits/{product_commit}"]),
        "api/tree.json": canonical(api_map[f"{api_base}/git/trees/{product_tree}?recursive=1"]),
        "assets/SHA256SUMS": checksums_body,
        "assets/PROVENANCE.json": provenance_body,
        "assets/nebular-v0.7.1-third-party-notices.tar.gz": notices_tar_bytes,
        "assets/theme-forge-nebular-fusion-v0.7.1-source.tar.gz": source_archive_body,
        "assets/nebular-compiled-public-build-source-authority-v0.7.1.json": source_authority_body,
        "npm/metadata.json": canonical({"name": "theme-forge-nebular-fusion", "version": "0.7.1"}),
        "source/LICENSE": legal_bodies["LICENSE"],
        "source/NOTICE": legal_bodies["NOTICE"],
    }
    for rel_path, body in source_bodies.items():
        evidence_body_map[f"source-files/{rel_path}"] = body

    evidence_files_descriptor: dict[str, dict] = {
        rel_path: {"path": rel_path, "size": len(body), "sha256": _sha(body)}
        for rel_path, body in sorted(evidence_body_map.items())
    }
    evidence_files_descriptor["npm/package.tgz"] = {
        "path": "npm/package.tgz",
        "size": len(npm_wrapper_bytes),
        "sha256": _sha(npm_wrapper_bytes),
    }

    def _make_descriptor_smoke_support(target: str) -> dict:
        files_with_ev = []
        closure_files = []
        for item in source_files:
            ev_rel = f"source-files/{item['path']}"
            files_with_ev.append({**item, "evidence_path": ev_rel})
            closure_files.append(dict(item))
        archive_name = "theme-forge-nebular-fusion-v0.7.1-source.tar.gz"
        authority_name = "nebular-compiled-public-build-source-authority-v0.7.1.json"
        closure_doc = {
            "schema": smoke_support.SMOKE_SUPPORT_SCHEMA,
            "target": target,
            "source": dict(product_source),
            "root": "source",
            "tool_root": "tools",
            "fixture_root": "docs/examples/v0.4/brand-system/core-minimal",
            "files": closure_files,
            "source_binding": {
                "archive": {
                    "path": archive_name,
                    "size": len(source_archive_body),
                    "sha256": _sha(source_archive_body),
                },
                "authority": {
                    "path": authority_name,
                    "size": len(source_authority_body),
                    "sha256": _sha(source_authority_body),
                },
            },
        }
        digest_hex = smoke_support._closure_digest(closure_doc)
        return {
            **closure_doc,
            "files": files_with_ev,
            "source_binding": {
                "archive": {
                    "path": archive_name,
                    "evidence_path": f"assets/{archive_name}",
                    "size": len(source_archive_body),
                    "sha256": _sha(source_archive_body),
                },
                "authority": {
                    "path": authority_name,
                    "evidence_path": f"assets/{authority_name}",
                    "size": len(source_authority_body),
                    "sha256": _sha(source_authority_body),
                },
            },
            "closure_sha256": digest_hex,
        }

    # Build raw-release files and target descriptors
    raw_release_body_map: dict[str, bytes] = {
        "record.json": record_bytes,
        "README.md": readme_bytes,
        "PROVENANCE.json": provenance_body,
        "LICENSE": legal_bodies["LICENSE"],
        "NOTICE": legal_bodies["NOTICE"],
        "COMMERCIAL-LICENSE.md": legal_bodies["COMMERCIAL-LICENSE.md"],
    }
    for target, raw_manifest in manifest_bytes_by_target.items():
        raw_release_body_map[f"{target}-manifest.json"] = raw_manifest

    # Darwin native qualification & smoke receipts
    darwin_members = {m["path"]: m for m in manifests_by_target["darwin-arm64"]["members"]}
    darwin_roles = consumer_core._nebular_native_role_paths("darwin-arm64", manifests_by_target["darwin-arm64"])
    darwin_gui = darwin_members[darwin_roles["gui"]]
    darwin_launcher = darwin_members[darwin_roles["launcher"]]
    darwin_sidecar = darwin_members[darwin_roles["sidecar"]]

    darwin_qual_doc = {
        "schema": "nebular.native-rc-qualification-v1",
        "platform": "darwin-arm64",
        "status": "pass",
        "executableSha256": darwin_gui["sha256"],
        "checks": [
            {"id": "executable-header", "ok": True, "detail": "macho64"},
            {"id": "launcher", "ok": True, "detail": darwin_launcher["sha256"]},
            {"id": "sidecar-runtime", "ok": True, "detail": "sidecar " + darwin_sidecar["sha256"]},
            {"id": "legal-notices", "ok": True, "detail": "ok"},
            {"id": "codesign", "ok": True, "detail": "ok"},
        ],
    }
    darwin_qual_bytes = canonical(darwin_qual_doc)
    raw_release_body_map["darwin-qualification.json"] = darwin_qual_bytes

    darwin_smoke_entries = {}
    darwin_receipt_digests = {}
    for channel in ("raw-archive", "npm-package"):
        receipt_doc = {
            "schema": "nebular.release-smoke-receipt-v1",
            "scenario": "A",
            "status": "pass",
            "target": "aarch64-apple-darwin",
            "executable": {"sha256": darwin_gui["sha256"]},
            "awaitingSignal": False,
            "driver": {
                "steps": [
                    {"id": step_id, "ok": True}
                    for step_id in consumer_core._NEBULAR_NATIVE_RC_STEPS["A"]
                ]
            },
        }
        receipt_bytes = canonical(receipt_doc)
        run_doc = {
            "schema": "nebular.native-rc-smoke-run-v1",
            "status": "pass",
            "platform": "darwin-arm64",
            "scenario": "A",
            "source": channel,
            "problems": [],
            "executable": {
                "path": darwin_roles["smoke_gui"],
                "sha256": darwin_gui["sha256"],
            },
            "receipt": {
                "status": "pass",
                "sha256": _sha(receipt_bytes),
            },
            "checks": {
                "orphans": [],
                "persistentUserState": {"changed": []},
                "scratchHomeWrites": 1,
            },
            "finalization": {
                "status": "complete",
                "exitObserved": True,
                "applicationReceiptObservation": "present-at-read",
                "applicationReceiptCopy": "written",
            },
        }
        run_bytes = canonical(run_doc)
        run_rel = f"darwin-{channel}-run.json"
        rec_rel = f"darwin-{channel}-receipt.json"
        raw_release_body_map[run_rel] = run_bytes
        raw_release_body_map[rec_rel] = receipt_bytes
        darwin_receipt_digests[channel] = _sha(receipt_bytes)
        darwin_smoke_entries[channel] = {
            "run": {"path": run_rel, "size": len(run_bytes), "sha256": _sha(run_bytes)},
            "receipt": {"path": rec_rel, "size": len(receipt_bytes), "sha256": _sha(receipt_bytes)},
        }

    darwin_provider_evidence = {
        "qualification_sha256": _sha(darwin_qual_bytes),
        "qualification_check_id": "sidecar-runtime",
        "qualification_detail_sha256": _sha(publisher.canonical("sidecar " + darwin_sidecar["sha256"])),
        "smoke_receipts": darwin_receipt_digests,
    }

    raw_release_targets = {}
    for row in payload_rows:
        target = row["target"]
        manifest = manifests_by_target[target]
        raw_manifest = manifest_bytes_by_target[target]
        members_by_path = {m["path"]: m for m in manifest["members"]}
        roles = consumer_core._nebular_native_role_paths(target, manifest)
        support_desc = _make_descriptor_smoke_support(target)

        if target == "darwin-arm64":
            nc_target = {
                "command": "tfnf",
                "protocol": "nebular.native-rc-smoke",
                "platform": "darwin-arm64",
                "scenario": "A",
                "argv": ["--nebular-release-smoke=A"],
                "timeout_seconds": 30,
                "state_paths": ["Library/Application Support/nebular"],
                "user_state_protocol": {
                    "schema": "nebular.native-rc-persistent-user-state-v1",
                    "method": "native-rc-smoke.persistentStateLocations+snapshotLocations",
                    "scope": "real-user-state",
                },
                "loader": {
                    "status": "verified",
                    "path": darwin_launcher["path"],
                    "sha256": darwin_launcher["sha256"],
                    "qualification_check_id": "launcher",
                },
                "provider_closure": {
                    "status": "verified",
                    "target": "darwin-arm64",
                    "mode": "host-observed",
                    "emulated": False,
                    "qualification_check_id": "sidecar-runtime",
                    "evidence_sha256": _sha(publisher.canonical(darwin_provider_evidence)),
                },
                "qualification": {
                    "path": "darwin-qualification.json",
                    "size": len(darwin_qual_bytes),
                    "sha256": _sha(darwin_qual_bytes),
                },
                "smoke": darwin_smoke_entries,
                "smoke_support": support_desc,
            }
        else:
            scenario = "B" if target == "linux-arm64-gnu" else "C"
            platform_name = "linux-arm64" if target == "linux-arm64-gnu" else "linux-x64"
            nc_target = {
                "schema": "rs9.tf-pypi-nebular071-system-native-consumer-input.v1",
                "target": target,
                "profile_id": "nebular-fusion-0.7.1-system-webkitgtk-4.1-v1",
                "runtime_profile": "system-webkitgtk-4.1",
                "archive": {
                    "payload": {
                        "name": row["name"],
                        "size": row["bytes"],
                        "sha256": row["sha256"],
                    },
                    "manifest": {
                        "path": f"{target}-manifest.json",
                        "size": len(raw_manifest),
                        "sha256": _sha(raw_manifest),
                    },
                },
                "members": {
                    role_key: {
                        "path": members_by_path[roles[role_key]]["path"],
                        "size": members_by_path[roles[role_key]]["size"],
                        "mode": members_by_path[roles[role_key]]["mode"],
                        "sha256": members_by_path[roles[role_key]]["sha256"],
                    }
                    for role_key in ("gui", "launcher", "sidecar")
                },
                "protocol": {
                    "command": "tfnf",
                    "protocol": "nebular.native-rc-smoke",
                    "platform": platform_name,
                    "scenario": scenario,
                    "argv": [f"--nebular-release-smoke={scenario}"],
                    "timeout_seconds": 30,
                    "state_paths": [".config/nebular", ".local/share/nebular"],
                    "user_state_protocol": {
                        "schema": "nebular.native-rc-persistent-user-state-v1",
                        "method": "native-rc-smoke.persistentStateLocations+snapshotLocations",
                        "scope": "real-user-state",
                    },
                },
                "preflight_contract": {
                    "schema": "rs9.nebular071-system-webkit-preflight.v1",
                    "soname": "libwebkit2gtk-4.1.so.0",
                    "launcher": "normal-installed-python",
                    "operation": "ctypes.CDLL",
                },
                "smoke_support": support_desc,
            }

        raw_release_targets[target] = {
            "schema": publisher.RAW_RELEASE_HANDOFF_SCHEMA,
            "target": target,
            "record": {"path": "record.json", "size": len(record_bytes), "sha256": _sha(record_bytes)},
            "readme": {"path": "README.md", "size": len(readme_bytes), "sha256": _sha(readme_bytes)},
            "provenance": {"path": "PROVENANCE.json", "size": len(provenance_body), "sha256": _sha(provenance_body)},
            "payload": {
                "path": f"assets/{row['name']}",
                "name": row["name"],
                "size": row["bytes"],
                "sha256": row["sha256"],
            },
            "manifest": {
                "path": f"{target}-manifest.json",
                "size": len(raw_manifest),
                "sha256": _sha(raw_manifest),
            },
            "legal_files": {
                leg_name: {"path": leg_name, "size": len(leg_body), "sha256": _sha(leg_body)}
                for leg_name, leg_body in legal_bodies.items()
            },
            "product_source": dict(product_source),
            "native_consumer": {target: nc_target},
        }

    release_binding = {
        "schema": "rs9.nebular-release-binding.v1alpha1",
        "release": "0.7.1",
        "application_version": "0.7.1",
        "distribution_version": "0.7.1",
        "repository": repo_name,
        "tag": "v0.7.1",
        "bootstrap_path": "operators/tf-pypi/bootstrap.json",
        "expectations_path": "operators/tf-pypi/expectations.json",
        "profile_path": str(publisher.GATE1_PROFILE_PATH),
        "status": "ready",
        "lineage": {
            "mode": "direct-tag-provenance-equality",
            "requires_historical_author_rewrite": False,
        },
        "provenance": {
            "path": "PROVENANCE.json",
            "commit_field": "releaseCommit",
            "tree_field": "testedTree",
        },
        "expected": {
            "repository_id": repo_id,
            "release_id": release_id,
            "tag_commit": product_commit,
            "tag_tree": product_tree,
            "bootstrap_sha256": _sha(bootstrap_bytes),
            "expectations_sha256": _sha(expectations_bytes),
        },
    }
    descriptor_doc = {
        "schema": public_inputs.DESCRIPTOR_SCHEMA,
        "project": "theme-forge-nebular-fusion",
        "version": "0.7.1",
        "distribution_version": "0.7.1",
        "workflow": publisher.WORKFLOW,
        "status": "ready",
        "upstream_origin": {
            "repository": repo_name,
            "tag": "v0.7.1",
            "release_url": f"https://github.com/{repo_name}/releases/tag/v0.7.1",
            "api_release_url": f"https://api.github.com/repos/{repo_name}/releases/tags/v0.7.1",
        },
        "release_binding": release_binding,
        "release_binding_sha256": _sha(publisher.canonical(release_binding)),
        "system_webkit": {
            "schema": publisher.SYSTEM_WEBKIT_INPUT_SCHEMA,
            "origin_kind": publisher.PUBLIC_INRUN_MANYLINUX_ORIGIN_KIND,
            "profile_id": publisher.SYSTEM_WEBKIT_PROFILE_ID,
        },
        "evidence": {
            "source_root": "evidence/public-release",
            "files": evidence_files_descriptor,
        },
        "raw_release": {
            "source_root": "raw-release",
            "targets": raw_release_targets,
        },
    }
    descriptor_bytes = canonical(descriptor_doc)

    # Package metadata tar.gz containing qualification-inputs.json, evidence/public-release/*, raw-release/*
    metadata_files: dict[str, bytes] = {"qualification-inputs.json": descriptor_bytes}
    for rel_path, body in evidence_body_map.items():
        metadata_files[f"evidence/public-release/{rel_path}"] = body
    for rel_path, body in raw_release_body_map.items():
        metadata_files[f"raw-release/{rel_path}"] = body

    metadata_dirs: set[str] = set()
    for file_path in metadata_files:
        parts = file_path.split("/")
        for idx in range(1, len(parts)):
            metadata_dirs.add("/".join(parts[:idx]))

    meta_stream = io.BytesIO()
    with tarfile.open(fileobj=meta_stream, mode="w:gz", format=tarfile.USTAR_FORMAT) as archive:
        for dir_path in sorted(metadata_dirs):
            info = tarfile.TarInfo(dir_path)
            info.type = tarfile.DIRTYPE
            info.mode = 0o755
            info.mtime = 0
            archive.addfile(info)
        for file_path, body in sorted(metadata_files.items()):
            info = tarfile.TarInfo(file_path)
            info.size = len(body)
            info.mode = 0o644
            info.mtime = 0
            archive.addfile(info, io.BytesIO(body))
    metadata_tar_bytes = meta_stream.getvalue()

    metadata_name = "nebular-v0.7.1-qualification-inputs.tar.gz"
    metadata_url = f"https://github.com/{repo_name}/releases/download/v0.7.1/{metadata_name}"
    npm_name = "nebular-v0.7.1-npm.tgz"
    npm_url = f"https://github.com/{repo_name}/releases/download/v0.7.1/{npm_name}"
    asset_map[metadata_url] = metadata_tar_bytes
    asset_map[npm_url] = npm_wrapper_bytes

    manifest_doc = {
        "schema": public_inputs.SCHEMA,
        "repository": repo_name,
        "version": "0.7.1",
        "release_id": release_id,
        "metadata": {
            "asset_id": 6001,
            "name": metadata_name,
            "url": metadata_url,
            "bytes": len(metadata_tar_bytes),
            "sha256": _sha(metadata_tar_bytes),
        },
        "payloads": [
            *[
                {
                    "asset_id": row["id"],
                    "name": row["name"],
                    "url": row["url"],
                    "bytes": row["bytes"],
                    "sha256": row["sha256"],
                    "path": f"raw-release/assets/{row['name']}",
                }
                for row in payload_rows
            ],
            {
                "asset_id": 6002,
                "name": npm_name,
                "url": npm_url,
                "bytes": len(npm_wrapper_bytes),
                "sha256": _sha(npm_wrapper_bytes),
                "path": "evidence/public-release/npm/package.tgz",
            },
        ],
    }
    manifest_rel = publisher.PUBLIC_INPUTS_MANIFEST_PATH
    manifest_full = repo_dir / manifest_rel
    manifest_full.parent.mkdir(parents=True, exist_ok=True)
    manifest_full.write_bytes(canonical(manifest_doc))

    return {
        "repo_dir": repo_dir,
        "manifest_rel": manifest_rel,
        "manifest_doc": manifest_doc,
        "descriptor_doc": descriptor_doc,
        "rs9_source": rs9_source,
        "run_id": run_id,
        "product_source": product_source,
        "pre_capture": pre_capture,
        "api_map": api_map,
        "asset_map": asset_map,
        "payload_rows": payload_rows,
        "description_bytes": description_bytes,
    }


def _git_output_stub(rs9_source: dict[str, str]):
    def _stub(_repo, args, _code):
        if "status" in args:
            return ""
        if any("tree" in token for token in args):
            return rs9_source["tree"]
        return rs9_source["commit"]

    return _stub


class CompleteOwnerChainTests(unittest.TestCase):
    def setUp(self):
        from test_nebular071_simulated_native_fixture import install_simulated_native_domain
        install_simulated_native_domain(self)

    def test_end_to_end_producer_bundle_consumer_matrix_and_publication_chain(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            fx = _build_complete_fixture(base)
            repo_dir = fx["repo_dir"]
            rs9_source = fx["rs9_source"]
            run_id = fx["run_id"]
            client = _SyntheticGitHubClient(fx["api_map"], fx["asset_map"])
            inrun_root = base / "inrun-public-inputs"

            with mock.patch.object(publisher, "_git_output", side_effect=_git_output_stub(rs9_source)):
                # 1. R1: Producer materializes and authenticates <inrun_root>/product-capture
                prep = publisher.prepare_public_inputs_071(
                    fx["manifest_rel"],
                    inrun_root,
                    repository=repo_dir,
                    rs9_source=rs9_source,
                    client=client,
                )
                self.assertEqual(prep["status"], "held")
                self.assertIn("product_capture", prep)
                self.assertEqual(
                    prep["product_capture"]["record_sha256"],
                    fx["product_source"]["record_sha256"],
                )
                held_capture = product_capture_mod.load_held_product_capture(inrun_root)
                self.assertEqual(
                    consumer.authenticated_product_source(held_capture),
                    fx["product_source"],
                )
                # Verify transport payload bytes were reused rather than fetched twice over HTTP
                for row in fx["payload_rows"]:
                    self.assertEqual(client.get_calls.count(row["url"]), 1)
                fetch_receipt = json.loads(
                    (inrun_root / "product-capture/evidence/fetch-receipt.json").read_bytes()
                )
                reused_paths = {
                    req.get("reused_transport_path")
                    for req in fetch_receipt.get("requests", [])
                    if isinstance(req, dict) and "reused_transport_path" in req
                }
                self.assertEqual(
                    reused_paths,
                    {f"raw-release/assets/{row['name']}" for row in fx["payload_rows"]},
                )

                # 2. Bundle build loads held product-capture from inrun_root (product_capture=None)
                bundle_dir = base / "bundle"
                prepared_descriptor = inrun_root / publisher.PUBLIC_INPUTS_DESCRIPTOR
                bundle_receipt = universal.build_bundle(
                    prepared_descriptor,
                    inrun_root,
                    bundle_dir,
                    repository=repo_dir,
                    expected_commit=rs9_source["commit"],
                    require_clean=True,
                )
                self.assertFalse(bundle_receipt["builder_can_publish"])
                self.assertFalse(bundle_receipt["publication_admitted"])

                # 3. R2 & R3: qualify_native -> materialize_universal_handoff ->
                # consume_universal_wheel -> capture_universal_runtime ->
                # _nebular_installed_consumer -> materialize_smoke_support
                qualify_work = base / "qualify-work"
                qualify_out = base / "qualify-out/darwin-arm64/result.json"
                raw_release_path = base / "handoff-darwin/raw_release.json"
                sandbox_calls = []

                def _stop_at_sandbox(python_exe, node_exe, base_env, prefix):
                    sandbox_calls.append((python_exe, node_exe, dict(base_env), tuple(prefix)))
                    raise _SandboxStopSentinel("stopped at network_denial after materialize_smoke_support")

                env_vars = {
                    "GITHUB_ACTIONS": "true",
                    "GITHUB_REPOSITORY": "Knowledge-Forge-AI/release-starport-9",
                    "GITHUB_REF": "refs/heads/main",
                    "GITHUB_SHA": rs9_source["commit"],
                    "GITHUB_RUN_ID": run_id,
                    "GITHUB_RUN_ATTEMPT": "1",
                }
                with mock.patch.dict(os.environ, env_vars, clear=False), \
                        mock.patch.object(consumer_core, "_nebular_identity_observed", return_value={
                            "source": "runner", "system": "darwin", "machine": "arm64",
                        }), \
                        mock.patch.object(publisher, "make_real_user_state_snapshotter", return_value=lambda _t, _p: {}), \
                        mock.patch.object(consumer_core, "node_binary", return_value=Path("/usr/bin/false")), \
                        mock.patch.object(consumer_core, "network_denial", side_effect=_stop_at_sandbox):
                    with self.assertRaises(_SandboxStopSentinel):
                        universal.qualify_native(
                            bundle_dir,
                            qualify_work,
                            qualify_out,
                            target="darwin-arm64",
                            expected_commit=rs9_source["commit"],
                            run_id=run_id,
                            run_attempt="1",
                            qualification_inputs=prepared_descriptor,
                            inrun_root=inrun_root,
                            raw_release_path=raw_release_path,
                            repository=repo_dir,
                            consumer_host_role="newer",
                        )

                self.assertEqual(len(sandbox_calls), 1)
                self.assertTrue(raw_release_path.is_file())
                self.assertTrue((qualify_work / "smoke-support/source/tools/native-rc-smoke.mjs").is_file())
                self.assertTrue((qualify_work / "smoke-support/source-bindings.json").is_file())

                # 4. R2 & R4: read_matrix_inputs and publication.verify_capture across all 8 artifacts
                receipts_dir = base / "receipts"
                floors_dir = base / "floors"
                positives = {}
                for index, (target, role) in enumerate(
                    sorted(
                        {(t, "newer") for t in wheel_builder.LAYOUTS}
                        | {(t, "floor") for t in universal.LINUX_TARGETS}
                    ),
                    1,
                ):
                    rec = {
                        "identity": f"{index:064x}",
                        "target": target,
                        "role": role,
                        "host_observation": {"identity": f"{index + 100:064x}"},
                    }
                    positives[target, role] = rec
                    target_dir = (receipts_dir if role == "newer" else floors_dir) / target
                    target_dir.mkdir(parents=True, exist_ok=True)
                    (target_dir / "result.json").write_bytes(canonical(rec))

                negatives = {}
                for index, target in enumerate(universal.LINUX_TARGETS, 1):
                    neg = {"identity": f"{index + 200:064x}"}
                    negatives[target] = neg
                    (floors_dir / target / "missing-runtime.json").write_bytes(canonical(neg))

                with mock.patch.object(
                    universal.consumer,
                    "validate_universal_consumer",
                    side_effect=lambda value, *_args, **_kwargs: value,
                ), mock.patch(
                    "rs9.nebular071_universal_missing.validate_missing_runtime",
                    side_effect=lambda value, *_args, **_kwargs: value,
                ):
                    matrix = universal.read_matrix_inputs(
                        bundle_dir,
                        prepared_descriptor,
                        inrun_root,
                        receipts_dir,
                        floors_dir,
                        base / "matrix-work",
                        repository=repo_dir,
                        source=rs9_source,
                        run_id=run_id,
                        run_attempt="1",
                    )

                self.assertEqual(matrix["schema"], universal.MATRIX_SCHEMA)
                self.assertFalse(matrix["publication_admitted"])
                self.assertEqual(len(matrix["lanes"]), 5)

                # Package the 8 artifacts for publication.verify_capture
                public_inputs_members = {
                    file_path.relative_to(inrun_root).as_posix(): file_path.read_bytes()
                    for file_path in sorted(inrun_root.rglob("*"))
                    if file_path.is_file()
                }
                self.assertIn("product-capture/selection.json", public_inputs_members)
                wheel_bytes = (bundle_dir / "dist" / wheel_builder.FILENAME).read_bytes()
                members_by_artifact = {
                    publication.PUBLIC_INPUTS: public_inputs_members,
                    publication.BUNDLE: {
                        "bundle.json": (bundle_dir / "bundle.json").read_bytes(),
                        "universal-build-receipt.json": (bundle_dir / "universal-build-receipt.json").read_bytes(),
                        "dist/" + wheel_builder.FILENAME: wheel_bytes,
                    },
                    publication.MATRIX: {publication.MATRIX_MEMBER: canonical(matrix)},
                }
                for target, art_name in publication.QUALIFICATION.items():
                    members_by_artifact[art_name] = {
                        f"{target}/result.json": (receipts_dir / target / "result.json").read_bytes()
                    }
                for target, art_name in publication.FLOOR.items():
                    members_by_artifact[art_name] = {
                        f"{target}/result.json": (floors_dir / target / "result.json").read_bytes(),
                        f"{target}/missing-runtime.json": (floors_dir / target / "missing-runtime.json").read_bytes(),
                    }

                def _build_archives_and_authority(members_map: dict[str, dict[str, bytes]]):
                    archives_bytes = {}
                    artifact_rows = {}
                    for idx, name in enumerate(publication.ARTIFACTS, 7100):
                        stream = io.BytesIO()
                        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                            for m_path, m_body in sorted(members_map[name].items()):
                                zf.writestr(m_path, m_body)
                        zip_raw = stream.getvalue()
                        archives_bytes[name] = zip_raw
                        artifact_rows[name] = {
                            "id": idx,
                            "size_in_bytes": len(zip_raw),
                            "archive_sha256": _sha(zip_raw),
                            "files": {
                                m_path: {"size": len(m_body), "sha256": _sha(m_body)}
                                for m_path, m_body in sorted(members_map[name].items())
                            },
                        }
                    run_doc = {
                        "id": int(run_id),
                        "run_attempt": 1,
                        "status": "completed",
                        "conclusion": "success",
                        "event": "workflow_dispatch",
                        "head_branch": "main",
                        "head_sha": rs9_source["commit"],
                        "path": ".github/workflows/" + publication.WORKFLOW,
                        "repository": {"full_name": publication.REPOSITORY},
                        "head_repository": {"full_name": publication.REPOSITORY},
                        "head_commit": {"id": rs9_source["commit"], "tree_id": rs9_source["tree"]},
                    }
                    api_docs = {
                        "run.json": run_doc,
                        "artifacts.json": {
                            "total_count": len(artifact_rows),
                            "artifacts": [
                                {
                                    "id": row["id"],
                                    "name": name,
                                    "size_in_bytes": row["size_in_bytes"],
                                    "digest": "sha256:" + row["archive_sha256"],
                                    "expired": False,
                                    "archive_download_url": (
                                        f"https://api.github.com/repos/{publication.REPOSITORY}"
                                        f"/actions/artifacts/{row['id']}/zip"
                                    ),
                                    "workflow_run": {
                                        "id": int(run_id),
                                        "head_sha": rs9_source["commit"],
                                        "head_branch": "main",
                                    },
                                }
                                for name, row in artifact_rows.items()
                            ],
                        },
                        "jobs.json": {"total_count": 1, "jobs": [{"id": 1, "name": "071 matrix"}]},
                    }
                    api_raw = {k: canonical(v) for k, v in api_docs.items()}
                    unsigned_auth = {
                        "schema": publication.SCHEMA,
                        "project": publication.PROJECT,
                        "version": wheel_builder.VERSION,
                        "distribution": consumer.DISTRIBUTION,
                        "workflow": publication.WORKFLOW,
                        "environment": publication.ENVIRONMENT,
                        "repository": publication.REPOSITORY,
                        "source": rs9_source,
                        "run": {"id": run_id, "attempt": "1"},
                        "wheel": bundle_receipt["wheel"],
                        "runtime_inputs_sha256": bundle_receipt["runtime_inputs_sha256"],
                        "runtime_index_sha256": bundle_receipt["runtime_index_sha256"],
                        "description_sha256": bundle_receipt["description_sha256"],
                        "matrix_sha256": _sha(canonical(matrix)),
                        "api": {k: {"size": len(v), "sha256": _sha(v)} for k, v in api_raw.items()},
                        "artifacts": artifact_rows,
                    }
                    auth = {**unsigned_auth, "identity": _sha(canonical(unsigned_auth))}
                    return archives_bytes, api_raw, auth

                archives_bytes, api_raw, authority = _build_archives_and_authority(members_by_artifact)
                api_dir = base / "pub-api"
                arch_dir = base / "pub-archives"
                api_dir.mkdir()
                arch_dir.mkdir()
                for name, body in api_raw.items():
                    (api_dir / name).write_bytes(body)
                for name, body in archives_bytes.items():
                    (arch_dir / f"{name}.zip").write_bytes(body)

                history_stub = mock.Mock()
                history_stub.validate_qualification_jobs.return_value = None
                with mock.patch.object(publication, "_history", return_value=history_stub), \
                        mock.patch.object(
                            universal.consumer,
                            "validate_universal_consumer",
                            side_effect=lambda value, *_args, **_kwargs: value,
                        ), \
                        mock.patch(
                            "rs9.nebular071_universal_missing.validate_missing_runtime",
                            side_effect=lambda value, *_args, **_kwargs: value,
                        ):
                    pub_ctx = publication.verify_capture(
                        authority,
                        api_dir,
                        arch_dir,
                        base / "pub-capture-out",
                        repository=repo_dir,
                    )

                self.assertEqual(pub_ctx["wheel"], wheel_bytes)
                self.assertEqual(pub_ctx["matrix_identity"], matrix["identity"])

                # Negative R4 test 1: missing product-capture/selection.json inside PUBLIC_INPUTS
                missing_sel_members = copy.deepcopy(members_by_artifact)
                del missing_sel_members[publication.PUBLIC_INPUTS]["product-capture/selection.json"]
                bad_arch1, bad_api1, bad_auth1 = _build_archives_and_authority(missing_sel_members)
                api_dir_bad1 = base / "pub-api-bad1"
                arch_dir_bad1 = base / "pub-arch-bad1"
                api_dir_bad1.mkdir()
                arch_dir_bad1.mkdir()
                for name, body in bad_api1.items():
                    (api_dir_bad1 / name).write_bytes(body)
                for name, body in bad_arch1.items():
                    (arch_dir_bad1 / f"{name}.zip").write_bytes(body)
                with mock.patch.object(publication, "_history", return_value=history_stub):
                    with self.assertRaisesRegex(ContractError, "NEBULAR_UNIVERSAL_PUBLICATION_PRODUCT_CAPTURE"):
                        publication.verify_capture(
                            bad_auth1,
                            api_dir_bad1,
                            arch_dir_bad1,
                            base / "pub-capture-bad1",
                            repository=repo_dir,
                        )

                # Negative R4 test 2: tampered product-capture/evidence/assets/SHA256SUMS inside PUBLIC_INPUTS
                tampered_members = copy.deepcopy(members_by_artifact)
                tampered_members[publication.PUBLIC_INPUTS]["product-capture/evidence/assets/SHA256SUMS"] = (
                    b"0" * 64 + b"  tampered.tar.gz\n"
                )
                bad_arch2, bad_api2, bad_auth2 = _build_archives_and_authority(tampered_members)
                api_dir_bad2 = base / "pub-api-bad2"
                arch_dir_bad2 = base / "pub-arch-bad2"
                api_dir_bad2.mkdir()
                arch_dir_bad2.mkdir()
                for name, body in bad_api2.items():
                    (api_dir_bad2 / name).write_bytes(body)
                for name, body in bad_arch2.items():
                    (arch_dir_bad2 / f"{name}.zip").write_bytes(body)
                with mock.patch.object(publication, "_history", return_value=history_stub):
                    with self.assertRaisesRegex(ContractError, "NEBULAR_UNIVERSAL_PUBLICATION_PRODUCT_CAPTURE"):
                        publication.verify_capture(
                            bad_auth2,
                            api_dir_bad2,
                            arch_dir_bad2,
                            base / "pub-capture-bad2",
                            repository=repo_dir,
                        )

                # Negative R4 test 3: ninth unknown artifact in artifacts.json rejected
                api_dir_bad3 = base / "pub-api-bad3"
                api_dir_bad3.mkdir()
                for name, body in api_raw.items():
                    (api_dir_bad3 / name).write_bytes(body)
                artifacts_doc3 = json.loads(api_raw["artifacts.json"])
                artifacts_doc3["artifacts"].append(
                    {
                        "id": 9999,
                        "name": "tfnf-071-universal-product-capture",
                        "size_in_bytes": 1,
                        "digest": "sha256:" + "0" * 64,
                        "expired": False,
                        "archive_download_url": f"https://api.github.com/repos/{publication.REPOSITORY}/actions/artifacts/9999/zip",
                        "workflow_run": {
                            "id": int(run_id),
                            "head_sha": rs9_source["commit"],
                            "head_branch": "main",
                        },
                    }
                )
                artifacts_doc3["total_count"] = len(artifacts_doc3["artifacts"])
                raw_art3 = canonical(artifacts_doc3)
                (api_dir_bad3 / "artifacts.json").write_bytes(raw_art3)
                auth3_unsigned = copy.deepcopy({k: v for k, v in authority.items() if k != "identity"})
                auth3_unsigned["api"]["artifacts.json"] = {"size": len(raw_art3), "sha256": _sha(raw_art3)}
                auth3 = {**auth3_unsigned, "identity": _sha(canonical(auth3_unsigned))}
                with mock.patch.object(publication, "_history", return_value=history_stub):
                    with self.assertRaisesRegex(ContractError, "NEBULAR_UNIVERSAL_PUBLICATION_QUALIFICATION_ARTIFACTS"):
                        publication.verify_capture(
                            auth3,
                            api_dir_bad3,
                            arch_dir,
                            base / "pub-capture-bad3",
                            repository=repo_dir,
                        )

    def test_negative_seams_fail_closed_across_r1_r2_r3(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            fx = _build_complete_fixture(base)
            repo_dir = fx["repo_dir"]
            rs9_source = fx["rs9_source"]
            client = _SyntheticGitHubClient(fx["api_map"], fx["asset_map"])
            inrun_root = base / "inrun"

            with mock.patch.object(publisher, "_git_output", side_effect=_git_output_stub(rs9_source)):
                publisher.prepare_public_inputs_071(
                    fx["manifest_rel"],
                    inrun_root,
                    repository=repo_dir,
                    rs9_source=rs9_source,
                    client=client,
                )
                held_capture = product_capture_mod.load_held_product_capture(inrun_root)
                prepared_descriptor = inrun_root / publisher.PUBLIC_INPUTS_DESCRIPTOR

                # R1 negative: root bounds check rejects excessive byte count
                with mock.patch.object(publisher, "PUBLIC_INPUTS_ARTIFACT_MAX_BYTES", 10):
                    with self.assertRaisesRegex(AdmissionError, "TF_PYPI_PUBLIC_INPUTS_OUTPUT"):
                        publisher._verify_public_inputs_root_bounds(inrun_root)

                # R1 negative: transport/product-capture join rejects mismatched payload digest
                bad_transport = {
                    "release_id": 71071,
                    "metadata": {"asset_id": 6001, "name": "meta.tar.gz"},
                    "payloads": [
                        {
                            "asset_id": row["id"],
                            "name": row["name"],
                            "bytes": row["bytes"],
                            "sha256": "0" * 64 if idx == 0 else row["sha256"],
                        }
                        for idx, row in enumerate(fx["payload_rows"])
                    ]
                    + [{"asset_id": 6002, "name": "npm.tgz", "bytes": 1, "sha256": "1" * 64}],
                }
                with self.assertRaisesRegex(AdmissionError, "TF_PYPI_PUBLIC_INPUTS_PRODUCT_CAPTURE"):
                    publisher._join_transport_to_product_capture(
                        bad_transport, fx["descriptor_doc"], held_capture
                    )

                # R2/R3 negative: descriptor validator rejects missing/dict product_capture and mismatched product_source
                with self.assertRaisesRegex(AdmissionError, "TF_PYPI_QUALIFICATION_INPUTS_PRODUCT_CAPTURE"):
                    publisher.validate_qualification_inputs_descriptor(
                        fx["descriptor_doc"],
                        repository=repo_dir,
                        phase=publisher.QUALIFICATION_INPUT_PHASE_PREP,
                        inrun_root=inrun_root,
                        product_capture=None,
                    )
                with self.assertRaisesRegex(AdmissionError, "TF_PYPI_QUALIFICATION_INPUTS_PRODUCT_CAPTURE"):
                    publisher.validate_qualification_inputs_descriptor(
                        fx["descriptor_doc"],
                        repository=repo_dir,
                        phase=publisher.QUALIFICATION_INPUT_PHASE_PREP,
                        inrun_root=inrun_root,
                        product_capture={"record": {}},
                    )
                drifted_desc = copy.deepcopy(fx["descriptor_doc"])
                drifted_desc["raw_release"]["targets"]["linux-x64-gnu"]["product_source"]["tree"] = "9" * 40
                with self.assertRaisesRegex(AdmissionError, "TF_PYPI_RAW_RELEASE_HANDOFF_BINDING"):
                    publisher.validate_qualification_inputs_descriptor(
                        drifted_desc,
                        repository=repo_dir,
                        phase=publisher.QUALIFICATION_INPUT_PHASE_PREP,
                        inrun_root=inrun_root,
                        product_capture=held_capture,
                    )

                # R3 negative: _nebular_installed_consumer fails closed BEFORE work_path.mkdir()
                bundle_dir = base / "bundle"
                universal.build_bundle(
                    prepared_descriptor,
                    inrun_root,
                    bundle_dir,
                    repository=repo_dir,
                    expected_commit=rs9_source["commit"],
                    require_clean=True,
                )
                _bundle, snapshot = universal.load_bundle(
                    bundle_dir, repository=repo_dir, expected_source=rs9_source
                )
                handoff = consumer.materialize_universal_handoff(
                    fx["descriptor_doc"],
                    base / "handoff-x64",
                    target="linux-x64-gnu",
                    repository=repo_dir,
                    inrun_root=inrun_root,
                    product_capture=held_capture,
                )
                captured_rt = consumer.capture_universal_runtime(
                    snapshot,
                    Path(handoff["root"]),
                    handoff,
                    target="linux-x64-gnu",
                    product_capture=held_capture,
                )
                wheel_path = bundle_dir / "dist" / wheel_builder.FILENAME

                # Missing product_capture refuses before creating work_path
                work_missing = base / "work-missing-capture"
                bad_rt_missing = dict(captured_rt, product_capture=None)
                with self.assertRaisesRegex(AdmissionError, "TF_PYPI_NEBULAR_PRODUCT_CAPTURE"):
                    consumer_core._nebular_installed_consumer(
                        bad_rt_missing,
                        wheel_path,
                        work_missing,
                        target="linux-x64-gnu",
                        fixture_only=False,
                        product_capture=None,
                    )
                self.assertFalse(work_missing.exists())

                # Tampered product_source refuses before creating work_path
                work_tampered = base / "work-tampered-source"
                bad_rt_source = dict(
                    captured_rt,
                    product_source={**captured_rt["product_source"], "commit": "9" * 40},
                )
                with self.assertRaisesRegex(AdmissionError, "TF_PYPI_NEBULAR_SMOKE_CLOSURE"):
                    consumer_core._nebular_installed_consumer(
                        bad_rt_source,
                        wheel_path,
                        work_tampered,
                        target="linux-x64-gnu",
                        fixture_only=False,
                        product_capture=held_capture,
                    )
                self.assertFalse(work_tampered.exists())

                # Seven-field product_source frame rejected
                work_seven = base / "work-seven-fields"
                bad_rt_seven = dict(
                    captured_rt,
                    product_source={**captured_rt["product_source"], "release_id": 71071},
                )
                with self.assertRaisesRegex(AdmissionError, "TF_PYPI_NEBULAR_SMOKE_CLOSURE"):
                    consumer_core._nebular_installed_consumer(
                        bad_rt_seven,
                        wheel_path,
                        work_seven,
                        target="linux-x64-gnu",
                        fixture_only=False,
                        product_capture=held_capture,
                    )
                self.assertFalse(work_seven.exists())

                # Cross-release A/B mixing and wrong compiler tree rejected
                release_frame = consumer.authenticated_product_release(held_capture)
                prov_bytes = release_frame["provenance_bytes"]
                prov_doc = json.loads(prov_bytes)
                native_record = copy.deepcopy(held_capture.record)
                x64_asset = snapshot["runtime_inputs"]["targets"]["linux-x64-gnu"]["asset"]
                proof = snapshot["runtime_inputs"]["product_native_reference"]
                upstream_rel = snapshot["runtime_inputs"]["upstream_release"]

                # R1 negative: if capture_product_release fails after materialize_public_inputs,
                # prepare_public_inputs_071 cleans up the partial output root so a retry is not blocked.
                bad_api_map = copy.deepcopy(fx["api_map"])
                rel_url = "https://api.github.com/repos/Knowledge-Forge-AI/theme-forge-nebular-fusion/releases/tags/v0.7.1"
                bad_api_map[rel_url]["id"] = 99999
                bad_prep_client = _SyntheticGitHubClient(bad_api_map, fx["asset_map"])
                failed_inrun = base / "inrun-failed-cleanup"
                with self.assertRaisesRegex(AdmissionError, "TF_PYPI_PUBLIC_INPUTS_PRODUCT_CAPTURE"):
                    publisher.prepare_public_inputs_071(
                        fx["manifest_rel"],
                        failed_inrun,
                        repository=repo_dir,
                        rs9_source=rs9_source,
                        client=bad_prep_client,
                    )
                self.assertFalse(failed_inrun.exists())

                mixed_record = copy.deepcopy(native_record)
                mixed_record["release"]["id"] = 99999
                with self.assertRaisesRegex(ContractError, "NEBULAR_UNIVERSAL_RELEASE_JOIN"):
                    consumer.join_product_native_release(
                        held_capture,
                        fx["product_source"],
                        upstream_rel,
                        mixed_record,
                        prov_doc,
                        proof,
                        x64_asset,
                        provenance_bytes=prov_bytes,
                    )

                # Cross-release payload asset mixing with resealed outer native record and provenance
                mixed_asset = dict(x64_asset, sha256="8" * 64)
                resealed_native_record = copy.deepcopy(native_record)
                for row in resealed_native_record["assets"]:
                    if row.get("github_asset_id") == x64_asset["id"]:
                        row["sha256"] = "8" * 64
                resealed_native_prov = copy.deepcopy(prov_doc)
                for row in resealed_native_prov["assets"]:
                    if row.get("id") == x64_asset["id"]:
                        row["sha256"] = "8" * 64
                with self.assertRaisesRegex(ContractError, "NEBULAR_UNIVERSAL_RELEASE_JOIN"):
                    consumer.join_product_native_release(
                        held_capture,
                        fx["product_source"],
                        upstream_rel,
                        resealed_native_record,
                        resealed_native_prov,
                        proof,
                        mixed_asset,
                    )

                # Source-archive and source-authority mixing with resealed outer digests
                alt_paths = sorted(
                    {f"tools/{name}" for name in smoke_support._REQUIRED_TOOLS}
                    | set(smoke_support._REQUIRED_FIXTURES)
                )
                alt_bodies = {p: ("alt-source-release-B:" + p + "\n").encode("utf-8") for p in alt_paths}
                alt_stream = io.BytesIO()
                with tarfile.open(fileobj=alt_stream, mode="w:gz", format=tarfile.USTAR_FORMAT) as archive:
                    for p in alt_paths:
                        info = tarfile.TarInfo(p)
                        info.size = len(alt_bodies[p])
                        info.mode = 0o644
                        info.mtime = 0
                        archive.addfile(info, io.BytesIO(alt_bodies[p]))
                alt_archive_body = alt_stream.getvalue()
                alt_inventory = [
                    {"path": p, "bytes": len(alt_bodies[p]), "mode": 0o644, "sha256": _sha(alt_bodies[p])}
                    for p in alt_paths
                ]
                alt_unsigned = {
                    "schema": "nebular-public-build-source-v1",
                    "version": "0.7.1",
                    "composition": smoke_support._js_identity(alt_inventory),
                    "locks": {"cargo": "1" * 64, "frontend": "2" * 64},
                    "components": {"burst": "3" * 64, "loom": "4" * 64, "solar": "5" * 64},
                    "recipe": "6" * 64,
                    "resourcePlans": {
                        triple: {"resources": ["release-notices"], "externalBin": ["binaries/service"]}
                        for triple in smoke_support._SOURCE_TRIPLES
                    },
                }
                alt_authority = {**alt_unsigned, "identity": smoke_support._js_identity(alt_unsigned)}
                alt_authority_body = canonical(alt_authority)
                resealed_support = copy.deepcopy(handoff["native_consumer"]["linux-x64-gnu"]["smoke_support"])
                resealed_support["source_binding"]["archive"] = {
                    "path": "theme-forge-nebular-fusion-v0.7.1-source.tar.gz",
                    "size": len(alt_archive_body),
                    "sha256": _sha(alt_archive_body),
                }
                resealed_support["source_binding"]["authority"] = {
                    "path": "nebular-compiled-public-build-source-authority-v0.7.1.json",
                    "size": len(alt_authority_body),
                    "sha256": _sha(alt_authority_body),
                }
                resealed_support["closure_sha256"] = smoke_support._closure_digest(resealed_support)
                with self.assertRaisesRegex(ContractError, "NEBULAR_UNIVERSAL_RELEASE_JOIN"):
                    consumer.join_product_native_release(
                        held_capture,
                        fx["product_source"],
                        upstream_rel,
                        native_record,
                        prov_doc,
                        proof,
                        x64_asset,
                        provenance_bytes=prov_bytes,
                        support=resealed_support,
                    )

                # Resealed source-archive mixing in descriptor rejected against held_capture
                resealed_desc = copy.deepcopy(fx["descriptor_doc"])
                for tgt_name, tgt_spec in resealed_desc["raw_release"]["targets"].items():
                    desc_support = tgt_spec["native_consumer"][tgt_name]["smoke_support"]
                    ev_arch_path = desc_support["source_binding"]["archive"]["evidence_path"]
                    ev_auth_path = desc_support["source_binding"]["authority"]["evidence_path"]
                    desc_support["source_binding"]["archive"]["size"] = len(alt_archive_body)
                    desc_support["source_binding"]["archive"]["sha256"] = _sha(alt_archive_body)
                    desc_support["source_binding"]["authority"]["size"] = len(alt_authority_body)
                    desc_support["source_binding"]["authority"]["sha256"] = _sha(alt_authority_body)
                    desc_support["closure_sha256"] = smoke_support._closure_digest(desc_support)
                    resealed_desc["evidence"]["files"][ev_arch_path] = {
                        "path": ev_arch_path,
                        "size": len(alt_archive_body),
                        "sha256": _sha(alt_archive_body),
                    }
                    resealed_desc["evidence"]["files"][ev_auth_path] = {
                        "path": ev_auth_path,
                        "size": len(alt_authority_body),
                        "sha256": _sha(alt_authority_body),
                    }
                with self.assertRaisesRegex(AdmissionError, "TF_PYPI_RAW_RELEASE_HANDOFF_BINDING"):
                    publisher.validate_qualification_inputs_descriptor(
                        resealed_desc,
                        repository=repo_dir,
                        phase=publisher.QUALIFICATION_INPUT_PHASE_PREP,
                        inrun_root=inrun_root,
                        product_capture=held_capture,
                    )

                # Wrong compiler tree: test both caller-drifted provenance AND a genuine ReleaseCapture
                # whose own authenticated PROVENANCE.json has testedTree != tag.tree
                wrong_compiler_tree = dict(prov_doc, testedTree="9" * 40)
                with self.assertRaisesRegex(ContractError, "NEBULAR_UNIVERSAL_RELEASE_JOIN"):
                    consumer.join_product_native_release(
                        held_capture,
                        fx["product_source"],
                        upstream_rel,
                        native_record,
                        wrong_compiler_tree,
                        proof,
                        x64_asset,
                    )

                bad_tree_ev = base / "bad-tree-capture-evidence"
                shutil.copytree(inrun_root / "product-capture/evidence", bad_tree_ev)
                bad_prov_bytes = canonical(wrong_compiler_tree)
                (bad_tree_ev / "assets/nebular-v0.7.1-native-ci-provenance.json").write_bytes(bad_prov_bytes)
                bad_rel_doc = json.loads((bad_tree_ev / "api/release.json").read_bytes())
                for asset_row in bad_rel_doc["assets"]:
                    if asset_row["name"] == "nebular-v0.7.1-native-ci-provenance.json":
                        asset_row["size"] = len(bad_prov_bytes)
                        asset_row["digest"] = "sha256:" + _sha(bad_prov_bytes)
                (bad_tree_ev / "api/release.json").write_bytes(canonical(bad_rel_doc))
                bad_tree_capture = product_capture_mod.authenticate_release(
                    product_capture_mod.product_selection(), bad_tree_ev
                )
                with self.assertRaisesRegex(ContractError, "NEBULAR_UNIVERSAL_PRODUCT_CAPTURE"):
                    consumer.authenticated_product_release(bad_tree_capture)
                with self.assertRaisesRegex(ContractError, "NEBULAR_UNIVERSAL_RELEASE_JOIN"):
                    consumer.join_product_native_release(
                        bad_tree_capture,
                        fx["product_source"],
                        upstream_rel,
                         copy.deepcopy(bad_tree_capture.record),
                        wrong_compiler_tree,
                        proof,
                        x64_asset,
                        provenance_bytes=bad_prov_bytes,
                    )

    def test_generated_workflow_cli_commands_execute_end_to_end(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            fx = _build_complete_fixture(base)
            repo_dir = fx["repo_dir"]
            rs9_source = fx["rs9_source"]
            run_id = fx["run_id"]
            runner_temp = base / "runner-temp"
            runner_temp.mkdir(mode=0o700)

            rendered = workflow.qualify_jobs_text()

            def _subst(tokens: list[str]) -> list[str]:
                mapping = {
                    "${{ runner.temp }}": str(runner_temp),
                    "${{ steps.rs9_source.outputs.commit }}": rs9_source["commit"],
                    "${{ steps.rs9_source.outputs.tree }}": rs9_source["tree"],
                    "$(git rev-parse --verify HEAD^{tree})": rs9_source["tree"],
                    "$(git rev-parse --verify 'HEAD^{tree}')": rs9_source["tree"],
                    "$GITHUB_WORKSPACE": str(repo_dir),
                    "${{ github.sha }}": rs9_source["commit"],
                    "${{ github.run_id }}": run_id,
                    "${{ github.run_attempt }}": "1",
                }
                out = []
                for token in tokens:
                    for key, val in mapping.items():
                        token = token.replace(key, val)
                    out.append(token)
                return out

            prepare_cmd = _subst(_generated_command(rendered, "-m rs9.tf_pypi_nebular071_publish prepare-public-inputs-071"))
            prepare_argv = prepare_cmd[prepare_cmd.index("prepare-public-inputs-071"):]
            build_cmd = _subst(_generated_command(rendered, "-m rs9.tf_pypi_nebular071_universal build-bundle"))
            build_argv = build_cmd[build_cmd.index("build-bundle"):]
            qualify_cmd = _subst(_generated_command(rendered, "-m rs9.tf_pypi_nebular071_universal qualify-native"))
            qualify_argv = qualify_cmd[qualify_cmd.index("qualify-native"):]
            admit_cmd = _subst(_generated_command(rendered, "-m rs9.tf_pypi_nebular071_universal admit-matrix"))
            admit_argv = admit_cmd[admit_cmd.index("admit-matrix"):]

            # Extract the rendered Python heredoc snippet from _native_job ("Resolve explicit Linux runtime profile")
            py_start = rendered.index("-B - <<'PY'\n") + len("-B - <<'PY'\n")
            py_end = rendered.index("\n          PY\n", py_start)
            rendered_profile_snippet = "\n".join(
                line[10:] if line.startswith("          ") else line
                for line in rendered[py_start:py_end].splitlines()
            )

            hosted_env = {
                "GITHUB_ACTIONS": "true",
                "GITHUB_REPOSITORY": universal.REPOSITORY,
                "GITHUB_REF": "refs/heads/main",
                "GITHUB_SHA": rs9_source["commit"],
                "GITHUB_RUN_ID": run_id,
                "GITHUB_RUN_ATTEMPT": "1",
            }

            with mock.patch.object(publisher, "_git_output", side_effect=_git_output_stub(rs9_source)), \
                    mock.patch.object(
                        product_capture_mod,
                        "public_client",
                        side_effect=lambda **_kw: _SyntheticGitHubClient(fx["api_map"], fx["asset_map"]),
                    ), \
                    mock.patch.object(Path, "cwd", return_value=repo_dir), \
                    mock.patch.dict(os.environ, hosted_env, clear=False), \
                    mock.patch("sys.stdout", new_callable=io.StringIO):
                rc_prep = publisher.main(prepare_argv)
                self.assertEqual(rc_prep, 0)

                inrun_root = runner_temp / publication.PUBLIC_INPUTS
                self.assertTrue((inrun_root / "product-capture/selection.json").is_file())
                self.assertTrue((inrun_root / "product-capture/evidence/assets/SHA256SUMS").is_file())

                # Execute the rendered _native_job Python profile-resolution snippet
                profile_env = {
                    **hosted_env,
                    "GITHUB_WORKSPACE": str(repo_dir),
                    "INRUN_ROOT": str(inrun_root),
                    "QUALIFICATION_INPUTS": str(inrun_root / publisher.PUBLIC_INPUTS_DESCRIPTOR),
                }
                snippet_stdout = io.StringIO()
                with mock.patch.dict(os.environ, profile_env, clear=False), \
                        mock.patch("sys.stdout", snippet_stdout):
                    exec(compile(rendered_profile_snippet, "<rendered-_native_job>", "exec"), {})
                self.assertEqual(snippet_stdout.getvalue().strip(), publisher.SYSTEM_WEBKIT_RUNTIME_PROFILE)

                buf = io.BytesIO()
                stdout_stub = mock.Mock()
                stdout_stub.buffer = buf
                with mock.patch("sys.stdout", stdout_stub):
                    rc_build = universal.main(build_argv)
                self.assertEqual(rc_build, 0)
                bundle_dir = runner_temp / "tfnf-071-universal-bundle"
                self.assertTrue((bundle_dir / "bundle.json").is_file())
                self.assertTrue((bundle_dir / "dist" / wheel_builder.FILENAME).is_file())

                # Execute the rendered qualify-native CLI command up to the network_denial sandbox boundary
                cli_sandbox_calls = []

                def _cli_stop_at_sandbox(python_exe, node_exe, base_env, prefix):
                    cli_sandbox_calls.append((python_exe, node_exe, dict(base_env), tuple(prefix)))
                    raise _SandboxStopSentinel("cli qualify-native reached network_denial")

                with mock.patch.object(consumer_core, "_nebular_identity_observed", return_value={
                    "source": "runner", "system": "darwin", "machine": "arm64",
                }), \
                        mock.patch.object(publisher, "make_real_user_state_snapshotter", return_value=lambda _t, _p: {}), \
                        mock.patch.object(consumer_core, "node_binary", return_value=Path("/usr/bin/false")), \
                        mock.patch.object(consumer_core, "network_denial", side_effect=_cli_stop_at_sandbox):
                    with self.assertRaises(_SandboxStopSentinel):
                        universal.main(qualify_argv)
                self.assertEqual(len(cli_sandbox_calls), 1)
                self.assertTrue(
                    (runner_temp / "tfnf-071-universal-raw-release-darwin-arm64/raw_release.json").is_file()
                )
                self.assertTrue(
                    (runner_temp / "tfnf-071-universal-work-darwin-arm64/smoke-support/source/tools/native-rc-smoke.mjs").is_file()
                )

                # Populate newer and floor receipts for the generated admit-matrix CLI command
                receipts_dir = runner_temp / "tfnf-071-universal-receipts"
                floor_receipts_dir = runner_temp / "tfnf-071-universal-floor-receipts"
                for index, (target, role) in enumerate(
                    sorted(
                        {(t, "newer") for t in wheel_builder.LAYOUTS}
                        | {(t, "floor") for t in universal.LINUX_TARGETS}
                    ),
                    1,
                ):
                    rec = {
                        "identity": f"{index:064x}",
                        "target": target,
                        "role": role,
                        "host_observation": {"identity": f"{index + 100:064x}"},
                    }
                    t_dir = (receipts_dir if role == "newer" else floor_receipts_dir) / target
                    t_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
                    (t_dir / "result.json").write_bytes(canonical(rec))
                for index, target in enumerate(universal.LINUX_TARGETS, 1):
                    neg = {"identity": f"{index + 200:064x}"}
                    (floor_receipts_dir / target / "missing-runtime.json").write_bytes(canonical(neg))

                buf2 = io.BytesIO()
                stdout_stub2 = mock.Mock()
                stdout_stub2.buffer = buf2
                with mock.patch("sys.stdout", stdout_stub2), \
                        mock.patch.object(
                            universal.consumer,
                            "validate_universal_consumer",
                            side_effect=lambda value, *_args, **_kwargs: value,
                        ), \
                        mock.patch(
                            "rs9.nebular071_universal_missing.validate_missing_runtime",
                            side_effect=lambda value, *_args, **_kwargs: value,
                        ):
                    rc_admit = universal.main(admit_argv)
                self.assertEqual(rc_admit, 0)
                matrix_receipt_path = runner_temp / "tfnf-071-universal-matrix/matrix_receipt.json"
                self.assertTrue(matrix_receipt_path.is_file())


if __name__ == "__main__":
    unittest.main()
