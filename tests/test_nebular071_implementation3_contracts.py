"""Connected implementation-3 contracts for the version-isolated 0.7.1 owner.

These tests use bounded synthetic bytes only.  They exercise the maintained
source/archive, workflow/history, metadata transport, and publication custody
validators; they are not hosted qualification, native execution, or release
evidence.
"""
from __future__ import annotations

import copy
import hashlib
import io
import json
from pathlib import Path
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

from rs9 import nebular071_public_inputs as public_inputs  # noqa: E402
from rs9 import nebular071_smoke_support as smoke_support  # noqa: E402
from rs9 import nebular071_universal_history as history  # noqa: E402
from rs9 import nebular071_universal_profile as profile  # noqa: E402
from rs9 import nebular071_universal_publication as publication  # noqa: E402
from rs9 import tf_pypi_nebular071_universal as universal  # noqa: E402
from rs9 import nebular071_universal_workflow as workflow  # noqa: E402
from rs9 import nebular071_darwin_harness as darwin_harness  # noqa: E402
from rs9.errors import ContractError  # noqa: E402
from rs9.scratch import canonical  # noqa: E402
from rs9.tf_pypi_archive import AdmissionError  # noqa: E402


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _git_blob(data: bytes) -> str:
    header = b"blob " + str(len(data)).encode("ascii") + b"\0"
    return hashlib.sha1(header + data).hexdigest()


def _source_offer() -> tuple[bytes, bytes, dict, dict[str, bytes]]:
    paths = sorted(
        {f"tools/{name}" for name in smoke_support._REQUIRED_TOOLS}
        | set(smoke_support._REQUIRED_FIXTURES)
        | {"docs/examples/v0.4/brand-system/core-minimal/071-extra.txt"}
    )
    bodies = {path: ("071-source-member:" + path + "\n").encode("utf-8") for path in paths}
    archive_stream = io.BytesIO()
    with tarfile.open(
        fileobj=archive_stream, mode="w:gz", format=tarfile.USTAR_FORMAT
    ) as archive:
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
    authority_body = json.dumps(authority, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    archive_name = "theme-forge-nebular-fusion-v0.7.1-source.tar.gz"
    authority_name = "nebular-compiled-public-build-source-authority-v0.7.1.json"
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
        if path != "docs/examples/v0.4/brand-system/core-minimal/071-extra.txt"
    ]
    source = {
        "authority": "authenticated-product-source",
        "repository": smoke_support.SOURCE_REPOSITORY,
        "commit": "a" * 40,
        "tree": "b" * 40,
        "record_sha256": "c" * 64,
        "authority_identity": authority["identity"],
    }
    support = {
        "schema": smoke_support.SMOKE_SUPPORT_SCHEMA,
        "target": "linux-x64-gnu",
        "source": source,
        "root": "source",
        "tool_root": "tools",
        "fixture_root": "docs/examples/v0.4/brand-system/core-minimal",
        "files": source_files,
        "source_binding": {
            "archive": {"path": archive_name, "size": len(archive_body), "sha256": _sha(archive_body)},
            "authority": {"path": authority_name, "size": len(authority_body), "sha256": _sha(authority_body)},
        },
    }
    support["closure_sha256"] = smoke_support._closure_digest(support)
    return archive_body, authority_body, support, bodies


def _metadata_archive() -> tuple[bytes, dict, bytes, bytes]:
    notice_body = b"third-party notices for 071\n"
    source_body = b"authenticated source archive bytes\n"
    notice_path = "evidence/public-release/assets/nebular-v0.7.1-third-party-notices.tar.gz"
    source_path = "evidence/public-release/assets/theme-forge-nebular-fusion-v0.7.1-source.tar.gz"
    descriptor = {
        "schema": public_inputs.DESCRIPTOR_SCHEMA,
        "project": "theme-forge-nebular-fusion",
        "version": "0.7.1",
        "evidence": {
            "source_root": "evidence/public-release",
            "files": {
                "assets/nebular-v0.7.1-third-party-notices.tar.gz": {
                    "path": "assets/nebular-v0.7.1-third-party-notices.tar.gz",
                    "size": len(notice_body), "sha256": _sha(notice_body),
                },
                "assets/theme-forge-nebular-fusion-v0.7.1-source.tar.gz": {
                    "path": "assets/theme-forge-nebular-fusion-v0.7.1-source.tar.gz",
                    "size": len(source_body), "sha256": _sha(source_body),
                },
                "npm/package.tgz": {
                    "path": "npm/package.tgz",
                    "size": 11, "sha256": _sha(b"npm-wrapper"),
                },
            },
        },
        "raw_release": {
            "source_root": "raw-release",
            "payloads": [
                "raw-release/aarch64-apple-darwin.tar.gz",
                "raw-release/aarch64-unknown-linux-gnu.tar.gz",
                "raw-release/x86_64-unknown-linux-gnu.tar.gz",
            ],
        },
    }
    bodies = {
        "qualification-inputs.json": canonical(descriptor),
        notice_path: notice_body,
        source_path: source_body,
    }
    directories = {
        "evidence", "evidence/public-release", "evidence/public-release/assets", "raw-release"
    }
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz", format=tarfile.USTAR_FORMAT) as archive:
        for path in sorted(directories):
            info = tarfile.TarInfo(path)
            info.type = tarfile.DIRTYPE
            info.mode = 0o755
            info.mtime = 0
            archive.addfile(info)
        for path, body in bodies.items():
            info = tarfile.TarInfo(path)
            info.size = len(body)
            info.mode = 0o644
            info.mtime = 0
            archive.addfile(info, io.BytesIO(body))
    return stream.getvalue(), descriptor, notice_body, source_body


def _metadata_manifest(archive: bytes, descriptor: dict, payloads: dict[str, bytes]) -> dict:
    """Build a closed transport manifest for the real materializer boundary."""
    metadata_name = "nebular-v0.7.1-qualification-inputs.tar.gz"
    rows = []
    for index, (name, path) in enumerate((
        ("nebular-v0.7.1-aarch64-apple-darwin.tar.gz", "raw-release/aarch64-apple-darwin.tar.gz"),
        ("nebular-v0.7.1-aarch64-unknown-linux-gnu.tar.gz", "raw-release/aarch64-unknown-linux-gnu.tar.gz"),
        ("nebular-v0.7.1-x86_64-unknown-linux-gnu.tar.gz", "raw-release/x86_64-unknown-linux-gnu.tar.gz"),
        ("nebular-v0.7.1-npm.tgz", "evidence/public-release/npm/package.tgz"),
    ), 10):
        body = payloads[name]
        rows.append({
            "asset_id": index,
            "name": name,
            "url": "https://github.com/Knowledge-Forge-AI/theme-forge-nebular-fusion/releases/download/v0.7.1/" + name,
            "bytes": len(body),
            "sha256": _sha(body),
            "path": path,
        })
    return {
        "schema": public_inputs.SCHEMA,
        "repository": public_inputs.REPOSITORY,
        "version": "0.7.1",
        "release_id": 7101,
        "metadata": {
            "asset_id": 1,
            "name": metadata_name,
            "url": "https://github.com/Knowledge-Forge-AI/theme-forge-nebular-fusion/releases/download/v0.7.1/" + metadata_name,
            "bytes": len(archive),
            "sha256": _sha(archive),
        },
        "payloads": rows,
    }


def _file_record(size: int, digest: str) -> dict[str, object]:
    return {"size": size, "sha256": digest}


def _zip_members(members: dict[str, bytes]) -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, body in members.items():
            archive.writestr(name, body)
    return stream.getvalue()


def _authority(seed: int) -> dict:
    wheel_sha = ("e" * 64)
    matrix_sha = ("d" * 64)
    artifacts = {}
    for index, name in enumerate(publication.ARTIFACTS, 1000 + seed * 100):
        if name == publication.PUBLIC_INPUTS:
            files = {publication.DESCRIPTOR_MEMBER: _file_record(1, "a" * 64)}
        elif name == publication.BUNDLE:
            files = {
                "bundle.json": _file_record(1, "a" * 64),
                "universal-build-receipt.json": _file_record(1, "b" * 64),
                "dist/" + publication.builder.FILENAME: _file_record(1, wheel_sha),
            }
        elif name == publication.MATRIX:
            files = {publication.MATRIX_MEMBER: _file_record(1, matrix_sha)}
        elif name in publication.QUALIFICATION.values():
            target = next(target for target, artifact in publication.QUALIFICATION.items() if artifact == name)
            files = {target + "/result.json": _file_record(1, "a" * 64)}
        else:
            target = next(target for target, artifact in publication.FLOOR.items() if artifact == name)
            files = {
                target + "/result.json": _file_record(1, "a" * 64),
                target + "/missing-runtime.json": _file_record(1, "b" * 64),
            }
        artifacts[name] = {
            "id": index,
            "size_in_bytes": 1,
            "archive_sha256": "f" * 64,
            "files": files,
        }
    unsigned = {
        "schema": publication.SCHEMA,
        "project": publication.PROJECT,
        "version": publication.builder.VERSION,
        "distribution": publication.consumer.DISTRIBUTION,
        "workflow": publication.WORKFLOW,
        "environment": publication.ENVIRONMENT,
        "repository": publication.REPOSITORY,
        "source": {"commit": "1" * 40, "tree": "2" * 40},
        "run": {"id": str(7100 + seed), "attempt": "1"},
        "wheel": {
            "filename": publication.builder.FILENAME,
            "tag": publication.consumer.TAG,
            "version": publication.builder.VERSION,
            "size": 1,
            "sha256": wheel_sha,
        },
        "runtime_inputs_sha256": "a" * 64,
        "runtime_index_sha256": "b" * 64,
        "description_sha256": "c" * 64,
        "matrix_sha256": matrix_sha,
        "api": {name: _file_record(1, "a" * 64) for name in publication.API_FILES},
        "artifacts": artifacts,
    }
    return {**unsigned, "identity": publication._sha(canonical(unsigned))}


class Implementation3ContractTests(unittest.TestCase):
    def setUp(self):
        from test_nebular071_simulated_native_fixture import install_simulated_native_domain
        install_simulated_native_domain(self)

    def test_fresh_source_offer_accepts_nonhistorical_member_count_and_rejects_tamper(self):
        archive_body, authority_body, support, bodies = _source_offer()
        self.assertNotEqual(len(bodies) + 1, 1559)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "inputs"
            source = root / "source"
            source.mkdir(parents=True)
            (source / support["source_binding"]["archive"]["path"]).write_bytes(archive_body)
            (source / support["source_binding"]["authority"]["path"]).write_bytes(authority_body)
            result = smoke_support.verify_source_binding(root, support, expected_source=support["source"])
            self.assertEqual(result["member_count"], len(bodies))
            self.assertEqual(result["archive_sha256"], _sha(archive_body))
            (source / support["source_binding"]["archive"]["path"]).write_bytes(archive_body + b"tamper")
            with self.assertRaises((ContractError, AdmissionError)):
                smoke_support.verify_source_binding(root, support)
            bad_authority = json.loads(authority_body)
            bad_authority["identity"] = "0" * 64
            (source / support["source_binding"]["archive"]["path"]).write_bytes(archive_body)
            (source / support["source_binding"]["authority"]["path"]).write_bytes(
                json.dumps(bad_authority, sort_keys=True, separators=(",", ":")).encode()
            )
            with self.assertRaises((ContractError, AdmissionError)):
                smoke_support.verify_source_binding(root, support)
            wrong_composition = json.loads(authority_body)
            wrong_composition["composition"] = "0" * 64
            wrong_composition["identity"] = smoke_support._js_identity({
                key: value for key, value in wrong_composition.items() if key != "identity"
            })
            wrong_body = json.dumps(
                wrong_composition, sort_keys=True, separators=(",", ":")
            ).encode()
            bad_support = copy.deepcopy(support)
            bad_support["source_binding"]["authority"]["sha256"] = _sha(wrong_body)
            bad_support["closure_sha256"] = smoke_support._closure_digest(bad_support)
            (source / support["source_binding"]["authority"]["path"]).write_bytes(wrong_body)
            with self.assertRaises((ContractError, AdmissionError)):
                smoke_support.verify_source_binding(root, bad_support)

    def test_opaque_source_and_notice_members_are_descriptor_bound(self):
        archive, descriptor, notice_body, source_body = _metadata_archive()
        entries = public_inputs._archive_members(archive)
        checked, _evidence_root, _raw_root, _digest = public_inputs._descriptor_from_entries(entries)
        public_inputs._validate_opaque_metadata(entries, checked)
        bad = copy.deepcopy(checked)
        path = "assets/nebular-v0.7.1-third-party-notices.tar.gz"
        bad["evidence"]["files"][path]["sha256"] = "0" * 64
        with self.assertRaises(ContractError):
            public_inputs._validate_opaque_metadata(entries, bad)
        self.assertEqual(descriptor["evidence"]["files"][path]["size"], len(notice_body))
        self.assertEqual(descriptor["evidence"]["files"]["assets/theme-forge-nebular-fusion-v0.7.1-source.tar.gz"]["size"], len(source_body))

    def test_opaque_members_survive_actual_materializer_descriptor_boundary(self):
        archive, descriptor, _notice_body, _source_body = _metadata_archive()
        payloads = {
            "nebular-v0.7.1-aarch64-apple-darwin.tar.gz": b"darwin-payload",
            "nebular-v0.7.1-aarch64-unknown-linux-gnu.tar.gz": b"arm-payload",
            "nebular-v0.7.1-x86_64-unknown-linux-gnu.tar.gz": b"x64-payload",
            "nebular-v0.7.1-npm.tgz": b"npm-wrapper",
        }
        manifest = _metadata_manifest(archive, descriptor, payloads)

        class Client:
            def __init__(self):
                self.calls = []

            def get(self, url, **_kwargs):
                self.calls.append(url)
                if url == manifest["metadata"]["url"]:
                    return archive
                for row in manifest["payloads"]:
                    if url == row["url"]:
                        return payloads[row["name"]]
                raise AssertionError("unexpected transport URL")

        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "materialized"
            receipt = public_inputs.materialize_public_inputs(manifest, output, client=Client())
            self.assertEqual(receipt["descriptor"]["source_roots"]["evidence"], "evidence/public-release")
            self.assertEqual(
                (output / "evidence/public-release/assets/nebular-v0.7.1-third-party-notices.tar.gz").read_bytes(),
                b"third-party notices for 071\n",
            )
            self.assertEqual(
                (output / "evidence/public-release/assets/theme-forge-nebular-fusion-v0.7.1-source.tar.gz").read_bytes(),
                b"authenticated source archive bytes\n",
            )
            self.assertEqual(
                (output / "evidence/public-release/npm/package.tgz").read_bytes(), b"npm-wrapper"
            )


    def test_darwin_harness_restores_strict_unchanged_helper_carrier(self):
        valid = {
            "schema": "rs9.nebular071-darwin-process-harness.v1",
            "source_sha256": "874355e36496884e55a6e4dae6986ecde817d20863bb3fe26d1b1b5a1d283e69",
            "derived_sha256": "d5c042b44be74319084d2f635e1ed97633c367e7fd1777a3c94ad99900fc9320",
            "transform": "authenticated-darwin-pgrep-snapshot-v1",
            "process_tool": "/usr/bin/pgrep",
        }
        self.assertEqual(darwin_harness.validate_darwin_harness(valid), valid)
        for key in ("source_sha256", "derived_sha256"):
            bad = dict(valid)
            bad[key] = "0" * 64
            with self.assertRaises((ContractError, AdmissionError)):
                darwin_harness.validate_darwin_harness(bad)
        with self.assertRaises((ContractError, AdmissionError)):
            darwin_harness.validate_darwin_harness({**valid, "source_binding": {}})

    def test_rendered_history_derives_all_qualifying_jobs_and_rejects_mode_drift(self):
        document = workflow.complete_workflow_text()
        profiles = history._profiles()
        self.assertEqual(set(profiles), set(history._profiles()))
        self.assertEqual(
            tuple(sorted(row["id"] for row in profiles.values()
                         if row["id"].startswith("universal_")
                         and row["id"] != "universal_publication_071")),
            workflow.rendered_qualification_job_ids(document),
        )
        run = {
            "id": 7101,
            "workflow_id": 7102,
            "head_sha": "a" * 40,
            "head_branch": "main",
            "event": "workflow_dispatch",
            "status": "completed",
            "conclusion": "success",
            "repository": {"full_name": history.legacy.DEFAULT_GITHUB_REPOSITORY},
            "path": ".github/workflows/" + profile.WORKFLOW,
            "run_attempt": 1,
            "display_title": "RS9 theme-forge-nebular-fusion 0.7.1 " + workflow.QUALIFY_MODE + " /",
            "inputs": {"release": "0.7.1", "mode": workflow.QUALIFY_MODE},
        }
        jobs = []
        for index, (name, row) in enumerate(sorted(profiles.items()), 1):
            qualifying = row["id"].startswith("universal_") and name != history.PUBLISH_JOB
            jobs.append({
                "id": 9000 + index,
                "run_id": run["id"],
                "run_attempt": 1,
                "name": name,
                "head_sha": run["head_sha"],
                "status": "completed",
                "conclusion": "success" if qualifying else "skipped",
                "labels": [row["label"]] if qualifying else [],
                "steps": ([
                    {"name": step, "number": step_index, "status": "completed", "conclusion": "success"}
                    for step_index, step in enumerate(sorted(row["declared"]), 1)
                ] if qualifying else []),
            })
        qualified = history.validate_qualification_jobs(run, jobs)
        self.assertEqual(len(qualified), len(workflow.rendered_qualification_job_ids(document)))
        drifted = dict(run)
        drifted["inputs"] = {"release": "0.7.1", "mode": "qualify"}
        with self.assertRaises(ContractError):
            history.validate_qualification_jobs(drifted, jobs)

    def test_publication_custody_accepts_five_bound_authorities_and_rejects_two_tamperings(self):
        for seed in range(1, 6):
            checked = publication.validate_authority(_authority(seed))
            self.assertEqual(checked["identity"], publication._sha(canonical({k: v for k, v in checked.items() if k != "identity"})))
        bad_matrix = _authority(6)
        bad_matrix["artifacts"][publication.MATRIX]["files"][publication.MATRIX_MEMBER]["sha256"] = "0" * 64
        with self.assertRaises(ContractError):
            publication.validate_authority(bad_matrix)
        bad_bundle = _authority(7)
        del bad_bundle["artifacts"][publication.BUNDLE]["files"]["bundle.json"]
        with self.assertRaises(ContractError):
            publication.validate_authority(bad_bundle)

    def test_connected_matrix_join_runs_five_positive_and_two_missing_runtime_lanes(self):
        targets = tuple(universal.builder.LAYOUTS)
        source = {"commit": "a" * 40, "tree": "b" * 40}
        snapshot = {
            "wheel": {"filename": universal.builder.FILENAME, "tag": universal.consumer.TAG,
                      "version": universal.builder.VERSION, "size": 17, "sha256": "c" * 64},
            "runtime_inputs_sha256": "d" * 64,
            "runtime_index_sha256": "e" * 64,
        }
        captures = {
            target: {"payload_sha256": (str(index + 1) * 64)[:64],
                     "manifest_sha256": (str(index + 4) * 64)[:64]}
            for index, target in enumerate(targets)
        }
        positives = {}
        for index, (target, role) in enumerate(
            sorted({(target, "newer") for target in targets} | {
                (target, "floor") for target in universal.LINUX_TARGETS
            }), 1
        ):
            positives[target, role] = {
                "identity": (f"{index:064x}"),
                "target": target,
                "role": role,
                "host_observation": {"identity": (f"{index + 100:064x}")},
            }
        negatives = {
            target: {"identity": (f"{index + 200:064x}")}
            for index, target in enumerate(universal.LINUX_TARGETS, 1)
        }
        positive_calls = []
        missing_calls = []

        def positive(value, seen_snapshot, capture, **kwargs):
            positive_calls.append((value, seen_snapshot, capture, kwargs))
            self.assertIs(seen_snapshot, snapshot)
            self.assertEqual(kwargs["source"], source)
            self.assertEqual(kwargs["run_id"], "7101")
            self.assertEqual(kwargs["run_attempt"], "1")
            return value

        def missing(value, target, *, source, run_id, run_attempt, snapshot, host_identity):
            missing_calls.append((value, target, source, run_id, run_attempt, snapshot, host_identity))
            self.assertIs(snapshot, seen_snapshot_for_missing[0])
            return value

        seen_snapshot_for_missing = [snapshot]
        with mock.patch.object(universal.consumer, "validate_universal_consumer", side_effect=positive), \
                mock.patch("rs9.nebular071_universal_missing.validate_missing_runtime", side_effect=missing):
            result = universal.validate_matrix_receipts(
                snapshot, captures, positives, negatives,
                source=source, run_id="7101", run_attempt="1",
            )
        self.assertEqual(len(positive_calls), 5)
        self.assertEqual(len(missing_calls), 2)
        self.assertEqual(len(result["lanes"]), 5)
        self.assertEqual({(row["target"], row["role"]) for row in positives.values()},
                         {(row["target"], row["role"]) for row in result["lanes"]})
        self.assertFalse(result["publication_admitted"])
        self.assertFalse(result["fixture_only"])

    def test_publication_capture_readback_reuses_connected_matrix_join(self):
        """Exercise verify_capture with the same real matrix/readback function."""
        source = {"commit": "a" * 40, "tree": "b" * 40}
        run_id = "7101"
        wheel_body = b"W"
        snapshot = {
            "wheel": {"filename": universal.builder.FILENAME, "tag": universal.consumer.TAG,
                      "version": universal.builder.VERSION, "size": len(wheel_body),
                      "sha256": _sha(wheel_body)},
            "runtime_inputs_sha256": "d" * 64,
            "runtime_index_sha256": "e" * 64,
        }
        captures = {
            target: {"payload_sha256": f"{index + 1:064x}",
                     "manifest_sha256": f"{index + 4:064x}"}
            for index, target in enumerate(universal.builder.LAYOUTS)
        }
        positives = {}
        for index, (target, role) in enumerate(
            sorted({(target, "newer") for target in universal.builder.LAYOUTS} | {
                (target, "floor") for target in universal.LINUX_TARGETS
            }), 1
        ):
            positives[target, role] = {
                "identity": f"{index:064x}", "target": target, "role": role,
                "host_observation": {"identity": f"{index + 100:064x}"},
            }
        negatives = {
            target: {"identity": f"{index + 200:064x}"}
            for index, target in enumerate(universal.LINUX_TARGETS, 1)
        }

        def read_matrix(_bundle, _inputs, _inrun, _receipts, _floors, _work, **kwargs):
            self.assertIsNotNone(kwargs.get("product_capture"))
            return universal.validate_matrix_receipts(
                snapshot, captures, positives, negatives,
                source=source, run_id=run_id, run_attempt="1",
            )

        with mock.patch.object(universal.consumer, "validate_universal_consumer",
                               side_effect=lambda value, *_args, **_kwargs: value), \
                mock.patch("rs9.nebular071_universal_missing.validate_missing_runtime",
                            side_effect=lambda value, *_args, **_kwargs: value):
            matrix = universal.validate_matrix_receipts(
                snapshot, captures, positives, negatives,
                source=source, run_id=run_id, run_attempt="1",
            )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            product_root = root / "product-capture"
            try:
                from tests.test_nebular071_implementation6_release_capture import _capture as _product_capture
            except ImportError:
                from test_nebular071_implementation6_release_capture import _capture as _product_capture
            selection, _capture = _product_capture(product_root / "evidence")
            selection_path = product_root / "selection.json"
            selection_path.write_bytes(canonical(selection))
            public_inputs_members = {publication.DESCRIPTOR_MEMBER: b"descriptor"}
            for file_path in sorted(product_root.rglob("*")):
                if file_path.is_file():
                    rel = "product-capture/" + file_path.relative_to(product_root).as_posix()
                    public_inputs_members[rel] = file_path.read_bytes()

            members = {
                publication.PUBLIC_INPUTS: public_inputs_members,
                publication.BUNDLE: {
                    "bundle.json": b"bundle",
                    "universal-build-receipt.json": b"receipt",
                    "dist/" + universal.builder.FILENAME: wheel_body,
                },
                publication.MATRIX: {publication.MATRIX_MEMBER: canonical(matrix)},
            }
            for target, name in publication.QUALIFICATION.items():
                members[name] = {target + "/result.json": b"newer"}
            for target, name in publication.FLOOR.items():
                members[name] = {
                    target + "/result.json": b"floor",
                    target + "/missing-runtime.json": b"missing",
                }
            archives = {name: _zip_members(files) for name, files in members.items()}
            artifact_rows = {}
            for index, name in enumerate(publication.ARTIFACTS, 7100):
                artifact_rows[name] = {
                    "id": index,
                    "size_in_bytes": len(archives[name]),
                    "archive_sha256": _sha(archives[name]),
                    "files": {
                        path: _file_record(len(body), _sha(body))
                        for path, body in members[name].items()
                    },
                }
            run = {
                "id": int(run_id), "run_attempt": 1, "status": "completed",
                "conclusion": "success", "event": "workflow_dispatch", "head_branch": "main",
                "head_sha": source["commit"],
                "path": ".github/workflows/" + publication.WORKFLOW,
                "repository": {"full_name": publication.REPOSITORY},
                "head_repository": {"full_name": publication.REPOSITORY},
                "head_commit": {"id": source["commit"], "tree_id": source["tree"]},
            }
            api_documents = {
                "run.json": run,
                "artifacts.json": {
                    "total_count": len(artifact_rows),
                    "artifacts": [
                        {
                            "id": row["id"], "name": name,
                            "size_in_bytes": row["size_in_bytes"],
                            "digest": "sha256:" + row["archive_sha256"], "expired": False,
                            "archive_download_url": "https://api.github.com/repos/"
                            + publication.REPOSITORY + "/actions/artifacts/" + str(row["id"]) + "/zip",
                            "workflow_run": {"id": int(run_id), "head_sha": source["commit"],
                                             "head_branch": "main"},
                        }
                        for name, row in artifact_rows.items()
                    ],
                },
                "jobs.json": {"total_count": 1, "jobs": [{"id": 1, "name": "071 matrix"}]},
            }
            api_records = {name: json.dumps(value, sort_keys=True).encode()
                           for name, value in api_documents.items()}
            authority_unsigned = {
                "schema": publication.SCHEMA, "project": publication.PROJECT, "version": universal.builder.VERSION,
                "distribution": universal.consumer.DISTRIBUTION, "workflow": publication.WORKFLOW,
                "environment": publication.ENVIRONMENT, "repository": publication.REPOSITORY,
                "source": source, "run": {"id": run_id, "attempt": "1"},
                "wheel": snapshot["wheel"],
                "runtime_inputs_sha256": snapshot["runtime_inputs_sha256"],
                "runtime_index_sha256": snapshot["runtime_index_sha256"],
                "description_sha256": _sha(b"# Nebular 0.7.1\n"),
                "matrix_sha256": _sha(canonical(matrix)),
                "api": {name: _file_record(len(body), _sha(body)) for name, body in api_records.items()},
                "artifacts": artifact_rows,
            }
            authority = {**authority_unsigned, "identity": _sha(canonical(authority_unsigned))}

            api_root = root / "api"
            archive_root = root / "archives"
            api_root.mkdir()
            archive_root.mkdir()
            for name, body in api_records.items():
                (api_root / name).write_bytes(body)
            for name, body in archives.items():
                (archive_root / (name + ".zip")).write_bytes(body)
            repository = root / "qualification"
            description = repository / universal.DESCRIPTION
            description.parent.mkdir(parents=True)
            description.write_bytes(b"# Nebular 0.7.1\n")
            history_stub = mock.Mock()
            history_stub.validate_qualification_jobs.return_value = None
            with mock.patch.object(publication, "_history", return_value=history_stub), \
                    mock.patch.object(universal, "load_bundle", return_value=(
                        {"wheel": snapshot["wheel"],
                         "description_sha256": _sha(b"# Nebular 0.7.1\n")}, snapshot)), \
                    mock.patch.object(universal, "read_matrix_inputs", side_effect=read_matrix), \
                    mock.patch.object(universal.consumer, "validate_universal_consumer",
                                      side_effect=lambda value, *_args, **_kwargs: value), \
                    mock.patch("rs9.nebular071_universal_missing.validate_missing_runtime",
                               side_effect=lambda value, *_args, **_kwargs: value):
                context = publication.verify_capture(
                    authority, api_root, archive_root, root / "capture", repository=repository,
                )
        self.assertEqual(context["wheel"], wheel_body)
        self.assertEqual(context["matrix_identity"], matrix["identity"])


if __name__ == "__main__":
    unittest.main()
