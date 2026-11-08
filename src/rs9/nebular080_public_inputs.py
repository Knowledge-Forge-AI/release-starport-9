"""Closed 0.8 public-input and raw-release descriptor validation."""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from pathlib import Path
import re
from typing import Any

from rs9.tf_pypi_archive import AdmissionError, canonical, physical_bytes, sha256
from rs9.tf_pypi_model import strict_json
from rs9.errors import ContractError

from rs9.nebular080_publication_coordinates import (
    GATE1_PROFILE_PATH,
    PUBLIC_INPUTS_DESCRIPTOR,
    PUBLIC_INPUTS_PREPARATION_RECEIPT,
    PUBLIC_INPUTS_PREPARATION_SCHEMA,
    QUALIFICATION_INPUT_PHASES,
    QUALIFICATION_INPUT_PHASE_PREP,
    QUALIFICATION_INPUT_PHASE_PUBLICATION,
    QUALIFICATION_INPUTS_SCHEMA,
    RAW_RELEASE_HANDOFF_SCHEMA,
    REQUIRED_QUALIFICATION_INPUTS_KEYS,
    SYSTEM_WEBKIT_INPUT_KEYS,
    SYSTEM_WEBKIT_INPUT_SCHEMA,
    SYSTEM_WEBKIT_PROFILE_ID,
    SYSTEM_WEBKIT_RUNTIME_PROFILE,
    SYSTEM_PUBLIC_INPUTS_PREPARATION_SCHEMA,
    PROJECT,
    VERSION,
    DISTRIBUTION_VERSION,
    TAG,
    WORKFLOW,
    REPOSITORY,
    TARGETS,
    PUBLIC_STAGE_A_SPEC,
)
from rs9.nebular080_universal_profile import SCHEMAS
from rs9.tf_pypi_universal_support import (
    _check_no_symlinks,
    _resolve_inrun_artifact_root,
    _resolve_repo_contained_dir,
    _validate_file_digest_entry,
    fail,
    read_regular_file,
    repo_root,
    resolve_inrun_artifact_root,
    validate_repo_relative_dir_spec,
    write_exclusive,
)


_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_REQUIRED_EVIDENCE = frozenset({
    "api/release.json", "api/repository.json", "api/ref.json", "api/commit.json",
    "api/tree.json", "assets/SHA256SUMS", "assets/PROVENANCE.json", "npm/metadata.json",
    "npm/package.tgz", "source/LICENSE", "source/NOTICE",
})
_REQUIRED_BINDING = frozenset({
    "schema", "release", "application_version", "distribution_version", "repository",
    "tag", "bootstrap_path", "expectations_path", "profile_path", "status", "lineage",
    "provenance", "expected",
})
_REQUIRED_RAW = frozenset({
    "record", "readme", "legal_files", "payload", "manifest", "provenance",
    "native_consumer", "product_source",
})


def _copy_json(value: Any) -> Any:
    try:
        return json.loads(canonical(value))
    except (TypeError, ValueError, UnicodeError):
        fail("QUALIFICATION_INPUTS_SCHEMA")
    raise AssertionError("unreachable")


def _hex(value: Any, length: int) -> bool:
    pattern = _HEX40 if length == 40 else _HEX64
    return isinstance(value, str) and bool(pattern.fullmatch(value))


def _safe_source(value: Any, *, code: str = "QUALIFICATION_INPUTS_SOURCE") -> dict[str, str]:
    expected = {"authority", "repository", "commit", "tree", "record_sha256", "authority_identity"}
    if (
        not isinstance(value, Mapping)
        or set(value) != expected
        or value.get("authority") != "authenticated-product-source"
        or value.get("repository") != REPOSITORY
        or not _hex(value.get("commit"), 40)
        or not _hex(value.get("tree"), 40)
        or not _hex(value.get("record_sha256"), 64)
        or not _hex(value.get("authority_identity"), 64)
    ):
        fail(code)
    return {key: str(value[key]) for key in sorted(expected)}


def validate_system_webkit_input_spec(value: Any) -> dict[str, str]:
    if (
        not isinstance(value, Mapping)
        or set(value) != SYSTEM_WEBKIT_INPUT_KEYS
        or value.get("schema") != SYSTEM_WEBKIT_INPUT_SCHEMA
        or value.get("origin_kind") != "public-in-run"
        or value.get("profile_id") != SYSTEM_WEBKIT_PROFILE_ID
    ):
        fail("SYSTEM_WEBKIT_INPUT")
    return dict(value)


_validate_system_webkit_input_spec = validate_system_webkit_input_spec


def validate_qualification_input_phase(phase: Any) -> str:
    if not isinstance(phase, str) or phase not in QUALIFICATION_INPUT_PHASES:
        fail("QUALIFICATION_INPUTS_PHASE")
    return phase


_validate_qualification_input_phase = validate_qualification_input_phase


def _validate_url(value: Any, *, host: str, tag: str) -> str:
    if not isinstance(value, str) or "\n" in value or "\r" in value:
        fail("QUALIFICATION_INPUTS_ORIGIN")
    prefix = f"https://{host}/"
    if not value.startswith(prefix) or value != value.strip() or "@" in value:
        fail("QUALIFICATION_INPUTS_ORIGIN")
    if not value.endswith(tag) or "?" in value or "#" in value:
        fail("QUALIFICATION_INPUTS_ORIGIN")
    return value


def _validate_origin(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != {
        "repository", "tag", "release_url", "api_release_url",
    }:
        fail("QUALIFICATION_INPUTS_ORIGIN")
    repository = value.get("repository")
    if not isinstance(repository, str) or repository != REPOSITORY:
        fail("QUALIFICATION_INPUTS_ORIGIN")
    if value.get("tag") != TAG:
        fail("QUALIFICATION_INPUTS_ORIGIN")
    _validate_url(value.get("release_url"), host="github.com", tag=f"/releases/tag/{TAG}")
    _validate_url(value.get("api_release_url"), host="api.github.com", tag=f"/repos/{REPOSITORY}/releases/tags/{TAG}")
    return dict(value)


def _validate_binding(binding: Any, *, product_source: Mapping[str, str], repository_root: Path) -> dict[str, Any]:
    if not isinstance(binding, Mapping) or set(binding) != _REQUIRED_BINDING:
        fail("QUALIFICATION_INPUTS_BINDING")
    if (
        binding.get("schema") != "rs9.nebular080-release-binding.v1alpha1"
        or binding.get("release") != VERSION
        or binding.get("application_version") != VERSION
        or binding.get("distribution_version") != DISTRIBUTION_VERSION
        or binding.get("repository") != product_source.get("repository")
        or binding.get("tag") != TAG
        or binding.get("status") != "ready"
        or binding.get("lineage") != {
            "mode": "direct-tag-provenance-equality",
            "requires_historical_author_rewrite": False,
        }
    ):
        fail("QUALIFICATION_INPUTS_BINDING")
    for field in ("bootstrap_path", "expectations_path", "profile_path"):
        value = binding.get(field)
        if (
            not isinstance(value, str)
            or not value
            or value.startswith("/")
            or "\\" in value
            or any(part in ("", ".", "..") for part in Path(value).parts)
        ):
            fail("QUALIFICATION_INPUTS_BINDING")
    if binding["profile_path"] != str(GATE1_PROFILE_PATH):
        fail("QUALIFICATION_INPUTS_BINDING")
    provenance = binding.get("provenance")
    if (
        not isinstance(provenance, Mapping)
        or set(provenance) != {"path", "commit_field", "tree_field"}
        or tuple(provenance.get(key) for key in ("path", "commit_field", "tree_field"))
        not in {
            ("PROVENANCE.json", "tagCommit", "tagTree"),
            ("PROVENANCE.json", "releaseCommit", "testedTree"),
            ("PYPI-INTAKE-PROVENANCE.json", "releaseCommit", "testedTree"),
        }
    ):
        fail("QUALIFICATION_INPUTS_BINDING")
    expected = binding.get("expected")
    if (
        not isinstance(expected, Mapping)
        or set(expected) != {
            "repository_id", "release_id", "tag_commit", "tag_tree",
            "bootstrap_sha256", "expectations_sha256",
        }
        or type(expected.get("repository_id")) is not int
        or expected["repository_id"] <= 0
        or type(expected.get("release_id")) is not int
        or expected["release_id"] <= 0
        or expected.get("tag_commit") != product_source.get("commit")
        or expected.get("tag_tree") != product_source.get("tree")
        or not _hex(expected.get("tag_commit"), 40)
        or not _hex(expected.get("tag_tree"), 40)
        or not _hex(expected.get("bootstrap_sha256"), 64)
        or not _hex(expected.get("expectations_sha256"), 64)
    ):
        fail("QUALIFICATION_INPUTS_BINDING")
    for field, code in (("bootstrap_path", "BOOTSTRAP_SYMLINK"), ("expectations_path", "EXPECTATIONS_SYMLINK")):
        path = repository_root / binding[field]
        _check_no_symlinks(path, code)
        if not path.is_file():
            fail("RELEASE_INPUTS_PENDING")
        try:
            data = physical_bytes(path, limit=1024 * 1024)
        except Exception:
            fail("RELEASE_INPUTS_PENDING")
        if sha256(data) != expected[field.replace("_path", "_sha256")]:
            fail("GATE1_" + field.split("_")[0].upper() + "_DIGEST_MISMATCH")
    return _copy_json(binding)


_validate_080_release_binding = _validate_binding


def _validate_target_file(value: Any, *, code: str = "QUALIFICATION_INPUTS_RAW_RELEASE") -> dict[str, Any]:
    return _validate_file_digest_entry(value, code=code)


def validate_descriptor_target_raw_release(
    target: str,
    entry: Any,
    *,
    evidence_files: Mapping[str, Any],
    expected_product_source: Mapping[str, str],
    system_webkit: bool = True,
) -> None:
    if target not in TARGETS or not isinstance(entry, Mapping):
        fail("QUALIFICATION_INPUTS_RAW_RELEASE")
    allowed = _REQUIRED_RAW | {
        "schema", "target", "candidate_receipt_sha256", "expected_artifact_record_sha256",
        "profile_result_sha256", "wheel_sha256",
    }
    if not _REQUIRED_RAW.issubset(entry) or not set(entry) <= allowed:
        fail("QUALIFICATION_INPUTS_RAW_RELEASE")
    if entry.get("schema", RAW_RELEASE_HANDOFF_SCHEMA) != RAW_RELEASE_HANDOFF_SCHEMA:
        fail("QUALIFICATION_INPUTS_RAW_RELEASE")
    if "target" in entry and entry["target"] != target:
        fail("RAW_RELEASE_HANDOFF_BINDING")
    for field in ("record", "readme", "payload", "manifest", "provenance"):
        checked = _validate_target_file(entry.get(field))
        if checked["path"] in evidence_files and checked != _validate_target_file(evidence_files[checked["path"]], code="QUALIFICATION_INPUTS_EVIDENCE"):
            fail("QUALIFICATION_INPUTS_RAW_RELEASE")
    legal = entry.get("legal_files")
    if not isinstance(legal, Mapping) or set(legal) != {"LICENSE", "NOTICE", "COMMERCIAL-LICENSE.md"}:
        fail("QUALIFICATION_INPUTS_RAW_RELEASE")
    for item in legal.values():
        _validate_target_file(item)
    source = _safe_source(entry.get("product_source"), code="RAW_RELEASE_HANDOFF_BINDING")
    if source != dict(expected_product_source):
        fail("RAW_RELEASE_HANDOFF_BINDING")
    native = entry.get("native_consumer")
    if not isinstance(native, Mapping) or target not in native:
        fail("QUALIFICATION_INPUTS_RAW_RELEASE")
    checked_native = native[target]
    if not isinstance(checked_native, Mapping) or "smoke_support" not in checked_native:
        fail("QUALIFICATION_INPUTS_RAW_RELEASE")
    if system_webkit and set(native) != {target} and target.startswith("linux"):
        fail("QUALIFICATION_INPUTS_RAW_RELEASE")
    try:
        from rs9.nebular080_smoke_support import validate_smoke_support
        validate_smoke_support(
            checked_native["smoke_support"], target,
            evidence_files=evidence_files, descriptor=True,
        )
    except (AdmissionError, ContractError, KeyError, TypeError, ValueError, ImportError):
        fail("QUALIFICATION_INPUTS_RAW_RELEASE")
    for field in (
        "candidate_receipt_sha256", "expected_artifact_record_sha256",
        "profile_result_sha256", "wheel_sha256",
    ):
        if field in entry and not _hex(entry[field], 64):
            fail("QUALIFICATION_INPUTS_RAW_RELEASE")


_validate_descriptor_target_raw_release = validate_descriptor_target_raw_release


def _resolve_evidence_root(
    document: Mapping[str, Any],
    *,
    repository_root: Path,
    inrun_root: str | Path | None,
    system_spec: Mapping[str, Any],
) -> Path:
    root = resolve_inrun_artifact_root(
        repository_root, None, inrun_root, system_webkit_spec=system_spec,
    )
    evidence = document.get("evidence")
    if not isinstance(evidence, Mapping):
        fail("QUALIFICATION_INPUTS_EVIDENCE")
    relative = validate_repo_relative_dir_spec(evidence.get("source_root"), code="QUALIFICATION_INPUTS_EVIDENCE")
    return _resolve_repo_contained_dir(
        root, relative, symlink_code="EVIDENCE_SYMLINK",
        missing_code="RELEASE_INPUTS_PENDING", containment_code="QUALIFICATION_INPUTS_EVIDENCE",
    )


def validate_qualification_inputs_descriptor(
    document: Mapping[str, Any],
    *,
    repository: str | Path | None = None,
    pending_code: str = "RELEASE_INPUTS_PENDING",
    phase: str = QUALIFICATION_INPUT_PHASE_PUBLICATION,
    inrun_root: str | Path | None = None,
    product_capture: Any = None,
) -> dict[str, Any]:
    validate_qualification_input_phase(phase)
    if not isinstance(document, Mapping):
        fail("QUALIFICATION_INPUTS_SCHEMA")
    if document.get("status") == "pending":
        fail(pending_code)
    if (
        not REQUIRED_QUALIFICATION_INPUTS_KEYS.issubset(document)
        or not set(document) <= REQUIRED_QUALIFICATION_INPUTS_KEYS | {"system_webkit", "manylinux"}
        or document.get("schema") != QUALIFICATION_INPUTS_SCHEMA
        or document.get("project") != PROJECT
        or document.get("version") != VERSION
        or document.get("distribution_version") != DISTRIBUTION_VERSION
        or document.get("workflow") != WORKFLOW
        or document.get("status") != "ready"
    ):
        fail("QUALIFICATION_INPUTS_SCHEMA")
    if "manylinux" in document or "system_webkit" not in document:
        fail("QUALIFICATION_INPUTS_RUNTIME_PROFILE")
    system_spec = validate_system_webkit_input_spec(document["system_webkit"])
    origin = _validate_origin(document.get("upstream_origin"))
    root = repo_root(repository)
    source_hint = document.get("product_source")
    if source_hint is None and isinstance(product_capture, Mapping):
        source_hint = product_capture.get("product_source")
    if source_hint is None:
        raw_hint = document.get("raw_release")
        raw_targets = raw_hint.get("targets") if isinstance(raw_hint, Mapping) else None
        if isinstance(raw_targets, Mapping) and raw_targets:
            first_target = next(iter(raw_targets.values()))
            if isinstance(first_target, Mapping):
                source_hint = first_target.get("product_source")
    binding_source = source_hint if source_hint is not None else {
        "authority": "authenticated-product-source", "repository": REPOSITORY,
        "commit": "0" * 40, "tree": "0" * 40,
        "record_sha256": "0" * 64, "authority_identity": "0" * 64,
    }
    expected_source = _safe_source(binding_source)
    binding = _validate_binding(
        document.get("release_binding"), product_source=expected_source, repository_root=root,
    )
    if (
        not _hex(document.get("release_binding_sha256"), 64)
        or sha256(canonical(binding)) != document.get("release_binding_sha256")
    ):
        fail("QUALIFICATION_INPUTS_BINDING")
    evidence_root = _resolve_evidence_root(
        document, repository_root=root, inrun_root=inrun_root, system_spec=system_spec,
    )
    evidence = document["evidence"]
    evidence_files = evidence.get("files")
    if not isinstance(evidence_files, Mapping) or not _REQUIRED_EVIDENCE <= set(evidence_files):
        fail("QUALIFICATION_INPUTS_EVIDENCE")
    for path, entry in evidence_files.items():
        if not isinstance(path, str) or path.startswith("/") or "\\" in path or ".." in Path(path).parts:
            fail("QUALIFICATION_INPUTS_EVIDENCE")
        checked = _validate_file_digest_entry(entry, code="QUALIFICATION_INPUTS_EVIDENCE")
        if checked.get("path") != path:
            fail("QUALIFICATION_INPUTS_EVIDENCE")
        disk = evidence_root / path
        _check_no_symlinks(disk, "EVIDENCE_SYMLINK")
        if not disk.is_file():
            fail(pending_code)
    raw = document.get("raw_release")
    if not isinstance(raw, Mapping) or set(raw) != {"source_root", "targets"}:
        fail("QUALIFICATION_INPUTS_RAW_RELEASE")
    raw_root = validate_repo_relative_dir_spec(raw.get("source_root"), code="QUALIFICATION_INPUTS_RAW_RELEASE")
    artifact_root = resolve_inrun_artifact_root(
        root, None, inrun_root, system_webkit_spec=system_spec,
    )
    _resolve_repo_contained_dir(
        artifact_root, raw_root, symlink_code="RAW_RELEASE_SYMLINK",
        missing_code=pending_code, containment_code="QUALIFICATION_INPUTS_RAW_RELEASE",
    )
    targets = raw.get("targets")
    if not isinstance(targets, Mapping) or set(targets) != set(TARGETS):
        fail("QUALIFICATION_INPUTS_RAW_RELEASE")
    for target in TARGETS:
        validate_descriptor_target_raw_release(
            target, targets[target], evidence_files=evidence_files,
            expected_product_source=expected_source, system_webkit=True,
        )
    checked = _copy_json(document)
    checked["system_webkit"] = system_spec
    checked["upstream_origin"] = origin
    checked["release_binding"] = binding
    return checked


def load_qualification_inputs_descriptor(
    path: str | Path | None = None,
    *,
    repository: str | Path | None = None,
    pending_code: str = "RELEASE_INPUTS_PENDING",
    phase: str = QUALIFICATION_INPUT_PHASE_PUBLICATION,
    inrun_root: str | Path | None = None,
    product_capture: Any = None,
) -> dict[str, Any]:
    root = repo_root(repository)
    candidate = Path(path) if path is not None else root / "operators/tf-pypi" / "theme-forge-nebular-fusion-0.8.0-qualification-inputs.json"
    if not candidate.is_absolute() and (root / candidate).exists():
        candidate = root / candidate
    _check_no_symlinks(candidate, "QUALIFICATION_INPUTS_SYMLINK")
    if not candidate.is_file():
        fail(pending_code)
    try:
        document = strict_json(read_regular_file(candidate, limit=4 * 1024 * 1024, code="QUALIFICATION_INPUTS_SCHEMA"))
    except (AdmissionError, ValueError, TypeError):
        fail("QUALIFICATION_INPUTS_SCHEMA")
    return validate_qualification_inputs_descriptor(
        document, repository=root, pending_code=pending_code, phase=phase,
        inrun_root=inrun_root, product_capture=product_capture,
    )


def stage_native_ci_evidence(
    capsule_root: str | Path,
    inrun_root: str | Path,
    descriptor: Mapping[str, Any],
) -> dict[str, Any]:
    """Stage fixed NativeRC evidence rows for a separate-process replay.

    ``capsule_root`` is the already authenticated native-evidence capsule
    root.  Only the native owner's fixed descriptor rows are copied into the
    caller-owned in-run root; payload archives and unrelated capsule files are
    never copied.  The descriptor rows are checked before each exclusive
    destination write, and partial owned output is removed on failure.
    """
    try:
        from rs9.nebular080_product_native import _descriptor_names
    except (ImportError, AttributeError):
        fail("QUALIFICATION_INPUTS_EVIDENCE")
    evidence = descriptor.get("evidence") if isinstance(descriptor, Mapping) else None
    declared = evidence.get("files") if isinstance(evidence, Mapping) else None
    if (
        not isinstance(evidence, Mapping)
        or evidence.get("source_root") != "evidence/public-release"
        or not isinstance(declared, Mapping)
    ):
        fail("QUALIFICATION_INPUTS_EVIDENCE")
    expected = {"native-ci/" + name for name in _descriptor_names()}
    rows = {
        key: value
        for key, value in declared.items()
        if isinstance(key, str) and key.startswith("native-ci/")
    }
    if set(rows) != expected:
        fail("QUALIFICATION_INPUTS_EVIDENCE")
    source = Path(capsule_root)
    run_root = Path(inrun_root)
    if (
        not source.is_absolute()
        or not run_root.is_absolute()
        or source == run_root
        or not source.is_dir()
        or not run_root.is_dir()
    ):
        fail("QUALIFICATION_INPUTS_ROOT")
    _check_no_symlinks(source, "QUALIFICATION_INPUTS_EVIDENCE")
    _check_no_symlinks(run_root, "QUALIFICATION_INPUTS_ROOT")
    destination = run_root / "evidence" / "public-release" / "native-ci"
    descriptor_digest = sha256(canonical(descriptor))
    _check_no_symlinks(destination.parent, "EVIDENCE_SYMLINK")
    if destination.exists() or destination.is_symlink():
        fail("PUBLIC_INPUTS_OUTPUT")
    created: list[Path] = []
    created_dirs: list[Path] = []
    try:
        try:
            destination.mkdir(parents=True, mode=0o700)
        except OSError:
            fail("PUBLIC_INPUTS_OUTPUT")
        created_dirs.append(destination)
        for relative in sorted(expected):
            row = rows[relative]
            if not isinstance(row, Mapping) or set(row) != {"path", "size", "sha256"}:
                fail("QUALIFICATION_INPUTS_EVIDENCE")
            if row.get("path") != relative:
                fail("QUALIFICATION_INPUTS_EVIDENCE")
            checked = _validate_file_digest_entry(row, code="QUALIFICATION_INPUTS_EVIDENCE")
            if checked != dict(row):
                fail("QUALIFICATION_INPUTS_EVIDENCE")
            source_path = source / relative.removeprefix("native-ci/")
            _check_no_symlinks(source_path, "EVIDENCE_SYMLINK")
            body = read_regular_file(
                source_path,
                limit=min(int(row["size"]), 512 * 1024 * 1024),
                code="RELEASE_INPUTS_PENDING",
            )
            if len(body) != row["size"] or sha256(body) != row["sha256"]:
                fail("QUALIFICATION_INPUTS_EVIDENCE")
            target = destination / relative.removeprefix("native-ci/")
            _check_no_symlinks(target.parent, "EVIDENCE_SYMLINK")
            pending_dirs: list[Path] = []
            cursor = target.parent
            while not cursor.exists():
                pending_dirs.append(cursor)
                cursor = cursor.parent
            _check_no_symlinks(cursor, "EVIDENCE_SYMLINK")
            for directory in reversed(pending_dirs):
                try:
                    directory.mkdir(mode=0o700)
                except OSError:
                    fail("PUBLIC_INPUTS_OUTPUT")
                created_dirs.append(directory)
            _check_no_symlinks(target.parent, "EVIDENCE_SYMLINK")
            write_exclusive(target, body, code="PUBLIC_INPUTS_OUTPUT")
            # Record ownership only after the exclusive writer succeeds.  A
            # race that places a foreign leaf before the write must preserve
            # that leaf during failure cleanup.
            created.append(target)
    except Exception:
        for path in reversed(created):
            try:
                path.unlink()
            except OSError:
                pass
        for directory in reversed(created_dirs):
            try:
                directory.rmdir()
            except OSError:
                pass
        raise
    return {
        "schema": "rs9.nebular080-native-ci-staging.v1",
        "root": "evidence/public-release/native-ci",
        "descriptor_sha256": descriptor_digest,
        "file_count": len(rows),
        "bytes": sum(int(row["size"]) for row in rows.values()),
        "files": {key: dict(rows[key]) for key in sorted(rows)},
    }


def prepare_public_inputs_080(
    manifest: str | Path,
    output: str | Path,
    *,
    repository: str | Path | None = None,
    rs9_source: Mapping[str, str],
    product_capture: Any = None,
    stage_a_spec: str = PUBLIC_STAGE_A_SPEC,
) -> dict[str, Any]:
    """Stage a descriptor already present in a bounded local manifest."""
    root = repo_root(repository)
    manifest_path = Path(manifest)
    if manifest_path.is_absolute() or not isinstance(rs9_source, Mapping) or set(rs9_source) != {"commit", "tree"}:
        fail("PUBLIC_INPUTS_MANIFEST")
    if not _hex(rs9_source.get("commit"), 40) or not _hex(rs9_source.get("tree"), 40):
        fail("PUBLIC_INPUTS_SOURCE")
    manifest_path = root / manifest_path
    _check_no_symlinks(manifest_path, "PUBLIC_INPUTS_MANIFEST")
    if not manifest_path.is_file():
        fail("PUBLIC_INPUTS_MANIFEST")
    if not isinstance(stage_a_spec, str) or Path(stage_a_spec).is_absolute() or ".." in Path(stage_a_spec).parts:
        fail("PUBLIC_INPUTS_STAGE_A_SPEC")
    output_path = Path(output)
    if not output_path.is_absolute() or output_path.exists() or output_path.is_symlink():
        fail("PUBLIC_INPUTS_OUTPUT")
    try:
        raw_manifest = read_regular_file(manifest_path, limit=4 * 1024 * 1024, code="PUBLIC_INPUTS_MANIFEST")
        source_doc = strict_json(raw_manifest)
    except (AdmissionError, ValueError, TypeError):
        fail("PUBLIC_INPUTS_MANIFEST")
    descriptor = source_doc.get("descriptor") if isinstance(source_doc, Mapping) else None
    if not isinstance(descriptor, Mapping):
        descriptor = source_doc if isinstance(source_doc, Mapping) else None
    if not isinstance(descriptor, Mapping):
        fail("PUBLIC_INPUTS_DESCRIPTOR")
    try:
        checked = validate_qualification_inputs_descriptor(
            descriptor, repository=root, phase=QUALIFICATION_INPUT_PHASE_PREP,
            product_capture=product_capture,
        )
    except AdmissionError:
        raise
    try:
        output_path.mkdir(parents=True, mode=0o700)
        descriptor_path = output_path / PUBLIC_INPUTS_DESCRIPTOR
        write_exclusive(descriptor_path, canonical(checked), code="PUBLIC_INPUTS_OUTPUT")
        receipt = {
            "schema": SYSTEM_PUBLIC_INPUTS_PREPARATION_SCHEMA if "system_webkit" in checked else PUBLIC_INPUTS_PREPARATION_SCHEMA,
            "status": "held",
            "manifest": {"path": manifest.relative_to(root).as_posix(), "sha256": sha256(raw_manifest)},
            "descriptor": {"path": PUBLIC_INPUTS_DESCRIPTOR, "sha256": sha256(canonical(checked)), "bytes": len(canonical(checked))},
            "source": dict(rs9_source),
        }
        write_exclusive(output_path / PUBLIC_INPUTS_PREPARATION_RECEIPT, canonical(receipt), code="PUBLIC_INPUTS_OUTPUT")
        return receipt
    except Exception:
        try:
            for child in output_path.iterdir():
                child.unlink()
            output_path.rmdir()
        except OSError:
            pass
        raise


_prepare_public_inputs_080 = prepare_public_inputs_080

