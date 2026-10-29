"""Runtime file adapter for the maintained Nebular 0.7 Stage-A assembler.

The public payload assembler intentionally accepts values, not paths.  This
small adapter is the boundary for an external, immutable input bundle: every
referenced file is opened without following links, bounded, hashed, and then
passed as detached bytes to :func:`assemble_public_payload`.  Repository
identity is taken from the checked checkout at invocation time, so a metadata
bundle cannot self-assert the current RS9 source.

This module does not produce qualification facts.  It only joins an already
authenticated runtime manifest, receipts, origins, and body records to the
maintained assembler and emits its returned Stage-A envelope.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import subprocess
from pathlib import Path
from typing import Any, Mapping

from rs9.errors import ContractError
from rs9.nebular070_payload import LINUX_TARGETS
from rs9.nebular070_public_payload import (
    BODY_KINDS,
    PRODUCT_COMMIT,
    PRODUCT_TREE,
    assemble_public_payload,
)
from rs9.scratch import ConfinedWriter, canonical, physical_directory
from rs9.security import validate_safe_relative_posix_path


SCHEMA = "rs9.nebular070-public-stage-a-files.v1"
OUTPUT_SCHEMA = "rs9.nebular070-public-stage-a-output.v1"
VERSION = "0.7.0"
MAX_SPEC_BYTES = 2 * 1024 * 1024
MAX_BODY_BYTES = 8 * 1024 * 1024
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_OUTPUT_BYTES = 32 * 1024 * 1024
HEX64 = set("0123456789abcdef")
PROTECTED_COMPONENTS = frozenset({
    ".git", ".serena", "RAW", "DB", "SQL", "sql", ".ninja_deps", ".ninja_log",
    ".cargo", "credentials", "secrets",
})
GIT_SELECTOR_ENV = frozenset({
    "GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_NAMESPACE",
    "GIT_CEILING_DIRECTORIES", "GIT_DISCOVERY_ACROSS_FILESYSTEM",
    "GIT_CONFIG", "GIT_CONFIG_COUNT", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM",
    "GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_PARAMETERS",
})
GIT_CONFIG_ENV_PREFIXES = ("GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_")
TARGETS = tuple(LINUX_TARGETS)
FILE_REF_FIELDS = frozenset({"path", "bytes", "sha256"})
SPEC_FIELDS = frozenset({
    "schema", "version", "product_source", "producer_source", "runtime_manifest",
    "runtime_inputs", "source_origins", "bodies", "artifact_metadata",
})


def _error(code: str, message: str) -> ContractError:
    return ContractError(code, message)


def _owned_directory(value: str | Path, label: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise _error("STAGE_A_PATH", f"{label} must be absolute")
    directory = physical_directory(path)
    info = directory.stat()
    if info.st_uid != os.getuid() or info.st_mode & 0o022:
        raise _error("STAGE_A_PATH", f"{label} is not a private owned directory")
    return directory


def _hex(value: Any, length: int, label: str) -> str:
    if not isinstance(value, str) or len(value) != length or set(value) - HEX64:
        raise _error("STAGE_A_SCHEMA", f"{label} is malformed")
    return value


def _source(value: Any, label: str) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != {"commit", "tree"}:
        raise _error("STAGE_A_SCHEMA", f"{label} is not a closed source coordinate")
    return {"commit": _hex(value["commit"], 40, f"{label}.commit"),
            "tree": _hex(value["tree"], 40, f"{label}.tree")}


def qualification_checked_checkout(
    repository: str | Path,
    expected_commit: str,
    expected_tree: str,
) -> None:
    """Apply the existing qualification checkout contract without a branch gate.

    The maintained publication ``operator.checked_checkout`` is deliberately
    stricter: it is an attended ``main``-branch review gate.  Native/public
    qualification runs may use a clean detached/actions checkout, so this
    helper mirrors the existing ``build_candidates_bundle(require_clean=True)``
    contract: exact HEAD commit/tree and no tracked or untracked worktree
    changes, with no branch or caller-selected checkout hook.
    """
    root = _owned_directory(repository, "repository")
    _hex(expected_commit, 40, "expected RS9 commit")
    _hex(expected_tree, 40, "expected RS9 tree")

    git_env = dict(os.environ)
    for name in tuple(git_env):
        if name in GIT_SELECTOR_ENV or any(name.startswith(prefix) for prefix in GIT_CONFIG_ENV_PREFIXES):
            git_env.pop(name, None)

    def git(*args: str) -> str:
        try:
            completed = subprocess.run(
                ["git", "-C", str(root), *args],
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=30,
                env=git_env,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise _error("STAGE_A_SOURCE", "qualification checkout inspection failed") from exc
        if completed.returncode != 0:
            raise _error("STAGE_A_SOURCE", "qualification checkout inspection failed")
        return completed.stdout.strip()

    if (
        git("rev-parse", "--verify", "HEAD^{commit}") != expected_commit
        or git("rev-parse", "--verify", "HEAD^{tree}") != expected_tree
    ):
        raise _error("STAGE_A_SOURCE", "qualification checkout differs from expected source")
    if git("status", "--porcelain", "--untracked-files=all") != "":
        raise _error("STAGE_A_SOURCE", "qualification checkout is dirty")


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _reject_constant(value: str) -> Any:
    raise ValueError(value)


def _json(raw: bytes, label: str) -> dict[str, Any]:
    if not raw or len(raw) > MAX_BODY_BYTES:
        raise _error("STAGE_A_INPUT", f"{label} exceeds its bounded size")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                           parse_constant=_reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise _error("STAGE_A_INPUT", f"{label} is not strict JSON") from exc
    if not isinstance(value, dict):
        raise _error("STAGE_A_INPUT", f"{label} must contain an object")
    return value


def _safe_relative(value: Any, label: str) -> str:
    try:
        validate_safe_relative_posix_path(value, label)
    except ContractError:
        raise
    if any(part in PROTECTED_COMPONENTS for part in value.split("/")):
        raise _error("STAGE_A_PATH", f"{label} names a protected component")
    return value


def _file_ref(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != FILE_REF_FIELDS:
        raise _error("STAGE_A_SCHEMA", f"{label} is not a closed file reference")
    path = _safe_relative(value["path"], f"{label}.path")
    if type(value["bytes"]) is not int or value["bytes"] < 1 or value["bytes"] > MAX_MANIFEST_BYTES:
        raise _error("STAGE_A_SCHEMA", f"{label}.bytes is malformed")
    digest = _hex(value["sha256"], 64, f"{label}.sha256")
    return {"path": path, "bytes": value["bytes"], "sha256": digest}


def _open_relative(root: Path, relative: str, label: str) -> tuple[int, int]:
    """Open a relative leaf while retaining its descriptor parent."""
    flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
    parent_fd = os.open(root, flags)
    try:
        parts = relative.split("/")
        for part in parts[:-1]:
            child_fd = os.open(part, flags, dir_fd=parent_fd)
            os.close(parent_fd)
            parent_fd = child_fd
        leaf_fd = os.open(parts[-1], os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_fd)
        return leaf_fd, parent_fd
    except OSError as exc:
        os.close(parent_fd)
        raise _error("STAGE_A_INPUT", f"{label} cannot be opened") from exc


def _read_ref(root: Path, ref: Any, label: str, *, limit: int) -> bytes:
    checked = _file_ref(ref, label)
    try:
        fd, directory_fd = _open_relative(root, checked["path"], label)
    except ContractError:
        raise
    try:
        first = os.fstat(fd)
        if not stat.S_ISREG(first.st_mode) or first.st_size != checked["bytes"] or first.st_size > limit:
            raise _error("STAGE_A_INPUT", f"{label} is not the declared bounded regular file")
        chunks: list[bytes] = []
        remaining = first.st_size
        while remaining:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                raise _error("STAGE_A_INPUT", f"{label} ended before its declared size")
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        final = os.fstat(fd)
        if ((final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns)
                != (first.st_dev, first.st_ino, first.st_size, first.st_mtime_ns)):
            raise _error("STAGE_A_INPUT", f"{label} changed while being read")
    except OSError as exc:
        raise _error("STAGE_A_INPUT", f"{label} could not be read") from exc
    finally:
        os.close(fd)
        os.close(directory_fd)
    if len(raw) != checked["bytes"] or hashlib.sha256(raw).hexdigest() != checked["sha256"]:
        raise _error("STAGE_A_INPUT", f"{label} digest does not match its declaration")
    return raw


def _read_unbound(root: Path, relative: str, label: str) -> bytes:
    """Read a phase artifact before its digest entry exists."""
    fd, directory_fd = _open_relative(root, relative, label)
    try:
        first = os.fstat(fd)
        if not stat.S_ISREG(first.st_mode) or first.st_size < 1 or first.st_size > MAX_OUTPUT_BYTES:
            raise _error("STAGE_A_INPUT", f"{label} is not a bounded regular file")
        chunks: list[bytes] = []
        remaining = first.st_size
        while remaining:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                raise _error("STAGE_A_INPUT", f"{label} ended before its declared size")
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        final = os.fstat(fd)
        if (final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns) != (
                first.st_dev, first.st_ino, first.st_size, first.st_mtime_ns):
            raise _error("STAGE_A_INPUT", f"{label} changed while being read")
        return raw
    except OSError as exc:
        raise _error("STAGE_A_INPUT", f"{label} could not be read") from exc
    finally:
        os.close(fd)
        os.close(directory_fd)


def _read_absolute_json(path: Path, label: str) -> tuple[bytes, dict[str, Any]]:
    parent = _owned_directory(path.parent, f"{label} parent")
    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    try:
        fd = os.open(path.name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_fd)
    except OSError as exc:
        os.close(parent_fd)
        raise _error("STAGE_A_INPUT", f"{label} cannot be opened") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size < 1 or info.st_size > MAX_SPEC_BYTES:
            raise _error("STAGE_A_INPUT", f"{label} is not a bounded regular file")
        raw = os.read(fd, info.st_size + 1)
        if len(raw) != info.st_size:
            raise _error("STAGE_A_INPUT", f"{label} could not be read completely")
        final = os.fstat(fd)
        if (final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns) != (
                info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns):
            raise _error("STAGE_A_INPUT", f"{label} changed while being read")
    except OSError as exc:
        raise _error("STAGE_A_INPUT", f"{label} could not be read") from exc
    finally:
        os.close(fd)
        os.close(parent_fd)
    return raw, _json(raw, label)


def _atomic_descriptor_write(path: Path, raw: bytes) -> None:
    parent = _owned_directory(path.parent, "descriptor output parent")
    if path.exists() or path.is_symlink():
        raise _error("STAGE_A_OUTPUT", "descriptor output must be fresh")
    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    temporary = f".{path.name}.stage-a-{os.getpid()}"
    fd = None
    created = False
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=parent_fd)
        created = True
        offset = 0
        while offset < len(raw):
            offset += os.write(fd, raw[offset:])
        os.fsync(fd)
        os.close(fd)
        fd = None
        os.link(temporary, path.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd, follow_symlinks=False)
        os.unlink(temporary, dir_fd=parent_fd)
        created = False
        os.fsync(parent_fd)
    except OSError as exc:
        if fd is not None:
            os.close(fd)
        if created:
            try:
                os.unlink(temporary, dir_fd=parent_fd)
            except OSError:
                pass
        raise _error("STAGE_A_OUTPUT", "descriptor output could not be committed") from exc
    finally:
        os.close(parent_fd)


def bind_descriptor_phase(
    *,
    descriptor_path: str | Path,
    stage_file: str,
    output_path: str | Path,
    repository: str | Path,
    inrun_root: str | Path,
    phase: str,
) -> dict[str, Any]:
    """Bind one held Stage-A/Stage-B file through the maintained validator.

    ``stage_file`` is relative to ``inrun_root``; when it is relative to the
    descriptor's declared evidence root, that root is prepended.  The input
    descriptor is never modified.  A ready candidate is validated for the
    requested preparation/publication phase before a fresh output descriptor
    is atomically installed.
    """
    from rs9.tf_pypi_nebular070_publish import (
        QUALIFICATION_INPUT_PHASE_PREP,
        QUALIFICATION_INPUT_PHASE_PUBLICATION,
        validate_qualification_inputs_descriptor,
    )
    if phase not in {QUALIFICATION_INPUT_PHASE_PREP, QUALIFICATION_INPUT_PHASE_PUBLICATION}:
        raise _error("STAGE_A_PHASE", "descriptor phase is not supported")
    repository_root = _owned_directory(repository, "repository")
    artifact_root = _owned_directory(inrun_root, "in-run root")
    descriptor_raw, document = _read_absolute_json(Path(descriptor_path), "descriptor")
    evidence = document.get("evidence")
    if not isinstance(evidence, Mapping) or not isinstance(evidence.get("source_root"), str):
        raise _error("STAGE_A_SCHEMA", "descriptor evidence root is required")
    evidence_root = _safe_relative(evidence["source_root"], "descriptor evidence root")
    stage_rel = _safe_relative(stage_file, "stage file")
    if stage_rel == evidence_root or stage_rel.startswith(evidence_root + "/"):
        evidence_rel = stage_rel[len(evidence_root):].lstrip("/")
        artifact_rel = stage_rel
    else:
        evidence_rel = stage_rel
        artifact_rel = evidence_root + "/" + stage_rel
    if not evidence_rel:
        raise _error("STAGE_A_PATH", "stage file must name a file below the evidence root")
    raw = _read_unbound(artifact_root, artifact_rel, "stage file")
    entry = {"path": evidence_rel, "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    candidate = json.loads(json.dumps(document))
    files = candidate.get("evidence", {}).get("files")
    manylinux = candidate.get("manylinux")
    if not isinstance(files, dict) or not isinstance(manylinux, dict):
        raise _error("STAGE_A_SCHEMA", "descriptor evidence and manylinux bindings are required")
    role = "stage_a" if phase == QUALIFICATION_INPUT_PHASE_PREP else "stage_b"
    files[evidence_rel] = entry
    manylinux[role] = entry
    candidate["status"] = "ready"
    validated = validate_qualification_inputs_descriptor(
        candidate, repository=repository_root, phase=phase, inrun_root=artifact_root,
    )
    output = Path(output_path)
    new_raw = canonical(validated)
    _atomic_descriptor_write(output, new_raw)
    return {
        "schema": "rs9.nebular070-public-descriptor-bind.v1",
        "status": "pass",
        "phase": phase,
        "role": role,
        "old_descriptor_sha256": hashlib.sha256(descriptor_raw).hexdigest(),
        "new_descriptor_sha256": hashlib.sha256(new_raw).hexdigest(),
        "stage_file": entry,
    }


def _refs(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise _error("STAGE_A_SCHEMA", f"{label} fields are not closed")
    return {key: value[key] for key in keys}


def _validate_spec(spec: Mapping[str, Any]) -> dict[str, Any]:
    if set(spec) != SPEC_FIELDS or spec.get("schema") != SCHEMA or spec.get("version") != VERSION:
        raise _error("STAGE_A_SCHEMA", "Stage-A file specification is not the maintained version")
    product = _source(spec["product_source"], "product_source")
    producer = _source(spec["producer_source"], "producer_source")
    if product != {"commit": PRODUCT_COMMIT, "tree": PRODUCT_TREE}:
        raise _error("STAGE_A_SOURCE", "product_source is not the authenticated product source")
    runtime_inputs = _refs(spec["runtime_inputs"], set(TARGETS), "runtime_inputs")
    origins = _refs(spec["source_origins"], set(TARGETS), "source_origins")
    metadata = _refs(spec["artifact_metadata"], set(TARGETS), "artifact_metadata")
    bodies = _refs(spec["bodies"], set(TARGETS), "bodies")
    normalized_bodies: dict[str, dict[str, Any]] = {}
    for target in TARGETS:
        runtime_inputs[target] = _refs(runtime_inputs[target], {"closed_manifest", "runtime_receipt"},
                                       f"runtime_inputs.{target}")
        bodies[target] = _refs(bodies[target], set(BODY_KINDS), f"bodies.{target}")
        normalized_bodies[target] = dict(bodies[target])
    normalized = {
        "schema": SCHEMA, "version": VERSION, "product_source": product,
        "producer_source": producer, "runtime_manifest": _file_ref(spec["runtime_manifest"], "runtime_manifest"),
        "runtime_inputs": runtime_inputs, "source_origins": origins,
        "bodies": normalized_bodies, "artifact_metadata": metadata,
    }
    return normalized


def _read_inputs(root: Path, spec: Mapping[str, Any]) -> dict[str, Any]:
    inputs: dict[str, Any] = {
        "product_source": spec["product_source"],
        "producer_source": spec["producer_source"],
        "runtime_manifest": _read_ref(root, spec["runtime_manifest"], "runtime_manifest", limit=MAX_MANIFEST_BYTES),
        "runtime_inputs": {}, "source_origins": {}, "bodies": {}, "artifact_metadata": {},
    }
    for target in TARGETS:
        lane = spec["runtime_inputs"][target]
        inputs["runtime_inputs"][target] = {
            key: _read_ref(root, lane[key], f"runtime_inputs.{target}.{key}", limit=MAX_MANIFEST_BYTES)
            for key in ("closed_manifest", "runtime_receipt")
        }
        inputs["source_origins"][target] = _read_ref(root, spec["source_origins"][target],
                                                       f"source_origins.{target}", limit=MAX_MANIFEST_BYTES)
        inputs["artifact_metadata"][target] = _read_ref(root, spec["artifact_metadata"][target],
                                                          f"artifact_metadata.{target}", limit=MAX_BODY_BYTES)
        inputs["bodies"][target] = {
            kind: _read_ref(root, spec["bodies"][target][kind], f"bodies.{target}.{kind}", limit=MAX_BODY_BYTES)
            for kind in BODY_KINDS
        }
    return inputs


def _new_output(root: Path, relative: str) -> tuple[Path, int, int, str]:
    relative = _safe_relative(relative, "output")
    parts = relative.split("/")
    current_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    try:
        for part in parts[:-1]:
            try:
                os.mkdir(part, 0o700, dir_fd=current_fd)
            except FileExistsError:
                pass
            child_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0), dir_fd=current_fd)
            os.close(current_fd)
            current_fd = child_fd
        os.mkdir(parts[-1], 0o700, dir_fd=current_fd)
        output_fd = os.open(parts[-1], os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0), dir_fd=current_fd)
        output = root.joinpath(*parts)
        return output, current_fd, output_fd, parts[-1]
    except OSError as exc:
        os.close(current_fd)
        raise _error("STAGE_A_OUTPUT", "fresh output directory could not be created") from exc


def _cleanup_output(
    parent_fd: int,
    leaf: str,
    output_fd: int,
    identity: tuple[int, int],
    owned_files: Mapping[str, tuple[int, int, int]],
) -> None:
    try:
        now = os.fstat(output_fd)
        if (now.st_dev, now.st_ino) != identity:
            return
        with os.scandir(output_fd) as entries:
            for entry in entries:
                expected = owned_files.get(entry.name)
                info = entry.stat(follow_symlinks=False)
                actual = (info.st_dev, info.st_ino, info.st_size)
                if expected is None or not entry.is_file(follow_symlinks=False) or actual != expected:
                    return
                os.unlink(entry.name, dir_fd=output_fd)
        os.rmdir(leaf, dir_fd=parent_fd)
    except (OSError, ValueError):
        # Losing custody must never turn into deletion of a replacement path.
        return


def assemble_stage_a_files(
    *,
    repository: str | Path,
    input_root: str | Path,
    spec: str,
    output: str,
    expected_rs9_commit: str,
    expected_rs9_tree: str,
    expected_tf_producer_commit: str,
    expected_tf_producer_tree: str,
) -> dict[str, Any]:
    repo = _owned_directory(repository, "repository")
    root = _owned_directory(input_root, "input_root")
    spec_rel = _safe_relative(spec, "spec")
    spec_fd, spec_parent_fd = _open_relative(root, spec_rel, "spec")
    try:
        spec_stat = os.fstat(spec_fd)
        if not stat.S_ISREG(spec_stat.st_mode) or spec_stat.st_size < 1 or spec_stat.st_size > MAX_SPEC_BYTES:
            raise _error("STAGE_A_INPUT", "spec is not a bounded regular file")
        chunks: list[bytes] = []
        remaining = spec_stat.st_size
        while remaining:
            chunk = os.read(spec_fd, min(1024 * 1024, remaining))
            if not chunk:
                raise _error("STAGE_A_INPUT", "spec ended before its declared size")
            chunks.append(chunk)
            remaining -= len(chunk)
        spec_raw = b"".join(chunks)
        final_stat = os.fstat(spec_fd)
        if (final_stat.st_dev, final_stat.st_ino, final_stat.st_size, final_stat.st_mtime_ns) != (
                spec_stat.st_dev, spec_stat.st_ino, spec_stat.st_size, spec_stat.st_mtime_ns):
            raise _error("STAGE_A_INPUT", "spec changed while being read")
    finally:
        os.close(spec_fd)
        os.close(spec_parent_fd)
    parsed = _validate_spec(_json(spec_raw, "spec"))
    rs9 = _source({"commit": expected_rs9_commit, "tree": expected_rs9_tree}, "expected RS9 source")
    producer = _source({"commit": expected_tf_producer_commit, "tree": expected_tf_producer_tree}, "expected TF source")
    if parsed["producer_source"] != producer:
        raise _error("STAGE_A_SOURCE", "spec producer source does not match the expected TF source")
    qualification_checked_checkout(repo, rs9["commit"], rs9["tree"])
    inputs = _read_inputs(root, parsed)
    inputs["rs9_tool_source"] = rs9
    envelope = assemble_public_payload(
        inputs,
        expected_tf_producer_source=producer,
        expected_rs9_tool_source=rs9,
    )
    # The maintained assembler has already validated each body.  Its actual
    # portability observations can exceed the generic scratch JSON node cap,
    # so serialize the validated value without re-running that unrelated cap.
    payload = canonical(envelope)
    if len(payload) > MAX_OUTPUT_BYTES:
        raise _error("STAGE_A_OUTPUT", "assembled Stage-A output exceeds its bound")
    output_path, parent_fd, output_fd, leaf = _new_output(root, output)
    identity = (os.fstat(output_fd).st_dev, os.fstat(output_fd).st_ino)
    owned_files: dict[str, tuple[int, int, int]] = {}
    try:
        with ConfinedWriter(output_path, file_mode=0o600, dir_mode=0o700) as writer:
            writer.write("payload-portability.json", payload)
            payload_stat = os.stat("payload-portability.json", dir_fd=output_fd, follow_symlinks=False)
            owned_files["payload-portability.json"] = (payload_stat.st_dev, payload_stat.st_ino, payload_stat.st_size)
            receipt = canonical({
                "schema": OUTPUT_SCHEMA,
                "version": VERSION,
                "status": "payload-qualified",
                "source": {"rs9": rs9, "tf_producer": producer},
                "spec_sha256": hashlib.sha256(spec_raw).hexdigest(),
                "payload": {"path": "payload-portability.json", "bytes": len(payload),
                            "sha256": hashlib.sha256(payload).hexdigest()},
                "input_counts": {"targets": len(TARGETS), "body_kinds": len(BODY_KINDS)},
            }, validate=True)
            writer.write("stage-a-receipt.json", receipt)
            receipt_stat = os.stat("stage-a-receipt.json", dir_fd=output_fd, follow_symlinks=False)
            owned_files["stage-a-receipt.json"] = (receipt_stat.st_dev, receipt_stat.st_ino, receipt_stat.st_size)
        return {"schema": OUTPUT_SCHEMA, "status": "pass", "output": output_path.relative_to(root).as_posix(),
                "payload_sha256": hashlib.sha256(payload).hexdigest(), "receipt_sha256": hashlib.sha256(receipt).hexdigest()}
    except Exception:
        _cleanup_output(parent_fd, leaf, output_fd, identity, owned_files)
        raise
    finally:
        os.close(output_fd)
        os.close(parent_fd)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("repository", "input-root", "spec", "output", "expected-rs9-commit",
                 "expected-rs9-tree", "expected-tf-producer-commit", "expected-tf-producer-tree"):
        parser.add_argument(f"--{name}", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = vars(_parser().parse_args(argv))
    try:
        result = assemble_stage_a_files(
            repository=args["repository"], input_root=args["input_root"], spec=args["spec"], output=args["output"],
            expected_rs9_commit=args["expected_rs9_commit"], expected_rs9_tree=args["expected_rs9_tree"],
            expected_tf_producer_commit=args["expected_tf_producer_commit"],
            expected_tf_producer_tree=args["expected_tf_producer_tree"],
        )
    except ContractError as exc:
        print(json.dumps({"status": "refused", "code": exc.code}, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
