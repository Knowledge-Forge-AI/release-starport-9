"""Bounded actual Stage-A payload-portability assembler for Nebular 0.7.0.

This module is deliberately an input assembler, not a native qualification or
wheel builder. It consumes separately captured bodies and artifact metadata,
then delegates the admission policy to the maintained payload validator.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from rs9.errors import ContractError
from rs9.archives import inspect_archive
from rs9.scratch import canonical
from rs9.nebular070_payload import (
    CLAIM,
    ARCHIVE_PORTABILITY_INPUT_SCHEMA,
    ARCHIVE_PORTABILITY_SCHEMA,
    LINUX_TARGETS,
    MAX_INPUT_BYTES,
    PORTABILITY_INPUT_SCHEMA,
    PORTABILITY_SCHEMA,
    VERSION,
    _body_digest,
    _digest,
    _hex,
    _source,
    validate_nebular070_payload_portability,
)

BODY_KINDS = (
    "source",
    "qualification",
    "portability",
    "runtime",
    "runtime_floor",
    "host_floor",
    "host_newer",
    "cpu",
)
BODY_SCHEMAS = {
    "source": "rs9.nebular070-source-input-binding.v1",
    "qualification": "nebular.native-rc-qualification-v1",
    "portability": "nebular-native-elf-portability-observation-set-v1",
    "runtime": "nebular-native-runtime-material-receipt-v1",
    "runtime_floor": "nebular-native-runtime-consumer-floor-observation-v1",
    "host_floor": "rs9.nebular070-linux-host-floor-observation.v1",
    "host_newer": "rs9.nebular070-linux-host-floor-observation.v1",
    "cpu": "rs9.nebular070-cpu-baseline-observation.v1",
}
ARTIFACT_METADATA_SCHEMA = "rs9.nebular070-stage-a-artifact-metadata.v1"
ARCHIVE_ARTIFACT_METADATA_SCHEMA = "rs9.nebular070-stage-a-artifact-metadata.v2"
PRODUCER_RECEIPT_SCHEMA = "rs9.nebular070-stage-a-producer-receipt.v1"
METADATA_SCHEMA = "rs9.nebular070-stage-a-producer-metadata.v1"
MAX_ARTIFACT_BYTES = 512 * 1024 * 1024
_OUTPUT_NAME = "payload_portability.json"
_METADATA_NAME = "payload_portability.metadata.json"
_RECEIPT_NAME = "payload_portability.receipt.json"


def _fail(code: str, message: str) -> ContractError:
    return ContractError(code, message)


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise _fail("NEBULAR_STAGE_A_SCHEMA", f"{label} must be an object")
    return value


def _closed(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    value = _mapping(value, label)
    if set(value) != keys:
        raise _fail("NEBULAR_STAGE_A_SCHEMA", f"{label} fields are not closed")
    return dict(value)


def _no_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _read_json(path_value: str | os.PathLike[str], label: str) -> tuple[dict[str, Any], str, int]:
    """Read one bounded regular JSON file through a no-follow descriptor."""
    if getattr(os, "O_NOFOLLOW", None) is None:
        raise _fail("NEBULAR_STAGE_A_INPUT", "nofollow file opening is unavailable")
    path = Path(path_value)
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise _fail("NEBULAR_STAGE_A_INPUT", f"{label} cannot be opened") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise _fail("NEBULAR_STAGE_A_INPUT", f"{label} is not a regular file")
        if info.st_size <= 0 or info.st_size > MAX_INPUT_BYTES:
            raise _fail("NEBULAR_STAGE_A_INPUT", f"{label} exceeds the bounded input size")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(1024 * 1024, MAX_INPUT_BYTES - total + 1))
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_INPUT_BYTES:
                raise _fail("NEBULAR_STAGE_A_INPUT", f"{label} exceeds the bounded input size")
            chunks.append(chunk)
    except ContractError:
        raise
    except OSError as exc:
        raise _fail("NEBULAR_STAGE_A_INPUT", f"{label} could not be read") from exc
    finally:
        os.close(fd)
    data = b"".join(chunks)
    try:
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_no_duplicate_pairs,
            parse_constant=lambda token: (_ for _ in ()).throw(ValueError(token)),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise _fail("NEBULAR_STAGE_A_INPUT", f"{label} is not strict JSON") from exc
    if not isinstance(value, dict):
        raise _fail("NEBULAR_STAGE_A_INPUT", f"{label} must contain an object")
    return value, hashlib.sha256(data).hexdigest(), len(data)


def _validate_path_map(
    value: Mapping[str, Mapping[str, str | os.PathLike[str]]],
    *,
    label: str,
) -> dict[str, dict[str, str | os.PathLike[str]]]:
    if not isinstance(value, Mapping) or set(value) != set(LINUX_TARGETS):
        raise _fail("NEBULAR_STAGE_A_INPUT", f"{label} targets are not the exact reviewed set")
    result: dict[str, dict[str, str | os.PathLike[str]]] = {}
    for target in LINUX_TARGETS:
        paths = value[target]
        if not isinstance(paths, Mapping) or set(paths) != set(BODY_KINDS):
            raise _fail("NEBULAR_STAGE_A_INPUT", f"{label} body kinds are incomplete")
        result[target] = {kind: paths[kind] for kind in BODY_KINDS}
    return result


def _validate_artifact_metadata(
    value: Mapping[str, Any],
    *,
    target: str,
    triple: str,
) -> dict[str, Any]:
    schema = value.get("schema") if isinstance(value, Mapping) else None
    archive_aware = schema == ARCHIVE_ARTIFACT_METADATA_SCHEMA
    fields = {"schema", "target", "triple", "payload_archive", "package_manifest"}
    if archive_aware:
        fields.add("archive_member_manifest_sha256")
    result = _closed(value, fields, f"{target} artifact metadata")
    if (not isinstance(schema, str)
            or schema not in {ARTIFACT_METADATA_SCHEMA, ARCHIVE_ARTIFACT_METADATA_SCHEMA}) \
            or result["target"] != target or result["triple"] != triple:
        raise _fail("NEBULAR_STAGE_A_INPUT", f"{target} artifact metadata does not join")
    for name in ("payload_archive", "package_manifest"):
        descriptor = _closed(
            result[name],
            {"sha256", "bytes"},
            f"{target} {name} metadata",
        )
        _hex(descriptor["sha256"], f"{target} {name}")
        if type(descriptor["bytes"]) is not int or not 0 < descriptor["bytes"] <= MAX_ARTIFACT_BYTES:
            raise _fail("NEBULAR_STAGE_A_INPUT", f"{target} {name} size is unresolved")
        result[name] = descriptor
    if archive_aware:
        _hex(result["archive_member_manifest_sha256"], f"{target} archive member manifest")
    return result


def _inspect_archive_path(
    path_value: str | os.PathLike[str],
    *,
    target: str,
    expected_size: int,
    expected_sha256: str,
) -> Mapping[str, Any]:
    """Inspect one authenticated archive snapshot, never a reopened path."""
    if getattr(os, "O_NOFOLLOW", None) is None:
        raise _fail("NEBULAR_STAGE_A_ARCHIVE", "nofollow archive opening is unavailable")
    path = Path(path_value)
    if any(candidate.is_symlink() for candidate in (path, *path.parents)):
        raise _fail("NEBULAR_STAGE_A_ARCHIVE", f"{target} archive path traverses a symlink")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise _fail("NEBULAR_STAGE_A_ARCHIVE", f"{target} archive path cannot be opened") from exc
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise _fail("NEBULAR_STAGE_A_ARCHIVE", f"{target} archive path is not regular")
        if before.st_size <= 0 or before.st_size > MAX_ARTIFACT_BYTES:
            raise _fail("NEBULAR_STAGE_A_ARCHIVE", f"{target} archive exceeds the bounded size")
        if before.st_size != expected_size:
            raise _fail("NEBULAR_STAGE_A_JOIN", f"{target} archive size does not join metadata")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(4 * 1024 * 1024, MAX_ARTIFACT_BYTES - total + 1))
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_ARTIFACT_BYTES:
                raise _fail("NEBULAR_STAGE_A_ARCHIVE", f"{target} archive exceeds the bounded size")
            chunks.append(chunk)
        after = os.fstat(fd)
    except ContractError:
        raise
    except OSError as exc:
        raise _fail("NEBULAR_STAGE_A_ARCHIVE", f"{target} archive could not be read") from exc
    finally:
        os.close(fd)
    raw = b"".join(chunks)
    if len(raw) != expected_size or hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise _fail("NEBULAR_STAGE_A_JOIN", f"{target} archive bytes do not join metadata")
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise _fail("NEBULAR_STAGE_A_ARCHIVE", f"{target} archive changed during read")
    with tempfile.TemporaryDirectory(prefix="rs9-nebular070-archive-") as temporary:
        snapshot = (Path(temporary) / "payload.tar.gz").resolve()
        try:
            snapshot.write_bytes(raw)
            os.chmod(snapshot, 0o600)
            return inspect_archive(snapshot, commands={})
        except (OSError, ContractError) as exc:
            raise _fail("NEBULAR_STAGE_A_ARCHIVE", f"{target} archive inspection failed") from exc


def _require_equal(values: list[Any], label: str) -> Any:
    if not values or any(value != values[0] for value in values[1:]):
        raise _fail("NEBULAR_STAGE_A_JOIN", f"{label} does not join")
    return values[0]


def _validate_body_headers(
    bodies: Mapping[str, Mapping[str, Any]],
    *,
    target: str,
    triple: str,
) -> None:
    for kind in BODY_KINDS:
        body = _mapping(bodies[f"{target}:{kind}"], f"{target}/{kind}")
        if body.get("schema") != BODY_SCHEMAS[kind]:
            raise _fail("NEBULAR_STAGE_A_SCHEMA", f"{target}/{kind} schema is not maintained")
        if kind in {"source", "runtime", "runtime_floor", "host_floor", "host_newer", "cpu"}                 and body.get("target") != triple:
            raise _fail("NEBULAR_STAGE_A_JOIN", f"{target}/{kind} target does not join")


def _derive_target_row(
    target: str,
    *,
    bodies: Mapping[str, Mapping[str, Any]],
    metadata: Mapping[str, Any],
    source_input_snapshot_sha256: str,
    archive_manifest: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    triple = LINUX_TARGETS[target][0]
    _validate_body_headers(bodies, target=target, triple=triple)
    source = _mapping(bodies[f"{target}:source"], f"{target}/source")
    qualification = _mapping(bodies[f"{target}:qualification"], f"{target}/qualification")
    runtime = _mapping(bodies[f"{target}:runtime"], f"{target}/runtime")
    runtime_floor = _mapping(bodies[f"{target}:runtime_floor"], f"{target}/runtime_floor")
    metadata = _validate_artifact_metadata(metadata, target=target, triple=triple)

    source_candidate = _hex(source.get("sourceCandidate"), f"{target} sourceCandidate")
    source_snapshot = _hex(
        source.get("sourceInputSnapshotSha256"),
        f"{target} source snapshot",
    )
    if source_snapshot != source_input_snapshot_sha256:
        raise _fail("NEBULAR_STAGE_A_JOIN", f"{target} source snapshot does not join")
    payload_archive_sha256 = _hex(source.get("payloadArchiveSha256"), f"{target} payload archive")
    manifest_sha256 = _hex(source.get("manifestSha256"), f"{target} manifest")
    inventory_identity = _hex(source.get("nativePayloadIdentity"), f"{target} native payload")
    material_digest = _hex(source.get("materialDigest"), f"{target} material")
    if payload_archive_sha256 != metadata["payload_archive"]["sha256"]             or manifest_sha256 != metadata["package_manifest"]["sha256"]:
        raise _fail("NEBULAR_STAGE_A_JOIN", f"{target} artifact metadata does not join source body")

    native_payload = _mapping(qualification.get("nativePayload"), f"{target} qualification payload")
    qualification_inventory = _hex(native_payload.get("identity"), f"{target} qualification payload")
    runtime_inventory = _hex(runtime.get("nativePayload"), f"{target} runtime payload")
    floor_inventory = _hex(runtime_floor.get("expectedNativePayload"), f"{target} floor payload")
    _require_equal(
        [inventory_identity, qualification_inventory, runtime_inventory, floor_inventory],
        f"{target} native payload identity",
    )
    qualification_material = _hex(qualification.get("materialDigest"), f"{target} qualification material")
    runtime_material = _hex(runtime.get("materialDigest"), f"{target} runtime material")
    floor_material = _hex(runtime_floor.get("materialDigest"), f"{target} floor material")
    _require_equal(
        [material_digest, qualification_material, runtime_material, floor_material],
        f"{target} runtime material digest",
    )
    _require_equal(
        [source_candidate, _hex(runtime.get("sourceCandidate"), f"{target} runtime sourceCandidate")],
        f"{target} sourceCandidate",
    )

    row = {
        "target": target,
        "triple": triple,
        "payload_archive_sha256": payload_archive_sha256,
        "manifest_sha256": manifest_sha256,
        "native_payload_inventory_identity": inventory_identity,
        "runtime_material_digest": material_digest,
        "source_candidate": source_candidate,
        "source_input_snapshot_sha256": source_snapshot,
        "qualification_sha256": _body_digest(qualification),
        "portability_observation_sha256": _body_digest(bodies[f"{target}:portability"]),
        "runtime_receipt_sha256": _body_digest(runtime),
        "runtime_floor_observation_sha256": _body_digest(runtime_floor),
        "host_floor_observation_sha256": _body_digest(bodies[f"{target}:host_floor"]),
        "host_newer_observation_sha256": _body_digest(bodies[f"{target}:host_newer"]),
        "cpu_baseline_sha256": _body_digest(bodies[f"{target}:cpu"]),
    }
    if metadata["schema"] == ARCHIVE_ARTIFACT_METADATA_SCHEMA:
        if archive_manifest is None or archive_manifest.get("manifest_sha256") != metadata["archive_member_manifest_sha256"]:
            raise _fail("NEBULAR_STAGE_A_JOIN", f"{target} complete archive manifest does not join metadata")
        row["archive_member_manifest_sha256"] = archive_manifest["manifest_sha256"]
    return row


def _validate_output_parent(output_path: Path) -> None:
    if output_path.name != _OUTPUT_NAME:
        raise _fail("NEBULAR_STAGE_A_OUTPUT", "output filename must be payload_portability.json")
    try:
        info = output_path.parent.lstat()
    except OSError as exc:
        raise _fail("NEBULAR_STAGE_A_OUTPUT", "output directory is unavailable") from exc
    if not stat.S_ISDIR(info.st_mode):
        raise _fail("NEBULAR_STAGE_A_OUTPUT", "output directory is not a directory")
    for name in (_OUTPUT_NAME, _METADATA_NAME, _RECEIPT_NAME):
        destination = output_path.parent / name
        try:
            destination.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise _fail("NEBULAR_STAGE_A_OUTPUT", "output destination cannot be inspected") from exc
        raise _fail("NEBULAR_STAGE_A_OUTPUT", "output destination already exists")


def _exclusive_atomic_write(files: Mapping[Path, bytes]) -> None:
    parent = next(iter(files)).parent
    temporary: list[Path] = []
    linked: list[Path] = []
    try:
        for destination, data in files.items():
            if destination.parent != parent:
                raise _fail("NEBULAR_STAGE_A_OUTPUT", "output files must share one directory")
            temporary_path = destination.parent / f".rs9-stage-a-{os.getpid()}-{len(temporary)}"
            fd = os.open(
                temporary_path,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o600,
            )
            temporary.append(temporary_path)
            try:
                remaining = memoryview(data)
                while remaining:
                    written = os.write(fd, remaining)
                    if written <= 0:
                        raise OSError("short output write")
                    remaining = remaining[written:]
                os.fsync(fd)
            finally:
                os.close(fd)
        for temporary_path, destination in zip(temporary, files):
            os.link(temporary_path, destination, follow_symlinks=False)
            linked.append(destination)
            os.unlink(temporary_path)
        temporary.clear()
    except (ContractError, OSError) as exc:
        for destination in linked:
            try:
                destination.unlink()
            except OSError:
                pass
        for temporary_path in temporary:
            try:
                temporary_path.unlink()
            except OSError:
                pass
        if isinstance(exc, ContractError):
            raise
        raise _fail("NEBULAR_STAGE_A_OUTPUT", "exclusive output write failed") from exc


def _load_body_set(body_paths: Mapping[str, Mapping[str, str | os.PathLike[str]]]) -> tuple[dict[str, Any], dict[str, Any]]:
    bodies: dict[str, Any] = {}
    files: dict[str, Any] = {}
    for target in LINUX_TARGETS:
        for kind in BODY_KINDS:
            key = f"{target}:{kind}"
            body, raw_sha256, raw_bytes = _read_json(body_paths[target][kind], key)
            bodies[key] = body
            files[key] = {"sha256": raw_sha256, "bytes": raw_bytes}
    return bodies, files


def _load_metadata_set(paths: Mapping[str, str | os.PathLike[str]]) -> tuple[dict[str, Any], dict[str, Any]]:
    bodies: dict[str, Any] = {}
    files: dict[str, Any] = {}
    for target in LINUX_TARGETS:
        body, raw_sha256, raw_bytes = _read_json(paths[target], f"{target}/artifact-metadata")
        bodies[target] = body
        files[target] = {"sha256": raw_sha256, "bytes": raw_bytes}
    return bodies, files


def assemble_payload_portability(
    body_paths: Mapping[str, Mapping[str, str | os.PathLike[str]]],
    target_metadata_paths: Mapping[str, str | os.PathLike[str]],
    tf_producer_source: Mapping[str, str],
    rs9_tool_source: Mapping[str, str],
    source_input_snapshot_sha256: str,
    output_path: str | os.PathLike[str],
    *,
    target_archive_paths: Mapping[str, str | os.PathLike[str]] | None = None,
) -> dict[str, Any]:
    """Assemble and admit an actual Stage-A bundle before exclusive output."""
    body_paths = _validate_path_map(body_paths, label="body")
    if not isinstance(target_metadata_paths, Mapping) or set(target_metadata_paths) != set(LINUX_TARGETS):
        raise _fail("NEBULAR_STAGE_A_INPUT", "artifact metadata targets are not the exact reviewed set")
    tf_source = _source(tf_producer_source, "TF producer source")
    rs9_source = _source(rs9_tool_source, "RS9 tool source")
    source_snapshot = _hex(source_input_snapshot_sha256, "source/input snapshot")

    loaded_bodies, body_file_info = _load_body_set(body_paths)
    loaded_metadata, metadata_file_info = _load_metadata_set(target_metadata_paths)
    for target in LINUX_TARGETS:
        loaded_metadata[target] = _validate_artifact_metadata(
            loaded_metadata[target],
            target=target,
            triple=LINUX_TARGETS[target][0],
        )

    metadata_schemas = {loaded_metadata[target].get("schema") for target in LINUX_TARGETS}
    if len(metadata_schemas) != 1:
        raise _fail("NEBULAR_STAGE_A_SCHEMA", "Both target artifact metadata records must use the same schema")
    archive_aware = ARCHIVE_ARTIFACT_METADATA_SCHEMA in metadata_schemas
    archive_manifests: dict[str, Mapping[str, Any]] | None = None
    if archive_aware:
        if not isinstance(target_archive_paths, Mapping) or set(target_archive_paths) != set(LINUX_TARGETS):
            raise _fail("NEBULAR_STAGE_A_ARCHIVE", "Archive-aware metadata requires both exact archive paths")
        archive_manifests = {}
        for target in LINUX_TARGETS:
            metadata = loaded_metadata[target]
            archive_manifests[target] = _inspect_archive_path(
                target_archive_paths[target],
                target=target,
                expected_size=metadata["payload_archive"]["bytes"],
                expected_sha256=metadata["payload_archive"]["sha256"],
            )
            if archive_manifests[target]["manifest_sha256"] != metadata["archive_member_manifest_sha256"]:
                raise _fail("NEBULAR_STAGE_A_JOIN", f"{target} archive manifest does not join metadata")
    elif target_archive_paths is not None:
        raise _fail("NEBULAR_STAGE_A_ARCHIVE", "Package-only metadata cannot consume archive paths")

    rows = [
        _derive_target_row(
            target,
            bodies=loaded_bodies,
            metadata=loaded_metadata[target],
            source_input_snapshot_sha256=source_snapshot,
            archive_manifest=archive_manifests[target] if archive_manifests is not None else None,
        )
        for target in LINUX_TARGETS
    ]
    record: dict[str, Any] = {
        "schema": ARCHIVE_PORTABILITY_SCHEMA if archive_aware else PORTABILITY_SCHEMA,
        "version": VERSION,
        "claim": CLAIM,
        "construction_status": "payload-qualified",
        "tf_producer_source": tf_source,
        "rs9_tool_source": rs9_source,
        "evidence_mode": "actual",
        "source_input_snapshot_sha256": source_snapshot,
        "targets": rows,
    }
    record["identity"] = _digest(record)
    bodies = {
        f"{target}:{kind}": loaded_bodies[f"{target}:{kind}"]
        for target in LINUX_TARGETS
        for kind in BODY_KINDS
    }
    validate_nebular070_payload_portability(
        record,
        bodies,
        expected_tf_producer_source=tf_source,
        expected_rs9_tool_source=rs9_source,
        allow_fixture=False,
    )

    output_path = Path(output_path)
    _validate_output_parent(output_path)
    output_bytes = canonical({
        "schema": ARCHIVE_PORTABILITY_INPUT_SCHEMA if archive_aware else PORTABILITY_INPUT_SCHEMA,
        "record": record,
        "bodies": bodies,
    })
    if len(output_bytes) > MAX_INPUT_BYTES:
        raise _fail("NEBULAR_STAGE_A_INPUT", "Assembled bundle exceeds the maintained loader input bound")
    metadata = {
        "schema": METADATA_SCHEMA,
        "record_identity": record["identity"],
        "tf_producer_source": tf_source,
        "rs9_tool_source": rs9_source,
        "source_input_snapshot_sha256": source_snapshot,
        "body_count": len(bodies),
        "body_canonical_digests": {
            key: _body_digest(bodies[key]) for key in sorted(bodies)
        },
    }
    metadata_bytes = canonical(metadata)
    receipt = {
        "schema": PRODUCER_RECEIPT_SCHEMA,
        "output": {
            "name": _OUTPUT_NAME,
            "bytes": len(output_bytes),
            "sha256": hashlib.sha256(output_bytes).hexdigest(),
        },
        "metadata": {
            "name": _METADATA_NAME,
            "bytes": len(metadata_bytes),
            "sha256": hashlib.sha256(metadata_bytes).hexdigest(),
        },
        "record_identity": record["identity"],
        "body_files": {key: body_file_info[key] for key in sorted(body_file_info)},
        "artifact_metadata_files": {
            target: metadata_file_info[target] for target in sorted(metadata_file_info)
        },
    }
    receipt_bytes = canonical(receipt)
    _exclusive_atomic_write(
        {
            output_path: output_bytes,
            output_path.with_name(_METADATA_NAME): metadata_bytes,
            output_path.with_name(_RECEIPT_NAME): receipt_bytes,
        }
    )
    return {
        "record": record,
        "metadata": metadata,
        "receipt": receipt,
    }


__all__ = [
    "assemble_payload_portability", "BODY_KINDS", "ARTIFACT_METADATA_SCHEMA",
    "ARCHIVE_ARTIFACT_METADATA_SCHEMA",
]
