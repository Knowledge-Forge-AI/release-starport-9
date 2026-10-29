"""Assemble the public Nebular 0.7 Linux Stage-A portability input.

This module is intentionally an assembler, not a producer of native facts.  It
accepts already authenticated JSON bodies (or the exact bytes from which those
bodies were read), checks the public TF runtime-input/source-origin contract,
derives one common source-input snapshot for both Linux lanes, and delegates
the final payload policy to :mod:`rs9.nebular070_payload`.

No file paths, commands, wheel data, or network operations are accepted here.
That boundary is important: a caller cannot turn an old receipt into current
evidence by pointing this function at a different path, and a missing hosted
body cannot be filled with a synthetic default.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from rs9.archives import inspect_archive
from rs9.errors import ContractError
from rs9.nebular070_payload import (
    ARCHIVE_PORTABILITY_INPUT_SCHEMA,
    ARCHIVE_PORTABILITY_SCHEMA,
    CLAIM,
    LINUX_TARGETS,
    PORTABILITY_INPUT_SCHEMA,
    PORTABILITY_SCHEMA,
    VERSION,
    _body_digest,
    _digest,
    _hex,
    validate_nebular070_payload_portability,
)
from rs9.scratch import canonical


RUNTIME_MANIFEST_SCHEMA = "nebular.public-pypi-runtime-input-manifest-v2"
RUNTIME_CLOSED_SCHEMA = "nebular070-public-hosted-runtime-input-closed-manifest-v2"
RUNTIME_RECEIPT_SCHEMA = "nebular070-public-hosted-runtime-input-receipt-v2"
SOURCE_ORIGIN_SCHEMA = "nebular.public-pypi-source-origin-v2"
SOURCE_CONTRACT = "public-source-first-v6"
REPOSITORY = "Knowledge-Forge-AI/theme-forge-nebular-fusion"
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
PRODUCT_COMMIT = "cadb40c4972f68f314096ff60fbcfb4da950c161"
PRODUCT_TREE = "27c643b6375c2aafde314799c4f08e844c14992c"
MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_PRODUCER_MANIFEST_BYTES = 256 * 1024
MAX_ARCHIVE_BYTES = 2 * 1024 * 1024 * 1024
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]*\Z")
TRIPLE_BY_TARGET = {target: triple for target, (triple, _tag) in LINUX_TARGETS.items()}
TARGET_BY_TRIPLE = {triple: target for target, (triple, _tag) in LINUX_TARGETS.items()}


def _fail(code: str, message: str) -> ContractError:
    return ContractError(code, message)


def _strict_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _reject_constant(value: str) -> Any:
    raise ValueError(value)


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise _fail("NEBULAR_STAGE_A_INPUT", f"{label} must be an object")
    return value


def _closed(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    value = _mapping(value, label)
    if set(value) != keys:
        raise _fail("NEBULAR_STAGE_A_SCHEMA", f"{label} fields are not closed")
    return dict(value)


def _source(value: Any, label: str) -> dict[str, str]:
    value = _closed(value, {"commit", "tree"}, label)
    if (not isinstance(value["commit"], str) or not HEX40.fullmatch(value["commit"])
            or not isinstance(value["tree"], str) or not HEX40.fullmatch(value["tree"])):
        raise _fail("NEBULAR_STAGE_A_SOURCE", f"{label} coordinates are malformed")
    return {"commit": value["commit"], "tree": value["tree"]}


def _digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _js_canonical(value: Any) -> bytes:
    """Match the compact canonical JSON used by the TF JavaScript producer."""
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise _fail("NEBULAR_STAGE_A_SCHEMA", "value is not finite JSON") from exc


def _js_digest(value: Any) -> str:
    return _digest_bytes(_js_canonical(value))


def _json_value(value: Any, label: str, *, max_bytes: int = MAX_JSON_BYTES) -> tuple[dict[str, Any], str, bytes]:
    """Return a detached JSON object, its supplied-byte digest, and bytes.

    Mapping inputs are serialized with the maintained Python canonical form;
    byte inputs are parsed with duplicate/non-finite rejection before any
    canonicalization.  Callers therefore cannot provide a mutable mapping and
    later change the object that was validated.
    """
    if isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        if not raw or len(raw) > max_bytes:
            raise _fail("NEBULAR_STAGE_A_INPUT", f"{label} exceeds its bounded JSON size")
        try:
            parsed = json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=_strict_pairs,
                parse_constant=_reject_constant,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise _fail("NEBULAR_STAGE_A_INPUT", f"{label} is not strict JSON") from exc
        if not isinstance(parsed, dict):
            raise _fail("NEBULAR_STAGE_A_INPUT", f"{label} must contain an object")
        # Validate that the detached value is JSON-safe before returning it.
        try:
            detached = json.loads(canonical(parsed, validate=True).decode("utf-8"))
        except (TypeError, ValueError, ContractError) as exc:
            raise _fail("NEBULAR_STAGE_A_INPUT", f"{label} contains unsupported JSON") from exc
        return detached, _digest_bytes(raw), raw
    if isinstance(value, Mapping):
        try:
            raw = canonical(dict(value), validate=True)
        except (TypeError, ValueError, ContractError) as exc:
            raise _fail("NEBULAR_STAGE_A_INPUT", f"{label} contains unsupported JSON") from exc
        if not raw or len(raw) > max_bytes:
            raise _fail("NEBULAR_STAGE_A_INPUT", f"{label} exceeds its bounded JSON size")
        try:
            detached = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:  # pragma: no cover - canonical JSON
            raise _fail("NEBULAR_STAGE_A_INPUT", f"{label} could not be detached") from exc
        return detached, _digest_bytes(raw), raw
    raise _fail("NEBULAR_STAGE_A_INPUT", f"{label} must be bytes or a mapping")


def _require_digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or not HEX64.fullmatch(value):
        raise _fail("NEBULAR_STAGE_A_SCHEMA", f"{label} digest is malformed")
    return value


def _positive_int(value: Any, label: str, maximum: int = 2**63 - 1) -> int:
    if type(value) is not int or value < 1 or value > maximum:
        raise _fail("NEBULAR_STAGE_A_SCHEMA", f"{label} is malformed")
    return value


def _archive_manifest_from_bytes(raw: bytes, label: str) -> dict[str, Any]:
    """Derive the complete archive-domain manifest from held bytes.

    ``inspect_archive`` is intentionally path-oriented.  The temporary file is
    phase-owned, regular, and removed on every outcome; no caller path or
    detached manifest is trusted as an authority.
    """
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_ARCHIVE_BYTES:
        raise _fail("NEBULAR_STAGE_A_ARCHIVE", f"{label} is outside the bounded archive size")
    try:
        with tempfile.TemporaryDirectory(prefix="rs9-nebular070-archive-") as temporary:
            path = Path(temporary).resolve() / "payload.tar.gz"
            path.write_bytes(raw)
            path.chmod(0o600)
            return inspect_archive(path, commands={})
    except ContractError as exc:
        raise _fail("NEBULAR_STAGE_A_ARCHIVE", f"{label} failed maintained archive inspection") from exc
    except OSError as exc:
        raise _fail("NEBULAR_STAGE_A_ARCHIVE", f"{label} could not be inspected") from exc


def _runtime_manifest(value: Any) -> tuple[dict[str, Any], str]:
    manifest, raw_sha, _raw = _json_value(value, "runtime manifest", max_bytes=MAX_MANIFEST_BYTES)
    if set(manifest) != {"schema", "version", "repository", "sourceContract", "runtimeToolSha256", "assets"}:
        raise _fail("NEBULAR_STAGE_A_SCHEMA", "runtime manifest fields are not closed")
    if (manifest["schema"] != RUNTIME_MANIFEST_SCHEMA or manifest["version"] != VERSION
            or manifest["repository"] != REPOSITORY or manifest["sourceContract"] != SOURCE_CONTRACT):
        raise _fail("NEBULAR_STAGE_A_SOURCE", "runtime manifest identity is not the public 0.7 contract")
    runtime_tool = _require_digest(manifest["runtimeToolSha256"], "runtime manifest runtimeToolSha256")
    assets = _closed(manifest["assets"], set(TARGET_BY_TRIPLE), "runtime manifest assets")
    normalized_assets: dict[str, Any] = {}
    for triple in sorted(TARGET_BY_TRIPLE):
        asset_value = _mapping(assets[triple], f"runtime manifest assets.{triple}")
        required_asset_keys = {
            "archive", "expectedMemberListSha256", "expectedManifestSha256", "expectedMaterialDigest",
            "correspondingSourceSha256", "releaseAssetSha256",
        }
        optional_asset_keys = {"memberCount", "manifestBytes", "materialBytes"}
        if not required_asset_keys.issubset(asset_value) or not set(asset_value) <= (required_asset_keys | optional_asset_keys):
            raise _fail("NEBULAR_STAGE_A_SCHEMA", f"runtime manifest assets.{triple} fields are not closed")
        asset = dict(asset_value)
        archive = _closed(asset["archive"], {"assetId", "name", "bytes", "sha256", "integrity"},
                          f"runtime manifest assets.{triple}.archive")
        if type(archive["assetId"]) is not int or archive["assetId"] < 1:
            raise _fail("NEBULAR_STAGE_A_SCHEMA", f"runtime manifest {triple} asset ID is malformed")
        if (not isinstance(archive["name"], str) or not SAFE_NAME.fullmatch(archive["name"])
                or archive["name"] != f"runtime-input-{triple}.tar.gz"):
            raise _fail("NEBULAR_STAGE_A_SCHEMA", f"runtime manifest {triple} archive name is invalid")
        archive_bytes = _positive_int(archive["bytes"], f"runtime manifest {triple} archive bytes", MAX_ARCHIVE_BYTES)
        archive_sha = _require_digest(archive["sha256"], f"runtime manifest {triple} archive sha256")
        if archive["integrity"] != "sha256-" + base64.b64encode(bytes.fromhex(archive_sha)).decode("ascii"):
            raise _fail("NEBULAR_STAGE_A_SCHEMA", f"runtime manifest {triple} archive integrity does not join")
        for key in ("expectedMemberListSha256", "expectedManifestSha256", "expectedMaterialDigest",
                    "correspondingSourceSha256", "releaseAssetSha256"):
            _require_digest(asset[key], f"runtime manifest {triple} {key}")
        optional_limits = {
            "memberCount": 2048,
            "manifestBytes": MAX_PRODUCER_MANIFEST_BYTES,
            "materialBytes": 1024 * 1024 * 1024,
        }
        for key in optional_asset_keys & set(asset):
            _positive_int(asset[key], f"runtime manifest {triple} {key}", optional_limits[key])
        # W4's validateRuntimeManifest returns a normalized asset that carries
        # the target key before computing manifestIdentity.  Keep this exact
        # shape; hashing the raw asset projection cannot join a genuine W4
        # source-origin receipt.
        normalized_assets[triple] = {"target": triple, **dict(asset)}
    normalized = dict(manifest)
    normalized["assets"] = normalized_assets
    # Keep the supplied-byte digest for source-origin manifestSha256; use the
    # compact JS identity for source-origin manifestIdentity.
    normalized["_manifest_identity"] = _js_digest({key: value for key, value in normalized.items() if key != "_manifest_identity"})
    return normalized, raw_sha


def compute_source_input_snapshot(
    product_source: Mapping[str, Any],
    producer_source: Mapping[str, Any],
    runtime_manifest: Mapping[str, Any],
    closed_manifest_digests: Mapping[str, str],
) -> str:
    """Compute the common two-target source/input snapshot digest.

    The target-specific source-origin identity is intentionally not included;
    it is joined in each lane's ``source`` body.  Thus both rows must carry
    this exact digest, while each lane retains its own hosted-origin identity.
    """
    product = _source(product_source, "product source")
    producer = _source(producer_source, "TF producer source")
    if not isinstance(runtime_manifest, Mapping):
        raise _fail("NEBULAR_STAGE_A_INPUT", "runtime manifest must be detached before snapshot computation")
    closed = _closed(closed_manifest_digests, set(TARGET_BY_TRIPLE), "closed runtime manifest digests")
    for triple in TARGET_BY_TRIPLE:
        _require_digest(closed[triple], f"closed runtime {triple} digest")
    body = {
        "schema": "rs9.nebular070-source-input-snapshot.v1",
        "productSource": product,
        "producerSource": producer,
        "runtimeManifestIdentity": _js_digest({key: value for key, value in runtime_manifest.items() if key != "_manifest_identity"}),
        "closedRuntimeManifestDigests": {key: closed[key] for key in sorted(closed)},
    }
    return _digest(body)


def _validate_source_origin(
    value: Any,
    *,
    target: str,
    manifest: Mapping[str, Any],
    manifest_sha: str,
    closed: Mapping[str, Any],
    descriptor_sha: str,
    descriptor_bytes: int,
    product_source: Mapping[str, str],
    producer_source: Mapping[str, str],
) -> tuple[dict[str, Any], str]:
    origin, _raw_sha, _raw = _json_value(value, f"{target} source origin", max_bytes=MAX_MANIFEST_BYTES)
    required = {"schema", "status", "contract", "repository", "version", "source", "producer", "ci", "runtime", "identity"}
    if set(origin) != required or origin["schema"] != SOURCE_ORIGIN_SCHEMA or origin["status"] != "pass" \
            or origin["contract"] != SOURCE_CONTRACT or origin["repository"] != REPOSITORY or origin["version"] != VERSION:
        raise _fail("NEBULAR_STAGE_A_SOURCE", f"{target} source origin is not a passing public receipt")
    if _source(origin["source"], f"{target} origin source") != dict(product_source):
        raise _fail("NEBULAR_STAGE_A_SOURCE", f"{target} origin product source does not bind CADB/tree27")
    if _source(origin["producer"], f"{target} origin producer") != dict(producer_source):
        raise _fail("NEBULAR_STAGE_A_SOURCE", f"{target} origin producer source does not bind the supplied TF source")
    if origin["source"] == origin["producer"]:
        raise _fail("NEBULAR_STAGE_A_SOURCE", f"{target} origin collapses product and producer identities")
    ci = _closed(origin["ci"], {"provider", "origin", "workflow", "workflowPath", "runId", "runAttempt", "event", "ref"},
                 f"{target} origin CI")
    if ci["provider"] != "github-actions" or ci["origin"] != "public-hosted-runner" \
            or ci["workflowPath"] != ".github/workflows/native-pypi-runtime.yml":
        raise _fail("NEBULAR_STAGE_A_SOURCE", f"{target} origin CI is not the public hosted runtime workflow")
    for key in ("workflow", "event", "ref"):
        if not isinstance(ci[key], str) or not ci[key]:
            raise _fail("NEBULAR_STAGE_A_SOURCE", f"{target} origin CI {key} is malformed")
    for key in ("runId", "runAttempt"):
        if not re.fullmatch(r"[1-9][0-9]*\Z", str(ci[key])):
            raise _fail("NEBULAR_STAGE_A_SOURCE", f"{target} origin CI {key} is malformed")
    runtime = _closed(origin["runtime"], {
        "target", "manifestSha256", "manifestIdentity", "runtimeToolSha256", "archiveAssetId", "archiveAssetName",
        "archiveSha256", "archiveBytes", "expectedMemberListSha256", "expectedManifestSha256", "expectedMaterialDigest",
        "descriptorSha256", "descriptorBytes", "evidence",
    }, f"{target} origin runtime")
    triple = TRIPLE_BY_TARGET[target]
    asset = _mapping(manifest["assets"][triple], f"{target} manifest asset")
    archive = _mapping(asset["archive"], f"{target} manifest archive")
    checks = {
        "target": triple,
        "manifestSha256": manifest_sha,
        "manifestIdentity": manifest["_manifest_identity"],
        "runtimeToolSha256": manifest["runtimeToolSha256"],
        "archiveAssetId": archive["assetId"],
        "archiveAssetName": archive["name"],
        "archiveSha256": archive["sha256"],
        "archiveBytes": archive["bytes"],
        "expectedMemberListSha256": asset["expectedMemberListSha256"],
        "expectedManifestSha256": asset["expectedManifestSha256"],
        "expectedMaterialDigest": asset["expectedMaterialDigest"],
        "descriptorSha256": descriptor_sha,
        "descriptorBytes": descriptor_bytes,
    }
    if any(runtime[key] != expected for key, expected in checks.items()):
        raise _fail("NEBULAR_STAGE_A_JOIN", f"{target} source origin runtime does not join the closed manifest")
    evidence = _closed(runtime["evidence"], {"correspondingSourceCustody", "releaseAsset", "runtimeMaterialArchive", "runtimeMaterialManifest"},
                       f"{target} origin runtime evidence")
    expected_evidence = {
        "correspondingSourceCustody": asset["correspondingSourceSha256"],
        "releaseAsset": asset["releaseAssetSha256"],
        "runtimeMaterialArchive": archive["sha256"],
        "runtimeMaterialManifest": asset["expectedManifestSha256"],
    }
    if evidence != expected_evidence:
        raise _fail("NEBULAR_STAGE_A_JOIN", f"{target} source origin evidence does not join the manifest")
    declared = _require_digest(origin["identity"], f"{target} source origin identity")
    unsigned = dict(origin)
    unsigned.pop("identity")
    if declared != _js_digest(unsigned):
        raise _fail("NEBULAR_STAGE_A_SOURCE", f"{target} source origin identity does not bind its body")
    return origin, declared


def _validate_runtime_input(
    value: Any,
    *,
    target: str,
    manifest: Mapping[str, Any],
    manifest_sha: str,
) -> tuple[dict[str, Any], dict[str, Any], str]:
    lane = _mapping(value, f"{target} runtime input")
    if set(lane) != {"closed_manifest", "runtime_receipt"} and set(lane) != {"closed_manifest", "runtime_receipt", "archive_bytes"}:
        raise _fail("NEBULAR_STAGE_A_INPUT", f"{target} runtime input fields are not closed")
    closed, closed_sha, _closed_raw = _json_value(lane["closed_manifest"], f"{target} closed runtime manifest", max_bytes=MAX_MANIFEST_BYTES)
    receipt, _receipt_sha, _receipt_raw = _json_value(lane["runtime_receipt"], f"{target} runtime input receipt", max_bytes=MAX_MANIFEST_BYTES)
    required_closed = {"schema", "target", "runtimePrefix", "archive", "materialManifest", "descriptor", "sourceRootRelative",
                       "maintainedRuntimeToolSha256", "authenticated", "productPayloadIncluded", "nativeExecution"}
    if set(closed) != required_closed or closed["schema"] != RUNTIME_CLOSED_SCHEMA or closed["target"] != TRIPLE_BY_TARGET[target] \
            or closed["runtimePrefix"] != "opt/nebular-private" or closed["sourceRootRelative"] != "source" \
            or closed["maintainedRuntimeToolSha256"] != manifest["runtimeToolSha256"] \
            or closed["authenticated"] is not True or closed["productPayloadIncluded"] is not False or closed["nativeExecution"] is not False:
        raise _fail("NEBULAR_STAGE_A_SOURCE", f"{target} closed runtime manifest is not authenticated runtime-only input")
    triple = TRIPLE_BY_TARGET[target]
    asset = _mapping(manifest["assets"][triple], f"{target} manifest asset")
    archive = _closed(closed["archive"], {"filename", "bytes", "sha256", "expectedBytes", "expectedSha256", "memberCount", "memberListSha256", "expectedMemberListSha256", "paxHeadersRejected"}, f"{target} closed archive")
    expected_archive = _mapping(asset["archive"], f"{target} manifest archive")
    if (archive["filename"], archive["bytes"], archive["sha256"], archive["expectedBytes"], archive["expectedSha256"], archive["memberListSha256"], archive["expectedMemberListSha256"]) != (
        expected_archive["name"], expected_archive["bytes"], expected_archive["sha256"], expected_archive["bytes"], expected_archive["sha256"], asset["expectedMemberListSha256"], asset["expectedMemberListSha256"]
    ) or archive["paxHeadersRejected"] is not True:
        raise _fail("NEBULAR_STAGE_A_JOIN", f"{target} closed archive does not join the common runtime manifest")
    _positive_int(archive["memberCount"], f"{target} closed archive memberCount", 2048)
    material = _closed(closed["materialManifest"], {"path", "bytes", "sha256", "materialDigest"}, f"{target} closed material")
    if material != {"path": "source/native-runtime.json", "bytes": material["bytes"], "sha256": asset["expectedManifestSha256"], "materialDigest": asset["expectedMaterialDigest"]}:
        raise _fail("NEBULAR_STAGE_A_JOIN", f"{target} closed material does not join the common runtime manifest")
    _positive_int(material["bytes"], f"{target} closed material bytes", MAX_MANIFEST_BYTES)
    descriptor = _closed(closed["descriptor"], {"path", "bytes", "sha256"}, f"{target} closed descriptor")
    if descriptor["path"] != "input/native-runtime-input.json":
        raise _fail("NEBULAR_STAGE_A_SCHEMA", f"{target} closed descriptor path is invalid")
    descriptor_sha = _require_digest(descriptor["sha256"], f"{target} descriptor")
    descriptor_bytes = _positive_int(descriptor["bytes"], f"{target} descriptor bytes", MAX_MANIFEST_BYTES)
    required_receipt = {"schema", "status", "target", "archive", "descriptor", "material", "evidence", "sourceRootRelative",
                        "maintainedRuntimeToolSha256", "authentication", "productPayloadIncluded", "nativeExecution", "buildOrQualificationClaim"}
    if set(receipt) != required_receipt or receipt["schema"] != RUNTIME_RECEIPT_SCHEMA or receipt["status"] != "runtime-only-input-authenticated" \
            or receipt["target"] != triple or receipt["sourceRootRelative"] != "source" \
            or receipt["maintainedRuntimeToolSha256"] != manifest["runtimeToolSha256"] \
            or receipt["productPayloadIncluded"] is not False or receipt["nativeExecution"] is not False \
            or receipt["buildOrQualificationClaim"] is not False:
        raise _fail("NEBULAR_STAGE_A_SOURCE", f"{target} runtime input receipt is not authenticated runtime-only evidence")
    if not isinstance(receipt["authentication"], Mapping) or receipt["authentication"].get("sourceSnapshotVerified") is not True:
        raise _fail("NEBULAR_STAGE_A_SOURCE", f"{target} runtime input receipt lacks source-snapshot authentication")
    receipt_archive = _closed(receipt["archive"], {"filename", "bytes", "expectedBytesSha256Verified", "sha256", "memberCount", "memberListSha256", "paxHeadersRejected"}, f"{target} receipt archive")
    if receipt_archive["filename"] != archive["filename"] or receipt_archive["bytes"] != archive["bytes"] \
            or receipt_archive["expectedBytesSha256Verified"] is not True or receipt_archive["sha256"] != archive["sha256"] \
            or receipt_archive["memberCount"] != archive["memberCount"] or receipt_archive["memberListSha256"] != archive["memberListSha256"] \
            or receipt_archive["paxHeadersRejected"] is not True:
        raise _fail("NEBULAR_STAGE_A_JOIN", f"{target} runtime receipt archive does not join")
    receipt_descriptor = _closed(receipt["descriptor"], {"path", "bytes", "sha256"}, f"{target} receipt descriptor")
    if receipt_descriptor != descriptor:
        raise _fail("NEBULAR_STAGE_A_JOIN", f"{target} runtime receipt descriptor does not join")
    receipt_material = _closed(receipt["material"], {"path", "bytes", "sha256", "materialDigest", "regulars", "aliases", "directories"}, f"{target} receipt material")
    if receipt_material["path"] != material["path"] or receipt_material["bytes"] != material["bytes"] \
            or receipt_material["sha256"] != material["sha256"] or receipt_material["materialDigest"] != material["materialDigest"]:
        raise _fail("NEBULAR_STAGE_A_JOIN", f"{target} runtime receipt material does not join")
    for key in ("regulars", "aliases", "directories"):
        if type(receipt_material[key]) is not int or receipt_material[key] < 0:
            raise _fail("NEBULAR_STAGE_A_SCHEMA", f"{target} runtime receipt material count is malformed")
    evidence = _closed(receipt["evidence"], {"correspondingSourceCustody", "releaseAsset", "runtimeMaterialArchive", "runtimeMaterialManifest"}, f"{target} receipt evidence")
    if (evidence["correspondingSourceCustody"] != asset["correspondingSourceSha256"]
            or evidence["releaseAsset"] != asset["releaseAssetSha256"]
            or evidence["runtimeMaterialArchive"] != archive["sha256"]
            or evidence["runtimeMaterialManifest"] != material["sha256"]):
        raise _fail("NEBULAR_STAGE_A_JOIN", f"{target} runtime receipt evidence does not join")
    if "archive_bytes" in lane:
        archive_bytes = lane["archive_bytes"]
        if not isinstance(archive_bytes, (bytes, bytearray, memoryview)):
            raise _fail("NEBULAR_STAGE_A_INPUT", f"{target} archive bytes are not bytes")
        raw = bytes(archive_bytes)
        if len(raw) != archive["bytes"] or _digest_bytes(raw) != archive["sha256"]:
            raise _fail("NEBULAR_STAGE_A_JOIN", f"{target} supplied runtime archive bytes do not join")
    return closed, receipt, closed_sha


def _validate_artifact_metadata(value: Any, *, target: str) -> dict[str, Any]:
    metadata, _raw_sha, _raw = _json_value(value, f"{target} Stage-A artifact metadata")
    triple = TRIPLE_BY_TARGET[target]
    schema = metadata.get("schema")
    archive_aware = schema == ARCHIVE_ARTIFACT_METADATA_SCHEMA
    expected = {"schema", "target", "triple", "payload_archive", "package_manifest"}
    if archive_aware:
        expected.add("archive_member_manifest_sha256")
    if set(metadata) != expected \
            or not isinstance(schema, str) \
            or schema not in {ARTIFACT_METADATA_SCHEMA, ARCHIVE_ARTIFACT_METADATA_SCHEMA} \
            or metadata["target"] != target or metadata["triple"] != triple:
        raise _fail("NEBULAR_STAGE_A_INPUT", f"{target} artifact metadata does not join")
    for key in ("payload_archive", "package_manifest"):
        descriptor = _closed(metadata[key], {"sha256", "bytes"}, f"{target} {key} metadata")
        _require_digest(descriptor["sha256"], f"{target} {key} sha256")
        _positive_int(descriptor["bytes"], f"{target} {key} bytes", MAX_ARCHIVE_BYTES)
    if archive_aware:
        _require_digest(metadata["archive_member_manifest_sha256"], f"{target} archive member manifest")
    return metadata


def _source_snapshot_and_rows(
    *,
    product_source: Mapping[str, str],
    producer_source: Mapping[str, str],
    bodies: dict[str, dict[str, Any]],
    metadata: dict[str, dict[str, Any]],
    origins: dict[str, tuple[dict[str, Any], str]],
    source_snapshot: str,
    archive_manifests: Mapping[str, Mapping[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for target in LINUX_TARGETS:
        triple = TRIPLE_BY_TARGET[target]
        source = bodies[f"{target}:source"]
        if source.get("schema") != BODY_SCHEMAS["source"] or source.get("target") != triple or source.get("status") != "verified":
            raise _fail("NEBULAR_STAGE_A_SOURCE", f"{target} source binding is not verified")
        origin, origin_identity = origins[target]
        if source.get("sourceCandidate") != origin_identity:
            raise _fail("NEBULAR_STAGE_A_JOIN", f"{target} source candidate does not bind source origin")
        if source.get("sourceInputSnapshotSha256") != source_snapshot:
            raise _fail("NEBULAR_STAGE_A_JOIN", f"{target} source snapshot does not join both-target snapshot")
        artifact = metadata[target]
        if source.get("payloadArchiveSha256") != artifact["payload_archive"]["sha256"] \
                or source.get("manifestSha256") != artifact["package_manifest"]["sha256"]:
            raise _fail("NEBULAR_STAGE_A_JOIN", f"{target} source binding does not join artifact metadata")
        qualification = bodies[f"{target}:qualification"]
        runtime = bodies[f"{target}:runtime"]
        runtime_floor = bodies[f"{target}:runtime_floor"]
        inventory = source.get("nativePayloadIdentity")
        material = source.get("materialDigest")
        if runtime.get("sourceCandidate") != origin_identity or runtime.get("inputSha256") != origin["runtime"]["descriptorSha256"]:
            raise _fail("NEBULAR_STAGE_A_JOIN", f"{target} runtime receipt does not join source origin")
        if (qualification.get("nativePayload", {}).get("identity") != inventory
                or qualification.get("materialDigest") != material
                or runtime.get("nativePayload") != inventory
                or runtime.get("materialDigest") != material
                or runtime_floor.get("expectedNativePayload") != inventory
                or runtime_floor.get("materialDigest") != material):
            raise _fail("NEBULAR_STAGE_A_JOIN", f"{target} native payload/runtime material identities do not join")
        row = {
            "target": target,
            "triple": triple,
            "payload_archive_sha256": source["payloadArchiveSha256"],
            "manifest_sha256": source["manifestSha256"],
            "native_payload_inventory_identity": inventory,
            "runtime_material_digest": material,
            "source_candidate": origin_identity,
            "source_input_snapshot_sha256": source_snapshot,
            "qualification_sha256": _body_digest(qualification),
            "portability_observation_sha256": _body_digest(bodies[f"{target}:portability"]),
            "runtime_receipt_sha256": _body_digest(runtime),
            "runtime_floor_observation_sha256": _body_digest(runtime_floor),
            "host_floor_observation_sha256": _body_digest(bodies[f"{target}:host_floor"]),
            "host_newer_observation_sha256": _body_digest(bodies[f"{target}:host_newer"]),
            "cpu_baseline_sha256": _body_digest(bodies[f"{target}:cpu"]),
        }
        if metadata[target]["schema"] == ARCHIVE_ARTIFACT_METADATA_SCHEMA:
            if archive_manifests is None or target not in archive_manifests:
                raise _fail("NEBULAR_STAGE_A_ARCHIVE", f"{target} complete archive manifest is missing")
            actual_manifest = archive_manifests[target]
            actual_sha = actual_manifest.get("manifest_sha256")
            if actual_sha != metadata[target]["archive_member_manifest_sha256"]:
                raise _fail("NEBULAR_STAGE_A_JOIN", f"{target} complete archive manifest does not join metadata")
            row["archive_member_manifest_sha256"] = actual_sha
        rows.append(row)
    return rows


def assemble_public_payload(
    inputs: Mapping[str, Any],
    *,
    expected_tf_producer_source: Mapping[str, str],
    expected_rs9_tool_source: Mapping[str, str],
) -> dict[str, Any]:
    """Assemble and validate one actual Stage-A input envelope.

    ``inputs`` is a closed mapping with these keys:

    ``product_source`` and ``producer_source`` are source coordinates;
    ``runtime_manifest`` is the common TF runtime manifest as bytes or a JSON
    mapping; ``runtime_inputs``, ``source_origins``, ``bodies`` and
    ``artifact_metadata`` are exact two-target mappings.  Each runtime-input
    lane contains ``closed_manifest`` and ``runtime_receipt`` and may include
    the archive bytes for an exact optional byte readback.  Body values may be
    mappings or their authenticated JSON bytes.  No path-like input is
    accepted.
    """
    if not isinstance(inputs, Mapping):
        raise _fail("NEBULAR_STAGE_A_INPUT", "Stage-A inputs must be a mapping")
    legacy_keys = {"product_source", "producer_source", "runtime_manifest", "runtime_inputs", "source_origins", "bodies", "artifact_metadata", "rs9_tool_source"}
    archive_keys = legacy_keys | {"payload_archives"}
    if set(inputs) != legacy_keys and set(inputs) != archive_keys:
        raise _fail("NEBULAR_STAGE_A_INPUT", "Stage-A input fields are not closed")
    archive_aware_input = set(inputs) == archive_keys
    product_source = _source(inputs["product_source"], "product source")
    if product_source != {"commit": PRODUCT_COMMIT, "tree": PRODUCT_TREE}:
        raise _fail("NEBULAR_STAGE_A_SOURCE", "product source is not the authenticated CADB/tree27 product")
    producer_source = _source(inputs["producer_source"], "TF producer source")
    expected_tf = _source(expected_tf_producer_source, "expected TF producer source")
    if producer_source != expected_tf:
        raise _fail("NEBULAR_STAGE_A_SOURCE", "supplied producer source does not match the expected TF source")
    rs9_source = _source(inputs["rs9_tool_source"], "RS9 tool source")
    expected_rs9 = _source(expected_rs9_tool_source, "expected RS9 tool source")
    if rs9_source != expected_rs9:
        raise _fail("NEBULAR_STAGE_A_SOURCE", "supplied RS9 tool source does not match the expected source")
    if producer_source == rs9_source:
        raise _fail("NEBULAR_STAGE_A_SOURCE", "TF producer and RS9 tool sources must remain distinct")

    manifest, manifest_sha = _runtime_manifest(inputs["runtime_manifest"])
    runtime_inputs = _closed(inputs["runtime_inputs"], set(LINUX_TARGETS), "runtime inputs")
    origins_input = _closed(inputs["source_origins"], set(LINUX_TARGETS), "source origins")
    metadata_input = _closed(inputs["artifact_metadata"], set(LINUX_TARGETS), "artifact metadata")
    body_input = _closed(inputs["bodies"], set(LINUX_TARGETS), "body targets")
    closed: dict[str, tuple[dict[str, Any], dict[str, Any], str]] = {}
    for target in LINUX_TARGETS:
        closed[target] = _validate_runtime_input(runtime_inputs[target], target=target, manifest=manifest, manifest_sha=manifest_sha)
    snapshot = compute_source_input_snapshot(product_source, producer_source, manifest, {
        TRIPLE_BY_TARGET[target]: closed[target][2] for target in LINUX_TARGETS
    })
    bodies: dict[str, dict[str, Any]] = {}
    for target in LINUX_TARGETS:
        lane = _closed(body_input[target], set(BODY_KINDS), f"{target} bodies")
        for kind in BODY_KINDS:
            body, _raw_sha, _raw = _json_value(lane[kind], f"{target}/{kind} body")
            if body.get("schema") != BODY_SCHEMAS[kind]:
                raise _fail("NEBULAR_STAGE_A_SCHEMA", f"{target}/{kind} schema is not maintained")
            bodies[f"{target}:{kind}"] = body
    metadata = {target: _validate_artifact_metadata(metadata_input[target], target=target) for target in LINUX_TARGETS}
    archive_manifests: dict[str, dict[str, Any]] | None = None
    if archive_aware_input:
        archive_values = _closed(inputs["payload_archives"], set(LINUX_TARGETS), "payload archives")
        archive_manifests = {}
        for target in LINUX_TARGETS:
            raw = archive_values[target]
            if not isinstance(raw, (bytes, bytearray, memoryview)):
                raise _fail("NEBULAR_STAGE_A_ARCHIVE", f"{target} payload archive is not detached bytes")
            raw = bytes(raw)
            descriptor = metadata[target]["payload_archive"]
            if metadata[target]["schema"] != ARCHIVE_ARTIFACT_METADATA_SCHEMA:
                raise _fail("NEBULAR_STAGE_A_SCHEMA", f"{target} archive input requires artifact metadata v2")
            if len(raw) != descriptor["bytes"] or _digest_bytes(raw) != descriptor["sha256"]:
                raise _fail("NEBULAR_STAGE_A_JOIN", f"{target} payload archive bytes do not join metadata")
            archive_manifests[target] = _archive_manifest_from_bytes(raw, f"{target} payload archive")
            if archive_manifests[target]["manifest_sha256"] != metadata[target]["archive_member_manifest_sha256"]:
                raise _fail("NEBULAR_STAGE_A_JOIN", f"{target} archive member manifest does not join")
    elif any(metadata[target]["schema"] == ARCHIVE_ARTIFACT_METADATA_SCHEMA for target in LINUX_TARGETS):
        raise _fail("NEBULAR_STAGE_A_ARCHIVE", "Archive artifact metadata requires the exact raw archive inputs")
    origins: dict[str, tuple[dict[str, Any], str]] = {}
    for target in LINUX_TARGETS:
        closed_body, receipt, _closed_sha = closed[target]
        descriptor = closed_body["descriptor"]
        origin = origins_input[target]
        origins[target] = _validate_source_origin(
            origin,
            target=target,
            manifest=manifest,
            manifest_sha=manifest_sha,
            closed=closed_body,
            descriptor_sha=descriptor["sha256"],
            descriptor_bytes=descriptor["bytes"],
            product_source=product_source,
            producer_source=producer_source,
        )
    rows = _source_snapshot_and_rows(
        product_source=product_source,
        producer_source=producer_source,
        bodies=bodies,
        metadata=metadata,
        origins=origins,
        source_snapshot=snapshot,
        archive_manifests=archive_manifests,
    )
    archive_aware = archive_manifests is not None
    record_schema = ARCHIVE_PORTABILITY_SCHEMA if archive_aware else PORTABILITY_SCHEMA
    input_schema = ARCHIVE_PORTABILITY_INPUT_SCHEMA if archive_aware else PORTABILITY_INPUT_SCHEMA
    record: dict[str, Any] = {
        "schema": record_schema,
        "version": VERSION,
        "claim": CLAIM,
        "construction_status": "payload-qualified",
        "tf_producer_source": producer_source,
        "rs9_tool_source": rs9_source,
        "evidence_mode": "actual",
        "source_input_snapshot_sha256": snapshot,
        "targets": rows,
    }
    record["identity"] = _digest(record)
    envelope = {
        "schema": input_schema,
        "record": record,
        "bodies": {key: bodies[key] for key in sorted(bodies)},
    }
    validate_nebular070_payload_portability(
        record,
        envelope["bodies"],
        expected_tf_producer_source=expected_tf,
        expected_rs9_tool_source=expected_rs9,
        allow_fixture=False,
    )
    return envelope


# Explicit aliases make the seam easy for the maintained Stage-A caller to
# discover without reintroducing the old path-based writer.
assemble_stage_a = assemble_public_payload
assemble_payload_portability = assemble_public_payload


__all__ = [
    "ARTIFACT_METADATA_SCHEMA",
    "ARCHIVE_ARTIFACT_METADATA_SCHEMA",
    "BODY_KINDS",
    "BODY_SCHEMAS",
    "PRODUCT_COMMIT",
    "PRODUCT_TREE",
    "RUNTIME_MANIFEST_SCHEMA",
    "SOURCE_ORIGIN_SCHEMA",
    "assemble_payload_portability",
    "assemble_public_payload",
    "assemble_stage_a",
    "compute_source_input_snapshot",
]
