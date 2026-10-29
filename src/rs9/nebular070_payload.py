"""Stage-A native payload portability and source/input evidence for Nebular 0.7.0."""
from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import os
import posixpath
import re
import stat
import zipfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rs9.errors import ContractError
from rs9.scratch import canonical

HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
PORTABILITY_SCHEMA = "rs9.nebular070-payload-portability.v2"
PORTABILITY_INPUT_SCHEMA = "rs9.nebular070-payload-portability-input.v2"
ARCHIVE_PORTABILITY_SCHEMA = "rs9.nebular070-payload-portability.v3"
ARCHIVE_PORTABILITY_INPUT_SCHEMA = "rs9.nebular070-payload-portability-input.v3"
LEGACY_PORTABILITY_SCHEMA = "rs9.nebular070-payload-portability.v1"
ADMISSION_SCHEMA = "rs9.nebular070-manylinux-release-admission.v1"
PAYLOAD_RECEIPT_SCHEMA = "rs9.nebular070-payload-evidence.v1"
OBSERVATION_SCHEMA = "rs9.nebular070-payload-observation.v1"
CONSUMER_RECEIPT_SCHEMA = "rs9.nebular070-installed-consumer.v1"
VERSION = "0.7.0"
CLAIM = "manylinux_2_36"
LINUX_TARGETS = {
    "linux-arm64-gnu": ("aarch64-unknown-linux-gnu", "py3-none-manylinux_2_36_aarch64"),
    "linux-x64-gnu": ("x86_64-unknown-linux-gnu", "py3-none-manylinux_2_36_x86_64"),
}
RECEIPT_KINDS = ("provider", "cpu", "floor", "newer", "functional", "coexistence")
OBSERVATION_KINDS = ("inventory", "runtime", "elf")
MAX_WHEEL_BYTES = 512 * 1024 * 1024
MAX_WHEEL_MEMBERS = 64
MAX_WHEEL_MEMBER_BYTES = 2 * 1024 * 1024 * 1024
MAX_WHEEL_TOTAL_BYTES = 3 * 1024 * 1024 * 1024
PAYLOAD_ROW_FIELDS = {
    "target", "triple", "payload_archive_sha256", "manifest_sha256",
    "native_payload_inventory_identity", "runtime_material_digest",
    "source_candidate", "source_input_snapshot_sha256",
    "qualification_sha256", "portability_observation_sha256",
    "runtime_receipt_sha256", "runtime_floor_observation_sha256",
    "host_floor_observation_sha256", "host_newer_observation_sha256",
    "cpu_baseline_sha256",
}
ARCHIVE_PAYLOAD_ROW_FIELDS = PAYLOAD_ROW_FIELDS | {"archive_member_manifest_sha256"}
ACTUAL_QUALIFICATION_SCHEMA = "nebular.native-rc-qualification-v1"
ELF_PORTABILITY_SCHEMA = "nebular-native-elf-portability-observation-set-v1"
RUNTIME_RECEIPT_SCHEMA = "nebular-native-runtime-material-receipt-v1"
RUNTIME_FLOOR_SCHEMA = "nebular-native-runtime-consumer-floor-observation-v1"
HOST_FLOOR_SCHEMA = "rs9.nebular070-linux-host-floor-observation.v1"
CPU_SCHEMA = "rs9.nebular070-cpu-baseline-observation.v1"
APPROVAL_SCHEMA = "rs9.tf-pypi-nebular070-artifacts.v1"
MATRIX_SCHEMA = "rs9.nebular070-hosted-matrix.v1"
MAX_INPUT_BYTES = 8 * 1024 * 1024
MAX_RUNTIME_FILE_BYTES = 512 * 1024 * 1024
SONAME_RE = re.compile(r"[A-Za-z0-9_+@.-]{1,255}\Z")
CPU_UNKNOWN_MARKERS = frozenset({
    "", "unknown", "unresolved", "unreported", "not-claimed", "not-observed",
    "n/a", "na", "null", "none", "missing", "unavailable", "not-available",
})


def _fail(code: str, message: str) -> ContractError:
    return ContractError(code, message)


def _hex(value: Any, label: str, pattern=HEX64) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise _fail("NEBULAR_MANYLINUX_SCHEMA", f"{label} digest is malformed")
    return value


def _closed(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise _fail("NEBULAR_MANYLINUX_SCHEMA", f"{label} fields are not closed")
    return dict(value)


def _source(value: Any, label: str) -> dict[str, str]:
    value = _closed(value, {"commit", "tree"}, label)
    if (not isinstance(value["commit"], str) or not isinstance(value["tree"], str)
            or not HEX40.fullmatch(value["commit"]) or not HEX40.fullmatch(value["tree"])):
        raise _fail("NEBULAR_MANYLINUX_SOURCE", f"{label} coordinates are malformed")
    return {"commit": value["commit"], "tree": value["tree"]}


def _payload(value: Any) -> dict[str, str]:
    value = _closed(value, {"archive_sha256", "manifest_sha256", "inventory_identity"}, "payload")
    return {key: _hex(value[key], f"payload {key}") for key in value}


def _runtime(value: Any) -> dict[str, str]:
    value = _closed(value, {"material_digest"}, "runtime")
    return {key: _hex(value[key], f"runtime {key}") for key in value}


def _payload_from_row(row: Mapping[str, Any]) -> dict[str, str]:
    return {
        "archive_sha256": _hex(row["payload_archive_sha256"], "payload archive"),
        "manifest_sha256": _hex(row["manifest_sha256"], "payload manifest"),
        "inventory_identity": _hex(row["native_payload_inventory_identity"], "payload inventory"),
    }


def _runtime_from_row(row: Mapping[str, Any]) -> dict[str, str]:
    return {"material_digest": _hex(row["runtime_material_digest"], "runtime material")}


def _receipt_digest_field(row: Mapping[str, Any], kind: str) -> str:
    field = {
        "provider": "provider_observation_identity",
        "cpu": "cpu_baseline_receipt_sha256",
        "floor": "payload_floor_consumer_receipt_sha256",
        "newer": "payload_newer_consumer_receipt_sha256",
        "functional": "payload_functional_receipt_sha256",
        "coexistence": "coexistence_receipt_sha256",
    }[kind]
    return _hex(row[field], f"{kind} receipt")


def _observation_field(row: Mapping[str, Any], kind: str) -> str:
    field = {
        "inventory": "native_payload_inventory_identity",
        "runtime": "runtime_material_digest",
        "elf": "elf_inventory_sha256",
    }[kind]
    return _hex(row[field], f"{kind} observation")


def _observation_body(body: Any, *, target: str, kind: str, source: dict[str, str]) -> dict[str, Any]:
    body = _closed(
        body,
        {"schema", "kind", "status", "target", "source", "value", "identity"},
        f"{target}/{kind} observation",
    )
    if body["schema"] != OBSERVATION_SCHEMA or body["kind"] != kind \
            or body["status"] != "pass" or body["target"] != target \
            or _source(body["source"], "observation source") != source:
        raise _fail("NEBULAR_MANYLINUX_RECEIPT", f"{target}/{kind} observation does not join")
    _hex(body["value"], f"{target}/{kind} observation value")
    unsigned = dict(body)
    unsigned.pop("identity")
    if _hex(body["identity"], f"{target}/{kind} observation identity") != _digest(unsigned):
        raise _fail("NEBULAR_MANYLINUX_RECEIPT", f"{target}/{kind} observation identity does not match")
    return body


def _receipt_body(body: Any, *, target: str, kind: str, source: dict[str, str],
                 payload: dict[str, str], runtime: dict[str, str]) -> dict[str, Any]:
    body = _closed(body, {"schema", "kind", "status", "target", "source", "payload", "runtime", "identity"},
                   f"{target}/{kind} receipt")
    if body["schema"] != PAYLOAD_RECEIPT_SCHEMA or body["kind"] != kind or body["status"] != "pass":
        raise _fail("NEBULAR_MANYLINUX_RECEIPT", f"{target}/{kind} receipt is not a passing maintained record")
    if body["target"] != target or _source(body["source"], "receipt source") != source:
        raise _fail("NEBULAR_MANYLINUX_RECEIPT", f"{target}/{kind} source or target does not join")
    if _payload(body["payload"]) != payload or _runtime(body["runtime"]) != runtime:
        raise _fail("NEBULAR_MANYLINUX_RECEIPT", f"{target}/{kind} payload/runtime does not join")
    unsigned = dict(body)
    unsigned.pop("identity")
    if _hex(body["identity"], "receipt identity") != _digest(unsigned):
        raise _fail("NEBULAR_MANYLINUX_RECEIPT", f"{target}/{kind} identity does not match its body")
    return body


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def _version_pair(value: Any, label: str) -> tuple[int, int]:
    if not isinstance(value, str) or re.fullmatch(r"\d+\.\d+", value) is None:
        raise _fail("NEBULAR_MANYLINUX_SCHEMA", f"{label} must be a major.minor version")
    return tuple(int(part) for part in value.split("."))  # type: ignore[return-value]


def _body_digest(body: Mapping[str, Any]) -> str:
    return _digest(dict(body))


def _admission_digest(value: Any) -> str:
    """Digest the compact JSON form used by the maintained publisher receipts."""
    encoded = (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _maintained_identity(value: Any) -> str:
    """Digest the compact JSON identity emitted by maintained JS receipts."""
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _identity_body(body: Any, *, schema: str, label: str) -> dict[str, Any]:
    if not isinstance(body, Mapping) or body.get("schema") != schema:
        raise _fail("NEBULAR_MANYLINUX_RECEIPT", f"{label} schema is not maintained")
    result = dict(body)
    identity_key = "identity" if "identity" in result else "observationIdentity"
    identity = result.pop(identity_key, None)
    declared = _hex(identity, f"{label} identity")
    if declared not in {_body_digest(result), _maintained_identity(result)}:
        raise _fail("NEBULAR_MANYLINUX_RECEIPT", f"{label} identity does not match its body")
    result[identity_key] = identity
    return result


def _actual_qualification(body: Any, *, target: str, triple: str) -> dict[str, Any]:
    expected_platform = "linux-arm64" if target == "linux-arm64-gnu" else "linux-x64"
    if not isinstance(body, Mapping):
        raise _fail("NEBULAR_MANYLINUX_RECEIPT", f"{target}/qualification is not an object")
    body = dict(body)
    if set(body) != {
        "schema", "platform", "status", "executableSha256", "glibcMinimum",
        "nativePayload", "materialDigest", "checks",
    } or body["schema"] != ACTUAL_QUALIFICATION_SCHEMA or body["platform"] != expected_platform \
            or body["status"] != "pass":
        raise _fail("NEBULAR_MANYLINUX_RECEIPT", f"{target}/qualification is not a passing native record")
    _hex(body["executableSha256"], f"{target} executable")
    glibc_requirement = _version_pair(body["glibcMinimum"], f"{target} payload glibc requirement")
    if glibc_requirement > (2, 36):
        raise _fail("NEBULAR_MANYLINUX_FLOOR", f"{target} payload glibc requirement exceeds 2.36")
    payload = body["nativePayload"]
    if not isinstance(payload, Mapping) or set(payload) != {"identity", "files"} \
            or not isinstance(payload["files"], int) or payload["files"] <= 0:
        raise _fail("NEBULAR_MANYLINUX_RECEIPT", f"{target} native payload inventory is malformed")
    payload_identity = _hex(payload["identity"], f"{target} native payload inventory")
    material_digest = _hex(body["materialDigest"], f"{target} material digest")
    checks = body["checks"]
    if not isinstance(checks, list) or not checks:
        raise _fail("NEBULAR_MANYLINUX_RECEIPT", f"{target} native checks are missing")
    by_id: dict[str, Mapping[str, Any]] = {}
    for check in checks:
        if not isinstance(check, Mapping) or set(check) != {"id", "ok", "detail"} \
                or not isinstance(check["id"], str) or check["id"] in by_id or check["ok"] is not True:
            raise _fail("NEBULAR_MANYLINUX_RECEIPT", f"{target} native checks are not passing and closed")
        by_id[check["id"]] = check
    required = {"mode:gui", "mode:sidecar", "mode:launcher", "glibc:gui", "glibc:sidecar",
                "glibc-floor", "linkage", "private-runtime-closure"}
    if not required.issubset(by_id):
        raise _fail("NEBULAR_MANYLINUX_RECEIPT", f"{target} native qualification is incomplete")
    closure = by_id["private-runtime-closure"]["detail"]
    if not isinstance(closure, Mapping) or not isinstance(closure.get("portabilityObservation"), Mapping):
        raise _fail("NEBULAR_MANYLINUX_RECEIPT", f"{target} lacks the maintained ELF portability observation")
    return {
        "body": body,
        "payload_identity": payload_identity,
        "material_digest": material_digest,
        "glibc_requirement": body["glibcMinimum"],
        "portability": dict(closure["portabilityObservation"]),
    }


def _actual_portability(body: Any, *, target: str, triple: str, payload_identity: str) -> dict[str, Any]:
    body = _identity_body(body, schema=ELF_PORTABILITY_SCHEMA, label=f"{target}/portability")
    if set(body) != {"schema", "target", "expectedNativePayload", "readelfArgs", "records", "admission", "identity"} \
            or body.get("target") != triple or body.get("expectedNativePayload") != payload_identity \
            or body.get("admission") != "not-claimed" or not isinstance(body.get("records"), list) \
            or not body["records"]:
        raise _fail("NEBULAR_MANYLINUX_RECEIPT", f"{target} ELF portability observation does not join")
    if body["readelfArgs"] != ["-h", "-l", "-d", "-V", "-n", "-A", "--wide"]:
        raise _fail("NEBULAR_MANYLINUX_RECEIPT", f"{target} ELF portability readelf contract does not join")
    expected_machines = (
        {"AArch64"} if triple == LINUX_TARGETS["linux-arm64-gnu"][0]
        else {"Advanced Micro Devices X86-64", "X86-64"}
    )
    seen_paths: set[str] = set()
    for record in body["records"]:
        if not isinstance(record, Mapping) or set(record) != {
            "schema", "target", "elf", "versionNeeds", "glibcPrivateVersionNeeds", "gnuProperty",
            "attributes", "cpuBaseline", "relativePath", "aliases", "bytes", "sha256", "readelf",
        } or record.get("schema") != "nebular-native-elf-portability-observation-v1" \
                or record.get("target") != triple or not isinstance(record.get("relativePath"), str) \
                or not record["relativePath"] or record["relativePath"] in seen_paths \
                or not isinstance(record.get("aliases"), list) or type(record.get("bytes")) is not int \
                or record["bytes"] <= 0 or not _hex(record.get("sha256"), f"{target} ELF bytes") \
                or not isinstance(record.get("elf"), Mapping) or set(record["elf"]) != {
                    "class", "machine", "elfType", "soname", "needed", "interpreters", "rpaths",
                    "versionDefinitions", "versionNeeds",
                } or record["elf"].get("class") != "ELF64" \
                or record["elf"].get("machine") not in expected_machines \
                or record["versionNeeds"] != record["elf"].get("versionNeeds") \
                or not isinstance(record.get("glibcPrivateVersionNeeds"), list) \
                or not isinstance(record.get("gnuProperty"), Mapping) \
                or not isinstance(record.get("attributes"), Mapping) \
                or not isinstance(record.get("cpuBaseline"), Mapping) \
                or record["cpuBaseline"].get("admission") != "not-claimed" \
                or not isinstance(record.get("readelf"), Mapping) \
                or set(record["readelf"]) != {
                    "args", "streamSha256", "stdoutBytes", "stderrBytes", "notesPresent", "notesStatus",
                } or record["readelf"].get("args") != body["readelfArgs"] \
                or not _hex(record["readelf"].get("streamSha256"), f"{target} readelf stream") \
                or type(record["readelf"].get("stdoutBytes")) is not int or record["readelf"]["stdoutBytes"] < 0 \
                or type(record["readelf"].get("stderrBytes")) is not int or record["readelf"]["stderrBytes"] < 0 \
                or record["readelf"].get("notesStatus") not in {"present", "absent", "unknown"} \
                or type(record["readelf"].get("notesPresent")) is not bool:
            raise _fail("NEBULAR_MANYLINUX_RECEIPT", f"{target} ELF portability record is incomplete")
        seen_paths.add(record["relativePath"])
    return body


def _actual_runtime(body: Any, *, target: str, triple: str, source_candidate: str,
                    payload_identity: str, material_digest: str) -> dict[str, Any]:
    body = dict(body) if isinstance(body, Mapping) else {}
    if set(body) != {"schema", "target", "materialDigest", "sourceCandidate", "nativePayload", "inputSha256"} \
            or body.get("schema") != RUNTIME_RECEIPT_SCHEMA or body.get("target") != triple \
            or body.get("sourceCandidate") != source_candidate or body.get("nativePayload") != payload_identity \
            or body.get("materialDigest") != material_digest:
        raise _fail("NEBULAR_MANYLINUX_RECEIPT", f"{target} runtime receipt does not join")
    _hex(body["inputSha256"], f"{target} runtime input")
    return body


def _runtime_provider_row(provider: Any, *, target: str, expected_machines: set[str]) -> str:
    provider = _closed(provider, {
        "soname", "classification", "requestedPath", "terminalPath", "aliasChain", "terminalFull9",
        "bytes", "sha256", "elfMachine", "elfClass", "versionDefinitions", "readelfEvidenceSha256",
    }, f"{target} runtime provider")
    if not isinstance(provider["soname"], str) or not SONAME_RE.fullmatch(provider["soname"]):
        raise _fail("NEBULAR_MANYLINUX_RECEIPT", f"{target} runtime provider SONAME is malformed")
    if provider["classification"] not in {"external-floor", "interpreter"}:
        raise _fail("NEBULAR_MANYLINUX_RECEIPT", f"{target} runtime provider classification is unsupported")
    for key in ("requestedPath", "terminalPath"):
        if not isinstance(provider[key], str) or not provider[key].startswith("/") \
                or "\x00" in provider[key] or "\\" in provider[key]:
            raise _fail("NEBULAR_MANYLINUX_RECEIPT", f"{target} runtime provider path is malformed")
    aliases = provider["aliasChain"]
    if not isinstance(aliases, list):
        raise _fail("NEBULAR_MANYLINUX_RECEIPT", f"{target} runtime provider alias chain is malformed")
    next_path = provider["requestedPath"]
    for alias in aliases:
        alias = _closed(alias, {"path", "rawTarget", "full9"}, f"{target} runtime provider alias")
        if alias["path"] != next_path or not isinstance(alias["path"], str) or not alias["path"].startswith("/"):
            raise _fail("NEBULAR_MANYLINUX_RECEIPT", f"{target} runtime provider alias chain is not contiguous")
        if not isinstance(alias["rawTarget"], str) or not alias["rawTarget"] \
                or len(alias["rawTarget"]) > 512 or "\x00" in alias["rawTarget"] \
                or "\\" in alias["rawTarget"]:
            raise _fail("NEBULAR_MANYLINUX_RECEIPT", f"{target} runtime provider alias target is malformed")
        full9 = alias["full9"]
        if not isinstance(full9, list) or len(full9) != 9 or any(type(value) not in (int, str) for value in full9):
            raise _fail("NEBULAR_MANYLINUX_RECEIPT", f"{target} runtime provider alias frame is malformed")
        next_path = posixpath.normpath(
            alias["rawTarget"] if alias["rawTarget"].startswith("/")
            else posixpath.join(posixpath.dirname(alias["path"]), alias["rawTarget"])
        )
    if next_path != provider["terminalPath"]:
        raise _fail("NEBULAR_MANYLINUX_RECEIPT", f"{target} runtime provider alias chain does not terminate")
    terminal_full9 = provider["terminalFull9"]
    if not isinstance(terminal_full9, list) or len(terminal_full9) != 9 \
            or any(type(value) not in (int, str) for value in terminal_full9):
        raise _fail("NEBULAR_MANYLINUX_RECEIPT", f"{target} runtime provider terminal frame is malformed")
    if type(provider["bytes"]) is not int or provider["bytes"] <= 0 \
            or provider["bytes"] > MAX_RUNTIME_FILE_BYTES:
        raise _fail("NEBULAR_MANYLINUX_RECEIPT", f"{target} runtime provider size is malformed")
    _hex(provider["sha256"], f"{target} runtime provider bytes")
    if provider["elfClass"] != "ELF64" or provider["elfMachine"] not in expected_machines:
        raise _fail("NEBULAR_MANYLINUX_RECEIPT", f"{target} runtime provider ELF identity does not join")
    versions = provider["versionDefinitions"]
    if not isinstance(versions, list) or any(not isinstance(value, str) or not value for value in versions) \
            or versions != sorted(set(versions)):
        raise _fail("NEBULAR_MANYLINUX_RECEIPT", f"{target} runtime provider version definitions are malformed")
    _hex(provider["readelfEvidenceSha256"], f"{target} runtime provider readelf evidence")
    return _maintained_identity(provider)


def _runtime_subject_row(subject: Any, *, target: str, provider_ids: set[str]) -> None:
    subject = _closed(subject, {
        "subjectRelativePath", "neededSoname", "resolvedPath", "providerObservationIdentity",
    }, f"{target} runtime subject resolution")
    relative = subject["subjectRelativePath"]
    if not isinstance(relative, str) or not relative or relative.startswith("/") \
            or "\x00" in relative or "\\" in relative or ".." in posixpath.normpath(relative).split("/"):
        raise _fail("NEBULAR_MANYLINUX_RECEIPT", f"{target} runtime subject path is malformed")
    if not isinstance(subject["neededSoname"], str) or not SONAME_RE.fullmatch(subject["neededSoname"]):
        raise _fail("NEBULAR_MANYLINUX_RECEIPT", f"{target} runtime subject SONAME is malformed")
    if not isinstance(subject["resolvedPath"], str) or not subject["resolvedPath"].startswith("/"):
        raise _fail("NEBULAR_MANYLINUX_RECEIPT", f"{target} runtime subject provider path is malformed")
    provider_id = subject["providerObservationIdentity"]
    if not isinstance(provider_id, str) or not HEX64.fullmatch(provider_id) or provider_id not in provider_ids:
        raise _fail("NEBULAR_MANYLINUX_RECEIPT", f"{target} runtime subject provider identity is unresolved")


def _runtime_tool_evidence(evidence: Any, *, target: str) -> None:
    if not isinstance(evidence, Mapping) \
            or set(evidence) != {"readelfRole", "resolutionToolRole", "boundedResults", "cleanupFacts"} \
            or evidence.get("readelfRole") != "actual-provider-terminal-readelf" \
            or evidence.get("resolutionToolRole") != "actual-consumer-ldd":
        raise _fail("NEBULAR_MANYLINUX_RECEIPT", f"{target} runtime provider observation is incomplete")
    bounded = evidence["boundedResults"]
    if not isinstance(bounded, list) or not bounded:
        raise _fail("NEBULAR_MANYLINUX_RECEIPT", f"{target} runtime bounded tool results are missing")
    for result in bounded:
        if not isinstance(result, Mapping) or not isinstance(result.get("role"), str) \
                or not isinstance(result.get("command"), str) or not isinstance(result.get("args"), list) \
                or type(result.get("status")) is not int or type(result.get("stdoutBytes")) is not int \
                or type(result.get("stderrBytes")) is not int or result["stdoutBytes"] < 0 \
                or result["stderrBytes"] < 0 or result.get("cleanupKnown") is not True:
            raise _fail("NEBULAR_MANYLINUX_RECEIPT", f"{target} runtime bounded result is malformed")
    cleanup = evidence["cleanupFacts"]
    if not isinstance(cleanup, Mapping) or cleanup.get("allCommandsBounded") is not True \
            or cleanup.get("noSurvivingProcessFamily") is not True:
        raise _fail("NEBULAR_MANYLINUX_RECEIPT", f"{target} runtime cleanup evidence is incomplete")


def _actual_runtime_floor(body: Any, *, target: str, triple: str, payload_identity: str,
                          material_digest: str) -> dict[str, Any]:
    body = _identity_body(body, schema=RUNTIME_FLOOR_SCHEMA, label=f"{target}/runtime-floor")
    if set(body) != {
        "schema", "target", "materialDigest", "expectedNativePayload", "observedProviderRows",
        "subjectResolutionRows", "toolEvidence", "observationIdentity",
    } or body.get("target") != triple or body.get("materialDigest") != material_digest \
            or body.get("expectedNativePayload") != payload_identity:
        raise _fail("NEBULAR_MANYLINUX_RECEIPT", f"{target} runtime floor does not join")
    expected_machines = (
        {"AArch64"} if triple == LINUX_TARGETS["linux-arm64-gnu"][0]
        else {"Advanced Micro Devices X86-64", "X86-64"}
    )
    provider_ids: set[str] = set()
    for provider in body["observedProviderRows"]:
        provider_id = _runtime_provider_row(provider, target=target, expected_machines=expected_machines)
        if provider_id in provider_ids:
            raise _fail("NEBULAR_MANYLINUX_RECEIPT", f"{target} runtime provider observation is duplicated")
        provider_ids.add(provider_id)
    for subject in body["subjectResolutionRows"]:
        _runtime_subject_row(subject, target=target, provider_ids=provider_ids)
    _runtime_tool_evidence(body["toolEvidence"], target=target)
    return body


def _actual_host(body: Any, *, target: str, triple: str, kind: str) -> dict[str, Any]:
    body = _identity_body(body, schema=HOST_FLOOR_SCHEMA, label=f"{target}/{kind}-host")
    expected_role = "floor" if kind == "floor" else "newer"
    if body.get("target") != triple or body.get("role") != expected_role or body.get("status") != "observed" \
            or not isinstance(body.get("loader"), str) or not body["loader"]:
        raise _fail("NEBULAR_MANYLINUX_RECEIPT", f"{target}/{kind} host observation does not join")
    glibc = _version_pair(body.get("glibc"), f"{target} {kind} host glibc")
    if kind == "floor" and glibc != (2, 36):
        raise _fail("NEBULAR_MANYLINUX_FLOOR", f"{target} host floor must be exactly 2.36")
    if kind == "newer" and glibc <= (2, 36):
        raise _fail("NEBULAR_MANYLINUX_FLOOR", f"{target} newer host must be above 2.36")
    return body


def _cpu_has_concrete_value(value: Any) -> bool:
    if isinstance(value, str):
        normalized = re.sub(r"[_\s]+", "-", value.strip().casefold())
        return normalized not in CPU_UNKNOWN_MARKERS
    if value is None:
        return False
    if type(value) in (bool, int, float):
        return True
    if isinstance(value, Mapping):
        return bool(value) and any(_cpu_has_concrete_value(item) for item in value.values())
    if isinstance(value, (list, tuple)):
        return bool(value) and any(_cpu_has_concrete_value(item) for item in value)
    return False


def _actual_cpu(body: Any, *, target: str, triple: str) -> dict[str, Any]:
    body = _identity_body(body, schema=CPU_SCHEMA, label=f"{target}/cpu")
    baseline = body.get("baseline")
    normalized_baseline = (
        re.sub(r"[_\s]+", "-", baseline.strip().casefold())
        if isinstance(baseline, str) else None
    )
    if body.get("target") != triple or body.get("status") != "observed" \
            or normalized_baseline is None or normalized_baseline in CPU_UNKNOWN_MARKERS \
            or not isinstance(body.get("properties"), Mapping) \
            or not _cpu_has_concrete_value(body["properties"]):
        raise _fail("NEBULAR_MANYLINUX_RECEIPT", f"{target} CPU baseline observation is unresolved")
    return body


def _actual_source_binding(body: Any, *, target: str, triple: str, row: Mapping[str, Any]) -> dict[str, Any]:
    body = _identity_body(body, schema="rs9.nebular070-source-input-binding.v1", label=f"{target}/source")
    expected = {
        "target": triple,
        "sourceCandidate": row["source_candidate"],
        "sourceInputSnapshotSha256": row["source_input_snapshot_sha256"],
        "payloadArchiveSha256": row["payload_archive_sha256"],
        "manifestSha256": row["manifest_sha256"],
        "nativePayloadIdentity": row["native_payload_inventory_identity"],
        "materialDigest": row["runtime_material_digest"],
        "status": "verified",
    }
    if {key: body.get(key) for key in expected} != expected:
        raise _fail("NEBULAR_MANYLINUX_SOURCE", f"{target} source/input binding does not join")
    return body


@dataclass(frozen=True)
class ValidatedPayloadPortability:
    record: dict[str, Any]
    digest: str
    receipt_bodies: dict[str, dict[str, Any]]
    fixture_only: bool = False

    def target(self, target: str) -> dict[str, Any]:
        for row in self.record["targets"]:
            if row["target"] == target:
                return dict(row)
        raise _fail("NEBULAR_MANYLINUX_TARGET", "Payload portability target is unavailable")


def _validate_payload_envelope(
    record: Mapping[str, Any],
    receipt_bodies: Mapping[str, Mapping[str, Any]],
    *,
    expected_tf_producer_source: Mapping[str, str],
    expected_rs9_tool_source: Mapping[str, str],
    allow_fixture: bool,
) -> tuple[dict[str, Any], list[Mapping[str, Any]], bool]:
    top = _closed(record, {
        "schema", "version", "claim", "construction_status", "tf_producer_source",
        "rs9_tool_source", "evidence_mode", "source_input_snapshot_sha256", "targets", "identity",
    }, "payload portability")
    schema = top["schema"]
    archive_aware = schema == ARCHIVE_PORTABILITY_SCHEMA
    if (not isinstance(schema, str) or schema not in {PORTABILITY_SCHEMA, ARCHIVE_PORTABILITY_SCHEMA}
            or top["version"] != VERSION) \
            or top["claim"] != CLAIM or top["construction_status"] != "payload-qualified" \
            or top["evidence_mode"] != ("fixture" if allow_fixture else "actual"):
        raise _fail("NEBULAR_MANYLINUX_POLICY", "Payload portability policy is not the 0.7.0 construction contract")
    if _source(top["tf_producer_source"], "TF producer source") != _source(
        expected_tf_producer_source, "expected TF producer source"
    ) or _source(top["rs9_tool_source"], "RS9 tool source") != _source(
        expected_rs9_tool_source, "expected RS9 tool source"
    ):
        raise _fail("NEBULAR_MANYLINUX_SOURCE", "Payload portability source identity does not match the caller")
    _hex(top["source_input_snapshot_sha256"], "source/input snapshot")
    targets = top["targets"]
    if not isinstance(targets, list) or len(targets) != len(LINUX_TARGETS) \
            or {row.get("target") for row in targets if isinstance(row, Mapping)} != set(LINUX_TARGETS):
        raise _fail("NEBULAR_MANYLINUX_TARGET", "Payload portability must contain both reviewed Linux targets")
    if not isinstance(receipt_bodies, Mapping):
        raise _fail("NEBULAR_MANYLINUX_RECEIPT", "Maintained receipt bodies are required")
    expected_receipts = {
        f"{target}:{kind}"
        for target in LINUX_TARGETS
        for kind in ("source", "qualification", "portability", "runtime", "runtime_floor",
                     "host_floor", "host_newer", "cpu")
    }
    if set(receipt_bodies) != expected_receipts:
        raise _fail("NEBULAR_MANYLINUX_RECEIPT", "Receipt body set is not exactly the reviewed target/kind set")
    return top, targets, archive_aware


def _join_payload_body(body: Mapping[str, Any], row: Mapping[str, Any], field: str, target: str) -> None:
    if _body_digest(body) != row[field]:
        raise _fail("NEBULAR_MANYLINUX_RECEIPT", f"{target} {field} does not join its row")


def _validate_payload_target_row(
    row: Mapping[str, Any], *, source_snapshot: str, archive_aware: bool
) -> dict[str, Any]:
    row = _closed(
        row,
        ARCHIVE_PAYLOAD_ROW_FIELDS if archive_aware else PAYLOAD_ROW_FIELDS,
        "payload target",
    )
    target = row["target"]
    if target not in LINUX_TARGETS or row["triple"] != LINUX_TARGETS[target][0]:
        raise _fail("NEBULAR_MANYLINUX_TARGET", "Payload target/triple does not match the reviewed set")
    for field in (
        "payload_archive_sha256", "manifest_sha256", "native_payload_inventory_identity",
        "runtime_material_digest", "source_candidate", "source_input_snapshot_sha256",
        "qualification_sha256", "portability_observation_sha256", "runtime_receipt_sha256",
        "runtime_floor_observation_sha256", "host_floor_observation_sha256",
        "host_newer_observation_sha256", "cpu_baseline_sha256",
    ):
        _hex(row[field], f"{target} {field}")
    if archive_aware:
        _hex(row["archive_member_manifest_sha256"], f"{target} archive member manifest")
    if row["source_input_snapshot_sha256"] != source_snapshot:
        raise _fail("NEBULAR_MANYLINUX_SOURCE", f"{target} source/input snapshot does not join the record")
    return row


def _validate_payload_target_native(
    row: Mapping[str, Any],
    receipt_bodies: Mapping[str, Mapping[str, Any]],
) -> dict[str, dict[str, Any]]:
    target, triple = row["target"], row["triple"]
    qualification = _actual_qualification(
        receipt_bodies[f"{target}:qualification"], target=target, triple=triple
    )
    if qualification["payload_identity"] != row["native_payload_inventory_identity"] \
            or qualification["material_digest"] != row["runtime_material_digest"]:
        raise _fail("NEBULAR_MANYLINUX_RECEIPT", f"{target} qualification does not join its row")
    _join_payload_body(qualification["body"], row, "qualification_sha256", target)
    qualification_portability = _actual_portability(
        qualification["portability"], target=target, triple=triple,
        payload_identity=row["native_payload_inventory_identity"],
    )
    supplied_portability = _actual_portability(
        receipt_bodies[f"{target}:portability"], target=target, triple=triple,
        payload_identity=row["native_payload_inventory_identity"],
    )
    if qualification_portability != supplied_portability:
        raise _fail("NEBULAR_MANYLINUX_RECEIPT", f"{target} ELF portability observation does not join qualification")
    _join_payload_body(supplied_portability, row, "portability_observation_sha256", target)
    runtime = _actual_runtime(
        receipt_bodies[f"{target}:runtime"], target=target, triple=triple,
        source_candidate=row["source_candidate"], payload_identity=row["native_payload_inventory_identity"],
        material_digest=row["runtime_material_digest"],
    )
    _join_payload_body(runtime, row, "runtime_receipt_sha256", target)
    runtime_floor = _actual_runtime_floor(
        receipt_bodies[f"{target}:runtime_floor"], target=target, triple=triple,
        payload_identity=row["native_payload_inventory_identity"], material_digest=row["runtime_material_digest"],
    )
    _join_payload_body(runtime_floor, row, "runtime_floor_observation_sha256", target)
    return {
        f"{target}:qualification": qualification["body"],
        f"{target}:portability": supplied_portability,
        f"{target}:runtime": runtime,
        f"{target}:runtime_floor": runtime_floor,
    }


def _validate_payload_target_host(
    row: Mapping[str, Any],
    receipt_bodies: Mapping[str, Mapping[str, Any]],
) -> dict[str, dict[str, Any]]:
    target, triple = row["target"], row["triple"]
    host_floor = _actual_host(
        receipt_bodies[f"{target}:host_floor"], target=target, triple=triple, kind="floor"
    )
    host_newer = _actual_host(
        receipt_bodies[f"{target}:host_newer"], target=target, triple=triple, kind="newer"
    )
    if _body_digest(host_floor) != row["host_floor_observation_sha256"] \
            or _body_digest(host_newer) != row["host_newer_observation_sha256"]:
        raise _fail("NEBULAR_MANYLINUX_RECEIPT", f"{target} host floor does not join its row")
    cpu = _actual_cpu(receipt_bodies[f"{target}:cpu"], target=target, triple=triple)
    _join_payload_body(cpu, row, "cpu_baseline_sha256", target)
    source = _actual_source_binding(
        receipt_bodies[f"{target}:source"], target=target, triple=triple, row=row
    )
    return {
        f"{target}:host_floor": host_floor,
        f"{target}:host_newer": host_newer,
        f"{target}:cpu": cpu,
        f"{target}:source": source,
    }


def _validate_payload_target(
    row: Mapping[str, Any],
    receipt_bodies: Mapping[str, Mapping[str, Any]],
    *,
    source_snapshot: str,
    archive_aware: bool,
) -> dict[str, dict[str, Any]]:
    row = _validate_payload_target_row(
        row, source_snapshot=source_snapshot, archive_aware=archive_aware,
    )
    checked = _validate_payload_target_native(row, receipt_bodies)
    checked.update(_validate_payload_target_host(row, receipt_bodies))
    return checked


def validate_nebular070_payload_portability(
    record: Mapping[str, Any],
    receipt_bodies: Mapping[str, Mapping[str, Any]],
    *,
    expected_tf_producer_source: Mapping[str, str],
    expected_rs9_tool_source: Mapping[str, str],
    allow_fixture: bool = False,
) -> ValidatedPayloadPortability:
    """Validate the maintained native portability evidence before wheel construction."""
    top, targets, archive_aware = _validate_payload_envelope(
        record,
        receipt_bodies,
        expected_tf_producer_source=expected_tf_producer_source,
        expected_rs9_tool_source=expected_rs9_tool_source,
        allow_fixture=allow_fixture,
    )
    checked: dict[str, dict[str, Any]] = {}
    for row in targets:
        checked.update(_validate_payload_target(
            row,
            receipt_bodies,
            source_snapshot=top["source_input_snapshot_sha256"],
            archive_aware=archive_aware,
        ))
    unsigned = dict(top)
    unsigned.pop("identity")
    identity = _hex(top["identity"], "payload portability identity")
    if identity != _digest(unsigned):
        raise _fail("NEBULAR_MANYLINUX_SCHEMA", "Payload portability identity does not match its contents")
    return ValidatedPayloadPortability(dict(top), identity, checked, allow_fixture)


def _read_input_json(path: Path, label: str) -> Mapping[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise _fail("NEBULAR_MANYLINUX_INPUT", f"{label} is not a regular file")
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise _fail("NEBULAR_MANYLINUX_INPUT", f"{label} could not be read") from exc
    if not data or len(data) > MAX_INPUT_BYTES:
        raise _fail("NEBULAR_MANYLINUX_INPUT", f"{label} exceeds the bounded input size")
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _fail("NEBULAR_MANYLINUX_INPUT", f"{label} is not strict JSON") from exc
    if not isinstance(value, Mapping):
        raise _fail("NEBULAR_MANYLINUX_INPUT", f"{label} must contain an object")
    return value


def load_payload_portability_bundle(
    path: str | Path,
    *,
    expected_tf_producer_source: Mapping[str, str],
    expected_rs9_tool_source: Mapping[str, str],
) -> ValidatedPayloadPortability:
    """Load a bounded external Stage-A bundle and validate every joined body.

    A file contains ``{"schema", "record", "bodies"}``.  A directory contains
    ``record.json`` and ``bodies.json``.  The bundle is source/input evidence,
    not a source file and never contains the post-wheel Stage-B admission.
    """
    root = Path(path)
    if root.is_symlink():
        raise _fail("NEBULAR_MANYLINUX_INPUT", "Stage-A input path must not be a symlink")
    if root.is_dir():
        record = _read_input_json(root / "record.json", "Stage-A record")
        record_schema = record.get("schema") if isinstance(record, Mapping) else None
        input_schema = (
            ARCHIVE_PORTABILITY_INPUT_SCHEMA
            if record_schema == ARCHIVE_PORTABILITY_SCHEMA
            else PORTABILITY_INPUT_SCHEMA
        )
        envelope: Mapping[str, Any] = {
            "schema": input_schema,
            "record": record,
            "bodies": _read_input_json(root / "bodies.json", "Stage-A bodies"),
        }
    else:
        envelope = _read_input_json(root, "Stage-A input")
    if not isinstance(envelope, Mapping) or set(envelope) != {"schema", "record", "bodies"}:
        raise _fail("NEBULAR_MANYLINUX_INPUT", "Stage-A input envelope is not closed")
    envelope_schema = envelope["schema"]
    if (not isinstance(envelope_schema, str)
            or envelope_schema not in {PORTABILITY_INPUT_SCHEMA, ARCHIVE_PORTABILITY_INPUT_SCHEMA}):
        raise _fail("NEBULAR_MANYLINUX_INPUT", "Stage-A input envelope is not closed")
    record = envelope["record"]
    bodies = envelope["bodies"]
    if not isinstance(record, Mapping) or not isinstance(bodies, Mapping):
        raise _fail("NEBULAR_MANYLINUX_INPUT", "Stage-A input record/bodies are malformed")
    record_schema = record.get("schema")
    if not isinstance(record_schema, str):
        raise _fail("NEBULAR_MANYLINUX_SCHEMA", "Stage-A record schema is not a string")
    expected_input_schema = {
        PORTABILITY_SCHEMA: PORTABILITY_INPUT_SCHEMA,
        ARCHIVE_PORTABILITY_SCHEMA: ARCHIVE_PORTABILITY_INPUT_SCHEMA,
    }.get(record_schema)
    if envelope_schema != expected_input_schema:
        raise _fail("NEBULAR_MANYLINUX_SCHEMA", "Stage-A input and record schemas are not a matching pair")
    return validate_nebular070_payload_portability(
        record,
        bodies,
        expected_tf_producer_source=expected_tf_producer_source,
        expected_rs9_tool_source=expected_rs9_tool_source,
    )



