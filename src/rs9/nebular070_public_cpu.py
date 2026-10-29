"""Assemble the current Nebular conventional CPU observation from W4/W5 facts.

The production API is pure: callers provide bounded authenticated JSON bytes and
their byte SHA-256 values.  It does not open paths, execute tools, infer a CPU
default, or claim an ISA admission.  W5's compiler-observation records are kept
distinct from the W4 native qualification/runtime records.

The surrounding producer must authenticate the retained W5 tool and maintained
portability-validator identities before calling this pure boundary.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

CPU_SCHEMA = "rs9.nebular070-cpu-baseline-observation.v1"
INPUT_SCHEMA = "rs9.nebular070-public-cpu-assembler-input.v2"
RUST_CENSUS_SCHEMA = "rs9.nebular070-public-rust-census.v1"
RUST_PROBE_SCHEMA = "rs9.nebular070-public-rustc-probe.v1"
RUST_METADATA_SCHEMA = "rs9.nebular070-public-rust-census-metadata.v1"
VERSION = "0.7.0"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
MAX_JSON_BYTES = 8 * 1024 * 1024
PRODUCT_SOURCE = {
    "commit": "cadb40c4972f68f314096ff60fbcfb4da950c161",
    "tree": "27c643b6375c2aafde314799c4f08e844c14992c",
}
TARGETS = {
    "linux-x64": {
        "triple": "x86_64-unknown-linux-gnu",
        "baseline": "x86-64-v1",
        "arch": "x86_64",
        "features": ("fxsr", "sse", "sse2"),
    },
    "linux-arm64": {
        "triple": "aarch64-unknown-linux-gnu",
        "baseline": "armv8-a+neon",
        "arch": "aarch64",
        "features": ("neon",),
        "optional_features": ("fp-armv8",),
    },
}
PORTABILITY_TARGETS = {
    "linux-x64": "linux-x64-gnu",
    "linux-arm64": "linux-arm64-gnu",
}
ADDON_FLAGS = ("-O2", "-std=c11", "-fPIC", "-shared")
ISA_UNKNOWN_KEYS = re.compile(r"(?:cpu|feature|isa|march|mtune|avx|sse|neon|sve|llvm-)", re.IGNORECASE)


class AssemblyError(ValueError):
    """Stable, path-free input-contract failure."""

    def __init__(self, code: str, message: str | None = None):
        self.code = f"NEBULAR_CPU_{code}"
        super().__init__(f"{self.code}: {message or self.code}")


def _fail(code: str, message: str | None = None) -> None:
    raise AssemblyError(code, message)


def _compact(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        _fail("JSON", "value is not finite JSON")
    raise AssertionError("unreachable")


def _pretty(value: Any) -> bytes:
    try:
        return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        _fail("JSON", "value is not finite JSON")
    raise AssertionError("unreachable")


def _digest(value: Any) -> str:
    """Return the maintained CPU-body identity digest (pretty JSON form)."""
    return hashlib.sha256(_pretty(value)).hexdigest()


def _compact_digest(value: Any) -> str:
    return hashlib.sha256(_compact(value)).hexdigest()


def _hex(value: Any, label: str) -> str:
    if not isinstance(value, str) or not HEX64.fullmatch(value):
        _fail("DIGEST", f"{label} must be a lowercase SHA-256 digest")
    return value


def _hex40(value: Any, label: str) -> str:
    if not isinstance(value, str) or not HEX40.fullmatch(value):
        _fail("SOURCE", f"{label} must be a lowercase source coordinate")
    return value


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _fail("SCHEMA", f"{label} must be an object")
    return value


def _closed(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    value = _mapping(value, label)
    if set(value) != keys:
        _fail("SCHEMA", f"{label} fields are not closed")
    return dict(value)


def _strict_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail("JSON_DUPLICATE", "duplicate JSON object key")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    _fail("JSON_NONFINITE", "non-finite JSON constant")


def _parse(raw: bytes, label: str) -> Any:
    if len(raw) > MAX_JSON_BYTES:
        _fail("JSON_SIZE", f"{label} exceeds the bounded JSON size")
    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_strict_pairs,
            parse_constant=_reject_constant,
        )
    except AssemblyError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError):
        _fail("JSON_PARSE", f"{label} is not strict UTF-8 JSON")
    raise AssertionError("unreachable")


@dataclass(frozen=True)
class _RawDocument:
    raw: bytes
    value: Any
    sha256: str


def _raw_document(value: Any, label: str) -> _RawDocument:
    descriptor = _closed(value, {"raw", "sha256"}, label)
    raw = descriptor["raw"]
    if not isinstance(raw, (bytes, bytearray, memoryview)):
        _fail("RAW_TYPE", f"{label} raw value must be bytes")
    raw = bytes(raw)
    sha256 = _hex(descriptor["sha256"], f"{label} raw SHA-256")
    actual = hashlib.sha256(raw).hexdigest()
    if actual != sha256:
        _fail("RAW_DIGEST", f"{label} raw SHA-256 does not match its descriptor")
    return _RawDocument(raw=raw, value=_parse(raw, label), sha256=sha256)


def _identity_body(value: Any, schema: str, label: str) -> dict[str, Any]:
    body = _mapping(value, label)
    if body.get("schema") != schema:
        _fail("JOIN", f"{label} schema does not match")
    result = dict(body)
    identity = result.pop("identity", None)
    _hex(identity, f"{label} identity")
    if identity != _compact_digest(result):
        _fail("JOIN", f"{label} identity does not match its compact body")
    result["identity"] = identity
    return result


def _validate_expected_producer(value: Any) -> dict[str, str]:
    producer = _closed(value, {"commit", "tree"}, "expected TF producer source")
    _hex40(producer["commit"], "expected TF producer commit")
    _hex40(producer["tree"], "expected TF producer tree")
    return {"commit": producer["commit"], "tree": producer["tree"]}


def _validate_source_origin(document: _RawDocument, target: dict[str, str], expected_producer: dict[str, str]) -> dict[str, Any]:
    body = _identity_body(document.value, "nebular.public-pypi-source-origin-v2", "source origin")
    required = {"schema", "status", "contract", "repository", "version", "source", "producer", "ci", "runtime", "identity"}
    if set(body) != required or body["status"] != "pass" or body["contract"] != "public-source-first-v6" \
            or body["repository"] != "Knowledge-Forge-AI/theme-forge-nebular-fusion" or body["version"] != VERSION:
        _fail("SOURCE", "source origin is not the maintained W4 passing receipt")
    source = _closed(body["source"], {"commit", "tree"}, "source origin product")
    producer = _closed(body["producer"], {"commit", "tree"}, "source origin producer")
    _hex40(source["commit"], "source origin product commit")
    _hex40(source["tree"], "source origin product tree")
    _hex40(producer["commit"], "source origin producer commit")
    _hex40(producer["tree"], "source origin producer tree")
    if source != PRODUCT_SOURCE or producer != expected_producer:
        _fail("SOURCE", "source origin product/producer coordinates do not join CADB/tree27")
    runtime = _mapping(body["runtime"], "source origin runtime")
    if runtime.get("target") != target["triple"]:
        _fail("JOIN", "source origin target does not match the canonical target")
    return body


def _validate_target(value: Any) -> dict[str, str]:
    target = _closed(value, {"platform", "triple"}, "target")
    if target["platform"] not in TARGETS or target["triple"] != TARGETS[target["platform"]]["triple"]:
        _fail("TARGET", "target platform/triple is not one of the reviewed Linux targets")
    return {"platform": target["platform"], "triple": target["triple"]}


def _validate_portability(document: _RawDocument, target: dict[str, str], payload_identity: str) -> dict[str, Any]:
    try:
        from rs9.errors import ContractError
        from rs9.nebular070_payload import _actual_portability
    except (ImportError, ModuleNotFoundError):
        _fail("PORTABILITY_VALIDATOR", "maintained Stage-A portability validator is unavailable")
    try:
        return _actual_portability(
            document.value,
            target=PORTABILITY_TARGETS[target["platform"]],
            triple=target["triple"],
            payload_identity=payload_identity,
        )
    except ContractError:
        _fail("PORTABILITY", "maintained Stage-A portability validator rejected the W4 observation")
    raise AssertionError("unreachable")


def _validate_qualification(document: _RawDocument, target: dict[str, str]) -> tuple[dict[str, Any], str, str]:
    body = _mapping(document.value, "qualification")
    expected_platform = "linux-arm64" if target["platform"] == "linux-arm64" else "linux-x64"
    expected = {"schema", "platform", "status", "executableSha256", "glibcMinimum", "nativePayload", "materialDigest", "checks"}
    if set(body) != expected or body.get("schema") != "nebular.native-rc-qualification-v1" \
            or body.get("platform") != expected_platform or body.get("status") != "pass":
        _fail("JOIN", "qualification is not the passing maintained W4 body")
    _hex(body["executableSha256"], "qualification executable")
    if not isinstance(body["glibcMinimum"], str) or re.fullmatch(r"\d+\.\d+", body["glibcMinimum"]) is None \
            or tuple(int(part) for part in body["glibcMinimum"].split(".")) > (2, 36):
        _fail("FLOOR", "qualification glibc floor exceeds Bookworm 2.36")
    payload = _closed(body["nativePayload"], {"identity", "files"}, "qualification native payload")
    payload_identity = _hex(payload["identity"], "qualification native payload identity")
    if type(payload["files"]) is not int or payload["files"] < 1:
        _fail("JOIN", "qualification native payload file count is malformed")
    material_digest = _hex(body["materialDigest"], "qualification material digest")
    checks = body["checks"]
    if not isinstance(checks, list):
        _fail("JOIN", "qualification checks are not a list")
    check_map: dict[str, Mapping[str, Any]] = {}
    for check in checks:
        check = _closed(check, {"id", "ok", "detail"}, "qualification check")
        if not isinstance(check["id"], str) or check["id"] in check_map or check["ok"] is not True:
            _fail("JOIN", "qualification check is not a passing unique record")
        check_map[check["id"]] = check
    required = {"mode:gui", "mode:sidecar", "mode:launcher", "glibc:gui", "glibc:sidecar", "glibc-floor", "linkage", "private-runtime-closure"}
    if not required.issubset(check_map):
        _fail("JOIN", "qualification is missing a maintained required check")
    closure = _mapping(check_map["private-runtime-closure"]["detail"], "qualification runtime closure")
    if not isinstance(closure.get("portabilityObservation"), Mapping):
        _fail("JOIN", "qualification runtime closure has no portability observation")
    return body, payload_identity, material_digest


def _validate_build(document: _RawDocument, target: dict[str, str], source: dict[str, Any], payload_identity: str) -> dict[str, Any]:
    body = _mapping(document.value, "build receipt")
    if body.get("schema") != "nebular.native-rc-build-receipt-v1" or body.get("platform") != target["platform"] \
            or body.get("triple") != target["triple"]:
        _fail("JOIN", "build receipt schema/target does not match W4")
    build_source = _closed(body.get("source"), {"commit", "tree"}, "build receipt source")
    if build_source != {"commit": source["source"]["commit"], "tree": source["source"]["tree"]}:
        _fail("JOIN", "build receipt source does not match source origin")
    payload = _closed(body.get("nativePayload"), {"identity", "files"}, "build receipt payload")
    if payload["identity"] != payload_identity or type(payload["files"]) is not int or payload["files"] < 1:
        _fail("JOIN", "build receipt payload does not match qualification")
    return body


def _validate_package(document: _RawDocument, target: dict[str, str], executable: str) -> dict[str, Any]:
    body = _mapping(document.value, "package record")
    if body.get("schema") != "nebular.native-rc-package-v1" or body.get("platform") != target["platform"] \
            or body.get("version") != VERSION:
        _fail("JOIN", "package record schema/target does not match W4")
    raw = _mapping(body.get("raw"), "package raw record")
    npm = _mapping(body.get("npm"), "package npm record")
    _hex(raw.get("sha256"), "raw package archive")
    _hex(npm.get("sha256"), "npm package archive")
    if raw.get("executableSha256") != executable:
        _fail("JOIN", "package raw archive executable does not match qualification")
    _hex(body.get("packageManifestSha256"), "package manifest")
    return body


def _validate_runtime(document: _RawDocument, manifest_document: _RawDocument, target: dict[str, str], source_candidate: str, payload_identity: str, material_digest: str) -> dict[str, Any]:
    body = _closed(document.value, {"schema", "target", "materialDigest", "sourceCandidate", "nativePayload", "inputSha256"}, "runtime receipt")
    if body["schema"] != "nebular-native-runtime-material-receipt-v1" or body["target"] != target["triple"] \
            or body["sourceCandidate"] != source_candidate or body["nativePayload"] != payload_identity or body["materialDigest"] != material_digest:
        _fail("JOIN", "runtime receipt does not join qualification/source")
    _hex(body["inputSha256"], "runtime input")
    material = _mapping(manifest_document.value, "runtime material manifest")
    expected_material_keys = {"schema", "target", "prefix", "directories", "regulars", "aliases", "requiredRoles", "externalFloor", "materialDigest"}
    if set(material) != expected_material_keys or material.get("schema") != "nebular-native-runtime-material-v1" \
            or material.get("target") != target["triple"] or material.get("materialDigest") != material_digest:
        _fail("JOIN", "runtime material manifest does not join receipt")
    unsigned = dict(material)
    unsigned.pop("materialDigest")
    if _compact_digest(unsigned) != material_digest:
        _fail("JOIN", "runtime material digest does not match its body")
    return body


def _validate_metadata(document: _RawDocument, source: dict[str, Any], target: dict[str, str], build_sha: str, package_sha: str, qualification_sha: str, probe_identity: str) -> dict[str, Any]:
    body = _identity_body(document.value, RUST_METADATA_SCHEMA, "Rust census metadata")
    expected_keys = {"schema", "status", "source", "product", "producer", "target", "build", "payload", "elf", "compiler_probe", "identity"}
    if set(body) != expected_keys or body["status"] != "observed":
        _fail("CENSUS_METADATA", "Rust metadata is not the closed W5 body")
    if body["source"] != {"identity": source["identity"], "kind": "source-origin"}:
        _fail("JOIN", "Rust metadata source binding does not join")
    product = _closed(body["product"], {"identity", "kind", "commit", "tree"}, "Rust metadata product")
    producer = _closed(body["producer"], {"identity", "kind", "commit", "tree"}, "Rust metadata producer")
    if product["kind"] != "product-source" or producer["kind"] != "producer-source" \
            or product["commit"] != PRODUCT_SOURCE["commit"] or product["tree"] != PRODUCT_SOURCE["tree"] \
            or product["identity"] != _compact_digest({"commit": product["commit"], "tree": product["tree"]}):
        _fail("JOIN", "Rust metadata product binding does not join CADB/tree27")
    expected_producer = source["producer"]
    if producer["identity"] != _compact_digest({"commit": producer["commit"], "tree": producer["tree"]}) \
            or {"commit": producer["commit"], "tree": producer["tree"]} != expected_producer:
        _fail("JOIN", "Rust metadata producer identity is not self-consistent")
    target_binding = _closed(body["target"], {"identity", "kind", "platform", "triple"}, "Rust metadata target")
    canonical_target = {"platform": target["platform"], "triple": target["triple"]}
    if target_binding["kind"] != "target" or target_binding["platform"] != target["platform"] \
            or target_binding["triple"] != target["triple"] or target_binding["identity"] != _compact_digest(canonical_target):
        _fail("JOIN", "Rust metadata target identity does not join canonical platform/triple")
    for key, expected, kind in (("build", build_sha, "build-receipt"), ("payload", package_sha, "package-record"), ("elf", qualification_sha, "qualification-file-binding")):
        binding = _closed(body[key], {"identity", "kind"}, f"Rust metadata {key}")
        if binding != {"identity": expected, "kind": kind}:
            _fail("JOIN", f"Rust metadata {key} binding does not join exact W4 bytes")
    compiler_probe = _closed(body["compiler_probe"], {"identity", "kind"}, "Rust metadata compiler probe")
    if compiler_probe != {"identity": probe_identity, "kind": "rustc-probe"}:
        _fail("JOIN", "Rust metadata compiler probe does not join")
    return body


def _unknown_is_isa_relevant(value: Any) -> bool:
    if not isinstance(value, Mapping) or not isinstance(value.get("key"), str):
        _fail("CENSUS", "unknown override record is malformed")
    return ISA_UNKNOWN_KEYS.search(value["key"]) is not None


def _validate_probe(document: _RawDocument, target: dict[str, str]) -> dict[str, Any]:
    body = _identity_body(document.value, RUST_PROBE_SCHEMA, "Rust compiler probe")
    expected_keys = {"schema", "status", "target", "rustc_sha256", "version_sha256", "cfg_sha256", "cfg_count", "cfg", "version", "environment", "identity"}
    if set(body) != expected_keys or body["status"] != "observed" or body["target"] != target["triple"]:
        _fail("PROBE", "Rust probe is not the exact W5 rustc-probe.v1 body")
    for key in ("rustc_sha256", "version_sha256", "cfg_sha256"):
        _hex(body[key], f"Rust probe {key}")
    cfg = _mapping(body["cfg"], "Rust probe cfg")
    expected_scalars = {
        "target_arch": TARGETS[target["platform"]]["arch"],
        "target_endian": "little",
        "target_env": "gnu",
        "target_os": "linux",
        "target_pointer_width": "64",
        "target_vendor": "unknown",
    }
    if set(cfg) != set(expected_scalars) | {"target_feature"} \
            or any(type(cfg.get(key)) is not str or cfg[key] != expected for key, expected in expected_scalars.items()):
        _fail("PROBE", "Rust probe cfg does not match the reviewed Linux target")
    features = cfg["target_feature"]
    expected_features = TARGETS[target["platform"]]["features"]
    optional_features = TARGETS[target["platform"]].get("optional_features", ())
    allowed_features = set(expected_features) | set(optional_features)
    if type(features) is not list or any(type(feature) is not str for feature in features) \
            or features != sorted(set(features)) or not set(expected_features).issubset(features) \
            or any(feature not in allowed_features for feature in features):
        _fail("PROBE", "Rust probe target features are not the reviewed typed baseline set")
    minimum_cfg_lines = len(expected_scalars) + len(features)
    if type(body["cfg_count"]) is not int or body["cfg_count"] < minimum_cfg_lines:
        _fail("PROBE", "Rust probe cfg count is below the retained scalar/feature observations")
    version = _mapping(body["version"], "Rust probe version")
    if version.get("release") != "1.98.0" or version.get("host") != target["triple"] \
            or any(type(value) is not str for value in version.values()):
        _fail("PROBE", "Rust probe compiler release/host does not match the native reviewed toolchain")
    if not isinstance(body["environment"], Mapping):
        _fail("PROBE", "Rust probe environment field is malformed")
    return body


def _validate_census(
    document: _RawDocument,
    metadata: dict[str, Any],
    source: dict[str, Any],
    target: dict[str, str],
    build_sha: str,
    package_sha: str,
    qualification_sha: str,
    metadata_sha256: str,
) -> dict[str, Any]:
    body = _identity_body(document.value, RUST_CENSUS_SCHEMA, "Rust census")
    expected_keys = {"schema", "status", "evidence_mode", "admission", "session", "metadata_sha256", "bindings", "record_count", "record_set_sha256", "records", "identity"}
    if set(body) != expected_keys or body["status"] != "observed" or body["evidence_mode"] != "compiler-invocation-observation" \
            or body["admission"] != "not-claimed" or not isinstance(body["session"], str) or not body["session"]:
        _fail("CENSUS", "Rust census is not the W5 non-admitting observation")
    _hex(body["metadata_sha256"], "Rust census metadata SHA-256")
    if body["metadata_sha256"] != metadata_sha256:
        _fail("JOIN", "Rust census metadata SHA-256 does not match raw W5 metadata bytes")
    expected_bindings = {
        "source": source["identity"],
        "product": metadata["product"]["identity"],
        "producer": metadata["producer"]["identity"],
        "target": metadata["target"]["identity"],
        "build": build_sha,
        "payload": package_sha,
        "elf": qualification_sha,
    }
    bindings = _closed(body["bindings"], set(expected_bindings), "Rust census bindings")
    if bindings != expected_bindings:
        _fail("JOIN", "Rust census seven-way metadata bindings do not join exact inputs")
    records = body["records"]
    if type(records) is not list:
        _fail("CENSUS", "Rust census records are not a list")
    if type(body["record_count"]) is not int or body["record_count"] < 1 or body["record_count"] != len(records):
        _fail("CENSUS", "Rust census has no complete positive invocation set")
    seen: set[str] = set()
    target_records = 0
    for record in records:
        item = _closed(record, {"member", "record_sha256", "full_argv_sha256", "compiler", "crate_name", "target", "codegen", "cpu_overrides", "feature_overrides", "llvm_overrides", "unknown_overrides"}, "Rust census record")
        member = item["member"]
        if not isinstance(member, str) or not member or "/" in member or "\\" in member or member in seen:
            _fail("CENSUS", "Rust census member is not a safe unique name")
        seen.add(member)
        _hex(item["record_sha256"], "Rust census record SHA-256")
        _hex(item["full_argv_sha256"], "Rust census argv SHA-256")
        if item["target"] is not None and item["target"] != target["triple"]:
            _fail("JOIN", "Rust census invocation target is not host-null or lane-specific")
        if item["target"] == target["triple"]:
            target_records += 1
        for key in ("codegen", "cpu_overrides", "feature_overrides"):
            if not isinstance(item[key], Mapping):
                _fail("CENSUS", f"Rust census {key} is malformed")
        for key in ("llvm_overrides", "unknown_overrides"):
            if not isinstance(item[key], list):
                _fail("CENSUS", f"Rust census {key} is malformed")
        if item["cpu_overrides"] or item["feature_overrides"] or item["llvm_overrides"]:
            _fail("OVERRIDE", "Rust census contains an explicit CPU, feature, or LLVM override")
        if any(_unknown_is_isa_relevant(value) for value in item["unknown_overrides"]):
            _fail("OVERRIDE", "Rust census contains an unknown ISA-relevant override")
    if target_records < 1:
        _fail("CENSUS_TARGET", "Rust census has no target-specific crate invocation")
    normalized = sorted(records, key=lambda item: item["member"])
    if body["record_set_sha256"] != _compact_digest(normalized):
        _fail("JOIN", "Rust census record set does not match its records")
    return body


def _validate_assumptions(value: Any) -> dict[str, Any]:
    assumptions = _closed(value, {"node", "sdk"}, "provider assumptions")
    node = _closed(assumptions["node"], {"status", "version", "source_sha256", "binary_sha256", "probe_sha256"}, "Node assumption")
    sdk = _closed(assumptions["sdk"], {"status", "source_sha256", "members_sha256", "dispatch_sha256"}, "SDK assumption")
    if node["status"] != "authenticated" or node["version"] != "22.23.3" or sdk["status"] != "authenticated":
        _fail("ASSUMPTION", "provider assumptions are not authenticated pinned inputs")
    for mapping, keys in ((node, ("source_sha256", "binary_sha256", "probe_sha256")), (sdk, ("source_sha256", "members_sha256", "dispatch_sha256"))):
        for key in keys:
            _hex(mapping[key], f"provider assumption {key}")
    return {"node": dict(node), "sdk": dict(sdk)}


def _validate_addon(value: Any) -> dict[str, Any]:
    addon = _closed(value, {"present", "source_identity", "output_identity", "flags", "compiler_provenance_sha256"}, "native addon")
    if type(addon["present"]) is not bool:
        _fail("ADDON", "native addon presence is malformed")
    if not addon["present"]:
        if any(addon[key] not in (None, []) for key in ("source_identity", "output_identity", "compiler_provenance_sha256", "flags")):
            _fail("ADDON", "absent native addon carries output claims")
        return {"present": False, "compiler_provenance_sha256": None, "rust_census_proves_addon": False}
    for key in ("source_identity", "output_identity", "compiler_provenance_sha256"):
        _hex(addon[key], f"native addon {key}")
    if addon["flags"] != list(ADDON_FLAGS):
        _fail("ADDON", "native addon flags do not match the fixed C contract")
    return {"present": True, "compiler_provenance_sha256": addon["compiler_provenance_sha256"], "rust_census_proves_addon": False}


def assemble_cpu_body(
    input_data: Mapping[str, Any],
    *,
    expected_tf_producer_source: Mapping[str, Any],
) -> dict[str, Any]:
    """Assemble a non-admitting CPU body from authenticated W4/W5 inputs."""
    top = _closed(input_data, {"schema", "version", "test_only", "target", "cadb", "source_origin", "evidence", "runtime", "rust", "provider_assumptions", "native_addon"}, "assembler input")
    if top["schema"] != INPUT_SCHEMA or top["version"] != VERSION:
        _fail("SCHEMA", "assembler input schema/version is not current")
    if type(top["test_only"]) is not bool or top["test_only"]:
        _fail("TEST_MARKER", "test-only input is not accepted by the assembler")
    target = _validate_target(top["target"])
    expected_producer = _validate_expected_producer(expected_tf_producer_source)
    cadb = _closed(top["cadb"], {"commit", "tree"}, "CADB source")
    if cadb != PRODUCT_SOURCE:
        _fail("SOURCE", "CADB/tree27 source coordinates do not match")
    source_document = _raw_document(top["source_origin"], "source origin")
    source = _validate_source_origin(source_document, target, expected_producer)
    evidence = _closed(top["evidence"], {"qualification", "portability", "build", "package"}, "W4 evidence")
    qualification_document = _raw_document(evidence["qualification"], "qualification")
    qualification, payload_identity, material_digest = _validate_qualification(qualification_document, target)
    portability_document = _raw_document(evidence["portability"], "portability")
    portability = _validate_portability(portability_document, target, payload_identity)
    closure = next(
        (check["detail"] for check in qualification["checks"] if check.get("id") == "private-runtime-closure"),
        {},
    )
    supplied_portability = _mapping(closure, "qualification runtime closure").get("portabilityObservation")
    if supplied_portability != portability:
        _fail("JOIN", "qualification portability observation does not match the supplied W4 body")
    build_document = _raw_document(evidence["build"], "build receipt")
    _validate_build(build_document, target, source, payload_identity)
    package_document = _raw_document(evidence["package"], "package record")
    _validate_package(package_document, target, qualification["executableSha256"])
    runtime_input = _closed(top["runtime"], {"receipt", "manifest"}, "runtime evidence")
    runtime_receipt_document = _raw_document(runtime_input["receipt"], "runtime receipt")
    runtime_manifest_document = _raw_document(runtime_input["manifest"], "runtime material manifest")
    runtime = _validate_runtime(runtime_receipt_document, runtime_manifest_document, target, source["identity"], payload_identity, material_digest)
    rust_input = _closed(top["rust"], {"census", "probe", "metadata"}, "Rust W5 evidence")
    probe_document = _raw_document(rust_input["probe"], "Rust compiler probe")
    probe = _validate_probe(probe_document, target)
    metadata_document = _raw_document(rust_input["metadata"], "Rust census metadata")
    metadata = _validate_metadata(metadata_document, source, target, build_document.sha256, package_document.sha256, qualification_document.sha256, probe["identity"])
    census_document = _raw_document(rust_input["census"], "Rust census")
    census = _validate_census(
        census_document, metadata, source, target, build_document.sha256,
        package_document.sha256, qualification_document.sha256, metadata_document.sha256,
    )
    assumptions = _validate_assumptions(top["provider_assumptions"])
    addon = _validate_addon(top["native_addon"])
    target_facts = TARGETS[target["platform"]]
    properties = {
        "evidence_mode": "fixture" if top["test_only"] else "compiler-invocation-observation",
        "status_meaning": "observed describes authenticated conventional toolchain/provider facts; it is not a measured final-ELF ISA floor",
        "assessment": "conventional-target-description-under-reviewed-toolchain-and-provider-assumptions-not-measured-final-elf-isa-floor",
        "claim_scope": "x86-64-v1 or ARMv8-A+NEON under trusted Rust defaults and authenticated provider assumptions",
        "binary_isa_floor": "unresolved",
        "qualification": "not-admitted",
        "gnu_note_absence": "neutral-unresolved",
        "source": {
            "identity": source["identity"],
            "raw_sha256": source_document.sha256,
            "commit": source["source"]["commit"],
            "tree": source["source"]["tree"],
            "producer_commit": source["producer"]["commit"],
            "producer_tree": source["producer"]["tree"],
        },
        "payload": {"native_payload_identity": payload_identity, "material_digest": material_digest},
        "evidence": {
            "qualification_raw_sha256": qualification_document.sha256,
            "portability_raw_sha256": portability_document.sha256,
            "build_raw_sha256": build_document.sha256,
            "package_raw_sha256": package_document.sha256,
            "runtime_receipt_raw_sha256": runtime_receipt_document.sha256,
            "runtime_manifest_raw_sha256": runtime_manifest_document.sha256,
            "rust_census_raw_sha256": census_document.sha256,
            "rust_metadata_raw_sha256": metadata_document.sha256,
            "rust_probe_raw_sha256": probe_document.sha256,
        },
        "runtime": {"material_digest": material_digest, "receipt_input_sha256": runtime["inputSha256"]},
        "rust": {
            "census_identity": census["identity"],
            "census_evidence_mode": census["evidence_mode"],
            "record_count": census["record_count"],
            "target_record_count": sum(1 for item in census["records"] if item["target"] == target["triple"]),
            "host_or_probe_record_count": sum(1 for item in census["records"] if item["target"] is None),
            "record_set_sha256": census["record_set_sha256"],
            "metadata_identity": metadata["identity"],
            "compiler_probe_identity": probe["identity"],
            "compiler_version_sha256": probe["version_sha256"],
            "cfg_sha256": probe["cfg_sha256"],
            "cfg_target_features": list(probe["cfg"]["target_feature"]),
            "explicit_cpu_feature_llvm_overrides": False,
            "native_addon_is_separate_c_proof": True,
        },
        "native_addon": addon,
        "provider_assumptions": {
            "node": {"version": assumptions["node"]["version"], "source_sha256": assumptions["node"]["source_sha256"], "binary_sha256": assumptions["node"]["binary_sha256"], "probe_sha256": assumptions["node"]["probe_sha256"]},
            "sdk": {"source_sha256": assumptions["sdk"]["source_sha256"], "members_sha256": assumptions["sdk"]["members_sha256"], "dispatch_sha256": assumptions["sdk"]["dispatch_sha256"]},
        },
        "unresolved": ["direct final-ELF ISA floor", "runtime CPU canary coverage beyond the tested environment"],
        "admission": {"stage_a": False, "wheel": False, "publication": False},
    }
    body: dict[str, Any] = {"schema": CPU_SCHEMA, "target": target["triple"], "status": "observed", "baseline": target_facts["baseline"], "properties": properties}
    body["identity"] = _digest(body)
    return body


__all__ = ["CPU_SCHEMA", "INPUT_SCHEMA", "PRODUCT_SOURCE", "AssemblyError", "assemble_cpu_body"]
