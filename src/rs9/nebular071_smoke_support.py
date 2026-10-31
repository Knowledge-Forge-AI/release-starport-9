"""Authenticated product smoke support for the installed-wheel consumer.

The wheel consumer must not import an ambient Theme Forge checkout.  A
publisher/qualification producer transports a bounded plaintext closure whose
members were read from an authenticated product source and whose bytes are
staged below the raw handoff root.  This module validates that contract and
materializes a fresh read-only execution source for the maintained smoke
helpers.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import stat
import tarfile
from pathlib import Path
from typing import Any, Mapping

from rs9.tf_pypi_archive import AdmissionError, canonical, fail, physical_bytes, sha256
from rs9.tf_pypi_model import strict_json
from rs9.security import validate_safe_relative_posix_path


SMOKE_SUPPORT_SCHEMA = "rs9.nebular071-smoke-support.v1"
MAX_SUPPORT_FILES = 512
MAX_SUPPORT_MEMBER_BYTES = 8 * 1024 * 1024
MAX_SUPPORT_TOTAL_BYTES = 32 * 1024 * 1024
# These are read limits, not producer facts.  Archive name/size/digest and
# source authority identity are late-bound from an authenticated 071 offer;
# retaining a historical 070 value here would allow cross-release admission.
SOURCE_ARCHIVE_SIZE = 2 * 1024 * 1024 * 1024
SOURCE_AUTHORITY_SIZE = 2 * 1024 * 1024
SOURCE_REPOSITORY = "Knowledge-Forge-AI/theme-forge-nebular-fusion"
MAX_SOURCE_ARCHIVE_MEMBERS = 4_096
MAX_SOURCE_ARCHIVE_TOTAL_BYTES = 32 * 1024 * 1024
# Only this already published parity7 source offer has the larger exact
# regular-file inventory. Other archives keep the ordinary 32 MiB ceiling.
_PARITY7_SOURCE_SIZE = 12_289_441
_PARITY7_SOURCE_SHA256 = "4ed41eaf2bcf29eae1d6dc0b2eb85f0dc70cb65fc9bef816f522db63304b9171"
_PARITY7_SOURCE_TOTAL = 34_280_236
_PARITY7_SOURCE_MEMBERS = 2_162
_HEX40 = re.compile(r"[0-9a-f]{40}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_BLOB40 = re.compile(r"[0-9a-f]{40}")
_ARCHIVE_SUFFIXES = frozenset({
    ".7z", ".bz2", ".gz", ".rar", ".tar", ".tgz", ".whl", ".xz", ".zip",
})
_TOOL_ROOTS = frozenset({"tools"})
_REQUIRED_TOOLS = frozenset({
    "native-rc-smoke.mjs", "sidecar-common.mjs", "sidecar-verify.mjs",
    "native-rc-package.mjs", "native-runtime.mjs", "native-launcher.mjs",
    "fs-snapshot.mjs", "platform-targets.mjs", "build-inputs.mjs",
    "build-settings.mjs", "candidate-provenance.mjs",
    "darwin-linkage-validator.mjs", "node-runtime-authority.mjs",
})
_REQUIRED_FIXTURES = frozenset({
    "docs/examples/v0.4/brand-system/core-minimal/.tfsb/assets/fixture-mark-on-dark.toml",
    "docs/examples/v0.4/brand-system/core-minimal/.tfsb/assets/fixture-mark-on-light.toml",
    "docs/examples/v0.4/brand-system/core-minimal/.tfsb/brand-package.toml",
    "docs/examples/v0.4/brand-system/core-minimal/.tfsb/brand.toml",
    "docs/examples/v0.4/brand-system/core-minimal/.tfsb/companions/GUIDANCE.md",
    "docs/examples/v0.4/brand-system/core-minimal/.tfsb/project.toml",
    "docs/examples/v0.4/brand-system/core-minimal/GUIDANCE.md",
    "docs/examples/v0.4/brand-system/core-minimal/bundle/assets/fixture-mark-on-dark.svg",
    "docs/examples/v0.4/brand-system/core-minimal/bundle/assets/fixture-mark-on-light.svg",
    "docs/examples/v0.4/brand-system/core-minimal/bundle/brand/brand-package.toml",
    "docs/examples/v0.4/brand-system/core-minimal/bundle/brand/brand.toml",
    "docs/examples/v0.4/brand-system/core-minimal/bundle/companions/GUIDANCE.md",
    "docs/examples/v0.4/brand-system/core-minimal/bundle/tfsb-brand-manifest.json",
    "docs/examples/v0.4/brand-system/core-minimal/bundle/tfsb-manifest.json",
})
_ALLOWED_ROLES = frozenset({
    "application-smoke", "verifier-module", "verifier-support", "fixture",
})
_SOURCE_KEYS = frozenset({
    "authority", "repository", "commit", "tree", "record_sha256", "authority_identity",
})
_SOURCE_BINDING_KEYS = frozenset({"archive", "authority"})
_SOURCE_REF_KEYS = frozenset({"path", "size", "sha256", "evidence_path"})
_SPEC_KEYS = frozenset({
    "schema", "target", "source", "root", "tool_root", "fixture_root", "files",
    "source_binding", "closure_sha256",
})
_FILE_KEYS = frozenset({"path", "size", "sha256", "blob", "role", "evidence_path"})
_PROTECTED_COMPONENTS = frozenset({"db", "raw", ".serena", ".git"})
_SOURCE_TRIPLES = frozenset({
    "aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "x86_64-unknown-linux-gnu",
})


def _reject_protected_components(path: Any, *, code: str = "NEBULAR_SMOKE_CLOSURE") -> str:
    """Reject protected path components before validation or filesystem use."""
    if not isinstance(path, str) or "\x00" in path:
        fail(code)
    components = path.replace("\\", "/").split("/")
    if any(component.casefold() in _PROTECTED_COMPONENTS for component in components):
        fail(code)
    return path


def checked_live_path(value: str | Path, *, code: str = "NEBULAR_SMOKE_CLOSURE") -> Path:
    """Check live ancestors before resolution can follow an alias.

    Callers own fresh input/output trees; this does not provide isolation from
    concurrent filesystem replacement. Historical receipt paths are data and
    must not be passed here for interpretation on a different host.
    """
    if not isinstance(value, (str, Path)) or not str(value):
        fail(code)
    path = Path(_reject_protected_components(str(value), code=code)).absolute()
    _reject_protected_components(str(path), code=code)

    def check_ancestors(candidate: Path) -> None:
        current = Path(candidate.anchor)
        for component in candidate.parts[1:]:
            current = current / component
            try:
                metadata = os.lstat(current)
            except FileNotFoundError:
                break  # Remaining components belong to a future output tree.
            except OSError:
                fail(code)
            if stat.S_ISLNK(metadata.st_mode):
                fail(code)

    check_ancestors(path)
    try:
        resolved = path.resolve()
    except (OSError, RuntimeError, ValueError):
        fail(code)
    _reject_protected_components(str(resolved), code=code)
    check_ancestors(resolved)
    return resolved


def _expected_role(path: str, *, tool_root: str, fixture_root: str) -> str:
    """Derive the only role permitted by a transported closure path."""
    if path == f"{tool_root}/native-rc-smoke.mjs":
        return "application-smoke"
    if path.startswith(f"{tool_root}/"):
        return "verifier-module"
    if path == "package.json":
        return "verifier-support"
    if path.startswith(f"{fixture_root}/"):
        return "fixture"
    fail("NEBULAR_SMOKE_CLOSURE")


def _safe_member(path: Any, *, code: str = "NEBULAR_SMOKE_CLOSURE") -> str:
    path = _reject_protected_components(path, code=code)
    try:
        validate_safe_relative_posix_path(path)
    except Exception:
        fail(code)
    if any(path.lower().endswith(suffix) for suffix in _ARCHIVE_SUFFIXES):
        fail(code)
    return path


def _source_identity(source: Any) -> dict[str, str]:
    if not isinstance(source, Mapping) or set(source.keys()) != _SOURCE_KEYS:
        fail("NEBULAR_SMOKE_CLOSURE")
    if (source.get("authority") != "authenticated-product-source"
            or source.get("repository") != SOURCE_REPOSITORY
            or not isinstance(source.get("commit"), str)
            or not _HEX40.fullmatch(source["commit"])
            or not isinstance(source.get("tree"), str)
            or not _HEX40.fullmatch(source["tree"])
            or not isinstance(source.get("record_sha256"), str)
            or not _HEX64.fullmatch(source["record_sha256"])
            or not isinstance(source.get("authority_identity"), str)
            or not _HEX64.fullmatch(source["authority_identity"])):
        fail("NEBULAR_SMOKE_CLOSURE")
    return {key: source[key] for key in sorted(_SOURCE_KEYS)}


def _js_canonical(value: Any) -> bytes:
    """Match the maintained JS ``candidate-provenance`` identity bytes.

    The public source authority is produced by JavaScript's compact,
    lexicographically sorted-key JSON identity.  Python's archive ``canonical``
    helper deliberately appends a newline, so using it here would authenticate
    a different record.
    """
    if value is None or isinstance(value, (bool, str)):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value).encode("ascii")
    if isinstance(value, list):
        return b"[" + b",".join(_js_canonical(item) for item in value) + b"]"
    if isinstance(value, dict):
        return b"{" + b",".join(
            json.dumps(key, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            + b":" + _js_canonical(value[key])
            for key in sorted(value)
        ) + b"}"
    fail("NEBULAR_SMOKE_CLOSURE")


def _js_identity(value: Any) -> str:
    return hashlib.sha256(_js_canonical(value)).hexdigest()


def _validate_source_authority_body(authority: Any, *, expected_identity: str) -> dict[str, Any]:
    """Authenticate the complete fresh 071 build-source authority envelope."""
    required = {"schema", "version", "composition", "locks", "components", "recipe",
                "resourcePlans", "identity"}
    if not isinstance(authority, Mapping) or set(authority) != required:
        fail("NEBULAR_SMOKE_CLOSURE")
    if (authority.get("schema") != "nebular-public-build-source-v1"
            or authority.get("version") != "0.7.1"
            or authority.get("identity") != expected_identity):
        fail("NEBULAR_SMOKE_CLOSURE")
    for name in ("composition", "recipe", "identity"):
        if not isinstance(authority.get(name), str) or not _HEX64.fullmatch(authority[name]):
            fail("NEBULAR_SMOKE_CLOSURE")
    locks = authority.get("locks")
    components = authority.get("components")
    if (not isinstance(locks, Mapping) or set(locks) != {"cargo", "frontend"}
            or not isinstance(components, Mapping) or set(components) != {"burst", "loom", "solar"}
            or any(not isinstance(value, str) or not _HEX64.fullmatch(value)
                   for value in [*locks.values(), *components.values()])):
        fail("NEBULAR_SMOKE_CLOSURE")
    plans = authority.get("resourcePlans")
    if not isinstance(plans, Mapping) or set(plans) != _SOURCE_TRIPLES:
        fail("NEBULAR_SMOKE_CLOSURE")
    for plan in plans.values():
        if not isinstance(plan, Mapping) or set(plan) != {"resources", "externalBin"}:
            fail("NEBULAR_SMOKE_CLOSURE")
        for key in ("resources", "externalBin"):
            paths = plan[key]
            if (not isinstance(paths, list) or not paths
                    or len(paths) != len(set(paths))
                    or any(not isinstance(path, str)
                           or re.fullmatch(r"[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*", path) is None
                           for path in paths)):
                fail("NEBULAR_SMOKE_CLOSURE")
    unsigned = {key: authority[key] for key in required if key != "identity"}
    if _js_identity(unsigned) != authority["identity"]:
        fail("NEBULAR_SMOKE_CLOSURE")
    return dict(authority)


def _safe_source_path(path: Any) -> str:
    path = _reject_protected_components(path)
    try:
        validate_safe_relative_posix_path(path)
    except Exception:
        fail("NEBULAR_SMOKE_CLOSURE")
    return path


def _source_ref(value: Any, kind: str, *, descriptor: bool) -> dict[str, Any]:
    if not isinstance(value, Mapping) or not set(value).issubset(_SOURCE_REF_KEYS):
        fail("NEBULAR_SMOKE_CLOSURE")
    required = {"path", "size", "sha256"}
    if descriptor:
        required.add("evidence_path")
    if not required.issubset(value) or (not descriptor and "evidence_path" in value):
        fail("NEBULAR_SMOKE_CLOSURE")
    path = _safe_source_path(value["path"])
    name = Path(path).name
    if kind == "archive":
        valid_name = (name.startswith("theme-forge-nebular-fusion-v0.7.1-")
                      and name.endswith(".tar.gz"))
        maximum = SOURCE_ARCHIVE_SIZE
    else:
        valid_name = name.startswith("nebular-") and name.endswith(".json")
        maximum = SOURCE_AUTHORITY_SIZE
    if not valid_name:
        fail("NEBULAR_SMOKE_CLOSURE")
    if (type(value["size"]) is not int or not 0 < value["size"] <= maximum
            or not isinstance(value.get("sha256"), str)
            or not _HEX64.fullmatch(value["sha256"])):
        fail("NEBULAR_SMOKE_CLOSURE")
    result = {"path": path, "size": value["size"], "sha256": value["sha256"]}
    if descriptor:
        result["evidence_path"] = _safe_source_path(value["evidence_path"])
    return result


def _source_binding(value: Any, *, descriptor: bool) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _SOURCE_BINDING_KEYS:
        fail("NEBULAR_SMOKE_CLOSURE")
    return {
        kind: _source_ref(value[kind], kind, descriptor=descriptor)
        for kind in ("archive", "authority")
    }


def _file_record(item: Any, *, descriptor: bool) -> dict[str, Any]:
    if not isinstance(item, Mapping) or not set(item.keys()).issubset(_FILE_KEYS):
        fail("NEBULAR_SMOKE_CLOSURE")
    required = {"path", "size", "sha256", "blob", "role"}
    if not required.issubset(item.keys()):
        fail("NEBULAR_SMOKE_CLOSURE")
    path = _safe_member(item["path"])
    if type(item["size"]) is not int or not 0 < item["size"] <= MAX_SUPPORT_MEMBER_BYTES:
        fail("NEBULAR_SMOKE_CLOSURE")
    if (not isinstance(item["sha256"], str) or not _HEX64.fullmatch(item["sha256"])
            or not isinstance(item["blob"], str) or not _BLOB40.fullmatch(item["blob"])
            or item["sha256"] != item["sha256"].lower()
            or item["blob"] != item["blob"].lower()):
        fail("NEBULAR_SMOKE_CLOSURE")
    if item["role"] not in _ALLOWED_ROLES:
        fail("NEBULAR_SMOKE_CLOSURE")
    result = {
        "path": path, "size": item["size"], "sha256": item["sha256"],
        "blob": item["blob"], "role": item["role"],
    }
    if "evidence_path" in item:
        if not descriptor:
            fail("NEBULAR_SMOKE_CLOSURE")
        result["evidence_path"] = _safe_member(item["evidence_path"])
    return result


def _closure_digest(spec: Mapping[str, Any]) -> str:
    files = [
        {key: item[key] for key in ("path", "size", "sha256", "blob", "role")}
        for item in sorted(spec["files"], key=lambda item: item["path"])
    ]
    body = {
        "schema": spec["schema"], "target": spec["target"], "source": spec["source"],
        "root": spec["root"], "tool_root": spec["tool_root"],
        "fixture_root": spec["fixture_root"], "source_binding": {
            kind: {
                key: spec["source_binding"][kind][key]
                for key in ("path", "size", "sha256")
            }
            for kind in ("archive", "authority")
        }, "files": files,
    }
    return sha256(canonical(body))


def validate_smoke_support(
    value: Any,
    target: str,
    *,
    evidence_files: Mapping[str, Any] | None = None,
    descriptor: bool = False,
) -> dict[str, Any]:
    """Validate the bounded, source-authenticated support contract."""
    if not isinstance(value, Mapping) or set(value.keys()) != _SPEC_KEYS:
        fail("NEBULAR_SMOKE_CLOSURE")
    if value.get("schema") != SMOKE_SUPPORT_SCHEMA or value.get("target") != target:
        fail("NEBULAR_SMOKE_CLOSURE")
    root = _safe_member(value.get("root"))
    tool_root = _safe_member(value.get("tool_root"))
    fixture_root = _safe_member(value.get("fixture_root"))
    if tool_root not in _TOOL_ROOTS or not fixture_root.startswith("docs/examples/v0.4/brand-system/core-minimal"):
        fail("NEBULAR_SMOKE_CLOSURE")
    source = _source_identity(value.get("source"))
    source_binding = _source_binding(
        value.get("source_binding"), descriptor=descriptor,
    )
    files = value.get("files")
    if not isinstance(files, list) or not 1 <= len(files) <= MAX_SUPPORT_FILES:
        fail("NEBULAR_SMOKE_CLOSURE")
    records = [_file_record(item, descriptor=descriptor) for item in files]
    paths = [item["path"] for item in records]
    if len(set(paths)) != len(paths):
        fail("NEBULAR_SMOKE_CLOSURE")
    allowed_prefixes = tuple(f"{root}/" for root in _TOOL_ROOTS) + (f"{fixture_root}/",)
    if any(path != "package.json" and not path.startswith(allowed_prefixes) for path in paths):
        fail("NEBULAR_SMOKE_CLOSURE")
    required_paths = {f"{tool_root}/{name}" for name in _REQUIRED_TOOLS}
    expected_paths = required_paths | _REQUIRED_FIXTURES
    if "package.json" in paths:
        expected_paths.add("package.json")
    if set(paths) != expected_paths:
        fail("NEBULAR_SMOKE_CLOSURE")
    if any(item["role"] != _expected_role(
            item["path"], tool_root=tool_root, fixture_root=fixture_root,
    ) for item in records):
        fail("NEBULAR_SMOKE_CLOSURE")
    total = sum(item["size"] for item in records)
    if total > MAX_SUPPORT_TOTAL_BYTES:
        fail("NEBULAR_SMOKE_CLOSURE")
    normalized = {
        "schema": SMOKE_SUPPORT_SCHEMA, "target": target, "source": source,
        "root": root, "tool_root": tool_root, "fixture_root": fixture_root,
        "source_binding": source_binding,
        "files": sorted(records, key=lambda item: item["path"]),
    }
    if value.get("closure_sha256") != _closure_digest(normalized):
        fail("NEBULAR_SMOKE_CLOSURE")
    normalized["closure_sha256"] = value["closure_sha256"]
    if evidence_files is not None:
        for item in normalized["files"]:
            evidence_path = item.get("evidence_path")
            evidence_path = _safe_source_path(evidence_path)
            evidence = evidence_files.get(evidence_path)
            if not isinstance(evidence, Mapping):
                fail("NEBULAR_SMOKE_CLOSURE")
            if (evidence.get("path", evidence_path) != evidence_path
                    or evidence.get("size") != item["size"]
                    or evidence.get("sha256") != item["sha256"]):
                fail("NEBULAR_SMOKE_CLOSURE")
        for kind, ref in source_binding.items():
            evidence_path = ref.get("evidence_path")
            evidence_path = _safe_source_path(evidence_path)
            evidence = evidence_files.get(evidence_path)
            if not isinstance(evidence, Mapping):
                fail("NEBULAR_SMOKE_CLOSURE")
            if (evidence.get("path", evidence_path) != evidence_path
                    or evidence.get("size") != ref["size"]
                    or evidence.get("sha256") != ref["sha256"]):
                fail("NEBULAR_SMOKE_CLOSURE")
    return normalized


def _source_archive_members(
    data: bytes, *, expected_size: int, expected_sha256: str,
) -> dict[str, tuple[int, str, str, int]]:
    """Read only regular, bounded source members without extracting them."""
    if len(data) != expected_size or sha256(data) != expected_sha256:
        fail("NEBULAR_SMOKE_CLOSURE")
    parity7 = expected_size == _PARITY7_SOURCE_SIZE and expected_sha256 == _PARITY7_SOURCE_SHA256
    total_limit = _PARITY7_SOURCE_TOTAL if parity7 else MAX_SOURCE_ARCHIVE_TOTAL_BYTES
    member_limit = _PARITY7_SOURCE_MEMBERS if parity7 else MAX_SOURCE_ARCHIVE_MEMBERS
    members: dict[str, tuple[int, str, str, int]] = {}
    total = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            for index, member in enumerate(archive, 1):
                if index > member_limit or (
                    member.pax_headers
                    and set(member.pax_headers) != {"path"}
                ):
                    fail("NEBULAR_SMOKE_CLOSURE")
                name = _safe_source_path(member.name)
                if member.pax_headers and member.pax_headers.get("path") != member.name:
                    fail("NEBULAR_SMOKE_CLOSURE")
                if not member.isreg() or name in members or member.size < 0:
                    fail("NEBULAR_SMOKE_CLOSURE")
                if member.size > MAX_SUPPORT_MEMBER_BYTES:
                    fail("NEBULAR_SMOKE_CLOSURE")
                if name in _REQUIRED_TOOLS | _REQUIRED_FIXTURES and (
                        member.pax_headers or member.mode & 0o111):
                    fail("NEBULAR_SMOKE_CLOSURE")
                stream = archive.extractfile(member)
                if stream is None:
                    fail("NEBULAR_SMOKE_CLOSURE")
                content = stream.read(member.size + 1)
                if len(content) != member.size:
                    fail("NEBULAR_SMOKE_CLOSURE")
                total += len(content)
                if total > total_limit:
                    fail("NEBULAR_SMOKE_CLOSURE")
                members[name] = (
                    len(content), sha256(content),
                    hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest(),
                    0o755 if member.mode & 0o111 else 0o644,
                )
    except AdmissionError:
        raise
    except (OSError, tarfile.TarError, EOFError, ValueError):
        fail("NEBULAR_SMOKE_CLOSURE")
    # The archive is a fresh 071 source offer, so its member count is not a
    # historical 070 identity.  Required tool/fixture paths and the bounded
    # archive limits above remain the admission floor.
    if parity7 and (len(members) != _PARITY7_SOURCE_MEMBERS or total != _PARITY7_SOURCE_TOTAL):
        fail("NEBULAR_SMOKE_CLOSURE")
    if len(members) < len(_REQUIRED_TOOLS | _REQUIRED_FIXTURES):
        fail("NEBULAR_SMOKE_CLOSURE")
    return members


def _source_composition_identity(members: Mapping[str, tuple[int, str, str, int]]) -> str:
    inventory = [
        {"path": path, "bytes": row[0], "mode": row[3], "sha256": row[1]}
        for path, row in sorted(members.items())
    ]
    return _js_identity(inventory)


def _verify_source_authority(
    data: bytes, *, expected_size: int, expected_sha256: str,
    expected_identity: str,
) -> dict[str, Any]:
    if len(data) != expected_size or sha256(data) != expected_sha256:
        fail("NEBULAR_SMOKE_CLOSURE")
    try:
        authority = strict_json(data)
    except Exception:
        fail("NEBULAR_SMOKE_CLOSURE")
    return _validate_source_authority_body(authority, expected_identity=expected_identity)


def verify_source_binding(
    raw_root: str | Path,
    support: Mapping[str, Any],
    *,
    root_is_support_root: bool = False,
    expected_source: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Authenticate the fixed source archive and every transported closure member."""
    checked = validate_smoke_support(support, str(support.get("target")), descriptor=False)
    root = checked_live_path(raw_root)
    source_root = root if root_is_support_root else root / checked["root"]
    archive_ref = checked["source_binding"]["archive"]
    authority_ref = checked["source_binding"]["authority"]
    archive_data = physical_bytes(
        checked_live_path(source_root / archive_ref["path"]), limit=SOURCE_ARCHIVE_SIZE,
    )
    authority_data = physical_bytes(
        checked_live_path(source_root / authority_ref["path"]), limit=SOURCE_AUTHORITY_SIZE,
    )
    authority = _verify_source_authority(
        authority_data,
        expected_size=authority_ref["size"],
        expected_sha256=authority_ref["sha256"],
        expected_identity=checked["source"]["authority_identity"],
    )
    members = _source_archive_members(
        archive_data,
        expected_size=archive_ref["size"],
        expected_sha256=archive_ref["sha256"],
    )
    if authority.get("composition") != _source_composition_identity(members):
        fail("NEBULAR_SMOKE_CLOSURE")
    # The source archive/authority does not carry Git coordinates.  A caller
    # that has independently authenticated a source offer/capture can provide
    # it here; accepting a different coordinate frame is never allowed.
    if expected_source is not None:
        try:
            expected = _source_identity(expected_source)
        except Exception:
            fail("NEBULAR_SMOKE_CLOSURE")
        if expected != checked["source"]:
            fail("NEBULAR_SMOKE_CLOSURE")
    for item in checked["files"]:
        observed = members.get(item["path"])
        if observed is None or observed[:3] != (item["size"], item["sha256"], item["blob"]):
            fail("NEBULAR_SMOKE_CLOSURE")
    return {
        "archive_sha256": sha256(archive_data),
        "authority_sha256": sha256(authority_data),
        "member_count": len(members),
        "composition": authority["composition"],
    }


def _write_regular(destination: Path, data: bytes) -> None:
    destination = checked_live_path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if destination.exists() or destination.is_symlink():
        fail("NEBULAR_SMOKE_CLOSURE")
    try:
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        destination.chmod(0o644)
    except OSError:
        try:
            destination.unlink()
        except OSError:
            pass
        fail("NEBULAR_SMOKE_CLOSURE")


def materialize_smoke_support(
    raw_root: str | Path,
    support: Mapping[str, Any],
    scratch: str | Path,
    *,
    target: str,
    expected_source: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Copy authenticated support files into a fresh source tree."""
    checked = validate_smoke_support(support, target)
    root = checked_live_path(raw_root)
    scratch_path = checked_live_path(scratch)
    if scratch_path.exists() or scratch_path.is_symlink():
        fail("NEBULAR_SMOKE_CLOSURE")
    source_verification = verify_source_binding(
        raw_root, checked, expected_source=expected_source,
    )
    scratch_path.mkdir(parents=True, mode=0o700)
    source = scratch_path / "source"
    records = []
    for ref in checked["source_binding"].values():
        source_file = checked_live_path(root / checked["root"] / ref["path"])
        data = physical_bytes(source_file, limit=SOURCE_ARCHIVE_SIZE)
        if len(data) != ref["size"] or sha256(data) != ref["sha256"]:
            fail("NEBULAR_SMOKE_CLOSURE")
        _write_regular(source / ref["path"], data)
    for item in checked["files"]:
        source_file = checked_live_path(root / checked["root"] / item["path"])
        data = physical_bytes(source_file, limit=MAX_SUPPORT_MEMBER_BYTES)
        if len(data) != item["size"] or sha256(data) != item["sha256"]:
            fail("NEBULAR_SMOKE_CLOSURE")
        blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        if blob != item["blob"]:
            fail("NEBULAR_SMOKE_CLOSURE")
        destination = source / item["path"]
        _write_regular(destination, data)
        records.append({key: item[key] for key in ("path", "size", "sha256", "blob", "role")})
    bindings = source.parent / "source-bindings.json"
    _write_regular(bindings, canonical(records))
    tools = source / checked["tool_root"]
    fixture = source / checked["fixture_root"]
    if not tools.is_dir() or not fixture.is_dir():
        fail("NEBULAR_SMOKE_CLOSURE")
    return {
        "source": source,
        "checkout": source,
        "tools": tools,
        "scratch": scratch_path,
        "records": records,
        "source_identity": checked["source"],
        "source_binding": checked["source_binding"],
        "closure_sha256": checked["closure_sha256"],
        "source_member_count": source_verification["member_count"],
        "fixture_root": checked["fixture_root"],
    }


def installed_runtime_root(gui_path: str | Path, target: str) -> Path:
    """Resolve the maintained smoke launch root from the authenticated GUI path."""
    path = checked_live_path(gui_path)
    if target == "darwin-arm64":
        app_parts = [index for index, part in enumerate(path.parts) if part.endswith(".app")]
        if len(app_parts) != 1 or app_parts[0] + 1 >= len(path.parts):
            fail("NEBULAR_SMOKE_CLOSURE")
        return Path(*path.parts[: app_parts[0] + 1])
    if target in {"linux-arm64-gnu", "linux-x64-gnu"}:
        if len(path.parents) < 2 or path.parent.name != "bin":
            fail("NEBULAR_SMOKE_CLOSURE")
        return path.parent.parent
    fail("NEBULAR_SMOKE_CLOSURE")
