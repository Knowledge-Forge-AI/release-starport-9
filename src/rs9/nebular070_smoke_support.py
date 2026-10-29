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
import os
import re
import stat
import tarfile
from pathlib import Path
from typing import Any, Mapping

from rs9.tf_pypi_archive import AdmissionError, canonical, fail, physical_bytes, sha256
from rs9.tf_pypi_model import strict_json
from rs9.security import validate_safe_relative_posix_path


SMOKE_SUPPORT_SCHEMA = "rs9.nebular070-smoke-support.v1"
MAX_SUPPORT_FILES = 512
MAX_SUPPORT_MEMBER_BYTES = 8 * 1024 * 1024
MAX_SUPPORT_TOTAL_BYTES = 32 * 1024 * 1024
SOURCE_ARCHIVE_NAME = "theme-forge-nebular-fusion-v0.7.0-source.tar.gz"
SOURCE_ARCHIVE_SIZE = 4_453_031
SOURCE_ARCHIVE_SHA256 = "183f99f5af7228eb6498ab990fa514bb501586e8a0ff31a93a7bc05c736a805a"
SOURCE_AUTHORITY_NAME = "nebular-compiled-public-build-source-authority-v0.7.0.json"
SOURCE_AUTHORITY_SIZE = 1_767
SOURCE_AUTHORITY_SHA256 = "c0cb518e56f3dd17e9d48fe3d98255780671fe3e4c63a6c81aaf59ea58e250d2"
SOURCE_AUTHORITY_IDENTITY = "f464c6f0af9535d476c9e1e61d8cffa3a2eb47b339a569bd68c8de9fe9d81f25"
SOURCE_REPOSITORY = "Knowledge-Forge-AI/theme-forge-nebular-fusion"
SOURCE_COMMIT = "cadb40c4972f68f314096ff60fbcfb4da950c161"
SOURCE_TREE = "27c643b6375c2aafde314799c4f08e844c14992c"
MAX_SOURCE_ARCHIVE_MEMBERS = 4_096
MAX_SOURCE_ARCHIVE_TOTAL_BYTES = 32 * 1024 * 1024
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
            or source.get("commit") != SOURCE_COMMIT
            or source.get("tree") != SOURCE_TREE
            or source.get("record_sha256") != SOURCE_AUTHORITY_SHA256
            or source.get("authority_identity") != SOURCE_AUTHORITY_IDENTITY):
        fail("NEBULAR_SMOKE_CLOSURE")
    return {key: source[key] for key in sorted(_SOURCE_KEYS)}


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
    expected_name, expected_size, expected_sha = (
        (SOURCE_ARCHIVE_NAME, SOURCE_ARCHIVE_SIZE, SOURCE_ARCHIVE_SHA256)
        if kind == "archive"
        else (SOURCE_AUTHORITY_NAME, SOURCE_AUTHORITY_SIZE, SOURCE_AUTHORITY_SHA256)
    )
    if Path(path).name != expected_name:
        fail("NEBULAR_SMOKE_CLOSURE")
    if type(value["size"]) is not int or value["size"] != expected_size:
        fail("NEBULAR_SMOKE_CLOSURE")
    if value.get("sha256") != expected_sha:
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


def _source_archive_members(data: bytes) -> dict[str, tuple[int, str, str]]:
    """Read only regular, bounded source members without extracting them."""
    if len(data) != SOURCE_ARCHIVE_SIZE or sha256(data) != SOURCE_ARCHIVE_SHA256:
        fail("NEBULAR_SMOKE_CLOSURE")
    members: dict[str, tuple[int, str, str]] = {}
    total = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            for index, member in enumerate(archive, 1):
                if index > MAX_SOURCE_ARCHIVE_MEMBERS or (
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
                if total > MAX_SOURCE_ARCHIVE_TOTAL_BYTES:
                    fail("NEBULAR_SMOKE_CLOSURE")
                members[name] = (
                    len(content), sha256(content),
                    hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest(),
                )
    except AdmissionError:
        raise
    except (OSError, tarfile.TarError, EOFError, ValueError):
        fail("NEBULAR_SMOKE_CLOSURE")
    if len(members) != 1_559:
        fail("NEBULAR_SMOKE_CLOSURE")
    return members


def _verify_source_authority(data: bytes) -> None:
    if len(data) != SOURCE_AUTHORITY_SIZE or sha256(data) != SOURCE_AUTHORITY_SHA256:
        fail("NEBULAR_SMOKE_CLOSURE")
    try:
        authority = strict_json(data)
    except Exception:
        fail("NEBULAR_SMOKE_CLOSURE")
    if (
        not isinstance(authority, Mapping)
        or authority.get("schema") != "nebular-public-build-source-v1"
        or authority.get("version") != "0.7.0"
        or authority.get("identity") != SOURCE_AUTHORITY_IDENTITY
    ):
        fail("NEBULAR_SMOKE_CLOSURE")


def verify_source_binding(
    raw_root: str | Path,
    support: Mapping[str, Any],
    *,
    root_is_support_root: bool = False,
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
    _verify_source_authority(authority_data)
    members = _source_archive_members(archive_data)
    for item in checked["files"]:
        observed = members.get(item["path"])
        if observed is None or observed != (item["size"], item["sha256"], item["blob"]):
            fail("NEBULAR_SMOKE_CLOSURE")
    return {
        "archive_sha256": sha256(archive_data),
        "authority_sha256": sha256(authority_data),
        "member_count": len(members),
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
) -> dict[str, Any]:
    """Copy authenticated support files into a fresh source tree."""
    checked = validate_smoke_support(support, target)
    root = checked_live_path(raw_root)
    scratch_path = checked_live_path(scratch)
    if scratch_path.exists() or scratch_path.is_symlink():
        fail("NEBULAR_SMOKE_CLOSURE")
    verify_source_binding(raw_root, checked)
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

