"""Successor Python wheel builder for the authenticated Nebular 0.6.1 payload.

The successor keeps the upstream application identity at ``0.6.1`` while using
the first Python distribution post release, ``0.6.1.post1``.  It deliberately
builds a verified legacy candidate first and then performs a deterministic,
small reassembly.  The older native builder remains the source of the archive,
manifest, and isolated helper contract; this module owns only the successor
metadata, launcher, provenance, and RECORD.
"""
from __future__ import annotations

import io
import json
import os
import re
import stat
import tempfile
import zipfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from rs9.archives import inspect_archive
from rs9.errors import ContractError
from rs9.hosted_platforms import (
    platform_contract,
    select_payload,
    system_from_target_triple,
)
from rs9.materialize import parse_manifest_members
from rs9.nebular_lineage import verify_forward_lineage_proof
from rs9.records import record_sha256
from rs9.release_core import ReleaseCapture, authenticated_record_hash, digest
from rs9.scratch import canonical
from rs9.security import scan_bytes_for_credentials, validate_safe_relative_posix_path
from rs9.verify_wheel import verify_wheel_record_bidirectional
from rs9.wheel import WheelBuildResult, WheelWithheldError, format_record
from rs9.wheel_native import (
    DISTRIBUTION_NAME,
    PACKAGE_NAME,
    PRODUCT_ID,
    build_native_wheel,
    get_embedded_rs9_helpers,
)

APPLICATION_VERSION = "0.6.1"
DISTRIBUTION_VERSION = "0.6.1.post1"
SUCCESSOR_PROVENANCE_SCHEMA = "rs9.wheel-provenance.v2alpha1"
LICENSE_EXPRESSION = "AGPL-3.0-or-later OR LicenseRef-Commercial"
LEGAL_FILES = ("LICENSE", "NOTICE", "COMMERCIAL-LICENSE.md")
EXPECTED_COMMAND = "tfnf"
SUPPORTED_SUCCESSOR_SYSTEMS = frozenset({"aarch64-darwin", "x86_64-linux", "aarch64-linux"})
DEFAULT_DESCRIPTION_PATH = "operators/tf-pypi/descriptions/nebular-fusion.md"
_HEX40 = re.compile(r"[0-9a-f]{40}\Z")


def _error(code: str, message: str, **details: Any) -> ContractError:
    return ContractError(code, message, details=details or None)


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _safe_destination(path: Path) -> None:
    absolute = path.absolute()
    if path.is_symlink() or any(parent.is_symlink() for parent in (absolute, *absolute.parents)):
        raise _error("UNSAFE_DESTINATION", "Wheel destination ancestry contains a symlink")


def _write_exclusive(path: Path, data: bytes) -> None:
    _safe_destination(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o644)
    except FileExistsError:
        raise _error("DESTINATION_EXISTS", "Wheel destination already exists") from None
    except OSError as exc:
        raise _error("UNSAFE_DESTINATION", "Wheel destination is unavailable") from exc
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
    except Exception:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def _resolve_target(system: str | None, target_platform: str | None, platform_tag: str | None,
                    candidate_only: bool) -> tuple[str, str, bool, str]:
    if system is None and target_platform is None:
        system, target_platform = "aarch64-darwin", "aarch64-apple-darwin"
    elif system is None:
        system = system_from_target_triple(target_platform)  # type: ignore[arg-type]
    elif target_platform is None:
        target_platform = platform_contract(system).target_triple
    else:
        if system_from_target_triple(target_platform) != system:
            raise _error("INCONSISTENT_PLATFORM", "System and target triple disagree",
                         system=system, target_triple=target_platform)
    if system not in SUPPORTED_SUCCESSOR_SYSTEMS:
        raise _error("INVALID_ARCHITECTURE", "Successor wheels support exactly the reviewed native systems",
                     system=system, supported_systems=sorted(SUPPORTED_SUCCESSOR_SYSTEMS))
    contract = platform_contract(system)
    if platform_tag == "any":
        raise _error("UNSUPPORTED_PLATFORM", "Successor wheels cannot use the universal tag")
    is_linux = system.endswith("-linux")
    expected_linux_tag = contract.platform_tag
    if is_linux and platform_tag and platform_tag not in {expected_linux_tag, "manylinux", "musllinux"}:
        if "manylinux" in platform_tag or "musllinux" in platform_tag:
            raise WheelWithheldError(
                "MANYLINUX_UNPROVEN",
                "manylinux and musllinux claims are withheld for the generic Linux candidate",
                product_id=PRODUCT_ID,
                reason="manylinux_unproven",
            )
        raise _error("INCONSISTENT_PLATFORM", "Linux wheel tag does not match the selected target architecture",
                     system=system, platform_tag=platform_tag, expected_platform_tag=expected_linux_tag)
    if not is_linux and platform_tag and "linux" in platform_tag:
        raise _error("INCONSISTENT_PLATFORM", "Darwin successor wheels cannot use a Linux platform tag",
                     system=system, platform_tag=platform_tag)
    if is_linux and not candidate_only:
        raise WheelWithheldError(
            "MANYLINUX_UNPROVEN",
            "Linux successor wheels are generic candidates until a manylinux policy is independently proven",
            product_id=PRODUCT_ID,
            reason="manylinux_unproven",
        )
    if is_linux and platform_tag and ("manylinux" in platform_tag or "musllinux" in platform_tag):
        raise WheelWithheldError(
            "MANYLINUX_UNPROVEN",
            "manylinux and musllinux claims are withheld for the generic Linux candidate",
            product_id=PRODUCT_ID,
            reason="manylinux_unproven",
        )
    family = "linux" if is_linux else "darwin"
    return system, target_platform, is_linux, family


def _read_description(description_path: str | Path) -> tuple[str, bytes]:
    path = Path(description_path)
    if not path.is_absolute():
        path = _repo_root() / path
    if path.is_symlink() or any(parent.is_symlink() for parent in (path, *path.parents)):
        raise _error("UNSAFE_DESCRIPTION", "Description ancestry contains a symlink")
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise _error("MISSING_DESCRIPTION", "Markdown description is unavailable") from exc
    if not data or len(data) > 2 * 1024 * 1024 or not data.endswith(b"\n"):
        raise _error("INVALID_DESCRIPTION", "Description must be bounded and end with a newline")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _error("INVALID_DESCRIPTION", "Description must be UTF-8 Markdown") from exc
    if any(ord(ch) < 32 and ch not in "\n\r\t" or ord(ch) == 127 for ch in text):
        raise _error("INVALID_DESCRIPTION", "Description contains control characters")
    scan_bytes_for_credentials(data, token_scan=True)
    return str(path.relative_to(_repo_root())) if path.is_relative_to(_repo_root()) else path.name, data


def _description_bytes(description_path: str | Path) -> tuple[str, bytes]:
    """Read the RS9-owned candidate README in both fixture and authenticated modes."""
    return _read_description(description_path)


def _legal_files(capture: ReleaseCapture | None, fixture_only: bool,
                 license_files: Mapping[str, bytes] | None) -> dict[str, bytes]:
    if fixture_only:
        observed = dict(license_files or {})
    else:
        if capture is None:
            raise _error("LICENSE_AUTHORITY", "Authenticated release capture is required")
        observed = (
            dict(license_files)
            if license_files is not None
            else {name: capture.source.get(name) for name in LEGAL_FILES}
        )
    if set(observed) != set(LEGAL_FILES):
        raise _error("LEGAL_FILES", "Exactly the three successor legal files are required",
                     expected_legal_files=list(LEGAL_FILES), observed_legal_files=sorted(observed))
    for name, data in observed.items():
        validate_safe_relative_posix_path(name)
        if not isinstance(data, bytes) or not data:
            raise _error("LEGAL_FILES", "Legal files must be non-empty byte strings")
        scan_bytes_for_credentials(data, token_scan=True)
    if not fixture_only:
        if capture is None:
            raise _error("LICENSE_AUTHORITY", "Authenticated release capture is required")
        for name in LEGAL_FILES:
            if capture.source.get(name) != observed[name]:
                raise _error("LICENSE_AUTHORITY", "Legal files must equal authenticated tagged source bytes")
    return {name: observed[name] for name in LEGAL_FILES}


def _capture_identity(capture: ReleaseCapture | None, fixture_only: bool) -> tuple[str | None, dict[str, Any] | None]:
    if fixture_only:
        if capture is not None:
            raise _error("FIXTURE_AUTHORITY", "Fixture mode cannot mix authenticated capture and raw inputs")
        return None, None
    if not isinstance(capture, ReleaseCapture):
        raise _error("PROVENANCE_REQUIRED", "Authenticated release capture is required")
    record_hash = authenticated_record_hash(capture)
    record = capture.record
    if record.get("repository", {}).get("full_name") != "Knowledge-Forge-AI/" + PRODUCT_ID:
        raise _error("REPOSITORY_MISMATCH", "Authenticated capture is for a different repository")
    if record.get("release", {}).get("tag") != "v" + APPLICATION_VERSION:
        raise _error("TAG_MISMATCH", "Authenticated capture is for a different upstream version")
    tag = record.get("tag", {})
    commit, tree = tag.get("commit"), tag.get("tree")
    if not isinstance(commit, str) or not _HEX40.fullmatch(commit) or not isinstance(tree, str) or not _HEX40.fullmatch(tree):
        raise _error("RELEASE_IDENTITY", "Authenticated commit and tree identities are required")
    return record_hash, {"repository": record["repository"]["full_name"], "tag": record["release"]["tag"],
                        "commit": commit, "tree": tree}


def _rs9_source_binding(commit: str | None, tree: str | None, fixture_only: bool) -> dict[str, Any]:
    """Bind explicit RS9 source coordinates without guessing a dirty checkout HEAD."""
    if (commit is None) != (tree is None):
        raise _error("RS9_SOURCE_IDENTITY", "RS9 source commit and tree must be supplied together")
    if commit is None:
        if not fixture_only:
            raise _error("RS9_SOURCE_IDENTITY", "Authenticated successor builds require explicit RS9 source coordinates")
        return {"status": "pending", "binding": "fixture-only", "commit": None, "tree": None, "verified": False}
    if (not isinstance(commit, str) or not isinstance(tree, str)
            or not _HEX40.fullmatch(commit) or not _HEX40.fullmatch(tree)):
        raise _error("RS9_SOURCE_IDENTITY", "RS9 source commit and tree must be lowercase 40-hex identities")
    return {
        "status": "candidate-input",
        "binding": "explicit-reviewed-source-input",
        "commit": commit,
        "tree": tree,
        "verified": False,
    }


def _archive_inputs(capture: ReleaseCapture | None, fixture_only: bool, system: str,
                    archive_path: str | Path | None, archive_bytes: bytes | None,
                    manifest: dict[str, Any] | None) -> tuple[dict[str, Any] | None, bytes | None, str | None,
                                                               str | None, str | None, str | None]:
    if not fixture_only:
        if capture is None:
            raise _error("PROVENANCE_REQUIRED", "Authenticated release capture is required")
        selected = select_payload(capture, system, allow_any=False)
        asset_id = selected["id"]
        path = capture.archives[asset_id]
        data = path.read_bytes()
        if len(data) != selected["size"] or digest(data) != selected["sha256"]:
            raise _error("INPUT_CHANGED", "Authenticated payload bytes changed")
        captured_manifest = capture.manifests[asset_id]
        selected_manifest = captured_manifest if manifest is None else manifest
        if selected_manifest != captured_manifest:
            raise _error("INPUT_CHANGED", "Manifest override differs from authenticated manifest")
        launch = selected.get("launchers", {}).get(EXPECTED_COMMAND)
        gui = selected.get("commands", {}).get(EXPECTED_COMMAND)
        launch_path = launch.get("path") if isinstance(launch, dict) else launch
        gui_path = gui.get("path") if isinstance(gui, dict) else gui
        return selected_manifest, data, selected["name"], launch_path, gui_path, str(selected["id"])
    if archive_path is None and archive_bytes is None:
        raise _error("MISSING_ASSET", "Fixture mode requires an archive")
    if archive_path is not None and archive_bytes is not None:
        raise _error("AMBIGUOUS_ASSET", "Provide one fixture archive input")
    if archive_path is not None:
        path = Path(archive_path)
        if path.is_symlink() or any(parent.is_symlink() for parent in (path, *path.parents)):
            raise _error("UNSAFE_ARCHIVE", "Fixture archive ancestry contains a symlink")
        data, name = path.read_bytes(), path.name
    else:
        if archive_bytes is None:
            raise _error("MISSING_ASSET", "Fixture archive bytes are unavailable")
        if system.endswith("-linux"):
            arch = "aarch64" if system.startswith(("aarch64", "arm64")) else "x86_64"
            name = f"theme-forge-nebular-fusion-v0.6.1-{arch}-unknown-linux-gnu.tar.gz"
        else:
            name = "theme-forge-nebular-fusion-v0.6.1-aarch64-apple-darwin.app.tar.gz"
        data = archive_bytes
    with tempfile.TemporaryDirectory(prefix="rs9-nebular-inspect-", dir=_repo_root()) as td:
        path = Path(td) / name
        path.write_bytes(data)
        actual_manifest = inspect_archive(path, commands={})
    if manifest is not None and canonical(manifest) != canonical(actual_manifest):
        raise _error("INPUT_CHANGED", "Fixture manifest does not describe the supplied archive bytes")
    selected_manifest = actual_manifest
    return selected_manifest, data, name, None, None, None


def _manifest_path(manifest: Mapping[str, Any], path: str, *, field: str) -> None:
    validate_safe_relative_posix_path(path)
    root = manifest.get("root")
    members = {row.get("path"): row for row in manifest.get("members", []) if isinstance(row, dict)}
    entry = members.get(path)
    if not isinstance(root, str) or not entry or entry.get("type") != "file" or not (int(entry.get("mode", 0)) & 0o111):
        raise _error("COMMAND_PATH", f"Authenticated {field} path is not an executable archive file")


def _path_from_capture_or_fixture(manifest: Mapping[str, Any], launch_path: str | None,
                                  gui_path: str | None, launcher_path: str | Path | None,
                                  gui_path_override: str | Path | None) -> tuple[str, str]:
    shell = str(launcher_path) if launcher_path is not None else launch_path
    gui = str(gui_path_override) if gui_path_override is not None else gui_path
    if not shell or not gui:
        raise _error("COMMAND_IDENTITY", "Exact launcher and GUI paths are required")
    _manifest_path(manifest, shell, field="launcher")
    _manifest_path(manifest, gui, field="GUI")
    return shell, gui


def _profile_license_facts(profile_result: Mapping[str, Any] | None) -> dict[str, str | None]:
    if not isinstance(profile_result, Mapping):
        return {"status": None, "comparison": None}
    sections = profile_result.get("sections")
    if not isinstance(sections, Mapping):
        return {"status": None, "comparison": None}
    license_section = sections.get("license")
    if not isinstance(license_section, Mapping):
        legacy = sections.get("legacy_ingestion")
        license_section = legacy.get("license") if isinstance(legacy, Mapping) else None
    if not isinstance(license_section, Mapping):
        return {"status": None, "comparison": None}
    return {
        "status": license_section.get("status") if isinstance(license_section.get("status"), str) else None,
        "comparison": license_section.get("comparison") if isinstance(license_section.get("comparison"), str) else None,
    }


def _render_successor_launcher(archive_name: str, archive_sha256: str, manifest_sha256: str,
                               shell_path: str, gui_path: str, family: str, arch: str) -> bytes:
    source = '''"""Theme Forge Nebular Fusion successor launcher; offline and identity-bound."""
from __future__ import annotations
import hashlib, json, os, platform, sys
from pathlib import Path

_PACKAGE_DIR = Path(__file__).resolve().parent
_ISOLATED = _PACKAGE_DIR / "_isolated"
if str(_ISOLATED) not in sys.path:
    sys.path.insert(0, str(_ISOLATED))
if "rs9" in sys.modules and Path(sys.modules["rs9"].__file__).resolve().parent != (_ISOLATED / "rs9").resolve():
    raise RuntimeError("Conflicting isolated materializer namespace")
from rs9.materialize import materialize_payload, resolve_launcher

APPLICATION_VERSION = __APP_VERSION__
DISTRIBUTION_VERSION = __DIST_VERSION__
ARCHIVE_FILENAME = __ARCHIVE_NAME__
EXPECTED_ARCHIVE_SHA256 = __ARCHIVE_SHA__
EXPECTED_MANIFEST_SHA256 = __MANIFEST_SHA__
SHELL_TARGET = __SHELL_TARGET__
GUI_TARGET = __GUI_TARGET__
TARGET_FAMILY = __FAMILY__
TARGET_ARCH = __ARCH__

def _cache_dir() -> Path:
    if "THEME_FORGE_CACHE_DIR" in os.environ:
        raw = os.environ["THEME_FORGE_CACHE_DIR"]
        if not raw or not Path(raw).is_absolute():
            raise RuntimeError("THEME_FORGE_CACHE_DIR must be a non-empty absolute path")
        return Path(raw)
    xdg = os.environ.get("XDG_CACHE_HOME")
    if xdg and Path(xdg).is_absolute():
        return Path(xdg) / "rs9" / "theme-forge-nebular-fusion"
    if TARGET_FAMILY == "darwin":
        return (Path.home() / "Library" / "Caches" / "rs9" / "theme-forge-nebular-fusion").absolute()
    return (Path.home() / ".cache" / "rs9" / "theme-forge-nebular-fusion").absolute()

def _platform_check() -> None:
    machine = platform.machine()
    if TARGET_FAMILY == "darwin":
        valid = sys.platform == "darwin" and machine in ("arm64", "aarch64")
        if not valid:
            raise RuntimeError("This successor wheel cannot run on the current Darwin architecture")
        return
    expected = ("x86_64", "amd64") if TARGET_ARCH == "x86_64" else ("aarch64", "arm64")
    if not sys.platform.startswith("linux") or machine not in expected:
        raise RuntimeError("This successor wheel requires its captured Linux target architecture")
    libc_name = (platform.libc_ver()[0] or "").lower()
    if libc_name != "glibc":
        raise RuntimeError("This successor wheel requires GNU glibc on Linux")

def _relative(root: Path, target: str) -> str:
    prefix = root.name + "/"
    if not target.startswith(prefix):
        raise RuntimeError("Captured command path is outside the payload root")
    return target[len(prefix):]

def run_launcher(command_name: str = "tfnf", argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if command_name != "tfnf":
        raise RuntimeError("Unknown successor command")
    if argv == ["--version"] or argv == ["-v"]:
        print(f"theme-forge-nebular-fusion {DISTRIBUTION_VERSION}")
        return 0
    if argv == ["--help"] or argv == ["-h"]:
        print("Usage: tfnf [--version|--help|--path] [application args...]")
        return 0
    _platform_check()
    payload = _PACKAGE_DIR / "payload" / ARCHIVE_FILENAME
    if payload.is_symlink() or not payload.is_file():
        raise RuntimeError("Embedded payload is unavailable")
    if hashlib.sha256(payload.read_bytes()).hexdigest() != EXPECTED_ARCHIVE_SHA256:
        raise RuntimeError("Embedded payload identity mismatch")
    manifest_path = _PACKAGE_DIR / "payload" / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    root = materialize_payload(payload, _cache_dir(), manifest, expected_manifest_sha256=EXPECTED_MANIFEST_SHA256)
    shell = resolve_launcher(root, _relative(root, SHELL_TARGET))
    gui = resolve_launcher(root, _relative(root, GUI_TARGET))
    if argv == ["--path"]:
        print(gui)
        return 0
    os.execv(str(shell), [str(shell), *argv])
    return 0

def main_tfnf() -> None:
    sys.exit(run_launcher("tfnf"))
'''
    replacements = {
        "__APP_VERSION__": repr(APPLICATION_VERSION),
        "__DIST_VERSION__": repr(DISTRIBUTION_VERSION),
        "__ARCHIVE_NAME__": repr(archive_name),
        "__ARCHIVE_SHA__": repr(archive_sha256),
        "__MANIFEST_SHA__": repr(manifest_sha256),
        "__SHELL_TARGET__": repr(shell_path),
        "__GUI_TARGET__": repr(gui_path),
        "__FAMILY__": repr(family),
        "__ARCH__": repr(arch),
    }
    for marker, value in replacements.items():
        source = source.replace(marker, value)
    return source.encode("utf-8")


def _successor_init_bytes() -> bytes:
    return (
        '"""Theme Forge Nebular Fusion Python successor package."""\n'
        f"__version__ = {DISTRIBUTION_VERSION!r}\n"
        f"__upstream_version__ = {APPLICATION_VERSION!r}\n"
        f"__product_id__ = {PRODUCT_ID!r}\n"
    ).encode()


def _successor_metadata_bytes(description: bytes) -> bytes:
    return (
        "Metadata-Version: 2.4\n"
        f"Name: {DISTRIBUTION_NAME}\n"
        f"Version: {DISTRIBUTION_VERSION}\n"
        "Summary: Theme Forge Nebular Fusion application distribution for Python 3\n"
        f"License-Expression: {LICENSE_EXPRESSION}\n"
        + "".join(f"License-File: {name}\n" for name in sorted(LEGAL_FILES))
        + "Requires-Python: >=3.10\n"
        "Description-Content-Type: text/markdown\n\n"
    ).encode("utf-8") + description


def _successor_wheel_info_bytes(wheel_tag: str) -> bytes:
    return (
        "Wheel-Version: 1.0\nGenerator: rs9-nebular-successor (1.0)\n"
        f"Root-Is-Purelib: false\nTag: {wheel_tag}\n"
    ).encode()


def _successor_entry_points_bytes() -> bytes:
    return f"[console_scripts]\ntfnf = {PACKAGE_NAME}.launcher:main_tfnf\n".encode()


def _base_entries(wheel_path: Path) -> tuple[dict[str, bytes], str]:
    with zipfile.ZipFile(wheel_path) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise _error("RECORD_MISMATCH", "Legacy candidate contains duplicate wheel members")
        dist_infos = sorted({name.split("/", 1)[0] for name in names if name.endswith(".dist-info/METADATA")})
        if len(dist_infos) != 1:
            raise _error("INVALID_WHEEL", "Legacy candidate must contain one dist-info directory")
        return {name: archive.read(name) for name in names}, dist_infos[0]


def _wheel_archive(entries: Mapping[str, bytes], modes: Mapping[str, int],
                   timestamp: tuple[int, int, int, int, int, int] | None = None) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in sorted(entries):
            info = zipfile.ZipInfo(name, date_time=timestamp or (2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = ((modes.get(name, 0o644) & 0o7777) | stat.S_IFREG) << 16
            archive.writestr(info, entries[name], compresslevel=9)
    return output.getvalue()


def build_successor_wheel(
    product_id: str,
    application_version: str = APPLICATION_VERSION,
    *,
    distribution_version: str = DISTRIBUTION_VERSION,
    capture: ReleaseCapture | None = None,
    archive_path: str | Path | None = None,
    archive_bytes: bytes | None = None,
    manifest: dict[str, Any] | None = None,
    output_dir: str | Path | None = None,
    output_path: str | Path | None = None,
    platform_tag: str | None = None,
    target_platform: str | None = None,
    system: str | None = None,
    license_files: Mapping[str, bytes] | None = None,
    description_path: str | Path = DEFAULT_DESCRIPTION_PATH,
    launcher_path: str | Path | None = None,
    gui_path: str | Path | None = None,
    profile_result: dict[str, Any] | None = None,
    rs9_source_commit: str | None = None,
    rs9_source_tree: str | None = None,
    lineage_proof: Any | None = None,
    lineage_intent: Mapping[str, Any] | None = None,
    fixture_only: bool = False,
    candidate_only: bool = False,
    deterministic_timestamp: tuple[int, int, int, int, int, int] | None = None,
) -> WheelBuildResult:
    """Build a non-admitted successor wheel from an authenticated or explicit fixture input."""
    if product_id != PRODUCT_ID:
        raise _error("UNSUPPORTED_PRODUCT", "Successor builder only supports Nebular Fusion")
    if application_version != APPLICATION_VERSION:
        raise _error("INVALID_VERSION", "Upstream application version is fixed to 0.6.1")
    if distribution_version != DISTRIBUTION_VERSION:
        raise _error("INVALID_VERSION", "Successor distribution version is fixed to 0.6.1.post1")
    if (output_dir is None) == (output_path is None):
        raise _error("DESTINATION_REQUIRED", "Exactly one wheel output destination is required")
    if fixture_only and capture is not None:
        raise _error("FIXTURE_AUTHORITY", "Fixture mode cannot accept an authenticated capture")
    if fixture_only and profile_result is not None:
        raise _error("FIXTURE_AUTHORITY", "Fixture mode cannot accept authenticated profile claims")
    if (lineage_proof is None) != (lineage_intent is None):
        raise _error("LINEAGE_REQUIRED", "Forward lineage proof and its bound intent must be supplied together")
    if fixture_only and (lineage_proof is not None or lineage_intent is not None):
        raise _error("FIXTURE_AUTHORITY", "Fixture mode cannot consume an authenticated forward lineage proof")
    if not fixture_only and (archive_path is not None or archive_bytes is not None):
        raise _error("PROVENANCE_REQUIRED", "Raw archives are fixture-only; authenticated capture is required")
    if not fixture_only and (launcher_path is not None or gui_path is not None):
        raise _error("COMMAND_OVERRIDE", "Authenticated command paths come only from the captured release")

    effective_system, target_triple, is_linux, family = _resolve_target(system, target_platform, platform_tag, candidate_only)
    release_hash, release_identity = _capture_identity(capture, fixture_only)
    forward_lineage = None
    if lineage_proof is not None:
        if capture is None or lineage_intent is None:
            raise _error("LINEAGE_REQUIRED", "Authenticated forward lineage inputs are incomplete")
        forward_lineage = verify_forward_lineage_proof(capture, lineage_proof, intent=lineage_intent)
    rs9_source = _rs9_source_binding(rs9_source_commit, rs9_source_tree, fixture_only)
    legal = _legal_files(capture, fixture_only, license_files)
    description_name, description = _description_bytes(description_path)
    archive_manifest, payload_bytes, payload_name, captured_shell, captured_gui, selected_asset_id = _archive_inputs(
        capture, fixture_only, effective_system, archive_path, archive_bytes, manifest
    )
    if archive_manifest is None or payload_bytes is None or payload_name is None:
        raise _error("MISSING_ASSET", "Archive and manifest inputs are unavailable")
    parse_manifest_members(archive_manifest)
    shell_path, actual_gui_path = _path_from_capture_or_fixture(
        archive_manifest, captured_shell, captured_gui, launcher_path, gui_path
    )
    payload_sha = digest(payload_bytes)
    manifest_sha = archive_manifest.get("manifest_sha256")
    if not isinstance(manifest_sha, str) or digest(canonical(archive_manifest.get("members", []))) != manifest_sha:
        raise _error("MANIFEST_IDENTITY", "Payload manifest digest is not self-consistent")

    with tempfile.TemporaryDirectory(prefix="rs9-nebular-successor-", dir=_repo_root()) as temp:
        old_dir = Path(temp) / "legacy"
        old_kwargs: dict[str, Any] = {
            "product_id": PRODUCT_ID,
            "version": APPLICATION_VERSION,
            "output_dir": old_dir,
            "platform_tag": platform_tag,
            "target_platform": target_triple,
            "system": effective_system,
            "manifest": archive_manifest,
            "license_files": {name: legal[name] for name in ("LICENSE", "NOTICE")},
            "candidate_only": candidate_only,
            "fixture_only": fixture_only,
        }
        if fixture_only:
            if archive_path is not None:
                old_kwargs["archive_path"] = archive_path
            else:
                old_kwargs["archive_bytes"] = payload_bytes
        else:
            old_kwargs.update({"capture": capture, "profile_result": profile_result})
        legacy = build_native_wheel(**old_kwargs)
        verify_wheel_record_bidirectional(legacy.wheel_path)
        base, _ = _base_entries(legacy.wheel_path)

    arch = "aarch64" if effective_system.startswith(("aarch64", "arm64")) else "x86_64"
    expected_tag = f"py3-none-linux_{arch}" if is_linux else None
    if is_linux:
        if legacy.tag != expected_tag:
            raise _error("PLATFORM_TAG", "Legacy Linux tag does not match the selected target architecture",
                         system=effective_system, observed_tag=legacy.tag, expected_tag=expected_tag)
    elif effective_system != "aarch64-darwin" or not re.fullmatch(r"py3-none-macosx_[0-9]+_[0-9]+_arm64", legacy.tag):
        raise _error("PLATFORM_TAG", "Legacy Darwin tag is outside the supported arm64 namespace",
                     system=effective_system, observed_tag=legacy.tag)

    package_prefix = PACKAGE_NAME + "/"
    payload_entries = {
        name: data for name, data in base.items()
        if name.startswith(package_prefix)
        and name not in {
            f"{PACKAGE_NAME}/__init__.py",
            f"{PACKAGE_NAME}/launcher.py",
            f"{PACKAGE_NAME}/_rs9/provenance.json",
        }
    }
    archive_member = f"{PACKAGE_NAME}/payload/{payload_name}"
    manifest_member = f"{PACKAGE_NAME}/payload/manifest.json"
    helpers = get_embedded_rs9_helpers()
    expected_payload_entries = {
        archive_member,
        manifest_member,
        *(f"{PACKAGE_NAME}/_isolated/{rel_name}" for rel_name in helpers),
    }
    if set(payload_entries) != expected_payload_entries:
        raise _error("PAYLOAD_LAYOUT", "Legacy candidate contains unexpected payload or isolated members",
                     expected=sorted(expected_payload_entries), observed=sorted(payload_entries))
    if payload_entries.get(archive_member) != payload_bytes:
        raise _error("PAYLOAD_IDENTITY", "Legacy candidate payload bytes differ from inspected archive bytes")
    if json.loads(payload_entries[manifest_member]) != archive_manifest:
        raise _error("MANIFEST_IDENTITY", "Legacy candidate manifest differs from selected manifest")
    for rel_name, helper_bytes in helpers.items():
        member = f"{PACKAGE_NAME}/_isolated/{rel_name}"
        if payload_entries.get(member) != helper_bytes:
            raise _error("HELPER_DRIFT", "Legacy candidate helper bytes changed")

    launcher_bytes = _render_successor_launcher(
        payload_name, payload_sha, manifest_sha, shell_path, actual_gui_path, family, arch
    )
    dist_name = DISTRIBUTION_NAME.replace("-", "_")
    dist_info = f"{dist_name}-{DISTRIBUTION_VERSION}.dist-info"
    wheel_tag = legacy.tag
    wheel_filename = f"{dist_name}-{DISTRIBUTION_VERSION}-{wheel_tag}.whl"
    init_bytes = _successor_init_bytes()
    metadata = _successor_metadata_bytes(description)
    wheel_info = _successor_wheel_info_bytes(wheel_tag)
    entry_points = _successor_entry_points_bytes()
    profile_result_sha256 = record_sha256(profile_result) if isinstance(profile_result, Mapping) else None
    license_facts = _profile_license_facts(profile_result)
    provenance = {
        "schema": SUCCESSOR_PROVENANCE_SCHEMA,
        "product_id": PRODUCT_ID,
        "distribution_name": DISTRIBUTION_NAME,
        "application_version": APPLICATION_VERSION,
        "distribution_version": DISTRIBUTION_VERSION,
        "source_identity": release_identity,
        "forward_lineage": forward_lineage,
        "rs9_source": rs9_source,
        "release_record_sha256": release_hash,
        "wheel_tag": wheel_tag,
        "target_system": effective_system,
        "target_triple": target_triple,
        "payload_archive_name": payload_name,
        "payload_archive_sha256": payload_sha,
        "manifest_sha256": manifest_sha,
        "selected_asset_id": selected_asset_id,
        "profile_result_sha256": profile_result_sha256,
        "license_facts": license_facts,
        "launcher_path": shell_path,
        "gui_path": actual_gui_path,
        "license_expression": LICENSE_EXPRESSION,
        "legal_files": {
            name: {"path": name, "size": len(data), "sha256": digest(data)}
            for name, data in legal.items()
        },
        "readme_path": description_name,
        "readme_sha256": digest(description),
        "readme_authority": {
            "source": "rs9-candidate-input",
            "path": description_name,
            "sha256": digest(description),
            "rs9_source": rs9_source,
            "verified": False,
        },
        "launcher_sha256": digest(launcher_bytes),
        "metadata_sha256": digest(metadata),
        "helper_source_sha256": {name: digest(data) for name, data in helpers.items()},
        "legacy_candidate": {"version": APPLICATION_VERSION, "filename": legacy.filename, "sha256": legacy.sha256},
        "fixture_only": fixture_only,
        "candidate_only": candidate_only,
        "candidate_status": "policy-pending" if is_linux else "candidate",
        "promotability": "policy-pending" if is_linux else "candidate",
        "manylinux_proven": False,
        "source_closure": {"status": "pending", "receipt_sha256": None, "admitted": False},
        "policy": {"status": "pending", "receipt_sha256": None, "manylinux_proven": False},
        "builder_can_publish": False,
        "can_publish": False,
        "publication_admitted": False,
    }
    entries: dict[str, bytes] = dict(payload_entries)
    entries.update({
        f"{PACKAGE_NAME}/__init__.py": init_bytes,
        f"{PACKAGE_NAME}/launcher.py": launcher_bytes,
        f"{PACKAGE_NAME}/_rs9/provenance.json": canonical(provenance),
        f"{dist_info}/METADATA": metadata,
        f"{dist_info}/WHEEL": wheel_info,
        f"{dist_info}/entry_points.txt": entry_points,
    })
    for name, data in legal.items():
        entries[f"{dist_info}/licenses/{name}"] = data
    entries[f"{dist_info}/RECORD"] = format_record(entries, dist_info)
    modes = {name: 0o644 for name in entries}
    modes[f"{PACKAGE_NAME}/launcher.py"] = 0o644
    wheel_bytes = _wheel_archive(entries, modes, deterministic_timestamp)
    destination = Path(output_path) if output_path is not None else Path(output_dir) / wheel_filename  # type: ignore[arg-type]
    _write_exclusive(destination, wheel_bytes)
    verify_wheel_record_bidirectional(destination)
    manifest_rows = [
        {"path": name, "size": len(entries[name]), "sha256": digest(entries[name]), "mode": modes[name]}
        for name in sorted(entries)
    ]
    return WheelBuildResult(
        wheel_path=destination.absolute(), filename=wheel_filename, distribution=DISTRIBUTION_NAME,
        version=DISTRIBUTION_VERSION, tag=wheel_tag, sha256=digest(wheel_bytes), size=len(wheel_bytes),
        release_hash=release_hash or "", record=provenance, manifest=manifest_rows,
        wheel_bytes=wheel_bytes, can_publish=False,
    )
