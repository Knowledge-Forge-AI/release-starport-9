"""Native Nebular Darwin compressed-archive wheel builder with isolated materialize runtime."""
from __future__ import annotations

import base64
import gzip
import io
import json
import os
from pathlib import Path
import plistlib
import posixpath
import re
import stat
import sys
import tarfile
from typing import Any, Mapping
import tempfile
import zipfile

from rs9.archives import inspect_archive
from rs9.errors import ContractError
from rs9.release_core import ReleaseCapture, authenticate_release, authenticated_record_hash, digest
from rs9.scratch import canonical
from rs9.records import record_sha256
from rs9.security import scan_for_credentials, validate_safe_relative_posix_path
from rs9.wheel import (
    NEBULAR_TAG_RE,
    WheelBuildResult,
    WheelWithheldError,
    canonical_product_id,
    format_record,
)

PRODUCT_ID = "theme-forge-nebular-fusion"
DISTRIBUTION_NAME = "theme-forge-nebular-fusion"
PACKAGE_NAME = "theme_forge_nebular_fusion"
VERSION = "0.6.1"
REVIEWED_HELPERS = ("materialize.py", "archives.py", "errors.py", "scratch.py", "security.py")


def extract_darwin_minimum_version(plist_bytes: bytes) -> tuple[int, int]:
    """Parse Info.plist and enforce Darwin arm64 minimum version >= 11.0."""
    try:
        data = plistlib.loads(plist_bytes)
    except Exception as exc:
        raise ContractError("INVALID_PLIST", "Failed to parse Darwin Info.plist bytes") from exc

    if not isinstance(data, dict):
        raise ContractError("INVALID_PLIST", "Info.plist root must be a dictionary")

    version_str = data.get("LSMinimumSystemVersion") or data.get("MinimumOSVersion")
    if not version_str or not isinstance(version_str, str):
        raise ContractError("INVALID_PLIST", "Info.plist missing required LSMinimumSystemVersion string")

    match = re.fullmatch(r"(\d+)(?:\.(\d+))?(?:\.\d+)?", version_str)
    if not match:
        raise ContractError("INVALID_PLIST", f"Unrecognized version format in Info.plist: {version_str!r}")

    major = int(match.group(1))
    minor = int(match.group(2) or 0)
    return max((11, 0), (major, minor))


def resolve_native_darwin_tag(plist_bytes: bytes, platform_tag: str | None = None) -> str:
    """Resolve and validate truthful Darwin wheel platform tag.

    Linux wheel tags must NOT claim manylinux compliance with external GTK/WebKit
    dependencies: withhold with explicit blocker until truthful PyPI-accepted policy proven,
    no fake universal.
    """
    if platform_tag == "any":
        raise ContractError("UNSUPPORTED_PLATFORM", "Native wheels cannot use fake universal 'any' tag")

    if platform_tag and ("linux" in platform_tag or "manylinux" in platform_tag or "musllinux" in platform_tag):
        raise WheelWithheldError(
            "MANYLINUX_UNPROVEN",
            "Linux wheel tags must NOT claim manylinux compliance with external GTK/WebKit dependencies: "
            "withhold with explicit blocker until truthful PyPI-accepted policy proven, no fake universal",
            product_id=PRODUCT_ID,
            reason="manylinux_unproven",
        )

    plist_major, plist_minor = extract_darwin_minimum_version(plist_bytes)

    if platform_tag:
        if not NEBULAR_TAG_RE.fullmatch(platform_tag):
            raise ContractError(
                "UNSUPPORTED_PLATFORM",
                f"Nebular platform tag must match macosx_[digits]_[digits]_arm64, got {platform_tag!r}",
            )
        m = re.match(r"^macosx_(\d+)_(\d+)_arm64$", platform_tag)
        req_major = int(m.group(1)) if m else 0
        if req_major < 11:
            raise ContractError("UNSUPPORTED_PLATFORM", f"Darwin minimum arm64 >= 11.0 required, got {platform_tag!r}")
        req_minor = int(m.group(2)) if m else 0
        if (req_major, req_minor) < (plist_major, plist_minor):
            raise ContractError(
                "UNSUPPORTED_PLATFORM",
                f"Requested tag {platform_tag!r} specifies macOS < Info.plist minimum ({plist_major}.{plist_minor})",
            )
        return f"py3-none-{platform_tag}"

    return f"py3-none-macosx_{plist_major}_{plist_minor}_arm64"


def resolve_native_linux_candidate_tag(target_platform: str | None = None, platform_tag: str | None = None) -> str:
    """Resolve honest Linux candidate platform tag (linux_x86_64 or linux_aarch64).

    Manylinux compliance claims remain strictly refused until genuinely proven by auditwheel.
    """
    if platform_tag == "any":
        raise ContractError("UNSUPPORTED_PLATFORM", "Native wheels cannot use fake universal 'any' tag")
    if platform_tag and ("manylinux" in platform_tag or "musllinux" in platform_tag):
        raise WheelWithheldError(
            "MANYLINUX_UNPROVEN",
            "Linux wheel tags must NOT claim manylinux compliance with external GTK/WebKit dependencies: "
            "withhold with explicit blocker until truthful PyPI-accepted policy proven, no fake universal",
            product_id=PRODUCT_ID,
            reason="manylinux_unproven",
        )
    if platform_tag in ("linux_x86_64", "linux_aarch64"):
        return f"py3-none-{platform_tag}"
    plat = (target_platform or "").lower()
    if "aarch64" in plat or "arm64" in plat:
        return "py3-none-linux_aarch64"
    return "py3-none-linux_x86_64"


def get_embedded_rs9_helpers() -> dict[str, bytes]:
    """Retrieve unchanged materialize.py and reviewed rs9 helper source bytes."""
    rs9_dir = Path(__file__).resolve().parent
    embedded: dict[str, bytes] = {
        "rs9/__init__.py": b'"""Isolated reviewed rs9 helper namespace."""\n',
    }
    for mod_name in REVIEWED_HELPERS:
        mod_path = rs9_dir / mod_name
        if not mod_path.is_file():
            raise ContractError("MISSING_HELPER", f"Reviewed helper module not found: {mod_path}")
        embedded[f"rs9/{mod_name}"] = mod_path.read_bytes()
    return embedded


def render_native_launcher(
    archive_filename: str,
    manifest_sha256: str,
    archive_sha256: str,
    launcher: str,
    platform_family: str = "darwin",
    target_arch: str = "arm64",
) -> str:
    """Render stdlib launcher embedding unchanged materialize.py runtime."""
    if platform_family == "linux":
        arch_norm = "aarch64" if target_arch in ("aarch64", "arm64") else "x86_64"
        arch_check = f'platform.machine() in ({arch_norm!r}, "arm64" if {arch_norm!r} == "aarch64" else "amd64")'
        platform_check = f'''    if not sys.platform.startswith("linux") or not ({arch_check}):
        sys.stderr.write("Error: Theme Forge Nebular Fusion candidate wheel requires Linux ({arch_norm}).\\n")
        sys.exit(1)'''
        cache_fn = '''def _get_cache_dir() -> Path:
    if "THEME_FORGE_CACHE_DIR" in os.environ:
        return Path(os.environ["THEME_FORGE_CACHE_DIR"]).absolute()
    if "XDG_CACHE_HOME" in os.environ:
        return (Path(os.environ["XDG_CACHE_HOME"]) / "rs9" / "theme-forge-nebular-fusion").absolute()
    return (Path.home() / ".cache" / "rs9" / "theme-forge-nebular-fusion").absolute()'''
    else:
        platform_check = '''    if sys.platform != "darwin" or platform.machine() not in ("arm64", "aarch64"):
        sys.stderr.write("Error: Theme Forge Nebular Fusion native wheel requires macOS (Darwin arm64).\\n")
        sys.exit(1)'''
        cache_fn = '''def _get_cache_dir() -> Path:
    if "THEME_FORGE_CACHE_DIR" in os.environ:
        return Path(os.environ["THEME_FORGE_CACHE_DIR"]).absolute()
    if "XDG_CACHE_HOME" in os.environ:
        return (Path(os.environ["XDG_CACHE_HOME"]) / "rs9" / "theme-forge-nebular-fusion").absolute()
    return (Path.home() / "Library" / "Caches" / "rs9" / "theme-forge-nebular-fusion").absolute()'''

    return f'''"""Theme Forge Nebular Fusion native wheel launcher. Isolated materialize runtime. No network access."""
from __future__ import annotations
import hashlib, json, os, platform, sys
from pathlib import Path

_PKG_DIR = Path(__file__).resolve().parent
_ISOLATED = _PKG_DIR / "_isolated"
if str(_ISOLATED) not in sys.path:
    sys.path.insert(0, str(_ISOLATED))
if "rs9" in sys.modules and Path(sys.modules["rs9"].__file__).parent != _ISOLATED / "rs9":
    raise RuntimeError("Conflicting materializer namespace")

from rs9.materialize import materialize_payload, resolve_launcher

ARCHIVE_FILENAME: str = {archive_filename!r}
EXPECTED_MANIFEST_SHA256: str = {manifest_sha256!r}
EXPECTED_ARCHIVE_SHA256: str = {archive_sha256!r}
LAUNCHER_TARGETS: dict[str, str] = {{"tfnf": {launcher!r}}}

{cache_fn}

def run_launcher(command_name: str, argv: list[str] | None = None) -> int:
{platform_check}
    argv = sys.argv[1:] if argv is None else argv
    payload_dir = _PKG_DIR / "payload"
    archive_path = payload_dir / ARCHIVE_FILENAME
    if archive_path.is_symlink() or hashlib.sha256(archive_path.read_bytes()).hexdigest() != EXPECTED_ARCHIVE_SHA256:
        raise RuntimeError("Embedded released archive identity mismatch")
    manifest_path = payload_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes()) if manifest_path.exists() else None
    cache_dir = _get_cache_dir()

    root = materialize_payload(
        source=archive_path,
        cache_root=cache_dir,
        manifest=manifest,
        expected_manifest_sha256=EXPECTED_MANIFEST_SHA256,
    )

    root_name = root.name
    launcher_path = LAUNCHER_TARGETS.get(command_name)

    def _rel(target: str | None) -> str | None:
        if not target: return None
        return target[len(root_name) + 1:] if target.startswith(root_name + "/") else target

    target_rel = _rel(launcher_path)
    exe = resolve_launcher(root, target_rel)
    os.execv(str(exe), [str(exe), *argv])

def main_tfnf() -> None:
    sys.exit(run_launcher("tfnf"))
'''



def build_native_wheel(
    product_id: str,
    version: str,
    capture: ReleaseCapture | None = None,
    *,
    selection: dict[str, Any] | None = None,
    evidence_dir: str | Path | None = None,
    archive_path: str | Path | None = None,
    archive_bytes: bytes | None = None,
    manifest: dict[str, Any] | None = None,
    output_dir: str | Path | None = None,
    output_path: str | Path | None = None,
    platform_tag: str | None = None,
    target_platform: str = "aarch64-apple-darwin",
    license_files: Mapping[str, bytes] | None = None,
    summary: str | None = None,
    deterministic_timestamp: tuple[int, int, int, int, int, int] | None = None,
    profile_result: dict[str, Any] | None = None,
    fixture_only: bool = False,
    candidate_only: bool = False,
) -> WheelBuildResult:
    """Build a deterministic native Nebular Darwin or Linux candidate compressed-archive wheel.

    Embeds unchanged materialize.py and reviewed rs9 helpers under an isolated package namespace.
    Preserves exact mode/type/symlink/manifest fail-closed semantics and actual compressed released payload.
    Withholds Linux production wheels claiming manylinux compliance with external GTK/WebKit dependencies.
    """
    if output_path is None and output_dir is None:
        raise ContractError("DESTINATION_REQUIRED", "Caller output destination (output_path or output_dir) is required")

    canonical_id = canonical_product_id(product_id)
    if canonical_id != PRODUCT_ID:
        raise ContractError("UNSUPPORTED_PRODUCT", f"Native builder only supports {PRODUCT_ID}, got {product_id}")
    if version != VERSION:
        raise ContractError("INVALID_VERSION", f"Version {version} differs from bound product version {VERSION}")

    is_linux_target = "linux" in target_platform or (platform_tag is not None and "linux" in platform_tag)
    if is_linux_target:
        if not candidate_only:
            raise WheelWithheldError(
                "MANYLINUX_UNPROVEN",
                "Linux wheel tags must NOT claim manylinux compliance with external GTK/WebKit dependencies: "
                "withhold with explicit blocker until truthful PyPI-accepted policy proven, no fake universal",
                product_id=PRODUCT_ID,
                reason="manylinux_unproven",
            )
        if platform_tag and ("manylinux" in platform_tag or "musllinux" in platform_tag):
            raise WheelWithheldError(
                "MANYLINUX_UNPROVEN",
                "Linux wheel tags must NOT claim manylinux compliance with external GTK/WebKit dependencies: "
                "withhold with explicit blocker until truthful PyPI-accepted policy proven, no fake universal",
                product_id=PRODUCT_ID,
                reason="manylinux_unproven",
            )

    if platform_tag == "any":
        raise ContractError("UNSUPPORTED_PLATFORM", "Native wheels cannot use fake universal 'any' tag")

    target_arch = "aarch64" if ("aarch64" in target_platform or "arm64" in target_platform or (platform_tag and "aarch64" in platform_tag)) else "x86_64"

    # Destination safety checks
    dest_path_check = Path(output_path) if output_path else Path(output_dir)  # type: ignore
    for p in (dest_path_check.absolute(), *dest_path_check.absolute().parents):
        if p.is_symlink():
            raise ContractError("UNSAFE_DESTINATION", "Destination or ancestry contains a symlink")

    # 1. Acquire authenticated release bytes and record
    release_hash: str
    if capture is not None:
        release_hash = authenticated_record_hash(capture)
    elif selection is not None and evidence_dir is not None:
        capture = authenticate_release(selection, evidence_dir)
        release_hash = authenticated_record_hash(capture)
    elif fixture_only and (archive_bytes is not None or archive_path is not None):
        release_hash = digest(archive_bytes if archive_bytes is not None else Path(archive_path).read_bytes())  # type: ignore
    else:
        raise ContractError(
            "PROVENANCE_REQUIRED",
            "Authenticated release capture is required; raw archive inputs are fixture-only",
        )
    if capture is not None and not fixture_only:
        if (profile_result is None or record_sha256(profile_result) not in capture._profile_results
                or profile_result.get("release_record_sha256") != release_hash):
            raise ContractError("PROFILE_BINDING", "Fresh evaluated release profile required")
        licence = profile_result["sections"].get("license", profile_result["sections"].get("legacy_ingestion", {}).get("license"))
        if not licence or licence.get("status") != "consistent":
            raise ContractError("LICENSE_AUTHORITY", "Consistent release license facts required")
    if capture is not None and (capture.record["repository"]["full_name"] != "Knowledge-Forge-AI/" + PRODUCT_ID or capture.record["release"]["tag"] != "v" + VERSION):
        raise ContractError("REPOSITORY_MISMATCH", "Native wheel requires the exact selected product generation")

    # 2. Acquire compressed archive bytes and archive filename
    payload_archive_name: str
    payload_archive_bytes: bytes
    if capture is not None:
        if is_linux_target:
            matched_asset = next(
                (
                    a for a in capture.record.get("payloads", [])
                    if any(p in a.get("platforms", []) for p in (target_platform, f"{target_arch}-linux", f"{target_arch}-unknown-linux-gnu"))
                    or (target_arch in a.get("name", "") and "linux" in a.get("name", ""))
                ),
                None,
            )
            if not matched_asset:
                raise ContractError("MISSING_ASSET", f"No Linux {target_arch} payload asset found in release capture")
            asset_id = matched_asset["id"]
            archive_file = capture.archives[asset_id]
            payload_archive_name = matched_asset["name"]
            payload_archive_bytes = archive_file.read_bytes()
            if len(payload_archive_bytes) != matched_asset["size"] or digest(payload_archive_bytes) != matched_asset["sha256"]:
                raise ContractError("INPUT_CHANGED", "Released native archive changed")
            archive_manifest = manifest or capture.manifests[asset_id]
            if archive_manifest["manifest_sha256"] != matched_asset["payload_manifest_sha256"]:
                raise ContractError("INPUT_CHANGED", "Native manifest differs from captured release")
            if digest(canonical(archive_manifest)) != digest(canonical(capture.manifests[asset_id])):
                raise ContractError("INPUT_CHANGED", "Native manifest override differs")
        else:
            darwin_asset = next(
                (
                    a for a in capture.record.get("payloads", [])
                    if "aarch64-darwin" in a.get("platforms", [])
                ),
                None,
            )
            if not darwin_asset:
                raise ContractError("MISSING_ASSET", "No Darwin arm64 payload asset found in release capture")
            asset_id = darwin_asset["id"]
            archive_file = capture.archives[asset_id]
            payload_archive_name = darwin_asset["name"]
            payload_archive_bytes = archive_file.read_bytes()
            if len(payload_archive_bytes) != darwin_asset["size"] or digest(payload_archive_bytes) != darwin_asset["sha256"]:
                raise ContractError("INPUT_CHANGED", "Released native archive changed")
            archive_manifest = manifest or capture.manifests[asset_id]
            if archive_manifest["manifest_sha256"] != darwin_asset["payload_manifest_sha256"]:
                raise ContractError("INPUT_CHANGED", "Native manifest differs from captured release")
            if digest(canonical(archive_manifest)) != digest(canonical(capture.manifests[asset_id])):
                raise ContractError("INPUT_CHANGED", "Native manifest override differs")
    elif archive_path is not None:
        p_path = Path(archive_path).resolve()
        payload_archive_name = p_path.name
        payload_archive_bytes = p_path.read_bytes()
        archive_manifest = manifest or inspect_archive(p_path, commands={})
    elif archive_bytes is not None:
        if is_linux_target:
            payload_archive_name = f"theme-forge-nebular-fusion-v{version}-{target_arch}-unknown-linux-gnu.tar.gz"
        else:
            payload_archive_name = f"theme-forge-nebular-fusion-v{version}-aarch64-apple-darwin.app.tar.gz"
        payload_archive_bytes = archive_bytes
        if manifest is not None:
            archive_manifest = manifest
        else:
            with tempfile.TemporaryDirectory() as td:
                temp_file = Path(td).resolve() / "temp.tar.gz"
                temp_file.write_bytes(payload_archive_bytes)
                archive_manifest = inspect_archive(temp_file, commands={})
    else:
        raise ContractError("MISSING_ASSET", "No archive input available")

    # Validate archive layout and fail-closed properties
    manifest_members = archive_manifest["members"]
    manifest_sha256 = archive_manifest["manifest_sha256"]
    from rs9.materialize import parse_manifest_members
    parse_manifest_members(archive_manifest)

    # 3. Resolve truthful wheel tag
    if is_linux_target:
        wheel_tag = resolve_native_linux_candidate_tag(target_platform, platform_tag)
    else:
        plist_bytes: bytes | None = None
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(payload_archive_bytes)) as gz, tarfile.open(fileobj=gz, mode="r|") as tf:
                for member in tf:
                    if member.name.endswith("/Contents/Info.plist") or member.name == "Contents/Info.plist":
                        extracted = tf.extractfile(member)
                        if extracted is not None:
                            plist_bytes = extracted.read()
                        break
        except Exception as exc:
            raise ContractError("INVALID_ARCHIVE", "Failed reading Darwin archive members") from exc

        if plist_bytes is None:
            raise ContractError("INVALID_PLIST", "Missing Contents/Info.plist in Darwin application bundle")

        wheel_tag = resolve_native_darwin_tag(plist_bytes, platform_tag)

    # 5. Licenses
    licenses_dict = dict(license_files or {})
    for name, data in licenses_dict.items():
        validate_safe_relative_posix_path(name)
        if not isinstance(data, bytes) or (capture is not None and capture.source.get(name) != data):
            raise ContractError("LICENSE_AUTHORITY", "Legal files must equal authenticated tagged bytes")
    if capture is not None:
        if "LICENSE" not in licenses_dict and "LICENSE" in capture.source:
            licenses_dict["LICENSE"] = capture.source["LICENSE"]
        if "NOTICE" not in licenses_dict and "NOTICE" in capture.source:
            licenses_dict["NOTICE"] = capture.source["NOTICE"]
    if "LICENSE" not in licenses_dict:
        # Check archive for license
        with gzip.GzipFile(fileobj=io.BytesIO(payload_archive_bytes)) as gz, tarfile.open(fileobj=gz, mode="r|") as tf:
            for member in tf:
                bname = posixpath.basename(member.name)
                if bname in ("LICENSE", "NOTICE") and bname not in licenses_dict:
                    ef = tf.extractfile(member)
                    if ef is not None:
                        licenses_dict[bname] = ef.read()

    if "LICENSE" not in licenses_dict:
        raise ContractError("MISSING_LICENSE", "Authoritative LICENSE bytes required")

    dist_norm = DISTRIBUTION_NAME.replace("-", "_")
    ver_norm = version.replace("-", "_")
    wheel_filename = f"{dist_norm}-{ver_norm}-{wheel_tag}.whl"
    dist_info_dir = f"{dist_norm}-{ver_norm}.dist-info"

    # 6. Embedded unchanged materialize.py and rs9 helpers under isolated namespace
    embedded_helpers = get_embedded_rs9_helpers()

    # 7. Render launcher
    if is_linux_target:
        launcher = (matched_asset["launchers"].get("tfnf", {}).get("path") if capture is not None
                    else "theme-forge-nebular-fusion/bin/tfnf")
    else:
        launcher = (darwin_asset["launchers"].get("tfnf", {}).get("path") if capture is not None
                    else "Theme Forge Nebular Fusion.app/Contents/Resources/bin/tfnf")
    if not launcher:
        raise ContractError("MISSING_LAUNCHER", "Released launcher identity required")
    validate_safe_relative_posix_path(launcher)
    launcher_code = render_native_launcher(
        payload_archive_name,
        manifest_sha256,
        digest(payload_archive_bytes),
        launcher,
        platform_family="linux" if is_linux_target else "darwin",
        target_arch=target_arch,
    ).encode("utf-8")
    init_code = f'"""Theme Forge Nebular Fusion native release package."""\n__version__ = {version!r}\n__product_id__ = {canonical_id!r}\n'.encode("utf-8")

    # Provenance
    provenance_data: dict[str, Any] = {
        "schema": "rs9.wheel-provenance.v1alpha1",
        "product_id": canonical_id,
        "distribution_name": DISTRIBUTION_NAME,
        "version": version,
        "wheel_tag": wheel_tag,
        "release_record_sha256": release_hash if capture is not None else None,
        "fixture_only": fixture_only,
        "candidate_only": candidate_only,
        "candidate_status": "policy-pending" if is_linux_target else "candidate",
        "promotability": "policy-pending" if is_linux_target else "candidate",
        "manylinux_proven": False,
        "helper_source_sha256": {name: digest(data) for name, data in embedded_helpers.items()},
        "payload_archive_sha256": digest(payload_archive_bytes),
        "manifest_sha256": manifest_sha256,
        "can_publish": False,
    }
    if capture is not None and getattr(capture, "record", None) is not None:
        provenance_data["release_record"] = capture.record

    # Metadata & dist-info
    summary_text = summary or (f"Theme Forge Nebular Fusion candidate Linux {target_arch} application wheel" if is_linux_target else "Theme Forge Nebular Fusion native Darwin application wheel")
    if any(ord(c) < 32 or ord(c) == 127 for c in summary_text):
        raise ContractError("METADATA_CONTENT", "Wheel summary contains unsafe header content")

    desc = (
        f"Theme Forge Nebular Fusion candidate wheel for Linux {target_arch} ({version}).\n\n"
        "Encapsulates exact compressed release payload with isolated, safe offline runtime materialization.\n"
        "Promotability: policy-pending; Manylinux compliance: unproven."
        if is_linux_target else
        f"Theme Forge Nebular Fusion native wheel for macOS arm64 ({version}).\n\n"
        "Encapsulates exact compressed release payload with isolated, safe offline runtime materialization."
    )
    meta_lines = [
        "Metadata-Version: 2.4",
        f"Name: {DISTRIBUTION_NAME}",
        f"Version: {version}",
        f"Summary: {summary_text}",
        "License-Expression: AGPL-3.0-or-later",
    ] + [f"License-File: {k}" for k in sorted(licenses_dict.keys())] + [
        "Requires-Python: >=3.9",
        "Description-Content-Type: text/plain",
        "",
        desc,
    ]

    wheel_info = f"Wheel-Version: 1.0\nGenerator: rs9-wheel (1.0)\nRoot-Is-Purelib: false\nTag: {wheel_tag}\n".encode("utf-8")
    entry_points = f"[console_scripts]\ntfnf = {PACKAGE_NAME}.launcher:main_tfnf\n".encode("utf-8")

    # Assemble entries
    archive_entries: dict[str, bytes] = {
        f"{PACKAGE_NAME}/__init__.py": init_code,
        f"{PACKAGE_NAME}/launcher.py": launcher_code,
        f"{PACKAGE_NAME}/payload/{payload_archive_name}": payload_archive_bytes,
        f"{PACKAGE_NAME}/payload/manifest.json": canonical(archive_manifest),
        f"{PACKAGE_NAME}/_rs9/provenance.json": canonical(provenance_data),
        f"{dist_info_dir}/METADATA": "\n".join(meta_lines).encode("utf-8"),
        f"{dist_info_dir}/WHEEL": wheel_info,
        f"{dist_info_dir}/entry_points.txt": entry_points,
    }
    entry_modes: dict[str, int] = {k: 0o644 for k in archive_entries}

    # Add embedded isolated helpers
    for rel_hpath, hbytes in sorted(embedded_helpers.items()):
        arc_k = f"{PACKAGE_NAME}/_isolated/{rel_hpath}"
        archive_entries[arc_k] = hbytes
        entry_modes[arc_k] = 0o644

    # Add licenses
    for lic_name, lic_bytes in sorted(licenses_dict.items()):
        lic_k = f"{dist_info_dir}/licenses/{lic_name}"
        archive_entries[lic_k] = lic_bytes
        entry_modes[lic_k] = 0o644

    # Add RECORD
    archive_entries[f"{dist_info_dir}/RECORD"] = format_record(archive_entries, dist_info_dir)
    entry_modes[f"{dist_info_dir}/RECORD"] = 0o644

    # 8. Create deterministic zip
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        for arc_path in sorted(archive_entries.keys()):
            zinfo = zipfile.ZipInfo(
                filename=arc_path,
                date_time=deterministic_timestamp or (2026, 1, 1, 0, 0, 0),
            )
            zinfo.compress_type = zipfile.ZIP_DEFLATED
            zinfo.create_system = 3
            zinfo.external_attr = ((entry_modes.get(arc_path, 0o644) & 0o7777) | stat.S_IFREG) << 16
            zf.writestr(zinfo, archive_entries[arc_path], compresslevel=9)
    wheel_bytes = zip_buf.getvalue()

    # 9. Exclusive write to output destination
    dest_target = Path(output_path) if output_path else Path(output_dir) / wheel_filename  # type: ignore
    final_path = dest_target.absolute()
    for p in (final_path, *final_path.parents):
        if p.is_symlink():
            raise ContractError("UNSAFE_DESTINATION", "Destination ancestry contains a forbidden symlink")

    final_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(str(final_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o644)
        with open(fd, "wb") as f:
            f.write(wheel_bytes)
    except FileExistsError:
        raise ContractError("DESTINATION_EXISTS", f"Wheel destination already exists: {final_path}")
    except OSError as exc:
        raise ContractError("UNSAFE_DESTINATION", f"Failed to write wheel safely: {exc}") from None

    manifest_list = [
        {"path": p, "size": len(archive_entries[p]), "sha256": digest(archive_entries[p]), "mode": entry_modes.get(p, 0o644)}
        for p in sorted(archive_entries.keys())
    ]

    return WheelBuildResult(
        wheel_path=final_path,
        filename=wheel_filename,
        distribution=DISTRIBUTION_NAME,
        version=version,
        tag=wheel_tag,
        sha256=digest(wheel_bytes),
        size=len(wheel_bytes),
        release_hash=release_hash,
        record=provenance_data,
        manifest=manifest_list,
        wheel_bytes=wheel_bytes,
        can_publish=False,
    )


build_nebular_wheel = build_native_wheel
