"""Deterministic stdlib-only wheel builder for authenticated Theme Forge payloads."""
from __future__ import annotations

import base64, csv, hashlib, io, json, os, posixpath, re, stat, subprocess, sys, zipfile
from pathlib import Path
from typing import Any, Mapping

from rs9.errors import ContractError
from rs9.release_core import digest
from rs9.scratch import canonical
from rs9.security import scan_for_credentials, validate_safe_relative_posix_path

VERSION_RE = re.compile(r"^[0-9]+(\.[0-9]+)*([a-zA-Z0-9_.-]*)$")
NEBULAR_TAG_RE = re.compile(r"^macosx_[0-9]+_[0-9]+_arm64$")
BURST_TAG_RE = re.compile(
    r"^(macosx_[0-9]+_[0-9]+_(arm64|x86_64)|manylinux_[0-9]+_[0-9]+_(x86_64|aarch64)|manylinux[0-9]+_(x86_64|aarch64)|musllinux_[0-9]+_[0-9]+_(x86_64|aarch64))$"
)
SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")

THEME_FORGE_PRODUCTS: dict[str, dict[str, Any]] = {
    "theme-forge-stellar-burst": {
        "package_name": "theme_forge_stellar_burst", "distribution_name": "theme-forge-stellar-burst", "version": "0.6.1",
        "console_scripts": {"tfsb": "main_tfsb", "tfsb-studio-service": "main_tfsb_studio_service"},
        "default_commands": {"tfsb": "package/dist/cli.js", "tfsb-studio-service": "package/dist/service-protocol/server-cli.js"},
        "runtime": "node",
    },
    "theme-forge-stellar-loom": {
        "package_name": "theme_forge_stellar_loom", "distribution_name": "theme-forge-stellar-loom", "version": "0.4.0",
        "console_scripts": {"tfsl": "main_tfsl", "tfsl-batch": "main_tfsl_batch"},
        "default_commands": {"tfsl": "package/bin/tfsl.js", "tfsl-batch": "package/bin/tfsl-batch.js"},
        "runtime": "node",
    },
    "theme-forge-solar-sail": {
        "package_name": "theme_forge_solar_sail", "distribution_name": "theme-forge-solar-sail", "version": "0.2.1",
        "console_scripts": {"tfss": "main_tfss"},
        "default_commands": {"tfss": "package/bin/tfss.js"},
        "runtime": "node",
    },
    "theme-forge-nebular-fusion": {
        "package_name": "theme_forge_nebular_fusion", "distribution_name": "theme-forge-nebular-fusion", "version": "0.6.1",
        "console_scripts": {"tfnf": "main_tfnf"},
        "default_commands": {"tfnf": "Theme Forge Nebular Fusion.app/Contents/MacOS/theme-forge-nebular-fusion"},
        "runtime": "native",
    },
}


class WheelWithheldError(ContractError):
    """Raised when a wheel artifact is withheld because safety/runtime conditions are unverified."""

    def __init__(self, code: str, message: str, *, product_id: str = "", reason: str = "") -> None:
        super().__init__(code, message)
        self.product_id, self.reason = product_id, reason


def canonical_product_id(product_id: str) -> str:
    """Validate canonical product ID."""
    pid = product_id.strip()
    if pid not in THEME_FORGE_PRODUCTS:
        raise ContractError("UNKNOWN_PRODUCT", 'Invalid candidate input or unavailable candidate operation')
    return pid


def resolve_wheel_tag(product_id: str, *, platform_tag: str | None = None, js_fallback: bool = False,
                      evidence: Any = None, mode_restoration_verified: bool = False) -> str:
    """Resolve and validate the truthful wheel platform tag for a product."""
    canonical_id = canonical_product_id(product_id)
    if canonical_id == "theme-forge-nebular-fusion":
        if not platform_tag or not NEBULAR_TAG_RE.fullmatch(platform_tag):
            raise ContractError("UNSUPPORTED_PLATFORM", "Nebular platform tag required matching macosx_[digits]_[digits]_arm64")
        raise WheelWithheldError("NATIVE_WHEEL_WITHHELD", "Native Theme Forge Nebular Fusion wheel withheld entirely",
                                 product_id=canonical_id, reason="native_withheld")
    if canonical_id == "theme-forge-stellar-burst":
        if evidence is _OFFLINE_JS_PROOF and platform_tag in (None, "any"):
            return "py3-none-any"
        if platform_tag and platform_tag != "any":
            if not BURST_TAG_RE.fullmatch(platform_tag):
                raise ContractError("UNSUPPORTED_PLATFORM", 'Invalid candidate input or unavailable candidate operation')
            return f"py3-none-{platform_tag}"
        if js_fallback:
            raise ContractError("UNQUALIFIED_PLATFORM", "A JavaScript fallback has not been independently proven")
        raise ContractError("UNQUALIFIED_PLATFORM", "Theme Forge Stellar Burst requires qualified platform tag or proven JS fallback with evidence")
    if platform_tag and platform_tag != "any":
        raise ContractError("UNSUPPORTED_PLATFORM", "Pure JavaScript wrappers require the any tag")
    return "py3-none-any"


# Only the authenticated closure builder issues this in-process representation.
_OFFLINE_JS_PROOF = object()


def _record_digest(data: bytes) -> str:
    return "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode("ascii").rstrip("=")



def format_record(entries: Mapping[str, bytes], dist_info_dir: str) -> bytes:
    """Format standard PEP 376 RECORD CSV."""
    output = io.StringIO()
    writer = csv.writer(output, lineterminator="\n")
    record_path = f"{dist_info_dir}/RECORD"
    for path in sorted(entries.keys()):
        if path != record_path:
            writer.writerow([path, _record_digest(entries[path]), len(entries[path])])
    writer.writerow([record_path, "", ""])
    return output.getvalue().encode("utf-8")


def render_launcher(command_targets: Mapping[str, str], runtime_kind: str = "node", min_node_major: int = 22) -> str:
    """Render stdlib launcher script with Node >= 22 check and no network dependencies."""
    targets_repr = json.dumps(dict(command_targets))
    return f'''"""Theme Forge stdlib launcher. Node >= {min_node_major} required. No network access."""
from __future__ import annotations
import json, os, re, shutil, subprocess, sys
from pathlib import Path

COMMAND_TARGETS: dict[str, str] = {targets_repr}
RUNTIME_KIND: str = {runtime_kind!r}
MIN_NODE_MAJOR: int = {min_node_major}

def _find_node(node_bin: str | None = None) -> str:
    cand = node_bin or os.environ.get("THEME_FORGE_NODE_BIN") or shutil.which("node")
    if not cand or not os.path.isfile(cand) or not os.access(cand, os.X_OK):
        msg = f"Error: 'node' executable not found on PATH. Node.js >= {{MIN_NODE_MAJOR}} is required.\\n" if not cand else f"Error: Specified node binary '{{cand}}' is not an executable file.\\n"
        sys.stderr.write(msg); sys.exit(1)
    return cand

def _check_node_version(node_path: str) -> None:
    try:
        out = subprocess.run([node_path, "--version"], capture_output=True, text=True, check=True, timeout=10).stdout.strip()
    except Exception as exc:
        sys.stderr.write(f"Error: Failed to query Node.js version from '{{node_path}}': {{exc}}\\n"); sys.exit(1)
    m = re.search(r"v?(\\d+)\\.(\\d+)", out)
    if not m or int(m.group(1)) < MIN_NODE_MAJOR:
        sys.stderr.write(f"Error: Node.js >= {{MIN_NODE_MAJOR}} is required, but found version '{{out}}'.\\n"); sys.exit(1)

def run_launcher(command_name: str, argv: list[str] | None = None, *, node_bin: str | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    target_rel = COMMAND_TARGETS.get(command_name)
    if not target_rel:
        sys.stderr.write(f"Error: Unknown command '{{command_name}}'.\\n"); sys.exit(1)
    target_path = Path(__file__).resolve().parent / "payload" / target_rel
    if not target_path.exists():
        sys.stderr.write(f"Error: Target payload file not found: '{{target_path}}'.\\n"); sys.exit(1)
    if RUNTIME_KIND == "node":
        node_path = _find_node(node_bin=node_bin)
        _check_node_version(node_path)
        os.execv(node_path, [node_path, str(target_path)] + argv)
    os.execv(str(target_path), [str(target_path)] + argv)

def main_tfsb() -> None: sys.exit(run_launcher("tfsb"))
def main_tfsb_studio_service() -> None: sys.exit(run_launcher("tfsb-studio-service"))
def main_tfsl() -> None: sys.exit(run_launcher("tfsl"))
def main_tfsl_batch() -> None: sys.exit(run_launcher("tfsl-batch"))
def main_tfss() -> None: sys.exit(run_launcher("tfss"))
def main_tfnf() -> None: sys.exit(run_launcher("tfnf"))
'''


class WheelBuildResult:
    """Deterministic wheel build result."""

    def __init__(self, wheel_path: Path, filename: str, distribution: str, version: str, tag: str,
                 sha256: str, size: int, release_hash: str, record: dict[str, Any],
                 manifest: list[dict[str, Any]], wheel_bytes: bytes, can_publish: bool = False) -> None:
        self.wheel_path, self.filename, self.distribution = wheel_path, filename, distribution
        self.version, self.tag, self.sha256, self.size = version, tag, sha256, size
        self.release_hash, self.record, self.manifest = release_hash, record, manifest
        self.wheel_bytes, self.can_publish = wheel_bytes, can_publish

    def __repr__(self) -> str:
        return f"<WheelBuildResult filename={self.filename!r} sha256={self.sha256[:12]}...>"


def _resolve_commands(
    product_config: dict[str, Any], console_scripts: dict[str, str] | None,
    command_map: dict[str, str] | None, release_record: dict[str, Any] | None,
    payload_files: Mapping[str, bytes],
) -> tuple[dict[str, str], dict[str, str]]:
    scripts: dict[str, str] = dict(console_scripts or product_config["console_scripts"])
    targets: dict[str, str] = dict(command_map or {})
    if release_record:
        for payload in release_record.get("payloads", []):
            for cmd_name, cmd_info in payload.get("commands", {}).items():
                if cmd_name not in targets:
                    targets[cmd_name] = cmd_info.get("path", cmd_info) if isinstance(cmd_info, dict) else cmd_info
    for cmd_name, default_path in product_config.get("default_commands", {}).items():
        if cmd_name not in targets:
            targets[cmd_name] = default_path
    if scripts != product_config["console_scripts"]:
        raise ContractError("COMMAND_IDENTITY", "Wheel commands must match the current product command set")
    for cmd_name in scripts:
        validate_safe_relative_posix_path(targets[cmd_name])
        if targets[cmd_name] not in payload_files:
            raise ContractError("COMMAND_IDENTITY", "Every entrypoint must bind an exact payload file")
    return scripts, targets


def build_wheel(
    product_id: str, version: str, payload_files: Mapping[str, bytes],
    payload_modes: Mapping[str, int] | None = None, *,
    output_dir: str | Path | None = None, output_path: str | Path | None = None,
    release_record: dict[str, Any] | None = None, release_hash: str | None = None,
    content_identity_sha256: str | None = None, platform_tag: str | None = None,
    js_fallback: bool = False, evidence: Any = None, mode_restoration_verified: bool = False,
    console_scripts: dict[str, str] | None = None, command_map: dict[str, str] | None = None,
    license_files: Mapping[str, bytes] | None = None, summary: str | None = None,
    deterministic_timestamp: tuple[int, int, int, int, int, int] | None = None,
    extra_provenance: dict[str, Any] | None = None,
) -> WheelBuildResult:
    """Build a deterministic standard Python wheel for Theme Forge release payloads."""
    if output_path is None and output_dir is None:
        raise ContractError("DESTINATION_REQUIRED", "Caller output destination (output_path or output_dir) is required")
    canonical_id = canonical_product_id(product_id)
    product_config = THEME_FORGE_PRODUCTS[canonical_id]
    if not isinstance(version, str) or not VERSION_RE.fullmatch(version):
        raise ContractError("INVALID_VERSION", "Strict semantic version format required")
    if version != product_config["version"]:
        raise ContractError("INVALID_VERSION", "LIVE1 version differs from the bound generation")
    if not payload_files:
        raise ContractError("EMPTY_PAYLOAD", "Payload files mapping cannot be empty")
    for path, data in payload_files.items():
        validate_safe_relative_posix_path(path)
        if not isinstance(data, bytes):
            raise ContractError("INVALID_PAYLOAD", 'Invalid candidate input or unavailable candidate operation')
        scan_for_credentials(path)
    for path, mode in (payload_modes or {}).items():
        validate_safe_relative_posix_path(path)
        if type(mode) is not int or not 0 <= mode <= 0o777:
            raise ContractError("UNSAFE_MODE" if isinstance(mode, int) else "INVALID_MODE", 'Invalid candidate input or unavailable candidate operation')

    if release_record is None and release_hash is None:
        raise ContractError("PROVENANCE_REQUIRED", "Authoritative release record or release hash is required; unauthenticated default is forbidden")
    if release_record is not None:
        if not isinstance(release_record, dict):
            raise ContractError("INVALID_RECORD", "Release record must be a dict")
        calc_hash = digest(canonical(release_record))
        if release_hash is not None and release_hash != calc_hash:
            raise ContractError("DIGEST_MISMATCH", "Release record digest does not match declared release hash")
        release_hash = calc_hash
    elif not isinstance(release_hash, str) or not SHA256_HEX_RE.fullmatch(release_hash):
        raise ContractError("INVALID_RELEASE_HASH", "Release hash must be a 64-character lowercase hex string")

    if content_identity_sha256 is not None:
        if not isinstance(content_identity_sha256, str) or not SHA256_HEX_RE.fullmatch(content_identity_sha256):
            raise ContractError("INVALID_CONTENT_IDENTITY", "Content identity sha256 must be a 64-character lowercase hex string")

    wheel_tag = resolve_wheel_tag(canonical_id, platform_tag=platform_tag, js_fallback=js_fallback, evidence=evidence, mode_restoration_verified=mode_restoration_verified)
    licenses_dict: dict[str, bytes] = dict(license_files or {})
    if not licenses_dict:
        for name in ("LICENSE", "NOTICE"):
            match = next((d for p, d in payload_files.items() if p == name or p.endswith("/" + name)), None)
            if match is not None:
                licenses_dict[name] = match
    for lic_name, lic_bytes in licenses_dict.items():
        if "\n" in lic_name or "\r" in lic_name:
            raise ContractError("INVALID_LICENSE_NAME", 'Invalid candidate input or unavailable candidate operation')
        validate_safe_relative_posix_path(lic_name)
        if posixpath.basename(lic_name).lower() in ("metadata", "record", "wheel", "entry_points.txt") or lic_name.lower().startswith(("metadata", "record")):
            raise ContractError("INVALID_LICENSE_NAME", 'Invalid candidate input or unavailable candidate operation')
        if not isinstance(lic_bytes, bytes):
            raise ContractError("INVALID_LICENSE_DATA", 'Invalid candidate input or unavailable candidate operation')
    if "LICENSE" not in licenses_dict:
        raise ContractError("MISSING_LICENSE", "Authoritative license bytes required; missing LICENSE file")

    dist_name, pkg_name = product_config["distribution_name"], product_config["package_name"]
    dist_norm, ver_norm = dist_name.replace("-", "_"), version.replace("-", "_")
    wheel_filename = f"{dist_norm}-{ver_norm}-{wheel_tag}.whl"
    dist_info_dir = f"{dist_norm}-{ver_norm}.dist-info"

    scripts, targets = _resolve_commands(product_config, console_scripts, command_map, release_record, payload_files)
    launcher_content = render_launcher(targets, runtime_kind=product_config.get("runtime", "node")).encode("utf-8")
    init_content = f'"""Theme Forge release package."""\n__version__ = {version!r}\n__product_id__ = {canonical_id!r}\n'.encode("utf-8")

    can_publish = False
    provenance_data: dict[str, Any] = {
        "schema": "rs9.wheel-provenance.v1alpha1", "product_id": canonical_id, "distribution_name": dist_name,
        "version": version, "wheel_tag": wheel_tag, "release_record_sha256": release_hash,
        "payload_hashes": {p: digest(b) for p, b in sorted(payload_files.items())},
        "payload_modes": {p: (payload_modes.get(p, 0o644) if payload_modes else 0o644) for p in sorted(payload_files)},
        "can_publish": can_publish,
    }
    if release_record is not None:
        provenance_data["release_record"] = release_record
    if content_identity_sha256 is not None:
        provenance_data["content_identity_sha256"] = content_identity_sha256
    if extra_provenance is not None:
        if set(extra_provenance) - {"npm_dependencies", "fixture_only"}:
            raise ContractError("PROVENANCE_REQUIRED", "Additional provenance cannot replace release bindings")
        provenance_data.update(extra_provenance)

    summary_text = summary or f"Theme Forge authenticated release payload for {dist_name}"
    if any(ord(c) < 32 or ord(c) == 127 for c in summary_text):
        raise ContractError("METADATA_CONTENT", "Wheel summary contains unsafe header content")
    desc = f"Theme Forge release wheel for {dist_name} ({version}).\n\nExternal runtime requirement: Node.js >= 22 is required to run console scripts."
    meta_lines = [
        "Metadata-Version: 2.4", f"Name: {dist_name}", f"Version: {version}", f"Summary: {summary_text}",
        "License-Expression: AGPL-3.0-or-later",
    ] + [f"License-File: {k}" for k in sorted(licenses_dict.keys())] + [
        "Requires-Python: >=3.9", "Description-Content-Type: text/plain", "", desc,
    ]
    is_pure = "true" if wheel_tag.endswith("-any") else "false"
    wheel_info = f"Wheel-Version: 1.0\nGenerator: rs9-wheel (1.0)\nRoot-Is-Purelib: {is_pure}\nTag: {wheel_tag}\n".encode("utf-8")
    entry_points = "\n".join(["[console_scripts]"] + [f"{s} = {pkg_name}.launcher:{f}" for s, f in sorted(scripts.items())]).encode("utf-8")

    archive_entries: dict[str, bytes] = {
        f"{pkg_name}/__init__.py": init_content, f"{pkg_name}/launcher.py": launcher_content,
        f"{pkg_name}/_rs9/provenance.json": canonical(provenance_data),
        f"{dist_info_dir}/METADATA": "\n".join(meta_lines).encode("utf-8"),
        f"{dist_info_dir}/WHEEL": wheel_info, f"{dist_info_dir}/entry_points.txt": entry_points,
    }
    entry_modes: dict[str, int] = {k: 0o644 for k in archive_entries}
    for rel_path, data in sorted(payload_files.items()):
        arc_path = f"{pkg_name}/payload/{rel_path}"
        archive_entries[arc_path] = data
        entry_modes[arc_path] = payload_modes.get(rel_path, 0o644) if payload_modes else 0o644
    for lic_name, lic_data in sorted(licenses_dict.items()):
        archive_entries[f"{dist_info_dir}/licenses/{lic_name}"] = lic_data
        entry_modes[f"{dist_info_dir}/licenses/{lic_name}"] = 0o644
    archive_entries[f"{dist_info_dir}/RECORD"] = format_record(archive_entries, dist_info_dir)
    entry_modes[f"{dist_info_dir}/RECORD"] = 0o644

    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        for arc_path in sorted(archive_entries.keys()):
            zinfo = zipfile.ZipInfo(filename=arc_path, date_time=deterministic_timestamp or (2026, 1, 1, 0, 0, 0))
            zinfo.compress_type, zinfo.create_system = zipfile.ZIP_DEFLATED, 3
            zinfo.external_attr = ((entry_modes.get(arc_path, 0o644) & 0o7777) | stat.S_IFREG) << 16
            zf.writestr(zinfo, archive_entries[arc_path], compresslevel=9)
    wheel_bytes = zip_buf.getvalue()

    dest_target = Path(output_path) if output_path else Path(output_dir) / wheel_filename  # type: ignore
    if dest_target.is_symlink() or os.path.islink(dest_target):
        raise ContractError("UNSAFE_DESTINATION", 'Invalid candidate input or unavailable candidate operation')
    if any(p.is_symlink() for p in dest_target.absolute().parents):
        raise ContractError("UNSAFE_DESTINATION", "Wheel destination ancestry contains a symlink")
    final_path = dest_target.absolute()
    final_path.parent.mkdir(parents=True, exist_ok=True)
    if final_path.is_symlink():
        raise ContractError("UNSAFE_DESTINATION", 'Invalid candidate input or unavailable candidate operation')
    try:
        fd = os.open(str(final_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o644)
        with open(fd, "wb") as f:
            f.write(wheel_bytes)
    except FileExistsError:
        raise ContractError("DESTINATION_EXISTS", 'Invalid candidate input or unavailable candidate operation')
    except OSError as exc:
        raise ContractError("UNSAFE_DESTINATION", 'Invalid candidate input or unavailable candidate operation')

    manifest_list = [
        {"path": p, "size": len(archive_entries[p]), "sha256": digest(archive_entries[p]), "mode": entry_modes.get(p, 0o644)}
        for p in sorted(archive_entries.keys())
    ]
    return WheelBuildResult(
        wheel_path=final_path, filename=wheel_filename, distribution=dist_name, version=version,
        tag=wheel_tag, sha256=digest(wheel_bytes), size=len(wheel_bytes), release_hash=release_hash,
        record=provenance_data, manifest=manifest_list, wheel_bytes=wheel_bytes, can_publish=can_publish,
    )


def verify_wheel_record_bidirectional(wheel_path: str | Path) -> dict[str, Any]:
    """Verify that every member in the wheel is in PEP 376 RECORD, and every RECORD entry matches.

    Performs strict bidirectional validation:
    1. Dist-info directory and RECORD must exist.
    2. Every file in the zip (except RECORD itself) must be present in RECORD.
    3. Every file listed in RECORD (except RECORD itself) must exist in the zip.
    4. Each member's size and SHA-256 base64 digest must match RECORD exactly.
    5. RECORD row syntax must follow standard PEP 376 CSV.
    6. Duplicate ZIP members and duplicate RECORD rows are strictly rejected.
    """
    path = Path(wheel_path).resolve()
    if not path.is_file():
        raise ContractError("INVALID_WHEEL", f"Wheel file does not exist: {path}")
    data = path.read_bytes()
    entries_info: dict[str, dict[str, Any]] = {}
    with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
        raw_namelist = zf.namelist()
        if len(raw_namelist) != len(set(raw_namelist)):
            raise ContractError("RECORD_MISMATCH", "Duplicate wheel members")
        dist_info = next((p.split("/")[0] for p in sorted(set(raw_namelist)) if p.endswith(".dist-info/METADATA")), None)
        if not dist_info:
            raise ContractError("INVALID_WHEEL", "Missing .dist-info/METADATA in wheel")
        record_path = f"{dist_info}/RECORD"
        if record_path not in raw_namelist:
            raise ContractError("INVALID_WHEEL", "Missing .dist-info/RECORD in wheel")

        record_bytes = zf.read(record_path)
        try:
            record_text = record_bytes.decode("utf-8")
        except UnicodeError:
            raise ContractError("RECORD_MISMATCH", "RECORD file is not valid UTF-8")

        rec_rows = list(csv.reader(record_text.splitlines()))
        rec_map: dict[str, tuple[str, int]] = {}
        for row in rec_rows:
            if not row:
                continue
            if len(row) != 3:
                raise ContractError("RECORD_MISMATCH", f"Invalid RECORD row: {row}")
            fn, h, sz = row[0], row[1], row[2]
            if fn in rec_map:
                raise ContractError("RECORD_MISMATCH", "Duplicate RECORD entry")
            if fn == record_path:
                if h != "" or sz != "":
                    raise ContractError("RECORD_MISMATCH", "RECORD row for RECORD itself must have empty hash and size")
                rec_map[fn] = ("", 0)
            else:
                try:
                    size_int = int(sz)
                except ValueError:
                    raise ContractError("RECORD_MISMATCH", f"Non-integer size in RECORD for {fn}: {sz}")
                rec_map[fn] = (h, size_int)

        if record_path not in rec_map:
            raise ContractError("RECORD_MISMATCH", "RECORD must contain an entry for itself")

        # Check every file in the zip against RECORD
        for z in zf.infolist():
            member_bytes = zf.read(z.filename)
            entries_info[z.filename] = {
                "size": len(member_bytes),
                "mode": (z.external_attr >> 16) & 0o7777,
                "sha256_record": _record_digest(member_bytes),
            }
            if z.filename == record_path:
                continue
            rec_entry = rec_map.get(z.filename)
            if rec_entry is None:
                raise ContractError("RECORD_MISMATCH", f"File in wheel not listed in RECORD: {z.filename}")
            expected_digest, expected_size = rec_entry
            if len(member_bytes) != expected_size:
                raise ContractError(
                    "RECORD_MISMATCH",
                    f"Size mismatch for {z.filename}: zip={len(member_bytes)}, RECORD={expected_size}",
                )
            actual_digest = _record_digest(member_bytes)
            if actual_digest != expected_digest:
                raise ContractError(
                    "RECORD_MISMATCH",
                    f"Digest mismatch for {z.filename}: zip={actual_digest}, RECORD={expected_digest}",
                )

        # Check every non-RECORD entry in RECORD exists in the zip
        for rec_file in rec_map:
            if rec_file == record_path:
                continue
            if rec_file not in entries_info:
                raise ContractError("RECORD_MISMATCH", f"File in RECORD not found in wheel: {rec_file}")

    return {
        "wheel_path": str(path),
        "filename": path.name,
        "dist_info": dist_info,
        "member_count": len(entries_info),
        "record_entries_count": len(rec_map),
        "record_valid": True,
        "entries": entries_info,
    }


def inspect_wheel(wheel_path: str | Path) -> dict[str, Any]:
    """Inspect and verify wheel structure, RECORD digests, and metadata."""
    path = Path(wheel_path).resolve()
    if not path.is_file():
        raise ContractError("INVALID_WHEEL", f"Wheel file does not exist: {path}")
    data = path.read_bytes()
    entries_info: dict[str, dict[str, Any]] = {}
    with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
        raw_names = zf.namelist()
        names = sorted(set(raw_names))
        dist_info = next((p.split("/")[0] for p in names if p.endswith(".dist-info/METADATA")), None)
        if not dist_info or f"{dist_info}/RECORD" not in raw_names:
            raise ContractError("INVALID_WHEEL", "Missing dist-info/METADATA or RECORD")

        # Consolidate with strict bidirectional RECORD logic
        valid = True
        try:
            verify_wheel_record_bidirectional(path)
        except ContractError as exc:
            if exc.code == "RECORD_MISMATCH":
                valid = False
            else:
                raise

        for z in zf.infolist():
            try:
                mb = zf.read(z.filename)
                entries_info[z.filename] = {"size": len(mb), "mode": (z.external_attr >> 16) & 0o7777, "sha256": digest(mb)}
            except Exception:
                valid = False

        meta_dict: dict[str, Any] = {}
        try:
            meta_raw = zf.read(f"{dist_info}/METADATA").decode("utf-8")
            headers_section = meta_raw.split("\n\n", 1)[0]
            for line in headers_section.splitlines():
                if not line.strip():
                    break
                if ":" in line and not line.startswith(" "):
                    k, v = [x.strip() for x in line.split(":", 1)]
                    if k in meta_dict:
                        meta_dict[k] = (meta_dict[k] if isinstance(meta_dict[k], list) else [meta_dict[k]]) + [v]
                    else:
                        meta_dict[k] = v
        except Exception:
            valid = False

        prov_entry = next((p for p in names if p.endswith("/_rs9/provenance.json") or p.endswith("/provenance.json")), None)
        prov = None
        if prov_entry:
            try:
                prov = json.loads(zf.read(prov_entry).decode("utf-8"))
            except Exception:
                pass

        return {
            "path": str(path),
            "filename": path.name,
            "size": len(data),
            "sha256": digest(data),
            "dist_info": dist_info,
            "metadata": meta_dict,
            "record_valid": valid,
            "entries": entries_info,
            "provenance": prov,
        }


def verify_wheel_record(wheel_path: str | Path) -> bool:
    """Verify that every file in the wheel matches the PEP 376 RECORD checksum and size."""
    verify_wheel_record_bidirectional(wheel_path)
    return True
