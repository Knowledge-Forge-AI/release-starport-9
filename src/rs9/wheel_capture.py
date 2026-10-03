"""Authenticated-capture CLI wheel builder using release_core and npm_deps."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Mapping

from rs9.archives import inspect_archive
from rs9.errors import ContractError
from rs9.npm_deps import authenticate_dependencies, closure_for_capture
from rs9.profiles import PACKAGE_PROFILE, evaluate_profile
from rs9.release_core import ReleaseCapture, authenticate_release, authenticated_record_hash, digest
from rs9.records import record_sha256
from rs9.security import scan_for_credentials, validate_safe_relative_posix_path
from rs9.spdx import validate_spdx_expression
from rs9.wheel import (
    THEME_FORGE_PRODUCTS,
    WheelBuildResult,
    build_wheel,
    canonical_product_id,
    resolve_wheel_tag,
    _OFFLINE_JS_PROOF,
)


def build_capture_wheel(
    product_id: str,
    version: str,
    capture: ReleaseCapture | None = None,
    *,
    selection: dict[str, Any] | None = None,
    evidence_dir: str | Path | None = None,
    output_dir: str | Path | None = None,
    output_path: str | Path | None = None,
    platform_tag: str | None = None,
    dependency_archives: Mapping[str, str | Path] | None = None,
    integrate_closure: bool = False,
    license_files: Mapping[str, bytes] | None = None,
    summary: str | None = None,
    content_identity_sha256: str | None = None,
    deterministic_timestamp: tuple[int, int, int, int, int, int] | None = None,
    profile_result: dict[str, Any] | None = None,
    fixture_only: bool = False,
) -> WheelBuildResult:
    """Build a deterministic CLI wheel from authenticated release capture bytes.
    
    Validates:
    - Release core authenticated capture (with fresh reauthentication).
    - Profile, license, and command identity against product specification.
    - Strict dependency closure through npm_deps without npm runtime.
    - Burst closure only when exact real lock supports it.
    """
    canonical_id = canonical_product_id(product_id)
    if canonical_id == "theme-forge-nebular-fusion":
        raise ContractError(
            "UNSUPPORTED_PRODUCT",
            "Theme Forge Nebular Fusion is a native desktop application; use wheel_native.py",
        )

    product_config = THEME_FORGE_PRODUCTS[canonical_id]
    if version != product_config["version"]:
        raise ContractError("INVALID_VERSION", f"Version {version} differs from bound product version {product_config['version']}")

    # 1. Reauthenticate release capture bytes
    if capture is not None:
        release_hash = authenticated_record_hash(capture)
    elif selection is not None and evidence_dir is not None:
        capture = authenticate_release(selection, evidence_dir)
        release_hash = authenticated_record_hash(capture)
    else:
        raise ContractError(
            "PROVENANCE_REQUIRED",
            "Either an authenticated ReleaseCapture or (selection, evidence_dir) must be provided",
        )

    if not fixture_only:
        if (profile_result is None or record_sha256(profile_result) not in capture._profile_results
                or profile_result.get("release_record_sha256") != release_hash):
            raise ContractError("PROFILE_BINDING", "Fresh evaluated release profile required")
        licence = profile_result["sections"].get("license", profile_result["sections"].get("legacy_ingestion", {}).get("license"))
        if not licence or licence.get("status") != "consistent":
            raise ContractError("LICENSE_AUTHORITY", "Consistent release license facts required")
    if capture.record["repository"]["full_name"] != "Knowledge-Forge-AI/" + canonical_id:
        raise ContractError("REPOSITORY_MISMATCH", "Payload must belong to selected product")
    # Validate release metadata tag alignment
    rel_tag = capture.record.get("release", {}).get("tag", "")
    if rel_tag != f"v{version}":
        raise ContractError("VERSION_MISMATCH", f"Capture release tag {rel_tag} does not agree with version {version}")

    # 2. License identity & SPDX validation
    licenses_dict = dict(license_files or {})
    if any(capture.source.get(name) != data for name, data in licenses_dict.items()):
        raise ContractError("LICENSE_AUTHORITY", "License overrides must equal authenticated tagged bytes")
    if "LICENSE" not in licenses_dict and "LICENSE" in capture.source:
        licenses_dict["LICENSE"] = capture.source["LICENSE"]
    if "NOTICE" not in licenses_dict and "NOTICE" in capture.source:
        licenses_dict["NOTICE"] = capture.source["NOTICE"]
    if "LICENSE" not in licenses_dict:
        raise ContractError("MISSING_LICENSE", "Authoritative LICENSE bytes required from capture or parameter")

    # Validate license expression from tagged package.json if present
    if "package.json" in capture.source:
        try:
            pkg_data = json.loads(capture.source["package.json"].decode("utf-8"))
            lic_expr = pkg_data.get("license")
            if lic_expr:
                scan_for_credentials(lic_expr)
                validate_spdx_expression(lic_expr)
            if lic_expr != "AGPL-3.0-or-later":
                raise ContractError("LICENSE_AUTHORITY", "CLI license expression differs from generation")
        except (ValueError, UnicodeError):
            raise ContractError("INVALID_METADATA", "Tagged package.json is malformed UTF-8/JSON")

    # 3. Extract payload files from authenticated archive
    if len(capture.record["payloads"]) != 1:
        raise ContractError("ASSET_COUNT", "CLI release requires exactly one package payload")
    payload = capture.record["payloads"][0]
    archive_path = capture.archives[payload["id"]]
    raw = Path(archive_path).read_bytes()
    if len(raw) != payload["size"] or digest(raw) != payload["sha256"]:
        raise ContractError("INPUT_CHANGED", "Released archive changed after capture")

    payload_files: dict[str, bytes] = {}
    payload_modes: dict[str, int] = {}

    def _extract_payload_member(name: str, content: bytes, mode: int) -> None:
        payload_files[name] = content
        payload_modes[name] = mode

    archive_manifest = inspect_archive(
        archive_path,
        commands={},
        on_file=_extract_payload_member,
        max_members=20000,
        max_member_bytes=16 * 1024 * 1024,
        max_total_bytes=128 * 1024 * 1024,
    )
    if archive_manifest["manifest_sha256"] != payload["payload_manifest_sha256"] or digest(Path(archive_path).read_bytes()) != payload["sha256"]:
        raise ContractError("INPUT_CHANGED", "Archive manifest differs from authenticated release")
    if any(row["type"] == "symlink" for row in archive_manifest["members"]):
        raise ContractError("NATIVE_WHEEL_WITHHELD", "CLI wheel symlink representation is unqualified")

    if not payload_files:
        raise ContractError("EMPTY_PAYLOAD", "Extracted payload files mapping is empty")

    # 4. Command identity
    for cmd_name, cmd_relpath in product_config.get("default_commands", {}).items():
        validate_safe_relative_posix_path(cmd_relpath)
        if cmd_relpath not in payload_files:
            raise ContractError(
                "COMMAND_IDENTITY",
                f"Required command target {cmd_relpath!r} for entrypoint {cmd_name!r} not found in payload",
            )
        script = payload_files[cmd_relpath].decode("utf-8")
        if re.search(r"[\"'`](?:npm|npx)(?:[\"'`\s])", script):
            raise ContractError("RUNTIME_INSTALL_WITHHELD", "Entry script references npm/npx execution")

    # 5. Dependency closure through npm_deps authenticated staging
    # "Burst closure must be integrated only when exact real lock supports it."
    extra_prov: dict[str, Any] = {"fixture_only": fixture_only}
    tagged_package = json.loads(capture.source["package.json"])
    if canonical_id == "theme-forge-stellar-burst" and not (integrate_closure or dependency_archives is not None):
        raise ContractError("NPM_LOCK", "Burst requires an inspected lock-bound runtime closure")
    if tagged_package.get("dependencies") and not (integrate_closure or dependency_archives is not None):
        raise ContractError("NPM_CLOSURE", "Offline runtime closure is mandatory")
    if any(tagged_package.get(key) for key in ("optionalDependencies", "peerDependencies")):
        raise ContractError("NPM_CLOSURE", "Optional/peer runtime dependencies remain unqualified")
    if integrate_closure or dependency_archives is not None:
        if "package-lock.json" not in capture.source:
            raise ContractError("NPM_LOCK", "Exact real lock required in authenticated capture to integrate closure")
        if dependency_archives is None:
            raise ContractError("NPM_CLOSURE", "Staged dependency archives required to integrate closure")

        # Authenticate runtime dependency closure without npm runtime
        dep_snapshot = authenticate_dependencies(capture, dependency_archives)

        # Unpack authenticated dependencies into package/node_modules/
        for dep_item in dep_snapshot.get("dependencies", []):
            dep_path = dep_item["path"]  # e.g. "node_modules/foo"
            dep_archive = dependency_archives.get(dep_path)
            if not dep_archive:
                raise ContractError("NPM_CLOSURE", f"Missing staged archive for dependency: {dep_path}")

            def _extract_dep_member(name: str, content: bytes, mode: int) -> None:
                if name.startswith("package/"):
                    rel_sub = name[len("package/"):]
                    target_key = f"package/{dep_path}/{rel_sub}"
                    payload_files[target_key] = content
                    payload_modes[target_key] = mode

            inspect_archive(
                dep_archive,
                commands={},
                on_file=_extract_dep_member,
                max_members=20000,
                max_member_bytes=8 * 1024 * 1024,
                max_total_bytes=64 * 1024 * 1024,
            )
            if digest(Path(dep_archive).read_bytes()) != dep_item["sha256"]:
                raise ContractError("INPUT_CHANGED", "Dependency bytes changed during staging")
            for legal_path in dep_item["legal_files"]:
                rel = legal_path.removeprefix("package/")
                licenses_dict[f"deps/{dep_path}/{rel}"] = payload_files[f"package/{dep_path}/{rel}"]

        extra_prov["npm_dependencies"] = dep_snapshot

    # Refuse native payload members or platform-constrained metadata. Universal
    # is justified only by the authenticated JS closure inspected here.
    for name, data in payload_files.items():
        if data.startswith((b"\x7fELF", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe")) or name.endswith(".node"):
            raise ContractError("UNQUALIFIED_PLATFORM", "Native CLI dependency wheels require platform qualification")
        if name.endswith("/package.json"):
            metadata = json.loads(data)
            if metadata.get("os") or metadata.get("cpu"):
                raise ContractError("UNQUALIFIED_PLATFORM", "Platform constrained dependencies require qualification")
    if platform_tag not in (None, "any"):
        raise ContractError("UNSUPPORTED_PLATFORM", "Authenticated pure JS closure uses the any tag")

    # 6. Build deterministic wheel
    return build_wheel(
        product_id=canonical_id,
        version=version,
        payload_files=payload_files,
        payload_modes=payload_modes,
        output_dir=output_dir,
        output_path=output_path,
        release_record=capture.record,
        release_hash=release_hash,
        content_identity_sha256=content_identity_sha256,
        platform_tag=platform_tag,
        evidence=_OFFLINE_JS_PROOF,
        license_files=licenses_dict,
        summary=summary,
        deterministic_timestamp=deterministic_timestamp,
        extra_provenance=extra_prov,
    )


build_wheel_from_capture = build_capture_wheel
