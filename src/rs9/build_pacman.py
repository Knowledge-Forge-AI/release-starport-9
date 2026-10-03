"""Normal-tool native package candidate driver for pacman x86_64 and any (Arch Linux).

Executes real host makepkg (strictly nonroot) and repo-add to generate candidate packages
and repository databases:
- Rejects root execution (makepkg nonroot requirement).
- Requires empty scratch root and exact authenticated release capture.
- CLI projects enforce arch 'any' and authenticated offline npm closure or fail closed.
- Native project (Nebular) enforces arch 'x86_64'.
- Native prerequisites absent -> explicit unavailable, never fabricated files.
- Subprocess derivation records bound to artifact, tool, container, and source.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import posixpath
import shlex
import shutil
from typing import Any, Mapping

from rs9.build_native import (
    CommandReceipt,
    CommandRunner,
    NativePrerequisiteUnavailable,
    SubprocessRunner,
    check_prerequisites,
    create_derivation_record,
    extract_for_packaging,
    stage_offline_npm_closure,
    validate_build_inputs,
    validate_scratch_root,
)
from rs9.errors import ContractError
from rs9.profiles import png_size
from rs9.release_core import ReleaseCapture, digest
from rs9.scratch import canonical, physical_directory
from rs9.security import validate_safe_relative_posix_path

PACMAN_REQUIRED_TOOLS = ["makepkg", "repo-add"]


def _desktop_entry(project_id: str, summary: str, command: str, categories: list[str]) -> bytes:
    escape = lambda s: s.replace("\\", "\\\\")
    cats = ";".join(sorted(categories)) + ";"
    return (
        f"[Desktop Entry]\nType=Application\nName=Theme Forge Nebular Fusion\n"
        f"Comment={escape(summary)}\nExec={command}\nIcon={project_id}\n"
        f"Terminal=false\nCategories={cats}\n"
    ).encode("utf-8")


def _render_pkgbuild(
    name: str,
    version: str,
    revision: int,
    summary: str,
    lic: str,
    asset: str,
    sha: str,
    arch: str,
    deps: list[str],
    cmds: list[dict[str, str]],
    is_nebular: bool,
    root: str,
    d_sha: str = "",
    i_sha: str = "",
) -> bytes:
    srcs = [asset] + ([f"{name}.desktop", "icon.png"] if is_nebular else [])
    sums = [sha] + ([d_sha, i_sha] if is_nebular else [])
    src_str = " ".join(shlex.quote(s) for s in srcs)
    sum_str = " ".join(f"'{s}'" for s in sums)
    dep_str = " ".join(shlex.quote(d) for d in deps)

    if is_nebular:
        launch = (
            f'  ln -s "/usr/lib/{name}/{cmds[0]["path"]}" "$pkgdir/usr/bin/{cmds[0]["name"]}"\n'
            f'  install -Dm644 "$srcdir/{name}.desktop" "$pkgdir/usr/share/applications/{name}.desktop"\n'
            f'  install -Dm644 "$srcdir/icon.png" "$pkgdir/usr/share/icons/hicolor/256x256/apps/{name}.png"'
        )
    else:
        launch = "\n".join(
            f'  cat << \'EOF\' > "$pkgdir/usr/bin/{c["name"]}"\n#!/bin/sh\nexec node "/usr/lib/{name}/{c["path"]}" "$@"\nEOF\n  chmod 0755 "$pkgdir/usr/bin/{c["name"]}"'
            for c in cmds
        )

    return (
        f"# RS9 pacman candidate recipe from exact authenticated release capture.\n"
        f"# Publication and signing deferred.\n"
        f"pkgname={name}\n"
        f"pkgver={version}\n"
        f"pkgrel={revision}\n"
        f"pkgdesc={shlex.quote(summary)}\n"
        f"arch=('{arch}')\n"
        f"url='https://github.com/Knowledge-Forge-AI/{name}'\n"
        f"license=('{lic}')\n"
        f"depends=({dep_str})\n"
        f"options=('!strip' '!debug' '!purge' '!zipman')\n"
        f"source=({src_str})\n"
        f"sha256sums=({sum_str})\n\n"
        f"package() {{\n"
        f'  local payload="$pkgdir/usr/lib/{name}"\n'
        f'  mkdir -p "$payload" "$pkgdir/usr/bin"\n'
        f'  cp -a "$srcdir/{root}/." "$payload/"\n'
        f"{launch}\n"
        f'  if [ -f "$payload/LICENSE" ]; then\n'
        f'    install -Dm644 "$payload/LICENSE" "$pkgdir/usr/share/licenses/{name}/LICENSE"\n'
        f"  fi\n"
        f'  if [ -f "$payload/NOTICE" ]; then\n'
        f'    install -Dm644 "$payload/NOTICE" "$pkgdir/usr/share/licenses/{name}/NOTICE"\n'
        f"  fi\n"
        f"}}\n"
    ).encode("utf-8")


def build_pacman_candidate(
    capture: ReleaseCapture,
    intent: dict[str, Any],
    arch: str,
    scratch_dir: str | Path,
    *,
    distro: str = "arch",
    revision: int = 1,
    offline_npm_archives: Mapping[str, str | Path] | None = None,
    runner: CommandRunner | None = None,
) -> dict[str, Any]:
    """Build pacman candidate package using normal host makepkg and repo-add."""
    scratch = validate_scratch_root(scratch_dir)

    ctx = validate_build_inputs(
        capture, intent, arch, adapter="pacman", distro=distro
    )
    project_id = ctx["project_id"]
    version = ctx["version"]
    is_native = ctx["is_native"]
    matched_arch = ctx["arch"]

    r = runner or SubprocessRunner()
    missing: list[str] = []
    for tool in PACMAN_REQUIRED_TOOLS:
        if r.which(tool) is None:
            missing.append(tool)
    if missing:
        raise NativePrerequisiteUnavailable(
            f"Pacman build prerequisites missing: {missing}. Never fabricating files.",
            missing_tools=missing,
        )

    # Check nonroot execution: makepkg strictly forbids running as root
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        raise ContractError(
            "NONROOT_REQUIRED",
            "makepkg must be executed as nonroot; root execution refused",
        )

    # Setup scratch directories
    pkg_work = scratch / "pacman" / project_id
    pkg_work.mkdir(parents=True, exist_ok=True)
    repo_dir = scratch / "repo" / matched_arch
    repo_dir.mkdir(parents=True, exist_ok=True)

    # Copy source asset into packaging directory
    asset_name = ctx["asset_name"]
    asset_file = pkg_work / asset_name
    asset_file.write_bytes(ctx["asset_bytes"])

    desktop_bytes = icon_bytes = None
    desktop_sha = icon_sha = ""
    cmds: list[dict[str, str]] = []

    if is_native:
        payload = ctx["payload"]
        launchers = payload.get("launchers", {})
        l_raw = launchers.get("tfnf", {}).get("path")
        if not l_raw:
            raise ContractError(
                "MISSING_LAUNCHER",
                "Nebular released launcher path missing from capture payload",
            )
        payload_root = ctx["payload_root"]
        l_rel = l_raw[len(payload_root) + 1:] if l_raw.startswith(payload_root + "/") else l_raw
        cmds = [{"name": "tfnf", "path": l_rel}]

        desktop_info = intent.get("desktop") or capture.record.get("desktop")
        if not desktop_info:
            raise ContractError(
                "MISSING_REQUIRED_KEY", "Desktop facts required for Nebular"
            )
        icon_path = desktop_info.get("icon", {}).get("path", "src-tauri/icons/icon.png")
        icon_bytes = capture.source.get(icon_path)
        if not icon_bytes:
            raise ContractError(
                "MISSING_ICON", "Nebular icon bytes missing from capture source"
            )
        png_size(icon_bytes)
        desktop_bytes = _desktop_entry(
            project_id, ctx["summary"], "tfnf", desktop_info.get("categories", ["Development"])
        )
        desktop_sha = digest(desktop_bytes)
        icon_sha = digest(icon_bytes)

        (pkg_work / f"{project_id}.desktop").write_bytes(desktop_bytes)
        (pkg_work / "icon.png").write_bytes(icon_bytes)

        # Nebular dependencies derived from DT_NEEDED / system libs
        raise ContractError("NATIVE_DEPENDENCY_DERIVATION_UNQUALIFIED", "Native dependency provider queries and clean client closure proof are required")
    else:
        # CLI projects: stage offline authenticated npm closure
        payload_root = ctx["payload_root"]
        cmd_dict = ctx["payload"].get("commands", {}) or intent.get("commands", {})
        cmds = [
            {"name": k, "path": v["path"][len(payload_root) + 1:]}
            for k, v in sorted(cmd_dict.items())
        ]
        # Stage offline npm closure into unpacked payload structure
        staged_nm = pkg_work / "staged_node_modules"
        stage_offline_npm_closure(capture, project_id, offline_npm_archives, staged_nm)
        from rs9.build_native import npm_bundle
        closure_sha = npm_bundle(staged_nm, pkg_work / "npm-closure.tar.gz")

        # Truthful extraction path for $srcdir
        src_dir = pkg_work / "src"
        src_dir.mkdir(parents=True, exist_ok=True)
        extract_for_packaging(asset_file, src_dir, expected_sha256=ctx["asset_sha"])
        shutil.copytree(staged_nm, src_dir / "node_modules")

        # CLI packages depend on nodejs >= 22 (classified as reviewed policy)
        derived_deps = ["nodejs>=22"]

    # Render PKGBUILD
    pkgbuild_bytes = _render_pkgbuild(
        project_id,
        version,
        revision,
        ctx["summary"],
        ctx["license"],
        asset_name,
        ctx["asset_sha"],
        matched_arch,
        derived_deps,
        cmds,
        is_native,
        ctx["payload_root"],
        desktop_sha,
        icon_sha,
    )
    pkgbuild_path = pkg_work / "PKGBUILD"
    if not is_native:
        text = pkgbuild_bytes.decode()
        text = text.replace("source=(", "source=('npm-closure.tar.gz' ", 1)
        text = text.replace("sha256sums=(", "sha256sums=('" + closure_sha + "' ", 1)
        text = text.replace('  cp -a "$srcdir/' + ctx["payload_root"] + '/." "$payload/"',
                            '  cp -a "$srcdir/' + ctx["payload_root"] + '/." "$payload/"\n  cp -a "$srcdir/node_modules" "$payload/node_modules"')
        pkgbuild_bytes = text.encode()
    pkgbuild_path.write_bytes(pkgbuild_bytes)

    # Run makepkg
    makepkg_cmd = [
        "makepkg",
        "--nodeps",
        "--noextract",
        "--force",
        "--clean",
    ]
    makepkg_receipt = r.run(makepkg_cmd, cwd=pkg_work)
    if makepkg_receipt.exit_code != 0:
        raise ContractError(
            "BUILD_FAILED",
            f"makepkg failed with exit code {makepkg_receipt.exit_code}: {makepkg_receipt.stderr_text}",
        )

    # Locate generated package file
    pkg_files = [
        p
        for p in pkg_work.iterdir()
        if p.name.startswith(f"{project_id}-{version}")
        and (p.name.endswith(".pkg.tar.zst") or p.name.endswith(".pkg.tar.xz") or p.name.endswith(".pkg.tar.gz"))
    ]
    if not pkg_files:
        # In a seam runner, the runner might not generate physical output on disk;
        # if the file doesn't exist, we do NOT fabricate fake files!
        # Check if the runner simulated output
        raise ContractError(
            "BUILD_FAILED",
            "makepkg completed but no candidate package file was generated",
        )

    pkg_file = pkg_files[0]
    pkg_bytes = pkg_file.read_bytes()
    dest_pkg = repo_dir / pkg_file.name
    dest_pkg.write_bytes(pkg_bytes)

    # Run repo-add
    repo_db_path = repo_dir / "custom.db.tar.gz"
    repo_add_cmd = ["repo-add", str(repo_db_path), str(dest_pkg)]
    repo_add_receipt = r.run(repo_add_cmd, cwd=repo_dir)
    if repo_add_receipt.exit_code != 0:
        raise ContractError(
            "BUILD_FAILED",
            f"repo-add failed with exit code {repo_add_receipt.exit_code}: {repo_add_receipt.stderr_text}",
        )

    rel_artifact_path = dest_pkg.relative_to(scratch).as_posix()
    validate_safe_relative_posix_path(rel_artifact_path)

    derivation = create_derivation_record(
        artifact_relpath=rel_artifact_path,
        artifact_bytes=pkg_bytes,
        tool_receipt=makepkg_receipt,
        capture=capture,
        intent=intent,
        adapter="pacman",
        arch=matched_arch,
        distro=distro,
        project_id=project_id,
        version=version,
        derived_dependencies=derived_deps,
        extra_tools=[repo_add_receipt],
        dependency_classification="reviewed-policy",
    )

    manifest = {
        "schema": "rs9.pacman-candidate.v1alpha1",
        "status": "unsigned-candidate",
        "qualification": "unqualified-candidate",
        "can_publish": False,
        "adapter": "pacman",
        "project": project_id,
        "version": version,
        "revision": revision,
        "architecture": matched_arch,
        "distro": distro,
        "package_file": rel_artifact_path,
        "package_sha256": digest(pkg_bytes),
        "package_size": len(pkg_bytes),
        "dependencies": derived_deps,
        "dependency_classification": "reviewed-policy",
        "derivation": derivation,
    }

    (scratch / "pacman-manifest.json").write_bytes(canonical(manifest))

    return {
        "manifest": manifest,
        "derivation_record": derivation,
        "package_path": dest_pkg,
        "repo_db_path": repo_db_path,
        "receipts": [makepkg_receipt, repo_add_receipt],
    }


def main(argv: list[str] | None = None) -> int:
    """CLI driver for pacman candidate builder."""
    parser = argparse.ArgumentParser(description="RS9 Pacman Candidate Package Driver")
    parser.add_argument("--arch", required=True, help="Target architecture (x86_64 or any)")
    parser.add_argument("--capture", required=True, help="Path to evidence capture directory")
    parser.add_argument("--intent", required=True, help="Path to intent JSON")
    parser.add_argument("--scratch", required=True, help="Path to empty scratch directory")
    parser.add_argument("--distro", default="arch", help="Target distro (default: arch)")
    parser.add_argument("--offline-npm", help="Path to offline npm archives JSON")
    parser.add_argument(
        "--check-prerequisites", action="store_true", help="Check tools and exit"
    )

    args = parser.parse_args(argv)

    if args.check_prerequisites:
        status = check_prerequisites("pacman", PACMAN_REQUIRED_TOOLS)
        print(canonical(status).decode(), end="")
        return 0 if status["available"] else 1

    try:
        from rs9.profiles import selection_for_intent
        from rs9.release_core import authenticate_release

        intent = json.loads(Path(args.intent).read_bytes())
        capture = authenticate_release(selection_for_intent(intent), Path(args.capture))
        offline_npm = None
        if args.offline_npm:
            offline_npm = json.loads(Path(args.offline_npm).read_bytes())

        res = build_pacman_candidate(
            capture,
            intent,
            args.arch,
            args.scratch,
            distro=args.distro,
            offline_npm_archives=offline_npm,
        )
        print(canonical(res["manifest"]).decode(), end="")
        return 0
    except ContractError as err:
        print(f"[{err.code}] {err.message}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
