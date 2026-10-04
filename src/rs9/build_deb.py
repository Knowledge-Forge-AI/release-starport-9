"""Normal-tool native package candidate driver for Debian / Ubuntu 26.04 (amd64, arm64, all).

Executes host dpkg-deb for CLI candidates; native dependency qualification remains withheld:
- Debian distributions (e.g. trixie, bookworm, debian-13) are strictly rejected; scope is Ubuntu 26.04 resolute.
- Native builds remain withheld until complete ELF dependency derivation and installed shlibs
  inventory are implemented and qualified. No caller list can substitute for that proof.
- CLI projects enforce arch 'all' and authenticated offline npm closure or fail closed.
- Native project (Nebular) enforces arch 'amd64' or 'arm64'.
- Explicit maintainer argument is mandatory; never invents maintainer email.
- Native prerequisites absent -> explicit unavailable, never fabricated files.
- Built package is integrated into candidate AptRepositoryCandidate and verified with validate_apt_repository.
- Subprocess derivation records bound to artifact, tool, container, and source.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import posixpath
import re
import shutil
import tarfile
from typing import Any, Mapping

from rs9.build_native import (
    CommandReceipt,
    CommandRunner,
    NativePrerequisiteUnavailable,
    SubprocessRunner,
    check_prerequisites,
    create_derivation_record,
    stage_offline_npm_closure,
    validate_build_inputs,
    validate_maintainer,
    validate_scratch_root,
)
from rs9.elf import parse_elf
from rs9.errors import ContractError
from rs9.profiles import png_size
from rs9.release_core import ReleaseCapture, digest
from rs9.repo_apt import AptRepositoryCandidate, validate_apt_repository
from rs9.scratch import canonical, physical_directory
from rs9.security import validate_safe_relative_posix_path

DEB_REQUIRED_TOOLS = ["dpkg-deb"]
DEB_NATIVE_REQUIRED_TOOLS = ["dpkg-deb", "dpkg-shlibdeps"]


def _desktop_entry(project_id: str, summary: str, command: str, categories: list[str]) -> bytes:
    escape = lambda s: s.replace("\\", "\\\\")
    cats = ";".join(sorted(categories)) + ";"
    return (
        f"[Desktop Entry]\nType=Application\nName=Theme Forge Nebular Fusion\n"
        f"Comment={escape(summary)}\nExec={command}\nIcon={project_id}\n"
        f"Terminal=false\nCategories={cats}\n"
    ).encode("utf-8")


def _render_control(
    package: str,
    version: str,
    revision: int,
    architecture: str,
    maintainer: str,
    description: str,
    depends: str,
    section: str = "utils",
    priority: str = "optional",
) -> bytes:
    lines = [
        f"Package: {package}",
        f"Version: {version}-{revision}",
        f"Architecture: {architecture}",
        f"Maintainer: {maintainer}",
        f"Depends: {depends}",
        f"Section: {section}",
        f"Priority: {priority}",
        f"Description: {description}",
    ]
    return ("\n".join(lines) + "\n").encode("utf-8")


def _parse_shlibdeps_output(output_text: str) -> str:
    """Parse shlibs:Depends from dpkg-shlibdeps output."""
    for line in output_text.splitlines():
        line = line.strip()
        if line.startswith("shlibs:Depends="):
            return line[len("shlibs:Depends="):].strip()
    return ""


ELF_MACHINE = {"amd64": "x86_64", "arm64": "aarch64"}
SOURCE_DATE_EPOCH = "1767225600"  # 2026-01-01T00:00:00Z, the repository index date
_DEPENDENCY_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9+.-]*(:[a-z0-9-]+)?$")


def collect_elf_inventory(root: str | Path) -> list[dict[str, Any]]:
    """Every regular ELF file under root, parsed strictly; unsupported ELF fails closed."""
    base = Path(root)
    rows: list[dict[str, Any]] = []
    for current, dirs, names in os.walk(str(base)):
        dirs.sort()
        for name in sorted(names):
            path = Path(current) / name
            if path.is_symlink() or not path.is_file():
                continue
            with path.open("rb") as stream:
                if stream.read(4) != b"\x7fELF":
                    continue
            data = path.read_bytes()
            info = parse_elf(data)
            rows.append({
                "path": path.relative_to(base).as_posix(),
                "sha256": digest(data),
                "machine": info["machine"],
                "type": info["type"],
                "interpreter": info["interpreter"],
                "needed": sorted(info["needed"]),
                "rpath": info["rpath"],
                "runpath": info["runpath"],
            })
    return rows


def derive_native_dependencies(
    runner: CommandRunner,
    scratch: Path,
    pkg_root: Path,
    project_id: str,
    arch: str,
    maintainer: str,
    elf_objects: list[dict[str, Any]],
) -> tuple[CommandReceipt, str, CommandReceipt, dict[str, Any]]:
    """Run dpkg-shlibdeps over ALL ELF objects, then inventory the providing installed packages.

    No caller-supplied dependency list can substitute: the dependency string is exactly the
    tool's shlibs:Depends output, and each named package must exist in the installed dpkg
    database (dpkg-query) of the environment that ran the derivation.
    """
    work = scratch / "shlibdeps"
    (work / "debian").mkdir(parents=True)
    (work / "debian" / "control").write_bytes(
        f"Source: {project_id}\nMaintainer: {maintainer}\n\nPackage: {project_id}\nArchitecture: {arch}\n".encode("utf-8")
    )
    lib_dirs = sorted({str((pkg_root / row["path"]).parent) for row in elf_objects if row["type"] == "shared"})
    command = [
        "dpkg-shlibdeps", "-O",
        *[f"-l{directory}" for directory in lib_dirs],
        *[f"-e{pkg_root / row['path']}" for row in elf_objects],
    ]
    receipt = runner.run(command, cwd=work)
    if receipt.exit_code != 0:
        raise ContractError("NATIVE_DEPENDENCY_DERIVATION_FAILED",
                            f"dpkg-shlibdeps failed with exit code {receipt.exit_code}")
    depends = _parse_shlibdeps_output(receipt.stdout_text)
    if not depends:
        raise ContractError("NATIVE_DEPENDENCY_DERIVATION_UNQUALIFIED",
                            "dpkg-shlibdeps derived no dependency for the native ELF objects")
    names: list[str] = []
    for group in depends.split(","):
        name = group.split("|")[0].strip().split(" ")[0]
        if not _DEPENDENCY_NAME_RE.fullmatch(name):
            raise ContractError("NATIVE_DEPENDENCY_DERIVATION_UNQUALIFIED", "Unparseable derived dependency")
        if name not in names:
            names.append(name)

    if runner.which("dpkg-query") is None:
        raise NativePrerequisiteUnavailable(
            "Installed shlibs inventory requires dpkg-query; never fabricating inventory.",
            missing_tools=["dpkg-query"],
        )
    query = runner.run(
        ["dpkg-query", "-W", "-f=${binary:Package}\\t${Version}\\t${Architecture}\\n", *names], cwd=work
    )
    rows = [line.split("\t") for line in query.stdout_text.splitlines() if line.strip()]
    installed = {row[0].split(":")[0]: row for row in rows if len(row) == 3}
    if query.exit_code != 0 or any(name.split(":")[0] not in installed for name in names):
        raise ContractError("NATIVE_DEPENDENCY_DERIVATION_UNQUALIFIED",
                            "Derived dependencies are absent from the installed shlibs inventory")
    inventory = {
        "packages": [
            {"name": installed[name.split(":")[0]][0], "version": installed[name.split(":")[0]][1],
             "architecture": installed[name.split(":")[0]][2]}
            for name in names
        ],
        "query_stdout_sha256": query.stdout_sha256,
    }
    return receipt, depends, query, inventory


def _stage_native_launcher_and_desktop(
    capture: ReleaseCapture, intent: dict[str, Any], ctx: dict[str, Any],
    pkg_root: Path, install_lib: Path, install_bin: Path,
) -> None:
    """Link the released launcher as /usr/bin/tfnf and stage the desktop entry and icon."""
    project_id, payload_root = ctx["project_id"], ctx["payload_root"]
    raw = ctx["payload"].get("launchers", {}).get("tfnf", {}).get("path")
    if not raw:
        raise ContractError("MISSING_LAUNCHER", "Nebular released launcher path missing from capture payload")
    relative = raw[len(payload_root) + 1:] if raw.startswith(payload_root + "/") else raw
    validate_safe_relative_posix_path(relative)
    if not (install_lib / relative).is_file():
        raise ContractError("MISSING_LAUNCHER", "Released launcher is absent from the staged payload")
    (install_bin / "tfnf").symlink_to(f"../lib/{project_id}/{relative}")

    desktop = intent.get("desktop") or capture.record.get("desktop")
    if not desktop:
        raise ContractError("MISSING_REQUIRED_KEY", "Desktop facts required for Nebular")
    icon = capture.source.get(desktop.get("icon", {}).get("path", "src-tauri/icons/icon.png"))
    if not icon:
        raise ContractError("MISSING_ICON", "Nebular icon bytes missing from capture source")
    size = png_size(icon)
    applications = pkg_root / "usr/share/applications"
    icons = pkg_root / f"usr/share/icons/hicolor/{size}x{size}/apps"
    applications.mkdir(parents=True, exist_ok=True)
    icons.mkdir(parents=True, exist_ok=True)
    (applications / f"{project_id}.desktop").write_bytes(
        _desktop_entry(project_id, ctx["summary"], "tfnf", desktop.get("categories", ["Development"]))
    )
    (icons / f"{project_id}.png").write_bytes(icon)


def build_deb_candidate(
    capture: ReleaseCapture,
    intent: dict[str, Any],
    arch: str,
    scratch_dir: str | Path,
    *,
    maintainer: str | None = None,
    distro: str = "ubuntu-26.04",
    revision: int = 1,
    offline_npm_archives: Mapping[str, str | Path] | None = None,
    runner: CommandRunner | None = None,
) -> dict[str, Any]:
    """Build Debian candidate package for Ubuntu 26.04 and publish into candidate APT repository."""
    scratch = validate_scratch_root(scratch_dir)

    # Maintainer email must be explicitly supplied; never invent maintainer email
    valid_maintainer = validate_maintainer(maintainer)

    # Distro scope check: strictly Ubuntu 26.04 resolute
    dist_lower = (distro or "").strip().lower()
    if dist_lower in ("debian", "debian-13", "debian13", "trixie", "bookworm"):
        raise ContractError(
            "UNSUPPORTED_PLATFORM",
            "Debian is not supported; repository scope is explicitly Ubuntu 26.04",
        )
    if dist_lower not in ("ubuntu-26.04", "ubuntu 26.04", "ubuntu26.04", "resolute"):
        raise ContractError(
            "UNSUPPORTED_PLATFORM",
            f"Unsupported distribution '{distro}'; scope is Ubuntu 26.04",
        )

    ctx = validate_build_inputs(
        capture, intent, arch, adapter="debian", distro=distro
    )
    project_id = ctx["project_id"]
    version = ctx["version"]
    is_native = ctx["is_native"]
    matched_arch = ctx["arch"]

    r = runner or SubprocessRunner()
    required_tools = DEB_NATIVE_REQUIRED_TOOLS if is_native else DEB_REQUIRED_TOOLS
    missing: list[str] = []
    for tool in required_tools:
        if r.which(tool) is None:
            missing.append(tool)
    if missing:
        raise NativePrerequisiteUnavailable(
            f"Debian build prerequisites missing: {missing}. Never fabricating files.",
            missing_tools=missing,
        )

    # Setup package build staging directory in scratch root
    pkg_root = scratch / "pkg" / f"{project_id}_{version}-{revision}_{matched_arch}"
    debian_dir = pkg_root / "DEBIAN"
    debian_dir.mkdir(parents=True, exist_ok=True)

    install_lib = pkg_root / "usr/lib" / project_id
    install_bin = pkg_root / "usr/bin"
    install_lib.mkdir(parents=True, exist_ok=True)
    install_bin.mkdir(parents=True, exist_ok=True)

    from rs9.build_native import stage_payload
    payload_root = ctx["payload_root"]
    stage_payload(capture, ctx["payload"], install_lib, scratch)

    shlibdeps_receipt = None
    shlibs_receipt = None
    shlibs_inventory = None
    if is_native:
        # Every ELF object in the staged payload feeds dpkg-shlibdeps; a payload with no ELF
        # object (for example only the shell launcher) can never qualify a native package.
        elf_objects = collect_elf_inventory(pkg_root)
        if not elf_objects:
            raise ContractError("NATIVE_DEPENDENCY_DERIVATION_UNQUALIFIED",
                                "Native payload contains no ELF object for dpkg-shlibdeps derivation")
        wrong_machine = [row["path"] for row in elf_objects if row["machine"] != ELF_MACHINE[matched_arch]]
        if wrong_machine:
            raise ContractError("INVALID_ARCHITECTURE",
                                f"ELF object machine differs from deb architecture {matched_arch}")
        shlibdeps_receipt, derived_depends, shlibs_receipt, shlibs_inventory = derive_native_dependencies(
            r, scratch, pkg_root, project_id, matched_arch, valid_maintainer, elf_objects
        )
        dependency_classification = "native-tool-derived"
        _stage_native_launcher_and_desktop(capture, intent, ctx, pkg_root, install_lib, install_bin)
    else:
        cmd_dict = ctx["payload"].get("commands", {}) or intent.get("commands", {})
        for cmd_name, cmd_info in sorted(cmd_dict.items()):
            rel_bin = cmd_info["path"][len(payload_root) + 1:]
            wrapper = f'#!/bin/sh\nexec node "/usr/lib/{project_id}/{rel_bin}" "$@"\n'
            w_file = install_bin / cmd_name
            w_file.write_text(wrapper, encoding="utf-8")
            w_file.chmod(0o755)
        stage_offline_npm_closure(capture, project_id, offline_npm_archives, install_lib / "node_modules")
        # Architecture-all CLI packages must contain no ELF object anywhere, npm closure included.
        elf_objects = collect_elf_inventory(pkg_root)
        if elf_objects:
            raise ContractError("INVALID_ARCHITECTURE",
                                "Architecture-all CLI package contains an ELF object")
        derived_depends = "nodejs (>= 22)"
        dependency_classification = "reviewed-policy"

    # Render DEBIAN/control file
    control_bytes = _render_control(
        package=project_id,
        version=version,
        revision=revision,
        architecture=matched_arch,
        maintainer=valid_maintainer,
        description=ctx["summary"],
        depends=derived_depends,
    )
    (debian_dir / "control").write_bytes(control_bytes)

    # Execute dpkg-deb to build the candidate .deb package
    deb_filename = f"{project_id}_{version}-{revision}_{matched_arch}.deb"
    output_deb = scratch / deb_filename
    dpkg_deb_cmd = [
        "dpkg-deb",
        "--build",
        "--root-owner-group",
        str(pkg_root),
        str(output_deb),
    ]
    # SOURCE_DATE_EPOCH clamps member mtimes so identical staged input yields identical bytes,
    # which keeps architecture-all packages byte-equal across the amd64 and arm64 lanes.
    dpkg_deb_receipt = r.run(dpkg_deb_cmd, cwd=scratch, env={"SOURCE_DATE_EPOCH": SOURCE_DATE_EPOCH})
    if dpkg_deb_receipt.exit_code != 0:
        raise ContractError(
            "BUILD_FAILED",
            f"dpkg-deb failed with exit code {dpkg_deb_receipt.exit_code}: {dpkg_deb_receipt.stderr_text}",
        )

    if not output_deb.exists():
        raise ContractError(
            "BUILD_FAILED",
            "dpkg-deb completed but candidate .deb package file was not created",
        )

    deb_bytes = output_deb.read_bytes()
    rel_artifact_path = output_deb.relative_to(scratch).as_posix()
    validate_safe_relative_posix_path(rel_artifact_path)

    # Candidate APT repository integration:
    # Index buildable candidate DEBs (amd64, arm64, all) and validate repository.
    # Architecture-all CLI DEBs are indexed under both binary-amd64 and binary-arm64.
    repo_root = scratch / "apt_repo"
    repo = AptRepositoryCandidate(repo_root, distribution="resolute")
    deb_pkg = repo.add_package(deb_bytes=deb_bytes, deb_file_path=output_deb)
    repo_indices = repo.build_indices()
    repo_validation = validate_apt_repository(repo_root, distribution="resolute")

    primary_tool = shlibdeps_receipt if shlibdeps_receipt is not None else dpkg_deb_receipt
    extra_tools = [dpkg_deb_receipt, shlibs_receipt] if shlibdeps_receipt is not None else []

    derivation = create_derivation_record(
        artifact_relpath=rel_artifact_path,
        artifact_bytes=deb_bytes,
        tool_receipt=primary_tool,
        capture=capture,
        intent=intent,
        adapter="debian",
        arch=matched_arch,
        distro="ubuntu-26.04",
        project_id=project_id,
        version=version,
        derived_dependencies=[d.strip() for d in derived_depends.split(",") if d.strip()],
        extra_tools=extra_tools,
        dependency_classification=dependency_classification,
        extra_evidence={
            "maintainer": valid_maintainer,
            "shlibs_inventory": shlibs_inventory,
            "dpkg_shlibdeps_executed": is_native,
            "elf_objects": elf_objects,
            "apt_repository": {
                "distribution": "resolute",
                "release_sha256": repo_indices["release_sha256"],
                "packages_count": len(repo.packages),
            }
            if repo_indices
            else None,
        },
    )

    manifest = {
        "schema": "rs9.deb-candidate.v1alpha1",
        "status": "unsigned-candidate",
        "qualification": "unqualified-candidate",
        "can_publish": False,
        "adapter": "debian",
        "project": project_id,
        "version": version,
        "revision": revision,
        "architecture": matched_arch,
        "distro": "ubuntu-26.04",
        "distribution_codename": "resolute",
        "maintainer": valid_maintainer,
        "package_file": rel_artifact_path,
        "package_sha256": digest(deb_bytes),
        "package_size": len(deb_bytes),
        "dependencies": derived_depends,
        "dependency_classification": dependency_classification,
        "elf_object_count": len(elf_objects),
        "shlibs_inventory": shlibs_inventory,
        "derivation": derivation,
        "apt_repository": repo_validation,
    }

    (scratch / "deb-manifest.json").write_bytes(canonical(manifest))

    return {
        "manifest": manifest,
        "derivation_record": derivation,
        "deb_path": output_deb,
        "apt_repo_root": repo_root,
        "apt_repo": repo,
        "receipts": extra_tools,
    }


def main(argv: list[str] | None = None) -> int:
    """CLI driver for Debian candidate builder."""
    parser = argparse.ArgumentParser(description="RS9 Debian Candidate Package Driver")
    parser.add_argument(
        "--arch", required=True, help="Target architecture (amd64, arm64, or all)"
    )
    parser.add_argument("--capture", required=True, help="Path to evidence capture directory")
    parser.add_argument("--intent", required=True, help="Path to intent JSON")
    parser.add_argument("--scratch", required=True, help="Path to empty scratch directory")
    parser.add_argument(
        "--maintainer",
        required=True,
        help="Explicit maintainer (e.g. 'Maintainer Name <pkg@example.com>')",
    )
    parser.add_argument(
        "--distro", default="ubuntu-26.04", help="Target distro (default: ubuntu-26.04)"
    )
    parser.add_argument("--offline-npm", help="Path to offline npm archives JSON")
    parser.add_argument(
        "--check-prerequisites", action="store_true", help="Check tools and exit"
    )

    args = parser.parse_args(argv)

    if args.check_prerequisites:
        status = check_prerequisites("debian", DEB_NATIVE_REQUIRED_TOOLS)
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

        res = build_deb_candidate(
            capture,
            intent,
            args.arch,
            args.scratch,
            maintainer=args.maintainer,
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
