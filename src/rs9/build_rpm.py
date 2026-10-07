"""Normal-tool native package candidate driver for RPM (Fedora 43 x86_64, aarch64, noarch).

Executes real host rpmbuild, rpm, rpmlint, and createrepo:
- Preserves native binaries: no strip, no debug package, no shebang mangling, no build-id links.
- Collects actual RPM v6 package identities and rpmlint receipts.
- Generates repository metadata using createrepo gzip --no-database.
- Pure JS CLI projects enforce arch 'noarch' with authenticated offline npm closure.
- Native Node CLI and native desktop products enforce arch 'x86_64' or 'aarch64'.
- Native prerequisites absent -> explicit unavailable, never fabricated files.
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
    validate_scratch_root,
)
from rs9.errors import ContractError
from rs9.profiles import png_size
from rs9.release_core import ReleaseCapture, digest
from rs9.scratch import canonical, physical_directory
from rs9.security import validate_safe_relative_posix_path

from rs9.rpm_query import (
    RPM_EXPECTED_ARCHITECTURES,
    _safe_observed_token,
    query_rpm_package,
    rpm_isolation_args,
    read_rpm_identity,
)


RPM_REQUIRED_TOOLS = ["rpmbuild", "rpm", "rpmlint"]
CREATEREPO_CANDIDATES = ["createrepo_c", "createrepo"]


def _find_createrepo(runner: CommandRunner) -> str | None:
    for candidate in CREATEREPO_CANDIDATES:
        if runner.which(candidate) is not None:
            return candidate
    return None


def _render_rpm_spec(
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
    is_native_node: bool = False,
) -> bytes:
    rpm_sum = summary.replace("%", "%%")
    reqs = "\n".join(f"Requires: {d}" for d in deps)
    srcs = f"Source0: {asset}\n" + (
        f"Source1: {name}.desktop\nSource2: icon.png\n" if is_nebular else ""
    )
    prep_checks = f"printf '%s  %s\\n' '{sha}' '%{{SOURCE0}}' | sha256sum -c -\n" + (
        f"printf '%s  %s\\n' '{d_sha}' '%{{SOURCE1}}' | sha256sum -c -\n"
        f"printf '%s  %s\\n' '{i_sha}' '%{{SOURCE2}}' | sha256sum -c -\n"
        if is_nebular
        else ""
    )

    if is_nebular:
        install_launch = (
            f"ln -s '/usr/lib/{name}/{cmds[0]['path']}' '%{{buildroot}}/usr/bin/{cmds[0]['name']}'\n"
            f"install -Dm644 '%{{SOURCE1}}' '%{{buildroot}}/usr/share/applications/{name}.desktop'\n"
            f"install -Dm644 '%{{SOURCE2}}' '%{{buildroot}}/usr/share/icons/hicolor/256x256/apps/{name}.png'\n"
        )
        files_extra = f"/usr/share/applications/{name}.desktop\n/usr/share/icons/hicolor/256x256/apps/{name}.png\n"
    else:
        install_launch = (
            "\n".join(
                f"cat << 'EOF' > '%{{buildroot}}/usr/bin/{c['name']}'\n#!/bin/sh\nexec node \"/usr/lib/{name}/{c['path']}\" \"$@\"\nEOF\nchmod 0755 '%{{buildroot}}/usr/bin/{c['name']}'"
                for c in cmds
            )
            + "\n"
        )
        files_extra = ""

    cmd_files = "\n".join(f"/usr/bin/{c['name']}" for c in cmds)
    arch_line = f"BuildArch: noarch" if arch == "noarch" else f"ExclusiveArch: {arch}"
    f2_excludes = ""
    if is_native_node:
        from rs9.burst_native import BURST_CLOSED_PREBUILDS
        from rs9.hosted_platforms import platform_contract
        from rs9.product_classes import packaging_system_for_arch
        target_key = platform_contract(packaging_system_for_arch("rpm", arch)).native_prebuild_key
        # RPM uses POSIX ERE. Exclude only the three authenticated foreign files;
        # the target prebuild remains subject to normal dependency generation.
        foreign_paths = ["/usr/lib/" + name + "/" + path.removeprefix("package/")
                         for key, path in sorted(BURST_CLOSED_PREBUILDS.items()) if key != target_key]
        pattern = "^(" + "|".join(re.escape(path) for path in foreign_paths) + ")$"
        f2_excludes = (f"%global __requires_exclude_from {pattern}\n"
                       f"%global __provides_exclude_from {pattern}\n")

    return (
        f"# RS9 LIVE1 RPM spec candidate from exact authenticated release capture.\n"
        f"# Publication and signing deferred.\n"
        f"%global debug_package %{{nil}}\n"
        f"%global __strip /bin/true\n"
        f"%undefine __brp_mangle_shebangs\n"
        f"%global _build_id_links none\n"
        f"%global __os_install_post %{{nil}}\n"
        f"{f2_excludes}"
        f"Name: {name}\n"
        f"Version: {version}\n"
        f"Release: {revision}%{{?dist}}\n"
        f"Summary: {rpm_sum}\n"
        f"License: {lic}\n"
        f"URL: https://github.com/Knowledge-Forge-AI/{name}\n"
        f"{arch_line}\n"
        f"{srcs}"
        f"{reqs}\n\n"
        f"%description\n{rpm_sum}\n\n"
        f"%prep\n{prep_checks}\n"
        f"%setup -q -c -n %{{name}}-%{{version}}\n\n"
        f"%build\n# Precompiled candidate payload; no transformations.\n\n"
        f"%install\n"
        f"mkdir -p '%{{buildroot}}/usr/lib/{name}' '%{{buildroot}}/usr/bin'\n"
        f"cp -a {root}/. '%{{buildroot}}/usr/lib/{name}/'\n"
        f"{install_launch}\n"
        f"%files\n"
        f"%license {root}/LICENSE\n"
        f"%license {root}/NOTICE\n"
        f"/usr/lib/{name}\n"
        f"{cmd_files}\n"
        f"{files_extra}"
    ).encode("utf-8")


def _desktop_entry(project_id: str, summary: str, command: str, categories: list[str]) -> bytes:
    escape = lambda s: s.replace("\\", "\\\\")
    cats = ";".join(sorted(categories)) + ";"
    return (
        f"[Desktop Entry]\nType=Application\nName=Theme Forge Nebular Fusion\n"
        f"Comment={escape(summary)}\nExec={command}\nIcon={project_id}\n"
        f"Terminal=false\nCategories={cats}\n"
    ).encode("utf-8")


def build_rpm_candidate(
    capture: ReleaseCapture,
    intent: dict[str, Any],
    arch: str,
    scratch_dir: str | Path,
    *,
    distro: str = "fedora-43",
    revision: int = 1,
    offline_npm_archives: Mapping[str, str | Path] | None = None,
    runner: CommandRunner | None = None,
) -> dict[str, Any]:
    """Build Fedora 43 RPM candidate package using real rpmbuild, rpmlint, and createrepo."""
    scratch = validate_scratch_root(scratch_dir)

    ctx = validate_build_inputs(
        capture, intent, arch, adapter="rpm", distro=distro
    )
    project_id = ctx["project_id"]
    version = ctx["version"]
    is_native = ctx["is_native"]
    matched_arch = ctx["arch"]

    r = runner or SubprocessRunner()

    createrepo_tool = _find_createrepo(r)
    required = list(RPM_REQUIRED_TOOLS)
    if createrepo_tool is None:
        required.append("createrepo_c")

    missing: list[str] = []
    for tool in required:
        if r.which(tool) is None:
            missing.append(tool)
    if missing:
        raise NativePrerequisiteUnavailable(
            f"RPM build prerequisites missing: {missing}. Never fabricating files.",
            missing_tools=missing,
        )

    createrepo_bin = createrepo_tool or "createrepo_c"

    # Setup standard RPM build tree in scratch root
    rpm_topdir = scratch / "rpmbuild"
    for subdir in ("BUILD", "RPMS", "SOURCES", "SPECS", "SRPMS"):
        (rpm_topdir / subdir).mkdir(parents=True, exist_ok=True)

    repo_dir = scratch / "repo" / matched_arch
    repo_dir.mkdir(parents=True, exist_ok=True)

    # Copy source asset into SOURCES
    asset_name = ctx["asset_name"]
    source0 = rpm_topdir / "SOURCES" / asset_name
    source0.write_bytes(ctx["asset_bytes"])

    desktop_bytes = icon_bytes = None
    desktop_sha = icon_sha = ""
    cmds: list[dict[str, str]] = []

    is_native_desktop = ctx.get("is_native_desktop", False)
    is_native_node_cli = ctx.get("is_native_node_cli", False)
    is_pure_js_cli = ctx.get("is_pure_js_cli", not is_native)

    if is_native_desktop:
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

        (rpm_topdir / "SOURCES" / f"{project_id}.desktop").write_bytes(desktop_bytes)
        (rpm_topdir / "SOURCES" / "icon.png").write_bytes(icon_bytes)

        # Derive ELF dependencies from released payload asset
        from rs9.dependencies import INTERPRETERS, LIBRARIES, shebang
        from rs9.elf import parse_elf
        import tarfile

        elf_objects = []
        scripts = []
        system_sonames = set()
        fedora_packages = set()

        with tarfile.open(ctx["asset_file"], "r:*") as tar:
            for member in tar.getmembers():
                if member.isfile():
                    f = tar.extractfile(member)
                    if f is not None:
                        data = f.read()
                        if data.startswith(b"\x7fELF"):
                            elf_info = parse_elf(data)
                            elf_objects.append({
                                "path": member.name,
                                "needed": elf_info["needed"],
                                "interpreter": elf_info.get("interpreter"),
                            })
                            for soname in elf_info["needed"]:
                                system_sonames.add(soname)
                                if soname in LIBRARIES:
                                    fedora_packages.add(LIBRARIES[soname][1])
                            interp = elf_info.get("interpreter")
                            if interp in {"/lib64/ld-linux-x86-64.so.2", "/lib/ld-linux-aarch64.so.1"}:
                                fedora_packages.add("glibc")
                        elif data.startswith(b"#!") and (member.mode & 0o111):
                            sh_info = shebang(data)
                            if sh_info and sh_info.get("interpreter"):
                                interp_name = sh_info["interpreter"]
                                scripts.append({"path": member.name, "interpreter": interp_name})
                                if interp_name in INTERPRETERS:
                                    fedora_packages.add(INTERPRETERS[interp_name][1])

        if not elf_objects:
            raise ContractError("NO_ELF_OBJECTS", "Native package contains no ELF binaries")

        derived_deps = sorted(fedora_packages)
        dependency_classification = "native-tool-derived"
    elif is_native_node_cli:
        # Native node CLI (Burst): stage offline authenticated npm closure
        payload_root = ctx["payload_root"]
        cmd_dict = ctx["payload"].get("commands", {}) or intent.get("commands", {})
        cmds = [
            {"name": k, "path": v["path"][len(payload_root) + 1:]}
            for k, v in sorted(cmd_dict.items())
        ]
        staged_nm = rpm_topdir / "staged_node_modules"
        stage_offline_npm_closure(capture, project_id, offline_npm_archives, staged_nm)
        from rs9.build_native import npm_bundle
        closure_sha = npm_bundle(staged_nm, rpm_topdir / "SOURCES/npm-closure.tar.gz")

        # Dependency derivation strictly targets matching prebuild; foreign exact closed prebuilds remain inert
        target_prebuild_path = (
            ctx.get("burst_prebuild_info", {}).get("target_path")
            if ctx.get("burst_prebuild_info")
            else (
                "package/native/directory-snapshot/prebuilds/linux-x64-gnu/native-addon-posix-openat-v1.node"
                if matched_arch == "x86_64"
                else "package/native/directory-snapshot/prebuilds/linux-arm64-gnu/native-addon-posix-openat-v1.node"
            )
        )
        from rs9.dependencies import LIBRARIES
        from rs9.elf import parse_elf
        import tarfile

        elf_objects = []
        system_sonames = set()
        fedora_packages = {"nodejs >= 22"}

        with tarfile.open(ctx["asset_file"], "r:*") as tar:
            found_target = False
            for member in tar.getmembers():
                if member.isfile() and (member.name == target_prebuild_path or member.name.endswith("/" + target_prebuild_path) or target_prebuild_path.endswith(member.name)):
                    found_target = True
                    f = tar.extractfile(member)
                    if f is not None:
                        data = f.read()
                        if data.startswith(b"\x7fELF"):
                            elf_info = parse_elf(data)
                            elf_objects.append({
                                "path": member.name,
                                "needed": elf_info["needed"],
                                "interpreter": elf_info.get("interpreter"),
                            })
                            for soname in elf_info["needed"]:
                                system_sonames.add(soname)
                                if soname in LIBRARIES:
                                    fedora_packages.add(LIBRARIES[soname][1])
                            interp = elf_info.get("interpreter")
                            if interp in {"/lib64/ld-linux-x86-64.so.2", "/lib/ld-linux-aarch64.so.1"}:
                                fedora_packages.add("glibc")
            if not found_target or not elf_objects:
                raise ContractError("MISSING_ASSET", f"Matching native prebuild missing from tarball: {target_prebuild_path}")

        derived_deps = sorted(fedora_packages)
        dependency_classification = "native-tool-derived"
    else:
        # Pure JS CLI projects: stage offline authenticated npm closure; pure JS retain no native checks
        payload_root = ctx["payload_root"]
        cmd_dict = ctx["payload"].get("commands", {}) or intent.get("commands", {})
        cmds = [
            {"name": k, "path": v["path"][len(payload_root) + 1:]}
            for k, v in sorted(cmd_dict.items())
        ]
        staged_nm = rpm_topdir / "staged_node_modules"
        stage_offline_npm_closure(capture, project_id, offline_npm_archives, staged_nm)
        from rs9.build_native import npm_bundle
        closure_sha = npm_bundle(staged_nm, rpm_topdir / "SOURCES/npm-closure.tar.gz")

        derived_deps = ["nodejs >= 22"]
        dependency_classification = "reviewed-policy"

    # Render RPM spec file
    spec_bytes = _render_rpm_spec(
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
        is_native_desktop,
        ctx["payload_root"],
        desktop_sha,
        icon_sha,
        is_native_node=is_native_node_cli,
    )
    spec_path = rpm_topdir / "SPECS" / f"{project_id}.spec"
    if not is_native_desktop:
        text = spec_bytes.decode()
        text = text.replace("Source0:", "Source3: npm-closure.tar.gz\nSource0:", 1)
        text = text.replace("%build\n", "printf '%s  %s\\n' '" + closure_sha + "' '%{SOURCE3}' | sha256sum -c -\ntar -xzf '%{SOURCE3}'\n\n%build\n", 1)
        text = text.replace("%files\n", "cp -a node_modules '%{buildroot}/usr/lib/" + project_id + "/node_modules'\n\n%files\n", 1)
        spec_bytes = text.encode()
    spec_path.write_bytes(spec_bytes)

    # Execute rpmbuild with preservation defines
    rpmbuild_cmd = [
        "rpmbuild",
        "-ba",
        str(spec_path),
        "--define",
        f"_topdir {rpm_topdir}",
        "--define",
        "debug_package %{nil}",
        "--define",
        "__strip /bin/true",
        "--define",
        "_build_id_links none",
        "--define",
        "__os_install_post %{nil}",
        "--undefine",
        "__brp_mangle_shebangs",
    ]
    rpmbuild_receipt = r.run(rpmbuild_cmd, cwd=rpm_topdir)
    if rpmbuild_receipt.exit_code != 0:
        raise ContractError(
            "BUILD_FAILED",
            f"rpmbuild failed with exit code {rpmbuild_receipt.exit_code}: {rpmbuild_receipt.stderr_text}",
        )

    # Locate built RPM in RPMS/<arch>
    rpm_search_dir = rpm_topdir / "RPMS" / matched_arch
    built_rpms = (
        list(rpm_search_dir.glob("*.rpm"))
        if rpm_search_dir.exists()
        else list((rpm_topdir / "RPMS").rglob("*.rpm"))
    )
    if not built_rpms:
        raise ContractError(
            "BUILD_FAILED",
            "rpmbuild completed but no candidate RPM file was found in RPMS",
        )

    rpm_file = built_rpms[0]
    rpm_bytes = rpm_file.read_bytes()
    dest_rpm = repo_dir / rpm_file.name
    dest_rpm.write_bytes(rpm_bytes)

    # Collect actual RPM package identity and payload digest separately (Option B)
    query_db, query_keyring = scratch / "query-rpmdb", scratch / "query-keyring"
    query_db.mkdir(exist_ok=True)
    query_keyring.mkdir(exist_ok=True)
    rpm_identity, rpm_payload_digest, query_receipts = query_rpm_package(
        r,
        dest_rpm,
        product=project_id,
        version=version,
        architecture=matched_arch,
        revision=revision,
        cwd=scratch,
        dbpath=query_db, keyring="rpmdb", keyringpath=query_keyring,
    )
    rpm_requires_receipt = None
    if is_native:
        rpm_requires_cmd = [
            "rpm",
            *rpm_isolation_args(dbpath=query_db, keyring="rpmdb", keyringpath=query_keyring),
            "-qp",
            "--requires",
            str(dest_rpm),
        ]
        rpm_requires_receipt = r.run(rpm_requires_cmd, cwd=scratch)
        if (rpm_requires_receipt.exit_code or rpm_requires_receipt.stderr_bytes
                or not rpm_requires_receipt.stdout_text.strip()):
            raise ContractError("DEPENDENCY_DERIVATION", "Actual RPM requirement readback required")
        policy_dependencies = list(derived_deps)
        derived_deps = sorted(set(rpm_requires_receipt.stdout_text.splitlines()))
        if is_native_node_cli:
            allowed_sonames = set(system_sonames)
            for requirement in derived_deps:
                base = requirement.split("(", 1)[0]
                if not (base in allowed_sonames or base == "rtld"
                        or requirement.startswith("rpmlib(")
                        or requirement in {"/bin/sh", "/usr/bin/env"}
                        or re.fullmatch(r"nodejs(?:\s*(?:>=|=)\s*[0-9][0-9.]*)?", requirement)
                        or requirement in policy_dependencies):
                    raise ContractError("DEPENDENCY_DERIVATION", "RPM requirement lies outside the target prebuild closure")

    # Execute rpmlint with structured evidence and fail-closed validation
    from rs9.rpm_lint import execute_rpmlint

    rpmlint_evidence, rpmlint_receipts = execute_rpmlint(
        runner=r,
        spec_path=spec_path,
        rpm_path=dest_rpm,
        product=project_id,
        rpm_identity=rpm_identity,
        rpm_payload_digest=rpm_payload_digest,
        cwd=scratch,
    )
    rpmlint_receipt = rpmlint_receipts[0]

    # Execute createrepo gzip --no-database
    createrepo_cmd = [
        createrepo_bin,
        "--no-database",
        "--compress-type",
        "gz",
        "-s",
        "sha256",
        str(scratch / "repo"),
    ]
    createrepo_receipt = r.run(createrepo_cmd, cwd=scratch)
    if createrepo_receipt.exit_code != 0:
        raise ContractError(
            "BUILD_FAILED",
            f"{createrepo_bin} failed with exit code {createrepo_receipt.exit_code}: {createrepo_receipt.stderr_text}",
        )

    rel_artifact_path = dest_rpm.relative_to(scratch).as_posix()
    validate_safe_relative_posix_path(rel_artifact_path)

    extra_tools = list(query_receipts)
    if rpm_requires_receipt is not None:
        extra_tools.append(rpm_requires_receipt)
    extra_tools.extend([rpmlint_receipt, createrepo_receipt])

    extra_ev: dict[str, Any] = {
        "rpm_identity": rpm_identity,
        "rpm_payload_digest": rpm_payload_digest,
        "rpmlint_status": "executed",
        "rpmlint_exit_code": rpmlint_receipt.exit_code,
        "rpmlint": rpmlint_evidence,
        "createrepo_flags": ["--no-database", "gzip"],
        "native_preservation": {
            "strip": False,
            "debug": False,
            "mangle_shebangs": False,
            "build_id": False,
        },
    }
    if is_native:
        extra_ev["policy_dependencies"] = policy_dependencies
        extra_ev["elf_dependencies"] = {
            "objects": elf_objects,
            "system_sonames": sorted(system_sonames),
            "derived_packages": derived_deps,
        }
        if rpm_requires_receipt is not None:
            extra_ev["rpm_query_evidence"] = {
                "requires": [
                    line.strip()
                    for line in rpm_requires_receipt.stdout_text.splitlines()
                    if line.strip()
                ],
            }

    derivation = create_derivation_record(
        artifact_relpath=rel_artifact_path,
        artifact_bytes=rpm_bytes,
        tool_receipt=rpmbuild_receipt,
        capture=capture,
        intent=intent,
        adapter="rpm",
        arch=matched_arch,
        distro=distro,
        project_id=project_id,
        version=version,
        derived_dependencies=derived_deps,
        extra_tools=extra_tools,
        extra_evidence=extra_ev,
        dependency_classification=dependency_classification,
    )

    manifest = {
        "schema": "rs9.rpm-candidate.v1alpha2",
        "status": "unsigned-candidate",
        "qualification": "unqualified-candidate",
        "can_publish": False,
        "adapter": "rpm",
        "package_class": ctx["product_class"],
        "project": project_id,
        "version": version,
        "revision": revision,
        "architecture": matched_arch,
        "distro": distro,
        "package_file": rel_artifact_path,
        "package_sha256": digest(rpm_bytes),
        "package_size": len(rpm_bytes),
        "dependencies": derived_deps,
        "dependency_classification": dependency_classification,
        "rpm_identity": rpm_identity,
        "rpm_payload_digest": rpm_payload_digest,
        "rpmlint": rpmlint_evidence,
        "derivation": derivation,
    }

    (scratch / "rpm-manifest.json").write_bytes(canonical(manifest))

    return {
        "manifest": manifest,
        "derivation_record": derivation,
        "rpm_path": dest_rpm,
        "repo_dir": scratch / "repo",
        "receipts": [
            rpmbuild_receipt,
            *query_receipts,
            rpmlint_receipt,
            createrepo_receipt,
        ],
    }


def main(argv: list[str] | None = None) -> int:
    """CLI driver for RPM candidate builder."""
    parser = argparse.ArgumentParser(description="RS9 RPM Candidate Package Driver")
    parser.add_argument(
        "--arch", required=True, help="Target architecture (x86_64, aarch64, or noarch)"
    )
    parser.add_argument("--capture", required=True, help="Path to evidence capture directory")
    parser.add_argument("--intent", required=True, help="Path to intent JSON")
    parser.add_argument("--scratch", required=True, help="Path to empty scratch directory")
    parser.add_argument("--distro", default="fedora-43", help="Target distro (default: fedora-43)")
    parser.add_argument("--offline-npm", help="Path to offline npm archives JSON")
    parser.add_argument(
        "--check-prerequisites", action="store_true", help="Check tools and exit"
    )

    args = parser.parse_args(argv)

    if args.check_prerequisites:
        status = check_prerequisites("rpm", RPM_REQUIRED_TOOLS)
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

        res = build_rpm_candidate(
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
