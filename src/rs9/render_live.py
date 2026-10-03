"""Deterministic RS9 LIVE1 native package recipe renderer.

Renders unsigned candidate package recipes (PKGBUILD, RPM spec, Debian control/install/rules)
for the four Theme Forge projects: Burst (0.6.1), Loom (0.4.0), Sail (0.2.1), Nebular (0.6.1).
"""

from __future__ import annotations

from pathlib import Path
import posixpath
import re
import shlex

from rs9.errors import ContractError
from rs9.profiles import png_size
from rs9.release_core import ReleaseCapture, authenticated_record_hash, digest
from rs9.scratch import ConfinedWriter, canonical
from rs9.security import validate_repository, validate_summary, validate_version_string, validate_safe_relative_posix_path
from rs9.profiles import selection_for_intent, evaluate_profile
from rs9.records import record_sha256

SUPPORTED_PROJECTS: dict[str, str] = {
    "theme-forge-stellar-burst": "0.6.1",
    "theme-forge-stellar-loom": "0.4.0",
    "theme-forge-solar-sail": "0.2.1",
    "theme-forge-nebular-fusion": "0.6.1",
}
REQUIRED_LICENSE = "AGPL-3.0-or-later"
REQUIRED_COMMANDS = {
    "theme-forge-stellar-burst": {"tfsb", "tfsb-studio-service"},
    "theme-forge-stellar-loom": {"tfsl", "tfsl-batch"},
    "theme-forge-solar-sail": {"tfss"},
    "theme-forge-nebular-fusion": {"tfnf"},
}


def _desktop_entry(project_id: str, summary: str, command: str, categories: list[str]) -> bytes:
    validate_summary(summary)
    escape = lambda s: s.replace("\\", "\\\\")
    cats = ";".join(sorted(categories)) + ";"
    return (
        f"[Desktop Entry]\nType=Application\nName=Theme Forge Nebular Fusion\n"
        f"Comment={escape(summary)}\nExec={command}\nIcon={project_id}\n"
        f"Terminal=false\nCategories={cats}\n"
    ).encode("utf-8")


def _render_pkgbuild(
    name: str, version: str, revision: int, summary: str, lic: str, asset: str,
    sha: str, deps: list[str], cmds: list[dict[str, str]], nebular: bool, root: str,
    d_sha: str = "", i_sha: str = "",
) -> bytes:
    srcs = [asset] + ([f"{name}.desktop", "icon.png"] if nebular else [])
    sums = [sha] + ([d_sha, i_sha] if nebular else [])
    src_str, sum_str = " ".join(shlex.quote(s) for s in srcs), " ".join(f"'{s}'" for s in sums)
    dep_str = " ".join(shlex.quote(d) for d in deps)
    if nebular:
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
        f"# RS9 LIVE1 unsigned candidate; publication and signing deferred.\n"
        f"# Review H2: signatures final retained identity later.\n"
        f"# Dependencies are caller-supplied; does not imply platform-qualified derivation.\n"
        f"pkgname={name}\npkgver={version}\npkgrel={revision}\npkgdesc={shlex.quote(summary)}\n"
        f"arch=('x86_64')\nurl='https://github.com/Knowledge-Forge-AI/{name}'\nlicense=('{lic}')\n"
        f"depends=({dep_str})\noptions=('!strip' '!debug' '!purge' '!zipman')\n"
        f"source=({src_str})\nsha256sums=({sum_str})\n\n"
        f"package() {{\n  local payload=\"$pkgdir/usr/lib/{name}\"\n  mkdir -p \"$payload\" \"$pkgdir/usr/bin\"\n"
        f'  cp -a "$srcdir/{root}/." "$payload/"\n{launch}\n'
        f'  install -Dm644 "$payload/LICENSE" "$pkgdir/usr/share/licenses/{name}/LICENSE"\n'
        f'  install -Dm644 "$payload/NOTICE" "$pkgdir/usr/share/licenses/{name}/NOTICE"\n}}\n'
    ).encode("utf-8")


def _render_rpm_spec(
    name: str, version: str, revision: int, summary: str, lic: str, asset: str,
    sha: str, deps: list[str], cmds: list[dict[str, str]], nebular: bool, root: str,
    d_sha: str = "", i_sha: str = "", architecture: str = "x86_64",
) -> bytes:
    validate_summary(summary)
    rpm_sum = summary.replace("%", "%%")
    reqs = "\n".join(f"Requires: {d}" for d in deps)
    srcs = f"Source0: {asset}\n" + (f"Source1: {name}.desktop\nSource2: icon.png\n" if nebular else "")
    prep_checks = f"printf '%s  %s\\n' '{sha}' '%{{SOURCE0}}' | sha256sum -c -\n" + (
        f"printf '%s  %s\\n' '{d_sha}' '%{{SOURCE1}}' | sha256sum -c -\nprintf '%s  %s\\n' '{i_sha}' '%{{SOURCE2}}' | sha256sum -c -\n"
        if nebular else ""
    )
    if nebular:
        install_launch = (
            f"ln -s '/usr/lib/{name}/{cmds[0]['path']}' '%{{buildroot}}/usr/bin/{cmds[0]['name']}'\n"
            f"install -Dm644 '%{{SOURCE1}}' '%{{buildroot}}/usr/share/applications/{name}.desktop'\n"
            f"install -Dm644 '%{{SOURCE2}}' '%{{buildroot}}/usr/share/icons/hicolor/256x256/apps/{name}.png'\n"
        )
        files_extra = f"/usr/share/applications/{name}.desktop\n/usr/share/icons/hicolor/256x256/apps/{name}.png\n"
    else:
        install_launch = "\n".join(
            f"cat << 'EOF' > '%{{buildroot}}/usr/bin/{c['name']}'\n#!/bin/sh\nexec node \"/usr/lib/{name}/{c['path']}\" \"$@\"\nEOF\nchmod 0755 '%{{buildroot}}/usr/bin/{c['name']}'"
            for c in cmds
        ) + "\n"
        files_extra = ""
    cmd_files = "\n".join(f"/usr/bin/{c['name']}" for c in cmds)
    return (
        f"# RS9 LIVE1 unsigned candidate; publication and license acceptance deferred.\n"
        f"# Review H2: signatures final retained identity later.\n"
        f"# Dependencies are caller-supplied; does not imply platform-qualified derivation.\n"
        f"%global debug_package %{{nil}}\n%global __strip /bin/true\n%undefine __brp_mangle_shebangs\n"
        f"%global _build_id_links none\n%global __os_install_post %{{nil}}\n"
        f"Name: {name}\nVersion: {version}\nRelease: {revision}%{{?dist}}\nSummary: {rpm_sum}\n"
        f"License: {lic}\nURL: https://github.com/Knowledge-Forge-AI/{name}\nExclusiveArch: {architecture}\n"
        f"{srcs}{reqs}\n\n%description\n{rpm_sum}\n\n%prep\n{prep_checks}\n"
        f"%setup -q -c -n %{{name}}-%{{version}}\n\n%build\n# Precompiled; no payload transformations.\n\n"
        f"%install\nmkdir -p '%{{buildroot}}/usr/lib/{name}' '%{{buildroot}}/usr/bin'\n"
        f"cp -a {root}/. '%{{buildroot}}/usr/lib/{name}/'\n{install_launch}\n"
        f"%files\n%license {root}/LICENSE\n%license {root}/NOTICE\n/usr/lib/{name}\n{cmd_files}\n{files_extra}"
    ).encode("utf-8")


def render_live(
    capture: ReleaseCapture,
    intent: dict,
    output_dir: str | Path | None = None,
    *,
    adapter: str,
    architecture: str,
    revision: int = 1,
    dependencies: list[str] | dict,
    distro: str,
) -> dict:
    """Render deterministic RS9 LIVE1 package recipes from sealed byte evidence."""
    authenticated_record_hash(capture)

    adapter_norm, distro_norm = adapter.strip().lower(), distro.strip().lower()
    if adapter_norm in ("pacman", "arch"):
        target_adapter = "pacman"
        if distro_norm not in ("arch", "archlinux"):
            raise ContractError("UNSUPPORTED_PLATFORM", 'Invalid candidate input or unavailable candidate operation')
    elif adapter_norm in ("dnf", "rpm", "fedora"):
        target_adapter = "rpm"
        if not (distro_norm.startswith("fedora") or distro_norm.startswith("fc")):
            raise ContractError("UNSUPPORTED_PLATFORM", 'Invalid candidate input or unavailable candidate operation')
    elif adapter_norm in ("debian", "apt", "ubuntu"):
        target_adapter = "debian"
        if distro_norm not in ("ubuntu-26.04", "ubuntu 26.04", "ubuntu26.04"):
            raise ContractError("UNSUPPORTED_PLATFORM", 'Invalid candidate input or unavailable candidate operation')
    else:
        raise ContractError("UNSUPPORTED_PLATFORM", 'Invalid candidate input or unavailable candidate operation')
    coverage = {"pacman": {"x86_64"}, "rpm": {"x86_64", "aarch64"}, "debian": {"amd64", "arm64"}}
    if architecture not in coverage[target_adapter]:
        raise ContractError("UNSUPPORTED_PLATFORM", "Unsupported adapter architecture")
    if target_adapter == "rpm" and not re.fullmatch(r"(?:fedora[- ]?|fc)\d+", distro_norm):
        raise ContractError("UNSUPPORTED_PLATFORM", "An explicit Fedora family is required")
    if target_adapter == "debian":
        raise ContractError("APT_RECIPE_UNQUALIFIED", "Ubuntu 26.04 package recipe requires a qualified native builder; rendering withheld")

    proj_val = intent.get("project")
    project_id = proj_val.get("id", "") if isinstance(proj_val, dict) else intent.get("project_id", "")
    if not isinstance(project_id, str) or not re.fullmatch(r"[a-z0-9][a-z0-9+._-]*", project_id):
        raise ContractError("RENDER_VALUE", "Unsafe project identifier")
    if project_id not in SUPPORTED_PROJECTS:
        raise ContractError("UNSUPPORTED_PROJECT", 'Invalid candidate input or unavailable candidate operation')

    version = intent.get("version", "")
    validate_version_string(version)
    if version != SUPPORTED_PROJECTS[project_id]:
        raise ContractError("UNSUPPORTED_VERSION", 'Invalid candidate input or unavailable candidate operation')

    repo = proj_val.get("repository", "") if isinstance(proj_val, dict) else intent.get("repository", "")
    validate_repository(repo)
    if capture.record["repository"]["full_name"] != repo:
        raise ContractError("REPOSITORY_MISMATCH", "Capture repository does not match intent")
    if capture.record["release"]["tag"] != intent.get("tag", f"v{version}"):
        raise ContractError("TAG_MISMATCH", "Capture release tag does not match intent")

    lic_val = intent.get("license")
    lic_expr = lic_val.get("expression", "") if isinstance(lic_val, dict) else (intent.get("license_expression") or intent.get("license", ""))
    if lic_expr != REQUIRED_LICENSE:
        raise ContractError("UNSUPPORTED_LICENSE", 'Invalid candidate input or unavailable candidate operation')

    if capture.record["selection_sha256"] != record_sha256(selection_for_intent(intent)):
        raise ContractError("SELECTION_MISMATCH", "Capture selection digest disagrees with intent")
    profile = evaluate_profile(capture, intent["release"]["evidence"]["profile"], intent)
    licence = profile["sections"].get("license", profile["sections"].get("legacy_ingestion", {}).get("license"))
    if licence["status"] != "consistent":
        raise ContractError("LICENSE_AUTHORITY", "Tagged repository licensing conflicts with candidate metadata")
    if type(revision) is not int or not 1 <= revision <= 999999:
        raise ContractError("RENDER_VALUE", "Package revision must be a bounded positive integer")

    matched_payload = None
    for p in capture.record.get("payloads", []):
        plats = p.get("platforms", ["any"])
        system = ("aarch64-linux" if architecture in {"aarch64", "arm64"} else "x86_64-linux")
        if system in plats or "any" in plats:
            matched_payload = p
            break
    if not matched_payload:
        raise ContractError("UNSUPPORTED_PLATFORM", 'Invalid candidate input or unavailable candidate operation')

    for p in capture.record.get("payloads", []):
        f = capture.archives.get(p.get("id")) or (capture.root / "assets" / p["name"])
        if not Path(f).exists():
            raise ContractError("INPUT_CHANGED", 'Invalid candidate input or unavailable candidate operation')
        actual = digest(Path(f).read_bytes())
        if actual != p["sha256"]:
            raise ContractError("INPUT_CHANGED", 'Invalid candidate input or unavailable candidate operation')

    asset_name = posixpath.basename(matched_payload["name"])
    asset_sha = matched_payload["sha256"]
    asset_file = capture.archives.get(matched_payload.get("id")) or (capture.root / "assets" / asset_name)
    asset_bytes = Path(asset_file).read_bytes()

    payload_root = matched_payload.get("root", "package")
    is_nebular = project_id == "theme-forge-nebular-fusion"
    summary = proj_val.get("summary", "Theme Forge release package")
    validate_summary(summary)

    if is_nebular:
        launchers, commands = matched_payload.get("launchers", {}), matched_payload.get("commands", {})
        l_raw = launchers.get("tfnf", {}).get("path")
        if not l_raw:
            raise ContractError("MISSING_LAUNCHER", "Nebular released launcher path missing from capture payload")
        l_rel = l_raw[len(payload_root) + 1:] if l_raw.startswith(payload_root + "/") else l_raw
        cmd_list = [{"name": "tfnf", "path": l_rel}]

        desktop_info = intent.get("desktop") or capture.record.get("desktop")
        if not desktop_info:
            raise ContractError("MISSING_REQUIRED_KEY", "Desktop facts required for Nebular")
        icon_path = desktop_info.get("icon", {}).get("path", "src-tauri/icons/icon.png")
        icon_bytes = capture.source.get(icon_path)
        if not icon_bytes:
            raise ContractError("MISSING_ICON", 'Invalid candidate input or unavailable candidate operation')
        png_size(icon_bytes)
        desktop_bytes = _desktop_entry(project_id, summary, "tfnf", desktop_info.get("categories", ["Development"]))
        desktop_sha, icon_sha = digest(desktop_bytes), digest(icon_bytes)
    else:
        cmd_dict = matched_payload.get("commands", {}) or intent.get("commands", {})
        cmd_list = [
            {"name": k, "path": v["path"][len(payload_root) + 1:]}
            for k, v in sorted(cmd_dict.items())
        ]
        desktop_bytes = icon_bytes = None
        desktop_sha = icon_sha = ""

    if project_id == "theme-forge-stellar-burst":
        raise ContractError("BURST_CLOSURE_MISSING", "Authenticated Burst dependency staging is not yet integrated; rendering withheld")

    if dependencies is None or not dependencies:
        raise ContractError("MISSING_DEPENDENCIES", "Explicit dependencies required; fail closed")
    raw_deps = (dependencies.get(target_adapter) or dependencies.get(adapter_norm)) if isinstance(dependencies, dict) else dependencies
    if isinstance(raw_deps, dict):
        raw_deps = raw_deps.get(distro)
    if not raw_deps or not isinstance(raw_deps, (list, tuple, set)):
        raise ContractError("MISSING_DEPENDENCIES", "Explicit dependencies required; fail closed")
    deps_list = sorted(str(d).strip() for d in raw_deps if str(d).strip())
    if any(not re.fullmatch(r"[A-Za-z0-9_+.,()>=<| -]+", dep) for dep in deps_list):
        raise ContractError("DEPENDENCY_VALUE", "Dependency contains unsafe recipe content")
    for command in cmd_list:
        if not re.fullmatch(r"[A-Za-z0-9_-]+", command["name"]):
            raise ContractError("COMMAND_VALUE", "Unsafe command name")
        validate_safe_relative_posix_path(command["path"])
        if not re.fullmatch(r"[A-Za-z0-9_+./ -]+", command["path"]):
            raise ContractError("COMMAND_VALUE", "Unsafe command path")
    if {command["name"] for command in cmd_list} != REQUIRED_COMMANDS[project_id]:
        raise ContractError("COMMAND_VALUE", "Current generation requires every authoritative product command")
    if not deps_list:
        raise ContractError("MISSING_DEPENDENCIES", "Explicit dependencies list is empty; fail closed")

    if not is_nebular:
        node_pattern = r"nodejs\s*>=\s*(\d+)(?:\.\d+)*" if target_adapter == "rpm" else (
            r"nodejs>=([0-9]+)(?:\.[0-9]+)*" if target_adapter == "pacman" else r"nodejs \(>= ([0-9]+)(?:\.[0-9]+)*\)")
        matches = [re.fullmatch(node_pattern, dependency) for dependency in deps_list]
        if not any(match and int(match.group(1)) >= 22 for match in matches):
            raise ContractError("MISSING_DEPENDENCIES", "CLI projects require an ecosystem-valid Node >=22 dependency")

    files: dict[str, bytes] = {}
    if target_adapter == "pacman":
        files[f"pacman/{project_id}/PKGBUILD"] = _render_pkgbuild(
            project_id, version, revision, summary, lic_expr, asset_name, asset_sha,
            deps_list, cmd_list, is_nebular, payload_root, desktop_sha, icon_sha,
        )
        files[f"pacman/{project_id}/{asset_name}"] = asset_bytes
        if is_nebular and desktop_bytes and icon_bytes:
            files[f"pacman/{project_id}/{project_id}.desktop"] = desktop_bytes
            files[f"pacman/{project_id}/icon.png"] = icon_bytes
    elif target_adapter == "rpm":
        files[f"rpm/{project_id}.spec"] = _render_rpm_spec(
            project_id, version, revision, summary, lic_expr, asset_name, asset_sha,
            deps_list, cmd_list, is_nebular, payload_root, desktop_sha, icon_sha, architecture=architecture,
        )
        files[f"rpm/{asset_name}"] = asset_bytes
        if is_nebular and desktop_bytes and icon_bytes:
            files[f"rpm/{project_id}.desktop"] = desktop_bytes
            files[f"rpm/icon.png"] = icon_bytes

    manifest = {
        "schema": "rs9.live-render.v1alpha1",
        "status": "unsigned-candidate",
        "review": "H2",
        "signing": "retained-identity-deferred",
        "signatures": "retained-identity-deferred",
        "verdict": "candidate",
        "project": project_id,
        "version": version,
        "license": lic_expr,
        "adapter": target_adapter,
        "architecture": architecture,
        "distro": distro,
        "revision": revision,
        "dependencies": deps_list,
        "dependency_derivation": "unqualified-caller-supplied",
        "platform_qualification": "none",
        "can_publish": False,
        "native_preservation": {"strip": False, "debug": False, "mangle_shebangs": False, "build_id": False},
        "files": [{"path": p, "size": len(b), "sha256": digest(b)} for p, b in sorted(files.items())],
    }
    if output_dir is not None:
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)
        with ConfinedWriter(out_path) as writer:
            for p, b in sorted(files.items()):
                writer.write(p, b)
            writer.write("render-manifest.json", canonical(manifest))

    manifest["rendered"] = files
    return manifest
