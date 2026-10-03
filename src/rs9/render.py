"""Small deterministic, deferred-only Nix/pacman/RPM/AUR shadow recipes."""
import json
import re
import shlex
from urllib.parse import quote

from rs9.dependencies import derive_dependencies
from rs9.errors import ContractError
from rs9.ingestion import AuthenticatedInputs, digest, read_evidence
from rs9.project import validate_desktop, validate_license
from rs9.scratch import ConfinedWriter, canonical
from rs9.security import (validate_repository, validate_safe_relative_posix_path,
                          validate_summary, validate_version_string)


def literal(value):
    validate_summary(value)
    return shlex.quote(value)


def identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-z0-9][a-z0-9+._-]*", value):
        raise ContractError("RENDER_VALUE", "Unsafe package or launcher identifier")
    return value


def path_literal(value):
    validate_safe_relative_posix_path(value)
    if not re.fullmatch(r"[A-Za-z0-9_ .+/-]+", value):
        raise ContractError("RENDER_VALUE", "Archive path outside renderer character subset")
    return shlex.quote(value)


def nix_string(value):
    validate_summary(value)
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("${", "\\${") + '"'


def rpm_string(value):
    validate_summary(value)
    return value.replace("%", "%%")


def desktop_entry(normalized):
    desktop = normalized.get("desktop")
    if desktop is None:
        raise ContractError("MISSING_REQUIRED_KEY", "Desktop facts required by this shadow slice")
    validate_desktop(desktop, normalized["commands"])
    command, project = identifier(desktop["command"]), normalized["project"]
    validate_summary(project["name"])
    validate_summary(project.get("summary"))
    escape = lambda s: s.replace("\\", "\\\\")
    return ("[Desktop Entry]\nType=Application\nName=" + escape(project["name"]) +
            "\nComment=" + escape(project["summary"]) + "\nExec=" + command +
            "\nIcon=" + identifier(project["id"]) + "\nTerminal=false\nCategories=" +
            ";".join(sorted(desktop["categories"])) + ";\n").encode("utf-8")


def context(authenticated, revision):
    if not isinstance(authenticated, AuthenticatedInputs):
        raise ContractError("AUTHENTICATION_REQUIRED", "Render requires an in-process evidence authentication result")
    if type(revision) is not int or not 1 <= revision <= 999999:
        raise ContractError("RENDER_VALUE", "Package revision must be a bounded positive integer")
    normalized = authenticated.normalized
    identifier(normalized["project"]["id"])
    validate_repository(normalized["project"]["repository"])
    validate_version_string(normalized["version"])
    validate_license(normalized["license"])
    if normalized["license"]["expression"] not in ("AGPL-3.0-or-later", "MIT"):
        raise ContractError("UNSUPPORTED_LICENSE", "No adapter license mapping for tenant expression")
    sources = {}
    for asset in authenticated.record["assets"]:
        if not re.fullmatch(r"[A-Za-z0-9_.+-]+", asset["name"]) or not re.fullmatch(r"[0-9a-f]{64}", asset["sha256"]):
            raise ContractError("RENDER_VALUE", "Unsafe authenticated asset identity")
        if digest(read_evidence(authenticated.archives[asset["id"]].parent, asset["name"], 1024 ** 3)) != asset["sha256"]:
            raise ContractError("INPUT_CHANGED", "Authenticated input changed before rendering")
        path_literal(asset["root"])
        for item in (*asset["commands"].values(), *asset["launchers"].values()):
            path_literal(item["path"])
        for platform in asset["platforms"]:
            if platform in sources:
                raise ContractError("RENDER_VALUE", "Ambiguous platform input")
            sources[platform] = asset
    dependencies = derive_dependencies(authenticated)
    unknown = [item for p in dependencies["platforms"].values() for item in p["unresolved"]
               if item["reason"] in ("unmapped-system-soname", "foreign-architecture", "unmapped-interpreter", "unmapped-elf-interpreter")]
    if unknown:
        raise ContractError("UNRESOLVED_DEPENDENCY", "Unmapped mandatory dependency blocks recipe rendering")
    return normalized, sources, dependencies


def source_url(n, asset):
    return ("https://github.com/" + n["project"]["repository"] + "/releases/download/" +
            quote(n["tag"], safe="") + "/" + quote(asset["name"], safe=""))


def icon_url(n, record):
    return ("https://raw.githubusercontent.com/" + n["project"]["repository"] + "/" +
            record["tag"]["commit"] + "/" + quote(record["icon"]["path"], safe="/"))


def launcher(asset, command):
    # Optional release-owned shim preserves upstream --version/resource behavior.
    item = asset["launchers"].get(command, asset["commands"].get(command))
    if item is None:
        raise ContractError("COMMAND_PATH", "Target input lacks desktop command")
    path_literal(item["path"])
    return item["path"][len(asset["root"]) + 1:]


def packages(detail, ecosystem):
    """Translate observed floors only when package/version semantics are known."""
    result = []
    node_floors = [int(s["runtime_constraint"][2:]) for s in detail["scripts"]
                   if s.get("runtime_constraint") and s.get("interpreter") == "node"]
    glibc = detail["version_floors"].get("GLIBC")
    for package in detail["packages"][ecosystem]:
        floor = glibc if package == "glibc" else str(max(node_floors)) if package == "nodejs" and node_floors else None
        result.append(package + ((">=" if ecosystem == "arch" else " >= ") + floor if floor else ""))
    if ecosystem in ("arch", "fedora"):
        result.append("hicolor-icon-theme")
    return sorted(result)


def pacman(n, target, sources, deps, record, desktop, revision):
    name = identifier(target["name"])
    project, command = n["project"]["id"], identifier(n["desktop"]["command"])
    architectures = sorted(p.split("-")[0] for p in target["effective-platforms"])
    if not architectures or not set(architectures) <= {"x86_64", "aarch64"}:
        raise ContractError("UNSUPPORTED_PLATFORM", "Pacman requires concrete supported Linux architectures")
    aur = target.get("profile") == "aur"
    if not aur and target["mode"] != "direct":
        raise ContractError("UNSUPPORTED_DESTINATION", "Pacman projection requires explicit AUR profile")
    if aur and (name != project + "-bin" or target["mode"] != "projection"):
        raise ContractError("RENDER_VALUE", "AUR binary name must match project identity")
    desktop_name = project + ".desktop"
    common_sources = [desktop_name, "icon.png::" + icon_url(n, record)]
    common_sums = [digest(desktop), record["icon"]["sha256"]]
    package_sets = [set(packages(deps["platforms"][a + "-linux"], "arch")) for a in architectures]
    common_depends = sorted(set.intersection(*package_sets))
    array = lambda values: "(" + " ".join(shlex.quote(v) for v in values) + ")"
    lines = ["# RS9 shadow candidate; publication and license acceptance deferred.",
             "pkgname=" + name, "pkgver=" + n["version"], "pkgrel=" + str(revision),
             "pkgdesc=" + literal(n["project"]["summary"]), "arch=" + array(architectures),
             "url=" + shlex.quote("https://github.com/" + n["project"]["repository"]),
             "license=" + array([n["license"]["expression"]]), "depends=" + array(common_depends),
             "options=('!strip' '!debug' '!purge' '!zipman')"]
    facts = {"pkgdesc": n["project"]["summary"], "pkgver": n["version"], "pkgrel": str(revision),
             "url": "https://github.com/" + n["project"]["repository"], "arch": architectures,
             "license": [n["license"]["expression"]], "depends": common_depends}
    if aur:
        lines += ["provides=" + array([project + "=" + n["version"]]), "conflicts=" + array([project])]
        facts.update(provides=[project + "=" + n["version"]], conflicts=[project])
    lines += ["source=" + array(common_sources), "sha256sums=" + array(common_sums)]
    facts.update(options=["!strip", "!debug", "!purge", "!zipman"], source=common_sources, sha256sums=common_sums)
    selected = []
    for architecture in architectures:
        asset = sources[architecture + "-linux"]
        selected.append(asset)
        extra = sorted(set(packages(deps["platforms"][architecture + "-linux"], "arch")) - set(common_depends))
        if extra:
            lines.append("depends_" + architecture + "=" + array(extra))
            facts["depends_" + architecture] = extra
        lines += ["source_" + architecture + "=" + array([source_url(n, asset)]),
                  "sha256sums_" + architecture + "=" + array([asset["sha256"]])]
        facts["source_" + architecture] = [source_url(n, asset)]
        facts["sha256sums_" + architecture] = [asset["sha256"]]
    if len({a["root"] for a in selected}) != 1 or len({launcher(a, command) for a in selected}) != 1:
        raise ContractError("RENDER_VALUE", "Pacman architectures require the same installed layout")
    payload_root, public = selected[0]["root"], launcher(selected[0], command)
    lines += ["", "package() {", '  local payload="$pkgdir/usr/lib/' + project + '"',
              '  mkdir -p "$payload" "$pkgdir/usr/bin"',
              '  cp -a "$srcdir/"' + path_literal(payload_root) + '/. "$payload/"',
              '  ln -s ' + shlex.quote("/usr/lib/" + project + "/" + public) + ' "$pkgdir/usr/bin/' + command + '"',
              '  install -Dm644 "$srcdir/' + desktop_name + '" "$pkgdir/usr/share/applications/' + desktop_name + '"',
              '  install -Dm644 "$srcdir/icon.png" "$pkgdir/usr/share/icons/hicolor/' + str(record["icon"]["size"]) + 'x' + str(record["icon"]["size"]) + '/apps/' + project + '.png"']
    for path in n["license"]["files"]:
        lines.append('  install -Dm644 "$payload/"' + path_literal(path) + ' "$pkgdir/usr/share/licenses/' + name + '/"' + path_literal(path))
    lines += ["}", ""]
    srcinfo = ["pkgbase = " + name]
    order = ["pkgdesc", "pkgver", "pkgrel", "url", "arch", "license", "depends", "provides", "conflicts", "options", "source", "sha256sums"]
    order += [key + "_" + arch for arch in architectures for key in ("source", "depends", "sha256sums")]
    for key in order:
        values = facts.get(key, [])
        for value in values if isinstance(values, list) else [values]:
            srcinfo.append("\t" + key + " = " + value)
    srcinfo += ["", "pkgname = " + name, ""]
    return "\n".join(lines).encode(), "\n".join(srcinfo).encode()


def rpm(n, target, sources, deps, record, desktop, revision):
    name, project = identifier(target["name"]), identifier(n["project"]["id"])
    command = identifier(n["desktop"]["command"])
    architectures = sorted(p.split("-")[0] for p in target["effective-platforms"])
    if not architectures or not set(architectures) <= {"aarch64", "x86_64"} or target["mode"] != "direct":
        raise ContractError("UNSUPPORTED_PLATFORM", "RPM shadow requires direct Linux targets")
    lines = ["# RS9 shadow candidate; publication and license acceptance deferred.", "%global debug_package %{nil}",
             "%global __strip /bin/true", "%undefine __brp_mangle_shebangs", "%global __os_install_post %{nil}",
             "Name: " + name, "Version: " + n["version"], "Release: " + str(revision) + "%{?dist}",
             "Summary: " + rpm_string(n["project"]["summary"]), "License: " + rpm_string(n["license"]["expression"]),
             "URL: https://github.com/" + n["project"]["repository"], "ExclusiveArch: " + " ".join(architectures)]
    selected = []
    for arch in architectures:
        asset = sources[arch + "-linux"]
        selected.append(asset)
        lines += ["%ifarch " + arch, "Source0: " + source_url(n, asset)]
        for package in packages(deps["platforms"][arch + "-linux"], "fedora"):
            lines.append("Requires: " + package)
        lines += ["%global raw_sha256 " + asset["sha256"], "%endif"]
    if len({launcher(a, command) for a in selected}) != 1 or len({a["root"] for a in selected}) != 1:
        raise ContractError("RENDER_VALUE", "RPM architectures require matching layout")
    private = sorted({b["soname"] for arch in architectures for b in deps["platforms"][arch + "-linux"]["bundled"]})
    if private:
        for soname in private:
            if not re.fullmatch(r"[A-Za-z0-9_.+-]+", soname):
                raise ContractError("RENDER_VALUE", "Unsafe private SONAME")
        regex = "|".join(re.escape(s) for s in private)
        lines += ["%global __requires_exclude ^(" + regex + ")(\\(.*)?$",
                  "%global __provides_exclude_from ^/usr/lib/" + project + "/.*$"]
    lines += ["Source1: " + project + ".desktop", "Source2: " + icon_url(n, record), "", "%description",
              rpm_string(n["project"]["summary"]), "", "%prep",
              "printf '%s  %s\\n' '%{raw_sha256}' '%{SOURCE0}' | sha256sum -c -",
              "printf '%s  %s\\n' '" + digest(desktop) + "' '%{SOURCE1}' | sha256sum -c -",
              "printf '%s  %s\\n' '" + record["icon"]["sha256"] + "' '%{SOURCE2}' | sha256sum -c -",
              "%setup -q -c -n %{name}-%{version}", "", "%build", "# Precompiled; no payload transformations.", "", "%install",
              "mkdir -p '%{buildroot}/usr/lib/" + project + "' '%{buildroot}/usr/bin'",
              "cp -a " + path_literal(selected[0]["root"]) + "/. '%{buildroot}/usr/lib/" + project + "/'",
              "ln -s '" + "/usr/lib/" + project + "/" + launcher(selected[0], command) + "' '%{buildroot}/usr/bin/" + command + "'",
              "install -Dm644 '%{SOURCE1}' '%{buildroot}/usr/share/applications/" + project + ".desktop'",
              "install -Dm644 '%{SOURCE2}' '%{buildroot}/usr/share/icons/hicolor/" + str(record["icon"]["size"]) + "x" + str(record["icon"]["size"]) + "/apps/" + project + ".png'", "", "%files"]
    lines += ["%license " + path_literal(selected[0]["root"] + "/" + p) for p in n["license"]["files"]]
    lines += ["/usr/lib/" + project, "/usr/bin/" + command, "/usr/share/applications/" + project + ".desktop",
              "/usr/share/icons/hicolor/" + str(record["icon"]["size"]) + "x" + str(record["icon"]["size"]) + "/apps/" + project + ".png", ""]
    return "\n".join(lines).encode()


def nix(n, target, sources, deps, record):
    project, command = identifier(n["project"]["id"]), identifier(n["desktop"]["command"])
    platforms = sorted(target["effective-platforms"])
    if not platforms or not set(platforms) <= {"aarch64-darwin", "aarch64-linux", "x86_64-linux"}:
        raise ContractError("UNSUPPORTED_PLATFORM", "Unsupported Nix shadow platform")
    lines = ["# RS9 shadow candidate; publication and license acceptance deferred.",
             "{ lib, stdenvNoCC, fetchurl, buildFHSEnv }:", "let", "  system = stdenvNoCC.hostPlatform.system;",
             "  sources = {"]
    for platform in platforms:
        asset = sources[platform]
        lines += ['    "' + platform + '" = { url = ' + json.dumps(source_url(n, asset)) + '; sha256 = "' + asset["sha256"] + '"; root = ' + json.dumps(asset["root"]) + '; launcher = ' + json.dumps(launcher(asset, command)) + "; };"]
    license_attr = {"AGPL-3.0-or-later": "agpl3Plus", "MIT": "mit"}[n["license"]["expression"]]
    lines += ["  };", '  selected = sources.${system} or (throw "Unsupported shadow system");',
              "  rawArchive = fetchurl { inherit (selected) url sha256; };",
              "  isDarwin = stdenvNoCC.hostPlatform.isDarwin;", "  meta = {",
              "    description = " + nix_string(n["project"]["summary"]) + ";",
              '    homepage = "https://github.com/' + n["project"]["repository"] + '";',
              "    license = lib.licenses." + license_attr + ";", '    mainProgram = "' + command + '";',
              "    platforms = " + "[ " + " ".join(json.dumps(p) for p in platforms) + " ];",
              "    sourceProvenance = [ lib.sourceTypes.binaryNativeCode ];", "  };",
              "  payload = stdenvNoCC.mkDerivation {", '    pname = "' + identifier(target["name"]) + '-payload";',
              '    version = "' + n["version"] + '";', "    src = rawArchive;", '    sourceRoot = ".";',
              "    dontConfigure = true; dontBuild = true; dontFixup = true;", "    installPhase = if isDarwin then ''",
              '      mkdir -p "$out/Applications" "$out/bin"',
              '      cp -a "${selected.root}" "$out/Applications/"',
              '      ln -s "$out/Applications/${selected.root}/${selected.launcher}" "$out/bin/' + command + '"',
              "    '' else ''", '      mkdir -p "$out/lib/' + project + '"',
              '      cp -a "${selected.root}/." "$out/lib/' + project + '/"', "    '';", "    inherit meta;", "  };",
              "  icon = fetchurl { url = " + json.dumps(icon_url(n, record)) + '; sha256 = "' + record["icon"]["sha256"] + '"; };',
              "  packages = {"]
    for platform in platforms:
        if platform.endswith("-linux"):
            values = deps["platforms"][platform]["packages"]["nix"]
            lines.append('    "' + platform + '" = pkgs: [ ' + " ".join("pkgs." + v for v in values) + " ];")
    lines += ["  };", "in if isDarwin then payload else buildFHSEnv {", '  name = "' + command + '";',
              "  targetPkgs = packages.${system};", '  runScript = "${payload}/lib/' + project + '/${selected.launcher}";',
              "  extraInstallCommands = ''", '    mkdir -p "$out/share/applications" "$out/share/icons/hicolor/' + str(record["icon"]["size"]) + 'x' + str(record["icon"]["size"]) + '/apps"',
              '    cp ${./' + project + '.desktop} "$out/share/applications/' + project + '.desktop"',
              '    cp ${icon} "$out/share/icons/hicolor/' + str(record["icon"]["size"]) + 'x' + str(record["icon"]["size"]) + '/apps/' + project + '.png"',
              "  '';", "  passthru = { inherit payload; };", "  inherit meta;", "}", ""]
    return "\n".join(lines).encode()


def render(authenticated, output, *, revision=1):
    n, sources, dependencies = context(authenticated, revision)
    desktop = desktop_entry(n)
    if not authenticated.record["icon"]:
        raise ContractError("MISSING_REQUIRED_KEY", "Authenticated icon required")
    files = {}
    for target in n["targets"]:
        adapter = target["adapter"]
        if adapter not in ("nix", "pacman", "dnf"):
            continue
        for platform in target["effective-platforms"]:
            if platform not in sources or sources[platform]["id"] not in target["assets"]:
                raise ContractError("RENDER_VALUE", "Target input does not cover selected asset/platform intent")
        identifier(target["name"])
        prefix = ("aur" if target.get("profile") == "aur" else {"nix": "nix", "pacman": "pacman", "dnf": "rpm"}[adapter])
        if adapter == "pacman":
            prefix += "/" + target["name"]
            recipe, srcinfo = pacman(n, target, sources, dependencies, authenticated.record, desktop, revision)
            products = {prefix + "/PKGBUILD": recipe}
            if target.get("profile") == "aur":
                products[prefix + "/.SRCINFO"] = srcinfo
        elif adapter == "dnf":
            products = {prefix + "/" + target["name"] + ".spec": rpm(n, target, sources, dependencies, authenticated.record, desktop, revision)}
        else:
            products = {prefix + "/" + target["name"] + ".nix": nix(n, target, sources, dependencies, authenticated.record)}
        products[prefix + "/" + n["project"]["id"] + ".desktop"] = desktop
        if set(products) & set(files):
            raise ContractError("RENDER_COLLISION", "Multiple targets collide in shadow output")
        files.update(products)
    manifest = {"schema": "rs9.shadow-render.v1alpha1", "revision": revision,
                "inputs": {"normalized_sha256": digest(canonical(n)), "ingestion_sha256": digest(canonical(authenticated.record)),
                           "dependencies_sha256": digest(canonical(dependencies))},
                "license_authority": authenticated.record["license"]["status"],
                "license_intent_status": n["license"].get("status", "declared"),
                "icon_authority": authenticated.record["icon"],
                "verdict": "deferred", "blockers": ["shadow-only; package build/install and provider mapping qualification required"],
                "files": [{"path": p, "size": len(b), "sha256": digest(b)} for p, b in sorted(files.items())]}
    if manifest["license_authority"] != "consistent":
        manifest["blockers"].append("tenant-license-conflict")
    if manifest["license_intent_status"] == "unresolved":
        manifest["blockers"].append("tenant-license-unresolved")
    for platform, detail in dependencies["platforms"].items():
        if detail["unresolved"]:
            manifest["blockers"].append(platform + ": unresolved runtime evidence")
    with ConfinedWriter(output) as writer:
        for path, content in sorted(files.items()):
            writer.write(path, content)
        writer.write("render-manifest.json", canonical(manifest))
    return manifest
