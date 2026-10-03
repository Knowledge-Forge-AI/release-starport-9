"""Structured field differences with complete, non-stale classifications."""
from rs9.errors import ContractError
from rs9.ingestion import digest
from rs9.scratch import canonical
from pathlib import Path
import fnmatch
import json
import re
import shlex

CLASSES = frozenset({"semantically equivalent", "intentional RS9 normalization",
                     "RS9 correction backed by release evidence",
                     "reference-only behavior retained pending evidence", "unresolved blocker"})
MATERIAL = frozenset({"name", "architectures", "installed_paths", "launcher", "license", "dependencies", "payload_policy", "icon_sizes", "provides", "conflicts", "Exec", "MimeType", "StartupWMClass", "Categories"})


def parse_srcinfo(data):
    result = {}
    for line in data.decode("utf-8").splitlines():
        if not line.strip():
            continue
        key, separator, value = line.strip().partition(" = ")
        if not separator:
            raise ContractError("INVALID_SRCINFO", "Malformed SRCINFO field")
        result.setdefault(key, []).append(value)
    return result


def differences(reference, shadow):
    rows = []
    for adapter in sorted(set(reference) | set(shadow)):
        before, after = reference.get(adapter, {}), shadow.get(adapter, {})
        for field in sorted(set(before) | set(after)):
            if before.get(field) != after.get(field):
                rows.append({"adapter": adapter, "field": field, "reference": before.get(field),
                             "shadow": after.get(field), "material": field in MATERIAL})
    return rows


def classify(reference, shadow, classifications):
    rows = differences(reference, shadow)
    expected = {(r["adapter"], r["field"]) for r in rows}
    lookup = {}
    for row in classifications:
        key = row["adapter"], row["field"]
        if key in lookup or row.get("class") not in CLASSES or not row.get("rationale") or not row.get("evidence"):
            raise ContractError("INVALID_COMPARISON", "Invalid or duplicate difference classification")
        lookup[key] = row
    if set(lookup) != expected:
        raise ContractError("UNCLASSIFIED_DIFFERENCE", "Comparison contains unclassified or stale entries")
    return {"schema": "rs9.shadow-comparison.v1alpha1", "reference_sha256": digest(canonical(reference)),
            "shadow_sha256": digest(canonical(shadow)), "differences": [{**r, **lookup[(r["adapter"], r["field"])]} for r in rows]}


def _one(pattern, text, flags=0):
    values = re.findall(pattern, text, flags)
    if len(set(values)) != 1:
        raise ContractError("INVALID_COMPARISON", "Missing or ambiguous static recipe field")
    return values[0]


def _resolve(value, variables):
    """Substitute only bound literal variables; never evaluate recipe expressions."""
    def replace(match):
        name = next(part for part in match.groups() if part is not None)
        if name not in variables:
            raise ContractError("INVALID_COMPARISON", "Unbound static recipe variable")
        return variables[name]
    return re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)|%\{([A-Za-z_][A-Za-z0-9_]*)\}", replace, value)


def _assignments(text):
    result = {}
    for match in re.finditer(r"^([a-z_][a-z0-9_]*)=(\([^)]*\)|[^\n]+)$", text, re.M):
        key, value = match.groups()
        if key in result:
            raise ContractError("INVALID_COMPARISON", "Duplicate static recipe assignment")
        result[key] = shlex.split(value[1:-1] if value.startswith("(") else value)
    return result


def _install_facts(text, variables):
    """Read literal copy/install/link destinations in the two Nebular grammars."""
    paths, links, sizes = set(), [], [""]
    loop = re.search(r"for size in ([0-9 ]+); do", text)
    if loop:
        sizes = loop[1].split()
    local = re.search(r'^\s*local (libdir|payload)=(.*)$', text, re.M)
    if local:
        variables = {**variables, local[1]: _resolve(shlex.split(local[2])[0], variables)}
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith(("cp ", "install ", "ln -s ")):
            continue
        words = shlex.split(line)
        destination = words[-1]
        if not any(marker in destination for marker in ("$pkgdir", "${pkgdir}", "%{buildroot}", "${libdir}", "$payload", "${payload}")):
            continue
        for size in sizes if "${size}" in destination else [""]:
            dest = _resolve(destination, {**variables, "size": size}).rstrip("/")
            if (not dest.startswith("/usr/") or any(p in (".", "..", "") for p in dest.split("/")[1:])
                    or any(c in dest for c in "$%\\\n\r")):
                raise ContractError("INVALID_COMPARISON", "Unsupported static installed path")
            paths.add(dest)
        if words[:2] == ["ln", "-s"]:
            links.append(_resolve(words[-2], variables))
    if len(links) != 1:
        raise ContractError("INVALID_COMPARISON", "Unique static public launcher required")
    return paths, links[0]


def _arch_facts(text, aur):
    a = _assignments(text)
    def scalar(key):
        if len(a[key]) != 1:
            raise ContractError("INVALID_COMPARISON", "Unique scalar recipe field required")
        return a[key][0]
    architectures = sorted(a["arch"])
    variables = {key: scalar(key) for key in ("pkgname", "pkgver", "_pkgname") if key in a}
    variables["pkgdir"] = ""
    paths, launcher = _install_facts(text, variables)
    options = set(a["options"])
    policy = ("cp -a all entries; strip/debug/purge/zipman disabled"
              if "cp -a " in text and {"!strip", "!debug", "!purge", "!zipman"} <= options
              else "cp -r nonhidden entries; strip disabled"
              if "cp -r " in text and "!strip" in options
              else "unresolved recipe copy/fixup policy")
    result = {"name": scalar("pkgname"), "version": scalar("pkgver"),
              "architectures": architectures, "license": scalar("license"),
              "summary": scalar("pkgdesc"), "url": scalar("url"),
              "dependencies": {arch: sorted(a.get("depends", []) + a.get("depends_" + arch, [])) for arch in architectures},
              "launcher": launcher, "installed_paths": sorted(paths),
              "icon_sizes": sorted({int(size) for path in paths for size in re.findall(r"hicolor/([0-9]+)x", path)}),
              "payload_policy": policy}
    if aur:
        result.update(provides=a["provides"], conflicts=a["conflicts"])
    return result


def _rpm_facts(text):
    headers = {key: _one(r"^" + key + r":\s*([^\n]+)$", text, re.M).strip()
               for key in ("Name", "Version", "License", "URL", "Summary", "ExclusiveArch")}
    architectures = sorted(headers["ExclusiveArch"].split())
    packages, common, selected = {arch: [] for arch in architectures}, [], None
    for line in text.splitlines():
        if line.startswith("%ifarch "):
            selected = line.split()[1:]
        elif line.startswith("%endif"):
            selected = None
        elif line.startswith("Requires:"):
            requirement = line.partition(":")[2].strip()
            if selected is None:
                common.append(requirement)
            else:
                for arch in selected:
                    if arch not in packages:
                        raise ContractError("INVALID_COMPARISON", "Unexpected RPM architecture")
                    packages[arch].append(requirement)
    installed, launcher = _install_facts(text, {"name": headers["Name"], "version": headers["Version"], "buildroot": ""})
    files = _one(r"^%files\n(.*?)(?=^%changelog|\Z)", text, re.M | re.S)
    paths = set()
    for line in files.splitlines():
        if line.startswith("%license "):
            for path in shlex.split(line)[1:]:
                resolved = _resolve(path, {"name": headers["Name"]})
                paths.add("RPM-managed " + resolved.rsplit("/", 1)[-1] + " copy")
        elif line.startswith("/usr/"):
            path = _resolve(line.strip(), {"name": headers["Name"]})
            if "*" in path:
                matches = {p for p in installed if fnmatch.fnmatchcase(p, path)}
                if not matches:
                    raise ContractError("INVALID_COMPARISON", "RPM file glob has no static destination")
                paths.update(matches)
            else:
                if path not in installed:
                    raise ContractError("INVALID_COMPARISON", "RPM listed path lacks a static install destination")
                paths.add(path)
    policy = ("cp -a all entries; brp transformations disabled; source checksums in prep"
              if "cp -a " in text and "%global __os_install_post %{nil}" in text and "sha256sum -c -" in text
              else "cp -r nonhidden entries; strip disabled; default brp"
              if "cp -r " in text and "%global __strip /bin/true" in text
              else "unresolved recipe copy/fixup policy")
    return {"name": headers["Name"], "version": headers["Version"], "architectures": architectures,
            "license": headers["License"], "url": headers["URL"], "summary": headers["Summary"],
            "dependencies": {arch: sorted(common + values) for arch, values in packages.items()},
            "launcher": launcher, "installed_paths": sorted(paths),
            "icon_sizes": sorted({int(size) for path in paths for size in re.findall(r"hicolor/([0-9]+)x", path)}),
            "payload_policy": policy}


def _nix_facts(text, reference):
    architectures = sorted(set(re.findall(r'"([a-z0-9_-]+-(?:linux|darwin))"\s*=\s*\{', text)))
    if not architectures:
        raise ContractError("INVALID_COMPARISON", "Nix source systems missing")
    version = _one(r'\bversion = "([^"\n]+)";', text)
    pname = _one(r'\bpname = "([^"\n]+)";', text) if not reference else _one(r'^  pname = "([^"\n]+)";', text, re.M)
    fhs_name = _one(r'\bname = "([^"\n]+)";', text)
    licenses = re.findall(r'\blicense = (?:lib\.)?licenses\.([a-zA-Z0-9_]+);', text)
    mapping = {"agpl3Plus": "AGPL-3.0-or-later", "mit": "MIT"}
    if len(set(licenses)) != 1 or licenses[0] not in mapping:
        raise ContractError("INVALID_COMPARISON", "Unknown or ambiguous Nix license mapping")
    if reference:
        packages = sorted(_one(r'targetPkgs = pkgs: \[(.*?)\];', text, re.S).split())
        dependencies = {p: packages for p in architectures if p.endswith("-linux")}
        darwin = _one(r'ln -s "\$out/Applications/[^"\n]+\.app/([^"\n]+)"', text)
        linux = _one(r'runScript = "\$\{linuxPayload\}/lib/[^/]+/([^"\n]+)";', text)
        launchers = {p: darwin if p.endswith("-darwin") else linux for p in architectures}
        policy = ("cp -r nonhidden Linux entries; dontStrip/dontPatchELF; optional FHS fallback"
                  if "cp -r " in text and "dontStrip = true;" in text and "dontPatchELF = true;" in text
                  and "if buildFHSEnv != null" in text else "unresolved recipe copy/fixup policy")
    else:
        dependencies = {p: sorted(v.replace("pkgs.", "").split())
                        for p, v in re.findall(r'"([^"\n]+-linux)" = pkgs: \[ (.*?) \];', text)}
        launchers = {p: value for p, value in re.findall(r'"([^"\n]+)" = \{ .*?launcher = "([^"\n]+)";', text)}
        _one(r'runScript = "(\$\{payload\}/lib/[^/]+/\$\{selected\.launcher\})";', text)
        policy = ("cp -a all entries; dontFixup; mandatory Linux FHS; no GUI installCheck"
                  if "cp -a " in text and "dontFixup = true;" in text
                  and "in if isDarwin then payload else buildFHSEnv {" in text
                  and "installCheck" not in text else "unresolved recipe copy/fixup policy")
    if set(launchers) != set(architectures) or set(dependencies) != {p for p in architectures if p.endswith("-linux")}:
        raise ContractError("INVALID_COMPARISON", "Nix platform facts are incomplete")
    return {"name": {p: pname if p.endswith("-darwin") else fhs_name for p in architectures},
            "version": version, "architectures": architectures, "license": mapping[licenses[0]],
            "summary": json.loads(_one(r'description = ("[^\n]+")\s*;', text)),
            "url": _one(r'homepage = "([^"\n]+)";', text), "dependencies": dependencies,
            "launcher": launchers, "icon_sizes": sorted({int(s) for s in re.findall(r"hicolor/([0-9]+)x", text)}),
            "payload_policy": policy}


def _desktop_facts(text):
    result = {}
    for line in text.splitlines():
        if "=" in line and not line.startswith("#"):
            key, value = line.split("=", 1)
            if key in result:
                raise ContractError("INVALID_COMPARISON", "Duplicate desktop field")
            result[key] = value
    return result


def _facts(root, reference):
    """Static first-tenant recipe profile, not a Bash/RPM/Nix interpreter."""
    root = Path(root)
    paths = ({"pacman": "templates/pacman/theme-forge-nebular-fusion/PKGBUILD",
              "aur": "aur/theme-forge-nebular-fusion-bin/PKGBUILD",
              "rpm": "templates/rpm/theme-forge-nebular-fusion.spec",
              "nix": "packages/nebular-fusion.nix",
              "desktop": "templates/desktop/theme-forge-nebular-fusion.desktop"}
             if reference else {"pacman": "pacman/theme-forge-nebular-fusion/PKGBUILD",
              "aur": "aur/theme-forge-nebular-fusion-bin/PKGBUILD",
              "rpm": "rpm/theme-forge-nebular-fusion.spec",
              "nix": "nix/theme-forge-nebular-fusion.nix",
              "desktop": "nix/theme-forge-nebular-fusion.desktop"})
    texts = {key: (root / path).read_text(encoding="utf-8") for key, path in paths.items()}
    try:
        return {"pacman": _arch_facts(texts["pacman"], False), "aur": _arch_facts(texts["aur"], True),
                "rpm": _rpm_facts(texts["rpm"]), "nix": _nix_facts(texts["nix"], reference),
                "desktop": _desktop_facts(texts["desktop"])}
    except (KeyError, IndexError, ValueError, TypeError):
        raise ContractError("INVALID_COMPARISON", "Recipe outside supported static comparison grammar") from None


def shadow_facts(root):
    return _facts(root, False)


def reference_facts(root):
    return _facts(root, True)
