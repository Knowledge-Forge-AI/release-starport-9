"""Released-byte Linux runtime evidence and explicitly unqualified ecosystem maps."""
import posixpath
import json
import re
import shlex

from rs9.archives import inspect_archive
from rs9.elf import parse_elf
from rs9.errors import ContractError
from rs9.ingestion import digest
from rs9.scratch import canonical

# These are adapter knowledge, never tenant runtime facts. Availability/provider
# proof in pinned distribution environments is a separate acceptance gate.
LIBRARIES = {
    "ld-linux-x86-64.so.2": ("glibc", "glibc", "glibc"),
    "ld-linux-aarch64.so.1": ("glibc", "glibc", "glibc"),
    "libc.so.6": ("glibc", "glibc", "glibc"),
    "libm.so.6": ("glibc", "glibc", "glibc"),
    "libdl.so.2": ("glibc", "glibc", "glibc"),
    "libpthread.so.0": ("glibc", "glibc", "glibc"),
    "librt.so.1": ("glibc", "glibc", "glibc"),
    "libgcc_s.so.1": ("libgcc", "libgcc", "stdenv.cc.cc.lib"),
    "libstdc++.so.6": ("libstdc++", "libstdc++", "stdenv.cc.cc.lib"),
    "libgtk-3.so.0": ("gtk3", "gtk3", "gtk3"),
    "libgdk-3.so.0": ("gtk3", "gtk3", "gtk3"),
    "libwebkit2gtk-4.1.so.0": ("webkit2gtk-4.1", "webkit2gtk4.1", "webkitgtk_4_1"),
    "libjavascriptcoregtk-4.1.so.0": ("webkit2gtk-4.1", "javascriptcoregtk4.1", "webkitgtk_4_1"),
    "libsoup-3.0.so.0": ("libsoup3", "libsoup3", "libsoup_3"),
    "libglib-2.0.so.0": ("glib2", "glib2", "glib"),
    "libgobject-2.0.so.0": ("glib2", "glib2", "glib"),
    "libgio-2.0.so.0": ("glib2", "glib2", "glib"),
    "libgmodule-2.0.so.0": ("glib2", "glib2", "glib"),
    "libgthread-2.0.so.0": ("glib2", "glib2", "glib"),
    "libcairo.so.2": ("cairo", "cairo", "cairo"),
    "libcairo-gobject.so.2": ("cairo", "cairo-gobject", "cairo"),
    "libpango-1.0.so.0": ("pango", "pango", "pango"),
    "libpangocairo-1.0.so.0": ("pango", "pango", "pango"),
    "libgdk_pixbuf-2.0.so.0": ("gdk-pixbuf2", "gdk-pixbuf2", "gdk-pixbuf"),
    "libdbus-1.so.3": ("dbus", "dbus-libs", "dbus"),
    "libssl.so.3": ("openssl", "openssl-libs", "openssl"),
    "libcrypto.so.3": ("openssl", "openssl-libs", "openssl"),
    "libz.so.1": ("zlib", "zlib", "zlib"),
    "libX11.so.6": ("libx11", "libX11", "xorg.libX11"),
    "libappindicator3.so.1": ("libappindicator-gtk3", "libappindicator-gtk3", "libappindicator-gtk3"),
}
INTERPRETERS = {"node": ("nodejs", "nodejs", "nodejs_22"), "sh": ("bash", "bash", "bash"),
                "bash": ("bash", "bash", "bash"), "python3": ("python", "python3", "python3")}


def shebang(data):
    if not data.startswith(b"#!"):
        return None
    line = data.split(b"\n", 1)[0]
    if len(line) > 4096:
        raise ContractError("INVALID_SHEBANG", "Interpreter line exceeds bound")
    try:
        argv = shlex.split(line[2:].decode("utf-8"))
    except (ValueError, UnicodeError):
        raise ContractError("INVALID_SHEBANG", "Malformed interpreter line") from None
    if not argv or not argv[0].startswith("/"):
        raise ContractError("INVALID_SHEBANG", "Absolute shebang interpreter required")
    executable = posixpath.basename(argv[0])
    if executable == "env":
        rest = argv[1:]
        if rest and rest[0] == "-S":
            rest = rest[1:]
        if not rest or rest[0].startswith("-") or "=" in rest[0]:
            return {"argv": argv, "interpreter": None, "resolution": "unresolved-env"}
        executable = posixpath.basename(rest[0])
    return {"argv": argv, "interpreter": executable, "resolution": "system-interpreter"}


def mapping(names, table):
    result = {"arch": set(), "fedora": set(), "nix": set()}
    unresolved = []
    for name in sorted(names):
        if name not in table:
            unresolved.append(name)
        else:
            for ecosystem, package in zip(result, table[name]):
                result[ecosystem].add(package)
    return {k: sorted(v) for k, v in result.items()}, unresolved


def derive_dependencies(authenticated):
    platforms = {}
    for asset in authenticated.record["assets"]:
        linux = [p for p in asset["platforms"] if p.endswith("-linux")]
        if not linux:
            continue
        objects, scripts, advisory, package_metadata = [], [], set(), {}

        def scan(path, data, mode):
            if data.startswith(b"\x7fELF"):
                objects.append({"path": path, "sha256": digest(data), **parse_elf(data)})
            elif mode & 0o111 and data.startswith(b"#!"):
                scripts.append({"path": path, "sha256": digest(data), **shebang(data)})
            if path.endswith("/package.json") and len(data) < 1024 * 1024:
                try:
                    package = json.loads(data)
                    if isinstance(package, dict):
                        package_metadata[posixpath.dirname(path)] = {"path": path, "sha256": digest(data), "engines": package.get("engines", {})}
                except (ValueError, UnicodeError):
                    pass
            advisory.update(m.decode("ascii") for m in re.findall(rb"\blib[A-Za-z0-9_+.-]+\.so(?:\.[0-9]+)*\b", data))

        manifest = inspect_archive(authenticated.archives[asset["id"]],
                                   authenticated.normalized["assets"][[a["id"] for a in authenticated.normalized["assets"]].index(asset["id"])]["commands"], on_file=scan)
        if manifest["manifest_sha256"] != asset["payload_manifest_sha256"]:
            raise ContractError("INPUT_CHANGED", "Authenticated archive bytes changed before dependency derivation")
        providers = {}
        for obj in objects:
            if obj["soname"]:
                providers.setdefault(obj["soname"], []).append(obj["path"])
        system, bundled, unresolved = {}, [], []
        versions = {}
        for obj in objects:
            if any(p.split("-")[0] != obj["machine"] for p in linux):
                unresolved.append({"path": obj["path"], "reason": "foreign-architecture"})
            directories = set()
            for path in obj["runpath"] or obj["rpath"]:
                if path == "$ORIGIN" or path.startswith("$ORIGIN/"):
                    directories.add(posixpath.normpath(path.replace("$ORIGIN", posixpath.dirname(obj["path"]))))
                else:
                    unresolved.append({"path": obj["path"], "reason": "unqualified-loader-search-path"})
            for name in obj["needed"]:
                local = [p for p in providers.get(name, []) if posixpath.dirname(p) in directories]
                if len(local) == 1:
                    bundled.append({"object": obj["path"], "soname": name, "provider": local[0]})
                elif len(local) > 1:
                    unresolved.append({"path": obj["path"], "reason": "ambiguous-bundled-provider"})
                else:
                    system.setdefault(name, []).append(obj["path"])
            for needed in obj["version_needs"].values():
                for version in needed:
                    prefix, _, value = version.partition("_")
                    if prefix in ("GLIBC", "GLIBCXX", "CXXABI") and re.fullmatch(r"[0-9]+(?:\.[0-9]+)*", value):
                        versions.setdefault(prefix, []).append(value)
        mapped, unknown = mapping(system, LIBRARIES)
        for name in unknown:
            unresolved.append({"soname": name, "reason": "unmapped-system-soname"})
        runtime, unknown_runtime = mapping({s["interpreter"] for s in scripts if s["interpreter"]}, INTERPRETERS)
        for script in scripts:
            if script["interpreter"] is None or script["interpreter"] in unknown_runtime:
                unresolved.append({"path": script["path"], "reason": "unmapped-interpreter"})
            elif script["interpreter"] == "node":
                directory = posixpath.dirname(script["path"])
                while directory and directory not in package_metadata:
                    directory = posixpath.dirname(directory)
                selected = package_metadata.get(directory, {})
                constraint = selected.get("engines", {}).get("node") if isinstance(selected.get("engines"), dict) else None
                script["runtime_constraint"] = constraint if isinstance(constraint, str) and re.fullmatch(r">=[0-9]+", constraint) else None
                script["constraint_source"] = {k: selected[k] for k in ("path", "sha256") if k in selected}
                unresolved.append({"path": script["path"], "reason": "node-module-resolution-unqualified" if script["runtime_constraint"] else "node-version-and-module-resolution-unqualified"})
        for key in mapped:
            mapped[key] = sorted(set(mapped[key]) | set(runtime[key]))
        interpreters = sorted({o["interpreter"] for o in objects if o["interpreter"]})
        for interpreter in interpreters:
            expected = {"/lib64/ld-linux-x86-64.so.2", "/lib/ld-linux-aarch64.so.1"}
            if interpreter not in expected:
                unresolved.append({"interpreter": interpreter, "reason": "unmapped-elf-interpreter"})
            else:
                for key in mapped:
                    mapped[key] = sorted(set(mapped[key]) | {"glibc"})
        detail = {"asset": asset["id"], "payload_manifest_sha256": manifest["manifest_sha256"],
                  "objects": sorted(objects, key=lambda o: o["path"]), "scripts": sorted(scripts, key=lambda s: s["path"]),
                  "interpreters": interpreters, "system_sonames": [{"soname": n, "required_by": sorted(v)} for n, v in sorted(system.items())],
                  "bundled": sorted(bundled, key=lambda b: (b["object"], b["soname"])),
                  "version_floors": {k: max(v, key=lambda s: tuple(map(int, s.split(".")))) for k, v in sorted(versions.items())},
                  "packages": mapped, "mapping_qualification": "not-executed; pinned provider queries required",
                  "unresolved": sorted(unresolved, key=lambda v: canonical(v)), "dlopen_candidates": sorted(advisory - set(system) - set(providers))}
        if not objects:
            detail["unresolved"].append({"reason": "no-elf-objects"})
        for platform in linux:
            platforms[platform] = detail
    return {"schema": "rs9.dependency-evidence.v1alpha1", "ingestion_sha256": digest(canonical(authenticated.record)),
            "platforms": dict(sorted(platforms.items())),
            "limits": ["DT_NEEDED does not prove dlopen, transitive dependencies or GUI resource resolution.",
                       "Package mappings are candidates until pinned distribution provider queries execute."]}
