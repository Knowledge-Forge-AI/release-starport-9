"""Closed first-wave intake contract; no npm execution or network access."""
import json
import re
from pathlib import Path

from rs9.tf_pypi_archive import canonical, fail, physical_bytes, read_tar, sha256

PRODUCTS = {
    "theme-forge-stellar-burst": ("0.6.1", "tfsb", {
        "tfsb": "dist/cli.js", "tfsb-studio-service": "dist/service-protocol/server-cli.js"}),
    "theme-forge-stellar-loom": ("0.4.0", "tfsl", {
        "tfsl": "bin/tfsl.js", "tfsl-batch": "bin/tfsl-batch.js"}),
    "theme-forge-solar-sail": ("0.2.1", "tfss", {"tfss": "bin/tfss.js"}),
}
LEGAL = ("LICENSE", "NOTICE", "COMMERCIAL-LICENSE.md")
NATIVE_MAGIC = (b"\x7fELF", b"MZ", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf",
                b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca", b"\xca\xfe\xba\xbf",
                b"\xbf\xba\xfe\xca", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xce")


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail("JSON")
        result[key] = value
    return result


def strict_json(data):
    try:
        return json.loads(data, object_pairs_hook=_unique,
                          parse_constant=lambda _: fail("JSON"))
    except (ValueError, UnicodeError, RecursionError):
        fail("JSON")


def validate_pin(pin):
    if not isinstance(pin, dict) or pin.get("project") not in PRODUCTS:
        fail("PRODUCT")
    project = pin["project"]
    allowed = {"schema", "project", "version", "workflow", "npm_name", "bins", "node",
               "license", "asset", "sha256", "size", "source_commit", "source_status",
               "withheld", "qualified_platforms", "dependencies"}
    if set(pin) - allowed:
        fail("PIN")
    version, short, bins = PRODUCTS[project]
    expected = {"version": version, "workflow": f"rs9-{short}-pypi-publish.yml",
                "npm_name": "@knowledge-forge-ai/" + project, "bins": bins,
                "node": ">=22", "license": "AGPL-3.0-or-later",
                "asset": f"knowledge-forge-ai-{project}-{version}.tgz"}
    if any(pin.get(k) != v for k, v in expected.items()):
        fail("PIN")
    if (not re.fullmatch(r"[0-9a-f]{64}", str(pin.get("sha256", "")))
            or type(pin.get("size")) is not int or not 0 < pin["size"] <= 32 * 1024**2
            or not re.fullmatch(r"[0-9a-f]{40}", str(pin.get("source_commit", "")))):
        fail("PIN")
    platforms = pin.get("qualified_platforms", [])
    if (not isinstance(platforms, list) or any(not isinstance(p, str) for p in platforms)
            or len(platforms) != len(set(platforms))
            or any(p not in {"darwin-arm64", "darwin-x64", "linux-arm64-gnu", "linux-x64-gnu"}
                   for p in platforms)):
        fail("PIN")
    if pin.get("source_status") not in {"READY", "BLOCKED"}:
        fail("PIN")
    if "dependencies" in pin:
        from rs9.tf_pypi_closure import DEPENDENCIES
        dependencies = pin["dependencies"]
        if (project != "theme-forge-stellar-burst" or not isinstance(dependencies, list)
                or len(dependencies) != len(DEPENDENCIES)):
            fail("PIN")
        for dep, frozen in zip(dependencies, DEPENDENCIES):
            if (not isinstance(dep, dict) or set(dep) != set(frozen) | {"integrity", "url"}
                    or any(dep.get(k) != v for k, v in frozen.items())
                    or dep["url"] != "https://registry.npmjs.org/" + dep["name"] + "/-/" + dep["asset"]
                    or not re.fullmatch(r"sha512-[A-Za-z0-9+/]{86}==", dep["integrity"])):
                fail("PIN")
    return pin


def load_pin(project):
    if project not in PRODUCTS:
        fail("PRODUCT")
    root = Path(__file__).resolve().parents[2]
    return validate_pin(strict_json(physical_bytes(root / "operators/tf-pypi" / (project + ".json"))))


def check_package(pin, files):
    if "package/package.json" not in files:
        fail("PACKAGE")
    package = strict_json(files["package/package.json"][0])
    if not isinstance(package, dict):
        fail("PACKAGE")
    if package.get("name") != pin["npm_name"]:
        fail("NAME")
    if package.get("version") != pin["version"]:
        fail("VERSION")
    if not isinstance(package.get("engines"), dict) or package["engines"].get("node") != pin["node"]:
        fail("NODE_ENGINE")
    if package.get("license") != pin["license"]:
        fail("LICENSE")
    bins = package.get("bin")
    if not isinstance(bins, dict) or any(not isinstance(p, str) for p in bins.values()):
        fail("ENTRYPOINT")
    normalized = {name: p[2:] if p.startswith("./") else p for name, p in bins.items()}
    if normalized != pin["bins"]:
        fail("ENTRYPOINT")
    for target in pin["bins"].values():
        entry = files.get("package/" + target)
        if entry is None or re.search(rb"\b(?:npm|npx)\b", entry[0]):
            fail("ENTRYPOINT")
    if any("package/" + name not in files or not files["package/" + name][0] for name in LEGAL[:2]):
        fail("LICENSE")
    return package


def pure_payload(files):
    for name, (data, _) in files.items():
        if (name.lower().endswith((".node", ".so", ".dylib", ".dll", ".exe", ".a"))
                or data.startswith(NATIVE_MAGIC)):
            fail("NATIVE_UNQUALIFIED")
        if "node_modules" in name.split("/"):
            fail("DEPENDENCY")
        if name.endswith("/package.json"):
            pkg = strict_json(data)
            if not isinstance(pkg, dict):
                fail("PACKAGE")
            for key in ("dependencies", "optionalDependencies", "peerDependencies",
                        "bundledDependencies", "bundleDependencies", "os", "cpu", "libc"):
                if pkg.get(key):
                    fail("DEPENDENCY")


def admit_bytes(pin, data, basename):
    validate_pin(pin)
    if basename != pin["asset"]:
        fail("BASENAME")
    if len(data) != pin["size"]:
        fail("SIZE")
    if sha256(data) != pin["sha256"]:
        fail("HASH")
    files = read_tar(data)
    check_package(pin, files)
    return files


def intake(pin, path):
    path = Path(path)
    if not path.exists():
        fail("ASSET_ABSENT")
    data = physical_bytes(path, limit=pin["size"] + 1)
    return data, admit_bytes(pin, data, path.name)


def logical_identity(files):
    return sha256(canonical([{"path": p, "size": len(b), "sha256": sha256(b), "mode": m}
                             for p, (b, m) in sorted(files.items())]))
