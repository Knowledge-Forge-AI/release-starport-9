"""Closed first-wave intake contract; no npm execution or network access."""
import json
import os
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
DISTRIBUTIONS = {
    "theme-forge-stellar-burst": "0.6.1.post1",
    "theme-forge-stellar-loom": "0.4.0.post1",
    "theme-forge-solar-sail": "0.2.1.post1",
}
RELEASES = {
    ("theme-forge-stellar-burst", "0.6.1", "0.6.1.post1"): (
        "theme-forge-stellar-burst.json",
        None,
    ),
    ("theme-forge-stellar-loom", "0.4.0", "0.4.0.post1"): (
        "theme-forge-stellar-loom.json",
        None,
    ),
    ("theme-forge-solar-sail", "0.2.1", "0.2.1.post1"): (
        "theme-forge-solar-sail.json",
        None,
    ),
    ("theme-forge-stellar-burst", "0.7.0", "0.7.0"): (
        "theme-forge-stellar-burst-0.7.0.json",
        "stellar-burst-0.7.0.md",
    ),
    ("theme-forge-stellar-loom", "0.5.0", "0.5.0"): (
        "theme-forge-stellar-loom-0.5.0.json",
        "stellar-loom-0.5.0.md",
    ),
    ("theme-forge-solar-sail", "0.3.0", "0.3.0"): (
        "theme-forge-solar-sail-0.3.0.json",
        "solar-sail-0.3.0.md",
    ),
}
TARGETS = ("darwin-arm64", "linux-arm64-gnu", "linux-x64-gnu")
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


def release(pin):
    if not isinstance(pin, dict):
        fail("PIN")
    project = pin.get("project")
    version = pin.get("version")
    distribution_version = pin.get("distribution_version")
    if (not isinstance(project, str)
            or not isinstance(version, str)
            or not isinstance(distribution_version, str)):
        fail("PIN")
    row = RELEASES.get((project, version, distribution_version))
    if row is None:
        fail("PIN")
    return row


def validate_pin(pin):
    if not isinstance(pin, dict) or not isinstance(pin.get("project"), str) or pin["project"] not in PRODUCTS:
        fail("PRODUCT")
    project = pin["project"]
    allowed = {"schema", "project", "version", "distribution_version", "workflow",
               "npm_name", "bins", "node", "license", "asset", "sha256", "size",
               "source_commit", "source_status", "withheld", "candidate_platforms",
               "qualified_platforms", "dependencies", "description"}
    if set(pin) - allowed:
        fail("PIN")
    _, expected_description = release(pin)
    version = pin["version"]
    distribution_version = pin["distribution_version"]
    _, short, bins = PRODUCTS[project]
    expected = {"schema": "rs9.tf-pypi-intake.v2", "version": version,
                "distribution_version": distribution_version,
                "workflow": f"rs9-{short}-pypi-publish.yml",
                "npm_name": "@knowledge-forge-ai/" + project, "bins": bins,
                "node": ">=22", "license": "AGPL-3.0-or-later",
                "asset": f"knowledge-forge-ai-{project}-{version}.tgz",
                "candidate_platforms": list(TARGETS)}
    if any(pin.get(k) != v for k, v in expected.items()):
        fail("PIN")
    if expected_description is None:
        if "description" in pin:
            fail("PIN")
    else:
        name = pin.get("description")
        if (not isinstance(name, str) or Path(name).name != name
                or not name.endswith(".md") or name != expected_description):
            fail("DESCRIPTION")
    if (not re.fullmatch(r"[0-9a-f]{64}", str(pin.get("sha256", "")))
            or type(pin.get("size")) is not int or not 0 < pin["size"] <= 32 * 1024**2
            or not re.fullmatch(r"[0-9a-f]{40}", str(pin.get("source_commit", "")))):
        fail("PIN")
    platforms = pin.get("qualified_platforms")
    if (not isinstance(platforms, list) or any(not isinstance(p, str) for p in platforms)
            or len(platforms) != len(set(platforms))
            or any(p not in TARGETS for p in platforms)):
        fail("PIN")
    if pin.get("source_status") not in {"READY", "BLOCKED"}:
        fail("PIN")
    if "dependencies" in pin:
        from rs9.tf_pypi_closure import dependencies_for_pin
        frozen = dependencies_for_pin(pin)
        dependencies = pin["dependencies"]
        if (project != "theme-forge-stellar-burst" or not isinstance(dependencies, list)
                or len(dependencies) != len(frozen)):
            fail("PIN")
        for dep, frozen_pin in zip(dependencies, frozen):
            if (not isinstance(dep, dict) or set(dep) != set(frozen_pin) | {"integrity", "url"}
                    or any(dep.get(k) != v for k, v in frozen_pin.items())
                    or dep["url"] != "https://registry.npmjs.org/" + dep["name"] + "/-/" + dep["asset"]
                    or not re.fullmatch(r"sha512-[A-Za-z0-9+/]{86}==", dep["integrity"])):
                fail("PIN")
    return pin


def build_pin(pin):
    validate_pin(pin)
    return {**pin, "qualified_platforms": []}


def load_pin(project, path=None):
    if not isinstance(project, str) or project not in PRODUCTS:
        fail("PRODUCT")
    if path is None:
        root = Path(__file__).resolve().parents[2]
        return validate_pin(strict_json(physical_bytes(root / "operators/tf-pypi" / (project + ".json"))))
    if not isinstance(path, (str, os.PathLike)):
        fail("PIN")
    raw_path = os.fspath(path)
    if not isinstance(raw_path, str) or not raw_path or raw_path.endswith(("/", "\\")):
        fail("PIN")
    candidate = Path(raw_path)
    if any(part.is_symlink() for part in (candidate, *candidate.parents)):
        fail("SYMLINK")
    allowed_names = {row[0] for key, row in RELEASES.items() if key[0] == project}
    if candidate.name not in allowed_names:
        fail("PIN")
    pin = strict_json(physical_bytes(candidate))
    if not isinstance(pin, dict) or not isinstance(pin.get("project"), str) or pin.get("project") != project:
        fail("PRODUCT")
    validate_pin(pin)
    if release(pin)[0] != candidate.name:
        fail("PIN")
    return pin


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
