"""Authenticated dependency closure for frozen Theme Forge Node CLI payloads.

Enforces offline deterministic dependency resolution, byte qualification,
hostile archive admission, and strict licensing boundaries.
"""

import os
from pathlib import Path
import re
import typing

from rs9.tf_pypi_archive import fail, physical_bytes, read_tar, sha256
from rs9.tf_pypi_model import LEGAL, NATIVE_MAGIC, PRODUCTS, strict_json, validate_pin

INSTALL_LIFECYCLE_SCRIPTS = (
    "preinstall",
    "install",
    "postinstall",
    "preprepare",
    "prepare",
    "postprepare",
)

_PIN_FIELDS = ("name", "version", "asset", "size", "sha256", "license")


class DependencyPin(dict):
    """Immutable-style pinned dependency metadata supporting dict, attr, and index access."""

    def __init__(self, *args: typing.Any, **kwargs: typing.Any) -> None:
        if len(args) == 6 and not kwargs:
            super().__init__(zip(_PIN_FIELDS, args))
        elif len(args) == 1 and isinstance(args[0], (tuple, list)) and len(args[0]) == 6 and not kwargs:
            super().__init__(zip(_PIN_FIELDS, args[0]))
        else:
            super().__init__(*args, **kwargs)

    def __getattr__(self, name: str) -> typing.Any:
        try:
            return self[name]
        except KeyError:
            raise AttributeError(f"'DependencyPin' object has no attribute {name!r}")

    def __setattr__(self, name: str, value: typing.Any) -> None:
        self[name] = value

    def __getitem__(self, item: typing.Union[str, int]) -> typing.Any:
        if isinstance(item, int):
            return self[_PIN_FIELDS[item]]
        return super().__getitem__(item)


DEPENDENCIES: list[DependencyPin] = [
    DependencyPin(
        name="@xmldom/xmldom",
        version="0.9.12",
        asset="xmldom-0.9.12.tgz",
        size=109708,
        sha256="08245e18c248b957b4c6e07f8549ad5f55ae11b7a8abd4c1113a0fd61ddc67ee",
        license="MIT",
    ),
    DependencyPin(
        name="fflate",
        version="0.8.3",
        asset="fflate-0.8.3.tgz",
        size=173034,
        sha256="38c2cd824402407b43153c782274aec2ea83ea688e4aa0b743c5f2c305857d92",
        license="MIT",
    ),
    DependencyPin(
        name="smol-toml",
        version="1.8.0",
        asset="smol-toml-1.8.0.tgz",
        size=23162,
        sha256="1fc995be91cdb777fc13e20c2edfebaaf60ef4e4d2d5331caef2837b04d37892",
        license="BSD-3-Clause",
    ),
]

BURST_070_DEPENDENCIES: list[DependencyPin] = [
    DependencyPin(
        name="@xmldom/xmldom",
        version="0.9.12",
        asset="xmldom-0.9.12.tgz",
        size=109708,
        sha256="08245e18c248b957b4c6e07f8549ad5f55ae11b7a8abd4c1113a0fd61ddc67ee",
        license="MIT",
    ),
    DependencyPin(
        name="fflate",
        version="0.8.3",
        asset="fflate-0.8.3.tgz",
        size=173034,
        sha256="38c2cd824402407b43153c782274aec2ea83ea688e4aa0b743c5f2c305857d92",
        license="MIT",
    ),
    DependencyPin(
        name="smol-toml",
        version="1.9.1",
        asset="smol-toml-1.9.1.tgz",
        size=31492,
        sha256="4ac8392f1918c22a4366be19047cf53aa42646077d4c711b2ef73263beefb172",
        license="BSD-3-Clause",
    ),
]

DEPENDENCIES_BY_ASSET: dict[str, DependencyPin] = {d["asset"]: d for d in DEPENDENCIES}
DEPENDENCIES_BY_NAME: dict[str, DependencyPin] = {d["name"]: d for d in DEPENDENCIES}


def dependencies_for_pin(pin: typing.Any) -> list[DependencyPin]:
    """Select the exact per-release dependency authority without changing legacy pins."""
    if (isinstance(pin, dict)
            and pin.get("project") == "theme-forge-stellar-burst"
            and pin.get("version") == "0.7.0"):
        return BURST_070_DEPENDENCIES
    return DEPENDENCIES


def _extract_pin(pin: typing.Any) -> tuple[str, str, str, int, str, str]:
    if isinstance(pin, dict):
        name = pin.get("name")
        version = pin.get("version")
        asset = pin.get("asset")
        size = pin.get("size")
        digest = pin.get("sha256")
        license_str = pin.get("license")
    elif isinstance(pin, (tuple, list)):
        if len(pin) != 6:
            fail("PIN")
        name, version, asset, size, digest, license_str = pin
    elif hasattr(pin, "name") and hasattr(pin, "version"):
        name = getattr(pin, "name", None)
        version = getattr(pin, "version", None)
        asset = getattr(pin, "asset", None)
        size = getattr(pin, "size", None)
        digest = getattr(pin, "sha256", None)
        license_str = getattr(pin, "license", None)
    else:
        fail("PIN")

    if not isinstance(name, str) or not name:
        fail("PIN")
    if not isinstance(version, str) or not version:
        fail("PIN")
    if not isinstance(asset, str) or not asset.endswith(".tgz"):
        fail("PIN")
    if type(size) is not int or size <= 0:
        fail("PIN")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", str(digest)):
        fail("PIN")
    if not isinstance(license_str, str) or not license_str:
        fail("PIN")

    return name, version, asset, size, digest, license_str


def admit_dependency(pin: typing.Any, data: bytes) -> dict[str, tuple[bytes, int]]:
    """Validate exact size/hash, hostile tar admission, strict inner identity, and safety."""
    name, version, asset, size, digest, license_str = _extract_pin(pin)
    if not isinstance(data, (bytes, bytearray)):
        fail("ARCHIVE")
    if len(data) != size:
        fail("SIZE")
    if sha256(data) != digest:
        fail("HASH")

    files = read_tar(data, root="package")
    if "package/package.json" not in files:
        fail("PACKAGE")
    pkg = strict_json(files["package/package.json"][0])
    if not isinstance(pkg, dict):
        fail("PACKAGE")

    if pkg.get("name") != name:
        fail("NAME")
    if pkg.get("version") != version:
        fail("VERSION")
    if pkg.get("license") != license_str:
        fail("LICENSE")
    if "package/LICENSE" not in files or not files["package/LICENSE"][0]:
        fail("LICENSE")

    for key in (
        "dependencies",
        "optionalDependencies",
        "peerDependencies",
        "bundledDependencies",
        "bundleDependencies",
    ):
        if pkg.get(key):
            fail("DEPENDENCY")

    scripts = pkg.get("scripts")
    if scripts is not None:
        if not isinstance(scripts, dict):
            fail("PACKAGE")
        for s in INSTALL_LIFECYCLE_SCRIPTS:
            if s in scripts:
                fail("INSTALL_SCRIPT")

    if "package/binding.gyp" in files:
        fail("INSTALL_SCRIPT")

    for p, (content, _) in files.items():
        if p.lower().endswith((".node", ".so", ".dylib", ".dll", ".exe", ".a")) or content.startswith(NATIVE_MAGIC):
            fail("NATIVE_UNQUALIFIED")
        if "node_modules" in p.split("/"):
            fail("DEPENDENCY")
        if p.endswith("/package.json") and p != "package/package.json":
            nested_pkg = strict_json(content)
            if not isinstance(nested_pkg, dict):
                fail("PACKAGE")
            for key in (
                "dependencies",
                "optionalDependencies",
                "peerDependencies",
                "bundledDependencies",
                "bundleDependencies",
            ):
                if nested_pkg.get(key):
                    fail("DEPENDENCY")
            nested_scripts = nested_pkg.get("scripts")
            if isinstance(nested_scripts, dict):
                for s in INSTALL_LIFECYCLE_SCRIPTS:
                    if s in nested_scripts:
                        fail("INSTALL_SCRIPT")

    return files


def closure_payload(
    pin: dict[str, typing.Any],
    files: dict[str, tuple[bytes, int]],
    dependencies: typing.Optional[typing.Mapping[str, bytes]] = None,
) -> dict[str, tuple[bytes, int]]:
    """Accept product pin, upstream files, and dependency map, producing authenticated closure."""
    validate_pin(pin)
    project = pin["project"]

    if "package/package.json" not in files:
        fail("PACKAGE")
    upstream_pkg = strict_json(files["package/package.json"][0])
    if not isinstance(upstream_pkg, dict):
        fail("PACKAGE")
    if any("node_modules" in p.split("/") for p in files):
        fail("DEPENDENCY")

    if project in ("theme-forge-stellar-loom", "theme-forge-solar-sail"):
        if dependencies:
            fail("DEPENDENCY")
        for key in (
            "dependencies",
            "optionalDependencies",
            "peerDependencies",
            "bundledDependencies",
            "bundleDependencies",
        ):
            if upstream_pkg.get(key):
                fail("DEPENDENCY")
        return dict(sorted(files.items()))

    if project == "theme-forge-stellar-burst":
        pins = dependencies_for_pin(pin)
        expected_deps = {p["name"]: p["version"] for p in pins}
        if upstream_pkg.get("dependencies") != expected_deps:
            fail("DEPENDENCY")
        for key in (
            "optionalDependencies",
            "peerDependencies",
            "bundledDependencies",
            "bundleDependencies",
        ):
            if upstream_pkg.get(key):
                fail("DEPENDENCY")

        if not isinstance(dependencies, typing.Mapping):
            fail("DEPENDENCY")
        expected_assets = {p["asset"] for p in pins}
        if set(dependencies.keys()) != expected_assets:
            fail("DEPENDENCY")

        result = dict(files)
        for dep_pin in pins:
            asset = dep_pin["asset"]
            data = dependencies[asset]
            dep_files = admit_dependency(dep_pin, data)
            dep_name = dep_pin["name"]
            for path, (body, mode) in dep_files.items():
                if not path.startswith("package/"):
                    fail("ARCHIVE")
                rel = path[len("package/") :]
                target_path = f"package/node_modules/{dep_name}/{rel}"
                if target_path in result:
                    fail("DUPLICATE")
                result[target_path] = (body, mode)

        return dict(sorted(result.items()))

    fail("PRODUCT")


def dependency_licenses(
    dependencies: typing.Mapping[str, typing.Any],
    pins: typing.Optional[typing.Iterable[typing.Mapping[str, typing.Any]]] = None,
) -> dict[str, tuple[bytes, int]]:
    """Return dict of relative 'node_modules/<name>/LICENSE' -> (bytes, mode) for legal_files."""
    if not isinstance(dependencies, typing.Mapping):
        fail("DEPENDENCY")
    if not dependencies:
        return {}

    sample_val = next(iter(dependencies.values()), None)
    if isinstance(sample_val, tuple) and len(sample_val) == 2 and isinstance(sample_val[0], (bytes, bytearray)):
        result = {}
        for path, (data, mode) in sorted(dependencies.items()):
            clean = path[len("package/") :] if path.startswith("package/") else path
            parts = clean.split("/")
            if len(parts) >= 3 and parts[0] == "node_modules" and parts[-1] in LEGAL:
                result[clean] = (data, mode)
        return dict(sorted(result.items()))

    frozen = DEPENDENCIES if pins is None else list(pins)
    by_asset = {pin["asset"]: pin for pin in frozen}
    result = {}
    for asset, data in sorted(dependencies.items()):
        if asset not in by_asset:
            fail("DEPENDENCY")
        pin = by_asset[asset]
        dep_files = admit_dependency(pin, data)
        for legal in LEGAL:
            path = f"package/{legal}"
            if path in dep_files:
                result[f"node_modules/{pin['name']}/{legal}"] = dep_files[path]
    return dict(sorted(result.items()))


def load_dependencies(
    directory: typing.Union[str, os.PathLike],
    pins: typing.Optional[typing.Iterable[typing.Mapping[str, typing.Any]]] = None,
) -> dict[str, bytes]:
    """Read regular physical bytes for each pinned dependency from directory."""
    dir_path = Path(directory)
    frozen = DEPENDENCIES if pins is None else list(pins)
    result = {}
    for pin in frozen:
        asset_path = dir_path / pin["asset"]
        data = physical_bytes(asset_path, limit=pin["size"] + 1)
        if len(data) != pin["size"]:
            fail("SIZE")
        if sha256(data) != pin["sha256"]:
            fail("HASH")
        result[pin["asset"]] = data
    return result
