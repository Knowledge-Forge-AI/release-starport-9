"""Deterministic, non-publishing builder for the Python-only Nebular launcher."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import zipfile

from rs9.archives import inspect_archive
from rs9.errors import ContractError
from rs9.materialize import validate_ancestry_not_symlink
from rs9.nebular070_universal_fetch import _validate_asset, RuntimeDownloadError
from rs9.scratch import canonical
from rs9.verify_wheel import verify_wheel_record_bidirectional
from rs9.wheel import format_record
from rs9.wheel_native import get_embedded_rs9_helpers

PACKAGE = "theme_forge_nebular_fusion"
VERSION = "0.7.0"
DIST_INFO = PACKAGE + "-" + VERSION + ".dist-info"
FILENAME = PACKAGE + "-" + VERSION + "-py3-none-any.whl"
LEGAL_FILES = ("LICENSE", "NOTICE", "COMMERCIAL-LICENSE.md")
LAYOUTS = {
    "darwin-arm64": ("darwin", "aarch64", "13.0", None, "aarch64-apple-darwin.app"),
    "linux-arm64-gnu": ("linux", "aarch64", None, "2.36", "aarch64-unknown-linux-gnu"),
    "linux-x64-gnu": ("linux", "x86_64", None, "2.36", "x86_64-unknown-linux-gnu"),
}


def _fail(code, message):
    raise ContractError("NEBULAR_UNIVERSAL_" + code, message)


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mode,
            info.st_mtime_ns, info.st_ctime_ns, info.st_uid, info.st_gid, info.st_nlink)


def _read(path, limit):
    try:
        path = validate_ancestry_not_symlink(path)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= limit:
                raise ValueError
            data = stream.read(limit + 1)
            identity = _identity(info)
            if (len(data) != info.st_size or identity != _identity(os.fstat(stream.fileno()))
                    or identity != _identity(path.lstat())):
                raise ValueError
        return data, identity
    except (OSError, ValueError):
        _fail("INPUT", "A required input is not an unchanged bounded regular file")


def _inputs(raw):
    try:
        value = json.loads(raw)
        if (set(value) != {"schema", "project", "version", "upstream_release", "native_payload_qualification", "targets"}
                or value["schema"] != "rs9.nebular070-universal-runtime-inputs.v1"
                or value["project"] != "theme-forge-nebular-fusion" or value["version"] != VERSION
                or set(value["targets"]) != set(LAYOUTS)):
            raise ValueError
        release, proof = value["upstream_release"], value["native_payload_qualification"]
        if (set(release) != {"repository", "tag", "commit", "tree"}
                or release["repository"] != "Knowledge-Forge-AI/theme-forge-nebular-fusion"
                or release["tag"] != "v0.7.0"
                or set(proof) != {"run_id", "repository", "source_commit", "source_tree", "qualifies_native_payloads_only"}
                or proof["repository"] != "Knowledge-Forge-AI/release-starport-9"
                or type(proof["run_id"]) is not int or proof["run_id"] <= 0
                or proof["qualifies_native_payloads_only"] is not True):
            raise ValueError
        for item in (release["commit"], release["tree"], proof["source_commit"], proof["source_tree"]):
            if not isinstance(item, str) or not re.fullmatch(r"[0-9a-f]{40}", item):
                raise ValueError
        for key, spec in value["targets"].items():
            family, arch, mac, glibc, triple = LAYOUTS[key]
            root = "Theme Forge Nebular Fusion.app" if family == "darwin" else "theme-forge-nebular-fusion"
            shell = root + ("/Contents/Resources/bin/tfnf" if family == "darwin" else "/bin/tfnf")
            gui = root + ("/Contents/MacOS/theme-forge-nebular-fusion" if family == "darwin" else "/bin/theme-forge-nebular-fusion")
            if (set(spec) != {"family", "arch", "minimum_os", "minimum_glibc", "asset", "manifest_sha256", "root", "shell_target", "gui_target"}
                    or (spec["family"], spec["arch"], spec["minimum_os"], spec["minimum_glibc"]) != (family, arch, mac, glibc)
                    or (spec["root"], spec["shell_target"], spec["gui_target"]) != (root, shell, gui)
                    or not isinstance(spec["manifest_sha256"], str)
                    or not re.fullmatch(r"[0-9a-f]{64}", spec["manifest_sha256"])):
                raise ValueError
            _validate_asset(spec["asset"])
            if spec["asset"]["name"] != "theme-forge-nebular-fusion-v0.7.0-" + triple + ".tar.gz":
                raise ValueError
        return value
    except (ValueError, TypeError, KeyError, UnicodeError, RuntimeDownloadError):
        _fail("PINS", "Runtime input identities or target contracts are invalid")


def _runtime_entries(inputs, archive_dir):
    entries, targets = {}, {}
    for key, spec in sorted(inputs["targets"].items()):
        asset = spec["asset"]
        path = archive_dir / asset["name"]
        data, identity = _read(path, asset["size"])
        if len(data) != asset["size"] or hashlib.sha256(data).hexdigest() != asset["sha256"]:
            _fail("ARCHIVE", "Runtime archive identity differs from its pin")
        del data
        try:
            manifest = inspect_archive(path, commands={})
        except ContractError:
            _fail("ARCHIVE", "Runtime archive inspection failed")
        if (_identity(path.lstat()) != identity or manifest["root"] != spec["root"]
                or manifest["manifest_sha256"] != spec["manifest_sha256"]):
            _fail("MANIFEST", "Runtime member manifest differs from its pin")
        members = {item["path"] for item in manifest["members"]}
        if spec["shell_target"] not in members or spec["gui_target"] not in members:
            _fail("TARGET", "Runtime executable paths are not in the pinned member table")
        raw = canonical(manifest)
        entries[f"{PACKAGE}/runtimes/{key}.json"] = raw
        targets[key] = {name: spec[name] for name in (
            "asset", "root", "manifest_sha256", "shell_target", "gui_target",
        )}
        targets[key]["manifest_resource_sha256"] = hashlib.sha256(raw).hexdigest()
    index = canonical({"schema": "rs9.nebular070-universal-runtime-index.v1", "version": VERSION, "targets": targets})
    entries[f"{PACKAGE}/runtime-index.json"] = index
    return entries, hashlib.sha256(index).hexdigest()


def _archive(entries):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(entries.items()):
            data.decode("utf-8")
            info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(info, data, compresslevel=9)
    return output.getvalue()


def _write(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    if _read(path, len(data))[0] != data:
        _fail("OUTPUT", "Written artifact identity differs")


def build_universal_wheel(runtime_inputs, archives_dir, description, output_dir, *, legal_root=None):
    """Construct text-only package bytes; this function supplies no publication authority."""
    raw_inputs, _ = _read(Path(runtime_inputs), 65536)
    inputs = _inputs(raw_inputs)
    entries, index_sha256 = _runtime_entries(inputs, Path(archives_dir))
    source_dir = Path(__file__).resolve().parent
    launcher, _ = _read(source_dir / "nebular070_universal_launcher.py", 262144)
    fetcher, _ = _read(source_dir / "nebular070_universal_fetch.py", 262144)
    marker = b"__TFNF_INDEX_SHA256__"
    if launcher.count(marker) != 1:
        _fail("SOURCE", "Launcher index marker is not unique")
    entries[f"{PACKAGE}/launcher.py"] = launcher.replace(marker, index_sha256.encode("ascii"))
    entries[f"{PACKAGE}/_fetch.py"] = fetcher
    entries[f"{PACKAGE}/__init__.py"] = ('"""Theme Forge Nebular Fusion Python launcher."""\n__version__ = "0.7.0"\n').encode()
    for name, source in get_embedded_rs9_helpers().items():
        entries[f"{PACKAGE}/_isolated/{name}"] = source
    raw_description, _ = _read(Path(description), 262144)
    raw_description.decode("utf-8")
    root = Path(legal_root) if legal_root is not None else source_dir.parents[1]
    for name in LEGAL_FILES:
        entries[f"{DIST_INFO}/licenses/{name}"] = _read(root / name, 2 * 1024 * 1024)[0]
    entries[f"{DIST_INFO}/METADATA"] = (
        "Metadata-Version: 2.4\nName: theme-forge-nebular-fusion\nVersion: 0.7.0\n"
        "Summary: Theme Forge Nebular Fusion desktop application launcher\n"
        "License-Expression: AGPL-3.0-or-later\n"
        + "".join("License-File: " + name + "\n" for name in LEGAL_FILES)
        + "Requires-Python: >=3.10\n"
        "Project-URL: Source, https://github.com/Knowledge-Forge-AI/theme-forge-nebular-fusion\n"
        "Project-URL: Packaging source, https://github.com/Knowledge-Forge-AI/release-starport-9\n"
        "Description-Content-Type: text/markdown\n\n"
    ).encode() + raw_description
    entries[f"{DIST_INFO}/WHEEL"] = b"Wheel-Version: 1.0\nGenerator: rs9-nebular-universal (1.0)\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
    entries[f"{DIST_INFO}/entry_points.txt"] = f"[console_scripts]\ntfnf = {PACKAGE}.launcher:main_tfnf\n".encode()
    provenance = {
        "schema": "rs9.nebular070-universal-package.v1", "builder_can_publish": False,
        "runtime_inputs_sha256": hashlib.sha256(raw_inputs).hexdigest(), "runtime_inputs": inputs,
        "runtime_index_sha256": index_sha256,
        "package_sources": {"launcher.py": hashlib.sha256(launcher).hexdigest(),
                            "_fetch.py": hashlib.sha256(fetcher).hexdigest()},
        "description_sha256": hashlib.sha256(raw_description).hexdigest(),
    }
    entries[f"{PACKAGE}/_rs9/provenance.json"] = canonical(provenance)
    entries[f"{DIST_INFO}/RECORD"] = format_record(entries, DIST_INFO)
    data = _archive(entries)
    output = validate_ancestry_not_symlink(output_dir)
    output.mkdir(parents=True, mode=0o700, exist_ok=True)
    if (output / FILENAME).exists() or (output / FILENAME).is_symlink():
        _fail("OUTPUT", "The output artifact already exists")
    if (output / "universal-build-receipt.json").exists():
        _fail("OUTPUT", "The output receipt already exists")
    _write(output / FILENAME, data)
    verify_wheel_record_bidirectional(output / FILENAME)
    result = {"schema": "rs9.nebular070-universal-build.v1", "builder_can_publish": False,
              "filename": FILENAME, "tag": "py3-none-any", "size": len(data),
              "sha256": hashlib.sha256(data).hexdigest(), "runtime_index_sha256": index_sha256,
              "runtime_inputs_sha256": hashlib.sha256(raw_inputs).hexdigest(), "targets": sorted(inputs["targets"])}
    _write(output / "universal-build-receipt.json", canonical(result))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-inputs", required=True, type=Path)
    parser.add_argument("--archives-dir", required=True, type=Path)
    parser.add_argument("--description", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args(argv)
    result = build_universal_wheel(args.runtime_inputs, args.archives_dir, args.description, args.output_dir)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
