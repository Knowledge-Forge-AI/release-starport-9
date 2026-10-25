"""Offline PEP 517 adapter for the frozen dependency-free Node CLI payloads.

All first-wave products remain publication-blocked until real-byte qualification.
This module and its stdlib-only helpers are copied unchanged into each sdist.
"""
import base64
import csv
import hashlib
import io
import json
from pathlib import Path
import stat
import tarfile
import zipfile
import zlib

from rs9.tf_pypi_archive import AdmissionError, canonical, fail, physical_bytes
from rs9.tf_pypi_model import (LEGAL, admit_bytes, build_pin, logical_identity,
                            pure_payload, release, strict_json, validate_pin)
from rs9.tf_pypi_closure import DEPENDENCIES, closure_payload, dependency_licenses
from rs9.tf_pypi_native import select_native
from rs9.tf_pypi_platform import build_target, check_tag, pure_tag

HELPERS = ("tf_pypi_archive.py", "tf_pypi_model.py", "tf_pypi_launcher.py", "tf_pypi_backend.py",
           "tf_pypi_closure.py", "tf_pypi_native.py", "tf_pypi_platform.py")
PYTHON_FLOOR = ">=3.9"
SUMMARY = "Python adapter for the frozen Theme Forge Node CLI"
CLASSIFIERS = ("Environment :: Console", "Operating System :: POSIX")
PROHIBITED_README_TEXT = (
    "Artifact platforms:",
    "Other hosts are refused",
    "RS9_TF_PYPI",
    "/" + "Users/",
)
ADAPTER_NOTICE = (
    "Release Starport 9 Python adapter\n\n"
    "Copyright (c) 2026 Samuel Leighton Lair and Release Starport 9 contributors.\n\n"
    "The RS9-authored launcher, build backend and helper modules are licensed under "
    "the GNU Affero General Public License v3.0 or later. See LICENSE.\n"
    "Upstream payload bytes and notices retain their original licensing terms.\n"
).encode()


def names(pin):
    validate_pin(pin)
    package = pin["project"].replace("-", "_")
    stem = package + "-" + pin["distribution_version"]
    return package, stem, stem + ".dist-info"


def description_name(pin):
    validate_pin(pin)
    _, versioned = release(pin)
    if versioned is not None:
        name = pin.get("description")
        if not isinstance(name, str) or Path(name).name != name or not name.endswith(".md") or name != versioned:
            fail("DESCRIPTION")
        return name
    prefix = "theme-forge-"
    project = pin["project"]
    if not project.startswith(prefix):
        fail("PRODUCT")
    return project[len(prefix):] + ".md"


def description_bytes(pin):
    name = description_name(pin)
    packaged = Path(__file__).resolve().with_name("descriptions") / name
    source = packaged if packaged.exists() else (
        Path(__file__).resolve().parents[2] / "operators/tf-pypi/descriptions" / name)
    try:
        raw = physical_bytes(source, limit=65536)
    except AdmissionError as err:
        if err.code == "TF_PYPI_SYMLINK":
            raise
        fail("DESCRIPTION")
    if len(raw) < 512 or b"\r" in raw or b"\x00" in raw or not raw.endswith(b"\n"):
        fail("DESCRIPTION")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        fail("DESCRIPTION")
    if (any(ord(ch) < 32 and ch not in ("\n", "\t") for ch in text)
            or any(token in text for token in PROHIBITED_README_TEXT)):
        fail("DESCRIPTION")
    return raw


def description(pin):
    return description_bytes(pin).decode("utf-8")


def adapter_license():
    helper = Path(__file__).resolve().with_name("RS9-LICENSE")
    return physical_bytes(helper if helper.exists() else Path(__file__).resolve().parents[2] / "LICENSE")


def license_expression(pin):
    terms = ["AGPL-3.0-or-later"]
    if pin["project"] == "theme-forge-stellar-burst":
        terms += ["MIT", "BSD-3-Clause"]
    return " AND ".join(terms)


def legal_files(files, dependencies=None):
    result = {name: files["package/" + name] for name in LEGAL if "package/" + name in files}
    result["RS9-NOTICE"] = (ADAPTER_NOTICE, 0o644)
    result["RS9-LICENSE"] = (adapter_license(), 0o644)
    if dependencies:
        result.update(dependency_licenses(dependencies))
    return result


def project_urls(pin):
    base = "https://github.com/Knowledge-Forge-AI/" + pin["project"]
    return {"Source": base + "/tree/" + pin["source_commit"],
            "Release": base + "/releases/tag/v" + pin["version"]}


def metadata(pin, files, dependencies=None):
    validate_pin(pin)
    headers = ["Metadata-Version: 2.4", "Name: " + pin["project"],
               "Version: " + pin["distribution_version"], "Summary: " + SUMMARY,
               "Requires-Python: " + PYTHON_FLOOR, "Requires-External: nodejs (>=22)",
               "License-Expression: " + license_expression(pin), "Description-Content-Type: text/markdown"]
    headers += ["Classifier: " + item for item in CLASSIFIERS]
    headers += ["Project-URL: " + label + ", " + url for label, url in project_urls(pin).items()]
    headers += ["License-File: " + name for name in sorted(legal_files(files, dependencies))]
    return ("\n".join(headers) + "\n\n" + description(pin)).encode()


def payload(pin, data, dependencies=None, target=None):
    files = admit_bytes(pin, data, pin["asset"])
    target = build_target(pin, target)
    if pin["project"] == "theme-forge-stellar-burst":
        if not dependencies:
            fail("NATIVE_UNQUALIFIED")
        for dep in pin.get("dependencies", []):
            body = dependencies.get(dep["asset"], b"")
            integrity = "sha512-" + base64.b64encode(hashlib.sha512(body).digest()).decode()
            if dep["integrity"] != integrity:
                fail("DEPENDENCY_INTEGRITY")
        files = closure_payload(pin, files, dependencies)
        files, tag, transform = select_native(files, target)
    else:
        pure_payload(files)
        files = closure_payload(pin, files, dependencies or {})
        tag, transform = pure_tag(target), {"target_key": target, "omissions": []}
    check_tag(pin, target, tag)
    transform.update(source_sha256=pin["sha256"], dependencies={
        name: __import__("hashlib").sha256(body).hexdigest() for name, body in sorted((dependencies or {}).items())})
    return files, tag, transform


def wheel_entries(pin, data, dependencies=None, target=None):
    files, tag, transform = payload(pin, data, dependencies, target)
    package, _, info = names(pin)
    entries = {f"{package}/payload/{p}": value for p, value in files.items()}
    launcher = physical_bytes(Path(__file__).resolve().with_name("tf_pypi_launcher.py"))
    launcher += ("\nTARGETS = " + repr(pin["bins"]) + "\n").encode()
    launcher += ("PLATFORM_KEY = " + repr(transform["target_key"]) + "\n").encode()
    if tag.startswith("manylinux_2_"):
        launcher += ("MIN_GLIBC = (2, " + tag.split("_")[2] + ")\n").encode()
    scripts = ["[console_scripts]"]
    for command in sorted(pin["bins"]):
        function = "main_" + command.replace("-", "_")
        launcher += f"\ndef {function}():\n    run({command!r})\n".encode()
        scripts.append(f"{command} = {package}.launcher:{function}")
    entries.update({f"{package}/__init__.py": (b"", 0o644),
                    f"{package}/launcher.py": (launcher, 0o644),
                    info + "/METADATA": (metadata(pin, files, dependencies), 0o644),
                    info + "/entry_points.txt": (("\n".join(scripts) + "\n").encode(), 0o644),
                    info + "/WHEEL": (("Wheel-Version: 1.0\nGenerator: rs9-tf-pypi\nRoot-Is-Purelib: false\nTag: py3-none-" + tag + "\n").encode(), 0o644),
                    info + "/rs9-tf-transform.json": (canonical(transform), 0o644)})
    entries.update({info + "/licenses/" + p: v for p, v in legal_files(files, dependencies).items()})
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    for path, (body, _) in sorted(entries.items()):
        digest = base64.urlsafe_b64encode(hashlib.sha256(body).digest()).decode().rstrip("=")
        writer.writerow([path, "sha256=" + digest, len(body)])
    writer.writerow([info + "/RECORD", "", ""])
    entries[info + "/RECORD"] = (output.getvalue().encode(), 0o644)
    return entries


def write_zip(files):
    # ZIP_STORED avoids cross-host zlib differences and preserves reproducible bytes.
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, (body, mode) in sorted(files.items()):
            entry = zipfile.ZipInfo(name, (2020, 1, 1, 0, 0, 0))
            entry.create_system = 3
            entry.external_attr = (stat.S_IFREG | mode) << 16
            archive.writestr(entry, body)
    return output.getvalue()


def write_tar(files, root):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name, (body, mode) in sorted(files.items()):
            entry = tarfile.TarInfo(root + "/" + name)
            entry.size, entry.mode, entry.mtime = len(body), mode, 0
            archive.addfile(entry, io.BytesIO(body))
    raw = output.getvalue()
    # RFC 1952 header and stored DEFLATE blocks; independent of zlib compressor versions.
    compressed = bytearray(b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff")
    for start in range(0, len(raw), 65535):
        block = raw[start:start + 65535]
        compressed.append(int(start + len(block) == len(raw)))
        compressed.extend(len(block).to_bytes(2, "little"))
        compressed.extend((65535 - len(block)).to_bytes(2, "little"))
        compressed.extend(block)
    compressed.extend((zlib.crc32(raw) & 0xffffffff).to_bytes(4, "little"))
    compressed.extend((len(raw) & 0xffffffff).to_bytes(4, "little"))
    return bytes(compressed)


def project_toml(pin, files, dependencies=None):
    validate_pin(pin)
    value = json.dumps
    lines = ['[build-system]', 'requires = []', 'build-backend = "rs9.tf_pypi_backend"',
             'backend-path = ["_rs9_build"]', '', '[project]', 'name = ' + value(pin['project']),
             'version = ' + value(pin['distribution_version']), 'requires-python = ' + value(PYTHON_FLOOR),
             'description = ' + value(SUMMARY), 'classifiers = ' + value(CLASSIFIERS),
             'license = ' + value(license_expression(pin)), 'license-files = ' + value(sorted(legal_files(files, dependencies))),
             'readme = {file = "README.md", content-type = "text/markdown"}', 'dynamic = []',
             '', '[project.urls]']
    lines += [value(label) + ' = ' + value(url) for label, url in project_urls(pin).items()]
    lines += ['', '[project.scripts]']
    package, _, _ = names(pin)
    for command in sorted(pin["bins"]):
        lines.append(value(command) + ' = ' + value(package + ".launcher:main_" + command.replace('-', '_')))
    return ("\n".join(lines) + "\n").encode()


def sdist_entries(pin, data, dependencies=None, target=None):
    files, _, _ = payload(pin, data, dependencies, target)
    desc = description_bytes(pin)
    result = {"PKG-INFO": (metadata(pin, files, dependencies), 0o644),
              "pyproject.toml": (project_toml(pin, files, dependencies), 0o644),
              "README.md": (desc, 0o644),
              "upstream/" + pin["asset"]: (data, 0o644),
              "_rs9_build/rs9/__init__.py": (b"", 0o644),
              "_rs9_build/rs9/pins.json": (canonical(build_pin(pin)), 0o644),
              "_rs9_build/rs9/descriptions/" + description_name(pin): (desc, 0o644)}
    result.update(legal_files(files, dependencies))
    result["_rs9_build/rs9/RS9-LICENSE"] = (adapter_license(), 0o644)
    result.update({"upstream/" + name: (body, 0o644) for name, body in (dependencies or {}).items()})
    for helper in HELPERS:
        result["_rs9_build/rs9/" + helper] = (physical_bytes(Path(__file__).resolve().with_name(helper)), 0o644)
    return result


def build_pair(pin, data, output, dependencies=None, target=None):
    """Build a local unqualified candidate; never confers publication admission."""
    validate_pin(pin)
    _, stem, _ = names(pin)
    files, tag, _ = payload(pin, data, dependencies, target)
    wheel, sdist = stem + "-py3-none-" + tag + ".whl", stem + ".tar.gz"
    wheel_data = write_zip(wheel_entries(pin, data, dependencies, target))
    sdist_data = write_tar(sdist_entries(pin, data, dependencies, target), stem)
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    for name, body in ((wheel, wheel_data), (sdist, sdist_data)):
        with (output / name).open("xb") as stream:
            stream.write(body)
    return {"wheel": wheel, "sdist": sdist,
            "payload_identity": logical_identity(files), "publication_admitted": False}


def build_aggregate(pin, data, output, dependencies=None):
    """Build the closed three-wheel plus common-sdist candidate aggregate."""
    validate_pin(pin)
    targets = list(pin["candidate_platforms"])
    _, stem, _ = names(pin)
    sdist = stem + ".tar.gz"
    wheels, wheel_blobs, sdist_sets = [], [], []
    for target in targets:
        _, tag, _ = payload(pin, data, dependencies, target)
        wheel = stem + "-py3-none-" + tag + ".whl"
        wheels.append(wheel)
        wheel_blobs.append((wheel, write_zip(wheel_entries(pin, data, dependencies, target))))
        sdist_sets.append(sdist_entries(pin, data, dependencies, target))
    common_sdist = sdist_sets[0]
    if any(entries != common_sdist for entries in sdist_sets[1:]):
        fail("SDIST_DIVERGENT")
    sdist_data = write_tar(common_sdist, stem)
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    for name, body in [*wheel_blobs, (sdist, sdist_data)]:
        with (output / name).open("xb") as stream:
            stream.write(body)
    return {"wheels": wheels, "sdist": sdist,
            "payload_identity": logical_identity(common_sdist), "publication_admitted": False}


def _inputs(config_settings):
    if config_settings:
        fail("BUILD_SETTINGS")
    # Resolve only this already imported backend's location. Untrusted archive and
    # artifact paths still use descriptor-relative no-follow reads unchanged.
    pin = validate_pin(strict_json(physical_bytes(Path(__file__).resolve().with_name("pins.json"))))
    data = physical_bytes(Path.cwd() / "upstream" / pin["asset"])
    dependencies = {p["asset"]: physical_bytes(Path.cwd() / "upstream" / p["asset"])
                    for p in DEPENDENCIES} if pin["project"] == "theme-forge-stellar-burst" else {}
    files, _, _ = payload(pin, data, dependencies)
    if (physical_bytes(Path.cwd() / "pyproject.toml") != project_toml(pin, files, dependencies)
            or physical_bytes(Path.cwd() / "README.md") != description(pin).encode()):
        fail("BUILD_METADATA")
    return pin, data, dependencies


def get_requires_for_build_wheel(config_settings=None):
    _inputs(config_settings)
    return []


get_requires_for_build_sdist = get_requires_for_build_wheel


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    pin, data, dependencies = _inputs(config_settings)
    files = wheel_entries(pin, data, dependencies)
    if metadata_directory:
        _, _, info = names(pin)
        if physical_bytes(Path(metadata_directory) / "METADATA") != files[info + "/METADATA"][0]:
            fail("METADATA")
    name = names(pin)[1] + "-py3-none-" + payload(pin, data, dependencies)[1] + ".whl"
    Path(wheel_directory).mkdir(parents=True, exist_ok=True)
    Path(wheel_directory, name).write_bytes(write_zip(files))
    return name


def build_sdist(sdist_directory, config_settings=None):
    pin, data, dependencies = _inputs(config_settings)
    stem = names(pin)[1]
    Path(sdist_directory).mkdir(parents=True, exist_ok=True)
    Path(sdist_directory, stem + ".tar.gz").write_bytes(write_tar(sdist_entries(pin, data, dependencies), stem))
    return stem + ".tar.gz"
