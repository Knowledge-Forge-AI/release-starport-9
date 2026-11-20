"""Authenticate a dependency-free Python CLI's already-captured release pair."""

from __future__ import annotations

import argparse
import configparser
from email import message_from_bytes
import json
from pathlib import Path
import re
import tomllib

from rs9.errors import ContractError
from rs9.release_core import authenticate_release, authenticated_record_hash, capture_release, digest, read_evidence
from rs9.scratch import physical_directory
from rs9.tf_pypi_archive import AdmissionError, read_tar
from rs9.tf_pypi_verify import read_wheel, verify_record

_SLUG = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
_VERSION = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
_TARGET = re.compile(r"([a-zA-Z_]\w*(?:\.[a-zA-Z_]\w*)*):[a-zA-Z_]\w*\Z", re.ASCII)
_LEGAL = ("COMMERCIAL-LICENSE.md", "LICENSE", "NOTICE")
_ASSET_LIMIT = 4 * 1024 * 1024


def _require(ok, code):
    if not ok:
        raise ContractError(code, "Python CLI release evidence was refused")


def _release_bytes(capture, name):
    record = capture.asset_metadata[name]
    body = read_evidence(capture.root, "assets/" + name, _ASSET_LIMIT)
    _require(len(body) == record["size"] and digest(body) == record["sha256"], "PYTHON_CLI_ASSET_CHANGED")
    return body


def _verify_build_source(tagged_body, sdist_body):
    tagged = tomllib.loads(tagged_body.decode("utf-8"))
    selected = tomllib.loads(sdist_body.decode("utf-8"))
    build = tagged.get("build-system", {})
    if build.get("build-backend") == "rs9_build" and build.get("backend-path") == ["packaging"]:
        # The release wrapper delegates to Flit. The sdist ships Flit's backend
        # directly and deliberately omits that repository-only wrapper.
        build.pop("backend-path")
        build["build-backend"] = "flit_core.buildapi"
    _require(tagged == selected, "PYTHON_CLI_SOURCE")
    return tagged["project"]


def _verify_pair(capture, wheel_name, sdist_name, *, stem, name, version, command):
    wheel = read_wheel(_release_bytes(capture, wheel_name), max_total_bytes=16 * 1024 * 1024)
    sdist = read_tar(_release_bytes(capture, sdist_name), stem, max_total_bytes=16 * 1024 * 1024)
    info = stem + ".dist-info/"
    verify_record(wheel, info.rstrip("/"))

    source = capture.source
    project = _verify_build_source(source["pyproject.toml"], sdist[stem + "/pyproject.toml"][0])
    python = project.get("requires-python", "")
    license_expression = project.get("license", "")
    legal = project.get("license-files")
    _require(project.get("name") == name and project.get("version") == version
             and isinstance(python, str) and re.fullmatch(r">=3\.(?:1[1-9]|[2-9][0-9])", python)
             and isinstance(license_expression, str) and bool(license_expression)
             and project.get("dependencies", []) == [] and project.get("optional-dependencies", {}) == {}
             and isinstance(legal, list) and sorted(legal) == list(_LEGAL), "PYTHON_CLI_PROJECT")
    metadata_body = wheel[info + "METADATA"][0]
    _require(sdist[stem + "/PKG-INFO"][0] == metadata_body, "PYTHON_CLI_METADATA")
    metadata = message_from_bytes(metadata_body)
    expected = {"Name": name, "Version": version, "Requires-Python": python,
                "License-Expression": license_expression}
    _require(not metadata.defects and all(metadata.get_all(field) == [value] for field, value in expected.items())
             and metadata.get_all("Requires-Dist") is None
             and metadata.get_all("Provides-Extra") is None
             and sorted(metadata.get_all("License-File", [])) == list(_LEGAL), "PYTHON_CLI_METADATA")

    wheel_header = message_from_bytes(wheel[info + "WHEEL"][0])
    _require(not wheel_header.defects and wheel_header.get_all("Wheel-Version") == ["1.0"]
             and wheel_header.get_all("Root-Is-Purelib") == ["true"]
             and wheel_header.get_all("Tag") == ["py3-none-any"], "PYTHON_CLI_WHEEL_TAG")

    scripts = project.get("scripts", {})
    _require(isinstance(scripts, dict) and scripts.keys() == {command}, "PYTHON_CLI_ENTRY_POINT")
    target = _TARGET.fullmatch(scripts[command]) if isinstance(scripts[command], str) else None
    _require(target is not None, "PYTHON_CLI_ENTRY_POINT")
    parser = configparser.ConfigParser(interpolation=None)
    parser.optionxform = str
    parser.read_string(wheel[info + "entry_points.txt"][0].decode("utf-8"))
    _require(parser.sections() == ["console_scripts"] and not parser.defaults()
             and dict(parser["console_scripts"]) == scripts, "PYTHON_CLI_ENTRY_POINT")
    module_path = target.group(1).replace(".", "/")
    package = module_path.split("/", 1)[0]
    _require(module_path + ".py" in wheel or module_path + "/__init__.py" in wheel, "PYTHON_CLI_ENTRY_POINT")

    allowed_metadata = {info + entry for entry in ("METADATA", "WHEEL", "entry_points.txt", "RECORD")}
    for filename in _LEGAL:
        destination = info + "licenses/" + filename
        allowed_metadata.add(destination)
        _require(wheel[destination][0] == sdist[stem + "/" + filename][0] == source[filename], "PYTHON_CLI_LICENSE")
    package_files = {path: value for path, value in wheel.items() if path.startswith(package + "/")}
    sdist_prefix = stem + "/src/"
    sdist_files = {path.removeprefix(sdist_prefix): value for path, value in sdist.items()
                   if path.startswith(sdist_prefix + package + "/")}
    _require(package + "/__init__.py" in wheel
             and all(not path.casefold().endswith((".so", ".pyd", ".dll", ".dylib", ".pth")) for path in package_files)
             and set(wheel) == allowed_metadata | set(package_files) and package_files == sdist_files,
             "PYTHON_CLI_PAYLOAD")
    return {"entryPoint": scripts[command], "packageMembers": len(package_files), "wheelMembers": len(wheel),
            "requiresPython": python, "license": license_expression}


def inspect_python_cli_release(repository: str, version: str, distribution: str, command: str, evidence: Path,
                               *, fresh_capture=False):
    """Verify a public release capture, optionally collecting it in a fresh directory."""
    _require(len(version) <= 30 and _VERSION.fullmatch(version)
             and len(distribution) <= 64 and _SLUG.fullmatch(distribution)
             and len(command) <= 64 and _SLUG.fullmatch(command), "PYTHON_CLI_COORDINATES")
    stem = distribution.replace("-", "_") + "-" + version
    wheel_name, sdist_name = stem + "-py3-none-any.whl", stem + ".tar.gz"
    selection = {
        "schema": "rs9.release-selection.v1alpha1", "repository": repository, "tag": "v" + version,
        "prerelease": "reject", "checksums": "SHA256SUMS",
        "source_paths": [*_LEGAL, "pyproject.toml"],
        "limits": {"asset_bytes": _ASSET_LIMIT},
        "payload_assets": [{"id": "cli-sdist", "name": sdist_name, "format": "tar.gz", "platforms": ["any"]}],
        "evidence_assets": [{"role": "cli-wheel", "name": wheel_name}],
    }
    if fresh_capture:
        target = physical_directory(evidence.parent) / evidence.name
        try:
            target.mkdir(mode=0o700)
        except FileExistsError:
            raise ContractError("PYTHON_CLI_CAPTURE_EXISTS", "A fresh capture directory is required") from None
        except OSError:
            raise ContractError("PYTHON_CLI_CAPTURE_DIRECTORY", "Cannot create the capture directory") from None
        try:
            capture_release(selection, target, asset_transport="release-api")
        except (AttributeError, KeyError, OSError, TypeError, ValueError):
            raise ContractError("PYTHON_CLI_CAPTURE_FAILED", "The public release capture failed") from None
    capture = authenticate_release(selection, evidence)
    record_digest = authenticated_record_hash(capture)
    try:
        facts = _verify_pair(capture, wheel_name, sdist_name, stem=stem, name=distribution, version=version, command=command)
    except (AdmissionError, AttributeError, KeyError, TypeError, UnicodeError, ValueError, configparser.Error):
        raise ContractError("PYTHON_CLI_ARCHIVE", "Python CLI release archives were refused") from None
    return {"schema": "rs9.python-cli-release.v1alpha1", "repository": repository,
            "version": version, "command": command, "tagCommit": capture.record["tag"]["commit"],
            "releaseRecordSha256": record_digest, "wheelSha256": capture.asset_metadata[wheel_name]["sha256"],
            "sdistSha256": capture.asset_metadata[sdist_name]["sha256"], **facts}


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, "Invalid Python CLI release inspection arguments.\n")


def main(argv=None):
    parser = _Parser(description=__doc__, allow_abbrev=False)
    parser.add_argument("repository", metavar="OWNER/REPO")
    parser.add_argument("--version", required=True)
    parser.add_argument("--distribution", required=True)
    parser.add_argument("--command", required=True)
    origin = parser.add_mutually_exclusive_group(required=True)
    origin.add_argument("--evidence", type=Path, help="inspect an existing capture")
    origin.add_argument("--capture", type=Path, help="collect public release evidence in a new directory and inspect it")
    arguments = parser.parse_args(argv)
    try:
        evidence = arguments.capture if arguments.capture is not None else arguments.evidence
        result = inspect_python_cli_release(arguments.repository, arguments.version, arguments.distribution,
                                            arguments.command, evidence, fresh_capture=arguments.capture is not None)
    except ContractError as error:
        print(json.dumps({"ok": False, "code": error.code}))
        return 1
    print(json.dumps({"ok": True, "result": result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
