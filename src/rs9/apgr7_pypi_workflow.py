"""Fixed pinned downloads and conflict-safe missing-file selection for Trusted Publishing."""
import argparse
import hashlib
import json
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from rs9.apgr7_io import Boundary
from rs9.apgr7_pypi import (
    DEFAULT_VERSION,
    PROJECT_NAME,
    SUPPORTED_VERSIONS,
    manifest_path,
    profile_for_version,
    verify_pins,
)
from rs9.apgr7_python import verify_artifact
from rs9.errors import ContractError
from rs9.release_core import read_evidence
from rs9.security import validate_safe_basename

def _selected_version(manifest, version=None):
    if not isinstance(manifest, dict):
        raise ContractError("APGR7_PYPI_PIN_DRIFT", "Pinned artifact document must be an object")
    selected = version if version is not None else manifest.get("version", DEFAULT_VERSION)
    profile_for_version(selected)
    if manifest.get("version") != selected:
        raise ContractError("APGR7_PYPI_VERSION", "Manifest and selected APGR release versions differ")
    return selected


def _load_manifest(version):
    profile_for_version(version)
    try:
        return json.loads(Path(manifest_path(version)).read_bytes())
    except FileNotFoundError:
        raise ContractError("APGR7_PYPI_PINS_MISSING", f"Versioned APGR {version} pins are not present") from None


def verify_files(root, manifest, *, version=None):
    version = _selected_version(manifest, version)
    verify_pins(pins_doc=manifest, version=version)
    rows = manifest["artifacts"]
    expected_count = len(profile_for_version(version)["artifact_names"])
    if len(rows) != expected_count or len({r["name"] for r in rows}) != expected_count:
        raise ContractError("APGR7_PYPI_SCOPE", f"{expected_count} pinned distributions required")
    if {p.name for p in root.iterdir()} != {r["name"] for r in rows}:
        raise ContractError("APGR7_PYPI_SCOPE", "Staged artifact set differs")
    for row in rows:
        validate_safe_basename(row["name"])
        body = read_evidence(root, row["name"], limit=row["size"])
        if len(body) != row["size"] or hashlib.sha256(body).hexdigest() != row["sha256"]:
            raise ContractError("APGR7_PYPI_DIGEST", "Staged distribution differs from committed pins")
        verify_artifact(row["name"], body, expected_project=PROJECT_NAME,
                        expected_version=version, expected_license="AGPL-3.0-or-later")


def select_missing(root, manifest, io, *, version=None):
    """Verify every existing artifact before removing exact files from the upload set."""
    version = _selected_version(manifest, version)
    verify_files(root, manifest, version=version)
    project = manifest["project"]
    try:
        doc = io.json(f"https://pypi.org/pypi/{project}/{version}/json")
    except ContractError as error:
        if error.code == "REMOTE_ABSENT":
            return [r["name"] for r in manifest["artifacts"]]
        raise
    if not isinstance(doc, dict) or not isinstance(doc.get("urls"), list):
        raise ContractError("REMOTE_UNKNOWN", "Malformed PyPI artifact inventory")
    expected = {r["name"]: r for r in manifest["artifacts"]}
    excluded = {r["name"] for r in manifest.get("excluded", [])}
    exact = set()
    for row in doc["urls"]:
        name = row.get("filename")
        if name in excluded:
            raise ContractError("APGR7_PYPI_CONFLICT", f"Excluded defective artifact present on PyPI: {name}")
        if name not in expected or name in exact:
            raise ContractError("APGR7_PYPI_CONFLICT", "Surplus or duplicate PyPI artifact")
        pin = expected[name]
        if row.get("digests", {}).get("sha256") != pin["sha256"] or row.get("size") != pin["size"]:
            raise ContractError("APGR7_PYPI_CONFLICT", "Existing artifact differs")
        if io.get(row.get("url", "")) != (root / name).read_bytes():
            raise ContractError("APGR7_PYPI_CONFLICT", "Downloaded artifact differs")
        exact.add(name)
    for name in exact:
        (root / name).unlink()
    return sorted(expected.keys() - exact)


def download(root, manifest, *, version=None):
    version = _selected_version(manifest, version)
    verify_pins(pins_doc=manifest, version=version)
    rows = manifest.get("artifacts", [])
    expected_count = len(profile_for_version(version)["artifact_names"])
    if len(rows) != expected_count or len({r["name"] for r in rows}) != expected_count:
        raise ContractError("APGR7_PYPI_SCOPE", f"{expected_count} pinned distributions required")
    excluded = {r["name"] for r in manifest.get("excluded", [])}
    root.mkdir()
    for row in rows:
        validate_safe_basename(row["name"])
        if row["name"] in excluded:
            raise ContractError("APGR7_PYPI_SCOPE", f"Excluded defective artifact in download list: {row['name']}")
        prefix = f"https://github.com/Knowledge-Forge-AI/agentic-praxis-grimoire/releases/download/{profile_for_version(version)['release_tag']}/"
        if row["url"] != prefix + row["name"]:
            raise ContractError("APGR7_PYPI_SCOPE", "Only fixed release URLs allowed")
        with urlopen(Request(row["url"], headers={"User-Agent": "RS9-APGR7/1"}), timeout=60) as response:
            target = urlsplit(response.geturl())
            if (target.scheme != "https" or target.username or target.password or target.port not in (None, 443)
                    or target.hostname not in {"github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"}):
                raise ContractError("APGR7_PYPI_SCOPE", "Release download redirect outside GitHub asset authority")
            body = response.read(row["size"] + 1)
        if len(body) != row["size"] or hashlib.sha256(body).hexdigest() != row["sha256"]:
            raise ContractError("APGR7_PYPI_DIGEST", "Downloaded distribution differs")
        (root / row["name"]).write_bytes(body)
    verify_files(root, manifest, version=version)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("download", "select-missing"))
    parser.add_argument("--version", choices=SUPPORTED_VERSIONS, required=True)
    args = parser.parse_args()
    manifest = _load_manifest(args.version)
    root = Path("dist")
    if args.mode == "download":
        download(root, manifest, version=args.version)
    else:
        missing = select_missing(root, manifest, Boundary(), version=args.version)
        print("upload=" + ("true" if missing else "false"))


if __name__ == "__main__":
    main()
