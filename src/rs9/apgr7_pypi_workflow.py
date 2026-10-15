"""Fixed pinned downloads and conflict-safe missing-file selection for Trusted Publishing."""
import argparse
import hashlib
import json
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from rs9.apgr7_io import Boundary
from rs9.apgr7_python import verify_artifact
from rs9.errors import ContractError
from rs9.security import validate_safe_basename
from rs9.release_core import read_evidence


EXPECTED_ARTIFACT_COUNT = 3


def verify_files(root, manifest):
    from rs9.apgr7_pypi import verify_pins
    verify_pins(pins_doc=manifest)
    rows = manifest["artifacts"]
    if len(rows) != EXPECTED_ARTIFACT_COUNT or len({r["name"] for r in rows}) != EXPECTED_ARTIFACT_COUNT:
        raise ContractError("APGR7_PYPI_SCOPE", "Three pinned distributions required")
    if {p.name for p in root.iterdir()} != {r["name"] for r in rows}:
        raise ContractError("APGR7_PYPI_SCOPE", "Staged artifact set differs")
    for row in rows:
        validate_safe_basename(row["name"])
        body = read_evidence(root, row["name"], limit=row["size"])
        if len(body) != row["size"] or hashlib.sha256(body).hexdigest() != row["sha256"]:
            raise ContractError("APGR7_PYPI_DIGEST", "Staged distribution differs from committed pins")
        verify_artifact(row["name"], body, expected_project="agentic-praxis-grimoire",
                        expected_version="0.13.0", expected_license="AGPL-3.0-or-later")


def select_missing(root, manifest, io):
    """Verify every existing artifact before removing exact files from the upload set."""
    verify_files(root, manifest)
    try:
        doc = io.json("https://pypi.org/pypi/agentic-praxis-grimoire/0.13.0/json")
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


def download(root, manifest):
    from rs9.apgr7_pypi import verify_pins
    verify_pins(pins_doc=manifest)
    rows = manifest.get("artifacts", [])
    if len(rows) != EXPECTED_ARTIFACT_COUNT or len({r["name"] for r in rows}) != EXPECTED_ARTIFACT_COUNT:
        raise ContractError("APGR7_PYPI_SCOPE", "Three pinned distributions required")
    excluded = {r["name"] for r in manifest.get("excluded", [])}
    root.mkdir()
    for row in rows:
        validate_safe_basename(row["name"])
        if row["name"] in excluded:
            raise ContractError("APGR7_PYPI_SCOPE", f"Excluded defective artifact in download list: {row['name']}")
        prefix = "https://github.com/Knowledge-Forge-AI/agentic-praxis-grimoire/releases/download/v0.13.0/"
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
    verify_files(root, manifest)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("download", "select-missing"))
    args = parser.parse_args()
    manifest = json.loads(Path("operators/apgr-publication/pypi-artifacts.json").read_bytes())
    root = Path("dist")
    if args.mode == "download":
        download(root, manifest)
    else:
        missing = select_missing(root, manifest, Boundary())
        print("upload=" + ("true" if missing else "false"))


if __name__ == "__main__":
    main()
