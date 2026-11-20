"""Read and verify the original signed RS9 0.1.0 artifact."""

import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tempfile
import zipfile

from rs9.hosted_signing_preflight import (
    PUBLIC_KEY, PUBLIC_SHA256, PreflightFailure, cleanup_agents, gpg, require,
    verify_signature_status,
)

REPO = "Knowledge-Forge-AI/release-starport-9"
SIGNER_RUN = 44766532675
SIGNER_SHA = "0ba4792abc8833b5873a7081b2c5e7e1a8193b1c"
ARTIFACT_ID = 14645261398
ARTIFACT_SHA = "c1452f996d64667b597fd7118c364adb78a86c1b5a2a32f388e28cf84dff82d6"
ARTIFACT_BYTES = 678291
INVENTORY = "rs9-package-inventory.json"
CHANNELS = {"apt", "keys", "pacman", "rpm"}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def api(path):
    return subprocess.check_output(["gh", "api", f"repos/{REPO}/actions/{path}"], timeout=45)


def original_archive():
    run = json.loads(api(f"runs/{SIGNER_RUN}"))
    require(run["id"] == SIGNER_RUN and run["head_sha"] == SIGNER_SHA and run["head_branch"] == "main")
    require(run["run_attempt"] == 1 and run["event"] == "workflow_dispatch")
    require(run["repository"]["full_name"] == run["head_repository"]["full_name"] == REPO)
    require(run["path"] == ".github/workflows/rs9-cli-linux-sign-v010.yml")
    require(run["status"] == "completed" and run["conclusion"] == "success")
    result = json.loads(api(f"runs/{SIGNER_RUN}/artifacts"))
    require(result["total_count"] == len(result["artifacts"]) == 1)
    row = result["artifacts"][0]
    require(row["id"] == ARTIFACT_ID and row["name"] == "rs9-cli-signed-linux-v010")
    require(row["expired"] is False and row["size_in_bytes"] == ARTIFACT_BYTES)
    require(row["digest"] == "sha256:" + ARTIFACT_SHA)
    archive = api(f"artifacts/{ARTIFACT_ID}/zip")
    require(len(archive) == ARTIFACT_BYTES and sha(archive) == ARTIFACT_SHA)
    return archive


def admit(archive, output):
    require(output.is_absolute() and not output.exists() and not output.is_symlink())
    with zipfile.ZipFile(io.BytesIO(archive)) as members:
        rows = members.infolist()
        names = {row.filename for row in rows}
        require(2 < len(rows) == len(names) <= 128 and {INVENTORY, INVENTORY + ".sig"} <= names)
        for row in rows:
            path = PurePosixPath(row.filename)
            require(not row.is_dir() and not path.is_absolute()
                    and re.fullmatch(r"[A-Za-z0-9_./+-]+", row.filename) is not None
                    and all(part not in ("", ".", "..") for part in row.filename.split("/"))
                    and 0 < row.file_size <= 1024**2)
        require(sum(row.file_size for row in rows) <= 8 * 1024**2)
        files = {row.filename: members.read(row) for row in rows}
    receipt = json.loads(files[INVENTORY])
    require(set(receipt) == {"schema", "files"} and receipt["schema"] == "knowledge-forge.rs9-pages-inventory.v1")
    inventory = receipt["files"]
    require(isinstance(inventory, dict) and set(inventory) | {INVENTORY, INVENTORY + ".sig"} == names)
    require(len({name.casefold() for name in names}) == len(names))
    found = set()
    for name, info in inventory.items():
        path = PurePosixPath(name)
        require(len(path.parts) >= 4 and path.parts[:2] == ("packages", "rs9") and path.parts[2] in CHANNELS)
        found.add(path.parts[2])
        require(not any(p.as_posix() in names for p in path.parents))
        require(info == {"bytes": len(files[name]), "sha256": sha(files[name])})
    require(found == CHANNELS)
    public = PUBLIC_KEY.read_bytes()
    require(sha(public) == PUBLIC_SHA256 and files["packages/rs9/keys/rs9-signing.asc"] == public)
    with tempfile.TemporaryDirectory(prefix="rs9-cli-public-proof-") as directory:
        home = Path(directory)
        path, sig = home / "inventory", home / "inventory.sig"
        path.write_bytes(files[INVENTORY])
        sig.write_bytes(files[INVENTORY + ".sig"])
        try:
            gpg(home, ["--import"], data=public)
            verify_signature_status(gpg(home, ["--status-fd", "1", "--verify", str(sig), str(path)]))
        finally:
            cleanup_agents((home,))
    output.mkdir(mode=0o755)
    for name, body in files.items():
        path = output / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(body)
        path.chmod(0o644)
    return inventory


def main():
    try:
        admit(original_archive(), Path(sys.argv[1]))
    except (PreflightFailure, KeyError, ValueError, OSError, subprocess.SubprocessError, zipfile.BadZipFile):
        print("RS9_LINUX_ARTIFACT_ADMISSION_FAILED", flush=True)
        return 1
    print("RS9_LINUX_SIGNED_ARTIFACT_ADMITTED", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
