"""Native same-artifact qualification; no build, download, upload or registry client."""
import argparse
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys

from rs9.tf_pypi_archive import AdmissionError, fail
from rs9.tf_pypi_consumer import smoke
from rs9.tf_pypi_model import PRODUCTS, load_pin
from rs9.tf_pypi_publish import verify_approved


def source_commit(expected):
    if not re.fullmatch(r"[0-9a-f]{40}", expected or ""):
        fail("HOSTED_COMMIT")
    root = Path(__file__).resolve().parents[2]
    result = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                            capture_output=True, timeout=15, check=False)
    if result.returncode or result.stdout.decode("ascii", "replace").strip() != expected:
        fail("HOSTED_COMMIT")
    return expected


def qualify(project, dist, work, expected_commit):
    """Must be invoked under OS network denial; smoke verifies Python and Node."""
    if platform.system() != "Darwin" or platform.machine().lower() != "arm64":
        fail("HOSTED_NATIVE_ARM64")
    commit = source_commit(expected_commit)
    pin = load_pin(project)
    approved = verify_approved(pin, Path(dist), target="darwin-arm64")
    before = approved["set_sha256"]
    consumer = smoke(pin, Path(dist), Path(work), functional=True)
    after = verify_approved(pin, Path(dist), target="darwin-arm64")
    if after != approved:
        fail("HOSTED_ARTIFACT_CHANGED")
    if (consumer.get("project") != project or consumer.get("system") != "aarch64-darwin"
            or consumer.get("set_sha256") != before or consumer.get("functional") is not True
            or consumer.get("offline_isolation", {}).get("network_disabled") is not True
            or consumer.get("publication_admitted") is not False):
        fail("HOSTED_CONSUMER_RECEIPT")
    lifecycle = consumer.get("lifecycle", [])
    if (len(lifecycle) != 2 or {x.get("kind") for x in lifecycle} != {"wheel", "sdist"}
            or any(x.get("install_exit") != 0 or not x.get("probes") for x in lifecycle)):
        fail("HOSTED_LIFECYCLE")
    return {"schema": "rs9.tf-pypi-hosted-consumer.v1", "status": "native-consumer-passed",
            "project": project, "version": pin["version"], "commit": commit,
            "artifacts": approved["files"], "set_sha256": before, "consumer": consumer,
            "network_mechanism": "macOS-seatbelt-deny-network",
            "qualification_scope": "current-native-macos-arm64-only",
            "public_writes": 0, "publication_admitted": False}


def write_report(path, record):
    path = Path(path).absolute()
    if any(p.is_symlink() for p in (path, *path.parents)):
        fail("HOSTED_REPORT_PATH")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as stream:
        json.dump(record, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["qualify"])
    parser.add_argument("--project", required=True, choices=sorted(PRODUCTS))
    parser.add_argument("--dist", required=True)
    parser.add_argument("--work", required=True)
    parser.add_argument("--report", required=True)
    parser.add_argument("--expected-commit", required=True)
    args = parser.parse_args(argv)
    result = {"schema": "rs9.tf-pypi-hosted-consumer.v1", "project": args.project,
              "status": "failed", "publication_admitted": False, "public_writes": 0}
    code = 1
    try:
        result = qualify(args.project, args.dist, args.work, args.expected_commit)
        code = 0
    except AdmissionError as error:
        result["error_code"] = error.code
    except Exception as error:
        # No home paths, environment or credentials are copied into public reports.
        result["error_type"] = type(error).__name__
    write_report(Path(args.report), result)
    print(json.dumps({"status": result["status"], "project": args.project,
                      "publication_admitted": False}, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
