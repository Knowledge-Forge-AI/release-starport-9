"""Native same-artifact qualification; no build, download, upload or registry client."""
import argparse
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys

from rs9.tf_pypi_archive import AdmissionError, canonical, fail, physical_bytes, sha256
from rs9.tf_pypi_consumer import smoke
from rs9.tf_pypi_model import PRODUCTS, TARGETS, load_pin, strict_json, validate_pin
from rs9.tf_pypi_platform import host_key
from rs9.tf_pypi_verify import host_view, verify_aggregate

TARGET_SYSTEMS = {
    "darwin-arm64": "aarch64-darwin",
    "linux-arm64-gnu": "aarch64-linux",
    "linux-x64-gnu": "x86_64-linux",
}


def source_commit(expected):
    if not re.fullmatch(r"[0-9a-f]{40}", expected or ""):
        fail("HOSTED_COMMIT")
    root = Path(__file__).resolve().parents[2]
    result = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                            capture_output=True, timeout=15, check=False)
    if result.returncode or result.stdout.decode("ascii", "replace").strip() != expected:
        fail("HOSTED_COMMIT")
    return expected


def _run_id(value):
    if not isinstance(value, str) or not re.fullmatch(r"[1-9][0-9]*", value):
        fail("HOSTED_RUN_IDENTITY")
    return value


def _check_consumer_fields(consumer, project, target, expected_pair_sha=None):
    if (not isinstance(consumer, dict)
            or consumer.get("project") != project
            or consumer.get("target") != target
            or consumer.get("system") != TARGET_SYSTEMS.get(target)
            or (expected_pair_sha is not None and consumer.get("set_sha256") != expected_pair_sha)
            or consumer.get("functional") is not True
            or not isinstance(consumer.get("offline_isolation"), dict)
            or consumer["offline_isolation"].get("network_disabled") is not True
            or consumer.get("publication_admitted") is not False):
        return False
    lifecycle = consumer.get("lifecycle", [])
    if (not isinstance(lifecycle, list) or len(lifecycle) != 2
            or {x.get("kind") for x in lifecycle if isinstance(x, dict)} != {"wheel", "sdist"}
            or any(
                not isinstance(x, dict)
                or x.get("install_exit") != 0
                or not isinstance(x.get("probes"), list)
                or not x.get("probes")
                or any(not isinstance(p, dict) or not isinstance(p.get("command"), str) or not p.get("command")
                       for p in x["probes"])
                for x in lifecycle
            )):
        return False
    return True


def qualify(project, dist, work, expected_commit, target="darwin-arm64", run_id="1", run_attempt="1", pin=None):
    """Must be invoked under OS network denial; smoke verifies Python and Node."""
    if isinstance(project, dict):
        if pin is not None:
            fail("PIN")
        pin = validate_pin(project)
        project = pin["project"]
    elif pin is None:
        pin = load_pin(project)
    elif isinstance(pin, (str, os.PathLike)):
        pin = load_pin(project, pin)
    else:
        if not isinstance(pin, dict) or not isinstance(pin.get("project"), str) or pin.get("project") != project:
            fail("PRODUCT")
        pin = validate_pin(pin)
    if target not in pin["candidate_platforms"]:
        fail("HOSTED_NATIVE_TARGET")
    try:
        current_host = host_key()
    except AdmissionError:
        fail("HOSTED_NATIVE_TARGET")
    if current_host != target:
        fail("HOSTED_NATIVE_TARGET")
    commit = source_commit(expected_commit)
    run_id = _run_id(run_id)
    run_attempt = _run_id(run_attempt)
    dist_path = Path(dist)
    aggregate = verify_aggregate(pin, dist_path)
    before = aggregate["set_sha256"]
    work_root = Path(work)
    if work_root.exists() or work_root.is_symlink():
        fail("HOSTED_WORK_DIR")
    view_dir = work_root / "view"
    consumer_dir = work_root / "consumer"
    pair = host_view(pin, dist_path, target, view_dir)
    consumer = smoke(pin, view_dir, consumer_dir,
                     offline_linux=target.startswith("linux"), functional=True)
    after = verify_aggregate(pin, dist_path)
    if after != aggregate:
        fail("HOSTED_ARTIFACT_CHANGED")
    if (not isinstance(consumer, dict)
            or consumer.get("project") != project
            or consumer.get("target") != target
            or consumer.get("system") != TARGET_SYSTEMS[target]
            or consumer.get("set_sha256") != pair["set_sha256"]
            or consumer.get("functional") is not True
            or not isinstance(consumer.get("offline_isolation"), dict)
            or consumer["offline_isolation"].get("network_disabled") is not True
            or consumer.get("publication_admitted") is not False):
        fail("HOSTED_CONSUMER_RECEIPT")
    lifecycle = consumer.get("lifecycle", [])
    if (not isinstance(lifecycle, list) or len(lifecycle) != 2
            or {x.get("kind") for x in lifecycle if isinstance(x, dict)} != {"wheel", "sdist"}
            or any(x.get("install_exit") != 0 or not x.get("probes") for x in lifecycle)):
        fail("HOSTED_LIFECYCLE")
    wheel_record = next(row for row in aggregate["files"] if row["target"] == target)
    sdist_record = next(row for row in aggregate["files"] if row["target"] is None)
    return {
        "schema": "rs9.tf-pypi-hosted-consumer.v2",
        "status": "native-consumer-passed",
        "project": project,
        "version": pin["distribution_version"],
        "upstream_version": pin["version"],
        "target": target,
        "commit": commit,
        "run_id": run_id,
        "run_attempt": run_attempt,
        "wheel": wheel_record,
        "sdist": sdist_record,
        "artifacts": pair["files"],
        "set_sha256": pair["set_sha256"],
        "aggregate_set_sha256": before,
        "consumer": consumer,
        "network_mechanism": ("linux-unshare-net" if target.startswith("linux")
                              else "macOS-seatbelt-deny-network"),
        "qualification_scope": f"native-{target}",
        "public_writes": 0,
        "publication_admitted": False,
    }


def admit_matrix(pin, dist, receipts, expected_commit, run_id, run_attempt, pin_path=None):
    """Validate same-run, first-attempt, three-host native receipts against the aggregate."""
    if isinstance(pin, str):
        pin = load_pin(pin) if pin_path is None else load_pin(pin, pin_path)
    else:
        if pin_path is not None:
            fail("PIN")
        validate_pin(pin)
    commit = source_commit(expected_commit)
    run_id = _run_id(run_id)
    run_attempt = _run_id(run_attempt)
    if run_attempt != "1":
        fail("HOSTED_RUN_ATTEMPT")
    aggregate = verify_aggregate(pin, Path(dist))
    receipts_dir = Path(receipts)
    if receipts_dir.is_symlink() or not receipts_dir.is_dir():
        fail("HOSTED_MATRIX_RECEIPTS")
    targets = list(pin["candidate_platforms"])
    try:
        entries = list(receipts_dir.iterdir())
    except OSError:
        fail("HOSTED_MATRIX_RECEIPTS")
    if {entry.name for entry in entries} != set(targets):
        fail("HOSTED_MATRIX_RECEIPTS")
    sdist_record = next((row for row in aggregate["files"] if row["target"] is None), None)
    verified = {}
    for target in targets:
        target_dir = receipts_dir / target
        if target_dir.is_symlink() or not target_dir.is_dir():
            fail("HOSTED_MATRIX_RECEIPTS")
        try:
            children = {child.name for child in target_dir.iterdir()}
        except OSError:
            fail("HOSTED_MATRIX_RECEIPTS")
        if children != {"result.json"}:
            fail("HOSTED_MATRIX_RECEIPTS")
        rec = strict_json(physical_bytes(target_dir / "result.json"))
        wheel_record = next((row for row in aggregate["files"] if row["target"] == target), None)
        if wheel_record is None or sdist_record is None:
            fail("HOSTED_MATRIX_RECEIPT")
        expected_artifacts = sorted(
            [{k: v for k, v in row.items() if k != "target"} for row in (wheel_record, sdist_record)],
            key=lambda row: row["filename"],
        )
        expected_pair_sha = sha256(canonical(expected_artifacts))
        expected_net = "linux-unshare-net" if target.startswith("linux") else "macOS-seatbelt-deny-network"
        if (not isinstance(rec, dict)
                or rec.get("schema") != "rs9.tf-pypi-hosted-consumer.v2"
                or rec.get("status") != "native-consumer-passed"
                or rec.get("project") != pin["project"]
                or rec.get("version") != pin["distribution_version"]
                or rec.get("upstream_version") != pin["version"]
                or rec.get("target") != target
                or rec.get("commit") != commit
                or rec.get("run_id") != run_id
                or rec.get("run_attempt") != "1"
                or rec.get("aggregate_set_sha256") != aggregate["set_sha256"]
                or rec.get("wheel") != wheel_record
                or rec.get("sdist") != sdist_record
                or rec.get("artifacts") != expected_artifacts
                or rec.get("set_sha256") != expected_pair_sha
                or rec.get("network_mechanism") != expected_net
                or rec.get("qualification_scope") != f"native-{target}"
                or rec.get("public_writes") != 0
                or rec.get("publication_admitted") is not False
                or not _check_consumer_fields(rec.get("consumer"), pin["project"], target, expected_pair_sha)):
            fail("HOSTED_MATRIX_RECEIPT")
        verified[target] = rec
    return {
        "schema": "rs9.tf-pypi-hosted-matrix.v1",
        "status": "native-matrix-passed",
        "project": pin["project"],
        "version": pin["distribution_version"],
        "upstream_version": pin["version"],
        "commit": commit,
        "run_id": run_id,
        "run_attempt": run_attempt,
        "targets": targets,
        "aggregate_set_sha256": aggregate["set_sha256"],
        "receipts": verified,
        "public_writes": 0,
        "publication_admitted": False,
    }


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
    parser.add_argument("operation", choices=["qualify", "admit"])
    parser.add_argument("--project", required=True, choices=sorted(PRODUCTS))
    parser.add_argument("--pin", type=Path, default=None)
    parser.add_argument("--dist", required=True)
    parser.add_argument("--work")
    parser.add_argument("--report")
    parser.add_argument("--receipts")
    parser.add_argument("--target", default="darwin-arm64", choices=list(TARGETS))
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--run-id", default="1")
    parser.add_argument("--run-attempt", default="1")
    args = parser.parse_args(argv)
    selected = None
    if args.pin is not None:
        try:
            selected = load_pin(args.project, args.pin)
        except AdmissionError as error:
            sys.stderr.write(error.code + "\n")
            return 1
        except Exception:
            sys.stderr.write("TF_PYPI_OPERATION_FAILED\n")
            return 1
    if args.operation == "admit":
        try:
            if not args.receipts:
                fail("HOSTED_MATRIX_RECEIPTS")
            record = admit_matrix(
                selected if selected is not None else args.project,
                args.dist, args.receipts,
                args.expected_commit, args.run_id, args.run_attempt,
            )
            if args.report:
                write_report(Path(args.report), record)
            sys.stdout.buffer.write(canonical(record))
            return 0
        except AdmissionError as error:
            sys.stderr.write(error.code + "\n")
            return 1
        except Exception:
            sys.stderr.write("TF_PYPI_OPERATION_FAILED\n")
            return 1
    result = {"schema": "rs9.tf-pypi-hosted-consumer.v2", "project": args.project,
              "target": args.target, "status": "failed",
              "publication_admitted": False, "public_writes": 0}
    code = 1
    try:
        if not args.work or not args.report:
            fail("HOSTED_WORK_DIR")
        qualify_kwargs = {
            "target": args.target,
            "run_id": args.run_id,
            "run_attempt": args.run_attempt,
        }
        if selected is not None:
            qualify_kwargs["pin"] = selected
        result = qualify(
            args.project, args.dist, args.work, args.expected_commit,
            **qualify_kwargs,
        )
        code = 0
    except AdmissionError as error:
        result["error_code"] = error.code
    except Exception as error:
        # No home paths, environment or credentials are copied into public reports.
        result["error_type"] = type(error).__name__
    if args.report:
        write_report(Path(args.report), result)
    print(json.dumps({"status": result["status"], "project": args.project,
                      "target": args.target, "publication_admitted": False}, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
