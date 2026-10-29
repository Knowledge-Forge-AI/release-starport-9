"""Native same-artifact qualification; no build, download, upload or registry client."""
import argparse
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
from typing import Any, Mapping, Sequence

from rs9.tf_pypi_archive import AdmissionError, canonical, fail, physical_bytes, sha256
from rs9.tf_pypi_consumer import consume_nebular_candidate, smoke
from rs9.tf_pypi_model import PRODUCTS, TARGETS, load_pin, strict_json, validate_pin
from rs9.tf_pypi_platform import host_key
from rs9.tf_pypi_verify import host_view, verify_aggregate
from rs9.nebular070_manylinux import (
    ARCHIVE_PORTABILITY_SCHEMA as NEBULAR070_ARCHIVE_PORTABILITY_SCHEMA,
    CLAIM as NEBULAR070_MANYLINUX_CLAIM,
    LINUX_TARGETS as NEBULAR070_MANYLINUX_TARGETS,
    PORTABILITY_SCHEMA as NEBULAR070_PORTABILITY_SCHEMA,
    VERSION as NEBULAR070_MANYLINUX_VERSION,
    ValidatedPayloadPortability,
    ValidatedReleaseAdmission,
    manylinux_tag_for_target,
    validate_nebular070_payload_portability as _validate_nebular070_payload_portability,
    validate_nebular070_release_admission as _validate_nebular070_release_admission,
)

TARGET_SYSTEMS = {
    "darwin-arm64": "aarch64-darwin",
    "linux-arm64-gnu": "aarch64-linux",
    "linux-x64-gnu": "x86_64-linux",
}


def validate_nebular070_payload_portability(
    record: Mapping[str, Any],
    receipt_bodies: Mapping[str, Mapping[str, Any]],
    *,
    expected_tf_producer_source: Mapping[str, str],
    expected_rs9_tool_source: Mapping[str, str],
) -> ValidatedPayloadPortability:
    """Validate Stage A before any hosted consumer can admit a manylinux tag."""
    return _validate_nebular070_payload_portability(
        record,
        receipt_bodies,
        expected_tf_producer_source=expected_tf_producer_source,
        expected_rs9_tool_source=expected_rs9_tool_source,
    )


def validate_nebular070_release_admission(
    record: Mapping[str, Any],
    *,
    stage_a: ValidatedPayloadPortability,
    wheel_bytes_by_target: Mapping[str, bytes],
    wheel_filenames_by_target: Mapping[str, str] | None = None,
    installed_consumer_bodies: Mapping[str, Mapping[str, Mapping[str, Any]]],
    existing_three_target_approval: Mapping[str, Any],
    existing_matrix_receipt: Mapping[str, Any],
    expected_rs9_release_source: Mapping[str, str],
) -> ValidatedReleaseAdmission:
    """Hosted release-admission seam; it never performs a publication write."""
    return _validate_nebular070_release_admission(
        record,
        stage_a=stage_a,
        wheel_bytes_by_target=wheel_bytes_by_target,
        wheel_filenames_by_target=wheel_filenames_by_target,
        installed_consumer_bodies=installed_consumer_bodies,
        existing_three_target_approval=existing_three_target_approval,
        existing_matrix_receipt=existing_matrix_receipt,
        expected_rs9_release_source=expected_rs9_release_source,
    )


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


# Gate 2 Nebular successor route.  This is an additive API beside the
# historical Stellar wheel/sdist route above; it intentionally has no build,
# upload, registry, or workflow mutation capability.
NEBULAR070_HOSTED_SCHEMA = "rs9.nebular070-hosted-consumer.v1"
NEBULAR070_MATRIX_SCHEMA = "rs9.nebular070-hosted-matrix.v1"
NEBULAR070_EXPECTED_ARTIFACT_SCHEMA = "rs9.nebular070-expected-artifacts.v1"
NEBULAR070_LICENSE_EXPRESSION = "AGPL-3.0-or-later"
NEBULAR070_WHEEL_TAGS = {
    "darwin-arm64": "py3-none-macosx_13_0_arm64",
    "linux-arm64-gnu": "py3-none-linux_aarch64",
    "linux-x64-gnu": "py3-none-linux_x86_64",
}
NEBULAR070_LINUX_RUNTIME_POLICY = {
    "wheel_tag_policy": "generic-linux",
    "glibc_floor": "2.36",
    "glibcxx_floor": "3.4.30",
    "provider_baseline": "manylinux236-named-provenance-only",
    "manylinux_claim": False,
    "dynamic_closure": "pending",
}
_NEBULAR070_STAGE_A_FIELDS = {
    "construction_stage", "release_admission", "manylinux_construction_receipt_sha256",
}
_NEBULAR070_STAGE_A_RECEIPT_KINDS = (
    "source", "qualification", "portability", "runtime", "runtime_floor",
    "host_floor", "host_newer", "cpu",
)


def _nebular_stage_a_digest(stage_a: ValidatedPayloadPortability | None) -> str | None:
    """Check the closed, non-fixture Stage-A object before enabling manylinux rows."""
    if stage_a is None:
        return None
    if not isinstance(stage_a, ValidatedPayloadPortability) or stage_a.fixture_only:
        fail("NEBULAR_EXPECTED_ARTIFACTS")
    record = stage_a.record
    if (not isinstance(record, Mapping)
            or set(record) != {
                "schema", "version", "claim", "construction_status", "tf_producer_source",
                "rs9_tool_source", "evidence_mode", "source_input_snapshot_sha256", "targets", "identity",
            }
            or record.get("schema") not in {
                NEBULAR070_PORTABILITY_SCHEMA,
                NEBULAR070_ARCHIVE_PORTABILITY_SCHEMA,
            }
            or record.get("version") != NEBULAR070_MANYLINUX_VERSION
            or record.get("claim") != NEBULAR070_MANYLINUX_CLAIM
            or record.get("construction_status") != "payload-qualified"
            or record.get("evidence_mode") != "actual"
            or not isinstance(record.get("targets"), list)
            or any(not isinstance(row, Mapping) or not isinstance(row.get("target"), str)
                   for row in record["targets"])
            or {row["target"] for row in record["targets"]}
            != set(NEBULAR070_MANYLINUX_TARGETS)):
        fail("NEBULAR_EXPECTED_ARTIFACTS")
    for source_key in ("tf_producer_source", "rs9_tool_source"):
        source = record.get(source_key)
        if (not isinstance(source, Mapping) or set(source) != {"commit", "tree"}
                or not re.fullmatch(r"[0-9a-f]{40}", str(source.get("commit")))
                or not re.fullmatch(r"[0-9a-f]{40}", str(source.get("tree")))):
            fail("NEBULAR_EXPECTED_ARTIFACTS")
    if not re.fullmatch(r"[0-9a-f]{64}", str(record.get("source_input_snapshot_sha256"))):
        fail("NEBULAR_EXPECTED_ARTIFACTS")
    digest = stage_a.digest
    if (not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)
            or record.get("identity") != digest
            or not isinstance(stage_a.receipt_bodies, Mapping)
            or set(stage_a.receipt_bodies) != {
                f"{target}:{kind}"
                for target in NEBULAR070_MANYLINUX_TARGETS
                for kind in _NEBULAR070_STAGE_A_RECEIPT_KINDS
            }):
        fail("NEBULAR_EXPECTED_ARTIFACTS")
    for row in record["targets"]:
        if (not isinstance(row, Mapping)
                or not isinstance(row.get("target"), str)
                or row.get("target") not in NEBULAR070_MANYLINUX_TARGETS
                or row.get("triple") != NEBULAR070_MANYLINUX_TARGETS[row["target"]][0]
                or not (record.get("schema") == NEBULAR070_ARCHIVE_PORTABILITY_SCHEMA
                        and isinstance(row.get("archive_member_manifest_sha256"), str)
                        and re.fullmatch(r"[0-9a-f]{64}", row["archive_member_manifest_sha256"]))):
            fail("NEBULAR_EXPECTED_ARTIFACTS")
    return digest


def _nebular_profile_sha(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        fail("NEBULAR_PROFILE_BINDING")
    return value


def _nebular_tree(expected: str) -> str:
    if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{40}", expected):
        fail("NEBULAR_HOSTED_TREE")
    root = Path(__file__).resolve().parents[2]
    result = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD^{tree}"],
                            capture_output=True, timeout=15, check=False)
    observed = result.stdout.decode("ascii", "replace").strip()
    if result.returncode or observed != expected:
        fail("NEBULAR_HOSTED_TREE")
    return expected


def _nebular_expected_artifacts(
    record: Mapping[str, Any],
    candidate: Mapping[str, Any],
    manylinux_stage_a: ValidatedPayloadPortability | None = None,
) -> dict[str, Any]:
    stage_a_digest = _nebular_stage_a_digest(manylinux_stage_a)
    if (not isinstance(record, Mapping)
            or record.get("schema") != NEBULAR070_EXPECTED_ARTIFACT_SCHEMA
            or record.get("candidate_rs9_source") != candidate.get("candidate_rs9_source")
            or not isinstance(record.get("wheels"), list)
            or len(record["wheels"]) != 3
            or not isinstance(record.get("record_sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", record["record_sha256"])):
        fail("NEBULAR_EXPECTED_ARTIFACTS")
    candidate_license = candidate.get("license")
    profile = candidate.get("profile")
    if (not isinstance(candidate_license, Mapping)
            or candidate_license.get("expression") != NEBULAR070_LICENSE_EXPRESSION
            or not isinstance(profile, Mapping)
            or profile.get("license_expression") != NEBULAR070_LICENSE_EXPRESSION
            or profile.get("darwin_floor") != {"major": 13, "minor": 0}
            or profile.get("linux_runtime_policy") != NEBULAR070_LINUX_RUNTIME_POLICY
            or candidate.get("linux_runtime_policy") != NEBULAR070_LINUX_RUNTIME_POLICY):
        fail("NEBULAR_EXPECTED_ARTIFACTS")
    rows = []
    for wheel in record["wheels"]:
        target = wheel.get("target") if isinstance(wheel, Mapping) else None
        expected_tag = NEBULAR070_WHEEL_TAGS.get(target) if isinstance(target, str) else None
        if stage_a_digest is not None and isinstance(target, str) and target in NEBULAR070_MANYLINUX_TARGETS:
            expected_tag = manylinux_tag_for_target(target)
        if (not isinstance(wheel, Mapping)
                or set(("target", "filename", "size", "sha256", "tag", "version")) - set(wheel)
                or not isinstance(target, str)
                or target not in TARGET_SYSTEMS
                or not isinstance(wheel.get("filename"), str)
                or type(wheel.get("size")) is not int or wheel["size"] <= 0
                or not re.fullmatch(r"[0-9a-f]{64}", str(wheel.get("sha256")))
                or not isinstance(wheel.get("tag"), str)
                or wheel.get("tag") != expected_tag
                or wheel.get("version") != "0.7.0"):
            fail("NEBULAR_EXPECTED_ARTIFACTS")
        if stage_a_digest is not None and target in NEBULAR070_MANYLINUX_TARGETS:
            if (wheel.get("filename") !=
                    f"theme_forge_nebular_fusion-0.7.0-{expected_tag}.whl"
                    or any(wheel.get(key) != value for key, value in {
                        "construction_stage": "payload-portability",
                        "release_admission": "external",
                        "manylinux_construction_receipt_sha256": stage_a_digest,
                    }.items())):
                fail("NEBULAR_EXPECTED_ARTIFACTS")
        elif any(key in wheel for key in _NEBULAR070_STAGE_A_FIELDS):
            fail("NEBULAR_EXPECTED_ARTIFACTS")
        rows.append(dict(wheel))
    rows.sort(key=lambda row: row["target"])
    if len({row["target"] for row in rows}) != 3 or sha256(canonical(rows)) != record["record_sha256"]:
        fail("NEBULAR_EXPECTED_ARTIFACTS")
    candidate_rows = {row.get("system"): row for row in candidate.get("rows", []) if isinstance(row, Mapping)}
    for target, system in ((key, value) for key, value in TARGET_SYSTEMS.items()):
        row = candidate_rows.get(system)
        expected = next((item for item in rows if item["target"] == target), None)
        expected_wheel = {key: expected[key] for key in ("filename", "sha256", "size", "tag", "version")}
        row_profile = row.get("candidate_profile") if isinstance(row, Mapping) else None
        if (not isinstance(row, Mapping) or not isinstance(expected, Mapping)
                or row.get("wheel") != expected_wheel
                or not isinstance(row_profile, Mapping)
                or row_profile.get("license_expression") != NEBULAR070_LICENSE_EXPRESSION
                or row.get("linux_runtime_policy") != NEBULAR070_LINUX_RUNTIME_POLICY):
            fail("NEBULAR_EXPECTED_ARTIFACTS")
        if stage_a_digest is not None and target in NEBULAR070_MANYLINUX_TARGETS:
            if any(row.get(key) != value for key, value in {
                "construction_stage": "payload-portability",
                "release_admission": "external",
                "manylinux_construction_receipt_sha256": stage_a_digest,
            }.items()):
                fail("NEBULAR_EXPECTED_ARTIFACTS")
        elif any(key in row for key in _NEBULAR070_STAGE_A_FIELDS):
            fail("NEBULAR_EXPECTED_ARTIFACTS")
    result = {"schema": record["schema"], "candidate_rs9_source": record["candidate_rs9_source"],
              "wheels": rows, "record_sha256": record["record_sha256"]}
    if stage_a_digest is not None:
        result["manylinux_stage_a_sha256"] = stage_a_digest
    return result


def qualify_nebular070(
    candidate: Mapping[str, Any],
    wheel_path: str | Path,
    raw_release: Mapping[str, Any],
    work: str | Path,
    *,
    expected_artifacts: Mapping[str, Any],
    expected_commit: str,
    expected_tree: str,
    profile_sha256: str,
    candidate_receipt_sha256: str,
    target: str,
    run_id: str = "1",
    run_attempt: str = "1",
    sandbox_prefix: Sequence[str] = (),
    sandbox_probe: Any = None,
    host_identity: Mapping[str, Any] | None = None,
    fixture_only: bool = False,
    runner: Any = None,
    process_observer: Any = None,
    state_snapshot: Any = None,
    real_user_state_snapshot: Any = None,
    offline_pip_bootstrap: Mapping[str, Any] | None = None,
    manylinux_stage_a: ValidatedPayloadPortability | None = None,
    smoke_support: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Run one Nebular 0.7 candidate through the post-path native consumer.

    The candidate receipt and expected-artifact record are immutable inputs;
    ``qualification_rs9_source`` is generated from the executing checkout and
    is never relabeled as the candidate source.  Controlled fixtures are
    explicitly non-qualification evidence.
    """
    if target not in TARGET_SYSTEMS:
        fail("NEBULAR_TARGET")
    run_id = _run_id(run_id)
    run_attempt = _run_id(run_attempt)
    if not isinstance(candidate_receipt_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", candidate_receipt_sha256):
        fail("NEBULAR_CANDIDATE_RECEIPT")
    profile_sha256 = _nebular_profile_sha(profile_sha256)
    if fixture_only and isinstance(host_identity, Mapping):
        commit = expected_commit
        tree = expected_tree
    else:
        commit = source_commit(expected_commit)
        tree = _nebular_tree(expected_tree)
    if (not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit)
            or not isinstance(tree, str) or not re.fullmatch(r"[0-9a-f]{40}", tree)):
        fail("NEBULAR_HOSTED_SOURCE")
    qualification_source = {
        "status": "executing-qualification-source",
        "commit": commit,
        "tree": tree,
        "run_id": run_id,
        "run_attempt": run_attempt,
        "profile_sha256": profile_sha256,
    }
    artifacts = _nebular_expected_artifacts(expected_artifacts, candidate, manylinux_stage_a)
    # Consumer-side validation also proves the candidate row and actual wheel
    # bytes agree with the expected record before a native process is spawned.
    expected_wheel = next(row for row in artifacts["wheels"] if row["target"] == target)
    if Path(wheel_path).name != expected_wheel["filename"]:
        fail("NEBULAR_EXPECTED_ARTIFACTS")
    consume_kwargs = {
        "target": target,
        "sandbox_prefix": sandbox_prefix,
        "sandbox_probe": sandbox_probe,
        "host_identity": host_identity,
        "fixture_only": fixture_only,
        "process_observer": process_observer,
        "state_snapshot": state_snapshot,
        "real_user_state_snapshot": real_user_state_snapshot,
    }
    if offline_pip_bootstrap is not None:
        consume_kwargs["offline_pip_bootstrap"] = offline_pip_bootstrap
    if smoke_support is not None:
        consume_kwargs["smoke_support"] = smoke_support
    if runner is not None:
        consume_kwargs["runner"] = runner
    consumer = consume_nebular_candidate(candidate, wheel_path, raw_release, work, **consume_kwargs)
    consumer.update({
        "candidate_receipt_sha256": candidate_receipt_sha256,
        "expected_artifact_record_sha256": artifacts["record_sha256"],
        "qualification_rs9_source": qualification_source,
    })
    result = {
        "schema": NEBULAR070_HOSTED_SCHEMA,
        "status": "fixture-native-consumer-passed" if fixture_only else "native-consumer-passed",
        "fixture_only": fixture_only,
        "native_qualified": not fixture_only,
        "candidate_receipt_sha256": candidate_receipt_sha256,
        "expected_artifact_record_sha256": artifacts["record_sha256"],
        "candidate_rs9_source": consumer["candidate_rs9_source"],
        "qualification_rs9_source": qualification_source,
        "target": target,
        "run_id": run_id,
        "run_attempt": run_attempt,
        "consumer": consumer,
        "publication_admitted": False,
        "public_writes": 0,
    }
    if "manylinux_stage_a_sha256" in artifacts:
        consumer["manylinux_stage_a_sha256"] = artifacts["manylinux_stage_a_sha256"]
        result["manylinux_stage_a_sha256"] = artifacts["manylinux_stage_a_sha256"]
    return result


def admit_nebular070_matrix(
    candidate: Mapping[str, Any],
    expected_artifacts: Mapping[str, Any],
    receipts: str | Path,
    *,
    expected_commit: str,
    expected_tree: str,
    profile_sha256: str,
    candidate_receipt_sha256: str,
    run_id: str,
    run_attempt: str,
    manylinux_stage_a: ValidatedPayloadPortability | None = None,
) -> dict[str, Any]:
    """Admit only genuine three-host Gate 2 receipts; fixture receipts fail closed."""
    run_id = _run_id(run_id)
    run_attempt = _run_id(run_attempt)
    if run_attempt != "1":
        fail("NEBULAR_HOSTED_RUN_ATTEMPT")
    profile_sha256 = _nebular_profile_sha(profile_sha256)
    if not isinstance(candidate_receipt_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", candidate_receipt_sha256):
        fail("NEBULAR_CANDIDATE_RECEIPT")
    if not isinstance(receipts, (str, os.PathLike)):
        fail("NEBULAR_MATRIX_RECEIPTS")
    root = Path(receipts)
    if root.is_symlink() or not root.is_dir():
        fail("NEBULAR_MATRIX_RECEIPTS")
    stage_a_digest = _nebular_stage_a_digest(manylinux_stage_a)
    expected = _nebular_expected_artifacts(expected_artifacts, candidate, manylinux_stage_a)
    candidate_source = candidate.get("candidate_rs9_source")
    if not isinstance(candidate_source, Mapping):
        fail("NEBULAR_CANDIDATE_SCHEMA")
    entries = sorted(path.name for path in root.iterdir())
    if entries != sorted(TARGET_SYSTEMS):
        fail("NEBULAR_MATRIX_RECEIPTS")
    verified: dict[str, Any] = {}
    qualification_sources: dict[str, Any] = {}
    for target in sorted(TARGET_SYSTEMS):
        target_dir = root / target
        result_path = target_dir / "result.json"
        if target_dir.is_symlink() or not target_dir.is_dir() or result_path.is_symlink() or not result_path.is_file():
            fail("NEBULAR_MATRIX_RECEIPTS")
        try:
            result = strict_json(physical_bytes(result_path, limit=4 * 1024 * 1024))
        except Exception:
            fail("NEBULAR_MATRIX_RECEIPT")
        if (not isinstance(result, Mapping)
                or result.get("schema") != NEBULAR070_HOSTED_SCHEMA
                or result.get("status") != "native-consumer-passed"
                or result.get("fixture_only") is not False
                or result.get("native_qualified") is not True
                or result.get("candidate_receipt_sha256") != candidate_receipt_sha256
                or result.get("candidate_rs9_source") != candidate_source
                or result.get("target") != target
                or result.get("run_id") != run_id
                or result.get("run_attempt") != "1"
                or result.get("expected_artifact_record_sha256") != expected["record_sha256"]
                or (stage_a_digest is not None
                    and result.get("manylinux_stage_a_sha256") != stage_a_digest)
                or (stage_a_digest is None
                    and "manylinux_stage_a_sha256" in result)
                or result.get("publication_admitted") is not False
                or not isinstance(result.get("qualification_rs9_source"), Mapping)):
            fail("NEBULAR_MATRIX_RECEIPT")
        # The matrix must carry the complete actual installed-consumer result
        # for every primary target, including Darwin.  The older shallow
        # booleans below are retained as cheap early checks; this maintained
        # validator owns the fresh A/B/C and x64 C-signal receipt contract.
        try:
            from rs9.nebular070_public_consumers import _required_actual_result
            _required_actual_result(result, target=target)
        except Exception as exc:
            raise AdmissionError("TF_PYPI_MATRIX_CONSUMER") from exc
        qualification = result["qualification_rs9_source"]
        if (qualification.get("status") != "executing-qualification-source"
                or qualification.get("run_id") != run_id
                or qualification.get("run_attempt") != "1"
                or qualification.get("profile_sha256") != profile_sha256
                or not re.fullmatch(r"[0-9a-f]{40}", str(qualification.get("commit")))
                or not re.fullmatch(r"[0-9a-f]{40}", str(qualification.get("tree")))):
            fail("NEBULAR_MATRIX_RECEIPT")
        consumer = result.get("consumer")
        if (not isinstance(consumer, Mapping)
                or consumer.get("fixture_only") is not False
                or consumer.get("native_qualified") is not True
                or consumer.get("process_observer", {}).get("orphan_count") != 0
                or consumer.get("user_state", {}).get("unchanged") is not True
                or consumer.get("sandbox", {}).get("network_disabled") is not True
                or consumer.get("provider_closure", {}).get("status") != "verified"
                or (stage_a_digest is not None
                    and consumer.get("manylinux_stage_a_sha256") != stage_a_digest)
                or (stage_a_digest is None
                    and "manylinux_stage_a_sha256" in consumer)):
            fail("NEBULAR_MATRIX_RECEIPT")
        expected_wheel = next(row for row in expected["wheels"] if row["target"] == target)
        if result.get("consumer", {}).get("wheel") != expected_wheel:
            fail("NEBULAR_MATRIX_RECEIPT")
        verified[target] = result
        qualification_sources[target] = qualification
    _nebular_tree(expected_tree)
    source_commit(expected_commit)
    result = {
        "schema": NEBULAR070_MATRIX_SCHEMA,
        "status": "native-matrix-passed",
        "fixture_only": False,
        "native_qualified": True,
        "candidate_receipt_sha256": candidate_receipt_sha256,
        "expected_artifact_record_sha256": expected["record_sha256"],
        "candidate_rs9_source": dict(candidate_source),
        "qualification_rs9_source": qualification_sources,
        "targets": sorted(TARGET_SYSTEMS),
        "receipts": verified,
        "run_id": run_id,
        "run_attempt": run_attempt,
        "publication_admitted": False,
        "public_writes": 0,
    }
    if stage_a_digest is not None:
        result["manylinux_stage_a_sha256"] = stage_a_digest
    return result
