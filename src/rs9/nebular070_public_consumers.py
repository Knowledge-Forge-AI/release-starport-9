"""Public Stage-B consumer production and manylinux receipt assembly.

This module is the narrow bridge between an actual hosted Linux consumer and
the existing Nebular 0.7.0 release admission owners.  It deliberately does
not build wheels, publish anything, or infer a consumer result from a config
file.  ``capture_public_consumer`` runs the maintained offline installed-wheel
consumer, observes the same host with :mod:`rs9.nebular070_host_observation`,
and only then emits the closed four-field consumer body consumed by the
existing release validator.

The assembler accepts four captures plus the already-authenticated Stage-A,
approval, matrix, and wheel inputs.  It calls both the real release admission
validator and the maintained manylinux materializer; no final gate is
reimplemented or weakened here.  Synthetic captures are available only to
portable contract tests through a private helper and are never accepted by
the production capture path.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from rs9.errors import ContractError
from rs9.nebular070_host_observation import (
    ROLE_FLOOR,
    ROLE_NEWER,
    _validate_extras,
    observe_host,
    validate_observation_body,
)
from rs9.nebular070_manylinux import (
    ADMISSION_SCHEMA,
    CLAIM,
    CONSUMER_RECEIPT_SCHEMA,
    LINUX_TARGETS,
    MAX_WHEEL_BYTES,
    VERSION,
    _admission_digest,
    _digest,
    _wheel_snapshot,
    load_payload_portability_bundle,
    validate_nebular070_release_admission,
)
from rs9.nebular070_release import _consumer_body
from rs9.nebular070_payload import ValidatedPayloadPortability
from rs9.scratch import canonical
from rs9.tf_pypi_archive import canonical as archive_canonical, physical_bytes
from rs9.tf_pypi_model import strict_json
from rs9.tf_pypi_hosted import qualify_nebular070
from rs9.tf_pypi_nebular070_publish import (
    MANYLINUX_ADMISSION_MEMBER,
    default_sandbox_prefix,
    make_real_user_state_snapshotter,
    materialize_manylinux_consumer_receipts,
)


PUBLIC_CONSUMER_CAPTURE_SCHEMA = "rs9.nebular070-public-consumer-capture.v1"
STAGE_B_INPUT_SCHEMA = "rs9.nebular070-public-stage-b-input.v1"
CONSUMER_KINDS = (ROLE_FLOOR, ROLE_NEWER)
LINUX_CONSUMER_TARGETS = tuple(LINUX_TARGETS)
_ACTUAL_CAPTURE_MODE = "actual"
_FIXTURE_CAPTURE_MODE = "fixture-test-only"
_REQUIRED_CONSUMER_RESULT = {
    "schema", "status", "fixture_only", "native_qualified", "target", "consumer",
    "publication_admitted", "public_writes",
}


def _fail(code: str, message: str) -> None:
    raise ContractError(code, message)


def _target(target: str) -> str:
    if type(target) is not str or target not in LINUX_TARGETS:
        _fail("NEBULAR_STAGE_B_TARGET", "A reviewed Linux target is required")
    return target


def _kind(kind: str) -> str:
    if type(kind) is not str or kind not in CONSUMER_KINDS:
        _fail("NEBULAR_STAGE_B_KIND", "A floor or newer consumer kind is required")
    return kind


def _wheel(raw: bytes, target: str, stage_a: ValidatedPayloadPortability) -> dict[str, Any]:
    if not isinstance(raw, bytes):
        _fail("NEBULAR_STAGE_B_WHEEL", "Authenticated wheel bytes are required")
    return _wheel_snapshot(raw, target, stage_a.digest)


def _required_actual_result(result: Mapping[str, Any], *, target: str) -> Mapping[str, Any]:
    if not isinstance(result, Mapping) or not _REQUIRED_CONSUMER_RESULT <= set(result):
        _fail("NEBULAR_STAGE_B_CONSUMER", "The maintained consumer result is incomplete")
    if (
        result.get("status") != "native-consumer-passed"
        or result.get("fixture_only") is not False
        or result.get("native_qualified") is not True
        or result.get("target") != target
        or result.get("publication_admitted") is not False
        or result.get("public_writes") != 0
    ):
        _fail("NEBULAR_STAGE_B_CONSUMER", "The consumer did not pass as actual non-public evidence")
    qualification_source = result.get("qualification_rs9_source")
    if (
        not isinstance(qualification_source, Mapping)
        or qualification_source.get("status") != "executing-qualification-source"
        or not isinstance(qualification_source.get("run_id"), str)
        or not isinstance(qualification_source.get("run_attempt"), str)
    ):
        _fail("NEBULAR_STAGE_B_CONSUMER", "The qualification source is not an actual run binding")
    consumer = result.get("consumer")
    if not isinstance(consumer, Mapping):
        _fail("NEBULAR_STAGE_B_CONSUMER", "The maintained consumer body is missing")
    if (
        consumer.get("schema") != "rs9.nebular070-native-consumer.v1"
        or consumer.get("status") != "native-consumer-passed"
        or consumer.get("fixture_only") is not False
        or consumer.get("native_qualified") is not True
        or consumer.get("target") != target
        or consumer.get("publication_admitted") is not False
        or consumer.get("public_writes") != 0
    ):
        _fail("NEBULAR_STAGE_B_CONSUMER", "The nested consumer result is not actual")
    process = consumer.get("process_observer")
    user_state = consumer.get("user_state")
    sandbox = consumer.get("sandbox")
    provider = consumer.get("provider_closure")
    cleanup = consumer.get("cleanup")
    if (
        not isinstance(process, Mapping) or process.get("orphan_count") != 0
        or not isinstance(user_state, Mapping) or user_state.get("unchanged") is not True
        or not isinstance(sandbox, Mapping) or sandbox.get("network_disabled") is not True
        or sandbox.get("method") not in {
            "inherited-provider-sandbox", "explicit-isolation-prefix",
        }
        or not isinstance(provider, Mapping) or provider.get("status") != "verified"
        or not isinstance(cleanup, Mapping)
        or cleanup.get("pip_uninstall_exit") != 0
        or cleanup.get("orphan_processes") != 0
    ):
        _fail(
            "NEBULAR_STAGE_B_CONSUMER",
            "The consumer isolation or cleanup evidence is incomplete",
        )
    probes = consumer.get("probes")
    if not isinstance(probes, Mapping):
        _fail("NEBULAR_STAGE_B_CONSUMER", "Consumer command probes are missing")
    native = probes.get("native")
    if (
        not isinstance(native, Mapping)
        or native.get("exit_code") != 0
        or native.get("cleanup_known") is not True
        or native.get("output_complete") is not True
        or native.get("forced_cleanup") is True
    ):
        _fail("NEBULAR_STAGE_B_CONSUMER", "The native consumer command did not complete cleanly")
    return result


def validate_actual_consumer_result(
    result: Mapping[str, Any], *, target: str,
) -> Mapping[str, Any]:
    """Validate the maintained non-fixture result before body projection."""
    return _required_actual_result(result, target=_target(target))


def _actual_host_body(
    host_body: Mapping[str, Any],
    host_extras: Mapping[str, Any],
    *,
    target: str,
    kind: str,
) -> dict[str, Any]:
    checked = validate_observation_body(host_body)
    if checked["target"] != LINUX_TARGETS[target][0] or checked["role"] != kind:
        _fail("NEBULAR_STAGE_B_HOST", "Host observation target or role does not join the consumer")
    try:
        _validate_extras(host_extras, checked)
    except ContractError as exc:
        raise ContractError(
            "NEBULAR_STAGE_B_HOST", "Actual host observation proof is incomplete",
        ) from exc
    return checked


def consumer_body_from_actual(
    qualification: Mapping[str, Any],
    host_body: Mapping[str, Any],
    host_extras: Mapping[str, Any],
    *,
    target: str,
    kind: str,
    wheel: Mapping[str, Any],
) -> dict[str, Any]:
    """Join actual qualification and host observations into the closed body.

    The qualification result must be the non-fixture result returned by the
    maintained ``qualify_nebular070`` path.  Host extras are checked with the
    existing host-observation owner, so a caller cannot turn a config value or
    a synthetic observation into Stage-B evidence.
    """
    target = _target(target)
    kind = _kind(kind)
    _required_actual_result(qualification, target=target)
    _actual_host_body(host_body, host_extras, target=target, kind=kind)
    consumer = qualification["consumer"]
    observed_wheel = consumer.get("wheel")
    if (
        not isinstance(observed_wheel, Mapping)
        or observed_wheel.get("target") != target
        or observed_wheel.get("sha256") != wheel.get("archive_sha256")
        or observed_wheel.get("tag") != wheel.get("tag")
    ):
        _fail("NEBULAR_STAGE_B_WHEEL", "Consumer result does not join the authenticated wheel")
    body = {
        "schema": CONSUMER_RECEIPT_SCHEMA,
        "kind": kind,
        "status": "pass",
        "target": target,
        "wheel_sha256": wheel["archive_sha256"],
        "wheel_tag": wheel["tag"],
        "host": {"glibc": host_body["glibc"], "loader": host_body["loader"]},
    }
    body["identity"] = _digest(body)
    return _consumer_body(body, target=target, wheel=dict(wheel), kind=kind)


def capture_public_consumer(
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
    kind: str,
    run_id: str = "1",
    run_attempt: str = "1",
    manylinux_stage_a: ValidatedPayloadPortability | None = None,
) -> dict[str, Any]:
    """Run the actual hosted consumer and return body plus private join proof.

    ``fixture_only`` and injected sandbox probes are intentionally not exposed
    here.  The only supported path is the maintained non-fixture consumer,
    with its existing no-index/no-deps install, network denial, process-group
    cleanup, and real-user-state callbacks.  The returned ``body`` is the
    exact member written by the Stage-B materializer; the remaining fields are
    same-run private evidence for the assembler and reviewer.
    """
    target = _target(target)
    kind = _kind(kind)
    if manylinux_stage_a is None:
        _fail("NEBULAR_STAGE_B_STAGE_A", "Stage-A portability evidence is required")
    if (
        manylinux_stage_a.fixture_only is not False
        or not isinstance(manylinux_stage_a.record, Mapping)
        or manylinux_stage_a.record.get("evidence_mode") != "actual"
    ):
        _fail("NEBULAR_STAGE_B_STAGE_A", "Fixture Stage-A evidence is not admissible")
    wheel_bytes = physical_bytes(wheel_path, limit=MAX_WHEEL_BYTES)
    wheel = _wheel(wheel_bytes, target, manylinux_stage_a)
    # Establish the role and loader floor before the installed-wheel command
    # can run; a wrong hosted image therefore fails closed without a consumer
    # side effect.
    host_body, host_extras = observe_host(kind)
    kwargs: dict[str, Any] = {
        "expected_artifacts": expected_artifacts,
        "expected_commit": expected_commit,
        "expected_tree": expected_tree,
        "profile_sha256": profile_sha256,
        "candidate_receipt_sha256": candidate_receipt_sha256,
        "target": target,
        "run_id": run_id,
        "run_attempt": run_attempt,
        "sandbox_prefix": default_sandbox_prefix(target),
        "real_user_state_snapshot": make_real_user_state_snapshotter(target),
        "fixture_only": False,
        "manylinux_stage_a": manylinux_stage_a,
    }
    qualification = qualify_nebular070(candidate, wheel_path, raw_release, work, **kwargs)
    body = consumer_body_from_actual(
        qualification, host_body, host_extras, target=target, kind=kind, wheel=wheel,
    )
    return {
        "schema": PUBLIC_CONSUMER_CAPTURE_SCHEMA,
        "evidence_mode": _ACTUAL_CAPTURE_MODE,
        "target": target,
        "kind": kind,
        "body": body,
        "qualification": qualification,
        "host_observation": host_body,
        "host_extras": host_extras,
    }


def _capture_body(
    capture: Mapping[str, Any], *, target: str, kind: str, allow_fixture: bool,
) -> dict[str, Any]:
    if not isinstance(capture, Mapping):
        _fail("NEBULAR_STAGE_B_CONSUMER", "A consumer capture is required")
    if capture.get("target") != target or capture.get("kind") != kind:
        _fail("NEBULAR_STAGE_B_TARGET", "Consumer capture target or kind does not join its slot")
    mode = capture.get("evidence_mode")
    if mode == _ACTUAL_CAPTURE_MODE:
        if capture.get("schema") != PUBLIC_CONSUMER_CAPTURE_SCHEMA:
            _fail("NEBULAR_STAGE_B_CONSUMER", "Actual consumer capture schema is malformed")
        _required_actual_result(capture.get("qualification"), target=target)
        _actual_host_body(
            capture.get("host_observation"), capture.get("host_extras"),
            target=target, kind=kind,
        )
    elif not (allow_fixture and mode == _FIXTURE_CAPTURE_MODE):
        _fail("NEBULAR_STAGE_B_CONSUMER", "Only actual captures are admitted")
    body = capture.get("body")
    if not isinstance(body, Mapping):
        _fail("NEBULAR_STAGE_B_CONSUMER", "Consumer capture body is missing")
    return dict(body)


def _require_same_run(
    approval: Mapping[str, Any], matrix: Mapping[str, Any],
) -> None:
    qualification = approval.get("qualification") if isinstance(approval, Mapping) else None
    if not isinstance(qualification, Mapping):
        _fail("NEBULAR_STAGE_B_RUN", "Approval qualification run is missing")
    run_id = qualification.get("qualification_run_id")
    attempt = qualification.get("qualification_run_attempt")
    if type(run_id) is not str or type(attempt) is not str:
        _fail("NEBULAR_STAGE_B_RUN", "Approval qualification run is not closed")
    if matrix.get("run_id") != run_id or matrix.get("run_attempt") != attempt:
        _fail("NEBULAR_STAGE_B_RUN", "Approval and matrix are from different hosted runs")
    sources = matrix.get("qualification_rs9_source")
    if not isinstance(sources, Mapping) or set(sources) != {"darwin-arm64", *LINUX_TARGETS}:
        _fail("NEBULAR_STAGE_B_RUN", "Matrix qualification sources are incomplete")
    for source in sources.values():
        if not isinstance(source, Mapping) or source.get("run_id") != run_id \
                or source.get("run_attempt") != attempt:
            _fail("NEBULAR_STAGE_B_RUN", "Matrix qualification source is from a different run")
    receipts = matrix.get("receipts")
    if not isinstance(receipts, Mapping):
        _fail("NEBULAR_STAGE_B_RUN", "Matrix receipts are missing")
    for receipt in receipts.values():
        source = receipt.get("qualification_rs9_source") if isinstance(receipt, Mapping) else None
        if not isinstance(source, Mapping) or source.get("run_id") != run_id \
                or source.get("run_attempt") != attempt:
            _fail("NEBULAR_STAGE_B_RUN", "A matrix consumer receipt is from a different run")


def _consumer_evidence_run(capture: Mapping[str, Any], matrix: Mapping[str, Any]) -> None:
    qualification = capture.get("qualification")
    if not isinstance(qualification, Mapping):
        _fail("NEBULAR_STAGE_B_RUN", "Actual consumer qualification is missing")
    source = qualification.get("qualification_rs9_source")
    if (
        qualification.get("run_id") != matrix.get("run_id")
        or qualification.get("run_attempt") != matrix.get("run_attempt")
        or not isinstance(source, Mapping)
        or source.get("run_id") != matrix.get("run_id")
        or source.get("run_attempt") != matrix.get("run_attempt")
    ):
        _fail("NEBULAR_STAGE_B_RUN", "Consumer qualification is from a different run")


def _consumer_evidence_joins(
    capture: Mapping[str, Any],
    *,
    target: str,
    approval: Mapping[str, Any],
    matrix: Mapping[str, Any],
) -> None:
    """Bind the actual consumer's complete source and artifact frame.

    A matching run/attempt is necessary but not sufficient: the consumer must
    describe the same candidate receipt, expected-artifact record, profile, and
    qualification source that the approved matrix and qualification approval
    describe for this target.
    """
    qualification = capture.get("qualification")
    approved_qualification = approval.get("qualification")
    if not isinstance(qualification, Mapping) or not isinstance(approved_qualification, Mapping):
        _fail("NEBULAR_STAGE_B_RUN", "Consumer approval qualification is missing")
    matrix_sources = matrix.get("qualification_rs9_source")
    matrix_receipts = matrix.get("receipts")
    target_source = matrix_sources.get(target) if isinstance(matrix_sources, Mapping) else None
    target_receipt = matrix_receipts.get(target) if isinstance(matrix_receipts, Mapping) else None
    target_receipt_source = (
        target_receipt.get("qualification_rs9_source")
        if isinstance(target_receipt, Mapping)
        else None
    )
    approved_sources = approved_qualification.get("target_qualification_sources")
    approved_target_source = (
        approved_sources.get(target) if isinstance(approved_sources, Mapping) else None
    )
    qualification_source = qualification.get("qualification_rs9_source")
    candidate_source = qualification.get("candidate_rs9_source")
    matrix_candidate_source = matrix.get("candidate_rs9_source")
    approved_candidate_source = {
        "commit": approved_qualification.get("candidate_source_commit"),
        "tree": approved_qualification.get("candidate_source_tree"),
    }
    if not all(
        isinstance(value, Mapping)
        for value in (
            target_source,
            target_receipt,
            target_receipt_source,
            approved_target_source,
            qualification_source,
            candidate_source,
            matrix_candidate_source,
        )
    ):
        _fail("NEBULAR_STAGE_B_RUN", "Consumer source joins are incomplete")
    for left, right in (
        (qualification.get("candidate_receipt_sha256"), approval.get("candidate_receipt_sha256")),
        (qualification.get("candidate_receipt_sha256"), matrix.get("candidate_receipt_sha256")),
        (qualification.get("candidate_receipt_sha256"), target_receipt.get("candidate_receipt_sha256")),
        (qualification.get("expected_artifact_record_sha256"), approval.get("expected_artifact_record_sha256")),
        (qualification.get("expected_artifact_record_sha256"), matrix.get("expected_artifact_record_sha256")),
        (qualification.get("expected_artifact_record_sha256"), target_receipt.get("expected_artifact_record_sha256")),
        (qualification.get("run_id"), approved_qualification.get("qualification_run_id")),
        (qualification.get("run_id"), matrix.get("run_id")),
        (qualification.get("run_attempt"), approved_qualification.get("qualification_run_attempt")),
        (qualification.get("run_attempt"), matrix.get("run_attempt")),
        (qualification_source.get("run_id"), matrix.get("run_id")),
        (qualification_source.get("run_attempt"), matrix.get("run_attempt")),
        (qualification_source.get("profile_sha256"), approved_qualification.get("profile_sha256")),
        (qualification_source.get("profile_sha256"), target_source.get("profile_sha256")),
        (qualification_source.get("profile_sha256"), target_receipt_source.get("profile_sha256")),
        (qualification_source.get("commit"), target_source.get("commit")),
        (qualification_source.get("tree"), target_source.get("tree")),
        (qualification_source.get("commit"), approved_target_source.get("commit")),
        (qualification_source.get("tree"), approved_target_source.get("tree")),
    ):
        if not isinstance(left, str) or left != right:
            _fail("NEBULAR_STAGE_B_RUN", "Consumer source or artifact evidence does not join approval")
    if candidate_source != matrix_candidate_source or candidate_source != approved_candidate_source:
        _fail("NEBULAR_STAGE_B_SOURCE", "Consumer candidate source does not join approval")
    if qualification.get("target") != target or target_receipt.get("target") != target:
        _fail("NEBULAR_STAGE_B_TARGET", "Consumer target does not join the matrix")


def _build_release_record(
    *,
    stage_a: ValidatedPayloadPortability,
    wheel_snapshots: Mapping[str, Mapping[str, Any]],
    consumers: Mapping[str, Mapping[str, Mapping[str, Any]]],
    existing_three_target_approval: Mapping[str, Any],
    existing_matrix_receipt: Mapping[str, Any],
    expected_rs9_release_source: Mapping[str, str],
) -> dict[str, Any]:
    """Derive the post-consumer admission record from authenticated inputs.

    The caller supplies Stage-A, wheel, approval, matrix, and recomputed
    consumer evidence; it cannot predeclare a release record for the
    assembler to trust.  The maintained release validator remains the final
    check of the derived record and all of its external joins.
    """
    if not isinstance(stage_a.record, Mapping):
        _fail("NEBULAR_STAGE_B_SOURCE", "Stage-A source record is missing")
    tf_source = stage_a.record.get("tf_producer_source")
    if not isinstance(tf_source, Mapping) or set(tf_source) != {"commit", "tree"}:
        _fail("NEBULAR_STAGE_B_SOURCE", "Stage-A producer source is incomplete")
    if (
        not isinstance(expected_rs9_release_source, Mapping)
        or set(expected_rs9_release_source) != {"commit", "tree"}
    ):
        _fail("NEBULAR_STAGE_B_SOURCE", "Expected RS9 release source is incomplete")
    rows: list[dict[str, Any]] = []
    for target in LINUX_CONSUMER_TARGETS:
        snapshot = wheel_snapshots.get(target)
        target_consumers = consumers.get(target)
        if (
            not isinstance(snapshot, Mapping)
            or not isinstance(target_consumers, Mapping)
            or set(target_consumers) != set(CONSUMER_KINDS)
        ):
            _fail("NEBULAR_STAGE_B_CONSUMER", "Post-consumer wheel snapshots are incomplete")
        floor = target_consumers.get(ROLE_FLOOR)
        newer = target_consumers.get(ROLE_NEWER)
        if not isinstance(floor, Mapping) or not isinstance(newer, Mapping):
            _fail("NEBULAR_STAGE_B_CONSUMER", "Post-consumer bodies are incomplete")
        rows.append({
            "target": target,
            "tag": snapshot.get("tag"),
            "wheel_archive_sha256": snapshot.get("archive_sha256"),
            "wheel_size": snapshot.get("size"),
            "wheel_member_sha256": snapshot.get("wheel_member_sha256"),
            "record_member_sha256": snapshot.get("record_member_sha256"),
            "provenance_member_sha256": snapshot.get("provenance_member_sha256"),
            "payload_archive_sha256": snapshot.get("payload_archive_sha256"),
            "manifest_sha256": snapshot.get("manifest_sha256"),
            "embedded_stage_a_digest": stage_a.digest,
            "installed_floor_consumer_receipt_sha256": floor.get("identity"),
            "installed_newer_consumer_receipt_sha256": newer.get("identity"),
        })
    approval_files = existing_three_target_approval.get("files")
    darwin_file = next(
        (row for row in approval_files if isinstance(row, Mapping) and row.get("target") == "darwin-arm64"),
        None,
    ) if isinstance(approval_files, list) else None
    matrix_receipts = existing_matrix_receipt.get("receipts")
    darwin_receipt = (
        matrix_receipts.get("darwin-arm64")
        if isinstance(matrix_receipts, Mapping)
        else None
    )
    legal_files = existing_three_target_approval.get("license_files")
    readme = existing_three_target_approval.get("readme")
    if (
        not isinstance(darwin_file, Mapping)
        or not isinstance(darwin_receipt, Mapping)
        or not isinstance(legal_files, Mapping)
        or not isinstance(legal_files.get("LICENSE"), Mapping)
        or not isinstance(legal_files.get("NOTICE"), Mapping)
        or not isinstance(readme, Mapping)
    ):
        _fail("NEBULAR_STAGE_B_APPROVAL", "Approved Darwin and legal inputs are incomplete")
    darwin_row = {
        "target": "darwin-arm64",
        "tag": darwin_file.get("tag"),
        "wheel_archive_sha256": darwin_file.get("sha256"),
        "receipt_sha256": _admission_digest(darwin_receipt),
    }
    record = {
        "schema": ADMISSION_SCHEMA,
        "version": VERSION,
        "claim": CLAIM,
        "stage_a_sha256": stage_a.digest,
        "rs9_release_source": dict(expected_rs9_release_source),
        "tf_producer_source": dict(tf_source),
        "targets": rows,
        "darwin_release_row": darwin_row,
        "existing_three_target_approval_sha256": existing_three_target_approval.get("admission_sha256"),
        "legal_readme_description_digests": {
            "license": legal_files["LICENSE"].get("sha256"),
            "notice": legal_files["NOTICE"].get("sha256"),
            "readme": readme.get("sha256"),
            "description": readme.get("sha256"),
        },
        "manylinux_claim": True,
        "publication_admitted": True,
    }
    record["final_wheel_set_sha256"] = _admission_digest({
        "linux": sorted(rows, key=lambda row: row["target"]),
        "darwin": darwin_row,
    })
    record["identity"] = _admission_digest(record)
    return record


def _actual_capture_body(
    capture: Mapping[str, Any],
    *,
    target: str,
    kind: str,
    wheel: Mapping[str, Any],
    approval: Mapping[str, Any],
    matrix: Mapping[str, Any],
) -> dict[str, Any]:
    """Recompute an actual body from authenticated capture inputs.

    The capture's serialized body is not trusted merely because its outer
    qualification passed.  Recomputing here binds the assembler's wheel
    snapshot and authenticated host sidecar to the body bytes it materializes.
    """
    _consumer_evidence_run(capture, matrix)
    _consumer_evidence_joins(capture, target=target, approval=approval, matrix=matrix)
    supplied = _capture_body(capture, target=target, kind=kind, allow_fixture=False)
    derived = consumer_body_from_actual(
        capture["qualification"],
        capture["host_observation"],
        capture["host_extras"],
        target=target,
        kind=kind,
        wheel=wheel,
    )
    if archive_canonical(supplied) != archive_canonical(derived):
        _fail("NEBULAR_STAGE_B_CONSUMER", "Serialized consumer body differs from authenticated inputs")
    return derived


def _admission_envelope(
    record: Mapping[str, Any], consumers: Mapping[str, Mapping[str, Any]],
    approval: Mapping[str, Any], matrix: Mapping[str, Any],
) -> dict[str, Any]:
    source = record.get("rs9_release_source")
    if not isinstance(source, Mapping) or set(source) != {"commit", "tree"}:
        _fail("NEBULAR_STAGE_B_SOURCE", "Release source is required for consumer members")
    captured: dict[str, dict[str, dict[str, Any]]] = {}
    for target in LINUX_CONSUMER_TARGETS:
        captured[target] = {}
        for kind in CONSUMER_KINDS:
            body = consumers[target][kind]
            raw = archive_canonical(body)
            captured[target][kind] = {
                "member": f"consumers/{target}/{kind}.json",
                "sha256": hashlib.sha256(raw).hexdigest(),
                "source": dict(source),
            }
    return {
        "schema": "rs9.nebular070-manylinux-admission-input.v1",
        "record": dict(record),
        "consumers": {target: dict(consumers[target]) for target in LINUX_CONSUMER_TARGETS},
        "approval": dict(approval),
        "matrix": dict(matrix),
        "captured_consumer_receipts": captured,
    }


def _assemble_stage_b(
    *,
    stage_a: ValidatedPayloadPortability,
    wheel_bytes_by_target: Mapping[str, bytes],
    wheel_filenames_by_target: Mapping[str, str],
    consumer_captures: Mapping[str, Mapping[str, Mapping[str, Any]]],
    existing_three_target_approval: Mapping[str, Any],
    existing_matrix_receipt: Mapping[str, Any],
    expected_rs9_release_source: Mapping[str, str],
    output_dir: str | Path,
    allow_fixture: bool = False,
) -> dict[str, Any]:
    """Validate and materialize the four actual Linux Stage-B members.

    ``allow_fixture`` is test-only: it admits explicitly marked fixture
    captures while retaining every real release/wheel/matrix validator.  The
    default production path is fail-closed for anything other than actual
    captures.  The output directory must be fresh; on an error this function
    removes only the directory it created.
    """
    if not isinstance(stage_a, ValidatedPayloadPortability):
        _fail("NEBULAR_STAGE_B_STAGE_A", "A validated Stage-A object is required")
    if not allow_fixture and (
        stage_a.fixture_only is not False
        or not isinstance(stage_a.record, Mapping)
        or stage_a.record.get("evidence_mode") != "actual"
    ):
        _fail("NEBULAR_STAGE_B_STAGE_A", "Fixture Stage-A evidence is not admissible")
    if not isinstance(consumer_captures, Mapping) \
            or set(consumer_captures) != set(LINUX_CONSUMER_TARGETS):
        _fail("NEBULAR_STAGE_B_CONSUMER", "Both Linux consumer targets are required")
    if not isinstance(existing_three_target_approval, Mapping) \
            or not isinstance(existing_matrix_receipt, Mapping):
        _fail("NEBULAR_STAGE_B_MATRIX", "Approval and matrix snapshots are required")
    _require_same_run(existing_three_target_approval, existing_matrix_receipt)
    consumers: dict[str, dict[str, dict[str, Any]]] = {}
    wheel_snapshots: dict[str, dict[str, Any]] = {}
    for target in LINUX_CONSUMER_TARGETS:
        target_captures = consumer_captures[target]
        if not isinstance(target_captures, Mapping) or set(target_captures) != set(CONSUMER_KINDS):
            _fail("NEBULAR_STAGE_B_CONSUMER", "Both floor and newer captures are required")
        wheel = _wheel(wheel_bytes_by_target[target], target, stage_a)
        wheel_snapshots[target] = wheel
        consumers[target] = {}
        for kind in CONSUMER_KINDS:
            capture = target_captures[kind]
            if isinstance(capture, Mapping) \
                    and capture.get("evidence_mode") == _ACTUAL_CAPTURE_MODE:
                consumers[target][kind] = _actual_capture_body(
                    capture,
                    target=target,
                    kind=kind,
                    wheel=wheel,
                    approval=existing_three_target_approval,
                    matrix=existing_matrix_receipt,
                )
            else:
                body = _capture_body(capture, target=target, kind=kind, allow_fixture=allow_fixture)
                consumers[target][kind] = _consumer_body(body, target=target, wheel=wheel, kind=kind)
    record = _build_release_record(
        stage_a=stage_a,
        wheel_snapshots=wheel_snapshots,
        consumers=consumers,
        existing_three_target_approval=existing_three_target_approval,
        existing_matrix_receipt=existing_matrix_receipt,
        expected_rs9_release_source=expected_rs9_release_source,
    )
    validated = validate_nebular070_release_admission(
        record,
        stage_a=stage_a,
        wheel_bytes_by_target=wheel_bytes_by_target,
        wheel_filenames_by_target=wheel_filenames_by_target,
        installed_consumer_bodies=consumers,
        existing_three_target_approval=existing_three_target_approval,
        existing_matrix_receipt=existing_matrix_receipt,
        expected_rs9_release_source=expected_rs9_release_source,
    )
    envelope = _admission_envelope(
        record, consumers, existing_three_target_approval, existing_matrix_receipt,
    )
    out = Path(output_dir)
    if not out.is_absolute() or out.exists() or out.is_symlink():
        _fail("NEBULAR_STAGE_B_OUTPUT", "A fresh absolute output directory is required")
    if not out.parent.is_dir() or out.parent.is_symlink():
        _fail("NEBULAR_STAGE_B_OUTPUT", "The output parent must be an existing physical directory")
    current = out.parent
    while current.parent != current:
        if current.is_symlink() or not current.is_dir():
            _fail("NEBULAR_STAGE_B_OUTPUT", "The output ancestry is not physical")
        current = current.parent
    out.mkdir(mode=0o700)
    admission_path = out / MANYLINUX_ADMISSION_MEMBER
    try:
        admission_path.write_bytes(canonical(envelope, validate=True))
        materialize_manylinux_consumer_receipts(admission_path, out)
    except Exception:
        if out.is_dir() and not out.is_symlink():
            shutil.rmtree(out)
        raise
    return {
        "schema": STAGE_B_INPUT_SCHEMA,
        "status": "validated-and-materialized",
        "admission_sha256": validated.digest,
        "stage_a_sha256": stage_a.digest,
        "output_dir": out,
        "admission_path": admission_path,
        "record": record,
        "wheel_snapshots": wheel_snapshots,
        "consumer_bodies": consumers,
    }


def assemble_stage_b(
    *,
    stage_a: ValidatedPayloadPortability,
    wheel_bytes_by_target: Mapping[str, bytes],
    wheel_filenames_by_target: Mapping[str, str],
    consumer_captures: Mapping[str, Mapping[str, Mapping[str, Any]]],
    existing_three_target_approval: Mapping[str, Any],
    existing_matrix_receipt: Mapping[str, Any],
    expected_rs9_release_source: Mapping[str, str],
    output_dir: str | Path,
) -> dict[str, Any]:
    """Production assembler; fixture evidence has no public switch."""
    return _assemble_stage_b(
        stage_a=stage_a,
        wheel_bytes_by_target=wheel_bytes_by_target,
        wheel_filenames_by_target=wheel_filenames_by_target,
        consumer_captures=consumer_captures,
        existing_three_target_approval=existing_three_target_approval,
        existing_matrix_receipt=existing_matrix_receipt,
        expected_rs9_release_source=expected_rs9_release_source,
        output_dir=output_dir,
        allow_fixture=False,
    )


def _assemble_stage_b_for_tests(
    *,
    stage_a: ValidatedPayloadPortability,
    wheel_bytes_by_target: Mapping[str, bytes],
    wheel_filenames_by_target: Mapping[str, str],
    consumer_captures: Mapping[str, Mapping[str, Mapping[str, Any]]],
    existing_three_target_approval: Mapping[str, Any],
    existing_matrix_receipt: Mapping[str, Any],
    expected_rs9_release_source: Mapping[str, str],
    output_dir: str | Path,
) -> dict[str, Any]:
    """Private fixture-only assembler used by pure contract tests."""
    return _assemble_stage_b(
        stage_a=stage_a,
        wheel_bytes_by_target=wheel_bytes_by_target,
        wheel_filenames_by_target=wheel_filenames_by_target,
        consumer_captures=consumer_captures,
        existing_three_target_approval=existing_three_target_approval,
        existing_matrix_receipt=existing_matrix_receipt,
        expected_rs9_release_source=expected_rs9_release_source,
        output_dir=output_dir,
        allow_fixture=True,
    )


def _read_json_object(path: str | Path, code: str) -> Mapping[str, Any]:
    try:
        value = strict_json(physical_bytes(path, limit=16 * 1024 * 1024))
    except Exception as error:
        if isinstance(error, ContractError):
            raise
        _fail(code, "A bounded JSON input is malformed")
    if not isinstance(value, Mapping):
        _fail(code, "A bounded JSON object is required")
    return value


def assemble_stage_b_from_paths(
    *,
    stage_a_path: str | Path,
    approval_path: str | Path,
    matrix_path: str | Path,
    wheels_dir: str | Path,
    captures_dir: str | Path,
    output_dir: str | Path,
    expected_tf_producer_source: Mapping[str, str],
    expected_rs9_tool_source: Mapping[str, str],
    expected_rs9_release_source: Mapping[str, str],
) -> dict[str, Any]:
    """Load authenticated hosted inputs and run the production assembler.

    This is intentionally a file-only CLI seam: it reads the already-produced
    Stage-A bundle, approval, matrix, wheel, and four consumer captures, then
    delegates to :func:`assemble_stage_b`.  It never executes a consumer or
    mutates a registry.
    """
    stage_a = load_payload_portability_bundle(
        stage_a_path,
        expected_tf_producer_source=expected_tf_producer_source,
        expected_rs9_tool_source=expected_rs9_tool_source,
    )
    approval = _read_json_object(approval_path, "NEBULAR_STAGE_B_APPROVAL")
    matrix = _read_json_object(matrix_path, "NEBULAR_STAGE_B_MATRIX")
    wheels_root = Path(wheels_dir)
    captures_root = Path(captures_dir)
    wheels: dict[str, bytes] = {}
    filenames: dict[str, str] = {}
    captures: dict[str, dict[str, Mapping[str, Any]]] = {}
    for target in LINUX_CONSUMER_TARGETS:
        tag = LINUX_TARGETS[target][1]
        filename = f"theme_forge_nebular_fusion-0.7.0-{tag}.whl"
        wheel_path = wheels_root / filename
        wheels[target] = physical_bytes(wheel_path, limit=MAX_WHEEL_BYTES)
        filenames[target] = filename
        captures[target] = {
            kind: _read_json_object(
                captures_root / target / f"{kind}.json",
                "NEBULAR_STAGE_B_CONSUMER",
            )
            for kind in CONSUMER_KINDS
        }
    return assemble_stage_b(
        stage_a=stage_a,
        wheel_bytes_by_target=wheels,
        wheel_filenames_by_target=filenames,
        consumer_captures=captures,
        existing_three_target_approval=approval,
        existing_matrix_receipt=matrix,
        expected_rs9_release_source=expected_rs9_release_source,
        output_dir=output_dir,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("assemble-stage-b",))
    parser.add_argument("--stage-a", required=True)
    parser.add_argument("--approval", required=True)
    parser.add_argument("--matrix", required=True)
    parser.add_argument("--wheels-dir", required=True)
    parser.add_argument("--captures-dir", required=True)
    parser.add_argument("--output", required=True)
    for prefix, label in (
        ("tf-producer", "TF producer"),
        ("rs9-tool", "RS9 tool"),
        ("rs9-release", "RS9 release"),
    ):
        parser.add_argument(f"--{prefix}-commit", required=True, help=f"{label} commit")
        parser.add_argument(f"--{prefix}-tree", required=True, help=f"{label} tree")
    args = parser.parse_args(argv)
    try:
        result = assemble_stage_b_from_paths(
            stage_a_path=args.stage_a,
            approval_path=args.approval,
            matrix_path=args.matrix,
            wheels_dir=args.wheels_dir,
            captures_dir=args.captures_dir,
            output_dir=args.output,
            expected_tf_producer_source={
                "commit": args.tf_producer_commit,
                "tree": args.tf_producer_tree,
            },
            expected_rs9_tool_source={
                "commit": args.rs9_tool_commit,
                "tree": args.rs9_tool_tree,
            },
            expected_rs9_release_source={
                "commit": args.rs9_release_commit,
                "tree": args.rs9_release_tree,
            },
        )
    except ContractError as error:
        print(error.code, file=sys.stderr)
        return 2
    except Exception:
        print("NEBULAR_STAGE_B_INPUT", file=sys.stderr)
        return 2
    print(json.dumps({
        "status": result["status"],
        "schema": result["schema"],
        "admission_sha256": result["admission_sha256"],
        "stage_a_sha256": result["stage_a_sha256"],
    }, sort_keys=True))
    return 0


__all__ = [
    "CONSUMER_KINDS",
    "LINUX_CONSUMER_TARGETS",
    "PUBLIC_CONSUMER_CAPTURE_SCHEMA",
    "STAGE_B_INPUT_SCHEMA",
    "assemble_stage_b",
    "assemble_stage_b_from_paths",
    "capture_public_consumer",
    "consumer_body_from_actual",
    "validate_actual_consumer_result",
]


if __name__ == "__main__":
    raise SystemExit(main())
