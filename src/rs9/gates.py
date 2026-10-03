"""Stable evidence-bound qualification gates; ecosystem policy remains explicit."""
from rs9.errors import ContractError
from rs9.records import Record, closed, record_sha256, snapshot, validate_sha256, validate_sanitized_string

STATUSES = {"pass", "fail", "not-run", "not-applicable", "deferred"}


def gate(gate_id, status, scope, evidence=(), *, reason, blocker=None):
    for value in (gate_id, scope, reason):
        validate_sanitized_string(value)
    if blocker is not None:
        validate_sanitized_string(blocker)
    if status not in STATUSES:
        raise ContractError("GATE_STATUS", "Unknown qualification status")
    rows = [dict(row) for row in evidence]
    for row in rows:
        closed(row, {"kind", "sha256"})
        validate_sanitized_string(row["kind"])
        validate_sha256(row["sha256"])
    rows.sort(key=lambda row: (row["kind"], row["sha256"]))
    if len({(row["kind"], row["sha256"]) for row in rows}) != len(rows):
        raise ContractError("GATE_EVIDENCE", "Duplicate gate evidence")
    if status == "pass" and not rows:
        raise ContractError("EMPTY_EVIDENCE", "Passing qualification requires bound evidence")
    return Record(snapshot({"schema": "rs9.qualification-gate.v1alpha1", "id": gate_id,
                           "status": status, "scope": scope, "evidence": rows,
                           "reason": reason, "blocker": blocker}))


def validate_gate(value):
    closed(value, {"schema", "id", "status", "scope", "evidence", "reason", "blocker"})
    if value["schema"] != "rs9.qualification-gate.v1alpha1":
        raise ContractError("GATE_SCHEMA", "Unknown gate contract")
    rebuilt = gate(value["id"], value["status"], value["scope"], value["evidence"], reason=value["reason"], blocker=value["blocker"])
    if rebuilt != value:
        raise ContractError("GATE_SCHEMA", "Gate must be canonical")
    return rebuilt


def license_status(intent, profile):
    sections = profile["sections"]
    license_record = sections.get("license", sections.get("legacy_ingestion", {}).get("license", {}))
    if license_record.get("status") == "conflict":
        return "fail", "tenant-license-conflict"
    if intent.get("license", {}).get("status") == "unresolved":
        return "deferred", "tenant-license-unresolved"
    # Declaration agreement does not itself establish licensing authority.
    return "not-run", "license-authority-not-qualified"


def derive_gates(intent, capture, profile, output):
    # Only core authentication produces this sealed hash. JSON cannot reauthorize.
    from rs9.release_core import authenticated_record_hash
    release_hash = authenticated_record_hash(capture)
    status, blocker = license_status(intent, profile)
    manifest = output["source_manifest"]
    # A renderer's own verdict is diagnostic, never publication authority.
    package_status = "not-run"
    return [gate("release.authenticated", "pass", "release", [{"kind": "release-record", "sha256": release_hash}], reason="captured-byte-authentication"),
            gate("license.authority", status, "tenant", [{"kind": "profile-result", "sha256": record_sha256(profile)}], reason=blocker or "tenant-authority-resolved", blocker=blocker),
            gate("package.render", package_status, output["destination"]["adapter"], [{"kind": "source-manifest", "sha256": output["source_manifest_sha256"]}], reason="package-qualified" if package_status == "pass" else "shadow-qualification-deferred")]


def check_gates(intent, capture, profile, output, values, policy):
    from rs9.adapter_gates import mandatory_gates
    from rs9.qualification import bound_qualifications
    from rs9.release_core import authenticated_record_hash
    release_hash = authenticated_record_hash(capture)
    rows = sorted([validate_gate(value) for value in values], key=lambda value: value["id"])
    by_id = {row["id"]: row for row in rows}
    if len(by_id) != len(rows):
        raise ContractError("GATE_ID", "Gate IDs must be unique")
    mandatory = mandatory_gates(intent, output["destination"]["adapter"])
    required = sorted(set(policy["required_gates"]) | mandatory)
    known = {"release.authenticated": ("release-record", release_hash),
             "license.authority": ("profile-result", record_sha256(profile)),
             "package.render": ("source-manifest", output["source_manifest_sha256"])}
    reasons = []
    for gate_id in required:
        row = by_id.get(gate_id)
        if row is None:
            reasons.append("missing:" + gate_id)
            continue
        if row["status"] == "not-applicable" and gate_id not in mandatory and gate_id in policy["allow_not_applicable"]:
            continue
        if row["status"] != "pass":
            reasons.append("status:" + gate_id + ":" + row["status"])
            continue
        if gate_id in known:
            kind, sha = known[gate_id]
            if {"kind": kind, "sha256": sha} not in row["evidence"]:
                reasons.append("unbound:" + gate_id)
            expected_scope = {"release.authenticated": "release", "license.authority": "tenant", "package.render": output["destination"]["adapter"]}[gate_id]
            if row["scope"] != expected_scope:
                reasons.append("scope:" + gate_id)
        if gate_id != "release.authenticated":
            allowed = set(policy["external_evidence"].get(gate_id, []))
            executed = set(bound_qualifications(capture, output, gate_id))
            evidence = {e["sha256"] for e in row["evidence"] if e["kind"] == "qualification-record"}
            if not evidence or not evidence <= (allowed & executed):
                reasons.append("execution-evidence-unbound:" + gate_id)
    status, blocker = license_status(intent, profile)
    authority = by_id.get("license.authority", {})
    bound_authority = bool(set(bound_qualifications(capture, output, "license.authority")) & set(policy["external_evidence"].get("license.authority", [])))
    if status == "not-run" and authority.get("status") == "pass" and bound_authority:
        sections = profile["sections"]
        record = sections.get("license", sections.get("legacy_ingestion", {}).get("license", {}))
        if record.get("status") != "consistent":
            reasons.append("license-declaration-inconsistent")
    else:
        reasons.append(blocker)
    return rows, sorted(set(reasons))
