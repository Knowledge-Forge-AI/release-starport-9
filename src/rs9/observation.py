"""Versioned destination observations, derived from explicit bounded readback."""
from rs9.errors import ContractError
from rs9.records import Record, closed, hash_map, snapshot, validate_bounded_int, validate_rfc3339_utc, validate_sha256, validate_sanitized_string

SCHEMA = "rs9.destination-observation.v1alpha1"
STATES = {"unknown", "unreachable", "absent", "exact", "incomplete", "conflict"}


def validate_destination(destination):
    closed(destination, {"id", "adapter", "mode"})
    for value in destination.values():
        validate_sanitized_string(value)
    snapshot(destination)
    if destination["mode"] not in {"direct", "projection", "contribution"}:
        raise ContractError("DESTINATION_MODE", "Unknown destination mode")


def validate_subject(subject):
    closed(subject, {"package", "version", "revision"})
    validate_sanitized_string(subject["package"])
    validate_sanitized_string(subject["version"])
    snapshot(subject)
    if subject["revision"] is not None:
        validate_bounded_int(subject["revision"], min_val=1, max_val=999999)


def classify_observation(readback, expected_hashes, desired_identity):
    if readback["transport"] == "unreachable":
        return "unreachable"
    if readback["transport"] == "unknown" or not readback["authenticated"]:
        return "unknown"
    if readback["presence"] == "unknown":
        return "unknown"
    if readback["level"] == "none":
        return "unknown"
    if readback["presence"] == "absent":
        if readback["components"] or readback["content_identity_sha256"]:
            raise ContractError("OBSERVATION_CONTRADICTION", "Absent readback contains publication content")
        return "absent"
    observed = readback["components"]
    identity = readback["content_identity_sha256"]
    if identity is not None and identity != desired_identity:
        return "conflict"
    if any(name not in expected_hashes or sha != expected_hashes[name] for name, sha in observed.items()):
        return "conflict"
    if identity is None or set(observed) != set(expected_hashes) or readback["level"] not in {"content", "full"}:
        return "incomplete"
    return "exact"


def observe(destination, subject, expected_hashes, desired_identity, *, readback, source, observed_at,
            remote=None, revisions=None, diagnostics=None, contribution=None, reader=None):
    validate_destination(destination)
    validate_subject(subject)
    expected_hashes = hash_map(expected_hashes)
    validate_sha256(desired_identity)
    closed(readback, {"authenticated", "transport", "presence", "components", "content_identity_sha256", "level"})
    if type(readback["authenticated"]) is not bool or readback["transport"] not in {"ok", "unknown", "unreachable"}:
        raise ContractError("READBACK_CONTRACT", "Explicit authentication and transport status required")
    if readback["presence"] not in {"absent", "present", "unknown"} or readback["level"] not in {"none", "metadata", "content", "full"}:
        raise ContractError("READBACK_CONTRACT", "Explicit presence and readback level required")
    if not isinstance(readback["components"], dict):
        raise ContractError("READBACK_CONTRACT", "Component hash mapping required")
    if readback["components"]:
        hash_map(readback["components"])
    if readback["content_identity_sha256"] is not None:
        validate_sha256(readback["content_identity_sha256"])
    if source not in {"synthetic-fixture", "adapter-readback", "live-read"}:
        raise ContractError("OBSERVATION_SOURCE", "Explicit observation source required")
    if reader is None and source == "synthetic-fixture":
        reader = {"id": "synthetic-fixture", "version": "v1alpha1"}
    closed(reader, {"id", "version"})
    for value in reader.values():
        validate_sanitized_string(value)
    validate_rfc3339_utc(observed_at)
    remote = remote or {}
    closed(remote, {"etag", "commit", "revision", "sequence", "registry_id"}, required=[])
    if "sequence" in remote:
        validate_bounded_int(remote["sequence"])
    for key, value in remote.items():
        if key != "sequence":
            validate_sanitized_string(value)
    revisions = revisions or []
    seen = set()
    for row in revisions:
        closed(row, {"revision", "content_identity_sha256", "complete"})
        validate_bounded_int(row["revision"], min_val=1, max_val=999999)
        validate_sha256(row["content_identity_sha256"])
        if type(row["complete"]) is not bool or row["revision"] in seen:
            raise ContractError("OBSERVATION_REVISIONS", "Unique bounded revision observations required")
        seen.add(row["revision"])
    diagnostics = diagnostics or []
    if len(diagnostics) > 16:
        raise ContractError("DIAGNOSTIC_LIMIT", "Diagnostic count exceeds bound")
    for item in diagnostics:
        closed(item, {"code", "message"})
        validate_sanitized_string(item["code"], max_length=96)
        validate_sanitized_string(item["message"])
    if contribution is not None:
        closed(contribution, {"pr_id", "state"})
        if contribution["state"] not in {"open", "merged", "closed"}:
            raise ContractError("CONTRIBUTION_STATE", "Unknown upstream PR state")
    state = classify_observation(readback, expected_hashes, desired_identity)
    record = {"schema": SCHEMA, "destination": destination, "subject": subject,
              "desired_identity_sha256": desired_identity, "expected_components": expected_hashes,
              "state": state, "readback": readback, "source": source, "reader": reader, "observed_at": observed_at,
              "remote": remote, "revisions": sorted(revisions, key=lambda row: row["revision"]),
              "diagnostics": sorted(diagnostics, key=lambda row: (row["code"], row["message"])),
              "contribution": contribution}
    return Record(snapshot(record))


def validate_observation(observation, destination=None, subject=None, expected_hashes=None, desired_identity=None):
    closed(observation, {"schema", "destination", "subject", "desired_identity_sha256", "expected_components", "state", "readback", "source", "reader", "observed_at", "remote", "revisions", "diagnostics", "contribution"})
    if observation["schema"] != SCHEMA:
        raise ContractError("OBSERVATION_SCHEMA", "Unknown observation schema")
    for actual, expected in ((observation["destination"], destination), (observation["subject"], subject),
                             (observation["expected_components"], expected_hashes), (observation["desired_identity_sha256"], desired_identity)):
        if expected is not None and actual != expected:
            raise ContractError("SUBJECT_MISMATCH", "Observation does not bind the queried desired publication")
    rebuilt = observe(observation["destination"], observation["subject"], observation["expected_components"],
                      observation["desired_identity_sha256"], readback=observation["readback"], source=observation["source"],
                      observed_at=observation["observed_at"], remote=observation["remote"], revisions=observation["revisions"],
                      diagnostics=observation["diagnostics"], contribution=observation["contribution"], reader=observation["reader"])
    if rebuilt != observation:
        raise ContractError("OBSERVATION_STATE", "Observation state or canonical fields contradict readback")
    return rebuilt
