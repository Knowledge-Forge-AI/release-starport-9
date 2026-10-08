"""Typed RPM evidence references and complete bounded diagnostic custody."""
import copy
import json
from pathlib import Path
import re

from rs9.errors import ContractError
from rs9.records import closed, sanitized, validate_sha256
from rs9.release_core import digest
from rs9.scratch import canonical
from rs9.security import scan_for_credentials, validate_safe_relative_posix_path

CURRENT_RPM_EVIDENCE_CONTRACT = "rs9.rpm-evidence-contract.v2"
LINT_PROJECTION_SCHEMA = "rs9.durable-lint-projection.v1"
POLICY_CHUNK_SCHEMA = "rs9.rpm-lint-policy-chunk.v1"
POLICY_SUMMARY_SCHEMA = "rs9.rpm-lint-policy-summary.v1"
PACKAGE_MEMBER_PATH_SCHEMA = "rs9.package-member-path.v1"
EMPTY_MESSAGE_SHA256 = digest(b"")
MAX_CANONICAL_CHUNK_BYTES = 48 * 1024
MAX_DIAGNOSTIC_FILE_BYTES = 64 * 1024
MAX_EVALUATION_BYTES = 512 * 1024
PRIVATE_PATH_REGEX = re.compile(r"/(?:Users|home|root|private|tmp)/|~[/\\]|[A-Za-z]:\\")
KNOWN_RAW_LINT_FIELDS = {
    "schema", "status", "clean", "product", "architecture", "package_file", "package_sha256",
    "spec_file", "spec_sha256", "rpm_identity", "rpm_payload_digest", "identity_status",
    "counts", "findings_summary", "findings", "findings_truncated", "groups", "error_records",
    "error_overflow", "parse_complete", "unparsed_count", "unparsed_samples", "unparsed_sha256",
    "arguments", "session_headers", "effective_configuration", "tool_version", "tool_receipt",
    "reason_token", "diagnostic_truncated",
}
ERROR_FIELDS = {"target", "code", "level", "message", "arguments_sha256", "arguments_complete",
                "path", "mode", "interpreter", "waste_bytes", "dependency", "line"}
EVALUATION_FIELDS = {"schema", "accepted", "status", "blockers", "accepted_findings", "inputs",
                     "policy_sha256", "inventory_sha256", "raw_exit_code", "raw_lint_status",
                     "calculated_duplicate_waste", "duplicate_groups", "member_proofs",
                     "observed_duplicate_groups", "observed_error_members", "rule_blockers", "rule_blocker_causes"}
PATH_FIELDS = {"path", "input_member", "members", "launcher", "target", "member"}


def _fail(code="RPM_POLICY_CUSTODY"):
    raise ContractError(code, "Typed RPM evidence contract or custody differs")


def _member_path(value, product, archive=False):
    validate_safe_relative_posix_path(value if archive else value.removeprefix("/"))
    if archive:
        if not value.startswith(product + "/"):
            _fail("PRIVATE_PATH")
    elif not value.startswith(("/usr/lib/", "/usr/bin/", "/usr/share/")):
        _fail("PRIVATE_PATH")
    return value


def encode_package_member_paths(value, product="theme-forge-nebular-fusion", field=None):
    """Only typed member fields can encode authenticated package/archive paths."""
    if isinstance(value, str):
        scan_for_credentials(value)
        if not PRIVATE_PATH_REGEX.search(value):
            return value
        if field not in PATH_FIELDS:
            _fail("PRIVATE_PATH")
        archive = not value.startswith("/")
        _member_path(value, product, archive)
        return {"schema": PACKAGE_MEMBER_PATH_SCHEMA, "absolute": not archive,
                "components": value.removeprefix("/").split("/")}
    if isinstance(value, list):
        return [encode_package_member_paths(v, product, field) for v in value]
    if isinstance(value, dict):
        return {k: encode_package_member_paths(v, product, k) for k, v in value.items()}
    return value


def decode_package_member_paths(value, product="theme-forge-nebular-fusion", field=None):
    if isinstance(value, dict):
        if value.get("schema") == PACKAGE_MEMBER_PATH_SCHEMA:
            closed(value, {"schema", "absolute", "components"})
            parts = value["components"]
            if (field not in PATH_FIELDS or type(value["absolute"]) is not bool
                    or not isinstance(parts, list) or not 1 <= len(parts) <= 64
                    or any(not isinstance(p, str) or "/" in p or p in {"", ".", ".."} for p in parts)):
                _fail()
            path = ("/" if value["absolute"] else "") + "/".join(parts)
            scan_for_credentials(path)
            return _member_path(path, product, not value["absolute"])
        return {k: decode_package_member_paths(v, product, k) for k, v in value.items()}
    if isinstance(value, list):
        return [decode_package_member_paths(v, product, field) for v in value]
    return value


def _error_projection(record):
    closed(record, ERROR_FIELDS, required={"target", "code", "level", "message", "arguments_sha256", "arguments_complete"})
    validate_sha256(record["arguments_sha256"])
    if type(record["arguments_complete"]) is not bool or not isinstance(record["message"], str):
        _fail("RPM_EVIDENCE_SCHEMA")
    result = copy.deepcopy(record)
    # Only this typed field permits null for absent argument text. Raw is untouched.
    if result["message"] == "":
        if result["arguments_sha256"] != EMPTY_MESSAGE_SHA256:
            _fail("RPM_EVIDENCE_MESSAGE")
        result["message"] = None
    return result


def durable_lint_projection(raw, object_path=None):
    closed(raw, KNOWN_RAW_LINT_FIELDS, required={"schema", "product", "status", "clean", "error_records", "groups", "tool_receipt"})
    if raw["schema"] != "rs9.rpmlint-evidence.v1alpha1" or type(raw["clean"]) is not bool:
        _fail("RPM_EVIDENCE_SCHEMA")
    closed(raw["tool_receipt"], {"tool", "executed", "command", "command_sha256", "exit_code",
           "stdout_sha256", "stderr_sha256", "stdout_bytes", "stderr_bytes"})
    for field, fields in (("counts", {"E", "W", "I"}),
                          ("findings_summary", {"errors", "warnings", "information", "filtered", "packages", "specfiles"}),
                          ("identity_status", {"package", "spec"}),
                          ("rpm_identity", {"name", "version", "release", "arch"}),
                          ("rpm_payload_digest", {"algo_tag", "algorithm", "algorithm_numeric", "capability", "digest",
                            "payload_digest", "payload_digest_algo", "querytags_sha256", "scope", "tag"}),
                          ("effective_configuration", {"filtered_count", "invocation", "listing_sha256", "session_header_sha256"})):
        if field in raw:
            closed(raw[field], fields, required=set())
    if "tool_version" in raw:
        version_fields = {"exit_code", "stderr_length", "stderr_sha256", "stdout_length", "stdout_sha256", "version"}
        closed(raw["tool_version"], version_fields | {"tool", "tool_identity_sha256", "package_query"}, required=set())
        if "package_query" in raw["tool_version"]:
            closed(raw["tool_version"]["package_query"], version_fields, required=set())
    # Validate fields deliberately retained by reference as well as projected fields.
    for finding in raw.get("findings", []):
        closed(finding, {"target", "check", "level", "message", "line"}, required={"target", "check", "level"})
    groups = []
    for group in raw["groups"]:
        closed(group, {"code", "severity", "count", "samples"})
        for sample in group["samples"]:
            closed(sample, {"target", "check", "level", "message", "line"}, required={"target", "check", "level"})
        groups.append({k: group[k] for k in ("code", "severity", "count")})
    path = object_path or "diagnostics/rpmlint-" + raw["product"] + ".json"
    validate_safe_relative_posix_path(path)
    data = canonical(raw)
    scan_for_credentials(data.decode())
    result = {"schema": LINT_PROJECTION_SCHEMA,
              "raw_evidence": {"schema": "rs9.evidence-ref.v1", "kind": "rpmlint-raw-evidence",
                               "object": path, "sha256": digest(data), "size": len(data)},
              "group_counts": groups, "error_records": [_error_projection(e) for e in raw["error_records"]]}
    # Warning samples, headers and parser diagnostics are reference-only by contract.
    fields = {"product", "architecture", "package_file", "package_sha256", "spec_file", "spec_sha256",
              "status", "clean", "reason_token", "parse_complete", "error_overflow", "unparsed_count",
              "counts", "findings_summary", "tool_receipt", "tool_version", "rpm_identity", "rpm_payload_digest",
              "effective_configuration", "identity_status"}
    result.update({k: copy.deepcopy(raw[k]) for k in fields if k in raw})
    sanitized(result)
    return result


def validate_durable_lint(projection, raw):
    expected = durable_lint_projection(raw, projection.get("raw_evidence", {}).get("object"))
    if canonical(projection) != canonical(expected):
        _fail("RPM_EVIDENCE_PROJECTION")
    return True


def _evaluation(evaluation):
    closed(evaluation, EVALUATION_FIELDS, required={"schema", "accepted", "status", "blockers", "inputs"})
    if (evaluation["schema"] != "rs9.rpm-lint-policy-evaluation.v1"
            or type(evaluation["accepted"]) is not bool
            or evaluation["status"] not in ({"accepted", "accepted-no-exceptions"} if evaluation["accepted"] else {"blocked"})):
        _fail("RPM_EVIDENCE_SCHEMA")
    inputs = evaluation["inputs"]
    closed(inputs, {"project_id", "version", "arch", "system", "asset_sha256", "payload_manifest_sha256", "closure_sha256"},
           required={"project_id", "version", "arch", "system"})
    sanitized(inputs)
    if inputs["system"] not in {"x86_64-linux", "aarch64-linux"}:
        _fail("RPM_EVIDENCE_SCHEMA")
    data = canonical(evaluation)
    if len(data) > MAX_EVALUATION_BYTES:
        _fail("POLICY_CHUNK_LIMIT")
    scan_for_credentials(data.decode())
    return inputs


def policy_chunks(evaluation):
    inputs = _evaluation(evaluation)
    encoded = encode_package_member_paths(evaluation, inputs["project_id"])
    identity = {"product": inputs["project_id"], "system": inputs["system"], "version": inputs["version"],
                "asset_sha256": inputs.get("asset_sha256"), "evaluation_sha256": digest(canonical(evaluation))}
    scalars = {k: v for k, v in encoded.items() if not isinstance(v, list)}
    sections = [("scalars", [scalars])] + [(k, v) for k, v in sorted(encoded.items()) if isinstance(v, list)]
    chunks = []
    def make(section, items, offset):
        return {"schema": POLICY_CHUNK_SCHEMA, **identity, "part": len(chunks) + 1, "total_parts": 128,
                "section": section, "offset": offset, "items": items, "items_sha256": digest(canonical(items))}
    for section, values in sections:
        items, offset = [], 0
        for value in values:
            candidate = make(section, items + [value], offset)
            if len(canonical(candidate)) > MAX_CANONICAL_CHUNK_BYTES:
                if not items:
                    _fail("POLICY_CHUNK_LIMIT")
                chunks.append(make(section, items, offset))
                offset += len(items)
                items = []
                if len(canonical(make(section, [value], offset))) > MAX_CANONICAL_CHUNK_BYTES:
                    _fail("POLICY_CHUNK_LIMIT")
            items.append(value)
        chunks.append(make(section, items, offset))
    if not 1 <= len(chunks) <= 128:
        _fail("POLICY_CHUNK_LIMIT")
    for index, chunk in enumerate(chunks, 1):
        chunk.update(part=index, total_parts=len(chunks))
        if len(canonical(chunk)) > MAX_CANONICAL_CHUNK_BYTES:
            _fail("POLICY_CHUNK_LIMIT")
    return chunks


def policy_summary(evaluation, chunks=None):
    inputs = _evaluation(evaluation)
    chunks = policy_chunks(evaluation) if chunks is None else chunks
    product = inputs["project_id"]
    result = {"schema": POLICY_SUMMARY_SCHEMA, "product": product, "system": inputs["system"],
              "version": inputs["version"], "architecture": inputs["arch"], "inputs": copy.deepcopy(inputs),
              "accepted": evaluation["accepted"], "status": evaluation["status"],
              "blockers": copy.deepcopy(evaluation["blockers"]),
              "rule_blockers": copy.deepcopy(evaluation.get("rule_blockers", [])),
              "accepted_findings": [_error_projection(e) for e in evaluation.get("accepted_findings", [])],
              "accepted_findings_count": len(evaluation.get("accepted_findings", [])),
              "raw_lint_status": evaluation.get("raw_lint_status"), "raw_exit_code": evaluation.get("raw_exit_code"),
              "policy_sha256": evaluation.get("policy_sha256"), "inventory_sha256": evaluation.get("inventory_sha256"),
              "calculated_duplicate_waste": evaluation.get("calculated_duplicate_waste"),
              "evaluation_sha256": digest(canonical(evaluation)), "evaluation_size": len(canonical(evaluation)),
              "chunk_count": len(chunks),
              "chunks": [{"part": i, "total_parts": len(chunks), "sha256": digest(canonical(c)),
                          "size": len(canonical(c)),
                          "object": "diagnostics/rpm-lint-policy-" + product + ".part-" + format(i, "04d") + ".json"}
                         for i, c in enumerate(chunks, 1)]}
    result = encode_package_member_paths(result, product)
    sanitized(result)
    return result


def assemble_policy_evaluation(summary, chunks):
    if (not isinstance(summary, dict) or summary.get("schema") != POLICY_SUMMARY_SCHEMA
            or not isinstance(chunks, list) or not chunks or len(chunks) != summary.get("chunk_count")
            or len(chunks) != len(summary.get("chunks", [])) or len(chunks) > 128):
        _fail()
    inputs = summary.get("inputs", {})
    rebuilt, sections, last_section = {}, set(), None
    for index, (chunk, ref) in enumerate(zip(chunks, summary["chunks"]), 1):
        closed(chunk, {"schema", "product", "system", "version", "asset_sha256", "evaluation_sha256",
                       "part", "total_parts", "section", "offset", "items", "items_sha256"})
        if (chunk["schema"] != POLICY_CHUNK_SCHEMA or chunk["part"] != index or chunk["total_parts"] != len(chunks)
                or any(chunk[k] != v for k, v in {"product": inputs.get("project_id"), "system": inputs.get("system"),
                    "version": inputs.get("version"), "asset_sha256": inputs.get("asset_sha256"),
                    "evaluation_sha256": summary.get("evaluation_sha256")}.items())
                or len(canonical(chunk)) > MAX_CANONICAL_CHUNK_BYTES
                or ref.get("sha256") != digest(canonical(chunk)) or ref.get("size") != len(canonical(chunk))
                or ref.get("part") != index or ref.get("total_parts") != len(chunks)
                or not isinstance(chunk["items"], list) or digest(canonical(chunk["items"])) != chunk["items_sha256"]):
            _fail()
        section = chunk["section"]
        if section == "scalars":
            if index != 1 or chunk["offset"] != 0 or len(chunk["items"]) != 1 or not isinstance(chunk["items"][0], dict):
                _fail()
            rebuilt = copy.deepcopy(chunk["items"][0])
        else:
            if section not in EVALUATION_FIELDS or section in rebuilt and not isinstance(rebuilt[section], list):
                _fail()
            if section != last_section and section in sections:
                _fail()
            sections.add(section)
            values = rebuilt.setdefault(section, [])
            if chunk["offset"] != len(values):
                _fail()
            values.extend(copy.deepcopy(chunk["items"]))
        last_section = section
    rebuilt = decode_package_member_paths(rebuilt, inputs.get("project_id"))
    _evaluation(rebuilt)
    if (digest(canonical(rebuilt)) != summary.get("evaluation_sha256")
            or len(canonical(rebuilt)) != summary.get("evaluation_size")
            or canonical(policy_summary(rebuilt, chunks)) != canonical(summary)
            or canonical(policy_chunks(rebuilt)) != canonical(chunks)):
        _fail()
    return rebuilt


def write_policy_evidence(directory, evaluation):
    directory = Path(directory)
    if directory.name != "diagnostics":
        directory /= "diagnostics"
    directory.mkdir(parents=True, exist_ok=True)
    chunks = policy_chunks(evaluation)
    summary = policy_summary(evaluation, chunks)
    assemble_policy_evaluation(summary, chunks)
    paths = []
    for chunk, ref in zip(chunks, summary["chunks"]):
        path = directory / Path(ref["object"]).name
        path.write_bytes(canonical(chunk))
        paths.append(path)
    path = directory / ("rpm-lint-policy-" + summary["product"] + ".json")
    path.write_bytes(canonical(summary))
    return summary, [path, *paths]


def verify_policy_custody(directory, manifest, summary):
    from rs9.hosted_custody import diagnostic_bytes, file_identity
    directory = Path(directory)
    product = summary.get("inputs", {}).get("project_id")
    if not isinstance(product, str):
        _fail()
    stem = "rpm-lint-policy-" + product
    rows = [r for r in manifest.get("files", []) if Path(r["path"]).name == stem + ".json"
            or Path(r["path"]).name.startswith(stem + ".part-")]
    summary_rows = [r for r in rows if Path(r["path"]).name == stem + ".json"]
    if len(summary_rows) != 1 or len(rows) != summary.get("chunk_count", 0) + 1:
        _fail()
    row = summary_rows[0]
    validate_safe_relative_posix_path(row["path"])
    summary_path = directory / row["path"]
    base = summary_path.parent
    if (any(p.is_symlink() for p in (summary_path, *summary_path.parents))
            or file_identity(summary_path) != {"sha256": row.get("sha256"), "size": row.get("size")}
            or diagnostic_bytes(summary_path) != canonical(summary)):
        _fail()
    expected_names = {stem + ".json"} | {Path(r["object"]).name for r in summary["chunks"]}
    actual_names = {p.name for p in base.iterdir() if p.name == stem + ".json" or p.name.startswith(stem + ".part-")}
    if actual_names != expected_names:
        _fail()
    chunks = []
    for ref in summary["chunks"]:
        validate_safe_relative_posix_path(ref["object"])
        path = base / Path(ref["object"]).name
        matches = [r for r in rows if r["path"] == path.relative_to(directory).as_posix()]
        if (len(matches) != 1 or matches[0].get("sha256") != ref["sha256"] or matches[0].get("size") != ref["size"]
                or any(p.is_symlink() for p in (path, *path.parents))
                or file_identity(path) != {"sha256": ref["sha256"], "size": ref["size"]}):
            _fail()
        chunks.append(json.loads(diagnostic_bytes(path)))
    return assemble_policy_evaluation(summary, chunks)


def is_current_rpm_evidence_contract(receipt_or_details):
    if not isinstance(receipt_or_details, dict):
        return False
    details = receipt_or_details.get("details", receipt_or_details)
    return isinstance(details, dict) and details.get("rpm_evidence_contract") == CURRENT_RPM_EVIDENCE_CONTRACT


def verify_raw_custody(directory, manifest, raw, product=None, receipt=None, derivation=None, rpm_manifest=None):
    """Resolve only manifest-selected producer objects; authenticate before projecting."""
    from rs9.hosted_custody import diagnostic_bytes, file_identity
    directory = Path(directory)
    product = product or (raw.get("product") if isinstance(raw, dict) else None)
    def fail(suffix):
        raise ContractError("RPM_RAW_EVIDENCE_" + suffix, "Retained RPM raw evidence differs",
                            details={"product": product})
    if not isinstance(raw, dict) or raw.get("schema") != "rs9.rpmlint-evidence.v1alpha1":
        fail("SCHEMA")
    if product not in {"theme-forge-stellar-burst", "theme-forge-stellar-loom", "theme-forge-solar-sail", "theme-forge-nebular-fusion"} or raw.get("product") != product:
        fail("PRODUCT")
    rows = manifest.get("files", [])
    stem = "rpmlint-" + product + ".json"
    # Hosted pipeline retains lane-work beneath its outer scratch. Standalone
    # retain uses the lane scratch itself; these are the two explicit layouts.
    candidates = [r for r in rows if r.get("path") in {"objects/diagnostics/" + stem, "objects/lane-work/diagnostics/" + stem}]
    if len(candidates) != 1:
        fail("UNSELECTED" if (directory / "objects/diagnostics" / stem).exists() or (directory / "objects/lane-work/diagnostics" / stem).exists() else "MISSING")
    row = candidates[0]
    if row.get("kind") != "evidence":
        fail("UNSELECTED")
    prefix = row["path"].removesuffix("diagnostics/" + stem)
    path = directory / row["path"]
    if any(p.is_symlink() for p in (path, *path.parents)):
        fail("UNSELECTED")
    if not path.is_file():
        fail("MISSING")
    identity = file_identity(path)
    if identity["size"] != row.get("size"):
        fail("SIZE")
    if identity["sha256"] != row.get("sha256"):
        fail("HASH")
    try:
        retained_bytes = diagnostic_bytes(path)
        retained = json.loads(retained_bytes)
    except ContractError as err:
        fail("WITHHELD" if err.code == "DIAGNOSTIC_LIMIT" else "SCHEMA")
    except (ValueError, UnicodeError):
        fail("SCHEMA")
    if not isinstance(retained, dict):
        fail("SCHEMA")
    if retained.get("schema") == "rs9.withheld-diagnostic.v1alpha1":
        fail("WITHHELD")
    if retained.get("schema") != raw.get("schema"):
        fail("SCHEMA")
    if retained.get("product") != product:
        fail("PRODUCT")
    if retained_bytes != canonical(raw):
        fail("HASH")
    if any(Path(r.get("path", "")).name.startswith("rpmlint-" + product) and r is not row for r in rows):
        fail("UNSELECTED")
    if any(p.name.startswith("rpmlint-" + product) and p.name != stem for p in path.parent.iterdir()):
        fail("UNSELECTED")
    if receipt is not None:
        if receipt.get("lane") != "rpm" or manifest.get("lane") != "rpm":
            fail("SOURCE")
        system = receipt.get("system")
        if manifest.get("system") != system or system not in {"x86_64-linux", "aarch64-linux"}:
            fail("SYSTEM")
        if raw.get("architecture") not in {"noarch", system.removesuffix("-linux")}:
            fail("SYSTEM")
        provenance = receipt.get("provenance", {})
        required_source = {"source_commit", "workflow_sha256", "contract_sha256", "release_ingestion_sha256", "builder_source_sha256", "ref", "event", "attempt"}
        if not isinstance(provenance, dict) or not required_source.issubset(provenance) or not required_source.issubset(manifest):
            fail("SOURCE")
        for key, value in provenance.items():
            if manifest.get(key) != value:
                fail("SOURCE")
        summary = receipt.get("details", {}).get("rpm_lint_policy", {}).get(product, {})
        if receipt.get("details", {}).get("rpm_lint_raw", {}).get(product) != raw:
            fail("HASH")
        if (("raw_lint_status" in summary and summary["raw_lint_status"] != raw.get("status"))
                or ("raw_exit_code" in summary and summary["raw_exit_code"] != raw.get("tool_receipt", {}).get("exit_code"))):
            fail("SCHEMA")
    else:
        summary = {}

    selected_manifests = [r for r in rows if r.get("path") == prefix + "build/" + product + "/rpm-manifest.json"]
    if len(selected_manifests) > 1:
        fail("UNSELECTED")
    if selected_manifests:
        mr = selected_manifests[0]
        mp = directory / mr["path"]
        if any(p.is_symlink() for p in (mp, *mp.parents)) or not mp.is_file():
            fail("MISSING")
        mid = file_identity(mp)
        if mid["size"] != mr.get("size"):
            fail("SIZE")
        if mid["sha256"] != mr.get("sha256"):
            fail("HASH")
        if mid["size"] > 16 * 1024 * 1024:
            fail("SIZE")
        try:
            data = mp.read_bytes()
            scan_for_credentials(data.decode("utf-8"))
            selected_manifest = json.loads(data)
        except (ValueError, UnicodeError):
            fail("SCHEMA")
        if rpm_manifest is not None and canonical(rpm_manifest) != canonical(selected_manifest):
            fail("HASH")
        rpm_manifest = selected_manifest
    elif (summary.get("accepted") is True and product not in (receipt or {}).get("details", {}).get("product_failures", {})) or rpm_manifest is not None or derivation is not None:
        fail("UNSELECTED")

    if rpm_manifest is not None:
        if rpm_manifest.get("schema") != "rs9.rpm-candidate.v1alpha2":
            fail("SCHEMA")
        if rpm_manifest.get("project") != product:
            fail("PRODUCT")
        if rpm_manifest.get("architecture") != raw.get("architecture"):
            fail("SYSTEM")
        if rpm_manifest.get("package_sha256") != raw.get("package_sha256"):
            fail("PACKAGE")
        if rpm_manifest.get("rpmlint") != raw:
            fail("HASH")
        selected_derivation = rpm_manifest.get("derivation")
        if not isinstance(selected_derivation, dict):
            _fail("RPM_EVIDENCE_PROJECTION")
        if derivation is not None and derivation != selected_derivation:
            _fail("RPM_EVIDENCE_PROJECTION")
        derivation = selected_derivation
        packages = [r for r in rows if r.get("path", "").startswith(prefix + "unsigned/") and r.get("kind") == "custody"
                    and Path(r["path"]).name == Path(rpm_manifest.get("package_file", "")).name]
        if len(packages) != 1 or packages[0].get("sha256") != raw.get("package_sha256") or packages[0].get("size") != rpm_manifest.get("package_size"):
            fail("PACKAGE")
        pp = directory / packages[0]["path"]
        if file_identity(pp) != {"sha256": packages[0]["sha256"], "size": packages[0]["size"]}:
            fail("PACKAGE")

    logical_object = "diagnostics/" + stem
    projection = durable_lint_projection(raw, object_path=logical_object)
    if derivation is not None:
        if not isinstance(derivation, dict) or derivation.get("project") != product or derivation.get("adapter") != "rpm":
            fail("PRODUCT")
        if derivation.get("artifact", {}).get("sha256") != raw.get("package_sha256"):
            fail("PACKAGE")
        durable = derivation.get("evidence", {}).get("rpmlint")
        if not isinstance(durable, dict):
            _fail("RPM_EVIDENCE_PROJECTION")
        ref = durable.get("raw_evidence", {})
        if ref.get("object") != logical_object:
            fail("UNSELECTED")
        if ref.get("schema") != "rs9.evidence-ref.v1" or ref.get("kind") != "rpmlint-raw-evidence":
            fail("SCHEMA")
        if ref.get("size") != row["size"]:
            fail("SIZE")
        if ref.get("sha256") != row["sha256"]:
            fail("HASH")
        validate_durable_lint(durable, retained)
        if durable != projection:
            _fail("RPM_EVIDENCE_PROJECTION")
    validate_durable_lint(projection, retained)
    return projection


def verify_rpm_custody(directory, manifest, receipt, derivations=None, rpm_manifests=None):
    if receipt.get("lane") != "rpm":
        return
    details = receipt.get("details", {})
    contract_marker = details.get("rpm_evidence_contract")
    is_current = contract_marker == CURRENT_RPM_EVIDENCE_CONTRACT

    if contract_marker is not None and not is_current:
        _fail("RPM_POLICY_CUSTODY")

    if not is_current:
        raise ContractError("RPM_POLICY_CUSTODY", "Current consumer requires an explicit RPM evidence contract")

    policies = details.get("rpm_lint_policy", {})
    raws = details.get("rpm_lint_raw", {})
    if not isinstance(policies, dict) or not isinstance(raws, dict):
        _fail()
    if not policies and not raws:
        if receipt.get("execution_error") or not any(g.get("name") == "rpm-lint-policy-accepted" and g.get("status") == "pass"
                                                     for g in receipt.get("gates", [])):
            return {}
        _fail()
    if set(policies) != set(raws):
        _fail("RPM_RAW_EVIDENCE_MISSING" if set(policies) - set(raws) else "RPM_POLICY_CUSTODY")
    results = {}
    for product, raw in raws.items():
        derivation = (derivations or {}).get(product)
        rpm_m = (rpm_manifests or {}).get(product)
        results[product] = verify_raw_custody(directory, manifest, raw, product=product, receipt=receipt,
                                              derivation=derivation, rpm_manifest=rpm_m)
    for product, summary in policies.items():
        if summary.get("schema") != POLICY_SUMMARY_SCHEMA:
            raise ContractError("RPM_POLICY_CUSTODY", "Current producer contract requires chunk summaries; inline bypass not permitted")
        if (summary.get("inputs", {}).get("project_id") != product
                or summary.get("inputs", {}).get("system") != receipt.get("system")):
            raise ContractError("RPM_POLICY_CUSTODY", "Policy and receipt identities differ")
        verify_policy_custody(directory, manifest, summary)

    return results


def historical_policy_diagnostic(receipt, *, contract, directory=None, manifest=None):
    """Explicit archive interpretation never supplies new qualification authority."""
    if contract not in {"cont11", "cont12-inline", "cont12-chunked"}:
        _fail()
    if (receipt.get("production_enabled") is not False or receipt.get("publication_authority") is not False
            or receipt.get("details", {}).get("rpm_evidence_contract") is not None):
        _fail()
    results = {}
    for product, value in receipt.get("details", {}).get("rpm_lint_policy", {}).items():
        if contract == "cont12-chunked":
            if directory is None or manifest is None or value.get("schema") != POLICY_SUMMARY_SCHEMA:
                _fail()
            results[product] = verify_policy_custody(directory, manifest, value)
        else:
            if value.get("schema") != "rs9.rpm-lint-policy-evaluation.v1" or "chunks" in value or "evaluation_sha256" in value:
                _fail()
            results[product] = copy.deepcopy(value)
    return {"schema": "rs9.historical-rpm-policy-diagnostic.v1", "contract": contract,
            "qualification_authority": False, "evaluations": results}
