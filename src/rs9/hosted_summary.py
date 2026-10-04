"""Source-defined hosted lane completeness and qualification without publication."""
import hashlib
import json
import os
from pathlib import Path

from rs9.errors import ContractError
from rs9.hosted_custody import provenance, verify_set
from rs9.scratch import canonical


def contract(repository):
    return json.loads((repository / "operators/live1/hosted-lanes.json").read_bytes())


def required(repository):
    return [r for r in contract(repository)["lanes"] if r.get("module")]


def gate_blockers(lane, receipt):
    blockers = []
    gates = receipt.get("gates", [])
    names = [g["name"] for g in gates]
    for name in lane["required_gates"]:
        matches = [g for g in gates if g["name"] == name]
        if len(matches) != 1:
            blockers.append("missing-or-duplicate-gate:" + name)
            continue
        gate = matches[0]
        allowed = lane.get("allowed_not_run", {}).get(name)
        if gate["status"] != "pass" and not (gate["status"] == "not-run" and gate.get("reason") == allowed and allowed):
            blockers.append(gate["status"] + ":" + name)
    blockers.extend("failed-gate:" + g["name"] for g in gates if g["status"] == "fail")
    if len(names) != len(set(names)):
        blockers.append("duplicate-gates")
    return blockers


def summarize(repository, inputs, output):
    lanes = required(repository)
    reasons, receipts, manifests = [], [], []
    jobs = json.loads(os.environ.get("RS9_JOB_CONCLUSIONS", "{}"))
    expected_jobs = set(contract(repository)["required_jobs"]) - {"summary"}
    if set(jobs) != expected_jobs or any(row.get("result") != "success" for row in jobs.values()):
        reasons.append("missing-or-failed-required-workflow-job")
    auth_values = set()
    for lane in lanes:
        directory = inputs / lane["artifact_name"]
        try:
            manifest = verify_set(directory)
            name = lane["lane"] + "-" + lane["system"] + ".json"
            receipt = json.loads((directory / name).read_bytes())
            if receipt["lane"] != lane["lane"] or receipt["system"] != lane["system"]:
                raise ContractError("SUMMARY_LANE", "Receipt lane differs from source contract")
            auth_values.add(manifest["release_ingestion_sha256"])
            receipts.append(receipt)
            manifests.append(manifest)
            reasons.extend(lane["artifact_name"] + ":" + r for r in gate_blockers(lane, receipt))
            if lane.get("custody_required") and not any(r["kind"] == "custody" for r in manifest["files"]):
                reasons.append(lane["artifact_name"] + ":missing-custody-objects")
            for product in lane.get("required_products", []):
                needle = product.replace("-", "_") if lane["lane"] == "wheels" else product
                if not any(Path(r["path"]).name.startswith(needle + "-" if lane["lane"] != "deb" else needle + "_")
                           and r["kind"] == "custody" and r.get("promotion") != "fixture-test-only" for r in manifest["files"]):
                    reasons.append(lane["artifact_name"] + ":missing-product:" + product)
            if receipt.get("execution_error"):
                reasons.append(lane["artifact_name"] + ":execution-failed")
            reasons.extend(receipt.get("policy_blockers", []))
        except (ContractError, OSError, ValueError, KeyError) as error:
            reasons.append(lane["artifact_name"] + ":" + (error.code if isinstance(error, ContractError) else "missing-or-invalid-artifact"))
    if len(auth_values) != 1 or None in auth_values:
        reasons.append("release-projection-missing-or-mixed")
    ingestion = next(iter(auth_values)) if len(auth_values) == 1 else None
    expected = provenance(repository, ingestion)
    for manifest in manifests:
        if any(manifest.get(k) != v for k, v in expected.items()):
            reasons.append("mixed-source-or-run-provenance")
    actual = {p.name for p in inputs.iterdir() if p.is_dir()}
    expected_sets = {r["artifact_name"] for r in lanes}
    if actual != expected_sets:
        reasons.append("missing-or-surplus-artifact-sets")
    qualified = not reasons
    record = {"schema": "rs9.hosted-candidate-summary.v1alpha2", **expected,
              "production_enabled": False, "publication_authority": False, "attended_gates_satisfied": False,
              "adoptable": expected["event"] == "push" and expected["ref"] == "refs/heads/main" and expected["attempt"] == 1,
              "qualification_verdict": "qualified" if qualified else "not-qualified",
              "lanes_executed_ok": len(receipts) == len(lanes) and all(not r.get("execution_error") for r in receipts),
              "blocking_reasons": sorted(set(reasons)), "receipts": receipts, "artifact_manifests": manifests}
    record["job_conclusions"] = {key: row.get("result") for key, row in jobs.items()}
    raw = canonical(record)
    if len(raw) > 16 * 1024 ** 2:
        raise ContractError("SUMMARY_LIMIT", "Bounded summary exceeded")
    output.mkdir(parents=True, exist_ok=True)
    (output / "hosted-summary.json").write_bytes(raw)
    return 0 if qualified else 2


def validate_summary(summary, repository, commit):
    record = json.loads((Path(summary) / "hosted-summary.json").read_bytes()) if not isinstance(summary, dict) else summary
    if record.get("schema") != "rs9.hosted-candidate-summary.v1alpha2":
        raise ContractError("HOSTED_SUMMARY", "Current hosted summary required")
    expected = provenance(repository, record.get("release_ingestion_sha256"))
    expected["source_commit"] = commit
    for key in ("source_commit", "workflow_sha256", "contract_sha256", "builder_source_sha256"):
        if record.get(key) != expected[key]:
            raise ContractError("HOSTED_BINDING", "Summary differs from adopted source")
    lanes = required(repository)
    keys = {(l["lane"], l["system"]) for l in lanes}
    receipts = record.get("receipts", [])
    if len(receipts) != len(keys) or {(r["lane"], r["system"]) for r in receipts} != keys:
        raise ContractError("HOSTED_COMPLETENESS", "Exact required receipt set missing")
    manifests = record.get("artifact_manifests", [])
    if len(manifests) != len(keys) or {(r["lane"], r["system"]) for r in manifests} != keys:
        raise ContractError("HOSTED_COMPLETENESS", "Exact required manifest set missing")
    for row in receipts:
        lane = next(l for l in lanes if (l["lane"], l["system"]) == (row["lane"], row["system"]))
        if row.get("provenance") != {k: record[k] for k in expected} or gate_blockers(lane, row):
            raise ContractError("HOSTED_GATES", "Missing gate or mixed receipt provenance")
        if row.get("execution_error") or row.get("policy_blockers") or row.get("production_enabled") is not False:
            raise ContractError("HOSTED_GATES", "Receipt has unresolved failures or publication authority")
        manifest = next(m for m in manifests if (m["lane"],m["system"]) == (row["lane"],row["system"]))
        receipt_name = row["lane"] + "-" + row["system"] + ".json"
        if (any(manifest.get(k) != record[k] for k in expected)
                or manifest.get("qualification_receipt_hashes") != {receipt_name: hashlib.sha256(canonical(row)).hexdigest()}
                or manifest.get("production_enabled") is not False or manifest.get("publication_authority") is not False
                or not manifest.get("files")):
            raise ContractError("HOSTED_CUSTODY", "Manifest and receipt binding differ")
    if record.get("job_conclusions") != {key:"success" for key in set(contract(repository)["required_jobs"]) - {"summary"}}:
        raise ContractError("HOSTED_JOBS", "Source-required workflow job conclusions missing")
    if (record.get("production_enabled") is not False or record.get("publication_authority") is not False
            or record.get("adoptable") is not True or record.get("event") != "push"
            or record.get("ref") != "refs/heads/main" or record.get("attempt") != 1
            or record.get("qualification_verdict") != "qualified" or record.get("blocking_reasons")):
        raise ContractError("HOSTED_NOT_QUALIFIED", "Candidate has unresolved qualification or provenance gates")
    return record
