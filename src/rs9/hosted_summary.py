"""Source-defined hosted lane completeness and qualification without publication."""
import hashlib
import json
import os
from pathlib import Path

from rs9.errors import ContractError
from rs9.hosted_custody import provenance, verify_set
from rs9.product_classes import get_product_class, supported_architectures, extract_package_arch
from rs9.scratch import canonical

LINUX_WHEEL_PROMOTION_BLOCKER = "linux-wheel-production-promotion-compatibility-unproven"
RPM_POLICY_PROMOTION_BLOCKER = "rpm-lint-policy-exceptions-not-raw-clean-not-fedora-qualified"


def validate_product_architectures(lane, files):
    """Reject custody filenames contradicting the product's qualified architecture."""
    family, system = lane["lane"], lane["system"]
    if family not in {"wheels", "pacman", "rpm", "deb"}:
        return
    for product in lane.get("required_products", []):
        product_class = get_product_class(product)
        prefix = product.replace("-", "_") + "-" if family == "wheels" else product + ("_" if family == "deb" else "-")
        names = [Path(r["path"]).name for r in files if r.get("kind") == "custody"
                 and r.get("promotion") != "fixture-test-only" and Path(r["path"]).name.startswith(prefix)]
        for name in names:
            if family == "wheels":
                tag = name.removesuffix(".whl").rsplit("-", 1)[-1]
                valid = (tag == "any" if product_class == "pure-js-cli" else
                         tag.startswith("macosx_") and tag.endswith("_arm64") if system == "aarch64-darwin" else
                         tag == {"x86_64-linux": "linux_x86_64", "aarch64-linux": "linux_aarch64"}.get(system))
            else:
                expected = (next(iter(supported_architectures(product, family))) if product_class == "pure-js-cli" else
                            system if family == "deb" else {"x86_64-linux": "x86_64", "aarch64-linux": "aarch64"}.get(system))
                valid = extract_package_arch(name) == expected
            if not valid:
                raise ContractError("CUSTODY_ARCHITECTURE", "Product custody has an unqualified package architecture")


def promotion_blockers(lane, receipt):
    values = receipt.get("production_promotion_blockers", [])
    if not isinstance(values, list) or any(not isinstance(v, str) for v in values):
        raise ContractError("HOSTED_POLICY", "Production promotion blockers must be a list of tokens")
    if (lane["lane"] == "wheels" and lane["system"].endswith("linux")
            and LINUX_WHEEL_PROMOTION_BLOCKER not in values):
        raise ContractError("HOSTED_POLICY", "Linux candidate wheels must retain the production compatibility blocker")
    if lane["lane"] == "rpm":
        policies = receipt.get("details", {}).get("rpm_lint_policy", {})
        if (any(p.get("accepted_findings") for p in policies.values())
                and RPM_POLICY_PROMOTION_BLOCKER not in values):
            raise ContractError("HOSTED_POLICY", "RPM preservation exceptions must retain promotion limits")
    return values


def rpm_lint_results(receipts):
    """Display raw failure independently of current candidate policy acceptance."""
    results = []
    for receipt in receipts:
        if receipt.get("lane") != "rpm":
            continue
        details = receipt.get("details", {})
        raw = details.get("rpm_lint_raw", {})
        policy = details.get("rpm_lint_policy", {})
        for product in sorted(set(raw) | set(policy)):
            evidence = raw.get(product, {})
            results.append({"system": receipt["system"], "product": product,
                            "raw_status": evidence.get("status", "unavailable"),
                            "raw_clean": evidence.get("clean"),
                            "raw_exit_code": evidence.get("tool_receipt", {}).get("exit_code"),
                            "raw_counts": evidence.get("findings_summary", {}),
                            "policy": policy.get(product, {"accepted": False, "status": "unavailable"})})
    return results


def validate_rpm_policy_source(repository, receipt):
    """Bind retained policy evaluations to the source file in builder provenance."""
    if receipt.get('lane') != 'rpm':
        return
    policies = receipt.get('details', {}).get('rpm_lint_policy', {})
    if not isinstance(policies, dict):
        raise ContractError('HOSTED_POLICY', 'Malformed RPM policy evaluations')
    if not policies:
        return  # Historical/absent results remain subject to required-gate checks.
    from rs9.rpm_lint_policy import load_policy
    expected = hashlib.sha256(canonical(load_policy(repository / 'operators/live1/rpm-lint-policy.json'))).hexdigest()
    if any(not isinstance(p, dict) or p.get('policy_sha256') != expected for p in policies.values()):
        raise ContractError('HOSTED_POLICY', 'RPM policy evaluation differs from reviewed source')


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
    reasons, receipts, manifests, promotion = [], [], [], []
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
            validate_product_architectures(lane, manifest["files"])
            for product in lane.get("required_products", []):
                needle = product.replace("-", "_") if lane["lane"] == "wheels" else product
                if not any(Path(r["path"]).name.startswith(needle + "-" if lane["lane"] != "deb" else needle + "_")
                           and r["kind"] == "custody" and r.get("promotion") != "fixture-test-only" for r in manifest["files"]):
                    reasons.append(lane["artifact_name"] + ":missing-product:" + product)
            if receipt.get("execution_error"):
                reasons.append(lane["artifact_name"] + ":execution-failed")
            reasons.extend(receipt.get("policy_blockers", []))
            validate_rpm_policy_source(repository, receipt)
            promotion.extend(promotion_blockers(lane, receipt))
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
    observe_receipt = next((r for r in receipts if r.get("lane") == "observe"), None)
    observe_details = observe_receipt.get("details", {}) if isinstance(observe_receipt, dict) else {}
    destinations = observe_details.get("destinations", {})
    planner_noops = observe_details.get("planner_noops", [])
    satisfied_observations = observe_details.get("satisfied_observations", [])
    exact_observations = observe_details.get("exact_observations", [])
    record = {"schema": "rs9.hosted-candidate-summary.v1alpha2", **expected,
              "production_enabled": False, "publication_authority": False, "attended_gates_satisfied": False,
              "adoptable": expected["event"] == "push" and expected["ref"] == "refs/heads/main" and expected["attempt"] == 1,
              "qualification_verdict": "qualified" if qualified else "not-qualified",
              "lanes_executed_ok": len(receipts) == len(lanes) and all(not r.get("execution_error") for r in receipts),
              "blocking_reasons": sorted(set(reasons)), "receipts": receipts, "artifact_manifests": manifests,
              "production_promotion_blockers": sorted(set(promotion)),
              "production_promotion_blocked": bool(promotion),
              "destinations": destinations,
              "destination_planner_noops": planner_noops,
              "destination_satisfied": satisfied_observations,
              "destination_exact": exact_observations}
    record["rpm_lint_results"] = rpm_lint_results(receipts)
    record["job_conclusions"] = {key: row.get("result") for key, row in jobs.items()}
    raw = canonical(record)
    if len(raw) > 16 * 1024 ** 2:
        raise ContractError("SUMMARY_LIMIT", "Bounded summary exceeded")
    output.mkdir(parents=True, exist_ok=True)
    (output / "hosted-summary.json").write_bytes(raw)
    return 0 if qualified else 2


def validate_summary_binding(summary, repository, commit):
    """Authenticate source/provenance without treating failed gates as passes."""
    record = json.loads((Path(summary) / "hosted-summary.json").read_bytes()) if not isinstance(summary, dict) else summary
    if record.get("schema") != "rs9.hosted-candidate-summary.v1alpha2":
        raise ContractError("HOSTED_SUMMARY", "Current hosted summary required")
    expected = provenance(repository, record.get("release_ingestion_sha256"))
    expected["source_commit"] = commit
    for key in ("source_commit", "workflow_sha256", "contract_sha256", "builder_source_sha256"):
        if record.get(key) != expected[key]:
            raise ContractError("HOSTED_BINDING", "Summary differs from adopted source")
    if (record.get("production_enabled") is not False or record.get("publication_authority") is not False
            or record.get("event") != "push" or record.get("ref") != "refs/heads/main"
            or record.get("attempt") != 1 or record.get("adoptable") is not True):
        raise ContractError("HOSTED_BINDING", "Summary differs from non-production push provenance")
    return record


def validate_summary(summary, repository, commit):
    record = validate_summary_binding(summary, repository, commit)
    expected = provenance(repository, record.get("release_ingestion_sha256"))
    expected["source_commit"] = commit
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
        validate_rpm_policy_source(repository, row)
        promotion_blockers(lane, row)
        manifest = next(m for m in manifests if (m["lane"],m["system"]) == (row["lane"],row["system"]))
        validate_product_architectures(lane, manifest.get("files", []))
        receipt_name = row["lane"] + "-" + row["system"] + ".json"
        if (any(manifest.get(k) != record[k] for k in expected)
                or manifest.get("qualification_receipt_hashes") != {receipt_name: hashlib.sha256(canonical(row)).hexdigest()}
                or manifest.get("production_enabled") is not False or manifest.get("publication_authority") is not False
                or not manifest.get("files")):
            raise ContractError("HOSTED_CUSTODY", "Manifest and receipt binding differ")
    promotion = sorted({v for row in receipts for v in promotion_blockers(row, row)})
    if (record.get("production_promotion_blockers") != promotion
            or record.get("production_promotion_blocked") is not bool(promotion)):
        raise ContractError("HOSTED_POLICY", "Summary must preserve production promotion blockers")
    if record.get("job_conclusions") != {key:"success" for key in set(contract(repository)["required_jobs"]) - {"summary"}}:
        raise ContractError("HOSTED_JOBS", "Source-required workflow job conclusions missing")
    if (record.get("production_enabled") is not False or record.get("publication_authority") is not False
            or record.get("adoptable") is not True or record.get("event") != "push"
            or record.get("ref") != "refs/heads/main" or record.get("attempt") != 1
            or record.get("qualification_verdict") != "qualified" or record.get("blocking_reasons")):
        raise ContractError("HOSTED_NOT_QUALIFIED", "Candidate has unresolved qualification or provenance gates")
    return record
