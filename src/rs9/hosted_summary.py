"""Source-defined hosted lane completeness and qualification without publication."""
import hashlib
import json
import os
import re
from pathlib import Path

from rs9.current_generation import (HISTORICAL_GENERATION, CURRENT_GENERATION, distribution_paths, rpm_policy_path)
from rs9.errors import ContractError
from rs9.hosted_custody import provenance, consumer_provenance, diagnostic_provenance, verify_set, validate_current_provenance
from rs9.product_classes import get_product_class, supported_architectures, extract_package_arch
from rs9.rpm_evidence import (
    CURRENT_RPM_EVIDENCE_CONTRACT,
    is_current_rpm_evidence_contract,
    verify_raw_custody,
    verify_rpm_custody,
    verify_policy_custody,
)
from rs9.scratch import canonical

LINUX_WHEEL_PROMOTION_BLOCKER = "linux-wheel-production-promotion-compatibility-unproven"
RPM_POLICY_PROMOTION_BLOCKER = "rpm-lint-policy-exceptions-not-raw-clean-not-fedora-qualified"


def validate_product_architectures(lane, files):
    """Reject custody filenames contradicting the product's qualified architecture."""
    family, system = lane["lane"], lane["system"]
    if family not in {"wheels", "pacman", "rpm", "deb"}:
        return
    from rs9.package_roles import is_installable_binary, effective_role, FIXTURE_SIGNED_COPY
    for product in lane.get("required_products", []):
        product_class = get_product_class(product)
        prefix = product.replace("-", "_") + "-" if family == "wheels" else product + ("_" if family == "deb" else "-")
        names = [Path(r["path"]).name for r in files if
                 (is_installable_binary(r) or
                  (r.get("kind") == "custody" and r.get("role") == FIXTURE_SIGNED_COPY) or
                  (r.get("role") is None and effective_role(family, r) in {"binary-package", FIXTURE_SIGNED_COPY}))
                 and Path(r["path"]).name.startswith(prefix)]
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


def promotion_restrictions(lane, receipt):
    """Compute (tokens, errors), recording HOSTED_POLICY and conservatively retaining required blockers."""
    tokens = set()
    errors = []
    values = receipt.get("production_promotion_blockers", [])
    if not isinstance(values, list):
        errors.append("HOSTED_POLICY")
    else:
        for v in values:
            if isinstance(v, str) and re.fullmatch(r"[a-z][a-z0-9-]{0,127}", v):
                tokens.add(v)
            else:
                errors.append("HOSTED_POLICY")

    if lane.get("lane") == "wheels" and lane.get("system", "").endswith("linux"):
        if LINUX_WHEEL_PROMOTION_BLOCKER not in tokens:
            errors.append("HOSTED_POLICY")
            tokens.add(LINUX_WHEEL_PROMOTION_BLOCKER)

    if lane.get("lane") == "rpm":
        details = receipt.get("details", {})
        if not isinstance(details, dict):
            errors.append("HOSTED_POLICY")
            tokens.add(RPM_POLICY_PROMOTION_BLOCKER)
        else:
            policies = details.get("rpm_lint_policy", {})
            if not isinstance(policies, dict):
                # Malformed rpm_lint_policy non-dict records HOSTED_POLICY AND adds RPM_POLICY_PROMOTION_BLOCKER
                errors.append("HOSTED_POLICY")
                tokens.add(RPM_POLICY_PROMOTION_BLOCKER)
            else:
                malformed = any(not isinstance(p, dict) or
                    ("accepted_findings" in p and not isinstance(p["accepted_findings"], list))
                    for p in policies.values())
                if malformed:
                    errors.append("HOSTED_POLICY")
                    tokens.add(RPM_POLICY_PROMOTION_BLOCKER)
                has_accepted = any(
                    isinstance(p, dict) and p.get("accepted_findings")
                    for p in policies.values()
                )
                if has_accepted:
                    if RPM_POLICY_PROMOTION_BLOCKER not in tokens:
                        errors.append("HOSTED_POLICY")
                        tokens.add(RPM_POLICY_PROMOTION_BLOCKER)

    return sorted(tokens), sorted(set(errors))


def promotion_blockers(lane, receipt):
    tokens, errors = promotion_restrictions(lane, receipt)
    if errors:
        raise ContractError(errors[0], "Production promotion blockers must be a list of tokens")
    return tokens


def rpm_lint_results(receipts):
    """Display raw failure independently of current candidate policy acceptance."""
    results = []
    for receipt in receipts:
        if receipt.get("lane") != "rpm":
            continue
        details = receipt.get("details", {})
        details = details if isinstance(details, dict) else {}
        raw = details.get("rpm_lint_raw", {})
        policy = details.get("rpm_lint_policy", {})
        raw = raw if isinstance(raw, dict) else {}
        policy = policy if isinstance(policy, dict) else {}
        for product in sorted(set(raw) | set(policy)):
            evidence = raw.get(product, {})
            evidence = evidence if isinstance(evidence, dict) else {}
            tool = evidence.get("tool_receipt", {})
            tool = tool if isinstance(tool, dict) else {}
            client_gates = [g for g in receipt.get("gates", [])
                            if g.get("name") == "rpm-client-qualification"]
            results.append({"system": receipt["system"], "product": product,
                            "raw_status": evidence.get("status", "unavailable"),
                            "raw_clean": evidence.get("clean"),
                            "raw_exit_code": tool.get("exit_code"),
                            "raw_counts": evidence.get("findings_summary", {}),
                            "policy": policy.get(product, {"accepted": False, "status": "unavailable"}),
                            "downstream_dnf": client_gates[0] if len(client_gates) == 1 else {"status": "unavailable"}})
    return results


def validate_rpm_policy_custody(directory, manifest, receipt):
    """Verify current summary/raw custody; historical parsing is an explicit diagnostic path."""
    return verify_rpm_custody(directory, manifest, receipt)


def validate_rpm_custody(directory, manifest, receipt):
    """Consumer API: verify RPM policy and raw custody references."""
    from rs9.rpm_evidence import verify_rpm_custody
    return verify_rpm_custody(directory, manifest, receipt)


def validate_rpm_policy_source(repository, receipt, *, generation=HISTORICAL_GENERATION):
    """Bind retained policy evaluations to the source file in builder provenance."""
    distribution_paths(generation)
    if receipt.get('lane') != 'rpm':
        return
    policy_path = repository / rpm_policy_path(generation)
    if generation == CURRENT_GENERATION and (not policy_path.is_file() or policy_path.is_symlink()):
        raise ContractError("CURRENT_RPM_POLICY_HELD", "Selected current RPM policy is not ready")
    from rs9.rpm_lint_policy import load_policy
    selected = None
    if generation == CURRENT_GENERATION:
        selected = load_policy(policy_path, generation=generation)
        if selected.get("blocking") is True or selected.get("status") == "blocked":
            raise ContractError("CURRENT_RPM_POLICY_HELD", "Selected current RPM policy blocks qualification")
    details = receipt.get('details', {})
    if not isinstance(details, dict):
        raise ContractError('HOSTED_POLICY', 'Malformed RPM policy details')
    policies = details.get('rpm_lint_policy', {})
    if not isinstance(policies, dict):
        raise ContractError('HOSTED_POLICY', 'Malformed RPM policy evaluations')
    if not policies:
        return  # Historical/absent results remain subject to required-gate checks.
    if generation == HISTORICAL_GENERATION:
        selected = load_policy(policy_path)
    expected = hashlib.sha256(canonical(selected)).hexdigest()
    if any(not isinstance(p, dict) or p.get('policy_sha256') != expected for p in policies.values()):
        raise ContractError('HOSTED_POLICY', 'RPM policy evaluation differs from reviewed source')


def contract(repository, *, generation=HISTORICAL_GENERATION):
    from rs9.hosted_contract import load_hosted_lanes
    return load_hosted_lanes(repository, generation=generation)


def required(repository, *, generation=HISTORICAL_GENERATION):
    return [r for r in contract(repository, generation=generation)["lanes"] if r.get("module")]


def gate_blockers(lane, receipt, *, generation=HISTORICAL_GENERATION):
    distribution_paths(generation)
    blockers = []
    if generation == CURRENT_GENERATION and lane["lane"] == "nix":
        from rs9.hosted_nix import PRODUCTS
        details = receipt.get("details", {})
        outputs = details.get("outputs", {}) if isinstance(details, dict) else {}
        if not isinstance(outputs, dict) or set(outputs) != set(PRODUCTS):
            blockers.append("missing-current-nix-products")
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


def summarize(repository, inputs, output, *, generation=HISTORICAL_GENERATION):
    lanes = required(repository, generation=generation)
    reasons, receipts, manifests, promotion = [], [], [], []
    jobs = json.loads(os.environ.get("RS9_JOB_CONCLUSIONS", "{}"))
    expected_jobs = set(contract(repository, generation=generation)["required_jobs"]) - {"summary"}
    if set(jobs) != expected_jobs or any(row.get("result") != "success" for row in jobs.values()):
        reasons.append("missing-or-failed-required-workflow-job")
    auth_values = set()
    for lane in lanes:
        directory = inputs / lane["artifact_name"]
        lane_name = lane["artifact_name"]
        try:
            manifest = verify_set(directory)
            name = lane["lane"] + "-" + lane["system"] + ".json"
            receipt = json.loads((directory / name).read_bytes())
            if receipt["lane"] != lane["lane"] or receipt["system"] != lane["system"]:
                raise ContractError("SUMMARY_LANE", "Receipt lane differs from source contract")
            auth_values.add(manifest["release_ingestion_sha256"])
            receipts.append(receipt)
            manifests.append(manifest)
        except (ContractError, OSError, ValueError, KeyError) as error:
            reasons.append(lane_name + ":" + (error.code if isinstance(error, ContractError) else "missing-or-invalid-artifact"))
            continue

        if generation == CURRENT_GENERATION and (receipt.get("production_enabled") is not False or receipt.get("publication_authority") is not False):
            reasons.append(lane_name + ":publication-authority-forbidden")

        # Guarded step: Gate blockers
        try:
            reasons.extend(lane_name + ":" + r for r in gate_blockers(lane, receipt, generation=generation))
        except (ContractError, OSError, ValueError, KeyError) as error:
            reasons.append(lane_name + ":" + (error.code if isinstance(error, ContractError) else "gate-blockers-error"))

        # Guarded step: Custody required
        from rs9.package_roles import verify_package_roles, is_installable_binary
        if lane.get("custody_required") and not any(is_installable_binary(r) for r in manifest.get("files", [])):
            reasons.append(lane_name + ":missing-custody-objects")

        # Guarded step: Role verification
        try:
            verify_package_roles(directory, manifest)
        except ContractError as error:
            reasons.append(lane_name + ":" + error.code)
        except Exception:
            reasons.append(lane_name + ":CUSTODY_ROLE")

        # Guarded step: Product architectures
        try:
            validate_product_architectures(lane, manifest.get("files", []))
        except ContractError as error:
            reasons.append(lane_name + ":" + error.code)
        except Exception:
            reasons.append(lane_name + ":CUSTODY_ARCHITECTURE")

        # Guarded step: Required binary presence
        for product in lane.get("required_products", []):
            needle = product.replace("-", "_") if lane["lane"] == "wheels" else product
            prefix = needle + "_" if lane["lane"] == "deb" else needle + "-"
            if not any(Path(r["path"]).name.startswith(prefix)
                       and is_installable_binary(r) for r in manifest.get("files", [])):
                reasons.append(lane_name + ":missing-product:" + product)

        # Guarded step: Execution error & policy blockers
        if receipt.get("execution_error"):
            reasons.append(lane_name + ":execution-failed")
        reasons.extend(receipt.get("policy_blockers", []))

        # Guarded step: Promotion restrictions (retained even if other checks fail)
        try:
            lane_tokens, lane_errors = promotion_restrictions(lane, receipt)
            promotion.extend(lane_tokens)
            for err in lane_errors:
                reasons.append(lane_name + ":" + err)
        except Exception:
            reasons.append(lane_name + ":HOSTED_POLICY")

        # Guarded step: RPM policy source
        try:
            validate_rpm_policy_source(repository, receipt, generation=generation)
        except ContractError as error:
            reasons.append(lane_name + ":" + error.code)
        except Exception:
            reasons.append(lane_name + ":HOSTED_POLICY")

        # Guarded step: RPM policy custody
        try:
            validate_rpm_policy_custody(directory, manifest, receipt)
        except ContractError as error:
            reasons.append(lane_name + ":" + error.code)
        except Exception:
            reasons.append(lane_name + ":RPM_POLICY_CUSTODY")
    if len(auth_values) != 1 or None in auth_values:
        reasons.append("release-projection-missing-or-mixed")
    ingestion = next(iter(auth_values)) if len(auth_values) == 1 else None
    source_authenticated = True
    try:
        expected = provenance(repository, ingestion, generation=generation)
    except ContractError as error:
        if generation != CURRENT_GENERATION or error.code not in {"HOSTED_SOURCE_TREE", "HOSTED_PROVENANCE"}:
            raise
        source_authenticated = False
        reasons.extend(["source-tree-unauthenticated", error.code])
        expected = diagnostic_provenance(repository, ingestion, error.code, generation=generation)
    for manifest in manifests:
        if any(manifest.get(k) != v for k, v in expected.items()):
            reasons.append("mixed-source-or-run-provenance")
    actual = {p.name for p in inputs.iterdir() if p.is_dir()}
    expected_sets = {r["artifact_name"] for r in lanes}
    if actual != expected_sets:
        reasons.append("missing-or-surplus-artifact-sets")
    if generation == CURRENT_GENERATION and (expected["event"] != "push" or expected["ref"] != "refs/heads/main" or expected["attempt"] != 1):
        reasons.append("current-distribution-push-main-attempt-one-required")
    qualified = not reasons
    observe_receipt = next((r for r in receipts if r.get("lane") == "observe"), None)
    observe_details = observe_receipt.get("details", {}) if isinstance(observe_receipt, dict) else {}
    destinations = observe_details.get("destinations", {})
    planner_noops = observe_details.get("planner_noops", [])
    satisfied_observations = observe_details.get("satisfied_observations", [])
    exact_observations = observe_details.get("exact_observations", [])
    record = {"schema": "rs9.hosted-candidate-summary.v1alpha2", **expected,
              "production_enabled": False, "publication_authority": False, "attended_gates_satisfied": False,
              "adoptable": source_authenticated and expected["event"] == "push" and expected["ref"] == "refs/heads/main" and expected["attempt"] == 1,
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


def _validation_provenance(repository, ingestion, commit, run_id, generation, original_run):
    if generation == CURRENT_GENERATION or original_run is not None:
        return consumer_provenance(repository, ingestion, original_run, source_commit=commit, run_id=run_id, generation=generation)
    return provenance(repository, ingestion, generation=generation, source_commit=commit, run_id=run_id)


def validate_summary_binding(summary, repository, commit, *, generation=HISTORICAL_GENERATION, run_id=None, original_run=None):
    """Authenticate source/provenance without treating failed gates as passes."""
    distribution_paths(generation)
    record = json.loads((Path(summary) / "hosted-summary.json").read_bytes()) if not isinstance(summary, dict) else summary
    if record.get("schema") != "rs9.hosted-candidate-summary.v1alpha2":
        raise ContractError("HOSTED_SUMMARY", "Current hosted summary required")
    if generation == CURRENT_GENERATION:
        validate_current_provenance(record)
    expected = _validation_provenance(repository, record.get("release_ingestion_sha256"), commit, run_id, generation, original_run)
    expected["source_commit"] = commit
    fields = ("source_commit", "workflow_sha256", "contract_sha256", "builder_source_sha256")
    if generation == CURRENT_GENERATION:
        fields += ("generation", "qualification_scope", "configuration_sha256", "source_tree", "repository", "run_id", "workflow_path")
    for key in fields:
        if record.get(key) != expected[key]:
            raise ContractError("HOSTED_BINDING", "Summary differs from adopted source")
    if (record.get("production_enabled") is not False or record.get("publication_authority") is not False
            or record.get("event") != "push" or record.get("ref") != "refs/heads/main"
            or record.get("attempt") != 1 or record.get("adoptable") is not True):
        raise ContractError("HOSTED_BINDING", "Summary differs from non-production push provenance")
    return record


def validate_summary(summary, repository, commit, *, generation=HISTORICAL_GENERATION, run_id=None, original_run=None):
    record = validate_summary_binding(summary, repository, commit, generation=generation, run_id=run_id, original_run=original_run)
    expected = _validation_provenance(repository, record.get("release_ingestion_sha256"), commit, run_id, generation, original_run)
    expected["source_commit"] = commit
    lanes = required(repository, generation=generation)
    keys = {(l["lane"], l["system"]) for l in lanes}
    receipts = record.get("receipts", [])
    if len(receipts) != len(keys) or {(r["lane"], r["system"]) for r in receipts} != keys:
        raise ContractError("HOSTED_COMPLETENESS", "Exact required receipt set missing")
    manifests = record.get("artifact_manifests", [])
    if len(manifests) != len(keys) or {(r["lane"], r["system"]) for r in manifests} != keys:
        raise ContractError("HOSTED_COMPLETENESS", "Exact required manifest set missing")
    for receipt in receipts:
        details = receipt.get("details", {})
        if receipt.get("lane") == "rpm" and isinstance(details, dict) and details.get("rpm_evidence_contract") != CURRENT_RPM_EVIDENCE_CONTRACT:
            raise ContractError("HOSTED_NOT_QUALIFIED", "Historical RPM evidence cannot acquire current qualification")
    # Check the conservative union before any lane's failing architecture or
    # policy check can hide a lost restriction in a public summary.
    promotion = sorted({token for receipt in receipts
                        for token in promotion_restrictions(receipt, receipt)[0]})
    if (record.get("production_promotion_blockers") != promotion
            or record.get("production_promotion_blocked") is not bool(promotion)):
        raise ContractError("HOSTED_POLICY", "Summary must preserve production promotion blockers")
    from rs9.package_roles import is_installable_binary, validate_role_declarations
    for row in receipts:
        lane = next(l for l in lanes if (l["lane"], l["system"]) == (row["lane"], row["system"]))
        if row.get("provenance") != {k: record[k] for k in expected} or gate_blockers(lane, row, generation=generation):
            raise ContractError("HOSTED_GATES", "Missing gate or mixed receipt provenance")
        if (row.get("execution_error") or row.get("policy_blockers") or row.get("production_enabled") is not False
                or (generation == CURRENT_GENERATION and row.get("publication_authority") is not False)):
            raise ContractError("HOSTED_GATES", "Receipt has unresolved failures or publication authority")
        if row.get("lane") == "rpm":
            details = row.get("details", {})
            if not isinstance(details, dict):
                raise ContractError("HOSTED_POLICY", "Malformed RPM policy details")
            if details.get("rpm_evidence_contract") != CURRENT_RPM_EVIDENCE_CONTRACT:
                raise ContractError("HOSTED_NOT_QUALIFIED", "Historical marker-free RPM evidence cannot acquire new qualification")
        validate_rpm_policy_source(repository, row, generation=generation)
        tokens, errors = promotion_restrictions(lane, row)
        if errors:
            raise ContractError(errors[0], "Receipt has invalid promotion restrictions")
        manifest = next(m for m in manifests if (m["lane"],m["system"]) == (row["lane"],row["system"]))
        validate_role_declarations(manifest)
        validate_product_architectures(lane, manifest.get("files", []))
        for product in lane.get("required_products", []):
            needle = product.replace("-", "_") if lane["lane"] == "wheels" else product
            prefix = needle + "_" if lane["lane"] == "deb" else needle + "-"
            if not any(Path(r["path"]).name.startswith(prefix)
                       and is_installable_binary(r) for r in manifest.get("files", [])):
                raise ContractError("HOSTED_CUSTODY", f"Missing required installable binary for {product}")
        receipt_name = row["lane"] + "-" + row["system"] + ".json"
        if (any(manifest.get(k) != record[k] for k in expected)
                or manifest.get("qualification_receipt_hashes") != {receipt_name: hashlib.sha256(canonical(row)).hexdigest()}
                or manifest.get("production_enabled") is not False or manifest.get("publication_authority") is not False
                or not manifest.get("files")):
            raise ContractError("HOSTED_CUSTODY", "Manifest and receipt binding differ")
    if record.get("job_conclusions") != {key:"success" for key in set(contract(repository, generation=generation)["required_jobs"]) - {"summary"}}:
        raise ContractError("HOSTED_JOBS", "Source-required workflow job conclusions missing")
    if (record.get("production_enabled") is not False or record.get("publication_authority") is not False
            or record.get("adoptable") is not True or record.get("event") != "push"
            or record.get("ref") != "refs/heads/main" or record.get("attempt") != 1
            or record.get("qualification_verdict") != "qualified" or record.get("blocking_reasons")):
        raise ContractError("HOSTED_NOT_QUALIFIED", "Candidate has unresolved qualification or provenance gates")
    return record
