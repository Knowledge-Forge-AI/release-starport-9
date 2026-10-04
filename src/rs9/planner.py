"""Pure destination planning and revision allocation. No mutation or clock access."""
from rs9.errors import ContractError
from rs9.gates import check_gates
from rs9.observation import validate_destination, validate_subject, validate_observation
from rs9.records import Record, closed, parse_rfc3339_utc, record_sha256, semantic_identity_sha256, snapshot, validate_bounded_int, validate_sha256, validate_sanitized_string
from rs9.security import validate_safe_relative_posix_path

_PLAN_PROOF = object()


class PublicationPlan(Record):
    """A persisted plan is evidence; fresh in-process planning owns authority."""


def has_plan_proof(value):
    return (isinstance(value, PublicationPlan) and value.__dict__.get("_proof") is _PLAN_PROOF
            and value.__dict__.get("_hash") == record_sha256(value))


def safe_repair_contract(contract_id, adapter, allowed_components):
    for name in allowed_components:
        validate_safe_relative_posix_path(name)
    if not allowed_components:
        raise ContractError("REPAIR_CONTRACT", "Repair must name bounded missing components")
    return Record(snapshot({"schema": "rs9.safe-repair.v1alpha1", "id": contract_id, "adapter": adapter,
                           "operation": "restore-missing-components", "allowed_components": sorted(set(allowed_components))}))


def adapter_output(destination, subject, semantic_identity, artifacts, source_manifest, *,
                   implementation, source_version, repair_contract=None, revision_scheme="none"):
    validate_destination(destination)
    validate_subject(subject)
    closed(implementation, {"id", "version"})
    for value in (*implementation.values(), source_version):
        validate_sanitized_string(value)
    if revision_scheme not in {"none", "pkgrel", "rpm-release", "apt-revision"}:
        raise ContractError("REVISION_SCHEME", "Unknown revision contract")
    if (revision_scheme == "none") != (subject["revision"] is None):
        raise ContractError("REVISION_SCHEME", "Subject revision must agree with revision scheme")
    semantic_hash = semantic_identity_sha256(semantic_identity)
    if semantic_identity["adapter"] != destination["adapter"] or semantic_identity["version"] != subject["version"]:
        raise ContractError("OUTPUT_BINDING", "Semantic identity disagrees with output")
    files = []
    for row in artifacts:
        closed(row, {"path", "size", "sha256"})
        validate_safe_relative_posix_path(row["path"])
        validate_bounded_int(row["size"], max_val=1024 ** 3)
        validate_sha256(row["sha256"])
        files.append(dict(row))
    if not files or len({row["path"] for row in files}) != len(files):
        raise ContractError("OUTPUT_ARTIFACTS", "Nonempty unique artifact manifest required")
    if repair_contract is not None:
        closed(repair_contract, {"schema", "id", "adapter", "operation", "allowed_components"})
        rebuilt = safe_repair_contract(repair_contract["id"], repair_contract["adapter"], repair_contract["allowed_components"])
        if rebuilt != repair_contract or repair_contract["adapter"] != destination["adapter"] or not set(repair_contract["allowed_components"]) <= {row["path"] for row in files}:
            raise ContractError("REPAIR_CONTRACT", "Repair contract must bind this adapter's output components")
    result = {"schema": "rs9.adapter-output.v1alpha1", "destination": destination, "subject": subject,
              "implementation": implementation, "source_version": source_version,
              "semantic_identity": semantic_identity, "content_identity_sha256": semantic_hash,
              "artifacts": sorted(files, key=lambda row: row["path"]), "source_manifest": source_manifest,
              "source_manifest_sha256": record_sha256(source_manifest), "repair_contract": repair_contract,
              "revision_scheme": revision_scheme}
    return Record(snapshot(result))


def validate_output(output):
    closed(output, {"schema", "destination", "subject", "implementation", "source_version", "semantic_identity", "content_identity_sha256", "artifacts", "source_manifest", "source_manifest_sha256", "repair_contract", "revision_scheme"})
    if output["schema"] != "rs9.adapter-output.v1alpha1":
        raise ContractError("OUTPUT_SCHEMA", "Unknown output contract")
    rebuilt = adapter_output(output["destination"], output["subject"], output["semantic_identity"], output["artifacts"], output["source_manifest"],
                             implementation=output["implementation"], source_version=output["source_version"],
                             repair_contract=output["repair_contract"], revision_scheme=output["revision_scheme"])
    if rebuilt != output:
        raise ContractError("OUTPUT_BINDING", "Output identity or canonical fields disagree")
    return rebuilt


def destination_policy(*, enabled=True, max_observation_age_seconds=300, required_gates=(),
                       allow_not_applicable=(), external_evidence=None, repair_contract=None,
                       immutable_versions=True, revision_floor=1, pinned_revision=None,
                       base_commit=None, allowed_paths=(), mode="publish"):
    if mode not in {"publish", "observe-only"}:
        raise ContractError("POLICY_MODE", "Unknown publication policy mode")
    if type(enabled) is not bool or type(immutable_versions) is not bool:
        raise ContractError("POLICY_TYPE", "Explicit policy booleans required")
    validate_bounded_int(max_observation_age_seconds, min_val=1, max_val=86400)
    validate_bounded_int(revision_floor, min_val=1, max_val=999999)
    if pinned_revision is not None:
        validate_bounded_int(pinned_revision, min_val=1, max_val=999999)
    if base_commit is not None:
        import re
        if not re.fullmatch(r"[0-9a-f]{40}", base_commit):
            raise ContractError("PROJECTION_BASE", "Immutable base commit required")
    for path in allowed_paths:
        validate_safe_relative_posix_path(path)
    external_evidence = external_evidence or {}
    for rows in external_evidence.values():
        for sha in rows:
            validate_sha256(sha)
    return Record(snapshot({"schema": "rs9.destination-policy.v1alpha2", "mode": mode, "enabled": enabled,
         "max_observation_age_seconds": max_observation_age_seconds, "required_gates": sorted(set(required_gates)),
         "allow_not_applicable": sorted(set(allow_not_applicable)),
         "external_evidence": {key: sorted(set(rows)) for key, rows in sorted(external_evidence.items())},
         "repair_contract": repair_contract, "immutable_versions": immutable_versions, "revision_floor": revision_floor,
         "pinned_revision": pinned_revision, "base_commit": base_commit, "allowed_paths": sorted(set(allowed_paths))}))


def validate_policy(policy):
    fields = {"schema", "mode", "enabled", "max_observation_age_seconds", "required_gates", "allow_not_applicable", "external_evidence", "repair_contract", "immutable_versions", "revision_floor", "pinned_revision", "base_commit", "allowed_paths"}
    closed(policy, fields)
    rebuilt = destination_policy(**{key: value for key, value in policy.items() if key != "schema"})
    if rebuilt != policy:
        raise ContractError("POLICY_SCHEMA", "Policy must use the canonical versioned contract")
    return rebuilt


def allocate_revision(scheme, revisions, content_identity, *, floor=1, pinned=None, immutable=True):
    if scheme not in {"none", "pkgrel", "rpm-release", "apt-revision"}:
        raise ContractError("REVISION_SCHEME", "Unknown revision scheme")
    validate_sha256(content_identity)
    validate_bounded_int(floor, min_val=1, max_val=999999)
    if pinned is not None:
        validate_bounded_int(pinned, min_val=1, max_val=999999)
        if scheme == "none":
            raise ContractError("REVISION_INPUT", "Unrevisioned destinations cannot pin ecosystem revisions")
    if type(immutable) is not bool:
        raise ContractError("REVISION_INPUT", "Explicit immutability policy required")
    for row in revisions:
        closed(row, {"revision", "content_identity_sha256", "complete"})
        validate_bounded_int(row["revision"], min_val=1, max_val=999999)
        validate_sha256(row["content_identity_sha256"])
        if type(row["complete"]) is not bool:
            raise ContractError("REVISION_INPUT", "Explicit revision completeness required")
    if len({row["revision"] for row in revisions}) != len(revisions):
        raise ContractError("REVISION_INPUT", "Duplicate revision observations forbidden")
    occupied = {row["revision"]: row for row in revisions}
    inputs = {"scheme": scheme, "observed_revisions": sorted(revisions, key=lambda row: row["revision"]),
              "content_identity_sha256": content_identity, "floor": floor, "pinned": pinned, "immutable": immutable}
    if immutable and any(row["content_identity_sha256"] != content_identity for row in revisions):
        result = {"revision": None, "basis": "immutable-conflict"}
    elif pinned is not None and pinned in occupied and occupied[pinned]["content_identity_sha256"] != content_identity:
        result = {"revision": None, "basis": "pinned-conflict"}
    elif scheme == "none":
        result = {"revision": None, "basis": "unrevisioned"}
    elif pinned is not None:
        result = {"revision": pinned, "basis": "pinned"}
    elif any(row["complete"] and row["content_identity_sha256"] == content_identity for row in revisions):
        result = {"revision": min(row["revision"] for row in revisions if row["complete"] and row["content_identity_sha256"] == content_identity), "basis": "reuse-exact"}
    else:
        result = {"revision": max(floor, max(occupied, default=0) + 1), "basis": "next-after-observed" if occupied else "first"}
    if result["revision"] is not None:
        validate_bounded_int(result["revision"], min_val=1, max_val=999999)
    return Record(snapshot({"input": inputs, "output": result}))


def expected_components(output):
    return {row["path"]: row["sha256"] for row in output["artifacts"]}


def adapter_outputs_from_shadow(authenticated, manifest):
    """Bind retained shadow output to semantic inputs, independent of pkgrel."""
    from rs9.records import build_semantic_content_identity
    intent = authenticated.normalized
    if manifest["inputs"]["normalized_sha256"] != record_sha256(intent) or manifest["inputs"]["ingestion_sha256"] != record_sha256(authenticated.record):
        raise ContractError("SHADOW_BINDING", "Shadow manifest does not bind authenticated inputs")
    outputs = []
    for target in intent["targets"]:
        adapter, mode = target["adapter"], target["mode"]
        prefix = ("aur/" + target["name"] + "/" if target.get("profile") == "aur" else
                  "pacman/" + target["name"] + "/" if adapter == "pacman" else
                  "rpm/" if adapter == "dnf" else "nix/")
        files = [row for row in manifest["files"] if row["path"].startswith(prefix)]
        payloads = {row["name"]: row["sha256"] for row in authenticated.record["assets"] if row["id"] in target["assets"]}
        semantics = {"project": intent["project"], "target": target, "license": intent["license"],
                     "commands": intent["commands"], "checks": intent["checks"],
                     "desktop": intent.get("desktop"), "runtime": intent.get("runtime"),
                     "source_files": authenticated.record["source_files"]}
        identity = build_semantic_content_identity(intent["project"]["id"], intent["version"], target["package"], adapter,
                                                  payloads, {"semantic-inputs": record_sha256(semantics)})
        scheme = "pkgrel" if adapter == "pacman" else "rpm-release" if adapter == "dnf" else "none"
        outputs.append(adapter_output({"id": target["destination"], "adapter": adapter, "mode": mode},
                     {"package": target["name"], "version": intent["version"], "revision": manifest["revision"] if scheme != "none" else None},
                     identity, files, manifest, implementation={"id": "rs9-shadow", "version": "v1alpha1"},
                     source_version="foundation3", revision_scheme=scheme))
    return sorted(outputs, key=lambda row: row["destination"]["id"])


def plan(intent, capture, profile_result, output, gates, policy, observation, *, evaluated_at, ingestion_record=None):
    from rs9.release_core import authenticated_record_hash
    release_hash = authenticated_record_hash(capture)
    from rs9.bootstrap import require_configuration_authority
    require_configuration_authority(capture, intent)
    output, policy = validate_output(output), validate_policy(policy)
    if intent["project"]["repository"] != capture.record["repository"]["full_name"] or intent["tag"] != capture.record["release"]["tag"]:
        raise ContractError("INTENT_BINDING", "Intent does not bind the captured release")
    if intent["version"] != output["subject"]["version"] or intent["project"]["id"] != output["semantic_identity"]["project_id"]:
        raise ContractError("INTENT_BINDING", "Intent does not bind desired package output")
    closed(profile_result, {"schema", "profile", "release_record_sha256", "intent_sha256", "sections"})
    if profile_result["schema"] != "rs9.evidence-profile-result.v1alpha1" or profile_result["release_record_sha256"] != release_hash:
        raise ContractError("PROFILE_BINDING", "Profile does not bind captured release")
    if record_sha256(profile_result) not in capture._profile_results:
        raise ContractError("PROFILE_BINDING", "Profile result requires fresh in-process evaluation")
    if profile_result["intent_sha256"] != record_sha256(intent) or profile_result["profile"] != intent["release"]["evidence"]["profile"]:
        raise ContractError("PROFILE_BINDING", "Profile result does not bind selected intent and profile")
    from rs9.profiles import selection_for_intent
    if record_sha256(selection_for_intent(intent, include_configuration=any(p.startswith(".rs9/") for p in capture.source))) != capture.record["selection_sha256"]:
        raise ContractError("INTENT_BINDING", "Release selection differs from authenticated capture")
    for name, sha in output["semantic_identity"]["artifact_payload_hashes"].items():
        if not any(row["name"] == name and row["sha256"] == sha for row in capture.record["payloads"]):
            raise ContractError("OUTPUT_BINDING", "Semantic payload hashes must bind captured payloads")
    identity = output["semantic_identity"]
    if "targets" in intent:
        selected = [row for row in intent["targets"] if row["package"] == identity["target_id"] and row["destination"] == output["destination"]["id"] and row["adapter"] == output["destination"]["adapter"]]
        if len(selected) != 1:
            raise ContractError("OUTPUT_BINDING", "Output must bind one normalized target")
        target = selected[0]
        if target["name"] != output["subject"]["package"] or target["mode"] != output["destination"]["mode"]:
            raise ContractError("OUTPUT_BINDING", "Output package and mode disagree with normalized target")
        semantics = {"project": intent["project"], "target": target, "license": intent["license"],
                     "commands": intent["commands"], "checks": intent["checks"], "desktop": intent.get("desktop"),
                     "runtime": intent.get("runtime"), "source_files": capture.record["source_files"]}
        config = {"semantic-inputs": record_sha256(semantics)}
    else:
        config = {"configuration": record_sha256(intent)}
    if "packaging_policy" in identity["configuration_identity"]:
        from rs9.product_classes import get_product_class, supported_architectures
        packaging_policy = {"package_class": get_product_class(intent["project"]["id"]),
                            "qualified_architectures": sorted(supported_architectures(intent["project"]["id"], output["destination"]["adapter"]))}
        config["packaging_policy"] = record_sha256(packaging_policy)
        if any(output["source_manifest"].get(key) != value for key, value in packaging_policy.items()):
            raise ContractError("OUTPUT_BINDING", "Publication architecture policy differs from the explicit product contract")
    if identity["configuration_identity"] != config:
        raise ContractError("OUTPUT_BINDING", "Semantic configuration must bind normalized inputs")
    observation = validate_observation(observation, output["destination"], output["subject"], expected_components(output), output["content_identity_sha256"])
    evaluation = parse_rfc3339_utc(evaluated_at)
    observed = parse_rfc3339_utc(observation["observed_at"])
    stale = observed > evaluation or (evaluation - observed).total_seconds() > policy["max_observation_age_seconds"]
    if output["destination"]["adapter"] in {"npm", "homebrew"} and policy["mode"] != "observe-only":
        raise ContractError("OBSERVE_ONLY", "Reference targets cannot acquire publication authority")
    gate_rows, gate_reasons = check_gates(intent, capture, profile_result, output, gates, policy)
    state, reasons = observation["state"], []
    allocation = allocate_revision(output["revision_scheme"], observation["revisions"], output["content_identity_sha256"],
                                   floor=policy["revision_floor"], pinned=policy["pinned_revision"], immutable=policy["immutable_versions"])
    missing = set(expected_components(output)) - set(observation["readback"]["components"])
    repair = output["repair_contract"]
    safe_repair = (repair is not None and repair["id"] == policy["repair_contract"] and missing
                   and missing <= set(repair["allowed_components"])
                   and observation["readback"]["content_identity_sha256"] == output["content_identity_sha256"])
    if not policy["enabled"]:
        outcome, reasons = "block", ["destination-disabled"]
    elif stale or state in {"unknown", "unreachable"}:
        outcome, reasons = "defer-readback", ["stale-observation" if stale else state]
    elif state == "conflict" or allocation["output"]["basis"] in {"immutable-conflict", "pinned-conflict"}:
        outcome, reasons = "block-conflict", ["immutable-publication-conflict"]
    elif state == "exact":
        outcome = "noop"
        allocation["output"] = {"revision": output["subject"]["revision"], "basis": "reuse-exact-readback"}
    elif policy["mode"] == "observe-only":
        outcome, reasons = "block", ["observe-only-destination"]
    elif gate_reasons:
        outcome, reasons = "block-gate", gate_reasons
    elif state == "absent":
        outcome = "publish-intent"
    elif safe_repair:
        outcome = "repair-intent"
    else:
        outcome, reasons = "block", ["safe-repair-contract-required"]
    if outcome in {"publish-intent", "repair-intent"} and allocation["output"]["revision"] != output["subject"]["revision"]:
        outcome, reasons = "block", ["allocated-revision-requires-render"]
    projection = None
    if output["destination"]["mode"] == "projection" and outcome in {"publish-intent", "repair-intent"}:
        if policy["base_commit"] is None or observation["remote"].get("commit") != policy["base_commit"]:
            outcome, reasons = "defer-readback", ["projection-base-readback-required"]
        elif not policy["allowed_paths"] or any(not any(row["path"] == path or row["path"].startswith(path + "/") for path in policy["allowed_paths"]) for row in output["artifacts"]):
            outcome, reasons = "block", ["projection-path-outside-policy"]
        projection = {"base_commit": policy["base_commit"], "allowed_paths": policy["allowed_paths"]}
    contribution = observation["contribution"]
    if output["destination"]["mode"] == "contribution" and contribution and contribution["state"] == "open" and outcome in {"publish-intent", "repair-intent"}:
        outcome, reasons = "block", ["upstream-pr-open"]
    result = {"schema": "rs9.publication-plan.v1alpha1", "tenant": intent["project"], "release": capture.record["release"],
              "release_identity": capture.record["tag"], "inputs": {"release_record_sha256": release_hash,
                 "profile_result_sha256": record_sha256(profile_result), "ingestion_sha256": record_sha256(ingestion_record) if ingestion_record is not None else None,
                 "normalized_sha256": record_sha256(intent), "config_inputs": intent.get("evidence", {}).get("inputs", []),
                 "adapter_output_sha256": record_sha256(output), "policy_sha256": record_sha256(policy),
                 "gate_set_sha256": record_sha256(gate_rows), "observation_sha256": record_sha256(observation)},
              "desired": output, "policy": policy, "gates": gate_rows, "observation": observation,
              "evaluated_at": evaluated_at, "outcome": outcome, "reasons": sorted(reasons),
              "revision_allocation": allocation, "projection": projection, "contribution": contribution}
    authorized = PublicationPlan(snapshot(result))
    authorized._proof, authorized._hash = _PLAN_PROOF, record_sha256(authorized)
    return authorized
