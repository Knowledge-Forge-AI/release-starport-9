"""Future publisher contracts: attempts, readback receipts, and mandatory rereads."""
from rs9.errors import ContractError
from rs9.observation import validate_observation
from rs9.planner import expected_components, validate_output, validate_policy
from rs9.records import Record, closed, parse_rfc3339_utc, record_sha256, snapshot, validate_bounded_int, validate_sha256

ATTEMPT_OUTCOMES = {"not_attempted", "confirmed", "ambiguous", "failed"}
MUTATING_INTENTS = {"publish-intent", "repair-intent"}


def validate_plan(plan):
    closed(plan, {"schema", "tenant", "release", "release_identity", "inputs", "desired", "policy", "gates", "observation", "evaluated_at", "outcome", "reasons", "revision_allocation", "projection", "contribution"})
    if plan["schema"] != "rs9.publication-plan.v1alpha1" or plan["outcome"] not in MUTATING_INTENTS | {"noop", "block", "block-conflict", "defer-readback", "block-gate"}:
        raise ContractError("PLAN_SCHEMA", "Unknown plan record")
    output, policy = validate_output(plan["desired"]), validate_policy(plan["policy"])
    validate_observation(plan["observation"], output["destination"], output["subject"], expected_components(output), output["content_identity_sha256"])
    bindings = {"adapter_output_sha256": output, "policy_sha256": policy, "gate_set_sha256": plan["gates"], "observation_sha256": plan["observation"]}
    for key, value in bindings.items():
        if plan["inputs"].get(key) != record_sha256(value):
            raise ContractError("PLAN_BINDING", "Plan inputs disagree with their bound records")
    parse_rfc3339_utc(plan["evaluated_at"])
    return snapshot(plan)


def mutation_attempt(plan, *, executor_role, started_at, finished_at, transport_outcome,
                     request_identity=None, response_remote=None, log_reference=None):
    validate_plan(plan)
    if transport_outcome not in ATTEMPT_OUTCOMES or executor_role not in {"operator", "ci-publisher", "synthetic-test"}:
        raise ContractError("ATTEMPT_STATUS", "Explicit executor role and transport outcome required")
    start, finish = parse_rfc3339_utc(started_at), parse_rfc3339_utc(finished_at)
    if finish < start or start < parse_rfc3339_utc(plan["evaluated_at"]):
        raise ContractError("ATTEMPT_TIME", "Attempt times must follow plan evaluation")
    if transport_outcome != "not_attempted" and plan["outcome"] not in MUTATING_INTENTS:
        raise ContractError("ATTEMPT_POLICY", "Only mutation intents can record attempted transport")
    if log_reference is not None:
        closed(log_reference, {"sha256", "size"})
        validate_sha256(log_reference["sha256"])
        validate_bounded_int(log_reference["size"], max_val=1024 * 1024)
    if response_remote:
        closed(response_remote, {"etag", "commit", "revision", "sequence", "registry_id"}, required=[])
        if "sequence" in response_remote:
            validate_bounded_int(response_remote["sequence"])
    return Record(snapshot({"schema": "rs9.mutation-attempt.v1alpha1", "plan_sha256": record_sha256(plan),
         "executor_role": executor_role, "request_identity": request_identity, "started_at": started_at,
         "finished_at": finished_at, "transport_outcome": transport_outcome,
         "response_remote": response_remote or {}, "log_reference": log_reference}))


def validate_attempt(plan, attempt):
    closed(attempt, {"schema", "plan_sha256", "executor_role", "request_identity", "started_at", "finished_at", "transport_outcome", "response_remote", "log_reference"})
    if attempt["schema"] != "rs9.mutation-attempt.v1alpha1" or attempt["plan_sha256"] != record_sha256(plan):
        raise ContractError("ATTEMPT_BINDING", "Attempt does not bind immutable plan")
    rebuilt = mutation_attempt(plan, **{key: value for key, value in attempt.items() if key not in {"schema", "plan_sha256"}})
    if rebuilt != attempt:
        raise ContractError("ATTEMPT_BINDING", "Attempt must be canonical")
    return rebuilt


def _ordered_after(observation, attempts, before):
    actual = [a for a in attempts if a["transport_outcome"] != "not_attempted"]
    if not actual:
        return None
    latest = max(actual, key=lambda row: parse_rfc3339_utc(row["finished_at"]))
    response = latest["response_remote"]
    remote = observation["remote"]
    # Response identities refer to the resulting destination state; equality is
    # usable even where executor/reader clocks cannot be compared reliably.
    proof = None
    if "sequence" in response:
        if type(remote.get("sequence")) is not int or remote["sequence"] < response["sequence"]:
            return None
        if "sequence" in before and response["sequence"] <= before["sequence"]:
            return None
        proof = {"basis": "remote-sequence", "remote": remote}
    for key in ("etag", "revision", "commit"):
        if key in response:
            if remote.get(key) != response[key] or before.get(key) == response[key]:
                return None
            if proof is None:
                proof = {"basis": "response-" + key, "remote": remote}
    if proof is not None:
        return proof
    if parse_rfc3339_utc(observation["observed_at"]) > max(parse_rfc3339_utc(a["finished_at"]) for a in actual):
        return {"basis": "timestamp-fallback", "observed_at": observation["observed_at"]}
    return None


def publication_receipt(plan, attempts, post_observation):
    validate_plan(plan)
    rows = [validate_attempt(plan, row) for row in attempts]
    if len({record_sha256(row) for row in rows}) != len(rows):
        raise ContractError("DUPLICATE_ATTEMPT", "Attempt records must be unique")
    rows.sort(key=record_sha256)
    output = plan["desired"]
    post = validate_observation(post_observation, output["destination"], output["subject"], expected_components(output), output["content_identity_sha256"])
    state, proof = post["state"], None
    actual = [row for row in rows if row["transport_outcome"] != "not_attempted"]
    if state == "exact" and plan["outcome"] == "noop" and not actual:
        final, proof = "already-exact", {"basis": "exact-noop", "observation_sha256": record_sha256(post)}
    elif state == "exact" and actual and any(row["transport_outcome"] in {"confirmed", "ambiguous"} for row in actual) and _ordered_after(post, actual, plan["observation"]["remote"]):
        final, proof = "published", _ordered_after(post, actual, plan["observation"]["remote"])
    elif state == "conflict":
        final = "conflict"
    elif state == "incomplete":
        final = "incomplete"
    elif not actual:
        final = "not-attempted"
    else:
        final = "unconfirmed"
    return Record(snapshot({"schema": "rs9.publication-receipt.v1alpha1", "plan_sha256": record_sha256(plan),
         "attempts": rows, "attempt_sha256s": [record_sha256(row) for row in rows],
         "post_observation": post, "post_observation_sha256": record_sha256(post),
         "readback_proof": proof, "final_state": final}))


def check_precondition(plan, observation, *, evaluated_at):
    validate_plan(plan)
    output = plan["desired"]
    observation = validate_observation(observation, output["destination"], output["subject"], expected_components(output), output["content_identity_sha256"])
    age = (parse_rfc3339_utc(evaluated_at) - parse_rfc3339_utc(observation["observed_at"])).total_seconds()
    if age < 0 or age > plan["policy"]["max_observation_age_seconds"]:
        return "reread-required"
    if record_sha256(observation) != plan["inputs"]["observation_sha256"]:
        return "stale-plan"
    return "ready"


def next_action(plan, attempts, latest_observation, *, evaluated_at, receipt=None):
    precondition = check_precondition(plan, latest_observation, evaluated_at=evaluated_at)
    rows = [validate_attempt(plan, row) for row in attempts]
    if receipt is not None:
        expected = publication_receipt(plan, receipt["attempts"], receipt["post_observation"])
        if expected != receipt:
            raise ContractError("RECEIPT_BINDING", "Receipt does not bind its exact readback graph")
        # A caller cannot erase recorded transport by omitting its attempts.
        rows = list({record_sha256(row): row for row in rows + expected["attempts"]}.values())
        observed_at = parse_rfc3339_utc(latest_observation["observed_at"])
        receipt_at = parse_rfc3339_utc(expected["post_observation"]["observed_at"])
        if observed_at < receipt_at or (observed_at == receipt_at and latest_observation != expected["post_observation"]):
            return "reread-required"
    age = (parse_rfc3339_utc(evaluated_at) - parse_rfc3339_utc(latest_observation["observed_at"])).total_seconds()
    if age < 0 or age > plan["policy"]["max_observation_age_seconds"]:
        return "reread-required"
    actual = [row for row in rows if row["transport_outcome"] != "not_attempted"]
    if actual and parse_rfc3339_utc(latest_observation["observed_at"]) <= max(parse_rfc3339_utc(row["finished_at"]) for row in actual):
        return "reread-required"
    state = latest_observation["state"]
    if state == "exact":
        return "noop"
    if state == "conflict":
        return "block-conflict"
    if state in {"unknown", "unreachable"}:
        return "reread-required"
    if precondition != "ready" or actual:
        return "replan-required"
    if state == "incomplete" and plan["outcome"] != "repair-intent":
        return "block"
    return plan["outcome"]
