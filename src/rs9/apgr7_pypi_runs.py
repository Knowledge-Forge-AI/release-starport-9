"""Durable dispatch correlation and bounded, read-only workflow recovery."""
import re
import secrets
import time

from rs9.apgr7_common import stop
from rs9.errors import ContractError


def list_workflow_runs(io):
    from rs9 import apgr7_pypi_deploy as deploy
    doc = deploy.api(io, "actions/workflows/" + deploy.WORKFLOW_NAME +
                     "/runs?event=workflow_dispatch&branch=main&per_page=100")
    rows = doc.get("workflow_runs")
    if not isinstance(rows, list) or any(not isinstance(r, dict) or type(r.get("id")) is not int for r in rows):
        raise ContractError("APGR7_DEPLOY_UNKNOWN", "Workflow run inventory unavailable")
    return rows


def _matches(doc, context):
    from rs9.apgr7_pypi_deploy import WORKFLOW_REL_PATH
    return (doc.get("head_sha") == context.get("head_sha")
            and doc.get("event") == "workflow_dispatch" and doc.get("head_branch") == "main"
            and doc.get("path") in (WORKFLOW_REL_PATH, WORKFLOW_REL_PATH + "@main")
            and doc.get("display_title") == context.get("display_title"))


def _uncertain():
    return {"state": "reconcile-only", "retry_safe": False, "stops": [stop(
        "workflow-dispatch-uncertain", [],
        "Preserve intent; run dispatch-status in the same journal. Registry absence cannot release an unbound or active run.")]}


def bind_run_status(io, run_id, *, expected_head=None, journal=None, **unused):
    from rs9 import apgr7_pypi_deploy as deploy
    context = journal.context("pypi", "pypi") if journal else None
    expected_head = expected_head or getattr(io, "pypi_run_head", None) or (context or {}).get("head_sha")
    run_id = run_id if run_id is not None else (context or {}).get("run_id")
    if type(run_id) is not int or not re.fullmatch(r"[0-9a-f]{40}", expected_head or ""):
        raise ContractError("APGR7_RUN_BINDING", "Run id and head from retained dispatch context required")
    doc = deploy.api(io, "actions/runs/" + str(run_id))
    if (doc.get("id") != run_id or doc.get("head_sha") != expected_head
            or doc.get("event") != "workflow_dispatch" or doc.get("head_branch") != "main"
            or doc.get("path") not in (deploy.WORKFLOW_REL_PATH, deploy.WORKFLOW_REL_PATH + "@main")
            or (context and (not _matches(doc, context) or context.get("run_id", run_id) != run_id))):
        raise ContractError("APGR7_RUN_BINDING", "Workflow run does not match retained dispatch identity")
    terminal = (doc.get("status") == "completed" and doc.get("conclusion") in
                ("success", "failure", "cancelled", "skipped", "timed_out", "action_required", "neutral", "stale", "startup_failure"))
    return {"run_id": run_id, "head_sha": expected_head, "status": doc.get("status"),
            "conclusion": doc.get("conclusion"), "retry_safe": bool(context and terminal),
            "basis": "workflow-run-only-not-registry-readback"}


def recover_dispatch(io, journal):
    """A missing inventory entry is uncertainty, never proof that no run exists."""
    if journal is None or "pypi" not in journal.unresolved("pypi"):
        return _uncertain()
    context = journal.context("pypi", "pypi")
    if not context:
        return _uncertain()
    try:
        run_id = context.get("run_id")
        if run_id is None:
            matches = [r for r in list_workflow_runs(io) if _matches(r, context)]
            if len(matches) != 1:
                return _uncertain()
            run_id = matches[0]["id"]
        status = bind_run_status(io, run_id, journal=journal)
        if context.get("run_id") != run_id:
            journal.record_context("pypi", "pypi", {**context, "run_id": run_id})
        receipt = {"basis": "workflow-dispatch-run-binding", "run_id": run_id,
                   "head_sha": context["head_sha"], "prepared_sha256": context["prepared_sha256"],
                   "dispatch_id": context["dispatch_id"], "workflow": "rs9-pypi-publish.yml"}
        return {"state": "reconcile-only", "transport_receipt": receipt, "run_status": status,
                "retry_safe": status["retry_safe"], "stops": []}
    except (ContractError, ValueError, KeyError, TypeError):
        return _uncertain()


def dispatch_workflow(io, *, ready=False, confirmed=None, prepared_sha256="", journal=None,
                      poll_attempts=6, poll_delay=2, **unused):
    from rs9 import apgr7_pypi_deploy as deploy
    cmd = ["gh", "workflow", "run", deploy.WORKFLOW_NAME, "--repo", deploy.REPOSITORY,
           "--ref", "main", "-f", "prepared_sha256=" + prepared_sha256]
    if not ready:
        return {"state": "handoff-emitted", "handoff": {"basis": "handoff-emitted", "command": cmd}, "stops": []}
    status = deploy.check_deployment_status(io)
    publisher = deploy.check_publisher_confirmation(io, confirmed=confirmed)
    if not status["workflow_deployed"] or not status["protected_environment"]["protected"] or not publisher["publisher_confirmed"]:
        return {"state": "blocked", "stops": status["stops"] + publisher["stops"]}
    if journal is None or journal.unresolved("pypi"):
        raise ContractError("APGR7_RECONCILE", "Reconcile prior PyPI operation before dispatch")
    if not re.fullmatch(r"[0-9a-f]{64}", prepared_sha256):
        raise ContractError("APGR7_PREPARED", "Prepared artifact digest required for dispatch correlation")
    if not 1 <= poll_attempts <= 10 or not 0 <= poll_delay <= 5:
        raise ContractError("APGR7_RUN_BINDING", "Dispatch polling must remain bounded")
    list_workflow_runs(io)  # Establish authenticated read capability before intent.
    if deploy.head(io)[0] != status["head_sha"]:
        raise ContractError("APGR7_DEPLOY_UNKNOWN", "Deployment changed before dispatch")
    token = secrets.token_hex(16)
    context = {"head_sha": status["head_sha"], "prepared_sha256": prepared_sha256,
               "dispatch_id": token, "display_title": "RS9 PyPI " + prepared_sha256 + " / " + token}
    journal.start("pypi", "pypi", context=context)
    try:
        io.run(cmd + ["-f", "dispatch_id=" + token])
    except ContractError:
        pass  # A failed response may still have created a run. Never redispatch here.
    for attempt in range(poll_attempts):
        observed = recover_dispatch(io, journal)
        if "transport_receipt" in observed:
            return observed
        if attempt + 1 < poll_attempts:
            time.sleep(poll_delay)
    return _uncertain()
