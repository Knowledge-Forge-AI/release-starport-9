"""Attended PyPI workflow deployment, status, dispatch, and run binding operations."""
from __future__ import annotations

import ast
import hashlib
import json
import re
import tempfile
from pathlib import Path
from typing import Any, Mapping

from rs9.apgr7_common import stop
from rs9.errors import ContractError
from rs9.scratch import canonical

WORKFLOW_NAME = "rs9-pypi-publish.yml"
COMMIT_OWNER_NAME = "Samuel Leighton Lair"
COMMIT_OWNER_EMAIL = "sam.lair@knowledge-forge.ai"
REPOSITORY = "Knowledge-Forge-AI/release-starport-9"
DEFAULT_BRANCH = "main"
ENVIRONMENT_NAME = "pypi"
PROJECT_NAME = "agentic-praxis-grimoire"
PINS_REL_PATH = "operators/apgr-publication/pypi-artifacts.json"
WORKFLOW_REL_PATH = ".github/workflows/rs9-pypi-publish.yml"


def _find_repo_root(root: Path | None = None) -> Path:
    if root is not None:
        return Path(root).resolve()
    # Find repository root by looking upward for operators/ or src/
    candidate = Path(__file__).resolve().parents[2]
    if (candidate / "src/rs9").is_dir():
        return candidate
    raise ContractError("APGR7_DEPLOY_CLOSURE", "Frozen verifier source root unavailable")


def _closure_imports(tree, src_dir):
    queue = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith("rs9."):
                    queue.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.startswith("rs9"):
                queue.append(node.module)
                if node.module == "rs9":
                    queue.extend("rs9." + alias.name for alias in node.names
                                 if (src_dir / "rs9" / (alias.name + ".py")).is_file())
            elif node.level and node.level > 0:
                # Relative import within rs9
                prefix = "rs9"
                sub = (node.module or "")
                full = f"{prefix}.{sub}" if sub else prefix
                queue.append(full)

    return queue


def readback_transitive_import_closure(root: Path | None = None) -> dict[str, Any]:
    """Statically determine and read back the transitive import closure for workflow execution."""
    repo_root = _find_repo_root(root)
    src_dir = repo_root / "src"

    visited: set[str] = set()
    queue = ["rs9.apgr7_pypi_workflow"]

    while queue:
        mod = queue.pop(0)
        if mod in visited:
            continue
        visited.add(mod)

        # Map module name to file path under src/
        rel_mod_path = mod.replace(".", "/") + ".py"
        file_path = src_dir / rel_mod_path
        if mod == "rs9":
            file_path = src_dir / "rs9/__init__.py"
        if not file_path.is_file():
            raise ContractError("APGR7_DEPLOY_CLOSURE", "Required verifier module absent")

        try:
            tree = ast.parse(file_path.read_text(encoding="utf-8"), filename=str(file_path))
        except (SyntaxError, UnicodeDecodeError) as err:
            raise ContractError("APGR7_DEPLOY_CLOSURE", f"Failed parsing module {mod}: {err}") from None

        queue.extend(_closure_imports(tree, src_dir))

    # Collect all closure files with paths, sizes, and sha256 digests
    files_record: list[dict[str, Any]] = []
    for mod in sorted(visited):
        rel = Path("src") / (mod.replace(".", "/") + ".py")
        abs_p = repo_root / rel
        if abs_p.is_file():
            content = abs_p.read_bytes()
            files_record.append({
                "path": rel.as_posix(),
                "module": mod,
                "size": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
            })

    # Include pins manifest and workflow file
    for extra_rel in (PINS_REL_PATH, WORKFLOW_REL_PATH, "src/rs9/__init__.py"):
        extra_abs = repo_root / extra_rel
        if not extra_abs.is_file():
            raise ContractError("APGR7_DEPLOY_CLOSURE", f"Required closure file missing: {extra_rel}")
        data = extra_abs.read_bytes()
        files_record.append({
            "path": extra_rel,
            "module": None,
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        })

    files_record.sort(key=lambda r: r["path"])
    closure_bytes = canonical(files_record)
    closure_sha256 = hashlib.sha256(closure_bytes).hexdigest()

    return {
        "modules": sorted(visited),
        "files": files_record,
        "closure_sha256": closure_sha256,
        "file_count": len(files_record),
    }


def api(io, path):
    value = io.run(["gh", "api", "repos/" + REPOSITORY + "/" + path])
    if value["returncode"]:
        raise ContractError("APGR7_DEPLOY_UNKNOWN", "Authenticated GitHub read unavailable")
    return json.loads(value["stdout"])


def head(io):
    doc = api(io, "commits/main")
    sha = doc.get("sha")
    if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ContractError("APGR7_DEPLOY_UNKNOWN", "Exact default branch identity unavailable")
    return sha, doc


def check_protected_environment(io, **unused):
    try:
        doc = api(io, "environments/pypi")
        reviewers = any(r.get("type") == "required_reviewers" and r.get("reviewers") for r in doc.get("protection_rules", []))
        policy = doc.get("deployment_branch_policy") or {}
        branches = api(io, "environments/pypi/deployment-branch-policies") if policy.get("custom_branch_policies") else {}
        rules = branches.get("branch_policies", [])
        protected = bool(reviewers and rules and all(r.get("name") == "main" and r.get("type", "branch") == "branch" for r in rules))
        return {"state": "protected" if protected else "unprotected", "protected": protected,
                "stops": [] if protected else [stop("protected-env-authority-required", [WORKFLOW_NAME], "Existing pypi environment needs reviewers and main-only branch policy; no policy change is performed.")]}
    except (ContractError, ValueError, KeyError):
        return {"state": "unknown", "protected": False, "stops": [stop("protected-env-unknown", [WORKFLOW_NAME], "Resolve authenticated environment readback.")]}


def check_publisher_confirmation(io=None, *, confirmed=None, **unused):
    value = bool(confirmed if confirmed is not None else getattr(io, "pypi_publisher_confirmed", False))
    return {"state": "operator-attested" if value else "operator-confirmation-required", "publisher_confirmed": value,
            "basis": "attended-attestation-not-registry-proof", "stops": [] if value else [stop("pypi-publisher-unconfirmed", [PROJECT_NAME], "Confirm existing Trusted Publisher repository/workflow/environment configuration separately.")]}


def check_deployment_status(io, *, root=None, **unused):
    closure = readback_transitive_import_closure(root)
    state, sha = "unknown", None
    try:
        sha, _ = head(io)
        exact, absent = True, False
        for row in closure["files"]:
            proc = io.run(["gh", "api", "--include", "-H", "Accept: application/vnd.github.raw+json",
                           "repos/" + REPOSITORY + "/contents/" + row["path"] + "?ref=" + sha])
            headers, separator, body = proc["stdout"].partition(b"\r\n\r\n")
            if not separator:
                headers, separator, body = proc["stdout"].partition(b"\n\n")
            status_line = headers.splitlines()[0] if headers else b""
            status = re.fullmatch(rb"HTTP/[0-9.]+ (\d{3})(?: .*)?", status_line)
            if separator and status and status[1] == b"404" and proc["returncode"]:
                absent, exact = True, False
                continue
            if proc["returncode"] or not separator or not status or status[1] != b"200":
                raise ContractError("APGR7_DEPLOY_UNKNOWN", "Closure readback unavailable")
            exact = exact and len(body) == row["size"] and hashlib.sha256(body).hexdigest() == row["sha256"]
        state = "deployed-exact" if exact else "absent" if absent else "differs"
    except (ContractError, ValueError, KeyError):
        pass
    env, publisher = check_protected_environment(io), check_publisher_confirmation(io)
    stops = env["stops"] + publisher["stops"]
    if state != "deployed-exact":
        stops.append(stop("workflow-closure-" + state, [WORKFLOW_NAME], "Deploy the exact workflow and full verifier import closure, then read back terminal bytes."))
    return {"deployment_state": state, "head_sha": sha, "workflow_deployed": state == "deployed-exact",
            "transitive_closure": closure, "protected_environment": env, "publisher_confirmation": publisher,
            "ready_to_dispatch": state == "deployed-exact" and env["protected"] and publisher["publisher_confirmed"], "stops": stops}


def mutate(io, endpoint, document, method="POST", *, command_returned=None):
    with tempfile.TemporaryDirectory(prefix="rs9-pypi-api-") as directory:
        path = Path(directory) / "request.json"
        path.write_bytes(canonical(document))
        proc = io.run(["gh", "api", "--method", method, "repos/" + REPOSITORY + "/" + endpoint, "--input", str(path)])
        # An actual child return is a command observation, NOT proof that
        # GitHub rejected or accepted the write. Timeout/start failure retains
        # ref-requested; every post-request outcome still needs exact readback.
        if command_returned is not None:
            command_returned()
    if proc["returncode"]:
        raise ContractError("APGR7_DEPLOY_UNCERTAIN", "Workflow deployment write requires read-only reconciliation")
    return json.loads(proc["stdout"])


def deployment_reconciliation(io, journal, *, root=None):
    """Recover in the same journal; pre-ref failures never changed the branch."""
    observed = check_deployment_status(io, root=root)
    if journal and "workflow-deployment" in journal.unresolved("pypi"):
        if observed["deployment_state"] == "deployed-exact":
            journal.finish("pypi", "workflow-deployment", "exact")
        else:
            context = journal.context("pypi", "workflow-deployment") or {}
            # Before PATCH there is no branch write. Once PATCH starts, neither
            # process return (including gh network errors), a malformed response,
            # nor an old branch readback proves non-publication. Older
            # ref-response-returned markers are also deliberately uncertain.
            phase = context.get("phase")
            safe = (phase == "before-ref-request"
                    and context.get("closure_sha256") == observed["transitive_closure"]["closure_sha256"]
                    and observed["deployment_state"] in ("absent", "differs"))
            row = {"state": observed["deployment_state"], "subjects": [
                {"name": "workflow-deployment", "state": "absent" if safe else "unknown"}]}
            observed["retry_safe"] = safe
            observed["reconciliation_sha256"] = journal.record_reconciliation("pypi", row)
    return observed


def deploy_workflow(io, *, root=None, execute=False, journal=None, after_reconcile=None, **unused):
    closure = readback_transitive_import_closure(root)
    plan = {"basis": "workflow-deployment-plan", "executed": False, "closure": closure,
            "operations": ["gh api POST git/trees (base_tree plus exact closure)", "gh api POST git/commits (one parent)", "gh api PATCH git/refs/heads/main (force=false)", "read back all closure bytes at resulting main commit"]}
    if not execute:
        return plan
    if journal is not None and journal.unresolved("pypi") and after_reconcile:
        observed = deployment_reconciliation(io, journal, root=root)
        row = {"state": observed["deployment_state"], "subjects": [
            {"name": "workflow-deployment", "state": "absent" if observed.get("retry_safe") else "unknown"}]}
        journal.release_absent("pypi", after_reconcile, row)
    if journal is None or journal.unresolved("pypi"):
        raise ContractError("APGR7_RECONCILE", "Persistent journal with no unresolved PyPI operation required")
    observed = check_deployment_status(io, root=root)
    if observed["deployment_state"] == "deployed-exact":
        return {**plan, "basis": "authenticated-deployment-noop", "deployment_readback": observed}
    if observed["deployment_state"] == "unknown":
        raise ContractError("APGR7_DEPLOY_UNKNOWN", "Unknown deployment cannot authorize a ref update")
    old, doc = head(io)
    root = _find_repo_root(root)
    entries = []
    for row in closure["files"]:
        body = (root / row["path"]).read_bytes()
        if len(body) != row["size"] or hashlib.sha256(body).hexdigest() != row["sha256"]:
            raise ContractError("APGR7_DEPLOY_CLOSURE", "Deployment source changed before write intent")
        entries.append({"path": row["path"], "mode": "100644", "type": "blob", "content": body.decode()})
    context = {"phase": "before-ref-request", "old_head": old, "closure_sha256": closure["closure_sha256"]}
    journal.start("pypi", "workflow-deployment", context=context)
    tree = mutate(io, "git/trees", {"base_tree": doc["commit"]["tree"]["sha"], "tree": entries})
    identity = {"name": COMMIT_OWNER_NAME, "email": COMMIT_OWNER_EMAIL}
    commit = mutate(io, "git/commits", {
        "message": "Deploy reviewed APGR PyPI workflow closure",
        "tree": tree["sha"], "parents": [old],
        "author": identity, "committer": identity,
    })
    commit_sha = commit.get("sha") if isinstance(commit, Mapping) else None
    if not isinstance(commit_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", commit_sha):
        raise ContractError("APGR7_DEPLOY_IDENTITY", "Created deployment commit identity unavailable")
    committed = api(io, "git/commits/" + commit_sha)
    if not isinstance(committed, Mapping) or committed.get("sha") != commit_sha or any(
        not isinstance(committed.get(role), Mapping)
        or any(committed[role].get(key) != value for key, value in identity.items())
        for role in ("author", "committer")
    ):
        raise ContractError("APGR7_DEPLOY_IDENTITY", "Deployment commit must use the repository owner for both roles")
    if head(io)[0] != old:
        raise ContractError("APGR7_DEPLOY_UNCERTAIN", "Default branch changed; reconcile deployment, never overwrite")
    ref_context = {**context, "phase": "ref-requested", "proposed_head": commit["sha"]}
    journal.record_context("pypi", "workflow-deployment", ref_context)
    def command_returned():
        journal.record_context("pypi", "workflow-deployment", {**ref_context, "phase": "ref-command-returned"})
    mutate(io, "git/refs/heads/main", {"sha": commit["sha"], "force": False}, "PATCH",
           command_returned=command_returned)
    observed = check_deployment_status(io, root=root)
    if observed["deployment_state"] == "deployed-exact":
        journal.finish("pypi", "workflow-deployment", "exact")
    return {**plan, "executed": True, "deployment_readback": observed}


from rs9.apgr7_pypi_runs import bind_run_status, dispatch_workflow, recover_dispatch


def pypi_deploy_operation(binding, io, *, stage=None, ready=False, journal=None, after_reconcile=None, **unused):
    binding.require_unchanged()
    stage = stage or io.pypi_stage
    if stage == "deploy-status":
        return deployment_reconciliation(io, journal)
    if stage == "deploy":
        return deploy_workflow(io, execute=ready, journal=journal, after_reconcile=after_reconcile)
    if stage == "dispatch":
        from rs9.apgr7_pypi import prepare
        return dispatch_workflow(io, ready=ready, journal=journal, confirmed=io.pypi_publisher_confirmed,
                                 prepared_sha256=prepare(binding, io)["prepared_sha256"])
    if stage == "dispatch-status":
        return recover_dispatch(io, journal)
    if stage == "run-status":
        return bind_run_status(io, io.pypi_run_id, journal=journal)
    raise ContractError("APGR7_STAGE", "Select a PyPI operation")
