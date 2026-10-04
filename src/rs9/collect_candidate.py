"""Read-only, bounded custody collection; write evidence before returning failure."""
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import subprocess
import time

from rs9.errors import ContractError
from rs9.scratch import canonical, physical_directory
from rs9.security import scan_for_credentials

REPOSITORY = "Knowledge-Forge-AI/release-starport-9"
WORKFLOW = "rs9-candidate-tests.yml"
LIMIT = 16 * 1024 * 1024


def output_directory(output):
    path = physical_directory(output)
    prefix = Path.home() / "Documents/agent/outbox/release-starport-9_dev"
    if prefix not in path.parents or any(path.iterdir()):
        raise ContractError("ADOPTION_OUTPUT", "Empty physical directory in the manager outbox required")
    return path


def write_packet(output, packet):
    raw = canonical(packet)
    if len(raw) > LIMIT:
        raise ContractError("HOSTED_PACKET_LIMIT", "Manager packet exceeds bound")
    scan_for_credentials(raw.decode("utf-8"))
    target = output / "manager-packet.json"
    target.write_bytes(raw)


def gh_read(root, argv, runner=None):
    """Only allow bounded GitHub read commands, including API GET pagination."""
    allowed = argv[:2] in (["run", "list"], ["run", "view"], ["run", "download"])
    if argv[:1] == ["api"]:
        allowed = "--method" in argv and argv[argv.index("--method") + 1] == "GET"
        allowed = allowed and not any(x in argv for x in ("-f", "-F", "--field", "--raw-field", "--input"))
    if not allowed:
        raise ContractError("HOSTED_COMMAND", "GitHub read command is outside the allowlist")
    if runner:
        return runner(root, ["gh", *argv])
    result = subprocess.run(["gh", *argv], cwd=root, capture_output=True, timeout=120)
    if result.returncode or len(result.stdout) > LIMIT:
        raise ContractError("HOSTED_READ", "GitHub evidence read failed or exceeded bound")
    return result.stdout.decode("utf-8")


def api_rows(root, endpoint, key, runner=None):
    rows = []
    for page in range(1, 11):
        raw = gh_read(root, ["api", "--method", "GET", endpoint + f"?per_page=100&page={page}"], runner)
        doc = json.loads(raw)
        part = doc.get(key)
        if not isinstance(part, list):
            raise ContractError("HOSTED_API", "Malformed paginated evidence")
        rows.extend(part)
        if len(part) < 100:
            if len(rows) != doc.get("total_count", len(rows)):
                raise ContractError("HOSTED_API", "Incomplete paginated evidence")
            return rows
    raise ContractError("HOSTED_API_LIMIT", "Evidence pagination exceeds bound")


def _run_identity(doc, commit):
    if (doc.get("head_sha") != commit or doc.get("event") != "push" or doc.get("head_branch") != "main"
            or doc.get("path") != ".github/workflows/" + WORKFLOW or doc.get("run_attempt") != 1
            or doc.get("repository", {}).get("full_name") != REPOSITORY):
        raise ContractError("HOSTED_BINDING", "Run differs from the new adopted push or is a rerun")


def collect(repository, output, *, commit, run_id=None, started_at=None, timeout=7200, runner=None):
    root = physical_directory(repository)
    output = output_directory(output)
    if not re.fullmatch(r"[0-9a-f]{40}", commit) or type(timeout) is not int or not 30 <= timeout <= 21600:
        raise ContractError("HOSTED_ARGUMENT", "Commit and bounded wait required")
    if run_id is not None and (type(run_id) is not int or run_id <= 0):
        raise ContractError("HOSTED_ARGUMENT", "Positive run id required")
    packet = {"schema": "rs9.hosted-manager-packet.v1alpha1", "source_commit": commit,
              "run_id": run_id, "production_enabled": False, "publication_authority": False,
              "status": "pending", "validation": {"status": "not-run", "reasons": []},
              "jobs": [], "artifacts": []}
    write_packet(output, packet)
    deadline = time.monotonic() + timeout
    try:
        while time.monotonic() < deadline:
            if run_id is None:
                rows = json.loads(gh_read(root, ["run", "list", "--repo", REPOSITORY, "--workflow", WORKFLOW,
                    "--event", "push", "--branch", "main", "--commit", commit, "--limit", "100",
                    "--json", "databaseId,headSha,event,status,conclusion,createdAt"], runner))
                matches = [r for r in rows if r["headSha"] == commit and r["event"] == "push"
                    and (started_at is None or datetime.fromisoformat(r["createdAt"].replace("Z", "+00:00")) >= started_at)]
                if len(matches) > 1:
                    raise ContractError("HOSTED_RUN", "Ambiguous new workflow run")
                if matches:
                    run_id = matches[0]["databaseId"]
                    packet["run_id"] = run_id
            if run_id is not None:
                doc = json.loads(gh_read(root, ["api", "--method", "GET",
                    f"repos/{REPOSITORY}/actions/runs/{run_id}"], runner))
                _run_identity(doc, commit)
                packet["run"] = {k: doc.get(k) for k in ("id", "head_sha", "event", "head_branch", "path",
                    "run_attempt", "status", "conclusion", "created_at", "updated_at", "html_url")}
                write_packet(output, packet)
                if doc["status"] == "completed":
                    break
            time.sleep(min(15, max(0, deadline - time.monotonic())))
        else:
            raise ContractError("HOSTED_TIMEOUT", "Hosted run still pending; collect again explicitly")
        endpoint = f"repos/{REPOSITORY}/actions/runs/{run_id}"
        jobs = api_rows(root, endpoint + "/jobs", "jobs", runner)
        packet["jobs"] = [{k: j.get(k) for k in ("id", "name", "status", "conclusion", "started_at", "completed_at", "steps")}
                          for j in jobs]
        artifacts = api_rows(root, endpoint + "/artifacts", "artifacts", runner)
        packet["artifacts"] = [{k: a.get(k) for k in ("id", "name", "size_in_bytes", "digest", "expired", "created_at", "expires_at")}
                               for a in artifacts]
        packet["status"] = "terminal"
        write_packet(output, packet)
        names = [a["name"] for a in artifacts]
        if len(names) != len(set(names)) or names.count("hosted-summary") != 1:
            raise ContractError("HOSTED_ARTIFACTS", "Unique hosted summary and artifact identities required")
        if any(a.get("expired") or not re.fullmatch(r"sha256:[0-9a-f]{64}", a.get("digest") or "") for a in artifacts):
            raise ContractError("HOSTED_ARTIFACTS", "Artifact custody expired or digest missing")
        summary_root = output / "hosted-summary"
        summary_root.mkdir()
        gh_read(root, ["run", "download", str(run_id), "--repo", REPOSITORY, "--name", "hosted-summary",
                       "--dir", str(summary_root)], runner)
        packet["summary_files"] = []
        total = 0
        for path in sorted(summary_root.rglob("*")):
            if path.is_symlink():
                raise ContractError("HOSTED_SUMMARY", "Physical bounded summary files required")
            if path.is_file():
                raw = path.read_bytes()
                total += len(raw)
                if total > LIMIT:
                    raise ContractError("HOSTED_SUMMARY", "Summary exceeds bound")
                packet["summary_files"].append({"path": path.relative_to(summary_root).as_posix(), "bytes": raw.decode("utf-8")})
        write_packet(output, packet)
        reported = json.loads((summary_root / "hosted-summary.json").read_bytes())
        # Preserve all reported blockers before fail-closed validation can stop
        # at its first contract error. These diagnostics confer no qualification.
        packet["reported_summary"] = {"qualification_authority": False,
            "qualification_verdict": reported.get("qualification_verdict"),
            "blocking_reasons": reported.get("blocking_reasons", [])}
        write_packet(output, packet)
        from rs9.hosted_contract import validate_hosted_summary, load_hosted_lanes
        summary = validate_hosted_summary(summary_root, root, commit)
        contract = load_hosted_lanes(root)
        expected = {r.get("artifact", r.get("artifact_name")) for r in contract.get("lanes", [])}
        expected.discard(None)
        expected_jobs = {r["lane"]+"-"+r["system"] if r["lane"] in {"wheels","nix","pacman","rpm","deb"} else r["lane"]
            for r in contract["lanes"]} | {"config"}
        actual_jobs = [j["name"] for j in jobs]
        if set(names) != expected | {"hosted-summary"} or set(actual_jobs) != expected_jobs or len(actual_jobs) != len(expected_jobs) or any(j["status"] != "completed" or j["conclusion"] != "success" for j in jobs):
            raise ContractError("HOSTED_COMPLETENESS", "Required artifacts or successful job/step conclusions missing")
        if any(s.get("conclusion") not in {"success", "skipped"} for j in jobs for s in j.get("steps", [])):
            raise ContractError("HOSTED_STEPS", "Workflow has unsuccessful steps")
        if packet["run"]["conclusion"] != "success" or summary.get("qualification_verdict", summary.get("verdict")) != "qualified":
            raise ContractError("HOSTED_NOT_QUALIFIED", "Hosted candidate is not qualified")
        packet["validation"] = {"status": "pass", "reasons": []}
    except (ContractError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        packet["validation"] = {"status": "fail", "reasons": [error.code if isinstance(error, ContractError) else "HOSTED_COLLECTION_FAILED"]}
        packet["status"] = "pending" if packet["validation"]["reasons"] == ["HOSTED_TIMEOUT"] else "not-qualified"
    write_packet(output, packet)
    return packet
