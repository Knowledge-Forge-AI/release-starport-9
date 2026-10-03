"""Attended source adoption and bounded hosted result collection; never publish.

The provider does not run this module. The manager supplies the reviewed source
tree, reviewed manifest digest and current reviewed parent. No historical hash
from a task prompt is a prerequisite.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import time

from rs9.candidate_inventory import MANIFEST, verify_inventory
from rs9.errors import ContractError
from rs9.hosted_candidate import REQUIRED_RECEIPTS, REQUIRED_RECEIPT_FILES
from rs9.scratch import canonical, physical_directory
from rs9.security import scan_for_credentials, validate_safe_relative_posix_path

REPOSITORY = "Knowledge-Forge-AI/release-starport-9"
WORKFLOW = "rs9-candidate-tests.yml"


def run(root, args):
    result = subprocess.run(args, cwd=root, capture_output=True, timeout=120)
    if result.returncode:
        raise ContractError("ADOPTION_COMMAND", "Attended command failed; inspect locally")
    return result.stdout.decode("utf-8").strip()


def validate_receipts(root, commit, workflow_sha256):
    root = physical_directory(root)
    manifest = root / "receipts-manifest.json"
    if manifest.is_symlink() or not manifest.is_file() or manifest.stat().st_size > 512 * 1024:
        raise ContractError("HOSTED_RECEIPTS", "Bounded receipts manifest required")
    try:
        manifest_raw = manifest.read_bytes()
        scan_for_credentials(manifest_raw.decode("utf-8"))
        record = json.loads(manifest_raw)
    except Exception as exc:
        raise ContractError("HOSTED_RECEIPTS", "Malformed receipts manifest") from exc

    if (not isinstance(record, dict) or record.get("schema") != "rs9.hosted-candidate-receipts.v1alpha1" or record.get("commit") != commit
            or record.get("workflow_sha256") != workflow_sha256 or record.get("production_enabled") is not False
            or record.get("status") != "incomplete-candidate"):
        raise ContractError("HOSTED_BINDING", "Hosted receipts differ from reviewed commit/workflow")

    files = record.get("files")
    if not isinstance(files, list) or len(files) != len(REQUIRED_RECEIPTS):
        raise ContractError("HOSTED_RECEIPTS", f"Exact {len(REQUIRED_RECEIPTS)} receipt inventory required")

    file_paths = [r.get("path") for r in files if isinstance(r, dict)]
    if len(set(file_paths)) != len(REQUIRED_RECEIPTS) or set(file_paths) != REQUIRED_RECEIPT_FILES:
        raise ContractError("HOSTED_RECEIPTS", "Receipt filenames do not match required workflow receipt set")

    # Reject duplicate, missing, unexpected files on disk
    actual = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file() or p.is_symlink()}
    expected_on_disk = REQUIRED_RECEIPT_FILES | {"receipts-manifest.json"}
    if actual != expected_on_disk:
        raise ContractError("HOSTED_RECEIPTS", "Directory contains unexpected or missing receipt files")

    # Validate outcomes in manifest
    outcomes = record.get("outcomes")
    if not isinstance(outcomes, list) or len(outcomes) != len(REQUIRED_RECEIPTS):
        raise ContractError("HOSTED_RECEIPTS", "Exact outcomes matching required receipts required")
    outcome_keys = []
    for out in outcomes:
        if not isinstance(out, dict):
            raise ContractError("HOSTED_RECEIPTS", "Malformed outcome entry")
        lane, system = out.get("lane"), out.get("system")
        if (lane, system) not in REQUIRED_RECEIPTS:
            raise ContractError("HOSTED_RECEIPTS", f"Unexpected outcome: {lane}-{system}")
        outcome_keys.append((lane, system))
    if len(set(outcome_keys)) != len(REQUIRED_RECEIPTS):
        raise ContractError("HOSTED_RECEIPTS", "Duplicate outcomes in receipts manifest")

    total = 0
    seen_keys = set()
    observed_outcomes = []
    for row in files:
        if not isinstance(row, dict) or "path" not in row or "size" not in row or "sha256" not in row:
            raise ContractError("HOSTED_RECEIPTS", "Malformed file row in receipts manifest")
        validate_safe_relative_posix_path(row["path"])
        path = root / row["path"]
        if any(p.is_symlink() for p in (path, *path.parents)) or not path.is_file() or path.stat().st_size > 512 * 1024:
            raise ContractError("HOSTED_RECEIPTS", "Physical bounded text receipts required")
        data = path.read_bytes()
        total += len(data)
        scan_for_credentials(data.decode("utf-8"))
        if row != {"path": row["path"], "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}:
            raise ContractError("HOSTED_RECEIPTS", "Receipt digest mismatch")

        # Validate individual receipt contents (reject malformed)
        try:
            val = json.loads(data)
        except Exception as exc:
            raise ContractError("HOSTED_RECEIPTS", f"Receipt {row['path']} is not valid JSON") from exc

        if not isinstance(val, dict):
            raise ContractError("HOSTED_RECEIPTS", f"Receipt {row['path']} is not a JSON object")

        if val.get("schema") != "rs9.hosted-candidate-diagnostic.v1alpha1":
            raise ContractError("HOSTED_RECEIPTS", f"Receipt {row['path']} has invalid schema")
        if val.get("source_commit") != commit:
            raise ContractError("HOSTED_BINDING", f"Receipt {row['path']} source commit mismatch")
        if val.get("production_enabled") is not False:
            raise ContractError("HOSTED_RECEIPTS", f"Receipt {row['path']} must not enable production")
        if val.get("publication_authority") is not False:
            raise ContractError("HOSTED_RECEIPTS", f"Receipt {row['path']} must not claim publication authority")
        if val.get("mandatory_gates_satisfied") is not False:
            raise ContractError("HOSTED_RECEIPTS", f"Receipt {row['path']} cannot claim mandatory gates satisfied")
        if val.get("trust_root") != "hosted-candidate-unattested" or val.get("status") not in {"blocked", "diagnostic-pass"}:
            raise ContractError("HOSTED_RECEIPTS", "Receipt must describe bounded candidate diagnostics")

        lane, system = val.get("lane"), val.get("system")
        if f"{lane}-{system}.json" != row["path"]:
            raise ContractError("HOSTED_RECEIPTS", f"Receipt {row['path']} lane/system does not match filename")
        key = (lane, system)
        if key not in REQUIRED_RECEIPTS:
            raise ContractError("HOSTED_RECEIPTS", f"Receipt {row['path']} not in required receipt set")
        if key in seen_keys:
            raise ContractError("HOSTED_RECEIPTS", f"Duplicate receipt for {key}")
        seen_keys.add(key)
        observed_outcomes.append({"lane": lane, "system": system, "status": val["status"],
                                  "mandatory_gates_satisfied": val["mandatory_gates_satisfied"]})

    if len(seen_keys) != len(REQUIRED_RECEIPTS):
        raise ContractError("HOSTED_RECEIPTS", "Not all required receipts were validated")
    if sorted(outcomes, key=lambda r: (r["lane"], r["system"])) != sorted(observed_outcomes, key=lambda r: (r["lane"], r["system"])):
        raise ContractError("HOSTED_RECEIPTS", "Manifest outcomes differ from actual diagnostic receipts")
    if total > 16 * 1024 * 1024:
        raise ContractError("HOSTED_RECEIPTS", "Receipt aggregate exceeds limit")
    return record


def adopt(repository, output, *, reviewed_parent, reviewed_tree, manifest_sha256, timeout=1800):
    root, output = physical_directory(repository), physical_directory(output)
    if any(output.iterdir()) or output == root or root in output.parents:
        raise ContractError("ADOPTION_OUTPUT", "Empty external physical result directory required")
    if any(not re.fullmatch(r"[0-9a-f]{40}", x) for x in (reviewed_parent, reviewed_tree)) or not re.fullmatch(r"[0-9a-f]{64}", manifest_sha256):
        raise ContractError("ADOPTION_REVIEW", "Exact manager review bindings required")
    if type(timeout) is not int or not 30 <= timeout <= 3600:
        raise ContractError("ADOPTION_TIMEOUT", "Wait must be bounded")
    manifest_path = root / MANIFEST
    if any(p.is_symlink() for p in (manifest_path, *manifest_path.parents)) or manifest_path.stat().st_size > 512 * 1024:
        raise ContractError("ADOPTION_REVIEW", "Bounded physical manifest required")
    raw = manifest_path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != manifest_sha256:
        raise ContractError("ADOPTION_REVIEW", "Manifest differs from reviewed bytes")
    manifest = json.loads(raw)
    # A blocked source checkpoint does not become an authorized completed
    # candidate just because this script exists.
    if manifest.get("candidate_adoption_ready") is not True:
        raise ContractError("ADOPTION_NOT_READY", "Local candidate qualification is incomplete")
    if verify_inventory(root, manifest) != reviewed_tree:
        raise ContractError("ADOPTION_REVIEW", "Source tree differs from exact manager review")
    git = lambda *args: run(root, ["git", *args])
    if git("branch", "--show-current") != "main" or git("rev-parse", "HEAD") != reviewed_parent or git("diff", "--cached", "--name-only"):
        raise ContractError("ADOPTION_PARENT", "Reviewed main parent and clean index required")
    remote = git("remote", "get-url", "origin")
    if remote not in {"https://github.com/" + REPOSITORY + ".git", "git@github.com:" + REPOSITORY + ".git"}:
        raise ContractError("ADOPTION_REMOTE", "RS9 origin required")
    unknown = git("ls-files", "--others", "--exclude-standard").splitlines() + git("ls-files", "--others", "--ignored", "--exclude-standard").splitlines()
    allowed = {r["path"] for r in manifest["files"]} | {MANIFEST}
    if any(p not in allowed and not p.startswith(".serena/") for p in unknown):
        raise ContractError("ADOPTION_INVENTORY", "Unreviewed checkout state present")
    git("fetch", "origin", "main")
    if git("rev-parse", "origin/main") != reviewed_parent:
        raise ContractError("ADOPTION_PARENT", "Origin advanced; fresh manager review required")
    # Recheck after fetch and immediately before index mutation.
    if verify_inventory(root, manifest) != reviewed_tree:
        raise ContractError("ADOPTION_REVIEW", "Candidate changed during preflight")
    if (git("branch", "--show-current") != "main" or git("rev-parse", "HEAD") != reviewed_parent
            or git("diff", "--cached", "--name-only")):
        raise ContractError("ADOPTION_PARENT", "Checkout or index changed during preflight")
    git("add", "--", *sorted(allowed))
    if git("write-tree") != reviewed_tree:
        raise ContractError("ADOPTION_REVIEW", "Staged tree differs; stop with index retained for inspection")
    git("commit", "-m", "Prepare Theme Forge candidate qualification")
    commit = git("rev-parse", "HEAD")
    if git("rev-parse", "HEAD^{tree}") != reviewed_tree or git("rev-parse", "HEAD^") != reviewed_parent:
        raise ContractError("ADOPTION_REVIEW", "Commit hook changed candidate; stop before push")
    started = datetime.now(timezone.utc).replace(microsecond=0)
    git("push", "origin", "HEAD:main")
    deadline = time.monotonic() + timeout
    gh = lambda *args: run(root, ["gh", *args, "--repo", REPOSITORY])
    run_id = None
    while time.monotonic() < deadline:
        rows = json.loads(gh("run", "list", "--workflow", WORKFLOW, "--event", "push", "--branch", "main", "--commit", commit,
                             "--limit", "100", "--json", "databaseId,headSha,event,status,conclusion,createdAt"))
        matching = [r for r in rows if r["headSha"] == commit and r["event"] == "push"
                    and datetime.fromisoformat(r["createdAt"].replace("Z", "+00:00")) >= started]
        if len(matching) > 1:
            raise ContractError("HOSTED_RUN", "Multiple new push runs; manager disposition required")
        if matching:
            run_id = matching[0]["databaseId"]
            if matching[0]["status"] == "completed":
                break
        time.sleep(min(15, max(0, deadline - time.monotonic())))
    else:
        (output / "hosted-timeout.json").write_bytes(canonical({"commit": commit, "run_id": run_id, "status": "pending", "production_enabled": False}))
        raise ContractError("HOSTED_TIMEOUT", "Candidate pushed; hosted results still pending")
    detail = json.loads(gh("run", "view", str(run_id), "--json", "headSha,event,status,conclusion,jobs,url"))
    if detail["headSha"] != commit or detail["event"] != "push" or not detail["jobs"]:
        raise ContractError("HOSTED_BINDING", "Hosted run binding is incomplete")
    # Keep all job and step outcomes; do not turn a partial successful job into
    # an accepted generation. Candidate evidence stays unattested.
    (output / "job-conclusions.json").write_bytes(canonical(detail))
    receipts = output / "receipts"
    receipts.mkdir()
    gh("run", "download", str(run_id), "--name", "hosted-candidate-receipts", "--dir", str(receipts))
    validate_receipts(receipts, commit, hashlib.sha256((root / ".github/workflows" / WORKFLOW).read_bytes()).hexdigest())
    return {"commit": commit, "tree": reviewed_tree, "run_id": run_id, "conclusion": detail["conclusion"],
            "manager_disposition_required": True, "production_enabled": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Attended RS9 source adoption and hosted qualification only")
    parser.add_argument("--repository", default=".")
    for flag in ("output", "reviewed-parent", "reviewed-tree", "manifest-sha256"):
        parser.add_argument("--" + flag, required=True)
    parser.add_argument("--timeout", type=int, default=1800)
    args = parser.parse_args(argv)
    try:
        result = adopt(args.repository, args.output, reviewed_parent=args.reviewed_parent, reviewed_tree=args.reviewed_tree,
                       manifest_sha256=args.manifest_sha256, timeout=args.timeout)
        print(canonical(result).decode(), end="")
        return 0 if result["conclusion"] == "success" else 2
    except (ContractError, OSError, ValueError, subprocess.SubprocessError) as error:
        print("Attended adoption stopped: " + (error.code if isinstance(error, ContractError) else "ADOPTION_FAILED"))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
