"""Read-only, bounded custody collection; write evidence before returning failure."""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import time
import zipfile

from rs9.errors import ContractError
from rs9.scratch import canonical, physical_directory
from rs9.security import scan_for_credentials, validate_safe_relative_posix_path

REPOSITORY = "Knowledge-Forge-AI/release-starport-9"
WORKFLOW = "rs9-candidate-tests.yml"
LIMIT = 16 * 1024 * 1024  # 16 MiB for packet and summary text
MAX_PER_ARTIFACT_BYTES = 2 * 1024 * 1024 * 1024  # 2 GiB
MAX_TOTAL_ARTIFACTS_BYTES = 8 * 1024 * 1024 * 1024  # 8 GiB
CHUNK_SIZE = 64 * 1024  # 64 KiB streaming chunk
CLOCK_SKEW_TOLERANCE = timedelta(seconds=60)
FORBIDDEN_MUTATION_VERBS = {
    "rerun", "cancel", "delete", "create", "edit", "enable", "disable",
    "dispatch", "publish", "release", "upload", "fork"
}


def check_gh_allowlist(argv):
    """Enforce read-only allowlist: GET and run list/view/download only; no rerun/dispatch/publish."""
    if any(arg.lower() in FORBIDDEN_MUTATION_VERBS for arg in argv):
        raise ContractError("HOSTED_COMMAND", "GitHub command contains forbidden mutation verb")
    allowed = argv[:2] in (["run", "list"], ["run", "view"], ["run", "download"])
    if argv[:1] == ["api"]:
        method = argv.index("--method") if "--method" in argv else len(argv)
        allowed = method + 1 < len(argv) and argv[method + 1] == "GET"
        allowed = allowed and not any(x in argv for x in ("-f", "-F", "--field", "--raw-field", "--input"))
    if not allowed:
        raise ContractError("HOSTED_COMMAND", "GitHub read command is outside the allowlist")


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
    check_gh_allowlist(argv)
    if runner:
        return runner(root, ["gh", *argv])
    result = subprocess.run(["gh", *argv], cwd=root, capture_output=True, timeout=120)
    if result.returncode or len(result.stdout) > LIMIT:
        raise ContractError("HOSTED_READ", "GitHub evidence read failed or exceeded bound")
    return result.stdout.decode("utf-8")


def gh_stream_artifact(root, artifact_id, zip_path, expected_digest, runner=None, total_tracker=None,
                       max_artifact_bytes=MAX_PER_ARTIFACT_BYTES, max_total_bytes=MAX_TOTAL_ARTIFACTS_BYTES,
                       download_timeout=120):
    """Stream authenticated ZIP bytes to an exclusive file, with byte and time bounds."""
    if type(artifact_id) is not int or artifact_id <= 0 or not re.fullmatch(r"sha256:[0-9a-f]{64}", expected_digest or ""):
        raise ContractError("HOSTED_ARTIFACTS", "Positive artifact identity and API digest required")
    argv = ["api", "--method", "GET", f"repos/{REPOSITORY}/actions/artifacts/{artifact_id}/zip"]
    check_gh_allowlist(argv)
    zip_path = Path(zip_path)
    physical_directory(zip_path.parent)
    hasher, downloaded, proc, stream = hashlib.sha256(), 0, None, None
    created = False
    def copy_chunk(chunk, dst):
        nonlocal downloaded
        downloaded += len(chunk)
        if total_tracker is not None:
            total_tracker[0] += len(chunk)
        if downloaded > max_artifact_bytes or (total_tracker is not None and total_tracker[0] > max_total_bytes):
            raise ContractError("HOSTED_ARTIFACTS", "Artifact byte bound exceeded")
        hasher.update(chunk)
        dst.write(chunk)
    try:
        fd = os.open(zip_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        created = True
        with os.fdopen(fd, "wb") as dst:
            if runner is not None:
                # Test seam only. Production never routes binary downloads through gh_read/run.
                response = runner(root, ["gh", *argv])
                if isinstance(response, bytes):
                    stream = io.BytesIO(response)
                elif hasattr(response, "read"):
                    stream = response
                else:
                    raise ContractError("HOSTED_ARTIFACTS", "Binary artifact stream required")
                while True:
                    chunk = stream.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    copy_chunk(chunk, dst)
            else:
                deadline = time.monotonic() + download_timeout
                # Discard raw stderr: it may contain private operational data, and cannot block stdout.
                proc = subprocess.Popen(["gh", *argv], cwd=root, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
                with selectors.DefaultSelector() as selector:
                    selector.register(proc.stdout, selectors.EVENT_READ)
                    while True:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0 or not selector.select(remaining):
                            raise ContractError("HOSTED_READ", "Artifact download exceeded time bound")
                        chunk = os.read(proc.stdout.fileno(), CHUNK_SIZE)
                        if not chunk:
                            break
                        copy_chunk(chunk, dst)
                proc.wait(timeout=max(0.001, deadline - time.monotonic()))
                if proc.returncode:
                    raise ContractError("HOSTED_READ", "GitHub artifact download failed")
        if "sha256:" + hasher.hexdigest() != expected_digest:
            raise ContractError("HOSTED_ARTIFACTS", "Artifact ZIP differs from its API digest")
        return downloaded
    except BaseException:
        if created:
            zip_path.unlink(missing_ok=True)
        raise
    finally:
        if proc is not None:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
            proc.stdout.close()
        if isinstance(stream, io.BytesIO):
            stream.close()


def extract_safe_zip(zip_path, target_dir, *, max_artifact_bytes=MAX_PER_ARTIFACT_BYTES,
                     max_total_bytes=MAX_TOTAL_ARTIFACTS_BYTES, total_extracted_tracker=None):
    """Validate the complete inventory before descriptor-relative, no-follow writes."""
    target_dir = Path(target_dir)
    physical_directory(target_dir.parent)
    if target_dir.is_symlink():
        raise ContractError("HOSTED_ARTIFACTS", "Physical extraction directory required")
    target_dir.mkdir(exist_ok=True)
    if any(target_dir.iterdir()):
        raise ContractError("HOSTED_ARTIFACTS", "Empty extraction directory required")
    root_fd = os.open(target_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    def parent_fd(parts):
        fd = os.dup(root_fd)
        try:
            for part in parts:
                try:
                    os.mkdir(part, 0o700, dir_fd=fd)
                except FileExistsError:
                    pass
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
            return fd
        except BaseException:
            os.close(fd)
            raise
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            infos = zf.infolist()
            if len(infos) > 100000:
                raise ContractError("HOSTED_ARTIFACTS", "ZIP member count exceeds bound")
            seen, declared, inventory = {}, 0, []
            for info in infos:
                original = getattr(info, "orig_filename", info.filename)
                name = info.filename.rstrip("/")
                if "\x00" in original or "\\" in original or not name:
                    raise ContractError("HOSTED_ARTIFACTS", "Invalid ZIP member path")
                try:
                    validate_safe_relative_posix_path(name)
                except ContractError as error:
                    raise ContractError("HOSTED_ARTIFACTS", "Unsafe ZIP member path") from error
                kind = (info.external_attr >> 16) & 0o170000
                directory = info.is_dir()
                if kind not in (0, stat.S_IFDIR if directory else stat.S_IFREG) or name in seen:
                    raise ContractError("HOSTED_ARTIFACTS", "Duplicate or special ZIP member")
                if directory and info.file_size:
                    raise ContractError("HOSTED_ARTIFACTS", "ZIP directory carries file bytes")
                seen[name] = directory
                declared += info.file_size
                inventory.append((info, name.split("/"), directory))
            prior = total_extracted_tracker[0] if total_extracted_tracker is not None else 0
            if declared > max_artifact_bytes or prior + declared > max_total_bytes:
                raise ContractError("HOSTED_ARTIFACTS", "Expanded ZIP bytes exceed bound")
            for _, parts, _ in inventory:
                if any(seen.get("/".join(parts[:n])) is False for n in range(1, len(parts))):
                    raise ContractError("HOSTED_ARTIFACTS", "ZIP file is used as a directory")
            expanded = 0
            for info, parts, directory in inventory:
                fd = parent_fd(parts if directory else parts[:-1])
                try:
                    if directory:
                        continue
                    out = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
                    count = 0
                    with os.fdopen(out, "wb") as dst, zf.open(info) as src:
                        while True:
                            chunk = src.read(CHUNK_SIZE)
                            if not chunk:
                                break
                            count += len(chunk)
                            expanded += len(chunk)
                            if count > info.file_size or expanded > max_artifact_bytes:
                                raise ContractError("HOSTED_ARTIFACTS", "Expanded ZIP differs from declared bounds")
                            dst.write(chunk)
                    if count != info.file_size:
                        raise ContractError("HOSTED_ARTIFACTS", "Truncated ZIP member")
                finally:
                    os.close(fd)
            if total_extracted_tracker is not None:
                total_extracted_tracker[0] += expanded
    except (zipfile.BadZipFile, RuntimeError, NotImplementedError) as error:
        raise ContractError("HOSTED_ARTIFACTS", "Invalid or unsupported ZIP archive") from error
    finally:
        os.close(root_fd)


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


def _run_identity(doc, commit, started_at=None):
    if (doc.get("head_sha") != commit or doc.get("event") != "push" or doc.get("head_branch") != "main"
            or doc.get("path") != ".github/workflows/" + WORKFLOW or doc.get("run_attempt") != 1
            or doc.get("repository", {}).get("full_name") != REPOSITORY):
        raise ContractError("HOSTED_BINDING", "Run differs from the new adopted push or is a rerun")
    if not isinstance(started_at, datetime) or started_at.tzinfo is None:
        raise ContractError("HOSTED_BINDING", "Timezone-aware push boundary required")
    if started_at is not None:
        try:
            created_at = datetime.fromisoformat(doc["created_at"].replace("Z", "+00:00"))
            fresh = created_at >= (started_at - CLOCK_SKEW_TOLERANCE)
        except (KeyError, TypeError, ValueError):
            fresh = False
        if not fresh:
            raise ContractError("HOSTED_BINDING", "Run predates the attended push")


def diagnostic_scope(repository, output, packet, contract, reported=None):
    """Persist individually authenticated diagnostics before qualification raises."""
    from rs9.hosted_custody import provenance, verify_set
    from rs9.hosted_summary import gate_blockers, validate_summary_binding
    from rs9.candidate_readiness import readiness_record
    scope = {"source_adoption_scope": "partial-diagnostic",
             "known_unqualified_lanes": readiness_record()["known_unqualified_lanes"],
             "full_live1_qualification": False, "published_linux_nix_ready": False,
             "summary_binding": "missing", "required_lanes": [], "experiments": [],
             "partial_diagnostic_lanes_all_pass": False}
    jobs = {j.get("name"): j for j in packet.get("jobs", [])}
    def job_passed(job):
        return bool(job and job.get("status") == "completed" and job.get("conclusion") == "success"
                    and all(step.get("conclusion") in {"success", "skipped"} for step in job.get("steps", [])))
    scope["source_job_failures"] = [name for name in ("config", "unit") if not job_passed(jobs.get(name))]
    bound = None
    if reported is not None:
        try:
            bound = validate_summary_binding(reported, repository, packet["source_commit"])
            scope["summary_binding"] = "verified"
        except (ContractError, KeyError, TypeError, ValueError, OSError):
            scope["summary_binding"] = "failed"
    expected = provenance(repository, bound.get("release_ingestion_sha256") if bound else None)
    expected.update(source_commit=packet["source_commit"], event="push", ref="refs/heads/main", attempt=1)
    if bound is None:
        expected.pop("release_ingestion_sha256")
    evidence = {r.get("name"): r for r in packet["artifacts"]}
    for experimental, lanes in ((False, contract["lanes"]), (True, contract.get("experiments", []))):
        for lane in lanes:
            if not lane.get("module"):
                continue
            name = lane["artifact_name"]
            row = {"lane": lane["lane"], "system": lane["system"], "artifact": name,
                   "status": "missing", "integrity": "missing", "reasons": []}
            artifact = evidence.get(name)
            if artifact is not None:
                row["status"] = "fail"
                row["integrity"] = "fail"
                if artifact.get("collection") == "verified":
                    try:
                        directory = output / name
                        manifest = verify_set(directory, expected_provenance=expected)
                        if (manifest["lane"], manifest["system"]) != (lane["lane"], lane["system"]):
                            raise ContractError("HOSTED_BINDING", "Artifact lane differs from declaration")
                        receipt = json.loads((directory / (lane["lane"] + "-" + lane["system"] + ".json")).read_bytes())
                        if (receipt.get("lane"), receipt.get("system")) != (lane["lane"], lane["system"]):
                            raise ContractError("HOSTED_BINDING", "Receipt lane differs from declaration")
                        if (receipt.get("production_enabled") is not False
                                or receipt.get("publication_authority") is not False
                                or receipt.get("provenance") != {k: manifest[k] for k in provenance(repository, manifest.get("release_ingestion_sha256"))}):
                            raise ContractError("HOSTED_BINDING", "Receipt differs from isolated source provenance")
                        if experimental and (receipt.get("schema") != "rs9.hosted-experiment-diagnostic.v1alpha1"
                                or receipt.get("qualification_authority") is not False):
                            raise ContractError("HOSTED_BINDING", "Experiment receipt differs from declared policy")
                        if experimental:
                            from rs9.hosted_contract import validate_hosted_experiment_diagnostic
                            validate_hosted_experiment_diagnostic(receipt, repository, packet["source_commit"])
                        if bound is not None and not experimental:
                            matches = [r for r in bound.get("receipts", []) if (r.get("lane"), r.get("system")) == (lane["lane"], lane["system"])]
                            if matches != [receipt]:
                                raise ContractError("HOSTED_BINDING", "Summary and individual receipt differ")
                        gates = dict(lane, required_gates=lane.get("experiment_gates", []) if experimental else lane["required_gates"])
                        blockers = gate_blockers(gates, receipt)
                        if receipt.get("execution_error") or receipt.get("policy_blockers"):
                            blockers.append("receipt-execution-or-policy-failed")
                        if experimental and receipt.get("network", {}).get("runtime_offline_status") != "pass":
                            blockers.append("experiment-offline-unproven")
                        row.update(status="fail" if blockers else "pass", integrity="verified", reasons=blockers[:64])
                    except (ContractError, KeyError, TypeError, ValueError, OSError):
                        row["reasons"] = ["receipt-binding-or-integrity-failed"]
                else:
                    row["reasons"] = ["artifact-custody-failed"]
            if not experimental:
                job_name = lane["lane"] + "-" + lane["system"] if lane["lane"] in {"wheels", "nix", "pacman", "rpm", "deb"} else lane["lane"]
                row["job_status"] = "pass" if job_passed(jobs.get(job_name)) else "fail"
                if row["job_status"] != "pass" and row["status"] == "pass":
                    row["status"] = "fail"
                    row["reasons"].append("required-job-or-step-failed")
            scope["experiments" if experimental else "required_lanes"].append(row)
    q = [r for r in scope["required_lanes"] if r["lane"] in {"rpm", "deb", "pacman", "pages", "observe"}]
    scope["partial_diagnostic_lanes_all_pass"] = bool(q) and all(r["status"] == "pass" for r in q)
    return scope


def packet_classification(packet):
    if packet["validation"]["status"] == "pass":
        return "fully-qualified-candidate"
    if "HOSTED_TIMEOUT" in packet["validation"]["reasons"]:
        return "timeout"
    scope = packet["diagnostic_scope"]
    if (packet.get("artifact_collection_reasons") or scope.get("summary_binding") != "verified"
            or any(r.get("integrity") == "fail" for r in scope["required_lanes"] + scope["experiments"])):
        return "collection-failure"
    if not scope["partial_diagnostic_lanes_all_pass"]:
        return "b-e-unqualified"
    from rs9.candidate_readiness import LINUX_A
    if any((r["lane"], r["system"]) in LINUX_A and r["status"] != "pass" for r in scope["required_lanes"]):
        others = [r for r in scope["required_lanes"] if (r["lane"], r["system"]) not in LINUX_A]
        return "a-only-unqualified" if not scope.get("source_job_failures") and all(r["status"] == "pass" for r in others) else "a-and-other-required-gates-unqualified"
    return "other-required-gate-failure"


def read_reported_summary(summary_root, packet):
    packet["summary_files"] = []
    total = 0
    for path in sorted(summary_root.rglob("*")):
        if path.is_symlink():
            raise ContractError("HOSTED_SUMMARY", "Physical bounded summary files required")
        if path.is_file():
            if path.stat().st_size + total > LIMIT:
                raise ContractError("HOSTED_SUMMARY", "Summary exceeds bound")
            raw = path.read_bytes()
            total += len(raw)
            if total > LIMIT:
                raise ContractError("HOSTED_SUMMARY", "Summary exceeds bound")
            scan_for_credentials(raw.decode("utf-8"))
            packet["summary_files"].append({"path": path.relative_to(summary_root).as_posix(),
                "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
    return json.loads((summary_root / "hosted-summary.json").read_bytes())


def collect(repository, output, *, commit, started_at, run_id=None, timeout=7200, runner=None):
    if not re.fullmatch(r"[0-9a-f]{40}", commit) or type(timeout) is not int or not 30 <= timeout <= 21600:
        raise ContractError("HOSTED_ARGUMENT", "Commit and bounded wait required")
    if run_id is not None and (type(run_id) is not int or run_id <= 0):
        raise ContractError("HOSTED_ARGUMENT", "Positive run id required")
    if started_at is None:
        raise ContractError("HOSTED_ARGUMENT", "Timezone-aware started_at required")
    if isinstance(started_at, str):
        if not started_at.endswith("Z"):
            raise ContractError("HOSTED_ARGUMENT", "Timezone-aware started_at (ISO8601Z) required")
        try:
            started_at = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ContractError("HOSTED_ARGUMENT", "Malformed started_at timestamp") from exc
    if not isinstance(started_at, datetime) or started_at.tzinfo is None:
        raise ContractError("HOSTED_ARGUMENT", "Timezone-aware started_at required")
    root = physical_directory(repository)
    output = output_directory(output)

    packet = {"schema": "rs9.hosted-manager-packet.v1alpha1", "source_commit": commit,
              "run_id": run_id, "production_enabled": False, "publication_authority": False,
              "status": "pending", "validation": {"status": "not-run", "reasons": []},
              "jobs": [], "artifacts": [], "clock_skew_tolerance_seconds": 60,
              "not_before": started_at.isoformat()}
    packet["diagnostic_scope"] = {"source_adoption_scope": "partial-diagnostic",
        "full_live1_qualification": False, "published_linux_nix_ready": False,
        "summary_binding": "missing", "required_lanes": [], "experiments": [],
        "partial_diagnostic_lanes_all_pass": False}
    from rs9.candidate_readiness import readiness_record
    packet["diagnostic_scope"]["known_unqualified_lanes"] = readiness_record()["known_unqualified_lanes"]
    packet["classification"] = "pending"
    write_packet(output, packet)
    deadline = time.monotonic() + timeout
    try:
        while time.monotonic() < deadline:
            if run_id is None:
                rows = json.loads(gh_read(root, ["run", "list", "--repo", REPOSITORY, "--workflow", WORKFLOW,
                    "--event", "push", "--branch", "main", "--commit", commit, "--limit", "100",
                    "--json", "databaseId,headSha,event,status,conclusion,createdAt"], runner))
                matches = [r for r in rows if r.get("headSha") == commit and r.get("event") == "push"
                    and datetime.fromisoformat(r["createdAt"].replace("Z", "+00:00")) >= (started_at - CLOCK_SKEW_TOLERANCE)]
                if len(matches) > 1:
                    raise ContractError("HOSTED_RUN", "Ambiguous new workflow run")
                if matches:
                    run_id = matches[0]["databaseId"]
                    packet["run_id"] = run_id
            if run_id is not None:
                doc = json.loads(gh_read(root, ["api", "--method", "GET",
                    f"repos/{REPOSITORY}/actions/runs/{run_id}"], runner))
                _run_identity(doc, commit, started_at)
                if doc.get("id") != run_id:
                    raise ContractError("HOSTED_BINDING", "API run identity differs from selected run")
                packet["run"] = {k: doc.get(k) for k in ("id", "head_sha", "event", "head_branch", "path",
                    "run_attempt", "status", "conclusion", "created_at", "updated_at", "html_url")}
                write_packet(output, packet)
                if doc.get("status") == "completed":
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
        names = [a.get("name") for a in artifacts]
        collection_errors = []
        if any(not isinstance(n, str) for n in names) or len(names) != len(set(names)) or names.count("hosted-summary") != 1:
            collection_errors.append("HOSTED_ARTIFACTS")
        total_download_tracker, total_extracted_tracker = [0], [0]
        for artifact, evidence in zip(artifacts, packet["artifacts"]):
            zip_path = None
            evidence["collection"] = "pending"
            try:
                name, identity = artifact.get("name"), artifact.get("id")
                if (not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", name)
                        or type(identity) is not int or identity <= 0 or artifact.get("expired")):
                    raise ContractError("HOSTED_ARTIFACTS", "Invalid or expired artifact identity")
                target_dir = output / (name if names.count(name) == 1 else f"artifact-{identity}")
                zip_path = output / f".artifact-{identity}.zip"
                size = gh_stream_artifact(root, identity, zip_path, artifact.get("digest"), runner=runner,
                                          total_tracker=total_download_tracker)
                evidence.update(zip_digest_verified=True, downloaded_bytes=size)
                extract_safe_zip(zip_path, target_dir, total_extracted_tracker=total_extracted_tracker)
                manifest_path = target_dir / "artifact-manifest.json"
                if manifest_path.is_file():
                    from rs9.hosted_custody import verify_set
                    verify_set(target_dir, expected_provenance={"source_commit": commit})
                    evidence["manifest_sha256"] = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
                elif name != "hosted-summary":
                    raise ContractError("HOSTED_ARTIFACTS", "Candidate artifact lacks custody manifest")
                evidence["collection"] = "verified"
            except (ContractError, OSError, ValueError, TypeError, subprocess.SubprocessError) as error:
                code = error.code if isinstance(error, ContractError) else "HOSTED_COLLECTION_FAILED"
                evidence.update(collection="failed", reason=code)
                collection_errors.append(code)
            finally:
                if zip_path is not None:
                    zip_path.unlink(missing_ok=True)
                write_packet(output, packet)
        # Preserve and attempt every listed artifact before reporting any custody failure.
        if collection_errors:
            packet["artifact_collection_reasons"] = sorted(set(collection_errors))

        summary_root = output / "hosted-summary"
        from rs9.hosted_contract import validate_hosted_summary, load_hosted_lanes
        contract = load_hosted_lanes(root)
        reported = None
        if any(a.get("name") == "hosted-summary" and a.get("collection") == "verified" for a in packet["artifacts"]):
            try:
                reported = read_reported_summary(summary_root, packet)
                if not isinstance(reported, dict):
                    raise ContractError("HOSTED_SUMMARY", "Summary object required")
            except (ContractError, OSError, ValueError, TypeError):
                collection_errors.append("HOSTED_SUMMARY")
                packet["artifact_collection_reasons"] = sorted(set(collection_errors))
                reported = None
        if reported is not None:
            packet["reported_summary"] = {"qualification_authority": False,
                "qualification_verdict": reported.get("qualification_verdict"),
                "blocking_reasons": reported.get("blocking_reasons", []),
                "production_promotion_blockers": reported.get("production_promotion_blockers", []),
                "production_promotion_blocked": reported.get("production_promotion_blocked", False)}
        packet["diagnostic_scope"] = diagnostic_scope(root, output, packet, contract, reported)
        write_packet(output, packet)
        if collection_errors:
            raise ContractError(collection_errors[0], "One or more artifacts could not be authenticated")
        if any(r["integrity"] == "fail" for r in packet["diagnostic_scope"]["experiments"]):
            raise ContractError("HOSTED_CUSTODY", "Declared experiment receipt or provenance invalid")
        summary = validate_hosted_summary(summary_root, root, commit)
        expected = {r.get("artifact", r.get("artifact_name")) for r in contract.get("lanes", [])}
        expected.discard(None)
        expected_jobs = {r["lane"]+"-"+r["system"] if r["lane"] in {"wheels","nix","pacman","rpm","deb"} else r["lane"]
            for r in contract["lanes"]} | {"config", "unit", "summary"}
        experiment_names = {r["artifact_name"] for r in contract.get("experiments", [])}
        experiment_jobs = {r["lane"] + "-" + r["system"] for r in contract.get("experiments", [])}
        actual_jobs = [j["name"] for j in jobs]
        required_jobs = [j for j in jobs if j["name"] in expected_jobs]
        if (not expected | {"hosted-summary"} <= set(names)
                or not set(names) <= expected | experiment_names | {"hosted-summary"}
                or set(actual_jobs) != expected_jobs | experiment_jobs
                or len(actual_jobs) != len(expected_jobs | experiment_jobs)
                or any(j["status"] != "completed" for j in jobs)
                or any(j["conclusion"] != "success" for j in required_jobs)):
            raise ContractError("HOSTED_COMPLETENESS", "Required artifacts or successful job/step conclusions missing")
        for lane in contract.get("experiments", []):
            job = next(j for j in jobs if j["name"] == lane["lane"] + "-" + lane["system"])
            if lane["artifact_name"] not in names and job["conclusion"] != "skipped":
                raise ContractError("HOSTED_COMPLETENESS", "Executed experiment lacks retained artifact")
        if any(s.get("conclusion") not in {"success", "skipped"} for j in required_jobs for s in j.get("steps", [])):
            raise ContractError("HOSTED_STEPS", "Workflow has unsuccessful steps")
        if summary.get("qualification_verdict", summary.get("verdict")) != "qualified":
            raise ContractError("HOSTED_NOT_QUALIFIED", "Hosted candidate is not qualified")
        packet["validation"] = {"status": "pass", "reasons": []}
        packet["diagnostic_scope"]["full_live1_qualification"] = True
    except (ContractError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        packet["validation"] = {"status": "fail", "reasons": [error.code if isinstance(error, ContractError) else "HOSTED_COLLECTION_FAILED"]}
        packet["status"] = "pending" if packet["validation"]["reasons"] == ["HOSTED_TIMEOUT"] else "not-qualified"
    packet["classification"] = packet_classification(packet)
    write_packet(output, packet)
    return packet


def main(argv=None):
    parser = argparse.ArgumentParser(description="Read-only bounded hosted candidate collection")
    parser.add_argument("--repository", default=".")
    parser.add_argument("--output", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--run-id", type=int, default=None)
    parser.add_argument("--not-before", required=True, help="ISO8601Z timestamp")
    parser.add_argument("--timeout", type=int, default=7200)
    args = parser.parse_args(argv)
    try:
        if not args.not_before.endswith("Z"):
            raise ContractError("HOSTED_ARGUMENT", "Timezone-aware --not-before (ISO8601Z) required")
        try:
            started_at = datetime.fromisoformat(args.not_before.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ContractError("HOSTED_ARGUMENT", "Malformed --not-before timestamp") from exc
        result = collect(args.repository, args.output, commit=args.commit, run_id=args.run_id,
                         started_at=started_at, timeout=args.timeout)
        print(canonical({"status": result["status"], "run_id": result["run_id"],
                         "validation": result["validation"], "production_enabled": False}).decode(), end="")
        return 0 if result["validation"]["status"] == "pass" else 2
    except (ContractError, OSError, ValueError, subprocess.SubprocessError) as error:
        print("Collection stopped: " + (error.code if isinstance(error, ContractError) else "COLLECTION_FAILED"))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
