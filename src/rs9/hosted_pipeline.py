"""GitHub-hosted non-production execution and exact candidate artifact custody."""
import argparse
import hashlib
import importlib
import json
import os
import platform
from pathlib import Path
import subprocess
import sys
import traceback

from rs9.candidate import capture_generation
from rs9.command_report import report_generation
from rs9.errors import ContractError, safe_details
from rs9.github import PublicClient
from rs9.hosted_commands import bind_commands
from rs9.hosted_contract import canonical_release_auth_projection, compute_auth_sha256, generate_matrix_outputs
from rs9.hosted_custody import provenance, retain, runner_facts, verify_set
from rs9.hosted_summary import contract, required, gate_blockers, summarize
from rs9.scratch import canonical, physical_directory


def internal_error_details(error, lane, module):
    """Hash private exception text; retain only a package-relative frame."""
    frames = traceback.extract_tb(error.__traceback__)
    package = Path(__file__).parent
    frame = None
    for item in frames:
        try:
            relative = Path(item.filename).relative_to(package)
        except ValueError:
            continue
        frame = "rs9/" + relative.as_posix() + ":" + str(item.lineno) + ":" + item.name
    details = {"stage": lane, "module": module,
               "exception_type": type(error).__name__,
               "traceback_sha256": hashlib.sha256("".join(traceback.format_exception(error)).encode()).hexdigest()}
    if frame:
        details["frame"] = frame
    return safe_details(details)


def _inputs(inputs, repository, commit):
    records = {}
    if inputs:
        for path in Path(inputs).rglob("artifact-manifest.json"):
            manifest = verify_set(path.parent)
            local = provenance(repository, manifest["release_ingestion_sha256"])
            if any(manifest.get(k) != local[k] for k in local):
                raise ContractError("CUSTODY_SOURCE", "Mixed source, workflow, builder, contract or run provenance")
            key = (manifest["lane"], manifest["system"])
            if key in records:
                raise ContractError("CUSTODY_DUPLICATE", "Duplicate upstream artifact")
            records[key] = path.parent
    return records


def validate_host(system):
    if system == "generation":
        return
    expected_os = "Darwin" if system.endswith("darwin") else "Linux"
    expected_arch = "arm64" if system.startswith(("aarch64", "arm64")) else "amd64"
    actual_arch = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "amd64", "AMD64": "amd64"}.get(platform.machine())
    if platform.system() != expected_os or actual_arch != expected_arch:
        raise ContractError("HOSTED_ARCHITECTURE", "Runner OS/architecture differs from the source-required lane")


def run_lane(repository, scratch, receipts, lane, system, *, client=None, inputs=None, phase="candidate"):
    repository, scratch = physical_directory(repository), physical_directory(scratch)
    if any(scratch.iterdir()):
        raise ContractError("OUTPUT_NOT_EMPTY", "Fresh hosted scratch required")
    c = contract(repository)
    all_lanes = c.get("lanes", []) + c.get("experiments", [])
    rows = [r for r in all_lanes if r["lane"] == lane and r["system"] == system]
    if len(rows) != 1:
        raise ContractError("HOSTED_LANE", "Lane absent or duplicated in source contract")
    row = rows[0]
    commit = os.environ.get("GITHUB_SHA", "0" * 40)
    is_experiment = lane in c.get("experiment_jobs", []) or row.get("qualification_authority") is False
    schema = "rs9.hosted-experiment-diagnostic.v1alpha1" if is_experiment else "rs9.hosted-candidate-diagnostic.v1alpha2"
    record = {"schema": schema, "lane": lane, "system": system,
              "production_enabled": False, "publication_authority": False, "attended_gates_satisfied": False,
              "qualification_authority": False if is_experiment else True,
              "application_qualified": False if is_experiment else None,
              "trust_root": "hosted-candidate-unattested", "gates": [], "execution_error": None,
              "policy_blockers": [],
              "production_promotion_blockers": ["experimental-proot-runtime-unqualified-for-production"] if is_experiment else [],
              "runner": runner_facts(),
              "fixture": {"used": False, "production": False}}
    if is_experiment:
        record["experiment_jobs"] = list(c.get("experiment_jobs", ["nix-proot"]))
        record["mandatory_gates_satisfied"] = False
    if lane == "wheels" and system.endswith("linux"):
        record["production_promotion_blockers"].append("linux-wheel-production-promotion-compatibility-unproven")
    files, ingestion = [], None
    lane_scratch = scratch / "lane-work"
    bytes_authenticated = False
    try:
        validate_host(system)
        upstream = _inputs(inputs, repository, commit)
        capture_root = scratch / "capture"
        capture_root.mkdir()
        client = client or PublicClient(api_token=os.environ.get("RS9_GITHUB_READ_TOKEN"))
        supplemental_receipts = []
        record["npm_corroboration"] = supplemental_receipts
        captures = capture_generation(repository, capture_root, client=client, checkout_binding="hosted:" + commit,
                                      supplemental_receipts=supplemental_receipts)
        bytes_authenticated = True
        projection = canonical_release_auth_projection(json.loads((capture_root / "summary/authentication.json").read_bytes()))
        ingestion = compute_auth_sha256(projection)
        expected_auth = upstream.get(("authenticate", "generation"))
        if expected_auth:
            manifest = json.loads((expected_auth / "artifact-manifest.json").read_bytes())
            if manifest["release_ingestion_sha256"] != ingestion:
                raise ContractError("AUTHENTICATION_MISMATCH", "Reauthenticated generation differs")
        elif lane != "authenticate":
            raise ContractError("AUTHENTICATION_MISSING", "Canonical authentication artifact required")
        pins = {}
        if ("pins", "generation") in upstream:
            pin_files = list(upstream[("pins", "generation")].rglob("pins.json"))
            if len(pin_files) != 1:
                raise ContractError("PINS_MISSING", "One run-wide pin manifest required")
            pins = json.loads(pin_files[0].read_bytes())["pins"]
        projection_path = scratch / "authentication-projection.json"
        projection_path.write_bytes(canonical(projection))
        files.append(projection_path)
        files.append(capture_root / "summary/authentication.json")
        transport = scratch / "authentication-transport.json"
        transport.write_bytes(canonical({"schema": "rs9.hosted-authentication-transport.v1alpha1",
            "production_enabled": False, "equivalence_authority": False,
            "requests": [{k: r[k] for k in ("url", "status", "size", "sha256", "collected_at")}
                         for r in client.receipts]}))
        files.append(transport)
        files.append(bind_commands(captures, repository, scratch))
        lane_scratch.mkdir()
        physical_directory(lane_scratch)
        context = {"repository": repository, "scratch": lane_scratch, "captures": captures, "client": client,
                   "binding": {"source_commit": commit, "checkout_binding": "hosted:" + commit}, "system": system,
                   "inputs": inputs, "pins": pins, "authentication_sha256": ingestion, "family": lane, "phase": phase}
        if lane == "authenticate":
            record["gates"] = [{"name": n, "status": "pass"} for n in row["required_gates"]]
        else:
            result = importlib.import_module(row["module"]).execute(context)
            record["gates"] = result["gates"]
            files.extend(result["artifacts"])
            record["details"] = result.get("details", {})
            if lane == "nix" and not pins.get("nix", {}).get("installer_sha256_by_system", {}).get(system):
                record["policy_blockers"].append("nix-installer-run-resolved-not-source-reproducible")
            if lane == "pins" and not result["details"]["pins"]["all_source_pinned"]:
                record["policy_blockers"].append("container-pins-run-resolved-not-source-reproducible")
        if gate_blockers(row, record):
            record["execution_error"] = "required-gates-unsatisfied"
    except Exception as error:
        # Retain diagnostic custody even for an unexpected builder exception.
        # Interrupts and process termination remain outside this boundary.
        record["execution_error"] = error.code if isinstance(error, ContractError) else "hosted-execution-failed"
        record["execution_error_detail"] = safe_details({"stage": lane,
            **(error.details if isinstance(error, ContractError) else internal_error_details(error, lane, row["module"]))})
        if not record["gates"]:
            record["gates"] = [{"name": n, "status": "fail", "reason": record["execution_error"]} for n in row["required_gates"]]
    # A capture can be complete before core authentication fails. Preserve the
    # bounded per-command metadata on both paths without retaining release bytes.
    if (scratch / "capture").is_dir():
        try:
            command_report = scratch / "command-report.json"
            command_report.write_bytes(canonical(report_generation(repository, scratch / "capture",
                                                                    bytes_authenticated=bytes_authenticated)))
            files.append(command_report)
        except Exception:
            record["command_report_error"] = "report-unavailable"
    record["provenance"] = provenance(repository, ingestion)
    if is_experiment:
        # Offline is proven only by the explicit in-guest denial result the gate itself carries;
        # a synthesized or absent gate (for example after an earlier execution error) proves nothing.
        offline_gate = next((g for g in record["gates"] if g.get("name") == "proot-in-guest-offline"), None)
        reported = offline_gate.get("runtime_offline_status") if offline_gate else None
        if reported == "pass" and offline_gate.get("status") == "pass":
            offline_status = "pass"
            offline_reason = "in-guest-offline-denial-observed"
        elif reported == "fail" and offline_gate.get("status") == "fail":
            offline_status = "fail"
            offline_reason = offline_gate.get("reason", "in-guest-offline-check-failed")
        else:
            offline_status = "not-run"
            offline_reason = (offline_gate.get("reason") if reported == "not-run" and offline_gate.get("reason")
                              else "experimental-runtime-offline-unproven")
        record["network"] = {
            "preparation_network": "used-for-authentication-and-provisioning",
            "runtime_mechanism": "netns+setpriv",
            "runtime_offline_status": offline_status,
            "runtime_reason": offline_reason,
        }
    else:
        runtime_lane = lane in {"wheels", "nix", "pacman", "rpm", "deb", "pages"}
        darwin = system.endswith("darwin")
        mechanism = "none" if darwin or not runtime_lane else "netns+setpriv" if lane == "nix" else "netns+setpriv-and-docker-network-none" if lane == "wheels" else "docker-network-none"
        record["network"] = {"preparation_network": "used-for-authentication-and-provisioning",
            "runtime_mechanism": mechanism,
            "runtime_offline_status": "pass" if runtime_lane and not darwin and not record["execution_error"] else "not-run",
            "runtime_reason": "darwin-offline-isolation-unsupported" if darwin else "negative-connectivity-and-unprivileged-runtime-required" if runtime_lane else "no-application-runtime-in-lane"}
    fixture_identity = lane_scratch / "fixture-identity.json"
    if fixture_identity.is_file() and not fixture_identity.is_symlink():
        record["fixture"] = json.loads(fixture_identity.read_bytes())
        files.append(fixture_identity)
    # Preserve completed package bytes after a later verifier fails. Never retain
    # fixture homedirs, raw transport payloads, or private fixture keys.
    for folder in ("retained", "unsigned", "unsigned-custody", "custody-deb", "diagnostics", "pages-client/diagnostics"):
        files.extend(p for p in (lane_scratch / folder).rglob("*") if p.is_file() and not p.is_symlink())
    retain(scratch, receipts, files, record)
    return 2 if record["execution_error"] else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="Non-production hosted qualification; no publish/deploy operation")
    parser.add_argument("command")
    parser.add_argument("--repository", default=".")
    parser.add_argument("--system", default="generation")
    parser.add_argument("--scratch")
    parser.add_argument("--receipts", required=False)
    parser.add_argument("--inputs")
    args = parser.parse_args(argv)
    repository = physical_directory(args.repository)
    if args.command == "config":
        outputs = generate_matrix_outputs(contract(repository))
        if os.environ.get("GITHUB_OUTPUT"):
            with open(os.environ["GITHUB_OUTPUT"], "a") as stream:
                for key, value in outputs.items():
                    stream.write(key + "=" + value + "\n")
        else:
            print(canonical(outputs).decode(), end="")
        return 0
    if args.command == "summary":
        return summarize(repository, physical_directory(args.inputs), Path(args.receipts))
    return run_lane(repository, physical_directory(args.scratch), Path(args.receipts), args.command, args.system,
                    inputs=Path(args.inputs) if args.inputs else None)


if __name__ == "__main__":
    raise SystemExit(main())
