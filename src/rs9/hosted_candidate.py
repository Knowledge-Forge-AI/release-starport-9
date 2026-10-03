"""Bounded, non-production candidate diagnostics; incomplete lanes fail closed."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys

from rs9.build_native import stage_payload
from rs9.candidate import capture_generation
from rs9.errors import ContractError
from rs9.github import PublicClient
from rs9.npm_deps import closure_for_capture
from rs9.scratch import canonical, physical_directory
from rs9.security import scan_for_credentials
from rs9.verify_wheel import verify_double_build, verify_offline_venv_lifecycle
from rs9.wheel import THEME_FORGE_PRODUCTS
from rs9.wheel_capture import build_capture_wheel

REQUIRED_RECEIPTS: tuple[tuple[str, str], ...] = (
    ("authenticate", "generation"),
    ("wheels", "aarch64-darwin"),
    ("wheels", "x86_64-linux"),
    ("wheels", "aarch64-linux"),
    ("nix", "aarch64-darwin"),
    ("nix", "x86_64-linux"),
    ("nix", "aarch64-linux"),
    ("pacman", "x86_64-linux"),
    ("rpm", "x86_64-linux"),
    ("rpm", "aarch64-linux"),
    ("deb", "amd64"),
    ("deb", "arm64"),
    ("pages", "generation"),
)
REQUIRED_RECEIPT_FILES: frozenset[str] = frozenset(f"{lane}-{system}.json" for lane, system in REQUIRED_RECEIPTS)


def receipt(root, name, record):
    data = canonical(record)
    if len(data) > 512 * 1024:
        raise ContractError("RECEIPT_LIMIT", "Candidate receipt exceeds bound")
    scan_for_credentials(data.decode("utf-8"))
    (root / (name + ".json")).write_bytes(data)


def command_probes(command: str) -> list[list[str]]:
    """Command-specific supported probes per architecture extraction inventory.
    tfsl-batch uses truthful empty input; do not invent --help or --version."""
    if command == "tfsl-batch":
        return [[]]
    if command in {"tfsb", "tfsl", "tfss"}:
        return [["--version"], ["--help"]]
    # The service protocol needs an authenticated supported scenario, not
    # generic command-line flags inferred from the other entrypoints.
    return []


def wheel_diagnostics(repository, scratch, client, binding):
    """Exercise real CLI wheels; native platform proof remains a mandatory blocker."""
    capture_root = scratch / "capture"
    capture_root.mkdir()
    captures = capture_generation(repository, capture_root, client=client, checkout_binding=binding)
    node = shutil.which("node")
    if not node:
        raise ContractError("NODE_UNAVAILABLE", "Node >=22 required")
    node_version = subprocess.run([node, "--version"], check=True, capture_output=True,
                                  text=True, timeout=10).stdout.strip()
    if int(node_version.removeprefix("v").split(".")[0]) < 22:
        raise ContractError("NODE_UNAVAILABLE", "Node >=22 required")
    runtime_bin = scratch / "runtime-bin"
    runtime_bin.mkdir()
    (runtime_bin / "node").symlink_to(node)
    results = []

    is_linux = platform.system() == "Linux"
    is_darwin = platform.system() == "Darwin"

    for capture, intent, profile in captures:
        product = intent["project"]["id"]
        if product == "theme-forge-nebular-fusion":
            results.append({"project": product, "status": "not-run", "reason": "native-platform-verifier-unimplemented"})
            continue
        project_root = scratch / product
        project_root.mkdir()

        try:
            package = json.loads(capture.source["package.json"])
            archives = None
            if package.get("dependencies") or product.endswith("stellar-burst"):
                archives = {}
                for index, row in enumerate(closure_for_capture(capture)):
                    target = project_root / f"dependency-{index}.tgz"
                    target.write_bytes(client.get(row["url"], limit=32 * 1024 ** 2))
                    archives[row["path"]] = target
            first, _ = verify_double_build(build_capture_wheel, product,
                THEME_FORGE_PRODUCTS[product]["version"], capture,
                output_dir_a=project_root / "build-a", output_dir_b=project_root / "build-b",
                dependency_archives=archives, profile_result=profile)
        except (ContractError, OSError, ValueError, KeyError, subprocess.SubprocessError) as err:
            results.append({
                "project": product,
                "status": "diagnostic-fail",
                "error": err.code if isinstance(err, ContractError) else "PRODUCT_BUILD_FAILED",
            })
            continue

        # On Darwin, proxy vars must never prove runtime offline, so fail closed/not-run without actual isolation
        if is_darwin or not is_linux:
            results.append({
                "project": product,
                "status": "not-run",
                "reason": "darwin-offline-isolation-unsupported" if is_darwin else "offline-isolation-unsupported",
                "network_isolation": "unsupported",
                "filename": first.filename,
                "sha256": first.sha256,
                "release_record_sha256": first.record["release_record_sha256"],
                "lifecycle": [],
            })
            continue

        # Linux netns CLI execution must drop root back to runner uid/gid and preserve runner-owned venv/cache
        sudo, unshare = shutil.which("sudo"), shutil.which("unshare")
        setpriv = shutil.which("setpriv")
        if not sudo or not unshare or not setpriv:
            raise ContractError("NETWORK_ISOLATION_UNAVAILABLE", "Network namespace and privilege dropping tools required")

        uid, gid = os.getuid(), os.getgid()
        if uid == 0 or gid == 0:
            raise ContractError("UNPRIVILEGED_CLIENT_REQUIRED", "Candidate commands require a non-root runner")
        drop = [setpriv, f"--reuid={uid}", f"--regid={gid}", "--clear-groups", "--"]

        payload = capture.record["payloads"][0]
        raw_root = project_root / "raw"
        raw_root.mkdir()
        stage_payload(capture, payload, raw_root, project_root)
        env = {"PATH": str(runtime_bin), "npm_config_cache": str(project_root / "npm-cache"),
               "HTTP_PROXY": "http://127.0.0.1:9", "HTTPS_PROXY": "http://127.0.0.1:9",
               "ALL_PROXY": "http://127.0.0.1:9", "NO_PROXY": "",
               "HOME": str(project_root), "XDG_CACHE_HOME": str(project_root / "cache")}
        prefix = [sudo, "-n", unshare, "--net", "--", *drop, "/usr/bin/env", "-i",
                  *(key + "=" + value for key, value in env.items())]

        command_records = []
        for command, target in THEME_FORGE_PRODUCTS[product]["default_commands"].items():
            relative = target.removeprefix("package/")
            # Raw runtime uses the same authenticated offline dependencies as the wheel.
            if archives is not None:
                from rs9.build_native import stage_offline_npm_closure
                if not (raw_root / "node_modules").exists():
                    stage_offline_npm_closure(capture, product, archives, raw_root / "node_modules")

            probes = command_probes(command)
            if not probes:
                command_records.append({"command": command, "status": "not-run",
                                        "reason": "command-probe-unqualified"})
                continue
            for index, args in enumerate(probes):
                raw_argv = [node, str(raw_root / relative), *args]
                stdin_input = ""
                try:
                    baseline = subprocess.run([*prefix, *raw_argv], input=stdin_input, env=env,
                                              text=True, capture_output=True, timeout=30)
                except Exception as exc:
                    command_records.append({
                        "command": command,
                        "argv": args,
                        "status": "diagnostic-fail",
                        "error": "RAW_COMMAND_FAILED",
                    })
                    continue

                if args and baseline.returncode != 0:
                    command_records.append({
                        "command": command,
                        "argv": args,
                        "status": "diagnostic-fail",
                        "error": "RAW_COMMAND_FAILED",
                        "returncode": baseline.returncode,
                    })
                    continue

                try:
                    lifecycle = verify_offline_venv_lifecycle(
                        first.wheel_path,
                        distribution_name=product,
                        venv_dir=project_root / f"venv-{command}-{index}",
                        commands_to_test={
                            command: {
                                "argv": args,
                                "input": stdin_input,
                                "expect_exit": baseline.returncode,
                                "raw_argv": raw_argv,
                                "env": env,
                                "clean_environment": True,
                            }
                        },
                        command_prefix=prefix,
                    )
                    command_records.append({
                        "command": command,
                        "argv": args,
                        "status": "diagnostic-pass",
                        "lifecycle": lifecycle,
                    })
                except ContractError as exc:
                    command_records.append({
                        "command": command,
                        "argv": args,
                        "status": "diagnostic-fail",
                        "error": exc.code,
                    })
                except Exception as exc:
                    command_records.append({
                        "command": command,
                        "argv": args,
                        "status": "diagnostic-fail",
                        "error": "LIFECYCLE_FAILED",
                    })

        if (project_root / "npm-cache").exists():
            results.append({
                "project": product,
                "status": "diagnostic-fail",
                "error": "RUNTIME_INSTALL_DETECTED",
                "filename": first.filename,
                "sha256": first.sha256,
                "release_record_sha256": first.record["release_record_sha256"],
                "lifecycle": command_records,
                "network_isolation": "network-namespace",
            })
            continue

        has_failures = not command_records or any(c.get("status") != "diagnostic-pass" for c in command_records)
        results.append({
            "project": product,
            "status": "diagnostic-fail" if has_failures else "diagnostic-pass",
            "filename": first.filename,
            "sha256": first.sha256,
            "release_record_sha256": first.record["release_record_sha256"],
            "lifecycle": command_records,
            "network_isolation": "network-namespace",
        })
    return results


def prerequisite_failures(repository, lane, system=None):
    targets_path = repository / "operators/live1/targets.json"
    if not targets_path.is_file():
        raise ContractError("TARGETS_MISSING", "Candidate targets declaration missing")
    targets = json.loads(targets_path.read_bytes())
    if targets.get("schema") != "rs9.live1-candidate-targets.v1alpha1":
        raise ContractError("TARGETS_SCHEMA", "Unexpected targets schema")

    system_to_arch = {
        "x86_64-linux": "x86_64",
        "aarch64-linux": "aarch64",
        "amd64": "amd64",
        "arm64": "arm64",
        "aarch64-darwin": "aarch64",
    }
    arch = system_to_arch.get(system, system)
    blockers = []

    if lane in {"pacman", "rpm", "deb"}:
        lane_cfg = targets.get(lane, {})
        if lane == "pacman":
            if not lane_cfg.get("container_digest"):
                blockers.append("authenticated-container-digest-unavailable")
            if not lane_cfg.get("snapshot"):
                blockers.append("arch-snapshot-unavailable")
        elif lane in {"rpm", "deb"}:
            container_digests = lane_cfg.get("container_digests", {})
            if arch:
                if not container_digests.get(arch):
                    blockers.append("authenticated-container-digest-unavailable")
            else:
                if not container_digests:
                    blockers.append("authenticated-container-digest-unavailable")

        if not targets.get("maintainer"):
            blockers.append("maintainer-unassigned")

        blockers.extend([
            "complete-dependency-derivation-unqualified",
            "clean-client-and-fixture-tamper-harness-unimplemented",
        ])
        return blockers

    if lane == "nix":
        nix_cfg = targets.get("nix", {})
        if not nix_cfg.get("nixpkgs_revision") or not nix_cfg.get("nixpkgs_nar_hash"):
            blockers.append("nixpkgs-lock-unavailable")
        if not nix_cfg.get("outputs_exposed"):
            blockers.append("native-closure-and-scenario-A-unqualified")
        # Exposure and pin fields are configuration, not executable proof.
        blockers.append("nix-build-check-run-harness-unimplemented")
        return blockers

    if lane == "pages":
        return ["qualified-repository-objects-unavailable"]

    raise ContractError("CANDIDATE_LANE", "Unsupported candidate lane")


def run_lane(repository, scratch, receipts, lane, system, *, client=None):
    record = {"schema": "rs9.hosted-candidate-diagnostic.v1alpha1", "source_commit": os.environ.get("GITHUB_SHA"),
              "trust_root": "hosted-candidate-unattested", "lane": lane, "system": system,
              "production_enabled": False, "publication_authority": False,
              "status": "blocked", "mandatory_gates_satisfied": False, "artifacts": []}
    record["host"] = {"os": platform.system(), "architecture": platform.machine()}
    try:
        actual = (platform.system(), platform.machine())
        required = {"aarch64-darwin": ("Darwin", {"arm64", "aarch64"}),
                    "x86_64-linux": ("Linux", {"x86_64"}), "aarch64-linux": ("Linux", {"aarch64", "arm64"}),
                    "amd64": ("Linux", {"x86_64"}), "arm64": ("Linux", {"aarch64", "arm64"})}.get(system)
        if required and (actual[0] != required[0] or actual[1] not in required[1]):
            raise ContractError("CANDIDATE_PLATFORM", "Actual runner differs from candidate target")
        if lane == "authenticate":
            capture_root = scratch / "capture"
            capture_root.mkdir()
            capture_generation(repository, capture_root, client=client,
                               checkout_binding="hosted:" + os.environ["GITHUB_SHA"])
            record["authentication"] = json.loads((capture_root / "summary/authentication.json").read_bytes())
            record["status"] = "diagnostic-pass"
        elif lane == "wheels":
            record["artifacts"] = wheel_diagnostics(repository, scratch, client,
                                                    "hosted:" + os.environ["GITHUB_SHA"])
            blockers = ["native-platform-verifier-unimplemented"]
            if platform.system() == "Darwin":
                blockers.append("darwin-offline-isolation-unsupported")
            record["blockers"] = blockers
        else:
            record["blockers"] = prerequisite_failures(repository, lane, system=system)
    except (ContractError, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        record["blockers"] = [error.code if isinstance(error, ContractError) else "candidate-execution-unavailable"]
    receipt(receipts, lane + "-" + system, record)
    return 0 if record["status"] == "diagnostic-pass" else 2


def summarize(repository, receipts):
    manifest_name = "receipts-manifest.json"
    actual_files = set()
    for path in receipts.iterdir():
        if path.is_symlink():
            raise ContractError("HOSTED_RECEIPTS", "Symlinks forbidden in receipts")
        if not path.is_file():
            continue
        if path.name == manifest_name:
            continue
        actual_files.add(path.name)

    if actual_files != REQUIRED_RECEIPT_FILES:
        missing = REQUIRED_RECEIPT_FILES - actual_files
        unexpected = actual_files - REQUIRED_RECEIPT_FILES
        raise ContractError(
            "HOSTED_RECEIPTS",
            f"Exact 13 receipts required; missing={sorted(missing)}, unexpected={sorted(unexpected)}",
        )

    rows = []
    outcomes = []
    seen_keys = set()
    commit = os.environ.get("GITHUB_SHA")
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ContractError("RECEIPT_BINDING", "Hosted source commit required")

    for lane, system in REQUIRED_RECEIPTS:
        fname = f"{lane}-{system}.json"
        path = receipts / fname
        if not path.is_file() or path.stat().st_size > 512 * 1024:
            raise ContractError("HOSTED_RECEIPTS", f"Receipt {fname} missing or exceeds bound")
        data = path.read_bytes()
        scan_for_credentials(data.decode("utf-8"))
        try:
            value = json.loads(data)
        except Exception as exc:
            raise ContractError("HOSTED_RECEIPTS", f"Receipt {fname} is malformed JSON") from exc

        if not isinstance(value, dict):
            raise ContractError("HOSTED_RECEIPTS", f"Receipt {fname} must be a JSON object")
        if value.get("schema") != "rs9.hosted-candidate-diagnostic.v1alpha1":
            raise ContractError("HOSTED_RECEIPTS", f"Receipt {fname} has invalid schema")
        if value.get("source_commit") != commit:
            raise ContractError("RECEIPT_BINDING", f"Receipt {fname} source commit differs")
        if value.get("lane") != lane or value.get("system") != system:
            raise ContractError("HOSTED_RECEIPTS", f"Receipt {fname} content lane/system mismatch")
        if value.get("production_enabled") is not False:
            raise ContractError("HOSTED_RECEIPTS", f"Receipt {fname} must not enable production")
        if value.get("publication_authority") is not False:
            raise ContractError("HOSTED_RECEIPTS", f"Receipt {fname} must not claim publication authority")
        if value.get("mandatory_gates_satisfied") is not False:
            raise ContractError("HOSTED_RECEIPTS", f"Receipt {fname} cannot claim mandatory gates satisfied")
        if value.get("trust_root") != "hosted-candidate-unattested" or value.get("status") not in {"blocked", "diagnostic-pass"}:
            raise ContractError("HOSTED_RECEIPTS", "Receipt must describe bounded candidate diagnostics")

        key = (lane, system)
        if key in seen_keys:
            raise ContractError("HOSTED_RECEIPTS", f"Duplicate receipt for {key}")
        seen_keys.add(key)

        rows.append({"path": fname, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()})
        outcomes.append({
            "lane": value["lane"],
            "system": value["system"],
            "status": value["status"],
            "mandatory_gates_satisfied": value["mandatory_gates_satisfied"],
        })

    # No subset of these diagnostic records can claim whole-generation qualification.
    record = {
        "schema": "rs9.hosted-candidate-receipts.v1alpha1",
        "commit": commit,
        "workflow_sha256": hashlib.sha256(
            (repository / ".github/workflows/rs9-candidate-tests.yml").read_bytes()
        ).hexdigest(),
        "production_enabled": False,
        "status": "incomplete-candidate",
        "outcomes": outcomes,
        "files": rows,
    }
    receipt(receipts, "receipts-manifest", record)
    return 2


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("lane", choices=["authenticate", "wheels", "nix", "pacman", "rpm", "deb", "pages", "summary"])
    parser.add_argument("--repository", default=".")
    parser.add_argument("--scratch")
    parser.add_argument("--receipts", required=True)
    parser.add_argument("--system", default="generation")
    args = parser.parse_args(argv)
    repository = physical_directory(args.repository)
    receipts = physical_directory(args.receipts)
    if args.lane == "summary":
        return summarize(repository, receipts)
    scratch = physical_directory(args.scratch)
    if any(scratch.iterdir()):
        raise ContractError("SCRATCH_NOT_EMPTY", "Empty candidate scratch required")
    client = PublicClient(api_token=os.environ.get("RS9_GITHUB_READ_TOKEN"))
    return run_lane(repository, scratch, receipts, args.lane, args.system, client=client)


if __name__ == "__main__":
    raise SystemExit(main())
