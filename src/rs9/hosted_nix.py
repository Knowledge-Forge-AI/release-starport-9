"""Real hosted Nix builds and bounded store/output qualification evidence."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

from rs9.build_native import stage_payload, stage_offline_npm_closure
from rs9.errors import ContractError, safe_details
from rs9.hosted_commands import command_diagnostic, linux_runtime_prefix, run_probes, runtime_environment
from rs9.hosted_platforms import select_payload
from rs9.hosted_smoke import prepare_smoke, snapshot_nebular_runtime, verify_nebular_runtime, verifier_import_preflight
from rs9.npm_deps import resolve_offline_npm_archives as _resolve_offline_npm_archives
from rs9.nix_loader import evaluate as evaluate_direct_loader
from rs9 import nix_installer
from rs9.product_classes import get_product_class as package_class
from rs9.hosted_burst import verify_burst_payload
from rs9.hosted_burst_clients import release_load_record
from rs9.scratch import canonical
from rs9.security import scan_for_credentials
from rs9.release_core import digest
from rs9.wheel_native import get_embedded_rs9_helpers

SYSTEMS = {"aarch64-darwin", "x86_64-linux", "aarch64-linux"}
PRODUCTS = ("theme-forge-stellar-burst", "theme-forge-stellar-loom",
            "theme-forge-solar-sail", "theme-forge-nebular-fusion")


def fhs_runtime_smoke(runtime, system, prefix, env):
    """Exercise the same disconnected FHS invocation before Nebular probes."""
    result = subprocess.run([*prefix, str(Path(runtime) / "bin/rs9-nebular-fhs"), "true"],
                            env=env, capture_output=True, timeout=30)
    details = command_diagnostic("tfnf", 0, {"kind": "fhs-runtime", "expect_exit": 0}, result,
                                 system=system, substage="nix-fhs-runtime-smoke")
    policy = Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
    try:
        value = policy.read_text().strip()
    except OSError:
        value = None
    details["userns_policy"] = {"0": "unrestricted", "1": "restricted"}.get(value, "unavailable")
    if result.returncode:
        code = "NIX_FHS_USERNS" if details["diagnostic_token"] in {"userns-denied", "uid-map-denied"} else "NIX_FHS_RUNTIME"
        raise ContractError(code, "Disconnected native FHS runtime failed", details=details)
    return {"name": "nix-fhs-runtime-smoke", "status": "pass", "details": details}


def command(argv, *, cwd=None, env=None, timeout=3600):
    details = {"tool": Path(argv[0]).name, "substage": "nix-" + argv[1]}
    try:
        result = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired as error:
        raise ContractError("TOOL_TIMEOUT", "Hosted Nix tool timed out", details={**details,
            "stdout_sha256": digest(error.stdout or b""), "stderr_sha256": digest(error.stderr or b"")}) from None
    except OSError:
        raise ContractError("TOOL_EXECUTION", "Hosted Nix tool unavailable", details=details) from None
    if result.returncode:
        raise ContractError("NIX_EXECUTION", "Hosted Nix tool failed", details={**details,
            "exit_code": result.returncode, "stdout_sha256": digest(result.stdout), "stderr_sha256": digest(result.stderr)})
    return result.stdout


def retain_installer_document(source, destination):
    """Copy only the closed installer evidence projection before any lane work."""
    if source.is_symlink() or not source.is_file() or source.stat().st_size > 64 * 1024:
        raise ContractError("NIX_INSTALLER", "Bounded physical installer evidence required")
    try:
        raw = source.read_bytes()
        scan_for_credentials(raw.decode())
        doc = json.loads(raw)
        if not isinstance(doc, dict):
            raise ValueError
    except (ValueError, OSError):
        raise ContractError("NIX_INSTALLER", "Installer evidence schema invalid") from None
    projected = {key: doc[key] for key in ("version", "system", "sha256", "archive_sha256", "pin_provenance", "status") if key in doc}
    for key in ("error", "code", "reason"):
        if key in doc:
            projected[key] = safe_details({"reason": doc[key]}).get("reason", "installer-failure")
    projected["error_detail"] = safe_details(doc.get("error_detail", {}))
    extraction = doc.get("extraction", {})
    if isinstance(extraction, dict):
        projected["extraction"] = {key: value for key, value in extraction.items()
            if (key in {"member_count", "uncompressed_bytes", "regular_files", "directories", "symlinks", "absolute_store_symlinks"}
                and type(value) is int and 0 <= value <= 2 * 1024 ** 3)}
        checksum = extraction.get("extraction_manifest_sha256")
        if isinstance(checksum, str) and len(checksum) == 64 and all(c in "0123456789abcdef" for c in checksum):
            projected["extraction"]["extraction_manifest_sha256"] = checksum
    destination.write_bytes(canonical(projected))
    return projected


def install(repository, scratch, *, client=None, runner=subprocess.run):
    """Version-bound official installer with closed authenticated extraction and per-system pin contract."""
    return nix_installer.install(repository, scratch, client=client, runner=runner)


def prepare_input(context):
    scratch = context["scratch"]
    source = scratch / "nix-source"
    source.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(context["repository"] / "flake.nix", source / "flake.nix")
    shutil.copytree(context["repository"] / "nix", source / "nix")
    capture_input = scratch / "nix-capture"
    capture_input.mkdir(parents=True, exist_ok=True)
    products = {}
    metadata = json.loads((context["repository"] / "nix/candidate-products.json").read_bytes())["products"]
    for capture, intent, profile in context["captures"]:
        pid = intent["project"]["id"]
        row = dict(metadata[pid])
        native = package_class(pid) == "native-desktop"
        if native:
            payload = select_payload(capture, context["system"])
        else:
            payloads = capture.record.get("payloads", [])
            if len(payloads) != 1:
                raise ContractError("NIX_CAPTURE", "One authenticated system payload required")
            payload = payloads[0]
        destination = capture_input / "payloads" / pid
        destination.parent.mkdir(parents=True, exist_ok=True)
        if not native:
            work = scratch / ("stage-" + pid)
            work.mkdir(parents=True, exist_ok=True)
            stage_payload(capture, payload, destination, work)
            archives = _resolve_offline_npm_archives(capture, pid, scratch, None, context["client"])
            stage_offline_npm_closure(capture, pid, archives, destination / "node_modules")
        else:
            # Nebular archive-in-store design: store authenticated archive and manifest
            destination.mkdir(parents=True, exist_ok=True)
            archive_src = capture.archives[payload["id"]]
            manifest = capture.manifests[payload["id"]]
            if digest(archive_src.read_bytes()) != payload["sha256"]:
                raise ContractError("NIX_CAPTURE", "Payload archive digest mismatch")
            if manifest["manifest_sha256"] != payload["payload_manifest_sha256"]:
                raise ContractError("NIX_CAPTURE", "Payload manifest digest mismatch")
            shutil.copyfile(archive_src, destination / "payload.tar.gz")
            (destination / "manifest.json").write_bytes(canonical(manifest["members"]))

            runtime = capture_input / "runtime"
            runtime.mkdir(parents=True, exist_ok=True)
            for name, data in get_embedded_rs9_helpers().items():
                target = runtime / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
            (runtime / "manifest.json").write_bytes(canonical(manifest["members"]))
            row["root"] = manifest["root"]
            launcher = payload["launchers"]["tfnf"]["path"]
            launcher = launcher.removeprefix(row["root"] + "/")
            code = """import json,os,sys
from pathlib import Path
from rs9.materialize import materialize_payload,resolve_launcher
base=Path(__file__).parent
archive_path = Path(sys.argv[1])
if archive_path.is_dir():
    archive_path = archive_path / "payload.tar.gz"
root=materialize_payload(archive_path, os.environ.get("THEME_FORGE_CACHE_DIR",str(Path.home()/".cache/theme-forge-nebular-fusion")),
 json.loads((base/"manifest.json").read_bytes()),source_is_store=False,expected_manifest_sha256=EXPECTED)
exe=resolve_launcher(root,LAUNCHER)
os.execv(str(exe),[str(exe),*sys.argv[2:]])
"""
            code = code.replace("EXPECTED", repr(manifest["manifest_sha256"])).replace("LAUNCHER", repr(launcher))
            (runtime / "launch.py").write_text(code)
        row.update(authenticated=True, asset_sha256=payload["sha256"], package_class=package_class(pid))
        products[pid] = row
    if set(products) != set(PRODUCTS):
        raise ContractError("NIX_CAPTURE", "All four products required")
    (capture_input / "products.json").write_bytes(canonical(products))
    return source, capture_input, products


def record_direct_loader_evaluation(source, system, overrides, scratch, capture, prefix, env):
    """Retain optional loader diagnostics without preempting the runtime gate."""
    try:
        facts_output = json.loads(command(["nix", "build", "--json", "--no-link", *overrides,
            str(source) + "#candidates." + system + "." + PRODUCTS[-1] + ".runtimeFacts"]))
        if not isinstance(facts_output, list) or len(facts_output) != 1:
            raise ContractError("NIX_LOADER_FACTS", "One loader facts output required")
        facts_path = facts_output[0]["outputs"]["out"]
        facts_raw = Path(facts_path).read_bytes()
        if len(facts_raw) > 64 * 1024:
            raise ContractError("NIX_LOADER_FACTS", "Loader fact bound exceeded")
        loader_payload = scratch / "nix-loader-payload"
        loader_work = scratch / "nix-loader-stage"
        loader_work.mkdir()
        stage_payload(capture, select_payload(capture, system), loader_payload, loader_work)
        elfs = []
        for file in loader_payload.rglob("*"):
            if file.is_file() and not file.is_symlink():
                with file.open("rb") as stream:
                    if stream.read(4) == b"\x7fELF":
                        elfs.append(file)
        evaluation = evaluate_direct_loader(json.loads(facts_raw), elfs, prefix=prefix, env=env)
    except (ContractError, OSError, ValueError, KeyError, TypeError) as error:
        evaluation = {"schema": "rs9.nix-loader-evaluation.v1", "status": "fail",
                      "application_qualified": False,
                      "reason": error.code if isinstance(error, ContractError) else "loader-evaluation-unavailable"}
    (scratch / "nix-loader-evaluation.json").write_bytes(canonical(evaluation))
    return evaluation


def execute(context):
    system, repository, scratch = context["system"], context["repository"], context["scratch"]
    if system not in SYSTEMS:
        raise ContractError("NIX_SYSTEM", "Unsupported Nix system")

    # Retain installer identity and failure into lane-work / diagnostics scratch
    runner_temp = Path(os.environ.get("RUNNER_TEMP", "/tmp"))
    install_scratch = runner_temp / "rs9-nix-install"
    installer_src = install_scratch / "installer-identity.json"
    diagnostic_root = scratch / "diagnostics"
    diagnostic_root.mkdir(exist_ok=True)
    installer_lane_copy = diagnostic_root / "installer-identity.json"
    installer_failure_src = install_scratch / "installer-failure.json"
    installer_failure_copy = diagnostic_root / "installer-failure.json"

    if installer_failure_src.is_file():
        retain_installer_document(installer_failure_src, installer_failure_copy)
    if installer_src.is_file():
        retain_installer_document(installer_src, installer_lane_copy)

    # Check failure FIRST before checking installer identity presence
    failure_path = installer_failure_copy if installer_failure_copy.is_file() else (installer_failure_src if installer_failure_src.is_file() else None)
    if failure_path:
        fail_data = {}
        try:
            fail_data = json.loads(failure_path.read_bytes())
        except (ValueError, OSError):
            raise ContractError("NIX_INSTALLER", "Installer failure evidence invalid") from None
        safe_err = {
            "system": system,
            "substage": "installer",
            "reason": fail_data.get("code") or fail_data.get("error") or fail_data.get("reason") or "installer-failure",
            **safe_details(fail_data.get("error_detail", {})),
        }
        raise ContractError("NIX_INSTALLER", "Prior Nix installation failed", details=safe_err)

    installer_path = installer_lane_copy if installer_lane_copy.is_file() else installer_src
    if not installer_path.is_file():
        raise ContractError("NIX_INSTALLER", "Installer identity missing from prior install step")
    installer_identity = json.loads(installer_path.read_bytes())
    if installer_identity.get("status") == "fail":
        safe_err = {
            "system": system,
            "substage": "installer",
            "reason": installer_identity.get("code") or installer_identity.get("error") or installer_identity.get("reason") or "installer-failure",
            **safe_details(installer_identity.get("error_detail", {})),
        }
        raise ContractError("NIX_INSTALLER", "Prior Nix installation failed", details=safe_err)

    targets = context["pins"]["nix"]
    expected_pin = nix_installer.get_installer_pin(targets, system)
    if installer_identity.get("version") != targets["installer_version"] or installer_identity.get("system") != system:
        raise ContractError("NIX_INSTALLER", "Actual installer identity differs from the required lane")
    if installer_identity.get("sha256") != expected_pin:
        raise ContractError("NIX_INSTALLER", "Installer differs from source-pinned checksum")

    source, capture_input, products = prepare_input(context)
    overrides = ["--override-input", "rs9-capture", "path:" + str(capture_input),
                 "--override-input", "nixpkgs", "github:NixOS/nixpkgs/" + targets["nixpkgs_revision"]]
    metadata = json.loads(command(["nix", "flake", "metadata", "--json", *overrides, str(source)], timeout=600))
    locked = metadata["locks"]["nodes"]["nixpkgs"]["locked"]
    if locked["rev"] != targets["nixpkgs_revision"] or locked["narHash"] != targets["nixpkgs_nar_hash"]:
        raise ContractError("NIX_PIN", "Actual fetched nixpkgs identity differs from source")
    command(["nix", "flake", "check", "--no-build", *overrides, str(source)], timeout=600)
    paths, gates = {}, [{"name": "nix-lock-pin", "status": "pass"}]
    env = runtime_environment(dict(os.environ, THEME_FORGE_CACHE_DIR=str(scratch / "nix-runtime-cache")))
    neb = next(c for c, i, _ in context["captures"] if i["project"]["id"] == PRODUCTS[-1])
    baseline = None
    prepared = None
    runtime_prefix = []
    def after_nebular_probe():
        nonlocal baseline
        if baseline is None:
            roots = list(Path(env["THEME_FORGE_CACHE_DIR"]).glob("entries/*/payload/*"))
            if len(roots) != 1:
                raise ContractError("NIX_RUNTIME", "First Nix launcher materialization missing")
            baseline = snapshot_nebular_runtime(roots[0], prepared, system)
    prefix = []
    if system.endswith("linux"):
        prefix = linux_runtime_prefix(env)
        command([*prefix, sys.executable, "-c", "import socket;s=socket.socket();s.settimeout(2);assert s.connect_ex(('1.1.1.1',443))!=0"], env=env, timeout=10)
    for pid in PRODUCTS:
        attr = str(source) + "#candidates." + system + "." + pid
        built = json.loads(command(["nix", "build", "--json", "--no-link", *overrides, attr]))
        if len(built) != 1 or "out" not in built[0]["outputs"]:
            raise ContractError("NIX_OUTPUT", "One actual output required")
        output = built[0]["outputs"]["out"]
        info = json.loads(command(["nix", "path-info", "--json", output], timeout=120))
        if isinstance(info, list):
            info = {r["path"]: r for r in info}
        paths[pid] = {"drvPath": built[0]["drvPath"], "outPath": output,
                      "package_class": package_class(pid), "architecture": system,
                      "narHash": info[output]["narHash"], "narSize": info[output]["narSize"]}
        if package_class(pid) == "native-node-cli":
            capture = next(c for c, intent, _ in context["captures"] if intent["project"]["id"] == pid)
            load_record = release_load_record(capture, system)
            paths[pid]["native_loader"] = verify_burst_payload(
                Path(output) / "lib/node_modules" / pid, load_record, system,
                scratch / "burst-native-probe", layout_prefix="", prefix=prefix, env=env)
            gates.extend({"name": name, "status": "pass"} for name in
                         ("burst-native-addon-target", "burst-native-addon-load"))
        if pid == PRODUCTS[-1]:
            if system.endswith("linux"):
                # Inspect the unmodified released ELFs before the known FHS
                # boundary. These results never qualify the application.
                paths[pid]["direct_loader_evaluation"] = record_direct_loader_evaluation(
                    source, system, overrides, scratch, neb, prefix, env)
                runtime = json.loads(command(["nix", "build", "--json", "--no-link", *overrides,
                    str(source) + "#candidates." + system + "." + pid + ".runtime"]))[0]["outputs"]["out"]
                gates.append(fhs_runtime_smoke(runtime, system, prefix, env))
                runtime_prefix = [str(Path(runtime) / "bin/rs9-nebular-fhs")]
            # Native outPath has symlink payload passthru: read back compressed archive from store
            store_payload_dir = Path(output) / "payload"
            if not store_payload_dir.exists():
                raise ContractError("NIX_OUTPUT", "Native outPath missing payload passthru")
            store_archive = store_payload_dir / "payload.tar.gz"
            if not store_archive.is_file():
                raise ContractError("NIX_OUTPUT", "Native store archive missing: payload.tar.gz")
            store_archive_bytes = store_archive.read_bytes()
            store_archive_sha256 = digest(store_archive_bytes)
            expected_release_sha256 = products[pid]["asset_sha256"]
            if store_archive_sha256 != expected_release_sha256:
                raise ContractError("NIX_OUTPUT", "Postbuild store archive sha256 mismatch with release")
            paths[pid]["store_archive_sha256"] = store_archive_sha256
            paths[pid]["asset_sha256"] = expected_release_sha256
            gates.append({"name": "nix-store-archive-readback", "status": "pass"})
            prepared = prepare_smoke(neb, context["captures"], context["client"], scratch / "nix-smoke")
            verifier_import_preflight(prepared, system, [*prefix, *runtime_prefix], env)

        for name in products[pid]["commands"]:
            rows = run_probes(name, Path(output) / "bin" / name, repository=repository, prefix=prefix, env=env,
                              system=system, substage="nix-command-probe",
                              **({"after_probe": after_nebular_probe} if pid == PRODUCTS[-1] else {}))
            if any(g["status"] != "pass" for g in rows):
                raise ContractError("NIX_COMMAND", "Installed Nix command contract failed")
            gates.extend(rows)
    # Actually build the check derivations, not just evaluate them.
    command(["nix", "flake", "check", *overrides, str(source)])
    roots = list(Path(env["THEME_FORGE_CACHE_DIR"]).glob("entries/*/payload/*"))
    if len(roots) != 1:
        raise ContractError("NIX_RUNTIME", "Actual Nix launcher materialization missing")
    if baseline is None:
        raise ContractError("SIDECAR_BASELINE", "Pre-probe Nix runtime identity required")
    if system.endswith("linux"):
        for file in roots[0].rglob("*"):
            if not file.is_file() or file.is_symlink():
                continue
            with file.open("rb") as stream:
                elf = stream.read(4) == bytes([127])+b"ELF"
            if elf:
                result = subprocess.run([*prefix, *runtime_prefix, "ldd", str(file)], env=env, capture_output=True, timeout=30)
                if b"not found" in result.stdout or (result.returncode and b"not a dynamic" not in result.stderr + result.stdout and b"statically linked" not in result.stderr + result.stdout):
                    raise ContractError("NIX_CLOSURE", "ELF dependency missing from actual FHS closure")
    smoke = verify_nebular_runtime(roots[0], prepared, system, [*prefix, *runtime_prefix], env, baseline=baseline)
    gates.extend([{"name": "nix-native-closure", "status": "pass"}, {"name": "nix-build-check-run", "status": "pass"}])
    evidence = scratch / "nix-output-receipt.json"
    evidence.write_bytes(canonical({"schema": "rs9.hosted-nix-output.v1alpha1", "system": system,
        "production_enabled": False, "locked": locked, "outputs": paths, "native_smoke": smoke,
        "installer": installer_identity}))
    artifacts = [evidence]
    if (scratch / "nix-loader-evaluation.json").is_file():
        artifacts.append(scratch / "nix-loader-evaluation.json")
    if installer_lane_copy.is_file():
        artifacts.append(installer_lane_copy)
    if installer_failure_copy.is_file():
        artifacts.append(installer_failure_copy)
    return {"gates": gates, "artifacts": artifacts, "details": {"outputs": paths}}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["install"])
    parser.add_argument("--repository", type=Path, default=Path("."))
    parser.add_argument("--scratch", type=Path, required=True)
    args = parser.parse_args()
    install(args.repository, args.scratch)
