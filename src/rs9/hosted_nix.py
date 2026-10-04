"""Real hosted Nix builds and bounded store/output qualification evidence."""
import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys

from rs9.build_native import stage_payload, stage_offline_npm_closure
from rs9.errors import ContractError
from rs9.github import PublicClient
from rs9.hosted_commands import linux_runtime_prefix, run_probes, runtime_environment
from rs9.hosted_smoke import prepare_smoke, verify_nebular_runtime
from rs9.hosted_wheels import _resolve_offline_npm_archives
from rs9.scratch import canonical
from rs9.release_core import digest
from rs9.wheel_native import get_embedded_rs9_helpers

SYSTEMS = {"aarch64-darwin", "x86_64-linux", "aarch64-linux"}
PRODUCTS = ("theme-forge-stellar-burst", "theme-forge-stellar-loom",
            "theme-forge-solar-sail", "theme-forge-nebular-fusion")


def command(argv, *, cwd=None, env=None, timeout=3600):
    result = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, timeout=timeout)
    if result.returncode:
        raise ContractError("NIX_EXECUTION", "Hosted Nix command failed: " + argv[1])
    return result.stdout


def install(repository, scratch, *, client=None):
    """Version-bound official installer; unresolved checksum is explicitly preparation evidence."""
    scratch.mkdir(parents=True, exist_ok=False)
    targets = json.loads((repository / "operators/live1/targets.json").read_bytes())["nix"]
    system = ("aarch64" if platform.machine() in ("arm64", "aarch64") else "x86_64") + ("-darwin" if sys.platform == "darwin" else "-linux")
    version = targets["installer_version"]
    filename = "nix-" + version + "-" + system + ".tar.xz"
    url = "https://releases.nixos.org/nix/nix-" + version + "/" + filename
    client = client or PublicClient()
    expected = targets.get("installer_sha256")
    if not expected:
        expected = client.get(url + ".sha256", request_class="nix-installer", limit=1024).decode().split()[0]
    import re
    if not re.fullmatch("[0-9a-f]{64}", expected):
        raise ContractError("NIX_INSTALLER", "Canonical installer checksum required")
    data = client.get(url, request_class="nix-installer", limit=256 * 1024 ** 2)
    if digest(data) != expected:
        raise ContractError("NIX_INSTALLER", "Official installer checksum mismatch")
    archive = scratch / filename
    archive.write_bytes(data)
    # Authenticate every path before invoking the official installer.
    import tarfile
    with tarfile.open(archive) as tar:
        for row in tar.getmembers():
            if row.name.startswith("/") or ".." in Path(row.name).parts or row.isdev() or row.isfifo():
                raise ContractError("NIX_INSTALLER", "Unsafe installer archive path")
        tar.extractall(scratch, filter="data")
    installer = scratch / ("nix-" + version + "-" + system) / "install"
    command(["sh", str(installer), "--daemon", "--yes"], timeout=1200)
    (scratch / "installer-identity.json").write_bytes(canonical({
        "version": version, "system": system, "sha256": expected,
        "pin_provenance": "source-pinned" if targets.get("installer_sha256") else "run-resolved"}))


def prepare_input(context):
    scratch = context["scratch"]
    source = scratch / "nix-source"
    source.mkdir()
    shutil.copyfile(context["repository"] / "flake.nix", source / "flake.nix")
    shutil.copytree(context["repository"] / "nix", source / "nix")
    capture_input = scratch / "nix-capture"
    capture_input.mkdir()
    products = {}
    metadata = json.loads((context["repository"] / "nix/candidate-products.json").read_bytes())["products"]
    for capture, intent, profile in context["captures"]:
        pid = intent["project"]["id"]
        row = dict(metadata[pid])
        native = pid == PRODUCTS[-1]
        arch = context["system"].split("-")[0]
        payloads = [p for p in capture.record["payloads"] if not native or
                    (arch in p["name"] and ("darwin" if context["system"].endswith("darwin") else "linux") in p["name"])]
        if len(payloads) != 1:
            raise ContractError("NIX_CAPTURE", "One authenticated system payload required")
        payload = payloads[0]
        work = scratch / ("stage-" + pid)
        work.mkdir()
        destination = capture_input / "payloads" / pid
        destination.parent.mkdir(exist_ok=True)
        stage_payload(capture, payload, destination, work)
        if not native:
            archives = _resolve_offline_npm_archives(capture, pid, scratch, None, context["client"])
            stage_offline_npm_closure(capture, pid, archives, destination / "node_modules")
        else:
            runtime = capture_input / "runtime"
            runtime.mkdir()
            for name, data in get_embedded_rs9_helpers().items():
                target = runtime / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
            manifest = capture.manifests[payload["id"]]
            (runtime / "manifest.json").write_bytes(canonical(manifest["members"]))
            row["root"] = manifest["root"]
            launcher = payload["launchers"]["tfnf"]["path"]
            launcher = launcher.removeprefix(row["root"] + "/")
            code = """import json,os,sys
from pathlib import Path
from rs9.materialize import materialize_payload,resolve_launcher
base=Path(__file__).parent
root=materialize_payload(sys.argv[1], os.environ.get("THEME_FORGE_CACHE_DIR",str(Path.home()/".cache/theme-forge-nebular-fusion")),
 json.loads((base/"manifest.json").read_bytes()),source_is_store=True,expected_manifest_sha256=EXPECTED)
exe=resolve_launcher(root,LAUNCHER)
os.execv(str(exe),[str(exe),*sys.argv[2:]])
"""
            code = code.replace("EXPECTED", repr(manifest["manifest_sha256"])).replace("LAUNCHER", repr(launcher))
            (runtime / "launch.py").write_text(code)
        row.update(authenticated=True, asset_sha256=payload["sha256"])
        products[pid] = row
    if set(products) != set(PRODUCTS):
        raise ContractError("NIX_CAPTURE", "All four products required")
    (capture_input / "products.json").write_bytes(canonical(products))
    return source, capture_input, products


def execute(context):
    system, repository, scratch = context["system"], context["repository"], context["scratch"]
    if system not in SYSTEMS:
        raise ContractError("NIX_SYSTEM", "Unsupported Nix system")
    source, capture_input, products = prepare_input(context)
    targets = context["pins"]["nix"]
    installer_path = Path(os.environ["RUNNER_TEMP"]) / "rs9-nix-install/installer-identity.json"
    installer_identity = json.loads(installer_path.read_bytes())
    if installer_identity["version"] != targets["installer_version"] or installer_identity["system"] != system:
        raise ContractError("NIX_INSTALLER", "Actual installer identity differs from the required lane")
    if targets.get("installer_sha256") and installer_identity["sha256"] != targets["installer_sha256"]:
        raise ContractError("NIX_INSTALLER", "Installer differs from source-pinned checksum")
    overrides = ["--override-input", "rs9-capture", "path:" + str(capture_input),
                 "--override-input", "nixpkgs", "github:NixOS/nixpkgs/" + targets["nixpkgs_revision"]]
    metadata = json.loads(command(["nix", "flake", "metadata", "--json", *overrides, str(source)], timeout=600))
    locked = metadata["locks"]["nodes"]["nixpkgs"]["locked"]
    if locked["rev"] != targets["nixpkgs_revision"] or locked["narHash"] != targets["nixpkgs_nar_hash"]:
        raise ContractError("NIX_PIN", "Actual fetched nixpkgs identity differs from source")
    command(["nix", "flake", "check", "--no-build", *overrides, str(source)], timeout=600)
    paths, gates = {}, [{"name": "nix-lock-pin", "status": "pass"}]
    env = runtime_environment(dict(os.environ, THEME_FORGE_CACHE_DIR=str(scratch / "nix-runtime-cache")))
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
                      "narHash": info[output]["narHash"], "narSize": info[output]["narSize"]}
        for name in products[pid]["commands"]:
            rows = run_probes(name, Path(output) / "bin" / name, repository=repository, prefix=prefix, env=env)
            if any(g["status"] != "pass" for g in rows):
                raise ContractError("NIX_COMMAND", "Installed Nix command contract failed")
            gates.extend(rows)
    # Actually build the check derivations, not just evaluate them.
    command(["nix", "flake", "check", *overrides, str(source)])
    neb = next(c for c, i, _ in context["captures"] if i["project"]["id"] == PRODUCTS[-1])
    prepared = prepare_smoke(neb, context["captures"], context["client"], scratch / "nix-smoke")
    roots = list(Path(env["THEME_FORGE_CACHE_DIR"]).glob("entries/*/payload/*"))
    if len(roots) != 1:
        raise ContractError("NIX_RUNTIME", "Actual Nix launcher materialization missing")
    runtime_prefix = []
    if system.endswith("linux"):
        runtime = json.loads(command(["nix", "build", "--json", "--no-link", *overrides,
                      str(source) + "#candidates." + system + "." + PRODUCTS[-1] + ".runtime"]))[0]["outputs"]["out"]
        runtime_prefix = [str(Path(runtime) / "bin/rs9-nebular-fhs")]
        for file in roots[0].rglob("*"):
            if not file.is_file() or file.is_symlink():
                continue
            with file.open("rb") as stream:
                elf = stream.read(4) == bytes([127])+b"ELF"
            if elf:
                result = subprocess.run([*prefix, *runtime_prefix, "ldd", str(file)], env=env, capture_output=True, timeout=30)
                if b"not found" in result.stdout or (result.returncode and b"not a dynamic" not in result.stderr + result.stdout and b"statically linked" not in result.stderr + result.stdout):
                    raise ContractError("NIX_CLOSURE", "ELF dependency missing from actual FHS closure")
    smoke = verify_nebular_runtime(roots[0], prepared, system, [*prefix, *runtime_prefix], env)
    gates.extend([{"name": "nix-native-closure", "status": "pass"}, {"name": "nix-build-check-run", "status": "pass"}])
    evidence = scratch / "nix-output-receipt.json"
    evidence.write_bytes(canonical({"schema": "rs9.hosted-nix-output.v1alpha1", "system": system,
        "production_enabled": False, "locked": locked, "outputs": paths, "native_smoke": smoke,
        "installer": installer_identity}))
    return {"gates": gates, "artifacts": [evidence], "details": {"outputs": paths}}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["install"])
    parser.add_argument("--repository", type=Path, default=Path("."))
    parser.add_argument("--scratch", type=Path, required=True)
    args = parser.parse_args()
    install(args.repository, args.scratch)
