"""Hosted execution for the experimental Linux PRoot Nebular runtime evaluation (candidate-only, diagnostic)."""
import json
import os
from pathlib import Path
from typing import Any

from rs9.errors import ContractError, safe_details
from rs9.hosted_commands import linux_runtime_prefix, run_probes, runtime_environment
from rs9.hosted_nix import command, prepare_input, retain_installer_document
from rs9.hosted_platforms import select_payload
from rs9.hosted_smoke import prepare_smoke, snapshot_nebular_runtime, verify_nebular_runtime
from rs9.materialize import resolve_launcher
from rs9.nix_installer import get_installer_pin
from rs9.nix_proot import (
    GuestRuntime,
    evaluate_proot_experiment,
    prepare_layout,
    proot_command_argv,
    proot_guest_prefix,
    read_closure,
    validate_proot_facts,
    wrapper_script,
)
from rs9.scratch import canonical

SYSTEMS = {"x86_64-linux", "aarch64-linux"}
NEBULAR = "theme-forge-nebular-fusion"
EXPERIMENT = "theme-forge-nebular-fusion-proot"
MAX_FACTS = 64 * 1024
MAX_RECIPE = 1024 * 1024
MAX_SCANNED_FILES = 50000


def _installer_identity(system, scratch, diagnostic_root):
    """Same installer custody as the production Nix lane; a failed install is never retried or ignored."""
    runner_temp = Path(os.environ.get("RUNNER_TEMP", "/tmp"))
    install_scratch = runner_temp / "rs9-nix-install"
    installer_src = install_scratch / "installer-identity.json"
    installer_lane_copy = diagnostic_root / "installer-identity.json"
    installer_failure_src = install_scratch / "installer-failure.json"
    installer_failure_copy = diagnostic_root / "installer-failure.json"

    if installer_failure_src.is_file():
        retain_installer_document(installer_failure_src, installer_failure_copy)
    if installer_src.is_file():
        retain_installer_document(installer_src, installer_lane_copy)

    failure_path = (
        installer_failure_copy
        if installer_failure_copy.is_file()
        else (installer_failure_src if installer_failure_src.is_file() else None)
    )
    if failure_path:
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

    identity = json.loads(installer_path.read_bytes())
    if identity.get("status") == "fail":
        safe_err = {
            "system": system,
            "substage": "installer",
            "reason": identity.get("code") or identity.get("error") or identity.get("reason") or "installer-failure",
            **safe_details(identity.get("error_detail", {})),
        }
        raise ContractError("NIX_INSTALLER", "Prior Nix installation failed", details=safe_err)
    return identity, [p for p in (installer_lane_copy, installer_failure_copy) if p.is_file()]


def _read_bounded(path, limit, code):
    path = Path(path)
    try:
        if path.stat().st_size > limit:
            raise ContractError(code, "Pinned input bound exceeded")
        return path.read_bytes()
    except OSError:
        raise ContractError(code, "Pinned input unreadable") from None


def _path_info(output):
    info = json.loads(output)
    if isinstance(info, list):
        info = {r["path"]: r for r in info}
    return info


def _closure_size(closure):
    """Measured NAR size of exactly the paths bound into the guest."""
    info = _path_info(command(["nix", "path-info", "--json", *closure], timeout=600))
    try:
        sizes = [info[path]["narSize"] for path in closure]
    except (KeyError, TypeError):
        raise ContractError("NIX_OUTPUT", "Closure path size unavailable") from None
    if any(type(size) is not int or size < 0 for size in sizes):
        raise ContractError("NIX_OUTPUT", "Closure path size invalid")
    return sum(sizes)


def _is_elf(path):
    with path.open("rb") as stream:
        return stream.read(4) == b"\x7fELF"


def _release_inventory(root):
    """Actual materialized release ELFs and sidecar; bounded and never guessed from names alone."""
    elfs, scanned = [], 0
    for file in sorted(root.rglob("*")):
        scanned += 1
        if scanned > MAX_SCANNED_FILES:
            raise ContractError("NIX_RUNTIME", "Release file inventory bound exceeded")
        if file.is_file() and not file.is_symlink() and _is_elf(file):
            elfs.append(str(file))
    sidecars = [p for p in root.rglob("tfsb-studio-service*") if p.is_file() and p.parent.name in {"bin", "MacOS"}]
    return elfs, (str(sidecars[0]) if len(sidecars) == 1 else None)


def execute(context: dict[str, Any]) -> dict[str, Any]:
    """Execute the hosted PRoot experiment on a candidate Linux platform."""
    system, repository, scratch = context["system"], context["repository"], context["scratch"]
    if system not in SYSTEMS:
        raise ContractError("NIX_SYSTEM", "Unsupported Linux Nix system for PRoot experiment: " + str(system))

    diagnostic_root = scratch / "diagnostics"
    diagnostic_root.mkdir(exist_ok=True)
    installer_identity, retained = _installer_identity(system, scratch, diagnostic_root)

    targets = context["pins"]["nix"]
    expected_pin = get_installer_pin(targets, system)
    if installer_identity.get("version") != targets["installer_version"] or installer_identity.get("system") != system:
        raise ContractError("NIX_INSTALLER", "Actual installer identity differs from the required lane")
    if installer_identity.get("sha256") != expected_pin:
        raise ContractError("NIX_INSTALLER", "Installer differs from source-pinned checksum")

    source, capture_input, _products = prepare_input(context)
    overrides = [
        "--override-input", "rs9-capture", "path:" + str(capture_input),
        "--override-input", "nixpkgs", "github:NixOS/nixpkgs/" + targets["nixpkgs_revision"],
    ]
    metadata = json.loads(command(["nix", "flake", "metadata", "--json", *overrides, str(source)], timeout=600))
    locked = metadata["locks"]["nodes"]["nixpkgs"]["locked"]
    if locked["rev"] != targets["nixpkgs_revision"] or locked["narHash"] != targets["nixpkgs_nar_hash"]:
        raise ContractError("NIX_PIN", "Actual fetched nixpkgs identity differs from source")

    # Only the experimental output is built; legacy candidates, checks and Darwin outputs are never evaluated here.
    attr = str(source) + "#experiments." + system + "." + EXPERIMENT
    built = json.loads(command(["nix", "build", "--json", "--no-link", *overrides, attr], timeout=3600))
    if not isinstance(built, list) or len(built) != 1 or "out" not in built[0]["outputs"]:
        raise ContractError("NIX_OUTPUT", "One actual experimental output required")
    out_path = built[0]["outputs"]["out"]
    facts_built = json.loads(command(["nix", "build", "--json", "--no-link", *overrides, attr + ".runtimeFacts"],
                                     timeout=600))
    if not isinstance(facts_built, list) or len(facts_built) != 1:
        raise ContractError("NIX_PROOT_FACTS", "One pinned facts output required")
    try:
        raw_facts = json.loads(_read_bounded(facts_built[0]["outputs"]["out"], MAX_FACTS, "NIX_PROOT_FACTS"))
    except ValueError:
        raise ContractError("NIX_PROOT_FACTS", "Pinned facts malformed") from None
    facts = validate_proot_facts(raw_facts)
    if facts["system"] != system:
        raise ContractError("NIX_PROOT_FACTS", "Pinned facts differ from the required lane")
    # The recipe bytes nixpkgs actually evaluated for PRoot; the blob is checked by the experiment's pin probe.
    recipe = _read_bounded(facts["proot_recipe_file"], MAX_RECIPE, "NIX_PROOT_FACTS")
    closure = read_closure(facts)
    closure_size = _closure_size(closure)
    out_info = _path_info(command(["nix", "path-info", "--json", out_path], timeout=120))[out_path]

    cache_dir = scratch / "nix-proot-cache"
    smoke_dir = scratch / "nix-smoke"
    smoke_dir.mkdir(parents=True, exist_ok=True)
    layout = prepare_layout(scratch / "proot-guest", cache_dir, workspaces=(smoke_dir,))
    env = runtime_environment(dict(os.environ, THEME_FORGE_CACHE_DIR=str(layout.cache_dir)))
    env.pop("LD_LIBRARY_PATH", None)
    prefix = linux_runtime_prefix(env)
    runtime = GuestRuntime(facts, layout, closure, prefix=prefix, env=env)

    state: dict[str, Any] = {}

    def materialize():
        """Run the unmodified release launcher in the guest, then inventory what it actually materialized."""
        neb = next((c for c, intent, _ in context["captures"] if intent["project"]["id"] == NEBULAR), None)
        if neb is None:
            raise ContractError("NIX_CAPTURE", "Authenticated Nebular capture required")
        state["neb"] = neb
        state["prepared"] = prepare_smoke(neb, context["captures"], context["client"], smoke_dir)
        argv, _, _ = proot_command_argv(facts, layout, closure, [facts["launcher"]], env=env)
        wrapper = scratch / "proot-guest" / "tfnf"
        wrapper.write_text(wrapper_script(argv))
        wrapper.chmod(0o700)

        def after_first_probe():
            if "baseline" not in state:
                found = list(layout.cache_dir.glob("entries/*/payload/*"))
                if len(found) != 1:
                    raise ContractError("NIX_RUNTIME", "First PRoot launcher materialization missing")
                state["baseline"] = snapshot_nebular_runtime(found[0], state["prepared"], system)

        rows = run_probes("tfnf", wrapper, repository=repository, prefix=prefix, env=env, system=system,
                          substage="nix-proot-command-probe", after_probe=after_first_probe)
        if any(row["status"] != "pass" for row in rows):
            raise ContractError("NIX_COMMAND", "Installed PRoot command contract failed")
        found = list(layout.cache_dir.glob("entries/*/payload/*"))
        if len(found) != 1:
            raise ContractError("NIX_RUNTIME", "Actual PRoot launcher materialization missing")
        root = found[0].resolve()
        state["root"] = root
        elfs, sea = _release_inventory(root)
        payload = select_payload(neb, system)
        relative = payload["launchers"]["tfnf"]["path"].removeprefix(neb.manifests[payload["id"]]["root"] + "/")
        try:
            launcher = resolve_launcher(root, relative)
        except ContractError:
            launcher = None
        return {"elfs": elfs, "sea": sea, "launcher": str(launcher) if launcher else None,
                "launcher_is_elf": bool(launcher and _is_elf(launcher))}

    def smoke(_released):
        if "baseline" not in state:
            raise ContractError("SIDECAR_BASELINE", "Pre-probe PRoot runtime identity required")
        # Released verifier and application smoke run unchanged; only the guest prefix differs.
        guest_prefix, _, _ = proot_guest_prefix(facts, layout, closure, env=env, cwd=None)
        return verify_nebular_runtime(state["root"], state["prepared"], system, [*prefix, *guest_prefix], env,
                                      baseline=state["baseline"])

    evaluation = evaluate_proot_experiment(runtime, recipe, materialize=materialize, smoke=smoke,
                                           closure_size_bytes=closure_size)

    evaluation_file = scratch / "nix-proot-evaluation.json"
    evaluation_file.write_bytes(canonical(evaluation))
    details = {
        "outPath": out_path,
        "narSize": out_info["narSize"],
        "narHash": out_info["narHash"],
        "closure_size_bytes": closure_size,
        "closure_path_count": len(closure),
        "facts": facts,
        "evaluation": evaluation,
        "application_qualified": False,
        "qualification_authority": False,
    }
    return {"gates": evaluation["gates"], "artifacts": [evaluation_file, *retained], "details": details}
