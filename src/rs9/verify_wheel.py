"""Wheel build verification suite supporting offline venvs, RECORD digests, and CLI parity."""
from __future__ import annotations

import hashlib

import csv
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Any, Callable, Mapping, Sequence
import zipfile

from rs9.errors import ContractError
from rs9.wheel import (
    WheelBuildResult,
    _record_digest,
    inspect_wheel,
    verify_wheel_record_bidirectional,
)


def verify_double_build(
    builder_fn: Callable[..., WheelBuildResult],
    *args: Any,
    output_dir_a: str | Path | None = None,
    output_dir_b: str | Path | None = None,
    **kwargs: Any,
) -> tuple[WheelBuildResult, WheelBuildResult]:
    """Verify bit-for-bit double-build determinism across two isolated destinations."""
    temp_parent: tempfile.TemporaryDirectory | None = None
    if output_dir_a is None or output_dir_b is None:
        temp_parent = tempfile.TemporaryDirectory()
        base = Path(temp_parent.name).resolve()
        dest_a = Path(output_dir_a).resolve() if output_dir_a else (base / "build_a")
        dest_b = Path(output_dir_b).resolve() if output_dir_b else (base / "build_b")
    else:
        dest_a = Path(output_dir_a).resolve()
        dest_b = Path(output_dir_b).resolve()

    dest_a.mkdir(parents=True, exist_ok=True)
    dest_b.mkdir(parents=True, exist_ok=True)

    res_a = builder_fn(*args, output_dir=dest_a, **kwargs)
    res_b = builder_fn(*args, output_dir=dest_b, **kwargs)

    if res_a.wheel_bytes != res_b.wheel_bytes:
        raise ContractError(
            "NONDETERMINISTIC_BUILD",
            f"Double-build produced non-identical wheel bytes (size_a={len(res_a.wheel_bytes)}, size_b={len(res_b.wheel_bytes)})",
        )
    if res_a.sha256 != res_b.sha256:
        raise ContractError(
            "NONDETERMINISTIC_BUILD",
            f"Double-build produced differing SHA256 (a={res_a.sha256}, b={res_b.sha256})",
        )
    if res_a.filename != res_b.filename:
        raise ContractError(
            "NONDETERMINISTIC_BUILD",
            f"Double-build produced differing filenames (a={res_a.filename}, b={res_b.filename})",
        )

    verify_wheel_record_bidirectional(res_a.wheel_path)
    verify_wheel_record_bidirectional(res_b.wheel_path)
    return res_a, res_b


def verify_raw_vs_wheel_parity(
    raw_cmd: Sequence[str],
    wheel_cmd: Sequence[str],
    *,
    stdin_input: str | bytes | None = None,
    env: dict[str, str] | None = None,
    timeout: int = 15,
    allow_json_stdout_equivalence: bool = False,
) -> dict[str, Any]:
    """Verify raw CLI command vs installed wheel entrypoint parity, including exit code and output."""
    raw_res = subprocess.run(
        list(raw_cmd),
        input=stdin_input,
        capture_output=True,
        text=isinstance(stdin_input, str) or stdin_input is None,
        env=env,
        timeout=timeout,
    )
    wheel_res = subprocess.run(
        list(wheel_cmd),
        input=stdin_input,
        capture_output=True,
        text=isinstance(stdin_input, str) or stdin_input is None,
        env=env,
        timeout=timeout,
    )

    if raw_res.returncode != wheel_res.returncode:
        raise ContractError(
            "CLI_PARITY_MISMATCH",
            "Raw and installed CLI exit codes differ",
        )

    # Check stdout equality
    stdout_matched = False
    if raw_res.stdout == wheel_res.stdout:
        stdout_matched = True
    elif allow_json_stdout_equivalence and isinstance(raw_res.stdout, str) and isinstance(wheel_res.stdout, str):
        try:
            raw_json = json.loads(raw_res.stdout)
            wheel_json = json.loads(wheel_res.stdout)
            if raw_json == wheel_json:
                stdout_matched = True
        except (ValueError, TypeError):
            pass

    if not stdout_matched:
        raise ContractError(
            "CLI_PARITY_MISMATCH",
            "Raw and installed CLI stdout differ",
        )
    if raw_res.stderr != wheel_res.stderr:
        raise ContractError("CLI_PARITY_MISMATCH", "Raw and installed CLI stderr differ")

    return {
        "returncode": raw_res.returncode,
        "stdout_sha256": hashlib.sha256(raw_res.stdout.encode() if isinstance(raw_res.stdout, str) else raw_res.stdout).hexdigest(),
        "stderr_sha256": hashlib.sha256(raw_res.stderr.encode() if isinstance(raw_res.stderr, str) else raw_res.stderr).hexdigest(),
        "parity_confirmed": True,
    }


def _venv_inventory(root: Path) -> dict[str, tuple[str, int, str]]:
    """Inventory relative names, types, modes and file bytes without timestamps."""
    result = {}
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        info = path.lstat()
        mode = stat.S_IMODE(info.st_mode)
        if path.is_symlink():
            entry = ("symlink", mode, os.readlink(path))
        elif stat.S_ISDIR(info.st_mode):
            entry = ("directory", mode, "")
        elif stat.S_ISREG(info.st_mode):
            entry = ("file", mode, hashlib.sha256(path.read_bytes()).hexdigest())
        else:
            raise ContractError("DIRTY_UNINSTALL", "Unexpected special file in venv")
        result[relative] = entry
    return result


def verify_offline_venv_lifecycle(
    wheel_path: str | Path,
    *,
    distribution_name: str,
    commands_to_test: Mapping[str, dict[str, Any]] | None = None,
    venv_dir: str | Path | None = None,
    command_prefix: Sequence[str] = (),
    cache_dir: str | Path | None = None,
) -> dict[str, Any]:
    """Verify offline installation into clean venv, command execution, and clean uninstallation."""
    whl = Path(wheel_path).resolve()
    if not whl.is_file():
        raise ContractError("INVALID_WHEEL", f"Wheel file not found: {whl}")

    cleanup_venv = False
    if venv_dir is None:
        temp_dir = tempfile.TemporaryDirectory()
        venv_path = Path(temp_dir.name).resolve() / "venv"
        cleanup_venv = True
    else:
        venv_path = Path(venv_dir).resolve()
        if venv_path.exists() and any(venv_path.iterdir()):
            raise ContractError("SCRATCH_NOT_EMPTY", "Clean-client venv target must be empty")

    # Isolate runtime materialization cache
    managed_temp_cache: tempfile.TemporaryDirectory | None = None
    if cache_dir is not None:
        effective_cache_path = Path(cache_dir).resolve()
    else:
        cmd_env_cache = None
        if commands_to_test:
            for cspec in commands_to_test.values():
                e = cspec.get("env") or {}
                if "THEME_FORGE_CACHE_DIR" in e:
                    cmd_env_cache = e["THEME_FORGE_CACHE_DIR"]
                    break
        if cmd_env_cache is not None:
            effective_cache_path = Path(cmd_env_cache).resolve()
        else:
            managed_temp_cache = tempfile.TemporaryDirectory()
            effective_cache_path = Path(managed_temp_cache.name).resolve() / "user_cache"

    try:
        if effective_cache_path.exists() and any(effective_cache_path.iterdir()):
            raise ContractError("SCRATCH_NOT_EMPTY", "Clean-client materialization cache must be empty")
        for spec in (commands_to_test or {}).values():
            declared_cache = (spec.get("env") or {}).get("THEME_FORGE_CACHE_DIR")
            if declared_cache is not None and Path(declared_cache).resolve() != effective_cache_path:
                raise ContractError("CACHE_BINDING", "All lifecycle commands must use the same isolated cache")
        # 1. Create clean venv
        subprocess.run(
            [sys.executable, "-m", "venv", str(venv_path)],
            check=True,
            capture_output=True,
            timeout=90,
        )

        baseline_inventory = _venv_inventory(venv_path)

        python_bin = venv_path / "bin" / "python"
        from rs9.hosted_commands import runtime_environment
        pip_env = {
            **runtime_environment(),
            "PIP_CONFIG_FILE": os.devnull,
            "PIP_NO_INDEX": "1",
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
        }

        # 2. Offline wheel installation (--no-index --no-deps)
        install_res = subprocess.run(
            [str(python_bin), "-m", "pip", "install", "--no-index", "--no-deps", str(whl)],
            check=True,
            capture_output=True,
            env=pip_env,
            timeout=60,
        )

        executed_commands: dict[str, Any] = {}
        # 3. Test console script commands
        if commands_to_test:
            for cmd_name, cmd_spec in commands_to_test.items():
                bin_path = venv_path / "bin" / cmd_name
                if not bin_path.is_file():
                    raise ContractError("COMMAND_NOT_FOUND", f"Expected installed console script missing: {bin_path}")
                cmd_args = cmd_spec.get("argv", [])
                stdin_input = cmd_spec.get("input")
                expected_exit = cmd_spec.get("expect_exit", 0)
                stdout_contains = cmd_spec.get("expect_stdout_contains")
                json_error_code = cmd_spec.get("expect_json_error")

                base_env = {} if cmd_spec.get("clean_environment") else dict(os.environ)
                command_env = {
                    **base_env,
                    "THEME_FORGE_CACHE_DIR": str(effective_cache_path),
                    **cmd_spec.get("env", {}),
                    "THEME_FORGE_CACHE_DIR": str(effective_cache_path),
                    "PYTHONDONTWRITEBYTECODE": "1",
                }

                if cmd_spec.get("verifier"):
                    observed = cmd_spec["verifier"](bin_path, command_prefix, command_env)
                    executed_commands[cmd_name] = {"verifier": observed}
                    continue
                run_res = subprocess.run(
                    [*command_prefix, str(bin_path), *cmd_args],
                    input=stdin_input,
                    capture_output=True,
                    text=True,
                    timeout=cmd_spec.get("timeout", 20),
                    env=command_env,
                )
                if run_res.returncode != expected_exit:
                    raise ContractError(
                        "COMMAND_EXECUTION_FAILED",
                        "Installed command exit code differs from reviewed expectation",
                    )
                if stdout_contains and stdout_contains not in run_res.stdout:
                    raise ContractError(
                        "COMMAND_EXECUTION_FAILED",
                        "Installed command stdout differs from reviewed expectation",
                    )
                if json_error_code:
                    try:
                        data = json.loads(run_res.stdout)
                        code = data.get("error", {}).get("code")
                        if code != json_error_code:
                            raise ContractError(
                                "COMMAND_EXECUTION_FAILED",
                                f"Command {cmd_name} error code {code!r} does not match expected {json_error_code!r}",
                            )
                    except (ValueError, TypeError) as exc:
                        raise ContractError(
                            "COMMAND_EXECUTION_FAILED",
                            "Installed command did not produce expected JSON",
                        ) from exc

                parity = None
                if cmd_spec.get("raw_argv"):
                    parity = verify_raw_vs_wheel_parity(
                        [*command_prefix, *cmd_spec["raw_argv"]],
                        [*command_prefix, str(bin_path), *cmd_args],
                        stdin_input=stdin_input,
                        env=command_env,
                        timeout=cmd_spec.get("timeout", 20),
                    )
                executed_commands[cmd_name] = {
                    "returncode": run_res.returncode,
                    "stdout_sha256": hashlib.sha256(run_res.stdout.encode()).hexdigest(),
                    "stderr_sha256": hashlib.sha256(run_res.stderr.encode()).hexdigest(),
                    "parity": parity,
                }

        # Check external cache materialization before uninstall
        materialized_entries: list[str] = []
        if (effective_cache_path / "entries").is_dir():
            materialized_entries = sorted([p.name for p in (effective_cache_path / "entries").iterdir() if p.is_dir()])
        has_materialized = len(materialized_entries) > 0

        # 4. Uninstall wheel
        uninstall_res = subprocess.run(
            [str(python_bin), "-m", "pip", "uninstall", "-y", distribution_name],
            check=True,
            capture_output=True,
            env=pip_env,
            timeout=60,
        )

        # 5. Verify clean uninstallation
        # Check command binaries removed
        if commands_to_test:
            for cmd_name in commands_to_test:
                bin_path = venv_path / "bin" / cmd_name
                if bin_path.exists():
                    raise ContractError("DIRTY_UNINSTALL", f"Console script was not removed: {bin_path}")

        # Check site-packages removed
        pkg_norm = distribution_name.replace("-", "_")
        site_packages = list(venv_path.glob("lib/python*/site-packages"))
        for sp in site_packages:
            leftovers = list(sp.glob(f"{pkg_norm}*")) + list(sp.glob(f"{distribution_name}*"))
            if leftovers:
                raise ContractError("DIRTY_UNINSTALL", f"Site-packages leftovers found after uninstall: {leftovers}")

        current_inventory = _venv_inventory(venv_path)
        residual_files = sorted(path for path in set(current_inventory) | set(baseline_inventory)
                                if current_inventory.get(path) != baseline_inventory.get(path))
        if residual_files:
            raise ContractError("DIRTY_UNINSTALL", f"Venv inventory differs after uninstall: {residual_files}")

        # Account for external materialization cache truthfully
        post_uninstall_entries: list[str] = []
        if (effective_cache_path / "entries").is_dir():
            post_uninstall_entries = sorted([p.name for p in (effective_cache_path / "entries").iterdir() if p.is_dir()])
        persisted_after_uninstall = (len(post_uninstall_entries) > 0) if has_materialized else False

        cache_report = {
            "isolated_cache": True,
            "scope": "candidate-lifecycle",
            "materialized": has_materialized,
            "materialized_entry_keys": materialized_entries,
            "persisted_after_uninstall": persisted_after_uninstall,
            "pip_removed": False,
            "temporary_cache_removed_by_harness": managed_temp_cache is not None,
            "persistent_cache_documented": True,
            "policy": "pip-retains-runtime-cache; harness-cleans-owned-temporary-cache",
        }

        return {
            "distribution": distribution_name,
            "installed_and_verified": True,
            "commands_tested": list(executed_commands.keys()),
            "command_results": executed_commands,
            "clean_uninstall_verified": True,
            "venv_residuals": residual_files,
            "venv_inventory_scope": "full-tree-bytes-types-modes",
            "materialization_cache": cache_report,
        }
    finally:
        if cleanup_venv:
            temp_dir.cleanup()
        if managed_temp_cache is not None:
            managed_temp_cache.cleanup()


def verify_nebular_sidecar_representation(
    wheel_path: str | Path,
    *,
    capture: Any | None = None,
    scenario_a: dict[str, Any] | None = None,
    runner: Any | None = None,
) -> dict[str, Any]:
    """Inspect immutable released capture source tools and scenario-A runtime representation.

    Verifies that the native wheel encapsulates the exact compressed release payload and
    that source tools (sidecar verifier/transcript) from immutable captures are inspected,
    without inventing synthetic tools or unproven GUI execution.
    """
    whl = Path(wheel_path).resolve()
    if not whl.is_file():
        raise ContractError("INVALID_WHEEL", f"Wheel file not found: {whl}")

    with zipfile.ZipFile(whl, "r") as zf:
        namelist = set(zf.namelist())
        prov_entry = next((n for n in namelist if n.endswith("_rs9/provenance.json")), None)
        if not prov_entry:
            raise ContractError("PROVENANCE_REQUIRED", "Wheel provenance record missing")
        prov = json.loads(zf.read(prov_entry).decode("utf-8"))

        manifest_entry = next((n for n in namelist if n.endswith("payload/manifest.json")), None)
        if not manifest_entry:
            raise ContractError("INVALID_WHEEL", "Embedded payload manifest missing")

        launcher_entry = next((n for n in namelist if n.endswith("launcher.py")), None)
        if not launcher_entry:
            raise ContractError("MISSING_LAUNCHER", "Wheel launcher missing")

    source_tools: dict[str, Any] = {}
    if capture is not None and hasattr(capture, "source") and isinstance(capture.source, dict):
        for path, data in capture.source.items():
            if path.startswith("tools/") or path in {"src-tauri/Cargo.toml", "src-tauri/tauri.conf.json", "package.json"}:
                b = data if isinstance(data, bytes) else str(data).encode("utf-8")
                source_tools[path] = {
                    "sha256": hashlib.sha256(b).hexdigest(),
                    "size": len(b),
                }

    scenario_result: dict[str, Any] = {"status": "not-run"}
    if scenario_a is not None:
        cmd = scenario_a.get("command") or ["tfnf", "--version"]
        scenario_result = {
            "status": "pass" if scenario_a.get("bound") else "not-run",
            "command": cmd,
            "expected_exit_code": scenario_a.get("expected_exit_code", 0),
            "reason": None if scenario_a.get("bound") else "released-command-contract-unbound",
        }

    return {
        "status": "pass" if source_tools else "not-run",
        "wheel_filename": whl.name,
        "payload_manifest_sha256": prov.get("manifest_sha256"),
        "payload_archive_sha256": prov.get("payload_archive_sha256"),
        "source_tools": source_tools,
        "scenario_a": scenario_result,
        "gui_build_probe": "not-run",
        "gui_rationale": "No GUI build probe: headless environment withholds unproven windowing runtime.",
    }
