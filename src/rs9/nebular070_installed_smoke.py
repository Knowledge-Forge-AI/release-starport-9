"""Bounded native-rc-smoke execution for an installed Nebular wheel.

The released application-aware harness is the qualification authority for the
fresh installed payload.  This adapter only supplies its fixed CLI, uses the
consumer's process-group runner, and validates the two files the harness
finalizes before returning.  It never treats a historical Gate-1 receipt as a
fresh installed-consumer result.
"""
from __future__ import annotations

import base64
import os
import re
from pathlib import Path
from typing import Any, Mapping, Sequence

from rs9.tf_pypi_archive import fail, physical_bytes, sha256
from rs9.tf_pypi_launcher import node_binary
from rs9.tf_pypi_model import strict_json
from rs9.nebular070_smoke_support import checked_live_path


_HEX64 = re.compile(r"[0-9a-f]{64}")
_MAX_JSON_BYTES = 4 * 1024 * 1024
_ARTIFACT_SCHEMA = "rs9.nebular070-installed-smoke-json-artifact.v1"
_SCENARIOS = {
    "darwin-arm64": {"platform": "darwin-arm64", "triple": "aarch64-apple-darwin", "scenarios": ("A",)},
    "linux-arm64-gnu": {"platform": "linux-arm64", "triple": "aarch64-unknown-linux-gnu", "scenarios": ("B",)},
    "linux-x64-gnu": {"platform": "linux-x64", "triple": "x86_64-unknown-linux-gnu", "scenarios": ("C", "C-signal")},
}
_STEPS = {
    "A": ("app-shell", "host-start", "host-status", "project-open", "brand-read",
          "theme-lab-compile", "app-theme-status", "app-theme-compile", "brand-system-view",
          "host-status-final"),
    "B": ("app-shell", "app-theme-status", "app-theme-compile", "theme-lab-compile",
          "brand-system-view", "host-start", "host-status", "project-open-upper",
          "brand-read-upper", "project-open-lower", "brand-read-lower", "host-status-final"),
    "C": ("app-shell", "host-start", "host-start-idempotent", "host-stop", "host-start-again",
          "host-status", "project-open-case", "derive-plan-cancel", "derive-plan-apply",
          "host-status-final"),
    "C-signal": ("app-shell", "host-start", "host-start-idempotent", "host-stop",
                 "host-start-again", "host-status", "project-open-case", "derive-plan-cancel",
                 "derive-plan-apply", "host-status-final"),
}


def _json_file(path: Path, label: str) -> tuple[dict[str, Any], bytes, str]:
    if path.is_symlink() or not path.is_file():
        fail("NEBULAR_INSTALLED_SMOKE")
    data = physical_bytes(path, limit=_MAX_JSON_BYTES)
    try:
        value = strict_json(data)
    except Exception:
        fail("NEBULAR_INSTALLED_SMOKE")
    if not isinstance(value, Mapping):
        fail("NEBULAR_INSTALLED_SMOKE")
    return dict(value), data, sha256(data)


def _steps(value: Any, expected: Sequence[str]) -> None:
    if not isinstance(value, list) or [item.get("id") for item in value if isinstance(item, Mapping)] != list(expected):
        fail("NEBULAR_INSTALLED_SMOKE")
    if any(
        not isinstance(item, Mapping)
        or item.get("ok") is not True
        or not isinstance(item.get("via"), str)
        or not item["via"]
        or type(item.get("ms")) is not int
        or item["ms"] < 0
        for item in value
    ):
        fail("NEBULAR_INSTALLED_SMOKE")


def _json_artifact(data: bytes, digest: str) -> dict[str, Any]:
    """Retain the exact bounded UTF-8 JSON bytes for matrix revalidation."""
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        fail("NEBULAR_INSTALLED_SMOKE")
    return {
        "schema": _ARTIFACT_SCHEMA,
        "encoding": "base64",
        "media_type": "application/json",
        "size": len(data),
        "sha256": digest,
        "utf8_base64": base64.b64encode(data).decode("ascii"),
    }


def _decode_json_artifact(value: Any) -> tuple[dict[str, Any], bytes, str]:
    if (not isinstance(value, Mapping)
            or set(value) != {
                "schema", "encoding", "media_type", "size", "sha256", "utf8_base64",
            }
            or value.get("schema") != _ARTIFACT_SCHEMA
            or value.get("encoding") != "base64"
            or value.get("media_type") != "application/json"
            or type(value.get("size")) is not int
            or not 1 <= value["size"] <= _MAX_JSON_BYTES
            or not isinstance(value.get("sha256"), str)
            or not _HEX64.fullmatch(value["sha256"])
            or not isinstance(value.get("utf8_base64"), str)):
        fail("NEBULAR_INSTALLED_SMOKE")
    try:
        data = base64.b64decode(value["utf8_base64"], validate=True)
        data.decode("utf-8")
        parsed = strict_json(data)
    except Exception:
        fail("NEBULAR_INSTALLED_SMOKE")
    if (len(data) != value["size"] or sha256(data) != value["sha256"]
            or not isinstance(parsed, Mapping)):
        fail("NEBULAR_INSTALLED_SMOKE")
    return dict(parsed), data, value["sha256"]


def validate_installed_receipts(
    run: Mapping[str, Any],
    receipt: Mapping[str, Any],
    *,
    target: str,
    scenario: str,
    gui_path: str,
    gui_sha256: str,
    receipt_sha256: str,
) -> dict[str, Any]:
    """Validate the complete fresh harness result, not only its digest."""
    expected = _SCENARIOS.get(target)
    if expected is None or scenario not in _STEPS or scenario not in expected["scenarios"]:
        fail("NEBULAR_INSTALLED_SMOKE")
    if (run.get("schema") != "nebular.native-rc-smoke-run-v1"
            or run.get("status") != "pass"
            or run.get("platform") != expected["platform"]
            or run.get("scenario") != scenario
            or run.get("source") != "raw-archive"
            or run.get("problems") != []):
        fail("NEBULAR_INSTALLED_SMOKE")
    executable = run.get("executable")
    if (not isinstance(executable, Mapping)
            or executable.get("path") != gui_path
            or executable.get("sha256") != gui_sha256
            or type(executable.get("size")) is not int
            or executable["size"] <= 0):
        fail("NEBULAR_INSTALLED_SMOKE")
    checks = run.get("checks")
    if (not isinstance(checks, Mapping) or checks.get("orphans") != []
            or not isinstance(checks.get("persistentUserState"), Mapping)
            or checks["persistentUserState"].get("changed") != []
            or type(checks.get("scratchHomeWrites")) is not int
            or checks["scratchHomeWrites"] < 0):
        fail("NEBULAR_INSTALLED_SMOKE")
    finalization = run.get("finalization")
    if (not isinstance(finalization, Mapping)
            or finalization.get("schema") != "nebular.native-rc-finalization-v1"
            or finalization.get("status") != "complete"
            or finalization.get("phase") != "complete"
            or finalization.get("exceptionFamily") is not None
            or finalization.get("spawned") is not True
            or finalization.get("exitObserved") is not True
            or finalization.get("applicationReceiptObservation") != "present-at-read"
            or finalization.get("applicationReceiptCopy") != "written"):
        fail("NEBULAR_INSTALLED_SMOKE")
    exit_info = run.get("exit")
    if (not isinstance(exit_info, Mapping)
            or type(exit_info.get("durationMs")) is not int
            or exit_info["durationMs"] < 0):
        fail("NEBULAR_INSTALLED_SMOKE")
    if scenario == "C-signal":
        signal_sent = exit_info.get("signalSent")
        if (exit_info.get("code") is not None
                or exit_info.get("signal") != "SIGTERM"
                or not isinstance(signal_sent, Mapping)
                or signal_sent.get("signal") != "SIGTERM"
                or type(signal_sent.get("at")) is not int
                or signal_sent["at"] < 0
                or checks.get("sidecarRunningBeforeSignal") is not True):
            fail("NEBULAR_INSTALLED_SMOKE")
    elif (exit_info.get("code") != 0
          or exit_info.get("signal") is not None
          or exit_info.get("signalSent") is not None):
        fail("NEBULAR_INSTALLED_SMOKE")
    run_receipt = run.get("receipt")
    if (not isinstance(run_receipt, Mapping)
            or run_receipt.get("status") != "pass"
            or run_receipt.get("sha256") != receipt_sha256):
        fail("NEBULAR_INSTALLED_SMOKE")
    _steps(run_receipt.get("steps"), _STEPS[scenario])

    if (receipt.get("schema") != "nebular.release-smoke-receipt-v1"
            or receipt.get("applicationVersion") != "0.7.0"
            or receipt.get("scenario") != scenario
            or receipt.get("status") != "pass"
            or receipt.get("failure") is not None
            or receipt.get("target") != expected["triple"]
            or receipt.get("awaitingSignal") is not (scenario == "C-signal")
            or not isinstance(receipt.get("executable"), Mapping)
            or receipt["executable"].get("sha256") != gui_sha256):
        fail("NEBULAR_INSTALLED_SMOKE")
    driver = receipt.get("driver")
    if (not isinstance(driver, Mapping)
            or driver.get("status") != "pass"
            or driver.get("scenario") != scenario
            or not isinstance(driver.get("facts"), list)):
        fail("NEBULAR_INSTALLED_SMOKE")
    _steps(driver.get("steps"), _STEPS[scenario])
    checked = {
        "schema": "rs9.nebular070-installed-native-smoke.v1",
        "status": "pass",
        "qualification_authority": True,
        "target": target,
        "scenario": scenario,
        "source": "raw-archive",
        "executable": {"path": gui_path, "sha256": gui_sha256, "size": executable["size"]},
        "run": {"schema": run["schema"], "status": run["status"]},
        "exit": dict(exit_info),
        "finalization": {
            "schema": finalization["schema"], "status": finalization["status"],
            "phase": finalization["phase"],
        },
        "receipt": {
            "schema": receipt["schema"], "status": receipt["status"],
            "scenario": scenario, "target": expected["triple"],
            "sha256": receipt_sha256,
            "awaitingSignal": receipt["awaitingSignal"],
            "steps": [{"id": item["id"], "ok": True} for item in driver["steps"]],
        },
        "checks": {
            "orphans": [],
            "persistentUserStateChanged": [],
            "scratchHomeWrites": checks["scratchHomeWrites"],
        },
    }
    if scenario == "C-signal":
        checked["checks"]["sidecarRunningBeforeSignal"] = True
    return checked


def _summary_native_probe(value: Any, expected: Mapping[str, Any]) -> dict[str, Any]:
    if (not isinstance(value, Mapping)
            or value.get("status") != "pass"
            or value.get("protocol") != "nebular.native-rc-smoke"
            or value.get("scenarios") != list(expected["scenarios"])
            or value.get("cleanup_known") is not True
            or value.get("output_complete") is not True
            or value.get("forced_cleanup") is not False
            or not isinstance(value.get("runs"), Mapping)
            or not isinstance(value.get("receipts"), Mapping)):
        fail("NEBULAR_INSTALLED_SMOKE")
    return dict(value)


def _summary_entry(
    entry: Any, *, target: str, scenario: str, native_probe: Mapping[str, Any],
    authenticated_gui: Mapping[str, Any],
) -> None:
    if (not isinstance(entry, Mapping)
            or entry.get("schema") != "rs9.nebular070-installed-native-smoke.v1"
            or entry.get("status") != "pass"
            or entry.get("qualification_authority") is not True
            or entry.get("target") != target
            or entry.get("scenario") != scenario
            or entry.get("source") != "raw-archive"):
        fail("NEBULAR_INSTALLED_SMOKE")
    executable = entry.get("executable")
    checks = entry.get("checks")
    finalization = entry.get("finalization")
    if (not isinstance(executable, Mapping)
            or not _HEX64.fullmatch(str(executable.get("sha256")))
            or type(executable.get("size")) is not int
            or executable["size"] <= 0
            or not isinstance(entry.get("run"), Mapping)
            or not isinstance(entry.get("receipt"), Mapping)
            or not isinstance(entry.get("exit"), Mapping)
            or not isinstance(finalization, Mapping)
            or finalization.get("status") != "complete"
            or finalization.get("phase") != "complete"
            or not isinstance(checks, Mapping)
            or checks.get("orphans") != []
            or checks.get("persistentUserStateChanged") != []
            or type(checks.get("scratchHomeWrites")) is not int
            or checks["scratchHomeWrites"] < 0):
        fail("NEBULAR_INSTALLED_SMOKE")
    exit_info = entry["exit"]
    if scenario == "C-signal":
        signal_sent = exit_info.get("signalSent")
        if (exit_info.get("code") is not None
                or exit_info.get("signal") != "SIGTERM"
                or not isinstance(signal_sent, Mapping)
                or signal_sent.get("signal") != "SIGTERM"
                or type(signal_sent.get("at")) is not int
                or signal_sent["at"] < 0
                or checks.get("sidecarRunningBeforeSignal") is not True):
            fail("NEBULAR_INSTALLED_SMOKE")
    elif (exit_info.get("code") != 0
          or exit_info.get("signal") is not None
          or exit_info.get("signalSent") is not None):
        fail("NEBULAR_INSTALLED_SMOKE")
    run = entry["run"]
    receipt = entry["receipt"]
    run_value, _run_data, run_digest = _decode_json_artifact(entry.get("run_artifact"))
    receipt_value, _receipt_data, receipt_digest = _decode_json_artifact(
        entry.get("receipt_artifact"),
    )
    if (run_digest != run.get("sha256")
            or receipt_digest != receipt.get("sha256")
            or not isinstance(executable.get("path"), str)
            or not executable["path"]
            or executable.get("path") != authenticated_gui.get("smoke_path")
            or executable.get("sha256") != authenticated_gui.get("sha256")):
        fail("NEBULAR_INSTALLED_SMOKE")
    validate_installed_receipts(
        run_value,
        receipt_value,
        target=target,
        scenario=scenario,
        gui_path=executable["path"],
        gui_sha256=executable["sha256"],
        receipt_sha256=receipt_digest,
    )
    steps = receipt.get("steps")
    entry_probe = entry.get("native_probe")
    if (run.get("schema") != "nebular.native-rc-smoke-run-v1"
            or run.get("status") != "pass"
            or not _HEX64.fullmatch(str(run.get("sha256")))
            or receipt.get("schema") != "nebular.release-smoke-receipt-v1"
            or receipt.get("status") != "pass"
            or receipt.get("scenario") != scenario
            or receipt.get("awaitingSignal") is not (scenario == "C-signal")
            or not _HEX64.fullmatch(str(receipt.get("sha256")))
            or not isinstance(steps, list)
            or not steps
            or any(not isinstance(step, Mapping) or step.get("ok") is not True for step in steps)
            or not isinstance(entry_probe, Mapping)
            or entry_probe.get("status") != "pass"
            or entry_probe.get("scenario") != scenario
            or entry_probe.get("cleanup_known") is not True
            or entry_probe.get("output_complete") is not True
            or entry_probe.get("forced_cleanup") is not False
            or native_probe["runs"].get(scenario) != run.get("sha256")
            or native_probe["receipts"].get(scenario) != receipt.get("sha256")):
        fail("NEBULAR_INSTALLED_SMOKE")


def validate_installed_smoke_summary(
    value: Mapping[str, Any], *, target: str, authenticated_gui: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate the complete multi-scenario summary at the matrix boundary."""
    expected = _SCENARIOS.get(target)
    if (
        not isinstance(authenticated_gui, Mapping)
        or authenticated_gui.get("status") != "verified"
        or authenticated_gui.get("type") != "file"
        or authenticated_gui.get("executable") is not True
        or authenticated_gui.get("label") != "gui"
        or not isinstance(authenticated_gui.get("smoke_path"), str)
        or not authenticated_gui["smoke_path"]
        or not _HEX64.fullmatch(str(authenticated_gui.get("sha256")))
    ):
        fail("NEBULAR_INSTALLED_SMOKE")
    if (not isinstance(value, Mapping)
            or expected is None
            or value.get("schema") != "rs9.nebular070-installed-native-smoke.v1"
            or value.get("status") != "pass"
            or value.get("qualification_authority") is not True
            or value.get("target") != target
            or value.get("source") != "raw-archive"):
        fail("NEBULAR_INSTALLED_SMOKE")
    scenarios = value.get("scenarios")
    if (not isinstance(scenarios, list)
            or [entry.get("scenario") for entry in scenarios if isinstance(entry, Mapping)]
            != list(expected["scenarios"])
            or len(scenarios) != len(expected["scenarios"])):
        fail("NEBULAR_INSTALLED_SMOKE")
    native_probe = _summary_native_probe(value.get("native_probe"), expected)
    for entry, scenario in zip(scenarios, expected["scenarios"]):
        _summary_entry(
            entry, target=target, scenario=scenario, native_probe=native_probe,
            authenticated_gui=authenticated_gui,
        )
    return dict(value)


def run_installed_smoke(
    *,
    prepared: Mapping[str, Any],
    target: str,
    runtime_root: str | Path,
    env: Mapping[str, str],
    prefix: Sequence[str],
    evidence: str | Path,
    native: Mapping[str, Any],
    gui: Mapping[str, Any],
    runner: Any,
    timeout: int,
) -> dict[str, Any]:
    """Run the released harness for every required scenario on the installed payload."""
    from rs9.tf_pypi_consumer import _nebular_run

    expected = _SCENARIOS.get(target)
    if (expected is None or not isinstance(prepared, Mapping)
            or not isinstance(native, Mapping) or not isinstance(gui, Mapping)
            or native.get("command") != "tfnf"
            or native.get("scenario") != expected["scenarios"][0]):
        fail("NEBULAR_NATIVE_CONTRACT")
    tools = checked_live_path(prepared.get("tools", ""))
    source = checked_live_path(prepared.get("source", ""))
    harness = checked_live_path(tools / "native-rc-smoke.mjs")
    evidence_root = checked_live_path(evidence, code="NEBULAR_INSTALLED_SMOKE")
    launch_root = checked_live_path(runtime_root)
    if (source.is_symlink() or not source.is_dir() or harness.is_symlink()
            or not harness.is_file() or not os.access(harness, os.R_OK)):
        fail("NEBULAR_SMOKE_CLOSURE")
    records = prepared.get("records")
    if not isinstance(records, list):
        fail("NEBULAR_SMOKE_CLOSURE")
    record = next((row for row in records if isinstance(row, Mapping)
                   and row.get("path") == f"{prepared.get('tool_root', 'tools')}/native-rc-smoke.mjs"), None)
    if not isinstance(record, Mapping) or sha256(physical_bytes(harness, limit=2 * 1024 * 1024)) != record.get("sha256"):
        fail("NEBULAR_SMOKE_CLOSURE")
    if evidence_root.exists() or evidence_root.is_symlink():
        fail("NEBULAR_INSTALLED_SMOKE")
    evidence_root.mkdir(parents=True, mode=0o700)
    if target == "darwin-arm64":
        launch_root = launch_root.parent
    checked_scenarios = []
    for scenario in expected["scenarios"]:
        scenario_dir = evidence_root / scenario
        scenario_dir.mkdir(mode=0o700)
        label = f"nebular-installed-{target}-{scenario}"
        command = [node_binary(), str(harness), "--platform", expected["platform"],
                   "--scenario", scenario, "--launch-root", str(launch_root),
                   "--checkout", str(source), "--evidence", str(scenario_dir),
                   "--label", label, "--source", "raw-archive"]
        if target.startswith("linux"):
            command = ["xvfb-run", "-a", "dbus-run-session", "--", *command]
        process = _nebular_run(command, env, source, prefix, timeout, runner=runner)
        if (process.get("exit_code") != 0 or process.get("timed_out")
                or process.get("output_limit_exceeded") or process.get("forced_cleanup")
                or process.get("cleanup_known") is not True or process.get("output_complete") is not True):
            fail("NEBULAR_NATIVE_EXECUTION")
        run_path = scenario_dir / f"{label}.run.json"
        receipt_path = scenario_dir / f"{label}.receipt.json"
        run, run_data, run_sha = _json_file(run_path, "native smoke run")
        receipt, receipt_data, receipt_sha = _json_file(receipt_path, "native smoke receipt")
        checked = validate_installed_receipts(
            run, receipt, target=target, scenario=scenario,
            gui_path=gui["smoke_path"], gui_sha256=gui["sha256"], receipt_sha256=receipt_sha,
        )
        checked["run"]["sha256"] = run_sha
        checked["run"]["size"] = len(run_data)
        checked["run_artifact"] = _json_artifact(run_data, run_sha)
        checked["run"].update({key: process[key] for key in (
            "exit_code", "signal", "stdout_sha256", "stderr_sha256", "duration_ms",
            "cleanup_known", "output_complete", "forced_cleanup",
        ) if key in process})
        checked["receipt"].update({"size": len(receipt_data)})
        checked["receipt_artifact"] = _json_artifact(receipt_data, receipt_sha)
        checked["native_probe"] = {
            "exit_code": process["exit_code"], "signal": process.get("signal"),
            "cleanup_known": process["cleanup_known"],
            "output_complete": process["output_complete"],
            "forced_cleanup": process["forced_cleanup"],
            "status": "pass", "protocol": "nebular.native-rc-smoke",
            "scenario": scenario, "run_sha256": run_sha,
            "receipt_sha256": receipt_sha,
        }
        checked_scenarios.append(checked)
    native_probe = {
        "exit_code": 0, "signal": None,
        "cleanup_known": all(item["native_probe"]["cleanup_known"] is True for item in checked_scenarios),
        "output_complete": all(item["native_probe"]["output_complete"] is True for item in checked_scenarios),
        "forced_cleanup": any(item["native_probe"]["forced_cleanup"] is True for item in checked_scenarios),
        "status": "pass", "protocol": "nebular.native-rc-smoke",
        "scenarios": list(expected["scenarios"]),
        "runs": {item["scenario"]: item["run"]["sha256"] for item in checked_scenarios},
        "receipts": {item["scenario"]: item["receipt"]["sha256"] for item in checked_scenarios},
    }
    return {
        "schema": "rs9.nebular070-installed-native-smoke.v1",
        "status": "pass", "qualification_authority": True,
        "target": target, "source": "raw-archive",
        "scenarios": checked_scenarios,
        "native_probe": native_probe,
    }
