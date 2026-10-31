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
import sys
import re
from pathlib import Path
from typing import Any, Mapping, Sequence

from rs9.tf_pypi_archive import AdmissionError, canonical, fail, physical_bytes, sha256
from rs9.tf_pypi_launcher import node_binary
from rs9.tf_pypi_model import strict_json
from rs9.nebular071_smoke_support import checked_live_path
from rs9.nebular071_darwin_harness import prepare_darwin_harness, validate_darwin_harness


_HEX64 = re.compile(r"[0-9a-f]{64}")
_MAX_JSON_BYTES = 4 * 1024 * 1024
_ARTIFACT_SCHEMA = "rs9.nebular071-installed-smoke-json-artifact.v1"
SYSTEM_WEBKIT_PROFILE = "system-webkitgtk-4.1"
SYSTEM_WEBKIT_PROFILE_ID = "nebular-fusion-0.7.1-system-webkitgtk-4.1-v1"
SYSTEM_WEBKIT_PREFLIGHT_SCHEMA = "rs9.nebular071-system-webkit-preflight.v1"
UNIVERSAL_WEBKIT_PREFLIGHT_SCHEMA = "rs9.nebular071-system-webkit-preflight.v2"
SYSTEM_WEBKIT_NATIVE_INPUT_SCHEMA = "rs9.tf-pypi-nebular071-system-native-consumer-input.v1"
SYSTEM_WEBKIT_SONAME = "libwebkit2gtk-4.1.so.0"
_SYSTEM_WEBKIT_HOST_CLASSES = {
    "floor": "bookworm-floor",
    "newer": "ubuntu-newer",
}
_SYSTEM_WEBKIT_SYSTEM_ROOTS = ("/lib/", "/lib64/", "/usr/lib/", "/usr/lib64/")
_SYSTEM_WEBKIT_HEX40 = re.compile(r"[0-9a-f]{40}")
_SCENARIOS = {
    "darwin-arm64": {"platform": "darwin-arm64", "triple": "aarch64-apple-darwin", "scenarios": ("A",)},
    "linux-arm64-gnu": {"platform": "linux-arm64", "triple": "aarch64-unknown-linux-gnu", "scenarios": ("B",)},
    "linux-x64-gnu": {"platform": "linux-x64", "triple": "x86_64-unknown-linux-gnu", "scenarios": ("C", "C-signal")},
}


def _static_relative_path(value: Any) -> str:
    if (not isinstance(value, str) or not value or value.startswith("/")
            or "\\" in value or "\x00" in value
            or any(part in {"", ".", ".."} for part in value.split("/"))):
        fail("NEBULAR_SYSTEM_NATIVE_INPUT")
    return value


def _static_file(value: Any, *, label: str, path_key: str = "path") -> dict[str, Any]:
    if (not isinstance(value, Mapping)
            or set(value) != {path_key, "size", "mode", "sha256"}
            or _static_relative_path(value.get(path_key)) != value.get(path_key)
            or type(value.get("size")) is not int or not 0 < value["size"] <= _MAX_JSON_BYTES * 64
            or type(value.get("mode")) is not int or value["mode"] & ~0o7777
            or not value["mode"] & 0o111
            or not _HEX64.fullmatch(str(value.get("sha256")))):
        fail("NEBULAR_SYSTEM_NATIVE_INPUT")
    return dict(value)


def validate_system_webkit_native_input(
    value: Mapping[str, Any], *, target: str, descriptor: bool = False,
    evidence_files: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Validate static system-consumer inputs without admitting observations.

    This envelope is the input to a hosted consumer.  Qualification, smoke,
    loader, and provider result fields are intentionally absent; those facts
    are produced by the current installed consumer and are never accepted
    from a build-input record.
    """
    if target not in {"linux-arm64-gnu", "linux-x64-gnu"}:
        fail("NEBULAR_SYSTEM_NATIVE_INPUT")
    required = {
        "schema", "target", "profile_id", "runtime_profile", "archive", "members",
        "protocol", "preflight_contract", "smoke_support",
    }
    if not isinstance(value, Mapping) or set(value) != required:
        fail("NEBULAR_SYSTEM_NATIVE_INPUT")
    forbidden = {
        "qualification", "smoke", "provider", "provider_closure", "loader",
        "native_evidence", "status", "passed", "qualified",
    }
    if any(key in value for key in forbidden):
        fail("NEBULAR_SYSTEM_NATIVE_INPUT")
    if (value.get("schema") != SYSTEM_WEBKIT_NATIVE_INPUT_SCHEMA
            or value.get("target") != target
            or value.get("profile_id") != SYSTEM_WEBKIT_PROFILE_ID
            or value.get("runtime_profile") != SYSTEM_WEBKIT_PROFILE):
        fail("NEBULAR_SYSTEM_NATIVE_INPUT")
    archive = value.get("archive")
    if not isinstance(archive, Mapping) or set(archive) != {"payload", "manifest"}:
        fail("NEBULAR_SYSTEM_NATIVE_INPUT")
    payload = archive.get("payload")
    manifest = archive.get("manifest")
    if (not isinstance(payload, Mapping) or set(payload) != {"name", "size", "sha256"}
            or not isinstance(payload.get("name"), str) or not payload["name"]
            or payload["name"] in {".", ".."}
            or "/" in payload["name"] or "\\" in payload["name"]
            or type(payload.get("size")) is not int
            or not 0 < payload["size"] <= _MAX_JSON_BYTES * 64
            or not _HEX64.fullmatch(str(payload.get("sha256")))):
        fail("NEBULAR_SYSTEM_NATIVE_INPUT")
    if (not isinstance(manifest, Mapping) or set(manifest) != {"path", "size", "sha256"}
            or _static_relative_path(manifest.get("path")) != manifest.get("path")
            or type(manifest.get("size")) is not int
            or not 0 < manifest["size"] <= _MAX_JSON_BYTES * 64
            or not _HEX64.fullmatch(str(manifest.get("sha256")))):
        fail("NEBULAR_SYSTEM_NATIVE_INPUT")
    members = value.get("members")
    if not isinstance(members, Mapping) or set(members) != {"gui", "launcher", "sidecar"}:
        fail("NEBULAR_SYSTEM_NATIVE_INPUT")
    checked_members = {role: _static_file(members[role], label=role) for role in members}
    protocol = value.get("protocol")
    expected = _SCENARIOS[target]
    expected_platform = expected["platform"]
    if (not isinstance(protocol, Mapping)
            or set(protocol) != {
                "command", "protocol", "platform", "scenario", "argv", "timeout_seconds",
                "state_paths", "user_state_protocol",
            }
            or protocol.get("command") != "tfnf"
            or protocol.get("protocol") != "nebular.native-rc-smoke"
            or protocol.get("platform") != expected_platform
            or protocol.get("scenario") != expected["scenarios"][0]
            or protocol.get("argv") != [f"--nebular-release-smoke={expected['scenarios'][0]}"]
            or type(protocol.get("timeout_seconds")) is not int
            or not 1 <= protocol["timeout_seconds"] <= 60
            or not isinstance(protocol.get("state_paths"), list)
            or any(_static_relative_path(item) != item for item in protocol["state_paths"])
            or not isinstance(protocol.get("user_state_protocol"), Mapping)
            or set(protocol["user_state_protocol"]) != {"schema", "method", "scope"}
            or protocol["user_state_protocol"].get("schema") != "nebular.native-rc-persistent-user-state-v1"
            or protocol["user_state_protocol"].get("method") != "native-rc-smoke.persistentStateLocations+snapshotLocations"
            or protocol["user_state_protocol"].get("scope") != "real-user-state"):
        fail("NEBULAR_SYSTEM_NATIVE_INPUT")
    contract = value.get("preflight_contract")
    if (not isinstance(contract, Mapping)
            or set(contract) != {"schema", "soname", "launcher", "operation"}
            or contract.get("schema") != SYSTEM_WEBKIT_PREFLIGHT_SCHEMA
            or contract.get("soname") != SYSTEM_WEBKIT_SONAME
            or contract.get("launcher") != "normal-installed-python"
            or contract.get("operation") != "ctypes.CDLL"):
        fail("NEBULAR_SYSTEM_NATIVE_INPUT")
    try:
        from rs9.nebular071_smoke_support import validate_smoke_support
        checked_support = validate_smoke_support(
            value["smoke_support"], target,
            evidence_files=evidence_files, descriptor=descriptor,
        )
    except AdmissionError:
        fail("NEBULAR_SYSTEM_NATIVE_INPUT")
    checked = dict(value)
    checked["archive"] = {"payload": dict(payload), "manifest": dict(manifest)}
    checked["members"] = checked_members
    checked["protocol"] = dict(protocol)
    checked["preflight_contract"] = dict(contract)
    checked["smoke_support"] = checked_support
    return checked
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


def _system_webkit_path(value: Any) -> str:
    if (not isinstance(value, str) or not value.startswith(_SYSTEM_WEBKIT_SYSTEM_ROOTS)
            or "\\" in value or "\x00" in value or "/../" in value
            or "opt/nebular-private" in value):
        fail("NEBULAR_SYSTEM_WEBKIT_PREFLIGHT")
    return value


def _system_webkit_stream(value: Any) -> dict[str, Any]:
    if (not isinstance(value, Mapping) or set(value) != {"bytes", "sha256"}
            or type(value.get("bytes")) is not int or not 0 <= value["bytes"] <= 64 * 1024
            or not isinstance(value.get("sha256"), str) or not _HEX64.fullmatch(value["sha256"])):
        fail("NEBULAR_SYSTEM_WEBKIT_PREFLIGHT")
    return dict(value)


def _system_webkit_source(value: Any) -> dict[str, str]:
    if (not isinstance(value, Mapping) or set(value) != {"commit", "tree"}
            or not isinstance(value.get("commit"), str) or not _SYSTEM_WEBKIT_HEX40.fullmatch(value["commit"])
            or not isinstance(value.get("tree"), str) or not _SYSTEM_WEBKIT_HEX40.fullmatch(value["tree"])):
        fail("NEBULAR_SYSTEM_WEBKIT_PREFLIGHT")
    return {"commit": value["commit"], "tree": value["tree"]}


def validate_system_webkit_preflight(
    value: Mapping[str, Any], *, target: str,
    wheel_sha256: str | None = None, wheel_tag: str | None = None,
    payload_archive_sha256: str | None = None, payload_manifest_sha256: str | None = None,
    source: Mapping[str, str] | None = None,
    run_id: str | None = None, run_attempt: str | None = None,
    host_observation_identity: str | None = None,
    distribution: str = "platform-wheel",
) -> dict[str, Any]:
    """Validate the small, profile-specific host WebKit evidence envelope.

    This is deliberately an evidence carrier, not a package/provider registry.
    The fixed SONAME is loaded by the normal installed Python launcher; the
    provider row only retains the resolved host file identity and bounded
    readelf/loader facts needed to join that result to the existing matrix.
    """
    if target not in {"linux-arm64-gnu", "linux-x64-gnu"}:
        fail("NEBULAR_SYSTEM_WEBKIT_PREFLIGHT")
    required = {
        "schema", "profile", "status", "target", "host", "wheel", "payload",
        "source", "run", "soname", "provider", "provider_observation_identity", "loader", "identity",
    }
    if distribution not in {"platform-wheel", "universal-launcher"}:
        fail("NEBULAR_SYSTEM_WEBKIT_PREFLIGHT")
    universal = distribution == "universal-launcher"
    if universal:
        required.add("distribution")
    if not isinstance(value, Mapping) or set(value) != required:
        fail("NEBULAR_SYSTEM_WEBKIT_PREFLIGHT")
    if universal and value.get("distribution") != distribution:
        fail("NEBULAR_SYSTEM_WEBKIT_PREFLIGHT")
    schema = UNIVERSAL_WEBKIT_PREFLIGHT_SCHEMA if universal else SYSTEM_WEBKIT_PREFLIGHT_SCHEMA
    if (value.get("schema") != schema
            or value.get("profile") != SYSTEM_WEBKIT_PROFILE_ID
            or value.get("status") != "passed"
            or value.get("target") != target
            or value.get("soname") != SYSTEM_WEBKIT_SONAME):
        fail("NEBULAR_SYSTEM_WEBKIT_PREFLIGHT")
    host = value.get("host")
    if (not isinstance(host, Mapping) or set(host) != {"identity", "role", "class"}
            or host.get("role") not in _SYSTEM_WEBKIT_HOST_CLASSES
            or host.get("class") != _SYSTEM_WEBKIT_HOST_CLASSES[host["role"]]
            or not _HEX64.fullmatch(str(host.get("identity")))):
        fail("NEBULAR_SYSTEM_WEBKIT_PREFLIGHT")
    wheel = value.get("wheel")
    if (not isinstance(wheel, Mapping) or set(wheel) != {"sha256", "tag"}
            or not _HEX64.fullmatch(str(wheel.get("sha256")))
            or not isinstance(wheel.get("tag"), str)
            or wheel["tag"] not in ({"py3-none-any"} if universal else
                                    {"py3-none-linux_aarch64", "py3-none-linux_x86_64"})):
        fail("NEBULAR_SYSTEM_WEBKIT_PREFLIGHT")
    payload = value.get("payload")
    if (not isinstance(payload, Mapping) or set(payload) != {"archive_sha256", "manifest_sha256"}
            or not _HEX64.fullmatch(str(payload.get("archive_sha256")))
            or not _HEX64.fullmatch(str(payload.get("manifest_sha256")))):
        fail("NEBULAR_SYSTEM_WEBKIT_PREFLIGHT")
    checked_source = _system_webkit_source(value.get("source"))
    run = value.get("run")
    if (not isinstance(run, Mapping) or set(run) != {"id", "attempt"}
            or not isinstance(run.get("id"), str) or not re.fullmatch(r"[1-9][0-9]*", run["id"])
            or not isinstance(run.get("attempt"), str) or not re.fullmatch(r"[1-9][0-9]*", run["attempt"])):
        fail("NEBULAR_SYSTEM_WEBKIT_PREFLIGHT")
    provider = value.get("provider")
    provider_keys = {
        "soname", "classification", "requestedPath", "terminalPath", "aliasChain", "terminalFull9",
        "bytes", "sha256", "elfMachine", "elfClass", "versionDefinitions", "readelfEvidenceSha256",
    }
    if not isinstance(provider, Mapping) or set(provider) != provider_keys:
        fail("NEBULAR_SYSTEM_WEBKIT_PREFLIGHT")
    if (provider.get("soname") != SYSTEM_WEBKIT_SONAME
            or provider.get("classification") != "system-webkitgtk-4.1"
            or type(provider.get("bytes")) is not int or provider["bytes"] <= 0
            or not _HEX64.fullmatch(str(provider.get("sha256")))
            or provider.get("elfClass") != "ELF64"
            or provider.get("elfMachine") not in (
                {"AArch64"} if target == "linux-arm64-gnu" else {"Advanced Micro Devices X86-64", "X86-64"}
            )
            or not _HEX64.fullmatch(str(provider.get("readelfEvidenceSha256")))):
        fail("NEBULAR_SYSTEM_WEBKIT_PREFLIGHT")
    requested = _system_webkit_path(provider.get("requestedPath"))
    terminal = _system_webkit_path(provider.get("terminalPath"))
    aliases = provider.get("aliasChain")
    if not isinstance(aliases, list):
        fail("NEBULAR_SYSTEM_WEBKIT_PREFLIGHT")
    next_path = requested
    for alias in aliases:
        if (not isinstance(alias, Mapping) or set(alias) != {"path", "rawTarget", "full9"}
                or alias.get("path") != next_path or not isinstance(alias.get("rawTarget"), str)
                or not alias["rawTarget"] or "\x00" in alias["rawTarget"]
                or not isinstance(alias.get("full9"), list) or len(alias["full9"]) != 9
                or any(type(item) not in (int, str) for item in alias["full9"])):
            fail("NEBULAR_SYSTEM_WEBKIT_PREFLIGHT")
        raw_target = alias["rawTarget"]
        next_path = raw_target if raw_target.startswith("/") else str(Path(alias["path"]).parent / raw_target)
        next_path = os.path.normpath(next_path)
        _system_webkit_path(next_path)
    terminal_full9 = provider.get("terminalFull9")
    if (next_path != terminal or not isinstance(terminal_full9, list) or len(terminal_full9) != 9
            or any(type(item) not in (int, str) for item in terminal_full9)):
        fail("NEBULAR_SYSTEM_WEBKIT_PREFLIGHT")
    versions = provider.get("versionDefinitions")
    if (not isinstance(versions, list) or any(not isinstance(item, str) or not item for item in versions)
            or versions != sorted(set(versions))):
        fail("NEBULAR_SYSTEM_WEBKIT_PREFLIGHT")
    from rs9.nebular071_payload import _runtime_provider_row
    try:
        provider_identity = _runtime_provider_row(
            provider, target=target,
            expected_machines={"AArch64"} if target == "linux-arm64-gnu"
            else {"Advanced Micro Devices X86-64", "X86-64"},
            classifications=frozenset({"system-webkitgtk-4.1"}),
        )
    except Exception as exc:
        raise AdmissionError("TF_PYPI_NEBULAR_SYSTEM_WEBKIT_PREFLIGHT") from exc
    if value.get("provider_observation_identity") != provider_identity:
        fail("NEBULAR_SYSTEM_WEBKIT_PREFLIGHT")
    loader = value.get("loader")
    loader_keys = {
        "status", "soname", "command", "exit_code", "signal", "stdout", "stderr",
        "cleanup_known", "output_complete", "forced_cleanup",
    }
    if (not isinstance(loader, Mapping) or set(loader) != loader_keys
            or loader.get("status") != "loaded" or loader.get("soname") != SYSTEM_WEBKIT_SONAME
            or loader.get("command") not in {"python-ctypes-cdll", "installed-tfnf"}
            or loader.get("exit_code") != 0
            or loader.get("signal") is not None or loader.get("cleanup_known") is not True
            or loader.get("output_complete") is not True or loader.get("forced_cleanup") is not False):
        fail("NEBULAR_SYSTEM_WEBKIT_PREFLIGHT")
    _system_webkit_stream(loader.get("stdout"))
    _system_webkit_stream(loader.get("stderr"))
    if wheel_sha256 is not None and wheel.get("sha256") != wheel_sha256:
        fail("NEBULAR_SYSTEM_WEBKIT_PREFLIGHT")
    if wheel_tag is not None and wheel.get("tag") != wheel_tag:
        fail("NEBULAR_SYSTEM_WEBKIT_PREFLIGHT")
    if payload_archive_sha256 is not None and payload.get("archive_sha256") != payload_archive_sha256:
        fail("NEBULAR_SYSTEM_WEBKIT_PREFLIGHT")
    if payload_manifest_sha256 is not None and payload.get("manifest_sha256") != payload_manifest_sha256:
        fail("NEBULAR_SYSTEM_WEBKIT_PREFLIGHT")
    if source is not None and dict(source) != checked_source:
        fail("NEBULAR_SYSTEM_WEBKIT_PREFLIGHT")
    if run_id is not None and run.get("id") != run_id:
        fail("NEBULAR_SYSTEM_WEBKIT_PREFLIGHT")
    if run_attempt is not None and run.get("attempt") != run_attempt:
        fail("NEBULAR_SYSTEM_WEBKIT_PREFLIGHT")
    if host_observation_identity is not None and host.get("identity") != host_observation_identity:
        fail("NEBULAR_SYSTEM_WEBKIT_PREFLIGHT")
    unsigned = dict(value)
    unsigned.pop("identity")
    if value.get("identity") != sha256(canonical(unsigned)):
        fail("NEBULAR_SYSTEM_WEBKIT_PREFLIGHT")
    return dict(value)


def produce_system_webkit_preflight(
    *, process: Mapping[str, Any], target: str, wheel_sha256: str, wheel_tag: str,
    payload_archive_sha256: str, payload_manifest_sha256: str,
    source: Mapping[str, str], run_id: str, run_attempt: str,
    host: Mapping[str, Any], provider: Mapping[str, Any],
    distribution: str = "platform-wheel",
) -> dict[str, Any]:
    """Produce fresh system-WebKit evidence from the current installed run.

    ``process`` is the result of the normal installed ``tfnf`` entrypoint.  It
    is the authoritative runtime check: the generated launcher performs the
    fixed SONAME load before entering the native application.  ``provider`` is
    an already-observed row from the current host qualification context, not a
    provider registry or a static build-input result.
    """
    if (not isinstance(process, Mapping)
            or process.get("exit_code") != 0
            or process.get("timed_out")
            or process.get("output_limit_exceeded")
            or process.get("forced_cleanup")
            or process.get("cleanup_known") is not True
            or process.get("output_complete") is not True):
        fail("NEBULAR_SYSTEM_WEBKIT_MISSING")
    stdout_token = process.get("stdout_token", "")
    stderr_token = process.get("stderr_token", "")
    if not isinstance(stdout_token, str) or not isinstance(stderr_token, str):
        fail("NEBULAR_SYSTEM_WEBKIT_MISSING")
    stdout = process.get("stdout_bytes", stdout_token.encode("utf-8"))
    stderr = process.get("stderr_bytes", stderr_token.encode("utf-8"))
    if not isinstance(stdout, bytes) or not isinstance(stderr, bytes):
        fail("NEBULAR_SYSTEM_WEBKIT_MISSING")
    if (not isinstance(process.get("stdout_sha256"), str)
            or process["stdout_sha256"] != sha256(stdout)
            or not isinstance(process.get("stderr_sha256"), str)
            or process["stderr_sha256"] != sha256(stderr)):
        fail("NEBULAR_SYSTEM_WEBKIT_MISSING")
    loader = {
        "status": "loaded", "soname": SYSTEM_WEBKIT_SONAME,
        "command": "installed-tfnf", "exit_code": process["exit_code"],
        "signal": process.get("signal"),
        "stdout": {"bytes": len(stdout), "sha256": process.get("stdout_sha256", sha256(stdout))},
        "stderr": {"bytes": len(stderr), "sha256": process.get("stderr_sha256", sha256(stderr))},
        "cleanup_known": process["cleanup_known"],
        "output_complete": process["output_complete"],
        "forced_cleanup": process["forced_cleanup"],
    }
    from rs9.nebular071_payload import _runtime_provider_row
    provider_identity = _runtime_provider_row(
        provider, target=target,
        expected_machines={"AArch64"} if target == "linux-arm64-gnu"
        else {"Advanced Micro Devices X86-64", "X86-64"},
        classifications=frozenset({"system-webkitgtk-4.1"}),
    )
    unsigned = {
        "schema": (UNIVERSAL_WEBKIT_PREFLIGHT_SCHEMA if distribution == "universal-launcher"
                   else SYSTEM_WEBKIT_PREFLIGHT_SCHEMA),
        "profile": SYSTEM_WEBKIT_PROFILE_ID,
        "status": "passed", "target": target,
        "host": dict(host),
        "wheel": {"sha256": wheel_sha256, "tag": wheel_tag},
        "payload": {"archive_sha256": payload_archive_sha256,
                     "manifest_sha256": payload_manifest_sha256},
        "source": dict(source), "run": {"id": run_id, "attempt": run_attempt},
        "soname": SYSTEM_WEBKIT_SONAME, "provider": dict(provider),
        "provider_observation_identity": provider_identity, "loader": loader,
    }
    if distribution == "universal-launcher":
        unsigned["distribution"] = distribution
    unsigned["identity"] = sha256(canonical(unsigned))
    validate_system_webkit_preflight(
        unsigned, target=target, wheel_sha256=wheel_sha256, wheel_tag=wheel_tag,
        payload_archive_sha256=payload_archive_sha256,
        payload_manifest_sha256=payload_manifest_sha256, source=source,
        run_id=run_id, run_attempt=run_attempt,
        host_observation_identity=host.get("identity") if isinstance(host, Mapping) else None,
        distribution=distribution,
    )
    return unsigned


def run_system_webkit_preflight(
    *, python_launcher: str | Path, env: Mapping[str, str], cwd: str | Path,
    prefix: Sequence[str], runner: Any, expected: Mapping[str, Any] | None = None,
    context: Mapping[str, Any] | None = None, installed_command: str | Path | None = None,
    installed_process: Mapping[str, Any] | None = None, timeout: int = 30,
) -> dict[str, Any]:
    """Run or consume the fixed SONAME check through the installed launcher.

    The ``expected`` argument is retained for old contract fixtures only.  A
    production system capture passes ``context`` and the already completed
    installed ``tfnf`` process, so no pre-existing preflight envelope is
    required or trusted as an input.
    """
    from rs9.nebular071_consumer_core import _nebular_run

    if expected is None:
        if not isinstance(context, Mapping) or installed_process is None:
            fail("NEBULAR_SYSTEM_WEBKIT_PREFLIGHT")
        return produce_system_webkit_preflight(process=installed_process, **context)

    script = (
        "import ctypes\n"
        f"soname={SYSTEM_WEBKIT_SONAME!r}\n"
        "try:\n"
        " ctypes.CDLL(soname)\n"
        "except (OSError, AttributeError):\n"
        " raise SystemExit(2)\n"
        "print('NEBULAR_SYSTEM_WEBKIT_READY')\n"
    )
    process = _nebular_run(
        [str(python_launcher), "-I", "-B", "-c", script],
        env, Path(cwd), prefix, timeout, runner=runner,
    )
    if (process.get("exit_code") != 0 or process.get("timed_out")
            or process.get("output_limit_exceeded") or process.get("forced_cleanup")
            or process.get("cleanup_known") is not True or process.get("output_complete") is not True
            or "NEBULAR_SYSTEM_WEBKIT_READY" not in process.get("stdout_token", "")):
        fail("NEBULAR_SYSTEM_WEBKIT_MISSING")
    validate_system_webkit_preflight(expected, target=expected["target"])
    expected_loader = expected["loader"]
    actual_loader = {
        "exit_code": process["exit_code"],
        "signal": process.get("signal"),
        "stdout": {
            "bytes": len(process.get("stdout_token", "").encode("utf-8")),
            "sha256": process.get("stdout_sha256"),
        },
        "stderr": {
            "bytes": len(process.get("stderr_token", "").encode("utf-8")),
            "sha256": process.get("stderr_sha256"),
        },
        "cleanup_known": process["cleanup_known"],
        "output_complete": process["output_complete"],
        "forced_cleanup": process["forced_cleanup"],
    }
    if any(actual_loader[key] != expected_loader[key] for key in actual_loader):
        fail("NEBULAR_SYSTEM_WEBKIT_MISSING")
    return {
        "schema": "rs9.nebular071-system-webkit-runtime-probe.v1",
        "status": "passed",
        "soname": SYSTEM_WEBKIT_SONAME,
        "command": "python-ctypes-cdll",
        "exit_code": process["exit_code"],
        "signal": process.get("signal"),
        "stdout": {
            "bytes": len(process.get("stdout_token", "").encode("utf-8")),
            "sha256": process.get("stdout_sha256"),
        },
        "stderr": {
            "bytes": len(process.get("stderr_token", "").encode("utf-8")),
            "sha256": process.get("stderr_sha256"),
        },
        "cleanup_known": process["cleanup_known"],
        "output_complete": process["output_complete"],
        "forced_cleanup": process["forced_cleanup"],
        "preflight_identity": expected["identity"],
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


def verified_application_receipt_digest(body: bytes, expected: str) -> str:
    """Verify the application bytes, allowing only the harness copy's LF.

    The product hashes its receipt before the harness copies that same JSON
    with one trailing newline. Keep that source digest distinct from the
    byte digest of the retained copy; never restamp either document.
    """
    if (not isinstance(body, bytes) or not body or len(body) > _MAX_JSON_BYTES
            or not isinstance(expected, str) or not _HEX64.fullmatch(expected)):
        fail("NEBULAR_INSTALLED_SMOKE")
    if sha256(body) == expected or (body.endswith(b"\n") and sha256(body[:-1]) == expected):
        return expected
    fail("NEBULAR_INSTALLED_SMOKE")


def validate_installed_receipts(
    run: Mapping[str, Any],
    receipt: Mapping[str, Any],
    *,
    target: str,
    scenario: str,
    gui_path: str,
    gui_sha256: str,
    receipt_sha256: str,
    receipt_bytes: bytes | None = None,
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
            or (receipt_bytes is None and run_receipt.get("sha256") != receipt_sha256)):
        fail("NEBULAR_INSTALLED_SMOKE")
    if receipt_bytes is not None:
        if sha256(receipt_bytes) != receipt_sha256:
            fail("NEBULAR_INSTALLED_SMOKE")
        verified_application_receipt_digest(receipt_bytes, run_receipt.get("sha256"))
    _steps(run_receipt.get("steps"), _STEPS[scenario])

    if (receipt.get("schema") != "nebular.release-smoke-receipt-v1"
            or receipt.get("applicationVersion") != "0.7.1"
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
        "schema": "rs9.nebular071-installed-native-smoke.v1",
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


def _summary_system_webkit(
    value: Any, *, target: str, distribution: str = "platform-wheel",
) -> dict[str, Any]:
    if isinstance(value, Mapping) and value.get("schema") in {
        SYSTEM_WEBKIT_PREFLIGHT_SCHEMA, UNIVERSAL_WEBKIT_PREFLIGHT_SCHEMA,
    }:
        return validate_system_webkit_preflight(value, target=target, distribution=distribution)
    if distribution != "platform-wheel":
        fail("NEBULAR_SYSTEM_WEBKIT_PREFLIGHT")
    if (not isinstance(value, Mapping)
            or value.get("schema") != "rs9.nebular071-system-webkit-runtime-probe.v1"
            or value.get("status") != "passed"
            or value.get("soname") != SYSTEM_WEBKIT_SONAME
            or value.get("command") not in {"python-ctypes-cdll", "installed-tfnf"}
            or value.get("exit_code") != 0
            or value.get("signal") is not None
            or value.get("cleanup_known") is not True
            or value.get("output_complete") is not True
            or value.get("forced_cleanup") is not False
            or not _HEX64.fullmatch(str(value.get("preflight_identity")))):
        fail("NEBULAR_INSTALLED_SMOKE")
    _system_webkit_stream(value.get("stdout"))
    _system_webkit_stream(value.get("stderr"))
    return dict(value)


def _summary_entry(
    entry: Any, *, target: str, scenario: str, native_probe: Mapping[str, Any],
    authenticated_gui: Mapping[str, Any],
) -> None:
    if (not isinstance(entry, Mapping)
            or entry.get("schema") != "rs9.nebular071-installed-native-smoke.v1"
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
        receipt_bytes=_receipt_data,
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
    distribution: str = "platform-wheel",
) -> dict[str, Any]:
    """Validate the complete multi-scenario summary at the matrix boundary."""
    expected = _SCENARIOS.get(target)
    if distribution not in {"platform-wheel", "universal-launcher"}:
        fail("NEBULAR_INSTALLED_SMOKE")
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
            or value.get("schema") != "rs9.nebular071-installed-native-smoke.v1"
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
    darwin_harness = value.get("darwin_process_harness")
    if darwin_harness is not None:
        checked_harness = validate_darwin_harness(darwin_harness)
        if (target != "darwin-arm64" or native_probe.get("darwin_process_harness") != checked_harness):
            fail("NEBULAR_DARWIN_HARNESS")
    elif native_probe.get("darwin_process_harness") is not None:
        fail("NEBULAR_DARWIN_HARNESS")
    system_probe = value.get("system_webkit_preflight")
    if target.startswith("linux") and distribution == "universal-launcher" and system_probe is None:
        fail("NEBULAR_SYSTEM_WEBKIT_PREFLIGHT")
    if system_probe is not None:
        _summary_system_webkit(system_probe, target=target, distribution=distribution)
        nested_probe = native_probe.get("system_webkit_preflight")
        if (not isinstance(nested_probe, Mapping)
                or canonical(nested_probe) != canonical(system_probe)):
            fail("NEBULAR_INSTALLED_SMOKE")
    if isinstance(system_probe, Mapping) and system_probe.get("schema") in {
        SYSTEM_WEBKIT_PREFLIGHT_SCHEMA, UNIVERSAL_WEBKIT_PREFLIGHT_SCHEMA,
    }:
        adapter = value.get("installed_launcher_harness")
        if (not isinstance(adapter, Mapping)
                or set(adapter) != {"schema", "source_sha256", "derived_sha256",
                                    "entrypoint_sha256", "entrypoint_bytes", "cache_root_sha256", "transform"}
                or adapter.get("schema") != "rs9.nebular071-installed-launcher-harness.v1"
                or adapter.get("transform") != "authenticated-native-harness-installed-entrypoint-v1"
                or any(not _HEX64.fullmatch(str(adapter.get(key))) for key in
                       ("source_sha256", "derived_sha256", "entrypoint_sha256", "cache_root_sha256"))
                or type(adapter.get("entrypoint_bytes")) is not int
                or not 0 < adapter["entrypoint_bytes"] <= 1024 * 1024):
            fail("NEBULAR_SYSTEM_WEBKIT_PREFLIGHT")
        for entry in scenarios:
            observed, _, _ = _decode_json_artifact(entry.get("run_artifact"))
            if (observed.get("installedEntrypoint") != {
                    "sha256": adapter["entrypoint_sha256"], "size": adapter["entrypoint_bytes"],
                } or observed.get("checks", {}).get("installedEntrypointObserved") is not True):
                fail("NEBULAR_SYSTEM_WEBKIT_PREFLIGHT")
    for entry, scenario in zip(scenarios, expected["scenarios"]):
        _summary_entry(
            entry, target=target, scenario=scenario, native_probe=native_probe,
            authenticated_gui=authenticated_gui,
        )
    return dict(value)


_DARWIN_SPAWN_PROBE = r"""const cp = require("node:child_process");
const fs = require("node:fs");
const codes = new Set(["EPERM", "EACCES", "ENOENT", "ENOBUFS", "ETIMEDOUT"]);
function probe(file, args) {
  const result = cp.spawnSync(file, args, {encoding: "utf8", timeout: 2000, maxBuffer: 65536});
  const error = result.error && typeof result.error.code === "string" ? result.error.code : null;
  return {
    error_code: error === null ? null : codes.has(error) ? error : "OTHER",
    status: Number.isInteger(result.status) ? result.status : null,
    stdout_type: ["string", "undefined", "object"].includes(typeof result.stdout) ? typeof result.stdout : "other",
    stdout_bytes: typeof result.stdout === "string" ? Buffer.byteLength(result.stdout) : 0,
    marker_observed: result.stdout === "OK\n"
  };
}
process.stdout.write(JSON.stringify({
  ps_is_setuid: Boolean(fs.statSync("/bin/ps").mode & 0o4000),
  rows: {
    ps: probe("/bin/ps", ["-p", String(process.pid), "-o", "pid="]),
    node: probe(process.execPath, ["-e", 'process.stdout.write("OK\\n")'])
  }
}));"""


def _collect_darwin_spawn_diagnostic(
    node: str, *, env: Mapping[str, str], cwd: Path, prefix: Sequence[str],
    runner: Any, evidence: Path,
) -> None:
    """Observe two existing tools under the unchanged public Darwin sandbox."""
    if os.environ.get("GITHUB_ACTIONS") != "true" or sys.platform != "darwin":
        return
    from rs9.nebular071_consumer_core import _nebular_run
    process = _nebular_run([node, "-e", _DARWIN_SPAWN_PROBE], env, cwd, prefix, 5, runner=runner)
    value = strict_json(str(process.get("stdout_token", "")).encode("utf-8"))
    if (not isinstance(value, Mapping) or set(value) != {"ps_is_setuid", "rows"}
            or type(value["ps_is_setuid"]) is not bool or not isinstance(value["rows"], Mapping)
            or set(value["rows"]) != {"ps", "node"}):
        return
    for row in value["rows"].values():
        if (not isinstance(row, Mapping) or set(row) != {
                "error_code", "status", "stdout_type", "stdout_bytes", "marker_observed"}
                or row["error_code"] not in {None, "EPERM", "EACCES", "ENOENT", "ENOBUFS", "ETIMEDOUT", "OTHER"}
                or (row["status"] is not None and (
                    type(row["status"]) is not int or not -64 <= row["status"] <= 255))
                or row["stdout_type"] not in {"string", "undefined", "object", "other"}
                or type(row["stdout_bytes"]) is not int or not 0 <= row["stdout_bytes"] <= 65536
                or type(row["marker_observed"]) is not bool):
            return
    record = {
        "schema": "rs9.nebular071-darwin-spawn-diagnostic.v1",
        "evidence_mode": "diagnostic-only", "qualification_authority": False,
        **dict(value),
        "probe_process": {
            "completed_cleanly": process.get("exit_code") == 0
                and process.get("cleanup_known") is True and process.get("output_complete") is True
                and process.get("forced_cleanup") is False,
            "timed_out": process.get("timed_out") is True,
            "output_limit_exceeded": process.get("output_limit_exceeded") is True,
        },
    }
    destination = evidence / "darwin-spawn-diagnostic.run.json"
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        remaining = memoryview(canonical(record))
        while remaining:
            count = os.write(fd, remaining)
            if count <= 0:
                raise OSError("diagnostic write did not progress")
            remaining = remaining[count:]
    finally:
        os.close(fd)


def _native_execution_failure_code(
    process: Mapping[str, Any], *, report: Mapping[str, Any] | None = None,
) -> str:
    """Expose only fixed diagnostic categories, never raw child output."""
    if process.get("timed_out"):
        return "NEBULAR_NATIVE_EXECUTION_TIMEOUT"
    if process.get("output_limit_exceeded"):
        return "NEBULAR_NATIVE_EXECUTION_OUTPUT_LIMIT"
    text = process.get("stderr_token", "")
    if not isinstance(text, str):
        text = ""
    problems: list[str] = []
    stdout = process.get("stdout_token", "")
    if isinstance(stdout, str) and len(stdout.encode("utf-8")) <= 64 * 1024:
        try:
            summary = strict_json(stdout.encode("utf-8"))
            if (isinstance(summary, Mapping) and set(summary) == {"label", "status", "problems"}
                    and summary.get("status") == "fail"
                    and isinstance(summary.get("problems"), list)
                    and len(summary["problems"]) <= 64
                    and all(isinstance(item, str) and len(item) <= 4096
                            for item in summary["problems"])):
                problems = summary["problems"]
                text += "\n" + "\n".join(problems)
        except Exception:
            pass  # Diagnostics cannot replace the original failed result.
    for category, tokens in (
        ("NODE_MODULE", ("ERR_MODULE_NOT_FOUND", "Cannot find module")),
        ("NODE_SYNTAX", ("SyntaxError",)),
        ("FILESYSTEM_MISSING", ("ENOENT", "no such file or directory")),
        ("FILESYSTEM_PERMISSION", ("EACCES", "EPERM", "Permission denied")),
        ("LIBRARY", ("Library not loaded", "cannot open shared object", "dyld[")),
        ("HARNESS_ARGUMENTS", ("Usage: native-rc-smoke.mjs",)),
        ("CANDIDATE_PATH", ("candidate executable", "Candidate executable")),
        ("CANDIDATE_LAUNCHER", ("candidate launcher", "Candidate launcher")),
    ):
        if any(token in text for token in tokens):
            return "NEBULAR_NATIVE_EXECUTION_" + category
    finalization = report.get("finalization") if isinstance(report, Mapping) else None
    if (isinstance(finalization, Mapping)
            and finalization.get("schema") == "nebular.native-rc-finalization-v1"
            and finalization.get("status") == "failed"
            and finalization.get("phase") in {"pre-spawn", "post-exit", "receipt-copy", "cleanup"}
            and finalization.get("exceptionFamily") in {
                "state", "parse", "timeout", "process", "filesystem", "unknown"}):
        phase = finalization["phase"].replace("-", "_").upper()
        family = finalization["exceptionFamily"].upper()
        return f"NEBULAR_NATIVE_EXECUTION_HARNESS_{phase}_{family}"
    for problem in problems:
        step = re.search(r"required step ([a-z-]+) (?:failed|missing)", problem)
        if step and step.group(1) in {item for values in _STEPS.values() for item in values}:
            return "NEBULAR_NATIVE_EXECUTION_STEP_" + step.group(1).replace("-", "_").upper()
    for category, tokens in (
        ("APPLICATION_TIMEOUT", ("the application did not exit within its bound",)),
        ("APPLICATION_EXIT", ("application exit code ", "application ended by ")),
        ("RECEIPT", ("receipt status ", "receipt schema", "smoke receipt")),
        ("ORPHANS", ("orphan candidate processes remained",)),
        ("USER_STATE", ("persistent user state changed",)),
        ("FIXTURE", ("read-only fixture ", "the case-distinct sibling", "the derived asset")),
        ("CLEANUP", ("harness cleanup of the owned scratch directory failed",)),
    ):
        if any(token in problem for token in tokens for problem in problems):
            return "NEBULAR_NATIVE_EXECUTION_" + category
    exit_code = process.get("exit_code")
    # Shell launch failures remain useful even if descendant cleanup was
    # subsequently required. Otherwise forced cleanup explains the failed
    # process contract more directly than a resulting TERM/KILL exit.
    if type(exit_code) is int and exit_code in (126, 127):
        suffix = "EXIT_PERMISSION" if exit_code == 126 else "EXIT_COMMAND_NOT_FOUND"
        return "NEBULAR_NATIVE_EXECUTION_" + suffix
    if process.get("forced_cleanup") is True:
        return "NEBULAR_NATIVE_EXECUTION_FORCED_CLEANUP"
    if process.get("cleanup_known") is False:
        return "NEBULAR_NATIVE_EXECUTION_CLEANUP_UNOBSERVED"
    if process.get("output_complete") is False:
        return "NEBULAR_NATIVE_EXECUTION_OUTPUT_INCOMPLETE"
    if type(exit_code) is int and 0 < exit_code <= 255:
        return "NEBULAR_NATIVE_EXECUTION_EXIT_NONZERO"
    if type(exit_code) is int and -64 <= exit_code < 0:
        return "NEBULAR_NATIVE_EXECUTION_SIGNAL"
    return "NEBULAR_NATIVE_EXECUTION"


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
    python_launcher: str | Path | None = None,
    system_webkit_preflight: Mapping[str, Any] | None = None,
    installed_command: str | Path | None = None,
    system_webkit_context: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Run the released harness for every required scenario on the installed payload."""
    from rs9.nebular071_consumer_core import _nebular_run

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
    system_entrypoint = system_webkit_context is not None
    if (source.is_symlink() or not source.is_dir()
            or harness.is_symlink() or not harness.is_file()
            or not os.access(harness, os.R_OK)):
        fail("NEBULAR_SMOKE_CLOSURE")
    records = prepared.get("records")
    if not isinstance(records, list):
        fail("NEBULAR_SMOKE_CLOSURE")
    record = next((row for row in records if isinstance(row, Mapping)
                   and row.get("path") == f"{prepared.get('tool_root', 'tools')}/native-rc-smoke.mjs"), None)
    if (not isinstance(record, Mapping)
            or sha256(physical_bytes(harness, limit=2 * 1024 * 1024)) != record.get("sha256")):
        fail("NEBULAR_SMOKE_CLOSURE")
    system_probe = None
    installed_harness = None
    darwin_harness = None
    if target == "darwin-arm64":
        harness, darwin_harness = prepare_darwin_harness(prepared)
    if system_webkit_preflight is not None and not system_entrypoint:
        if python_launcher is None:
            fail("NEBULAR_SYSTEM_WEBKIT_PREFLIGHT")
        system_probe = run_system_webkit_preflight(
            python_launcher=python_launcher, env=env, cwd=source, prefix=prefix,
            runner=runner, expected=system_webkit_preflight, timeout=min(timeout, 30),
        )
    if system_entrypoint:
        if (target not in {"linux-arm64-gnu", "linux-x64-gnu"}
                or installed_command is None
                or not isinstance(system_webkit_context, Mapping)):
            fail("NEBULAR_SYSTEM_WEBKIT_PREFLIGHT")
        installed_command = checked_live_path(installed_command, code="NEBULAR_SYSTEM_WEBKIT_PREFLIGHT")
        if (installed_command.is_symlink() or not installed_command.is_file()
                or not os.access(installed_command, os.X_OK)):
            fail("NEBULAR_SYSTEM_WEBKIT_PREFLIGHT")
        provider = system_webkit_context.get("provider")
        if not isinstance(provider, Mapping) or not provider:
            fail("NEBULAR_SYSTEM_WEBKIT_PREFLIGHT")
        from rs9.nebular071_system_webkit import observe_provider, prepare_installed_harness
        if canonical(observe_provider(target)) != canonical(provider):
            fail("NEBULAR_SYSTEM_WEBKIT_PREFLIGHT")
        if (launch_root.parent.name != "payload"
                or launch_root.parent.parent.name != prepared.get("manifest_sha256")
                or launch_root.parent.parent.parent.name != "entries"):
            fail("NEBULAR_SYSTEM_WEBKIT_PREFLIGHT")
        harness, installed_harness = prepare_installed_harness(
            prepared, installed_command, cache_root=launch_root.parents[3],
        )
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
        process_cwd = source
        if target.startswith("linux"):
            command = ["xvfb-run", "-a", "dbus-run-session", "--", *command]
        run_path = scenario_dir / f"{label}.run.json"
        receipt_path = scenario_dir / f"{label}.receipt.json"
        process = _nebular_run(command, env, process_cwd, prefix, timeout, runner=runner)
        if (process.get("exit_code") != 0 or process.get("timed_out")
                or process.get("output_limit_exceeded") or process.get("forced_cleanup")
                or process.get("cleanup_known") is not True or process.get("output_complete") is not True):
            report = None
            try:
                report, _, _ = _json_file(run_path, "failed native smoke run")
            except Exception:
                pass
            try:
                if target == "darwin-arm64":
                    _collect_darwin_spawn_diagnostic(
                        command[0], env=env, cwd=process_cwd, prefix=prefix,
                        runner=runner, evidence=scenario_dir,
                    )
            except Exception:
                pass  # Optional diagnostics cannot mask or admit a failed run.
            fail(_native_execution_failure_code(process, report=report))
        run, run_data, run_sha = _json_file(run_path, "native smoke run")
        receipt, receipt_data, receipt_sha = _json_file(receipt_path, "native smoke receipt")
        checked = validate_installed_receipts(
            run, receipt, target=target, scenario=scenario,
            gui_path=gui["smoke_path"], gui_sha256=gui["sha256"], receipt_sha256=receipt_sha,
            receipt_bytes=receipt_data,
        )
        if system_entrypoint:
            expected_entrypoint = {
                "sha256": installed_harness["entrypoint_sha256"],
                "size": installed_harness["entrypoint_bytes"],
            }
            if run.get("installedEntrypoint") != expected_entrypoint:
                fail("NEBULAR_SYSTEM_WEBKIT_PREFLIGHT")
            if run.get("checks", {}).get("installedEntrypointObserved") is not True:
                fail("NEBULAR_SYSTEM_WEBKIT_PREFLIGHT")
            child_stdout = physical_bytes(scenario_dir / f"{label}.stdout.log", limit=64 * 1024)
            child_stderr = physical_bytes(scenario_dir / f"{label}.stderr.log", limit=64 * 1024)
            child_process = {
                "exit_code": run["exit"]["code"], "signal": run["exit"]["signal"],
                "stdout_bytes": child_stdout, "stderr_bytes": child_stderr,
                "stdout_token": "", "stderr_token": "",
                "stdout_sha256": sha256(child_stdout), "stderr_sha256": sha256(child_stderr),
                "cleanup_known": process["cleanup_known"],
                "output_complete": process["output_complete"],
                "forced_cleanup": process["forced_cleanup"],
            }
            if system_probe is None:
                system_probe = run_system_webkit_preflight(
                    python_launcher=str(installed_command), env=env, cwd=process_cwd,
                    prefix=prefix, runner=runner, context=system_webkit_context,
                    installed_process=child_process, timeout=min(timeout, 30),
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
        if system_entrypoint:
            checked["native_probe"]["entrypoint"] = {
                "command": "installed-tfnf",
                "argv": [f"--nebular-release-smoke={scenario}"],
                "exit_code": child_process["exit_code"],
                "signal": child_process.get("signal"),
                "stdout_sha256": child_process["stdout_sha256"],
                "stderr_sha256": child_process["stderr_sha256"],
            }
        checked_scenarios.append(checked)
    if system_entrypoint and canonical(observe_provider(target)) != canonical(system_webkit_context["provider"]):
        fail("NEBULAR_SYSTEM_WEBKIT_PREFLIGHT")
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
    if system_probe is not None:
        native_probe["system_webkit_preflight"] = system_probe
    if darwin_harness is not None:
        native_probe["darwin_process_harness"] = darwin_harness
    if system_entrypoint:
        native_probe["system_webkit_entrypoint"] = {
            "command": "installed-tfnf",
            "scenarios": list(expected["scenarios"]),
            "argv": [f"--nebular-release-smoke={scenario}" for scenario in expected["scenarios"]],
            "status": "passed",
        }
    return {
        "schema": "rs9.nebular071-installed-native-smoke.v1",
        "status": "pass", "qualification_authority": True,
        "target": target, "source": "raw-archive",
        "scenarios": checked_scenarios,
        "native_probe": native_probe,
        **({"system_webkit_preflight": system_probe} if system_probe is not None else {}),
        **({"installed_launcher_harness": installed_harness} if installed_harness is not None else {}),
        **({"darwin_process_harness": darwin_harness} if darwin_harness is not None else {}),
    }
