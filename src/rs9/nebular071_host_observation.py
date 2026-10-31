"""Actual Linux host observations for the Nebular 0.7.1 Stage-A boundary.

This module observes only the current Linux host.  It does not inspect wheels,
payloads, containers, images, or release state, and it never claims a Stage-B
release result.  The production CLI has fixed public-system probe inputs;
tests may inject a bounded synthetic command runner, but such results cannot
be written as actual evidence.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
from collections.abc import Callable, Mapping
from typing import Any

from rs9.bounded_process import run_bounded
from rs9.errors import ContractError
from rs9.nebular071_manylinux import HOST_FLOOR_SCHEMA, LINUX_TARGETS, _digest
from rs9.scratch import canonical


ROLE_FLOOR = "floor"
ROLE_NEWER = "newer"
ROLES = frozenset((ROLE_FLOOR, ROLE_NEWER))
MAX_PROBE_SECONDS = 5
MAX_PROBE_BYTES = 64 * 1024
READELF = "/usr/bin/readelf"
LDD = "/usr/bin/ldd"
PROC_ROOT = "/proc"
_VERSION = re.compile(r"(?<!\d)(\d+)\.(\d+)(?!\d)")
# Tool banners carry distribution package revisions such as "2.39-0ubuntu8.4";
# only a standalone major.minor token is a glibc version candidate.
_BANNER_VERSION = re.compile(r"(?<![\w.+])(\d+)\.(\d+)(?![\w+]|\.\d)")
_FORBIDDEN_COMPONENTS = frozenset({"db", "raw", ".serena"})
_FORBIDDEN_SUFFIXES = (".db", ".raw", ".sqlite", ".sqlite3", ".wal", ".shm", ".journal")
_SYSTEM_ROOTS = ("/lib/", "/lib64/", "/usr/lib/", "/usr/lib64/")


class HostObservationError(ContractError):
    """Stable, path-free failure for host observation and output."""


def _fail(code: str, message: str) -> None:
    raise HostObservationError(code, message)


def _role(role: str) -> str:
    if type(role) is not str or role not in ROLES:
        _fail("NEBULAR_HOST_ROLE", "A floor or newer host role is required")
    return role


def _target(system: str, machine: str) -> tuple[str, str, str]:
    if system != "Linux":
        _fail("NEBULAR_HOST_PLATFORM", "A Linux host is required")
    if type(machine) is not str:
        _fail("NEBULAR_HOST_ARCHITECTURE", "The host architecture is unavailable")
    key = machine.lower()
    if key in {"aarch64", "arm64"}:
        return "linux-arm64-gnu", LINUX_TARGETS["linux-arm64-gnu"][0], "aarch64"
    if key in {"x86_64", "amd64"}:
        return "linux-x64-gnu", LINUX_TARGETS["linux-x64-gnu"][0], "x86_64"
    _fail("NEBULAR_HOST_ARCHITECTURE", "The host architecture is outside the reviewed Linux targets")


def _version(value: Any, label: str) -> str:
    if type(value) is not str or _VERSION.fullmatch(value) is None:
        _fail("NEBULAR_HOST_GLIBC", f"{label} did not provide a major.minor glibc version")
    return value


def _version_tuple(value: str) -> tuple[int, int]:
    match = _VERSION.fullmatch(value)
    if match is None:  # pragma: no cover - guarded by _version
        _fail("NEBULAR_HOST_GLIBC", "The glibc version is malformed")
    return int(match.group(1)), int(match.group(2))


def _python_glibc_version() -> str:
    """Read the version exported by the libc loaded into this Python process."""
    try:
        libc = ctypes.CDLL(None)
        function = libc.gnu_get_libc_version
        function.restype = ctypes.c_char_p
        raw = function()
    except (AttributeError, OSError):
        _fail("NEBULAR_HOST_GLIBC", "The current Python process has no readable glibc probe")
    if not isinstance(raw, bytes):
        _fail("NEBULAR_HOST_GLIBC", "The current Python glibc probe returned no version")
    try:
        return _version(raw.decode("ascii"), "Python libc")
    except UnicodeDecodeError:
        _fail("NEBULAR_HOST_GLIBC", "The current Python glibc probe was not ASCII")


def _platform_glibc_version() -> tuple[str, str]:
    try:
        name, value = platform.libc_ver()
    except (OSError, RuntimeError):
        _fail("NEBULAR_HOST_GLIBC", "The platform libc probe failed")
    if type(name) is not str or name.lower() != "glibc":
        _fail("NEBULAR_HOST_GLIBC", "The current host is not identified as glibc")
    return name.lower(), _version(value, "platform libc")


def _public_probe_path(path: str) -> str:
    if (not isinstance(path, str) or not path.startswith(_SYSTEM_ROOTS)
            or "\x00" in path or "\\" in path or "/../" in path
            or any(part.lower() in _FORBIDDEN_COMPONENTS for part in Path(path).parts)
            or any(part.lower().endswith(_FORBIDDEN_SUFFIXES) for part in Path(path).parts)):
        _fail("NEBULAR_HOST_LOADER", "The observed loader is outside the public system roots")
    return path


def _tool_result(
    argv: list[str],
    result: Any,
    *,
    synthetic: bool,
) -> tuple[bytes, bytes, dict[str, Any]]:
    stdout = getattr(result, "stdout", None)
    stderr = getattr(result, "stderr", None)
    returncode = getattr(result, "returncode", None)
    if not isinstance(stdout, (bytes, bytearray)) or not isinstance(stderr, (bytes, bytearray)):
        _fail("NEBULAR_HOST_PROBE", "The bounded host probe returned invalid streams")
    stdout = bytes(stdout)
    stderr = bytes(stderr)
    if type(returncode) is not int:
        _fail("NEBULAR_HOST_PROBE", "The bounded host probe did not return an exit code")
    if returncode != 0:
        _fail("NEBULAR_HOST_PROBE", "The bounded host probe failed")
    if len(stdout) > MAX_PROBE_BYTES or len(stderr) > MAX_PROBE_BYTES:
        _fail("NEBULAR_HOST_PROBE", "The bounded host probe exceeded its stream limit")
    return stdout, stderr, {
        "tool": Path(argv[0]).name,
        "args": argv[1:],
        "frame": "synthetic-test-runner" if synthetic else "same-process-linux-host",
        "termination": "exited",
        "reaped": True,
        "cleanup": "not-needed",
        "returncode": returncode,
        "stdout": {"bytes": len(stdout), "sha256": hashlib.sha256(stdout).hexdigest()},
        "stderr": {"bytes": len(stderr), "sha256": hashlib.sha256(stderr).hexdigest()},
    }


def _bounded_tool(argv: list[str]) -> tuple[bytes, bytes, dict[str, Any]]:
    env = {"LC_ALL": "C", "LANG": "C", "PATH": "/usr/bin:/bin"}
    result = run_bounded(argv, env=env, timeout=MAX_PROBE_SECONDS, limit=MAX_PROBE_BYTES)
    if result.termination != "exited" or not result.reaped or result.returncode != 0:
        _fail("NEBULAR_HOST_PROBE", "The bounded host probe did not complete successfully")
    completed = result.diagnostic_result()
    stdout, stderr, proof = _tool_result(argv, completed, synthetic=False)
    proof["custody"] = result.custody()
    return stdout, stderr, proof


def _run_probe(
    argv: list[str],
    command_runner: Callable[[list[str]], Any] | None,
) -> tuple[bytes, bytes, dict[str, Any]]:
    if command_runner is None:
        return _bounded_tool(argv)
    result = command_runner(list(argv))
    return _tool_result(argv, result, synthetic=True)


def _parse_versions(stdout: bytes, stderr: bytes, label: str) -> str:
    try:
        text = (stdout + b"\n" + stderr).decode("ascii")
    except UnicodeDecodeError:
        _fail("NEBULAR_HOST_GLIBC", f"The {label} version output was not ASCII")
    matches = set(_BANNER_VERSION.findall(text))
    if not matches:
        _fail("NEBULAR_HOST_GLIBC", f"The {label} probe contained no glibc version")
    if len(matches) != 1:
        _fail("NEBULAR_HOST_GLIBC", f"The {label} probe contained ambiguous versions")
    major, minor = next(iter(matches))
    return _version(f"{major}.{minor}", label)


def _parse_readelf(stdout: bytes, stderr: bytes, expected_arch: str) -> str:
    try:
        text = (stdout + b"\n" + stderr).decode("ascii")
    except UnicodeDecodeError:
        _fail("NEBULAR_HOST_LOADER", "The ELF probe output was not ASCII")
    machines = re.findall(r"^\s*Machine:\s*(.+?)\s*$", text, re.MULTILINE)
    interpreters = re.findall(r"\[Requesting program interpreter:\s*([^\]\s]+)\]", text)
    if len(machines) != 1 or len(interpreters) != 1:
        _fail("NEBULAR_HOST_LOADER", "The ELF probe did not identify one machine and loader")
    expected_machines = {
        "aarch64": {"AArch64"},
        "x86_64": {"Advanced Micro Devices X86-64", "X86-64"},
    }[expected_arch]
    if machines[0] not in expected_machines:
        _fail("NEBULAR_HOST_ARCHITECTURE", "The ELF machine disagrees with the host architecture")
    loader = _public_probe_path(interpreters[0])
    expected_loader = {
        "aarch64": "ld-linux-aarch64.so.1",
        "x86_64": "ld-linux-x86-64.so.2",
    }[expected_arch]
    if Path(loader).name != expected_loader:
        _fail("NEBULAR_HOST_LOADER", "The ELF loader disagrees with the host architecture")
    return loader


def validate_observation_body(body: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the exact existing host-observation body and its identity."""
    required = {"schema", "target", "role", "status", "glibc", "loader", "identity"}
    if not isinstance(body, Mapping) or set(body) != required:
        _fail("NEBULAR_HOST_BODY", "Host observation fields are not closed")
    checked = dict(body)
    if checked["schema"] != HOST_FLOOR_SCHEMA or checked["target"] not in {
        LINUX_TARGETS[key][0] for key in LINUX_TARGETS
    } or checked["role"] not in ROLES or checked["status"] != "observed":
        _fail("NEBULAR_HOST_BODY", "Host observation identity is malformed")
    glibc = _version(checked["glibc"], "host")
    version = _version_tuple(glibc)
    if checked["role"] == ROLE_FLOOR and version != (2, 36):
        _fail("NEBULAR_HOST_FLOOR", "A floor observation must be glibc 2.36")
    if checked["role"] == ROLE_NEWER and version <= (2, 36):
        _fail("NEBULAR_HOST_FLOOR", "A newer observation must exceed glibc 2.36")
    _public_probe_path(checked["loader"])
    unsigned = dict(checked)
    identity = unsigned.pop("identity")
    if type(identity) is not str or not re.fullmatch(r"[0-9a-f]{64}", identity) or identity != _digest(unsigned):
        _fail("NEBULAR_HOST_BODY", "Host observation identity does not match its body")
    return checked


def _observer_executable() -> str:
    pid = os.getpid()
    if type(pid) is not int or pid <= 0:
        _fail("NEBULAR_HOST_PROBE", "The observer process identity is unavailable")
    return f"{PROC_ROOT}/{pid}/exe"


def _platform_context(
    python_probe: Callable[[], str],
    platform_probe: Callable[[], tuple[str, str]],
) -> tuple[dict[str, str], dict[str, str]]:
    target, triple, expected_arch = _target(platform.system(), platform.machine())
    python_version = _version(python_probe(), "Python libc")
    platform_name, platform_version = platform_probe()
    if platform_name != "glibc":
        _fail("NEBULAR_HOST_GLIBC", "The platform libc probe did not identify glibc")
    context = {"target": target, "triple": triple, "arch": expected_arch}
    versions = {"python_libc": python_version, "platform_libc": _version(platform_version, "platform libc")}
    return context, versions


def _loader_observation(
    context: Mapping[str, str], command_runner: Callable[[list[str]], Any] | None,
) -> tuple[str, dict[str, Any]]:
    stdout, stderr, proof = _run_probe(
        [READELF, "-h", "-l", "--wide", _observer_executable()], command_runner
    )
    return _parse_readelf(stdout, stderr, context["arch"]), proof


def _glibc_observations(
    loader: str, command_runner: Callable[[list[str]], Any] | None,
) -> tuple[dict[str, str], list[dict[str, Any]]]:
    ldd_stdout, ldd_stderr, ldd_proof = _run_probe([LDD, "--version"], command_runner)
    loader_stdout, loader_stderr, loader_proof = _run_probe([loader, "--version"], command_runner)
    versions = {
        "ldd": _parse_versions(ldd_stdout, ldd_stderr, "ldd"),
        "loader": _parse_versions(loader_stdout, loader_stderr, "loader"),
    }
    return versions, [ldd_proof, loader_proof]


def _observed_body(
    role: str, context: Mapping[str, str], loader: str, versions: Mapping[str, str],
) -> dict[str, Any]:
    observed = set(versions.values())
    if len(observed) != 1:
        _fail("NEBULAR_HOST_GLIBC", "The Python, platform, ldd, and loader versions disagree")
    unsigned = {
        "schema": HOST_FLOOR_SCHEMA,
        "target": context["triple"],
        "role": role,
        "status": "observed",
        "glibc": next(iter(observed)),
        "loader": loader,
    }
    body = {**unsigned, "identity": _digest(unsigned)}
    return validate_observation_body(body)


def _observation_sidecar(
    role: str, context: Mapping[str, str], versions: Mapping[str, str],
    proofs: list[dict[str, Any]], body: Mapping[str, Any], synthetic: bool,
) -> dict[str, Any]:
    return {
        "schema": "rs9.nebular071-host-observation-extras.v1",
        "evidence_mode": "synthetic" if synthetic else "actual",
        "target": context["target"],
        "role": role,
        "frame": "synthetic-test-inputs" if synthetic else "same-process-linux-host",
        "platform": {"system": "Linux", "machine": context["arch"]},
        "cross_checks": dict(versions),
        "probes": proofs,
        "body_identity": body["identity"],
    }


def observe_host(
    role: str,
    *,
    command_runner: Callable[[list[str]], Any] | None = None,
    python_libc_probe: Callable[[], str] | None = None,
    platform_libc_probe: Callable[[], tuple[str, str]] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Observe the current Linux host and return body plus private probe proof.

    Injected probes are test-only evidence and are marked synthetic in the
    sidecar.  ``write_observation`` refuses to write such a sidecar.
    """
    role = _role(role)
    python_probe = python_libc_probe or _python_glibc_version
    platform_probe = platform_libc_probe or _platform_glibc_version
    context, versions = _platform_context(python_probe, platform_probe)
    loader, readelf_proof = _loader_observation(context, command_runner)
    tool_versions, tool_proofs = _glibc_observations(loader, command_runner)
    versions.update(tool_versions)
    body = _observed_body(role, context, loader, versions)
    synthetic = command_runner is not None or python_libc_probe is not None or platform_libc_probe is not None
    sidecar = _observation_sidecar(role, context, versions, [readelf_proof, *tool_proofs], body, synthetic)
    return body, sidecar


def _safe_output_path(value: str | Path) -> Path:
    path = Path(value)
    if not path.is_absolute() or "\x00" in str(path) or path.name in {"", ".", ".."}:
        _fail("NEBULAR_HOST_OUTPUT", "An absolute output path is required")
    for part in path.parts:
        lower = part.lower()
        if lower in _FORBIDDEN_COMPONENTS or lower.endswith(_FORBIDDEN_SUFFIXES):
            _fail("NEBULAR_HOST_OUTPUT", "Protected output path refused")
    if path.exists() or path.is_symlink():
        _fail("NEBULAR_HOST_OUTPUT", "Output already exists")
    current = path.parent
    while True:
        if current.is_symlink() or not current.is_dir():
            _fail("NEBULAR_HOST_OUTPUT", "Output ancestry is not a physical directory")
        if current.parent == current:
            break
        current = current.parent
    return path


def _output_stamp(path: Path) -> tuple[int, ...]:
    value = path.lstat()
    return (value.st_dev, value.st_ino, value.st_size, value.st_mode,
            value.st_mtime_ns, value.st_ctime_ns, value.st_uid,
            value.st_gid, value.st_nlink)


def _remove_owned_output(path: Path, stamp: tuple[int, ...]) -> None:
    try:
        if _output_stamp(path) == stamp:
            path.unlink()
    except FileNotFoundError:
        pass


def _write_exclusive(path: Path, data: bytes) -> tuple[int, ...]:
    import tempfile

    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(name)
    created = os.fstat(descriptor)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        temporary_stamp = _output_stamp(temporary)
        if temporary_stamp[:2] != (created.st_dev, created.st_ino):
            _fail("NEBULAR_HOST_OUTPUT", "Temporary output identity changed")
        os.link(temporary, path, follow_symlinks=False)
    except OSError:
        _fail("NEBULAR_HOST_OUTPUT", "Exclusive output write failed")
    finally:
        # mkstemp created this exact name; never remove a replacement inode.
        try:
            current = temporary.lstat()
            if (current.st_dev, current.st_ino) == (created.st_dev, created.st_ino):
                temporary.unlink()
        except FileNotFoundError:
            pass
    parent = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(parent)
    finally:
        os.close(parent)
    return _output_stamp(path)


def _validate_extras(extras: Mapping[str, Any], body: Mapping[str, Any]) -> None:
    required = {
        "schema", "evidence_mode", "target", "role", "frame", "platform",
        "cross_checks", "probes", "body_identity",
    }
    if not isinstance(extras, Mapping) or set(extras) != required \
            or extras.get("schema") != "rs9.nebular071-host-observation-extras.v1" \
            or extras.get("evidence_mode") != "actual" \
            or extras.get("frame") != "same-process-linux-host" \
            or extras.get("body_identity") != body["identity"] \
            or extras.get("role") != body["role"]:
        _fail("NEBULAR_HOST_OUTPUT", "Host probe sidecar is not the closed actual envelope")
    targets = {key: LINUX_TARGETS[key][0] for key in LINUX_TARGETS}
    target = extras.get("target")
    if target not in targets or targets[target] != body["target"]:
        _fail("NEBULAR_HOST_OUTPUT", "Host probe sidecar target does not join its body")
    expected_arch = "aarch64" if target == "linux-arm64-gnu" else "x86_64"
    if extras.get("platform") != {"system": "Linux", "machine": expected_arch}:
        _fail("NEBULAR_HOST_OUTPUT", "Host probe sidecar platform does not join its body")
    checks = extras.get("cross_checks")
    if not isinstance(checks, Mapping) or set(checks) != {"python_libc", "platform_libc", "ldd", "loader"} \
            or any(checks[key] != body["glibc"] for key in checks):
        _fail("NEBULAR_HOST_OUTPUT", "Host probe sidecar cross-checks do not join its body")
    probes = extras.get("probes")
    if not isinstance(probes, list) or len(probes) != 3:
        _fail("NEBULAR_HOST_OUTPUT", "Host probe sidecar tool proof is incomplete")
    expected_tools = ("readelf", "ldd", Path(body["loader"]).name)
    for probe, expected_tool in zip(probes, expected_tools):
        if not isinstance(probe, Mapping) or set(probe) != {
            "tool", "args", "frame", "termination", "reaped", "cleanup", "returncode",
            "stdout", "stderr", "custody",
        } or probe.get("tool") != expected_tool or probe.get("frame") != "same-process-linux-host" \
                or probe.get("termination") != "exited" or probe.get("reaped") is not True \
                or probe.get("cleanup") != "not-needed" or probe.get("returncode") != 0:
            _fail("NEBULAR_HOST_OUTPUT", "Host probe sidecar tool proof is malformed")
        if not isinstance(probe.get("args"), list) or any(
            type(value) is not str or not value or "\x00" in value for value in probe["args"]
        ):
            _fail("NEBULAR_HOST_OUTPUT", "Host probe sidecar arguments are malformed")
        for stream_name in ("stdout", "stderr"):
            stream = probe.get(stream_name)
            if not isinstance(stream, Mapping) or set(stream) != {"bytes", "sha256"} \
                    or type(stream["bytes"]) is not int or not 0 <= stream["bytes"] <= MAX_PROBE_BYTES \
                    or not isinstance(stream["sha256"], str) \
                    or re.fullmatch(r"[0-9a-f]{64}", stream["sha256"]) is None:
                _fail("NEBULAR_HOST_OUTPUT", "Host probe sidecar stream proof is malformed")
        custody = probe.get("custody")
        if not isinstance(custody, Mapping) or custody.get("termination") != "exited" \
                or custody.get("reaped") is not True or custody.get("cleanup") != "not-needed":
            _fail("NEBULAR_HOST_OUTPUT", "Host probe sidecar cleanup proof is incomplete")


def _write_observation(
    body_path: str | Path,
    extras_path: str | Path,
    body: Mapping[str, Any],
    extras: Mapping[str, Any],
) -> None:
    """Serialize producer-owned observations; capture_observation owns admission."""
    checked = validate_observation_body(body)
    _validate_extras(extras, checked)
    target = _safe_output_path(body_path)
    sidecar = _safe_output_path(extras_path)
    if target == sidecar:
        _fail("NEBULAR_HOST_OUTPUT", "Body and sidecar outputs must differ")
    body_bytes = canonical(checked, validate=True)
    extras_bytes = canonical(dict(extras), validate=True)
    sidecar_stamp = None
    try:
        sidecar_stamp = _write_exclusive(sidecar, extras_bytes)
        _write_exclusive(target, body_bytes)
    except Exception:
        if sidecar_stamp is not None:
            _remove_owned_output(sidecar, sidecar_stamp)
        raise


def capture_observation(role: str, body_path: str | Path, extras_path: str | Path) -> None:
    """Capture and persist actual observations through the production entry point.

    The private serializer is not an authentication boundary. Production capture
    accepts no caller-supplied body, sidecar, or injected observation probes.
    """
    body, extras = observe_host(role)
    _write_observation(body_path, extras_path, body, extras)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Observe the actual Linux host for Nebular 0.7.1")
    parser.add_argument("--role", choices=sorted(ROLES), required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--extras", required=True)
    args = parser.parse_args(argv)
    try:
        capture_observation(args.role, args.output, args.extras)
    except ContractError as error:
        print(str(error), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
