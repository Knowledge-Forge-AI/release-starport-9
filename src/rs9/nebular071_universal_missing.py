"""Hosted Bookworm floor proof that the universal launcher refuses without WebKit.

This runs only on the disposable matching public floor runner before its
approved runtime packages are installed. It never removes, hides, or
redirects a library, materializes no payload, and grants no publication
authority. It is its own receipt domain, not the platform-wheel receipt.
"""
from __future__ import annotations

import hashlib
import os
import platform
import re
import stat
import sys
import venv
from collections.abc import Mapping
from pathlib import Path

from rs9 import nebular071_universal_consumer as consumer
from rs9 import wheel_nebular071_universal as builder
from rs9.errors import ContractError
from rs9.materialize import validate_ancestry_not_symlink
from rs9.nebular071_payload import LINUX_TARGETS
from rs9.scratch import canonical


SCHEMA = "rs9.nebular071-universal-missing-runtime.v1"
SONAME = "libwebkit2gtk-4.1.so.0"
PROJECT = "theme-forge-nebular-fusion"
REPOSITORY = "Knowledge-Forge-AI/release-starport-9"
MACHINES = {"linux-arm64-gnu": "aarch64", "linux-x64-gnu": "x86_64"}
VERSION_LINE = "theme-forge-nebular-fusion " + builder.VERSION + "\n"
MISSING_LINE = "TFNF_RUNTIME_MISSING: Run tfnf install-runtime before launching.\n"
WEBKIT_LINE = (
    "TFNF_RUNTIME_WEBKIT: WebKitGTK 4.1 is unavailable; install your "
    "distribution's WebKitGTK 4.1 runtime package first. "
    "Debian/Ubuntu: sudo apt install libwebkit2gtk-4.1-0.\n"
)
# Expected exit code plus exact product stdout/stderr where the launcher
# defines them; pip and probe output are only bounded, not pinned.
PROCESSES = {
    "webkit_unavailable": (2, None, None),
    "install": (0, None, None),
    "help": (0, None, ""),
    "version": (0, VERSION_LINE, ""),
    "cold_launch": (1, "", MISSING_LINE),
    "explicit_setup": (1, "", WEBKIT_LINE),
    "uninstall": (0, None, None),
}
SANDBOX = {"method": "explicit-isolation-prefix", "network_disabled": True}
KEYS = frozenset({
    "schema", "distribution", "status", "target", "source", "run", "wheel",
    "runtime_inputs_sha256", "runtime_index_sha256", "host_class", "host_observation",
    "host_extras", "soname", "sandbox", "processes", "payload_materialized",
    "library_environment_modified", "publication_admitted", "identity",
})
_HEX40 = re.compile(r"[0-9a-f]{40}")
_HEX64 = re.compile(r"[0-9a-f]{64}")


def _fail(code):
    raise ContractError("NEBULAR_UNIVERSAL_MISSING_" + code,
                        "Universal missing-runtime proof does not match")


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _hex64(value):
    return type(value) is str and _HEX64.fullmatch(value) is not None


def _coordinates(target, source, run_id, run_attempt):
    if (type(target) is not str or target not in MACHINES
            or not isinstance(source, Mapping) or set(source) != {"commit", "tree"}
            or any(type(value) is not str or not _HEX40.fullmatch(value)
                   for value in source.values())
            or type(run_id) is not str or not re.fullmatch(r"[1-9][0-9]*", run_id)
            or run_attempt != "1"):
        _fail("CONTEXT")


def _wheel(snapshot, target):
    """Return the snapshot's closed wheel pin and runtime digests."""
    if not isinstance(snapshot, Mapping) or snapshot.get("publication_admitted") is not False:
        _fail("SNAPSHOT")
    wheel = snapshot.get("wheel")
    inputs = snapshot.get("runtime_inputs")
    if (not isinstance(wheel, Mapping)
            or set(wheel) != {"filename", "tag", "version", "size", "sha256"}
            or wheel["filename"] != builder.FILENAME or wheel["tag"] != consumer.TAG
            or wheel["version"] != builder.VERSION or type(wheel["size"]) is not int
            or not 0 < wheel["size"] <= consumer.MAX_WHEEL_BYTES or not _hex64(wheel["sha256"])
            or not _hex64(snapshot.get("runtime_inputs_sha256"))
            or not _hex64(snapshot.get("runtime_index_sha256"))
            or not isinstance(inputs, Mapping) or not isinstance(inputs.get("targets"), Mapping)
            or target not in inputs["targets"]):
        _fail("SNAPSHOT")
    return dict(wheel)


def _host(body, extras, target):
    from rs9.nebular071_host_observation import _validate_extras, validate_observation_body
    try:
        checked = validate_observation_body(body)
        _validate_extras(extras, checked)
    except (ContractError, KeyError, TypeError, ValueError):
        _fail("HOST")
    if (checked["role"] != "floor" or checked["target"] != LINUX_TARGETS[target][0]
            or extras.get("target") != target):
        _fail("HOST")
    return checked


def _tree(root):
    rows = []
    for parent, directories, files in os.walk(root):
        for name in sorted(directories + files):
            rows.append(os.path.relpath(os.path.join(parent, name), root))
    return sorted(rows)


def check_missing_runtime(
    wheel_path: Path, work: Path, *, target: str, source: Mapping[str, str],
    run_id: str, run_attempt: str, prefix: tuple[str, ...], snapshot: Mapping,
) -> dict:
    """Install the admitted universal wheel offline and observe its refusals.

    Source Git commit/tree equality is owned by the frontend; this still
    binds the hosted environment to the given coordinates before effects.
    """
    from rs9.nebular071_host_observation import observe_host
    from rs9.nebular071_consumer_core import _nebular_run

    _coordinates(target, source, run_id, run_attempt)
    if (os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("GITHUB_REPOSITORY") != REPOSITORY
            or os.environ.get("GITHUB_REF") != "refs/heads/main"
            or os.environ.get("GITHUB_RUN_ID") != run_id
            or os.environ.get("GITHUB_RUN_ATTEMPT") != run_attempt
            or os.environ.get("GITHUB_SHA") != source["commit"]
            or platform.system() != "Linux" or platform.machine() != MACHINES[target]):
        _fail("CONTEXT")
    if (not isinstance(prefix, tuple) or not prefix
            or any(type(item) is not str or not item or "\x00" in item for item in prefix)):
        _fail("SANDBOX")
    wheel = _wheel(snapshot, target)
    wheel_path = Path(wheel_path)

    def reverify():
        if wheel_path.name != builder.FILENAME:
            _fail("WHEEL")
        raw = builder._read(wheel_path, consumer.MAX_WHEEL_BYTES)[0]
        if len(raw) != wheel["size"] or _sha(raw) != wheel["sha256"]:
            _fail("WHEEL")
        return validate_ancestry_not_symlink(wheel_path)

    wheel_path = reverify()
    work = validate_ancestry_not_symlink(work)
    if work.exists() or work.is_symlink() or not work.parent.is_dir():
        _fail("WORK")
    host, extras = observe_host("floor")
    _host(host, extras, target)

    work.mkdir(mode=0o700)
    home, temporary = work / "home", work / "tmp"
    home.mkdir(mode=0o700)
    temporary.mkdir(mode=0o700)
    # Only names preserved by the Linux isolation prefix; the launcher's
    # default cache is therefore XDG_CACHE_HOME/rs9/theme-forge-nebular-fusion.
    env = {
        "HOME": str(home), "TMPDIR": str(temporary), "TMP": str(temporary),
        "TEMP": str(temporary), "PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C",
        "PIP_CONFIG_FILE": os.devnull, "PIP_NO_INDEX": "1", "PIP_NO_CACHE_DIR": "1",
        "PIP_DISABLE_PIP_VERSION_CHECK": "1", "PYTHONDONTWRITEBYTECODE": "1",
        "XDG_CACHE_HOME": str(home / ".cache"), "XDG_CONFIG_HOME": str(home / ".config"),
        "XDG_DATA_HOME": str(home / ".local/share"), "XDG_STATE_HOME": str(home / ".local/state"),
    }
    cache = home / ".cache"
    processes = {}

    def execute(label, argv):
        expected, stdout, stderr = PROCESSES[label]
        # Every step, including explicit setup, keeps the network-denial
        # prefix: WebKit must be refused before any download is attempted.
        result = _nebular_run(argv, env, work, prefix, 60)
        if (not isinstance(result, Mapping) or not consumer.PROCESS_FIELDS.issubset(result)
                or type(result.get("exit_code")) is not int or result["exit_code"] != expected
                or result.get("signal") is not None or result.get("timed_out") is not False
                or result.get("output_limit_exceeded") is not False
                or result.get("forced_cleanup") is not False
                or result.get("cleanup_known") is not True or result.get("output_complete") is not True
                or type(result.get("stdout_token")) is not str
                or type(result.get("stderr_token")) is not str
                or (stdout is not None and (result["stdout_token"] != stdout
                                            or result["stdout_sha256"] != _sha(stdout.encode())))
                or (stderr is not None and (result["stderr_token"] != stderr
                                            or result["stderr_sha256"] != _sha(stderr.encode())))
                or "Traceback" in result["stderr_token"]):
            _fail("PROCESS")
        processes[label] = consumer._public_process(result)
        return result

    # Observe actual unavailability without altering the loader environment.
    execute("webkit_unavailable", [
        sys.executable, "-I", "-c",
        "import ctypes\ntry: ctypes.CDLL(%r)\nexcept OSError: raise SystemExit(2)" % SONAME])
    venv_root = work / "venv"
    venv.EnvBuilder(with_pip=True).create(venv_root)
    python = venv_root / "bin/python"
    execute("install", [str(python), "-I", "-m", "pip", "install", "--no-index", "--no-deps",
                        "--no-compile", "--only-binary=:all:", str(reverify())])
    command = venv_root / "bin/tfnf"
    info = command.lstat() if command.exists() or command.is_symlink() else None
    if info is None or not stat.S_ISREG(info.st_mode) or not info.st_mode & 0o111:
        _fail("ENTRYPOINT")
    before = _tree(home)
    if not execute("help", [str(command), "--help"])["stdout_token"].startswith("Usage: tfnf "):
        _fail("PROCESS")
    execute("version", [str(command), "--version"])
    execute("cold_launch", [str(command)])
    execute("explicit_setup", [str(command), "install-runtime", "--json"])
    if cache.exists() or cache.is_symlink() or _tree(home) != before:
        _fail("PAYLOAD")
    execute("uninstall", [str(python), "-I", "-m", "pip", "uninstall", "--yes", PROJECT])
    if command.exists() or command.is_symlink():
        _fail("UNINSTALL")
    unsigned = {
        "schema": SCHEMA, "distribution": consumer.DISTRIBUTION, "status": "passed",
        "target": target, "source": dict(source), "run": {"id": run_id, "attempt": run_attempt},
        "wheel": wheel, "runtime_inputs_sha256": snapshot["runtime_inputs_sha256"],
        "runtime_index_sha256": snapshot["runtime_index_sha256"],
        "host_class": "bookworm-floor", "host_observation": dict(host), "host_extras": dict(extras),
        "soname": SONAME, "sandbox": dict(SANDBOX), "processes": processes,
        "payload_materialized": False, "library_environment_modified": False,
        "publication_admitted": False,
    }
    result = {**unsigned, "identity": _sha(canonical(unsigned))}
    return validate_missing_runtime(
        result, target=target, source=source, run_id=run_id, run_attempt=run_attempt,
        snapshot=snapshot, host_identity=host["identity"])


def validate_missing_runtime(
    value: Mapping, *, target: str, source: Mapping[str, str], run_id: str,
    run_attempt: str, snapshot: Mapping, host_identity: str,
) -> dict:
    """Join a floor refusal to the admitted wheel and later positive floor host."""
    _coordinates(target, source, run_id, run_attempt)
    wheel = _wheel(snapshot, target)
    if not _hex64(host_identity):
        _fail("HOST")
    if (not isinstance(value, Mapping) or set(value) != KEYS
            or value["schema"] != SCHEMA or value["distribution"] != consumer.DISTRIBUTION
            or value["status"] != "passed" or value["target"] != target
            or value["source"] != dict(source)
            or value["run"] != {"id": run_id, "attempt": run_attempt}
            or value["host_class"] != "bookworm-floor" or value["soname"] != SONAME
            or value["payload_materialized"] is not False
            or value["library_environment_modified"] is not False
            or value["publication_admitted"] is not False):
        _fail("RECEIPT")
    found = value["wheel"]
    if (not isinstance(found, Mapping) or found != wheel
            or any(type(found[key]) is not type(wheel[key]) for key in wheel)
            or value["runtime_inputs_sha256"] != snapshot["runtime_inputs_sha256"]
            or value["runtime_index_sha256"] != snapshot["runtime_index_sha256"]):
        _fail("BINDING")
    sandbox = value["sandbox"]
    if (not isinstance(sandbox, Mapping) or set(sandbox) != set(SANDBOX)
            or sandbox["method"] != SANDBOX["method"] or sandbox["network_disabled"] is not True):
        _fail("SANDBOX")
    body = _host(value["host_observation"], value["host_extras"], target)
    if body["identity"] != host_identity:
        _fail("HOST")
    processes = value["processes"]
    if not isinstance(processes, Mapping) or set(processes) != set(PROCESSES):
        _fail("PROCESS")
    for label, (expected, stdout, stderr) in PROCESSES.items():
        process = processes[label]
        if (not isinstance(process, Mapping) or set(process) != consumer.PROCESS_FIELDS
                or type(process["exit_code"]) is not int or process["exit_code"] != expected
                or process["signal"] is not None or process["timed_out"] is not False
                or process["output_limit_exceeded"] is not False
                or process["cleanup_known"] is not True or process["output_complete"] is not True
                or process["forced_cleanup"] is not False
                or type(process["duration_ms"]) is not int or process["duration_ms"] < 0
                or not _hex64(process["stdout_sha256"]) or not _hex64(process["stderr_sha256"])
                or (stdout is not None and process["stdout_sha256"] != _sha(stdout.encode()))
                or (stderr is not None and process["stderr_sha256"] != _sha(stderr.encode()))):
            _fail("PROCESS")
    unsigned = {key: item for key, item in value.items() if key != "identity"}
    if not _hex64(value["identity"]) or value["identity"] != _sha(canonical(unsigned)):
        _fail("IDENTITY")
    return dict(value)
