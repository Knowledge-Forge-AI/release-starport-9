"""Experimental Linux PRoot runtime: pinned guest-only invocation and falsifiable probes.

PRoot is an execution-compatibility hypothesis for unprivileged Linux hosts. It is
not an isolation boundary and never an application qualification: every result here
is diagnostic, application_qualified and qualification_authority stay false, and no
pass is derived from missing or unobservable evidence.

Known measurement limits, recorded rather than papered over:
- A released ELF cannot report its own /proc/self/exe without modifying release bytes or
  preloading code, so executable-self is read back by a sibling guest process from /proc/<pid>.
- The WebKit sandbox state is read from the actual descendant tree of the released launcher under
  Xvfb and a D-Bus session; if no WebKitWebProcess appears, or none runs under bwrap, the gate
  fails. The experiment never sets or removes a sandbox override.
- PRoot shares the host PID namespace and /proc, so it is not an isolation boundary.
- A signal death in the guest must be reflected in the wrapper's own status, and an external
  SIGTERM must end the wrapper and the whole guest tree; whether the guest handler ran is recorded.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import signal
import subprocess
import time
import tempfile
from typing import Any, Callable, NamedTuple

from rs9.errors import ContractError, safe_details

SCHEMA = "rs9.nix-proot-evaluation.v2"
FACTS_SCHEMA = "rs9.nix-proot-facts.v2"
MAX_OUTPUT = 1024 * 1024
MAX_CLOSURE = 4096
MAX_ELFS = 512

# Pinned nixpkgs PRoot recipe (existing nixpkgs derivation; not vendored here).
PROOT_VERSION = "5.4.0"
PROOT_NIXPKGS_REVISION = "0921fdb3e13e40fe25fbc52b89661a9d6d32ac68"
PROOT_RECIPE_BLOB = "02766094fbf82ab7ee4425a14d480f061cbcdadc"
PROOT_SOURCE_HASH = "sha256-Z9Y7ccWp5KEVuo9xfHcgo58XqYVdFo7ck1jH7cnT2KA="
PROOT_FILE_PATH = "pkgs/by-name/pr/proot/package.nix"

INTERPRETERS = {
    "x86_64-linux": ("/lib64/ld-linux-x86-64.so.2", "ld-linux-x86-64.so.2"),
    "aarch64-linux": ("/lib/ld-linux-aarch64.so.1", "ld-linux-aarch64.so.1"),
}
STORE_FACTS = ("proot", "proot_recipe_file", "guest_root", "guest_env", "guest_path", "closure_paths_file",
               "loader", "glibc_lib", "env", "sh", "python", "node", "readelf", "ldd", "xvfb_run",
               "dbus_run_session", "bwrap", "launcher")
HOST_ONLY_FACTS = frozenset({"proot", "proot_recipe_file", "guest_root", "closure_paths_file"})
SCALAR_FACTS = ("schema", "system", "proot_version", "proot_nixpkgs_rev", "proot_recipe_blob",
                "proot_source_hash", "foreign_interpreter")
REQUIRED_FACT_KEYS = frozenset({*STORE_FACTS, *SCALAR_FACTS, "library_path", "guest_environment"})
GUEST_ENVIRONMENT_KEYS = frozenset({"PATH", "LD_LIBRARY_PATH", "FONTCONFIG_FILE", "GIO_EXTRA_MODULES",
                                    "GDK_PIXBUF_MODULE_FILE", "XDG_DATA_DIRS"})
SANDBOX_DISABLING = ("WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS", "WEBKIT_FORCE_SANDBOX")
FORBIDDEN_BIND_SOURCES = frozenset({
    "/", "/etc", "/tmp", "/nix", "/nix/store", "/usr", "/var", "/home", "/run", "/lib", "/lib64", "/bin",
    "/sbin", "/root", "/proc", "/dev", "/sys", "/opt", "/srv", "/mnt", "/boot"})
GUEST_DEVICES = ("/dev/null", "/dev/zero", "/dev/full", "/dev/random", "/dev/urandom", "/dev/tty", "/dev/shm")
DENIAL_ERRNOS = frozenset({errno.ENETUNREACH, errno.EHOSTUNREACH, errno.EPERM, errno.EACCES, errno.EAFNOSUPPORT})
GATES = ("proot-pinned-derivation", "proot-no-userns-ptrace", "proot-executable-self",
         "proot-descendant-interpreter", "proot-closure-resolution", "proot-args-exit-signals",
         "proot-in-guest-offline", "proot-webkit-sandbox-state", "proot-verifier-smoke")

_STORE = re.compile(r"/nix/store/[0-9a-df-np-sv-z]{32}-[A-Za-z0-9+._?=-]+(?:/[A-Za-z0-9+._?=@~-]+)*")
_STORE_TOP = re.compile(r"/nix/store/[0-9a-df-np-sv-z]{32}-[A-Za-z0-9+._?=-]+")
_GUEST_SENTINELS = ("/etc/os-release", "/etc/ld.so.cache", "/lib/x86_64-linux-gnu", "/lib/aarch64-linux-gnu",
                    "/usr/lib", "/usr/share", "/var/lib/dpkg")
_GUEST_ETC = frozenset({"passwd", "group", "nsswitch.conf", "hosts"})


def verify_pinned_proot(content: bytes | str | Path) -> dict[str, Any]:
    """Verify that PRoot recipe bytes match the exact pinned Git blob and source hash."""
    if isinstance(content, Path):
        data = content.read_bytes()
    elif isinstance(content, str):
        data = content.encode("utf-8")
    else:
        data = content

    header = f"blob {len(data)}\0".encode("ascii")
    blob_sha1 = hashlib.sha1(header + data).hexdigest()
    if blob_sha1 != PROOT_RECIPE_BLOB:
        raise ContractError(
            "PROOT_BLOB_MISMATCH",
            f"PRoot recipe blob {blob_sha1} does not match expected {PROOT_RECIPE_BLOB}",
            details={"actual_blob": blob_sha1, "expected_blob": PROOT_RECIPE_BLOB},
        )

    text = data.decode("utf-8", errors="replace")
    if PROOT_SOURCE_HASH not in text:
        raise ContractError(
            "PROOT_SOURCE_HASH_MISMATCH",
            "PRoot recipe does not contain expected recursive source hash",
            details={"expected_source_hash": PROOT_SOURCE_HASH},
        )
    if f'version = "{PROOT_VERSION}"' not in text:
        raise ContractError(
            "PROOT_VERSION_MISMATCH",
            f"PRoot recipe does not declare version {PROOT_VERSION}",
            details={"expected_version": PROOT_VERSION},
        )

    return {
        "status": "verified",
        "version": PROOT_VERSION,
        "nixpkgs_revision": PROOT_NIXPKGS_REVISION,
        "git_blob": blob_sha1,
        "source_hash": PROOT_SOURCE_HASH,
        "upstream_tag": "v5.4.0", "license": "GPL-2.0-or-later", "derivation_do_check": False,
    }


def _store_path(value: Any, key: str) -> str:
    if not isinstance(value, str) or "\x00" in value or not _STORE.fullmatch(value) or ".." in value.split("/"):
        raise ContractError("NIX_PROOT_FACTS", f"Store-backed path required for {key}")
    return value


def _top(path: str) -> str:
    return "/".join(path.split("/")[:4])


def validate_proot_facts(facts: dict[str, Any]) -> dict[str, Any]:
    """Validate closed pinned PRoot runtime facts emitted by the experimental Nix recipe."""
    if not isinstance(facts, dict) or set(facts) != REQUIRED_FACT_KEYS:
        raise ContractError("NIX_PROOT_FACTS", "Closed pinned PRoot facts required")
    for key in SCALAR_FACTS:
        value = facts[key]
        if not isinstance(value, str) or not value or "\x00" in value:
            raise ContractError("NIX_PROOT_FACTS", f"Invalid scalar fact {key}")
    if facts["schema"] != FACTS_SCHEMA:
        raise ContractError("NIX_PROOT_FACTS", "Unsupported PRoot facts schema")
    if facts["system"] not in INTERPRETERS:
        raise ContractError("NIX_PROOT_FACTS", "Unsupported PRoot system")
    for key in STORE_FACTS:
        _store_path(facts[key], key)

    for key, expected in (("proot_version", PROOT_VERSION), ("proot_nixpkgs_rev", PROOT_NIXPKGS_REVISION),
                          ("proot_recipe_blob", PROOT_RECIPE_BLOB), ("proot_source_hash", PROOT_SOURCE_HASH)):
        if facts[key] != expected:
            raise ContractError("NIX_PROOT_FACTS", f"PRoot pin mismatch in facts: {key}")

    interpreter, loader_name = INTERPRETERS[facts["system"]]
    if facts["foreign_interpreter"] != interpreter:
        raise ContractError("NIX_PROOT_FACTS", "Foreign interpreter path must match the system")
    if not isinstance(facts["library_path"], str):
        raise ContractError("NIX_PROOT_FACTS", "Store-only library closure required")
    libraries = facts["library_path"].split(":")
    for entry in libraries:
        _store_path(entry, "library_path")
    if (os.path.basename(facts["loader"]) != loader_name or str(Path(facts["loader"]).parent) != facts["glibc_lib"]
            or facts["glibc_lib"] not in libraries):
        raise ContractError("NIX_PROOT_FACTS", "Loader and libc must share the pinned glibc output")

    guest = facts["guest_environment"]
    if not isinstance(guest, dict) or set(guest) != GUEST_ENVIRONMENT_KEYS:
        raise ContractError("NIX_PROOT_FACTS", "Closed guest environment required")
    for key, value in guest.items():
        if not isinstance(value, str):
            raise ContractError("NIX_PROOT_FACTS", f"Invalid guest environment {key}")
        for entry in value.split(":"):
            _store_path(entry, key)
    if guest["LD_LIBRARY_PATH"] != facts["library_path"] or guest["PATH"] != facts["guest_path"]:
        raise ContractError("NIX_PROOT_FACTS", "Guest PATH and library path must match the pinned closure")
    return facts


def verify_closure(facts: dict[str, Any], paths: list[str]) -> list[str]:
    """The bound closure must be genuine top-level store paths covering every guest-visible fact."""
    validate_proot_facts(facts)
    if not 1 <= len(paths) <= MAX_CLOSURE or len(set(paths)) != len(paths):
        raise ContractError("NIX_PROOT_CLOSURE", "Bounded unique pinned closure required")
    for path in paths:
        if not isinstance(path, str) or not _STORE_TOP.fullmatch(path):
            raise ContractError("NIX_PROOT_CLOSURE", "Top-level store paths required in closure")
    known = set(paths)
    visible = [facts[k] for k in STORE_FACTS if k not in HOST_ONLY_FACTS]
    visible += facts["library_path"].split(":")
    for value in facts["guest_environment"].values():
        visible += value.split(":")
    missing = sorted({_top(v) for v in visible} - known)
    if missing:
        raise ContractError("NIX_PROOT_CLOSURE", "Guest-visible path outside pinned closure",
                            details={"reason": "guest-fact-not-in-closure"})
    return sorted(paths)


def read_closure(facts: dict[str, Any]) -> list[str]:
    validate_proot_facts(facts)
    try:
        raw = Path(facts["closure_paths_file"]).read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        raise ContractError("NIX_PROOT_CLOSURE", "Pinned closure listing unreadable") from None
    return verify_closure(facts, sorted({line for line in raw.splitlines() if line}))


@dataclass(frozen=True)
class GuestLayout:
    """Host directories that become the only writable or host-derived guest state."""
    cache_dir: Path
    tmp_dir: Path
    loader_tmp: Path
    etc_dir: Path
    workspaces: tuple[Path, ...] = ()
    x11_dir: Path | None = None
    dbus_socket: Path | None = None
    xdg_runtime_dir: Path | None = None


def _bind_source(path: Path | str) -> str:
    text = str(path)
    if (not text.startswith("/") or any(c in text for c in ":\x00\n") or text in FORBIDDEN_BIND_SOURCES
            or os.path.normpath(text) != text):
        raise ContractError("NIX_PROOT_BIND", "Narrow absolute bind source required")
    return text


def prepare_layout(base: Path, cache_dir: Path, *, workspaces: tuple[Path, ...] = (), uid: int | None = None,
                   gid: int | None = None) -> GuestLayout:
    """Create the explicit writable guest state; nothing is guessed from HOME."""
    uid = os.getuid() if uid is None else uid
    gid = os.getgid() if gid is None else gid
    base = Path(base)
    dirs = {name: base / name for name in ("tmp", "loader", "etc")}
    for path in (*dirs.values(), dirs["tmp"] / "home", Path(cache_dir)):
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    (dirs["etc"] / "passwd").write_text(f"rs9:x:{uid}:{gid}:rs9:/tmp/home:/bin/sh\n")
    (dirs["etc"] / "group").write_text(f"rs9:x:{gid}:\n")
    return GuestLayout(Path(cache_dir), dirs["tmp"], dirs["loader"], dirs["etc"], tuple(Path(w) for w in workspaces))


def guest_bindings(layout: GuestLayout, closure: list[str], *, exists: Callable[[str], bool] = os.path.exists
                   ) -> list[tuple[str, str]]:
    """Only closure store paths, explicit writable state and needed devices; never /etc, /tmp or the whole store."""
    binds = [(p, p) for p in closure]
    binds += [(_bind_source(layout.tmp_dir), "/tmp"),
              (_bind_source(layout.etc_dir / "passwd"), "/etc/passwd"),
              (_bind_source(layout.etc_dir / "group"), "/etc/group"),
              ("/proc", "/proc")]
    binds += [(d, d) for d in GUEST_DEVICES if exists(d)]
    for path in (layout.cache_dir, *layout.workspaces, layout.dbus_socket, layout.xdg_runtime_dir):
        if path is not None:
            source = _bind_source(path)
            binds.append((source, source))
    if layout.x11_dir is not None:
        binds.append((_bind_source(layout.x11_dir), "/tmp/.X11-unix"))
    unique: list[tuple[str, str]] = []
    targets: dict[str, str] = {}
    for source, target in binds:
        if targets.setdefault(target, source) != source:
            raise ContractError("NIX_PROOT_BIND", "Conflicting guest bind target")
        if (source, target) not in unique:
            unique.append((source, target))
    return unique


def guest_environment(facts: dict[str, Any], layout: GuestLayout, env: dict[str, str] | None = None) -> dict[str, str]:
    """Guest-only environment; host PATH/HOME/LD_* never cross, WebKit sandbox overrides are refused."""
    env = dict(env or {})
    for key in SANDBOX_DISABLING:
        if env.get(key) not in (None, "") and (key != "WEBKIT_FORCE_SANDBOX" or env[key] == "0"):
            raise ContractError("PROOT_ENV_SANDBOX", "WebKit sandbox override refused")
    guest = dict(facts["guest_environment"])
    home = "/tmp/home"
    guest.update(HOME=home, TMPDIR="/tmp", PYTHONDONTWRITEBYTECODE="1", XDG_CONFIG_HOME=home + "/.config",
                 XDG_CACHE_HOME=home + "/.cache", XDG_DATA_HOME=home + "/.local/share",
                 XDG_STATE_HOME=home + "/.local/state", THEME_FORGE_CACHE_DIR=str(layout.cache_dir))
    if env.get("THEME_FORGE_CACHE_DIR") not in (None, str(layout.cache_dir)):
        raise ContractError("PROOT_ENV_CACHE", "Cache directory must be the explicit bound cache")
    for key in ("LANG", "LC_ALL", "TZ"):
        if key in env:
            guest[key] = env[key]
    optional = {"DISPLAY": layout.x11_dir, "XAUTHORITY": layout.x11_dir, "WAYLAND_DISPLAY": layout.xdg_runtime_dir,
                "DBUS_SESSION_BUS_ADDRESS": layout.dbus_socket, "XDG_RUNTIME_DIR": layout.xdg_runtime_dir}
    for key, bound in optional.items():
        if bound is not None and key in env:
            guest[key] = env[key]
    for key, value in guest.items():
        if not isinstance(value, str) or "\x00" in value or "\n" in value or "=" in key:
            raise ContractError("PROOT_ENV", "Closed single-line guest environment required")
    return guest


def proot_guest_prefix(facts: dict[str, Any], layout: GuestLayout, closure: list[str], *,
                       env: dict[str, str] | None = None, cwd: str | None = None
                       ) -> tuple[list[str], dict[str, str], int]:
    """Argv prefix ending in a guest `env -i`; append any guest command. Returns (prefix, guest_env, bind_count)."""
    validate_proot_facts(facts)
    binds = guest_bindings(layout, closure)
    guest = guest_environment(facts, layout, env)
    prefix = [facts["env"], f"PROOT_TMP_DIR={_bind_source(layout.loader_tmp)}", facts["proot"], "--kill-on-exit",
              "-r", facts["guest_root"]]
    for source, target in binds:
        prefix += ["-b", f"{source}:{target}"]
    if cwd:
        prefix += ["-w", cwd]
    prefix += [facts["env"], "-i", *[f"{k}={v}" for k, v in sorted(guest.items())]]
    return prefix, guest, len(binds)


def proot_command_argv(facts: dict[str, Any], layout: GuestLayout, closure: list[str], command: list[str], *,
                       env: dict[str, str] | None = None, cwd: str | None = "/tmp"
                       ) -> tuple[list[str], dict[str, str], int]:
    prefix, guest, count = proot_guest_prefix(facts, layout, closure, env=env, cwd=cwd)
    return [*prefix, *command], guest, count


def wrapper_script(argv: list[str]) -> str:
    """Exact guest invocation as an executable wrapper that forwards arguments."""
    return "#!/bin/sh\nexec " + " ".join(shlex.quote(a) for a in argv) + ' "$@"\n'


class Run(NamedTuple):
    returncode: int | None
    stdout: bytes
    stderr: bytes
    elapsed: float
    error: str | None


def _bytes(value: Any) -> bytes:
    return value if isinstance(value, bytes) else value.encode() if isinstance(value, str) else b""


def bounded_guest_run(argv, *, env, capture_output=True, timeout=60):
    """Bound output while running and terminate the probe process group on every exit."""
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        child = subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                 start_new_session=True)
        deadline = time.monotonic() + timeout
        try:
            while child.poll() is None:
                if max(os.fstat(stdout.fileno()).st_size, os.fstat(stderr.fileno()).st_size) > MAX_OUTPUT:
                    break
                if time.monotonic() >= deadline:
                    raise subprocess.TimeoutExpired(argv, timeout)
                time.sleep(0.05)
        finally:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait(timeout=10)
        stdout.seek(0); stderr.seek(0)
        return subprocess.CompletedProcess(argv, child.returncode, stdout.read(MAX_OUTPUT + 1), stderr.read(MAX_OUTPUT + 1))


@dataclass
class GuestRuntime:
    """One pinned guest invocation context shared by every probe."""
    facts: dict[str, Any]
    layout: GuestLayout
    closure: list[str]
    prefix: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    runner: Callable = bounded_guest_run
    popen: Callable = subprocess.Popen
    sleep: Callable[[float], None] = time.sleep
    proc_root: Path = Path("/proc")
    host_userns: Callable[[], str] = lambda: os.readlink("/proc/self/ns/user")
    bind_count: int | None = None
    timeouts: dict[str, int] = field(default_factory=dict)
    elapsed: dict[str, float] = field(default_factory=dict)

    def host_env(self) -> dict[str, str]:
        return {k: v for k, v in self.env.items() if not k.startswith("LD_")}

    def argv(self, command: list[str], *, cwd: str | None = "/tmp") -> list[str]:
        argv, _, count = proot_command_argv(self.facts, self.layout, self.closure, command, env=self.env, cwd=cwd)
        self.bind_count = count
        return [*self.prefix, *argv]

    def run(self, probe: str, command: list[str], *, timeout: float = 60, cwd: str | None = "/tmp") -> Run:
        argv = self.argv(command, cwd=cwd)
        start = time.monotonic()
        error = None
        result = None
        try:
            result = self.runner(argv, env=self.host_env(), capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            self.timeouts[probe] = self.timeouts.get(probe, 0) + 1
            error = "timeout"
        except OSError:
            error = "spawn-failed"
        elapsed = time.monotonic() - start
        self.elapsed[probe] = round(self.elapsed.get(probe, 0.0) + elapsed, 3)
        if result is None:
            return Run(None, b"", b"", elapsed, error)
        stdout, stderr = _bytes(result.stdout), _bytes(result.stderr)
        if len(stdout) > MAX_OUTPUT or len(stderr) > MAX_OUTPUT:
            return Run(result.returncode, b"", b"", elapsed, "output-limit")
        return Run(result.returncode, stdout, stderr, elapsed, None)


def _result(name: str, status: str, reason: str | None = None, **details: Any) -> dict[str, Any]:
    row: dict[str, Any] = {"name": name, "status": status}
    if reason:
        row["reason"] = reason
    row["details"] = details
    return row


def _public(error: ContractError) -> dict[str, Any]:
    """Closed public error details that cannot collide with result fields."""
    return {k: v for k, v in safe_details(error.details).items() if k not in {"name", "status", "reason"}}


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _launch_reason(stderr: bytes) -> str:
    text = stderr.decode("utf-8", errors="replace").lower()
    if "ptrace" in text:
        return "ptrace-denied"
    if "no such file or directory" in text:
        return "guest-path-missing"
    if "user namespace" in text or "creating new namespace" in text:
        return "userns-denied"
    return "proot-launch-failed"


def _run_failure(name: str, run: Run, **details: Any) -> dict[str, Any]:
    reason = {"timeout": "probe-timeout", "spawn-failed": "probe-spawn-failed", "output-limit": "probe-output-limit"}.get(run.error or "")
    return _result(name, "fail", reason or _launch_reason(run.stderr), exit_code=run.returncode,
                   stdout_sha256=_sha(run.stdout), stderr_sha256=_sha(run.stderr),
                   elapsed_seconds=round(run.elapsed, 3), **details)


def _json(run: Run) -> dict[str, Any] | None:
    try:
        doc = json.loads(run.stdout.decode("utf-8"))
    except (ValueError, UnicodeError):
        return None
    return doc if isinstance(doc, dict) else None


def probe_pinned_derivation(recipe_content: bytes | str | Path | None) -> dict[str, Any]:
    """Gate proot-pinned-derivation: the nixpkgs recipe bytes actually evaluated match the pinned Git blob."""
    name = "proot-pinned-derivation"
    if recipe_content is None:
        return _result(name, "not-run", "recipe-bytes-unavailable")
    try:
        verified = verify_pinned_proot(recipe_content)
        return _result(name, "pass", **{k: v for k, v in verified.items() if k != "status"})
    except ContractError as error:
        return _result(name, "fail", error.code, **_public(error))


def probe_no_userns_ptrace(rt: GuestRuntime) -> dict[str, Any]:
    """Gate proot-no-userns-ptrace: same user namespace inode and guest path translation, no host leakage."""
    name = "proot-no-userns-ptrace"
    nonce = secrets.token_hex(8)
    (rt.layout.tmp_dir / "rs9-translation-nonce").write_text(nonce)
    code = ("import json,os\n"
            "nonce=open('/tmp/rs9-translation-nonce').read()\n"
            f"sentinels={list(_GUEST_SENTINELS)!r}\n"
            "print(json.dumps({'userns':os.readlink('/proc/self/ns/user'),'uid':os.getuid(),'nonce':nonce,"
            "'visible':[p for p in sentinels if os.path.exists(p)],'etc':sorted(os.listdir('/etc'))}))\n")
    run = rt.run(name, [rt.facts["python"], "-I", "-S", "-B", "-c", code])
    policy = "unavailable"
    try:
        value = Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns").read_text().strip()
        policy = {"0": "unrestricted", "1": "restricted"}.get(value, "unavailable")
    except OSError:
        pass
    if run.error or run.returncode != 0:
        return _run_failure(name, run, userns_policy=policy, bind_count=rt.bind_count)
    doc = _json(run)
    if doc is None or not all(k in doc for k in ("userns", "uid", "nonce", "visible", "etc")):
        return _result(name, "fail", "translation-probe-unparseable", userns_policy=policy)
    try:
        host_userns = rt.host_userns()
    except OSError:
        return _result(name, "not-run", "host-userns-unreadable", userns_policy=policy)
    unexpected = sorted(set(doc["etc"]) - _GUEST_ETC) if isinstance(doc["etc"], list) else ["unparseable"]
    visible = doc["visible"] if isinstance(doc["visible"], list) else ["unparseable"]
    checks = {"userns_inode_equal": doc["userns"] == host_userns, "uid_equal": doc["uid"] == os.getuid(),
              "tmp_translated": doc["nonce"] == nonce, "host_paths_hidden": not visible,
              "etc_closed": not unexpected}
    details = {**checks, "userns_policy": policy, "bind_count": rt.bind_count, "host_paths_visible": len(visible),
               "unexpected_etc_entries": len(unexpected), "elapsed_seconds": round(run.elapsed, 3)}
    if not checks["userns_inode_equal"]:
        return _result(name, "fail", "user-namespace-created", **details)
    if not all(checks.values()):
        return _result(name, "fail", "path-translation-or-isolation-failed", **details)
    return _result(name, "pass", **details)


_OBSERVER = r'''
import hashlib, json, os, signal, subprocess, sys, time, tempfile
spec = json.load(open(sys.argv[1]))
PROC = "/proc"
expected = set(spec["expected"])

def text(path):
    try:
        with open(path, "rb") as stream:
            return stream.read().decode("utf-8", "replace")
    except OSError:
        return None

def table():
    rows = {}
    for name in os.listdir(PROC):
        if not name.isdigit():
            continue
        stat = text(PROC + "/" + name + "/stat")
        if not stat or ")" not in stat:
            continue
        head, tail = stat[:stat.rfind(")")], stat[stat.rfind(")") + 2:].split()
        if len(tail) >= 2:
            rows[int(name)] = {"comm": head[head.find("(") + 1:], "ppid": int(tail[1])}
    return rows

def tree(root):
    rows = table()
    found = {root} if root in rows else set()
    grew = True
    while grew:
        grew = False
        for pid, row in rows.items():
            if pid not in found and row["ppid"] in found:
                found.add(pid)
                grew = True
    return {pid: rows[pid] for pid in found}

def is_loader(base):
    return base.startswith("ld-linux") or (base.startswith("ld-") and base.endswith(".so"))

def describe(pid, row):
    try:
        exe = os.readlink(PROC + "/%d/exe" % pid)
    except OSError:
        exe = None
    if exe and exe.endswith(" (deleted)"):
        exe = exe[:-10]
    base = os.path.basename(exe or "")
    cls = ("expected" if exe in expected else "loader" if is_loader(base) else "proot" if "proot" in base
           else "unreadable" if exe is None else "other")
    out = {"pid": pid, "ppid": row["ppid"], "comm": row["comm"], "exe_class": cls, "interps": 0, "interps_pinned": 0,
           "libcs": 0, "libcs_pinned": 0, "outside_system": 0, "outside_other": 0, "no_new_privs": None, "seccomp": None}
    for line in (text(PROC + "/%d/maps" % pid) or "").splitlines():
        parts = line.split(None, 5)
        if len(parts) < 6 or not parts[5].startswith("/"):
            continue
        path = parts[5][:-10] if parts[5].endswith(" (deleted)") else parts[5]
        name = os.path.basename(path)
        pinned = path.startswith(spec["glibc_lib"] + "/")
        if is_loader(name):
            out["interps"] += 1
            out["interps_pinned"] += pinned
        elif name.startswith("libc.so") or (name.startswith("libc-") and name.endswith(".so")):
            out["libcs"] += 1
            out["libcs_pinned"] += pinned
        if any(path.startswith(p) for p in spec["allowed"]):
            continue
        if (path.startswith("/memfd:") or path.startswith("/memfd ") or path == "/memfd"
                or path.startswith("//anon") or path.startswith("/[aio]")
                or path.startswith("/SYSV") or name.startswith("memfd:")):
            continue
        if any(path.startswith(p) for p in ("/lib/", "/lib64/", "/usr/")):
            out["outside_system"] += 1
        else:
            out["outside_other"] += 1
    for line in (text(PROC + "/%d/status" % pid) or "").splitlines():
        if line.startswith("NoNewPrivs:"):
            out["no_new_privs"] = int(line.split()[1])
        elif line.startswith("Seccomp:"):
            out["seccomp"] = int(line.split()[1])
    return out

stderr_file = tempfile.TemporaryFile()
try:
    child = subprocess.Popen([spec["exe"], *spec["args"]], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=stderr_file, start_new_session=True)
except OSError:
    print(json.dumps({"started": False, "processes": []}))
    sys.exit(0)
seen = {}
early = None
last = {}
grace = None
deadline = time.monotonic() + spec["hold"]
while time.monotonic() < deadline:
    code = child.poll()
    last = tree(child.pid)
    for pid, row in last.items():
        key = (pid, row["comm"])
        row_out = describe(pid, row)
        old = seen.get(key)
        if old is None or row_out["libcs"] + row_out["interps"] >= old["libcs"] + old["interps"]:
            seen[key] = row_out
    if code is not None or len(seen) > 48 or os.fstat(stderr_file.fileno()).st_size > 65536:
        early = code
        break
    if spec["until_webkit"]:
        if grace is None and any(k[1].startswith("WebKitWebProc") for k in seen):
            grace = time.monotonic() + 2.0
        if grace is not None and time.monotonic() >= grace:
            break
    time.sleep(0.25)
for pid in list(last):
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        pass
stop = time.monotonic() + 3
while child.poll() is None and time.monotonic() < stop:
    time.sleep(0.1)
for pid in list(last):
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass
child.wait(timeout=10)
stderr_file.seek(0)
stderr = stderr_file.read(65537)
stderr_file.close()
message = stderr.decode("utf-8", "replace").lower()
userns_denied = ("user namespace" in message or "creating new namespace" in message or
                ("bwrap" in message and ("operation not permitted" in message or "permission denied" in message)))
print(json.dumps({"started": True, "early_exit_code": early, "root_pid": child.pid,
                  "processes": list(seen.values()) if len(seen) <= 48 else [],
                  "process_capacity_exceeded": len(seen) > 48, "stderr_capacity_exceeded": len(stderr) > 65536,
                  "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
                  "diagnostic_token": "userns-denied" if userns_denied else "none"}))
'''


def observe_native(rt: GuestRuntime, exe: str, *, label: str, expected: list[str], root_is_elf: bool,
                   args: tuple[str, ...] = (), display: bool = False, hold: float = 6.0,
                   until_webkit: bool = False) -> dict[str, Any]:
    """Launch an unmodified released executable in the guest and sample its actual process tree.

    The sampler is a sibling guest process reading /proc, so release bytes, env and argv are untouched.
    """
    tmp = rt.layout.tmp_dir
    allowed = [*[p + "/" for p in rt.closure], "/dev/", "/proc/", str(rt.layout.loader_tmp) + "/", str(tmp) + "/",
               str(rt.layout.cache_dir) + "/", *[str(w) + "/" for w in rt.layout.workspaces]]
    (tmp / "rs9-observer.py").write_text(_OBSERVER)
    (tmp / f"rs9-observe-{label}.json").write_text(json.dumps({
        "exe": exe, "args": list(args), "hold": hold, "until_webkit": until_webkit, "expected": expected,
        "glibc_lib": rt.facts["glibc_lib"], "allowed": allowed}))
    command = [rt.facts["python"], "-I", "-S", "-B", "/tmp/rs9-observer.py", f"/tmp/rs9-observe-{label}.json"]
    if display:
        command = ["xvfb-run", "-a", "dbus-run-session", "--", *command]
    run = rt.run("observe-" + label, command, timeout=hold + 90, cwd="/tmp")
    if run.error or run.returncode != 0:
        return {"label": label, "status": "unobserved", "reason": _run_failure(label, run)["reason"]}
    doc = _json(run)
    if doc is None or not doc.get("started") or (doc.get("process_capacity_exceeded") or doc.get("stderr_capacity_exceeded")) or not isinstance(doc.get("processes"), list):
        return {"label": label, "status": "unobserved", "reason": "release-process-not-started"}
    token = "userns-denied" if doc.get("diagnostic_token") == "userns-denied" else "none"
    if any(not isinstance(p, dict) for p in doc["processes"]):
        return {"label": label, "status": "unobserved", "reason": "malformed-process-record"}
    processes = doc["processes"]
    if not processes or all(p.get("exe_class") == "unreadable" for p in processes):
        return {"label": label, "status": "unobserved", "reason": "exited-before-observation",
                "early_exit_code": doc.get("early_exit_code"), "diagnostic_token": token}
    return {"label": label, "status": "observed", "root_is_elf": root_is_elf, "root_pid": doc.get("root_pid"),
            "early_exit_code": doc.get("early_exit_code"), "processes": processes, "diagnostic_token": token}


def _combine(parts: dict[str, tuple[str, str | None, dict]]) -> tuple[str, str | None, dict]:
    details = {k: {"status": s, **({"reason": r} if r else {}), **d} for k, (s, r, d) in parts.items()}
    for wanted in ("fail", "not-run"):
        for status, reason, _ in parts.values():
            if status == wanted:
                return wanted, reason, details
    return "pass", None, details


def _observation_state(obs: dict[str, Any] | None, check: Callable[[dict], tuple[str, str | None, dict]]
                       ) -> tuple[str, str | None, dict]:
    if not obs or obs.get("status") == "not-run":
        return "not-run", (obs or {}).get("reason", "release-observation-absent"), {}
    if obs.get("status") != "observed":
        return "fail", obs.get("reason", "release-process-unobserved"), {}
    return check(obs)


def _self_check(obs: dict[str, Any]) -> tuple[str, str | None, dict]:
    procs = obs["processes"]
    expected = [p for p in procs if p.get("exe_class") == "expected"]
    diverged = [p for p in procs if p.get("exe_class") in {"loader", "proot"}]
    details = {"process_count": len(procs), "released_process_count": len(expected), "diverged_count": len(diverged)}
    if diverged:
        return "fail", "executable-self-diverged", details
    if obs.get("root_is_elf"):
        root = [p for p in procs if p.get("pid") == obs.get("root_pid")]
        if not root or root[0].get("exe_class") != "expected":
            return "fail", "root-executable-self-diverged", details
    if not expected:
        return "fail", "no-released-process-observed", details
    return "pass", None, details


def _interp_check(obs: dict[str, Any]) -> tuple[str, str | None, dict]:
    procs = obs["processes"]
    expected = [p for p in procs if p.get("exe_class") == "expected"]
    leaked = sum(int(p.get("outside_system", 0)) for p in procs)
    outside_other = sum(int(p.get("outside_other", 0)) for p in procs)
    unpinned = [p for p in expected if not (
        p.get("interps", 0) >= 1 and p.get("interps") == p.get("interps_pinned")
        and p.get("libcs", 0) >= 1 and p.get("libcs") == p.get("libcs_pinned"))]
    details = {"released_process_count": len(expected), "host_library_maps": leaked,
               "outside_other_maps": outside_other, "unpinned_processes": len(unpinned)}
    if leaked:
        return "fail", "host-library-mapped", details
    if outside_other:
        return "fail", "outside-other-mapped", details
    if not expected:
        return "fail", "no-released-process-observed", details
    if unpinned:
        return "fail", "descendant-interpreter-or-libc-not-pinned", details
    return "pass", None, details


def probe_executable_self(rt: GuestRuntime, observations: dict[str, dict[str, Any] | None]) -> dict[str, Any]:
    """Gate proot-executable-self: pinned tools plus the actual released main and SEA executables."""
    name = "proot-executable-self"
    tools: dict[str, tuple[str, str | None, dict]] = {}
    for tool, code in (("python", "import json,os;print(json.dumps({'exe':os.readlink('/proc/self/exe')}))"),
                       ("node", "console.log(JSON.stringify({exe:require('fs').readlinkSync('/proc/self/exe'),"
                                "execPath:process.execPath}))")):
        args = ["-I", "-S", "-B", "-c", code] if tool == "python" else ["-e", code]
        run = rt.run(name, [rt.facts[tool], *args], timeout=30)
        doc = None if run.error or run.returncode != 0 else _json(run)
        if doc is None or not isinstance(doc.get("exe"), str):
            tools[tool] = ("fail", _run_failure(name, run)["reason"] if (run.error or run.returncode) else
                           "self-probe-unparseable-output", {})
            continue
        real = os.path.realpath(doc["exe"]) == os.path.realpath(rt.facts[tool])
        preserved = tool != "node" or doc.get("execPath") == rt.facts[tool]
        tools[tool] = ("pass" if real and preserved else "fail", None if real and preserved else "executable-self-diverged",
                       {"self_is_tool": real, "exec_path_preserved": preserved if tool == "node" else None})
    parts = {f"tool-{k}": v for k, v in tools.items()}
    for label in ("sea", "main"):
        parts[label] = _observation_state(observations.get(label), _self_check)
    status, reason, details = _combine(parts)
    return _result(name, status, reason, parts=details, method="guest-sibling-procfs-readback")


def probe_descendant_interpreter(rt: GuestRuntime, observations: dict[str, dict[str, Any] | None]) -> dict[str, Any]:
    """Gate proot-descendant-interpreter: released native processes map only the pinned loader and libc."""
    name = "proot-descendant-interpreter"
    parts = {label: _observation_state(observations.get(label), _interp_check) for label in ("sea", "main")}
    status, reason, details = _combine(parts)
    return _result(name, status, reason, parts=details, pinned_loader=os.path.basename(rt.facts["loader"]))


def probe_closure_resolution(rt: GuestRuntime, elf_paths: list[str] | None, closure_size_bytes: int | None, *,
                             budget_seconds: float = 600) -> dict[str, Any]:
    """Gate proot-closure-resolution: every released ELF resolves entirely inside the pinned bound closure."""
    name = "proot-closure-resolution"
    if elf_paths is None:
        return _result(name, "not-run", "payload-materialization-absent")
    if not elf_paths:
        return _result(name, "fail", "no-released-elf-inventory")
    if len(elf_paths) > MAX_ELFS:
        return _result(name, "fail", "elf-inventory-bound-exceeded", elf_count=len(elf_paths))
    if not isinstance(closure_size_bytes, int) or closure_size_bytes <= 0:
        return _result(name, "not-run", "closure-size-unmeasured", closure_path_count=len(rt.closure))
    known = set(rt.closure)
    resolved = static = 0
    problems: dict[str, int] = {"missing": 0, "outside-closure": 0, "ldd-failed": 0, "timeout": 0}
    spent = 0.0
    foreign_interp = rt.facts.get("foreign_interpreter")
    loader = rt.facts.get("loader")
    for elf in elf_paths:
        if spent > budget_seconds:
            return _result(name, "fail", "closure-budget-exhausted", resolved_count=resolved, problems=problems)
        run = rt.run(name, [rt.facts["ldd"], elf], timeout=30)
        spent += run.elapsed
        text = run.stdout.decode("utf-8", errors="replace") + run.stderr.decode("utf-8", errors="replace")
        if run.error:
            problems["timeout" if run.error == "timeout" else "ldd-failed"] += 1
        elif "not a dynamic executable" in text or "statically linked" in text:
            static += 1
        elif run.returncode != 0:
            problems["ldd-failed"] += 1
        elif "not found" in text:
            problems["missing"] += 1
        else:
            outside = []
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                m_arrow = re.search(r"=>\s+(/\S+)\s+\(0x", line)
                if m_arrow:
                    target = m_arrow.group(1)
                    if _top(target) not in known:
                        outside.append(target)
                    continue
                m_direct = re.search(r"^(/\S+)\s+\(0x", line)
                if m_direct:
                    target = m_direct.group(1)
                    valid_interp = target == foreign_interp or target == loader
                    if _top(target) not in known and not valid_interp:
                        outside.append(target)
                    continue
            if outside:
                problems["outside-closure"] += 1
            else:
                resolved += 1
    details = {"resolved_count": resolved, "static_count": static, "elf_count": len(elf_paths), "problems": problems,
               "closure_path_count": len(rt.closure), "closure_size_bytes": closure_size_bytes}
    if any(problems.values()):
        return _result(name, "fail", "unresolved-closure-dependencies", **details)
    return _result(name, "pass", **details)


def _scan_cmdlines(proc_root: Path, needle: bytes) -> list[int]:
    pids = []
    try:
        entries = list(proc_root.iterdir())
    except OSError:
        return pids
    for entry in entries:
        if not entry.name.isdigit():
            continue
        try:
            if needle in (entry / "cmdline").read_bytes():
                pids.append(int(entry.name))
        except OSError:
            continue
    return pids


def _reap(rt: GuestRuntime, needle: bytes) -> int:
    """Bounded orphan check: processes still carrying the unique probe token after the wrapper has gone."""
    survivors: list[int] = []
    for _ in range(10):
        survivors = _scan_cmdlines(rt.proc_root, needle)
        if not survivors:
            return 0
        rt.sleep(0.3)
    for pid in survivors:
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
    return len(survivors)


def probe_args_exit_signals_orphans(rt: GuestRuntime) -> dict[str, Any]:
    """Gate proot-args-exit-signals: argv, exit status, signal death, external SIGTERM and orphan tracees."""
    name = "proot-args-exit-signals"
    python = [rt.facts["python"], "-I", "-S", "-B", "-c"]
    args = ["arg with space", "--flag=value", "semi;colon", "quote'test", "new\nline", "", "$HOME", "*"]
    run = rt.run(name, [*python, "import sys,json;print(json.dumps(sys.argv[1:]))", *args], timeout=30)
    if run.error or run.returncode != 0:
        return _run_failure(name, run, stage="arguments")
    if (_json_list(run)) != args:
        return _result(name, "fail", "argument-forwarding-mismatch")
    for code in (0, 7, 42):
        run = rt.run(name, [*python, f"import sys;sys.exit({code})"], timeout=30)
        if run.error or run.returncode != code:
            return _result(name, "fail", "exit-code-propagation-failed", expected_exit=code, exit_code=run.returncode,
                           stage="exit")
    run = rt.run(name, [*python, "import os,signal,time;signal.signal(signal.SIGTERM,signal.SIG_DFL);"
                                 "os.kill(os.getpid(),signal.SIGTERM);time.sleep(5)"], timeout=30)
    if run.error or run.returncode not in {-signal.SIGTERM, 128 + signal.SIGTERM}:
        return _result(name, "fail", "guest-signal-status-not-propagated", exit_code=run.returncode, stage="signal")
    guest_signal_status = run.returncode

    orphan = secrets.token_hex(8).encode()
    run = rt.run(name, [*python, "import subprocess,sys;subprocess.Popen([sys.executable,'-I','-S','-B','-c',"
                                 "'import time;time.sleep(600)',sys.argv[1]]);import os;os._exit(0)",
                        orphan.decode()], timeout=30)
    survivors = _reap(rt, orphan)
    if run.error or run.returncode != 0:
        return _run_failure(name, run, stage="orphan")
    if survivors:
        return _result(name, "fail", "orphaned-tracee-survived", orphaned_tracees=survivors)

    external = _external_sigterm(rt, name)
    if external["status"] != "pass":
        return _result(name, "fail", external["reason"], **external["details"])
    return _result(name, "pass", arg_forwarding="verified", exit_codes_verified=[0, 7, 42],
                   guest_signal_exit_code=guest_signal_status, orphaned_tracees=0, external_sigterm=external["details"])


def _json_list(run: Run) -> Any:
    try:
        return json.loads(run.stdout.decode("utf-8"))
    except (ValueError, UnicodeError):
        return None


def _run_signal_attempt(rt: GuestRuntime, name: str, *, deliver_to_group: bool = False
                        ) -> tuple[str | None, int | None, bool, int, str]:
    nonce = secrets.token_hex(8)
    marker, ready = f"rs9-term-{nonce}", f"rs9-ready-{nonce}"
    code = ("import os,signal,sys,time\n"
            "def term(signum,frame):\n"
            "    open('/tmp/%s','w').write(str(signum)); os._exit(0)\n"
            "signal.signal(signal.SIGTERM,term)\n"
            "open('/tmp/%s','w').write('1')\n"
            "time.sleep(60)\nos._exit(3)\n" % (marker, ready))
    argv = rt.argv([rt.facts["python"], "-I", "-S", "-B", "-c", code])
    proc = rt.popen(argv, env=rt.host_env(), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, start_new_session=True)
    reason, exit_code, survivors = None, None, 0
    try:
        for _ in range(100):
            if (rt.layout.tmp_dir / ready).exists() or proc.poll() is not None:
                break
            rt.sleep(0.2)
        if not (rt.layout.tmp_dir / ready).exists():
            reason = "signal-probe-guest-not-ready"
        else:
            if deliver_to_group:
                if hasattr(proc, "send_group_signal"):
                    proc.send_group_signal(signal.SIGTERM)
                else:
                    pid = getattr(proc, "pid", None)
                    if pid is not None:
                        try:
                            os.killpg(pid, signal.SIGTERM)
                        except OSError:
                            reason = "process-group-delivery-unavailable"
                    else:
                        reason = "process-group-delivery-unavailable"
            else:
                proc.send_signal(signal.SIGTERM)
            try:
                exit_code = proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                rt.timeouts[name] = rt.timeouts.get(name, 0) + 1
                reason = "sigterm-did-not-terminate-wrapper"
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=10)
        survivors = _reap(rt, nonce.encode())
    observed = (rt.layout.tmp_dir / marker).exists()
    if reason is None and not observed:
        reason = "guest-sigterm-not-observed"
    if survivors:
        reason = "orphaned-tracee-survived"
    return reason, exit_code, observed, survivors, os.path.basename(argv[0])


def _external_sigterm(rt: GuestRuntime, name: str) -> dict[str, Any]:
    reason, exit_code, observed, survivors, target = _run_signal_attempt(rt, name, deliver_to_group=False)
    control_details: dict[str, Any] | None = None
    if reason in {"guest-sigterm-not-observed", "sigterm-did-not-terminate-wrapper"}:
        c_reason, c_exit_code, c_observed, c_survivors, _ = _run_signal_attempt(rt, name, deliver_to_group=True)
        control_details = {
            "delivery_scope": "process-group",
            "guest_handler_observed": c_observed,
            "wrapper_exit_code": c_exit_code,
            "orphaned_tracees": c_survivors,
            "status": "pass" if c_observed and not c_reason else "fail",
            **({"reason": c_reason} if c_reason else {}),
        }

    if observed:
        product_implication = (
            "SIGTERM to the outer process reached the guest handler; "
            "supervisor process-group signaling remains recommended."
        )
    elif control_details and control_details.get("guest_handler_observed"):
        product_implication = (
            "Outer-process delivery did not reach the guest handler; "
            "process-group delivery succeeded in control but cannot substitute for product wrapper forwarding."
        )
    elif reason == "signal-probe-guest-not-ready":
        product_implication = "Guest failed to become ready before external signal could be delivered."
    elif reason == "sigterm-did-not-terminate-wrapper":
        product_implication = "Outer-process SIGTERM did not terminate the wrapper; the responsible layer is unproven."
    else:
        product_implication = "SIGTERM delivery failed to reach or terminate guest handler under outer process delivery."

    details: dict[str, Any] = {
        "wrapper_exit_code": exit_code,
        "guest_handler_observed": observed,
        "orphaned_tracees": survivors,
        "stage": "signal",
        "signal_target": target,
        "delivery_scope": "outer-process",
        "product_wrapper_implication": product_implication,
    }
    if control_details:
        details["process_group_control"] = control_details
    return {"status": "fail" if reason else "pass", "reason": reason, "details": details}


def probe_in_guest_offline(rt: GuestRuntime) -> dict[str, Any]:
    """Gate proot-in-guest-offline: pass only from an explicit denial result observed inside the guest."""
    name = "proot-in-guest-offline"
    if not rt.prefix:
        row = _result(name, "not-run", "network-denial-prefix-absent")
        row["runtime_offline_status"] = "not-run"
        return row
    code = ("import json,socket\n"
            "s=socket.socket();s.settimeout(2)\n"
            "rc=s.connect_ex(('1.1.1.1',443));s.close()\n"
            "rows=open('/proc/net/dev').read().splitlines()[2:]\n"
            "print(json.dumps({'connect_errno':rc,'interfaces':sorted(r.split(':')[0].strip() for r in rows)}))\n")
    run = rt.run(name, [rt.facts["python"], "-I", "-S", "-B", "-c", code], timeout=20)
    doc = None if run.error or run.returncode != 0 else _json(run)
    if doc is None or type(doc.get("connect_errno")) is not int or not isinstance(doc.get("interfaces"), list):
        row = _run_failure(name, run) if (run.error or run.returncode) else _result(name, "fail", "offline-probe-unparseable")
        row["runtime_offline_status"] = "fail"
        return row
    denied = doc["connect_errno"] in DENIAL_ERRNOS
    loopback_only = all(i == "lo" for i in doc["interfaces"])
    details = {"connect_errno": doc["connect_errno"], "denied": denied, "loopback_only": loopback_only,
               "mechanism": "netns+setpriv"}
    if denied and loopback_only:
        row = _result(name, "pass", **details)
        row["runtime_offline_status"] = "pass"
        return row
    row = _result(name, "fail", "network-denial-not-observed-in-guest", **details)
    row["runtime_offline_status"] = "fail"
    return row


def probe_bwrap_mechanism(rt: GuestRuntime) -> dict[str, Any]:
    """Informational: can the pinned WebKit sandbox helper create its user namespace under PRoot?"""
    run = rt.run("proot-webkit-sandbox-state", [rt.facts["bwrap"], "--unshare-user", "--ro-bind", "/", "/", "--",
                                                 rt.facts["python"], "-I", "-S", "-B", "-c", "pass"], timeout=30)
    text = run.stderr.decode("utf-8", errors="replace").lower()
    token = ("userns-denied" if "namespace" in text or "operation not permitted" in text else
             "no-such-file" if "no such file" in text else "unclassified" if run.returncode else "none")
    return {"exit_code": run.returncode, "diagnostic_token": token, "stderr_sha256": _sha(run.stderr),
            "timed_out": run.error == "timeout"}


def probe_webkit_sandbox_state(rt: GuestRuntime, main: dict[str, Any] | None, mechanism: dict[str, Any] | None = None
                               ) -> dict[str, Any]:
    """Gate proot-webkit-sandbox-state: actual descendant WebKit web process under bwrap; never disabled here."""
    name = "proot-webkit-sandbox-state"
    base = {"sandbox_disabled_by_experiment": False, **({"bwrap_mechanism": mechanism} if mechanism else {})}
    if not main or main.get("status") == "not-run":
        return _result(name, "not-run", (main or {}).get("reason", "main-observation-absent"), **base)
    if main.get("status") != "observed":
        reason = "webkit-sandbox-requires-userns" if main.get("diagnostic_token") == "userns-denied" else "webkit-main-process-unobserved"
        return _result(name, "fail", reason, cause=main.get("reason"), **base)
    procs = main["processes"]
    by_pid = {p.get("pid"): p for p in procs}
    web = [p for p in procs if str(p.get("comm", "")).startswith("WebKitWebProc")]
    if not web:
        reason = ("webkit-sandbox-requires-userns" if main.get("diagnostic_token") == "userns-denied"
                  else "webkit-web-process-not-observed")
        return _result(name, "fail", reason, process_count=len(procs), **base)
    bwrap = [p for p in procs if p.get("comm") == "bwrap"]
    sandboxed = [w for w in web if by_pid.get(w.get("ppid"), {}).get("comm") == "bwrap"]
    baseline_proc = by_pid.get(main.get("root_pid")) or next(
        (p for p in procs if not str(p.get("comm", "")).startswith("WebKitWebProc") and p.get("comm") != "bwrap"),
        None,
    )
    baseline_nnp = baseline_proc.get("no_new_privs") if baseline_proc else None
    baseline_seccomp = baseline_proc.get("seccomp") if baseline_proc else None
    baseline_matches = baseline_nnp == 1 and baseline_seccomp == 2

    details = {"web_process_count": len(web), "bwrap_process_count": len(bwrap), "sandboxed_web_processes": len(sandboxed),
               "no_new_privs": [w.get("no_new_privs") for w in web][:8], "seccomp": [w.get("seccomp") for w in web][:8],
               "baseline_no_new_privs": baseline_nnp, "baseline_seccomp": baseline_seccomp,
               "baseline_matches_proot_acceleration": baseline_matches,
               "sandbox_diagnostics_confounded": True, "nnp_seccomp_confounded": True,
               "sandbox_enabled_evidence": "bwrap-parent-observation"}
    # PRoot can install these flags independently on tracees. They are a
    # consistency check, never evidence of WebKit's own seccomp filter.
    if (len(sandboxed) != len(web) or any(w.get("no_new_privs") != 1 or w.get("seccomp") != 2 for w in web)):
        return _result(name, "fail", "webkit-sandbox-not-observed-enabled", **details, **base)
    return _result(name, "pass", **details, **base)


def probe_verifier_and_smoke(smoke: Callable[[], dict[str, Any]] | None) -> dict[str, Any]:
    """Gate proot-verifier-smoke: the released verifier and unchanged smoke, run through the guest by the caller."""
    name = "proot-verifier-smoke"
    if smoke is None:
        return _result(name, "not-run", "verifier-smoke-inputs-absent")
    try:
        evidence = smoke()
    except ContractError as error:
        return _result(name, "fail", error.code, **_public(error))
    except (OSError, KeyError, ValueError, TypeError, subprocess.SubprocessError):
        return _result(name, "fail", "verifier-smoke-execution-failed")
    if not isinstance(evidence, dict) or evidence.get("sidecar", {}).get("verified") is not True or not evidence.get("scenarios"):
        return _result(name, "fail", "verifier-smoke-evidence-incomplete")
    return _result(name, "pass", scenarios=[s.get("scenario") for s in evidence["scenarios"]],
                   verifier_verified=True, smoke_unchanged=True,
                   drift=bool((evidence.get("drift") or {}).get("has_drift")))


def evaluate_proot_experiment(
    rt: GuestRuntime,
    recipe_content: bytes | str | Path | None,
    *,
    materialize: Callable[[], dict[str, Any]] | None = None,
    smoke: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
    closure_size_bytes: int | None = None,
) -> dict[str, Any]:
    """Run every falsifiable probe. application_qualified and qualification_authority are always false.

    `materialize` runs the unmodified release launcher in the guest and returns
    {"elfs", "launcher", "launcher_is_elf", "sea"} for the actual materialized payload; `smoke`
    receives that mapping and runs the released verifier and unchanged smoke. Missing inputs
    are recorded as not-run, never as a pass.
    """
    released: dict[str, Any] | None = None
    release_problem: tuple[str, str] | None = None
    if materialize is None:
        release_problem = ("not-run", "payload-materialization-absent")
    else:
        try:
            released = materialize()
        except ContractError as error:
            release_problem = ("fail", error.code)
        except (OSError, KeyError, ValueError, TypeError):
            release_problem = ("fail", "release-materialization-failed")

    def absent(reason: str) -> dict[str, Any]:
        return {"status": "not-run", "reason": reason}

    pinned = probe_pinned_derivation(recipe_content)
    userns = probe_no_userns_ptrace(rt)
    # The released verifier and smoke run first, against the baseline taken right after
    # materialization; the observers below launch the release again and may mutate its tree.
    if released is None:
        verifier = _result("proot-verifier-smoke", *(release_problem or ("not-run", "payload-materialization-absent")))
    else:
        verifier = probe_verifier_and_smoke((lambda: smoke(released)) if smoke else None)
    observations: dict[str, dict[str, Any] | None] = {}
    elfs: list[str] | None = None
    if released is None:
        status, reason = release_problem or ("not-run", "payload-materialization-absent")
        observations = {"sea": {"status": "unobserved" if status == "fail" else "not-run", "reason": reason},
                        "main": {"status": "unobserved" if status == "fail" else "not-run", "reason": reason}}
        if status == "fail":
            elfs = []
    else:
        elfs = list(released.get("elfs") or [])
        all_elfs = [str(p) for p in elfs]
        sea, launcher = released.get("sea"), released.get("launcher")
        observations["sea"] = (observe_native(rt, str(sea), label="sea", expected=all_elfs, root_is_elf=True, hold=4.0)
                               if sea else absent("sea-executable-unresolved"))
        observations["main"] = (observe_native(rt, str(launcher), label="main", expected=all_elfs,
                                               root_is_elf=bool(released.get("launcher_is_elf")), display=True,
                                               hold=30.0, until_webkit=True)
                                if launcher else absent("launcher-unresolved"))
    exe_self = probe_executable_self(rt, observations)
    interp = probe_descendant_interpreter(rt, observations)
    closure = probe_closure_resolution(rt, elfs, closure_size_bytes)
    signals = probe_args_exit_signals_orphans(rt)
    offline = probe_in_guest_offline(rt)
    webkit = probe_webkit_sandbox_state(rt, observations.get("main"), probe_bwrap_mechanism(rt))

    probes = [pinned, userns, exe_self, interp, closure, signals, offline, webkit, verifier]
    gates = [{"name": p["name"], "status": p["status"], **({"reason": p["reason"]} if "reason" in p else {}),
              **({"runtime_offline_status": p["runtime_offline_status"]} if "runtime_offline_status" in p else {})}
             for p in probes]
    all_passed = all(p["status"] == "pass" for p in probes)
    return {
        "schema": SCHEMA,
        "system": rt.facts["system"],
        "application_qualified": False,
        "qualification_authority": False,
        "status": "diagnostic-pass" if all_passed else "diagnostic-fail",
        "probes": probes,
        "gates": gates,
        "measurements": {"bind_count": rt.bind_count, "closure_path_count": len(rt.closure),
                         "closure_size_bytes": closure_size_bytes, "timeouts": dict(sorted(rt.timeouts.items())),
                         "elapsed_seconds": dict(sorted(rt.elapsed.items()))},
        "gaps": [{"name": p["name"], "status": p["status"], "reason": p.get("reason")}
                 for p in probes if p["status"] != "pass"],
        "reason": None if all_passed else "falsifiable-probe-incompatibility-or-missing-evidence",
    }
