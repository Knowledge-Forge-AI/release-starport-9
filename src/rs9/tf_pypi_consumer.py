"""Isolated offline pip lifecycle and released command contracts, without upload."""
import io
import os
import json
import errno
from pathlib import Path
import platform
import re
import selectors
import signal
import shlex
import shutil
import subprocess
import sys
import tarfile
import time
import venv
from typing import Any, Callable, Mapping, Sequence

from rs9.tf_pypi_archive import canonical, fail, physical_bytes, sha256
from rs9.tf_pypi_launcher import node_binary
from rs9.tf_pypi_model import strict_json
from rs9.tf_pypi_verify import read_wheel, verify_pair, verify_record
from rs9.tf_pypi_platform import host_key
from rs9.tf_pypi_probes import functional_probes
from rs9.tf_pypi_probes import receipt

_CONSUMER_ENV_KEYS = (
    "HOME", "LANG", "LC_ALL", "PATH", "PIP_CONFIG_FILE",
    "PIP_DISABLE_PIP_VERSION_CHECK", "PIP_NO_CACHE_DIR", "PIP_NO_INDEX",
    "PYTHONDONTWRITEBYTECODE", "TEMP", "THEME_FORGE_NODE_BIN", "TMP", "TMPDIR",
)


def host_system():
    system, machine = platform.system(), platform.machine().lower()
    key = (system, machine)
    supported = {("Darwin", "arm64"): "aarch64-darwin", ("Linux", "x86_64"): "x86_64-linux",
                 ("Linux", "aarch64"): "aarch64-linux", ("Linux", "arm64"): "aarch64-linux"}
    if key not in supported or sys.version_info < (3, 9):
        fail("UNSUPPORTED_HOST")
    if system == "Linux" and platform.libc_ver()[0] != "glibc":
        fail("UNSUPPORTED_HOST")
    return supported[key]


def _expand_prefix(prefix, env):
    if not prefix:
        return ()
    raw = list(prefix)
    if raw and raw[0] == "sudo":
        raw[0] = (shutil.which("sudo", path=env.get("PATH"))
                  or shutil.which("sudo", path="/usr/bin:/bin")
                  or "/usr/bin/sudo")
    if "/usr/bin/env" in raw:
        raw = raw[:raw.index("/usr/bin/env")]
        assignments = [
            f"{k}={env[k]}" for k in _CONSUMER_ENV_KEYS
            if k in env and isinstance(env[k], str)
        ]
        raw.extend(["/usr/bin/env", "-i", *assignments])
    return tuple(raw)


def _run(argv, env, *, prefix=(), input=b""):
    effective_prefix = _expand_prefix(prefix, env)
    try:
        result = subprocess.run([*effective_prefix, *map(str, argv)], env=env, input=input,
                                capture_output=True, timeout=90, cwd=env.get("HOME"))
    except (OSError, subprocess.SubprocessError):
        fail("CONSUMER_PROCESS")
    if len(result.stdout) + len(result.stderr) > 1024**2:
        fail("CONSUMER_OUTPUT")
    return result


def _success(argv, env, *, prefix=()):
    result = _run(argv, env, prefix=prefix)
    if result.returncode:
        fail("CONSUMER_PROCESS")
    return result


def _inventory(root):
    return sorted(p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file() or p.is_symlink())


def _probes(pin, root, env, prefix, functional):
    records = []
    for command in sorted(pin["bins"]):
        if command == "tfsb-studio-service":
            continue
        batch = command == "tfsl-batch"
        argv = [root / "bin" / command] + ([] if batch else ["--version"])
        result = _run(argv, env, prefix=prefix)
        token = b"EMPTY_INPUT" if batch else pin["version"].encode()
        if result.returncode != (1 if batch else 0) or token not in result.stdout:
            fail("COMMAND_CONTRACT")
        records.append({"command": command, "exit": result.returncode,
                        "stdout_sha256": sha256(result.stdout), "stderr_sha256": sha256(result.stderr)})
    records.extend(node_negatives(pin, root, env, prefix))
    if functional:
        records.extend(functional_probes(pin, root, env, prefix, _run))
    return records


def node_negatives(pin, root, env, prefix):
    directory = Path(env["HOME"]) / (root.name + "-node-negatives")
    directory.mkdir()
    old, wrong, inert = (directory / name for name in ("old", "wrong", "inert"))
    old.write_text("#!/bin/sh\necho v20.0.0\n")
    wrong.write_text("#!/bin/sh\nif [ \"$1\" = --version ]; then echo v22.0.0; else "
                     "echo '{\"platform\":\"win32\",\"arch\":\"x64\",\"glibc\":null}'; fi\n")
    inert.write_text("not executable\n")
    old.chmod(0o755)
    wrong.chmod(0o755)
    inert.chmod(0o644)
    records = []
    for kind, override in (("missing", None), ("old", old), ("not-executable", inert), ("platform", wrong)):
        negative = {**env, "PATH": ""}
        negative.pop("THEME_FORGE_NODE_BIN", None)
        if override:
            negative["THEME_FORGE_NODE_BIN"] = str(override)
        for command in sorted(pin["bins"]):
            result = _run([root / "bin" / command], negative, prefix=prefix)
            code = b"TF_PYPI_NODE_PLATFORM" if kind == "platform" else b"TF_PYPI_NODE_REQUIRED"
            if result.returncode != 1 or code not in result.stderr:
                fail("NODE_NEGATIVE")
            records.append(receipt(command, "node-" + kind, result))
    return records


def smoke(pin, dist, work, *, offline_linux=False, functional=True):
    """Receipts describe only the current host; never mark source READY."""
    target = host_key()
    manifest = verify_pair(pin, dist, target=target)
    system = host_system()
    node = node_binary()
    work, dist = Path(work).resolve(), Path(dist).resolve()
    work.mkdir(parents=True, exist_ok=False)
    temp = work / "tmp"
    temp.mkdir(mode=0o700, exist_ok=False)
    env = {"PATH": str(Path(node).parent) + os.pathsep + "/usr/bin:/bin", "HOME": str(work),
           "THEME_FORGE_NODE_BIN": node, "LANG": "C", "LC_ALL": "C",
           "PYTHONDONTWRITEBYTECODE": "1", "PIP_CONFIG_FILE": os.devnull,
           "PIP_DISABLE_PIP_VERSION_CHECK": "1", "PIP_NO_CACHE_DIR": "1",
           "PIP_NO_INDEX": "1", "TEMP": str(temp), "TMP": str(temp),
           "TMPDIR": str(temp)}
    prefix = []
    if offline_linux:
        if not system.endswith("-linux"):
            fail("UNSUPPORTED_HOST")
        from rs9.hosted_commands import linux_runtime_prefix
        prefix = _expand_prefix(linux_runtime_prefix(env), env)
        probe = ("import socket\ns=socket.socket();s.settimeout(1)\ntry:s.connect(('1.1.1.1',443))"
                 "\nexcept OSError:print('blocked')\nelse:print('connected')\nfinally:s.close()")
        result = _success([sys.executable, "-I", "-c", probe], env, prefix=prefix)
        if result.stdout.strip() != b"blocked":
            fail("OFFLINE_ISOLATION")
    isolation = network_denial(sys.executable, node, env, prefix)
    records = []
    for kind in ("wheel", "sdist"):
        root = work / kind
        venv.EnvBuilder(with_pip=True).create(root)
        before = _inventory(root)
        python = root / "bin/python"
        network_denial(python, node, env, prefix)
        pip = [python, "-I", "-B", "-m", "pip", "--disable-pip-version-check"]
        suffix = ".whl" if kind == "wheel" else ".tar.gz"
        filename = next(row["filename"] for row in manifest["files"] if row["filename"].endswith(suffix))
        _success([*pip, "install", "--no-index", "--no-deps", "--no-cache-dir", "--no-compile",
                  "--no-build-isolation", dist / filename], env, prefix=prefix)
        records.append({"kind": kind, "install_exit": 0, "probes": _probes(pin, root, env, prefix, functional)})
        if kind == "sdist":
            rebuilt = work / "rebuilt"
            _success([*pip, "wheel", "--no-index", "--no-deps", "--no-cache-dir", "--no-build-isolation",
                      "--wheel-dir", rebuilt, dist / filename], env, prefix=prefix)
            expected = next(row["filename"] for row in manifest["files"] if row["filename"].endswith(".whl"))
            if physical_bytes(rebuilt / expected) != physical_bytes(dist / expected):
                fail("SDIST_MATCH")
        _success([*pip, "uninstall", "--yes", pin["project"]], env, prefix=prefix)
        if _inventory(root) != before:
            fail("UNINSTALL")
    return {"project": pin["project"], "target": target, "system": system, "python": platform.python_version(),
            "node": _success([node, "--version"], env).stdout.decode().strip(),
            "set_sha256": manifest["set_sha256"], "lifecycle": records,
            "offline_isolation": isolation, "functional": functional,
            "publication_admitted": False}


def network_denial(python, node, env, prefix=()):
    py = """import socket,json
r={}
for host in ['1.1.1.1','registry.npmjs.org']:
 s=socket.socket();s.settimeout(2)
 try:s.connect((host,443));r[host]=0
 except OSError as e:r[host]=e.errno
 finally:s.close()
print(json.dumps(r))
"""
    js = """const net=require('node:net'),dns=require('node:dns');
const s=net.connect(443,'1.1.1.1');
s.on('connect',()=>{console.log('TCP_CONNECTED');s.destroy()});
s.on('error',e=>console.log(e.code));
s.setTimeout(2000,()=>{console.log('TCP_TIMEOUT');s.destroy()});
dns.lookup('registry.npmjs.org',(e)=>console.log(e?e.code:'DNS_CONNECTED'));
"""
    a = _success([python, '-I', '-B', '-c', py], env, prefix=prefix)
    b = _success([node, '-e', js], env, prefix=prefix)
    has_unshare_net = "unshare" in prefix and "--net" in prefix
    try:
        facts = json.loads(a.stdout)
        permitted_errors = {errno.EPERM, errno.EACCES} | ({errno.ENETUNREACH} if has_unshare_net else set())
        if facts.get('1.1.1.1') not in permitted_errors or not facts.get('registry.npmjs.org'):
            fail('OFFLINE_ISOLATION')
        tokens = b.stdout.decode().splitlines()
        tcp_tokens = {'EPERM', 'EACCES'} | ({'ENETUNREACH'} if has_unshare_net else set())
        dns_tokens = {'ENOTFOUND', 'EAI_AGAIN', 'EPERM', 'EACCES'} | ({'ENETUNREACH'} if has_unshare_net else set())
        if not (tcp_tokens & set(tokens)) or not (dns_tokens & set(tokens)):
            fail('OFFLINE_ISOLATION')
        if any(x in tokens for x in ['TCP_CONNECTED', 'TCP_TIMEOUT', 'DNS_CONNECTED']):
            fail('OFFLINE_ISOLATION')
    except (ValueError, UnicodeError):
        fail('OFFLINE_ISOLATION')
    return {'method': 'explicit-isolation-prefix' if prefix else 'inherited-provider-sandbox',
            'python_tcp_errno': facts['1.1.1.1'], 'python_dns_errno': facts['registry.npmjs.org'],
            'node_denials': tokens, 'network_disabled': True}


# Gate 2 is deliberately separate from the historical Stellar wheel/sdist
# smoke path above.  It consumes a closed Nebular 0.7 candidate receipt and
# authenticated release capture, then drives the installed wheel's launcher
# through a declared native/sidecar probe.  The implementation has no build,
# archive-download, registry, or publication capability.
NEBULAR070_CONSUMER_SCHEMA = "rs9.nebular070-native-consumer.v1"
NEBULAR070_TARGET_SYSTEMS = {
    "darwin-arm64": "aarch64-darwin",
    "linux-arm64-gnu": "aarch64-linux",
    "linux-x64-gnu": "x86_64-linux",
}
_NEBULAR_HEX40 = re.compile(r"[0-9a-f]{40}")
_NEBULAR_HEX64 = re.compile(r"[0-9a-f]{64}")
_NEBULAR_MAX_OUTPUT = 1024 * 1024
# Retained release metadata measures 47,079,690 bytes for the largest known
# native archive and 46,792,720 bytes for its wheel.  Keep a measured 64 MiB
# ceiling; a future larger artifact needs a new measured contract, not a
# silent cap widening.
_NEBULAR_MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
_NEBULAR_IO_CHUNK = 64 * 1024
_NEBULAR_TERMINATION_GRACE = 0.5
_NEBULAR_DRAIN_GRACE = 0.5


def _nebular_grace_deadline(current: float | None, now: float) -> float:
    """Keep the first termination grace deadline stable across loop checks."""
    return current if current is not None else now + _NEBULAR_TERMINATION_GRACE


def _nebular_safe_rel(value: Any) -> str:
    if (not isinstance(value, str) or not value or not value.isascii()
            or value.startswith("/") or "\\" in value or ":" in value
            or "\x00" in value):
        fail("NEBULAR_CAPTURE_PATH")
    parts = value.split("/")
    if any(part in ("", ".", "..") for part in parts):
        fail("NEBULAR_CAPTURE_PATH")
    return value


def _nebular_descriptor(root: Path, descriptor: Mapping[str, Any], label: str,
                        *, limit: int = _NEBULAR_MAX_ARTIFACT_BYTES) -> tuple[bytes, str]:
    if not isinstance(descriptor, Mapping):
        fail("NEBULAR_CAPTURE_BINDING")
    path = _nebular_safe_rel(descriptor.get("path"))
    size = descriptor.get("size")
    digest = descriptor.get("sha256")
    if (type(size) is not int or size <= 0 or size > limit
            or not isinstance(digest, str) or not _NEBULAR_HEX64.fullmatch(digest)):
        fail("NEBULAR_CAPTURE_BINDING")
    if root.is_symlink() or not root.is_dir():
        fail("NEBULAR_CAPTURE_ROOT")
    target = root.joinpath(*path.split("/"))
    try:
        target.relative_to(root)
    except ValueError:
        fail("NEBULAR_CAPTURE_PATH")
    if target.is_symlink() or not target.is_file():
        fail("NEBULAR_CAPTURE_BINDING")
    data = physical_bytes(target, limit=limit)
    if len(data) != size or sha256(data) != digest:
        fail("NEBULAR_CAPTURE_BINDING")
    return data, digest


def _nebular_source(value: Any) -> dict[str, Any]:
    if (not isinstance(value, Mapping)
            or set(value) != {"status", "binding", "commit", "tree", "verified"}
            or value.get("status") != "candidate-input"
            or value.get("binding") != "explicit-reviewed-source-input"
            or value.get("verified") is not False
            or not isinstance(value.get("commit"), str)
            or not _NEBULAR_HEX40.fullmatch(value["commit"])
            or not isinstance(value.get("tree"), str)
            or not _NEBULAR_HEX40.fullmatch(value["tree"])):
        fail("NEBULAR_SOURCE_BINDING")
    return dict(value)


def _nebular_identity(value: Any) -> dict[str, Any]:
    required = {"repository", "tag", "commit", "tree", "release_record_sha256"}
    if not isinstance(value, Mapping) or not required <= set(value):
        fail("NEBULAR_RELEASE_BINDING")
    if (not isinstance(value.get("repository"), str)
            or not isinstance(value.get("tag"), str)
            or not _NEBULAR_HEX40.fullmatch(str(value.get("commit")))
            or not _NEBULAR_HEX40.fullmatch(str(value.get("tree")))
            or not _NEBULAR_HEX64.fullmatch(str(value.get("release_record_sha256")))):
        fail("NEBULAR_RELEASE_BINDING")
    return {key: value[key] for key in required}


_NEBULAR_NATIVE_RC_PLATFORMS = {
    "darwin-arm64": "darwin-arm64",
    "linux-arm64-gnu": "linux-arm64",
    "linux-x64-gnu": "linux-x64",
}
_NEBULAR_NATIVE_RC_TRIPLES = {
    "darwin-arm64": "aarch64-apple-darwin",
    "linux-arm64-gnu": "aarch64-unknown-linux-gnu",
    "linux-x64-gnu": "x86_64-unknown-linux-gnu",
}
_NEBULAR_NATIVE_RC_SCENARIOS = {
    "darwin-arm64": {"raw-archive": "A", "npm-package": "A"},
    "linux-arm64-gnu": {"raw-archive": "B", "npm-package": "B"},
    "linux-x64-gnu": {"raw-archive": "C", "npm-package": "C-signal"},
}
_NEBULAR_ARCHIVE_ROOTS = {
    "darwin-arm64": "Theme Forge Nebular Fusion.app",
    "linux-arm64-gnu": "theme-forge-nebular-fusion",
    "linux-x64-gnu": "theme-forge-nebular-fusion",
}
_NEBULAR_NATIVE_ROLE_RELATIVE = {
    "darwin-arm64": {
        "gui": "Contents/MacOS/theme-forge-nebular-fusion",
        "launcher": "Contents/Resources/bin/tfnf",
        "sidecar": "Contents/MacOS/tfsb-studio-service",
    },
    "linux-arm64-gnu": {
        "gui": "bin/theme-forge-nebular-fusion",
        "launcher": "bin/tfnf",
        "sidecar": "bin/tfsb-studio-service",
    },
    "linux-x64-gnu": {
        "gui": "bin/theme-forge-nebular-fusion",
        "launcher": "bin/tfnf",
        "sidecar": "bin/tfsb-studio-service",
    },
}
_NEBULAR_NATIVE_RC_STEPS = {
    "A": ("app-shell", "host-start", "host-status", "project-open", "brand-read", "theme-lab-compile", "app-theme-status", "app-theme-compile", "brand-system-view", "host-status-final"),
    "B": ("app-shell", "app-theme-status", "app-theme-compile", "theme-lab-compile", "brand-system-view", "host-start", "host-status", "project-open-upper", "brand-read-upper", "project-open-lower", "brand-read-lower", "host-status-final"),
    "C": ("app-shell", "host-start", "host-start-idempotent", "host-stop", "host-start-again", "host-status", "project-open-case", "derive-plan-cancel", "derive-plan-apply", "host-status-final"),
    "C-signal": ("app-shell", "host-start", "host-start-idempotent", "host-stop", "host-start-again", "host-status", "project-open-case", "derive-plan-cancel", "derive-plan-apply", "host-status-final"),
}
_NEBULAR_EXPECTED_WHEEL_TAGS = {
    "darwin-arm64": "py3-none-macosx_13_0_arm64",
    "linux-arm64-gnu": "py3-none-linux_aarch64",
    "linux-x64-gnu": "py3-none-linux_x86_64",
}
_NEBULAR_LICENSE_EXPRESSION = "AGPL-3.0-or-later"
_NEBULAR_LINUX_RUNTIME_POLICY = {
    "wheel_tag_policy": "generic-linux",
    "glibc_floor": "2.36",
    "glibcxx_floor": "3.4.30",
    "provider_baseline": "manylinux236-named-provenance-only",
    "manylinux_claim": False,
    "dynamic_closure": "pending",
}
_NEBULAR_DARWIN_FLOOR = {"major": 13, "minor": 0}


def _nebular_lineage_sha(value: Any) -> str:
    if (not isinstance(value, Mapping)
            or not _NEBULAR_HEX64.fullmatch(str(value.get("provenance_sha256")))):
        fail("NEBULAR_PROVENANCE_BINDING")
    return str(value["provenance_sha256"])


def _nebular_floor_evidence(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        fail("NEBULAR_FLOOR_BINDING")
    if (value.get("schema") != "rs9.darwin-floor-evidence.v1alpha1"
            or value.get("status") != "cross-checked"
            or value.get("required_floor") != _NEBULAR_DARWIN_FLOOR
            or value.get("info_plist") != _NEBULAR_DARWIN_FLOOR):
        fail("NEBULAR_FLOOR_BINDING")
    macho = value.get("macho")
    scripts = value.get("scripts")
    if (not isinstance(macho, list) or not macho or not isinstance(scripts, list) or not scripts
            or any(not isinstance(row, Mapping)
                   or row.get("major") != _NEBULAR_DARWIN_FLOOR["major"]
                   or row.get("minor") != _NEBULAR_DARWIN_FLOOR["minor"]
                   or not isinstance(row.get("path"), str)
                   or not isinstance(row.get("role"), str)
                   for row in macho)
            or any(not isinstance(row, Mapping) or row.get("role") != "script"
                   or not isinstance(row.get("path"), str) for row in scripts)):
        fail("NEBULAR_FLOOR_BINDING")
    return dict(value)


def _nebular_native_role_paths(target: str, manifest: Mapping[str, Any]) -> dict[str, str]:
    expected_root = _NEBULAR_ARCHIVE_ROOTS.get(target)
    relatives = _NEBULAR_NATIVE_ROLE_RELATIVE.get(target)
    if expected_root is None or relatives is None or manifest.get("root") != expected_root:
        fail("NEBULAR_NATIVE_CONTRACT")
    # native-rc-smoke reports a path relative to its launchRoot.  The
    # maintained current tool passes the Darwin bundle's parent as launchRoot,
    # so Darwin retains the app-bundle prefix; Linux reports its bin-relative
    # path.  Materialization, in contrast, returns payload/<archive-root> and
    # therefore needs the canonical archive-root-relative member path below.
    smoke_gui = (f"{expected_root}/{relatives['gui']}"
                 if target.startswith("darwin") else relatives["gui"])
    return {
        "root": expected_root,
        **{role: f"{expected_root}/{relative}" for role, relative in relatives.items()},
        "runtime_gui": smoke_gui,
        "smoke_gui": smoke_gui,
        "materialized_gui": f"{expected_root}/{relatives['gui']}",
    }


def _nebular_profile_contract(candidate: Mapping[str, Any], row: Mapping[str, Any], target: str) -> dict[str, Any]:
    expected_tag = _NEBULAR_EXPECTED_WHEEL_TAGS.get(target)
    if expected_tag is None:
        fail("NEBULAR_TARGET")
    license_info = candidate.get("license")
    profile = candidate.get("profile")
    if (not isinstance(license_info, Mapping)
            or license_info.get("expression") != _NEBULAR_LICENSE_EXPRESSION
            or not isinstance(profile, Mapping)
            or profile.get("license_expression") != _NEBULAR_LICENSE_EXPRESSION
            or profile.get("darwin_floor") != _NEBULAR_DARWIN_FLOOR
            or profile.get("linux_runtime_policy") != _NEBULAR_LINUX_RUNTIME_POLICY
            or candidate.get("linux_runtime_policy") != _NEBULAR_LINUX_RUNTIME_POLICY):
        fail("NEBULAR_LICENSE")
    row_profile = row.get("candidate_profile")
    source_legal = row.get("source_legal_profile")
    if (not isinstance(row_profile, Mapping)
            or row_profile.get("license_expression") != _NEBULAR_LICENSE_EXPRESSION
            or row_profile.get("linux_runtime_policy") != _NEBULAR_LINUX_RUNTIME_POLICY
            or not isinstance(source_legal, Mapping)
            or source_legal.get("expression") != _NEBULAR_LICENSE_EXPRESSION):
        fail("NEBULAR_LICENSE")
    wheel = row.get("wheel")
    if not isinstance(wheel, Mapping) or wheel.get("tag") != expected_tag:
        fail("NEBULAR_WHEEL_BINDING")
    floor = row.get("darwin_floor_evidence")
    if target == "darwin-arm64":
        floor = _nebular_floor_evidence(floor)
        if candidate.get("darwin_floor_evidence") != floor:
            fail("NEBULAR_FLOOR_BINDING")
    elif floor is not None:
        fail("NEBULAR_FLOOR_BINDING")
    return {
        "license_expression": _NEBULAR_LICENSE_EXPRESSION,
        "linux_runtime_policy": _NEBULAR_LINUX_RUNTIME_POLICY,
        "darwin_floor_evidence": floor,
        "wheel_tag": expected_tag,
    }


def _nebular_json_descriptor(root: Path, descriptor: Any, label: str,
                             *, limit: int = 16 * 1024 * 1024) -> tuple[dict[str, Any], str]:
    data, digest = _nebular_descriptor(root, descriptor, label, limit=limit)
    try:
        value = strict_json(data)
    except Exception:
        fail("NEBULAR_NATIVE_EVIDENCE")
    if not isinstance(value, Mapping):
        fail("NEBULAR_NATIVE_EVIDENCE")
    return dict(value), digest


def _nebular_payload_member(root: Path, payload: bytes, member: Mapping[str, Any]) -> bytes:
    """Read one authenticated payload member for the controlled fixture path."""
    path = _nebular_safe_rel(member.get("path"))
    expected_sha = member.get("sha256")
    expected_size = member.get("size")
    if (type(expected_size) is not int or expected_size <= 0
            or expected_size > _NEBULAR_MAX_ARTIFACT_BYTES
            or not _NEBULAR_HEX64.fullmatch(str(expected_sha))):
        fail("NEBULAR_NATIVE_CONTRACT")
    # The raw-release root contains descriptors and the archive itself; it is
    # not an alternate source of executable bytes.  Read the member from the
    # authenticated payload archive so a same-named side file cannot satisfy
    # the Gate1 manifest while the shipped payload is different.
    try:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
            item = archive.getmember(path)
            if not item.isfile():
                fail("NEBULAR_NATIVE_CONTRACT")
            stream = archive.extractfile(item)
            data = stream.read(_NEBULAR_MAX_ARTIFACT_BYTES + 1) if stream is not None else b""
    except (KeyError, OSError, tarfile.TarError, EOFError):
        fail("NEBULAR_NATIVE_CONTRACT")
    if len(data) != expected_size or sha256(data) != expected_sha:
        fail("NEBULAR_NATIVE_CONTRACT")
    return data


def _nebular_check_rows(receipt: Mapping[str, Any], required: Sequence[str]) -> dict[str, dict[str, Any]]:
    rows = receipt.get("checks")
    if not isinstance(rows, list):
        fail("NEBULAR_NATIVE_EVIDENCE")
    by_id: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, Mapping) or not isinstance(row.get("id"), str) or row["id"] in by_id:
            fail("NEBULAR_NATIVE_EVIDENCE")
        by_id[row["id"]] = dict(row)
    for check_id in required:
        row = by_id.get(check_id)
        if row is None or row.get("ok") is not True or "detail" not in row:
            fail("NEBULAR_NATIVE_EVIDENCE")
    return by_id


def _nebular_native_evidence(root: Path, native: Mapping[str, Any], *, target: str,
                             fixture_only: bool,
                             loader: Mapping[str, Any], gui: Mapping[str, Any],
                             sidecar: Mapping[str, Any],
                             provider: Mapping[str, Any]) -> dict[str, Any]:
    """Bind Gate 2 to maintained native-rc qualification and smoke receipts.

    The old contract accepted caller-provided ``verified`` booleans and a
    stdout token.  These receipts are emitted by the maintained C82 tools:
    qualification checks, the raw/npm smoke runs, their full application
    receipts, and the exact executable digest all have to agree.
    """
    native_platform = _NEBULAR_NATIVE_RC_PLATFORMS.get(target)
    if native_platform is None:
        fail("NEBULAR_NATIVE_EVIDENCE")
    qualification, qualification_digest = _nebular_json_descriptor(
        root, native.get("qualification"), "native-rc qualification",
    )
    if (qualification.get("schema") != "nebular.native-rc-qualification-v1"
            or qualification.get("platform") != native_platform
            or qualification.get("status") != "pass"):
        fail("NEBULAR_NATIVE_EVIDENCE")
    executable_sha = qualification.get("executableSha256")
    if not isinstance(executable_sha, str) or not _NEBULAR_HEX64.fullmatch(executable_sha):
        fail("NEBULAR_NATIVE_EVIDENCE")
    if executable_sha != gui.get("sha256"):
        fail("NEBULAR_NATIVE_EVIDENCE")
    if len({loader.get("sha256"), gui.get("sha256"), sidecar.get("sha256")}) != 3:
        fail("NEBULAR_NATIVE_EVIDENCE")
    if target.startswith("linux"):
        required = ("executable-header", "launcher", "sidecar-runtime", "mode:gui",
                    "mode:sidecar", "mode:launcher", "glibc:gui", "glibc:sidecar",
                    "glibc-floor", "linkage", "private-runtime-closure")
    else:
        required = ("executable-header", "launcher", "sidecar-runtime", "legal-notices", "codesign")
    checks = _nebular_check_rows(qualification, required)
    launcher_detail = checks["launcher"].get("detail")
    if launcher_detail != loader.get("sha256"):
        fail("NEBULAR_NATIVE_EVIDENCE")
    sidecar_detail = checks["sidecar-runtime"].get("detail")
    if not isinstance(sidecar_detail, str):
        fail("NEBULAR_NATIVE_EVIDENCE")
    sidecar_digests = _NEBULAR_HEX64.findall(sidecar_detail)
    if not sidecar_digests or sidecar_digests[-1] != sidecar.get("sha256"):
        fail("NEBULAR_NATIVE_EVIDENCE")
    if (loader.get("status") != "verified"
            or loader.get("qualification_check_id") != "launcher"):
        fail("NEBULAR_NATIVE_EVIDENCE")
    provider_check_id = "private-runtime-closure" if target.startswith("linux") else "sidecar-runtime"
    provider_detail = checks[provider_check_id].get("detail")
    if target.startswith("linux"):
        if (not isinstance(provider_detail, Mapping)
                or not _NEBULAR_HEX64.fullmatch(str(provider_detail.get("observationIdentity")))
                or not isinstance(provider_detail.get("observedProviderRows"), list)
                or not provider_detail["observedProviderRows"]
                or not isinstance(provider_detail.get("subjectResolutionRows"), list)
                or not provider_detail["subjectResolutionRows"]
                or not isinstance(provider_detail.get("toolEvidence"), Mapping)
                or provider_detail["toolEvidence"].get("readelfRole") != "actual-provider-terminal-readelf"
                or provider_detail["toolEvidence"].get("resolutionToolRole") != "actual-consumer-ldd"
                or provider_detail["toolEvidence"].get("cleanupFacts", {}).get("noSurvivingProcessFamily") is not True):
            fail("NEBULAR_NATIVE_EVIDENCE")
    provider_detail_digest = sha256(canonical(provider_detail))
    smoke = native.get("smoke")
    if not isinstance(smoke, Mapping):
        fail("NEBULAR_NATIVE_EVIDENCE")
    runs: dict[str, dict[str, Any]] = {}
    receipts: dict[str, dict[str, Any]] = {}
    for source, scenario in _NEBULAR_NATIVE_RC_SCENARIOS[target].items():
        entry = smoke.get(source)
        if not isinstance(entry, Mapping):
            fail("NEBULAR_NATIVE_EVIDENCE")
        run, run_digest = _nebular_json_descriptor(root, entry.get("run"), f"native-rc smoke {source}")
        receipt, receipt_digest = _nebular_json_descriptor(root, entry.get("receipt"), f"native-rc receipt {source}")
        if (run.get("schema") != "nebular.native-rc-smoke-run-v1"
                or run.get("status") != "pass"
                or run.get("platform") != native_platform
                or run.get("scenario") != scenario
                or run.get("source") != source
                or run.get("problems") != []
                or run.get("executable", {}).get("path") != gui.get("smoke_path")
                or run.get("executable", {}).get("sha256") != executable_sha
                or run.get("receipt", {}).get("status") != "pass"
                or run.get("receipt", {}).get("sha256") != receipt_digest):
            fail("NEBULAR_NATIVE_EVIDENCE")
        run_checks = run.get("checks")
        if (not isinstance(run_checks, Mapping)
                or run_checks.get("orphans") != []
                or not isinstance(run_checks.get("persistentUserState"), Mapping)
                or run_checks["persistentUserState"].get("changed") != []
                or not isinstance(run_checks.get("scratchHomeWrites"), int)
                or not isinstance(run.get("finalization"), Mapping)
                or run["finalization"].get("status") != "complete"
                or run["finalization"].get("exitObserved") is not True
                or run["finalization"].get("applicationReceiptObservation") != "present-at-read"
                or run["finalization"].get("applicationReceiptCopy") != "written"):
            fail("NEBULAR_NATIVE_EVIDENCE")
        expected_steps = _NEBULAR_NATIVE_RC_STEPS[scenario]
        receipt_steps = receipt.get("driver", {}).get("steps")
        by_step = {step.get("id"): step for step in receipt_steps} if isinstance(receipt_steps, list) else {}
        triple = _NEBULAR_NATIVE_RC_TRIPLES[target]
        if (receipt.get("schema") != "nebular.release-smoke-receipt-v1"
                or receipt.get("scenario") != scenario
                or receipt.get("status") != "pass"
                or receipt.get("target") != triple
                or receipt.get("executable", {}).get("sha256") != executable_sha
                or receipt.get("awaitingSignal") is not (scenario == "C-signal")
                or any(not isinstance(by_step.get(step_id), Mapping) or by_step[step_id].get("ok") is not True
                       for step_id in expected_steps)):
            fail("NEBULAR_NATIVE_EVIDENCE")
        runs[source] = {"sha256": run_digest, "scenario": scenario}
        receipts[source] = {"sha256": receipt_digest, "scenario": scenario}
    provider_evidence = {
        "qualification_sha256": qualification_digest,
        "qualification_check_id": provider_check_id,
        "qualification_detail_sha256": provider_detail_digest,
        "smoke_receipts": {source: receipts[source]["sha256"] for source in sorted(receipts)},
    }
    if (provider.get("status") != "verified"
            or provider.get("target") != target
            or provider.get("mode") != ("controlled-fixture" if fixture_only else "host-observed")
            or provider.get("emulated") is not False
            or provider.get("qualification_check_id") != provider_check_id
            or provider.get("evidence_sha256") != sha256(canonical(provider_evidence))):
        fail("NEBULAR_PROVIDER_CLOSURE")
    return {
        "qualification_sha256": qualification_digest,
        "qualification": qualification,
        "smoke_runs": runs,
        "smoke_receipts": receipts,
        "executable_sha256": executable_sha,
        "launcher_sha256": loader["sha256"],
        "sidecar_sha256": sidecar["sha256"],
        "provider_evidence": provider_evidence,
    }


def _nebular_candidate_row(candidate: Mapping[str, Any], target: str) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    if (not isinstance(candidate, Mapping)
            or candidate.get("schema") != "rs9.nebular-successor-candidate.v2alpha1"
            or candidate.get("application_version") != "0.7.0"
            or candidate.get("distribution_version") != "0.7.0"):
        fail("NEBULAR_CANDIDATE_SCHEMA")
    flags = candidate.get("flags")
    if flags != {
        "candidate_only": True,
        "builder_can_publish": False,
        "can_publish": False,
        "publication_admitted": False,
        "manylinux_proven": False,
    }:
        fail("NEBULAR_PUBLICATION_HOLD")
    if candidate.get("qualification_rs9_source") != {"status": "not-run", "reason": "gate1-only"}:
        fail("NEBULAR_CANDIDATE_SCHEMA")
    source = _nebular_source(candidate.get("candidate_rs9_source"))
    identity = _nebular_identity(candidate.get("source_identity"))
    rows = candidate.get("rows")
    if not isinstance(rows, list) or len(rows) != 3:
        fail("NEBULAR_CANDIDATE_ROWS")
    systems = {system for system in NEBULAR070_TARGET_SYSTEMS.values()}
    if {row.get("system") for row in rows if isinstance(row, Mapping)} != systems:
        fail("NEBULAR_CANDIDATE_ROWS")
    system = NEBULAR070_TARGET_SYSTEMS.get(target)
    if system is None:
        fail("NEBULAR_TARGET")
    row = next((row for row in rows if isinstance(row, Mapping) and row.get("system") == system), None)
    if not isinstance(row, dict) or row.get("candidate_rs9_source") != source:
        fail("NEBULAR_CANDIDATE_ROWS")
    direct_lineage = candidate.get("direct_lineage")
    direct_lineage_sha = _nebular_lineage_sha(direct_lineage)
    row_lineage = row.get("forward_lineage")
    if (_nebular_lineage_sha(row_lineage) != direct_lineage_sha
            or row_lineage != direct_lineage):
        fail("NEBULAR_PROVENANCE_BINDING")
    wheel = row.get("wheel")
    if (not isinstance(wheel, Mapping)
            or set(("filename", "sha256", "size", "tag", "version")) - set(wheel)
            or wheel.get("version") != "0.7.0"
            or not isinstance(wheel.get("filename"), str)
            or not _NEBULAR_HEX64.fullmatch(str(wheel.get("sha256")))
            or type(wheel.get("size")) is not int or wheel.get("size") <= 0):
        fail("NEBULAR_CANDIDATE_WHEEL")
    if (row.get("source_identity") != identity
            or not isinstance(row.get("payload_archive_name"), str)
            or not _NEBULAR_HEX64.fullmatch(str(row.get("payload_archive_sha256")))
            or not _NEBULAR_HEX64.fullmatch(str(row.get("manifest_sha256")))):
        fail("NEBULAR_CANDIDATE_BINDING")
    profile_contract = _nebular_profile_contract(candidate, row, target)
    return dict(row), dict(wheel), {
        "source": source,
        "identity": identity,
        "direct_lineage": dict(direct_lineage),
        "profile_contract": profile_contract,
    }


def _nebular_process_snapshot(work: Path, *, runner: Callable[..., Any] = subprocess.run) -> dict[str, Any]:
    ps = shutil.which("ps", path="/usr/bin:/bin") or "/bin/ps"
    try:
        result = runner([ps, "-axww", "-o", "pid=,command="], capture_output=True,
                        env={"PATH": "/usr/bin:/bin"}, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError):
        fail("NEBULAR_PROCESS_OBSERVER")
    if result.returncode != 0 or len(result.stdout or b"") > _NEBULAR_MAX_OUTPUT:
        fail("NEBULAR_PROCESS_OBSERVER")
    needle = str(work.resolve()).encode("utf-8")
    rows = []
    for line in (result.stdout or b"").splitlines():
        if needle not in line:
            continue
        fields = line.strip().split(None, 1)
        if not fields or fields[0] == str(os.getpid()).encode("ascii"):
            continue
        rows.append(sha256(line))
    return {"orphan_count": len(rows), "observation_sha256": sha256(canonical(sorted(rows)))}


def _nebular_state_snapshot(home: Path, relatives: Sequence[str]) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for relative in relatives:
        rel = _nebular_safe_rel(relative)
        path = home.joinpath(*rel.split("/"))
        if path.is_symlink():
            rows.append({"path": rel, "kind": "symlink", "target_sha256": sha256(os.readlink(path).encode())})
            continue
        if not path.exists():
            rows.append({"path": rel, "kind": "absent"})
            continue
        if path.is_file():
            data = physical_bytes(path, limit=16 * 1024 * 1024)
            rows.append({"path": rel, "kind": "file", "size": len(data), "sha256": sha256(data)})
            continue
        if not path.is_dir():
            fail("NEBULAR_USER_STATE")
        count = 0
        for directory, dirs, files in os.walk(path, followlinks=False):
            for name in sorted(dirs + files):
                child = Path(directory) / name
                child_rel = child.relative_to(home).as_posix()
                if child.is_symlink():
                    rows.append({"path": child_rel, "kind": "symlink",
                                 "target_sha256": sha256(os.readlink(child).encode())})
                elif child.is_file():
                    data = physical_bytes(child, limit=16 * 1024 * 1024)
                    rows.append({"path": child_rel, "kind": "file", "size": len(data), "sha256": sha256(data)})
                elif not child.is_dir():
                    fail("NEBULAR_USER_STATE")
                count += 1
                if count > 512 or len(rows) > 2048:
                    fail("NEBULAR_USER_STATE")
        rows.append({"path": rel, "kind": "directory"})
    ordered = sorted(rows, key=lambda row: (row["path"], row["kind"]))
    return {"target_count": len(relatives), "entry_count": len(ordered),
            "sha256": sha256(canonical(ordered))}


def _nebular_real_user_state(value: Any, *, target: str, phase: str) -> dict[str, Any]:
    """Validate the maintained native-rc-smoke persistent-state observation.

    Production callers must supply this callback; the scratch HOME snapshot is
    only an isolation check and is never treated as the real-user invariant.
    The callback is expected to use the maintained
    ``persistentStateLocations``/``snapshotLocations`` protocol.
    """
    if (not isinstance(value, Mapping)
            or value.get("schema") != "nebular.native-rc-persistent-user-state-v1"
            or value.get("method") != "native-rc-smoke.persistentStateLocations+snapshotLocations"
            or value.get("scope") != "real-user-state"
            or value.get("target") != target
            or value.get("phase") != phase
            or type(value.get("locations")) is not int or value["locations"] <= 0
            or not _NEBULAR_HEX64.fullmatch(str(value.get("snapshot_sha256")))
            or not isinstance(value.get("changed"), list)):
        fail("NEBULAR_USER_STATE_GUARD")
    if value["changed"]:
        fail("NEBULAR_USER_STATE_GUARD")
    return dict(value)


def _nebular_group_exists(pid: int) -> bool:
    try:
        os.killpg(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError as error:
        return error.errno != errno.ESRCH


def _nebular_signal_group(child: Any, signal_number: int) -> bool:
    try:
        os.killpg(child.pid, signal_number)
        return True
    except ProcessLookupError:
        return False
    except OSError:
        try:
            child.send_signal(signal_number)
            return True
        except (OSError, AttributeError):
            return False


def _nebular_run(argv: Sequence[str], env: Mapping[str, str], cwd: Path,
                 prefix: Sequence[str], timeout: int, *, runner: Any = subprocess.Popen) -> dict[str, Any]:
    """Run one probe with streaming bounded pipes and process-group cleanup.

    ``Popen.communicate`` is intentionally not used: a hostile or faulty
    consumer must not make the qualification process retain unbounded output
    before the size check runs.  The child starts a fresh process group; TERM
    then KILL are bounded and all remaining pipe bytes are discarded after the
    cap is reached.
    """
    command = [*map(str, prefix), *map(str, argv)]
    try:
        child = runner(command, cwd=str(cwd), env=dict(env), stdin=subprocess.DEVNULL,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    except (OSError, subprocess.SubprocessError):
        fail("NEBULAR_NATIVE_EXECUTION")
    streams: dict[int, tuple[str, Any]] = {}
    selector = selectors.DefaultSelector()
    output = {"stdout": bytearray(), "stderr": bytearray()}
    total = 0
    stream_error: str | None = None
    timed_out = False
    output_limit_exceeded = False
    forced_cleanup = False
    termination_reason: str | None = None
    term_sent = False
    kill_sent = False
    cleanup_deadline: float | None = None
    post_exit_deadline: float | None = None
    started = time.monotonic()
    try:
        for name, stream in (("stdout", child.stdout), ("stderr", child.stderr)):
            if stream is None:
                continue
            fd = stream.fileno()
            os.set_blocking(fd, False)
            selector.register(fd, selectors.EVENT_READ, (name, stream))
            streams[fd] = (name, stream)

        def request_termination(reason: str, *, timeout_reason: bool = False) -> None:
            nonlocal cleanup_deadline, forced_cleanup, termination_reason, timed_out, term_sent
            forced_cleanup = True
            termination_reason = termination_reason or reason
            timed_out = timed_out or timeout_reason
            if not term_sent:
                _nebular_signal_group(child, signal.SIGTERM)
                term_sent = True
            cleanup_deadline = _nebular_grace_deadline(cleanup_deadline, time.monotonic())

        def escalate() -> None:
            nonlocal cleanup_deadline, forced_cleanup, kill_sent
            forced_cleanup = True
            if not kill_sent:
                _nebular_signal_group(child, signal.SIGKILL)
                kill_sent = True
            cleanup_deadline = time.monotonic() + _NEBULAR_TERMINATION_GRACE

        deadline = time.monotonic() + max(0.0, float(timeout))
        while True:
            now = time.monotonic()
            code = child.poll()
            if code is None and now >= deadline:
                request_termination("native probe timeout", timeout_reason=True)
            elif code is not None and post_exit_deadline is None:
                post_exit_deadline = now + _NEBULAR_DRAIN_GRACE
                if _nebular_group_exists(child.pid):
                    request_termination("native probe descendant cleanup")
            if cleanup_deadline is not None and now >= cleanup_deadline and not kill_sent:
                escalate()
            if code is not None and streams and post_exit_deadline is not None and now >= post_exit_deadline:
                stream_error = stream_error or "native probe output streams did not close after leader exit"
                for fd, (_name, stream) in list(streams.items()):
                    try:
                        selector.unregister(fd)
                    except (KeyError, ValueError):
                        pass
                    try:
                        stream.close()
                    except OSError:
                        pass
                    streams.pop(fd, None)
                forced_cleanup = True
            # A reaped leader and closed pipes do not prove that its created
            # process group has disappeared.  Finish the already-started
            # post-exit/cleanup grace before returning the group observation;
            # never extend the production deadlines or admit a surviving or
            # unobservable group as clean.
            if (code is not None and not streams
                    and post_exit_deadline is not None
                    and now >= post_exit_deadline
                    and (cleanup_deadline is None or now >= cleanup_deadline)):
                break
            if code is None and kill_sent and cleanup_deadline is not None and now >= cleanup_deadline:
                try:
                    child.kill()
                except OSError:
                    pass
                try:
                    child.wait(timeout=_NEBULAR_TERMINATION_GRACE)
                except subprocess.TimeoutExpired:
                    stream_error = stream_error or "native probe process did not terminate after SIGKILL"
                code = child.poll()
                # Let the next loop turn establish the post-exit observation
                # even when wait() reaped the leader after group escalation.

            wait_for = 0.05
            if code is None:
                wait_for = min(wait_for, max(0.001, deadline - now))
            if cleanup_deadline is not None:
                wait_for = min(wait_for, max(0.001, cleanup_deadline - now))
            if post_exit_deadline is not None:
                wait_for = min(wait_for, max(0.001, post_exit_deadline - now))
            events = selector.select(wait_for) if streams else []
            if not streams and not events:
                # An empty selector does not provide the bounded wait needed
                # to finish post-exit cleanup; keep the loop deadline-bound.
                time.sleep(wait_for)
            for key, _mask in events:
                fd = key.fd
                name, stream = key.data
                try:
                    chunk = os.read(fd, _NEBULAR_IO_CHUNK)
                except BlockingIOError:
                    continue
                except OSError as error:
                    stream_error = stream_error or str(error)
                    chunk = b""
                if not chunk:
                    try:
                        selector.unregister(fd)
                    except (KeyError, ValueError):
                        pass
                    try:
                        stream.close()
                    except OSError:
                        pass
                    streams.pop(fd, None)
                    continue
                if output_limit_exceeded:
                    continue
                remaining = _NEBULAR_MAX_OUTPUT - total
                if len(chunk) > remaining:
                    if remaining > 0:
                        output[name].extend(chunk[:remaining])
                        total += remaining
                    output_limit_exceeded = True
                    request_termination("native probe output limit exceeded")
                else:
                    output[name].extend(chunk)
                    total += len(chunk)
    finally:
        for fd, (_name, stream) in list(streams.items()):
            try:
                selector.unregister(fd)
            except (KeyError, ValueError):
                pass
            try:
                stream.close()
            except OSError:
                pass
        selector.close()
        if child.poll() is None:
            forced_cleanup = True
            _nebular_signal_group(child, signal.SIGKILL)
            try:
                child.wait(timeout=_NEBULAR_TERMINATION_GRACE)
            except subprocess.TimeoutExpired:
                stream_error = stream_error or "native probe process wait exceeded bound"

    code = child.poll()
    cleanup_known = code is not None and not _nebular_group_exists(child.pid)
    return {
        "exit_code": code,
        "signal": -code if isinstance(code, int) and code < 0 else None,
        "stdout_sha256": sha256(bytes(output["stdout"])),
        "stderr_sha256": sha256(bytes(output["stderr"])),
        "stdout_token": bytes(output["stdout"]).decode("utf-8", "replace"),
        "stderr_token": bytes(output["stderr"]).decode("utf-8", "replace"),
        "timed_out": timed_out,
        "output_limit_exceeded": output_limit_exceeded,
        "cleanup_known": cleanup_known,
        "output_complete": not output_limit_exceeded and stream_error is None and not streams,
        "forced_cleanup": forced_cleanup,
        "bounded": True,
        "termination_reason": termination_reason,
        "duration_ms": int((time.monotonic() - started) * 1000),
    }


def _nebular_identity_observed(host_identity: Mapping[str, Any] | None, target: str,
                               fixture_only: bool) -> dict[str, Any]:
    expected = NEBULAR070_TARGET_SYSTEMS.get(target)
    if expected is None:
        fail("NEBULAR_TARGET")
    if fixture_only:
        if (not isinstance(host_identity, Mapping)
                or host_identity.get("source") != "controlled-fixture"
                or host_identity.get("system") != expected):
            fail("NEBULAR_HOST_IDENTITY")
        return dict(host_identity)
    actual_system = platform.system()
    actual_machine = platform.machine().lower()
    actual = {"source": "runner", "system": expected, "machine": actual_machine}
    if target == "darwin-arm64" and (actual_system != "Darwin" or actual_machine not in {"arm64", "aarch64"}):
        fail("NEBULAR_HOST_IDENTITY")
    if target.startswith("linux") and (actual_system != "Linux" or
                                         (target == "linux-x64-gnu" and actual_machine not in {"x86_64", "amd64"}) or
                                         (target == "linux-arm64-gnu" and actual_machine not in {"aarch64", "arm64"}) or
                                         (platform.libc_ver()[0] or "").lower() != "glibc"):
        fail("NEBULAR_HOST_IDENTITY")
    return actual


def _nebular_validate_capture(candidate: Mapping[str, Any], row: Mapping[str, Any], context: Mapping[str, Any],
                              raw_release: Mapping[str, Any], *, target: str,
                              fixture_only: bool) -> dict[str, Any]:
    root_raw = raw_release.get("root")
    if not isinstance(root_raw, str) or not os.path.isabs(root_raw):
        fail("NEBULAR_CAPTURE_ROOT")
    root = Path(root_raw).resolve()
    identity = context["identity"]
    record_bytes, _ = _nebular_descriptor(root, raw_release.get("record"), "release-record")
    record = strict_json(record_bytes)
    record_identity = record.get("source_identity") if isinstance(record, Mapping) else None
    expected_record_identity = {key: identity[key] for key in ("repository", "tag", "commit", "tree")}
    if isinstance(record, Mapping) and record.get("schema") == "rs9.release-record.v1alpha1":
        record_repository = record.get("repository")
        record_release = record.get("release")
        record_tag = record.get("tag")
        record_identity = {
            "repository": record_repository.get("full_name") if isinstance(record_repository, Mapping) else None,
            "tag": record_release.get("tag") if isinstance(record_release, Mapping) else None,
            "commit": record_tag.get("commit") if isinstance(record_tag, Mapping) else None,
            "tree": record_tag.get("tree") if isinstance(record_tag, Mapping) else None,
        }
    if (not isinstance(record_identity, Mapping)
            or {key: record_identity.get(key) for key in expected_record_identity} != expected_record_identity
            or sha256(record_bytes) != identity["release_record_sha256"]):
        fail("NEBULAR_RELEASE_BINDING")
    readme = candidate.get("readme")
    readme_bytes, _ = _nebular_descriptor(root, raw_release.get("readme"), "README")
    if (not isinstance(readme, Mapping) or raw_release.get("readme", {}).get("path") != readme.get("path")
            or raw_release.get("readme", {}).get("sha256") != readme.get("sha256")):
        fail("NEBULAR_README_BINDING")
    legal_expected = candidate.get("legal_files")
    legal_descriptors = raw_release.get("legal_files")
    if not isinstance(legal_expected, Mapping) or not isinstance(legal_descriptors, Mapping):
        fail("NEBULAR_LEGAL_BINDING")
    for name, expected in legal_expected.items():
        if not isinstance(expected, Mapping) or expected.get("path") != name:
            fail("NEBULAR_LEGAL_BINDING")
        raw_desc = legal_descriptors.get(name)
        data, _ = _nebular_descriptor(root, raw_desc, "legal")
        if len(data) != expected.get("size") or sha256(data) != expected.get("sha256"):
            fail("NEBULAR_LEGAL_BINDING")
    provenance_bytes, provenance_digest = _nebular_descriptor(root, raw_release.get("provenance"), "PROVENANCE")
    provenance = strict_json(provenance_bytes)
    if (provenance_digest != context["direct_lineage"].get("provenance_sha256")
            or provenance_digest != row.get("forward_lineage", {}).get("provenance_sha256")):
        fail("NEBULAR_PROVENANCE_BINDING")
    direct_release = provenance.get("release") if isinstance(provenance, Mapping) else None
    provenance_matches_candidate = (
        isinstance(provenance, Mapping)
        and provenance.get("candidate_rs9_source") == context["source"]
        and provenance.get("source_identity") == identity
    )
    provenance_matches_release = (
        isinstance(direct_release, Mapping)
        and direct_release.get("repository") == identity["repository"]
        and direct_release.get("tag") == identity["tag"]
        and direct_release.get("tagCommit") == identity["commit"]
        and direct_release.get("tagTree") == identity["tree"]
    )
    if not (provenance_matches_candidate or provenance_matches_release):
        fail("NEBULAR_PROVENANCE_BINDING")
    payload_desc = raw_release.get("payload")
    payload_bytes, payload_digest = _nebular_descriptor(root, payload_desc, "payload")
    if (row.get("payload_archive_name") != payload_desc.get("name", payload_desc.get("path"))
            or row.get("payload_archive_sha256") != payload_digest):
        fail("NEBULAR_PAYLOAD_BINDING")
    manifest_desc = raw_release.get("manifest")
    manifest_bytes, manifest_digest = _nebular_descriptor(root, manifest_desc, "manifest")
    if row.get("manifest_sha256") != manifest_digest:
        fail("NEBULAR_PAYLOAD_BINDING")
    manifest_value = strict_json(manifest_bytes)
    if isinstance(manifest_value, Mapping):
        manifest = dict(manifest_value)
    elif isinstance(manifest_value, list):
        # Gate 1 binds the archive manifest digest to its canonical member
        # list.  The raw handoff may carry only that authenticated member list;
        # derive the two maintained command roles from the canonical payload
        # root and paths rather than trusting an arbitrary suffix or a caller
        # supplied command map.
        expected_root = _NEBULAR_ARCHIVE_ROOTS.get(target)
        relatives = _NEBULAR_NATIVE_ROLE_RELATIVE.get(target)
        if expected_root is None or relatives is None:
            fail("NEBULAR_NATIVE_CONTRACT")
        by_path = {
            item.get("path"): item for item in manifest_value
            if isinstance(item, Mapping) and isinstance(item.get("path"), str)
        }
        gui_path = f"{expected_root}/{relatives['gui']}"
        launcher_path = f"{expected_root}/{relatives['launcher']}"
        if gui_path not in by_path or launcher_path not in by_path:
            fail("NEBULAR_NATIVE_CONTRACT")
        manifest = {
            "root": expected_root,
            "members": manifest_value,
            "commands": {
                "tfnf": dict(by_path[gui_path]),
                "launcher:tfnf": dict(by_path[launcher_path]),
            },
        }
    else:
        fail("NEBULAR_NATIVE_CONTRACT")
    native_rows = raw_release.get("native_consumer")
    native = native_rows.get(target) if isinstance(native_rows, Mapping) else None
    if not isinstance(manifest, Mapping) or not isinstance(native, Mapping):
        fail("NEBULAR_NATIVE_CONTRACT")
    loader = native.get("loader")
    provider = native.get("provider_closure")
    members = manifest.get("members")
    if not isinstance(members, list):
        fail("NEBULAR_NATIVE_CONTRACT")
    member_by_path = {
        item.get("path"): item for item in members
        if isinstance(item, Mapping) and isinstance(item.get("path"), str)
    }

    roles = _nebular_native_role_paths(target, manifest)
    commands = manifest.get("commands")
    if (not isinstance(commands, Mapping)
            or not isinstance(commands.get("tfnf"), Mapping)
            or not isinstance(commands.get("launcher:tfnf"), Mapping)):
        fail("NEBULAR_NATIVE_CONTRACT")

    def authenticated_executable(path: Any, label: str) -> dict[str, Any]:
        entry = member_by_path.get(path)
        if (not isinstance(path, str) or not isinstance(entry, Mapping)
                or entry.get("type") != "file"
                or type(entry.get("mode")) is not int
                or not (entry["mode"] & 0o111)
                or not _NEBULAR_HEX64.fullmatch(str(entry.get("sha256")))):
            fail("NEBULAR_NATIVE_CONTRACT")
        return {"status": "verified", "path": path, "sha256": entry["sha256"],
                "size": entry["size"], "mode": entry["mode"], "type": "file", "executable": True,
                "label": label}

    if (row.get("launcher_path") != roles["launcher"]
            or row.get("gui_path") != roles["gui"]):
        fail("NEBULAR_NATIVE_CONTRACT")
    launcher = authenticated_executable(roles["launcher"], "launcher")
    gui = authenticated_executable(roles["gui"], "gui")
    sidecar = authenticated_executable(roles["sidecar"], "sidecar")
    # The manifest is an authenticated description, not proof that the
    # archive bytes still carry those members.  Re-read each executable from
    # the exact payload archive and join its bytes to the Gate1 digest before
    # any installed consumer is invoked.
    for executable in (launcher, gui, sidecar):
        _nebular_payload_member(root, payload_bytes, executable)
    for command_name, role in (("tfnf", gui), ("launcher:tfnf", launcher)):
        declared = commands[command_name]
        if any(declared.get(key) != role[key] for key in ("path", "sha256", "size", "mode")):
            fail("NEBULAR_NATIVE_CONTRACT")
    if (not isinstance(loader, Mapping)
            or loader.get("path") != launcher["path"]
            or loader.get("sha256") != launcher["sha256"]
            or not isinstance(provider, Mapping)
            or loader.get("status") != "verified"):
        fail("NEBULAR_NATIVE_CONTRACT")
    gui["smoke_path"] = roles["smoke_gui"]
    # Keep the PREP3 result field as an alias for downstream readers while
    # making the smoke-vs-materialized path distinction explicit.
    gui["runtime_path"] = roles["smoke_gui"]
    gui["materialized_path"] = roles["materialized_gui"]
    if provider.get("target") != target or provider.get("emulated") is True:
        fail("NEBULAR_PROVIDER_CLOSURE")
    if fixture_only:
        if provider.get("mode") != "controlled-fixture":
            fail("NEBULAR_PROVIDER_CLOSURE")
    elif provider.get("mode") != "host-observed":
        fail("NEBULAR_PROVIDER_CLOSURE")
    native_platform = _NEBULAR_NATIVE_RC_PLATFORMS.get(target)
    expected_scenario = _NEBULAR_NATIVE_RC_SCENARIOS.get(target, {}).get("raw-archive")
    protocol = native.get("protocol")
    if (not isinstance(native.get("command"), str) or not native["command"]
            or protocol != "nebular.native-rc-smoke"
            or native.get("platform") != native_platform
            or native.get("scenario") != expected_scenario
            or native.get("argv") != [f"--nebular-release-smoke={expected_scenario}"]
            or type(native.get("timeout_seconds")) is not int or not 1 <= native["timeout_seconds"] <= 60
            or not isinstance(native.get("state_paths"), list)
            or any(not isinstance(value, str) for value in native["state_paths"])
            or not isinstance(native.get("user_state_protocol"), Mapping)
            or native["user_state_protocol"].get("schema") != "nebular.native-rc-persistent-user-state-v1"
            or native["user_state_protocol"].get("method") != "native-rc-smoke.persistentStateLocations+snapshotLocations"
            or native["user_state_protocol"].get("scope") != "real-user-state"):
        fail("NEBULAR_NATIVE_CONTRACT")
    evidence = _nebular_native_evidence(
        root, native, target=target, fixture_only=fixture_only,
        loader=loader, gui=gui, sidecar=sidecar, provider=provider,
    )
    return {"root": root, "readme_bytes": readme_bytes, "payload_bytes": payload_bytes,
            "manifest": manifest, "manifest_sha256": manifest_digest, "provenance": provenance,
            "provenance_sha256": provenance_digest, "native": dict(native), "provider": dict(provider),
            "loader": dict(loader), "gui": gui, "sidecar": sidecar,
            "native_evidence": evidence}


def consume_nebular_candidate(
    candidate: Mapping[str, Any],
    wheel_path: str | Path,
    raw_release: Mapping[str, Any],
    work: str | Path,
    *,
    target: str,
    sandbox_prefix: Sequence[str] = (),
    sandbox_probe: Callable[[Mapping[str, str], Sequence[str]], Mapping[str, Any]] | None = None,
    host_identity: Mapping[str, Any] | None = None,
    fixture_only: bool = False,
    runner: Any = subprocess.Popen,
    process_observer: Callable[[Path], dict[str, Any]] | None = None,
    state_snapshot: Callable[[Path, Sequence[str]], dict[str, Any]] | None = None,
    real_user_state_snapshot: Callable[[str, str], Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Qualify one authenticated Nebular 0.7 wheel through a real installed native probe.

    ``fixture_only`` is an explicit, non-qualification mode for connected
    contract tests.  It requires controlled host/provider identities and the
    returned receipt can never be treated as hosted qualification evidence.
    Production callers must leave it false and provide the platform sandbox.
    """
    if not isinstance(raw_release, Mapping):
        fail("NEBULAR_CAPTURE_BINDING")
    row, wheel, context = _nebular_candidate_row(candidate, target)
    host = _nebular_identity_observed(host_identity, target, fixture_only)
    capture = _nebular_validate_capture(candidate, row, context, raw_release,
                                        target=target, fixture_only=fixture_only)
    wheel_file = Path(wheel_path)
    if wheel_file.is_symlink() or not wheel_file.is_file() or wheel_file.name != wheel["filename"]:
        fail("NEBULAR_WHEEL_BINDING")
    wheel_bytes = physical_bytes(wheel_file, limit=_NEBULAR_MAX_ARTIFACT_BYTES)
    if len(wheel_bytes) != wheel["size"] or sha256(wheel_bytes) != wheel["sha256"]:
        fail("NEBULAR_WHEEL_BINDING")
    wheel_files = read_wheel(
        wheel_bytes,
        max_total_bytes=_NEBULAR_MAX_ARTIFACT_BYTES,
        max_member_bytes=_NEBULAR_MAX_ARTIFACT_BYTES,
    )
    dist_infos = sorted({name.split("/", 1)[0] for name in wheel_files if name.endswith(".dist-info/METADATA")})
    if len(dist_infos) != 1:
        fail("NEBULAR_WHEEL_BINDING")
    info = dist_infos[0]
    verify_record(wheel_files, info)
    try:
        metadata = wheel_files[f"{info}/METADATA"][0].decode("utf-8")
    except (KeyError, UnicodeDecodeError):
        fail("NEBULAR_WHEEL_BINDING")
    metadata_lines = dict(line.split(": ", 1) for line in metadata.splitlines() if ": " in line)
    try:
        wheel_metadata = wheel_files[f"{info}/WHEEL"][0].decode("utf-8")
    except (KeyError, UnicodeDecodeError):
        fail("NEBULAR_WHEEL_BINDING")
    wheel_tags = [line.split(": ", 1)[1] for line in wheel_metadata.splitlines()
                  if line.startswith("Tag: ") and ": " in line]
    expected_tag = _NEBULAR_EXPECTED_WHEEL_TAGS[target]
    if (metadata_lines.get("Name") != "theme-forge-nebular-fusion"
            or metadata_lines.get("Version") != "0.7.0"
            or metadata_lines.get("License-Expression") != _NEBULAR_LICENSE_EXPRESSION
            or wheel.get("tag") != expected_tag
            or wheel_tags != [expected_tag]):
        fail("NEBULAR_WHEEL_BINDING")
    provenance_members = [name for name in wheel_files if name.endswith("/_rs9/provenance.json")]
    if len(provenance_members) != 1:
        fail("NEBULAR_WHEEL_BINDING")
    wheel_provenance = strict_json(wheel_files[provenance_members[0]][0])
    if (not isinstance(wheel_provenance, Mapping)
            or wheel_provenance.get("rs9_source") != context["source"]
            or wheel_provenance.get("release_record_sha256") != context["identity"]["release_record_sha256"]
            or wheel_provenance.get("payload_archive_sha256") != row["payload_archive_sha256"]
            or wheel_provenance.get("manifest_sha256") != row["manifest_sha256"]
            or wheel_provenance.get("forward_lineage") != context["direct_lineage"]
            or wheel_provenance.get("license_expression") != _NEBULAR_LICENSE_EXPRESSION
            or wheel_provenance.get("wheel_tag") != expected_tag
            or wheel_provenance.get("linux_runtime_policy") != context["profile_contract"]["linux_runtime_policy"]
            or wheel_provenance.get("darwin_floor_evidence") != context["profile_contract"]["darwin_floor_evidence"]):
        fail("NEBULAR_WHEEL_BINDING")
    payload_member = next((name for name in wheel_files
                           if name.endswith("/payload/" + str(row["payload_archive_name"]))), None)
    if payload_member is None or wheel_files[payload_member][0] != capture["payload_bytes"]:
        fail("NEBULAR_WHEEL_BINDING")
    package_root = "theme_forge_nebular_fusion"
    manifest_member = f"{package_root}/payload/manifest.json"
    embedded_manifest = strict_json(wheel_files[manifest_member][0]) if manifest_member in wheel_files else None
    embedded_members = embedded_manifest.get("members") if isinstance(embedded_manifest, Mapping) else embedded_manifest
    if (manifest_member not in wheel_files
            or not isinstance(embedded_manifest, Mapping)
            or not isinstance(embedded_members, list)
            or embedded_manifest.get("manifest_sha256") != row["manifest_sha256"]
            or embedded_members != capture["manifest"].get("members")):
        fail("NEBULAR_WHEEL_BINDING")
    for name, descriptor in candidate["legal_files"].items():
        member = f"{info}/licenses/{name}"
        if member not in wheel_files or wheel_files[member][0] != _nebular_descriptor(
                capture["root"], raw_release["legal_files"][name], "legal")[0]:
            fail("NEBULAR_WHEEL_BINDING")

    work_path = Path(work).resolve()
    if work_path.exists() or work_path.is_symlink():
        fail("NEBULAR_WORK_DIR")
    work_path.mkdir(parents=True, mode=0o700)
    home = work_path / "home"
    temp = work_path / "tmp"
    home.mkdir(mode=0o700)
    temp.mkdir(mode=0o700)
    base_env = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(home),
        "TMPDIR": str(temp),
        "TEMP": str(temp),
        "TMP": str(temp),
        "LANG": "C",
        "LC_ALL": "C",
        "PIP_CONFIG_FILE": os.devnull,
        "PIP_NO_INDEX": "1",
        "PIP_NO_CACHE_DIR": "1",
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "XDG_CACHE_HOME": str(home / ".cache"),
        "XDG_CONFIG_HOME": str(home / ".config"),
        "XDG_DATA_HOME": str(home / ".local/share"),
        "XDG_STATE_HOME": str(home / ".local/state"),
    }
    if sandbox_probe is None:
        node = node_binary()
        sandbox = network_denial(sys.executable, node, base_env, sandbox_prefix)
    else:
        sandbox = dict(sandbox_probe(base_env, sandbox_prefix))
    if sandbox.get("network_disabled") is not True:
        fail("NEBULAR_SANDBOX")
    observer = process_observer or _nebular_process_snapshot
    states = state_snapshot or _nebular_state_snapshot
    if real_user_state_snapshot is None:
        fail("NEBULAR_USER_STATE_GUARD")
    before_process = observer(work_path)
    before_state = states(home, capture["native"].get("state_paths", []))
    real_before = _nebular_real_user_state(
        real_user_state_snapshot("before", target), target=target, phase="before",
    )
    try:
        materialized_cache = home / ".cache" / "rs9" / "theme-forge-nebular-fusion"
        expected_materialized_path = (
            materialized_cache / "entries" / capture["manifest_sha256"] / "payload"
            / capture["gui"]["materialized_path"]
        )
        expected_gui_relative = expected_materialized_path.relative_to(home)
        if fixture_only:
            # A fixture may describe another host architecture, but it must
            # remain explicitly non-qualification evidence.  pip's target
            # install authenticates the wheel without pretending the current
            # host can execute a foreign platform wheel.
            site = work_path / "site"
            site.mkdir(mode=0o700)
            python = Path(sys.executable)
            install_env = {**base_env, "PATH": str(python.parent) + os.pathsep + base_env["PATH"]}
            pip_platform = {
                "darwin-arm64": "macosx_13_0_arm64",
                "linux-arm64-gnu": "linux_aarch64",
                "linux-x64-gnu": "linux_x86_64",
            }[target]
            install_args = [python, "-I", "-B", "-m", "pip", "install", "--no-index", "--no-deps",
                            "--only-binary=:all:", "--no-cache-dir", "--target", site,
                            "--platform", pip_platform, wheel_file.resolve()]
        else:
            venv_root = work_path / "venv"
            venv.EnvBuilder(with_pip=True, clear=False).create(venv_root)
            python = venv_root / "bin/python"
            install_env = {**base_env, "PATH": str(python.parent) + os.pathsep + base_env["PATH"]}
            install_args = [python, "-I", "-B", "-m", "pip", "install", "--no-index", "--no-deps",
                            "--only-binary=:all:", "--no-cache-dir", wheel_file.resolve()]
        install = _nebular_run(
            install_args,
            install_env, work_path, sandbox_prefix, 60, runner=runner,
        )
        if (install["exit_code"] != 0 or install.get("timed_out")
                or install.get("output_limit_exceeded") or not install.get("cleanup_known")
                or not install.get("output_complete") or install.get("forced_cleanup")):
            fail("NEBULAR_WHEEL_INSTALL")
        if fixture_only:
            # The installed fixture launcher must materialize its own
            # embedded wheel payload.  Pre-populating this cache here would
            # make --path prove only the consumer's setup, not the wheel.
            command = work_path / "bin" / capture["native"]["command"]
            command.parent.mkdir(mode=0o700)
            code = ("import sys;sys.path.insert(0," + repr(str(site)) + ");"
                    "from theme_forge_nebular_fusion.launcher import main_tfnf;main_tfnf()")
            command.write_text("#!/bin/sh\nexec " + shlex.quote(str(python)) + " -I -c "
                               + shlex.quote(code) + " \"$@\"\n", encoding="utf-8")
            command.chmod(0o755)
        else:
            command = work_path / "venv" / "bin" / capture["native"]["command"]
        if command.is_symlink() or not command.is_file() or not os.access(command, os.X_OK):
            fail("NEBULAR_NATIVE_EXECUTION")

        def require_clean(result: Mapping[str, Any], code: str) -> None:
            if (result.get("exit_code") != 0 or result.get("timed_out")
                    or result.get("output_limit_exceeded") or not result.get("cleanup_known")
                    or not result.get("output_complete") or result.get("forced_cleanup")):
                fail(code)

        version = _nebular_run([command, "--version"], install_env, work_path,
                               sandbox_prefix, 30, runner=runner)
        require_clean(version, "NEBULAR_COMMAND_CONTRACT")
        if b"0.7.0" not in version.get("stdout_token", "").encode():
            fail("NEBULAR_COMMAND_CONTRACT")
        path_probe = _nebular_run([command, "--path"], install_env, work_path,
                                  sandbox_prefix, 30, runner=runner)
        require_clean(path_probe, "NEBULAR_COMMAND_CONTRACT")
        path_lines = path_probe.get("stdout_token", "").splitlines()
        if len(path_lines) != 1 or not path_lines[0].strip():
            fail("NEBULAR_COMMAND_CONTRACT")
        resolved_gui = Path(path_lines[0].strip())
        try:
            observed_relative = resolved_gui.resolve().relative_to(home.resolve())
        except (OSError, ValueError):
            fail("NEBULAR_COMMAND_CONTRACT")
        if (observed_relative != expected_gui_relative
                or resolved_gui.is_symlink()
                or not resolved_gui.is_file()
                or not os.access(resolved_gui, os.X_OK)
                or sha256(physical_bytes(resolved_gui, limit=_NEBULAR_MAX_ARTIFACT_BYTES))
                != capture["gui"]["sha256"]):
            fail("NEBULAR_COMMAND_CONTRACT")
        native = _nebular_run([command, *capture["native"]["argv"]], install_env, work_path,
                              sandbox_prefix, capture["native"]["timeout_seconds"], runner=runner)
        require_clean(native, "NEBULAR_NATIVE_CONTRACT")
        if fixture_only:
            shutil.rmtree(site)
            uninstall = {"exit_code": 0, "signal": None, "stdout_sha256": sha256(b""),
                         "stderr_sha256": sha256(b"")}
        else:
            uninstall = _nebular_run([python, "-I", "-B", "-m", "pip", "uninstall", "--yes",
                                       "theme-forge-nebular-fusion"], install_env, work_path,
                                     sandbox_prefix, 60, runner=runner)
        if (uninstall["exit_code"] != 0 or uninstall.get("timed_out")
                or uninstall.get("output_limit_exceeded") or uninstall.get("forced_cleanup")
                or uninstall.get("cleanup_known", True) is not True):
            fail("NEBULAR_CLEANUP")
    finally:
        after_process = observer(work_path)
        after_state = states(home, capture["native"].get("state_paths", []))
        real_after = _nebular_real_user_state(
            real_user_state_snapshot("after", target), target=target, phase="after",
        )
    if after_process.get("orphan_count") != 0:
        fail("NEBULAR_ORPHAN_PROCESSES")
    if before_state != after_state:
        fail("NEBULAR_USER_STATE")
    if (real_before.get("snapshot_sha256") != real_after.get("snapshot_sha256")
            or real_after.get("changed") != []):
        fail("NEBULAR_USER_STATE_GUARD")
    result = {
        "schema": NEBULAR070_CONSUMER_SCHEMA,
        "status": "fixture-native-consumer-passed" if fixture_only else "native-consumer-passed",
        "fixture_only": fixture_only,
        "native_qualified": not fixture_only,
        "target": target,
        "system": NEBULAR070_TARGET_SYSTEMS[target],
        "candidate_rs9_source": context["source"],
        "candidate_source_identity": context["identity"],
        "wheel": {"target": target, "filename": wheel["filename"], "size": wheel["size"],
                   "sha256": wheel["sha256"], "tag": wheel.get("tag"), "version": "0.7.0"},
        "raw_release": {
            "release_record_sha256": context["identity"]["release_record_sha256"],
            "payload_sha256": row["payload_archive_sha256"],
            "manifest_sha256": row["manifest_sha256"],
            "readme_sha256": candidate["readme"]["sha256"],
            "legal_files": {name: value["sha256"] for name, value in candidate["legal_files"].items()},
            "provenance_sha256": sha256(_nebular_descriptor(capture["root"], raw_release["provenance"], "PROVENANCE")[0]),
        },
        "host_identity": host,
        "provider_closure": capture["provider"],
        "loader": capture["loader"],
        "gui": capture["gui"],
        "sandbox": {key: value for key, value in sandbox.items() if key in {"network_disabled", "method", "proof_sha256"}},
        "process_observer": {"before": before_process, "after": after_process, "orphan_count": 0},
        "user_state": {
            "scratch": {"before": before_state, "after": after_state, "unchanged": True},
            "real_user_state": {"before": real_before, "after": real_after, "unchanged": True},
            "unchanged": True,
        },
        "probes": {
            "version": {key: value for key, value in version.items() if key != "stdout_token"},
            "path": {
                **{key: value for key, value in path_probe.items() if key != "stdout_token"},
                "resolved_relative": observed_relative.as_posix(),
                "resolved_sha256": capture["gui"]["sha256"],
            },
            "native": {key: value for key, value in native.items() if key != "stdout_token"},
        },
        "cleanup": {"pip_uninstall_exit": 0, "orphan_processes": 0},
        "publication_admitted": False,
        "public_writes": 0,
    }
    return result
