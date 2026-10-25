"""Isolated offline pip lifecycle and released command contracts, without upload."""
import os
import json
import errno
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import venv

from rs9.tf_pypi_archive import fail, physical_bytes, sha256
from rs9.tf_pypi_launcher import node_binary
from rs9.tf_pypi_verify import verify_pair
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
