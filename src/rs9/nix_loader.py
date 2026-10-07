"""Bounded direct-loader diagnostics; never qualify a native application."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

from rs9.elf import parse_elf
from rs9.errors import ContractError

SCHEMA = "rs9.nix-loader-evaluation.v1"
MAX_OUTPUT = 1024 * 1024
MAX_ELF = 512 * 1024 * 1024
_GLIBC = re.compile(r"GLIBC_(?:[0-9]+(?:\.[0-9]+)+|ABI_[A-Za-z0-9_]+)")


def glibc_definitions(stdout):
    """Only version definitions establish capabilities; needs are not providers."""
    if not isinstance(stdout, bytes) or len(stdout) > MAX_OUTPUT:
        raise ContractError("NIX_LOADER_ABI", "Bounded version definitions required")
    definitions = set()
    section = False
    try:
        lines = stdout.decode("utf-8", errors="strict").splitlines()
    except UnicodeError:
        raise ContractError("NIX_LOADER_ABI", "Malformed version definitions") from None
    for line in lines:
        if line.startswith("Version "):
            section = line.startswith("Version definition section")
        if section:
            for name in re.findall(r"\bName: (\S+)", line):
                if _GLIBC.fullmatch(name):
                    definitions.add(name)
    if not definitions:
        raise ContractError("NIX_LOADER_ABI", "No glibc version definitions observed")
    return definitions


def check_glibc_abi(version_needs, providers):
    """Match required versions to the actual same-named store library."""
    missing = []
    for library, names in version_needs.items():
        required = {name for name in names if name.startswith("GLIBC_")}
        if required - providers.get(library, set()):
            missing.extend(sorted(required - providers.get(library, set())))
    if missing:
        raise ContractError("NIX_LOADER_ABI", "Pinned glibc does not cover ELF requirements",
                            details={"reason": "missing-glibc-versions", "versions": sorted(set(missing))[:20]})
    return {"status": "compatible", "required_versions": sorted({n for ns in version_needs.values()
            for n in ns if n.startswith("GLIBC_")})}


def loader_argv(facts, executable, args=()):
    """One pinned loader/libc pair, with no host LD_LIBRARY_PATH inheritance."""
    required = {"loader", "glibc_lib", "library_path", "python", "node", "readelf"}
    if not isinstance(facts, dict) or set(facts) != required:
        raise ContractError("NIX_LOADER_FACTS", "Closed pinned loader facts required")
    if any(not isinstance(v, str) or not v.startswith("/nix/store/") or "\x00" in v for v in facts.values()):
        raise ContractError("NIX_LOADER_FACTS", "Store-backed runtime paths required")
    libraries = facts["library_path"].split(":")
    if any(not p.startswith("/nix/store/") or any(c in {"", ".", ".."} for c in p.split("/")[1:]) for p in libraries):
        raise ContractError("NIX_LOADER_FACTS", "Store-only library closure required")
    if str(Path(facts["loader"]).parent) != facts["glibc_lib"] or facts["glibc_lib"] not in libraries:
        raise ContractError("NIX_LOADER_FACTS", "Loader and libc must share the pinned glibc output")
    return [facts["loader"], "--argv0", str(executable), "--library-path", facts["library_path"], str(executable), *args]


def evaluate(facts, elf_paths, *, prefix=(), env=None, runner=subprocess.run):
    """List unmodified release ELFs and measure executable-self identity.

    This does not launch Nebular or its sidecar, change release bytes, or stand
    in for the released verifier/application smoke. Raw paths stay ephemeral.
    """
    loader_argv(facts, facts["python"])
    safe_env = dict(env or {})
    safe_env.pop("LD_LIBRARY_PATH", None)
    safe_env.pop("LD_PRELOAD", None)

    def run(args):
        try:
            result = runner([*prefix, *args], env=safe_env, capture_output=True, timeout=30)
        except (OSError, subprocess.TimeoutExpired):
            raise ContractError("NIX_LOADER_EVALUATION", "Loader diagnostic unavailable",
                                details={"reason": "tool-unavailable-or-timeout"}) from None
        if len(result.stdout) > MAX_OUTPUT or len(result.stderr) > MAX_OUTPUT or result.returncode:
            raise ContractError("NIX_LOADER_EVALUATION", "Loader diagnostic failed", details={
                "exit_code": result.returncode, "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
                "stderr_sha256": hashlib.sha256(result.stderr).hexdigest()})
        return result.stdout

    rows = []
    paths = list(elf_paths)
    if not paths or len(paths) > 256:
        raise ContractError("NIX_LOADER_EVALUATION", "Bounded actual release ELF inventory required")
    for path in paths:
        path = Path(path)
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_ELF:
            raise ContractError("NIX_LOADER_EVALUATION", "Bounded unmodified regular ELF required")
        data = path.read_bytes()
        info = parse_elf(data)
        providers = {}
        for library, names in info["version_needs"].items():
            if not any(n.startswith("GLIBC_") for n in names):
                continue
            if not re.fullmatch(r"[A-Za-z0-9_.+-]+", library):
                raise ContractError("NIX_LOADER_ABI", "Unsafe glibc library name")
            output = run([facts["readelf"], "--version-info", str(Path(facts["glibc_lib"]) / library)])
            providers[library] = glibc_definitions(output)
        abi = check_glibc_abi(info["version_needs"], providers)
        listed = run([facts["loader"], "--library-path", facts["library_path"], "--list", str(path)])
        if b"not found" in listed:
            raise ContractError("NIX_LOADER_EVALUATION", "Direct-loader library closure missing")
        if path.read_bytes() != data:
            raise ContractError("NIX_LOADER_EVALUATION", "Release ELF changed during diagnostic")
        rows.append({"elf_sha256": hashlib.sha256(data).hexdigest(), "machine": info["machine"],
                     "foreign_interpreter": bool(info["interpreter"] and not info["interpreter"].startswith("/nix/store/")),
                     "abi": abi, "loader_list_sha256": hashlib.sha256(listed).hexdigest()})
    python_probe = "import json,os;print(json.dumps({'exe':os.readlink('/proc/self/exe')}))"
    node_probe = "console.log(JSON.stringify({exe:require('fs').readlinkSync('/proc/self/exe'),execPath:process.execPath}))"
    observed = []
    for tool, args in (("python", ["-I", "-S", "-B", "-c", python_probe]), ("node", ["-e", node_probe])):
        try:
            normal = json.loads(run([facts[tool], *args]))
            direct = json.loads(run(loader_argv(facts, facts[tool], args)))
        except (ValueError, UnicodeError):
            raise ContractError("NIX_LOADER_EVALUATION", "Malformed executable-self readback") from None
        keys = {"exe"} if tool == "python" else {"exe", "execPath"}
        if (not isinstance(normal, dict) or not isinstance(direct, dict)
                or set(normal) != keys or set(direct) != keys
                or any(not isinstance(v, str) or not v for v in [*normal.values(), *direct.values()])):
            raise ContractError("NIX_LOADER_EVALUATION", "Incomplete executable-self readback")
        normal_ok = os.path.realpath(normal["exe"]) == os.path.realpath(facts[tool])
        direct_loader = os.path.realpath(direct["exe"]) == os.path.realpath(facts["loader"])
        if not normal_ok or not direct_loader:
            raise ContractError("NIX_LOADER_EVALUATION", "Unexpected executable-self identity")
        observed.append({"tool": tool, "normal_self_is_tool": normal_ok, "direct_self_is_loader": direct_loader,
                         "exec_path_preserved": normal.get("execPath") == direct.get("execPath") if tool == "node" else None})
    return {"schema": SCHEMA, "status": "diagnostics-only", "application_qualified": False,
            "sole_runtime_supported": False, "elfs": rows, "self_readers": observed,
            "reason": "executable-self-and-foreign-child-interpreter-require-adapter"}
