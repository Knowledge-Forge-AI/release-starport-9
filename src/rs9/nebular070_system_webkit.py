"""Public-hosted system-WebKit consumer helpers; no operator-host execution."""
from __future__ import annotations

import json
import os
import platform
import re
import stat
import struct
import sys
import venv
from pathlib import Path
from typing import Any, Mapping

from rs9.tf_pypi_archive import canonical, fail, physical_bytes, sha256


def _frame(value: os.stat_result) -> list[int]:
    return [value.st_dev, value.st_ino, value.st_size, value.st_mode,
            value.st_mtime_ns, value.st_ctime_ns, value.st_uid, value.st_gid, value.st_nlink]


def _provider_version_definitions(data: bytes) -> list[str]:
    """Read ELF64 little-endian definition names without dumping symbol rows."""
    try:
        if len(data) < 64 or data[:6] != b"\x7fELF\x02\x01":
            raise ValueError
        table = struct.unpack_from("<Q", data, 40)[0]
        stride, count = struct.unpack_from("<HH", data, 58)
        if table < 64 or stride != 64 or not count or table + stride * count > len(data):
            raise ValueError
        sections = [struct.unpack_from("<IIQQQQIIQQ", data, table + i * stride)
                    for i in range(count)]
        definitions = [row for row in sections if row[1] == 0x6FFFFFFD]
        if not definitions:
            return []
        if len(definitions) != 1:
            raise ValueError
        row = definitions[0]
        start, size, link, entries = row[4:8]
        if start < 64 or link >= count or entries > 4096 or start + size > len(data):
            raise ValueError
        strings = sections[link]
        string_start, string_size = strings[4:6]
        if strings[1] != 3 or string_start < 64 or string_start + string_size > len(data):
            raise ValueError
        names, cursor = [], start
        for index in range(entries):
            if cursor + 20 > start + size:
                raise ValueError
            version, _, _, auxiliary_count, _, auxiliary, following = struct.unpack_from("<HHHHIII", data, cursor)
            if version != 1 or not 1 <= auxiliary_count <= 256 or auxiliary < 20:
                raise ValueError
            auxiliary_cursor = cursor + auxiliary
            for number in range(auxiliary_count):
                if auxiliary_cursor + 8 > start + size:
                    raise ValueError
                name_offset, next_auxiliary = struct.unpack_from("<II", data, auxiliary_cursor)
                if name_offset >= string_size:
                    raise ValueError
                offset = string_start + name_offset
                end = data.find(b"\0", offset, min(string_start + string_size, offset + 512))
                if end <= offset:
                    raise ValueError
                if number == 0:
                    names.append(data[offset:end].decode("utf-8"))
                if number + 1 == auxiliary_count:
                    if next_auxiliary != 0:
                        raise ValueError
                elif next_auxiliary < 8:
                    raise ValueError
                auxiliary_cursor += next_auxiliary
            if index + 1 == entries:
                if following != 0:
                    raise ValueError
            elif following < 20:
                raise ValueError
            cursor += following
        if not entries and size:
            raise ValueError
        return sorted(set(names))
    except (ValueError, struct.error, UnicodeError):
        fail("NEBULAR_SYSTEM_PROVIDER_ELF")


def observe_provider(target: str) -> dict[str, Any]:
    """Observe the exact distro provider on a matching public native runner."""
    from rs9.elf import parse_elf
    from rs9.nebular070_host_observation import _bounded_tool
    from rs9.nebular070_payload import _runtime_provider_row

    architectures = {
        "linux-arm64-gnu": ("aarch64", "aarch64-linux-gnu", "AArch64"),
        "linux-x64-gnu": ("x86_64", "x86_64-linux-gnu", "Advanced Micro Devices X86-64"),
    }
    if (target not in architectures or os.environ.get("GITHUB_ACTIONS") != "true"
            or platform.system() != "Linux" or platform.machine() != architectures[target][0]):
        fail("NEBULAR_SYSTEM_PROVIDER_HOST")
    machine, multiarch, elf_machine = architectures[target]
    soname = "libwebkit2gtk-4.1.so.0"
    requested = Path("/usr/lib") / multiarch / soname
    cursor = requested
    aliases = []
    for _ in range(16):
        try:
            before = cursor.lstat()
        except OSError:
            fail("NEBULAR_SYSTEM_WEBKIT_MISSING")
        if not stat.S_ISLNK(before.st_mode):
            break
        raw_target = os.readlink(cursor)
        if _frame(cursor.lstat()) != _frame(before):
            fail("NEBULAR_SYSTEM_PROVIDER_CHANGED")
        aliases.append({"path": str(cursor), "rawTarget": raw_target, "full9": _frame(before)})
        cursor = Path(os.path.normpath(str(cursor.parent / raw_target)))
        if not str(cursor).startswith(("/usr/lib/", "/lib/")):
            fail("NEBULAR_SYSTEM_PROVIDER_PATH")
    else:
        fail("NEBULAR_SYSTEM_PROVIDER_PATH")
    if not stat.S_ISREG(before.st_mode):
        fail("NEBULAR_SYSTEM_PROVIDER_PATH")
    data = physical_bytes(cursor, limit=256 * 1024 * 1024)
    parsed = parse_elf(data)
    if parsed.get("machine") != machine or parsed.get("soname") != soname:
        fail("NEBULAR_SYSTEM_PROVIDER_ELF")
    # -V also prints the complete symbol-version table, exceeding the existing
    # host probe's stream cap for WebKit. Keep that cap and observe the small
    # header/dynamic table; definition names come from the same hashed bytes.
    stdout, stderr, proof = _bounded_tool(["/usr/bin/readelf", "-h", "-d", "--wide", str(cursor)])
    versions = _provider_version_definitions(data)
    if stderr or _frame(cursor.lstat()) != _frame(before):
        fail("NEBULAR_SYSTEM_PROVIDER_CHANGED")
    for alias in aliases:
        if (_frame(Path(alias["path"]).lstat()) != alias["full9"]
                or os.readlink(alias["path"]) != alias["rawTarget"]):
            fail("NEBULAR_SYSTEM_PROVIDER_CHANGED")
    row = {
        "soname": soname, "classification": "system-webkitgtk-4.1",
        "requestedPath": str(requested), "terminalPath": str(cursor),
        "aliasChain": aliases, "terminalFull9": _frame(before),
        "bytes": len(data), "sha256": sha256(data), "elfMachine": elf_machine,
        "elfClass": "ELF64", "versionDefinitions": versions,
        "readelfEvidenceSha256": sha256(canonical({
            key: proof[key] for key in ("tool", "args", "returncode", "stdout", "stderr")
        })),
    }
    _runtime_provider_row(row, target=target, expected_machines={elf_machine},
                          classifications=frozenset({"system-webkitgtk-4.1"}))
    return row


def check_missing_runtime(
    wheel_path: Path, work: Path, *, target: str, source: Mapping[str, str],
    run_id: str, run_attempt: str, prefix: tuple[str, ...],
) -> dict[str, Any]:
    """Install the real wheel and prove its normal command refuses no WebKit.

    This runs only on the disposable matching public Bookworm runner before
    its runtime packages are installed. It never removes or hides a library.
    """
    from rs9.nebular070_host_observation import observe_host
    from rs9.nebular070_public_consumers import _system_wheel
    from rs9.tf_pypi_consumer import _nebular_run

    expected = {"linux-arm64-gnu": "aarch64", "linux-x64-gnu": "x86_64"}
    if (os.environ.get("GITHUB_ACTIONS") != "true" or platform.system() != "Linux"
            or platform.machine() != expected.get(target) or work.exists() or work.is_symlink()):
        fail("NEBULAR_SYSTEM_MISSING_HOST")
    snapshot = _system_wheel(physical_bytes(wheel_path, limit=100 * 1024 * 1024), target)
    host, _ = observe_host("floor")
    work.mkdir(parents=True, mode=0o700)
    home, temporary = work / "home", work / "tmp"
    home.mkdir(mode=0o700)
    temporary.mkdir(mode=0o700)
    env = {
        "HOME": str(home), "TMPDIR": str(temporary), "TMP": str(temporary),
        "PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C",
        "PIP_CONFIG_FILE": os.devnull, "PIP_NO_INDEX": "1", "PIP_NO_CACHE_DIR": "1",
        "PIP_DISABLE_PIP_VERSION_CHECK": "1", "PYTHONDONTWRITEBYTECODE": "1",
        "THEME_FORGE_CACHE_DIR": str(work / "payload-cache"),
        "XDG_CACHE_HOME": str(home / ".cache"), "XDG_CONFIG_HOME": str(home / ".config"),
        "XDG_DATA_HOME": str(home / ".local/share"), "XDG_STATE_HOME": str(home / ".local/state"),
    }
    def execute(argv: list[str], *, expected_exit: int = 0) -> dict[str, Any]:
        result = _nebular_run(argv, env, work, prefix, 60)
        if (result.get("exit_code") != expected_exit or result.get("timed_out")
                or result.get("output_limit_exceeded") or result.get("forced_cleanup")
                or result.get("cleanup_known") is not True or result.get("output_complete") is not True):
            fail("NEBULAR_SYSTEM_MISSING_CHECK")
        return result
    # Observe actual unavailability without altering the loader environment.
    absent = execute([sys.executable, "-I", "-c",
                      "import ctypes\ntry: ctypes.CDLL('libwebkit2gtk-4.1.so.0')\n"
                      "except OSError: raise SystemExit(2)"], expected_exit=2)
    venv_root = work / "venv"
    venv.EnvBuilder(with_pip=True).create(venv_root)
    python = venv_root / "bin/python"
    install = execute([str(python), "-I", "-m", "pip", "install", "--no-index", "--no-deps",
                       "--no-compile", "--only-binary=:all:", str(wheel_path.resolve())])
    command = venv_root / "bin/tfnf"
    for arg, token in (("--help", "Usage: tfnf"), ("--version", "0.7.0")):
        result = execute([str(command), arg])
        if token not in result.get("stdout_token", ""):
            fail("NEBULAR_SYSTEM_MISSING_CHECK")
    refusal = execute([str(command)], expected_exit=1)
    stderr = refusal.get("stderr_token", "")
    if ("WebKitGTK 4.1 is unavailable" not in stderr
            or "sudo apt install libwebkit2gtk-4.1-0" not in stderr
            or "Traceback" in stderr or (work / "payload-cache").exists()
            or (home / ".cache").exists()):
        fail("NEBULAR_SYSTEM_MISSING_CHECK")
    uninstall = execute([str(python), "-I", "-m", "pip", "uninstall", "--yes", "theme-forge-nebular-fusion"])
    def summary(result: Mapping[str, Any]) -> dict[str, Any]:
        return {key: result[key] for key in (
            "exit_code", "signal", "stdout_sha256", "stderr_sha256", "cleanup_known",
            "output_complete", "forced_cleanup",
        )}
    unsigned = {
        "schema": "rs9.nebular070-system-webkit-missing-runtime.v1", "status": "passed",
        "target": target, "source": dict(source), "run": {"id": run_id, "attempt": run_attempt},
        "host_observation_identity": host["identity"], "host_class": "bookworm-floor",
        "wheel_sha256": snapshot["archive_sha256"], "wheel_tag": snapshot["tag"],
        "soname": "libwebkit2gtk-4.1.so.0", "unavailable": summary(absent),
        "install": summary(install), "normal_entrypoint": summary(refusal),
        "uninstall": summary(uninstall), "payload_materialized": False,
        "library_environment_modified": False,
    }
    return {**unsigned, "identity": sha256(canonical(unsigned))}


def validate_missing_runtime(
    value: Mapping[str, Any], *, target: str, source: Mapping[str, str],
    run_id: str, run_attempt: str, wheel: Mapping[str, Any], host_identity: str,
) -> dict[str, Any]:
    """Join the floor's observed refusal to its later positive consumer."""
    keys = {
        "schema", "status", "target", "source", "run", "host_observation_identity",
        "host_class", "wheel_sha256", "wheel_tag", "soname", "unavailable", "install",
        "normal_entrypoint", "uninstall", "payload_materialized",
        "library_environment_modified", "identity",
    }
    if (not isinstance(value, Mapping) or set(value) != keys
            or value.get("schema") != "rs9.nebular070-system-webkit-missing-runtime.v1"
            or value.get("status") != "passed" or value.get("target") != target
            or value.get("source") != dict(source)
            or value.get("run") != {"id": run_id, "attempt": run_attempt}
            or value.get("host_observation_identity") != host_identity
            or value.get("host_class") != "bookworm-floor"
            or value.get("wheel_sha256") != wheel.get("sha256")
            or value.get("wheel_tag") != wheel.get("tag")
            or value.get("soname") != "libwebkit2gtk-4.1.so.0"
            or value.get("payload_materialized") is not False
            or value.get("library_environment_modified") is not False):
        fail("NEBULAR_SYSTEM_MISSING_RECEIPT")
    for label, code in (("unavailable", 2), ("install", 0), ("normal_entrypoint", 1), ("uninstall", 0)):
        result = value.get(label)
        if (not isinstance(result, Mapping)
                or set(result) != {"exit_code", "signal", "stdout_sha256", "stderr_sha256",
                                    "cleanup_known", "output_complete", "forced_cleanup"}
                or result.get("exit_code") != code or result.get("signal") is not None
                or result.get("cleanup_known") is not True
                or result.get("output_complete") is not True
                or result.get("forced_cleanup") is not False
                or any(not re.fullmatch(r"[0-9a-f]{64}", str(result.get(key)))
                       for key in ("stdout_sha256", "stderr_sha256"))):
            fail("NEBULAR_SYSTEM_MISSING_RECEIPT")
    if value.get("identity") != sha256(canonical({key: item for key, item in value.items() if key != "identity"})):
        fail("NEBULAR_SYSTEM_MISSING_RECEIPT")
    return dict(value)


def prepare_installed_harness(
    prepared: Mapping[str, Any], installed_command: Path, *, cache_root: Path,
) -> tuple[Path, dict[str, Any]]:
    """Derive one bound launch seam from the authenticated product harness.

    The source harness still owns fixture preparation, application receipts,
    executable/PID identity, signal handling, and cleanup. The adapter selects
    the installed Python entrypoint and its existing cache, adds process
    identity evidence, and retains the original application receipt bytes.
    Both source and derived identities are retained; the derived script is
    never represented as unmodified product source.
    """
    tools = Path(prepared["tools"])
    original = tools / "native-rc-smoke.mjs"
    records = prepared.get("records")
    if not isinstance(records, list):
        fail("NEBULAR_SMOKE_CLOSURE")
    record = next((row for row in records if isinstance(row, Mapping)
                   and row.get("path") == f"{prepared.get('tool_root', 'tools')}/native-rc-smoke.mjs"), None)
    raw = physical_bytes(original, limit=2 * 1024 * 1024)
    if not isinstance(record, Mapping) or sha256(raw) != record.get("sha256"):
        fail("NEBULAR_SMOKE_CLOSURE")
    if installed_command.is_symlink() or not os.access(installed_command, os.X_OK):
        fail("NEBULAR_SYSTEM_WEBKIT_PREFLIGHT")
    entry = physical_bytes(installed_command, limit=1024 * 1024)
    entry_sha = sha256(entry)
    literal = json.dumps(str(installed_command))
    cache_literal = json.dumps(str(cache_root))
    source = raw.decode("utf-8")
    changes = (
        (
            "  const launchTarget = launcherPath(launchRoot, platform);",
            "  const launchTarget = launcherPath(launchRoot, platform);\n"
            f"  const installedEntry = readRegularSnapshot({literal}, {{ label: 'Installed Python entrypoint', maxBytes: 1024 * 1024 }});\n"
            f"  if (!installedEntry.executable || installedEntry.sha256 !== {json.dumps(entry_sha)}) throw new Error('installed entrypoint changed');",
        ),
        (
            'source: options.source ?? null, executable:',
            'source: options.source ?? null, installedEntrypoint: '
            f'{{ sha256: installedEntry.sha256, size: installedEntry.size }}, executable:',
        ),
        (
            'const child = spawn(launchTarget, [`--nebular-release-smoke=${scenario}`]',
            f'const child = spawn({literal}, [`--nebular-release-smoke=${{scenario}}`]',
        ),
        (
            '{ cwd: home, env, detached: true',
            f'{{ cwd: home, env: {{ ...env, THEME_FORGE_CACHE_DIR: {cache_literal} }}, detached: true',
        ),
        (
            '      const timeout = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;',
            '      const timeout = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;\n'
            '      result.checks.installedEntrypointObserved = Boolean(await waitUntil(() => '\
            'candidateProcesses(launchRoot).some((entry) => entry.pid === child.pid), Math.min(timeout, 10000), 25));\n'
            "      if (!result.checks.installedEntrypointObserved) result.problems.push('installed entrypoint did not enter the authenticated payload root');",
        ),
        (
            r'(observed) => writeFileSync(join(evidenceDir, `${label}.receipt.json`), `${JSON.stringify(observed.receipt, null, 2)}\n`),',
            '(observed) => {\n'
            '          const captured = readRegularSnapshot(join(smokeDir, "receipt.json"), { label: "Application receipt copy", maxBytes: 4 * 1024 * 1024 });\n'
            '          if (captured.sha256 !== observed.sha256) throw new Error("application receipt changed before copy");\n'
            '          writeFileSync(join(evidenceDir, `${label}.receipt.json`), captured.bytes);\n'
            '        },',
        ),
    )
    for before, after in changes:
        if source.count(before) != 1:
            fail("NEBULAR_SYSTEM_HARNESS_SOURCE")
        source = source.replace(before, after)
    adapted = source.encode("utf-8")
    output = tools / "native-rc-smoke-installed.mjs"
    if output.exists() or output.is_symlink():
        fail("NEBULAR_SYSTEM_HARNESS_OUTPUT")
    with output.open("xb") as stream:
        stream.write(adapted)
    output.chmod(0o600)
    return output, {
        "schema": "rs9.nebular070-installed-launcher-harness.v1",
        "source_sha256": sha256(raw), "derived_sha256": sha256(adapted),
        "entrypoint_sha256": entry_sha, "entrypoint_bytes": len(entry),
        "cache_root_sha256": sha256(str(cache_root).encode("utf-8")),
        "transform": "authenticated-native-harness-installed-entrypoint-v1",
    }
