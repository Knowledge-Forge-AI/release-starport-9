"""Python-only launcher copied into the Nebular universal wheel."""
from __future__ import annotations

import hashlib
import importlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import sys

VERSION = "0.7.0"
INDEX_SHA256 = "__TFNF_INDEX_SHA256__"
TARGETS = ("darwin-arm64", "linux-arm64-gnu", "linux-x64-gnu")
_PACKAGE_DIR = Path(__file__).resolve().parent


class RuntimeSetupError(RuntimeError):
    """An actionable error with no private transport or filesystem details."""


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mode,
            info.st_mtime_ns, info.st_ctime_ns, info.st_uid, info.st_gid, info.st_nlink)


def _resource(name: str, limit: int) -> bytes:
    allowed = {"runtime-index.json", *("runtimes/" + key + ".json" for key in TARGETS)}
    if name not in allowed:
        raise RuntimeSetupError("TFNF_RUNTIME_PACKAGE: Invalid runtime resource.")
    target = _PACKAGE_DIR / name
    if target.parent.is_symlink():
        raise RuntimeSetupError("TFNF_RUNTIME_PACKAGE: Invalid runtime resource.")
    try:
        fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= limit:
                raise ValueError
            data = stream.read(limit + 1)
            if (len(data) != before.st_size
                    or _identity(before) != _identity(os.fstat(stream.fileno()))
                    or _identity(before) != _identity(target.lstat())):
                raise ValueError
        return data
    except (OSError, ValueError):
        raise RuntimeSetupError("TFNF_RUNTIME_PACKAGE: Runtime resource integrity failed.") from None


def _platform_key() -> str:
    machine = platform.machine().lower()
    if sys.platform == "darwin":
        version = platform.mac_ver()[0]
        if machine in ("arm64", "aarch64") and re.fullmatch(r"\d+(?:\.\d+)*", version):
            if int(version.split(".")[0]) >= 13:
                return "darwin-arm64"
    elif sys.platform.startswith("linux"):
        try:
            version = os.confstr("CS_GNU_LIBC_VERSION") or ""
        except (OSError, ValueError, AttributeError):
            version = ""
        match = re.fullmatch(r"glibc (\d+)\.(\d+)(?:\.\d+)*", version)
        if match and tuple(map(int, match.groups())) >= (2, 36):
            if machine in ("x86_64", "amd64"):
                return "linux-x64-gnu"
            if machine in ("aarch64", "arm64"):
                return "linux-arm64-gnu"
    raise RuntimeSetupError(
        "TFNF_RUNTIME_PLATFORM: Requires macOS 13+ on Apple Silicon, or "
        "glibc 2.36+ Linux on ARM64 or AMD64."
    )


def _runtime_spec(key: str):
    try:
        raw = _resource("runtime-index.json", 65536)
        if hashlib.sha256(raw).hexdigest() != INDEX_SHA256:
            raise ValueError
        index = json.loads(raw)
        if (set(index) != {"schema", "version", "targets"}
                or index["schema"] != "rs9.nebular070-universal-runtime-index.v1"
                or index["version"] != VERSION or set(index["targets"]) != set(TARGETS)):
            raise ValueError
        spec = index["targets"][key]
        raw_manifest = _resource("runtimes/" + key + ".json", 4 * 1024 * 1024)
        if hashlib.sha256(raw_manifest).hexdigest() != spec["manifest_resource_sha256"]:
            raise ValueError
        manifest = json.loads(raw_manifest)
        if (manifest["root"] != spec["root"]
                or manifest["manifest_sha256"] != spec["manifest_sha256"]):
            raise ValueError
        return spec, manifest
    except (ValueError, KeyError, TypeError, UnicodeError):
        raise RuntimeSetupError("TFNF_RUNTIME_PACKAGE: Runtime resource integrity failed.") from None


def _cache_dir(key: str) -> Path:
    if "THEME_FORGE_CACHE_DIR" in os.environ:
        raw = os.environ["THEME_FORGE_CACHE_DIR"]
        if not raw or not Path(raw).is_absolute():
            raise RuntimeSetupError("THEME_FORGE_CACHE_DIR must be a non-empty absolute path.")
        return Path(raw)
    xdg = os.environ.get("XDG_CACHE_HOME")
    if xdg and Path(xdg).is_absolute():
        return Path(xdg) / "rs9" / "theme-forge-nebular-fusion"
    if key == "darwin-arm64":
        return (Path.home() / "Library/Caches/rs9/theme-forge-nebular-fusion").absolute()
    return (Path.home() / ".cache/rs9/theme-forge-nebular-fusion").absolute()


def _materializer():
    isolated = _PACKAGE_DIR / "_isolated"
    existing = sys.modules.get("rs9")
    if existing is not None:
        location = getattr(existing, "__file__", None)
        if location is None or Path(location).resolve().parent != (isolated / "rs9").resolve():
            raise RuntimeSetupError("TFNF_RUNTIME_PACKAGE: Conflicting materializer namespace.")
    if str(isolated) not in sys.path:
        sys.path.insert(0, str(isolated))
    return importlib.import_module("rs9.materialize")


def _fetcher():
    return importlib.import_module(__package__ + "._fetch")


def _cached_archive(asset, cache: Path, helpers):
    path = cache / "archives" / (asset["sha256"] + ".tgz")
    failure = "unsafe"
    try:
        helpers.validate_ancestry_not_symlink(cache / "archives")
        before_path = path.lstat()
        if (not stat.S_ISREG(before_path.st_mode) or before_path.st_nlink != 1
                or before_path.st_uid != os.geteuid()):
            raise ValueError
        failure = "repair"
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            if _identity(before) != _identity(before_path):
                failure = "unsafe"
                raise ValueError
            if before.st_size != asset["size"]:
                raise ValueError
            digest = hashlib.sha256()
            remaining = asset["size"] + 1
            while remaining:
                chunk = stream.read(min(65536, remaining))
                if not chunk:
                    break
                digest.update(chunk)
                remaining -= len(chunk)
            if (_identity(before) != _identity(os.fstat(stream.fileno()))
                    or _identity(before) != _identity(path.lstat())):
                failure = "unsafe"
                raise ValueError
            if remaining != 1 or digest.hexdigest() != asset["sha256"]:
                raise ValueError
        return path
    except FileNotFoundError:
        return None
    except Exception:
        pass
    if failure == "repair":
        raise RuntimeSetupError(
            "TFNF_RUNTIME_CACHE: The saved runtime archive is invalid or unreadable; "
            "run tfnf install-runtime to repair it."
        )
    raise RuntimeSetupError(
        "TFNF_RUNTIME_CACHE: The runtime cache is unsafe or changed; set "
        "THEME_FORGE_CACHE_DIR to a new absolute directory, then run tfnf install-runtime."
    )


def _webkit_preflight() -> None:
    import subprocess
    try:
        result = subprocess.run(
            [sys.executable, "-I", "-c", "import ctypes; ctypes.CDLL('libwebkit2gtk-4.1.so.0')"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=5.0, check=False,
        )
        if result.returncode == 0:
            return
    except (OSError, subprocess.SubprocessError):
        pass
    raise RuntimeSetupError(
        "TFNF_RUNTIME_WEBKIT: WebKitGTK 4.1 is unavailable; install your "
        "distribution's WebKitGTK 4.1 runtime package first. "
        "Debian/Ubuntu: sudo apt install libwebkit2gtk-4.1-0."
    )


def _materialized_paths(archive: Path, cache: Path, spec, manifest, helpers):
    root = helpers.materialize_payload(
        archive, cache, manifest, expected_manifest_sha256=spec["manifest_sha256"],
    )
    prefix = manifest["root"] + "/"
    targets = []
    for name in ("shell_target", "gui_target"):
        target = spec[name]
        if not isinstance(target, str) or not target.startswith(prefix):
            raise RuntimeSetupError("TFNF_RUNTIME_PACKAGE: Invalid launcher target.")
        targets.append(helpers.resolve_launcher(root, target[len(prefix):]))
    return targets


def _run_launcher_checked(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv in (["--version"], ["-v"]):
        print("theme-forge-nebular-fusion " + VERSION)
        return 0
    if argv in (["--help"], ["-h"], ["install-runtime", "--help"], ["install-runtime", "-h"]):
        print("Usage: tfnf [--version|--help|--path] [application args...]\n"
              "       tfnf install-runtime [--json]")
        return 0
    install = bool(argv and argv[0] == "install-runtime")
    if install and argv not in (["install-runtime"], ["install-runtime", "--json"]):
        raise RuntimeSetupError("Usage: tfnf install-runtime [--json]")
    key = _platform_key()
    spec, manifest = _runtime_spec(key)
    cache = _cache_dir(key)
    helpers = _materializer()
    if install:
        if key.startswith("linux-"):
            _webkit_preflight()
        message = None
        try:
            result = _fetcher().fetch_archive(spec["asset"], cache / "archives")
        except Exception as error:
            code = getattr(error, "code", None)
            messages = {
                "TFNF_RUNTIME_TLS": (
                    "TFNF_RUNTIME_TLS: HTTPS certificate verification failed. Check Python's "
                    "trusted certificates and any proxy trust configuration, then retry tfnf install-runtime."
                ),
                "TFNF_RUNTIME_DEADLINE": (
                    "TFNF_RUNTIME_DEADLINE: The download exceeded its 15-minute acceptance budget. "
                    "Check the connection and retry tfnf install-runtime."
                ),
                "TFNF_RUNTIME_CACHE": (
                    "TFNF_RUNTIME_CACHE: Runtime setup cannot safely use this cache. Set "
                    "THEME_FORGE_CACHE_DIR to a new absolute directory, then run tfnf install-runtime."
                ),
                "TFNF_RUNTIME_PIN": (
                    "TFNF_RUNTIME_PACKAGE: Runtime pins are invalid; reinstall the Python package."
                ),
                "TFNF_RUNTIME_REDIRECT": (
                    "TFNF_RUNTIME_REDIRECT: The download redirected outside the trusted release service. "
                    "Check the connection or proxy configuration before retrying tfnf install-runtime."
                ),
            }
            if type(code) is str and code in {"TFNF_RUNTIME_SIZE", "TFNF_RUNTIME_DIGEST",
                                              "TFNF_RUNTIME_RESPONSE", "TFNF_RUNTIME_ENCODING"}:
                message = (
                    "TFNF_RUNTIME_DOWNLOAD: Runtime download verification failed. "
                    "Check the connection and retry tfnf install-runtime."
                )
            elif type(code) is str and code in messages:
                message = messages[code]
            else:
                message = (
                    "TFNF_RUNTIME_DOWNLOAD: Runtime download failed. "
                    "Check the connection and retry tfnf install-runtime."
                )
        if message is not None:
            raise RuntimeSetupError(message)
        archive = _cached_archive(spec["asset"], cache, helpers)
        if archive is None or archive != result.archive:
            raise RuntimeSetupError("TFNF_RUNTIME_CACHE: Runtime archive integrity failed.")
        _materialized_paths(archive, cache, spec, manifest, helpers)
        if argv == ["install-runtime", "--json"]:
            print(json.dumps({
                "schema": "theme-forge-nebular-fusion.runtime-install.v1",
                "version": VERSION, "target": key,
                "archive_sha256": spec["asset"]["sha256"], "archive_bytes": spec["asset"]["size"],
                "manifest_sha256": spec["manifest_sha256"], "downloaded": result.downloaded,
                "redirect_hosts": list(result.redirect_hosts),
            }, sort_keys=True))
        else:
            print("Theme Forge Nebular Fusion runtime is installed.")
        return 0
    archive = _cached_archive(spec["asset"], cache, helpers)
    if archive is None:
        raise RuntimeSetupError("TFNF_RUNTIME_MISSING: Run tfnf install-runtime before launching.")
    if key.startswith("linux-") and argv != ["--path"]:
        _webkit_preflight()
    shell, gui = _materialized_paths(archive, cache, spec, manifest, helpers)
    if argv == ["--path"]:
        print(gui)
        return 0
    os.execv(str(shell), [str(shell), *argv])
    return 0


def run_launcher(argv: list[str] | None = None) -> int:
    """Expose a fresh safe error without preserving private exception chains."""
    try:
        return _run_launcher_checked(argv)
    except RuntimeSetupError as error:
        message = str(error)
    except Exception:
        message = (
            "TFNF_RUNTIME_INTEGRITY: Runtime setup failed; reinstall the Python package or runtime."
        )
    raise RuntimeSetupError(message)


def main_tfnf() -> None:
    try:
        raise SystemExit(run_launcher())
    except RuntimeSetupError as error:
        print(str(error), file=sys.stderr)
    except Exception:
        print("TFNF_RUNTIME_INTEGRITY: Runtime setup failed; reinstall the Python package or runtime.",
              file=sys.stderr)
    raise SystemExit(1)
