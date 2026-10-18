"""Runtime source copied into the wheel; Node is an explicit prerequisite."""
import os
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys


def node_binary():
    candidate = os.environ.get("THEME_FORGE_NODE_BIN") or shutil.which("node")
    if not candidate or not os.path.isfile(candidate) or not os.access(candidate, os.X_OK):
        raise RuntimeError("Node.js >=22 is required; install Node or set THEME_FORGE_NODE_BIN.")
    candidate = os.path.abspath(candidate)
    try:
        result = subprocess.run([candidate, "--version"], capture_output=True, timeout=10,
                                check=True, text=True)
    except (OSError, subprocess.SubprocessError, UnicodeError):
        raise RuntimeError("Cannot query Node.js version.") from None
    version = re.fullmatch(r"v(\d+)\.\d+\.\d+", result.stdout.strip())
    if not version or int(version[1]) < 22:
        raise RuntimeError("Node.js >=22 is required.")
    return candidate


def check_platform(node):
    script = ("console.log(JSON.stringify({platform:process.platform,arch:process.arch,"
              "glibc:process.report.getReport().header.glibcVersionRuntime||null}))")
    try:
        result = subprocess.run([node, "-e", script], capture_output=True, timeout=10,
                                check=True, text=True)
        facts = json.loads(result.stdout)
        key = facts["platform"] + "-" + facts["arch"]
        if facts["platform"] == "linux":
            if not facts.get("glibc"):
                raise ValueError("glibc required")
            key += "-gnu"
        if key != PLATFORM_KEY:
            raise ValueError("platform mismatch")
        minimum = globals().get("MIN_GLIBC")
        if minimum and tuple(map(int, facts["glibc"].split("."))) < tuple(minimum):
            raise ValueError("glibc too old")
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError):
        raise RuntimeError("TF_PYPI_NODE_PLATFORM") from None


def run(command):
    # The build-time generator appends only a validated, frozen TARGETS table.
    try:
        if os.name != "posix":
            raise RuntimeError("This adapter supports POSIX hosts only.")
        target = Path(__file__).resolve().parent / "payload/package" / TARGETS[command]
        if not target.is_file():
            raise RuntimeError("Installed entrypoint payload is missing.")
        node = node_binary()
        check_platform(node)
        os.execv(node, [node, str(target), *sys.argv[1:]])
    except (RuntimeError, OSError, KeyError) as error:
        code = "TF_PYPI_NODE_PLATFORM" if str(error) == "TF_PYPI_NODE_PLATFORM" else "TF_PYPI_NODE_REQUIRED"
        sys.stderr.write(code + ": Node.js >=22 and an intact supported POSIX installation are required.\n")
        raise SystemExit(1) from None
