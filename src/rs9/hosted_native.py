"""Real native package preparation and unprivileged runtime helpers."""
import hashlib
import os
from pathlib import Path
import re
from typing import Any

from rs9.build_native import SubprocessRunner
from rs9.errors import ContractError

EXCLUDED_INVENTORY_PATTERNS = [
    r"^var/lib/pacman(/.*)?$",
    r"^var/cache/pacman(/.*)?$",
    r"^var/lib/rpm(/.*)?$",
    r"^var/cache/dnf(/.*)?$",
    r"^var/cache/yum(/.*)?$",
    r"^var/cache/ldconfig(/.*)?$",
    r"^etc/ld\.so\.cache$",
    r"^var/log(/.*)?$",
    r"^tmp(/.*)?$",
    r"^run(/.*)?$",
    r"^var/tmp(/.*)?$",
]
_COMPILED_EXCLUDES = [re.compile(p) for p in EXCLUDED_INVENTORY_PATTERNS]


def is_excluded_inventory_path(rel_path: str) -> bool:
    """Check if relative file path belongs to documented package manager db/cache."""
    clean = rel_path.lstrip("/").replace("\\", "/")
    return any(p.search(clean) is not None for p in _COMPILED_EXCLUDES)


def capture_system_inventory(root: Path | str) -> dict[str, str]:
    """Capture file hash inventory of client installation root, excluding package cache."""
    root_path = Path(root).resolve()
    inventory: dict[str, str] = {}
    if not root_path.exists():
        return inventory
    for path in sorted(root_path.rglob("*")):
        try:
            rel = path.relative_to(root_path).as_posix()
        except ValueError:
            continue
        if is_excluded_inventory_path(rel):
            continue
        if path.is_file() and not path.is_symlink():
            inventory[rel] = hashlib.sha256(path.read_bytes()).hexdigest()
        elif path.is_symlink():
            inventory[rel] = f"symlink:{os.readlink(path)}"
        elif path.is_dir():
            inventory[rel] = "dir"
    return inventory


def compare_inventories(
    before: dict[str, str], after: dict[str, str]
) -> dict[str, Any]:
    """Compare before and after installation inventories for clean removal."""
    added = {k: after[k] for k in after if k not in before}
    removed = {k: before[k] for k in before if k not in after}
    modified = {
        k: {"before": before[k], "after": after[k]}
        for k in before
        if k in after and before[k] != after[k]
    }
    is_clean = len(added) == 0 and len(removed) == 0 and len(modified) == 0
    return {
        "clean": is_clean,
        "added": sorted(added.keys()),
        "removed": sorted(removed.keys()),
        "modified": sorted(modified.keys()),
    }



def get_command_probes(command, repository=None):
    from rs9.hosted_commands import probes_for
    return probes_for(command, repository=repository)


def execute_probes(command, path, repository=None, prefix=None, env=None, runner=None):
    from rs9.hosted_commands import run_probes
    # The protocol requires an interactive subprocess, including docker exec -i.
    # Never downgrade it to an empty-stdin tool-exit check.
    return run_probes(command, path, repository=repository, prefix=prefix, env=env)


def get_signing_authority(context, scratch):
    from rs9.signing_fixture import SigningFixture
    directory = scratch / "signing-fixture"
    directory.mkdir()
    return SigningFixture(scratch_dir=directory)


def container_tool_facts(runner, names):
    """Record versions in the actual provisioned builder, outside runtime probes."""
    facts = {}
    for name in names:
        if runner.which(name) is None:
            facts[name] = "unavailable"
            continue
        result = runner.run([name, "--version"])
        lines = (result.stdout_text or result.stderr_text).splitlines()
        facts[name] = lines[0][:256] if result.exit_code == 0 and lines else "version-output-unavailable"
    return facts


def provision(family, system, pins=None, *, repository=None, runner=None):
    runner = runner or SubprocessRunner()
    cfg = (pins or {}).get(family, {})
    arch = "aarch64" if "aarch64" in system else "x86_64"
    image = cfg.get("container_digest") if family == "pacman" else cfg.get("container_digests", {}).get(arch)
    if not image or not re.fullmatch(r"[a-z0-9./_-]+@sha256:[0-9a-f]{64}", image):
        raise ContractError("CONTAINER_PIN", "Run-wide immutable platform image required",
                            details={"substage": "pin", "family": family, "system": system})
    platform = "linux/arm64" if arch == "aarch64" else "linux/amd64"
    pull = runner.run(["docker", "pull", "--platform", platform, image])
    if pull.exit_code:
        raise ContractError("CONTAINER_PULL", "Pinned platform image pull failed",
                            details={"substage": "pull", "tool": "docker", "exit_code": pull.exit_code,
                                     "stdout_sha256": pull.stdout_sha256, "stderr_sha256": pull.stderr_sha256})
    result = runner.run(["docker", "run", "--rm", "--network", "none", "--platform", platform, image,
                         "sh", "-c", "cat /etc/os-release; uname -m"])
    lines = [line.strip() for line in result.stdout_text.splitlines() if line.strip()]
    if result.exit_code or not lines or arch not in lines[-1]:
        raise ContractError("CONTAINER_ARCH", "Actual container architecture mismatch",
                            details={"substage": "architecture", "tool": "uname", "exit_code": result.exit_code,
                                     "stdout_sha256": result.stdout_sha256, "stderr_sha256": result.stderr_sha256})
    release = dict(line.split("=",1) for line in lines if "=" in line)
    if (family == "rpm" and release.get("VERSION_ID", "").strip(chr(34)) != "43") or (family == "pacman" and release.get("ID", "").strip(chr(34)) != "arch"):
        raise ContractError("CONTAINER_DISTRO", "Actual distro differs from contract",
                            details={"substage": "distro", "tool": "cat", "exit_code": result.exit_code,
                                     "stdout_sha256": result.stdout_sha256, "stderr_sha256": result.stderr_sha256})
    packages = ["nodejs", "gtk3", "cairo", "pango", "gdk-pixbuf2", "libsoup3", "webkit2gtk-4.1"] if family == "pacman" else ["nodejs", "gtk3", "cairo", "pango", "gdk-pixbuf2", "libsoup3", "webkit2gtk4.1"]
    source_pinned = (pins or {}).get("pin_provenance", {}).get(family + "." + arch) == "source-pinned"
    return {"family":family,"system":system,"image_ref":image,"digest":image.split("@")[1],
            "platform":platform,"source_pinned":source_pinned,"unpinned":not source_pinned,
            "preprovisioned_packages":packages,"os_release":release}


def execute(context):
    from rs9.hosted_packaging import execute
    return execute(context)
