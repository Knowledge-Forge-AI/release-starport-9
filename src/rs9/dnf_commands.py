"""Pinned guest presentation and same-command identity for DNF5 diagnostics."""
import re

from rs9.release_core import digest
from rs9.scratch import canonical

DNF_PRESENTATION = {"FORCE_COLUMNS": "512", "LC_ALL": "C", "LANG": "C", "DNF5_FORCE_INTERACTIVE": "0"}
DNF_VERSION = "5.2.18.0"
DNF_TOOL_VERSION = DNF_VERSION
DNF_REPO_ID = "rs9-fedora-nonproduction"


def guest_prefix(argv=None):
    return ["env", *(f"{k}={v}" for k, v in DNF_PRESENTATION.items()), *(argv or [])]


def command_base():
    return guest_prefix(["dnf", "-y", "--disablerepo=*", f"--enablerepo={DNF_REPO_ID}",
        f"--setopt={DNF_REPO_ID}.skip_if_unavailable=False", f"--setopt={DNF_REPO_ID}.gpgcheck=1",
        f"--setopt={DNF_REPO_ID}.repo_gpgcheck=1", "--setopt=system_cachedir=/var/cache/libdnf5",
        "--setopt=cacheonly=none", "--color=never"])


def stage_command(stage, product="RS9_PRODUCT"):
    return command_base() + (["--refresh", "makecache"] if stage == "refresh" else ["install", product])


def guest_command(receipt):
    """Remove only the owned docker-exec envelope; retain the exact guest argv."""
    command = list(receipt.command)
    if command[:2] != ["docker", "exec"]:
        return command
    offset = 2
    while offset + 1 < len(command) and command[offset] in {"-e", "--user"}:
        option, value = command[offset:offset + 2]
        if (option == "-e" and value not in {"LC_ALL=C", "LANG=C"}) or (option == "--user" and value != "0"):
            return []
        offset += 2
    if offset >= len(command) or not re.fullmatch(r"rs9-client-[0-9a-f]{12}", command[offset]):
        return []
    return command[offset + 1:]


def command_matches(receipt, stage, product="RS9_PRODUCT"):
    return receipt is not None and guest_command(receipt) == stage_command(stage, product)


def command_identities():
    return {stage: digest(canonical(stage_command(stage))) for stage in ("refresh", "install")}
