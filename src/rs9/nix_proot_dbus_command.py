"""Pinned D-Bus session command generation and strict argument validation.

Ensures that dbus-run-session invocations in guest environments and smoke tests
always use explicit pinned store paths for dbus-run-session, dbus-daemon, and
session.conf, co-rooted at the same validated Nix store path.
"""
from __future__ import annotations

from collections.abc import Mapping
import posixpath
import re
from typing import Any, Sequence

from rs9.errors import ContractError

# Nix base-32 characters: 0-9, a-z excluding e, o, u, t.
# Pinned store root pattern: /nix/store/<32-char-hash>-<package-name>
_STORE_ROOT_PATTERN = re.compile(
    r"^/nix/store/[0-9a-df-np-sv-z]{32}-[A-Za-z0-9+._-]+$"
)

# Forbidden shell metacharacters and control characters
_FORBIDDEN_CHARS = frozenset(';|&$`<>(){}"\'\\*?!~# \t\r\n\x00')

_RUN_SESSION_SUFFIX = "/bin/dbus-run-session"
_DAEMON_SUFFIX = "/bin/dbus-daemon"
_CONFIG_SUFFIX = "/share/dbus-1/session.conf"

__all__ = ["dbus_session_command", "validate_session_bus_argv"]


def _validate_store_path_string(path: str) -> None:
    """Ensure path is a single-line canonical string without control or shell characters."""
    if not isinstance(path, str):
        raise ContractError("NIX_PROOT_DBUS", "Store path must be a string")
    if not path.startswith("/"):
        raise ContractError("NIX_PROOT_DBUS", "Store path must be absolute")
    if any(c in _FORBIDDEN_CHARS for c in path):
        raise ContractError("NIX_PROOT_DBUS", "Store path contains forbidden control or shell characters")
    if any(ord(c) < 32 or ord(c) >= 127 for c in path):
        raise ContractError("NIX_PROOT_DBUS", "Store path contains non-ASCII or control characters")
    if ".." in path.split("/"):
        raise ContractError("NIX_PROOT_DBUS", "Canonical store path required without directory traversal")
    if posixpath.normpath(path) != path:
        raise ContractError("NIX_PROOT_DBUS", "Store path must be canonical")
    if "//" in path:
        raise ContractError("NIX_PROOT_DBUS", "Store path must not contain redundant slashes")
    if path.endswith("/"):
        raise ContractError("NIX_PROOT_DBUS", "Store path must not contain trailing slashes")


def _validate_pinned_paths(run_session: str, daemon: str, config: str) -> str:
    """Strictly validate store root regex and co-root identity across all three paths."""
    for p in (run_session, daemon, config):
        _validate_store_path_string(p)

    if not run_session.endswith(_RUN_SESSION_SUFFIX):
        raise ContractError("NIX_PROOT_DBUS", "D-Bus session command binary must be /bin/dbus-run-session")

    root = run_session[:-len(_RUN_SESSION_SUFFIX)]
    if not _STORE_ROOT_PATTERN.fullmatch(root):
        raise ContractError("NIX_PROOT_DBUS", "Pinned store root required for D-Bus session command")
    if ".." in root.split("/"):
        raise ContractError("NIX_PROOT_DBUS", "Canonical store path required without directory traversal")
    if posixpath.normpath(root) != root:
        raise ContractError("NIX_PROOT_DBUS", "Store root must be canonical")

    expected_daemon = root + _DAEMON_SUFFIX
    if daemon != expected_daemon:
        raise ContractError("NIX_PROOT_DBUS", "D-Bus session daemon must share store root with dbus-run-session")

    expected_config = root + _CONFIG_SUFFIX
    if config != expected_config:
        raise ContractError("NIX_PROOT_DBUS", "D-Bus session config must share store root with dbus-run-session")

    return root


def validate_session_bus_argv(argv: Sequence[str]) -> list[str]:
    """Validate that argv matches ONLY the exact four-argument pinned command form.

    Expected form:
    [
        '<store-root>/bin/dbus-run-session',
        '--dbus-daemon=<store-root>/bin/dbus-daemon',
        '--config-file=<store-root>/share/dbus-1/session.conf',
        '--',
    ]

    Returns a new list of the 4 validated arguments. Fails closed with ContractError.
    """
    if not isinstance(argv, (list, tuple)):
        raise ContractError("NIX_PROOT_DBUS", "Exact four-argument pinned D-Bus session command required")
    if len(argv) != 4:
        raise ContractError("NIX_PROOT_DBUS", "Exact four-argument pinned D-Bus session command required")
    if any(not isinstance(arg, str) for arg in argv):
        raise ContractError("NIX_PROOT_DBUS", "D-Bus session command arguments must be strings")

    daemon_flag_prefix = "--dbus-daemon="
    config_flag_prefix = "--config-file="

    if not argv[1].startswith(daemon_flag_prefix):
        raise ContractError("NIX_PROOT_DBUS", "D-Bus session command requires pinned --dbus-daemon argument")
    if not argv[2].startswith(config_flag_prefix):
        raise ContractError("NIX_PROOT_DBUS", "D-Bus session command requires pinned --config-file argument")
    if argv[3] != "--":
        raise ContractError("NIX_PROOT_DBUS", "D-Bus session command must terminate with '--'")

    run_session = argv[0]
    daemon = argv[1][len(daemon_flag_prefix):]
    config = argv[2][len(config_flag_prefix):]

    _validate_pinned_paths(run_session, daemon, config)
    return [argv[0], argv[1], argv[2], argv[3]]


def dbus_session_command(facts: Any) -> list[str]:
    """Build the exact four-argument pinned D-Bus session command from facts.

    Returns:
    [
        facts.dbus_run_session,
        '--dbus-daemon=' + facts.dbus_daemon,
        '--config-file=' + facts.dbus_session_config,
        '--',
    ]
    """
    if facts is None:
        raise ContractError("NIX_PROOT_DBUS", "Facts object is required")

    run_session = None
    daemon = None
    config = None

    if hasattr(facts, "dbus_run_session") and hasattr(facts, "dbus_daemon") and hasattr(facts, "dbus_session_config"):
        run_session = getattr(facts, "dbus_run_session")
        daemon = getattr(facts, "dbus_daemon")
        config = getattr(facts, "dbus_session_config")
    elif isinstance(facts, Mapping):
        run_session = facts.get("dbus_run_session")
        daemon = facts.get("dbus_daemon")
        config = facts.get("dbus_session_config")
    elif hasattr(facts, "__getitem__"):
        try:
            run_session = facts["dbus_run_session"]
            daemon = facts["dbus_daemon"]
            config = facts["dbus_session_config"]
        except (KeyError, TypeError, IndexError):
            raise ContractError("NIX_PROOT_DBUS", "Facts missing required D-Bus keys")
    else:
        raise ContractError("NIX_PROOT_DBUS", "Facts must provide D-Bus session attributes or mapping keys")

    if not isinstance(run_session, str) or not isinstance(daemon, str) or not isinstance(config, str):
        raise ContractError("NIX_PROOT_DBUS", "D-Bus session fact values must be strings")

    argv = [
        run_session,
        f"--dbus-daemon={daemon}",
        f"--config-file={config}",
        "--",
    ]
    return validate_session_bus_argv(argv)
