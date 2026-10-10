"""DNF-only classification of canonical Fedora package-manager regular files.

Paths stay byte-lossless: no normalization, symlink following or payload waiver.
Legacy exclusions retain their established policy in hosted_deb/hosted_native.
"""
from __future__ import annotations

import re

from rs9.release_core import digest
from rs9.scratch import canonical

DNF_STATE_ROOTS = ("usr/lib/sysimage/libdnf5", "usr/lib/sysimage/rpm")
LEGACY_DNF_ROOTS = ("var/lib/dnf", "var/cache/libdnf5", "var/lib/rpm-state", "var/cache/dnf", "var/lib/rpm")
CANONICAL_SIX_PATHS = (
    "usr/lib/sysimage/libdnf5/system.toml",
    "usr/lib/sysimage/libdnf5/transaction_history.sqlite",
    "usr/lib/sysimage/libdnf5/transaction_history.sqlite-shm",
    "usr/lib/sysimage/libdnf5/transaction_history.sqlite-wal",
    "usr/lib/sysimage/rpm/rpmdb.sqlite",
    "usr/lib/sysimage/rpm/rpmdb.sqlite-shm",
)
# The scanner and parser share the exact grammar. No empty, dot, dot-dot,
# backslash, NUL or line-break components can match a trusted state root.
_COMPONENT = r"(?!\.{1,2}(?:/|\Z))[^/\\\r\n\x00]+"
DNF_STATE_FILE_PATTERNS = tuple(r"^" + re.escape(root) + "/" + _COMPONENT
                              + "(?:/" + _COMPONENT + r")*\Z" for root in DNF_STATE_ROOTS)
_PATTERNS = tuple(re.compile(p) for p in DNF_STATE_FILE_PATTERNS)


def is_dnf_state_file(path: str, kind: str = "file") -> bool:
    return (kind == "file" and isinstance(path, str)
            and any(pattern.fullmatch(path) is not None for pattern in _PATTERNS))


def dnf_state_policy() -> dict:
    return {"schema": "rs9.dnf-state-policy.v1", "family": "dnf",
            "roots": list(DNF_STATE_ROOTS), "classification": "package-manager-state",
            "applies_to": "regular-files-below-root", "no_normalization": True,
            "pattern_set_sha256": digest(canonical(list(DNF_STATE_FILE_PATTERNS)))}
