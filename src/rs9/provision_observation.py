"""Closed observations from failed provision output; no cause or admission proof.

Only a bounded prefix is inspected. Raw lines never leave this module, and
missing names can come only from the caller's already-selected package list.
"""
from __future__ import annotations

import re
from collections.abc import Sequence

from rs9.errors import ContractError
from rs9.security import scan_for_credentials

MAX_STREAM_BYTES = 65536
MAX_LINES = 512
MAX_LINE_BYTES = 2048
MAX_SOURCE_PACKAGES = 256
MAX_MISSING_NAMES = 4
MAX_REASON_BYTES = 240

CATEGORIES = ("metadata", "mirror", "dns", "network", "tls", "repo-gpg", "no-match", "disk", "oom")
_PACKAGE = re.compile(r"[A-Za-z0-9][A-Za-z0-9+._-]{0,63}(?::[a-z0-9-]{1,16})?\Z")
_PATTERNS = {
    "metadata": re.compile(r"failed to download metadata|cannot download repomd\.xml|"
                           r"some index files failed to download|failed to synchronize all databases", re.I),
    "mirror": re.compile(r"all mirrors were tried|no more mirrors to try|failed retrieving file", re.I),
    "dns": re.compile(r"could not resolve host|couldn't resolve host name|temporary failure resolving|"
                      r"temporary failure in name resolution|name or service not known", re.I),
    "network": re.compile(r"failed to connect|connection timed out|operation timed out|"
                          r"network is unreachable|connection (?:reset|refused)|curl error \(7\)", re.I),
    "tls": re.compile(r"ssl certificate problem|certificate verify failed|"
                      r"peer certificate cannot be authenticated|ssl connect error|"
                      r"tls handshake failed|curl error \(60\)", re.I),
    "repo-gpg": re.compile(r"gpg check failed|public key for .{0,512} is not installed|"
                           r"gpg keys .{0,512} are not installed|signatures couldn't be verified|"
                           r"signature .{0,512} is unknown trust|invalid signature", re.I),
    "no-match": re.compile(r"no match for argument:|unable to find a match:|unable to locate package |"
                           r"target not found:|has no installation candidate|^no package .{0,512} available\.?$", re.I),
    "disk": re.compile(r"no space left on device|disk quota exceeded|not enough free space", re.I),
    "oom": re.compile(r"out of memory|cannot allocate memory|oom-kill", re.I),
}
_MISSING = (
    re.compile(r"^(?:error:\s*)?no match for argument:\s*(\S+)\s*$", re.I),
    re.compile(r"^(?:e:\s*)?unable to locate package\s+(\S+)\s*$", re.I),
    re.compile(r"^(?:error:\s*)?target not found:\s*(\S+)\s*$", re.I),
    re.compile(r"^(?:error:\s*)?unable to find a match:\s*(.+)$", re.I),
    re.compile(r"^(?:e:\s*)?package ['\"]([^'\"]+)['\"] has no installation candidate\s*$", re.I),
    re.compile(r"^no package (\S+) available\.?$", re.I),
)


def _source_packages(packages: Sequence[str]) -> tuple[set[str], bool]:
    if not isinstance(packages, (list, tuple)):
        return set(), True
    allowed = set()
    for name in packages[:MAX_SOURCE_PACKAGES]:
        if not isinstance(name, str) or len(name) > 64 or not _PACKAGE.fullmatch(name):
            continue
        try:
            scan_for_credentials(name)
        except ContractError:
            continue
        allowed.add(name)
    return allowed, len(packages) > MAX_SOURCE_PACKAGES


def classify_provision_failure(stdout: bytes, stderr: bytes, packages: Sequence[str]) -> str:
    """Return one existing safe_details reason_token, never raw output fragments.

    Categories mean only that a tool-output template was observed. They do not
    identify the root cause, authorize package changes, or affect failure state.
    """
    categories, missing, flags = set(), set(), set()
    allowed, source_omitted = _source_packages(packages)
    scanned = 0
    for stream in (stderr, stdout):
        if not isinstance(stream, bytes):
            flags.add("output-unreadable")
            continue
        bounded = stream[:MAX_STREAM_BYTES]
        lines = bounded.splitlines()
        if len(stream) > MAX_STREAM_BYTES:
            flags.add("scan-truncated")
            # Never interpret a partial last line as a complete missing name.
            if not bounded.endswith((b"\n", b"\r")):
                lines = lines[:-1]
        for raw in lines:
            if scanned >= MAX_LINES:
                flags.add("scan-truncated")
                break
            scanned += 1
            if len(raw) > MAX_LINE_BYTES:
                flags.add("scan-truncated")
                continue
            try:
                line = raw.decode("utf-8").strip()
            except UnicodeError:
                flags.add("output-unreadable")
                continue
            categories.update(name for name, pattern in _PATTERNS.items() if pattern.search(line))
            for pattern in _MISSING:
                match = pattern.fullmatch(line)
                if match:
                    missing.update(name for name in match.group(1).split() if name in allowed)
                    break
    parts = [name for name in CATEGORIES if name in categories] or ["unknown"]
    parts.extend(sorted(flags))
    omitted = source_omitted and "no-match" in categories
    emitted = 0
    for name in sorted(missing):
        token = "missing:" + name
        if emitted >= MAX_MISSING_NAMES or len(" ".join([*parts, token, "names-omitted"])) > MAX_REASON_BYTES:
            omitted = True
            continue
        parts.append(token)
        emitted += 1
    if omitted:
        parts.append("names-omitted")
    return " ".join(parts)
