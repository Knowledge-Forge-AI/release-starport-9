"""Bounded read-only RPM header parser and tag delta inspector.

Provides robust bounded parsing for RPM headers:
- Header decoding according to RPM format (lead, signature, main header).
- Reader API header_delta(a: bytes, b: bytes) -> list[int] returning sorted differing tag IDs.
- Reader API tag_digest_map(data: bytes) -> dict[int, str] mapping tag ID to entry digest.
- Strict bounds checks preventing resource exhaustion or malformed structure traversal.
"""

from __future__ import annotations

import hashlib
import struct
from typing import Any

RPM_LEAD_MAGIC = b"\xed\xab\xee\xdb"
RPM_HEADER_MAGIC = b"\x8e\xad\xe8\x01"

MAX_HEADER_DATA_BYTES = 256 * 1024 * 1024
MAX_INDEX_COUNT = 20000

TAG_NAMES: dict[int, str] = {
    1000: "NAME",
    1001: "VERSION",
    1002: "RELEASE",
    1003: "EPOCH",
    1004: "SUMMARY",
    1005: "DESCRIPTION",
    1006: "BUILDTIME",
    1007: "BUILDHOST",
    1008: "INSTALLTIME",
    1009: "SIZE",
    1010: "DISTRIBUTION",
    1011: "VENDOR",
    1014: "LICENSE",
    1015: "PACKAGER",
    1016: "GROUP",
    1020: "URL",
    1021: "OS",
    1022: "ARCH",
    1027: "FILENAMES",
    1028: "FILESIZES",
    1030: "FILEMODES",
    1034: "FILEMTIMES",
    1035: "FILEDIGESTS",
    1094: "COOKIE",
    1116: "DIRINDEXES",
    1117: "BASENAMES",
    1118: "DIRNAMES",
    1122: "OPTFLAGS",
    1123: "PAYLOADFORMAT",
    1124: "PAYLOADCOMPRESSOR",
    1125: "PAYLOADFLAGS",
    1146: "SOURCEPKGID",
}


def parse_header(data: bytes, start: int = 0) -> tuple[dict[int, dict[str, Any]], int]:
    """Parse a single RPM header structure starting at byte offset start.

    Returns (tags_dict, end_offset).
    Each tag entry contains 'type', 'count', 'value', and 'raw'.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise ValueError("invalid-rpm-header-type")
    if len(data) > MAX_HEADER_DATA_BYTES:
        raise ValueError("header-bound")
    if start < 0 or start + 16 > len(data):
        raise ValueError("header-truncation")
    if data[start : start + 4] != RPM_HEADER_MAGIC:
        raise ValueError("invalid-rpm-header")

    count, size = struct.unpack_from(">II", data, start + 8)
    offset = start + 16 + 16 * count
    if count > MAX_INDEX_COUNT or size > MAX_HEADER_DATA_BYTES or offset + size > len(data):
        raise ValueError("header-bound")

    store = data[offset : offset + size]
    result: dict[int, dict[str, Any]] = {}

    for i in range(count):
        tag, typ, off, num = struct.unpack_from(">IIII", data, start + 16 + i * 16)
        if tag in result:
            raise ValueError("duplicate-header-tag")
        if off > len(store) or num > MAX_INDEX_COUNT:
            raise ValueError("header-index")

        if typ in (1, 2):
            length = num
            if off + length > len(store):
                raise ValueError("integer-bound")
            raw_slice = store[off : off + length]
            value: Any = list(raw_slice)
        elif typ == 3:
            length = num * 2
            if off + length > len(store):
                raise ValueError("integer-bound")
            raw_slice = store[off : off + length]
            value = list(struct.unpack_from(">" + "H" * num, store, off))
        elif typ == 4:
            length = num * 4
            if off + length > len(store):
                raise ValueError("integer-bound")
            raw_slice = store[off : off + length]
            value = list(struct.unpack_from(">" + "I" * num, store, off))
        elif typ == 5:
            length = num * 8
            if off + length > len(store):
                raise ValueError("integer-bound")
            raw_slice = store[off : off + length]
            value = list(struct.unpack_from(">" + "Q" * num, store, off))
        elif typ == 6:
            if num != 1:
                raise ValueError("string-count")
            end = store.find(b"\0", off)
            if end == -1:
                raise ValueError("string-terminator")
            raw_slice = store[off : end + 1]
            value = [store[off:end].decode("utf-8", errors="strict")]
        elif typ == 7:
            length = num
            if off + length > len(store):
                raise ValueError("binary-bound")
            raw_slice = store[off : off + length]
            value = raw_slice.hex()
        elif typ in (8, 9):
            cur = off
            str_list = []
            for _ in range(num):
                end = store.find(b"\0", cur)
                if end == -1:
                    raise ValueError("string-terminator")
                str_list.append(store[cur:end].decode("utf-8", errors="strict"))
                cur = end + 1
            raw_slice = store[off:cur]
            value = str_list
        else:
            raise ValueError(f"unsupported-type: {typ}")

        result[tag] = {
            "type": typ,
            "count": num,
            "value": value,
            "raw": raw_slice,
        }

    return result, offset + size


def inspect_rpm(data: bytes) -> tuple[dict[int, dict[str, Any]], dict[int, dict[str, Any]], bytes]:
    """Parse complete RPM: lead (96 bytes), signature header, main header, and compressed payload.

    Returns (signature_header, main_header, payload_bytes).
    """
    if not isinstance(data, (bytes, bytearray)):
        raise ValueError("invalid-rpm-type")
    if len(data) > MAX_HEADER_DATA_BYTES:
        raise ValueError("header-bound")
    if len(data) < 112 or data[:4] != RPM_LEAD_MAGIC:
        raise ValueError("invalid-rpm-reference")

    sig, end = parse_header(data, 96)
    main_offset = (end + 7) & ~7
    main, end = parse_header(data, main_offset)
    payload = data[end:]
    return sig, main, payload


def tag_digest_map(data: bytes) -> dict[int, str]:
    """Compute mapping of tag_id (int) -> SHA-256 digest of tag type, count, and raw store slice.

    Supports full RPM package bytes or raw RPM header bytes.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise ValueError("invalid-rpm-data")
    if data.startswith(RPM_LEAD_MAGIC):
        _, main, _ = inspect_rpm(data)
        header_entries = main
    elif data.startswith(RPM_HEADER_MAGIC):
        header_entries, _ = parse_header(data, 0)
    else:
        raise ValueError("invalid-rpm-header")

    digests: dict[int, str] = {}
    for tag, entry in header_entries.items():
        typ = entry["type"]
        num = entry["count"]
        raw = entry["raw"]
        digest = hashlib.sha256(struct.pack(">II", typ, num) + raw).hexdigest()
        digests[tag] = digest
    return digests


def header_delta(a: bytes, b: bytes) -> list[int]:
    """Compare two RPMs or headers; return sorted list of differing main header tag IDs (list[int])."""
    da = tag_digest_map(a)
    db = tag_digest_map(b)
    all_tags = set(da.keys()) | set(db.keys())
    return sorted([t for t in all_tags if da.get(t) != db.get(t)])
