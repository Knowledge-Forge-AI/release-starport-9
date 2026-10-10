"""Byte-bound provenance for DNF candidate trust mutations; no signing keys."""

from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
import re
import stat

from rs9.errors import ContractError
from rs9.release_core import digest
from rs9.scratch import canonical, physical_directory


def _invalid():
    raise ContractError("INVALID_TAMPER_MUTATION", "DNF mutation provenance is not exact")


def _crc24(raw: bytes) -> bytes:
    value = 0xB704CE
    for byte in raw:
        value ^= byte << 16
        for _ in range(8):
            value <<= 1
            if value & 0x1000000:
                value ^= 0x1864CFB
    return (value & 0xFFFFFF).to_bytes(3, "big")


def _signature_armor(raw: bytes):
    if len(raw) > 1024 * 1024 or b"\r" in raw or not raw.endswith(b"\n"):
        _invalid()
    lines = raw.split(b"\n")
    if lines[0] != b"-----BEGIN PGP SIGNATURE-----" or lines[-2:] != [b"-----END PGP SIGNATURE-----", b""]:
        _invalid()
    blank = 1
    while blank < len(lines) and lines[blank]:
        if not re.fullmatch(rb"[A-Za-z-]+: [ -~]*", lines[blank]):
            _invalid()
        blank += 1
    end = len(lines) - 2
    crc_index = end - 1 if lines[end - 1].startswith(b"=") else None
    body_end = crc_index if crc_index is not None else end
    body = lines[blank + 1:body_end]
    if not body or any(not re.fullmatch(rb"[A-Za-z0-9+/]+={0,2}", line) for line in body):
        _invalid()
    try:
        packet = base64.b64decode(b"".join(body), validate=True)
        if crc_index is not None and base64.b64decode(lines[crc_index][1:], validate=True) != _crc24(packet):
            _invalid()
    except ValueError:
        _invalid()
    if base64.b64encode(packet) != b"".join(body) or len(packet) < 8:
        _invalid()
    header = packet[0]
    if not header & 0x80:
        _invalid()
    if header & 0x40:
        tag = header & 0x3F
        first = packet[1]
        if first < 192:
            offset, length = 2, first
        elif first < 224:
            offset, length = 3, ((first - 192) << 8) + packet[2] + 192
        elif first == 255:
            offset, length = 6, int.from_bytes(packet[2:6], "big")
        else:
            _invalid()
    else:
        tag = (header >> 2) & 15
        length_type = header & 3
        if length_type == 3:
            _invalid()
        width = 1 << length_type
        offset, length = 1 + width, int.from_bytes(packet[1:1 + width], "big")
    if tag != 2 or offset + length != len(packet) or length < 6 or packet[offset] not in {4, 5, 6}:
        _invalid()
    return lines, blank + 1, body_end, crc_index, packet


def corrupt_dnf_signature(path: Path) -> None:
    """Change the signature value, keeping packet framing and armor valid."""
    lines, start, end, crc_index, packet = _signature_armor(path.read_bytes())
    changed = packet[:-1] + bytes([packet[-1] ^ 1])
    body = base64.b64encode(changed)
    offset = 0
    for i in range(start, end):
        width = len(lines[i])
        lines[i] = body[offset:offset + width]
        offset += width
    if crc_index is not None:
        lines[crc_index] = b"=" + base64.b64encode(_crc24(changed))
    path.write_bytes(b"\n".join(lines))


def _snapshot(root: Path):
    result = {}
    for path in sorted(root.rglob("*")):
        st = path.lstat()
        mode = stat.S_IMODE(st.st_mode)
        rel = path.relative_to(root).as_posix()
        if stat.S_ISDIR(st.st_mode):
            result[rel] = {"kind": "directory", "mode": mode}
        elif stat.S_ISREG(st.st_mode):
            sha = hashlib.sha256()
            with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as stream:
                while block := stream.read(1024 * 1024):
                    sha.update(block)
            result[rel] = {"kind": "file", "mode": mode, "size": st.st_size, "sha256": sha.hexdigest()}
        elif stat.S_ISLNK(st.st_mode):
            result[rel] = {"kind": "symlink", "mode": mode, "target_sha256": digest(os.fsencode(os.readlink(path)))}
        else:
            _invalid()
    return result


def verify_dnf_mutation(original: Path, tampered: Path, *, arch: str, product: str, kind: str,
                        wrong_signer=None, public_fingerprint: str | None = None):
    """Only the intended member changes; index and signature differ by provenance."""
    original, tampered = physical_directory(original), physical_directory(tampered)
    before, after = _snapshot(original), _snapshot(tampered)
    if set(before) != set(after):
        _invalid()
    prefix = f"fedora/43/{arch}/"
    if kind == "package":
        targets = [name for name in before if name.startswith(prefix + "Packages/" + product + "-") and name.endswith(".rpm")]
        if len(targets) != 1:
            _invalid()
        target = targets[0]
    elif kind in {"index", "signature", "wrongkey"}:
        target = prefix + "repodata/repomd.xml" + ("" if kind == "index" else ".asc")
    else:
        _invalid()
    if target not in before or before[target]["kind"] != "file" or after[target]["kind"] != "file":
        _invalid()
    changed = [name for name in before if before[name] != after[name]]
    if changed != [target] or before[target]["mode"] != after[target]["mode"]:
        _invalid()
    control, mutation = (root / target for root in (original, tampered))
    details = {}
    if kind == "package":
        if before[target]["size"] != after[target]["size"] or before[target]["size"] == 0:
            _invalid()
        with control.open("rb") as a, mutation.open("rb") as b:
            remaining = before[target]["size"] - 1
            while remaining:
                count = min(remaining, 1024 * 1024)
                if a.read(count) != b.read(count):
                    _invalid()
                remaining -= count
            if a.read(1)[0] ^ b.read(1)[0] != 1:
                _invalid()
    elif kind == "index":
        if mutation.read_bytes() != control.read_bytes() + b"<!-- tampered -->\n":
            _invalid()
        details["authentication_boundary"] = "repomd-signature"
    elif kind == "signature":
        a_lines, a_start, a_end, a_crc, a = _signature_armor(control.read_bytes())
        b_lines, b_start, b_end, b_crc, b = _signature_armor(mutation.read_bytes())
        if (len(a) != len(b) or a[:-1] != b[:-1] or a[-1] ^ b[-1] != 1
                or (a_start, a_end, a_crc) != (b_start, b_end, b_crc)
                or [len(line) for line in a_lines] != [len(line) for line in b_lines]
                or any(x != y for i, (x, y) in enumerate(zip(a_lines, b_lines))
                       if i not in range(a_start, a_end) and i != a_crc)):
            _invalid()
        details.update(packet_changed_offset=len(a)-1, packet_length=len(a), armor_framing_preserved=True)
    else:
        _signature_armor(control.read_bytes())
        _signature_armor(mutation.read_bytes())
        # Armor alone cannot establish a wrong issuer. The isolated fixture
        # verifier pins the replacement signature to its own public key. The
        # matching DNF positive control authenticates the original repository.
        issuer = getattr(wrong_signer, "primary_fingerprint", None)
        if (not isinstance(issuer, str) or not re.fullmatch(r"[0-9A-F]{40}", issuer)
                or not isinstance(public_fingerprint, str)
                or not re.fullmatch(r"[0-9A-F]{40}", public_fingerprint)
                or issuer == public_fingerprint):
            _invalid()
        verification = wrong_signer.verify((original / (prefix + "repodata/repomd.xml")).read_bytes(),
                                           mutation.read_bytes())
        if (verification.get("status") != "valid" or verification.get("verified_issuer") != issuer):
            _invalid()
        details.update(control_key_fingerprint=public_fingerprint, replacement_issuer=issuer,
                       replacement_signature_verified=True)
    return {"verified": True, "kind": kind, "target": target,
            "control_sha256": before[target]["sha256"], "tampered_sha256": after[target]["sha256"],
            "control_tree_sha256": digest(canonical(before)), "tampered_tree_sha256": digest(canonical(after)), **details}
