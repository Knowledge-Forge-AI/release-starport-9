"""Ported pure rootfs/file/signature-status helpers (origin: qualified base/runtime probes).

``inspect_members`` only reads tar headers and three pinned public unit files;
it never extracts a rootfs. ``check_gpg_status`` accepts exactly one good
signature by the pinned fingerprint with the audited algorithm closure.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import stat
import tarfile

from rs9._archarm_support.refusal import SdkRefusal, require

FINGERPRINT = "68B3537F39A313B3E574D06777193F152BDBE6A6"
# Audited pinned-signature closure: RSA (1) with SHA-256 (8) or SHA-512 (10).
ALLOWED_PUBKEY_ALGOS = frozenset({"1"})
ALLOWED_HASH_ALGOS = frozenset({"8", "10"})
BAD_GPG_STATUS = frozenset({"BADSIG", "ERRSIG", "EXPSIG", "EXPKEYSIG", "REVKEYSIG",
                            "NO_PUBKEY", "NODATA", "BADARMOR", "UNEXPECTED", "FAILURE",
                            "ERROR", "BADMDC", "DECRYPTION_FAILED"})


def _relative(name):
    require(isinstance(name, str) and bool(name), "MEMBER_NAME")
    while name.startswith("./"):
        name = name[2:]
    name = name.rstrip("/")
    require(bool(name) and not name.startswith("/") and "\x00" not in name, "MEMBER_NAME")
    require(all(p not in ("", ".", "..") for p in name.split("/")), "MEMBER_NAME")
    return name


def _link_target(member, target, *, hardlink):
    require(isinstance(target, str) and bool(target) and "\x00" not in target, "LINK_TARGET")
    # Absolute symlinks are interpreted inside the container root. No extraction
    # to the host occurs. Hardlink targets are archive-relative names.
    require(not (hardlink and target.startswith("/")), "LINK_TARGET")
    parts = [] if hardlink or target.startswith("/") else member.split("/")[:-1]
    for part in target.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            require(bool(parts), "LINK_ESCAPE")
            parts.pop()
        else:
            parts.append(part)
    return "/".join(parts)


def inspect_members(path, pin):
    """Inspect headers and three public unit files; never extract a rootfs."""
    exceptions = {r["path"]: r for r in pin["literalEscapes"]}
    require(len(exceptions) == 3, "EXCEPTION_PIN")
    seen, observed, special, hardlinks = set(), {}, [], []
    count = size = roots = 0
    with tarfile.open(path, "r|gz") as archive:
        for member in archive:
            count += 1
            require(count <= pin["members"], "ARCHIVE_LIMIT")
            if member.name in (".", "./") and member.isdir():
                roots += 1
                continue
            name = _relative(member.name)
            require(name not in seen, "DUPLICATE_MEMBER")
            seen.add(name)
            require(member.isfile() or member.isdir() or member.issym() or member.islnk(),
                    "SPECIAL_MEMBER")
            require(member.size >= 0, "MEMBER_SIZE")
            size += member.size
            require(count <= pin["members"] and size <= pin["declaredBytes"], "ARCHIVE_LIMIT")
            if "\\" in name:
                record = exceptions.get(name)
                require(record is not None and member.isfile()
                        and member.size == record["size"] and member.mode == record["mode"],
                        "LITERAL_ESCAPE")
                body = archive.extractfile(member).read(record["size"] + 1)
                require(hashlib.sha256(body).hexdigest() == record["sha256"], "LITERAL_ESCAPE")
                observed[name] = record
            if member.mode & 0o6000:
                special.append({"path": name, "type": member.type.decode("ascii"),
                                "mode": member.mode, "size": member.size})
            if member.issym() or member.islnk():
                if "\\" in member.linkname:
                    require({"path": name, "target": member.linkname} in
                            pin["literalEscapeLinks"], "LINK_TARGET")
                target = _link_target(name, member.linkname, hardlink=member.islnk())
                if member.islnk():
                    hardlinks.append(target)
    require(count == pin["members"] and size == pin["declaredBytes"], "ARCHIVE_INVENTORY")
    require(roots == pin["rootDirectoryHeaders"], "ARCHIVE_INVENTORY")
    require(set(observed) == set(exceptions), "LITERAL_ESCAPE")
    require(sorted(special, key=lambda r: r["path"])
            == sorted(pin["setIdMembers"], key=lambda r: r["path"]), "SETID_INVENTORY")
    require(all(target in seen for target in hardlinks), "HARDLINK_TARGET")
    return {"members": count, "declaredBytes": size, "literalEscapes": len(observed),
            "setIdMembers": len(special), "filesystemExtraction": False}


def check_file(path, expected_size, expected_sha):
    path = Path(path)
    try:
        s = path.lstat()
    except OSError:
        raise SdkRefusal("INPUT_FILE") from None
    require(stat.S_ISREG(s.st_mode) and not path.is_symlink()
            and s.st_size == expected_size, "INPUT_FILE")
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    require(h.hexdigest() == expected_sha, "INPUT_HASH")


def check_gpg_status(code, status, fingerprint, label):
    require(code == 0, label)
    try:
        text = status.decode("ascii", "strict")
    except (UnicodeDecodeError, AttributeError):
        raise SdkRefusal(label) from None
    counts = {"NEWSIG": 0, "GOODSIG": 0, "VALIDSIG": 0}
    valid = good = None
    for line in text.splitlines():
        require(line.startswith("[GNUPG:] "), label)
        fields = line.split()
        require(len(fields) >= 2 and fields[1] not in BAD_GPG_STATUS, label)
        if fields[1] in counts:
            counts[fields[1]] += 1
        if fields[1] == "VALIDSIG":
            valid = fields
        elif fields[1] == "GOODSIG":
            good = fields
    require(counts["NEWSIG"] <= 1 and counts["GOODSIG"] == 1 and counts["VALIDSIG"] == 1, label)
    require(len(valid) == 12 and valid[2] == fingerprint and valid[11] == fingerprint, label)
    require(valid[6] == "4" and valid[8] in ALLOWED_PUBKEY_ALGOS
            and valid[9] in ALLOWED_HASH_ALGOS and valid[10] == "00", label)
    require(len(good) >= 3 and (good[2] == fingerprint
                                or (len(good[2]) == 16 and fingerprint.endswith(good[2]))), label)
    return True
