"""Ordered C-locale DNF repository bootstrap and terminal failure grammar."""
import re

PROGRESS = re.compile(r"(?:>>> )?repomd\.xml GPG signature verification error: (.+)")
FATAL = re.compile(r'Failed to download metadata \(baseurl: "([^"]+)"\) for repository "([^"]+)": repomd\.xml GPG signature verification error: (.+)')
KEY_HEADER = re.compile(r"Importing OpenPGP key 0x([0-9A-Fa-f]{8,16}):")


def reason_category(reason):
    if reason == "Signing key not found":
        return "KEY_MISMATCH"
    if reason == "Bad PGP signature" or re.fullmatch(r"Bad PGP signature: [^\r\n]+", reason):
        return "SIGNATURE_REJECTED"
    return None


def _import_block(lines, offset, identity):
    """Consume one complete expected-key block without retaining UserID text."""
    header = KEY_HEADER.fullmatch(lines[offset])
    if not header or len(lines) < offset + 5:
        return None
    cursor = offset + 1
    users = 0
    while cursor < len(lines) and re.fullmatch(r'UserID\s*:\s*"[^"\r\n]{1,512}"', lines[cursor]):
        cursor += 1
        users += 1
    if not 1 <= users <= 8 or cursor + 2 >= len(lines):
        return None
    fingerprint = re.fullmatch(r"Fingerprint:\s*([0-9A-F]{40})", lines[cursor])
    if (not fingerprint or fingerprint[1] != identity["public_fingerprint"]
            or not fingerprint[1].endswith(header[1].upper())
            or not re.fullmatch(r"From\s*:\s*" + re.escape(identity["key_uri"]), lines[cursor + 1])
            or lines[cursor + 2] != "The key was successfully imported."):
        return None
    return cursor + 3


def terminal_failure(out, err, identity):
    """Return one bound fatal result; every causal line has one ordered role."""
    if any(stream and not stream.endswith("\n") for stream in (out, err)):
        return None
    # Causal text in both streams has no retained cross-stream ordering.
    causal = lambda stream: bool(re.search(r"signature verification error|Importing OpenPGP|Failed to download metadata", stream))
    if causal(out) and causal(err):
        return None
    other = out if causal(err) else err
    if re.search(r"(?i)signature|signing key|openpgp|fingerprint|issuer|userid|key was|failed|error:|skipping|disabled|ignoring", other):
        return None
    text = out + "\n" + err
    if re.search(r"(?i)issuer", text):
        return None
    uris = re.findall(r"file:[^\s\"']+", text)
    if any(uri not in {identity["source_uri"], identity["key_uri"]} for uri in uris):
        return None
    if any(repo != identity["repo_id"] for repo in re.findall(r'repository "([^"]+)"', text)):
        return None
    lines = [line.strip() for line in (err if causal(err) else out).splitlines() if line.strip()]
    events, progress, imported, terminal = [], [], False, None
    cursor = 0
    while cursor < len(lines):
        line = lines[cursor]
        fatal = FATAL.fullmatch(line)
        message = PROGRESS.fullmatch(line)
        if fatal:
            category = reason_category(fatal[3])
            if (terminal is not None or cursor != len(lines) - 1 or not progress
                    or fatal[1] != identity["source_uri"] or fatal[2] != identity["repo_id"]
                    or category is None or any(reason != fatal[3] for reason in progress)):
                return None
            terminal = category
            events.append({"phase": "terminal", "category": category})
        elif message:
            if reason_category(message[1]) is None or len(progress) >= 2:
                return None
            progress.append(message[1])
        elif KEY_HEADER.fullmatch(line):
            if imported or progress != ["Signing key not found"]:
                return None
            end = _import_block(lines, cursor, identity)
            if end is None:
                return None
            imported = True
            progress = []
            events.extend([{"phase": "bootstrap", "category": "KEY_MISMATCH"},
                           {"event": "KEY_IMPORTED", "fingerprint": identity["public_fingerprint"]}])
            cursor = end
            continue
        elif re.search(r"(?i)signature|signing key|openpgp|fingerprint|issuer|userid|^from\s*:|key was|failed|error:|no match|skipping|disabled|ignoring", line):
            return None
        cursor += 1
    if terminal is None:
        return None
    return {"category": terminal, "terminal_category": terminal,
            "intermediate_categories": ["KEY_MISMATCH"] if imported else [],
            "bootstrap_categories": ["KEY_MISMATCH"] if imported else [],
            "events": events, "imported_fingerprint": identity["public_fingerprint"] if imported else None}
