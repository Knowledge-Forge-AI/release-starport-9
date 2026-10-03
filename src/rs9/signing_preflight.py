"""Attended production custody inspection. No signing or secret export."""
import argparse
import hashlib
import json
import re
import subprocess
import time

from rs9.errors import ContractError

PRIMARY = "7D03EE84F8C7025FD2F3D772BF89DF6643C2F1AF"
SIGNING = "C021E00EE3D37C459B0E1CB3199F8028126E8A8C"


def inspect_listing(text, *, now):
    """Parse documented colon fields; discard UIDs, grips and token serials."""
    keys, pending, parent = {}, None, None
    for line in text.splitlines():
        fields = line.split(":")
        if fields[0] in {"sec", "ssb"}:
            if len(fields) < 15:
                raise ContractError("SIGNING_PREFLIGHT", "Incomplete GnuPG key listing")
            pending = fields
            if fields[0] == "sec":
                parent = None
        elif fields[0] == "fpr" and pending is not None:
            fingerprint = fields[9] if len(fields) > 9 else ""
            if not re.fullmatch(r"[0-9A-F]{40}", fingerprint):
                raise ContractError("SIGNING_PREFLIGHT", "Unsupported fingerprint listing")
            if fingerprint in keys:
                raise ContractError("SIGNING_PREFLIGHT", "Ambiguous fingerprint listing")
            if pending[0] == "sec":
                parent = fingerprint
            try:
                expiry = int(pending[6] or "0")
            except ValueError:
                raise ContractError("SIGNING_PREFLIGHT", "Unsupported expiration listing") from None
            capabilities = pending[11]
            keys[fingerprint] = {"primary": parent, "usable": pending[1] not in {"r", "e", "d", "i", "n"}
                and "D" not in capabilities and (expiry == 0 or expiry > now),
                "signing": "s" in capabilities, "secret_available": pending[14] == "+"}
            pending = None
    primary, signing = keys.get(PRIMARY, {}), keys.get(SIGNING, {})
    return {"primary_fingerprint": PRIMARY, "signing_fingerprint": SIGNING,
            "primary_present": bool(primary), "primary_usable": primary.get("usable", False),
            "signing_present": bool(signing), "signing_usable": signing.get("usable", False),
            "signing_capability": signing.get("signing", False), "secret_available": signing.get("secret_available", False),
            "signing_bound_to_primary": signing.get("primary") == PRIMARY}


def inspect_custody(pinned_public_key_sha256):
    """Compare the exact binary output of `gpg --batch --export PRIMARY`.

    The reviewed digest must use this same export command and public keyring
    content. UID/certification changes can alter it without changing fingerprints;
    they require attended digest review, never a silent digest refresh.
    """
    if not re.fullmatch(r"[0-9a-f]{64}", pinned_public_key_sha256 or ""):
        raise ContractError("SIGNING_PREFLIGHT", "Reviewed public-key digest required")
    # stdout is held only in memory and never printed or retained. --with-secret
    # explicitly requests '+' availability; stubs/cards do not satisfy this lane.
    result = subprocess.run(["gpg", "--batch", "--with-colons", "--fixed-list-mode", "--with-secret",
                             "--with-fingerprint", "--with-fingerprint", "--list-secret-keys", PRIMARY],
                            capture_output=True, timeout=20)
    if result.returncode:
        raise ContractError("SIGNING_PREFLIGHT", "Custody inspection unavailable")
    facts = inspect_listing(result.stdout.decode(), now=int(time.time()))
    public = subprocess.run(["gpg", "--batch", "--export", PRIMARY], capture_output=True, timeout=20)
    facts["public_key_matches"] = public.returncode == 0 and bool(public.stdout) and hashlib.sha256(public.stdout).hexdigest() == pinned_public_key_sha256
    facts["inspection_satisfied"] = all(v for k, v in facts.items() if not k.endswith("fingerprint"))
    facts.update(signing_performed=False, publication_authority=False, passphrase_usability="not-tested")
    return facts


def main(argv=None):
    parser = argparse.ArgumentParser(description="Attended signing-key custody inspection; does not sign")
    parser.add_argument("--pinned-public-key-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        facts = inspect_custody(args.pinned_public_key_sha256)
        print(json.dumps(facts, indent=2, sort_keys=True))
        return 0 if facts["inspection_satisfied"] else 2
    except (ContractError, OSError, ValueError, subprocess.SubprocessError):
        print("Signing custody inspection unavailable; no private data retained.")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
