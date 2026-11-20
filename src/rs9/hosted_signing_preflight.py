"""Verify the protected RS9 CI subkey with one throwaway signature."""

import hashlib
import os
from pathlib import Path
import re
import resource
import subprocess
import tempfile
import time

from rs9.errors import ContractError
from rs9.signing_preflight import PRIMARY, SIGNING, inspect_listing


PUBLIC_SHA256 = "6931a99cf38e204c0adc75dd868f8c0e79d68e58e2644f575d4be1da2ea18d95"
PUBLIC_KEY = Path("operators/live1/rs9-signing-public.asc")
KEY = "PACKAGE_SIGNING_KEY"
PASSPHRASE = "PACKAGE_SIGNING_PASSPHRASE"
PACKET_HEADER = re.compile(rb"(?m)^:([^:\r\n]+ packet):[^\r\n]*\r?\n")
GPG = Path("/usr/bin")


class PreflightFailure(Exception):
    """Fixed-result refusal with private diagnostics retained in memory only."""


def require(condition):
    if not condition:
        raise PreflightFailure


def gpg(home, arguments, *, data=None, binaries=GPG):
    command = [str(binaries / "gpg"), "--no-options", "--homedir", str(home), "--batch",
               "--no-tty", "--no-auto-key-retrieve", "--auto-key-locate", "local", *arguments]
    env = {"LC_ALL": "C", "LANG": "C", "PATH": str(binaries) + ":/usr/bin:/bin",
           "HOME": str(home.parent), "TMPDIR": str(home.parent)}
    return checked_command(command, env, data=data)


def checked_command(command, env, *, data=None):
    result = subprocess.run(command, input=data if data is not None else b"",
                            capture_output=True, timeout=30, env=env)
    require(result.returncode == 0)
    return result.stdout


def verify_packet_protection(output):
    # Same GnuPG labels used by the attended bundle guard. Never retain OUTPUT.
    parts = PACKET_HEADER.split(output)
    packets = list(zip(parts[1::2], parts[2::2], strict=True))
    allowed = {b"secret key packet", b"secret sub key packet", b"user ID packet", b"signature packet"}
    require(bool(packets) and all(kind in allowed for kind, _ in packets))
    primary = [body for kind, body in packets if kind == b"secret key packet"]
    subkey = [body for kind, body in packets if kind == b"secret sub key packet"]
    require(len(primary) == len(subkey) == 1)
    require(re.search(rb"(?m)^\s*gnu-dummy, algo:", primary[0]) is not None)
    require(re.search(rb"(?m)^\s*iter\+salt S2K, algo:", subkey[0]) is not None)
    require(b"[v4 protected]" in subkey[0])


def verify_imported_secret(output):
    listing = output.decode("utf-8", errors="strict")
    records = [line.split(":") for line in listing.splitlines() if line.startswith(("sec:", "ssb:"))]
    require(len(records) == 2 and all(len(fields) >= 15 for fields in records))
    require([(fields[0], fields[14]) for fields in records] == [("sec", "#"), ("ssb", "+")])
    facts = inspect_listing(listing, now=int(time.time()))
    require(all(value for key, value in facts.items() if not key.endswith("fingerprint")))


def verify_signature_status(output):
    signatures = [
        line.split()[2:] for line in output.splitlines()
        if line.startswith(b"[GNUPG:] VALIDSIG ")
    ]
    require(len(signatures) == 1 and len(signatures[0]) == 10)
    require(signatures[0][0] == SIGNING.encode("ascii"))
    require(signatures[0][-1] == PRIMARY.encode("ascii"))


def cleanup_agents(homes, *, binaries=GPG):
    failed = False
    for home in homes:
        env = {"LC_ALL": "C", "HOME": str(home.parent), "PATH": str(binaries) + ":/usr/bin:/bin"}
        try:
            checked_command([str(binaries / "gpgconf"), "--homedir", str(home), "--kill", "all"], env)
        except (PreflightFailure, OSError, subprocess.SubprocessError):
            failed = True
    require(not failed)


def verify_bundle_and_sign(secret, passphrase, *, certificate=PUBLIC_KEY, binaries=GPG):
    require(0 < len(secret) < 48 * 1024 and 0 < len(passphrase) <= 4096)
    require(not any(character in passphrase for character in b"\r\n\x00"))
    armor_begin = b"-----BEGIN PGP " + b"PRIVATE KEY BLOCK-----"
    armor_end = b"-----END PGP " + b"PRIVATE KEY BLOCK-----"
    require(secret.startswith(armor_begin) and secret.rstrip().endswith(armor_end))
    require(secret.count(armor_begin) == secret.count(armor_end) == 1)
    public = certificate.read_bytes()
    require(hashlib.sha256(public).hexdigest() == PUBLIC_SHA256)
    with tempfile.TemporaryDirectory(prefix="rs9-signing-", dir=os.environ.get("RUNNER_TEMP")) as temp:
        root = Path(temp)
        signer, verifier = root / "sign", root / "verify"
        signer.mkdir(mode=0o700)
        verifier.mkdir(mode=0o700)
        try:
            (signer / "gpg-agent.conf").write_text(
                "allow-loopback-pinentry\ndefault-cache-ttl 0\nmax-cache-ttl 0\nno-allow-external-cache\n",
                encoding="ascii",
            )
            packets = gpg(signer, ["--no-autostart", "--list-packets"], data=secret, binaries=binaries)
            verify_packet_protection(packets)
            gpg(signer, ["--import"], data=secret, binaries=binaries)
            listing = gpg(signer, ["--with-colons", "--with-secret", "--with-fingerprint",
                                  "--with-fingerprint", "--list-secret-keys"], binaries=binaries)
            verify_imported_secret(listing)
            gpg(verifier, ["--import"], data=public, binaries=binaries)
            message, signature = root / "throwaway", root / "throwaway.sig"
            message.write_bytes(b"RS9 signing preflight\n" + os.urandom(32))
            gpg(signer, ["--pinentry-mode", "loopback", "--passphrase-fd", "0",
                         "--local-user", SIGNING + "!", "--output", str(signature),
                         "--detach-sign", str(message)], data=passphrase + b"\n", binaries=binaries)
            status = gpg(verifier, ["--status-fd", "1", "--verify", str(signature), str(message)],
                         binaries=binaries)
            verify_signature_status(status)
        finally:
            cleanup_agents((signer, verifier), binaries=binaries)


def main():
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    secret = os.environ.pop(KEY, "")
    passphrase = os.environ.pop(PASSPHRASE, "")
    for name, value in ((KEY, secret), (PASSPHRASE, passphrase)):
        print(name + (": available" if value else ": unavailable"), flush=True)
    try:
        verify_bundle_and_sign(secret.encode(), passphrase.encode())
    except (PreflightFailure, ContractError, ValueError, OSError, subprocess.SubprocessError):
        print("production-signing-key-preflight: failed", flush=True)
        return 1
    print("production-signing-key-preflight: passed", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
