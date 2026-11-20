"""Assemble the exact RS9 0.1.0 Linux repositories in an offline signing container."""

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import resource
import shutil
import subprocess
import sys
import tempfile
import zipfile

from rs9.errors import ContractError
from rs9.hosted_signing_preflight import (
    PRIMARY, SIGNING, PUBLIC_KEY, PUBLIC_SHA256, PreflightFailure, cleanup_agents,
    gpg, require, verify_imported_secret, verify_packet_protection, verify_signature_status,
)


ENTRY = Path(__file__).resolve().parent
PACMAN = "release-starport-9-0.1.0-1-any.pkg.tar.zst"
RPM = "release-starport-9-0.1.0-1.noarch.rpm"
MAX_FRAME = 128 * 1024
ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C", "HOME": "/tmp"}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def command(*argv, cwd=None, fds=(), success=True):
    result = subprocess.run(argv, cwd=cwd, env=ENV, stdin=subprocess.DEVNULL,
                            capture_output=True, pass_fds=fds, timeout=90)
    require((result.returncode == 0) == success)
    return result.stdout


def admit_inputs(archive, tree, build):
    pin = json.loads((ENTRY / "inputs.json").read_bytes())
    require(pin["schema"] == "rs9.cli-v010-linux-inputs.v1")
    require(archive.is_file() and not archive.is_symlink()
            and archive.stat().st_size == pin["archive"]["bytes"] < 1024**2)
    require(sha(archive.read_bytes()) == pin["archive"]["sha256"])
    with zipfile.ZipFile(archive) as source:
        rows = source.infolist()
        require(len(rows) == len(pin["members"]) == 8)
        require({row.filename for row in rows} == set(pin["members"]))
        for row in rows:
            path = PurePosixPath(row.filename)
            require(not path.is_absolute() and all(p not in {".", ".."} for p in path.parts))
            record = pin["members"][row.filename]
            require(row.file_size == record["bytes"] < 1024**2)
            body = source.read(row)
            require(len(body) == record["bytes"] and sha(body) == record["sha256"])
            if path.parts[0] == "build-inputs":
                require(len(path.parts) == 2 and path.name in {RPM, PACMAN})
                target = build / path.name
            else:
                require(path.parts[0] == "apt")
                target = tree / path
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("xb") as handle:
                handle.write(body)


def sign(home, verifier, phrase, source, output, mode=("--detach-sign",)):
    gpg(home, ["--pinentry-mode", "loopback", "--passphrase-fd", "0",
               "--local-user", SIGNING + "!", "--digest-algo", "SHA256",
               *mode, "--output", str(output), str(source)], data=phrase + b"\n")
    signed = (str(output),) if "--clearsign" in mode else (str(output), str(source))
    verify_signature_status(gpg(verifier, ["--status-fd", "1", "--verify", *signed]))


def sign_rpm(home, phrase, rpm_db, package):
    # RPM feeds its header to GPG on stdin. The passphrase has its own inherited fd.
    reader, writer = os.pipe()
    try:
        # The input bound fits the standard pipe capacity on the Linux signing image.
        require(len(phrase) < 4096 and os.write(writer, phrase + b"\n") == len(phrase) + 1)
        os.close(writer)
        writer = None
        macro = (
            "%__gpg_sign_cmd() %{shescape:%{__gpg}} --homedir %{shescape:%{_gpg_path}} "
            "--no-options --no-autostart --batch --pinentry-mode loopback "
            f"--passphrase-fd {reader} --no-armor --no-verbose --no-secmem-warning "
            "-u %{shescape:%{_openpgp_sign_id}} -sbo %{shescape:%{2}} -- %{shescape:%{1}}"
        )
        command("/usr/bin/rpmsign", "--dbpath", str(rpm_db), "--define", "%_openpgp_sign gpg",
                "--define", f"%_openpgp_sign_id {SIGNING}!", "--define", "%__gpg /usr/bin/gpg",
                "--define", f"%_gpg_path {home}", "--define", macro, "--addsign", str(package),
                fds=(reader,))
    finally:
        os.close(reader)
        if writer is not None:
            os.close(writer)


def sign_repositories(tree, build, home, verifier, phrase):
    release = tree / "apt/dists/stable/Release"
    sign(home, verifier, phrase, release, release.with_name("InRelease"), ("--clearsign",))
    sign(home, verifier, phrase, release, release.with_name("Release.gpg"), ("--armor", "--detach-sign"))

    rpm_db = build / "rpm-keyring"
    rpm_db.mkdir(mode=0o700)
    rpm = tree / "rpm" / RPM
    rpm.parent.mkdir()
    shutil.copyfile(build / RPM, rpm)
    original = sha(command("/usr/bin/rpm2cpio", str(rpm)))
    sign_rpm(home, phrase, rpm_db, rpm)
    require(sha(command("/usr/bin/rpm2cpio", str(rpm))) == original)
    command("/usr/bin/rpmkeys", "--dbpath", str(rpm_db), "--checksig", str(rpm), success=False)
    command("/usr/bin/rpmkeys", "--dbpath", str(rpm_db), "--import", str(tree / "keys/rs9-signing.asc"))
    require(b"digests signatures OK" in command("/usr/bin/rpmkeys", "--dbpath", str(rpm_db), "--checksig", str(rpm)))
    command("/usr/bin/createrepo_c", "--checksum", "sha256", str(rpm.parent))
    metadata = rpm.parent / "repodata/repomd.xml"
    sign(home, verifier, phrase, metadata, metadata.with_suffix(".xml.asc"), ("--armor", "--detach-sign"))

    for arch in ("x86_64", "aarch64"):
        package = tree / "pacman" / arch / PACMAN
        package.parent.mkdir(parents=True)
        shutil.copyfile(build / PACMAN, package)
        sign(home, verifier, phrase, package, package.with_suffix(".zst.sig"))
        command("/usr/bin/repo-add", "--include-sigs", "rs9.db.tar.gz", PACMAN, cwd=package.parent)
        for name in ("rs9.db", "rs9.files"):
            index = package.parent / name
            archive = index.with_suffix(index.suffix + ".tar.gz")
            require(index.is_symlink() and os.readlink(index) == archive.name and archive.is_file())
            index.unlink()
            archive.rename(index)
            sign(home, verifier, phrase, index, index.with_suffix(index.suffix + ".sig"))


def inventory(output):
    entries = {}
    for path in sorted((output / "packages/rs9").rglob("*")):
        require(not path.is_symlink())
        if path.is_dir():
            continue
        require(path.is_file() and 0 < path.stat().st_size <= 16 * 1024 * 1024)
        body = path.read_bytes()
        entries[path.relative_to(output).as_posix()] = {"bytes": len(body), "sha256": sha(body)}
    return {"schema": "knowledge-forge.rs9-pages-inventory.v1", "files": entries}


def run(archive, output, secret, phrase, public):
    require(0 < len(secret) < 48 * 1024 and 0 < len(phrase) < 4096)
    require(not any(c in phrase for c in b"\r\n\x00") and sha(public) == PUBLIC_SHA256)
    require(output.is_dir() and not output.is_symlink() and not any(output.iterdir()))
    tree = output / "packages/rs9"
    with tempfile.TemporaryDirectory(prefix="rs9-cli-sign-", dir="/tmp") as directory:
        build = Path(directory)
        home, verifier = build / "sign", build / "verify"
        home.mkdir(mode=0o700)
        verifier.mkdir(mode=0o700)
        try:
            admit_inputs(archive, tree, build)
            (home / "gpg-agent.conf").write_text(
                "allow-loopback-pinentry\ndefault-cache-ttl 0\nmax-cache-ttl 0\nno-allow-external-cache\n",
                encoding="ascii")
            verify_packet_protection(gpg(home, ["--no-autostart", "--list-packets"], data=secret))
            gpg(home, ["--import"], data=secret)
            verify_imported_secret(gpg(home, ["--with-colons", "--with-secret",
                "--with-fingerprint", "--with-fingerprint", "--list-secret-keys"]))
            gpg(verifier, ["--import"], data=public)
            keys = tree / "keys"
            keys.mkdir()
            (keys / "rs9-signing.asc").write_bytes(public)
            (keys / "rs9-signing.gpg").write_bytes(gpg(verifier, ["--export", PRIMARY]))
            sign_repositories(tree, build, home, verifier, phrase)
            manifest = output / "rs9-package-inventory.json"
            manifest.write_text(json.dumps(inventory(output), sort_keys=True, indent=2) + "\n")
            sign(home, verifier, phrase, manifest, output / "rs9-package-inventory.json.sig")
        finally:
            cleanup_agents((home, verifier))


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o022)
    try:
        frame = sys.stdin.buffer.read(MAX_FRAME + 1)
        require(0 < len(frame) <= MAX_FRAME)
        request = json.loads(frame)
        require(isinstance(request, dict) and set(request) == {"key", "passphrase"})
        require(all(isinstance(value, str) for value in request.values()))
        run(Path("/input/release.zip"), Path("/output"), request["key"].encode(),
            request["passphrase"].encode(), PUBLIC_KEY.read_bytes())
    except (PreflightFailure, ContractError, KeyError, ValueError, OSError, subprocess.SubprocessError, zipfile.BadZipFile):
        print("RS9_LINUX_SIGNING_FAILED", flush=True)
        return 1
    print("RS9_LINUX_APT_RPM_PACMAN_SIGNING_VERIFIED", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
