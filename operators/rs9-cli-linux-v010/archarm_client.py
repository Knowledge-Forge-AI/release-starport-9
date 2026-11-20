"""Exercise the signed RS9 CLI with the existing qualified native ArchARM SDK."""

import os
from pathlib import Path
import shutil
import sys

from rs9.archarm_sdk import acquire_sdk
from rs9.build_native import SubprocessRunner
from rs9.current_generation import CURRENT_GENERATION
from rs9.hosted_signing_preflight import PRIMARY


def config(server):
    return ("[options]\nArchitecture = aarch64\nGPGDir = /tmp/rs9-cli-keyring\n"
            "SigLevel = PackageRequired DatabaseRequired\nLocalFileSigLevel = Required\n"
            f"[rs9]\nServer = file://{server}\n")


def run(inputs, work):
    root = "/srv/rs9-cli-admitted"
    live = root + "/packages/rs9"
    keys = live + "/keys/rs9-signing.gpg"
    inputs.joinpath("client.conf").write_text(config(live + "/pacman/aarch64"))
    shutil.copytree(inputs / "packages/rs9/pacman/aarch64", inputs / "tampered")
    with (inputs / "tampered/rs9.db").open("ab") as file:
        file.write(b"tampered\n")
    inputs.joinpath("negative.conf").write_text(config(root + "/tampered"))
    probe = work / "probe"
    probe.mkdir(mode=0o700)
    uid, gid = os.getuid(), os.stat(work).st_gid
    context = {"runId": os.environ["GITHUB_RUN_ID"], "runAttempt": 1,
               "sourceSha": os.environ["GITHUB_SHA"], "generation": CURRENT_GENERATION}
    with acquire_sdk(host=SubprocessRunner(), workspace=work / "sdk", context=context,
                     uid=uid, gid=gid, input_profile="successor-20261120") as sdk:
        with sdk.client([(inputs, root, False)], probe) as client:
            def checked(*argv, user=None):
                result = client.exec(argv, user=user)
                if not result.executed or result.exit_code != 0:
                    raise RuntimeError("RS9_ARCHARM_CLIENT_COMMAND " + argv[0])
                return result.stdout_bytes
            for args in (("--init",), ("--add", keys), ("--lsign-key", PRIMARY)):
                checked("/usr/bin/pacman-key", "--gpgdir", "/tmp/rs9-cli-keyring", *args)
            command = ("/usr/bin/pacman", "--config", root + "/client.conf")
            checked(*command, "-Sy", "--noconfirm", "release-starport-9")
            if not client.verify_unprivileged_identity():
                raise RuntimeError("RS9_ARCHARM_CLIENT_IDENTITY")
            if checked("/usr/bin/rs9", "--version", user=sdk.user).strip() != b"0.1.0":
                raise RuntimeError("RS9_ARCHARM_CLIENT_VERSION")
            checked("/usr/bin/rs9", "doctor", user=sdk.user)
            checked(*command, "-R", "--noconfirm", "release-starport-9")
            checked("/usr/bin/test", "!", "-e", "/usr/bin/rs9")
            checked("/usr/bin/mkdir", "/tmp/rs9-cli-negative")
            result = client.exec(("/usr/bin/pacman", "--config", root + "/negative.conf",
                                  "--dbpath", "/tmp/rs9-cli-negative", "-Sy", "--noconfirm"))
            if (not result.executed or result.exit_code == 0
                    or b"pgp signature" not in result.stderr_bytes.lower()):
                raise RuntimeError("RS9_ARCHARM_CLIENT_TAMPER_NOT_REJECTED")
    print("RS9_LINUX_CLIENT_PASSED pacman-aarch64")


if __name__ == "__main__":
    run(Path(sys.argv[1]), Path(sys.argv[2]))
