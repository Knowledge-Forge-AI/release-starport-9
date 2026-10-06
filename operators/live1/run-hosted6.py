#!/usr/bin/env python3
"""Attended run-6 adoption after exact dispatcher review acceptance.

No automatic rerun. All preflight failures emit only LOG, RC and MANAGER_PACKET.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
PARENT = "a09fcc21c68c292cd526033bb2ecebccf3167b90"


class BoundedArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError("invalid-arguments")

    def exit(self, status=0, message=None):
        raise ValueError("invalid-arguments")


def dependencies():
    sys.path.insert(0, str(ROOT / "src"))
    from rs9.candidate_inventory import MANIFEST, verify_inventory
    from rs9.collect_candidate import output_directory
    from rs9.errors import ContractError
    return MANIFEST, verify_inventory, output_directory, ContractError


def bounded_path(value):
    value = str(value)
    return value if len(value) <= 1024 and all(ord(c) >= 32 and ord(c) != 127 for c in value) else "unavailable"


def main(argv=None):
    code, stream = 2, None
    packet_dir, log, manager_packet = None, None, None
    try:
        parser = BoundedArgumentParser(description=__doc__, add_help=False)
        parser.add_argument("--reviewed-tree", required=True)
        parser.add_argument("--manifest-sha256", required=True)
        parser.add_argument("--output", type=Path, required=True,
                            help="Existing empty physical packet directory; no automatic rerun.")
        args = parser.parse_args(argv)
        requested_output = args.output
        log = requested_output.with_name(requested_output.name + ".operator.log")
        if os.path.lexists(log):
            raise ValueError("log-exists")
        manifest_path, verify_inventory, output_directory, ContractError = dependencies()
        packet_dir = output_directory(requested_output)
        log = packet_dir.with_name(packet_dir.name + ".operator.log")
        fd = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            stream = os.fdopen(fd, "wb")
        except Exception:
            os.close(fd)
            raise
        raw = (ROOT / manifest_path).read_bytes()
        if (hashlib.sha256(raw).hexdigest() != args.manifest_sha256
                or verify_inventory(ROOT, json.loads(raw), parent=PARENT) != args.reviewed_tree):
            raise ContractError("ADOPTION_REVIEW", "Accepted review differs from source")
        for command, expected in ((["branch", "--show-current"], "main"), (["rev-parse", "HEAD"], PARENT),
                                  (["rev-parse", "origin/main"], PARENT)):
            value = subprocess.check_output(["git", *command], cwd=ROOT, stderr=stream, timeout=30).decode().strip()
            if value != expected:
                raise ContractError("ADOPTION_PARENT", "Reviewed public parent and main required")
        command = [sys.executable, str(ROOT / "operators/live1/adopt-and-qualify.py"), "adopt",
                   "--repository", str(ROOT), "--reviewed-parent", PARENT, "--reviewed-tree", args.reviewed_tree,
                   "--manifest-sha256", args.manifest_sha256,
                   "--commit-message", "Repair hosted verifier, native package and observation gates for run 6",
                   "--output", str(packet_dir)]
        child_env = dict(os.environ, PYTHONPATH=str(ROOT / "src"), PYTHONDONTWRITEBYTECODE="1")
        code = subprocess.run(command, cwd=ROOT, env=child_env, stdout=stream, stderr=stream).returncode
        packet = packet_dir / "manager-packet.json"
        if packet.is_file() and not packet.is_symlink():
            manager_packet = packet
    except Exception:
        if stream is not None:
            try:
                stream.write(b"Attended operator stopped: ADOPTION_PREFLIGHT\n")
            except OSError:
                pass
    finally:
        if stream is not None:
            try:
                stream.close()
            except OSError:
                pass
    print("LOG=" + (bounded_path(log) if log is not None else "unavailable"))
    print("RC=" + str(code))
    print("MANAGER_PACKET=" + (bounded_path(manager_packet) if manager_packet is not None else "unavailable"))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
