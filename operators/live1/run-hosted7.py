#!/usr/bin/env python3
"""Attended, exact-review-bound run-7 adoption and one push-bound collection.

Invoke only after manager acceptance. There is no automatic retry or publication.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]


class BoundedArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError("invalid-arguments")

    def exit(self, status=0, message=None):
        raise ValueError("invalid-arguments")


def main(argv=None):
    code, log, packet = 2, None, None
    streams = []
    try:
        parser = BoundedArgumentParser(add_help=False, description=__doc__)
        for flag in ("reviewed-parent", "reviewed-tree", "manifest-sha256"):
            parser.add_argument("--" + flag, required=True)
        parser.add_argument("--output", type=Path, required=True)
        parser.add_argument("--timeout", type=int, default=7200)
        parser.add_argument("--manager-attestation", type=Path)
        parser.add_argument("--manager-attestation-sha256")
        args = parser.parse_args(argv)
        sys.path.insert(0, str(ROOT / "src"))
        from rs9.candidate_inventory import MANIFEST, verify_inventory
        from rs9.collect_candidate import output_directory
        from rs9.errors import ContractError
        output = output_directory(args.output)
        log = output.with_name(output.name + ".operator.log")
        fd = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            streams.append(os.fdopen(fd, "wb"))
        except Exception:
            os.close(fd)
            raise
        raw = (ROOT / MANIFEST).read_bytes()
        manifest = json.loads(raw)
        from rs9.candidate_readiness import validate_adoption_authority
        from rs9.hosted_contract import load_hosted_lanes
        validate_adoption_authority(manifest, ROOT,
            {"reviewed_parent": args.reviewed_parent, "reviewed_tree": args.reviewed_tree,
             "manifest_sha256": args.manifest_sha256}, contract=load_hosted_lanes(ROOT),
            manager_attestation=args.manager_attestation,
            manager_attestation_sha256=args.manager_attestation_sha256)
        if (hashlib.sha256(raw).hexdigest() != args.manifest_sha256
                or verify_inventory(ROOT, manifest, parent=args.reviewed_parent) != args.reviewed_tree):
            raise ContractError("ADOPTION_REVIEW", "Source differs from exact accepted review")
        command = [sys.executable, str(ROOT / "operators/live1/adopt-and-qualify.py"), "adopt",
                   "--repository", str(ROOT), "--reviewed-parent", args.reviewed_parent,
                   "--reviewed-tree", args.reviewed_tree, "--manifest-sha256", args.manifest_sha256,
                   "--timeout", str(args.timeout), "--output", str(output),
                   "--commit-message", "Prepare partial diagnostic qualification and pinned PRoot experiment for run 7"]
        if args.manager_attestation is not None:
            command.extend(["--manager-attestation", str(args.manager_attestation),
                            "--manager-attestation-sha256", args.manager_attestation_sha256])
        # The shared adoption implementation rechecks main/index/remote parent,
        # stages only reviewed changed_paths, checks the resulting tree, makes
        # one normal commit/push, then collects the new push-bound run and stops.
        env = dict(os.environ, PYTHONPATH=str(ROOT / "src"), PYTHONDONTWRITEBYTECODE="1")
        code = subprocess.run(command, cwd=ROOT, env=env, stdout=streams[0], stderr=streams[0]).returncode
        if (output / "manager-packet.json").is_file() and not (output / "manager-packet.json").is_symlink():
            packet = output / "manager-packet.json"
    except Exception as error:
        if streams:
            from rs9.errors import ContractError
            token = error.code if isinstance(error, ContractError) else "ADOPTION_PREFLIGHT"
            streams[-1].write(("Attended operator stopped: " + token + "\n").encode())
    finally:
        for stream in streams:
            stream.close()
    # Full diagnostic streams stay in files. No publication receipt is issued.
    for name, value in (("LOG", log), ("RC", code), ("MANAGER_PACKET", packet)):
        text = str(value) if value is not None else "unavailable"
        if len(text) > 1024 or any(ord(c) < 32 or ord(c) == 127 for c in text):
            text = "unavailable"
        print(name + "=" + text)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
