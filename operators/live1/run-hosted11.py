#!/usr/bin/env python3
"""Attended, exact-review-bound run-11 adoption and one push-bound collection.

Invoke only after manager acceptance. There is no automatic retry or publication.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[2]


class BoundedArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError("invalid-arguments")

    def exit(self, status=0, message=None):
        raise ValueError("invalid-arguments")


def small_result_zip(output):
    """Explicit bounded text subset; large packages remain in separate custody."""
    from rs9.scratch import canonical
    from rs9.security import scan_for_credentials
    from rs9.hosted_custody import diagnostic_bytes
    selected = []
    for path in sorted(output.rglob("*.json")):
        relative = path.relative_to(output).as_posix()
        if (path.name in {"manager-packet.json", "hosted-summary.json", "artifact-manifest.json",
                          "evidence-provenance.json", "hosted-deb-manifest.json",
                          "native-qualification.json", "destination-observations.json",
                          "nix-proot-evaluation.json", "deb-amd64.json", "deb-arm64.json",
                          "rpm-x86_64-linux.json", "rpm-aarch64-linux.json"}
                or "diagnostics" in path.relative_to(output).parts):
            if path.is_symlink() or not path.is_file():
                raise ValueError("unsafe-result-file")
            if "diagnostics" in path.relative_to(output).parts:
                data = diagnostic_bytes(path)
            else:
                if path.stat().st_size > 16 * 1024 * 1024:
                    raise ValueError("result-text-limit")
                data = path.read_bytes()
                scan_for_credentials(data.decode("utf-8"))
                json.loads(data)
            selected.append((relative, data))
    if not any(p == "manager-packet.json" for p, data in selected):
        raise ValueError("manager-packet-missing")
    if sum(len(data) for p, data in selected) > 64 * 1024 * 1024:
        raise ValueError("result-aggregate-limit")
    upload = output.with_name(output.name + ".result.zip")
    fd = os.open(upload, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream, zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for relative, data in selected:
            archive.writestr(relative, data)
        archive.writestr("result-selection.json", canonical({
            "schema": "rs9.small-hosted-result.v1", "large_packages_embedded": False,
            "files": [{"path": p, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()} for p, data in selected]}))
    return upload


def main(argv=None):
    code, log, packet, upload = 2, None, None, None
    streams = []
    try:
        parser = BoundedArgumentParser(add_help=False, description=__doc__)
        for flag in ("reviewed-parent", "reviewed-tree", "manifest-sha256"):
            parser.add_argument("--" + flag, required=True)
        parser.add_argument("--output", type=Path, required=True)
        parser.add_argument("--collect-only", action="store_true")
        parser.add_argument("--commit")
        parser.add_argument("--run-id", type=int)
        parser.add_argument("--not-before")
        parser.add_argument("--timeout", type=int, default=7200)
        parser.add_argument("--manager-attestation", type=Path, required=True)
        parser.add_argument("--manager-attestation-sha256", required=True)
        args = parser.parse_args(argv)
        continuation = (args.commit, args.run_id, args.not_before)
        if args.collect_only:
            import re
            from datetime import datetime
            if (not all(continuation) or not re.fullmatch(r"[0-9a-f]{40}", args.commit)
                    or args.run_id <= 0 or not args.not_before.endswith("Z")):
                raise ValueError("continuation-binding-required")
            datetime.fromisoformat(args.not_before.replace("Z", "+00:00"))
        elif any(x is not None for x in continuation):
            raise ValueError("continuation-requires-collect-only")
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
                   "--commit-message", "Repair RPM durable evidence and exact Nebular preservation policy for run 11"]
        if args.collect_only:
            # Keep the original packet's time and exact run/commit identity.
            # The shared collector performs only allowlisted read operations.
            head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, stderr=streams[0]).decode().strip()
            tree = subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=ROOT, stderr=streams[0]).decode().strip()
            if head != args.commit or tree != args.reviewed_tree:
                raise ContractError("HOSTED_BINDING", "Continuation differs from adopted source")
            command = [sys.executable, str(ROOT / "operators/live1/adopt-and-qualify.py"), "collect",
                       "--repository", str(ROOT), "--output", str(output), "--timeout", str(args.timeout),
                       "--commit", args.commit, "--run-id", str(args.run_id), "--not-before", args.not_before]
        if not args.collect_only and args.manager_attestation is not None:
            command.extend(["--manager-attestation", str(args.manager_attestation),
                            "--manager-attestation-sha256", args.manager_attestation_sha256])
        from rs9.scratch import canonical
        metadata = output.with_name(output.name + ".operator.json")
        metadata_fd = os.open(metadata, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(metadata_fd, "wb") as stream:
            stream.write(canonical({"schema": "rs9.run11-operator.v1", "collect_only": args.collect_only,
                "reviewed_parent": args.reviewed_parent, "reviewed_tree": args.reviewed_tree,
                "manifest_sha256": args.manifest_sha256, "commit": args.commit,
                "run_id": args.run_id, "not_before": args.not_before,
                "production_enabled": False, "publication_authority": False}))
        # The shared adoption implementation rechecks main/index/remote parent,
        # stages only reviewed changed_paths, checks the resulting tree, makes
        # one normal commit/push, then collects the new push-bound run and stops.
        env = dict(os.environ, PYTHONPATH=str(ROOT / "src"), PYTHONDONTWRITEBYTECODE="1")
        code = subprocess.run(command, cwd=ROOT, env=env, stdout=streams[0], stderr=streams[0]).returncode
        if (output / "manager-packet.json").is_file() and not (output / "manager-packet.json").is_symlink():
            packet = output / "manager-packet.json"
            upload = small_result_zip(output)
    except Exception as error:
        code = 2
        if streams:
            from rs9.errors import ContractError
            token = error.code if isinstance(error, ContractError) else "ADOPTION_PREFLIGHT"
            streams[-1].write(("Attended operator stopped: " + token + "\n").encode())
    finally:
        for stream in streams:
            stream.close()
    # Full diagnostic streams stay in files. No publication receipt is issued.
    for name, value in (("LOG", log), ("RC", code), ("MANAGER_PACKET", packet), ("UPLOAD", upload)):
        text = str(value) if value is not None else "unavailable"
        if len(text) > 1024 or any(ord(c) < 32 or ord(c) == 127 for c in text):
            text = "unavailable"
        print(name + "=" + text)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
