"""Executable proposal driver for one held OS080 RPM construction lane.

The driver is intentionally separate from ``hosted_pipeline.run_lane``: it
authenticates only Nebular, provisions only the existing Fedora RPM builder,
invokes the bounded adapter, and emits one sanitized readback. It is not a
publication, signing, installation, or qualification command.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
from typing import Any, Callable

from rs9.build_native import SubprocessRunner
from rs9.build_rpm import build_rpm_candidate
from rs9.candidate import capture_generation
from rs9.current080_rpm_keyfree import (
    GENERATION,
    POLICY_PATH,
    POLICY_SHA256,
    PROJECT,
    construct_and_readback,
    request_for_system,
)
from rs9.errors import ContractError, safe_details
from rs9.github import PublicClient
from rs9.hosted_deb import (
    ContainerRunner,
    RecordingRunner,
    _cleanup_step,
    provision_image,
)
from rs9.hosted_native import provision
from rs9.release_core import digest
from rs9.scratch import ConfinedWriter, canonical, physical_directory


DRIVER_SCHEMA = "rs9.current080-rpm-keyfree-driver-receipt.v1"
EXPECTED_REPOSITORY = "Knowledge-Forge-AI/release-starport-9"
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
MAX_RECEIPT_BYTES = 2 * 1024 * 1024
RPM_TOOL_PACKAGES = (
    "rpm-build",
    "rpmlint",
    "createrepo_c",
    "binutils",
    "findutils",
    "python3",
)


def _fail(code: str, message: str) -> None:
    raise ContractError(code, message)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Held OS080 Nebular RPM construction/readback; no signing or publication"
    )
    parser.add_argument("--repository", required=True)
    parser.add_argument("--scratch", required=True)
    parser.add_argument("--receipts", required=True)
    parser.add_argument("--system", choices=("x86_64-linux", "aarch64-linux"), required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--source-tree", required=True)
    parser.add_argument("--generation", default=GENERATION)
    return parser.parse_args(argv)


def _validate_checkout(args: argparse.Namespace) -> None:
    if args.generation != GENERATION:
        _fail("KEYFREE_SOURCE", "Source checkout identity is not the reviewed exact binding")
    for value in (args.source_commit, args.source_tree):
        if not isinstance(value, str) or HEX40.fullmatch(value) is None or value == "0" * 40:
            _fail("KEYFREE_SOURCE", "Source checkout identity is not a real 40-hex binding")
    actual_sha = os.environ.get("GITHUB_SHA")
    if actual_sha is not None and actual_sha != args.source_commit:
        _fail("KEYFREE_SOURCE", "Source commit differs from the workflow checkout")
    if os.environ.get("GITHUB_ACTIONS") == "true":
        if os.environ.get("GITHUB_REPOSITORY") != EXPECTED_REPOSITORY:
            _fail("KEYFREE_SOURCE", "Workflow repository context differs")
        if os.environ.get("GITHUB_RUN_ATTEMPT") != "1":
            _fail("KEYFREE_SOURCE", "Only the original workflow attempt is accepted")
        if actual_sha != args.source_commit:
            _fail("KEYFREE_SOURCE", "Source commit must equal github.sha")
        workspace = os.environ.get("GITHUB_WORKSPACE")
        if workspace and Path(args.repository).resolve() != Path(workspace).resolve():
            _fail("KEYFREE_SOURCE", "Driver repository differs from the workflow workspace")


def _verify_checkout_identity(repository: Path, commit: str, tree: str, *, run: Callable[..., Any] = subprocess.run) -> None:
    """Read the actual checkout identities before any capture or container work."""
    for ref, expected in (("HEAD", commit), ("HEAD^{tree}", tree)):
        try:
            result = run(
                ["git", "--no-optional-locks", "-C", str(repository), "rev-parse", "--verify", ref],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                timeout=10, check=False,
            )
            valid = result.returncode == 0 and result.stdout == (expected + "\n").encode("ascii")
        except (OSError, subprocess.TimeoutExpired, UnicodeError):
            valid = False
        if not valid:
            _fail("KEYFREE_SOURCE", "Actual checkout commit or tree differs from its binding")


def _load_pins(repository: Path, system: str) -> dict[str, Any]:
    path = repository / "operators" / "live1" / "targets.json"
    if path.is_symlink() or not path.is_file():
        _fail("KEYFREE_PIN", "Maintained RPM target pins are unavailable")
    try:
        targets = json.loads(path.read_bytes())
        rpm = targets["rpm"]
        arch = "aarch64" if system == "aarch64-linux" else "x86_64"
        expected_digest = {
            "x86_64": "sha256:c5e15bd1e07c25904d0c5b9865fb7ee4589f8ca234e635742b0c1195838f4bfd",
            "aarch64": "sha256:0b0303ee12217251f2ec18a71a21284f383e99d1d3bae1eb6c8970fd2e16e26b",
        }[arch]
        if (
            rpm["distribution"] != "fedora-43"
            or rpm["container_repository"] != "registry.fedoraproject.org/fedora"
            or rpm["container_tag"] != "43"
            or rpm["container_digests"][arch] != expected_digest
        ):
            _fail("KEYFREE_PIN", "Maintained Fedora RPM target pin differs")
        container_repository = rpm["container_repository"]
        container_digests = {
            name: f"{container_repository}@{rpm['container_digests'][name]}"
            for name in ("x86_64", "aarch64")
        }
        return {
            "rpm": {
                "container_repository": container_repository,
                "container_tag": rpm["container_tag"],
                "container_digests": container_digests,
            },
            "pin_provenance": {
                "rpm.x86_64": "source-pinned",
                "rpm.aarch64": "source-pinned",
            },
        }
    except (KeyError, TypeError, ValueError):
        _fail("KEYFREE_PIN", "Maintained Fedora RPM target pin is malformed")


def _require_inventory_retention(repository: Path) -> None:
    """Refuse before any container work unless the reviewed builder delta exists."""
    path = repository / "src" / "rs9" / "build_rpm.py"
    if path.is_symlink() or not path.is_file():
        _fail("KEYFREE_SOURCE", "Reviewed RPM inventory-retention seam is unavailable")
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        _fail("KEYFREE_SOURCE", "Reviewed RPM inventory-retention seam is unreadable")
    marker = "err.preservation_inventory = inventory\n        err.preservation_inventory_receipts = inventory_receipts"
    if source.count(marker) != 1:
        _fail("KEYFREE_SOURCE", "Reviewed RPM inventory-retention seam is not applied exactly once")


def _load_policy(repository: Path, request: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    path = repository / POLICY_PATH
    if path.is_symlink() or not path.is_file():
        _fail("KEYFREE_POLICY", "Exact held OS080 policy is unavailable")
    try:
        policy_bytes = path.read_bytes()
        if digest(policy_bytes) != POLICY_SHA256:
            _fail("KEYFREE_POLICY", "Exact held OS080 policy is unavailable")
        raw = json.loads(policy_bytes)
        project = raw["projects"][PROJECT]
        summary = {
            "path": POLICY_PATH,
            "sha256": POLICY_SHA256,
            "status": raw["status"],
            "blocking": raw["blocking"],
            "exceptions": project["exceptions"],
            "production_enabled": raw["production_enabled"],
            "publication_authority": raw["publication_authority"],
        }
        if (
            summary != request["policy"]
            or raw["generation"] != GENERATION
            or raw["schema"] != "rs9.rpm-lint-policy.v1"
        ):
            _fail("KEYFREE_POLICY", "Exact held OS080 policy binding differs")
        return raw, summary
    except (KeyError, TypeError, ValueError):
        _fail("KEYFREE_POLICY", "Held OS080 policy is malformed")


def verify_capture(request: dict[str, Any], capture: Any, intent: dict[str, Any]) -> None:
    """Bind the in-process authenticated capture to the closed request."""
    if intent.get("project", {}).get("id") != PROJECT:
        _fail("KEYFREE_CAPTURE", "Authenticated capture project differs")
    record = getattr(capture, "record", None)
    metadata = getattr(capture, "asset_metadata", None)
    archives = getattr(capture, "archives", None)
    if not isinstance(record, dict) or not isinstance(metadata, dict) or not isinstance(archives, dict):
        _fail("KEYFREE_CAPTURE", "Authenticated capture object is incomplete")
    if (
        record.get("release", {}).get("id") != request["source"]["release_id"]
        or record.get("release", {}).get("tag") != request["source"]["tag"]
        or record.get("tag", {}).get("commit") != request["source"]["commit"]
        or record.get("tag", {}).get("tree") != request["source"]["tree"]
    ):
        _fail("KEYFREE_CAPTURE", "Authenticated release identity differs")
    asset = request["raw_asset"]
    observed = metadata.get(asset["name"])
    if (
        not isinstance(observed, dict)
        or observed.get("github_asset_id") != asset["github_asset_id"]
        or observed.get("size") != asset["bytes"]
        or observed.get("sha256") != asset["sha256"]
    ):
        _fail("KEYFREE_CAPTURE", "Authenticated raw RPM asset differs")
    payload_rows = record.get("payloads")
    if not isinstance(payload_rows, list) or any(not isinstance(row, dict) for row in payload_rows):
        _fail("KEYFREE_CAPTURE", "Authenticated payload manifest list is malformed")
    payloads = [
        row
        for row in payload_rows
        if row.get("github_asset_id") == asset["github_asset_id"]
    ]
    if len(payloads) != 1 or (
        payloads[0].get("payload_manifest_sha256") != asset["release_payload_manifest_sha256"]
        or payloads[0].get("member_count") != asset["release_payload_member_count"]
    ):
        _fail("KEYFREE_CAPTURE", "Authenticated RPM payload manifest differs")
    if payloads[0].get("id") not in archives:
        _fail("KEYFREE_CAPTURE", "Authenticated RPM archive key differs")


def _write_receipt(root: Path, system: str, receipt: dict[str, Any]) -> None:
    encoded = canonical(receipt, validate=True)
    if len(encoded) > MAX_RECEIPT_BYTES:
        _fail("KEYFREE_READBACK", "Driver receipt exceeds the bounded evidence budget")
    with ConfinedWriter(root) as writer:
        writer.write(f"current080-rpm-keyfree-{system}.json", encoded)


def _refusal(system: str, code: str, details: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "schema": DRIVER_SCHEMA,
        "status": "refused",
        "system": system,
        "accepted": False,
        "production_enabled": False,
        "publication_authority": False,
        "error": code,
        "details": safe_details(details or {}),
    }


def run_lane(
    args: argparse.Namespace,
    *,
    capture_factory: Callable[..., Any] = capture_generation,
    provisioner: Callable[..., Any] = provision,
    image_provisioner: Callable[..., Any] = provision_image,
    builder: Callable[..., Any] = build_rpm_candidate,
    adapter: Callable[..., Any] = construct_and_readback,
    host_factory: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Run the narrow future lane; tests may inject only bounded pure seams."""
    _validate_checkout(args)
    repository = physical_directory(args.repository)
    _verify_checkout_identity(repository, args.source_commit, args.source_tree)
    scratch = physical_directory(args.scratch)
    receipts = physical_directory(args.receipts)
    if any(scratch.iterdir()) or any(receipts.iterdir()):
        _fail("OUTPUT_NOT_EMPTY", "Fresh key-free lane roots are required")
    _require_inventory_retention(repository)
    request = request_for_system(args.system)
    raw_policy, summary_policy = _load_policy(repository, request)
    pins = _load_pins(repository, args.system)
    host = host_factory() if host_factory is not None else RecordingRunner(SubprocessRunner(timeout=1800))
    capture_root = scratch / "capture"
    capture_root.mkdir()
    client = PublicClient(api_token=os.environ.get("RS9_GITHUB_READ_TOKEN"))
    captures = capture_factory(
        repository,
        capture_root,
        project=PROJECT,
        client=client,
        checkout_binding="hosted:" + args.source_commit,
        generation=GENERATION,
    )
    if len(captures) != 1:
        _fail("KEYFREE_CAPTURE", "Exactly one Nebular capture is required")
    capture, intent, _profile = captures[0]
    verify_capture(request, capture, intent)
    environment = provisioner("rpm", args.system, pins, runner=host)
    tag = "rs9-rpm-keyfree-" + args.system
    cleanup = "failed"
    try:
        image_provisioner(
            host,
            "dnf",
            environment["image_ref"],
            environment["platform"],
            tag,
            [*environment["preprovisioned_packages"], *RPM_TOOL_PACKAGES],
            recorder=host,
            substage_prefix="rpm-keyfree-",
        )
        work = scratch / "build"
        work.mkdir()
        user = f"{os.getuid()}:{os.getgid()}"
        runner = RecordingRunner(
            ContainerRunner(
                host,
                tag,
                platform=environment["platform"],
                mounts=[(str(scratch), str(scratch), True)],
                user=user,
            )
        )
        result = adapter(
            builder,
            request,
            capture,
            intent,
            work,
            runner=runner,
            policy=summary_policy,
            builder_policy=raw_policy,
        )
    finally:
        cleanup = _cleanup_step(host, host, ["docker", "rmi", "-f", tag], "rpm-keyfree-image-cleanup")
    if cleanup != "complete":
        _fail("CONTAINER_CLEANUP", "RPM key-free builder image cleanup failed")
    receipt = {
        "schema": DRIVER_SCHEMA,
        "status": "policy-held",
        "accepted": False,
        "production_enabled": False,
        "publication_authority": False,
        "system": args.system,
        "source_checkout": {"commit": args.source_commit, "tree": args.source_tree},
        "cleanup": cleanup,
        "readback": result,
    }
    _write_receipt(receipts, args.system, receipt)
    return receipt


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        run_lane(args)
    except (ContractError, OSError, TypeError, ValueError, KeyError, AttributeError) as error:
        # A refusal record is emitted only when its root was still empty; no
        # exception text or raw process output is ever written to the receipt.
        try:
            receipts = physical_directory(args.receipts)
            if not any(receipts.iterdir()):
                _write_receipt(receipts, args.system, _refusal(args.system, getattr(error, "code", "KEYFREE_REFUSED"), getattr(error, "details", {})))
        except (ContractError, OSError, TypeError, ValueError, AttributeError):
            pass
        print("OS080 key-free RPM construction refused; no accepted artifact produced.")
        return 2
    print("OS080 key-free RPM construction reached the held policy boundary; readback retained.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
