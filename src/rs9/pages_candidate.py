"""Pages candidate tree assembler and privacy verification for RS9.

Constructs candidate-only fixture signed trees in empty scratch directories
from exact inventories, strictly scanning for privacy/credentials and bounded hashes.
Enforces exact inventory bindings and strictly prohibits any live deployment or publication.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any

from rs9.errors import ContractError
from rs9.pages import (
    scan_pages_tree,
    validate_pages_tree,
)
from rs9.records import Record, snapshot, validate_sha256
from rs9.scratch import ConfinedWriter, physical_directory
from rs9.security import validate_safe_relative_posix_path
from rs9.signed_store import SignedStore, _check_no_symlinks, _safe_read_file

PAGES_HOST = "rs9.knowledge-forge.ai"


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class PagesCandidate:
    """Represents a validated Pages candidate deployment tree.

    Candidate-only: enforces exact inventory binding and strictly forbids deployment.
    """

    def __init__(
        self,
        root: Path,
        manifest: Record,
        exact_inventory: dict[str, str],
    ) -> None:
        self.root = root
        self.manifest = manifest
        self.exact_inventory = exact_inventory
        self.is_candidate = True
        self.is_live = False
        self.qualification = "pending"

    def status(self) -> dict[str, Any]:
        """Return candidate status summary."""
        return {
            "status": "candidate",
            "is_candidate": True,
            "is_live": False,
            "qualification": "pending",
            "file_count": self.manifest.get("file_count", len(self.exact_inventory)),
            "total_bytes": self.manifest.get("total_bytes", 0),
            "root": str(self.root),
            "categories": self.manifest.get("categories", {}),
            "inventory_binding": "supplied" if self.manifest["authoritative"] else "discovery",
        }

    def deploy(self, *args: Any, **kwargs: Any) -> None:
        """Candidate pages must never deploy."""
        raise ContractError(
            "DEPLOYMENT_FORBIDDEN",
            "Pages candidate cannot deploy; production publication is disabled",
        )

    def publish(self, *args: Any, **kwargs: Any) -> None:
        """Candidate pages must never publish."""
        raise ContractError(
            "DEPLOYMENT_FORBIDDEN",
            "Pages candidate cannot publish; production publication is disabled",
        )

    def claim_live(self) -> None:
        """Candidate pages must never claim live status."""
        raise ContractError(
            "DEPLOYMENT_FORBIDDEN",
            "Candidate pages cannot claim live; publication is disabled",
        )


def assemble_pages_candidate(
    target_dir: str | Path,
    *,
    files: dict[str, bytes | str] | None = None,
    exact_inventory: dict[str, str] | None = None,
    signed_store: SignedStore | None = None,
    generation: str | None = None,
    cname: str | None = None,
    signing_fixture: Any = None,
    apt_repo: Any = None,
    require_exact_inventory: bool = True,
) -> PagesCandidate:
    """Construct and validate candidate Pages tree in empty scratch.

    Binds exact inventories, executes strict privacy/credential scan,
    and returns a candidate handle that forbids deployment.
    """
    target = physical_directory(target_dir)
    _check_no_symlinks(target)

    # Scratch directory must be empty
    existing = list(target.iterdir())
    if existing:
        raise ContractError(
            "SCRATCH_NOT_EMPTY",
            "Pages candidate target scratch directory must be completely empty",
        )

    to_write: dict[str, bytes] = {}

    def add(path: str, content: bytes) -> None:
        validate_safe_relative_posix_path(path)
        if path in to_write:
            raise ContractError("CANDIDATE_COLLISION", "Multiple sources supply the same Pages path")
        to_write[path] = content

    if cname is not None:
        if cname != PAGES_HOST:
            raise ContractError("CANDIDATE_CNAME", "Pages origin differs from reviewed RS9 authority")
        add("CNAME", (cname + "\n").encode("utf-8"))

    if signing_fixture is not None:
        add("keys/rs9.asc", signing_fixture.public_key_bytes)
        add("keys/rs9-archive-keyring.gpg", signing_fixture.public_key_binary)

    if apt_repo is not None:
        repo_root = physical_directory(apt_repo.root)
        _check_no_symlinks(repo_root)
        for cur, _, fnames in os.walk(str(repo_root)):
            cur_p = Path(cur)
            _check_no_symlinks(cur_p)
            for f in fnames:
                fp = cur_p / f
                _check_no_symlinks(fp)
                rel_p = fp.relative_to(repo_root).as_posix()
                add(f"apt/{rel_p}", _safe_read_file(fp))

    if signed_store is not None:
        for rel_path in signed_store.list_records(generation=generation):
            path_str = rel_path["rel_path"]
            _, content = signed_store.get(path_str, generation=generation)
            add(path_str, content)

    if files is not None:
        for path_str, content in files.items():
            if isinstance(content, str):
                add(path_str, content.encode("utf-8"))
            elif isinstance(content, bytes):
                add(path_str, content)
            else:
                raise ContractError("INVALID_TYPE", "File content must be bytes or str")

    if not to_write:
        raise ContractError("EMPTY_CANDIDATE", "Cannot assemble empty candidate tree")

    if "CNAME" in to_write and to_write["CNAME"] != (PAGES_HOST + "\n").encode():
        raise ContractError("CANDIDATE_CNAME", "Pages CNAME differs from reviewed RS9 authority")
    if require_exact_inventory and exact_inventory is None:
        raise ContractError("MANIFEST_REQUIRED", "An independently supplied exact inventory is required")
    if exact_inventory is not None:
        for path, expected in exact_inventory.items():
            validate_safe_relative_posix_path(path)
            validate_sha256(expected)
        if set(exact_inventory) - set(to_write):
            raise ContractError("MISSING_MANIFESTED_FILE", "Declared Pages files are missing")
        if set(to_write) - set(exact_inventory):
            raise ContractError("UNMANIFESTED_FILE", "Pages inputs include undeclared files")
        if any(_digest(to_write[path]) != expected for path, expected in exact_inventory.items()):
            raise ContractError("TAMPER_DETECTED", "Pages input differs from supplied inventory")

    # Confined atomic write
    with ConfinedWriter(target) as writer:
        for rel_path in sorted(to_write):
            validate_safe_relative_posix_path(rel_path)
            writer.write(rel_path, to_write[rel_path])

    # Compute inventory and verify against exact inventory
    computed_inventory: dict[str, str] = {}
    for cur, _, fnames in os.walk(str(target)):
        cur_p = Path(cur)
        _check_no_symlinks(cur_p)
        for f in fnames:
            fp = cur_p / f
            _check_no_symlinks(fp)
            rel_p = fp.relative_to(target).as_posix()
            data = _safe_read_file(fp)
            computed_inventory[rel_p] = _digest(data)

    if exact_inventory is not None:
        for p, expected_sha in exact_inventory.items():
            validate_safe_relative_posix_path(p)
            validate_sha256(expected_sha)

        missing = set(exact_inventory.keys()) - set(computed_inventory.keys())
        if missing:
            raise ContractError(
                "MISSING_MANIFESTED_FILE",
                f"Missing declared inventory files: {sorted(missing)}",
            )

        unmanifested = set(computed_inventory.keys()) - set(exact_inventory.keys())
        if unmanifested:
            raise ContractError(
                "UNMANIFESTED_FILE",
                f"Unmanifested files in candidate tree: {sorted(unmanifested)}",
            )

        for p, expected_sha in exact_inventory.items():
            if computed_inventory[p] != expected_sha:
                raise ContractError(
                    "TAMPER_DETECTED",
                    f"Hash mismatch for manifested file {p}",
                )
        bound_inventory = exact_inventory
    else:
        bound_inventory = computed_inventory

    # Strict privacy scan and pages tree validation
    manifest_record = (validate_pages_tree(target, manifest=bound_inventory) if exact_inventory is not None
                       else scan_pages_tree(target))

    return PagesCandidate(
        root=target,
        manifest=manifest_record,
        exact_inventory=bound_inventory,
    )
