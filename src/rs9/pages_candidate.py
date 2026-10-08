"""Pages candidate tree assembler and privacy verification for RS9.

Constructs candidate-only fixture signed trees in empty scratch directories
from exact inventories, strictly scanning for privacy/credentials and bounded hashes.
Enforces exact inventory bindings and strictly prohibits any live deployment or publication.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Any

from rs9.errors import ContractError
from rs9.pages import (
    merkle_inventory,
    scan_pages_tree,
    validate_pages_tree,
    verify_merkle_inventory,
)
from rs9.records import Record, snapshot, validate_sha256
from rs9.scratch import ConfinedWriter, canonical, physical_directory, verify_public_tree_modes
from rs9.security import scan_for_credentials, validate_safe_basename, validate_safe_relative_posix_path
from rs9.signed_store import SignedStore, _check_no_symlinks, _safe_read_file

PAGES_HOST = "rs9.knowledge-forge.ai"

CUSTODY_SCHEMA = "rs9.hosted-custody.v1alpha1"
CUSTODY_MANIFEST = "custody-manifest.json"
CUSTODY_FAMILY_SUFFIXES = {"deb": (".deb",), "rpm": (".rpm",), "pacman": (".pkg.tar.zst",)}
CUSTODY_KEYS = {
    "schema", "family", "system", "nonproduction", "production_enabled", "source_commit",
    "authentication_sha256", "files", "merkle",
}


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
            "merkle_root": self.merkle["root"],
        }

    @property
    def merkle(self) -> dict[str, Any]:
        """Exact Merkle commitment over the bound inventory (path -> content sha256)."""
        return merkle_inventory(self.exact_inventory)

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


def _fixture_public_armor(signing_fixture: Any) -> bytes:
    armor = getattr(signing_fixture, "public_key_bytes", None)
    if armor is None:
        armor = signing_fixture.public_key_armor.encode("utf-8")
    return armor


def collect_candidate_sources(
    *,
    files: dict[str, bytes | str] | None = None,
    signed_store: SignedStore | None = None,
    generation: str | None = None,
    cname: str | None = None,
    signing_fixture: Any = None,
    apt_repo: Any = None,
) -> dict[str, bytes]:
    """Gather every Pages path -> bytes from the reviewed sources; collisions fail closed."""
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
        add("keys/rs9-candidate-fixture-NONPRODUCTION.asc", _fixture_public_armor(signing_fixture))
        add("keys/rs9-candidate-fixture-NONPRODUCTION.gpg", signing_fixture.public_key_binary)
        add("keys/KEY-METADATA.json", canonical({"production":False,"fixture":True,
            "fingerprint":signing_fixture.primary_fingerprint,"purpose":"NON-PRODUCTION CANDIDATE TEST ONLY"}))

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

    if signing_fixture is not None and any(p in to_write for p in ("keys/rs9.asc","keys/rs9-archive-keyring.gpg")):
        raise ContractError("FIXTURE_KEY_PATH", "Candidate fixture must use nonproduction key paths")
    if "CNAME" in to_write and to_write["CNAME"] != (PAGES_HOST + "\n").encode():
        raise ContractError("CANDIDATE_CNAME", "Pages CNAME differs from reviewed RS9 authority")
    return to_write


def exact_inventory_for(sources: dict[str, bytes]) -> dict[str, str]:
    """Content digests of gathered sources, for binding before anything is written."""
    return {path: _digest(content) for path, content in sources.items()}


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

    # Public 0644/0755: explicitly set root mode to 0o755 with readback verification; outside ancestors untouched
    target_fd = os.open(str(target), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fchmod(target_fd, 0o755)
        st = os.fstat(target_fd)
        if stat.S_IMODE(st.st_mode) != 0o755:
            raise ContractError("PERMISSION_ERROR", "Failed to set Pages candidate root permissions")
    finally:
        os.close(target_fd)

    to_write = collect_candidate_sources(
        files=files, signed_store=signed_store, generation=generation, cname=cname,
        signing_fixture=signing_fixture, apt_repo=apt_repo,
    )

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
    with ConfinedWriter(target, file_mode=0o644, dir_mode=0o755) as writer:
        for rel_path in sorted(to_write):
            validate_safe_relative_posix_path(rel_path)
            writer.write(rel_path, to_write[rel_path])

    verify_public_tree_modes(target, raise_on_error=True)

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


NONPRODUCTION_BANNER = "NONPRODUCTION CANDIDATE: signed with an ephemeral fixture key; not for installation."
CLIENT_KEYRING_PATH = "/etc/apt/keyrings/rs9-nonproduction.gpg"


def render_install_docs() -> dict[str, str]:
    """Static candidate docs; every page states the NONPRODUCTION fixture trust boundary."""
    steps = (
        f"{NONPRODUCTION_BANNER}\n\n"
        "APT (Ubuntu 26.04 resolute, amd64 or arm64):\n"
        f"  curl -fsSL https://{PAGES_HOST}/keys/rs9-candidate-fixture-NONPRODUCTION.gpg -o {CLIENT_KEYRING_PATH}\n"
        f"  deb [signed-by={CLIENT_KEYRING_PATH}] https://{PAGES_HOST}/apt resolute main\n\n"
        "DNF (Fedora 43, x86_64 or aarch64): use rpm/rs9.repo with gpgcheck=1 and repo_gpgcheck=1.\n"
        "Pacman (Arch Linux x86_64): add keys/rs9-candidate-fixture-NONPRODUCTION.asc to the pacman keyring, then use SigLevel = Required.\n"
    )
    return {
        "docs/install/README.md": "# RS9 candidate install notes\n\n" + steps,
        "docs/install/index.html": (
            "<!DOCTYPE html><html><body><h1>RS9 candidate install notes</h1><pre>"
            + steps.replace("&", "&amp;").replace("<", "&lt;")
            + "</pre></body></html>\n"
        ),
        "docs/index.html": f"<!DOCTYPE html><html><body><p>{NONPRODUCTION_BANNER}</p></body></html>\n",
        "docs/README.md": f"# RS9 candidate mirror\n\n{NONPRODUCTION_BANNER}\n",
        "rpm/rs9.repo": (
            "[rs9-fedora-nonproduction]\n"
            "name=RS9 Fedora 43 NONPRODUCTION candidate\n"
            f"baseurl=https://{PAGES_HOST}/rpm/fedora/43/$basearch\n"
            "enabled=1\n"
            "gpgcheck=1\n"
            "repo_gpgcheck=1\n"
            f"gpgkey=https://{PAGES_HOST}/keys/rs9-candidate-fixture-NONPRODUCTION.asc\n"
        ),
    }


REQUIRED_PAGES_FILES = frozenset({
    "CNAME", "docs/index.html", "docs/README.md", "keys/KEY-METADATA.json", "keys/rs9-candidate-fixture-NONPRODUCTION.asc", "keys/rs9-candidate-fixture-NONPRODUCTION.gpg",
    "docs/install/index.html", "docs/install/README.md", "rpm/rs9.repo",
})


def verify_pages_completeness(inventory: dict[str, str], families: tuple[str, ...] = ("apt", "rpm", "pacman")) -> None:
    """Strict tree shape: documents, keys, CNAME and each requested family's signed metadata."""
    missing = sorted(REQUIRED_PAGES_FILES - set(inventory))
    required_by_family = {
        "apt": ("apt/dists/resolute/Release", "apt/dists/resolute/InRelease", "apt/dists/resolute/Release.gpg"),
        "rpm": tuple(f"rpm/fedora/43/{a}/repodata/{n}" for a in ("x86_64", "aarch64") for n in ("repomd.xml", "repomd.xml.asc")),
        "pacman": ("pacman/x86_64/rs9.db.tar.gz", "pacman/x86_64/rs9.db.tar.gz.sig"),
    }
    for family in families:
        if family not in required_by_family:
            raise ContractError("INVALID_ARGUMENT", "Unsupported Pages family")
        missing += [path for path in required_by_family[family] if path not in inventory]
    if missing:
        raise ContractError("MISSING_MANIFESTED_FILE", f"Pages tree incomplete: {sorted(missing)}")
    allowed_roots = {"apt", "rpm", "pacman", "keys", "docs"}
    for path in inventory:
        head = path.split("/", 1)[0]
        if "/" in path and head not in allowed_roots:
            raise ContractError("DISALLOWED_FILE", "Pages tree contains an unreviewed top-level directory")


def write_custody_bundle(
    target_dir: str | Path,
    *,
    family: str,
    system: str,
    packages: dict[str, bytes],
    authentication_sha256: str | None,
    source_commit: str | None,
) -> dict[str, Any]:
    """Retain exact UNSIGNED candidate package bytes with a per-file and Merkle manifest."""
    if family not in CUSTODY_FAMILY_SUFFIXES:
        raise ContractError("INVALID_ARGUMENT", "Unsupported custody family")
    if not packages:
        raise ContractError("EMPTY_CANDIDATE", "Custody bundle needs at least one package")
    if authentication_sha256 is not None:
        validate_sha256(authentication_sha256)
    rows: dict[str, dict[str, Any]] = {}
    for name, data in packages.items():
        validate_safe_basename(name, "package name")
        if not name.endswith(CUSTODY_FAMILY_SUFFIXES[family]) or not isinstance(data, bytes) or not data:
            raise ContractError("CUSTODY_FILE", "Custody accepts only unsigned package bytes for its family")
        rows[name] = {"sha256": _digest(data), "size": len(data)}
    manifest = {
        "schema": CUSTODY_SCHEMA,
        "family": family,
        "system": system,
        "nonproduction": True,
        "production_enabled": False,
        "source_commit": source_commit,
        "authentication_sha256": authentication_sha256,
        "files": rows,
        "merkle": merkle_inventory({name: row["sha256"] for name, row in rows.items()}),
    }
    with ConfinedWriter(physical_directory(target_dir)) as writer:
        for name in sorted(packages):
            writer.write(f"files/{name}", packages[name])
        writer.write(CUSTODY_MANIFEST, canonical(manifest))
    return manifest


def load_custody_bundle(
    path: str | Path,
    *,
    expected_family: str | None = None,
    expected_authentication_sha256: str | None = None,
) -> dict[str, Any]:
    """Verify a downloaded custody tree exactly: file set, digests, Merkle root, provenance."""
    root = physical_directory(path)
    _check_no_symlinks(root)
    manifest_file = root / CUSTODY_MANIFEST
    if not manifest_file.is_file():
        raise ContractError("CUSTODY_MISSING", "Custody manifest missing")
    raw = _safe_read_file(manifest_file, max_bytes=8 * 1024 * 1024)
    scan_for_credentials(raw.decode("utf-8", errors="replace"))
    try:
        doc = json.loads(raw)
    except ValueError:
        raise ContractError("CUSTODY_SCHEMA", "Malformed custody manifest") from None
    if not isinstance(doc, dict) or set(doc) != CUSTODY_KEYS or doc["schema"] != CUSTODY_SCHEMA:
        raise ContractError("CUSTODY_SCHEMA", "Custody manifest schema mismatch")
    if doc["nonproduction"] is not True or doc["production_enabled"] is not False:
        raise ContractError("CUSTODY_POLICY", "Custody must be explicitly NONPRODUCTION")
    family = doc["family"]
    if family not in CUSTODY_FAMILY_SUFFIXES or (expected_family is not None and family != expected_family):
        raise ContractError("CUSTODY_SCHEMA", "Custody family mismatch")
    bound = doc["authentication_sha256"]
    if expected_authentication_sha256 is not None and bound != expected_authentication_sha256:
        raise ContractError("HOSTED_PROVENANCE", "Custody authentication provenance differs from this run")
    rows = doc["files"]
    if not isinstance(rows, dict) or not rows:
        raise ContractError("CUSTODY_SCHEMA", "Custody file inventory required")

    actual: dict[str, Path] = {}
    for cur, dirs, fnames in os.walk(str(root)):
        cur_p = Path(cur)
        _check_no_symlinks(cur_p)
        for name in fnames:
            actual[(cur_p / name).relative_to(root).as_posix()] = cur_p / name
    expected_paths = {f"files/{name}" for name in rows} | {CUSTODY_MANIFEST}
    if set(actual) != expected_paths:
        raise ContractError("CUSTODY_INVENTORY", "Custody tree differs from its exact file inventory")
    packages: dict[str, Path] = {}
    for name, row in rows.items():
        validate_safe_basename(name, "package name")
        if not name.endswith(CUSTODY_FAMILY_SUFFIXES[family]):
            raise ContractError("CUSTODY_FILE", "Custody accepts only unsigned package bytes for its family")
        data = _safe_read_file(actual[f"files/{name}"])
        if not isinstance(row, dict) or row != {"sha256": _digest(data), "size": len(data)}:
            raise ContractError("TAMPER_DETECTED", "Custody package differs from its manifest")
        packages[name] = actual[f"files/{name}"]
    verify_merkle_inventory(doc["merkle"], {name: row["sha256"] for name, row in rows.items()})
    return {"manifest": doc, "root": root, "packages": packages}
