"""Synthetic repository objects for privacy/fixture-trust tests only."""
from pathlib import Path
import hashlib
from typing import Any
from rs9.pages_candidate import PagesCandidate, assemble_pages_candidate


def construct_candidate_signed_tree(
    scratch_dir: str | Path,
    *,
    signing_fixture: Any,
    cname: str = "rs9.knowledge-forge.ai",
    custom_files: dict[str, bytes | str] | None = None,
) -> PagesCandidate:
    """Construct a complete standard fixture-signed candidate tree."""
    repomd_xml = b'<?xml version="1.0" encoding="UTF-8"?>\n<repomd xmlns="http://linux.duke.edu/metadata/repo">\n</repomd>\n'
    repomd_asc = signing_fixture.detach_sign(repomd_xml, armor=True)

    pacman_db = b"FAKE-PACMAN-DB-CONTENT"
    pacman_db_sig = signing_fixture.detach_sign(pacman_db, armor=False)

    sample_repo_config = (
        "[rs9-fedora]\n"
        "name=RS9 Fedora 43 Repository\n"
        "baseurl=https://rs9.knowledge-forge.ai/rpm/fedora/43/$basearch\n"
        "enabled=1\n"
        "gpgcheck=1\n"
        "gpgkey=https://rs9.knowledge-forge.ai/keys/rs9.asc\n"
    )

    base_files: dict[str, bytes | str] = {
        "index.html": "<!DOCTYPE html><html><body>RS9 Candidate Repository</body></html>\n",
        "README.md": "# RS9 Candidate Mirror\nCandidate repository mirror only.\n",
        "docs/install/index.html": "<!DOCTYPE html><html><body>Install Instructions</body></html>\n",
        "docs/install/README.md": "# Installation Guide\nChannel installation instructions.\n",
        "rpm/rs9.repo": sample_repo_config,
        "rpm/fedora/43/x86_64/repodata/repomd.xml": repomd_xml,
        "rpm/fedora/43/x86_64/repodata/repomd.xml.asc": repomd_asc,
        "rpm/fedora/43/aarch64/repodata/repomd.xml": repomd_xml,
        "rpm/fedora/43/aarch64/repodata/repomd.xml.asc": repomd_asc,
        "pacman/x86_64/rs9.db": pacman_db,
        "pacman/x86_64/rs9.db.sig": pacman_db_sig,
        "pacman/x86_64/rs9.files": pacman_db,
        "pacman/x86_64/rs9.files.sig": pacman_db_sig,
    }

    if custom_files:
        base_files.update(custom_files)

    bound_files = {**base_files, "CNAME": (cname + "\n").encode(),
                   "keys/rs9.asc": signing_fixture.public_key_bytes,
                   "keys/rs9-archive-keyring.gpg": signing_fixture.public_key_binary}
    exact_inventory = {p: hashlib.sha256(v.encode() if isinstance(v, str) else v).hexdigest()
                       for p, v in bound_files.items()}

    return assemble_pages_candidate(
        scratch_dir,
        files=base_files,
        cname=cname,
        signing_fixture=signing_fixture,
        exact_inventory=exact_inventory,
    )
