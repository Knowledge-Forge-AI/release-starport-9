"""Synthetic repository objects for privacy/fixture-trust tests only."""
from pathlib import Path
import hashlib
from typing import Any
from rs9.pages_candidate import PagesCandidate, assemble_pages_candidate
from rs9.scratch import canonical


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
        "[rs9-fedora-nonproduction]\n"
        "name=RS9 Fedora 43 NONPRODUCTION candidate\n"
        f"baseurl=https://{cname}/rpm/fedora/43/$basearch\n"
        "enabled=1\n"
        "gpgcheck=1\n"
        "repo_gpgcheck=1\n"
        f"gpgkey=https://{cname}/keys/rs9-candidate-fixture-NONPRODUCTION.asc\n"
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

    key_metadata = canonical({
        "production": False,
        "fixture": True,
        "fingerprint": signing_fixture.primary_fingerprint,
        "purpose": "NON-PRODUCTION CANDIDATE TEST ONLY",
    })

    # Bind fixture-owned bytes independently of the assembler's armor helper.
    public_armor = getattr(signing_fixture, "public_key_bytes", None)
    if public_armor is None:
        public_armor = signing_fixture.public_key_armor.encode("utf-8")
    bound_files = {
        **base_files,
        "CNAME": (cname + "\n").encode(),
        "keys/rs9-candidate-fixture-NONPRODUCTION.asc": public_armor,
        "keys/rs9-candidate-fixture-NONPRODUCTION.gpg": signing_fixture.public_key_binary,
        "keys/KEY-METADATA.json": key_metadata,
    }
    exact_inventory = {
        p: hashlib.sha256(v.encode() if isinstance(v, str) else v).hexdigest()
        for p, v in bound_files.items()
    }

    return assemble_pages_candidate(
        scratch_dir,
        files=base_files,
        cname=cname,
        signing_fixture=signing_fixture,
        exact_inventory=exact_inventory,
    )
