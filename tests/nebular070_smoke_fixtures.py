"""Hermetic, non-admitting smoke-support fixtures for the DRIVER6 tests.

The production closure is pinned to a public release archive.  Unit tests use
the same 27-member shape, but generate every byte locally so test collection
never reads an operator checkout, scratch run, or downloaded release asset.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import tarfile
from contextlib import ExitStack, contextmanager
from functools import lru_cache
from pathlib import Path
from types import ModuleType
from unittest.mock import patch


TOOL_ROOT = "tools"
FIXTURE_ROOT = "docs/examples/v0.4/brand-system/core-minimal"
TOOL_NAMES = (
    "native-rc-smoke.mjs", "sidecar-common.mjs", "sidecar-verify.mjs",
    "native-rc-package.mjs", "native-runtime.mjs", "native-launcher.mjs",
    "fs-snapshot.mjs", "platform-targets.mjs", "build-inputs.mjs",
    "build-settings.mjs", "candidate-provenance.mjs",
    "darwin-linkage-validator.mjs", "node-runtime-authority.mjs",
)
FIXTURE_PATHS = (
    "docs/examples/v0.4/brand-system/core-minimal/.tfsb/assets/fixture-mark-on-dark.toml",
    "docs/examples/v0.4/brand-system/core-minimal/.tfsb/assets/fixture-mark-on-light.toml",
    "docs/examples/v0.4/brand-system/core-minimal/.tfsb/brand-package.toml",
    "docs/examples/v0.4/brand-system/core-minimal/.tfsb/brand.toml",
    "docs/examples/v0.4/brand-system/core-minimal/.tfsb/companions/GUIDANCE.md",
    "docs/examples/v0.4/brand-system/core-minimal/.tfsb/project.toml",
    "docs/examples/v0.4/brand-system/core-minimal/GUIDANCE.md",
    "docs/examples/v0.4/brand-system/core-minimal/bundle/assets/fixture-mark-on-dark.svg",
    "docs/examples/v0.4/brand-system/core-minimal/bundle/assets/fixture-mark-on-light.svg",
    "docs/examples/v0.4/brand-system/core-minimal/bundle/brand/brand-package.toml",
    "docs/examples/v0.4/brand-system/core-minimal/bundle/brand/brand.toml",
    "docs/examples/v0.4/brand-system/core-minimal/bundle/companions/GUIDANCE.md",
    "docs/examples/v0.4/brand-system/core-minimal/bundle/tfsb-brand-manifest.json",
    "docs/examples/v0.4/brand-system/core-minimal/bundle/tfsb-manifest.json",
)
ARCHIVE_NAME = "theme-forge-nebular-fusion-v0.7.0-source.tar.gz"
AUTHORITY_NAME = "nebular-compiled-public-build-source-authority-v0.7.0.json"
_PATCHED_NAMES = (
    "SOURCE_ARCHIVE_SIZE", "SOURCE_ARCHIVE_SHA256", "SOURCE_AUTHORITY_SIZE",
    "SOURCE_AUTHORITY_SHA256", "SOURCE_AUTHORITY_IDENTITY",
)


def _member_bytes(path: str) -> bytes:
    return ("driver6 synthetic source member: " + path + "\n").encode("utf-8")


def _archive_bytes(members: dict[str, bytes]) -> bytes:
    output = io.BytesIO()
    with gzip.GzipFile(fileobj=output, mode="wb", filename="", mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for path in sorted(members):
                info = tarfile.TarInfo(path)
                info.size = len(members[path])
                info.mode = 0o644
                info.uid = info.gid = 0
                info.mtime = 0
                info.uname = info.gname = ""
                archive.addfile(info, io.BytesIO(members[path]))
    return output.getvalue()


@lru_cache(maxsize=1)
def fixture_contract() -> dict[str, object]:
    selected = {
        **{f"{TOOL_ROOT}/{name}": _member_bytes(f"{TOOL_ROOT}/{name}") for name in TOOL_NAMES},
        **{path: _member_bytes(path) for path in FIXTURE_PATHS},
    }
    archive = _archive_bytes(selected)
    identity = hashlib.sha256(b"driver6 synthetic authority identity\n").hexdigest()
    authority = json.dumps(
        {
            "schema": "nebular-public-build-source-v1",
            "version": "0.7.0",
            "identity": identity,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return {
        "archive_name": ARCHIVE_NAME,
        "archive_bytes": archive,
        "archive_size": len(archive),
        "archive_sha256": hashlib.sha256(archive).hexdigest(),
        "authority_name": AUTHORITY_NAME,
        "authority_bytes": authority,
        "authority_size": len(authority),
        "authority_sha256": hashlib.sha256(authority).hexdigest(),
        "authority_identity": identity,
        "members": selected,
    }


def source_members() -> dict[str, bytes]:
    """Return a fresh mapping of all 27 locally generated source members."""
    contract = fixture_contract()
    return {
        **dict(contract["members"]),
        contract["archive_name"]: contract["archive_bytes"],
        contract["authority_name"]: contract["authority_bytes"],
    }


def _fixture_archive_members(data: bytes) -> dict[str, tuple[int, str, str]]:
    """Adapt the production member-index seam to the tiny test archive."""
    contract = fixture_contract()
    if data != contract["archive_bytes"]:
        raise AssertionError("fixture archive bytes were changed")
    return {
        path: (
            len(content),
            hashlib.sha256(content).hexdigest(),
            hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest(),
        )
        for path, content in contract["members"].items()
    }


@contextmanager
def patched_source_contract(*caller_modules: ModuleType):
    """Patch only fixed production expectations for a hermetic unit fixture.

    The member-index adapter is the test-only dynamic seam that permits the
    27-member fixture; production still validates the real 1,559-member
    archive outside this context.
    """
    import rs9.nebular070_smoke_support as production

    contract = fixture_contract()
    values = {
        "SOURCE_ARCHIVE_SIZE": contract["archive_size"],
        "SOURCE_ARCHIVE_SHA256": contract["archive_sha256"],
        "SOURCE_AUTHORITY_SIZE": contract["authority_size"],
        "SOURCE_AUTHORITY_SHA256": contract["authority_sha256"],
        "SOURCE_AUTHORITY_IDENTITY": contract["authority_identity"],
    }
    with ExitStack() as stack:
        for module in (production, *caller_modules):
            for name in _PATCHED_NAMES:
                if hasattr(module, name):
                    stack.enter_context(patch.object(module, name, values[name]))
        stack.enter_context(patch.object(production, "_source_archive_members", _fixture_archive_members))
        yield contract


def stage_support(root: str | Path, support: dict[str, object]) -> None:
    """Stage generated support bytes under the descriptor's fresh root."""
    source_data = source_members()
    support_root = Path(root) / support["root"]
    for item in support["files"]:
        destination = support_root / item["path"]
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(source_data[item["path"]])
    for ref in support["source_binding"].values():
        destination = support_root / ref["path"]
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(source_data[Path(ref["path"]).name])
