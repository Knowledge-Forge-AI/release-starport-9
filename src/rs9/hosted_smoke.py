"""Run released Nebular verifiers against the actual installed runtime tree."""
import hashlib
import json
import os
import re
import stat
import subprocess
from pathlib import Path

from rs9.errors import ContractError, safe_details
from rs9.hosted_commands import runtime_environment
from rs9.nebular_callers import CURRENT070_COMMIT, CURRENT070_TREE, current_contract_for_capture
from rs9.current_os071 import (CURRENT071_COMMIT, CURRENT071_TREE, CURRENT071_VERIFIER_FILES,
                               CURRENT071_VERIFIER_IMPORTS)
from rs9.nebular_lineage import (
    CURRENT_COMMIT,
    CURRENT_TREE,
    HISTORICAL_COMMIT,
    HISTORICAL_TREE,
)
from rs9.release_core import (authenticated_record_hash, authenticated_tree,
                              authenticated_release_metadata, digest)
from rs9.scratch import canonical
from rs9.security import validate_safe_relative_posix_path


def tagged_files(capture, client, output, prefixes, *, paths=(), role="verifier-module"):
    """Supplement a fresh capture with bounded blobs authenticated by its Git tree."""
    authenticated_record_hash(capture)
    records, total = [], 0
    for entry in authenticated_tree(capture)["tree"]:
        name = entry["path"]
        if not (name in paths or any(name.startswith(p) for p in prefixes)):
            continue
        if entry.get("type") != "blob":
            if name in paths:
                raise ContractError("SIDECAR_HARNESS_IMPORT", "Regular authenticated support source required",
                                    details={"substage": "verifier-closure", "missing_path": name})
            continue
        validate_safe_relative_posix_path(name)
        if entry.get("mode") not in ("100644", "100755") or entry.get("size", 0) > 2 * 1024 ** 2:
            raise ContractError("SMOKE_SOURCE", "Bounded regular tagged source required")
        data = client.get("https://raw.githubusercontent.com/" + capture.record["repository"]["full_name"]
                          + "/" + capture.record["tag"]["commit"] + "/" + name,
                          request_class="github-source", limit=2 * 1024 ** 2)
        total += len(data)
        blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        if blob != entry["sha"] or total > 32 * 1024 ** 2 or len(records) >= 1000:
            raise ContractError("SMOKE_SOURCE", "Tagged source identity or bounds failed")
        target = output / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        records.append({"path": name, "blob": blob, "sha256": digest(data), "size": len(data), "role": role,
                        "tag_commit": capture.record["tag"]["commit"]})
    if set(paths) - {r["path"] for r in records}:
        raise ContractError("SIDECAR_HARNESS_IMPORT", "Authenticated support source missing",
                            details={"substage": "verifier-closure", "missing_path": sorted(set(paths) - {r["path"] for r in records})[0]})
    return records


# platform-targets.mjs reads this file at import time. Unknown tagged closures
# require a reviewed binding; never substitute an ambient checkout's metadata.
VERIFIER_SUPPORT = {
    HISTORICAL_COMMIT: ("package.json",),
    CURRENT_COMMIT: ("package.json",),
    CURRENT070_COMMIT: ("package.json",),
    CURRENT071_COMMIT: ("package.json",),
}
VERIFIER_SUPPORT_TREES = {
    HISTORICAL_COMMIT: HISTORICAL_TREE,
    CURRENT_COMMIT: CURRENT_TREE,
    CURRENT070_COMMIT: CURRENT070_TREE,
    CURRENT071_COMMIT: CURRENT071_TREE,
}


# Exact import-time closure and fixture members measured from current tagged bytes.
CURRENT070_VERIFIER_FILES = {'package.json': {'blob': '161ee788b7a8660916e2b6fbbebbac0de4a87f42',
                  'sha256': '15d3f118dfdc0014129fc37d63533a6a02cf355fdb89961a215eca77e95b7cd2',
                  'size': 1833},
 'tools/build-inputs.mjs': {'blob': 'd9e0019d04d4ca8862f789fd2a5319fd828a0855',
                            'sha256': '92cc77082ffc399a9c39ad4fce41811e9ac8aba7e2d852ac223cdf0e193381bc',
                            'size': 16400},
 'tools/build-settings.mjs': {'blob': '87b69b40534ef60f1895bdd866ce7e74fa581dae',
                              'sha256': 'f7578fccf935e14aee190a2de4378a986a182b038e41b261f3f9355e33449cd0',
                              'size': 24182},
 'tools/candidate-provenance.mjs': {'blob': '129b0da16329d07697daab619f8fdbc5690f72fa',
                                    'sha256': '20244b6765d6e7d0ee5fd86452096a4546f189103b0acb9f065c4a1479c23155',
                                    'size': 15484},
 'tools/darwin-linkage-validator.mjs': {'blob': '3ca8ede088162f10d922b9cbec1d091daa052c33',
                                        'sha256': '67073d25aa00bc6c8086e8d10a2bd7302cc46c6416894bcba553880edf83f0f9',
                                        'size': 7678},
 'tools/fs-snapshot.mjs': {'blob': '841cfecd874517d0c619cf9a3866c2697e12ecd6',
                           'sha256': '30ad6c3f0394126a7d3e5534507fe46c78c34946edd15bd5c91b36e2b36df351',
                           'size': 13794},
 'tools/native-launcher.mjs': {'blob': '9c84fff880957edcb98925bbaea941fc0f7e66fe',
                               'sha256': '3595cfaf0a2f1ac51a48862dc5f6aa842db6d3431a62159bcb93cb0abc812f2d',
                               'size': 7193},
 'tools/native-rc-package.mjs': {'blob': '570d4d2b6cee8551bb0d77417e54ee4a0d308ca8',
                                 'sha256': '0ef948c2f9f45a9343586288681ae5ed6f6527b85912a52bd8c37aa50e3682c6',
                                 'size': 33102},
 'tools/native-rc-smoke.mjs': {'blob': 'cbf6a2148c11ed1516ba5d7fc2d4dd32dee3ee9f',
                               'sha256': '874355e36496884e55a6e4dae6986ecde817d20863bb3fe26d1b1b5a1d283e69',
                               'size': 30732},
 'tools/native-runtime.mjs': {'blob': '333192471147289f232bd915c6813ae23b39f1bb',
                              'sha256': 'a9d6c8e885b9db41877c5d2d79efe48f2e47daf791e0f1ad1ca06636d37d962e',
                              'size': 118749},
 'tools/node-runtime-authority.mjs': {'blob': 'f55c2231f07d35af6593634b49d13c30d429ba1f',
                                      'sha256': '962014ba74a1b0285388b85026016d7d664adea6353ebca5c61a407a6c7ee653',
                                      'size': 37930},
 'tools/platform-targets.mjs': {'blob': 'ebe518bbf27856c496541bca46bf13066805a606',
                                'sha256': '35321c7e888038210589612873136c96bf697789f6f4e90918442faa41e13aec',
                                'size': 7292},
 'tools/sidecar-common.mjs': {'blob': 'a79812c8b47bb9a0a34c341261c49f7c1060d12e',
                              'sha256': 'e0ca4d4a4bba4abd756f1399e31a768a20873eefb6c50ac26a75adddccc1978c',
                              'size': 81902},
 'tools/sidecar-verify.mjs': {'blob': 'a456da327097d26bec9a41fdfaf288af57f38657',
                              'sha256': 'fba7f292b3c01ed062f4727e0c22912bc269b6ca76fca8328fb5329c098aac77',
                              'size': 1906}}
# Reviewed graph documentation, not a JavaScript parser or a separate authority.
# Exact member pins/readback and import preflight enforce the actual closure.
CURRENT070_VERIFIER_IMPORTS = {'tools/build-inputs.mjs': ['tools/build-settings.mjs',
                            'tools/candidate-provenance.mjs',
                            'tools/platform-targets.mjs'],
 'tools/build-settings.mjs': ['tools/candidate-provenance.mjs', 'tools/fs-snapshot.mjs'],
 'tools/candidate-provenance.mjs': ['tools/platform-targets.mjs'],
 'tools/darwin-linkage-validator.mjs': [],
 'tools/fs-snapshot.mjs': [],
 'tools/native-launcher.mjs': ['tools/platform-targets.mjs'],
 'tools/native-rc-package.mjs': ['tools/fs-snapshot.mjs',
                                 'tools/native-launcher.mjs',
                                 'tools/native-runtime.mjs',
                                 'tools/platform-targets.mjs'],
 'tools/native-rc-smoke.mjs': ['tools/fs-snapshot.mjs',
                               'tools/native-launcher.mjs',
                               'tools/native-rc-package.mjs',
                               'tools/native-runtime.mjs'],
 'tools/native-runtime.mjs': ['tools/candidate-provenance.mjs'],
 'tools/node-runtime-authority.mjs': ['tools/darwin-linkage-validator.mjs'],
 'tools/platform-targets.mjs': [],
 'tools/sidecar-common.mjs': ['tools/build-inputs.mjs',
                              'tools/candidate-provenance.mjs',
                              'tools/darwin-linkage-validator.mjs',
                              'tools/node-runtime-authority.mjs',
                              'tools/platform-targets.mjs'],
 'tools/sidecar-verify.mjs': ['tools/build-inputs.mjs',
                              'tools/platform-targets.mjs',
                              'tools/sidecar-common.mjs']}
CURRENT070_FIXTURE_COMMIT = '3edb9d2c40dd19a2b7d97d9309bc210e7fed711c'
CURRENT070_FIXTURE_TREE = '4be1551c49b15dff788d07ed1fb00ddcd8839a76'
CURRENT070_FIXTURE_FILES = {'docs/examples/v0.4/brand-system/core-minimal/.tfsb/assets/fixture-mark-on-dark.toml': {'blob': '36e238da1aec1b8a5ef4ab35569175101b202204',
                                                                                         'sha256': '6a95e550c0c3e92793a873251eed3bc888e5e4c4a3355124d5230eaebe479387',
                                                                                         'size': 371},
 'docs/examples/v0.4/brand-system/core-minimal/.tfsb/assets/fixture-mark-on-light.toml': {'blob': 'b4d6b7644c40bb94ff58ad6449537f17e1e2f2b3',
                                                                                          'sha256': '8e53627c743ba21b079b281638804f3a9214895686514dbf5fec0c279db71667',
                                                                                          'size': 375},
 'docs/examples/v0.4/brand-system/core-minimal/.tfsb/brand-package.toml': {'blob': '78a6a5b2cd6b36da681450e94bd2841a86469454',
                                                                           'sha256': 'd205c6db34f0af25d6657a8133593d1d67b50dda8e4cfc34973450dd141c7bd4',
                                                                           'size': 1194},
 'docs/examples/v0.4/brand-system/core-minimal/.tfsb/brand.toml': {'blob': 'c024cf83958ff1debf9ec614cfce06ca08ec5702',
                                                                   'sha256': '1017ebaca28269b4d4397e84bf29696ddea3f615ef1a8e5a6d67606a369c8b41',
                                                                   'size': 1012},
 'docs/examples/v0.4/brand-system/core-minimal/.tfsb/companions/GUIDANCE.md': {'blob': '3166248645c5459c066cece832c9a7d0c82c10aa',
                                                                               'sha256': '10a61401be21913c99086526840a27a24991815db9d7044ac1668787e737a9d3',
                                                                               'size': 90},
 'docs/examples/v0.4/brand-system/core-minimal/.tfsb/project.toml': {'blob': '513887cacede8047e8451ef241222c1e4661a4d2',
                                                                     'sha256': '932378720ed558961f520df7c6d74da2a3b11c6a5f31263cbe565a22d5e801c3',
                                                                     'size': 69},
 'docs/examples/v0.4/brand-system/core-minimal/GUIDANCE.md': {'blob': '3166248645c5459c066cece832c9a7d0c82c10aa',
                                                              'sha256': '10a61401be21913c99086526840a27a24991815db9d7044ac1668787e737a9d3',
                                                              'size': 90},
 'docs/examples/v0.4/brand-system/core-minimal/bundle/assets/fixture-mark-on-dark.svg': {'blob': '8ec42a928976bcce8e5972c7191fe928dbb159e9',
                                                                                         'sha256': '1068a15abd03564d4a48257825914baa14ae26990aad96c0c8f46e2d5a27a15b',
                                                                                         'size': 345},
 'docs/examples/v0.4/brand-system/core-minimal/bundle/assets/fixture-mark-on-light.svg': {'blob': 'e1f2c48c977fcca5f220af6b8760b008195a4f87',
                                                                                          'sha256': 'a1bf2b63584d6c5e7832d2e7c29f9137f6f15c4a0d004b9e71c1ee599d75d75f',
                                                                                          'size': 348},
 'docs/examples/v0.4/brand-system/core-minimal/bundle/brand/brand-package.toml': {'blob': '78a6a5b2cd6b36da681450e94bd2841a86469454',
                                                                                  'sha256': 'd205c6db34f0af25d6657a8133593d1d67b50dda8e4cfc34973450dd141c7bd4',
                                                                                  'size': 1194},
 'docs/examples/v0.4/brand-system/core-minimal/bundle/brand/brand.toml': {'blob': 'c024cf83958ff1debf9ec614cfce06ca08ec5702',
                                                                          'sha256': '1017ebaca28269b4d4397e84bf29696ddea3f615ef1a8e5a6d67606a369c8b41',
                                                                          'size': 1012},
 'docs/examples/v0.4/brand-system/core-minimal/bundle/companions/GUIDANCE.md': {'blob': '3166248645c5459c066cece832c9a7d0c82c10aa',
                                                                                'sha256': '10a61401be21913c99086526840a27a24991815db9d7044ac1668787e737a9d3',
                                                                                'size': 90},
 'docs/examples/v0.4/brand-system/core-minimal/bundle/tfsb-brand-manifest.json': {'blob': '38feefb3c5f7575af7bcd3dcb0a818e83a27732c',
                                                                                  'sha256': 'c9c652e36d881775d14ed467bad4a1e5494d3ef55b2aade0252f74c6299a28e4',
                                                                                  'size': 1874},
 'docs/examples/v0.4/brand-system/core-minimal/bundle/tfsb-manifest.json': {'blob': 'f867a70f3e48d29f20c958ac93dd95425cca4410',
                                                                            'sha256': '53ece77670595a24f49bbdfb0af0498e093e5a08366ecaff090814a02c9f70e8',
                                                                            'size': 1110}}


def _reviewed_verifier_support(capture):
    """Return support paths only for an exact reviewed commit/tree pair."""
    tag = capture.record.get("tag") if isinstance(capture.record, dict) else None
    if not isinstance(tag, dict):
        raise ContractError("SIDECAR_HARNESS_IMPORT", "Tagged verifier identity is missing",
                            details={"substage": "verifier-closure", "reason": "tag-identity-missing"})
    commit = tag.get("commit")
    if not isinstance(commit, str):
        raise ContractError("SIDECAR_HARNESS_IMPORT", "Tagged verifier support closure is unreviewed",
                            details={"substage": "verifier-closure", "reason": "unknown-tag-closure"})
    support = VERIFIER_SUPPORT.get(commit)
    if support is None:
        raise ContractError("SIDECAR_HARNESS_IMPORT", "Tagged verifier support closure is unreviewed",
                            details={"substage": "verifier-closure", "reason": "unknown-tag-closure"})
    if tag.get("tree") != VERIFIER_SUPPORT_TREES[commit]:
        raise ContractError("SIDECAR_HARNESS_IMPORT", "Tagged verifier tree is not the reviewed closure",
                            details={"substage": "verifier-closure", "reason": "tag-tree-mismatch"})
    if commit in (CURRENT070_COMMIT, CURRENT071_COMMIT):
        _current_smoke_capture(capture)
    elif (isinstance(capture.record.get("release"), dict)
          and capture.record["release"].get("tag") in ("v0.7.0", "v0.7.1")):
        raise ContractError("SIDECAR_HARNESS_IMPORT", "Mixed verifier generation is forbidden",
                            details={"substage": "verifier-closure", "reason": "mixed-generation"})
    return support


def _current_smoke_capture(capture):
    try:
        current_contract_for_capture(capture)
    except (ContractError, OSError, ValueError, KeyError, TypeError, AttributeError):
        raise ContractError("SIDECAR_HARNESS_IMPORT", "Exact authenticated current verifier capture required",
                            details={"substage": "verifier-closure", "reason": "current-capture-binding"}) from None


def _current_fixture_identity(capture):
    try:
        authenticated_record_hash(capture)
        authenticated_tree(capture)
        metadata = authenticated_release_metadata(capture)
        record = capture.record
        identity = (record["repository"]["full_name"], record["repository"]["id"],
                    record["release"]["id"], record["release"]["tag"],
                    record["tag"]["commit"], record["tag"]["tree"])
        if (identity != ("Knowledge-Forge-AI/theme-forge-stellar-burst", 1342490027, 424873797,
                         "v0.7.0", CURRENT070_FIXTURE_COMMIT, CURRENT070_FIXTURE_TREE)
                or metadata.get("id") != 424873797 or metadata.get("tag_name") != "v0.7.0"):
            raise ValueError("fixture identity")
    except (ContractError, KeyError, TypeError, AttributeError, ValueError):
        raise ContractError("SIDECAR_HARNESS_IMPORT", "Exact authenticated current Burst fixture required",
                            details={"substage": "verifier-closure", "reason": "current-fixture-binding"}) from None


def _verify_current_source_binding(prepared):
    """Close the current source set and both producer identities before import."""
    if prepared.get("source_generation") != "theme-forge-current-202610":
        raise ContractError("SIDECAR_HARNESS_IMPORT", "Current verifier generation marker differs")
    _current_smoke_capture(prepared.get("capture"))
    _current_fixture_identity(prepared.get("fixture_capture"))
    from rs9.smoke_source_envelope import verify_members
    verify_members(prepared["source"], prepared["tools"], prepared.get("records"))


def export_current_source_readback(prepared):
    """Parent-only export gate: plain envelope/guest dictionaries cannot pass."""
    _verify_current_source_binding(prepared)
    verify_source_readback(prepared)
    from rs9.smoke_source_envelope import _make_envelope
    return _make_envelope(prepared["records"])


def verify_execution_source_readback(prepared):
    """Guest source proof and parent authentication are distinct entry points."""
    if "_source_readback_proof" in prepared:
        from rs9.smoke_source_envelope import verify_guest_prepared
        return verify_guest_prepared(prepared)
    return verify_source_readback(prepared)


def _safe_label(value):
    if not value or not isinstance(value, str):
        return None
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", value):
        return value
    return None


def prepare_smoke(capture, captures, client, scratch, label=None):
    scratch = Path(scratch)
    scratch.mkdir(parents=True, exist_ok=True)
    source = scratch / "source"
    source.mkdir()
    support = _reviewed_verifier_support(capture)
    current = capture.record["tag"]["commit"] in (CURRENT070_COMMIT, CURRENT071_COMMIT)
    if current:
        records = tagged_files(capture, client, source, (),
                               paths=tuple(path for path in (CURRENT071_VERIFIER_FILES if capture.record["tag"]["commit"] == CURRENT071_COMMIT
                                                            else CURRENT070_VERIFIER_FILES) if path != "package.json"))
    else:
        records = tagged_files(capture, client, source, ("tools/", "apps/studio/tools/"))
    records += tagged_files(capture, client, source, (), paths=support, role="verifier-support")
    for row in records:
        if row["path"].endswith("/native-rc-smoke.mjs"):
            row["role"] = "application-smoke"
    tools = source / "tools"
    if not (tools / "native-rc-smoke.mjs").is_file():
        tools = source / "apps/studio/tools"
    if not all((tools / p).is_file() for p in ("native-rc-smoke.mjs", "sidecar-common.mjs", "sidecar-verify.mjs")):
        raise ContractError("SIDECAR_HARNESS_IMPORT", "Released application-aware harness is unavailable",
                            details={"substage": "verifier-closure"})
    fixture = next(c for c, intent, _ in captures if intent["project"]["id"] == "theme-forge-stellar-burst")
    if current:
        _current_fixture_identity(fixture)
        records += tagged_files(fixture, client, source, (), paths=tuple(CURRENT070_FIXTURE_FILES), role="fixture")
    else:
        records += tagged_files(fixture, client, source, ("docs/examples/v0.4/brand-system/core-minimal/",), role="fixture")
    if len(records) > 1000 or sum(r["size"] for r in records) > 32 * 1024 ** 2:
        raise ContractError("SMOKE_SOURCE", "Complete source closure exceeds bounds")
    if not (source / "docs/examples/v0.4/brand-system/core-minimal").is_dir():
        raise ContractError("SMOKE_FIXTURE", "Authenticated released fixture required")
    if label is None and scratch.name.startswith("smoke-"):
        label = scratch.name[len("smoke-"):]
    safe = _safe_label(label)
    result = {"source": source, "tools": tools, "records": records, "scratch": scratch, "capture": capture}
    if current:
        result["source_generation"] = "theme-forge-current-202610"
        result["fixture_capture"] = fixture
        verify_source_readback(result)
    (scratch / "source-bindings.json").write_bytes(canonical(records))
    if safe:
        result["label"] = safe
        result["family"] = safe
    return result


def _file_hash(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        hasher = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


KNOWN_FLAG_NAMES = frozenset({
    "UF_NODUMP", "UF_IMMUTABLE", "UF_APPEND", "UF_OPAQUE", "UF_HIDDEN",
    "UF_COMPRESSED", "UF_TRACKED", "UF_DATAVAULT",
    "SF_ARCHIVED", "SF_IMMUTABLE", "SF_APPEND", "SF_RESTRICTED", "SF_NOUNLINK",
})

KNOWN_XATTR_NAMES = frozenset({
    "com.apple.quarantine",
    "com.apple.FinderInfo",
    "com.apple.macl",
    "com.apple.provenance",
})


def _bound_path(path, max_len=120):
    if len(path) <= max_len:
        return path
    h = digest(path.encode("utf-8"))[:12]
    prefix_len = (max_len - 18) // 2
    suffix_len = max_len - 18 - prefix_len
    return f"{path[:prefix_len]}...[{h}]...{path[-suffix_len:]}"


def _inventory_runtime(root):
    root = Path(root)
    rows = []
    seen_flags = set()
    seen_xattrs = set()
    flags_count = 0
    xattrs_count = 0
    condition_samples = {"flags": [], "xattrs": []}
    members_map = {}
    for directory, dirs, files in os.walk(root, followlinks=False):
        for path in [Path(directory), *(Path(directory) / p for p in sorted(dirs + files))]:
            # Each physical directory is inventoried when visited, not twice.
            info = path.lstat()
            if path != Path(directory) and stat.S_ISDIR(info.st_mode):
                continue
            relative = path.relative_to(root.parent).as_posix()
            try:
                validate_safe_relative_posix_path(relative)
            except ContractError:
                relative = "unsafe-name-" + digest(relative.encode())
            kind = "file" if stat.S_ISREG(info.st_mode) else "directory" if stat.S_ISDIR(info.st_mode) else "symlink" if stat.S_ISLNK(info.st_mode) else "special"
            mode = stat.S_IMODE(info.st_mode)
            row = {"path": relative, "type": kind, "mode": mode}
            if kind == "file":
                row.update(size=info.st_size, sha256=_file_hash(path))
            elif kind == "symlink":
                row["target_sha256"] = digest(os.readlink(path).encode())
            rows.append(row)
            members_map[relative] = row

            st_flags = getattr(info, "st_flags", 0)
            if st_flags:
                flags_count += 1
                if len(condition_samples["flags"]) < 10:
                    condition_samples["flags"].append({"path": _bound_path(relative), "st_flags": st_flags})
                rem = st_flags
                for fname in sorted(KNOWN_FLAG_NAMES):
                    bit = getattr(stat, fname, 0)
                    if bit and (st_flags & bit):
                        seen_flags.add(fname)
                        rem &= ~bit
                if rem:
                    seen_flags.add("hash:" + digest(str(rem).encode("utf-8")))

            if hasattr(os, "listxattr"):
                try:
                    attrs = os.listxattr(path, follow_symlinks=False)
                    xattrs_count += len(attrs)
                    safe_names = sorted(a if a in KNOWN_XATTR_NAMES else "hash:" + digest(a.encode()) for a in attrs)
                    if attrs and len(condition_samples["xattrs"]) < 10:
                        condition_samples["xattrs"].append({"path": _bound_path(relative), "names": safe_names[:10]})
                    for attr in attrs:
                        if attr in KNOWN_XATTR_NAMES:
                            seen_xattrs.add(attr)
                        else:
                            seen_xattrs.add("hash:" + digest(attr.encode("utf-8")))
                except OSError:
                    pass
    rows.sort(key=lambda r: r["path"])
    return rows, flags_count, xattrs_count, sorted(seen_flags)[:20], sorted(seen_xattrs)[:20], members_map, condition_samples


def classify_diagnostic(identity, verifier=None, drift=None):
    """Classify diagnostic according to strict precedence rules:
    harness/import/execution -> causal drift -> manifest -> bytes -> file_mode -> dir_mode ->
    symlink -> ancestry -> flags/xattr -> non-causal drift -> verifier-rejected
    """
    # 1. harness/import/execution
    if verifier and verifier.get("status") != "pass":
        phase = verifier.get("phase")
        token = verifier.get("reason_token")
        code = verifier.get("code")
        if (phase in ("import", "execution", "unavailable", "unknown")
                or token in ("tool-timeout", "tool-unavailable")
                or code in ("ERR_MODULE_NOT_FOUND", "ENOENT", "EACCES", "ERR_UNKNOWN_FILE_EXTENSION")
                or (verifier.get("exit_code") not in (0, None) and phase != "verify")):
            return "harness/import/execution"

    counts = identity.get("mismatch_counts", {}) if identity else {}
    v_token = verifier.get("reason_token") if verifier else None
    verifier_failed = bool(verifier and verifier.get("status") != "pass")

    drift_counts = drift.get("drift_counts", {}) if drift else {}
    has_drift = bool(
        drift and (drift.get("has_drift") or any(v > 0 for v in drift_counts.values()))
    )
    drift_paths = {
        item["path"]
        for sample_list in drift.get("drift_samples", {}).values()
        for item in sample_list
        if isinstance(item, dict) and "path" in item
    } if drift else set()
    mismatch_paths = {
        item["path"]
        for k, sample_list in identity.get("mismatch_samples", {}).items()
        if k != "dir_mode"
        for item in sample_list
        if isinstance(item, dict) and "path" in item
    } if identity else set()

    mismatch_total = sum(counts.get(k, 0) for k in ("missing", "extra", "type", "bytes", "file_mode", "directory_mode", "symlink"))
    sampled_mismatch_total = sum(len(samples) for kind, samples in identity.get("mismatch_samples", {}).items()
                                if kind != "dir_mode") if identity else 0
    drift_total = sum(drift_counts.values())

    has_intersection = bool(drift_paths & mismatch_paths)
    has_unrelated_mismatch = (bool(mismatch_paths - drift_paths)
                              or mismatch_total > drift_total
                              or mismatch_total > sampled_mismatch_total
                              or any(value > 0 for value in drift.get("baseline_mismatch_counts", {}).values())) if drift else False
    manifest_tokens = {"manifest-not-canonical", "manifest-self-digest", "manifest-fixed-identity"}
    if v_token in manifest_tokens and not any("manifest" in p for p in drift_paths):
        has_unrelated_mismatch = True

    # Causal drift before manifest/bytes/modes/flags when drift explains failures/mismatches
    if has_drift and has_intersection and not has_unrelated_mismatch:
        return "post-probe-drift"

    # 2. manifest
    if (
        counts.get("missing", 0) > 0
        or counts.get("extra", 0) > 0
        or counts.get("type", 0) > 0
        or (identity.get("expected_member_count") is not None
            and identity.get("actual_member_count") != identity.get("expected_member_count"))
        or v_token in ("manifest-not-canonical", "manifest-self-digest", "manifest-fixed-identity",
                       "payload-inventory", "payload-totals", "actual-input-identity")
    ):
        return "manifest"

    # 3. bytes
    if counts.get("bytes", 0) > 0:
        return "bytes"

    # 4. file_mode
    if counts.get("file_mode", 0) > 0:
        return "file_mode"

    # 5. dir_mode
    if counts.get("directory_mode", 0) > 0 or counts.get("dir_mode", 0) > 0:
        return "dir_mode"

    # 6. symlink
    if counts.get("symlink", 0) > 0:
        return "symlink"

    # 7. ancestry
    ancestors = identity.get("ancestor_modes", []) if identity else []
    if v_token == "symlink-ancestor" or any(a.get("symlink") or a.get("ancestry_unsafe") for a in ancestors):
        return "ancestry"

    has_flags = bool(
        identity.get("nonzero_file_flags_count", 0) > 0
        or identity.get("extended_attribute_count", 0) > 0
        or identity.get("file_flags")
        or identity.get("extended_attributes")
    )

    # 8. flags/xattr
    if has_flags:
        return "flags/xattr"

    # 9. post-probe-drift
    if has_drift and not verifier_failed:
        return "post-probe-drift"

    # 10. dedicated verifier-rejected when verify failed no specific cause
    if verifier_failed:
        return "verifier-rejected"

    if verifier is None and any(counts.get(k, 0) > 0 for k in counts):
        return "unclassified"

    return None


def runtime_evidence(root, sidecar, manifest, expected_members=None, return_members=False):
    """Bounded identities and mismatch samples, without retaining runtime paths."""
    root = Path(root)
    rows, flags, xattrs, file_flags, ext_attrs, members_map, conditions = _inventory_runtime(root)
    expected, metadata = expected_members or [], {}
    entry = root.parent.parent
    if not expected and (entry / "manifest.json").is_file() and not (entry / "manifest.json").is_symlink():
        expected = json.loads((entry / "manifest.json").read_bytes())
    if (entry / "meta.json").is_file() and not (entry / "meta.json").is_symlink():
        metadata = json.loads((entry / "meta.json").read_bytes())
    actual = {r["path"]: r for r in rows}
    samples = {k: [] for k in ("missing", "extra", "bytes", "file_mode", "directory_mode", "dir_mode", "symlink", "type")}
    counts = {k: 0 for k in samples}
    def mismatch(kind, path, **extra):
        counts[kind] += 1
        if len(samples[kind]) < 10:
            item = {"path": _bound_path(path)}
            item.update(extra)
            samples[kind].append(item)
    expected_by_path = {r["path"]: r for r in expected}
    for name, row in expected_by_path.items():
        observed = actual.get(name)
        if observed is None:
            mismatch("missing", name)
        elif observed["type"] != row["type"]:
            mismatch("type", name)
        elif row["type"] == "file":
            if (observed["size"], observed["sha256"]) != (row["size"], row["sha256"]):
                mismatch("bytes", name, expected_size=row["size"], actual_size=observed["size"],
                         expected_sha256=row["sha256"], actual_sha256=observed["sha256"])
            if observed["mode"] != row["mode"]:
                mismatch("file_mode", name, expected_mode=row["mode"], actual_mode=observed["mode"],
                         expected=row["mode"], observed=observed["mode"])
        elif row["type"] == "directory" and observed["mode"] != row["mode"]:
            mismatch("directory_mode", name, expected_mode=row["mode"], actual_mode=observed["mode"],
                     expected=row["mode"], observed=observed["mode"])
        elif row["type"] == "symlink" and observed["target_sha256"] != digest(row["target"].encode()):
            mismatch("symlink", name)
    if expected:
        for name in sorted(actual.keys() - expected_by_path.keys()):
            mismatch("extra", name)
    counts["dir_mode"] = counts["directory_mode"]
    samples["dir_mode"] = samples["directory_mode"]

    ancestors = []
    my_uid = os.getuid() if hasattr(os, "getuid") else None
    for path in (root, *root.parents)[:32]:
        info = path.lstat()
        mode = stat.S_IMODE(info.st_mode)
        raw_mode = info.st_mode
        is_symlink = stat.S_ISLNK(raw_mode)
        is_sticky = bool(raw_mode & stat.S_ISVTX)
        uid = info.st_uid
        uid_is_self = (uid == my_uid) if my_uid is not None else True
        is_root_uid = (uid == 0)
        group_writable = bool(mode & 0o020)
        other_writable = bool(mode & 0o002)
        ancestry_unsafe = is_symlink or (other_writable and not is_sticky) or (not uid_is_self and not is_root_uid)
        ancestors.append({
            "symlink": is_symlink,
            "mode": mode,
            "uid_is_self": uid_is_self,
            "group_writable": group_writable,
            "other_writable": other_writable,
            "group_or_other_writable": group_writable or other_writable,
            "writable_by_group_or_other": group_writable or other_writable,
            "is_sticky": is_sticky,
            "is_root": is_root_uid,
            "ancestry_unsafe": ancestry_unsafe,
        })
    evidence = {"runtime_root_sha256": digest(canonical(rows)), "actual_member_count": len(rows),
                "expected_member_count": len(expected) if expected else None,
                "expected_manifest_sha256": metadata.get("manifest_sha256"),
                "materializer_source": "nix-store-tree" if metadata.get("source_is_store") else "compressed-release-archive" if metadata else "installed-package",
                "mismatch_counts": counts, "mismatch_samples": samples, "ancestor_modes": ancestors,
                "nonzero_file_flags_count": flags, "extended_attribute_count": xattrs,
                "condition_samples": conditions,
                "file_flags": file_flags, "extended_attributes": ext_attrs,
                "file_flag_names": file_flags, "extended_attribute_names": ext_attrs,
                "flag_names": file_flags, "xattr_names": ext_attrs,
                "sidecar_binary_sha256": _file_hash(sidecar), "sidecar_manifest_sha256": _file_hash(manifest)}
    evidence["classification"] = classify_diagnostic(evidence)
    if return_members:
        return evidence, members_map
    return evidence


def _verifier_script(module):
    # Error text is hashed; only released, fixed messages become public tokens.
    reasons = {"sidecar path has a symlinked ancestor": "symlink-ancestor",
               "manifest bytes are not canonical": "manifest-not-canonical",
               "manifest self-digest is invalid": "manifest-self-digest",
               "sidecar runtime is invalid": "runtime-identity",
               "sidecar payload inventory is invalid": "payload-inventory",
               "sidecar payload totals are invalid": "payload-totals",
               "sidecar actual input identity is invalid": "actual-input-identity",
               "manifest fixed identity is invalid": "manifest-fixed-identity"}
    return ("import {createHash} from 'node:crypto';\nlet phase='import';\ntry {\n"
            "const {verifyDistribution}=await import(" + json.dumps(module.as_uri()) + ");\n"
            "phase='verify'; const result=await verifyDistribution({binaryPath:process.argv[2],payloadRoot:process.argv[3]});\n"
            "phase='output'; console.log(JSON.stringify({status:'pass',result}));\n"
            "} catch(e) { const reasons=" + json.dumps(reasons) + ";\n"
            "console.log(JSON.stringify({status:'fail',phase,"
            "name:['Error','TypeError','SyntaxError','RangeError','ReferenceError'].includes(e.name)?e.name:'Error',"
            "code:['ERR_MODULE_NOT_FOUND','ENOENT','EACCES','ERR_UNKNOWN_FILE_EXTENSION'].includes(e.code)?e.code:null,"
            "message_sha256:createHash('sha256').update(String(e.message)).digest('hex'),"
            "reason_token:reasons[e.message]??'unclassified-released-verifier-error'})); process.exitCode=2; }\n")


def _run_verifier(script, sidecar, payload, prefix, env, cwd=None):
    try:
        result = subprocess.run([*prefix, "node", str(script), str(sidecar), str(payload)],
                                cwd=cwd, env=env, capture_output=True, timeout=180)
    except subprocess.TimeoutExpired as error:
        return {"status": "fail", "phase": "execution", "reason_token": "tool-timeout",
                "stdout_sha256": digest(error.stdout or b""), "stderr_sha256": digest(error.stderr or b"")}, None
    except OSError:
        return {"status": "fail", "phase": "execution", "reason_token": "tool-unavailable"}, None
    stdout, stderr = getattr(result, "stdout", b""), getattr(result, "stderr", b"")
    evidence = {"exit_code": result.returncode, "stdout_sha256": digest(stdout), "stderr_sha256": digest(stderr)}
    try:
        doc = json.loads(stdout)
    except (ValueError, UnicodeError):
        doc = {}
    if isinstance(doc, dict):
        node = doc.get("node_version")
        if isinstance(node, str) and re.fullmatch(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", node):
            evidence["node_version"] = node
        for key in ("missing_path", "diagnostic_token"):
            if key in doc:
                evidence.update(safe_details({key: doc[key]}))
    if result.returncode == 0 and isinstance(doc, dict) and doc.get("status") == "pass" and isinstance(doc.get("result"), dict):
        return {**evidence, "status": "pass"}, doc["result"]
    phases = {"import", "verify", "output", "execution", "unavailable", "unknown"}
    raw_phase = doc.get("phase") if isinstance(doc, dict) and doc.get("phase") in phases else "unknown"
    evidence.update(status="fail", phase=raw_phase,
                    reason_token="unclassified-released-verifier-error")
    if isinstance(doc, dict):
        if doc.get("name") in {"Error", "TypeError", "SyntaxError", "RangeError", "ReferenceError"}:
            evidence["exception_type"] = doc["name"]
        if doc.get("code") in {"ERR_MODULE_NOT_FOUND", "ENOENT", "EACCES", "ERR_UNKNOWN_FILE_EXTENSION"}:
            evidence["code"] = doc["code"]
        if doc.get("reason_token") in {"symlink-ancestor", "manifest-not-canonical", "manifest-self-digest", "runtime-identity", "payload-inventory", "payload-totals", "actual-input-identity", "manifest-fixed-identity"}:
            evidence["reason_token"] = doc["reason_token"]
        checksum = safe_details({"stderr_sha256": doc.get("message_sha256")}).get("stderr_sha256")
        if checksum:
            evidence["message_sha256"] = checksum
    return evidence, None


def _probe_script(prepared, name, text):
    """Container wrappers are immutable inputs; host wrappers retain their existing path."""
    path = Path(prepared.get("probe", prepared["scratch"])) / name
    if "probe" in prepared:
        if path.is_symlink() or path.read_bytes() != text.encode():
            raise ContractError("SIDECAR_HARNESS_IMPORT", "Read-only verifier wrapper differs",
                                details={"substage": "verifier-wrapper", "missing_path": name})
    else:
        path.write_text(text)
    return path


def _import_preflight_script(source, tools):
    modules = [(tools / p).as_uri() for p in ("sidecar-common.mjs", "sidecar-verify.mjs", "native-rc-smoke.mjs")]
    return (
        "import {createHash} from 'node:crypto'; import {relative,isAbsolute} from 'node:path';\n"
        "import {fileURLToPath} from 'node:url';\ntry {\n"
        "const modules=await Promise.all(" + json.dumps(modules) + ".map(p=>import(p)));\n"
        "if(typeof modules[0].verifyDistribution!=='function'||typeof modules[1].verifySidecar!=='function') throw new TypeError('verifier export missing');\n"
        "console.log(JSON.stringify({status:'pass',result:{},node_version:process.versions.node}));\n"
        "} catch(e) { let path=e.path; if(!path&&e.url) {try {path=fileURLToPath(e.url);} catch {}}\n"
        "const rel=typeof path==='string'?relative(" + json.dumps(str(source)) + ",path):null;\n"
        "const safe=rel&&!isAbsolute(rel)&&!rel.startsWith('..')&&/^[A-Za-z0-9_./@+-]{1,256}$/.test(rel)?rel:path?'outside-source-root':null;\n"
        "console.log(JSON.stringify({status:'fail',phase:'import',name:e.name,code:e.code,node_version:process.versions.node,"
        "missing_path:safe,diagnostic_token:typeof e.syscall==='string'&&e.syscall.startsWith('spawn')?'spawn-unavailable':'module-import',"
        "message_sha256:createHash('sha256').update(String(e.message)).digest('hex')})); process.exitCode=2; }\n"
    )


def verify_source_readback(prepared):
    source = Path(prepared["source"])
    capture = prepared.get("capture")
    record = getattr(capture, "record", None)
    tag = record.get("tag") if isinstance(record, dict) else None
    tag = tag if isinstance(tag, dict) else {}
    rows = prepared.get("records", [])
    if (not isinstance(rows, list) or any(not isinstance(row, dict)
            or not isinstance(row.get("path"), str) or type(row.get("size")) is not int
            or not isinstance(row.get("sha256"), str) or not isinstance(row.get("blob"), str) for row in rows)):
        raise ContractError("SIDECAR_HARNESS_IMPORT", "Malformed verifier source records")
    if (prepared.get("source_generation") == "theme-forge-current-202610"
            or tag.get("commit") in (CURRENT070_COMMIT, CURRENT071_COMMIT)
            or any(row.get("tag_commit") in (CURRENT070_COMMIT, CURRENT071_COMMIT) for row in rows)):
        _verify_current_source_binding(prepared)
    if source.is_symlink():
        raise ContractError("SIDECAR_HARNESS_IMPORT", "Verifier source root cannot be an alias")
    source = source.resolve()
    # Recheck transported blobs before executing them in a wheel/native client.
    for row in rows:
        validate_safe_relative_posix_path(row["path"])
        path = source / row["path"]
        if any(p.is_symlink() for p in (path, *path.parents)) or not path.is_file():
            raise ContractError("SIDECAR_HARNESS_IMPORT", "Authenticated verifier source is missing",
                                details={"substage": "verifier-source-readback", "missing_path": row["path"]})
        if path.stat().st_size > 2 * 1024 ** 2:
            raise ContractError("SIDECAR_HARNESS_IMPORT", "Verifier source exceeds bound")
        data = path.read_bytes()
        blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        if len(data) != row["size"] or digest(data) != row["sha256"] or blob != row["blob"]:
            raise ContractError("SIDECAR_HARNESS_IMPORT", "Authenticated verifier source changed",
                                details={"substage": "verifier-source-readback", "missing_path": row["path"]})


def verifier_import_preflight(prepared, system, prefix=(), env=None):
    """Import the authentic released sibling closure before inspecting any runtime."""
    source = Path(prepared.get("source", prepared["tools"]))
    if source.is_symlink():
        raise ContractError("SIDECAR_HARNESS_IMPORT", "Verifier source root cannot be an alias")
    source = source.resolve()
    tools = Path(prepared["tools"]).resolve()
    verify_execution_source_readback({**prepared, "source": source, "tools": tools})
    script = Path(prepared.get("probe", prepared["scratch"])) / "verify-import-preflight.mjs"
    _probe_script(prepared, "verify-import-preflight.mjs", _import_preflight_script(source, tools))
    evidence, result = _run_verifier(script, "", "", prefix, runtime_environment(env), cwd=source)
    if result is None:
        diagnostic = {"schema": "rs9.sidecar-import-preflight.v1alpha1", "product": "theme-forge-nebular-fusion",
                      "system": system, "substage": "verifier-import-preflight",
                      "classification": "harness/import/execution", "verifier": evidence}
        diagnostics = Path(prepared["scratch"]).parent / "diagnostics"
        diagnostics.mkdir(exist_ok=True)
        label = _safe_label(prepared.get("label") or prepared.get("family"))
        filename = "sidecar-verifier-" + label + ".json" if label else "sidecar-verifier.json"
        (diagnostics / filename).write_bytes(canonical(diagnostic))
        raise ContractError("SIDECAR_HARNESS_IMPORT", "Released verifier import preflight failed",
                            details={"product": "theme-forge-nebular-fusion", "system": system,
                                     "substage": "verifier-import-preflight", **evidence})
    return evidence


def expected_runtime_members(prepared, system):
    capture = prepared.get("capture")
    if capture:
        candidates = [p for p in capture.record["payloads"] if system in p["platforms"]]
        if len(candidates) == 1:
            return capture.manifests[candidates[0]["id"]]["members"]
    if "expected_members" in prepared:
        members = prepared["expected_members"]
        if not isinstance(members, list) or digest(canonical(members)) != prepared.get("manifest_sha256"):
            raise ContractError("SIDECAR_MANIFEST_BINDING", "Transported runtime manifest identity differs")
        return members
    return None


def _control_verifier(capture, system, prepared, script, prefix, env, runtime_identity=None):
    """Independent raw archive control; its result never satisfies the runtime gate."""
    from rs9.materialize import materialize_payload
    candidates = [p for p in capture.record["payloads"] if system in p["platforms"]]
    if len(candidates) != 1:
        return {"status": "not-run", "reason": "control-asset-selection"}
    asset = candidates[0]
    archive, manifest = capture.archives[asset["id"]], capture.manifests[asset["id"]]
    if _file_hash(archive) != asset["sha256"]:
        return {"status": "fail", "reason": "control-archive-identity"}
    try:
        cache = prepared["scratch"] / "control-cache"
        root = materialize_payload(archive, cache, manifest,
                                   expected_manifest_sha256=asset["payload_manifest_sha256"])
        # Only cache administration ancestors change; released payload modes stay exact.
        for path in (cache, cache / "entries", root.parent.parent, root.parent):
            path.chmod(0o755)
        manifests = list(root.rglob("sidecar-payload/manifest.json"))
        binaries = [p for p in root.rglob("tfsb-studio-service*") if p.is_file() and p.parent.name in {"bin", "MacOS"}]
        if len(manifests) != 1 or len(binaries) != 1:
            return {"status": "fail", "reason": "control-sidecar-representation"}
        evidence, _ = _run_verifier(script, binaries[0], manifests[0].parent, prefix, env,
                                   cwd=prepared.get("source", prepared["tools"]))
        expected_members = manifest.get("members") if isinstance(manifest, dict) else manifest if isinstance(manifest, list) else None
        control_identity = runtime_evidence(root, binaries[0], manifests[0], expected_members=expected_members)
        comparison = {
            "mismatch_count_deltas": {k: control_identity["mismatch_counts"].get(k, 0) - runtime_identity.get("mismatch_counts", {}).get(k, 0)
                                      for k in control_identity["mismatch_counts"]} if runtime_identity else None,
            "counts_equal": bool(runtime_identity and control_identity["actual_member_count"] == runtime_identity.get("actual_member_count")),
            "hash_equal": bool(runtime_identity and control_identity["runtime_root_sha256"] == runtime_identity.get("runtime_root_sha256")),
            "actual_member_counts": {
                "control": control_identity["actual_member_count"],
                "runtime": runtime_identity.get("actual_member_count") if runtime_identity else None,
            },
            "runtime_root_sha256": {
                "control": control_identity["runtime_root_sha256"],
                "runtime": runtime_identity.get("runtime_root_sha256") if runtime_identity else None,
            },
        }
        return {
            **evidence,
            "archive_sha256": asset["sha256"],
            "manifest_sha256": asset["payload_manifest_sha256"],
            "runtime_identity": control_identity,
            "comparison_to_runtime": comparison,
            "satisfies_installed_gate": False,
        }
    except (ContractError, OSError) as error:
        return {"status": "fail", "reason": error.code if isinstance(error, ContractError) else "control-io"}


def compare_drift(baseline, root, current_identity, current_members=None):
    """Compare post-probe runtime against captured baseline."""
    if not baseline:
        return None
    baseline_root_sha256 = baseline.get("runtime_root_sha256")
    baseline_member_count = baseline.get("actual_member_count")
    current_root_sha256 = current_identity.get("runtime_root_sha256")
    current_member_count = current_identity.get("actual_member_count")

    baseline_members = baseline.get("members")
    drift_counts = {"modified": 0, "added": 0, "removed": 0, "mode": 0}
    drift_samples = {"modified": [], "added": [], "removed": [], "mode": []}

    def record_drift(kind, path, **extra):
        drift_counts[kind] += 1
        if len(drift_samples[kind]) < 10:
            item = {"path": _bound_path(path)}
            item.update(extra)
            drift_samples[kind].append(item)

    if baseline_members is not None:
        if current_members is None:
            _, _, _, _, _, current_members, _ = _inventory_runtime(root)

        for path, b_row in baseline_members.items():
            c_row = current_members.get(path)
            if c_row is None:
                record_drift("removed", path)
            else:
                if b_row["type"] != c_row["type"]:
                    record_drift("modified", path, reason="type_changed")
                elif b_row["type"] == "file":
                    if (b_row.get("size"), b_row.get("sha256")) != (c_row.get("size"), c_row.get("sha256")):
                        record_drift("modified", path)
                    if b_row["mode"] != c_row["mode"]:
                        record_drift("mode", path, expected_mode=b_row["mode"], actual_mode=c_row["mode"],
                                     baseline_mode=b_row["mode"], current_mode=c_row["mode"])
                elif b_row["type"] == "directory":
                    if b_row["mode"] != c_row["mode"]:
                        record_drift("mode", path, expected_mode=b_row["mode"], actual_mode=c_row["mode"],
                                     baseline_mode=b_row["mode"], current_mode=c_row["mode"])
                elif b_row["type"] == "symlink":
                    if b_row.get("target_sha256") != c_row.get("target_sha256"):
                        record_drift("modified", path)

        for path in sorted(current_members.keys() - baseline_members.keys()):
            record_drift("added", path)

    has_drift = (
        baseline_root_sha256 != current_root_sha256
        or any(v > 0 for v in drift_counts.values())
        or baseline_member_count != current_member_count
    )

    return {
        "has_drift": has_drift,
        "baseline_runtime_root_sha256": baseline_root_sha256,
        "current_runtime_root_sha256": current_root_sha256,
        "baseline_member_count": baseline_member_count,
        "current_member_count": current_member_count,
        "baseline_mismatch_counts": baseline.get("evidence", {}).get("mismatch_counts", {}),
        "drift_counts": drift_counts,
        "drift_samples": drift_samples,
    }


def snapshot_nebular_runtime(runtime_root, prepared, system, discovered=None):
    """Snapshot Nebular baseline after first launcher materialization and before remaining command probes."""
    root = Path(runtime_root)
    manifests = [Path(p) for p in discovered["manifests"]] if discovered else list(root.rglob("sidecar-payload/manifest.json"))
    binaries = [Path(p) for p in discovered["binaries"]] if discovered else [p for p in root.rglob("tfsb-studio-service*") if p.is_file() and p.parent.name in ("bin", "MacOS")]
    if len(manifests) != 1 or len(binaries) != 1:
        raise ContractError("SIDECAR_REPRESENTATION", "One released sidecar and payload required")
    sidecar = binaries[0]
    expected = expected_runtime_members(prepared, system) if prepared else None
    identity, members_map = runtime_evidence(root, sidecar, manifests[0], expected, return_members=True)
    return {
        "schema": "rs9.nebular-runtime-baseline.v1alpha1",
        "system": system,
        "runtime_root_sha256": identity["runtime_root_sha256"],
        "actual_member_count": identity["actual_member_count"],
        "sidecar_binary_sha256": identity.get("sidecar_binary_sha256"),
        "sidecar_manifest_sha256": identity.get("sidecar_manifest_sha256"),
        "evidence": identity,
        "members": members_map,
    }


def bound_diagnostic(diagnostic, max_bytes=60 * 1024):
    """Bound every nested sample, including the archive control, then enforce a hard cap."""
    def project(value, sample_limit=10, depth=0):
        if depth > 12:
            return {"omitted": True}
        if isinstance(value, dict):
            return {k: project(v, sample_limit, depth + 1) for k, v in list(value.items())[:64]}
        if isinstance(value, list):
            return [project(v, sample_limit, depth + 1) for v in value[:sample_limit]]
        if isinstance(value, str) and len(value) > 256:
            return "sha256:" + digest(value.encode())
        return value
    for limit in (10, 3, 1, 0):
        result = project(diagnostic, limit)
        if result != diagnostic:
            result["diagnostic_truncated"] = True
        if len(canonical(result)) <= max_bytes:
            return result
    result = {"schema": "rs9.sidecar-verifier-diagnostic.v1alpha1", "diagnostic_truncated": True,
              "classification": diagnostic.get("classification"),
              "verifier": safe_details({key: value for key, value in diagnostic.get("verifier", {}).items()
                                        if key in {"phase", "reason_token", "exit_code", "stdout_sha256", "stderr_sha256"}}),
              "mismatch_counts": {k: v for k, v in diagnostic.get("mismatch_counts", {}).items()
                                  if k in {"missing", "extra", "type", "bytes", "file_mode", "directory_mode", "dir_mode", "symlink"}
                                  and type(v) is int and 0 <= v < 2 ** 63},
              "diagnostic_sha256": digest(canonical(diagnostic))}
    for key in ("system", "product", "substage", "family", "invocation"):
        if key in diagnostic:
            result[key] = diagnostic[key]
    if len(canonical(result)) > max_bytes:
        raise ContractError("SIDECAR_DIAGNOSTIC_LIMIT", "Diagnostic bound cannot retain classification")
    return result


def verify_nebular_runtime(runtime_root, prepared, system, prefix=(), env=None, discovered=None, baseline=None,
                            label=None, diagnostic_extras: bool = False, diagnostic_boundary_probes: bool = False,
                            diagnostic_replay: bool = False, diagnostic_initial_observation: bool = False,
                            session_bus_argv=None):
    """No extraction here: runtime_root is the wheel cache, Nix cache, or installed package."""
    if session_bus_argv is not None:
        from rs9.nix_proot_dbus_command import validate_session_bus_argv
        session_bus_argv = validate_session_bus_argv(session_bus_argv)
    env = runtime_environment(env)
    import_evidence = verifier_import_preflight(prepared, system, prefix, env)
    root = Path(runtime_root)
    darwin = system == "aarch64-darwin"
    if darwin:
        launch_root = root.parent
        sidecar = root / "Contents/MacOS/tfsb-studio-service"
        payload = root / "Contents/Resources/sidecar-payload"
    else:
        launch_root = root
        sidecar = root / "bin/tfsb-studio-service"
        payload = root / "lib/sidecar-payload"
    # Resolve the release's payload representation by its canonical manifest, not guessed flags.
    manifests = [Path(p) for p in discovered["manifests"]] if discovered else list(root.rglob("sidecar-payload/manifest.json"))
    binaries = [Path(p) for p in discovered["binaries"]] if discovered else [p for p in root.rglob("tfsb-studio-service*") if p.is_file() and p.parent.name in ("bin", "MacOS")]
    if len(manifests) != 1 or len(binaries) != 1:
        raise ContractError("SIDECAR_REPRESENTATION", "One released sidecar and payload required")
    sidecar, payload = binaries[0], manifests[0].parent
    script = _probe_script(prepared, "verify-runtime.mjs", _verifier_script(prepared["tools"] / "sidecar-common.mjs"))
    capture = prepared.get("capture")
    expected = expected_runtime_members(prepared, system)
    identity, current_members = runtime_evidence(root, sidecar, manifests[0], expected, return_members=True)
    verifier, verification = _run_verifier(script, sidecar, payload, prefix, env,
                                         cwd=prepared.get("source", prepared["tools"]))
    drift = compare_drift(baseline, root, identity, current_members=current_members) if baseline else None
    classification = classify_diagnostic(identity, verifier=verifier, drift=drift)

    inv_label = _safe_label(label or (prepared.get("label") if prepared else None) or (prepared.get("family") if prepared else None))
    if not inv_label and prepared and "scratch" in prepared:
        scratch_path = Path(prepared["scratch"])
        if scratch_path.name.startswith("smoke-"):
            inv_label = _safe_label(scratch_path.name[len("smoke-"):])

    diagnostic = {"schema": "rs9.sidecar-verifier-diagnostic.v1alpha1", "system": system,
                  "product": "theme-forge-nebular-fusion", "substage": "released-sidecar-verifier",
                  **identity, "classification": classification, "verifier": verifier,
                  "import_preflight": import_evidence}
    if inv_label:
        diagnostic["family"] = inv_label
        diagnostic["invocation"] = inv_label
    if drift is not None:
        diagnostic["drift"] = drift
    diagnostic["archive_control"] = (_control_verifier(capture, system, prepared, script, prefix, env, runtime_identity=identity)
                                         if capture else {"status": "not-run", "reason": "client-control-not-applicable"})
    diagnostic = bound_diagnostic(diagnostic, max_bytes=60 * 1024)
    diagnostics = prepared["scratch"].parent / "diagnostics"
    diagnostics.mkdir(exist_ok=True)
    filename = f"sidecar-verifier-{inv_label}.json" if inv_label else "sidecar-verifier.json"
    (diagnostics / filename).write_bytes(canonical(diagnostic))
    if verification is None:
        raise ContractError("SIDECAR_VERIFIER", "Released sidecar verifier rejected actual runtime representation",
                            details={"product": "theme-forge-nebular-fusion", "substage": "released-sidecar-verifier",
                                     "system": system, "reason": verifier["reason_token"],
                                     **{k: v for k, v in verifier.items() if k in {"exit_code", "stdout_sha256", "stderr_sha256", "exception_type", "phase"}}})
    from rs9.application_smoke_diagnostic import execute_application_smoke
    runs = execute_application_smoke(
        prepared=prepared,
        system=system,
        launch_root=launch_root,
        prefix=prefix,
        env=env,
        diagnostic_extras=diagnostic_extras,
        diagnostic_boundary_probes=diagnostic_boundary_probes,
        diagnostic_replay=diagnostic_replay,
        diagnostic_initial_observation=diagnostic_initial_observation,
        session_bus_argv=session_bus_argv,
    )
    # Raw harness logs can contain ephemeral paths. Keep only bounded public identities.
    res = {"sidecar": {"verifier_stdout_sha256": digest(canonical(verification)), "verified": True},
           "scenarios": runs, "source_bindings": prepared["records"]}
    if drift is not None:
        res["drift"] = drift
    return res
