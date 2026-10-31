"""Admission and installed-consumer bridge for the universal Python launcher.

This proof domain does not impersonate the historical three-wheel profiles.
Construction and individual consumer checks supply no publication authority.
"""
from __future__ import annotations

import hashlib
from collections.abc import Mapping
from pathlib import Path

from rs9.errors import ContractError
from rs9.materialize import parse_manifest_members
from rs9.scratch import canonical
from rs9.tf_pypi_model import strict_json
from rs9.tf_pypi_verify import read_wheel, verify_record
from rs9.wheel_native import get_embedded_rs9_helpers
from rs9 import wheel_nebular071_universal as builder


DISTRIBUTION = "universal-launcher"
TAG = "py3-none-any"
MAX_WHEEL_BYTES = 4 * 1024 * 1024
_SOURCE_KEYS = (
    "authority",
    "repository",
    "commit",
    "tree",
    "record_sha256",
    "authority_identity",
)
PROCESS_FIELDS = frozenset({
    "exit_code", "signal", "stdout_sha256", "stderr_sha256", "duration_ms",
    "timed_out", "output_limit_exceeded", "cleanup_known", "output_complete", "forced_cleanup",
})


def _fail(code):
    raise ContractError("NEBULAR_UNIVERSAL_" + code,
                        "Universal launcher inputs or evidence do not match")


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _public_process(value):
    if not isinstance(value, Mapping) or not PROCESS_FIELDS.issubset(value):
        _fail("PROCESS")
    return {key: value[key] for key in sorted(PROCESS_FIELDS)}


def authenticated_product_source(capture):
    """Derive the 0.7.1 product-source frame from a generic ReleaseCapture.

    The source coordinates and source-authority identity are deliberately not
    accepted as a second caller-owned dictionary.  The generic release
    authenticator has already checked the selected release/tag/tree and asset
    bytes; this adapter rechecks the selected source archive and authority
    assets, then derives the frame consumed by the installed-wheel closure.
    """
    from rs9.release_core import (
        ReleaseCapture,
        authenticated_record_hash,
        authenticated_release_metadata,
        authenticated_tree,
    )
    from rs9.nebular071_smoke_support import (
        _source_archive_members,
        _source_composition_identity,
        _validate_source_authority_body,
    )

    if not isinstance(capture, ReleaseCapture):
        _fail("PRODUCT_CAPTURE")
    try:
        record_sha = authenticated_record_hash(capture)
        tree = authenticated_tree(capture)
        release = authenticated_release_metadata(capture)
    except Exception:
        _fail("PRODUCT_CAPTURE")
    record = capture.record
    repository = record.get("repository") if isinstance(record, Mapping) else None
    release_row = record.get("release") if isinstance(record, Mapping) else None
    tag = record.get("tag") if isinstance(record, Mapping) else None
    if (not isinstance(repository, Mapping) or repository.get("full_name") !=
            "Knowledge-Forge-AI/theme-forge-nebular-fusion"
            or type(repository.get("id")) is not int or repository["id"] <= 0
            or not isinstance(release_row, Mapping)
            or release_row.get("tag") != "v0.7.1"
            or type(release_row.get("id")) is not int or release_row["id"] <= 0
            or release_row.get("draft") is not False
            or release_row.get("prerelease") is not False
            or not isinstance(tag, Mapping)
            or not isinstance(tag.get("commit"), str)
            or not isinstance(tag.get("tree"), str)
            or len(tag["commit"]) != 40 or len(tag["tree"]) != 40
            or any(ch not in "0123456789abcdef" for ch in tag["commit"] + tag["tree"])
            or not isinstance(tree, Mapping) or tree.get("sha") != tag["tree"]
            or not isinstance(release, Mapping)
            or release.get("tag_name") != release_row["tag"]
            or release.get("id") != release_row["id"]
            or release.get("draft") is not False
            or release.get("prerelease") is not False):
        _fail("PRODUCT_CAPTURE")

    assets = record.get("assets")
    if not isinstance(assets, list):
        _fail("PRODUCT_CAPTURE")
    by_role = {}
    for row in assets:
        if not isinstance(row, Mapping):
            _fail("PRODUCT_CAPTURE")
        role = row.get("role")
        if role in {"source-archive", "source-authority"}:
            if role in by_role or not isinstance(row.get("name"), str):
                _fail("PRODUCT_CAPTURE")
            by_role[role] = row
    if set(by_role) != {"source-archive", "source-authority"}:
        _fail("PRODUCT_CAPTURE")
    evidence = capture.evidence_bytes
    if not isinstance(evidence, Mapping):
        _fail("PRODUCT_CAPTURE")
    bodies = {}
    for role, row in by_role.items():
        name = row["name"]
        body = evidence.get(name)
        if (not isinstance(body, bytes) or type(row.get("size")) is not int
                or row["size"] != len(body) or row.get("sha256") != _sha(body)):
            _fail("PRODUCT_CAPTURE")
        bodies[role] = body
    archive_row, authority_row = by_role["source-archive"], by_role["source-authority"]
    archive_name, authority_name = archive_row["name"], authority_row["name"]
    if (not archive_name.startswith("theme-forge-nebular-fusion-v0.7.1-")
            or not archive_name.endswith("-source.tar.gz")
            or authority_name != "nebular-compiled-public-build-source-authority-v0.7.1.json"
            or not authority_name.endswith(".json")):
        _fail("PRODUCT_CAPTURE")
    try:
        authority = strict_json(bodies["source-authority"])
        authority_identity = authority.get("identity") if isinstance(authority, Mapping) else None
        checked_authority = _validate_source_authority_body(
            authority, expected_identity=authority_identity,
        )
        members = _source_archive_members(
            bodies["source-archive"], expected_size=archive_row["size"],
            expected_sha256=archive_row["sha256"],
        )
    except Exception:
        _fail("PRODUCT_CAPTURE")
    if checked_authority.get("composition") != _source_composition_identity(members):
        _fail("PRODUCT_CAPTURE")
    return {
        "authority": "authenticated-product-source",
        "repository": repository["full_name"],
        "commit": tag["commit"],
        "tree": tag["tree"],
        "record_sha256": record_sha,
        "authority_identity": checked_authority["identity"],
    }


def authenticated_product_release(capture) -> dict:
    """Derive the full authenticated product release frame and asset index."""
    source_identity = authenticated_product_source(capture)
    record = capture.record
    repository = record["repository"]
    release_row = record["release"]
    tag = record["tag"]
    assets = record["assets"]
    evidence = capture.evidence_bytes
    assets_by_name = {}
    assets_by_role = {}
    for row in assets:
        if (not isinstance(row, Mapping) or not isinstance(row.get("name"), str)
                or type(row.get("github_asset_id")) is not int or row["github_asset_id"] <= 0
                or type(row.get("size")) is not int or row["size"] <= 0
                or not isinstance(row.get("sha256"), str) or len(row["sha256"]) != 64
                or any(ch not in "0123456789abcdef" for ch in row["sha256"])):
            _fail("PRODUCT_CAPTURE")
        name = row["name"]
        if name in assets_by_name:
            _fail("PRODUCT_CAPTURE")
        assets_by_name[name] = dict(row)
        role = row.get("role")
        if role in {"source-archive", "source-authority", "native-provenance"}:
            if role in assets_by_role:
                _fail("PRODUCT_CAPTURE")
            assets_by_role[role] = dict(row)
    if set(assets_by_role) != {"source-archive", "source-authority", "native-provenance"}:
        _fail("PRODUCT_CAPTURE")
    prov_row = assets_by_role["native-provenance"]
    if prov_row["name"] != "nebular-v0.7.1-native-ci-provenance.json":
        _fail("PRODUCT_CAPTURE")
    prov_bytes = evidence.get("nebular-v0.7.1-native-ci-provenance.json")
    if (not isinstance(prov_bytes, bytes) or len(prov_bytes) != prov_row["size"]
            or _sha(prov_bytes) != prov_row["sha256"]):
        _fail("PRODUCT_CAPTURE")
    try:
        provenance = strict_json(prov_bytes)
    except Exception:
        _fail("PRODUCT_CAPTURE")
    if (not isinstance(provenance, Mapping)
            or provenance.get("schema") != "nebular.public-native-ci-release-provenance.v1"
            or provenance.get("repository") != repository["full_name"]
            or provenance.get("version") != builder.VERSION
            or provenance.get("release") != release_row["id"]
            or provenance.get("releaseCommit") != tag["commit"]
            or provenance.get("testedTree") != tag["tree"]
            or not isinstance(provenance.get("testedCommit"), str)
            or len(provenance["testedCommit"]) != 40
            or any(ch not in "0123456789abcdef" for ch in provenance["testedCommit"])
            or any(
                type(provenance.get(field)) is not int or provenance[field] <= 0
                for field in ("nativeCiRun", "nativeCiAttempt", "sourceCiRun")
            )):
        _fail("PRODUCT_CAPTURE")
    return {
        "repository": {"full_name": repository["full_name"], "id": repository["id"]},
        "release_id": release_row["id"],
        "tag": release_row["tag"],
        "commit": tag["commit"],
        "tree": tag["tree"],
        "record_sha256": source_identity["record_sha256"],
        "source": source_identity,
        "assets_by_name": assets_by_name,
        "assets_by_role": assets_by_role,
        "provenance_bytes": prov_bytes,
        "provenance": dict(provenance),
    }


def join_product_native_release(product_capture, product_source, release,
                                record, provenance, proof, asset, *,
                                provenance_bytes: bytes | None = None,
                                support: Mapping | None = None, native_admission=None) -> dict:
    """Join the authenticated product release to one native release frame.

    The product ``ReleaseCapture`` is the authority for source/archive and
    tag coordinates.  The native record and provenance are a separate,
    authenticated readback.  A caller-supplied source dictionary cannot make
    either side match: the native payload row must also be present in the
    product capture's selected asset records.  Compiler commits come from
    authenticated native provenance (``testedCommit`` / ``testedTree``) and
    may differ from the final release commit only when ``testedTree`` equals
    the authenticated release tree.  Original product CI is admitted by a separate typed capability; future RS9
    installed-consumer authority is emitted only by the current hosted probes.
    """
    from rs9.release_core import ReleaseCapture

    if (not isinstance(product_capture, ReleaseCapture)
            or not isinstance(product_source, Mapping)
            or not isinstance(release, Mapping)
            or not isinstance(record, Mapping)
            or not isinstance(provenance, Mapping)
            or not isinstance(proof, Mapping)
            or not isinstance(asset, Mapping)):
        _fail("RELEASE_JOIN")
    try:
        product_frame = authenticated_product_release(product_capture)
    except ContractError:
        _fail("RELEASE_JOIN")
    if dict(product_source) != product_frame["source"]:
        _fail("RELEASE_JOIN")

    product_repo = product_frame["repository"]
    native_repo = record.get("repository")
    native_release = record.get("release")
    native_tag = record.get("tag")
    if (not isinstance(native_repo, Mapping)
            or not isinstance(native_release, Mapping)
            or not isinstance(native_tag, Mapping)):
        _fail("RELEASE_JOIN")
    if (record.get("schema") != "rs9.release-record.v1alpha1"
            or native_repo.get("full_name") != release.get("repository")
            or native_repo.get("full_name") != product_repo["full_name"]
            or native_repo.get("id") != product_repo["id"]
            or native_release.get("tag") != "v0.7.1"
            or native_release.get("tag") != release.get("tag")
            or native_release.get("id") != product_frame["release_id"]
            or native_release.get("draft") is not False
            or native_release.get("prerelease") is not False
            or native_tag.get("commit") != release.get("commit")
            or native_tag.get("tree") != release.get("tree")
            or native_tag.get("commit") != product_frame["commit"]
            or native_tag.get("tree") != product_frame["tree"]):
        _fail("RELEASE_JOIN")

    def _matching_payload(rows):
        if not isinstance(rows, list):
            return []
        return [
            row for row in rows
            if isinstance(row, Mapping)
            and row.get("github_asset_id") == asset.get("id")
            and row.get("name") == asset.get("name")
            and row.get("size") == asset.get("size")
            and row.get("sha256") == asset.get("sha256")
            and row.get("role") == "payload"
            and row.get("checksum_covered") is True
        ]

    product_matches = _matching_payload(product_capture.record.get("assets"))
    native_matches = _matching_payload(record.get("assets"))
    if len(product_matches) != 1 or len(native_matches) != 1:
        _fail("RELEASE_JOIN")

    if provenance_bytes is not None and provenance_bytes != product_frame["provenance_bytes"]:
        _fail("RELEASE_JOIN")
    try:
        if canonical(provenance) != canonical(product_frame["provenance"]):
            _fail("RELEASE_JOIN")
    except Exception:
        _fail("RELEASE_JOIN")
    prov_assets = [
        item for item in provenance.get("assets", [])
        if isinstance(item, Mapping)
        and item.get("id") == asset.get("id")
        and item.get("name") == asset.get("name")
        and item.get("bytes") == asset.get("size")
        and item.get("sha256") == asset.get("sha256")
        and item.get("role") == "raw-archive"
    ]
    if len(prov_assets) != 1:
        _fail("RELEASE_JOIN")

    if support is not None:
        if not isinstance(support, Mapping) or support.get("source") != product_frame["source"]:
            _fail("RELEASE_JOIN")
        binding = support.get("source_binding")
        archive_asset = product_frame["assets_by_role"]["source-archive"]
        authority_asset = product_frame["assets_by_role"]["source-authority"]
        archive_bind = binding.get("archive") if isinstance(binding, Mapping) else None
        authority_bind = binding.get("authority") if isinstance(binding, Mapping) else None
        if (not isinstance(archive_bind, Mapping) or not isinstance(authority_bind, Mapping)
                or archive_bind.get("size") != archive_asset["size"]
                or archive_bind.get("sha256") != archive_asset["sha256"]
                or authority_bind.get("size") != authority_asset["size"]
                or authority_bind.get("sha256") != authority_asset["sha256"]):
            _fail("RELEASE_JOIN")

    from rs9.nebular071_product_native import require_native_admission
    try:
        admitted_native = require_native_admission(native_admission, product_capture, proof, asset)
    except ContractError:
        _fail("RELEASE_JOIN")

    tested_commit = provenance["testedCommit"]
    tested_tree = provenance["testedTree"]
    native_record_hash = _sha(canonical(record))
    return {
        "schema": "rs9.nebular071-release-join.v1",
        "repository": product_repo["full_name"],
        "tag": "v0.7.1",
        "release_id": product_frame["release_id"],
        "product": {
            "commit": product_source["commit"],
            "tree": product_source["tree"],
            "record_sha256": product_frame["record_sha256"],
            "authority_identity": product_source["authority_identity"],
        },
        "native": {
            "commit": release["commit"],
            "tree": release["tree"],
            "record_sha256": native_record_hash,
            "provenance_sha256": _sha(product_frame["provenance_bytes"]),
            "asset_id": asset["id"],
        },
        "compiler": {
            "commit": tested_commit,
            "tree": tested_tree,
            "relation": (
                "release-commit"
                if tested_commit == product_frame["commit"]
                else "authenticated-equal-tree"
            ),
            "native_ci_run": provenance["nativeCiRun"],
            "native_ci_attempt": provenance["nativeCiAttempt"],
            "source_ci_run": provenance["sourceCiRun"],
        },
        "product_native": admitted_native,
    }


def inspect_universal_wheel(
    raw: bytes, runtime_inputs: bytes, *, repository: Path,
    description: bytes, legal_root: Path | None = None,
) -> dict:
    """Join one RECORD-verified text-only wheel to current source and all pins."""
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_WHEEL_BYTES:
        _fail("WHEEL")
    inputs = builder._inputs(runtime_inputs)
    files = read_wheel(raw, max_total_bytes=16 * 1024 * 1024,
                       max_member_bytes=4 * 1024 * 1024)
    package, info = builder.PACKAGE, builder.DIST_INFO
    verify_record(files, info)
    helpers = get_embedded_rs9_helpers()
    expected = {
        package + "/__init__.py", package + "/launcher.py", package + "/_fetch.py",
        package + "/runtime-index.json", package + "/_rs9/provenance.json",
        *(package + "/runtimes/" + key + ".json" for key in builder.LAYOUTS),
        *(package + "/_isolated/" + key for key in helpers),
        *(info + "/licenses/" + name for name in builder.LEGAL_FILES),
        *(info + "/" + name for name in ("METADATA", "WHEEL", "entry_points.txt", "RECORD")),
    }
    if set(files) != expected:
        _fail("MEMBERS")
    try:
        for data, _mode in files.values():
            data.decode("utf-8")
    except UnicodeError:
        _fail("MEMBERS")

    def member(name):
        return files[name][0]

    if member(info + "/WHEEL") != (
        b"Wheel-Version: 1.0\nGenerator: rs9-nebular-universal (1.0)\n"
        b"Root-Is-Purelib: true\nTag: py3-none-any\n"
    ):
        _fail("TAG")
    metadata = (
        "Metadata-Version: 2.4\nName: theme-forge-nebular-fusion\nVersion: 0.7.1\n"
        "Summary: Theme Forge Nebular Fusion desktop application launcher\n"
        "License-Expression: AGPL-3.0-or-later\n"
        + "".join("License-File: " + name + "\n" for name in builder.LEGAL_FILES)
        + "Requires-Python: >=3.10\n"
        "Project-URL: Source, https://github.com/Knowledge-Forge-AI/theme-forge-nebular-fusion\n"
        "Project-URL: Packaging source, https://github.com/Knowledge-Forge-AI/release-starport-9\n"
        "Description-Content-Type: text/markdown\n\n"
    ).encode() + description
    if member(info + "/METADATA") != metadata:
        _fail("METADATA")
    if (member(info + "/entry_points.txt") !=
            b"[console_scripts]\ntfnf = theme_forge_nebular_fusion.launcher:main_tfnf\n"
            or member(package + "/__init__.py") !=
            b'"""Theme Forge Nebular Fusion Python launcher."""\n__version__ = "0.7.1"\n'):
        _fail("SOURCE")
    legal = Path(legal_root) if legal_root is not None else Path(repository)
    for name in builder.LEGAL_FILES:
        if member(info + "/licenses/" + name) != builder._read(legal / name, 2 * 1024 * 1024)[0]:
            _fail("LICENSE")
    for name, source in helpers.items():
        if member(package + "/_isolated/" + name) != source:
            _fail("SOURCE")
    source = Path(repository) / "src/rs9"
    launcher = builder._read(source / "nebular071_universal_launcher.py", 262144)[0]
    fetcher = builder._read(source / "nebular071_universal_fetch.py", 262144)[0]
    raw_index = member(package + "/runtime-index.json")
    index_sha = _sha(raw_index)
    if (launcher.count(b"__TFNF_INDEX_SHA256__") != 1
            or member(package + "/launcher.py") != launcher.replace(
                b"__TFNF_INDEX_SHA256__", index_sha.encode())
            or member(package + "/_fetch.py") != fetcher):
        _fail("SOURCE")
    manifests, targets = {}, {}
    for key, spec in inputs["targets"].items():
        raw_manifest = member(package + "/runtimes/" + key + ".json")
        value = strict_json(raw_manifest)
        members, root, digest = parse_manifest_members(value)
        if (not isinstance(value, dict) or canonical(value) != raw_manifest
                or value.get("root") != root or root != spec["root"]
                or digest != spec["manifest_sha256"]):
            _fail("MANIFEST")
        manifests[key] = value
        targets[key] = {name: spec[name] for name in (
            "asset", "root", "manifest_sha256", "shell_target", "gui_target")}
        targets[key]["manifest_resource_sha256"] = _sha(raw_manifest)
    expected_index = {"schema": "rs9.nebular071-universal-runtime-index.v1",
                      "version": builder.VERSION, "targets": targets}
    if raw_index != canonical(expected_index):
        _fail("INDEX")
    expected_provenance = {
        "schema": "rs9.nebular071-universal-package.v1", "builder_can_publish": False,
        "runtime_inputs_sha256": _sha(runtime_inputs), "runtime_inputs": inputs,
        "runtime_index_sha256": index_sha,
        "package_sources": {"launcher.py": _sha(launcher), "_fetch.py": _sha(fetcher)},
        "description_sha256": _sha(description),
    }
    if member(package + "/_rs9/provenance.json") != canonical(expected_provenance):
        _fail("PROVENANCE")
    return {
        "wheel": {"filename": builder.FILENAME, "tag": TAG, "version": builder.VERSION,
                  "size": len(raw), "sha256": _sha(raw)},
        "runtime_inputs": inputs, "runtime_inputs_sha256": _sha(runtime_inputs),
        "runtime_index_sha256": index_sha, "manifests": manifests,
        "publication_admitted": False,
    }


def capture_universal_runtime(snapshot: Mapping, raw_root: Path,
                             raw_target: Mapping, *, target: str,
                             product_capture=None, native_admission=None) -> dict:
    """Authenticate static inputs and derive product identity before host work."""
    from rs9 import nebular071_consumer_core as consumer

    if target not in builder.LAYOUTS or not isinstance(raw_target, Mapping):
        _fail("TARGET")
    product_source = authenticated_product_source(product_capture)
    root = Path(raw_root)
    spec = snapshot["runtime_inputs"]["targets"][target]
    release = snapshot["runtime_inputs"]["upstream_release"]
    payload, payload_sha = consumer._nebular_descriptor(root, raw_target.get("payload"), "payload")
    desc = raw_target["payload"]
    asset = spec["asset"]
    if (payload_sha != asset["sha256"] or len(payload) != asset["size"]
            or desc.get("name", desc.get("path")) != asset["name"]):
        _fail("ARCHIVE")
    raw_manifest, manifest_sha = consumer._nebular_descriptor(
        root, raw_target.get("manifest"), "manifest")
    manifest = snapshot["manifests"][target]
    members = strict_json(raw_manifest)
    if isinstance(members, Mapping):
        members = members.get("members")
    if (manifest_sha != spec["manifest_sha256"] or members != manifest["members"]):
        _fail("MANIFEST")
    record_bytes, record_sha = consumer._nebular_descriptor(root, raw_target.get("record"), "record")
    record = strict_json(record_bytes)
    if (not isinstance(record, Mapping) or record.get("schema") != "rs9.release-record.v1alpha1"
            or record.get("repository", {}).get("full_name") != release["repository"]
            or record.get("release", {}).get("tag") != release["tag"]
            or record.get("release", {}).get("draft") is not False
            or record.get("release", {}).get("prerelease") is not False
            or record.get("tag", {}).get("commit") != release["commit"]
            or record.get("tag", {}).get("tree") != release["tree"]):
        _fail("RELEASE")
    assets = [item for item in record.get("assets", []) if isinstance(item, Mapping)
              and item.get("github_asset_id") == asset["id"]]
    if (len(assets) != 1 or assets[0].get("role") != "payload"
            or assets[0].get("checksum_covered") is not True
            or any(assets[0].get(key) != asset[key] for key in ("name", "sha256", "size"))):
        _fail("RELEASE")
    provenance_bytes, provenance_sha = consumer._nebular_descriptor(
        root, raw_target.get("provenance"), "PROVENANCE")
    provenance = strict_json(provenance_bytes)
    if (not isinstance(provenance, Mapping)
            or provenance.get("schema") != "nebular.public-native-ci-release-provenance.v1"
            or provenance.get("repository") != release["repository"]
            or provenance.get("version") != builder.VERSION
            or provenance.get("releaseCommit") != release["commit"]
            or provenance.get("testedTree") != release["tree"]
            or provenance.get("release") != record["release"].get("id")):
        _fail("PROVENANCE")
    native_assets = [item for item in provenance.get("assets", []) if isinstance(item, Mapping)
                     and item.get("id") == asset["id"]]
    if (len(native_assets) != 1 or native_assets[0].get("role") != "raw-archive"
            or native_assets[0].get("unauthenticatedReadback") is not True
            or native_assets[0].get("httpStatus") != 200
            or native_assets[0].get("bytes") != asset["size"]
            or any(native_assets[0].get(key) != asset[key] for key in ("name", "sha256", "url"))):
        _fail("PROVENANCE")
    rows = raw_target.get("native_consumer")
    native = rows.get(target) if isinstance(rows, Mapping) else None
    if not isinstance(native, Mapping) or not isinstance(native.get("smoke_support"), Mapping):
        _fail("NATIVE_CONTRACT")
    release_join = join_product_native_release(
        product_capture, product_source, release, record, provenance,
        snapshot["runtime_inputs"]["product_native_reference"], asset,
        provenance_bytes=provenance_bytes,
        support=native["smoke_support"], native_admission=native_admission,
    )
    roles = consumer._nebular_native_role_paths(target, manifest)
    by_path = {item["path"]: item for item in manifest["members"]}
    executables = {}
    for role in ("gui", "launcher", "sidecar"):
        path = roles[role]
        item = by_path.get(path)
        if (not isinstance(item, Mapping) or item.get("type") != "file"
                or type(item.get("mode")) is not int or not item["mode"] & 0o111):
            _fail("EXECUTABLE")
        executable = {**item, "status": "verified", "executable": True, "label": role}
        consumer._nebular_payload_member(root, payload, executable)
        executables[role] = executable
    if (spec["shell_target"] != roles["launcher"] or spec["gui_target"] != roles["gui"]):
        _fail("EXECUTABLE")
    gui = executables["gui"]
    gui.update(smoke_path=roles["smoke_gui"], runtime_path=roles["smoke_gui"],
               materialized_path=roles["materialized_gui"])
    static = None
    if target.startswith("linux"):
        native, static = consumer._nebular_static_system_native(
            native, target=target, manifest=manifest,
            payload_digest=payload_sha, manifest_digest=manifest_sha)
    expected = consumer._NEBULAR_NATIVE_RC_SCENARIOS[target]["raw-archive"]
    protocol = native.get("user_state_protocol")
    if (native.get("command") != "tfnf" or native.get("protocol") != "nebular.native-rc-smoke"
            or native.get("platform") != consumer._NEBULAR_NATIVE_RC_PLATFORMS[target]
            or native.get("scenario") != expected
            or native.get("argv") != ["--nebular-release-smoke=" + expected]
            or type(native.get("timeout_seconds")) is not int
            or not 1 <= native["timeout_seconds"] <= 60
            or not isinstance(native.get("state_paths"), list)
            or any(not isinstance(item, str) for item in native["state_paths"])
            or not isinstance(protocol, Mapping)
            or protocol.get("schema") != "nebular.native-rc-persistent-user-state-v1"
            or protocol.get("method") != "native-rc-smoke.persistentStateLocations+snapshotLocations"
            or protocol.get("scope") != "real-user-state"):
        _fail("NATIVE_CONTRACT")
    native_evidence = None
    if target == "darwin-arm64":
        loader, provider = native.get("loader"), native.get("provider_closure")
        if (not isinstance(loader, Mapping) or not isinstance(provider, Mapping)
                or loader.get("path") != executables["launcher"]["path"]
                or loader.get("sha256") != executables["launcher"]["sha256"]
                or loader.get("status") != "verified"
                or provider.get("target") != target or provider.get("emulated") is True
                or provider.get("mode") != "host-observed"):
            _fail("NATIVE_CONTRACT")
        native_evidence = consumer._nebular_native_evidence(
            root, native, target=target, fixture_only=False,
            loader=loader, provider=provider, gui=gui, sidecar=executables["sidecar"])
    return {
        "root": root, "manifest": manifest, "manifest_sha256": manifest_sha,
        "payload_sha256": payload_sha, "native": dict(native), "gui": gui,
        "system_static_input": static, "native_evidence": native_evidence,
        "release_record_sha256": record_sha, "provenance_sha256": provenance_sha,
        "product_capture": product_capture,
        "product_source": product_source,
        "release_join": release_join,
    }


def materialize_universal_handoff(descriptor: Mapping, output: Path, *, target: str,
                                  repository: Path, inrun_root: Path,
                                  product_capture=None, native_admission=None) -> dict:
    """Stage the maintained static input closure without a three-wheel candidate.

    Descriptor-only evidence paths are validated before normalization. This
    supplies input bytes only; it produces no consumer or qualification proof.
    """
    import json
    import os
    import shutil
    from rs9 import tf_pypi_nebular071_publish as owner
    from rs9 import nebular071_consumer_core as consumer
    from rs9.nebular071_smoke_support import validate_smoke_support

    if target not in builder.LAYOUTS:
        _fail("TARGET")
    checked = owner.validate_qualification_inputs_descriptor(
        descriptor, repository=repository, phase=owner.QUALIFICATION_INPUT_PHASE_PREP,
        inrun_root=inrun_root, product_capture=product_capture)
    from rs9.nebular071_product_native import replay_descriptor_native, require_native_admission, reference
    if native_admission is None:
        native_admission = replay_descriptor_native(checked, inrun_root, product_capture)
    require_native_admission(native_admission, product_capture, reference())
    artifact_root = owner._resolve_inrun_artifact_root(
        Path(repository), checked.get("manylinux"), inrun_root,
        system_webkit_spec=checked.get("system_webkit"))
    source = owner._resolve_repo_contained_dir(
        artifact_root, checked["raw_release"]["source_root"],
        symlink_code="RAW_RELEASE_SYMLINK", missing_code="RAW_RELEASE_HANDOFF_PENDING",
        containment_code="QUALIFICATION_INPUTS_RAW_RELEASE")
    evidence_source = owner._resolve_repo_contained_dir(
        artifact_root, checked["evidence"]["source_root"],
        symlink_code="RAW_RELEASE_SYMLINK", missing_code="RAW_RELEASE_HANDOFF_PENDING",
        containment_code="QUALIFICATION_INPUTS_EVIDENCE")
    output = Path(output)
    owner._check_no_symlinks(output, "RAW_RELEASE_SYMLINK")
    if output.exists() or output.is_symlink() or not output.parent.is_dir():
        _fail("HANDOFF_OUTPUT")
    output.mkdir(mode=0o700)
    owned_output = output.lstat()

    def stage(entry, destination=None, *, origin=None):
        row = owner._validate_file_digest_entry(entry, code="RAW_RELEASE_HANDOFF_SCHEMA")
        data, _digest = consumer._nebular_descriptor(source if origin is None else origin, row, "raw-input")
        relative = destination or row.get("path", row.get("name"))
        from rs9.materialize import validate_safe_relative_posix_path
        validate_safe_relative_posix_path(relative)
        path = output / relative
        path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        owner._check_no_symlinks(path.parent, "RAW_RELEASE_SYMLINK")
        if path.exists() or path.is_symlink():
            _fail("HANDOFF_OUTPUT")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
        if builder._read(path, len(data))[0] != data:
            _fail("HANDOFF_OUTPUT")
        return dict(row)

    try:
        row = json.loads(canonical(checked["raw_release"]["targets"][target]))
        native = row["native_consumer"][target]
        if target == "darwin-arm64":
            stage(native["qualification"])
            for channel in ("raw-archive", "npm-package"):
                for key in ("run", "receipt"):
                    stage(native["smoke"][channel][key])
        support = validate_smoke_support(
            native["smoke_support"], target,
            evidence_files=checked["evidence"]["files"], descriptor=True)
        normalized = dict(support)
        normalized["files"] = []
        for item in support["files"]:
            stage({"path": item["evidence_path"], "size": item["size"], "sha256": item["sha256"]},
                  support["root"] + "/" + item["path"], origin=evidence_source)
            normalized["files"].append({key: item[key] for key in ("path", "size", "sha256", "blob", "role")})
        normalized["source_binding"] = {}
        for kind, item in support["source_binding"].items():
            stage({"path": item["evidence_path"], "size": item["size"], "sha256": item["sha256"]},
                  support["root"] + "/" + item["path"], origin=evidence_source)
            normalized["source_binding"][kind] = {key: item[key] for key in ("path", "size", "sha256")}
        native["smoke_support"] = normalized
        for key in ("record", "payload", "manifest", "provenance"):
            stage(row[key])
        # The pure launcher retains the packaging repository's legal files.
        # The separately downloaded native payload retains its own licenses
        # and notices. The old platform-wheel README/legal staging is unused.
        row.pop("readme", None)
        row.pop("legal_files", None)
        return {**row, "root": str(output)}
    except BaseException:
        try:
            current = output.lstat()
            if (current.st_dev, current.st_ino) == (owned_output.st_dev, owned_output.st_ino):
                shutil.rmtree(output, ignore_errors=True)
        except OSError:
            pass
        raise


def install_runtime_for_consumer(*, spec: Mapping, target: str, command: Path,
                                 python: Path, env: Mapping, work: Path,
                                 prefix: tuple, runner) -> dict:
    """Observe cold refusal, explicit setup, and verified reuse without network."""
    import os
    import stat
    from rs9.nebular071_consumer_core import _nebular_run

    asset = spec["asset"]
    cache = Path(env["XDG_CACHE_HOME"]) / "rs9/theme-forge-nebular-fusion"
    archive = cache / "archives" / (asset["sha256"] + ".tgz")

    def clean(result, expected=0):
        if (result.get("exit_code") != expected or result.get("timed_out")
                or result.get("output_limit_exceeded") or result.get("forced_cleanup")
                or result.get("cleanup_known") is not True
                or result.get("output_complete") is not True):
            _fail("RUNTIME_SETUP")

    def receipt(result, downloaded):
        clean(result)
        token = result.get("stdout_token")
        if (not isinstance(token, str) or len(token) > 65536
                or result.get("stdout_sha256") != _sha(token.encode())):
            _fail("RUNTIME_SETUP")
        value = strict_json(token.encode())
        expected = {
            "schema": "theme-forge-nebular-fusion.runtime-install.v1",
            "version": builder.VERSION, "target": target,
            "archive_sha256": asset["sha256"], "archive_bytes": asset["size"],
            "manifest_sha256": spec["manifest_sha256"], "downloaded": downloaded,
            "redirect_hosts": ["release-assets.githubusercontent.com"] if downloaded else [],
        }
        if value != expected or type(value.get("downloaded")) is not bool:
            _fail("RUNTIME_SETUP")

    def archive_identity():
        data, identity = builder._read(archive, asset["size"])
        info = archive.lstat()
        if (len(data) != asset["size"] or _sha(data) != asset["sha256"]
                or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != os.geteuid() or builder._identity(info) != identity):
            _fail("RUNTIME_ARCHIVE")
        return identity

    if cache.exists() or cache.is_symlink():
        _fail("RUNTIME_COLD_CACHE")
    missing = _nebular_run([command], env, work, prefix, 30, runner=runner)
    clean(missing, expected=1)
    if (not missing.get("stderr_token", "").startswith("TFNF_RUNTIME_MISSING:")
            or "Traceback" in missing.get("stderr_token", "")
            or cache.exists() or cache.is_symlink()):
        _fail("RUNTIME_COLD_CACHE")
    # Only this explicit command runs with network access. The product still
    # authenticates its fixed HTTPS source, exact size, hash and member table.
    setup = _nebular_run([command, "install-runtime", "--json"], env, work, (), 60, runner=runner)
    receipt(setup, True)
    before = archive_identity()
    offline = _nebular_run([command, "install-runtime", "--json"], env, work, prefix, 30, runner=runner)
    receipt(offline, False)
    if archive_identity() != before:
        _fail("RUNTIME_ARCHIVE")

    def summary(result):
        return _public_process(result)

    return {
        "schema": "rs9.nebular071-universal-runtime-setup.v1", "status": "passed",
        "target": target, "archive_sha256": asset["sha256"], "archive_bytes": asset["size"],
        "manifest_sha256": spec["manifest_sha256"],
        "cold_refusal": summary(missing), "explicit_setup": summary(setup),
        "offline_reuse": summary(offline), "archive_unchanged": True,
        "publication_admitted": False,
    }


def consume_universal_wheel(
    wheel_path: Path, runtime_inputs: bytes, description: bytes,
    handoff: Mapping, work: Path, *, target: str, source: Mapping,
    run_id: str, run_attempt: str, repository: Path, consumer_host_role: str = "newer",
    offline_pip_bootstrap: Mapping | None = None, product_capture=None, native_admission=None,
) -> dict:
    """Run the real installed launcher using the established native guard core.

    The public workflow must still bind this result to actual run APIs and all
    five required native lanes. An individual receipt cannot authorize upload.
    """
    import functools
    import os
    import re
    from rs9 import nebular071_consumer_core as consumer
    from rs9 import tf_pypi_nebular071_publish as owner
    from rs9.nebular071_installed_smoke import validate_installed_smoke_summary

    if (os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("GITHUB_REPOSITORY") != "Knowledge-Forge-AI/release-starport-9"
            or os.environ.get("GITHUB_REF") != "refs/heads/main"
            or os.environ.get("GITHUB_RUN_ID") != run_id
            or os.environ.get("GITHUB_RUN_ATTEMPT") != run_attempt
            or run_attempt != "1" or not re.fullmatch(r"[1-9][0-9]*", run_id)
            or not isinstance(source, Mapping) or set(source) != {"commit", "tree"}
            or any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{40}", value)
                   for value in source.values())
            or os.environ.get("GITHUB_SHA") != source["commit"]
            or consumer_host_role not in {"floor", "newer"}
            or target not in builder.LAYOUTS
            or (target == "darwin-arm64" and consumer_host_role != "newer")):
        _fail("HOSTED_CONTEXT")
    actual = {"commit": owner._git_output(repository, ["rev-parse", "HEAD"], "HOSTED_COMMIT"),
              "tree": owner._git_output(repository, ["rev-parse", "HEAD^{tree}"], "HOSTED_COMMIT")}
    if actual != dict(source):
        _fail("SOURCE")
    wheel_path = Path(wheel_path)
    if wheel_path.name != builder.FILENAME:
        _fail("WHEEL")
    raw = builder._read(wheel_path, MAX_WHEEL_BYTES)[0]
    snapshot = inspect_universal_wheel(raw, runtime_inputs, repository=repository, description=description)
    capture = capture_universal_runtime(
        snapshot, Path(handoff["root"]), handoff, target=target,
        product_capture=product_capture, native_admission=native_admission,
    )
    host_identity = consumer._nebular_identity_observed(None, target, False)
    host, extras, context = None, None, None
    if target.startswith("linux"):
        from rs9.nebular071_host_observation import observe_host
        from rs9.nebular071_system_webkit import observe_provider
        host, extras = observe_host(consumer_host_role)
        context = {
            "target": target, "wheel_sha256": snapshot["wheel"]["sha256"], "wheel_tag": TAG,
            "payload_archive_sha256": capture["payload_sha256"],
            "payload_manifest_sha256": capture["manifest_sha256"],
            "source": dict(source), "run_id": run_id, "run_attempt": run_attempt,
            "host": {"identity": host["identity"], "role": consumer_host_role,
                     "class": "bookworm-floor" if consumer_host_role == "floor" else "ubuntu-newer"},
            "provider": observe_provider(target), "distribution": DISTRIBUTION,
        }
    installed = consumer._nebular_installed_consumer(
        capture, wheel_path, Path(work), target=target,
        pip_source=consumer._nebular_offline_pip_input(offline_pip_bootstrap, target),
        sandbox_prefix=owner.default_sandbox_prefix(target),
        real_user_state_snapshot=owner.make_real_user_state_snapshotter(target),
        system_context=context,
        runtime_setup=functools.partial(
            install_runtime_for_consumer,
            spec=snapshot["runtime_inputs"]["targets"][target], target=target),
    )
    application = validate_installed_smoke_summary(
        installed.get("application_smoke"), target=target,
        authenticated_gui=capture["gui"], distribution=DISTRIBUTION)
    if (installed.get("runtime_setup", {}).get("schema") !=
            "rs9.nebular071-universal-runtime-setup.v1"
            or installed["runtime_setup"].get("status") != "passed"):
        _fail("RUNTIME_SETUP")
    installed["probes"]["version"] = _public_process(installed["probes"]["version"])
    path_probe = installed["probes"]["path"]
    installed["probes"]["path"] = {
        **_public_process(path_probe),
        "resolved_relative": path_probe["resolved_relative"],
        "resolved_sha256": path_probe["resolved_sha256"],
    }
    unsigned = {
        "schema": "rs9.nebular071-universal-native-consumer.v1", "distribution": DISTRIBUTION,
        "status": "passed", "target": target, "consumer_host_role": consumer_host_role,
        "source": dict(source), "run": {"id": run_id, "attempt": run_attempt},
        "wheel": snapshot["wheel"], "runtime_inputs_sha256": snapshot["runtime_inputs_sha256"],
        "runtime_index_sha256": snapshot["runtime_index_sha256"],
        "payload_sha256": capture["payload_sha256"], "manifest_sha256": capture["manifest_sha256"],
        "release_record_sha256": capture["release_record_sha256"],
        "provenance_sha256": capture["provenance_sha256"],
        "host_identity": host_identity, "host_observation": host, "host_extras": extras,
        "gui": capture["gui"], **installed, "application_smoke": application,
        "native_qualified": True, "fixture_only": False,
        "publication_admitted": False, "public_writes": 0,
    }
    result = {**unsigned, "identity": _sha(canonical(unsigned))}
    return validate_universal_consumer(
        result, snapshot, capture, target=target, role=consumer_host_role,
        source=source, run_id=run_id, run_attempt=run_attempt)


def validate_universal_consumer(value: Mapping, snapshot: Mapping, capture: Mapping,
                                *, target: str, role: str, source: Mapping,
                                run_id: str, run_attempt: str) -> dict:
    """Read back a universal receipt in its own source/run/distribution domain."""
    import re
    from rs9 import nebular071_consumer_core as consumer
    from rs9.nebular071_installed_smoke import (
        validate_installed_smoke_summary, validate_system_webkit_preflight,
    )

    required = {
        "schema", "distribution", "status", "target", "consumer_host_role", "source", "run",
        "wheel", "runtime_inputs_sha256", "runtime_index_sha256", "payload_sha256", "manifest_sha256",
        "release_record_sha256", "provenance_sha256", "host_identity", "host_observation", "host_extras",
        "gui", "sandbox", "process_observer", "user_state", "probes", "cleanup", "application_smoke",
        "runtime_setup", "native_qualified", "fixture_only", "publication_admitted", "public_writes", "identity",
    }
    if (not isinstance(value, Mapping) or set(value) != required
            or value.get("schema") != "rs9.nebular071-universal-native-consumer.v1"
            or value.get("distribution") != DISTRIBUTION or value.get("status") != "passed"
            or value.get("target") != target or target not in builder.LAYOUTS
            or role not in {"floor", "newer"} or value.get("consumer_host_role") != role
            or (target == "darwin-arm64" and role != "newer")
            or value.get("source") != dict(source)
            or value.get("run") != {"id": run_id, "attempt": run_attempt}
            or run_attempt != "1" or not re.fullmatch(r"[1-9][0-9]*", run_id)
            or value.get("native_qualified") is not True or value.get("fixture_only") is not False
            or value.get("publication_admitted") is not False or type(value.get("public_writes")) is not int
            or value["public_writes"] != 0 or value.get("wheel") != snapshot["wheel"]
            or value["wheel"].get("tag") != TAG):
        _fail("CONSUMER")
    unsigned = dict(value)
    identity = unsigned.pop("identity")
    if identity != _sha(canonical(unsigned)):
        _fail("CONSUMER_IDENTITY")
    for key in ("runtime_inputs_sha256", "runtime_index_sha256"):
        if value[key] != snapshot[key]:
            _fail("CONSUMER_BINDING")
    for key in ("payload_sha256", "manifest_sha256", "release_record_sha256", "provenance_sha256"):
        if value[key] != capture[key]:
            _fail("CONSUMER_BINDING")
    if value["gui"] != capture["gui"]:
        _fail("CONSUMER_BINDING")
    host = value["host_identity"]
    machines = {"arm64", "aarch64"} if target != "linux-x64-gnu" else {"x86_64", "amd64"}
    if (not isinstance(host, Mapping) or set(host) != {"source", "system", "machine"}
            or host.get("source") != "runner" or host.get("machine") not in machines
            or host.get("system") != consumer.NEBULAR071_TARGET_SYSTEMS[target]):
        _fail("HOSTED_CONTEXT")
    sandbox = value["sandbox"]
    if (not isinstance(sandbox, Mapping) or set(sandbox) != {"network_disabled", "method"}
            or sandbox.get("network_disabled") is not True
            or sandbox.get("method") != "explicit-isolation-prefix"):
        _fail("SANDBOX")
    observations = value["process_observer"]
    if (not isinstance(observations, Mapping) or observations.get("orphan_count") != 0
            or not isinstance(observations.get("after"), Mapping)
            or observations["after"].get("orphan_count") != 0):
        _fail("ORPHANS")
    states = value["user_state"]
    if not isinstance(states, Mapping) or states.get("unchanged") is not True:
        _fail("USER_STATE")
    for kind in ("scratch", "real_user_state"):
        state = states.get(kind)
        if not isinstance(state, Mapping) or state.get("unchanged") is not True:
            _fail("USER_STATE")
        if kind == "scratch":
            if (not isinstance(state.get("before"), Mapping)
                    or not isinstance(state.get("after"), Mapping)
                    or state.get("before") != state.get("after")):
                _fail("USER_STATE")
        else:
            before = consumer._nebular_real_user_state(state.get("before"), target=target, phase="before")
            after = consumer._nebular_real_user_state(state.get("after"), target=target, phase="after")
            if before["snapshot_sha256"] != after["snapshot_sha256"]:
                _fail("USER_STATE")
    if value["cleanup"] != {"pip_uninstall_exit": 0, "orphan_processes": 0}:
        _fail("CLEANUP")

    def clean(process, expected=0, *, path=False):
        required_process = PROCESS_FIELDS | ({"resolved_relative", "resolved_sha256"} if path else set())
        if (not isinstance(process, Mapping) or set(process) != required_process
                or type(process.get("exit_code")) is not int
                or process.get("exit_code") != expected or process.get("signal") is not None
                or process.get("timed_out") is not False or process.get("output_limit_exceeded") is not False
                or process.get("cleanup_known") is not True or process.get("output_complete") is not True
                or process.get("forced_cleanup") is not False
                or any(not isinstance(process.get(key), str) or not re.fullmatch(r"[0-9a-f]{64}", process[key])
                       for key in ("stdout_sha256", "stderr_sha256"))):
            _fail("PROCESS")

    probes = value["probes"]
    if not isinstance(probes, Mapping) or set(probes) != {"version", "path", "native"}:
        _fail("PROCESS")
    clean(probes["version"])
    clean(probes["path"], path=True)
    if (probes["version"]["stdout_sha256"] != _sha(b"theme-forge-nebular-fusion 0.7.1\n")
            or probes["path"].get("resolved_sha256") != capture["gui"]["sha256"]
            or probes["path"].get("resolved_relative") != (
                ".cache/rs9/theme-forge-nebular-fusion/entries/" + capture["manifest_sha256"]
                + "/payload/" + capture["gui"]["materialized_path"])):
        _fail("COMMAND_CONTRACT")
    app = validate_installed_smoke_summary(
        value["application_smoke"], target=target, authenticated_gui=capture["gui"],
        distribution=DISTRIBUTION)
    if probes["native"] != app["native_probe"]:
        _fail("NATIVE_CONTRACT")
    setup = value["runtime_setup"]
    spec = snapshot["runtime_inputs"]["targets"][target]
    setup_keys = {"schema", "status", "target", "archive_sha256", "archive_bytes", "manifest_sha256",
                  "cold_refusal", "explicit_setup", "offline_reuse", "archive_unchanged", "publication_admitted"}
    if (not isinstance(setup, Mapping) or set(setup) != setup_keys
            or setup.get("schema") != "rs9.nebular071-universal-runtime-setup.v1"
            or setup.get("status") != "passed" or setup.get("target") != target
            or setup.get("archive_sha256") != spec["asset"]["sha256"]
            or setup.get("archive_bytes") != spec["asset"]["size"]
            or setup.get("manifest_sha256") != spec["manifest_sha256"]
            or setup.get("archive_unchanged") is not True or setup.get("publication_admitted") is not False):
        _fail("RUNTIME_SETUP")
    clean(setup["cold_refusal"], 1)
    clean(setup["explicit_setup"])
    clean(setup["offline_reuse"])
    if target.startswith("linux"):
        from rs9.nebular071_host_observation import validate_observation_body, _validate_extras
        body = validate_observation_body(value["host_observation"])
        _validate_extras(value["host_extras"], body)
        if body["role"] != role or value["host_extras"]["target"] != target:
            _fail("HOSTED_CONTEXT")
        validate_system_webkit_preflight(
            app.get("system_webkit_preflight"), target=target, distribution=DISTRIBUTION,
            wheel_sha256=snapshot["wheel"]["sha256"], wheel_tag=TAG,
            payload_archive_sha256=capture["payload_sha256"], payload_manifest_sha256=capture["manifest_sha256"],
            source=source, run_id=run_id, run_attempt=run_attempt,
            host_observation_identity=body["identity"])
    elif value["host_observation"] is not None or value["host_extras"] is not None:
        _fail("HOSTED_CONTEXT")
    return dict(value)
