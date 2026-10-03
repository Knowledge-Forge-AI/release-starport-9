"""Deterministic authentication over captured bytes, never over a verdict string."""
import base64
import hashlib
import json
import re
import struct
import os
import stat
from pathlib import Path

from rs9.archives import inspect_archive
from rs9.errors import ContractError
from rs9.fetch import EVIDENCE_NAMES, SOURCE_EVIDENCE
from rs9.scratch import canonical, physical_directory
from rs9.security import validate_safe_relative_posix_path, validate_ecosystem_name, scan_for_credentials
from rs9.spdx import validate_spdx_expression

HEX = re.compile(r"[0-9a-f]{40}\Z")
SHA256 = re.compile(r"sha256:([0-9a-f]{64})\Z")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read_evidence(root, relative, limit=16 * 1024 * 1024):
    validate_safe_relative_posix_path(relative)
    root = physical_directory(root)
    current = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parts = relative.split("/")
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
            os.close(current)
            current = child
        descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=current)
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
                raise ContractError("MISSING_EVIDENCE", "Required bounded regular evidence file is unavailable")
            data = stream.read(limit + 1)
            if len(data) > limit:
                raise ContractError("MISSING_EVIDENCE", "Evidence exceeds size limit")
            return data
    except OSError:
        raise ContractError("MISSING_EVIDENCE", "Required physical evidence file is unavailable") from None
    finally:
        os.close(current)


def json_evidence(root, relative):
    try:
        return json.loads(read_evidence(root, relative))
    except (ValueError, UnicodeError):
        raise ContractError("INVALID_EVIDENCE", "Malformed captured JSON") from None


def checksum_entries(data):
    entries = {}
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeError:
        raise ContractError("CHECKSUM_FORMAT", "Checksum evidence must be UTF-8") from None
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64})  ([^\r\n]+)", line)
        if not match:
            raise ContractError("CHECKSUM_FORMAT", "Strict SHA256SUMS syntax required")
        sha, name = match.groups()
        validate_safe_relative_posix_path(name)
        if name in entries:
            raise ContractError("DUPLICATE_CHECKSUM", "Duplicate checksum entry")
        entries[name] = sha
    return entries


def png_size(data):
    if (len(data) < 33 or data[:8] != b"\x89PNG\r\n\x1a\n" or data[8:16] != b"\0\0\0\rIHDR"):
        raise ContractError("INVALID_ICON", "A PNG IHDR is required")
    width, height = struct.unpack_from(">II", data, 16)
    if width != height or width not in (16, 22, 24, 32, 48, 64, 96, 128, 256, 512):
        raise ContractError("INVALID_ICON", "Icon must be square at a supported hicolor size")
    return width


class AuthenticatedInputs:
    """In-process evidence result. JSON records alone cannot authorize acceptance.

    Rendering always produces a deferred shadow candidate. Fresh TLS collection,
    tenant license reconciliation and installation qualification are additional
    external gates; this offline result does not manufacture those assurances.
    """

    def __init__(self, normalized, record, archives, source, manifests):
        self.normalized = normalized
        self.record = record
        self.archives = archives
        self.source = source
        self.manifests = manifests


def authenticate(normalized, evidence):
    try:
        return _authenticate(normalized, evidence)
    except (KeyError, TypeError, ValueError, IndexError, AttributeError):
        raise ContractError("INVALID_EVIDENCE", "Captured evidence does not satisfy the ingestion schema") from None


def _authenticate(normalized, evidence):
    root = physical_directory(evidence)
    repository = json_evidence(root, "api/repository.json")
    release = json_evidence(root, "api/release.json")
    ref = json_evidence(root, "api/ref.json")
    tags = json_evidence(root, "api/tags.json")
    commit = json_evidence(root, "api/commit.json")
    tree = json_evidence(root, "api/tree.json")
    if repository.get("full_name") != normalized["project"]["repository"] or type(repository.get("id")) is not int:
        raise ContractError("REPOSITORY_MISMATCH", "Selected repository identity disagrees")
    if release.get("tag_name") != normalized["tag"] or ref.get("ref") != "refs/tags/" + normalized["tag"]:
        raise ContractError("TAG_MISMATCH", "Selected release/tag identity disagrees")
    if type(release.get("id")) is not int or release["id"] <= 0:
        raise ContractError("INVALID_EVIDENCE", "A positive release identity is required")
    if release.get("draft") is not False or type(release.get("prerelease")) is not bool:
        raise ContractError("RELEASE_STATE", "Draft or malformed release state")
    if release["prerelease"] and normalized["release"]["prerelease"] != "allow":
        raise ContractError("PRERELEASE_REJECTED", "Tenant rejects prereleases")
    obj = ref.get("object", {})
    tag_chain = []
    if not isinstance(tags, list) or len(tags) > 8:
        raise ContractError("TAG_TARGET", "Invalid tag dereference evidence")
    for item in tags:
        if obj.get("type") != "tag" or obj.get("sha") != item.get("sha"):
            raise ContractError("TAG_TARGET", "Annotated tag evidence disagrees")
        tag_chain.append(item["sha"])
        obj = item.get("object", {})
    if obj.get("type") != "commit" or not HEX.fullmatch(obj.get("sha", "")) or commit.get("sha") != obj["sha"]:
        raise ContractError("TAG_TARGET", "Tag commit evidence disagrees")
    target = release.get("target_commitish", "")
    if HEX.fullmatch(target) and target != obj["sha"]:
        raise ContractError("RELEASE_TARGET", "Release target differs from tag commit")
    tree_sha = commit.get("tree", {}).get("sha", "")
    if not HEX.fullmatch(tree_sha) or tree.get("sha") != tree_sha:
        raise ContractError("TREE_MISMATCH", "Source tree evidence disagrees")
    if tree.get("truncated") is not False:
        raise ContractError("TRUNCATED_TREE", "Truncated tree cannot bind source files")
    blobs = {}
    for entry in tree.get("tree", []):
        path = entry.get("path", "")
        validate_safe_relative_posix_path(path)
        if path in blobs:
            raise ContractError("TREE_MISMATCH", "Duplicate source tree path")
        blobs[path] = entry
    source, source_records = {}, []
    paths = set(SOURCE_EVIDENCE) | set(normalized["license"]["files"])
    if "desktop" in normalized:
        paths.add(normalized["desktop"]["icon"]["path"])
    for path in sorted(paths):
        data = read_evidence(root, "source/" + path)
        entry = blobs.get(path, {})
        blob = hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()
        if entry.get("type") != "blob" or entry.get("mode") not in ("100644", "100755") or entry.get("sha") != blob:
            raise ContractError("SOURCE_BLOB_MISMATCH", "Tagged source bytes differ from tree blob")
        source[path] = data
        source_records.append({"path": path, "blob": blob, "sha256": digest(data), "size": len(data)})
    all_assets = release.get("assets", [])
    if not isinstance(all_assets, list):
        raise ContractError("INVALID_EVIDENCE", "Release assets must be a list")
    metadata, payloads = {}, {}
    required = [a["name"] for a in normalized["assets"]] + list(EVIDENCE_NAMES)
    wrappers = [a.get("name", "") for a in all_assets if a.get("name", "").endswith(".tgz")
                and "linux" not in a["name"] and "darwin" not in a["name"]]
    if len(wrappers) != 1:
        raise ContractError("NPM_IDENTITY", "Unique GitHub-attached npm wrapper evidence required")
    required += wrappers
    for name in required:
        matches = [a for a in all_assets if a.get("name") == name]
        if not matches:
            raise ContractError("MISSING_ASSET", "Required raw or evidence asset missing")
        if len(matches) != 1:
            raise ContractError("DUPLICATE_ASSET", "Required asset name is ambiguous")
        asset = matches[0]
        match = SHA256.fullmatch(asset.get("digest") or "")
        if asset.get("state") != "uploaded" or type(asset.get("id")) is not int or not match:
            raise ContractError("ASSET_METADATA", "Uploaded asset identity and GitHub digest required")
        data = read_evidence(root, "assets/" + name, limit=1024 ** 3)
        if type(asset.get("size")) is not int or len(data) != asset["size"]:
            raise ContractError("SIZE_MISMATCH", "Captured asset size differs")
        if digest(data) != match[1]:
            raise ContractError("DIGEST_MISMATCH", "Captured asset digest differs from GitHub")
        metadata[name] = {"name": name, "github_asset_id": asset["id"], "size": len(data), "sha256": digest(data)}
        if name in EVIDENCE_NAMES or name in wrappers:
            payloads[name] = data
    sums = checksum_entries(payloads["SHA256SUMS"])
    for name, asset in metadata.items():
        if name != "SHA256SUMS" and sums.get(name) != asset["sha256"]:
            raise ContractError("CHECKSUM_MISMATCH", "SHA256SUMS does not independently agree")
    archives, manifests, inputs, license_copies = {}, {}, [], []
    for asset in sorted(normalized["assets"], key=lambda a: a["id"]):
        if asset["format"] != "tar.gz":
            raise ContractError("UNSUPPORTED_ARCHIVE", "Shadow supports raw tar.gz inputs only")
        path = root / "assets" / asset["name"]
        copies = {}
        archive_root = next(iter(asset["commands"].values())).split("/")[0]
        license_base = archive_root + ("/Contents/Resources/" if archive_root.endswith(".app") else "/")

        def capture(name, data, mode):
            for license_path in normalized["license"]["files"]:
                if name == license_base + license_path:
                    copies[name] = data

        command_paths = {**asset["commands"], **{"launcher:" + k: v for k, v in asset.get("launchers", {}).items()}}
        manifest = inspect_archive(path, command_paths, on_file=capture)
        if len(copies) != len(normalized["license"]["files"]):
            raise ContractError("PAYLOAD_LICENSE_MISSING", "Payload project license copies are required")
        for name, data in sorted(copies.items()):
            declared = name[len(license_base):]
            if data != source[declared]:
                raise ContractError("PAYLOAD_LICENSE_MISMATCH", "Archive license differs from tagged authority")
            license_copies.append({"asset": asset["id"], "path": name, "source": declared, "sha256": digest(data)})
        archives[asset["id"]] = path
        manifests[asset["id"]] = manifest
        inputs.append({**metadata[asset["name"]], "id": asset["id"], "platforms": asset["platforms"],
                       "root": manifest["root"], "commands": {k: v for k, v in manifest["commands"].items() if not k.startswith("launcher:")},
                       "launchers": {k[9:]: v for k, v in manifest["commands"].items() if k.startswith("launcher:")},
                       "payload_manifest_sha256": manifest["manifest_sha256"], "member_count": len(manifest["members"])})
    try:
        provenance = json.loads(payloads["PROVENANCE.json"])
    except (ValueError, UnicodeError):
        raise ContractError("INVALID_EVIDENCE", "Invalid provenance JSON") from None
    # Publisher assertions are consistency evidence, not signatures or attestations.
    assertions = provenance.get("release", {})
    for key, expected in {"repository": repository["full_name"], "tag": normalized["tag"],
                          "tagTarget": obj["sha"], "mergedMainTree": tree_sha}.items():
        if key in assertions and assertions[key] != expected:
            raise ContractError("PROVENANCE_MISMATCH", "Publisher lineage assertion disagrees")
    for candidate in provenance.get("candidates", []):
        raw = candidate.get("raw", {})
        matching = [a for a in inputs if a["name"] == raw.get("name")]
        if matching:
            asset = matching[0]
            if raw.get("sha256") != asset["sha256"] or raw.get("size") != asset["size"]:
                raise ContractError("PROVENANCE_MISMATCH", "Publisher raw asset assertion disagrees")
            hashes = {c["sha256"] for c in asset["commands"].values()}
            if candidate.get("executableSha256") not in hashes:
                raise ContractError("PROVENANCE_MISMATCH", "Publisher executable assertion disagrees")
    for item in provenance.get("assets", []):
        if isinstance(item, dict) and item.get("name") in metadata and item.get("sha256") != metadata[item["name"]]["sha256"]:
            raise ContractError("PROVENANCE_MISMATCH", "Publisher asset assertion disagrees")
    declarations = []
    try:
        tagged_package = json.loads(source["package.json"])
        validate_ecosystem_name("npm", tagged_package["name"])
        declarations.append({"source": "tagged:package.json", "expression": tagged_package["license"]})
        import tomllib
        cargo = tomllib.loads(source["src-tauri/Cargo.toml"].decode("utf-8"))
        declarations.append({"source": "tagged:src-tauri/Cargo.toml", "expression": cargo["package"]["license"]})
        for path in ("NOTICE", "COMMERCIAL-LICENSE.md"):
            text = source[path].decode("utf-8")
            declared = sorted(set(re.findall(r"\bAGPL-3\.0-(?:or-later|only)\b", text)))
            method = "explicit-expression"
            if not declared and "GNU Affero General Public License v3.0 or later" in text:
                declared = ["AGPL-3.0-or-later"]
                method = "explicit-version-and-later-prose"
            if not declared:
                raise ContractError("LICENSE_EVIDENCE", "Nebular profile requires explicit tagged AGPL notice declarations")
            declarations.extend({"source": "tagged:" + path, "expression": expression, "method": method} for expression in declared)
        npm = json_evidence(root, "npm/metadata.json")
        if npm.get("version") != normalized["version"] or npm.get("name") != tagged_package.get("name"):
            raise ContractError("NPM_IDENTITY", "Published npm supporting evidence identity differs")
        declarations.append({"source": "npm-registry:version-metadata", "expression": npm["license"]})
        npm_bytes = read_evidence(root, "npm/package.tgz", limit=32 * 1024 * 1024)
        if npm_bytes != payloads[wrappers[0]]:
            raise ContractError("NPM_RELEASE_MISMATCH", "Published wrapper differs from GitHub release attachment")
        integrity = npm["dist"]["integrity"]
        expected = "sha512-" + base64.b64encode(hashlib.sha512(npm_bytes).digest()).decode("ascii")
        if integrity != expected:
            raise ContractError("NPM_INTEGRITY", "Published npm bytes disagree with integrity")
        packaged = {}

        def capture_npm(path, data, mode):
            if path in ("package/package.json", "package/LICENSE", "package/NOTICE", "package/COMMERCIAL-LICENSE.md"):
                packaged[path] = data

        npm_manifest = inspect_archive(root / "npm/package.tgz", {}, on_file=capture_npm,
                                       max_members=2000, max_member_bytes=4 * 1024 * 1024, max_total_bytes=64 * 1024 * 1024)
        if npm_manifest["root"] != "package" or "package/package.json" not in packaged:
            raise ContractError("NPM_IDENTITY", "Unique regular npm package metadata required")
        package = json.loads(packaged["package/package.json"])
        if package.get("name") != npm["name"] or package.get("version") != normalized["version"]:
            raise ContractError("NPM_IDENTITY", "Published package bytes identity differs")
        declarations.append({"source": "npm-artifact:package/package.json", "expression": package["license"]})
        spdx = json.loads(payloads["nebular.spdx.json"])
        for item in spdx.get("packages", []):
            if item.get("name") in (tagged_package["name"], normalized["project"]["id"]) and item.get("versionInfo") == normalized["version"]:
                declarations.append({"source": "release:nebular.spdx.json:root", "expression": item.get("licenseDeclared", "NOASSERTION")})
    except (KeyError, ValueError, UnicodeError):
        raise ContractError("LICENSE_EVIDENCE", "Required tagged/published license evidence malformed") from None
    for declaration in declarations:
        scan_for_credentials(declaration["expression"])
        validate_spdx_expression(declaration["expression"])
    license_status = "consistent" if all(d["expression"] == normalized["license"]["expression"] for d in declarations) else "conflict"
    icon = None
    if "desktop" in normalized:
        selected = normalized["desktop"]["icon"]["path"]
        icon = {"authority": "tagged-repository", "path": selected, "size": png_size(source[selected]),
                "sha256": digest(source[selected]), "commit": obj["sha"]}
    record = {"schema": "rs9.ingestion.v1alpha1", "repository": {"full_name": repository["full_name"], "id": repository["id"]},
              "release": {"id": release["id"], "tag": normalized["tag"], "draft": False, "prerelease": release["prerelease"]},
              "tag": {"commit": obj["sha"], "tree": tree_sha, "tag_objects": tag_chain,
                      "target_basis": "sha-match" if HEX.fullmatch(target) else "tag-ref"},
              "assets": inputs, "evidence_assets": [metadata[n] for n in sorted((*EVIDENCE_NAMES, *wrappers))],
              "source_files": source_records, "payload_license_copies": license_copies,
              "license": {"status": license_status, "declarations": declarations, "comparison": "exact-string; SPDX list membership unvalidated"},
              "npm_support": {"name": npm["name"], "version": npm["version"], "sha256": digest(npm_bytes),
                              "release_asset": wrappers[0], "integrity_agrees": True,
                              "payload_manifest_sha256": npm_manifest["manifest_sha256"],
                              "legal_files": [{"path": p, "sha256": digest(b)} for p, b in sorted(packaged.items()) if p != "package/package.json"]},
              "icon": icon, "limits": ["Captured API identity relies on trusted TLS collection; offline records cannot prove freshness.",
                                         "Publisher provenance is self-asserted; signatures and attestations not evaluated.",
                                         "No package acceptance or tenant license decision is implied."]}
    return AuthenticatedInputs(normalized, record, archives, source, manifests)
