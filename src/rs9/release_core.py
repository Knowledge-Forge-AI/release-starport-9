"""Generic, bounded captured-byte release ingestion; no tenant evidence policy."""
import hashlib
import json
import os
import re
import stat
from urllib.parse import quote

from rs9.command_policies import inspect_selected_archive, validate_command_policy
from rs9.errors import ContractError
from rs9.github import PublicClient
from rs9.releases import safe_tag
from rs9.scratch import ConfinedWriter, canonical, physical_directory
from rs9.security import validate_repository, validate_safe_basename, validate_safe_relative_posix_path, validate_slug

HEX = re.compile(r"[0-9a-f]{40}\Z")
SHA256 = re.compile(r"sha256:([0-9a-f]{64})\Z")
DEFAULT_LIMITS = {"asset_bytes": 1024 ** 3, "capture_bytes": 2 * 1024 ** 3,
                  "source_bytes": 16 * 1024 ** 2, "members": 20000,
                  "member_bytes": 256 * 1024 ** 2, "archive_bytes": 1024 ** 3,
                  "ratio": 1000}
_CAPTURE_PROOF = object()


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
            raise ContractError("CHECKSUM_FORMAT", "Strict checksum syntax required")
        sha, name = match.groups()
        validate_safe_relative_posix_path(name)
        if name in entries:
            raise ContractError("DUPLICATE_CHECKSUM", "Duplicate checksum entry")
        entries[name] = sha
    return entries


def validate_selection(selection):
    if not isinstance(selection, dict) or set(selection) - {"schema", "repository", "tag", "prerelease", "payload_assets", "evidence_assets", "checksums", "source_paths", "limits"}:
        raise ContractError("INVALID_SELECTION", "Closed release selection required")
    if selection.get("schema") != "rs9.release-selection.v1alpha1":
        raise ContractError("INVALID_SELECTION", "Versioned release selection required")
    validate_repository(selection.get("repository"))
    safe_tag(selection.get("tag"))
    if selection.get("prerelease") not in ("allow", "reject"):
        raise ContractError("INVALID_SELECTION", "Explicit prerelease policy required")
    validate_safe_basename(selection.get("checksums"))
    names, identities = {selection["checksums"]}, set()
    for kind in ("payload_assets", "evidence_assets"):
        rows = selection.get(kind)
        if not isinstance(rows, list) or len(rows) > 256 or (kind == "payload_assets" and not rows):
            raise ContractError("INVALID_SELECTION", "Explicit asset selections required")
        for row in rows:
            allowed = {"id", "name", "format", "commands", "launchers", "platforms", "checksum_covered", "command_policy"} if kind == "payload_assets" else {"role", "name", "checksum_covered"}
            if not isinstance(row, dict) or set(row) - allowed:
                raise ContractError("INVALID_SELECTION", "Closed selected asset required")
            validate_safe_basename(row.get("name"))
            identity = row.get("id" if kind == "payload_assets" else "role")
            validate_slug(identity)
            if row["name"] in names or (kind, identity) in identities:
                raise ContractError("INVALID_SELECTION", "Unique asset names and identities required")
            names.add(row["name"])
            identities.add((kind, identity))
            if type(row.get("checksum_covered", True)) is not bool:
                raise ContractError("INVALID_SELECTION", "Checksum coverage must be explicit boolean")
            if kind == "payload_assets":
                validate_command_policy(row)
                if row.get("format") != "tar.gz":
                    raise ContractError("UNSUPPORTED_ARCHIVE", "Bounded tar.gz inputs required")
                for field in ("commands", "launchers"):
                    if not isinstance(row.get(field, {}), dict):
                        raise ContractError("INVALID_SELECTION", "Command mappings required")
                    for key, path in row.get(field, {}).items():
                        validate_slug(key)
                        validate_safe_relative_posix_path(path)
                if not isinstance(row.get("platforms", []), list):
                    raise ContractError("INVALID_SELECTION", "Platform list required")
                for platform in row.get("platforms", []):
                    if not isinstance(platform, str) or not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,127}", platform):
                        raise ContractError("INVALID_SELECTION", "Bounded platform identity required")
    paths = selection.get("source_paths")
    if not isinstance(paths, list) or len(paths) > 256 or any(not isinstance(path, str) for path in paths) or len(set(paths)) != len(paths):
        raise ContractError("INVALID_SELECTION", "Unique source paths required")
    for path in paths:
        validate_safe_relative_posix_path(path)
    limits = selection.get("limits", {})
    if not isinstance(limits, dict) or set(limits) - set(DEFAULT_LIMITS):
        raise ContractError("INVALID_SELECTION", "Closed byte limits required")
    for name, value in limits.items():
        if type(value) is not int or not 0 < value <= DEFAULT_LIMITS[name]:
            raise ContractError("INVALID_SELECTION", "Limits may only narrow core bounds")
    return {**DEFAULT_LIMITS, **limits}


def _selected(selection):
    return [*selection["payload_assets"], *selection["evidence_assets"],
            {"name": selection["checksums"], "role": "checksums", "checksum_covered": False}]


def capture_release(selection, output, *, client=None):
    """Public transport capture only; authenticate_release checks the exact bytes."""
    limits = validate_selection(selection)
    client = client or PublicClient()
    repository, tag = selection["repository"], selection["tag"]
    base = "https://api.github.com/repos/" + repository
    repo = client.json(base, no_redirect=True)
    if repo.get("full_name") != repository:
        raise ContractError("REPOSITORY_MISMATCH", "Selected repository identity disagrees")
    ref = client.json(base + "/git/ref/tags/" + quote(tag, safe=""))
    obj, tags, seen = ref["object"], [], set()
    while obj["type"] == "tag":
        if len(tags) == 8 or obj["sha"] in seen:
            raise ContractError("TAG_LIMIT", "Annotated tag depth or cycle exceeded")
        seen.add(obj["sha"])
        item = client.json(base + "/git/tags/" + obj["sha"])
        tags.append(item)
        obj = item["object"]
    if obj["type"] != "commit" or not HEX.fullmatch(obj["sha"]):
        raise ContractError("TAG_TARGET", "Release tag does not resolve to a commit")
    commit = client.json(base + "/git/commits/" + obj["sha"])
    tree = client.json(base + "/git/trees/" + commit["tree"]["sha"] + "?recursive=1")
    if tree.get("truncated") is not False:
        raise ContractError("TRUNCATED_TREE", "Full tagged tree evidence is required")
    release = client.json(base + "/releases/tags/" + quote(tag, safe=""))
    total = 0
    with ConfinedWriter(output) as writer:
        for name, value in {"repository": repo, "ref": ref, "tags": tags, "commit": commit,
                            "tree": tree, "release": release}.items():
            writer.write("api/" + name + ".json", canonical(value))
        for selected in sorted(_selected(selection), key=lambda row: row["name"]):
            name = selected["name"]
            matches = [a for a in release["assets"] if a["name"] == name]
            if len(matches) != 1:
                raise ContractError("ASSET_COUNT", "Required release asset must exist exactly once")
            asset = matches[0]
            if type(asset["size"]) is not int or not 0 < asset["size"] <= limits["asset_bytes"]:
                raise ContractError("FETCH_LIMIT", "Invalid release asset size")
            expected = "https://github.com/" + repository + "/releases/download/" + quote(tag, safe="") + "/" + quote(name, safe="")
            if asset["browser_download_url"] != expected:
                raise ContractError("ASSET_AUTHORITY", "Asset URL differs from selected authority")
            total += asset["size"]
            if total > limits["capture_bytes"]:
                raise ContractError("FETCH_LIMIT", "Aggregate capture bound exceeded")
            writer.write("assets/" + name, client.get(expected, limit=limits["asset_bytes"], expected_size=asset["size"]))
        for path in sorted(selection["source_paths"]):
            data = client.get("https://raw.githubusercontent.com/" + repository + "/" + obj["sha"] + "/" + quote(path, safe="/"), limit=limits["source_bytes"])
            total += len(data)
            if total > limits["capture_bytes"]:
                raise ContractError("FETCH_LIMIT", "Aggregate capture bound exceeded")
            writer.write("source/" + path, data)
        writer.write("fetch-receipt.json", canonical({"schema": "rs9.fetch-receipt.v1alpha1",
                     "selection_sha256": digest(canonical(selection)), "requests": client.receipts}))
    return output


class ReleaseCapture:
    """In-process byte evidence. Persisted JSON is an audit record, not a capability."""
    def __init__(self, record, archives, source, manifests, asset_metadata, evidence_bytes, root, *, _proof=None):
        self.record, self.archives, self.source = record, archives, source
        self.manifests, self.asset_metadata = manifests, asset_metadata
        self.evidence_bytes, self.root = evidence_bytes, root
        self._proof = _proof
        self._record_hash = digest(canonical(record))
        self._profile_results = set()


def authenticated_record_hash(capture):
    if not isinstance(capture, ReleaseCapture) or capture._proof is not _CAPTURE_PROOF:
        raise ContractError("RELEASE_CAPTURE", "Fresh in-process byte authentication required")
    if digest(canonical(capture.record)) != capture._record_hash:
        raise ContractError("INPUT_CHANGED", "Release record changed after authentication")
    source_records = {row["path"]: row for row in capture.record["source_files"]}
    if set(capture.source) != set(source_records) or any(
        not isinstance(data, bytes) or len(data) != source_records[path]["size"]
        or digest(data) != source_records[path]["sha256"] for path, data in capture.source.items()
    ):
        raise ContractError("INPUT_CHANGED", "Authenticated tagged source bytes changed")
    return capture._record_hash


def authenticated_tree(capture):
    """Configuration authority requires the tree authenticated with the capture."""
    authenticated_record_hash(capture)
    tree = json_evidence(capture.root, "api/tree.json")
    if digest(canonical(tree)) != capture.__dict__.get("_tree_hash"):
        raise ContractError("INPUT_CHANGED", "Captured tagged tree changed after authentication")
    return tree


def authenticated_release_metadata(capture):
    """Return the unchanged release metadata used to authenticate asset bytes."""
    authenticated_record_hash(capture)
    release = json_evidence(capture.root, "api/release.json")
    if digest(canonical(release)) != capture.__dict__.get("_release_metadata_hash"):
        raise ContractError("INPUT_CHANGED", "Captured release metadata changed after authentication")
    return release


def authenticate_release(selection, evidence):
    try:
        return _authenticate_release(selection, evidence)
    except (KeyError, TypeError, ValueError, IndexError, AttributeError):
        raise ContractError("INVALID_EVIDENCE", "Captured bytes do not satisfy the release schema") from None


def _authenticate_release(selection, evidence):
    limits = validate_selection(selection)
    root = physical_directory(evidence)
    repository = json_evidence(root, "api/repository.json")
    release = json_evidence(root, "api/release.json")
    ref = json_evidence(root, "api/ref.json")
    tags = json_evidence(root, "api/tags.json")
    commit = json_evidence(root, "api/commit.json")
    tree = json_evidence(root, "api/tree.json")
    if repository.get("full_name") != selection["repository"] or type(repository.get("id")) is not int or repository["id"] <= 0:
        raise ContractError("REPOSITORY_MISMATCH", "Selected repository identity disagrees")
    if release.get("tag_name") != selection["tag"] or ref.get("ref") != "refs/tags/" + selection["tag"]:
        raise ContractError("TAG_MISMATCH", "Selected release/tag identity disagrees")
    if type(release.get("id")) is not int or release["id"] <= 0:
        raise ContractError("INVALID_EVIDENCE", "Positive release identity required")
    if release.get("draft") is not False or type(release.get("prerelease")) is not bool:
        raise ContractError("RELEASE_STATE", "Draft or malformed release state")
    if release["prerelease"] and selection["prerelease"] != "allow":
        raise ContractError("PRERELEASE_REJECTED", "Selection rejects prereleases")
    obj, tag_chain = ref.get("object", {}), []
    if not isinstance(tags, list) or len(tags) > 8:
        raise ContractError("TAG_TARGET", "Invalid tag dereference evidence")
    for item in tags:
        if obj.get("type") != "tag" or obj.get("sha") != item.get("sha") or not HEX.fullmatch(item.get("sha", "")) or item["sha"] in tag_chain:
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
    source, source_records, total = {}, [], 0
    for path in sorted(selection["source_paths"]):
        data = read_evidence(root, "source/" + path, limits["source_bytes"])
        entry = blobs.get(path, {})
        blob = hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()
        if entry.get("type") != "blob" or entry.get("mode") not in ("100644", "100755") or entry.get("sha") != blob:
            raise ContractError("SOURCE_BLOB_MISMATCH", "Tagged source bytes differ from tree blob")
        source[path] = data
        total += len(data)
        source_records.append({"path": path, "blob": blob, "sha256": digest(data), "size": len(data)})
    all_assets = release.get("assets", [])
    if not isinstance(all_assets, list):
        raise ContractError("INVALID_EVIDENCE", "Release assets must be a list")
    metadata, payloads, records = {}, {}, []
    for selected in sorted(_selected(selection), key=lambda row: row["name"]):
        name = selected["name"]
        matches = [a for a in all_assets if a.get("name") == name]
        if not matches:
            raise ContractError("MISSING_ASSET", "Required raw or evidence asset missing")
        if len(matches) != 1:
            raise ContractError("DUPLICATE_ASSET", "Required asset name is ambiguous")
        asset = matches[0]
        match = SHA256.fullmatch(asset.get("digest") or "")
        if asset.get("state") != "uploaded" or type(asset.get("id")) is not int or asset["id"] <= 0 or not match:
            raise ContractError("ASSET_METADATA", "Uploaded asset identity and digest required")
        data = read_evidence(root, "assets/" + name, limit=limits["asset_bytes"])
        if type(asset.get("size")) is not int or len(data) != asset["size"]:
            raise ContractError("SIZE_MISMATCH", "Captured asset size differs")
        if digest(data) != match[1]:
            raise ContractError("DIGEST_MISMATCH", "Captured asset digest differs")
        total += len(data)
        if total > limits["capture_bytes"]:
            raise ContractError("FETCH_LIMIT", "Aggregate capture bound exceeded")
        metadata[name] = {"name": name, "github_asset_id": asset["id"], "size": len(data), "sha256": digest(data)}
        records.append({**metadata[name], "role": selected.get("role", "payload"),
                        "checksum_covered": selected.get("checksum_covered", True)})
        if "role" in selected:
            payloads[name] = data
    sums = checksum_entries(payloads[selection["checksums"]])
    for selected in _selected(selection):
        name = selected["name"]
        if selected.get("checksum_covered", True) and sums.get(name) != metadata[name]["sha256"]:
            raise ContractError("CHECKSUM_MISMATCH", "Configured checksums do not independently agree")
        if name in sums and sums[name] != metadata[name]["sha256"]:
            raise ContractError("CHECKSUM_MISMATCH", "Present checksum disagrees even without required coverage")
    archives, manifests, inputs = {}, {}, []
    for asset in sorted(selection["payload_assets"], key=lambda row: row["id"]):
        path = root / "assets" / asset["name"]
        policy = validate_command_policy(asset)
        try:
            manifest = inspect_selected_archive(path, asset, limits)
        except ContractError as error:
            raise error.with_details(asset=asset["id"]) from None
        archives[asset["id"]], manifests[asset["id"]] = path, manifest
        inputs.append({**metadata[asset["name"]], "id": asset["id"], "platforms": sorted(asset.get("platforms", [])),
                       "command_policy": policy,
                       "root": manifest["root"], "commands": {k: v for k, v in manifest["commands"].items() if not k.startswith("launcher:")},
                       "launchers": {k[9:]: v for k, v in manifest["commands"].items() if k.startswith("launcher:")},
                       "payload_manifest_sha256": manifest["manifest_sha256"], "member_count": len(manifest["members"])})
    record = {"schema": "rs9.release-record.v1alpha1", "selection_sha256": digest(canonical(selection)),
              "repository": {"full_name": repository["full_name"], "id": repository["id"]},
              "release": {"id": release["id"], "tag": selection["tag"], "draft": False, "prerelease": release["prerelease"]},
              "tag": {"commit": obj["sha"], "tree": tree_sha, "tag_objects": tag_chain,
                      "target_basis": "sha-match" if HEX.fullmatch(target) else "tag-ref"},
              "assets": records, "payloads": inputs, "source_files": source_records, "limits": limits}
    # Immutable release times are meaningful; volatile fetch times live in the receipt.
    for key in ("created_at", "published_at"):
        if release.get(key) is not None:
            from datetime import datetime
            value = release[key]
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
                raise ContractError("INVALID_EVIDENCE", "Release timestamp must be UTC")
            record.setdefault("source_times", {})[key] = value
    capture = ReleaseCapture(record, archives, source, manifests, metadata, payloads, root, _proof=_CAPTURE_PROOF)
    capture._tree_hash = digest(canonical(tree))
    capture._release_metadata_hash = digest(canonical(release))
    return capture
