"""Closed versioned RS9-owned evidence profiles, selected explicitly by intent."""
import base64
import hashlib
import json
import re
import struct
from urllib.parse import quote

from rs9.archives import inspect_archive
from rs9.errors import ContractError
from rs9.release_core import ReleaseCapture, digest, read_evidence, json_evidence, authenticated_record_hash
from rs9.scratch import ConfinedWriter, canonical, physical_directory
from rs9.security import validate_ecosystem_name, scan_for_credentials, validate_safe_relative_posix_path
from rs9.spdx import validate_spdx_expression

TAURI_PROFILE = "tauri-desktop-archive.v1alpha1"
PACKAGE_PROFILE = "npm-package-archive.v1alpha1"
TAURI_SOURCES = ("LICENSE", "NOTICE", "COMMERCIAL-LICENSE.md", "package.json",
                 "src-tauri/Cargo.toml", "src-tauri/tauri.conf.json")
PROFILE_ROLES = {TAURI_PROFILE: {"provenance", "sbom-spdx", "third-party-notices", "npm-wrapper"},
                 PACKAGE_PROFILE: {"provenance", "notice"}}


def png_size(data):
    if len(data) < 33 or data[:8] != b"\x89PNG\r\n\x1a\n" or data[8:16] != b"\0\0\0\rIHDR":
        raise ContractError("INVALID_ICON", "A PNG IHDR is required")
    width, height = struct.unpack_from(">II", data, 16)
    if width != height or width not in (16, 22, 24, 32, 48, 64, 96, 128, 256, 512):
        raise ContractError("INVALID_ICON", "Icon must be square at a supported hicolor size")
    return width


def evidence_policy(normalized):
    evidence = normalized.get("release", {}).get("evidence")
    if not isinstance(evidence, dict):
        raise ContractError("EVIDENCE_PROFILE_REQUIRED", "Explicit versioned evidence profile required for authentication")
    profile = evidence.get("profile")
    if profile not in PROFILE_ROLES:
        raise ContractError("EVIDENCE_PROFILE", "Unknown RS9-owned evidence profile")
    roles = {row["role"]: row["name"] for row in evidence["assets"]}
    if len(roles) != len(evidence["assets"]) or set(roles) != PROFILE_ROLES[profile]:
        raise ContractError("EVIDENCE_ROLES", "Profile evidence roles must match exactly")
    return profile, evidence, roles


def selection_for_intent(normalized):
    profile, evidence, roles = evidence_policy(normalized)
    sources = set(TAURI_SOURCES if profile == TAURI_PROFILE else ("package.json",))
    sources.update(normalized.get("license", {}).get("files", []))
    if "desktop" in normalized:
        if profile != TAURI_PROFILE:
            raise ContractError("EVIDENCE_PROFILE", "Desktop evidence requires desktop profile")
        sources.add(normalized["desktop"]["icon"]["path"])
    return {"schema": "rs9.release-selection.v1alpha1", "repository": normalized["project"]["repository"],
            "tag": normalized["tag"], "prerelease": normalized["release"]["prerelease"],
            "payload_assets": normalized["assets"], "evidence_assets": evidence["assets"],
            "checksums": evidence["checksums"], "source_paths": sorted(sources)}


def capture_supplemental(normalized, output, client):
    profile, evidence, roles = evidence_policy(normalized)
    if profile != TAURI_PROFILE:
        return
    # This corroboration belongs solely to the desktop evidence profile.
    package = json_evidence(output, "source/package.json")["name"]
    validate_ecosystem_name("npm", package)
    metadata = client.json("https://registry.npmjs.org/" + quote(package, safe="") + "/" + quote(normalized["version"], safe=""))
    url = metadata["dist"]["tarball"]
    if not url.startswith("https://registry.npmjs.org/"):
        raise ContractError("NPM_IDENTITY", "Supplemental capture must use public registry authority")
    target = physical_directory(output) / "npm"
    try:
        target.mkdir()
    except OSError:
        raise ContractError("OUTPUT_CONFINEMENT", "Exclusive supplemental output required") from None
    with ConfinedWriter(target) as writer:
        writer.write("metadata.json", canonical(metadata))
        writer.write("package.tgz", client.get(url, limit=32 * 1024 * 1024))
        writer.write("profile-fetch-receipt.json", canonical({"schema": "rs9.profile-fetch-receipt.v1alpha1",
                     "profile": profile, "requests": client.receipts}))


def evaluate_profile(capture, profile, intent, *, roles=None):
    release_hash = authenticated_record_hash(capture)
    if profile not in PROFILE_ROLES:
        raise ContractError("EVIDENCE_PROFILE", "Unknown RS9-owned evidence profile")
    if roles is None:
        selected, evidence, roles = evidence_policy(intent)
        if selected != profile:
            raise ContractError("EVIDENCE_PROFILE", "Selected profile disagrees")
    if set(roles) != PROFILE_ROLES[profile]:
        raise ContractError("EVIDENCE_ROLES", "Profile evidence roles must match exactly")
    for role, name in roles.items():
        if not any(row["role"] == role and row["name"] == name for row in capture.record["assets"]):
            raise ContractError("EVIDENCE_ROLES", "Profile roles must bind selected authenticated assets")
    try:
        sections = _evaluate_tauri(capture, intent, roles) if profile == TAURI_PROFILE else _evaluate_package(capture, intent, roles)
    except (KeyError, TypeError, ValueError, UnicodeError, AttributeError):
        raise ContractError("INVALID_EVIDENCE", "Profile evidence does not satisfy its schema") from None
    result = {"schema": "rs9.evidence-profile-result.v1alpha1", "profile": profile,
              "release_record_sha256": release_hash, "intent_sha256": digest(canonical(intent)), "sections": sections}
    capture._profile_results.add(digest(canonical(result)))
    return result


def _evaluate_tauri(capture, normalized, roles):
    root, source, metadata, payloads = capture.root, capture.source, capture.asset_metadata, capture.evidence_bytes
    repository = capture.record["repository"]
    release = capture.record["release"]
    obj, tree_sha = {"sha": capture.record["tag"]["commit"]}, capture.record["tag"]["tree"]
    tag_chain = capture.record["tag"]["tag_objects"]
    EVIDENCE_NAMES = (normalized["release"]["evidence"]["checksums"], roles["provenance"], roles["sbom-spdx"], roles["third-party-notices"])
    wrappers = [roles["npm-wrapper"]]
    source_records = capture.record["source_files"]
    archives, manifests, inputs, license_copies = {}, {}, [], []
    for asset in sorted(normalized["assets"], key=lambda a: a["id"]):
        if asset["format"] != "tar.gz":
            raise ContractError("UNSUPPORTED_ARCHIVE", "Shadow supports raw tar.gz inputs only")
        path = root / "assets" / asset["name"]
        copies = {}
        archive_root = next(iter(asset["commands"].values())).split("/")[0]
        license_base = archive_root + ("/Contents/Resources/" if archive_root.endswith(".app") else "/")

        def capture_license(name, data, mode):
            for license_path in normalized["license"]["files"]:
                if name == license_base + license_path:
                    copies[name] = data

        command_paths = {**asset["commands"], **{"launcher:" + k: v for k, v in asset.get("launchers", {}).items()}}
        manifest = inspect_archive(path, command_paths, on_file=capture_license)
        if manifest != capture.manifests[asset["id"]]:
            raise ContractError("INPUT_CHANGED", "Archive changed after core authentication")
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
        provenance = json.loads(payloads[roles["provenance"]])
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
                raise ContractError("LICENSE_EVIDENCE", "Selected profile requires explicit tagged AGPL notice declarations")
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
        spdx = json.loads(payloads[roles["sbom-spdx"]])
        for item in spdx.get("packages", []):
            if item.get("name") in (tagged_package["name"], normalized["project"]["id"]) and item.get("versionInfo") == normalized["version"]:
                declarations.append({"source": "release:" + roles["sbom-spdx"] + ":root", "expression": item.get("licenseDeclared", "NOASSERTION")})
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
                      "target_basis": capture.record["tag"]["target_basis"]},
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
    return {"legacy_ingestion": record}


def _evaluate_package(capture, intent, roles):
    if len(capture.archives) != 1:
        raise ContractError("PACKAGE_IDENTITY", "Package profile selects exactly one payload")
    identity = next(iter(capture.archives))
    packaged = {}

    def visitor(path, data, mode):
        if path in ("package/package.json", "package/NOTICE", "package/LICENSE"):
            packaged[path] = data

    manifest = inspect_archive(capture.archives[identity], {}, on_file=visitor,
                               max_members=20000, max_member_bytes=4 * 1024 ** 2,
                               max_total_bytes=64 * 1024 ** 2)
    if manifest != capture.manifests[identity]:
        raise ContractError("INPUT_CHANGED", "Archive changed after core authentication")
    if manifest["root"] != "package" or "package/package.json" not in packaged:
        raise ContractError("PACKAGE_IDENTITY", "Single package root and regular metadata required")
    package = json.loads(packaged["package/package.json"])
    tagged = json.loads(capture.source["package.json"])
    validate_ecosystem_name("npm", package["name"])
    for key in ("name", "version"):
        if tagged.get(key) != package.get(key):
            raise ContractError("PACKAGE_IDENTITY", "Package and tagged metadata disagree")
    if package["version"] != intent["version"] or capture.record["release"]["tag"] != intent["tag"]:
        raise ContractError("PACKAGE_IDENTITY", "Package release identity disagrees")
    declarations = [{"source": "tagged:package.json", "expression": tagged["license"]},
                    {"source": "artifact:package/package.json", "expression": package["license"]}]
    for declaration in declarations:
        scan_for_credentials(declaration["expression"])
        validate_spdx_expression(declaration["expression"])
    bins = package.get("bin", {})
    if isinstance(bins, str):
        bins = {package["name"].rsplit("/", 1)[-1]: bins}
    if not isinstance(bins, dict):
        raise ContractError("PACKAGE_IDENTITY", "Package bin mapping must be declarative")
    members = {row["path"]: row for row in manifest["members"]}
    commands = []
    for name, target in sorted(bins.items()):
        validate_ecosystem_name("npm", name)
        if target.startswith("./"):
            target = target[2:]
        validate_safe_relative_posix_path(target)
        row = members.get("package/" + target, {})
        if row.get("type") != "file":
            raise ContractError("COMMAND_PATH", "Package bin must be a regular authenticated member")
        commands.append({"name": name, "path": row["path"], "sha256": row["sha256"]})
    provenance = json.loads(capture.evidence_bytes[roles["provenance"]])
    assertions = provenance.get("release", {})
    for key, expected in {"repository": capture.record["repository"]["full_name"], "tag": intent["tag"],
                          "tagTarget": capture.record["tag"]["commit"], "mergedMainTree": capture.record["tag"]["tree"]}.items():
        if key in assertions and assertions[key] != expected:
            raise ContractError("PROVENANCE_MISMATCH", "Publisher release assertion disagrees")
    notice = capture.evidence_bytes[roles["notice"]]
    notice.decode("utf-8")
    for supplied in (capture.source.get("NOTICE"), packaged.get("package/NOTICE")):
        if supplied is not None and supplied != notice:
            raise ContractError("NOTICE_MISMATCH", "Selected release, tagged and packaged notices disagree")
    for row in provenance.get("assets", []):
        if isinstance(row, dict) and row.get("name") in capture.asset_metadata:
            asset = capture.asset_metadata[row["name"]]
            if row.get("sha256") != asset["sha256"] or ("size" in row and row["size"] != asset["size"]):
                raise ContractError("PROVENANCE_MISMATCH", "Publisher selected asset assertion disagrees")
    return {"package": {"name": package["name"], "version": package["version"],
                        "payload_manifest_sha256": manifest["manifest_sha256"], "commands": commands},
            "license": {"status": "consistent" if tagged["license"] == package["license"] else "conflict",
                        "declarations": declarations, "comparison": "exact-string; no legal acceptance"},
            "notice_sha256": digest(notice), "provenance_sha256": digest(capture.evidence_bytes[roles["provenance"]]),
            "legal_files": [{"path": path, "sha256": digest(data)} for path, data in sorted(packaged.items()) if path != "package/package.json"]}
