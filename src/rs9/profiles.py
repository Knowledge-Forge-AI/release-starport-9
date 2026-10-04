"""Closed versioned RS9-owned evidence profiles, selected explicitly by intent."""
import base64
import hashlib
import json
import re
import struct

from rs9.archives import inspect_archive
from rs9.errors import ContractError
from rs9.release_core import ReleaseCapture, digest, read_evidence, json_evidence, authenticated_record_hash
from rs9.scratch import ConfinedWriter, canonical, physical_directory
from rs9.security import validate_ecosystem_name, scan_for_credentials, validate_safe_relative_posix_path
from rs9.spdx import validate_spdx_expression

TAURI_PROFILE = "tauri-desktop-archive.v1alpha1"
TAURI_AUTHORITY_PROFILE = "tauri-desktop-archive.v1alpha2"
PACKAGE_PROFILE = "npm-package-archive.v1alpha1"
TAURI_SOURCES = ("LICENSE", "NOTICE", "COMMERCIAL-LICENSE.md", "package.json",
                 "src-tauri/Cargo.toml", "src-tauri/tauri.conf.json")
PROFILE_ROLES = {TAURI_PROFILE: {"provenance", "sbom-spdx", "third-party-notices", "npm-wrapper"},
                 PACKAGE_PROFILE: {"provenance", "notice"}}
PROFILE_ROLES[TAURI_AUTHORITY_PROFILE] = PROFILE_ROLES[TAURI_PROFILE]


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


def selection_for_intent(normalized, *, include_configuration=False):
    profile, evidence, roles = evidence_policy(normalized)
    sources = set(TAURI_SOURCES if profile in {TAURI_PROFILE, TAURI_AUTHORITY_PROFILE} else ("package.json",))
    sources.update(normalized.get("license", {}).get("files", []))
    from rs9.constants import ALLOWED_PROJECT_FILES
    for row in normalized.get("evidence", {}).get("inputs", []) if include_configuration else ():
        if row.get("filename") in ALLOWED_PROJECT_FILES:
            sources.add(".rs9/" + row["filename"])
    if normalized.get("project", {}).get("id") == "theme-forge-stellar-burst":
        sources.add("package-lock.json")
    if "desktop" in normalized:
        if profile not in {TAURI_PROFILE, TAURI_AUTHORITY_PROFILE}:
            raise ContractError("EVIDENCE_PROFILE", "Desktop evidence requires desktop profile")
        sources.add(normalized["desktop"]["icon"]["path"])
    return {"schema": "rs9.release-selection.v1alpha1", "repository": normalized["project"]["repository"],
            "tag": normalized["tag"], "prerelease": normalized["release"]["prerelease"],
            "payload_assets": [{**asset, "command_policy": "npm-package-bin" if profile == PACKAGE_PROFILE else "native-executable"}
                               for asset in normalized["assets"]], "evidence_assets": evidence["assets"],
            "checksums": evidence["checksums"], "source_paths": sorted(sources)}


def _npm_packument_url(name):
    validate_ecosystem_name("npm", name)
    scan_for_credentials(name)
    return "https://registry.npmjs.org/" + name.replace("/", "%2F", 1)


def _npm_tarball_url(name, version):
    _npm_packument_url(name)
    number = r"(?:0|[1-9][0-9]*)"
    prerelease = r"(?:" + number + r"|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
    if (not isinstance(version, str) or len(version) > 128
            or not re.fullmatch(number + r"\." + number + r"\." + number
                                + r"(?:-" + prerelease + r"(?:\." + prerelease + r")*)?"
                                + r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?", version)):
        raise ContractError("NPM_IDENTITY", "Exact safe npm version required")
    return "https://registry.npmjs.org/" + name + "/-/" + name.rsplit("/", 1)[-1] + "-" + version + ".tgz"


def _npm_version(packument, name, version):
    if (not isinstance(packument, dict) or packument.get("name") != name
            or not isinstance(packument.get("versions"), dict)):
        raise ContractError("NPM_IDENTITY", "Malformed npm packument", details={"reason": "malformed-packument"})
    metadata = packument["versions"].get(version)
    if (not isinstance(metadata, dict) or metadata.get("name") != name or metadata.get("version") != version
            or not isinstance(metadata.get("dist"), dict)):
        raise ContractError("NPM_IDENTITY", "Exact npm version identity required", details={"reason": "exact-version"})
    dist = metadata["dist"]
    integrity = dist.get("integrity")
    try:
        valid_integrity = (isinstance(integrity, str) and integrity.startswith("sha512-")
                           and len(base64.b64decode(integrity[7:], validate=True)) == 64)
    except ValueError:
        valid_integrity = False
    if not valid_integrity or dist.get("tarball") != _npm_tarball_url(name, version):
        raise ContractError("NPM_IDENTITY", "Exact public npm distribution identity required", details={"reason": "npm-dist"})
    return metadata


def capture_supplemental(normalized, output, client, *, corroboration=None, core_authenticated=False):
    profile, evidence, roles = evidence_policy(normalized)
    if profile not in {TAURI_PROFILE, TAURI_AUTHORITY_PROFILE}:
        return
    # This corroboration belongs solely to the desktop evidence profile.
    tagged = json_evidence(output, "source/package.json")
    if not isinstance(tagged, dict) or not isinstance(tagged.get("name"), str):
        raise ContractError("NPM_IDENTITY", "Tagged npm name required")
    package, version = tagged["name"], normalized["version"]
    url = _npm_packument_url(package)
    tarball = _npm_tarball_url(package, version)
    receipt = corroboration if corroboration is not None else {}
    receipt.update(schema="rs9.npm-corroboration.v1alpha1", profile=profile,
                   release_authentication="core-authenticated" if core_authenticated else "captured-unverified",
                   npm_corroboration="pending", wrapper_bytes="pending", integrity="pending",
                   packument={"operation": "npm-packument", "url": url, "name": package,
                              "selected_version": version, "accept": "application/json", "status": "pending"},
                   tarball={"operation": "npm-tarball", "url": tarball, "accept": "*/*", "status": "pending"})
    target = physical_directory(output) / "npm"
    try:
        target.mkdir()
    except OSError:
        raise ContractError("OUTPUT_CONFINEMENT", "Exclusive supplemental output required") from None
    with ConfinedWriter(target) as writer:
        operation = "npm-packument"
        try:
            packument = client.json(url, request_class=operation, limit=16 * 1024 * 1024)
            receipt["packument"].update(status="fetched", http_status=200)
            for request in reversed(client.receipts):
                if request.get("url") == url and request.get("operation") == operation:
                    receipt["packument"].update({k: request[k] for k in ("size", "sha256")})
                    break
            metadata = _npm_version(packument, package, version)
            receipt["packument"]["status"] = "pass"
            writer.write("metadata.json", canonical(metadata))
            operation = "npm-tarball"
            body = client.get(tarball, request_class=operation, limit=32 * 1024 * 1024)
            writer.write("package.tgz", body)
            receipt["tarball"].update(status="pass", http_status=200, size=len(body), sha256=digest(body))
        except ContractError as error:
            receipt["npm_corroboration"] = "fail"
            receipt["packument" if operation == "npm-packument" else "tarball"]["status"] = "fail"
            receipt["error"] = error.code
            receipt["diagnostic"] = error.with_details(operation=operation, host="registry.npmjs.org").details
            raise error.with_details(operation=operation, host="registry.npmjs.org") from None
        finally:
            # Capture remains pending until the authenticated profile compares bytes.
            writer.write("profile-fetch-receipt.json", canonical(receipt))


def record_corroboration_failure(corroboration, error):
    """Keep npm evidence distinct from an unrelated required profile failure."""
    if corroboration is None:
        return
    state = corroboration.get("npm_corroboration", "pending")
    if error.code.startswith("NPM_"):
        state = "fail"
    elif state == "pending":
        state = "blocked"
    corroboration.update(npm_corroboration=state, error=error.code)


def evaluate_profile(capture, profile, intent, *, roles=None, corroboration=None):
    release_hash = authenticated_record_hash(capture)
    if profile not in PROFILE_ROLES:
        raise ContractError("EVIDENCE_PROFILE", "Unknown RS9-owned evidence profile")
    expected_policy = "npm-package-bin" if profile == PACKAGE_PROFILE else "native-executable"
    if any(p.get("command_policy", "native-executable") != expected_policy for p in capture.record["payloads"]):
        raise ContractError("EVIDENCE_PROFILE", "Profile and captured command execution policy disagree")
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
        sections = (_evaluate_tauri(capture, intent, roles, repository_authority=profile == TAURI_AUTHORITY_PROFILE,
                                   corroboration=corroboration)
                    if profile in {TAURI_PROFILE, TAURI_AUTHORITY_PROFILE} else _evaluate_package(capture, intent, roles))
    except ContractError as error:
        record_corroboration_failure(corroboration, error)
        raise
    except (KeyError, TypeError, ValueError, UnicodeError, AttributeError):
        error = ContractError("INVALID_EVIDENCE", "Profile evidence does not satisfy its schema")
        record_corroboration_failure(corroboration, error)
        raise error from None
    result = {"schema": "rs9.evidence-profile-result.v1alpha1", "profile": profile,
              "release_record_sha256": release_hash, "intent_sha256": digest(canonical(intent)), "sections": sections}
    capture._profile_results.add(digest(canonical(result)))
    if corroboration is not None:
        corroboration["npm_corroboration"] = "pass"
    return result


def _evaluate_tauri(capture, normalized, roles, *, repository_authority=False, corroboration=None):
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
                       # Preserve the legacy shadow record's path/hash projection;
                       # complete modes and sizes remain in the generic capture.
                       "root": manifest["root"], "commands": {k: {f: v[f] for f in ("path", "sha256")} for k, v in manifest["commands"].items() if not k.startswith("launcher:")},
                       "launchers": {k[9:]: {f: v[f] for f in ("path", "sha256")} for k, v in manifest["commands"].items() if k.startswith("launcher:")},
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
        if corroboration is not None:
            corroboration["release_wrapper"] = {"asset": wrappers[0], "sha256": digest(payloads[wrappers[0]])}
            corroboration["wrapper_bytes"] = "pass" if npm_bytes == payloads[wrappers[0]] else "fail"
        if npm_bytes != payloads[wrappers[0]]:
            raise ContractError("NPM_RELEASE_MISMATCH", "Published wrapper differs from GitHub release attachment")
        integrity = npm["dist"]["integrity"]
        expected = "sha512-" + base64.b64encode(hashlib.sha512(npm_bytes).digest()).decode("ascii")
        if corroboration is not None:
            corroboration["integrity"] = "pass" if integrity == expected else "fail"
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
        if corroboration is not None:
            corroboration["npm_corroboration"] = "pass"
        spdx = json.loads(payloads[roles["sbom-spdx"]])
        for item in spdx.get("packages", []):
            if item.get("name") in (tagged_package["name"], normalized["project"]["id"]) and item.get("versionInfo") == normalized["version"]:
                declarations.append({"source": "release:" + roles["sbom-spdx"] + ":root", "expression": item.get("licenseDeclared", "NOASSERTION")})
    except (KeyError, ValueError, UnicodeError):
        raise ContractError("LICENSE_EVIDENCE", "Required tagged/published license evidence malformed") from None
    for declaration in declarations:
        scan_for_credentials(declaration["expression"])
        validate_spdx_expression(declaration["expression"])
    authority = [d for d in declarations if d["source"].startswith("tagged:")]
    conflicts = [d for d in declarations if not d["source"].startswith("tagged:")
                 and d["expression"] != normalized["license"]["expression"]]
    license_status = "consistent" if all(d["expression"] == normalized["license"]["expression"] for d in (authority if repository_authority else declarations)) else "conflict"
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
              "license": {"status": license_status, "declarations": declarations,
                          **({"authority": "tagged-repository", "downstream_metadata_conflicts": conflicts,
                              "comparison": "tagged-authority; downstream conflicts retained"} if repository_authority
                             else {"comparison": "exact-string; SPDX list membership unvalidated"})},
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
        elif path in selected.get("commands", {}).values():
            packaged[path] = data[:257]

    selected = next(a for a in intent["assets"] if a["id"] == identity)
    manifest = inspect_archive(capture.archives[identity], selected.get("commands", {}), command_policy="npm-package-bin", on_file=visitor,
                               max_members=20000, max_member_bytes=4 * 1024 ** 2,
                               max_total_bytes=64 * 1024 ** 2)
    if manifest != capture.manifests[identity]:
        raise ContractError("INPUT_CHANGED", "Archive changed after core authentication")
    if manifest["root"] != "package" or "package/package.json" not in packaged:
        raise ContractError("PACKAGE_IDENTITY", "Single package root and regular metadata required")
    from rs9.npm_commands import authenticate_bins
    try:
        package, commands, undeclared_bins = authenticate_bins(manifest, packaged, selected.get("commands", {}))
    except ContractError as error:
        raise error.with_details(asset=identity) from None
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
                        "payload_manifest_sha256": manifest["manifest_sha256"], "commands": commands,
                        "undeclared_bins": undeclared_bins},
            "license": {"status": "consistent" if tagged["license"] == package["license"] else "conflict",
                        "declarations": declarations, "comparison": "exact-string; no legal acceptance"},
            "notice_sha256": digest(notice), "provenance_sha256": digest(capture.evidence_bytes[roles["provenance"]]),
            "legal_files": [{"path": path, "sha256": digest(data)} for path, data in sorted(packaged.items())
                            if path in {"package/LICENSE", "package/NOTICE"}]}
