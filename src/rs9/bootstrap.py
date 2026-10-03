"""One-time RS9-owned configuration for exact authenticated pre-RS9 releases."""
import json
from pathlib import Path

from rs9.errors import ContractError
from rs9.records import closed, record_sha256, snapshot, validate_sha256
from rs9.release_core import authenticated_record_hash, authenticated_tree, digest
from rs9.security import validate_safe_relative_posix_path, validate_slug
from rs9.scratch import physical_directory

_BOOTSTRAP_PROOF = object()


def checked_bootstrap_configurations(manifest_path, *, approved_manifests):
    """Check every configuration before it can select a URL or output path."""
    path = Path(manifest_path)
    root = physical_directory(path.parent)
    if path.is_symlink() or path.stat().st_size > 512 * 1024:
        raise ContractError("BOOTSTRAP_MANIFEST", "Bounded physical manifest required")
    raw = path.read_bytes()
    if digest(raw) not in approved_manifests:
        raise ContractError("BOOTSTRAP_APPROVAL", "Exact reviewed bootstrap bytes must be allowlisted")
    manifest = json.loads(raw)
    closed(manifest, {"schema", "bootstrap-pre-rs9", "release-contains-rs9", "scope", "future-releases", "projects"})
    if (manifest["schema"] != "rs9.bootstrap-tenant-manifest.v1alpha1"
            or manifest["bootstrap-pre-rs9"] is not True or manifest["release-contains-rs9"] is not False
            or manifest["scope"] != "exact-generation" or manifest["future-releases"] != "forbidden"):
        raise ContractError("BOOTSTRAP_SCOPE", "Only an explicit one-time pre-RS9 exception is valid")
    if not isinstance(manifest["projects"], list) or not 1 <= len(manifest["projects"]) <= 64:
        raise ContractError("BOOTSTRAP_SCOPE", "Bounded nonempty generation required")
    results, identities, directories, projects = [], set(), set(), set()
    from rs9.profiles import selection_for_intent
    from rs9.release_core import validate_selection
    for row in manifest["projects"]:
        validate_safe_relative_posix_path(row["configuration"])
        validate_sha256(row["config_sha256"])
        directory = root / row["configuration"]
        if record_sha256(configuration_inventory(directory)) != row["config_sha256"]:
            raise ContractError("BOOTSTRAP_CONFIG", "Bootstrap configuration hash disagrees")
        intent = json.loads((directory / "intent.json").read_bytes())
        validate_slug(intent["project"]["id"])
        if (intent["version"] != row["version"] or intent["tag"] != row["tag"]
                or intent["project"]["repository"] != row["repository"]):
            raise ContractError("BOOTSTRAP_BINDING", "Configuration identity differs from exception")
        validate_selection(selection_for_intent(intent))
        identity = (row["repository"], row["tag"])
        if identity in identities or row["configuration"] in directories or intent["project"]["id"] in projects:
            raise ContractError("BOOTSTRAP_BINDING", "Unique generation identities required")
        identities.add(identity)
        directories.add(row["configuration"])
        projects.add(intent["project"]["id"])
        results.append((snapshot(row), snapshot(intent)))
    return results


def configuration_inventory(directory):
    root = physical_directory(directory)
    rows = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ContractError("BOOTSTRAP_SYMLINK", "Bootstrap configuration cannot contain links")
        if path.is_file():
            if path.stat().st_size > 512 * 1024:
                raise ContractError("BOOTSTRAP_LIMIT", "Configuration exceeds bounded text size")
            path.read_bytes().decode("utf-8")
            rows.append({"path": path.relative_to(root).as_posix(), "sha256": digest(path.read_bytes())})
    if not rows:
        raise ContractError("BOOTSTRAP_CONFIG", "Nonempty configuration inventory required")
    return rows


def load_bootstrap(manifest_path, capture, *, approved_manifests):
    authenticated_record_hash(capture)
    path = Path(manifest_path)
    configurations = checked_bootstrap_configurations(path, approved_manifests=approved_manifests)
    record = capture.record
    bindings = {"repository": record["repository"]["full_name"], "repository_id": record["repository"]["id"],
                "tag": record["release"]["tag"], "release_id": record["release"]["id"],
                "tag_commit": record["tag"]["commit"], "tag_tree": record["tag"]["tree"]}
    matches = [(row, intent) for row, intent in configurations if all(row.get(k) == v for k, v in bindings.items())]
    if len(matches) != 1:
        raise ContractError("BOOTSTRAP_BINDING", "Release does not match exactly one reviewed bootstrap binding")
    row, intent = matches[0]
    tree = authenticated_tree(capture)
    if any(e["path"] == ".rs9" or e["path"].startswith(".rs9/") for e in tree["tree"]):
        raise ContractError("BOOTSTRAP_AUTHORITY", "Release-owned configuration takes precedence; exception refused")
    from rs9.profiles import selection_for_intent
    if record_sha256(selection_for_intent(intent)) != record["selection_sha256"]:
        raise ContractError("BOOTSTRAP_BINDING", "Configuration differs from authenticated selection")
    capture._bootstrap_authority = (_BOOTSTRAP_PROOF, record_sha256(intent), path, digest(path.read_bytes()))
    return snapshot(intent)


def require_release_configuration(capture):
    """Future ingestion has no ambient/example/bootstrap configuration fallback."""
    authenticated_record_hash(capture)
    tree = authenticated_tree(capture)
    paths = {e["path"] for e in tree["tree"] if e["type"] == "blob" and e["path"].startswith(".rs9/")}
    required = {".rs9/project.toml", ".rs9/releases.toml"}
    if not required <= paths or not paths <= set(capture.source):
        raise ContractError("RELEASE_CONFIG_REQUIRED", "Capture all project-owned tagged .rs9 configuration before ingestion")
    return {path: capture.source[path] for path in sorted(paths)}


def require_configuration_authority(capture, intent):
    """Publication accepts release-owned config or a fresh exact exception capability."""
    authority = capture.__dict__.get("_bootstrap_authority")
    if authority and authority[0] is _BOOTSTRAP_PROOF and authority[1] == record_sha256(intent):
        loaded = load_bootstrap(authority[2], capture, approved_manifests=[authority[3]])
        if loaded != intent:
            raise ContractError("BOOTSTRAP_BINDING", "Intent differs from approved bootstrap")
        return
    files = require_release_configuration(capture)
    inputs = intent.get("evidence", {}).get("inputs", [])
    for path, data in files.items():
        matches = [row for row in inputs if row.get("filename") == path[len(".rs9/"):]]
        if len(matches) != 1 or matches[0].get("sha256") != digest(data):
            raise ContractError("RELEASE_CONFIG_BINDING", "Intent inputs must bind every tagged configuration file")
