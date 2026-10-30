"""Published npm archive/receipt consistency with authenticated tagged legal files.

Producer receipts are unsigned assertions. Their historical source coordinates
do not establish equivalence with the public tag or native qualification.
"""
import base64
import hashlib
import json

from rs9.archives import inspect_archive
from rs9.bootstrap import require_configuration_authority
from rs9.errors import ContractError
from rs9.npm_commands import authenticate_bins
from rs9.release_core import authenticated_record_hash, digest
from rs9.security import scan_for_credentials, validate_ecosystem_name
from rs9.spdx import validate_spdx_expression

CURRENT_PACKAGE_PROFILE = "npm-root-receipt-archive.v1alpha1"
LEGAL_SOURCES = ("LICENSE", "NOTICE", "COMMERCIAL-LICENSE.md")


def _mismatch(message):
    raise ContractError("CURRENT_PACKAGE_RECEIPT", message)


def validate_receipt(receipt, *, package, version, repository, asset, sri):
    """Validate only declared public package bindings, never producer ancestry."""
    if not isinstance(receipt, dict) or receipt.get("version") != version:
        _mismatch("Receipt package version differs")
    schema = receipt.get("schema")
    if schema == "tf.burst-release-root-receipt.v1":
        if (package != "@knowledge-forge-ai/theme-forge-stellar-burst"
                or receipt.get("repository") != repository
                or receipt.get("product") != "stellar-burst"
                or type(receipt.get("schemaVersion")) is not int or receipt["schemaVersion"] != 1
                or receipt.get("status") != "pass"
                or any(receipt.get(key) is not False for key in
                       ("provenanceClaimed", "publicationAdmitted", "signatureClaimed"))):
            _mismatch("Burst root receipt identity differs")
        references = receipt.get("references")
        if not isinstance(references, list) or any(not isinstance(row, dict) for row in references):
            _mismatch("Receipt references must be objects")
        matches = [row for row in references if row.get("name") == asset["name"]]
        if len(matches) != 1:
            _mismatch("One exact archive reference required")
        archive = matches[0]
    elif schema == "tf.js-release-root-package-receipt.v2":
        if (package not in {"@knowledge-forge-ai/theme-forge-stellar-loom",
                            "@knowledge-forge-ai/theme-forge-solar-sail"}
                or receipt.get("package") != package):
            _mismatch("Root receipt package identity differs")
        archive = receipt.get("archive")
        if not isinstance(archive, dict) or archive.get("sri") != sri:
            _mismatch("Receipt archive integrity differs")
    else:
        _mismatch("Unsupported current root receipt schema")
    if (type(archive.get("bytes")) is not int or archive["bytes"] != asset["size"]
            or archive.get("sha256") != asset["sha256"]):
        _mismatch("Receipt archive size or digest differs")
    return schema


def evaluate_current_package(capture, intent, roles):
    """Require real release and bootstrap capabilities before reading assertions."""
    authenticated_record_hash(capture)
    require_configuration_authority(capture, intent)
    if len(capture.archives) != 1 or roles != {"root-package-receipt": "root-package.receipt.json"}:
        raise ContractError("PACKAGE_IDENTITY", "One package and the current root receipt required")
    identity = next(iter(capture.archives))
    selected = next(a for a in intent["assets"] if a["id"] == identity)
    packaged = {}

    def visitor(path, data, mode):
        if path in {"package/package.json", *("package/" + name for name in LEGAL_SOURCES)}:
            packaged[path] = data
        elif path in selected.get("commands", {}).values():
            packaged[path] = data[:257]

    manifest = inspect_archive(capture.archives[identity], selected.get("commands", {}),
        command_policy="npm-package-bin", on_file=visitor, max_members=20000,
        max_member_bytes=4 * 1024 ** 2, max_total_bytes=64 * 1024 ** 2)
    if manifest != capture.manifests[identity]:
        raise ContractError("INPUT_CHANGED", "Archive changed after core authentication")
    if manifest["root"] != "package" or "package/package.json" not in packaged:
        raise ContractError("PACKAGE_IDENTITY", "Single package root and metadata required")
    package, commands, undeclared_bins = authenticate_bins(manifest, packaged, selected.get("commands", {}))
    tagged = json.loads(capture.source["package.json"])
    validate_ecosystem_name("npm", package["name"])
    repository = capture.record["repository"]["full_name"]
    expected_name = "@knowledge-forge-ai/" + intent["project"]["id"]
    if (package["name"] != expected_name or repository != "Knowledge-Forge-AI/" + intent["project"]["id"]
            or any(tagged.get(key) != package.get(key) for key in ("name", "version"))
            or package["version"] != intent["version"]
            or capture.record["release"]["tag"] != intent["tag"]):
        raise ContractError("PACKAGE_IDENTITY", "Tagged and packaged release identity differs")
    declarations = []
    for origin, expression in (("tagged:package.json", tagged.get("license")),
                               ("artifact:package/package.json", package.get("license"))):
        if not isinstance(expression, str):
            raise ContractError("PACKAGE_IDENTITY", "Package license declaration required")
        scan_for_credentials(expression)
        validate_spdx_expression(expression)
        if expression != intent["license"]["expression"]:
            raise ContractError("PACKAGE_IDENTITY", "Tagged and packaged license declarations differ")
        declarations.append({"source": origin, "expression": expression})
    legal = []
    for name in LEGAL_SOURCES:
        data = capture.source.get(name)
        if not isinstance(data, bytes) or not data.strip():
            raise ContractError("PAYLOAD_LICENSE_MISSING", "Authenticated tagged legal files required")
        data.decode("utf-8")
        copy = packaged.get("package/" + name)
        if copy is not None and copy != data:
            raise ContractError("PAYLOAD_LICENSE_MISMATCH", "Packaged legal copy differs from tagged source")
        legal.append({"path": name, "source": "tagged-repository", "sha256": digest(data),
                      "packaged_copy": copy is not None})
    raw = capture.evidence_bytes[roles["root-package-receipt"]]
    metadata = next(row for row in capture.record["assets"] if row["name"] == selected["name"])
    receipt_metadata = next(row for row in capture.record["assets"] if row["name"] == roles["root-package-receipt"])
    archive_bytes = capture.archives[identity].read_bytes()
    if (len(raw) != receipt_metadata["size"] or digest(raw) != receipt_metadata["sha256"]
            or len(archive_bytes) != metadata["size"] or digest(archive_bytes) != metadata["sha256"]):
        raise ContractError("INPUT_CHANGED", "Receipt or archive changed after core authentication")
    sri = "sha512-" + base64.b64encode(hashlib.sha512(archive_bytes).digest()).decode("ascii")
    schema = validate_receipt(json.loads(raw), package=package["name"], version=intent["version"],
                              repository=repository, asset=metadata, sri=sri)
    return {"package": {"name": package["name"], "version": package["version"],
                        "payload_manifest_sha256": manifest["manifest_sha256"],
                        "commands": commands, "undeclared_bins": undeclared_bins},
            "license": {"status": "consistent", "declarations": declarations,
                        "comparison": "exact-string-and-present-legal-copies; no legal acceptance"},
            "legal_files": legal, "notice_sha256": digest(capture.source["NOTICE"]),
            "receipt": {"schema": schema, "sha256": digest(raw), "archive_sha256": metadata["sha256"],
                        "basis": "unsigned-publisher-consistency", "source_equivalence": "not-established",
                        "native_qualification": False, "publication_authority": False}}
