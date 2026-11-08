"""Held OS080 RPM construction/readback adapter.

This module is a source-preparation seam for one narrow, non-production
operation.  It delegates construction to the maintained ``build_rpm_candidate``
function and only normalizes its late, policy-held failure into a bounded
readback record.  It never signs, publishes, installs, qualifies, or invents
RPM evidence.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
import re
from typing import Any

from rs9.errors import ContractError
from rs9.scratch import canonical


REQUEST_SCHEMA = "rs9.current080-rpm-keyfree-request.v1"
READBACK_SCHEMA = "rs9.current080-rpm-keyfree-readback.v1"
GENERATION = "theme-forge-current-202610"
PROJECT = "theme-forge-nebular-fusion"
VERSION = "0.8.0"
POLICY_VARIANT = "current080"
DISTRO = "fedora-43"
SOURCE_BINDING = {
    "release_id": 437909062,
    "tag": "v0.8.0",
    "version": VERSION,
    "commit": "516f5a7d8a449946a0246ea23d37991f586dfc2c",
    "tree": "907163a09d2995c9080074294db54c54af626563",
}
POLICY_PATH = "operators/theme-forge-current-202610/rpm-lint-policy-nebular080.json"
POLICY_SHA256 = "6e0f66ab486b09992343ff32ff812b3eb51958daf5c1bd68b27cfa17e5781649"
MAX_READBACK_BYTES = 2 * 1024 * 1024
MAX_PACKAGE_BYTES = 128 * 1024 * 1024
MAX_INVENTORY_FILES = 20_000
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")

SYSTEM_BINDINGS = {
    "x86_64-linux": {
        "architecture": "x86_64",
        "platform": "linux/amd64",
        "container_digest": "sha256:c5e15bd1e07c25904d0c5b9865fb7ee4589f8ca234e635742b0c1195838f4bfd",
        "github_asset_id": 722264633,
        "asset_name": "theme-forge-nebular-fusion-v0.8.0-x86_64-unknown-linux-gnu.tar.gz",
        "asset_bytes": 56825312,
        "asset_sha256": "498f0f6ff81c32200843e04016f86f7733905df0b0712c3f3639162ad5655abc",
        "executable_sha256": "61773740d5a165ccbf287ba8eaa175470d7288d23bd6c332e209e6cc07a7d8b1",
        "native_package_manifest_sha256": "fb2b250b354949fd704e0901bde79ff60ec66b92577a08d1b299945f02fef19d",
        "release_payload_manifest_sha256": "7c3d40d57d30300ce0f6888e8fc8a975e96711ce9a01d79fb598b1656d0d4f88",
        "sidecar_manifest_sha256": "5caf3591b05181a5c605e6d9929ed6660e2ca073359eeae8d42fc7a1c6253160",
        "native_package_member_count": 1785,
        "release_payload_member_count": 1785,
    },
    "aarch64-linux": {
        "architecture": "aarch64",
        "platform": "linux/arm64",
        "container_digest": "sha256:0b0303ee12217251f2ec18a71a21284f383e99d1d3bae1eb6c8970fd2e16e26b",
        "github_asset_id": 722265731,
        "asset_name": "theme-forge-nebular-fusion-v0.8.0-aarch64-unknown-linux-gnu.tar.gz",
        "asset_bytes": 57038323,
        "asset_sha256": "4bbc40f180d954e1ca496606da9b63d7ce0f49dd29e802893aabc4aa0e859e94",
        "executable_sha256": "65cbd19123ace49cd45de5b812506ed6c085350105ea6eaffff2b6191091a1fc",
        "native_package_manifest_sha256": "aaaf6f47d9a2aec517ff721f1eccb598804596185aec76ab6b607c37037bbeab",
        "release_payload_manifest_sha256": "f2b980ab4e9b0bc2bd251708a47070be6a4fcb8836e03c6ef29abb27c5c0ffd5",
        "sidecar_manifest_sha256": "8b275de7becbcd47886ebdfb1e156a64b3a5991cf181b34b8ce126af44df0eb4",
        "native_package_member_count": 1785,
        "release_payload_member_count": 1785,
    },
}

REQUIRED_TOOLS = ("rpmbuild", "rpm", "rpmlint", "createrepo_c")
BUILDER_BINDING = {
    "module": "rs9.build_rpm",
    "function": "build_rpm_candidate",
    "runner": "rs9.hosted_deb.ContainerRunner",
    "container_repository": "registry.fedoraproject.org/fedora",
    "container_tag": "43",
    "required_tools": REQUIRED_TOOLS,
}
MODE_FIELDS = ("signing", "publication", "installation", "qualification")
READBACK_REQUIRED = (
    "construction_witness",
    "preservation_inventory",
    "rpmlint_evidence",
    "rpmlint_policy",
)


def _fail(code: str, message: str) -> None:
    raise ContractError(code, message)


def _closed(value: Mapping[str, Any], fields: set[str], required: set[str], label: str) -> None:
    if not isinstance(value, Mapping) or set(value) != fields or not required <= set(value):
        _fail("KEYFREE_SCHEMA", f"Closed {label} contract required")


def _sha(value: Any, label: str) -> None:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        _fail("KEYFREE_SCHEMA", f"Bound {label} digest required")


def _validate_source(source: Mapping[str, Any]) -> None:
    fields = {"release_id", "tag", "version", "commit", "tree"}
    _closed(source, fields, fields, "source identity")
    if dict(source) != SOURCE_BINDING:
        _fail("KEYFREE_SOURCE", "OS080 source identity differs")


def _validate_asset(asset: Mapping[str, Any], system: str) -> None:
    fields = {
        "github_asset_id",
        "name",
        "bytes",
        "sha256",
        "executable_sha256",
        "native_package_manifest_sha256",
        "release_payload_manifest_sha256",
        "sidecar_manifest_sha256",
        "native_package_member_count",
        "release_payload_member_count",
    }
    _closed(asset, fields, fields, "raw asset")
    binding = SYSTEM_BINDINGS[system]
    if asset["github_asset_id"] != binding["github_asset_id"] or asset["name"] != binding["asset_name"]:
        _fail("KEYFREE_ASSET", "Raw OS080 asset architecture differs")
    for key in (
        "sha256",
        "executable_sha256",
        "native_package_manifest_sha256",
        "release_payload_manifest_sha256",
        "sidecar_manifest_sha256",
    ):
        _sha(asset[key], f"asset {key}")
    if asset["bytes"] != binding["asset_bytes"]:
        _fail("KEYFREE_ASSET", "Bound raw asset size required")
    if asset["sha256"] != binding["asset_sha256"]:
        _fail("KEYFREE_ASSET", "Raw OS080 asset digest differs")
    if asset["executable_sha256"] != binding["executable_sha256"]:
        _fail("KEYFREE_ASSET", "Raw OS080 executable digest differs")
    if asset["native_package_manifest_sha256"] != binding["native_package_manifest_sha256"]:
        _fail("KEYFREE_ASSET", "Raw OS080 native package manifest differs")
    if asset["release_payload_manifest_sha256"] != binding["release_payload_manifest_sha256"]:
        _fail("KEYFREE_ASSET", "Raw OS080 release payload manifest differs")
    if asset["sidecar_manifest_sha256"] != binding["sidecar_manifest_sha256"]:
        _fail("KEYFREE_ASSET", "Raw OS080 sidecar manifest differs")
    if asset["native_package_member_count"] != binding["native_package_member_count"]:
        _fail("KEYFREE_ASSET", "Bound native package member count required")
    if asset["release_payload_member_count"] != binding["release_payload_member_count"]:
        _fail("KEYFREE_ASSET", "Bound release payload member count required")
    if not binding["container_digest"].startswith("sha256:"):
        _fail("KEYFREE_SCHEMA", "Container digest binding unavailable")


def _validate_policy(policy: Mapping[str, Any]) -> None:
    fields = {
        "path",
        "sha256",
        "status",
        "blocking",
        "exceptions",
        "production_enabled",
        "publication_authority",
    }
    _closed(policy, fields, fields, "held policy")
    _sha(policy["sha256"], "policy")
    if (
        policy["status"] != "blocked"
        or policy["blocking"] is not True
        or policy["exceptions"] != {}
        or policy["production_enabled"] is not False
        or policy["publication_authority"] is not False
    ):
        _fail("KEYFREE_POLICY", "OS080 policy must remain explicitly blocked")
    if policy["path"] != POLICY_PATH or policy["sha256"] != POLICY_SHA256:
        _fail("KEYFREE_POLICY", "OS080 policy binding differs")


def _validate_builder_policy(policy: Mapping[str, Any], request: Mapping[str, Any]) -> None:
    """Bind the full maintained policy passed to ``build_rpm_candidate``."""
    if not isinstance(policy, Mapping):
        _fail("KEYFREE_POLICY", "Full maintained RPM policy is required by the builder")
    if set(policy) == {
        "path",
        "sha256",
        "status",
        "blocking",
        "exceptions",
        "production_enabled",
        "publication_authority",
    }:
        _validate_policy(policy)
        return
    required = {
        "schema",
        "generation",
        "scope",
        "status",
        "blocking",
        "production_enabled",
        "publication_authority",
        "projects",
    }
    if not isinstance(policy, Mapping) or not required <= set(policy):
        _fail("KEYFREE_POLICY", "Full maintained RPM policy is required by the builder")
    if (
        policy["schema"] != "rs9.rpm-lint-policy.v1"
        or policy["generation"] != GENERATION
        or policy["status"] != "blocked"
        or policy["blocking"] is not True
        or policy["production_enabled"] is not False
        or policy["publication_authority"] is not False
    ):
        _fail("KEYFREE_POLICY", "Full OS080 policy must remain explicitly blocked")
    projects = policy["projects"]
    project = projects.get(request["project"]) if isinstance(projects, Mapping) else None
    authenticated_assets = project.get("authenticated_inputs", {}).get("assets", []) if isinstance(project, Mapping) else []
    matching_assets = [
        row
        for row in authenticated_assets
        if isinstance(row, Mapping)
        and row.get("name") == request["raw_asset"]["name"]
        and row.get("sha256") == request["raw_asset"]["sha256"]
    ]
    if (
        not isinstance(project, Mapping)
        or project.get("status") != "blocked"
        or project.get("blocking") is not True
        or project.get("exceptions") != {}
        or project.get("version") != VERSION
        or request["system"] not in project.get("allowed_systems", [])
        or request["architecture"] not in project.get("allowed_architectures", [])
        or len(matching_assets) != 1
    ):
        _fail("KEYFREE_POLICY", "Full OS080 Nebular policy binding differs")


def _validate_container(container: Mapping[str, Any], system: str) -> None:
    fields = {"repository", "tag", "digest", "platform"}
    _closed(container, fields, fields, "container")
    expected = SYSTEM_BINDINGS[system]
    if (
        container["repository"] != BUILDER_BINDING["container_repository"]
        or container["tag"] != BUILDER_BINDING["container_tag"]
        or container["digest"] != expected["container_digest"]
        or container["platform"] != expected["platform"]
    ):
        _fail("KEYFREE_CONTAINER", "Fedora 43 platform pin differs")


def request_for_system(system: str) -> dict[str, Any]:
    """Return the exact closed request for one maintained Linux RPM lane."""
    if system not in SYSTEM_BINDINGS:
        _fail("KEYFREE_SELECTION", "Only the two maintained Linux RPM systems are supported")
    binding = SYSTEM_BINDINGS[system]
    request = {
        "schema": REQUEST_SCHEMA,
        "generation": GENERATION,
        "policy_variant": POLICY_VARIANT,
        "project": PROJECT,
        "version": VERSION,
        "system": system,
        "architecture": binding["architecture"],
        "distro": DISTRO,
        "source": dict(SOURCE_BINDING),
        "raw_asset": {
            "github_asset_id": binding["github_asset_id"],
            "name": binding["asset_name"],
            "bytes": binding["asset_bytes"],
            "sha256": binding["asset_sha256"],
            "executable_sha256": binding["executable_sha256"],
            "native_package_manifest_sha256": binding["native_package_manifest_sha256"],
            "release_payload_manifest_sha256": binding["release_payload_manifest_sha256"],
            "sidecar_manifest_sha256": binding["sidecar_manifest_sha256"],
            "native_package_member_count": binding["native_package_member_count"],
            "release_payload_member_count": binding["release_payload_member_count"],
        },
        "container": {
            "repository": BUILDER_BINDING["container_repository"],
            "tag": BUILDER_BINDING["container_tag"],
            "digest": binding["container_digest"],
            "platform": binding["platform"],
        },
        "builder": {**BUILDER_BINDING, "required_tools": list(REQUIRED_TOOLS)},
        "policy": {
            "path": POLICY_PATH,
            "sha256": POLICY_SHA256,
            "status": "blocked",
            "blocking": True,
            "exceptions": {},
            "production_enabled": False,
            "publication_authority": False,
        },
        "mode": {field: False for field in MODE_FIELDS},
    }
    validate_request(request)
    return request


def validate_request(request: Mapping[str, Any]) -> dict[str, Any]:
    """Validate a closed request made from maintained OS080 source data."""
    fields = {
        "schema",
        "generation",
        "policy_variant",
        "project",
        "version",
        "system",
        "architecture",
        "distro",
        "source",
        "raw_asset",
        "container",
        "builder",
        "policy",
        "mode",
    }
    _closed(request, fields, fields, "request")
    if (
        request["schema"] != REQUEST_SCHEMA
        or request["generation"] != GENERATION
        or request["policy_variant"] != POLICY_VARIANT
        or request["project"] != PROJECT
        or request["version"] != VERSION
        or request["distro"] != DISTRO
    ):
        _fail("KEYFREE_SELECTION", "OS080 RPM selection differs")
    system = request["system"]
    if system not in SYSTEM_BINDINGS:
        _fail("KEYFREE_SELECTION", "Only the two maintained Linux RPM systems are supported")
    expected = SYSTEM_BINDINGS[system]
    if request["architecture"] != expected["architecture"]:
        _fail("KEYFREE_SELECTION", "RPM architecture differs from system")
    _validate_source(request["source"])
    _validate_asset(request["raw_asset"], system)
    _validate_container(request["container"], system)
    _closed(request["builder"], set(BUILDER_BINDING) | {"required_tools"}, set(BUILDER_BINDING), "builder")
    if request["builder"] != {**BUILDER_BINDING, "required_tools": list(REQUIRED_TOOLS)}:
        _fail("KEYFREE_BUILDER", "Maintained RPM builder binding differs")
    _validate_policy(request["policy"])
    _closed(request["mode"], set(MODE_FIELDS), set(MODE_FIELDS), "operation mode")
    if any(request["mode"][key] is not False for key in MODE_FIELDS):
        _fail("KEYFREE_MODE", "Key-free precursor cannot sign, publish, install, or qualify")
    return dict(request)


def _require_sha(value: Any, label: str) -> None:
    _sha(value, label)


def _validate_witness(witness: Mapping[str, Any], request: Mapping[str, Any]) -> None:
    required = {"schema", "rpmbuild_receipt", "rpm_identity", "rpm_payload_digest", "package_sha256", "package_size", "spec_sha256"}
    if not isinstance(witness, Mapping) or not required <= set(witness):
        _fail("KEYFREE_READBACK", "RPM construction witness is incomplete")
    if witness["schema"] != "rs9.rpm-construction-witness.v1":
        _fail("KEYFREE_READBACK", "RPM construction witness schema differs")
    _require_sha(witness["package_sha256"], "package")
    _require_sha(witness["spec_sha256"], "spec")
    if type(witness["package_size"]) is not int or not 1 <= witness["package_size"] <= MAX_PACKAGE_BYTES:
        _fail("KEYFREE_READBACK", "RPM package size is outside the bounded contract")
    identity = witness["rpm_identity"]
    if not isinstance(identity, Mapping) or set(identity) != {"name", "version", "release", "arch"}:
        _fail("KEYFREE_READBACK", "RPM header identity is incomplete")
    if identity["name"] != PROJECT or identity["version"] != VERSION or identity["arch"] != request["architecture"]:
        _fail("KEYFREE_READBACK", "RPM header identity differs from request")
    payload = witness["rpm_payload_digest"]
    if (
        not isinstance(payload, Mapping)
        or payload.get("algorithm") != "sha256"
        or not isinstance(payload.get("digest"), str)
    ):
        _fail("KEYFREE_READBACK", "RPM payload digest readback is missing")
    _require_sha(payload["digest"], "RPM payload")


def _validate_inventory(
    inventory: Mapping[str, Any],
    request: Mapping[str, Any],
    witness: Mapping[str, Any],
) -> list[Mapping[str, Any]]:
    required = {
        "schema",
        "complete",
        "package_sha256",
        "asset_sha256",
        "payload_manifest_sha256",
        "files",
        "expected",
        "duplicate_groups",
        "calculated_duplicate_waste",
        "possible_duplicate_waste_bytes",
    }
    if not isinstance(inventory, Mapping) or not required <= set(inventory):
        _fail("KEYFREE_READBACK", "RPM preservation inventory is incomplete")
    if inventory["schema"] != "rs9.rpm-preservation-inventory.v1" or inventory["complete"] is not True:
        _fail("KEYFREE_READBACK", "Complete RPM preservation inventory required")
    if inventory["package_sha256"] != witness["package_sha256"]:
        _fail("KEYFREE_READBACK", "Inventory package digest differs from construction witness")
    if inventory["asset_sha256"] != request["raw_asset"]["sha256"]:
        _fail("KEYFREE_READBACK", "Inventory source asset differs from request")
    if inventory["payload_manifest_sha256"] != request["raw_asset"]["release_payload_manifest_sha256"]:
        _fail("KEYFREE_READBACK", "Inventory payload manifest differs from request")
    files = inventory["files"]
    if not isinstance(files, Mapping) or not 1 <= len(files) <= MAX_INVENTORY_FILES:
        _fail("KEYFREE_READBACK", "Bound RPM member inventory required")
    for row in files.values():
        if not isinstance(row, Mapping) or not {"path", "type", "mode", "size", "inode", "device", "flags"} <= set(row):
            _fail("KEYFREE_READBACK", "RPM inode/device/flags fields are required")
        if type(row["inode"]) is not int or row["inode"] < 0 or type(row["device"]) is not int or row["device"] < 0 or type(row["flags"]) is not int or row["flags"] < 0:
            _fail("KEYFREE_READBACK", "RPM inode/device/flags fields are malformed")
    receipts = inventory.get("receipts")
    if (
        not isinstance(receipts, list)
        or len(receipts) != 3
        or any(not isinstance(receipt, Mapping) for receipt in receipts)
    ):
        _fail("KEYFREE_READBACK", "RPM dump/algo/attrs receipts are required")
    return [dict(receipt) for receipt in receipts]


def _project_inventory(inventory: Mapping[str, Any], receipts: list[Any]) -> dict[str, Any]:
    """Keep only package-member identity and bounded query evidence for readback."""
    row_fields = (
        "path",
        "type",
        "mode",
        "size",
        "owner",
        "group",
        "inode",
        "device",
        "flags",
        "sha256",
        "target",
    )
    files = {
        path: {field: row[field] for field in row_fields if field in row}
        for path, row in inventory["files"].items()
    }
    return {
        "schema": inventory["schema"],
        "complete": inventory["complete"],
        "package_sha256": inventory["package_sha256"],
        "asset_sha256": inventory["asset_sha256"],
        "payload_manifest_sha256": inventory["payload_manifest_sha256"],
        "files": files,
        "duplicate_groups": inventory["duplicate_groups"],
        "calculated_duplicate_waste": inventory["calculated_duplicate_waste"],
        "possible_duplicate_waste_bytes": inventory["possible_duplicate_waste_bytes"],
        "receipts": receipts,
    }


def _validate_lint(evidence: Mapping[str, Any], witness: Mapping[str, Any]) -> None:
    if not isinstance(evidence, Mapping) or evidence.get("schema") != "rs9.rpmlint-evidence.v1alpha1":
        _fail("KEYFREE_READBACK", "Structured rpmlint evidence required")
    receipt = evidence.get("tool_receipt")
    if not isinstance(receipt, Mapping) or receipt.get("tool") != "rpmlint":
        _fail("KEYFREE_READBACK", "rpmlint tool receipt required")
    if receipt.get("exit_code") not in {0, 64}:
        _fail("KEYFREE_READBACK", "rpmlint exit code is outside the existing contract")
    if evidence.get("package_sha256") != witness["package_sha256"]:
        _fail("KEYFREE_READBACK", "rpmlint package digest differs from construction witness")


def normalize_policy_held_failure(request: Mapping[str, Any], error: BaseException) -> dict[str, Any]:
    """Normalize only the maintained builder's late, blocked-policy failure."""
    validate_request(request)
    if not isinstance(error, ContractError) or error.code != "RPMLINT_FAILED":
        _fail("KEYFREE_READBACK", "RPM construction did not reach the held-policy boundary")
    witness = getattr(error, "construction_witness", None)
    inventory = getattr(error, "preservation_inventory", None)
    lint = getattr(error, "rpmlint_evidence", None)
    policy = getattr(error, "rpmlint_policy", None)
    if not isinstance(policy, Mapping) or policy.get("status") != "blocked" or policy.get("accepted") is not False:
        _fail("KEYFREE_POLICY", "A blocked policy result is required; acceptance cannot be fabricated")
    if "current-generation-diagnostic-only" not in set(policy.get("blockers", [])):
        _fail("KEYFREE_POLICY", "OS080 diagnostic-only policy blocker is required")
    _validate_witness(witness, request)
    receipts = _validate_inventory(inventory, request, witness)
    _validate_lint(lint, witness)
    projected_inventory = _project_inventory(inventory, receipts)
    result = {
        "schema": READBACK_SCHEMA,
        "status": "constructed-policy-held",
        "accepted": False,
        "production_enabled": False,
        "publication_authority": False,
        "source": {
            "release_id": request["source"]["release_id"],
            "version": request["source"]["version"],
            "commit": request["source"]["commit"],
            "tree": request["source"]["tree"],
            "asset_sha256": request["raw_asset"]["sha256"],
        },
        "system": request["system"],
        "architecture": request["architecture"],
        "construction_witness": witness,
        "preservation_inventory": projected_inventory,
        "rpmlint_evidence": lint,
        "rpmlint_policy": policy,
        "cleanup": "required-before-receipt-close",
    }
    try:
        encoded = canonical(result, validate=True)
    except (ContractError, TypeError, ValueError):
        _fail("KEYFREE_READBACK", "RPM readback contains an unsupported value")
    if len(encoded) > MAX_READBACK_BYTES:
        _fail("KEYFREE_READBACK", "RPM readback exceeds the bounded evidence budget")
    return result


def construct_and_readback(
    build: Callable[..., Any],
    request: Mapping[str, Any],
    capture: Any,
    intent: Mapping[str, Any],
    scratch: Any,
    *,
    runner: Any,
    policy: Mapping[str, Any],
    builder_policy: Mapping[str, Any] | None = None,
    client_runtime: Mapping[str, Any] | None = None,
    caller_evidence: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Invoke the maintained builder and return only a policy-held readback."""
    request = validate_request(request)
    _validate_policy(policy)
    selected_builder_policy = builder_policy if builder_policy is not None else policy
    _validate_builder_policy(selected_builder_policy, request)
    try:
        result = build(
            capture,
            intent,
            request["architecture"],
            scratch,
            distro=request["distro"],
            runner=runner,
            policy=selected_builder_policy,
            builder_system=request["system"],
            client_runtime=client_runtime,
            caller_evidence=caller_evidence,
            generation=request["generation"],
            policy_variant=request["policy_variant"],
        )
    except ContractError as error:
        return normalize_policy_held_failure(request, error)
    except (OSError, TypeError, ValueError):
        _fail("KEYFREE_READBACK", "RPM construction failed before the held-policy boundary")
    if result is not None:
        _fail("KEYFREE_POLICY", "A held OS080 policy cannot return an accepted construction")
    _fail("KEYFREE_POLICY", "Held OS080 policy did not produce a bounded readback")

