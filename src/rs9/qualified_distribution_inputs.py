"""Strict read-only input verification; no signing, publication or deployment authority."""
from dataclasses import dataclass
from datetime import datetime
import json
from pathlib import Path
import re

from rs9.candidate import configuration_rows
from rs9.collect_candidate import collect, admit_original_run, LIMIT, REPOSITORY
from rs9.current_generation import CURRENT_GENERATION, DISTRIBUTION_SCOPE, distribution_paths
from rs9.errors import ContractError
from rs9.hosted_contract import validate_hosted_summary
from rs9.hosted_custody import source_identity, consumer_provenance, verify_set
from rs9.hosted_summary import (required, promotion_restrictions, validate_product_architectures,
                                validate_rpm_policy_source)
from rs9.package_roles import verify_package_roles, is_installable_binary
from rs9.public_release_transport import MODES
from rs9.product_classes import extract_package_arch
from rs9.scratch import canonical, physical_directory


@dataclass(frozen=True)
class SourceBoundConfiguration:
    repository: Path
    source_commit: str
    source_tree: str
    run_id: int
    not_before: datetime
    workflow_sha256: str
    contract_sha256: str
    builder_source_sha256: str
    configuration_sha256: str
    release_ingestion_sha256: str

    def expected(self):
        if not isinstance(self.repository, Path):
            raise ContractError("DISTRIBUTION_CONFIG", "Physical source repository Path required")
        for name in ("source_commit", "source_tree", "workflow_sha256", "contract_sha256", "builder_source_sha256",
                     "configuration_sha256", "release_ingestion_sha256"):
            size = 40 if name in {"source_commit", "source_tree"} else 64
            value = getattr(self, name)
            if not isinstance(value, str) or not re.fullmatch("[0-9a-f]{" + str(size) + "}", value):
                raise ContractError("DISTRIBUTION_CONFIG", "Exact source-bound identities required")
        if (type(self.run_id) is not int or self.run_id <= 0 or not isinstance(self.not_before, datetime)
                or self.not_before.tzinfo is None or self.not_before.utcoffset() is None):
            raise ContractError("DISTRIBUTION_CONFIG", "Exact run and timezone-aware push boundary required")
        return {"repository": REPOSITORY, "source_commit": self.source_commit, "source_tree": self.source_tree,
                "run_id": self.run_id, "workflow_path": distribution_paths(CURRENT_GENERATION)[0],
                "workflow_sha256": self.workflow_sha256, "contract_sha256": self.contract_sha256,
                "builder_source_sha256": self.builder_source_sha256, "configuration_sha256": self.configuration_sha256,
                "release_ingestion_sha256": self.release_ingestion_sha256, "generation": CURRENT_GENERATION,
                "qualification_scope": DISTRIBUTION_SCOPE, "event": "push", "ref": "refs/heads/main", "attempt": 1}


def _json(path):
    path = Path(path)
    if any(part.is_symlink() for part in (path, *path.parents)) or not path.is_file() or path.stat().st_size > LIMIT:
        raise ContractError("DISTRIBUTION_INPUT", "Bounded physical qualification JSON required")
    try:
        with path.open("rb") as stream:
            raw = stream.read(LIMIT + 1)
        if len(raw) > LIMIT:
            raise ContractError("DISTRIBUTION_INPUT", "Qualification JSON exceeds bound")
        value = json.loads(raw)
    except (ValueError, UnicodeError):
        raise ContractError("DISTRIBUTION_INPUT", "Qualification JSON invalid") from None
    if not isinstance(value, dict):
        raise ContractError("DISTRIBUTION_INPUT", "Qualification object required")
    return value


def _authority_boundaries(record):
    if any(record.get(field) is not False for field in ("production_enabled", "publication_authority", "attended_gates_satisfied")):
        raise ContractError("DISTRIBUTION_AUTHORITY", "Original non-production authority boundaries must remain false")


def _binary_inputs(repository, output, summary, expected, *, _admission=None):
    """Join physical custody to the validated summary, then verify real byte roles."""
    from rs9.hosted_deb import _custody_unique, _rpm_custody_unique
    versions = {intent["project"]["id"]: intent["version"] for _, intent in configuration_rows(repository, generation=CURRENT_GENERATION)}
    receipts = {(row["lane"], row["system"]): row for row in summary["receipts"]}
    manifests = {(row["lane"], row["system"]): row for row in summary["artifact_manifests"]}
    unique, independent, bundles = {}, {}, {"deb": [], "rpm": [], "pacman": []}
    nix = {}
    for lane in required(repository, generation=CURRENT_GENERATION):
        key = lane["lane"], lane["system"]
        directory = output / lane["artifact_name"]
        manifest = verify_set(directory, expected_provenance=expected)
        receipt = _json(directory / (lane["lane"] + "-" + lane["system"] + ".json"))
        if (canonical(manifest) != canonical(manifests.get(key)) or canonical(receipt) != canonical(receipts.get(key))
                or receipt.get("provenance") != expected):
            raise ContractError("DISTRIBUTION_CUSTODY", "Physical receipt/manifest differs from validated summary")
        _authority_boundaries(receipt)
        tokens, errors = promotion_restrictions(lane, receipt)
        if _admission is None:
            if tokens or errors or receipt.get("production_promotion_blockers") != []:
                raise ContractError("DISTRIBUTION_PROMOTION_HELD", "Lane promotion restrictions prohibit import")
        else:
            from rs9.own_repository_admission import check_lane, VERSIONS
            check_lane(_admission, lane, receipt, manifest)
            # The live paired proof covers its fixed070 transport contract,
            # not the active071 generation. Never infer this scope from JSON.
            versions = dict(VERSIONS)
        validate_rpm_policy_source(repository, receipt, generation=CURRENT_GENERATION)
        verify_package_roles(directory, manifest)
        validate_product_architectures(lane, manifest["files"])
        if lane["lane"] == "nix":
            nix[lane["system"]] = receipt["details"]["outputs"]
        if lane["lane"] not in bundles:
            continue
        family, packages, present = lane["lane"], {}, set()
        for row in manifest["files"]:
            if not is_installable_binary(row):
                continue
            name = Path(row["path"]).name
            product = next((product for product in versions if name.startswith(product + ("_" if family == "deb" else "-"))), None)
            if product is None:
                raise ContractError("DISTRIBUTION_BINARY_SCOPE", "Unexpected installable binary product")
            version_prefix = product + ("_" if family == "deb" else "-") + versions[product] + "-"
            if not name.startswith(version_prefix):
                raise ContractError("DISTRIBUTION_BINARY_SCOPE", "Binary filename differs from selected current version")
            present.add(product)
            identity = (name, row["sha256"], row["size"])
            arch = extract_package_arch(name)
            if arch in {"all", "any", "noarch"}:
                prior = independent.setdefault((family, product), identity)
                if prior != identity:
                    raise ContractError("CUSTODY_CONFLICT", "Architecture-independent binary identity differs between lanes")
            object_key = family, name
            origin = {"artifact": lane["artifact_name"], "system": lane["system"], "path": row["path"]}
            if object_key in unique:
                prior = unique[object_key]
                if (prior["sha256"], prior["size"]) != (row["sha256"], row["size"]):
                    raise ContractError("CUSTODY_CONFLICT", "Duplicate binary name has different bytes")
                prior["origins"].append(origin)
            else:
                unique[object_key] = {"family": family, "name": name, "product": product, "version": versions[product],
                                      "architecture": arch, "sha256": row["sha256"], "size": row["size"], "origins": [origin]}
            packages[name] = directory / row["path"]
        if present != set(lane.get("required_products", [])):
            raise ContractError("DISTRIBUTION_BINARY_SCOPE", "Exact required installable binary products missing")
        bundles[family].append({"manifest": {"family": family, "system": lane["system"]}, "packages": packages})
    _custody_unique(bundles["deb"])
    _custody_unique(bundles["pacman"])
    _rpm_custody_unique(bundles["rpm"])
    return [unique[key] for key in sorted(unique)], nix


def _verified_context(config, output, *, zip_transport="actions", timeout=7200, _execution_source=False):
    """Collect fresh live metadata and recompute validators; saved packet flags are never inputs."""
    if zip_transport not in MODES:
        raise ContractError("PUBLIC_RELAY_MODE", "Unknown ZIP transport mode")
    if type(config) is not SourceBoundConfiguration:
        raise ContractError("DISTRIBUTION_CONFIG", "Closed source-bound configuration required")
    expected = config.expected()
    repository = physical_directory(config.repository)
    actual = source_identity(repository, config.source_commit, generation=CURRENT_GENERATION)
    source_fields = set(expected) - {"event", "ref", "attempt", "run_id", "release_ingestion_sha256"}
    if any(actual.get(field) != expected[field] for field in source_fields):
        raise ContractError("DISTRIBUTION_SOURCE", "Caller configuration differs from authenticated current source")
    try:
        packet = collect(repository, output, commit=config.source_commit, started_at=config.not_before, run_id=config.run_id,
                         timeout=timeout, generation=CURRENT_GENERATION, zip_transport=zip_transport)
    finally:
        if _execution_source:
            from rs9.own_repository_admission import verify_execution_source
            verify_execution_source(repository)
    scope = packet.get("diagnostic_scope", {})
    if (packet.get("validation") != {"status": "pass", "reasons": []}
            or packet.get("classification") != "qualified-current-distribution-candidate"
            or packet.get("generation") != CURRENT_GENERATION or packet.get("qualification_scope") != DISTRIBUTION_SCOPE
            or packet.get("source_commit") != config.source_commit or packet.get("run_id") != config.run_id
            or scope.get("current_distribution_qualification") is not True
            or scope.get("full_live1_qualification") is not False or scope.get("published_linux_nix_ready") is not False
            or packet.get("production_enabled") is not False or packet.get("publication_authority") is not False):
        raise ContractError("DISTRIBUTION_NOT_QUALIFIED", "Recomputed collection does not qualify the selected distribution")
    output = physical_directory(output)
    actual_summary = _json(output / "hosted-summary/hosted-summary.json")
    _, original_run = admit_original_run(repository, commit=config.source_commit, run_id=config.run_id,
                                        started_at=config.not_before, generation=CURRENT_GENERATION)
    rechecked = consumer_provenance(repository, config.release_ingestion_sha256, original_run,
                                   source_commit=config.source_commit, run_id=config.run_id, generation=CURRENT_GENERATION)
    if rechecked != expected:
        raise ContractError("DISTRIBUTION_SOURCE", "Final original run/source context differs from caller configuration")
    summary = validate_hosted_summary(output / "hosted-summary", repository, config.source_commit,
                                      generation=CURRENT_GENERATION, run_id=config.run_id, original_run=original_run)
    if canonical(actual_summary) != canonical(summary):
        raise ContractError("DISTRIBUTION_CUSTODY", "Summary changed during revalidation")
    if (summary.get("qualification_verdict") != "qualified" or summary.get("adoptable") is not True
            or summary.get("blocking_reasons") != [] or any(summary.get(field) != value for field, value in expected.items())):
        raise ContractError("DISTRIBUTION_NOT_QUALIFIED", "Revalidated summary differs from exact source-bound qualification")
    _authority_boundaries(summary)
    return repository, output, summary, expected


def _inventory(expected, binaries, nix):
    return {"schema": "rs9.verified-distribution-inputs.v1alpha1", **expected, "binaries": binaries, "nix_outputs": nix,
            "production_enabled": False, "publication_authority": False, "attended_gates_satisfied": False,
            "signing_authority": False, "full_live1_qualification": False, "published_linux_nix_ready": False}


def qualified_distribution_inputs(config, output, *, zip_transport="actions", timeout=7200):
    """Generic/default facade remains strict for every promotion restriction."""
    repository, output, summary, expected = _verified_context(config, output, zip_transport=zip_transport, timeout=timeout)
    if summary.get("production_promotion_blockers") != [] or summary.get("production_promotion_blocked") is not False:
        raise ContractError("DISTRIBUTION_PROMOTION_HELD", "Actual production promotion restrictions prohibit import")
    binaries, nix = _binary_inputs(repository, output, summary, expected)
    return _inventory(expected, binaries, nix)


def qualified_theme_forge_packages_inputs(config, output, *, consumer_repository, consumer_commit, consumer_tree,
                                          zip_transport="actions", timeout=7200):
    """Fixed source-bound P unsigned inputs only; never generic token permission."""
    if type(config) is not SourceBoundConfiguration:
        raise ContractError("DISTRIBUTION_CONFIG", "Closed source-bound configuration required")
    from rs9.own_repository_admission import consumer_source, admit, release, release_consumer, verify_execution_source
    verify_execution_source(config.repository)
    consumer = consumer_source(config, consumer_repository, consumer_commit, consumer_tree)
    proof = None
    observations = [consumer]
    try:
        repository, output, summary, expected = _verified_context(config, output, zip_transport=zip_transport, timeout=timeout, _execution_source=True)
        verify_execution_source(config.repository)
        observations.append(consumer_source(config, consumer_repository, consumer_commit, consumer_tree))
        if observations[-1].record != consumer.record:
            raise ContractError("OWN_REPOSITORY_SOURCE", "Consumer changed during original-run admission")
        proof = admit(repository, output, summary, expected, consumer)
        binaries, nix = _binary_inputs(repository, output, summary, expected, _admission=proof)
        verify_execution_source(config.repository)
        observations.append(consumer_source(config, consumer_repository, consumer_commit, consumer_tree))
        if observations[-1].record != consumer.record:
            raise ContractError("OWN_REPOSITORY_SOURCE", "Consumer changed during input readback")
        verify_execution_source(config.repository)
        return {**_inventory(expected, binaries, nix), "own_repository_admission": proof.record}
    finally:
        if proof is not None:
            release(proof)
        for binding in observations:
            release_consumer(binding)
