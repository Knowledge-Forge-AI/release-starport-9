"""Closed 0.8 own-repository proof; the 0.7.1 module remains independent."""
from dataclasses import dataclass
import hashlib
import re
from weakref import WeakKeyDictionary

from rs9.collect_candidate import gh_read, REPOSITORY as RS9_REPOSITORY
from rs9.current_generation import CURRENT_GENERATION, CURRENT080_POLICY_VARIANT, rpm_policy_path
from rs9.hosted_custody import source_tree_identity, verify_set
from rs9.hosted_summary import (
    required,
    validate_rpm_policy_source,
)
from rs9.rpm_evidence import verify_rpm_custody, verify_policy_custody
from rs9.rpm_lint_policy import load_policy, _raw_blockers
from rs9.scratch import physical_directory
from rs9.own_repository_admission import (
    _json,
    _restriction,
    digest,
    fail,
    held,
    verify_execution_source,
)


TARGET = "Knowledge-Forge-AI/theme-forge-packages"
DESCRIPTOR = "tools/verification/current-rs9-inputs.json"
IMPORTER = "tools/verification/current_import_routing.py"
VERSIONS_080 = {
    "theme-forge-stellar-burst": "0.7.0",
    "theme-forge-stellar-loom": "0.5.0",
    "theme-forge-solar-sail": "0.3.0",
    "theme-forge-nebular-fusion": "0.8.0",
}
# Exact proposed 0.8 paired-P body pins; no caller or JSON may replace them.
CONSUMER_FILE_HASHES_080 = {
    ".github/workflows/publish.yml": "ce92b6e89dff958cce5f18060f0719c5458945f355fc3355ee652e3b0b47745e",
    "flake.lock": "ed928e945c79e3d7f19d37b13a05f0d97b98440b38661d97bf77844e40606431",
    "flake.nix": "67be263eae65764407ef29126d28183f0270f60ad45acb8fd1202cec6411d9dd",
    "keys/knowledge-forge-ai-packages.asc": "6931a99cf38e204c0adc75dd868f8c0e79d68e58e2644f575d4be1da2ea18d95",
    "package-matrix.json": "7e74cd3c676cc57dad275b5123f71c89227d101c024676c012a7fb4c7d93d091",
    "release-lock.json": "d489a366edeeadf26ed33bd72f9ada63e7826cf590824b84f51a2a225d4d788c",
    "tools/verification/current_import_routing.py": "3e5a482117e702f69802385468e84b9bd41495c39be902a6f8acbf2574d23494",
    "tools/verification/generate-publication-provenance.mjs": "1fd13ff84ca4267fb2d2207f006fb966e910426d7555528d115a9afd9119b695",
    "tools/verification/verify-publication-provenance.mjs": "50abdc435dc2a34bdc8a7511329f7fe9baad7c3554a7eecdab258c004145ef87",
}

_PROOF_080 = object()
_ACTIVE_080 = WeakKeyDictionary()
_CONSUMERS_080 = WeakKeyDictionary()


@dataclass(frozen=True, eq=False)
class _Consumer:
    record: dict
    expected_sha256: str
    _proof: object


def consumer_source_080(config, root, commit, tree):
    """Bind an exact 0.8 paired consumer to its source and descriptor."""
    root = physical_directory(root)
    if (not CONSUMER_FILE_HASHES_080 or IMPORTER not in CONSUMER_FILE_HASHES_080
            or any(not re.fullmatch("[0-9a-f]{40}", value or "") for value in (commit, tree))):
        fail("Exact paired 0.8 consumer source required", "OWN_REPOSITORY_SOURCE")
    if source_tree_identity(root, commit) != tree:
        fail("Clean 0.8 consumer tree differs", "OWN_REPOSITORY_SOURCE")

    def api(endpoint):
        value = _json(gh_read(root, ["api", "--hostname", "github.com", "--method", "GET",
                                      f"repos/{TARGET}/{endpoint}"]))
        if not isinstance(value, dict):
            fail("Consumer source API object required", "OWN_REPOSITORY_SOURCE")
        return value

    ref = api("git/ref/heads/main")
    actual = api("git/commits/" + commit)
    listing = api("git/trees/" + tree + "?recursive=1")
    if (ref.get("object", {}).get("type") != "commit" or ref.get("object", {}).get("sha") != commit
            or actual.get("sha") != commit or actual.get("tree", {}).get("sha") != tree
            or listing.get("sha") != tree or listing.get("truncated") is not False
            or not isinstance(listing.get("tree"), list)):
        fail("Adopted fixed P 0.8 main source differs", "OWN_REPOSITORY_SOURCE")
    rows = {}
    for row in listing["tree"]:
        if not isinstance(row, dict) or not isinstance(row.get("path"), str) or row["path"] in rows:
            fail("Malformed consumer tracked tree", "OWN_REPOSITORY_SOURCE")
        rows[row["path"]] = row
    files = {}
    for name in sorted(set(CONSUMER_FILE_HASHES_080) | {DESCRIPTOR}):
        row = rows.get(name, {})
        if row.get("type") != "blob" or row.get("mode") not in {"100644", "100755"}:
            fail("Required consumer path is not tracked blob", "OWN_REPOSITORY_SOURCE")
        data = held(root / name)
        blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        value = hashlib.sha256(data).hexdigest()
        if blob != row.get("sha") or (name in CONSUMER_FILE_HASHES_080 and value != CONSUMER_FILE_HASHES_080[name]):
            fail("Tracked/executing 0.8 consumer bytes differ", "OWN_REPOSITORY_SOURCE")
        files[name] = value
        if name == DESCRIPTOR:
            descriptor = _json(data)
    if not isinstance(descriptor, dict) or set(descriptor) != {
            "schema", "generation", "status", "production_enabled", "publication_authority", "rs9"}:
        fail("Closed tracked descriptor required", "OWN_REPOSITORY_SOURCE")
    if (descriptor["schema"] != "theme-forge.current-rs9-input-source.v1"
            or descriptor["generation"] != CURRENT_GENERATION
            or descriptor["production_enabled"] is not False
            or descriptor["publication_authority"] is not False):
        fail("Nonproduction current descriptor required", "OWN_REPOSITORY_SOURCE")
    if descriptor["status"] != "qualified-original-run-inputs" or not isinstance(descriptor["rs9"], dict):
        fail("No qualified original run adopted in descriptor", "OWN_REPOSITORY_UNADMITTED")
    expected = {**config.expected(), "not_before": config.not_before.isoformat()}
    if descriptor["rs9"] != expected or expected["repository"] != RS9_REPOSITORY:
        fail("Descriptor differs from fresh original-run configuration", "OWN_REPOSITORY_SOURCE")
    record = {
        "hostname": "github.com",
        "repository": TARGET,
        "commit": commit,
        "tree": tree,
        "files": files,
        "consumer_contract": "current-four-unsigned-inputs.v1",
        "admission_profile": CURRENT080_POLICY_VARIANT,
        "descriptor_sha256": files[DESCRIPTOR],
    }
    binding = _Consumer(record, digest(config.expected()), _PROOF_080)
    _CONSUMERS_080[binding] = (digest(record), binding.expected_sha256)
    return binding


def release_consumer_080(binding):
    _CONSUMERS_080.pop(binding, None)


@dataclass(frozen=True, eq=False)
class _Admission:
    ledger: tuple
    record: dict
    _proof: object


def release_080(proof):
    _ACTIVE_080.pop(proof, None)


def check_lane_080(proof, lane, receipt, manifest):
    if (type(proof) is not _Admission or proof._proof is not _PROOF_080
            or _ACTIVE_080.get(proof) != digest(proof.record)):
        fail("Live recomputed 0.8 scope proof required")
    row = (lane["lane"], lane["system"], digest(receipt), digest(manifest))
    if row not in proof.ledger:
        fail("0.8 scope proof does not cover actual lane bytes")


def admit_080(repository, output, summary, expected, consumer):
    """Rejoin physical custody under the fixed current080 policy only."""
    if (type(consumer) is not _Consumer or consumer._proof is not _PROOF_080
            or _CONSUMERS_080.get(consumer) != (digest(consumer.record), digest(expected))
            or consumer.record.get("repository") != TARGET
            or consumer.record.get("admission_profile") != CURRENT080_POLICY_VARIANT):
        fail("Fresh fixed 0.8-consumer source proof required")
    selected = load_policy(repository / rpm_policy_path(CURRENT_GENERATION, policy_variant=CURRENT080_POLICY_VARIANT),
                           generation=CURRENT_GENERATION, policy_variant=CURRENT080_POLICY_VARIANT)
    projects = selected.get("projects", {})
    if (selected.get("generation") != CURRENT_GENERATION or selected.get("status") != "authorized"
            or selected.get("blocking") is not False or set(projects) != set(VERSIONS_080)
            or any(not isinstance(projects.get(name), dict)
                   or projects[name].get("package_name") != name
                   or projects[name].get("version") != version
                   for name, version in VERSIONS_080.items())):
        fail("Complete adopted current080 policy required", "CURRENT_RPM_POLICY_HELD")
    policy_hash = digest(selected)
    ledger = []
    limitations = []
    rpm_systems = set()
    receipts = {(r["lane"], r["system"]): r for r in summary["receipts"]}
    manifests = {(r["lane"], r["system"]): r for r in summary["artifact_manifests"]}
    for lane in required(repository, generation=CURRENT_GENERATION):
        key = lane["lane"], lane["system"]
        directory = output / lane["artifact_name"]
        manifest = verify_set(directory, expected_provenance=expected)
        receipt = _json(held(directory / (lane["lane"] + "-" + lane["system"] + ".json"), 16 * 1024 * 1024))
        if manifest != manifests.get(key) or receipt != receipts.get(key):
            fail("Scoped custody differs from validated original")
        _restriction(lane, receipt)
        if lane["lane"] == "rpm":
            rpm_systems.add(lane["system"])
            validate_rpm_policy_source(repository, receipt, generation=CURRENT_GENERATION,
                                       policy_variant=CURRENT080_POLICY_VARIANT)
            raw_projections = verify_rpm_custody(directory, manifest, receipt)
            details = receipt.get("details", {})
            policies = details.get("rpm_lint_policy", {})
            raws = details.get("rpm_lint_raw", {})
            if set(policies) != set(VERSIONS_080) or set(raws) != set(VERSIONS_080):
                fail("Exact four current080 raw/policy products required")
            for product, version in VERSIONS_080.items():
                evaluation = verify_policy_custody(directory, manifest, policies[product])
                raw = raws[product]
                entry = selected["projects"][product]
                inputs = evaluation.get("inputs", {})
                if (entry.get("version") != version or entry.get("status") != "authorized"
                        or entry.get("blocking") is not False
                        or evaluation.get("accepted") is not True
                        or evaluation.get("status") not in {"accepted", "accepted-no-exceptions"}
                        or evaluation.get("blockers") != [] or evaluation.get("rule_blockers", []) != []
                        or evaluation.get("policy_sha256") != policy_hash or _raw_blockers(raw, selected)
                        or inputs.get("project_id") != product or inputs.get("version") != version
                        or inputs.get("system") != lane["system"]
                        or inputs.get("arch") not in entry["allowed_architectures"]
                        or inputs.get("payload_manifest_sha256") != entry.get("inventory_bindings", {}).get(
                            lane["system"], {}).get("payload_manifest_sha256")
                        or not re.fullmatch("[0-9a-f]{64}", evaluation.get("inventory_sha256", "") or "")):
                    fail("Incomplete current080 preservation/native evaluation")
                auth = entry["authenticated_inputs"]
                assets = ({row["sha256"] for row in auth["assets"]
                           if row["name"].endswith("-" + lane["system"].removesuffix("-linux") + "-unknown-linux-gnu.tar.gz")}
                          if "assets" in auth else {auth.get("asset_sha256")})
                if (inputs.get("asset_sha256") not in assets
                        or inputs.get("closure_sha256") != auth.get("closure_sha256")):
                    fail("Policy/capture asset or closure differs")
                if evaluation.get("accepted_findings", []) != raw.get("error_records", []):
                    fail("Accepted error set differs from complete retained raw set")
                limitations.append({
                    "system": lane["system"], "product": product,
                    "raw_status": raw.get("status"), "raw_clean": raw.get("clean"),
                    "raw_counts": raw.get("findings_summary"), "raw_sha256": digest(raw),
                    "raw_custody": raw_projections[product],
                    "policy_evaluation_sha256": digest(evaluation), "policy_sha256": policy_hash,
                })
        ledger.append((*key, digest(receipt), digest(manifest)))
    union = sorted({token for receipt in receipts.values() for token in receipt.get("production_promotion_blockers", [])})
    if (rpm_systems != {"x86_64-linux", "aarch64-linux"}
            or summary.get("production_promotion_blockers") != union
            or summary.get("production_promotion_blocked") is not bool(union)):
        fail("Conservative summary restriction union differs")
    record = {
        "schema": "rs9.theme-forge-own-repository-admission.v1",
        "target": TARGET,
        "scope": "unsigned-current-four-inputs",
        "admission_profile": CURRENT080_POLICY_VARIANT,
        "consumer_source": consumer.record,
        "original_source": dict(expected),
        "original_restrictions": union,
        "original_summary_sha256": digest(summary),
        "lane_custody": [{"lane": row[0], "system": row[1], "receipt_sha256": row[2], "manifest_sha256": row[3]}
                         for row in ledger],
        "original_production_promotion_blocked": bool(union),
        "policy_sha256": policy_hash,
        "raw_policy_evidence": limitations,
        "raw_clean_claim": False,
        "official_fedora_qualification_claim": False,
        "production_enabled": False,
        "publication_authority": False,
        "signing_authority": False,
        "assembly_ready": False,
    }
    proof = _Admission(tuple(ledger), record, _PROOF_080)
    _ACTIVE_080[proof] = digest(record)
    return proof


__all__ = [
    "CONSUMER_FILE_HASHES_080",
    "CURRENT080_POLICY_VARIANT",
    "VERSIONS_080",
    "admit_080",
    "check_lane_080",
    "consumer_source_080",
    "release_080",
    "release_consumer_080",
    "verify_execution_source",
]
