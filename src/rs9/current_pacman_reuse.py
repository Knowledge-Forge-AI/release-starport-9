"""Current ARM reuse consistency and original provider joins.

Candidate consistency is never a substitute for the final original-run API join.
Replica paths are test/reuse witnesses; only x64 construction custody is selected.
"""
import hashlib
import json
from pathlib import Path
from rs9 import current_pacman_any as origin
from rs9.current_generation import CURRENT_GENERATION
from rs9.errors import ContractError
from rs9.hosted_custody import verify_set
from rs9.package_roles import RAW_REUSE_REPLICA, validate_role_declarations
from rs9.scratch import canonical

ARM_ARTIFACT = "candidate-pacman-aarch64-linux"
CANONICAL_ARTIFACT = "candidate-pacman-x86_64-linux"
WITNESS_PATH = "objects/lane-work/canonical-any-witness.json"


def _fail():
    raise ContractError("CANONICAL_ANY_REUSE", "Exact current ARM replica/original custody join required")


def declared_reuse_products(manifest, receipt):
    """Closed receipt/manifest consistency only; never provider or byte authority."""
    if (manifest.get("generation"),manifest.get("lane"),manifest.get("system")) != (
            CURRENT_GENERATION,"pacman","aarch64-linux"):
        return set()
    declared=receipt.get("details",{}).get("canonical_any_reuse")
    if (not isinstance(declared,dict) or set(declared) != {
            "role","construction_on_this_lane","construction_authority","witness_file","witness_sha256","replicas"}
            or declared["role"] != "reuse-witness" or declared["construction_on_this_lane"] is not False
            or declared["construction_authority"] != {"family":"pacman","system":"x86_64-linux"}
            or declared["witness_file"] != "canonical-any-witness.json"
            or not origin._hex64(declared["witness_sha256"])
            or not isinstance(declared["replicas"],dict)
            or set(declared["replicas"]) != set(origin.ANY_PRODUCTS)):
        _fail()
    entries={row["path"]:row for row in manifest["files"]}
    witness=entries.get(WITNESS_PATH)
    if (not isinstance(witness,dict) or witness.get("kind") != "evidence"
            or witness.get("sha256") != declared["witness_sha256"]):
        _fail()
    expected=set()
    for product,item in declared["replicas"].items():
        if (not isinstance(item,dict) or set(item) != {"file","sha256","size"}
                or not isinstance(item["file"],str)
                or not item["file"].startswith("canonical-any/files/"+product+"-")
                or not item["file"].endswith("-any.pkg.tar.zst")
                or len(Path(item["file"]).parts) != 3):
            _fail()
        relative="objects/lane-work/"+item["file"]
        row=entries.get(relative)
        if (not isinstance(row,dict) or row.get("role") != RAW_REUSE_REPLICA
                or row.get("kind") != "custody" or row.get("promotion") != "candidate-only"
                or row.get("sha256") != item["sha256"] or row.get("size") != item["size"]):
            _fail()
        expected.add(relative)
    if expected != {row["path"] for row in manifest["files"] if row.get("role") == RAW_REUSE_REPLICA}:
        _fail()
    return set(origin.ANY_PRODUCTS)


def candidate_reuse(repository, inputs, expected):
    """Read-bound consistency only; no API authority or qualification claim."""
    inputs = Path(inputs)
    arm_root = inputs / ARM_ARTIFACT
    manifest = verify_set(arm_root, expected_provenance=expected)
    if (manifest.get("lane"), manifest.get("system"), manifest.get("generation")) != (
            "pacman", "aarch64-linux", CURRENT_GENERATION):
        _fail()
    validate_role_declarations(manifest)
    entries = {row["path"]:row for row in manifest["files"]}
    if WITNESS_PATH not in entries or entries[WITNESS_PATH].get("kind") != "evidence":
        _fail()
    witness = origin._read_regular(arm_root / WITNESS_PATH, origin.MAX_JSON_BYTES)
    doc = origin._parse_witness(witness)
    if doc["source"] != {key:expected[key] for key in origin.SOURCE_KEYS}:
        _fail()
    lane = origin._constructor_lane(repository)
    admitted = origin._admit_constructor_tree(inputs / CANONICAL_ARTIFACT, expected, lane, None)
    for key in ("artifact_manifest_sha256", "receipt_sha256", "custody_manifest_sha256", "merkle_root"):
        if doc["constructor"][key] != admitted[key]:
            _fail()
    expected_raw, replicas = set(), {}
    for product in origin.ANY_PRODUCTS:
        item = admitted["products"][product]
        relative = "objects/lane-work/canonical-any/files/" + item["name"]
        expected_raw.add(relative)
        row = entries.get(relative)
        if (not isinstance(row, dict) or row.get("role") != RAW_REUSE_REPLICA
                or row.get("kind") != "custody" or row.get("promotion") != "candidate-only"
                or row.get("sha256") != item["sha256"] or row.get("size") != item["size"]):
            _fail()
        expected_file = {"name":item["name"], "sha256":item["sha256"], "size":item["size"],
                         "architecture":"any", "replica_path":origin.REPLICA_DIRECTORY + "/" + item["name"]}
        if doc["files"][product] != expected_file:
            _fail()
        replicas[product] = arm_root / relative
    if {row["path"] for row in manifest["files"] if row.get("role") == RAW_REUSE_REPLICA} != expected_raw:
        _fail()
    receipt = json.loads(origin._read_regular(arm_root / "pacman-aarch64-linux.json", origin.MAX_JSON_BYTES))
    declared = receipt.get("details", {}).get("canonical_any_reuse")
    expected_declared = {
        "role":"reuse-witness", "construction_on_this_lane":False,
        "construction_authority":{"family":"pacman", "system":"x86_64-linux"},
        "witness_file":"canonical-any-witness.json",
        "witness_sha256":hashlib.sha256(witness).hexdigest(),
        "replicas":{p:{"file":doc["files"][p]["replica_path"], "sha256":doc["files"][p]["sha256"],
                       "size":doc["files"][p]["size"]} for p in origin.ANY_PRODUCTS}}
    if declared != expected_declared:
        _fail()
    return {"replicas":replicas, "witness":witness, "canonical":admitted}


def original_reuse(repository, inputs, packet, original_run, expected):
    """Final admission joins the live collector's original API rows and exact bytes."""
    admitted = candidate_reuse(repository, inputs, expected)
    rows = [row for row in packet.get("artifacts", []) if row.get("name") == ARM_ARTIFACT]
    raw = (Path(inputs) / ARM_ARTIFACT / "artifact-manifest.json").read_bytes()
    if (len(rows) != 1 or rows[0].get("collection") != "verified"
            or rows[0].get("zip_digest_verified") is not True
            or rows[0].get("manifest_sha256") != hashlib.sha256(raw).hexdigest()):
        _fail()
    return origin.validate_reuse_witness(
        admitted["witness"], repository=repository, original_run=original_run, packet=packet,
        canonical_directory=Path(inputs) / CANONICAL_ARTIFACT, replica_files=admitted["replicas"])


def repository_package_sets(bundles, reuse):
    """Current Pages uses canonical x64 any bytes in both repository views."""
    from rs9.product_classes import extract_package_arch
    products = set(origin.ANY_PRODUCTS) | {"theme-forge-stellar-burst", "theme-forge-nebular-fusion"}
    result = {}
    for system, arch in (("x86_64-linux","x86_64"),("aarch64-linux","aarch64")):
        bundle = bundles.get(("pacman",system))
        if not isinstance(bundle,dict):
            _fail()
        packages = dict(bundle["packages"])
        named = {}
        for name,path in packages.items():
            matches = [p for p in products if name.startswith(p + "-")]
            if len(matches) != 1 or matches[0] in named:
                _fail()
            product=matches[0]
            if product in origin.ANY_PRODUCTS:
                if system != "x86_64-linux" or extract_package_arch(name) != "any":
                    _fail()
                expected=reuse["canonical"]["products"][product]
                if name != expected["name"] or hashlib.sha256(Path(path).read_bytes()).hexdigest() != expected["sha256"]:
                    _fail()
            elif extract_package_arch(name) != arch:
                _fail()
            named[product]=(name,Path(path))
        expected_products = products if system == "x86_64-linux" else products - set(origin.ANY_PRODUCTS)
        if set(named) != expected_products:
            _fail()
        if system == "aarch64-linux":
            for product in origin.ANY_PRODUCTS:
                item=reuse["canonical"]["products"][product]
                named[product]=(item["name"],Path(item["path"]))
        result[arch]={name:path for name,path in named.values()}
    return result
