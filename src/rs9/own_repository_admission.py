"""Fixed P unsigned-input scope. Raw restrictions and generic refusal survive."""
from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import inspect
from weakref import WeakKeyDictionary

from rs9.collect_candidate import gh_read, REPOSITORY as RS9_REPOSITORY
from rs9.current_generation import CURRENT_GENERATION, rpm_policy_path
from rs9.errors import ContractError
from rs9.hosted_custody import source_tree_identity, verify_set
from rs9.hosted_summary import promotion_restrictions, RPM_POLICY_PROMOTION_BLOCKER, required, validate_rpm_policy_source
from rs9.rpm_evidence import verify_rpm_custody, verify_policy_custody
from rs9.rpm_lint_policy import load_policy, _raw_blockers
from rs9.scratch import canonical, physical_directory

TARGET = "Knowledge-Forge-AI/theme-forge-packages"
DESCRIPTOR = "tools/verification/current-rs9-inputs.json"
IMPORTER = "tools/verification/current_import_routing.py"
VERSIONS = {"theme-forge-stellar-burst":"0.7.0", "theme-forge-stellar-loom":"0.5.0",
            "theme-forge-solar-sail":"0.3.0", "theme-forge-nebular-fusion":"0.7.0"}
# Filled from the actual paired P body + immutable P9 bytes by the retained
# preparation sealer. No caller/env/JSON can choose these expected identities.
CONSUMER_FILE_HASHES = {'.github/workflows/publish.yml': '3fef1507c55fefb30d07c5cef8aef110974b12d102e08768f4958561431db590', 'flake.lock': 'ed928e945c79e3d7f19d37b13a05f0d97b98440b38661d97bf77844e40606431', 'flake.nix': '67be263eae65764407ef29126d28183f0270f60ad45acb8fd1202cec6411d9dd', 'keys/knowledge-forge-ai-packages.asc': '6931a99cf38e204c0adc75dd868f8c0e79d68e58e2644f575d4be1da2ea18d95', 'package-matrix.json': '85316f9c08ef226130189fa680864e57bf360daeea087b9aa37081121105de5f', 'release-lock.json': 'c12e976de5660ae411f9ed1dd8c575a732afcdacfd3609bcf30eaa814061c96c', 'tools/verification/current_import_routing.py': '6807f16e8b6be540799020dc63c4ef1e62030fb54f44907b828728492c034d07', 'tools/verification/generate-publication-provenance.mjs': '1fd13ff84ca4267fb2d2207f006fb966e910426d7555528d115a9afd9119b695', 'tools/verification/verify-publication-provenance.mjs': '50abdc435dc2a34bdc8a7511329f7fe9baad7c3554a7eecdab258c004145ef87'}  # PAIR_BODY_HASHES
_PROOF = object()
_ACTIVE = WeakKeyDictionary()
_CONSUMERS = WeakKeyDictionary()


@dataclass(frozen=True,eq=False)
class _Consumer:
    record: dict
    expected_sha256: str
    _proof: object


def fail(reason, code="OWN_REPOSITORY_ADMISSION"):
    raise ContractError(code, reason)


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def held(path, limit=2*1024*1024):
    path=Path(path)
    if any(p.is_symlink() for p in (path,*path.parents)):
        fail("Physical consumer source required", "OWN_REPOSITORY_SOURCE")
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,"rb") as stream:
        before=os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size>limit:
            fail("Bounded consumer source required", "OWN_REPOSITORY_SOURCE")
        data=stream.read(limit+1);after=os.fstat(stream.fileno())
    fields=lambda info:(info.st_dev,info.st_ino,info.st_mode,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
    if len(data)!=before.st_size or fields(before)!=fields(after) or fields(after)!=fields(path.stat()):
        fail("Consumer source changed", "OWN_REPOSITORY_SOURCE")
    return data


def _json(raw):
    def unique(pairs):
        out={}
        for key,value in pairs:
            if key in out:fail("Duplicate source JSON field", "OWN_REPOSITORY_SOURCE")
            out[key]=value
        return out
    try:return json.loads(raw,object_pairs_hook=unique)
    except (ValueError,UnicodeError,TypeError):fail("Malformed source JSON", "OWN_REPOSITORY_SOURCE")


def _require_selected_execution_root(executing, root):
    if executing != physical_directory(root)/"src/rs9":
        fail("Executing RS9 package must come from selected physical checkout", "OWN_REPOSITORY_SOURCE")


def verify_execution_source(root):
    """Join the executing package/helper closure to the selected source inventory.

    This is mixed-installation hygiene, not confinement of hostile Python code.
    The existing fresh source/Git/API validation authenticates the selected tree;
    every package source byte and loaded helper origin must join that tree.
    The executing package must reside in that exact physical checkout, so all
    __file__-anchored policy/catalog/caller inputs share its authenticated root.
    """
    import rs9
    try:
        executing = Path(__file__).absolute().parent
        selected = Path(root)/"src/rs9"
        _require_selected_execution_root(executing, root)
        if (Path(rs9.__file__).absolute() != executing/"__init__.py" or
                list(rs9.__path__) != [str(executing)] or
                rs9.__spec__ is None or rs9.__spec__.origin != str(executing/"__init__.py")):
            fail("Executing RS9 package origin differs", "OWN_REPOSITORY_SOURCE")
        names = {p.name for p in executing.glob("*.py")}
        if names != {p.name for p in selected.glob("*.py")}:
            fail("Executing RS9 source inventory differs", "OWN_REPOSITORY_SOURCE")
        for name in sorted(names):
            if held(executing/name) != held(selected/name):
                fail("Executing RS9 helper bytes differ from selected checkout", "OWN_REPOSITORY_SOURCE")
        for name, module in list(sys.modules.items()):
            if name == "rs9" or name.startswith("rs9."):
                leaf = "__init__.py" if name == "rs9" else name.removeprefix("rs9.")+".py"
                expected = executing/leaf
                if (leaf not in names or module is None or
                        getattr(module, "__file__", None) != str(expected) or
                        getattr(module, "__spec__", None) is None or module.__spec__.origin != str(expected)):
                    fail("Mixed RS9 helper package origin", "OWN_REPOSITORY_SOURCE")
                for value in vars(module).values():
                    if inspect.isfunction(value) and value.__module__.startswith("rs9."):
                        unwrapped = inspect.unwrap(value)
                        if not inspect.isfunction(unwrapped):
                            fail("Mixed RS9 imported helper type", "OWN_REPOSITORY_SOURCE")
                        origin = Path(unwrapped.__code__.co_filename)
                        if origin.parent != executing or origin.name not in names:
                            fail("Mixed RS9 imported helper origin", "OWN_REPOSITORY_SOURCE")
    except (OSError, TypeError, AttributeError, ValueError):
        fail("Executing RS9 helper source unavailable", "OWN_REPOSITORY_SOURCE")


def consumer_source(config, root, commit, tree):
    """Locators are checked against fixed main/source/body/descriptor authority."""
    root=physical_directory(root)
    if (not CONSUMER_FILE_HASHES or IMPORTER not in CONSUMER_FILE_HASHES or
            any(not re.fullmatch("[0-9a-f]{40}",value or "") for value in (commit,tree))):
        fail("Exact paired consumer source required", "OWN_REPOSITORY_SOURCE")
    if source_tree_identity(root,commit)!=tree:
        fail("Clean consumer tree differs", "OWN_REPOSITORY_SOURCE")
    def api(endpoint):
        value=_json(gh_read(root,["api","--hostname","github.com","--method","GET",f"repos/{TARGET}/{endpoint}"]))
        if not isinstance(value,dict):fail("Consumer source API object required", "OWN_REPOSITORY_SOURCE")
        return value
    ref=api("git/ref/heads/main")
    actual=api("git/commits/"+commit)
    listing=api("git/trees/"+tree+"?recursive=1")
    if (ref.get("object",{}).get("type")!="commit" or ref.get("object",{}).get("sha")!=commit or
            actual.get("sha")!=commit or actual.get("tree",{}).get("sha")!=tree or
            listing.get("sha")!=tree or listing.get("truncated") is not False or not isinstance(listing.get("tree"),list)):
        fail("Adopted fixed P main source differs", "OWN_REPOSITORY_SOURCE")
    rows={}
    for row in listing["tree"]:
        if not isinstance(row,dict) or not isinstance(row.get("path"),str) or row["path"] in rows:
            fail("Malformed consumer tracked tree", "OWN_REPOSITORY_SOURCE")
        rows[row["path"]]=row
    files={}
    for name in sorted(set(CONSUMER_FILE_HASHES)|{DESCRIPTOR}):
        row=rows.get(name,{})
        if row.get("type")!="blob" or row.get("mode") not in {"100644","100755"}:
            fail("Required consumer path is not tracked blob", "OWN_REPOSITORY_SOURCE")
        data=held(root/name)
        blob=hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest()
        value=hashlib.sha256(data).hexdigest()
        if blob!=row.get("sha") or (name in CONSUMER_FILE_HASHES and value!=CONSUMER_FILE_HASHES[name]):
            fail("Tracked/executing consumer bytes differ", "OWN_REPOSITORY_SOURCE")
        files[name]=value
        if name==DESCRIPTOR:descriptor=_json(data)
    if not isinstance(descriptor,dict) or set(descriptor)!={"schema","generation","status","production_enabled","publication_authority","rs9"}:
        fail("Closed tracked descriptor required", "OWN_REPOSITORY_SOURCE")
    if (descriptor["schema"]!="theme-forge.current-rs9-input-source.v1" or descriptor["generation"]!=CURRENT_GENERATION or
            descriptor["production_enabled"] is not False or descriptor["publication_authority"] is not False):
        fail("Nonproduction current descriptor required", "OWN_REPOSITORY_SOURCE")
    if descriptor["status"]!="qualified-original-run-inputs" or not isinstance(descriptor["rs9"],dict):
        fail("No qualified original run adopted in descriptor", "OWN_REPOSITORY_UNADMITTED")
    expected={**config.expected(),"not_before":config.not_before.isoformat()}
    if descriptor["rs9"]!=expected or expected["repository"]!=RS9_REPOSITORY:
        fail("Descriptor differs from fresh original-run configuration", "OWN_REPOSITORY_SOURCE")
    record={"hostname":"github.com","repository":TARGET,"commit":commit,"tree":tree,"files":files,
            "consumer_contract":"current-four-unsigned-inputs.v1","descriptor_sha256":files[DESCRIPTOR]}
    binding=_Consumer(record,digest(config.expected()),_PROOF)
    _CONSUMERS[binding]=(digest(record),binding.expected_sha256)
    return binding


def release_consumer(binding):
    _CONSUMERS.pop(binding,None)


@dataclass(frozen=True,eq=False)
class _Admission:
    ledger: tuple
    record: dict
    _proof: object


def release(proof):
    _ACTIVE.pop(proof,None)


def check_lane(proof,lane,receipt,manifest):
    if type(proof) is not _Admission or proof._proof is not _PROOF or _ACTIVE.get(proof)!=digest(proof.record):
        fail("Live recomputed scope proof required")
    row=(lane["lane"],lane["system"],digest(receipt),digest(manifest))
    if row not in proof.ledger:fail("Scope proof does not cover actual lane bytes")


def _restriction(lane,receipt):
    tokens,errors=promotion_restrictions(lane,receipt)
    if errors:fail("Malformed or missing restriction provenance")
    accepted=any(p.get("accepted_findings") for p in receipt.get("details",{}).get("rpm_lint_policy",{}).values()) if lane["lane"]=="rpm" else False
    expected=[RPM_POLICY_PROMOTION_BLOCKER] if accepted else []
    if tokens!=expected or receipt.get("production_promotion_blockers")!=expected:
        fail("Unknown, misplaced or gratuitous promotion restriction")
    return tokens


def admit(repository,output,summary,expected,consumer):
    """All original technical validation has already run; rejoin physical proof."""
    if (type(consumer) is not _Consumer or consumer._proof is not _PROOF or
            _CONSUMERS.get(consumer)!=(digest(consumer.record),digest(expected)) or
            consumer.record.get("repository")!=TARGET):
        fail("Fresh fixed-consumer source proof required")
    selected=load_policy(repository/rpm_policy_path(CURRENT_GENERATION),generation=CURRENT_GENERATION)
    if (selected.get("generation")!=CURRENT_GENERATION or selected.get("status")!="authorized" or
            selected.get("blocking") is not False or set(selected.get("projects",{}))!=set(VERSIONS)):
        fail("Complete adopted current policy required", "CURRENT_RPM_POLICY_HELD")
    policy_hash=digest(selected);ledger=[];limitations=[];rpm_systems=set()
    receipts={(r["lane"],r["system"]):r for r in summary["receipts"]}
    manifests={(r["lane"],r["system"]):r for r in summary["artifact_manifests"]}
    for lane in required(repository,generation=CURRENT_GENERATION):
        key=lane["lane"],lane["system"];directory=output/lane["artifact_name"]
        manifest=verify_set(directory,expected_provenance=expected)
        receipt=_json(held(directory/(lane["lane"]+"-"+lane["system"]+".json"),16*1024*1024))
        if manifest!=manifests.get(key) or receipt!=receipts.get(key):fail("Scoped custody differs from validated original")
        tokens=_restriction(lane,receipt)
        if lane["lane"]=="rpm":
            rpm_systems.add(lane["system"])
            validate_rpm_policy_source(repository,receipt,generation=CURRENT_GENERATION)
            raw_projections=verify_rpm_custody(directory,manifest,receipt)
            details=receipt.get("details",{});policies=details.get("rpm_lint_policy",{});raws=details.get("rpm_lint_raw",{})
            if set(policies)!=set(VERSIONS) or set(raws)!=set(VERSIONS):fail("Exact four current raw/policy products required")
            for product,version in VERSIONS.items():
                evaluation=verify_policy_custody(directory,manifest,policies[product]);raw=raws[product]
                entry=selected["projects"][product];inputs=evaluation.get("inputs",{})
                if (entry.get("version")!=version or entry.get("status")!="authorized" or entry.get("blocking") is not False or
                        evaluation.get("accepted") is not True or evaluation.get("status") not in {"accepted","accepted-no-exceptions"} or
                        evaluation.get("blockers")!=[] or evaluation.get("rule_blockers",[])!=[] or
                        evaluation.get("policy_sha256")!=policy_hash or _raw_blockers(raw,selected) or
                        inputs.get("project_id")!=product or inputs.get("version")!=version or inputs.get("system")!=lane["system"] or
                        inputs.get("arch") not in entry["allowed_architectures"] or
                        inputs.get("payload_manifest_sha256")!=entry.get("inventory_bindings",{}).get(lane["system"],{}).get("payload_manifest_sha256") or
                        not re.fullmatch("[0-9a-f]{64}",evaluation.get("inventory_sha256","") or "")):
                    fail("Incomplete current preservation/native evaluation")
                auth=entry["authenticated_inputs"]
                assets=({row["sha256"] for row in auth["assets"]
                         if row["name"].endswith("-"+lane["system"].removesuffix("-linux")+"-unknown-linux-gnu.tar.gz")}
                        if "assets" in auth else {auth.get("asset_sha256")})
                if inputs.get("asset_sha256") not in assets or inputs.get("closure_sha256")!=auth.get("closure_sha256"):
                    fail("Policy/capture asset or closure differs")
                if evaluation.get("accepted_findings",[])!=raw.get("error_records",[]):
                    fail("Accepted error set differs from complete retained raw set")
                limitations.append({"system":lane["system"],"product":product,
                                    "raw_status":raw.get("status"),"raw_clean":raw.get("clean"),
                                    "raw_counts":raw.get("findings_summary"),"raw_sha256":digest(raw),
                                    "raw_custody":raw_projections[product],
                                    "policy_evaluation_sha256":digest(evaluation),"policy_sha256":policy_hash})
        ledger.append((*key,digest(receipt),digest(manifest)))
    union=sorted({token for receipt in receipts.values() for token in receipt.get("production_promotion_blockers",[])})
    if (rpm_systems!={"x86_64-linux","aarch64-linux"} or summary.get("production_promotion_blockers")!=union or
            summary.get("production_promotion_blocked") is not bool(union)):
        fail("Conservative summary restriction union differs")
    record={"schema":"rs9.theme-forge-own-repository-admission.v1","target":TARGET,"scope":"unsigned-current-four-inputs",
            "consumer_source":consumer.record,"original_source":dict(expected),"original_restrictions":union,"original_summary_sha256":digest(summary),
            "lane_custody":[{"lane":row[0],"system":row[1],"receipt_sha256":row[2],"manifest_sha256":row[3]} for row in ledger],
            "original_production_promotion_blocked":bool(union),"policy_sha256":policy_hash,"raw_policy_evidence":limitations,
            "raw_clean_claim":False,"official_fedora_qualification_claim":False,
            "production_enabled":False,"publication_authority":False,"signing_authority":False,"assembly_ready":False}
    proof=_Admission(tuple(ledger),record,_PROOF);_ACTIVE[proof]=digest(record)
    return proof
