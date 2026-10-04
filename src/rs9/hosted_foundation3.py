"""Fresh deterministic candidate verification and Foundation 3 blocked plans."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil

from rs9.errors import ContractError
from rs9.gates import derive_gates
from rs9.planner import adapter_output, destination_policy, plan
from rs9.qualification import execute_qualification
from rs9.readers import read_pypi_project
from rs9.records import build_semantic_content_identity, record_sha256
from rs9.release_core import authenticated_record_hash
from rs9.scratch import canonical
from rs9.security import validate_safe_relative_posix_path
from rs9.wheel import verify_wheel_record_bidirectional
from rs9.pages import scan_binary_artifact
from rs9.hosted_custody import verify_set
from rs9.observation import observe
from rs9.planner import expected_components


def verify_candidate_files(root):
    """Independent rehash and strict wheel RECORD verification; never import CI PASS."""
    rows = json.loads((root / "inventory.json").read_bytes())
    if not rows or len({r["path"] for r in rows}) != len(rows):
        raise ContractError("FOUNDATION_INVENTORY", "Unique real candidate inventory required")
    for row in rows:
        validate_safe_relative_posix_path(row["path"])
        path = root / row["path"]
        if path.is_symlink() or not path.is_file():
            raise ContractError("FOUNDATION_INVENTORY", "Physical package bytes required")
        raw = path.read_bytes()
        if len(raw) != row["size"] or hashlib.sha256(raw).hexdigest() != row["sha256"]:
            raise ContractError("FOUNDATION_INVENTORY", "Retained candidate identity changed")
        if path.suffix == ".whl":
            verify_wheel_record_bidirectional(path)
        else:
            scanned = scan_binary_artifact(raw, path.name)
            if scanned is None or not scanned["complete"]:
                raise ContractError("FOUNDATION_FORMAT", "Complete independent native-format verification required")
    observed = canonical(rows)
    return [{"id": "independent-candidate-hash-and-wheel-record", "exit_code": 0,
             "stdout_sha256": hashlib.sha256(observed).hexdigest(),
             "stderr_sha256": hashlib.sha256(b"").hexdigest()}]


def execute(context):
    inputs = context.get("inputs")
    artifacts, records, missing = [], [], []
    if not inputs or not Path(inputs).is_dir():
        missing.append("candidate-custody-inputs")
    for capture, intent, profile in context["captures"]:
        product = intent["project"]["id"]
        stem = product.replace("-", "_")
        # Foundation 3 verifies exact wheel candidates in-process; native-client
        # and repository evidence remains a separately hashed annex, not imported authority.
        matches = sorted(Path(inputs).rglob(stem + "-" + intent["version"] + "-*.whl")) if inputs else []
        if not matches:
            missing.append(product + ":wheel-custody")
            continue
        root = context["scratch"] / product
        root.mkdir()
        rows = []
        for source in matches:
            existing = next((r for r in rows if r["path"] == source.name),None)
            if existing and hashlib.sha256(source.read_bytes()).hexdigest() == existing["sha256"]:
                continue
            if source.is_symlink() or existing:
                raise ContractError("FOUNDATION_CUSTODY", "Duplicate or linked wheel custody")
            target = root / source.name
            shutil.copyfile(source, target)
            raw = target.read_bytes()
            rows.append({"path": target.name, "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
        inventory_path = root / "inventory.json"
        inventory_path.write_bytes(canonical(rows))
        raw = inventory_path.read_bytes()
        inventory = rows + [{"path": inventory_path.name, "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}]
        payloads = {p["name"]: p["sha256"] for p in capture.record["payloads"]}
        identity = build_semantic_content_identity(product, intent["version"], product, "pypi", payloads,
                                                  {"configuration": record_sha256(intent)})
        output = adapter_output({"id": "pypi", "adapter": "pypi", "mode": "direct"},
            {"package": product, "version": intent["version"], "revision": None}, identity, inventory,
            {"release_record_sha256": authenticated_record_hash(capture), "wheel_inventory": rows},
            implementation={"id": "rs9-hosted-candidate", "version": "v1alpha1"}, source_version="LIVE1-CONT2")
        qualification = execute_qualification(capture, output, "pypi.wheel-record", root, verify_candidate_files,
            verifier_id="rs9-independent-wheel-inventory", verifier_source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            environment={"purpose": "non-production-hosted-candidate"}, trust_root="hosted-candidate-unattested")
        observation = read_pypi_project(output)
        proposal = plan(intent, capture, profile, output, derive_gates(intent, capture, profile, output),
                        destination_policy(enabled=False), observation,
                        evaluated_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"))
        record_path = root / "qualification-record.json"
        record_path.write_bytes(canonical(qualification))
        plan_path = root / "publication-plan.json"
        plan_path.write_bytes(canonical(proposal))
        artifacts.extend([record_path, plan_path])
        records.append({"project": product, "qualification_record_sha256": record_sha256(qualification),
                        "plan_sha256": record_sha256(proposal), "outcome": proposal["outcome"]})
    annex = []
    # Native family plans retain real package bytes and repeat deterministic
    # structure/privacy verification in-process. Client verdicts stay an annex.
    native_sets = []
    if inputs:
        native_sets = [(p.parent,verify_set(p.parent)) for p in Path(inputs).rglob("artifact-manifest.json")]
    for family, adapter in (("deb","debian"),("rpm","rpm"),("pacman","pacman")):
        for capture,intent,profile in context["captures"]:
            product = intent["project"]["id"]
            candidates = [(directory,row) for directory,manifest in native_sets if manifest["lane"] == family
                          for row in manifest["files"] if row["kind"] == "custody" and row["path"].split("/")[-1].startswith(product)
                          and "custody" in row["path"] and row.get("promotion") != "fixture-test-only"]
            if not candidates:
                missing.append(family + ":" + product + ":custody")
                continue
            root = context["scratch"] / (family + "-" + product)
            root.mkdir()
            rows = []
            # Retain conflicting equal filenames under immutable hash namespaces.
            for directory,row in candidates:
                name = row["sha256"][:16] + "/" + Path(row["path"]).name
                if any(r["path"] == name for r in rows):
                    continue
                path = root / name
                path.parent.mkdir(exist_ok=True)
                shutil.copyfile(directory / row["path"],path)
                rows.append({"path":name,"sha256":row["sha256"],"size":row["size"]})
            inventory_path = root / "inventory.json"
            inventory_path.write_bytes(canonical(rows))
            inventory = rows + [{"path":"inventory.json","size":inventory_path.stat().st_size,
                                "sha256":hashlib.sha256(inventory_path.read_bytes()).hexdigest()}]
            identity = build_semantic_content_identity(product,intent["version"],product,adapter,
                {p["name"]:p["sha256"] for p in capture.record["payloads"]},{"configuration":record_sha256(intent)})
            output = adapter_output({"id":family,"adapter":adapter,"mode":"direct"},
                {"package":product,"version":intent["version"],"revision":1},identity,inventory,
                {"release_record_sha256":authenticated_record_hash(capture),"unsigned_packages":rows},
                implementation={"id":"rs9-hosted-candidate","version":"v1alpha1"},source_version="LIVE1-CONT2",
                revision_scheme={"deb":"apt-revision","rpm":"rpm-release","pacman":"pkgrel"}[family])
            qualification = execute_qualification(capture,output,adapter+".candidate-inventory",root,verify_candidate_files,
                verifier_id="rs9-independent-native-inventory",verifier_source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                environment={"purpose":"non-production-hosted-candidate"},trust_root="hosted-candidate-unattested")
            observed = observe(output["destination"],output["subject"],expected_components(output),output["content_identity_sha256"],
                readback={"authenticated":False,"transport":"unknown","presence":"unknown","components":{},
                    "content_identity_sha256":None,"level":"none"},source="adapter-readback",
                observed_at=datetime.now(timezone.utc).isoformat().replace("+00:00","Z"),
                reader={"id":"hosted-planning-disabled","version":"v1alpha1"})
            proposal = plan(intent,capture,profile,output,derive_gates(intent,capture,profile,output),
                destination_policy(enabled=False),observed,evaluated_at=datetime.now(timezone.utc).isoformat().replace("+00:00","Z"))
            qpath,ppath = root / "qualification-record.json",root / "publication-plan.json"
            qpath.write_bytes(canonical(qualification)); ppath.write_bytes(canonical(proposal))
            artifacts.extend([qpath,ppath])
            records.append({"project":product,"adapter":adapter,"qualification_record_sha256":record_sha256(qualification),
                            "plan_sha256":record_sha256(proposal),"outcome":proposal["outcome"]})
    if inputs:
        for path in sorted(Path(inputs).rglob("*-*.json")):
            if path.stat().st_size <= 512 * 1024:
                annex.append({"name": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    doc = {"schema": "rs9.hosted-foundation3.v1alpha1", "production_enabled": False,
           "attended_gates_satisfied": False, "qualification_records": records, "missing_inputs": missing,
           "hosted_evidence_annex": annex, "production_receipts": []}
    path = context["scratch"] / "foundation3.json"
    path.write_bytes(canonical(doc))
    artifacts.append(path)
    return {"gates": [{"name": "foundation3-plan-assembly", "status": "pass" if not missing else "fail",
                       "reason": "fresh-in-process-verification" if not missing else "missing-custody-inputs"},
                      {"name": "publication-readiness-evaluation", "status": "pass",
                       "reason": "evaluated-as-disabled-attended-gates-unsatisfied"}],
            "artifacts": artifacts, "details": {"missing_inputs": missing, "records": records,
            "production_receipt_count": 0}}
