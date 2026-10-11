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
from rs9.product_classes import (
    NATIVE_PACKAGING_MAPPINGS,
    extract_package_arch,
    get_product_class,
    is_pure_js_cli,
    supported_architectures,
)
from rs9.package_roles import is_installable_binary, verify_package_roles


# Bounded substages
FOUNDATION_SUBSTAGES: tuple[str, ...] = (
    "selection",
    "roles",
    "architecture",
    "inventory",
    "adapter-output",
    "qualification",
    "observation",
    "plan",
    "serialization",
)

FOUNDATION_SELECTION_ERROR: str = "FOUNDATION_SELECTION"
FOUNDATION_ROLES_ERROR: str = "FOUNDATION_ROLES"
FOUNDATION_ARCHITECTURE_ERROR: str = "CUSTODY_ARCHITECTURE"
FOUNDATION_INVENTORY_ERROR: str = "FOUNDATION_INVENTORY"
FOUNDATION_ADAPTER_OUTPUT_ERROR: str = "FOUNDATION_ADAPTER_OUTPUT"
FOUNDATION_QUALIFICATION_ERROR: str = "FOUNDATION_QUALIFICATION"
FOUNDATION_OBSERVATION_ERROR: str = "FOUNDATION_OBSERVATION"
FOUNDATION_PLAN_ERROR: str = "FOUNDATION_PLAN"
FOUNDATION_SERIALIZATION_ERROR: str = "FOUNDATION_SERIALIZATION"

FOUNDATION_SUBSTAGE_ERROR_CODES: dict[str, str] = {
    "selection": FOUNDATION_SELECTION_ERROR,
    "roles": FOUNDATION_ROLES_ERROR,
    "architecture": FOUNDATION_ARCHITECTURE_ERROR,
    "inventory": FOUNDATION_INVENTORY_ERROR,
    "adapter-output": FOUNDATION_ADAPTER_OUTPUT_ERROR,
    "qualification": FOUNDATION_QUALIFICATION_ERROR,
    "observation": FOUNDATION_OBSERVATION_ERROR,
    "plan": FOUNDATION_PLAN_ERROR,
    "serialization": FOUNDATION_SERIALIZATION_ERROR,
}


class FoundationExecutionError(ContractError):
    """Bounded foundation execution error capturing product, adapter, substage, and code."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        product: str = "",
        adapter: str = "",
        substage: str = "",
        details: dict | None = None,
        partial_result: dict | None = None,
    ) -> None:
        err_details = {"product": product, "adapter": adapter, "substage": substage, "code": code}
        if details:
            err_details.update(details)
        super().__init__(code, message, details=err_details)
        self.product = product
        self.adapter = adapter
        self.substage = substage
        self.bounded_error = {
            "product": product,
            "adapter": adapter,
            "substage": substage,
            "code": code,
        }
        self.partial_result = partial_result


def wheel_architecture_set(product, filenames):
    observed = set()
    for filename in filenames:
        platform = filename.removesuffix(".whl").rsplit("-", 1)[-1]
        if is_pure_js_cli(product):
            if platform != "any":
                raise ContractError("CUSTODY_ARCHITECTURE", "Pure JS wheel architecture changed")
            observed.add("any")
        elif platform in ("linux_x86_64", "linux_aarch64"):
            observed.add(platform)
        elif platform == "macosx_13_0_arm64":
            observed.add(platform)
        else:
            raise ContractError("CUSTODY_ARCHITECTURE", "Native wheel has an unqualified architecture tag")
    return observed


def publication_policy(product, architectures):
    return {"package_class": get_product_class(product), "qualified_architectures": sorted(architectures)}


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


def resolve_destination_binding(intent, capture, adapter, family, product, policy, payloads):
    """Bind adapter output destination and identity to normalized intent targets if present, else fallback."""
    if "targets" in intent:
        targets = intent.get("targets")
        if not isinstance(targets, list):
            raise ContractError("OUTPUT_BINDING", "Targets must be a list of normalized targets")
        matching = [t for t in targets if isinstance(t, dict) and t.get("adapter") == adapter]
        if not matching:
            raise ContractError("OUTPUT_BINDING", f"Target absent for adapter {adapter}")
        direct = [t for t in matching if t.get("mode") == "direct"]
        if len(direct) > 1:
            raise ContractError("OUTPUT_BINDING", f"Ambiguous direct targets for adapter {adapter}")
        if not direct and len(matching) > 1:
            raise ContractError("OUTPUT_BINDING", f"Ambiguous targets for adapter {adapter}")
        target = direct[0] if direct else matching[0]
        dest_id = target["destination"]
        mode = target.get("mode", "direct")
        package_name = target.get("name", product)
        target_id = target.get("package", product)
        semantics = {
            "project": intent["project"],
            "target": target,
            "license": intent["license"],
            "commands": intent.get("commands", {}),
            "checks": intent.get("checks", {}),
            "desktop": intent.get("desktop"),
            "runtime": intent.get("runtime"),
            "source_files": capture.record.get("source_files", []),
        }
        config = {
            "semantic-inputs": record_sha256(semantics),
            "packaging_policy": record_sha256(policy),
        }
    else:
        dest_id = family if family != adapter else adapter
        mode = "direct"
        package_name = product
        target_id = product
        config = {
            "configuration": record_sha256(intent),
            "packaging_policy": record_sha256(policy),
        }
    identity = build_semantic_content_identity(
        product, intent["version"], target_id, adapter, payloads, config
    )
    dest = {"id": dest_id, "adapter": adapter, "mode": mode}
    return dest, package_name, identity


def execute(context):
    inputs = context.get("inputs")
    artifacts, records, missing = [], [], []
    custody_error = None
    annex = []
    native_sets = []

    if not inputs or not Path(inputs).is_dir():
        missing.append("candidate-custody-inputs")

    current_adapter = "pypi"
    for capture, intent, profile in context.get("captures", []):
        product = intent["project"]["id"]
        substage = "selection"
        try:
            substage = "selection"
            stem = product.replace("-", "_")
            # Foundation 3 verifies exact wheel candidates in-process; native-client
            # and repository evidence remains a separately hashed annex, not imported authority.
            matches = sorted(Path(inputs).rglob(stem + "-" + intent["version"] + "-*.whl")) if inputs else []
            if not matches:
                missing.append(product + ":wheel-custody")
                continue

            substage = "architecture"
            expected_wheels = supported_architectures(product, "pypi")
            observed_wheels = wheel_architecture_set(product, [p.name for p in matches])
            if observed_wheels != expected_wheels:
                missing.extend(product + ":wheel:" + arch + ":custody" for arch in sorted(expected_wheels - observed_wheels))
                continue

            substage = "inventory"
            policy = publication_policy(product, expected_wheels)
            root = context["scratch"] / product
            root.mkdir(exist_ok=True)
            rows = []
            for source in matches:
                existing = next((r for r in rows if r["path"] == source.name), None)
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

            substage = "adapter-output"
            payloads = {p["name"]: p["sha256"] for p in (capture.record.get("payloads") or capture.record.get("assets") or [])}
            dest, pkg_name, identity = resolve_destination_binding(intent, capture, "pypi", "pypi", product, policy, payloads)
            output = adapter_output(
                dest,
                {"package": pkg_name, "version": intent["version"], "revision": None},
                identity,
                inventory,
                {"release_record_sha256": authenticated_record_hash(capture), "wheel_inventory": rows, **policy},
                implementation={"id": "rs9-hosted-candidate", "version": "v1alpha1"},
                source_version="LIVE1-CONT2",
            )

            substage = "qualification"
            qualification = execute_qualification(
                capture,
                output,
                "pypi.wheel-record",
                root,
                verify_candidate_files,
                verifier_id="rs9-independent-wheel-inventory",
                verifier_source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                environment={"purpose": "non-production-hosted-candidate"},
                trust_root="hosted-candidate-unattested",
            )

            substage = "observation"
            observation = read_pypi_project(output)

            substage = "plan"
            proposal = plan(
                intent,
                capture,
                profile,
                output,
                derive_gates(intent, capture, profile, output),
                destination_policy(enabled=False),
                observation,
                evaluated_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            )

            substage = "serialization"
            record_path = root / "qualification-record.json"
            record_path.write_bytes(canonical(qualification))
            plan_path = root / "publication-plan.json"
            plan_path.write_bytes(canonical(proposal))
            artifacts.extend([record_path, plan_path])
            records.append({
                "project": product,
                "adapter": "pypi",
                "qualification_record_sha256": record_sha256(qualification),
                "plan_sha256": record_sha256(proposal),
                "outcome": proposal["outcome"],
            })
        except Exception as error:
            code = error.code if isinstance(error, ContractError) else FOUNDATION_SUBSTAGE_ERROR_CODES.get(substage, "FOUNDATION_ERROR")
            bounded_error = {
                "product": product,
                "adapter": current_adapter,
                "substage": substage,
                "code": code,
            }
            doc = {
                "schema": "rs9.hosted-foundation3.v1alpha1",
                "production_enabled": False,
                "attended_gates_satisfied": False,
                "qualification_records": records,
                "missing_inputs": missing,
                "hosted_evidence_annex": annex,
                "production_receipts": [],
                "rpm_lint_results": [],
                "failed_records": [bounded_error],
            }
            path = context["scratch"] / "foundation3.json"
            path.write_bytes(canonical(doc))
            artifacts.append(path)
            details = {
                "missing_inputs": missing,
                "records": records,
                "production_receipt_count": 0,
                "failed_records": [bounded_error],
                "failure": bounded_error,
            }
            partial_result = {
                "gates": [
                    {"name": "foundation3-plan-assembly", "status": "fail", "reason": code},
                    {"name": "publication-readiness-evaluation", "status": "fail", "reason": code},
                ],
                "artifacts": artifacts,
                "details": details,
            }
            if not context.get("raise_on_error", True):
                return partial_result
            raise FoundationExecutionError(
                code,
                f"[{code}] {substage} failed for {product} on {current_adapter}",
                product=product,
                adapter=current_adapter,
                substage=substage,
                details=getattr(error, "details", None),
                partial_result=partial_result,
            ) from error

    valid_native_sets = []
    if inputs and Path(inputs).is_dir():
        for path in Path(inputs).rglob("artifact-manifest.json"):
            try:
                native_sets.append((path.parent, verify_set(path.parent)))
            except (ContractError, OSError, ValueError, KeyError) as error:
                custody_error = error.code if isinstance(error, ContractError) else "CUSTODY_SCHEMA"
                missing.append("native-custody-invalid:" + custody_error)

        for directory, manifest in native_sets:
            try:
                verify_package_roles(directory, manifest)
                valid_native_sets.append((directory, manifest))
            except (ContractError, OSError, ValueError, KeyError) as err:
                code = err.code if isinstance(err, ContractError) else "CUSTODY_ROLE"
                custody_error = code
                missing.append(f"package-roles-invalid:{code}")

    from rs9.hosted_summary import rpm_lint_results
    rpm_receipts, receipts_by_directory = [], {}
    for directory, manifest in native_sets:
        if manifest.get("lane") != "rpm":
            continue
        try:
            receipt = json.loads((directory / ("rpm-" + manifest["system"] + ".json")).read_bytes())
            if (not isinstance(receipt, dict) or receipt.get("lane") != "rpm"
                    or receipt.get("system") != manifest["system"]
                    or not isinstance(receipt.get("details"), dict)):
                raise ContractError("RPM_POLICY_CUSTODY", "RPM receipt identity or details malformed")
            rpm_receipts.append(receipt)
            receipts_by_directory[directory] = receipt
        except (ContractError, OSError, ValueError, KeyError, TypeError) as error:
            custody_error = error.code if isinstance(error, ContractError) else "RPM_POLICY_CUSTODY"
            missing.append("rpm-custody-invalid:" + custody_error)
    from rs9.hosted_summary import validate_rpm_policy_custody
    verified_native_sets = []
    for directory, manifest in valid_native_sets:
        if manifest.get("lane") == "rpm":
            receipt = receipts_by_directory.get(directory)
            if receipt is not None:
                try:
                    validate_rpm_policy_custody(directory, manifest, receipt)
                    verified_native_sets.append((directory, manifest))
                except (ContractError, OSError, ValueError, KeyError, TypeError, AttributeError) as err:
                    custody_code = err.code if isinstance(err, ContractError) else "RPM_POLICY_CUSTODY"
                    custody_error = custody_code
                    missing.append(f"rpm-custody-invalid:{custody_code}")
        else:
            verified_native_sets.append((directory, manifest))

    for mapping in NATIVE_PACKAGING_MAPPINGS:
        family = mapping.family
        format_key = mapping.format
        canonical_adapter = mapping.canonical_adapter
        revision_scheme = mapping.revision_scheme
        current_adapter = canonical_adapter

        for capture, intent, profile in context.get("captures", []):
            product = intent["project"]["id"]
            substage = "selection"
            try:
                substage = "selection"
                expected_archs = supported_architectures(product, format_key)

                substage = "roles"
                candidates = [
                    (directory, row)
                    for directory, manifest in verified_native_sets
                    if manifest["lane"] == family
                    for row in manifest["files"]
                    if row.get("kind") == "custody"
                    and Path(row["path"]).name.startswith(product)
                    and "custody" in row["path"]
                    and row.get("promotion") != "fixture-test-only"
                    and is_installable_binary(row)
                ]
                if not candidates:
                    missing.append(family + ":" + product + ":custody")
                    continue

                substage = "architecture"
                observed_archs = {extract_package_arch(Path(row["path"]).name) for _, row in candidates}
                if observed_archs - expected_archs:
                    raise ContractError("CUSTODY_ARCHITECTURE", "Native package custody includes an unqualified architecture")
                missing_archs = expected_archs - observed_archs
                if missing_archs:
                    for a in sorted(missing_archs):
                        missing.append(f"{family}:{product}:{a}:custody")
                    continue

                substage = "inventory"
                root = context["scratch"] / (family + "-" + product)
                root.mkdir(exist_ok=True)
                rows = []
                # Retain conflicting equal filenames under immutable hash namespaces.
                for directory, row in candidates:
                    name = row["sha256"][:16] + "/" + Path(row["path"]).name
                    if any(r["path"] == name for r in rows):
                        continue
                    path = root / name
                    path.parent.mkdir(exist_ok=True)
                    shutil.copyfile(directory / row["path"], path)
                    rows.append({"path": name, "sha256": row["sha256"], "size": row["size"]})
                inventory_path = root / "inventory.json"
                inventory_path.write_bytes(canonical(rows))
                inventory = rows + [{
                    "path": "inventory.json",
                    "size": inventory_path.stat().st_size,
                    "sha256": hashlib.sha256(inventory_path.read_bytes()).hexdigest(),
                }]

                substage = "adapter-output"
                payload_dict = {p["name"]: p["sha256"] for p in (capture.record.get("payloads") or capture.record.get("assets") or [])}
                policy = publication_policy(product, expected_archs)
                dest, pkg_name, identity = resolve_destination_binding(intent, capture, canonical_adapter, family, product, policy, payload_dict)
                extra_manifest = {
                    "release_record_sha256": authenticated_record_hash(capture),
                    "unsigned_packages": rows,
                    "architecture_set": sorted(expected_archs),
                    **policy,
                    **({"rpm_lint_results": [r for r in rpm_lint_results(rpm_receipts) if r["product"] == product],
                        "required_candidate_lint_gate": "rpm-lint-policy-accepted"} if family == "rpm" else {}),
                }
                output = adapter_output(
                    dest,
                    {"package": pkg_name, "version": intent["version"], "revision": 1},
                    identity,
                    inventory,
                    extra_manifest,
                    implementation={"id": "rs9-hosted-candidate", "version": "v1alpha1"},
                    source_version="LIVE1-CONT2",
                    revision_scheme=revision_scheme,
                )

                substage = "qualification"
                qualification = execute_qualification(
                    capture,
                    output,
                    f"{format_key}.candidate-inventory",
                    root,
                    verify_candidate_files,
                    verifier_id="rs9-independent-native-inventory",
                    verifier_source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                    environment={"purpose": "non-production-hosted-candidate"},
                    trust_root="hosted-candidate-unattested",
                )

                substage = "observation"
                observed = observe(
                    output["destination"],
                    output["subject"],
                    expected_components(output),
                    output["content_identity_sha256"],
                    readback={
                        "authenticated": False,
                        "transport": "unknown",
                        "presence": "unknown",
                        "components": {},
                        "content_identity_sha256": None,
                        "level": "none",
                    },
                    source="adapter-readback",
                    observed_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                    reader={"id": "hosted-planning-disabled", "version": "v1alpha1"},
                )

                substage = "plan"
                proposal = plan(
                    intent,
                    capture,
                    profile,
                    output,
                    derive_gates(intent, capture, profile, output),
                    destination_policy(enabled=False),
                    observed,
                    evaluated_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                )

                substage = "serialization"
                qpath, ppath = root / "qualification-record.json", root / "publication-plan.json"
                qpath.write_bytes(canonical(qualification))
                ppath.write_bytes(canonical(proposal))
                artifacts.extend([qpath, ppath])
                records.append({
                    "project": product,
                    "adapter": canonical_adapter,
                    "native_format": format_key,
                    "qualification_record_sha256": record_sha256(qualification),
                    "plan_sha256": record_sha256(proposal),
                    "outcome": proposal["outcome"],
                })
            except Exception as error:
                code = error.code if isinstance(error, ContractError) else FOUNDATION_SUBSTAGE_ERROR_CODES.get(substage, "FOUNDATION_ERROR")
                bounded_error = {
                    "product": product,
                    "adapter": current_adapter,
                    "substage": substage,
                    "code": code,
                }
                doc = {
                    "schema": "rs9.hosted-foundation3.v1alpha1",
                    "production_enabled": False,
                    "attended_gates_satisfied": False,
                    "qualification_records": records,
                    "missing_inputs": missing,
                    "hosted_evidence_annex": annex,
                    "production_receipts": [],
                    "rpm_lint_results": rpm_lint_results(rpm_receipts) if 'rpm_receipts' in locals() else [],
                    "failed_records": [bounded_error],
                }
                path = context["scratch"] / "foundation3.json"
                path.write_bytes(canonical(doc))
                artifacts.append(path)
                details = {
                    "missing_inputs": missing,
                    "records": records,
                    "production_receipt_count": 0,
                    "failed_records": [bounded_error],
                    "failure": bounded_error,
                }
                partial_result = {
                    "gates": [
                        {"name": "foundation3-plan-assembly", "status": "fail", "reason": code},
                        {"name": "publication-readiness-evaluation", "status": "fail", "reason": code},
                    ],
                    "artifacts": artifacts,
                    "details": details,
                }
                if not context.get("raise_on_error", True):
                    return partial_result
                raise FoundationExecutionError(
                    code,
                    f"[{code}] {substage} failed for {product} on {current_adapter}",
                    product=product,
                    adapter=current_adapter,
                    substage=substage,
                    details=getattr(error, "details", None),
                    partial_result=partial_result,
                ) from error

    if inputs:
        for path in sorted(Path(inputs).rglob("*-*.json")):
            if path.stat().st_size <= 512 * 1024:
                annex.append({"name": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    doc = {
        "schema": "rs9.hosted-foundation3.v1alpha1",
        "production_enabled": False,
        "attended_gates_satisfied": False,
        "qualification_records": records,
        "missing_inputs": missing,
        "hosted_evidence_annex": annex,
        "production_receipts": [],
    }
    doc["rpm_lint_results"] = rpm_lint_results(rpm_receipts)
    path = context["scratch"] / "foundation3.json"
    path.write_bytes(canonical(doc))
    artifacts.append(path)
    details = {"missing_inputs": missing, "records": records, "production_receipt_count": 0}
    if custody_error:
        details["custody_error"] = custody_error
    return {
        "gates": [
            {
                "name": "foundation3-plan-assembly",
                "status": "pass" if not missing and not custody_error else "fail",
                "reason": "fresh-in-process-verification" if not missing and not custody_error else "missing-custody-inputs",
            },
            {
                "name": "publication-readiness-evaluation",
                "status": "pass",
                "reason": "evaluated-as-disabled-attended-gates-unsatisfied",
            },
        ],
        "artifacts": artifacts,
        "details": details,
    }
