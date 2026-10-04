"""Source-driven nonproduction hosted workflow authority, lane contracts, and gate schemas."""
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any

from rs9.errors import ContractError
from rs9.scratch import canonical, physical_directory
from rs9.security import scan_for_credentials, validate_safe_relative_posix_path

SCHEMA_HOSTED_DIAGNOSTIC = "rs9.hosted-candidate-diagnostic.v1alpha1"
SCHEMA_HOSTED_RECEIPTS = "rs9.hosted-candidate-receipts.v1alpha1"
SCHEMA_HOSTED_SUMMARY = "rs9.hosted-candidate-summary.v1alpha1"
SCHEMA_HOSTED_LANES = "rs9.hosted-lanes.v1alpha1"
SCHEMA_HOSTED_ARTIFACT_SET = "rs9.hosted-artifact-set.v1alpha1"

ARTIFACT_SET_FIELDS: tuple[str, ...] = (
    "schema",
    "commit",
    "production_enabled",
    "publication_authority",
    "artifacts",
)

ARTIFACT_RECORD_FIELDS: tuple[str, ...] = (
    "path",
    "sha256",
    "size",
)

_SOURCE_LANES = json.loads((Path(__file__).resolve().parents[2] / "operators/live1/hosted-lanes.json").read_bytes())["lanes"]
REQUIRED_RECEIPTS = tuple((r["lane"], r["system"]) for r in _SOURCE_LANES if r.get("module"))
REQUIRED_RECEIPT_FILES = frozenset(f"{lane}-{system}.json" for lane, system in REQUIRED_RECEIPTS)
REQUIRED_LANES = tuple(dict.fromkeys(r["lane"] for r in _SOURCE_LANES))
REQUIRED_GATES = {r["lane"]: r["required_gates"] for r in _SOURCE_LANES if r.get("module")}

POLICY_BLOCKERS: tuple[str, ...] = (
    "no-production-authority-in-hosted-candidate",
    "publication-disabled-by-tenant-policy",
    "manager-attended-disposition-required",
    "native-binary-custody-unreviewed",
    "signing-authority-unattested",
    "readiness-not-certified",
)


def canonical_release_auth_projection(data: dict) -> dict:
    """Project release authentication evidence to canonical form, strictly
    excluding ephemeral collected_at timestamps and redirect transport."""
    if not isinstance(data, dict):
        raise ContractError("INVALID_EVIDENCE", "Authentication data must be a dictionary")

    def _project_item(item: Any) -> Any:
        if isinstance(item, dict):
            clean = {}
            for k, v in item.items():
                if k in {
                    "collected_at",
                    "observed_at",
                    "timestamp",
                    "final_url",
                    "redirect",
                    "redirects",
                    "redirect_transport",
                }:
                    continue
                clean[k] = _project_item(v)
            return clean
        elif isinstance(item, list):
            return [_project_item(elem) for elem in item]
        return item

    projected = _project_item(data)
    if "projects" in projected and isinstance(projected["projects"], list):
        projected["projects"] = sorted(
            projected["projects"],
            key=lambda p: p.get("project", "") if isinstance(p, dict) else str(p),
        )
    return projected


def compute_auth_sha256(projection: dict) -> str:
    """Compute deterministic SHA-256 over canonical projection bytes."""
    return hashlib.sha256(canonical(projection)).hexdigest()


def load_hosted_lanes(repository: Path) -> dict:
    """Load and validate operators/live1/hosted-lanes.json."""
    lanes_path = physical_directory(repository) / "operators/live1/hosted-lanes.json"
    if not lanes_path.is_file():
        raise ContractError("LANES_MISSING", "operators/live1/hosted-lanes.json missing")
    raw = lanes_path.read_bytes()
    scan_for_credentials(raw.decode("utf-8"))
    try:
        doc = json.loads(raw)
    except Exception as exc:
        raise ContractError("LANES_SCHEMA", "Malformed hosted-lanes.json") from exc
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA_HOSTED_LANES:
        raise ContractError("LANES_SCHEMA", "Invalid hosted-lanes schema")
    if doc.get("production_enabled") is not False:
        raise ContractError("LANES_POLICY", "production_enabled must be false")
    if not isinstance(doc.get("lanes"), list):
        raise ContractError("LANES_SCHEMA", "Hosted lanes must be a list")
    return doc


def generate_matrix_outputs(lanes_doc: dict) -> dict[str, str]:
    """Generate workflow matrix JSON strings for GitHub Actions outputs."""
    lanes = lanes_doc.get("lanes", [])
    wheels = [
        {"system": l["system"], "runner": l["runner"], "job_name":l["lane"]+"-"+l["system"],
         "timeout_minutes": l["timeout_minutes"], "artifact_name": l["artifact_name"]}
        for l in lanes
        if l.get("lane") == "wheels"
    ]
    nix = [
        {"system": l["system"], "runner": l["runner"], "job_name":l["lane"]+"-"+l["system"],
         "timeout_minutes": l["timeout_minutes"], "artifact_name": l["artifact_name"]}
        for l in lanes
        if l.get("lane") == "nix"
    ]
    native = [
        {"lane": l["lane"], "system": l["system"], "runner": l["runner"], "job_name":l["lane"]+"-"+l["system"],
         "timeout_minutes": l["timeout_minutes"], "artifact_name": l["artifact_name"]}
        for l in lanes
        if l.get("lane") in {"pacman", "rpm", "deb"}
    ]
    candidate = [
        {"lane": l["lane"], "system": l["system"], "runner": l["runner"], "job_name":l["lane"]+"-"+l["system"],
         "timeout_minutes": l["timeout_minutes"], "artifact_name": l["artifact_name"]}
        for l in lanes
        if l.get("lane") not in {"unit", "summary"}
    ]
    return {
        "matrix_wheels": json.dumps({"include": wheels}, separators=(",", ":")),
        "matrix_nix": json.dumps({"include": nix}, separators=(",", ":")),
        "matrix_native": json.dumps({"include": native}, separators=(",", ":")),
        "matrix_candidate": json.dumps({"include": candidate}, separators=(",", ":")),
        "lanes": json.dumps(lanes, separators=(",", ":")),
    }


def validate_execution_context(context: dict) -> None:
    """Validate amended shared interface context keys."""
    if not isinstance(context, dict):
        raise ContractError("CONTEXT_INVALID", "Context must be a dictionary")
    if not isinstance(context.get("repository"), Path):
        raise ContractError("CONTEXT_INVALID", "context['repository'] must be a Path")
    if not isinstance(context.get("scratch"), Path):
        raise ContractError("CONTEXT_INVALID", "context['scratch'] must be a Path")
    if not isinstance(context.get("system"), str):
        raise ContractError("CONTEXT_INVALID", "context['system'] must be a string")


def validate_execution_result(result: dict) -> dict:
    """Validate amended shared interface result keys."""
    if not isinstance(result, dict):
        raise ContractError("RESULT_INVALID", "Result must be a dictionary")
    gates = result.get("gates")
    if not isinstance(gates, list):
        raise ContractError("RESULT_INVALID", "result['gates'] must be a list")
    for g in gates:
        if not isinstance(g, dict) or "name" not in g or g.get("status") not in {"pass", "fail", "not-run"}:
            raise ContractError("RESULT_INVALID", "Malformed gate record in result")
    artifacts = result.get("artifacts")
    if not isinstance(artifacts, list) or any(not isinstance(a, Path) for a in artifacts):
        raise ContractError("RESULT_INVALID", "result['artifacts'] must be a list of Path instances")
    details = result.get("details")
    if not isinstance(details, dict):
        raise ContractError("RESULT_INVALID", "result['details'] must be a dictionary")
    return result


def validate_hosted_summary(summary: Any, repository: Path, commit: str) -> dict:
    from rs9.hosted_summary import validate_summary
    if isinstance(summary, dict) and summary.get("schema") == "rs9.hosted-candidate-summary.v1alpha2":
        return validate_summary(summary, repository, commit)
    if isinstance(summary, (str, Path)) and (Path(summary) / "hosted-summary.json").is_file():
        return validate_summary(summary, repository, commit)
    """Validate fail-closed hosted summary completeness and provenance.
    Usable by parent operator validate_hosted_summary(summary, repository, commit)."""
    repository = physical_directory(repository)
    if isinstance(summary, (str, Path)):
        summary_path = physical_directory(Path(summary))
        if summary_path.is_dir():
            manifest_file = summary_path / "receipts-manifest.json"
            if not manifest_file.is_file():
                manifest_file = summary_path / "hosted-summary.json"
            if not manifest_file.is_file():
                raise ContractError("HOSTED_RECEIPTS", "Summary manifest missing in directory")
            raw = manifest_file.read_bytes()
        else:
            raw = summary_path.read_bytes()
        scan_for_credentials(raw.decode("utf-8"))
        try:
            record = json.loads(raw)
        except Exception as exc:
            raise ContractError("HOSTED_RECEIPTS", "Malformed summary JSON") from exc
        receipts_root = summary_path if summary_path.is_dir() else summary_path.parent
    elif isinstance(summary, dict):
        record = summary
        receipts_root = None
    else:
        raise ContractError("HOSTED_RECEIPTS", "Summary must be dict or Path")

    if not isinstance(record, dict):
        raise ContractError("HOSTED_RECEIPTS", "Summary must be a JSON object")

    valid_schemas = {SCHEMA_HOSTED_RECEIPTS, SCHEMA_HOSTED_SUMMARY}
    if record.get("schema") not in valid_schemas:
        raise ContractError("HOSTED_RECEIPTS", f"Summary schema must be one of {valid_schemas}")

    summary_commit = record.get("commit") or record.get("source_commit")
    if summary_commit != commit:
        raise ContractError("HOSTED_BINDING", "Summary commit mismatch")

    workflow_path = repository / ".github/workflows/rs9-candidate-tests.yml"
    if not workflow_path.is_file():
        raise ContractError("HOSTED_BINDING", "Workflow file missing from repository")
    expected_workflow_hash = hashlib.sha256(workflow_path.read_bytes()).hexdigest()
    if record.get("workflow_sha256") != expected_workflow_hash:
        raise ContractError("HOSTED_BINDING", "Summary workflow hash mismatch")

    if record.get("production_enabled") is not False:
        raise ContractError("HOSTED_POLICY", "production_enabled must be false")
    if record.get("publication_authority") is not False:
        raise ContractError("HOSTED_POLICY", "publication_authority must be false")

    if record.get("status") not in {"incomplete-candidate", "blocked"}:
        raise ContractError("HOSTED_POLICY", "Non-production summary status must fail closed; no fake PASS")

    # Provenance verification: push main attempt 1 only adoptable
    event = record.get("event")
    ref = record.get("ref")
    attempt = record.get("attempt")
    if record.get("adoptable") is True:
        if event != "push" or ref not in {"refs/heads/main", "main"} or str(attempt) != "1":
            raise ContractError("HOSTED_PROVENANCE", "Only push on main attempt 1 can claim adoptable")

    # Files / Receipts verification
    files = record.get("files")
    if not isinstance(files, list) or len(files) != len(REQUIRED_RECEIPTS):
        raise ContractError("HOSTED_RECEIPTS", f"Exact {len(REQUIRED_RECEIPTS)} receipt inventory required")

    file_paths = [r.get("path") for r in files if isinstance(r, dict)]
    if len(set(file_paths)) != len(REQUIRED_RECEIPTS) or set(file_paths) != REQUIRED_RECEIPT_FILES:
        raise ContractError("HOSTED_RECEIPTS", "Receipt filenames do not match required receipt set")

    # If physical directory available, verify disk files
    if receipts_root is not None:
        actual_files = {p.relative_to(receipts_root).as_posix() for p in receipts_root.rglob("*") if p.is_file() or p.is_symlink()}
        expected_files = REQUIRED_RECEIPT_FILES | {"receipts-manifest.json"}
        if (receipts_root / "hosted-summary.json").is_file():
            expected_files.add("hosted-summary.json")
        if actual_files != expected_files:
            raise ContractError("HOSTED_RECEIPTS", "Directory contains unexpected or missing receipt files")

    seen_keys = set()
    observed_auth_shas = set()
    for row in files:
        if not isinstance(row, dict) or "path" not in row or "size" not in row or "sha256" not in row:
            raise ContractError("HOSTED_RECEIPTS", "Malformed file row in summary")
        validate_safe_relative_posix_path(row["path"])

        if receipts_root is not None:
            path = receipts_root / row["path"]
            if any(p.is_symlink() for p in (path, *path.parents)) or not path.is_file() or path.stat().st_size > 512 * 1024:
                raise ContractError("HOSTED_RECEIPTS", f"Physical bounded receipt required for {row['path']}")
            data = path.read_bytes()
            scan_for_credentials(data.decode("utf-8"))
            if row != {"path": row["path"], "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}:
                raise ContractError("HOSTED_RECEIPTS", f"Receipt digest mismatch for {row['path']}")

            try:
                receipt_val = json.loads(data)
            except Exception as exc:
                raise ContractError("HOSTED_RECEIPTS", f"Receipt {row['path']} malformed JSON") from exc

            if not isinstance(receipt_val, dict):
                raise ContractError("HOSTED_RECEIPTS", f"Receipt {row['path']} must be JSON object")
            if receipt_val.get("schema") != SCHEMA_HOSTED_DIAGNOSTIC:
                raise ContractError("HOSTED_RECEIPTS", f"Receipt {row['path']} invalid schema")
            if receipt_val.get("source_commit") != commit:
                raise ContractError("HOSTED_BINDING", f"Receipt {row['path']} commit mismatch")
            if receipt_val.get("production_enabled") is not False:
                raise ContractError("HOSTED_RECEIPTS", f"Receipt {row['path']} cannot enable production")
            if receipt_val.get("publication_authority") is not False:
                raise ContractError("HOSTED_RECEIPTS", f"Receipt {row['path']} cannot claim publication authority")
            if receipt_val.get("mandatory_gates_satisfied") is not False:
                raise ContractError("HOSTED_RECEIPTS", f"Receipt {row['path']} cannot claim mandatory gates satisfied")
            if receipt_val.get("trust_root") != "hosted-candidate-unattested":
                raise ContractError("HOSTED_RECEIPTS", f"Receipt {row['path']} unexpected trust root")
            if receipt_val.get("status") not in {"blocked", "diagnostic-pass", "diagnostic-fail"}:
                raise ContractError("HOSTED_RECEIPTS", f"Receipt {row['path']} invalid status")

            lane, system = receipt_val.get("lane"), receipt_val.get("system")
            if f"{lane}-{system}.json" != row["path"]:
                raise ContractError("HOSTED_RECEIPTS", f"Receipt {row['path']} lane/system does not match filename")
            key = (lane, system)
            if key not in REQUIRED_RECEIPTS:
                raise ContractError("HOSTED_RECEIPTS", f"Receipt {row['path']} not in required receipt set")
            if key in seen_keys:
                raise ContractError("HOSTED_RECEIPTS", f"Duplicate receipt for {key}")
            seen_keys.add(key)

            auth_sha = receipt_val.get("authentication_sha256")
            if auth_sha:
                observed_auth_shas.add(auth_sha)

    # Mixed authentication provenance rejected
    if len(observed_auth_shas) > 1:
        raise ContractError("HOSTED_PROVENANCE", "Mixed authentication_sha256 across receipts rejected")

    return record


def validate_hosted_artifact_set(
    artifact_set: Any,
    repository: Path | None = None,
    commit: str | None = None,
) -> dict:
    """Validate hosted artifact set schema, provenance, and custody boundaries.
    Usable by parent operator validate_hosted_summary(summary, repository, commit)."""
    if isinstance(artifact_set, (str, Path)):
        p = physical_directory(Path(artifact_set))
        if p.is_dir():
            target = p / "artifact-set.json"
            if not target.is_file():
                target = p / "hosted-artifact-set.json"
            if not target.is_file():
                raise ContractError("ARTIFACT_SET", "artifact-set.json not found in directory")
            raw = target.read_bytes()
        else:
            raw = p.read_bytes()
        scan_for_credentials(raw.decode("utf-8"))
        try:
            doc = json.loads(raw)
        except Exception as exc:
            raise ContractError("ARTIFACT_SET", "Malformed artifact-set JSON") from exc
    elif isinstance(artifact_set, dict):
        doc = artifact_set
    else:
        raise ContractError("ARTIFACT_SET", "artifact_set must be dict or Path")

    if not isinstance(doc, dict):
        raise ContractError("ARTIFACT_SET", "Artifact set must be a JSON object")

    if doc.get("schema") != SCHEMA_HOSTED_ARTIFACT_SET:
        raise ContractError("ARTIFACT_SET", f"Invalid artifact set schema: {doc.get('schema')}")

    if commit and doc.get("commit") != commit:
        raise ContractError("ARTIFACT_SET", "Artifact set commit mismatch")

    if doc.get("production_enabled") is not False:
        raise ContractError("ARTIFACT_SET", "production_enabled must be false")

    if doc.get("publication_authority") is not False:
        raise ContractError("ARTIFACT_SET", "publication_authority must be false")

    artifacts = doc.get("artifacts")
    if not isinstance(artifacts, list):
        raise ContractError("ARTIFACT_SET", "artifacts must be a list")

    for art in artifacts:
        if not isinstance(art, dict):
            raise ContractError("ARTIFACT_SET", "Malformed artifact record")
        for field in ("path", "sha256", "size"):
            if field not in art:
                raise ContractError("ARTIFACT_SET", f"Artifact missing required field: {field}")
        validate_safe_relative_posix_path(art["path"])
        if not re.fullmatch(r"[0-9a-f]{64}", str(art.get("sha256"))):
            raise ContractError("ARTIFACT_SET", f"Invalid artifact sha256: {art.get('sha256')}")

    return doc


def build_hosted_artifact_set(summary: dict) -> dict:
    """Build canonical hosted-artifact-set manifest from hosted summary."""
    return {
        "schema": SCHEMA_HOSTED_ARTIFACT_SET,
        "commit": summary.get("commit") or summary.get("source_commit"),
        "production_enabled": False,
        "publication_authority": False,
        "artifacts": summary.get("artifacts", []),
    }
