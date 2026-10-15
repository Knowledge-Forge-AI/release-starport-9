"""Bounded APGR exact upstream PyPI route: verification, destination readback and dispatch."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any
from urllib.parse import quote

from rs9.apgr7_common import PROFILES, result, stop
from rs9.apgr7_python import assess_sdist_fallback, check_requires_python, normalize_project_name, verify_artifact
from rs9.errors import ContractError
from rs9.scratch import canonical

WORKFLOW_NAME = "rs9-pypi-publish.yml"
REPOSITORY = "Knowledge-Forge-AI/release-starport-9"
EXPECTED_ARTIFACT_COUNT = 3


def verify(binding: Any) -> list[dict[str, Any]]:
    """Verify approved 3 APGR release artifacts and verify macos wheel exclusion defect."""
    pypi_conf = binding.sidecar.get("pypi", {})
    project = pypi_conf.get("project")
    if not project or normalize_project_name(project) != "agentic-praxis-grimoire":
        raise ContractError("APGR7_PYPI_CONFIG", "PyPI project must be agentic-praxis-grimoire")

    artifacts = pypi_conf.get("artifacts", [])
    if len(artifacts) != EXPECTED_ARTIFACT_COUNT:
        raise ContractError(
            "APGR7_PYPI_SCOPE",
            f"Expected exactly {EXPECTED_ARTIFACT_COUNT} PyPI release artifacts, got {len(artifacts)}",
        )

    excluded = pypi_conf.get("excluded", [])
    if len(excluded) != 1:
        raise ContractError(
            "APGR7_PYPI_CONFIG",
            f"Expected exactly 1 excluded PyPI artifact, got {len(excluded)}",
        )

    license_conf = binding.sidecar.get("license", {})
    license_expr = license_conf.get("expression")
    if not license_expr:
        raise ContractError("APGR7_PYPI_CONFIG", "License expression required in sidecar")

    verified = []
    for art in artifacts:
        name = art.get("name")
        expected_size = art.get("size")
        expected_sha = art.get("sha256")
        if not name or expected_size is None or not expected_sha:
            raise ContractError("APGR7_PYPI_CONFIG", f"Invalid artifact specification: {art}")

        body = binding.asset(name)
        if len(body) != expected_size:
            raise ContractError(
                "APGR7_PYPI_SIZE",
                f"Asset {name} size mismatch: got {len(body)}, expected {expected_size}",
            )

        actual_sha = hashlib.sha256(body).hexdigest()
        if actual_sha != expected_sha:
            raise ContractError(
                "APGR7_PYPI_DIGEST",
                f"Asset {name} SHA256 mismatch: got {actual_sha}, expected {expected_sha}",
            )

        try:
            info = verify_artifact(name, body, expected_project=project, expected_version="0.13.0",
                                   expected_license=license_expr)
        except ContractError as error:
            raise error.with_details(asset=name) from None
        verified.append({
            "name": name,
            "size": expected_size,
            "sha256": expected_sha,
            "kind": info["kind"],
            "tag": info.get("tag"),
            "requires_python": info["metadata"].get("Requires-Python", ""),
            "python_compatibility": {"3." + str(minor): check_requires_python(info["metadata"].get("Requires-Python", ""), (3, minor)) for minor in (12, 13, 14)},
        })

    # Verify excluded defective macos wheel and verify its defect remains APGR7_PYTHON_MACHO
    excl = excluded[0]
    excl_name = excl.get("name")
    if excl_name != "agentic_praxis_grimoire-0.13.0-py3-none-macosx_11_0_arm64.whl":
        raise ContractError("APGR7_PYPI_CONFIG", f"Unexpected excluded artifact: {excl_name}")
    if excl.get("reason") != "APGR7_PYTHON_MACHO":
        raise ContractError("APGR7_PYPI_CONFIG", f"Excluded reason must be APGR7_PYTHON_MACHO, got {excl.get('reason')}")

    excl_body = binding.asset(excl_name)
    if len(excl_body) != excl.get("size"):
        raise ContractError("APGR7_PYPI_SIZE", f"Excluded asset {excl_name} size mismatch")
    if hashlib.sha256(excl_body).hexdigest() != excl.get("sha256"):
        raise ContractError("APGR7_PYPI_DIGEST", f"Excluded asset {excl_name} SHA256 mismatch")

    try:
        verify_artifact(excl_name, excl_body, expected_project=project, expected_version="0.13.0",
                        expected_license=license_expr)
        raise ContractError("APGR7_PYPI_EXCLUSION", "Excluded defective artifact unexpectedly passed verification")
    except ContractError as err:
        if err.code != "APGR7_PYTHON_MACHO":
            raise ContractError("APGR7_PYPI_EXCLUSION", f"Excluded artifact failed with {err.code}, expected APGR7_PYTHON_MACHO")

    return sorted(verified, key=lambda r: r["name"])


def verify_pins(binding=None, pins_doc=None):
    """The frozen source owns production pins; an explicit document is a test seam."""
    from rs9.records import closed
    if pins_doc is None:
        pins_doc = Path(__file__).resolve().parents[2] / "operators/apgr-publication/pypi-artifacts.json"
    pins = json.loads(pins_doc.read_bytes()) if isinstance(pins_doc, Path) else pins_doc
    closed(pins, {"schema", "project", "version", "repository", "release_tag", "artifacts", "excluded"})
    if (pins["schema"] != "rs9.pypi-artifacts.v1alpha2" or pins["project"] != "agentic-praxis-grimoire" or pins["version"] != "0.13.0"
            or pins["repository"] != "Knowledge-Forge-AI/agentic-praxis-grimoire" or pins["release_tag"] != "v0.13.0"):
        raise ContractError("APGR7_PYPI_PIN_DRIFT", "Committed pin schema or release differs")
    prefix = "agentic_praxis_grimoire-0.13.0"
    names = {prefix + s for s in ("-py3-none-manylinux_2_17_aarch64.whl", "-py3-none-manylinux_2_17_x86_64.whl", ".tar.gz")}
    if len(pins["artifacts"]) != 3 or {r["name"] for r in pins["artifacts"]} != names or len(pins["excluded"]) != 1:
        raise ContractError("APGR7_PYPI_SCOPE", "Only the approved immutable three-file subset is uploadable")
    selected = []
    for row in pins["artifacts"]:
        closed(row, {"name", "size", "sha256", "url"})
        if row["url"] != "https://github.com/Knowledge-Forge-AI/agentic-praxis-grimoire/releases/download/v0.13.0/" + row["name"]:
            raise ContractError("APGR7_PYPI_SCOPE", "Fixed immutable release URL required")
        selected.append({k: row[k] for k in ("name", "size", "sha256")})
    excluded = pins["excluded"][0]
    closed(excluded, {"name", "size", "sha256", "reason"})
    if excluded["name"] != prefix + "-py3-none-macosx_11_0_arm64.whl" or excluded["reason"] != "APGR7_PYTHON_MACHO":
        raise ContractError("APGR7_PYPI_PIN_DRIFT", "Defective macOS wheel remains explicitly excluded")
    if binding is not None:
        conf = binding.sidecar["pypi"]
        if sorted(selected, key=lambda r: r["name"]) != sorted(conf["artifacts"], key=lambda r: r["name"]) or pins["excluded"] != conf["excluded"]:
            raise ContractError("APGR7_PYPI_PIN_DRIFT", "Committed selection differs from authenticated sidecar")
    return pins


def _observe_files(binding, io, verified_artifacts, remote_by_name):
    subjects, stops = [], []
    for art in verified_artifacts:
        name = art["name"]
        if name not in remote_by_name:
            subjects.append({
                "name": name,
                "size": art["size"],
                "sha256": art["sha256"],
                "state": "absent",
            })
            continue

        rem = remote_by_name[name]
        rem_sha = rem.get("digests", {}).get("sha256")
        rem_size = rem.get("size")
        rem_url = rem.get("url")

        if rem_sha != art["sha256"] or rem_size != art["size"] or not rem_url:
            subjects.append({
                "name": name,
                "size": art["size"],
                "sha256": art["sha256"],
                "state": "conflict",
                "observed_sha256": rem_sha,
            })
            continue

        # Download exact artifact bytes and compare all bytes
        try:
            remote_bytes = io.get(rem_url)
        except ContractError as err:
            subjects.append({
                "name": name,
                "size": art["size"],
                "sha256": art["sha256"],
                "state": "unknown",
            })
            stops.append(stop(err.code, [name], f"Failed downloading remote PyPI artifact: {name}"))
            continue

        actual_sha = hashlib.sha256(remote_bytes).hexdigest()
        bound_bytes = binding.asset(name)
        if actual_sha == art["sha256"] and len(remote_bytes) == art["size"] and remote_bytes == bound_bytes:
            subjects.append({
                "name": name,
                "size": art["size"],
                "sha256": art["sha256"],
                "state": "exact",
            })
        else:
            subjects.append({
                "name": name,
                "size": art["size"],
                "sha256": art["sha256"],
                "state": "conflict",
                "observed_sha256": actual_sha,
            })

    return subjects, stops


def _observe_destination(
    binding: Any, io: Any, verified_artifacts: list[dict[str, Any]]
) -> tuple[str, list[dict[str, Any]], list[dict[str, Any]]]:
    """Query PyPI JSON API and download published files to compare bytes."""
    project = binding.sidecar["pypi"]["project"]
    url = f"https://pypi.org/pypi/{quote(project, safe='')}/0.13.0/json"

    try:
        doc = io.json(url)
    except ContractError as err:
        if err.code == "REMOTE_ABSENT":
            # Version 0.13.0 does not exist on PyPI
            subjects = [
                {
                    "name": art["name"],
                    "size": art["size"],
                    "sha256": art["sha256"],
                    "state": "absent",
                }
                for art in verified_artifacts
            ]
            stops = [
                stop(
                    "protected-env-authority-required",
                    [WORKFLOW_NAME],
                    "Default branch deployment and protected env authority remain required before first live write.",
                )
            ]
            return "publish-ready", subjects, stops
        # Any other failure is REMOTE_UNKNOWN ("unknown never absent")
        subjects = [
            {
                "name": art["name"],
                "size": art["size"],
                "sha256": art["sha256"],
                "state": "unknown",
            }
            for art in verified_artifacts
        ]
        stops = [stop(err.code, [], "Repeat authenticated destination readback before publishing.")]
        return "unknown", subjects, stops

    # Parse PyPI published release files
    if not isinstance(doc, dict) or not isinstance(doc.get("urls"), list):
        subjects = [
            {
                "name": art["name"],
                "size": art["size"],
                "sha256": art["sha256"],
                "state": "unknown",
            }
            for art in verified_artifacts
        ]
        stops = [stop("REMOTE_UNKNOWN", [], "Malformed PyPI destination metadata response.")]
        return "unknown", subjects, stops

    remote_urls = doc.get("urls", [])
    if (any(not isinstance(u, dict) or not isinstance(u.get("filename"), str) for u in remote_urls)
            or len({u["filename"] for u in remote_urls}) != len(remote_urls)):
        return "unknown", [], [stop("REMOTE_UNKNOWN", [], "Malformed or duplicate PyPI file inventory.")]
    remote_by_name = {u.get("filename"): u for u in remote_urls if isinstance(u, dict)}

    expected_names = {art["name"] for art in verified_artifacts}
    unexpected_names = set(remote_by_name.keys()) - expected_names

    excluded_names = {e["name"] for e in binding.sidecar.get("pypi", {}).get("excluded", [])}
    excluded_present = sorted(set(remote_by_name.keys()) & excluded_names)
    if excluded_present:
        stops = [
            stop(
                "pypi-excluded-artifact-conflict",
                excluded_present,
                "Defective excluded artifact present on PyPI registry; conflicts preserved and live publish forbidden.",
            )
        ]
        subjects, _ = _observe_files(binding, io, verified_artifacts, remote_by_name)
        return "conflict", subjects, stops

    subjects, stops = _observe_files(binding, io, verified_artifacts, remote_by_name)

    states = {s["state"] for s in subjects}

    if unexpected_names:
        stops.append(
            stop(
                "pypi-artifact-conflict",
                sorted(unexpected_names),
                "Unexpected extra artifacts present on PyPI release; conflicts preserved.",
            )
        )
        return "conflict", subjects, stops

    if "unknown" in states:
        return "unknown", subjects, stops

    if "conflict" in states:
        conflicts = [s["name"] for s in subjects if s["state"] == "conflict"]
        stops.append(
            stop(
                "pypi-artifact-conflict",
                conflicts,
                "Existing PyPI release artifacts conflict with authenticated release bytes; cannot overwrite.",
            )
        )
        return "conflict", subjects, stops

    if states == {"exact"}:
        return "exact", subjects, []

    if states == {"absent"}:
        stops.append(
            stop(
                "protected-env-authority-required",
                [WORKFLOW_NAME],
                "Default branch deployment and protected env authority remain required before first live write.",
            )
        )
        return "publish-ready", subjects, stops

    # Some exact, some absent -> incomplete (partial upload)
    if "exact" in states and "absent" in states:
        missing = [s["name"] for s in subjects if s["state"] == "absent"]
        stops.append(
            stop(
                "pypi-partial-upload",
                missing,
                "Safe repair required: PyPI does not allow re-uploading existing files; only missing artifacts may be uploaded.",
            )
        )
        return "incomplete", subjects, stops

    return "blocked", subjects, stops


def prepare(binding: Any, io: Any) -> dict[str, Any]:
    """Prepare PyPI publication: verify local artifacts, check remote presence, return roster row."""
    try:
        verify_pins(binding, getattr(io, "pypi_pins", None))
        verified_artifacts = verify(binding)
    except ContractError as error:
        remedy = ("Resolve this exact upstream artifact's metadata/native compatibility; preserve immutable release bytes.")
        return result("pypi", PROFILES["pypi"], "blocked", stops=[stop(error.code,
            [error.details["asset"]] if "asset" in error.details else [],
            remedy)])

    # Compute prepared artifacts ledger digest
    ledger_bytes = canonical({
        "project": binding.sidecar["pypi"]["project"],
        "version": "0.13.0",
        "artifacts": verified_artifacts,
    })
    prepared_sha256 = hashlib.sha256(ledger_bytes).hexdigest()

    state, subjects, stops = _observe_destination(binding, io, verified_artifacts)

    row = result(
        "pypi",
        PROFILES["pypi"],
        state,
        subjects=subjects,
        stops=stops,
        observed_version="0.13.0" if state == "exact" else None,
        verified_bytes=state == "exact",
    )
    row["prepared_sha256"] = prepared_sha256
    row["excluded_artifacts"] = binding.sidecar["pypi"]["excluded"]
    row["sdist_fallback"] = assess_sdist_fallback(
        verified_artifacts,
        binding.sidecar.get("pypi", {}).get("excluded", []),
    )
    return row


def publish(binding, io, prepared_row, *, ready=False, journal=None):
    """Only the protected deployed workflow can acquire publication custody."""
    from rs9.apgr7_pypi_deploy import dispatch_workflow
    current = prepare(binding, io)
    if current["state"] not in ("publish-ready", "incomplete"):
        return current
    operation = dispatch_workflow(io, ready=ready, journal=journal,
                                  confirmed=getattr(io, "pypi_publisher_confirmed", False),
                                  prepared_sha256=current["prepared_sha256"])
    current["state"] = operation["state"]
    current["stops"].extend(operation.get("stops", []))
    for field in ("transport_receipt", "handoff"):
        if field in operation:
            current[field] = operation[field]
    return current
