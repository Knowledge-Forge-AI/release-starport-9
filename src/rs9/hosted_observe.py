"""Read-only destinations; unknown transport never proves absence or exactness."""
import base64
import hashlib
import http.client
import json
from pathlib import Path
import re
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import quote

from rs9.errors import ContractError, safe_details
from rs9.github import PublicClient
from rs9.hosted_platforms import select_payload
from rs9.readers import read_pypi_project, read_npm, read_homebrew, read_pages
from rs9.records import record_sha256, build_semantic_content_identity
from rs9.scratch import canonical
from rs9.product_classes import get_product_class, NATIVE_DESKTOP
from rs9.security import scan_for_credentials, validate_safe_relative_posix_path
from rs9.spdx import validate_spdx_expression


def readback_satisfied(row):
    state = row["observation"].get("state")
    if row["adapter"] == "pypi":
        return state in {"absent", "exact"}
    if row["adapter"] == "pages":
        return state == "absent"
    return state == "exact"


def select_brew_payload(capture):
    return select_payload(capture, "aarch64-darwin", allow_any=True)


def select_npm_payload(capture, expected_commands):
    """Select authenticated npm payload by npm-package-bin/root package/platform any/source-authenticated command mapping."""
    payloads = capture.record.get("payloads")
    if not isinstance(payloads, list) or not payloads:
        raise ValueError
    matching = []
    for p in payloads:
        if not isinstance(p, dict):
            continue
        if p.get("command_policy") != "npm-package-bin":
            continue
        if p.get("root") != "package":
            continue
        platforms = p.get("platforms")
        if platforms != ["any"]:
            continue
        p_commands = p.get("commands")
        if not isinstance(p_commands, dict):
            raise ContractError("OBSERVATION_IDENTITY", "Authenticated npm commands are missing or malformed")
        p_cmd_map = {}
        for cmd, row in p_commands.items():
            if (not isinstance(cmd, str) or not isinstance(row, dict)
                    or not isinstance(row.get("path"), str) or not row["path"].startswith("package/")):
                raise ContractError("OBSERVATION_IDENTITY", "Authenticated npm command path is malformed")
            target = row["path"].removeprefix("package/")
            validate_safe_relative_posix_path(target)
            p_cmd_map[cmd] = target
        if p_cmd_map != expected_commands:
            raise ContractError("OBSERVATION_IDENTITY", "Authenticated npm commands conflict with source")
        matching.append(p)
    if len(matching) > 1:
        raise ContractError("OBSERVATION_IDENTITY", "Ambiguous matching npm payload rows")
    if len(matching) == 1:
        return matching[0]
    return None


def authenticated_npm_projection(capture, intent, profile):
    """Share one byte-bound projection between npm and Homebrew readback."""
    from rs9.profiles import _npm_tarball_url
    from rs9.readers import _normalized_npm_bin
    project, version = intent["project"]["id"], intent["version"]
    details = {"product": project, "destination": "npm", "substage": "npm-projection"}
    try:
        metadata_path = (capture.root / "npm/metadata.json") if hasattr(capture, "root") and capture.root else None
        archive_path = (capture.root / "npm/package.tgz") if hasattr(capture, "root") and capture.root else None
        if get_product_class(project) == NATIVE_DESKTOP:
            # Preserve the accepted desktop supplemental-npm readback policy.
            if metadata_path is None or not metadata_path.is_file():
                return None
            package = json.loads(capture.source["package.json"])
            npm = json.loads(metadata_path.read_bytes())
            body = archive_path.read_bytes()
            url = npm["dist"]["tarball"]
            commands = npm.get("bin", package.get("bin", {}))
            license_expression = npm.get("license")
            name = package["name"]
            asset_name = url.rsplit("/", 1)[-1]
        else:
            package = json.loads(capture.source["package.json"])
            if (not isinstance(package, dict) or not isinstance(package.get("name"), str)
                    or not isinstance(package.get("license"), str)):
                raise ValueError
            name = package["name"]
            if not name.startswith("@") or name.rsplit("/", 1)[-1] != project or package.get("version") != version:
                raise ValueError
            url = _npm_tarball_url(name, version)
            source_rows = [row for row in capture.record["source_files"] if row.get("path") == "package.json"]
            if len(source_rows) != 1 or hashlib.sha256(capture.source["package.json"]).hexdigest() != source_rows[0]["sha256"]:
                raise ValueError
            commands = _normalized_npm_bin(name, package.get("bin"))
            intended = [row["name"] for row in intent["commands"]]
            if not commands or len(set(intended)) != len(intended) or set(commands) != set(intended):
                raise ValueError
            payload = select_npm_payload(capture, commands)
            if payload is None:
                return None
            if payload.get("id") not in capture.archives:
                raise ValueError
            body = capture.archives[payload["id"]].read_bytes()
            if len(body) != payload["size"] or hashlib.sha256(body).hexdigest() != payload["sha256"]:
                raise ValueError
            license_expression = package["license"]
            asset_name = url.rsplit("/", 1)[-1]
            # Supplemental files are optional and can only corroborate these facts.
            if (metadata_path and metadata_path.exists()) or (archive_path and archive_path.exists()):
                npm = json.loads(metadata_path.read_bytes())
                if (npm.get("name") != name or npm.get("version") != version
                        or npm.get("dist", {}).get("tarball") != url
                        or npm.get("license") != license_expression
                        or _normalized_npm_bin(name, npm.get("bin")) != commands
                        or archive_path.read_bytes() != body):
                    raise ValueError
        body_sha = hashlib.sha256(body).hexdigest()
        integrity = "sha512-" + base64.b64encode(hashlib.sha512(body).digest()).decode()
        return {"package_name": name, "version": version, "asset_name": asset_name,
                "url": url, "body": body, "sha256": body_sha, "integrity": integrity,
                "commands": commands, "expected_license": license_expression}
    except ContractError as error:
        raise error.with_details(**details) from None
    except (AttributeError, KeyError, OSError, TypeError, ValueError):
        raise ContractError("OBSERVATION_IDENTITY", "Authenticated npm projection identity differs or is unavailable",
                            details=details) from None


def homebrew_generation_facts(capture, intent, profile, *, npm_projection=None, npm_state=None):
    """Projection facts come from authenticated native payload or npm closure."""
    product = intent["project"]["id"]

    license_expression = intent.get("license", {}).get("expression")
    if not license_expression or not isinstance(license_expression, str):
        raise ContractError("LICENSE_AUTHORITY", "Explicit authenticated license authority required")

    scan_for_credentials(license_expression)
    validate_spdx_expression(license_expression)

    if isinstance(profile, dict) and profile:
        sections = profile.get("sections", {})
        profile_lic = sections.get("license") or sections.get("legacy_ingestion", {}).get("license")
        if isinstance(profile_lic, dict):
            status = profile_lic.get("status")
            if status is not None and status != "consistent":
                raise ContractError("LICENSE_AUTHORITY", "Consistent release license facts required")
            if "expression" in profile_lic and profile_lic["expression"] != license_expression:
                raise ContractError("LICENSE_AUTHORITY", "Profile license authority disagrees with intent")
            for dec in profile_lic.get("declarations", []):
                if isinstance(dec, dict) and dec.get("source", "").startswith("tagged:") and dec.get("expression") != license_expression:
                    raise ContractError("LICENSE_AUTHORITY", "Tagged repository licensing conflicts with candidate metadata")

    if get_product_class(product) == NATIVE_DESKTOP:
        payload = select_brew_payload(capture)
        commands = {row["name"]: "released-launcher" for row in intent["commands"]}
        return {"url": f"https://github.com/{capture.record['repository']['full_name']}/releases/download/{capture.record['release']['tag']}/{payload['name']}",
                "sha256": payload["sha256"], "license": license_expression,
                "commands": commands,
                "restrictions": "aarch64-darwin"}

    if npm_state != "exact" or not isinstance(npm_projection, dict):
        raise ContractError("OBSERVATION_IDENTITY", "Exact npm corroboration and shared projection facts required")
    from rs9.profiles import _npm_tarball_url
    try:
        name = npm_projection["package_name"]
        payload = select_npm_payload(capture, npm_projection["commands"])
        if payload is None:
            raise ValueError
        expected_commands = {name: (row["path"] if isinstance(row, dict) and "path" in row else str(row)).removeprefix("package/")
                             for name, row in payload["commands"].items()}
        if (name != json.loads(capture.source["package.json"])["name"]
                or not name.startswith("@") or name.rsplit("/", 1)[-1] != product
                or npm_projection["version"] != intent["version"]
                or npm_projection["url"] != _npm_tarball_url(name, intent["version"])
                or npm_projection["sha256"] != payload["sha256"]
                or hashlib.sha256(npm_projection["body"]).hexdigest() != payload["sha256"]
                or npm_projection["commands"] != expected_commands
                or set(expected_commands) != {row["name"] for row in intent["commands"]}):
            raise ValueError
    except (AttributeError, KeyError, TypeError, ValueError):
        raise ContractError("OBSERVATION_IDENTITY", "Shared npm projection differs from authenticated CLI facts") from None
    if (license_expression != "AGPL-3.0-or-later"
            or npm_projection["expected_license"] != license_expression):
        raise ContractError("LICENSE_AUTHORITY", "Authenticated CLI license authority differs from npm projection")
    return {"url": npm_projection["url"], "sha256": npm_projection["sha256"],
            "license": license_expression, "commands": npm_projection["commands"], "restrictions": "node"}


def reference_identity(capture, intent, adapter):
    return build_semantic_content_identity(intent["project"]["id"], intent["version"],
        intent["project"]["id"], adapter,
        {row["name"]: row["sha256"] for row in capture.record["payloads"]},
        {"configuration": record_sha256(intent)})


def reference_noop(capture, intent, profile, identity, observation, artifacts):
    """Run the fresh Foundation 3 planner with read-only destination policy."""
    from rs9.gates import derive_gates
    from rs9.planner import adapter_output, destination_policy, plan
    from rs9.release_core import authenticated_record_hash
    output = adapter_output(observation["destination"], observation["subject"], identity, artifacts,
        {"release_record_sha256": authenticated_record_hash(capture)},
        implementation={"id": "rs9-read-only-reference", "version": "v1alpha1"}, source_version="LIVE1-CONT6R2")
    proposal = plan(intent, capture, profile, output, derive_gates(intent, capture, profile, output),
        destination_policy(mode="observe-only"), observation,
        evaluated_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"))
    if proposal["outcome"] != "noop":
        raise ContractError("OBSERVATION_PLAN", "Exact reference readback must produce a planner noop")
    return {"planner_outcome": proposal["outcome"], "plan_sha256": record_sha256(proposal)}


def tap_snapshot(client, tap, *, evidence_sink=None):
    """Bind the maintained formulas to one observed default-branch commit tree."""
    repository = client.json("https://api.github.com/repos/" + tap, request_class="github-api")
    branch = repository.get("default_branch") if isinstance(repository, dict) else None
    if not isinstance(branch, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9/._-]{0,199}", branch):
        raise ContractError("HOMEBREW_PROTOCOL", "Default branch identity unavailable")
    commit = client.json("https://api.github.com/repos/" + tap + "/commits/" + quote(branch, safe=""), request_class="github-api")
    ref = commit.get("sha") if isinstance(commit, dict) else None
    tree_sha = commit.get("commit", {}).get("tree", {}).get("sha") if isinstance(commit, dict) else None
    if not all(isinstance(v, str) and re.fullmatch(r"[0-9a-f]{40}", v) for v in (ref, tree_sha)):
        raise ContractError("HOMEBREW_PROTOCOL", "Commit and tree identities unavailable")
    tree = client.json("https://api.github.com/repos/" + tap + "/git/trees/" + tree_sha + "?recursive=1", request_class="github-api")
    if (not isinstance(tree, dict) or tree.get("sha") != tree_sha or tree.get("truncated") is not False
            or not isinstance(tree.get("tree"), list)):
        raise ContractError("HOMEBREW_PROTOCOL", "Complete commit tree unavailable")
    required = {"Formula/" + product + ".rb" for product in
                ("theme-forge-stellar-burst", "theme-forge-stellar-loom", "theme-forge-solar-sail", "theme-forge-nebular-fusion")}
    blobs = {}
    for row in tree["tree"]:
        if not isinstance(row, dict) or row.get("path") not in required:
            continue
        path, sha = row["path"], row.get("sha")
        if (path in blobs or row.get("type") != "blob" or row.get("mode") != "100644"
                or not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{40}", sha)):
            raise ContractError("HOMEBREW_FORMULA_SCHEMA", "Formula tree identity drift")
        blobs[path] = sha
    if set(blobs) != required:
        raise ContractError("HOMEBREW_FORMULA_SCHEMA", "Maintained formula inventory drift")
    if evidence_sink is not None:
        evidence_sink.update(commit_sha=ref, tree_sha=tree_sha)
    return branch, ref, blobs


def execute(context):
    captures = context.get("captures")
    if not isinstance(captures, (list, tuple)) or len(captures) != 4:
        raise ContractError("OBSERVATION_CAPTURE", "Fresh complete generation required", details={"substage": "capture-validation"})
    client = context.get("client") or PublicClient()
    tap = "Knowledge-Forge-AI/homebrew-tap"
    ref = None
    default_branch = None
    formula_blobs = {}
    tap_state = "unknown"
    tap_evidence = {}
    try:
        default_branch, ref, formula_blobs = tap_snapshot(client, tap, evidence_sink=tap_evidence)
        tap_state = "bound"
    except (ContractError, OSError, KeyError, ValueError, TypeError, http.client.HTTPException, URLError, HTTPError) as error:
        tap_state = "conflict" if isinstance(error, ContractError) and error.code == "HOMEBREW_FORMULA_SCHEMA" else "unknown"
    observations = []
    diagnostics = []
    diagnostic_dir = context["scratch"] / "diagnostics"
    diagnostic_dir.mkdir(exist_ok=True)

    def record_diagnostic(project, destination, substage, code):
        detail = safe_details({"product": project, "destination": destination, "substage": substage, "code": code})
        diagnostics.append(detail)
        (diagnostic_dir / "observe-destinations.json").write_bytes(canonical(diagnostics))

    def read_destination(project, destination, reader, *args, **kwargs):
        try:
            observation = reader(*args, **kwargs)
        except ContractError as error:
            detail = safe_details({"product": project, "destination": destination, "substage": "destination-read", "code": error.code, **error.details})
            diagnostics.append(detail)
            (diagnostic_dir / "observe-destinations.json").write_bytes(canonical(diagnostics))
            raise error.with_details(**detail) from None
        diagnostics.append({"product": project, "destination": destination, "substage": "destination-read", "code": observation["state"], "state": observation["state"],
                            "diagnostic_sha256": hashlib.sha256(canonical(observation.get("diagnostics", []))).hexdigest()})
        (diagnostic_dir / "observe-destinations.json").write_bytes(canonical(diagnostics))
        return observation
    for capture, intent, profile in captures:
        if not hasattr(capture, "record") or not isinstance(capture.record, dict):
            raise ContractError("OBSERVATION_RECORD", "Capture record required", details={"substage": "record-validation"})
        if "release" not in capture.record or not isinstance(capture.record["release"], dict) or "tag" not in capture.record["release"]:
            raise ContractError("OBSERVATION_RECORD", "Release record requires release tag", details={"substage": "record-validation"})
        if "repository" not in capture.record or not isinstance(capture.record["repository"], dict) or "full_name" not in capture.record["repository"]:
            raise ContractError("OBSERVATION_RECORD", "Release record requires repository full name", details={"substage": "record-validation"})

        project, version = intent["project"]["id"], intent["version"]
        if (not isinstance(version, str) or not isinstance(capture.record["release"]["tag"], str)
                or capture.record["release"]["tag"] != "v" + version
                or not isinstance(capture.record["repository"]["full_name"], str)
                or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", capture.record["repository"]["full_name"])):
            raise ContractError("OBSERVATION_RECORD", "Authenticated release identity differs from the intended version",
                                details={"substage": "record-validation"})
        observations.append({"project": project, "adapter": "pypi", "observation": read_destination(project, "pypi", read_pypi_project, project, version)})

        try:
            projection = authenticated_npm_projection(capture, intent, profile)
        except ContractError as error:
            record_diagnostic(project, "npm", "npm-projection", error.code)
            raise
        if projection is None:
            record_diagnostic(project, "npm", "npm-projection", "npm-identity-unavailable")
            npm_observation = {"state": "unknown", "reason": "npm-identity-unavailable"}
        else:
            npm_identity = reference_identity(capture, intent, "npm")
            identity = record_sha256(npm_identity)
            subject = {"package": projection["package_name"], "version": version, "revision": None}
            npm_observation = read_destination(project, "npm", read_npm,
                {"id": "npm", "adapter": "npm", "mode": "direct"}, subject,
                desired_identity=identity, expected_hashes={projection["asset_name"]: projection["sha256"]},
                expected_commands=projection["commands"],
                expected_integrity=projection["integrity"],
                expected_license=projection["expected_license"])
        npm_entry = {"project": project, "adapter": "npm", "mode": "observe-only",
                     "observation": npm_observation}
        if npm_observation.get("state") == "exact":
            npm_entry.update(reference_noop(capture, intent, profile, npm_identity, npm_observation,
                             [{"path": projection["asset_name"], "sha256": projection["sha256"], "size": len(projection["body"])}]))
        observations.append(npm_entry)

        formula_path = f"Formula/{project}.rb"
        expected_blob = formula_blobs.get(formula_path)
        native = get_product_class(project) == NATIVE_DESKTOP
        if tap_state != "bound" or expected_blob is None:
            observation = {"state": tap_state if tap_state in {"unknown", "conflict"} else "conflict",
                           "reason": "tap-snapshot-unavailable-or-drifted"}
        elif not native and npm_observation.get("state") != "exact":
            state = "unknown" if npm_observation.get("state") == "unknown" else "conflict"
            reason = "npm-readback-" + state
            record_diagnostic(project, "homebrew", "npm-prerequisite", reason)
            observation = {"state": state, "reason": reason}
        else:
            try:
                brew_facts = homebrew_generation_facts(capture, intent, profile,
                    npm_projection=projection, npm_state=npm_observation.get("state"))
            except (ContractError, AttributeError, KeyError, OSError, TypeError, ValueError) as error:
                if not isinstance(error, ContractError):
                    error = ContractError("OBSERVATION_IDENTITY", "Homebrew projection facts are malformed or unavailable")
                record_diagnostic(project, "homebrew", "homebrew-generation-facts", error.code)
                detail = {"product": project, "destination": "homebrew", "substage": "homebrew-generation-facts", "code": error.code}
                if error.code != "MISSING_ASSET":
                    raise error.with_details(**detail) from None
                observation = {"state": "conflict", "reason": "payload-unavailable"}
            else:
                brew_identity = reference_identity(capture, intent, "homebrew")
                brew_artifact = {}
                observation = read_destination(project, "homebrew", read_homebrew,
                    {"id": "homebrew", "adapter": "homebrew", "mode": "projection"},
                    {"package": project, "version": version, "revision": None}, pinned_ref=ref,
                    desired_identity=record_sha256(brew_identity),
                    expected_payload_url=brew_facts["url"], expected_payload_sha256=brew_facts["sha256"],
                    expected_license=brew_facts["license"], expected_commands=brew_facts["commands"],
                    expected_restrictions=brew_facts["restrictions"], expected_blob_sha=expected_blob,
                    evidence_sink=brew_artifact)
        brew_entry = {"project": project, "adapter": "homebrew", "mode": "observe-only",
                      "pinned_ref": ref, "formula_blob_sha": expected_blob, "observation": observation}
        if observation.get("state") == "exact":
            brew_entry.update(reference_noop(capture, intent, profile, brew_identity, observation, [brew_artifact]))
        observations.append(brew_entry)
    pages = read_destination("generation", "pages", read_pages, {"id": "pages", "adapter": "pages", "mode": "projection"},
        {"package": "rs9-pages", "version": "1", "revision": None}, path="CNAME")
    observations.append({"project": "generation", "adapter": "pages", "deployment_performed": False,
                         "observation": pages})
    doc = {"schema": "rs9.hosted-destination-observations.v1alpha1", "production_enabled": False,
           "observations": observations, "homebrew_tap": tap_evidence, "publication_receipts": []}
    path = context["scratch"] / "destination-observations.json"
    path.write_bytes(canonical(doc))
    known = all(readback_satisfied(r) for r in observations)
    conflict = any(r["observation"]["state"] != "unknown" and not readback_satisfied(r) for r in observations)
    exact_planner_noops = [r["project"] + ":" + r["adapter"] for r in observations if r.get("planner_outcome") == "noop"]
    destinations = {}
    for adapter in ("pypi", "npm", "homebrew", "pages"):
        rows = [r for r in observations if r["adapter"] == adapter]
        dest_satisfied = bool(rows) and all(readback_satisfied(r) for r in rows)
        dest_exact = [r["project"] for r in rows if r["observation"].get("state") == "exact"]
        dest_satisfied_projects = [r["project"] for r in rows if readback_satisfied(r)]
        dest_noops = [r["project"] for r in rows if r.get("planner_outcome") == "noop"]
        dest_states = {r["project"]: r["observation"].get("state") for r in rows}
        destinations[adapter] = {
            "satisfied": dest_satisfied,
            "satisfied_count": len(dest_satisfied_projects),
            "total_count": len(rows),
            "exact": dest_exact,
            "exact_count": len(dest_exact),
            "satisfied_observations": dest_satisfied_projects,
            "exact_observations": dest_exact,
            "planner_noops": dest_noops,
            "states": dest_states,
        }
    satisfied_observations = [r["project"] + ":" + r["adapter"] for r in observations if readback_satisfied(r)]
    exact_observations = [r["project"] + ":" + r["adapter"] for r in observations if r["observation"].get("state") == "exact"]
    return {"gates": [{"name": "destination-observations-recorded", "status": "pass"},
            {"name": "readback-byte-comparison", "status": "pass" if known else "fail" if conflict else "not-run",
             "reason": "identity-conflict-or-required-target-absent" if conflict else "observations-recorded-with-unknown-or-metadata-only-states" if not known else "live-byte-readback"}],
            "artifacts": [path], "details": {"observations_sha256": record_sha256(doc),
            "production_receipt_count": 0, "states": [r["observation"]["state"] for r in observations],
            "planner_noops": exact_planner_noops,
            "destinations": destinations,
            "satisfied_observations": satisfied_observations,
            "exact_observations": exact_observations,
            "tap_default_branch": default_branch,
            "tap_commit_sha": ref, "tap_tree_sha": tap_evidence.get("tree_sha"), "bound_formula_blobs": formula_blobs}}
