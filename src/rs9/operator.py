"""Attended LIVE1 preparation. Production transport remains closed.

The exact checkout binding is supplied after candidate adoption, not copied from
the planning prompt. This module never writes product source or production.
"""
import argparse
import copy
import json
import re
import subprocess
from pathlib import Path

from rs9.bootstrap import load_bootstrap, checked_bootstrap_configurations, require_configuration_authority
from rs9.errors import ContractError
from rs9.nebular_lineage import select_forward_lineage_proof
from rs9.profiles import evaluate_profile, selection_for_intent
from rs9.records import record_sha256, snapshot
from rs9.release_core import authenticate_release, capture_release, digest, authenticated_tree, authenticated_release_metadata, read_evidence
from rs9.scratch import ConfinedWriter, canonical, physical_directory

BOOTSTRAP = "bootstrap/pre-rs9/theme-forge-live1/manifest-author-aligned.json"
EXPECTATIONS = "operators/live1/expectations.json"

# The v0.6.1 controller remains the historical owner of its exact paths and
# expectations.  v0.7.0 deliberately has no embedded release hashes yet: the
# release capture and its reviewed bootstrap/expectation bytes are future
# inputs, not values this checkout may infer from v0.6.1.
NEBULAR070_PROFILE = "operators/tf-pypi/theme-forge-nebular-fusion-0.7.0-gate1.json"
NEBULAR070_BOOTSTRAP = "bootstrap/pre-rs9/theme-forge-nebular-0.7.0/manifest.json"
NEBULAR070_EXPECTATIONS = "operators/tf-pypi/nebular-0.7.0/expectations.json"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_CURRENT_NATIVE_PROVENANCE = {
    "path": "PROVENANCE.json",
    "commit_field": "releaseCommit",
    "tree_field": "testedTree",
}


def release_bindings(release: str) -> dict:
    """Return the release-specific capture contract without inventing inputs.

    The historical selector preserves the v0.6.1 controller.  The 0.7
    selector names the new bootstrap/expectation locations and direct lineage
    mode, but remains pending until a real release capture supplies immutable
    IDs, commit/tree coordinates, asset rows, and reviewed configuration
    digests.  Callers may pass a validated ready binding to the Gate1 adapter;
    this function never derives one from a historical release.
    """
    if release == "0.6.1.post1":
        return {
            "schema": "rs9.nebular-release-binding.v1alpha1",
            "release": "0.6.1.post1",
            "application_version": "0.6.1",
            "distribution_version": "0.6.1.post1",
            "repository": "Knowledge-Forge-AI/theme-forge-nebular-fusion",
            "tag": "v0.6.1",
            "bootstrap_path": BOOTSTRAP,
            "expectations_path": EXPECTATIONS,
            "status": "legacy-reviewed",
            "lineage": {
                "mode": "historical-forward-correction",
                "requires_historical_author_rewrite": True,
            },
        }
    if release != "0.7.0":
        raise ContractError("RELEASE_SELECTION", "Unsupported Nebular release binding")
    return {
        "schema": "rs9.nebular-release-binding.v1alpha1",
        "release": "0.7.0",
        "application_version": "0.7.0",
        "distribution_version": "0.7.0",
        "repository": "Knowledge-Forge-AI/theme-forge-nebular-fusion",
        "tag": "v0.7.0",
        "bootstrap_path": NEBULAR070_BOOTSTRAP,
        "expectations_path": NEBULAR070_EXPECTATIONS,
        "profile_path": NEBULAR070_PROFILE,
        "status": "pending-release-inputs",
        "lineage": {
            "mode": "direct-tag-provenance-equality",
            "requires_historical_author_rewrite": False,
        },
        "provenance": {
            "path": "PROVENANCE.json",
            "commit_field": "tagCommit",
            "tree_field": "tagTree",
        },
        "required_inputs": [
            "repository_id",
            "release_id",
            "tag_commit",
            "tag_tree",
            "bootstrap_sha256",
            "expectations_sha256",
            "asset_inventory",
            "source_capture",
        ],
    }


def validate_release_binding(binding: dict) -> dict:
    """Validate a caller-supplied release binding before it selects evidence."""
    if not isinstance(binding, dict):
        raise ContractError("RELEASE_BINDING", "Release binding object required")
    required = {
        "schema", "release", "application_version", "distribution_version",
        "repository", "tag", "bootstrap_path", "expectations_path", "status", "lineage",
    }
    if not required <= set(binding) or binding.get("schema") != "rs9.nebular-release-binding.v1alpha1":
        raise ContractError("RELEASE_BINDING", "Release binding fields are not closed")
    if binding["release"] != "0.7.0" or binding["application_version"] != "0.7.0" \
            or binding["distribution_version"] != "0.7.0" \
            or binding["repository"] != "Knowledge-Forge-AI/theme-forge-nebular-fusion" \
            or binding["tag"] != "v0.7.0" \
            or binding["bootstrap_path"] != NEBULAR070_BOOTSTRAP \
            or binding["expectations_path"] != NEBULAR070_EXPECTATIONS \
            or binding.get("profile_path") != NEBULAR070_PROFILE:
        raise ContractError("RELEASE_BINDING", "Only the 0.7.0 Gate1 binding is accepted")
    if binding["status"] not in {"pending-release-inputs", "ready"}:
        raise ContractError("RELEASE_BINDING", "Unknown Gate1 release-binding status")
    lineage = binding["lineage"]
    if lineage != {
        "mode": "direct-tag-provenance-equality",
        "requires_historical_author_rewrite": False,
    }:
        raise ContractError("RELEASE_BINDING", "Gate1 direct lineage mode is required")
    provenance = binding.get("provenance")
    if not isinstance(provenance, dict):
        raise ContractError("RELEASE_BINDING", "Gate1 provenance field selection is required")
    if provenance != {
        "path": "PROVENANCE.json",
        "commit_field": "tagCommit",
        "tree_field": "tagTree",
    } and provenance != _CURRENT_NATIVE_PROVENANCE:
        raise ContractError("RELEASE_BINDING", "Gate1 provenance identity fields are fixed")
    if binding["status"] == "pending-release-inputs":
        return copy.deepcopy(binding)
    expected = binding.get("expected")
    if not isinstance(expected, dict) or set(expected) != {
        "repository_id", "release_id", "tag_commit", "tag_tree",
        "bootstrap_sha256", "expectations_sha256",
    }:
        raise ContractError("RELEASE_BINDING", "Ready Gate1 bindings require exact release coordinates")
    if (type(expected["repository_id"]) is not int or expected["repository_id"] <= 0
            or type(expected["release_id"]) is not int or expected["release_id"] <= 0
            or not re.fullmatch(r"[0-9a-f]{40}\Z", expected["tag_commit"])
            or not re.fullmatch(r"[0-9a-f]{40}\Z", expected["tag_tree"])
            or not _SHA256.fullmatch(expected["bootstrap_sha256"])
            or not _SHA256.fullmatch(expected["expectations_sha256"])):
        raise ContractError("RELEASE_BINDING", "Ready Gate1 release coordinates are malformed")
    return copy.deepcopy(binding)


def checked_checkout(root, commit, tree):
    import re
    if any(not re.fullmatch(r"[0-9a-f]{40}", x or "") for x in (commit, tree)):
        raise ContractError("OPERATOR_REVIEW", "Reviewed commit and tree are required")
    def git(*args):
        return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()
    if git("rev-parse", "HEAD") != commit or git("rev-parse", "HEAD^{tree}") != tree:
        raise ContractError("OPERATOR_REVIEW", "Checkout differs from exact attended review binding")
    if git("branch", "--show-current") != "main" or git("diff", "--name-only", "HEAD"):
        raise ContractError("OPERATOR_REVIEW", "Reviewed main checkout has tracked changes")
    untracked = git("ls-files", "--others", "--exclude-standard").splitlines()
    if any(not path.startswith(".serena/") for path in untracked):
        raise ContractError("OPERATOR_REVIEW", "Unreviewed files are present in attended checkout")
    ignored = git("ls-files", "--others", "--ignored", "--exclude-standard").splitlines()
    if any(not path.startswith(".serena/") for path in ignored):
        raise ContractError("OPERATOR_REVIEW", "Ignored files are present in attended checkout")


def assert_release_expectations(capture, expected):
    actual = capture.record
    release = authenticated_release_metadata(capture)
    tree = authenticated_tree(capture)
    bindings = {"repository": actual["repository"]["full_name"], "repository_id": actual["repository"]["id"],
                "tag": actual["release"]["tag"], "release_id": actual["release"]["id"],
                "commit": actual["tag"]["commit"], "tree": actual["tag"]["tree"]}
    bindings.update(immutable=release.get("immutable"), published_at=actual.get("source_times", {}).get("published_at"),
                    contains_rs9=any(e["path"] == ".rs9" or e["path"].startswith(".rs9/") for e in tree["tree"]),
                    truncated=tree.get("truncated"))
    if type(bindings["immutable"]) is not bool or not bindings["published_at"]:
        raise ContractError("LIVE1_RELEASE_MISMATCH", "Expected release state and publication time required")
    if any(expected.get(k) != value for k,value in bindings.items()):
        raise ContractError("LIVE1_RELEASE_MISMATCH", "Authenticated generation differs from manager expectations")
    for asset in expected["assets"]:
        matches = [a for a in actual["assets"] if a["name"] == asset["name"]]
        if len(matches) != 1 or any(matches[0][k] != asset[k] for k in ("sha256", "size")):
            raise ContractError("LIVE1_RELEASE_MISMATCH", "Authenticated payload differs from reviewed expectation")
        if matches[0]["github_asset_id"] != asset["id"]:
            raise ContractError("LIVE1_RELEASE_MISMATCH", "Release asset identity differs from reviewed expectation")


def authenticate_generation(repository, output, *, approved_bootstrap_sha256, client=None):
    """Fresh download; no offline JSON capability and no historical-verdict reuse."""
    from rs9.github import PublicClient
    from rs9.profiles import capture_supplemental
    client = client or PublicClient()
    repository, output = physical_directory(repository), physical_directory(output)
    if any(output.iterdir()):
        raise ContractError("OUTPUT_NOT_EMPTY", "Authentication evidence root must be empty")
    manifest_path = repository / BOOTSTRAP
    configurations = checked_bootstrap_configurations(manifest_path, approved_manifests=[approved_bootstrap_sha256])
    expectations = json.loads(read_evidence(repository, EXPECTATIONS, 512 * 1024))["projects"]
    results = []
    for row, intent in configurations:
        evidence = output / intent["project"]["id"]
        evidence.mkdir()
        capture_release(selection_for_intent(intent), evidence, client=client)
        capture = authenticate_release(selection_for_intent(intent), evidence)
        selected = [e for e in expectations if e["repository"] == row["repository"]]
        if len(selected) != 1:
            raise ContractError("LIVE1_RELEASE_MISMATCH", "One expectation per repository required")
        assert_release_expectations(capture, selected[0])
        intent = load_bootstrap(manifest_path, capture, approved_manifests=[approved_bootstrap_sha256])
        require_configuration_authority(capture, intent)
        lineage_correction = select_forward_lineage_proof(repository, capture, intent)
        capture_supplemental(intent, evidence, client)
        profile_kwargs = {}
        if lineage_correction is not None:
            profile_kwargs["lineage_correction"] = lineage_correction
        profile = evaluate_profile(capture, intent["release"]["evidence"]["profile"], intent,
                                   **profile_kwargs)
        results.append({"project": intent["project"]["id"], "release": capture.record,
                        "profile": profile, "release_record_sha256": record_sha256(capture.record)})
    with ConfinedWriter(output / _make_summary_dir(output)) as writer:
        writer.write("authenticated-generation.json", canonical({"schema":"rs9.live1-authentication-summary.v1alpha1", "projects":results}))
    return snapshot(results)


def _make_summary_dir(output):
    (output / "summary").mkdir()
    return "summary"


def preparation_status(repository):
    """Read explicit pending facts; does not infer external setup or qualification."""
    root = physical_directory(repository)
    readiness = json.loads((root / "operators/live1/readiness.json").read_bytes())
    return {"schema":"rs9.live1-operator-status.v1alpha1", "production_enabled":False,
            "bootstrap_sha256":digest((root / BOOTSTRAP).read_bytes()),
            "readiness":readiness, "publication":"blocked"}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Attended RS9 LIVE1 preparation; no production transport")
    parser.add_argument("phase", choices=["status", "authenticate", "publish-pages", "publish-pypi"])
    parser.add_argument("--repository", default=".")
    parser.add_argument("--evidence")
    parser.add_argument("--reviewed-commit")
    parser.add_argument("--reviewed-tree")
    parser.add_argument("--approved-bootstrap-sha256")
    args = parser.parse_args(argv)
    try:
        root = physical_directory(args.repository)
        if args.phase == "status":
            print(canonical(preparation_status(root)).decode(), end="")
            return 0
        checked_checkout(root, args.reviewed_commit, args.reviewed_tree)
        if args.phase.startswith("publish-"):
            raise ContractError("PUBLICATION_NOT_READY", "Mandatory real qualification and destination transports are incomplete")
        if not args.evidence:
            raise ContractError("EVIDENCE_REQUIRED", "Caller-owned physical evidence directory required")
        authenticate_generation(root, args.evidence, approved_bootstrap_sha256=args.approved_bootstrap_sha256)
        print("Authenticated generation recorded; publication remains blocked.")
        return 0
    except (ContractError, OSError, subprocess.SubprocessError, ValueError) as error:
        print("RS9 preparation stopped: " + (error.code if isinstance(error, ContractError) else "PREPARATION_FAILED"))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
