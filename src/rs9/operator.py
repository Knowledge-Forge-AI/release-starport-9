"""Attended LIVE1 preparation. Production transport remains closed.

The exact checkout binding is supplied after candidate adoption, not copied from
the planning prompt. This module never writes product source or production.
"""
import argparse
import json
import subprocess
from pathlib import Path

from rs9.bootstrap import load_bootstrap, checked_bootstrap_configurations, require_configuration_authority
from rs9.errors import ContractError
from rs9.profiles import evaluate_profile, selection_for_intent
from rs9.records import record_sha256, snapshot
from rs9.release_core import authenticate_release, capture_release, digest, authenticated_tree, authenticated_release_metadata, read_evidence
from rs9.scratch import ConfinedWriter, canonical, physical_directory

BOOTSTRAP = "bootstrap/pre-rs9/theme-forge-live1/manifest.json"
EXPECTATIONS = "operators/live1/expectations.json"


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
        capture_supplemental(intent, evidence, client)
        profile = evaluate_profile(capture, intent["release"]["evidence"]["profile"], intent)
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
