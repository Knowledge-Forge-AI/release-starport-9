"""Fresh candidate capture. No publication, reservation or persisted capabilities."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path

from rs9.bootstrap import checked_bootstrap_configurations, load_bootstrap, require_configuration_authority
from rs9.errors import ContractError
from rs9.github import PublicClient
from rs9.operator import BOOTSTRAP, EXPECTATIONS, assert_release_expectations
from rs9.profiles import capture_supplemental, evaluate_profile, selection_for_intent
from rs9.records import record_sha256
from rs9.release_core import authenticate_release, capture_release, digest
from rs9.scratch import ConfinedWriter, canonical, physical_directory


def configuration_rows(repository):
    root = physical_directory(repository)
    manifest = root / BOOTSTRAP
    # Candidate source selects its checked bootstrap; this is not an operator
    # approval and cannot authorize publication. load_bootstrap grants only the
    # configuration capability needed to inspect this exact old generation.
    return checked_bootstrap_configurations(manifest, approved_manifests=[digest(manifest.read_bytes())])


def capture_generation(repository, output, *, project=None, client=None, checkout_binding="provider-uncommitted"):
    root, output = physical_directory(repository), physical_directory(output)
    if any(output.iterdir()):
        raise ContractError("OUTPUT_NOT_EMPTY", "Fresh candidate scratch must be empty")
    rows = configuration_rows(root)
    if project is not None:
        rows = [(row, intent) for row, intent in rows if intent["project"]["id"] == project]
        if len(rows) != 1:
            raise ContractError("CANDIDATE_PROJECT", "One current-generation project required")
    expectations = json.loads((root / EXPECTATIONS).read_bytes())["projects"]
    client = client or PublicClient()
    results, summaries = [], []
    for row, intent in rows:
        target = output / intent["project"]["id"]
        target.mkdir()
        selection = selection_for_intent(intent)
        stage = "capture"
        try:
            capture_release(selection, target, client=client)
            stage = "core-authenticate"
            capture = authenticate_release(selection, target)
            stage = "expectations"
            expected = [r for r in expectations if r["repository"] == row["repository"]]
            if len(expected) != 1:
                raise ContractError("LIVE1_RELEASE_MISMATCH", "Exactly one release expectation required")
            assert_release_expectations(capture, expected[0])
            stage = "bootstrap"
            manifest = root / BOOTSTRAP
            intent = load_bootstrap(manifest, capture, approved_manifests=[digest(manifest.read_bytes())])
            require_configuration_authority(capture, intent)
            stage = "supplemental"
            capture_supplemental(intent, target, client)
            stage = "profile"
            profile = evaluate_profile(capture, intent["release"]["evidence"]["profile"], intent)
        except ContractError as error:
            raise error.with_details(project=intent["project"]["id"], stage=stage) from None
        summary = {"project": intent["project"]["id"], "release_record_sha256": record_sha256(capture.record),
                   "profile_result_sha256": record_sha256(profile), "repository": capture.record["repository"],
                   "release": capture.record["release"], "tag": capture.record["tag"],
                   "assets": capture.record["assets"], "payloads": capture.record["payloads"],
                   "source_files": capture.record["source_files"], "license": profile["sections"].get("license", profile["sections"].get("legacy_ingestion", {}).get("license"))}
        results.append((capture, intent, profile))
        summaries.append(summary)
    summary_root = output / "summary"
    summary_root.mkdir()
    with ConfinedWriter(summary_root) as writer:
        writer.write("authentication.json", canonical({"schema": "rs9.candidate-authentication.v1alpha1",
            "checkout_binding": checkout_binding, "trust_root": "hosted-candidate-unattested" if checkout_binding.startswith("hosted:") else "provider-local-unattested",
            "observed_at": datetime.now(timezone.utc).isoformat(), "production_enabled": False,
            "projects": summaries}))
    return results


def main(argv=None):
    parser = argparse.ArgumentParser(description="Fresh RS9 candidate capture, no production operations")
    parser.add_argument("command", choices=["authenticate"])
    parser.add_argument("--repository", default=".")
    parser.add_argument("--scratch", required=True)
    parser.add_argument("--project")
    args = parser.parse_args(argv)
    scratch = physical_directory(args.scratch)
    try:
        binding = "hosted:" + os.environ["GITHUB_SHA"] if os.environ.get("GITHUB_ACTIONS") == "true" else "provider-uncommitted"
        identity = os.environ.get("RS9_GITHUB_READ_TOKEN") if os.environ.get("GITHUB_ACTIONS") == "true" else None
        capture_generation(args.repository, scratch, project=args.project, client=PublicClient(api_token=identity), checkout_binding=binding)
        print("Fresh release authentication complete; production disabled.")
        return 0
    except (ContractError, OSError, ValueError, KeyError):
        print("Candidate capture blocked; no fallback to historical bytes.")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
