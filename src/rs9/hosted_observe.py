"""Read-only destinations; unknown transport never proves absence or exactness."""
import base64
import hashlib
import json
from pathlib import Path

from rs9.errors import ContractError
from rs9.github import PublicClient
from rs9.readers import read_pypi_project, read_npm, read_homebrew, read_pages
from rs9.records import record_sha256
from rs9.scratch import canonical


def readback_satisfied(row):
    state = row["observation"].get("state")
    if row["adapter"] == "pypi":
        return state in {"absent", "exact"}
    if row["adapter"] == "pages":
        return state == "absent"
    return state == "exact"


def execute(context):
    captures = context["captures"]
    if len(captures) != 4:
        raise ContractError("OBSERVATION_CAPTURE", "Fresh complete generation required")
    client = context["client"] or PublicClient()
    tap = "Knowledge-Forge-AI/homebrew-tap"
    try:
        ref = client.json("https://api.github.com/repos/" + tap + "/commits/main", request_class="github-api")["sha"]
    except (ContractError, OSError, KeyError, ValueError):
        ref = None
    observations = []
    for capture, intent, profile in captures:
        project, version = intent["project"]["id"], intent["version"]
        observations.append({"project": project, "adapter": "pypi", "observation": read_pypi_project(project, version)})
        package = json.loads(capture.source["package.json"])
        if (capture.root / "npm/metadata.json").is_file():
            npm = json.loads((capture.root / "npm/metadata.json").read_bytes())
            body = (capture.root / "npm/package.tgz").read_bytes()
            asset_name = npm["dist"]["tarball"].rsplit("/", 1)[-1]
            url = npm["dist"]["tarball"]
            bins = npm.get("bin", package.get("bin", {}))
            expected_license = npm.get("license")
        else:
            payload = capture.record["payloads"][0]
            body = capture.archives[payload["id"]].read_bytes()
            asset_name = project + "-" + version + ".tgz"
            url = "https://registry.npmjs.org/" + package["name"] + "/-/" + asset_name
            bins = package.get("bin", {})
            expected_license = package["license"]
        identity = hashlib.sha256(body).hexdigest()
        subject = {"package": package["name"], "version": version, "revision": None}
        observations.append({"project": project, "adapter": "npm", "mode": "observe-only",
            "observation": read_npm({"id": "npm", "adapter": "npm", "mode": "direct"}, subject,
                desired_identity=identity, expected_hashes={asset_name: identity}, expected_commands=bins,
                expected_integrity="sha512-" + base64.b64encode(hashlib.sha512(body).digest()).decode(),
                expected_license=expected_license)})
        if ref:
            # Formula payloads are released application assets, not npm tarballs.
            brew_payload = next((p for p in capture.record["payloads"] if "aarch64" in p["name"] and "darwin" in p["name"]), capture.record["payloads"][0])
            brew_url = "https://github.com/" + capture.record["repository"]["full_name"] + "/releases/download/" + capture.record["tag"]["name"] + "/" + brew_payload["name"]
            observation = read_homebrew({"id": "homebrew", "adapter": "homebrew", "mode": "projection"},
                {"package": project, "version": version, "revision": None}, pinned_ref=ref,
                desired_identity=brew_payload["sha256"], expected_payload_url=brew_url, expected_payload_sha256=brew_payload["sha256"])
        else:
            observation = {"state": "unknown", "reason": "tap-head-read-failed"}
        observations.append({"project": project, "adapter": "homebrew", "mode": "observe-only",
                             "pinned_ref": ref, "observation": observation})
    pages = read_pages({"id": "pages", "adapter": "pages", "mode": "projection"},
        {"package": "rs9-pages", "version": "1", "revision": None}, path="CNAME")
    observations.append({"project": "generation", "adapter": "pages", "deployment_performed": False,
                         "observation": pages})
    doc = {"schema": "rs9.hosted-destination-observations.v1alpha1", "production_enabled": False,
           "observations": observations, "publication_receipts": []}
    path = context["scratch"] / "destination-observations.json"
    path.write_bytes(canonical(doc))
    known = all(readback_satisfied(r) for r in observations)
    return {"gates": [{"name": "destination-observations-recorded", "status": "pass"},
            {"name": "readback-byte-comparison", "status": "pass" if known else "not-run",
             "reason": "observations-recorded-with-unknown-or-metadata-only-states" if not known else "live-byte-readback"}],
            "artifacts": [path], "details": {"observations_sha256": record_sha256(doc),
            "production_receipt_count": 0, "states": [r["observation"]["state"] for r in observations]}}
