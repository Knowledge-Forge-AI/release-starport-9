"""Closed original product-native admission for the unpublished 071 CI route.

References are configuration. Only replay of the fixed public API snapshots,
original catalog and original evidence against a genuine ReleaseCapture mints
an ephemeral capability. This module is never embedded in the launcher.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import weakref
import zipfile

from rs9.errors import ContractError
from rs9.release_core import read_evidence
from rs9.scratch import canonical
from rs9.tf_pypi_model import strict_json

_REFERENCE = json.loads(r'''
{
  "schema": "rs9.nebular071-product-native-reference.v1",
  "repository": "Knowledge-Forge-AI/theme-forge-nebular-fusion",
  "workflow": ".github/workflows/native-rc.yml",
  "run_id": 41176311998,
  "run_attempt": 1,
  "tested_commit": "7aadefdbcf496a34c097c4880d1802a02d00acc7",
  "tested_tree": "6e3561855f6ee0093fb709488ad976b69bf501d2",
  "catalog": {
    "id": 13032699957,
    "name": "nebular-rc-index-41176311998-a1",
    "size": 2589,
    "sha256": "cf835009a430f93895ae5a0f97b2e62e38a7b8c6472ae0471b4a7224d6558ad0",
    "member": {
      "path": "rc-index.json",
      "size": 9748,
      "sha256": "93eb9016ea2a4529803e51dca00e9999217edc1c0394b696b370929eb6428404"
    }
  },
  "lanes": [
    {
      "lane": "macos-arm64",
      "artifact_id": 13032957569,
      "artifact_sha256": "3942533bbd9d41d9b174a808681d4d335eefd395212181732a557991f2976093",
      "evidence_sha256": "1e0f9e80a5cc2d8af4d6823bb69217318a9f79531fe917285c84e089cfcde9ca"
    },
    {
      "lane": "linux-arm64",
      "artifact_id": 13033139137,
      "artifact_sha256": "299f0fe252f08e3b457b638535bd54e9ee016953fc77637a4671619ad465ccfe",
      "evidence_sha256": "09832b90cbbb2bfc1f2a27f235b1ebae313ead331f392bce649abad5b752baf7"
    },
    {
      "lane": "linux-x64",
      "artifact_id": 13033108750,
      "artifact_sha256": "5c13a6b9de8fa69405739b4f883c9754092718c43f67db64c79af839b1f34f0f",
      "evidence_sha256": "2e384ec263ec95ad12fb5ccf29a168d3ef12373c49b4744e1bd38eb872c4e9f9"
    }
  ]
}
''')
_API_PINS = json.loads(r'''
{
  "run.json": [
    14965,
    "da667fc9eec63b7c3b27840f39d1eecb694e985187640fa2f8d713d91bfeff35"
  ],
  "jobs.json": [
    21787,
    "3bed4653f10f6b66209cc79e4329ba99ce8f54e0634876268c3eda70165bd069"
  ],
  "compiler-commit.json": [
    1511,
    "39ebd516344b725e463c9701e044b7a11194dc006d0ba224de6193187b59e8e4"
  ],
  "artifacts.json": [
    3125,
    "a87c2e3f7ce08fff83244b5b490628baf7b691760d6c3cfc4211c65f3f4d637a"
  ]
}
''')
_ORIGINAL_PINS = json.loads(r'''
{
  "darwin-arm64/build-receipt.json": [
    2014,
    "60f8f6140d3bd88d953f76d4b07286db6f0afb8583a9b4df1058846d501aa556"
  ],
  "darwin-arm64/node-authenticity.json": [
    1171,
    "420b5c8465976f3782917d4a22517a5060973e3eccd05e45297bea0ff7434f79"
  ],
  "darwin-arm64/package-manifest.json": [
    433214,
    "51a0611b02b9f6ea9c8429233b040fdd46a5b1f64014ec41bbfff8a72792e453"
  ],
  "darwin-arm64/package-record.json": [
    910,
    "44d126fc82a029f88496ba3025634f461fe26000589f71ec429b226923918d85"
  ],
  "darwin-arm64/plan.json": [
    1246,
    "e65e9de2ae42ea4336210fa1fb4e826a17b3b5e57801e1bc33b0a4b92d969c7a"
  ],
  "darwin-arm64/qualification.json": [
    1997,
    "9754d3dcb4a14b61aa794715f9be615762c38b92afb8b27132951b3c9e138273"
  ],
  "darwin-arm64/rc-evidence.json": [
    8215,
    "1e0f9e80a5cc2d8af4d6823bb69217318a9f79531fe917285c84e089cfcde9ca"
  ],
  "darwin-arm64/smoke/darwin-arm64-A-npm-package.receipt.json": [
    2844,
    "fba677533dc18694b04035e758dbc66687351d192c59f6baab482f366635c173"
  ],
  "darwin-arm64/smoke/darwin-arm64-A-npm-package.run.json": [
    2349,
    "c6351a335f886324b320e03bbdedc845d6f6dc6c0455b3dd2b860e1567b551bf"
  ],
  "darwin-arm64/smoke/darwin-arm64-A-raw-archive.receipt.json": [
    2830,
    "e157ab0376da0f24492f2457fd8aab090ca09fb00709885870a2ba5ac1983cb5"
  ],
  "darwin-arm64/smoke/darwin-arm64-A-raw-archive.run.json": [
    2352,
    "2cac2f0874b46cbf338ebceb6a3ebd81b6ce478a8e2898e5d46247c5867fc0cd"
  ],
  "linux-arm64/build-receipt.json": [
    2157,
    "39b48daab5dc6919038794ded7be2fec5b803257184e801a39e353662e75a358"
  ],
  "linux-arm64/node-authenticity.json": [
    850,
    "00d5766f8e73286d1788afc6e21661a6130d5692180f02d1df64c4086f9563a5"
  ],
  "linux-arm64/package-manifest.json": [
    421431,
    "49960a15d960136b74c0d5ff626580e2068d679bf743058209df990aeb1c1e96"
  ],
  "linux-arm64/package-record.json": [
    911,
    "bc8d04ecd054e383059bc7e2f9462a83516ac461404fd300d377a3b7ef6e9a6c"
  ],
  "linux-arm64/plan.json": [
    1246,
    "e65e9de2ae42ea4336210fa1fb4e826a17b3b5e57801e1bc33b0a4b92d969c7a"
  ],
  "linux-arm64/qualification.json": [
    2744,
    "cc4862bddc9950ee5e39c902ff91492a914eb02f230990b3a6b69a822b55d94a"
  ],
  "linux-arm64/rc-evidence.json": [
    9550,
    "09832b90cbbb2bfc1f2a27f235b1ebae313ead331f392bce649abad5b752baf7"
  ],
  "linux-arm64/smoke/linux-arm64-B-npm-package.receipt.json": [
    3145,
    "329e7d1e5a918b69f28532643a9a9afab1b3b3c1dab5fdbbf8fca1a0e5d1ecef"
  ],
  "linux-arm64/smoke/linux-arm64-B-npm-package.run.json": [
    2649,
    "21368695fca3efdea9928f466fdffa985b4aa4a0ff134245155c66511f7aaeed"
  ],
  "linux-arm64/smoke/linux-arm64-B-raw-archive.receipt.json": [
    3156,
    "bf5d5160d059171d01c724256d4e59c0a5b519252227b7f6602d0d888ade3f7f"
  ],
  "linux-arm64/smoke/linux-arm64-B-raw-archive.run.json": [
    2649,
    "854a521f25014e981b7558f5f685b17db3b0cebbe3b3ba039a523a4dee85231a"
  ],
  "linux-x64/build-receipt.json": [
    2151,
    "af12b2e3e1c012db4630e28aa9b360cf154ecaeb550f345cc55d6d1a79b50ec5"
  ],
  "linux-x64/node-authenticity.json": [
    847,
    "ed28783d541a39b126dfb63e7f7d6b6aac3d71c3dfa718a7ca63896e7514ec26"
  ],
  "linux-x64/package-manifest.json": [
    421421,
    "370f85ec51de194e55b0a0ac3f2c8862cc1ec10d8c525705b198f6e4ba44bdc5"
  ],
  "linux-x64/package-record.json": [
    906,
    "eea089ea4cfd28a93e6eda2b15e2cbf995389c404904b72575dcc65441705fb1"
  ],
  "linux-x64/plan.json": [
    1246,
    "e65e9de2ae42ea4336210fa1fb4e826a17b3b5e57801e1bc33b0a4b92d969c7a"
  ],
  "linux-x64/qualification.json": [
    2723,
    "a0fc621c10108a2ac26800e6fbef7a1d6cc669a9be98ca584c2b9980fa8aa1d9"
  ],
  "linux-x64/rc-evidence.json": [
    9110,
    "2e384ec263ec95ad12fb5ccf29a168d3ef12373c49b4744e1bd38eb872c4e9f9"
  ],
  "linux-x64/smoke/linux-x64-C-raw-archive.receipt.json": [
    2842,
    "1462005a7b869e927f52808e1d464b308ad633e0afb327d8da722d893d265cd3"
  ],
  "linux-x64/smoke/linux-x64-C-raw-archive.run.json": [
    2580,
    "4ccd3950121922b635d7317c9840366144cb2ffeb93f7eca7b7c56cb865b228b"
  ],
  "linux-x64/smoke/linux-x64-C-signal-npm-package.receipt.json": [
    2844,
    "72f64b298a4fc3fe26c1d3de818c18ad9f1fee17186a1f576668656243fd01fe"
  ],
  "linux-x64/smoke/linux-x64-C-signal-npm-package.run.json": [
    2973,
    "ff03af78e70407ed9b4f27019a8495c2582a0b8e96abf589d3c5da12acb9d47e"
  ]
}
''')
FINAL_COMMIT = "f2c527ee6f3cbd53fd44e095d5355ca7f5c7519a"
AUTHORITY_IDENTITY = "3ed872811ef61b4ac15d6f344de15d1986c5a71a505ee9bafcfb72413e264481"
_JOBS = {
    124464482398: "Select native release-candidate lanes",
    124464530373: "macOS arm64 release candidate (scenario A)",
    124464530387: "Linux arm64 release candidate (scenario B)",
    124464530436: "Linux x64 release candidate (scenario C + C-signal)",
    124468062948: "Release-candidate catalog",
}
_SEAL = object()
_ISSUED = weakref.WeakKeyDictionary()


def _fail():
    raise ContractError("NEBULAR071_PRODUCT_NATIVE", "Original product-native evidence is unavailable or disagrees")


def reference():
    """Return ordinary pinned configuration, never an admission."""
    return json.loads(canonical(_REFERENCE))


def validate_reference(value):
    if not isinstance(value, dict) or canonical(value) != canonical(_REFERENCE):
        _fail()
    return reference()


def catalog_index(data):
    """Inspect only the exact opaque original catalog ZIP, without extraction."""
    catalog = _REFERENCE["catalog"]
    if len(data) != catalog["size"] or hashlib.sha256(data).hexdigest() != catalog["sha256"]:
        _fail()
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            rows = archive.infolist()
            if len(rows) != 1:
                _fail()
            row = rows[0]
            mode = row.external_attr >> 16
            if (row.filename != "rc-index.json" or row.file_size != catalog["member"]["size"]
                    or row.is_dir() or row.flag_bits & 1 or row.extra
                    or stat.S_ISLNK(mode) or mode & 0o7111
                    or (stat.S_IFMT(mode) not in (0, stat.S_IFREG))):
                _fail()
            with archive.open(row) as stream:
                body = stream.read(catalog["member"]["size"] + 1)
            if (len(body) != catalog["member"]["size"]
                    or hashlib.sha256(body).hexdigest() != catalog["member"]["sha256"]):
                _fail()
            return strict_json(body)
    except (ValueError, OSError, zipfile.BadZipFile, RuntimeError):
        _fail()


def _body(root, relative, pin):
    data = read_evidence(root, relative, limit=pin[0])
    if len(data) != pin[0] or hashlib.sha256(data).hexdigest() != pin[1]:
        _fail()
    return data


def _apis(run, jobs, compiler, artifacts):
    ref = _REFERENCE
    repo = ref["repository"]
    if (run.get("id") != ref["run_id"] or type(run.get("run_attempt")) is not int
            or run.get("run_attempt") != 1
            or run.get("head_sha") != ref["tested_commit"]
            or run.get("path") != ref["workflow"] or run.get("workflow_id") != 371104521
            or run.get("event") != "pull_request"
            or run.get("status") != "completed" or run.get("conclusion") != "success"
            or any(run.get(k, {}).get("full_name") != repo
                   or run.get(k, {}).get("id") != 1358643872 for k in ("repository", "head_repository"))
            or compiler.get("sha") != ref["tested_commit"]
            or compiler.get("tree", {}).get("sha") != ref["tested_tree"]):
        _fail()
    rows = jobs.get("jobs")
    if (jobs.get("total_count") != 5 or not isinstance(rows, list) or len(rows) != 5
            or {r.get("id") for r in rows} != set(_JOBS)):
        _fail()
    for row in rows:
        if (row.get("name") != _JOBS[row["id"]] or row.get("run_id") != ref["run_id"]
                or type(row.get("run_attempt")) is not int or row.get("run_attempt") != 1
                or row.get("head_sha") != ref["tested_commit"]
                or row.get("status") != "completed" or row.get("conclusion") != "success"):
            _fail()
    rows = artifacts.get("artifacts")
    expected = {r["artifact_id"]: r["artifact_sha256"] for r in ref["lanes"]}
    expected[ref["catalog"]["id"]] = ref["catalog"]["sha256"]
    if (artifacts.get("total_count") != 4 or not isinstance(rows, list) or len(rows) != 4
            or {r.get("id") for r in rows} != set(expected)):
        _fail()
    for row in rows:
        ctx = row.get("workflow_run", {})
        try:
            expires = datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00"))
        except (ValueError, KeyError, TypeError):
            _fail()
        if (row.get("expired") is not False or expires.utcoffset() is None
                or expires <= datetime.now(timezone.utc)
                or row.get("digest") != "sha256:" + expected[row["id"]]
                or ctx.get("id") != ref["run_id"] or ctx.get("head_sha") != ref["tested_commit"]
                or ctx.get("repository_id") != 1358643872 or ctx.get("head_repository_id") != 1358643872):
            _fail()
    return {r["id"]: r for r in rows}


def _authenticate(root, product_capture, *, client=None):
    from rs9.nebular071_universal_consumer import authenticated_product_release
    from rs9.nebular071_installed_smoke import verified_application_receipt_digest
    frame = authenticated_product_release(product_capture)
    ref = _REFERENCE
    if (frame["release_id"] != 429782340 or frame["commit"] != FINAL_COMMIT
            or frame["tree"] != ref["tested_tree"]
            or frame["source"]["authority_identity"] != AUTHORITY_IDENTITY):
        _fail()
    root = Path(root)
    validate_reference(strict_json(read_evidence(root, "native-reference.json", limit=65536)))
    api = {n: strict_json(_body(root, "api/" + n, pin)) for n, pin in _API_PINS.items()}
    artifacts = _apis(api["run.json"], api["jobs.json"], api["compiler-commit.json"], api["artifacts.json"])
    if client is not None:
        prefix = "https://api.github.com/repos/" + ref["repository"]
        urls = {
            "run.json": prefix + "/actions/runs/41176311998/attempts/1",
            "jobs.json": prefix + "/actions/runs/41176311998/attempts/1/jobs?per_page=100",
            "compiler-commit.json": prefix + "/git/commits/" + ref["tested_commit"],
            "artifacts.json": prefix + "/actions/runs/41176311998/artifacts?per_page=100",
        }
        fresh = {n: client.json(url, request_class="github-api", limit=1024 * 1024) for n, url in urls.items()}
        fresh_artifacts = _apis(fresh["run.json"], fresh["jobs.json"], fresh["compiler-commit.json"], fresh["artifacts.json"])
        # The dynamic expired flag/time must still be checked; all fixed artifact
        # custody fields must agree with the original authenticated readback.
        for ident, row in artifacts.items():
            if any(fresh_artifacts[ident].get(k) != row.get(k)
                   for k in ("name", "size_in_bytes", "digest", "workflow_run")):
                _fail()
    catalog = strict_json(read_evidence(root, "artifact-metadata.json", limit=65536))
    if catalog != artifacts[ref["catalog"]["id"]]:
        _fail()
    if (catalog.get("name") != ref["catalog"]["name"]
            or catalog.get("size_in_bytes") != ref["catalog"]["size"]):
        _fail()
    index = catalog_index(read_evidence(root, "rc-index-original.zip", limit=2589))
    lanes = [r["lane"] for r in ref["lanes"]]
    if (index.get("schema") != "nebular.native-rc-index-v1" or index.get("status") != "pass"
            or index.get("source") != {"sha": ref["tested_commit"], "runId": "41176311998", "runAttempt": "1", "version": "0.7.1"}
            or index.get("selected") != lanes or index.get("passed") != lanes
            or index.get("failed") != [] or index.get("skipped") != []
            or len(index.get("lanes", [])) != 3):
        _fail()
    prov = frame["provenance"]
    if (prov.get("nativeCiRun") != ref["run_id"] or prov.get("nativeCiAttempt") != 1
            or prov.get("nativeIndexSha256") != ref["catalog"]["member"]["sha256"]
            or prov.get("testedCommit") != ref["tested_commit"] or prov.get("testedTree") != frame["tree"]):
        _fail()
    bodies = {n: _body(root, n, pin) for n, pin in _ORIGINAL_PINS.items()}
    raw_assets = []
    for lane, expected in zip(index["lanes"], ref["lanes"]):
        artifact = artifacts[expected["artifact_id"]]
        platform = lane["platform"]
        rc_body = bodies[platform + "/rc-evidence.json"]
        rc = strict_json(rc_body)
        q = strict_json(bodies[platform + "/qualification.json"])
        if (lane["lane"] != expected["lane"] or lane.get("selected") is not True
                or lane.get("status") != "qualified-automated" or lane.get("jobResult") != "success"
                or lane.get("problems") != [] or lane["source"] != rc.get("source")
                or lane["source"].get("commit") != ref["tested_commit"]
                or lane["source"].get("tree") != ref["tested_tree"]
                or int(lane["artifact"]["id"]) != artifact["id"]
                or lane["artifact"]["name"] != artifact["name"]
                or lane["artifact"]["apiDigest"] != artifact["digest"]
                or hashlib.sha256(rc_body).hexdigest() != lane["evidenceSha256"]
                or rc.get("schema") != "nebular.native-rc-evidence-v1" or rc.get("status") != "pass"
                or rc.get("problems") != [] or rc.get("lane") != lane["lane"]
                or rc.get("platform") != platform or rc.get("candidate") != lane["candidate"]
                or q.get("schema") != "nebular.native-rc-qualification-v1"
                or q.get("status") != "pass" or q.get("platform") != platform
                or q.get("executableSha256") != lane["candidate"]["raw"]["executableSha256"]
                or [{"id": r["id"], "ok": r["ok"]} for r in q["checks"]] != rc["qualification"]["checks"]
                or any(r.get("ok") is not True for r in q["checks"])):
            _fail()
        raw = lane["candidate"]["raw"]
        selected = frame["assets_by_name"].get(raw["filename"], {})
        manifests = product_capture.manifests
        manifest = manifests.get(raw["filename"])
        if manifest is None:
            # Generic capture keys manifests by selection payload id.
            target = "darwin-arm64" if platform == "darwin-arm64" else platform + "-gnu"
            manifest = manifests.get(target)
        target = "darwin-arm64" if platform == "darwin-arm64" else platform + "-gnu"
        payload_rows = [r for r in product_capture.record["payloads"] if r.get("id") == target]
        from rs9.wheel_nebular071_universal import _read
        raw_bytes, _identity = _read(product_capture.archives[target], raw["size"])
        if len(raw_bytes) != raw["size"] or hashlib.sha256(raw_bytes).hexdigest() != raw["sha256"]:
            _fail()
        if (len(payload_rows) != 1 or not isinstance(manifest, dict)
                or payload_rows[0].get("payload_manifest_sha256") != manifest.get("manifest_sha256")
                or hashlib.sha256(canonical(manifest.get("members"))).hexdigest() != manifest.get("manifest_sha256")):
            _fail()
        if (selected.get("role") != "payload" or selected.get("size") != raw["size"]
                or selected.get("sha256") != raw["sha256"] or not isinstance(manifest, dict)
                or len(manifest.get("members", [])) != raw["members"]
                or not any(r.get("sha256") == raw["executableSha256"] and r.get("type") == "file"
                           for r in manifest["members"])):
            _fail()
        matches = [a for a in prov["assets"] if a.get("name") == raw["filename"]]
        if (len(matches) != 1 or matches[0].get("role") != "raw-archive"
                or matches[0].get("id") != selected.get("github_asset_id")
                or matches[0].get("sha256") != raw["sha256"] or matches[0].get("bytes") != raw["size"]):
            _fail()
        raw_assets.append({"id": selected["github_asset_id"], "name": raw["filename"],
                           "size": raw["size"], "sha256": raw["sha256"],
                           "manifest_sha256": manifest["manifest_sha256"]})
        if ([{k: row[k] for k in ("label", "scenario", "source", "status", "receiptSha256")}
             for row in rc.get("smoke", [])] != lane.get("smoke")):
            _fail()
        for smoke in rc["smoke"]:
            prefix = platform + "/smoke/" + smoke["label"]
            run = strict_json(bodies[prefix + ".run.json"])
            receipt_body = bodies[prefix + ".receipt.json"]
            receipt = strict_json(receipt_body)
            verified_application_receipt_digest(receipt_body, smoke["receiptSha256"])
            if (run.get("schema") != "nebular.native-rc-smoke-run-v1" or run.get("status") != "pass"
                    or run.get("platform") != platform or run.get("scenario") != smoke["scenario"]
                    or run.get("source") != smoke["source"] or run.get("problems") != []
                    or run.get("receipt", {}).get("sha256") != smoke["receiptSha256"]
                    or run.get("receipt", {}).get("steps") != smoke["steps"]
                    or run.get("exit") != smoke["exit"]
                    or run.get("checks", {}).get("orphans") != []
                    or run.get("checks", {}).get("persistentUserState", {}).get("changed") != []
                    or run.get("finalization", {}).get("status") != "complete"
                    or run.get("finalization", {}).get("exitObserved") is not True
                    or receipt.get("status") != "pass" or receipt.get("applicationVersion") != "0.7.1"
                    or any(r.get("ok") is not True for r in receipt.get("driver", {}).get("steps", []))):
                _fail()
    return {"schema": "rs9.nebular071-product-native-admission-frame.v1",
            "reference": reference(), "product_source": frame["source"],
            "assets": raw_assets, "compiler_relation": "authenticated-equal-tree"}


class _NativePayloadAdmission:
    __slots__ = ("__weakref__",)

    def __init__(self, seal=None):
        if seal is not _SEAL:
            _fail()


def replay_native_admission(root, product_capture, *, client=None):
    """Re-run authenticators; saved JSON and status fields never admit."""
    try:
        frame = _authenticate(Path(root), product_capture, client=client)
        admission = _NativePayloadAdmission(_SEAL)
        _ISSUED[admission] = (os.getpid(), Path(root), product_capture, canonical(frame))
        return admission
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        _fail()


def require_native_admission(admission, product_capture, ref, asset=None):
    """Require same-process minted capability and replay unchanged held bytes."""
    validate_reference(ref)
    if type(admission) is not _NativePayloadAdmission:
        _fail()
    state = _ISSUED.get(admission)
    if state is None or state[0] != os.getpid() or state[2] is not product_capture:
        _fail()
    try:
        frame = _authenticate(state[1], product_capture)
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        _fail()
    if canonical(frame) != state[3]:
        _fail()
    if asset is not None and not any(all(row.get(k) == asset.get(k) for k in ("id", "name", "size", "sha256"))
                                     for row in frame["assets"]):
        _fail()
    return frame


def replay_descriptor_native(descriptor, inrun_root, product_capture, *, client=None):
    evidence = descriptor.get("evidence", {})
    # Fixed native evidence role, not a caller-selected arbitrary path.
    if evidence.get("source_root") != "evidence/public-release":
        _fail()
    root = Path(inrun_root) / "evidence/public-release/native-ci"
    declared = evidence.get("files")
    if not isinstance(declared, dict):
        _fail()
    names = {"rc-index-original.zip", "native-reference.json", "artifact-metadata.json"}
    names.update("api/" + name for name in _API_PINS)
    names.update(_ORIGINAL_PINS)
    for name in names:
        # Every fixed-role held body is also enrolled in descriptor custody;
        # descriptor hashes alone still cannot mint native admission.
        body = read_evidence(root, name, limit=1024 * 1024)
        relative = "native-ci/" + name
        row = declared.get(relative)
        if (not isinstance(row, dict) or set(row) != {"path", "size", "sha256"}
                or row.get("path") != relative or type(row.get("size")) is not int
                or row["size"] != len(body) or row.get("sha256") != hashlib.sha256(body).hexdigest()):
            _fail()
    return replay_native_admission(root, product_capture, client=client)
