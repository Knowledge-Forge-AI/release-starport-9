"""Closed upstream Actions-artifact transport; never publication authority."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

from .tf_pypi_model import validate_pin, admit_bytes

ROOT = Path(__file__).resolve().parents[2]
SELECTION = ROOT / "operators/tf-pypi/actions-inputs/loom-0.5.0-ci.json"
PIN = ROOT / "operators/tf-pypi/theme-forge-stellar-loom-0.5.0.json"
REPO = "Knowledge-Forge-AI/theme-forge-stellar-loom"
API = "https://api.github.com/repos/" + REPO
PROJECT = "theme-forge-stellar-loom"
ARTIFACT_HOST = "productionresultssa5.blob.core.windows.net"
MAX_JSON = 16 * 1024 * 1024
MAX_ZIP = 32 * 1024 * 1024
MAX_EXPANDED = 64 * 1024 * 1024
ROOT_FILES = {"receipt.json", "pack-manifest.json", "test-report.json", "audit-result.json", "root-package.tgz", "artifact-manifest.json"}
ARTIFACT_FILES = {
    "root-package-artifacts": ROOT_FILES,
    "source-policy-receipt": {"receipt.json", "artifact-manifest.json"},
    "evidence-aggregate-artifacts": {"receipt.json", "ci-evidence-manifest.json", "ci-evidence-summary.md"},
}


def require(condition, reason):
    if not condition:
        raise ValueError("ACTIONS_INPUT_" + reason)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def decode(data):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "DUPLICATE_JSON_KEY")
            result[key] = value
        return result
    require(len(data) <= MAX_JSON, "JSON_LIMIT")
    return json.loads(data.decode("utf-8"), object_pairs_hook=pairs)


def frame(s):
    return (s.st_dev, s.st_ino, s.st_size, s.st_mode, s.st_mtime_ns, s.st_ctime_ns, s.st_uid, s.st_gid, s.st_nlink)


def parents(path):
    for parent in reversed(path.absolute().parents):
        s = parent.lstat()
        require(stat.S_ISDIR(s.st_mode), "PARENT")


def regular(path, limit):
    parents(path)
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= limit, "INPUT_TYPE")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as f:
        require(frame(os.fstat(f.fileno())) == frame(before), "INPUT_OPEN")
        data = f.read(limit + 1)
        require(len(data) == before.st_size and frame(os.fstat(f.fileno())) == frame(before), "INPUT_READ")
    require(frame(path.lstat()) == frame(before), "INPUT_NAMED")
    return data


def validate_selection(s, pin):
    require(s["schema"] == "rs9.tf-pypi-actions-selection.v1" and s["repository"] == REPO and s["repositoryId"] == 1361513719, "SELECTION_REPO")
    require(s["project"] == PROJECT and s["version"] == "0.5.0", "SELECTION_PROJECT")
    r = s["run"]
    require(r["id"] == 40222221851 and r["run_attempt"] == 1 and r["workflow_id"] == 353226742 and r["path"] == ".github/workflows/ci.yml", "SELECTION_RUN")
    require(r["event"] == "pull_request" and r["head_branch"] == "staging" and r["status"] == "completed" and r["conclusion"] == "success" and s["pr"] == 5, "SELECTION_STATUS")
    for value in [r["head_sha"], s["headTree"], s["baseCommit"], s["ciMergeCommit"], s["mainCommit"]]:
        require(isinstance(value, str) and re.fullmatch("[0-9a-f]{40}", value), "COMMIT")
    require(s["workflow"]["id"] == r["workflow_id"] and s["workflow"]["path"] == r["path"], "WORKFLOW")
    require(pin["project"] == PROJECT and pin["version"] == "0.5.0" and pin["source_commit"] == s["mainCommit"], "PIN_SOURCE")
    require(pin["sha256"] == s["pack"]["sha256"] and pin["size"] == s["pack"]["bytes"] and pin["size"] == 272836, "PIN_PACK")
    require(re.fullmatch("[0-9a-f]{64}", pin["sha256"]), "PACK_SHA")
    require(len(s["artifacts"]) == 3 and {a["name"] for a in s["artifacts"]} == set(ARTIFACT_FILES), "ARTIFACT_SET")
    require(len({a["id"] for a in s["artifacts"]}) == 3, "ARTIFACT_IDS")
    for a in s["artifacts"]:
        require(type(a["id"]) is int and a["id"] > 0 and type(a["size_in_bytes"]) is int and 0 < a["size_in_bytes"] <= MAX_ZIP, "ARTIFACT_SIZE")
        require(re.fullmatch("sha256:[0-9a-f]{64}", a["digest"]) and a["expired"] is False, "ARTIFACT_DIGEST")
        require(a["workflow_run"]["id"] == r["id"] and a["workflow_run"]["head_sha"] == r["head_sha"], "ARTIFACT_RUN")
        members = a["members"]
        require(len(members) == len(ARTIFACT_FILES[a["name"]]) and {m["name"] for m in members} == ARTIFACT_FILES[a["name"]], "SELECTED_MEMBER_SET")
        for m in members:
            require(type(m["bytes"]) is int and 0 < m["bytes"] <= MAX_JSON and re.fullmatch("[0-9a-f]{64}", m["sha256"]), "SELECTED_MEMBER")
    aggregate_rows(s["aggregateArtifacts"])
    hosts = s["artifactDownloadHosts"]
    require(hosts == [ARTIFACT_HOST], "REDIRECT_HOSTS")
    for host in hosts:
        require(host == ARTIFACT_HOST, "REDIRECT_HOST")
    require(s["redirectAdmission"] == ("exact-live-host-observed" if hosts else "pending-exact-live-host-observation"), "REDIRECT_ADMISSION")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Client:
    """Token only to fixed API; artifact redirect hosts require reviewed admission."""
    def __init__(self, selection):
        self.hosts = selection["artifactDownloadHosts"]
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def get(self, suffix, limit, archive=False):
        require(suffix.startswith("/") and not any(c in suffix for c in ["..", "#", "\\"]), "ENDPOINT")
        url = API + suffix
        deadline = time.monotonic() + 120
        for step in range(4):
            parsed = urllib.parse.urlsplit(url)
            headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "rs9-actions-intake"}
            if step == 0:
                token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
                if token:
                    headers["Authorization"] = "Bearer " + token
            else:
                require(archive and parsed.scheme == "https" and parsed.hostname == ARTIFACT_HOST and parsed.hostname in self.hosts and not parsed.username and not parsed.password and not parsed.fragment and parsed.port in (None, 443), "REDIRECT")
                headers = {"User-Agent": "rs9-actions-intake"}
            require(time.monotonic() < deadline, "HTTP_DEADLINE")
            request = urllib.request.Request(url, headers=headers)
            try:
                response = self.opener.open(request, timeout=min(20, max(0.1, deadline - time.monotonic())))
            except urllib.error.HTTPError as error:
                if error.code in (301, 302, 303, 307, 308):
                    try:
                        require(archive, "API_REDIRECT")
                        url = urllib.parse.urljoin(url, error.headers.get("Location", ""))
                    finally:
                        error.close()
                    continue
                error.close()
                raise ValueError("ACTIONS_INPUT_HTTP_STATUS") from None
            with response:
                require(response.status == 200 and response.geturl() == url, "HTTP_RESPONSE")
                chunks = []; count = 0
                while True:
                    require(time.monotonic() < deadline, "HTTP_DEADLINE")
                    block = response.read1(min(65536, limit + 1 - count))
                    if not block:
                        break
                    chunks.append(block); count += len(block)
                    require(count <= limit, "HTTP_LIMIT")
                return b"".join(chunks)
        raise ValueError("ACTIONS_INPUT_REDIRECT_LIMIT")

    def json(self, suffix):
        return decode(self.get(suffix, MAX_JSON))


def authenticate(s, client):
    r = client.json("/actions/runs/40222221851/attempts/1")
    for key in ("id", "run_attempt", "workflow_id", "path", "head_sha", "head_branch", "event", "status", "conclusion"):
        require(r[key] == s["run"][key], "LIVE_RUN_" + key.upper())
    require(r["repository"]["full_name"] == REPO and r["repository"]["id"] == s["repositoryId"] and r["head_repository"]["id"] == s["repositoryId"], "LIVE_REPO")
    workflow = client.json("/actions/workflows/353226742")
    require(workflow["id"] == s["workflow"]["id"] and workflow["path"] == s["workflow"]["path"] and workflow["state"] == "active", "LIVE_WORKFLOW")
    pr = client.json("/pulls/5")
    require(pr["number"] == 5 and pr["merged"] is True and pr["merge_commit_sha"] == s["mainCommit"], "LIVE_PR_MERGE")
    require(pr["head"]["sha"] == s["run"]["head_sha"] and pr["head"]["ref"] == "staging" and pr["base"]["ref"] == "main", "LIVE_PR_HEAD")
    require(pr["head"]["repo"]["id"] == s["repositoryId"] and pr["base"]["repo"]["id"] == s["repositoryId"], "LIVE_PR_REPO")
    commits = {}
    for key, sha in [("head", s["run"]["head_sha"]), ("ci", s["ciMergeCommit"]), ("main", s["mainCommit"])]:
        value = client.json("/git/commits/" + sha)
        require(value["sha"] == sha and value["tree"]["sha"] == s["headTree"], "LIVE_TREE")
        commits[key] = value
    require([p["sha"] for p in commits["ci"]["parents"]] == [s["baseCommit"], s["run"]["head_sha"]], "LIVE_CI_PARENTS")
    artifacts = {}
    for a in s["artifacts"]:
        actual = client.json("/actions/artifacts/" + str(a["id"]))
        for key in ("id", "name", "size_in_bytes", "digest", "expired"):
            require(actual[key] == a[key], "LIVE_ARTIFACT_" + key.upper())
        for key in ("id", "head_sha", "repository_id", "head_repository_id"):
            require(actual["workflow_run"][key] == a["workflow_run"][key], "LIVE_ARTIFACT_RUN")
        artifacts[a["name"]] = actual
    # pull_requests may legitimately be empty after merge; PR API and receipts bind it.
    return {"run": r, "workflow": workflow, "pr": pr, "commits": commits, "artifacts": artifacts}


def unpack(data, name):
    require(len(data) <= MAX_ZIP, "ZIP_LIMIT")
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        infos = z.infolist()
        require(len(infos) == len(ARTIFACT_FILES[name]) and len(infos) <= 16, "ZIP_COUNT")
        names = [i.filename for i in infos]
        require(all(i.orig_filename == i.filename and "\x00" not in i.orig_filename for i in infos), "ZIP_RAW_NAME")
        require(set(names) == ARTIFACT_FILES[name] and len(set(n.casefold() for n in names)) == len(names), "ZIP_NAMES")
        require(sum(i.file_size for i in infos) <= MAX_EXPANDED, "ZIP_EXPANDED")
        output = {}
        for info in infos:
            mode = info.external_attr >> 16
            require(not info.is_dir() and not info.flag_bits & 1 and stat.S_IFMT(mode) in (0, stat.S_IFREG) and not mode & 0o7000, "ZIP_TYPE")
            cap = 272836 if info.filename == "root-package.tgz" else MAX_JSON
            require(0 < info.file_size <= cap, "ZIP_MEMBER_LIMIT")
            with z.open(info) as f:
                body = f.read(cap + 1)
                require(len(body) == info.file_size and not f.read(1), "ZIP_MEMBER_SIZE")
            output[info.filename] = body
        return output


def selected_members(artifact, files):
    require(len(artifact["members"]) == len(files) and {r["name"] for r in artifact["members"]} == set(files), "SELECTED_MEMBER_SET")
    for row in artifact["members"]:
        body = files[row["name"]]
        require(len(body) == row["bytes"] and digest(body) == row["sha256"], "SELECTED_MEMBER_BODY")


def receipt(s, raw, job, role):
    r = decode(raw)
    require(r["schema"] == "tfsb.ci-exact-head-receipt" and r["schemaVersion"] == 1 and r["status"] == "pass", "RECEIPT")
    e = r["event"]; w = r["workflow"]; c = r["checkout"]
    require(e["name"] == "pull_request" and e["action"] in ("opened", "synchronize", "reopened") and e["number"] == 5, "RECEIPT_EVENT")
    require(all(e[k] == REPO for k in ("repository", "headRepository", "baseRepository")), "RECEIPT_REPO")
    require(e["headRef"] == "staging" and e["baseRef"] == "main" and e["headSha"] == s["run"]["head_sha"] and e["baseSha"] == s["baseCommit"], "RECEIPT_HEAD")
    require(w["runId"] == str(s["run"]["id"]) and w["runAttempt"] == "1" and w["job"] == job and w["matrix"] == {}, "RECEIPT_RUN")
    require(c["role"] == role and c["clean"] is True and c["tree"] == s["headTree"], "RECEIPT_CHECKOUT")
    require(c["commit"] == (s["run"]["head_sha"] if role == "staging-head" else s["ciMergeCommit"]), "RECEIPT_COMMIT")
    if role == "merge-candidate":
        require(c["parents"] == [s["baseCommit"], s["run"]["head_sha"]], "RECEIPT_PARENTS")
    head = r["identities"]["stagingHead"]
    require(head["commit"] == s["run"]["head_sha"] and head["tree"] == s["headTree"] and head["repository"] == REPO, "RECEIPT_STAGING")
    return r


def manifest(files, job):
    m = decode(files["artifact-manifest.json"])
    require(m["schema"] == "tfsb.ci-job-artifact-manifest" and m["schemaVersion"] == 1 and m["status"] == "pass" and m["job"] == job and m["matrix"] == {}, "MANIFEST")
    rows = m["artifacts"]
    require(len(rows) == len(files) - 1 and {r["path"] for r in rows} == set(files) - {"artifact-manifest.json"}, "MANIFEST_SET")
    for row in rows:
        body = files[row["path"]]
        require(row["size"] == len(body) and row["sha256"] == digest(body), "MANIFEST_BODY")


def aggregate_rows(rows):
    require(isinstance(rows, list) and len(rows) == 35, "AGGREGATE_ROW_COUNT")
    seen = set()
    for row in rows:
        require(isinstance(row, dict) and set(row) == {"path", "size", "sha256"}, "AGGREGATE_ROW_SHAPE")
        path = row["path"]
        require(isinstance(path, str) and path and not path.startswith("/") and "\\" not in path and "\x00" not in path, "AGGREGATE_ROW_PATH")
        require(all(part not in ("", ".", "..") for part in path.split("/")), "AGGREGATE_ROW_PATH")
        require(path not in seen and path.casefold() not in {p.casefold() for p in seen}, "AGGREGATE_ROW_DUPLICATE")
        seen.add(path)
        require(type(row["size"]) is int and 0 < row["size"] <= MAX_EXPANDED, "AGGREGATE_ROW_SIZE")
        require(isinstance(row["sha256"], str) and re.fullmatch("[0-9a-f]{64}", row["sha256"]), "AGGREGATE_ROW_SHA")
    require(sum(row["size"] for row in rows) <= MAX_EXPANDED, "AGGREGATE_ROWS_LIMIT")
    return {row["path"]: row for row in rows}


def validate_bodies(s, pin, files):
    root = files["root-package-artifacts"]; source = files["source-policy-receipt"]; aggregate = files["evidence-aggregate-artifacts"]
    manifest(root, "root-package"); manifest(source, "source-policy")
    receipt(s, root["receipt.json"], "root-package", "merge-candidate")
    receipt(s, source["receipt.json"], "source-policy", "staging-head")
    receipt(s, aggregate["receipt.json"], "evidence-aggregate", "merge-candidate")
    a = decode(aggregate["ci-evidence-manifest.json"])
    require(a["schema"] == "tfsb.ci-aggregate-evidence-manifest" and a["schemaVersion"] == 3 and a["status"] == "pass" and a["errors"] == [], "AGGREGATE")
    require(a["product"] == "stellar-loom" and a["headSha"] == s["run"]["head_sha"] and a["headTree"] == s["headTree"], "AGGREGATE_HEAD")
    needs = a["dependencyResults"]
    expected = {"source-policy", "root-package", "consumer-fixture", "codeql", "supply-chain"}
    require(set(needs) == expected and all(v == "success" for v in needs.values()), "AGGREGATE_JOBS")
    rows = a["artifacts"]
    index = aggregate_rows(rows)
    require(index == aggregate_rows(s["aggregateArtifacts"]), "AGGREGATE_SELECTED_ROWS")
    for name, members in [("root-package-artifacts", root), ("source-policy-receipt", source)]:
        for path, body in members.items():
            row = index[name + "/" + path]
            require(row["size"] == len(body) and row["sha256"] == digest(body), "AGGREGATE_BODY")
    pack = root["root-package.tgz"]
    require(len(pack) == pin["size"] and digest(pack) == pin["sha256"], "PACKAGE")
    p = decode(root["pack-manifest.json"])
    require(isinstance(p, list) and len(p) == 1 and p[0]["name"] == pin["npm_name"] and p[0]["version"] == pin["version"] and p[0]["size"] == len(pack), "PACK_MANIFEST")
    import base64
    require(p[0]["integrity"] == "sha512-" + base64.b64encode(hashlib.sha512(pack).digest()).decode(), "PACK_INTEGRITY")
    admit_bytes(pin, pack, pin["asset"])
    return pack


def write_new(path, data):
    parents(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data); f.flush(); os.fsync(f.fileno())
    require(regular(path, max(len(data), 1)) == data, "OUTPUT_READBACK")


def transport(output, client=None):
    """Create one fresh owned output root; retain truthful partial failure there."""
    selection_bytes = regular(SELECTION, MAX_JSON)
    pin_bytes = regular(PIN, MAX_JSON)
    control_frames = {SELECTION: frame(SELECTION.lstat()), PIN: frame(PIN.lstat())}
    s = decode(selection_bytes); pin = decode(pin_bytes)
    validate_pin(pin); validate_selection(s, pin)
    def controls():
        for path, data in [(SELECTION, selection_bytes), (PIN, pin_bytes)]:
            require(frame(path.lstat()) == control_frames[path], "CONTROL_FRAME")
            require(regular(path, MAX_JSON) == data and frame(path.lstat()) == control_frames[path], "CONTROL_POSTGUARD")
    output = Path(output).absolute(); parents(output)
    output.mkdir(mode=0o700)
    anchor = output.stat(); anchor = (anchor.st_dev, anchor.st_ino, anchor.st_mode, anchor.st_uid, anchor.st_gid)
    def owned():
        now = output.lstat()
        require(stat.S_ISDIR(now.st_mode) and (now.st_dev, now.st_ino, now.st_mode, now.st_uid, now.st_gid) == anchor, "OUTPUT_OWNER")
    try:
        owned(); c = client or Client(s)
        metadata = authenticate(s, c)
        payloads = {}
        evidence = output / "producer"; evidence.mkdir(mode=0o700)
        write_new(evidence / "selection.json", (json.dumps(s, sort_keys=True) + "\n").encode())
        write_new(evidence / "api-metadata.json", (json.dumps(metadata, sort_keys=True) + "\n").encode())
        for a in s["artifacts"]:
            raw = c.get("/actions/artifacts/" + str(a["id"]) + "/zip", MAX_ZIP, archive=True)
            require(len(raw) == a["size_in_bytes"] and "sha256:" + digest(raw) == a["digest"], "ARCHIVE_DIGEST")
            payloads[a["name"]] = unpack(raw, a["name"])
            selected_members(a, payloads[a["name"]])
            write_new(evidence / (str(a["id"]) + ".zip"), raw)
        pack = validate_bodies(s, pin, payloads)
        inputs = output / "inputs"; inputs.mkdir(mode=0o700)
        write_new(inputs / pin["asset"], pack)
        controls()
        owned()
        result = {"schema": "rs9.tf-pypi-actions-transport.v1", "status": "transport-admitted", "project": PROJECT, "upstream_run": s["run"]["id"], "upstream_attempt": 1, "source_commit": s["mainCommit"], "source_tree": s["headTree"], "package_sha256": digest(pack), "package_bytes": len(pack), "publication_admitted": False, "public_writes": 0, "native_qualification": False}
        write_new(output / "transport-receipt.json", (json.dumps(result, sort_keys=True) + "\n").encode())
        return result
    except BaseException as error:
        guard_errors = []
        retention_errors = []
        try:
            controls()
        except Exception as guard:
            guard_errors.append(type(guard).__name__)
        failure = {"schema": "rs9.tf-pypi-actions-transport-failure.v1", "status": "failed", "error_class": type(error).__name__, "reason": str(error) if isinstance(error, ValueError) and str(error).startswith("ACTIONS_INPUT_") else None, "control_postguard_errors": guard_errors, "retention_errors": retention_errors, "failurePersistenceUnknown": False, "publication_admitted": False}
        try:
            owned()
        except BaseException as custody:
            retention_errors.append({"role": "output-owner", "error_class": type(custody).__name__})
            failure["failurePersistenceUnknown"] = True
        else:
            try:
                write_new(output / "failure.json", (json.dumps(failure) + "\n").encode())
            except BaseException as retention:
                retention_errors.append({"role": "failure-receipt", "error_class": type(retention).__name__})
                failure["failurePersistenceUnknown"] = True
        # Preserve the primary exception and expose bounded finalization facts to
        # the CLI/parent even when there is no longer an owned writable root.
        error.transport_failure = failure
        raise


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", required=True)
    args = p.parse_args(argv)
    try:
        result = transport(args.output)
    except Exception as error:
        failure = getattr(error, "transport_failure", {"status": "failed", "error_class": type(error).__name__, "failurePersistenceUnknown": True, "publication_admitted": False})
        print(json.dumps(failure, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
