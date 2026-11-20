"""Assemble website files while retaining the exact published package inventory.

This program reads public artifacts and GitHub deployment metadata. It never
imports package contents, invokes a package manager, signs, or publishes.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
import urllib.error
import urllib.parse
import urllib.request


class Refused(Exception):
    pass


SITES = {
    "theme-forge-packages": "tf.rs9.knowledge-forge.ai",
    "release-starport-9": "rs9.knowledge-forge.ai",
}
WEBSITE_FILES = ("index.html", "styles.css", "main.js", "robots.txt", "CNAME", "hikari.webp")
INVENTORY_SHA256 = "83f3792790824c9837260f79a365683b1288709e6f37442df87aac3da0ae530c"
RS9_INVENTORY_FILE = "rs9-package-inventory.json"
RS9_PACKAGE_PREFIX = "packages/rs9/"
RS9_CHANNELS = frozenset({"apt", "rpm", "pacman", "keys"})
INITIAL_PACKAGE_DEPLOYMENT = 7688464725
INITIAL_PACKAGE_SOURCE = "97f6895f465dbd86000025805135e50f653f28a5"


def require(condition, code):
    if not condition:
        raise Refused(code)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def safe_member(path):
    require(isinstance(path, str) and re.fullmatch(r"[A-Za-z0-9_./+-]+", path), "MEMBER_NAME")
    parts = path.split("/")
    require(not path.startswith("/") and all(p not in ("", ".", "..") for p in parts), "MEMBER_PATH")
    require(all(p.casefold() not in ("db", "raw", ".serena", ".git") for p in parts), "MEMBER_SCOPE")
    return path


def validate_inventory(data):
    require(isinstance(data, dict) and len(data) == 75, "INVENTORY_COUNT")
    total = 0
    for path, record in data.items():
        safe_member(path)
        require(PurePosixPath(path).parts[0] in ("apt", "arch", "keys", "rpm"), "INVENTORY_ROOT")
        require(isinstance(record, dict) and set(record) == {"bytes", "sha256"}, "INVENTORY_FIELDS")
        require(type(record["bytes"]) is int and 0 < record["bytes"] <= 128 * 1024 * 1024, "MEMBER_BOUND")
        require(isinstance(record["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", record["sha256"]), "MEMBER_DIGEST")
        total += record["bytes"]
    require(total == 268028902, "INVENTORY_TOTAL")
    return data


def unique_json_object(pairs):
    result = {}
    for name, value in pairs:
        require(name not in result, "RS9_INVENTORY_DUPLICATE")
        result[name] = value
    return result


def read_rs9_inventory(site_root):
    source = read_regular(site_root / RS9_INVENTORY_FILE, 65536)
    data = json.loads(source, object_pairs_hook=unique_json_object)
    require(isinstance(data, dict) and data.keys() == {"schema", "files"}
            and data["schema"] == "knowledge-forge.rs9-pages-inventory.v1", "RS9_INVENTORY_SCHEMA")
    inventory = data["files"]
    require(isinstance(inventory, dict) and 1 <= len(inventory) <= 128, "RS9_INVENTORY_COUNT")
    total = 0
    path_set = set()
    channels = set()
    for name, record in inventory.items():
        safe_member(name)
        relative = name.removeprefix(RS9_PACKAGE_PREFIX)
        channel, separator, _ = relative.partition("/")
        require(relative != name and separator and channel in RS9_CHANNELS, "RS9_INVENTORY_ROOT")
        channels.add(channel)
        require(name.casefold() not in path_set, "RS9_INVENTORY_CASE_COLLISION")
        path_set.add(name.casefold())
        require(isinstance(record, dict) and record.keys() == {"bytes", "sha256"}, "RS9_INVENTORY_FIELDS")
        require(type(record["bytes"]) is int and 0 < record["bytes"] <= 16 * 1024 * 1024, "RS9_MEMBER_BOUND")
        require(isinstance(record["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", record["sha256"]), "RS9_MEMBER_DIGEST")
        total += record["bytes"]
    require(total <= 64 * 1024 * 1024, "RS9_INVENTORY_TOTAL")
    require(all(not any(parent.as_posix().casefold() in path_set for parent in PurePosixPath(name).parents)
                for name in inventory), "RS9_INVENTORY_PATH_COLLISION")
    require(channels == RS9_CHANNELS, "RS9_INVENTORY_CHANNELS")
    return inventory, sha256(source)


def verify_live_rs9_inventory(previous, inventory, digest, *, initial):
    if initial and previous.get("kind") == "initial-project-site":
        return  # Deployment admission already confirmed that the origin has no site.
    origin = "https://" + SITES["release-starport-9"]
    receipt = json.loads(fetch(origin + "/site-preservation.json", 65536), object_pairs_hook=unique_json_object)
    require(isinstance(receipt, dict)
            and receipt.get("schema") == "knowledge-forge.website-preservation.v1"
            and receipt.get("repository") == "Knowledge-Forge-AI/release-starport-9"
            and previous.get("sourceCommit") is not None
            and receipt.get("websiteSourceCommit") == previous["sourceCommit"], "RS9_LIVE_RECEIPT_IDENTITY")
    require("protectedInventorySha256" in receipt and receipt["protectedInventorySha256"] == (None if initial else digest)
            and type(receipt.get("protectedFileCount")) is int
            and receipt["protectedFileCount"] == (0 if initial else len(inventory))
            and type(receipt.get("protectedPublicBytes")) is int
            and receipt["protectedPublicBytes"] == (0 if initial else sum(record["bytes"] for record in inventory.values())),
            "RS9_LIVE_INVENTORY_MISMATCH")


class SameOriginRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        before = urllib.parse.urlsplit(request.full_url)
        after = urllib.parse.urlsplit(newurl)
        require(after.scheme == "https" and after.netloc == before.netloc, "REDIRECT_ORIGIN")
        if before.netloc == "api.github.com":
            prefix = "/".join(before.path.split("/")[:4]) + "/"
            require(after.path.startswith(prefix), "REDIRECT_REPOSITORY")
        return super().redirect_request(request, fp, code, message, headers, newurl)


def fetch(url, limit, token=None):
    headers = {"User-Agent": "Knowledge-Forge-website-assembly", "Accept-Encoding": "identity"}
    if token:
        require(urllib.parse.urlsplit(url).netloc == "api.github.com", "TOKEN_DESTINATION")
        headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.build_opener(SameOriginRedirect()).open(request, timeout=30) as response:
        require(response.status == 200, "HTTP_STATUS")
        body = response.read(limit + 1)
    require(len(body) <= limit, "HTTP_BODY_BOUND")
    return body


def api(repository, suffix):
    require(repository in SITES and suffix.startswith(("deployments?", "deployments/", "actions/runs/")), "API_SCOPE")
    return json.loads(fetch("https://api.github.com/repos/Knowledge-Forge-AI/" + repository + "/" + suffix,
                            2 * 1024 * 1024, os.environ.get("GH_TOKEN")))


def admit_previous_deployment(repository):
    deployments = api(repository, "deployments?environment=github-pages&per_page=1")
    require(isinstance(deployments, list) and len(deployments) <= 1, "DEPLOYMENT_RESPONSE")
    if not deployments:
        require(repository == "release-starport-9", "PACKAGE_DEPLOYMENT_MISSING")
        try:
            fetch("https://" + SITES[repository] + "/", 1024 * 1024)
        except urllib.error.HTTPError as error:
            require(error.code == 404, "INITIAL_ORIGIN_UNKNOWN")
        else:
            raise Refused("INITIAL_ORIGIN_NOT_EMPTY")
        return {"kind": "initial-project-site", "previousDeployment": None}
    deployment = deployments[0]
    identifier = deployment.get("id")
    require(type(identifier) is int and identifier > 0 and deployment.get("ref") == "main", "DEPLOYMENT_IDENTITY")
    statuses = api(repository, "deployments/" + str(identifier) + "/statuses")
    require(isinstance(statuses, list) and statuses and statuses[0].get("state") == "success", "PREVIOUS_DEPLOYMENT_NOT_SUCCESSFUL")
    if repository == "theme-forge-packages" and identifier == INITIAL_PACKAGE_DEPLOYMENT:
        require(deployment.get("sha") == INITIAL_PACKAGE_SOURCE, "INITIAL_PACKAGE_SOURCE")
        require(statuses[0].get("log_url") == "https://github.com/Knowledge-Forge-AI/theme-forge-packages/actions/runs/42859410403/job/129981612851", "INITIAL_PACKAGE_RUN")
        return {"kind": "qualified-package-publication", "previousDeployment": identifier}
    prefix = "https://github.com/Knowledge-Forge-AI/" + repository + "/actions/runs/"
    log = statuses[0].get("log_url", "")
    require(isinstance(log, str) and log.startswith(prefix), "PREVIOUS_RUN_LINK")
    suffix = log[len(prefix):]
    match = re.fullmatch(r"([1-9][0-9]*)/job/[1-9][0-9]*", suffix)
    require(match is not None, "PREVIOUS_RUN_LINK")
    run = api(repository, "actions/runs/" + match.group(1))
    publishers = {".github/workflows/project-pages.yml"}
    if repository == "release-starport-9":
        publishers.add(".github/workflows/rs9-cli-linux-publish-v010.yml")
    require(run.get("path") in publishers and run.get("head_branch") == "main"
            and run.get("conclusion") == "success" and run.get("head_sha") == deployment.get("sha"), "FOREIGN_PAGES_PUBLISHER")
    result = {"kind": "prior-website-publication", "previousDeployment": identifier}
    if repository == "release-starport-9":
        require(isinstance(deployment.get("sha"), str) and re.fullmatch(r"[0-9a-f]{40}", deployment["sha"]),
                "RS9_PREVIOUS_SOURCE")
        result["sourceCommit"] = deployment["sha"]
    return result


def read_regular(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= limit, "SOURCE_FILE")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            body = stream.read(limit + 1)
        after = os.fstat(fd)
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), "SOURCE_CHANGED")
        require(len(body) == before.st_size, "SOURCE_BOUND")
        return body
    finally:
        os.close(fd)


def write_new(root, name, body):
    safe_member(name)
    path = root.joinpath(*PurePosixPath(name).parts)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(body)
    path.chmod(0o644)


def verify_protected(root, inventory):
    for name, record in inventory.items():
        body = read_regular(root / name, record["bytes"])
        require(len(body) == record["bytes"] and sha256(body) == record["sha256"], "PROTECTED_MEMBER_CHANGED")


def archive_exact(root, names, destination, inventory=None):
    inventory = {} if inventory is None else inventory
    require(destination.is_absolute() and not destination.exists() and not destination.is_symlink(), "ARCHIVE_EXISTS")
    members = list(root.rglob("*"))
    require(all(not p.is_symlink() for p in members), "OUTPUT_LINK")
    actual = {p.relative_to(root).as_posix() for p in members if not p.is_dir()}
    require(actual == set(names), "OUTPUT_INVENTORY")
    with tarfile.open(destination, "x", format=tarfile.USTAR_FORMAT) as archive:
        for name in sorted(names):
            body = read_regular(root / name, 128 * 1024 * 1024)
            if name in inventory:
                record = inventory[name]
                require(len(body) == record["bytes"] and sha256(body) == record["sha256"], "ARCHIVE_PROTECTED_MEMBER_CHANGED")
            info = tarfile.TarInfo(name)
            info.size = len(body)
            info.mode = 0o644
            info.uid = info.gid = info.mtime = 0
            info.uname = info.gname = ""
            archive.addfile(info, io.BytesIO(body))
    # Bind the actual closed upload archive, rather than only its input tree.
    with tarfile.open(destination, "r:") as archive:
        archived = archive.getmembers()
        require(len(archived) == len(names) and {m.name for m in archived} == set(names), "ARCHIVE_INVENTORY")
        for member in archived:
            require(member.isfile() and not member.issym() and not member.islnk(), "ARCHIVE_MEMBER_TYPE")
            if member.name in inventory:
                record = inventory[member.name]
                require(member.size == record["bytes"], "ARCHIVE_PROTECTED_SIZE")
                body = archive.extractfile(member).read(record["bytes"] + 1)
                require(len(body) == record["bytes"] and sha256(body) == record["sha256"], "ARCHIVE_PROTECTED_DIGEST")


def assemble(repository, site_root, output, archive, *, initial_rs9_tree=None):
    require(repository in SITES, "REPOSITORY")
    require(initial_rs9_tree is None or repository == "release-starport-9", "RS9_INITIAL_REPOSITORY")
    require(output.is_absolute() and not output.exists() and not output.is_symlink(), "OUTPUT_EXISTS")
    require(read_regular(site_root / "CNAME", 256) == (SITES[repository] + "\n").encode(), "CNAME_DOMAIN")
    if "GITHUB_REPOSITORY" in os.environ:
        require(os.environ["GITHUB_REPOSITORY"] == "Knowledge-Forge-AI/" + repository
                and os.environ.get("GITHUB_REF") == "refs/heads/main", "WORKFLOW_REPOSITORY")
    previous = admit_previous_deployment(repository)
    if repository == "theme-forge-packages":
        source = read_regular(site_root / "protected-inventory.json", 65536)
        require(sha256(source) == INVENTORY_SHA256, "INVENTORY_SOURCE_DIGEST")
        inventory = validate_inventory(json.loads(source))
        inventory_sha256 = INVENTORY_SHA256
    else:
        inventory, inventory_sha256 = read_rs9_inventory(site_root)
        verify_live_rs9_inventory(previous, inventory, inventory_sha256, initial=initial_rs9_tree is not None)
    if initial_rs9_tree is not None:
        require(initial_rs9_tree.is_absolute() and initial_rs9_tree.is_dir()
                and initial_rs9_tree.resolve(strict=True) == initial_rs9_tree, "RS9_INITIAL_ROOT")
        members = list(initial_rs9_tree.rglob("*"))
        require(all(not path.is_symlink() for path in members), "RS9_INITIAL_LINK")
        actual = {path.relative_to(initial_rs9_tree).as_posix() for path in members if not path.is_dir()}
        require(actual == set(inventory), "RS9_INITIAL_INVENTORY_MISMATCH")
    output.mkdir(mode=0o700)
    def retain(item):
        name, record = item
        if initial_rs9_tree is None:
            body = fetch("https://" + SITES[repository] + "/" + urllib.parse.quote(name, safe="/+.-_"), record["bytes"])
        else:
            body = read_regular(initial_rs9_tree / name, record["bytes"])
        code = "PUBLIC_MEMBER_CHANGED" if initial_rs9_tree is None else "RS9_INITIAL_MEMBER_CHANGED"
        require(len(body) == record["bytes"] and sha256(body) == record["sha256"], code)
        write_new(output, name, body)
    with ThreadPoolExecutor(max_workers=4) as executor:
        list(executor.map(retain, inventory.items()))
    for name in WEBSITE_FILES:
        require(name not in inventory, "WEBSITE_COLLISION")
        write_new(output, name, read_regular(site_root / name, 1024 * 1024))
    source_commit = os.environ.get("GITHUB_SHA", "local-unpublished")
    require(source_commit == "local-unpublished" or re.fullmatch(r"[0-9a-f]{40}", source_commit), "SOURCE_COMMIT")
    receipt = {"schema": "knowledge-forge.website-preservation.v1", "repository": "Knowledge-Forge-AI/" + repository,
               "websiteSourceCommit": source_commit, "protectedFileCount": len(inventory),
               "protectedPublicBytes": sum(r["bytes"] for r in inventory.values()),
               "protectedInventorySha256": inventory_sha256,
               "packageBodiesChanged": initial_rs9_tree is not None, "packagesRebuilt": False, "signingUsed": False,
               "websiteFiles": list(WEBSITE_FILES), "previousHosting": previous}
    write_new(output, "site-preservation.json", (json.dumps(receipt, indent=2) + "\n").encode())
    verify_protected(output, inventory)
    archive_exact(output, [*inventory, *WEBSITE_FILES, "site-preservation.json"], archive, inventory)
    return receipt


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True, choices=tuple(SITES))
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--initial-rs9-tree", type=Path, help="Admitted package tree for the first RS9 publication")
    arguments = parser.parse_args()
    try:
        receipt = assemble(arguments.repository, Path(__file__).resolve().parents[1], arguments.output, arguments.archive,
                           initial_rs9_tree=arguments.initial_rs9_tree)
    except Refused as error:
        print("SITE_ASSEMBLY_REFUSED:" + str(error))
        return 1
    except Exception:
        print("SITE_ASSEMBLY_REFUSED:UNCLASSIFIED")
        return 1
    print("SITE_ASSEMBLY_OK protected=" + str(receipt["protectedFileCount"]) + " website=" + str(len(WEBSITE_FILES) + 1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
