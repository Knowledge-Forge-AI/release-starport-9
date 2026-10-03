"""Capture exact public inputs; authentication is a separate offline operation."""
from urllib.parse import quote

from rs9.errors import ContractError
from rs9.github import PublicClient
from rs9.scratch import ConfinedWriter, canonical
from rs9.security import validate_repository, validate_safe_basename

EVIDENCE_NAMES = ("SHA256SUMS", "PROVENANCE.json", "nebular.spdx.json", "THIRD_PARTY_NOTICES.md")
SOURCE_EVIDENCE = ("LICENSE", "NOTICE", "COMMERCIAL-LICENSE.md", "package.json",
                   "src-tauri/Cargo.toml", "src-tauri/tauri.conf.json")


def fetch(normalized, output, *, client=None):
    client = client or PublicClient()
    repository = normalized["project"]["repository"]
    validate_repository(repository)
    base = "https://api.github.com/repos/" + repository
    repo = client.json(base, no_redirect=True)
    tag = normalized["tag"]
    ref = client.json(base + "/git/ref/tags/" + quote(tag, safe=""))
    obj, tags = ref["object"], []
    while obj["type"] == "tag":
        if len(tags) == 8:
            raise ContractError("TAG_LIMIT", "Annotated tag depth exceeded")
        item = client.json(base + "/git/tags/" + obj["sha"])
        tags.append(item)
        obj = item["object"]
    if obj["type"] != "commit":
        raise ContractError("TAG_TARGET", "Release tag does not resolve to a commit")
    commit = client.json(base + "/git/commits/" + obj["sha"])
    tree = client.json(base + "/git/trees/" + commit["tree"]["sha"] + "?recursive=1")
    if tree.get("truncated") is not False:
        raise ContractError("TRUNCATED_TREE", "Full tagged tree evidence is required")
    release = client.json(base + "/releases/tags/" + quote(tag, safe=""))
    selected = [a["name"] for a in normalized["assets"]] + list(EVIDENCE_NAMES)
    # GitHub wrapper assets support license evidence; they are not adapter inputs.
    selected += [a["name"] for a in release["assets"] if a["name"].endswith(".tgz") and "linux" not in a["name"] and "darwin" not in a["name"]]
    sources = set(SOURCE_EVIDENCE) | set(normalized["license"]["files"])
    if "desktop" in normalized:
        sources.add(normalized["desktop"]["icon"]["path"])
    with ConfinedWriter(output) as writer:
        for name, value in {"repository": repo, "ref": ref, "tags": tags, "commit": commit,
                            "tree": tree, "release": release}.items():
            writer.write("api/" + name + ".json", canonical(value))
        for name in sorted(set(selected)):
            validate_safe_basename(name)
            matches = [a for a in release["assets"] if a["name"] == name]
            if len(matches) != 1:
                raise ContractError("ASSET_COUNT", "Required release asset must exist exactly once")
            asset = matches[0]
            if type(asset["size"]) is not int or not 0 < asset["size"] <= 1024 ** 3:
                raise ContractError("FETCH_LIMIT", "Invalid release asset size")
            url = asset["browser_download_url"]
            expected = "https://github.com/" + repository + "/releases/download/" + quote(tag, safe="") + "/" + quote(name, safe="")
            if url != expected:
                raise ContractError("ASSET_AUTHORITY", "Release asset URL does not match selected repository and tag")
            writer.write("assets/" + name, client.get(url, limit=1024 ** 3, expected_size=asset["size"]))
        for path in sorted(sources):
            writer.write("source/" + path, client.get("https://raw.githubusercontent.com/" + repository + "/" + obj["sha"] + "/" + quote(path, safe="/")))
        import json
        package = json.loads(client.get("https://raw.githubusercontent.com/" + repository + "/" + obj["sha"] + "/package.json"))["name"]
        metadata = client.json("https://registry.npmjs.org/" + quote(package, safe="") + "/" + quote(normalized["version"], safe=""))
        writer.write("npm/metadata.json", canonical(metadata))
        writer.write("npm/package.tgz", client.get(metadata["dist"]["tarball"], limit=32 * 1024 * 1024))
        writer.write("fetch-receipt.json", canonical({"schema": "rs9.fetch-receipt.v1alpha1", "requests": client.receipts}))
    return output
