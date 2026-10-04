"""Small synthetic second-profile bytes; never a substitute for live evidence."""
import hashlib
import tarfile

from rs9.release_core import digest
from rs9.scratch import canonical
from tests.shadow_fixtures import tar_bytes


def package_evidence(root):
    repository, tag = "Example/second-project", "v0.6.1"
    source = canonical({"name": "second-project", "version": "0.6.1", "license": "MIT",
                        "bin": {"second": "bin/run.js"}})
    payload = tar_bytes([("package/package.json", source, 0o644, tarfile.REGTYPE, ""),
                         ("package/bin/run.js", b"#!/usr/bin/env node\n", 0o755, tarfile.REGTYPE, "")])
    assets = {"second-0.6.1.tgz": payload, "NOTICE": b"Synthetic MIT declaration.\n",
              "PROVENANCE.json": canonical({"release": {"repository": repository, "tag": tag,
                                      "tagTarget": "a" * 40, "mergedMainTree": "b" * 40}})}
    assets["SHA256SUMS"] = "".join(digest(data) + "  " + name + "\n" for name, data in sorted(assets.items())).encode()
    blob = hashlib.sha1(b"blob " + str(len(source)).encode() + b"\0" + source).hexdigest()
    api = {"repository": {"id": 12, "full_name": repository},
           "ref": {"ref": "refs/tags/" + tag, "object": {"type": "commit", "sha": "a" * 40}}, "tags": [],
           "commit": {"sha": "a" * 40, "tree": {"sha": "b" * 40}},
           "tree": {"sha": "b" * 40, "truncated": False, "tree": [{"path": "package.json", "sha": blob, "type": "blob", "mode": "100644"}]},
           "release": {"id": 34, "tag_name": tag, "target_commitish": "a" * 40, "draft": False, "prerelease": False,
                       "assets": [{"id": i + 1, "name": name, "size": len(data), "digest": "sha256:" + digest(data), "state": "uploaded"}
                                  for i, (name, data) in enumerate(assets.items())]}}
    for family, rows in (("api", {name + ".json": canonical(value) for name, value in api.items()}),
                         ("assets", assets), ("source", {"package.json": source})):
        (root / family).mkdir()
        for name, data in rows.items():
            (root / family / name).write_bytes(data)
    policy = {"profile": "npm-package-archive.v1alpha1", "checksums": "SHA256SUMS",
              "assets": [{"role": "notice", "name": "NOTICE"}, {"role": "provenance", "name": "PROVENANCE.json"}]}
    intent = {"project": {"repository": repository, "id": "second-project"}, "tag": tag, "version": "0.6.1",
              "release": {"prerelease": "reject", "evidence": policy},
              "assets": [{"id": "package", "name": "second-0.6.1.tgz", "format": "tar.gz", "commands": {"second": "package/bin/run.js"}, "platforms": ["any"]}],
              "license": {"files": [], "expression": "MIT"}}
    return intent
