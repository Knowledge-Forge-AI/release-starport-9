"""Synthetic bytes for offline negative tests; no live-authentication claims."""
import base64
import copy
import hashlib
import io
import json
from pathlib import Path
import struct
import tarfile
import zlib

from rs9.ingestion import digest
from rs9.scratch import canonical
from tests.elf_builder import build_elf

ROOT = Path(__file__).resolve().parents[1]


def tar_bytes(entries):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for name, data, mode, kind, target in entries:
            item = tarfile.TarInfo(name)
            item.mode = mode
            item.type = kind
            item.linkname = target
            item.size = len(data) if kind == tarfile.REGTYPE else 0
            archive.addfile(item, io.BytesIO(data) if kind == tarfile.REGTYPE else None)
    return output.getvalue()


def fixture_evidence(directory, *, extra_linux=()):
    n = json.loads((ROOT / "tests/golden/theme-forge-nebular-fusion.normalized.json").read_bytes())
    sources = {"LICENSE": b"Synthetic license text for offline fixture only.\n", "NOTICE": b"Synthetic AGPL-3.0-or-later declaration.\n",
               "COMMERCIAL-LICENSE.md": b"Synthetic AGPL-3.0-or-later community and separate offer.\n",
               "package.json": canonical({"name": "@knowledge-forge-ai/theme-forge-nebular-fusion", "version": "0.6.1", "license": "AGPL-3.0-or-later"}),
               "src-tauri/Cargo.toml": b'[package]\nlicense = "AGPL-3.0-or-later"\n',
               "src-tauri/tauri.conf.json": canonical({"productName": n["project"]["name"]})}
    ihdr = struct.pack(">IIBBBBB", 256, 256, 8, 6, 0, 0, 0)
    sources["src-tauri/icons/icon.png"] = b"\x89PNG\r\n\x1a\n" + struct.pack(">I", 13) + b"IHDR" + ihdr + struct.pack(">I", zlib.crc32(b"IHDR" + ihdr))
    for path, data in sources.items():
        p = directory / "source" / path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    tree = [{"path": p, "type": "blob", "mode": "100644", "sha": hashlib.sha1(b"blob " + str(len(b)).encode() + b"\0" + b).hexdigest()} for p, b in sources.items()]
    raw = {}
    for asset in n["assets"]:
        root = next(iter(asset["commands"].values())).split("/")[0]
        command = next(iter(asset["commands"].values()))
        license_root = root + ("/Contents/Resources" if root.endswith(".app") else "")
        native = b"synthetic Mach-O stand-in\n" if root.endswith(".app") else build_elf(machine=asset["platforms"][0].split("-")[0], needed=["libc.so.6"], interpreter="/lib/ld-linux-aarch64.so.1" if asset["platforms"] == ["aarch64-linux"] else "/lib64/ld-linux-x86-64.so.2", version_needs={"libc.so.6": ["GLIBC_2.34"]})
        entries = [(root, b"", 0o755, tarfile.DIRTYPE, ""), (command, native, 0o755, tarfile.REGTYPE, "")]
        entries += [(license_root + "/" + p, sources[p], 0o644, tarfile.REGTYPE, "") for p in ("LICENSE", "NOTICE")]
        entries += [(p, b"#!/bin/sh\nexit 0\n", 0o755, tarfile.REGTYPE, "") for p in asset["launchers"].values()]
        if not root.endswith(".app"):
            entries += list(extra_linux)
        raw[asset["name"]] = tar_bytes(entries)
    wrapper = tar_bytes([("package/package.json", sources["package.json"], 0o644, tarfile.REGTYPE, "")])
    raw["knowledge-forge-ai-theme-forge-nebular-fusion-0.6.1.tgz"] = wrapper
    raw["PROVENANCE.json"] = canonical({"release": {"repository": n["project"]["repository"], "tag": n["tag"], "tagTarget": "a" * 40, "mergedMainTree": "b" * 40}})
    raw["nebular.spdx.json"] = canonical({"packages": []})
    raw["THIRD_PARTY_NOTICES.md"] = b"Synthetic third-party notices.\n"
    raw["SHA256SUMS"] = "".join(digest(data) + "  " + name + "\n" for name, data in sorted(raw.items())).encode()
    (directory / "assets").mkdir()
    for name, data in raw.items():
        (directory / "assets" / name).write_bytes(data)
    assets = [{"id": i + 1, "name": name, "size": len(data), "digest": "sha256:" + digest(data), "state": "uploaded"} for i, (name, data) in enumerate(raw.items())]
    metadata = {"repository": {"id": 123, "full_name": n["project"]["repository"]},
                "release": {"id": 456, "tag_name": n["tag"], "target_commitish": "a" * 40, "draft": False, "prerelease": False, "assets": assets},
                "ref": {"ref": "refs/tags/" + n["tag"], "object": {"type": "commit", "sha": "a" * 40}}, "tags": [],
                "commit": {"sha": "a" * 40, "tree": {"sha": "b" * 40}}, "tree": {"sha": "b" * 40, "truncated": False, "tree": tree}}
    (directory / "api").mkdir()
    for name, value in metadata.items():
        (directory / "api" / (name + ".json")).write_bytes(canonical(value))
    (directory / "npm").mkdir()
    (directory / "npm/package.tgz").write_bytes(wrapper)
    (directory / "npm/metadata.json").write_bytes(canonical({"name": "@knowledge-forge-ai/theme-forge-nebular-fusion", "version": "0.6.1", "license": "AGPL-3.0-or-later", "dist": {"integrity": "sha512-" + base64.b64encode(hashlib.sha512(wrapper).digest()).decode()}}))
    return n
