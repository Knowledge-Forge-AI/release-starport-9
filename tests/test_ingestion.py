import copy
import json
from pathlib import Path
import tempfile
import unittest

from rs9.errors import ContractError
from rs9.ingestion import authenticate, digest, png_size
from rs9.scratch import canonical
from tests.shadow_fixtures import fixture_evidence
from tests.shadow_fixtures import tar_bytes
import tarfile


class IngestionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.n = fixture_evidence(self.root)

    def edit(self, relative, change):
        path = self.root / relative
        value = json.loads(path.read_bytes())
        change(value)
        path.write_bytes(canonical(value))

    def rejects(self, code):
        with self.assertRaises(ContractError) as caught:
            authenticate(self.n, self.root)
        self.assertEqual(caught.exception.code, code)

    def test_determinism_no_volatile_or_assurance_fields(self):
        before = canonical(authenticate(self.n, self.root).record)
        self.edit("api/release.json", lambda r: r.update(updated_at="later", download_count=10, name="arbitrary", body="ignored", uploader={"name": "ignored"}))
        self.assertEqual(before, canonical(authenticate(self.n, self.root).record))
        self.assertNotIn(b'"authentication"', before)
        self.assertNotIn(b'"authenticated"', before)

    def test_digest_negative(self):
        path = self.root / "assets" / self.n["assets"][0]["name"]
        data = path.read_bytes()
        path.write_bytes(bytes([data[0] ^ 1]) + data[1:])
        self.rejects("DIGEST_MISMATCH")

    def test_missing_duplicate_asset(self):
        original = (self.root / "api/release.json").read_bytes()
        self.edit("api/release.json", lambda r: r["assets"].pop(0))
        self.rejects("MISSING_ASSET")
        (self.root / "api/release.json").write_bytes(original)
        self.edit("api/release.json", lambda r: r["assets"].append(copy.deepcopy(r["assets"][0])))
        self.rejects("DUPLICATE_ASSET")

    def test_draft_prerelease_and_allowed_policy(self):
        self.edit("api/release.json", lambda r: r.update(draft=True))
        self.rejects("RELEASE_STATE")
        self.edit("api/release.json", lambda r: r.update(draft=False, prerelease=True))
        self.rejects("PRERELEASE_REJECTED")
        self.n["release"]["prerelease"] = "allow"
        self.assertTrue(authenticate(self.n, self.root).record["release"]["prerelease"])

    def test_repo_tag_target_tree_negatives(self):
        for relative, change, code in [("api/repository.json", lambda r: r.update(full_name="Other/Repo"), "REPOSITORY_MISMATCH"), ("api/ref.json", lambda r: r.update(ref="refs/tags/v2"), "TAG_MISMATCH"), ("api/release.json", lambda r: r.update(target_commitish="c" * 40), "RELEASE_TARGET"), ("api/tree.json", lambda r: r.update(truncated=True), "TRUNCATED_TREE"), ("api/tree.json", lambda r: r["tree"][0].update(sha="c" * 40), "SOURCE_BLOB_MISMATCH")]:
            with self.subTest(code=code):
                path = self.root / relative
                original = path.read_bytes()
                self.edit(relative, change)
                self.rejects(code)
                path.write_bytes(original)

    def test_asset_size_missing_digest_and_state(self):
        for change, code in [(lambda a: a.update(size=a["size"] + 1), "SIZE_MISMATCH"), (lambda a: a.pop("digest"), "ASSET_METADATA"), (lambda a: a.update(state="new"), "ASSET_METADATA")]:
            path = self.root / "api/release.json"
            original = path.read_bytes()
            self.edit("api/release.json", lambda r: change(r["assets"][0]))
            self.rejects(code)
            path.write_bytes(original)

    def bind_asset(self, name, data):
        (self.root / "assets" / name).write_bytes(data)
        def change(release):
            for asset in release["assets"]:
                if asset["name"] == name:
                    asset.update(size=len(data), digest="sha256:" + digest(data))
        self.edit("api/release.json", change)

    def rebind_with_sums(self, name, data):
        self.bind_asset(name, data)
        sums = (self.root / "assets/SHA256SUMS").read_text()
        lines = [digest(data) + "  " + name if l.endswith("  " + name) else l for l in sums.splitlines()]
        self.bind_asset("SHA256SUMS", ("\n".join(lines) + "\n").encode())

    def test_authenticated_digest_does_not_bypass_unsafe_archive(self):
        name = self.n["assets"][0]["name"]
        data = tar_bytes([("../escape", b"x", 0o755, tarfile.REGTYPE, "")])
        self.rebind_with_sums(name, data)
        self.rejects("UNSAFE_PATH")

    def test_unsafe_source_symlink_and_malformed_release_shape(self):
        path = self.root / "source/LICENSE"
        original = path.read_bytes()
        path.unlink()
        path.symlink_to(self.root / "source/NOTICE")
        self.rejects("MISSING_EVIDENCE")
        path.unlink()
        path.write_bytes(original)
        self.edit("api/release.json", lambda r: r.update(assets="invalid"))
        self.rejects("INVALID_EVIDENCE")

    def test_published_wrapper_cannot_differ_from_release_attachment(self):
        (self.root / "npm/package.tgz").write_bytes(b"different")
        self.rejects("NPM_RELEASE_MISMATCH")

    def test_checksum_missing_duplicate_disagreement(self):
        sums = (self.root / "assets/SHA256SUMS").read_bytes()
        for data, code in [(sums.split(b"\n", 1)[1], "CHECKSUM_MISMATCH"), (sums + sums.splitlines()[0] + b"\n", "DUPLICATE_CHECKSUM"), (b"0" * 64 + sums[64:], "CHECKSUM_MISMATCH")]:
            self.bind_asset("SHA256SUMS", data)
            self.rejects(code)
        self.bind_asset("SHA256SUMS", sums)

    def test_provenance_disagreement(self):
        data = canonical({"release": {"tagTarget": "c" * 40}})
        self.bind_asset("PROVENANCE.json", data)
        sums = (self.root / "assets/SHA256SUMS").read_text()
        lines = [digest(data) + "  PROVENANCE.json" if l.endswith("  PROVENANCE.json") else l for l in sums.splitlines()]
        self.bind_asset("SHA256SUMS", ("\n".join(lines) + "\n").encode())
        self.rejects("PROVENANCE_MISMATCH")

    def test_payload_license_mismatch(self):
        path = self.root / "source/LICENSE"
        path.write_bytes(b"different tagged license\n")
        data = path.read_bytes()
        import hashlib
        sha = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        self.edit("api/tree.json", lambda t: [e.update(sha=sha) for e in t["tree"] if e["path"] == "LICENSE"])
        self.rejects("PAYLOAD_LICENSE_MISMATCH")

    def test_notice_explicit_prose_and_missing_declaration(self):
        # The live NOTICE spells the license out instead of using an SPDX token.
        # Exercise prose through the other notice, without changing LICENSE/NOTICE copies.
        source = self.root / "source/COMMERCIAL-LICENSE.md"
        import hashlib
        for text, expected in [("GNU Affero General Public License v3.0 or later", "explicit-version-and-later-prose"), ("Commercial licenses are available", None)]:
            source.write_text(text + "\n")
            data = source.read_bytes()
            blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
            self.edit("api/tree.json", lambda t: [e.update(sha=blob) for e in t["tree"] if e["path"] == "COMMERCIAL-LICENSE.md"])
            if expected:
                rows = authenticate(self.n, self.root).record["license"]["declarations"]
                row = next(r for r in rows if r["source"] == "tagged:COMMERCIAL-LICENSE.md")
                self.assertEqual(row["expression"], "AGPL-3.0-or-later")
                self.assertEqual(row["method"], expected)
            else:
                self.rejects("LICENSE_EVIDENCE")

    def test_annotated_tag_and_no_extra_tag_objects(self):
        self.edit("api/ref.json", lambda r: r.update(object={"type": "tag", "sha": "d" * 40}))
        (self.root / "api/tags.json").write_bytes(canonical([{"sha": "d" * 40, "object": {"type": "commit", "sha": "a" * 40}}]))
        self.assertEqual(authenticate(self.n, self.root).record["tag"]["tag_objects"], ["d" * 40])

    def test_npm_integrity_and_license_conflict(self):
        self.edit("npm/metadata.json", lambda r: r.update(license="AGPL-3.0-or-later OR Commercial"))
        self.assertEqual(authenticate(self.n, self.root).record["license"]["status"], "conflict")
        self.edit("npm/metadata.json", lambda r: r["dist"].update(integrity="sha512-invalid"))
        self.rejects("NPM_INTEGRITY")

    def test_png_shape(self):
        self.assertEqual(png_size((self.root / "source/src-tauri/icons/icon.png").read_bytes()), 256)
        for invalid in (b"not png", b"\x89PNG\r\n\x1a\n" + b"\0" * 25):
            with self.assertRaises(ContractError):
                png_size(invalid)
