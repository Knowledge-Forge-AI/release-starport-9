"""Original ZIP preservation and anonymous GET-only relay fixture tests."""
import copy
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.request import Request
import zipfile

from rs9.current_generation import CURRENT_GENERATION, HISTORICAL_GENERATION
from rs9.errors import ContractError
from rs9.public_release_transport import (PublicReleaseTransport, RelayRedirects, RELAY_REPOSITORY,
    relay_tag, relay_asset_name, select_zip_transport, _validate_url)
from rs9.collect_candidate import collect

COMMIT = "1" * 40


def zip_bytes(compression=zipfile.ZIP_STORED):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=compression) as archive:
        archive.writestr("fixture.txt", b"synthetic original artifact" * 40)
    return buffer.getvalue()


class Response(io.BytesIO):
    def __init__(self, data, url, *, status=200):
        super().__init__(data)
        self.url, self.status, self.headers = url, status, {"Content-Length": str(len(data))}
    def geturl(self):
        return self.url


class Metadata:
    def __init__(self, document):
        self.document, self.calls = document, []
    def json(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return copy.deepcopy(self.document)


class Opener:
    def __init__(self, data, final=None):
        self.data, self.final, self.requests = data, final, []
    def open(self, request, timeout):
        self.requests.append((request, timeout))
        return Response(self.data, self.final or request.full_url)


class PublicRelayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.data = zip_bytes()
        self.artifact = {"id": 9, "name": "hosted-summary", "digest": "sha256:" + hashlib.sha256(self.data).hexdigest(),
                         "expired": False, "size_in_bytes": len(self.data)}
        tag, name = relay_tag(COMMIT, 7), relay_asset_name(self.artifact)
        self.url = "https://github.com/" + RELAY_REPOSITORY + "/releases/download/" + tag + "/" + name
        self.release = {"tag_name": tag, "draft": False, "prerelease": False, "assets": [
            {"id": 11, "name": name, "digest": self.artifact["digest"], "size": len(self.data), "state": "uploaded", "browser_download_url": self.url}]}

    def prepare(self, *, release=None, artifact=None, opener=None):
        metadata = Metadata(release if release is not None else self.release)
        selected = PublicReleaseTransport(metadata_client=metadata, opener=opener or Opener(self.data))
        session = selected.prepare([artifact or self.artifact], commit=COMMIT, run_id=7, generation=CURRENT_GENERATION)
        return session, metadata

    def test_original_zip_bytes_and_digest_preserved_without_credentials(self):
        opener = Opener(self.data, "https://release-assets.githubusercontent.com/fixture?sig=transient-secret&se=deadline")
        with patch.dict("os.environ", {"GH_TOKEN": "fixture-secret", "HTTP_PROXY": "http://fixture.invalid"}):
            session, metadata = self.prepare(opener=opener)
            count = session.download(self.artifact, self.root / "original.zip")
        self.assertEqual(count, len(self.data))
        self.assertEqual((self.root / "original.zip").read_bytes(), self.data)
        request, timeout = opener.requests[0]
        self.assertEqual(request.get_method(), "GET")
        self.assertEqual(timeout, 20)
        self.assertFalse(request.has_header("Authorization"))
        self.assertFalse(request.has_header("Cookie"))
        self.assertEqual(metadata.calls[0], ("https://api.github.com/repos/" + RELAY_REPOSITORY + "/releases/tags/" + relay_tag(COMMIT, 7),
            {"request_class": "github-api", "limit": 1024 ** 2, "no_redirect": True}))
        self.assertNotIn("transient-secret", repr(session.assets))

    def test_real_public_client_signature_and_default_anonymous_metadata_transport(self):
        from urllib.request import HTTPSHandler
        requests = []
        def controlled_https(handler, request):
            requests.append(request)
            response = Response(json.dumps(self.release).encode(), request.full_url)
            response.code, response.msg = 200, "OK"
            response.info = lambda: response.headers
            return response
        with patch.dict("os.environ", {"GH_TOKEN": "fixture-token", "GITHUB_TOKEN": "fixture-token", "HTTPS_PROXY": "http://fixture.invalid"}), patch.object(HTTPSHandler, "https_open", controlled_https):
            transport = PublicReleaseTransport(opener=Opener(self.data))
            session = transport.prepare([self.artifact], commit=COMMIT, run_id=7, generation=CURRENT_GENERATION)
        self.assertEqual(len(requests), 1)
        request = requests[0]
        self.assertEqual(request.get_method(), "GET")
        self.assertFalse(request.has_header("Authorization"))
        self.assertFalse(request.has_header("Cookie"))
        self.assertTrue(request.rs9_no_redirect)
        self.assertEqual(transport.client.receipts[0]["operation"], "github-api")
        self.assertEqual(session.download(self.artifact, self.root / "default-client.zip"), len(self.data))

    def test_unknown_mode_and_historical_relay_refuse_before_get(self):
        self.assertIsNone(select_zip_transport("actions", generation=HISTORICAL_GENERATION))
        for mode, generation in (("public-release-relay", HISTORICAL_GENERATION), ("unknown", CURRENT_GENERATION), (None, CURRENT_GENERATION)):
            with self.subTest(mode=mode), self.assertRaises(ContractError):
                select_zip_transport(mode, generation=generation)
        client = Metadata(self.release)
        with self.assertRaises(ContractError):
            PublicReleaseTransport(metadata_client=client).prepare([self.artifact], commit=COMMIT, run_id=7, generation=HISTORICAL_GENERATION)
        self.assertEqual(client.calls, [])

    def test_exact_relay_set_and_original_metadata_are_mandatory(self):
        mutations = []
        extra = copy.deepcopy(self.release); extra["assets"].append({**extra["assets"][0], "id": 12, "name": "extra.zip"}); mutations.append(extra)
        duplicate = copy.deepcopy(self.release); duplicate["assets"].append(copy.deepcopy(duplicate["assets"][0])); mutations.append(duplicate)
        missing = copy.deepcopy(self.release); missing["assets"] = []; mutations.append(missing)
        for field, value in (("digest", None), ("digest", "sha256:" + "0" * 64), ("browser_download_url", self.url + "?arbitrary=1"),
                             ("browser_download_url", self.url.replace("https:", "http:")), ("browser_download_url", self.url.replace(RELAY_REPOSITORY, "other/repository"))):
            changed = copy.deepcopy(self.release); changed["assets"][0][field] = value; mutations.append(changed)
        for changed in mutations:
            with self.subTest(changed=changed), self.assertRaises(ContractError):
                self.prepare(release=changed)
        for field, value in (("expired", True), ("expired", None), ("digest", None), ("id", 0), ("name", "../evil")):
            with self.subTest(field=field), self.assertRaises(ContractError):
                self.prepare(artifact={**self.artifact, field: value})
        with self.assertRaises(ContractError):
            PublicReleaseTransport(metadata_client=Metadata(self.release)).prepare([self.artifact, self.artifact], commit=COMMIT, run_id=7, generation=CURRENT_GENERATION)

    def test_recompression_and_changed_bytes_cannot_replace_original_zip(self):
        for replacement in (zip_bytes(zipfile.ZIP_DEFLATED), self.data[:-1] + b"X"):
            release = copy.deepcopy(self.release); release["assets"][0]["size"] = len(replacement)
            session, _ = self.prepare(release=release, opener=Opener(replacement))
            with self.assertRaises(ContractError) as error:
                session.download(self.artifact, self.root / "bad.zip")
            self.assertEqual(error.exception.code, "PUBLIC_RELAY_DIGEST")
            self.assertFalse((self.root / "bad.zip").exists())

    def test_size_total_time_and_exclusive_file_bounds(self):
        session, _ = self.prepare()
        for limits in ({"max_artifact_bytes": len(self.data) - 1}, {"total_tracker": [0], "max_total_bytes": len(self.data) - 1}):
            with self.assertRaises(ContractError):
                session.download(self.artifact, self.root / "limited.zip", **limits)
            self.assertFalse((self.root / "limited.zip").exists())
        with patch("rs9.public_release_transport.time.monotonic", side_effect=[0, 121]), self.assertRaises(ContractError) as error:
            session.download(self.artifact, self.root / "late.zip")
        self.assertEqual(error.exception.code, "PUBLIC_RELAY_TIMEOUT")
        self.assertFalse((self.root / "late.zip").exists())
        existing = self.root / "exists.zip"; existing.write_bytes(b"preserve")
        with self.assertRaises(ContractError):
            session.download(self.artifact, existing)
        self.assertEqual(existing.read_bytes(), b"preserve")

    def test_redirect_policy_rejects_other_origins_queries_downgrades_and_hops(self):
        for url in ("http://github.com/fixture", "https://github.com/other/repository/releases/download/tag/file.zip", "https://evil.invalid/fixture", "https://user:secret@github.com/fixture",
                    "https://github.com/fixture?x=1", "https://release-assets.githubusercontent.com/fixture?arbitrary=1", "https://github.com/fixture#fragment"):
            with self.subTest(url=url), self.assertRaises(ContractError):
                _validate_url(url, redirected=True)
        handler = RelayRedirects()
        request = Request(self.url); request.rs9_relay_hops = 3
        with self.assertRaises(ContractError):
            handler.redirect_request(request, None, 302, "", {}, "https://release-assets.githubusercontent.com/fixture?sig=value")
        opener = Opener(self.data, "https://evil.invalid/download")
        session, _ = self.prepare(opener=opener)
        with self.assertRaises(ContractError):
            session.download(self.artifact, self.root / "evil.zip")
        self.assertFalse((self.root / "evil.zip").exists())

    def test_collector_relay_is_explicit_and_never_uses_runner_for_zip(self):
        from rs9.current_generation import distribution_paths
        response = zip_bytes()
        def metadata(root, argv):
            endpoint = argv[-1]
            if endpoint.endswith("/zip"):
                self.fail("Production relay must not use the test runner as ZIP fallback")
            if "/jobs?" in endpoint:
                return json.dumps({"total_count": 0, "jobs": []})
            if "/artifacts?" in endpoint:
                return json.dumps({"total_count": 1, "artifacts": [self.artifact]})
            return json.dumps({"id": 7, "head_sha": COMMIT, "event": "push", "head_branch": "main", "path": distribution_paths(CURRENT_GENERATION)[0],
                "run_attempt": 1, "status": "completed", "conclusion": "failure", "repository": {"full_name": "Knowledge-Forge-AI/release-starport-9"},
                "created_at": "2026-10-29T00:00:01Z"})
        def download(artifact, target, **kwargs):
            self.assertEqual(artifact["digest"], self.artifact["digest"])
            target.write_bytes(response)
            return len(response)
        with patch("rs9.public_release_transport.PublicReleaseTransport") as transport, \
             patch("rs9.collect_candidate.output_directory", return_value=self.root), \
             patch("rs9.collect_candidate.gh_stream_artifact") as actions:
            transport.return_value.prepare.return_value.download.side_effect = download
            result = collect(Path(__file__).resolve().parents[1], self.root, commit=COMMIT, started_at=datetime(2026, 10, 29, tzinfo=timezone.utc),
                run_id=7, timeout=30, runner=metadata, generation=CURRENT_GENERATION, zip_transport="public-release-relay")
        actions.assert_not_called()
        self.assertEqual(transport.return_value.prepare.call_args.kwargs, {"commit": COMMIT, "run_id": 7, "generation": CURRENT_GENERATION})
        self.assertEqual(result["validation"]["status"], "fail")

    def test_rejected_redirect_response_is_closed(self):
        from email.message import Message
        headers = Message(); headers["Location"] = "https://evil.invalid/redirect"
        response = Response(b"", self.url)
        with self.assertRaises(ContractError):
            RelayRedirects().http_error_302(Request(self.url), response, 302, "Found", headers)
        self.assertTrue(response.closed)
