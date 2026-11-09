"""Public binary transport retains release authority and authentication."""
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request

from rs9.candidate import capture_generation
from rs9.current_generation import CURRENT_GENERATION, HISTORICAL_GENERATION
from rs9.errors import ContractError
from rs9.github import PublicClient, Redirects, ScopedGitHubAuthorization
from rs9.profiles import selection_for_intent
from rs9.release_core import authenticate_release, capture_release
from tests.release_fixtures import package_evidence
from tests.test_fetch import FixtureClient
from tests.test_npm_transport import TOKEN, transport

ROOT = Path(__file__).resolve().parents[1]
API = "https://api.github.com/repos/example/project/releases/assets/123"
CLASS = "github-public-release-asset"


class Response(io.BytesIO):
    status = 200

    def geturl(self):
        return API


class Opener:
    def __init__(self, body=b"data"):
        self.body, self.requests = body, []

    def open(self, request, timeout):
        self.requests.append(request)
        return Response(self.body)


class AssetFixtureClient(FixtureClient):
    def __init__(self, root, intent, *, change=None, tamper=False):
        super().__init__(root, intent)
        self.change, self.tamper, self.asset_requests = change, tamper, []

    def get(self, url, **kwargs):
        prefix = "https://api.github.com/repos/" + self.n["project"]["repository"]
        if url.startswith(prefix + "/releases/assets/"):
            self.asset_requests.append((url, kwargs))
            release = json.loads((self.root / "api/release.json").read_text())
            asset = next(a for a in release["assets"] if str(a["id"]) == url.rsplit("/", 1)[1])
            data = (self.root / "assets" / asset["name"]).read_bytes()
            return (bytes([data[0] ^ 1]) + data[1:]) if self.tamper else data
        data = super().get(url, **kwargs)
        if url == prefix + "/releases/tags/v0.6.1" and self.change:
            release = json.loads(data)
            self.change(release)
            return json.dumps(release).encode()
        return data


class ReleaseAssetApiTests(unittest.TestCase):
    def test_binary_class_uses_octet_stream_and_same_bounds(self):
        opener = Opener()
        client = PublicClient(opener)
        self.assertEqual(client.get(API, request_class=CLASS, limit=4, expected_size=4), b"data")
        self.assertEqual(opener.requests[0].get_header("Accept"), "application/octet-stream")
        self.assertEqual(client.receipts[0]["operation"], CLASS)
        for limits in ({"limit": 3}, {"expected_size": 5}):
            with self.subTest(limits=limits), self.assertRaises(ContractError):
                client.get(API, request_class=CLASS, **limits)

    def test_binary_redirect_strips_api_identity_and_receipt_query(self):
        request = Request(API)
        request.rs9_operation = CLASS
        request.rs9_trace = {"operation": CLASS, "host": "api.github.com", "redirect_hops": 0}
        request.rs9_no_redirect = False
        auth = ScopedGitHubAuthorization("synthetic-test-identity")
        auth.https_request(request)
        self.assertTrue(request.has_header("Authorization"))
        target = "https://release-assets.githubusercontent.com/example?signature=synthetic-value"
        redirected = Redirects().redirect_request(request, None, 302, "", {}, target)
        auth.https_request(redirected)
        self.assertFalse(redirected.has_header("Authorization"))
        self.assertEqual(redirected.rs9_trace["redirect_hops"], 1)
        class RedirectResponse(Response):
            def geturl(self):
                return target
        class RedirectOpener(Opener):
            def open(self, request, timeout):
                return RedirectResponse(b"data")
        client = PublicClient(RedirectOpener())
        client.get(API, request_class=CLASS)
        self.assertEqual(client.receipts[0]["final_url"], target.split("?")[0])

    def test_binary_identity_is_api_get_only(self):
        auth = ScopedGitHubAuthorization("synthetic-test-identity")
        for url, method in (("https://release-assets.githubusercontent.com/example", "GET"),
                            (API, "POST"), ("https://github.com/example", "GET")):
            request = Request(url, method=method)
            request.rs9_operation = CLASS
            auth.https_request(request)
            self.assertFalse(request.has_header("Authorization"))

    def test_binary_origin_and_redirect_authority_remain_closed(self):
        for url in ("https://github.com/example", "https://evil.example/file", "http://api.github.com/file"):
            with self.subTest(url=url), self.assertRaises(ContractError):
                PublicClient(Opener()).get(url, request_class=CLASS)
        for url in ("https://github.com/example", "https://api.github.com/different", "https://evil.example/file"):
            request = Request(API)
            request.rs9_operation, request.rs9_trace, request.rs9_no_redirect = CLASS, {"redirect_hops": 0}, False
            with self.subTest(redirect=url), self.assertRaises(ContractError):
                Redirects().redirect_request(request, None, 302, "", {}, url)

    def test_api_504_fails_without_browser_fallback_or_retry(self):
        class Unreadable(io.BytesIO):
            def read(self, *args):
                raise AssertionError("An error body must not be read")
        body = Unreadable(b"withheld error")
        class FailingOpener(Opener):
            def open(self, request, timeout):
                self.requests.append(request)
                raise HTTPError(API, 504, "unretained message", {}, body)
        opener = FailingOpener()
        with self.assertRaises(ContractError) as caught:
            PublicClient(opener).get(API, request_class=CLASS)
        self.assertEqual(caught.exception.code, "FETCH_FAILED")
        self.assertEqual(caught.exception.details["http_status"], 504)
        self.assertEqual(len(opener.requests), 1)
        self.assertTrue(body.closed)

    def test_real_handler_chain_binary_response_and_cross_host_identity(self):
        for final in (API, "https://objects.githubusercontent.com/file?signature=synthetic-value",
                      "https://release-assets.githubusercontent.com/file?signature=synthetic-value"):
            routes = {API: (200, b"data")} if final == API else {API: (302, final), final: (200, b"data")}
            client, handler = transport(routes)
            self.assertEqual(client.get(API, request_class=CLASS, expected_size=4), b"data")
            self.assertEqual(handler.requests[0].get_header("Authorization"), "Bearer " + TOKEN)
            self.assertEqual(handler.requests[0].get_header("Accept"), "application/octet-stream")
            for request in handler.requests[1:]:
                self.assertFalse(request.has_header("Authorization"))
            self.assertNotIn(TOKEN, json.dumps(client.receipts))
            self.assertNotIn("signature", json.dumps(client.receipts))

    def test_binary_transfer_deadline_and_failure_details_remain_bounded(self):
        client, handler = transport({API: (200, b"data")})
        with patch("rs9.github.time.monotonic", side_effect=[0, 121]):
            with self.assertRaises(ContractError) as caught:
                client.get(API, request_class=CLASS)
        self.assertEqual(caught.exception.code, "FETCH_LIMIT")
        self.assertEqual(caught.exception.details["reason"], "deadline")
        self.assertTrue(handler.bodies[0].closed)
        client, handler = transport({API: (504, TOKEN.encode())})
        with self.assertRaises(ContractError) as caught:
            client.get(API, request_class=CLASS)
        self.assertEqual(caught.exception.details["operation"], CLASS)
        self.assertEqual(caught.exception.details["http_status"], 504)
        self.assertEqual(len(handler.requests), 1)
        self.assertTrue(handler.bodies[0].closed)
        self.assertNotIn(TOKEN, json.dumps(caught.exception.details))

    def test_api_and_browser_captures_have_identical_authenticated_records(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            source = root / "fixture"; source.mkdir()
            intent = package_evidence(source)
            selection = selection_for_intent(intent)
            browser = root / "browser"; browser.mkdir()
            api = root / "api-copy"; api.mkdir()
            capture_release(selection, browser, client=FixtureClient(source, intent))
            client = AssetFixtureClient(source, intent)
            capture_release(selection, api, client=client, asset_transport="release-api")
            self.assertEqual(authenticate_release(selection, browser).record,
                             authenticate_release(selection, api).record)
            metadata = json.loads((source / "api/release.json").read_text())
            self.assertEqual(len(client.asset_requests), len(metadata["assets"]))
            for url, options in client.asset_requests:
                self.assertEqual(options["request_class"], CLASS)
                self.assertTrue(url.startswith("https://api.github.com/repos/" + intent["project"]["repository"] + "/releases/assets/"))

    def test_api_capture_refuses_invalid_asset_identity_before_body_fetch(self):
        for bad in (None, 0, -1, True, "123"):
            with self.subTest(id=bad), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve(); source = root / "fixture"; source.mkdir()
                intent = package_evidence(source); target = root / "target"; target.mkdir()
                def change(release):
                    for row in release["assets"]:
                        row["id"] = bad
                client = AssetFixtureClient(source, intent, change=change)
                with self.assertRaises(ContractError) as caught:
                    capture_release(selection_for_intent(intent), target, client=client, asset_transport="release-api")
                self.assertEqual(caught.exception.code, "ASSET_AUTHORITY")
                self.assertEqual(client.asset_requests, [])

    def test_api_capture_still_refuses_wrong_browser_authority(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(); source = root / "fixture"; source.mkdir()
            intent = package_evidence(source); target = root / "target"; target.mkdir()
            def change(release):
                for row in release["assets"]:
                    row["browser_download_url"] = "https://github.com/different/project/file"
            client = AssetFixtureClient(source, intent, change=change)
            with self.assertRaises(ContractError) as caught:
                capture_release(selection_for_intent(intent), target, client=client, asset_transport="release-api")
            self.assertEqual(caught.exception.code, "ASSET_AUTHORITY")
            self.assertEqual(client.asset_requests, [])

    def test_api_capture_still_requires_digest_authentication(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(); source = root / "fixture"; source.mkdir()
            intent = package_evidence(source); target = root / "target"; target.mkdir()
            client = AssetFixtureClient(source, intent, tamper=True)
            selection = selection_for_intent(intent)
            capture_release(selection, target, client=client, asset_transport="release-api")
            with self.assertRaises(ContractError) as caught:
                authenticate_release(selection, target)
            self.assertEqual(caught.exception.code, "DIGEST_MISMATCH")

    def test_api_capture_refuses_inconsistent_asset_api_url(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(); source = root / "fixture"; source.mkdir()
            intent = package_evidence(source); target = root / "target"; target.mkdir()
            def change(release):
                for row in release["assets"]:
                    row["url"] = "https://api.github.com/repos/different/project/releases/assets/123"
            client = AssetFixtureClient(source, intent, change=change)
            with self.assertRaises(ContractError) as caught:
                capture_release(selection_for_intent(intent), target, client=client, asset_transport="release-api")
            self.assertEqual(caught.exception.code, "ASSET_AUTHORITY")
            self.assertEqual(client.asset_requests, [])

    def test_api_capture_still_requires_tagged_source_authentication(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(); source = root / "fixture"; source.mkdir()
            intent = package_evidence(source); target = root / "target"; target.mkdir()
            selection = selection_for_intent(intent)
            capture_release(selection, target, client=AssetFixtureClient(source, intent), asset_transport="release-api")
            leaf = next(p for p in (target / "source").iterdir() if p.is_file())
            leaf.write_bytes(leaf.read_bytes() + b"\n")
            with self.assertRaises(ContractError) as caught:
                authenticate_release(selection, target)
            self.assertEqual(caught.exception.code, "SOURCE_BLOB_MISMATCH")

    def test_unknown_transport_refused_before_network(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(); source = root / "fixture"; source.mkdir()
            selection = selection_for_intent(package_evidence(source))
            for mode in (None, {}, "fallback", True):
                client = AssetFixtureClient(source, {})
                with self.subTest(mode=mode), self.assertRaises(ContractError) as caught:
                    capture_release(selection, root, client=client, asset_transport=mode)
                self.assertEqual(caught.exception.code, "ASSET_TRANSPORT")

    def test_only_explicit_current_generation_selects_asset_api(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(); source = root / "fixture"; source.mkdir()
            intent = package_evidence(source)
            rows = [({"repository": intent["project"]["repository"]}, intent)]
            for generation in (HISTORICAL_GENERATION, CURRENT_GENERATION):
                target = root / generation; target.mkdir()
                with patch("rs9.candidate.configuration_rows", return_value=rows), \
                     patch("rs9.candidate.capture_release", side_effect=ContractError("SYNTHETIC_STOP", "Before transport")) as capture:
                    with self.assertRaises(ContractError):
                        capture_generation(ROOT, target, client=object(), generation=generation)
                mode = capture.call_args.kwargs.get("asset_transport", "browser")
                self.assertEqual(mode, "release-api" if generation == CURRENT_GENERATION else "browser")
