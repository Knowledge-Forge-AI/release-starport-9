"""Real urllib handler-chain tests without contacting public services."""
import http.client
import io
import json
from email.message import Message
import socket
import ssl
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError
from urllib.request import BaseHandler, Request
from urllib.response import addinfourl

from rs9.errors import ContractError, safe_details
from rs9.github import PublicClient, REQUEST_CLASSES, ScopedGitHubAuthorization, public_opener

TOKEN = "ghp_" + "a" * 36  # Synthetic, never a credential.


class RecordingHTTPS(BaseHandler):
    handler_order = 100

    def __init__(self, routes):
        self.routes, self.requests, self.bodies = routes, [], []

    def https_open(self, request):
        self.requests.append(request)
        action = self.routes[request.full_url]
        if isinstance(action, Exception):
            raise action
        status, payload = action
        headers = Message()
        if status in (301, 302, 303, 307, 308):
            headers["Location"] = payload
            payload = b"redirect"
        body = io.BytesIO(payload)
        self.bodies.append(body)
        response = addinfourl(body, headers, request.full_url, status)
        response.msg = "synthetic"
        return response


def transport(routes):
    handler = RecordingHTTPS(routes)
    return PublicClient(public_opener(TOKEN, handler)), handler


class NpmTransportTests(unittest.TestCase):
    def test_each_class_has_correct_accept_and_scoped_authorization(self):
        cases = (("github-api", "api.github.com", "application/vnd.github+json", True),
                 ("npm-packument", "registry.npmjs.org", "application/json", False),
                 ("npm-tarball", "registry.npmjs.org", "*/*", False),
                 ("github-asset", "github.com", "*/*", False),
                 ("github-source", "raw.githubusercontent.com", "*/*", False),
                 ("nix-installer", "releases.nixos.org", "*/*", False))
        for operation, host, accept, auth in cases:
            with self.subTest(operation=operation):
                url = "https://" + host + "/example"
                client, handler = transport({url: (200, b"{}")})
                self.assertEqual(client.get(url, request_class=operation), b"{}")
                request = handler.requests[0]
                self.assertEqual(request.get_header("Accept"), accept)
                self.assertEqual(request.get_header("Authorization"), "Bearer " + TOKEN if auth else None)
                self.assertNotIn(TOKEN, json.dumps(client.receipts))

    def test_same_host_api_redirect_preserves_class_and_scoped_identity(self):
        first, final = "https://api.github.com/first", "https://api.github.com/final"
        client, handler = transport({first: (302, final), final: (200, b"{}")})
        client.get(first, request_class="github-api")
        self.assertEqual(len(handler.requests), 2)
        for request in handler.requests:
            self.assertEqual(request.rs9_operation, "github-api")
            self.assertEqual(request.get_header("Authorization"), "Bearer " + TOKEN)

    def test_asset_cdn_and_raw_redirects_never_receive_identity(self):
        for first, final, operation in (
            ("https://github.com/asset", "https://release-assets.githubusercontent.com/asset?signature=synthetic", "github-asset"),
            ("https://github.com/asset", "https://objects.githubusercontent.com/asset", "github-asset"),
            ("https://raw.githubusercontent.com/first", "https://raw.githubusercontent.com/final", "github-source")):
            with self.subTest(final=final):
                client, handler = transport({first: (302, final), final: (200, b"x")})
                client.get(first, request_class=operation)
                self.assertTrue(all(r.get_header("Authorization") is None for r in handler.requests))
                self.assertNotIn("signature", json.dumps(client.receipts))

    def test_api_cross_origin_and_packument_redirects_fail_closed(self):
        for first, final, operation in (
            ("https://api.github.com/first", "https://raw.githubusercontent.com/final", "github-api"),
            ("https://registry.npmjs.org/first", "https://registry.npmjs.org/final", "npm-packument"),
            ("https://registry.npmjs.org/first", "https://github.com/final", "npm-tarball")):
            client, handler = transport({first: (302, final)})
            with self.assertRaises(ContractError) as caught:
                client.get(first, request_class=operation)
            self.assertEqual(caught.exception.code, "REDIRECT_REJECTED")
            self.assertEqual(len(handler.requests), 1)

    def test_redirect_limit_and_no_redirect_are_enforced(self):
        routes = {"https://api.github.com/" + str(i): (302, "https://api.github.com/" + str(i + 1)) for i in range(6)}
        for no_redirect, hops in ((False, 5), (True, 0)):
            client, _ = transport(routes)
            with self.assertRaises(ContractError) as caught:
                client.get("https://api.github.com/0", request_class="github-api", no_redirect=no_redirect)
            self.assertEqual(caught.exception.code, "REDIRECT_REJECTED")
            self.assertEqual(caught.exception.details["redirect_hops"], hops)

    def test_injected_opener_cannot_escape_final_origin(self):
        class Opener:
            def open(self, request, timeout):
                return addinfourl(io.BytesIO(b"x"), {}, "https://github.com/escaped", 200)
        with self.assertRaises(ContractError) as caught:
            PublicClient(Opener()).get("https://registry.npmjs.org/example.tgz", request_class="npm-tarball")
        self.assertEqual(caught.exception.code, "REDIRECT_REJECTED")

    def test_metadata_and_tarball_http_failures_are_closed_sanitized_and_not_retried(self):
        for operation in ("npm-packument", "npm-tarball"):
            for status in (404, 406, 503):
                with self.subTest(operation=operation, status=status):
                    url = "https://registry.npmjs.org/example"
                    client, handler = transport({url: (status, TOKEN.encode())})
                    with self.assertRaises(ContractError) as caught:
                        client.get(url, request_class=operation)
                    self.assertEqual(caught.exception.code, "FETCH_FAILED")
                    self.assertEqual(caught.exception.details, {"operation": operation, "host": "registry.npmjs.org",
                        "redirect_hops": 0, "http_status": status, "reason": "http-status"})
                    self.assertEqual(len(handler.requests), 1)
                    self.assertTrue(handler.bodies[0].closed)
                    self.assertNotIn(TOKEN, str(caught.exception) + json.dumps(caught.exception.details) + json.dumps(client.receipts))

    def test_transport_errors_retain_only_closed_classes(self):
        cases = ((URLError(TimeoutError(TOKEN)), "timeout"), (URLError(ssl.SSLError(TOKEN)), "tls"),
                 (URLError(socket.gaierror(TOKEN)), "dns"), (ConnectionResetError(TOKEN), "connection"),
                 (http.client.IncompleteRead(TOKEN.encode()), "protocol"), (URLError(TOKEN), "transport"))
        for error, category in cases:
            url = "https://registry.npmjs.org/example.tgz"
            client, _ = transport({url: error})
            with self.assertRaises(ContractError) as caught:
                client.get(url, request_class="npm-tarball")
            self.assertEqual(caught.exception.details["transport_error"], category)
            self.assertNotIn(TOKEN, str(caught.exception) + json.dumps(caught.exception.details))

    def test_request_class_header_and_token_validation(self):
        client, handler = transport({})
        with self.assertRaises(TypeError):
            client.get("https://api.github.com/example")
        with self.assertRaises(TypeError):
            client.json("https://api.github.com/example")
        with self.assertRaises(TypeError):
            client.get("https://api.github.com/example", request_class="github-api", headers={"X": "x"})
        with self.assertRaises(ContractError) as caught:
            client.get("https://api.github.com/example", request_class="untrusted")
        self.assertEqual(caught.exception.code, "REQUEST_CLASS")
        for bad in ("json\r\nX: injected", "json\0", "json\t", "json\x7f"):
            with patch.dict(REQUEST_CLASSES, {"npm-packument": (bad, {"registry.npmjs.org"}, set())}):
                with self.assertRaises(ContractError) as caught:
                    client.get("https://registry.npmjs.org/example", request_class="npm-packument")
                self.assertEqual(caught.exception.code, "REQUEST_HEADER")
            with self.assertRaises(ContractError):
                ScopedGitHubAuthorization(bad)
        self.assertEqual(handler.requests, [])

    def test_misclassified_requests_and_non_get_never_get_token(self):
        request = Request("https://api.github.com/example", method="POST")
        request.rs9_operation = "github-api"
        self.assertIsNone(ScopedGitHubAuthorization(TOKEN).https_request(request).get_header("Authorization"))
        client, handler = transport({})
        with self.assertRaises(ContractError):
            client.get("https://api.github.com/example", request_class="npm-tarball")
        self.assertEqual(handler.requests, [])

    def test_safe_details_drops_unknown_and_out_of_range_values(self):
        self.assertEqual(safe_details({"operation": TOKEN, "host": "secret.example", "http_status": True,
            "redirect_hops": 6, "transport_error": "private failure", "headers": {"Authorization": TOKEN}}),
            {"details_truncated": True})
        for key, value in (("http_status", 99), ("http_status", 600), ("redirect_hops", -1)):
            self.assertEqual(safe_details({key: value}), {"details_truncated": True})

    def test_limit_and_deadline_close_response_and_remain_distinct(self):
        url = "https://registry.npmjs.org/example.tgz"
        for deadline in (False, True):
            client, handler = transport({url: (200, b"12345")})
            with patch("rs9.github.time.monotonic", side_effect=[0, 121] if deadline else [0, 0]):
                with self.assertRaises(ContractError) as caught:
                    client.get(url, request_class="npm-tarball", limit=4)
            self.assertEqual(caught.exception.code, "FETCH_LIMIT")
            self.assertEqual(caught.exception.details["reason"], "deadline" if deadline else "size-limit")
            self.assertTrue(handler.bodies[0].closed)
