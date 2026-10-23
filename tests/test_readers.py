"""Hermetic unit tests for destination readers and bin normalization."""
import unittest

from rs9.errors import ContractError
from rs9.readers import _normalized_npm_bin


class NormalizedNpmBinTests(unittest.TestCase):
    def test_command_alias_paths_are_rejected(self):
        for command in ("/tool", "../tool", "dir/tool", "dir\\tool", "x:tool"):
            with self.subTest(command=command), self.assertRaises(ContractError):
                _normalized_npm_bin("pkg", {command: "./bin/tool"})

    def test_allows_one_dot_slash_prefix_and_missing_prefix_regression(self):
        """Allow one ./ prefix or missing ./ prefix, normalizing both to safe relative posix paths."""
        # String bin with scoped and unscoped package names
        self.assertEqual(_normalized_npm_bin("my-tool", "./bin/tool.js"), {"my-tool": "bin/tool.js"})
        self.assertEqual(_normalized_npm_bin("my-tool", "bin/tool.js"), {"my-tool": "bin/tool.js"})
        self.assertEqual(_normalized_npm_bin("@scope/my-tool", "./bin/tool.js"), {"my-tool": "bin/tool.js"})
        self.assertEqual(_normalized_npm_bin("@scope/my-tool", "bin/tool.js"), {"my-tool": "bin/tool.js"})

        # Dictionary bin targets with and without ./ prefix
        targets = {
            "cmd-a": "./bin/a.js",
            "cmd-b": "bin/b.js",
            "cmd-c": "./dist/cli.mjs",
            "cmd-d": "dist/cli.mjs",
        }
        expected = {
            "cmd-a": "bin/a.js",
            "cmd-b": "bin/b.js",
            "cmd-c": "dist/cli.mjs",
            "cmd-d": "dist/cli.mjs",
        }
        self.assertEqual(_normalized_npm_bin("test-pkg", targets), expected)

        # Direct ./bin and bin target regression
        self.assertEqual(_normalized_npm_bin("burst", "./bin"), {"burst": "bin"})
        self.assertEqual(_normalized_npm_bin("burst", "bin"), {"burst": "bin"})
        self.assertEqual(_normalized_npm_bin("burst", {"burst": "./bin"}), {"burst": "bin"})
        self.assertEqual(_normalized_npm_bin("burst", {"burst": "bin"}), {"burst": "bin"})

        # Missing or None bin returns empty dict
        self.assertEqual(_normalized_npm_bin("pkg", None), {})

    def test_valid_bin_array_normalized_by_basename(self):
        """Array of unique bin paths normalizes each command to its basename."""
        self.assertEqual(
            _normalized_npm_bin("my-pkg", ["./bin/tool-a", "bin/tool-b", "./dist/tool-c"]),
            {"tool-a": "bin/tool-a", "tool-b": "bin/tool-b", "tool-c": "dist/tool-c"},
        )

    def test_rejects_duplicate_array_basename_aliases(self):
        """Array with colliding basenames fails closed with duplicate array basename aliases."""
        colliding_cases = [
            ["./bin/tool", "./other/tool"],
            ["bin/tool", "other/tool"],
            ["./dir1/sub/tool.js", "./dir2/tool.js"],
        ]
        for paths in colliding_cases:
            with self.subTest(paths=paths):
                with self.assertRaises(ContractError) as caught:
                    _normalized_npm_bin("my-pkg", paths)
                self.assertEqual(caught.exception.code, "NPM_METADATA")
                self.assertIn("Duplicate array basename aliases", str(caught.exception))

    def test_rejects_multiple_dot_slash_prefixes(self):
        """Multiple ./ prefixes (e.g. ././bin) are rejected."""
        invalid_targets = ["././bin/tool.js", "./././tool.js"]
        for target in invalid_targets:
            with self.subTest(target=target):
                with self.assertRaises(ContractError):
                    _normalized_npm_bin("pkg", target)

    def test_rejects_absolute_paths(self):
        """Absolute paths starting with / are rejected."""
        absolute_targets = ["/bin/tool", "/usr/bin/tool", "/cli.js"]
        for target in absolute_targets:
            with self.subTest(target=target):
                with self.assertRaises(ContractError):
                    _normalized_npm_bin("pkg", target)

    def test_rejects_directory_traversal(self):
        """Directory traversal segments like .. or . are rejected."""
        traversal_targets = [
            "../bin/tool",
            "./../bin/tool",
            "bin/../tool",
            "bin/../../tool",
            "bin/./tool",
        ]
        for target in traversal_targets:
            with self.subTest(target=target):
                with self.assertRaises(ContractError):
                    _normalized_npm_bin("pkg", target)

    def test_rejects_backslashes(self):
        """Backslashes in targets are rejected rather than sanitized to slashes."""
        backslash_targets = ["bin\\tool", ".\\bin\\tool", "bin\\subdir\\tool.js"]
        for target in backslash_targets:
            with self.subTest(target=target):
                with self.assertRaises(ContractError):
                    _normalized_npm_bin("pkg", target)

    def test_rejects_nul_and_control_characters(self):
        """NUL bytes and ASCII control characters are rejected."""
        control_targets = ["bin/\0tool", "bin/\x1ftool", "bin/\r/tool", "bin/\n/tool"]
        for target in control_targets:
            with self.subTest(target=target):
                with self.assertRaises(ContractError):
                    _normalized_npm_bin("pkg", target)

    def test_rejects_empty_targets(self):
        """Empty string and isolated ./ target are rejected."""
        for target in ("", "./"):
            with self.subTest(target=target):
                with self.assertRaises(ContractError):
                    _normalized_npm_bin("pkg", target)

    def test_rejects_invalid_types_and_unsupported_metadata(self):
        """Non-string/dict/list/None bin structures are rejected."""
        for invalid in (123, True, [123], {"cmd": 123}, {"": "bin/tool"}):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ContractError):
                    _normalized_npm_bin("pkg", invalid)


class ReadNpmAndHomebrewTests(unittest.TestCase):
    def test_read_npm_with_dot_slash_bin_reaches_exact_state(self):
        import base64
        import hashlib
        import io
        import tarfile
        from unittest.mock import patch
        from rs9.readers import read_npm
        from rs9.scratch import canonical

        package = {
            "name": "fixture-tool",
            "version": "1.0.0",
            "license": "MIT",
            "bin": {"fixture-tool": "./bin/main.js"},
        }
        metadata = canonical(package)
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            member = tarfile.TarInfo("package/package.json")
            member.size = len(metadata)
            archive.addfile(member, io.BytesIO(metadata))
        payload = buffer.getvalue()
        integrity = "sha512-" + base64.b64encode(hashlib.sha512(payload).digest()).decode()
        registry = {
            "name": "fixture-tool",
            "versions": {
                "1.0.0": {
                    **package,
                    "dist": {
                        "integrity": integrity,
                        "tarball": "https://registry.npmjs.org/fixture-tool/-/fixture-tool-1.0.0.tgz",
                    },
                }
            },
        }
        with patch("rs9.readers._get", side_effect=[canonical(registry), payload]):
            obs = read_npm(
                "fixture-tool",
                "1.0.0",
                expected_integrity=integrity,
                expected_license="MIT",
                expected_commands={"fixture-tool": "bin/main.js"},
                expected_hashes={"fixture-tool-1.0.0.tgz": hashlib.sha256(payload).hexdigest()},
            )
        self.assertEqual(obs["state"], "exact")

    def test_read_npm_with_unsafe_bin_fails_closed_to_unknown_with_diagnostic(self):
        from unittest.mock import patch
        from rs9.readers import read_npm
        from rs9.scratch import canonical

        registry = {
            "name": "unsafe-tool",
            "versions": {
                "1.0.0": {
                    "name": "unsafe-tool",
                    "version": "1.0.0",
                    "license": "MIT",
                    "bin": {"unsafe-tool": "../etc/passwd"},
                    "dist": {
                        "integrity": "sha512-" + "a" * 86 + "==",
                        "tarball": "https://registry.npmjs.org/unsafe-tool/-/unsafe-tool-1.0.0.tgz",
                    },
                }
            },
        }
        with patch("rs9.readers._get", return_value=canonical(registry)):
            obs = read_npm(
                "unsafe-tool",
                "1.0.0",
                expected_integrity="sha512-" + "a" * 86 + "==",
                expected_license="MIT",
                expected_commands={"unsafe-tool": "bin/tool.js"},
            )
        self.assertEqual(obs["state"], "unknown")
        diags = obs.get("diagnostics", [])
        self.assertTrue(any(d.get("code") == "destination-contract-error" for d in diags))

    def test_read_homebrew_requires_immutable_pinned_ref(self):
        from rs9.readers import read_homebrew

        for bad_ref in ("main", "HEAD", "not-a-sha", "1" * 39, "1" * 41):
            with self.subTest(bad_ref=bad_ref):
                with self.assertRaises(ContractError) as caught:
                    read_homebrew("test-tool", "1.0.0", pinned_ref=bad_ref)
                self.assertEqual(caught.exception.code, "HOMEBREW_PIN")

    def test_read_homebrew_requires_homebrew_adapter(self):
        from rs9.readers import read_homebrew

        with self.assertRaises(ContractError) as caught:
            read_homebrew({"id": "npm", "adapter": "npm", "mode": "projection"}, pinned_ref="a" * 40)
        self.assertEqual(caught.exception.code, "READER_DESTINATION")


MARKER = "rs9-leak-marker-91d4"
JSON_URL = "https://pypi.org/pypi/theme-forge-solar-sail/json"
FILE_URL = "https://files.pythonhosted.org/packages/ab/cd/theme_forge_solar_sail-0.2.1.post1.tar.gz"


class FakePypiResponse:
    """Scripted urllib response: parts are bytes served at most n per read, or exceptions raised."""

    def __init__(self, parts=(), *, url, status=200, headers=(), overserve=False):
        from http.client import HTTPMessage
        self.status, self._url, self._parts, self._offset = status, url, list(parts), 0
        self.headers = HTTPMessage()
        for key, value in headers:
            self.headers[key] = value
        self.overserve, self.reads, self.served, self.closed = overserve, [], 0, 0

    def geturl(self):
        return self._url

    def read(self, n):
        self.reads.append(n)
        while self._parts:
            part = self._parts[0]
            if isinstance(part, BaseException):
                self._parts.pop(0)
                raise part
            if self._offset < len(part):
                data = part[self._offset:self._offset + n + (1 if self.overserve else 0)]
                self._offset += len(data)
                self.served += len(data)
                return data
            self._parts.pop(0)
            self._offset = 0
        return b""

    def close(self):
        self.closed += 1


class FakePypiOpener:
    def __init__(self, outcomes):
        self.outcomes, self.requests = outcomes, []

    def open(self, request, timeout=None):
        self.requests.append((request.full_url, request.get_header("User-agent"), timeout))
        outcome = self.outcomes[request.full_url] if isinstance(self.outcomes, dict) else self.outcomes
        outcome = outcome() if callable(outcome) and not isinstance(outcome, BaseException) else outcome
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


class PypiBoundedFetchTests(unittest.TestCase):
    def fetch_for(self, outcome):
        from rs9.readers import _PypiBoundedFetch
        opener = FakePypiOpener(outcome)
        return _PypiBoundedFetch(opener=opener), opener

    def assert_failure(self, fetch, url, limit, token, code="TF_PYPI_REMOTE_UNKNOWN"):
        from rs9.tf_pypi_archive import AdmissionError
        from rs9.tf_pypi_remote import _FETCH_TOKENS, _ObserverAdmissionError
        before = list(fetch.failures)
        with self.assertRaises(AdmissionError) as caught:
            fetch(url, limit)
        error = caught.exception
        self.assertIsInstance(error, _ObserverAdmissionError)
        self.assertEqual((error.code, error.cause, error.args), (code, token, (code,)))
        self.assertIn(token, _FETCH_TOKENS)
        self.assertEqual(fetch.failures, before + [token])
        self.assertTrue(error.__suppress_context__)
        self.assertIsNone(error.__cause__)
        self.assertNotIn(MARKER, str(error) + repr(error) + repr(fetch.failures) + repr(vars(error)))
        return error

    def response(self, parts=(), *, url=FILE_URL, length=None, **kwargs):
        headers = kwargs.pop("headers", [("Content-Length", str(length))] if length is not None else [])
        return FakePypiResponse(parts, url=url, headers=headers, **kwargs)

    def test_complete_bodies_within_bound_are_returned(self):
        body = b"0123456789"
        cases = (
            ([body], len(body), 10, body),
            ([body[:4], body[4:]], len(body), 10, body),
            ([body[:5]], 5, 10, body[:5]),
            ([body], None, 10, body),
            ([body[:3], body[3:6]], None, 10, body[:6]),
            ([b""], 0, 10, b""),
        )
        for parts, length, limit, expected in cases:
            response = self.response(parts, length=length)
            fetch, opener = self.fetch_for(response)
            with self.subTest(parts=parts, length=length):
                self.assertEqual(fetch(FILE_URL, limit), expected)
                self.assertEqual(opener.requests, [(FILE_URL, "RS9-readback-v1alpha1", 20)])
                self.assertEqual(response.closed, 1)
                self.assertEqual(fetch.failures, [])
                self.assertLessEqual(response.served, limit + 1)
                self.assertTrue(all(0 < n <= limit + 1 for n in response.reads))

    def test_over_bound_is_limit_and_never_returned(self):
        response = self.response([b"x" * 11])
        fetch, _ = self.fetch_for(response)
        self.assert_failure(fetch, FILE_URL, 10, "limit")
        self.assertLessEqual(response.served, 11)
        self.assertEqual(response.closed, 1)
        response = self.response([b"x" * 11], length=11)
        fetch, _ = self.fetch_for(response)
        self.assert_failure(fetch, FILE_URL, 10, "limit")
        self.assertEqual(response.reads, [])
        self.assertEqual(response.closed, 1)

    def test_size_plus_one_reads_at_most_limit_plus_one(self):
        from rs9.readers import _PYPI_FETCH_CHUNK
        limit = 2 * _PYPI_FETCH_CHUNK + 5
        response = self.response([b"y" * (limit + 1000)])
        fetch, _ = self.fetch_for(response)
        self.assert_failure(fetch, FILE_URL, limit, "limit")
        self.assertEqual(response.served, limit + 1)
        self.assertEqual(sum(response.reads), limit + 1)
        self.assertTrue(all(n <= _PYPI_FETCH_CHUNK for n in response.reads))

    def test_declared_transfer_mismatch_is_incomplete_body(self):
        for parts, length in (([b"x" * 6], 10), ([b"x" * 8], 5), ([b"x" * 3, b"x" * 3], 10)):
            response = self.response(parts, length=length)
            fetch, _ = self.fetch_for(response)
            with self.subTest(parts=parts, length=length):
                self.assert_failure(fetch, FILE_URL, 10, "incomplete-body")
                self.assertEqual(response.closed, 1)

    def test_malformed_content_length_and_reads_are_protocol(self):
        from http.client import IncompleteRead
        cases = (
            self.response([b"x"], headers=[("Content-Length", "abc")]),
            self.response([b"x"], headers=[("Content-Length", "-1")]),
            self.response([b"x"], headers=[("Content-Length", "1e3")]),
            self.response([b"x"], headers=[("Content-Length", "١")]),
            self.response([b"x"], headers=[("Content-Length", "1"), ("Content-Length", "1")]),
            self.response([b"xx", IncompleteRead(MARKER.encode(), 10)], length=10),
            self.response([IncompleteRead(b"", 3)]),
            self.response([b"x" * 20], length=10, overserve=True),
            self.response(["text"]),
        )
        for response in cases:
            fetch, _ = self.fetch_for(response)
            with self.subTest(headers=response.headers.items()):
                self.assert_failure(fetch, FILE_URL, 10, "protocol")
                self.assertEqual(response.closed, 1)

    def test_open_failures_map_to_closed_tokens(self):
        import socket
        import ssl
        from http.client import BadStatusLine
        from urllib.error import URLError
        cert = ssl.SSLCertVerificationError(1, MARKER)
        cert.verify_code = 20
        cases = (
            (BadStatusLine(MARKER), "protocol", None),
            (URLError(cert), "tls-certificate-verify-failed", 20),
            (cert, "tls-certificate-verify-failed", 20),
            (ssl.SSLEOFError(8, MARKER), "tls-unexpected-eof", None),
            (TimeoutError(MARKER), "timeout", None),
            (URLError(TimeoutError(MARKER)), "timeout", None),
            (ConnectionResetError(MARKER), "transport", None),
            (URLError(MARKER), "transport", None),
            (URLError(socket.gaierror(MARKER)), "transport", None),
            (ContractError("READER_REDIRECT", MARKER), "redirect", None),
        )
        for raised, token, verify_code in cases:
            fetch, _ = self.fetch_for(raised)
            with self.subTest(raised=type(raised).__name__, token=token):
                self.assert_failure(fetch, JSON_URL, 10, token)
                self.assertEqual(fetch.tls_verify_code, verify_code)
        fetch, _ = self.fetch_for(ContractError("OTHER_CONTRACT", MARKER))
        with self.assertRaises(ContractError):
            fetch(JSON_URL, 10)

    def test_read_failures_close_the_response(self):
        import ssl
        for raised, token in ((TimeoutError(MARKER), "timeout"), (ssl.SSLEOFError(8, MARKER), "tls-unexpected-eof"),
                              (ConnectionResetError(MARKER), "transport")):
            response = self.response([b"xx", raised], length=10)
            fetch, _ = self.fetch_for(response)
            with self.subTest(token=token):
                self.assert_failure(fetch, FILE_URL, 10, token)
                self.assertEqual(response.closed, 1)

    def test_close_failures_map_to_closed_tokens_and_discard_the_body(self):
        from http.client import HTTPException

        class FailingClose(FakePypiResponse):
            def __init__(self, raised, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.raised = raised

            def close(self):
                super().close()
                raise self.raised

        for raised, token in ((ConnectionResetError(MARKER), "transport"), (TimeoutError(MARKER), "timeout"),
                              (HTTPException(MARKER), "protocol")):
            response = FailingClose(raised, [b"0123456789"], url=FILE_URL, headers=[("Content-Length", "10")])
            fetch, _ = self.fetch_for(response)
            with self.subTest(token=token):
                self.assert_failure(fetch, FILE_URL, 10, token)
                self.assertEqual(response.closed, 1)
        # The first failure token wins over a later close failure.
        response = FailingClose(ConnectionResetError(MARKER), [b"x" * 11], url=FILE_URL)
        fetch, _ = self.fetch_for(response)
        self.assert_failure(fetch, FILE_URL, 10, "limit")
        self.assertEqual(response.closed, 1)

    def test_http_errors_absent_only_for_exact_url_404(self):
        import io
        from http.client import HTTPMessage
        from urllib.error import HTTPError
        cases = (
            (FILE_URL, 404, "http-404", "TF_PYPI_REMOTE_ABSENT"),
            (FILE_URL + "x", 404, "http-404", "TF_PYPI_REMOTE_UNKNOWN"),
            (FILE_URL, 403, "http-403", "TF_PYPI_REMOTE_UNKNOWN"),
            (FILE_URL, 500, "http-500", "TF_PYPI_REMOTE_UNKNOWN"),
            (FILE_URL, 301, "http-301", "TF_PYPI_REMOTE_UNKNOWN"),
            (FILE_URL, 999, "http-unknown", "TF_PYPI_REMOTE_UNKNOWN"),
        )
        for error_url, status, token, code in cases:
            body = io.BytesIO(MARKER.encode())
            fetch, _ = self.fetch_for(HTTPError(error_url, status, MARKER, HTTPMessage(), body))
            with self.subTest(status=status, error_url=error_url):
                self.assert_failure(fetch, FILE_URL, 10, token, code)
                self.assertTrue(body.closed)

    def test_non_200_status_and_foreign_response_url_fail(self):
        response = self.response([b"x"], status=203)
        fetch, _ = self.fetch_for(response)
        self.assert_failure(fetch, FILE_URL, 10, "http-203")
        self.assertEqual((response.reads, response.closed), ([], 1))
        response = self.response([b"x"], url=FILE_URL.replace("files.pythonhosted.org", "evil.example"))
        fetch, _ = self.fetch_for(response)
        self.assert_failure(fetch, FILE_URL, 10, "url-authority")
        self.assertEqual((response.reads, response.closed), ([], 1))

    def test_request_discipline_refuses_before_opening(self):
        bad_urls = (
            "http://pypi.org/pypi/x/json",
            "https://evil.example/pypi/x/json",
            "https://pypi.org:8443/pypi/x/json",
            "https://pypi.org:abc/pypi/x/json",
            "https://user@pypi.org/pypi/x/json",
            "https://user:pw@files.pythonhosted.org/packages/x.whl",
            "https://pypi.org/pypi/x/json?x=1",
            "https://pypi.org/pypi/x/json?",
            "https://pypi.org/pypi/x/json#frag",
            "https://pypi.org/simple/x/",
            "https://pypi.org/pypi/../json",
            "https://pypi.org/packages/ab/x.whl",
            "https://files.pythonhosted.org/",
            "https://files.pythonhosted.org/packages/../x.whl",
            "https://files.pythonhosted.org/packages//x.whl",
            "https://files.pythonhosted.org/packages/a%2fb.whl",
            "https://files.pythonhosted.org/packages/a b.whl",
            "https://files.pythonhosted.org/packages/é.whl",
            "https://files.pythonhosted.org\\packages/x.whl",
            "https://files.pythonhosted.org.evil.example/packages/x.whl",
            "",
            None,
            b"https://pypi.org/pypi/x/json",
        )
        fetch, opener = self.fetch_for(AssertionError("opened"))
        for url in bad_urls:
            with self.subTest(url=url):
                self.assert_failure(fetch, url, 10, "url-authority")
        self.assert_failure(fetch, "https://pypi.org/pypi/ghp_" + "A" * 36 + "/json", 10, "credential-scan")
        from rs9.readers import _PYPI_FETCH_MAX
        for limit in (0, -1, True, 1.0, "10", None, _PYPI_FETCH_MAX + 1):
            with self.subTest(limit=limit):
                self.assert_failure(fetch, FILE_URL, limit, "limit")
        self.assertEqual(opener.requests, [])

    def test_default_opener_has_no_proxy_and_refuses_redirects(self):
        from unittest.mock import patch
        from urllib.request import HTTPRedirectHandler, ProxyHandler, build_opener

        from rs9.readers import NoRedirect, _PypiBoundedFetch
        with patch("urllib.request.getproxies", return_value={"https": "http://proxy.invalid:1"}):
            ambient_handlers = build_opener().handlers
            handlers = _PypiBoundedFetch()._opener.handlers
        self.assertTrue(any(isinstance(h, ProxyHandler) and h.proxies for h in ambient_handlers))
        # urllib may omit a handler with no proxy methods; absence is also proxy-free.
        self.assertFalse(any(isinstance(h, ProxyHandler) and h.proxies for h in handlers))
        redirects = [h for h in handlers if isinstance(h, HTTPRedirectHandler)]
        self.assertTrue(redirects)
        self.assertTrue(all(isinstance(h, NoRedirect) for h in redirects))

    def test_redirect_handler_closes_the_redirect_response(self):
        import io
        from http.client import HTTPMessage
        from urllib.request import Request

        from rs9.readers import _ClosingNoRedirect
        body = io.BytesIO(MARKER.encode())
        with self.assertRaises(ContractError) as caught:
            _ClosingNoRedirect().redirect_request(Request(JSON_URL), body, 302, "Found", HTTPMessage(),
                                                  "https://evil.example/")
        self.assertEqual(caught.exception.code, "READER_REDIRECT")
        self.assertTrue(body.closed)

    def test_tls_tokens_match_reader_tls_classes(self):
        from rs9.readers import TLS_CLASSES
        from rs9.tf_pypi_remote import _FETCH_TOKENS, _TLS_TOKENS
        self.assertEqual(_TLS_TOKENS, {"tls-" + name for name in TLS_CLASSES})
        self.assertTrue(_TLS_TOKENS <= _FETCH_TOKENS)

    def test_fetch_does_not_retain_state_between_instances(self):
        from rs9.readers import _PypiBoundedFetch
        first, second = _PypiBoundedFetch(opener=FakePypiOpener(AssertionError())), _PypiBoundedFetch(
            opener=FakePypiOpener(AssertionError()))
        self.assert_failure(first, "http://pypi.org/x", 10, "url-authority")
        self.assertEqual(second.failures, [])


class ApprovedStateOverBoundedFetchTests(unittest.TestCase):
    """approved_state driven through the real adapter with a scripted opener (no network)."""

    project = "theme-forge-nebular-fusion"
    version = "0.6.1"
    name = "theme_forge_nebular_fusion-0.6.1-py3-none-macosx_11_0_arm64.whl"

    def run_state(self, body, approved_size, *, with_length=True, file_outcome=None):
        import hashlib

        from rs9.readers import _PypiBoundedFetch
        from rs9.tf_pypi_archive import canonical
        from rs9.tf_pypi_remote import approved_state
        base = "https://pypi.org/pypi/" + self.project
        file_url = "https://files.pythonhosted.org/packages/0a/1b/" + self.name
        digest = hashlib.sha256(body).hexdigest()
        docs = {
            base + "/json": canonical({"info": {"name": self.project, "version": self.version},
                                       "releases": {self.version: [{}]}}),
            base + "/" + self.version + "/json": canonical({
                "info": {"name": self.project, "version": self.version},
                "urls": [{"filename": self.name, "size": approved_size, "digests": {"sha256": digest},
                          "yanked": False, "url": file_url}]}),
        }

        def respond(url, data):
            headers = [("Content-Length", str(len(data)))] if with_length else []
            return lambda: FakePypiResponse([data], url=url, headers=headers)
        outcomes = {url: respond(url, data) for url, data in docs.items()}
        outcomes[file_url] = file_outcome if file_outcome is not None else respond(file_url, body)
        fetch = _PypiBoundedFetch(opener=FakePypiOpener(outcomes))
        approved = {self.name: (approved_size, digest)}
        return approved_state(self.project, self.version, approved, fetch), fetch

    def test_file_above_json_cap_is_bounded_by_its_approved_size(self):
        size = 32 * 1024 ** 2 + 17
        body = bytes(size)
        for with_length in (True, False):
            with self.subTest(with_length=with_length):
                result, fetch = self.run_state(body, size, with_length=with_length)
                self.assertEqual((result["state"], result["code"]), ("published-exact", "pypi-distribution-exact"))
                self.assertEqual(result["bodies"][self.name], body)
                self.assertEqual(fetch.failures, [])
                result, fetch = self.run_state(body + b"\0", size, with_length=with_length)
                self.assertEqual((result["state"], result["code"]), ("unknown", "pypi-limit"))
                self.assertNotIn("bodies", result)
                self.assertEqual(fetch.failures, ["limit"])

    def test_adapter_failures_reach_the_observer_as_unknown(self):
        import io
        import ssl
        from http.client import HTTPMessage
        from urllib.error import HTTPError, URLError
        cert = ssl.SSLCertVerificationError(1, MARKER)
        cert.verify_code = 20
        file_url = "https://files.pythonhosted.org/packages/0a/1b/" + self.name
        cases = (
            (URLError(cert), "pypi-tls-certificate-verify-failed", "tls-certificate-verify-failed"),
            (HTTPError(file_url, 404, MARKER, HTTPMessage(), io.BytesIO()), "pypi-transport-unknown", "http-404"),
        )
        for outcome, code, token in cases:
            with self.subTest(code=code):
                result, fetch = self.run_state(b"payload", 7, file_outcome=outcome)
                self.assertEqual((result["state"], result["code"]), ("unknown", code))
                self.assertEqual(fetch.failures, [token])
                self.assertNotIn(MARKER, repr(result))


if __name__ == "__main__":
    unittest.main()
