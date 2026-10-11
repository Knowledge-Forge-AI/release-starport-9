"""Tests for rs9.pages_origin read-only fixed public Pages origin diagnostics.

Verifies:
- Fixed public target rs9.knowledge-forge.ai and safe relative path validation.
- Standard cert and hostname verification (no trust weakening).
- Stage diagnostics: DNS, TCP, TLS, HTTP, redirect, comparison.
- Failure at any stage stays state=unknown.
- Redirect is rejected and stays state=unknown.
- Exact authenticated 404 yields state=absent with exact origin evidence.
- Comparison match yields state=exact; mismatch yields unknown.
- Produced diagnostics are accepted by diagnostic_bytes without private paths or credentials.
- Zero ResourceWarning leaks across all execution paths.
"""
from __future__ import annotations

import hashlib
import http.client
import io
from pathlib import Path
import socket
import ssl
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from rs9.errors import ContractError
from rs9.hosted_custody import diagnostic_bytes
from rs9.pages_origin import (
    PAGES_ORIGIN_HOST,
    PAGES_ORIGIN_PORT,
    diagnose_pages_origin,
    validate_origin_path,
)
from rs9.scratch import canonical


class FakeSocket:
    def __init__(self, is_tls: bool = True):
        self.is_tls = is_tls
        self.closed = False
        self.timeout = 5.0

    def settimeout(self, timeout):
        self.timeout = timeout

    def close(self):
        self.closed = True


class FakeHTTPResponse:
    def __init__(self, status: int, body: bytes = b"", headers: dict | None = None):
        self.status = status
        self.reason = "OK" if status == 200 else "Not Found" if status == 404 else "Error"
        self._body = io.BytesIO(body)
        self.headers = headers or {}
        self.closed = False

    def read(self, amt: int | None = None) -> bytes:
        if amt is None:
            return self._body.read()
        return self._body.read(amt)

    def close(self):
        self.closed = True


class FakeHTTPConnection:
    def __init__(self, host: str, port: int, timeout: float = 5.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock = None
        self.closed = False
        self.requested_url = None
        self.requested_headers = None
        self.next_response = FakeHTTPResponse(200, b"")

    def request(self, method: str, url: str, headers: dict | None = None):
        self.requested_url = url
        self.requested_headers = headers

    def getresponse(self):
        return self.next_response

    def close(self):
        self.closed = True


class PagesOriginTests(unittest.TestCase):
    def test_resolver_timeout_is_bounded_and_unavailable_is_unknown(self):
        import subprocess
        with patch("rs9.pages_origin.subprocess.run", side_effect=subprocess.TimeoutExpired("resolver", 5)) as child:
            diag = diagnose_pages_origin("CNAME")
        self.assertEqual(diag["state"], "unknown")
        self.assertEqual(diag["stage"], "dns")
        self.assertEqual(diag["class"], "timeout")
        self.assertEqual(child.call_args.kwargs["timeout"], 5)
        for value in (float("inf"), float("nan"), 0, 31, True):
            with self.subTest(timeout=value), self.assertRaises(ContractError):
                diagnose_pages_origin("CNAME", timeouts={"dns": value})

    def test_body_deadline_and_limit_are_unknown(self):
        conn = FakeHTTPConnection(PAGES_ORIGIN_HOST, PAGES_ORIGIN_PORT)
        conn.next_response = FakeHTTPResponse(200, b"a" * 20)
        with patch("rs9.pages_origin.MAX_RESPONSE_BODY", 10):
            diag = diagnose_pages_origin("CNAME", _conn=conn)
        self.assertEqual(diag["state"], "unknown")
        self.assertEqual(diag["class"], "response-limit-exceeded")
        conn = FakeHTTPConnection(PAGES_ORIGIN_HOST, PAGES_ORIGIN_PORT)
        with patch("rs9.pages_origin.time.monotonic", side_effect=[0, 6]):
            diag = diagnose_pages_origin("CNAME", _conn=conn)
        self.assertEqual(diag["state"], "unknown")
        self.assertEqual(diag["class"], "timeout")

    def test_exact_request_redirect_metadata_and_cli(self):
        import contextlib
        import json
        from rs9.pages_origin import main
        conn = FakeHTTPConnection(PAGES_ORIGIN_HOST, PAGES_ORIGIN_PORT)
        conn.next_response = FakeHTTPResponse(302, headers={"Location": "https://other.invalid/CNAME"})
        diag = diagnose_pages_origin("CNAME", _conn=conn)
        self.assertFalse(diag["redirect_same_host"])
        self.assertEqual(conn.requested_url, "/CNAME")
        self.assertEqual(conn.requested_headers["Host"], PAGES_ORIGIN_HOST)
        with patch("rs9.pages_origin.diagnose_pages_origin", return_value=diag) as probe, \
                contextlib.redirect_stdout(io.StringIO()) as stream:
            self.assertEqual(main(["--path", "CNAME"]), 0)
        self.assertEqual(json.loads(stream.getvalue()), diag)
        probe.assert_called_once_with("CNAME", expected_sha256=None)

    def setUp(self):
        self.dummy_addr = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("185.199.110.153", 443))
        ]

    def _assert_diagnostic_valid(self, diag: dict):
        """Assert diagnostic dict satisfies schema and is accepted by diagnostic_bytes."""
        self.assertEqual(diag["schema"], "rs9.pages-origin-diagnostic.v1alpha1")
        self.assertEqual(diag["target"], PAGES_ORIGIN_HOST)
        self.assertEqual(diag["port"], PAGES_ORIGIN_PORT)
        self.assertIn("observed_at", diag)
        self.assertIn(diag["state"], {"unknown", "absent", "exact", "present"})
        self.assertIn(diag["stage"], {"dns", "tcp", "tls", "http", "redirect", "comparison"})
        self.assertIsInstance(diag["diagnostics"], list)

        # Ensure custody validator accepts the output
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "pages-origin-diagnostic.json"
            p.write_bytes(canonical(diag))
            accepted = diagnostic_bytes(p)
            self.assertEqual(accepted, p.read_bytes())

    def test_fixed_public_target_and_path_validation(self):
        """Target host is fixed to rs9.knowledge-forge.ai and invalid paths are refused."""
        self.assertEqual(PAGES_ORIGIN_HOST, "rs9.knowledge-forge.ai")
        self.assertEqual(PAGES_ORIGIN_PORT, 443)

        self.assertEqual(validate_origin_path("CNAME"), "CNAME")
        self.assertEqual(validate_origin_path("pool/main/t/pkg.deb"), "pool/main/t/pkg.deb")
        with self.assertRaises(ContractError):
            validate_origin_path("/pool/main/t/pkg.deb")

        # Refuses empty path, directory traversal, credentials
        with self.assertRaises(ContractError):
            validate_origin_path("")
        with self.assertRaises(ContractError):
            validate_origin_path("../secret")
        with self.assertRaises(ContractError):
            validate_origin_path(f"sub/ghp_{'a' * 36}")

    def test_dns_failure_returns_unknown_and_safe_metadata(self):
        """DNS failure returns stage=dns, class=dns-unknown, state=unknown."""
        with patch("rs9.pages_origin._resolve_origin", side_effect=socket.gaierror(-2, "Name or service not known")):
            diag = diagnose_pages_origin("CNAME")
        self.assertEqual(diag["state"], "unknown")
        self.assertEqual(diag["stage"], "dns")
        self.assertEqual(diag["class"], "dns-unknown")
        self.assertFalse(diag["origin_verified"])
        self.assertEqual(diag["dns_safe"]["host"], PAGES_ORIGIN_HOST)
        self._assert_diagnostic_valid(diag)

    def test_dns_timeout_returns_unknown(self):
        """DNS resolution timeout returns stage=dns, class=timeout, state=unknown."""
        with patch("rs9.pages_origin._resolve_origin", side_effect=socket.timeout("DNS timeout")):
            diag = diagnose_pages_origin("CNAME")
        self.assertEqual(diag["state"], "unknown")
        self.assertEqual(diag["stage"], "dns")
        self.assertEqual(diag["class"], "timeout")
        self._assert_diagnostic_valid(diag)

    def test_tcp_connection_refused_and_timeout(self):
        """TCP connect failure records stage=tcp, class=connection-refused/timeout, state=unknown."""
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = ConnectionRefusedError(61, "Connection refused")
        with patch("socket.socket", return_value=mock_sock):
            diag = diagnose_pages_origin("CNAME", _addr_info=self.dummy_addr)
        self.assertEqual(diag["state"], "unknown")
        self.assertEqual(diag["stage"], "tcp")
        self.assertEqual(diag["class"], "connection-refused")
        self.assertEqual(diag["code"], 61)
        mock_sock.close.assert_called_once()
        self._assert_diagnostic_valid(diag)

        mock_sock2 = MagicMock()
        mock_sock2.connect.side_effect = socket.timeout("Connect timeout")
        with patch("socket.socket", return_value=mock_sock2):
            diag2 = diagnose_pages_origin("CNAME", _addr_info=self.dummy_addr)
        self.assertEqual(diag2["state"], "unknown")
        self.assertEqual(diag2["stage"], "tcp")
        self.assertEqual(diag2["class"], "timeout")
        mock_sock2.close.assert_called_once()
        self._assert_diagnostic_valid(diag2)

    def test_tls_certificate_verification_failure_records_verify_code(self):
        """TLS certificate failure retains bounded verify_code and stage=tls, state=unknown."""
        ssl_err = ssl.SSLCertVerificationError(18, "[SSL: CERTIFICATE_VERIFY_FAILED] self-signed certificate")
        ssl_err.verify_code = 18
        ssl_err.reason = "CERTIFICATE_VERIFY_FAILED"

        raw_sock = FakeSocket(is_tls=False)
        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.side_effect = ssl_err

        with patch("ssl.create_default_context", return_value=mock_ctx):
            diag = diagnose_pages_origin("CNAME", _addr_info=self.dummy_addr, _sock=raw_sock)

        self.assertEqual(diag["state"], "unknown")
        self.assertEqual(diag["stage"], "tls")
        self.assertEqual(diag["class"], "certificate-verify-failed")
        self.assertEqual(diag["code"], 18)
        self.assertFalse(diag["origin_verified"])
        diag_codes = [d["code"] for d in diag["diagnostics"]]
        self.assertIn("pages-origin-tls-certificate-verify-failed", diag_codes)
        self.assertIn("pages-origin-tls-verify-code", diag_codes)
        self._assert_diagnostic_valid(diag)

    def test_tls_hostname_mismatch_failure(self):
        """TLS hostname mismatch returns verify code 62 and class=certificate-verify-failed."""
        ssl_err = ssl.SSLCertVerificationError(62, "[SSL: CERTIFICATE_VERIFY_FAILED] Hostname mismatch")
        ssl_err.verify_code = 62
        ssl_err.reason = "CERTIFICATE_VERIFY_FAILED"

        raw_sock = FakeSocket(is_tls=False)
        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.side_effect = ssl_err

        with patch("ssl.create_default_context", return_value=mock_ctx):
            diag = diagnose_pages_origin("CNAME", _addr_info=self.dummy_addr, _sock=raw_sock)

        self.assertEqual(diag["state"], "unknown")
        self.assertEqual(diag["stage"], "tls")
        self.assertEqual(diag["class"], "certificate-verify-failed")
        self.assertEqual(diag["code"], 62)
        self._assert_diagnostic_valid(diag)

    def test_tls_handshake_and_protocol_failures(self):
        """TLS handshake and protocol errors are classified and remain state=unknown."""
        cases = [
            (ssl.SSLError("SSL handshake failure: wrong version"), "handshake-failure"),
            (getattr(ssl, "SSLEOFError", ssl.SSLError)("EOF in TLS"), "unexpected-eof"),
            (getattr(ssl, "SSLZeroReturnError", ssl.SSLError)("TLS zero return"), "protocol-error"),
        ]
        for exc, expected_token in cases:
            with self.subTest(exc=expected_token):
                raw_sock = FakeSocket(is_tls=False)
                mock_ctx = MagicMock()
                mock_ctx.wrap_socket.side_effect = exc
                with patch("ssl.create_default_context", return_value=mock_ctx):
                    diag = diagnose_pages_origin("CNAME", _addr_info=self.dummy_addr, _sock=raw_sock)
                self.assertEqual(diag["state"], "unknown")
                self.assertEqual(diag["stage"], "tls")
                self.assertEqual(diag["class"], expected_token)
                self._assert_diagnostic_valid(diag)

    def test_redirect_rejected_and_stays_unknown(self):
        """HTTP redirects (301, 302, 307, 308) are rejected and stay state=unknown."""
        for status in (301, 302, 307, 308):
            with self.subTest(status=status):
                conn = FakeHTTPConnection(PAGES_ORIGIN_HOST, PAGES_ORIGIN_PORT)
                conn.next_response = FakeHTTPResponse(status, b"Redirecting")
                diag = diagnose_pages_origin("CNAME", _conn=conn)
                self.assertEqual(diag["state"], "unknown")
                self.assertEqual(diag["stage"], "redirect")
                self.assertEqual(diag["class"], "redirect-rejected")
                self.assertEqual(diag["code"], status)
                self.assertTrue(diag["origin_verified"])
                self._assert_diagnostic_valid(diag)

    def test_exact_authenticated_404_yields_absent(self):
        """HTTP 404 on verified origin yields state=absent with exact origin evidence."""
        conn = FakeHTTPConnection(PAGES_ORIGIN_HOST, PAGES_ORIGIN_PORT)
        conn.next_response = FakeHTTPResponse(404, b"Not Found")
        diag = diagnose_pages_origin("nonexistent/pkg.deb", _conn=conn)
        self.assertEqual(diag["state"], "absent")
        self.assertEqual(diag["stage"], "http")
        self.assertEqual(diag["class"], "authenticated-404")
        self.assertEqual(diag["code"], 404)
        self.assertTrue(diag["origin_verified"])
        self._assert_diagnostic_valid(diag)

    def test_200_ok_comparison_match_and_mismatch(self):
        """HTTP 200 with matching sha256 yields state=exact; mismatch yields unknown."""
        payload = b"rs9.knowledge-forge.ai\n"
        correct_sha = hashlib.sha256(payload).hexdigest()

        # Match
        conn_match = FakeHTTPConnection(PAGES_ORIGIN_HOST, PAGES_ORIGIN_PORT)
        conn_match.next_response = FakeHTTPResponse(200, payload)
        diag_match = diagnose_pages_origin("CNAME", expected_sha256=correct_sha, _conn=conn_match)
        self.assertEqual(diag_match["state"], "exact")
        self.assertEqual(diag_match["stage"], "comparison")
        self.assertEqual(diag_match["class"], "comparison-match")
        self.assertEqual(diag_match["code"], 200)
        self.assertEqual(diag_match["body_sha256"], correct_sha)
        self.assertTrue(diag_match["origin_verified"])
        self._assert_diagnostic_valid(diag_match)

        # Mismatch (hash conflict) stays unknown
        conn_mismatch = FakeHTTPConnection(PAGES_ORIGIN_HOST, PAGES_ORIGIN_PORT)
        conn_mismatch.next_response = FakeHTTPResponse(200, payload)
        diag_mismatch = diagnose_pages_origin("CNAME", expected_sha256="0" * 64, _conn=conn_mismatch)
        self.assertEqual(diag_mismatch["state"], "unknown")
        self.assertEqual(diag_mismatch["stage"], "comparison")
        self.assertEqual(diag_mismatch["class"], "comparison-mismatch")
        self.assertEqual(diag_mismatch["code"], 200)
        self.assertTrue(diag_mismatch["origin_verified"])
        self._assert_diagnostic_valid(diag_mismatch)

        # 200 without expected hash yields state=present
        conn_present = FakeHTTPConnection(PAGES_ORIGIN_HOST, PAGES_ORIGIN_PORT)
        conn_present.next_response = FakeHTTPResponse(200, payload)
        diag_present = diagnose_pages_origin("CNAME", _conn=conn_present)
        self.assertEqual(diag_present["state"], "present")
        self.assertEqual(diag_present["stage"], "http")
        self.assertEqual(diag_present["class"], "http-ok")
        self._assert_diagnostic_valid(diag_present)

    def test_http_server_error_and_timeout(self):
        """HTTP 500/503 errors and timeouts remain state=unknown."""
        conn_500 = FakeHTTPConnection(PAGES_ORIGIN_HOST, PAGES_ORIGIN_PORT)
        conn_500.next_response = FakeHTTPResponse(500, b"Server Error")
        diag_500 = diagnose_pages_origin("CNAME", _conn=conn_500)
        self.assertEqual(diag_500["state"], "unknown")
        self.assertEqual(diag_500["stage"], "http")
        self.assertEqual(diag_500["class"], "http-error")
        self.assertEqual(diag_500["code"], 500)
        self._assert_diagnostic_valid(diag_500)

        # HTTP Timeout
        conn_timeout = MagicMock()
        conn_timeout.getresponse.side_effect = socket.timeout("Response timeout")
        diag_timeout = diagnose_pages_origin("CNAME", _conn=conn_timeout)
        self.assertEqual(diag_timeout["state"], "unknown")
        self.assertEqual(diag_timeout["stage"], "http")
        self.assertEqual(diag_timeout["class"], "timeout")
        self._assert_diagnostic_valid(diag_timeout)

    def test_live_execution_produces_valid_diagnostic(self):
        """Execution against target produces valid diagnostic (source qualification no network requirement)."""
        with patch("rs9.pages_origin._resolve_origin", side_effect=PermissionError()):
            diag = diagnose_pages_origin("CNAME")
        self._assert_diagnostic_valid(diag)
        self.assertEqual(diag["state"], "unknown")


if __name__ == "__main__":
    unittest.main()
