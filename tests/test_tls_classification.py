"""Tests for typed-first TLS error classification and MemoryBIO handshakes.

Exercises genuine MemoryBIO SSL reason strings (wrapped, unwrapped, cycles),
certificate and hostname failures via openssl CLI, bounded numeric verify_code,
DNS/non-TLS/timeout/redirect distinctions, exact authenticated 404, and object comparison.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError

from rs9.errors import ContractError
from rs9.readers import (
    TLS_CLASSES,
    classify_tls_error,
    extract_tls_verify_code,
    read_pages,
    unwrap_transport_error,
)


def _generate_openssl_cert(directory: Path, common_name: str = "rs9-test.invalid") -> tuple[Path, Path]:
    """Generate self-signed certificate and private key using existing openssl CLI."""
    key_path = directory / "test-key.pem"
    cert_path = directory / "test-cert.pem"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key_path), "-out", str(cert_path), "-days", "1",
            "-subj", f"/CN={common_name}",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return cert_path, key_path


def _run_memorybio_handshake(
    cert_path: Path,
    key_path: Path,
    *,
    server_hostname: str = "rs9-test.invalid",
    trust_cert: bool = False,
) -> ssl.SSLError:
    """Run genuine in-memory TLS handshake using MemoryBIO and return any raised SSLError."""
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(cert_path, key_path)

    client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if trust_cert:
        client_ctx.load_verify_locations(cert_path)

    ci, co, si, so = (ssl.MemoryBIO() for _ in range(4))
    client = client_ctx.wrap_bio(ci, co, server_side=False, server_hostname=server_hostname)
    server = server_ctx.wrap_bio(si, so, server_side=True)

    for _ in range(20):
        try:
            client.do_handshake()
        except (ssl.SSLCertVerificationError, getattr(ssl, "CertificateError", ())) as exc:
            return exc
        except ssl.SSLWantReadError:
            pass

        outgoing = co.read()
        if outgoing:
            si.write(outgoing)

        try:
            server.do_handshake()
        except (ssl.SSLCertVerificationError, getattr(ssl, "CertificateError", ())) as exc:
            return exc
        except ssl.SSLWantReadError:
            pass

        outgoing = so.read()
        if outgoing:
            ci.write(outgoing)

    raise AssertionError("Expected MemoryBIO handshake failure")


class TLSClassificationTests(unittest.TestCase):
    def test_genuine_protocol_error_has_string_reason(self):
        incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        context = ssl.create_default_context()
        client = context.wrap_bio(incoming, outgoing, server_hostname="rs9-test.invalid")
        incoming.write(b"HTTP/1.1 200 OK\r\n\r\n")
        with self.assertRaises(ssl.SSLError) as caught:
            client.do_handshake()
        self.assertIsInstance(caught.exception.reason, str)
        self.assertEqual(classify_tls_error(caught.exception), "protocol-error")
        self.assertEqual(classify_tls_error(URLError(caught.exception)), "protocol-error")

    def test_only_transport_wrappers_unwrap_and_codes_are_numeric(self):
        error = RuntimeError("not-a-transport-wrapper")
        error.reason = ssl.SSLCertVerificationError("certificate failure")
        self.assertEqual(classify_tls_error(error), "transport-error")
        for value in (True, -1, 1001, "18"):
            error = ssl.SSLCertVerificationError("certificate failure")
            error.verify_code = value
            self.assertIsNone(extract_tls_verify_code(error))

    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory(prefix="rs9-tls-test-")
        cls.dir_path = Path(cls.temp_dir.name)
        cls.cert_path, cls.key_path = _generate_openssl_cert(cls.dir_path, "rs9-test.invalid")

    @classmethod
    def tearDownClass(cls):
        cls.temp_dir.cleanup()

    def test_genuine_memorybio_ssl_reason_string_unwrapped(self):
        """Native SSLCertVerificationError has string .reason and classifies correctly unwrapped."""
        exc = _run_memorybio_handshake(self.cert_path, self.key_path, trust_cert=False)
        self.assertIsInstance(exc, ssl.SSLCertVerificationError)
        self.assertIsInstance(exc.reason, str)
        self.assertEqual(exc.reason, "CERTIFICATE_VERIFY_FAILED")
        self.assertEqual(exc.verify_code, 18)

        token = classify_tls_error(exc)
        self.assertEqual(token, "certificate-verify-failed")
        self.assertIn(token, TLS_CLASSES)

        code = extract_tls_verify_code(exc)
        self.assertEqual(code, 18)

    def test_genuine_memorybio_ssl_reason_string_wrapped_and_causes(self):
        """Native SSLCertVerificationError inside URLError or explicit causes classifies correctly."""
        exc = _run_memorybio_handshake(self.cert_path, self.key_path, trust_cert=False)

        # Single URLError wrap
        wrapped1 = URLError(exc)
        self.assertEqual(classify_tls_error(wrapped1), "certificate-verify-failed")
        self.assertEqual(extract_tls_verify_code(wrapped1), 18)

        # Double URLError wrap
        wrapped2 = URLError(wrapped1)
        self.assertEqual(classify_tls_error(wrapped2), "certificate-verify-failed")
        self.assertEqual(extract_tls_verify_code(wrapped2), 18)

        # Explicit cause: raise E from exc
        try:
            raise RuntimeError("Transport wrapper") from exc
        except RuntimeError as caught:
            self.assertEqual(classify_tls_error(caught), "certificate-verify-failed")
            self.assertEqual(extract_tls_verify_code(caught), 18)

    def test_genuine_memorybio_hostname_failure(self):
        """Trusted certificate with hostname mismatch produces typed certificate error."""
        exc = _run_memorybio_handshake(
            self.cert_path, self.key_path,
            server_hostname="mismatched.rs9.invalid",
            trust_cert=True,
        )
        self.assertIsInstance(exc, (ssl.SSLCertVerificationError, getattr(ssl, "CertificateError", ())))
        token = classify_tls_error(exc)
        self.assertEqual(token, "certificate-verify-failed")
        code = extract_tls_verify_code(exc)
        self.assertIsInstance(code, int)

    def test_unwrapping_cycle_detection_and_depth_bound(self):
        """Unwrapping handles circular references and chains beyond max depth safely."""
        # Direct cycle: e1 -> e2 -> e1
        e1 = URLError("first")
        e2 = URLError("second")
        e1.reason = e2
        e2.reason = e1

        unwrapped = unwrap_transport_error(e1, max_depth=4)
        self.assertIn(unwrapped, (e1, e2))
        token = classify_tls_error(e1)
        self.assertEqual(token, "transport-error")

        # Self-referential cause: e -> e
        e_self = RuntimeError("self")
        e_self.__cause__ = e_self
        self.assertEqual(unwrap_transport_error(e_self), e_self)

        # Chain beyond depth 4 halts at bound
        chain = URLError("bottom")
        for i in range(10):
            chain = URLError(chain)
        halted = unwrap_transport_error(chain, max_depth=4)
        self.assertIsInstance(halted, URLError)

    def test_tls_classes_enumeration_and_types(self):
        """All bounded TLS exception types map to valid TLS_CLASSES tokens."""
        cases = [
            (getattr(ssl, "SSLCertVerificationError", ssl.SSLError)("cert error"), "certificate-verify-failed"),
            (getattr(ssl, "CertificateError", Exception)("hostname mismatch"), "certificate-verify-failed"),
            (getattr(ssl, "SSLEOFError", ssl.SSLError)("eof in tls"), "unexpected-eof"),
            (getattr(ssl, "SSLZeroReturnError", ssl.SSLError)("protocol error"), "protocol-error"),
            (getattr(ssl, "SSLSyscallError", ssl.SSLError)("syscall io error"), "transport-error"),
            (getattr(ssl, "SSLWantReadError", ssl.SSLError)("want read"), "transport-error"),
            (getattr(ssl, "SSLWantWriteError", ssl.SSLError)("want write"), "transport-error"),
            (ssl.SSLError("SSL handshake failure: unsupported protocol"), "handshake-failure"),
            (ssl.SSLError("certificate verify failed: self-signed"), "certificate-verify-failed"),
        ]
        for exc, expected in cases:
            with self.subTest(exc=type(exc).__name__, expected=expected):
                token = classify_tls_error(exc)
                self.assertEqual(token, expected)
                self.assertIn(token, TLS_CLASSES)

    def test_read_pages_genuine_memorybio_error_preserves_tokens_and_code(self):
        """read_pages records bounded TLS tokens and numeric verify_code on genuine failure."""
        exc = _run_memorybio_handshake(self.cert_path, self.key_path, trust_cert=False)
        dest = {"id": "pages", "adapter": "pages", "mode": "direct"}
        subj = {"package": "rs9-pages", "version": "1", "revision": None}

        # Test both direct SSLCertVerificationError and URLError-wrapped
        for side_effect in (exc, URLError(exc)):
            with self.subTest(wrapped=isinstance(side_effect, URLError)), patch("rs9.readers._get", side_effect=side_effect):
                obs = read_pages(dest, subj, path="CNAME")
                self.assertEqual(obs["state"], "unknown")
                self.assertEqual(obs["readback"]["presence"], "unknown")
                self.assertEqual(obs["readback"]["transport"], "unknown")

                diag_codes = [d["code"] for d in obs["diagnostics"]]
                self.assertIn("pages-tls-error", diag_codes)
                self.assertIn("pages-tls-certificate-verify-failed", diag_codes)
                self.assertIn("pages-tls-verify-code", diag_codes)

                verify_msg = next(d["message"] for d in obs["diagnostics"] if d["code"] == "pages-tls-verify-code")
                self.assertIn("18", verify_msg)

    def test_dns_and_timeout_distinctions(self):
        """DNS failure and timeout are distinguished in diagnostics without arbitrary text."""
        dest = {"id": "pages", "adapter": "pages", "mode": "direct"}
        subj = {"package": "rs9-pages", "version": "1", "revision": None}

        # DNS
        dns_err = URLError(socket.gaierror(-2, "Name or service not known"))
        with patch("rs9.readers._get", side_effect=dns_err):
            obs = read_pages(dest, subj, path="CNAME")
            self.assertEqual(obs["state"], "unknown")
            diag_codes = [d["code"] for d in obs["diagnostics"]]
            self.assertIn("pages-dns-unknown", diag_codes)
            self.assertNotIn("pages-tls-error", diag_codes)

        # Timeout
        timeout_err = URLError(TimeoutError("Connection timed out"))
        with patch("rs9.readers._get", side_effect=timeout_err):
            obs = read_pages(dest, subj, path="CNAME")
            self.assertEqual(obs["state"], "unknown")
            diag_codes = [d["code"] for d in obs["diagnostics"]]
            self.assertIn("pages-timeout", diag_codes)

    def test_redirect_exact404_and_object_comparison(self):
        """Redirect stays unknown, exact 404 yields absent, matching content yields exact."""
        dest = {"id": "pages", "adapter": "pages", "mode": "direct"}
        subj = {"package": "rs9-pages", "version": "1", "revision": None}

        # Redirect stays unknown
        with patch("rs9.readers._get", side_effect=ContractError("READER_REDIRECT", "Redirect rejected")):
            obs = read_pages(dest, subj, path="CNAME")
            self.assertEqual(obs["state"], "unknown")
            self.assertNotEqual(obs["readback"]["presence"], "absent")

        # Exact authenticated 404 yields absent
        url = "https://rs9.knowledge-forge.ai/CNAME"
        with patch("rs9.readers._get", side_effect=HTTPError(url, 404, "Not Found", {}, None)):
            obs = read_pages(dest, subj, path="CNAME")
            self.assertEqual(obs["state"], "absent")
            self.assertEqual(obs["readback"]["presence"], "absent")

        # 200 comparison match yields exact
        data = b"rs9.knowledge-forge.ai\n"
        data_sha = hashlib.sha256(data).hexdigest()
        with patch("rs9.readers._get", return_value=data):
            obs_match = read_pages(dest, subj, path="CNAME", desired_identity=data_sha, expected_sha256=data_sha)
            self.assertEqual(obs_match["state"], "exact")

            obs_conflict = read_pages(dest, subj, path="CNAME", desired_identity=data_sha, expected_sha256="0" * 64)
            self.assertEqual(obs_conflict["state"], "conflict")


if __name__ == "__main__":
    unittest.main()
