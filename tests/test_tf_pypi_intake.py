"""Pinned public GET intake with bounded fake HTTP; no provider calls."""
import io
from urllib.error import HTTPError, URLError
import unittest

from rs9.tf_pypi_archive import AdmissionError
from rs9.tf_pypi_intake import asset_url, download
from tests.tf_pypi_fixtures import fixture


class Response(io.BytesIO):
    status = 200

    def __init__(self, url, body):
        super().__init__(body)
        self.url = url

    def geturl(self):
        return self.url


class Opener:
    def __init__(self, responses):
        self.responses, self.calls = responses, []

    def open(self, request, timeout):
        self.calls.append(request)
        value = self.responses.pop(0)
        if isinstance(value, BaseException):
            raise value
        return value


class IntakeTests(unittest.TestCase):
    def test_only_exact_authenticated_asset_accepted(self):
        pin, data = fixture()
        url = asset_url(pin)
        opener = Opener([Response(url, data)])
        self.assertEqual(download(pin, opener=opener), data)
        self.assertNotIn("Authorization", opener.calls[0].headers)

    def test_github_asset_redirect_then_hash_validation(self):
        pin, data = fixture()
        url, target = asset_url(pin), "https://release-assets.githubusercontent.com/github-production-release-asset/x?sig=fixture"
        opener = Opener([HTTPError(url, 302, "redirect", {"Location": target}, io.BytesIO()), Response(target, data)])
        self.assertEqual(download(pin, opener=opener), data)

    def test_absent_unknown_untrusted_redirect_size_and_hash(self):
        pin, data = fixture()
        url = asset_url(pin)
        cases = [(HTTPError(url, 404, "absent", {}, io.BytesIO()), "ASSET_ABSENT"),
                 (HTTPError(url, 503, "down", {}, io.BytesIO()), "REMOTE_UNKNOWN"),
                 (URLError("fixture DNS failure"), "REMOTE_UNKNOWN"),
                 (HTTPError(url, 302, "redirect", {"Location": "https://evil.example/payload"}, io.BytesIO()), "REDIRECT"),
                 (Response(url, data + b"x"), "SIZE"),
                 (Response(url, data[:-1] + bytes([data[-1] ^ 1])), "HASH")]
        for value, code in cases:
            with self.subTest(code=code), self.assertRaises(AdmissionError) as caught:
                download(pin, opener=Opener([value]))
            self.assertEqual(caught.exception.code, "TF_PYPI_" + code)

    def test_redirect_loop_is_bounded(self):
        pin, _ = fixture()
        url = asset_url(pin)
        opener = Opener([HTTPError(url, 302, "loop", {"Location": url}, io.BytesIO()) for _ in range(4)])
        with self.assertRaises(AdmissionError):
            download(pin, opener=opener)
        self.assertEqual(len(opener.calls), 4)
