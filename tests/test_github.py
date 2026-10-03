import io
import unittest
from urllib.request import Request

from rs9.errors import ContractError
from rs9.github import PublicClient, Redirects, validate_https


class Response(io.BytesIO):
    status = 200

    def geturl(self):
        return "https://api.github.com/example"


class Opener:
    def __init__(self, data):
        self.data = data

    def open(self, request, timeout):
        return Response(self.data)


class GithubTests(unittest.TestCase):
    def test_bounded_download_and_size(self):
        client = PublicClient(Opener(b"12345"))
        self.assertEqual(client.get("https://api.github.com/example", limit=5, expected_size=5), b"12345")
        for kwargs in ({"limit": 4}, {"expected_size": 6}):
            with self.assertRaises(ContractError):
                client.get("https://api.github.com/example", **kwargs)

    def test_hosts_credentials_ports_and_redirect_limits(self):
        for url in ("http://api.github.com/x", "https://evil.example/x", "https://user:pass@github.com/x", "https://github.com:80/x", "https://github.com/a\nb"):
            with self.assertRaises(ContractError):
                validate_https(url)
        req = Request("https://api.github.com/example")
        req.rs9_no_redirect = True
        with self.assertRaises(ContractError):
            Redirects().redirect_request(req, None, 302, "", {}, "https://github.com/new")
        req.rs9_no_redirect = False
        req.rs9_hops = 5
        with self.assertRaises(ContractError):
            Redirects().redirect_request(req, None, 302, "", {}, "https://github.com/new")

    def test_repository_final_url_and_invalid_json(self):
        client = PublicClient(Opener(b"not JSON"))
        with self.assertRaises(ContractError):
            client.get("https://api.github.com/different", no_redirect=True)
        with self.assertRaises(ContractError):
            client.json("https://api.github.com/example")
