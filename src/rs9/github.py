"""Bounded public HTTPS collection, without credentials or environment proxies."""
import json
import time
from datetime import datetime, timezone
from urllib.error import URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from rs9.errors import ContractError

HOSTS = frozenset({"api.github.com", "github.com", "objects.githubusercontent.com",
                   "release-assets.githubusercontent.com", "raw.githubusercontent.com", "registry.npmjs.org"})


def validate_https(url):
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError:
        raise ContractError("INVALID_URL", "Invalid evidence URL") from None
    if (parsed.scheme != "https" or parsed.hostname not in HOSTS or port not in (None, 443)
            or parsed.username or parsed.password or parsed.fragment
            or any(c.isspace() or ord(c) < 32 or c == "\\" for c in url)):
        raise ContractError("INVALID_URL", "Evidence URL outside public HTTPS authority")


class Redirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        validate_https(newurl)
        hops = getattr(req, "rs9_hops", 0) + 1
        if hops > 5 or getattr(req, "rs9_no_redirect", False):
            raise ContractError("REDIRECT_REJECTED", "Redirect limit or repository identity policy")
        result = super().redirect_request(req, fp, code, msg, headers, newurl)
        result.rs9_hops = hops
        return result


class PublicClient:
    def __init__(self, opener=None):
        self.opener = opener or build_opener(ProxyHandler({}), Redirects())
        self.receipts = []

    def get(self, url, *, limit=16 * 1024 * 1024, expected_size=None, no_redirect=False):
        validate_https(url)
        request = Request(url, headers={"User-Agent": "RS9-shadow-v1alpha1", "Accept": "application/vnd.github+json"})
        request.rs9_no_redirect = no_redirect
        started = time.monotonic()
        try:
            with self.opener.open(request, timeout=20) as response:
                validate_https(response.geturl())
                if no_redirect and response.geturl() != url:
                    raise ContractError("REDIRECT_REJECTED", "Repository identity redirected")
                if response.status != 200:
                    raise ContractError("FETCH_FAILED", "Evidence request did not return HTTP 200")
                chunks, length = [], 0
                while True:
                    if time.monotonic() - started > 120:
                        raise ContractError("FETCH_LIMIT", "Evidence transfer deadline exceeded")
                    chunk = response.read(min(1024 * 1024, limit - length + 1))
                    if not chunk:
                        break
                    length += len(chunk)
                    if length > limit:
                        raise ContractError("FETCH_LIMIT", "Evidence response exceeds size limit")
                    chunks.append(chunk)
                if expected_size is not None and length != expected_size:
                    raise ContractError("SIZE_MISMATCH", "Downloaded size differs from release metadata")
                data = b"".join(chunks)
                import hashlib
                def receipt_url(value):
                    parsed = urlsplit(value)
                    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
                self.receipts.append({"url": receipt_url(url), "final_url": receipt_url(response.geturl()), "status": 200,
                                      "size": length, "sha256": hashlib.sha256(data).hexdigest(),
                                      "collected_at": datetime.now(timezone.utc).isoformat()})
                return data
        except (URLError, OSError):
            raise ContractError("FETCH_FAILED", "Public evidence transport unavailable") from None

    def json(self, url, **kwargs):
        try:
            return json.loads(self.get(url, **kwargs))
        except (ValueError, UnicodeError):
            raise ContractError("INVALID_EVIDENCE", "Evidence response is not JSON") from None
