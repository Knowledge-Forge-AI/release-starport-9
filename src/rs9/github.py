"""Bounded public HTTPS collection, without ambient credentials or proxies."""
import hashlib
import http.client
import json
import re
import socket
import ssl
import time
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import BaseHandler, HTTPRedirectHandler, ProxyHandler, Request, build_opener

from rs9.errors import ContractError

HOSTS = frozenset({"api.github.com", "github.com", "objects.githubusercontent.com",
                   "release-assets.githubusercontent.com", "raw.githubusercontent.com", "registry.npmjs.org",
                   "releases.nixos.org"})
# Caller intent and origin are both checked. Callers cannot supply headers.
REQUEST_CLASSES = {
    "github-api": ("application/vnd.github+json", {"api.github.com"}, {"api.github.com"}),
    "github-asset": ("*/*", {"github.com"},
                     {"github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"}),
    "github-source": ("*/*", {"raw.githubusercontent.com"}, {"raw.githubusercontent.com"}),
    "npm-packument": ("application/json", {"registry.npmjs.org"}, set()),
    "npm-tarball": ("*/*", {"registry.npmjs.org"}, {"registry.npmjs.org"}),
    "nix-installer": ("*/*", {"releases.nixos.org"}, {"releases.nixos.org"}),
}


def validate_https(url):
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except (ValueError, TypeError, AttributeError):
        raise ContractError("INVALID_URL", "Invalid evidence URL") from None
    if (parsed.scheme != "https" or parsed.hostname not in HOSTS or port not in (None, 443)
            or parsed.username or parsed.password or parsed.fragment
            or any(c.isspace() or ord(c) < 32 or ord(c) == 127 or c == "\\" for c in url)):
        raise ContractError("INVALID_URL", "Evidence URL outside public HTTPS authority")


def _policy(operation):
    if not isinstance(operation, str) or operation not in REQUEST_CLASSES:
        raise ContractError("REQUEST_CLASS", "Closed public request class required")
    return REQUEST_CLASSES[operation]


def _headers(operation):
    headers = {"User-Agent": "RS9-shadow-v1alpha1", "Accept": _policy(operation)[0]}
    for name, value in headers.items():
        if (not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name)
                or not isinstance(value, str) or not value
                or any(ord(c) < 32 or ord(c) >= 127 for c in value)):
            raise ContractError("REQUEST_HEADER", "Invalid public request header")
    return headers


def _origin(url, operation, *, redirected=False):
    validate_https(url)
    host = urlsplit(url).hostname
    if host not in _policy(operation)[2 if redirected else 1]:
        raise ContractError("REDIRECT_REJECTED" if redirected else "INVALID_URL",
                            "Request class origin policy rejected", details={"reason": "redirect-host" if redirected else "request-host"})
    return host


class Redirects(HTTPRedirectHandler):
    def http_error_302(self, req, fp, code, msg, headers):
        try:
            return super().http_error_302(req, fp, code, msg, headers)
        except (ContractError, URLError):
            fp.close()
            raise

    http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        trace = req.rs9_trace
        hops = trace["redirect_hops"] + 1
        if hops > 5 or req.rs9_no_redirect:
            raise ContractError("REDIRECT_REJECTED", "Redirect limit or repository identity policy",
                                details={"reason": "redirect-limit"})
        host = _origin(newurl, req.rs9_operation, redirected=True)
        trace.update(host=host, redirect_hops=hops)
        result = super().redirect_request(req, fp, code, msg, headers, newurl)
        if result is not None:
            result.rs9_operation = req.rs9_operation
            result.rs9_trace = trace
            result.rs9_no_redirect = req.rs9_no_redirect
        return result


class ScopedGitHubAuthorization(BaseHandler):
    """Unredirected GET identity confined to the GitHub API request class."""
    def __init__(self, value):
        if not isinstance(value, str) or not value or any(ord(c) <= 32 or ord(c) >= 127 for c in value):
            raise ContractError("GITHUB_IDENTITY", "Invalid read-only workflow identity")
        self._value = value

    def https_request(self, request):
        if (getattr(request, "rs9_operation", None) == "github-api"
                and urlsplit(request.full_url).hostname == "api.github.com"
                and request.get_method() == "GET"):
            request.add_unredirected_header("Authorization", "Bearer " + self._value)
        return request


def public_opener(api_token=None, *extra_handlers):
    handlers = [ProxyHandler({}), Redirects(), *extra_handlers]
    if api_token is not None:
        handlers.append(ScopedGitHubAuthorization(api_token))
    return build_opener(*handlers)


def _transport_class(error):
    reason = error.reason if isinstance(error, URLError) else error
    if isinstance(reason, (TimeoutError, socket.timeout)):
        return "timeout"
    if isinstance(reason, ssl.SSLError):
        return "tls"
    if isinstance(reason, socket.gaierror):
        return "dns"
    if isinstance(reason, ConnectionError):
        return "connection"
    if isinstance(reason, http.client.HTTPException):
        return "protocol"
    return "transport"


def _receipt_url(value):
    parsed = urlsplit(value)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


def _read_response(response, limit, expected_size, started):
    chunks, length = [], 0
    while True:
        if time.monotonic() - started > 120:
            raise ContractError("FETCH_LIMIT", "Evidence transfer deadline exceeded", details={"reason": "deadline"})
        chunk = response.read(min(1024 * 1024, limit - length + 1))
        if not chunk:
            break
        length += len(chunk)
        if length > limit:
            raise ContractError("FETCH_LIMIT", "Evidence response exceeds size limit", details={"reason": "size-limit"})
        chunks.append(chunk)
    if expected_size is not None and length != expected_size:
        raise ContractError("SIZE_MISMATCH", "Downloaded size differs from release metadata")
    return b"".join(chunks)


class PublicClient:
    def __init__(self, opener=None, *, api_token=None):
        self.opener = opener or public_opener(api_token)
        self.receipts = []

    def get(self, url, *, request_class, limit=16 * 1024 * 1024, expected_size=None, no_redirect=False):
        trace = {"operation": request_class, "redirect_hops": 0}
        try:
            trace["host"] = _origin(url, request_class)
            request = Request(url, headers=_headers(request_class))
            request.rs9_operation = request_class
            request.rs9_trace = trace
            request.rs9_no_redirect = no_redirect
            started = time.monotonic()
            with self.opener.open(request, timeout=20) as response:
                final = response.geturl()
                # Injected openers cannot bypass final-origin or redirect policy.
                host = _origin(final, request_class, redirected=final != url or trace["redirect_hops"] > 0)
                trace["host"] = host
                if no_redirect and final != url:
                    raise ContractError("REDIRECT_REJECTED", "Repository identity redirected", details={"reason": "redirect-limit"})
                if response.status != 200:
                    raise ContractError("FETCH_FAILED", "Evidence request did not return HTTP 200",
                                        details={"http_status": response.status, "reason": "http-status"})
                data = _read_response(response, limit, expected_size, started)
                self.receipts.append({"url": _receipt_url(url), "final_url": _receipt_url(final), "status": 200,
                                      "operation": request_class, "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                                      "collected_at": datetime.now(timezone.utc).isoformat()})
                return data
        except ContractError as error:
            raise error.with_details(**trace) from None
        except HTTPError as error:
            status = error.code
            error.close()  # Never read or retain an arbitrary error body.
            raise ContractError("FETCH_FAILED", "Public evidence HTTP failure",
                                details={**trace, "http_status": status, "reason": "http-status"}) from None
        except (URLError, OSError, http.client.HTTPException) as error:
            raise ContractError("FETCH_FAILED", "Public evidence transport unavailable",
                                details={**trace, "transport_error": _transport_class(error), "reason": "transport"}) from None

    def json(self, url, *, request_class, **kwargs):
        try:
            return json.loads(self.get(url, request_class=request_class, **kwargs))
        except (ValueError, UnicodeError):
            raise ContractError("INVALID_EVIDENCE", "Evidence response is not JSON",
                                details={"operation": request_class, "host": urlsplit(url).hostname}) from None
