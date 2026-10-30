"""Optional anonymous public relay of ORIGINAL Actions ZIP bytes; GET only."""
from dataclasses import dataclass
import hashlib
import http.client
import os
from pathlib import Path
import re
import time
from types import MappingProxyType
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from rs9.current_generation import CURRENT_GENERATION, generation_paths
from rs9.errors import ContractError
from rs9.github import PublicClient
from rs9.scratch import physical_directory

RELAY_REPOSITORY = "Knowledge-Forge-AI/theme-forge-packages"
MODES = ("actions", "public-release-relay")
MAX_BYTES = 2 * 1024 ** 3
MAX_TOTAL_BYTES = 8 * 1024 ** 3
CHUNK = 64 * 1024
REDIRECT_HOSTS = frozenset({"github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"})
SIGNED_QUERY_KEYS = frozenset({"sp", "sv", "sr", "spr", "se", "rscd", "rsct", "skt", "ske", "sks", "skv", "skoid", "sktid", "sig", "jwt",
    "response-content-disposition", "response-content-type", "X-Amz-Algorithm", "X-Amz-Credential", "X-Amz-Date", "X-Amz-Expires",
    "X-Amz-SignedHeaders", "X-Amz-Signature", "X-Amz-Security-Token"})


def relay_tag(commit, run_id):
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit) or type(run_id) is not int or run_id <= 0:
        raise ContractError("PUBLIC_RELAY_IDENTITY", "Exact source commit and positive original run required")
    return "rs9-current-distribution-" + commit + "-run-" + str(run_id) + "-attempt-1"


def relay_asset_name(artifact):
    if (not isinstance(artifact, dict) or type(artifact.get("id")) is not int or artifact["id"] <= 0
            or not isinstance(artifact.get("name"), str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", artifact["name"])
            or artifact.get("expired") is not False
            or not isinstance(artifact.get("digest"), str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", artifact["digest"])
            or type(artifact.get("size_in_bytes")) is not int or not 0 < artifact["size_in_bytes"] <= MAX_BYTES):
        raise ContractError("PUBLIC_RELAY_ARTIFACT", "Unexpired original artifact identity, size and digest required")
    return "rs9-artifact-" + str(artifact["id"]) + "-" + artifact["name"] + ".zip"


def _validate_url(url, *, redirected=False):
    try:
        parsed = urlsplit(url)
        valid = (isinstance(url, str) and len(url) <= 16384 and parsed.scheme == "https"
                 and parsed.hostname in REDIRECT_HOSTS and parsed.port in (None, 443)
                 and not parsed.username and not parsed.password and not parsed.fragment
                 and not any(c.isspace() or ord(c) < 32 or ord(c) == 127 or c == "\\" for c in url))
        if not valid:
            raise ValueError
        if parsed.hostname == "github.com" and not parsed.path.startswith("/" + RELAY_REPOSITORY + "/releases/download/"):
            raise ValueError
        if parsed.query:
            pairs = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True)
            if (not redirected or parsed.hostname == "github.com" or not pairs
                    or any(key not in SIGNED_QUERY_KEYS for key, _ in pairs)
                    or len({key for key, _ in pairs}) != len(pairs)):
                raise ValueError
    except (ValueError, TypeError, AttributeError):
        raise ContractError("PUBLIC_RELAY_URL", "Relay HTTPS origin or redirect policy rejected") from None


class RelayRedirects(HTTPRedirectHandler):
    def http_error_302(self, req, fp, code, msg, headers):
        try:
            return super().http_error_302(req, fp, code, msg, headers)
        except (ContractError, URLError):
            fp.close()
            raise

    http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        hops = getattr(req, "rs9_relay_hops", 0) + 1
        if hops > 3:
            raise ContractError("PUBLIC_RELAY_REDIRECT", "Relay redirect bound exceeded")
        _validate_url(newurl, redirected=True)
        origin = getattr(req, "rs9_relay_origin", req.full_url)
        if urlsplit(newurl).hostname == "github.com" and newurl != origin:
            raise ContractError("PUBLIC_RELAY_URL", "Relay redirect changed its fixed release asset")
        result = super().redirect_request(req, fp, code, msg, headers, newurl)
        if result is not None:
            result.rs9_relay_hops = hops
            result.rs9_relay_origin = origin
        return result


@dataclass(frozen=True)
class RelayAsset:
    original_id: int
    name: str
    digest: str
    size: int
    url: str


@dataclass(frozen=True)
class PublicRelaySession:
    assets: object
    opener: object

    def download(self, artifact, destination, *, total_tracker=None, max_artifact_bytes=MAX_BYTES,
                 max_total_bytes=MAX_TOTAL_BYTES, download_timeout=120):
        name = relay_asset_name(artifact)
        asset = self.assets.get(artifact["id"])
        if asset is None or asset.name != name or asset.digest != artifact["digest"]:
            raise ContractError("PUBLIC_RELAY_SET", "Artifact differs from the prepared original set")
        destination = Path(destination)
        physical_directory(destination.parent)
        created = False
        try:
            _validate_url(asset.url)
            request = Request(asset.url, method="GET", headers={"User-Agent": "RS9-public-ZIP-relay-v1", "Accept": "application/octet-stream"})
            request.rs9_relay_hops = 0
            request.rs9_relay_origin = asset.url
            started = time.monotonic()
            with self.opener.open(request, timeout=20) as response:
                final_url = response.geturl()
                _validate_url(final_url, redirected=final_url != asset.url)
                if urlsplit(final_url).hostname == "github.com" and final_url != asset.url:
                    raise ContractError("PUBLIC_RELAY_URL", "Relay response changed its fixed release asset")
                if response.status != 200:
                    raise ContractError("PUBLIC_RELAY_HTTP", "Public relay GET did not return HTTP 200")
                length = response.headers.get("Content-Length")
                if length is not None and (not str(length).isdigit() or int(length) != asset.size):
                    raise ContractError("PUBLIC_RELAY_SIZE", "Relay response size differs from public asset metadata")
                fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                created = True
                digest, count = hashlib.sha256(), 0
                with os.fdopen(fd, "wb") as output:
                    while True:
                        if time.monotonic() - started > download_timeout:
                            raise ContractError("PUBLIC_RELAY_TIMEOUT", "Public relay transfer exceeded deadline")
                        chunk = response.read(CHUNK)
                        if time.monotonic() - started > download_timeout:
                            raise ContractError("PUBLIC_RELAY_TIMEOUT", "Public relay transfer exceeded deadline")
                        if not chunk:
                            break
                        count += len(chunk)
                        if total_tracker is not None:
                            total_tracker[0] += len(chunk)
                        if (count > max_artifact_bytes or count > asset.size or
                                (total_tracker is not None and total_tracker[0] > max_total_bytes)):
                            raise ContractError("PUBLIC_RELAY_LIMIT", "Public relay byte bound exceeded")
                        digest.update(chunk)
                        output.write(chunk)
                if count != asset.size or "sha256:" + digest.hexdigest() != artifact["digest"]:
                    raise ContractError("PUBLIC_RELAY_DIGEST", "Relay ZIP differs from ORIGINAL live Actions artifact digest")
                return count
        except BaseException as error:
            if created:
                destination.unlink(missing_ok=True)
            if isinstance(error, HTTPError):
                error.close()
                raise ContractError("PUBLIC_RELAY_HTTP", "Public relay HTTP GET failed") from None
            if isinstance(error, (URLError, OSError, http.client.HTTPException)):
                raise ContractError("PUBLIC_RELAY_HTTP", "Public relay GET unavailable") from None
            raise


class PublicReleaseTransport:
    """Explicit production transport; injected clients/openers are fixture seams only."""
    def __init__(self, *, metadata_client=None, opener=None):
        self.client = metadata_client if metadata_client is not None else PublicClient(api_token=None)
        self.opener = opener if opener is not None else build_opener(ProxyHandler({}), RelayRedirects())

    def prepare(self, artifacts, *, commit, run_id, generation):
        generation_paths(generation)
        if generation != CURRENT_GENERATION:
            raise ContractError("PUBLIC_RELAY_SCOPE", "Public relay is current-distribution only")
        tag = relay_tag(commit, run_id)
        if not isinstance(artifacts, list) or not 1 <= len(artifacts) <= 64:
            raise ContractError("PUBLIC_RELAY_SET", "Bounded exact original artifact set required")
        expected = {relay_asset_name(row): row for row in artifacts}
        if len(expected) != len(artifacts) or len({row["id"] for row in artifacts}) != len(artifacts):
            raise ContractError("PUBLIC_RELAY_SET", "Duplicate original artifact identity")
        release = self.client.json("https://api.github.com/repos/" + RELAY_REPOSITORY + "/releases/tags/" + tag,
                                   request_class="github-api", limit=1024 ** 2, no_redirect=True)
        if (not isinstance(release, dict) or release.get("tag_name") != tag or release.get("draft") is not False
                or release.get("prerelease") is not False or not isinstance(release.get("assets"), list)):
            raise ContractError("PUBLIC_RELAY_SET", "Exact public relay release required")
        rows = release["assets"]
        if (len(rows) != len(expected) or any(not isinstance(row, dict) or not isinstance(row.get("name"), str) or type(row.get("id")) is not int for row in rows)
                or {row.get("name") for row in rows} != set(expected)
                or len({row.get("id") for row in rows}) != len(rows)):
            raise ContractError("PUBLIC_RELAY_SET", "Missing, extra or duplicate public relay assets")
        selected = {}
        for row in rows:
            original = expected[row["name"]]
            url = "https://github.com/" + RELAY_REPOSITORY + "/releases/download/" + tag + "/" + row["name"]
            if (type(row.get("id")) is not int or row["id"] <= 0 or row.get("state") != "uploaded"
                    or type(row.get("size")) is not int or not 0 < row["size"] <= MAX_BYTES
                    or row.get("digest") != original["digest"] or row.get("browser_download_url") != url):
                raise ContractError("PUBLIC_RELAY_SET", "Relay asset identity or digest differs from original ZIP")
            selected[original["id"]] = RelayAsset(original["id"], row["name"], original["digest"], row["size"], url)
        return PublicRelaySession(MappingProxyType(selected), self.opener)


def select_zip_transport(mode, *, generation):
    generation_paths(generation)
    if mode == "actions":
        return None
    if mode == "public-release-relay" and generation == CURRENT_GENERATION:
        return PublicReleaseTransport()
    raise ContractError("PUBLIC_RELAY_MODE", "Unknown or unsupported ZIP transport mode")
