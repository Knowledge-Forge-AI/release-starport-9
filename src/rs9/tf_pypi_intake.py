"""Public read-only asset fetch; no ambient credentials, npm or executable hooks."""
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from rs9.tf_pypi_archive import AdmissionError, fail
from rs9.tf_pypi_model import admit_bytes, validate_pin


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def asset_url(pin):
    validate_pin(pin)
    return ("https://github.com/Knowledge-Forge-AI/" + pin["project"] +
            "/releases/download/v" + pin["version"] + "/" + pin["asset"])


def _url_allowed(url):
    try:
        parsed = urlsplit(url)
        return (parsed.scheme == "https" and parsed.hostname in {
            "github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"} and not parsed.username
            and not parsed.password and parsed.port in (None, 443) and not parsed.fragment)
    except ValueError:
        return False


def download(pin, *, opener=None):
    """Only redirects issued by the pinned public GitHub request are considered."""
    opener = opener or build_opener(ProxyHandler({}), NoRedirect())
    url = asset_url(pin)
    for _ in range(4):
        if not _url_allowed(url):
            fail("REDIRECT")
        try:
            with opener.open(Request(url, headers={"User-Agent": "RS9-TF-PyPI/1"}), timeout=30) as response:
                if response.status != 200 or response.geturl() != url:
                    fail("REMOTE_UNKNOWN")
                body = response.read(pin["size"] + 1)
                admit_bytes(pin, body, pin["asset"])
                return body
        except HTTPError as error:
            code, location, actual = error.code, error.headers.get("Location"), error.geturl()
            error.close()
            if code == 404 and actual == url:
                fail("ASSET_ABSENT")
            if code not in {301, 302, 303, 307, 308} or not location or actual != url:
                fail("REMOTE_UNKNOWN")
            url = location
        except AdmissionError:
            raise
        except (URLError, OSError, ValueError):
            fail("REMOTE_UNKNOWN")
    fail("REDIRECT")


def fetch(pin, directory):
    data = download(pin)
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    with (directory / pin["asset"]).open("xb") as stream:
        stream.write(data)
    return {"asset": pin["asset"], "size": len(data), "sha256": pin["sha256"]}
