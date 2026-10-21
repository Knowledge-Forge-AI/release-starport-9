"""Read-only PyPI state classifier. There is deliberately no upload operation."""
import re
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import ProxyHandler, Request, build_opener

from rs9.tf_pypi_archive import AdmissionError, fail, sha256
from rs9.tf_pypi_intake import NoRedirect
from rs9.tf_pypi_model import strict_json, validate_pin


def _public_url(url, hosts):
    if not isinstance(url, str):
        fail("REMOTE_UNKNOWN")
    parsed = urlsplit(url)
    if (parsed.scheme != "https" or parsed.hostname not in hosts or parsed.username
            or parsed.password or parsed.port not in (None, 443) or parsed.query or parsed.fragment):
        fail("REMOTE_UNKNOWN")


def _normalize_version(value):
    if not isinstance(value, str):
        return ""
    folded = value.strip().casefold()
    if folded.startswith("v"):
        folded = folded[1:]
    if folded.startswith("0!"):
        folded = folded[2:]
    match = re.fullmatch(
        r"([0-9]+(?:\.[0-9]+)*)(?:[-_.]*(?:post|rev|r)[-_.]*([0-9]*)|-([0-9]+))?",
        folded,
    )
    if match:
        release = ".".join(str(int(part)) for part in match.group(1).split("."))
        if match.group(2) is not None:
            post_num = int(match.group(2)) if match.group(2) else 0
            return f"{release}.post{post_num}"
        if match.group(3) is not None:
            return f"{release}.post{int(match.group(3))}"
        return release
    return folded


class PublicReader:
    def __init__(self):
        self.opener = build_opener(ProxyHandler({}), NoRedirect())

    def get(self, url):
        try:
            _public_url(url, {"pypi.org", "files.pythonhosted.org"})
            with self.opener.open(Request(url, headers={"User-Agent": "RS9-TF-PyPI/1"}), timeout=20) as response:
                if response.status != 200 or response.geturl() != url:
                    fail("REMOTE_UNKNOWN")
                body = response.read(32 * 1024**2 + 1)
                if len(body) > 32 * 1024**2:
                    fail("REMOTE_UNKNOWN")
                return body
        except HTTPError as error:
            absent = error.code == 404 and error.geturl() == url
            error.close()
            fail("REMOTE_ABSENT" if absent else "REMOTE_UNKNOWN")
        except (URLError, OSError, ValueError):
            fail("REMOTE_UNKNOWN")


def project_state(pin, get=None):
    """A remote project alone cannot establish ownership or trusted publication."""
    validate_pin(pin)
    get = get or PublicReader().get
    dv = pin["distribution_version"]
    url = "https://pypi.org/pypi/" + pin["project"] + "/json"
    try:
        obj = strict_json(get(url))
        if not isinstance(obj, dict) or not isinstance(obj.get("releases"), dict):
            return "unknown"
        if not isinstance(obj.get("info"), dict) or obj["info"].get("name") != pin["project"]:
            return "conflict"
        releases = obj["releases"]
        if dv in releases:
            return "present-unverified"
        norm_dv = _normalize_version(dv)
        if any(_normalize_version(key) == norm_dv for key in releases):
            return "conflict"
    except AdmissionError as error:
        return "absent" if error.code == "TF_PYPI_REMOTE_ABSENT" else "unknown"
    version_url = "https://pypi.org/pypi/" + pin["project"] + "/" + dv + "/json"
    try:
        get(version_url)
    except AdmissionError as error:
        return "version-absent" if error.code == "TF_PYPI_REMOTE_ABSENT" else "unknown"
    return "unknown"


def _version_rows(pin, get):
    dv = pin["distribution_version"]
    url = "https://pypi.org/pypi/" + pin["project"] + "/" + dv + "/json"
    obj = strict_json(get(url))
    if not isinstance(obj, dict) or not isinstance(obj.get("info"), dict):
        fail("REMOTE_UNKNOWN")
    expected = {"name": pin["project"], "version": dv}
    if any(obj["info"].get(key) != value for key, value in expected.items()):
        fail("REMOTE_CONFLICT")
    rows = obj.get("urls")
    if not isinstance(rows, list) or not rows:
        fail("REMOTE_UNKNOWN")
    return rows


def _verified_file(row, local, get):
    if not isinstance(row, dict):
        fail("REMOTE_UNKNOWN")
    name = row.get("filename")
    if not isinstance(name, str) or name not in local:
        fail("REMOTE_CONFLICT")
    body = local[name]
    if row.get("yanked") is not False or type(row.get("size")) is not int:
        fail("REMOTE_CONFLICT")
    digests = row.get("digests")
    if not isinstance(digests, dict) or (row["size"], digests.get("sha256")) != (len(body), sha256(body)):
        fail("REMOTE_CONFLICT")
    url = row.get("url")
    _public_url(url, {"files.pythonhosted.org"})
    if get(url) != body:
        fail("REMOTE_CONFLICT")
    return name


def exact_state(pin, local, get=None):
    """Compare the exact candidate filename/size/hash set AND downloaded bytes.

    Caller supplies a verified candidate set; this result grants no write authority.
    """
    get = get or PublicReader().get
    state = project_state(pin, get)
    if state != "present-unverified":
        return {"state": state, "missing": sorted(local) if state in ("absent", "version-absent") else []}
    try:
        seen = set()
        for row in _version_rows(pin, get):
            name = _verified_file(row, local, get)
            if name in seen:
                fail("REMOTE_CONFLICT")
            seen.add(name)
        missing = sorted(set(local) - seen)
        return {"state": "incomplete" if missing else "published-exact", "missing": missing}
    except AdmissionError as error:
        state = "conflict" if error.code == "TF_PYPI_REMOTE_CONFLICT" else "unknown"
        return {"state": state, "missing": []}
    except ValueError:
        return {"state": "unknown", "missing": []}
