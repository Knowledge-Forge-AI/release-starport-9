"""Read-only PyPI state classifier. There is deliberately no upload operation."""
import re
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import ProxyHandler, Request, build_opener

from rs9.tf_pypi_archive import AdmissionError, fail, sha256
from rs9.tf_pypi_intake import NoRedirect
from rs9.tf_pypi_model import strict_json, validate_pin

_JSON_LIMIT = 32 * 1024 ** 2
_ROW_CAUSES = frozenset({"version-identity-mismatch", "surplus-file", "file-yanked", "file-changed",
                         "metadata-schema", "file-host"})
# Literal copy of rs9.readers.TLS_CLASSES; this module never imports readers.
_TLS_TOKENS = frozenset("tls-" + name for name in (
    "certificate-verify-failed", "handshake-failure", "protocol-error", "unexpected-eof", "transport-error"))
_FETCH_TOKENS = frozenset({f"http-{status}" for status in range(100, 600)} | {
    "http-unknown", "timeout", "redirect", "url-authority", "limit", "credential-scan", "protocol",
    "incomplete-body", "transport"} | _TLS_TOKENS)
_SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
_SHA256_HEX = re.compile(r"[0-9a-f]{64}")
# Closed observer outcome per cause. State is never derived from AdmissionError.code.
_OUTCOMES = {
    "project-absent": ("absent", "pypi-project-absent"),
    "version-absent": ("version-absent", "pypi-distribution-version-absent"),
    "project-name-mismatch": ("conflict", "pypi-project-name-mismatch"),
    "version-normalization-collision": ("conflict", "pypi-version-normalization-collision"),
    "version-identity-mismatch": ("conflict", "pypi-version-identity-mismatch"),
    "surplus-file": ("conflict", "pypi-surplus-file"),
    "file-yanked": ("conflict", "pypi-file-yanked"),
    "file-changed": ("conflict", "pypi-file-changed"),
    "duplicate-file": ("conflict", "pypi-duplicate-file"),
    "bytes-differ": ("conflict", "pypi-bytes-differ"),
    "metadata-schema": ("unknown", "pypi-metadata-schema"),
    "file-host": ("unknown", "pypi-file-host-unknown"),
    "version-inconsistent": ("unknown", "pypi-version-inconsistent"),
    "limit": ("unknown", "pypi-limit"),
    "protocol": ("unknown", "pypi-protocol"),
    "incomplete-body": ("unknown", "pypi-incomplete-body"),
    **{token: ("unknown", "pypi-" + token) for token in _TLS_TOKENS},
}
_UNKNOWN_OUTCOME = ("unknown", "pypi-transport-unknown")


class _ObserverAdmissionError(AdmissionError):
    """Legacy code-only AdmissionError carrying one closed cause for approved_state only."""

    def __init__(self, code, cause):
        if type(cause) is not str or (cause not in _ROW_CAUSES and cause not in _FETCH_TOKENS):
            raise RuntimeError("closed observer cause required")
        super().__init__(code)
        self.cause = cause

    def __reduce__(self):
        return type(self), (self.code, self.cause)


def _observer_fail(code, cause):
    raise _ObserverAdmissionError("TF_PYPI_" + code, cause)


def _fetch_cause(error):
    cause = error.cause if isinstance(error, _ObserverAdmissionError) else None
    return cause if cause in _FETCH_TOKENS else None


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


def _error_cause(error):
    if error.code == "TF_PYPI_JSON":
        return "metadata-schema"
    return _fetch_cause(error) or "transport"


def _project_state_for(project, dv, get):
    """Return the legacy project_state result and a closed cause (None only when present-unverified)."""
    url = "https://pypi.org/pypi/" + project + "/json"
    try:
        obj = strict_json(get(url))
        if not isinstance(obj, dict) or not isinstance(obj.get("releases"), dict):
            return "unknown", "metadata-schema"
        if not isinstance(obj.get("info"), dict) or obj["info"].get("name") != project:
            info = obj.get("info")
            malformed = not isinstance(info, dict) or not isinstance(info.get("name"), str)
            return "conflict", "metadata-schema" if malformed else "project-name-mismatch"
        releases = obj["releases"]
        if dv in releases:
            return "present-unverified", None
        norm_dv = _normalize_version(dv)
        if any(_normalize_version(key) == norm_dv for key in releases):
            return "conflict", "version-normalization-collision"
    except AdmissionError as error:
        if error.code == "TF_PYPI_REMOTE_ABSENT":
            return "absent", "project-absent"
        return "unknown", _error_cause(error)
    version_url = "https://pypi.org/pypi/" + project + "/" + dv + "/json"
    try:
        get(version_url)
    except AdmissionError as error:
        if error.code == "TF_PYPI_REMOTE_ABSENT":
            return "version-absent", "version-absent"
        return "unknown", _error_cause(error)
    return "unknown", "version-inconsistent"


def project_state(pin, get=None):
    """A remote project alone cannot establish ownership or trusted publication."""
    validate_pin(pin)
    get = get or PublicReader().get
    return _project_state_for(pin["project"], pin["distribution_version"], get)[0]


def _version_rows_for(project, dv, get):
    url = "https://pypi.org/pypi/" + project + "/" + dv + "/json"
    obj = strict_json(get(url))
    if not isinstance(obj, dict) or not isinstance(obj.get("info"), dict):
        _observer_fail("REMOTE_UNKNOWN", "metadata-schema")
    expected = {"name": project, "version": dv}
    if any(obj["info"].get(key) != value for key, value in expected.items()):
        malformed = any(not isinstance(obj["info"].get(key), str) for key in expected)
        _observer_fail("REMOTE_CONFLICT", "metadata-schema" if malformed else "version-identity-mismatch")
    rows = obj.get("urls")
    if not isinstance(rows, list) or not rows:
        _observer_fail("REMOTE_UNKNOWN", "metadata-schema")
    return rows


def _version_rows(pin, get):
    return _version_rows_for(pin["project"], pin["distribution_version"], get)


def _checked_row(row, approved):
    """Legacy per-file metadata checks in their original order; approved maps name -> (size, sha256)."""
    if not isinstance(row, dict):
        _observer_fail("REMOTE_UNKNOWN", "metadata-schema")
    name = row.get("filename")
    if not isinstance(name, str) or name not in approved:
        _observer_fail("REMOTE_CONFLICT", "surplus-file" if isinstance(name, str) else "metadata-schema")
    yanked, size = row.get("yanked"), row.get("size")
    if yanked is not False or type(size) is not int:
        malformed = type(yanked) is not bool or type(size) is not int
        _observer_fail("REMOTE_CONFLICT", "metadata-schema" if malformed else "file-yanked")
    digests = row.get("digests")
    if not isinstance(digests, dict) or (size, digests.get("sha256")) != approved[name]:
        malformed = (not isinstance(digests, dict) or not isinstance(digests.get("sha256"), str)
                     or not _SHA256_HEX.fullmatch(digests["sha256"]))
        _observer_fail("REMOTE_CONFLICT", "metadata-schema" if malformed else "file-changed")
    url = row.get("url")
    try:
        _public_url(url, {"files.pythonhosted.org"})
    except AdmissionError as error:
        raise _ObserverAdmissionError(error.code, "file-host") from None
    return name, url


class _LocalPairs:
    """Lazy name -> (size, sha256) view of verified local bytes, hashed only when compared."""

    def __init__(self, local):
        self._local = local

    def __contains__(self, name):
        return name in self._local

    def __getitem__(self, name):
        body = self._local[name]
        return len(body), sha256(body)


def _verified_file(row, local, get):
    name, url = _checked_row(row, _LocalPairs(local))
    if get(url) != local[name]:
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


def _bounded_get(fetch, limit):
    """Adapt fetch(url, limit) so a fetch failure can only carry a fetch token, never a row cause."""
    def get(url):
        try:
            body = fetch(url, limit)
        except AdmissionError as error:
            absent = error.code == "TF_PYPI_REMOTE_ABSENT"
            code = "TF_PYPI_REMOTE_ABSENT" if absent else "TF_PYPI_REMOTE_UNKNOWN"
            raise _ObserverAdmissionError(code, _fetch_cause(error) or ("http-404" if absent else "transport")) from None
        if type(body) is not bytes:
            _observer_fail("REMOTE_UNKNOWN", "protocol")
        if len(body) > limit:
            _observer_fail("REMOTE_UNKNOWN", "limit")
        return body
    return get


def _validate_approved_inputs(project, dv, approved, fetch):
    if (not isinstance(project, str) or not _SAFE_NAME.fullmatch(project)
            or not isinstance(dv, str) or not _SAFE_NAME.fullmatch(dv)
            or not isinstance(approved, dict) or not approved or not callable(fetch)):
        fail("REMOTE_INPUT")
    for name, pair in approved.items():
        if (not isinstance(name, str) or not _SAFE_NAME.fullmatch(name) or type(pair) is not tuple
                or len(pair) != 2 or type(pair[0]) is not int or pair[0] <= 0
                or not isinstance(pair[1], str) or not _SHA256_HEX.fullmatch(pair[1])):
            fail("REMOTE_INPUT")


def _outcome(cause, observed, missing=()):
    state, code = _OUTCOMES.get(cause, _UNKNOWN_OUTCOME)
    return {"state": state, "code": code, "observed": dict(sorted(observed.items())), "missing": list(missing)}


def approved_state(project, distribution_version, approved, fetch):
    """Observer-only exact comparison of one PyPI distribution with an approved file set.

    approved maps filename -> (size, sha256). fetch(url, limit) returns only a complete body of at
    most limit bytes or raises AdmissionError (REMOTE_ABSENT only for a 404 at the exact URL).
    States: published-exact, absent, version-absent, incomplete, conflict, unknown. The application
    version and project-level info.version are never consulted. The result grants no upload or ownership authority.
    """
    _validate_approved_inputs(project, distribution_version, approved, fetch)
    dv = distribution_version
    json_get = _bounded_get(fetch, _JSON_LIMIT)
    state, cause = _project_state_for(project, dv, json_get)
    if state != "present-unverified":
        return _outcome(cause, {}, sorted(approved) if cause in ("project-absent", "version-absent") else ())
    try:
        rows = _version_rows_for(project, dv, json_get)
    except AdmissionError as error:
        if error.code == "TF_PYPI_REMOTE_ABSENT":
            return _outcome("version-inconsistent", {})
        cause = error.cause if isinstance(error, _ObserverAdmissionError) else _error_cause(error)
        return _outcome(cause, {})
    # Every listed row is checked before any download; the first failing row in listed order decides.
    observed, checked = {}, {}
    for row in rows:
        try:
            name, url = _checked_row(row, approved)
        except AdmissionError as error:
            cause = error.cause if isinstance(error, _ObserverAdmissionError) else None
            if cause == "file-changed":
                observed[row["filename"]] = row["digests"]["sha256"]
            return _outcome(cause, observed)
        except ValueError:
            # urlsplit/port reject a malformed remote row authority; legacy exact_state is unknown too.
            return _outcome("file-host", observed)
        if name in checked:
            return _outcome("duplicate-file", observed)
        checked[name] = url
        observed[name] = approved[name][1]
    bodies = {}
    for name in sorted(checked):
        size, digest = approved[name]
        try:
            body = _bounded_get(fetch, size)(checked[name])
        except _ObserverAdmissionError as error:
            return _outcome(error.cause, observed)
        observed[name] = sha256(body)
        if (len(body), observed[name]) != (size, digest):
            return _outcome("bytes-differ", observed)
        bodies[name] = body
    missing = sorted(set(approved) - set(checked))
    if missing:
        return {"state": "incomplete", "code": "pypi-file-missing",
                "observed": dict(sorted(observed.items())), "missing": missing}
    return {"state": "published-exact", "code": "pypi-distribution-exact",
            "observed": dict(sorted(observed.items())), "missing": [], "bodies": bodies}
