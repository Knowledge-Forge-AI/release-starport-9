"""Read-only destination transport with a nonserializable live-read proof.

Imported JSON and an asserted reader name cannot mint publication authority.
Unknown transports produce unknown observations; they never imply absence.
"""
import hashlib
import json
import re
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from rs9.errors import ContractError
from rs9.observation import observe
from rs9.planner import expected_components, validate_output
from rs9.records import Record, record_sha256

_LIVE_PROOF = object()
READERS = {"pypi-json-files": "v1alpha1"}


class LiveObservation(Record):
    pass


def has_live_proof(value):
    return (isinstance(value, LiveObservation)
            and value.__dict__.get("_proof") is _LIVE_PROOF
            and value.__dict__.get("_hash") == record_sha256(value)
            and READERS.get(value["reader"]["id"]) == value["reader"]["version"]
            and value["source"] == "live-read")


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ContractError("READER_REDIRECT", "Destination identity cannot redirect")


def _get(url, hosts, limit):
    parsed = urlsplit(url)
    if (parsed.scheme != "https" or parsed.hostname not in hosts or parsed.port not in (None, 443)
            or parsed.username or parsed.password or parsed.query or parsed.fragment):
        raise ContractError("READER_URL", "Destination read outside public authority")
    opener = build_opener(ProxyHandler({}), NoRedirect())
    with opener.open(Request(url, headers={"User-Agent": "RS9-readback-v1alpha1"}), timeout=20) as response:
        data = response.read(limit + 1)
        if response.status != 200 or len(data) > limit:
            raise ContractError("READER_LIMIT", "Destination response outside bound")
        return data


def read_pypi(output):
    """Validate release metadata and every published file, including surplus files.

    Provenance must be present in each exact wheel and must bind the semantic
    identity. Filename/digest equality alone does not infer semantic identity.
    """
    import io
    import zipfile
    validate_output(output)
    if output["destination"]["adapter"] != "pypi" or output["destination"]["mode"] != "direct":
        raise ContractError("READER_DESTINATION", "PyPI direct output required")
    subject = output["subject"]
    url = "https://pypi.org/pypi/" + quote(subject["package"], safe="") + "/" + quote(subject["version"], safe="") + "/json"
    readback = {"authenticated": False, "transport": "unknown", "presence": "unknown",
                "components": {}, "content_identity_sha256": None, "level": "none"}
    remote = {}
    try:
        try:
            metadata_bytes = _get(url, {"pypi.org"}, 4 * 1024 ** 2)
        except HTTPError as error:
            error_url = getattr(error, "url", None)
            if error_url is None and hasattr(error, "geturl"):
                error_url = error.geturl()
            if error.code == 404 and error_url == url:
                readback.update(authenticated=True, transport="ok", presence="absent", level="full")
            raise
        metadata = json.loads(metadata_bytes)
        normalized = lambda name: re.sub(r"[-_.]+", "-", name).lower()
        if (metadata["info"]["version"] != subject["version"]
                or normalized(metadata["info"]["name"]) != normalized(subject["package"])
                or metadata["info"].get("license_expression") != "AGPL-3.0-or-later"
                or not metadata["urls"]):
            raise ContractError("PYPI_METADATA", "Version and published file inventory required")
        if type(metadata["last_serial"]) is not int or metadata["last_serial"] < 0:
            raise ContractError("PYPI_METADATA", "Registry sequence must be a nonnegative integer")
        components, identities = {}, set()
        complete_provenance = True
        for row in metadata["urls"]:
            name = row["filename"]
            if name in components:
                raise ContractError("PYPI_METADATA", "Duplicate published file")
            data = _get(row["url"], {"files.pythonhosted.org"}, 256 * 1024 ** 2)
            sha = hashlib.sha256(data).hexdigest()
            if row["digests"]["sha256"] != sha or row["size"] != len(data):
                raise ContractError("PYPI_FILE", "Registry file digest or size mismatch")
            components[name] = sha
            if not name.endswith(".whl"):
                complete_provenance = False
                continue
            with zipfile.ZipFile(io.BytesIO(data)) as wheel:
                candidates = [n for n in wheel.namelist() if n.endswith("/_rs9/provenance.json")]
                if len(candidates) != 1 or wheel.getinfo(candidates[0]).file_size > 512 * 1024:
                    complete_provenance = False
                    continue
                identities.add(json.loads(wheel.read(candidates[0])).get("content_identity_sha256"))
        identity = identities.pop() if complete_provenance and len(identities) == 1 else None
        remote = {"sequence": metadata["last_serial"]}
        readback.update(authenticated=True, transport="ok", presence="present", components=components,
                        content_identity_sha256=identity, level="full")
    except (HTTPError, URLError, OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile, ContractError):
        pass
    result = LiveObservation(observe(output["destination"], subject, expected_components(output),
        output["content_identity_sha256"], readback=readback, source="live-read",
        reader={"id": "pypi-json-files", "version": "v1alpha1"},
        observed_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"), remote=remote))
    result._proof, result._hash = _LIVE_PROOF, record_sha256(result)
    return result
