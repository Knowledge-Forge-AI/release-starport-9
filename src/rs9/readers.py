"""Read-only destination transport with a nonserializable live-read proof.

Imported JSON and an asserted reader name cannot mint publication authority.
Unknown transports produce unknown observations; they never imply absence.
"""
import hashlib
import json
import posixpath
import re
import socket
import ssl
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from rs9.errors import ContractError
from rs9.observation import observe, validate_destination, validate_subject
from rs9.planner import expected_components, validate_output
from rs9.records import Record, record_sha256, validate_sanitized_string
from rs9.security import scan_for_credentials, validate_repository, validate_safe_relative_posix_path

_LIVE_PROOF = object()
READERS = {
    "pypi-json-files": "v1alpha1",
    "pypi-project": "v1alpha1",
    "npm-registry": "v1alpha1",
    "homebrew-formula": "v1alpha1",
    "pages-http": "v1alpha1",
    "github-api": "v1alpha1",
    "signed-repo": "v1alpha1",
}


class LiveObservation(Record):
    pass


def has_live_proof(value):
    return (isinstance(value, LiveObservation)
            and value.__dict__.get("_proof") is _LIVE_PROOF
            and value.__dict__.get("_hash") == record_sha256(value)
            and READERS.get(value["reader"]["id"]) == value["reader"]["version"]
            and value["source"] == "live-read")


def _make_live_observation(destination, subject, expected_hashes, desired_identity, readback, reader,
                           remote=None, revisions=None, diagnostics=None, contribution=None):
    result = LiveObservation(observe(
        destination, subject, expected_hashes, desired_identity,
        readback=readback, source="live-read", reader=reader,
        observed_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        remote=remote, revisions=revisions, diagnostics=diagnostics, contribution=contribution
    ))
    result._proof, result._hash = _LIVE_PROOF, record_sha256(result)
    return result


def _normalize_reader_target(target, subject=None, desired_identity=None, expected_hashes=None,
                             default_adapter="pypi", default_mode="direct"):
    if isinstance(target, str):
        validate_sanitized_string(target)
        destination = {"id": default_adapter, "adapter": default_adapter, "mode": default_mode}
        pkg_name = target
        version = "0.0.0"
        if isinstance(subject, str):
            version = subject
            subject = {"package": pkg_name, "version": version, "revision": None}
        elif subject is None:
            subject = {"package": pkg_name, "version": version, "revision": None}
        validate_destination(destination)
        validate_subject(subject)
        desired_identity = desired_identity or "0" * 64
        expected_hashes = expected_hashes or {subject["package"]: desired_identity}
    elif isinstance(target, dict) and "schema" in target and target["schema"] == "rs9.adapter-output.v1alpha1":
        validate_output(target)
        destination = target["destination"]
        subject = target["subject"]
        desired_identity = desired_identity or target["content_identity_sha256"]
        expected_hashes = expected_hashes if expected_hashes is not None else expected_components(target)
    elif isinstance(target, dict) and "adapter" in target:
        validate_destination(target)
        destination = target
        if isinstance(subject, str):
            subject = {"package": subject, "version": "0.0.0", "revision": None}
        elif subject is None:
            subject = {"package": destination["id"], "version": "0.0.0", "revision": None}
        validate_subject(subject)
        desired_identity = desired_identity or "0" * 64
        expected_hashes = expected_hashes or {subject["package"]: desired_identity}
    else:
        raise ContractError("READER_INPUT", "Invalid reader target")
    return destination, subject, desired_identity, expected_hashes


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ContractError("READER_REDIRECT", "Destination identity cannot redirect")


def _http_error_url(error):
    url = getattr(error, "url", None)
    if url is None:
        try:
            url = error.geturl()
        except AttributeError:
            pass
    return url


def _get(url, hosts, limit, headers=None):
    parsed = urlsplit(url)
    if (parsed.scheme != "https" or parsed.hostname not in hosts or parsed.port not in (None, 443)
            or parsed.username or parsed.password or parsed.query or parsed.fragment):
        raise ContractError("READER_URL", "Destination read outside public authority")
    scan_for_credentials(url)
    req_headers = {"User-Agent": "RS9-readback-v1alpha1"}
    if headers:
        for k, v in headers.items():
            scan_for_credentials(f"{k}: {v}")
            req_headers[k] = v
    opener = build_opener(ProxyHandler({}), NoRedirect())
    with opener.open(Request(url, headers=req_headers), timeout=20) as response:
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
            error_url = _http_error_url(error)
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


def read_pypi_project(output_or_destination, subject=None, *, desired_identity=None, expected_hashes=None):
    """Read-only project-level PyPI observations: absent/exact/conflict-ownership-unattested/unknown.

    Can be called with destination and subject, or output, without requiring physical artifacts.
    """
    destination, subject, desired_identity, expected_hashes = _normalize_reader_target(
        output_or_destination, subject, desired_identity, expected_hashes, default_adapter="pypi", default_mode="direct"
    )
    if destination["adapter"] != "pypi":
        raise ContractError("READER_DESTINATION", "PyPI adapter required")
    url = "https://pypi.org/pypi/" + quote(subject["package"], safe="") + "/json"
    readback = {"authenticated": False, "transport": "unknown", "presence": "unknown",
                "components": {}, "content_identity_sha256": None, "level": "none"}
    diagnostics = []
    remote = {}
    exp_hashes = expected_hashes
    try:
        try:
            metadata_bytes = _get(url, {"pypi.org"}, 4 * 1024 ** 2)
        except HTTPError as error:
            error_url = _http_error_url(error)
            if error.code == 404 and error_url == url:
                readback.update(authenticated=True, transport="ok", presence="absent", level="full")
            raise
        metadata = json.loads(metadata_bytes)
        normalized = lambda name: re.sub(r"[-_.]+", "-", name).lower()
        if normalized(metadata["info"]["name"]) != normalized(subject["package"]):
            raise ContractError("PYPI_METADATA", "Package name mismatch")
        if type(metadata.get("last_serial")) is int and metadata["last_serial"] >= 0:
            remote = {"sequence": metadata["last_serial"]}
        releases = metadata.get("releases", {})
        version = subject["version"]
        if version in releases and releases[version]:
            from rs9.records import validate_sha256
            components = {}
            for row in releases[version]:
                name, digest = row["filename"], row["digests"]["sha256"]
                validate_safe_relative_posix_path(name)
                validate_sha256(digest)
                if "/" in name or name in components:
                    raise ContractError("PYPI_METADATA", "Unique registry filenames required")
                components[name] = digest
            if expected_hashes and set(components) == set(expected_hashes) and all(components[k] == expected_hashes[k] for k in expected_hashes):
                exp_hashes = expected_hashes
                diagnostics.append({"code": "metadata-only-match", "message": "File byte and embedded provenance readback required"})
                # Project metadata establishes existence, but cannot establish
                # candidate semantic identity or qualify exact artifact bytes.
                if isinstance(output_or_destination, dict) and output_or_destination.get("schema") == "rs9.adapter-output.v1alpha1":
                    return read_pypi(output_or_destination)
            else:
                diagnostics.append({"code": "conflict-ownership-unattested",
                                    "message": "PyPI release file digests disagree or ownership unattested"})
                conflict_components = components
                exp_hashes = expected_hashes
                readback.update(authenticated=True, transport="ok", presence="present",
                                components=conflict_components,
                                content_identity_sha256=None, level="metadata")
        else:
            diagnostics.append({"code": "conflict-ownership-unattested",
                                "message": "PyPI package exists but ownership is unattested"})
            exp_hashes = expected_hashes
            readback.update(authenticated=True, transport="ok", presence="present",
                            components={"_pypi_project_metadata": hashlib.sha256(metadata_bytes).hexdigest()},
                            content_identity_sha256=None, level="metadata")
    except (HTTPError, URLError, OSError, ValueError, KeyError, TypeError, ContractError):
        pass
    return _make_live_observation(
        destination, subject, exp_hashes, desired_identity,
        readback=readback, reader={"id": "pypi-project", "version": "v1alpha1"},
        remote=remote, diagnostics=diagnostics
    )


def read_npm(output_or_destination, subject=None, *, desired_identity=None, expected_hashes=None,
             expected_integrity=None, expected_license=None, expected_commands=None):
    """npm observe-only: verify remote tarball and exact packaged metadata."""
    import tarfile
    destination, subject, desired_identity, expected_hashes = _normalize_reader_target(
        output_or_destination, subject, desired_identity, expected_hashes, default_adapter="npm", default_mode="direct"
    )
    if destination["adapter"] != "npm":
        raise ContractError("READER_DESTINATION", "npm adapter required")
    url = "https://registry.npmjs.org/" + quote(subject["package"], safe="@")
    readback = {"authenticated": False, "transport": "unknown", "presence": "unknown",
                "components": {}, "content_identity_sha256": None, "level": "none"}
    diagnostics = []
    exp_hashes = expected_hashes
    try:
        try:
            data = _get(url, {"registry.npmjs.org"}, 16 * 1024 ** 2)
        except HTTPError as error:
            error_url = _http_error_url(error)
            if error.code == 404 and error_url == url:
                readback.update(authenticated=True, transport="ok", presence="absent", level="full")
            raise
        doc = json.loads(data)
        if doc.get("name") != subject["package"]:
            raise ContractError("NPM_METADATA", "Package name mismatch")
        versions = doc.get("versions", {})
        version = subject["version"]
        if version not in versions:
            readback.update(authenticated=True, transport="ok", presence="absent", level="full")
        else:
            v_meta = versions[version]
            dist = v_meta.get("dist", {})
            integrity = dist.get("integrity", "")
            if not integrity or not re.fullmatch(r"sha512-[A-Za-z0-9+/]+={0,2}", integrity):
                raise ContractError("NPM_INTEGRITY", "Valid sha512 integrity required")
            observed_license = v_meta.get("license")
            observed_bin = _normalized_npm_bin(subject["package"], v_meta.get("bin"))

            conflict = False
            reasons = []
            if expected_integrity and integrity != expected_integrity:
                conflict = True
                reasons.append(f"integrity {integrity} != {expected_integrity}")
            if expected_license and observed_license != expected_license:
                conflict = True
                reasons.append(f"license {observed_license} != {expected_license}")
            if expected_commands is not None:
                exp_keys = set(expected_commands.keys()) if isinstance(expected_commands, dict) else set(expected_commands)
                if set(observed_bin.keys()) != exp_keys:
                    conflict = True
                    reasons.append(f"commands {set(observed_bin)} != {exp_keys}")

            tarball_url = dist.get("tarball", "")
            tarball_name = tarball_url.rsplit("/", 1)[-1] if "/" in tarball_url else f"{subject['package']}-{version}.tgz"

            if conflict:
                diagnostics.append({"code": "npm-conflict", "message": "; ".join(reasons) or "npm metadata conflict"})
                exp_hashes = expected_hashes
                readback.update(authenticated=True, transport="ok", presence="present",
                                components={tarball_name: "f" * 64},
                                content_identity_sha256="f" * 64 if desired_identity != "f" * 64 else "e" * 64,
                                level="full")
            else:
                # Registry metadata alone cannot assert remote payload identity.
                # Fetch exact bytes and independently check the strongest lock digest.
                import base64
                import io
                import tarfile
                payload = _get(tarball_url, {"registry.npmjs.org"}, 256 * 1024 ** 2)
                actual_integrity = "sha512-" + base64.b64encode(hashlib.sha512(payload).digest()).decode()
                if actual_integrity != integrity:
                    raise ContractError("NPM_INTEGRITY", "Remote tarball differs from registry integrity")
                with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
                    members = [m for m in archive.getmembers() if m.name == "package/package.json"]
                    if len(members) != 1 or not members[0].isfile() or members[0].size > 64 * 1024:
                        raise ContractError("NPM_METADATA", "Bounded unique packaged metadata required")
                    packaged = json.load(archive.extractfile(members[0]))
                if (packaged.get("name") != subject["package"] or packaged.get("version") != version
                        or packaged.get("license") != observed_license
                        or _normalized_npm_bin(subject["package"], packaged.get("bin")) != observed_bin):
                    raise ContractError("NPM_METADATA", "Packaged and registry metadata differ")
                if (not expected_integrity or not expected_license or not isinstance(expected_commands, dict)
                        or observed_bin != _normalized_npm_bin(subject["package"], expected_commands)
                        or tarball_name not in expected_hashes):
                    diagnostics.append({"code": "npm-identity-unavailable", "message": "Exact candidate inventory and command paths required"})
                    readback.update(transport="ok", presence="present", level="metadata")
                else:
                    readback.update(authenticated=True, transport="ok", presence="present",
                                    components={tarball_name: hashlib.sha256(payload).hexdigest()},
                                    content_identity_sha256=desired_identity, level="full")
    except (HTTPError, URLError, OSError, ValueError, KeyError, TypeError, tarfile.TarError, ContractError):
        pass
    return _make_live_observation(
        destination, subject, exp_hashes, desired_identity,
        readback=readback, reader={"id": "npm-registry", "version": "v1alpha1"},
        diagnostics=diagnostics
    )


def _normalized_npm_bin(name, value):
    """Compare npm's POSIX bin normalization without installing a dependency.

    Reference: npm/npm-normalize-package-bin v3.0.1, lib/index.js.
    Colliding normalized command names remain ambiguous and fail closed.
    """
    if isinstance(value, str):
        value = {name: value}
    elif isinstance(value, list):
        if not all(isinstance(path, str) for path in value):
            raise ContractError("NPM_METADATA", "Unsupported bin array")
        value = {posixpath.basename(path): path for path in value}
    elif value is None:
        return {}
    if not isinstance(value, dict):
        raise ContractError("NPM_METADATA", "Unsupported bin metadata")
    result = {}
    for command, target in value.items():
        if not isinstance(command, str) or not isinstance(target, str):
            raise ContractError("NPM_METADATA", "String bin names and targets required")
        command = posixpath.normpath("/" + posixpath.basename(command.replace("\\", "/").replace(":", "/"))).lstrip("/")
        target = posixpath.normpath("/" + target.replace("\\", "/").lstrip("/")).lstrip("/")
        if not command or not target:
            raise ContractError("NPM_METADATA", "Empty normalized bin entry")
        if command in result:
            raise ContractError("NPM_METADATA", "Ambiguous normalized bin entry")
        result[command] = target
    return result


def read_homebrew(output_or_destination, subject=None, *, pinned_ref, tap="Knowledge-Forge-AI/homebrew-tap",
                  desired_identity=None, expected_hashes=None, expected_payload_url=None, expected_payload_sha256=None):
    """Homebrew pinned ref formula URL/hash readback."""
    destination, subject, desired_identity, expected_hashes = _normalize_reader_target(
        output_or_destination, subject, desired_identity, expected_hashes, default_adapter="homebrew", default_mode="projection"
    )
    if destination["adapter"] != "homebrew":
        raise ContractError("READER_DESTINATION", "Homebrew adapter required")
    if not isinstance(pinned_ref, str) or not re.fullmatch(r"[0-9a-f]{40}", pinned_ref):
        raise ContractError("HOMEBREW_PIN", "Homebrew readback requires an immutable pinned ref")
    validate_repository(tap)
    formula_name = subject["package"]
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", formula_name):
        raise ContractError("HOMEBREW_FORMULA", "Safe formula name required")
    url = f"https://raw.githubusercontent.com/{tap}/{pinned_ref}/Formula/{formula_name}.rb"
    readback = {"authenticated": False, "transport": "unknown", "presence": "unknown",
                "components": {}, "content_identity_sha256": None, "level": "none"}
    diagnostics = []
    exp_hashes = expected_hashes
    try:
        try:
            data = _get(url, {"raw.githubusercontent.com"}, 1024 * 1024)
        except HTTPError as error:
            error_url = _http_error_url(error)
            if error.code == 404 and error_url == url:
                readback.update(authenticated=True, transport="ok", presence="absent", level="full")
            raise
        formula_text = data.decode("utf-8", errors="replace")
        url_match = re.search(r'url\s+"([^"]+)"', formula_text)
        sha_match = re.search(r'sha256\s+"([0-9a-f]{64})"', formula_text)
        if not url_match or not sha_match:
            raise ContractError("HOMEBREW_FORMULA", "Formula lacks url or sha256")
        observed_url = url_match.group(1)
        observed_sha = sha_match.group(1)
        formula_sha = hashlib.sha256(data).hexdigest()
        formula_path = f"Formula/{formula_name}.rb"

        conflict = False
        reasons = []
        if expected_payload_url and observed_url != expected_payload_url:
            conflict = True
            reasons.append("payload URL mismatch")
        if expected_payload_sha256 and observed_sha != expected_payload_sha256:
            conflict = True
            reasons.append("payload SHA256 mismatch")
        if expected_hashes and formula_path in expected_hashes and expected_hashes[formula_path] != formula_sha:
            conflict = True
            reasons.append("formula SHA256 mismatch")

        if conflict:
            diagnostics.append({"code": "homebrew-conflict", "message": "; ".join(reasons) or "Formula mismatch"})
            exp_hashes = expected_hashes
            readback.update(authenticated=True, transport="ok", presence="present",
                            components={formula_path: formula_sha},
                            content_identity_sha256="f" * 64 if desired_identity != "f" * 64 else "e" * 64,
                            level="full")
        else:
            diagnostics.append({"code": "homebrew-identity-unavailable", "message": "Formula parsing is diagnostic; complete platform/command/license identity required"})
            readback.update(transport="ok", presence="present", level="metadata")
    except (HTTPError, URLError, OSError, ValueError, KeyError, TypeError, ContractError):
        pass
    return _make_live_observation(
        destination, subject, exp_hashes, desired_identity,
        readback=readback, reader={"id": "homebrew-formula", "version": "v1alpha1"},
        diagnostics=diagnostics
    )


def read_pages(output_or_destination, subject=None, *, path, host="rs9.knowledge-forge.ai",
               desired_identity=None, expected_sha256=None):
    """Pages exact HTTP repository object absence only successful TLS exact404 no redirects, DNS unknown."""
    destination, subject, desired_identity, expected_hashes = _normalize_reader_target(
        output_or_destination, subject, desired_identity, None, default_adapter="pages", default_mode="direct"
    )
    validate_safe_relative_posix_path(path.lstrip("/"))
    clean_path = path.lstrip("/")
    url = f"https://{host}/{clean_path}"
    readback = {"authenticated": False, "transport": "unknown", "presence": "unknown",
                "components": {}, "content_identity_sha256": None, "level": "none"}
    diagnostics = []
    exp_hashes = {clean_path: expected_sha256} if expected_sha256 else {clean_path: desired_identity}
    try:
        try:
            data = _get(url, {host}, 16 * 1024 ** 2)
        except HTTPError as error:
            error_url = _http_error_url(error)
            if error.code == 404 and error_url == url:
                readback.update(authenticated=True, transport="ok", presence="absent", level="full")
            raise
        except URLError as error:
            reason = getattr(error, "reason", None)
            if isinstance(reason, socket.gaierror):
                diagnostics.append({"code": "pages-dns-unknown", "message": "DNS resolution unavailable"})
            elif isinstance(reason, ssl.SSLError):
                diagnostics.append({"code": "pages-tls-error", "message": "TLS verification failed"})
            raise
        sha = hashlib.sha256(data).hexdigest()
        components = {clean_path: sha}
        if expected_sha256 and sha != expected_sha256:
            diagnostics.append({"code": "pages-hash-conflict", "message": "Object SHA256 differs from expected"})
            exp_hashes = {clean_path: expected_sha256}
            readback.update(authenticated=True, transport="ok", presence="present",
                            components=components, content_identity_sha256="f" * 64 if desired_identity != "f" * 64 else "e" * 64,
                            level="full")
        else:
            exp_hashes = {clean_path: sha}
            readback.update(authenticated=True, transport="ok", presence="present",
                            components=components, content_identity_sha256=desired_identity, level="full")
    except (HTTPError, URLError, OSError, ValueError, KeyError, TypeError, ContractError):
        pass
    return _make_live_observation(
        destination, subject, exp_hashes, desired_identity,
        readback=readback, reader={"id": "pages-http", "version": "v1alpha1"},
        diagnostics=diagnostics
    )


def read_github(output_or_destination, subject=None, *, repository=None, query_type="pages", ref=None,
                desired_identity=None, expected_sha=None):
    """Github refs/current Pages state read-only (never secrets)."""
    if repository is None and isinstance(output_or_destination, str):
        repository = output_or_destination
    elif repository is None and isinstance(output_or_destination, dict) and "id" in output_or_destination:
        repository = output_or_destination["id"]
    if not repository:
        raise ContractError("GITHUB_REPOSITORY", "Repository required for GitHub readback")

    validate_repository(repository)
    scan_for_credentials(repository)
    if ref:
        scan_for_credentials(ref)

    destination, subject, desired_identity, expected_hashes = _normalize_reader_target(
        output_or_destination, subject, desired_identity, None, default_adapter="github", default_mode="projection"
    )
    readback = {"authenticated": False, "transport": "unknown", "presence": "unknown",
                "components": {}, "content_identity_sha256": None, "level": "none"}
    diagnostics = []
    exp_hashes = expected_hashes
    try:
        if query_type == "pages":
            url = f"https://api.github.com/repos/{repository}/pages"
            # An unauthenticated Pages administration 404 may conceal access,
            # so it never proves an undeployed site.
            data = _get(url, {"api.github.com"}, 1024 * 1024)
            doc = json.loads(data)
            status = doc.get("status", "unknown")
            status_sha = hashlib.sha256(status.encode()).hexdigest()
            components = {"pages_status": status_sha}
            diagnostics.append({"code": "github-metadata-only", "message": "Pages administration metadata does not prove hosted objects"})
            readback.update(transport="ok", presence="present", level="metadata")
        elif query_type == "ref":
            if not ref:
                raise ContractError("GITHUB_REF", "Git ref required")
            clean_ref = ref.removeprefix("refs/")
            url = f"https://api.github.com/repos/{repository}/git/ref/{clean_ref}"
            try:
                data = _get(url, {"api.github.com"}, 1024 * 1024)
            except HTTPError as error:
                error_url = _http_error_url(error)
                if error.code == 404 and error_url == url:
                    readback.update(authenticated=True, transport="ok", presence="absent", level="full")
                raise
            doc = json.loads(data)
            sha = doc.get("object", {}).get("sha", "")
            if not re.fullmatch(r"[0-9a-f]{40}", sha) or doc.get("object", {}).get("type") != "commit":
                raise ContractError("GITHUB_REF", "A commit ref is required")
            components = {ref: hashlib.sha256(sha.encode()).hexdigest()}
            if expected_sha and sha != expected_sha:
                diagnostics.append({"code": "github-ref-conflict", "message": f"Ref sha {sha} != {expected_sha}"})
                exp_hashes = {ref: hashlib.sha256(expected_sha.encode()).hexdigest()}
                readback.update(authenticated=True, transport="ok", presence="present",
                                components=components, content_identity_sha256="f" * 64 if desired_identity != "f" * 64 else "e" * 64,
                                level="full")
            else:
                diagnostics.append({"code": "github-metadata-only", "message": "Commit ref does not prove flake outputs or qualification"})
                readback.update(transport="ok", presence="present", level="metadata")
        else:
            raise ContractError("GITHUB_QUERY", "Unknown GitHub query type")
    except (HTTPError, URLError, OSError, ValueError, KeyError, TypeError, ContractError):
        pass
    return _make_live_observation(
        destination, subject, exp_hashes, desired_identity,
        readback=readback, reader={"id": "github-api", "version": "v1alpha1"},
        diagnostics=diagnostics
    )


def read_signed_repo(output_or_destination, subject=None, *, base_url, index_path, signature_path=None,
                     verifier=None, index_parser=None, desired_identity=None, expected_hashes=None):
    """Verify pinned issuer, signed index inventory, then every exact object.

    Parsers and signature verifiers are reviewed in-process code boundaries.
    Missing parser, issuer proof or candidate inventory stays unknown.
    """
    from rs9.signed_store import PRODUCTION_PRIMARY_FINGERPRINT, PRODUCTION_SIGNING_SUBKEY
    destination, subject, desired_identity, inventory = _normalize_reader_target(
        output_or_destination, subject, desired_identity, expected_hashes, default_adapter="signed-store", default_mode="direct")
    validate_safe_relative_posix_path(index_path)
    if signature_path is not None:
        validate_safe_relative_posix_path(signature_path)
    parsed = urlsplit(base_url)
    if parsed.scheme != "https" or parsed.hostname != "rs9.knowledge-forge.ai" or parsed.query or parsed.fragment:
        raise ContractError("READER_URL", "Signed repository read outside RS9 authority")
    hosts = {parsed.hostname}
    index_url = base_url.rstrip("/") + "/" + index_path
    readback = {"authenticated": False, "transport": "unknown", "presence": "unknown",
                "components": {}, "content_identity_sha256": None, "level": "none"}
    diagnostics = []
    try:
        try:
            index_bytes = _get(index_url, hosts, 16 * 1024 ** 2)
        except HTTPError as error:
            error_url = _http_error_url(error)
            if error.code == 404 and error_url == index_url:
                readback.update(authenticated=True, transport="ok", presence="absent", level="full")
            raise
        if verifier is None:
            diagnostics.append({"code": "signature-unverified", "message": "Reviewed signature verifier required"})
            raise ContractError("SIGNATURE_VERIFIER", "No signature verifier")
        signature = _get(base_url.rstrip("/") + "/" + signature_path, hosts, 1024 * 1024) if signature_path else None
        verified = verifier(index_bytes, signature) if signature is not None else verifier(index_bytes)
        if (not isinstance(verified, dict) or verified.get("status") != "valid"
                or verified.get("primary_key_id") != PRODUCTION_PRIMARY_FINGERPRINT
                or verified.get("verified_issuer") != PRODUCTION_SIGNING_SUBKEY):
            diagnostics.append({"code": "signature-invalid", "message": "Pinned primary and signing issuer proof required"})
            raise ContractError("SIGNATURE_INVALID", "Unverified signature issuer")
        if index_parser is None or not inventory or index_path not in inventory:
            diagnostics.append({"code": "signed-inventory-unavailable", "message": "Reviewed parser and exact candidate inventory required"})
            raise ContractError("READER_INDEX", "Missing signed index parser or candidate inventory")
        objects = index_parser(index_bytes)
        if not isinstance(objects, dict) or not 1 <= len(objects) <= 4096:
            raise ContractError("READER_INDEX", "Nonempty signed object inventory required")
        expected_names = set(objects) | {index_path} | ({signature_path} if signature_path else set())
        if set(inventory) != expected_names:
            raise ContractError("READER_INDEX", "Signed inventory differs from exact candidate object set")
        components = {index_path: hashlib.sha256(index_bytes).hexdigest()}
        if signature_path:
            components[signature_path] = hashlib.sha256(signature).hexdigest()
        for path, sha in sorted(objects.items()):
            validate_safe_relative_posix_path(path)
            if path in components or not re.fullmatch(r"[0-9a-f]{64}", sha):
                raise ContractError("READER_INDEX", "Invalid signed object inventory")
            body = _get(base_url.rstrip("/") + "/" + path, hosts, 512 * 1024 ** 2)
            actual = hashlib.sha256(body).hexdigest()
            if actual != sha:
                raise ContractError("READER_OBJECT", "Remote object differs from signed index")
            components[path] = actual
        readback.update(authenticated=True, transport="ok", presence="present", components=components,
                        content_identity_sha256=desired_identity, level="full")
    except (HTTPError, URLError, OSError, ValueError, KeyError, TypeError, ContractError):
        pass
    return _make_live_observation(destination, subject, inventory, desired_identity, readback=readback,
        reader={"id": "signed-repo", "version": "v1alpha1"}, diagnostics=diagnostics)
