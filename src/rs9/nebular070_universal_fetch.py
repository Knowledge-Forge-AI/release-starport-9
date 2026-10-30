"""Bounded verified archive fetch, imported only for explicit runtime setup."""
from __future__ import annotations

from dataclasses import dataclass
import errno
import hashlib
import os
from pathlib import Path
import re
import stat
import tempfile
import time
from typing import Mapping

from rs9.materialize import MaterializeLock, validate_ancestry_not_symlink

BASE_URL = "https://github.com/Knowledge-Forge-AI/theme-forge-nebular-fusion/releases/download/v0.7.0/"
ASSET_NAMES = frozenset({
    "theme-forge-nebular-fusion-v0.7.0-aarch64-apple-darwin.app.tar.gz",
    "theme-forge-nebular-fusion-v0.7.0-aarch64-unknown-linux-gnu.tar.gz",
    "theme-forge-nebular-fusion-v0.7.0-x86_64-unknown-linux-gnu.tar.gz",
})
ASSET_HOST = "release-assets.githubusercontent.com"
DOWNLOAD_ACCEPTANCE_SECONDS = 900.0
FAILURE_CODES = frozenset({
    "TFNF_RUNTIME_PIN", "TFNF_RUNTIME_CACHE", "TFNF_RUNTIME_REDIRECT",
    "TFNF_RUNTIME_DEADLINE", "TFNF_RUNTIME_RESPONSE", "TFNF_RUNTIME_ENCODING",
    "TFNF_RUNTIME_SIZE", "TFNF_RUNTIME_DIGEST", "TFNF_RUNTIME_TRANSPORT", "TFNF_RUNTIME_TLS",
})


class RuntimeDownloadError(RuntimeError):
    """A closed failure code without transport exception payloads or chains."""

    def __init__(self, code):
        self.code = code if type(code) is str and code in FAILURE_CODES else "TFNF_RUNTIME_TRANSPORT"
        super().__init__(self.code)


def _failure_code(error, default):
    import ssl
    from urllib.error import URLError
    if isinstance(error, RuntimeDownloadError):
        return error.code
    if isinstance(error, ssl.SSLCertVerificationError) or (
        isinstance(error, URLError) and isinstance(error.reason, ssl.SSLCertVerificationError)
    ):
        return "TFNF_RUNTIME_TLS"
    return default


@dataclass(frozen=True)
class FetchResult:
    archive: Path
    downloaded: bool
    redirect_hosts: tuple[str, ...]


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mode,
            info.st_mtime_ns, info.st_ctime_ns, info.st_uid, info.st_gid, info.st_nlink)


def _validate_asset(asset):
    if (not isinstance(asset, Mapping) or set(asset) != {"id", "name", "size", "sha256", "url"}
            or type(asset["id"]) is not int or asset["id"] <= 0
            or type(asset["size"]) is not int or not 0 < asset["size"] <= 64 * 1024 * 1024
            or not isinstance(asset["name"], str) or asset["name"] not in ASSET_NAMES
            or not isinstance(asset["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", asset["sha256"])
            or asset["url"] != BASE_URL + asset["name"]):
        raise RuntimeDownloadError("TFNF_RUNTIME_PIN")


def _existing(path, asset):
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False, None
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid()):
        raise RuntimeDownloadError("TFNF_RUNTIME_CACHE")
    identity = _identity(info)
    if info.st_size != asset["size"]:
        return False, identity
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            if _identity(os.fstat(stream.fileno())) != identity:
                raise RuntimeDownloadError("TFNF_RUNTIME_CACHE")
            digest, remaining = hashlib.sha256(), asset["size"] + 1
            while remaining:
                data = stream.read(min(65536, remaining))
                if not data:
                    break
                digest.update(data)
                remaining -= len(data)
            if (_identity(os.fstat(stream.fileno())) != identity
                    or _identity(path.lstat()) != identity):
                raise RuntimeDownloadError("TFNF_RUNTIME_CACHE")
        return remaining == 1 and digest.hexdigest() == asset["sha256"], identity
    except OSError as error:
        if error.errno in {errno.EACCES, errno.EPERM}:
            try:
                unchanged = _identity(path.lstat()) == identity
            except OSError:
                unchanged = False
            if unchanged:
                # It is our stable regular single-link file. Explicit setup
                # can replace it without reading its inaccessible contents.
                return False, identity
    raise RuntimeDownloadError("TFNF_RUNTIME_CACHE")


def _safe_asset_url(url):
    from urllib.parse import urlsplit
    valid = False
    try:
        parsed = urlsplit(url)
        valid = (parsed.scheme == "https" and parsed.hostname == ASSET_HOST
                 and parsed.username is None and parsed.password is None
                 and parsed.port in (None, 443) and not parsed.fragment)
    except (TypeError, ValueError):
        pass
    if valid:
        return ASSET_HOST
    raise RuntimeDownloadError("TFNF_RUNTIME_REDIRECT")


def _remaining(deadline, clock):
    remaining = deadline - clock()
    if remaining <= 0:
        raise RuntimeDownloadError("TFNF_RUNTIME_DEADLINE")
    return min(10.0, remaining)


def _opener(initial_url, hosts, deadline, clock):
    import ssl
    import urllib.request

    class Guard(urllib.request.HTTPRedirectHandler):
        redirects = 0

        def redirect_request(self, req, fp, code, msg, headers, newurl):
            _remaining(deadline, clock)
            if self.redirects == 0 and req.full_url != initial_url:
                raise RuntimeDownloadError("TFNF_RUNTIME_REDIRECT")
            host = _safe_asset_url(newurl)
            self.redirects += 1
            if self.redirects > 3:
                raise RuntimeDownloadError("TFNF_RUNTIME_REDIRECT")
            redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
            if redirected is None:
                raise RuntimeDownloadError("TFNF_RUNTIME_REDIRECT")
            for name, _ in list(redirected.header_items()):
                if name.lower() in {"authorization", "proxy-authorization"}:
                    redirected.remove_header(name)
            hosts.append(host)
            return redirected

    return urllib.request.build_opener(
        Guard(), urllib.request.HTTPSHandler(context=ssl.create_default_context()),
    )


def _stream(response, stream, asset, deadline, clock):
    if response.status != 200:
        raise RuntimeDownloadError("TFNF_RUNTIME_RESPONSE")
    if response.headers.get("Content-Encoding", "identity").strip().lower() != "identity":
        raise RuntimeDownloadError("TFNF_RUNTIME_ENCODING")
    if response.headers.get("Transfer-Encoding", "identity").strip().lower() != "identity":
        raise RuntimeDownloadError("TFNF_RUNTIME_ENCODING")
    length = response.headers.get("Content-Length")
    if length is not None and (not re.fullmatch(r"[0-9]+", length) or int(length) != asset["size"]):
        raise RuntimeDownloadError("TFNF_RUNTIME_SIZE")
    digest, count = hashlib.sha256(), 0
    while True:
        _remaining(deadline, clock)
        # HTTPResponse.read1 yields between underlying reads so a slow body
        # cannot hide progress inside a buffer-filling read(size).
        data = response.read1(min(65536, asset["size"] - count + 1))
        _remaining(deadline, clock)
        if not isinstance(data, bytes):
            raise RuntimeDownloadError("TFNF_RUNTIME_RESPONSE")
        if not data:
            break
        count += len(data)
        if count > asset["size"]:
            raise RuntimeDownloadError("TFNF_RUNTIME_SIZE")
        stream.write(data)
        digest.update(data)
    if count != asset["size"] or digest.hexdigest() != asset["sha256"]:
        raise RuntimeDownloadError("TFNF_RUNTIME_DIGEST")


def _download_checked(asset, directory, destination, previous, opener, clock):
    import urllib.request
    deadline, hosts = clock() + DOWNLOAD_ACCEPTANCE_SECONDS, []
    client = opener if opener is not None else _opener(asset["url"], hosts, deadline, clock)
    fd, name = tempfile.mkstemp(prefix="." + asset["sha256"] + ".", suffix=".part", dir=directory)
    temporary = Path(name)
    owned = os.fstat(fd)
    try:
        with os.fdopen(fd, "wb") as stream:
            response = None
            try:
                request = urllib.request.Request(asset["url"], headers={"Accept-Encoding": "identity"})
                response = client.open(request, timeout=_remaining(deadline, clock))
                final_url = response.geturl()
                if final_url != asset["url"]:
                    hosts.append(_safe_asset_url(final_url))
                _stream(response, stream, asset, deadline, clock)
            finally:
                if response is not None:
                    try:
                        response.close()
                    except Exception:
                        pass
            stream.flush()
            os.fsync(stream.fileno())
            _remaining(deadline, clock)
            written = os.fstat(stream.fileno())
            if (_identity(written) != _identity(temporary.lstat())
                    or written.st_nlink != 1 or written.st_size != asset["size"]):
                raise RuntimeDownloadError("TFNF_RUNTIME_CACHE")
            try:
                current = _identity(destination.lstat())
            except FileNotFoundError:
                current = None
            if current != previous:
                raise RuntimeDownloadError("TFNF_RUNTIME_CACHE")
            os.replace(temporary, destination)
        parent_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
        return FetchResult(destination, True, tuple(sorted(set(hosts))))
    finally:
        try:
            current = temporary.lstat()
            if (current.st_dev, current.st_ino) == (owned.st_dev, owned.st_ino):
                temporary.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            # Cleanup is best effort and must not replace a committed result
            # or the primary closed failure. Never remove a different inode.
            pass


def _download(asset, directory, destination, previous, opener, clock):
    try:
        return _download_checked(asset, directory, destination, previous, opener, clock)
    except Exception as error:
        code = _failure_code(error, "TFNF_RUNTIME_TRANSPORT")
    # Raising outside the except suite clears both implicit and explicit chains.
    raise RuntimeDownloadError(code)


def _fetch_archive_checked(asset: Mapping[str, object], archive_dir: Path, *, opener=None, clock=None) -> FetchResult:
    """Explicit setup only; commit exclusively verified bytes into the owned cache."""
    _validate_asset(asset)
    directory = Path(archive_dir)
    if not directory.is_absolute():
        raise RuntimeDownloadError("TFNF_RUNTIME_CACHE")
    try:
        directory = validate_ancestry_not_symlink(directory)
        directory.mkdir(parents=True, mode=0o700, exist_ok=True)
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
            raise RuntimeDownloadError("TFNF_RUNTIME_CACHE")
        os.chmod(directory, 0o700)
        destination = directory / (asset["sha256"] + ".tgz")
        with MaterializeLock(directory / ".locks" / (asset["sha256"] + ".lock")):
            valid, previous = _existing(destination, asset)
            if valid:
                return FetchResult(destination, False, ())
            return _download(asset, directory, destination, previous, opener, clock or time.monotonic)
    except RuntimeDownloadError:
        raise
    except Exception:
        raise RuntimeDownloadError("TFNF_RUNTIME_CACHE") from None


def fetch_archive(asset: Mapping[str, object], archive_dir: Path, *, opener=None, clock=None) -> FetchResult:
    """Explicit setup only; expose only a fresh closed error at this boundary."""
    try:
        return _fetch_archive_checked(asset, archive_dir, opener=opener, clock=clock)
    except Exception as error:
        code = _failure_code(error, "TFNF_RUNTIME_CACHE")
    raise RuntimeDownloadError(code)
