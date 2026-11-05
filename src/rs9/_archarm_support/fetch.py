"""Anonymous fixed host-side downloads (ported ``download``/``download_package``).

Only the frozen fl.us ArchARM mirror URLs from the pins are accepted. No proxy,
redirect, cookie, credential or retry. Exact Content-Length, bounded read, then
the pinned SHA-256. Upstream disappearance is a hard stop (no mirror change).
"""
from __future__ import annotations

import http.client
from pathlib import Path
import ssl
import time
import urllib.request

from rs9._archarm_support.pins import (MAX_PACKAGE_BYTES, MAX_SIGNATURE_BYTES, PACKAGE_URL_RE,
                                       ROOTFS_URL_PREFIX)
from rs9._archarm_support.refusal import SdkRefusal, require
from rs9._archarm_support.rootfs import check_file

ROOTFS_SECONDS = 900
PER_PACKAGE_SECONDS = 300
CONNECT_TIMEOUT_SECONDS = 30
MAX_ROOTFS_BYTES = 2 * 1024 * 1024 * 1024


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise SdkRefusal("INPUT_REDIRECT")


def build_opener():
    context = ssl.create_default_context()
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                                       urllib.request.HTTPSHandler(context=context))


def _url_class(url, rootfs_url):
    if url in (rootfs_url, rootfs_url + ".sig") and url.startswith(ROOTFS_URL_PREFIX):
        return "rootfs"
    if PACKAGE_URL_RE.fullmatch(url) is not None:
        return "package"
    raise SdkRefusal("INPUT_URL")


class AnonymousFetcher:
    """Real side effects (network). Tests substitute an object with ``fetch``."""

    def __init__(self, *, opener_factory=build_opener, clock=time.monotonic):
        self._opener_factory = opener_factory
        self._clock = clock

    def fetch(self, url, destination, size, sha256, deadline, *, rootfs_url):
        require(isinstance(url, str), "INPUT_URL")
        kind = _url_class(url, rootfs_url)
        limit = MAX_ROOTFS_BYTES if kind == "rootfs" else MAX_PACKAGE_BYTES
        if url.endswith(".sig"):
            limit = MAX_SIGNATURE_BYTES
        require(type(size) is int and 0 < size <= limit, "INPUT_SIZE")
        seconds = ROOTFS_SECONDS if kind == "rootfs" else PER_PACKAGE_SECONDS
        file_deadline = min(deadline, self._clock() + seconds)
        require(self._clock() <= file_deadline, "INPUT_TIMEOUT")
        total = 0
        try:
            with self._opener_factory().open(url, timeout=CONNECT_TIMEOUT_SECONDS) as response, \
                    Path(destination).open("xb") as output:
                require(response.status == 200 and response.geturl() == url, "INPUT_TRANSPORT")
                require(response.headers.get("Content-Length") == str(size), "INPUT_SIZE")
                while True:
                    require(self._clock() <= file_deadline, "INPUT_TIMEOUT")
                    chunk = response.read(min(1024 * 1024, size - total + 1))
                    if not chunk:
                        break
                    total += len(chunk)
                    require(total <= size, "INPUT_SIZE")
                    output.write(chunk)
        except SdkRefusal:
            raise
        except (OSError, ValueError, http.client.HTTPException):
            raise SdkRefusal("INPUT_TRANSPORT") from None
        require(total == size, "INPUT_SIZE")
        check_file(Path(destination), size, sha256)
