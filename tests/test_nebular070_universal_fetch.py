"""Synthetic network and cache contracts; no actual network requests."""

import hashlib
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from rs9 import nebular070_universal_fetch as fetch


class Response:
    def __init__(self, body=b"abc", headers=None, url=None, on_read=None):
        self.body = io.BytesIO(body)
        self.headers = {"Content-Length": str(len(body))} if headers is None else headers
        self.status = 200
        self.url = url or "https://release-assets.githubusercontent.com/fixture?private-signature=fixture"
        self.on_read = on_read

    def read1(self, size):
        if self.on_read:
            self.on_read()
        return self.body.read(size)

    def read(self, size):
        raise AssertionError("A buffer-filling read can hide deadline progress")

    def geturl(self):
        return self.url

    def close(self):
        self.body.close()


class Opener:
    def __init__(self, response):
        self.response = response
        self.calls = 0

    def open(self, request, timeout):
        self.calls += 1
        self.request = request
        self.timeout = timeout
        return self.response


class UniversalFetchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.directory = self.root / "archives"
        name = "theme-forge-nebular-fusion-v0.7.0-aarch64-apple-darwin.app.tar.gz"
        self.asset = {"id": 1, "name": name, "size": 3,
                      "sha256": hashlib.sha256(b"abc").hexdigest(),
                      "url": "https://github.com/Knowledge-Forge-AI/theme-forge-nebular-fusion/releases/download/v0.7.0/" + name}
        self.path = self.directory / (self.asset["sha256"] + ".tgz")

    def test_verified_bytes_commit_atomically_and_cache_reuse_has_no_network(self):
        opener = Opener(Response())
        result = fetch.fetch_archive(self.asset, self.directory, opener=opener)
        self.assertEqual(result.archive, self.path)
        self.assertTrue(result.downloaded)
        self.assertEqual(self.path.read_bytes(), b"abc")
        self.assertEqual(result.redirect_hosts, ("release-assets.githubusercontent.com",))
        self.assertEqual(opener.request.get_header("Accept-encoding"), "identity")
        self.assertLessEqual(opener.timeout, 10)
        result = fetch.fetch_archive(self.asset, self.directory, opener=Opener(None))
        self.assertFalse(result.downloaded)
        self.assertEqual(result.redirect_hosts, ())
        self.assertFalse(list(self.directory.glob("*.part")))

    def test_explicit_setup_can_replace_a_corrupt_regular_archive(self):
        self.directory.mkdir()
        self.path.write_bytes(b"bad")
        before = self.path.stat().st_ino
        fetch.fetch_archive(self.asset, self.directory, opener=Opener(Response()))
        self.assertEqual(self.path.read_bytes(), b"abc")
        self.assertNotEqual(self.path.stat().st_ino, before)

    def test_network_or_integrity_failure_preserves_existing_and_unrelated_files(self):
        for label, response in (
            ("digest", Response(b"bad")),
            ("short", Response(b"ab", headers={})),
            ("long", Response(b"abcd", headers={})),
            ("length", Response(headers={"Content-Length": "4"})),
            ("encoding", Response(headers={"Content-Encoding": "gzip"})),
            ("transfer", Response(headers={"Transfer-Encoding": "chunked"})),
            ("host", Response(url="https://unapproved.invalid/fixture?secret=fixture")),
        ):
            with self.subTest(label=label):
                directory = self.root / label
                directory.mkdir()
                destination = directory / self.path.name
                destination.write_bytes(b"old")
                unrelated = directory / "keep"
                unrelated.write_bytes(b"preserve")
                with self.assertRaises(fetch.RuntimeDownloadError) as caught:
                    fetch.fetch_archive(self.asset, directory, opener=Opener(response))
                self.assertNotIn("secret", str(caught.exception))
                self.assertEqual(destination.read_bytes(), b"old")
                self.assertEqual(unrelated.read_bytes(), b"preserve")
                self.assertFalse(list(directory.glob("*.part")))

    def test_fixed_source_and_pin_types_are_enforced_before_network(self):
        cases = [{"url": self.asset["url"].replace("https:", "http:")},
                 {"url": self.asset["url"].replace("github.com", "user:password@github.com")},
                 {"name": "../outside"}, {"name": []}, {"size": True}, {"size": 0},
                 {"size": 65 * 1024 * 1024}, {"id": True}, {"sha256": "F" * 64},
                 {"url": self.asset["url"] + "?override=fixture"}]
        for change in cases:
            with self.subTest(change=tuple(change)):
                opener = Opener(None)
                with self.assertRaises(fetch.RuntimeDownloadError):
                    fetch.fetch_archive(dict(self.asset, **change), self.directory, opener=opener)
                self.assertEqual(opener.calls, 0)

    def test_symlink_hardlink_and_fifo_destinations_are_not_opened(self):
        for kind in ("symlink", "hardlink", "fifo"):
            directory = self.root / kind
            directory.mkdir()
            path = directory / self.path.name
            outside = self.root / (kind + "-outside")
            outside.write_bytes(b"abc")
            if kind == "symlink":
                path.symlink_to(outside)
            elif kind == "hardlink":
                os.link(outside, path)
            else:
                os.mkfifo(path)
            opener = Opener(None)
            with self.subTest(kind=kind), self.assertRaises(fetch.RuntimeDownloadError):
                fetch.fetch_archive(self.asset, directory, opener=opener)
            self.assertEqual(opener.calls, 0)
            self.assertEqual(outside.read_bytes(), b"abc")

    def test_destination_interference_prevents_replacement(self):
        self.directory.mkdir()
        self.path.write_bytes(b"old")
        response = Response(on_read=lambda: self.path.write_bytes(b"owner changed this"))
        with self.assertRaises(fetch.RuntimeDownloadError):
            fetch.fetch_archive(self.asset, self.directory, opener=Opener(response))
        self.assertEqual(self.path.read_bytes(), b"owner changed this")
        self.assertFalse(list(self.directory.glob("*.part")))

    def test_total_deadline_prevents_acceptance_of_a_late_stream(self):
        now = [0.0]
        response = Response(on_read=lambda: now.__setitem__(0, now[0] + 901))
        with self.assertRaises(fetch.RuntimeDownloadError):
            fetch.fetch_archive(self.asset, self.directory, opener=Opener(response), clock=lambda: now[0])
        self.assertFalse(self.path.exists())
        self.assertFalse(list(self.directory.glob("*.part")))

    def test_product_budget_allows_a_verified_stream_slower_than_two_minutes(self):
        now = [0.0]
        response = Response(on_read=lambda: now.__setitem__(0, now[0] + 61))
        result = fetch.fetch_archive(self.asset, self.directory, opener=Opener(response), clock=lambda: now[0])
        self.assertTrue(result.downloaded)
        self.assertGreater(now[0], 120)

    def test_transport_exception_payloads_are_not_retained(self):
        def fail():
            raise OSError("/private/fixture?token=PRIVATE_MARKER")
        with self.assertRaises(fetch.RuntimeDownloadError) as caught:
            fetch.fetch_archive(self.asset, self.directory, opener=Opener(Response(on_read=fail)))
        self.assertNotIn("PRIVATE_MARKER", str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)
        self.assertFalse(self.path.exists())

    def test_closed_failure_codes_and_tls_reason_survive_without_raw_context(self):
        import ssl
        import urllib.error
        for error, code in (
            (ssl.SSLCertVerificationError("PRIVATE_MARKER"), "TFNF_RUNTIME_TLS"),
            (urllib.error.URLError(ssl.SSLCertVerificationError("PRIVATE_MARKER")), "TFNF_RUNTIME_TLS"),
            (OSError("PRIVATE_MARKER"), "TFNF_RUNTIME_TRANSPORT"),
        ):
            def fail(*args, **kwargs):
                raise error
            with self.subTest(code=code), patch.object(Opener, "open", side_effect=fail):
                with self.assertRaises(fetch.RuntimeDownloadError) as caught:
                    fetch.fetch_archive(self.asset, self.directory, opener=Opener(None))
                self.assertEqual(caught.exception.code, code)
                self.assertNotIn("PRIVATE_MARKER", repr(caught.exception))
                self.assertIsNone(caught.exception.__cause__)
                self.assertIsNone(caught.exception.__context__)

    def test_unreadable_owned_regular_archive_can_be_replaced_without_reading_it(self):
        import errno
        self.directory.mkdir()
        self.path.write_bytes(b"bad")
        original = os.open
        def unreadable(path, flags, *args, **kwargs):
            if Path(path) == self.path and flags & os.O_NOFOLLOW:
                raise PermissionError(errno.EACCES, "PRIVATE_MARKER")
            return original(path, flags, *args, **kwargs)
        with patch.object(fetch.os, "open", side_effect=unreadable):
            value = fetch.fetch_archive(self.asset, self.directory, opener=Opener(Response()))
        self.assertTrue(value.downloaded)
        self.assertEqual(self.path.read_bytes(), b"abc")

    def test_temp_cleanup_failure_does_not_mask_commit_or_primary_failure(self):
        original = Path.lstat
        def cleanup_fails(path):
            if str(path).endswith(".part") and not path.exists():
                raise PermissionError("PRIVATE_MARKER")
            return original(path)
        with patch.object(Path, "lstat", cleanup_fails):
            result = fetch.fetch_archive(self.asset, self.directory, opener=Opener(Response()))
        self.assertTrue(result.downloaded)
        self.assertEqual(self.path.read_bytes(), b"abc")
        self.path.unlink()
        with patch.object(Path, "unlink", side_effect=PermissionError("PRIVATE_MARKER")):
            with self.assertRaises(fetch.RuntimeDownloadError) as caught:
                fetch.fetch_archive(self.asset, self.directory, opener=Opener(Response(b"bad")))
        self.assertEqual(caught.exception.code, "TFNF_RUNTIME_DIGEST")
        self.assertIsNone(caught.exception.__context__)

    def test_existing_dotdot_cache_alias_is_preserved_by_real_fetcher(self):
        (self.root / "anchor").mkdir()
        directory = self.root / "anchor" / ".." / "archives"
        result = fetch.fetch_archive(self.asset, directory, opener=Opener(Response()))
        self.assertEqual(result.archive, directory / self.path.name)
        self.assertEqual(result.archive.read_bytes(), b"abc")

    def test_two_processes_share_one_fetch_under_the_real_cache_lock(self):
        import json
        import select
        import subprocess
        import sys
        script = r'''
import fcntl, io, json, os, sys
from pathlib import Path
from rs9 import nebular070_universal_fetch as fetch
role, directory, spec = sys.argv[1:]
asset = json.loads(spec)
if role == "second":
    original = fcntl.flock
    def observed(fd, operation):
        if operation == fcntl.LOCK_EX:
            try:
                original(fd, operation | fcntl.LOCK_NB)
            except BlockingIOError:
                os.write(1, b"BLOCKED\n")
                return original(fd, operation)
            os.write(1, b"UNEXPECTED_UNLOCKED\n")
            return None
        return original(fd, operation)
    fcntl.flock = observed
class Response:
    status = 200
    headers = {"Content-Length": "3"}
    def __init__(self): self.body = io.BytesIO(b"abc")
    def geturl(self): return asset["url"]
    def read1(self, count): return self.body.read(count)
    def close(self): self.body.close()
class Opener:
    def open(self, request, timeout):
        if role != "first": raise AssertionError("a second network fetch occurred")
        os.write(1, b"FETCH_HELD\n")
        if sys.stdin.readline() != "GO\n": raise AssertionError("missing release barrier")
        return Response()
result = fetch.fetch_archive(asset, Path(directory), opener=Opener())
print(json.dumps({"downloaded": result.downloaded}), flush=True)
'''
        children = []
        def start(role):
            process = subprocess.Popen(
                [sys.executable, "-B", "-c", script, role, str(self.directory), json.dumps(self.asset)],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            children.append(process)
            return process
        def line(process):
            ready, _, _ = select.select([process.stdout], [], [], 10)
            self.assertTrue(ready, "synthetic child did not reach its bounded barrier")
            return process.stdout.readline()
        try:
            first = start("first")
            self.assertEqual(line(first), "FETCH_HELD\n")
            second = start("second")
            self.assertEqual(line(second), "BLOCKED\n")
            first.stdin.write("GO\n")
            first.stdin.flush()
            first_out, first_error = first.communicate(timeout=10)
            second_out, second_error = second.communicate(timeout=10)
            self.assertEqual((first.returncode, second.returncode), (0, 0), first_error + second_error)
            self.assertTrue(json.loads(first_out)["downloaded"])
            self.assertFalse(json.loads(second_out)["downloaded"])
            self.assertEqual(self.path.read_bytes(), b"abc")
        finally:
            for child in children:
                if child.poll() is None:
                    child.kill()
                child.communicate(timeout=10)

    def test_redirect_policy_rejects_other_origins_and_strips_authorization(self):
        import urllib.request
        hosts = []
        opener = fetch._opener(self.asset["url"], hosts, 120, lambda: 0)
        handler = next(h for h in opener.handlers if isinstance(h, urllib.request.HTTPRedirectHandler))
        request = urllib.request.Request(self.asset["url"], headers={
            "Authorization": "SYNTHETIC", "Proxy-Authorization": "SYNTHETIC_PROXY",
        })
        valid = "https://release-assets.githubusercontent.com/fixture?private-signature=fixture"
        redirected = handler.redirect_request(request, None, 302, "", {}, valid)
        self.assertIsNone(redirected.get_header("Authorization"))
        self.assertFalse(any(key.lower() in {"authorization", "proxy-authorization"}
                             for key, _ in redirected.header_items()))
        for target in ("http://release-assets.githubusercontent.com/a", "https://unapproved.invalid/a",
                       "https://user:password@release-assets.githubusercontent.com/a",
                       "https://release-assets.githubusercontent.com:444/a", valid + "#fragment"):
            with self.subTest(target=target), self.assertRaises(fetch.RuntimeDownloadError):
                handler.redirect_request(request, None, 302, "", {}, target)
        self.assertTrue(set(hosts) <= {"release-assets.githubusercontent.com"})

    def test_redirect_count_is_bounded(self):
        import urllib.request
        hosts = []
        opener = fetch._opener(self.asset["url"], hosts, 120, lambda: 0)
        handler = next(h for h in opener.handlers if isinstance(h, urllib.request.HTTPRedirectHandler))
        request = urllib.request.Request(self.asset["url"])
        for _ in range(3):
            request = handler.redirect_request(
                request, None, 302, "", {}, "https://release-assets.githubusercontent.com/fixture",
            )
        with self.assertRaises(fetch.RuntimeDownloadError):
            handler.redirect_request(request, None, 302, "", {}, "https://release-assets.githubusercontent.com/fixture")
