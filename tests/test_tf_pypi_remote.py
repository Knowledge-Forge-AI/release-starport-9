"""Every remote state remains a read-only observation, separate from READY."""
import unittest

from rs9.tf_pypi_archive import canonical, fail, sha256
from rs9.tf_pypi_model import load_pin
from rs9.tf_pypi_remote import exact_state, project_state


class RemoteTests(unittest.TestCase):
    def setUp(self):
        self.pin = load_pin("theme-forge-solar-sail")
        self.local = {"fixture.whl": b"wheel", "fixture.tar.gz": b"sdist"}
        self.url = "https://pypi.org/pypi/" + self.pin["project"] + "/json"
        self.version_url = self.url[:-5] + "/" + self.pin["version"] + "/json"

    def rows(self):
        return [{"filename": name, "size": len(body), "digests": {"sha256": sha256(body)},
                 "yanked": False, "url": "https://files.pythonhosted.org/" + name}
                for name, body in self.local.items()]

    def get(self, rows, *, project=None, wrong_bytes=False):
        values = {self.url: canonical(project if project is not None else {
                      "info": {"name": self.pin["project"]}, "releases": {self.pin["version"]: []}}),
                  self.version_url: canonical({"info": {"name": self.pin["project"], "version": self.pin["version"]}, "urls": rows})}
        values.update({"https://files.pythonhosted.org/" + name: (b"wrong" if wrong_bytes else body)
                       for name, body in self.local.items()})
        return lambda url: values[url]

    def test_absent_conflict_and_unknown_do_not_authorize_any_write(self):
        for code, expected in (("REMOTE_ABSENT", "absent"), ("REMOTE_UNKNOWN", "unknown")):
            result = exact_state(self.pin, self.local, lambda _: fail(code))
            self.assertEqual(result["state"], expected)
        self.assertEqual(exact_state(self.pin, self.local, self.get([], project={"releases": {}}))["state"], "conflict")
        for body in (b"not json", b"[]", b'{"releases":[]}'):
            self.assertEqual(project_state(self.pin, lambda _: body), "unknown")

    def test_exact_and_subset_require_downloaded_bytes(self):
        self.assertEqual(exact_state(self.pin, self.local, self.get(self.rows()))["state"], "published-exact")
        result = exact_state(self.pin, self.local, self.get(self.rows()[:1]))
        self.assertEqual(result, {"state": "incomplete", "missing": ["fixture.tar.gz"]})
        self.assertEqual(exact_state(self.pin, self.local, self.get(self.rows(), wrong_bytes=True))["state"], "conflict")

    def test_extra_duplicate_yanked_wrong_size_digest_and_url_refuse(self):
        for key, value in (("filename", "foreign.whl"), ("size", 100), ("size", True),
                           ("digests", {"sha256": "0" * 64}), ("yanked", True),
                           ("url", "https://evil.example/payload")):
            rows = self.rows()
            rows[0][key] = value
            with self.subTest(key=key):
                self.assertIn(exact_state(self.pin, self.local, self.get(rows))["state"], {"conflict", "unknown"})
        self.assertEqual(exact_state(self.pin, self.local, self.get(self.rows() * 2))["state"], "conflict")
        self.assertEqual(exact_state(self.pin, self.local, self.get([]))["state"], "unknown")

    def test_version_disappearing_after_project_read_is_unknown(self):
        good = self.get(self.rows())
        def get(url):
            return fail("REMOTE_ABSENT") if url == self.version_url else good(url)
        self.assertEqual(exact_state(self.pin, self.local, get)["state"], "unknown")
