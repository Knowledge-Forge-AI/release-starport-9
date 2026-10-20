"""Every remote state remains a read-only observation, separate from READY."""
import unittest

from rs9.tf_pypi_archive import canonical, fail, sha256
from rs9.tf_pypi_model import load_pin
from rs9.tf_pypi_remote import exact_state, project_state


class RemoteTests(unittest.TestCase):
    def setUp(self):
        self.pin = load_pin("theme-forge-solar-sail")
        self.dv = self.pin["distribution_version"]
        self.local = {
            "theme_forge_solar_sail-0.2.1.post1-py3-none-macosx_11_0_arm64.whl": b"wheel-darwin",
            "theme_forge_solar_sail-0.2.1.post1-py3-none-manylinux_2_28_aarch64.whl": b"wheel-arm64",
            "theme_forge_solar_sail-0.2.1.post1-py3-none-manylinux_2_28_x86_64.whl": b"wheel-x64",
            "theme_forge_solar_sail-0.2.1.post1.tar.gz": b"sdist",
        }
        self.url = "https://pypi.org/pypi/" + self.pin["project"] + "/json"
        self.version_url = self.url[:-5] + "/" + self.dv + "/json"

    def rows(self):
        return [{"filename": name, "size": len(body), "digests": {"sha256": sha256(body)},
                 "yanked": False, "url": "https://files.pythonhosted.org/" + name}
                for name, body in sorted(self.local.items())]

    def get(self, rows, *, project=None, version_info=None, wrong_bytes=False, version_absent=False):
        values = {
            self.url: canonical(project if project is not None else {
                "info": {"name": self.pin["project"]},
                "releases": {self.pin["version"]: [{}], self.dv: []},
            }),
            self.version_url: canonical(version_info if version_info is not None else {
                "info": {"name": self.pin["project"], "version": self.dv},
                "urls": rows,
            }),
        }
        values.update({"https://files.pythonhosted.org/" + name: (b"wrong" if wrong_bytes else body)
                       for name, body in self.local.items()})

        def reader(url):
            if version_absent and url == self.version_url:
                fail("REMOTE_ABSENT")
            return values[url]

        return reader

    def test_absent_version_absent_conflict_and_unknown_do_not_authorize_any_write(self):
        for code, expected in (("REMOTE_ABSENT", "absent"), ("REMOTE_UNKNOWN", "unknown")):
            result = exact_state(self.pin, self.local, lambda _: fail(code))
            self.assertEqual(result["state"], expected)
            self.assertEqual(result["missing"], sorted(self.local) if expected == "absent" else [])

        version_absent_project = {
            "info": {"name": self.pin["project"]},
            "releases": {self.pin["version"]: [{}]},
        }
        self.assertEqual(
            project_state(self.pin, self.get([], project=version_absent_project, version_absent=True)),
            "version-absent",
        )
        self.assertEqual(
            exact_state(self.pin, self.local, self.get([], project=version_absent_project, version_absent=True)),
            {"state": "version-absent", "missing": sorted(self.local)},
        )

        # Unlisted version in releases whose version endpoint returns 200 or transport error is unknown.
        self.assertEqual(
            project_state(self.pin, self.get(self.rows(), project=version_absent_project, version_absent=False)),
            "unknown",
        )
        def unlisted_transport_err(url):
            if url == self.url:
                return canonical(version_absent_project)
            fail("REMOTE_UNKNOWN")
        self.assertEqual(project_state(self.pin, unlisted_transport_err), "unknown")

        # Differently spelled equivalent of .post1 is a conflict.
        for eq in (
            "0.2.1-post1",
            "0.2.1_post1",
            "0.2.1.POST1",
            "0.2.1post1",
            "0.2.1.post-1",
            "0.2.1-r1",
            "0.2.1-rev1",
            "0.2.1-1",
            "v0.2.1.post1",
            "0!0.2.1.post1",
            "0.2.1.post01",
            "0.02.1.post1",
        ):
            with self.subTest(equivalent=eq):
                proj = {"info": {"name": self.pin["project"]}, "releases": {eq: []}}
                self.assertEqual(project_state(self.pin, self.get([], project=proj, version_absent=True)), "conflict")
                self.assertEqual(exact_state(self.pin, self.local, self.get([], project=proj, version_absent=True))["state"], "conflict")

        # Wrong info.name or version endpoint reporting upstream version instead of distribution_version -> conflict.
        self.assertEqual(exact_state(self.pin, self.local, self.get([], project={"releases": {}}))["state"], "conflict")
        wrong_ver_info = {"info": {"name": self.pin["project"], "version": self.pin["version"]}, "urls": self.rows()}
        self.assertEqual(exact_state(self.pin, self.local, self.get(self.rows(), version_info=wrong_ver_info))["state"], "conflict")

        for body in (b"not json", b"[]", b'{"releases":[]}'):
            self.assertEqual(project_state(self.pin, lambda _: body), "unknown")

    def test_exact_and_subset_require_downloaded_bytes(self):
        self.assertEqual(exact_state(self.pin, self.local, self.get(self.rows()))["state"], "published-exact")
        rows = self.rows()
        result = exact_state(self.pin, self.local, self.get(rows[:3]))
        self.assertEqual(result, {"state": "incomplete", "missing": [rows[3]["filename"]]})
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


if __name__ == "__main__":
    unittest.main()
