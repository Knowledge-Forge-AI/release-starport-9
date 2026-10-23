"""Every remote state remains a read-only observation, separate from READY."""
import copy
import pickle
import unittest

from rs9.tf_pypi_archive import AdmissionError, canonical, fail, sha256
from rs9.tf_pypi_model import load_pin
from rs9.tf_pypi_remote import (
    _FETCH_TOKENS,
    _ObserverAdmissionError,
    _project_state_for,
    _verified_file,
    _version_rows,
    approved_state,
    exact_state,
    project_state,
)


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


# S1a observer tests. Everything below is offline and uses injected getters or fetch callables.
SOLAR = "theme-forge-solar-sail"
DV = "0.2.1.post1"
PROJECT_URL = "https://pypi.org/pypi/" + SOLAR + "/json"
VERSION_URL = "https://pypi.org/pypi/" + SOLAR + "/" + DV + "/json"
APP_VERSION_URL = "https://pypi.org/pypi/" + SOLAR + "/0.2.1/json"
FILE_BASE = "https://files.pythonhosted.org/packages/ab/cd/"
JSON_LIMIT = 32 * 1024 ** 2
FILES = {
    "theme_forge_solar_sail-0.2.1.post1-py3-none-macosx_11_0_arm64.whl": b"wheel-darwin",
    "theme_forge_solar_sail-0.2.1.post1-py3-none-manylinux_2_28_aarch64.whl": b"wheel-arm64",
    "theme_forge_solar_sail-0.2.1.post1-py3-none-manylinux_2_28_x86_64.whl": b"wheel-x64",
    "theme_forge_solar_sail-0.2.1.post1.tar.gz": b"sdist",
}
APP_FILES = {"theme_forge_solar_sail-0.2.1-py3-none-macosx_11_0_arm64.whl": b"old-wheel",
             "theme_forge_solar_sail-0.2.1.tar.gz": b"old-sdist"}
MARKER = "rs9-leak-marker-5c1e"


def file_rows(files):
    return [{"filename": name, "size": len(body), "digests": {"sha256": sha256(body)},
             "yanked": False, "url": FILE_BASE + name} for name, body in sorted(files.items())]


class FakeFetch:
    """URL -> bytes map recording (url, limit); failures maps URL -> (code, cause or None)."""

    def __init__(self, values, failures=None, override=None):
        self.values, self.failures, self.override, self.calls = values, failures or {}, override or {}, []

    def __call__(self, url, limit):
        self.calls.append((url, limit))
        if url in self.failures:
            code, cause = self.failures[url]
            if cause is None:
                fail(code)
            raise _ObserverAdmissionError("TF_PYPI_" + code, cause)
        if url in self.override:
            return self.override[url]
        if url not in self.values:
            raise AssertionError("unexpected fetch")
        return self.values[url]


class ObserverFixture(unittest.TestCase):
    def setUp(self):
        self.approved = {name: (len(body), sha256(body)) for name, body in FILES.items()}

    def values(self, *, rows=None, project=None, version_doc=None, files=FILES):
        values = {
            PROJECT_URL: canonical(project if project is not None else {
                "info": {"name": SOLAR, "version": "0.2.1", "description": MARKER},
                "releases": {"0.2.1": [{}], DV: [{}]},
            }),
            VERSION_URL: canonical(version_doc if version_doc is not None else {
                "info": {"name": SOLAR, "version": DV},
                "urls": file_rows(files) if rows is None else rows,
            }),
        }
        values.update({FILE_BASE + name: body for name, body in files.items()})
        return values

    def observe(self, fetch):
        return approved_state(SOLAR, DV, self.approved, fetch)

    def assert_outcome(self, result, state, code):
        self.assertEqual((result["state"], result["code"]), (state, code))
        self.assertNotIn("bodies", result)
        self.assertNotIn(MARKER, repr(result))


class LegacyCauseRegressionTests(unittest.TestCase):
    def setUp(self):
        self.pin = load_pin(SOLAR)

    def getter(self, values, absent=()):
        calls = []

        def get(url):
            calls.append(url)
            if url in absent:
                fail("REMOTE_ABSENT")
            if url not in values:
                fail("REMOTE_UNKNOWN")
            body = values[url]
            return body if isinstance(body, bytes) else canonical(body)
        get.calls = calls
        return get

    def test_project_state_results_and_causes_per_branch(self):
        listed = {"info": {"name": SOLAR}, "releases": {DV: []}}
        unlisted = {"info": {"name": SOLAR}, "releases": {"0.2.1": []}}
        cases = (
            ({PROJECT_URL: listed}, (), ("present-unverified", None)),
            ({PROJECT_URL: b"not json"}, (), ("unknown", "metadata-schema")),
            ({PROJECT_URL: b"[]"}, (), ("unknown", "metadata-schema")),
            ({PROJECT_URL: {"releases": []}}, (), ("unknown", "metadata-schema")),
            ({PROJECT_URL: {"releases": {}}}, (), ("conflict", "metadata-schema")),
            ({PROJECT_URL: {"info": [], "releases": {}}}, (), ("conflict", "metadata-schema")),
            ({PROJECT_URL: {"info": {"name": 7}, "releases": {}}}, (), ("conflict", "metadata-schema")),
            ({PROJECT_URL: {"info": {"name": "other"}, "releases": {}}}, (), ("conflict", "project-name-mismatch")),
            ({PROJECT_URL: {"info": {"name": SOLAR}, "releases": {"0.2.1-post1": []}}}, (),
             ("conflict", "version-normalization-collision")),
            ({}, (PROJECT_URL,), ("absent", "project-absent")),
            ({}, (), ("unknown", "transport")),
            ({PROJECT_URL: unlisted}, (VERSION_URL,), ("version-absent", "version-absent")),
            ({PROJECT_URL: unlisted, VERSION_URL: b"{}"}, (), ("unknown", "version-inconsistent")),
            ({PROJECT_URL: unlisted}, (), ("unknown", "transport")),
        )
        for values, absent, expected in cases:
            with self.subTest(expected=expected, values=sorted(values)):
                self.assertEqual(project_state(self.pin, self.getter(values, absent)), expected[0])
                self.assertEqual(_project_state_for(SOLAR, DV, self.getter(values, absent)), expected)

    def test_project_state_never_reads_info_version(self):
        get = self.getter({PROJECT_URL: {"info": {"name": SOLAR, "version": "0.2.1"},
                                         "releases": {"0.2.1": []}}}, (VERSION_URL,))
        self.assertEqual(project_state(self.pin, get), "version-absent")
        self.assertEqual(get.calls, [PROJECT_URL, VERSION_URL])

    def test_version_rows_codes_are_unchanged(self):
        rows = file_rows(FILES)
        cases = (
            (b"not json", "TF_PYPI_JSON", None),
            ({"urls": rows}, "TF_PYPI_REMOTE_UNKNOWN", "metadata-schema"),
            ({"info": {"name": "other", "version": DV}, "urls": rows}, "TF_PYPI_REMOTE_CONFLICT",
             "version-identity-mismatch"),
            ({"info": {"name": SOLAR, "version": "0.2.1"}, "urls": rows}, "TF_PYPI_REMOTE_CONFLICT",
             "version-identity-mismatch"),
            ({"info": {"name": SOLAR, "version": None}, "urls": rows}, "TF_PYPI_REMOTE_CONFLICT", "metadata-schema"),
            ({"info": {"name": SOLAR, "version": DV}, "urls": []}, "TF_PYPI_REMOTE_UNKNOWN", "metadata-schema"),
            ({"info": {"name": SOLAR, "version": DV}}, "TF_PYPI_REMOTE_UNKNOWN", "metadata-schema"),
        )
        for doc, code, cause in cases:
            with self.subTest(code=code, cause=cause):
                with self.assertRaises(AdmissionError) as caught:
                    _version_rows(self.pin, self.getter({VERSION_URL: doc}))
                self.assertEqual((caught.exception.code, str(caught.exception)), (code, code))
                self.assertEqual(repr(caught.exception), f"AdmissionError({code!r})")
                self.assertEqual(getattr(caught.exception, "cause", None), cause)
        self.assertEqual(_version_rows(self.pin, self.getter({VERSION_URL: {
            "info": {"name": SOLAR, "version": DV}, "urls": rows}})), rows)

    def test_verified_file_codes_and_check_order_are_unchanged(self):
        name = min(FILES)
        good = file_rows(FILES)[0]
        cases = (
            ("not-a-row", "TF_PYPI_REMOTE_UNKNOWN"),
            ({**good, "filename": "foreign.whl"}, "TF_PYPI_REMOTE_CONFLICT"),
            ({**good, "filename": "foreign.whl", "url": "https://evil.example/x"}, "TF_PYPI_REMOTE_CONFLICT"),
            ({**good, "filename": None}, "TF_PYPI_REMOTE_CONFLICT"),
            ({**good, "yanked": True}, "TF_PYPI_REMOTE_CONFLICT"),
            ({**good, "yanked": None}, "TF_PYPI_REMOTE_CONFLICT"),
            ({**good, "size": True}, "TF_PYPI_REMOTE_CONFLICT"),
            ({**good, "size": 100}, "TF_PYPI_REMOTE_CONFLICT"),
            ({**good, "digests": {"sha256": "0" * 64}}, "TF_PYPI_REMOTE_CONFLICT"),
            ({**good, "digests": None}, "TF_PYPI_REMOTE_CONFLICT"),
            ({**good, "yanked": True, "url": "https://evil.example/x"}, "TF_PYPI_REMOTE_CONFLICT"),
            ({**good, "url": "https://evil.example/x"}, "TF_PYPI_REMOTE_UNKNOWN"),
            ({**good, "url": None}, "TF_PYPI_REMOTE_UNKNOWN"),
        )
        for row, code in cases:
            get = self.getter({FILE_BASE + name: FILES[name]})
            with self.subTest(row=row, code=code):
                with self.assertRaises(AdmissionError) as caught:
                    _verified_file(row, FILES, get)
                self.assertEqual((caught.exception.code, str(caught.exception)), (code, code))
                self.assertEqual(get.calls, [])
        with self.assertRaises(AdmissionError) as caught:
            _verified_file(good, FILES, self.getter({FILE_BASE + name: b"wrong"}))
        self.assertEqual(caught.exception.code, "TF_PYPI_REMOTE_CONFLICT")
        get = self.getter({FILE_BASE + name: FILES[name]})
        self.assertEqual(_verified_file(good, FILES, get), name)
        self.assertEqual(get.calls, [FILE_BASE + name])

    def test_exact_state_keeps_legacy_results_for_malformed_metadata(self):
        project = {"info": {"name": SOLAR}, "releases": {DV: []}}
        for key, value in (("yanked", None), ("size", "12"), ("digests", {}), ("filename", 3)):
            rows = file_rows(FILES)
            rows[0][key] = value
            get = self.getter({PROJECT_URL: project,
                               VERSION_URL: {"info": {"name": SOLAR, "version": DV}, "urls": rows}})
            with self.subTest(key=key):
                self.assertEqual(exact_state(self.pin, FILES, get), {"state": "conflict", "missing": []})
        get = self.getter({PROJECT_URL: {"info": {"name": 7}, "releases": {}}})
        self.assertEqual(exact_state(self.pin, FILES, get), {"state": "conflict", "missing": []})

    def test_private_error_keeps_the_code_only_admission_surface(self):
        code = "TF_PYPI_REMOTE_CONFLICT"
        private, legacy = _ObserverAdmissionError(code, "surplus-file"), AdmissionError(code)
        self.assertIsInstance(private, AdmissionError)
        self.assertIsInstance(private, ValueError)
        for view in (lambda e: e.code, str, repr, lambda e: e.args):
            self.assertEqual(view(private), view(legacy))
        self.assertNotIn("surplus", str(private) + repr(private))
        for clone in (copy.copy(private), pickle.loads(pickle.dumps(private))):
            self.assertEqual((type(clone), clone.code, clone.cause, clone.args),
                             (_ObserverAdmissionError, code, "surplus-file", (code,)))
        for cause in (None, "", "conflict", MARKER, "http-600", "pypi-limit", ["limit"], b"limit"):
            with self.subTest(cause=cause), self.assertRaises(RuntimeError):
                _ObserverAdmissionError(code, cause)


class ApprovedStateTests(ObserverFixture):
    def test_exact_reads_only_the_distribution_version_with_per_file_bounds(self):
        fetch = FakeFetch(self.values())
        result = self.observe(fetch)
        self.assertEqual(result, {"state": "published-exact", "code": "pypi-distribution-exact",
                                  "observed": {n: d for n, (_, d) in sorted(self.approved.items())},
                                  "missing": [], "bodies": FILES})
        self.assertEqual(fetch.calls, [(PROJECT_URL, JSON_LIMIT), (VERSION_URL, JSON_LIMIT)]
                         + [(FILE_BASE + n, len(FILES[n])) for n in sorted(FILES)])

    def test_coexisting_application_release_is_never_consulted(self):
        values = self.values()
        values[APP_VERSION_URL] = canonical({"info": {"name": SOLAR, "version": "0.2.1"},
                                             "urls": file_rows(APP_FILES)})
        values.update({FILE_BASE + n: b for n, b in APP_FILES.items()})
        fetch = FakeFetch(values)
        self.assertEqual(self.observe(fetch)["state"], "published-exact")
        called = {url for url, _ in fetch.calls}
        self.assertNotIn(APP_VERSION_URL, called)
        self.assertFalse(called & {FILE_BASE + n for n in APP_FILES})

    def test_application_release_alone_is_version_absent_without_fallback(self):
        values = self.values(project={"info": {"name": SOLAR, "version": "0.2.1"},
                                      "releases": {"0.2.1": [{}]}}, files=APP_FILES)
        values[APP_VERSION_URL] = canonical({"info": {"name": SOLAR, "version": "0.2.1"},
                                             "urls": file_rows(APP_FILES)})
        fetch = FakeFetch(values, {VERSION_URL: ("REMOTE_ABSENT", "http-404")})
        result = self.observe(fetch)
        self.assertEqual(result, {"state": "version-absent", "code": "pypi-distribution-version-absent",
                                  "observed": {}, "missing": sorted(FILES)})
        self.assertEqual([url for url, _ in fetch.calls], [PROJECT_URL, VERSION_URL])

    def test_project_absent_only_from_an_absent_project_read(self):
        for cause in ("http-404", None):
            fetch = FakeFetch({}, {PROJECT_URL: ("REMOTE_ABSENT", cause)})
            with self.subTest(cause=cause):
                self.assertEqual(self.observe(fetch), {"state": "absent", "code": "pypi-project-absent",
                                                       "observed": {}, "missing": sorted(FILES)})

    def test_inconsistent_or_unreadable_remote_is_unknown_never_absent(self):
        unlisted = {"info": {"name": SOLAR}, "releases": {"0.2.1": []}}
        cases = (
            ({}, {PROJECT_URL: ("REMOTE_UNKNOWN", "http-404")}, "pypi-transport-unknown"),
            ({}, {PROJECT_URL: ("REMOTE_UNKNOWN", "http-500")}, "pypi-transport-unknown"),
            ({}, {PROJECT_URL: ("REMOTE_UNKNOWN", "limit")}, "pypi-limit"),
            ({}, {PROJECT_URL: ("REMOTE_UNKNOWN", "tls-certificate-verify-failed")},
             "pypi-tls-certificate-verify-failed"),
            ({}, {PROJECT_URL: ("REMOTE_UNKNOWN", "redirect")}, "pypi-transport-unknown"),
            ({}, {PROJECT_URL: ("REMOTE_UNKNOWN", "timeout")}, "pypi-transport-unknown"),
            ({}, {PROJECT_URL: ("REMOTE_UNKNOWN", None)}, "pypi-transport-unknown"),
            ({}, {PROJECT_URL: ("REMOTE_CONFLICT", None)}, "pypi-transport-unknown"),
            ({}, {PROJECT_URL: ("REMOTE_UNKNOWN", "surplus-file")}, "pypi-transport-unknown"),
            ({PROJECT_URL: canonical(unlisted), VERSION_URL: b"{}"}, {}, "pypi-version-inconsistent"),
            ({PROJECT_URL: canonical(unlisted)}, {VERSION_URL: ("REMOTE_UNKNOWN", "http-503")},
             "pypi-transport-unknown"),
            (self.values(), {VERSION_URL: ("REMOTE_ABSENT", "http-404")}, "pypi-version-inconsistent"),
            (self.values(), {VERSION_URL: ("REMOTE_UNKNOWN", "limit")}, "pypi-limit"),
            (self.values(), {VERSION_URL: ("REMOTE_UNKNOWN", "protocol")}, "pypi-protocol"),
        )
        for values, failures, code in cases:
            with self.subTest(failures=failures, code=code):
                result = self.observe(FakeFetch(values, failures))
                self.assert_outcome(result, "unknown", code)
                self.assertEqual(result["missing"], [])

    def test_one_conflict_per_closed_code_without_downloads_for_metadata(self):
        name = min(FILES)
        changed_digest = "1" * 64

        def rows_with(**change):
            rows = file_rows(FILES)
            rows[0].update(change)
            return rows
        cases = (
            ({"project": {"info": {"name": "other"}, "releases": {DV: []}}}, "pypi-project-name-mismatch"),
            ({"project": {"info": {"name": SOLAR}, "releases": {"0.2.1": [], "0.2.1-post1": []}}},
             "pypi-version-normalization-collision"),
            ({"version_doc": {"info": {"name": "other", "version": DV}, "urls": file_rows(FILES)}},
             "pypi-version-identity-mismatch"),
            ({"version_doc": {"info": {"name": SOLAR, "version": "0.2.1"}, "urls": file_rows(FILES)}},
             "pypi-version-identity-mismatch"),
            ({"rows": file_rows(FILES) + [{**file_rows(FILES)[0], "filename": "surplus.whl"}]},
             "pypi-surplus-file"),
            ({"rows": rows_with(size=999)}, "pypi-file-changed"),
            ({"rows": rows_with(digests={"sha256": changed_digest})}, "pypi-file-changed"),
            ({"rows": rows_with(yanked=True)}, "pypi-file-yanked"),
            ({"rows": file_rows(FILES) + file_rows(FILES)[:1]}, "pypi-duplicate-file"),
        )
        for change, code in cases:
            fetch = FakeFetch(self.values(**change))
            with self.subTest(code=code, change=sorted(change)):
                result = self.observe(fetch)
                self.assert_outcome(result, "conflict", code)
                self.assertFalse([url for url, _ in fetch.calls if url.startswith(FILE_BASE)])
                self.assertTrue(set(result["observed"]) <= set(FILES))
        result = self.observe(FakeFetch(self.values(rows=rows_with(digests={"sha256": changed_digest}))))
        self.assertEqual(result["observed"], {name: changed_digest})

    def test_complete_bounded_body_that_differs_is_bytes_conflict(self):
        name = min(FILES)
        for served in (FILES[name][:-1], b"x" * len(FILES[name]), b""):
            fetch = FakeFetch(self.values(), override={FILE_BASE + name: served})
            with self.subTest(served=served):
                result = self.observe(fetch)
                self.assert_outcome(result, "conflict", "pypi-bytes-differ")
                self.assertEqual(result["observed"][name], sha256(served))

    def test_malformed_metadata_is_unknown_not_conflict(self):
        def rows_with(**change):
            rows = file_rows(FILES)
            rows[0].update(change)
            return rows
        cases = [
            {"project": {"releases": {}}},
            {"project": {"info": [], "releases": {DV: []}}},
            {"project": {"info": {"name": 7}, "releases": {DV: []}}},
            {"project": {"info": {"name": SOLAR}, "releases": []}},
            {"project": []},
            {"version_doc": {"urls": file_rows(FILES)}},
            {"version_doc": {"info": {"name": None, "version": DV}, "urls": file_rows(FILES)}},
            {"version_doc": {"info": {"name": SOLAR, "version": 1}, "urls": file_rows(FILES)}},
            {"version_doc": {"info": {"name": SOLAR, "version": DV}, "urls": []}},
            {"version_doc": {"info": {"name": SOLAR, "version": DV}, "urls": {}}},
            {"rows": ["not-a-row"]},
            {"rows": rows_with(filename=None)},
            {"rows": [{k: v for k, v in file_rows(FILES)[0].items() if k != "filename"}]},
            {"rows": [{k: v for k, v in file_rows(FILES)[0].items() if k != "yanked"}]},
            {"rows": rows_with(yanked="false")},
            {"rows": rows_with(yanked=0)},
            {"rows": rows_with(yanked=True, size="12")},
            {"rows": rows_with(size=True)},
            {"rows": rows_with(size="12")},
            {"rows": rows_with(size=12.0)},
            {"rows": rows_with(digests=None)},
            {"rows": rows_with(digests={})},
            {"rows": rows_with(digests={"sha256": "A" * 64})},
            {"rows": rows_with(digests={"sha256": MARKER})},
        ]
        for change in cases:
            fetch = FakeFetch(self.values(**change))
            with self.subTest(change=change):
                self.assert_outcome(self.observe(fetch), "unknown", "pypi-metadata-schema")
                self.assertFalse([url for url, _ in fetch.calls if url.startswith(FILE_BASE)])
        for doc_url in (PROJECT_URL, VERSION_URL):
            with self.subTest(invalid_json=doc_url):
                fetch = FakeFetch(self.values(), override={doc_url: b"{" + MARKER.encode()})
                self.assert_outcome(self.observe(fetch), "unknown", "pypi-metadata-schema")

    def test_foreign_file_host_is_unknown(self):
        malformed_authorities = ("https://files.pythonhosted.org:abc/x.whl", "https://files.pythonhosted.org:99999/x.whl",
                                 "https://[" + MARKER + "/x.whl")
        for url in ("https://evil.example/" + MARKER, "http://files.pythonhosted.org/x.whl", None,
                    *malformed_authorities):
            rows = file_rows(FILES)
            rows[0]["url"] = url
            fetch = FakeFetch(self.values(rows=rows))
            with self.subTest(url=url):
                self.assert_outcome(self.observe(fetch), "unknown", "pypi-file-host-unknown")
                self.assertFalse([u for u, _ in fetch.calls if u.startswith(FILE_BASE)])

    def test_file_fetch_failures_are_unknown_tokens_never_absent_or_conflict(self):
        name = min(FILES)
        cases = (
            (("REMOTE_UNKNOWN", "limit"), "pypi-limit"),
            (("REMOTE_UNKNOWN", "incomplete-body"), "pypi-incomplete-body"),
            (("REMOTE_UNKNOWN", "protocol"), "pypi-protocol"),
            (("REMOTE_UNKNOWN", "tls-unexpected-eof"), "pypi-tls-unexpected-eof"),
            (("REMOTE_UNKNOWN", "http-500"), "pypi-transport-unknown"),
            (("REMOTE_ABSENT", "http-404"), "pypi-transport-unknown"),
            (("REMOTE_ABSENT", None), "pypi-transport-unknown"),
            (("REMOTE_UNKNOWN", None), "pypi-transport-unknown"),
            (("REMOTE_CONFLICT", None), "pypi-transport-unknown"),
            (("REMOTE_CONFLICT", "file-changed"), "pypi-transport-unknown"),
            (("REMOTE_UNKNOWN", "surplus-file"), "pypi-transport-unknown"),
        )
        for failure, code in cases:
            with self.subTest(failure=failure):
                result = self.observe(FakeFetch(self.values(), {FILE_BASE + name: failure}))
                self.assert_outcome(result, "unknown", code)

    def test_fetch_contract_violations_are_unknown(self):
        name = min(FILES)
        for served, code in ((FILES[name] + b"!", "pypi-limit"), ("wheel-darwin", "pypi-protocol"),
                             (bytearray(FILES[name]), "pypi-protocol")):
            with self.subTest(served=served):
                fetch = FakeFetch(self.values(), override={FILE_BASE + name: served})
                self.assert_outcome(self.observe(fetch), "unknown", code)

    def test_unlisted_approved_file_is_incomplete(self):
        rows = file_rows(FILES)
        result = self.observe(FakeFetch(self.values(rows=rows[:3])))
        self.assertEqual(result, {"state": "incomplete", "code": "pypi-file-missing",
                                  "observed": {r["filename"]: r["digests"]["sha256"] for r in rows[:3]},
                                  "missing": [rows[3]["filename"]]})

    def test_first_failing_row_in_listed_order_decides(self):
        rows = file_rows(FILES)
        malformed = {**rows[0], "yanked": None}
        surplus = {**rows[1], "filename": "surplus.whl"}
        self.assert_outcome(self.observe(FakeFetch(self.values(rows=[malformed, surplus]))),
                            "unknown", "pypi-metadata-schema")
        self.assert_outcome(self.observe(FakeFetch(self.values(rows=[surplus, malformed]))),
                            "conflict", "pypi-surplus-file")
        # Per-row checks run before duplicate detection for that row.
        self.assert_outcome(self.observe(FakeFetch(self.values(rows=[rows[0], {**rows[0], "yanked": True}]))),
                            "conflict", "pypi-file-yanked")
        self.assert_outcome(self.observe(FakeFetch(self.values(rows=[rows[0], {**rows[0], "size": None}]))),
                            "unknown", "pypi-metadata-schema")

    def test_untrusted_inputs_are_refused_before_any_fetch(self):
        good = dict(self.approved)
        name = min(good)
        bad_approved = ({}, None, [], {name: list(good[name])}, {name: (0, good[name][1])},
                        {name: (True, good[name][1])}, {name: (-1, good[name][1])},
                        {name: (5, good[name][1].upper())}, {name: (5, "0" * 63)}, {name: (5,)},
                        {"../" + name: good[name]}, {"": good[name]}, {7: good[name]})
        calls = []
        for approved in bad_approved:
            with self.subTest(approved=approved), self.assertRaises(AdmissionError) as caught:
                approved_state(SOLAR, DV, approved, lambda url, limit: calls.append(url))
            self.assertEqual(caught.exception.code, "TF_PYPI_REMOTE_INPUT")
        for project, dv, fetch in ((SOLAR + "/../x", DV, len), ("", DV, len), (None, DV, len),
                                   (SOLAR, "0.2.1/../0.2.1", len), (SOLAR, "", len), (SOLAR, DV, None)):
            with self.subTest(project=project, dv=dv), self.assertRaises(AdmissionError):
                approved_state(project, dv, good, fetch)
        self.assertEqual(calls, [])

    def test_unexpected_exceptions_are_not_swallowed(self):
        class TrustInputFailure(Exception):
            pass

        def fetch(url, limit):
            raise TrustInputFailure()
        with self.assertRaises(TrustInputFailure):
            self.observe(fetch)

    def test_every_fetch_token_maps_to_unknown(self):
        name = min(FILES)
        for token in sorted(_FETCH_TOKENS):
            with self.subTest(token=token):
                result = self.observe(FakeFetch(self.values(), {FILE_BASE + name: ("REMOTE_UNKNOWN", token)}))
                self.assertEqual(result["state"], "unknown")
                self.assertTrue(result["code"].startswith("pypi-"))


if __name__ == "__main__":
    unittest.main()
