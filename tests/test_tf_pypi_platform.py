"""Platform-constrained artifacts, runtime mismatch and unsupported sdist hosts."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from rs9.tf_pypi_archive import AdmissionError
from rs9.tf_pypi_backend import build_pair, names, sdist_entries, wheel_entries, write_zip
from rs9.tf_pypi_platform import build_target, host_key
from rs9.tf_pypi_launcher import check_platform
from rs9.tf_pypi_verify import verify_pair
from tests.tf_pypi_fixtures import fixture


class PlatformTests(unittest.TestCase):
    def test_unsupported_host_and_musl_refuse(self):
        for system, machine, libc in [("Windows", "AMD64", ""), ("Linux", "x86_64", "musl"),
                                      ("Linux", "ppc64", "glibc")]:
            with self.subTest(system=system), patch("platform.system", return_value=system), \
                    patch("platform.machine", return_value=machine), patch("platform.libc_ver", return_value=(libc, "1")):
                with self.assertRaises(AdmissionError):
                    host_key()

    def test_only_explicit_qualified_target_can_build(self):
        pin, data = fixture()
        for target in ("win32-x64", "linux-x64-gnu", "darwin-x64"):
            with self.subTest(target=target), self.assertRaises(AdmissionError):
                build_target(pin, target)
        with patch("rs9.tf_pypi_platform.host_key", return_value="linux-x64-gnu"), self.assertRaises(AdmissionError):
            wheel_entries(pin, data)
        # CI may reproduce a qualified target without asserting that CI is that host.
        with patch("rs9.tf_pypi_platform.host_key", return_value="linux-x64-gnu"):
            self.assertTrue(wheel_entries(pin, data, target="darwin-arm64"))

    def test_platform_wheel_cannot_be_relabelled_or_claim_purelib(self):
        pin, data = fixture()
        for mutation in ("filename", "tag", "purelib", "native"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve()
                build_pair(pin, data, root)
                wheel = next(root.glob("*.whl"))
                files = wheel_entries(pin, data)
                info = names(pin)[2]
                if mutation == "filename":
                    wheel.rename(wheel.with_name(names(pin)[1] + "-py3-none-any.whl"))
                else:
                    if mutation == "native":
                        files[names(pin)[0] + "/payload/package/surplus.node"] = (b"\x7fELF", 0o644)
                    else:
                        header = files[info + "/WHEEL"][0]
                        files[info + "/WHEEL"] = (header.replace(b"false", b"true") if mutation == "purelib"
                                                 else header.replace(b"macosx_11_0_arm64", b"any"), 0o644)
                    wheel.write_bytes(write_zip(files))
                with self.assertRaises(AdmissionError):
                    verify_pair(pin, root)

    def test_node_platform_and_libc_preflight_reject_mismatch(self):
        from subprocess import CompletedProcess
        for facts in ({"platform": "darwin", "arch": "x64"}, {"platform": "linux", "arch": "arm64", "glibc": None}):
            result = CompletedProcess([], 0, json.dumps(facts), "")
            with patch("rs9.tf_pypi_launcher.PLATFORM_KEY", "darwin-arm64", create=True), \
                    patch("rs9.tf_pypi_launcher.subprocess.run", return_value=result), self.assertRaisesRegex(RuntimeError, "TF_PYPI_NODE_PLATFORM"):
                check_platform("/fixture/node")

    def test_sdist_contains_all_backend_modules_and_rs9_license(self):
        pin, data = fixture()
        from rs9.tf_pypi_backend import HELPERS
        entries = sdist_entries(pin, data)
        for helper in HELPERS:
            self.assertIn("_rs9_build/rs9/" + helper, entries)
        self.assertEqual(entries["RS9-LICENSE"], entries["_rs9_build/rs9/RS9-LICENSE"])
