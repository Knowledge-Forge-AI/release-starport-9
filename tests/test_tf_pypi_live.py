"""Opt-in exact upstream byte tests. Skips are not product qualification."""
import os
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from rs9.tf_pypi_archive import AdmissionError
from rs9.tf_pypi_backend import build_pair
from rs9.tf_pypi_consumer import smoke
from rs9.tf_pypi_closure import load_dependencies
from rs9.tf_pypi_closure import DEPENDENCIES
from rs9.tf_pypi_intake import asset_url
from rs9.tf_pypi_model import PRODUCTS, intake, load_pin
from rs9.tf_pypi_publish import build, dependency_url, load_approval
from rs9.tf_pypi_verify import verify_pair
from tests.tf_pypi_fixtures import live_inputs


class RealInputConfigurationTests(unittest.TestCase):
    def test_optional_absent_inputs_skip(self):
        with patch.dict(os.environ, {}, clear=True), self.assertRaises(unittest.SkipTest):
            live_inputs(self)

    def test_required_absent_inputs_fail(self):
        with patch.dict(os.environ, {"RS9_TF_PYPI_REQUIRE_LIVE": "1"}, clear=True):
            with self.assertRaisesRegex(AssertionError, "RS9_TF_PYPI_INPUTS is required"):
                live_inputs(self)

    def test_configured_missing_inputs_fail_even_without_requirement(self):
        with tempfile.TemporaryDirectory() as directory:
            for required in (False, True):
                env = {"RS9_TF_PYPI_INPUTS": str(Path(directory) / "absent")}
                if required:
                    env["RS9_TF_PYPI_REQUIRE_LIVE"] = "1"
                with self.subTest(required=required), patch.dict(os.environ, env, clear=True):
                    with self.assertRaisesRegex(AssertionError, "input directory unavailable"):
                        live_inputs(self)


class RealBytesTests(unittest.TestCase):
    def setUp(self):
        self.inputs = live_inputs(self)

    def test_all_three_intakes(self):
        for product in PRODUCTS:
            pin = load_pin(product)
            with self.subTest(project=product):
                intake(pin, self.inputs / pin["asset"])

    def test_all_three_real_builds_match_committed_approved_artifacts(self):
        for product in PRODUCTS:
            with self.subTest(project=product), tempfile.TemporaryDirectory() as directory:
                # build verifies against the real committed approval, without a mock.
                approved = build(product, output=Path(directory).resolve() / "dist", inputs=self.inputs)
                self.assertEqual(approved["project"], product)

    def test_linux_download_fixture_rebuilds_exact_darwin_artifacts_without_execution(self):
        # This exercises CI's download branch with authenticated retained bytes.
        # It simulates Linux selection, not Linux execution or Darwin runtime.
        bodies = {asset_url(load_pin(p)): (self.inputs / load_pin(p)["asset"]).read_bytes()
                  for p in PRODUCTS}
        bodies.update({dependency_url(d): (self.inputs / d["asset"]).read_bytes() for d in DEPENDENCIES})
        requests = []

        class Response(io.BytesIO):
            status = 200
            def __init__(self, url):
                super().__init__(bodies[url])
                self.url = url
            def geturl(self):
                return self.url

        class Opener:
            def open(self, request, *, timeout):
                requests.append(request.full_url)
                return Response(request.full_url)

        with patch("platform.system", return_value="Linux"), \
                patch("platform.machine", return_value="x86_64"), \
                patch("platform.libc_ver", return_value=("glibc", "2.39")), \
                patch("sys.platform", "linux"), \
                patch("subprocess.Popen", side_effect=AssertionError("native execution attempted")), \
                patch("socket.socket", side_effect=AssertionError("network attempted")):
            for product in PRODUCTS:
                with self.subTest(product=product), tempfile.TemporaryDirectory() as directory:
                    approved = build(product, output=Path(directory).resolve() / "dist", opener=Opener())
                    self.assertEqual(approved, load_approval(product))
        self.assertCountEqual(requests, bodies)

    def test_pure_products_real_build_and_current_host_lifecycle(self):
        for product in ("theme-forge-stellar-loom", "theme-forge-solar-sail"):
            pin = load_pin(product)
            data, _ = intake(pin, self.inputs / pin["asset"])
            with self.subTest(project=product), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                build_pair(pin, data, root / "dist")
                verify_pair(pin, root / "dist")
                smoke(pin, root / "dist", root / "consumer",
                      offline_linux=os.environ.get("RS9_TF_PYPI_OFFLINE_LINUX") == "1")

    def test_burst_real_closure_build_and_host_lifecycle(self):
        pin = load_pin("theme-forge-stellar-burst")
        inputs = self.inputs
        data, _ = intake(pin, inputs / pin["asset"])
        dependencies = load_dependencies(inputs)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            build_pair(pin, data, root / "dist", dependencies)
            verify_pair(pin, root / "dist")
            smoke(pin, root / "dist", root / "consumer")
