"""Synthetic adapter fixtures and explicit configuration for real-input tests."""
import copy
import io
import json
import os
from pathlib import Path

from rs9.tf_pypi_archive import sha256
from rs9.tf_pypi_backend import build_aggregate, write_tar
from rs9.tf_pypi_model import load_pin
from rs9.tf_pypi_verify import verify_aggregate

ROOT = Path(__file__).resolve().parents[1]


def live_inputs(testcase):
    """Skip only unrequested qualification; required or misconfigured inputs fail."""
    value = os.environ.get("RS9_TF_PYPI_INPUTS")
    if not value:
        if os.environ.get("RS9_TF_PYPI_REQUIRE_LIVE"):
            testcase.fail("RS9_TF_PYPI_INPUTS is required for live qualification")
        testcase.skipTest("exact release inputs not supplied")
    inputs = Path(value)
    testcase.assertTrue(inputs.is_dir(), "authenticated input directory unavailable")
    return inputs


def fixture(project="theme-forge-stellar-loom", *, changes=None, extra=None):
    pin = copy.deepcopy(load_pin(project))
    package = {"name": pin["npm_name"], "version": pin["version"], "license": pin["license"],
               "engines": {"node": ">=22"}, "bin": pin["bins"]}
    package.update(changes or {})
    files = {"package.json": (json.dumps(package).encode(), 0o644),
             "LICENSE": (b"Synthetic license fixture, not upstream legal bytes.\n", 0o644),
             "NOTICE": (b"Synthetic fixture only.\n", 0o644),
             "COMMERCIAL-LICENSE.md": (b"Synthetic commercial notice.\n", 0o644)}
    for command, target in pin["bins"].items():
        if command == "tfsl-batch":
            body = b"process.stdout.write('EMPTY_INPUT\\n');process.exit(1);\n"
        else:
            body = f"process.stdout.write({json.dumps(pin['version'] + chr(10))});\n".encode()
        files[target] = (body, 0o755)
    files.update(extra or {})
    data = write_tar(files, "package")
    pin.update(size=len(data), sha256=sha256(data))
    return pin, data


def qualified(pin):
    result = copy.deepcopy(pin)
    result["qualified_platforms"] = list(result["candidate_platforms"])
    return result


def aggregate(pin, data, root, dependencies=None):
    build_aggregate(pin, data, root, dependencies=dependencies)
    return verify_aggregate(pin, root)
