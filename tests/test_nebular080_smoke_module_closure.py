"""Connected source-closure producer/validator regressions for Nebular 0.8."""
from __future__ import annotations

import copy
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest


SOURCE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SOURCE_ROOT / "src"))

from rs9 import nebular080_public_input_acquisition as acquisition  # noqa: E402
from rs9 import nebular080_smoke_support as support  # noqa: E402
from rs9 import current_os080  # noqa: E402
from rs9.errors import ContractError  # noqa: E402
from rs9.tf_pypi_archive import AdmissionError  # noqa: E402


TARGET = "linux-x64-gnu"


def _body(path: str) -> bytes:
    return ("controlled-closure-member:" + path).encode("utf-8")


def _authority() -> bytes:
    unsigned = {
        "schema": "nebular-public-build-source-v1",
        "version": "0.8.0",
        "composition": "a" * 64,
        "locks": {"cargo": "b" * 64, "frontend": "c" * 64},
        "components": {"burst": "d" * 64, "loom": "e" * 64, "solar": "f" * 64},
        "recipe": "1" * 64,
        "resourcePlans": {
            triple: {"resources": ["runtime"], "externalBin": ["sidecar"]}
            for triple in support._SOURCE_TRIPLES
        },
    }
    value = {**unsigned, "identity": support._js_identity(unsigned)}
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _archive(paths: list[str]) -> tuple[bytes, dict[str, tuple[int, str, str, int]]]:
    members: dict[str, tuple[int, str, str, int]] = {}
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        for path in paths:
            body = _body(path)
            info = tarfile.TarInfo(path)
            info.size = len(body)
            info.mode = 0o644
            info.mtime = 0
            archive.addfile(info, io.BytesIO(body))
            blob = hashlib.sha1(b"blob " + str(len(body)).encode() + b"\0" + body).hexdigest()
            members[path] = (len(body), hashlib.sha256(body).hexdigest(), blob, 0o644)
    return stream.getvalue(), members


class SmokeModuleClosureTests(unittest.TestCase):
    def _produced_spec(self) -> tuple[dict, dict, str]:
        self.assertEqual(acquisition._SOURCE_TOOLS, support._REQUIRED_TOOLS)
        self.assertEqual(support._REQUIRED_SUPPORT, {"package.json"})
        self.assertEqual(
            current_os080.CURRENT080_VERIFIER_FILES["package.json"],
            {
                "blob": "1001d40761261042da55c19e02874deb0c0002b5",
                "sha256": "64df6f25e3fee6d56d31afdeefa6da1fdb4ebdf7d79033195caecb6fb2ed6be9",
                "size": 1833,
            },
        )
        paths = sorted(
            {"tools/" + name for name in acquisition._SOURCE_TOOLS}
            | set(acquisition._SOURCE_FIXTURES)
            | set(acquisition._SOURCE_SUPPORT)
        )
        archive_data, source_members = _archive(paths)
        authority_data = _authority()
        source = {
            "authority": "authenticated-product-source",
            "repository": support.SOURCE_REPOSITORY,
            "commit": "0" * 40,
            "tree": "1" * 40,
            "record_sha256": "2" * 64,
            "authority_identity": json.loads(authority_data)["identity"],
        }
        evidence: dict[str, dict[str, object]] = {}
        with tempfile.TemporaryDirectory(prefix="nebular080-closure-") as raw_name:
            raw_root = Path(raw_name)
            spec = acquisition._smoke_spec(
                TARGET, source, archive_data, authority_data, source_members, evidence, raw_root,
            )
        nested_paths = [
            item["path"] for item in spec["files"]
            if item["path"].startswith("tools/") and item["path"].count("/") > 1
        ]
        self.assertEqual(nested_paths, ["tools/appearance-matrix-prep1/generate.mjs"])
        self.assertIn("package.json", {item["path"] for item in spec["files"]})
        return spec, evidence, nested_paths[0]

    def test_producer_projects_deep_member_and_validator_accepts_it(self) -> None:
        spec, evidence, nested_path = self._produced_spec()
        checked = support.validate_smoke_support(
            spec, TARGET, evidence_files=evidence, descriptor=True,
        )
        self.assertIn(nested_path, {item["path"] for item in checked["files"]})
        self.assertEqual(checked["target"], TARGET)

    def test_missing_or_tampered_deep_member_is_refused(self) -> None:
        spec, evidence, nested_path = self._produced_spec()
        for path in (nested_path, "package.json"):
            with self.subTest(path=path):
                missing = copy.deepcopy(spec)
                missing["files"] = [item for item in missing["files"] if item["path"] != path]
                missing["closure_sha256"] = support._closure_digest(missing)
                with self.assertRaises((AdmissionError, ContractError)):
                    support.validate_smoke_support(missing, TARGET, evidence_files=evidence, descriptor=True)

                tampered = copy.deepcopy(spec)
                for item in tampered["files"]:
                    if item["path"] == path:
                        item["sha256"] = "f" * 64
                        break
                tampered["closure_sha256"] = support._closure_digest(tampered)
                with self.assertRaises((AdmissionError, ContractError)):
                    support.validate_smoke_support(tampered, TARGET, evidence_files=evidence, descriptor=True)

    def test_root_package_retains_verifier_support_role(self) -> None:
        spec, evidence, _ = self._produced_spec()
        package = next(item for item in spec["files"] if item["path"] == "package.json")
        self.assertEqual(package["role"], "verifier-support")
        package["role"] = "verifier-module"
        spec["closure_sha256"] = support._closure_digest(spec)
        with self.assertRaises((AdmissionError, ContractError)):
            support.validate_smoke_support(spec, TARGET, evidence_files=evidence, descriptor=True)


if __name__ == "__main__":
    unittest.main()
