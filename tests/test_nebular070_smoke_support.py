"""Bounded contract tests for the installed-wheel smoke support closure."""

import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

from rs9.nebular070_smoke_support import (
    _closure_digest,
    installed_runtime_root,
    materialize_smoke_support,
    SOURCE_ARCHIVE_NAME,
    validate_smoke_support,
)
from rs9.tf_pypi_archive import AdmissionError, sha256
from tests.nebular070_smoke_fixtures import (
    FIXTURE_PATHS,
    FIXTURE_ROOT,
    TOOL_NAMES,
    TOOL_ROOT,
    fixture_contract,
    patched_source_contract,
    source_members,
    stage_support,
)


TARGET = "linux-arm64-gnu"
def _source_bytes() -> dict[str, bytes]:
    return source_members()


def _record(path, data, role, *, evidence_path=None):
    record = {
        "path": path,
        "size": len(data),
        "sha256": sha256(data),
        "blob": hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest(),
        "role": role,
    }
    if evidence_path is not None:
        record["evidence_path"] = evidence_path
    return record


def _support(*, evidence=False, target=TARGET):
    contract = fixture_contract()
    source_data = _source_bytes()
    files = []
    for name in TOOL_NAMES:
        role = "application-smoke" if name == "native-rc-smoke.mjs" else "verifier-module"
        files.append(_record(f"{TOOL_ROOT}/{name}", source_data[f"{TOOL_ROOT}/{name}"], role,
                             evidence_path=f"closure/{name}" if evidence else None))
    for fixture_path in FIXTURE_PATHS:
        files.append(_record(fixture_path, source_data[fixture_path], "fixture",
                             evidence_path=f"closure/{fixture_path.removeprefix(FIXTURE_ROOT + '/')}")
                     if evidence else _record(fixture_path, source_data[fixture_path], "fixture"))
    value = {
        "schema": "rs9.nebular070-smoke-support.v1",
        "target": target,
        "source": {
            "authority": "authenticated-product-source",
            "repository": "Knowledge-Forge-AI/theme-forge-nebular-fusion",
            "commit": "cadb40c4972f68f314096ff60fbcfb4da950c161",
            "tree": "27c643b6375c2aafde314799c4f08e844c14992c",
            "record_sha256": contract["authority_sha256"],
            "authority_identity": contract["authority_identity"],
        },
        "root": "smoke-support",
        "tool_root": TOOL_ROOT,
        "fixture_root": FIXTURE_ROOT,
        "source_binding": {
            "archive": {
                "path": f"source-authority/{contract['archive_name']}",
                "size": contract["archive_size"],
                "sha256": contract["archive_sha256"],
                **({"evidence_path": "source/" + contract["archive_name"]} if evidence else {}),
            },
            "authority": {
                "path": f"source-authority/{contract['authority_name']}",
                "size": contract["authority_size"],
                "sha256": contract["authority_sha256"],
                **({"evidence_path": "source/" + contract["authority_name"]} if evidence else {}),
            },
        },
        "files": files,
    }
    value["files"] = sorted(value["files"], key=lambda item: item["path"])
    value["closure_sha256"] = _closure_digest(value)
    return value


class SmokeSupportTests(unittest.TestCase):
    def setUp(self):
        self._fixture_contract = patched_source_contract(sys.modules[__name__])
        self._fixture_contract.__enter__()
        self.addCleanup(self._fixture_contract.__exit__, None, None, None)

    def test_materialize_preserves_authenticated_bytes_and_records(self):
        support = _support()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "handoff"
            stage_support(root, support)
            prepared = materialize_smoke_support(root, support, Path(temporary) / "prepared", target=TARGET)
            self.assertEqual(prepared["closure_sha256"], support["closure_sha256"])
            self.assertTrue((prepared["tools"] / "native-rc-smoke.mjs").is_file())
            self.assertTrue((prepared["source"] / FIXTURE_ROOT / "GUIDANCE.md").is_file())
            self.assertEqual(len(prepared["records"]), 27)

    def test_descriptor_requires_matching_evidence_paths(self):
        support = _support(evidence=True)
        evidence = {
            item["evidence_path"]: {
                "path": item["evidence_path"], "size": item["size"], "sha256": item["sha256"],
            }
            for item in support["files"]
        }
        for ref in support["source_binding"].values():
            evidence[ref["evidence_path"]] = {
                "path": ref["evidence_path"], "size": ref["size"], "sha256": ref["sha256"],
            }
        self.assertEqual(
            validate_smoke_support(support, TARGET, evidence_files=evidence, descriptor=True)["target"],
            TARGET,
        )
        evidence["closure/.tfsb/brand.toml"]["sha256"] = "d" * 64
        with self.assertRaises(AdmissionError) as caught:
            validate_smoke_support(support, TARGET, evidence_files=evidence, descriptor=True)
        self.assertEqual(caught.exception.code, "TF_PYPI_NEBULAR_SMOKE_CLOSURE")

    def test_rejects_archive_member_missing_required_tool_and_tamper(self):
        support = _support()
        support["files"] = [item for item in support["files"] if not item["path"].endswith("sidecar-verify.mjs")]
        support["closure_sha256"] = _closure_digest(support)
        with self.assertRaises(AdmissionError):
            validate_smoke_support(support, TARGET)

        archive = _support()
        archive["files"][0] = dict(archive["files"][0], path="tools/support.tar.gz")
        archive["closure_sha256"] = _closure_digest(archive)
        with self.assertRaises(AdmissionError):
            validate_smoke_support(archive, TARGET)

    def test_source_binding_rejects_self_authored_closure_member(self):
        support = _support()
        support["files"][0] = dict(support["files"][0], sha256="d" * 64)
        support["closure_sha256"] = _closure_digest(support)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "handoff"
            stage_support(root, support)
            with self.assertRaises(AdmissionError) as caught:
                materialize_smoke_support(root, support, Path(temporary) / "prepared", target=TARGET)
            self.assertEqual(caught.exception.code, "TF_PYPI_NEBULAR_SMOKE_CLOSURE")

    def test_source_identity_cannot_be_self_declared(self):
        support = _support()
        support["source"] = dict(support["source"], commit="a" * 40)
        support["closure_sha256"] = _closure_digest(support)
        with self.assertRaises(AdmissionError) as caught:
            validate_smoke_support(support, TARGET)
        self.assertEqual(caught.exception.code, "TF_PYPI_NEBULAR_SMOKE_CLOSURE")

    def test_protected_components_are_rejected_casefolded_before_use(self):
        cases = []
        root_case = _support()
        root_case["root"] = "handoff/DB"
        root_case["closure_sha256"] = _closure_digest(root_case)
        cases.append(root_case)

        member_case = _support()
        member_case["files"][0] = dict(member_case["files"][0], path="tools/RAW/native-rc-smoke.mjs")
        member_case["closure_sha256"] = _closure_digest(member_case)
        cases.append(member_case)

        source_case = _support()
        source_case["source_binding"]["archive"] = dict(
            source_case["source_binding"]["archive"], path="proof/.git/" + SOURCE_ARCHIVE_NAME,
        )
        source_case["closure_sha256"] = _closure_digest(source_case)
        cases.append(source_case)

        evidence_case = _support(evidence=True)
        evidence_case["files"][0] = dict(evidence_case["files"][0], evidence_path="proof/.SERENA/file")
        evidence_case["closure_sha256"] = _closure_digest(evidence_case)
        cases.append(evidence_case)

        for value in cases:
            with self.subTest(value=value):
                with self.assertRaises(AdmissionError) as caught:
                    validate_smoke_support(value, TARGET, descriptor="evidence_path" in value["files"][0])
                self.assertEqual(caught.exception.code, "TF_PYPI_NEBULAR_SMOKE_CLOSURE")

        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(AdmissionError):
                materialize_smoke_support(
                    Path(temporary) / "RAW", _support(), Path(temporary) / "prepared", target=TARGET,
                )

    def test_explicit_root_and_optional_support_role_are_valid(self):
        support = _support()
        support["root"] = "handoff-root"
        support["files"].append(_record("package.json", b"{}\n", "verifier-support"))
        support["files"] = sorted(support["files"], key=lambda item: item["path"])
        support["closure_sha256"] = _closure_digest(support)
        self.assertEqual(validate_smoke_support(support, TARGET)["root"], "handoff-root")

    def test_role_relabel_with_recomputed_closure_is_rejected(self):
        support = _support()
        support["files"][0] = dict(support["files"][0], role="application-smoke")
        support["closure_sha256"] = _closure_digest(support)
        with self.assertRaises(AdmissionError) as caught:
            validate_smoke_support(support, TARGET)
        self.assertEqual(caught.exception.code, "TF_PYPI_NEBULAR_SMOKE_CLOSURE")

    def test_generated_authenticated_archive_materializes_all_primary_targets(self):
        for target in ("darwin-arm64", "linux-arm64-gnu", "linux-x64-gnu"):
            with self.subTest(target=target):
                with tempfile.TemporaryDirectory() as temporary:
                    support = _support(target=target)
                    raw_root = Path(temporary) / "raw-root"
                    stage_support(raw_root, support)
                    prepared = materialize_smoke_support(
                        raw_root, support, Path(temporary) / target, target=target,
                    )
                    self.assertEqual(len(prepared["records"]), 27)
                    self.assertEqual(
                        prepared["source_binding"]["archive"]["sha256"],
                        fixture_contract()["archive_sha256"],
                    )
                    self.assertTrue((prepared["tools"] / "native-rc-smoke.mjs").is_file())

    def test_installed_runtime_root_is_platform_bound(self):
        self.assertEqual(
            installed_runtime_root("/owned/cache/payload/bin/theme-forge-nebular-fusion", TARGET),
            Path("/owned/cache/payload"),
        )
        self.assertEqual(
            installed_runtime_root(
                "/owned/cache/payload/Theme Forge Nebular Fusion.app/Contents/MacOS/theme-forge-nebular-fusion",
                "darwin-arm64",
            ),
            Path("/owned/cache/payload/Theme Forge Nebular Fusion.app"),
        )
        with self.assertRaises(AdmissionError):
            installed_runtime_root("/owned/cache/payload/lib/theme-forge-nebular-fusion", TARGET)


if __name__ == "__main__":
    unittest.main()
