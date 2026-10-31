"""Connected 0.7.1 product-capture regressions.

The fixtures are bounded synthetic bytes.  They exercise the maintained
generic release authenticator and the real 0.7.1 source adapter; they are not
hosted qualification or publication evidence.
"""
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

_CANDIDATE = Path(__file__).resolve().parents[1]
tempfile.tempdir = str(Path(tempfile.gettempdir()).resolve())
sys.path.insert(0, str(_CANDIDATE / "src"))
sys.path.insert(0, str(_CANDIDATE / "tests"))
import rs9  # noqa: E402

try:
    from tests.test_nebular071_implementation3_contracts import _source_offer  # noqa: E402
except ImportError:
    from test_nebular071_implementation3_contracts import _source_offer  # noqa: E402
from rs9 import nebular071_product_capture as product_capture_mod  # noqa: E402
from rs9 import nebular071_universal_consumer as consumer  # noqa: E402
from rs9 import tf_pypi_nebular071_universal as universal  # noqa: E402
from rs9 import tf_pypi_nebular071_publish as publisher  # noqa: E402
from rs9.errors import ContractError  # noqa: E402
from rs9.release_core import authenticate_release  # noqa: E402
from rs9.scratch import canonical  # noqa: E402
from rs9.tf_pypi_archive import AdmissionError  # noqa: E402


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _blob(value: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(value)).encode("ascii") + b"\0" + value).hexdigest()


def _payload(label: str = "package") -> bytes:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz", format=tarfile.USTAR_FORMAT) as archive:
        info = tarfile.TarInfo(f"{label}/package.json")
        body = f'{{"name":"nebular-universal","target":"{label}","version":"0.7.1"}}\n'.encode()
        info.size = len(body)
        info.mode = 0o644
        info.mtime = 0
        archive.addfile(info, io.BytesIO(body))
    return stream.getvalue()


def _provenance_bytes(*, release_id: int = 7102, release_commit: str = "a" * 40,
                      tested_commit: str = "a" * 40, tested_tree: str = "b" * 40,
                      assets: list[dict] | None = None) -> bytes:
    return canonical({
        "schema": "nebular.public-native-ci-release-provenance.v1",
        "repository": "Knowledge-Forge-AI/theme-forge-nebular-fusion",
        "version": "0.7.1",
        "release": release_id,
        "releaseCommit": release_commit,
        "testedCommit": tested_commit,
        "testedTree": tested_tree,
        "nativeCiRun": 8101,
        "nativeCiAttempt": 1,
        "sourceCiRun": 8102,
        "assets": assets or [],
    })


def _capture(root: Path, *, tested_commit: str = "a" * 40):
    source_archive, source_authority, _support, _bodies = _source_offer()
    selection = product_capture_mod.product_selection()
    payloads = {
        row["name"]: _payload(row["id"])
        for row in selection["payload_assets"]
    }
    sums = "".join(
        f"{_sha(body)}  {name}\n" for name, body in sorted(payloads.items())
    ).encode("utf-8")
    base_assets = {
        **payloads,
        "SHA256SUMS": sums,
        "theme-forge-nebular-fusion-v0.7.1-source.tar.gz": source_archive,
        "nebular-compiled-public-build-source-authority-v0.7.1.json": source_authority,
    }
    asset_ids = {
        name: index + 1
        for index, name in enumerate(sorted([*base_assets, "nebular-v0.7.1-native-ci-provenance.json"]))
    }
    prov_assets = [
        {
            "id": asset_ids[name],
            "name": name,
            "bytes": len(body),
            "sha256": _sha(body),
            "role": "raw-archive",
            "unauthenticatedReadback": True,
            "httpStatus": 200,
            "url": (
                "https://github.com/Knowledge-Forge-AI/theme-forge-nebular-fusion"
                f"/releases/download/v0.7.1/{name}"
            ),
        }
        for name, body in sorted(payloads.items())
    ]
    provenance = _provenance_bytes(tested_commit=tested_commit, assets=prov_assets)
    assets = {
        **base_assets,
        "nebular-v0.7.1-native-ci-provenance.json": provenance,
    }
    api = {
        "repository": {"id": 7101, "full_name": "Knowledge-Forge-AI/theme-forge-nebular-fusion"},
        "release": {
            "id": 7102, "tag_name": "v0.7.1", "target_commitish": "a" * 40,
            "draft": False, "prerelease": False,
            "assets": [
                {
                    "id": asset_ids[name], "name": name, "size": len(body),
                    "digest": "sha256:" + _sha(body), "state": "uploaded",
                    "browser_download_url": (
                        "https://github.com/Knowledge-Forge-AI/theme-forge-nebular-fusion"
                        f"/releases/download/v0.7.1/{name}"
                    ),
                }
                for name, body in sorted(assets.items())
            ],
        },
        "ref": {"ref": "refs/tags/v0.7.1", "object": {"type": "commit", "sha": "a" * 40}},
        "tags": [],
        "commit": {"sha": "a" * 40, "tree": {"sha": "b" * 40}},
        "tree": {"sha": "b" * 40, "truncated": False, "tree": []},
    }
    (root / "api").mkdir(parents=True, exist_ok=True)
    for name, value in api.items():
        (root / "api" / (name + ".json")).write_bytes(canonical(value))
    (root / "assets").mkdir(parents=True, exist_ok=True)
    for name, body in assets.items():
        (root / "assets" / name).write_bytes(body)
    (root / "fetch-receipt.json").write_bytes(canonical({
        "schema": "rs9.fetch-receipt.v1alpha1",
        "selection_sha256": _sha(canonical(selection)),
        "requests": [],
    }))
    return selection, authenticate_release(selection, root)


class Implementation6ReleaseCaptureTests(unittest.TestCase):
    def test_runtime_capture_requires_product_authority_before_static_work(self):
        with self.assertRaisesRegex(Exception, "NEBULAR_UNIVERSAL_PRODUCT_CAPTURE"):
            consumer.capture_universal_runtime(
                {}, Path("/unused"), {}, target="linux-x64-gnu",
            )

    def test_authenticated_product_source_is_derived_from_release_capture(self):
        with tempfile.TemporaryDirectory() as temporary:
            capture_root = Path(temporary)
            _selection, capture = _capture(capture_root)
            source = consumer.authenticated_product_source(capture)
            self.assertEqual(set(source), set(consumer._SOURCE_KEYS))
            self.assertEqual(source["repository"], "Knowledge-Forge-AI/theme-forge-nebular-fusion")
            self.assertEqual(source["commit"], "a" * 40)
            self.assertEqual(source["tree"], "b" * 40)
            self.assertEqual(source["record_sha256"], capture._record_hash)
            release_frame = consumer.authenticated_product_release(capture)
            self.assertEqual(release_frame["release_id"], 7102)
            self.assertEqual(release_frame["source"], source)
            with self.assertRaises(Exception):
                consumer.authenticated_product_source({"product_source": source})
            capture.evidence_bytes[
                "nebular-compiled-public-build-source-authority-v0.7.1.json"
            ] = b"tampered"
            with self.assertRaisesRegex(Exception, "NEBULAR_SMOKE_CLOSURE|PRODUCT_CAPTURE"):
                consumer.authenticated_product_source(capture)

    def test_071_binding_uses_capture_ids_and_coordinates(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _selection, capture = _capture(root)
            source = consumer.authenticated_product_source(capture)
            binding = {
                "schema": "rs9.nebular-release-binding.v1alpha1",
                "release": "0.7.1", "application_version": "0.7.1",
                "distribution_version": "0.7.1",
                "repository": source["repository"], "tag": "v0.7.1",
                "bootstrap_path": "operators/tf-pypi/bootstrap-071.json",
                "expectations_path": "operators/tf-pypi/expectations-071.json",
                "profile_path": "operators/tf-pypi/theme-forge-nebular-fusion-0.7.1-gate1.json",
                "status": "ready",
                "lineage": {"mode": "direct-tag-provenance-equality",
                            "requires_historical_author_rewrite": False},
                "provenance": {"path": "PROVENANCE.json", "commit_field": "tagCommit",
                                "tree_field": "tagTree"},
                "expected": {
                    "repository_id": 7101, "release_id": 7102,
                    "tag_commit": "a" * 40, "tag_tree": "b" * 40,
                    "bootstrap_sha256": "c" * 64, "expectations_sha256": "d" * 64,
                },
            }
            checked = publisher._validate_071_release_binding(
                binding, product_capture=capture, product_source=source,
            )
            self.assertEqual(checked, binding)
            wrong = copy.deepcopy(binding)
            wrong["expected"]["tag_tree"] = "e" * 40
            with self.assertRaisesRegex(Exception, "QUALIFICATION_INPUTS_BINDING"):
                publisher._validate_071_release_binding(
                    wrong, product_capture=capture, product_source=source,
                )

    def test_cli_loader_returns_in_process_capture_not_serialized_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            capture_root = root / "product-capture"
            selection, expected = _capture(capture_root / "evidence")
            selection_path = capture_root / "selection.json"
            selection_path.write_bytes(canonical(selection))
            loaded = universal._load_product_capture(root)
            self.assertEqual(type(loaded), type(expected))
            self.assertEqual(
                consumer.authenticated_product_source(loaded),
                consumer.authenticated_product_source(expected),
            )


if __name__ == "__main__":
    unittest.main()
