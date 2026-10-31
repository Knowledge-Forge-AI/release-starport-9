"""Caller-path regressions for the independently authenticated product source frame.

These tests stop before a wheel/native process is run.  They exercise the real
consumer materializer and raw-release publisher validator with a bounded
authenticated source closure, proving that omission or resealing of the
transported source coordinates fails closed.
"""
from __future__ import annotations

import copy
import sys
from pathlib import Path
import tempfile
import unittest
from unittest import mock


_CANDIDATE = Path(__file__).resolve().parents[1]
tempfile.tempdir = str(Path(tempfile.gettempdir()).resolve())
sys.path.insert(0, str(_CANDIDATE / "src"))
sys.path.insert(0, str(_CANDIDATE / "tests"))
import rs9  # noqa: E402

try:
    from tests.test_nebular071_implementation3_contracts import _source_offer  # noqa: E402
    from tests.test_nebular071_implementation6_release_capture import _capture  # noqa: E402
except ImportError:
    from test_nebular071_implementation3_contracts import _source_offer  # noqa: E402
    from test_nebular071_implementation6_release_capture import _capture  # noqa: E402
from rs9 import nebular071_consumer_core as consumer  # noqa: E402
from rs9 import nebular071_smoke_support as smoke_support  # noqa: E402
from rs9 import nebular071_universal_consumer as uconsumer  # noqa: E402
from rs9 import tf_pypi_nebular071_publish as publisher  # noqa: E402
from rs9.tf_pypi_archive import AdmissionError  # noqa: E402


class _StopAfterMaterialization(Exception):
    """Stop before process/user-state work while retaining materialized bytes."""


def _write_source_inputs(root: Path, archive: bytes, authority: bytes,
                         support: dict, bodies: dict[str, bytes]) -> None:
    source = root / support["root"]
    source.mkdir(parents=True)
    (source / support["source_binding"]["archive"]["path"]).write_bytes(archive)
    (source / support["source_binding"]["authority"]["path"]).write_bytes(authority)
    for relative, body in bodies.items():
        path = source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)


def _entry(root: Path, relative: str, body: bytes) -> dict[str, object]:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(body)
    import hashlib
    return {"path": relative, "size": len(body), "sha256": hashlib.sha256(body).hexdigest()}


class Implementation5ProductSourceTests(unittest.TestCase):
    def test_consumer_caller_requires_independent_product_source_before_output(self):
        archive, authority, support, bodies = _source_offer()
        with tempfile.TemporaryDirectory() as temporary:
            temp_root = Path(temporary)
            _selection, product_capture = _capture(temp_root / "product-evidence")
            derived_source = uconsumer.authenticated_product_source(product_capture)
            support = copy.deepcopy(support)
            support["source"] = dict(derived_source)
            support["closure_sha256"] = smoke_support._closure_digest(support)
            root = temp_root / "inputs"
            _write_source_inputs(root, archive, authority, support, bodies)

            capture = {
                "root": root,
                "native": {"smoke_support": support, "state_paths": []},
                "product_source": dict(derived_source),
                "product_capture": product_capture,
            }
            wheel = root / "candidate.whl"

            def stop_probe(_env, _prefix):
                raise _StopAfterMaterialization

            positive_work = temp_root / "positive-work"
            with mock.patch.object(
                smoke_support,
                "materialize_smoke_support",
                wraps=smoke_support.materialize_smoke_support,
            ) as materialize:
                with self.assertRaises(_StopAfterMaterialization):
                    consumer._nebular_installed_consumer(
                        capture, wheel, positive_work, target="linux-x64-gnu",
                        sandbox_probe=stop_probe, fixture_only=False,
                    )
                self.assertEqual(
                    materialize.call_args.kwargs["expected_source"],
                    capture["product_source"],
                )
            self.assertTrue(
                (positive_work / "smoke-support" / "source" / "tools" /
                 "native-rc-smoke.mjs").is_file()
            )

            resealed_support = copy.deepcopy(support)
            resealed_support["source"]["commit"] = "d" * 40
            resealed_support["closure_sha256"] = smoke_support._closure_digest(resealed_support)
            wrong_capture = {
                **capture,
                "native": {"smoke_support": resealed_support, "state_paths": []},
            }
            positive_work2 = temp_root / "positive-work2"
            with self.assertRaises(_StopAfterMaterialization):
                consumer._nebular_installed_consumer(
                    capture, wheel, positive_work2, target="linux-x64-gnu",
                    sandbox_probe=stop_probe, fixture_only=False,
                )
            missing_capture = dict(capture)
            missing_capture.pop("product_source")
            missing_work = temp_root / "missing-work"
            with self.assertRaises(AdmissionError):
                consumer._nebular_installed_consumer(
                    missing_capture, wheel, missing_work, target="linux-x64-gnu",
                    sandbox_probe=stop_probe, fixture_only=False,
                )
            self.assertFalse(missing_work.exists())
            no_rel_capture = dict(capture)
            no_rel_capture.pop("product_capture")
            no_rel_work = temp_root / "no-rel-work"
            with self.assertRaises(AdmissionError):
                consumer._nebular_installed_consumer(
                    no_rel_capture, wheel, no_rel_work, target="linux-x64-gnu",
                    sandbox_probe=stop_probe, fixture_only=False,
                )
            self.assertFalse(no_rel_work.exists())
            wrong_work = temp_root / "wrong-work"
            with self.assertRaises(AdmissionError):
                consumer._nebular_installed_consumer(
                    wrong_capture, wheel, wrong_work, target="linux-x64-gnu",
                    sandbox_probe=stop_probe, fixture_only=False,
                )
            self.assertFalse(wrong_work.exists())

    def test_publisher_handoff_rejects_resealed_product_coordinates(self):
        archive, authority, support, bodies = _source_offer()
        with tempfile.TemporaryDirectory() as temporary:
            temp_root = Path(temporary)
            _selection, product_capture = _capture(temp_root / "product-evidence")
            derived_source = uconsumer.authenticated_product_source(product_capture)
            support = copy.deepcopy(support)
            support["source"] = dict(derived_source)
            support["closure_sha256"] = smoke_support._closure_digest(support)
            root = temp_root / "handoff"
            _write_source_inputs(root, archive, authority, support, bodies)
            record = _entry(root, "record.json", b"record")
            readme = _entry(root, "README.md", b"readme")
            provenance = _entry(root, "provenance.json", b"provenance")
            payload = _entry(root, "payload.tar.gz", b"payload")
            manifest = _entry(root, "manifest.json", b"manifest")
            legal = {
                name: _entry(root, name, name.encode("utf-8"))
                for name in ("LICENSE", "NOTICE", "COMMERCIAL-LICENSE.md")
            }
            qualification = _entry(root, "qualification.json", b"qualification")
            smoke = {
                channel: {
                    kind: _entry(root, f"{channel}-{kind}.json", f"{channel}-{kind}".encode())
                    for kind in ("run", "receipt")
                }
                for channel in ("raw-archive", "npm-package")
            }
            target = "linux-x64-gnu"
            native = {
                "qualification": qualification,
                "smoke": smoke,
                "smoke_support": support,
                "loader": {"path": "theme-forge-nebular-fusion/bin/tfnf", "sha256": "a" * 64},
                "provider_closure": {"target": target},
            }
            handoff = {
                "schema": publisher.RAW_RELEASE_HANDOFF_SCHEMA,
                "target": target,
                "root": str(root),
                "record": record,
                "readme": readme,
                "legal_files": legal,
                "payload": payload,
                "manifest": manifest,
                "provenance": provenance,
                "product_source": dict(support["source"]),
                "native_consumer": {target: native},
            }
            checked = publisher.validate_raw_release_handoff_binding(
                handoff, target=target, product_capture=product_capture,
            )
            self.assertEqual(checked["product_source"], support["source"])

            with self.assertRaises(AdmissionError):
                publisher.validate_raw_release_handoff_binding(handoff, target=target)

            wrong = copy.deepcopy(handoff)
            wrong_support = wrong["native_consumer"][target]["smoke_support"]
            wrong_support["source"]["tree"] = "e" * 40
            wrong_support["closure_sha256"] = smoke_support._closure_digest(wrong_support)
            with self.assertRaises(AdmissionError):
                publisher.validate_raw_release_handoff_binding(
                    wrong, target=target, product_capture=product_capture,
                )

            missing = dict(handoff)
            missing.pop("product_source")
            with self.assertRaises(AdmissionError):
                publisher.validate_raw_release_handoff_binding(
                    missing, target=target, product_capture=product_capture,
                )


if __name__ == "__main__":
    unittest.main()
