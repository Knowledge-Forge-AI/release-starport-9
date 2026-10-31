"""Connected 0.7.1 caller wiring and release-frame joins.

All bytes here are bounded synthetic ReleaseCapture evidence.  The tests
exercise the production parser/capture adapter and publication call seam;
they do not qualify a native consumer or publish a release.
"""
from __future__ import annotations

import copy
from pathlib import Path
import shlex
import sys
import tempfile
import unittest

_CANDIDATE = Path(__file__).resolve().parents[1]
tempfile.tempdir = str(Path(tempfile.gettempdir()).resolve())
sys.path.insert(0, str(_CANDIDATE / "src"))
sys.path.insert(0, str(_CANDIDATE / "tests"))
import rs9  # noqa: E402

try:
    from tests.test_nebular071_implementation6_release_capture import (  # noqa: E402
        _capture,
        _provenance_bytes,
    )
except ImportError:
    from test_nebular071_implementation6_release_capture import (  # noqa: E402
        _capture,
        _provenance_bytes,
    )
from rs9 import nebular071_universal_consumer as consumer  # noqa: E402
from rs9 import nebular071_universal_publication as publication  # noqa: E402
from rs9 import nebular071_universal_workflow as workflow  # noqa: E402
from rs9 import tf_pypi_nebular071_publish as publisher  # noqa: E402
from rs9 import tf_pypi_nebular071_universal as universal  # noqa: E402
from rs9.tf_pypi_model import strict_json  # noqa: E402


def _generated_command(document: str, marker: str) -> list[str]:
    """Extract one real multiline CLI argv from rendered workflow text."""
    lines = document.splitlines()
    for index, line in enumerate(lines):
        if marker not in line:
            continue
        parts = []
        while index < len(lines):
            part = lines[index].strip()
            if not part:
                break
            continued = part.endswith("\\")
            parts.append(part[:-1].rstrip() if continued else part)
            if not continued:
                return shlex.split(" ".join(parts))
            index += 1
    raise AssertionError(f"rendered command not found: {marker}")


class Implementation7WiringTests(unittest.TestCase):
    def setUp(self):
        from test_nebular071_simulated_native_fixture import install_simulated_native_domain
        install_simulated_native_domain(self)

    def test_rendered_071_commands_use_held_public_inputs_capture_and_8_artifacts(self):
        rendered = workflow.qualify_jobs_text()
        complete = workflow.complete_workflow_text()
        self.assertNotIn("--product-selection", complete)
        self.assertNotIn("--product-evidence", complete)
        self.assertNotIn("tfnf-071-universal-product-capture", complete)
        self.assertNotIn("gh run download", complete)
        self.assertIn("RS9_GITHUB_READ_TOKEN: ${{ github.token }}", rendered)
        self.assertIn("load_held_product_capture(Path(os.environ[\"INRUN_ROOT\"]))", rendered)
        self.assertIn("product_capture=product_capture", rendered)
        self.assertEqual(len(publication.ARTIFACTS), 8)

        build_argv = _generated_command(rendered, "-m rs9.tf_pypi_nebular071_universal build-bundle")
        universal.parser().parse_args(build_argv[build_argv.index("build-bundle"):])
        prepare_argv = _generated_command(rendered, "-m rs9.tf_pypi_nebular071_publish prepare-public-inputs-071")
        publisher.parser().parse_args(prepare_argv[prepare_argv.index("prepare-public-inputs-071"):])
        matrix_argv = _generated_command(rendered, "-m rs9.tf_pypi_nebular071_universal admit-matrix")
        universal.parser().parse_args(matrix_argv[matrix_argv.index("admit-matrix"):])
        qualify_argv = _generated_command(rendered, "-m rs9.tf_pypi_nebular071_universal qualify-native")
        universal.parser().parse_args(qualify_argv[qualify_argv.index("qualify-native"):])

        pub_text = workflow.publication_job_text()
        for op in ("select-missing", "verify-upload", "readback"):
            argv = _generated_command(pub_text, f"-m rs9.nebular071_universal_publication {op}")
            clean = [token for token in argv[argv.index(op):] if token not in {">>", "$GITHUB_OUTPUT"}]
            publication.parser().parse_args(clean)

    def test_authenticated_product_and_native_release_frames_join(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _selection, capture = _capture(root / "evidence", tested_commit="f" * 40)
            source = consumer.authenticated_product_source(capture)
            release_frame = consumer.authenticated_product_release(capture)
            native_record = copy.deepcopy(capture.record)
            native_asset = next(
                row for row in native_record["assets"]
                if row["name"] == "theme-forge-nebular-fusion-v0.7.1-x86_64-unknown-linux-gnu.tar.gz"
            )
            asset = {
                "id": native_asset["github_asset_id"], "name": native_asset["name"],
                "size": native_asset["size"], "sha256": native_asset["sha256"],
            }
            release = {
                "repository": source["repository"], "tag": "v0.7.1",
                "commit": source["commit"], "tree": source["tree"],
            }
            prov_bytes = release_frame["provenance_bytes"]
            provenance = strict_json(prov_bytes)
            archive_row = release_frame["assets_by_role"]["source-archive"]
            authority_row = release_frame["assets_by_role"]["source-authority"]
            support = {
                "source": dict(source),
                "source_binding": {
                    "archive": {
                        "path": archive_row["name"],
                        "size": archive_row["size"],
                        "sha256": archive_row["sha256"],
                    },
                    "authority": {
                        "path": authority_row["name"],
                        "size": authority_row["size"],
                        "sha256": authority_row["sha256"],
                    },
                },
            }
            from rs9.nebular071_product_native import reference
            proof = reference()
            joined = consumer.join_product_native_release(
                capture, source, release, native_record, provenance, proof, asset,
                provenance_bytes=prov_bytes, support=support,
            )
            self.assertEqual(joined["schema"], "rs9.nebular071-release-join.v1")
            self.assertEqual(joined["product"]["record_sha256"], source["record_sha256"])
            self.assertEqual(joined["compiler"]["commit"], "f" * 40)
            self.assertEqual(joined["compiler"]["tree"], source["tree"])
            self.assertEqual(joined["product_native"]["reference"]["tested_commit"], "7aadefdbcf496a34c097c4880d1802a02d00acc7")
            self.assertEqual(joined["product_native"]["reference"]["tested_tree"], "6e3561855f6ee0093fb709488ad976b69bf501d2")

            wrong_release = dict(release, tag="v0.7.0")
            with self.assertRaisesRegex(Exception, "NEBULAR_UNIVERSAL_RELEASE_JOIN"):
                consumer.join_product_native_release(
                    capture, source, wrong_release, native_record, provenance, proof, asset,
                    provenance_bytes=prov_bytes, support=support,
                )
            wrong_repo_proof = dict(proof, repository="Knowledge-Forge-AI/release-starport-9")
            with self.assertRaisesRegex(Exception, "NEBULAR_UNIVERSAL_RELEASE_JOIN"):
                consumer.join_product_native_release(
                    capture, source, release, native_record, provenance,
                    wrong_repo_proof, asset,
                    provenance_bytes=prov_bytes, support=support,
                )
            wrong_asset = dict(asset, id=999999)
            with self.assertRaisesRegex(Exception, "NEBULAR_UNIVERSAL_RELEASE_JOIN"):
                consumer.join_product_native_release(
                    capture, source, release, native_record, provenance, proof, wrong_asset,
                    provenance_bytes=prov_bytes, support=support,
                )
            with self.assertRaisesRegex(Exception, "NEBULAR_UNIVERSAL_RELEASE_JOIN"):
                consumer.join_product_native_release(
                    capture, source, release, native_record, provenance, proof, asset,
                    provenance_bytes=prov_bytes + b" ", support=support,
                )


if __name__ == "__main__":
    unittest.main()
