"""Closed successor release selection, backend metadata, and CLI forwarding tests."""
import copy
import email.parser
import io
import json
import os
from pathlib import Path
import shlex
import tempfile
import tomllib
import unittest
from unittest.mock import patch
import yaml

from rs9 import tf_pypi_hosted as h
from rs9 import tf_pypi_publish as p
from rs9 import tf_pypi_workflow as w
from rs9.tf_pypi_archive import AdmissionError, canonical, fail, physical_bytes, sha256
from rs9.tf_pypi_backend import (
    build_aggregate,
    description,
    description_bytes,
    description_name,
    metadata,
    names,
    project_toml,
    project_urls,
    sdist_entries,
    wheel_entries,
    write_tar,
)
from rs9.tf_pypi_model import (
    DISTRIBUTIONS,
    PRODUCTS,
    RELEASES,
    TARGETS,
    admit_bytes,
    build_pin,
    load_pin,
    release,
    strict_json,
    validate_pin,
)
from rs9.tf_pypi_verify import verify_aggregate
from tests.tf_pypi_fixtures import ROOT

PIN_DIR = ROOT / "operators/tf-pypi"
DESC_DIR = PIN_DIR / "descriptions"
COMMIT = "a" * 40
RUN_ID = "54321"
EXPECTED_SUCCESSOR_WITHHELD = [
    "PYPI_RELEASE_MANIFEST_PENDING",
    "PYPI_CONSUMER_MATRIX_PENDING",
    "PYPI_WHEEL_ARTIFACT_RECEIPTS_PENDING",
]

EXPECTED_ASSET_HASHES = {
    "operators/tf-pypi/theme-forge-stellar-burst-0.7.0.json": (
        "fcbe586eff3089546c79c8bd630494402c2de63c6c7c59caf4141a01bc304049"
    ),
    "operators/tf-pypi/descriptions/stellar-burst-0.7.0.md": (
        "629a25fc68705bd610d0a09eeef4d77173ac5f6d7d6c98e3a4335d15b140dbb9"
    ),
    "operators/tf-pypi/theme-forge-stellar-loom-0.5.0.json": (
        "b7eeb74870b6b4e2b566296caef3222d7e7c74e61d221b475bdecb10c8647013"
    ),
    "operators/tf-pypi/descriptions/stellar-loom-0.5.0.md": (
        "c183c3cf30410d5637d8bb877a571ebb841e7c53967cb1bac8a305d9b655bfc3"
    ),
    "operators/tf-pypi/theme-forge-solar-sail-0.3.0.json": (
        "c75b91e828ea74a99514aea4164d1a7b881dfce029be87985e1262c54130d15d"
    ),
    "operators/tf-pypi/descriptions/solar-sail-0.3.0.md": (
        "e3e8171561e933b0aabc1e4668defdcb727471505c6aebe9caebdb2289d1a9cf"
    ),
}

SUCCESSOR_SPECS = {
    "theme-forge-stellar-burst": {
        "version": "0.7.0",
        "pin_file": "theme-forge-stellar-burst-0.7.0.json",
        "description": "stellar-burst-0.7.0.md",
        "historical_description": "stellar-burst.md",
        "size": 646799,
        "sha256": "2629b32980a7aa5a93cf3e893a9763695db47c01bd90db68ab7434ee309c029d",
    },
    "theme-forge-stellar-loom": {
        "version": "0.5.0",
        "pin_file": "theme-forge-stellar-loom-0.5.0.json",
        "description": "stellar-loom-0.5.0.md",
        "historical_description": "stellar-loom.md",
        "size": 272836,
        "sha256": "4e7a7d436c09ba111f5dca8101876c6e085ad15859d96bab8f728c5669880b5f",
    },
    "theme-forge-solar-sail": {
        "version": "0.3.0",
        "pin_file": "theme-forge-solar-sail-0.3.0.json",
        "description": "solar-sail-0.3.0.md",
        "historical_description": "solar-sail.md",
        "size": 110836,
        "sha256": "65070c3478a1d55476c1b09fbe1dcadfdf7c3d3aa54a154bc9ac9e299411f415",
    },
}

HISTORICAL_WORKFLOW_SHA256 = {
    "theme-forge-solar-sail": "524928f0b30596190946260dd724b7e3c302a0312865eee1b5eeff39d98cdb20",
    "theme-forge-stellar-burst": "c8b8a8e7f1ff455d956ed17cb57dfd5e01afe35b5a98b1e59dd643b75a87e410",
    "theme-forge-stellar-loom": "980618ae843f51f27e9eab462d8a5a58cfd43a1d98153e347a8c55f19d41260a"
}


HISTORICAL_SPECS = {
    "theme-forge-stellar-burst": ("0.6.1", "0.6.1.post1", "stellar-burst.md"),
    "theme-forge-stellar-loom": ("0.4.0", "0.4.0.post1", "stellar-loom.md"),
    "theme-forge-solar-sail": ("0.2.1", "0.2.1.post1", "solar-sail.md"),
}


class _BufferStdout:
    def __init__(self):
        self.buffer = io.BytesIO()

    def write(self, text):
        self.buffer.write(text.encode("utf-8"))


def _successor_fixture(project="theme-forge-stellar-loom"):
    spec = SUCCESSOR_SPECS[project]
    pin = copy.deepcopy(load_pin(project, PIN_DIR / spec["pin_file"]))
    package = {
        "name": pin["npm_name"],
        "version": pin["version"],
        "license": pin["license"],
        "engines": {"node": ">=22"},
        "bin": pin["bins"],
    }
    files = {
        "package.json": (json.dumps(package).encode("utf-8"), 0o644),
        "LICENSE": (b"Synthetic license fixture, not upstream legal bytes.\n", 0o644),
        "NOTICE": (b"Synthetic fixture only.\n", 0o644),
        "COMMERCIAL-LICENSE.md": (b"Synthetic commercial notice.\n", 0o644),
    }
    for command, target in pin["bins"].items():
        if command == "tfsl-batch":
            body = b"process.stdout.write('EMPTY_INPUT\\n');process.exit(1);\n"
        else:
            body = f"process.stdout.write({json.dumps(pin['version'] + chr(10))});\n".encode("utf-8")
        files[target] = (body, 0o755)
    data = write_tar(files, "package")
    pin.update(size=len(data), sha256=sha256(data))
    return pin, data


class SuccessorReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()

    def assertAdmissionError(self, expected_code, func, *args, **kwargs):
        with self.assertRaises(AdmissionError) as caught:
            func(*args, **kwargs)
        code = expected_code if expected_code.startswith("TF_PYPI_") else "TF_PYPI_" + expected_code
        self.assertEqual(caught.exception.code, code)

    def test_committed_successor_assets_and_closed_release_table(self):
        for rel_path, expected_digest in EXPECTED_ASSET_HASHES.items():
            raw = physical_bytes(ROOT / rel_path)
            self.assertEqual(sha256(raw), expected_digest, rel_path)

        expected_releases = {
            ("theme-forge-stellar-burst", "0.6.1", "0.6.1.post1"): (
                "theme-forge-stellar-burst.json",
                None,
            ),
            ("theme-forge-stellar-loom", "0.4.0", "0.4.0.post1"): (
                "theme-forge-stellar-loom.json",
                None,
            ),
            ("theme-forge-solar-sail", "0.2.1", "0.2.1.post1"): (
                "theme-forge-solar-sail.json",
                None,
            ),
            ("theme-forge-stellar-burst", "0.7.0", "0.7.0"): (
                "theme-forge-stellar-burst-0.7.0.json",
                "stellar-burst-0.7.0.md",
            ),
            ("theme-forge-stellar-loom", "0.5.0", "0.5.0"): (
                "theme-forge-stellar-loom-0.5.0.json",
                "stellar-loom-0.5.0.md",
            ),
            ("theme-forge-solar-sail", "0.3.0", "0.3.0"): (
                "theme-forge-solar-sail-0.3.0.json",
                "solar-sail-0.3.0.md",
            ),
        }
        self.assertEqual(RELEASES, expected_releases)
        self.assertEqual(len(RELEASES), 6)

        previous_cwd = Path.cwd()
        try:
            os.chdir(ROOT)
            for project, spec in SUCCESSOR_SPECS.items():
                abs_path = PIN_DIR / spec["pin_file"]
                rel_path = Path("operators/tf-pypi") / spec["pin_file"]
                pin = load_pin(project, abs_path)
                self.assertEqual(pin, load_pin(project, str(abs_path)))
                self.assertEqual(pin, load_pin(project, rel_path))
                self.assertEqual(pin["project"], project)
                self.assertEqual(pin["version"], spec["version"])
                self.assertEqual(pin["distribution_version"], spec["version"])
                self.assertEqual(pin["description"], spec["description"])
                self.assertEqual(
                    pin["asset"],
                    f"knowledge-forge-ai-{project}-{spec['version']}.tgz",
                )
                self.assertEqual(pin["size"], spec["size"])
                self.assertEqual(pin["sha256"], spec["sha256"])
                if project in {"theme-forge-solar-sail", "theme-forge-stellar-loom"}:
                    self.assertEqual(pin["source_status"], "READY")
                    self.assertEqual(pin["withheld"], EXPECTED_SUCCESSOR_WITHHELD)
                else:
                    self.assertEqual(pin["source_status"], "BLOCKED")
                    self.assertTrue(pin["withheld"])
                self.assertEqual(
                    pin["qualified_platforms"],
                    list(TARGETS) if project in {"theme-forge-solar-sail", "theme-forge-stellar-loom"} else [],
                )
                self.assertIsInstance(pin["withheld"], list)
                self.assertEqual(pin["candidate_platforms"], list(TARGETS))
                self.assertEqual(validate_pin(pin), pin)
                self.assertEqual(build_pin(pin), {**pin, "qualified_platforms": []})
                self.assertEqual(
                    p.approval_path(pin).name,
                    f"{project}-{spec['version']}-artifacts.json",
                )
                self.assertEqual(
                    p.approval_path(project, abs_path),
                    p.approval_path(pin),
                )
        finally:
            os.chdir(previous_cwd)

    def test_current_approval_manifests_are_exact_and_admitted(self):
        expected = {
            "theme-forge-solar-sail": (
                "0.3.0",
                "7da37398aed89bda28ceddfe015fc307deb7fec32812a8bc11980096b1d85ce2",
                "3e04e6af27a59262a590507bc8dcce631a267e92a1b3426db36755bd3c4f8c88",
            ),
            "theme-forge-stellar-loom": (
                "0.5.0",
                "6a41854669eee7630aa843cce6943e1b1dec9a6d423d219641af6581f66a1d4c",
                "3d9ab535c3d17a850849f0517cbbd03ce2eb180b9a66c0de8f94cd485a766caf",
            ),
        }
        for project, (version, file_sha, set_sha) in expected.items():
            with self.subTest(project=project):
                pin = load_pin(project, PIN_DIR / f"{project}-{version}.json")
                raw = physical_bytes(p.approval_path(pin))
                self.assertEqual(sha256(raw), file_sha)
                record = strict_json(raw)
                self.assertEqual(record["schema"], "rs9.tf-pypi-candidate-aggregate.v1")
                self.assertEqual(record["project"], project)
                self.assertEqual(record["version"], pin["distribution_version"])
                self.assertEqual(record["upstream_version"], pin["version"])
                self.assertEqual(record["targets"], list(TARGETS))
                self.assertEqual(record["set_sha256"], set_sha)
                self.assertIs(record["publication_admitted"], True)
                self.assertEqual(len(record["files"]), 4)
                self.assertEqual(
                    [row["filename"] for row in record["files"]],
                    sorted(row["filename"] for row in record["files"]),
                )

    def test_historical_defaults_and_explicit_historical_paths_unchanged(self):
        for project, (upstream_ver, dist_ver, desc_file) in HISTORICAL_SPECS.items():
            default_pin = load_pin(project)
            explicit_pin = load_pin(project, PIN_DIR / f"{project}.json")
            self.assertEqual(default_pin, explicit_pin)
            self.assertEqual(default_pin["version"], upstream_ver)
            self.assertEqual(default_pin["distribution_version"], dist_ver)
            self.assertEqual(DISTRIBUTIONS[project], dist_ver)
            self.assertNotIn("description", default_pin)
            self.assertEqual(description_name(default_pin), desc_file)
            pkg = project.replace("-", "_")
            self.assertEqual(
                names(default_pin),
                (pkg, f"{pkg}-{dist_ver}", f"{pkg}-{dist_ver}.dist-info"),
            )

    def test_backend_names_metadata_bytes_toml_and_descriptions_for_all_successors(self):
        synthetic_files = {
            "package/LICENSE": (b"AGPL-3.0-or-later\n", 0o644),
            "package/NOTICE": (b"Notice\n", 0o644),
            "package/COMMERCIAL-LICENSE.md": (b"Commercial\n", 0o644),
        }
        for project, spec in SUCCESSOR_SPECS.items():
            with self.subTest(project=project):
                pin = load_pin(project, PIN_DIR / spec["pin_file"])
                ver = spec["version"]
                pkg = project.replace("-", "_")
                expected_stem = f"{pkg}-{ver}"
                self.assertEqual(
                    names(pin),
                    (pkg, expected_stem, f"{expected_stem}.dist-info"),
                )
                self.assertNotIn("post1", expected_stem)

                urls = project_urls(pin)
                self.assertTrue(urls["Release"].endswith(f"/releases/tag/v{ver}"))
                self.assertTrue(urls["Source"].endswith(f"/tree/{pin['source_commit']}"))

                self.assertEqual(description_name(pin), spec["description"])
                raw_desc = description_bytes(pin)
                self.assertIsInstance(raw_desc, bytes)
                self.assertEqual(raw_desc, physical_bytes(DESC_DIR / spec["description"]))
                self.assertNotEqual(raw_desc, physical_bytes(DESC_DIR / spec["historical_description"]))
                self.assertEqual(description(pin), raw_desc.decode("utf-8"))

                meta_bytes = metadata(pin, synthetic_files)
                self.assertIsInstance(meta_bytes, bytes)
                self.assertIn(f"Name: {project}\n".encode("utf-8"), meta_bytes)
                self.assertIn(f"Version: {ver}\n".encode("utf-8"), meta_bytes)
                self.assertNotIn(b".post1", meta_bytes)
                self.assertTrue(meta_bytes.endswith(b"\n\n" + raw_desc))
                parsed_meta = email.parser.BytesParser().parsebytes(meta_bytes)
                self.assertEqual(parsed_meta["Name"], project)
                self.assertEqual(parsed_meta["Version"], ver)

                toml_bytes = project_toml(pin, synthetic_files)
                self.assertIsInstance(toml_bytes, bytes)
                self.assertIn(f'version = "{ver}"'.encode("utf-8"), toml_bytes)
                self.assertNotIn(b".post1", toml_bytes)
                parsed_toml = tomllib.loads(toml_bytes.decode("utf-8"))
                self.assertEqual(parsed_toml["project"]["name"], project)
                self.assertEqual(parsed_toml["project"]["version"], ver)
                expected_scripts = {
                    cmd: f"{pkg}.launcher:main_{cmd.replace('-', '_')}"
                    for cmd in pin["bins"]
                }
                self.assertEqual(parsed_toml["project"]["scripts"], expected_scripts)

        for project in ("theme-forge-stellar-loom", "theme-forge-solar-sail"):
            pin, data = _successor_fixture(project)
            files = admit_bytes(pin, data, pin["asset"])
            self.assertIn("package/package.json", files)
            wheel = wheel_entries(pin, data, target="darwin-arm64")
            sdist = sdist_entries(pin, data, target="darwin-arm64")
            _, _, info = names(pin)
            self.assertEqual(wheel[info + "/METADATA"][0], sdist["PKG-INFO"][0])
            self.assertEqual(
                sdist["_rs9_build/rs9/descriptions/" + description_name(pin)][0],
                description_bytes(pin),
            )

    def test_independently_varied_pin_and_load_refusals(self):
        burst_pin = load_pin("theme-forge-stellar-burst", PIN_DIR / "theme-forge-stellar-burst-0.7.0.json")
        loom_pin = load_pin("theme-forge-stellar-loom", PIN_DIR / "theme-forge-stellar-loom-0.5.0.json")
        solar_pin = load_pin("theme-forge-solar-sail", PIN_DIR / "theme-forge-solar-sail-0.3.0.json")
        historical_loom = load_pin("theme-forge-stellar-loom")

        self.assertEqual(validate_pin(copy.deepcopy(burst_pin)), burst_pin)
        self.assertEqual(validate_pin(copy.deepcopy(loom_pin)), loom_pin)
        self.assertEqual(validate_pin(copy.deepcopy(solar_pin)), solar_pin)
        self.assertEqual(validate_pin(copy.deepcopy(historical_loom)), historical_loom)

        # Single-field version / cross-pair / arbitrary SemVer variations on valid baseline.
        version_negatives = [
            {**loom_pin, "version": "0.5.1"},
            {**loom_pin, "distribution_version": "0.5.1"},
            {**loom_pin, "distribution_version": "0.5.0.post1"},
            {**loom_pin, "distribution_version": "0.4.0.post1"},
            {**loom_pin, "version": "0.4.0"},
            {**loom_pin, "version": "0.7.0", "distribution_version": "0.7.0"},
            {**burst_pin, "version": "0.5.0", "distribution_version": "0.5.0"},
            {**burst_pin, "distribution_version": "0.6.1.post1"},
            {**burst_pin, "distribution_version": "0.7.0.post1"},
            {**solar_pin, "distribution_version": "0.3.0.post1"},
            {**historical_loom, "distribution_version": "0.4.0"},
        ]
        for mutated in version_negatives:
            with self.subTest(version=mutated.get("version"), dv=mutated.get("distribution_version")):
                self.assertAdmissionError("PIN", validate_pin, mutated)

        # Missing keys and unhashable list/dict values must raise AdmissionError, never TypeError/KeyError.
        for missing_key in ("version", "distribution_version"):
            dropped = copy.deepcopy(loom_pin)
            dropped.pop(missing_key)
            self.assertAdmissionError("PIN", validate_pin, dropped)
            self.assertAdmissionError("PIN", release, dropped)

        dropped_project = copy.deepcopy(loom_pin)
        dropped_project.pop("project")
        self.assertAdmissionError("PRODUCT", validate_pin, dropped_project)
        self.assertAdmissionError("PIN", release, dropped_project)
        self.assertAdmissionError("PIN", release, ["not-a-dict"])

        for bad_val in (["0.5.0"], {"v": "0.5.0"}, None, 5):
            self.assertAdmissionError("PIN", validate_pin, {**loom_pin, "version": bad_val})
            self.assertAdmissionError("PIN", validate_pin, {**loom_pin, "distribution_version": bad_val})
            self.assertAdmissionError("PIN", release, {**loom_pin, "version": bad_val})
            self.assertAdmissionError("PIN", release, {**loom_pin, "distribution_version": bad_val})

        for bad_proj in (["theme-forge-stellar-loom"], {"p": "theme-forge-stellar-loom"}, None, 123):
            self.assertAdmissionError("PRODUCT", validate_pin, {**loom_pin, "project": bad_proj})
            self.assertAdmissionError("PRODUCT", load_pin, bad_proj)
            self.assertAdmissionError("PIN", release, {**loom_pin, "project": bad_proj})

        # Description exactness and traversal refusals on valid successor and historical baselines.
        for bad_desc in (
            "stellar-loom.md",
            "stellar-burst-0.7.0.md",
            "../stellar-loom-0.5.0.md",
            "sub/stellar-loom-0.5.0.md",
            "stellar-loom-0.5.0.txt",
            "",
            None,
            ["stellar-loom-0.5.0.md"],
        ):
            self.assertAdmissionError("DESCRIPTION", validate_pin, {**loom_pin, "description": bad_desc})

        no_desc = copy.deepcopy(loom_pin)
        no_desc.pop("description")
        self.assertAdmissionError("DESCRIPTION", validate_pin, no_desc)
        self.assertAdmissionError(
            "PIN",
            validate_pin,
            {**historical_loom, "description": "stellar-loom.md"},
        )
        for hist_project, (_, _, hist_desc) in HISTORICAL_SPECS.items():
            hist_pin = load_pin(hist_project)
            succ_desc = SUCCESSOR_SPECS[hist_project]["description"]
            for stray_desc in (hist_desc, succ_desc, "", None, ["x.md"], "../x.md"):
                with self.subTest(project=hist_project, description=stray_desc):
                    self.assertAdmissionError(
                        "PIN",
                        validate_pin,
                        {**hist_pin, "description": stray_desc},
                    )

        # Explicit-path load_pin refusals: non-path, symlink, duplicate key, wrong project, body/basename mismatch.
        for bad_path in (123, ["path"], {"path": "x"}, ""):
            self.assertAdmissionError("PIN", load_pin, "theme-forge-stellar-loom", bad_path)

        valid_copy = self.root / "theme-forge-stellar-loom-0.5.0.json"
        valid_copy.write_bytes(physical_bytes(PIN_DIR / "theme-forge-stellar-loom-0.5.0.json"))
        self.assertEqual(load_pin("theme-forge-stellar-loom", valid_copy), loom_pin)

        symlink_dir = self.root / "symdir"
        symlink_dir.mkdir()
        symlink_same_name = symlink_dir / "theme-forge-stellar-loom-0.5.0.json"
        symlink_same_name.symlink_to(valid_copy)
        self.assertAdmissionError("SYMLINK", load_pin, "theme-forge-stellar-loom", symlink_same_name)

        symlink_alt_name = symlink_dir / "alt-link.json"
        symlink_alt_name.symlink_to(valid_copy)
        self.assertAdmissionError("SYMLINK", load_pin, "theme-forge-stellar-loom", symlink_alt_name)

        dup_dir = self.root / "dup"
        dup_dir.mkdir()
        dup_file = dup_dir / "theme-forge-stellar-loom-0.5.0.json"
        dup_file.write_bytes(
            b'{"project":"theme-forge-stellar-loom","project":"theme-forge-stellar-loom"}\n'
        )
        self.assertAdmissionError("JSON", load_pin, "theme-forge-stellar-loom", dup_file)

        wrong_proj_dir = self.root / "wrong-proj"
        wrong_proj_dir.mkdir()
        loom_under_burst_name = wrong_proj_dir / "theme-forge-stellar-burst-0.7.0.json"
        loom_under_burst_name.write_bytes(canonical(loom_pin))
        self.assertAdmissionError("PRODUCT", load_pin, "theme-forge-stellar-burst", loom_under_burst_name)

        unhashable_proj_file = wrong_proj_dir / "theme-forge-stellar-loom-0.5.0.json"
        unhashable_proj_file.write_bytes(
            b'{"project":["theme-forge-stellar-loom"],"version":"0.5.0","distribution_version":"0.5.0"}\n'
        )
        self.assertAdmissionError("PRODUCT", load_pin, "theme-forge-stellar-loom", unhashable_proj_file)

        unhashable_ver_file = self.root / "unhashable-ver" / "theme-forge-stellar-loom-0.5.0.json"
        unhashable_ver_file.parent.mkdir()
        unhashable_ver_file.write_bytes(canonical({**loom_pin, "version": ["0.5.0"]}))
        self.assertAdmissionError("PIN", load_pin, "theme-forge-stellar-loom", unhashable_ver_file)

        # Body/basename mismatches: 0.7.0 body under project.json and 0.6.1.post1 body under -0.7.0.json.
        mismatch_dir = self.root / "mismatch"
        mismatch_dir.mkdir()
        succ_in_hist = mismatch_dir / "theme-forge-stellar-burst.json"
        succ_in_hist.write_bytes(canonical(burst_pin))
        self.assertAdmissionError("PIN", load_pin, "theme-forge-stellar-burst", succ_in_hist)

        hist_in_succ = mismatch_dir / "theme-forge-stellar-burst-0.7.0.json"
        hist_in_succ.write_bytes(canonical(load_pin("theme-forge-stellar-burst")))
        self.assertAdmissionError("PIN", load_pin, "theme-forge-stellar-burst", hist_in_succ)

        unlisted_basename = mismatch_dir / "theme-forge-stellar-burst-0.7.1.json"
        unlisted_basename.write_bytes(canonical(burst_pin))
        self.assertAdmissionError("PIN", load_pin, "theme-forge-stellar-burst", unlisted_basename)

        # Cross-project basename rejected before file open.
        self.assertAdmissionError(
            "PIN",
            load_pin,
            "theme-forge-stellar-burst",
            self.root / "nonexistent" / "theme-forge-stellar-loom-0.5.0.json",
        )
        self.assertAdmissionError(
            "ASSET_ABSENT",
            load_pin,
            "theme-forge-stellar-burst",
            self.root / "nonexistent" / "theme-forge-stellar-burst-0.7.0.json",
        )

    def test_workflow_cli_forwards_selected_pin_and_rejects_before_writes(self):
        project = "theme-forge-stellar-burst"
        pin_path = PIN_DIR / "theme-forge-stellar-burst-0.7.0.json"
        expected_pin = load_pin(project, pin_path)
        inputs_dir = self.root / "inputs"
        inputs_dir.mkdir()
        out_dir = self.root / "out"
        dist_dir = self.root / "dist"
        work_dir = self.root / "work"

        # 1. status
        buf = _BufferStdout()
        with patch.object(w, "project_state", return_value="absent") as state_mock, \
                patch("sys.stdout", buf):
            rc = w.main(["status", "--project", project, "--pin", str(pin_path), "--remote"])
        self.assertEqual(rc, 0)
        state_mock.assert_called_once_with(expected_pin)
        status_doc = json.loads(buf.buffer.getvalue())
        self.assertEqual(status_doc["version"], "0.7.0")
        self.assertEqual(status_doc["upstream_version"], "0.7.0")
        self.assertEqual(status_doc["source"], "BLOCKED")

        # 2. fetch
        buf = _BufferStdout()
        with patch.object(w, "fetch", return_value={"fetched": True}) as fetch_mock, \
                patch("sys.stdout", buf):
            rc = w.main(["fetch", "--project", project, "--pin", str(pin_path), "--output", str(out_dir)])
        self.assertEqual(rc, 0)
        fetch_mock.assert_called_once_with(expected_pin, out_dir)

        # 3. intake
        buf = _BufferStdout()
        with patch.object(w, "intake", return_value=(b"tar", {"package/package.json": (b"{}", 0o644)})) as intake_mock, \
                patch("sys.stdout", buf):
            rc = w.main(["intake", "--project", project, "--pin", str(pin_path), "--inputs", str(inputs_dir)])
        self.assertEqual(rc, 0)
        intake_mock.assert_called_once_with(expected_pin, inputs_dir / expected_pin["asset"])

        # 4. build
        buf = _BufferStdout()
        with patch.object(w, "intake", return_value=(b"tar", {"package/package.json": (b"{}", 0o644)})) as intake_mock, \
                patch.object(w, "load_dependencies", return_value={"dep": b"1"}) as deps_mock, \
                patch.object(w, "build_aggregate") as build_mock, \
                patch.object(w, "verify_aggregate", return_value={"version": "0.7.0"}) as verify_mock, \
                patch("sys.stdout", buf):
            rc = w.main([
                "build", "--project", project, "--pin", str(pin_path),
                "--inputs", str(inputs_dir), "--output", str(out_dir),
            ])
        self.assertEqual(rc, 0)
        intake_mock.assert_called_once_with(expected_pin, inputs_dir / expected_pin["asset"])
        deps_mock.assert_called_once_with(inputs_dir)
        build_mock.assert_called_once_with(expected_pin, b"tar", out_dir, {"dep": b"1"})
        verify_mock.assert_called_once_with(expected_pin, out_dir)

        # 5. verify
        buf = _BufferStdout()
        with patch.object(w, "verify_aggregate", return_value={"version": "0.7.0"}) as verify_mock, \
                patch("sys.stdout", buf):
            rc = w.main(["verify", "--project", project, "--pin", str(pin_path), "--dist", str(dist_dir)])
        self.assertEqual(rc, 0)
        verify_mock.assert_called_once_with(expected_pin, dist_dir)

        # 6. consumer
        buf = _BufferStdout()
        with patch.object(w, "host_key", return_value="darwin-arm64"), \
                patch.object(w, "host_view") as view_mock, \
                patch.object(w, "smoke", return_value={"functional": True}) as smoke_mock, \
                patch("sys.stdout", buf):
            rc = w.main([
                "consumer", "--project", project, "--pin", str(pin_path),
                "--dist", str(dist_dir), "--work", str(work_dir),
            ])
        self.assertEqual(rc, 0)
        view_mock.assert_called_once_with(expected_pin, dist_dir, "darwin-arm64", work_dir / "view")
        smoke_mock.assert_called_once_with(
            expected_pin, work_dir / "view", work_dir / "consumer", offline_linux=False
        )

        # Invalid --pin fails closed before calling any operation or creating directories.
        bad_pin_path = self.root / "theme-forge-stellar-burst-0.7.1.json"
        bad_pin_path.write_bytes(canonical(expected_pin))
        unused_work = self.root / "unused-work"
        unused_out = self.root / "unused-out"
        err = io.StringIO()
        with patch.object(w, "fetch", side_effect=AssertionError("fetch called")) as fetch_mock, \
                patch.object(w, "host_view", side_effect=AssertionError("view called")) as view_mock, \
                patch.object(w, "smoke", side_effect=AssertionError("smoke called")) as smoke_mock, \
                patch("sys.stderr", err):
            rc1 = w.main(["fetch", "--project", project, "--pin", str(bad_pin_path), "--output", str(unused_out)])
            rc2 = w.main([
                "consumer", "--project", project, "--pin", str(bad_pin_path),
                "--dist", str(dist_dir), "--work", str(unused_work),
            ])
        self.assertEqual(rc1, 1)
        self.assertEqual(rc2, 1)
        self.assertEqual(err.getvalue(), "TF_PYPI_PIN\nTF_PYPI_PIN\n")
        fetch_mock.assert_not_called()
        view_mock.assert_not_called()
        smoke_mock.assert_not_called()
        self.assertFalse(unused_out.exists())
        self.assertFalse(unused_work.exists())

    def test_publish_and_hosted_clis_and_helpers_share_same_selection_before_writes(self):
        project = "theme-forge-stellar-burst"
        pin_path = PIN_DIR / "theme-forge-stellar-burst-0.7.0.json"
        selected = load_pin(project, pin_path)
        inputs_dir = self.root / "inputs"
        inputs_dir.mkdir()
        dist_dir = self.root / "dist"
        upload_dir = self.root / "upload"
        receipts_dir = self.root / "receipts"

        # Publish build --pin forwards selected pin to intake/build_aggregate/verify_aggregate.
        buf = _BufferStdout()
        with patch.object(p, "intake", return_value=(b"tar", {})) as intake_mock, \
                patch.object(p, "load_dependencies", return_value={"d": b"1"}) as deps_mock, \
                patch.object(p, "build_aggregate") as build_mock, \
                patch.object(p, "verify_aggregate", return_value={"version": "0.7.0"}) as verify_mock, \
                patch("sys.stdout", buf):
            rc = p.main([
                "build", "--project", project, "--pin", str(pin_path),
                "--inputs", str(inputs_dir), "--output", str(dist_dir),
            ])
        self.assertEqual(rc, 0)
        intake_mock.assert_called_once_with(selected, inputs_dir / selected["asset"])
        deps_mock.assert_called_once_with(inputs_dir)
        build_mock.assert_called_once_with(selected, b"tar", dist_dir, dependencies={"d": b"1"})
        verify_mock.assert_called_once_with(selected, dist_dir)

        # Real BLOCKED successor pin on select-missing and readback fails with SOURCE_NOT_READY
        # before approval read, matrix admission, remote state, or upload directory creation.
        for argv in (
            [
                "select-missing", "--project", project, "--pin", str(pin_path),
                "--dist", str(dist_dir), "--upload-dir", str(upload_dir),
                "--receipts", str(receipts_dir), "--expected-commit", COMMIT,
            ],
            [
                "readback", "--project", project, "--pin", str(pin_path),
                "--dist", str(dist_dir),
            ],
        ):
            err = io.StringIO()
            with patch.object(p, "load_approval", side_effect=AssertionError("approval read")) as app_mock, \
                    patch.object(p, "admit_matrix", side_effect=AssertionError("matrix called")) as mat_mock, \
                    patch.object(p, "exact_state", side_effect=AssertionError("remote called")) as rem_mock, \
                    patch("sys.stderr", err):
                rc = p.main(argv)
            self.assertEqual(rc, 1)
            self.assertEqual(err.getvalue(), "TF_PYPI_SOURCE_NOT_READY\n")
            app_mock.assert_not_called()
            mat_mock.assert_not_called()
            rem_mock.assert_not_called()
            self.assertFalse(upload_dir.exists())

        # Same-selection identity without reload across select_missing -> verify_approved -> admit_matrix,
        # and across hosted qualify / admit_matrix.
        ready_copy = copy.deepcopy(selected)
        ready_copy["source_status"] = "READY"
        ready_copy["qualified_platforms"] = list(TARGETS)
        seen_pins = []

        def spy_verify_approved(pin_arg, dist_arg):
            seen_pins.append(("verify_approved", pin_arg))
            return {"publication_admitted": True, "files": []}

        def spy_admit_matrix(pin_arg, *args):
            seen_pins.append(("admit_matrix", pin_arg))
            fail("HOSTED_MATRIX_RECEIPT")

        with patch.object(p, "load_pin", side_effect=AssertionError("publish reloaded pin")), \
                patch.object(h, "load_pin", side_effect=AssertionError("hosted reloaded pin")), \
                patch.object(p, "verify_approved", side_effect=spy_verify_approved), \
                patch.object(p, "admit_matrix", side_effect=spy_admit_matrix), \
                patch.object(p, "exact_state", side_effect=AssertionError("remote called")):
            self.assertAdmissionError(
                "HOSTED_MATRIX_RECEIPT",
                p.select_missing,
                ready_copy,
                dist=dist_dir,
                upload_dir=upload_dir,
                receipts=receipts_dir,
                expected_commit=COMMIT,
                run_id=RUN_ID,
                run_attempt="1",
            )
        self.assertEqual([name for name, _ in seen_pins], ["verify_approved", "admit_matrix"])
        self.assertIs(seen_pins[0][1], ready_copy)
        self.assertIs(seen_pins[1][1], ready_copy)
        self.assertFalse(upload_dir.exists())

        # Direct hosted qualify and admit_matrix with pre-validated mapping do not reload load_pin.
        qualify_seen = []
        admit_seen = []
        with patch.object(h, "load_pin", side_effect=AssertionError("hosted reloaded pin")), \
                patch.object(h, "host_key", return_value="darwin-arm64"), \
                patch.object(h, "source_commit", return_value=COMMIT), \
                patch.object(
                    h,
                    "verify_aggregate",
                    side_effect=lambda pin_arg, _: qualify_seen.append(pin_arg) or fail("FILE_SET"),
                ):
            self.assertAdmissionError(
                "FILE_SET",
                h.qualify,
                project,
                dist_dir,
                self.root / "qwork",
                COMMIT,
                target="darwin-arm64",
                pin=selected,
            )
        self.assertEqual(len(qualify_seen), 1)
        self.assertIs(qualify_seen[0], selected)

        with patch.object(h, "load_pin", side_effect=AssertionError("hosted reloaded pin")), \
                patch.object(h, "source_commit", return_value=COMMIT), \
                patch.object(
                    h,
                    "verify_aggregate",
                    side_effect=lambda pin_arg, _: admit_seen.append(pin_arg) or fail("FILE_SET"),
                ):
            self.assertAdmissionError(
                "FILE_SET",
                h.admit_matrix,
                selected,
                dist_dir,
                receipts_dir,
                COMMIT,
                RUN_ID,
                "1",
            )
        self.assertEqual(len(admit_seen), 1)
        self.assertIs(admit_seen[0], selected)

        # Project mismatch in hosted.qualify(project, ..., pin=other_pin) fails with PRODUCT.
        loom_pin = load_pin("theme-forge-stellar-loom", PIN_DIR / "theme-forge-stellar-loom-0.5.0.json")
        self.assertAdmissionError(
            "PRODUCT",
            h.qualify,
            project,
            dist_dir,
            self.root / "qwork2",
            COMMIT,
            pin=loom_pin,
        )

        # Hosted CLI main with valid --pin forwards selected mapping; with invalid --pin rejects before writes.
        report_file = self.root / "report" / "result.json"
        q_work = self.root / "cli-qwork"
        out_stream = io.StringIO()
        with patch.object(h, "qualify", return_value={"status": "native-consumer-passed"}) as q_mock, \
                patch.object(h, "write_report") as w_mock, \
                patch("sys.stdout", out_stream):
            rc = h.main([
                "qualify", "--project", project, "--pin", str(pin_path),
                "--dist", str(dist_dir), "--work", str(q_work),
                "--report", str(report_file), "--expected-commit", COMMIT,
            ])
        self.assertEqual(rc, 0)
        q_mock.assert_called_once()
        self.assertEqual(q_mock.call_args.kwargs["pin"], selected)
        w_mock.assert_called_once()

        bad_pin = self.root / "theme-forge-stellar-burst-0.7.1.json"
        bad_pin.write_bytes(canonical(selected))
        refused_report = self.root / "refused-report" / "result.json"
        refused_work = self.root / "refused-work"
        for bad_argv in (
            [
                "qualify", "--project", project, "--pin", str(bad_pin),
                "--dist", str(dist_dir), "--work", str(refused_work),
                "--report", str(refused_report), "--expected-commit", COMMIT,
            ],
            [
                "admit", "--project", project, "--pin", str(bad_pin),
                "--dist", str(dist_dir), "--receipts", str(receipts_dir),
                "--report", str(refused_report), "--expected-commit", COMMIT,
            ],
        ):
            err = io.StringIO()
            with patch.object(h, "qualify", side_effect=AssertionError("qualify called")) as q_mock, \
                    patch.object(h, "admit_matrix", side_effect=AssertionError("admit called")) as a_mock, \
                    patch.object(h, "write_report", side_effect=AssertionError("report written")) as w_mock, \
                    patch("sys.stderr", err):
                rc = h.main(bad_argv)
            self.assertEqual(rc, 1)
            self.assertEqual(err.getvalue(), "TF_PYPI_PIN\n")
            q_mock.assert_not_called()
            a_mock.assert_not_called()
            w_mock.assert_not_called()
            self.assertFalse(refused_report.exists())
            self.assertFalse(refused_report.parent.exists())
            self.assertFalse(refused_work.exists())

    def _extract_module_invocations(self, doc):
        invocations = []
        for job_id, job in doc["jobs"].items():
            for step in job["steps"]:
                run_text = step.get("run")
                if not run_text:
                    continue
                joined = run_text.replace("\\\n", " ")
                for line in joined.splitlines():
                    for module in ("rs9.tf_pypi_publish", "rs9.tf_pypi_hosted"):
                        if f"-m {module}" in line:
                            tokens = shlex.split(line)
                            if ">>" in tokens:
                                tokens = tokens[:tokens.index(">>")]
                            idx = tokens.index(module)
                            invocations.append((job_id, module, tokens[idx + 1:]))
        return invocations

    def test_successor_qualification_list_normalization_preserves_aggregate_bytes(self):
        # Synthetic metadata transition only: this is not a native qualification.
        pin, data = _successor_fixture()
        before = copy.deepcopy(pin)
        before.update(
            source_status="READY",
            withheld=copy.deepcopy(EXPECTED_SUCCESSOR_WITHHELD),
            qualified_platforms=[],
        )
        after = copy.deepcopy(before)
        after["qualified_platforms"] = list(TARGETS)
        saved_before = copy.deepcopy(before)
        saved_after = copy.deepcopy(after)
        self.assertEqual(before["withheld"], EXPECTED_SUCCESSOR_WITHHELD)
        self.assertEqual(after["withheld"], EXPECTED_SUCCESSOR_WITHHELD)
        self.assertNotEqual(before["qualified_platforms"], after["qualified_platforms"])
        self.assertEqual(build_pin(before), build_pin(after))
        self.assertEqual(build_pin(after)["qualified_platforms"], [])
        self.assertEqual(build_pin(before)["withheld"], EXPECTED_SUCCESSOR_WITHHELD)
        self.assertEqual(build_pin(after)["withheld"], EXPECTED_SUCCESSOR_WITHHELD)

        for target in TARGETS:
            with self.subTest(target=target):
                self.assertEqual(
                    wheel_entries(before, data, target=target),
                    wheel_entries(after, data, target=target),
                )
                first_sdist = sdist_entries(before, data, target=target)
                second_sdist = sdist_entries(after, data, target=target)
                self.assertEqual(first_sdist, second_sdist)
                first_pin = first_sdist["_rs9_build/rs9/pins.json"][0]
                second_pin = second_sdist["_rs9_build/rs9/pins.json"][0]
                self.assertEqual(first_pin, second_pin)
                self.assertEqual(strict_json(first_pin), build_pin(before))
                self.assertEqual(strict_json(second_pin)["qualified_platforms"], [])
                self.assertEqual(strict_json(first_pin)["withheld"], EXPECTED_SUCCESSOR_WITHHELD)
                self.assertEqual(strict_json(second_pin)["withheld"], EXPECTED_SUCCESSOR_WITHHELD)

        one = self.root / "successor-unqualified-aggregate"
        two = self.root / "successor-qualified-metadata-aggregate"
        self.assertEqual(build_aggregate(before, data, one), build_aggregate(after, data, two))
        first_manifest = verify_aggregate(before, one)
        second_manifest = verify_aggregate(after, two)
        self.assertEqual(first_manifest, second_manifest)
        self.assertIs(first_manifest["publication_admitted"], False)
        self.assertEqual(len(first_manifest["files"]), 4)
        self.assertEqual(
            {path.name: path.read_bytes() for path in one.iterdir()},
            {path.name: path.read_bytes() for path in two.iterdir()},
        )
        self.assertEqual(before, saved_before)
        self.assertEqual(after, saved_after)

    def test_generated_workflow_propagates_closed_relative_pin_and_preserves_historical_bytes(self):
        workflows = ROOT / ".github/workflows"
        for project in sorted(PRODUCTS):
            hist_pin = load_pin(project)
            explicit_hist_pin = load_pin(project, PIN_DIR / f"{project}.json")
            # Registered workflows now select successors; historical generation
            # remains bound to the exact previous workflow bytes by digest.
            historical_bytes = p.workflow_text(hist_pin).encode("utf-8")
            self.assertEqual(sha256(historical_bytes), HISTORICAL_WORKFLOW_SHA256[project])
            self.assertEqual(p.workflow_text(project).encode("utf-8"), historical_bytes)
            self.assertEqual(p.workflow_text(hist_pin).encode("utf-8"), historical_bytes)
            self.assertEqual(p.workflow_text(explicit_hist_pin).encode("utf-8"), historical_bytes)
            self.assertEqual(
                p.workflow_text(project, PIN_DIR / f"{project}.json").encode("utf-8"),
                historical_bytes,
            )

        previous_cwd = Path.cwd()
        try:
            os.chdir(ROOT)
            for project, spec in SUCCESSOR_SPECS.items():
                temp_pin_file = self.root / spec["pin_file"]
                temp_pin_file.write_bytes(physical_bytes(PIN_DIR / spec["pin_file"]))

                out_buf = io.StringIO()
                with patch("sys.stdout", out_buf):
                    rc = p.main(["workflow", "--project", project, "--pin", str(temp_pin_file)])
                self.assertEqual(rc, 0)
                text = out_buf.getvalue()

                expected_rel = f"operators/tf-pypi/{spec['pin_file']}"
                expected_selector = f" --pin {expected_rel}"
                self.assertNotIn(str(self.root), text)
                self.assertNotIn(str(ROOT), text)
                self.assertEqual(text.count(expected_selector), 7)
                self.assertEqual(
                    sha256(text.replace(expected_selector, "").encode("utf-8")),
                    HISTORICAL_WORKFLOW_SHA256[project],
                )
                self.assertEqual(
                    text.encode("utf-8"),
                    (workflows / load_pin(project)["workflow"]).read_bytes(),
                )

                doc = yaml.safe_load(text)
                invocations = self._extract_module_invocations(doc)
                self.assertEqual(len(invocations), 7)

                expected_pin = load_pin(project, PIN_DIR / spec["pin_file"])
                publish_ops = []
                qualify_targets = []
                admit_jobs = []

                for job_id, module, argv in invocations:
                    self.assertIn("--pin", argv)
                    pin_idx = argv.index("--pin")
                    self.assertEqual(argv[pin_idx + 1], expected_rel)
                    if module == "rs9.tf_pypi_publish":
                        args = p.parser().parse_args(argv)
                        self.assertEqual(args.project, project)
                        self.assertEqual(args.pin, Path(expected_rel))
                        self.assertEqual(load_pin(args.project, args.pin), expected_pin)
                        publish_ops.append(args.operation)
                    else:
                        out_stream = _BufferStdout()
                        err_stream = io.StringIO()
                        with patch.object(h, "qualify", return_value={"status": "native-consumer-passed"}) as q_mock, \
                                patch.object(h, "admit_matrix", return_value={"status": "native-matrix-passed"}) as a_mock, \
                                patch.object(h, "write_report"), \
                                patch("sys.stdout", out_stream), \
                                patch("sys.stderr", err_stream):
                            rc = h.main(argv)
                        self.assertEqual(rc, 0, err_stream.getvalue())
                        if argv[0] == "qualify":
                            q_mock.assert_called_once()
                            self.assertEqual(q_mock.call_args.kwargs["pin"], expected_pin)
                            qualify_targets.append(q_mock.call_args.kwargs["target"])
                        elif argv[0] == "admit":
                            a_mock.assert_called_once()
                            self.assertEqual(a_mock.call_args.args[0], expected_pin)
                            admit_jobs.append(job_id)

                self.assertEqual(publish_ops, ["build", "select-missing", "readback"])
                self.assertEqual(qualify_targets, list(TARGETS))
                self.assertEqual(admit_jobs, ["qualification_gate"])
        finally:
            os.chdir(previous_cwd)


if __name__ == "__main__":
    unittest.main()
