"""Closed generation routing and real capture/bootstrap/profile boundaries."""
import base64
import hashlib
import json
from pathlib import Path
import shutil
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from rs9.bootstrap import configuration_inventory, load_bootstrap
from rs9.candidate import capture_generation, configuration_rows
from rs9.command_report import report_generation
from rs9.current_generation import (CURRENT_GENERATION, HISTORICAL_GENERATION,
                                    generation_paths)
from rs9.current_npm_profile import CURRENT_PACKAGE_PROFILE
from rs9.errors import ContractError
from rs9.operator import BOOTSTRAP, EXPECTATIONS, authenticate_generation, assert_release_expectations
from rs9.profiles import PROFILE_ROLES, PACKAGE_PROFILE, evaluate_profile, selection_for_intent
from rs9.records import record_sha256
from rs9.release_core import authenticate_release, digest
from rs9.scratch import canonical
from tests.release_fixtures import package_evidence
from tests.shadow_fixtures import tar_bytes

ROOT = Path(__file__).resolve().parents[1]


def current_fixture(root, product="stellar-loom", *, receipt_change=None, packaged_notice=None, engine=None):
    """Synthetic bytes use the real release, bootstrap and profile mechanisms."""
    evidence = root / "capture"
    evidence.mkdir()
    intent = package_evidence(evidence)
    project = "theme-forge-" + product
    version = {"stellar-burst": "0.7.0", "stellar-loom": "0.5.0", "solar-sail": "0.3.0"}[product]
    repository = "Knowledge-Forge-AI/" + project
    package = {"name": "@knowledge-forge-ai/" + project, "version": version,
               "license": "MIT", "bin": {"second": "bin/run.js"}}
    if engine is not None:
        package["engines"] = {"node": engine}
    source = {"package.json": canonical(package), "LICENSE": b"Synthetic MIT license\n",
              "NOTICE": b"Synthetic notice\n", "COMMERCIAL-LICENSE.md": b"Synthetic terms\n"}
    if product == "stellar-burst":
        source["package-lock.json"] = canonical({"lockfileVersion": 3})
    archive = tar_bytes([("package/package.json", source["package.json"], 0o644, tarfile.REGTYPE, ""),
                         ("package/bin/run.js", b"#!/usr/bin/env node\n", 0o755, tarfile.REGTYPE, ""),
                         ("package/LICENSE", source["LICENSE"], 0o644, tarfile.REGTYPE, ""),
                         ("package/NOTICE", packaged_notice or source["NOTICE"], 0o644, tarfile.REGTYPE, "")])
    archive_name = project + "-" + version + ".tgz"
    binding = {"bytes": len(archive), "sha256": digest(archive)}
    if product == "stellar-burst":
        receipt = {"schema": "tf.burst-release-root-receipt.v1", "schemaVersion": 1,
                   "repository": repository, "product": product, "version": version, "status": "pass",
                   "provenanceClaimed": False, "publicationAdmitted": False, "signatureClaimed": False,
                   "references": [{"name": archive_name, **binding}],
                   "binding": {"projection": {"sourceCommit": "c" * 40}}}
    else:
        receipt = {"schema": "tf.js-release-root-package-receipt.v2", "package": package["name"],
                   "version": version, "archive": {**binding, "sri": "sha512-" +
                       base64.b64encode(hashlib.sha512(archive).digest()).decode()},
                   "producerEvidence": {"preflight": {"sourceCommit": "c" * 40}}}
    if receipt_change:
        receipt_change(receipt)
    assets = {archive_name: archive, "root-package.receipt.json": canonical(receipt)}
    assets["SHA256SUMS"] = "".join(digest(data) + "  " + name + "\n" for name, data in sorted(assets.items())).encode()
    for family in ("assets", "source"):
        shutil.rmtree(evidence / family)
        (evidence / family).mkdir()
    for name, data in assets.items():
        (evidence / "assets" / name).write_bytes(data)
    for name, data in source.items():
        (evidence / "source" / name).write_bytes(data)
    api = evidence / "api"
    (api / "repository.json").write_bytes(canonical({"id": 12, "full_name": repository}))
    (api / "ref.json").write_bytes(canonical({"ref": "refs/tags/v" + version,
                                               "object": {"type": "commit", "sha": "a" * 40}}))
    (api / "tree.json").write_bytes(canonical({"sha": "b" * 40, "truncated": False, "tree": [
        {"path": name, "sha": hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest(),
         "type": "blob", "mode": "100644"} for name, data in sorted(source.items())]}))
    (api / "release.json").write_bytes(canonical({"id": 34, "tag_name": "v" + version,
        "target_commitish": "a" * 40, "draft": False, "prerelease": False,
        "immutable": False, "published_at": "2026-10-29T02:09:29Z", "assets": [
            {"id": index + 1, "name": name, "size": len(data), "digest": "sha256:" + digest(data), "state": "uploaded"}
            for index, (name, data) in enumerate(assets.items())]}))
    intent.update(project={"id": project, "repository": repository}, version=version, tag="v" + version)
    intent["license"]["files"] = ["LICENSE", "NOTICE", "COMMERCIAL-LICENSE.md"]
    intent["release"]["evidence"] = {"profile": CURRENT_PACKAGE_PROFILE, "checksums": "SHA256SUMS",
        "assets": [{"role": "root-package-receipt", "name": "root-package.receipt.json"}]}
    intent["assets"][0]["name"] = archive_name
    base = root / "bootstrap"
    directory = base / project
    directory.mkdir(parents=True)
    (directory / "intent.json").write_bytes(canonical(intent))
    manifest = {"schema": "rs9.bootstrap-tenant-manifest.v1alpha1", "bootstrap-pre-rs9": True,
        "release-contains-rs9": False, "scope": "exact-generation", "future-releases": "forbidden", "projects": [
            {"repository": repository, "repository_id": 12, "release_id": 34, "tag": intent["tag"],
             "version": version, "tag_commit": "a" * 40, "tag_tree": "b" * 40, "configuration": project,
             "config_sha256": record_sha256(configuration_inventory(directory))}]}
    manifest_path = base / "manifest.json"
    manifest_path.write_bytes(canonical(manifest))
    capture = authenticate_release(selection_for_intent(intent), evidence)
    return capture, intent, manifest_path


class CurrentGenerationTests(unittest.TestCase):
    def test_historical_default_is_unchanged(self):
        self.assertEqual(generation_paths(), (BOOTSTRAP, EXPECTATIONS))
        self.assertEqual(configuration_rows(ROOT), configuration_rows(ROOT, generation=HISTORICAL_GENERATION))
        self.assertEqual([intent["version"] for _, intent in configuration_rows(ROOT)],
                         ["0.6.1", "0.4.0", "0.2.1", "0.6.1"])
        self.assertEqual(PROFILE_ROLES[PACKAGE_PROFILE], {"provenance", "notice"})

    def test_unknown_selector_refused_before_network(self):
        with tempfile.TemporaryDirectory() as temporary:
            with patch("rs9.candidate.PublicClient") as client:
                for generation in ("latest", "../theme-forge-live1", None, {}):
                    with self.subTest(generation=generation), self.assertRaises(ContractError) as caught:
                        capture_generation(ROOT, temporary, generation=generation)
                    self.assertEqual(caught.exception.code, "GENERATION_SELECTION")
                client.assert_not_called()

    def test_current_metadata_has_exact_bindings_and_actual_roles(self):
        manifest, expectations = generation_paths(CURRENT_GENERATION)
        expected = {row["repository"]: row for row in json.loads((ROOT / expectations).read_bytes())["projects"]}
        rows = configuration_rows(ROOT, generation=CURRENT_GENERATION)
        self.assertEqual([intent["version"] for _, intent in rows], ["0.7.0", "0.5.0", "0.3.0", "0.7.1"])
        self.assertEqual([(row["repository_id"], row["release_id"], row["tag_commit"], row["tag_tree"]) for row, _ in rows], [
            (1342490027, 424873797, "3edb9d2c40dd19a2b7d97d9309bc210e7fed711c", "4be1551c49b15dff788d07ed1fb00ddcd8839a76"),
            (1361513719, 423916361, "9063fe5d283881f464ab566d8b74296a6ce1b688", "9ac1906d36baff63fd3e28f49d50ce2e0e07ee04"),
            (1374611333, 423916603, "eafd594af8bce04ef3752c489ae770946b4e0e3b", "a87aa8428f7b5d773683c8fb4ab0135b1ff73fd0"),
            (1358643872, 429782340, "f2c527ee6f3cbd53fd44e095d5355ca7f5c7519a", "6e3561855f6ee0093fb709488ad976b69bf501d2")])
        data = json.loads((ROOT / manifest).read_bytes())
        self.assertEqual((data["scope"], data["future-releases"], data["release-contains-rs9"]),
                         ("exact-generation", "forbidden", False))
        for row, intent in rows:
            binding = expected[row["repository"]]
            for source, target in (("repository_id", "repository_id"), ("release_id", "release_id"),
                                   ("tag", "tag"), ("tag_commit", "commit"), ("tag_tree", "tree")):
                self.assertEqual(row[source], binding[target])
            names = {asset["name"] for asset in binding["assets"]}
            self.assertTrue({a["name"] for a in intent["assets"]} <= names)
            self.assertTrue({a["name"] for a in intent["release"]["evidence"]["assets"]} <= names)
            if intent["release"]["evidence"]["profile"] == CURRENT_PACKAGE_PROFILE:
                self.assertEqual(intent["release"]["evidence"]["assets"],
                    [{"role": "root-package-receipt", "name": "root-package.receipt.json"}])
                self.assertTrue({"LICENSE", "NOTICE", "COMMERCIAL-LICENSE.md"} <=
                                set(selection_for_intent(intent)["source_paths"]))

    def test_configuration_tamper_and_future_scope_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest, _ = generation_paths(CURRENT_GENERATION)
            source = ROOT / Path(manifest).parent
            destination = root / Path(manifest).parent
            shutil.copytree(source, destination)
            path = destination / "theme-forge-stellar-loom/intent.json"
            path.write_bytes(path.read_bytes() + b" ")
            with self.assertRaises(ContractError) as caught:
                configuration_rows(root, generation=CURRENT_GENERATION)
            self.assertEqual(caught.exception.code, "BOOTSTRAP_CONFIG")
            path.write_bytes((source / "theme-forge-stellar-loom/intent.json").read_bytes())
            path = root / manifest
            value = json.loads(path.read_bytes())
            value["future-releases"] = "allowed"
            path.write_bytes(canonical(value))
            with self.assertRaises(ContractError) as caught:
                configuration_rows(root, generation=CURRENT_GENERATION)
            self.assertEqual(caught.exception.code, "BOOTSTRAP_SCOPE")

    def test_current_receipts_require_real_capture_and_bootstrap(self):
        for product in ("stellar-burst", "stellar-loom", "solar-sail"):
            with self.subTest(product=product), tempfile.TemporaryDirectory() as temporary:
                capture, intent, manifest = current_fixture(Path(temporary), product)
                with self.assertRaises(ContractError) as caught:
                    evaluate_profile(capture, CURRENT_PACKAGE_PROFILE, intent)
                self.assertEqual(caught.exception.code, "RELEASE_CONFIG_REQUIRED")
                load_bootstrap(manifest, capture, approved_manifests=[digest(manifest.read_bytes())])
                result = evaluate_profile(capture, CURRENT_PACKAGE_PROFILE, intent)["sections"]
                self.assertEqual(result["package"]["version"], intent["version"])
                self.assertFalse(result["receipt"]["publication_authority"])
                self.assertFalse(result["receipt"]["native_qualification"])
                self.assertEqual(result["receipt"]["source_equivalence"], "not-established")
                with self.assertRaises(ContractError):
                    evaluate_profile(capture.record, CURRENT_PACKAGE_PROFILE, intent)

    def test_receipt_bytes_cannot_be_replaced_after_authentication(self):
        with tempfile.TemporaryDirectory() as temporary:
            capture, intent, manifest = current_fixture(Path(temporary))
            load_bootstrap(manifest, capture, approved_manifests=[digest(manifest.read_bytes())])
            receipt = json.loads(capture.evidence_bytes["root-package.receipt.json"])
            receipt["producerEvidence"] = {}
            capture.evidence_bytes["root-package.receipt.json"] = canonical(receipt)
            with self.assertRaises(ContractError) as caught:
                evaluate_profile(capture, CURRENT_PACKAGE_PROFILE, intent)
            self.assertEqual(caught.exception.code, "INPUT_CHANGED")

    def test_tagged_rs9_still_refuses_bootstrap_exception(self):
        with tempfile.TemporaryDirectory() as temporary:
            capture, intent, manifest = current_fixture(Path(temporary))
            tree_path = capture.root / "api/tree.json"
            tree = json.loads(tree_path.read_bytes())
            tree["tree"].append({"path": ".rs9/project.toml", "sha": "d" * 40,
                                 "mode": "100644", "type": "blob"})
            tree_path.write_bytes(canonical(tree))
            capture = authenticate_release(selection_for_intent(intent), capture.root)
            with self.assertRaises(ContractError) as caught:
                load_bootstrap(manifest, capture, approved_manifests=[digest(manifest.read_bytes())])
            self.assertEqual(caught.exception.code, "BOOTSTRAP_AUTHORITY")

    def test_receipt_mismatch_legal_mismatch_and_unknown_schema_rejected(self):
        changes = [lambda r: r.update(version="9.9.9"),
                   lambda r: r.update(schema="unknown"),
                   lambda r: r["archive"].update(sha256="0" * 64),
                   lambda r: r["archive"].update(bytes=1),
                   lambda r: r["archive"].update(sri="sha512-invalid"),
                   lambda r: r.update(package="@knowledge-forge-ai/wrong")]
        for change in changes:
            with tempfile.TemporaryDirectory() as temporary:
                capture, intent, manifest = current_fixture(Path(temporary), receipt_change=change)
                load_bootstrap(manifest, capture, approved_manifests=[digest(manifest.read_bytes())])
                with self.assertRaises(ContractError) as caught:
                    evaluate_profile(capture, CURRENT_PACKAGE_PROFILE, intent)
                self.assertEqual(caught.exception.code, "CURRENT_PACKAGE_RECEIPT")
        with tempfile.TemporaryDirectory() as temporary:
            capture, intent, manifest = current_fixture(Path(temporary), packaged_notice=b"Different\n")
            load_bootstrap(manifest, capture, approved_manifests=[digest(manifest.read_bytes())])
            with self.assertRaises(ContractError) as caught:
                evaluate_profile(capture, CURRENT_PACKAGE_PROFILE, intent)
            self.assertEqual(caught.exception.code, "PAYLOAD_LICENSE_MISMATCH")
        for change in (lambda r: r["references"][0].update(sha256="0" * 64),
                       lambda r: r["references"].append(dict(r["references"][0])),
                       lambda r: r.update(publicationAdmitted=True)):
            with tempfile.TemporaryDirectory() as temporary:
                capture, intent, manifest = current_fixture(Path(temporary), "stellar-burst", receipt_change=change)
                load_bootstrap(manifest, capture, approved_manifests=[digest(manifest.read_bytes())])
                with self.assertRaises(ContractError) as caught:
                    evaluate_profile(capture, CURRENT_PACKAGE_PROFILE, intent)
                self.assertEqual(caught.exception.code, "CURRENT_PACKAGE_RECEIPT")

    def test_exact_expectations_reject_mixed_generation(self):
        with tempfile.TemporaryDirectory() as temporary:
            capture, _, _ = current_fixture(Path(temporary))
            expected = {"repository": capture.record["repository"]["full_name"], "repository_id": 12,
                "tag": capture.record["release"]["tag"], "release_id": 34, "commit": "a" * 40,
                "tree": "b" * 40, "immutable": False, "published_at": "2026-10-29T02:09:29Z",
                "contains_rs9": False, "truncated": False, "assets": []}
            assert_release_expectations(capture, expected)
            for field, value in (("release_id", 35), ("commit", "c" * 40), ("tree", "c" * 40), ("tag", "v0.4.0")):
                with self.subTest(field=field), self.assertRaises(ContractError) as caught:
                    assert_release_expectations(capture, {**expected, field: value})
                self.assertEqual(caught.exception.code, "LIVE1_RELEASE_MISMATCH")
            asset = capture.record["assets"][0]
            expected["assets"] = [{"id": asset["github_asset_id"], "name": asset["name"],
                                   "sha256": asset["sha256"], "size": asset["size"]}]
            assert_release_expectations(capture, expected)
            expected["assets"][0]["id"] += 1
            with self.assertRaises(ContractError) as caught:
                assert_release_expectations(capture, expected)
            self.assertEqual(caught.exception.code, "LIVE1_RELEASE_MISMATCH")

    def test_report_and_fallback_use_selected_generation(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = report_generation(ROOT, temporary, generation=CURRENT_GENERATION)
            self.assertTrue(report["unavailable"])
            from rs9.hosted_deb import _ensure_captures
            with patch("rs9.candidate.capture_generation", return_value=[]) as capture:
                _ensure_captures({"client": object(), "generation": CURRENT_GENERATION}, ROOT, Path(temporary))
                self.assertEqual(capture.call_args.kwargs["generation"], CURRENT_GENERATION)

    def test_hosted_capture_failure_reports_same_selected_generation(self):
        from rs9.hosted_pipeline import run_lane
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary) / "work"
            work.mkdir()
            receipts = Path(temporary) / "receipts"
            with patch.dict("os.environ", {"GITHUB_SHA": "1" * 40, "GITHUB_RUN_ID": "7", "GITHUB_RUN_ATTEMPT": "1",
                    "GITHUB_REPOSITORY": "Knowledge-Forge-AI/release-starport-9", "GITHUB_EVENT_NAME": "push", "GITHUB_REF": "refs/heads/main"}), \
                 patch("rs9.hosted_pipeline.capture_generation", side_effect=ContractError("FETCH_FAILED", "Offline")) as capture, \
                 patch("rs9.hosted_pipeline.report_generation", return_value={}) as report, \
                 patch("rs9.hosted_pipeline.runner_facts", return_value={}):
                self.assertEqual(run_lane(ROOT, work, receipts, "authenticate", "generation",
                    client=object(), generation=CURRENT_GENERATION), 2)
            capture.assert_not_called()
            report.assert_not_called()
            receipt = json.loads((receipts / "authenticate-generation.json").read_bytes())
            manifest = json.loads((receipts / "artifact-manifest.json").read_bytes())
            self.assertEqual(receipt["execution_error"], "HOSTED_SOURCE_TREE")
            self.assertIsNone(receipt["provenance"]["source_tree"])
            self.assertIsNone(manifest["source_tree"])
            self.assertEqual(manifest["execution_error"], "HOSTED_SOURCE_TREE")
            self.assertEqual(manifest["generation"], CURRENT_GENERATION)

    def test_attended_authentication_selects_current_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            class Offline:
                def json(self, *args, **kwargs):
                    raise ContractError("FETCH_FAILED", "Offline fixture")
            bootstrap, _ = generation_paths(CURRENT_GENERATION)
            with self.assertRaises(ContractError) as caught:
                authenticate_generation(ROOT, temporary, client=Offline(), generation=CURRENT_GENERATION,
                                        approved_bootstrap_sha256=digest((ROOT / bootstrap).read_bytes()))
            self.assertEqual(caught.exception.code, "FETCH_FAILED")
            with self.assertRaises(ContractError) as caught:
                authenticate_generation(ROOT, temporary, generation="latest", approved_bootstrap_sha256="0" * 64)
            self.assertEqual(caught.exception.code, "GENERATION_SELECTION")
