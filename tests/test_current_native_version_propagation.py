"""Real byte/configuration validation with synthetic archives; no native commands."""
import hashlib
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from rs9.bootstrap import load_bootstrap
from rs9.candidate import configuration_rows
from rs9.current_generation import CURRENT_GENERATION, HISTORICAL_GENERATION, bind_native_build_generation, generation_paths
from rs9.build_native import validate_build_inputs, MockCommandRunner, NativePrerequisiteUnavailable
from rs9.build_deb import build_deb_candidate
from rs9.build_pacman import build_pacman_candidate
from rs9.build_rpm import build_rpm_candidate
from rs9.errors import ContractError
from rs9.profiles import selection_for_intent
from rs9.release_core import authenticate_release, digest
from rs9.rpm_client_runtime import bind_engine_floors, prepare_client
from rs9.scratch import canonical
from tests.shadow_fixtures import tar_bytes
from tests.test_rpm_client_runtime import ClientHost, ENVIRONMENT

ROOT = Path(__file__).resolve().parents[1]


def current_cli(root, product="theme-forge-stellar-loom"):
    """Use exact source-owned current intent and identities with labelled synthetic payloads.

    Core/configuration authority is real; this fixture does not claim profile acceptance.
    """
    row, intent = next((row, intent) for row, intent in configuration_rows(ROOT, generation=CURRENT_GENERATION)
                       if intent["project"]["id"] == product)
    selection = selection_for_intent(intent)
    root.mkdir(parents=True)
    for family in ("api", "assets", "source"):
        (root / family).mkdir()
    bins = {name: path.removeprefix("package/") for name, path in intent["assets"][0]["commands"].items()}
    package = {"name": "@knowledge-forge-ai/" + product, "version": row["version"], "license": "AGPL-3.0-or-later",
               "bin": bins, "engines": {"node": ">=22"}}
    source = {path: b"Synthetic tagged legal text\n" for path in selection["source_paths"]}
    source["package.json"] = canonical(package)
    if "package-lock.json" in source:
        source["package-lock.json"] = canonical({"lockfileVersion": 3, "packages": {}})
    entries = [("package/" + name, data, 0o644, tarfile.REGTYPE, "") for name, data in source.items() if "/" not in name]
    entries.extend((path, b"#!/usr/bin/env node\n", 0o755, tarfile.REGTYPE, "") for path in intent["assets"][0]["commands"].values())
    assets = {intent["assets"][0]["name"]: tar_bytes(entries)}
    for selected in selection["evidence_assets"]:
        assets[selected["name"]] = canonical({"synthetic": True})
    assets[selection["checksums"]] = "".join(digest(data) + "  " + name + "\n" for name, data in sorted(assets.items())).encode()
    for name, data in assets.items():
        (root / "assets" / name).write_bytes(data)
    for name, data in source.items():
        path = root / "source" / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(data)
    docs = {"tags": [], "repository": {"id": row["repository_id"], "full_name": row["repository"]},
            "ref": {"ref": "refs/tags/" + row["tag"], "object": {"type": "commit", "sha": row["tag_commit"]}},
            "commit": {"sha": row["tag_commit"], "tree": {"sha": row["tag_tree"]}},
            "tree": {"sha": row["tag_tree"], "truncated": False, "tree": [
                {"path": name, "sha": hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest(),
                 "type": "blob", "mode": "100644"} for name, data in source.items()]},
            "release": {"id": row["release_id"], "tag_name": row["tag"], "target_commitish": row["tag_commit"],
                "published_at": "2026-10-29T00:00:00Z", "draft": False, "prerelease": False, "assets": [
                    {"id": index + 1, "name": name, "size": len(data), "digest": "sha256:" + digest(data), "state": "uploaded"}
                    for index, (name, data) in enumerate(assets.items())]}}
    for name, document in docs.items():
        (root / "api" / (name + ".json")).write_bytes(canonical(document))
    capture = authenticate_release(selection, root)
    manifest = ROOT / generation_paths(CURRENT_GENERATION)[0]
    loaded = load_bootstrap(manifest, capture, approved_manifests=[digest(manifest.read_bytes())])
    assert loaded == intent
    return capture, intent


class CurrentNativeVersionPropagationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup); self.root = Path(self.temp.name)

    def test_real_current_validation_for_cli_adapters(self):
        for product in ("theme-forge-stellar-loom", "theme-forge-solar-sail"):
            capture, intent = current_cli(self.root / product, product)
            for adapter, arch in (("debian", "all"), ("rpm", "noarch"), ("pacman", "any")):
                with self.subTest(product=product, adapter=adapter):
                    inputs = validate_build_inputs(capture, intent, arch, adapter=adapter, generation=CURRENT_GENERATION)
                    self.assertEqual(inputs["version"], intent["version"])
                    self.assertEqual(inputs["asset_sha"], digest(inputs["asset_bytes"]))
                    with self.assertRaises(ContractError) as error:
                        validate_build_inputs(capture, intent, arch, adapter=adapter)
                    self.assertEqual(error.exception.code, "UNSUPPORTED_VERSION")

    def test_real_builder_entrypoints_reach_prerequisites_after_current_validation(self):
        capture, intent = current_cli(self.root / "capture")
        for name, build, arch, extra in (("deb", build_deb_candidate, "all", {"maintainer": "Fixture <fixture@example.test>"}),
                ("pacman", build_pacman_candidate, "any", {}), ("rpm", build_rpm_candidate, "noarch", {})):
            scratch = self.root / name; scratch.mkdir()
            with self.subTest(builder=name), self.assertRaises(NativePrerequisiteUnavailable):
                build(capture, intent, arch, scratch, runner=MockCommandRunner(), generation=CURRENT_GENERATION, **extra)
            with self.subTest(builder=name), self.assertRaises(ContractError) as error:
                build(capture, intent, arch, scratch, runner=MockCommandRunner(), **extra)
            self.assertEqual(error.exception.code, "UNSUPPORTED_VERSION")

    def test_current_rpm_reaches_raw_lint_without_policy_acceptance(self):
        from tests.test_build_rpm import BuildRpmTests
        capture, intent = current_cli(self.root / "capture")
        fixture = BuildRpmTests(); fixture.root = self.root
        runner = fixture._setup_runner(version=intent["version"])
        scratch = self.root / "rpm"; scratch.mkdir()
        try:
            result = build_rpm_candidate(capture, intent, "noarch", scratch, runner=runner, generation=CURRENT_GENERATION)
        except ContractError as error:
            self.assertTrue(any("rpmlint" in str(call["argv"][0]) for call in runner.calls), error)
            self.assertIsNotNone(getattr(error, "rpmlint_evidence", None), error)
            self.assertFalse(error.rpmlint_policy["accepted"])
        else:
            self.fail("Blocked current RPM policy unexpectedly returned a successful build")
        self.assertTrue(any("rpmbuild" in str(call["argv"][0]) for call in runner.calls))

    def test_current_loader_failure_keeps_raw_lint_and_does_not_fallback(self):
        from tests.test_build_rpm import BuildRpmTests
        capture, intent = current_cli(self.root / "capture")
        fixture = BuildRpmTests(); fixture.root = self.root
        runner = fixture._setup_runner(version=intent["version"])
        scratch = self.root / "rpm"; scratch.mkdir()
        with patch("rs9.rpm_lint_policy.load_policy", side_effect=ContractError("INVALID_POLICY", "Synthetic missing current policy")) as loader:
            with self.assertRaises(ContractError) as caught:
                build_rpm_candidate(capture, intent, "noarch", scratch, runner=runner, generation=CURRENT_GENERATION)
        loader.assert_called_once_with(generation=CURRENT_GENERATION)
        self.assertEqual(caught.exception.code, "RPMLINT_FAILED")
        self.assertFalse(caught.exception.rpmlint_policy["accepted"])
        self.assertIsNotNone(caught.exception.rpmlint_evidence)
        self.assertTrue(any("rpmlint" in str(call["argv"][0]) for call in runner.calls))

    def test_hosted_deb_build_products_forwards_to_real_current_validator(self):
        from rs9.hosted_deb import _build_products
        capture, intent = current_cli(self.root / "capture")
        work = self.root / "work"; work.mkdir()
        products, errors = _build_products([(capture, intent, {})], "amd64", work, MockCommandRunner(),
            "Fixture <fixture@example.test>", None, None, [intent["project"]["id"]], generation=CURRENT_GENERATION)
        self.assertFalse(products)
        self.assertEqual(errors, {intent["project"]["id"]: "tool-unavailable:dpkg-deb"})

    def test_unknown_generation_refuses_before_io_for_every_entrypoint(self):
        for function, args, kwargs in ((validate_build_inputs, (None, {}, "all"), {"adapter": "debian"}),
                (build_deb_candidate, (None, {}, "all", self.root / "absent"), {}),
                (build_pacman_candidate, (None, {}, "any", self.root / "absent"), {}),
                (build_rpm_candidate, (None, {}, "noarch", self.root / "absent"), {}),
                (bind_engine_floors, ({"status": "fail"}, []), {})):
            with self.subTest(function=function.__name__), self.assertRaises(ContractError) as error:
                function(*args, generation="unknown", **kwargs)
            self.assertEqual(error.exception.code, "GENERATION_SELECTION")
        self.assertFalse((self.root / "absent").exists())

    def test_current_binding_refuses_wrong_intent_capture_source_or_json(self):
        capture, intent = current_cli(self.root / "capture")
        for field, value in (("version", "0.4.0"), ("version", "99.0.0"), ("tag", "v99.0.0")):
            changed = {**intent, field: value}
            with self.subTest(field=field, value=value), self.assertRaises(ContractError):
                validate_build_inputs(capture, changed, "all", adapter="debian", generation=CURRENT_GENERATION)
        with self.assertRaises(ContractError):
            bind_native_build_generation(json.loads(json.dumps(capture.record)), intent, generation=CURRENT_GENERATION)
        original = capture.source["package.json"]
        capture.source["package.json"] += b" "
        with self.assertRaises(ContractError) as error:
            validate_build_inputs(capture, intent, "all", adapter="debian", generation=CURRENT_GENERATION)
        self.assertEqual(error.exception.code, "INPUT_CHANGED")
        capture.source["package.json"] = original
        other, other_intent = current_cli(self.root / "other", "theme-forge-solar-sail")
        with self.assertRaises(ContractError):
            bind_native_build_generation(other, intent, generation=CURRENT_GENERATION)

    def runtime(self):
        with patch("rs9.hosted_deb.provision_image"):
            return prepare_client(ClientHost(), ENVIRONMENT, arch="x86_64", system="x86_64-linux", tag="fixture-client")

    def test_current_engine_binding_uses_authenticated_source_and_rejects_changed_source(self):
        capture, intent = current_cli(self.root / "capture")
        result = bind_engine_floors(self.runtime(), [(capture, intent, {})], generation=CURRENT_GENERATION)
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["engine_constraints"], [{"product": intent["project"]["id"], "source_sha256": digest(capture.source["package.json"]), "floor": ">=22"}])
        capture.source["package.json"] += b" "
        result = bind_engine_floors(self.runtime(), [(capture, intent, {})], generation=CURRENT_GENERATION)
        self.assertEqual(result["reason"], "NODE_ENGINE_SOURCE_UNPROVEN")

    def test_source_owned_current_binding_rejects_historical_capture_even_with_selector(self):
        from tests.test_build_native import create_cli_fixture
        capture, intent, _ = create_cli_fixture(self.root / "historical")
        with self.assertRaises(ContractError) as error:
            validate_build_inputs(capture, intent, "all", adapter="debian", generation=CURRENT_GENERATION)
        self.assertEqual(error.exception.code, "NATIVE_GENERATION_BINDING")
        result = bind_engine_floors(self.runtime(), [(capture, intent, {})], generation=CURRENT_GENERATION)
        self.assertEqual(result["reason"], "NODE_ENGINE_SOURCE_UNPROVEN")
