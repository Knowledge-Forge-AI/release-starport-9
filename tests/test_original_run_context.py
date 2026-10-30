"""Cross-repository consumer context; API/Git/package fixtures are synthetic."""
import copy
from dataclasses import FrozenInstanceError, asdict, replace
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from rs9.collect_candidate import collect, admit_original_run
from rs9.current_generation import CURRENT_GENERATION, HISTORICAL_GENERATION, DISTRIBUTION_JOBS, distribution_paths
from rs9.errors import ContractError
from rs9.hosted_custody import (OriginalRunContext, provenance, source_identity, consumer_provenance)
from rs9.hosted_summary import required, summarize, validate_summary_binding
from rs9.qualified_distribution_inputs import SourceBoundConfiguration, qualified_distribution_inputs
from rs9.scratch import canonical

ROOT = Path(__file__).resolve().parents[1]
COMMIT, TREE = "1" * 40, "2" * 40
PRODUCER = {"GITHUB_REPOSITORY": "Knowledge-Forge-AI/release-starport-9", "GITHUB_SHA": COMMIT, "GITHUB_RUN_ID": "7",
            "GITHUB_REF": "refs/heads/main", "GITHUB_EVENT_NAME": "push", "GITHUB_RUN_ATTEMPT": "1"}
PACKAGES = {"GITHUB_REPOSITORY": "Knowledge-Forge-AI/theme-forge-packages", "GITHUB_SHA": "f" * 40, "GITHUB_RUN_ID": "999",
            "GITHUB_REF": "refs/tags/packages", "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_RUN_ATTEMPT": "4",
            "GITHUB_WORKFLOW_REF": "Knowledge-Forge-AI/theme-forge-packages/.github/workflows/publish.yml@refs/heads/main"}
STARTED = datetime(2026, 10, 29, tzinfo=timezone.utc)


class OriginalRunContextTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup); self.root = Path(self.temp.name)
        env = patch.dict(os.environ, PRODUCER); env.start(); self.addCleanup(env.stop)
        tree = patch("rs9.hosted_custody.source_tree_identity", return_value=TREE); tree.start(); self.addCleanup(tree.stop)
        self.document = {"id": 7, "head_sha": COMMIT, "event": "push", "head_branch": "main", "path": distribution_paths(CURRENT_GENERATION)[0],
            "run_attempt": 1, "status": "completed", "conclusion": "success", "repository": {"full_name": "Knowledge-Forge-AI/release-starport-9"},
            "created_at": "2026-10-29T00:00:01Z"}
        self.expected = provenance(ROOT, "a" * 64, generation=CURRENT_GENERATION)
        self.run_reads = 0

    def admit(self, document=None):
        return admit_original_run(ROOT, commit=COMMIT, run_id=7, started_at=STARTED, generation=CURRENT_GENERATION,
            runner=lambda root, argv: json.dumps(self.document if document is None else document))[1]

    def test_consumer_uses_original_context_under_packages_or_absent_environment(self):
        context = self.admit()
        for environment in (PACKAGES, {key: value for key, value in os.environ.items() if not key.startswith("GITHUB_")}):
            with self.subTest(environment=environment.get("GITHUB_REPOSITORY")), patch.dict(os.environ, environment, clear="GITHUB_REPOSITORY" not in environment):
                before = dict(os.environ)
                self.assertEqual(consumer_provenance(ROOT, "a" * 64, context, source_commit=COMMIT, run_id=7), self.expected)
                identity = source_identity(ROOT, COMMIT)
                self.assertEqual(identity["source_tree"], TREE)
                self.assertEqual(identity["repository"], PRODUCER["GITHUB_REPOSITORY"])
                self.assertEqual(dict(os.environ), before)
                with self.assertRaises(ContractError) as error:
                    provenance(ROOT, "a" * 64, generation=CURRENT_GENERATION, source_commit=COMMIT, run_id=7)
                self.assertEqual(error.exception.code, "HOSTED_PROVENANCE")

    def test_public_current_summary_validator_always_requires_admitted_context(self):
        from rs9.hosted_contract import validate_hosted_summary
        record = {"schema": "rs9.hosted-candidate-summary.v1alpha2", **self.expected,
                  "production_enabled": False, "publication_authority": False, "adoptable": True}
        for environment in (PACKAGES, PRODUCER):
            with self.subTest(repository=environment["GITHUB_REPOSITORY"]), patch.dict(os.environ, environment):
                with self.assertRaises(ContractError) as error:
                    validate_hosted_summary(record, ROOT, COMMIT, generation=CURRENT_GENERATION, run_id=7)
                self.assertEqual(error.exception.code, "HOSTED_RUN_CONTEXT")

    def test_original_api_wrong_repository_workflow_commit_id_main_event_attempt_refuse(self):
        mutations = [{"repository": {"full_name": PACKAGES["GITHUB_REPOSITORY"]}}, {"path": distribution_paths()[0]},
                     {"head_sha": "3" * 40}, {"id": 8}, {"id": True}, {"head_branch": "topic"},
                     {"event": "workflow_dispatch"}, {"run_attempt": 2}, {"run_attempt": True}]
        with patch.dict(os.environ, PACKAGES):
            for mutation in mutations:
                with self.subTest(mutation=mutation), self.assertRaises(ContractError):
                    self.admit({**self.document, **mutation})

    def test_context_is_frozen_process_local_and_cannot_be_relabelled_or_loaded_from_json(self):
        context = self.admit()
        with self.assertRaises(FrozenInstanceError):
            context.run_id = 8
        for invalid in (asdict(context), replace(context, run_id=8), replace(context), OriginalRunContext(**{key: value for key, value in asdict(context).items() if key != "_proof"})):
            with self.subTest(invalid=type(invalid).__name__), self.assertRaises(ContractError) as error:
                consumer_provenance(ROOT, "a" * 64, invalid, source_commit=COMMIT, run_id=7)
            self.assertEqual(error.exception.code, "HOSTED_RUN_CONTEXT")
        queued = self.admit({**self.document, "status": "in_progress"})
        with self.assertRaises(ContractError):
            consumer_provenance(ROOT, "a" * 64, queued, source_commit=COMMIT, run_id=7)

    def test_source_tree_hashes_and_producer_execution_checks_remain_strict(self):
        context = self.admit()
        record = {"schema": "rs9.hosted-candidate-summary.v1alpha2", **self.expected, "production_enabled": False,
                  "publication_authority": False, "adoptable": True}
        with patch.dict(os.environ, PACKAGES):
            validate_summary_binding(record, ROOT, COMMIT, generation=CURRENT_GENERATION, run_id=7, original_run=context)
            for field in ("source_tree", "workflow_sha256", "contract_sha256", "builder_source_sha256", "configuration_sha256", "run_id"):
                with self.subTest(field=field), self.assertRaises(ContractError):
                    validate_summary_binding({**record, field: "mixed"}, ROOT, COMMIT, generation=CURRENT_GENERATION, run_id=7, original_run=context)
            with patch("rs9.hosted_custody.source_tree_identity", side_effect=ContractError("HOSTED_SOURCE_TREE", "Synthetic dirty source")), self.assertRaises(ContractError):
                consumer_provenance(ROOT, "a" * 64, context, source_commit=COMMIT, run_id=7)
        with patch.dict(os.environ, PRODUCER):
            for overrides in ({"source_commit": "3" * 40}, {"run_id": 8}):
                with self.subTest(overrides=overrides), self.assertRaises(ContractError):
                    provenance(ROOT, "a" * 64, generation=CURRENT_GENERATION, **overrides)
        with patch.dict(os.environ, PACKAGES):
            historical = provenance(ROOT, "a" * 64)
            self.assertEqual(historical["source_commit"], PACKAGES["GITHUB_SHA"])
            self.assertNotIn("repository", historical)
            self.assertNotIn("source_tree", historical)

    def prepare_artifacts(self, *, mixed=False):
        from tests.test_hosted_summary import HostedSummaryTests
        from rs9.hosted_nix import PRODUCTS
        fixture = HostedSummaryTests(); fixture.setUp(); self.addCleanup(fixture.doCleanups)
        lanes = required(ROOT, generation=CURRENT_GENERATION)
        names = {lane["artifact_name"] for lane in lanes}
        for directory in fixture.inputs.iterdir():
            if directory.name not in names:
                shutil.rmtree(directory)
        for lane in lanes:
            directory = fixture.inputs / lane["artifact_name"]
            name = lane["lane"] + "-" + lane["system"] + ".json"
            receipt = json.loads((directory / name).read_bytes()); receipt["provenance"] = self.expected
            if lane["lane"] == "nix":
                receipt["details"] = {"outputs": {product: {} for product in PRODUCTS}}
            (directory / name).write_bytes(canonical(receipt))
            path = directory / "artifact-manifest.json"; manifest = json.loads(path.read_bytes()); manifest.update(self.expected)
            manifest["qualification_receipt_hashes"] = {name: hashlib.sha256(canonical(receipt)).hexdigest()}; path.write_bytes(canonical(manifest))
        jobs = {job: {"result": "success"} for job in DISTRIBUTION_JOBS if job != "summary"}
        # Isolate the environment join from the separately held policy-admission layer.
        with patch.dict(os.environ, {"RS9_JOB_CONCLUSIONS": json.dumps(jobs)}), patch("rs9.hosted_summary.validate_rpm_policy_source"):
            self.assertEqual(summarize(ROOT, fixture.inputs, fixture.output, generation=CURRENT_GENERATION), 0)
        if mixed:
            target = fixture.inputs / "candidate-authenticate-generation/authenticate-generation.json"
            receipt = json.loads(target.read_bytes())
            if mixed == "gate":
                receipt["gates"][0]["status"] = "fail"
            else:
                receipt["provenance"] = {**receipt["provenance"], "run_id": 8}
            target.write_bytes(canonical(receipt))
            path = target.parent / "artifact-manifest.json"; manifest = json.loads(path.read_bytes()); manifest["qualification_receipt_hashes"] = {target.name: hashlib.sha256(canonical(receipt)).hexdigest()}; path.write_bytes(canonical(manifest))
        directories = [(lane["artifact_name"], fixture.inputs / lane["artifact_name"]) for lane in lanes] + [("hosted-summary", fixture.output)]
        self.artifacts, self.zips = [], {}
        for identity, (name, directory) in enumerate(directories, 10):
            data = io.BytesIO()
            with zipfile.ZipFile(data, "w") as zipper:
                for path in sorted(directory.rglob("*")):
                    if path.is_file():
                        zipper.writestr(path.relative_to(directory).as_posix(), path.read_bytes())
            raw = data.getvalue(); self.zips[identity] = raw
            self.artifacts.append({"id": identity, "name": name, "digest": "sha256:" + hashlib.sha256(raw).hexdigest(), "expired": False, "size_in_bytes": len(raw)})
        self.jobs = [{"id": index, "name": name, "status": "completed", "conclusion": "success", "steps": [{"name": "fixture", "conclusion": "success"}]}
                     for index, name in enumerate(sorted({lane["lane"] + "-" + lane["system"] if lane["lane"] in {"nix", "rpm", "deb", "pacman"} else lane["lane"] for lane in lanes} | {"config", "unit", "summary"}), 1)]

    def api(self, root, argv):
        endpoint = argv[-1]
        if endpoint.endswith("/zip"):
            return self.zips[int(endpoint.split("/")[-2])]
        if "/jobs?" in endpoint:
            return json.dumps({"total_count": len(self.jobs), "jobs": self.jobs})
        if "/artifacts?" in endpoint:
            return json.dumps({"total_count": len(self.artifacts), "artifacts": self.artifacts})
        self.run_reads += 1
        return json.dumps(self.document)

    def test_successful_collector_under_actual_packages_environment(self):
        self.prepare_artifacts()
        absent = {key: value for key, value in os.environ.items() if not key.startswith("GITHUB_")}
        for label, environment, clear in (("packages", PACKAGES, False), ("absent", absent, True)):
            output = self.root / ("packet-" + label); output.mkdir()
            with self.subTest(environment=label), patch.dict(os.environ, environment, clear=clear), \
                 patch("rs9.collect_candidate.output_directory", return_value=output), patch("rs9.hosted_summary.validate_rpm_policy_source"):
                before = dict(os.environ)
                packet = collect(ROOT, output, commit=COMMIT, run_id=7, started_at=STARTED, timeout=30, runner=self.api, generation=CURRENT_GENERATION)
                self.assertEqual(dict(os.environ), before)
            self.assertEqual(packet["validation"], {"status": "pass", "reasons": []})
            self.assertEqual(packet["classification"], "qualified-current-distribution-candidate")
            self.assertTrue(packet["diagnostic_scope"]["current_distribution_qualification"])
            self.assertTrue(all(row["integrity"] == "verified" for row in packet["diagnostic_scope"]["required_lanes"]))

    def test_successful_facade_refetches_original_context_under_packages_environment(self):
        self.prepare_artifacts()
        config = SourceBoundConfiguration(ROOT, COMMIT, TREE, 7, STARTED,
            *[self.expected[field] for field in ("workflow_sha256", "contract_sha256", "builder_source_sha256", "configuration_sha256", "release_ingestion_sha256")])
        def fresh_collect(*args, **kwargs):
            return collect(*args, runner=self.api, **kwargs)
        absent = {key: value for key, value in os.environ.items() if not key.startswith("GITHUB_")}
        for label, environment, clear in (("packages", PACKAGES, False), ("absent", absent, True)):
            output = self.root / ("facade-" + label); output.mkdir()
            reads = self.run_reads
            with self.subTest(environment=label), patch.dict(os.environ, environment, clear=clear), \
                 patch("rs9.collect_candidate.output_directory", return_value=output), \
                 patch("rs9.collect_candidate.gh_read", side_effect=lambda root, argv, runner=None: self.api(root, ["gh", *argv])), \
                 patch("rs9.qualified_distribution_inputs.collect", side_effect=fresh_collect), patch("rs9.hosted_summary.validate_rpm_policy_source"), \
                 patch("rs9.qualified_distribution_inputs._binary_inputs", return_value=([], {})):
                before = dict(os.environ)
                result = qualified_distribution_inputs(config, output, timeout=30)
                self.assertEqual(dict(os.environ), before)
            self.assertGreaterEqual(self.run_reads - reads, 2)
            self.assertEqual(result["repository"], PRODUCER["GITHUB_REPOSITORY"])
            self.assertEqual(result["source_commit"], COMMIT)
            self.assertEqual(result["run_id"], 7)
            self.assertEqual(result["event"], "push")
            self.assertEqual(result["ref"], "refs/heads/main")
            self.assertEqual(result["attempt"], 1)
            self.assertIs(result["publication_authority"], False)
            self.assertIs(result["signing_authority"], False)

    def test_mixed_original_receipts_cannot_qualify_under_packages_environment(self):
        for kind in ("run", "gate"):
            self.prepare_artifacts(mixed=kind)
            output = self.root / ("mixed-" + kind); output.mkdir()
            with self.subTest(kind=kind), patch.dict(os.environ, PACKAGES), patch("rs9.collect_candidate.output_directory", return_value=output), patch("rs9.hosted_summary.validate_rpm_policy_source"):
                packet = collect(ROOT, output, commit=COMMIT, run_id=7, started_at=STARTED, timeout=30, runner=self.api, generation=CURRENT_GENERATION)
            self.assertEqual(packet["validation"]["status"], "fail")
            self.assertNotEqual(packet["classification"], "qualified-current-distribution-candidate")
            self.assertTrue(any(row["integrity"] == "fail" for row in packet["diagnostic_scope"]["required_lanes"]))

    def test_facade_refuses_coherent_summary_with_wrong_run_or_tampered_physical_receipt(self):
        for kind in ("run", "gate"):
            self.prepare_artifacts(mixed=kind)
            config = SourceBoundConfiguration(ROOT, COMMIT, TREE, 7, STARTED,
                *[self.expected[field] for field in ("workflow_sha256", "contract_sha256", "builder_source_sha256", "configuration_sha256", "release_ingestion_sha256")])
            output = self.root / ("mixed-facade-" + kind); output.mkdir()
            def fresh_collect(*args, **kwargs):
                return collect(*args, runner=self.api, **kwargs)
            with self.subTest(kind=kind), patch.dict(os.environ, PACKAGES), patch("rs9.collect_candidate.output_directory", return_value=output), \
                 patch("rs9.qualified_distribution_inputs.collect", side_effect=fresh_collect), patch("rs9.hosted_summary.validate_rpm_policy_source"), \
                 patch("rs9.qualified_distribution_inputs.admit_original_run") as final_admission, \
                 patch("rs9.qualified_distribution_inputs._binary_inputs") as binaries, self.assertRaises(ContractError) as error:
                qualified_distribution_inputs(config, output, timeout=30)
            self.assertEqual(error.exception.code, "DISTRIBUTION_NOT_QUALIFIED")
            final_admission.assert_not_called(); binaries.assert_not_called()
