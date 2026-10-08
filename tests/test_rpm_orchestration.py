"""Actual execute -> builder -> inventory -> policy flow with external tool doubles."""
import copy
import json
import os
from contextlib import ExitStack
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from rs9 import build_rpm, hosted_packaging, rpm_lint_policy
from rs9.errors import ContractError
from tests.rpm_fixtures import fixture_policy
from tests.test_build_native import create_cli_fixture
from tests import test_build_rpm as build_helpers
from tests.test_rpm_client_runtime import ClientHost, ENVIRONMENT

ROOT = Path(__file__).resolve().parents[1]


class RpmOrchestrationTests(unittest.TestCase):
    def lane(self, root, *, probe_failure=None, version="22.23.0", boundary=None, hosted=False):
        capture, intent, npm = create_cli_fixture(root / "input")
        runner = build_helpers.BuildRpmTests()._setup_runner()
        original_run = runner.run
        events = []
        # The double represents an executed external command for source orchestration;
        # no Docker, RPM, DNF or signing qualification is claimed.
        def run(command, **kwargs):
            events.append(command)
            receipt = original_run(command, **kwargs)
            receipt.executed = True
            return receipt
        runner.run = run
        warm = root / "fixture-preparation"; warm.mkdir()
        with patch("rs9.rpm_lint_policy.load_policy", side_effect=lambda *args: fixture_policy(root)):
            build_rpm.build_rpm_candidate(capture, intent, "noarch", warm, offline_npm_archives=npm, runner=runner)
        policy = fixture_policy(root)
        events.clear()
        host = ClientHost(failure=probe_failure, version=version)
        host_run = host.run
        def outer(command, **kwargs):
            events.append(command)
            return host_run(command, **kwargs)
        host.run = outer
        host.which = lambda tool: tool
        outer_scratch = root / "lane"; outer_scratch.mkdir()
        scratch = outer_scratch / "lane-work" if hosted else outer_scratch
        context = {"family": "rpm", "system": "x86_64-linux", "repository": root,
                   "scratch": scratch, "pins": {}, "client": None, "runner": host,
                   "captures": [(capture, intent, {})], "binding": {"source_commit": "0" * 40},
                   "authentication_sha256": "1" * 64}
        observed = []
        evaluate = build_rpm.evaluate_policy
        def evaluation(**kwargs):
            observed.append(copy.deepcopy(kwargs))
            events.append(["policy-evaluation"])
            return evaluate(**kwargs)
        def tool(self, command, **kwargs):
            return runner.run(command, **kwargs)
        with patch.object(hosted_packaging, "provision", return_value=copy.deepcopy(ENVIRONMENT)), \
             patch.object(hosted_packaging, "container_tool_facts", return_value={}), \
             patch.object(hosted_packaging, "_resolve_offline_npm_archives", return_value=npm), \
             patch("rs9.hosted_deb.ContainerRunner.which", side_effect=runner.which), \
             patch("rs9.hosted_deb.ContainerRunner.run", tool), \
             patch("rs9.rpm_lint_policy.load_policy", return_value=policy), \
             patch.object(build_rpm, "evaluate_policy", side_effect=evaluation), \
             patch.object(build_rpm, "create_derivation_record", wraps=build_rpm.create_derivation_record) as derive:
            if boundary == "derivation":
                derive.side_effect = ContractError("INVALID_STRING", "Controlled typed boundary")
            with ExitStack() as stack:
                if boundary == "manifest":
                    write = Path.write_bytes
                    def manifest_write(path, data):
                        if path == scratch / "build" / intent["project"]["id"] / "rpm-manifest.json":
                            raise OSError("Controlled manifest boundary")
                        return write(path, data)
                    stack.enter_context(patch.object(Path, "write_bytes", manifest_write))
                if boundary == "custody":
                    stack.enter_context(patch("rs9.rpm_evidence.write_policy_evidence",
                                              side_effect=ContractError("RECORD_LIMIT", "Controlled custody boundary")))
                if hosted:
                    from rs9 import hosted_pipeline
                    from rs9.hosted_custody import verify_set
                    from rs9.scratch import canonical
                    upstream = root / "upstream"; upstream.mkdir()
                    (upstream / "artifact-manifest.json").write_bytes(canonical({"release_ingestion_sha256": "1" * 64}))
                    packet = root / "packet"; packet.mkdir()
                    retained = packet / "candidate-rpm-x86_64-linux"
                    def authenticated_inputs(repository, output, **kwargs):
                        (output / "summary").mkdir()
                        (output / "summary/authentication.json").write_bytes(b"{}")
                        return context["captures"]
                    def command_bindings(captures, repository, output):
                        path = output / "command-bindings.json"
                        path.write_bytes(b"{}")
                        return path
                    # Double external authentication, host inspection and tools;
                    # execute, builder, evaluator, pipeline and retain stay real.
                    stack.enter_context(patch.object(hosted_pipeline, "capture_generation", side_effect=authenticated_inputs))
                    stack.enter_context(patch.object(hosted_pipeline, "validate_host"))
                    stack.enter_context(patch.object(hosted_pipeline, "runner_facts", return_value={}))
                    stack.enter_context(patch.object(hosted_pipeline, "_inputs", return_value={("authenticate", "generation"): upstream}))
                    stack.enter_context(patch.object(hosted_pipeline, "canonical_release_auth_projection", return_value={}))
                    stack.enter_context(patch.object(hosted_pipeline, "compute_auth_sha256", return_value="1" * 64))
                    stack.enter_context(patch.object(hosted_pipeline, "bind_commands", side_effect=command_bindings))
                    stack.enter_context(patch.object(hosted_packaging, "SubprocessRunner", return_value=host))
                    code = hosted_pipeline.run_lane(ROOT, outer_scratch, retained, "rpm", "x86_64-linux",
                                                   client=SimpleNamespace(receipts=[]), inputs=upstream)
                    self.assertEqual(code, 2)  # One-product fixture cannot qualify a four-product lane.
                    artifact_manifest = verify_set(retained)
                    record = json.loads((retained / "rpm-x86_64-linux.json").read_bytes())
                    result = {"gates": record["gates"], "details": record["details"],
                              "artifacts": [retained / row["path"] for row in artifact_manifest["files"]],
                              "retained": retained, "receipt": record, "artifact_manifest": artifact_manifest,
                              "captures": context["captures"], "fixture_policy": policy}
                else:
                    result = hosted_packaging.execute(context)
        return result, events, observed, intent["project"]["id"]

    def test_hosted_pipeline_exports_package_after_actual_manifest_boundary(self):
        with tempfile.TemporaryDirectory() as tmp:
            result, _, _, product = self.lane(Path(tmp).resolve(), boundary="manifest", hosted=True)
            failure = result["details"]["product_failures"][product]
            witness = result["details"]["construction_witnesses"][product]
            row = next(row for row in result["artifact_manifest"]["files"] if '/quarantine/' in row['path'])
            self.assertEqual(row['sha256'], witness['package_sha256'])
            self.assertEqual(row['size'], witness['package_size'])
            self.assertEqual(failure['diagnostics']['construction'], 'verified-retained')
            self.assertEqual(failure['code'], 'RPM_MANIFEST_RECORD')
            gate = next(g for g in result['gates'] if g['name'] == 'rpm-derivation-record')
            self.assertNotIn(product, gate['products'])

    def test_execute_builder_pipeline_custody_reaches_all_four_consumers(self):
        from rs9.hosted_summary import validate_rpm_policy_custody, summarize
        from rs9.collect_candidate import diagnostic_scope
        from rs9.hosted_foundation3 import execute as foundation3
        from rs9.hosted_deb import execute_pages
        from rs9.rpm_evidence import verify_rpm_custody
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {
                "GITHUB_SHA": "0" * 40, "GITHUB_REF": "refs/heads/main", "GITHUB_EVENT_NAME": "push",
                "GITHUB_RUN_ATTEMPT": "1"}):
            root = Path(tmp).resolve()
            result, _, observed, product = self.lane(root, hosted=True)
            directory, manifest, record = result['retained'], result['artifact_manifest'], result['receipt']
            self.assertTrue(result['details']['rpm_lint_policy'][product]['accepted'])
            self.assertTrue(observed)
            self.assertIn(product, verify_rpm_custody(directory, manifest, record))
            validate_rpm_policy_custody(directory, manifest, record)
            lane = {'lane': 'rpm', 'system': 'x86_64-linux', 'module': 'rs9.hosted_packaging',
                    'artifact_name': directory.name, 'required_gates': ['rpm-lint-policy-accepted']}
            packet = {'source_commit': '0' * 40, 'artifacts': [{'name': directory.name, 'collection': 'verified'}],
                      'jobs': [{'name': 'rpm-x86_64-linux', 'status': 'completed', 'conclusion': 'failure', 'steps': []}]}
            with patch('rs9.rpm_lint_policy.load_policy', return_value=result['fixture_policy']):
                scope = diagnostic_scope(ROOT, directory.parent, packet, {'lanes': [lane]})
                self.assertFalse(any('rpm-policy-custody-invalid' in reason for reason in scope['required_lanes'][0]['reasons']))
                summary_dir = root / 'summary'
                self.assertEqual(summarize(ROOT, directory.parent, summary_dir), 2)
                summary = json.loads((summary_dir / 'hosted-summary.json').read_bytes())
                self.assertFalse(any('RPM_RAW_' in reason or 'RPM_POLICY_CUSTODY' in reason for reason in summary['blocking_reasons']))
            f3_scratch = root / 'foundation3'; f3_scratch.mkdir()
            f3 = foundation3({'inputs': directory.parent, 'scratch': f3_scratch, 'captures': result['captures']})
            self.assertNotIn('custody_error', f3['details'])
            pages_scratch = root / 'pages'; pages_scratch.mkdir()
            pages = execute_pages({'repository': ROOT, 'inputs': directory.parent, 'scratch': pages_scratch,
                                   'system': 'generation', 'family': 'pages', 'authentication_sha256': '1' * 64,
                                   'captures': result['captures']})
            self.assertNotIn('custody_error', pages['details'])

    def test_preparation_and_probe_reach_real_policy_while_acceptance_pending(self):
        with tempfile.TemporaryDirectory() as tmp:
            result, events, observed, product = self.lane(Path(tmp).resolve())
        probe = next(i for i,c in enumerate(events) if "-qf" in c)
        build = next(i for i,c in enumerate(events) if c[0] == "rpmbuild")
        evaluation = next(i for i,c in enumerate(events) if c[0] == "policy-evaluation")
        self.assertLess(probe, build)
        self.assertLess(build, evaluation)
        self.assertFalse(any(c[0] in {"rpmsign", "dnf"} for c in events))
        self.assertEqual(len(observed), 1)
        evidence = observed[0]["inventory"]["client_runtime_evidence"]
        self.assertEqual(evidence["status"], "pass")
        self.assertEqual(evidence["rpm_query"]["identity"]["name"], "nodejs22")
        self.assertEqual(result["details"]["client_runtime_evidence"], evidence)
        self.assertTrue(result["details"]["rpm_lint_policy"][product]["accepted"])

    def test_unexecuted_probe_is_transported_without_builder_node_substitution(self):
        with tempfile.TemporaryDirectory() as tmp:
            result, _, observed, _ = self.lane(Path(tmp).resolve(), probe_failure="unexecuted")
        self.assertEqual(observed[0]["inventory"]["client_runtime_evidence"]["status"], "fail")
        gate = next(g for g in result["gates"] if g["name"] == "rpm-client-preparation")
        self.assertEqual(gate["status"], "fail")

    def test_actual_caller_engine_floor_blocks_old_client_before_policy(self):
        with tempfile.TemporaryDirectory() as tmp:
            result, events, observed, _ = self.lane(Path(tmp).resolve(), version="20.0.0")
        evidence=observed[0]["inventory"]["client_runtime_evidence"]
        self.assertEqual(evidence["status"],"fail")
        self.assertEqual(evidence["reason"],"NODE_RUNTIME_FLOOR_UNMET")
        self.assertEqual(evidence["engine_constraints"][0]["floor"],">=22")
        self.assertFalse(any(c[0] in {"rpmsign","dnf"} for c in events))

    def test_actual_derivation_failure_retains_verified_construction_and_cause(self):
        with tempfile.TemporaryDirectory() as tmp:
            result, _, _, product = self.lane(Path(tmp).resolve(), boundary="derivation")
            failure = result["details"]["product_failures"][product]
            self.assertEqual(failure["code"], "RPM_DERIVATION_RECORD")
            self.assertEqual(failure["substage"], "rpm-derivation-record")
            self.assertIn(product, result["details"]["construction_witnesses"])
            self.assertEqual(failure["diagnostics"]["construction"], "verified-retained")
            self.assertTrue((Path(tmp) / "lane/quarantine").is_dir())
            self.assertFalse((Path(tmp) / "lane/unsigned-custody").exists())
            gates = {g["name"]:g for g in result["gates"]}
            self.assertEqual(gates["rpm-derivation-record"]["status"], "fail")
            self.assertEqual(gates["rpm-client-qualification"]["status"], "not-run")

    def test_actual_manifest_and_custody_failures_retain_verified_construction(self):
        for boundary, code, gate in (("manifest", "RPM_MANIFEST_RECORD", "rpm-manifest-record"),
                                     ("custody", "RPM_POLICY_CUSTODY", "rpm-policy-custody")):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as tmp:
                result, _, _, product = self.lane(Path(tmp).resolve(), boundary=boundary)
                failure = result["details"]["product_failures"][product]
                self.assertEqual(failure["code"], code)
                self.assertEqual(failure["diagnostics"]["construction"], "verified-retained")
                self.assertIn(product, result["details"]["construction_witnesses"])
                retained = next((Path(tmp).resolve() / "lane/quarantine").glob("*.rpm"))
                self.assertIn(retained, result["artifacts"])
                gates = {g["name"]:g for g in result["gates"]}
                self.assertEqual(gates[gate]["status"], "fail")
                if boundary == "manifest":
                    self.assertNotIn(product, gates["rpm-derivation-record"]["products"])
                self.assertEqual(gates["rpm-repository-indexing"]["status"], "not-run")
