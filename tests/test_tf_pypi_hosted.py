"""Native qualification routing, same-artifact receipt and workflow safety regressions."""
import copy
import errno
import json
from pathlib import Path
from subprocess import CompletedProcess
import tempfile
import unittest
from unittest.mock import patch
import yaml

from rs9.tf_pypi_archive import AdmissionError, canonical
from rs9 import tf_pypi_consumer as c
from rs9 import tf_pypi_hosted as h
from rs9.tf_pypi_model import PRODUCTS, TARGETS, load_pin, strict_json
from rs9.tf_pypi_publish import workflow_text
from rs9.tf_pypi_verify import verify_pair
from tests.tf_pypi_fixtures import ROOT, aggregate, fixture

COMMIT = "a" * 40
RUN_ID = "98765"
PROJECT = "theme-forge-stellar-loom"


class NativeContract(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.pin, self.data = fixture(PROJECT)
        self.dist = self.root / "dist"
        self.aggregate = aggregate(self.pin, self.data, self.dist)

    def _consumer_receipt(self, target, pair_sha, **overrides):
        base = {
            "project": PROJECT,
            "target": target,
            "system": h.TARGET_SYSTEMS[target],
            "set_sha256": pair_sha,
            "functional": True,
            "offline_isolation": {"network_disabled": True},
            "publication_admitted": False,
            "lifecycle": [
                {"kind": k, "install_exit": 0, "probes": [{"command": "tfsl"}]}
                for k in ("wheel", "sdist")
            ],
        }
        base.update(overrides)
        return base

    def attempt(self, target="darwin-arm64", *, consumer_overrides=None, mutate_after=False, run_id=RUN_ID, run_attempt="1"):
        work = self.root / f"work-{target}-{run_id}-{run_attempt}"
        observed = []

        def fake_smoke(pin, view_dir, consumer_dir, *, offline_linux=False, functional=True):
            pair = verify_pair(pin, view_dir, target=target)
            observed.append((pair, Path(view_dir), Path(consumer_dir), offline_linux, functional))
            if mutate_after:
                (self.dist / "extra.txt").write_bytes(b"tampered")
            return self._consumer_receipt(target, pair["set_sha256"], **(consumer_overrides or {}))

        with patch.object(h, "load_pin", return_value=self.pin), \
                patch.object(h, "host_key", return_value=target), \
                patch.object(h, "source_commit", return_value=COMMIT), \
                patch.object(h, "smoke", side_effect=fake_smoke):
            result = h.qualify(
                PROJECT, self.dist, work, COMMIT,
                target=target, run_id=run_id, run_attempt=run_attempt,
            )
        self.assertEqual(len(observed), 1)
        pair, view_dir, consumer_dir, offline_linux, functional = observed[0]
        self.assertEqual(view_dir, work / "view")
        self.assertEqual(consumer_dir, work / "consumer")
        self.assertEqual(offline_linux, target.startswith("linux"))
        self.assertTrue(functional)
        self.assertEqual(len(pair["files"]), 2)
        return result

    def test_exact_native_receipts_for_all_three_targets_do_not_admit_publication(self):
        for target in TARGETS:
            result = self.attempt(target=target)
            self.assertEqual(result["schema"], "rs9.tf-pypi-hosted-consumer.v2")
            self.assertEqual(result["status"], "native-consumer-passed")
            self.assertEqual(result["project"], PROJECT)
            self.assertEqual(result["version"], self.pin["distribution_version"])
            self.assertEqual(result["upstream_version"], self.pin["version"])
            self.assertEqual(result["target"], target)
            self.assertEqual(result["commit"], COMMIT)
            self.assertEqual(result["run_id"], RUN_ID)
            self.assertEqual(result["run_attempt"], "1")
            self.assertEqual(result["aggregate_set_sha256"], self.aggregate["set_sha256"])
            self.assertEqual(result["wheel"]["target"], target)
            self.assertIsNone(result["sdist"]["target"])
            self.assertFalse(result["publication_admitted"])

    def test_wrong_host_or_unsupported_target_stops_before_commit_or_consumer(self):
        for host, target in (
            ("linux-x64-gnu", "darwin-arm64"),
            ("darwin-arm64", "linux-arm64-gnu"),
            ("darwin-x64", "darwin-x64"),
        ):
            with self.subTest(host=host, target=target), \
                    patch.object(h, "load_pin", return_value=self.pin), \
                    patch.object(h, "host_key", return_value=host), \
                    patch.object(h, "source_commit") as commit_call, \
                    patch.object(h, "smoke") as smoke_call, \
                    self.assertRaises(AdmissionError) as caught:
                h.qualify(PROJECT, self.dist, self.root / "unused", COMMIT, target=target)
            self.assertEqual(caught.exception.code, "TF_PYPI_HOSTED_NATIVE_TARGET")
            commit_call.assert_not_called()
            smoke_call.assert_not_called()

    def test_source_mismatch_and_invalid_run_identity_stop_before_consumer(self):
        with patch.object(h, "load_pin", return_value=self.pin), \
                patch.object(h, "host_key", return_value="darwin-arm64"), \
                patch.object(h, "source_commit", side_effect=AdmissionError("TF_PYPI_HOSTED_COMMIT")), \
                patch.object(h, "smoke") as call, \
                self.assertRaises(AdmissionError):
            h.qualify(PROJECT, self.dist, self.root / "w1", COMMIT)
        call.assert_not_called()

        for bad_run in ("0", "-1", "abc", ""):
            with self.subTest(bad_run=bad_run), \
                    patch.object(h, "load_pin", return_value=self.pin), \
                    patch.object(h, "host_key", return_value="darwin-arm64"), \
                    patch.object(h, "source_commit", return_value=COMMIT), \
                    patch.object(h, "smoke") as call, \
                    self.assertRaises(AdmissionError) as caught:
                h.qualify(PROJECT, self.dist, self.root / f"w-{bad_run}", COMMIT, run_id=bad_run)
            self.assertEqual(caught.exception.code, "TF_PYPI_HOSTED_RUN_IDENTITY")
            call.assert_not_called()

    def test_artifact_mutation_and_consumer_field_negatives_refused(self):
        with self.assertRaises(AdmissionError) as caught:
            self.attempt(mutate_after=True)
        self.assertEqual(caught.exception.code, "TF_PYPI_ FILE_SET".replace(" ", ""))
        (self.dist / "extra.txt").unlink()

        for key, value in (
            ("project", "wrong"),
            ("target", "linux-x64-gnu"),
            ("system", "x86_64-linux"),
            ("set_sha256", "c" * 64),
            ("functional", False),
            ("offline_isolation", {}),
            ("publication_admitted", True),
        ):
            with self.subTest(key=key), self.assertRaises(AdmissionError):
                self.attempt(consumer_overrides={key: value})

        for life in (
            [{"kind": "wheel", "install_exit": 0, "probes": [{"command": "tfsl"}]}],
            [{"kind": k, "install_exit": 1, "probes": [{"command": "tfsl"}]} for k in ("wheel", "sdist")],
            [{"kind": k, "install_exit": 0, "probes": []} for k in ("wheel", "sdist")],
        ):
            with self.subTest(life=life), self.assertRaises(AdmissionError):
                self.attempt(consumer_overrides={"lifecycle": life})

    def test_admit_matrix_requires_exact_three_first_attempt_same_run_receipts(self):
        receipts_dir = self.root / "receipts"
        for target in TARGETS:
            rec = self.attempt(target=target)
            target_dir = receipts_dir / target
            target_dir.mkdir(parents=True, exist_ok=True)
            (target_dir / "result.json").write_bytes(canonical(rec))

        with patch.object(h, "source_commit", return_value=COMMIT):
            matrix = h.admit_matrix(self.pin, self.dist, receipts_dir, COMMIT, RUN_ID, "1")
        self.assertEqual(matrix["schema"], "rs9.tf-pypi-hosted-matrix.v1")
        self.assertEqual(matrix["status"], "native-matrix-passed")
        self.assertEqual(matrix["targets"], list(TARGETS))
        self.assertFalse(matrix["publication_admitted"])

        # Rerun / attempt 2 is forbidden.
        with patch.object(h, "source_commit", return_value=COMMIT), \
                self.assertRaises(AdmissionError) as caught:
            h.admit_matrix(self.pin, self.dist, receipts_dir, COMMIT, RUN_ID, "2")
        self.assertEqual(caught.exception.code, "TF_PYPI_HOSTED_RUN_ATTEMPT")

        # Tampering any receipt field or inner consumer field fails with HOSTED_MATRIX_RECEIPT.
        darwin_file = receipts_dir / "darwin-arm64/result.json"
        original = strict_json(darwin_file.read_bytes())
        mutations = [
            {**original, "run_id": "11111"},
            {**original, "run_attempt": "2"},
            {**original, "commit": "b" * 40},
            {**original, "target": "linux-x64-gnu"},
            {**original, "aggregate_set_sha256": "0" * 64},
            {**original, "set_sha256": "0" * 64, "consumer": {**original["consumer"], "set_sha256": "0" * 64}},
            {**original, "artifacts": [original["artifacts"][0]]},
            {**original, "wheel": {**original["wheel"], "size": original["wheel"]["size"] + 1}},
            {**original, "sdist": {**original["sdist"], "size": original["sdist"]["size"] + 1}},
            {**original, "network_mechanism": "none"},
            {**original, "qualification_scope": "wrong"},
            {**original, "publication_admitted": True},
            {**original, "consumer": {**original["consumer"], "system": "x86_64-linux"}},
            {**original, "consumer": {**original["consumer"], "functional": False}},
            {**original, "consumer": {**original["consumer"], "offline_isolation": {"network_disabled": False}}},
            {**original, "consumer": {**original["consumer"], "lifecycle": [original["consumer"]["lifecycle"][0]]}},
        ]
        for idx, mutated in enumerate(mutations):
            darwin_file.write_bytes(canonical(mutated))
            with self.subTest(idx=idx), patch.object(h, "source_commit", return_value=COMMIT), \
                    self.assertRaises(AdmissionError) as caught:
                h.admit_matrix(self.pin, self.dist, receipts_dir, COMMIT, RUN_ID, "1")
            self.assertEqual(caught.exception.code, "TF_PYPI_HOSTED_MATRIX_RECEIPT")
        darwin_file.write_bytes(canonical(original))

        # Extra file or missing target directory fails with HOSTED_MATRIX_RECEIPTS.
        extra = receipts_dir / "darwin-arm64/extra.json"
        extra.write_bytes(b"{}")
        with patch.object(h, "source_commit", return_value=COMMIT), \
                self.assertRaises(AdmissionError) as caught:
            h.admit_matrix(self.pin, self.dist, receipts_dir, COMMIT, RUN_ID, "1")
        self.assertEqual(caught.exception.code, "TF_PYPI_HOSTED_MATRIX_RECEIPTS")
        extra.unlink()

        (receipts_dir / "linux-x64-gnu/result.json").unlink()
        (receipts_dir / "linux-x64-gnu").rmdir()
        with patch.object(h, "source_commit", return_value=COMMIT), \
                self.assertRaises(AdmissionError) as caught:
            h.admit_matrix(self.pin, self.dist, receipts_dir, COMMIT, RUN_ID, "1")
        self.assertEqual(caught.exception.code, "TF_PYPI_HOSTED_MATRIX_RECEIPTS")

    def test_admit_matrix_refuses_incomplete_and_stale_receipts(self):
        receipts_dir = self.root / "receipts-full"
        for target in TARGETS:
            rec = self.attempt(target=target)
            target_dir = receipts_dir / target
            target_dir.mkdir(parents=True, exist_ok=True)
            (target_dir / "result.json").write_bytes(canonical(rec))

        # Incomplete Darwin-only receipt directory refuses.
        darwin_only = self.root / "receipts-darwin-only"
        (darwin_only / "darwin-arm64").mkdir(parents=True)
        (darwin_only / "darwin-arm64/result.json").write_bytes(
            (receipts_dir / "darwin-arm64/result.json").read_bytes()
        )
        with patch.object(h, "source_commit", return_value=COMMIT), \
                self.assertRaises(AdmissionError) as caught:
            h.admit_matrix(self.pin, self.dist, darwin_only, COMMIT, RUN_ID, "1")
        self.assertEqual(caught.exception.code, "TF_PYPI_HOSTED_MATRIX_RECEIPTS")

        # Legacy single-consumer top-level result.json layout refuses.
        legacy_dir = self.root / "receipts-legacy"
        legacy_dir.mkdir(parents=True)
        (legacy_dir / "result.json").write_bytes(
            (receipts_dir / "darwin-arm64/result.json").read_bytes()
        )
        with patch.object(h, "source_commit", return_value=COMMIT), \
                self.assertRaises(AdmissionError) as caught:
            h.admit_matrix(self.pin, self.dist, legacy_dir, COMMIT, RUN_ID, "1")
        self.assertEqual(caught.exception.code, "TF_PYPI_HOSTED_MATRIX_RECEIPTS")

        # Wrong expected_commit fails before accepting receipts.
        with patch.object(h, "source_commit", side_effect=AdmissionError("TF_PYPI_HOSTED_COMMIT")), \
                self.assertRaises(AdmissionError) as caught:
            h.admit_matrix(self.pin, self.dist, receipts_dir, "b" * 40, RUN_ID, "1")
        self.assertEqual(caught.exception.code, "TF_PYPI_HOSTED_COMMIT")

        darwin_file = receipts_dir / "darwin-arm64/result.json"
        original = strict_json(darwin_file.read_bytes())

        other_pin, other_data = fixture("theme-forge-solar-sail")
        other_dist = self.root / "other-dist"
        other_agg = aggregate(other_pin, other_data, other_dist)
        other_wheel = next(r for r in other_agg["files"] if r["target"] == "darwin-arm64")
        other_sdist = next(r for r in other_agg["files"] if r["target"] is None)

        stale_nebular = {
            k: v for k, v in original.items()
            if k not in ("run_id", "run_attempt", "aggregate_set_sha256")
        }
        stale_nebular["schema"] = "rs9.tf-pypi-hosted-consumer.v1"
        stale_nebular["project"] = "theme-forge-nebular-fusion"

        empty_probe_life = [
            {"kind": "wheel", "install_exit": 0, "probes": [{"command": ""}]},
            {"kind": "sdist", "install_exit": 0, "probes": [{"command": "tfsl"}]},
        ]
        more_mutations = [
            stale_nebular,
            {**original, "schema": "rs9.tf-pypi-hosted-consumer.v1"},
            {**original, "status": "failed"},
            {**original, "project": "theme-forge-solar-sail"},
            {**original, "version": self.pin["version"]},
            {**original, "upstream_version": self.pin["distribution_version"]},
            {**original, "public_writes": 1},
            {**original, "consumer": {**original["consumer"], "project": "theme-forge-solar-sail"}},
            {**original, "consumer": {**original["consumer"], "target": "linux-x64-gnu"}},
            {**original, "consumer": {**original["consumer"], "lifecycle": empty_probe_life}},
            {
                **original,
                "wheel": other_wheel,
                "sdist": other_sdist,
                "aggregate_set_sha256": other_agg["set_sha256"],
            },
        ]
        for idx, mutated in enumerate(more_mutations):
            darwin_file.write_bytes(canonical(mutated))
            with self.subTest(mutation_idx=idx), patch.object(h, "source_commit", return_value=COMMIT), \
                    self.assertRaises(AdmissionError) as caught:
                h.admit_matrix(self.pin, self.dist, receipts_dir, COMMIT, RUN_ID, "1")
            self.assertEqual(caught.exception.code, "TF_PYPI_HOSTED_MATRIX_RECEIPT")
        darwin_file.write_bytes(canonical(original))

    def test_linux_consumer_prefix_expansion_and_enetunreach_isolation(self):
        raw_prefix = [
            "sudo", "-n", "unshare", "--net", "/bin/sh", "-euc",
            'ip link set lo up; exec "$@"', "sh",
            "/usr/bin/env", "-i", "HOME=/frozen", "PATH=/usr/bin:/bin",
        ]
        negative_env = {
            "HOME": "/tmp/work",
            "PATH": "",
            "THEME_FORGE_NODE_BIN": "/custom/node",
            "PIP_NO_INDEX": "1",
        }
        expanded = c._expand_prefix(raw_prefix, negative_env)
        self.assertTrue(expanded[0].startswith("/"))
        self.assertIn("THEME_FORGE_NODE_BIN=/custom/node", expanded)
        self.assertIn("PATH=", expanded)
        self.assertIn("PIP_NO_INDEX=1", expanded)
        self.assertNotIn("HOME=/frozen", expanded)

        py_out = json.dumps({"1.1.1.1": errno.ENETUNREACH, "registry.npmjs.org": -3}).encode()
        js_out = b"ENETUNREACH\nEAI_AGAIN\n"
        with patch.object(c, "_success", side_effect=[
            CompletedProcess([], 0, py_out, b""),
            CompletedProcess([], 0, js_out, b""),
        ]):
            proof = c.network_denial("python3", "node", negative_env, prefix=("unshare", "--net"))
        self.assertTrue(proof["network_disabled"])
        self.assertEqual(proof["method"], "explicit-isolation-prefix")

        # Without an unshare --net prefix (inherited macOS sandbox or non-unshare prefix), ENETUNREACH is rejected.
        for bad_prefix in ((), ("/usr/bin/env",)):
            with self.subTest(bad_prefix=bad_prefix), patch.object(c, "_success", side_effect=[
                CompletedProcess([], 0, py_out, b""),
                CompletedProcess([], 0, js_out, b""),
            ]), self.assertRaises(AdmissionError) as caught:
                c.network_denial("python3", "node", negative_env, prefix=bad_prefix)
            self.assertEqual(caught.exception.code, "TF_PYPI_OFFLINE_ISOLATION")

    def test_failure_report_survives_and_has_no_local_error_path(self):
        out = self.root / "result.json"
        with patch.object(h, "qualify", side_effect=RuntimeError(str(self.root))):
            rc = h.main([
                "qualify", "--project", PROJECT, "--dist", "unused", "--work", str(self.root / "w"),
                "--report", str(out), "--expected-commit", COMMIT,
            ])
        data = out.read_text()
        self.assertEqual(rc, 1)
        self.assertNotIn(str(self.root), data)
        self.assertEqual(json.loads(data)["error_type"], "RuntimeError")

    def test_existing_report_is_preserved_and_symlink_refused(self):
        out = self.root / "existing.json"
        out.write_text("original")
        with self.assertRaises(FileExistsError):
            h.write_report(out, {"status": "wrong"})
        self.assertEqual(out.read_text(), "original")

        (self.root / "link").symlink_to(out)
        with self.assertRaises(AdmissionError):
            h.write_report(self.root / "link", {})
        self.assertEqual(out.read_text(), "original")

    def test_source_sha_malformed_refused_without_git(self):
        with patch.object(h.subprocess, "run") as call, self.assertRaises(AdmissionError):
            h.source_commit("main")
        call.assert_not_called()


class HostedWorkflow(unittest.TestCase):
    def docs(self):
        return [(p, yaml.safe_load(workflow_text(p))) for p in sorted(PRODUCTS)]

    def registered_docs(self):
        workflows = ROOT / ".github/workflows"
        return [
            (p, yaml.safe_load((workflows / load_pin(p)["workflow"]).read_text(encoding="utf-8")))
            for p in sorted(PRODUCTS)
        ]

    def _assert_workflow_docs_qualify_without_registry_or_oidc(self, docs):
        non_publish_jobs = (
            "build_verify",
            "native_darwin_arm64",
            "native_linux_arm64",
            "native_linux_x64",
            "qualification_gate",
        )
        native_jobs = (
            ("native_darwin_arm64", "macos-15", "darwin-arm64"),
            ("native_linux_arm64", "ubuntu-24.04-arm", "linux-arm64-gnu"),
            ("native_linux_x64", "ubuntu-24.04", "linux-x64-gnu"),
        )
        for project, doc in docs:
            trigger = doc.get("on") or doc.get(True)
            self.assertEqual(trigger["push"]["branches"], ["rs9-tf-pypi-hostqual1"])
            jobs = doc["jobs"]
            self.assertNotIn("id-token", doc["permissions"])
            for name in non_publish_jobs:
                self.assertIn(name, jobs)
                self.assertNotIn("environment", jobs[name])
                self.assertNotIn("id-token", jobs[name].get("permissions", {}))
            self.assertIn("github.event_name == 'workflow_dispatch'", jobs["publish"]["if"])
            self.assertIn("github.ref == 'refs/heads/main'", jobs["publish"]["if"])
            self.assertIn("inputs.mode == 'publish'", jobs["publish"]["if"])
            for job_name, runner, target in native_jobs:
                job = jobs[job_name]
                self.assertEqual(job["runs-on"], runner)
                self.assertEqual(job["needs"], ["build_verify"])
                downloads = [x for x in job["steps"] if x.get("uses", "").startswith("actions/download-artifact@")]
                self.assertEqual(len(downloads), 1)
                self.assertEqual(downloads[0]["with"], {"name": "pypi-artifacts", "path": "dist/"})
                runs = "\n".join(x.get("run", "") for x in job["steps"])
                self.assertIn("rs9.tf_pypi_hosted qualify", runs)
                self.assertIn(f"--target {target}", runs)
                self.assertNotIn("tf_pypi_publish build", runs)
                self.assertIn("--expected-commit", runs)
                self.assertIn('--run-id "$QUALIFY_RUN_ID"', runs)
                self.assertIn('--run-attempt "$QUALIFY_RUN_ATTEMPT"', runs)
                uploads = [x for x in job["steps"] if x.get("uses", "").startswith("actions/upload-artifact@")]
                self.assertEqual(len(uploads), 1)
                self.assertEqual(uploads[0]["if"], "always()")
                self.assertEqual(uploads[0]["with"]["if-no-files-found"], "error")
                self.assertEqual(uploads[0]["with"]["name"], f"native-consumer-{project}-{target}")
            for job in jobs.values():
                for step in job["steps"]:
                    if "run" in step:
                        self.assertNotIn("${{", step["run"])
                    if "uses" in step:
                        self.assertRegex(step["uses"], r"^[\w./-]+@[0-9a-f]{40}$")
                    if step.get("uses", "").startswith("actions/download-artifact@"):
                        self.assertNotIn("run-id", step["with"])
                        self.assertNotIn("github-token", step["with"])

    def test_registered_workflows_qualify_without_registry_or_oidc(self):
        self._assert_workflow_docs_qualify_without_registry_or_oidc(self.registered_docs())

    def test_three_branch_workflows_qualify_without_registry_or_oidc(self):
        non_publish_jobs = (
            "build_verify",
            "native_darwin_arm64",
            "native_linux_arm64",
            "native_linux_x64",
            "qualification_gate",
        )
        for project, doc in self.docs():
            trigger = doc.get("on") or doc.get(True)
            self.assertEqual(trigger["push"]["branches"], ["rs9-tf-pypi-hostqual1"])
            jobs = doc["jobs"]
            self.assertNotIn("id-token", doc["permissions"])
            for name in non_publish_jobs:
                self.assertNotIn("environment", jobs[name])
                self.assertNotIn("id-token", jobs[name].get("permissions", {}))
            self.assertIn("github.event_name == 'workflow_dispatch'", jobs["publish"]["if"])
            self.assertIn("github.ref == 'refs/heads/main'", jobs["publish"]["if"])

    def test_native_jobs_use_same_run_artifact_and_no_script_interpolation(self):
        native_jobs = (
            ("native_darwin_arm64", "macos-15", "darwin-arm64"),
            ("native_linux_arm64", "ubuntu-24.04-arm", "linux-arm64-gnu"),
            ("native_linux_x64", "ubuntu-24.04", "linux-x64-gnu"),
        )
        for project, doc in self.docs():
            for job_name, runner, target in native_jobs:
                job = doc["jobs"][job_name]
                self.assertEqual(job["runs-on"], runner)
                self.assertEqual(job["needs"], ["build_verify"])
                downloads = [x for x in job["steps"] if x.get("uses", "").startswith("actions/download-artifact@")]
                self.assertEqual(len(downloads), 1)
                self.assertEqual(downloads[0]["with"], {"name": "pypi-artifacts", "path": "dist/"})
                runs = "\n".join(x.get("run", "") for x in job["steps"])
                self.assertIn("rs9.tf_pypi_hosted qualify", runs)
                self.assertIn(f"--target {target}", runs)
                self.assertNotIn("tf_pypi_publish build", runs)
                self.assertIn("--expected-commit", runs)
                uploads = [x for x in job["steps"] if x.get("uses", "").startswith("actions/upload-artifact@")]
                self.assertEqual(len(uploads), 1)
                self.assertEqual(uploads[0]["if"], "always()")
                self.assertEqual(uploads[0]["with"]["if-no-files-found"], "error")
                self.assertEqual(uploads[0]["with"]["name"], f"native-consumer-{project}-{target}")
            for job in doc["jobs"].values():
                for step in job["steps"]:
                    if "run" in step:
                        self.assertNotIn("${{", step["run"])

    def test_no_unpinned_actions_or_cross_run_inputs(self):
        for project, doc in self.docs():
            for job in doc["jobs"].values():
                for step in job["steps"]:
                    if "uses" in step:
                        self.assertRegex(step["uses"], r"^[\w./-]+@[0-9a-f]{40}$")
                    if step.get("uses", "").startswith("actions/download-artifact@"):
                        self.assertNotIn("run-id", step["with"])
                        self.assertNotIn("github-token", step["with"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
