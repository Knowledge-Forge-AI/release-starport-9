"""Pure tests: current-only canonical x86_64 Loom/Solar pacman ``any`` reuse on AArch64.

Fixtures are realistic but inert and offline:
- the ORIGINAL x86_64 artifact is produced by the real ``hosted_custody.retain`` and
  ``pages_candidate.write_custody_bundle`` code (receipt, artifact manifest, roles,
  unsigned custody, Merkle), plus fixture-repository copies, detached signatures,
  fixture DB/files and a public certificate, then zipped like an Actions artifact;
- GitHub API run/attempt-jobs/artifacts documents and the ZIP bytes are served via
  the existing ``collect_candidate`` gh runner seam, which records every request;
- Git tree resolution and GITHUB_* executor identity are patched at their process
  boundary, exactly like ``test_original_run_context``.
No network, workflow, Docker, GPG, pacman or database is used. Nothing here proves
any native gate (see tasks/ANY-RESULT.md).
"""
from __future__ import annotations

import copy
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import pickle
import tempfile
import unittest
from unittest.mock import patch
import warnings
import zipfile

from rs9 import current_pacman_any as any_mod
from rs9.collect_candidate import admit_original_run, extract_safe_zip
from rs9.current_generation import CURRENT_GENERATION, distribution_paths
from rs9.errors import ContractError
from rs9.hosted_custody import OriginalRunContext, provenance, retain
from rs9.hosted_summary import contract
from rs9.pages_candidate import write_custody_bundle
from rs9.scratch import canonical

ROOT = Path(__file__).resolve().parents[1]
REPO = "Knowledge-Forge-AI/release-starport-9"
COMMIT, TREE, AUTH = "1" * 40, "2" * 40, "a" * 64
RUN_ID, REPO_ID, CONSTRUCTOR_ID, IMPORTER_ID, ARTIFACT_ID = 7001, 901, 501, 777, 3301
PRODUCER = {"GITHUB_REPOSITORY": REPO, "GITHUB_SHA": COMMIT, "GITHUB_RUN_ID": str(RUN_ID),
            "GITHUB_REF": "refs/heads/main", "GITHUB_EVENT_NAME": "push", "GITHUB_RUN_ATTEMPT": "1"}
STARTED = datetime(2026, 11, 5, 9, 59, tzinfo=timezone.utc)
WORKFLOW, _, SCOPE = distribution_paths(CURRENT_GENERATION)
BURST, LOOM, SOLAR, NEBULAR = ("theme-forge-stellar-burst", "theme-forge-stellar-loom",
                               "theme-forge-solar-sail", "theme-forge-nebular-fusion")
PRODUCTS = (BURST, LOOM, SOLAR, NEBULAR)
VERSIONS = {BURST: "0.6.1", LOOM: "0.5.0", SOLAR: "0.4.2", NEBULAR: "0.7.1"}
ARCH = {BURST: "x86_64", LOOM: "any", SOLAR: "any", NEBULAR: "x86_64"}
CLASSES = {BURST: "native-node-cli", LOOM: "pure-js-cli", SOLAR: "pure-js-cli", NEBULAR: "native-desktop"}
CONSTRUCTOR_ARTIFACT = "candidate-pacman-x86_64-linux"
CUSTODY = "objects/lane-work/unsigned-custody/"
LANE = next(r for r in contract(ROOT, generation=CURRENT_GENERATION)["lanes"]
            if (r["lane"], r["system"]) == ("pacman", "x86_64-linux"))


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def name(product, version=None):
    return f"{product}-{version or VERSIONS[product]}-1-{ARCH[product]}.pkg.tar.zst"


def payload(package_name):
    return any_mod.ZSTD_MAGIC + b" inert fixture package bytes " + package_name.encode()


def receipt(source):
    return {"schema": "rs9.hosted-candidate-diagnostic.v1alpha2", "lane": "pacman", "system": "x86_64-linux",
            "production_enabled": False, "publication_authority": False, "attended_gates_satisfied": False,
            "qualification_authority": True, "application_qualified": None,
            "trust_root": "hosted-candidate-unattested",
            "gates": [{"name": gate, "status": "pass"} for gate in LANE["required_gates"]],
            "execution_error": None, "policy_blockers": [], "production_promotion_blockers": [],
            "runner": {"os": "Linux", "architecture": "x86_64", "kernel": "6.8.0-fixture", "image_os": "ubuntu24",
                       "image_version": "20261101.1", "tools": {"python": "3.12.3"}},
            "fixture": {"used": True, "production": False},
            "network": {"preparation_network": "used-for-authentication-and-provisioning",
                        "runtime_mechanism": "docker-network-none", "runtime_offline_status": "pass",
                        "runtime_reason": "negative-connectivity-and-unprivileged-runtime-required"},
            "provenance": dict(source)}


def constructor_zip(root: Path, source: dict, *, packages=None, custody_exclude=(), fixture_copy_bytes=None,
                    build_changes=None, record_changes=None, extra_retained=(), after_retain=None,
                    zip_extra=(), zip_drop=(), zip_replace=None):
    """Original x86_64 pacman lane output, retained by the real producer code and zipped."""
    root.mkdir(parents=True)
    scratch = root / "scratch"
    lane = scratch / "lane-work"
    packages = dict(packages if packages is not None else {name(p): payload(name(p)) for p in PRODUCTS})
    custody = {n: d for n, d in packages.items() if n not in custody_exclude}
    files = []
    unsigned = lane / "unsigned"
    unsigned.mkdir(parents=True)
    for package_name, data in custody.items():
        (unsigned / package_name).write_bytes(data)
        files.append(unsigned / package_name)
    bundle = lane / "unsigned-custody"
    bundle.mkdir()
    write_custody_bundle(bundle, family="pacman", system="x86_64-linux", packages=custody,
                         authentication_sha256=source["release_ingestion_sha256"], source_commit=source["source_commit"])
    files.extend(p for p in bundle.rglob("*") if p.is_file())
    for product in PRODUCTS:
        matches = sorted(n for n in packages if n.startswith(product + "-"))
        if not matches:
            continue
        package_name = matches[0]
        data = packages[package_name]
        build = {"schema": "rs9.pacman-candidate.v1alpha1", "status": "unsigned-candidate",
                 "qualification": "unqualified-candidate", "can_publish": False, "adapter": "pacman",
                 "package_class": CLASSES[product], "project": product, "version": VERSIONS[product], "revision": "1",
                 "architecture": ARCH[product], "distro": "arch", "package_file": "repo/" + ARCH[product] + "/" + package_name,
                 "package_sha256": sha(data), "package_size": len(data), "dependencies": [],
                 "dependency_classification": {}, "derivation": {"adapter": "pacman"}}
        build.update((build_changes or {}).get(product, {}))
        work = lane / "build" / product
        work.mkdir(parents=True)
        (work / "pacman-manifest.json").write_bytes(canonical(build))
        files.append(work / "pacman-manifest.json")
    # Fixture repository: signed copies, detached signatures and DB/files are test-only roles.
    repository = lane / "pacman" / "x86_64"
    repository.mkdir(parents=True)
    for package_name, data in packages.items():
        (repository / package_name).write_bytes((fixture_copy_bytes or {}).get(package_name, data))
        (repository / (package_name + ".sig")).write_bytes(b"inert fixture detached signature")
        files += [repository / package_name, repository / (package_name + ".sig")]
    for metadata in ("rs9.db.tar.gz", "rs9.db.tar.gz.sig", "rs9.files.tar.gz", "rs9.files.tar.gz.sig"):
        (repository / metadata).write_bytes(b"inert fixture repository metadata")
        files.append(repository / metadata)
    keys = lane / "keys"
    keys.mkdir()
    (keys / "rs9-candidate-fixture-NONPRODUCTION.asc").write_bytes(b"inert fixture public certificate")
    files.append(keys / "rs9-candidate-fixture-NONPRODUCTION.asc")
    (lane / "fixture-identity.json").write_bytes(canonical({"used": True, "production": False,
                                                             "purpose": "NON-PRODUCTION CANDIDATE TEST ONLY"}))
    files.append(lane / "fixture-identity.json")
    (scratch / "authentication-projection.json").write_bytes(canonical({"schema": "fixture-projection"}))
    files.append(scratch / "authentication-projection.json")
    for relative, data in extra_retained:
        target = scratch / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        files.append(target)
    record = receipt(source)
    record.update(record_changes or {})
    output = root / "output"
    output.mkdir()
    retain(scratch, output, files, record)
    if after_retain is not None:
        after_retain(output)
    members = {p.relative_to(output).as_posix(): p.read_bytes() for p in sorted(output.rglob("*")) if p.is_file()}
    for member in zip_drop:
        del members[member]
    members.update(zip_replace or {})
    buffer = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            for member, data in [*sorted(members.items()), *zip_extra]:
                archive.writestr(member, data)
    return buffer.getvalue()


def rewrite_manifest_row(path, **changes):
    def mutate(output):
        manifest = json.loads((output / "artifact-manifest.json").read_bytes())
        for row in manifest["files"]:
            if row["path"] == path:
                row.update(changes)
        (output / "artifact-manifest.json").write_bytes(canonical(manifest))
    return mutate


def step(number, step_name, conclusion="success", status="completed"):
    return {"name": step_name, "number": number, "status": status, "conclusion": conclusion}


def native_steps(lane="success", upload="success"):
    return [step(1, "Set up job"), step(2, "Run actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09"),
            step(3, "Run actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020"),
            step(4, "Provision hosted repository tools"),
            step(5, "Run actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093"),
            step(6, "Execute non-production native lane", lane),
            step(7, "Run actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02", upload),
            step(8, "Complete job")]


def job(job_id, job_name, labels, *, status="completed", conclusion="success", started="2026-11-05T10:10:00Z",
        completed="2026-11-05T10:40:00Z", steps=None):
    return {"id": job_id, "run_id": RUN_ID, "run_attempt": 1, "head_sha": COMMIT, "head_branch": "main",
            "workflow_name": "RS9 current distribution qualification proposal", "name": job_name,
            "status": status, "conclusion": conclusion, "started_at": started, "completed_at": completed,
            "labels": labels, "steps": native_steps() if steps is None else steps}


class Provider:
    """GitHub API + original ZIP behind the existing collector gh runner seam."""

    def __init__(self, zip_bytes, *, served=None):
        self.served = zip_bytes if served is None else served
        self.calls = []
        self.run = {"id": RUN_ID, "run_attempt": 1, "head_sha": COMMIT, "event": "push", "head_branch": "main",
                    "path": WORKFLOW, "status": "in_progress", "conclusion": None,
                    "repository": {"id": REPO_ID, "full_name": REPO},
                    "head_repository": {"id": REPO_ID, "full_name": REPO}, "created_at": "2026-11-05T10:00:00Z"}
        simple = [step(1, "Set up job"), step(2, "Complete job")]
        self.jobs = [job(401, "config", ["ubuntu-24.04"], steps=simple),
                     job(402, "authenticate", ["ubuntu-24.04"], steps=simple),
                     job(403, "pins", ["ubuntu-24.04"], steps=simple),
                     job(CONSTRUCTOR_ID, "pacman-x86_64-linux", ["ubuntu-24.04"]),
                     job(502, "rpm-x86_64-linux", ["ubuntu-24.04"]),
                     job(IMPORTER_ID, "pacman-aarch64-linux", ["ubuntu-24.04-arm"], status="in_progress",
                         conclusion=None, started="2026-11-05T10:41:00Z", completed=None,
                         steps=[step(1, "Set up job"),
                                step(6, "Execute non-production native lane", None, "in_progress")])]
        self.artifacts = [
            {"id": 3101, "name": "candidate-authenticate-generation", "size_in_bytes": 4096,
             "digest": "sha256:" + "4" * 64, "expired": False, "created_at": "2026-11-05T10:05:00Z",
             "expires_at": "2027-02-03T10:05:00Z",
             "archive_download_url": f"https://api.github.com/repos/{REPO}/actions/artifacts/3101/zip",
             "workflow_run": {"id": RUN_ID, "repository_id": REPO_ID, "head_repository_id": REPO_ID,
                              "head_branch": "main", "head_sha": COMMIT}},
            {"id": ARTIFACT_ID, "name": CONSTRUCTOR_ARTIFACT, "size_in_bytes": len(zip_bytes),
             "digest": "sha256:" + sha(zip_bytes), "expired": False, "created_at": "2026-11-05T10:39:30Z",
             "expires_at": "2027-02-03T10:39:30Z",
             "archive_download_url": f"https://api.github.com/repos/{REPO}/actions/artifacts/{ARTIFACT_ID}/zip",
             "workflow_run": {"id": RUN_ID, "repository_id": REPO_ID, "head_repository_id": REPO_ID,
                              "head_branch": "main", "head_sha": COMMIT}}]

    def job(self, job_name):
        return next(j for j in self.jobs if j["name"] == job_name)

    def artifact(self, artifact_name=CONSTRUCTOR_ARTIFACT):
        return next(a for a in self.artifacts if a["name"] == artifact_name)

    def __call__(self, root, argv):
        self.calls.append(list(argv))
        if argv[:4] != ["gh", "api", "--method", "GET"] or len(argv) != 5:
            raise AssertionError("unexpected provider command")
        prefix = f"repos/{REPO}/actions/"
        endpoint = argv[4]
        if endpoint == prefix + f"runs/{RUN_ID}":
            return json.dumps(self.run)
        if endpoint == prefix + f"runs/{RUN_ID}/attempts/1/jobs?per_page=100&page=1":
            return json.dumps({"total_count": len(self.jobs), "jobs": self.jobs})
        if endpoint == prefix + f"runs/{RUN_ID}/artifacts?per_page=100&page=1":
            return json.dumps({"total_count": len(self.artifacts), "artifacts": self.artifacts})
        if endpoint == prefix + f"artifacts/{ARTIFACT_ID}/zip":
            return self.served
        raise AssertionError("unexpected provider endpoint")


class CanonicalAnyCase(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        env = patch.dict(os.environ, PRODUCER)
        env.start()
        self.addCleanup(env.stop)
        tree = patch("rs9.hosted_custody.source_tree_identity", side_effect=self.tree)
        tree.start()
        self.addCleanup(tree.stop)
        network = patch("rs9.github.PublicClient.get", side_effect=AssertionError("network access refused"))
        network.start()
        self.addCleanup(network.stop)
        any_mod._ACQUIRED.clear()
        self.addCleanup(any_mod._ACQUIRED.clear)
        self.source = provenance(ROOT, AUTH, generation=CURRENT_GENERATION)
        self.counter = 0

    @staticmethod
    def tree(repository, commit):
        if commit != COMMIT:
            raise ContractError("HOSTED_SOURCE_TREE", "Source checkout differs from adopted commit")
        return TREE

    def fresh(self, label):
        self.counter += 1
        path = self.root / f"{label}-{self.counter}"
        path.mkdir()
        return path

    def build(self, source=None, **kwargs):
        return constructor_zip(self.fresh("producer") / "x86", source or self.source, **kwargs)

    def context(self, **changes):
        value = {"repository": ROOT, "generation": CURRENT_GENERATION, "family": "pacman", "system": "aarch64-linux",
                 "binding": {"source_commit": COMMIT, "checkout_binding": "hosted:" + COMMIT},
                 "authentication_sha256": AUTH, "phase": "candidate", "client": object(),
                 "captures": [(None, {"project": {"id": p}, "version": VERSIONS[p]}, None) for p in PRODUCTS]}
        value.update(changes)
        return value

    def acquire(self, provider, *, context=None, workspace=None, client=None):
        workspace = workspace if workspace is not None else self.fresh("workspace")
        reader = client if client is not None else any_mod.ActionsArtifactReader(ROOT, runner=provider)
        token = any_mod.acquire_canonical_any(context or self.context(), reader, workspace)
        self.addCleanup(token.close)
        return token, workspace

    def refuse(self, provider, code, **kwargs):
        workspace = self.fresh("workspace")
        with self.assertRaises(ContractError) as caught:
            self.acquire(provider, workspace=workspace, **kwargs)
        self.assertEqual(caught.exception.code, code)
        self.assertEqual(list(workspace.iterdir()), [], "refusal must leave no imported state")
        self.assertEqual(any_mod._ACQUIRED, set())
        return caught.exception


class AcquireSuccessTests(CanonicalAnyCase):
    def test_success_imports_exact_original_bytes_with_closed_witness(self):
        zip_bytes = self.build()
        provider = Provider(zip_bytes)
        token, workspace = self.acquire(provider)
        files = token.files
        self.assertEqual(set(files), {LOOM, SOLAR})
        for product, path in files.items():
            self.assertEqual(path, workspace / "canonical-any" / "files" / name(product))
            self.assertEqual(path.read_bytes(), payload(name(product)))
            self.assertTrue(path.name.endswith("-any.pkg.tar.zst"))
        inventory = sorted(p.relative_to(workspace).as_posix() for p in workspace.rglob("*"))
        self.assertEqual(inventory, sorted(["canonical-any", "canonical-any/files",
                                            "canonical-any/files/" + name(LOOM), "canonical-any/files/" + name(SOLAR)]))
        prefix = f"repos/{REPO}/actions/"
        self.assertEqual([call[4] for call in provider.calls], [
            prefix + f"runs/{RUN_ID}", prefix + f"runs/{RUN_ID}/attempts/1/jobs?per_page=100&page=1",
            prefix + f"runs/{RUN_ID}/artifacts?per_page=100&page=1", prefix + f"artifacts/{ARTIFACT_ID}/zip"])

        raw = token.witness_record()
        document = json.loads(raw)
        self.assertEqual(raw, canonical(document))
        self.assertEqual(set(document), any_mod.WITNESS_KEYS)
        self.assertEqual((document["role"], document["derivation"], document["construction_authority"]),
                         ("reuse-witness", "none-original-bytes-reused", "pacman/x86_64-linux"))
        self.assertIs(document["production_enabled"], False)
        self.assertIs(document["publication_authority"], False)
        self.assertEqual(document["source"], self.source)
        self.assertEqual(document["constructor"]["artifact_digest"], "sha256:" + sha(zip_bytes))
        self.assertEqual((document["constructor"]["artifact_id"], document["constructor"]["job_id"],
                          document["importer"]["job_id"]), (ARTIFACT_ID, CONSTRUCTOR_ID, IMPORTER_ID))
        for product in (LOOM, SOLAR):
            self.assertEqual(document["files"][product], {
                "name": name(product), "sha256": sha(payload(name(product))), "size": len(payload(name(product))),
                "architecture": "any", "replica_path": "canonical-any/files/" + name(product)})
        text = raw.decode()
        for private in (str(self.root), str(ROOT), "/" + "Users/", "/home/", "/private/", "/tmp/", ".sig", ".db", "keys/",
                        "true"):
            self.assertNotIn(private, text)

        with token as held:
            self.assertIs(held, token)
        for operation in (lambda: token.files, token.witness_record, token.verify):
            with self.assertRaises(ContractError) as caught:
                operation()
            self.assertEqual(caught.exception.code, "CANONICAL_ANY_SEAL")

    def test_token_has_no_second_constructor_copy_or_mutation(self):
        with self.assertRaises(ContractError) as caught:
            any_mod.CanonicalAny(object(), {}, {}, b"{}\n")
        self.assertEqual(caught.exception.code, "CANONICAL_ANY_SEAL")
        token, _ = self.acquire(Provider(self.build()))
        for operation in (lambda: copy.copy(token), lambda: copy.deepcopy(token), lambda: pickle.dumps(token),
                          lambda: setattr(token, "_files", {}), lambda: setattr(token, "_closed", False)):
            with self.subTest(operation=operation), self.assertRaises(ContractError) as caught:
                operation()
            self.assertEqual(caught.exception.code, "CANONICAL_ANY_SEAL")
        self.assertEqual(set(token.files), {LOOM, SOLAR})

    def test_second_acquisition_for_same_run_is_refused(self):
        zip_bytes = self.build()
        self.acquire(Provider(zip_bytes))
        workspace = self.fresh("workspace")
        provider = Provider(zip_bytes)
        with self.assertRaises(ContractError) as caught:
            self.acquire(provider, workspace=workspace)
        self.assertEqual(caught.exception.code, "CANONICAL_ANY_DUPLICATE")
        self.assertEqual(provider.calls, [])
        self.assertEqual(list(workspace.iterdir()), [])


class ImporterIdentityTests(CanonicalAnyCase):
    def test_importer_execution_identity_and_context(self):
        provider = Provider(self.build())
        for environment, code in (({"GITHUB_RUN_ATTEMPT": "2"}, "CANONICAL_ANY_CONTEXT"),
                                  ({"GITHUB_EVENT_NAME": "workflow_dispatch"}, "CANONICAL_ANY_CONTEXT"),
                                  ({"GITHUB_REF": "refs/heads/topic"}, "CANONICAL_ANY_CONTEXT"),
                                  ({"GITHUB_SHA": "3" * 40}, "HOSTED_PROVENANCE"),
                                  ({"GITHUB_REPOSITORY": "Knowledge-Forge-AI/theme-forge-packages"}, "HOSTED_PROVENANCE")):
            with self.subTest(environment=environment), patch.dict(os.environ, environment):
                self.refuse(provider, code)
        captures = [(None, {"project": {"id": p}, "version": VERSIONS[p]}, None) for p in (BURST, LOOM, NEBULAR)]
        for changes in ({"system": "x86_64-linux"}, {"family": "rpm"}, {"generation": "theme-forge-live1"},
                        {"authentication_sha256": "A" * 64}, {"binding": {"source_commit": "short"}},
                        {"captures": captures}, {"repository": None}):
            with self.subTest(changes=list(changes)):
                self.refuse(provider, "CANONICAL_ANY_CONTEXT", context=self.context(**changes))
        self.assertEqual(provider.calls, [])

    def test_importer_reauthentication_must_match_original_ingestion(self):
        self.refuse(Provider(self.build()), "CUSTODY_SOURCE", context=self.context(authentication_sha256="b" * 64))

    def test_closed_provider_reader_required(self):
        provider = Provider(self.build())
        from rs9.github import PublicClient
        for client in (provider, PublicClient(), any_mod.ActionsArtifactReader(self.root, runner=provider)):
            with self.subTest(client=type(client).__name__):
                self.refuse(provider, "CANONICAL_ANY_CLIENT", client=client)
        self.assertEqual(provider.calls, [])

    def test_nonempty_workspace_refused(self):
        workspace = self.fresh("workspace")
        (workspace / "preexisting").write_bytes(b"x")
        with self.assertRaises(ContractError) as caught:
            self.acquire(Provider(self.build()), workspace=workspace)
        self.assertEqual(caught.exception.code, "CANONICAL_ANY_WORKSPACE")


class ProviderIdentityTests(CanonicalAnyCase):
    def setUp(self):
        super().setUp()
        self.zip = self.build()

    def test_wrong_repository_source_run_attempt_refused(self):
        cases = {"repository": {"repository": {"id": REPO_ID, "full_name": "Knowledge-Forge-AI/theme-forge-packages"}},
                 "fork": {"head_repository": {"id": 1, "full_name": "someone/release-starport-9"}},
                 "source": {"head_sha": "3" * 40}, "run": {"id": RUN_ID + 1}, "bool-run": {"id": True},
                 "attempt": {"run_attempt": 2}, "event": {"event": "workflow_dispatch"},
                 "branch": {"head_branch": "topic"}, "workflow": {"path": ".github/workflows/rs9-candidate-tests.yml"},
                 "completed": {"status": "completed", "conclusion": "success"}}
        for label, mutation in cases.items():
            with self.subTest(case=label):
                provider = Provider(self.zip)
                provider.run.update(mutation)
                self.refuse(provider, "CANONICAL_ANY_RUN")
                self.assertEqual(len(provider.calls), 1)

    def test_wrong_jobs_refused(self):
        constructor, importer = "pacman-x86_64-linux", "pacman-aarch64-linux"
        cases = [
            ("constructor-failed", lambda p: p.job(constructor).update(conclusion="failure"), "CANONICAL_ANY_JOB"),
            ("constructor-running", lambda p: p.job(constructor).update(status="in_progress", conclusion=None),
             "CANONICAL_ANY_JOB"),
            ("lane-step-skipped", lambda p: p.job(constructor).update(steps=native_steps(lane="skipped")),
             "CANONICAL_ANY_JOB"),
            ("upload-step-failed", lambda p: p.job(constructor).update(steps=native_steps(upload="failure")),
             "CANONICAL_ANY_JOB"),
            ("upload-step-missing", lambda p: p.job(constructor).update(
                steps=[s for s in native_steps() if not s["name"].startswith("Run actions/upload")]), "CANONICAL_ANY_JOB"),
            ("constructor-on-arm", lambda p: p.job(constructor).update(labels=["ubuntu-24.04-arm"]), "CANONICAL_ANY_JOB"),
            ("rerun-attempt", lambda p: p.job(constructor).update(run_attempt=2), "CANONICAL_ANY_JOB"),
            ("other-run", lambda p: p.job(constructor).update(run_id=RUN_ID + 1), "CANONICAL_ANY_JOB"),
            ("other-source", lambda p: p.job(constructor).update(head_sha="3" * 40), "CANONICAL_ANY_JOB"),
            ("importer-finished", lambda p: p.job(importer).update(status="completed", conclusion="success"),
             "CANONICAL_ANY_JOB"),
            ("importer-on-x86", lambda p: p.job(importer).update(labels=["ubuntu-24.04"]), "CANONICAL_ANY_JOB"),
            ("importer-not-sequenced", lambda p: p.job(importer).update(started_at="2026-11-05T10:20:00Z"),
             "CANONICAL_ANY_JOB"),
            ("importer-missing", lambda p: p.jobs.remove(p.job(importer)), "CANONICAL_ANY_DUPLICATE"),
            ("constructor-missing", lambda p: p.jobs.remove(p.job(constructor)), "CANONICAL_ANY_DUPLICATE"),
        ]
        for label, mutate, code in cases:
            with self.subTest(case=label):
                provider = Provider(self.zip)
                mutate(provider)
                self.refuse(provider, code)
                self.assertEqual(len(provider.calls), 2, "no artifact data or ZIP after a job refusal")

    def test_wrong_artifact_identity_or_digest_refused(self):
        other = "sha256:" + sha(self.zip + b"other")
        cases = [
            ("expired", {"expired": True}, "CANONICAL_ANY_ARTIFACT"),
            ("digest-format", {"digest": "md5:" + "0" * 32}, "CANONICAL_ANY_ARTIFACT"),
            ("other-run", {"workflow_run": {**Provider(self.zip).artifact()["workflow_run"], "id": RUN_ID + 1}},
             "CANONICAL_ANY_ARTIFACT"),
            ("other-source", {"workflow_run": {**Provider(self.zip).artifact()["workflow_run"], "head_sha": "3" * 40}},
             "CANONICAL_ANY_ARTIFACT"),
            ("other-repository", {"workflow_run": {**Provider(self.zip).artifact()["workflow_run"], "repository_id": 1}},
             "CANONICAL_ANY_ARTIFACT"),
            ("fork", {"workflow_run": {**Provider(self.zip).artifact()["workflow_run"], "head_repository_id": 1}},
             "CANONICAL_ANY_ARTIFACT"),
            ("download-origin", {"archive_download_url": "https://api.github.com/repos/Knowledge-Forge-AI/"
                                                         f"theme-forge-packages/actions/artifacts/{ARTIFACT_ID}/zip"},
             "CANONICAL_ANY_ARTIFACT"),
            ("before-job", {"created_at": "2026-11-05T10:00:00Z"}, "CANONICAL_ANY_ARTIFACT"),
            ("after-job", {"created_at": "2026-11-05T10:45:00Z"}, "CANONICAL_ANY_ARTIFACT"),
            ("size", {"size_in_bytes": len(self.zip) + 1}, "CANONICAL_ANY_ARTIFACT"),
            ("digest", {"digest": other}, "HOSTED_ARTIFACTS"),
        ]
        for label, mutation, code in cases:
            with self.subTest(case=label):
                provider = Provider(self.zip)
                provider.artifact().update(mutation)
                self.refuse(provider, code)
        tampered = bytearray(self.zip)
        tampered[len(tampered) // 2] ^= 0xFF
        self.refuse(Provider(self.zip, served=bytes(tampered)), "HOSTED_ARTIFACTS")

    def test_duplicate_or_competing_constructor_refused(self):
        def second_constructor(p):
            p.jobs.append(job(503, "pacman-x86_64-linux", ["ubuntu-24.04"]))

        def any_job(p):
            p.jobs.append(job(504, "pacman-any-linux", ["ubuntu-24.04-arm"]))

        def second_artifact(p):
            p.artifacts.append({**p.artifact(), "id": ARTIFACT_ID + 1})

        def premature_import(p):
            p.artifacts.append({**p.artifact(), "id": ARTIFACT_ID + 2, "name": "candidate-pacman-aarch64-linux"})

        def missing(p):
            p.artifact()["name"] = "candidate-pacman-x86_64-linux-renamed"

        for mutate in (second_constructor, any_job, second_artifact, premature_import, missing):
            with self.subTest(case=mutate.__name__):
                provider = Provider(self.zip)
                mutate(provider)
                self.refuse(provider, "CANONICAL_ANY_DUPLICATE")
                self.assertFalse(any(call[4].endswith("/zip") for call in provider.calls))


class OriginalCustodyTests(CanonicalAnyCase):
    def test_original_source_tree_and_hash_substitutions_refused(self):
        cases = (("source_tree", "3" * 40, "CUSTODY_SOURCE"), ("source_commit", "3" * 40, "CUSTODY_SOURCE"),
                 ("builder_source_sha256", "b" * 64, "CUSTODY_SOURCE"), ("contract_sha256", "c" * 64, "CUSTODY_SOURCE"),
                 ("workflow_sha256", "d" * 64, "CUSTODY_SOURCE"), ("configuration_sha256", "e" * 64, "CUSTODY_SOURCE"),
                 ("release_ingestion_sha256", "f" * 64, "CUSTODY_SOURCE"), ("run_id", RUN_ID - 1, "CUSTODY_SOURCE"),
                 ("attempt", 2, "CUSTODY_SOURCE"),
                 ("repository", "Knowledge-Forge-AI/theme-forge-packages", "HOSTED_PROVENANCE"))
        for key, value, code in cases:
            with self.subTest(field=key):
                self.refuse(Provider(self.build(source={**self.source, key: value})), code)

    def test_member_path_and_inventory_substitutions_refused(self):
        loom = CUSTODY + "files/" + name(LOOM)
        cases = [
            ("surplus-member", {"zip_extra": [(CUSTODY + "files/" + name(LOOM, "0.5.1"), payload("x"))]},
             "CUSTODY_INVENTORY"),
            ("traversal-member", {"zip_extra": [("../escape.pkg.tar.zst", payload("x"))]}, "HOSTED_ARTIFACTS"),
            ("duplicate-member", {"zip_extra": [(loom, payload("other"))]}, "HOSTED_ARTIFACTS"),
            ("missing-custody-manifest", {"zip_drop": [CUSTODY + "custody-manifest.json"]}, "CUSTODY_FILE"),
            ("tampered-package", {"zip_replace": {loom: payload(name(LOOM)) + b"!"}}, "CUSTODY_HASH"),
            ("tampered-receipt", {"zip_replace": {"pacman-x86_64-linux.json": b"{}\n"}}, "CUSTODY_RECEIPT"),
        ]
        for label, kwargs, code in cases:
            with self.subTest(case=label):
                self.refuse(Provider(self.build(**kwargs)), code)

    def test_receipt_gate_and_policy_refused(self):
        gates = receipt(self.source)["gates"]
        failed = [dict(g, status="fail") if g["name"] == "pacman-client-qualification" else g for g in gates]
        not_run = [dict(g, status="not-run") if g["name"] == "pacman-package-build" else g for g in gates]
        cases = {"failed-gate": {"gates": failed}, "missing-gate": {"gates": gates[1:]},
                 "duplicate-gate": {"gates": gates + gates[:1]}, "not-run-gate": {"gates": not_run},
                 "execution-error": {"execution_error": "NATIVE_BUILD"}, "policy-blocker": {"policy_blockers": ["held"]},
                 "arm-runner": {"runner": {**receipt(self.source)["runner"], "architecture": "aarch64"}},
                 "offline-unproven": {"network": {**receipt(self.source)["network"], "runtime_offline_status": "not-run"}},
                 "production": {"production_enabled": True},
                 "experiment-schema": {"schema": "rs9.hosted-experiment-diagnostic.v1alpha1"}}
        for label, changes in cases.items():
            with self.subTest(case=label):
                self.refuse(Provider(self.build(record_changes=changes)), "CANONICAL_ANY_RECEIPT")

    def test_signature_and_fixture_role_substitutions_refused(self):
        loom = CUSTODY + "files/" + name(LOOM)
        cases = [
            ("detached-signature-in-custody",
             {"extra_retained": [("lane-work/unsigned-custody/files/" + name(LOOM) + ".sig", b"inert signature")]},
             "CUSTODY_INVENTORY"),
            ("custody-row-declared-fixture-copy",
             {"after_retain": rewrite_manifest_row(loom, role="fixture-signed-copy", promotion="fixture-test-only")},
             "CUSTODY_ROLE"),
            ("unsigned-row-fixture-promotion",
             {"after_retain": rewrite_manifest_row("objects/lane-work/unsigned/" + name(LOOM),
                                                   promotion="fixture-test-only")}, "CUSTODY_ROLE"),
            ("custody-row-policy-pending",
             {"after_retain": rewrite_manifest_row(loom, promotion="candidate-policy-pending")}, "CANONICAL_ANY_ROLE"),
            ("only-fixture-repository-copy", {"custody_exclude": [name(LOOM)]}, "CANONICAL_ANY_CUSTODY"),
            ("divergent-fixture-copy", {"fixture_copy_bytes": {name(LOOM): payload(name(LOOM)) + b"fixture"}},
             "CANONICAL_ANY_DUPLICATE"),
            ("second-loom-in-custody",
             {"packages": {**{name(p): payload(name(p)) for p in PRODUCTS},
                           name(LOOM, "0.5.1"): payload(name(LOOM, "0.5.1"))}}, "CANONICAL_ANY_DUPLICATE"),
            ("build-manifest-other-version", {"build_changes": {LOOM: {"version": "0.5.1"}}}, "CANONICAL_ANY_CUSTODY"),
            ("build-manifest-native-arch", {"build_changes": {SOLAR: {"architecture": "x86_64"}}}, "CANONICAL_ANY_CUSTODY"),
            ("build-manifest-other-bytes", {"build_changes": {SOLAR: {"package_sha256": "0" * 64}}}, "CANONICAL_ANY_CUSTODY"),
            ("not-a-zstd-package",
             {"packages": {**{name(p): payload(name(p)) for p in PRODUCTS}, name(SOLAR): b"plain fixture bytes"}},
             "CANONICAL_ANY_CUSTODY"),
        ]
        for label, kwargs, code in cases:
            with self.subTest(case=label):
                self.refuse(Provider(self.build(**kwargs)), code)

    def test_authenticated_intent_version_must_match(self):
        captures = [(None, {"project": {"id": p}, "version": "9.9.9" if p == LOOM else VERSIONS[p]}, None)
                    for p in PRODUCTS]
        self.refuse(Provider(self.build()), "CANONICAL_ANY_CUSTODY", context=self.context(captures=captures))


class ReplicaTamperTests(CanonicalAnyCase):
    def test_tampered_copied_bytes_are_detected(self):
        zip_bytes = self.build()

        def in_place(path):
            with open(path, "r+b") as stream:
                stream.seek(5)
                stream.write(b"X")

        def truncate(path):
            path.write_bytes(b"")

        def replace_same_bytes(path):
            data = path.read_bytes()
            path.unlink()
            path.write_bytes(data)

        def symlink(path):
            target = path.with_name("elsewhere")
            target.write_bytes(path.read_bytes())
            path.unlink()
            path.symlink_to(target)

        for tamper in (in_place, truncate, replace_same_bytes, symlink):
            with self.subTest(tamper=tamper.__name__):
                any_mod._ACQUIRED.clear()
                token, _ = self.acquire(Provider(zip_bytes))
                tamper(token.files[LOOM])
                with self.assertRaises(ContractError) as caught:
                    token.files
                self.assertEqual(caught.exception.code, "CANONICAL_ANY_REPLICA")
                token.close()


class WitnessValidationTests(CanonicalAnyCase):
    def setUp(self):
        super().setUp()
        self.zip = self.build()
        self.provider = Provider(self.zip)
        self.token, _ = self.acquire(self.provider)
        self.witness = self.token.witness_record()
        self.replicas = dict(self.token.files)
        final = self.fresh("final-collection")
        (final / "artifact.zip").write_bytes(self.zip)
        self.canonical_directory = final / CONSTRUCTOR_ARTIFACT
        extract_safe_zip(final / "artifact.zip", self.canonical_directory)
        self.original_run = self.admit()
        manifest_sha = sha((self.canonical_directory / "artifact-manifest.json").read_bytes())
        jobs = copy.deepcopy(self.provider.jobs)
        importer = next(j for j in jobs if j["name"] == "pacman-aarch64-linux")
        importer.update(status="completed", conclusion="success", completed_at="2026-11-05T11:20:00Z",
                        steps=[step(1, "Set up job"), step(6, "Execute non-production native lane"),
                               step(7, "Run actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02")])
        keys = ("id", "name", "status", "conclusion", "started_at", "completed_at", "steps")
        self.packet = {"schema": "rs9.hosted-manager-packet.v1alpha1", "source_commit": COMMIT, "run_id": RUN_ID,
                       "generation": CURRENT_GENERATION, "qualification_scope": SCOPE,
                       "jobs": [{k: j.get(k) for k in keys} for j in jobs],
                       "artifacts": [{**{k: a.get(k) for k in ("id", "name", "size_in_bytes", "digest", "expired",
                                                                "created_at", "expires_at")},
                                      "collection": "verified", "zip_digest_verified": True,
                                      **({"manifest_sha256": manifest_sha} if a["name"] == CONSTRUCTOR_ARTIFACT else {})}
                                     for a in self.provider.artifacts]}

    def admit(self, **changes):
        document = {**self.provider.run, "status": "completed", "conclusion": "success", **changes}
        return admit_original_run(ROOT, commit=COMMIT, run_id=RUN_ID, started_at=STARTED, generation=CURRENT_GENERATION,
                                  runner=lambda root, argv: json.dumps(document))[1]

    def validate(self, witness=None, **changes):
        arguments = {"repository": ROOT, "original_run": self.original_run, "packet": self.packet,
                     "canonical_directory": self.canonical_directory, "replica_files": self.replicas}
        arguments.update(changes)
        return any_mod.validate_reuse_witness(self.witness if witness is None else witness, **arguments)

    def refuse_validation(self, code, witness=None, **changes):
        with self.assertRaises(ContractError) as caught:
            self.validate(witness, **changes)
        self.assertEqual(caught.exception.code, code)

    def rewritten(self, mutate):
        document = json.loads(self.witness)
        mutate(document)
        return canonical(document)

    def test_witness_validates_against_final_completed_campaign(self):
        for replicas in (self.replicas, None):
            with self.subTest(replicas=replicas is not None):
                selection = self.validate(replica_files=replicas)
                self.assertEqual(selection["construction_authority"], "pacman/x86_64-linux")
                self.assertEqual(selection["provider"], {"lane": "pacman", "system": "x86_64-linux", "run_id": RUN_ID,
                                                         "job_id": CONSTRUCTOR_ID, "artifact_id": ARTIFACT_ID,
                                                         "artifact_digest": "sha256:" + sha(self.zip)})
                for product in (LOOM, SOLAR):
                    path = selection["custody_paths"][product]
                    # Selection points at canonical unsigned custody, never at the ARM replica or fixture repo.
                    self.assertEqual(path, self.canonical_directory / CUSTODY / "files" / name(product))
                    self.assertEqual(selection["files"][product]["sha256"], sha(payload(name(product))))
                self.assertEqual(set(selection["files"]), {LOOM, SOLAR})

    def test_witness_alone_cannot_mint_authority(self):
        forged = OriginalRunContext(REPO, COMMIT, RUN_ID, WORKFLOW, CURRENT_GENERATION, SCOPE, "push",
                                    "refs/heads/main", 1, "completed")
        self.refuse_validation("HOSTED_RUN_CONTEXT", original_run=forged)
        self.refuse_validation("HOSTED_RUN_CONTEXT", original_run=self.admit(status="in_progress", conclusion=None))
        self.refuse_validation("CANONICAL_ANY_WITNESS", witness=json.dumps(json.loads(self.witness)).encode())
        self.refuse_validation("CANONICAL_ANY_WITNESS", witness=self.witness.decode())
        for label, mutate in (
                ("extra-authority", lambda d: d.update(construction_granted=True)),
                ("construction-role", lambda d: d.update(role="construction")),
                ("arm-constructor", lambda d: d.update(construction_authority="pacman/aarch64-linux")),
                ("production", lambda d: d.update(production_enabled=True)),
                ("other-digest", lambda d: d["constructor"].update(artifact_digest="sha256:" + "9" * 64)),
                ("other-file", lambda d: d["files"][LOOM].update(sha256="9" * 64)),
                ("other-replica-path", lambda d: d["files"][LOOM].update(replica_path="lane-work/pacman/x86_64/x")),
                ("host-path", lambda d: d["files"][LOOM].update(replica_path="/" + "home/runner/work/x")),
                ("other-importer", lambda d: d["importer"].update(job_id=IMPORTER_ID + 1))):
            with self.subTest(case=label):
                self.refuse_validation("CANONICAL_ANY_WITNESS", witness=self.rewritten(mutate))

    def test_final_campaign_rows_must_match(self):
        def artifact():
            return next(a for a in self.packet["artifacts"] if a["name"] == CONSTRUCTOR_ARTIFACT)

        def job_row(job_name):
            return next(j for j in self.packet["jobs"] if j["name"] == job_name)

        cases = [
            ("other-digest", lambda: artifact().update(digest="sha256:" + "9" * 64), "CANONICAL_ANY_WITNESS"),
            ("collection-failed", lambda: artifact().update(collection="failed"), "CANONICAL_ANY_ARTIFACT"),
            ("other-manifest", lambda: artifact().update(manifest_sha256="9" * 64), "CANONICAL_ANY_ARTIFACT"),
            ("importer-failed", lambda: job_row("pacman-aarch64-linux").update(conclusion="failure"), "CANONICAL_ANY_JOB"),
            ("constructor-failed", lambda: job_row("pacman-x86_64-linux").update(conclusion="failure"),
             "CANONICAL_ANY_JOB"),
            ("second-constructor", lambda: self.packet["jobs"].append({**job_row("pacman-x86_64-linux"), "id": 999}),
             "CANONICAL_ANY_DUPLICATE"),
            ("other-run", lambda: self.packet.update(run_id=RUN_ID + 1), "CANONICAL_ANY_RUN"),
        ]
        pristine = copy.deepcopy(self.packet)
        for label, mutate, code in cases:
            with self.subTest(case=label):
                self.packet = copy.deepcopy(pristine)
                mutate()
                self.refuse_validation(code)

    def test_canonical_set_from_another_campaign_refused(self):
        other = self.build(source={**self.source, "run_id": RUN_ID - 1})
        final = self.fresh("other-campaign")
        (final / "artifact.zip").write_bytes(other)
        extract_safe_zip(final / "artifact.zip", final / CONSTRUCTOR_ARTIFACT)
        self.refuse_validation("CUSTODY_SOURCE", canonical_directory=final / CONSTRUCTOR_ARTIFACT)

    def test_replica_substitution_or_tamper_refused(self):
        copies = self.fresh("replicas")
        tampered = {}
        for product, path in self.replicas.items():
            target = copies / path.name
            target.write_bytes(path.read_bytes() + (b"!" if product == LOOM else b""))
            tampered[product] = target
        self.refuse_validation("CANONICAL_ANY_REPLICA", replica_files=tampered)
        signature = copies / (name(SOLAR) + ".sig")
        signature.write_bytes(self.replicas[SOLAR].read_bytes())
        self.refuse_validation("CANONICAL_ANY_REPLICA", replica_files={**self.replicas, SOLAR: signature})
        self.refuse_validation("CANONICAL_ANY_REPLICA", replica_files={LOOM: self.replicas[LOOM]})
        fixture_copy = self.canonical_directory / "objects/lane-work/pacman/x86_64" / (name(BURST))
        self.refuse_validation("CANONICAL_ANY_REPLICA", replica_files={**self.replicas, BURST: fixture_copy})


class PlannerSelectionTests(unittest.TestCase):
    FILES = {LOOM: "1" * 64, SOLAR: "2" * 64}

    def row(self, system, role, files=None):
        return {"lane": "pacman", "system": system, "role": role, "files": dict(files or self.FILES)}

    def test_only_canonical_x86_64_constructor_is_selected(self):
        canonical_row = self.row("x86_64-linux", "construction")
        witness = self.row("aarch64-linux", "reuse-witness")
        for providers in ([canonical_row], [canonical_row, witness], [witness, canonical_row]):
            with self.subTest(order=[p["system"] for p in providers]):
                self.assertEqual(any_mod.select_canonical_any_provider(providers),
                                 {"lane": "pacman", "system": "x86_64-linux", "files": self.FILES})

    def test_second_constructor_refused_not_deduplicated(self):
        canonical_row = self.row("x86_64-linux", "construction")
        cases = [
            ("identical-arm-construction", [canonical_row, self.row("aarch64-linux", "construction")],
             "CANONICAL_ANY_DUPLICATE"),
            ("same-filename-twice", [canonical_row, dict(canonical_row)], "CANONICAL_ANY_DUPLICATE"),
            ("arm-only", [self.row("aarch64-linux", "construction")], "CANONICAL_ANY_PROVIDER"),
            ("no-constructor", [self.row("aarch64-linux", "reuse-witness")], "CANONICAL_ANY_DUPLICATE"),
            ("divergent-witness", [canonical_row, self.row("aarch64-linux", "reuse-witness", {**self.FILES, LOOM: "3" * 64})],
             "CANONICAL_ANY_REPLICA"),
            ("x86-witness", [canonical_row, self.row("x86_64-linux", "reuse-witness")], "CANONICAL_ANY_REPLICA"),
            ("unknown-role", [canonical_row, self.row("aarch64-linux", "derivation")], "CANONICAL_ANY_PROVIDER"),
        ]
        for label, providers, code in cases:
            with self.subTest(case=label), self.assertRaises(ContractError) as caught:
                any_mod.select_canonical_any_provider(providers)
            self.assertEqual(caught.exception.code, code)


if __name__ == "__main__":
    unittest.main()
