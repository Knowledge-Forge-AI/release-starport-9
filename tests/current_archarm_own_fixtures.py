"""Controlled current ARM pacman reuse transport for own-repository admission tests.

Unit-only fixture helpers; no native, Git, network, Docker, GPG, pacman or
compression authority. Package bodies are inert synthetic zstd-prefix bytes.

* The canonical x86_64 pacman artifact is retained by the real producer code
  (``hosted_custody.retain`` + ``pages_candidate.write_custody_bundle``) via the
  existing ``tests.test_current_pacman_any.constructor_zip`` seam, with the
  fixed own-repository versions supplied as explicit packages/build changes.
* The ARM lane obtains its two raw replicas and its witness from the REAL
  ``current_pacman_any.acquire_canonical_any`` importer, reading an in-process
  import-time view of the SAME controlled original run (same run, job, step and
  artifact ids, timestamps and ZIP bytes later served to the final collector).
* The ARM lane constructs only Burst/Nebular aarch64 bytes; it has no ``any``
  build manifest, custody row or second constructor.
"""
from __future__ import annotations

import copy
import hashlib
import io
import json
from pathlib import Path
import shutil
import zipfile

from rs9 import current_pacman_any as any_mod
from rs9.current_generation import CURRENT_GENERATION, distribution_paths
from rs9.hosted_custody import retain
from rs9.hosted_summary import contract
from rs9.pages_candidate import write_custody_bundle
from rs9.scratch import canonical
from tests import test_current_pacman_any as any_fixtures

REPOSITORY = any_mod.REPOSITORY
REPOSITORY_ID = any_fixtures.REPO_ID
RUN_ID = 7
ZIP_TIME = (2026, 10, 29, 0, 0, 0)
RUN_CREATED = "2026-10-29T00:00:01Z"
EXPIRES = "2027-01-27T00:00:00Z"
ANY_PRODUCTS = frozenset(any_mod.ANY_PRODUCTS)
CONSTRUCTOR_JOB, IMPORTER_JOB = any_mod.CONSTRUCTOR_JOB, any_mod.IMPORTER_JOB
WORKFLOW_NAME = "RS9 current distribution qualification proposal"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _t(seconds: int) -> str:
    return f"2026-10-29T{seconds // 3600:02d}:{seconds % 3600 // 60:02d}:{seconds % 60:02d}Z"


# Original-run timeline (seconds after 2026-10-29T00:00:00Z). Every other
# native/nix lane runs in the default window; ARM imports after the canonical
# x86_64 constructor completed; Pages and the summary follow ARM.
WINDOWS = {"config": (10, 60), "unit": (60, 300), "authenticate": (60, 360), "pins": (60, 360),
           IMPORTER_JOB: (41 * 60, 80 * 60), "pages": (81 * 60, 95 * 60), "summary": (96 * 60, 100 * 60)}
DEFAULT_WINDOW = (10 * 60, 40 * 60)


def window(job_name):
    return WINDOWS.get(job_name, DEFAULT_WINDOW)


def artifact_created(job_name):
    return _t(window(job_name)[1] - 30)


def importer_started():
    return _t(window(IMPORTER_JOB)[0])


def package_name(product, versions):
    return f"{product}-{versions[product]}-1-{any_fixtures.ARCH[product]}.pkg.tar.zst"


def native_arm_name(product, versions):
    return f"{product}-{versions[product]}-1-aarch64.pkg.tar.zst"


def zip_directory(directory, date_time=ZIP_TIME):
    """Deterministic Actions-like ZIP of a retained artifact directory."""
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        for path in sorted(Path(directory).rglob("*")):
            if path.is_file():
                info = zipfile.ZipInfo(path.relative_to(directory).as_posix(), date_time=date_time)
                archive.writestr(info, path.read_bytes())
    return stream.getvalue()


def run_document(commit, *, status, conclusion):
    return {"id": RUN_ID, "run_attempt": 1, "head_sha": commit, "event": "push", "head_branch": "main",
            "path": distribution_paths(CURRENT_GENERATION)[0], "status": status, "conclusion": conclusion,
            "repository": {"id": REPOSITORY_ID, "full_name": REPOSITORY},
            "head_repository": {"id": REPOSITORY_ID, "full_name": REPOSITORY}, "created_at": RUN_CREATED}


def artifact_row(identity, name, body, created_at, commit):
    return {"id": identity, "name": name, "size_in_bytes": len(body), "digest": "sha256:" + sha(body),
            "expired": False, "created_at": created_at, "expires_at": EXPIRES,
            "archive_download_url": f"https://api.github.com/repos/{REPOSITORY}/actions/artifacts/{identity}/zip",
            "workflow_run": {"id": RUN_ID, "repository_id": REPOSITORY_ID, "head_repository_id": REPOSITORY_ID,
                             "head_branch": "main", "head_sha": commit}}


def job_runners(repository):
    runners = {}
    for lane in contract(repository, generation=CURRENT_GENERATION)["lanes"]:
        name = lane["lane"] + "-" + lane["system"] if lane["lane"] in {"nix", "rpm", "deb", "pacman"} else lane["lane"]
        runners[name] = lane["runner"]
    return runners


def jobs(names, commit, runners):
    """Final completed attempt-1 jobs; pacman jobs carry the executed lane/upload steps."""
    rows = []
    for identity, name in enumerate(sorted(names), 1):
        started, completed = window(name)
        native = name in (CONSTRUCTOR_JOB, IMPORTER_JOB)
        rows.append({"id": identity, "run_id": RUN_ID, "run_attempt": 1, "head_sha": commit, "head_branch": "main",
                     "workflow_name": WORKFLOW_NAME, "name": name, "status": "completed", "conclusion": "success",
                     "started_at": _t(started), "completed_at": _t(completed),
                     "labels": [runners.get(name, "ubuntu-24.04")],
                     "steps": any_fixtures.native_steps() if native else
                     [{"name": "controlled fixture", "conclusion": "success"}]})
    return rows


def import_time_jobs(final_jobs):
    """The same job ids while the ARM importer job is executing its lane step."""
    view = copy.deepcopy(final_jobs)
    importer_start = window(IMPORTER_JOB)[0]
    for job in view:
        if job["name"] == IMPORTER_JOB:
            job.update(status="in_progress", conclusion=None, completed_at=None,
                       steps=[any_fixtures.step(1, "Set up job"),
                              any_fixtures.step(6, any_mod.LANE_STEP, None, "in_progress")])
        elif window(job["name"])[0] > importer_start:
            job.update(status="queued", conclusion=None, started_at=None, completed_at=None, steps=[])
    return view


def import_time_artifacts(final_rows):
    return [copy.deepcopy(row) for row in final_rows if row["created_at"] < importer_started()]


class ImportTimeApi:
    """Strict in-process API for the in-progress original run, behind the collector gh seam."""

    def __init__(self, run, job_rows, artifacts, zips):
        self.run, self.jobs, self.artifacts, self.zips = run, job_rows, artifacts, zips
        self.calls = []

    def __call__(self, root, argv):
        self.calls.append(list(argv))
        if argv[:4] != ["gh", "api", "--method", "GET"] or len(argv) != 5:
            raise AssertionError("unexpected import-time provider command")
        prefix = f"repos/{REPOSITORY}/actions/"
        endpoint = argv[4]
        if endpoint == prefix + f"runs/{RUN_ID}":
            return json.dumps(self.run)
        if endpoint == prefix + f"runs/{RUN_ID}/attempts/1/jobs?per_page=100&page=1":
            return json.dumps({"total_count": len(self.jobs), "jobs": self.jobs})
        if endpoint == prefix + f"runs/{RUN_ID}/artifacts?per_page=100&page=1":
            return json.dumps({"total_count": len(self.artifacts), "artifacts": self.artifacts})
        for row in self.artifacts:
            if endpoint == prefix + f"artifacts/{row['id']}/zip":
                return self.zips[row["id"]]
        raise AssertionError("unexpected import-time provider endpoint")


def retain_constructor(root, target, source, versions):
    """Canonical x86_64 constructor custody (own versions) retained by real producer code."""
    packages = {package_name(p, versions): any_fixtures.payload(package_name(p, versions)) for p in any_fixtures.PRODUCTS}
    any_fixtures.constructor_zip(Path(root), source, packages=packages,
                                 build_changes={p: {"version": versions[p]} for p in any_fixtures.PRODUCTS})
    shutil.copytree(Path(root) / "output", target)
    return target


def import_canonical_any(repository, versions, workspace, api, *, authentication_sha256, commit):
    """Real importer; returns the verbatim witness bytes and its own replica paths."""
    context = {"repository": repository, "generation": CURRENT_GENERATION, "family": "pacman",
               "system": "aarch64-linux", "binding": {"source_commit": commit, "checkout_binding": "hosted:" + commit},
               "authentication_sha256": authentication_sha256, "phase": "candidate", "client": object(),
               "captures": [(None, {"project": {"id": p}, "version": versions[p]}, None) for p in sorted(versions)]}
    token = any_mod.acquire_canonical_any(context, any_mod.ActionsArtifactReader(repository, runner=api), workspace)
    try:
        return token.witness_record(), dict(token.files)
    finally:
        token.close()


def produce_arm_lane(repository, scratch, output, *, source, versions, gates, api):
    """Current ARM output: raw replicas + witness, and native-only unsigned custody."""
    lane_work = Path(scratch) / "lane-work"
    lane_work.mkdir(parents=True)
    witness, replicas = import_canonical_any(repository, versions, lane_work, api,
                                             authentication_sha256=source["release_ingestion_sha256"],
                                             commit=source["source_commit"])
    files = [replicas[p] for p in sorted(replicas)]
    witness_path = lane_work / "canonical-any-witness.json"
    witness_path.write_bytes(witness)
    files.append(witness_path)
    natives = {native_arm_name(p, versions): any_fixtures.payload(native_arm_name(p, versions))
               for p in sorted(versions) if p not in ANY_PRODUCTS}
    unsigned = lane_work / "unsigned"
    unsigned.mkdir()
    for name, data in natives.items():
        (unsigned / name).write_bytes(data)
        files.append(unsigned / name)
    bundle = lane_work / "unsigned-custody"
    bundle.mkdir()
    write_custody_bundle(bundle, family="pacman", system="aarch64-linux", packages=natives,
                         authentication_sha256=source["release_ingestion_sha256"], source_commit=source["source_commit"])
    files.extend(sorted(p for p in bundle.rglob("*") if p.is_file()))
    for product in sorted(versions):
        if product in ANY_PRODUCTS:
            continue
        name = native_arm_name(product, versions)
        build = {"schema": any_mod.BUILD_SCHEMA, "status": "unsigned-candidate", "qualification": "unqualified-candidate",
                 "can_publish": False, "adapter": "pacman", "package_class": any_fixtures.CLASSES[product],
                 "project": product, "version": versions[product], "revision": "1", "architecture": "aarch64",
                 "distro": "arch", "package_file": "repo/aarch64/" + name, "package_sha256": sha(natives[name]),
                 "package_size": len(natives[name]), "dependencies": [], "dependency_classification": {},
                 "derivation": {"adapter": "pacman"}}
        work = lane_work / "build" / product
        work.mkdir(parents=True)
        (work / "pacman-manifest.json").write_bytes(canonical(build))
        files.append(work / "pacman-manifest.json")
    document = json.loads(witness)
    declared = {"role": "reuse-witness", "construction_on_this_lane": False,
                "construction_authority": {"family": "pacman", "system": "x86_64-linux"},
                "witness_file": witness_path.name, "witness_sha256": sha(witness),
                "replicas": {p: {"file": d["replica_path"], "sha256": d["sha256"], "size": d["size"]}
                             for p, d in document["files"].items()}}
    record = {"schema": "rs9.hosted-candidate-diagnostic.v1alpha2", "lane": "pacman", "system": "aarch64-linux",
              "production_enabled": False, "publication_authority": False, "attended_gates_satisfied": False,
              "execution_error": None, "policy_blockers": [], "runner": {"os": "Linux", "architecture": "aarch64"},
              "provenance": dict(source), "production_promotion_blockers": [],
              "gates": [{"name": name, "status": "pass"} for name in gates],
              "details": {"canonical_any_reuse": declared}}
    return retain(scratch, output, files, record), witness
