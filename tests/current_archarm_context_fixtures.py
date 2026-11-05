"""Current twelve-lane pacman composition for original-run-context fixtures.

Unit-only adapter over ``tests.current_archarm_own_fixtures``; no native, Git,
network, signing, pacman or compression authority. Package bodies are inert
synthetic bytes and never execute.

* The canonical x86_64 pacman artifact is retained by the real producer code
  through the existing constructor seam (selected current versions).
* The current ARM lane obtains its raw ``any`` replicas and witness from the
  REAL ``current_pacman_any.acquire_canonical_any`` importer, reading an
  import-time view of the SAME controlled original run: same run, job and
  artifact ids, timestamps and deterministic ZIP bytes later served to the
  final collector, where ``original_reuse``/``validate_reuse_witness`` run
  unpatched.
* Historical/default ``HostedSummaryTests`` fixtures are not modified; callers
  replace only the current pacman lanes in their own scratch copy.
"""
from __future__ import annotations

from pathlib import Path
import shutil

from rs9 import current_pacman_any as any_mod
from rs9.candidate import configuration_rows
from rs9.current_generation import CURRENT_GENERATION
from rs9.current_pacman_reuse import ARM_ARTIFACT, CANONICAL_ARTIFACT
from rs9.hosted_summary import required
from tests import current_archarm_own_fixtures as arm
from tests import test_current_pacman_any as any_fixtures

CURRENT_PACMAN_ARTIFACTS = frozenset({CANONICAL_ARTIFACT, ARM_ARTIFACT})
RUN_ID = arm.RUN_ID


def job_name(lane):
    return lane["lane"] + "-" + lane["system"] if lane["lane"] in {"nix", "rpm", "deb", "pacman"} else lane["lane"]


def job_names(repository):
    return {job_name(lane) for lane in required(repository, generation=CURRENT_GENERATION)} | {"config", "unit", "summary"}


def pacman_versions(repository):
    """Pacman versions selected by the current source configuration (as the facade reads them)."""
    selected = {intent["project"]["id"]: intent["version"]
                for _, intent in configuration_rows(repository, generation=CURRENT_GENERATION)}
    return {product: selected[product] for product in any_fixtures.PRODUCTS}


def artifact_directories(repository, inputs, summary):
    """Original-run artifact order; identities are assigned from 10 in this order."""
    return [(lane["artifact_name"], Path(inputs) / lane["artifact_name"], job_name(lane))
            for lane in required(repository, generation=CURRENT_GENERATION)] + [("hosted-summary", Path(summary), "summary")]


def artifact_rows(repository, inputs, summary, commit, names=None):
    """Exact provider rows plus deterministic Actions-like ZIP bodies."""
    rows, zips = [], {}
    for identity, (name, directory, job) in enumerate(artifact_directories(repository, inputs, summary), 10):
        if names is not None and name not in names:
            continue
        body = arm.zip_directory(directory)
        zips[identity] = body
        rows.append(arm.artifact_row(identity, name, body, arm.artifact_created(job), commit))
    return rows, zips


def final_jobs(repository, commit):
    """Completed attempt-1 jobs; pacman constructor/importer carry executed lane/upload steps."""
    return arm.jobs(job_names(repository), commit, arm.job_runners(repository))


def original_api(repository, inputs, summary, commit):
    """Final original-run artifacts, ZIP bodies and jobs for the collector seam."""
    artifacts, zips = artifact_rows(repository, inputs, summary, commit)
    return artifacts, zips, final_jobs(repository, commit)


def retain_canonical_constructor(repository, scratch_root, inputs, source):
    """Replace the historical pacman x86_64 directory with real-producer constructor custody."""
    target = Path(inputs) / CANONICAL_ARTIFACT
    if target.exists():
        shutil.rmtree(target)
    return arm.retain_constructor(Path(scratch_root) / "constructor-x86_64", target, source, pacman_versions(repository))


def produce_arm_reuse_lane(repository, scratch_root, inputs, summary, source, commit):
    """Current ARM lane minted by the real importer against the in-progress original run.

    Call only after every artifact uploaded before the importer started is final,
    so the import-time ZIP bytes equal the bytes the final collector receives.
    """
    lane = next(row for row in required(repository, generation=CURRENT_GENERATION) if row["artifact_name"] == ARM_ARTIFACT)
    target = Path(inputs) / ARM_ARTIFACT
    if target.exists():
        shutil.rmtree(target)
    earlier = {name for name, _, job in artifact_directories(repository, inputs, summary)
               if arm.artifact_created(job) < arm.importer_started()}
    rows, zips = artifact_rows(repository, inputs, summary, commit, earlier)
    api = arm.ImportTimeApi(arm.run_document(commit, status="in_progress", conclusion=None),
                            arm.import_time_jobs(final_jobs(repository, commit)), arm.import_time_artifacts(rows), zips)
    # Each composition models a fresh original run 7 in this test process; the
    # importer's own one-import-per-run guard stays active during the import.
    any_mod._ACQUIRED.discard(RUN_ID)
    try:
        _, witness = arm.produce_arm_lane(repository, Path(scratch_root) / ("scratch-" + ARM_ARTIFACT), target,
                                          source=source, versions=pacman_versions(repository),
                                          gates=lane["required_gates"], api=api)
    finally:
        any_mod._ACQUIRED.discard(RUN_ID)
    return witness, api
