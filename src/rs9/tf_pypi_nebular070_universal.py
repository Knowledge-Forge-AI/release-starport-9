"""Closed qualification commands for the one-wheel Nebular 0.7.0 distribution."""
from __future__ import annotations

import argparse
from collections.abc import Mapping
import hashlib
import os
from pathlib import Path
import re
import sys

from rs9 import nebular070_universal_consumer as consumer
from rs9 import tf_pypi_nebular070_publish as legacy
from rs9 import wheel_nebular070_universal as builder
from rs9.errors import ContractError
from rs9.materialize import validate_ancestry_not_symlink
from rs9.scratch import canonical
from rs9.tf_pypi_archive import AdmissionError
from rs9.tf_pypi_model import strict_json


RUNTIME_INPUTS = Path("operators/tf-pypi/nebular-fusion-0.7.0-universal-runtime-inputs.json")
DESCRIPTION = Path("operators/tf-pypi/descriptions/nebular-fusion-0.7.0-universal.md")
BUNDLE_SCHEMA = "rs9.nebular070-universal-bundle.v1"
MATRIX_SCHEMA = "rs9.nebular070-universal-installed-matrix.v1"
REPOSITORY = "Knowledge-Forge-AI/release-starport-9"
LINUX_TARGETS = ("linux-arm64-gnu", "linux-x64-gnu")


def _fail(code):
    raise ContractError("NEBULAR_UNIVERSAL_" + code, "Universal qualification contract failed")


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _source(repository: Path, expected_commit: str, *, require_clean: bool) -> dict:
    if not isinstance(expected_commit, str) or not re.fullmatch(r"[0-9a-f]{40}", expected_commit):
        _fail("SOURCE")
    source = {"commit": legacy._git_output(repository, ["rev-parse", "HEAD"], "HOSTED_COMMIT"),
              "tree": legacy._git_output(repository, ["rev-parse", "HEAD^{tree}"], "HOSTED_COMMIT")}
    if source["commit"] != expected_commit:
        _fail("SOURCE")
    if require_clean and legacy._git_output(repository, [
        "--no-optional-locks", "status", "--porcelain=v1", "--untracked-files=normal",
    ], "HOSTED_COMMIT"):
        _fail("SOURCE_DIRTY")
    return source


def _descriptor(path: Path, repository: Path, inrun_root: Path) -> dict:
    return legacy.load_qualification_inputs_descriptor(
        path, repository=repository, phase=legacy.QUALIFICATION_INPUT_PHASE_PREP,
        inrun_root=inrun_root)


def _release_root(descriptor: dict, repository: Path, inrun_root: Path) -> Path:
    artifact_root = legacy._resolve_inrun_artifact_root(
        repository, descriptor.get("manylinux"), inrun_root,
        system_webkit_spec=descriptor.get("system_webkit"))
    if "system_webkit" not in descriptor or "manylinux" in descriptor:
        _fail("RUNTIME_PROFILE")
    return legacy._resolve_repo_contained_dir(
        artifact_root, descriptor["raw_release"]["source_root"],
        symlink_code="RAW_RELEASE_SYMLINK", missing_code="RAW_RELEASE_HANDOFF_PENDING",
        containment_code="QUALIFICATION_INPUTS_RAW_RELEASE")


def build_bundle(qualification_inputs: Path, inrun_root: Path, output: Path, *,
                 repository: Path, expected_commit: str, require_clean: bool) -> dict:
    """Construct one source-bound wheel from the maintained static release inputs."""
    source = _source(repository, expected_commit, require_clean=require_clean)
    descriptor = _descriptor(qualification_inputs, repository, inrun_root)
    release_root = _release_root(descriptor, repository, inrun_root)
    raw_pins = builder._read(repository / RUNTIME_INPUTS, 65536)[0]
    pins = builder._inputs(raw_pins)
    parents = set()
    for target, spec in pins["targets"].items():
        row = descriptor["raw_release"]["targets"][target]["payload"]
        # Reuse the descriptor reader's nofollow, byte-length and hash checks.
        from rs9.tf_pypi_consumer import _nebular_descriptor
        data, digest = _nebular_descriptor(release_root, row, "payload")
        if len(data) != spec["asset"]["size"] or digest != spec["asset"]["sha256"]:
            _fail("ARCHIVE")
        path = release_root / row.get("path", row.get("name"))
        if path.name != spec["asset"]["name"]:
            _fail("ARCHIVE")
        parents.add(path.parent)
    if len(parents) != 1:
        _fail("ARCHIVE")
    output = validate_ancestry_not_symlink(output)
    if output.exists() or output.is_symlink():
        _fail("BUNDLE_OUTPUT")
    output.mkdir(parents=True, mode=0o700)
    receipt = builder.build_universal_wheel(
        repository / RUNTIME_INPUTS, parents.pop(), repository / DESCRIPTION,
        output / "dist", legal_root=repository)
    os.replace(output / "dist/universal-build-receipt.json", output / "universal-build-receipt.json")
    description = builder._read(repository / DESCRIPTION, 262144)[0]
    raw_wheel = builder._read(output / "dist" / builder.FILENAME, consumer.MAX_WHEEL_BYTES)[0]
    checked = consumer.inspect_universal_wheel(
        raw_wheel, raw_pins, repository=repository, description=description)
    unsigned = {
        "schema": BUNDLE_SCHEMA, "version": builder.VERSION, "distribution": consumer.DISTRIBUTION,
        "source": source, "wheel": checked["wheel"],
        "runtime_inputs_sha256": checked["runtime_inputs_sha256"],
        "runtime_index_sha256": checked["runtime_index_sha256"],
        "description_sha256": _sha(description),
        "build_receipt_sha256": _sha(canonical(receipt)),
        "builder_can_publish": False, "publication_admitted": False,
    }
    result = {**unsigned, "identity": _sha(canonical(unsigned))}
    builder._write(output / "bundle.json", canonical(result))
    load_bundle(output, repository=repository, expected_source=source)
    return result


def load_bundle(path: Path, *, repository: Path, expected_source: dict | None = None) -> tuple[dict, dict]:
    """Validate the exact bundle file set and current-source package bytes."""
    path = validate_ancestry_not_symlink(path)
    if not path.is_dir() or {item.name for item in path.iterdir()} != {
        "bundle.json", "universal-build-receipt.json", "dist",
    }:
        _fail("BUNDLE")
    dist = validate_ancestry_not_symlink(path / "dist")
    if not dist.is_dir() or {item.name for item in dist.iterdir()} != {builder.FILENAME}:
        _fail("BUNDLE")
    value = strict_json(builder._read(path / "bundle.json", 65536)[0])
    keys = {"schema", "version", "distribution", "source", "wheel", "runtime_inputs_sha256",
            "runtime_index_sha256", "description_sha256", "build_receipt_sha256",
            "builder_can_publish", "publication_admitted", "identity"}
    if (not isinstance(value, dict) or set(value) != keys or value["schema"] != BUNDLE_SCHEMA
            or value["version"] != builder.VERSION or value["distribution"] != consumer.DISTRIBUTION
            or value["builder_can_publish"] is not False or value["publication_admitted"] is not False
            or not isinstance(value["source"], dict) or set(value["source"]) != {"commit", "tree"}
            or any(not isinstance(item, str) or not re.fullmatch(r"[0-9a-f]{40}", item)
                   for item in value["source"].values())
            or (expected_source is not None and value["source"] != expected_source)):
        _fail("BUNDLE")
    unsigned = dict(value)
    identity = unsigned.pop("identity")
    if identity != _sha(canonical(unsigned)):
        _fail("BUNDLE")
    raw_receipt = builder._read(path / "universal-build-receipt.json", 65536)[0]
    receipt = strict_json(raw_receipt)
    description = builder._read(repository / DESCRIPTION, 262144)[0]
    snapshot = consumer.inspect_universal_wheel(
        builder._read(dist / builder.FILENAME, consumer.MAX_WHEEL_BYTES)[0],
        builder._read(repository / RUNTIME_INPUTS, 65536)[0], repository=repository, description=description)
    if (value["wheel"] != snapshot["wheel"] or value["description_sha256"] != _sha(description)
            or value["build_receipt_sha256"] != _sha(raw_receipt)
            or value["runtime_inputs_sha256"] != snapshot["runtime_inputs_sha256"]
            or value["runtime_index_sha256"] != snapshot["runtime_index_sha256"]
            or not isinstance(receipt, dict) or receipt.get("builder_can_publish") is not False
            or receipt.get("schema") != "rs9.nebular070-universal-build.v1"
            or any(receipt.get(key) != snapshot["wheel"][key] for key in ("filename", "tag", "size", "sha256"))):
        _fail("BUNDLE")
    return value, snapshot


def _hosted_context(source: Mapping, run_id: str, run_attempt: str) -> None:
    if (not isinstance(source, Mapping) or set(source) != {"commit", "tree"}
            or any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{40}", value)
                   for value in source.values())
            or not isinstance(run_id, str) or not re.fullmatch(r"[1-9][0-9]*", run_id)
            or run_attempt != "1" or os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("GITHUB_REPOSITORY") != REPOSITORY
            or os.environ.get("GITHUB_REF") != "refs/heads/main"
            or os.environ.get("GITHUB_SHA") != source["commit"]
            or os.environ.get("GITHUB_RUN_ID") != run_id
            or os.environ.get("GITHUB_RUN_ATTEMPT") != run_attempt):
        _fail("HOSTED_CONTEXT")


def _output_path(path: Path) -> Path:
    path = validate_ancestry_not_symlink(path)
    if path.exists() or path.is_symlink():
        _fail("OUTPUT")
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    validate_ancestry_not_symlink(path.parent)
    return path


def qualify_native(bundle: Path, work: Path, output: Path, *, target: str,
                   expected_commit: str, run_id: str, run_attempt: str,
                   qualification_inputs: Path, inrun_root: Path,
                   raw_release_path: Path, repository: Path,
                   consumer_host_role: str = "newer") -> dict:
    """Install the genuine universal wheel on the matching public native host."""
    source = _source(repository, expected_commit, require_clean=True)
    _hosted_context(source, run_id, run_attempt)
    if (target not in builder.LAYOUTS or consumer_host_role not in {"floor", "newer"}
            or (target == "darwin-arm64" and consumer_host_role != "newer")):
        _fail("TARGET")
    _bundle, snapshot = load_bundle(bundle, repository=repository, expected_source=source)
    output = _output_path(output)
    handoff_path = validate_ancestry_not_symlink(raw_release_path)
    if (handoff_path.name != "raw_release.json" or handoff_path.parent.exists()
            or not handoff_path.parent.parent.is_dir()):
        _fail("HANDOFF_OUTPUT")
    descriptor = _descriptor(qualification_inputs, repository, inrun_root)
    handoff = consumer.materialize_universal_handoff(
        descriptor, handoff_path.parent, target=target,
        repository=repository, inrun_root=inrun_root)
    builder._write(handoff_path, canonical(handoff))
    result = consumer.consume_universal_wheel(
        Path(bundle) / "dist" / snapshot["wheel"]["filename"],
        builder._read(repository / RUNTIME_INPUTS, 65536)[0],
        builder._read(repository / DESCRIPTION, 262144)[0], handoff, work,
        target=target, source=source, run_id=run_id, run_attempt=run_attempt,
        repository=repository, consumer_host_role=consumer_host_role)
    builder._write(output, canonical(result))
    return result


def check_system_webkit_missing(bundle: Path, work: Path, output: Path, *, target: str,
                                expected_commit: str, run_id: str, run_attempt: str,
                                repository: Path) -> dict:
    from rs9.nebular070_universal_missing import check_missing_runtime
    source = _source(repository, expected_commit, require_clean=True)
    _hosted_context(source, run_id, run_attempt)
    _bundle, snapshot = load_bundle(bundle, repository=repository, expected_source=source)
    output = _output_path(output)
    result = check_missing_runtime(
        Path(bundle) / "dist" / snapshot["wheel"]["filename"], work,
        target=target, source=source, run_id=run_id, run_attempt=run_attempt,
        prefix=legacy.default_sandbox_prefix(target), snapshot=snapshot)
    builder._write(output, canonical(result))
    return result


def _receipt_file_set(receipts: Path, floors: Path) -> None:
    """Require the exact five consumer and two floor-refusal receipt files."""
    for root, targets, filenames in (
        (Path(receipts), set(builder.LAYOUTS), {"result.json"}),
        (Path(floors), set(LINUX_TARGETS), {"result.json", "missing-runtime.json"}),
    ):
        root = validate_ancestry_not_symlink(root)
        if not root.is_dir() or {path.name for path in root.iterdir()} != targets:
            _fail("MATRIX_FILES")
        for target in targets:
            directory = validate_ancestry_not_symlink(root / target)
            if not directory.is_dir() or {path.name for path in directory.iterdir()} != filenames:
                _fail("MATRIX_FILES")
            for filename in filenames:
                builder._read(directory / filename, 4 * 1024 * 1024)


def validate_matrix_receipts(snapshot: Mapping, captures: Mapping, positives: Mapping,
                             negatives: Mapping, *, source: Mapping,
                             run_id: str, run_attempt: str) -> dict:
    """Join all five new receipt domains to reauthenticated native input bytes."""
    from rs9.nebular070_universal_missing import validate_missing_runtime
    lanes = {(target, "newer") for target in builder.LAYOUTS} | {
        (target, "floor") for target in LINUX_TARGETS}
    if (not isinstance(captures, Mapping) or set(captures) != set(builder.LAYOUTS)
            or not isinstance(positives, Mapping) or set(positives) != lanes
            or not isinstance(negatives, Mapping) or set(negatives) != set(LINUX_TARGETS)):
        _fail("MATRIX_LANES")
    rows = []
    for target, role in sorted(lanes):
        value = consumer.validate_universal_consumer(
            positives[target, role], snapshot, captures[target], target=target, role=role,
            source=source, run_id=run_id, run_attempt=run_attempt)
        row = {"target": target, "role": role, "consumer_identity": value["identity"],
               "consumer_sha256": _sha(canonical(value)),
               "payload_sha256": captures[target]["payload_sha256"],
               "manifest_sha256": captures[target]["manifest_sha256"]}
        if role == "floor":
            negative = validate_missing_runtime(
                negatives[target], target=target, source=source, run_id=run_id,
                run_attempt=run_attempt, snapshot=snapshot,
                host_identity=value["host_observation"]["identity"])
            row["missing_runtime_identity"] = negative["identity"]
            row["missing_runtime_sha256"] = _sha(canonical(negative))
        rows.append(row)
    unsigned = {
        "schema": MATRIX_SCHEMA, "distribution": consumer.DISTRIBUTION,
        "version": builder.VERSION, "status": "passed", "source": dict(source),
        "run": {"id": run_id, "attempt": run_attempt}, "wheel": snapshot["wheel"],
        "runtime_inputs_sha256": snapshot["runtime_inputs_sha256"],
        "runtime_index_sha256": snapshot["runtime_index_sha256"], "lanes": rows,
        "native_qualified": True, "fixture_only": False, "publication_admitted": False,
        "public_writes": 0,
    }
    return {**unsigned, "identity": _sha(canonical(unsigned))}


def admit_matrix(bundle: Path, qualification_inputs: Path, inrun_root: Path,
                 receipts: Path, floor_receipts: Path, work: Path, output: Path, *,
                 expected_commit: str, run_id: str, run_attempt: str,
                 repository: Path) -> dict:
    """Read actual artifacts; static recapture never executes a native payload."""
    source = _source(repository, expected_commit, require_clean=True)
    _hosted_context(source, run_id, run_attempt)
    output = _output_path(output)
    result = read_matrix_inputs(
        bundle, qualification_inputs, inrun_root, receipts, floor_receipts, work,
        repository=repository, source=source, run_id=run_id, run_attempt=run_attempt)
    builder._write(output, canonical(result))
    return result


def read_matrix_inputs(bundle: Path, qualification_inputs: Path, inrun_root: Path,
                       receipts: Path, floor_receipts: Path, work: Path, *,
                       repository: Path, source: Mapping, run_id: str, run_attempt: str) -> dict:
    """Pure retained-evidence readback, also used by the two-checkout publisher.

    Unlike creation of hosted receipts, this operation observes no native host
    and executes no product. Its caller authenticates the run and source from
    GitHub APIs; every original receipt is revalidated against native bytes.
    """
    _bundle, snapshot = load_bundle(bundle, repository=repository, expected_source=dict(source))
    _receipt_file_set(receipts, floor_receipts)
    work = validate_ancestry_not_symlink(work)
    if work.exists() or work.is_symlink():
        _fail("MATRIX_WORK")
    work.mkdir(parents=True, mode=0o700)
    descriptor = _descriptor(qualification_inputs, repository, inrun_root)
    captures = {}
    for target in builder.LAYOUTS:
        handoff = consumer.materialize_universal_handoff(
            descriptor, work / target, target=target, repository=repository, inrun_root=inrun_root)
        captures[target] = consumer.capture_universal_runtime(
            snapshot, Path(handoff["root"]), handoff, target=target)
    def read(path):
        return strict_json(builder._read(path, 4 * 1024 * 1024)[0])
    positives = {(target, "newer"): read(Path(receipts) / target / "result.json")
                 for target in builder.LAYOUTS}
    positives.update({(target, "floor"): read(Path(floor_receipts) / target / "result.json")
                      for target in LINUX_TARGETS})
    negatives = {target: read(Path(floor_receipts) / target / "missing-runtime.json")
                 for target in LINUX_TARGETS}
    return validate_matrix_receipts(
        snapshot, captures, positives, negatives, source=source,
        run_id=run_id, run_attempt=run_attempt)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="operation", required=True)
    build = commands.add_parser("build-bundle")
    build.add_argument("--qualification-inputs", type=Path, required=True)
    build.add_argument("--inrun-root", type=Path, required=True)
    build.add_argument("--output", type=Path, required=True)
    build.add_argument("--expected-commit", required=True)
    build.add_argument("--require-clean", action="store_true")
    for name in ("qualify-native", "check-system-webkit-missing", "admit-matrix"):
        command = commands.add_parser(name)
        for field in ("bundle", "work", "output"):
            command.add_argument("--" + field, type=Path, required=True)
        for field in ("expected-commit", "run-id", "run-attempt"):
            command.add_argument("--" + field, required=True)
        if name == "check-system-webkit-missing":
            command.add_argument("--target", choices=LINUX_TARGETS, required=True)
        else:
            command.add_argument("--qualification-inputs", type=Path, required=True)
            command.add_argument("--inrun-root", type=Path, required=True)
            if name == "qualify-native":
                command.add_argument("--target", choices=tuple(builder.LAYOUTS), required=True)
                command.add_argument("--consumer-host-role", choices=("floor", "newer"), default="newer")
                command.add_argument("--raw-release", type=Path, required=True)
            else:
                command.add_argument("--receipts-dir", type=Path, required=True)
                command.add_argument("--floor-receipts", type=Path, required=True)
    return result


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    repository = Path.cwd()
    try:
        if args.operation == "build-bundle":
            value = build_bundle(args.qualification_inputs, args.inrun_root, args.output,
                                 repository=repository, expected_commit=args.expected_commit,
                                 require_clean=args.require_clean)
        else:
            options = dict(repository=repository, expected_commit=args.expected_commit,
                           run_id=args.run_id, run_attempt=args.run_attempt)
            if args.operation == "qualify-native":
                value = qualify_native(
                    args.bundle, args.work, args.output, target=args.target,
                    consumer_host_role=args.consumer_host_role, qualification_inputs=args.qualification_inputs,
                    inrun_root=args.inrun_root, raw_release_path=args.raw_release, **options)
            elif args.operation == "check-system-webkit-missing":
                value = check_system_webkit_missing(
                    args.bundle, args.work, args.output, target=args.target, **options)
            else:
                value = admit_matrix(
                    args.bundle, args.qualification_inputs, args.inrun_root, args.receipts_dir,
                    args.floor_receipts, args.work, args.output, **options)
        sys.stdout.buffer.write(canonical(value))
        return 0
    except (ContractError, AdmissionError) as error:
        sys.stderr.write(str(getattr(error, "code", "NEBULAR_UNIVERSAL_CONTRACT")) + "\n")
        return 1
    except (OSError, ValueError, TypeError, KeyError):
        sys.stderr.write("NEBULAR_UNIVERSAL_CONTRACT\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
