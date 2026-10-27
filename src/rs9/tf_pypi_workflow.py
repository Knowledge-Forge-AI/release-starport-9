"""Source-phase operator: intake, local candidate build/verify/smoke, read-only state.

There is no publication command and no runnable first-wave publishing workflow.
"""
import argparse
from pathlib import Path
import sys

from rs9.tf_pypi_archive import AdmissionError, canonical, fail
from rs9.tf_pypi_backend import build_aggregate
from rs9.tf_pypi_closure import dependencies_for_pin, load_dependencies
from rs9.tf_pypi_consumer import smoke
from rs9.tf_pypi_intake import fetch
from rs9.tf_pypi_model import PRODUCTS, intake, load_pin, logical_identity
from rs9.tf_pypi_platform import host_key
from rs9.tf_pypi_remote import project_state
from rs9.tf_pypi_verify import host_view, verify_aggregate


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    sub = result.add_subparsers(dest="operation", required=True)
    for operation in ("fetch", "intake", "build", "verify", "consumer", "status"):
        command = sub.add_parser(operation)
        command.add_argument("--project", choices=sorted(PRODUCTS), required=True)
        command.add_argument("--pin", type=Path, default=None)
        if operation in {"intake", "build"}:
            command.add_argument("--inputs", type=Path, required=True)
        if operation in {"fetch", "build"}:
            command.add_argument("--output", type=Path, required=True)
        if operation in {"verify", "consumer"}:
            command.add_argument("--dist", type=Path, required=True)
        if operation == "consumer":
            command.add_argument("--work", type=Path, required=True)
            command.add_argument("--offline-linux", action="store_true")
        if operation == "status":
            command.add_argument("--remote", action="store_true")
    return result


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        pin = load_pin(args.project, args.pin)
        operation = args.operation
        if operation == "status":
            remote = project_state(pin) if args.remote else "not-read"
            result = {"project": pin["project"], "version": pin["distribution_version"],
                      "upstream_version": pin["version"], "source": pin["source_status"],
                      "reasons": pin["withheld"], "remote": remote, "publication_admitted": False}
            sys.stdout.buffer.write(canonical(result))
            return 1 if remote in {"unknown", "conflict", "present-unverified"} else 0
        if operation == "fetch":
            result = fetch(pin, args.output)
        elif operation in {"intake", "build"}:
            data, files = intake(pin, args.inputs / pin["asset"])
            result = {"project": pin["project"], "payload_identity": logical_identity(files),
                      "source": "BLOCKED", "publication_admitted": False}
            if operation == "build":
                dependencies = (load_dependencies(args.inputs, dependencies_for_pin(pin))
                                if pin["project"] == "theme-forge-stellar-burst" else {})
                build_aggregate(pin, data, args.output, dependencies)
                result = verify_aggregate(pin, args.output)
        elif operation == "verify":
            result = verify_aggregate(pin, args.dist)
        else:
            work_root = Path(args.work)
            if work_root.exists() or work_root.is_symlink():
                fail("CONSUMER_WORK_DIR")
            view_dir = work_root / "view"
            host_view(pin, args.dist, host_key(), view_dir)
            result = smoke(pin, view_dir, work_root / "consumer", offline_linux=args.offline_linux)
        sys.stdout.buffer.write(canonical(result))
        return 0
    except AdmissionError as error:
        sys.stderr.write(error.code + "\n")
    except (OSError, ValueError, KeyError, RuntimeError):
        sys.stderr.write("TF_PYPI_OPERATION_FAILED\n")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
