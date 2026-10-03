"""Command-line interface and entry point for .rs9 contract validation and normalization."""

from __future__ import annotations

import argparse
import sys
from typing import Sequence

from rs9.errors import ContractError
from rs9.normalizer import normalize
from rs9.validator import cross_validate, load_destinations, load_project

__all__ = [
    "ContractError",
    "load_destinations",
    "load_project",
    "main",
    "normalize",
]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m rs9.contract",
        description=".rs9 v1alpha1 contract validator and normalizer",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # validate PROJECT [--destinations FILE]
    validate_parser = subparsers.add_parser(
        "validate",
        help="Validate .rs9 project configuration",
    )
    validate_parser.add_argument("project", help="Path to selected project root containing .rs9")
    validate_parser.add_argument(
        "--destinations",
        dest="destinations",
        default=None,
        help="Optional path to destinations configuration file",
    )

    # normalize PROJECT --destinations FILE --version VERSION
    normalize_parser = subparsers.add_parser(
        "normalize",
        help="Normalize .rs9 project configuration to canonical JSON bytes",
    )
    normalize_parser.add_argument("project", help="Path to selected project root containing .rs9")
    normalize_parser.add_argument(
        "--destinations",
        dest="destinations",
        required=True,
        help="Path to destinations configuration file",
    )
    normalize_parser.add_argument(
        "--version",
        dest="version",
        required=True,
        help="Release version string",
    )

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "validate":
            project_map = load_project(args.project)
            if args.destinations:
                destinations_doc = load_destinations(args.destinations)
                cross_validate(project_map, destinations_doc)
            return 0

        if args.command == "normalize":
            json_bytes = normalize(
                project_dir=args.project,
                destinations_path=args.destinations,
                version=args.version,
            )
            sys.stdout.buffer.write(json_bytes)
            sys.stdout.buffer.flush()
            return 0

    except ContractError as err:
        sys.stderr.write(f"Error: {err}\n")
        return 1
    except Exception as err:
        sys.stderr.write(f"Unexpected error: {type(err).__name__}\n")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
