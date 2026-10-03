"""Explicit scratch-only CLI; saved ingestion JSON is evidence, never authority."""
import argparse
import json
import sys
from pathlib import Path

from rs9.contract import normalize
from rs9.dependencies import derive_dependencies
from rs9.errors import ContractError
from rs9.fetch import fetch
from rs9.ingestion import authenticate_shadow as authenticate
from rs9.render import render
from rs9.scratch import ConfinedWriter, canonical


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("fetch", "authenticate", "dependencies", "render"))
    parser.add_argument("project")
    parser.add_argument("--destinations", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--evidence")
    parser.add_argument("--output", required=True, help="Existing empty physical directory")
    parser.add_argument("--revision", type=int, default=1)
    args = parser.parse_args(argv)
    try:
        normalized = json.loads(normalize(args.project, args.destinations, args.version))
        if args.operation == "fetch":
            fetch(normalized, args.output)
        else:
            if not args.evidence:
                parser.error("--evidence is required for offline byte authentication")
            authenticated = authenticate(normalized, args.evidence)
            if args.operation == "render":
                render(authenticated, args.output, revision=args.revision)
            else:
                record = authenticated.record if args.operation == "authenticate" else derive_dependencies(authenticated)
                filename = "ingestion.json" if args.operation == "authenticate" else "dependency-evidence.json"
                with ConfinedWriter(args.output) as writer:
                    writer.write(filename, canonical(record))
        return 0
    except ContractError as error:
        print("Error: [" + error.code + "] " + error.message, file=sys.stderr)
        return 2
    except (KeyError, ValueError, TypeError, OSError):
        print("Error: [INVALID_EVIDENCE] Malformed or unavailable shadow input", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
