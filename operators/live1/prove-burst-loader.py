#!/usr/bin/env python3
"""Execute real released Stellar Burst loader proof and record authenticated evidence."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from rs9.burst_loader_proof import prove_burst_loader
from rs9.errors import ContractError


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "evidence/live1/burst-loader-darwin-arm64.json",
        help="Path for output evidence JSON record",
    )
    parser.add_argument(
        "--system",
        default="aarch64-darwin",
        help="Target platform system triple (default: aarch64-darwin)",
    )
    parser.add_argument(
        "--capture-dir",
        type=Path,
        default=None,
        help="Optional local capture directory to use instead of network discovery",
    )
    parser.add_argument(
        "--scratch-root",
        type=Path,
        default=None,
        help="Optional base scratch directory (defaults to the configured shared scratch root)",
    )

    args = parser.parse_args(argv)

    try:
        evidence = prove_burst_loader(
            system=args.system,
            capture_dir=args.capture_dir,
            scratch_root=args.scratch_root,
            output_evidence=args.output,
        )
        print("Burst loader proof completed successfully.")
        print(f"System: {evidence['system']}")
        print(f"Status: {evidence['status']}")
        print(f"Target Addon: {evidence['target_prebuild']['key']} ({evidence['target_prebuild']['architecture']})")
        print(f"Addon SHA256: {evidence['target_prebuild']['sha256']}")
        print(f"Loader SHA256: {evidence['loader_contract']['sha256']}")
        print(f"Observed Node: {evidence['observed_load_receipt']['node_version']} (ABI: {evidence['observed_load_receipt']['node_abi']})")
        print(f"Wheel SHA256: {evidence['wheel_artifact']['sha256']}")
        print("Authenticated evidence written.")
        return 0
    except ContractError as exc:
        print(f"Burst loader proof failed: {exc.code}", file=sys.stderr)
        return 1
    except Exception:
        print("Burst loader proof failed: unavailable", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
