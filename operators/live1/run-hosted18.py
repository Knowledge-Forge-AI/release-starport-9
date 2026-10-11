#!/usr/bin/env python3
"""Attended run 18; invoke only after exact external manager acceptance."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import attended_run as shared

DEFAULT_COMMIT_MESSAGE = "Retain bounded D-Bus and signal diagnostics for run 18"


def main(argv=None):
    return shared.main(argv, root=ROOT, run_label="run18", commit_message=DEFAULT_COMMIT_MESSAGE)


if __name__ == "__main__":
    raise SystemExit(main())
