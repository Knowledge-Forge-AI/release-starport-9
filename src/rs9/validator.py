"""Validation facade re-exporting project, destination, and cross validation."""

from __future__ import annotations

from rs9.cross_validator import cross_validate
from rs9.destinations import load_destinations
from rs9.project import find_rs9_dir, load_project

__all__ = [
    "cross_validate",
    "find_rs9_dir",
    "load_destinations",
    "load_project",
]
