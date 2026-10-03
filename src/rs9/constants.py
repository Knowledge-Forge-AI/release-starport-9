"""Constants for the .rs9 v1alpha1 contract specification."""

from __future__ import annotations

# Schemas
SCHEMA_PROJECT = "rs9.project.v1alpha1"
SCHEMA_RELEASES = "rs9.releases.v1alpha1"
SCHEMA_DESTINATIONS = "rs9.destinations.v1alpha1"
SCHEMA_NORMALIZED = "rs9.normalized-tenant.v1alpha1"

def adapter_schema(adapter: str) -> str:
    return f"rs9.{adapter}.v1alpha1"

# Adapters
ADAPTER_NAMES = frozenset({
    "npm",
    "pypi",
    "nix",
    "homebrew",
    "pacman",
    "dnf",
    "apt",
})

# Allowed filenames inside the .rs9/ directory
ALLOWED_PROJECT_FILES = frozenset({
    "project.toml",
    "releases.toml",
    "npm.toml",
    "pypi.toml",
    "nix.toml",
    "homebrew.toml",
    "pacman.toml",
    "dnf.toml",
    "apt.toml",
})

# Concrete canonical platforms
CANONICAL_CONCRETE_PLATFORMS = frozenset({
    "x86_64-linux",
    "aarch64-linux",
    "x86_64-darwin",
    "aarch64-darwin",
})

LINUX_PLATFORMS = frozenset({
    "x86_64-linux",
    "aarch64-linux",
})

DARWIN_PLATFORMS = frozenset({
    "x86_64-darwin",
    "aarch64-darwin",
})

# Publication modes
VALID_MODES = frozenset({
    "direct",
    "projection",
    "contribution",
})

# Destination statuses
VALID_DESTINATION_STATUSES = frozenset({
    "illustrative",
    "candidate",
    "live",
})

# Release prerelease policies
VALID_PRERELEASE_OPTIONS = frozenset({
    "reject",
    "allow",
})

# Asset formats
VALID_ASSET_FORMATS = frozenset({
    "tar.gz",
    "npm-tarball",
    "wheel",
    "sdist",
})

# Command interfaces
VALID_COMMAND_INTERFACES = frozenset({
    "cli",
    "gui",
})

# Runtime kinds
VALID_RUNTIME_KINDS = frozenset({
    "native",
    "node",
    "python",
})

# License source
REQUIRED_LICENSE_SOURCE = "tagged-repository"
