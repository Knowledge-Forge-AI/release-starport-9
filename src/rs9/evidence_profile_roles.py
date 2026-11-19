"""Closed evidence-role vocabulary shared by offline intent and authentication.

Keep import-free: contract validation must not import historical collectors or
native publication tools merely to validate a declared profile's role names.
"""

TAURI_PROFILE = "tauri-desktop-archive.v1alpha1"
TAURI_AUTHORITY_PROFILE = "tauri-desktop-archive.v1alpha2"
PACKAGE_PROFILE = "npm-package-archive.v1alpha1"
CURRENT_PACKAGE_PROFILE = "npm-root-receipt-archive.v1alpha1"

PROFILE_ROLES = {
    TAURI_PROFILE: {"provenance", "sbom-spdx", "third-party-notices", "npm-wrapper"},
    PACKAGE_PROFILE: {"provenance", "notice"},
    CURRENT_PACKAGE_PROFILE: {"root-package-receipt"},
}
PROFILE_ROLES[TAURI_AUTHORITY_PROFILE] = PROFILE_ROLES[TAURI_PROFILE]
