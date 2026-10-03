# APGR v0.13.0 onboarding readiness

Status: next-cycle preparation only; no APGR files or release are changed in LIVE1.

Before the GitHub release is cut, the tagged source should contain project-owned
`.rs9/project.toml`, `.rs9/releases.toml` and each requested adapter file. Declare
repository/project identity, version/tag rules, license expression and authoritative
license/notice files, commands and truthful runtime checks, exact payload asset
selection/platforms, and the evidence profile/checksum/provenance roles.

The release should attach exact installable payloads, `SHA256SUMS` covering them,
`PROVENANCE.json` binding repository/tag/commit/tree and `NOTICE`. Include exact
wheel/sdist assets if RS9 should upload existing Python distributions; do not make
RS9 infer an uncontrolled source build. A suitable reviewed Python-distribution
evidence profile is still required. Enable immutable GitHub releases where possible.

APGR's release pipeline ends at its public GitHub Release. RS9 then authenticates
those assets/configuration, qualifies downstream artifacts and owns publication.
The Theme Forge bootstrap exception does not apply. Existing APGR Homebrew
projection requires a separate adoption decision. Do not start APGR publication
until Theme Forge LIVE1 is accepted.
