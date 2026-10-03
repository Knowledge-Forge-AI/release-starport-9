# Foundation 2 candidate path inventory

Status: bounded terminal source candidate. This is the exact changed-path
allowlist for manager adoption after terminal review disposition and verification.
No staging is performed by this phase. Blob and SHA256 identities plus the full
candidate tree are bound in the external candidate inventory returned at handoff.

Exclude `.serena/**`, scratch, worker metadata, downloads, icons, package binaries
and bytecode. Historical Foundation 1 evidence and governance files are unchanged.

Changed paths: 72.

```text
README.md
docs/README.md
docs/adr/0001-tenant-contract-v1alpha1.md
docs/adr/0002-github-release-sole-ingestion-authority.md
docs/adr/0003-authenticated-ingestion-and-shadow-adapters.md
docs/architecture.md
docs/architecture/adapter-destination-model.md
docs/architecture/migration-map.md
docs/architecture/nebular-shadow-projection.md
docs/architecture/theme-forge-extraction-inventory.md
docs/foundation2-candidate.md
docs/foundation2-inventory.md
docs/foundation2-qualification.md
docs/install/README.md
docs/project-contract.md
docs/specs/rs9-config-v1alpha1.md
docs/specs/rs9-dependency-evidence-v1alpha1.md
docs/specs/rs9-ingestion-record-v1alpha1.md
examples/README.md
examples/destinations.example.toml
examples/theme-forge/theme-forge-nebular-fusion/.rs9/project.toml
examples/theme-forge/theme-forge-nebular-fusion/.rs9/releases.toml
src/rs9/archives.py
src/rs9/compare.py
src/rs9/cross_validator.py
src/rs9/dependencies.py
src/rs9/destinations.py
src/rs9/elf.py
src/rs9/fetch.py
src/rs9/github.py
src/rs9/ingestion.py
src/rs9/normalizer.py
src/rs9/project.py
src/rs9/releases.py
src/rs9/render.py
src/rs9/scratch.py
src/rs9/security.py
src/rs9/shadow.py
tests/elf_builder.py
tests/fixtures/nebular-0.6.1/comparison-classification.json
tests/fixtures/nebular-0.6.1/comparison.json
tests/fixtures/nebular-0.6.1/dependency-evidence.json
tests/fixtures/nebular-0.6.1/ingestion.json
tests/fixtures/nebular-0.6.1/live-observations.json
tests/fixtures/nebular-0.6.1/qualification-readback.json
tests/fixtures/nebular-0.6.1/reference-byte-comparison.json
tests/fixtures/nebular-0.6.1/reference-facts.json
tests/golden/shadow/nebular-0.6.1/README.md
tests/golden/shadow/nebular-0.6.1/aur/theme-forge-nebular-fusion-bin/.SRCINFO
tests/golden/shadow/nebular-0.6.1/aur/theme-forge-nebular-fusion-bin/PKGBUILD
tests/golden/shadow/nebular-0.6.1/aur/theme-forge-nebular-fusion-bin/theme-forge-nebular-fusion.desktop
tests/golden/shadow/nebular-0.6.1/nix/theme-forge-nebular-fusion.desktop
tests/golden/shadow/nebular-0.6.1/nix/theme-forge-nebular-fusion.nix
tests/golden/shadow/nebular-0.6.1/pacman/theme-forge-nebular-fusion/PKGBUILD
tests/golden/shadow/nebular-0.6.1/pacman/theme-forge-nebular-fusion/theme-forge-nebular-fusion.desktop
tests/golden/shadow/nebular-0.6.1/render-manifest.json
tests/golden/shadow/nebular-0.6.1/rpm/theme-forge-nebular-fusion.desktop
tests/golden/shadow/nebular-0.6.1/rpm/theme-forge-nebular-fusion.spec
tests/golden/theme-forge-nebular-fusion.normalized.json
tests/shadow_fixtures.py
tests/test_archives.py
tests/test_dependencies.py
tests/test_elf.py
tests/test_fetch.py
tests/test_github.py
tests/test_hygiene.py
tests/test_ingestion.py
tests/test_live_nebular.py
tests/test_reference_comparison.py
tests/test_render.py
tests/test_shadow_cli.py
tests/test_shadow_contract.py
```
