# RS9 documentation

Release Starport 9 is organized around a small number of stable contracts:

- [Architecture](architecture.md) — control-plane responsibilities, publication modes, and trust boundaries.
- [Project contract](project-contract.md) — the intended `.rs9/*.toml` interface between a project and RS9.
- [v1alpha1 specification](specs/rs9-config-v1alpha1.md) — implemented validator subset.
- [Tenant decision](adr/0001-tenant-contract-v1alpha1.md) and
  [release authority decision](adr/0002-github-release-sole-ingestion-authority.md).
- [Extraction inventory](architecture/theme-forge-extraction-inventory.md),
  [adapter/destination boundary](architecture/adapter-destination-model.md), and
  [migration map](architecture/migration-map.md).
- [Project/ecosystem install index](install/README.md) — routes to current authorities.
- [Foundation disposition and qualification](foundation1-candidate.md) — bounded phase record.
- [Foundation 2 candidate](foundation2-candidate.md),
  [Nebular shadow design](architecture/nebular-shadow-projection.md),
  [qualification](foundation2-qualification.md), and
  [ingestion decision](adr/0003-authenticated-ingestion-and-shadow-adapters.md).
- [Input record](specs/rs9-ingestion-record-v1alpha1.md) and
  [Linux dependency evidence](specs/rs9-dependency-evidence-v1alpha1.md).

Ecosystem-specific operator and adapter documentation will be added as the corresponding adapters are adopted.
