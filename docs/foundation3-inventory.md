# Foundation 3 exact changed-file inventory

Status: terminal candidate product inventory. The following 52 paths comprise the cumulative product delta. Closeout amended six of these paths, listed in the candidate report; no path was added or removed from this inventory. Operator state, scratch, bytecode and dispatcher metadata are excluded and remain unstaged by the provider.

| Path | Change |
|---|---|
| `docs/README.md` | modified |
| `docs/adr/0003-authenticated-ingestion-and-shadow-adapters.md` | modified |
| `docs/adr/0004-ingestion-core-and-evidence-profiles.md` | new |
| `docs/adr/0005-publication-state-planner-and-receipts.md` | new |
| `docs/architecture.md` | modified |
| `docs/architecture/adapter-destination-model.md` | modified |
| `docs/architecture/migration-map.md` | modified |
| `docs/foundation3-candidate.md` | new |
| `docs/foundation3-inventory.md` | new |
| `docs/project-contract.md` | modified |
| `docs/specs/rs9-config-v1alpha1.md` | modified |
| `docs/specs/rs9-destination-observation-v1alpha1.md` | new |
| `docs/specs/rs9-ingestion-record-v1alpha1.md` | modified |
| `docs/specs/rs9-publication-plan-v1alpha1.md` | new |
| `docs/specs/rs9-publication-receipt-v1alpha1.md` | new |
| `docs/specs/rs9-release-record-v1alpha1.md` | new |
| `docs/specs/rs9-retry-idempotence-v1alpha1.md` | new |
| `examples/theme-forge/theme-forge-nebular-fusion/.rs9/releases.toml` | modified |
| `src/rs9/archives.py` | modified |
| `src/rs9/fetch.py` | modified |
| `src/rs9/gates.py` | new |
| `src/rs9/github.py` | modified |
| `src/rs9/ingestion.py` | modified |
| `src/rs9/normalizer.py` | modified |
| `src/rs9/observation.py` | new |
| `src/rs9/planner.py` | new |
| `src/rs9/profiles.py` | new |
| `src/rs9/publication.py` | new |
| `src/rs9/records.py` | new |
| `src/rs9/release_core.py` | new |
| `src/rs9/releases.py` | modified |
| `tests/fixtures/stellar-burst-0.6.1/live-observations.json` | new |
| `tests/fixtures/stellar-burst-0.6.1/profile-result.json` | new |
| `tests/fixtures/stellar-burst-0.6.1/release-record.json` | new |
| `tests/fixtures/stellar-burst-0.6.1/selection.json` | new |
| `tests/golden/shadow/nebular-0.6.1/render-manifest.json` | modified |
| `tests/golden/theme-forge-nebular-fusion.normalized.json` | modified |
| `tests/publication_fixtures.py` | new |
| `tests/release_fixtures.py` | new |
| `tests/shadow_fixtures.py` | modified |
| `tests/test_archive_hardlinks.py` | new |
| `tests/test_archives.py` | modified |
| `tests/test_contract.py` | modified |
| `tests/test_gates.py` | new |
| `tests/test_github.py` | modified |
| `tests/test_live_nebular.py` | modified |
| `tests/test_live_stellar_burst.py` | new |
| `tests/test_observation.py` | new |
| `tests/test_planner.py` | new |
| `tests/test_profiles.py` | new |
| `tests/test_publication.py` | new |
| `tests/test_release_core.py` | new |

No dependency, lockfile, package metadata or test-runner policy changes are present. No release payload binary is included. Retained Nebular ingestion/dependency records and recipe/desktop bytes are unchanged; only the render manifest normalized input hash changes.

See the [candidate and verification report](foundation3-candidate.md).
