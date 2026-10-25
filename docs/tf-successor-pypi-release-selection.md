# Theme Forge Successor PyPI Release Selection

This document describes the closed release-selection contract for Theme Forge Python adapter distributions in Release Starport 9 (RS9).

## Closed Release Table and Immutable Defaults

RS9 admits only six exact `(project, version, distribution_version)` triples in `src/rs9/tf_pypi_model.py`:

| Project | Upstream npm Version | Python Distribution Version | Pin File (`operators/tf-pypi/`) | Description (`operators/tf-pypi/descriptions/`) | Role & Current Status |
| --- | --- | --- | --- | --- | --- |
| `theme-forge-stellar-burst` | `0.6.1` | `0.6.1.post1` | `theme-forge-stellar-burst.json` | `stellar-burst.md` | Default (`READY`) |
| `theme-forge-stellar-loom` | `0.4.0` | `0.4.0.post1` | `theme-forge-stellar-loom.json` | `stellar-loom.md` | Default (`READY`) |
| `theme-forge-solar-sail` | `0.2.1` | `0.2.1.post1` | `theme-forge-solar-sail.json` | `solar-sail.md` | Default (`READY`) |
| `theme-forge-stellar-burst` | `0.7.0` | `0.7.0` | `theme-forge-stellar-burst-0.7.0.json` | `stellar-burst-0.7.0.md` | Explicit opt-in (`BLOCKED`) |
| `theme-forge-stellar-loom` | `0.5.0` | `0.5.0` | `theme-forge-stellar-loom-0.5.0.json` | `stellar-loom-0.5.0.md` | Explicit opt-in (`BLOCKED`) |
| `theme-forge-solar-sail` | `0.3.0` | `0.3.0` | `theme-forge-solar-sail-0.3.0.json` | `solar-sail-0.3.0.md` | Explicit opt-in (`BLOCKED`) |

When `--pin` is omitted, `load_pin(project)` and all CLI operations retain the historical `.post1` defaults (`operators/tf-pypi/<project>.json`) and unversioned descriptions byte-for-byte. Arbitrary SemVer values, cross-version pairs, wrong-project bodies, symlinked pin files, duplicate JSON keys, and unlisted basenames fail closed before any operation writes or network calls.

## Opt-In CLI Usage

Select a versioned successor pin explicitly with `--pin`:

```sh
# Source-phase workflow inspection, intake, build, verify, or consumer smoke
python3 -B -m rs9.tf_pypi_workflow status \
  --project theme-forge-stellar-burst \
  --pin operators/tf-pypi/theme-forge-stellar-burst-0.7.0.json

python3 -B -m rs9.tf_pypi_workflow build \
  --project theme-forge-stellar-burst \
  --pin operators/tf-pypi/theme-forge-stellar-burst-0.7.0.json \
  --inputs path/to/inputs \
  --output dist

# Publisher build, workflow generation, select-missing, and readback
python3 -B -m rs9.tf_pypi_publish build \
  --project theme-forge-stellar-loom \
  --pin operators/tf-pypi/theme-forge-stellar-loom-0.5.0.json \
  --output dist

python3 -B -m rs9.tf_pypi_publish workflow \
  --project theme-forge-solar-sail \
  --pin operators/tf-pypi/theme-forge-solar-sail-0.3.0.json

# Hosted native qualification and three-host matrix admission
python3 -B -m rs9.tf_pypi_hosted qualify \
  --project theme-forge-stellar-burst \
  --pin operators/tf-pypi/theme-forge-stellar-burst-0.7.0.json \
  --target darwin-arm64 \
  --dist dist \
  --work work/tf-consumer \
  --report work/tf-consumer-report/result.json \
  --expected-commit "$QUALIFY_COMMIT" \
  --run-id "$QUALIFY_RUN_ID" \
  --run-attempt "$QUALIFY_RUN_ATTEMPT"

python3 -B -m rs9.tf_pypi_hosted admit \
  --project theme-forge-stellar-burst \
  --pin operators/tf-pypi/theme-forge-stellar-burst-0.7.0.json \
  --dist dist \
  --receipts receipts \
  --expected-commit "$QUALIFY_COMMIT" \
  --run-id "$QUALIFY_RUN_ID" \
  --run-attempt "$QUALIFY_RUN_ATTEMPT"
```

When `tf_pypi_publish workflow` is called with a successor pin, every generated job command (`build_verify`, the three native qualification jobs, `qualification_gate`, and `publish` `select-missing` / `readback`) emits the closed repository-relative selector `--pin operators/tf-pypi/<project>-<version>.json` derived from `RELEASES`, never the caller's operational filesystem path. The three registered workflows now contain these explicit successor selectors under their existing filenames (`rs9-tfsb-pypi-publish.yml`, `rs9-tfsl-pypi-publish.yml`, and `rs9-tfss-pypi-publish.yml`). Default CLI selection and historical pin files remain unchanged. Workflow registration alone admits no source, platform, artifact or publication.

## Blocked Status and Required Qualification Gates

All three successor pins (`0.7.0`, `0.5.0`, `0.3.0`) remain `source_status: "BLOCKED"` with `qualified_platforms: []` and non-empty `withheld` gate lists. While blocked, `verify_approved`, `select-missing`, and `readback` fail closed with `TF_PYPI_SOURCE_NOT_READY` before reading approval manifests, contacting PyPI, or creating an upload directory.

The following order describes future, separately evidenced transitions; this checkpoint changes none of the pin status, withheld, qualification or approval fields:

1. Verify source-release admission for the exact upstream archive, tag target/tree and lineage. The upstream `source_commit` is distinct from the checked-out RS9 commit recorded by hosted receipts.
2. After source admission, set that successor pin to `source_status: "READY"` and clear `withheld`, keeping `qualified_platforms: []`.
3. Build and verify the four-file aggregate (three wheels and one sdist) with the explicit versioned pin while its qualification list is empty.
4. Qualify the exact artifacts on all three native target hosts, then admit the same-run, first-attempt receipt matrix. These receipts remain qualification-only with `publication_admitted: false`.
5. Only after that evidence passes, record the exact candidate-platform list in `qualified_platforms`. `build_pin(pin)` clears this list in the embedded build pin, so this metadata-only transition preserves the aggregate bytes; it does not warrant a rebuild.
6. Admit the exact versioned artifact approval manifest and Trusted Publisher binding through their existing gates. The unchanged publish job requires `main`, explicit `workflow_dispatch` and `mode: publish`.
7. `select-missing` must recheck READY, exact qualifications, approval, same-run matrix and remote state; final readback must report `published-exact`.

READY/withheld fields must be settled before the final aggregate build because they remain embedded in the sdist. The normalization regression uses synthetic metadata and proves byte invariance only; it is not a native qualification receipt or permission to promote a real pin.

## Rollback

Successor pins/descriptions remain alongside historical defaults. Omitting `--pin` still selects the historical `.post1` releases and their unchanged descriptions/approvals. The registered workflow files now select successors explicitly; restoring their prior frozen bytes is the bounded workflow-routing rollback. This does not rewrite existing releases or change default CLI resolution. Failed or unqualified successor candidates remain withheld, and no approval or platform state is inferred from workflow registration.
