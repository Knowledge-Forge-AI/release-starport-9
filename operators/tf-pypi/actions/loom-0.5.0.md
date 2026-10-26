# Loom-owned Actions artifact qualification

This finite route selects the terminal regular Loom 0.5.0 CI run 40238216121, attempt 1, for PR 6 and the exact three artifacts recorded in `actions-inputs/loom-0.5.0-ci.json`. The upstream package is 272836 bytes with SHA256 `4e7a7d436c09ba111f5dca8101876c6e085ad15859d96bab8f728c5669880b5f`, bound to current merged source `9063fe5d283881f464ab566d8b74296a6ce1b688` (tree `9ac1906d36baff63fd3e28f49d50ce2e0e07ee04`). This current source is published on GitHub. The versioned Loom pin is READY for source admission with `qualified_platforms: []`; `PYPI_RELEASE_MANIFEST_PENDING`, `PYPI_CONSUMER_MATRIX_PENDING` and `PYPI_WHEEL_ARTIFACT_RECEIPTS_PENDING` remain withheld. This records current GitHub source/package provenance only: it does not publish to a registry, qualify a platform or mutate readiness.

After this source is independently reviewed, accepted and publicly committed, render with that actual full RS9 commit:

```sh
PYTHONPATH=src python3 -B -m rs9.tf_pypi_loom_actions_workflow --rs9-commit "$ACCEPTED_RS9_COMMIT"
```

Review and adopt output as Loom's .github/workflows/rs9-tfsl-pypi-actions-qualify.yml. It runs only in Knowledge-Forge-AI/theme-forge-stellar-loom; its own Actions-read job token authenticates the selected Loom ZIPs. It checks out exact RS9 tooling in every job; native receipts name that tooling commit and the real Loom caller run ID/attempt. The required workflow_dispatch input is dispatch_id. No generated executable workflow with a synthetic or older tooling commit is retained here.

The build job calls tf_pypi_loom_actions_intake into fresh transport, then tf_pypi_publish build with the explicit Loom 0.5.0 pin and --inputs transport/inputs. Three unchanged native renderers consume the same-run aggregate on Darwin ARM64, Linux ARM64 GNU and Linux x64 GNU under maintained network isolation. The matrix admits all three first-attempt receipts. The Loom route leaves Solar's workflow renderer and default invocation unchanged. Neither route publishes, qualifies a platform or mutates the READY/withheld pin metadata.

The adapter has no URL, run, product or arbitrary selector override. Metadata, merged PR/tree lineage, exact selected ZIP and member hashes, complete 35-row aggregate, package SRI and package intake all fail closed on substitution or expiration. The redirect host is the exact observed `productionresultssa9.blob.core.windows.net`; token forwarding stops after the API request. A changed/expired upstream artifact requires new reviewed evidence, not retrying another version or broadening the host rule.

Native qualification and publication remain future gates. READY/withheld metadata changes affect the final aggregate and require corresponding requalification. Only qualified_platforms normalization has the maintained byte-invariance contract. Failed runs, historical default pins and separate three-platform evidence remain intact.
