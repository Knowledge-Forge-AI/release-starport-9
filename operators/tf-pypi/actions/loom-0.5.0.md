# Loom-owned Actions artifact qualification

This finite route selects Loom0.5.0 CI run40222221851/attempt1 and the exact three artifacts recorded in actions-inputs/loom-0.5.0-ci.json. The upstream package is272836 bytes with SHA2564e7a7d436c09ba111f5dca8101876c6e085ad15859d96bab8f728c5669880b5f, bound to merged source fca7db68bbf62ee7c9d53a72993b7fc6bda789f5. The pin remains BLOCKED with no qualified platforms.

After this source is independently reviewed, accepted and publicly committed, render with that actual full RS9 commit:

```sh
PYTHONPATH=src python3 -B -m rs9.tf_pypi_loom_actions_workflow --rs9-commit "$ACCEPTED_RS9_COMMIT"
```

Review and adopt output as Loom's .github/workflows/rs9-tfsl-pypi-actions-qualify.yml. It runs only in Knowledge-Forge-AI/theme-forge-stellar-loom; its own Actions-read job token authenticates the selected Loom ZIPs. It checks out exact RS9 tooling in every job; native receipts name that tooling commit and the real Loom caller run ID/attempt. The required workflow_dispatch input is dispatch_id. No generated executable workflow with a synthetic or older tooling commit is retained here.

The build job calls tf_pypi_loom_actions_intake into fresh transport, then tf_pypi_publish build with the explicit Loom0.5 pin and --inputs transport/inputs. Three unchanged native renderers consume the same-run aggregate on Darwin ARM64, Linux ARM64 GNU and Linux x64 GNU under maintained network isolation. The matrix admits all three first-attempt receipts. Solar's adapter, selector, renderer and default invocation remain unchanged. Neither route publishes or marks READY.

The adapter has no URL, run, product or arbitrary selector override. Metadata, merged PR/tree lineage, exact selected ZIP and member hashes, complete35-row aggregate, package SRI and package intake all fail closed on substitution or expiration. The redirect host is the exact observed productionresultssa5.blob.core.windows.net; token forwarding stops after the API request. A changed/expired upstream artifact requires new reviewed evidence, not retrying another version or broadening the host rule.

Native qualification and publication remain future gates. READY/withheld metadata changes affect the final aggregate and require corresponding requalification. Only qualified_platforms normalization has the maintained byte-invariance contract. Failed runs and historical default pins remain intact.
