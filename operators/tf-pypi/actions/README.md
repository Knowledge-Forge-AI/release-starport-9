# Solar-owned qualification workflow

The generated workflow belongs in the Solar repository, not RS9: its GitHub job token needs Actions read access to the selected Solar artifact ZIPs. Public artifact metadata access alone does not grant ZIP download authority.

After the RS9 source is publicly accepted and committed, render with the exact accepted full commit:

```sh
python3 -B -m rs9.tf_pypi_actions_workflow --rs9-commit "$ACCEPTED_RS9_COMMIT"
```

Review and commit that output as a Solar `.github/workflows` file, then use its attended `workflow_dispatch` correlation input. The renderer refuses missing, abbreviated or malformed commit selectors. The operator supplies an actually accepted public commit; syntax validation cannot itself attest acceptance. No generated executable workflow with a placeholder or self-referential source commit is retained in RS9.

All five jobs explicitly check out the RS9 repository at the selected commit into the workspace root, with credentials persistence disabled. Jobs refuse execution outside the Solar repository. The three native jobs and matrix gate bind `--expected-commit` to RS9 source identity; run ID and attempt remain the real Solar workflow execution. The transport receipt independently authenticates the earlier selected Solar CI run and package. These identities must not be conflated.

Only the build/intake job needs Actions read permission for Solar ZIP downloads. No new credential, reusable workflow API, publisher/OIDC job, dependency or release bypass is introduced. Existing native platform checks, OS network isolation, wheel/sdist consumer checks, same-run receipt admission and independent publication gates remain unchanged. Generated workflow review, actual dispatch and native qualification are still required; rendering earns none of them.
