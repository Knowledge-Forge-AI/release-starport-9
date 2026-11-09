# Canonical pacman `any` import: fixed refusal diagnostics

This source checkpoint preserves every existing run, job, artifact, custody,
role and final-completion admission predicate. It changes only fixed values in
the existing `CANONICAL_ANY_RUN` diagnostic `substage` field.

The eleven new import-time fixed labels are `provider-run-json`, `provider-run-id`, `provider-run-attempt`,
`provider-run-source`, `provider-run-event`, `provider-run-branch`,
`provider-run-workflow`, `provider-run-repository`,
`provider-run-head-repository`, `provider-run-queued-null`, and
`provider-run-lifecycle`. Other existing refusal contexts remain unchanged.
The JSON label classifies existing decode/non-object
refusal without retaining the rejected bytes. The queued/null label is emitted only after all run
identity comparisons pass and the original active-run guard refuses an
explicit `queued` status with an explicitly present null conclusion. It still
refuses. All labels are untrusted comparison outcomes, not authority. No field
values, API bodies, raw output, private paths or credentials are retained.

The [preceding original campaign](https://github.com/Knowledge-Forge-AI/release-starport-9/actions/runs/42663002334)
refused before SDK acquisition with a generic provider-run label. Its original
API document was not retained; the native cause remains unproved. This distinct
diagnostic-retention class requires an owner decision before source adoption.

A fresh original campaign must be evaluated without combining evidence from
other attempts. If all required jobs pass, ordinary publication qualification
can continue. A separately prepared queued/null correction is held unless the
owner has approved that class and this diagnostic checkpoint records the
queued/null refusal in authenticated original native evidence. Any different
or unexplained result stops that conditional correction.

Final collection still requires completed-success evidence. No signing,
deployment, dependencies, permissions, timeouts or runtime profiles change.
Rollback restores the previous generic substage without deleting failed
evidence or claiming qualification.
