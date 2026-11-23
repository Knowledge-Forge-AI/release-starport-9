# Canonical pacman `any` import: provider-run state policy

The native ARM lane reuses the original x86_64 Loom and Solar packages. It does
not gain construction authority for either package. Provider admission binds the
same repository and head repository, run ID, original attempt 1, exact source
commit, push event, main branch and workflow path.

For import-time admission, aggregate run status may be `in_progress` or `queued`,
with an explicitly present null conclusion. Missing or non-null conclusions and
all other aggregate states refuse. This does not establish job liveness: the
immediately following admission still requires exactly one original x86_64
constructor with successful executed lane/upload steps and exactly one active
native ARM importer with a null conclusion, correct runner labels and source,
and the required sequencing. Artifact identity, exact-byte custody, witness and
role checks follow unchanged. Final collection still requires completed-success
evidence; no failed or partial original run can qualify.

`CANONICAL_ANY_RUN` remains the public refusal code. Import-time decoding and
comparison use eleven new fixed values in its existing `substage` field:
`provider-run-json`, `provider-run-id`, `provider-run-attempt`,
`provider-run-source`, `provider-run-event`, `provider-run-branch`,
`provider-run-workflow`, `provider-run-repository`,
`provider-run-head-repository`, `provider-run-lifecycle`, or
`provider-run-conclusion`. Other existing refusal contexts remain unchanged.
These are untrusted comparison outcomes, not evidence
of authority or successful qualification. They reveal coarse public-provider
input validity, without retaining field values, API bodies, raw output, private
paths or credentials. An existing generic field carries the label; no diagnostic
schema, permissions, timeout, dependency or runtime profile is added.

The preceding [original campaign](https://github.com/Knowledge-Forge-AI/release-starport-9/actions/runs/42663002334)
refused before SDK acquisition with `CANONICAL_ANY_RUN/provider-run`. Its past API
document was not retained, so the precise native cause remains unproved. A later
readback passed the old guard. The queued/null case is reproduced synthetically;
the correction must therefore be qualified as a corrective/diagnostic successor,
not described as an established native fix.

Source adoption requires an explicit owner decision for this admission and
diagnostic class. This extension remains held unless the approved diagnostic
checkpoint records `provider-run-queued-null` in authenticated original native
evidence with the expected source/run identity. A later live replay is not
sufficient. A different or unexplained result stops this conditional extension.
After adoption, both full hosted unit gates and all fifteen
jobs of one fresh original current-distribution campaign must pass independently
before downstream signing. No automatic retry, evidence stitching, production
signing or deployment follows from local checks. Existing key and environment
protections remain in force.

Rollback removes this extension and restores the preceding diagnostic phase's
strict lifecycle admission. It preserves all failed receipts and does not claim
that the earlier campaign qualified.
