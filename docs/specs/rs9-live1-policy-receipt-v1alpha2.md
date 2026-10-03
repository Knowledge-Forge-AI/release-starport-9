# LIVE1 destination policy and receipt v1alpha2

Status: implemented contract changes; production transports disabled.

`rs9.destination-policy.v1alpha2` adds `mode=publish|observe-only`. npm and
Homebrew are constrained to observe-only. Exact produces noop; conflict produces
block-conflict; unknown/unreachable defers; absent or incomplete blocks. An exact
observation bypasses mutation qualification because no transport is authorized.
There is no checksum-only shortcut to semantic identity.

Adapter mandatory gates are added to `required_gates` and cannot be waived by
`allow_not_applicable`. Rendered manifests never establish `package.render` pass.
Qualification is independently executed and bound as specified in the
[qualification contract](rs9-qualification-record-v1alpha1.md).

Policies serialized as v1alpha1 are rejected by the current validator. Their
historical bytes remain evidence. Explicit migration creates a v1alpha2 policy
and requires fresh observation and planning. Plan and attempt schemas retain
v1alpha1 shapes; hashes change when their bound policy changes.

`rs9.publication-receipt.v1alpha2` adds final state `simulated`. Published requires
an exact post-observation, an actual confirmed/ambiguous non-synthetic attempt,
valid ordering proof, a fresh sealed in-process plan and a sealed observation from
an implemented live reader. Writing `source=live-read` into JSON is insufficient.
PyPI JSON/file readback is implemented; other production readers remain pending.
Every wheel must provide the bound semantic provenance, the registry inventory
must match exactly, and license/name/version/file digests are checked.

Serializing a plan or live observation removes its capability. Stored attempts
and receipt graphs remain structurally auditable. A persisted published claim
cannot mint another published receipt or authorize new transport. Restart retains
attempt history, reads the destination again and re-plans before any mutation.
Synthetic fixtures now report simulated where v1alpha1 tests reported published.
Historical v1alpha1 receipts are not implicitly replayed as v1alpha2 authority.

Ordering rules retain the Foundation 3 hierarchy: remote sequence, changed
response identity, then documented timestamp fallback. PyPI uses `last_serial`
when an upload supplies a corroborated resulting serial; Pages must use a fresh
timestamp fallback unless its transport provides an independently corroborated
result identity. Any supplied inconsistent identifier fails closed.
