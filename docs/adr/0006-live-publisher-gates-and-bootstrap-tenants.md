# ADR 0006: LIVE1 mandatory gates and exact-generation bootstrap

Status: implementation candidate; production publishers remain disabled.

Foundation 3 is accepted as the publication-state foundation. A renderer's own
verdict and a policy containing arbitrary evidence hashes cannot qualify a real
publisher. Releases predating project-owned `.rs9/` also need a narrowly reviewed
configuration authority without changing their tags or assets.

RS9 now unions adapter-owned mandatory gates with policy additions. Mandatory
gates cannot be waived as not applicable. `package.render` starts not-run even
when a render manifest says qualified. A passing non-release gate requires a
matching executed qualification capability, the full candidate binding and a
separate policy allowlist of that qualification record's hash.

The qualification trust root is **reviewed verifier code rerun by an attended
operator**. RS9 rehashes the actual verifier module and candidate files before and
after execution. JSON imports cannot establish that authority. This code trust
boundary is not a sandbox. Production adapter verifiers, including independent
rebuild/install/runtime/signature checks, remain to be implemented and qualified;
synthetic tests do not close those gates.

Destination policy becomes `rs9.destination-policy.v1alpha2`, adding explicit
publish/observe-only modes. npm and Homebrew require observe-only. Receipts become
`rs9.publication-receipt.v1alpha2`: synthetic or asserted-live JSON yields simulated
confirmation, while published requires fresh in-process planning, actual transport
and exact readback from an implemented live reader. Historical plans and attempts
remain audit records and cannot authorize a new mutation. There is no implicit
upgrade from v1alpha1 policies; migrate explicitly and re-observe/re-plan.

The RS9-owned bootstrap manifest applies only to the four exact Theme Forge
repository/tag/release/commit/tree/version tuples. Configuration is hash-bound,
explicitly absent from the release, independently allowlisted and forbidden for
future releases. The example Nebular configuration remains illustrative and is
not loaded for LIVE1. Future normal ingestion requires project-owned `.rs9/`
captured from the authenticated tagged tree.

Repository-authoritative licensing uses `AGPL-3.0-or-later`. Commercial negotiation
remains separate. Nebular's differing npm wrapper declaration is recorded as a
historical metadata conflict. Third-party dependency notices must be preserved;
this candidate does not adopt the proposal's composite license expression.

Nix outputs remain unexposed until qualification and a separate reviewed exposure
change. Hosted publication must retain signed objects once and identify their
signed bytes separately from the unsigned candidate; restart must reuse those
objects. The persistent signed store implements retention mechanics only. Native
cryptographic verification and production storage custody remain open gates.

Verification: planner, forged-evidence, bootstrap, synthetic receipt/replay,
signed-store tamper and candidate-builder tests. Real publication and hosted/native
qualification are deferred as detailed in the [LIVE1 candidate](../live1-candidate.md).
