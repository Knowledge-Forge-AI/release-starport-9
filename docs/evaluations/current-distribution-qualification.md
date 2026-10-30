# Current distribution qualification proposal

Status: PREPARE ONLY. This independent source snapshot is a review artifact.
The new workflow and policy have not been adopted, committed, activated, or run.
Production and publication authority remain false.

## Problem and selected scope

The historical full qualification contract includes wheel rebuilding, observation,
foundation readiness, and PRoot diagnostics. Those channels do not describe the
requested current distribution-only qualification. The proposed closed selector
uses generation `theme-forge-current-202610`, qualification scope
`current-distribution-only`, workflow `rs9-current-distribution-tests.yml`, and
`operators/theme-forge-current-202610/hosted-lanes.json`.

The eight required jobs are config, unit, authenticate, pins, nix, native, pages,
and summary. Eleven lane receipts are required: authentication, pins, three Nix
systems, two Debian architectures, two RPM architectures, one pacman system,
and Pages. Every historical lane row, required gate, product requirement,
architecture, custody requirement, and allowed-not-run policy for those channels
is retained exactly. All four products, including Nebular GUI, remain required.
Current Nix summaries additionally require outputs for all four products.

Historical workflow and contract bytes, defaults, collector `WORKFLOW`, and
historical full-contract constants remain unchanged. A current distribution
result cannot establish historical full qualification or npm/PyPI qualification.

## Binding and fail-closed behavior

Closed source-owned paths select the workflow, contract, catalog, command
contracts, caller configuration, bootstrap configuration, and RPM policy.
Current builder identity incorporates the selected configuration identity,
including an explicit missing-input marker where a prerequisite is held.
Changing selected catalog, commands, caller configuration, or RPM policy changes
both configuration and builder identities.

Current provenance binds repository, adopted source commit, source tree,
workflow path and hash, contract hash, builder hash, configuration hash,
generation, scope, release-ingestion hash, run ID, event, ref, and attempt.
Git tree authentication requires a real source checkout at the adopted commit,
without tracked changes or untracked non-ignored source files. Legitimate
ignored generated caches do not invalidate that check.
This snapshot has no Git directory and cannot authenticate that boundary.
Static tests use explicitly synthetic tree identities; they establish no Git
or hosted qualification claim. Current lanes authenticate source identity
inside the custody boundary before execution and recheck it afterward. A
source-tree or provenance failure retains a failing receipt and manifest with
`source_tree: null` and an explicit source-identity error. Such diagnostic
provenance is rejected by custody and qualification consumers. Summary identity
failures likewise retain a not-qualified summary with a classified source-tree
blocker and `adoptable: false`.

Config, lane execution, upstream custody validation, summary creation and
validation, and collection pass the selected generation explicitly. Mixing
source, workflow, generation, scope, run, tree, configuration, or release
projection fails. Collection preserves exact repository/run/path/artifact
identity, required job and step conclusions, package roles, architectures,
promotion restrictions, and every required gate. Adoption requires push on
main, attempt 1. Current summary and collector classifications identify only
the distinct distribution scope; the historical full qualification flag stays
false for current runs.

The current RPM policy file is absent. RPM lane preparation records a held
failure, and summary validation refuses current RPM qualification without that
selected policy. Current policy loading passes the selected generation explicitly, with no
historical fallback. A diagnostic-only blocked current policy and its runtime
loader integration are separate prerequisites; summary validation also refuses
an explicitly blocked selected policy. Adding that policy can permit
diagnostic construction while its failing acceptance gate still blocks
qualification. The exact pending loader dependency is
`rs9.rpm_lint_policy.load_policy(path=None, *, generation=HISTORICAL_GENERATION)`.
The qualifier calls that API with the selected current generation. Its
implementation is available in the separate accepted prepare-only RPM proposal
and remains to be integrated into this snapshot; the qualifier does not provide
a compatibility fallback. Historical policy acceptance is not substituted. A synthetic
complete distribution receipt set still returns not-qualified, with both RPM
policy holds retained.

## Proposed runner policy for owner review

- Problem: qualify current Nix/APT/DNF/pacman distributions without claiming a
  pass of unrelated historical wheel and registry channels.
- Alternatives: retaining the historical full contract would require unrelated
  work and would describe a different scope; deleting gates from the historical
  contract would change existing authority. A distinct closed contract preserves
  both scopes.
- License review: no dependency or license change. Existing project license and
  existing workflow components remain applicable.
- Supply-chain review: existing pinned action revisions, Node version, public
  native hosts, Nix installer, container pins, and repository tool classes are
  reused. No new action, installer, permission, or tool class is introduced.
- Runtime and packaging impact: a separate workflow schedules only the selected
  distribution lanes. Package construction, fixture signing, disconnected
  unprivileged runtime probes, custody roles, and promotion restrictions remain
  owned by the existing lane modules.
- Compatibility: historical defaults and policy files remain intact. Selection
  is explicit; unknown generations and mixed provenance fail closed.
- Rollback: decline adoption of this proposal, or remove the new selected policy
  and workflow together and revert the bounded selector plumbing. No hosted
  state, installed state, or production objects have been changed.
- Correctness evidence: source and synthetic custody tests verify exact lane
  retention, generation separation, source/run binding, missing-policy holds,
  and selected configuration hashing. No performance claim is made.
- Governance: this document is the proposed runner-policy disposition. Adoption
  and any hosted execution require the owner's review of this exact change set.

Both distinct workflows retain push triggers for main. If this proposal is
adopted, each main push schedules both the historical full workflow and the
current distribution workflow, with separate concurrency groups. That adds
hosted runner work and cost; this proposal does not change historical triggers.

The maintained Linux Nix AppArmor user-namespace guard and restoration script is
unchanged and remains wrapped around the Linux Nix invocation. No WebKit sandbox
disabling, new privilege, or replacement runtime mechanism is proposed.

## Verification and prerequisites

125 focused source/static tests passed. Existing historical contract, summary,
collector, capture, command, role, and PRoot receipt tests are included. Test
Git-tree values and package custody are synthetic; released applications,
installers, package builders, Nix, Docker, and signing tools were not executed.

The existing verified actionlint parser accepted the new workflow with
`-shellcheck= -pyflakes=`. ShellCheck and Pyflakes were explicitly disabled;
this is workflow parser validation, not execution or external checker evidence.

Still required before hosted qualification: owner approval of this exact new
runner policy; real adopted Git commit/tree and hosted run identities; current
RPM policy and runtime integration; current caller and smoke integration; and
all native hosted build, GUI/caller, install/load, offline, custody, and tamper
evidence. Those integrations are separate source slices. No production bridge,
production key, Pages deployment, registry publication, or live activation is
part of this proposal. The first hosted run must also confirm that Nix and
Pages have no implicit dependency on excluded wheel, observe, or foundation
artifacts, and that all three Nix systems report all four product outputs,
including Nebular GUI on aarch64-darwin.
