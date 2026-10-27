# Required Linux Nix runner policy proposal

Status: inert owner-review proposal, not permission to change a runner.
The source candidate is 4f8ad21f751fb362e6e515c1516330f81fd5e96a.
Required Linux Nix gates fail NIX_FHS_USERNS with uid-map-denied and a
restricted AppArmor user-namespace state. The same failure is present on the
unchanged main-branch campaign. Experimental PRoot is separately excluded from
required_jobs; it does not waive ordinary Nix or unit qualification.

The attached relative patch is a bounded diagnostic-remediation trial. It
changes only the existing nix job call site (`Execute non-production nix lane`
under `if: ${{ !cancelled() }}`) to branch on `RUNNER_OS`, adds its guarded
Bash wrapper, and adds stub-only tests. Darwin keeps the exact byte-identical
direct command line; PRoot, unit, publication, permissions, tokens, Nix pins
and catalogs are unchanged. The proposed script is executable mode 100755. No
part of this patch may be applied until the owner explicitly authorizes this
test-runner policy class.

Core privilege trade-off: standard GitHub-hosted Linux runner users already
have passwordless `sudo`, so this wrapper does not grant new root capability to
the job user. The security delta is exposing the kernel's unprivileged
user-namespace attack surface (`kernel.apparmor_restrict_unprivileged_userns=0`)
to processes inside the non-production Linux Nix lane for the duration of that
step on a single-tenant ephemeral VM.

The wrapper requires GITHUB_ACTIONS=true, RUNNER_OS=Linux, the exact repository
and RUNNER_ENVIRONMENT=github-hosted. Missing, self-hosted or unsupported
contexts fail before any host call. It accepts only the exact original
kernel.apparmor_restrict_unprivileged_userns value 0 or 1, sets and verifies
temporary 0 only when needed, executes the unchanged quoted argument vector,
and compares/restores/verifies the original state through EXIT/INT/TERM hooks.
Command failures retain their failure status; restoration failures cannot
produce success, including when the original was 0 and the lane changed it.

A foreground child may defer Bash's TERM handler until the child returns.
Restoration is not guaranteed to be immediate on cancellation, and the
`sudo -n sysctl` admission/restore calls have no independent command timeout
beyond the enclosing job `timeout-minutes`. SIGKILL cannot run a trap:
disposable GitHub-hosted VM teardown is the final containment boundary.
Persistent/shared runners are outside this proposal. The original job timeout
is unchanged. There is no new global process sweep, privileged Docker, AppArmor
disablement, no-sandbox path, continue-on-error or gate waiver.

The Bash profile response is Orange pending the explicit owner decision:
privileged job-local kernel state and signal cleanup are one cohesive owner.
The quote-preserving command vector is fixed at the workflow call site.
Eleven stub-only tests, the existing workflow/diagnostic suites
(`test_hosted_diagnostics`, `test_workflow_static`, `test_scoped_workflow_graph`,
34 tests total in an isolated reference copy), and `bash -n` passed; the full
relative patch passed `git apply --check`. These tests use temporary
sudo/sysctl stubs and never alter a real kernel. They do not prove that
AppArmor is the actual cause of every uid-map error. Source defined diagnostics
establish correlation only.

Alternatives are retaining the blocker, or qualifying a narrower job-specific
bwrap AppArmor profile with exact store-path and child-profile coverage. The
latter requires additional provisioning and qualification. This proposal does
not invent that mechanism. The existing strict Nix gates remain mandatory.

After owner approval and independent review, apply only the exact reviewed
workflow/script/test postimages, run a fresh candidate campaign, and inspect
both required Linux Nix receipts plus restoration output. Any missing/unknown
state, admission/restore failure, unsupported host, or unexplained runtime
error fails closed. The trial does not enable publication readiness. Rollback
restores the original workflow and removes only the new script/test.

Primary references:
- https://documentation.ubuntu.com/release-notes/24.04/
- https://docs.github.com/en/actions/how-tos/write-workflows/choose-where-workflows-run/choose-the-runner-for-a-job
- https://docs.github.com/en/actions/reference/workflows-and-actions/variables
