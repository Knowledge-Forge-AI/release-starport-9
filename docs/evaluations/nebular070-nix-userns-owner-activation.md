# Nebular 0.7.0 Linux Nix runner admission

Status: owner-approved source activation; hosted qualification pending.

The owner approved the exact three-file runner proposal on 2026-10-27.
The Linux Nix step uses a guard limited to this repository's disposable
GitHub-hosted Linux runners. It temporarily permits unprivileged user
namespaces, runs the existing lane command, and restores and verifies the
original setting. The original Darwin command remains direct.

The security trade-off is the additional unprivileged-user-namespace attack
surface during the lane. The runner already grants passwordless sudo.
Handled signals can be deferred while a foreground child runs; a hard kill
or job timeout relies on disposable VM teardown. The sysctl commands have
the enclosing job timeout rather than a separate command timeout.

Verification on the exact applied patch: 34 stub and workflow tests passed,
including Linux guard behavior, hosted diagnostics, static workflow checks,
and scoped workflow graph checks. Local verification made no real sysctl
or sudo calls. The independently reviewed guard bytes are unchanged.
The reviewed probe fixes separately retain the exact 173-test evidence.

Fresh hosted unit and required Nix qualification must pass before source
promotion. The experimental proot lanes retain their established status.
Publication permissions and the pending three-wheel compatibility admission
are separate from this runner activation.

Rollback restores the candidate workflow and removes the new guard and its
test; the earlier proposal and evaluation records remain historical evidence.
