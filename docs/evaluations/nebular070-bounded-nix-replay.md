# Nebular 0.7.0 bounded Linux post-failure replay

Status: source-evaluation note for the independent diagnostic replay seam.
Replay is diagnostic evidence only; it never changes qualification, admission,
or publication status. Hosted, native, and publication evidence are pending.

## Context

Hosted run 40558745317 failed the required Linux Nix application smoke at the
original 240-second bound: ARM64 scenario B and x86_64 scenario C both timed
out without a receipt, and cleanup of the original attempt was not observed.
Wheel, native-packaging, and Darwin Nix lanes passed, as did the pinned D-Bus
controls. Boundary probes were already enabled for Linux Nix, but the bounded
replay was reachable only through x86_64 `diagnostic_extras`, which the Nix
caller does not request.

## Change

An independent `diagnostic_replay` flag (default false) is propagated through
`execute_application_smoke`, `verify_nebular_runtime`, and the Nix runtime
caller. Only Linux Nix opts in (`system.endswith("-linux")`). On an original
failure, `_retain_failure` receives `include_replay=(extras or
diagnostic_replay)`, so existing x86_64 extras behavior is unchanged.

The original application smoke attempt remains the authoritative gate. Its
process path, 240-second timeout, failure details, and short-circuit are
unchanged. A failure may trigger one separate replay through the existing
bounded process-group runner, with a fresh `evidence-replay-<scenario>`
directory, the existing output cap and cleanup/reap checks, and the same
240-second bound. The replay reuses the caller's prefix, environment, and
pinned session-bus argv. The diagnostic records the replay as non-equivalent
to the original, the gate status stays `fail` even if the replay passes, and
if scenario C fails, C-signal remains unstarted. No process sweep, timeout
widening, gate waiver, D-Bus/PATH/pin change, or qualification claim is
introduced. The worst-case added wall time per failed lane is one 240-second
replay plus its 10-second reap grace; the probe budget was already present.
This stays within the lane timeout.

The authenticated pip helper is intentionally outside this change; current
hosted lanes do not use it.

## Review disposition

The integrated source was reviewed for gate preservation, default-off
forwarding, privacy of retained fields, and scenario short-circuiting. One
in-scope gap was closed: no test exercised the actual Linux Nix combination
of replay, boundary probes, and pinned session-bus argv. A focused test now
asserts one original attempt, a single replay ordered before the probes, the
pinned argv on both commands without an ambient bus fallback, a failed gate,
a non-equivalent replay, non-qualifying probes, and no raw stream text or
scratch paths in the diagnostic. No source defect was found. The independent
work review found no blocking defect. Its advisories were dispositioned at
close: the diagnostic-bound residual below was deferred, and the Nix caller's
source-text forwarding assertion was accepted because it matches the
existing pattern and runtime forwarding is covered elsewhere.

Residual limits: the original attempt still uses the legacy runner, so its
descendants are not proven absent before the replay starts; the diagnostic
already records this as unproven. Linux Nix now retains a larger record than
before: the full original diagnostics, the replay summary, and the probes. As
on the existing x86_64 extras path, an exception from the replay step or a
record above the 60 KiB diagnostic bound would raise a contract error. The
gate would still fail, but the original failure details would be lost. The
added replay fields are closed categories and digests, so the risk is low.
Hardening this, by keeping the original error when the diagnostic step fails,
is deferred because it would also change the existing extras behavior.

## Checks

Focused `unittest` modules `test_application_smoke_diagnostic`,
`test_hosted_smoke`, and `test_hosted_nix` pass on the resulting source under
Python 3.13.12 with bytecode writes disabled and a bounded process-group
runner. These are controlled synthetic fixtures, not Linux Nix
qualification and not cleanup proof for the failed hosted run.

## Rollback

Revert the Nix caller line to stop requesting replay; the flag defaults to
false, so removing the parameter from the three call sites restores the prior
behavior without touching gates or evidence formats.
