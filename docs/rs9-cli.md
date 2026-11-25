# RS9 CLI

RS9 0.1.0 provides an installable CLI for Python 3.11 and later. The ordinary
local commands validate and normalize `.rs9/` configuration without remote access.
The explicit `instance github` family has two separate contracts: the
existing-repository `plan`/`apply`/`resume` lane, and the explicit
`provision-plan`/`provision-apply`/`provision-resume` lane for bounded
repository provisioning. Only the latter can create a private repository
under its narrow protocol; neither lane installs packages or publishes
releases.

The first release includes offline validation and planning, Homebrew formula
rendering, and the bounded GitHub instance operations below. GitHub operations
use the operator's installed `gh` and require the appropriate repository access.

Install a built wheel into a fresh environment and invoke the installed
frontend:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install https://github.com/Knowledge-Forge-AI/release-starport-9/releases/download/v0.1.0/release_starport_9-0.1.0-py3-none-any.whl
.venv/bin/rs9 --version
.venv/bin/rs9 --help
```

Editable (`pip install -e`) installation is not supported by this qualification
boundary. For source development, use:

```text
PYTHONPATH=src python3 -m rs9 --help
```

`python3 -m rs9` is the source entry point. The existing
`python3 -m rs9.contract` entry point is independent and unchanged.

## Signed Linux repositories

RS9 0.1.0 is available through signed APT, DNF and pacman repositories on
[the RS9 Pages origin](https://rs9.knowledge-forge.ai/). The package name is
`release-starport-9` and the installed command is `rs9`. The
[native qualification](https://github.com/Knowledge-Forge-AI/release-starport-9/actions/runs/44770929836)
covered install, version reporting, doctor, removal and a signature-rejection
case for each ecosystem on x86-64 and ARM64.

Check the public certificate before trusting it. Its primary fingerprint is
`7D03EE84F8C7025FD2F3D772BF89DF6643C2F1AF` and its signing subkey is
`C021E00EE3D37C459B0E1CB3199F8028126E8A8C`.

### APT

Download the [binary public certificate](https://rs9.knowledge-forge.ai/packages/rs9/keys/rs9-signing.gpg)
and install it as `/etc/apt/keyrings/rs9-signing.gpg`, readable by APT.
Use this line in a new `rs9.list` under `/etc/apt/sources.list.d/`:

```text
deb [signed-by=/etc/apt/keyrings/rs9-signing.gpg] https://rs9.knowledge-forge.ai/packages/rs9/apt stable main
```

Refresh with `sudo apt update`, then run `sudo apt install release-starport-9`.

### DNF

Add a new `rs9.repo` under `/etc/yum.repos.d/`:

```ini
[rs9]
name=Release Starport 9
baseurl=https://rs9.knowledge-forge.ai/packages/rs9/rpm
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://rs9.knowledge-forge.ai/packages/rs9/keys/rs9-signing.asc
```

Run `sudo dnf install release-starport-9` and confirm the publisher
fingerprint if prompted.

### pacman

Download the [binary public certificate](https://rs9.knowledge-forge.ai/packages/rs9/keys/rs9-signing.gpg)
as `rs9-signing.gpg`. Add and locally sign the verified key:

```sh
sudo pacman-key --add rs9-signing.gpg
sudo pacman-key --lsign-key 7D03EE84F8C7025FD2F3D772BF89DF6643C2F1AF
```

Append a new repository entry to `/etc/pacman.conf`. The `$arch` variable
selects the signed index for the installed system:

```ini
[rs9]
SigLevel = PackageRequired DatabaseRequired
Server = https://rs9.knowledge-forge.ai/packages/rs9/pacman/$arch
```

Install as part of a full system sync with `sudo pacman -Syu release-starport-9`.

## Inspect the release used by the RS9 self-consumer

From the source checkout, use the Python CLI release profile to capture and
verify the original RS9 0.1.0 wheel and source distribution:

```sh
PYTHONPATH=src python3 -m rs9.python_cli_release \
  Knowledge-Forge-AI/release-starport-9 --version 0.1.0 \
  --distribution release-starport-9 --command rs9 --capture ./rs9-v010-evidence
```

The capture directory must be new. Use `--evidence ./rs9-v010-evidence` in
place of `--capture` for an offline recheck. The result binds the release tag,
checksums, wheel RECORD, Python floor, console entry point, package contents
and three tagged license files. The profile covers dependency-free pure
Python CLI archives and executes no archive members. The published 0.1.0 wheel predates the installed `release inspect` command. A verification result supplies evidence
for onboarding and creates no publisher registration or deployment.

## Commands

Builds that include `rs9 release inspect` can use the same release profile
through the installed CLI.

```text
rs9 --version
rs9 doctor
rs9 project validate PROJECT [--destinations FILE]
rs9 project intent PROJECT --destinations FILE --version RELEASE_VERSION
rs9 adapter homebrew render --normalized FILE --payload-facts FILE \
  --variant cli-archive --output DIRECTORY
rs9 instance init PUBLISHER_ROOT --id INSTANCE_ID \
  --publisher-repository OWNER/REPO --publisher-branch BRANCH \
  [--template TEMPLATE_ID] [--template-version TEMPLATE_VERSION] \
  [--runner RUNNER] [--environment ENVIRONMENT] [--operator-binding BINDING]
rs9 instance doctor PUBLISHER_ROOT [--json]
rs9 instance register PUBLISHER_ROOT --id CONSUMER_ID \
  --project PROJECT --destinations FILE --destination DESTINATION_ID \
  --package PACKAGE_ID [--dry-run] [--expect-plan-sha256 SHA256]
rs9 instance plan PUBLISHER_ROOT --consumer CONSUMER_ID \
  --project PROJECT --destinations FILE --version RELEASE_VERSION
rs9 instance prepare-homebrew PUBLISHER_ROOT --consumer CONSUMER_ID \
  --project PROJECT --destinations FILE --version RELEASE_VERSION \
  --release-evidence CAPTURE --output NEW_DIRECTORY
rs9 instance apply-homebrew PUBLISHER_ROOT --consumer CONSUMER_ID \
  --project PROJECT --destinations FILE --version RELEASE_VERSION \
  --release-evidence CAPTURE --tap-root TAP_CHECKOUT \
  --tap-repository OWNER/TAP --expect-formula-sha256 SHA256 \
  [--expect-tap-target-sha256 SHA256] [--dry-run]
rs9 instance inspect-homebrew PUBLISHER_ROOT --consumer CONSUMER_ID \
  --project PROJECT --destinations FILE --version RELEASE_VERSION \
  --release-evidence CAPTURE --branch TAP_BRANCH
rs9 instance plan-upgrade PUBLISHER_ROOT --consumer CONSUMER_ID \
  --project PROJECT --destinations FILE --version RELEASE_VERSION --json > PLAN
rs9 instance apply-upgrade PUBLISHER_ROOT --consumer CONSUMER_ID \
  --project PROJECT --destinations FILE --version RELEASE_VERSION \
  --plan PLAN [--dry-run]
rs9 instance github doctor [--engine-wheel PATH]
rs9 instance github doctor --publisher-root PUBLISHER_ROOT --engine-wheel PATH [--json]
rs9 instance github plan PUBLISHER_ROOT --engine-wheel PATH --output PLAN
rs9 instance github apply PUBLISHER_ROOT --plan PLAN --engine-wheel PATH \
  [--operation-id OPERATION_ID]
rs9 instance github resume PUBLISHER_ROOT --operation-id OPERATION_ID \
  --engine-wheel PATH [--prior-result RESULT]
rs9 instance github provision-plan PUBLISHER_ROOT --engine-wheel PATH \
  --output PLAN --operation-id OPERATION_ID
rs9 instance github provision-apply PUBLISHER_ROOT --plan PLAN \
  --engine-wheel PATH --operation-id OPERATION_ID
rs9 instance github provision-resume PUBLISHER_ROOT --operation-id OPERATION_ID \
  --engine-wheel PATH
```

`--version` reads the actual `release-starport-9` distribution metadata through
`importlib.metadata`, but only when that metadata resolves to the same
`rs9/cli.py` being executed. An absent or mismatched installation, including a
stale distribution selected from another `PYTHONPATH`, reports `unreleased`;
the CLI does not invent or borrow a release number.
The resulting engine string is a distribution label: a development value such
as `unreleased` cannot distinguish independently rebuilt source trees.

`instance doctor` checks the local publisher manifest, installed template,
registration files and recorded desired state. It reports pending local
transactions for inspection and returns a nonzero exit when the publisher
needs review. It reads no consumer checkout and contacts no remote service.
Use `instance plan` to compare a specific consumer's current inputs.
The doctor result leaves remote state unknown and confers no publication
authority.

`doctor` reports only the running Python implementation/version and whether a
`gh` executable is present on `PATH`. It does not execute `gh` and does not
read authentication, configuration, token, local-path, or remote-state data.
The supported Python floor is 3.11, so `tomllib` is expected to be available
on supported installations.

`project validate` calls the current contract engine. Without `--destinations`
it validates the selected tenant files; with it, it additionally validates
destination routing and cross-project coverage. `project intent` calls the
current normalizer and wraps its `rs9.normalized-tenant.v1alpha1` output in an
offline intent result. The wrapper always states `remoteState: "unknown"` and
`publicationAuthority: false`; it is not an authenticated plan.

`adapter homebrew render` consumes one bounded normalized JSON document and one
closed six-field payload-facts JSON document. The only supported CLI variant is
`cli-archive`; each input may be a local regular file or one may be `-` for
stdin. Duplicate JSON keys, non-finite values, symlinks, special files,
oversize inputs, unknown payload fields, and a second stdin selector are
rejected without output. The command calls the pure
`rs9.homebrew_renderer.render_homebrew_formula` function and writes exactly one
formula plus `render-result.json` into a new no-clobber output directory. The
result contains raw and canonical input hashes, formula/template hashes, and
`qualified: false`, `publication_enabled: false`, and `remote_state: "unknown"`.
It never fetches the payload URL, reads credentials, invokes Homebrew or other
processes, or writes a tap. Both input paths and the output path must have
physical, non-symlink ancestors after lexical absolutization, and the output's
parent must already exist. On macOS, spell temporary paths through
`/private/tmp` or `/private/var` rather than the `/tmp` or `/var` aliases.
These checks do not provide atomic protection against hostile ancestor swaps.

Only exit `0`, with an `ok: true` envelope in JSON mode, signals a completed
render. Any directory retained after a non-zero exit is partial, whether its
formula and `render-result.json` are complete, truncated, or missing; its
formula must not be consumed. A missing `render-result.json` always means
partial output. Local write failures can return `ENVIRONMENT_ERROR`, exit `3`,
without a result. Inspect retained files and select a fresh output directory
for another attempt; the command never deletes or overwrites them. Installed
wheel binding and later Homebrew build/install qualification remain separate.

`instance init` creates or inspects the publisher-root manifest and inert
allowlisted Homebrew projection scaffold. The running CLI binds the actual
engine identity returned by its version helper; there is no engine-version
override flag. Optional runner, environment, and operator-binding arguments
are bounded declarative labels persisted in the manifest; they do not execute
commands or resolve credentials. `instance register` validates the selected
consumer with the current engine, requires the manifest's engine pin to match
that runtime identity before mutation, and records only its selected Homebrew
projection and input hash baseline. `instance plan` runs the current normalizer
and emits a local desired-state plan. `inputs.normalized_sha256` hashes the canonical embedded
selected intent; `inputs.normalized_engine_sha256` is explicitly the full
engine-output digest, including unselected adapter inputs. It reports the
runtime engine identity separately and rejects a manifest pinned to a different
engine version. Instance plans remain
`remoteState: "unknown"`, `publicationAuthority: false`, and do not perform
GitHub operations.

Use `instance register --dry-run --json` to review the local registration
without writing. It reports `ready` for a new registration, `resume` for a
matching interrupted transaction, or `noop` for a complete registration.
Pass the reported `planSha256` as `--expect-plan-sha256` on the same command
without `--dry-run` to require the reviewed managed-file state, input
bindings and transaction before staging. Take a fresh review after changes
or an interruption. Registration describes local intent. Remote state and
publication authority require separate qualification.

Use `--require-tagged-consumer-contract` with `release inspect` to capture
or verify the release tag's exact `.rs9/project.toml`, `.rs9/releases.toml`,
and `.rs9/homebrew.toml` files. Strict intake also recomputes the Git object
ID for the complete closed `.rs9` directory from its listed blob entries and
requires it to equal the directory object recorded in the captured tree.
The option is also available on the three
Homebrew instance commands that consume `--release-evidence`. Those commands
compare the three captured blob digests against the freshly normalized local
inputs. Other adapter inputs and instance destination configuration remain
separate. Ordinary release inspection preserves archive-only verification
for releases that predate the consumer contract.

`instance apply-homebrew` always requires tagged consumer input verification.
It matches the declared destination and an explicitly reviewed formula digest
before applying to the local checkout's existing `Formula/` directory. A
missing formula is linked atomically from complete staged bytes. Identical
bytes and mode give a no-op. Different bytes, unexpected modes, symlinks,
and conflicting arrivals are refused. This operation creates no Git commit,
contacts no remote, and does not confer publication authority.

Use the same command with `--dry-run` to check the tagged input, reviewed
formula, and local tap before applying changes. The result includes
`dryRun: true` and reports `ready` when the destination is absent
or `noop` when its bytes and mode already match. Drift and unsafe paths
use the same refusals as apply. Apply repeats admission and file checks.
When reviewing a local target, use `--dry-run --json` and pass its
`tapTargetSha256` to apply as `--expect-tap-target-sha256`. This binds
the tap repository label and the two reviewed local directories by device
and inode. A different checkout or replaced `Formula/` directory requires
a fresh review. The digest is a local filesystem binding. GitHub identity
and publication remain governed by the separate remote commands.

`instance inspect-homebrew` reruns local planning and release-evidence
verification, renders the expected formula in memory, and reads the tap
repository declared by the selected destination. The command compares the
Git mode and exact formula bytes at a pinned branch commit. It rereads the
branch and reports `unknown` if the branch or identity changed during the
observation. Other results are `match`, `missing`, `drift`, and `unsafe`.
Drift is a successful observation and does not authorize replacement.
The result includes formula digests and the tagged-consumer-contract flag.
It omits the remote file contents and claims no publication authority.

### Review a forward update to an existing tap formula

Start with a release tag that contains the consumer contract. RS9's
historical `v0.1.0` tag predates that contract. Its archive evidence is
useful for inspection, while a successor needs its own tagged evidence.
Confirm that `instance plan` matches the registered consumer. Render the
successor in a new directory with `instance prepare-homebrew` and the
`--require-tagged-consumer-contract` option. Use the same evidence and
strict option with `instance inspect-homebrew`.

For an existing formula, use a fresh tap checkout at the exact observed
commit. Confirm that its index is clean, the formula is a `100644` entry,
and the index blob's SHA-256 matches `remote.sha256` in the observation.
Confirm that the generated file's SHA-256 matches `desired.sha256` and
review the diff, including version, archive URLs, hashes and native checks.
An `unsafe` or `unknown` observation needs investigation before review.

Apply the reviewed one-file patch to the isolated Git index with
`git apply --cached --check` followed by `git apply --cached`. Verify that
the staged formula matches the reviewed digest and mode and is the only
staged path. The index operation leaves the worktree untouched. Recheck
the remote branch before submitting the tap change. If the base changed,
repeat the observation and review against the new base. A native check of
the exact formula and its release archives is still required before
enabling the forward publication lane.

Publisher-root confinement for the instance lane uses POSIX descriptor-relative
filesystem operations (`dir_fd`/`O_NOFOLLOW`) and is qualified only for that
scope. No Windows instance-filesystem qualification is claimed by this CLI.
State-file replacement checks the predecessor hash for a single local
operator. Coordinate concurrent writers before applying a plan.

When `instance plan` reports input drift, use `instance plan-upgrade --json`
to save a review for the existing registration. The review binds the complete
destinations file, normalized intent, registration and publisher state. Run
`instance apply-upgrade --dry-run` with the same inputs and saved plan to check
whether it can apply, resume or return a no-op without writing files. Apply
with the same command and omit `--dry-run`. Apply rechecks the bound inputs
and publisher state. A relevant change requires a fresh review.
If a local publisher mutation returns `INSTANCE_BUSY`, let the active writer
finish, then retry the reviewed apply. The retry still verifies that the
reviewed state is current or can be resumed.

After an interruption, rerun apply with the same reviewed plan. RS9 can
resume an exact pending transaction and leaves unrelated files and unowned
staging artifacts in place. These upgrade commands operate locally and carry
no publication authority.

The physical-ancestor policy checks the publisher root, selected consumer
project and `.rs9` roots, and the destinations-file parent without silently
realpath-widening them. An ancestor symlink is rejected before file processing
as `SYMLINK_REJECTED`; a symlinked or non-directory control-path component
inside an otherwise physical publisher root can fail traversal as
`OUTPUT_CONFINEMENT`. A managed leaf symlink or special file is instead a
privacy-safe per-file `unsafe` result. On macOS, `/tmp` and `/var` may alias
into `/private`, so default temporary paths can fail this strict physical check;
source proofs use a physical task-root `TMPDIR`. The closed
`.rs9-instance/consumers` directory rejects unknown `.DS_Store` and editor
swap entries as `UNKNOWN_FILE`.

The embedded validated engine `normalizedIntent` is exempt from the
instance-produced private-path filter: legal engine summaries such as
`~/.config`, check argv such as `/tmp/x`, and relative license evidence such as
`LICENSE` remain valid. Credential scanning still applies.

No apply, publish, sign, workflow-dispatch, or other remote mutation command is
implemented by the ordinary offline commands. The two opt-in `instance
github` contracts are the remote-capable surfaces described below. The
existing-repository lane never creates a repository or bootstraps a branch;
the separate provisioning lane can create a private repository and bootstrap
its selected branch only through its fixed protocol. Neither lane dispatches a
workflow, publishes, signs, activates a consumer, or retries an uncertain
operation.

## Existing-repository GitHub instance commands

This section is limited to the pre-existing `plan`, `apply`, and `resume`
contract. It operates on an already-existing repository. It does not create a
repository or bootstrap a branch; those behaviors belong only to the separate
provisioning contract below.

The GitHub family is opt-in by command name. Ordinary `rs9`, `doctor`,
`project`, and local `instance` commands remain offline and auth-free.
`instance github doctor` by default reports whether `gh` is available
and optionally verifies the named engine wheel offline. Specify
`--publisher-root` with `--engine-wheel` to read that publisher's
configured GitHub branch through the existing read transport. The JSON
result identifies the observed commit, managed-file comparisons and
reason. An exact snapshot returns exit 0. Drift, missing files and an
unknown remote state return exit 1. The observation produces no plan
file, transaction journal, or publication authority.

The `plan`, `apply`, and `resume` commands require `--engine-wheel PATH`. The
wheel is opened as a bounded local archive and its raw SHA-256 is recorded;
the actual installed `release-starport-9` distribution's `rs9` module/resource
members are compared byte-for-byte. Version metadata and `direct_url.json` are not artifact identity. The
wheel path is never serialized or echoed in a public error. A mismatch is
rejected before remote I/O.

`plan` validates the output destination and local engine pin before performing
fresh bounded GitHub reads through the fixed `github.com` reader. When the
remote state is observable, it binds that result to an immutable branch
commit/tree; unknown or non-applicable outcomes remain reviewable plan files
but return exit `1`. The output parent and leaf are checked without silently
realpath-widening; this is a check-then-open limitation for a hostile ancestor
swap, not descriptor-relative confinement. An existing output path is never
overwritten. The plan file contains the validated protocol plan, engine
artifact/member binding, reader protocol, hashes, and false authority fields.
It contains no local publisher-root path, wheel path, plan path, credentials, or
raw API response. On macOS, `/tmp` and `/var` may alias into `/private`; the
strict physical-parent check can reject default temporary paths, so proofs use
a physical task-root `TMPDIR`.

`apply` is an explicit write intent; no redundant permission flag is needed.
It accepts only a new `create` or `noop` plan, rechecks the engine/local state,
performs the coordinator's fresh authenticated preflight and exact plan
comparison, and uses the existing journal before every object/ref mutation.
For a `create` plan without `--operation-id`, the CLI mints a bounded unique ID
before entering the coordinator. If that call escapes without a validated
result, the closed `GITHUB_OPERATION` failure still reports that ID so explicit
read-only `resume` can inspect it; no fabricated coordinator base result is
emitted, and resume without `--prior-result` remains valid.
The writer creates bounded blobs, trees, and canonical commits, then updates
one branch using GraphQL `updateRefs` with `beforeOid`, `afterOid`, and
`force: false`. Exact reader readback is required for completion. There is no
force option, auto-retry, repository creation, workflow dispatch, publication,
or activation claim. Lost responses remain uncertain and require review.

`resume` requires an explicit operation ID and never accepts or constructs a
writer. It may read the remote branch/files for an eligible ref/readback
journal and may close the local journal only after exact current engine,
config, target commit/tree, branch policy, managed bytes/modes, and journal
inventory proof. Prepared and object-uncertain states remain held; no replay,
repair, deletion, migration, or new remote attempt is automatic. `--prior-result`
accepts either the exact successful or closed-error `instance.github.apply`
CLI JSON envelope/result, or a raw validated coordinator result; other wrappers
are rejected. Local input paths are not serialized. An explicit
`--operation-id` is ignored by a `noop` coordinator result, which remains
journal-free with a null operation ID.
The distinct `GITHUB_OPERATION` escape record has no fabricated coordinator
base and is not a `--prior-result` input; resume may be invoked without that
option.

All GitHub command success and failure outputs use the existing
`rs9.cli.v1alpha1` JSON envelope. The apply result retains the sanitized engine
view plus the validated coordinator decision/status, operation/plan/config/
journal hashes, readback summary, base result, and authority booleans. Local
paths, tokens, HTTP bodies, and exception text are not emitted.
`noop`/exactly-read-back `completed` return exit `0`; non-applicable plan
outcomes, validated drift, stale plans, held or uncertain journals, engine
mismatches, and reader/writer `ContractError` outcomes return exit `1`; usage
returns `2`. Only bounded failures that escape as environment/output/internal
errors (including `OSError`, `UnicodeError`, process, timeout, or executable
failures not converted to a contract result) return exit `3`. A failed apply's
human review line includes its bounded operation ID when one exists.

The CLI does not constrain a default downstream frontend hash. Any private
engineering evidence can verify exact source or wheel bytes independently;
those private hash values are not embedded as frontend defaults or treated as
publication authority.

The binding covers on-disk `rs9/` distribution members at verification time.
It does not cover non-`rs9` distribution files, bytecode caches, script shims,
or which already-loaded code objects are executing.

This slice intentionally couples to three private accepted-module helpers:
`instance_github._now`, `instance_github._instance.record_sha256`, and
`instance_github_apply._validate_coordinator_result`. They are bound by the
source review receipt, not promoted public APIs; an accepted-owner refactor
must update this CLI boundary together.

## Explicit repository-provisioning commands

The `provision-*` commands are a distinct, versioned adapter contract. They
must not be interpreted as alternate spellings for the existing-repository
commands above.

### Exact command arguments and schemas

Each command takes the positional `PUBLISHER_ROOT` and the required
`--engine-wheel PATH`. The command-specific arguments are:

| Command | Required arguments | Result schema |
| --- | --- | --- |
| `instance github provision-plan` | `--output PLAN`, `--operation-id OPERATION_ID` | `rs9.instance-github-provision-cli-plan.v1alpha1` |
| `instance github provision-apply` | `--plan PLAN`, `--operation-id OPERATION_ID` | `rs9.instance-github-provision-cli-result.v1alpha1` |
| `instance github provision-resume` | `--operation-id OPERATION_ID` | `rs9.instance-github-provision-cli-resume.v1alpha1` |

`--json` is accepted on each command and uses the existing
`rs9.cli.v1alpha1` envelope. `provision-plan` performs a fresh bounded
GitHub read, validates the local publisher-root and engine binding, and writes
only an immutable `create`, `adopt-exact`, or `noop` plan. It does not persist
a plan for `held`, `adoption-required`, malformed, drifted, or unknown remote
state. The only accepted repository-absence observation is the reader's
explicit `not-observed-404`; the adapter never infers absence from a missing
or ambiguous response.

`provision-apply` requires the exact plan operation ID, current local source
identity, and the selected engine artifact to match the plan. A `create` plan
uses the fixed private-repository/managed-README/target-ref sequence before
the accepted bootstrap handoff. An `adopt-exact` plan is admitted only for the
exact observed repository node and anchor and performs only its bounded target
ref step before that handoff. A `noop` plan remains journal-free and uses a
writer that rejects mutation. No arbitrary endpoint, force update, repository
delete, workflow dispatch, publication, or activation is exposed.

Provisioning is not a universal replacement for the existing-repository lane.
After a repository has been populated, a fresh `provision-plan` can refuse
with `existing-apply-required`/`target-existing-incomplete` when the observed
target ref no longer matches the exact bootstrap anchor. That refusal is
intentional: route an already-populated target through the existing
`instance github plan`/`apply` contract after review. The adapter never
silently converts this state into a noop or retries the mutation.

### Unknown, refusal, hold, and resume behavior

Remote non-success responses, malformed payloads, identity or branch drift,
unbounded inventory, and any response that cannot establish the required
observation are classified as refusal or held/unknown contract outcomes. They
return the sanitized `rs9.cli.v1alpha1` error boundary (normally exit `1`)
without creating a plan or starting a mutation. A failed or uncertain
mutation is not retried automatically and is never replayed by a later
command. The operation remains available for explicit review or recovery.

`provision-resume` requires an explicit operation ID and verifies the saved
source/engine binding before reading remote state. It is read-only: it never
constructs a writer, sends a mutation, repairs or deletes a repository, or
silently adopts a new plan. Prepared, object-uncertain, and unresolved
readback states remain held; only the accepted exact readback transitions can
close a journal. A successful no-op or fully validated completion may return
exit `0`; refusal, drift, held, and uncertain outcomes return exit `1`.

### Help, exit compatibility, and packaging boundary

The private parser copy catches argparse's help path so the in-process
`rs9.cli.main([... , "--help"])` call returns `0`. The source module entry
point and the installed console wrapper also exit `0` for help; this preserves
the process-level status while deliberately changing the in-process behavior
from the older `SystemExit(0)` path.

The general exit table below describes the top-level `rs9` CLI. The separate
`rs9.provision_cli` adapter's `_emit_error` deliberately returns `1` for every
emitted adapter error, including `USAGE_ERROR`, `ENVIRONMENT_ERROR`, and
`INTERNAL_ERROR`; callers must not infer exit `2` or `3` from those adapter
error codes. Top-level parser usage failures can still return `2`, and
unhandled top-level environment/internal failures can still return `3`.

The distribution contains 36 Python modules, six packaged resources, and
three legal files. The provisioning implementation includes the following modules:

- `bootstrap_binding`
- `provision_cli`
- `instance_provision`
- `provision_journal`
- `github_provision_reader`
- `instance_github_bootstrap`
- `github_provision`

The bootstrap implementation requires `bootstrap_binding`. Installation has
no Python runtime dependencies. Native package publishers remain separate
from this CLI distribution.

## Output and exit codes

Human success output is concise and never includes selected filesystem paths.
Human intent output reports status only and points to `--json` for the complete
normalized intent and its explicit offline authority fields.
Human instance output reports only a bounded status; use `--json` for the
manifest, registration, or desired-state details.
Contract failures use the stable closed message `Contract input rejected.` on
stderr and do not echo project, destination, version, or diagnostic values.
Argument failures similarly use a closed message rather than argparse's raw
token echo. JSON failures remain on stderr, preserving the existing CLI stream
boundary.

Passing `--json` on a command (or before it) produces the stable
`rs9.cli.v1alpha1` envelope:

```json
{
  "command": "project.intent",
  "ok": true,
  "result": {
    "intent": {"schema": "rs9.normalized-tenant.v1alpha1"},
    "publicationAuthority": false,
    "remoteState": "unknown"
  },
  "schema": "rs9.cli.v1alpha1"
}
```

The example abbreviates the normalized intent; the CLI emits the complete
engine result. Failure envelopes contain only `command`, `ok: false`, `schema`,
and a closed `{code, message}` error object, except that privacy-safe
`GITHUB_RESULT` and `GITHUB_OPERATION` failures retain their validated result
or bounded operation-failure record for review/resume handoff. Instance drift, missing managed
files, and interrupted state failures additionally retain the validated
privacy-safe instance result (per-file states or local plan state) alongside
the error so callers can resume from observed state. Runtime engine mismatch
results separate `configuredEngine` and `runtimeEngine`; they do not expose
exception text or input paths.

Exit status is deliberately small and explicit:

| Status | Meaning |
| ---: | --- |
| `0` | Command completed successfully |
| `1` | Current contract rejected the selected input |
| `2` | Usage or unsupported-command error |
| `3` | Local environment or internal CLI error |

For the instance commands, bounded filesystem and instance-state I/O failures
that reach the current engine are closed contract outcomes and retain exit
`1`; they do not become a generic environment diagnosis. Generic frontend
output/stream failures, unrelated environment failures, and internal CLI
failures remain exit `3`. The installed Python import API is not a qualified
surface in this slice; use the `rs9` command or the documented source entry
point.

Instance drift, missing managed files, unsafe managed files, and interrupted
partial writes are not successful CLI results. They return the closed
contract-rejection envelope and exit `1`, leaving unmanaged publisher files and
consumer `.rs9/` content untouched.

Managed instance files must have exact mode `0644`; a mode-only mismatch is
drift even when bytes are unchanged. The writer applies this mode after
creation despite the caller's umask. An authorized local operator may use a
non-destructive `chmod 0644` repair and re-check, but the CLI never overwrites
drifted bytes implicitly.

Output encoding, closed-stream, and broken-pipe failures return `3` without a
traceback; a broken stdout pipe is redirected to a disposable null sink so
interpreter shutdown does not emit a second flush error.

The CLI does not install consumer packages or claim native runtime acceptance,
authenticated remote readiness, activation, or publication. A provisioning
`adopt-exact` result is a bounded protocol outcome for an explicitly observed
repository; it is not a live qualification, release, or publication claim.
