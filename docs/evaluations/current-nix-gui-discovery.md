# Optional Nix GUI discovery observation

Status: private combined diagnostic proposal; native qualification pending.
The observer adds source-bound runtimeFacts metadata and uses the existing FHS
Node for a bounded filesystem observation. It changes no runtime package list,
FHS recipe, payload, application environment, original smoke argv, required gate
or original/replay deadline. A failed or successful observation admits no native
application, release, bootstrap or publication capability.

Selected store files use no-follow/nonblocking opens, bounded reads and stable
fstat frames. Nanosecond times are canonical decimal strings preserving exact
BigInt equality; malformed/negative/out-of-range times refuse. Other stat fields
still require JS safe integers, so unusually large device/inode identities may
produce a fail-closed unavailable diagnostic. Final JSON is projected to the existing 64-KiB diagnostic-custody limit, keeping a deterministic prefix of records and recomputed per-root counts when needed. It is preflighted through the existing custody privacy/size validator and atomically placed under the lane diagnostics folder, which is retained on later smoke failure. A privacy rejection becomes a small safe optional-failure record; custody policy is not widened. Partial count/read/output bounds
remain explicit; canonical envelope expansion also falls back to typed partial
facts. Optional observation/output failures cannot replace required results.

The source-owned closure list restricts normalized symlink target strings.
Physical intermediate-component sealing is not claimed. A single target outside
that list fails the observation; its scope is not widened. Roots are observed
in a shared bounded traversal, and zero retained records is not proof of an
empty or completely walked root when status is partial. No package-output
selection or closure-completeness claim has been evaluated through Nix here.
The actual pinned output roots still need validation during authorized hosted
qualification. No glib output or provider choice was changed speculatively.

The production Node script has no subprocess/network/environment operations;
its in-memory fs double is used only by pure tests. The lane's existing
runtime_environment allowlist excludes NODE_OPTIONS. No new environment or
process runner policy is introduced. The diagnostic uses a 30-second direct-child helper timeout independently of the original qualifying smoke deadline; descendant cleanup is not newly established. It runs before smoke and may warm the page cache, so a later timeout disappearance would have that confound.

Focused tests use synthetic filesystem doubles, not live store traversal.
They cover modern/sub-ms stat changes, malformed and bounded observations,
symlink cycles/closure escapes, exact stream limits, nofollow output custody,
optional error continuation, and successful artifact retention without a gate and real pipeline failure-path custody.
These facts establish local diagnostic behavior only; original GUI startup and
the Linux Nix timeout cause remain unresolved.
