# Linux Nix execution without user namespaces

Status: PRoot dependency class authorized for a candidate-only experiment; product runtime not selected or qualified.

## Context and preserved contracts

Hosted run 6 could not start Nebular's `buildFHSEnv` runtime because creation
of its UID map was denied. Darwin Nix and the wheel lanes are separate and
remain preserved. The original release archive must remain SHA-bound in the
store, and materialization must preserve every released byte and mode. Neither
ELF patching nor a rebuilt application, changed verifier, global nix-ld,
privileged container, or host setting is authorized.

## Direct loader evaluation

The concrete candidate invocation is the pinned glibc's architecture-specific
`ld-linux` with `--argv0` and `--library-path` over its matching store closure,
followed by the **unmodified** released ELF and the original arguments. An
ordinary shell wrapper can preserve argument and exit-status handling by
using `exec`. This does not make direct-loader execution suitable for the
whole application:

- Invoking ld.so explicitly makes the process executable the loader.
  `--argv0` changes argv, not `/proc/self/exe`. Rust executable discovery and
  embedded Node/SEA executable-self readers may consequently read the loader
  or derive resources and sibling sidecars from its directory.
- Nebular's authenticated Linux layout has a main executable, sibling
  `bin/tfsb-studio-service`, and `lib/sidecar-payload`. Resource discovery and
  sidecar startup must be evaluated against those exact released paths.
- A native child launched with exec uses its own foreign PT_INTERP. A parent's
  `--library-path` does not change the child's kernel interpreter resolution.
  Inherited LD_LIBRARY_PATH alone either mixes a host loader with store libc
  or leaves NixOS without the required foreign interpreter path.
- GTK/WebKit/GLib need the dynamic library closure, schemas, GIO modules and
  helper executables. A successful trivial loader command establishes none
  of the resource, descendant, signal, or offline application contracts.

The hosted source includes a bounded direct-loader evaluation probe. Its
results are diagnostics, never application qualification. It checks a normal
store-backed executable against explicit loader execution and checks the
released ELF's GLIBC symbol requirements against the pinned libc. Native
x86_64 and aarch64 execution remains owed; source tests exercise parsing and
fail-closed behavior only.

## Decision

Reject direct-loader invocation as the sole product runtime until executable
self-readers and every native child are accounted for. Keep the current
Linux harness and shadow recipe explicitly userns-dependent and unqualified;
do not qualify a different harness from the recipe that would ship.

The manager authorizes PRoot only for the explicit experimental Linux Nebular
attribute `experiments.<system>.theme-forge-nebular-fusion-proot` and its hosted
probes. It is excluded from ordinary candidates/checks and the rendered product
recipe. This dependency is confined to that attribute; it does not become part
of Agent-Central, the dispatcher, or unrelated projects. PRoot translates paths
with ptrace; it provides execution compatibility, not an isolation boundary.

The PRoot design must use the existing pinned nixpkgs source, a guest-only
LD_LIBRARY_PATH and matching pinned glibc loader/libc. It must expose the Nix
tools (Node, Python, binutils, Xvfb and D-Bus), schemas and GIO modules, and
bind the actual `THEME_FORGE_CACHE_DIR` and smoke workspace, not assume a
home-directory cache. Host executables must not enter the guest library
environment. Nix glibc's store configuration must not be assumed to consume
a guest `/etc/ld.so.cache`. Library collisions need explicit resolution.

The harness's existing `sudo unshare --net` is attended offline isolation,
not a product runtime requirement. No product wrapper may require unshare,
bwrap, a sysctl change, or host-wide nix-ld. PRoot is not a security sandbox
and would inherit the harness's separately verified network denial.

## Acceptance, dependency review and rollback

The supplied recipe was inspected and byte-checked: nixpkgs revision
`0921fdb3e13e40fe25fbc52b89661a9d6d32ac68`, recipe Git blob
`02766094fbf82ab7ee4425a14d480f061cbcdadc`, PRoot 5.4.0/tag `v5.4.0`, recursive
fetchFromGitHub source hash
`sha256-Z9Y7ccWp5KEVuo9xfHcgo58XqYVdFo7ck1jH7cnT2KA=`. This is a Nix recursive
source hash, not a release-tarball digest. The pinned derivation is Linux-only,
retains upstream GPL-2.0-or-later, and has `doCheck=false`. This metadata is not
a legal compatibility opinion and does not relicense PRoot under RS9. No
floating download or nixpkgs update is introduced. Native architecture behavior,
closure size, bind count, and timings remain measurements owed to the hosted
probe; none are inferred from source tests.

Direct-loader execution was rejected because executable-self/SEA and foreign
child interpreters remain unresolved. Host nix-ld, patched ELF assets, privilege
grants and disabled WebKit sandboxing are outside the authorized scope. The
candidate experiment tests the pinned PRoot hypothesis while retaining those
contracts and the separate network-denial harness. Success can qualify only
this candidate attribute; `published_linux_nix_ready=false` remains explicit.
Adding a top-level experiments output also changes builder-source identity and
may produce a legacy `nix flake check` unknown-output warning. Darwin evaluation
and the existing candidates/checks do not select the experiment.

Native hosted acceptance must cover executable-self identity, sidecar resource
discovery and embedded executable readers, foreign-interpreter child execution,
GLIBC compatibility, GTK/WebKit helpers and schemas, argument/exit/signal
propagation, offline runtime behavior, exact archive/materialized bytes and
modes, released verifier, and unchanged application-aware smoke scenarios.
WebKit's own descendant sandbox must be observed; disabling it is not implied.
When enabled, WebKitGTK's bwrap sandbox itself requires user namespaces;
replacing only the outer FHS runtime cannot establish a no-userns application.
Ptrace denial, missing closure, incompatible ABI, or failed smoke stays fail
or not-run. Rollback removes the experimental flake output, adapter/probes, contract rows
and separate workflow job;
it never edits released bytes, the verifier, host configuration or pins.

## Verification and deferral

Hermetic probe-contract tests are source evidence. They cannot establish Nix
evaluation/build success or native application compatibility. The original
Linux runtime repair therefore remains open pending native hosted
qualification and separately reviewed product/harness promotion. This explicit deferral is independent of the
completed RPM, Debian, inventory and Homebrew source repairs.
