# Adapter and destination boundary

Status: contract design with executable intent validation only. Package builders,
publishers, signers, projection writers and contribution clients are deferred.

## Inputs and ownership

The intended adapter consumes normalized tenant facts, an authenticated ingestion
record (repo/tag/commit/assets/hashes/license evidence), qualified operator
destination/trust policy and publication state (versions/revisions/readback).
Adapters must not discover alternate upstreams or silently rebuild release bytes.
The foundation normalizer emits only tenant intent and raw configuration hashes;
it supplies none of the authentication, trust or qualification records.

Core owns release authentication, canonical records, native payload identity,
qualification state and publication receipts. Adapters own construction and
ecosystem-specific readback/signature/install verification. Destinations own
repository topology, shared indexes, origin, retention and trust binding.
Credentials live in operator facilities, with references in a future separate
operator contract. They are absent from this foundation's interpreted schema.

## Modes and results

| Mode | Intended effect | Required future readback |
|---|---|---|
| direct | Registry publication or atomic hosted-repository generation | Exact package content/identity and registry metadata, or authenticated signed index and installed payload. |
| projection | Controlled updates to required repos, including tap and one AUR repo per package | Generated tree, upstream base, allowed paths, commit/PR identity, projection binding and merged/current tree. |
| contribution | Reviewed packaging proposal in external repos | Source/build policy, branch/PR identity, upstream review/merge outcome and contribution-specific qualification. |

A projection can travel by PR without becoming contribution mode: the distinction
is whether RS9 owns the generated projection or proposes an ecosystem-maintained
package. Registry is a direct destination, not a fourth mode.

Future adapter output must report upstream input hashes, artifact hashes,
transformations, recipe identity, effective architecture coverage, package
license, qualification receipts and destination readback. Stable schemas for
those reports are deferred until a real shadow adapter supplies evidence.

## Retry and publication state

Read authenticated destination state before any mutation. An absent package may
be published after qualification. An exact already-published result is a no-op.
The same version/revision with different bytes or identity fails. Partial or
unverifiable state fails pending operator disposition. A timeout after a mutation
requires readback, not blind retry. Projection updates require a current base and
an allowed-path diff; contribution completion is never inferred from opening a PR.

Multi-package npm ordering (platform packages before launcher), registry-specific
immutability and failed partial fanout require adapter qualification. An index
rebuild must retain the previously authenticated objects clients may still name.
APT's current guard permits first/unchanged generations but blocks changed indexes
until retention is implemented. Repeated equivalent static-tree generation must
not accidentally advance tenant versions or packaging revisions.

## Trust and qualification

Private keys/passphrases/tokens never enter tenant files, fixtures, source or
public evidence. Public trust binding must identify key fingerprint, signing
subkey, validity/rotation and key URL independently from payload licenses.
Fixture keys are confined to qualification; they must fail production binding.
OIDC is registry-specific, and publisher identity must be proven rather than
derived from the location of reusable code.

Package qualification eventually includes tamper/signature failure, clean install
and uninstall, architecture/runtime closure and native byte readback. A GUI launch
needs a display-capable harness. Contribution channels requiring source builds
have separate provenance and byte rules; they cannot reuse a binary-preservation
receipt as proof of source-build compliance.
