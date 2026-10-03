# Staged migration map

Status: future migration design; no live cutover authorized or performed. Incorporates Foundation 3 pure publication control plane (observation derivation, safety gates, pure planner, revision allocator, receipts, and retry evaluation).

Keep current authoritative publication surfaces operational until an RS9 equivalent independently qualifies in shadow against one actual release. Retain current generators and known-good signed generations as rollback inputs. A signing, publisher, or domain change is a separate operator action with client compatibility and verified rollback; a passing configuration validator or pure plan grants none of that authority.

| Surface | Preconditions and staged adoption | Compatibility and rollback |
|---|---|---|
| `theme-forge-packages` | Canonicalize unpublished generator/workflow changes and repair hosted qualification. Foundation 2 rendered Nebular shadow recipes; Foundation 3 models destination observation, evidence-bound gates, pure planning, receipts, and retry logic. Only after independent qualification replace the generator and later publication orchestration. | Keep repo, URLs and current trust unchanged during machinery replacement. Preserve frozen DIST1 generator, receipts and previous signed tree; restore through current publication machinery. |
| APT overlay | Remains staged, not live. Operator decides whether to fold into DIST1 before RS9 or adopt its qualified behavior directly. Preserve Ubuntu 26.04 amd64/arm64 support, target-derived Depends, SHA256 indexes/by-hash, dual metadata signatures and destination keyring. Changed indexes require authenticated previous-generation retention and corresponding provenance/verifier semantics first. | Never advertise Debian 13 Node support. Keep candidate isolated until qualification. Roll back to prior served signed generation and retain pool/by-hash objects needed by clients. Initial trust and keyring upgrade trust are distinct. |
| `homebrew-tap` | Render formulas in shadow, qualify install/test/payload and compare observed formulas. Later controlled PRs update only adopted families' formulas/docs. APGR stays separately managed until adopted. | Keep Homebrew-shaped tap and formula names; preserve other families. Manual formula maintenance remains rollback. |
| npm | Fresh API reads found current Burst/Loom/Sail release tarballs with lock-matching reported digests. Authenticate downloaded assets and resolve source/build/release-repository identity. Read-only registry/GitHub byte parity first. Qualify npm provenance repository compatibility and OIDC route. Then separately authorize publication and exact-match/partial-fanout behavior. | Never silently rewrite `package.json.repository`, repack an asset or assume central `--provenance` works. Retain current TF helper/token policy until a qualified replacement is approved. Existing immutable versions remain untouched. |
| future PyPI | Produce authenticated wheels/sdist, define package/runtime/license facts and independently qualify PyPI publisher/caller claims, clean install and registry byte readback. Synthetic fixture proves shape only. | No claim of existing Theme Forge PyPI artifacts or credentials. Retain any future tenant publisher until RS9 qualifies; no PyPI production path exists to cut over here. |
| stable custom-domain serving | Operator separately configures canonical RS9 origin and path/query-preserving convenience redirect. Serve identical signed tree in parallel, qualify client downloads/trust, then update snippets through reviewed compatibility changes. | Current github.io URLs continue to work. DNS, Pages and redirect rollback must retain existing client paths and signed bytes. Key branding/UID disposition is independent; do not combine domain and trust migration. |
| future AUR projection repos | Confirm account/SSH authority and current ecosystem registration policy; don't treat historical registration availability as permanent. Qualify one repo per package and current native architecture recipes. Shadow first, then explicit submission authorization. | Preserve staged recipes. Existing AUR clients/maintainers govern updates; no repo is created here. |
| official-repository contributions | One ecosystem-specific ADR and policy/maintainer/source-build qualification before PR automation. Cover nixpkgs, Homebrew upstream and distro repositories separately. | Contribution mode follows ecosystem review and source policy; binary-preservation direct-channel receipts cannot substitute. Withdraw or amend unmerged proposals; upstream release rollback remains ecosystem-owned. |

## Unresolved migration gates

1. **Release authentication across release streams**:
   Authenticate release/tag lineage and downloaded asset bytes. Read-only genericity and byte-compatibility evidence is recorded in the [Foundation 3 candidate](../foundation3-candidate.md).
2. **Nebular's genuine license conflict**:
   Nebular's npm wrapper declares `AGPL-3.0-or-later OR Commercial` while tagged Git source and release archives declare `AGPL-3.0-or-later`. This conflict remains **unresolved**; tenant authority must decide. Syntax-only acceptance does not settle it, and RS9 cannot invent a resolution.
3. **Current signing authority branding, UID domain, and rotation**:
   Preserve established trust until an independently qualified operator change.
4. **Hosted GUI/FHS checks and display smoke qualification**:
   Qualify display-dependent launch in a suitable test harness without modifying payloads.
5. **Native platform coverage and dependency/desktop/icon authority**:
   Nebular has both-architecture released-byte dependency records, deterministic desktop facts, and a tagged 256px PNG selection. Runtime/resource, provider, and install qualification remain bounded by Foundation 2 evidence.
6. **npm/PyPI publisher identity and provenance compatibility**:
   No registry fallback or byte transformation is implicitly authorized.
7. **APT candidate's native hosted obligations and authenticated generation retention**:
   Changed indexes require previous-generation retention before publication adoption.

## Current control plane adoption gate

`RS9-FOUNDATION3-PUBLICATION-CONTROL-PLANE`: Verify observation derivation, evidence-bound gates, pure planner actions, revision allocation, execution attempt auditing, confirmed receipts, and deterministic retry evaluation in pure offline test harnesses. No live signing, production publication, external repository mutation, or cutover is authorized.

## Local Links

- [ADR 0004: Ingestion core and evidence profiles](../adr/0004-ingestion-core-and-evidence-profiles.md)
- [ADR 0005: Publication state, planner, and receipts](../adr/0005-publication-state-planner-and-receipts.md)
- [Adapter and destination boundary](adapter-destination-model.md)
- [Architecture overview](../architecture.md)
- [Foundation 2 candidate](../foundation2-candidate.md)
- [Foundation 2 qualification](../foundation2-qualification.md)
