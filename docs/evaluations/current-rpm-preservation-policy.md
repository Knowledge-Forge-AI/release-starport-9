# Current RPM preservation policy proposal

Status: prepared for independent review and owner approval. The proposed current policy permits exact preservation findings for the current four releases. It does not grant production signing or publication authority. Historical policy selection and defaults remain unchanged.

## Observed findings

Original Actions run 41015086215 used source commit 19f075c735fe1a27e907da2fc43480b9bfe869f0. Both original RPM artifacts were retained with their authoritative ZIP digests. Each architecture reported 17 errors and 166 warnings under rpmlint 2.8.0-2.fc43 with the existing eight filters.

| Product | Version | Errors / warnings, each architecture | Preserved error classes | Waste-exception duplicate groups, each architecture |
| --- | --- | --- | --- | --- |
| Stellar Burst | 0.7.0 | 5 / 12 | four non-executable scripts; duplicate waste | 5 |
| Stellar Loom | 0.5.0 | 2 / 7 | two environment interpreter scripts | 0 |
| Solar Sail | 0.3.0 | 1 / 6 | one environment interpreter script | 0 |
| Nebular Fusion | 0.7.0 | 9 / 141 | two environment interpreter scripts; six non-executable scripts; duplicate waste | 130 |

Current Nebular has 130 duplicate groups, rather than the historical 128. Burst's current dependency closure and five duplicate groups were derived independently; a coincidentally unchanged waste total does not inherit historical authority. No additional preservation class or duplicate origin was needed. Warnings remain visible and are not converted into exception rules.

## Exact admission

The existing current policy file contains proposed complete `authorized` rules. The loader also accepts the original explicit `blocked` diagnostic shape, which continues to refuse admission. Unknown, partial and malformed dispositions refuse. Caller-supplied flags or modified policy JSON cannot authorize: the complete proposed policy must equal the physical selected source-owned file and satisfy the exact current version, catalog, caller and architecture contracts.

Each system has its own source inventory and payload manifest binding, including platforms whose resulting hashes coincide. Stable identity includes complete expected file projections, permitted directories, legal copies, wrappers, archive contract members and the Node floor. Volatile inode/device values are excluded from persisted identity; observed runtime file identity, unique inodes, ownership, byte preservation and duplicate proofs remain mandatory. Exact script rules bind the archive, member, digest, mode, shebang and launcher or authenticated caller role. Exact duplicate rules bind every group, group set hash and permitted waste total. Missing, extra or repeated raw errors cannot collapse the expected exception set.

Current Nebular still requires the existing live authenticated caller capability and runtime floor proof. Saved JSON cannot recreate that capability. Source archives, lock integrity, observed header and CPIO payload bytes were joined independently. The original complete inventory query ledger was unavailable; retained test observations are explicitly reconstructed, rather than presented as the original executed query ledger. RPM header field interpretation was checked against the [upstream RPM 6.0.0 tag definitions](https://raw.githubusercontent.com/rpm-software-management/rpm/rpm-6.0.0-release/include/rpm/rpmtag.h).

## Validation and remaining gates

Pure regressions exercise actual retained raw findings for both architectures, blocked policy behavior, source ownership, wrong versions, asset/closure/manifest/inventory hashes, paths, classes, architectures, duplicate groups, raw count collapse and inode aliases. Serialized Nebular observations refuse; the private actual-byte evaluation separately reconstructs the genuine authenticated caller evidence before evaluating both Nebular cases.

All eight retrospective evaluations accept the exact proposed preservation findings while raw lint remains `fail`. This does not requalify the original run, which remains bound to its original source and blocked policy. Adoption changes source and configuration identity and requires fresh hosted qualification. Derivation, custody, repository/client operations, application/native-addon smoke and Pages gates remain required.

The existing `rpm-lint-policy-exceptions-not-raw-clean-not-fedora-qualified` promotion restriction remains mandatory. The strict distribution input verifier continues to reject that restriction. Own-repository production admission is a separate unresolved decision; neither exception acceptance nor candidate qualification supplies it. Production and publication flags remain false.

## Operational effect and alternatives

The proposal changes test admission only. It does not rewrite payload bytes, shebangs, executable modes, wrappers, legal copies or package versions. Existing runtime/caller requirements remain. Historical full-workflow policy and all runner/tool/dependency selection remain unchanged. Future releases or changed raw findings fail these exact rules until separately reviewed.

The alternatives are to retain the diagnostic block, obtain upstream payload changes, or redesign package contents. Those alternatives require their own source and runtime evidence. The preservation option keeps actual released bytes with narrowly bound evidence and visible raw failures. It adds no dependency, installation or license grant. Existing dependency license copies remain present; observed locked dependencies retain their MIT or BSD-3-Clause terms.

Rollback restores the prior blocked current policy and corresponding loader state, or selects an explicitly valid blocked current disposition. Historical defaults remain available. No maintained adoption, hosted execution, production signing or publication is established by this preparation.
