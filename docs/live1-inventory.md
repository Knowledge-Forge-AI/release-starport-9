# LIVE1 candidate inventory

Status: source/configuration candidate only; no authenticated downstream artifacts.

The machine-readable [candidate manifest](../operators/live1/candidate-manifest.json)
lists bounded product-source/config/documentation/workflow files by relative path,
size and SHA-256. It separately records the bootstrap raw hash and each config
inventory hash. It excludes itself, `.git/`, `.serena/`, interpreter caches and
temporary test fixtures to avoid a circular inventory or unrelated-state adoption.
Its hash is reported in the terminal handoff; it is not a publication receipt.

| Group | Candidate responsibilities |
|---|---|
| Ingestion/bootstrap | Exact generation config, expectation comparison, tagged source/tree integrity, pinned npm closure authentication, repository-authoritative Nebular profile |
| Publication control plane | Mandatory adapter gates, local verifier capabilities, observe-only policy, sealed live readback and fresh plans, conservative persisted-attempt replay |
| Package builders | Deterministic wheel constructor and pacman/RPM recipe candidates; APT recipes, Burst staging and native Nebular wheel integration withheld |
| Nix/runtime | Unexposed candidates and generic mode materializer; pinned lock/FHS/native gates pending |
| Repository retention | Deterministic bounded APT indices, public Pages scanner and immutable signed-object retention; real signing/native clients pending |
| Operators/evidence/docs | Preparation operator, setup packets, pending install index, metadata/readiness/preparation/gate matrices, exact scope/proposal disposition and APGR onboarding note |

`authenticated_release_records`, `downstream_artifacts`, `qualification_records`,
`publication_plans` and `publication_receipts` are empty in this handoff. A new
candidate inventory must bind actual unsigned/signed package bytes and real evidence
before independent production readiness review. The manifest cannot authorize
transport merely by listing source hashes.
