# Current RPM diagnostic policy preparation

Status: blocked, diagnostic-only preparation. This source change does not authorize a native run, an exception, signing, publication, indexing or client qualification.

## Selection and identity contract

`load_policy(path=None, *, generation=HISTORICAL_GENERATION)`, `_validate_policy(policy, *, generation=HISTORICAL_GENERATION)` and `evaluate_policy(raw_evidence, inventory, inputs, policy=None, *, generation=HISTORICAL_GENERATION)` retain their historical defaults. The existing `CURRENT_VERSIONS` historical constant and historical policy remain unchanged.

`build_rpm_candidate(..., generation=HISTORICAL_GENERATION)` passes current selection explicitly into policy loading and evaluation. The hosted RPM path selects the closed source-owned `rpm_policy_path(generation)` and supplies the loaded policy explicitly. A failed current selection supplies an invalid current policy for rejection; it never reloads historical policy. The existing `current_generation.py` path helper is an integration prerequisite owned by the distribution qualifier work, outside this patch.

Current versions are fixed in source: Burst 0.7.0, Loom 0.5.0, Solar Sail 0.3.0 and Nebular Fusion 0.7.0. A policy JSON document cannot choose another version or infer generation. Cross-generation policies reject. Current validation also requires the exact source-owned current asset coordinates, architecture scope, CLI wrapper definitions and Nebular caller contract. The source catalog is coordinate input, not native acceptance evidence.

Loom and Solar use noarch. Burst and Nebular use x86_64/aarch64, each on the corresponding Linux system. Nebular uses the current thin raw archives, not portable archives. Its public `tfnf` symlink is declared separately from CLI node wrappers. Existing complete preservation inventory verifies the constructed public files and release members.

## Deliberately blocked policy

The top-level and all four product statuses are `blocked`, with `blocking: true`. Every product has `exceptions: {}`. `production_enabled` and `publication_authority` are both false. Current validation rejects an authorized status, nonempty exception rules, altered strict tool constraints or altered current identity contracts.

The permitted exception vocabulary remains `env-script-interpreter`, `non-executable-script` and `files-duplicated-waste`; none is authorized for this generation. The unwaivable classes remain `no-changelogname-tag` and `explicit-lib-dependency`. Existing rpmlint 2.8.0 / 2.8.0-2.fc43 identity, exit 0/64, filter count 8, complete raw parsing and package/spec requirements remain strict.

An unconditional `current-generation-diagnostic-only` blocker prevents clean raw lint from becoming accepted. There is no current partial-proof or clean-lint route to acceptance. Historical authorization/disposition labels and exception rules were not copied.

## Nebular runtime floor

Current Nebular `runtime_requires_contract` binds the current caller contract's installed Loom package metadata member, SHA-256 and `/engines/node` pointer. Its archive contract includes that member and the sidecar manifest. The current builder invokes `release_runtime_floor(archive, entry, capture=capture)`, using the actual authenticated capture already supplied to the builder. That helper owns authentication and current archive binding. The historical call remains `release_runtime_floor(archive, entry)`.

## Raw evidence and stop boundary

The existing rpmbuild, RPM query and raw rpmlint operations remain before policy evaluation. The valid blocked current policy reaches that path. A rejection retains the existing raw findings/receipt, spec and package identities, construction witness and quarantine custody. Hosted failure handling stops before repository indexing, signing and client qualification. No diagnostic bypass, lint filter relaxation, synthetic native receipt or acceptance shortcut was added.

CLI npm closure hashes are null with `held_pending_observed_npm_closure`; unavailable current closure hashes were not copied from history or invented. Fresh native construction must observe and bind those closures and complete inventories. This policy intentionally cannot accept them even after evidence appears. Any later exception disposition requires separate human review of observed current native findings and a separate source/policy change. Historical receipts cannot supply that disposition.

## Verification and limits

Pure tests cover cross-generation rejection, JSON version/asset/wrapper tampering, strict tool constraints, clean-lint rejection, unwaivable errors, selected-policy failure without historical fallback, raw lint before policy, retained unsigned/spec/witness evidence, no downstream signer/repository/client path, and actual current capture argument forwarding with the unchanged historical floor call.

Native commands in those tests are tool doubles. These checks prove source contracts and orchestration only. They do not prove actual rpmbuild output, current raw rpmlint findings, native runtime behavior, package installation, signing or hosted qualification. The policy is ready for parent review and later integration with the qualifier's generation/summary wiring; workflows, caller/smoke code and shared checkouts are outside this patch.
