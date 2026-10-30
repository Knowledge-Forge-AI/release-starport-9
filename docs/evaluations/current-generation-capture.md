# Current Theme Forge generation capture

Status: source capture slice evaluated; publication and native qualification remain held.

## Scope

The closed selector `theme-forge-current-202610` selects separate bootstrap,
configuration and release expectation files for these exact releases:

| Product | Version | GitHub release ID | Tagged commit |
| --- | --- | --- | --- |
| Stellar Burst | 0.7.0 | 424873797 | `3edb9d2c40dd19a2b7d97d9309bc210e7fed711c` |
| Stellar Loom | 0.5.0 | 423916361 | `9063fe5d283881f464ab566d8b74296a6ce1b688` |
| Solar Sail | 0.3.0 | 423916603 | `eafd594af8bce04ef3752c489ae770946b4e0e3b` |
| Nebular Fusion GUI | 0.7.0 | 426333162 | `cadb40c4972f68f314096ff60fbcfb4da950c161` |

Omitting the selector retains `theme-forge-live1`, the historical author-aligned
manifest, expectations and behavior. Unknown selectors fail closed. Candidate
capture and command report CLIs accept `--generation`; attended authentication
accepts the keyword argument without changing its publication controller.
Hosted lane capture, reporting and fallback capture pass the same selector.
The native backends' `(capture, intent, profile)` tuple interface is unchanged.

The checked manifests still require exact-generation scope, forbid future
releases, bind configuration inventories and reject tagged `.rs9` configuration.
Generation JSON and persisted capture summaries grant no runtime capability.
Every successful capture still requires fresh core release authentication,
exact release expectations, `load_bootstrap`, configuration authority and
profile evaluation. Gate1's hardcoded path validation is unchanged.

## Published npm receipt profile

The three current npm releases publish `root-package.receipt.json`, but no
standalone release `NOTICE` asset. Their new, separate profile is
`npm-root-receipt-archive.v1alpha1`; the legacy package profile and its
`provenance`/`notice` role requirements remain unchanged.

The new profile selects the actual package archive, root receipt and checksums,
and authenticates tagged `package.json`, `LICENSE`, `NOTICE` and
`COMMERCIAL-LICENSE.md`. Packaged identity and bin declarations must agree
with the tagged identity and intent. Present packaged legal copies must equal
tagged source. No packaged legal copy is required; any present copy must
equal authenticated tagged source.

The inspected published receipts have two schemas:

- Burst's `tf.burst-release-root-receipt.v1` identifies the product, repository
  and version and names the exact npm archive in `references`, with size and
  SHA-256. The profile requires one matching reference and the published false
  signature, provenance and publication admission claims.
- Loom and Solar's `tf.js-release-root-package-receipt.v2` identify the npm
  package and version and bind its `archive` size, SHA-256 and SHA-512 SRI.

Receipt and archive bytes remain bound to the authenticated release record.
Producer/preflight source coordinates inside receipts are historical inputs;
the profile does not equate them to the public tag or claim source equivalence.
Receipt consistency is unsigned publisher evidence. It grants neither native
qualification nor publication authority.

Nebular uses the existing reviewed system-WebKit intent structure, native CI
provenance asset and desktop authority profile. No desktop profile relaxation
was required.

## Observed verification

Four exact-version GitHub release API readbacks matched the supplied release,
tag and asset coordinates. Fresh core authentication additionally verified the
repository, commit and tree bindings against exact expectations. Release
mutability remains recorded truthfully as `immutable: false`.

A fresh, read-only current4 capture passed for Burst 0.7.0, Loom 0.5.0,
Solar 0.3.0 and Nebular 0.7.0 through the real capture and authentication path.
The resulting captured bytes were also reauthenticated through expectations,
bootstrap authority and profiles against the resulting source state. Current
command inspection reported 11 command/launcher rows and zero unavailable
assets. Nebular's three captured executable hashes matched the supplied native
executable identities. No native payload was executed.

Focused verification:

```sh
PYTHONPATH=src python3 -m unittest \
  tests.test_current_generation tests.test_candidate_capture \
  tests.test_profiles tests.test_author_aligned_bootstrap \
  tests.test_hosted_candidate
```

Result: 30 tests passed. They cover historical defaults, unknown generation
refusal, exact current metadata, configuration tampering, forbidden future
scope, tagged `.rs9` refusal, real bootstrap capability requirements, JSON
capability refusal, receipt/archive binding failures, legal copy mismatch,
post-authentication receipt tampering, mixed release expectations and selector
propagation into reports and hosted fallback capture. `git diff --check` passed.
These are focused source checks, not a full repository or hosted native gate.

Fresh capture bytes and transient diagnostics remain operator-visible task
scratch; they are not committed as capabilities or durable publication evidence.

## Held follow-up contracts

1. `nix/candidate-products.json` and its consumers still describe historical
   product inputs. Current-generation catalog bindings require a separate slice.
2. `operators/live1/command-contracts.json` and `hosted_commands.py` still own
   historical version expectations and command bindings. Current command
   research, binding and qualification require a separate slice.
3. `nebular_callers.py` still binds `v0.6.1` caller inputs. Nebular 0.7.0 caller
   authentication and installed caller qualification require a separate slice.
4. Public hosted native Nix/APT/DNF/pacman builds, installation, GUI/caller
   execution and resulting-state review remain required before publication.
   No workflow dispatch, local native build, Docker/Nix build, signing or
   production transport occurred in this slice. AUR remains deferred.

This source capture result does not qualify native packages, authorize a
successor tree or establish publication completion.
