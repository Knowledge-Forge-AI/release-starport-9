# Current generation catalog and command selection

Status: source slice implemented; runtime and public qualification remain held.
Generation: `theme-forge-current-202610`. Production remains disabled.

## Scope and identity

The closed selector chooses a separate Nix catalog and command contract for
Stellar Burst 0.7.0, Stellar Loom 0.5.0, Solar Sail 0.3.0, and Nebular Fusion
0.7.0. The default remains `theme-forge-live1`. Historical catalog and command
contract bytes are unchanged. Unknown selectors fail before path access or lane
actions. Selection is passed explicitly through the hosted pipeline, native,
Debian/Pages, wheel, Nix, and PRoot command consumers.

Current Nix preparation validates the complete four-product capture set before
creating inputs. Native catalog system keys must exactly match the authenticated
payload systems. Missing and extra systems fail with a contract error. Catalog repository, version, tag, commit, archive name, digest,
size, root, executable, launcher, Node entry points, engine, and Nebular icon
coordinates must agree with fresh in-process authenticated captures and intents.
The icon digest and size describe the actual tagged `src-tauri/icons/icon.png`.

| Product | Tagged source commit |
| --- | --- |
| Stellar Burst | `3edb9d2c40dd19a2b7d97d9309bc210e7fed711c` |
| Stellar Loom | `9063fe5d283881f464ab566d8b74296a6ce1b688` |
| Solar Sail | `eafd594af8bce04ef3752c489ae770946b4e0e3b` |
| Nebular Fusion | `cadb40c4972f68f314096ff60fbcfb4da950c161` |

## Command evidence

Current command implementations were inspected inside authenticated release
archives. Each contract records exact implementation digests and tagged source
identity. Binding verifies archive digests, implementation digests, guards, and
release identity before authorizing a probe. Differing implementation bytes for
the same archived path across platforms are refused in either payload order.
Archived bytes retain precedence over tagged source. Both current binders parse
the same immutable archive bytes they hashed. Current audit records include the
selected generation and canonical command-contract digest; mixed generations
and changed contracts cannot reuse bindings. Historical audit and diagnostic
shapes, and historical unbound-probe short-circuit behavior, are preserved.

Loom's released batch implementation still emits `EMPTY_INPUT` with exit 1 for
empty input. Burst's released Studio implementation still supports the bounded
1.0 initialize/initialized/shutdown/exit lifecycle. Those probe semantics are
unchanged. Nebular's released launcher implements its 0.7.0 version response;
this does not establish GUI caller qualification.

Current bindings also require an ephemeral in-process capability. Serialized
JSON is audit evidence and cannot recreate that capability. Historical behavior
is preserved.

## Verification

110 focused Python tests passed: current catalog/commands and capture tests;
historical command, Nix, native, PRoot and wheel tests; scripted Debian client-cycle tests, and scripted native packaging generation
forwarding tests. Synthetic protocol fixtures execute only fixture Python.
Released applications, package builders, containers, installers, Nix, signing,
and hosted CI were not executed.

A separate static check reauthenticated all four captured releases, bound all
four catalog rows and all six command contracts, and refused 19 mutations to
version, tag, commit, command paths, native executable digest, icon digest, and native platform coverage.
The check establishes source/archive agreement only.

Catalog file SHA-256:
`887328b4d919a767cc854d7aa18e3f7eea060bf6fe520a608eaf2bcbaab13d05`.
Command-contract file SHA-256:
`ea45ec4b6763c154ba814e9828df5177944b2cd37d523b5d42ea992cbe88c9f8`.

## Held integration and limits

Current wheel builds refuse a mismatch between the selected intent version and
the historical wheel-builder product table before invoking a builder. Building
current wheels is outside the selected distribution scope.

The wheel-client subprocess currently receives serialized command audit rows.
That transport cannot authorize current-generation probes. A later bounded
integration must make the selected authenticated capture evidence available to
the child, reauthenticate it there, and call `bind_commands` with the explicit
selected generation before probing. JSON-only current bindings stay unbound;
required probes are not promoted to passing.

A source-wide AST scan found two remaining unthreaded command calls in the
separate `tf_pypi_nebular` path (`bind_commands` and `run_probes`). Their current
generation integration remains held outside this distribution slice.

Current Nebular caller contracts, current RPM policy contracts, installed
acceptance, and main-push public qualification remain separate held slices.
No workflow, publication, deployment, dependency, or historical metadata change
is part of this slice.
