# Nebular 0.7.0 native launch diagnostics

Status: diagnostic source accepted locally; fresh hosted Linux Nix observation pending.

The required Linux Nix lanes in [run 40505968017](https://github.com/Knowledge-Forge-AI/release-starport-9/actions/runs/40505968017) reached application smoke scenario B and exited 127. The existing DBus category did not identify the failed executable. The temporary user-namespace setting was restored successfully. The hosted unit suite passed with 2,676 tests reported, including 34 skips; Darwin Nix and all three wheel lanes also passed.

The diagnostic now adds a bounded `diagnostic_token` through the existing safe error-detail schema. It recognizes failed-callee templates for the DBus wrapper, daemon or configuration, Node, smoke script, and loader. It handles errno text and ASCII or UTF-8 quoting, uses the nearest failed command rather than a reporting prefix, and distinguishes a missing module from its importer. Conflicting or unrecognized targets remain unknown. Tokens describe lexical evidence; they do not establish executable existence or qualify a runtime.

Commands, subprocess ownership, replay behavior, privileges, gate outcomes, and raw-output withholding retain their existing contracts. The approved runner setting is outside this change.

Read-only independent review identified residual wrapper, importer, and ambiguity cases. The closing revision addressed them and extended the focused fixtures. There was one independent review; it did not rerun tests. The revised diagnostic suite passed 38 tests, and the related hosted-smoke/diagnostic suites passed 42 tests. Root verification of the resulting source uses those same three affected modules under Python 3.13.12 with bounded output and process lifetime. These are local component checks, not hosted or native qualification.

The source change is limited to the diagnostic module, its existing test module, and this record. The existing large test module receives a bounded addition for the same diagnostic contract; no unrelated decomposition is included. Rollback reverts this diagnostic change while preserving the separately approved runner policy.

Next: publish the changed source to the existing candidate branch and run fresh hosted CI. The actual Linux failure remains unresolved until that observation identifies the next correction.
