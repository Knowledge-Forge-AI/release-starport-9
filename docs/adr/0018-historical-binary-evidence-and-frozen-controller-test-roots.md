# ADR 0018: Historical binary evidence and frozen controller test roots

Status: proposed checkpoint amendment; review required. Admission remains BLOCKED.

## Context

The development checkout contains source modules outside the immutable E1
controller inventory. E1 activation documents `--controller CHECKOUT` and verifies
that checkout with `checkout_errors` (`operators/live1/e1-activate.py`). The
development tip is not an admissible E1 controller. Synthetic readback tests used
it as one, causing inventory refusal before their intended receipt checks.

Two tracked historical review ZIPs also predate this phase. The frozen
`candidate_inventory.file_inventory` decodes every file as UTF-8. The ZIPs cannot
pass that inventory, and removing them would destroy retained historical evidence.
AUTH1 snapshots the complete approved source before applying E1's controller
inventory, so its production admission remains blocked as well.

## Decision

Synthetic readback tests construct a separate controller using only binding-listed
source and operator files. The fixture checks `controller_errors == []` before
any deliberate corruption. All controller, symlink, source hash and isolated
import checks remain in force. This repairs the test boundary without admitting
the development tip or changing E1/AUTH1 bindings or production operators.

Product hygiene explicitly changes the former only-bounded-text invariant:
exactly two binary ZIPs listed in `tests/fixtures/historical-binary-evidence.json`
are permitted at their pinned sizes and SHA-256 digests. The fixture records mode
`100644`; hygiene checks that literal and refuses executable files, but does not
verify Git index mode or tracked status. This exception does not apply to other
binary files. Their members must be bounded UTF-8 text,
with safe names and no links, encryption, duplicate entries, unsupported
compression, extra fields, prefix or trailing data. Actual bounded decompression
and CRC checking precede credential and private-path scanning. File reads and
checks run inside per-file subtests so a bad early file cannot abort later scans.
Untracked and ignored product files remain within the existing scan boundary;
new hits must be reported without rewriting unrelated user work.

## Consequences and verification

A green hygiene result is not inventory admissibility. The two live inventory
tests and two AUTH1 tests remain failing, with exact IDs and diagnostics in
`evidence/tf-pypi/admission3-verification.json`. Frozen inventory decode errors
are retained rather than converted into expected failures. Unblocking requires
a separately authorized controller/binding migration or historical evidence
storage decision. This phase grants neither.

The manifest parent remains the original recorded parent. Raw byte rows for the
two ZIPs may be carried forward after exact reauthentication; all text rows use
the frozen inventory routine. Completeness and Git-tree calculations by scratch
tools are diagnostic and cannot replace the frozen `verify_inventory` gate.
Readiness and publication flags remain false. The REALQUAL2 combined closeout
remains BLOCKED, and the terminal amendments require dispatcher review.
