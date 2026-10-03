# Authenticated input record v1alpha1

Status: implemented candidate for the Nebular shadow profile. Canonical JSON uses
sorted keys, two-space indentation, UTF-8, LF and a final newline. No timestamp,
private path, volatile API field or authentication assurance flag participates in
record identity. The captured HTTP receipt is separate scratch evidence.

`rs9.ingestion.v1alpha1` has this explicit output field allowlist:

| Field | Bound evidence |
|---|---|
| `repository` | Exact full name and numeric GitHub repository id |
| `release` | Numeric release id, selected tag, draft/prerelease state |
| `tag` | Resolved commit/tree, annotated tag object chain, target comparison basis |
| `assets` | Tenant asset id/name/platforms, GitHub asset id, size/SHA256, archive root, commands/launchers, manifest hash and member count |
| `evidence_assets` | Checksums, provenance, SPDX, notices and npm wrapper asset identities/digests |
| `source_files` | Tagged path, recomputed Git blob SHA1, SHA256 and byte length |
| `payload_license_copies` | Exact project license path, source relationship and agreeing byte hash |
| `license` | Exact declarations, reconciliation status and syntax-only limitation |
| `npm_support` | Wrapper identity, digest, GitHub attachment parity, registry integrity agreement, legal-file hashes and safe payload manifest binding |
| `icon` | Tagged source relationship, commit/hash and derived square hicolor size |
| `limits` | Freshness, self-asserted provenance and acceptance limitations |

Asset presence is exact and unambiguous. Each uploaded required asset needs a
GitHub `sha256:` digest. Downloaded bytes must match size and digest; authenticated
SHA256SUMS must independently agree for every non-self selected asset. SHA256SUMS
uses strict lowercase hexadecimal, two spaces and unique filenames. Drafts fail;
prereleases follow tenant policy. Lightweight and bounded annotated tags are
supported. Branch-valued release targets use the resolved tag as authority;
SHA-valued targets must agree. A truncated recursive source tree fails closed.

Tagged source files must be regular Git blobs, with locally recomputed blob
identities matching the captured tree. Current project license copies at the
archive root (or app Resources directory) must match their tagged source bytes.
Nested third-party license files are preserved but are not project license
declarations. Publisher provenance lineage/raw/executable assertions are
cross-checked where present, without claiming independent signer authentication.

Archive inspection never extracts. It bounds decompressed bytes including
metadata, per-member bytes, compression ratio, count and link traversal. Absolute,
non-NFC, dot/traversal/control/backslash paths, duplicate members, unsafe links,
cycles, non-directory ancestors, privileged modes and special members fail.
Commands and selected launchers must be executable regular nonlink files. Full
per-member manifests stay in scratch and are bound by canonical hashes.

The supporting npm wrapper is hash-equal to its GitHub attachment, agrees with
registry SHA512 integrity, and is safety-inspected through the same archive code.
It is legal evidence, not a package input for these adapters. Registry license
metadata is distinct from the artifact's actual package.json declaration.
Tagged NOTICE/COMMERCIAL declarations record whether they used an explicit SPDX
expression or the exact GNU AGPL v3.0-or-later prose observed in this profile.
A commercial-offer sentence alone is not converted into an SPDX expression.

The collector is public/no-token HTTPS only, checks every redirect and forbids
repository-identity redirects. It ignores environment proxies, bounds response
size and transfer time, and records request receipts separately. This first
profile selects Nebular's observed Tauri/license/evidence paths; future tenants
need an explicit profile rather than an invented universal layout.

Errors are sanitized `ContractError` codes. Missing/duplicate assets, malformed
evidence, digest/checksum mismatch, source/provenance disagreement, unsafe archives
or missing license copies produce no record. Partial collection never silently
downgrades to fixture authentication. Offline records demonstrate captured-byte
consistency; fresh HTTPS collection is a separate evidence claim.
