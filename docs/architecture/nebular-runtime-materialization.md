# Nebular release runtime representation

Status: materializer mechanics tested with fixtures; actual native proof not run.

The released verifier source compares file mode bits exactly to its manifest and
rejects symlink ancestors. Fresh tagged-source observation agrees with the legacy
diagnostic: store-normalized 0555 files differ from a 0755 manifest despite equal
bytes. That establishes the code predicate, not a successful native remediation.
The real raw/store/materialized comparison remains a mandatory gate on Darwin
arm64 and Linux x86_64/arm64.

`rs9.materialize` copies an authenticated tree into a physical user-cache root,
restores manifest modes, verifies inventory, hashes and modes, and atomically
adopts the resulting payload. It rejects changed cache contents, path escapes,
unexpected files and sidecar/launcher symlinks. Fixtures cover concurrent reuse,
store-like modes, directory/link inventory and tampering. No upstream binary or
verifier is modified. Native wheel/Nix integration remains withheld.

Required proof: raw extraction passes smoke A/B/C on its matching architecture;
the actual Nix store representation fails with the exact verifier mismatch;
byte-identical materialized contents pass the released verifier and smoke. Record
file/directory mode inventories, sidecar/service outcomes and exact payload hashes.
All smoke runs occur outside the Nix build sandbox. A store derivation or static
metadata check is insufficient.

For Linux, derive every ELF interpreter/SONAME and resolve the complete FHS closure
on each architecture. The missing `libgdk_pixbuf-2.0.so.0` is a diagnostic, not the
dependency solution. Check dynamic-loader traces for host leakage. Software/Xvfb
smoke does not qualify every GPU/EGL driver path on non-NixOS hosts; record that
coverage limit separately.

Cache location ancestors must satisfy the released no-symlink rule. Canonicalizing
a symlink does not prove its original ancestry safe. Cache markers must stay
outside the verifier-covered tree. Uninstall checks must separately report any
documented user-cache residue. The present Nix candidate exposes no launchable
Darwin application or Nebular package until these proofs exist.
