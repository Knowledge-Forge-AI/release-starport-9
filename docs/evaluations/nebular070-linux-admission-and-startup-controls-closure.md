# Nebular 0.7.0 Linux admission and startup controls

Status: accepted source checkpoint. Fresh hosted qualification and actual release evidence remain pending.

The Linux Nix smoke path now runs fixed display, DBus and Node controls after the original application failure. They use the same FHS prefix and PATH resolution seam, retain bounded status/size/digest/shape facts, and cannot replace the failing application gate. Commands have a five-second cap and a shared 30-second execution budget; probe cleanup is separately bounded. Dirty cleanup or an unreaped child stops subsequent controls. Existing runner policy and privileges are unchanged.

The version-scoped publisher now binds pre-wheel native portability evidence to an external post-wheel admission. Stage A is captured as payload_portability.json and anchored to the approval's manylinux_stage_a_sha256. Stage B remains outside the wheels and binds the four floor/newer Linux consumer members, their raw hashes and source coordinates, the three-target matrix and wheel readback. The floor host must report glibc 2.36; the newer host must be above it. Git commit/tree coordinates remain distinct from source-candidate digests.

Resume and final verification carry the mandatory matrix_receipt.json and preserve canonical equality checks. The generated qualification step reads its Stage-B path from the current command's shell output, avoiding an unavailable same-step GitHub output. The generator and emitted workflow agree. These records rely on the existing authenticated capture chain; self-consistent JSON alone does not establish genuine execution.

Verification: 103 affected diagnostic tests passed. The final resulting publisher source passed 82 focused tests under Python 3.13.12 with bounded process/output capture. Root verified that the final receipt's 16 source frames match the accepted postimages. Independent code review identified the workflow and documentation corrections; the closing revision addressed them and decomposed the new consumer materializer. There was no second independent review after that revision. The reviewer could not access the external test-output directory; root separately verified the retained receipts and streams.

The prior a991 hosted campaign passed its 2,678-test unit suite, including 34 skips, Darwin Nix, three wheel lanes and native-package lanes. Both required Linux Nix lanes still failed application smoke with exit 127 and an unknown-startup diagnostic. This checkpoint does not resolve that runtime failure.

Release remains held. Follow-up work must tighten unresolved CPU-observation handling, assemble actual Stage-A bodies, collect final native and installed floor/newer consumer evidence, and complete current hosted gates before OIDC exchange or upload. Synthetic fixtures and compiler defaults are not native portability qualification. The 0.6.1 route and publication permissions are preserved.

Rollback reverts the twelve modified source/test/workflow files, removes the four new manylinux modules/tests and this record, and leaves the separately approved runner policy intact.
