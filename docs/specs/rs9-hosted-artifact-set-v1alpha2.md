# Hosted artifact set v1alpha2

Status: Non-production candidate contract.

Every source-declared artifact directory contains artifact-manifest.json, one lane-system.json receipt and exactly the manifest's objects. Logical file identities are path, size and SHA-256. Paths are unique physical relative paths; symlinks, extra objects and mixed provenance fail.

Provenance contains source_commit, workflow_sha256, contract_sha256, builder_source_sha256, release_ingestion_sha256, ref, event and attempt. Builder identity hashes an ordered inventory of the reviewed Python/Nix builders and target/command configuration. Release identity hashes a canonical release/tag/asset/checksum/provenance projection; transport time and redirect URLs remain per-capture evidence and are excluded from equivalence.

Lane receipts state preparation network access separately from the runtime denial mechanism and outcome. Darwin offline remains not-run; fixture identities are explicitly non-production.

The manifest includes schema, lane/system, runner/tool facts, files, production_enabled:false, publication_authority:false and qualification_receipt_hashes. Files carry kind:custody|evidence and promotion:candidate-only|candidate-policy-pending|fixture-test-only. Unsigned RPM custody and fixture-signed RPM identities are distinct. Linux Nebular wheels are candidate-policy-pending.

Uploaded archive digests are produced by GitHub artifact storage, outside the logical manifest (embedding an archive's own digest would be circular). The operator binds API artifact ID/name/digest/size/expiry to the exact run and commit and preserves these fields in its packet. Future consumers must check both archive custody and every logical object.

Pages tree inventory includes all paths and object hashes. Merkle leaves hash 0x00 followed by a four-byte big-endian UTF-8 path length, the path bytes and the 32-byte content SHA-256. Interior nodes hash 0x01 plus left/right hashes. Leaves are sorted by path bytes; odd nodes are promoted unchanged. Empty inventories are refused. The implementation and test vectors in pages.py are authority. A public tree up to 2 GiB is retained whole. The split fallback retains the tree index, non-package objects and newly fixture-signed RPM objects because signing changes their bytes; unchanged package bytes are held by their family artifact manifests.

The aggregate checks the exact source-defined lane set, required gates and products, receipt hashes, manifests, job conclusions and provenance. A qualified result requires no required failure/not-run or policy blocker. Darwin's precisely declared unsupported offline gate is allowed and remains visibly not-run. Hosted records cannot satisfy Foundation 3 attended production gates.
