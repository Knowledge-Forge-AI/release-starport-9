# Bootstrap tenant manifest v1alpha1

Status: implemented loader; real-release qualification pending.

`bootstrap/pre-rs9/theme-forge-live1/manifest-author-aligned.json` is the current
LIVE1 configuration authority. The historical
`bootstrap/pre-rs9/theme-forge-live1/manifest.json` remains byte-identical
archival evidence for the CONT5 legal/readback guard and is not a current
selector. Both manifests use the schema `rs9.bootstrap-tenant-manifest.v1alpha1`, with
`bootstrap-pre-rs9=true`, `release-contains-rs9=false`, `scope=exact-generation`
and `future-releases=forbidden`. The manifest makes no claim that a release
contained these files.

Each project binds repository name/id, tag, version, release id, tag commit/tree,
the physical configuration directory and `config_sha256`. The configuration hash
is SHA-256 of canonical JSON for the sorted `(path, sha256)` inventory of that
directory. The approved manifest hash is SHA-256 of its exact stored bytes.
`intent.json` supplies ingestion selection data; `channels.json` records pending
downstream intent and observe-only channels, without authorizing transport.
Asset digests belong in the authenticated ingestion record. The operator's
expectations are independent hard-stop comparisons; they are not tenant config.

`load_bootstrap` requires an authenticated in-process release capture, an
independently approved manifest hash, an exact tuple match, an unchanged config
inventory and matching release-selection hash. It rejects a tagged `.rs9/` tree,
changed tag/commit/release/version, links, and absent allowlist approval.
`authenticate` and the publication planner enforce `require_configuration_authority`.
Normal ingestion requires every tagged `.rs9/` blob, including project/release files,
to be captured and bound to the normalized input hashes. Capture normal releases
with `selection_for_intent(intent, include_configuration=True)`. The bootstrap loader
registers a nonserializable exact-intent exception on the capture and rechecks the
approved manifest/config bytes at planning. This exception never matches future tags.

`authenticate_shadow` preserves historical read-only diagnostics without granting
configuration authority. Shadow captures cannot pass planning unless a separately
approved exact bootstrap is loaded or tagged configuration is authenticated.
The preparation operator checks all config hashes and safe project identifiers
before selecting network requests or creating per-project evidence directories.

The example Nebular `.rs9/` files are historical examples. Operators must not
merge them with bootstrap configuration or silently choose between authorities.
The historical manifest hash and all four config hashes are in the frozen
candidate inventory; the forward manifest has no adoption inventory yet. The
current forward manifest SHA-256 is
`f31bd4ddc1caf0f591b1d8447c1bf694ffa822994fc5f88bb346a3292227bf78`; this is a
review identifier only, not a production approval.

Manifest `license_authority.files` records tagged source authority evidence.
When present, the loader requires every listed authority file to be selected by
the intent/profile before capture (`BOOTSTRAP_LICENSE_AUTHORITY` otherwise).
It is separate from the desktop intent's `license.files`, which lists native
payload legal copies. Nebular requires `LICENSE` and `NOTICE` inside its native
archives; tagged `COMMERCIAL-LICENSE.md` remains selected through `TAURI_SOURCES`
and authenticated as community/commercial-offer evidence. The npm-profile
bootstrap lists retain their broader source-selection meaning.

The CONT5 reviewed-manifest candidate digest is
`93081d30cb2eedb88eb6248653177ab03570dbd51f7047293e25670d860b8e64`.
Its Nebular configuration inventory digest is
`b985546482cfff16436d166ff3ba175b54b4afc03b35c48e4310cf070690c27f`.
These identify source bytes for review, not production authorization.
