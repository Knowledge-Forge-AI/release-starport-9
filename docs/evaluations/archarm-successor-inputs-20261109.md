# ArchARM dependency-input successor, 2026-11-09

Three frozen Arch Linux ARM package downloads and their signatures became
unavailable. The owner approved only these replacements: desktop-file-utils
0.28-1 to 0.29-1, fakeroot 1:2.1.4-1 to 2:1.37.2-1, and libstemmer 3.1.1-1 to
3.2.0-1. Fakeroot is an epoch rebaseline. The other 136 package records, base,
signing certificate, official mirror, container controls and tool versions stay
fixed. No additional dependency provider is admitted.

The distinct `successor-20261109` profile contains 139 packages totaling
201,488,096 bytes. Its package-pin SHA-256 is
`a0896233d98b32fde260c6139321dfc64be4efa345585ee16bdbdd4ffdd2f207`.
The historical origin records, original loader and original pin file remain
unchanged. Selection is explicit: Nebular 0.8.0 uses the successor; the existing
0.7.1 route retains the historical profile. Unsupported versions refuse before
SDK acquisition. The public SDK API accepts only named profiles, and the producer
checks the returned rootfs and package-pin digests against its selected identity.

The new inputs passed the original public native ARM runtime probe
[42653433050](https://github.com/Knowledge-Forge-AI/theme-forge-packages/actions/runs/42653433050)
at packages commit `0407736e2cf542a25cf521a45fbe95f11f30ccb6`.
All 139 package signatures, all 32 runtime predicates and cleanup passed.
The original result ZIP is artifact `13691106928`, 1,081 bytes, SHA-256
`a6689b55e419fb36f33651b0da4636f26283d79670b1cd8fa4a489dc478b2c4f`;
its sole result body is 2,097 bytes, SHA-256
`30515943aff4c1fd56021effa5ad9f7ce9d9a551c1d9179e34099a57b20a5616`.
The retained source manifest and original artifact were authenticated locally;
the maintained controller accepted the result's closed schema and predicates.

This evidence qualifies the dependency runtime. The ported SDK implementation
still declares `MODULE_NATIVE_QUALIFIED = False`; product construction, all
native client controls, original source custody, signing and publication require
their separate gates. Current builder custody includes the new pin file and
Python identity module. Historical builder hashing remains unchanged.

The admitted class retains GPL-2.0-or-later/GPL-3.0-or-later/BSD-3-Clause notices
as applicable to the three upstream packages. Their signatures and exact archive
hashes were verified, direct and reverse dependencies were checked against the
authenticated frozen base and unchanged package set, and the native runtime
probe supplies compatibility evidence. No host installation or product runtime
dependency change occurs. The fixture's aggregate download size decreases by
11,356 bytes. A fresh original fifteen-job RS9 campaign must independently pass
before using this source for downstream signing qualification.

Rollback restores historical profile selection in a reviewed source revision;
it does not relabel old results or silently select another package set. The old
URLs remain unavailable, so such a rollback does not claim restored publication
readiness. Failed original campaigns and dependency decisions remain immutable.
