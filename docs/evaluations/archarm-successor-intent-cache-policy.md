# Successor ArchARM generated desktop cache policy

Status: proposed source and test-runner policy; adoption and fresh native
qualification require owner approval. Passing local checks do not qualify the
SDK or make the failed campaign acceptable.

## Observed failure and upstream evidence

Original current-distribution run
[42709547826](https://github.com/Knowledge-Forge-AI/release-starport-9/actions/runs/42709547826)
at `30f8961a8b22aefc12363f48c4480a33bfcffcb6` failed the AArch64
Nebular post-remove inventory with one added path:
`usr/share/applications/intent.cache`. Package construction, application checks,
canonical import and SDK/fixture teardown passed. The separate inventory failure
also makes the folded client cleanup gate fail. The retained native evidence
does not identify the entry's kind or contents.

The already approved successor's desktop-file-utils 0.29-1 archive has SHA-256
`cd8a30c717a8df9c2db78209ac3c6fe23c0ea7e651a081a638240127c0512453`.
Its ALPM hook runs `update-desktop-database --quiet` after installation, upgrade
and removal of desktop entries. The exact updater contains the `intent.cache`
filename. The [official 0.29 source release](https://www.freedesktop.org/software/desktop-file-utils/releases/desktop-file-utils-0.29.tar.xz)
documents and implements the new cache. The [XDG specification](https://specifications.freedesktop.org/intent-apps/latest/#cache)
describes this generated cache. These sources support the cache explanation;
they do not retroactively establish the failed entry's kind.

## Exact proposed acceptance

Only `ArchArmClient.inventory` selects the existing parser's regular-file
callback, and only when both conditions hold:

- the SDK's `pins_qualified` value is literally `True`;
- its `packagePinsSha256` equals the successor-20261109 package-pin digest
  `a0896233d98b32fde260c6139321dfc64be4efa345585ee16bdbdd4ffdd2f207`.

The callback matches only the exact relative leaf
`usr/share/applications/intent.cache`. This applies symmetrically to all inventory
stages of clients using that qualified successor SDK. Regular-file contents and
modes at this one cache leaf cease to affect the before/after comparison. The
exception does not authenticate those contents or prove them benign. A regular
hardlinked entry is still a regular file under the existing protocol.

Schema, digest, path, entry-count and resource-limit validation occurs before
the callback. Directories, symlinks, special entries, neighboring names and
children stay inventoried. The global Pacman exclusions, scanner argv, scanner
hashing, 32 MiB capture bound, ordinary 8 MiB bound, legacy/historical SDKs,
x64 Pacman, APT and DNF are unchanged. No cache priming or deletion command is
added; cleanup and application gates retain their existing behavior.

## Alternatives and limits

Priming the ARM cache before the baseline would preserve cache-content comparison
but adds a new guest command and state transition. Removing the cache after
uninstall adds deletion authority. A global regex would broaden the policy to
other contexts and entry kinds. The proposed existing parser callback has the
smallest execution and scope change.

No dependency, package pin, public certificate, capability, trust context,
permission, timeout, workflow or diagnostic-retention class changes. Local tests
exercise the actual client inventory method and framed parser with in-memory
receipts, not a running SDK or package manager.

## Adoption, qualification and rollback

If approved, land the exact three-path patch and require both full hosted unit
gates and one fresh original 15-job current-distribution campaign to pass.
Any failure stops without automatic retry or evidence stitching. A nonregular
native cache entry remains a failure. Signing, GUI and production publication
must still meet their separate existing gates; no deployment is triggered by
this policy. The previously conditional queued/null canonical policy remains
inactive because its required original refusal was not observed.

Rollback reverts these three paths and requires fresh qualification before
later adoption. Historical evidence and the failed original run remain intact.
