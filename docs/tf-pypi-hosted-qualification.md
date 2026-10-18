# Native qualification of the first Theme Forge PyPI cohort

This successor adds native macOS ARM64 qualification to the three existing
workflow identities. A push to `rs9-tf-pypi-hostqual1` runs qualification only.
It does not update `main`, publish a package, or consume a pending publisher.

Each workflow first builds the exact approved Darwin distributions on Ubuntu.
Its `native_consumer` job downloads those same-run artifact bytes onto `macos-15`,
checks the actual host architecture and source commit, and exercises the existing
wheel and sdist install/command/rebuild/uninstall lifecycle under macOS network
denial. Python and Node network-denial probes remain mandatory. The original
published npm/native input archives and committed Python artifact hashes do not
change. Tool setup happens before network denial. No package cache is shared.

Native receipts identify the source commit, Python and Node versions, artifact
set and functional lifecycle. A failed probe is a failed job, with a separate
failure receipt when execution reached the consumer entrypoint. Reports are
uploaded even after test failure. Receipt output directories must be physical.

Publication remains an explicit workflow-dispatch action on `main`, protected
by its existing `pypi` environment. It now depends on **both** `build_verify` and
`native_consumer` in the same run. The preparation branch cannot execute the
publish job. A successful branch qualification is not a registry upload or a
claim that every historical RS9 control is green. The five historical conflict
paths and all retained private evaluation files remain excluded from this
public-source projection.

After evidence review, promote the same tested commit without rewriting it
when possible. If source changes or merge resolution changes the candidate,
qualify the new commit before publishing. Preserve failed workflow attempts;
do not automatically rerun them or recreate a branch to hide their results.

The initial artifact scope is Darwin ARM64 only. These runs do not establish
Linux, Intel macOS, Windows or additional Python-version support. APGR's separate
publication workflow and artifact selection remain unchanged. Nebular Fusion
is not added to this first pending-publisher cohort.
