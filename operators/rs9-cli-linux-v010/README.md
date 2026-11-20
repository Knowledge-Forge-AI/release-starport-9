# RS9 0.1.0 Linux repository signing

The unsigned archive contains the three audited architecture-independent
packages and the exact APT indexes. Its member and archive identities are in
`inputs.json`. Each package was built from the original v0.1.0 wheel and
retains its 49 files. The auxiliary input release preserves the published
v0.1.0 wheel and source archive inventory.

The signing workflow builds its disposable tool image from digest-pinned
Fedora and Arch bases. DNF verifies Fedora package signatures and the
Dockerfile checks the resulting full RPM package inventory. The Arch
`repo-add` runs with its original helper files. This image is internal
workflow tooling and uses the upstream Fedora and Arch package licenses.
Use the existing `rs9-signing` environment for the protected subkey. The
signer imports it in a private temporary directory inside a network-disabled
container and uses separate passphrase input for RPM signing. Only the signed
public output passes into the artifact.

The signer verifies APT's embedded and detached Release signatures, checks
RPM CPIO parity and signature trust, and verifies the DNF metadata and both
pacman architectures' package and index signatures. It also signs an exact
file inventory for downstream admission. The hosted artifact is the input to
native client qualification and the separate guarded Pages deployment.
