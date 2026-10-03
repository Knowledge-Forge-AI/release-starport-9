# LIVE1 PyPI candidate requirements

Status: source preparation only; no real wheels, name ownership or publisher setup qualified.
Names and application versions remain theme-forge-stellar-burst 0.6.1,
theme-forge-stellar-loom 0.4.0, theme-forge-solar-sail 0.2.1 and
theme-forge-nebular-fusion 0.6.1. No upload or name reservation was performed.

CLI wheels must embed the authenticated package release plus the exact tagged
lockfile runtime closure, with dependency legal files in PEP 639-relative license
locations. No npm installation occurs at wheel install or launch. Their launchers
check external Node >=22. Architecture-independent tags require an inspected closure
without native or platform-limited dependencies. Loom batch empty-input output must
match the released command, including exit status and both output streams.

The Darwin Nebular builder retains the exact compressed release and reviewed helper
bytes, restoring a verified tree into a locked user cache. Its arm64 tag is at least
macosx_11_0_arm64. Uninstall removes the distribution; the verified application cache
is separate user state and must be documented/tested. Released sidecar/native scenario-A
and honest platform dependencies are mandatory, still not-run.

Linux Nebular wheels remain withheld. A glibc floor alone cannot promise manylinux
compatibility where GUI dependencies are outside the portability contract. A disclosed
auditwheel deviation does not repair an inaccurate platform tag. The compatibility
promise must be proved before a wheel is offered.
[Platform tags](https://packaging.python.org/en/latest/specifications/platform-compatibility-tags/),
[PEP 600](https://peps.python.org/pep-0600/).

No sdist is emitted. These builders wrap immutable application release artifacts and
do not implement a source-build backend. An sdist that silently downloads native
assets at build time would not be truthful. Investigation of the actual upstream
source-build capability is blocked on fresh source/release capture; this is not a
claim that upstream cannot build from source.

Official PyPI documentation was read during this work stage. The default per-file
limit is 100 MB; every actual wheel must be measured before upload. No real candidate
size has been measured here.
[Storage limits](https://docs.pypi.org/project-management/storage-limits/).

For each manager-authorized name, the intended Trusted Publisher binding is owner
Knowledge-Forge-AI, repository release-starport-9, workflow filename
rs9-pypi-publish.yml, environment pypi. The future protected production workflow must
be separately implemented and independently reviewed; rs9-candidate-tests.yml is not
an upload workflow and has no id-token permission. PyPI matches workflow filename and
environment, while GitHub's upload job needs id-token: write for OIDC. Do not add a
token fallback. Owner and project setup remain manager attestations.
[Publisher configuration](https://docs.pypi.org/trusted-publishers/adding-a-publisher/),
[OIDC usage](https://docs.pypi.org/trusted-publishers/using-a-publisher/).

A pending publisher may create a project on its first authorized publication. It
does not reserve the name; an intervening creation by another account can invalidate
that path. Immediately reread project and version state before setup and publication.
An exact metadata URL 404 may mean absent; download errors, rate limits and DNS/TLS
failures remain unknown. No secret or account credential belongs in evidence.
[Pending publishers](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/).
