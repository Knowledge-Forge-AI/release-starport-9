# Current-generation release asset transport

Current-generation captures download selected public GitHub release assets by
the asset ID returned in the selected release metadata. Historical captures and
the generic release collector retain the browser-download route by default.

The collector still verifies the selected repository, tag and canonical browser
URL before constructing the API path. Asset IDs must be positive integers. An
API URL present in the metadata must agree with the constructed path. API body
requests use `Accept: application/octet-stream` and the same size, transfer and
redirect limits as other public evidence downloads. There is no retry or
fallback to cached bytes or another release.

The binary request class starts only at `api.github.com`. Redirects may reach
only the existing GitHub object/release-asset hosts. When the existing read-only
GitHub identity is available, it is confined to an unredirected API GET header;
it is never forwarded to a release-asset host. Public assets can also be read
without authentication. Proxy, cookie and credential controls remain unchanged.

Changing the download route grants no authentication or publication capability.
The unchanged release authenticator still verifies asset identities, sizes,
digests, checksums, tagged source blobs and selected archive contents. Transport
receipts identify the API request class and omit redirect query values. A failed
request fails the capture and its required qualification gates.

GitHub documents binary asset downloads through either its browser URL or the
[release-asset API](https://docs.github.com/en/rest/releases/assets#get-a-release-asset),
which can stream a response or redirect to the binary content. Native hosted
qualification and original artifact custody remain required for this source.
