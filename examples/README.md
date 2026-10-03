# Contract examples

These are RS9-authored, non-production illustrations under RS9's existing
license. They describe tenant facts; they do not grant rights to tenant
payloads or automatically acquire a tenant's license when copied. A steward
decision on a permissive example-file exception is deferred. Independently
authored tenant `.rs9` files remain tenant-repository material.

- `theme-forge/theme-forge-nebular-fusion/.rs9`: the first executable extraction,
  using three observed 0.6.1 native archive mappings and current package names.
- `destinations.example.toml`: illustrative destinations, including staged APT
  and AUR. A destination's presence is no publication authorization.
- `../tests/fixtures/synthetic-mit-tool`: invented MIT payload metadata to test
  license preservation and npm/PyPI shapes; no real package or release exists.

The validator neither downloads nor authenticates releases. Separate Foundation 2
modules authenticate captured bytes and render shadow recipes from this example.
It remains an RS9-authored stand-in, with explicit summary, tagged icon selection
and upstream launcher paths. License reconciliation, runtime/provider closure,
trust binding and qualification remain migration gates.

The Nebular example and golden manifest provisionally match distro packaging's
`AGPL-3.0-or-later` expression. That agreement is not tenant license authority and
does not resolve npm's `OR Commercial` declaration. Foundation 2 authenticated
tagged/payload license parity and confirmed that the published wrapper bytes
contain the conflicting expression. See the
[candidate](../docs/foundation2-candidate.md) and
[qualification](../docs/foundation2-qualification.md). Public shim checks do not
replace GUI/sidecar readiness qualification.

Use Python 3.11 or newer, without installing anything:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m rs9.contract validate examples/theme-forge/theme-forge-nebular-fusion --destinations examples/destinations.example.toml
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m rs9.contract normalize examples/theme-forge/theme-forge-nebular-fusion --destinations examples/destinations.example.toml --version 0.6.1
```

Normalization proves configuration relationships, not publication readiness.
