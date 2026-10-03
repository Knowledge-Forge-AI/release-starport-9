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

The validator neither downloads nor authenticates releases. These examples are
not migration-ready: license authority, release authentication, desktop assets,
dependencies, trust binding and qualification remain gates in the migration map.

The Nebular example and golden manifest provisionally match distro packaging's
`AGPL-3.0-or-later` expression. That agreement is not tenant license authority and
does not resolve npm's `OR Commercial` declaration. FOUNDATION2 must reconcile
tagged repository and payload terms before adopting generated metadata; the
golden may change with that evidence. The proposed `--version` stdout check has
not been executed against an authenticated release binary in this phase.

Use Python 3.11 or newer, without installing anything:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m rs9.contract validate examples/theme-forge/theme-forge-nebular-fusion --destinations examples/destinations.example.toml
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m rs9.contract normalize examples/theme-forge/theme-forge-nebular-fusion --destinations examples/destinations.example.toml --version 0.6.1
```

Normalization proves configuration relationships, not publication readiness.
