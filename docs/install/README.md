# Theme Forge installation channels

Status: **RS9 LIVE1 pending / not live.** None of the new RS9 channels below is
ready for installation. The four products keep their already-released versions:
Stellar Burst 0.6.1, Stellar Loom 0.4.0, Solar Sail 0.2.1 and Nebular Fusion 0.6.1.

| Channel | Intended LIVE1 coverage | Current status |
|---|---|---|
| PyPI | Four project names; pure CLI wheels where truthful, native wheels only for qualified platforms | Pending availability, ownership, artifact and install qualification |
| Nix | RS9 flake; Linux x86_64/aarch64 and macOS arm64 as qualified | Package/app outputs withheld |
| pacman | Signed RS9 repository, x86_64 | Pending native packages, clients, signatures and hosting |
| DNF/RPM | Signed RS9 repositories, x86_64/aarch64, separately qualified Fedora families | Pending; no Fedora family claimed supported |
| APT | Signed RS9 repository, Ubuntu 26.04 amd64/arm64 | Pending; no Debian 13 claim |

[Publication readiness and remaining checks](../live1-candidate.md) lists the
qualification needed before install commands can be advertised. Canonical new
repository URLs will use `https://rs9.knowledge-forge.ai/` after verified hosting
and TLS. The convenience alias must preserve path and query. This candidate does
not assert current DNS, TLS or Pages readiness.

Existing npm and [Homebrew tap](https://github.com/Knowledge-Forge-AI/homebrew-tap)
channels remain managed by their existing authorities. Use each upstream project's
current instructions:

- [Stellar Burst](https://github.com/Knowledge-Forge-AI/theme-forge-stellar-burst)
- [Stellar Loom](https://github.com/Knowledge-Forge-AI/theme-forge-stellar-loom)
- [Solar Sail](https://github.com/Knowledge-Forge-AI/theme-forge-solar-sail)
- [Nebular Fusion](https://github.com/Knowledge-Forge-AI/theme-forge-nebular-fusion)

The [legacy distribution repository](https://github.com/Knowledge-Forge-AI/theme-forge-packages)
is retained as reference and rollback evidence. LIVE1 does not repair its generator
or establish a new permanent client URL there. After exact production readback,
install, upgrade, uninstall and trust instructions require a separately reviewed
documentation update bound to the published generation.
