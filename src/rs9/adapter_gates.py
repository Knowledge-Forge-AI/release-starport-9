"""Adapter-owned minimum gates. Policy can add obligations, never waive them."""
from rs9.errors import ContractError

COMMON = {"release.authenticated", "license.authority", "package.render",
          "payload.identity", "provenance.binding", "build.reproducible",
          "build.platform", "install.clean", "runtime.commands", "uninstall.clean"}
REPOSITORY = {"deps.per-arch-derivation", "signature.packages", "signature.metadata",
              "trust.bootstrap", "tamper.package", "tamper.metadata",
              "index.deterministic", "pages.public-only", "domain.tls"}
ADAPTER_GATES = {
    "pypi": COMMON | {"pypi.metadata-tags", "pypi.name-state", "pypi.trusted-publisher"},
    "nix": COMMON | {"deps.per-arch-derivation", "nix.offline"},
    "pacman": COMMON | REPOSITORY,
    "dnf": COMMON | REPOSITORY,
    "apt": COMMON | REPOSITORY,
    # Foundation fixtures can exercise planner mechanics without real transport.
    "registry": {"release.authenticated", "license.authority", "package.render"},
    "npm": set(), "homebrew": set(),
}


def mandatory_gates(intent, adapter):
    if adapter not in ADAPTER_GATES:
        raise ContractError("ADAPTER_GATES", "Unqualified adapter has no publication authority")
    required = set(ADAPTER_GATES[adapter])
    if adapter in {"npm", "homebrew", "registry"}:
        return required
    if intent.get("runtime", {}).get("kind") == "native":
        required |= {"nebular.sidecar-verifier", "nebular.release-smoke"}
        if adapter in {"nix", "pacman", "dnf", "apt"}:
            required.add("desktop.integration")
        if adapter == "nix":
            required.add("linux.fhs-closure")
    else:
        required.add("runtime.cli-truth")
    return required
