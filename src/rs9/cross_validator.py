"""One routing calculation shared by validation and normalization."""
from rs9.constants import LINUX_PLATFORMS
from rs9.errors import ContractError


def effective_coverage(package, destination, assets):
    selected = [assets[reference] for reference in package["assets"]]
    independent = all(asset["platforms"] == ["any"] for asset in selected)
    candidates = set()
    for asset in selected:
        candidates.update(destination["platforms"] if asset["platforms"] == ["any"] else asset["platforms"])
    candidates.intersection_update(package.get("platforms", candidates))
    effective = sorted(candidates & set(destination["platforms"]))
    if not effective:
        raise ContractError("EMPTY_PLATFORM_INTERSECTION", "Package has no destination platform")
    return effective, independent


def ecosystem_architectures(adapter, effective, independent):
    universal = {"pacman": "any", "dnf": "noarch", "apt": "all"}
    if independent and adapter in universal:
        return [universal[adapter]]
    if independent or adapter in ("nix", "pypi"):
        return sorted(effective)
    labels = {"apt": {"x86_64": "amd64", "aarch64": "arm64"},
              "npm": {"x86_64": "x64", "aarch64": "arm64"},
              "homebrew": {"aarch64": "arm64"}}
    cpus = {platform.split("-")[0] for platform in effective}
    return sorted({labels.get(adapter, {}).get(cpu, cpu) for cpu in cpus})


def resolve_target(adapter, package, destination, assets):
    if destination["adapter"] != adapter:
        raise ContractError("ADAPTER_MISMATCH", "Destination adapter does not match intent")
    effective, independent = effective_coverage(package, destination, assets)
    if adapter in ("pacman", "dnf", "apt") and not set(destination["platforms"]) <= LINUX_PLATFORMS:
        raise ContractError("UNSUPPORTED_OS", "Native repository adapter requires Linux")
    contributing = sorted(reference for reference in package["assets"]
                          if assets[reference]["platforms"] == ["any"]
                          or set(assets[reference]["platforms"]) & set(effective))
    target = {"adapter": adapter, "assets": contributing,
              "destination": destination["id"], "destination-status": destination["status"],
              "ecosystem-architectures": ecosystem_architectures(adapter, effective, independent),
              "effective-platforms": effective, "mode": destination["mode"],
              "name": package["name"], "package": package["id"]}
    for key in ("base-url", "repository"):
        if key in destination:
            target[key] = destination[key]
    return target


def resolve_targets(project_map, destinations_doc):
    destinations = {d["id"]: d for d in destinations_doc["destinations"]}
    assets = {a["id"]: a for a in project_map["releases.toml"]["assets"]}
    targets = []
    for filename, doc in project_map.items():
        if filename in ("project.toml", "releases.toml"):
            continue
        packages = {p["id"]: p for p in doc["packages"]}
        for publication in doc.get("publish", []):
            if publication["destination"] not in destinations:
                raise ContractError("UNKNOWN_REFERENCE", "Unknown destination reference")
            target = resolve_target(filename[:-5], packages[publication["package"]],
                                    destinations[publication["destination"]], assets)
            targets.append(target)
    identities = [(t["destination"], t["name"]) for t in targets]
    if len(set(identities)) != len(identities):
        raise ContractError("AMBIGUOUS_COVERAGE", "Multiple intents name the same destination package")
    return sorted(targets, key=lambda t: (t["destination"], t["package"]))


def cross_validate(project_map, destinations_doc):
    resolve_targets(project_map, destinations_doc)
