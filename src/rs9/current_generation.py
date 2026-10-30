"""Closed source-owned capture generations; selection grants no capability."""
from rs9.errors import ContractError

HISTORICAL_GENERATION = "theme-forge-live1"
CURRENT_GENERATION = "theme-forge-current-202610"
GENERATIONS = (HISTORICAL_GENERATION, CURRENT_GENERATION)


def generation_paths(generation=HISTORICAL_GENERATION):
    """Resolve only reviewed source locations, never caller-supplied paths."""
    if generation == HISTORICAL_GENERATION:
        # Keep the historical controller as owner of its existing constants.
        from rs9.operator import BOOTSTRAP, EXPECTATIONS
        return BOOTSTRAP, EXPECTATIONS
    if generation == CURRENT_GENERATION:
        return ("bootstrap/pre-rs9/theme-forge-current-202610/manifest.json",
                "operators/theme-forge-current-202610/expectations.json")
    raise ContractError("GENERATION_SELECTION", "Unknown capture generation")


def catalog_path(generation=HISTORICAL_GENERATION):
    generation_paths(generation)
    return ("nix/candidate-products.json" if generation == HISTORICAL_GENERATION
            else "nix/theme-forge-current-202610-products.json")


def command_contract_path(generation=HISTORICAL_GENERATION):
    generation_paths(generation)
    return ("operators/live1/command-contracts.json" if generation == HISTORICAL_GENERATION
            else "operators/theme-forge-current-202610/command-contracts.json")


def bind_catalog_product(row, capture, intent, *, generation=HISTORICAL_GENERATION):
    """Current coordinates must agree with fresh authenticated release bytes."""
    generation_paths(generation)
    if generation == HISTORICAL_GENERATION:
        return
    import io
    import json
    import tarfile
    from rs9.release_core import authenticated_record_hash, digest
    authenticated_record_hash(capture)
    record = capture.record
    repository = intent["project"]["repository"]
    if (row["id"] != intent["project"]["id"] or row["pname"] != row["id"]
            or row["repository"] != repository or record["repository"]["full_name"] != repository
            or row["version"] != intent["version"] or row["tag"] != intent["tag"]
            or record["release"]["tag"] != row["tag"] or record["tag"]["commit"] != row["commit"]
            or set(row["commands"]) != {c["name"] for c in intent["commands"]}):
        raise ContractError("NIX_CATALOG_BINDING", "Catalog release coordinates differ from authenticated intent")
    selected = {a["id"]: a for a in intent["assets"]}
    if set(selected) != {p["id"] for p in record["payloads"]}:
        raise ContractError("NIX_CATALOG_BINDING", "Catalog requires the selected release payload set")
    if row["kind"] == "materialized-desktop" and (not isinstance(row.get("assets"), dict) or set(row["assets"]) != {
            system for payload in record["payloads"] for system in payload["platforms"]}):
        raise ContractError("NIX_CATALOG_BINDING", "Catalog requires exactly the authenticated payload systems")
    for payload in record["payloads"]:
        expected = selected[payload["id"]]
        native = row["kind"] == "materialized-desktop"
        coordinates = ([row["assets"][system] for system in payload["platforms"]]
                       if native else [row["asset"]])
        archive_bytes = capture.archives[payload["id"]].read_bytes()
        if payload["name"] != expected["name"] or digest(archive_bytes) != payload["sha256"]:
            raise ContractError("NIX_CATALOG_BINDING", "Authenticated archive identity changed")
        for asset in coordinates:
            if (any(asset[key] != payload[key] for key in ("name", "sha256", "size", "root"))
                    or asset["url"] != "https://github.com/" + repository + "/releases/download/" + row["tag"] + "/" + payload["name"]):
                raise ContractError("NIX_CATALOG_BINDING", "Catalog archive coordinates differ from authenticated payload")
            if native:
                executable = payload["commands"]["tfnf"]
                launcher = payload["launchers"]["tfnf"]
                if (asset["executable_path"] != executable["path"]
                        or asset["executable_sha256"] != executable["sha256"]
                        or asset["launcher"] != launcher["path"].removeprefix(payload["root"] + "/")):
                    raise ContractError("NIX_CATALOG_BINDING", "Catalog executable differs from authenticated payload")
        if not native:
            package = json.loads(capture.source["package.json"])
            paths = {name: path.removeprefix(payload["root"] + "/") for name, path in expected["commands"].items()}
            try:
                with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:*") as archive:
                    member = archive.getmember(payload["root"] + "/package.json")
                    if not member.isfile():
                        raise ContractError("NIX_CATALOG_BINDING", "Regular archived package metadata required")
                    packaged = json.load(archive.extractfile(member))
            except (KeyError, ValueError, tarfile.TarError):
                raise ContractError("NIX_CATALOG_BINDING", "Archived package metadata unavailable") from None
            if (package["version"] != row["version"] or packaged != package
                    or row["command_paths"] != paths
                    or {k: v.removeprefix("./") for k, v in package["bin"].items()} != paths
                    or row["node_engine"] != package["engines"]["node"]):
                raise ContractError("NIX_CATALOG_BINDING", "Catalog commands differ from authenticated package")
    if row["kind"] == "materialized-desktop":
        icon = row["icon"]
        path = intent["desktop"]["icon"]["path"]
        data = capture.source[path]
        if (icon["path"] != path or icon["sha256"] != digest(data) or icon["size"] != len(data)
                or icon["url"] != "https://raw.githubusercontent.com/" + repository + "/" + row["commit"] + "/" + path):
            raise ContractError("NIX_CATALOG_BINDING", "Catalog icon differs from authenticated tagged source")
