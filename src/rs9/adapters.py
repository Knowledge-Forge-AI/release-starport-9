"""Limited adapter naming, asset selection and destination intent."""
from rs9.constants import adapter_schema
from rs9.errors import ContractError
from rs9.fields import platforms, schema, strings, table, typed, unique_rows
from rs9.security import validate_ecosystem_name, validate_slug


def selected_assets(package, assets):
    references = strings(package.get("assets"), "package.assets")
    if not set(references) <= set(assets):
        raise ContractError("UNKNOWN_REFERENCE", "Undeclared package asset")
    return [assets[reference] for reference in references]


def validate_formats(adapter, assets):
    allowed = {"npm": {"npm-tarball"}, "pypi": {"wheel", "sdist"}}
    if adapter in allowed and any(a["format"] not in allowed[adapter] for a in assets):
        raise ContractError("FORMAT_RESTRICTION", "Inappropriate registry asset format")


def validate_package(adapter, value, assets):
    package = table(value, {"id", "name", "assets", "platforms"}, "package", required={"id", "name", "assets"})
    validate_slug(package.get("id"), "package.id")
    validate_ecosystem_name(adapter, package.get("name"))
    selected = selected_assets(package, assets)
    validate_formats(adapter, selected)
    independent = any(a["platforms"] == ["any"] for a in selected)
    concrete = set().union(*(set(a["platforms"]) - {"any"} for a in selected))
    if "platforms" in package:
        restriction = platforms(package["platforms"], False)
        if not independent and not set(restriction) <= concrete:
            raise ContractError("SUBSET_VIOLATION", "Package platforms exceed asset coverage")
    if independent and concrete and adapter != "pypi":
        raise ContractError("AMBIGUOUS_COVERAGE", "Mixed independent and concrete assets are unsupported")


def validate_publish(value, packages):
    publication = table(value, {"package", "destination"}, "publish", required={"package", "destination"})
    reference = typed(publication.get("package"), str, "publish.package")
    if reference not in packages:
        raise ContractError("UNKNOWN_REFERENCE", "Undeclared publication package")
    validate_slug(publication.get("destination"), "publish.destination")


def validate_adapter(adapter, doc, assets):
    table(doc, {"schema", "packages", "publish"}, "adapter file", required={"schema", "packages"})
    schema(doc, adapter_schema(adapter))
    packages = typed(doc.get("packages"), list, "packages")
    if not packages:
        raise ContractError("INVALID_CONFIG", "Adapter packages cannot be empty")
    for package in packages:
        validate_package(adapter, package, assets)
    unique_rows(packages, "id")
    publications = typed(doc.get("publish", []), list, "publish")
    for publication in publications:
        validate_publish(publication, {p["id"] for p in packages})
    pairs = [(p["package"], p["destination"]) for p in publications]
    if len(set(pairs)) != len(pairs):
        raise ContractError("DUPLICATE_IDENTIFIER", "Duplicate publication intent")
    names = {p["id"]: p["name"] for p in packages}
    identities = [(p["destination"], names[p["package"]]) for p in publications]
    if len(set(identities)) != len(identities):
        raise ContractError("AMBIGUOUS_COVERAGE", "Multiple intents name the same destination package")
