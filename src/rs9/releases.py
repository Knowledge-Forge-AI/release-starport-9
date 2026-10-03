"""Release selection and unambiguous asset mappings."""
from rs9.constants import SCHEMA_RELEASES, VALID_ASSET_FORMATS
from rs9.errors import ContractError
from rs9.fields import choice, platforms, schema, table, typed, unique_rows
from rs9.security import validate_safe_basename, validate_safe_relative_posix_path, validate_slug, validate_template


def validate_tag(template):
    validate_template(template, True, "release.tag")
    safe_tag(template.replace("{version}", "1.0.0"))


def safe_tag(tag):
    validate_safe_relative_posix_path(tag, "release.tag")
    if any(c.isspace() or c in "~^:?*[" for c in tag):
        raise ContractError("UNSAFE_PATH", "Unsafe Git tag characters")
    if ".." in tag or tag.endswith((".", ".lock")) or any(p.startswith(".") for p in tag.split("/")):
        raise ContractError("UNSAFE_PATH", "Unsafe Git tag segments")


def validate_asset(value, declared_commands):
    asset = table(value, {"id", "name", "format", "platforms", "commands"}, "asset",
                  required={"id", "name", "format", "platforms", "commands"})
    validate_slug(asset.get("id"), "asset.id")
    validate_template(asset.get("name"), True, "asset.name")
    validate_safe_basename(asset["name"].replace("{version}", "1.0.0"), "asset.name")
    choice(asset.get("format"), VALID_ASSET_FORMATS, "asset.format")
    platforms(asset.get("platforms"))
    commands = typed(asset.get("commands"), dict, "asset.commands")
    for command, path in commands.items():
        if command not in declared_commands:
            raise ContractError("UNKNOWN_REFERENCE", "Undeclared asset command")
        validate_safe_relative_posix_path(path, "asset command path")


def validate_coverage(assets):
    coverage = {}
    for asset in assets:
        current = set(asset["platforms"])
        for command in asset["commands"]:
            previous = coverage.get(command, set())
            if previous and ("any" in previous or "any" in current or previous & current):
                raise ContractError("AMBIGUOUS_COVERAGE", "Ambiguous command platform coverage")
            coverage[command] = previous | current


def validate_releases(doc, commands):
    table(doc, {"schema", "release", "assets"}, "releases.toml", required={"schema", "release", "assets"})
    schema(doc, SCHEMA_RELEASES)
    release = table(doc.get("release"), {"tag", "prerelease"}, "release", required={"tag", "prerelease"})
    validate_tag(release.get("tag"))
    choice(release.get("prerelease"), {"reject", "allow"}, "release.prerelease")
    assets = typed(doc.get("assets"), list, "assets")
    if not assets:
        raise ContractError("INVALID_CONFIG", "Release assets cannot be empty")
    for asset in assets:
        validate_asset(asset, commands)
    unique_rows(assets, "id")
    if len({a["name"] for a in assets}) != len(assets):
        raise ContractError("AMBIGUOUS_COVERAGE", "Duplicate asset name")
    validate_coverage(assets)
