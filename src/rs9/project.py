"""Tenant facts and bounded configuration-directory loading."""
from pathlib import Path
from rs9.adapters import validate_adapter
from rs9.constants import ALLOWED_PROJECT_FILES, SCHEMA_PROJECT
from rs9.errors import ContractError
from rs9.fields import choice, read_toml, schema, strings, table, typed, unique_rows
from rs9.releases import validate_releases
from rs9.security import (validate_nfc_string, validate_repository, validate_safe_basename,
                          validate_safe_relative_posix_path, validate_slug,
                          validate_summary, validate_template)
from rs9.spdx import validate_spdx_expression


def find_rs9_dir(project_dir):
    root = Path(project_dir)
    directory = root / ".rs9"
    if root.is_symlink() or directory.is_symlink():
        raise ContractError("SYMLINK_REJECTED", "Project/configuration root cannot be a symlink")
    if not directory.exists():
        raise ContractError("MISSING_REQUIRED_FILE", "Could not locate .rs9 directory")
    if not directory.is_dir():
        raise ContractError("INVALID_DIRECTORY", ".rs9 must be a directory")
    return directory


def load_project(project_dir, *, input_hashes=None):
    directory = find_rs9_dir(project_dir)
    for entry in directory.iterdir():
        if entry.is_symlink():
            raise ContractError("SYMLINK_REJECTED", "Symlinks are forbidden in .rs9")
        if entry.name not in ALLOWED_PROJECT_FILES or not entry.is_file():
            raise ContractError("UNKNOWN_FILE", "Unknown or non-regular configuration entry")
    for required in ("project.toml", "releases.toml"):
        if not (directory / required).is_file():
            raise ContractError("MISSING_REQUIRED_FILE", "Required tenant configuration is missing")
    documents = {}
    for entry in sorted(directory.iterdir()):
        documents[entry.name], digest = read_toml(entry)
        if input_hashes is not None:
            input_hashes[entry.name] = digest
    validate_project(documents["project.toml"])
    commands = {c["name"] for c in documents["project.toml"].get("commands", [])}
    validate_releases(documents["releases.toml"], commands)
    assets = {a["id"]: a for a in documents["releases.toml"]["assets"]}
    for filename, doc in documents.items():
        if filename not in ("project.toml", "releases.toml"):
            validate_adapter(filename[:-5], doc, assets)
    return documents


def validate_license(value):
    license = table(value, {"expression", "files", "source", "status"}, "license",
                    required={"expression", "files", "source"})
    validate_spdx_expression(license.get("expression", ""))
    for path in strings(license.get("files"), "license.files"):
        validate_safe_relative_posix_path(path, "license.files")
    choice(license.get("source"), {"tagged-repository"}, "license.source")
    if "status" in license:
        choice(license["status"], {"unresolved"}, "license.status")


def validate_command(value):
    command = table(value, {"name", "interface"}, "command", required={"name", "interface"})
    validate_safe_basename(command.get("name"), "command.name")
    choice(command.get("interface"), {"cli", "gui"}, "command.interface")


def validate_check(value, commands):
    check = table(value, {"id", "argv", "expect-exit", "expect-stdout-contains", "requires-display"}, "check",
                  required={"id", "argv", "requires-display"})
    validate_slug(check.get("id"), "check.id")
    argv = typed(check.get("argv"), list, "check.argv")
    if not argv:
        raise ContractError("INVALID_CONFIG", "Check argv cannot be empty")
    for argument in argv:
        typed(argument, str, "check.argv item")
        validate_nfc_string(argument)
    if argv[0] not in commands:
        raise ContractError("UNKNOWN_REFERENCE", "Check must name a declared command")
    typed(check.get("expect-exit", 0), int, "check.expect-exit")
    typed(check["requires-display"], bool, "check.requires-display")
    if "expect-stdout-contains" in check:
        typed(check["expect-stdout-contains"], str, "check output")
        validate_nfc_string(check["expect-stdout-contains"])
        validate_template(check["expect-stdout-contains"], False, "check output")


FREEDESKTOP_MAIN_CATEGORIES = {
    "Audio",
    "AudioVideo",
    "Development",
    "Education",
    "Game",
    "Graphics",
    "Network",
    "Office",
    "Science",
    "Settings",
    "System",
    "Utility",
    "Video",
}
FREEDESKTOP_ADDITIONAL_CATEGORIES = {
    "IDE",
}
ALL_FREEDESKTOP_CATEGORIES = FREEDESKTOP_MAIN_CATEGORIES | FREEDESKTOP_ADDITIONAL_CATEGORIES


def validate_desktop(value, commands):
    desktop = table(value, {"command", "categories", "icon"}, "desktop",
                    required={"command", "categories", "icon"})
    command_name = typed(desktop.get("command"), str, "desktop.command")
    cmd_map = {c["name"]: c for c in commands}
    if command_name not in cmd_map:
        raise ContractError("UNKNOWN_REFERENCE", "Desktop command must name a declared command")
    if cmd_map[command_name].get("interface") != "gui":
        raise ContractError("INVALID_CONFIG", "Desktop command must have gui interface")

    categories = strings(desktop.get("categories"), "desktop.categories")
    for category in categories:
        if category not in ALL_FREEDESKTOP_CATEGORIES:
            raise ContractError("INVALID_CONFIG", "Desktop categories must be from the allowed category set")
    if not any(category in FREEDESKTOP_MAIN_CATEGORIES for category in categories):
        raise ContractError("INVALID_CONFIG", "Desktop categories must include at least one main category")
    if (({"Audio", "Video"} & set(categories) and "AudioVideo" not in categories)
            or ("IDE" in categories and "Development" not in categories)):
        raise ContractError("INVALID_CONFIG", "Desktop category prerequisite is missing")

    icon = table(desktop.get("icon"), {"source", "path"}, "desktop.icon",
                 required={"source", "path"})
    choice(icon.get("source"), {"tagged-repository"}, "desktop.icon.source")
    validate_safe_relative_posix_path(icon.get("path"), "desktop.icon.path")
    if not icon["path"].endswith(".png"):
        raise ContractError("INVALID_CONFIG", "Desktop icon path must end with .png")


def validate_project(doc):
    table(doc, {"schema", "project", "license", "runtime", "commands", "checks", "desktop"}, "project.toml",
          required={"schema", "project", "license"})
    schema(doc, SCHEMA_PROJECT)
    project = table(doc.get("project"), {"id", "name", "repository", "family", "summary"}, "project",
                    required={"id", "name", "repository"})
    validate_slug(project.get("id"), "project.id")
    if not typed(project.get("name"), str, "project.name").strip():
        raise ContractError("INVALID_CONFIG", "Project name cannot be empty")
    validate_repository(project.get("repository"))
    if "family" in project:
        validate_slug(project["family"], "project.family")
    if "summary" in project:
        validate_summary(project["summary"])
    validate_license(doc.get("license"))
    commands = typed(doc.get("commands", []), list, "commands")
    for command in commands:
        validate_command(command)
    unique_rows(commands, "name")
    checks = typed(doc.get("checks", []), list, "checks")
    for check in checks:
        validate_check(check, {c["name"] for c in commands})
    unique_rows(checks, "id")
    if "desktop" in doc:
        validate_desktop(doc["desktop"], commands)
    if "runtime" in doc:
        runtime = table(doc["runtime"], {"kind", "constraint"}, "runtime", required={"kind"})
        choice(runtime.get("kind"), {"native", "node", "python"}, "runtime.kind")
        if "constraint" in runtime:
            typed(runtime["constraint"], str, "runtime.constraint")
