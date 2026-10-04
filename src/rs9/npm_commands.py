"""RS9-owned npm bin semantics, shared by capture and package-profile callers."""
import json

from rs9.command_report import node_script_shape
from rs9.errors import ContractError
from rs9.security import validate_ecosystem_name, validate_safe_relative_posix_path

# Burst 0.6.1 publishes both authenticated Node bins as 0644. npm materializes
# executable bins on installation; RS9 wrappers invoke Node explicitly. Native
# commands retain their independent regular+executable archive policy.


def authenticate_bins(manifest, packaged, declared):
    members = {r["path"]: r for r in manifest["members"]}
    if manifest["root"] != "package" or members.get("package/package.json", {}).get("type") != "file":
        raise ContractError("PACKAGE_IDENTITY", "Single package root and regular metadata required")
    try:
        package = json.loads(packaged["package/package.json"])
        bins = package.get("bin", {})
        if isinstance(bins, str):
            bins = {package["name"].rsplit("/", 1)[-1]: bins}
        if not isinstance(bins, dict) or len(bins) > 256:
            raise ValueError
    except (KeyError, ValueError, UnicodeError, TypeError, AttributeError):
        raise ContractError("PACKAGE_IDENTITY", "Bounded declarative package bin metadata required") from None
    normalized = {}
    for command, target in sorted(bins.items()):
        validate_ecosystem_name("npm", command)
        if not isinstance(target, str):
            raise ContractError("PACKAGE_IDENTITY", "Package bin target must be a path")
        target = target.removeprefix("./")
        validate_safe_relative_posix_path(target)
        normalized[command] = "package/" + target
    commands = []
    for command, path in sorted(declared.items()):
        row = members.get(path, {})
        reason = ("bin-mismatch" if normalized.get(command) != path else
                  "bin-target-not-regular" if row.get("type") != "file" else
                  "bin-shebang" if not node_script_shape(packaged.get(path, b""))["node_shebang"] else None)
        if reason:
            raise ContractError("COMMAND_PATH", "Declared npm command violates authenticated bin contract", details={
                "command": command, "command_kind": "command", "archive_path": path,
                "member_type": row.get("type", "missing"), "mode": row.get("mode", 0), "reason": reason})
        commands.append({"name": command, **{k: row[k] for k in ("path", "sha256", "size", "mode")},
                         "raw_mode_executable": bool(row["mode"] & 0o111), "execution": "node-explicit"})
    return package, commands, sorted(set(normalized) - set(declared))
