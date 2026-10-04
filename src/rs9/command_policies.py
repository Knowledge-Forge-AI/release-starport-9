"""Closed RS9-owned archive execution profiles; no arbitrary executable hooks."""
from rs9.archives import inspect_archive
from rs9.errors import ContractError

NATIVE = "native-executable"
PACKAGE = "npm-package-bin"


def validate_command_policy(asset):
    policy = asset.get("command_policy", NATIVE)
    if policy not in {NATIVE, PACKAGE}:
        raise ContractError("INVALID_SELECTION", "Unknown command execution policy")
    if policy == PACKAGE and asset.get("launchers"):
        raise ContractError("INVALID_SELECTION", "Package bins cannot declare native launchers")
    return policy


def inspect_selected_archive(path, asset, limits):
    policy = validate_command_policy(asset)
    commands = {**asset.get("commands", {}),
                **{"launcher:" + k: v for k, v in asset.get("launchers", {}).items()}}
    packaged = {}

    def visitor(name, data, mode):
        if name == "package/package.json":
            packaged[name] = data
        elif name in commands.values():
            packaged[name] = data[:257]

    manifest = inspect_archive(path, commands, command_policy=policy,
                               on_file=visitor if policy == PACKAGE else None,
                               max_members=limits["members"], max_member_bytes=limits["member_bytes"],
                               max_total_bytes=limits["archive_bytes"], max_ratio=limits["ratio"])
    if policy == PACKAGE:
        from rs9.npm_commands import authenticate_bins
        authenticate_bins(manifest, packaged, commands)
    return manifest
