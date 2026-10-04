"""Bounded command metadata from captured archives; never retains asset bytes."""
import argparse
import json
import re
from pathlib import Path

from rs9.archives import inspect_archive
from rs9.errors import ContractError
from rs9.scratch import canonical
from rs9.security import scan_for_credentials, validate_safe_relative_posix_path


def node_script_shape(data):
    """Classify only a bounded first line, without echoing script content."""
    line = data[:257].split(b"\n", 1)[0]
    try:
        text = line.decode("utf-8")
    except UnicodeError:
        return {"utf8_first_line": False, "node_shebang": False, "shebang_kind": "none"}
    valid = len(line) <= 256 and bool(re.fullmatch(
        r"#!(?:/usr/bin/env[ \t]+node|/[A-Za-z0-9_./-]+/node)(?:[ \t]+[^\r\n]+)?\r?", text))
    shell = len(line) <= 256 and bool(re.fullmatch(r"#!(?:/bin/(?:ba)?sh|/usr/bin/env[ \t]+(?:ba)?sh)\r?", text))
    return {"utf8_first_line": True, "node_shebang": valid,
            "shebang_kind": "node" if valid else "shell" if shell else "other" if text.startswith("#!") else "none"}


def report_asset(project, asset, path, *, npm=False, bytes_authenticated=False):
    selected = {**asset.get("commands", {}),
                **{"launcher:" + k: v for k, v in asset.get("launchers", {}).items()}}
    shapes, package = {}, {}

    def visitor(name, data, mode):
        if name in selected.values():
            shapes[name] = node_script_shape(data)
        if npm and name == "package/package.json":
            try:
                package.update(json.loads(data))
            except (ValueError, UnicodeError, TypeError):
                pass

    manifest = inspect_archive(path, {}, on_file=visitor)
    members = {r["path"]: r for r in manifest["members"]}
    bins = package.get("bin", {})
    if isinstance(bins, str):
        bins = {str(package.get("name", "")).rsplit("/", 1)[-1]: bins}
    if not isinstance(bins, dict):
        bins = {}
    rows = []
    for command, name in sorted(selected.items()):
        member = members.get(name, {})
        launcher = command.startswith("launcher:")
        row = {"project": project, "asset": asset["id"], "payload_asset": asset["name"],
               "bytes_authenticated": bytes_authenticated,
               "basis": "authenticated-generation" if bytes_authenticated else "captured-archive-inspection",
               "command": command[9:] if launcher else command,
               "command_kind": "launcher" if launcher else "command", "archive_path": name,
               "member_type": member.get("type", "missing"),
               "mode": format(member["mode"], "04o") if "mode" in member else None}
        if member.get("type") == "file":
            row.update({k: member[k] for k in ("size", "sha256")})
            row.update(shapes.get(name, {}))
        if npm:
            target = bins.get(command)
            try:
                if not isinstance(target, str) or len(target) > 256:
                    raise ContractError("UNSAFE_PATH", "Bounded bin target required")
                validate_safe_relative_posix_path(target.removeprefix("./"))
                scan_for_credentials(target)
            except ContractError:
                target = None
            row["package_bin_target"] = target if isinstance(target, str) and len(target) <= 256 else None
            row["bin_agrees"] = isinstance(target, str) and "package/" + target.removeprefix("./") == name
        rows.append(row)
    scan_for_credentials(canonical(rows).decode())
    return rows


def report_generation(repository, capture_root, *, bytes_authenticated=False):
    """Inspection hashes confer no authentication; the caller supplies completed custody."""
    from rs9.candidate import configuration_rows
    rows, unavailable = [], []
    for _, intent in configuration_rows(repository):
        project = intent["project"]["id"]
        for asset in intent["assets"]:
            try:
                rows.extend(report_asset(project, asset, Path(capture_root) / project / "assets" / asset["name"],
                                         npm=intent["release"]["evidence"]["profile"] == "npm-package-archive.v1alpha1",
                                         bytes_authenticated=bytes_authenticated))
            except ContractError as error:
                unavailable.append({"project": project, "asset": asset["id"], "error": error.code})
    result = {"schema": "rs9.command-report.v1alpha1", "commands": rows, "unavailable": unavailable,
              "bytes_authenticated": bytes_authenticated,
              "basis": "authenticated-generation" if bytes_authenticated else "captured-archive-inspection"}
    scan_for_credentials(canonical(result).decode())
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", default=".")
    parser.add_argument("--capture", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    Path(args.output).write_bytes(canonical(report_generation(args.repository, args.capture)))


if __name__ == "__main__":
    main()
