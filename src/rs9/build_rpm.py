"""Normal-tool native package candidate driver for RPM (Fedora 43 x86_64, aarch64, noarch).

Executes real host rpmbuild, rpm, rpmlint, and createrepo:
- Preserves native binaries: no strip, no debug package, no shebang mangling, no build-id links.
- Collects actual RPM v6 package identities and rpmlint receipts.
- Generates repository metadata using createrepo gzip --no-database.
- Pure JS CLI projects enforce arch 'noarch' with authenticated offline npm closure.
- Native Node CLI and native desktop products enforce arch 'x86_64' or 'aarch64'.
- Native prerequisites absent -> explicit unavailable, never fabricated files.
- Subprocess derivation records bound to artifact, tool, container, and source.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import posixpath
import re
import shutil
from typing import Any, Mapping, Sequence

from rs9.build_native import (
    CommandReceipt,
    CommandRunner,
    NativePrerequisiteUnavailable,
    SubprocessRunner,
    check_prerequisites,
    create_derivation_record,
    stage_offline_npm_closure,
    validate_build_inputs,
    validate_scratch_root,
)
from rs9.errors import ContractError
from rs9.machine_stream import machine_records
from rs9.profiles import png_size
from rs9.release_core import ReleaseCapture, digest
from rs9.scratch import canonical, physical_directory
from rs9.security import validate_safe_relative_posix_path

from rs9.rpm_query import (
    RPM_EXPECTED_ARCHITECTURES,
    _safe_observed_token,
    query_rpm_package,
    rpm_isolation_args,
    read_rpm_identity,
)
from rs9.rpm_header import inspect_rpm, tag_digest_map

_RPM_WEEKDAYS = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
_RPM_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
DEFAULT_RPM_MAINTAINER = "Knowledge Forge AI <nonproduction@knowledge-forge.invalid>"
RPM_CAPABILITY_MAX_BYTES = 1024 * 1024


def _capability_records(receipt, substage):
    """Read complete RPM capabilities; retain space trimming, reject controls."""
    if receipt.exit_code or receipt.stderr_bytes:
        error = ContractError("DEPENDENCY_DERIVATION", "Actual RPM capability readback failed",
                              details={"substage": substage, "tool": "rpm",
                                       "reason_token": "query-failed", "exit_code": receipt.exit_code,
                                       "stdout_sha256": receipt.stdout_sha256,
                                       "stderr_sha256": receipt.stderr_sha256})
        error.receipt = receipt
        raise error
    records = machine_records(receipt, limit=RPM_CAPABILITY_MAX_BYTES,
                              code="DEPENDENCY_DERIVATION", substage=substage, encoding="ascii")
    if any(not row.strip() or any(not 32 <= ord(c) < 127 for c in row) for row in records):
        error = ContractError("DEPENDENCY_DERIVATION", "Malformed RPM capability record",
                              details={"substage": substage, "tool": "rpm",
                                       "reason_token": "malformed-capability-record",
                                       "exit_code": receipt.exit_code,
                                       "stdout_sha256": receipt.stdout_sha256,
                                       "stderr_sha256": receipt.stderr_sha256})
        error.receipt = receipt
        raise error
    return [row.strip() for row in records]


def _coverage_diagnostic(missing, sonames, requires, provides, product):
    """Bound display samples independently of the complete coverage decision."""
    from rs9.rpm_lint import sanitize_text
    result = {"substage": "rpm-dependency-coverage", "product": product,
              "self_provides_count": len(provides)}
    for key, records in (("missing_dependencies", missing), ("required_sonames", sonames),
                         ("actual_requires", requires), ("actual_provides", provides)):
        result[key] = [sanitize_text(row, 128) for row in records[:32]]
        result[key + "_count"] = len(records)
        result[key + "_sha256"] = digest(canonical(records))
    result["samples_complete"] = all(len(rows) <= 32 for rows in (missing, sonames, requires, provides))
    return result
REDUNDANT_NEBULAR_REQUIRES = frozenset({
    "dbus-libs",
    "glib2",
    "libgcc",
    "libstdc++",
    "libsoup3",
})


def _get_rpm_maintainer(root_dir: Path | None = None) -> str:
    """Retrieve reviewed identity from operators/live1/targets.json."""
    targets_path = (root_dir or Path(__file__).resolve().parents[2]) / "operators/live1/targets.json"
    try:
        value = json.loads(targets_path.read_bytes()).get("maintainer")
    except (OSError, ValueError, TypeError) as exc:
        raise ContractError("CHANGELOG_IDENTITY", "Reviewed RPM packaging identity unavailable") from exc
    if value != DEFAULT_RPM_MAINTAINER:
        raise ContractError("CHANGELOG_IDENTITY", "Reserved nonproduction packaging identity required")
    return value


def _format_rpm_changelog(
    capture_or_published_at: ReleaseCapture | str | None,
    version: str,
    revision: int,
    maintainer: str | None = None,
) -> str:
    """Format truthful deterministic RPM changelog derived from UTC published_at."""
    published_at = None
    if isinstance(capture_or_published_at, ReleaseCapture):
        source_times = capture_or_published_at.record.get("source_times") or {}
        published_at = source_times.get("published_at")
        if not published_at:
            published_at = capture_or_published_at.record.get("release", {}).get("published_at")
    elif isinstance(capture_or_published_at, str):
        published_at = capture_or_published_at

    if not published_at:
        raise ContractError("CHANGELOG_DATE", "Authenticated release publication time required")

    if isinstance(published_at,str) and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z",published_at):
        try:
            dt = datetime.fromisoformat(published_at[:-1] + "+00:00").astimezone(timezone.utc)
        except ValueError as exc:
            raise ContractError("CHANGELOG_DATE", "Invalid authenticated publication timestamp") from exc
    else:
        raise ContractError("CHANGELOG_DATE", "Authenticated publication time must be UTC")

    # Compute weekday without locale/walltime
    weekday = _RPM_WEEKDAYS[dt.weekday()]
    month = _RPM_MONTHS[dt.month - 1]
    day = dt.day
    year = dt.year
    date_str = f"{weekday} {month} {day:02d} {year}"

    maint = maintainer or DEFAULT_RPM_MAINTAINER
    return (
        f"%changelog\n"
        f"* {date_str} {maint} - {version}-{revision}\n"
        f"- Candidate packaging of authenticated release v{version}; dated by upstream publication\n"
    )


def _authenticated_source_epoch(
    capture_or_published_at: ReleaseCapture | str | None,
) -> tuple[int, str]:
    """Derive authenticated deterministic source epoch (day clamped) from publication timestamp."""
    published_at = None
    if isinstance(capture_or_published_at, ReleaseCapture):
        source_times = capture_or_published_at.record.get("source_times") or {}
        published_at = source_times.get("published_at")
        if not published_at:
            published_at = capture_or_published_at.record.get("release", {}).get("published_at")
    elif isinstance(capture_or_published_at, str):
        published_at = capture_or_published_at

    if not published_at:
        raise ContractError("CHANGELOG_DATE", "Authenticated release publication time required")

    if isinstance(published_at, str) and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z", published_at):
        try:
            dt = datetime.fromisoformat(published_at[:-1] + "+00:00").astimezone(timezone.utc)
        except ValueError as exc:
            raise ContractError("CHANGELOG_DATE", "Invalid authenticated publication timestamp") from exc
    else:
        raise ContractError("CHANGELOG_DATE", "Authenticated publication time must be UTC")

    day_dt = datetime(dt.year, dt.month, dt.day, 0, 0, 0, tzinfo=timezone.utc)
    epoch = int(day_dt.timestamp())
    if not 0 < epoch < 2**32:
        raise ContractError("CHANGELOG_DATE", "Publication day must fit the RPM timestamp contract")
    return epoch, published_at


NOARCH_BUILDHOST = "rs9-noarch-repack.reproducible.invalid"
NOARCH_MACRO_QUERY = (
    "%{_buildtime}|%{_buildhost}|%{optflags}|%{_target_cpu}|%{_target_os}|"
    "%{_target_platform}|%{use_source_date_epoch_as_buildtime}|"
    "%{source_date_epoch_from_changelog}|%{build_mtime_policy}|%{getenv:SOURCE_DATE_EPOCH}"
)


def _noarch_build_inputs(capture, topdir, runner):
    """Pinned RPM 6.0.2 controls for repacking, shared by source and binary builds."""
    epoch, published_at = _authenticated_source_epoch(capture)
    controls = [f"_buildtime {epoch}", f"_buildhost {NOARCH_BUILDHOST}", "optflags %{nil}",
                "_target_platform noarch-redhat-linux", "use_source_date_epoch_as_buildtime 1",
                "source_date_epoch_from_changelog 1", "build_mtime_policy clamp_to_source_date_epoch"]
    arguments = ["--target", "noarch"]
    for control in controls:
        arguments.extend(["--define", control])
    environment = {"SOURCE_DATE_EPOCH": str(epoch), "TZ": "UTC", "LC_ALL": "C"}
    # Input copies only: the authenticated archive and payload members are unchanged.
    for subdirectory in ("SPECS", "SOURCES"):
        for path in sorted((topdir / subdirectory).iterdir()):
            if path.is_symlink() or not path.is_file():
                raise ContractError("RPM_REPRODUCIBILITY", "Regular noarch source input required")
            path.chmod(0o644)
            os.utime(path, (epoch, epoch))
    receipt = runner.run(["rpm", *arguments, "--eval", NOARCH_MACRO_QUERY], cwd=topdir, env=environment)
    expected = f"{epoch}|{NOARCH_BUILDHOST}||noarch|linux|noarch-redhat-linux|1|1|clamp_to_source_date_epoch|{epoch}\n".encode()
    if not receipt.executed or receipt.exit_code or receipt.stderr_bytes or receipt.stdout_bytes != expected:
        error = ContractError("RPM_REPRODUCIBILITY", "Effective noarch controls differ from authenticated inputs",
                              details={"substage": "noarch-macro-readback", "tool": "rpm",
                                       "exit_code": receipt.exit_code, "stdout_sha256": receipt.stdout_sha256,
                                       "stderr_sha256": receipt.stderr_sha256})
        error.receipt = receipt
        raise error
    evidence = {"schema": "rs9.noarch-repack-inputs.v1", "source_date_epoch": epoch,
                "epoch_source": "authenticated-release-publication-day-utc", "published_at": published_at,
                "declared_buildhost": NOARCH_BUILDHOST, "physical_buildhost_claimed": False,
                "target": "noarch", "macro_readback_scope": "rpm-cli-context",
                "spec_local_controls": ["%global optflags %{nil}"],
                "controls": controls, "effective_macros": expected.decode().strip(),
                "macro_receipt": {"executed": receipt.executed, "exit_code": receipt.exit_code,
                                  "command_sha256": digest(canonical(receipt.command)),
                                  "stdout_sha256": receipt.stdout_sha256, "stderr_sha256": receipt.stderr_sha256}}
    return arguments, environment, evidence


def inspect_noarch_headers(
    binary_rpm_bytes: bytes,
    source_rpm_bytes: bytes,
    expected_epoch: int,
    expected_buildhost: str = NOARCH_BUILDHOST,
    spec_bytes: bytes | None = None,
    closure_sha: str | None = None,
) -> dict[str, Any]:
    """Parse finished binary and source RPM via rs9.rpm_header.inspect_rpm read-only.

    Requires:
    - noarch architecture in binary main header
    - expected authenticated epoch (tag 1006 BUILDTIME) in both RPMs
    - expected authenticated buildhost (tag 1007 BUILDHOST) in both RPMs
    - OPTFLAGS (tag 1122) absent or empty in binary and source RPMs
    Records digests of tags 1094, 1122, 1132, 1146, compressed payload, and byte identities.
    Never modifies package bytes.
    """
    failures, parsed = [], {}
    for name, raw in (("binary", binary_rpm_bytes), ("source", source_rpm_bytes)):
        try:
            _, tags, payload = inspect_rpm(raw)
            tag_digests = tag_digest_map(raw)
        except (ValueError, TypeError, UnicodeError):
            failures.append(name + "-rpm-parse-failure")
            tags, payload, tag_digests = {}, b"", {}
        parsed[name] = (tags, payload, tag_digests)

    def is_tag(tags, number, typ, value):
        tag = tags.get(number, {})
        return tag.get("type") == typ and tag.get("count") == 1 and tag.get("value") == [value]

    records = {}
    for name in ("binary", "source"):
        tags, payload, tag_digests = parsed[name]
        prefix = "" if name == "binary" else "srpm-"
        arch_ok = is_tag(tags, 1022, 6, "noarch")
        epoch_ok = is_tag(tags, 1006, 4, expected_epoch)
        host_ok = is_tag(tags, 1007, 6, expected_buildhost)
        opt_ok = 1122 not in tags or is_tag(tags, 1122, 6, "")
        if tags:
            if name == "binary" and not arch_ok: failures.append("arch-mismatch")
            if not epoch_ok: failures.append(prefix + "buildtime-epoch-mismatch")
            if not host_ok: failures.append(prefix + "buildhost-mismatch")
            if not opt_ok: failures.append(prefix + "optflags-non-empty")
        records[name + "_rpm"] = {
            "architecture": "noarch" if arch_ok else None,
            "buildtime": expected_epoch if epoch_ok else None,
            "buildhost": expected_buildhost if host_ok else None,
            "optflags": None,
            "optflags_presence": "absent" if 1122 not in tags else "empty" if opt_ok else "unexpected-withheld",
            "optflags_absent_or_empty": opt_ok and bool(tags),
            "tag_digests": {str(k): tag_digests.get(k) for k in (1006, 1007, 1094, 1122, 1132, 1146)},
            "compressed_payload_sha256": digest(payload) if tags else None,
            "package_sha256": digest(binary_rpm_bytes if name == "binary" else source_rpm_bytes),
        }
    records["source_rpm"]["source_rpm_sha256"] = digest(source_rpm_bytes)
    return {"schema": "rs9.noarch-header-readback.v1", "status": "fail" if failures else "pass",
            "reason": failures[0] if failures else None, "failures": failures,
            "target_architecture": "noarch", "authenticated_epoch": expected_epoch,
            "declared_buildhost": expected_buildhost, **records,
            "identities": {"spec_sha256": digest(spec_bytes) if spec_bytes is not None else None,
                "source_rpm_sha256": digest(source_rpm_bytes), "closure_sha256": closure_sha,
                "package_sha256": digest(binary_rpm_bytes),
                "compressed_payload_sha256": records["binary_rpm"]["compressed_payload_sha256"],
                **{"tag_" + str(k) + "_digest": parsed["binary"][2].get(k) for k in (1094, 1122, 1132, 1146)}}}


def is_soname_covered(soname: str, requires: Sequence[str], provides: Sequence[str]) -> bool:
    """Check if a native SONAME capability is covered by RPM requires or self-provides."""
    for p in provides:
        p_clean = p.strip()
        p_base = p_clean.split()[0].split("(")[0]
        if p_clean == soname or p_base == soname or p_clean.startswith(soname + "("):
            return True
    for r in requires:
        r_clean = r.strip()
        r_base = r_clean.split()[0].split("(")[0]
        if r_clean == soname or r_base == soname or r_clean.startswith(soname + "("):
            return True
    return False


from rs9.rpm_lint import execute_rpmlint
from rs9.rpm_preservation import collect_preservation_inventory
from rs9.rpm_lint_policy import evaluate_policy


RPM_REQUIRED_TOOLS = ["rpmbuild", "rpm", "rpmlint"]
def _find_createrepo(runner: CommandRunner) -> str | None:
    """Require the maintained C implementation and retain its resolved executable.

    A legacy-name-only installation is an unavailable prerequisite; no ambiguous
    version string establishes the supported option contract.
    """
    return runner.which("createrepo_c")


def _render_rpm_spec(
    name: str,
    version: str,
    revision: int,
    summary: str,
    lic: str,
    asset: str,
    sha: str,
    arch: str,
    deps: list[str],
    cmds: list[dict[str, str]],
    is_nebular: bool,
    root: str,
    d_sha: str = "",
    i_sha: str = "",
    is_native_node: bool = False,
    published_at: str | None = None,
    maintainer: str = DEFAULT_RPM_MAINTAINER,
    changelog_text: str | None = None,
) -> bytes:
    rpm_sum = summary.replace("%", "%%")
    reqs = "\n".join(f"Requires: {d}" for d in deps)
    srcs = f"Source0: {asset}\n" + (
        f"Source1: {name}.desktop\nSource2: icon.png\n" if is_nebular else ""
    )
    prep_checks = f"printf '%s  %s\\n' '{sha}' '%{{SOURCE0}}' | sha256sum -c -\n" + (
        f"printf '%s  %s\\n' '{d_sha}' '%{{SOURCE1}}' | sha256sum -c -\n"
        f"printf '%s  %s\\n' '{i_sha}' '%{{SOURCE2}}' | sha256sum -c -\n"
        if is_nebular
        else ""
    )

    if is_nebular:
        install_launch = (
            f"ln -s '/usr/lib/{name}/{cmds[0]['path']}' '%{{buildroot}}/usr/bin/{cmds[0]['name']}'\n"
            f"install -Dm644 '%{{SOURCE1}}' '%{{buildroot}}/usr/share/applications/{name}.desktop'\n"
            f"install -Dm644 '%{{SOURCE2}}' '%{{buildroot}}/usr/share/icons/hicolor/256x256/apps/{name}.png'\n"
        )
        files_extra = f"/usr/share/applications/{name}.desktop\n/usr/share/icons/hicolor/256x256/apps/{name}.png\n"
    else:
        install_launch = (
            "\n".join(
                f"cat << 'EOF' > '%{{buildroot}}/usr/bin/{c['name']}'\n#!/bin/sh\nexec node \"/usr/lib/{name}/{c['path']}\" \"$@\"\nEOF\nchmod 0755 '%{{buildroot}}/usr/bin/{c['name']}'"
                for c in cmds
            )
            + "\n"
        )
        files_extra = ""

    cmd_files = "\n".join(f"/usr/bin/{c['name']}" for c in cmds)
    arch_line = f"BuildArch: noarch" if arch == "noarch" else f"ExclusiveArch: {arch}"
    f2_excludes = ""
    if is_native_node:
        from rs9.burst_native import BURST_CLOSED_PREBUILDS
        from rs9.hosted_platforms import platform_contract
        from rs9.product_classes import packaging_system_for_arch
        target_key = platform_contract(packaging_system_for_arch("rpm", arch)).native_prebuild_key
        # RPM uses POSIX ERE. Exclude only the three authenticated foreign files;
        # the target prebuild remains subject to normal dependency generation.
        foreign_paths = ["/usr/lib/" + name + "/" + path.removeprefix("package/")
                         for key, path in sorted(BURST_CLOSED_PREBUILDS.items()) if key != target_key]
        pattern = "^(" + "|".join(re.escape(path) for path in foreign_paths) + ")$"
        f2_excludes = (f"%global __requires_exclude_from {pattern}\n"
                       f"%global __provides_exclude_from {pattern}\n")

    cl_entry = changelog_text or _format_rpm_changelog(published_at, version, revision, maintainer)
    cl_section = f"\n{cl_entry.strip()}\n"

    noarch_optflags = ""
    if arch == "noarch" and name in {"theme-forge-stellar-loom", "theme-forge-solar-sail"}:
        noarch_optflags = "%global optflags %{nil}\n"

    return (
        f"# RS9 LIVE1 RPM spec candidate from exact authenticated release capture.\n"
        f"# Publication and signing deferred.\n"
        f"%global debug_package %{{nil}}\n"
        f"%global __strip /bin/true\n"
        f"%undefine __brp_mangle_shebangs\n"
        f"%global _build_id_links none\n"
        f"%global __os_install_post %{{nil}}\n"
        f"{noarch_optflags}"
        f"{f2_excludes}"
        f"Name: {name}\n"
        f"Version: {version}\n"
        f"Release: {revision}%{{?dist}}\n"
        f"Summary: {rpm_sum}\n"
        f"License: {lic}\n"
        f"URL: https://github.com/Knowledge-Forge-AI/{name}\n"
        f"{arch_line}\n"
        f"{srcs}"
        f"{reqs}\n\n"
        f"%description\n{rpm_sum}\n\n"
        f"%prep\n{prep_checks}\n"
        f"%setup -q -c -n %{{name}}-%{{version}}\n\n"
        f"%build\n# Precompiled candidate payload; no transformations.\n\n"
        f"%install\n"
        f"mkdir -p '%{{buildroot}}/usr/lib/{name}' '%{{buildroot}}/usr/bin'\n"
        f"cp -a {root}/. '%{{buildroot}}/usr/lib/{name}/'\n"
        f"{install_launch}\n"
        f"%files\n"
        f"%license {root}/LICENSE\n"
        f"%license {root}/NOTICE\n"
        f"/usr/lib/{name}\n"
        f"{cmd_files}\n"
        f"{files_extra}"
        f"{cl_section}"
    ).encode("utf-8")


def _desktop_entry(project_id: str, summary: str, command: str, categories: list[str]) -> bytes:
    escape = lambda s: s.replace("\\", "\\\\")
    cats = ";".join(sorted(categories)) + ";"
    return (
        f"[Desktop Entry]\nType=Application\nName=Theme Forge Nebular Fusion\n"
        f"Comment={escape(summary)}\nExec={command}\nIcon={project_id}\n"
        f"Terminal=false\nCategories={cats}\n"
    ).encode("utf-8")


def build_rpm_candidate(
    capture: ReleaseCapture,
    intent: dict[str, Any],
    arch: str,
    scratch_dir: str | Path,
    *,
    distro: str = "fedora-43",
    revision: int = 1,
    offline_npm_archives: Mapping[str, str | Path] | None = None,
    runner: CommandRunner | None = None,
    builder_system: str | None = None,
    policy: Mapping[str, Any] | None = None,
    client_runtime: Mapping[str, Any] | None = None,
    caller_evidence: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build Fedora 43 RPM candidate package using real rpmbuild, rpmlint, and createrepo."""
    scratch = validate_scratch_root(scratch_dir)

    ctx = validate_build_inputs(
        capture, intent, arch, adapter="rpm", distro=distro
    )
    project_id = ctx["project_id"]
    version = ctx["version"]
    is_native = ctx["is_native"]
    matched_arch = ctx["arch"]
    system = builder_system or ("aarch64-linux" if matched_arch == "aarch64" else "x86_64-linux")
    if system not in {"x86_64-linux", "aarch64-linux"} or (matched_arch != "noarch" and system != matched_arch + "-linux"):
        raise ContractError("INVALID_ARCHITECTURE", "RPM builder system and target mismatch")

    r = runner or SubprocessRunner()

    createrepo_tool = _find_createrepo(r)
    required = list(RPM_REQUIRED_TOOLS)
    if createrepo_tool is None:
        required.append("createrepo_c")

    missing: list[str] = []
    for tool in required:
        if r.which(tool) is None:
            missing.append(tool)
    if missing:
        raise NativePrerequisiteUnavailable(
            f"RPM build prerequisites missing: {missing}. Never fabricating files.",
            missing_tools=missing,
        )

    createrepo_bin = createrepo_tool or "createrepo_c"

    # Setup standard RPM build tree in scratch root
    rpm_topdir = scratch / "rpmbuild"
    for subdir in ("BUILD", "RPMS", "SOURCES", "SPECS", "SRPMS"):
        (rpm_topdir / subdir).mkdir(parents=True, exist_ok=True)

    repo_dir = scratch / "repo" / matched_arch
    repo_dir.mkdir(parents=True, exist_ok=True)

    # Copy source asset into SOURCES
    asset_name = ctx["asset_name"]
    source0 = rpm_topdir / "SOURCES" / asset_name
    source0.write_bytes(ctx["asset_bytes"])

    desktop_bytes = icon_bytes = None
    desktop_sha = icon_sha = ""
    cmds: list[dict[str, str]] = []

    is_native_desktop = ctx.get("is_native_desktop", False)
    is_native_node_cli = ctx.get("is_native_node_cli", False)
    is_pure_js_cli = ctx.get("is_pure_js_cli", not is_native)

    if is_native_desktop:
        payload = ctx["payload"]
        launchers = payload.get("launchers", {})
        l_raw = launchers.get("tfnf", {}).get("path")
        if not l_raw:
            raise ContractError(
                "MISSING_LAUNCHER",
                "Nebular released launcher path missing from capture payload",
            )
        payload_root = ctx["payload_root"]
        l_rel = l_raw[len(payload_root) + 1:] if l_raw.startswith(payload_root + "/") else l_raw
        cmds = [{"name": "tfnf", "path": l_rel}]

        desktop_info = intent.get("desktop") or capture.record.get("desktop")
        if not desktop_info:
            raise ContractError(
                "MISSING_REQUIRED_KEY", "Desktop facts required for Nebular"
            )
        icon_path = desktop_info.get("icon", {}).get("path", "src-tauri/icons/icon.png")
        icon_bytes = capture.source.get(icon_path)
        if not icon_bytes:
            raise ContractError(
                "MISSING_ICON", "Nebular icon bytes missing from capture source"
            )
        png_size(icon_bytes)
        desktop_bytes = _desktop_entry(
            project_id, ctx["summary"], "tfnf", desktop_info.get("categories", ["Development"])
        )
        desktop_sha = digest(desktop_bytes)
        icon_sha = digest(icon_bytes)

        (rpm_topdir / "SOURCES" / f"{project_id}.desktop").write_bytes(desktop_bytes)
        (rpm_topdir / "SOURCES" / "icon.png").write_bytes(icon_bytes)

        # Derive ELF dependencies from released payload asset
        from rs9.dependencies import INTERPRETERS, LIBRARIES, shebang
        from rs9.elf import parse_elf
        import tarfile

        elf_objects = []
        scripts = []
        system_sonames = set()
        fedora_packages = set()
        dt_needed_packages = set()
        script_packages = set()

        with tarfile.open(ctx["asset_file"], "r:*") as tar:
            for member in tar.getmembers():
                if member.isfile():
                    f = tar.extractfile(member)
                    if f is not None:
                        try:
                            data = f.read()
                        finally:
                            f.close()
                        if data.startswith(b"\x7fELF"):
                            elf_info = parse_elf(data)
                            is_executable = bool(member.mode & 0o111)
                            elf_objects.append({
                                "path": member.name,
                                "needed": elf_info["needed"],
                                "interpreter": elf_info.get("interpreter"),
                                "mode": oct(member.mode),
                                "executable": is_executable,
                            })
                            for soname in elf_info["needed"]:
                                system_sonames.add(soname)
                                if soname in LIBRARIES:
                                    pkg = LIBRARIES[soname][1]
                                    fedora_packages.add(pkg)
                                    dt_needed_packages.add(pkg)
                            interp = elf_info.get("interpreter")
                            if interp in {"/lib64/ld-linux-x86-64.so.2", "/lib/ld-linux-aarch64.so.1"}:
                                fedora_packages.add("glibc")
                        elif data.startswith(b"#!") and (member.mode & 0o111):
                            sh_info = shebang(data)
                            if sh_info and sh_info.get("interpreter"):
                                interp_name = sh_info["interpreter"]
                                scripts.append({"path": member.name, "interpreter": interp_name})
                                if interp_name in INTERPRETERS:
                                    pkg = INTERPRETERS[interp_name][1]
                                    fedora_packages.add(pkg)
                                    script_packages.add(pkg)

        if not elf_objects:
            raise ContractError("NO_ELF_OBJECTS", "Native package contains no ELF binaries")

        # Keep glibc and all interpreters/helpers/dlopen needs.
        # Remove ONLY redundant Nebular named library Requires lint targets:
        # (dbus-libs/glib2/libgcc/libstdc++/libsoup3)
        # provided they come only from DT_NEEDED mapping.
        protected_packages = set(script_packages) | {"glibc"}
        removable_targets = (dt_needed_packages & REDUNDANT_NEBULAR_REQUIRES) - protected_packages
        fedora_packages_for_spec = fedora_packages - removable_targets
        if "nodejs" in fedora_packages_for_spec:
            # Keep executable Loom shebang Requires, bound to authenticated metadata.
            from rs9.nebular_callers import release_runtime_floor
            from rs9.rpm_lint_policy import load_policy
            current_policy = policy if policy is not None else load_policy()
            floor = release_runtime_floor(ctx["asset_file"], current_policy["projects"][project_id])
            fedora_packages_for_spec.remove("nodejs")
            fedora_packages_for_spec.add("nodejs " + floor)

        derived_deps = sorted(fedora_packages_for_spec)
        policy_dependencies = sorted(fedora_packages)
        dependency_classification = "native-tool-derived"
    elif is_native_node_cli:
        # Native node CLI (Burst): stage offline authenticated npm closure
        payload_root = ctx["payload_root"]
        cmd_dict = ctx["payload"].get("commands", {}) or intent.get("commands", {})
        cmds = [
            {"name": k, "path": v["path"][len(payload_root) + 1:]}
            for k, v in sorted(cmd_dict.items())
        ]
        staged_nm = rpm_topdir / "staged_node_modules"
        stage_offline_npm_closure(capture, project_id, offline_npm_archives, staged_nm)
        from rs9.build_native import npm_bundle
        closure_sha = npm_bundle(staged_nm, rpm_topdir / "SOURCES/npm-closure.tar.gz")

        # Dependency derivation strictly targets matching prebuild; foreign exact closed prebuilds remain inert
        target_prebuild_path = (
            ctx.get("burst_prebuild_info", {}).get("target_path")
            if ctx.get("burst_prebuild_info")
            else (
                "package/native/directory-snapshot/prebuilds/linux-x64-gnu/native-addon-posix-openat-v1.node"
                if matched_arch == "x86_64"
                else "package/native/directory-snapshot/prebuilds/linux-arm64-gnu/native-addon-posix-openat-v1.node"
            )
        )
        from rs9.dependencies import LIBRARIES
        from rs9.elf import parse_elf
        import tarfile

        elf_objects = []
        system_sonames = set()
        fedora_packages = {"nodejs >= 22"}

        with tarfile.open(ctx["asset_file"], "r:*") as tar:
            found_target = False
            for member in tar.getmembers():
                if member.isfile() and (member.name == target_prebuild_path or member.name.endswith("/" + target_prebuild_path) or target_prebuild_path.endswith(member.name)):
                    found_target = True
                    f = tar.extractfile(member)
                    if f is not None:
                        try:
                            data = f.read()
                        finally:
                            f.close()
                        if data.startswith(b"\x7fELF"):
                            elf_info = parse_elf(data)
                            elf_objects.append({
                                "path": member.name,
                                "needed": elf_info["needed"],
                                "interpreter": elf_info.get("interpreter"),
                                "mode": oct(member.mode),
                                "executable": bool(member.mode & 0o111),
                            })
                            for soname in elf_info["needed"]:
                                system_sonames.add(soname)
                                if soname in LIBRARIES:
                                    fedora_packages.add(LIBRARIES[soname][1])
                            interp = elf_info.get("interpreter")
                            if interp in {"/lib64/ld-linux-x86-64.so.2", "/lib/ld-linux-aarch64.so.1"}:
                                fedora_packages.add("glibc")
            if not found_target or not elf_objects:
                raise ContractError("MISSING_ASSET", f"Matching native prebuild missing from tarball: {target_prebuild_path}")

        derived_deps = sorted(fedora_packages)
        dependency_classification = "native-tool-derived"
    else:
        # Pure JS CLI projects: stage offline authenticated npm closure; pure JS retain no native checks
        payload_root = ctx["payload_root"]
        cmd_dict = ctx["payload"].get("commands", {}) or intent.get("commands", {})
        cmds = [
            {"name": k, "path": v["path"][len(payload_root) + 1:]}
            for k, v in sorted(cmd_dict.items())
        ]
        staged_nm = rpm_topdir / "staged_node_modules"
        stage_offline_npm_closure(capture, project_id, offline_npm_archives, staged_nm)
        from rs9.build_native import npm_bundle
        closure_sha = npm_bundle(staged_nm, rpm_topdir / "SOURCES/npm-closure.tar.gz")

        derived_deps = ["nodejs >= 22"]
        dependency_classification = "reviewed-policy"

    # Format truthful deterministic RPM changelog derived from UTC published_at
    changelog_str = _format_rpm_changelog(
        capture, version, revision, maintainer=_get_rpm_maintainer()
    )

    # Render RPM spec file
    spec_bytes = _render_rpm_spec(
        project_id,
        version,
        revision,
        ctx["summary"],
        ctx["license"],
        asset_name,
        ctx["asset_sha"],
        matched_arch,
        derived_deps,
        cmds,
        is_native_desktop,
        ctx["payload_root"],
        desktop_sha,
        icon_sha,
        is_native_node=is_native_node_cli,
        changelog_text=changelog_str,
    )
    spec_path = rpm_topdir / "SPECS" / f"{project_id}.spec"
    if not is_native_desktop:
        text = spec_bytes.decode()
        text = text.replace("Source0:", "Source3: npm-closure.tar.gz\nSource0:", 1)
        text = text.replace("%build\n", "printf '%s  %s\\n' '" + closure_sha + "' '%{SOURCE3}' | sha256sum -c -\ntar -xzf '%{SOURCE3}'\n\n%build\n", 1)
        text = text.replace("%files\n", "cp -a node_modules '%{buildroot}/usr/lib/" + project_id + "/node_modules'\n\n%files\n", 1)
        spec_bytes = text.encode()
    spec_path.write_bytes(spec_bytes)

    # Execute rpmbuild with preservation defines
    rpmbuild_cmd = [
        "rpmbuild",
        "-ba",
        str(spec_path),
        "--define",
        f"_topdir {rpm_topdir}",
        "--define",
        "debug_package %{nil}",
        "--define",
        "__strip /bin/true",
        "--define",
        "_build_id_links none",
        "--define",
        "__os_install_post %{nil}",
        "--undefine",
        "__brp_mangle_shebangs",
    ]
    reproducibility = None
    build_environment = None
    if matched_arch == "noarch":
        arguments, build_environment, reproducibility = _noarch_build_inputs(capture, rpm_topdir, r)
        rpmbuild_cmd.extend(arguments)
        reproducibility["npm_closure_sha256"] = closure_sha
        reproducibility["builder_environment"] = {"system": system, "target_architecture": matched_arch}
    rpmbuild_receipt = r.run(rpmbuild_cmd, cwd=rpm_topdir, env=build_environment)
    if rpmbuild_receipt.exit_code != 0:
        raise ContractError(
            "BUILD_FAILED",
            f"rpmbuild failed with exit code {rpmbuild_receipt.exit_code}: {rpmbuild_receipt.stderr_text}",
        )

    # Locate built RPM in RPMS/<arch>
    rpm_search_dir = rpm_topdir / "RPMS" / matched_arch
    built_rpms = (
        list(rpm_search_dir.glob("*.rpm"))
        if rpm_search_dir.exists()
        else list((rpm_topdir / "RPMS").rglob("*.rpm"))
    )
    if not built_rpms:
        raise ContractError(
            "BUILD_FAILED",
            "rpmbuild completed but no candidate RPM file was found in RPMS",
        )

    rpm_file = built_rpms[0]
    rpm_bytes = rpm_file.read_bytes()
    dest_rpm = repo_dir / rpm_file.name
    dest_rpm.write_bytes(rpm_bytes)

    # Collect actual RPM package identity and payload digest separately
    query_db, query_keyring = scratch / "query-rpmdb", scratch / "query-keyring"
    query_db.mkdir(exist_ok=True)
    query_keyring.mkdir(exist_ok=True)
    rpm_identity, rpm_payload_digest, query_receipts = query_rpm_package(
        r,
        dest_rpm,
        product=project_id,
        version=version,
        architecture=matched_arch,
        revision=revision,
        cwd=scratch,
        dbpath=query_db, keyring="rpmdb", keyringpath=query_keyring,
    )

    construction_witness = {
        "schema": "rs9.rpm-construction-witness.v1",
        "rpmbuild_receipt": {
            "executed": rpmbuild_receipt.executed,
            "exit_code": rpmbuild_receipt.exit_code,
            "tool": "rpmbuild",
            "stdout_sha256": rpmbuild_receipt.stdout_sha256,
            "stderr_sha256": rpmbuild_receipt.stderr_sha256,
            "command_sha256": digest(canonical(rpmbuild_receipt.command)),
        },
        "rpm_identity": rpm_identity,
        "rpm_payload_digest": rpm_payload_digest,
        "package_sha256": digest(rpm_bytes),
        "package_size": len(rpm_bytes),
        "spec_sha256": digest(spec_bytes),
    }
    if reproducibility is not None:
        srpms = sorted((rpm_topdir / "SRPMS").glob("*.src.rpm"))
        if len(srpms) != 1 or srpms[0].is_symlink():
            error = ContractError("RPM_REPRODUCIBILITY", "One completed noarch source RPM required",
                                  details={"substage": "noarch-source-rpm"})
            error.construction_witness = construction_witness
            error.package_path = str(dest_rpm)
            raise error
        srpm_bytes = srpms[0].read_bytes()
        reproducibility["source_rpm"] = {"name": srpms[0].name, "sha256": digest(srpm_bytes),
                                         "size": srpms[0].stat().st_size}
        header_readback = inspect_noarch_headers(
            binary_rpm_bytes=rpm_bytes,
            source_rpm_bytes=srpm_bytes,
            expected_epoch=reproducibility["source_date_epoch"],
            expected_buildhost=reproducibility.get("declared_buildhost", NOARCH_BUILDHOST),
            spec_bytes=spec_bytes,
            closure_sha=closure_sha,
        )
        reproducibility["finished_header"] = header_readback
        construction_witness["reproducibility"] = reproducibility
        construction_witness["finished_header"] = header_readback

    def _attach_witness(exc: ContractError) -> ContractError:
        exc.construction_witness = construction_witness
        exc.package_artifact = str(dest_rpm)
        exc.package_path = str(dest_rpm)
        exc.package_sha256 = digest(rpm_bytes)
        if hasattr(exc, "details") and isinstance(exc.details, dict):
            exc.details["construction_witness"] = construction_witness
        return exc

    def _post_construction_run(command):
        try:
            return r.run(command, cwd=scratch)
        except (ContractError, OSError) as cause:
            error = cause if isinstance(cause, ContractError) else ContractError("BUILD_FAILED", "Post-construction tool unavailable")
            raise _attach_witness(error) from cause

    # Capture RPM requires for ALL products (node interpreter enforcement), not native only.
    rpm_requires_cmd = [
        "rpm",
        *rpm_isolation_args(dbpath=query_db, keyring="rpmdb", keyringpath=query_keyring),
        "-qp",
        "--requires",
        str(dest_rpm),
    ]
    rpm_requires_receipt = _post_construction_run(rpm_requires_cmd)
    try:
        actual_rpm_requires = _capability_records(rpm_requires_receipt, "rpm-requires")
    except ContractError as err:
        raise _attach_witness(err)

    # Node interpreter enforcement for pure JS CLI
    if is_pure_js_cli:
        has_node = "nodejs >= 22" in actual_rpm_requires
        if not has_node:
            raise _attach_witness(ContractError("DEPENDENCY_DERIVATION", "Pure JS CLI package requires missing nodejs interpreter"))

    # Add rpm --provides readback and coverage evidence
    rpm_provides_cmd = [
        "rpm",
        *rpm_isolation_args(dbpath=query_db, keyring="rpmdb", keyringpath=query_keyring),
        "-qp",
        "--provides",
        str(dest_rpm),
    ]
    rpm_provides_receipt = _post_construction_run(rpm_provides_cmd)
    try:
        actual_rpm_provides = _capability_records(rpm_provides_receipt, "rpm-provides")
    except ContractError as err:
        raise _attach_witness(err)
    self_provides_count = len(actual_rpm_provides)

    if is_native:
        policy_dependencies = list(derived_deps)
        derived_deps = sorted(set(actual_rpm_requires))
        if is_native_node_cli:
            allowed_sonames = set(system_sonames)
            if not "nodejs >= 22" in actual_rpm_requires:
                raise _attach_witness(ContractError("DEPENDENCY_DERIVATION", "Native Node CLI RPM requires missing nodejs interpreter"))
            for requirement in derived_deps:
                base = requirement.split("(", 1)[0]
                if not (base in allowed_sonames or base == "rtld"
                        or requirement.startswith("rpmlib(")
                        or requirement in {"/bin/sh", "/usr/bin/env"}
                        or re.fullmatch(r"nodejs(?:\s*(?:>=|=)\s*[0-9][0-9.]*)?", requirement)
                        or requirement in policy_dependencies):
                    raise _attach_witness(ContractError("DEPENDENCY_DERIVATION", "RPM requirement lies outside the target prebuild closure"))

        if is_native:
            # Verify DT_NEEDED capability coverage for target ELFs only
            missing_sonames = [
                s for s in sorted(system_sonames)
                if not is_soname_covered(s, actual_rpm_requires, actual_rpm_provides)
            ]
            if missing_sonames:
                details = _coverage_diagnostic(missing_sonames, sorted(system_sonames),
                                               actual_rpm_requires, actual_rpm_provides, project_id)
                err = ContractError(
                    "DEPENDENCY_DERIVATION",
                    f"Actual RPM capabilities do not cover native ELF dependencies: {missing_sonames}",
                    details=details,
                )
                err.dependency_coverage = details
                err.receipt = rpm_requires_receipt
                err.requires_receipt = rpm_requires_receipt
                err.provides_receipt = rpm_provides_receipt
                raise _attach_witness(err)

    # Execute raw rpmlint with structured evidence
    try:
        rpmlint_evidence, rpmlint_receipts = execute_rpmlint(
            runner=r,
            spec_path=spec_path,
            rpm_path=dest_rpm,
            product=project_id,
            rpm_identity=rpm_identity,
            rpm_payload_digest=rpm_payload_digest,
            cwd=scratch,
            allow_policy=True,
        )
    except ContractError as err:
        raise _attach_witness(err)
    rpmlint_receipt = rpmlint_receipts[0]

    # Resolve policy at builder seam if not provided
    resolved_policy = policy
    if resolved_policy is None:
        try:
            from rs9.rpm_lint_policy import load_policy
            resolved_policy = load_policy()
        except Exception:
            resolved_policy = None

    # Collect preservation inventory
    staged_nm_for_inventory = None if is_native_desktop else (rpm_topdir / "staged_node_modules")
    try:
        inventory, inventory_receipts = collect_preservation_inventory(
            runner=r,
            rpm_file=dest_rpm,
            capture=capture,
            ctx=ctx,
            staged_nm=staged_nm_for_inventory,
            cmds=cmds,
            requires=actual_rpm_requires,
            scratch=scratch,
            dbpath=query_db,
            keyringpath=query_keyring,
            policy=resolved_policy,
            client_runtime=client_runtime,
            caller_evidence=caller_evidence,
        )

    except (ContractError, ValueError, OSError) as cause:
        causal = getattr(cause, "receipt", None)
        cause_details = getattr(cause, "details", {})
        details = {"substage": "rpm-preservation-inventory", "product": project_id,
                   "reason_token": cause_details.get("reason_token", "inventory-projection"),
                   "diagnostic_token": cause_details.get("diagnostic_token", "inventory-projection"),
                   "underlying_code": getattr(cause, "code", "INPUT_PROJECTION")}
        for key in ('tool', 'stdout_sha256', 'stderr_sha256', 'elapsed_ms', 'deadline_seconds',
                    'size', 'observed', 'maximum'):
            if key in cause_details:
                details[key] = cause_details[key]
        if causal is not None:
            details.update(tool="rpm", exit_code=causal.exit_code,
                           stdout_sha256=causal.stdout_sha256, stderr_sha256=causal.stderr_sha256)
        err = ContractError("RPM_INVENTORY_FAILED", "Candidate preservation inventory unavailable",
                             details=details)
        err.receipt = causal
        err.rpmlint_receipt = rpmlint_receipt
        err.inventory_diagnostic = getattr(cause, "inventory_diagnostic", None)
        err.rpmlint_evidence = rpmlint_evidence
        err.rpmlint_policy = {"schema":"rs9.rpm-lint-policy-evaluation.v1","accepted":False,
                             "status":"blocked","blockers":["incomplete-preservation-inventory"],
                             "accepted_findings":[],"raw_lint_status":rpmlint_evidence["status"],
                             "raw_exit_code":rpmlint_receipt.exit_code,
                             "inputs": {"project_id": project_id, "version": version,
                                        "arch": matched_arch, "system": system,
                                        "asset_sha256": ctx["asset_sha"],
                                        "payload_manifest_sha256": ctx["payload"].get("payload_manifest_sha256"),
                                        "closure_sha256": closure_sha if not is_native_desktop else None}}
        err.package_path, err.spec_path = str(dest_rpm), str(spec_path)
        err.package_sha256, err.spec_sha256 = digest(rpm_bytes), digest(spec_path.read_bytes())
        raise _attach_witness(err) from cause

    # Evaluate policy
    policy_inputs = {
        "project_id": project_id,
        "version": version,
        "arch": matched_arch,
        "system": system,
        "asset_sha256": ctx["asset_sha"],
        "payload_manifest_sha256": ctx["payload"].get("payload_manifest_sha256"),
        "closure_sha256": closure_sha if not is_native_desktop else None,
    }
    policy_evidence = evaluate_policy(
        raw_evidence=rpmlint_evidence,
        inventory=inventory,
        inputs=policy_inputs,
        policy=resolved_policy,
    )

    # Check policy acceptance
    if not policy_evidence.get("accepted", False):
        findings = rpmlint_evidence.get("findings", [])
        primary_check = (
            findings[0]["check"]
            if findings
            else policy_evidence.get("reason_token") or rpmlint_evidence.get("reason_token", "policy-rejected")
        )
        details = {
            "substage": "rpmlint",
            "tool": "rpmlint",
            "exit_code": rpmlint_receipt.exit_code,
            "stdout_sha256": rpmlint_receipt.stdout_sha256,
            "stderr_sha256": rpmlint_receipt.stderr_sha256,
            "product": project_id,
            "sha256": rpmlint_evidence["package_sha256"],
            "observed_field_count": len(findings),
            "observed_field_tokens": [_safe_observed_token(f["check"]) for f in findings[:6]],
            "diagnostic_token": _safe_observed_token(primary_check),
            "reason_token": policy_evidence.get("reason_token", "policy-rejected"),
        }
        err = ContractError(
            "RPMLINT_FAILED",
            f"Candidate RPM did not pass rpmlint policy: {primary_check}",
            details=details,
        )
        err.receipt = rpmlint_receipt
        err.evidence = rpmlint_evidence
        err.rpmlint_evidence = rpmlint_evidence
        err.dependency_coverage = {"product":project_id,"required_sonames":sorted(system_sonames) if is_native else [],
                                   "actual_requires":actual_rpm_requires,"actual_provides":actual_rpm_provides,
                                   "coverage":"complete"}
        err.rpmlint_policy = policy_evidence
        err.package_path = str(dest_rpm)
        err.spec_path = str(spec_path)
        err.spec_sha256 = rpmlint_evidence.get("spec_sha256", "")
        err.package_sha256 = rpmlint_evidence.get("package_sha256", "")
        raise _attach_witness(err)

    # Execute createrepo gzip --no-database (atomic: reached ONLY after policy acceptance!)
    from rs9.rpm_repository import metadata_command
    createrepo_cmd = metadata_command(scratch / "repo", binary=createrepo_bin)
    createrepo_receipt = _post_construction_run(createrepo_cmd)
    if createrepo_receipt.exit_code != 0:
        details = {
            "substage": "createrepo",
            "tool": "createrepo",
            "exit_code": createrepo_receipt.exit_code,
            "stdout_sha256": createrepo_receipt.stdout_sha256,
            "stderr_sha256": createrepo_receipt.stderr_sha256,
            "product": project_id,
        }
        err = ContractError(
            "BUILD_FAILED",
            "Candidate local repository indexing failed",
            details=details,
        )
        err.receipt = createrepo_receipt
        err.causal_receipt = createrepo_receipt
        err.rpmlint_evidence, err.rpmlint_policy = rpmlint_evidence, policy_evidence
        err.package_path, err.spec_path = str(dest_rpm), str(spec_path)
        err.package_sha256, err.spec_sha256 = digest(rpm_bytes), digest(spec_path.read_bytes())
        raise _attach_witness(err)

    # Verify repository metadata format, compression, and content linkage before ready
    from rs9.rpm_metadata import verify_repository_metadata
    rel_builder_pkg = f"{matched_arch}/{dest_rpm.name}"
    try:
        verify_repository_metadata(
            scratch / "repo", expected_packages=[rel_builder_pkg],
            is_signed=False, receipt=createrepo_receipt,
        )
    except ContractError as err:
        err.causal_receipt = createrepo_receipt
        err.rpmlint_evidence, err.rpmlint_policy = rpmlint_evidence, policy_evidence
        err.package_path, err.spec_path = str(dest_rpm), str(spec_path)
        err.package_sha256, err.spec_sha256 = digest(rpm_bytes), digest(spec_path.read_bytes())
        raise _attach_witness(err)

    rel_artifact_path = dest_rpm.relative_to(scratch).as_posix()
    validate_safe_relative_posix_path(rel_artifact_path)

    extra_tools = list(query_receipts)
    if rpm_requires_receipt is not None:
        extra_tools.append(rpm_requires_receipt)
    extra_tools.extend([rpm_provides_receipt, *inventory_receipts, rpmlint_receipt, createrepo_receipt])

    boundary_substage = "rpm-derivation-record"
    try:
        from rs9.rpm_evidence import durable_lint_projection, policy_summary
        durable_lint = durable_lint_projection(rpmlint_evidence)
        durable_policy = policy_summary(policy_evidence)

        extra_ev: dict[str, Any] = {
            "rpm_identity": rpm_identity,
            "rpm_payload_digest": rpm_payload_digest,
            "rpmlint_status": rpmlint_evidence["status"],
            "rpmlint_exit_code": rpmlint_receipt.exit_code,
            "rpmlint": durable_lint,
            "rpmlint_policy": durable_policy,
            "createrepo_flags": createrepo_cmd[1:-1],
            "native_preservation": {
                "strip": False,
                "debug": False,
                "mangle_shebangs": False,
                "build_id": False,
            },
            "rpm_query_evidence": {
                "requires": actual_rpm_requires,
                "provides": actual_rpm_provides,
                "self_provides_count": self_provides_count,
            },
            "construction_witness": construction_witness,
        }
        if reproducibility is not None:
            extra_ev["reproducibility"] = reproducibility
        if is_native:
            extra_ev["policy_dependencies"] = policy_dependencies
            extra_ev["elf_dependencies"] = {
                "objects": elf_objects,
                "system_sonames": sorted(system_sonames),
                "derived_packages": derived_deps,
                "covered_sonames": sorted(system_sonames),
                "self_provides_count": self_provides_count,
                "coverage": "complete",
                "redundant_named_requires_removed": sorted(removable_targets) if is_native_desktop else [],
                "rpm6_elf_generator_scope": "all-matching-ELF-including-mode-0644",
            }
            extra_ev["rpm_provides_coverage"] = {
                "status": "covered",
                "required_sonames": sorted(system_sonames),
                "self_provides_count": self_provides_count,
            }

        derivation = create_derivation_record(
            artifact_relpath=rel_artifact_path,
            artifact_bytes=rpm_bytes,
            tool_receipt=rpmbuild_receipt,
            capture=capture,
            intent=intent,
            adapter="rpm",
            arch=matched_arch,
            distro=distro,
            project_id=project_id,
            version=version,
            derived_dependencies=derived_deps,
            extra_tools=extra_tools,
            extra_evidence=extra_ev,
            dependency_classification=dependency_classification,
        )

        manifest = {
            "schema": "rs9.rpm-candidate.v1alpha2",
            "status": "unsigned-candidate",
            "qualification": "unqualified-candidate",
            "can_publish": False,
            "adapter": "rpm",
            "package_class": ctx["product_class"],
            "project": project_id,
            "version": version,
            "revision": revision,
            "architecture": matched_arch,
            "distro": distro,
            "package_file": rel_artifact_path,
            "package_sha256": digest(rpm_bytes),
            "package_size": len(rpm_bytes),
            "spec_file": spec_path.name,
            "spec_sha256": digest(spec_path.read_bytes()),
            "dependencies": derived_deps,
            "dependency_classification": dependency_classification,
            "rpm_identity": rpm_identity,
            "rpm_payload_digest": rpm_payload_digest,
            "rpmlint": rpmlint_evidence,
            "rpmlint_policy": durable_policy,
            "construction_witness": construction_witness,
            "derivation": derivation,
        }
        if reproducibility is not None:
            manifest["reproducibility"] = reproducibility

        boundary_substage = "rpm-manifest-write"
        (scratch / "rpm-manifest.json").write_bytes(canonical(manifest))
    except (ContractError, ValueError, TypeError, OSError) as cause:
        cause_field_path = getattr(cause, "field_path", None)
        cause_rule = getattr(cause, "rule", None) or getattr(cause, "code", "RECORD_BOUNDARY")
        cause_code = getattr(cause, "code", "RECORD_ERROR")
        details = {
            "substage": boundary_substage,
            "product": project_id,
            "reason_token": "record-boundary-failure",
            "diagnostic_token": "record-boundary-failure",
            "underlying_code": cause_code,
            "field_path": cause_field_path or "$",
            "rule": cause_rule,
            "package_sha256": digest(rpm_bytes),
            "spec_sha256": digest(spec_path.read_bytes()),
        }
        err = ContractError(
            "RPM_DERIVATION_RECORD" if boundary_substage == "rpm-derivation-record" else "RPM_MANIFEST_RECORD",
            "Candidate RPM durable record boundary failed",
            details=details,
        )
        err.receipt = None
        err.causal_receipt = None
        err.field_path = cause_field_path
        err.rule = cause_rule
        err.substage = boundary_substage
        err.rpmlint_evidence = rpmlint_evidence
        err.rpmlint_policy = policy_evidence
        err.package_path = str(dest_rpm)
        err.package_sha256 = digest(rpm_bytes)
        err.spec_path = str(spec_path)
        err.spec_sha256 = digest(spec_path.read_bytes())
        err.createrepo_receipt = createrepo_receipt
        err.rpmlint_receipt = rpmlint_receipt
        err.completed_records = ["derivation"] if boundary_substage == "rpm-manifest-write" else []
        raise _attach_witness(err) from cause

    return {
        "manifest": manifest,
        "derivation_record": derivation,
        "rpm_path": dest_rpm,
        "srpm_path": srpms[0] if reproducibility is not None else None,
        "repo_dir": scratch / "repo",
        "receipts": [
            rpmbuild_receipt,
            *query_receipts,
            rpm_requires_receipt,
            rpm_provides_receipt,
            *inventory_receipts,
            rpmlint_receipt,
            createrepo_receipt,
        ],
        "policy_evaluation": policy_evidence,
        "construction_witness": construction_witness,
    }


def main(argv: list[str] | None = None) -> int:
    """CLI driver for RPM candidate builder."""
    parser = argparse.ArgumentParser(description="RS9 RPM Candidate Package Driver")
    parser.add_argument(
        "--arch", required=True, help="Target architecture (x86_64, aarch64, or noarch)"
    )
    parser.add_argument("--capture", required=True, help="Path to evidence capture directory")
    parser.add_argument("--intent", required=True, help="Path to intent JSON")
    parser.add_argument("--scratch", required=True, help="Path to empty scratch directory")
    parser.add_argument("--distro", default="fedora-43", help="Target distro (default: fedora-43)")
    parser.add_argument("--offline-npm", help="Path to offline npm archives JSON")
    parser.add_argument(
        "--check-prerequisites", action="store_true", help="Check tools and exit"
    )

    args = parser.parse_args(argv)

    if args.check_prerequisites:
        status = check_prerequisites("rpm", RPM_REQUIRED_TOOLS)
        print(canonical(status).decode(), end="")
        return 0 if status["available"] else 1

    try:
        from rs9.profiles import selection_for_intent
        from rs9.release_core import authenticate_release

        intent = json.loads(Path(args.intent).read_bytes())
        capture = authenticate_release(selection_for_intent(intent), Path(args.capture))
        offline_npm = None
        if args.offline_npm:
            offline_npm = json.loads(Path(args.offline_npm).read_bytes())

        res = build_rpm_candidate(
            capture,
            intent,
            args.arch,
            args.scratch,
            distro=args.distro,
            offline_npm_archives=offline_npm,
        )
        print(canonical(res["manifest"]).decode(), end="")
        return 0
    except ContractError as err:
        print(f"[{err.code}] {err.message}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
