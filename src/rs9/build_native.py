"""Deterministic RS9 LIVE1 native package candidate builder common foundation.

Provides shared infrastructure for pacman, RPM (Fedora 43), and Debian (Ubuntu 26.04)
candidate drivers:
- Empty scratch root validation and confinement.
- Exact authenticated release capture validation and bootstrap intent binding.
- Truthful architecture and distribution validation.
- Subprocess execution abstraction (normal tool runner seam) with command receipts.
- Explicit unavailable handling when native tools are absent (never fabricate files).
- Offline authenticated npm closure staging for CLI projects.
- Subprocess-derived dependency records bound to artifact/tool/container/source.
- Nebular sidecar verifier and scenario-A runner definitions.
- Command driver CLI API.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import posixpath
import re
import shutil
import stat
import subprocess
import tarfile
from typing import Any, Mapping

from rs9.archives import inspect_archive
from rs9.bootstrap import require_configuration_authority
from rs9.errors import ContractError
from rs9.npm_deps import authenticate_dependencies, closure_for_capture
from rs9.records import closed, record_sha256, snapshot, validate_sanitized_string, validate_sha256
from rs9.release_core import ReleaseCapture, authenticated_record_hash, digest
from rs9.scratch import canonical, physical_directory
from rs9.security import validate_repository, validate_safe_relative_posix_path, validate_summary, validate_version_string


def extract_for_packaging(archive, destination, *, expected_sha256):
    """Inspect the complete archive before writes, preserving explicit modes.

    npm archives can omit directory entries. Their implicit directories use 0755;
    this does not alter any released file, symlink or explicit directory mode.
    """
    destination = physical_directory(destination)
    if any(destination.iterdir()):
        raise ContractError("OUTPUT_NOT_EMPTY", "Empty packaging stage required")
    files = {}
    manifest = inspect_archive(archive, {}, on_file=lambda name, data, mode: files.update({name: data}))
    if digest(Path(archive).read_bytes()) != expected_sha256:
        raise ContractError("INPUT_CHANGED", "Archive changed during inspection")
    entries = {row["path"]: row for row in manifest["members"]}
    for name in entries:
        parent = posixpath.dirname(name)
        while parent:
            if parent in entries and entries[parent]["type"] != "directory":
                raise ContractError("UNSAFE_LINK", "Archive ancestor must be a directory")
            parent = posixpath.dirname(parent)
    for name in sorted(entries, key=lambda item: (item.count("/"), item)):
        row = entries[name]
        path = destination / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if row["type"] == "directory":
            path.mkdir(exist_ok=True)
        elif row["type"] == "file":
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(files[name])
            path.chmod(row["mode"])
        elif row["type"] == "symlink":
            path.symlink_to(row["target"])
        else:
            raise ContractError("UNSAFE_MEMBER", "Unsupported packaging member")
    for row in reversed(manifest["members"]):
        if row["type"] == "directory":
            (destination / row["path"]).chmod(row["mode"])
    return manifest

SUPPORTED_PROJECTS: dict[str, str] = {
    "theme-forge-stellar-burst": "0.6.1",
    "theme-forge-stellar-loom": "0.4.0",
    "theme-forge-solar-sail": "0.2.1",
    "theme-forge-nebular-fusion": "0.6.1",
}

REQUIRED_LICENSE = "AGPL-3.0-or-later"

REQUIRED_COMMANDS: dict[str, set[str]] = {
    "theme-forge-stellar-burst": {"tfsb", "tfsb-studio-service"},
    "theme-forge-stellar-loom": {"tfsl", "tfsl-batch"},
    "theme-forge-solar-sail": {"tfss"},
    "theme-forge-nebular-fusion": {"tfnf"},
}

NATIVE_PROJECTS = {"theme-forge-nebular-fusion"}
CLI_PROJECTS = {
    "theme-forge-stellar-burst",
    "theme-forge-stellar-loom",
    "theme-forge-solar-sail",
}

ADAPTER_COVERAGE: dict[str, dict[str, set[str]]] = {
    "pacman": {
        "native": {"x86_64"},
        "cli": {"any"},
    },
    "rpm": {
        "native": {"x86_64", "aarch64"},
        "cli": {"noarch"},
    },
    "debian": {
        "native": {"amd64", "arm64"},
        "cli": {"all"},
    },
}

SUPPORTED_DISTROS: dict[str, set[str]] = {
    "pacman": {"arch", "archlinux"},
    "rpm": {"fedora-43", "fedora43", "fc43"},
    "debian": {"ubuntu-26.04", "ubuntu 26.04", "ubuntu26.04", "resolute"},
}


class NativePrerequisiteUnavailable(ContractError):
    """Raised when required native platform tools are not installed.

    Native prerequisites absent -> explicit unavailable, never fabricated files.
    """

    def __init__(self, message: str, *, missing_tools: list[str] | None = None) -> None:
        super().__init__("TOOL_UNAVAILABLE", message)
        self.missing_tools = missing_tools or []


class CommandReceipt:
    """Bounded receipt for a normal tool subprocess execution."""

    def __init__(
        self,
        command: list[str],
        exit_code: int,
        stdout_bytes: bytes,
        stderr_bytes: bytes,
        *,
        tool_name: str | None = None,
        tool_path: str | None = None,
        executed: bool = False,
    ) -> None:
        self.command = list(command)
        self.exit_code = int(exit_code)
        self.stdout_bytes = stdout_bytes
        self.stderr_bytes = stderr_bytes
        self.stdout_sha256 = digest(stdout_bytes)
        self.stderr_sha256 = digest(stderr_bytes)
        self.stdout_text = stdout_bytes[:65536].decode("utf-8", errors="replace")
        self.stderr_text = stderr_bytes[:65536].decode("utf-8", errors="replace")
        self.tool_name = tool_name or (command[0] if command else "")
        self.tool_path = tool_path or ""
        self.executed = executed

    def to_record(self) -> dict[str, Any]:
        tool_id = posixpath.basename(self.tool_name) or "tool"
        return {
            "id": tool_id,
            "tool": tool_id,
            "exit_code": self.exit_code,
            "stdout_sha256": self.stdout_sha256,
            "stderr_sha256": self.stderr_sha256,
        }


class CommandRunner:
    """Pluggable runner seam for executing native tools or mocking tool seams."""

    def which(self, tool_name: str) -> str | None:
        raise NotImplementedError

    def run(
        self,
        argv: list[str],
        *,
        cwd: Path | str | None = None,
        env: dict[str, str] | None = None,
    ) -> CommandReceipt:
        raise NotImplementedError


class SubprocessRunner(CommandRunner):
    """Real subprocess runner invoking normal native host tools."""

    def which(self, tool_name: str) -> str | None:
        return shutil.which(tool_name)

    def run(
        self,
        argv: list[str],
        *,
        cwd: Path | str | None = None,
        env: dict[str, str] | None = None,
    ) -> CommandReceipt:
        if not argv:
            raise ContractError("INVALID_ARGUMENT", "Command argv cannot be empty")
        tool = argv[0]
        tool_path = self.which(tool)
        if tool_path is None:
            raise NativePrerequisiteUnavailable(
                f"Native tool '{tool}' not found in PATH", missing_tools=[tool]
            )

        cmd_env = dict(os.environ)
        if env:
            cmd_env.update(env)

        proc = subprocess.run(
            argv,
            cwd=str(cwd) if cwd else None,
            env=cmd_env,
            capture_output=True,
            check=False,
            timeout=600,
        )
        return CommandReceipt(
            argv,
            proc.returncode,
            proc.stdout,
            proc.stderr,
            tool_name=tool,
            tool_path=tool_path,
            executed=True,
        )


class MockCommandRunner(CommandRunner):
    """Testing seam runner supporting registered tool behaviors, refusal, and receipts."""

    def __init__(
        self,
        *,
        available_tools: Mapping[str, str] | None = None,
        handlers: Mapping[str, Any] | None = None,
    ) -> None:
        self.available_tools = dict(available_tools or {})
        self.handlers = dict(handlers or {})
        self.calls: list[dict[str, Any]] = []

    def which(self, tool_name: str) -> str | None:
        return self.available_tools.get(tool_name)

    def run(
        self,
        argv: list[str],
        *,
        cwd: Path | str | None = None,
        env: dict[str, str] | None = None,
    ) -> CommandReceipt:
        if not argv:
            raise ContractError("INVALID_ARGUMENT", "Command argv cannot be empty")
        tool = argv[0]
        tool_path = self.which(tool)
        if tool_path is None:
            raise NativePrerequisiteUnavailable(
                f"Native tool '{tool}' is unavailable", missing_tools=[tool]
            )

        call_info = {"argv": list(argv), "cwd": str(cwd) if cwd else None, "env": env}
        self.calls.append(call_info)

        if tool in self.handlers:
            handler = self.handlers[tool]
            if callable(handler):
                return handler(argv, cwd=cwd, env=env)
            if isinstance(handler, CommandReceipt):
                return handler
            if isinstance(handler, dict):
                return CommandReceipt(
                    argv,
                    handler.get("exit_code", 0),
                    handler.get("stdout", b""),
                    handler.get("stderr", b""),
                    tool_name=tool,
                    tool_path=tool_path,
                )

        return CommandReceipt(
            argv, 0, b"", b"", tool_name=tool, tool_path=tool_path
        )


def validate_scratch_root(scratch_dir: str | Path) -> Path:
    """Validate that scratch root is an existing physical empty directory."""
    path = physical_directory(scratch_dir)
    entries = list(path.iterdir())
    if entries:
        raise ContractError("OUTPUT_NOT_EMPTY", "Scratch root must be empty")
    return path


def check_prerequisites(
    adapter: str,
    required_tools: list[str],
    runner: CommandRunner | None = None,
) -> dict[str, Any]:
    """Check availability of required native tools without creating fake files."""
    r = runner or SubprocessRunner()
    found: dict[str, str | None] = {}
    missing: list[str] = []
    for tool in required_tools:
        p = r.which(tool)
        found[tool] = p
        if p is None:
            missing.append(tool)
    return {
        "adapter": adapter,
        "available": len(missing) == 0,
        "missing": missing,
        "tools": found,
    }


def normalize_distro(adapter: str, distro: str | None) -> str:
    """Normalize and validate target distribution."""
    if not distro or not isinstance(distro, str):
        default_distros = {
            "pacman": "arch",
            "rpm": "fedora-43",
            "debian": "ubuntu-26.04",
        }
        return default_distros[adapter]
    dist_norm = distro.strip().lower()
    if adapter == "debian" and dist_norm in (
        "debian",
        "debian-13",
        "debian13",
        "trixie",
        "bookworm",
    ):
        raise ContractError(
            "UNSUPPORTED_PLATFORM",
            "Debian is not supported; repository scope is explicitly Ubuntu 26.04",
        )
    if dist_norm not in SUPPORTED_DISTROS.get(adapter, set()):
        raise ContractError(
            "UNSUPPORTED_PLATFORM",
            f"Unsupported distribution '{distro}' for adapter '{adapter}'",
        )
    return dist_norm


def validate_build_inputs(
    capture: ReleaseCapture,
    intent: dict[str, Any],
    arch: str,
    *,
    adapter: str,
    distro: str | None = None,
) -> dict[str, Any]:
    """Validate release capture, bootstrap authority, architecture, and licensing."""
    authenticated_record_hash(capture)
    require_configuration_authority(capture, intent)

    if adapter not in ADAPTER_COVERAGE:
        raise ContractError("UNSUPPORTED_PLATFORM", f"Unsupported adapter: {adapter}")

    distro_norm = normalize_distro(adapter, distro)

    proj_val = intent.get("project")
    project_id = (
        proj_val.get("id", "") if isinstance(proj_val, dict) else intent.get("project_id", "")
    )
    if not isinstance(project_id, str) or not re.fullmatch(r"[a-z0-9][a-z0-9+._-]*", project_id):
        raise ContractError("RENDER_VALUE", "Unsafe project identifier")
    if project_id not in SUPPORTED_PROJECTS:
        raise ContractError("UNSUPPORTED_PROJECT", "Invalid candidate project input")

    version = intent.get("version", "")
    validate_version_string(version)
    if version != SUPPORTED_PROJECTS[project_id]:
        raise ContractError("UNSUPPORTED_VERSION", "Invalid candidate project version")

    repo = (
        proj_val.get("repository", "")
        if isinstance(proj_val, dict)
        else intent.get("repository", "")
    )
    validate_repository(repo)
    if capture.record["repository"]["full_name"] != repo:
        raise ContractError("REPOSITORY_MISMATCH", "Capture repository does not match intent")
    if capture.record["release"]["tag"] != intent.get("tag", f"v{version}"):
        raise ContractError("TAG_MISMATCH", "Capture release tag does not match intent")

    lic_val = intent.get("license")
    lic_expr = (
        lic_val.get("expression", "")
        if isinstance(lic_val, dict)
        else (intent.get("license_expression") or intent.get("license", ""))
    )
    if lic_expr != REQUIRED_LICENSE:
        raise ContractError("UNSUPPORTED_LICENSE", "Invalid candidate project license")

    is_native = project_id in NATIVE_PROJECTS
    is_cli = not is_native

    # Architecture truthfulness check:
    # CLI projects must be pacman any, RPM noarch, deb all.
    # Native projects (Nebular) must target actual platform archs.
    arch_norm = arch.strip().lower()
    if is_cli:
        cli_arch_expected = {
            "pacman": "any",
            "rpm": "noarch",
            "debian": "all",
        }[adapter]
        if arch_norm != cli_arch_expected:
            raise ContractError(
                "INVALID_ARCHITECTURE",
                f"CLI project '{project_id}' must target '{cli_arch_expected}' for {adapter}, not '{arch}'",
            )
    else:
        native_arch_allowed = ADAPTER_COVERAGE[adapter]["native"]
        if arch_norm not in native_arch_allowed:
            raise ContractError(
                "INVALID_ARCHITECTURE",
                f"Native project '{project_id}' architecture '{arch}' not supported for {adapter}; allowed: {sorted(native_arch_allowed)}",
            )

    matched_payload = None
    for p in capture.record.get("payloads", []):
        plats = p.get("platforms", ["any"])
        system = (
            "aarch64-linux" if arch_norm in {"aarch64", "arm64"} else "x86_64-linux"
        )
        if system in plats or "any" in plats:
            matched_payload = p
            break
    if not matched_payload:
        raise ContractError("UNSUPPORTED_PLATFORM", "No candidate payload matches target architecture")

    # Validate physical archive existence and sha256
    asset_file = capture.archives.get(matched_payload.get("id")) or (
        capture.root / "assets" / matched_payload["name"]
    )
    if not Path(asset_file).exists():
        raise ContractError("INPUT_CHANGED", "Payload asset file missing")
    actual_sha = digest(Path(asset_file).read_bytes())
    if actual_sha != matched_payload["sha256"]:
        raise ContractError("INPUT_CHANGED", "Payload asset bytes modified before build")

    payload_root = matched_payload.get("root", "package")
    summary = proj_val.get("summary", "Theme Forge release package") if isinstance(proj_val, dict) else "Theme Forge release package"
    validate_summary(summary)

    if is_cli:
        cli_files: dict[str, bytes] = {}
        inspect_archive(Path(asset_file), {}, on_file=lambda name, data, mode: cli_files.update({name: data}))
        assert_no_native_payloads(cli_files, context=f"CLI project payload '{project_id}'")

    return {
        "project_id": project_id,
        "version": version,
        "repository": repo,
        "license": lic_expr,
        "summary": summary,
        "is_native": is_native,
        "is_cli": is_cli,
        "arch": arch_norm,
        "distro": distro_norm,
        "adapter": adapter,
        "payload": matched_payload,
        "payload_root": payload_root,
        "asset_file": Path(asset_file),
        "asset_bytes": Path(asset_file).read_bytes(),
        "asset_sha": actual_sha,
        "asset_name": posixpath.basename(matched_payload["name"]),
    }


NATIVE_LIBRARY_SUFFIXES = (".node", ".so", ".dylib", ".dll", ".a", ".lib")
NATIVE_MAGIC_PREFIXES = (
    b"\x7fELF",                 # ELF
    b"\xfe\xed\xfa\xce",         # Mach-O 32-bit big-endian
    b"\xce\xfa\xed\xfe",         # Mach-O 32-bit little-endian
    b"\xfe\xed\xfa\xcf",         # Mach-O 64-bit big-endian
    b"\xcf\xfa\xed\xfe",         # Mach-O 64-bit little-endian
    b"\xca\xfe\xba\xbe",         # Mach-O Fat / Universal 32-bit big-endian
    b"\xbe\xba\xfe\xca",         # Mach-O Fat / Universal 32-bit little-endian
    b"\xca\xfe\xba\xbf",         # Mach-O Fat / Universal 64-bit big-endian
    b"\xbf\xba\xfe\xca",         # Mach-O Fat / Universal 64-bit little-endian
    b"MZ",                       # PE / DOS executable
)


def is_native_payload(name: str, data: bytes) -> bool:
    """Detect native architecture-dependent payloads (Mach-O, PE, ELF, native libs)."""
    name_lower = name.lower()
    if any(name_lower.endswith(sfx) for sfx in NATIVE_LIBRARY_SUFFIXES):
        return True
    if ".so." in name_lower or ".dylib." in name_lower:
        return True
    if data.startswith(NATIVE_MAGIC_PREFIXES):
        return True
    return False


def assert_no_native_payloads(files: Mapping[str, bytes], context: str = "Payload") -> None:
    """Fail closed if any architecture-independent payload member is a native binary."""
    for name, data in files.items():
        if is_native_payload(name, data):
            raise ContractError(
                "INVALID_ARCHITECTURE",
                f"{context} contains native payload '{name}'; architecture-independent packages forbid native binaries",
            )


def stage_offline_npm_closure(
    capture: ReleaseCapture,
    project_id: str,
    offline_npm_archives: Mapping[str, str | Path] | None,
    target_node_modules_dir: Path,
) -> list[dict[str, Any]]:
    """Stage authenticated offline npm closure for CLI projects or fail closed."""
    package = json.loads(capture.source["package.json"])
    if any(package.get(key) for key in ("optionalDependencies", "peerDependencies")):
        raise ContractError("NPM_CLOSURE", "Optional/peer dependencies require qualification")
    if not package.get("dependencies") and project_id != "theme-forge-stellar-burst":
        if offline_npm_archives:
            raise ContractError("NPM_CLOSURE", "Unexpected runtime dependencies")
        return []
    if offline_npm_archives is None:
        raise ContractError("NPM_CLOSURE", "Lock-bound offline dependency archives required")
    records = authenticate_dependencies(capture, offline_npm_archives)
    base = target_node_modules_dir.parent
    for row in records["dependencies"]:
        archive = Path(offline_npm_archives[row["path"]])
        files = {}
        manifest = inspect_archive(archive, {}, on_file=lambda name, data, mode: files.update({name: data}))
        if digest(archive.read_bytes()) != row["sha256"]:
            raise ContractError("INPUT_CHANGED", "Npm dependency changed during staging")
        assert_no_native_payloads(files, context=f"Npm dependency '{row['path']}'")
        for name, data in files.items():
            if name.endswith("/package.json"):
                info = json.loads(data)
                if info.get("cpu") or info.get("os"):
                    raise ContractError("INVALID_ARCHITECTURE", "Platform restricted npm dependencies require qualification")
        destination = target_node_modules_dir / row["path"].removeprefix("node_modules/")
        if destination.exists() or destination.is_symlink():
            raise ContractError("NPM_CLOSURE", "Dependency staging collision")
        temporary = base / ("dependency-" + digest(row["path"].encode())[:16])
        temporary.mkdir()
        extracted = extract_for_packaging(archive, temporary, expected_sha256=row["sha256"])
        root_name = extracted["root"]
        destination.parent.mkdir(parents=True, exist_ok=True)
        (temporary / root_name).rename(destination)
        temporary.rmdir()
    return records["dependencies"]


def npm_bundle(directory, output):
    """Deterministic local closure bundle; never invokes npm or a network tool."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    import gzip
    with Path(output).open("xb") as stream, gzip.GzipFile(fileobj=stream, mode="wb", mtime=0, filename="") as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for path in [directory, *sorted(directory.rglob("*"))]:
                name = "node_modules" + ("/" + path.relative_to(directory).as_posix() if path != directory else "")
                info = archive.gettarinfo(str(path), arcname=name)
                info.uid = info.gid = info.mtime = 0
                info.uname = info.gname = ""
                if info.isfile():
                    with path.open("rb") as data:
                        archive.addfile(info, data)
                else:
                    archive.addfile(info)
    return digest(Path(output).read_bytes())


def stage_payload(capture, payload, destination, scratch):
    """Use the unchanged reviewed extractor; preserve every member and mode."""
    destination, scratch = Path(destination), physical_directory(scratch)
    archive = capture.archives[payload["id"]]
    manifest = capture.manifests[payload["id"]]
    if digest(archive.read_bytes()) != payload["sha256"] or manifest["manifest_sha256"] != payload["payload_manifest_sha256"]:
        raise ContractError("INPUT_CHANGED", "Payload staging identity mismatch")
    stage = scratch / "exact-payload-stage"
    stage.mkdir()
    extracted = extract_for_packaging(archive, stage, expected_sha256=payload["sha256"])
    if extracted["manifest_sha256"] != payload["payload_manifest_sha256"]:
        raise ContractError("INPUT_CHANGED", "Packaging manifest differs from release")
    root_name = extracted["root"]
    if destination.exists():
        destination.rmdir()
    (stage / root_name).rename(destination)
    stage.rmdir()
    return destination


def create_derivation_record(
    *,
    artifact_relpath: str,
    artifact_bytes: bytes,
    tool_receipt: CommandReceipt,
    capture: ReleaseCapture,
    intent: dict[str, Any],
    adapter: str,
    arch: str,
    distro: str,
    project_id: str,
    version: str,
    derived_dependencies: list[str],
    extra_tools: list[CommandReceipt] | None = None,
    extra_evidence: dict[str, Any] | None = None,
    dependency_classification: str = "reviewed-policy",
) -> dict[str, Any]:
    """Create a bounded derivation record from actual tool subprocess output."""
    validate_safe_relative_posix_path(artifact_relpath)
    if dependency_classification not in {"reviewed-policy", "native-tool-derived"}:
        raise ContractError("DEPENDENCY_DERIVATION", "Explicit dependency evidence class required")
    tool_records = [tool_receipt.to_record()] + [
        t.to_record() for t in (extra_tools or [])
    ]

    record = {
        "schema": "rs9.native-derivation.v1alpha1",
        "status": "candidate",
        "qualification": "unqualified-candidate",
        "can_publish": False,
        "adapter": adapter,
        "architecture": arch,
        "distro": distro,
        "project": project_id,
        "version": version,
        "artifact": {
            "path": artifact_relpath,
            "size": len(artifact_bytes),
            "sha256": digest(artifact_bytes),
        },
        "tool": tool_records[0],
        "tool_receipts": tool_records,
        "container": {
            "os": platform.system(),
            "machine": platform.machine(),
            "builder_source_sha256": digest(Path(__file__).read_bytes()),
        },
        "source": {
            "release_record_sha256": authenticated_record_hash(capture),
            "config_sha256": record_sha256(intent),
        },
        "dependency_classification": dependency_classification,
        "derived_dependencies": sorted(set(derived_dependencies)),
        "derivation_source": ("reviewed-policy" if dependency_classification == "reviewed-policy"
                              else "actual-native-tool-subprocess" if tool_receipt.executed
                              else "synthetic-command-seam"),
        "builder_execution_source": "actual-native-tool-subprocess" if tool_receipt.executed else "synthetic-command-seam",
    }
    if extra_evidence:
        record["evidence"] = extra_evidence

    return snapshot(record)


def verify_nebular_sidecar(
    install_root: Path,
    *,
    scenario_a: dict[str, Any] | None = None,
    runner: CommandRunner | None = None,
) -> dict[str, Any]:
    """Diagnostic layout presence only; no released native verifier is implemented.

    A caller command or --version result cannot prove the released sidecar verifier
    or scenario-A. This helper never executes that unbound command or claims a gate.
    """
    root = physical_directory(install_root)
    checks = {
        "binary_present": (root / "usr/lib/theme-forge-nebular-fusion/tfnf").is_file(),
        "launcher_present": (root / "usr/bin/tfnf").exists() or (root / "usr/bin/tfnf").is_symlink(),
        "desktop_present": (root / "usr/share/applications/theme-forge-nebular-fusion.desktop").is_file(),
        "icon_present": (root / "usr/share/icons/hicolor/256x256/apps/theme-forge-nebular-fusion.png").is_file(),
    }
    return {"status": "not-run", "qualification": "unqualified", "checks": checks,
            "sidecar_verifier": "not-run", "scenario_a": {"status": "not-run"},
            "reason": "authenticated released verifier and scenario-A binding required"}


def validate_maintainer(maintainer: str | None) -> str:
    """Validate explicit maintainer argument. Never invent maintainer email."""
    if not maintainer or not isinstance(maintainer, str) or not maintainer.strip():
        raise ContractError(
            "MISSING_MAINTAINER",
            "Explicit maintainer is required; no default maintainer permitted",
        )
    m = maintainer.strip()
    if "\r" in m or "\n" in m:
        raise ContractError("INVALID_METADATA", "CR or newline injection in maintainer")
    if not re.fullmatch(r"[^<>\r\n]+<[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+>", m):
        raise ContractError("INVALID_METADATA", "Maintainer must be in 'Name <email@domain>' format")
    validate_sanitized_string(m, max_length=256)
    return m


def build_native_main(argv: list[str] | None = None) -> int:
    """Command driver CLI API for normal native package candidate builders."""
    parser = argparse.ArgumentParser(
        description="RS9 Normal-Tool Native Package Candidate Driver"
    )
    parser.add_argument(
        "--adapter",
        required=True,
        choices=["pacman", "rpm", "debian"],
        help="Target packaging adapter",
    )
    parser.add_argument("--arch", required=True, help="Target architecture")
    parser.add_argument(
        "--distro",
        default=None,
        help="Target distribution (e.g. arch, fedora-43, ubuntu-26.04)",
    )
    parser.add_argument("--capture", help="Path to evidence capture directory")
    parser.add_argument("--intent", help="Path to normalized bootstrap intent JSON")
    parser.add_argument("--scratch", help="Path to empty scratch directory")
    parser.add_argument(
        "--maintainer",
        help="Explicit maintainer string (required for debian, e.g. 'Name <email@domain>')",
    )
    parser.add_argument(
        "--offline-npm",
        help="Path to JSON file mapping node_modules paths to offline archives",
    )
    parser.add_argument(
        "--check-prerequisites",
        action="store_true",
        help="Check tool availability without building",
    )

    args = parser.parse_args(argv)

    try:
        from rs9.build_pacman import build_pacman_candidate, PACMAN_REQUIRED_TOOLS
        from rs9.build_rpm import build_rpm_candidate, RPM_REQUIRED_TOOLS
        from rs9.build_deb import build_deb_candidate, DEB_REQUIRED_TOOLS

        tool_map = {
            "pacman": (PACMAN_REQUIRED_TOOLS, build_pacman_candidate),
            "rpm": (RPM_REQUIRED_TOOLS, build_rpm_candidate),
            "debian": (DEB_REQUIRED_TOOLS, build_deb_candidate),
        }
        tools, builder = tool_map[args.adapter]

        if args.check_prerequisites:
            status = check_prerequisites(args.adapter, tools)
            print(canonical(status).decode(), end="")
            return 0 if status["available"] else 1

        if not args.capture or not args.intent or not args.scratch:
            raise ContractError(
                "MISSING_ARGUMENT",
                "--capture, --intent, and --scratch are required for building candidates",
            )

        intent = json.loads(Path(args.intent).read_bytes())
        from rs9.release_core import authenticate_release
        from rs9.profiles import selection_for_intent

        capture = authenticate_release(selection_for_intent(intent), Path(args.capture))

        offline_npm = None
        if args.offline_npm:
            offline_npm = json.loads(Path(args.offline_npm).read_bytes())

        extra_kwargs: dict[str, Any] = {}
        if args.adapter == "debian":
            extra_kwargs["maintainer"] = args.maintainer

        result = builder(
            capture,
            intent,
            args.arch,
            args.scratch,
            distro=args.distro,
            offline_npm_archives=offline_npm,
            **extra_kwargs,
        )
        print(canonical(result["manifest"]).decode(), end="")
        return 0

    except ContractError as err:
        print(f"[{err.code}] {err.message}")
        return 2
    except Exception as exc:
        print(f"[BUILD_ERROR] {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(build_native_main())
