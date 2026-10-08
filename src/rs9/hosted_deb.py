"""Hosted Ubuntu 26.04 APT and assembled-Pages candidate lanes (family ``deb`` and ``pages``).

``execute(context)`` is the shared hosted lane interface; it returns
``{"gates": [...], "artifacts": [Path], "details": {...}}`` and never raises for lane-level
blockers, so partial evidence is retained. Everything is nonproduction:

deb lane (amd64 or arm64 runner, Ubuntu 26.04 'resolute' container of the runner architecture)
- builds two architecture-all pure JS debs and architecture-specific Burst/Nebular debs; Nebular dependencies
  come only from dpkg-shlibdeps over every ELF object plus the installed dpkg inventory;
- assembles ONE repository (pool, dists, by-hash, Packages/.gz/.xz in both amd64 and arm64
  indexes) and signs it with a real GnuPG NONPRODUCTION fixture key (InRelease, Release.gpg);
- installs, runs unprivileged probes, purges and inventories each product in a fresh
  provisioned client whose network is disconnected (``--network none``), then proves that a
  tampered package, tampered index, corrupted signature and wrong signing key are rejected;
- retains the exact unsigned debs as a custody bundle with a Merkle manifest.

pages lane (generation)
- verifies downloaded unsigned custody bundles exactly, rebuilds ALL repository metadata
  (APT, createrepo, repo-add) and signs it with a fresh NONPRODUCTION fixture key;
- assembles the strict tree (apt, rpm, pacman, keys, docs, CNAME rs9.knowledge-forge.ai),
  runs the format-aware privacy scan and an exact Merkle inventory;
- install-tests the ASSEMBLED tree per client family (apt, dnf, pacman) network-disconnected.

A gate is ``pass`` only when its commands really ran (``CommandReceipt.executed``); a synthetic
command seam yields ``not-run``. Missing tools, digests, maintainers or custody yield
``not-run``; any failed assertion yields ``fail``. Nothing here can publish or deploy.
"""

from __future__ import annotations

import copy
import json
import os
import time
from pathlib import Path
import re
import shutil
from typing import Any, Mapping, Sequence
import uuid

from rs9.apt_diagnostics import (
    trust_identity,
    build_positive_control,
    classify_rejection,
    probe_guest_trust,
    qualify_tamper_rejection,
    record_command_diagnostics,
    validate_positive_control,
)
from rs9.build_deb import build_deb_candidate
from rs9.build_native import (
    REQUIRED_COMMANDS,
    CommandReceipt,
    CommandRunner,
    NativePrerequisiteUnavailable,
    SubprocessRunner,
    validate_scratch_root,
)
from rs9.errors import ContractError, safe_details
from rs9.hosted_native import compare_inventories, execute_probes, is_excluded_inventory_path
from rs9.hosted_native import provision as provision_native
from rs9.npm_deps import resolve_offline_npm_archives
from rs9.pages import merkle_inventory, verify_merkle_inventory
from rs9.pages_candidate import (
    CLIENT_KEYRING_PATH,
    CUSTODY_MANIFEST,
    PAGES_HOST,
    assemble_pages_candidate,
    collect_candidate_sources,
    exact_inventory_for,
    load_custody_bundle,
    render_install_docs,
    verify_pages_completeness,
    write_custody_bundle,
)
from rs9.release_core import digest
from rs9.repo_apt import (
    AptRepositoryCandidate,
    apt_source_line,
    parse_deb_control,
    tamper_apt_repository,
    verify_apt_signatures,
)
from rs9.scratch import canonical, physical_directory

SCHEMA_DEB = "rs9.hosted-deb-manifest.v1alpha1"
SCHEMA_PAGES = "rs9.hosted-pages-manifest.v1alpha1"

DEB_PLATFORMS = {"amd64": "linux/amd64", "arm64": "linux/arm64"}
REQUIRED_PRODUCTS = (
    "theme-forge-stellar-burst",
    "theme-forge-stellar-loom",
    "theme-forge-solar-sail",
    "theme-forge-nebular-fusion",
)
NATIVE_PRODUCT = "theme-forge-nebular-fusion"
CLIENT_USER = "65534:65534"
SERVER_ROOT = "/srv/rs9"
APT_LIST = "/etc/apt/rs9-nonproduction.list"
DNF_REPO_FILE = "/etc/yum.repos.d/rs9-nonproduction.repo"
DNF_REPO_ID = "rs9-fedora-nonproduction"
PACMAN_CONF = "/etc/rs9-pacman.conf"
TAMPER_KINDS_ALL = ("package", "index", "signature", "wrongkey")
TAMPER_KINDS_PAGES = ("package", "index", "signature", "wrongkey")

# Documented provisioning inputs; pins['deb']['build_packages'] overrides the native library set.
BUILD_TOOL_PACKAGES = ("dpkg-dev", "binutils")
DEFAULT_NATIVE_LIBRARY_PACKAGES = (
    "libgtk-3-0t64", "libcairo2", "libpango-1.0-0", "libgdk-pixbuf-2.0-0", "libsoup-3.0-0",
    "libwebkit2gtk-4.1-0", "libjavascriptcoregtk-4.1-0",
)

_PACKAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+._-]*(:[a-z0-9-]+)?$")
_FINGERPRINT_RE = re.compile(r"^[0-9A-F]{40}$")

_COMMON_EXCLUDES = (r"^etc/ld\.so\.cache$", r"^usr/share/icons/hicolor/icon-theme\.cache$")
INVENTORY_EXCLUDES: dict[str, list[re.Pattern[str]]] = {
    "apt": [re.compile(p) for p in (
        r"^var/lib/dpkg(/.*)?$", r"^var/lib/apt(/.*)?$", r"^var/cache/apt(/.*)?$",
        r"^var/log/(apt(/.*)?|dpkg\.log|alternatives\.log|bootstrap\.log)$",
        r"^var/cache/debconf(/.*)?$", r"^var/cache/ldconfig(/.*)?$", *_COMMON_EXCLUDES)],
    "dnf": [re.compile(p) for p in (
        r"^var/lib/dnf(/.*)?$", r"^var/cache/libdnf5(/.*)?$", r"^var/lib/rpm-state(/.*)?$", *_COMMON_EXCLUDES)],
    "pacman": [re.compile(p) for p in (r"^etc/pacman\.d/gnupg(/.*)?$", *_COMMON_EXCLUDES)],
}

from rs9.client_inventory import parse_inventory as parse_client_inventory, run_and_parse


# --------------------------------------------------------------------------- gates and runners


def _gate(name: str, status: str, reason: str | None = None, **extra: Any) -> dict[str, Any]:
    row: dict[str, Any] = {"name": name, "status": status}
    if reason:
        row["reason"] = reason
    row.update(extra)
    return row


def _status(ok: bool, real: bool) -> tuple[str, str | None]:
    """pass needs both a satisfied assertion and commands that really ran."""
    if not ok:
        return "fail", None
    if not real:
        return "not-run", "synthetic-command-seam"
    return "pass", None


def _fold(rows: Sequence[dict[str, Any]]) -> str:
    """Aggregate: any fail -> fail; else any not-run (or none) -> not-run; else pass."""
    statuses = [row["status"] for row in rows]
    if "fail" in statuses:
        return "fail"
    if not statuses or "not-run" in statuses:
        return "not-run"
    return "pass"


class RecordingRunner(CommandRunner):
    """Records every receipt so a stage can prove its commands were actually executed."""

    def __init__(self, inner: CommandRunner) -> None:
        self.inner = inner
        self.receipts: list[CommandReceipt] = []

    def which(self, tool_name: str) -> str | None:
        return self.inner.which(tool_name)

    def run(self, argv: list[str], *, cwd: Path | str | None = None, env: dict[str, str] | None = None) -> CommandReceipt:
        receipt = self.inner.run(argv, cwd=cwd, env=env)
        self.receipts.append(receipt)
        return receipt

    def mark(self) -> int:
        return len(self.receipts)

    def real_since(self, mark: int) -> bool:
        rows = self.receipts[mark:]
        return bool(rows) and all(row.executed for row in rows)

    def records_since(self, mark: int, limit: int = 200) -> list[dict[str, Any]]:
        return [row.to_record() for row in self.receipts[mark:][:limit]]


class ContainerRunner(CommandRunner):
    """Runs each tool in a throwaway container; receipts keep the inner tool identity."""

    def __init__(
        self,
        host: CommandRunner,
        image: str,
        *,
        platform: str,
        mounts: Sequence[tuple[str, str, bool]] = (),
        network: bool = False,
        user: str | None = None,
    ) -> None:
        self.host, self.image, self.platform = host, image, platform
        self.mounts, self.network, self.user = list(mounts), network, user

    def docker_argv(self, argv: Sequence[str], cwd: Path | str | None = None, env: Mapping[str, str] | None = None) -> list[str]:
        command = ["docker", "run", "--rm", "--platform", self.platform]
        if not self.network:
            command += ["--network", "none"]
        if self.user:
            command += ["--user", self.user, "-e", "HOME=/tmp"]
        for source, target, writable in self.mounts:
            command += ["-v", f"{source}:{target}" + ("" if writable else ":ro")]
        if cwd:
            command += ["-w", str(cwd)]
        for key, value in sorted((env or {}).items()):
            command += ["-e", f"{key}={value}"]
        return [*command, self.image, *argv]

    def which(self, tool_name: str) -> str | None:
        if not re.fullmatch(r"[A-Za-z0-9_.+-]+", tool_name):
            raise ContractError("INVALID_ARGUMENT", "Unsafe tool name")
        receipt = self.host.run(self.docker_argv(["sh", "-c", f"command -v {tool_name}"]))
        located = receipt.stdout_text.strip()
        return located if receipt.exit_code == 0 and located else None

    def run(self, argv: list[str], *, cwd: Path | str | None = None, env: dict[str, str] | None = None) -> CommandReceipt:
        if not argv:
            raise ContractError("INVALID_ARGUMENT", "Command argv cannot be empty")
        try:
            outer = self.host.run(self.docker_argv(argv, cwd, env))
        except NativePrerequisiteUnavailable:
            raise
        except ContractError as error:
            raise error.with_details(tool=Path(argv[0]).name, substage="container-tool") from None
        return CommandReceipt(
            list(argv), outer.exit_code, outer.stdout_bytes, outer.stderr_bytes,
            tool_name=argv[0], tool_path=f"container:{self.image}", executed=outer.executed,
        )


def _user() -> str | None:
    return None if os.getuid() == 0 else f"{os.getuid()}:{os.getgid()}"


# --------------------------------------------------------------------------- inventory


def inventory_excluded(family: str, rel_path: str) -> bool:
    """Documented package-manager state and generated caches only."""
    return is_excluded_inventory_path(rel_path) or any(p.search(rel_path) for p in INVENTORY_EXCLUDES[family])


def inventory_samples(paths):
    """Escape filename bytes and cap failure details without retaining snapshots."""
    return [path.encode("utf-8", errors="backslashreplace").decode("utf-8").encode("unicode_escape").decode("ascii")[:256]
            for path in paths[:40]]


def parse_inventory(stdout: bytes, family: str) -> dict[str, str]:
    """Versioned byte-lossless transport with the maintained family exclusions."""
    return parse_client_inventory(stdout, exclusion=lambda path: inventory_excluded(family, path), with_modes=True)


# --------------------------------------------------------------------------- containers


def _record_receipt(recorder, host, receipt):
    if recorder is not None and recorder is not host and hasattr(recorder, "receipts"):
        recorder.receipts.append(receipt)


def _preparation_rows(recorder):
    if recorder is None:
        return None
    if isinstance(recorder, list):
        return recorder
    if not hasattr(recorder, "preparation"):
        recorder.preparation = []
    return recorder.preparation


def _timeout_runner(host):
    current = host
    while hasattr(current, "inner") or hasattr(current, "host"):
        current = current.inner if hasattr(current, "inner") else current.host
    return current if isinstance(current, SubprocessRunner) else None


def _bounded_runner(host, limit):
    """Copy runner wrappers, preserving receipt sinks without changing shared deadlines."""
    if isinstance(host, SubprocessRunner):
        bounded = copy.copy(host)
        bounded.timeout = limit if host.timeout is None else min(host.timeout, limit)
        return bounded
    link = "inner" if hasattr(host, "inner") else "host" if hasattr(host, "host") else None
    if link is None:
        return host
    bounded = copy.copy(host)
    setattr(bounded, link, _bounded_runner(getattr(host, link), limit))
    return bounded


def _prep_step(host, recorder, substage, argv, *, timeout_limit=None, **kwargs):
    """Retain every preparation boundary, including failures before a receipt exists."""
    rows = _preparation_rows(recorder)
    command_host = _bounded_runner(host, timeout_limit) if timeout_limit is not None else host
    timed = _timeout_runner(command_host)
    deadline = getattr(timed, "timeout", None)
    row = {"stage": "container-preparation", "substage": substage,
           "tool": Path(argv[0]).name, "deadline_seconds": int(deadline) if deadline is not None else None}
    start = time.monotonic()
    try:
        receipt = command_host.run(argv, **kwargs)
    except ContractError as error:
        details = {"stage": "container-preparation", "substage": substage,
                   "tool": Path(argv[0]).name,
                   "elapsed_ms": max(0, int((time.monotonic() - start) * 1000)),
                   **error.details}
        details.update(stage="container-preparation", substage=substage)
        row.update(safe_details(details), outcome="timeout" if error.code == "TOOL_TIMEOUT" else "error",
                   code=error.code, exit_code=None)
        if rows is not None:
            rows.append(row)
        if isinstance(error, NativePrerequisiteUnavailable):
            raise
        raise error.with_details(**details) from None
    except OSError:
        row.update(outcome="error", code="TOOL_EXECUTION", exit_code=None,
                   elapsed_ms=max(0,int((time.monotonic()-start)*1000)))
        if rows is not None:
            rows.append(row)
        raise ContractError("TOOL_EXECUTION", "Preparation command could not execute",
                            details=safe_details(row)) from None
    row.update(outcome="completed" if receipt.exit_code == 0 else "error", exit_code=receipt.exit_code,
               elapsed_ms=max(0, int((time.monotonic() - start) * 1000)),
               stdout_sha256=receipt.stdout_sha256, stderr_sha256=receipt.stderr_sha256,
               executed=receipt.executed)
    if rows is not None:
        rows.append(row)
    _record_receipt(recorder, host, receipt)
    return receipt


def _cleanup_step(host, recorder, argv, substage="cleanup"):
    # A finite command deadline for exact phase-owned cleanup, never a retry.
    try:
        return "complete" if _prep_step(host, recorder, substage, argv, timeout_limit=30).exit_code == 0 else "failed"
    except (ContractError, OSError):
        return "failed"


class _PreparationTools(CommandRunner):
    def __init__(self, inner, recorder):
        self.inner, self.recorder = inner, recorder
    def which(self, name):
        if not re.fullmatch(r"[A-Za-z0-9_.+-]+", name):
            raise ContractError("INVALID_ARGUMENT", "Unsafe tool name")
        receipt = self.run(["sh", "-c", f"command -v {name}"])
        located = receipt.stdout_text.strip()
        return located if receipt.exit_code == 0 and located else None
    def run(self, argv, **kwargs):
        if not isinstance(self.inner, ContainerRunner):
            return _prep_step(self.inner, self.recorder, "container-tool", argv, **kwargs)
        name = f"rs9-tool-{uuid.uuid4().hex[:12]}"
        command = self.inner.docker_argv(argv, **kwargs)
        command.remove("--rm")
        command[2:2] = ["--name", name]
        try:
            outer = _prep_step(self.inner.host, self.recorder, "container-tool", command)
        except BaseException as error:
            cleanup = _cleanup_step(self.inner.host, self.recorder, ["docker", "rm", "-f", name])
            if isinstance(error, ContractError) and not isinstance(error, NativePrerequisiteUnavailable):
                raise error.with_details(cleanup=cleanup) from None
            raise
        cleanup = _cleanup_step(self.inner.host, self.recorder, ["docker", "rm", "-f", name])
        if cleanup != "complete":
            raise ContractError("CONTAINER_CLEANUP", "Preparation tool container cleanup failed",
                                details={"stage": "container-preparation", "substage": "cleanup", "cleanup": cleanup})
        return CommandReceipt(list(argv), outer.exit_code, outer.stdout_bytes, outer.stderr_bytes,
                              tool_name=argv[0], tool_path=f"container:{self.inner.image}", executed=outer.executed)


def _verify_public_tree_modes(root):
    from rs9.repo_apt import verify_public_tree_modes
    return verify_public_tree_modes(root)


def _write_public_keyring(path, data):
    from rs9.signed_store import _safe_write_file
    _safe_write_file(path, data, mode=0o644)


def _digest_from_inspect(text: str) -> tuple[str | None, str | None]:
    parts = text.strip().split("|")
    reference = parts[0] if parts else ""
    arch = parts[1] if len(parts) > 1 else None
    return (reference.split("@", 1)[1] if "@sha256:" in reference else None), arch


def prepare_environment(
    host: CommandRunner,
    system: str,
    pins: Mapping[str, Any],
    recorder: Any = None,
) -> dict[str, Any]:
    """Pull the Ubuntu 26.04 base (pinned digest or run-resolved) and verify what actually runs."""
    cfg = (pins or {}).get("deb", {}) or {}
    pin = (cfg.get("container_digests", {}) or {}).get(system) or cfg.get("image")
    pin_digest = None
    if pin and str(pin).startswith("sha256:"):
        reference, pin_digest = f"ubuntu@{pin}", str(pin)
    elif pin and "@sha256:" in str(pin):
        reference, pin_digest = str(pin), "sha256:" + str(pin).split("@sha256:")[1]
    else:
        reference = str(pin) if pin else "ubuntu:26.04"
    platform = DEB_PLATFORMS[system]
    try:
        pulled = _prep_step(host, recorder, "pull", ["docker", "pull", "--platform", platform, reference])
    except NativePrerequisiteUnavailable:
        raise
    except ContractError as err:
        raise err.with_details(substage="pull", tool="docker") from None
    if pulled.exit_code != 0:
        raise ContractError("CONTAINER_PULL_FAILED", f"docker pull failed with exit code {pulled.exit_code}",
                            details={"substage": "pull", "tool": "docker", "exit_code": pulled.exit_code,
                                     "stdout_sha256": pulled.stdout_sha256, "stderr_sha256": pulled.stderr_sha256})
    try:
        inspected = _prep_step(host, recorder, "inspect", ["docker", "image", "inspect", "--format", "{{index .RepoDigests 0}}|{{.Architecture}}", reference])
    except NativePrerequisiteUnavailable:
        raise
    except ContractError as err:
        raise err.with_details(substage="inspect", tool="docker") from None
    resolved, image_arch = _digest_from_inspect(inspected.stdout_text)
    if inspected.exit_code != 0 or not resolved:
        raise ContractError("CONTAINER_DIGEST_UNRESOLVED", "Container image digest could not be resolved",
                            details={"substage": "inspect", "tool": "docker", "exit_code": inspected.exit_code,
                                     "stdout_sha256": inspected.stdout_sha256, "stderr_sha256": inspected.stderr_sha256})
    if pin_digest is not None and resolved != pin_digest:
        raise ContractError("CONTAINER_DIGEST_MISMATCH", "Pulled image digest differs from the source pin",
                            details={"substage": "pin", "tool": "docker", "expected_digest": pin_digest, "actual_digest": resolved})
    if image_arch != system:
        raise ContractError("INVALID_ARCHITECTURE", "Container image architecture differs from the lane system",
                            details={"substage": "architecture", "tool": "docker", "exit_code": inspected.exit_code,
                                     "stdout_sha256": inspected.stdout_sha256, "stderr_sha256": inspected.stderr_sha256})
    pinned_ref = f"ubuntu@{resolved}"
    probe_name = f"rs9-release-probe-{uuid.uuid4().hex[:12]}"
    try:
        try:
            release = _prep_step(host, recorder, "release-probe", ["docker", "run", "--name", probe_name, "--platform", platform, "--network", "none", pinned_ref,
                                "sh", "-c", "cat /etc/os-release && dpkg --print-architecture"])
        except NativePrerequisiteUnavailable:
            raise
        except ContractError as err:
            raise err.with_details(substage="release-probe", tool="docker") from None
        fields = dict(
            line.split("=", 1) for line in release.stdout_text.splitlines() if "=" in line and not line.startswith("#")
        )
        lines = [line for line in release.stdout_text.splitlines() if line.strip()]
        version_id = fields.get("VERSION_ID", "").strip('"')
        codename = fields.get("VERSION_CODENAME", "").strip('"')
        if release.exit_code != 0 or version_id != "26.04" or codename != "resolute":
            raise ContractError("UNSUPPORTED_PLATFORM", "Container is not Ubuntu 26.04 resolute",
                                details={"substage": "distro", "tool": "cat", "exit_code": release.exit_code,
                                         "stdout_sha256": release.stdout_sha256, "stderr_sha256": release.stderr_sha256})
        if not lines or lines[-1].strip() != system:
            raise ContractError("INVALID_ARCHITECTURE", "Container dpkg architecture differs from the lane system",
                                details={"substage": "architecture", "tool": "dpkg", "exit_code": release.exit_code,
                                         "stdout_sha256": release.stdout_sha256, "stderr_sha256": release.stderr_sha256})
    except BaseException as exc:
        cleanup = _cleanup_step(host, recorder, ["docker", "rm", "-f", probe_name])
        if isinstance(exc, NativePrerequisiteUnavailable):
            raise
        if isinstance(exc, ContractError):
            raise exc.with_details(cleanup=cleanup) from None
        raise
    else:
        cleanup = _cleanup_step(host, recorder, ["docker", "rm", "-f", probe_name])
        if cleanup != "complete":
            raise ContractError("CONTAINER_CLEANUP", "Preparation container cleanup failed",
                                details={"stage":"container-preparation", "substage":"cleanup", "cleanup":cleanup})
    source_pinned = pin_digest is not None and (pins.get("pin_provenance") or {}).get("deb." + system, "source-pinned") == "source-pinned"
    return {
        "image_ref": pinned_ref,
        "digest": resolved,
        "source_pinned": source_pinned,
        "unpinned": not source_pinned,
        "platform": platform,
        "version_id": version_id,
        "codename": codename,
        "dpkg_architecture": lines[-1].strip(),
    }


PROVISION_COMMANDS = {
    "apt": "apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends {packages}",
    "dnf": "dnf -y install {packages}",
    "pacman": "pacman -Sy --noconfirm --needed {packages}",
}


def provision_image(
    host: CommandRunner,
    family: str,
    base_ref: str,
    platform: str,
    tag: str,
    packages: Sequence[str],
    recorder: Any = None,
    substage_prefix: str = "",
) -> str:
    """Network-enabled one-time provisioning, committed to a local image used offline afterwards."""
    for package in packages:
        if not _PACKAGE_RE.fullmatch(package):
            raise ContractError("INVALID_ARGUMENT", "Unsafe package name for provisioning")
    name = f"rs9-prov-{uuid.uuid4().hex[:12]}"
    script = PROVISION_COMMANDS[family].format(packages=" ".join(packages))
    if family == "pacman":
        script += " && pacman -Fy --noconfirm"
    if os.getuid() > 0:
        script += " && (getent passwd " + str(os.getuid()) + " || useradd -m -u " + str(os.getuid()) + " rs9builder)"
    prov_substage = f"{substage_prefix}provision" if substage_prefix else "provision"
    commit_substage = f"{substage_prefix}commit" if substage_prefix else "commit"
    try:
        try:
            run = _prep_step(host, recorder, prov_substage, ["docker", "run", "--name", name, "--platform", platform, base_ref, "sh", "-c", script])
        except NativePrerequisiteUnavailable:
            raise
        except ContractError as err:
            raise err.with_details(substage=prov_substage) from None
        if run.exit_code != 0:
            raise ContractError("PROVISION_FAILED", f"{family} provisioning failed with exit code {run.exit_code}",
                                details={"substage": prov_substage, "tool": family, "exit_code": run.exit_code,
                                         "stdout_sha256": run.stdout_sha256, "stderr_sha256": run.stderr_sha256})
        try:
            commit = _prep_step(host, recorder, commit_substage, ["docker", "commit", name, tag])
        except NativePrerequisiteUnavailable:
            raise
        except ContractError as err:
            raise err.with_details(substage=commit_substage, tool="docker") from None
        if commit.exit_code != 0:
            raise ContractError("PROVISION_FAILED", "Provisioned image commit failed",
                                details={"substage": commit_substage, "tool": "docker", "exit_code": commit.exit_code,
                                         "stdout_sha256": commit.stdout_sha256, "stderr_sha256": commit.stderr_sha256})
    except BaseException as exc:
        cleanup = _cleanup_step(host, recorder, ["docker", "rm", "-f", name])
        if isinstance(exc, NativePrerequisiteUnavailable):
            raise
        if isinstance(exc, ContractError):
            raise exc.with_details(cleanup=cleanup) from None
        raise
    else:
        cleanup = _cleanup_step(host, recorder, ["docker", "rm", "-f", name])
        if cleanup != "complete":
            raise ContractError("CONTAINER_CLEANUP", "Preparation container cleanup failed",
                                details={"stage":"container-preparation", "substage":"cleanup", "cleanup":cleanup})
    return tag


class ClientContainer:
    """A fresh, network-disconnected, long-lived container driven through ``docker exec``."""

    def __init__(self, host: CommandRunner, image: str, platform: str, mounts: Sequence[tuple[str, str, bool]], family: str) -> None:
        self.host, self.image, self.platform, self.family = host, image, platform, family
        self.mounts = list(mounts)
        self.name = f"rs9-client-{uuid.uuid4().hex[:12]}"
        self.last_diagnostics: dict[str, Any] = {}

    def __enter__(self) -> ClientContainer:
        command = ["docker", "run", "-d", "--name", self.name, "--platform", self.platform, "--network", "none"]
        for source, target, writable in self.mounts:
            command += ["-v", f"{source}:{target}" + ("" if writable else ":ro")]
        started = self.host.run([*command, self.image, "sleep", "infinity"])
        if started.exit_code != 0:
            raise ContractError("CLIENT_START_FAILED", "Disconnected client container did not start")
        return self

    def __exit__(self, *exc: Any) -> None:
        try:
            self.host.run(["docker", "rm", "-f", self.name])
        except ContractError:
            pass

    def exec(self, argv: Sequence[str], *, user: str | None = None) -> CommandReceipt:
        command = ["docker", "exec"]
        if user:
            command += ["--user", user]
        return self.host.run([*command, self.name, *argv])

    @property
    def unprivileged_prefix(self) -> list[str]:
        return ["docker", "exec", "-i", "--user", CLIENT_USER, "-e", "HOME=/tmp", self.name]

    def inventory(self, stage: str | None = None) -> dict[str, str]:
        self.last_diagnostics = {}
        res = run_and_parse(
            self,
            exclusion=lambda path: inventory_excluded(self.family, path),
            with_modes=True,
            stage=stage,
            family=self.family,
            return_diagnostics=True,
        )
        if isinstance(res, tuple):
            self.last_diagnostics = res[1] or {}
            return res[0]
        return res


def _printf_file(path: str, lines: Sequence[str]) -> list[str]:
    for line in lines:
        if "'" in line or "\n" in line:
            raise ContractError("INVALID_METADATA", "Unsafe client configuration line")
    quoted = " ".join(f"'{line}'" for line in lines)
    return ["sh", "-c", f"printf '%s\\n' {quoted} > {path}"]


def apt_spec(apt_dir: Path, keyring: Path, arch: str, *, public_fingerprint=None) -> dict[str, Any]:
    line = apt_source_line(f"file:{SERVER_ROOT}/apt", CLIENT_KEYRING_PATH, arch=arch).strip()
    opts = ["-o", f"Dir::Etc::sourcelist={APT_LIST}", "-o", "Dir::Etc::sourceparts=-",
            "-o", "APT::Get::AllowUnauthenticated=false", "-o", "Acquire::AllowInsecureRepositories=false",
            "-o", "Acquire::Languages=none"]
    return {
        "family": "apt", "public_fingerprint": public_fingerprint,
        "expected_key_sha256": digest(keyring.read_bytes()) if keyring.is_file() else None,
        "mounts": [(str(apt_dir), f"{SERVER_ROOT}/apt", False), (str(keyring), CLIENT_KEYRING_PATH, False)],
        "configure": [_printf_file(APT_LIST, [line])],
        "refresh": ["apt-get", *opts, "update"],
        "install": lambda pkg: ["apt-get", *opts, "install", "-y", "--no-install-recommends", pkg],
        "remove": lambda pkg: ["apt-get", *opts, "purge", "-y", pkg],
        "query": lambda pkg: ["dpkg-query", "-W", "-f=${Version} ${Architecture}\\n", pkg],
    }


def dnf_spec(rpm_dir: Path, keys_dir: Path, arch: str) -> dict[str, Any]:
    if arch not in {"x86_64", "aarch64"}:
        raise ContractError("INVALID_ARCHITECTURE", "Fedora client architecture must be x86_64 or aarch64")
    repo = [
        f"[{DNF_REPO_ID}]", "name=RS9 Fedora 43 NONPRODUCTION candidate",
        f"baseurl=file://{SERVER_ROOT}/rpm/fedora/43/{arch}", "enabled=1",
        "gpgcheck=1", "repo_gpgcheck=1", f"gpgkey=file://{SERVER_ROOT}/keys/rs9-candidate-fixture-NONPRODUCTION.asc",
    ]
    only = ["--disablerepo=*", f"--enablerepo={DNF_REPO_ID}"]
    return {
        "family": "dnf",
        "mounts": [(str(rpm_dir), f"{SERVER_ROOT}/rpm", False), (str(keys_dir), f"{SERVER_ROOT}/keys", False)],
        "configure": [_printf_file(DNF_REPO_FILE, repo)],
        "refresh": ["dnf", "-y", *only, "makecache"],
        "install": lambda pkg: ["dnf", "-y", *only, "install", pkg],
        "remove": lambda pkg: ["dnf", "-y", "--setopt=clean_requirements_on_remove=False", "remove", pkg],
        "query": lambda pkg: ["rpm", "-q", "--qf", "%{VERSION}-%{RELEASE} %{ARCH}\\n", pkg],
    }


def pacman_spec(pacman_dir: Path, keys_dir: Path, fingerprint: str) -> dict[str, Any]:
    if not _FINGERPRINT_RE.fullmatch(fingerprint):
        raise ContractError("INVALID_ARGUMENT", "Signing fixture fingerprint required for pacman trust")
    conf = ["[options]", "Architecture = x86_64", "SigLevel = Required DatabaseRequired", "[rs9]",
            f"Server = file://{SERVER_ROOT}/pacman/$arch"]
    base = ["pacman", "--config", PACMAN_CONF]
    return {
        "family": "pacman",
        "mounts": [(str(pacman_dir), f"{SERVER_ROOT}/pacman", False), (str(keys_dir), f"{SERVER_ROOT}/keys", False)],
        "configure": [
            _printf_file(PACMAN_CONF, conf),
            ["pacman-key", "--init"],
            ["pacman-key", "--add", f"{SERVER_ROOT}/keys/rs9-candidate-fixture-NONPRODUCTION.asc"],
            ["pacman-key", "--lsign-key", fingerprint],
        ],
        "refresh": [*base, "-Sy", "--noconfirm"],
        "install": lambda pkg: [*base, "-S", "--noconfirm", "--needed", f"rs9/{pkg}"],
        "remove": lambda pkg: [*base, "-R", "--noconfirm", pkg],
        "query": lambda pkg: ["pacman", "-Q", pkg],
    }


def _family_error(err: Exception) -> str:
    if isinstance(err, NativePrerequisiteUnavailable):
        return "tool-unavailable:" + ",".join(err.missing_tools)
    return err.code if isinstance(err, ContractError) else type(err).__name__


def _cleanup_installed_client(client, spec, product, label, before, family):
    """Cleanup errors never overwrite the primary probe/smoke failure."""
    rows, evidence = [], {}
    try:
        removed=client.exec(spec["remove"](product))
        gone=client.exec(spec["query"](product))
        ok=removed.exit_code==0 and gone.exit_code!=0
        rows.append(_gate(label+".uninstall", *_pair(ok)))
        evidence["uninstall"]={"exit_code":removed.exit_code,"query_exit_code":gone.exit_code,
                              "stdout_sha256":removed.stdout_sha256,"stderr_sha256":removed.stderr_sha256}
    except (ContractError,NativePrerequisiteUnavailable,OSError) as error:
        rows.append(_gate(label+".uninstall","fail",_family_error(error)))
    try:
        after=client.inventory("post-remove")
        comparison=compare_inventories(before,after)
        diag=getattr(client,"last_diagnostics",{})
        evidence["inventory_stats"]={"post-remove":diag}
        evidence["inventory_clean"]=comparison["clean"]
        extra={}
        if not comparison["clean"]:
            extra={"leftover":inventory_samples(comparison["added"][:20]+comparison["modified"][:20]),
                   "counts":{k:len(comparison[k]) for k in ("added","removed","modified")},
                   "family":family,"stage":"post-remove","safe_cause":"unclean-inventory",
                   "counters":diag.get("counters",{})}
            evidence.update(extra)
        evidence["removed"]=inventory_samples(comparison["removed"][:20])
        rows.append(_gate(label+".inventory",*_pair(comparison["clean"]),**extra))
    except (ContractError,NativePrerequisiteUnavailable,OSError) as error:
        rows.append(_gate(label+".inventory","fail",_family_error(error)))
        evidence["inventory_clean"]=False
        evidence.update(error=_family_error(error), safe_cause=_family_error(error), counters=getattr(client,"last_diagnostics",{}).get("counters",{}))
        rows.append(_gate(label+".client","fail",_family_error(error),family=family,stage="post-remove",safe_cause=_family_error(error),counters=evidence["counters"]))
    status=_fold(rows)
    evidence["cleanup"]={"status":status,"uninstall_status":rows[0]["status"],"inventory_status":rows[1]["status"]}
    rows.append(_gate(label+".cleanup",status))
    return rows,evidence


def client_cycle(
    host: RecordingRunner,
    spec: Mapping[str, Any],
    *,
    image: str,
    platform: str,
    products: Sequence[str],
    repository: Path,
    prefix: str,
    smoke: Mapping[str, Any] | None = None,
    system: str | None = None,
    burst_record: Mapping[str, Any] | None = None,
    burst_scratch: Path | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Fresh container per product: configure, inventory, install, probe, remove, inventory."""
    gates: list[dict[str, Any]] = []
    evidence: dict[str, Any] = {}
    family = spec["family"]
    setup_sha256 = trust_identity(spec)
    for product in products:
        label = f"{prefix}.{product}"
        mark = host.mark()
        rows: list[dict[str, Any]] = []
        product_evidence: dict[str, Any] = {}
        current_stage = "start"
        client = None
        installed_ok = False
        container_smoke = None
        try:
            mounts = list(spec["mounts"])
            if burst_record is not None or (product == NATIVE_PRODUCT and smoke):
                mounts.append((str(repository / "src"), "/rs9-source", False))
            if product == "theme-forge-stellar-burst" and burst_scratch is not None:
                burst_scratch.mkdir(parents=True, exist_ok=True)
                burst_scratch.chmod(0o755)
                mounts.append((str(burst_scratch), str(burst_scratch), True))
            if product == NATIVE_PRODUCT and smoke:
                from rs9.hosted_container_smoke import prepare_container_smoke
                container_smoke = prepare_container_smoke(smoke, system, family)
                mounts.extend(container_smoke["mounts"])
            with ClientContainer(host, image, platform, mounts, family) as client_ctx:
                client = client_ctx
                if container_smoke:
                    from rs9.hosted_container_smoke import configure_container_output
                    configure_container_output(client, user=CLIENT_USER)
                current_stage = "configure"
                cfg_receipts = []
                for command in spec["configure"]:
                    cfg_rcpt = client.exec(command)
                    cfg_receipts.append(cfg_rcpt)
                    if cfg_rcpt.exit_code != 0:
                        diag = record_command_diagnostics(
                            stage="configure", family=family, product=product, arch=platform.split("/")[-1],
                            receipt=cfg_rcpt, repo_identity=setup_sha256,
                            public_fingerprint=spec.get("public_fingerprint"),
                        )
                        product_evidence["command_diagnostics"] = diag
                        raise ContractError("CLIENT_CONFIGURE_FAILED", "Client repository trust setup failed",
                                            details={"stage": "configure", "family": family, "exit_code": cfg_rcpt.exit_code,
                                                     "stdout_sha256": cfg_rcpt.stdout_sha256, "stderr_sha256": cfg_rcpt.stderr_sha256})
                current_stage = "network-denial"
                negative = client.exec(["python3","-c",
                    "import socket;s=socket.socket();s.settimeout(2);assert s.connect_ex(('1.1.1.1',443))!=0"], user=CLIENT_USER)
                if negative.exit_code:
                    raise ContractError("NETWORK_DENIAL", "Disconnected client still has runtime egress")
                rows.append(_gate(f"{label}.network-denial", "pass"))
                current_stage = "pre-install"
                before = client.inventory("pre-install")
                product_evidence["inventory_stats"] = {"pre-install": getattr(client, "last_diagnostics", {})}
                if family == "apt":
                    probe = probe_guest_trust(
                        client,
                        keyring_path=CLIENT_KEYRING_PATH,
                        repo_root=f"{SERVER_ROOT}/apt",
                        arch="arm64" if platform=="linux/arm64" else "amd64",
                        expected_key_sha256=spec.get("expected_key_sha256"),
                        public_fingerprint=spec.get("public_fingerprint"),
                    )
                    product_evidence["guest_trust_probe"] = probe
                    from rs9.apt_diagnostics import apt_readability
                    readability = apt_readability(probe, executed=host.real_since(mark),
                        repo_root=f"{SERVER_ROOT}/apt", keyring_path=CLIENT_KEYRING_PATH,
                        arch="arm64" if platform=="linux/arm64" else "amd64")
                    product_evidence["apt_readability"] = readability
                    if isinstance(probe, dict):
                        probe["apt_readability"] = readability
                current_stage = "refresh"
                refresh_rcpt = client.exec(spec["refresh"])
                product_evidence["refresh"] = record_command_diagnostics(
                    stage="refresh", family=family, product=product, arch=platform.split("/")[-1],
                    receipt=refresh_rcpt, repo_identity=setup_sha256,
                    public_fingerprint=spec.get("public_fingerprint"),
                    verification={"untampered_refresh": "pass" if refresh_rcpt.exit_code==0 else "fail"})
                if refresh_rcpt.exit_code != 0:
                    if family == "apt":
                        try:
                            debug = client.exec([*spec["refresh"][:-1], "-o", "Debug::Acquire::gpgv=true", spec["refresh"][-1]])
                            product_evidence["refresh_debug"] = record_command_diagnostics(
                                stage="diagnostic-refresh",family=family,product=product,arch=platform.split("/")[-1],receipt=debug,
                                repo_identity=setup_sha256,public_fingerprint=spec.get("public_fingerprint"))
                        except (ContractError, OSError) as debug_error:
                            product_evidence["refresh_debug"] = {
                                "stage": "diagnostic-refresh", "status": "unavailable",
                                "safe_cause": _family_error(debug_error),
                            }
                    diag = record_command_diagnostics(
                        stage="refresh", family=family, product=product, arch=platform.split("/")[-1],
                        receipt=refresh_rcpt, repo_identity=setup_sha256,
                        public_fingerprint=spec.get("public_fingerprint"),
                    )
                    product_evidence["command_diagnostics"] = diag
                    raise ContractError("CLIENT_REFRESH_FAILED", "Repository metadata refresh failed",
                                        details={"stage": "refresh", "family": family, "exit_code": refresh_rcpt.exit_code,
                                                 "stdout_sha256": refresh_rcpt.stdout_sha256, "stderr_sha256": refresh_rcpt.stderr_sha256})
                try:
                    current_stage = "install"
                    installed = client.exec(spec["install"](product))
                    installed_ok = installed.exit_code == 0
                    present = client.exec(spec["query"](product))
                    rows.append(_gate(f"{label}.install", *_pair(installed.exit_code == 0 and present.exit_code == 0)))
                    if installed.exit_code != 0 or present.exit_code != 0:
                        diag = record_command_diagnostics(
                            stage="install", family=family, product=product, arch=platform.split("/")[-1],
                            receipt=installed, repo_identity=setup_sha256,
                            public_fingerprint=spec.get("public_fingerprint"),
                        )
                        product_evidence["command_diagnostics"] = diag
                        raise ContractError("CLIENT_INSTALL_FAILED", "Candidate package did not install",
                                            details={"stage": "install", "family": family, "exit_code": installed.exit_code,
                                                     "stdout_sha256": installed.stdout_sha256, "stderr_sha256": installed.stderr_sha256})
                    repo_mount = spec["mounts"][0][0] if spec.get("mounts") else (str(repository) if repository else None)
                    key_mount = spec["mounts"][1][0] if spec.get("mounts") and len(spec["mounts"]) > 1 else (CLIENT_KEYRING_PATH if family == "apt" else None)
                    control = build_positive_control(
                        family=family,
                        image=image,
                        platform=platform,
                        product=product,
                        repository=repo_mount,
                        keyring=key_mount,
                        receipts={"configure": cfg_receipts, "refresh": refresh_rcpt, "install": installed, "query": present},
                        success=True, setup_sha256=setup_sha256,
                    )
                    product_evidence["positive_control"] = control
                    evidence.setdefault("positive_controls", {})[product] = control
                    current_stage = "probes"
                    for command in sorted(REQUIRED_COMMANDS.get(product, [])):
                        try:
                            probe_rows = execute_probes(
                                command, f"/usr/bin/{command}", repository=repository,
                                prefix=client.unprivileged_prefix, runner=host,
                            )
                        except Exception as err:  # probe execution is untrusted lane input
                            probe_rows = [{"name": f"probe.{command}", "status": "fail", "reason": _family_error(err)}]
                        for row in probe_rows:
                            rows.append(_gate(f"{label}.{row['name']}", row["status"], row.get("reason")))
                    if product == "theme-forge-stellar-burst":
                        current_stage = "burst"
                        if burst_record is None or burst_scratch is None or system is None:
                            raise ContractError("BURST_NATIVE_TARGET", "Authenticated installed Burst proof required")
                        from rs9.hosted_burst_clients import verify_client_burst
                        product_evidence["native_loader"] = verify_client_burst(
                            client, burst_record, system, burst_scratch / product, user=CLIENT_USER)
                        rows.append(_gate(f"{label}.burst-native-addon-target", "pass"))
                        rows.append(_gate(f"{label}.burst-native-addon-load", "pass"))
                    if product == NATIVE_PRODUCT:
                        current_stage = "native-closure"
                        closure = client.exec(["python3","-c",
                            "from pathlib import Path;import subprocess;root=Path('/usr/lib/theme-forge-nebular-fusion');"
                            "files=[p for p in root.rglob('*') if p.is_file() and not p.is_symlink() and p.read_bytes()[:4]==bytes([127])+b'ELF'];"
                            "assert files;"
                            "results=[subprocess.run(['ldd',str(p)],capture_output=True) for p in files];"
                            "assert all(b'not found' not in r.stdout+r.stderr and (r.returncode==0 or b'not a dynamic' in r.stdout+r.stderr or b'statically linked' in r.stdout+r.stderr) for r in results)"], user=CLIENT_USER)
                        rows.append(_gate(f"{label}.native-closure", *_pair(closure.exit_code == 0)))
                        if smoke:
                            current_stage = "smoke"
                            from rs9.hosted_container_smoke import verify_container_nebular
                            product_evidence["application_smoke"] = verify_container_nebular(
                                client, container_smoke, user=CLIENT_USER)
                            rows.append(_gate(f"{label}.application-smoke","pass"))
                finally:
                    if installed_ok:
                        cleanup_rows, cleanup_evidence = _cleanup_installed_client(client, spec, product, label, before, family)
                        rows.extend(cleanup_rows)
                        stats={**product_evidence.get("inventory_stats",{}),**cleanup_evidence.get("inventory_stats",{})}
                        product_evidence.update(cleanup_evidence)
                        product_evidence["inventory_stats"]=stats
                evidence[product] = {**product_evidence, "family": family, "stage": "post-remove"}
        except (ContractError, NativePrerequisiteUnavailable, OSError) as err:
            err_family = (err.details.get("family") if isinstance(err, ContractError) and err.details else None) or family
            err_stage = (err.details.get("stage") if isinstance(err, ContractError) and err.details else None) or current_stage
            safe_cause = _family_error(err)
            diag = getattr(client, "last_diagnostics", {}) if client is not None else {}
            err_counters = (err.details.get("counters") if isinstance(err, ContractError) and err.details else None) or diag.get("counters", {})
            gate_extra = {
                "family": err_family,
                "stage": err_stage,
                "safe_cause": safe_cause,
            }
            gate_extra["counters"] = err_counters or {}
            gate_extra["max"] = (err.details or {}).get("max", {}) if isinstance(err, ContractError) else {}
            if isinstance(err, ContractError):
                failure = {k: err.details[k] for k in ("cause", "limit", "observed", "maximum") if k in err.details}
                if failure:
                    gate_extra["inventory_failure"] = failure
            rows.append(_gate(f"{label}.client", "fail" if not isinstance(err, NativePrerequisiteUnavailable) else "not-run",
                              safe_cause, **gate_extra))
            repo_mount = spec["mounts"][0][0] if spec.get("mounts") else (str(repository) if repository else None)
            key_mount = spec["mounts"][1][0] if spec.get("mounts") and len(spec["mounts"]) > 1 else (CLIENT_KEYRING_PATH if family == "apt" else None)
            failed_control = product_evidence.get("positive_control") or build_positive_control(
                family=err_family, image=image, platform=platform, product=product,
                repository=repo_mount, keyring=key_mount,
                success=False, setup_sha256=setup_sha256,
            )
            evidence[product] = {
                **product_evidence,
                "error": safe_cause,
                "family": err_family,
                "stage": err_stage,
                "safe_cause": safe_cause,
                "positive_control": failed_control,
            }
            evidence.setdefault("positive_controls", {})[product] = failed_control
            evidence[product]["counters"] = err_counters or {}
            evidence[product]["max"] = gate_extra["max"]
            if "inventory_failure" in gate_extra:
                evidence[product]["inventory_failure"] = gate_extra["inventory_failure"]
            if product == "theme-forge-stellar-burst":
                for name in ("burst-native-addon-target", "burst-native-addon-load"):
                    if not any(row["name"].endswith("." + name) for row in rows):
                        rows.append(_gate(f"{label}.{name}", "fail", safe_cause))
        real = host.real_since(mark)
        for row in rows:
            if row["status"] == "pass" and not real:
                row["status"], row["reason"] = "not-run", "synthetic-command-seam"
        gates.extend(rows)
    return gates, evidence


def burst_client_gates(rows):
    """A required loader gate passes only through a real successful client row."""
    return [_gate(name, _fold([row for row in rows if row["name"].endswith("." + name)]),
                  None if any(row["name"].endswith("." + name) for row in rows) else "missing-native-loader-proof")
            for name in ("burst-native-addon-target", "burst-native-addon-load")]


def _burst_release_record(captures, system):
    from rs9.hosted_burst_clients import release_load_record
    matches = [c for c, i, _ in captures if i["project"]["id"] == "theme-forge-stellar-burst"]
    if len(matches) != 1:
        raise ContractError("BURST_NATIVE_TARGET", "One authenticated Burst capture required")
    return release_load_record(matches[0], system)


def _pair(ok: bool) -> tuple[str, str | None]:
    return ("pass", None) if ok else ("fail", None)


# --------------------------------------------------------------------------- tamper


def _flip_last_byte(path: Path) -> str:
    data = path.read_bytes()
    path.write_bytes(data[:-1] + bytes([data[-1] ^ 0x01]))
    return path.name


def _corrupt_signature(path: Path) -> None:
    data = bytearray(path.read_bytes())
    data[min(len(data) - 1, 12)] ^= 0x01
    path.write_bytes(bytes(data))


def _product_files(directory: Path, pattern: str, product: str) -> list[Path]:
    found = [path for path in sorted(directory.glob(pattern)) if path.name.startswith(product + "-")]
    if not found:
        raise ContractError("MISSING_PACKAGE", "No package of the tested product to tamper")
    return found


def tamper_family_copy(
    family: str, kind: str, dirs: Mapping[str, Path], dest: Path, *, arch: str, wrong_signer: Any, product: str
) -> dict[str, Path]:
    """Copy the family tree under ``dest`` and corrupt the copy; keys are never modified.

    ``package`` tampering always targets the product the client is about to install.
    """
    if kind not in TAMPER_KINDS_ALL:
        raise ContractError("INVALID_ARGUMENT", "Unsupported tamper kind")
    out = dict(dirs)
    if family == "apt":
        copy = dest / "apt"
        shutil.copytree(dirs["apt"], copy)
        tamper_apt_repository(copy, kind, arch=arch, wrong_signer=wrong_signer, package=product)
        modes_report = _verify_public_tree_modes(copy)
        if modes_report.get("status") != "pass":
            raise ContractError("MODE_MISMATCH", "APT tamper copy public tree mode verification failed",
                                details={"substage": "apt-tamper", "reason": "public-mode-mismatch"})
        out["apt"] = copy
    elif family == "dnf":
        copy = dest / "rpm"
        shutil.copytree(dirs["rpm"], copy)
        base = copy / "fedora/43" / arch
        if kind == "package":
            _flip_last_byte(_product_files(base / "Packages", "*.rpm", product)[0])
        elif kind == "index":
            with (base / "repodata/repomd.xml").open("ab") as stream:
                stream.write(b"<!-- tampered -->\n")
        elif kind == "signature":
            _corrupt_signature(base / "repodata/repomd.xml.asc")
        else:
            (base / "repodata/repomd.xml.asc").write_bytes(
                wrong_signer.detach_sign((base / "repodata/repomd.xml").read_bytes(), armor=True))
        out["rpm"] = copy
    elif family == "pacman":
        copy = dest / "pacman"
        shutil.copytree(dirs["pacman"], copy)
        base = copy / "x86_64"
        if kind == "package":
            _flip_last_byte(_product_files(base, "*.pkg.tar.zst", product)[0])
        elif kind == "index":
            for name in ("rs9.db.tar.gz", "rs9.db"):
                with (base / name).open("ab") as stream:
                    stream.write(b"\x00")
        elif kind == "signature":
            for name in ("rs9.db.tar.gz.sig", "rs9.db.sig"):
                _corrupt_signature(base / name)
        else:
            for sig in sorted(base.glob("*.sig")):
                target = base / sig.name[: -len(".sig")]
                sig.write_bytes(wrong_signer.detach_sign(target.read_bytes(), armor=False))
        out["pacman"] = copy
    else:
        raise ContractError("INVALID_ARGUMENT", "Unsupported client family")
    return out


def tamper_cycle(
    host: RecordingRunner,
    spec_for: Any,
    family: str,
    dirs: Mapping[str, Path],
    *,
    image: str,
    platform: str,
    product: str,
    work: Path,
    arch: str,
    wrong_signer: Any,
    kinds: Sequence[str],
    prefix: str,
    positive_control: Mapping[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Every tamper must stop installation; causal qualification requires explicit positive control."""
    gates = []
    control_ok, control_reason = validate_positive_control(
        positive_control,
        family=family,
        image=image,
        platform=platform,
        product=product,
        dirs=dirs, setup_sha256=trust_identity(spec_for(dirs)),
    )
    for kind in kinds:
        label = f"{prefix}.tamper.{kind}"
        mark = host.mark()
        raw_negative_receipts: list[dict[str, Any]] = []
        try:
            copy_root = work / f"tamper-{family}-{kind}"
            copy_root.mkdir()
            tampered = tamper_family_copy(family, kind, dirs, copy_root, arch=arch, wrong_signer=wrong_signer,
                                          product=product)
            spec = spec_for(tampered)
            with ClientContainer(host, image, platform, spec["mounts"], family) as client:
                for command in spec["configure"]:
                    cfg_rcpt = client.exec(command)
                    raw_negative_receipts.append({
                        "stage": "configure", "exit_code": cfg_rcpt.exit_code, "executed": cfg_rcpt.executed,
                        "stdout_sha256": cfg_rcpt.stdout_sha256, "stderr_sha256": cfg_rcpt.stderr_sha256,
                    })
                    if cfg_rcpt.exit_code != 0:
                        raise ContractError("CLIENT_CONFIGURE_FAILED", "Client repository trust setup failed")
                refresh_rcpt = client.exec(spec["refresh"])  # may fail first; installation must still never succeed
                raw_negative_receipts.append({
                    "stage": "refresh", "exit_code": refresh_rcpt.exit_code,
                    "stdout_sha256": refresh_rcpt.stdout_sha256, "stderr_sha256": refresh_rcpt.stderr_sha256,
                    "executed": refresh_rcpt.executed,
                })
                install = client.exec(spec["install"](product))
                raw_negative_receipts.append({
                    "stage": "install", "exit_code": install.exit_code,
                    "stdout_sha256": install.stdout_sha256, "stderr_sha256": install.stderr_sha256,
                    "executed": install.executed,
                })
                present = client.exec(spec["query"](product))
                raw_negative_receipts.append({
                    "stage": "query", "exit_code": present.exit_code,
                    "executed": present.executed,
                    "stdout_sha256": present.stdout_sha256, "stderr_sha256": present.stderr_sha256,
                })

            is_qualified, category, qual_reason, qual_diag = qualify_tamper_rejection(
                kind, refresh_rcpt, install, present, family=family
            )
            if qual_reason == "tampered-content-accepted":
                row = _gate(label, "fail", "tampered-content-accepted",
                            rejection_category=category,
                            negative_receipts=raw_negative_receipts)
            elif not control_ok:
                row = _gate(label, "not-run", "blocked-by:positive-control",
                            negative_receipts=raw_negative_receipts,
                            control_error=control_reason)
            else:
                if is_qualified:
                    control_real=all(r.get("executed") is True for stage in positive_control["stages"].values() for r in stage)
                    status, reason = _status(True, host.real_since(mark) and control_real)
                    row = _gate(label, status, reason,
                                rejection_category=category,
                                negative_receipts=raw_negative_receipts,
                                **qual_diag)
                else:
                    row = _gate(label, "fail", qual_reason or f"wrong-tamper-rejection-reason:{category}",
                                rejection_category=category,
                                negative_receipts=raw_negative_receipts,
                                **qual_diag)
        except (ContractError, NativePrerequisiteUnavailable, OSError) as err:
            if not control_ok:
                row = _gate(label, "not-run", "blocked-by:positive-control",
                            negative_receipts=raw_negative_receipts,
                            control_error=control_reason)
            else:
                row = _gate(label, "fail" if not isinstance(err, NativePrerequisiteUnavailable) else "not-run",
                            _family_error(err), negative_receipts=raw_negative_receipts)
        gates.append(row)
    return gates


# --------------------------------------------------------------------------- shared lane helpers


def _targets_maintainer(repository: Path) -> str | None:
    try:
        targets = json.loads((repository / "operators/live1/targets.json").read_bytes())
    except (OSError, ValueError):
        return None
    value = targets.get("maintainer")
    return value if isinstance(value, str) and value.strip() else None


def _open_signing_fixture(context: Mapping[str, Any]) -> tuple[Any, bool]:
    """Real GnuPG fixture (created here unless supplied); (None, False) when GnuPG is unavailable."""
    supplied = context.get("signing_fixture")
    if supplied is not None:
        return supplied, False
    from rs9.signing_fixture import SigningFixture, find_gpg_binary

    if find_gpg_binary() is None:
        return None, False
    try:
        return SigningFixture(), True
    except ContractError:
        return None, False


def _fixture_is_real(fixture: Any) -> bool:
    return isinstance(getattr(fixture, "gpg", None), str)


def _new_wrong_signer(context: Mapping[str, Any]) -> tuple[Any, bool]:
    supplied = context.get("wrong_signing_fixture")
    if supplied is not None:
        return supplied, False
    from rs9.signing_fixture import SigningFixture

    return SigningFixture(user_id="RS9 NON-PRODUCTION WRONG-KEY FIXTURE <nonproduction@invalid>"), True


def _tree_inventory(root: Path) -> dict[str, str]:
    inventory: dict[str, str] = {}
    for current, _, names in os.walk(str(root)):
        for name in names:
            path = Path(current) / name
            if path.is_symlink():
                raise ContractError("SYMLINK_REJECTED", "Symlink in retained tree")
            inventory[path.relative_to(root).as_posix()] = digest(path.read_bytes())
    return inventory


def _dependency_names(deb_bytes: bytes) -> list[str]:
    depends = parse_deb_control(deb_bytes).get("Depends", "")
    names: list[str] = []
    for group in depends.split(","):
        name = group.split("|")[0].strip().split(" ")[0]
        if name and name not in names:
            names.append(name)
    return names


def _offline_npm_archives(capture: Any, product: str, inputs: Path | None, client: Any, scratch: Path) -> dict[str, Path] | None:
    return resolve_offline_npm_archives(capture, product, scratch, inputs=inputs, client=client)


def _ensure_captures(context: dict[str, Any], repository: Path, scratch: Path) -> list[Any]:
    captures = context.setdefault("captures", [])
    if not captures and context.get("client") is not None:
        from rs9.candidate import capture_generation

        root = scratch / "capture"
        root.mkdir()
        binding = context.get("binding", {}) or {}
        captures.extend(capture_generation(repository, root, client=context["client"],
                                           checkout_binding=binding.get("checkout_binding", "hosted:unknown")))
    return captures


def _result(gates: list[dict[str, Any]], artifacts: list[Path], details: dict[str, Any]) -> dict[str, Any]:
    return {"gates": gates, "artifacts": artifacts, "details": details}


def _write_manifest(scratch: Path, name: str, manifest: dict[str, Any], artifacts: list[Path]) -> dict[str, Any]:
    data = canonical(manifest)
    path = scratch / name
    path.write_bytes(data)
    artifacts.append(path)
    return {"manifest_path": path.relative_to(scratch).as_posix(), "manifest_sha256": digest(data)}


# --------------------------------------------------------------------------- deb lane


def _build_products(
    captures: Sequence[Any], system: str, scratch: Path, builder: CommandRunner, maintainer: str,
    inputs: Path | None, client: Any, required: Sequence[str],
) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    products: dict[str, dict[str, Any]] = {}
    errors: dict[str, str] = {}
    for capture, intent, _profile in captures:
        product = intent["project"]["id"]
        if product not in required:
            continue
        build_dir = scratch / "build" / product
        build_dir.mkdir(parents=True)
        try:
            from rs9.product_classes import is_pure_js_cli, get_product_class
            target_arch = "all" if is_pure_js_cli(product) else system
            built = build_deb_candidate(
                capture, intent, target_arch, build_dir,
                maintainer=maintainer,
                offline_npm_archives=resolve_offline_npm_archives(capture, product, scratch, inputs=inputs, client=client),
                runner=builder,
            )
        except (ContractError, NativePrerequisiteUnavailable, OSError) as err:
            errors[product] = "PACKAGE_FILESYSTEM" if isinstance(err, OSError) else _family_error(err)
            continue
        manifest = built["manifest"]
        derivation = built["derivation_record"]
        products[product] = {
            "package_file": built["deb_path"].name,
            "path": built["deb_path"],
            "sha256": manifest["package_sha256"],
            "size": manifest["package_size"],
            "architecture": manifest["architecture"],
            "package_class": get_product_class(product),
            "dependencies": manifest["dependencies"],
            "dependency_classification": manifest["dependency_classification"],
            "elf_object_count": manifest["elf_object_count"],
            "derivation_source": derivation["derivation_source"],
            "shlibs_inventory": manifest["shlibs_inventory"],
        }
    for product in required:
        if product not in products and product not in errors:
            errors[product] = "capture-missing"
    return products, errors


def execute_deb(context: dict[str, Any]) -> dict[str, Any]:
    repository = physical_directory(context["repository"])
    scratch = validate_scratch_root(context["scratch"])
    system = context.get("system")
    if system not in DEB_PLATFORMS:
        raise ContractError("INVALID_ARCHITECTURE", f"Deb lane requires amd64 or arm64, received: {system}")
    pins = context.get("pins") or {}
    inputs = Path(context["inputs"]).resolve() if context.get("inputs") else None
    binding = context.get("binding") or {}
    required = tuple(context.get("required_products") or REQUIRED_PRODUCTS)
    host = RecordingRunner(context.get("runner") or SubprocessRunner())
    platform = DEB_PLATFORMS[system]
    gates: list[dict[str, Any]] = []
    artifacts: list[Path] = []
    details: dict[str, Any] = {"family": "deb", "system": system, "required_products": list(required),
                               "container_preparation": []}
    images: list[str] = []
    fixture: Any = None
    owns_fixture = wrong_owned = False
    wrong_signer: Any = None
    blocked: str | None = None

    def block(names: Sequence[str], reason: str) -> None:
        gates.extend(_gate(name, "not-run", reason) for name in names)

    try:
        # -- environment: pinned or run-resolved Ubuntu 26.04 container, builder image ----------
        mark = host.mark()
        env: dict[str, Any] | None = None
        builder: ContainerRunner | None = None
        try:
            env = prepare_environment(host, system, pins, recorder=details["container_preparation"])
            libs = tuple((pins.get("deb", {}) or {}).get("build_packages") or DEFAULT_NATIVE_LIBRARY_PACKAGES)
            builder_tag = f"rs9-deb-builder-{system}:{uuid.uuid4().hex[:8]}"
            images.append(builder_tag)
            provision_image(host, "apt", env["image_ref"], platform, builder_tag, [*BUILD_TOOL_PACKAGES, *libs], recorder=details["container_preparation"], substage_prefix="build-")
            builder = ContainerRunner(host, builder_tag, platform=platform,
                                      mounts=[(str(scratch), str(scratch), True)], user=_user())
            from rs9.hosted_native import container_tool_facts
            env["tools"] = container_tool_facts(_PreparationTools(builder, details["container_preparation"]), ["dpkg-deb", "dpkg-shlibdeps", "dpkg-query", "ldd"])
            status, reason = _status(True, host.real_since(mark))
            gates.append(_gate("deb-container-environment", status,
                               reason or ("run-resolved-digest" if env["unpinned"] else None)))
            details["container"] = env
        except (ContractError, NativePrerequisiteUnavailable) as err:
            blocked = "deb-container-environment"
            err_details = safe_details(err.details) if isinstance(err, ContractError) and err.details else {}
            gates.append(_gate(blocked, "not-run" if isinstance(err, NativePrerequisiteUnavailable) else "fail",
                               _family_error(err), details=err_details,
                               **{k:v for k,v in err_details.items() if k not in {"name","status","reason"}}))
            details["environment_failure"] = {"code":err.code, "details":err_details}

        maintainer = context.get("maintainer", _targets_maintainer(repository))
        if blocked is None and not maintainer:
            blocked = "maintainer-unassigned"
        if blocked is not None:
            block(["deb-package-build", "deb-shlibdeps-closure", "deb-apt-repository-indexing", "deb-client-qualification"],
                  blocked if blocked == "maintainer-unassigned" else f"blocked-by:{blocked}")

        products: dict[str, dict[str, Any]] = {}
        if blocked is None:
            # -- build all products; native dependencies only from dpkg-shlibdeps over every ELF --
            mark = host.mark()
            captures = _ensure_captures(context, repository, scratch)
            products, errors = _build_products(captures, system, scratch, builder, maintainer, inputs,
                                               context.get("client"), required)
            details["products"] = {k: {kk: vv for kk, vv in v.items() if kk != "path"} for k, v in products.items()}
            if errors:
                details["build_errors"] = errors
                diag_dir = scratch / "diagnostics"
                diag_dir.mkdir(exist_ok=True)
                diag_file = diag_dir / "build-errors.json"
                diag_file.write_bytes(canonical({"schema": "rs9.build-errors.v1alpha1", "family": "deb", "system": system, "errors": errors}))
                artifacts.append(diag_file)
            native_error = errors.get(NATIVE_PRODUCT, "")
            from rs9.product_classes import is_pure_js_cli
            native_prods = [k for k in required if not is_pure_js_cli(k)]
            shlibs_ok = (
                not errors
                and all(
                    products[k]["dependency_classification"] == "native-tool-derived"
                    and products[k]["elf_object_count"] >= 1
                    for k in native_prods if k in products
                )
                and all(
                    p["elf_object_count"] == 0
                    for k, p in products.items()
                    if is_pure_js_cli(k)
                )
            ) if native_prods else not errors
            native_real = all(
                p["derivation_source"] == "actual-native-tool-subprocess"
                for k, p in products.items() if not is_pure_js_cli(k)
            ) and host.real_since(mark)
            status, reason = _status(not errors, host.real_since(mark))
            gates.append(_gate("deb-package-build", status, reason or (
                None if not errors else ",".join(f"{k}:{v}" for k, v in sorted(errors.items())))))
            status, reason = _status(shlibs_ok, native_real)
            gates.append(_gate("deb-shlibdeps-closure", status, reason or (
                None if shlibs_ok else (native_error or "native-or-cli-elf-closure-unproven"))))
            if errors:
                blocked = "deb-package-build"
                block(["deb-apt-repository-indexing", "deb-client-qualification"], f"blocked-by:{blocked}")

        if blocked is None:
            # -- one assembled repository, real GnuPG fixture signatures ---------------------------
            mark = host.mark()
            fixture, owns_fixture = _open_signing_fixture(context)
            if fixture is None:
                blocked = "gpg-unavailable"
                block(["deb-apt-repository-indexing", "deb-client-qualification"], "gpg-unavailable")
            else:
                (scratch / "fixture-identity.json").write_bytes(canonical({"used": True, "production": False,
                    "purpose": "NON-PRODUCTION CANDIDATE TEST ONLY", "fingerprint": fixture.primary_fingerprint}))
                apt_root = scratch / "apt"
                apt_root.mkdir()
                try:
                    repo = AptRepositoryCandidate(apt_root, distribution="resolute")
                    for product in required:
                        repo.add_package(deb_bytes=products[product]["path"].read_bytes())
                    repo.build_indices()
                    signed = repo.sign_with_fixture(fixture)
                    verified = verify_apt_signatures(apt_root, fixture)
                    modes_report = _verify_public_tree_modes(apt_root)
                    details["apt_public_modes"] = modes_report
                    if modes_report.get("status") != "pass":
                        raise ContractError("MODE_MISMATCH", "APT repository public tree mode verification failed",
                                            details={"substage": "apt-repository", "reason": "public-mode-mismatch"})
                    tree = _tree_inventory(apt_root)
                    merkle = merkle_inventory(tree)
                    details["apt_repository"] = {
                        "release_sha256": verified["release_sha256"],
                        "inrelease_sha256": signed["inrelease_sha256"],
                        "release_gpg_sha256": signed["release_gpg_sha256"],
                        "verified_indices": verified["verified_indices"],
                        "verified_packages": verified["verified_packages"],
                        "verified_issuer": verified["verified_issuer"],
                        "merkle_root": merkle["root"],
                        "file_count": merkle["leaf_count"],
                    }
                    real = _fixture_is_real(fixture)
                    status, reason = _status(True, real)
                    gates.append(_gate("deb-apt-repository-indexing", status, reason))
                    for name in ("InRelease", "Release.gpg", "Release"):
                        artifacts.append(apt_root / f"dists/resolute/{name}")
                except ContractError as err:
                    blocked = "deb-apt-repository-indexing"
                    gates.append(_gate(blocked, "fail", err.code))
                    block(["deb-client-qualification"], f"blocked-by:{blocked}")

        if blocked is None:
            # -- fresh provisioned disconnected clients; tamper rejection --------------------------
            mark = host.mark()
            rows: list[dict[str, Any]] = []
            try:
                names: list[str] = []
                for product in required:
                    for name in _dependency_names(products[product]["path"].read_bytes()):
                        if name not in names:
                            names.append(name)
                client_tag = f"rs9-deb-client-{system}:{uuid.uuid4().hex[:8]}"
                images.append(client_tag)
                provision_image(host, "apt", env["image_ref"], platform, client_tag, [*names, "python3", "xvfb", "dbus-x11"], recorder=details["container_preparation"], substage_prefix="client-")
                keyring = scratch / "client-keyring" / "rs9-nonproduction.gpg"
                keyring.parent.mkdir()
                _write_public_keyring(keyring, fixture.public_key_binary)
                apt_dir = scratch / "apt"
                from rs9.hosted_smoke import prepare_smoke
                neb = next((c for c,i,_ in context["captures"] if i["project"]["id"] == NATIVE_PRODUCT),None)
                prepared = prepare_smoke(neb, context["captures"], context["client"], scratch / "application-smoke") if neb else None
                spec = apt_spec(apt_dir, keyring, system, public_fingerprint=fixture.primary_fingerprint)
                cycle_rows, evidence = client_cycle(
                    host, spec, image=client_tag, platform=platform,
                    products=required, repository=repository, prefix="deb-client", smoke=prepared,
                    system="aarch64-linux" if system=="arm64" else "x86_64-linux",
                    burst_record=(_burst_release_record(context["captures"], "aarch64-linux" if system=="arm64" else "x86_64-linux")
                                  if "theme-forge-stellar-burst" in required else None),
                    burst_scratch=scratch / "burst-native-probe")
                rows.extend(cycle_rows)
                details["client"] = evidence
                wrong_signer, wrong_owned = _new_wrong_signer(context)
                rows.extend(tamper_cycle(
                    host, lambda dirs: apt_spec(dirs["apt"], keyring, system, public_fingerprint=fixture.primary_fingerprint), "apt", {"apt": apt_dir},
                    image=client_tag, platform=platform, product=required[0], work=scratch, arch=system,
                    wrong_signer=wrong_signer, kinds=TAMPER_KINDS_ALL, prefix="deb-client",
                    positive_control=evidence.get(required[0], {}).get("positive_control")))
            except (ContractError, NativePrerequisiteUnavailable) as err:
                err_details = safe_details(err.details) if isinstance(err, ContractError) and err.details else {}
                rows.append(_gate("deb-client.setup", "not-run" if isinstance(err, NativePrerequisiteUnavailable) else "fail",
                                  _family_error(err), details=err_details,
                                  **{k:v for k,v in err_details.items() if k not in {"name","status","reason"}}))
                details["client_setup_failure"] = {"code":err.code, "details":err_details}
            gates.extend(rows)
            gates.extend(burst_client_gates(rows))
            aggregate = _fold(rows)
            gates.append(_gate("deb-client-qualification", aggregate,
                               None if aggregate == "pass" else "see-client-gates"))

        # -- custody: exact unsigned debs for the Pages lane --------------------------------------
        if products and len(products) == len(required):
            custody_dir = scratch / "custody-deb"
            custody_dir.mkdir()
            custody = write_custody_bundle(
                custody_dir, family="deb", system=system,
                packages={p["package_file"]: p["path"].read_bytes() for p in products.values()},
                authentication_sha256=context.get("authentication_sha256"),
                source_commit=binding.get("source_commit"))
            artifacts.extend(p for p in custody_dir.rglob("*") if p.is_file())
            details["custody"] = {"merkle_root": custody["merkle"]["root"], "directory": custody_dir.relative_to(scratch).as_posix()}
    finally:
        for tag in images:
            _cleanup_step(host, details["container_preparation"], ["docker", "rmi", "-f", tag], "image-cleanup")
        for owned, closer in ((owns_fixture, fixture), (wrong_owned, wrong_signer)):
            if owned and closer is not None:
                closer.close()

    manifest = {
        "schema": SCHEMA_DEB, "family": "deb", "system": system, "nonproduction": True,
        "status": "pass" if gates and all(g["status"] == "pass" for g in gates) else "incomplete",
        "authentication_sha256": context.get("authentication_sha256"),
        "gates": gates, "details": details, "receipts": host.records_since(0),
    }
    details.update(_write_manifest(scratch, "hosted-deb-manifest.json", manifest, artifacts))
    details["status"] = manifest["status"]
    return _result(gates, artifacts, details)


# --------------------------------------------------------------------------- pages lane


def _validate_bundle_architectures(bundle):
    from rs9.hosted_summary import validate_product_architectures
    manifest = bundle["manifest"]
    validate_product_architectures({"lane": manifest["family"], "system": manifest["system"],
                                   "required_products": list(REQUIRED_PRODUCTS)},
                                  [{"path": name, "kind": "custody"} for name in bundle["packages"]])


def _gather_custody(inputs: Path | None, authentication_sha256: str | None, source_commit: str | None = None) -> dict[tuple[str, str], dict[str, Any]]:
    bundles: dict[tuple[str, str], dict[str, Any]] = {}
    if inputs is None:
        return bundles
    for manifest in sorted(inputs.rglob(CUSTODY_MANIFEST)):
        bundle = load_custody_bundle(manifest.parent, expected_authentication_sha256=authentication_sha256)
        _validate_bundle_architectures(bundle)
        if source_commit is not None and bundle["manifest"].get("source_commit") != source_commit:
            raise ContractError("CUSTODY_SOURCE", "Unsigned bundle source differs from the candidate source")
        key = (bundle["manifest"]["family"], bundle["manifest"]["system"])
        if key in bundles:
            raise ContractError("CUSTODY_CONFLICT", "Duplicate custody bundle for one family and system")
        bundles[key] = bundle
    return bundles


def _custody_unique(bundles: Sequence[dict[str, Any]]) -> dict[str, Path]:
    """Same package name from several lanes (architecture all) must be byte-identical."""
    unique: dict[str, Path] = {}
    for bundle in bundles:
        _validate_bundle_architectures(bundle)
        for name, path in bundle["packages"].items():
            if name in unique and digest(unique[name].read_bytes()) != digest(path.read_bytes()):
                raise ContractError("CUSTODY_CONFLICT", "Architecture-all package bytes differ between lanes")
            unique.setdefault(name, path)
    return unique


def _rpm_custody_unique(bundles: Sequence[dict[str, Any]]) -> dict[str, Path]:
    """Same noarch package filename or product across RPM lanes must be byte-identical."""
    unique: dict[str, Path] = {}
    products: dict[str, tuple[str, Path]] = {}
    for bundle in bundles:
        _validate_bundle_architectures(bundle)
        for name, path in bundle["packages"].items():
            path_bytes = path.read_bytes()
            path_sha = digest(path_bytes)
            if name in unique and digest(unique[name].read_bytes()) != path_sha:
                raise ContractError("CUSTODY_CONFLICT", "RPM package bytes differ between lanes")
            if name.endswith(".noarch.rpm"):
                product = next((p for p in REQUIRED_PRODUCTS if name.startswith(p + "-")), None)
                if product is None:
                    raise ContractError("CUSTODY_CONFLICT", "Unknown noarch RPM product")
                if product in products:
                    prior_name, prior_path = products[product]
                    if prior_name != name or digest(prior_path.read_bytes()) != path_sha:
                        raise ContractError("CUSTODY_CONFLICT", "Noarch RPM package bytes differ between lanes")
                products.setdefault(product, (name, path))
            unique.setdefault(name, path)
    return unique


def _run_tool_container(host: RecordingRunner, image: str, platform: str, work: Path, argv: list[str], *, network: bool = False) -> None:
    runner = ContainerRunner(host, image, platform=platform, mounts=[(str(work), str(work), True)],
                             user=_user(), network=network)
    receipt = runner.run(argv, cwd=work)
    if receipt.exit_code != 0:
        tool = Path(argv[0]).name if argv else "tool"
        raise ContractError("METADATA_BUILD_FAILED", f"{argv[0]} failed with exit code {receipt.exit_code}",
                            details={"substage": "metadata", "tool": tool, "exit_code": receipt.exit_code,
                                     "stdout_sha256": receipt.stdout_sha256, "stderr_sha256": receipt.stderr_sha256})


PAGES_GATES = ("pages-repository-objects", "pages-inventory-integrity", "pages-privacy-scan", "pages-client.apt", "pages-client.dnf", "pages-client.pacman")


def execute_pages(context: dict[str, Any]) -> dict[str, Any]:
    repository = physical_directory(context["repository"])
    scratch = validate_scratch_root(context["scratch"])
    pins = context.get("pins") or {}
    inputs = Path(context["inputs"]).resolve() if context.get("inputs") else None
    auth = context.get("authentication_sha256")
    host = RecordingRunner(context.get("runner") or SubprocessRunner())
    gates: list[dict[str, Any]] = []
    artifacts: list[Path] = []
    details: dict[str, Any] = {"family": "pages", "system": context.get("system", "generation"), "host": PAGES_HOST}
    images: list[str] = []
    closers: list[Any] = []  # fixtures created here (never caller-supplied ones)

    def block(names: Sequence[str], reason: str) -> None:
        gates.extend(_gate(name, "not-run", reason) for name in names)

    try:
        needed = [("deb", "amd64"), ("deb", "arm64"), ("rpm", "x86_64-linux"), ("rpm", "aarch64-linux"), ("pacman", "x86_64-linux")]
        try:
            bundles = _gather_custody(inputs, auth, (context.get("binding") or {}).get("source_commit"))
        except ContractError as err:
            if err.code == "CUSTODY_ARCHITECTURE":
                gates.extend(_gate(name, "fail", err.code) for name in PAGES_GATES)
            else:
                block(PAGES_GATES, f"custody-invalid:{err.code}")
            bundles, needed = {}, []
            details["custody_error"] = err.code
        missing = [f"{family}-{system}" for family, system in needed if (family, system) not in bundles]
        if needed and missing:
            block(PAGES_GATES, "custody-missing:" + ",".join(missing))
        elif needed:
            fixture, owns_fixture = _open_signing_fixture(context)
            if owns_fixture:
                closers.append(fixture)
            if fixture is None:
                block(PAGES_GATES, "gpg-unavailable")
            else:
                _assemble_and_test_pages(
                    context, host, repository, scratch, pins, bundles, fixture, gates, artifacts, details, images,
                    closers)
    finally:
        for tag in images:
            try:
                host.run(["docker", "rmi", "-f", tag])
            except (ContractError, NativePrerequisiteUnavailable):
                pass
        for closer in closers:
            closer.close()

    manifest = {
        "schema": SCHEMA_PAGES, "family": "pages", "nonproduction": True,
        "status": "pass" if gates and all(g["status"] == "pass" for g in gates) else "incomplete",
        "authentication_sha256": auth, "gates": gates, "details": details, "receipts": host.records_since(0),
    }
    details.update(_write_manifest(scratch, "hosted-pages-manifest.json", manifest, artifacts))
    details["status"] = manifest["status"]
    return _result(gates, artifacts, details)


def _assemble_and_test_pages(
    context: dict[str, Any], host: RecordingRunner, repository: Path, scratch: Path, pins: Mapping[str, Any],
    bundles: Mapping[tuple[str, str], dict[str, Any]], fixture: Any, gates: list[dict[str, Any]],
    artifacts: list[Path], details: dict[str, Any], images: list[str], closers: list[Any],
) -> None:
    stage = scratch / "stage"
    stage.mkdir()
    (scratch / "fixture-identity.json").write_bytes(canonical({"used": True, "production": False,
        "purpose": "NON-PRODUCTION CANDIDATE TEST ONLY", "fingerprint": fixture.primary_fingerprint}))
    mark = host.mark()
    real = _fixture_is_real(fixture)
    rpm_tag = ""
    try:
        # APT: rebuilt from custody debs; signed by this lane's fixture only.
        debs = _custody_unique([bundles[("deb", "amd64")], bundles[("deb", "arm64")]])
        _rpm_custody_unique([bundles[("rpm", "x86_64-linux")], bundles[("rpm", "aarch64-linux")]])
        apt_root = stage / "apt-repo"
        apt_root.mkdir()
        repo = AptRepositoryCandidate(apt_root, distribution="resolute")
        for name in sorted(debs):
            repo.add_package(deb_bytes=debs[name].read_bytes())
        repo.build_indices()
        repo.sign_with_fixture(fixture)
        verify_apt_signatures(apt_root, fixture)
        modes_report = _verify_public_tree_modes(apt_root)
        details["apt_staging_public_modes"] = modes_report
        if modes_report.get("status") != "pass":
            raise ContractError("MODE_MISMATCH", "Pages APT repository public tree mode verification failed",
                                details={"substage": "pages-apt-staging", "reason": "public-mode-mismatch"})

        files: dict[str, bytes | str] = dict(render_install_docs())
        # RPM and pacman metadata is rebuilt by the family tools in their own containers.
        rpm_image = provision_native("rpm", "x86_64-linux", pins, runner=host)
        pacman_image = provision_native("pacman", "x86_64-linux", pins, runner=host)
        rpm_tag = f"rs9-pages-fedora:{uuid.uuid4().hex[:8]}"
        provision_image(host, "dnf", rpm_image["image_ref"], "linux/amd64", rpm_tag,
                        ["createrepo_c", "rpm-sign", "gnupg2", "python3", "xorg-x11-server-Xvfb", "dbus-daemon", "findutils", *rpm_image["preprovisioned_packages"]],
                        recorder=host, substage_prefix="build-")
        images.append(rpm_tag)
        rpm_signing_identities = []
        wrong_rpm, wrong_rpm_owned = _new_wrong_signer(context)
        if wrong_rpm_owned:
            closers.append(wrong_rpm)
        for arch, system in (("x86_64", "x86_64-linux"), ("aarch64", "aarch64-linux")):
            arch_dir = stage / "rpm" / "fedora/43" / arch
            (arch_dir / "Packages").mkdir(parents=True)
            for name, path in sorted(bundles[("rpm", system)]["packages"].items()):
                shutil.copyfile(path, arch_dir / "Packages" / name)
                from rs9.hosted_packaging import sign_rpm
                signer = ContainerRunner(host,rpm_tag,platform="linux/amd64",
                    mounts=[(str(stage),str(stage),True),(str(fixture.homedir),str(fixture.homedir),True)]
                        + ([(str(wrong_rpm.homedir),str(wrong_rpm.homedir),True)]
                           if getattr(wrong_rpm, "homedir", None) else []))
                matches = [(capture, intent) for capture, intent, _ in context["captures"]
                           if name.startswith(intent["project"]["id"] + "-" +
                                              str(intent["version"]) + "-")]
                if len(matches) != 1:
                    raise ContractError("RPM_SIGNING", "Custody RPM has no unique intended product")
                _, intent = matches[0]
                from rs9.product_classes import is_pure_js_cli
                rpm_signing_identities.append(sign_rpm(signer, arch_dir / "Packages" / name, fixture,
                    wrong_fixture=wrong_rpm, diagnostics_dir=scratch / "diagnostics",
                    expected={"package_sha256": bundles[("rpm", system)]["manifest"]["files"][name]["sha256"],
                              "name": intent["project"]["id"], "version": str(intent["version"]),
                              "arch": "noarch" if is_pure_js_cli(intent["project"]["id"]) else arch,
                              "revision": 1}))
            _run_tool_container(host, rpm_tag, "linux/amd64", stage,
                                ["createrepo_c", "--no-database", "--compress-type", "gz", "-s", "sha256", str(arch_dir)])
            repomd = arch_dir / "repodata/repomd.xml"
            (arch_dir / "repodata/repomd.xml.asc").write_bytes(fixture.detach_sign(repomd.read_bytes(), armor=True))
        pac_dir = stage / "pacman/x86_64"
        pac_dir.mkdir(parents=True)
        for name, path in sorted(bundles[("pacman", "x86_64-linux")]["packages"].items()):
            shutil.copyfile(path, pac_dir / name)
            (pac_dir / f"{name}.sig").write_bytes(fixture.detach_sign(path.read_bytes(), armor=False))
        _run_tool_container(
            host, pacman_image["image_ref"], "linux/amd64", stage,
            ["sh", "-c", f"cd {pac_dir} && repo-add rs9.db.tar.gz *.pkg.tar.zst && "
                         "for n in db files; do rm -f rs9.$n; cp rs9.$n.tar.gz rs9.$n; done"])
        for name in ("rs9.db.tar.gz", "rs9.db", "rs9.files.tar.gz", "rs9.files"):
            (pac_dir / f"{name}.sig").write_bytes(fixture.detach_sign((pac_dir / name).read_bytes(), armor=False))
        for family_dir in ((stage / "rpm"), pac_dir.parent):
            for path in sorted(family_dir.rglob("*")):
                if path.is_file():
                    files[path.relative_to(stage).as_posix()] = path.read_bytes()

        sources = collect_candidate_sources(files=files, cname=PAGES_HOST, signing_fixture=fixture, apt_repo=repo)
        inventory = exact_inventory_for(sources)
        verify_pages_completeness(inventory)
        tree = scratch / "pages-tree"
        tree.mkdir()
        candidate = assemble_pages_candidate(
            tree, files=files, cname=PAGES_HOST, signing_fixture=fixture, apt_repo=repo, exact_inventory=inventory)
        if (tree / "apt").exists():
            pages_apt_modes = _verify_public_tree_modes(tree / "apt")
            details["pages_apt_public_modes"] = pages_apt_modes
            if pages_apt_modes.get("status") != "pass":
                raise ContractError("MODE_MISMATCH", "Pages candidate APT projection public tree mode verification failed",
                                    details={"substage": "pages-apt-projection", "reason": "public-mode-mismatch"})
        status, reason = _status(True, real and host.real_since(mark))
        gates.append(_gate("pages-repository-objects", status, reason))
        # Exact custody bytes survive into the assembled tree, and the tree on disk is the Merkle inventory.
        custody_sha = {name: digest(path.read_bytes()) for bundle in bundles.values() for name, path in bundle["packages"].items()}
        tree_sha = {Path(p).name: sha for p, sha in candidate.exact_inventory.items()}
        # Signing RPM headers changes only the fixture copy; commit both identities explicitly.
        bound = all(tree_sha.get(name) == sha for name, sha in custody_sha.items() if not name.endswith(".rpm"))
        details["rpm_fixture_identities"] = rpm_signing_identities
        verify_merkle_inventory(candidate.merkle, _tree_inventory(tree))
        details["pages"] = {"merkle_root": candidate.merkle["root"], "file_count": len(candidate.exact_inventory),
                            "custody_roots": {f"{k[0]}-{k[1]}": v["manifest"]["merkle"]["root"] for k, v in bundles.items()}}
        gates.append(_gate("pages-inventory-integrity", *_pair(bound)))
        scans = {p: row.get("format_scan") for p, row in candidate.manifest["files"].items()
                 if p.endswith((".deb", ".rpm", ".pkg.tar.zst"))}
        unproven = sorted(p for p, scan in scans.items() if scan is None)
        incomplete = sorted(p for p, scan in scans.items() if scan is not None and not scan["complete"])
        if unproven:
            gates.append(_gate("pages-privacy-scan", "fail", "format-scan-unproven:" + ",".join(unproven)))
        elif incomplete:
            gates.append(_gate("pages-privacy-scan", "not-run", "format-scan-incomplete:" + ",".join(incomplete)))
        else:
            gates.append(_gate("pages-privacy-scan", "pass"))
        index = scratch / "pages-tree-index.json"
        index.write_bytes(canonical({"schema":"rs9.pages-candidate-tree.v1alpha1","production":False,
            "files":candidate.exact_inventory,"merkle":candidate.merkle,
            "package_objects":"sha256-bound-to-unsigned-or-fixture-signed-lane-custody"}))
        artifacts.append(index)
        tree_files = [p for p in tree.rglob("*") if p.is_file()]
        if sum(p.stat().st_size for p in tree_files) <= 2 * 1024**3:
            artifacts.extend(tree_files)
            details["pages_tree_custody"] = "complete-tree"
        else:
            artifacts.extend(p for p in tree_files if not p.name.endswith((".deb",".pkg.tar.zst")))
            details["pages_tree_custody"] = "split-index-and-fixture-rpm-objects;apt-pacman-in-family-custody"
    except (ContractError, NativePrerequisiteUnavailable, OSError) as err:
        for name in PAGES_GATES:
            if not any(g["name"] == name for g in gates):
                gates.append(_gate(name, "not-run" if isinstance(err, NativePrerequisiteUnavailable) else "fail",
                                   _family_error(err)))
        return

    # A failed assembly gate stops here; not-run (synthetic seam, incomplete scan) still proceeds so
    # every family client gate reports its own truthful status.
    if any(g["status"] == "fail" for g in gates):
        for name in ("pages-client.apt", "pages-client.dnf", "pages-client.pacman"):
            if not any(g["name"] == name for g in gates):
                gates.append(_gate(name, "not-run", "blocked-by:assembly-failure"))
        return
    _pages_client_tests(context, host, repository, scratch, pins, tree, bundles, fixture, gates, details, images,
                        closers, rpm_tag)


def _pages_client_tests(
    context: dict[str, Any], host: RecordingRunner, repository: Path, scratch: Path, pins: Mapping[str, Any],
    tree: Path, bundles: Mapping[tuple[str, str], dict[str, Any]], fixture: Any, gates: list[dict[str, Any]],
    details: dict[str, Any], images: list[str], closers: list[Any], rpm_tag: str,
) -> None:
    """Install the ASSEMBLED tree per family on the runner architecture, network disconnected."""
    keys = tree / "keys"
    work = scratch / "pages-client"
    work.mkdir()
    try:
        wrong_signer, wrong_owned = _new_wrong_signer(context)
        if wrong_owned:
            closers.append(wrong_signer)
        env = prepare_environment(host, "amd64", pins, recorder=details.setdefault("container_preparation", []))
        deb_names: list[str] = []
        for bundle in (bundles[("deb", "amd64")],):
            for path in bundle["packages"].values():
                deb_names += [n for n in _dependency_names(path.read_bytes()) if n not in deb_names]
        apt_tag = f"rs9-pages-apt:{uuid.uuid4().hex[:8]}"
        provision_image(host, "apt", env["image_ref"], "linux/amd64", apt_tag, [*deb_names, "python3", "xvfb", "dbus-x11"], recorder=host, substage_prefix="client-")
        images.append(apt_tag)
        pacman_image = provision_native("pacman", "x86_64-linux", pins, runner=host)
        pac_tag = f"rs9-pages-arch:{uuid.uuid4().hex[:8]}"
        provision_image(host, "pacman", pacman_image["image_ref"], "linux/amd64", pac_tag,
                        [*pacman_image["preprovisioned_packages"], "python", "xorg-server-xvfb", "dbus"], recorder=host, substage_prefix="client-")
        images.append(pac_tag)
    except (ContractError, NativePrerequisiteUnavailable, OSError) as err:
        status = "not-run" if isinstance(err, NativePrerequisiteUnavailable) else "fail"
        reason = _family_error(err)
        err_details = safe_details(err.details) if isinstance(err, ContractError) and err.details else {}
        gates.append(_gate("pages-client.setup", status, reason, details=err_details,
                           **{k:v for k,v in err_details.items() if k not in {"name","status","reason"}}))
        details["environment_failure"] = {"code":err.code if isinstance(err,ContractError) else "TOOL_EXECUTION", "details":err_details}
        for gate_name in ("pages-client.apt", "pages-client.dnf", "pages-client.pacman"):
            gates.append(_gate(gate_name, status, reason))
        return

    families = [
        ("apt", apt_tag, {"apt": tree / "apt"}, lambda d: apt_spec(d["apt"], keys / "rs9-candidate-fixture-NONPRODUCTION.gpg", "amd64", public_fingerprint=fixture.primary_fingerprint),
         "amd64", list(REQUIRED_PRODUCTS)),
        ("dnf", rpm_tag, {"rpm": tree / "rpm"}, lambda d: dnf_spec(d["rpm"], keys, "x86_64"), "x86_64",
         list(REQUIRED_PRODUCTS)),
        ("pacman", pac_tag, {"pacman": tree / "pacman"}, lambda d: pacman_spec(d["pacman"], keys, fixture.primary_fingerprint),
         "x86_64", list(REQUIRED_PRODUCTS)),
    ]
    for family, tag, dirs, spec_for, arch, products in families:
        prefix = f"pages-client.{family}"
        from rs9.hosted_smoke import prepare_smoke
        neb = next(c for c,i,_ in context["captures"] if i["project"]["id"] == NATIVE_PRODUCT)
        prepared = prepare_smoke(neb, context["captures"], context["client"], work / ("smoke-"+family))
        spec = spec_for(dirs)
        rows, evidence = client_cycle(host, spec, image=tag, platform="linux/amd64", products=products,
                                      repository=repository, prefix=prefix, smoke=prepared, system="x86_64-linux",
                                      burst_record=_burst_release_record(context["captures"], "x86_64-linux"),
                                      burst_scratch=work / ("burst-probe-" + family))
        rows += tamper_cycle(host, spec_for, family, dirs, image=tag, platform="linux/amd64", product=products[0],
                             work=work, arch=arch, wrong_signer=wrong_signer, kinds=TAMPER_KINDS_PAGES, prefix=prefix,
                             positive_control=evidence.get(products[0], {}).get("positive_control"))
        gates.extend(rows)
        gates.append(_gate(prefix, _fold(rows)))
        details.setdefault("client", {})[family] = evidence


# --------------------------------------------------------------------------- shared interface


def execute(context: dict[str, Any]) -> dict[str, Any]:
    """Shared hosted lane interface: family ``deb`` (amd64/arm64) or ``pages`` (generation)."""
    family = context.get("family")
    if family == "deb":
        return execute_deb(context)
    if family == "pages":
        return execute_pages(context)
    raise ContractError("UNSUPPORTED_PLATFORM", f"Unsupported family: {family}")
