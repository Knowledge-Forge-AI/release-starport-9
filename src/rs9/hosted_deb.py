"""Hosted Ubuntu 26.04 APT and assembled-Pages candidate lanes (family ``deb`` and ``pages``).

``execute(context)`` is the shared hosted lane interface; it returns
``{"gates": [...], "artifacts": [Path], "details": {...}}`` and never raises for lane-level
blockers, so partial evidence is retained. Everything is nonproduction:

deb lane (amd64 or arm64 runner, Ubuntu 26.04 'resolute' container of the runner architecture)
- builds the three architecture-all CLI debs and the native Nebular deb; Nebular dependencies
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

import json
import os
from pathlib import Path
import re
import shutil
from typing import Any, Mapping, Sequence
import uuid

from rs9.build_deb import build_deb_candidate
from rs9.build_native import (
    REQUIRED_COMMANDS,
    CommandReceipt,
    CommandRunner,
    NativePrerequisiteUnavailable,
    SubprocessRunner,
    validate_scratch_root,
)
from rs9.errors import ContractError
from rs9.hosted_native import compare_inventories, execute_probes, is_excluded_inventory_path
from rs9.hosted_native import provision as provision_native
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

INVENTORY_SCRIPT = (
    "cd / && find . -xdev "
    "\\( -path ./proc -o -path ./sys -o -path ./dev -o -path ./run -o -path ./tmp -o -path ./srv/rs9 \\) -prune -o "
    "\\( -type f -exec sha256sum {} + \\) -o \\( -type l -printf 'L %p -> %l\\n' \\) -o \\( -type d -printf 'D %p\\n' \\)"
)


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
        outer = self.host.run(self.docker_argv(argv, cwd, env))
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


def parse_inventory(stdout: bytes, family: str) -> dict[str, str]:
    """Parse INVENTORY_SCRIPT output into {relative path: sha256 | 'dir' | 'symlink:<target>'}."""
    inventory: dict[str, str] = {}
    for raw in stdout.decode("utf-8", errors="surrogateescape").split("\n"):
        if not raw:
            continue
        if raw.startswith("D "):
            path, value = raw[2:], "dir"
        elif raw.startswith("L "):
            path, _, target = raw[2:].partition(" -> ")
            value = f"symlink:{target}"
        else:
            match = re.fullmatch(r"([0-9a-f]{64})  (.+)", raw)
            if match is None:
                raise ContractError("INVENTORY_PARSE", "Unparseable client inventory line")
            value, path = match.group(1), match.group(2)
        rel = path.removeprefix("./")
        if rel in {"", "."} or inventory_excluded(family, rel):
            continue
        inventory[rel] = value
    return inventory


# --------------------------------------------------------------------------- containers


def _digest_from_inspect(text: str) -> tuple[str | None, str | None]:
    parts = text.strip().split("|")
    reference = parts[0] if parts else ""
    arch = parts[1] if len(parts) > 1 else None
    return (reference.split("@", 1)[1] if "@sha256:" in reference else None), arch


def prepare_environment(host: CommandRunner, system: str, pins: Mapping[str, Any]) -> dict[str, Any]:
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
    pulled = host.run(["docker", "pull", "--platform", platform, reference])
    if pulled.exit_code != 0:
        raise ContractError("CONTAINER_PULL_FAILED", f"docker pull failed with exit code {pulled.exit_code}")
    inspected = host.run(["docker", "image", "inspect", "--format", "{{index .RepoDigests 0}}|{{.Architecture}}", reference])
    resolved, image_arch = _digest_from_inspect(inspected.stdout_text)
    if inspected.exit_code != 0 or not resolved:
        raise ContractError("CONTAINER_DIGEST_UNRESOLVED", "Container image digest could not be resolved")
    if pin_digest is not None and resolved != pin_digest:
        raise ContractError("CONTAINER_DIGEST_MISMATCH", "Pulled image digest differs from the source pin")
    if image_arch != system:
        raise ContractError("INVALID_ARCHITECTURE", "Container image architecture differs from the lane system")
    pinned_ref = f"ubuntu@{resolved}"
    release = host.run(["docker", "run", "--rm", "--platform", platform, "--network", "none", pinned_ref,
                        "sh", "-c", "cat /etc/os-release && dpkg --print-architecture"])
    fields = dict(
        line.split("=", 1) for line in release.stdout_text.splitlines() if "=" in line and not line.startswith("#")
    )
    lines = [line for line in release.stdout_text.splitlines() if line.strip()]
    version_id = fields.get("VERSION_ID", "").strip('"')
    codename = fields.get("VERSION_CODENAME", "").strip('"')
    if release.exit_code != 0 or version_id != "26.04" or codename != "resolute":
        raise ContractError("UNSUPPORTED_PLATFORM", "Container is not Ubuntu 26.04 resolute")
    if not lines or lines[-1].strip() != system:
        raise ContractError("INVALID_ARCHITECTURE", "Container dpkg architecture differs from the lane system")
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
    host: CommandRunner, family: str, base_ref: str, platform: str, tag: str, packages: Sequence[str]
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
    try:
        run = host.run(["docker", "run", "--name", name, "--platform", platform, base_ref, "sh", "-c", script])
        if run.exit_code != 0:
            raise ContractError("PROVISION_FAILED", f"{family} provisioning failed with exit code {run.exit_code}")
        commit = host.run(["docker", "commit", name, tag])
        if commit.exit_code != 0:
            raise ContractError("PROVISION_FAILED", "Provisioned image commit failed")
    finally:
        try:
            host.run(["docker", "rm", "-f", name])
        except ContractError:
            pass
    return tag


class ClientContainer:
    """A fresh, network-disconnected, long-lived container driven through ``docker exec``."""

    def __init__(self, host: CommandRunner, image: str, platform: str, mounts: Sequence[tuple[str, str, bool]], family: str) -> None:
        self.host, self.image, self.platform, self.family = host, image, platform, family
        self.mounts = list(mounts)
        self.name = f"rs9-client-{uuid.uuid4().hex[:12]}"

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

    def inventory(self) -> dict[str, str]:
        receipt = self.exec(["sh", "-c", INVENTORY_SCRIPT])
        if receipt.exit_code != 0:
            raise ContractError("INVENTORY_FAILED", "Client inventory command failed")
        return parse_inventory(receipt.stdout_bytes, self.family)


def _printf_file(path: str, lines: Sequence[str]) -> list[str]:
    for line in lines:
        if "'" in line or "\n" in line:
            raise ContractError("INVALID_METADATA", "Unsafe client configuration line")
    quoted = " ".join(f"'{line}'" for line in lines)
    return ["sh", "-c", f"printf '%s\\n' {quoted} > {path}"]


def apt_spec(apt_dir: Path, keyring: Path, arch: str) -> dict[str, Any]:
    line = apt_source_line(f"file:{SERVER_ROOT}/apt", CLIENT_KEYRING_PATH, arch=arch).strip()
    opts = ["-o", f"Dir::Etc::sourcelist={APT_LIST}", "-o", "Dir::Etc::sourceparts=-",
            "-o", "APT::Get::AllowUnauthenticated=false", "-o", "Acquire::AllowInsecureRepositories=false",
            "-o", "Acquire::Languages=none"]
    return {
        "family": "apt",
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
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Fresh container per product: configure, inventory, install, probe, remove, inventory."""
    gates: list[dict[str, Any]] = []
    evidence: dict[str, Any] = {}
    family = spec["family"]
    for product in products:
        label = f"{prefix}.{product}"
        mark = host.mark()
        rows: list[dict[str, Any]] = []
        try:
            with ClientContainer(host, image, platform, spec["mounts"], family) as client:
                for command in spec["configure"]:
                    if client.exec(command).exit_code != 0:
                        raise ContractError("CLIENT_CONFIGURE_FAILED", "Client repository trust setup failed")
                negative = client.exec(["python3","-c",
                    "import socket;s=socket.socket();s.settimeout(2);assert s.connect_ex(('1.1.1.1',443))!=0"], user=CLIENT_USER)
                if negative.exit_code:
                    raise ContractError("NETWORK_DENIAL", "Disconnected client still has runtime egress")
                rows.append(_gate(f"{label}.network-denial", "pass"))
                before = client.inventory()
                if client.exec(spec["refresh"]).exit_code != 0:
                    raise ContractError("CLIENT_REFRESH_FAILED", "Repository metadata refresh failed")
                installed = client.exec(spec["install"](product))
                present = client.exec(spec["query"](product))
                rows.append(_gate(f"{label}.install", *_pair(installed.exit_code == 0 and present.exit_code == 0)))
                if installed.exit_code != 0 or present.exit_code != 0:
                    raise ContractError("CLIENT_INSTALL_FAILED", "Candidate package did not install")
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
                if product == NATIVE_PRODUCT:
                    closure = client.exec(["python3","-c",
                        "from pathlib import Path;import subprocess;root=Path('/usr/lib/theme-forge-nebular-fusion');"
                        "files=[p for p in root.rglob('*') if p.is_file() and not p.is_symlink() and p.read_bytes()[:4]==bytes([127])+b'ELF'];"
                        "assert files;"
                        "results=[subprocess.run(['ldd',str(p)],capture_output=True) for p in files];"
                        "assert all(b'not found' not in r.stdout+r.stderr and (r.returncode==0 or b'not a dynamic' in r.stdout+r.stderr or b'statically linked' in r.stdout+r.stderr) for r in results)"], user=CLIENT_USER)
                    rows.append(_gate(f"{label}.native-closure", *_pair(closure.exit_code == 0)))
                    if smoke:
                        from rs9.hosted_smoke import verify_nebular_runtime
                        inspected = client.exec(["python3","-c",
                            "from pathlib import Path;import json;"
                            "r=Path('/usr/lib/theme-forge-nebular-fusion');"
                            "print(json.dumps({'manifests':[str(p) for p in r.rglob('sidecar-payload/manifest.json')],"
                            "'binaries':[str(p) for p in r.rglob('tfsb-studio-service*') if p.is_file() and p.parent.name in ('bin','MacOS')]}))"])
                        if inspected.exit_code:
                            raise ContractError("SIDECAR_REPRESENTATION","Installed package representation missing")
                        verify_nebular_runtime("/usr/lib/theme-forge-nebular-fusion", smoke, system,
                            client.unprivileged_prefix, discovered=json.loads(inspected.stdout_bytes))
                        rows.append(_gate(f"{label}.application-smoke","pass"))
                removed = client.exec(spec["remove"](product))
                gone = client.exec(spec["query"](product))
                rows.append(_gate(f"{label}.uninstall", *_pair(removed.exit_code == 0 and gone.exit_code != 0)))
                comparison = compare_inventories(before, client.inventory())
                rows.append(_gate(
                    f"{label}.inventory", *_pair(comparison["clean"]),
                    **({} if comparison["clean"] else {"leftover": comparison["added"][:20] + comparison["modified"][:20]}),
                ))
                evidence[product] = {"inventory_clean": comparison["clean"], "removed": comparison["removed"][:20]}
        except (ContractError, NativePrerequisiteUnavailable, OSError) as err:
            rows.append(_gate(f"{label}.client", "fail" if not isinstance(err, NativePrerequisiteUnavailable) else "not-run",
                              _family_error(err)))
            evidence[product] = {"error": _family_error(err)}
        real = host.real_since(mark)
        for row in rows:
            if row["status"] == "pass" and not real:
                row["status"], row["reason"] = "not-run", "synthetic-command-seam"
        gates.extend(rows)
    return gates, evidence


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
) -> list[dict[str, Any]]:
    """Every tamper must stop installation; the untampered control already passed elsewhere."""
    gates = []
    for kind in kinds:
        label = f"{prefix}.tamper.{kind}"
        mark = host.mark()
        try:
            copy_root = work / f"tamper-{family}-{kind}"
            copy_root.mkdir()
            tampered = tamper_family_copy(family, kind, dirs, copy_root, arch=arch, wrong_signer=wrong_signer,
                                          product=product)
            spec = spec_for(tampered)
            with ClientContainer(host, image, platform, spec["mounts"], family) as client:
                for command in spec["configure"]:
                    if client.exec(command).exit_code != 0:
                        raise ContractError("CLIENT_CONFIGURE_FAILED", "Client repository trust setup failed")
                client.exec(spec["refresh"])  # may fail first; installation must still never succeed
                install = client.exec(spec["install"](product))
                present = client.exec(spec["query"](product))
            rejected = install.exit_code != 0 and present.exit_code != 0
            row = _gate(label, *_status(rejected, host.real_since(mark)))
        except (ContractError, NativePrerequisiteUnavailable, OSError) as err:
            row = _gate(label, "fail" if not isinstance(err, NativePrerequisiteUnavailable) else "not-run", _family_error(err))
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
    import posixpath

    from rs9.npm_deps import closure_for_capture

    package = json.loads(capture.source.get("package.json", "{}"))
    if not (package.get("dependencies") or product == "theme-forge-stellar-burst"):
        return None
    archives: dict[str, Path] = {}
    for index, row in enumerate(closure_for_capture(capture)):
        cached = inputs / posixpath.basename(row["url"]) if inputs else None
        if cached is not None and cached.is_file():
            archives[row["path"]] = cached
        elif client is not None:
            target = scratch / "npm_downloads" / f"dep-{product}-{index}.tgz"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(client.get(row["url"], limit=32 * 1024 ** 2))
            archives[row["path"]] = target
    return archives


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
            built = build_deb_candidate(
                capture, intent, system if product == NATIVE_PRODUCT else "all", build_dir,
                maintainer=maintainer,
                offline_npm_archives=_offline_npm_archives(capture, product, inputs, client, scratch),
                runner=builder,
            )
        except (ContractError, NativePrerequisiteUnavailable) as err:
            errors[product] = _family_error(err)
            continue
        manifest = built["manifest"]
        derivation = built["derivation_record"]
        products[product] = {
            "package_file": built["deb_path"].name,
            "path": built["deb_path"],
            "sha256": manifest["package_sha256"],
            "size": manifest["package_size"],
            "architecture": manifest["architecture"],
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
    details: dict[str, Any] = {"family": "deb", "system": system, "required_products": list(required)}
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
            env = prepare_environment(host, system, pins)
            libs = tuple((pins.get("deb", {}) or {}).get("build_packages") or DEFAULT_NATIVE_LIBRARY_PACKAGES)
            builder_tag = f"rs9-deb-builder-{system}:{uuid.uuid4().hex[:8]}"
            provision_image(host, "apt", env["image_ref"], platform, builder_tag, [*BUILD_TOOL_PACKAGES, *libs])
            images.append(builder_tag)
            builder = ContainerRunner(host, builder_tag, platform=platform,
                                      mounts=[(str(scratch), str(scratch), True)], user=_user())
            from rs9.hosted_native import container_tool_facts
            env["tools"] = container_tool_facts(builder, ["dpkg-deb", "dpkg-shlibdeps", "dpkg-query", "ldd"])
            status, reason = _status(True, host.real_since(mark))
            gates.append(_gate("deb-container-environment", status,
                               reason or ("run-resolved-digest" if env["unpinned"] else None)))
            details["container"] = env
        except (ContractError, NativePrerequisiteUnavailable) as err:
            blocked = "deb-container-environment"
            gates.append(_gate(blocked, "not-run" if isinstance(err, NativePrerequisiteUnavailable) else "fail",
                               _family_error(err)))

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
            native_error = errors.get(NATIVE_PRODUCT, "")
            shlibs_ok = (
                not errors
                and products[NATIVE_PRODUCT]["dependency_classification"] == "native-tool-derived"
                and products[NATIVE_PRODUCT]["elf_object_count"] >= 1
                and all(p["elf_object_count"] == 0 for k, p in products.items() if k != NATIVE_PRODUCT)
            ) if NATIVE_PRODUCT in required else not errors
            native_real = all(
                p["derivation_source"] == "actual-native-tool-subprocess"
                for k, p in products.items() if k == NATIVE_PRODUCT
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
                provision_image(host, "apt", env["image_ref"], platform, client_tag, [*names, "python3", "xvfb", "dbus-x11"])
                images.append(client_tag)
                keyring = scratch / "client-keyring" / "rs9-nonproduction.gpg"
                keyring.parent.mkdir()
                keyring.write_bytes(fixture.public_key_binary)
                apt_dir = scratch / "apt"
                from rs9.hosted_smoke import prepare_smoke
                neb = next((c for c,i,_ in context["captures"] if i["project"]["id"] == NATIVE_PRODUCT),None)
                prepared = prepare_smoke(neb, context["captures"], context["client"], scratch / "application-smoke") if neb else None
                spec = apt_spec(apt_dir, keyring, system)
                spec["mounts"].append((str(scratch),str(scratch),True))
                cycle_rows, evidence = client_cycle(
                    host, spec, image=client_tag, platform=platform,
                    products=required, repository=repository, prefix="deb-client", smoke=prepared,
                    system="aarch64-linux" if system=="arm64" else "x86_64-linux")
                rows.extend(cycle_rows)
                details["client"] = evidence
                wrong_signer, wrong_owned = _new_wrong_signer(context)
                rows.extend(tamper_cycle(
                    host, lambda dirs: apt_spec(dirs["apt"], keyring, system), "apt", {"apt": apt_dir},
                    image=client_tag, platform=platform, product=required[0], work=scratch, arch=system,
                    wrong_signer=wrong_signer, kinds=TAMPER_KINDS_ALL, prefix="deb-client"))
            except (ContractError, NativePrerequisiteUnavailable) as err:
                rows.append(_gate("deb-client.setup", "not-run" if isinstance(err, NativePrerequisiteUnavailable) else "fail",
                                  _family_error(err)))
            gates.extend(rows)
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
            try:
                host.run(["docker", "rmi", "-f", tag])
            except (ContractError, NativePrerequisiteUnavailable):
                pass
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


def _gather_custody(inputs: Path | None, authentication_sha256: str | None, source_commit: str | None = None) -> dict[tuple[str, str], dict[str, Any]]:
    bundles: dict[tuple[str, str], dict[str, Any]] = {}
    if inputs is None:
        return bundles
    for manifest in sorted(inputs.rglob(CUSTODY_MANIFEST)):
        bundle = load_custody_bundle(manifest.parent, expected_authentication_sha256=authentication_sha256)
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
        raise ContractError("METADATA_BUILD_FAILED", f"{argv[0]} failed with exit code {receipt.exit_code}")


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

        files: dict[str, bytes | str] = dict(render_install_docs())
        # RPM and pacman metadata is rebuilt by the family tools in their own containers.
        rpm_image = provision_native("rpm", "x86_64-linux", pins, runner=host)
        pacman_image = provision_native("pacman", "x86_64-linux", pins, runner=host)
        rpm_tag = f"rs9-pages-fedora:{uuid.uuid4().hex[:8]}"
        provision_image(host, "dnf", rpm_image["image_ref"], "linux/amd64", rpm_tag,
                        ["createrepo_c", "rpm-sign", "gnupg2", "python3", "xorg-x11-server-Xvfb", "dbus-daemon", "findutils", *rpm_image["preprovisioned_packages"]])
        images.append(rpm_tag)
        for arch, system in (("x86_64", "x86_64-linux"), ("aarch64", "aarch64-linux")):
            arch_dir = stage / "rpm" / "fedora/43" / arch
            (arch_dir / "Packages").mkdir(parents=True)
            for name, path in sorted(bundles[("rpm", system)]["packages"].items()):
                shutil.copyfile(path, arch_dir / "Packages" / name)
                from rs9.hosted_packaging import sign_rpm
                signer = ContainerRunner(host,rpm_tag,platform="linux/amd64",
                    mounts=[(str(stage),str(stage),True),(str(fixture.homedir),str(fixture.homedir),True)])
                sign_rpm(signer, arch_dir / "Packages" / name, fixture)
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
        status, reason = _status(True, real and host.real_since(mark))
        gates.append(_gate("pages-repository-objects", status, reason))
        # Exact custody bytes survive into the assembled tree, and the tree on disk is the Merkle inventory.
        custody_sha = {name: digest(path.read_bytes()) for bundle in bundles.values() for name, path in bundle["packages"].items()}
        tree_sha = {Path(p).name: sha for p, sha in candidate.exact_inventory.items()}
        # Signing RPM headers changes only the fixture copy; commit both identities explicitly.
        bound = all(tree_sha.get(name) == sha for name, sha in custody_sha.items() if not name.endswith(".rpm"))
        details["rpm_fixture_identities"] = [{"unsigned_sha256":sha,"fixture_signed_sha256":tree_sha.get(name)}
            for name,sha in custody_sha.items() if name.endswith(".rpm")]
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
        env = prepare_environment(host, "amd64", pins)
        deb_names: list[str] = []
        for bundle in (bundles[("deb", "amd64")],):
            for path in bundle["packages"].values():
                deb_names += [n for n in _dependency_names(path.read_bytes()) if n not in deb_names]
        apt_tag = f"rs9-pages-apt:{uuid.uuid4().hex[:8]}"
        provision_image(host, "apt", env["image_ref"], "linux/amd64", apt_tag, [*deb_names, "python3", "xvfb", "dbus-x11"])
        images.append(apt_tag)
        pacman_image = provision_native("pacman", "x86_64-linux", pins, runner=host)
        pac_tag = f"rs9-pages-arch:{uuid.uuid4().hex[:8]}"
        provision_image(host, "pacman", pacman_image["image_ref"], "linux/amd64", pac_tag,
                        [*pacman_image["preprovisioned_packages"], "python", "xorg-server-xvfb", "dbus"])
        images.append(pac_tag)
    except (ContractError, NativePrerequisiteUnavailable, OSError) as err:
        status = "not-run" if isinstance(err, NativePrerequisiteUnavailable) else "fail"
        reason = _family_error(err)
        gates.append(_gate("pages-client.setup", status, reason))
        for gate_name in ("pages-client.apt", "pages-client.dnf", "pages-client.pacman"):
            gates.append(_gate(gate_name, status, reason))
        return

    families = [
        ("apt", apt_tag, {"apt": tree / "apt"}, lambda d: apt_spec(d["apt"], keys / "rs9-candidate-fixture-NONPRODUCTION.gpg", "amd64"),
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
        spec["mounts"].append((str(scratch),str(scratch),True))
        rows, evidence = client_cycle(host, spec, image=tag, platform="linux/amd64", products=products,
                                      repository=repository, prefix=prefix, smoke=prepared, system="x86_64-linux")
        rows += tamper_cycle(host, spec_for, family, dirs, image=tag, platform="linux/amd64", product=products[0],
                             work=work, arch=arch, wrong_signer=wrong_signer, kinds=TAMPER_KINDS_PAGES, prefix=prefix)
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
