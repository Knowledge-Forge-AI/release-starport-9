"""Current-generation-only native pacman/aarch64-linux producer (ArchARM SDK route).

``execute(context)`` is reached only through the single early dispatch in
``rs9.hosted_packaging.execute`` for generation ``theme-forge-current-202610``,
family ``pacman`` and system ``aarch64-linux``. Every historical and x86_64 route
stays in ``hosted_packaging`` unchanged.

Operating policy (policy/OWNER-GRANT.json option A, PROPOSED-POLICY.json):

- The ArchARM SDK is one fixed, source-bound lease from ``rs9.archarm_sdk``.
  The legacy online provisioner (``provision``/``provision_image``/``pacman -Fy``),
  the whole-scratch ``ContainerRunner`` and root ``repo-add`` are never used here.
- Only Burst and Nebular are built natively (two builds, never four). Each build
  gets its own SDK builder runner whose sole writable bind is that product's
  build/output tree. No public source is mounted because the existing builder
  stages every authenticated input host-side into that tree, so the offline npm
  cache copy lives only there.
- Loom/Solar ``any`` packages are imported only from the canonical x86_64
  constructor through ``rs9.current_pacman_any`` into the fresh lane scratch
  (``canonical-any/files``). Those held copies are re-exported as raw
  unsigned-custody *reuse replicas* together with the importer's witness. They
  are never rebuilt, never copied a second time and never placed in the
  construction custody bundle.
- The builder's own per-product ``repo-add`` (``custom.db``) runs in an SDK
  repository runner whose sole bind is that product's db directory.
- Fixture and wrong-key identities are fresh, host-side, in explicit owned homes.
  Agent/dirmngr quiescence is verified with real receipts, and unknown state fails.
  Only the public certificate, detached package signatures and detached DB/files
  signatures enter the assembly. ``repo-add`` runs nonroot with the assembly as
  its sole writable bind and never with ``-s``.
- Policy-forbidden dependency/integrity bypass flags make the build fail. They
  are never rewritten or relaxed.

A gate passes only when its commands really executed (``CommandReceipt.executed``).
Nothing here can sign for production, publish or deploy.
"""

from __future__ import annotations

from contextlib import ExitStack, contextmanager
import importlib
import inspect
import json
import os
from pathlib import Path
import re
import shutil
import stat
import time
from typing import Any, Mapping, Sequence
from urllib.parse import unquote

from rs9.build_native import CommandReceipt, CommandRunner, SubprocessRunner
from rs9.current_generation import CURRENT_GENERATION, generation_paths
from rs9.errors import ContractError, safe_details
from rs9.release_core import digest
from rs9.scratch import canonical

FAMILY = "pacman"
SYSTEM = "aarch64-linux"
ARCHITECTURE = "aarch64"
PLATFORM = "linux/arm64"
CANONICAL_ANY_SYSTEM = "x86_64-linux"

BURST = "theme-forge-stellar-burst"
LOOM = "theme-forge-stellar-loom"
SOLAR = "theme-forge-solar-sail"
NEBULAR = "theme-forge-nebular-fusion"
REQUIRED_PRODUCTS = (BURST, LOOM, SOLAR, NEBULAR)
NATIVE_PRODUCTS = (BURST, NEBULAR)
IMPORTED_ANY_PRODUCTS = (LOOM, SOLAR)

ENV_GATE = "pacman-container-environment"
BUILD_GATE = "pacman-package-build"
INDEX_GATE = "pacman-repository-indexing"
CLIENT_GATE = "pacman-client-qualification"
BURST_TARGET_GATE = "burst-native-addon-target"
BURST_LOAD_GATE = "burst-native-addon-load"
ANY_GATE = "pacman-canonical-any-reuse"
CLEANUP_GATE = "pacman-sdk-cleanup"
# Exact source contract names (operators/theme-forge-current-202610/hosted-lanes.json
# and hosted_contract.load_hosted_lanes): the x86_64 pacman gates plus two ARM gates.
REQUIRED_GATES = (ENV_GATE, BUILD_GATE, INDEX_GATE, CLIENT_GATE, BURST_TARGET_GATE,
                  BURST_LOAD_GATE, ANY_GATE, CLEANUP_GATE)
TAMPER_KINDS = ("package", "index", "signature", "wrongkey")

STAGE_GATES = {
    "canonical-any": ANY_GATE,
    "sdk": ENV_GATE,
    "package-build": BUILD_GATE,
    "custody": BUILD_GATE,
    "fixture-preparation": INDEX_GATE,
    "package-signing": INDEX_GATE,
    "repository-metadata": INDEX_GATE,
    "client-preparation": CLIENT_GATE,
    "client-cycle": CLIENT_GATE,
    "tamper-cycle": CLIENT_GATE,
    "qualification-record": CLIENT_GATE,
}

# Context keys this route consumes. hosted_pipeline.run_lane supplies all of them
# for current pacman/aarch64-linux; ``runner`` is the same optional seam as x86_64.
REQUIRED_CONTEXT_KEYS = ("generation", "family", "system", "repository", "scratch", "captures",
                         "client", "binding", "authentication_sha256", "upstream", "producer_provenance")

# Shared hosted_deb keywords the parent adds; absence is a hard stop, never a fallback.
SHARED_API_KEYWORDS = (("client_cycle", "sdk_lease"), ("tamper_cycle", "sdk_lease"),
                       ("pacman_spec", "architecture"))

FIXTURE_USER_ID = "RS9 NON-PRODUCTION CANDIDATE FIXTURE <nonproduction@invalid>"
WRONG_USER_ID = "RS9 NON-PRODUCTION WRONG-KEY FIXTURE <nonproduction@invalid>"
REUSE_DIRECTORY = "canonical-any"  # = current_pacman_any.REPLICA_DIRECTORY parent
WITNESS_FILE = "canonical-any-witness.json"
WITNESS_ROLE = "reuse-witness"
CONSTRUCTION_AUTHORITY = FAMILY + "/" + CANONICAL_ANY_SYSTEM
PRIVATE_FIXTURE_HOMES = ("fixture", "fixture-wrong")
SDK_WORKSPACE = "archarm-sdk"
SDK_ASSERTIONS_FALSE = ("signingSecretsUsed", "publicationAuthority", "productionKeysAuthorized")
DETAILS_SCHEMA = "rs9.current-archarm-pacman-producer.v1alpha1"
ENVIRONMENT_SCHEMA = "rs9.current-archarm-environment.v1alpha1"
MAX_NUMERIC_ID = 2147483647
QUIESCENCE_POLLS = 20
QUIESCENCE_INTERVAL_SECONDS = 0.1

# Frozen identities of the qualified probe (PROPOSED-POLICY.json inputIdentity).
# Recorded as the producer's expectation; the SDK lease owns their verification.
QUALIFIED_INPUTS = {
    "qualified_probe_run": 42033829642,
    "qualified_source": "bfa1a8a83c328e623692c467b84aeaf81cf546bd",
    "rootfs_sha256": "42a4eeaa038994ffd31fa173256ef2f0ef511358eeb41b9ea1f8626391b9b319",
    "rootfs_pin_sha256": "0d92f648e1f9bc2ef29846b7f37d7fae99ccbb4adc6fd918d797c2ac9054edff",
    "package_pins_sha256": "53c812397e73cdb16c80cd5cd72b6ed66889817d8aa79b075034434895da2987",
    "packages": 139,
    "refresh_allowed": False,
}

# Mount/identity classes this producer requests from the lease. The SDK enforces them.
REQUESTED_PROFILES = {
    "builder": {"identity": "runner-numeric-uid-gid", "capabilities": [], "rootfs": "ro", "network": "none",
                "writable_binds": ["active-product-build-output"], "readonly_binds": []},
    "repository": {"identity": "runner-numeric-uid-gid", "capabilities": [], "rootfs": "ro", "network": "none",
                   "writable_binds": ["repository-assembly"], "readonly_binds": [],
                   "signing_flags": "refused"},
    "client": {"identity": "sdk-client-profile", "network": "none", "writable_binds": ["per-product-probe-output"],
               "readonly_binds": ["repository", "public-keys", "filtered-public-source"],
               "fixture_homes_mounted": False},
    "host_fixture": {"location": "host-only", "fresh_per_job": True,
                     "exports": ["public-certificate", "detached-package-signatures",
                                 "detached-db-files-signatures"]},
}

PROVIDER_POLICY = {
    "installed_package_queries": True,
    "live_files_db_refresh": False,
    "missing_provider": "fail-closed",
    "bypass_flags_refused": ["--nodeps", "-d", "--skipinteg", "--skippgpcheck", "--skipchecksums",
                             "-A", "--ignorearch"],
}

ENVIRONMENT_KEYS = frozenset({
    "schema", "generation", "family", "system", "architecture", "platform", "image", "runner_identity",
    "sdk_records_sha256", "qualified_inputs", "profiles", "provider_policy", "canonical_any_witness_sha256",
    "cleanup"})

_HEX40 = re.compile(r"[0-9a-f]{40}")
_HEX64 = re.compile(r"[0-9a-f]{64}")


# --------------------------------------------------------------------------- command policy


_MAKEPKG_LONG_FORBIDDEN = frozenset({"--nodeps", "--skipinteg", "--skippgpcheck", "--skipchecksums",
                                     "--ignorearch", "--syncdeps", "--install", "--rmdeps", "--asdeps"})
_MAKEPKG_SHORT_FORBIDDEN = frozenset("dAsir")
_REPO_ADD_LONG_FORBIDDEN = frozenset({"--sign", "--key", "--verify"})
_REPO_ADD_SHORT_FORBIDDEN = frozenset("skv")
_PACMAN_LONG_FORBIDDEN = frozenset({"--refresh", "--sync", "--upgrade", "--remove", "--database",
                                    "--sysupgrade", "--overwrite", "--dbonly", "--root", "--dbpath",
                                    "--config", "--gpgdir", "--hookdir", "--cachedir"})
_PACMAN_OPERATIONS = frozenset("DFQRSTUV")
_ADMITTED_TOOLS = {"builder": frozenset({"makepkg", "repo-add", "pacman"}),
                   "repository": frozenset({"repo-add"})}
_ADMITTED_ENV = frozenset({"SOURCE_DATE_EPOCH", "PKGEXT"})


def _refuse(reason: str, tool: str | None = None) -> ContractError:
    details = {"substage": "sdk-command-policy", "reason": reason}
    if tool:
        details["tool"] = tool
    return ContractError("ARCHARM_FORBIDDEN_COMMAND", "Command refused by the current ArchARM operating policy",
                         details=details)


def _within(path: str | Path, root: Path) -> bool:
    real_root = os.path.realpath(root)
    real = os.path.realpath(path)
    return real == real_root or real.startswith(real_root + os.sep)


def _option_tokens(args: Sequence[str], long_forbidden, short_forbidden, tool: str) -> None:
    for token in args:
        if token.startswith("--"):
            if token.split("=", 1)[0] in long_forbidden:
                raise _refuse(tool + "-forbidden-flag", tool)
        elif token.startswith("-") and len(token) > 1:
            if set(token[1:]) & short_forbidden:
                raise _refuse(tool + "-forbidden-flag", tool)


def admit_command(role: str, root: Path, argv: Sequence[str], *, cwd=None, env=None) -> None:
    """Closed role allow-list; raises before the SDK runner can execute anything."""
    if role not in _ADMITTED_TOOLS:
        raise _refuse("unknown-runner-role")
    if not argv or not all(isinstance(token, str) and token and "\x00" not in token for token in argv):
        raise _refuse("invalid-argv")
    tool = argv[0]
    if tool != Path(tool).name or tool not in _ADMITTED_TOOLS[role]:
        raise _refuse("tool-not-admitted")
    if cwd is not None and not _within(cwd, root):
        raise _refuse("cwd-outside-sole-writable-bind", tool)
    for key, value in (env or {}).items():
        if key not in _ADMITTED_ENV or not isinstance(value, str):
            raise _refuse("environment-not-admitted", tool)
        if key == "PKGEXT" and value != ".pkg.tar.zst":
            raise _refuse("environment-not-admitted", tool)
        if key == "SOURCE_DATE_EPOCH" and not value.isdigit():
            raise _refuse("environment-not-admitted", tool)
    args = list(argv[1:])
    if tool == "pacman":
        operations, shorts = set(), set()
        for token in args:
            if token.startswith("--"):
                if token.split("=", 1)[0] in _PACMAN_LONG_FORBIDDEN:
                    raise _refuse("pacman-mutation-or-redirection", tool)
            elif token.startswith("-") and len(token) > 1:
                chars = set(token[1:])
                operations |= chars & _PACMAN_OPERATIONS
                shorts |= chars
            elif token.startswith("/") and not token.startswith("/usr/lib/"):
                raise _refuse("pacman-query-path", tool)
        if operations != {"Q"}:
            raise _refuse("pacman-operation-not-query", tool)
        if "y" in shorts:
            raise _refuse("pacman-refresh", tool)
        return
    if tool == "makepkg":
        _option_tokens(args, _MAKEPKG_LONG_FORBIDDEN, _MAKEPKG_SHORT_FORBIDDEN, tool)
    else:
        _option_tokens(args, _REPO_ADD_LONG_FORBIDDEN, _REPO_ADD_SHORT_FORBIDDEN, tool)
        positional = [token for token in args if not token.startswith("-")]
        if len(positional) < 2:
            raise _refuse("repo-add-arguments", tool)
    for token in args:
        if token.startswith("/") and not _within(token, root):
            raise _refuse("path-outside-sole-writable-bind", tool)


class GuardedRunner(CommandRunner):
    """Applies the closed ArchARM command policy in front of one SDK role runner.

    The SDK builder role refuses ``repo-add``; the existing builder's per-product
    ``custom.db`` step is therefore dispatched to an SDK repository runner created
    on first use whose sole writable bind is that product's db directory.
    """

    def __init__(self, inner: CommandRunner, *, role: str, root: Path, repository_factory=None) -> None:
        if role not in _ADMITTED_TOOLS:
            raise _refuse("unknown-runner-role")
        self.inner, self.role, self.root = inner, role, Path(root)
        self.repository_factory = repository_factory
        self.repository_runners: dict[str, CommandRunner] = {}

    def which(self, tool_name: str) -> str | None:
        return self.inner.which(tool_name) if tool_name in _ADMITTED_TOOLS[self.role] else None

    def run(self, argv: list[str], *, cwd=None, env=None) -> CommandReceipt:
        admit_command(self.role, self.root, argv, cwd=cwd, env=env)
        if self.role == "builder" and argv[0] == "repo-add":
            if self.repository_factory is None or env:
                raise _refuse("repo-add-runner-unavailable", "repo-add")
            directory = os.path.dirname(os.path.normpath(next(a for a in argv[1:] if not a.startswith("-"))))
            if not _within(directory, self.root) or os.path.realpath(directory) == os.path.realpath(self.root):
                raise _refuse("path-outside-sole-writable-bind", "repo-add")
            runner = self.repository_runners.get(directory)
            if runner is None:
                runner = self.repository_runners[directory] = self.repository_factory(Path(directory))
            return runner.run(list(argv), cwd=cwd)
        return self.inner.run(list(argv), cwd=cwd, env=env)


# --------------------------------------------------------------------------- preflight


def shared_api_gaps(hosted_deb: Any) -> list[str]:
    """Exact missing parent-owned keywords; a VAR_KEYWORD catch-all is not acceptance."""
    gaps = []
    for name, keyword in SHARED_API_KEYWORDS:
        function = getattr(hosted_deb, name, None)
        try:
            parameters = inspect.signature(function).parameters
        except (TypeError, ValueError):
            gaps.append(name)
            continue
        if keyword not in parameters or parameters[keyword].kind not in (
                inspect.Parameter.KEYWORD_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD):
            gaps.append(name + "." + keyword)
    return gaps


def _provider(module: str, attribute: str, code: str):
    try:
        provider = getattr(importlib.import_module(module), attribute)
    except (ImportError, AttributeError):
        raise ContractError(code, "Required current ArchARM peer provider is unavailable",
                            details={"substage": "provider-preflight", "module": module}) from None
    if not callable(provider):
        raise ContractError(code, "Required current ArchARM peer provider is not callable",
                            details={"substage": "provider-preflight", "module": module})
    return provider


def runner_identity() -> tuple[int, int]:
    """Actual nonroot native runner numeric identity; never a username."""
    uid, gid = os.getuid(), os.getgid()
    if (type(uid) is not int or type(gid) is not int
            or not 0 < uid <= MAX_NUMERIC_ID or not 0 < gid <= MAX_NUMERIC_ID):
        raise ContractError("ARCHARM_RUNNER_IDENTITY", "Nonroot runner numeric UID/GID required",
                            details={"substage": "runner-identity"})
    return uid, gid


def _select_sdk_inputs(captures):
    """Select a fixed input identity from the already closed product intents."""
    versions = [intent.get("version") for _, intent, _ in captures
                if intent.get("project", {}).get("id") == NEBULAR]
    if versions == ["0.8.0"]:
        from rs9._archarm_support.successor_20261109 import INPUTS, PROFILE
        return PROFILE, dict(INPUTS)
    if versions == ["0.7.1"]:
        return "historical", dict(QUALIFIED_INPUTS)
    raise ContractError("CONTEXT_INVALID", "No qualified ArchARM input profile for these intents",
                        details={"substage": "context", "reason": "captures"})


def _validate_context(context: Any) -> dict[str, Any]:
    if not isinstance(context, Mapping):
        raise ContractError("CONTEXT_INVALID", "Context must be a mapping")
    generation_paths(context.get("generation"))
    if (context.get("generation") != CURRENT_GENERATION or context.get("family") != FAMILY
            or context.get("system") != SYSTEM):
        raise ContractError("ARCHARM_ROUTE", "Only current pacman/aarch64-linux uses this producer",
                            details={"substage": "route-selection"})
    missing = [key for key in REQUIRED_CONTEXT_KEYS if key not in context]
    if missing:
        raise ContractError("CONTEXT_INVALID", "Current ArchARM producer context incomplete",
                            details={"substage": "context", "reason": "+".join(missing)})
    repository, scratch = context["repository"], context["scratch"]
    if not isinstance(repository, Path) or not repository.is_dir():
        raise ContractError("CONTEXT_INVALID", "Repository must be a directory path", details={"substage": "context"})
    if (not isinstance(scratch, Path) or scratch.is_symlink() or not scratch.is_dir()
            or any(scratch.iterdir())):
        raise ContractError("CONTEXT_INVALID", "A fresh empty owned lane scratch is required",
                            details={"substage": "context", "reason": "lane-scratch"})
    captures = context["captures"]
    if not isinstance(captures, (list, tuple)) or len(captures) != len(REQUIRED_PRODUCTS):
        raise ContractError("CONTEXT_INVALID", "Exactly the four required captures are required",
                            details={"substage": "context", "reason": "captures"})
    ids = []
    for row in captures:
        if not isinstance(row, (list, tuple)) or len(row) != 3 or not isinstance(row[1], Mapping):
            raise ContractError("CONTEXT_INVALID", "Malformed capture row", details={"substage": "context"})
        project = row[1].get("project")
        ids.append(project.get("id") if isinstance(project, Mapping) else None)
    if sorted(ids, key=str) != sorted(REQUIRED_PRODUCTS):
        raise ContractError("CONTEXT_INVALID", "Captures differ from the four required products",
                            details={"substage": "context", "reason": "captures"})
    sdk_input_profile, qualified_inputs = _select_sdk_inputs(captures)
    if context["client"] is None:
        raise ContractError("CONTEXT_INVALID", "Authenticated public client required", details={"substage": "context"})
    binding = context["binding"]
    commit = binding.get("source_commit") if isinstance(binding, Mapping) else None
    if not isinstance(commit, str) or not _HEX40.fullmatch(commit):
        raise ContractError("CONTEXT_INVALID", "Exact source commit required", details={"substage": "context"})
    if not isinstance(context["authentication_sha256"], str) or not _HEX64.fullmatch(context["authentication_sha256"]):
        raise ContractError("CONTEXT_INVALID", "Release authentication digest required", details={"substage": "context"})
    if not isinstance(context["upstream"], Mapping):
        raise ContractError("CONTEXT_INVALID", "Upstream artifact map required", details={"substage": "context"})
    producer = context["producer_provenance"]
    if (not isinstance(producer, Mapping) or producer.get("source_commit") != commit
            or type(producer.get("run_id")) is not int or not 0 < producer["run_id"] < 10 ** 20
            or type(producer.get("attempt")) is not int):
        raise ContractError("CONTEXT_INVALID", "Producer provenance must bind this source commit and run",
                            details={"substage": "context", "reason": "producer-provenance"})
    return {"repository": repository, "scratch": scratch, "captures": list(captures), "commit": commit,
            "run_id": producer["run_id"], "attempt": producer["attempt"],
            "sdk_input_profile": sdk_input_profile, "qualified_inputs": qualified_inputs}


def _authenticate_captures(captures) -> None:
    """Authoritative capture bytes are re-checked before any worker can see staged inputs."""
    from rs9 import release_core
    for capture, _, _ in captures:
        release_core.authenticated_record_hash(capture)


# --------------------------------------------------------------------------- filesystem policy


def _audit_tree(root: Path, *, uid: int, allow_symlinks: bool) -> None:
    """No world-writable, set-id, special or foreign-owned entry under a worker-written tree."""
    def check(path: Path) -> None:
        info = os.lstat(path)
        relative = "." if path == root else path.relative_to(root).as_posix()
        def fail(reason):
            raise ContractError("ARCHARM_OUTPUT_POLICY", "Worker output violates the owned public tree policy",
                                details={"substage": "output-audit", "reason": reason, "target": relative})
        if stat.S_ISLNK(info.st_mode):
            if not allow_symlinks:
                fail("symlink")
            return
        if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
            fail("special-file")
        if info.st_mode & (stat.S_ISUID | stat.S_ISGID):
            fail("set-id")
        if info.st_mode & stat.S_IWOTH:
            fail("world-writable")
        if info.st_uid != uid:
            fail("unexpected-owner")
    check(root)
    for current, directories, files in os.walk(root, followlinks=False):
        for name in [*directories, *files]:
            check(Path(current) / name)


def _regular_file(path: Any, *, uid: int | None = None) -> Path:
    if not isinstance(path, Path):
        raise ContractError("ARCHARM_OUTPUT_POLICY", "Package path must be a Path", details={"substage": "output-audit"})
    info = os.lstat(path)
    if (not stat.S_ISREG(info.st_mode) or info.st_mode & (stat.S_ISUID | stat.S_ISGID | stat.S_IWOTH)
            or (uid is not None and info.st_uid != uid)):
        raise ContractError("ARCHARM_OUTPUT_POLICY", "Package must be an owned non-writable regular file",
                            details={"substage": "output-audit", "target": path.name})
    return path


def _code(error: BaseException) -> str:
    if isinstance(error, ContractError):
        return error.code
    if isinstance(error, OSError):
        return "PACKAGE_FILESYSTEM"
    return type(error).__name__


def _gate(name: str, status: str, reason: str | None = None, **extra: Any) -> dict[str, Any]:
    row: dict[str, Any] = {"name": name, "status": status}
    if reason:
        row["reason"] = reason
    row.update(extra)
    return row


@contextmanager
def _held(manager: Any, record: dict, *, success_status: str, close_only: bool = False):
    """Enter a peer-held handle and always exit it with no exception context.

    Exit failures are recorded instead of replacing the primary failure.
    """
    if hasattr(manager, "__enter__") and hasattr(manager, "__exit__"):
        value = manager.__enter__()
        value = manager if value is None else value
        release = lambda: manager.__exit__(None, None, None)
    elif close_only:
        value = manager
        release = getattr(manager, "close", None)
        release = release if callable(release) else None
    else:
        raise ContractError("ARCHARM_SHARED_API", "Peer handle must be a context manager",
                            details={"substage": "provider-handle"})
    record.clear()
    record.update(status="held")
    try:
        yield value
    finally:
        record.clear()
        if release is None:
            record.update(status=success_status, reason="no-held-handles")
        else:
            try:
                release()
            except Exception as error:  # cleanup never masks the primary result
                record.update(status="fail", reason=_code(error))
            else:
                record.update(status=success_status)


def _lease_records(lease: Any) -> Mapping[str, Any] | None:
    try:
        records = lease.records
    except Exception:  # an unreadable lease is unknown state
        return None
    return records if isinstance(records, Mapping) else None


def _sdk_cleanup_readback(lease: Any) -> dict[str, Any]:
    """Pass needs the lease's own cleanup readback (archarm_sdk ``records``), not a quiet exit."""
    records = _lease_records(lease)
    if records is None:
        return {"status": "fail", "reason": "sdk-cleanup-readback-missing"}
    if records.get("cleanupComplete") is not True or records.get("state") not in ("closed", "failed"):
        return {"status": "fail", "reason": "sdk-cleanup-incomplete-or-retained"}
    count = records.get("hostReceiptCount")
    if type(count) is not int or count <= 0:
        return {"status": "not-run", "reason": "synthetic-command-seam"}
    return {"status": "pass"}


def _validate_lease(lease: Any, uid: int, gid: int, expected_inputs=QUALIFIED_INPUTS) -> tuple[Mapping[str, Any], bool]:
    """Typed lease identity plus its closed ready readback; returns (records, executed)."""
    image = getattr(lease, "image", None)
    if (getattr(lease, "platform", None) != PLATFORM or getattr(lease, "uid", None) != uid
            or getattr(lease, "gid", None) != gid or not isinstance(image, str) or not image
            or any(c.isspace() for c in image)
            or not all(callable(getattr(lease, name, None)) for name in ("builder_runner", "repository_runner", "client"))):
        raise ContractError("ARCHARM_SDK_LEASE", "SDK lease differs from the verified runner identity or API",
                            details={"substage": "sdk-lease"})
    records = _lease_records(lease)
    flags = records.get("flags") if records is not None else None
    assertions = records.get("assertions") if records is not None else None
    identity = records.get("identity") if records is not None else None
    digests = records.get("digests") if records is not None else None
    expected_digests = {"rootfsSha256": expected_inputs["rootfs_sha256"],
                        "rootfsPinSha256": expected_inputs["rootfs_pin_sha256"],
                        "packagePinsSha256": expected_inputs["package_pins_sha256"]}
    if (records is None or records.get("state") != "ready" or records.get("platform") != PLATFORM
            or records.get("generation") != CURRENT_GENERATION
            or records.get("pinsMatchQualifiedOrigin") is not True
            or not isinstance(digests, Mapping)
            or any(digests.get(k) != v for k, v in expected_digests.items())
            or not isinstance(flags, Mapping) or not flags or not all(v is True for v in flags.values())
            or not isinstance(assertions, Mapping) or any(assertions.get(k) is not False for k in SDK_ASSERTIONS_FALSE)
            or not isinstance(identity, Mapping) or (identity.get("uid"), identity.get("gid")) != (uid, gid)):
        raise ContractError("ARCHARM_SDK_LEASE", "SDK lease readback is not the exact qualified ready origin",
                            details={"substage": "sdk-lease-readback"})
    count = records.get("hostReceiptCount")
    return records, type(count) is int and count > 0


# --------------------------------------------------------------------------- producer


class _Blocked(Exception):
    """Internal stop after a gate has already been recorded as not passing."""


class _ArmProducer:
    def __init__(self, context, inputs, hosted_deb, uid, gid):
        self.context, self.hd = context, hosted_deb
        self.repository, self.scratch = inputs["repository"], inputs["scratch"]
        self.captures, self.commit = inputs["captures"], inputs["commit"]
        self.run_id, self.attempt = inputs["run_id"], inputs["attempt"]
        self.sdk_input_profile = inputs["sdk_input_profile"]
        self.qualified_inputs = inputs["qualified_inputs"]
        self.client = context["client"]
        self.any_token = None
        self.sdk_manager = None
        self.uid, self.gid = uid, gid
        self.host = hosted_deb.RecordingRunner(context.get("runner") or SubprocessRunner(timeout=1800))
        self.intents = {intent["project"]["id"]: intent for _, intent, _ in self.captures}
        self.capture_of = {intent["project"]["id"]: capture for capture, intent, _ in self.captures}
        self.order = [intent["project"]["id"] for _, intent, _ in self.captures]
        self.gates: dict[str, dict | None] = {name: None for name in REQUIRED_GATES}
        self.blocked_by: str | None = None
        self.extra: list[dict] = []
        self.artifacts: list[Path] = []
        self.products: dict[str, dict] = {}
        self.unsigned: dict[str, Path] = {}
        self.replicas: dict[str, Path] = {}
        self.replica_sha256: dict[str, str] = {}
        self.any_record: dict | None = None
        self.build_errors: dict[str, str] = {}
        self.product_failures: dict[str, dict] = {}
        self.secondary: list[dict] = []
        self.failure: dict | None = None
        self.lease = None
        self._builders: dict[str, Any] = {}
        self.client_ran = False
        self.client_rows: list[dict] = []
        self.stage = "canonical-any"
        self.cleanup = {"canonical_any": {"status": "not-run", "reason": "token-not-acquired"},
                        "sdk": {"status": "not-run", "reason": "sdk-not-acquired"},
                        "fixture": {"status": "not-run", "reason": "fixture-not-created"}}
        self.environment = {
            "schema": ENVIRONMENT_SCHEMA, "generation": CURRENT_GENERATION, "family": FAMILY, "system": SYSTEM,
            "architecture": ARCHITECTURE, "platform": None, "image": None,
            "runner_identity": {"uid": uid, "gid": gid}, "sdk_records_sha256": None,
            "qualified_inputs": dict(self.qualified_inputs), "profiles": REQUESTED_PROFILES,
            "provider_policy": PROVIDER_POLICY, "canonical_any_witness_sha256": None, "cleanup": {}}

    # ---- bookkeeping

    def _fresh_dir(self, relative: str, mode: int) -> Path:
        path = self.scratch / relative
        path.mkdir()
        os.chmod(path, mode)
        return path

    def _set(self, name: str, status: str, reason: str | None = None, **extra: Any) -> None:
        self.gates[name] = _gate(name, status, reason, **extra)
        if status != "pass" and self.blocked_by is None:
            self.blocked_by = name

    def _fail_stage(self, error: BaseException) -> None:
        gate = STAGE_GATES[self.stage]
        code = _code(error)
        row = self.gates.get(gate)
        if row is None or row["status"] == "pass":
            self._set(gate, "fail", code, causal_substage=self.stage)
        causal = dict(error.details) if isinstance(error, ContractError) else {}
        self.failure = {"code": code, "causal_substage": self.stage, **safe_details(causal)}

    # ---- stages

    def _canonical_any(self, stack: ExitStack, acquire_any) -> None:
        self.stage = "canonical-any"
        acquire, reader_type = acquire_any
        # The importer's worker output is the fresh, still-empty lane scratch, so its
        # held copies land at lane-work/canonical-any/files exactly as its witness says.
        handle = acquire(self.context, reader_type(self.repository), self.scratch)
        token = stack.enter_context(_held(handle, self.cleanup["canonical_any"], success_status="pass",
                                          close_only=True))
        self.any_token = token
        if isinstance(token, Mapping) or token is None:
            raise ContractError("CANONICAL_ANY_TOKEN", "A held canonical-any token is required, not serialized data",
                                details={"substage": "canonical-any-token"})
        files, witness_record = getattr(token, "files", None), getattr(token, "witness_record", None)
        if not isinstance(files, Mapping) or set(files) != set(IMPORTED_ANY_PRODUCTS) or not callable(witness_record):
            raise ContractError("CANONICAL_ANY_TOKEN", "Canonical-any token must map exactly Loom and Solar",
                                details={"substage": "canonical-any-token"})
        raw = witness_record()
        try:
            document = json.loads(raw) if isinstance(raw, (bytes, bytearray)) else None
        except ValueError:
            document = None
        if (not isinstance(document, dict) or canonical(document) != bytes(raw)
                or document.get("role") != WITNESS_ROLE
                or document.get("construction_authority") != CONSTRUCTION_AUTHORITY
                or not isinstance(document.get("files"), dict)
                or set(document["files"]) != set(IMPORTED_ANY_PRODUCTS)):
            raise ContractError("CANONICAL_ANY_WITNESS", "Closed canonical reuse witness bytes required",
                                details={"substage": "canonical-any-witness"})
        raw = bytes(raw)
        text = raw.decode("utf-8")
        from rs9.security import scan_for_credentials
        scan_for_credentials(text)
        markers = {str(path) for path in (self.scratch, self.repository, Path.home()) if len(str(path)) > 1}
        if any(marker in text for marker in markers):
            raise ContractError("CANONICAL_ANY_WITNESS", "Witness must not carry host paths",
                                details={"substage": "canonical-any-witness", "reason": "host-path"})
        replicas_dir = self.scratch / REUSE_DIRECTORY / "files"
        replicas = {}
        for pid in IMPORTED_ANY_PRODUCTS:
            source = _regular_file(files[pid])
            if source.parent != replicas_dir:
                raise ContractError("CANONICAL_ANY_TOKEN", "Imported replica is outside the worker output",
                                    details={"substage": "canonical-any-token", "product": pid})
            version = self.intents[pid]["version"]
            if not re.fullmatch(re.escape(pid) + "-" + re.escape(version) + r"-[1-9][0-9]*-any\.pkg\.tar\.zst",
                                source.name):
                raise ContractError("CANONICAL_ANY_TOKEN", "Imported any package identity differs from the capture",
                                    details={"substage": "canonical-any-token", "product": pid})
            data = source.read_bytes()
            sha = digest(data)
            entry = document["files"][pid]
            if (sha not in text or not isinstance(entry, dict) or entry.get("sha256") != sha
                    or entry.get("name") != source.name or entry.get("size") != len(data)):
                raise ContractError("CANONICAL_ANY_WITNESS", "Witness does not bind the exact imported bytes",
                                    details={"substage": "canonical-any-witness", "product": pid})
            self.replicas[pid], self.replica_sha256[pid] = source, sha
            replicas[pid] = {"file": REUSE_DIRECTORY + "/files/" + source.name, "sha256": sha, "size": len(data)}
            self.products[pid] = {"package_class": "pure-js-cli", "architecture": "any", "package_file": source.name,
                                  "sha256": sha, "role": "canonical-any-reuse-replica",
                                  "construction_authority": CONSTRUCTION_AUTHORITY}
        witness_path = self.scratch / WITNESS_FILE
        witness_path.write_bytes(raw)
        os.chmod(witness_path, 0o644)
        self.artifacts.extend([*self.replicas.values(), witness_path])
        self.any_record = {"role": WITNESS_ROLE, "construction_on_this_lane": False,
                           "construction_authority": {"family": FAMILY, "system": CANONICAL_ANY_SYSTEM},
                           "witness_file": WITNESS_FILE, "witness_sha256": digest(raw), "replicas": replicas}
        self.environment["canonical_any_witness_sha256"] = digest(raw)

    def _sdk(self, stack: ExitStack, acquire_sdk) -> None:
        self.stage = "sdk"
        mark = self.host.mark()
        self.cleanup["sdk"] = {"status": "fail", "reason": "sdk-acquisition-failed-cleanup-unproven"}
        # Closed archarm_sdk context: the workspace must not exist yet; fixture homes
        # are declared private so no worker bind can ever overlap them.
        sdk_context = {"runId": str(self.run_id), "runAttempt": self.attempt, "sourceSha": self.commit,
                       "generation": CURRENT_GENERATION,
                       "privateRoots": [str(self.scratch / name) for name in PRIVATE_FIXTURE_HOMES]}
        manager = acquire_sdk(host=self.host, workspace=self.scratch / SDK_WORKSPACE, context=sdk_context,
                              uid=self.uid, gid=self.gid, input_profile=self.sdk_input_profile)
        self.sdk_manager = manager
        self.lease = stack.enter_context(_held(manager, self.cleanup["sdk"], success_status="exited"))
        records, executed = _validate_lease(self.lease, self.uid, self.gid, self.qualified_inputs)
        try:
            records_sha256 = digest(canonical(records))
        except (TypeError, ValueError, ContractError):
            records_sha256 = None
        self.environment.update(platform=self.lease.platform, image=self.lease.image, sdk_records_sha256=records_sha256)
        if executed and all(receipt.executed for receipt in self.host.receipts[mark:]):
            self._set(ENV_GATE, "pass")
        else:
            self._set(ENV_GATE, "not-run", "synthetic-command-seam")
            raise _Blocked()

    def _build_one(self, capture, intent) -> bool:
        from rs9 import build_pacman, npm_deps
        from rs9.product_classes import get_product_class
        pid, version = intent["project"]["id"], intent["version"]
        work = self.scratch / "build" / pid
        work.mkdir()
        os.chmod(work, 0o755)
        npm_dir = self.scratch / "npm-input" / pid
        npm_dir.mkdir()
        os.chmod(npm_dir, 0o700)
        npm = npm_deps.resolve_offline_npm_archives(capture, pid, npm_dir, None, self.client)
        builder = self.hd.RecordingRunner(GuardedRunner(
            self.lease.builder_runner(work, ()), role="builder", root=work,
            repository_factory=lambda directory: GuardedRunner(self.lease.repository_runner(directory),
                                                               role="repository", root=directory)))
        self._builders[pid] = builder
        mark = builder.mark()
        kwargs: dict[str, Any] = {"offline_npm_archives": npm, "runner": builder, "generation": CURRENT_GENERATION}
        try:
            if "builder_system" in inspect.signature(build_pacman.build_pacman_candidate).parameters:
                kwargs["builder_system"] = SYSTEM
        except (TypeError, ValueError):
            pass
        result = build_pacman.build_pacman_candidate(capture, intent, ARCHITECTURE, work, **kwargs)
        if not isinstance(result, Mapping) or not isinstance(result.get("manifest"), Mapping):
            raise ContractError("BUILD_FAILED", "Builder returned no manifest", details={"substage": "package-build"})
        manifest = result["manifest"]
        package = _regular_file(result.get("package_path"), uid=self.uid)
        if not _within(package, work) or package.name != f"{pid}-{version}-1-{ARCHITECTURE}.pkg.tar.zst":
            raise ContractError("BUILD_FAILED", "Native package identity or location differs",
                                details={"substage": "package-output", "product": pid})
        data = package.read_bytes()
        if (manifest.get("project") != pid or manifest.get("architecture") != ARCHITECTURE
                or manifest.get("version") != version or manifest.get("package_sha256") != digest(data)
                or manifest.get("package_size") != len(data)):
            raise ContractError("BUILD_FAILED", "Native build manifest differs from the produced bytes",
                                details={"substage": "package-output", "product": pid})
        _audit_tree(work, uid=self.uid, allow_symlinks=True)
        destination = self.scratch / "unsigned" / package.name
        destination.write_bytes(data)
        os.chmod(destination, 0o644)
        self.unsigned[pid] = destination
        self.products[pid] = {"package_class": get_product_class(pid), "architecture": ARCHITECTURE,
                              "package_file": destination.name, "sha256": digest(data),
                              "role": "native-construction"}
        self.artifacts.extend([destination, work / "pacman-manifest.json"])
        return builder.real_since(mark)

    def _build(self) -> None:
        self.stage = "package-build"
        self._fresh_dir("unsigned", 0o755)
        self._fresh_dir("build", 0o755)
        self._fresh_dir("npm-input", 0o700)
        real = True
        for pid in [p for p in self.order if p in NATIVE_PRODUCTS]:
            try:
                real = self._build_one(self.capture_of[pid], self.intents[pid]) and real
            except (ContractError, OSError) as error:
                code = _code(error)
                self.build_errors[pid] = code
                details = {"product": pid, "family": FAMILY, "system": SYSTEM, "substage": "package-build"}
                builder = self._builders.get(pid)
                failed = next((r for r in reversed(builder.receipts) if r.exit_code), None) if builder else None
                if failed is not None:
                    details.update(tool=Path(failed.tool_name or failed.command[0]).name, exit_code=failed.exit_code,
                                   stdout_sha256=failed.stdout_sha256, stderr_sha256=failed.stderr_sha256)
                if isinstance(error, ContractError):
                    details.update(error.details)
                self.product_failures[pid] = {"code": code, **safe_details(details)}
        if self.build_errors:
            self._set(BUILD_GATE, "fail", "native-build-failed", products=sorted(self.build_errors))
            self.failure = {"code": "NATIVE_BUILD", "causal_substage": "package-build"}
            try:
                diagnostics = self.scratch / "diagnostics"
                diagnostics.mkdir(exist_ok=True)
                record = diagnostics / "build-errors.json"
                record.write_bytes(canonical({"schema": "rs9.build-errors.v1alpha1", "family": FAMILY,
                                              "system": SYSTEM, "errors": self.build_errors,
                                              "product_failures": self.product_failures}))
                self.artifacts.append(record)
            except OSError as secondary:
                self.secondary.append({"operation": "build-error-record", "code": _code(secondary)})
            raise _Blocked()
        if not real:
            self._set(BUILD_GATE, "not-run", "synthetic-command-seam")
            raise _Blocked()
        self._set(BUILD_GATE, "pass")

    def _custody(self) -> None:
        self.stage = "custody"
        from rs9.pages_candidate import write_custody_bundle
        bundle = self._fresh_dir("unsigned-custody", 0o755)
        # Construction custody holds only this lane's native constructions; the
        # imported any replicas are reuse witnesses, never a second provider.
        write_custody_bundle(bundle, packages={path.name: path.read_bytes() for path in self.unsigned.values()},
                             family=FAMILY, system=SYSTEM,
                             authentication_sha256=self.context["authentication_sha256"], source_commit=self.commit)
        self.artifacts.extend(sorted(p for p in bundle.rglob("*") if p.is_file() and not p.is_symlink()))

    @contextmanager
    def _fixture_pair(self):
        from rs9 import signing_fixture
        record = self.cleanup["fixture"]
        homes = {"fixture": self._fresh_dir("fixture", 0o700), "wrong": self._fresh_dir("fixture-wrong", 0o700)}
        record.clear()
        record.update(status="open")
        opened: dict[str, Any] = {}
        try:
            opened["fixture"] = signing_fixture.SigningFixture(scratch_dir=homes["fixture"], user_id=FIXTURE_USER_ID)
            opened["wrong"] = signing_fixture.SigningFixture(scratch_dir=homes["wrong"], user_id=WRONG_USER_ID)
            if opened["wrong"].primary_fingerprint == opened["fixture"].primary_fingerprint:
                raise ContractError("FIXTURE_IDENTITY", "A distinct wrong-key fixture is required",
                                    details={"substage": "fixture-preparation"})
            yield opened["fixture"], opened["wrong"]
        finally:
            closed = self._close_fixtures(opened, homes)
            record.clear()
            record.update(closed)

    def _close_fixtures(self, opened: Mapping[str, Any], homes: Mapping[str, Path]) -> dict[str, Any]:
        gpg = next((fx.gpg for fx in opened.values() if isinstance(getattr(fx, "gpg", None), str)), None)
        if gpg is None:
            from rs9 import signing_fixture
            gpg = signing_fixture.find_gpg_binary()
        gpgconf = Path(gpg).resolve().parent / "gpgconf" if gpg else None
        roles: dict[str, dict] = {}
        for role, home in homes.items():
            row: dict[str, Any] = {}
            fixture = opened.get(role)
            if fixture is not None:
                try:
                    fixture.close()
                except Exception as error:
                    row["close"] = _code(error)
            row.update(self._quiescence(gpgconf, home))
            if "close" in row:
                row["status"] = "fail"
            roles[role] = row
        passed = all(row["status"] == "pass" for row in roles.values())
        removed = False
        if passed:
            try:
                for home in homes.values():
                    shutil.rmtree(home)
                removed = True
            except OSError as error:
                passed = False
                self.secondary.append({"operation": "fixture-private-state-removal", "code": _code(error)})
        return {"status": "pass" if passed else "fail", "roles": roles, "private_state_removed": removed}

    def _quiescence(self, gpgconf: Path | None, home: Path) -> dict[str, Any]:
        """Track the owned agent/dirmngr scope; unknown state is failure."""
        if gpgconf is None or not gpgconf.is_file():
            return {"status": "fail", "reason": "gpgconf-unavailable"}
        try:
            killed = self.host.run([str(gpgconf), "--homedir", str(home), "--kill", "all"])
            listed = self.host.run([str(gpgconf), "--homedir", str(home), "--list-dirs", "socketdir"])
        except (ContractError, OSError) as error:
            return {"status": "fail", "reason": "cleanup-command-" + _code(error).lower().replace("_", "-")}
        if not (killed.executed and listed.executed):
            return {"status": "fail", "reason": "cleanup-not-executed"}
        if killed.exit_code or listed.exit_code:
            return {"status": "fail", "reason": "cleanup-command-failed"}
        lines = listed.stdout_text.strip().splitlines()
        if len(lines) != 1 or not lines[0].startswith("/"):
            return {"status": "fail", "reason": "socketdir-unknown"}
        scopes = {home, Path(unquote(lines[0]))}
        for attempt in range(QUIESCENCE_POLLS):
            try:
                lingering = [entry for scope in scopes if scope.is_dir() for entry in scope.iterdir()
                             if entry.name.startswith("S.")]
            except OSError:
                return {"status": "fail", "reason": "socketdir-unreadable"}
            if not lingering:
                return {"status": "pass"}
            if attempt + 1 < QUIESCENCE_POLLS:
                time.sleep(QUIESCENCE_INTERVAL_SECONDS)
        return {"status": "fail", "reason": "lingering-agent-socket"}

    def _qualify(self, stack: ExitStack) -> None:
        from rs9 import hosted_smoke
        from rs9.hosted_packaging import write_keys
        self.stage = "fixture-preparation"
        fixture, wrong = stack.enter_context(self._fixture_pair())
        (self.scratch / "fixture-identity.json").write_bytes(canonical({
            "used": True, "production": False, "purpose": "NON-PRODUCTION CANDIDATE TEST ONLY",
            "fingerprint": fixture.primary_fingerprint, "wrong_key_fingerprint": wrong.primary_fingerprint}))
        keys = self._fresh_dir("keys", 0o755)
        write_keys(keys, fixture)
        for path in keys.iterdir():
            os.chmod(path, 0o644)

        self.stage = "package-signing"
        repo = self._fresh_dir(FAMILY, 0o755)
        directory = repo / ARCHITECTURE
        directory.mkdir()
        os.chmod(directory, 0o755)
        packages = []
        for pid in self.order:
            source = self.unsigned.get(pid) or self.replicas[pid]
            copy = directory / source.name
            copy.write_bytes(source.read_bytes())
            os.chmod(copy, 0o644)
            packages.append(copy)
        for package in packages:
            self._detach_sign(fixture, package)

        self.stage = "repository-metadata"
        runner = self.hd.RecordingRunner(GuardedRunner(self.lease.repository_runner(repo), role="repository", root=repo))
        receipt = runner.run(["repo-add", str(directory / "rs9.db.tar.gz"), *[str(p) for p in sorted(packages)]])
        if receipt.exit_code:
            raise ContractError("NATIVE_TOOL", "Actual native command failed: repo-add",
                                details={"substage": "repository-metadata", "tool": "repo-add",
                                         "exit_code": receipt.exit_code, "stdout_sha256": receipt.stdout_sha256,
                                         "stderr_sha256": receipt.stderr_sha256})
        for suffix in ("db", "files"):
            archive = _regular_file(directory / ("rs9." + suffix + ".tar.gz"), uid=self.uid)
            link = directory / ("rs9." + suffix)
            if link.is_symlink():
                link.unlink()
            link.write_bytes(archive.read_bytes())
            os.chmod(link, 0o644)
            for name in (link, archive):
                self._detach_sign(fixture, name)
        _audit_tree(repo, uid=self.uid, allow_symlinks=False)
        self._verify_unchanged(held=True)
        if receipt.executed and runner.real_since(0):
            self._set(INDEX_GATE, "pass")
        else:
            self._set(INDEX_GATE, "not-run", "synthetic-command-seam")

        self.stage = "client-preparation"
        fingerprint = fixture.primary_fingerprint
        spec_for = lambda dirs: self.hd.pacman_spec(dirs[FAMILY], keys, fingerprint, architecture=ARCHITECTURE)
        spec = spec_for({FAMILY: repo})
        prepared = hosted_smoke.prepare_smoke(self.capture_of[NEBULAR], self.captures, self.client,
                                              self.scratch / "application-smoke")
        burst_record = self.hd._burst_release_record(self.captures, SYSTEM)

        self.stage = "client-cycle"
        self.client_ran = True
        rows, evidence = self.hd.client_cycle(
            self.host, spec, image=self.lease.image, platform=self.lease.platform, generation=CURRENT_GENERATION,
            products=list(self.order), repository=self.repository, prefix=FAMILY + "-client", smoke=prepared,
            system=SYSTEM, burst_record=burst_record, burst_scratch=self.scratch / "burst-native-probe",
            sdk_lease=self.lease)
        self.client_rows = list(rows)
        self.extra.extend(rows)

        self.stage = "tamper-cycle"
        tamper_work = self._fresh_dir("tamper", 0o755)
        tamper_rows = self.hd.tamper_cycle(
            self.host, spec_for, FAMILY, {FAMILY: repo}, image=self.lease.image, platform=self.lease.platform,
            product=self.order[0], work=tamper_work, wrong_signer=wrong, arch=ARCHITECTURE, kinds=TAMPER_KINDS,
            prefix=FAMILY + "-trust", positive_control=evidence.get(self.order[0], {}).get("positive_control"),
            sdk_lease=self.lease)
        self.extra.extend(tamper_rows)
        folded = self.hd._fold([*rows, *tamper_rows])
        self._set(CLIENT_GATE, folded, None if folded == "pass" else "client-or-tamper-row-not-passing")

        self.stage = "qualification-record"
        self.artifacts.extend(p for p in [*sorted(repo.rglob("*")), *sorted(keys.rglob("*"))]
                              if p.is_file() and not p.is_symlink())
        manifest = self.scratch / "native-qualification.json"
        manifest.write_bytes(canonical({
            "schema": "rs9.native-hosted.v1alpha1", "production": False, "environment": self.environment,
            "fixture_fingerprint": fingerprint, "products": self.products, "client": evidence,
            "canonical_any_reuse": self.any_record, "build_errors": self.build_errors}))
        self.artifacts.append(manifest)

    def _detach_sign(self, fixture, path: Path) -> None:
        data = path.read_bytes()
        signature = path.with_name(path.name + ".sig")
        signature.write_bytes(fixture.detach_sign(data, armor=False))
        os.chmod(signature, 0o644)
        fixture.verify(data, signature.read_bytes())

    def _verify_unchanged(self, *, held: bool = False) -> None:
        if held and self.any_token is not None and callable(getattr(self.any_token, "verify", None)):
            try:
                self.any_token.verify()  # held fd/inode/byte identity of the importer copies
            except ContractError as error:
                raise ContractError("CUSTODY_HASH", "Canonical any reuse replica changed",
                                    details={"substage": "canonical-any-replica", "causal_code": error.code}) from None
        for pid, path in self.unsigned.items():
            if path.is_symlink() or digest(path.read_bytes()) != self.products[pid]["sha256"]:
                raise ContractError("CUSTODY_HASH", "Unsigned native candidate changed during fixture operations",
                                    details={"substage": "unsigned-custody-verification", "product": pid})
        for pid, path in self.replicas.items():
            if path.is_symlink() or digest(path.read_bytes()) != self.replica_sha256[pid]:
                raise ContractError("CUSTODY_HASH", "Canonical any reuse replica changed",
                                    details={"substage": "canonical-any-replica", "product": pid})

    # ---- result

    def run(self, acquire_sdk, acquire_any) -> dict[str, Any]:
        unexpected = None
        try:
            with ExitStack() as stack:
                self._canonical_any(stack, acquire_any)
                self._sdk(stack, acquire_sdk)
                self._build()
                self._custody()
                self._qualify(stack)
        except _Blocked:
            pass
        except (ContractError, OSError) as error:
            self._fail_stage(error)
        except Exception as error:  # retained, then re-raised with partial evidence
            self._fail_stage(error)
            unexpected = error
        self._finalize()
        result = self._result()
        if unexpected is not None:
            unexpected.partial_result = result
            raise unexpected
        return result

    def _finalize(self) -> None:
        if self.any_record is not None:
            try:
                self._verify_unchanged()
            except ContractError as error:
                self._set(ANY_GATE, "fail", error.code)
                self.secondary.append({"operation": "final-custody-verification", "code": error.code})
            if self.gates[ANY_GATE] is None:
                if self.cleanup["canonical_any"]["status"] == "fail":
                    self._set(ANY_GATE, "fail", "canonical-any-release-failed")
                else:
                    self._set(ANY_GATE, "pass")
        if self.lease is not None and self.cleanup["sdk"].get("status") == "exited":
            self.cleanup["sdk"] = _sdk_cleanup_readback(self.lease)
        elif self.lease is None and self.sdk_manager is not None:
            # Entry failed: the lease cleans itself; pass only on its own complete readback.
            readback = _sdk_cleanup_readback(self.sdk_manager)
            self.cleanup["sdk"] = readback if readback["status"] != "not-run" else {
                "status": "fail", "reason": "sdk-acquisition-failed-cleanup-unproven"}
        sdk_status = self.cleanup["sdk"]["status"]
        fixture_status = self.cleanup["fixture"]["status"]
        statuses = [sdk_status] + ([fixture_status] if fixture_status != "not-run" else [])
        if sdk_status == "not-run" and self.cleanup["sdk"].get("reason") == "sdk-not-acquired":
            pass  # never acquired: blocked below
        elif "fail" in statuses:
            self._set(CLEANUP_GATE, "fail", "owned-cleanup-failed-or-unproven")
        elif all(status == "pass" for status in statuses):
            self._set(CLEANUP_GATE, "pass")
        else:
            self._set(CLEANUP_GATE, "not-run", "synthetic-command-seam")
        if self.client_ran:
            for row in self.hd.burst_client_gates(self.client_rows):
                if row["name"] in self.gates and self.gates[row["name"]] is None:
                    self._set(row["name"], row["status"], row.get("reason"))
        reason = "blocked-by:" + (self.blocked_by or "unknown")
        for name in REQUIRED_GATES:
            if self.gates[name] is None:
                self.gates[name] = _gate(name, "not-run", reason)
        self.environment["cleanup"] = {key: value["status"] for key, value in self.cleanup.items()}
        if set(self.environment) != ENVIRONMENT_KEYS:
            raise ContractError("ARCHARM_ENVIRONMENT_SCHEMA", "Environment record outside its closed schema")

    def _result(self) -> dict[str, Any]:
        names = set(REQUIRED_GATES)
        gates = [self.gates[name] for name in REQUIRED_GATES] + [row for row in self.extra if row["name"] not in names]
        artifacts, seen = [], set()
        for path in self.artifacts:
            if path not in seen and path.is_file() and not path.is_symlink():
                seen.add(path)
                artifacts.append(path)
        details = {"schema": DETAILS_SCHEMA, "environment": self.environment,
                   "canonical_any_reuse": self.any_record, "products": self.products,
                   "build_errors": self.build_errors, "product_failures": self.product_failures,
                   "operation_failure": self.failure, "cleanup_evidence": self.cleanup,
                   "secondary_diagnostics": self.secondary}
        return {"gates": gates, "artifacts": artifacts, "details": details, "production_promotion_blockers": []}


def execute(context: Mapping[str, Any]) -> dict[str, Any]:
    """Current pacman/aarch64-linux producer; refuses every other route."""
    inputs = _validate_context(context)
    from rs9 import hosted_deb
    gaps = shared_api_gaps(hosted_deb)
    if gaps:
        raise ContractError("ARCHARM_SHARED_API", "Required parent-owned shared keyword is absent",
                            details={"substage": "shared-api-preflight", "reason": "+".join(sorted(gaps))})
    acquire_sdk = _provider("rs9.archarm_sdk", "acquire_sdk", "ARCHARM_SDK_UNAVAILABLE")
    acquire_any = (_provider("rs9.current_pacman_any", "acquire_canonical_any", "CANONICAL_ANY_UNAVAILABLE"),
                   _provider("rs9.current_pacman_any", "ActionsArtifactReader", "CANONICAL_ANY_UNAVAILABLE"))
    uid, gid = runner_identity()
    _authenticate_captures(inputs["captures"])
    return _ArmProducer(context, inputs, hosted_deb, uid, gid).run(acquire_sdk, acquire_any)
