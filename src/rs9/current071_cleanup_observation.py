"""Authenticated current071 APT scratch cleanup retries and closed error observation."""
from __future__ import annotations

from collections.abc import Mapping
import json
import os
from pathlib import Path
import re
import stat

from rs9.current_os071 import (
    CURRENT071_COMMIT,
    CURRENT071_REPLAY_PROGRESS_PROFILE,
    CURRENT071_TREE,
)
from rs9.errors import ContractError
from rs9.hosted_smoke import verify_execution_source_readback
from rs9.release_core import digest
from rs9.smoke_source_envelope import (
    GENERATION as CURRENT_SMOKE_GENERATION,
    verify_checkout,
)

CURRENT071_CLEANUP_OBSERVATION_SCHEMA = "rs9.current071-cleanup-observation.v1alpha2"
CURRENT071_LEGACY_CLEANUP_OBSERVATION_SCHEMA = "rs9.current071-cleanup-observation.v1alpha1"
CURRENT071_CLEANUP_OBSERVER_ID = "current071-apt-cleanup-rm-sync-rewalk-v1"
CURRENT071_BUILTIN_RETRY_CLEANUP_OBSERVER_ID = "current071-apt-cleanup-rm-sync-retry-v1"
CURRENT071_LEGACY_CLEANUP_OBSERVER_ID = "current071-apt-cleanup-rm-sync-v1"
CURRENT071_CLEANUP_POLICY_ID = "rs9.runner-policy.current071-apt-cleanup-rewalk.v1alpha1"
CURRENT071_CLEANUP_OBSERVER_FILENAME = "current071-cleanup-observer.mjs"
CURRENT071_CLEANUP_MARKER_PREFIX = "RS9_CURRENT071_CLEANUP_ERRNO="
CURRENT071_REWALK_MARKER_PREFIX = "RS9_CURRENT071_CLEANUP_REWALK="
CURRENT071_REWALK_OUTCOMES = frozenset({
    "ineligible", "identity-lost-after-1", "identity-lost-after-2",
    "identity-lost-after-3", "exhausted-4", "nonretryable-after-1",
    "nonretryable-after-2", "nonretryable-after-3", "nonretryable-after-4",
    "unclassified",
})
CURRENT071_CLEANUP_MAX_STDERR_BYTES = 64 * 1024

CURRENT071_NATIVE_RC_SMOKE_PIN = {
    "blob": "cbf6a2148c11ed1516ba5d7fc2d4dd32dee3ee9f",
    "sha256": "874355e36496884e55a6e4dae6986ecde817d20863bb3fe26d1b1b5a1d283e69",
    "size": 30732,
}
CURRENT071_CLOSURE_MODULE_NAMES = frozenset(CURRENT071_REPLAY_PROGRESS_PROFILE["modules"].keys())

CURRENT071_CLEANUP_ALLOWED_SYSTEMS = {
    "aarch64-linux": ("linux-arm64", ("B",)),
    "x86_64-linux": ("linux-x64", ("C", "C-signal")),
}
CURRENT071_CLEANUP_SYSTEM_BINDINGS = frozenset({
    ("aarch64-linux", "linux-arm64", "B"),
    ("x86_64-linux", "linux-x64", "C"),
    ("x86_64-linux", "linux-x64", "C-signal"),
})
CURRENT071_CLEANUP_ERRNO_CODES = frozenset({
    "EACCES",
    "EPERM",
    "ENOTEMPTY",
    "EBUSY",
    "ENOENT",
    "EEXIST",
    "ENOTDIR",
    "EISDIR",
    "ELOOP",
    "EMLINK",
    "ENOSPC",
    "EROFS",
    "EIO",
    "EMFILE",
    "ENFILE",
    "EXDEV",
    "ENAMETOOLONG",
    "EBADF",
    "EINVAL",
    "OTHER",
})
CURRENT071_CLEANUP_STATUSES = frozenset({
    "cleanup-error-observed",
    "no-cleanup-error-observed",
    "withheld",
})
CURRENT071_CLEANUP_WITHHELD_REASONS = frozenset({
    "incomplete-stream",
    "invalid-marker",
    "multiple-markers",
    "invalid-observation",
    "binding-mismatch",
})
_LEGACY_CLEANUP_OBSERVATION_KEYS = frozenset({
    "schema",
    "observer_id",
    "family",
    "system",
    "scenario",
    "stderr_bytes",
    "stderr_sha256",
    "status",
    "errno_code",
    "marker_count",
    "withheld_reason",
})
_CLEANUP_OBSERVATION_KEYS = _LEGACY_CLEANUP_OBSERVATION_KEYS | {"rewalk_outcome"}
_EMPTY_SHA256 = digest(b"")
_SHA256_RE = re.compile(r"[0-9a-f]{64}")

_OBSERVER_TEMPLATE = """import { createHash } from "node:crypto";
import fs from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const EXPECTED_PROFILE = Object.freeze(__EXPECTED_PROFILE_JSON__);
const HARDCODED_HARNESS_PIN = Object.freeze({
  blob: "cbf6a2148c11ed1516ba5d7fc2d4dd32dee3ee9f",
  sha256: "874355e36496884e55a6e4dae6986ecde817d20863bb3fe26d1b1b5a1d283e69",
  size: 30732,
});

const ALLOWED_BINDINGS = new Set(["linux-arm64:B", "linux-x64:C", "linux-x64:C-signal"]);
const ALLOWED_ERRNO_CODES = new Set([
  "EACCES",
  "EPERM",
  "ENOTEMPTY",
  "EBUSY",
  "ENOENT",
  "EEXIST",
  "ENOTDIR",
  "EISDIR",
  "ELOOP",
  "EMLINK",
  "ENOSPC",
  "EROFS",
  "EIO",
  "EMFILE",
  "ENFILE",
  "EXDEV",
  "ENAMETOOLONG",
  "EBADF",
  "EINVAL",
]);

const originalRmSync = fs.rmSync;
const originalLstatSync = fs.lstatSync;
const originalRealpathSync = fs.realpathSync;
const originalOpenSync = fs.openSync;
const originalFstatSync = fs.fstatSync;
const originalReadFileSync = fs.readFileSync;
const originalCloseSync = fs.closeSync;

function refuse() {
  process.stderr.write("current071 cleanup observer refused unauthenticated target\\n");
  process.exit(2);
}

function readRegularVerified(filePath, expectedPin) {
  if (!expectedPin || typeof expectedPin !== "object") {
    throw new Error("missing-pin");
  }
  const lstat = originalLstatSync(filePath);
  if (lstat.isSymbolicLink() || !lstat.isFile()) {
    throw new Error("nonregular");
  }
  const openFlags = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0);
  const fd = originalOpenSync(filePath, openFlags);
  try {
    const fstat = originalFstatSync(fd);
    if (!fstat.isFile() || fstat.size !== expectedPin.size) {
      throw new Error("size");
    }
    const raw = originalReadFileSync(fd);
    if (raw.length !== expectedPin.size) {
      throw new Error("length");
    }
    const sha256 = createHash("sha256").update(raw).digest("hex");
    const blob = createHash("sha1")
      .update(`blob ${raw.length}\\0`)
      .update(raw)
      .digest("hex");
    if (sha256 !== expectedPin.sha256 || blob !== expectedPin.blob) {
      throw new Error("digest");
    }
    return raw;
  } finally {
    originalCloseSync(fd);
  }
}

function parseForwardedFlags(args) {
  const out = new Map();
  for (let i = 0; i < args.length; i += 2) {
    const key = args[i];
    const val = args[i + 1];
    if (
      typeof key !== "string" ||
      !key.startsWith("--") ||
      typeof val !== "string" ||
      val.length === 0 ||
      val.startsWith("--") ||
      out.has(key)
    ) {
      throw new Error("argv");
    }
    out.set(key, val);
  }
  const required = ["--platform", "--scenario", "--launch-root", "--checkout", "--evidence", "--label"];
  if (out.size !== required.length || required.some((k) => !out.has(k))) {
    throw new Error("flags");
  }
  return out;
}

let canonicalTarget;
try {
  if (process.argv.length < 3) {
    throw new Error("missing-target");
  }
  const targetArg = process.argv[2];
  const forwardedArgs = process.argv.slice(3);
  if (typeof targetArg !== "string" || basename(targetArg) !== "native-rc-smoke.mjs") {
    throw new Error("target-name");
  }
  const resolvedTarget = resolve(targetArg);
  const toolsDir = dirname(resolvedTarget);
  const sourceDir = dirname(toolsDir);
  if (basename(toolsDir) !== "tools") {
    throw new Error("tools-dir");
  }
  for (const dirPath of [sourceDir, toolsDir]) {
    const st = originalLstatSync(dirPath);
    if (st.isSymbolicLink() || !st.isDirectory()) {
      throw new Error("dir-symlink");
    }
  }
  if (
    !EXPECTED_PROFILE ||
    EXPECTED_PROFILE.id !== "nebular071" ||
    EXPECTED_PROFILE.commit !== "f2c527ee6f3cbd53fd44e095d5355ca7f5c7519a" ||
    EXPECTED_PROFILE.tree !== "6e3561855f6ee0093fb709488ad976b69bf501d2" ||
    !EXPECTED_PROFILE.modules ||
    typeof EXPECTED_PROFILE.modules !== "object"
  ) {
    throw new Error("profile");
  }
  const harnessPin = EXPECTED_PROFILE.modules["native-rc-smoke.mjs"];
  if (
    !harnessPin ||
    harnessPin.sha256 !== HARDCODED_HARNESS_PIN.sha256 ||
    harnessPin.blob !== HARDCODED_HARNESS_PIN.blob ||
    harnessPin.size !== HARDCODED_HARNESS_PIN.size
  ) {
    throw new Error("harness-pin");
  }
  const pkgRaw = readRegularVerified(join(sourceDir, "package.json"), EXPECTED_PROFILE.support);
  const pkg = JSON.parse(pkgRaw.toString("utf8"));
  if (!pkg || pkg.version !== "0.7.1") {
    throw new Error("pkg-version");
  }
  const expectedNames = Object.keys(EXPECTED_PROFILE.modules).sort();
  if (expectedNames.length !== 7) {
    throw new Error("closure-count");
  }
  for (const name of expectedNames) {
    readRegularVerified(join(toolsDir, name), EXPECTED_PROFILE.modules[name]);
  }
  readRegularVerified(resolvedTarget, HARDCODED_HARNESS_PIN);
  const flags = parseForwardedFlags(forwardedArgs);
  const platform = flags.get("--platform");
  const scenario = flags.get("--scenario");
  if (!ALLOWED_BINDINGS.has(`${platform}:${scenario}`)) {
    throw new Error("binding");
  }
  if (flags.get("--label") !== `${platform}-${scenario}`) {
    throw new Error("label");
  }
  const checkoutPath = flags.get("--checkout");
  const checkoutStat = originalLstatSync(checkoutPath);
  if (checkoutStat.isSymbolicLink() || !checkoutStat.isDirectory()) {
    throw new Error("checkout-symlink");
  }
  // The installed client intentionally receives a separate, verified fixture
  // checkout. Import the immutable source while forwarding that original path.
  const checkoutTools = join(checkoutPath, "tools");
  const checkoutToolsStat = originalLstatSync(checkoutTools);
  if (checkoutToolsStat.isSymbolicLink() || !checkoutToolsStat.isDirectory()) {
    throw new Error("checkout-tools");
  }
  readRegularVerified(join(checkoutPath, "package.json"), EXPECTED_PROFILE.support);
  for (const name of expectedNames) {
    readRegularVerified(join(checkoutTools, name), EXPECTED_PROFILE.modules[name]);
  }
  canonicalTarget = originalRealpathSync(resolvedTarget);
} catch {
  refuse();
}

const expectedTmpParents = new Set([resolve(tmpdir())]);
try {
  expectedTmpParents.add(originalRealpathSync(tmpdir()));
} catch {
  // Ignore realpath failure on tmpdir fallback.
}

function isTargetCleanupCall(args) {
  if (args.length !== 2) {
    return false;
  }
  const [target, options] = args;
  if (typeof target !== "string" || target.length === 0) {
    return false;
  }
  if (
    options === null ||
    typeof options !== "object" ||
    Array.isArray(options) ||
    options.recursive !== true ||
    options.force !== true
  ) {
    return false;
  }
  if (resolve(target) !== target) {
    return false;
  }
  const base = basename(target);
  if (!/^nebular-rc-smoke-[A-Za-z0-9_-]+$/.test(base)) {
    return false;
  }
  const parentDir = dirname(target);
  let parentMatched = expectedTmpParents.has(parentDir);
  if (!parentMatched) {
    try {
      parentMatched = expectedTmpParents.has(originalRealpathSync(parentDir));
    } catch {
      parentMatched = false;
    }
  }
  if (!parentMatched) {
    return false;
  }
  try {
    const st = originalLstatSync(target, { throwIfNoEntry: false });
    if (st && st.isSymbolicLink()) {
      return false;
    }
  } catch {
    return false;
  }
  return true;
}

function retryIdentity(args) {
  const keys = Reflect.ownKeys(args[1]);
  if (keys.length !== 2 || !keys.includes("recursive") || !keys.includes("force")) {
    return null;
  }
  try {
    const st = originalLstatSync(args[0], { throwIfNoEntry: false });
    if (
      st &&
      !st.isSymbolicLink() &&
      st.isDirectory() &&
      typeof process.getuid === "function" &&
      st.uid === process.getuid() &&
      (st.mode & 0o777) === 0o700 &&
      Number.isSafeInteger(st.dev) &&
      Number.isSafeInteger(st.ino)
    ) {
      return st;
    }
  } catch {
    // Retry eligibility failure never replaces an original cleanup error.
  }
  return null;
}

function cleanupWithRewalk(receiver, args, state) {
  const identity = retryIdentity(args);
  if (!identity) {
    state.outcome = "ineligible";
    return Reflect.apply(originalRmSync, receiver, args);
  }
  for (let attempt = 0; ; attempt++) {
    try {
      return Reflect.apply(originalRmSync, receiver, args);
    } catch (error) {
      let code;
      try {
        code = error !== null && typeof error === "object" ? error.code : undefined;
      } catch {
        throw error;
      }
      if (code !== "ENOTEMPTY") {
        state.outcome = "nonretryable-after-" + (attempt + 1);
        throw error;
      }
      if (attempt === 3) {
        state.outcome = "exhausted-4";
        throw error;
      }
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, (attempt + 1) * 100);
      const next = retryIdentity(args);
      if (!next || next.dev !== identity.dev || next.ino !== identity.ino) {
        state.outcome = "identity-lost-after-" + (attempt + 1);
        throw error;
      }
    }
  }
}

let observedTargetCalls = 0;

fs.rmSync = function wrappedRmSync(...args) {
  const matched = isTargetCleanupCall(args);
  const rewalk = { outcome: "unclassified" };
  try {
    return matched && observedTargetCalls === 0
      ? cleanupWithRewalk(this, args, rewalk)
      : Reflect.apply(originalRmSync, this, args);
  } catch (error) {
    if (matched && observedTargetCalls === 0) {
      observedTargetCalls += 1;
      try {
        const rawCode =
          error !== null && typeof error === "object" && typeof error.code === "string"
            ? error.code
            : "";
        const code = ALLOWED_ERRNO_CODES.has(rawCode) ? rawCode : "OTHER";
        const outcome = /^(?:ineligible|identity-lost-after-[1-3]|exhausted-4|nonretryable-after-[1-4]|unclassified)$/.test(rewalk.outcome)
          ? rewalk.outcome : "unclassified";
        process.stderr.write(`RS9_CURRENT071_CLEANUP_REWALK=${outcome}\\nRS9_CURRENT071_CLEANUP_ERRNO=${code}\\n`);
      } catch {
        // Never allow diagnostic emission to mask or alter the original cleanup error.
      }
    }
    throw error;
  } finally {
    if (matched && observedTargetCalls === 0) {
      observedTargetCalls += 1;
    }
  }
};

syncBuiltinESMExports();

const forwardedArgs = process.argv.slice(3);
process.argv = [process.argv[0], canonicalTarget, ...forwardedArgs];
await import(pathToFileURL(canonicalTarget).href);
"""


def render_current071_cleanup_observer_bytes(profile: Mapping[str, object] | None = None) -> bytes:
    """Render deterministic Node22 observer bytes bound to the authenticated 0.7.1 profile."""
    selected = CURRENT071_REPLAY_PROGRESS_PROFILE if profile is None else profile
    if not isinstance(selected, Mapping):
        raise ContractError("APPLICATION_SMOKE", "Invalid 0.7.1 profile for cleanup observer")
    modules = selected.get("modules")
    support = selected.get("support")
    if (
        selected.get("id") != "nebular071"
        or selected.get("commit") != CURRENT071_COMMIT
        or selected.get("tree") != CURRENT071_TREE
        or not isinstance(modules, Mapping)
        or set(modules.keys()) != CURRENT071_CLOSURE_MODULE_NAMES
        or modules.get("native-rc-smoke.mjs") != CURRENT071_NATIVE_RC_SMOKE_PIN
        or not isinstance(support, Mapping)
    ):
        raise ContractError("APPLICATION_SMOKE", "Unauthenticated 0.7.1 profile for cleanup observer")
    profile_json = json.dumps(selected, sort_keys=True, separators=(",", ":"))
    return _OBSERVER_TEMPLATE.replace("__EXPECTED_PROFILE_JSON__", profile_json).encode("utf-8")


CURRENT071_CLEANUP_OBSERVER_BYTES = render_current071_cleanup_observer_bytes(CURRENT071_REPLAY_PROGRESS_PROFILE)
CURRENT071_CLEANUP_OBSERVER_SHA256 = digest(CURRENT071_CLEANUP_OBSERVER_BYTES)


def _assert_no_symlink_chain(path: Path) -> None:
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise ContractError("APPLICATION_SMOKE", "Symlinked current071 cleanup observation path refused")


def _write_observer_script(scratch: Path, script_bytes: bytes) -> Path:
    _assert_no_symlink_chain(scratch)
    if not scratch.is_dir():
        raise ContractError("APPLICATION_SMOKE", "Scratch directory required for current071 cleanup observer")
    wrapper_path = scratch / CURRENT071_CLEANUP_OBSERVER_FILENAME
    if wrapper_path.is_symlink():
        raise ContractError("APPLICATION_SMOKE", "Symlinked current071 cleanup observer wrapper refused")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(wrapper_path, flags, 0o600)
        with os.fdopen(fd, "wb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ContractError("APPLICATION_SMOKE", "Regular current071 cleanup observer wrapper required")
            stream.write(script_bytes)
    except OSError as exc:
        raise ContractError("APPLICATION_SMOKE", "Unable to materialize current071 cleanup observer") from exc
    return wrapper_path


def _verify_observer_file(wrapper_path: Path, expected_bytes: bytes, expected_sha256: str) -> None:
    _assert_no_symlink_chain(wrapper_path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(wrapper_path, flags)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise ContractError("APPLICATION_SMOKE", "Regular current071 cleanup observer wrapper required")
            raw = stream.read(len(expected_bytes) + 1)
    except OSError as exc:
        raise ContractError("APPLICATION_SMOKE", "Readable current071 cleanup observer wrapper required") from exc
    if raw != expected_bytes or digest(raw) != expected_sha256:
        raise ContractError("APPLICATION_SMOKE", "Authenticated current071 cleanup observer wrapper mismatch")


def _authenticate_current071_apt_context(
    prepared: Mapping[str, object], *, system: str, platform: str, scenario: str
) -> tuple[Path, Path, Path, Mapping[str, object]]:
    if (
        not all(isinstance(v, str) for v in (system, platform, scenario))
        or (system, platform, scenario) not in CURRENT071_CLEANUP_SYSTEM_BINDINGS
    ):
        raise ContractError("APPLICATION_SMOKE", "current071 cleanup observer requires Linux B/C/C-signal binding")
    if not isinstance(prepared, Mapping) or prepared.get("container_client") is not True:
        raise ContractError("APPLICATION_SMOKE", "current071 cleanup observer requires container client context")
    if prepared.get("nix_client") is True or "environment_transform" in prepared:
        raise ContractError("APPLICATION_SMOKE", "current071 cleanup observer refused on Nix route")
    family = prepared.get("family")
    label = prepared.get("label")
    if family is not None and family != "apt":
        raise ContractError("APPLICATION_SMOKE", "current071 cleanup observer is restricted to APT family")
    if label is not None and label != "apt":
        raise ContractError("APPLICATION_SMOKE", "current071 cleanup observer requires APT container label")
    if family != "apt" and label != "apt":
        raise ContractError("APPLICATION_SMOKE", "current071 cleanup observer requires explicit APT family binding")
    req = prepared.get("request")
    if req is not None and (not isinstance(req, Mapping) or req.get("family") != "apt"):
        raise ContractError("APPLICATION_SMOKE", "current071 cleanup observer request family mismatch")
    if prepared.get("source_generation") != CURRENT_SMOKE_GENERATION:
        raise ContractError("APPLICATION_SMOKE", "current071 cleanup observer requires current smoke generation")
    raw_source = prepared.get("source")
    raw_tools = prepared.get("tools")
    raw_scratch = prepared.get("scratch")
    if not all(isinstance(p, (str, Path)) for p in (raw_source, raw_tools, raw_scratch)):
        raise ContractError("APPLICATION_SMOKE", "current071 cleanup observer requires source, tools, and scratch paths")
    source = Path(raw_source)
    tools = Path(raw_tools)
    scratch = Path(raw_scratch)
    _assert_no_symlink_chain(source)
    _assert_no_symlink_chain(tools)
    _assert_no_symlink_chain(scratch)
    if tools.resolve() != (source.resolve() / "tools").resolve():
        raise ContractError("APPLICATION_SMOKE", "current071 cleanup observer tools path must resolve to source/tools")
    if scratch.resolve() == source.resolve() or source.resolve() in scratch.resolve().parents:
        raise ContractError("APPLICATION_SMOKE", "current071 cleanup observer scratch must be disjoint from source")
    raw_checkout = prepared.get("checkout")
    if raw_checkout is not None:
        if not isinstance(raw_checkout, (str, Path)):
            raise ContractError("APPLICATION_SMOKE", "Invalid checkout path for current071 cleanup observer")
        checkout = Path(raw_checkout)
        _assert_no_symlink_chain(checkout)
        # guest_main authenticates a disjoint fixture copy. Its complete
        # source-envelope inventory is verified below; path equality is not
        # the identity contract.
    try:
        verify_execution_source_readback(prepared)
    except ContractError as exc:
        raise ContractError("APPLICATION_SMOKE", "current071 cleanup observer source readback verification failed") from exc
    envelope = prepared.get("source_readback")
    producers = envelope.get("producers") if isinstance(envelope, Mapping) else None
    nebular = producers.get("nebular") if isinstance(producers, Mapping) else None
    if (
        not isinstance(nebular, Mapping)
        or nebular.get("commit") != CURRENT071_COMMIT
        or nebular.get("tree") != CURRENT071_TREE
        or nebular.get("tag") != "v0.7.1"
    ):
        raise ContractError("APPLICATION_SMOKE", "current071 cleanup observer requires authenticated 0.7.1 source readback")
    if raw_checkout is not None:
        try:
            verify_checkout(envelope, Path(raw_checkout))
        except ContractError as exc:
            raise ContractError("APPLICATION_SMOKE", "current071 cleanup observer checkout verification failed") from exc
    from rs9 import application_smoke_diagnostic as diagnostic
    profile = diagnostic._current_replay_progress_profile(prepared)
    if profile is None or profile != diagnostic.CURRENT071_REPLAY_PROGRESS_PROFILE:
        raise ContractError("APPLICATION_SMOKE", "current071 cleanup observer requires authenticated 0.7.1 harness closure")
    return source, tools, scratch, profile


def prepare_current071_cleanup_observation(
    prepared: Mapping[str, object], *, system: str, platform: str, scenario: str
) -> dict[str, object]:
    """Authenticate current071 Linux APT context and write the disjoint scratch observer wrapper."""
    source, tools, scratch, profile = _authenticate_current071_apt_context(
        prepared, system=system, platform=platform, scenario=scenario
    )
    script_bytes = render_current071_cleanup_observer_bytes(profile)
    script_sha256 = digest(script_bytes)
    wrapper_path = _write_observer_script(scratch, script_bytes)
    harness_path = tools / "native-rc-smoke.mjs"
    _assert_no_symlink_chain(harness_path)
    return {
        "observer_id": CURRENT071_CLEANUP_OBSERVER_ID,
        "public_identity": {
            "policy_id": CURRENT071_CLEANUP_POLICY_ID,
            "source_commit": CURRENT071_COMMIT,
            "source_tree": CURRENT071_TREE,
            "harness_sha256": CURRENT071_NATIVE_RC_SMOKE_PIN["sha256"],
            "observer_sha256": script_sha256,
        },
        "execution_mode": "reviewed-test-execution-bounded-rewalk",
        "non_admitting": True,
        "untouched_original_argv_execution": False,
        "family": "apt",
        "system": system,
        "platform": platform,
        "scenario": scenario,
        "wrapper": wrapper_path,
        "wrapper_sha256": script_sha256,
        "target_harness_sha256": CURRENT071_NATIVE_RC_SMOKE_PIN["sha256"],
        "source_commit": profile["commit"],
        "source_tree": profile["tree"],
        "harness": harness_path,
        "source": source,
    }


def validate_cleanup_observation_plan(
    plan: object, *, prepared: Mapping[str, object], platform: str, scenario: str
) -> tuple[Path, Path]:
    """Validate an authenticated cleanup-observation plan before building the Node command."""
    if not isinstance(plan, Mapping):
        raise ContractError("APPLICATION_SMOKE", "Invalid current071 cleanup observation plan")
    system = plan.get("system")
    if (
        plan.get("observer_id") != CURRENT071_CLEANUP_OBSERVER_ID
        or plan.get("execution_mode") != "reviewed-test-execution-bounded-rewalk"
        or plan.get("non_admitting") is not True
        or plan.get("untouched_original_argv_execution") is not False
        or plan.get("family") != "apt"
        or plan.get("platform") != platform
        or plan.get("scenario") != scenario
        or not isinstance(system, str)
    ):
        raise ContractError("APPLICATION_SMOKE", "Mismatched current071 cleanup observation plan")
    source, tools, scratch, profile = _authenticate_current071_apt_context(
        prepared, system=system, platform=platform, scenario=scenario
    )
    expected_bytes = render_current071_cleanup_observer_bytes(profile)
    expected_sha256 = digest(expected_bytes)
    expected_identity = {
        "policy_id": CURRENT071_CLEANUP_POLICY_ID,
        "source_commit": CURRENT071_COMMIT,
        "source_tree": CURRENT071_TREE,
        "harness_sha256": CURRENT071_NATIVE_RC_SMOKE_PIN["sha256"],
        "observer_sha256": expected_sha256,
    }
    if plan.get("public_identity") != expected_identity:
        raise ContractError("APPLICATION_SMOKE", "Mismatched current071 cleanup observation identity")
    if (
        plan.get("wrapper_sha256") != expected_sha256
        or plan.get("target_harness_sha256") != CURRENT071_NATIVE_RC_SMOKE_PIN["sha256"]
        or plan.get("source_commit") != profile["commit"]
        or plan.get("source_tree") != profile["tree"]
    ):
        raise ContractError("APPLICATION_SMOKE", "Mismatched current071 cleanup observer digest")
    wrapper_path = plan.get("wrapper")
    harness_path = plan.get("harness")
    if not isinstance(wrapper_path, (str, Path)) or not isinstance(harness_path, (str, Path)):
        raise ContractError("APPLICATION_SMOKE", "Invalid current071 cleanup observation wrapper paths")
    wrapper = Path(wrapper_path)
    harness = Path(harness_path)
    if wrapper.resolve() != (scratch / CURRENT071_CLEANUP_OBSERVER_FILENAME).resolve():
        raise ContractError("APPLICATION_SMOKE", "current071 cleanup observer must reside in scratch")
    if harness.resolve() != (tools / "native-rc-smoke.mjs").resolve():
        raise ContractError("APPLICATION_SMOKE", "current071 cleanup observer harness mismatch")
    if Path(plan.get("source", "")).resolve() != source.resolve():
        raise ContractError("APPLICATION_SMOKE", "current071 cleanup observer source mismatch")
    _verify_observer_file(wrapper, expected_bytes, expected_sha256)
    return wrapper, harness


def withheld_current071_cleanup_observation(
    reason: str, *, observer_id: str = CURRENT071_CLEANUP_OBSERVER_ID
) -> dict[str, object]:
    """Return the canonical closed withheld cleanup-observation record (3-pass fixed point)."""
    closed_reason = reason if isinstance(reason, str) and reason in CURRENT071_CLEANUP_WITHHELD_REASONS else "invalid-observation"
    if observer_id not in (CURRENT071_CLEANUP_OBSERVER_ID, CURRENT071_BUILTIN_RETRY_CLEANUP_OBSERVER_ID, CURRENT071_LEGACY_CLEANUP_OBSERVER_ID):
        observer_id = CURRENT071_CLEANUP_OBSERVER_ID
    result = {
        "schema": (CURRENT071_CLEANUP_OBSERVATION_SCHEMA if observer_id == CURRENT071_CLEANUP_OBSERVER_ID
                   else CURRENT071_LEGACY_CLEANUP_OBSERVATION_SCHEMA),
        "observer_id": observer_id,
        "family": "apt",
        "system": None,
        "scenario": None,
        "stderr_bytes": None,
        "stderr_sha256": None,
        "status": "withheld",
        "errno_code": None,
        "marker_count": None,
        "withheld_reason": closed_reason,
    }

    if observer_id == CURRENT071_CLEANUP_OBSERVER_ID:
        result["rewalk_outcome"] = None
    return result


def _valid_rewalk_outcome(errno_code: object, outcome: object) -> bool:
    if not isinstance(outcome, str) or outcome not in CURRENT071_REWALK_OUTCOMES:
        return False
    if outcome == "exhausted-4" or outcome.startswith("identity-lost-after-"):
        return errno_code == "ENOTEMPTY"
    if outcome.startswith("nonretryable-after-"):
        return errno_code != "ENOTEMPTY"
    return True


def observe_current071_cleanup(
    stderr: bytes,
    *,
    system: str,
    scenario: str,
    stderr_bytes: int | None,
    stderr_sha256: str | None,
    complete: bool,
) -> dict[str, object]:
    """Extract fixed errno and rewalk outcome from failed current071 APT outer stderr."""
    if (
        not isinstance(system, str)
        or not isinstance(scenario, str)
        or system not in CURRENT071_CLEANUP_ALLOWED_SYSTEMS
        or scenario not in CURRENT071_CLEANUP_ALLOWED_SYSTEMS[system][1]
    ):
        return withheld_current071_cleanup_observation("binding-mismatch")
    if (
        complete is not True
        or not isinstance(stderr, (bytes, bytearray))
        or type(stderr_bytes) is not int
        or stderr_bytes != len(stderr)
        or not 0 <= stderr_bytes <= CURRENT071_CLEANUP_MAX_STDERR_BYTES
        or not isinstance(stderr_sha256, str)
        or stderr_sha256 != digest(bytes(stderr))
    ):
        return withheld_current071_cleanup_observation("incomplete-stream")
    raw = bytes(stderr)
    if b"RS9_CURRENT071_CLEANUP_ERRNO" not in raw:
        if b"RS9_CURRENT071_CLEANUP_REWALK" in raw:
            return withheld_current071_cleanup_observation("invalid-marker")
        return {
            "schema": CURRENT071_CLEANUP_OBSERVATION_SCHEMA,
            "observer_id": CURRENT071_CLEANUP_OBSERVER_ID,
            "family": "apt",
            "system": system,
            "scenario": scenario,
            "stderr_bytes": stderr_bytes,
            "stderr_sha256": stderr_sha256,
            "status": "no-cleanup-error-observed",
            "errno_code": None,
            "marker_count": 0,
            "withheld_reason": None,
            "rewalk_outcome": None,
        }
    try:
        text = raw.decode("utf-8")
    except UnicodeError:
        return withheld_current071_cleanup_observation("invalid-marker")
    if not text.endswith("\n") or any(ord(c) < 32 and c not in "\n\t" or ord(c) == 127 for c in text):
        return withheld_current071_cleanup_observation("invalid-marker")
    lines = text.split("\n")[:-1]
    marker_lines = [line for line in lines if "RS9_CURRENT071_CLEANUP_ERRNO" in line]
    if len(marker_lines) > 1:
        return withheld_current071_cleanup_observation("multiple-markers")
    marker_line = marker_lines[0]
    if not marker_line.startswith(CURRENT071_CLEANUP_MARKER_PREFIX):
        return withheld_current071_cleanup_observation("invalid-marker")
    errno_code = marker_line[len(CURRENT071_CLEANUP_MARKER_PREFIX):]
    if errno_code not in CURRENT071_CLEANUP_ERRNO_CODES:
        return withheld_current071_cleanup_observation("invalid-marker")
    rewalk_lines = [line for line in lines if "RS9_CURRENT071_CLEANUP_REWALK" in line]
    if len(rewalk_lines) != 1 or not rewalk_lines[0].startswith(CURRENT071_REWALK_MARKER_PREFIX):
        return withheld_current071_cleanup_observation("invalid-marker")
    outcome = rewalk_lines[0][len(CURRENT071_REWALK_MARKER_PREFIX):]
    if not _valid_rewalk_outcome(errno_code, outcome):
        return withheld_current071_cleanup_observation("invalid-marker")
    return {
        "schema": CURRENT071_CLEANUP_OBSERVATION_SCHEMA,
        "observer_id": CURRENT071_CLEANUP_OBSERVER_ID,
        "family": "apt",
        "system": system,
        "scenario": scenario,
        "stderr_bytes": stderr_bytes,
        "stderr_sha256": stderr_sha256,
        "status": "cleanup-error-observed",
        "errno_code": errno_code,
        "marker_count": 1,
        "withheld_reason": None,
        "rewalk_outcome": outcome,
    }


def validate_current071_cleanup_observation(
    raw: object,
    *,
    system: str | None = None,
    scenario: str | None = None,
    stderr_bytes: int | None = None,
    stderr_sha256: str | None = None,
    complete: bool = False,
    mismatch: bool = False,
    family: str | None = None,
) -> dict[str, object] | None:
    """Idempotent host-side closed validator for cleanup_observation bound to outer stderr."""
    observer_id = (
        raw.get("observer_id")
        if isinstance(raw, dict) and raw.get("observer_id") in (
            CURRENT071_CLEANUP_OBSERVER_ID, CURRENT071_BUILTIN_RETRY_CLEANUP_OBSERVER_ID,
            CURRENT071_LEGACY_CLEANUP_OBSERVER_ID
        )
        else CURRENT071_CLEANUP_OBSERVER_ID
    )

    def withheld(reason: str) -> dict[str, object]:
        return withheld_current071_cleanup_observation(reason, observer_id=observer_id)

    if raw is None:
        return None
    if family is not None and family != "apt":
        mismatch = True
    fallback = "binding-mismatch" if mismatch else "invalid-observation"
    current = observer_id == CURRENT071_CLEANUP_OBSERVER_ID
    expected_keys = _CLEANUP_OBSERVATION_KEYS if current else _LEGACY_CLEANUP_OBSERVATION_KEYS
    expected_schema = (CURRENT071_CLEANUP_OBSERVATION_SCHEMA if current
                       else CURRENT071_LEGACY_CLEANUP_OBSERVATION_SCHEMA)
    if not isinstance(raw, dict) or set(raw.keys()) != expected_keys:
        return withheld(fallback)
    if (
        raw.get("schema") != expected_schema
        or raw.get("observer_id") not in (CURRENT071_CLEANUP_OBSERVER_ID, CURRENT071_BUILTIN_RETRY_CLEANUP_OBSERVER_ID, CURRENT071_LEGACY_CLEANUP_OBSERVER_ID)
        or raw.get("family") != "apt"
    ):
        return withheld(fallback)
    status = raw.get("status")
    if not isinstance(status, str) or status not in CURRENT071_CLEANUP_STATUSES:
        return withheld(fallback)
    if status == "withheld":
        reason = raw.get("withheld_reason")
        if (
            any(raw.get(k) is not None for k in ("system", "scenario", "stderr_bytes", "stderr_sha256", "errno_code", "marker_count"))
            or not isinstance(reason, str)
            or reason not in CURRENT071_CLEANUP_WITHHELD_REASONS
            or (current and raw.get("rewalk_outcome") is not None)
        ):
            return withheld("binding-mismatch" if mismatch else "invalid-observation")
        if mismatch:
            return withheld("binding-mismatch")
        return withheld(reason)
    obs_system = raw.get("system")
    obs_scenario = raw.get("scenario")
    obs_bytes = raw.get("stderr_bytes")
    obs_sha = raw.get("stderr_sha256")
    obs_errno = raw.get("errno_code")
    obs_count = raw.get("marker_count")
    obs_reason = raw.get("withheld_reason")
    if (
        not isinstance(obs_system, str)
        or obs_system not in CURRENT071_CLEANUP_ALLOWED_SYSTEMS
        or not isinstance(obs_scenario, str)
        or obs_scenario not in CURRENT071_CLEANUP_ALLOWED_SYSTEMS[obs_system][1]
        or type(obs_bytes) is not int
        or not 0 <= obs_bytes <= CURRENT071_CLEANUP_MAX_STDERR_BYTES
        or not isinstance(obs_sha, str)
        or not _SHA256_RE.fullmatch(obs_sha)
        or (obs_bytes == 0 and obs_sha != _EMPTY_SHA256)
        or (obs_bytes > 0 and obs_sha == _EMPTY_SHA256)
        or obs_reason is not None
    ):
        return withheld("binding-mismatch" if mismatch else "invalid-observation")
    if status == "cleanup-error-observed":
        min_marker_bytes = len(CURRENT071_CLEANUP_MARKER_PREFIX) + 2
        if (
            not isinstance(obs_errno, str)
            or obs_errno not in CURRENT071_CLEANUP_ERRNO_CODES
            or type(obs_count) is not int
            or obs_count != 1
            or obs_bytes < min_marker_bytes
        ):
            return withheld("binding-mismatch" if mismatch else "invalid-observation")
    elif status == "no-cleanup-error-observed":
        if obs_errno is not None or type(obs_count) is not int or obs_count != 0:
            return withheld("binding-mismatch" if mismatch else "invalid-observation")
    if current:
        outcome = raw.get("rewalk_outcome")
        if status == "cleanup-error-observed":
            if not _valid_rewalk_outcome(obs_errno, outcome):
                return withheld(fallback)
        elif outcome is not None:
            return withheld(fallback)
    if (
        mismatch
        or (system is not None and obs_system != system)
        or (scenario is not None and obs_scenario != scenario)
        or obs_bytes != stderr_bytes
        or obs_sha != stderr_sha256
    ):
        return withheld("binding-mismatch")
    if complete is not True:
        return withheld("incomplete-stream")
    result = {
        "schema": expected_schema,
        "observer_id": raw["observer_id"],
        "family": "apt",
        "system": obs_system,
        "scenario": obs_scenario,
        "stderr_bytes": obs_bytes,
        "stderr_sha256": obs_sha,
        "status": status,
        "errno_code": obs_errno,
        "marker_count": obs_count,
        "withheld_reason": None,
    }
    if current:
        result["rewalk_outcome"] = raw["rewalk_outcome"]
    return result
