#!/usr/bin/env node
// Optional RS9 replay observer.  The released smoke harness remains the
// authority: this wrapper authenticates it, imports its existing runSmoke
// export, and adds only bounded fixed-enum progress facts.
import childProcess from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import { registerHooks, syncBuiltinESMExports } from "node:module";
import { basename, dirname, relative, resolve, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const CURRENT_PROFILE = Object.freeze({
  "id": "nebular070",
  "commit": "cadb40c4972f68f314096ff60fbcfb4da950c161",
  "tree": "27c643b6375c2aafde314799c4f08e844c14992c",
  "modules": {
    "candidate-provenance.mjs": {
      "sha256": "20244b6765d6e7d0ee5fd86452096a4546f189103b0acb9f065c4a1479c23155",
      "blob": "129b0da16329d07697daab619f8fdbc5690f72fa",
      "size": 15484
    },
    "fs-snapshot.mjs": {
      "sha256": "30ad6c3f0394126a7d3e5534507fe46c78c34946edd15bd5c91b36e2b36df351",
      "blob": "841cfecd874517d0c619cf9a3866c2697e12ecd6",
      "size": 13794
    },
    "native-launcher.mjs": {
      "sha256": "3595cfaf0a2f1ac51a48862dc5f6aa842db6d3431a62159bcb93cb0abc812f2d",
      "blob": "9c84fff880957edcb98925bbaea941fc0f7e66fe",
      "size": 7193
    },
    "native-rc-package.mjs": {
      "sha256": "0ef948c2f9f45a9343586288681ae5ed6f6527b85912a52bd8c37aa50e3682c6",
      "blob": "570d4d2b6cee8551bb0d77417e54ee4a0d308ca8",
      "size": 33102
    },
    "native-rc-smoke.mjs": {
      "sha256": "874355e36496884e55a6e4dae6986ecde817d20863bb3fe26d1b1b5a1d283e69",
      "blob": "cbf6a2148c11ed1516ba5d7fc2d4dd32dee3ee9f",
      "size": 30732
    },
    "native-runtime.mjs": {
      "sha256": "a9d6c8e885b9db41877c5d2d79efe48f2e47daf791e0f1ad1ca06636d37d962e",
      "blob": "333192471147289f232bd915c6813ae23b39f1bb",
      "size": 118749
    },
    "platform-targets.mjs": {
      "sha256": "35321c7e888038210589612873136c96bf697789f6f4e90918442faa41e13aec",
      "blob": "ebe518bbf27856c496541bca46bf13066805a606",
      "size": 7292
    }
  },
  "support": {
    "sha256": "15d3f118dfdc0014129fc37d63533a6a02cf355fdb89961a215eca77e95b7cd2",
    "blob": "161ee788b7a8660916e2b6fbbebbac0de4a87f42",
    "size": 1833
  }
});
const CURRENT071_PROFILE = Object.freeze({
  "commit": "f2c527ee6f3cbd53fd44e095d5355ca7f5c7519a",
  "id": "nebular071",
  "modules": {
    "candidate-provenance.mjs": {
      "blob": "129b0da16329d07697daab619f8fdbc5690f72fa",
      "sha256": "20244b6765d6e7d0ee5fd86452096a4546f189103b0acb9f065c4a1479c23155",
      "size": 15484
    },
    "fs-snapshot.mjs": {
      "blob": "841cfecd874517d0c619cf9a3866c2697e12ecd6",
      "sha256": "30ad6c3f0394126a7d3e5534507fe46c78c34946edd15bd5c91b36e2b36df351",
      "size": 13794
    },
    "native-launcher.mjs": {
      "blob": "9c84fff880957edcb98925bbaea941fc0f7e66fe",
      "sha256": "3595cfaf0a2f1ac51a48862dc5f6aa842db6d3431a62159bcb93cb0abc812f2d",
      "size": 7193
    },
    "native-rc-package.mjs": {
      "blob": "570d4d2b6cee8551bb0d77417e54ee4a0d308ca8",
      "sha256": "0ef948c2f9f45a9343586288681ae5ed6f6527b85912a52bd8c37aa50e3682c6",
      "size": 33102
    },
    "native-rc-smoke.mjs": {
      "blob": "cbf6a2148c11ed1516ba5d7fc2d4dd32dee3ee9f",
      "sha256": "874355e36496884e55a6e4dae6986ecde817d20863bb3fe26d1b1b5a1d283e69",
      "size": 30732
    },
    "native-runtime.mjs": {
      "blob": "333192471147289f232bd915c6813ae23b39f1bb",
      "sha256": "a9d6c8e885b9db41877c5d2d79efe48f2e47daf791e0f1ad1ca06636d37d962e",
      "size": 118749
    },
    "platform-targets.mjs": {
      "blob": "ebe518bbf27856c496541bca46bf13066805a606",
      "sha256": "35321c7e888038210589612873136c96bf697789f6f4e90918442faa41e13aec",
      "size": 7292
    }
  },
  "support": {
    "blob": "a0ea0f117edb7c980db653ad1073e005d603b71a",
    "sha256": "0d68c1e18c5024f5fc8b52815d9f01ad25fd68f878f85bed59bdb4833a7f98c0",
    "size": 1833
  },
  "tree": "6e3561855f6ee0093fb709488ad976b69bf501d2"
});
const PROGRESS_SCHEMA = "rs9.application-smoke-replay-progress.v1";
const MAX_PROGRESS_BYTES = 16 * 1024;
const MAX_PROGRESS_EVENTS = 32;
const INITIAL_OBSERVATION_SCHEMA = "rs9.application-smoke-initial-observation.v1";
const INITIAL_OBSERVATION_KIND = "initial-observation";
const MAX_INITIAL_OBSERVATION_BYTES = 16 * 1024;
const MAX_INITIAL_STREAM_BYTES = 1024 * 1024;
const MAX_INITIAL_SNAPSHOT_WRITES = 32;
const INITIAL_SNAPSHOT_INTERVAL_MS = 8_000;
const CURRENT071_REQUIRED_INITIAL_TIMEOUT_MS = 210_000;
const CURRENT071_SIGNAL_INITIAL_TIMEOUT_MS = 180_000;
const FIXED_PROGRESS_EVENTS = new Set([
  "harness|import-start", "harness|imported", "harness|import-failed", "harness|export-missing",
  "candidate|launch-failed", "candidate|launched", "candidate|exited",
  "application|release-smoke-active", "run-smoke|enter", "run-smoke|returned", "run-smoke|error",
  "receipt|write-start", "receipt|finalized", "receipt|write-failed",
  "run-record|write-start", "run-record|finalized", "run-record|write-failed",
]);
const INITIAL_ERROR_CATEGORIES = Object.freeze([
  "dbus-session-conf-missing", "dbus-daemon-error", "xvfb-display-error", "xvfb-auth-error",
  "module-not-found", "command-not-found", "shared-library-missing", "webkit-crash",
  "assertion", "socket-unavailable",
]);
const INITIAL_HELPER_IDENTIFIERS = Object.freeze([
  "dbus-run-session", "dbus-daemon", "node", "native-rc-smoke.mjs",
]);
const INITIAL_ERROR_PATTERNS = Object.freeze([
  ["dbus-session-conf-missing", /session\.conf.*(?:no such|failed|missing|not found)/i],
  ["dbus-daemon-error", /(?:dbus-daemon|dbus-run-session).*(?:failed|error|no such|not found|refused)/i],
  ["xvfb-display-error", /(?:cannot open display|xvfb failed|x server failed|xvfb-run: error)/i],
  ["xvfb-auth-error", /(?:xauth: error|authorization required|no protocol specified)/i],
  ["module-not-found", /(?:err_module_not_found|cannot find module)/i],
  ["command-not-found", /(?:command not found|failed to exec.*(?:no such|not found))/i],
  ["shared-library-missing", /error while loading shared libraries/i],
  ["webkit-crash", /webkit(?:web)?process crashed/i],
  ["assertion", /assertion(?:error| failed)/i],
  ["socket-unavailable", /(?:failed to bind socket|socket: no such file|connection refused)/i],
]);
const INITIAL_HELPER_PATTERNS = Object.freeze(INITIAL_HELPER_IDENTIFIERS.map(identifier => [
  identifier,
  new RegExp("(^|[^a-z0-9._-])" + identifier.replace(/[\^$.*+?()[\]{}|]/g, "\\$&")
    + "($|[^a-z0-9._-])", "i"),
]));
const MAX_INITIAL_CATEGORY_COUNT = 4096;
const INITIAL_SCAN_TAIL_CHARS = 2048;
const MAX_HARNESS_BYTES = 4 * 1024 * 1024;
const MAX_CLOSURE_FILES = 8;
const MAX_CLOSURE_BYTES = 8 * 1024 * 1024;
const O_NOFOLLOW = fs.constants.O_NOFOLLOW;
const INTERNAL = Object.freeze({
  harness: "--rs9-replay-progress-harness",
  progress: "--rs9-replay-progress-file",
  expected: "--rs9-replay-progress-expected-sha256",
  closure: "--rs9-replay-progress-closure-member",
  profile: "--rs9-replay-progress-profile",
  commit: "--rs9-replay-progress-source-commit",
  tree: "--rs9-replay-progress-source-tree",
  support: "--rs9-replay-progress-support-member",
  initialKind: "--rs9-initial-observation-kind",
  initialFile: "--rs9-initial-observation-file",
});

const sha256 = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");

function parseInternalArgs(argv) {
  let harnessPath;
  let progressPath;
  let expectedSha256;
  const closureMembers = [];
  const currentArgs = new Map();
  const forwarded = [];
  let initialObservationKind;
  let initialObservationPath;
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    const value = argv[index + 1];
    if ([INTERNAL.profile, INTERNAL.commit, INTERNAL.tree, INTERNAL.support].includes(flag)) {
      if (value === undefined || currentArgs.has(flag)) throw new Error("Current replay profile arguments differ");
      currentArgs.set(flag, value);
      index += 1;
    } else if (flag === INTERNAL.harness || flag === INTERNAL.progress || flag === INTERNAL.expected
        || flag === INTERNAL.closure) {
      if (value === undefined) throw new Error("Replay progress wrapper internal argument is incomplete");
      if (flag === INTERNAL.harness) harnessPath = value;
      if (flag === INTERNAL.progress) progressPath = value;
      if (flag === INTERNAL.expected) expectedSha256 = value;
      if (flag === INTERNAL.closure) closureMembers.push(value);
      index += 1;
    } else if (flag === INTERNAL.initialKind || flag === INTERNAL.initialFile) {
      if (value === undefined) throw new Error("Initial observation argument is incomplete");
      if (flag === INTERNAL.initialKind) {
        if (initialObservationKind !== undefined || value !== INITIAL_OBSERVATION_KIND)
          throw new Error("Initial observation kind is invalid");
        initialObservationKind = value;
      } else {
        if (initialObservationPath !== undefined) throw new Error("Initial observation file is duplicated");
        initialObservationPath = value;
      }
      index += 1;
    } else {
      forwarded.push(flag);
    }
  }
  if (typeof harnessPath !== "string" || typeof progressPath !== "string"
      || !/^[0-9a-f]{64}$/.test(expectedSha256 ?? "")) {
    throw new Error("Authenticated released smoke harness and progress sink are required");
  }
  if ((initialObservationKind === undefined) !== (initialObservationPath === undefined))
    throw new Error("Initial observation arguments must be paired");
  return { harnessPath, progressPath, expectedSha256, closureMembers, forwarded, currentArgs,
    initialObservationKind, initialObservationPath };
}

function parseSmokeArgs(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (flag === "--keep") { options.keep = true; continue; }
    const key = {
      "--platform": "platform", "--scenario": "scenario", "--launch-root": "launchRoot",
      "--checkout": "checkout", "--evidence": "evidenceDir", "--label": "label",
      "--timeout-ms": "timeoutMs", "--source": "source",
      "--package-manifest-sha256": "packageManifestSha256",
    }[flag];
    if (!key || value === undefined) {
      throw new Error("Usage: native-rc-smoke.mjs --platform <p> --scenario <s> --launch-root <dir> --checkout <dir> --evidence <dir> [--label l] [--timeout-ms n] [--source raw-archive|npm-package] [--package-manifest-sha256 sha256] [--keep]");
    }
    options[key] = key === "timeoutMs" ? Number(value) : value;
    index += 1;
  }
  return options;
}

function readHeldRegular(path, expectedSha256) {
  if (typeof O_NOFOLLOW !== "number") throw new Error("No-follow harness read is unavailable");
  let fd;
  try {
    fd = fs.openSync(path, fs.constants.O_RDONLY | O_NOFOLLOW | fs.constants.O_NONBLOCK);
    const info = fs.fstatSync(fd);
    if (!info.isFile() || info.size > MAX_HARNESS_BYTES) throw new Error("Authenticated replay source is not a bounded regular file");
    const bytes = fs.readFileSync(fd);
    const after = fs.fstatSync(fd);
    if (after.size !== info.size || bytes.length !== info.size) throw new Error("Authenticated replay source changed while read");
    if (sha256(bytes) !== expectedSha256) throw new Error("Released smoke harness identity mismatch");
    return bytes;
  } catch (error) {
    if (error instanceof Error && error.message.includes("identity mismatch")) throw error;
    throw new Error("Authenticated replay source is unavailable");
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

function parseClosureMember(value) {
  const separator = value.indexOf("=");
  const name = separator < 0 ? "" : value.slice(0, separator);
  const expectedSha256 = separator < 0 ? "" : value.slice(separator + 1);
  if (!/^(?:[A-Za-z0-9._-]+\/)*[A-Za-z0-9._-]+\.mjs$/.test(name)
      || name.split("/").some(part => part === "." || part === "..")
      || !/^[0-9a-f]{64}$/.test(expectedSha256)) {
    throw new Error("Authenticated replay source closure is invalid");
  }
  return { name, expectedSha256 };
}

function moduleSpecifiers(bytes) {
  const source = bytes.toString("utf8");
  const patterns = [
    /\bfrom\s*["']([^"']+)["']/g,
    /\bimport\s+["']([^"']+)["']/g,
    /\bimport\s*\(\s*["']([^"']+)["']\s*\)/g,
  ];
  const specs = new Set();
  for (const pattern of patterns) {
    for (const match of source.matchAll(pattern)) specs.add(match[1]);
  }
  return [...specs];
}

function closurePath(root, name) {
  const path = resolve(root, name);
  const relativePath = relative(root, path).split(sep).join("/");
  if (relativePath !== name || relativePath.startsWith("../") || relativePath === "..") {
    throw new Error("Authenticated replay source escaped its closure");
  }
  return path;
}

function buildAuthenticatedClosure(harnessPath, expectedSha256, rawMembers, current = null) {
  const entryPath = resolve(harnessPath);
  const root = dirname(entryPath);
  const entryName = basename(entryPath);
  const expected = new Map();
  for (const raw of rawMembers) {
    const member = parseClosureMember(raw);
    if (expected.has(member.name)) throw new Error("Authenticated replay source closure is duplicated");
    expected.set(member.name, member.expectedSha256);
  }
  if (expected.size === 0) expected.set(entryName, expectedSha256);
  if (expected.get(entryName) !== expectedSha256) {
    throw new Error("Authenticated replay source entry is not bound to its closure");
  }
  if (expected.size + (current ? 1 : 0) > MAX_CLOSURE_FILES) throw new Error("Authenticated replay source closure is too large");

  const sources = new Map();
  const visited = new Set();
  let totalBytes = current ? current.supportBytes.length : 0;
  const visit = (name) => {
    if (visited.has(name)) return;
    const path = closurePath(root, name);
    const bytes = readHeldRegular(path, expected.get(name));
    if (current) verifyCurrentBytes(bytes, current.profile.modules[name]);
    totalBytes += bytes.length;
    if (totalBytes > MAX_CLOSURE_BYTES) throw new Error("Authenticated replay source closure is too large");
    visited.add(name);
    sources.set(path, bytes);
    for (const specifier of moduleSpecifiers(bytes)) {
      if (specifier.startsWith("node:")) continue;
      if (!specifier.startsWith("./") && !specifier.startsWith("../")) {
        throw new Error("Replay harness imports an unapproved module");
      }
      const childURL = new URL(specifier, pathToFileURL(path));
      if (childURL.protocol !== "file:") throw new Error("Replay harness imports a non-file module");
      const childPath = fileURLToPath(childURL);
      const childName = relative(root, childPath).split(sep).join("/");
      if (!expected.has(childName)) throw new Error("Replay harness imports outside its authenticated closure");
      visit(childName);
    }
  };
  visit(entryName);
  if (visited.size !== expected.size) throw new Error("Authenticated replay source closure has unused members");
  return { entryPath, sources };
}

function installAuthenticatedLoader(closure) {
  if (typeof registerHooks !== "function") throw new Error("Authenticated ESM loader hooks are unavailable");
  const hooks = registerHooks({
    resolve(specifier, context, nextResolve) {
      if (specifier.startsWith("node:")) return nextResolve(specifier, context);
      let url;
      try {
        url = specifier.startsWith("file:")
          ? new URL(specifier)
          : new URL(specifier, context.parentURL);
      } catch {
        throw new Error("Replay harness module resolution failed");
      }
      if (url.protocol !== "file:") throw new Error("Replay harness imports an unapproved module");
      const path = fileURLToPath(url);
      if (!closure.sources.has(path)) throw new Error("Replay harness imports outside its authenticated closure");
      return { url: pathToFileURL(path).href, shortCircuit: true };
    },
    load(url, context, nextLoad) {
      if (url.startsWith("node:")) return nextLoad(url, context);
      if (!url.startsWith("file:")) throw new Error("Replay harness loaded a non-file module");
      const path = fileURLToPath(new URL(url));
      const source = closure.sources.get(path);
      if (source === undefined) throw new Error("Replay harness loaded outside its authenticated closure");
      return { format: "module", source, shortCircuit: true };
    },
  });
  return hooks;
}

function installProgressObservers(progressPath, current = null, options = null, initialObservation = null) {
  const originalSpawn = childProcess.spawn;
  const originalWriteFileSync = fs.writeFileSync;
  let sequence = 0;
  let launchObserved = false;
  const streamRestores = [];
  const emit = (stage, event) => {
    if (initialObservation) {
      initialObservation.addPhase(stage, event);
      return;
    }
    if (sequence >= MAX_PROGRESS_EVENTS) return;
    const record = JSON.stringify({ schema: PROGRESS_SCHEMA, seq: sequence + 1, stage, event }) + "\n";
    const bytes = Buffer.from(record, "utf8");
    let fd;
    try {
      const first = sequence === 0;
      const flags = fs.constants.O_WRONLY | fs.constants.O_CREAT | O_NOFOLLOW | fs.constants.O_NONBLOCK
        | (first ? fs.constants.O_EXCL : fs.constants.O_APPEND);
      fd = fs.openSync(progressPath, flags, 0o600);
      const info = fs.fstatSync(fd);
      if (!info.isFile() || info.size + bytes.length > MAX_PROGRESS_BYTES) return;
      fs.writeSync(fd, bytes, 0, bytes.length);
      sequence += 1;
    } catch {
      // Progress is diagnostic-only.  A sink failure never changes smoke status.
    } finally {
      if (fd !== undefined) {
        try { fs.closeSync(fd); } catch { /* diagnostic sink only */ }
      }
    }
  };

  childProcess.spawn = function observedSpawn(...args) {
    let child;
    try {
      child = originalSpawn.apply(this, args);
    } catch (error) {
      if (!launchObserved) emit("candidate", "launch-failed");
      throw error;
    }
    if (!launchObserved) {
      launchObserved = true;
      if (!current || typeof child?.pid === "number") emit("candidate", "launched");
      if (current && typeof child?.stderr?.emit === "function") {
        const stream = child.stderr;
        const originalEmit = stream.emit;
        const ownEmit = Object.getOwnPropertyDescriptor(stream, "emit");
        let pending = "";
        let observedBytes = 0;
        let active = false;
        const marker = `TFSB Studio release smoke scenario ${options.scenario} active`;
        const observe = chunk => {
          try {
            if (active || observedBytes >= 64 * 1024) return;
            const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
            const bounded = bytes.subarray(0, 64 * 1024 - observedBytes);
            observedBytes += bounded.length;
            pending += bounded.toString("utf8");
            const lines = pending.split("\n");
            pending = lines.pop().slice(-512);
            if (lines.some(line => line.replace(/\r$/, "") === marker)) {
              active = true;
              emit("application", "release-smoke-active");
            }
          } catch { /* Optional observation cannot change the released stream path. */ }
        };
        const observedEmit = function(event, ...values) {
          if (!initialObservation) {
            if (event === "data") observe(values[0]);
            return originalEmit.call(this, event, ...values);
          }
          // Deliver the released stream first, preserving its return or exception.
          const result = originalEmit.call(this, event, ...values);
          if (event === "data") {
            observe(values[0]);
            initialObservation.capture("stderr", values[0]);
          }
          return result;
        };
        try {
          Object.defineProperty(stream, "emit", {value: observedEmit, writable: true, configurable: true});
          streamRestores.push(() => {
            if (stream.emit !== observedEmit) return;
            if (ownEmit) Object.defineProperty(stream, "emit", ownEmit);
            else delete stream.emit;
          });
        } catch { /* A stream that cannot be observed stays untouched. */ }
      }
      if (initialObservation && typeof child?.stdout?.emit === "function") {
        const stream = child.stdout;
        const originalEmit = stream.emit;
        const ownEmit = Object.getOwnPropertyDescriptor(stream, "emit");
        const observedEmit = function(event, ...values) {
          const result = originalEmit.call(this, event, ...values);
          if (event === "data") initialObservation.capture("stdout", values[0]);
          return result;
        };
        try {
          Object.defineProperty(stream, "emit", {value: observedEmit, writable: true, configurable: true});
          streamRestores.push(() => {
            if (stream.emit !== observedEmit) return;
            if (ownEmit) Object.defineProperty(stream, "emit", ownEmit);
            else delete stream.emit;
          });
        } catch { initialObservation.noteError("observer-fault"); }
      }
      if (child && typeof child.once === "function") {
        child.once("exit", () => emit("candidate", "exited"));
      }
    }
    return child;
  };

  fs.writeFileSync = function observedWriteFileSync(filePath, ...args) {
    const name = typeof filePath === "string" ? basename(filePath) : "";
    const receipt = current
      ? typeof filePath === "string" && resolve(filePath) === resolve(options.evidenceDir, `${options.label ?? `${options.platform}-${options.scenario}`}.receipt.json`)
      : name.endsWith(".receipt.json");
    const report = current
      ? typeof filePath === "string" && resolve(filePath) === resolve(options.evidenceDir, `${options.label ?? `${options.platform}-${options.scenario}`}.run.json`)
      : name.endsWith(".run.json");
    if (receipt) emit("receipt", "write-start");
    if (report) emit("run-record", "write-start");
    try {
      const result = originalWriteFileSync.call(this, filePath, ...args);
      if (receipt) emit("receipt", "finalized");
      if (report) emit("run-record", "finalized");
      return result;
    } catch (error) {
      if (receipt) emit("receipt", "write-failed");
      if (report) emit("run-record", "write-failed");
      throw error;
    }
  };
  syncBuiltinESMExports();
  return {
    emit,
    finish: status => { if (initialObservation) initialObservation.finish(status); },
    restore: () => {
      for (const restore of streamRestores) restore();
      childProcess.spawn = originalSpawn;
      fs.writeFileSync = originalWriteFileSync;
      syncBuiltinESMExports();
    },
  };
}

function verifyCurrentBytes(bytes, pin) {
  if (!pin || bytes.length !== pin.size || sha256(bytes) !== pin.sha256
      || crypto.createHash("sha1").update(Buffer.concat([
        Buffer.from(`blob ${bytes.length}\0`), bytes,
      ])).digest("hex") !== pin.blob) throw new Error("Current replay source binding differs");
}

function currentProfile(args) {
  if (args.currentArgs.size === 0) return null;
  const id = args.currentArgs.get(INTERNAL.profile);
  const profile = id === "nebular070" ? CURRENT_PROFILE : id === "nebular071" ? CURRENT071_PROFILE : null;
  if (!profile) throw new Error("Unknown current replay source profile");
  const expected = new Map([
    [INTERNAL.profile, profile.id], [INTERNAL.commit, profile.commit],
    [INTERNAL.tree, profile.tree],
    [INTERNAL.support, `package.json=${profile.support.sha256}`],
  ]);
  if (args.currentArgs.size !== expected.size
      || [...expected].some(([key, value]) => args.currentArgs.get(key) !== value)
      || basename(args.harnessPath) !== "native-rc-smoke.mjs"
      || args.expectedSha256 !== profile.modules["native-rc-smoke.mjs"].sha256) {
    throw new Error("Current replay profile binding differs");
  }
  const members = new Map();
  for (const raw of args.closureMembers) {
    const item = parseClosureMember(raw);
    if (members.has(item.name)) throw new Error("Current replay closure duplicated");
    members.set(item.name, item.expectedSha256);
  }
  const pins = profile.modules;
  if (members.size !== Object.keys(pins).length || [...members].some(([name, hash]) => pins[name]?.sha256 !== hash)) {
    throw new Error("Current replay closure differs");
  }
  const toolsRoot = dirname(resolve(args.harnessPath));
  for (const root of [toolsRoot, dirname(toolsRoot)]) {
    const info = fs.lstatSync(root);
    if (!info.isDirectory() || info.isSymbolicLink()) throw new Error("Current replay source root differs");
  }
  const supportPath = resolve(toolsRoot, "../package.json");
  const supportBytes = readHeldRegular(supportPath, profile.support.sha256);
  verifyCurrentBytes(supportBytes, profile.support);
  if (JSON.parse(supportBytes.toString("utf8")).version !== (profile.id === "nebular071" ? "0.7.1" : "0.7.0")) throw new Error("Current replay version differs");
  return { supportPath, supportBytes, profile };
}

function installCurrentSupport(current) {
  if (!current) return () => {};
  const originalRead = fs.readFileSync;
  fs.readFileSync = function heldSupportRead(path, options) {
    const name = path instanceof URL ? fileURLToPath(path) : typeof path === "string" ? resolve(path) : null;
    if (name === current.supportPath) {
      if (options === "utf8") return current.supportBytes.toString("utf8");
      if (options === undefined) return Buffer.from(current.supportBytes);
      throw new Error("Current replay support read differs");
    }
    return originalRead.call(this, path, options);
  };
  syncBuiltinESMExports();
  let restored = false;
  return () => {
    if (restored) return;
    restored = true;
    fs.readFileSync = originalRead;
    syncBuiltinESMExports();
  };
}

function initialObservationProfile(profile) {
  return {
    id: profile.id,
    source_commit: profile.commit,
    source_tree: profile.tree,
    harness_sha256: profile.modules["native-rc-smoke.mjs"].sha256,
    closure_sha256s: Object.fromEntries(Object.entries(profile.modules)
      .map(([name, pin]) => [name, pin.sha256])),
  };
}

function makeInitialObservation(path, profile) {
  const state = {
    schema: INITIAL_OBSERVATION_SCHEMA,
    attempt_kind: INITIAL_OBSERVATION_KIND,
    non_admitting: true,
    status: "observing",
    source_profile: initialObservationProfile(profile),
    phase_events: [],
    error_counts: {"observer-fault": 0, "stream-fault": 0, "write-failure": 0},
    error_category_counts: Object.fromEntries(INITIAL_ERROR_CATEGORIES.map(name => [name, 0])),
    helper_identifier_counts: Object.fromEntries(INITIAL_HELPER_IDENTIFIERS.map(name => [name, 0])),
    streams: {
      stdout: {bytes_seen: 0, bytes_hashed: 0, sha256: sha256(Buffer.alloc(0)), truncated: false},
      stderr: {bytes_seen: 0, bytes_hashed: 0, sha256: sha256(Buffer.alloc(0)), truncated: false},
    },
    truncated: false,
  };
  const hashes = {stdout: crypto.createHash("sha256"), stderr: crypto.createHash("sha256")};
  let disabled = false;
  let writing = false;
  let snapshotWrites = 0;
  let snapshotScheduled = false;
  let finished = false;
  const pending = {stdout: "", stderr: ""};

  const noteError = kind => {
    if (Object.prototype.hasOwnProperty.call(state.error_counts, kind)) state.error_counts[kind] += 1;
    else state.error_counts["observer-fault"] += 1;
    state.status = "partial";
  };

  const count = (table, name) => {
    if (table[name] < MAX_INITIAL_CATEGORY_COUNT) table[name] += 1;
    else state.truncated = true;
  };

  const classifyLine = line => {
    const text = line.toLowerCase();
    for (const [name, pattern] of INITIAL_ERROR_PATTERNS) {
      if (pattern.test(text)) count(state.error_category_counts, name);
    }
    for (const [name, pattern] of INITIAL_HELPER_PATTERNS) {
      if (pattern.test(text)) count(state.helper_identifier_counts, name);
    }
  };

  const scan = (name, text, final = false) => {
    const combined = pending[name] + text;
    const lines = combined.split(/\r?\n/);
    const tail = lines.pop() ?? "";
    if (final) {
      if (tail) lines.push(tail);
      pending[name] = "";
    } else {
      pending[name] = tail.slice(-INITIAL_SCAN_TAIL_CHARS);
    }
    for (const line of lines) classifyLine(line.replace(/\r$/, ""));
  };

  const snapshot = () => {
    const streams = {};
    for (const name of ["stdout", "stderr"]) {
      const row = state.streams[name];
      let digest = row.sha256;
      try { digest = hashes[name].copy().digest("hex"); } catch { noteError("stream-fault"); }
      streams[name] = {...row, sha256: digest};
    }
    return {...state, streams, phase_events: [...state.phase_events]};
  };

  const writeSnapshot = (final = false) => {
    const limit = final ? MAX_INITIAL_SNAPSHOT_WRITES : MAX_INITIAL_SNAPSHOT_WRITES - 1;
    if (disabled || writing || snapshotWrites >= limit) return;
    writing = true;
    snapshotWrites += 1;
    // Reserve one final write. A saturated live sink explicitly reports partial data.
    if (!final && snapshotWrites === MAX_INITIAL_SNAPSHOT_WRITES - 1) {
      state.truncated = true;
      state.status = "partial";
    }
    let temporary;
    let fd;
    try {
      const destination = resolve(path);
      try {
        const existing = fs.lstatSync(destination);
        if (!existing.isFile() || existing.isSymbolicLink()) throw new Error("Initial observation destination is not regular");
      } catch (error) {
        if (error?.code !== "ENOENT") throw error;
      }
      let value = snapshot();
      let bytes = Buffer.from(JSON.stringify(value) + "\n", "utf8");
      if (bytes.length > MAX_INITIAL_OBSERVATION_BYTES) {
        state.truncated = true;
        state.phase_events = state.phase_events.slice(0, 8);
        value = snapshot();
        bytes = Buffer.from(JSON.stringify(value) + "\n", "utf8");
      }
      if (bytes.length > MAX_INITIAL_OBSERVATION_BYTES) throw new Error("Initial observation output bound exceeded");
      temporary = `${destination}.tmp-${process.pid}`;
      fd = fs.openSync(temporary, fs.constants.O_WRONLY | fs.constants.O_CREAT
        | fs.constants.O_EXCL | O_NOFOLLOW, 0o600);
      const written = fs.writeSync(fd, bytes, 0, bytes.length);
      if (written !== bytes.length) throw new Error("Initial observation write was short");
      fs.closeSync(fd); fd = undefined;
      fs.renameSync(temporary, destination);
      temporary = undefined;
    } catch {
      disabled = true;
      noteError("write-failure");
    } finally {
      if (fd !== undefined) { try { fs.closeSync(fd); } catch { /* diagnostic only */ } }
      if (temporary !== undefined) { try { fs.unlinkSync(temporary); } catch { /* diagnostic only */ } }
      writing = false;
    }
  };

  const requestSnapshot = () => {
    if (disabled || finished || snapshotScheduled
        || snapshotWrites >= MAX_INITIAL_SNAPSHOT_WRITES - 1) return;
    snapshotScheduled = true;
    const timer = setTimeout(() => {
      snapshotScheduled = false;
      if (!finished) writeSnapshot();
    }, INITIAL_SNAPSHOT_INTERVAL_MS);
    timer.unref();
  };

  const addPhase = (stage, event) => {
    if (!FIXED_PROGRESS_EVENTS.has(`${stage}|${event}`)) return;
    if (state.phase_events.length >= MAX_PROGRESS_EVENTS) state.truncated = true;
    else state.phase_events.push({seq: state.phase_events.length + 1, stage, event});
    requestSnapshot();
  };

  const capture = (name, value) => {
    if (disabled || finished || state.streams[name].truncated) return;
    try {
      const bytes = Buffer.isBuffer(value) ? value : Buffer.from(value);
      const row = state.streams[name];
      const remaining = Math.max(0, MAX_INITIAL_STREAM_BYTES - row.bytes_hashed);
      let bounded = Buffer.alloc(0);
      if (remaining > 0) {
        bounded = bytes.subarray(0, remaining);
        hashes[name].update(bounded);
        row.bytes_hashed += bounded.length;
      }
      if (bounded.length > 0) scan(name, bounded.toString("utf8"));
      row.bytes_seen = Math.min(MAX_INITIAL_STREAM_BYTES + 1, row.bytes_seen + bytes.length);
      if (row.bytes_seen > MAX_INITIAL_STREAM_BYTES) {
        row.truncated = true;
        state.truncated = true;
      }
      requestSnapshot();
    } catch {
      noteError("stream-fault");
      requestSnapshot();
    }
  };

  writeSnapshot();
  return {
    addPhase,
    capture,
    noteError,
    finish: status => {
      if (finished) return;
      finished = true;
      scan("stdout", "", true);
      scan("stderr", "", true);
      state.status = status;
      writeSnapshot(true);
    },
  };
}

function writeLegacyError(error) {
  if (error && typeof error === "object" && error.finalization) {
    process.stderr.write(`${JSON.stringify({ finalization: error.finalization, reportWriteFamily: error.reportWriteFamily })}\n`);
  } else {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  }
}

function current071InitialTimeoutMs(options) {
  if (options.platform === "linux-x64" && options.scenario === "C-signal")
    return CURRENT071_SIGNAL_INITIAL_TIMEOUT_MS;
  return CURRENT071_REQUIRED_INITIAL_TIMEOUT_MS;
}

async function main() {
  const args = parseInternalArgs(process.argv.slice(2));
  const { harnessPath, progressPath, expectedSha256, closureMembers, forwarded,
    initialObservationKind, initialObservationPath } = args;
  const current = currentProfile(args);
  if (initialObservationKind !== undefined && !current)
    throw new Error("Initial observation requires the authenticated current profile");
  const closure = buildAuthenticatedClosure(harnessPath, expectedSha256, closureMembers, current);
  const options = current ? parseSmokeArgs(forwarded) : null;
  if (current && !((options.platform === "linux-x64" && ["C", "C-signal"].includes(options.scenario))
      || (options.platform === "linux-arm64" && options.scenario === "B"))) throw new Error("Current replay scenario differs");
  if (initialObservationKind !== undefined && options.timeoutMs !== undefined
      && !(current?.profile?.id === "nebular071"
        && options.timeoutMs === current071InitialTimeoutMs(options)))
    throw new Error("Initial observation timeout is not authorized for this source profile");
  const initialObservation = initialObservationKind === INITIAL_OBSERVATION_KIND
    ? makeInitialObservation(initialObservationPath, current.profile) : null;
  const restoreSupport = installCurrentSupport(current);
  const loader = installAuthenticatedLoader(closure);
  const observer = installProgressObservers(progressPath, current, options, initialObservation);
  let harness;
  let result;
  try {
    observer.emit("harness", "import-start");
    harness = await import(pathToFileURL(closure.entryPath).href);
    restoreSupport();
    observer.emit("harness", "imported");
    if (!harness || typeof harness.runSmoke !== "function") {
      observer.emit("harness", "export-missing");
      throw new Error("Released smoke harness export runSmoke is unavailable");
    }
    observer.emit("run-smoke", "enter");
    result = await harness.runSmoke(parseSmokeArgs(forwarded));
    observer.emit("run-smoke", "returned");
    observer.finish(result?.status === "pass" ? "completed" : "failed");
  } catch (error) {
    observer.emit(harness ? "run-smoke" : "harness", harness ? "error" : "import-failed");
    observer.finish("failed");
    throw error;
  } finally {
    loader.deregister();
    observer.restore();
    restoreSupport();
  }
  process.stdout.write(`${JSON.stringify({ label: result.label, status: result.status, problems: result.problems })}\n`);
  if (result.status !== "pass") process.exitCode = 1;
}

try {
  await main();
} catch (error) {
  writeLegacyError(error);
  process.exitCode = 1;
}
