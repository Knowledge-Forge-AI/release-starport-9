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

const PROGRESS_SCHEMA = "rs9.application-smoke-replay-progress.v1";
const MAX_PROGRESS_BYTES = 16 * 1024;
const MAX_PROGRESS_EVENTS = 32;
const MAX_HARNESS_BYTES = 4 * 1024 * 1024;
const MAX_CLOSURE_FILES = 8;
const MAX_CLOSURE_BYTES = 8 * 1024 * 1024;
const O_NOFOLLOW = fs.constants.O_NOFOLLOW;
const INTERNAL = Object.freeze({
  harness: "--rs9-replay-progress-harness",
  progress: "--rs9-replay-progress-file",
  expected: "--rs9-replay-progress-expected-sha256",
  closure: "--rs9-replay-progress-closure-member",
});

const sha256 = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");

function parseInternalArgs(argv) {
  let harnessPath;
  let progressPath;
  let expectedSha256;
  const closureMembers = [];
  const forwarded = [];
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (flag === INTERNAL.harness || flag === INTERNAL.progress || flag === INTERNAL.expected
        || flag === INTERNAL.closure) {
      if (value === undefined) throw new Error("Replay progress wrapper internal argument is incomplete");
      if (flag === INTERNAL.harness) harnessPath = value;
      if (flag === INTERNAL.progress) progressPath = value;
      if (flag === INTERNAL.expected) expectedSha256 = value;
      if (flag === INTERNAL.closure) closureMembers.push(value);
      index += 1;
    } else {
      forwarded.push(flag);
    }
  }
  if (typeof harnessPath !== "string" || typeof progressPath !== "string"
      || !/^[0-9a-f]{64}$/.test(expectedSha256 ?? "")) {
    throw new Error("Authenticated released smoke harness and progress sink are required");
  }
  return { harnessPath, progressPath, expectedSha256, closureMembers, forwarded };
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

function buildAuthenticatedClosure(harnessPath, expectedSha256, rawMembers) {
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
  if (expected.size > MAX_CLOSURE_FILES) throw new Error("Authenticated replay source closure is too large");

  const sources = new Map();
  const visited = new Set();
  let totalBytes = 0;
  const visit = (name) => {
    if (visited.has(name)) return;
    const path = closurePath(root, name);
    const bytes = readHeldRegular(path, expected.get(name));
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

function installProgressObservers(progressPath) {
  const originalSpawn = childProcess.spawn;
  const originalWriteFileSync = fs.writeFileSync;
  let sequence = 0;
  let launchObserved = false;
  const emit = (stage, event) => {
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
      emit("candidate", "launched");
      if (child && typeof child.once === "function") {
        child.once("exit", () => emit("candidate", "exited"));
      }
    }
    return child;
  };

  fs.writeFileSync = function observedWriteFileSync(filePath, ...args) {
    const name = typeof filePath === "string" ? basename(filePath) : "";
    const receipt = name.endsWith(".receipt.json");
    const report = name.endsWith(".run.json");
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
    restore: () => {
      childProcess.spawn = originalSpawn;
      fs.writeFileSync = originalWriteFileSync;
      syncBuiltinESMExports();
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

async function main() {
  const { harnessPath, progressPath, expectedSha256, closureMembers, forwarded } = parseInternalArgs(process.argv.slice(2));
  const closure = buildAuthenticatedClosure(harnessPath, expectedSha256, closureMembers);
  const loader = installAuthenticatedLoader(closure);
  const observer = installProgressObservers(progressPath);
  let harness;
  let result;
  try {
    observer.emit("harness", "import-start");
    harness = await import(pathToFileURL(closure.entryPath).href);
    observer.emit("harness", "imported");
    if (!harness || typeof harness.runSmoke !== "function") {
      observer.emit("harness", "export-missing");
      throw new Error("Released smoke harness export runSmoke is unavailable");
    }
    observer.emit("run-smoke", "enter");
    result = await harness.runSmoke(parseSmokeArgs(forwarded));
    observer.emit("run-smoke", "returned");
  } catch (error) {
    observer.emit(harness ? "run-smoke" : "harness", harness ? "error" : "import-failed");
    throw error;
  } finally {
    loader.deregister();
    observer.restore();
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
