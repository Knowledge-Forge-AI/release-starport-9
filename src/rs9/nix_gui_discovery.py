"""Optional bounded GUI-store discovery inside the authenticated Nix FHS.

This module is diagnostic-only. It observes only source-bound Nix-store roots
and never changes the FHS environment, product payload, qualification gates, or
smoke command.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Mapping, Sequence

from rs9.errors import ContractError
from rs9.scratch import canonical

SCHEMA = "rs9.nix-fhs-gui-observation.v1"
FACTS_SCHEMA = "rs9.nix-fhs-gui-discovery.v1"
_ROLES = ("glib", "gtk", "webkit", "pixbuf")
_CATEGORIES = (
    "helper", "libexec", "gio-module", "gsettings-schema",
    "pixbuf-loader", "font", "data",
)
_STORE_ROOT = re.compile(
    r"^/nix/store/[0-9a-df-np-sv-z]{32}-[A-Za-z0-9+._?=-]+$"
)
_STORE_PATH = re.compile(
    r"^/nix/store/[0-9a-df-np-sv-z]{32}-[A-Za-z0-9+._?=-]+(?:/.*)?$"
)
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_MAX_OUTPUT_BYTES = 4 * 1024 * 1024
_MAX_CUSTODY_BYTES = 64 * 1024
_MAX_SAMPLE_RECORDS = len(_ROLES) * len(_CATEGORIES)
_CREDENTIAL_WORDS = (
    "token", "password", "secret", "cookie", "authorization", "credential",
    "private_key", "privatekey",
)

# This is deliberately a Node standard-library script: it is supplied through
# the -e argument to the already-pinned nodejs_22 inside the existing FHS and
# receives only the closed request JSON on stdin. A pure test may inject an
# in-memory fs/path/crypto double through __RS9_FS_DOUBLE__; production never
# sets that hook. The production path has no module, shell, environment,
# subprocess, or network access beyond these standard-library primitives.
NODE_FS_SOURCE = r"""
const injected = globalThis.__RS9_FS_DOUBLE__;
const fs = injected?.fs ?? require('node:fs');
const path = injected?.path ?? require('node:path');
const crypto = injected?.crypto ?? require('node:crypto');
const output = injected?.output ?? process.stdout;

const STORE_ROOT = /^\/nix\/store\/[0-9a-df-np-sv-z]{32}-[A-Za-z0-9+._?=-]+$/;
const STORE_PATH = /^\/nix\/store\/[0-9a-df-np-sv-z]{32}-[A-Za-z0-9+._?=-]+(?:\/.*)?$/;
const CATEGORIES = new Set(['helper', 'libexec', 'gio-module', 'gsettings-schema', 'pixbuf-loader', 'font', 'data']);
const ROLES = ['glib', 'gtk', 'webkit', 'pixbuf'];
const SAMPLE_LIMIT_PER_CATEGORY = 1;
const MAX_SAMPLE_RECORDS = ROLES.length * CATEGORIES.size;
const DESCENT_ANCHORS = new Set([
  'libexec', 'gio', 'gsettings-schemas', 'glib-2.0', 'gdk-pixbuf-2.0', 'fonts',
]);
function newCategorySummary() {
  const summary = {};
  for (const role of ROLES) {
    summary[role] = {};
    for (const categoryName of CATEGORIES)
      summary[role][categoryName] = {observed: 0, sampled: 0};
  }
  return summary;
}
const state = {
  roots: {},
  records: [],
  samples: [],
  sampleKeys: new Set(),
  prunedDirectories: 0,
  category_summary: newCategorySummary(),
  totals: {entries: 0, read_bytes: 0, skipped_uncategorized: 0, skipped_oversize: 0},
  truncated: null,
};
let input;
let phase = 'request';

class ObservationStop extends Error {
  constructor(reason, fatal = false) { super(reason); this.reason = reason; this.fatal = fatal; }
}
class ContractFailure extends Error {
  constructor(reason) { super(reason); this.reason = reason; }
}
function stop(reason, fatal = false) {
  if (!state.truncated) state.truncated = {reason};
  throw new ObservationStop(reason, fatal);
}
function fail(reason) { throw new ContractFailure(reason); }
function safeInteger(value, reason) {
  if (typeof value === 'bigint') {
    if (value < 0n || value > BigInt(Number.MAX_SAFE_INTEGER)) fail(reason);
    return Number(value);
  }
  if (!Number.isSafeInteger(value) || value < 0) fail(reason);
  return value;
}
function timeNs(ns, ms, reason) {
  const maximum = (1n << 63n) - 1n;
  let value;
  if (ns !== undefined) {
    if (typeof ns === 'bigint') value = ns;
    else if (Number.isSafeInteger(ns)) value = BigInt(ns);
    else fail(reason);
  } else if (typeof ms === 'bigint') {
    value = ms * 1000000n;
  } else if (Number.isFinite(ms) && ms >= 0 && Number.isSafeInteger(Math.trunc(ms))) {
    // Only the sub-millisecond remainder is converted as Number; never epoch ns.
    value = BigInt(Math.trunc(ms)) * 1000000n + BigInt(Math.round((ms % 1) * 1e6));
  } else fail(reason);
  if (value < 0n || value > maximum) fail(reason);
  return value.toString();
}
function statOptions() { return {bigint: true}; }
function lstat(name) { return fs.lstatSync(name, statOptions()); }
function fstat(fd) { return fs.fstatSync(fd, statOptions()); }
function frame(stat) {
  return {
    dev: safeInteger(stat.dev, 'invalid-stat'), ino: safeInteger(stat.ino, 'invalid-stat'),
    size: safeInteger(stat.size, 'invalid-stat'), mode: safeInteger(stat.mode, 'invalid-stat'),
    mtimeNs: timeNs(stat.mtimeNs, stat.mtimeMs, 'invalid-stat-time'),
    ctimeNs: timeNs(stat.ctimeNs, stat.ctimeMs, 'invalid-stat-time'),
    uid: safeInteger(stat.uid, 'invalid-stat'), gid: safeInteger(stat.gid, 'invalid-stat'),
    nlink: safeInteger(stat.nlink, 'invalid-stat'),
  };
}
function sameFrame(left, right) {
  return JSON.stringify(frame(left)) === JSON.stringify(frame(right));
}
function sha256(bytes) { return crypto.createHash('sha256').update(bytes).digest('hex'); }
function storeRoot(value) {
  if (typeof value !== 'string' || !STORE_ROOT.test(value) || value.includes('..'))
    fail('invalid-store-root');
  return value;
}
function storePath(value) {
  if (typeof value !== 'string' || !STORE_PATH.test(value) || value.includes('..'))
    fail('store-path-escape');
  return value;
}
function inside(root, value) { return value === root || value.startsWith(`${root}/`); }
function insideClosure(roots, value) { return roots.some((root) => inside(root, value)); }
function executable(stat) { return (safeInteger(stat.mode, 'invalid-stat') & 0o111) !== 0; }
function category(relative, stat, directory = false) {
  const parts = relative.split('/').filter(Boolean).map((item) => item.toLowerCase());
  const base = parts[parts.length - 1] || '';
  const categories = new Set();
  if (parts.includes('libexec')) categories.add('libexec');
  if (parts.includes('libexec') && executable(stat)) categories.add('helper');
  if (parts.includes('gio') && parts.includes('modules')) categories.add('gio-module');
  if (parts.includes('gsettings-schemas') || (parts.includes('glib-2.0') && parts.includes('schemas')))
    categories.add('gsettings-schema');
  if (parts.includes('gdk-pixbuf-2.0') && parts.includes('loaders')) categories.add('pixbuf-loader');
  if (parts.includes('fonts') || /\.(ttf|otf|woff2?)$/.test(base)) categories.add('font');
  // A broad share tree is represented by directory presence only. Locale,
  // documentation, and other data files are not read or hashed wholesale.
  if (directory && parts.includes('share')) categories.add('data');
  return [...categories].filter((item) => CATEGORIES.has(item)).sort();
}
function noteRecord(record) {
  const summary = state.category_summary[record.role];
  for (const categoryName of record.categories) summary[categoryName].observed += 1;
  if (record.type !== 'regular' && record.type !== 'symlink') return;
  if (state.samples.length >= MAX_SAMPLE_RECORDS) return;
  const key = `${record.role}\u0000${record.path}`;
  if (state.sampleKeys.has(key)) return;
  if (!record.categories.some((categoryName) =>
      summary[categoryName].sampled < SAMPLE_LIMIT_PER_CATEGORY)) return;
  state.samples.push(record);
  state.sampleKeys.add(key);
  for (const categoryName of record.categories)
    summary[categoryName].sampled += 1;
}
function resolveChain(start, closureRoots) {
  let current = storePath(path.resolve(start));
  if (!insideClosure(closureRoots, current)) stop('symlink-closure-escape', true);
  const seen = new Set();
  const chain = [];
  for (let hop = 0; hop <= input.limits.max_symlink_hops; hop += 1) {
    if (seen.has(current)) stop('symlink-cycle', true);
    seen.add(current);
    const before = lstat(current);
    if (!before.isSymbolicLink()) return {terminal: current, chain};
    const target = fs.readlinkSync(current);
    if (typeof target !== 'string' || target.length > 4096 || target.includes('\0'))
      stop('invalid-symlink-target', true);
    const next = storePath(path.resolve(path.dirname(current), target));
    if (!insideClosure(closureRoots, next)) stop('symlink-closure-escape', true);
    chain.push({path: current, target, full9: frame(before), target_sha256: sha256(Buffer.from(target))});
    current = next;
  }
  stop('symlink-depth', true);
}
function readRegular(absolute, expected, remaining) {
  if (expected > input.limits.max_file_bytes) return {skipped: 'file-bound'};
  if (expected > remaining) return {skipped: 'read-byte-bound'};
  const noFollow = fs.constants && fs.constants.O_NOFOLLOW;
  if (!noFollow || !fs.constants.O_NONBLOCK) stop('nofollow-unavailable', true);
  const fd = fs.openSync(absolute, fs.constants.O_RDONLY | noFollow | fs.constants.O_NONBLOCK);
  try {
    const before = fstat(fd);
    if (!before.isFile() || safeInteger(before.size, 'invalid-stat') !== expected)
      stop('file-changed', true);
    const bytes = Buffer.alloc(expected);
    let offset = 0;
    while (offset < expected) {
      const count = fs.readSync(fd, bytes, offset, expected - offset, offset);
      if (!Number.isInteger(count) || count <= 0) stop('file-read-short', true);
      offset += count;
    }
    const after = fstat(fd);
    if (!sameFrame(before, after)) stop('file-changed', true);
    return {bytes, full9: frame(after)};
  } finally {
    fs.closeSync(fd);
  }
}
function addRecord(record) {
  if (state.records.length >= input.limits.max_entries) stop('entry-bound');
  state.records.push(record);
  noteRecord(record);
}
function descentPriority(relative) {
  if (relative === 'share') return 0;
  const parts = relative.split('/').filter(Boolean);
  if (parts.some((part) => DESCENT_ANCHORS.has(part))) return 0;
  if (parts.includes('lib')) return 1;
  return 2;
}
function shouldDescend(relative) {
  if (relative === 'share') return true;
  const parts = relative.split('/').filter(Boolean);
  if (!parts.includes('share')) return true;
  return parts.some((part) => DESCENT_ANCHORS.has(part));
}
function enqueueDirectory(queue, item) {
  queue.push(item);
  queue.sort((left, right) => descentPriority(left.relative) - descentPriority(right.relative)
    || (left.relative < right.relative ? -1 : left.relative > right.relative ? 1 : 0));
}
function loadCurrentDirectory(rootState) {
  while (!rootState.current || rootState.current.index >= rootState.current.children.length) {
    rootState.current = null;
    if (!rootState.queue.length) return false;
    const current = rootState.queue.shift();
    let children;
    try {
      children = [...fs.readdirSync(current.absolute, {withFileTypes: true})].sort((left, right) =>
        left.name < right.name ? -1 : left.name > right.name ? 1 : 0);
    } catch (_) { stop('directory-read-failed', true); }
    rootState.current = {absolute: current.absolute, relative: current.relative, children, index: 0};
  }
  return true;
}
function scanEntry(rootState, closureRoots) {
  if (!loadCurrentDirectory(rootState)) return false;
  const current = rootState.current;
  const child = current.children[current.index];
  current.index += 1;
  if (current.index >= current.children.length) rootState.current = null;
  state.totals.entries += 1;
  if (state.totals.entries > input.limits.max_entries) stop('entry-bound');
  if (typeof child.name !== 'string' || !child.name || child.name === '.' || child.name === '..'
      || child.name.includes('\0') || child.name.length > 512)
    stop('invalid-entry-name', true);
  const relative = current.relative ? `${current.relative}/${child.name}` : child.name;
  if (relative.length > 4096) stop('entry-path-bound', true);
  const absolute = path.join(current.absolute, child.name);
  let stat;
  try { stat = lstat(absolute); } catch (_) { stop('entry-disappeared', true); }
  if (stat.isSymbolicLink()) {
    const categories = category(relative, stat);
    if (!categories.length) { state.totals.skipped_uncategorized += 1; return true; }
    const resolved = resolveChain(absolute, closureRoots);
    let terminal;
    try { terminal = lstat(resolved.terminal); } catch (_) { stop('symlink-target-missing', true); }
    addRecord({role: rootState.role, path: relative, categories, type: 'symlink', full9: frame(stat),
      chain: resolved.chain, terminal: {path: resolved.terminal, full9: frame(terminal), regular: terminal.isFile()}});
    return true;
  }
  if (stat.isDirectory()) {
    const categories = category(relative, stat, true);
    if (categories.length) {
      const record = {role: rootState.role, path: relative, categories, type: 'directory', full9: frame(stat)};
      // Keep the share root and category-bearing directories, but count
      // broad data-only children without retaining locale/theme noise.
      if (relative === 'share' || categories.some((item) => item !== 'data')) addRecord(record);
      else noteRecord(record);
    }
    if (shouldDescend(relative)) enqueueDirectory(rootState.queue, {absolute, relative});
    else state.prunedDirectories += 1;
    return true;
  }
  if (!stat.isFile()) { state.totals.skipped_uncategorized += 1; return true; }
  const categories = category(relative, stat);
  if (!categories.length) { state.totals.skipped_uncategorized += 1; return true; }
  const expected = safeInteger(stat.size, 'invalid-stat');
  const read = readRegular(absolute, expected, input.limits.max_bytes - state.totals.read_bytes);
  if (read.skipped) {
    state.totals.skipped_oversize += 1;
    addRecord({role: rootState.role, path: relative, categories, type: 'regular', full9: frame(stat),
      read: false, reason: read.skipped});
    if (read.skipped === 'read-byte-bound') stop('read-byte-bound');
    return true;
  }
  state.totals.read_bytes += read.bytes.length;
  addRecord({role: rootState.role, path: relative, categories, type: 'regular', full9: read.full9,
    read: true, sha256: sha256(read.bytes)});
  return true;
}
function observeRoots(roots, closureRoots) {
  const states = ROLES.map((role) => ({role, queue: [{absolute: roots[role].path, relative: ''}]}));
  let active = true;
  while (active) {
    active = false;
    for (const rootState of states) {
      if (scanEntry(rootState, closureRoots)) active = true;
    }
  }
}
function emit(status, reason = null) {
  for (const role of ROLES) {
    if (state.roots[role])
      state.roots[role].records = state.records.filter((item) => item.role === role).length;
  }
  const result = {schema: 'rs9.nix-fhs-gui-observation.v1', status,
    roots: state.roots, totals: state.totals, categories: input.categories,
    category_summary: state.category_summary, category_summary_complete: false,
    samples: state.samples, records: state.records};
  if (state.truncated || reason) result.truncated = state.truncated || {reason};
  let encoded = JSON.stringify(result);
  if (Buffer.byteLength(encoded, 'utf8') > 4 * 1024 * 1024) {
    result.status = 'partial';
    result.records = [];
    for (const root of Object.values(result.roots)) root.records = 0;
    result.truncated = {reason: 'output-bound', records_dropped: true};
    encoded = JSON.stringify(result);
  }
  output.write(encoded);
}

try {
  input = JSON.parse(fs.readFileSync(0, 'utf8'));
  if (input.schema !== 'rs9.nix-fhs-gui-discovery-request.v1'
      || !input.roots || typeof input.roots !== 'object'
      || !Array.isArray(input.closure_roots) || !input.limits
      || !Array.isArray(input.categories) || input.categories.some((item) => !CATEGORIES.has(item)))
    fail('invalid-request');
  const closureRoots = [...new Set(input.closure_roots.map(storeRoot))];
  if (!closureRoots.length || closureRoots.length !== input.closure_roots.length)
    fail('invalid-closure-roots');
  for (const key of ['max_entries', 'max_bytes', 'max_file_bytes', 'max_symlink_hops']) {
    if (!Number.isSafeInteger(input.limits[key]) || input.limits[key] <= 0) fail('invalid-limits');
  }
  if (input.limits.max_entries > 4096 || input.limits.max_bytes > 64 * 1024 * 1024
      || input.limits.max_file_bytes > 4 * 1024 * 1024
      || input.limits.max_symlink_hops > 16) fail('invalid-limits');
  const roots = {};
  for (const role of ROLES) {
    const root = storeRoot(input.roots[role]);
    if (!insideClosure(closureRoots, root)) fail('root-outside-closure');
    let stat;
    try { stat = lstat(root); } catch (_) { fail('root-missing'); }
    if (!stat.isDirectory()) fail('root-not-directory');
    roots[role] = {path: root, full9: frame(stat), records: 0};
  }
  state.roots = roots;
  phase = 'observe';
  observeRoots(roots, closureRoots);
  for (const role of ROLES)
    roots[role].records = state.records.filter((item) => item.role === role).length;
  if (state.prunedDirectories > 0) emit('partial', 'category-pruned');
  else emit('pass');
} catch (error) {
  if (error instanceof ObservationStop) {
    // Bounds retain typed partial facts; custody/identity failures remain fatal.
    if (error.fatal)
      output.write(JSON.stringify({schema: 'rs9.nix-fhs-gui-observation.v1', status: 'fail', reason: error.reason}));
    else
      emit('partial', error.reason);
  } else if (error instanceof ContractFailure) {
    output.write(JSON.stringify({schema: 'rs9.nix-fhs-gui-observation.v1', status: 'fail', reason: error.reason}));
  } else {
    output.write(JSON.stringify({schema: 'rs9.nix-fhs-gui-observation.v1', status: 'fail', reason: 'observation-failed'}));
  }
}
"""


def _store_root(value: Any) -> str:
    if not isinstance(value, str) or "\x00" in value or not _STORE_ROOT.fullmatch(value):
        raise ValueError("invalid store root")
    return value


def _store_path(value: Any, *, suffix: str | None = None) -> str:
    if not isinstance(value, str) or "\x00" in value or ".." in value.split("/"):
        raise ValueError("invalid store path")
    if not _STORE_PATH.fullmatch(value):
        raise ValueError("invalid store path")
    if suffix is not None and not value.endswith(suffix):
        raise ValueError("invalid store executable")
    return value


def _discovery_request(facts: Mapping[str, Any]) -> dict[str, Any]:
    value = facts.get("gui_discovery")
    if not isinstance(value, Mapping) or set(value) != {
            "schema", "roots", "closure_roots", "max_entries", "max_bytes",
            "max_file_bytes", "max_symlink_hops", "categories"}:
        raise ValueError("closed GUI discovery facts required")
    if value.get("schema") != FACTS_SCHEMA:
        raise ValueError("GUI discovery schema mismatch")
    roots = value.get("roots")
    if not isinstance(roots, Mapping) or set(roots) != set(_ROLES):
        raise ValueError("closed GUI discovery roots required")
    checked_roots = {role: _store_root(roots[role]) for role in _ROLES}
    closure = value.get("closure_roots")
    if (not isinstance(closure, list) or not closure
            or any(not isinstance(item, str) for item in closure)):
        raise ValueError("closed GUI discovery closure required")
    checked_closure = sorted({_store_root(item) for item in closure})
    if any(root not in checked_closure for root in checked_roots.values()):
        raise ValueError("GUI discovery root outside closure")
    limits = {key: value.get(key) for key in (
        "max_entries", "max_bytes", "max_file_bytes", "max_symlink_hops")}
    if any(type(item) is not int or item <= 0 for item in limits.values()):
        raise ValueError("bounded GUI discovery limits required")
    if (limits["max_entries"] > 4096 or limits["max_bytes"] > 64 * 1024 * 1024
            or limits["max_file_bytes"] > 4 * 1024 * 1024
            or limits["max_symlink_hops"] > 16):
        raise ValueError("GUI discovery bound exceeds contract")
    categories = value.get("categories")
    if categories != list(_CATEGORIES):
        raise ValueError("closed GUI discovery categories required")
    node = _store_path(facts.get("node"), suffix="/bin/node")
    return {"schema": "rs9.nix-fhs-gui-discovery-request.v1", "roots": checked_roots,
            "closure_roots": checked_closure, "limits": limits,
            "categories": list(_CATEGORIES), "node": node}


def _check_metadata(value: Any, *, depth: int = 0, key: str = "") -> None:
    if depth > 12:
        raise ValueError("observation metadata depth bound")
    if isinstance(value, Mapping):
        if len(value) > 4096:
            raise ValueError("observation metadata map bound")
        for name, item in value.items():
            if (not isinstance(name, str) or len(name) > 128
                    or any(word in name.lower() for word in _CREDENTIAL_WORDS)):
                raise ValueError("observation metadata key refused")
            _check_metadata(item, depth=depth + 1, key=name)
        return
    if isinstance(value, list):
        if len(value) > 4096:
            raise ValueError("observation metadata list bound")
        for item in value:
            _check_metadata(item, depth=depth + 1, key=key)
        return
    if isinstance(value, str):
        if len(value) > 4096 or "\x00" in value:
            raise ValueError("observation metadata string bound")
        if value.startswith("/") and not _STORE_PATH.fullmatch(value):
            raise ValueError("observation path outside store")
        return
    if isinstance(value, (bool, int)) or value is None:
        return
    raise ValueError("observation metadata type refused")


def _valid_full9(value: Any) -> bool:
    keys = {"dev", "ino", "size", "mode", "mtimeNs", "ctimeNs", "uid", "gid", "nlink"}
    if not isinstance(value, Mapping) or set(value) != keys:
        return False
    for key, item in value.items():
        if key in {"mtimeNs", "ctimeNs"}:
            if (not isinstance(item, str) or not re.fullmatch(r"0|[1-9][0-9]{0,18}", item)
                    or int(item) > 2**63 - 1):
                return False
        elif type(item) is not int or not 0 <= item <= 2**53 - 1:
            return False
    return True


def _validate_observation(result: Any) -> None:
    if not isinstance(result, Mapping) or result.get("schema") != SCHEMA:
        raise ValueError("observation schema mismatch")
    status = result.get("status")
    if status == "fail":
        if set(result) != {"schema", "status", "reason"} or not isinstance(result.get("reason"), str):
            raise ValueError("closed failure observation required")
        _check_metadata(result)
        return
    if status not in {"pass", "partial"}:
        raise ValueError("observation status mismatch")
    required = {"schema", "status", "roots", "totals", "categories", "records"}
    allowed = required | {"truncated", "category_summary", "category_summary_complete", "samples"}
    if set(result) - allowed or not required <= set(result):
        raise ValueError("closed observation required")
    if status == "partial" and not isinstance(result.get("truncated"), Mapping):
        raise ValueError("partial observation truncation required")
    roots = result.get("roots")
    if not isinstance(roots, Mapping) or set(roots) - set(_ROLES):
        raise ValueError("observation roots mismatch")
    if status == "pass" and set(roots) != set(_ROLES):
        raise ValueError("complete observation roots required")
    full9_keys = {"dev", "ino", "size", "mode", "mtimeNs", "ctimeNs", "uid", "gid", "nlink"}
    for role, root in roots.items():
        if (not isinstance(root, Mapping)
                or set(root) != {"path", "full9", "records"}
                or not isinstance(root.get("path"), str)
                or not _STORE_ROOT.fullmatch(root["path"])
                or not _valid_full9(root.get("full9"))
                or type(root.get("records")) is not int or root["records"] < 0):
            raise ValueError(f"observation root {role} mismatch")
    totals = result.get("totals")
    if (not isinstance(totals, Mapping)
            or set(totals) != {"entries", "read_bytes", "skipped_uncategorized", "skipped_oversize"}
            or any(type(totals.get(key)) is not int or totals[key] < 0 for key in totals)):
        raise ValueError("observation totals mismatch")
    if result.get("categories") != list(_CATEGORIES) or not isinstance(result.get("records"), list):
        raise ValueError("observation categories mismatch")
    if len(result["records"]) > 4096:
        raise ValueError("observation records bound")
    for record in result["records"]:
        _validate_record(record, full9_keys)
    projection_fields = {"category_summary", "category_summary_complete", "samples"}
    if projection_fields & set(result):
        if projection_fields - set(result):
            raise ValueError("observation projection fields incomplete")
        _validate_category_summary(result["category_summary"])
        if result["category_summary_complete"] is not False:
            raise ValueError("observation category summary must remain partial")
        samples = result["samples"]
        if not isinstance(samples, list) or len(samples) > _MAX_SAMPLE_RECORDS:
            raise ValueError("observation sample bound")
        for sample in samples:
            if not isinstance(sample, Mapping) or sample.get("type") not in {"regular", "symlink"}:
                raise ValueError("observation sample kind mismatch")
            _validate_record(sample, full9_keys)
    if "truncated" in result:
        truncated = result["truncated"]
        if (not isinstance(truncated, Mapping)
                or set(truncated) - {"reason", "records_dropped", "samples_dropped"}
                or not isinstance(truncated.get("reason"), str)
                or ("records_dropped" in truncated and type(truncated["records_dropped"]) is not bool)
                or ("samples_dropped" in truncated and type(truncated["samples_dropped"]) is not bool)):
            raise ValueError("observation truncation mismatch")
    _check_metadata(result)


def _validate_category_summary(value: Any) -> None:
    if not isinstance(value, Mapping) or set(value) != set(_ROLES):
        raise ValueError("observation category summary roles mismatch")
    for role in _ROLES:
        row = value[role]
        if not isinstance(row, Mapping) or set(row) != set(_CATEGORIES):
            raise ValueError("observation category summary categories mismatch")
        for category in _CATEGORIES:
            counts = row[category]
            if (not isinstance(counts, Mapping) or set(counts) != {"observed", "sampled"}
                    or type(counts["observed"]) is not int or counts["observed"] < 0
                    or type(counts["sampled"]) is not int or counts["sampled"] < 0
                    or counts["sampled"] > counts["observed"]):
                raise ValueError("observation category summary counts mismatch")


def _sampled_category_summary(value: Mapping[str, Any], samples: list[Any]) -> dict[str, Any]:
    return {
        role: {
            category: {
                **value[role][category],
                "sampled": sum(
                    1 for sample in samples
                    if sample.get("role") == role and category in sample.get("categories", [])
                ),
            }
            for category in _CATEGORIES
        }
        for role in _ROLES
    }


def _validate_record(record: Any, full9_keys: set[str]) -> None:
    if not isinstance(record, Mapping):
        raise ValueError("observation record type mismatch")
    common = {"role", "path", "categories", "type", "full9"}
    if (not common <= set(record) or record.get("role") not in _ROLES
            or not isinstance(record.get("path"), str)
            or record["path"].startswith("/") or ".." in record["path"].split("/")
            or len(record["path"]) > 4096
            or not isinstance(record.get("categories"), list)
            or any(not isinstance(item, str) or item not in _CATEGORIES for item in record["categories"])
            or record["categories"] != sorted(set(record["categories"]))
            or not _valid_full9(record.get("full9"))):
        raise ValueError("observation record common fields mismatch")
    kind = record["type"]
    if kind == "directory":
        if set(record) != common:
            raise ValueError("observation directory fields mismatch")
        return
    if kind == "regular":
        if set(record) - (common | {"read", "sha256", "reason"}) or type(record.get("read")) is not bool:
            raise ValueError("observation regular fields mismatch")
        if record["read"]:
            if set(record) != common | {"read", "sha256"} or not _HEX64.fullmatch(str(record["sha256"])):
                raise ValueError("observation regular digest mismatch")
        elif (set(record) != common | {"read", "reason"}
              or record["reason"] not in {"file-bound", "read-byte-bound"}):
            raise ValueError("observation regular bound mismatch")
        return
    if kind == "symlink":
        if set(record) != common | {"chain", "terminal"} or not isinstance(record["chain"], list):
            raise ValueError("observation symlink fields mismatch")
        for link in record["chain"]:
            if (not isinstance(link, Mapping) or set(link) != {"path", "target", "full9", "target_sha256"}
                    or not isinstance(link["path"], str) or not _STORE_PATH.fullmatch(link["path"])
                    or not isinstance(link["target"], str) or len(link["target"]) > 4096
                    or not _valid_full9(link["full9"])
                    or not _HEX64.fullmatch(str(link["target_sha256"]))):
                raise ValueError("observation symlink chain mismatch")
        terminal = record["terminal"]
        if (not isinstance(terminal, Mapping) or set(terminal) != {"path", "full9", "regular"}
                or not isinstance(terminal["path"], str) or not _STORE_PATH.fullmatch(terminal["path"])
                or not _valid_full9(terminal["full9"])
                or type(terminal["regular"]) is not bool):
            raise ValueError("observation symlink terminal mismatch")
        return
    raise ValueError("observation record kind mismatch")


def _write_record(destination: Path, record: Mapping[str, Any]) -> dict[str, Any]:
    """Preflight the existing custody contract; optional output never admits a gate."""
    from rs9.hosted_custody import diagnostic_bytes
    temporary = None
    try:
        encoded = canonical(record)
        observed = record.get("result")
        if len(encoded) > _MAX_CUSTODY_BYTES and isinstance(observed, Mapping) and observed.get("status") in {"pass", "partial"}:
            # Keep a deterministic prefix that fits the existing diagnostic
            # custody budget, including canonical whitespace and outer fields.
            retained = list(observed["records"])
            retained_samples = list(observed.get("samples", []))
            records_dropped = False
            samples_dropped = False
            while True:
                if retained:
                    retained = retained[:len(retained) // 2]
                    records_dropped = True
                elif retained_samples:
                    retained_samples = retained_samples[:len(retained_samples) // 2]
                    samples_dropped = True
                else:
                    break
                truncation = {"reason": "output-bound", "records_dropped": records_dropped}
                if "samples" in observed:
                    truncation["samples_dropped"] = samples_dropped
                reduced = {**observed, "status": "partial", "records": retained,
                    "roots": {role: {**root, "records": sum(row["role"] == role for row in retained)}
                              for role, root in observed["roots"].items()},
                    "truncated": truncation}
                if "samples" in observed:
                    reduced["samples"] = retained_samples
                    if "category_summary" in observed:
                        reduced["category_summary"] = _sampled_category_summary(
                            observed["category_summary"], retained_samples
                        )
                record = {**record, "result": reduced,
                          "status": "partial" if record.get("status") in {"pass", "partial"} else "fail"}
                encoded = canonical(record)
                if len(encoded) <= _MAX_CUSTODY_BYTES or (not retained and not retained_samples):
                    break
        if len(encoded) > _MAX_CUSTODY_BYTES or destination.is_symlink():
            raise OSError("diagnostic output unavailable")
        fd, name = tempfile.mkstemp(prefix=".rs9-gui-discovery-", suffix=".json", dir=destination.parent)
        temporary = Path(name)
        with os.fdopen(fd, "wb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise OSError("regular diagnostic output required")
            stream.write(encoded)
        try:
            diagnostic_bytes(temporary)
        except ContractError as error:
            # The existing privacy/size policy stays authoritative. A rejected
            # optional observation becomes a small, admissible failure record.
            record = {"schema": SCHEMA, "status": "fail", "diagnostic_only": True,
                      "reason": "diagnostic-custody-withheld", "custody_reason": error.code}
            temporary.write_bytes(canonical(record))
            diagnostic_bytes(temporary)
        os.replace(temporary, destination)
        temporary = None
        return dict(record)
    except (OSError, ContractError):
        return {"schema": SCHEMA, "status": "fail", "diagnostic_only": True,
                "reason": "diagnostic-output-unavailable"}
    finally:
        if temporary is not None:
            try:
                temporary.unlink()
            except OSError:
                pass


def record_fhs_gui_discovery(
    facts: Mapping[str, Any], prefix: Sequence[str], runtime_prefix: Sequence[str],
    env: Mapping[str, str], destination: Path,
) -> dict[str, Any]:
    """Record bounded store-only discovery without affecting any production gate."""
    script_sha256 = hashlib.sha256(NODE_FS_SOURCE.encode("utf-8")).hexdigest()
    try:
        request = _discovery_request(facts)
    except (TypeError, ValueError, KeyError):
        record = {"schema": SCHEMA, "status": "fail", "diagnostic_only": True,
                  "reason": "invalid-source-bound-facts", "script_sha256": script_sha256}
        return _write_record(destination, record)
    input_bytes = canonical(request)
    request_sha256 = hashlib.sha256(input_bytes).hexdigest()
    argv = [*prefix, *runtime_prefix, request["node"], "--input-type=commonjs",
            "-e", NODE_FS_SOURCE]
    try:
        completed = subprocess.run(argv, env=dict(env), input=input_bytes,
                                   capture_output=True, timeout=30)
        stdout = completed.stdout if isinstance(completed.stdout, bytes) else b""
        stderr = completed.stderr if isinstance(completed.stderr, bytes) else b""
        if len(stdout) > _MAX_OUTPUT_BYTES or len(stderr) > 64 * 1024:
            raise ValueError("diagnostic stream bound exceeded")
        result = json.loads(stdout) if stdout else {
            "schema": SCHEMA, "status": "fail", "reason": "empty-observation"}
        _validate_observation(result)
        inner_status = result["status"]
        status = "fail" if completed.returncode != 0 or stderr or inner_status == "fail" else inner_status
        record = {
            "schema": SCHEMA, "status": status, "diagnostic_only": True,
            "script_sha256": script_sha256, "request_sha256": request_sha256,
            "exit_code": completed.returncode, "stdout_bytes": len(stdout),
            "stdout_sha256": hashlib.sha256(stdout).hexdigest(), "stderr_bytes": len(stderr),
            "stderr_sha256": hashlib.sha256(stderr).hexdigest(), "result": result,
        }
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError, RecursionError):
        record = {"schema": SCHEMA, "status": "fail", "diagnostic_only": True,
                  "reason": "bounded-observation-unavailable", "script_sha256": script_sha256,
                  "request_sha256": request_sha256}
    return _write_record(destination, record)
