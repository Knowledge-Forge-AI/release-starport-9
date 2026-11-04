"""Contract checks for bounded current071 APT scratch cleanup retries.

These execute the actual rendered wrapper with inert filesystem calls. They
do not establish Linux GUI acceptance or identify the native scratch writer.
"""
from __future__ import annotations
import json
import subprocess
import unittest

from rs9 import current071_cleanup_observation as cleanup


def _rewalk_marker(errno: str, outcome: str = "exhausted-4") -> bytes:
    return ("RS9_CURRENT071_CLEANUP_REWALK=" + outcome + "\n"
            "RS9_CURRENT071_CLEANUP_ERRNO=" + errno + "\n").encode()


def _historical_record(record: dict[str, object], observer_id: str) -> dict[str, object]:
    result = {k: v for k, v in record.items() if k != "rewalk_outcome"}
    result.update(schema=cleanup.CURRENT071_LEGACY_CLEANUP_OBSERVATION_SCHEMA,
                  observer_id=observer_id)
    return result


class Current071CleanupRetryTests(unittest.TestCase):
    def run_node(self, body: str) -> None:
        rendered = cleanup.render_current071_cleanup_observer_bytes().decode()
        start = rendered.index("const expectedTmpParents =")
        end = rendered.index("\nsyncBuiltinESMExports();", start)
        prefix = r'''import assert from "node:assert/strict";
import { resolve, dirname, basename } from "node:path";
const block = __BLOCK__;
const defaultStat = () => ({
 isSymbolicLink: () => false, isDirectory: () => true,
 uid: process.getuid(), mode: 0o40700, dev:1, ino:2,
});
function build(original, lstat = defaultStat) {
 return new Function("fs", "originalRmSync", "originalLstatSync", "originalRealpathSync",
  "tmpdir", "resolve", "dirname", "basename", "ALLOWED_ERRNO_CODES",
  block + "; return fs.rmSync;")(
   {}, original, lstat, value => value, () => "/fixture-tmp",
   resolve, dirname, basename, new Set(["ENOTEMPTY", "EACCES"]));
}
const target = "/fixture-tmp/nebular-rc-smoke-fixture";
const options = Object.freeze({recursive: true, force: true});
const receiver = {};
const waits = [];
const savedWait = Atomics.wait;
Atomics.wait = (buffer, index, expected, milliseconds) => {
 assert.ok(buffer instanceof Int32Array); assert.equal(buffer.length, 1);
 assert.equal(index, 0); assert.equal(expected, 0);
 waits.push(milliseconds); return "timed-out";
};
'''
        script = (prefix.replace("__BLOCK__", json.dumps(rendered[start:end]))
                  + "\ntry {\n" + body + "\n} finally {Atomics.wait = savedWait;}\n")
        proc = subprocess.run(["node", "--input-type=module", "-e", script],
                              capture_output=True, timeout=15)
        self.assertEqual(proc.returncode, 0, proc.stderr.decode(errors="replace"))
        self.assertEqual(proc.stdout, b"")
        self.assertEqual(proc.stderr, b"")

    def test_whole_call_limits_options_and_exhausted_error_preservation(self) -> None:
        self.run_node(r'''
let calls = 0;
const result = {};
const wrapped = build(function(...args) {
 calls++; assert.equal(this, receiver); assert.equal(args[0], target);
 assert.equal(args[1], options); return result;
});
assert.equal(wrapped.call(receiver, target, options), result);
assert.equal(calls, 1);
const transient = Object.assign(new Error("controlled transient"), {code:"ENOTEMPTY"});
let subsequent = 0;
let secondExternal = false;
const once = build(function(path, opts) {
 assert.equal(path, target); assert.equal(opts, options); subsequent++;
 if (secondExternal || subsequent === 1) throw transient;
 return result;
});
assert.equal(once(target, options), result);
assert.equal(subsequent, 2);
assert.deepEqual(waits, [100]); waits.length = 0;
secondExternal = true;
assert.throws(() => once(target, options), error => error === transient);
assert.equal(subsequent, 3); // second external cleanup gets no retry
assert.deepEqual(options, {recursive:true, force:true});
const emitted = [];
const write = process.stderr.write;
process.stderr.write = text => {emitted.push(text); return true;};
try {
 const failure = Object.assign(new Error("inert metadata case"), {code:"ENOTEMPTY"});
 const observedOnly = build(function(path, opts) {
  assert.equal(opts, options); throw failure;
 }, () => ({...defaultStat(), mode:0o40755}));
 assert.throws(() => observedOnly(target, options), error => error === failure);
 assert.deepEqual(emitted, ["RS9_CURRENT071_CLEANUP_REWALK=ineligible\nRS9_CURRENT071_CLEANUP_ERRNO=ENOTEMPTY\n"]);
 emitted.length = 0;
 for (const code of ["ENOTEMPTY", "EACCES", "EBUSY", "EPERM", "UNKNOWN"]) {
  const original = Object.assign(new Error("inert failure"), {code});
  let attempts = 0; waits.length = 0;
  const failing = build(function(...args) {
   attempts++; assert.equal(args[1], options); throw original;
  });
  assert.throws(() => failing(target, options), error => error === original);
  assert.equal(attempts, code === "ENOTEMPTY" ? 4 : 1);
  assert.deepEqual(waits, code === "ENOTEMPTY" ? [100,200,300] : []);
 }
 assert.deepEqual(emitted, [
  "RS9_CURRENT071_CLEANUP_REWALK=exhausted-4\nRS9_CURRENT071_CLEANUP_ERRNO=ENOTEMPTY\n",
  "RS9_CURRENT071_CLEANUP_REWALK=nonretryable-after-1\nRS9_CURRENT071_CLEANUP_ERRNO=EACCES\n",
  ...Array(3).fill("RS9_CURRENT071_CLEANUP_REWALK=nonretryable-after-1\nRS9_CURRENT071_CLEANUP_ERRNO=OTHER\n")]);
} finally {process.stderr.write = write;}
''')

    def test_same_root_metadata_rechecked_before_each_retry(self) -> None:
        self.run_node(r'''
const base = defaultStat();
const replacements = [
 {...base, ino:base.ino + 1}, {...base, dev:base.dev + 1},
 {...base, uid:base.uid + 1}, {...base, mode:0o40755},
 {...base, isDirectory:() => false}, {...base, isSymbolicLink:() => true},
 undefined, {...base, ino:Number.NaN},
];
const write = process.stderr.write;
const emitted = [];
process.stderr.write = text => {emitted.push(text); return true;};
try {
 for (const replacement of replacements) {
  emitted.length = 0;
  let failed = false;
  let calls = 0;
  const original = Object.assign(new Error("inert original"), {code:"ENOTEMPTY"});
  const wrapped = build(() => {calls++; failed = true; throw original;},
   () => failed ? replacement : base);
  assert.throws(() => wrapped(target, options), error => error === original);
  assert.equal(calls, 1);
  assert.deepEqual(emitted, ["RS9_CURRENT071_CLEANUP_REWALK=identity-lost-after-1\nRS9_CURRENT071_CLEANUP_ERRNO=ENOTEMPTY\n"]);
 }
 emitted.length = 0;
 let calls = 0;
 const first = Object.assign(new Error("first"), {code:"ENOTEMPTY"});
 const last = Object.assign(new Error("last"), {code:"EACCES"});
 const wrapped = build(() => {if (++calls === 1) throw first; throw last;});
 assert.throws(() => wrapped(target, options), error => error === last);
 assert.equal(calls, 2);
 assert.deepEqual(emitted, ["RS9_CURRENT071_CLEANUP_REWALK=nonretryable-after-2\nRS9_CURRENT071_CLEANUP_ERRNO=EACCES\n"]);
} finally {process.stderr.write = write;}
''')

    def test_ineligible_calls_keep_original_options_and_identity(self) -> None:
        self.run_node(r'''
const base = defaultStat();
const cases = [
 ["/fixture-tmp/unrelated", options],
 ["/other/nebular-rc-smoke-fixture", options],
 ["relative/nebular-rc-smoke-fixture", options],
 [target, {recursive: true, force: true, maxRetries: 99}],
 [target, {recursive: true, force: true, retryDelay: 1}],
 [target, {recursive: false, force: true}],
 [target, {recursive: true, force: false}],
 [target, {recursive: true, force: true, [Symbol("extra")]: true}],
 [target, Object.assign(Object.create({recursive:true, force:true}), {extra:true, other:true})],
 [target, options, () => ({...base, isSymbolicLink: () => true})],
 [target, options, () => ({...base, isDirectory: () => false})],
 [target, options, () => ({...base, uid: process.getuid() + 1})],
 [target, options, () => ({...base, mode: 0o40755})],
 [target, options, () => undefined],
 [target, options, () => {throw new Error("inert metadata failure");}],
];
for (const [path, opts, lstat] of cases) {
 const sentinel = {};
 const wrapped = build(function(...args) {
  assert.equal(this, receiver); assert.equal(args[0], path);
  assert.equal(args[1], opts); return sentinel;
 }, lstat);
 assert.equal(wrapped.call(receiver, path, opts), sentinel);
 let attempts = 0;
 const failure = Object.assign(new Error("ineligible fixture"), {code:"ENOTEMPTY"});
 const savedWrite = process.stderr.write;
 process.stderr.write = () => true;
 try {
  const failing = build(function(...args) {
   attempts++; assert.equal(args[1], opts); throw failure;
  }, lstat);
  assert.throws(() => failing.call(receiver, path, opts), error => error === failure);
  assert.equal(attempts, 1);
 } finally {process.stderr.write = savedWrite;}
}
const failure = new Error("non-target failure");
assert.throws(() => build(() => {throw failure;})("/unrelated", options),
 error => error === failure);
''')


    def test_historical_observer_identity_is_preserved_not_promoted(self) -> None:
        marker = _rewalk_marker("ENOTEMPTY")
        from rs9.release_core import digest
        current = cleanup.observe_current071_cleanup(
            marker, system="aarch64-linux", scenario="B",
            stderr_bytes=len(marker), stderr_sha256=digest(marker), complete=True,
        )
        self.assertEqual(current["observer_id"], "current071-apt-cleanup-rm-sync-rewalk-v1")
        self.assertEqual(current["status"], "cleanup-error-observed")
        self.assertEqual(current["errno_code"], "ENOTEMPTY")
        historical = _historical_record(current, "current071-apt-cleanup-rm-sync-v1")
        for record in (current, historical, _historical_record(current, cleanup.CURRENT071_BUILTIN_RETRY_CLEANUP_OBSERVER_ID)):
            for _ in range(3):
                validated = cleanup.validate_current071_cleanup_observation(
                    record, system="aarch64-linux", scenario="B", family="apt",
                    stderr_bytes=len(marker), stderr_sha256=digest(marker), complete=True,
                )
                self.assertEqual(validated, record)
                record = validated
        withheld = cleanup.withheld_current071_cleanup_observation(
            "incomplete-stream", observer_id=cleanup.CURRENT071_LEGACY_CLEANUP_OBSERVER_ID)
        self.assertEqual(cleanup.validate_current071_cleanup_observation(withheld), withheld)


    def test_legacy_and_current_fallbacks_preserve_their_observer_identity(self) -> None:
        from rs9.release_core import digest
        marker = _rewalk_marker("ENOTEMPTY")
        current = cleanup.observe_current071_cleanup(
            marker, system="aarch64-linux", scenario="B",
            stderr_bytes=len(marker), stderr_sha256=digest(marker), complete=True,
        )
        defaults = dict(system="aarch64-linux", scenario="B", family="apt",
                        stderr_bytes=len(marker), stderr_sha256=digest(marker), complete=True)
        for observer_id in (cleanup.CURRENT071_LEGACY_CLEANUP_OBSERVER_ID,
                            cleanup.CURRENT071_BUILTIN_RETRY_CLEANUP_OBSERVER_ID,
                            cleanup.CURRENT071_CLEANUP_OBSERVER_ID):
            record = (current if observer_id == cleanup.CURRENT071_CLEANUP_OBSERVER_ID
                      else _historical_record(current, observer_id))
            for overrides, reason in (
                ({"complete": False}, "incomplete-stream"),
                ({"system": "x86_64-linux"}, "binding-mismatch"),
                ({"stderr_sha256": "a"*64}, "binding-mismatch"),
                ({"mismatch": True}, "binding-mismatch"),
            ):
                result = cleanup.validate_current071_cleanup_observation(
                    record, **{**defaults, **overrides})
                self.assertEqual(result["observer_id"], observer_id)
                self.assertEqual(result["status"], "withheld")
                self.assertEqual(result["withheld_reason"], reason)
            for overrides in ({"status": "unknown"}, {"marker_count": 2},
                              {"stderr_bytes": -1}, {"family": "unknown"},
                              {"extra": True}):
                result = cleanup.validate_current071_cleanup_observation(
                    {**record, **overrides}, **defaults)
                self.assertEqual(result["status"], "withheld")
                self.assertEqual(result["observer_id"], observer_id)
            withheld = cleanup.withheld_current071_cleanup_observation(
                "binding-mismatch", observer_id=observer_id)
            for _ in range(3):
                after = cleanup.validate_current071_cleanup_observation(withheld, mismatch=True)
                self.assertEqual(after, withheld)
                withheld = after

    def test_real_node_red_and_green_revisit_controlled_late_child(self) -> None:
        rendered = cleanup.render_current071_cleanup_observer_bytes().decode()
        start = rendered.index("const expectedTmpParents =")
        end = rendered.index("\nsyncBuiltinESMExports();", start)
        script = r'''import assert from "node:assert/strict";
import fs from "node:fs";
import {tmpdir} from "node:os";
import {resolve, dirname, basename, join} from "node:path";
const roots = [];
const states = new Map();
const originalRm = fs.rmSync;
const originalRmdir = fs.rmdirSync;
const emitted = [];
const write = process.stderr.write;
function fixture() {
 const root = fs.realpathSync(fs.mkdtempSync(join(tmpdir(), "nebular-rc-smoke-")));
 roots.push(root);
 fs.writeFileSync(join(root, "initial-entry"), "controlled fixture\n");
 states.set(root, {calls:0, injected:0});
 return root;
}
fs.rmdirSync = function(target, ...args) {
 const root = String(target);
 const state = states.get(root);
 if (state && ++state.calls === 2) {
  fs.writeFileSync(join(root, "late-entry"), "controlled fixture\n");
  state.injected++;
 }
 return Reflect.apply(originalRmdir, this, [target, ...args]);
};
process.stderr.write = value => {emitted.push(value); return true;};
try {
 const red = fixture();
 assert.throws(() => originalRm(red,
  {recursive:true, force:true, maxRetries:3, retryDelay:100}),
  error => error.code === "ENOTEMPTY");
 assert.equal(states.get(red).injected, 1);
 assert.equal(states.get(red).calls, 5);
 assert.deepEqual(fs.readdirSync(red), ["late-entry"]);

 const green = fixture();
 const options = Object.freeze({recursive:true, force:true});
 let wholeCalls = 0;
 const countedRm = function(...args) {
  assert.equal(this, fs); assert.equal(args[0], green); assert.equal(args[1], options);
  wholeCalls++;
  return Reflect.apply(originalRm, this, args);
 };
 const wrapped = new Function("fs", "originalRmSync", "originalLstatSync",
  "originalRealpathSync", "tmpdir", "resolve", "dirname", "basename",
  "ALLOWED_ERRNO_CODES", __BLOCK__ + "; return fs.rmSync;")(
   {}, countedRm, fs.lstatSync, fs.realpathSync, tmpdir, resolve, dirname,
   basename, new Set(["ENOTEMPTY", "EACCES"]));
 wrapped.call(fs, green, options);
 assert.equal(states.get(green).injected, 1);
 assert.equal(wholeCalls, 2);
 assert.equal(states.get(green).calls, 4);
 assert.equal(fs.existsSync(green), false);
 assert.deepEqual(emitted, []);
} finally {
 process.stderr.write = write;
 fs.rmdirSync = originalRmdir;
 for (const root of roots) originalRm(root, {recursive:true, force:true});
}
assert.ok(roots.every(root => !fs.existsSync(root)));
'''
        script = script.replace("__BLOCK__", json.dumps(rendered[start:end]))
        proc = subprocess.run(["node", "--input-type=module", "-e", script],
                              capture_output=True, timeout=15)
        self.assertEqual(proc.returncode, 0, proc.stderr.decode(errors="replace"))
        self.assertEqual(proc.stdout, b"")
        self.assertEqual(proc.stderr, b"")

    def test_versioned_rewalk_outcome_is_closed_and_historically_separate(self) -> None:
        from rs9.release_core import digest
        for outcome in cleanup.CURRENT071_REWALK_OUTCOMES:
            errno = ("EACCES" if outcome.startswith("nonretryable-") else
                     "OTHER" if outcome == "unclassified" else "ENOTEMPTY")
            marker = _rewalk_marker(errno, outcome)
            record = cleanup.observe_current071_cleanup(
                marker, system="aarch64-linux", scenario="B",
                stderr_bytes=len(marker), stderr_sha256=digest(marker), complete=True)
            self.assertEqual(record["status"], "cleanup-error-observed")
            self.assertEqual(record["rewalk_outcome"], outcome)
            self.assertEqual(record["schema"], "rs9.current071-cleanup-observation.v1alpha2")
            for _ in range(3):
                after = cleanup.validate_current071_cleanup_observation(
                    record, system="aarch64-linux", scenario="B",
                    stderr_bytes=len(marker), stderr_sha256=digest(marker), complete=True,
                    family="apt")
                self.assertEqual(after, record)
                record = after
            for bad in (None, {}, [], "identity-lost-after-4", "exhausted-5", "private-fixture-value"):
                result = cleanup.validate_current071_cleanup_observation(
                    {**record, "rewalk_outcome":bad},
                    system="aarch64-linux", scenario="B",
                    stderr_bytes=len(marker), stderr_sha256=digest(marker), complete=True)
                self.assertEqual(result["status"], "withheld")
                self.assertIsNone(result["rewalk_outcome"])
                self.assertNotIn("private-fixture-value", json.dumps(result))
            missing = {k:v for k,v in record.items() if k != "rewalk_outcome"}
            for bad in (missing, {**record, "schema":cleanup.CURRENT071_LEGACY_CLEANUP_OBSERVATION_SCHEMA}):
                result = cleanup.validate_current071_cleanup_observation(
                    bad, system="aarch64-linux", scenario="B",
                    stderr_bytes=len(marker), stderr_sha256=digest(marker), complete=True)
                self.assertEqual(result["status"], "withheld")
                self.assertIsNone(result["rewalk_outcome"])
            for old_id in (cleanup.CURRENT071_LEGACY_CLEANUP_OBSERVER_ID,
                           cleanup.CURRENT071_BUILTIN_RETRY_CLEANUP_OBSERVER_ID):
                historical = _historical_record(record, old_id)
                for bad in ({**historical,"schema":cleanup.CURRENT071_CLEANUP_OBSERVATION_SCHEMA},
                            {**historical,"rewalk_outcome":outcome}):
                    result = cleanup.validate_current071_cleanup_observation(
                        bad, system="aarch64-linux", scenario="B",
                        stderr_bytes=len(marker), stderr_sha256=digest(marker), complete=True)
                    self.assertEqual(result["status"], "withheld")
                    self.assertEqual(result["observer_id"], old_id)
                    self.assertNotIn("rewalk_outcome", result)
        for marker in (
            b"RS9_CURRENT071_CLEANUP_ERRNO=ENOTEMPTY\n",
            b"RS9_CURRENT071_CLEANUP_REWALK=ineligible\n",
            _rewalk_marker("ENOTEMPTY", "nonretryable-after-1"),
            _rewalk_marker("EACCES", "identity-lost-after-1"),
            _rewalk_marker("ENOTEMPTY", "exhausted-5"),
            _rewalk_marker("ENOTEMPTY") + b"RS9_CURRENT071_CLEANUP_REWALK=ineligible\n",
            b"prefix RS9_CURRENT071_CLEANUP_REWALK=ineligible\nRS9_CURRENT071_CLEANUP_ERRNO=ENOTEMPTY\n",
        ):
            result = cleanup.observe_current071_cleanup(
                marker, system="aarch64-linux", scenario="B",
                stderr_bytes=len(marker), stderr_sha256=digest(marker), complete=True)
            self.assertEqual(result["status"], "withheld")
            self.assertIsNone(result["rewalk_outcome"])
