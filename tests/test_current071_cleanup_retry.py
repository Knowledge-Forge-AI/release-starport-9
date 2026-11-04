"""Contract checks for bounded current071 APT scratch cleanup retries.

These execute the actual rendered wrapper with inert filesystem calls. They
do not establish Linux GUI acceptance or identify the native scratch writer.
"""
from __future__ import annotations
import json
import subprocess
import unittest

from rs9 import current071_cleanup_observation as cleanup


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
 uid: process.getuid(), mode: 0o40700,
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
'''
        script = prefix.replace("__BLOCK__", json.dumps(rendered[start:end])) + body
        proc = subprocess.run(["node", "--input-type=module", "-e", script],
                              capture_output=True, timeout=15)
        self.assertEqual(proc.returncode, 0, proc.stderr.decode(errors="replace"))
        self.assertEqual(proc.stdout, b"")
        self.assertEqual(proc.stderr, b"")

    def test_exact_retry_options_and_exhausted_error_preservation(self) -> None:
        self.run_node(r'''
let calls = 0;
const result = {};
const wrapped = build(function(...args) {
 calls++; assert.equal(this, receiver);
 assert.equal(args[0], target);
 assert.deepEqual(args[1], {recursive: true, force: true, maxRetries: 3, retryDelay: 100});
 assert.notEqual(args[1], options); return result;
});
assert.equal(wrapped.call(receiver, target, options), result);
assert.equal(calls, 1); // Node's own rmSync owns internal retries.
// The same wrapper must not add retries to a second target call.
let subsequent = 0;
const once = build(function(path, opts) {
 assert.equal(path, target);
 if (subsequent++ === 0) assert.equal(opts.maxRetries, 3);
 else assert.equal(opts, options);
});
once(target, options); once(target, options);
assert.equal(subsequent, 2);
assert.deepEqual(options, {recursive: true, force: true});
const emitted = [];
const write = process.stderr.write;
process.stderr.write = text => { emitted.push(text); return true; };
try {
 const ineligibleFailure = Object.assign(new Error("inert metadata case"), {code: "ENOTEMPTY"});
 const observedOnly = build(function(path, opts) {
  assert.equal(path, target); assert.equal(opts, options); throw ineligibleFailure;
 }, () => ({...defaultStat(), mode: 0o40755}));
 assert.throws(() => observedOnly(target, options), error => error === ineligibleFailure);
 assert.deepEqual(emitted, ["RS9_CURRENT071_CLEANUP_ERRNO=ENOTEMPTY\n"]);
 emitted.length = 0;
 for (const code of ["ENOTEMPTY", "EACCES", "UNKNOWN"]) {
  const failure = Object.assign(new Error("inert failure"), {code});
  const failing = build(function(...args) {
   assert.deepEqual(args[1], {recursive: true, force: true, maxRetries: 3, retryDelay: 100});
   throw failure;
  });
  assert.throws(() => failing(target, options), error => error === failure);
 }
 assert.deepEqual(emitted, ["RS9_CURRENT071_CLEANUP_ERRNO=ENOTEMPTY\n",
  "RS9_CURRENT071_CLEANUP_ERRNO=EACCES\n", "RS9_CURRENT071_CLEANUP_ERRNO=OTHER\n"]);
} finally { process.stderr.write = write; }
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
}
const failure = new Error("non-target failure");
assert.throws(() => build(() => {throw failure;})("/unrelated", options),
 error => error === failure);
''')


    def test_historical_observer_identity_is_preserved_not_promoted(self) -> None:
        marker = b"RS9_CURRENT071_CLEANUP_ERRNO=ENOTEMPTY\n"
        from rs9.release_core import digest
        current = cleanup.observe_current071_cleanup(
            marker, system="aarch64-linux", scenario="B",
            stderr_bytes=len(marker), stderr_sha256=digest(marker), complete=True,
        )
        self.assertEqual(current["observer_id"], "current071-apt-cleanup-rm-sync-retry-v1")
        self.assertEqual(current["status"], "cleanup-error-observed")
        self.assertEqual(current["errno_code"], "ENOTEMPTY")
        historical = {**current, "observer_id": "current071-apt-cleanup-rm-sync-v1"}
        for record in (current, historical):
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
        marker = b"RS9_CURRENT071_CLEANUP_ERRNO=ENOTEMPTY"+bytes([10])
        current = cleanup.observe_current071_cleanup(
            marker, system="aarch64-linux", scenario="B",
            stderr_bytes=len(marker), stderr_sha256=digest(marker), complete=True,
        )
        defaults = dict(system="aarch64-linux", scenario="B", family="apt",
                        stderr_bytes=len(marker), stderr_sha256=digest(marker), complete=True)
        for observer_id in (cleanup.CURRENT071_LEGACY_CLEANUP_OBSERVER_ID,
                            cleanup.CURRENT071_CLEANUP_OBSERVER_ID):
            record = {**current, "observer_id": observer_id}
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
