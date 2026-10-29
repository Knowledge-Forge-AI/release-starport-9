"""Authenticated Darwin observer adaptation; all process output is synthetic."""
from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from rs9.nebular070_darwin_harness import (
    RELEASE_DERIVED_SHA256, RELEASE_SOURCE_SHA256,
    prepare_darwin_harness, require_release_darwin_harness, validate_darwin_harness,
)
from rs9.tf_pypi_archive import AdmissionError, sha256
from rs9.tf_pypi_launcher import node_binary


ORIGINAL_FUNCTION = '''export function candidateProcesses(launchRoot) {
  const root = realpathSync(launchRoot);
  const found = [];
  if (process.platform === "linux") {
    throw new Error("synthetic fixture is Darwin only");
  } else {
    const listing = spawnSync("ps", ["-axww", "-o", "pid=,command="], { encoding: "utf8" });
    for (const line of listing.stdout.split("\\n")) {
      const match = /^\\s*(\\d+)\\s+(.*)$/.exec(line);
      if (match && (match[2].startsWith(root + sep) || match[2].includes(` ${root}${sep}`))) found.push({ pid: Number(match[1]), exe: match[2] });
    }
  }
  return found.filter((entry) => entry.pid !== process.pid);
}
'''
WITNESS = "/fixture/native-rc-smoke-darwin.mjs"


def witnessed_response(stdout=""):
    return {"status": 0, "stdout": f"7 /fixture/node {WITNESS} --platform darwin-arm64\n" + stdout,
            "stderr": ""}


class DarwinHarnessTests(unittest.TestCase):
    def _prepared(self, body=ORIGINAL_FUNCTION):
        temporary = tempfile.TemporaryDirectory(prefix="rs9-darwin-harness-")
        self.addCleanup(temporary.cleanup)
        tools = Path(temporary.name).resolve()
        original = tools / "native-rc-smoke.mjs"
        original.write_text(body)
        return {"tools": tools, "records": [{"path": "tools/native-rc-smoke.mjs",
                                             "sha256": sha256(original.read_bytes())}]}

    def test_derivation_preserves_source_and_binds_both_hashes(self):
        prepared = self._prepared()
        original = (prepared["tools"] / "native-rc-smoke.mjs").read_bytes()
        derived, record = prepare_darwin_harness(prepared)
        self.assertEqual((prepared["tools"] / "native-rc-smoke.mjs").read_bytes(), original)
        self.assertEqual(record["source_sha256"], sha256(original))
        self.assertEqual(record["derived_sha256"], sha256(derived.read_bytes()))
        self.assertEqual(validate_darwin_harness(record), record)
        self.assertEqual(derived.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(AdmissionError):
            prepare_darwin_harness(prepared)

    def test_source_digest_and_ambiguous_transform_are_refused(self):
        prepared = self._prepared()
        prepared["records"][0]["sha256"] = "0" * 64
        with self.assertRaises(AdmissionError):
            prepare_darwin_harness(prepared)
        for body in ("export const unrelated = true;", ORIGINAL_FUNCTION * 2):
            with self.subTest(body=body[:30]), self.assertRaises(AdmissionError):
                prepare_darwin_harness(self._prepared(body))

    def _observe(self, response, root="/fixture/App [test].app", pid=7):
        derived, _ = prepare_darwin_harness(self._prepared())
        data = {"source": derived.read_text(), "response": response, "root": root, "pid": pid,
                "witness": WITNESS}
        script = '''const fs = require("node:fs");
const vm = require("node:vm");
const input = JSON.parse(fs.readFileSync(0, "utf8"));
const calls = [];
const context = {root: input.root, realpathSync: x => x, sep: "/",
  process: {platform: "darwin", pid: input.pid, argv: ["/fixture/node", input.witness]},
  spawnSync: (file, args, options) => {calls.push({file, args, options}); return input.response;}};
let result = null, error = null;
try {result = vm.runInNewContext(input.source.replace("export function", "function") +
  "\\n;candidateProcesses(root)", context, {timeout: 1000});} catch (e) {error = e.message;}
process.stdout.write(JSON.stringify({result, error, calls}));'''
        process = subprocess.run([node_binary(), "-e", script], input=json.dumps(data).encode(),
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5, check=True)
        self.assertLess(len(process.stdout), 16 * 1024)
        self.assertEqual(process.stderr, b"")
        return json.loads(process.stdout)

    def test_observer_keeps_ancestors_full_arguments_and_candidate_boundaries(self):
        root = "/fixture/App [test].app"
        stdout = f"41 {root}/Contents/MacOS/gui\n42 /bin/sh {root}/runner\n43 /sibling/gui\n"
        observed = self._observe(witnessed_response(stdout), root=root)
        self.assertIsNone(observed["error"])
        self.assertEqual([row["pid"] for row in observed["result"]], [41, 42])
        call = observed["calls"][0]
        self.assertEqual(call["file"], "/usr/bin/pgrep")
        self.assertEqual(call["args"][:4], ["-a", "-f", "-l", "--"])
        self.assertEqual(call["args"][4],
                         r"(^| )/fixture/App \[test]\.app/|(^| )/fixture/native-rc-smoke-darwin\.mjs( |$)")
        self.assertEqual(call["options"], {"encoding": "utf8", "timeout": 2000, "maxBuffer": 65536})

    def test_observed_empty_candidates_require_the_full_argument_witness(self):
        observed = self._observe(witnessed_response())
        self.assertEqual(observed["result"], [])
        self.assertIsNone(observed["error"])
        cases = [
            {"error": {"code": "EPERM"}},
            {"status": 2, "stdout": "", "stderr": ""},
            {"status": 3, "stdout": "", "stderr": ""},
            {"status": 1, "stdout": "", "stderr": ""},
            {"status": None, "stdout": "", "stderr": ""},
            {"status": 0, "stdout": "", "stderr": ""},
            {"status": 1, "stdout": "41 /fixture/App [test].app/gui\n", "stderr": ""},
            {"status": 0, "stdout": "not a process row\n", "stderr": ""},
            {"status": 0, "stdout": "0 /fixture/App [test].app/gui\n", "stderr": ""},
            {"status": 0, "stdout": "41 /fixture/App [test].app/gui\n", "stderr": "partial"},
            witnessed_response("41 /fixture/App [test].app/gui"),
            {"status": 0, "stdout": "7 node\n", "stderr": ""},
        ]
        for response in cases:
            with self.subTest(response=response):
                observed = self._observe(response)
                self.assertIsNone(observed["result"])
                self.assertEqual(observed["error"], "candidate process snapshot failed")

    def test_harness_record_is_closed_and_hashes_are_required(self):
        _, record = prepare_darwin_harness(self._prepared())
        for change in ({"extra": True}, {"source_sha256": "bad"}, {"process_tool": "/bin/ps"},
                       {"transform": "unreviewed"}):
            with self.subTest(change=change), self.assertRaises(AdmissionError):
                validate_darwin_harness({**record, **change})

    def test_release_matrix_refuses_missing_or_arbitrary_harness_identity(self):
        _, record = prepare_darwin_harness(self._prepared())
        with self.assertRaises(AdmissionError):
            require_release_darwin_harness(None)
        with self.assertRaises(AdmissionError):
            require_release_darwin_harness(record)
        released = {**record, "source_sha256": RELEASE_SOURCE_SHA256,
                    "derived_sha256": RELEASE_DERIVED_SHA256}
        self.assertEqual(require_release_darwin_harness(released), released)
        for key in ("source_sha256", "derived_sha256"):
            with self.subTest(key=key), self.assertRaises(AdmissionError):
                require_release_darwin_harness({**released, key: "0" * 64})


if __name__ == "__main__":
    unittest.main()
