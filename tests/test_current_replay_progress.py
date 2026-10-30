"""Current replay profile fixtures; synthetic pins never qualify native applications."""
import copy
import hashlib
import json
import inspect
import os
import re
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from rs9 import application_smoke_diagnostic as diagnostic
from rs9 import hosted_nix
from rs9.errors import ContractError
from tests import test_current_smoke_source_transport as transport_fixtures


def pin(data):
    return {"sha256": hashlib.sha256(data).hexdigest(), "blob": hashlib.sha1(
        b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest(), "size": len(data)}


class CurrentReplayProfileSelectionTests(unittest.TestCase):
    def setUp(self):
        self.fixture = transport_fixtures.CurrentSourceTransportTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.prepared = self.fixture.prepared
        self.profile = copy.deepcopy(diagnostic.CURRENT_REPLAY_PROGRESS_PROFILE)
        source = self.prepared["source"]
        self.profile["modules"] = {name: pin((source / "tools" / name).read_bytes())
                                   for name in self.profile["modules"]}
        self.profile["support"] = pin((source / "package.json").read_bytes())
        patcher = patch.object(diagnostic, "CURRENT_REPLAY_PROGRESS_PROFILE", self.profile)
        patcher.start(); self.addCleanup(patcher.stop)

    def test_real_authentication_and_closed_current_profile(self):
        self.assertEqual(diagnostic._current_replay_progress_profile(self.prepared), self.profile)
        self.assertIsNotNone(diagnostic._replay_progress_wrapper(self.prepared))
        # A JSON-shaped object gains neither source-profile admission nor release authority.
        plain = {k: v for k, v in self.prepared.items() if k not in {"capture", "fixture_capture"}}
        self.assertIsNone(diagnostic._current_replay_progress_profile(plain))
        for field in ("commit", "tree", "name"):
            value = copy.deepcopy(self.prepared)
            value["capture"].record["tag"][field] = "wrong"
            self.assertIsNone(diagnostic._current_replay_progress_profile(value))
        self.assertIsNone(diagnostic._current_replay_progress_profile({**self.prepared, "source_generation": "unknown"}))

    def test_current_replay_integration_preserves_original_and_failed_gate(self):
        from types import SimpleNamespace
        calls = []
        def original(argv, **kwargs):
            calls.append(("original", argv, kwargs))
            raise subprocess.TimeoutExpired(argv, kwargs["timeout"], stderr=b"synthetic timeout")
        def replay(argv, **kwargs):
            calls.append(("replay", argv, kwargs))
            sink = Path(argv[argv.index("--rs9-replay-progress-file") + 1])
            sink.write_text(json.dumps({"schema": diagnostic.REPLAY_PROGRESS_SCHEMA, "seq": 1,
                "stage": "application", "event": "release-smoke-active"}) + "\n")
            return SimpleNamespace(returncode=1, stdout=b"", stderr=b"synthetic failure")
        with patch.object(diagnostic.subprocess, "run", side_effect=original), patch.object(
                diagnostic, "_bounded_run", side_effect=replay):
            with self.assertRaises(ContractError) as caught:
                diagnostic.execute_application_smoke(prepared=self.prepared, system="x86_64-linux",
                    launch_root=self.fixture.root / "static-runtime", diagnostic_replay=True)
        self.assertEqual(caught.exception.code, "APPLICATION_SMOKE")
        self.assertEqual([x[0] for x in calls], ["original", "replay"])
        self.assertNotIn("--rs9-replay-progress-profile", calls[0][1])
        self.assertNotIn("--timeout-ms", calls[0][1])
        self.assertEqual(calls[0][2]["timeout"], 240)
        self.assertEqual(calls[1][2]["timeout"], 240)
        command = calls[1][1]
        self.assertEqual(command[command.index("--rs9-replay-progress-profile") + 1], "nebular070")
        self.assertEqual(command.count("--rs9-replay-progress-closure-member"), 7)
        self.assertIn("package.json=" + self.profile["support"]["sha256"], command)
        doc = json.loads((self.prepared["scratch"].parent / "diagnostics/application-smoke-diagnostic.json").read_bytes())
        self.assertEqual(doc["gate_status"], "fail")
        self.assertFalse(doc["replay_equivalent_to_original"])
        self.assertEqual(doc["replay"]["progress"]["status"], "observed")
        from rs9.release_core import authenticated_record_hash
        with self.assertRaises(ContractError):
            authenticated_record_hash(self.profile)

    def test_initial_observation_keeps_original_outer_timeout_and_released_default(self):
        calls = []

        def original(argv, **kwargs):
            calls.append((argv, kwargs))
            raise subprocess.TimeoutExpired(argv, kwargs["timeout"], stderr=b"synthetic timeout")

        with patch.object(diagnostic.subprocess, "run", side_effect=original):
            with self.assertRaises(ContractError) as caught:
                diagnostic.execute_application_smoke(
                    prepared=self.prepared, system="x86_64-linux",
                    launch_root=self.fixture.root / "static-runtime",
                    diagnostic_initial_observation=True,
                )
        self.assertEqual(caught.exception.code, "APPLICATION_SMOKE")
        self.assertEqual(len(calls), 1)
        argv, kwargs = calls[0]
        self.assertEqual(kwargs["timeout"], 240)
        self.assertNotIn("--timeout-ms", argv)
        self.assertIn("--rs9-initial-observation-kind", argv)
        self.assertEqual(argv[argv.index("--rs9-initial-observation-kind") + 1], "initial-observation")
        diagnostic_record = json.loads(
            (self.prepared["scratch"].parent / "diagnostics/application-smoke-diagnostic.json").read_bytes())
        self.assertEqual(diagnostic_record["initial_run"]["initial_observation"]["status"], "unobserved")
        self.assertEqual(diagnostic_record["initial_run"]["initial_observation"]["reason"], "missing")

    def test_initial_observation_reader_rejects_malformed_or_credentialed_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "initial-observation.json"
            path.write_text('{"schema":"wrong"}\n')
            self.assertEqual(diagnostic._read_initial_observation(path)["status"], "unobserved")
            path.write_text('{"token":"secret-value"}\n')
            self.assertEqual(diagnostic._read_initial_observation(path)["status"], "unobserved")

    def test_initial_observation_is_shed_before_legacy_failure_fields_at_cap(self):
        fields = {
            "cause": "process-timeout", "scenario": "C", "problem_codes": [],
            "legacy_failure": "retain",
            "harness_problem_categories": {"origin": "synthetic", "problems": []},
            "initial_observation": {"schema": "fixture", "payload": "z" * 5000},
        }
        with patch.object(diagnostic, "MAX_DIAGNOSTIC", 800):
            diagnostic._retain_failure(
                self.prepared, "x86_64-linux", "linux-x64", "C", self.fixture.root,
                [], {}, fields, [], include_replay=False)
        record = json.loads(
            (self.prepared["scratch"].parent / "diagnostics/application-smoke-diagnostic.json").read_bytes())
        self.assertNotIn("initial_observation", record["initial_run"])
        self.assertEqual(record["initial_run"]["legacy_failure"], "retain")

    def test_current_nix_join_enables_initial_observation_only_for_authenticated_current_linux(self):
        prepared = {
            "source_generation": "theme-forge-current-202610",
            "capture": object(), "fixture_capture": object(),
        }
        self.assertTrue(hosted_nix._current_linux_initial_observation_enabled(
            "theme-forge-current-202610", "x86_64-linux", prepared))
        self.assertFalse(hosted_nix._current_linux_initial_observation_enabled(
            "theme-forge-live1", "x86_64-linux", prepared))
        self.assertFalse(hosted_nix._current_linux_initial_observation_enabled(
            "theme-forge-current-202610", "aarch64-darwin", prepared))
        root = "/nix/store/" + "a" * 32 + "-dbus-1"
        facts = {
            "dbus_run_session": root + "/bin/dbus-run-session",
            "dbus_daemon": root + "/bin/dbus-daemon",
            "dbus_session_config": root + "/share/dbus-1/session.conf",
        }
        with patch.object(hosted_nix, "verify_nebular_runtime", return_value={"status": "pass"}) as verify:
            hosted_nix._verify_final_nebular_runtime(
                Path("/nix/store/" + "b" * 32 + "-runtime"), prepared, "x86_64-linux",
                [], [], {}, None, facts, "theme-forge-current-202610")
        self.assertTrue(verify.call_args.kwargs["diagnostic_initial_observation"])

    def test_member_support_pin_blob_and_missing_extra_refusals(self):
        source = self.prepared["source"]
        for relative in ("tools/native-rc-smoke.mjs", "package.json"):
            path = source / relative; original = path.read_bytes()
            for changed in (None, b"changed"):
                if changed is None: path.unlink()
                else: path.write_bytes(changed)
                self.assertIsNone(diagnostic._current_replay_progress_profile(self.prepared))
                path.write_bytes(original)
        extra = source / "tools/extra.mjs"; extra.write_text("unlisted")
        self.assertIsNone(diagnostic._current_replay_progress_profile(self.prepared)); extra.unlink()
        for key in ("blob", "sha256", "size"):
            profile = copy.deepcopy(self.profile)
            profile["support"][key] = 0 if key == "size" else "0" * (40 if key == "blob" else 64)
            with patch.object(diagnostic, "CURRENT_REPLAY_PROGRESS_PROFILE", profile):
                self.assertIsNone(diagnostic._current_replay_progress_profile(self.prepared))


class CurrentReplayWrapperTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve(); self.source = self.root / "source"
        self.tools = self.source / "tools"; self.tools.mkdir(parents=True)
        self.evidence = self.root / "evidence"; self.evidence.mkdir()
        self.node = shutil.which("node"); self.assertIsNotNone(self.node)
        self.profile = copy.deepcopy(diagnostic.CURRENT_REPLAY_PROGRESS_PROFILE)
        names = list(self.profile["modules"])
        for name in names:
            text = "export const fixture = true;\n"
            if name == "platform-targets.mjs":
                text = "import{readFileSync}from'node:fs';export const version=JSON.parse(readFileSync(new URL('../package.json',import.meta.url),'utf8')).version;\n"
            if name == "native-rc-smoke.mjs":
                text = "".join("import './" + child + "';\n" for child in names if child != name)
                text += """import {spawn} from 'node:child_process';
import {writeFileSync,readFileSync} from 'node:fs';
import {join} from 'node:path';
export async function runSmoke(options) {
  const code = String.raw`process.stdout.write('UNCHANGED_STDOUT');process.stderr.write('UNKNOWN_PRIVATE_MARKER_947');setTimeout(()=>{process.stderr.write('\\nTFSB Studio release smoke scena');setTimeout(()=>{process.stderr.write('rio C active\\n');},5);},5);`;
  const runtimePackage = JSON.parse(readFileSync(new URL('../package.json',import.meta.url), {encoding:'utf8'}));
  if(runtimePackage.version!=='0.7.0') throw new Error('runtime support read changed');
  const child = spawn(process.execPath, ['-e',code], {stdio:['ignore','pipe','pipe']});
  let out='';let err='';child.stdout.on('data',x=>out+=x);child.stderr.on('data',x=>err+=x);
  await new Promise(resolve=>child.on('exit',resolve));
  writeFileSync(join(options.evidenceDir,'stream-check.json'),JSON.stringify({out,err}));
  writeFileSync(join(options.evidenceDir,'unrelated.receipt.json'),'{}');
  writeFileSync(join(options.evidenceDir,options.label+'.receipt.json'),'{}');
  writeFileSync(join(options.evidenceDir,options.label+'.run.json'),'{}');
  return {label:options.label,status:'fail',problems:[]};
}
"""
            (self.tools / name).write_text(text)
        (self.source / "package.json").write_text('{"version":"0.7.0"}\n')
        self.profile["modules"] = {name: pin((self.tools / name).read_bytes()) for name in names}
        self.profile["support"] = pin((self.source / "package.json").read_bytes())
        original = Path(diagnostic.__file__).with_name("replay_progress_wrapper.mjs").read_text()
        start = original.index('const CURRENT_PROFILE = Object.freeze(')
        end = original.index(');\n',start)+3
        self.wrapper = self.root / "wrapper.mjs"
        self.wrapper.write_text(original[:start]+'const CURRENT_PROFILE = Object.freeze('+json.dumps(self.profile)+');\n'+original[end:])

    def command(self):
        p = self.profile
        command = [self.node,str(self.wrapper),'--rs9-replay-progress-harness',str(self.tools/'native-rc-smoke.mjs'),
            '--rs9-replay-progress-file',str(self.root/'progress.jsonl'),
            '--rs9-replay-progress-expected-sha256',p['modules']['native-rc-smoke.mjs']['sha256'],
            '--rs9-replay-progress-profile',p['id'],'--rs9-replay-progress-source-commit',p['commit'],
            '--rs9-replay-progress-source-tree',p['tree'],
            '--rs9-replay-progress-support-member','package.json='+p['support']['sha256']]
        for name,row in p['modules'].items():command += ['--rs9-replay-progress-closure-member',name+'='+row['sha256']]
        return command+['--platform','linux-x64','--scenario','C','--launch-root',str(self.root/'empty-runtime'),
            '--checkout',str(self.source),'--evidence',str(self.evidence),'--label','linux-x64-C','--timeout-ms','180000']

    def initial_command(self):
        command = self.command()[:-2]
        # Accelerate only the fixed observer interval; production remains 8000ms.
        clock = self.root / 'accelerated-observer-clock.mjs'
        clock.write_text("const original=setTimeout;globalThis.setTimeout=(fn,ms,...args)=>original(fn,ms===8000?8:ms,...args);\n")
        command[1:1] = ['--import', str(clock)]
        return command + ['--rs9-initial-observation-kind','initial-observation',
            '--rs9-initial-observation-file',str(self.root/'initial-observation.json')]

    def run_wrapper(self, command=None):
        return subprocess.run(command or self.command(),capture_output=True,timeout=10,check=False)

    def test_current_spawn_write_and_marker_hooks_preserve_streams_and_fail_status(self):
        before = {str(p):p.read_bytes() for p in self.source.rglob('*') if p.is_file()}
        result = self.run_wrapper(); self.assertEqual(result.returncode,1,result.stderr)
        events = diagnostic._read_replay_progress(self.root/'progress.jsonl')
        self.assertEqual(events['status'],'observed')
        pairs=[(e['stage'],e['event']) for e in events['events']]
        self.assertIn(('candidate','launched'),pairs);self.assertIn(('candidate','exited'),pairs)
        self.assertEqual(pairs.count(('application','release-smoke-active')),1)
        self.assertEqual(pairs.count(('receipt','write-start')),1)
        self.assertEqual(pairs.count(('receipt','finalized')),1)
        self.assertIn(('run-record','finalized'),pairs)
        self.assertNotIn('UNKNOWN_PRIVATE_MARKER_947',json.dumps(events))
        streams=json.loads((self.evidence/'stream-check.json').read_bytes())
        self.assertEqual(streams['out'],'UNCHANGED_STDOUT')
        self.assertEqual(streams['err'],'UNKNOWN_PRIVATE_MARKER_947\nTFSB Studio release smoke scenario C active\n')
        self.assertEqual(before,{str(p):p.read_bytes() for p in self.source.rglob('*') if p.is_file()})
        self.assertEqual(json.loads(result.stdout)['status'],'fail')
        self.assertFalse(any('authority' in str(e) for e in events['events']))

    def test_initial_observation_captures_bounded_stream_facts_without_raw_bytes(self):
        result = self.run_wrapper(self.initial_command())
        self.assertEqual(result.returncode, 1, result.stderr)
        path = self.root / 'initial-observation.json'
        raw = path.read_bytes()
        self.assertLessEqual(len(raw), diagnostic.INITIAL_OBSERVATION_MAX_BYTES)
        self.assertNotIn(b'UNKNOWN_PRIVATE_MARKER_947', raw)
        observation = json.loads(raw)
        self.assertEqual(observation['schema'], diagnostic.INITIAL_OBSERVATION_SCHEMA)
        self.assertEqual(observation['attempt_kind'], 'initial-observation')
        self.assertTrue(observation['non_admitting'])
        self.assertEqual(observation['status'], 'failed')
        self.assertEqual(observation['source_profile']['id'], self.profile['id'])
        pairs = [(row['stage'], row['event']) for row in observation['phase_events']]
        self.assertIn(('candidate', 'launched'), pairs)
        self.assertIn(('application', 'release-smoke-active'), pairs)
        self.assertGreater(observation['streams']['stdout']['bytes_hashed'], 0)
        self.assertGreater(observation['streams']['stderr']['bytes_hashed'], 0)
        self.assertEqual(len(observation['streams']['stderr']['sha256']), 64)
        self.assertEqual(diagnostic._read_initial_observation(path, expected_profile=self.profile), observation)

    def test_initial_observation_classifies_split_fixed_tokens_and_withholds_unknown_text(self):
        names = list(self.profile['modules'])
        text = ''.join("import './" + name + "';\n" for name in names if name != 'native-rc-smoke.mjs')
        hidden_path = "/" + "/".join(("private", "secret", "node"))
        text += """import {spawn} from 'node:child_process';
import {writeFileSync} from 'node:fs';
import {join} from 'node:path';
export async function runSmoke(options) {
 const child=spawn(process.execPath,['-e',"process.stderr.write('dbus-run-sess');setTimeout(()=>process.stderr.write('ion: dbus-daemon failed: no such file\\\\ncommand not found\\\\nHIDDEN_FIXTURE_PATH: UNKNOWN_PRIVATE_MARKER_947\\\\n'),5)"],{stdio:['ignore','ignore','pipe']});
 child.stderr.on('data',()=>{});
 await new Promise(resolve=>child.once('exit',resolve));
 writeFileSync(join(options.evidenceDir,options.label+'.receipt.json'),'{}');
 writeFileSync(join(options.evidenceDir,options.label+'.run.json'),'{}');
 return {label:options.label,status:'fail',problems:[]};
}
"""
        text = text.replace("HIDDEN_FIXTURE_PATH", hidden_path)
        self._reseal_harness(text)
        result = self.run_wrapper(self.initial_command())
        self.assertEqual(result.returncode, 1, result.stderr)
        raw = (self.root / 'initial-observation.json').read_bytes()
        self.assertNotIn(hidden_path.encode(), raw)
        observation = json.loads(raw)
        categories = observation['error_category_counts']
        helpers = observation['helper_identifier_counts']
        self.assertEqual(categories['dbus-daemon-error'], 1)
        self.assertEqual(categories['command-not-found'], 1)
        self.assertEqual(helpers['dbus-run-session'], 1)
        self.assertEqual(helpers['dbus-daemon'], 1)
        self.assertEqual(helpers['node'], 1)
        self.assertEqual(helpers['native-rc-smoke.mjs'], 0)
        self.assertEqual(set(observation['error_category_counts']), diagnostic.INITIAL_ERROR_CATEGORIES)
        self.assertEqual(set(observation['helper_identifier_counts']), diagnostic.INITIAL_HELPER_IDENTIFIERS)

    def test_initial_observation_bounds_large_child_stream_before_write(self):
        names = list(self.profile['modules'])
        text = ''.join("import './" + name + "';\n" for name in names if name != 'native-rc-smoke.mjs')
        text += """import {spawn} from 'node:child_process';
import {writeFileSync} from 'node:fs';
import {join} from 'node:path';
export async function runSmoke(options) {
 const child=spawn(process.execPath,['-e',"process.stderr.write('x'.repeat(2*1024*1024))"],{stdio:['ignore','ignore','pipe']});
 child.stderr.on('data',()=>{});
 await new Promise(resolve=>child.once('exit',resolve));
 writeFileSync(join(options.evidenceDir,options.label+'.receipt.json'),'{}');
 writeFileSync(join(options.evidenceDir,options.label+'.run.json'),'{}');
 return {label:options.label,status:'fail',problems:[]};
}
"""
        self._reseal_harness(text)
        result = self.run_wrapper(self.initial_command())
        self.assertEqual(result.returncode, 1, result.stderr)
        observation = json.loads((self.root / 'initial-observation.json').read_bytes())
        stderr = observation['streams']['stderr']
        self.assertEqual(stderr['bytes_hashed'], diagnostic.INITIAL_OBSERVATION_MAX_STREAM_BYTES)
        self.assertEqual(stderr['bytes_seen'], diagnostic.INITIAL_OBSERVATION_MAX_STREAM_BYTES + 1)
        self.assertTrue(stderr['truncated'])
        self.assertTrue(observation['truncated'])
        self.assertTrue(observation['non_admitting'])

    def _initial_fixture(self, body):
        names = list(self.profile['modules'])
        imports = ''.join("import './" + name + "';\n" for name in names if name != 'native-rc-smoke.mjs')
        self._reseal_harness(imports + """
import childProcess from 'node:child_process';
import fs from 'node:fs';
import {join} from 'node:path';
import assert from 'node:assert/strict';
export async function runSmoke(options) {
""" + body + """
  return {label:options.label,status:'fail',problems:[]};
}
""")

    def test_initial_stream_delivery_precedes_observer_and_preserves_emit_contract(self):
        self._initial_fixture(r"""
  const child = childProcess.spawn(process.execPath, ['-e','setInterval(()=>{},1000)'],
    {stdio:['ignore','pipe','pipe']});
  const exited = new Promise(resolve => child.once('exit', resolve));
  const originalRename = fs.renameSync;
  let renames = 0, delivered = 0, throwingDelivered = 0;
  fs.renameSync = function(...args) { renames++; return originalRename.apply(this,args); };
  try {
    for (const stream of [child.stdout, child.stderr]) {
      stream.on('data', () => { assert.equal(renames, 0); delivered++; });
      assert.equal(stream.emit('data',Buffer.from('dbus-daemon failed\n')), true);
      const sentinel = new Error('fixture listener exception');
      stream.once('data', () => { throwingDelivered++; throw sentinel; });
      assert.throws(() => stream.emit('data',Buffer.from('command not found\n')), error => error === sentinel);
      assert.equal(renames, 0);
    }
    await new Promise(resolve => setTimeout(resolve,12));
    assert.ok(renames > 0);
    fs.writeFileSync(join(options.evidenceDir,'delivery-proof.json'),
      JSON.stringify({delivered,throwingDelivered,renames,originalReturn:true,originalException:true}));
  } finally {
    fs.renameSync = originalRename;
    child.kill('SIGTERM'); await exited;
  }
""")
        result = self.run_wrapper(self.initial_command())
        self.assertEqual(result.returncode, 1, result.stderr)
        proof = json.loads((self.evidence/'delivery-proof.json').read_bytes())
        self.assertEqual(proof['delivered'], 4)
        self.assertEqual(proof['throwingDelivered'], 2)
        self.assertTrue(proof['originalReturn'] and proof['originalException'])
        observation = json.loads((self.root/'initial-observation.json').read_bytes())
        # A throwing listener prevents subsequent optional observation.
        self.assertEqual(observation['error_category_counts']['command-not-found'], 0)
        self.assertEqual(observation['error_category_counts']['dbus-daemon-error'], 2)

    def test_initial_snapshot_writes_coalesce_saturate_and_stop_after_stream_cap(self):
        self._initial_fixture(r"""
  const child = childProcess.spawn(process.execPath, ['-e','setInterval(()=>{},1000)'],
    {stdio:['ignore','pipe','pipe']});
  const exited = new Promise(resolve => child.once('exit', resolve));
  child.stdout.on('data',()=>{}); child.stderr.on('data',()=>{});
  const originalRename = fs.renameSync;
  let renames = 0, syncRenames = -1, plateauBefore = -1, plateauAfter = -1;
  const proofPath = join(options.evidenceDir,'write-bound-proof.json');
  fs.renameSync = function(...args) {
    renames++;
    const result = originalRename.apply(this,args);
    fs.writeFileSync(proofPath,JSON.stringify({renames,syncRenames,plateauBefore,plateauAfter}));
    return result;
  };
  try {
    for (let n=0;n<8192;n++) child.stdout.emit('data',Buffer.from('x'));
    syncRenames = renames;
    assert.equal(syncRenames,0);
    await new Promise(resolve => setTimeout(resolve,12));
    assert.equal(renames,1);
    for (let n=0;n<100;n++) {
      child.stdout.emit('data',Buffer.from('x'));
      await new Promise(resolve => setTimeout(resolve,10));
    }
    plateauBefore = renames;
    for (let n=0;n<100;n++) {
      child.stdout.emit('data',Buffer.from('x'));
      await new Promise(resolve => setTimeout(resolve,10));
    }
    plateauAfter = renames;
    assert.equal(plateauAfter,plateauBefore);
    assert.ok(renames <= 31);
    child.stderr.emit('data',Buffer.alloc(2*1024*1024,120));
    for (let n=0;n<4096;n++) child.stderr.emit('data',Buffer.from('command not found\n'));
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(renames,plateauAfter);
  } finally {
    child.kill('SIGTERM'); await exited;
    // Retain the spy through wrapper finalization to count its reserved final write.
  }
""")
        result = self.run_wrapper(self.initial_command())
        self.assertEqual(result.returncode, 1, result.stderr)
        proof = json.loads((self.evidence/'write-bound-proof.json').read_bytes())
        self.assertEqual(proof['syncRenames'], 0)
        self.assertEqual(proof['plateauBefore'], proof['plateauAfter'])
        self.assertLessEqual(proof['renames'], 32)
        self.assertEqual(proof['renames'], proof['plateauAfter'] + 1)
        raw = (self.root/'initial-observation.json').read_bytes()
        observation = json.loads(raw)
        self.assertLessEqual(len(raw), diagnostic.INITIAL_OBSERVATION_MAX_BYTES)
        self.assertTrue(observation['truncated'])
        self.assertEqual(observation['streams']['stderr']['bytes_hashed'],
                         diagnostic.INITIAL_OBSERVATION_MAX_STREAM_BYTES)
        self.assertEqual(observation['streams']['stderr']['bytes_seen'],
                         diagnostic.INITIAL_OBSERVATION_MAX_STREAM_BYTES + 1)
        self.assertEqual(observation['error_category_counts']['command-not-found'], 0)
        self.assertEqual(diagnostic._read_initial_observation(
            self.root/'initial-observation.json', expected_profile=self.profile), observation)

    def test_initial_late_category_survives_outer_kill_without_finish(self):
        original = Path(diagnostic.__file__).with_name('replay_progress_wrapper.mjs').read_text()
        self.assertIn('const INITIAL_SNAPSHOT_INTERVAL_MS = 8_000;', original)
        self.assertIn('timer.unref();', original)
        self._initial_fixture(r"""
  const child = childProcess.spawn(process.execPath,['-e','setInterval(()=>{},1000)'],
    {stdio:['ignore','pipe','pipe']});
  const exited = new Promise(resolve => child.once('exit', resolve));
  child.stdout.on('data',()=>{}); child.stderr.on('data',()=>{});
  for (let n=0;n<60;n++) {
    child.stderr.emit('data',Buffer.from('fixture chatter\n'));
    await new Promise(resolve => setImmediate(resolve));
  }
  await new Promise(resolve => setTimeout(resolve,100));
  child.stderr.emit('data',Buffer.from('dbus-daemon failed: command not found\n'));
  await new Promise(resolve => setTimeout(resolve,30));
  child.kill('SIGTERM'); await exited;
  fs.writeFileSync(join(options.evidenceDir,'late-observation-ready.json'),
    JSON.stringify({frames:60,ownedChildExited:true}));
  await new Promise(resolve => setTimeout(resolve,60000));
""")
        process = subprocess.Popen(self.initial_command(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            ready = self.evidence/'late-observation-ready.json'
            deadline = time.monotonic() + 5
            while not ready.exists():
                self.assertIsNone(process.poll(), 'wrapper exited before kill fixture')
                self.assertLess(time.monotonic(), deadline, 'fixture did not become ready')
                time.sleep(.01)
            proof = json.loads(ready.read_bytes())
            self.assertEqual(proof['frames'], 60)
            self.assertTrue(proof['ownedChildExited'])
            process.kill()
            stdout, stderr = process.communicate(timeout=5)
            self.assertEqual(process.returncode, -9, stderr)
            self.assertEqual(stdout, b'')
            observation = diagnostic._read_initial_observation(
                self.root/'initial-observation.json', expected_profile=self.profile)
            self.assertEqual(observation['status'], 'observing')
            self.assertEqual(observation['error_category_counts']['dbus-daemon-error'], 1)
            self.assertEqual(observation['error_category_counts']['command-not-found'], 1)
            self.assertFalse(any(row['event'] == 'returned' for row in observation['phase_events']))
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=5)

    def test_python_attempt_builds_accepted_real_wrapper_argv_and_preserves_evidence(self):
        self._initial_fixture(r"""
  fs.writeFileSync(join(options.evidenceDir,options.label+'.run.json'),
    JSON.stringify({status:'pass',problems:[],executable:{sha256:'a'.repeat(64)}}));
  fs.writeFileSync(join(options.evidenceDir,options.label+'.receipt.json'),'{}');
""".replace("return {label:options.label,status:'fail',problems:[]};", "return {label:options.label,status:'pass',problems:[]};"))
        # The helper's default terminal result is a deliberate fixture failure;
        # this integration case needs a passing synthetic run record.
        harness = (self.tools/'native-rc-smoke.mjs').read_text()
        harness = harness.replace("return {label:options.label,status:'fail',problems:[]};",
                                  "return {label:options.label,status:'pass',problems:[]};")
        self._reseal_harness(harness)
        before = {str(path):path.read_bytes() for path in self.source.rglob('*') if path.is_file()}
        binary = self.root/'fixture-bin'
        binary.mkdir()
        for name, flag in [('xvfb-run','-a'),('dbus-run-session','--')]:
            path = binary/name
            path.write_text('#!/bin/sh\n[ "$1" = "' + flag + '" ] || exit 97\nshift\nexec "$@"\n')
            path.chmod(0o700)
        progress = self.evidence/'legacy-progress.jsonl'
        observation = self.evidence/'initial-observation.json'
        stale = self.evidence/'initial-observation.json.tmp-stale'
        stale.write_bytes(b'owned stale fixture')
        descriptor = {'wrapper':self.wrapper,'harness':self.tools/'native-rc-smoke.mjs',
                      'progress':progress,'path':observation,'profile':self.profile}
        env = dict(os.environ)
        env['PATH'] = str(binary) + os.pathsep + str(Path(self.node).parent) + os.pathsep + env.get('PATH','')
        with patch.object(diagnostic, 'CURRENT_REPLAY_PROGRESS_PROFILE', self.profile):
            fields = diagnostic._attempt(
                {'tools':self.tools,'source':self.source,'checkout':self.source},
                'linux-x64','C',self.root/'empty-runtime',self.evidence,[],env,False,
                timeout=5,system='x86_64-linux',initial_observation=descriptor)
        self.assertFalse(fields['failed'], fields)
        self.assertEqual(fields['exit_code'], 0)
        self.assertEqual(fields['receipt']['status'], 'pass')
        self.assertEqual(fields['initial_observation']['status'], 'completed')
        self.assertEqual(fields['initial_observation']['source_profile']['id'], self.profile['id'])
        self.assertFalse(progress.exists())
        self.assertEqual(stale.read_bytes(), b'owned stale fixture')
        self.assertEqual(list(self.evidence.glob('initial-observation.json.tmp-*')), [stale])
        self.assertEqual(before,{str(path):path.read_bytes() for path in self.source.rglob('*') if path.is_file()})

    def test_initial_snapshot_budget_covers_original_outer_timeout(self):
        source = Path(diagnostic.__file__).with_name('replay_progress_wrapper.mjs').read_text()
        writes = int(re.search(r'const MAX_INITIAL_SNAPSHOT_WRITES = (\d+);',source).group(1))
        interval = int(re.search(r'const INITIAL_SNAPSHOT_INTERVAL_MS = ([\d_]+);',source).group(1).replace('_',''))
        timeout = inspect.signature(diagnostic._attempt).parameters['timeout'].default
        # One leading snapshot and one reserved final snapshot leave writes-2 intervals.
        self.assertGreaterEqual((writes-2)*interval,timeout*1000)

    def test_initial_observer_write_fault_disables_only_optional_observation(self):
        destination = self.root / 'observation-directory'
        destination.mkdir()
        command = self.initial_command()
        command[command.index('--rs9-initial-observation-file') + 1] = str(destination)
        result = self.run_wrapper(command)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(json.loads(result.stdout)['status'], 'fail')
        self.assertTrue(destination.is_dir())

    def _reseal_harness(self, text):
        harness = self.tools / "native-rc-smoke.mjs"
        harness.write_text(text)
        self.profile["modules"][harness.name] = pin(harness.read_bytes())
        original = self.wrapper.read_text()
        start = original.index('const CURRENT_PROFILE = Object.freeze(')
        end = original.index(');\n', start) + 3
        self.wrapper.write_text(original[:start] + 'const CURRENT_PROFILE = Object.freeze('
                               + json.dumps(self.profile) + ');\n' + original[end:])

    def test_late_stderr_consumer_retains_flow_state_and_every_byte(self):
        harness = self.tools / 'native-rc-smoke.mjs'
        text = harness.read_text().replace("},5);},5);`;", "},5);},5);setTimeout(()=>{},200);`;")
        text = text.replace("  let out='';let err='';child.stdout.on", "  const flowBefore=child.stderr.readableFlowing;const listenersBefore=child.stderr.listenerCount('data');\n  await new Promise(resolve=>setTimeout(resolve,50));\n  let out='';let err='';child.stdout.on")
        text = text.replace("JSON.stringify({out,err})", "JSON.stringify({out,err,flowBefore,listenersBefore})")
        self._reseal_harness(text)
        result = self.run_wrapper(); self.assertEqual(result.returncode,1,result.stderr)
        streams = json.loads((self.evidence / 'stream-check.json').read_bytes())
        self.assertIsNone(streams['flowBefore'])
        self.assertEqual(streams['listenersBefore'],0)
        self.assertEqual(streams['err'],'UNKNOWN_PRIVATE_MARKER_947\nTFSB Studio release smoke scenario C active\n')
        self.assertEqual(streams['out'],'UNCHANGED_STDOUT')

    def test_never_drained_pipe_is_not_put_in_flowing_mode(self):
        harness = self.tools / 'native-rc-smoke.mjs'
        # Only a synthetic owned Node child is launched. Its unread pipe retains
        # backpressure; terminate this test-owned child after the observation.
        text = "".join("import './" + name + "';\n" for name in self.profile['modules'] if name != harness.name)
        text += """import {spawn} from 'node:child_process';
import {writeFileSync} from 'node:fs';
import {join} from 'node:path';
export async function runSmoke(options) {
 const child=spawn(process.execPath,['-e',"process.stderr.write('x'.repeat(4*1024*1024))"],{stdio:['ignore','ignore','pipe']});
 const exited=new Promise(resolve=>child.once('exit',resolve));
 await new Promise(resolve=>setTimeout(resolve,200));
 const state={flow:child.stderr.readableFlowing,listeners:child.stderr.listenerCount('data'),running:child.exitCode===null};
 child.kill('SIGTERM');await exited;
 writeFileSync(join(options.evidenceDir,'pipe-state.json'),JSON.stringify(state));
 return {label:options.label,status:'fail',problems:[]};
}
"""
        self._reseal_harness(text)
        result=self.run_wrapper();self.assertEqual(result.returncode,1,result.stderr)
        state=json.loads((self.evidence/'pipe-state.json').read_bytes())
        self.assertIsNone(state['flow']);self.assertEqual(state['listeners'],0);self.assertTrue(state['running'])
        events=diagnostic._read_replay_progress(self.root/'progress.jsonl')
        self.assertFalse(any(row['stage']=='application' for row in events['events']))

    def test_arm_and_signal_scenario_markers_use_the_exact_validated_scenario(self):
        original = (self.tools / 'native-rc-smoke.mjs').read_text()
        for platform, scenario in [('linux-arm64','B'),('linux-x64','C-signal')]:
            with self.subTest(platform=platform, scenario=scenario):
                progress = self.root / 'progress.jsonl'
                if progress.exists(): progress.unlink()
                self._reseal_harness(original.replace('rio C active', 'rio ' + scenario + ' active'))
                argv = self.command()
                argv[argv.index('--platform') + 1] = platform
                argv[argv.index('--scenario') + 1] = scenario
                result = self.run_wrapper(argv)
                self.assertEqual(result.returncode, 1, result.stderr)
                observed = diagnostic._read_replay_progress(progress)
                self.assertEqual(sum(row['stage']=='application' for row in observed['events']),1)

    def test_unknown_or_private_marker_is_ignored(self):
        harness = self.tools / "native-rc-smoke.mjs"
        harness.write_text(harness.read_text().replace("rio C active", "rio D active"))
        self.profile["modules"][harness.name] = pin(harness.read_bytes())
        original = self.wrapper.read_text()
        start = original.index('const CURRENT_PROFILE = Object.freeze(')
        end = original.index(');\n', start) + 3
        self.wrapper.write_text(original[:start] + 'const CURRENT_PROFILE = Object.freeze('
                               + json.dumps(self.profile) + ');\n' + original[end:])
        result = self.run_wrapper()
        self.assertEqual(result.returncode, 1, result.stderr)
        events = diagnostic._read_replay_progress(self.root / 'progress.jsonl')
        self.assertFalse(any(row['stage'] == 'application' for row in events['events']))
        self.assertNotIn('UNKNOWN_PRIVATE_MARKER_947', json.dumps(events))

    def test_missing_extra_wrong_module_support_identity_refuse_before_import(self):
        original = self.command()
        variants=[]
        for flag in ('--rs9-replay-progress-profile','--rs9-replay-progress-source-commit','--rs9-replay-progress-source-tree'):
            value=list(original);value[value.index(flag)+1]='wrong';variants.append(value)
        value=list(original);index=value.index('--rs9-replay-progress-closure-member');del value[index:index+2];variants.append(value)
        value=list(original);value += ['--rs9-replay-progress-closure-member','extra.mjs='+'0'*64];variants.append(value)
        value=list(original);value += ['--rs9-replay-progress-closure-member',next(iter(self.profile['modules']))+'='+'0'*64];variants.append(value)
        value=list(original);value[value.index('--rs9-replay-progress-support-member')+1]='package.json='+'0'*64;variants.append(value)
        for value in variants:
            result=self.run_wrapper(value);self.assertNotEqual(result.returncode,0)
            self.assertFalse((self.root/'progress.jsonl').exists(),result.stdout)
        for target in (self.tools/'fs-snapshot.mjs',self.source/'package.json'):
            saved=target.read_bytes();target.write_bytes(b'changed')
            result=self.run_wrapper();self.assertNotEqual(result.returncode,0)
            self.assertFalse((self.root/'progress.jsonl').exists());target.write_bytes(saved)

    def test_git_blob_and_package_version_refuse_even_if_other_unit_pins_resealed(self):
        for kind in ('blob','version'):
            profile=copy.deepcopy(self.profile)
            if kind=='blob':profile['modules']['fs-snapshot.mjs']['blob']='0'*40
            else:
                (self.source/'package.json').write_text('{"version":"0.6.1"}')
                profile['support']=pin((self.source/'package.json').read_bytes())
            original=self.wrapper.read_text();start=original.index('const CURRENT_PROFILE = Object.freeze(');end=original.index(');\n',start)+3
            self.wrapper.write_text(original[:start]+'const CURRENT_PROFILE = Object.freeze('+json.dumps(profile)+');\n'+original[end:])
            if kind=='version':self.profile=profile
            result=self.run_wrapper();self.assertNotEqual(result.returncode,0)
            self.assertFalse((self.root/'progress.jsonl').exists())
            self.wrapper.write_text(original)
