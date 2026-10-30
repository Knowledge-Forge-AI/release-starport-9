"""Current replay profile fixtures; synthetic pins never qualify native applications."""
import copy
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from rs9 import application_smoke_diagnostic as diagnostic
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
