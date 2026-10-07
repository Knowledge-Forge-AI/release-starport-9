"""Synthetic transport fixture with real disjoint filesystem and Node execution.

This is source regression evidence, never native package qualification.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from rs9.build_native import CommandReceipt
from rs9.errors import ContractError
from rs9.hosted_container_smoke import (
    RUNTIME, SCHEMA, _logical_io, configure_container_output,
    prepare_container_smoke, read_output, verify_container_nebular,
)
from rs9.hosted_smoke import _inventory_runtime, runtime_evidence
from rs9.release_core import digest
from rs9.scratch import canonical


class ProtocolTests(unittest.TestCase):
    def test_missing_guest_output_preserves_command_receipt(self):
        receipt = CommandReceipt(['fixture'], 137, b'bounded stdout', b'bounded stderr', executed=True)
        class Client:
            def exec(self, argv, **kwargs):
                return receipt
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ContractError) as caught:
                verify_container_nebular(Client(), {'output': Path(tmp), 'family': 'pacman'}, user='65534:65534')
        self.assertEqual(caught.exception.code, 'SMOKE_OUTPUT')
        self.assertEqual(caught.exception.details['exit_code'], 137)
        self.assertEqual(caught.exception.details['stdout_sha256'], receipt.stdout_sha256)
        self.assertEqual(caught.exception.details['stderr_sha256'], receipt.stderr_sha256)

    def test_request_parse_failures_write_sanitized_result(self):
        from rs9 import hosted_container_smoke as m
        for raw in (b'{invalid', b'[]', b'{}'):
            with self.subTest(raw=raw), tempfile.TemporaryDirectory() as tmp:
                guest = Path(tmp)
                (guest / 'input').mkdir()
                (guest / 'out').mkdir()
                (guest / 'input/request.json').write_bytes(raw)
                with patch.object(m, 'GUEST', guest), patch('os.getuid', return_value=65534):
                    self.assertEqual(m.guest_main(), 2)
                result = read_output(guest / 'out/result.json')
                self.assertEqual(result['status'], 'fail')
                self.assertEqual(result['code'], 'SMOKE_INPUT')
                self.assertEqual(result['request_sha256'], digest(raw))
                self.assertNotIn('missing_path', result['details'])

    def test_outputs_reject_symlinks_special_files_oversize_and_malformed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            actual = root / "actual"
            actual.write_text('{}')
            link = root / "link"
            link.symlink_to(actual)
            fifo = root / "fifo"
            os.mkfifo(fifo)
            for path in (link, fifo):
                with self.assertRaises(ContractError):
                    read_output(path)
            with self.assertRaises(ContractError):
                read_output(actual, 1)
            actual.write_text('[1]')
            with self.assertRaises(ContractError):
                read_output(actual)
            actual.write_text('malformed')
            with self.assertRaises(ContractError):
                read_output(actual)

    def test_missing_resource_uses_logical_location(self):
        for path, resource in ((RUNTIME + '/bin/missing', 'installed-runtime'),
                               ('/srv/rs9/smoke/source/tools/missing.mjs', 'verifier-source'),
                               ('/private/operator-secret/file', 'verifier-output')):
            doc = _logical_io(FileNotFoundError(2, 'fixture', path))
            self.assertEqual(doc['cause'], resource)
            self.assertFalse(doc['missing_path'].startswith('/'))
            self.assertNotIn('operator-secret', json.dumps(doc))

    def test_output_permissions_have_explicit_unprivileged_owner(self):
        class Client:
            def exec(self, argv):
                self.argv = argv
                return CommandReceipt(argv, 0, b'', b'', executed=True)
        client = Client()
        configure_container_output(client, user='65534:65534')
        self.assertIn('os.chown(p,65534,65534)', client.argv[-1])
        self.assertIn('os.chmod(p,0o755)', client.argv[-1])
        with self.assertRaises(ContractError):
            configure_container_output(client, user='0:0')


@unittest.skipUnless(shutil.which('node'), 'Node needed for disjoint filesystem fixture')
class DisjointFilesystemTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name).resolve()
        self.guest = self.work / 'guest'
        self.runtime = self.guest / 'usr/lib/theme-forge-nebular-fusion'
        (self.runtime / 'bin').mkdir(parents=True)
        (self.runtime / 'bin/tfsb-studio-service').write_bytes(b'fixture-authenticated-native')
        payload = self.runtime / 'lib/sidecar-payload'
        payload.mkdir(parents=True)
        (payload / 'manifest.json').write_bytes(b'{}')
        source = self.work / 'host/source'
        tools = source / 'tools'
        tools.mkdir(parents=True)
        (tools / 'sidecar-common.mjs').write_text(
            "import{readFileSync}from'node:fs';export async function verifyDistribution(p){"
            "if(readFileSync(p.binaryPath).toString()!=='fixture-authenticated-native')throw Error('bytes');"
            "if(readFileSync(p.payloadRoot+'/manifest.json').toString()!=='{}')throw Error('manifest');return{verified:true};}")
        (tools / 'sidecar-verify.mjs').write_text('export function verifySidecar(){}')
        (tools / 'native-rc-smoke.mjs').write_text(
            "import{readFileSync,writeFileSync}from'node:fs';import{createHash}from'node:crypto';"
            "if(process.argv.includes('--scenario')){const a=process.argv;const v=k=>a[a.indexOf(k)+1];"
            "const b=readFileSync(v('--launch-root')+'/bin/tfsb-studio-service');"
            "const sha=createHash('sha256').update(b).digest('hex');"
            "writeFileSync(v('--evidence')+'/'+v('--label')+'.run.json',JSON.stringify({status:'pass',problems:[],executable:{sha256:sha}}));}")
        records = []
        for path in sorted(tools.iterdir()):
            data = path.read_bytes()
            records.append({'path':path.relative_to(source).as_posix(), 'size':len(data),
                            'sha256':digest(data), 'blob':hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()})
        expected = _inventory_runtime(self.runtime)[0]
        scratch = self.work / 'host/smoke'
        scratch.mkdir()
        prepared = {'source':source,'tools':tools,'scratch':scratch,'records':records,
                    'expected_members':expected,'manifest_sha256':digest(canonical(expected))}
        self.guest_smoke = self.guest / 'srv/rs9/smoke'
        # Explicit transport mapping; all guest reads below execute in a separate
        # interpreter. No runtime filesystem operation is mocked.
        with patch('rs9.hosted_container_smoke.GUEST', self.guest_smoke):
            self.binding = prepare_container_smoke(prepared,'x86_64-linux','pacman')
        self.guest_smoke.mkdir(parents=True)
        for src, target, writable in self.binding['mounts']:
            if writable:
                Path(target).mkdir()
            else:
                shutil.copytree(src,target)
        self.bin = self.work / 'fixture-bin'
        self.bin.mkdir()
        (self.bin / 'node').symlink_to(shutil.which('node'))
        for name, content in [('xvfb-run','#!/bin/sh\nshift; exec "$@"\n'),
                              ('dbus-run-session','#!/bin/sh\nshift; exec "$@"\n')]:
            (self.bin / name).write_text(content)
            (self.bin / name).chmod(0o755)

    def client(self, before_main=''):
        case = self
        class Client:
            def exec(self, argv, *, user):
                case.assertEqual(user,'65534:65534')
                code = ("from pathlib import Path;import os;"
                        "from rs9 import hosted_container_smoke as m;"
                        f"m.GUEST=Path({str(case.guest_smoke)!r});m.RUNTIME={str(case.runtime)!r};"
                        # Fixture transport cannot change host UID. Production
                        # guest_main enforces the actual UID, tested separately.
                        "os.getuid=lambda:65534;" + before_main + "\nraise SystemExit(m.guest_main())")
                env = dict(os.environ,PYTHONPATH=str(Path(__file__).resolve().parents[1]/'src'),
                           PYTHONDONTWRITEBYTECODE='1',PATH=str(case.bin)+':'+os.environ.get('PATH',''))
                run = subprocess.run([sys.executable,'-W','error::ResourceWarning','-c',code],capture_output=True,env=env)
                shutil.copytree(case.guest_smoke/'out',case.binding['output'],dirs_exist_ok=True)
                return CommandReceipt(argv,run.returncode,run.stdout,run.stderr,executed=True)
        return Client()

    def test_real_guest_only_reads_and_commands_succeed(self):
        self.assertFalse(Path(RUNTIME).exists())
        with self.assertRaises(FileNotFoundError):
            runtime_evidence(RUNTIME, RUNTIME+'/bin/tfsb-studio-service', RUNTIME+'/lib/sidecar-payload/manifest.json')
        original_open, original_lstat = os.open, Path.lstat
        def guarded_open(path, *args, **kwargs):
            if isinstance(path,(str,Path)) and str(path).startswith(str(self.runtime)):
                raise AssertionError('Host read of guest runtime')
            return original_open(path,*args,**kwargs)
        def guarded_lstat(path,*args,**kwargs):
            if str(path).startswith(str(self.runtime)):
                raise AssertionError('Host stat of guest runtime')
            return original_lstat(path,*args,**kwargs)
        with patch('os.open',guarded_open),patch.object(Path,'lstat',guarded_lstat):
            result = verify_container_nebular(self.client(),self.binding,user='65534:65534')
        self.assertTrue(result['sidecar']['verified'])
        self.assertEqual(result['filesystem'],'installed-client')
        self.assertEqual(len(result['scenarios']),2)
        self.assertTrue(all(not rw for src,target,rw in self.binding['mounts'] if not target.endswith('/out')))
        diag = json.loads((self.work/'host/diagnostics/sidecar-verifier-pacman.json').read_bytes())
        self.assertEqual(diag['materializer_source'],'installed-package')
        self.assertEqual(diag['sidecar_binary_sha256'],digest(b'fixture-authenticated-native'))

    def test_guest_source_readback_detects_changed_transport(self):
        (self.guest_smoke/'source/tools/sidecar-common.mjs').write_text('changed')
        with self.assertRaises(ContractError) as caught:
            verify_container_nebular(self.client(),self.binding,user='65534:65534')
        self.assertEqual(caught.exception.code,'SIDECAR_HARNESS_IMPORT')

    def test_unexpected_guest_exception_is_returned_without_private_message(self):
        injection = "\ndef crash(*a,**k): raise RuntimeError('/private/fixture-secret')\nm.verify_nebular_runtime=crash\n"
        with self.assertRaises(ContractError) as caught:
            verify_container_nebular(self.client(injection), self.binding, user='65534:65534')
        self.assertEqual(caught.exception.code, 'SMOKE_EXECUTION')
        doc = read_output(self.binding['output'] / 'result.json')
        self.assertEqual(doc['details']['exception_type'], 'RuntimeError')
        self.assertNotIn('fixture-secret', json.dumps(doc))
        self.assertNotIn('missing_path', doc['details'])

    def test_smoke_nonzero_timeout_and_missing_receipt_have_distinct_evidence(self):
        for fault in ('nonzero', 'timeout', 'missing'):
            with self.subTest(fault=fault):
                # Remove only this fixture's previous output before a fresh guest run.
                for root in (self.guest_smoke / 'out', self.binding['output']):
                    for path in root.iterdir():
                        shutil.rmtree(path) if path.is_dir() else path.unlink()
                injection = ("\nimport subprocess\noriginal_run=subprocess.run\n"
                    "def injected_run(argv,**kwargs):\n"
                    " if any(str(a).endswith('native-rc-smoke.mjs') for a in argv) and '--scenario' in argv:\n")
                if fault == 'timeout':
                    injection += "  raise subprocess.TimeoutExpired(argv,240,output=b'fixture-out',stderr=b'fixture-err')\n"
                else:
                    injection += f"  return subprocess.CompletedProcess(argv,{23 if fault == 'nonzero' else 0},b'fixture-out',b'fixture-err')\n"
                injection += " return original_run(argv,**kwargs)\nsubprocess.run=injected_run\n"
                with self.assertRaises(ContractError) as caught:
                    verify_container_nebular(self.client(injection), self.binding, user='65534:65534')
                self.assertEqual(caught.exception.code, 'APPLICATION_SMOKE')
                details = read_output(self.binding['output'] / 'result.json')['details']
                self.assertEqual(details['stdout_sha256'], digest(b'fixture-out'))
                self.assertEqual(details['stderr_sha256'], digest(b'fixture-err'))
                self.assertEqual(caught.exception.details['stdout_sha256'], details['stdout_sha256'])
                self.assertEqual(caught.exception.details['stderr_sha256'], details['stderr_sha256'])
                if fault == 'nonzero':
                    self.assertEqual(caught.exception.details['exit_code'], 23)
                self.assertEqual(details['reason_token'], {'nonzero': 'process-nonzero', 'timeout': 'process-timeout', 'missing': 'receipt-missing'}[fault])
                if fault == 'missing':
                    self.assertEqual(details['missing_path'], 'output/evidence/linux-x64-C.run.json')
                else:
                    self.assertNotIn('missing_path', details)

    def test_malformed_diagnostic_preserves_primary_guest_failure(self):
        injection = ("\ndef crash(*a,**k):\n"
            " p=m.GUEST/'out/diagnostics';p.mkdir();(p/'sidecar-verifier-pacman.json').write_text('invalid')\n"
            " raise ContractError('APPLICATION_SMOKE','Fixture failure',details={'reason_token':'process-nonzero'})\n"
            "from rs9.errors import ContractError\nm.verify_nebular_runtime=crash\n")
        with self.assertRaises(ContractError) as caught:
            verify_container_nebular(self.client(injection), self.binding, user='65534:65534')
        self.assertEqual(caught.exception.code, 'APPLICATION_SMOKE')
        doc = read_output(self.binding['output'] / 'result.json')
        self.assertEqual(doc['details']['reason_token'], 'process-nonzero')
        self.assertEqual(doc['diagnostic_error']['code'], 'SMOKE_OUTPUT')

    def test_cleanup_runs_after_smoke_failure_and_preserves_primary_error(self):
        from rs9 import hosted_deb as hd
        from test_hosted_deb import ScriptedDocker, ExecutedMock, host_runner
        for dirty in (False, True):
            with self.subTest(dirty=dirty):
                host=hd.RecordingRunner(host_runner(ScriptedDocker(dirty_uninstall=dirty), ExecutedMock))
                spec=hd.pacman_spec(self.work/'pacman',self.work/'keys','A'*40)
                with patch('rs9.hosted_container_smoke.prepare_container_smoke',return_value=self.binding), \
                     patch('rs9.hosted_container_smoke.verify_container_nebular',side_effect=ContractError('APPLICATION_SMOKE','Fixture smoke failure')):
                    rows,evidence=hd.client_cycle(host,spec,image='fixture',platform='linux/amd64',
                        products=[hd.NATIVE_PRODUCT],repository=self.work,prefix='pacman-client',
                        smoke={'fixture':True},system='x86_64-linux')
                product=evidence[hd.NATIVE_PRODUCT]
                self.assertEqual(product['error'],'APPLICATION_SMOKE')
                self.assertEqual(product['stage'],'smoke')
                self.assertTrue(product['positive_control']['success'])
                self.assertEqual(product['cleanup']['status'],'fail' if dirty else 'pass')
                self.assertTrue(any(r['name'].endswith('.uninstall') for r in rows))
                self.assertTrue(any(r['name'].endswith('.inventory') for r in rows))
                self.assertTrue(any(r['name'].endswith('.client') and r['reason']=='APPLICATION_SMOKE' for r in rows))

    def test_output_binding_and_symlink_cannot_qualify(self):
        path = self.binding['output']/'result.json'
        path.write_bytes(canonical({'schema':SCHEMA,'request_sha256':'0'*64,'family':'pacman',
                                   'system':'x86_64-linux','uid':65534,'status':'pass'}))
        class Client:
            def exec(self,argv,**kwargs):
                return CommandReceipt(argv,0,b'',b'',executed=True)
        with self.assertRaises(ContractError):
            verify_container_nebular(Client(),self.binding,user='65534:65534')
        path.unlink()
        path.symlink_to(self.binding['prepared']['source']/'tools/sidecar-common.mjs')
        with self.assertRaises(ContractError):
            verify_container_nebular(Client(),self.binding,user='65534:65534')
