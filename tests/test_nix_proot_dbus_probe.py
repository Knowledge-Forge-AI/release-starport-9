"""Synthetic controls and real disposable harness children, not native PRoot proof."""
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from rs9.nix_proot import Run
from rs9.nix_proot_dbus_probe import (DAEMON_PROBE_SOURCE, SESSION_PROBE_SOURCE, SOCKET_PROBE_SOURCE,
    config_include_structure, daemon_control, decomposition_cause, observed_survivors, run_dbus_decomposition, session_control, socket_control)
from rs9.nix_proot_launch import run_launch_chain
from rs9.scratch import canonical
from rs9.security import scan_for_credentials
from rs9.hosted_contract import validate_hosted_experiment_diagnostic
from tests import test_nix_proot_launch


class DbusControls(unittest.TestCase):
    def test_self_include_is_observed_without_reclassifying_audit_or_daemon(self):
        audit={'status':'pass','audit_complete':True,'files':[{'real_path':'/store/config'}],
               'includes':[{'present':True,'depth':0,'real_path':'/store/config'}]}
        result=config_include_structure(audit)
        self.assertTrue(result['root_self_include_observed'])
        self.assertEqual(result['native_daemon_acceptance'],'unproven')
        self.assertEqual(audit['status'],'pass')
        self.assertFalse(result['qualification_authority'])
    def frame(self, **updates):
        raw = b''
        doc = {'schema': 'rs9.dbus-daemon-control.v1', 'spawn_errno': None,
               'child_pid': 102, 'child_starttime': 5, 'address_class': 'unix',
               'timed_out': False, 'output_limit': False, 'wait_status': 15,
               'raw_returncode': -15, 'reaped': True, 'cleanup_errno': None,
               'stdout_bytes': 35, 'stderr_bytes': len(raw), 'stderr_truncated': False,
               'stderr_sha256': hashlib.sha256(raw).hexdigest(), 'stderr_base64': base64.b64encode(raw).decode()}
        doc.update(updates)
        return Run(0, json.dumps(doc).encode(), b'', .1, None)

    def control(self, run):
        return daemon_control(run, stage='daemon-explicit', argv_sha256='a'*64)

    def test_closed_frame_and_raw_signal_wait(self):
        result = self.control(self.frame())
        self.assertEqual(result['status'], 'observed')
        self.assertEqual(result['raw_returncode'], -15)
        self.assertNotIn('stderr_base64', result)
        for updates in ({'wait_status': 255<<8}, {'raw_returncode': 255}, {'reaped': False},
                        {'child_pid': True}, {'address_class': 'secret'}, {'extra': 1},
                        {'stderr_sha256': 'b'*64}, {'stderr_bytes': 1}, {'stderr_base64': '!'}):
            with self.subTest(updates=updates):
                self.assertEqual(self.control(self.frame(**updates))['status'], 'unobserved')

    def test_truncation_and_timeout_never_give_cause_or_excerpt(self):
        for updates in ({'stderr_bytes': 5000, 'stderr_truncated': True}, {'timed_out': True}, {'output_limit': True}):
            result = self.control(self.frame(**updates))
            self.assertEqual(result['status'], 'fail')
            self.assertFalse(result['stderr_diagnostic']['complete'])
            self.assertNotIn('excerpt', result['stderr_diagnostic'])

    def test_socket_path_and_abstract_are_independent(self):
        doc = {'schema':'rs9.dbus-socket-control.v1','tmp_mode':0o700,'tmp_owner_matches':True,
               'tmp_writable':True,'path':{'bound':True,'errno':None},'abstract':{'bound':False,'errno':97}}
        run = Run(0,json.dumps(doc).encode(),b'',0,None)
        self.assertEqual(socket_control(run)['status'],'observed')
        doc['path']['bound'] = False
        self.assertEqual(socket_control(run._replace(stdout=json.dumps(doc).encode()))['status'],'unobserved')

    def rows(self):
        rows = [{'stage':k,'status':'pass'} for k in ('daemon-version','run-session-version','socket-controls',
                'daemon-default','daemon-explicit','session-tmp','session-root','session-explicit')]
        by = {r['stage']:r for r in rows}
        by['socket-controls']['control'] = {'status':'observed','path':{'bound':True},'abstract':{'bound':False}}
        for k in ('daemon-default','daemon-explicit'):by[k]['control']={'status':'observed'}
        return rows,by

    def test_control_boundaries_and_cwd_precede_orchestration(self):
        rows,by = self.rows()
        self.assertEqual(decomposition_cause(rows,True),'target-or-probe-failed')
        self.assertEqual(decomposition_cause(rows,False),'not-reproduced-in-controls')
        for key,expected in (('daemon-version','daemon-version-control-failed'),
                ('run-session-version','run-session-version-control-failed'),
                ('session-tmp','guest-cwd-dependent'),('session-root','session-control-divergent'),
                ('session-explicit','session-control-divergent')):
            by[key]['status']='fail'
            self.assertEqual(decomposition_cause(rows,True),expected)
            by[key]['status']='pass'
        by['session-tmp']['status']=by['session-root']['status']='fail'
        self.assertEqual(decomposition_cause(rows,True),'run-session-control-failed')
        rows,by=self.rows()
        by['daemon-default']['control']['status']='fail'
        self.assertEqual(decomposition_cause(rows,True),'compiled-config-path-control-divergent')
        by['daemon-explicit']['control']['status']='fail'
        self.assertEqual(decomposition_cause(rows,True),'default-and-explicit-daemon-controls-failed')
        by['daemon-default']['control']['status']='observed'
        self.assertEqual(decomposition_cause(rows,True),'explicit-config-daemon-control-failed')
        by['daemon-version']['status']='unobserved'
        self.assertEqual(decomposition_cause(rows,True),'control-evidence-incomplete')
        rows,by=self.rows();by['socket-controls']['control']['path']['bound']=False
        self.assertEqual(decomposition_cause(rows,True),'path-socket-bind-failed')

    def test_original_first_failure_and_gates_are_preserved_and_packet_safe(self):
        with tempfile.TemporaryDirectory() as temp:
            rt=test_nix_proot_launch.LaunchDiagnostics().runtime(Path(temp),lambda argv,**kw: subprocess.CompletedProcess(argv,127,b'',b'unknown'))
            with patch('rs9.nix_proot_launch.guest_audit',return_value={'files':[],'dbus_config':{'status':'pass'}}):
                result=run_launch_chain(rt)
            self.assertEqual(len(result['stages']),5)
            self.assertEqual(result['first_failure']['stage'],'display-only')
            self.assertEqual(result['first_failure']['raw_returncode'],127)
            self.assertFalse(result['dbus_decomposition']['qualification_authority'])
            scan_for_credentials(canonical({'details':{'evaluation':result}}).decode())
            self.assertNotIn(str(rt.layout.tmp_dir),canonical(result).decode())
            receipt={'schema':'rs9.hosted-experiment-diagnostic.v1alpha1',
                     'production_enabled':False,'publication_authority':False,
                     'qualification_authority':False,'application_qualified':False,
                     'mandatory_gates_satisfied':False,'gates':[],
                     'details':{'evaluation':result}}
            packet=Path(temp).resolve()/'receipt.json';packet.write_bytes(canonical(receipt))
            checked=validate_hosted_experiment_diagnostic(packet)
            self.assertEqual(checked['details']['evaluation'],result)

    def test_pid_reuse_is_observation_only(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);(root/'102').mkdir()
            (root/'102/stat').write_text('102 (dbus daemon) S '+ ' '.join(['0']*18+['7']))
            rt=SimpleNamespace(proc_root=root,sleep=lambda n:None)
            self.assertEqual(observed_survivors(rt,[{'pid':102,'starttime':5}])['survivors'],0)
            self.assertEqual(observed_survivors(rt,[{'pid':102,'starttime':7}])['survivors'],1)
            self.assertFalse(observed_survivors(rt,[{'pid':102,'starttime':7}])['kill_authority'])

    def test_zero_session_exit_without_valid_frame_is_unobserved(self):
        with tempfile.TemporaryDirectory() as temp:
            rt=test_nix_proot_launch.LaunchDiagnostics().runtime(Path(temp),
                lambda argv,**kw: subprocess.CompletedProcess(argv,0,b'{}',b''))
            sockets={'status':'observed','path':{'bound':True},'abstract':{'bound':True}}
            with patch('rs9.nix_proot_dbus_probe.daemon_control',return_value={'status':'observed'}), \
                 patch('rs9.nix_proot_dbus_probe.socket_control',return_value=sockets):
                result=run_dbus_decomposition(rt,True,'pass')
            sessions=[r for r in result['stages'] if r['stage'] in ('session-tmp','session-root')]
            self.assertEqual([r['status'] for r in sessions],['unobserved','unobserved'])
            self.assertEqual(result['dbus_cause'],'control-evidence-incomplete')
            self.assertFalse(result['application_qualified'])

    def test_empty_daemon_observation_does_not_establish_absence(self):
        rt=SimpleNamespace(proc_root=Path('/unavailable-proc'),sleep=lambda n:None)
        run=Run(0,json.dumps({'schema':'rs9.dbus-session-control.v1','complete':True,'daemons':[]}).encode(),b'',0,None)
        result=session_control(rt,run)
        self.assertEqual(result['status'],'unobserved')
        self.assertEqual(result['reason'],'daemon-identity-unobserved')
        self.assertFalse(result['lifecycle']['kill_authority'])

    def test_minimal_config_control_is_temporary_closed_and_reaped(self):
        from rs9.nix_proot_dbus_probe import MINIMAL_CONFIG
        import xml.etree.ElementTree as ET
        config=ET.fromstring(MINIMAL_CONFIG)
        self.assertEqual(config.tag,'busconfig')
        self.assertEqual(config.findtext('listen'),'unix:tmpdir=/tmp')
        self.assertEqual(config.findtext('auth'),'EXTERNAL')
        self.assertEqual(config.findall('.//include'),[])
        self.assertEqual(config.findall('.//allow'),[])
        self.assertEqual(config.find('policy/deny').attrib,{'send_destination':'*'})
        with tempfile.TemporaryDirectory() as temp:
            import os
            code=("import hashlib,pathlib,sys,time;"
                  "p=pathlib.Path(sys.argv[2].removeprefix('--config-file='));"
                  "assert hashlib.sha256(p.read_bytes()).hexdigest()==sys.argv[1];"
                  "print('unix:path=/tmp/control-only',flush=True);time.sleep(30)")
            command=[sys.executable,'-c',code,hashlib.sha256(MINIMAL_CONFIG.encode()).hexdigest()]
            result=subprocess.run([sys.executable,'-I','-S','-B','-W','error','-c',DAEMON_PROBE_SOURCE,
                json.dumps(command),'minimal-no-includes'],env={**os.environ,'TMPDIR':temp},
                capture_output=True,timeout=10,check=True)
            doc=self.control(Run(0,result.stdout,result.stderr,0,None))
            self.assertEqual(doc['status'],'observed')
            self.assertTrue(doc['reaped'])
            self.assertEqual(list(Path(temp).iterdir()),[])
            self.assertEqual(result.stderr,b'')

    def test_minimal_control_keeps_original_config_and_no_application_authority(self):
        with tempfile.TemporaryDirectory() as temp:
            rt=test_nix_proot_launch.LaunchDiagnostics().runtime(Path(temp),
                lambda argv,**kw: subprocess.CompletedProcess(argv,127,b'',b'unknown'))
            result=run_dbus_decomposition(rt,True,'pass')
            by={row['stage']:row for row in result['stages']}
            self.assertIn('daemon-minimal',by)
            self.assertEqual(by['daemon-minimal']['config_variant'],'temporary-minimal-no-includes')
            self.assertEqual(by['daemon-minimal']['qualification_authority'],False)
            self.assertIn('--config-file=/etc/dbus-1/session.conf',' '.join(by['daemon-explicit']['stage_argv']))
            self.assertFalse(result['application_qualified'])

    def test_real_harness_reaps_only_its_child_without_retaining_address(self):
        command=[sys.executable,'-c',"import sys,time;print('unix:path=/tmp/private-socket,guid=abc',flush=True);time.sleep(30)"]
        result=subprocess.run([sys.executable,'-I','-S','-B','-W','error','-c',DAEMON_PROBE_SOURCE,json.dumps(command)],
                              capture_output=True,timeout=10,check=True)
        doc=self.control(Run(result.returncode,result.stdout,result.stderr,0,None))
        self.assertTrue(doc['reaped'])
        self.assertEqual(doc['address_class'],'unix')
        self.assertNotIn(b'private-socket',result.stdout)
        self.assertEqual(result.stderr,b'')

    def test_real_harness_spawn_error_and_oversize_are_bounded(self):
        for command in (['/nonexistent-rs9-daemon'],[sys.executable,'-c',"import sys;sys.stderr.write('x'*5000)"]):
            result=subprocess.run([sys.executable,'-I','-S','-B','-W','error','-c',DAEMON_PROBE_SOURCE,json.dumps(command)],
                                  capture_output=True,timeout=10,check=True)
            doc=self.control(Run(0,result.stdout,result.stderr,0,None))
            self.assertEqual(doc['status'],'fail')
            self.assertNotIn('excerpt',doc['stderr_diagnostic'])
            self.assertLess(len(result.stdout),8192)

    def test_real_harness_timeout_retains_wait_and_reaps_owned_child(self):
        command=[sys.executable,'-c','import time;time.sleep(30)']
        result=subprocess.run([sys.executable,'-I','-S','-B','-W','error','-c',DAEMON_PROBE_SOURCE,json.dumps(command)],
                              capture_output=True,timeout=10,check=True)
        doc=self.control(Run(0,result.stdout,result.stderr,0,None))
        self.assertTrue(doc['timed_out'])
        self.assertTrue(doc['reaped'])
        self.assertEqual(doc['status'],'fail')
        self.assertEqual(doc['stderr_diagnostic']['cause_token'],'timeout')

    def test_fixed_sources_compile_without_execution(self):
        for source in (DAEMON_PROBE_SOURCE,SOCKET_PROBE_SOURCE,SESSION_PROBE_SOURCE):
            compile(source,'<fixed-guest-control>','exec')
