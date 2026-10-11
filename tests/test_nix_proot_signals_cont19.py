"""Synthetic per-layer status receipts cannot qualify the original wrapper."""
import json
import re
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from rs9.nix_proot import Run
from rs9.nix_proot_signals import probe_signals


class SignalAttribution(unittest.TestCase):
    def runtime(self, native_status):
        calls=[]
        def run(probe, command, **kwargs):
            code=command[5]
            if 'json.dumps(sys.argv[1:])' in code:
                return Run(0,json.dumps(command[6:]).encode(),b'',.1,None)
            match=re.search(r'sys.exit\((\d+)\)',code)
            return Run(int(match[1]) if match else 255 if 'SIGTERM' in code else 0,b'',b'',.1,None)
        def runner(command, **kwargs):
            calls.append(command)
            return subprocess.CompletedProcess(command,native_status,b'',b'')
        return SimpleNamespace(facts={'python':'/pinned/python'},prefix=['offline-prefix','--'],
            host_env=lambda:{},run=run,runner=runner),calls

    def test_native_prefix_status_and_invalid_frame_never_repair_wrapper(self):
        for native in (-15,255):
            rt,calls=self.runtime(native)
            invalid={'status':'contradictory','compatible_status':False,'signal_status_collapsed':True,
                     'record':{'kind':'signaled','signal':15}}
            with patch('rs9.nix_proot_signals.platform.system',return_value='Linux'), \
                 patch('rs9.nix_proot_signals.diagnostic_guest_run',return_value=(Run(255,b'',b'',.1,None),invalid)):
                result=probe_signals(rt,lambda *a:{'status':'pass','details':{}},lambda n:0)
            self.assertEqual(result['status'],'fail')
            self.assertEqual(result['reason'],'guest-signal-status-not-propagated')
            self.assertEqual(calls[0][:2],rt.prefix)
            self.assertEqual(result['details']['native_prefix_sigterm']['raw_returncode'],native)
            self.assertFalse(result['details']['status_mapping_enabled'])
            wait=next(r for r in result['details']['stages'] if r['stage']=='wait-signal-death')
            self.assertNotIn('signal_status_token',wait['details'])
            self.assertEqual(wait['details']['raw_returncode'],255)
