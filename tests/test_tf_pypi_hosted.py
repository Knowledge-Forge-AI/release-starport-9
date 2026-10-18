"""Native qualification routing, same-artifact receipt and workflow safety regressions."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import yaml

from rs9.tf_pypi_archive import AdmissionError
from rs9 import tf_pypi_hosted as h
from rs9.tf_pypi_publish import workflow_text
from rs9.tf_pypi_model import PRODUCTS

COMMIT = 'a' * 40
PROJECT = 'theme-forge-stellar-loom'
APPROVED = {'set_sha256': 'b' * 64, 'files': [{'filename': 'example.whl'}]}
CONSUMER = {'project': PROJECT, 'system': 'aarch64-darwin', 'set_sha256': 'b' * 64,
            'functional': True, 'offline_isolation': {'network_disabled': True},
            'publication_admitted': False,
            'lifecycle': [{'kind': k, 'install_exit': 0, 'probes': [{'command': 'tfsl'}]}
                          for k in ('wheel', 'sdist')]}


class NativeContract(unittest.TestCase):
    def attempt(self, consumer=None, approvals=None):
        with patch.object(h.platform, 'system', return_value='Darwin'), \
                patch.object(h.platform, 'machine', return_value='arm64'), \
                patch.object(h, 'source_commit', return_value=COMMIT), \
                patch.object(h, 'verify_approved', side_effect=approvals or [APPROVED, APPROVED]), \
                patch.object(h, 'smoke', return_value=consumer or CONSUMER) as call:
            value = h.qualify(PROJECT, '/unused/dist', '/unused/work', COMMIT)
            call.assert_called_once()
            self.assertTrue(call.call_args.kwargs['functional'])
            return value

    def test_exact_native_receipt_does_not_admit_publication(self):
        result = self.attempt()
        self.assertEqual(result['status'], 'native-consumer-passed')
        self.assertEqual(result['commit'], COMMIT)
        self.assertFalse(result['publication_admitted'])
        self.assertEqual(result['artifacts'], APPROVED['files'])

    def test_wrong_host_stops_before_consumer(self):
        for system, machine in [('Linux', 'x86_64'), ('Darwin', 'x86_64')]:
            with self.subTest(system=system, machine=machine), \
                    patch.object(h.platform, 'system', return_value=system), \
                    patch.object(h.platform, 'machine', return_value=machine), \
                    patch.object(h, 'smoke') as call, self.assertRaises(AdmissionError):
                h.qualify(PROJECT, '/unused', '/unused', COMMIT)
            call.assert_not_called()

    def test_source_mismatch_stops_before_artifact_or_consumer(self):
        with patch.object(h.platform, 'system', return_value='Darwin'), \
                patch.object(h.platform, 'machine', return_value='arm64'), \
                patch.object(h, 'source_commit', side_effect=AdmissionError('TF_PYPI_HOSTED_COMMIT')), \
                patch.object(h, 'smoke') as call, self.assertRaises(AdmissionError):
            h.qualify(PROJECT, '/unused', '/unused', COMMIT)
        call.assert_not_called()

    def test_artifact_mutation_refused(self):
        with self.assertRaises(AdmissionError):
            self.attempt(approvals=[APPROVED, {**APPROVED, 'set_sha256': 'c'*64}])

    def test_wrong_product_system_or_digest_refused(self):
        for key,value in [('project', 'wrong'), ('system', 'x86_64-linux'), ('set_sha256', 'c'*64)]:
            with self.subTest(key=key), self.assertRaises(AdmissionError):
                self.attempt(consumer={**CONSUMER,key:value})

    def test_no_offline_proof_refused(self):
        with self.assertRaises(AdmissionError):
            self.attempt(consumer={**CONSUMER, 'offline_isolation': {}})

    def test_functional_disabled_refused(self):
        with self.assertRaises(AdmissionError):
            self.attempt(consumer={**CONSUMER, 'functional': False})

    def test_missing_sdist_or_failed_install_refused(self):
        for life in [[CONSUMER['lifecycle'][0]],
                     [{**x,'install_exit':1} for x in CONSUMER['lifecycle']]]:
            with self.subTest(life=life), self.assertRaises(AdmissionError):
                self.attempt(consumer={**CONSUMER,'lifecycle':life})

    def test_empty_probes_refused(self):
        life=[{**x,'probes':[]} for x in CONSUMER['lifecycle']]
        with self.assertRaises(AdmissionError):self.attempt(consumer={**CONSUMER,'lifecycle':life})

    def test_receipt_cannot_grant_publication(self):
        with self.assertRaises(AdmissionError):
            self.attempt(consumer={**CONSUMER,'publication_admitted':True})

    def test_failure_report_survives_and_has_no_local_error_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();out=root/'result.json'
            with patch.object(h,'qualify',side_effect=RuntimeError(str(root))):
                rc=h.main(['qualify','--project',PROJECT,'--dist','unused','--work','unused',
                           '--report',str(out),'--expected-commit',COMMIT])
            data=out.read_text();self.assertEqual(rc,1);self.assertNotIn(str(root),data)
            self.assertEqual(json.loads(data)['error_type'],'RuntimeError')

    def test_existing_report_is_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            out=Path(tmp).resolve()/'result.json';out.write_text('original')
            with self.assertRaises(FileExistsError):h.write_report(out,{'status':'wrong'})
            self.assertEqual(out.read_text(),'original')

    def test_report_symlink_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();(root/'original').write_text('original')
            (root/'link').symlink_to(root/'original')
            with self.assertRaises(AdmissionError):h.write_report(root/'link',{})
            self.assertEqual((root/'original').read_text(),'original')

    def test_source_sha_malformed_refused_without_git(self):
        with patch.object(h.subprocess,'run') as call,self.assertRaises(AdmissionError):
            h.source_commit('main')
        call.assert_not_called()


class HostedWorkflow(unittest.TestCase):
    def docs(self):return [(p,yaml.safe_load(workflow_text(p))) for p in sorted(PRODUCTS)]

    def test_three_branch_workflows_qualify_without_registry_or_oidc(self):
        for project,doc in self.docs():
            trigger=doc.get('on') or doc.get(True)
            self.assertEqual(trigger['push']['branches'],['rs9-tf-pypi-hostqual1'])
            jobs=doc['jobs'];self.assertNotIn('id-token',doc['permissions'])
            for name in ['build_verify','native_consumer']:
                self.assertNotIn('environment',jobs[name]);self.assertNotIn('id-token',jobs[name].get('permissions',{}))
            self.assertIn("github.event_name == 'workflow_dispatch'",jobs['publish']['if'])
            self.assertIn("github.ref == 'refs/heads/main'",jobs['publish']['if'])

    def test_native_job_uses_same_run_artifact_not_rebuild(self):
        for project,doc in self.docs():
            job=doc['jobs']['native_consumer']
            self.assertEqual(job['runs-on'],'macos-15');self.assertEqual(job['needs'],['build_verify'])
            downloads=[x for x in job['steps'] if x.get('uses','').startswith('actions/download-artifact@')]
            self.assertEqual(len(downloads),1);self.assertEqual(downloads[0]['with'],{'name':'pypi-artifacts','path':'dist/'})
            runs='\n'.join(x.get('run','') for x in job['steps'])
            self.assertIn('/usr/bin/sandbox-exec',runs);self.assertIn('(deny network*)',runs)
            self.assertIn('rs9.tf_pypi_hosted qualify',runs);self.assertNotIn('tf_pypi_publish build',runs)
            self.assertIn('--expected-commit',runs)
            self.assertEqual(doc['jobs']['publish']['needs'],['build_verify','native_consumer'])

    def test_failure_evidence_upload_is_unconditional(self):
        for project,doc in self.docs():
            uploads=[x for x in doc['jobs']['native_consumer']['steps'] if x.get('uses','').startswith('actions/upload-artifact@')]
            self.assertEqual(len(uploads),1);self.assertEqual(uploads[0]['if'],'always()')
            self.assertEqual(uploads[0]['with']['if-no-files-found'],'error')
            self.assertEqual(uploads[0]['with']['name'],'native-consumer-'+project)

    def test_no_unpinned_actions_or_cross_run_inputs(self):
        for project,doc in self.docs():
            for job in doc['jobs'].values():
                for step in job['steps']:
                    if 'uses' in step:
                        self.assertRegex(step['uses'],r'^[\w./-]+@[0-9a-f]{40}$')
                    if step.get('uses','').startswith('actions/download-artifact@'):
                        self.assertNotIn('run-id',step['with']);self.assertNotIn('github-token',step['with'])


if __name__=='__main__':unittest.main(verbosity=2)
