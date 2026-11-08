"""Bind publisher intake to the actual frozen RS9 workflow, not product aliases."""
from __future__ import annotations

import hashlib
from pathlib import Path
import re
import tempfile
import unittest

from rs9 import nebular080_universal_publication as publication
from rs9 import nebular080_universal_profile as product
from rs9 import nebular080_universal_workflow as workflow
from rs9.errors import ContractError
from rs9.scratch import canonical


ROOT = Path(__file__).resolve().parents[1]
RS9_REPOSITORY = 'Knowledge-Forge-AI/release-starport-9'
AUTHORITY_PATH = Path('operators/tf-pypi/nebular-fusion-0.8.0-universal-publication.json')


def authority_fixture():
    """Structurally valid fixture only; not hosted/native qualification evidence."""
    record = {'size': 1, 'sha256': 'a' * 64}
    wheel = {'filename': publication.builder.FILENAME, 'tag': 'py3-none-any',
             'version': '0.8.0', **record}
    artifacts = {}
    for index, name in enumerate(publication.ARTIFACTS, 1):
        members = publication._expected_members(name) or {'qualification-inputs-prep.json'}
        artifacts[name] = {'id': index, 'size_in_bytes': 1, 'archive_sha256': 'b' * 64,
                           'files': {member: dict(record) for member in members}}
    value = {'schema': 'rs9.nebular080-universal-publication.v1',
             'project': 'theme-forge-nebular-fusion', 'version': '0.8.0',
             'distribution': publication.consumer.DISTRIBUTION,
             'workflow': 'rs9-tfnf-pypi-publish.yml', 'environment': 'pypi',
             'repository': RS9_REPOSITORY, 'source': {'commit': '1' * 40, 'tree': '2' * 40},
             'run': {'id': '123', 'attempt': '1'}, 'wheel': wheel,
             'runtime_inputs_sha256': 'a' * 64, 'runtime_index_sha256': 'a' * 64,
             'description_sha256': 'a' * 64, 'matrix_sha256': 'a' * 64,
             'api': {name: dict(record) for name in publication.API_FILES}, 'artifacts': artifacts}
    value['identity'] = hashlib.sha256(canonical(value)).hexdigest()
    return value


class PublicationWorkflowCoordinatesTests(unittest.TestCase):
    def test_authority_is_loaded_from_the_workflow_declared_file(self):
        text = (ROOT / '.github/workflows/rs9-tfnf-pypi-publish.yml').read_text()
        self.assertIn('publisher-authority/' + AUTHORITY_PATH.as_posix(), text)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            target = root / AUTHORITY_PATH
            target.parent.mkdir(parents=True)
            target.write_bytes(canonical(authority_fixture()))
            self.assertEqual(publication.load_authority(root)['repository'], RS9_REPOSITORY)

    def test_rs9_hosted_context_is_accepted_and_product_context_is_rejected(self):
        value = authority_fixture()
        environ = {'GITHUB_ACTIONS': 'true', 'GITHUB_REPOSITORY': RS9_REPOSITORY,
                   'GITHUB_REF': 'refs/heads/main', 'GITHUB_EVENT_NAME': 'workflow_dispatch',
                   'GITHUB_WORKFLOW_REF': RS9_REPOSITORY + '/.github/workflows/rs9-tfnf-pypi-publish.yml@refs/heads/main',
                   'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_SHA': '3' * 40, 'GITHUB_RUN_ID': '124'}
        self.assertEqual(publication._hosted(environ, '3' * 40, value), '124')
        self.assertEqual(product.REPOSITORY, 'Knowledge-Forge-AI/theme-forge-nebular-fusion')
        environ.update(GITHUB_REPOSITORY=product.REPOSITORY,
                       GITHUB_WORKFLOW_REF=product.REPOSITORY + '/.github/workflows/rs9-tfnf-pypi-publish.yml@refs/heads/main')
        with self.assertRaises(ContractError):
            publication._hosted(environ, '3' * 40, value)

    def test_qualification_run_is_bound_to_rs9(self):
        value = authority_fixture()
        run = {'id': 123, 'run_attempt': 1, 'status': 'completed', 'conclusion': 'success',
               'event': 'workflow_dispatch', 'head_branch': 'main', 'head_sha': '1' * 40,
               'path': '.github/workflows/rs9-tfnf-pypi-publish.yml',
               'repository': {'full_name': RS9_REPOSITORY}, 'head_repository': {'full_name': RS9_REPOSITORY},
               'head_commit': {'id': '1' * 40, 'tree_id': '2' * 40}}
        publication._check_run(run, value)
        run['repository'] = {'full_name': product.REPOSITORY}
        with self.assertRaises(ContractError):
            publication._check_run(run, value)

    def test_required_artifacts_match_actual_qualification_uploads(self):
        text = (ROOT / '.github/workflows/rs9-tfnf-pypi-publish.yml').read_text()
        starts = list(re.finditer(r'^  ([A-Za-z0-9_]+):\n', text, re.M))
        uploads = set()
        for index, match in enumerate(starts):
            if match[1] not in workflow.QUALIFICATION_JOB_IDS:
                continue
            section = text[match.start():starts[index + 1].start() if index + 1 < len(starts) else len(text)]
            names = re.findall(r'uses: actions/upload-artifact@[^\n]+\n(?:(?!      -)[\s\S])*?\n          name: ([^\n]+)', section)
            uploads.update(name for name in names if not name.endswith('-failure-diagnostic'))
        self.assertEqual(len(uploads), 8)
        self.assertEqual(set(publication.ARTIFACTS), uploads)

    def test_authority_schema_accepts_only_the_workflow_repository(self):
        value = authority_fixture()
        self.assertEqual(publication.validate_authority(value)['repository'], RS9_REPOSITORY)
        value['repository'] = product.REPOSITORY
        value.pop('identity')
        value['identity'] = hashlib.sha256(canonical(value)).hexdigest()
        with self.assertRaises(ContractError):
            publication.validate_authority(value)


if __name__ == '__main__':
    unittest.main()
