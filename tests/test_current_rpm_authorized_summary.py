"""Current authorized summary/custody regressions, never native qualification.
Synthetic RPM headers and hosted gates are test doubles. Raw findings/evaluations
are disclosed retained observations. They cannot mint live caller capabilities.
Only Git/source observations, GitHub transport and outbox location are controlled;
selected policy, custody, source binding, summary and facade checks are real.
"""
from pathlib import Path
import base64, gzip, unittest
import copy, hashlib, io, json, os, shutil, zipfile
from functools import lru_cache
from unittest.mock import patch
ROOT = Path(__file__).resolve().parents[1]
from tests import test_hosted_summary as summary_fixtures
from tests import test_original_run_context as original_context
from tests.test_original_run_context import COMMIT, TREE, STARTED, PACKAGES
from rs9.current_generation import CURRENT_GENERATION, DISTRIBUTION_JOBS
from rs9.hosted_summary import required, summarize, validate_rpm_policy_custody, RPM_POLICY_PROMOTION_BLOCKER, validate_rpm_policy_source
from rs9.hosted_custody import retain, provenance
from rs9.rpm_evidence import write_policy_evidence, durable_lint_projection
from rs9.rpm_lint_policy import load_policy
from rs9.qualified_distribution_inputs import qualified_distribution_inputs, SourceBoundConfiguration
from rs9.collect_candidate import collect
from rs9.errors import ContractError
from rs9.scratch import canonical
from tests.test_current_rpm_preservation_policy import actual_case
from tests.test_hosted_summary_roles import _make_synthetic_rpm

@lru_cache(maxsize=1)
def _evaluations():
    envelope = json.loads((ROOT / 'tests/fixtures/current-rpm-authorized-evaluations.json').read_bytes())
    with gzip.GzipFile(fileobj=io.BytesIO(base64.b64decode(envelope['data'], validate=True))) as stream:
        data = stream.read(4 * 1024 ** 2 + 1)
    if not (len(data) == envelope['decoded_bytes'] and len(data) <= 4 * 1024 ** 2):
        raise AssertionError('Regression predicate failed')
    if not hashlib.sha256(data).hexdigest() == envelope['data_sha256']:
        raise AssertionError('Regression predicate failed')
    return json.loads(data)

def probe(case):
    context = original_context.OriginalRunContextTests()
    fixture = summary_fixtures.HostedSummaryTests()
    try:
        context.setUp()
        fixture.setUp()
        lanes = required(ROOT, generation=CURRENT_GENERATION)
        names = {x['artifact_name'] for x in lanes}
        for directory in fixture.inputs.iterdir():
            if directory.name not in names:
                shutil.rmtree(directory)
        jobs = {job: {'result': 'success'} for job in DISTRIBUTION_JOBS if job != 'summary'}
        with patch.dict(os.environ, {'RS9_JOB_CONCLUSIONS': json.dumps(jobs)}):
            selected = provenance(ROOT, 'a' * 64, generation=CURRENT_GENERATION)
            for lane in lanes:
                directory = fixture.inputs / lane['artifact_name']
                name = lane['lane'] + '-' + lane['system'] + '.json'
                receipt = json.loads((directory / name).read_bytes())
                receipt['provenance'] = selected
                if lane['lane'] == 'nix':
                    receipt['details'] = {'outputs': {p: {} for p in load_policy(generation=CURRENT_GENERATION)['projects']}}
                if lane['lane'] == 'rpm':
                    scratch = fixture.root / ('actual-' + lane['system'])
                    scratch.mkdir()
                    files = []
                    policies = {}
                    raws = {}
                    for product in load_policy(generation=CURRENT_GENERATION)['projects']:
                        raw = copy.deepcopy(actual_case(product, lane['system'])['raw'])
                        evaluation = copy.deepcopy(_evaluations()[product + '-' + lane['system']])
                        if not (evaluation['accepted'] and evaluation['accepted_findings']):
                            raise AssertionError('Regression predicate failed')
                        package = scratch / 'unsigned' / raw['package_file']
                        package.parent.mkdir(exist_ok=True)
                        package.write_bytes(_make_synthetic_rpm(product, arch=raw['architecture'], version=evaluation['inputs']['version']))
                        raw['package_sha256'] = hashlib.sha256(package.read_bytes()).hexdigest()
                        files.append(package)
                        rawpath = scratch / 'diagnostics' / ('rpmlint-' + product + '.json')
                        rawpath.parent.mkdir(exist_ok=True)
                        rawpath.write_bytes(canonical(raw))
                        files.append(rawpath)
                        summary, chunks = write_policy_evidence(scratch, evaluation)
                        files.extend(chunks)
                        policies[product] = summary
                        raws[product] = raw
                        derivation = dict(project=product, adapter='rpm', artifact=dict(sha256=raw['package_sha256']), evidence=dict(rpmlint=durable_lint_projection(raw)))
                        manifest = dict(schema='rs9.rpm-candidate.v1alpha2', project=product, architecture=raw['architecture'], package_file='unsigned/' + package.name, package_sha256=raw['package_sha256'], package_size=package.stat().st_size, rpmlint=raw, derivation=derivation)
                        mp = scratch / 'build' / product / 'rpm-manifest.json'
                        mp.parent.mkdir(parents=True)
                        mp.write_bytes(canonical(manifest))
                        files.append(mp)
                    receipt['details'] = dict(rpm_evidence_contract='rs9.rpm-evidence-contract.v2', rpm_lint_raw=raws, rpm_lint_policy=policies)
                    receipt['production_promotion_blockers'] = [RPM_POLICY_PROMOTION_BLOCKER]
                    shutil.rmtree(directory)
                    retain(scratch, directory, files, receipt)
                    manifest = json.loads((directory / 'artifact-manifest.json').read_bytes())
                    validate_rpm_policy_source(ROOT, receipt, generation=CURRENT_GENERATION)
                    validate_rpm_policy_custody(directory, manifest, receipt)
                    if case == 'omitted':
                        receipt['details'].pop('rpm_lint_policy')
                    elif case == 'empty':
                        receipt['details']['rpm_lint_policy'] = {}
                    elif case in {'empty-policy-and-raw', 'empty-maps-missing-required-gate'}:
                        receipt['details'].update(rpm_lint_policy={}, rpm_lint_raw={})
                        if case == 'empty-maps-missing-required-gate':
                            receipt['gates'] = [gate for gate in receipt['gates'] if gate['name'] != 'rpm-lint-policy-accepted']
                    elif case == 'all-findings-stripped':
                        for policy_summary in receipt['details']['rpm_lint_policy'].values():
                            policy_summary['accepted_findings'] = []
                    elif case == 'stripped-findings':
                        next(iter(receipt['details']['rpm_lint_policy'].values()))['accepted_findings'] = []
                    if case in {'omitted', 'empty', 'empty-policy-and-raw', 'empty-maps-missing-required-gate', 'stripped-findings', 'all-findings-stripped', 'stripped-token'}:
                        receipt['production_promotion_blockers'] = []
                raw = canonical(receipt)
                (directory / name).write_bytes(raw)
                mp = directory / 'artifact-manifest.json'
                manifest = json.loads(mp.read_bytes())
                manifest.update(selected)
                manifest['qualification_receipt_hashes'] = {name: hashlib.sha256(raw).hexdigest()}
                mp.write_bytes(canonical(manifest))
            code = summarize(ROOT, fixture.inputs, fixture.output, generation=CURRENT_GENERATION)
            summary = json.loads((fixture.output / 'hosted-summary.json').read_bytes())
            if case == 'intact':
                if not (code == 0 and summary['production_promotion_blockers'] == [RPM_POLICY_PROMOTION_BLOCKER]):
                    raise AssertionError(summary['blocking_reasons'])
            elif case in {'omitted', 'empty', 'empty-policy-and-raw'}:
                if not (code == 2 and any(('RPM_POLICY_CUSTODY' in x for x in summary['blocking_reasons']))):
                    raise AssertionError(summary['blocking_reasons'])
            elif case == 'empty-maps-missing-required-gate':
                if not code == 2:
                    raise AssertionError('Regression predicate failed')
            elif case in {'stripped-findings', 'all-findings-stripped'}:
                if not (code == 2 and any(('RPM_POLICY_CUSTODY' in x for x in summary['blocking_reasons']))):
                    raise AssertionError(summary['blocking_reasons'])
            elif not (code == 2 and any(('HOSTED_POLICY' in x for x in summary['blocking_reasons']))):
                raise AssertionError(summary['blocking_reasons'])
            reason_codes = {'intact': [], 'omitted': ['RPM_POLICY_CUSTODY'], 'empty': ['RPM_POLICY_CUSTODY'], 'empty-policy-and-raw': ['RPM_POLICY_CUSTODY'], 'all-findings-stripped': ['RPM_POLICY_CUSTODY'], 'stripped-findings': ['HOSTED_POLICY', 'RPM_POLICY_CUSTODY'], 'stripped-token': ['HOSTED_POLICY'], 'empty-maps-missing-required-gate': ['missing-or-duplicate-gate:rpm-lint-policy-accepted']}[case]
            expected_reasons = sorted(('candidate-rpm-' + system + ':' + reason for system in ('aarch64-linux', 'x86_64-linux') for reason in reason_codes))
            if not sorted(summary['blocking_reasons']) == expected_reasons:
                raise AssertionError(summary['blocking_reasons'])
            context.artifacts = []
            context.zips = {}
            for identity, (name, directory) in enumerate([(x['artifact_name'], fixture.inputs / x['artifact_name']) for x in lanes] + [('hosted-summary', fixture.output)], 10):
                buf = io.BytesIO()
                with zipfile.ZipFile(buf, 'w') as z:
                    for path in sorted(directory.rglob('*')):
                        if path.is_file():
                            z.writestr(path.relative_to(directory).as_posix(), path.read_bytes())
                body = buf.getvalue()
                context.zips[identity] = body
                context.artifacts.append(dict(id=identity, name=name, digest='sha256:' + hashlib.sha256(body).hexdigest(), expired=False, size_in_bytes=len(body)))
            context.jobs = [dict(id=i, name=name, status='completed', conclusion='success', steps=[dict(name='fixture', conclusion='success')]) for i, name in enumerate(sorted({x['lane'] + '-' + x['system'] if x['lane'] in {'nix', 'rpm', 'deb', 'pacman'} else x['lane'] for x in lanes} | {'config', 'unit', 'summary'}), 1)]
            config = SourceBoundConfiguration(ROOT, COMMIT, TREE, 7, STARTED, *[selected[k] for k in ('workflow_sha256', 'contract_sha256', 'builder_source_sha256', 'configuration_sha256', 'release_ingestion_sha256')])
            output = fixture.root / 'facade'
            output.mkdir()

            def controlled_collect(*args, **kwargs):
                return collect(*args, runner=context.api, **kwargs)
            with patch.dict(os.environ, PACKAGES), patch('rs9.collect_candidate.output_directory', return_value=output), patch('rs9.collect_candidate.gh_read', side_effect=lambda root, argv, runner=None: context.api(root, ['gh', *argv])), patch('rs9.qualified_distribution_inputs.collect', side_effect=controlled_collect):
                try:
                    qualified_distribution_inputs(config, output, timeout=30)
                except ContractError as error:
                    facade_code = error.code
                else:
                    raise AssertionError('Strict facade must refuse')
            packet = json.loads((output / 'manager-packet.json').read_bytes())
            if case == 'intact':
                if not facade_code == 'DISTRIBUTION_PROMOTION_HELD':
                    raise AssertionError(facade_code)
            elif not facade_code == 'DISTRIBUTION_NOT_QUALIFIED':
                raise AssertionError(facade_code)
            return dict(case=case, summary_exit=code, blocking_reasons=summary['blocking_reasons'], tokens=summary['production_promotion_blockers'], facade_error=facade_code, packet_validation=packet['validation'], original_run_reads=context.run_reads, positive_physical_custody_controls=2)
    finally:
        fixture.doCleanups()
        context.doCleanups()

class AuthorizedCurrentSummaryTests(unittest.TestCase):

    def test_intact(self):
        probe('intact')

    def test_omitted(self):
        probe('omitted')

    def test_empty(self):
        probe('empty')

    def test_empty_policy_and_raw(self):
        probe('empty-policy-and-raw')

    def test_stripped_findings(self):
        probe('stripped-findings')

    def test_all_findings_stripped(self):
        probe('all-findings-stripped')

    def test_stripped_token(self):
        probe('stripped-token')

    def test_empty_maps_missing_required_gate(self):
        probe('empty-maps-missing-required-gate')
if __name__ == '__main__':
    unittest.main()
