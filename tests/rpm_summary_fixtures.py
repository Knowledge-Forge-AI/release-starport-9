"""Explicit custody fixtures for summary tests; no native tool qualification."""
from pathlib import Path

from rs9.build_native import CommandReceipt
from rs9.release_core import digest
from rs9.rpm_lint import build_rpmlint_evidence
from rs9.rpm_lint_policy import load_policy
from rs9.rpm_evidence import durable_lint_projection, write_policy_evidence
from rs9.scratch import canonical


def witnessed_build_double(builder):
    """Add an explicitly simulated successful rpmbuild/query to legacy tool doubles."""
    from rs9.errors import ContractError
    def invoke(capture, intent, arch, work, **kwargs):
        pid=intent['project']['id']
        def attach(target, package):
            specs=list(Path(work).rglob('*.spec'))
            if not package or not Path(package).is_file() or not specs:
                return
            package=Path(package)
            witness=dict(schema='rs9.rpm-construction-witness.v1',package_sha256=digest(package.read_bytes()),
                package_size=package.stat().st_size,spec_sha256=digest(specs[0].read_bytes()),
                rpm_identity=dict(name=pid,version='1.0.0',release='1',arch=arch),
                rpm_payload_digest=dict(payload_digest_algo='sha256',payload_digest=digest(b'fixture-payload')),
                rpmbuild_receipt=dict(executed=True,exit_code=0,tool='rpmbuild',command_sha256=digest(canonical(['rpmbuild','fixture.spec'])),stdout_sha256=digest(b''),stderr_sha256=digest(b'')))
            if isinstance(target,dict):target['construction_witness']=witness
            else:target.construction_witness=witness;target.package_path=str(package)
        try:
            result=builder(capture,intent,arch,work,**kwargs)
        except ContractError as err:
            if not hasattr(err,'construction_witness') and err.code=='RPMLINT_FAILED':
                packages=list(Path(work).rglob('*.rpm'))
                attach(err,getattr(err,'package_path',None) or (packages[0] if packages else None))
            raise
        attach(result,result.get('rpm_path'))
        return result
    return invoke


def add_rpm_annex(scratch, receipt, files):
    raw_results, policies = {}, {}
    for package in list(files):
        product = next(p for p in load_policy()['projects'] if package.name.startswith(p+'-'))
        arch = 'noarch' if '.noarch.rpm' in package.name else receipt['system'].removesuffix('-linux')
        spec = scratch / (product+'.spec'); spec.write_bytes(b'fixture-spec')
        stdout=b'1 packages and 1 specfiles checked; 0 errors, 0 warnings, 8 filtered.\n'
        tool=CommandReceipt(['rpmlint',spec.name,package.name],0,stdout,b'',executed=True)
        raw=build_rpmlint_evidence(tool,spec,package,product,rpm_identity=dict(name=product,version='0.6.1',release='1',arch=arch))
        raw_path=scratch/'diagnostics'/('rpmlint-'+product+'.json');raw_path.parent.mkdir(exist_ok=True);raw_path.write_bytes(canonical(raw))
        evaluation=dict(schema='rs9.rpm-lint-policy-evaluation.v1',accepted=True,status='accepted-no-exceptions',blockers=[],
            inputs=dict(project_id=product,version='0.6.1',arch=arch,system=receipt['system']),raw_lint_status=raw['status'],raw_exit_code=0,
            policy_sha256=digest(canonical(load_policy())),accepted_findings=[])
        summary, chunks=write_policy_evidence(scratch,evaluation)
        derivation=dict(project=product,adapter='rpm',artifact=dict(sha256=raw['package_sha256']),evidence=dict(rpmlint=durable_lint_projection(raw)))
        manifest=dict(schema='rs9.rpm-candidate.v1alpha2',project=product,architecture=arch,package_file='unsigned/'+package.name,
            package_sha256=raw['package_sha256'],package_size=package.stat().st_size,rpmlint=raw,derivation=derivation)
        mp=scratch/'build'/product/'rpm-manifest.json';mp.parent.mkdir(parents=True);mp.write_bytes(canonical(manifest))
        files.extend([raw_path,mp,*chunks]);raw_results[product]=raw;policies[product]=summary
    receipt['details']=dict(rpm_evidence_contract='rs9.rpm-evidence-contract.v2',rpm_lint_raw=raw_results,rpm_lint_policy=policies)
