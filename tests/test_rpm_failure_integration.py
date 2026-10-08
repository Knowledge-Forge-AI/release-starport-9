"""Actual hosted handler plus lint backend with real receipts; fixture execution only."""
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from rs9 import hosted_packaging as hosted
from rs9.build_native import CommandReceipt
from rs9.errors import ContractError
from rs9.release_core import digest
from rs9.rpm_lint import execute_rpmlint

PRODUCTS = ("theme-forge-stellar-burst", "theme-forge-stellar-loom",
            "theme-forge-solar-sail", "theme-forge-nebular-fusion")
CLEAN = b"1 packages and 1 specfiles checked; 0 errors, 0 warnings.\n"
ERROR = b"fixture.x86_64: E: fixture-check fixture-message\n1 packages and 1 specfiles checked; 1 errors, 0 warnings.\n"


class RpmFailureIntegrationTests(unittest.TestCase):
    def run_lane(self, root, outcomes, *, version="success", missing=(), secondary_fail=False, injected_errors=None):
        scratch = root/"lane-work"
        scratch.mkdir()
        context = {"family":"rpm", "system":"x86_64-linux", "repository":root,
                   "scratch":scratch,"pins":{},"client":None,
                   "captures":[(SimpleNamespace(),{"project":{"id":p}}, {}) for p in PRODUCTS],
                   "binding":{"source_commit":"0"*40},"authentication_sha256":"1"*64}
        environment = {"platform":"linux/amd64","image_ref":"fixture@sha256:"+"a"*64,
                       "preprovisioned_packages":[],"tools":{}}
        current = {}
        receipts = []
        def backend(self, command, **kwargs):
            if "--version" in command:
                if version == "throws":raise OSError("fixture-probe-error")
                if version == "removes-inputs":
                    for p in (current["spec"],current["rpm"]):
                        if p.exists():p.unlink()
                    raise OSError("fixture-probe-error")
                r=CommandReceipt(command, 1 if version=="fails" else 0,b"rpmlint 2.6\n",b"",executed=True)
            elif command[0]=="rpm":
                r=CommandReceipt(command,1,b"",b"fixture-rpm-query",executed=True)
            else:
                code, out=current["outcome"]
                r=CommandReceipt(command,code,out,b"fixture-causal-stderr",executed=True)
                receipts.append(r)
            return r
        def build(capture,intent,arch,work,*,runner,**kwargs):
            pid=intent["project"]["id"]
            if injected_errors and pid in injected_errors:
                raise injected_errors[pid]
            if outcomes[pid] == "build-failure":raise ContractError("BUILD_FAILED","fixture-construction-failure")
            rpm=work/(pid+".rpm");spec=work/(pid+".spec")
            if "rpm" not in missing:rpm.write_bytes(b"fixture-rpm")
            if "spec" not in missing:spec.write_bytes(b"Name: fixture\n")
            current.update(rpm=rpm,spec=spec,outcome=outcomes[pid])
            execute_rpmlint(runner,spec,rpm,pid,cwd=work)
            (work/"rpm-manifest.json").write_text('{}')
            return {"rpm_path":rpm,"manifest":{"rpm_identity":{"name":pid},"rpm_payload_digest":{}}}
        original_copy=hosted.shutil.copyfile
        def copy(source,target,*args,**kwargs):
            if secondary_fail and Path(target).parent.name=="quarantine":raise OSError("fixture-copy-error")
            return original_copy(source,target,*args,**kwargs)
        with patch.object(hosted,"provision",return_value=environment), \
             patch("rs9.hosted_deb.provision_image"),patch.object(hosted,"checked"), \
             patch.object(hosted,"container_tool_facts",return_value={}), \
             patch.object(hosted,"_resolve_offline_npm_archives",return_value=None), \
             patch.object(hosted,"build_rpm_candidate",side_effect=build), \
             patch("rs9.hosted_deb.ContainerRunner.run",backend), \
             patch.object(hosted.shutil,"copyfile",side_effect=copy):
            result=hosted.execute(context)
        return result, scratch, receipts

    def test_actual_inventory_failure_custody_keeps_lint_and_causal_receipt(self):
        from tests.test_build_rpm import BuildRpmTests
        from tests.test_build_native import create_cli_fixture
        from rs9.build_rpm import build_rpm_candidate
        from rs9.hosted_custody import diagnostic_bytes
        from rs9.security import scan_for_credentials
        import json
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            capture, intent, npm = create_cli_fixture(root / 'input',
                extra_asset_entries=[(f'data/member-{i:04d}.txt', f'row-{i}'.encode()) for i in range(1200)])
            work = root / 'builder'; work.mkdir()
            runner = BuildRpmTests()._setup_runner()
            original = runner.handlers['rpm']
            queried = []
            def query(argv, **kwargs):
                receipt = original(argv, **kwargs)
                if '--dump' in argv:
                    self.assertGreater(len(receipt.stdout_bytes), 65536)
                    receipt = CommandReceipt(argv, 0, receipt.stdout_bytes + b'bad final record\n', b'')
                    queried.append(receipt)
                return receipt
            runner.handlers['rpm'] = query
            pid = intent['project']['id']
            lint_bytes = (pid + '.noarch: E: env-script-interpreter /usr/lib/' + pid +
                '/bin/run.js /usr/bin/env node\n1 packages and 1 specfiles checked; 1 errors, 0 warnings, 0 filtered.\n').encode()
            runner.handlers['rpmlint'] = lambda argv, **kw: CommandReceipt(argv,
                0 if '--version' in argv else 64, b'2.8.0\n' if '--version' in argv else lint_bytes, b'')
            with self.assertRaises(ContractError) as caught:
                build_rpm_candidate(capture, intent, 'noarch', work, offline_npm_archives=npm, runner=runner)
            error = caught.exception
            result, scratch, _ = self.run_lane(root, {p:(1, ERROR) for p in PRODUCTS}, injected_errors={pid:error})
            failure = result['details']['product_failures'][pid]
            self.assertEqual(failure['code'], 'RPM_INVENTORY_FAILED')
            self.assertEqual(failure['tool'], 'rpm')
            self.assertEqual(failure['exit_code'], 0)
            self.assertEqual(failure['stdout_sha256'], queried[0].stdout_sha256)
            inventory = scratch / 'diagnostics' / f'rpm-inventory-{pid}.json'
            lint = scratch / 'diagnostics' / f'rpmlint-{pid}.json'
            policy = scratch / 'diagnostics' / f'rpm-lint-policy-{pid}.json'
            for path in (inventory, lint, policy):
                self.assertIn(path, result['artifacts'])
                scan_for_credentials(diagnostic_bytes(path).decode())
            inventory_bytes = inventory.read_bytes()
            self.assertLessEqual(len(inventory_bytes), 16 * 1024)
            self.assertNotIn(b'/usr/', inventory_bytes)
            self.assertNotIn(str(root).encode(), inventory_bytes)
            self.assertEqual(json.loads(lint.read_bytes())['tool_receipt']['stdout_sha256'], digest(lint_bytes))
            self.assertEqual(json.loads(policy.read_bytes())['raw_exit_code'], 64)
            # A projection failure has no query cause; preceding failed lint must not be blamed.
            error.receipt = None
            for key in ('tool', 'exit_code', 'stdout_sha256', 'stderr_sha256'):
                error.details.pop(key, None)
            other = root / 'projection'; other.mkdir()
            projection, _, _ = self.run_lane(other, {p:(1, ERROR) for p in PRODUCTS}, injected_errors={pid:error})
            no_query = projection['details']['product_failures'][pid]
            self.assertNotIn('tool', no_query)
            self.assertNotIn('stdout_sha256', no_query)

    def test_real_lint_failure_matrix_preserves_cause_and_quarantine(self):
        cases=[(0,CLEAN),(0,ERROR),(1,ERROR),(64,CLEAN),(1,b"malformed\n"),
               (1,b"fixture.x86_64: E: fixture-check text\n1 packages and 1 specfiles checked; 2 errors, 0 warnings.\n")]
        for version in ("success","fails","throws"):
            for outcome in cases:
                with self.subTest(version=version,outcome=outcome),tempfile.TemporaryDirectory() as tmp:
                    outcomes={p:outcome for p in PRODUCTS}
                    outcomes[PRODUCTS[0]]=(1,ERROR) # Lane stays diagnostic while other real parses vary.
                    result,scratch,receipts=self.run_lane(Path(tmp).resolve(),outcomes,version=version)
                    self.assertEqual(len(receipts),4)
                    self.assertTrue(all(not hasattr(r,"argv") for r in receipts))
                    failures=result["details"]["product_failures"]
                    for pid in failures:
                        self.assertEqual(failures[pid]["code"],"RPMLINT_FAILED")
                        evidence=result["details"]["lint_evidence"][pid]
                        r=receipts[PRODUCTS.index(pid)]
                        self.assertEqual(evidence["tool_receipt"]["exit_code"],r.exit_code)
                        self.assertEqual(evidence["tool_receipt"]["stdout_sha256"],r.stdout_sha256)
                        self.assertEqual(evidence["tool_receipt"]["stderr_sha256"],r.stderr_sha256)
                        self.assertEqual(evidence["package_sha256"],digest(b"fixture-rpm"))
                        self.assertEqual(evidence["spec_sha256"],digest(b"Name: fixture\n"))
                        self.assertEqual(failures[pid]["quarantine_sha256"],digest(b"fixture-rpm"))
                        self.assertNotIn(scratch/"quarantine"/(pid+".rpm"),result["artifacts"])
                    gates={r["name"]:r["status"] for r in result["gates"]}
                    self.assertEqual(gates["rpm-package-build"],"pass")
                    self.assertEqual(gates["rpm-lint-policy-accepted"],"fail")
                    self.assertFalse((scratch/"unsigned-custody").exists())

    def test_missing_context_and_secondary_failures_do_not_replace_lint(self):
        for missing in ((),("rpm",),("spec",),("rpm","spec")):
            for version in ("success","removes-inputs"):
                with self.subTest(missing=missing,version=version),tempfile.TemporaryDirectory() as tmp:
                    result,_,_=self.run_lane(Path(tmp).resolve(),{p:(1,ERROR) for p in PRODUCTS},
                                            missing=missing,version=version,secondary_fail=True)
                    for pid,failure in result["details"]["product_failures"].items():
                        self.assertEqual(failure["code"],"RPMLINT_FAILED")
                        ev=result["details"]["lint_evidence"][pid]
                        self.assertEqual(ev["findings_summary"]["errors"],1)
                        self.assertEqual(ev["parse_complete"],True)
                        self.assertEqual(ev["identity_status"]["package"],"unavailable" if "rpm" in missing else "available")
                        self.assertIn(failure["diagnostics"]["quarantine"],("failed","unavailable"))
                    gates={row["name"]:row for row in result["gates"]}
                    self.assertEqual(gates["rpm-package-build"]["status"],
                                     "fail" if "rpm" in missing else "pass")
                    self.assertEqual(gates["rpm-repository-indexing"]["reason"],
                                     "blocked-by:rpm-package-build" if "rpm" in missing
                                     else "blocked-by:rpm-lint-policy-accepted")

    def test_mixed_construction_and_lint_failures_retain_all_products(self):
        with tempfile.TemporaryDirectory() as tmp:
            outcomes={PRODUCTS[0]:"build-failure",PRODUCTS[1]:(1,ERROR),
                      PRODUCTS[2]:(64,CLEAN),PRODUCTS[3]:(1,b"malformed\n")}
            result,scratch,receipts=self.run_lane(Path(tmp).resolve(),outcomes)
            self.assertEqual(set(result["details"]["product_failures"]),set(PRODUCTS))
            self.assertEqual(len(receipts),3)
            self.assertEqual(result["details"]["product_failures"][PRODUCTS[0]]["code"],"BUILD_FAILED")
            gates={g["name"]:g for g in result["gates"]}
            self.assertEqual(gates["rpm-package-build"]["status"],"fail")
            self.assertEqual(gates["rpm-repository-indexing"]["status"],"not-run")
            self.assertFalse((scratch/"unsigned-custody").exists())
