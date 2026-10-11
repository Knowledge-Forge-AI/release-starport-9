"""Integration regressions driving ACTUAL retain -> summarize with package roles.

Covers:
- source + correct binaries
- source only (must not satisfy presence)
- absent binary
- wrong architecture binary
- role/type disagreement
- unknown/malformed package
- changed/missing source evidence
- fixture-only copies
- both actual run-14 manifests from sanitized public fixture
- promotion restriction conservative accumulation even when lane checks fail
"""

import copy
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from rs9.errors import ContractError
from rs9.hosted_custody import provenance, retain, verify_set
from rs9.hosted_summary import (
    contract,
    required,
    summarize,
    validate_summary,
    validate_product_architectures,
    promotion_restrictions,
    LINUX_WHEEL_PROMOTION_BLOCKER,
    RPM_POLICY_PROMOTION_BLOCKER,
)
from rs9.package_roles import (
    BINARY_PACKAGE,
    SOURCE_PACKAGE_EVIDENCE,
    FIXTURE_SIGNED_COPY,
    UNCLASSIFIED_PACKAGE,
    producer_role,
    is_installable_binary,
    verify_package_roles,
)
from rs9.records import canonical, digest
from rs9.rpm_header import RPM_LEAD_MAGIC, RPM_HEADER_MAGIC

ROOT = Path(__file__).resolve().parents[1]
RUN14_FIXTURE_PATH = ROOT / "tests/fixtures/run14-rpm-manifests.json"


def _make_synthetic_rpm(
    name: str = "test-pkg",
    arch: str = "noarch",
    version: str = "0.6.1",
    release: str = "1.fc43",
    is_source: bool = False,
    sourcerpm: str | None = None,
    payload: bytes = b"fixture-rpm-payload",
) -> bytes:
    lead_type = 1 if is_source else 0
    lead = RPM_LEAD_MAGIC + struct.pack(">BBH", 3, 0, lead_type) + b"\0" * 88

    def _hdr(tags):
        store = bytearray()
        index = []
        for tid, (typ, val) in sorted(tags.items()):
            off = len(store)
            if typ == 6:
                s = val[0] if isinstance(val, list) else val
                store.extend(s.encode("utf-8") + b"\0")
                num = 1
            elif typ == 4:
                store.extend(struct.pack(">I", val)); num = 1
            index.append(struct.pack(">IIII", tid, typ, off, num))
        return RPM_HEADER_MAGIC + b"\0\0\0\0" + struct.pack(">II", len(index), len(store)) + b"".join(index) + bytes(store)

    sig_hdr = _hdr({1000: (6, "sig")})
    pad = b"\0" * (((len(sig_hdr) + 7) & ~7) - len(sig_hdr))
    main_tags = {
        1000: (6, name),
        1001: (6, version),
        1002: (6, release),
        1022: (6, "noarch" if is_source else arch),
    }
    if is_source:
        main_tags[1106] = (4, 1)
    if sourcerpm and not is_source:
        main_tags[1044] = (6, sourcerpm)
    main_hdr = _hdr(main_tags)
    return lead + sig_hdr + pad + main_hdr + payload


class HostedSummaryRolesIntegrationTests(unittest.TestCase):
    def test_malformed_policy_and_restrictions_preserve_union_and_validate(self):
        self._populate_standard_lanes()
        directory = self.inputs / "candidate-rpm-x86_64-linux"
        receipt_path = directory / "rpm-x86_64-linux.json"
        receipt = json.loads(receipt_path.read_bytes())
        receipt["details"]["rpm_lint_policy"] = ["invalid"]
        receipt["production_promotion_blockers"] = [RPM_POLICY_PROMOTION_BLOCKER, "not a token", 7]
        receipt_path.write_bytes(canonical(receipt))
        manifest_path = directory / "artifact-manifest.json"
        manifest = json.loads(manifest_path.read_bytes())
        manifest["qualification_receipt_hashes"][receipt_path.name] = digest(canonical(receipt))
        manifest_path.write_bytes(canonical(manifest))
        self.assertEqual(summarize(ROOT, self.inputs, self.output), 2)
        summary = json.loads((self.output / "hosted-summary.json").read_bytes())
        self.assertIn("candidate-rpm-x86_64-linux:HOSTED_POLICY", summary["blocking_reasons"])
        expected = sorted([RPM_POLICY_PROMOTION_BLOCKER, LINUX_WHEEL_PROMOTION_BLOCKER])
        self.assertEqual(summary["production_promotion_blockers"], expected)
        with self.assertRaises(ContractError) as caught:
            validate_summary(summary, ROOT, "1" * 40)
        self.assertEqual(caught.exception.code, "HOSTED_POLICY")
        summary["production_promotion_blockers"] = [LINUX_WHEEL_PROMOTION_BLOCKER]
        with self.assertRaises(ContractError) as caught:
            validate_summary(summary, ROOT, "1" * 40)
        self.assertEqual(caught.exception.code, "HOSTED_POLICY")

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.inputs = self.root / "inputs"
        self.inputs.mkdir()
        self.output = self.root / "summary"
        jobs = {j: {"result": "success"} for j in contract(ROOT)["required_jobs"] if j != "summary"}
        env = patch.dict("os.environ", {
            "GITHUB_SHA": "1" * 40,
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_RUN_ATTEMPT": "1",
            "RS9_JOB_CONCLUSIONS": json.dumps(jobs),
        })
        env.start()
        self.addCleanup(env.stop)

    def _populate_standard_lanes(self, skip_rpm=False):
        for row in required(ROOT):
            if skip_rpm and row["lane"] == "rpm":
                continue
            scratch = self.root / row["artifact_name"]
            scratch.mkdir(parents=True, exist_ok=True)
            files = []
            if row.get("custody_required"):
                for product in row["required_products"]:
                    from rs9.product_classes import is_pure_js_cli
                    pure = is_pure_js_cli(product)
                    if row["lane"] == "wheels":
                        tag = "any" if pure else {"aarch64-darwin": "macosx_11_0_arm64", "x86_64-linux": "linux_x86_64", "aarch64-linux": "linux_aarch64"}[row["system"]]
                        name = product.replace("-", "_") + "-0.6.1-py3-none-" + tag + ".whl"
                        p = scratch / "unsigned" / name
                        p.parent.mkdir(exist_ok=True)
                        p.write_bytes(b"whl-bytes")
                        files.append(p)
                    elif row["lane"] == "deb":
                        name = product + "_0.6.1_" + ("all" if pure else row["system"]) + ".deb"
                        p = scratch / "unsigned" / name
                        p.parent.mkdir(exist_ok=True)
                        p.write_bytes(b"deb-bytes")
                        files.append(p)
                    elif row["lane"] == "pacman":
                        name = product + "-0.6.1-1-" + ("any" if pure else "x86_64") + ".pkg.tar.zst"
                        p = scratch / "unsigned" / name
                        p.parent.mkdir(exist_ok=True)
                        p.write_bytes(b"pacman-bytes")
                        files.append(p)
                    elif row["lane"] == "rpm":
                        arch = "noarch" if pure else {"x86_64-linux": "x86_64", "aarch64-linux": "aarch64"}[row["system"]]
                        name = product + "-0.6.1-1." + arch + ".rpm"
                        p = scratch / "unsigned" / name
                        p.parent.mkdir(exist_ok=True)
                        p.write_bytes(_make_synthetic_rpm(product, arch=arch, is_source=False))
                        files.append(p)
            else:
                p = scratch / "fixture-evidence.json"
                p.write_bytes(b"{}")
                files.append(p)

            receipt = {
                "schema": "rs9.hosted-candidate-diagnostic.v1alpha2",
                "lane": row["lane"],
                "system": row["system"],
                "production_enabled": False,
                "publication_authority": False,
                "attended_gates_satisfied": False,
                "execution_error": None,
                "policy_blockers": [],
                "runner": {},
                "provenance": provenance(ROOT, "a" * 64),
                "production_promotion_blockers": [LINUX_WHEEL_PROMOTION_BLOCKER] if row["lane"] == "wheels" and row["system"].endswith("linux") else [],
                "gates": [{"name": g, "status": "pass"} for g in row["required_gates"]],
            }
            if row["lane"] == "rpm":
                from tests.rpm_summary_fixtures import add_rpm_annex
                add_rpm_annex(scratch, receipt, files)
            retain(scratch, self.inputs / row["artifact_name"], files, receipt)

    def test_actual_retain_summarize_source_plus_correct_binaries(self):
        """Actual retain -> summarize with valid typed packages: 4 binaries + 2 source RPMs."""
        self._populate_standard_lanes(skip_rpm=True)

        for system in ("x86_64-linux", "aarch64-linux"):
            scratch = self.root / f"candidate-rpm-{system}"
            scratch.mkdir(parents=True, exist_ok=True)
            files = []
            arch_map = {"x86_64-linux": "x86_64", "aarch64-linux": "aarch64"}
            sys_arch = arch_map[system]

            # 4 binary RPMs
            products = [
                ("theme-forge-stellar-burst", sys_arch),
                ("theme-forge-stellar-loom", "noarch"),
                ("theme-forge-solar-sail", "noarch"),
                ("theme-forge-nebular-fusion", sys_arch),
            ]
            bin_files = []
            for pid, arch in products:
                bin_file = scratch / "unsigned" / f"{pid}-0.6.1-1.{arch}.rpm"
                bin_file.parent.mkdir(exist_ok=True)
                bin_file.write_bytes(_make_synthetic_rpm(pid, arch=arch, is_source=False))
                bin_files.append(bin_file)

            # 2 source RPMs in unsigned-source
            src_files = []
            for pid in ("theme-forge-stellar-loom", "theme-forge-solar-sail"):
                src_file = scratch / "lane-work/unsigned-source" / f"{pid}-0.6.1-1.fc43.src.rpm"
                src_file.parent.mkdir(parents=True, exist_ok=True)
                src_file.write_bytes(_make_synthetic_rpm(pid, arch="src", is_source=True))
                src_files.append(src_file)

            rpm_row = next(r for r in required(ROOT) if r["lane"] == "rpm" and r["system"] == system)
            receipt = {
                "schema": "rs9.hosted-candidate-diagnostic.v1alpha2",
                "lane": "rpm",
                "system": system,
                "production_enabled": False,
                "publication_authority": False,
                "attended_gates_satisfied": False,
                "execution_error": None,
                "policy_blockers": [],
                "runner": {},
                "provenance": provenance(ROOT, "a" * 64),
                "production_promotion_blockers": [],
                "gates": [{"name": g, "status": "pass"} for g in rpm_row["required_gates"]],
            }
            from tests.rpm_summary_fixtures import add_rpm_annex
            add_rpm_annex(scratch, receipt, bin_files)

            for source in src_files:
                project = source.name.split("-0.6.1-")[0]
                build_path = scratch / "build" / project / "rpm-manifest.json"
                build = json.loads(build_path.read_bytes())
                build["reproducibility"] = {"source_rpm": {"name": source.name,
                    "sha256": digest(source.read_bytes()), "size": source.stat().st_size}}
                build_path.write_bytes(canonical(build))
            manifest = retain(scratch, self.inputs / f"candidate-rpm-{system}", bin_files + src_files, receipt)

            # Verify explicit roles in retained manifest
            roles = {r["path"].split("/")[-1]: r.get("role") for r in manifest["files"] if r.get("kind") == "custody"}
            self.assertEqual(roles["theme-forge-stellar-loom-0.6.1-1.fc43.src.rpm"], SOURCE_PACKAGE_EVIDENCE)
            self.assertEqual(roles["theme-forge-solar-sail-0.6.1-1.fc43.src.rpm"], SOURCE_PACKAGE_EVIDENCE)
            self.assertEqual(roles["theme-forge-stellar-loom-0.6.1-1.noarch.rpm"], BINARY_PACKAGE)
            self.assertEqual(roles["theme-forge-solar-sail-0.6.1-1.noarch.rpm"], BINARY_PACKAGE)

        code = summarize(ROOT, self.inputs, self.output)
        summary = json.loads((self.output / "hosted-summary.json").read_bytes())
        self.assertEqual(code, 0)
        self.assertEqual(summary["qualification_verdict"], "qualified")
        self.assertEqual(summary["blocking_reasons"], [])

    def test_source_only_input_must_not_satisfy_presence(self):
        """Source-only input must not satisfy required binary presence gates."""
        self._populate_standard_lanes(skip_rpm=True)

        for system in ("x86_64-linux", "aarch64-linux"):
            scratch = self.root / f"candidate-rpm-{system}"
            scratch.mkdir(parents=True, exist_ok=True)
            files = []

            # Only source RPMs, NO binaries
            for pid in ("theme-forge-stellar-loom", "theme-forge-solar-sail"):
                src_file = scratch / "lane-work/unsigned-source" / f"{pid}-0.6.1-1.fc43.src.rpm"
                src_file.parent.mkdir(parents=True, exist_ok=True)
                src_file.write_bytes(_make_synthetic_rpm(pid, arch="src", is_source=True))
                files.append(src_file)
                build = scratch / "build" / pid / "rpm-manifest.json"
                build.parent.mkdir(parents=True)
                build.write_bytes(canonical({"project": pid, "reproducibility": {"source_rpm": {
                    "name": src_file.name, "sha256": digest(src_file.read_bytes()),
                    "size": src_file.stat().st_size}}}))
                files.append(build)

            receipt = {
                "schema": "rs9.hosted-candidate-diagnostic.v1alpha2",
                "lane": "rpm",
                "system": system,
                "production_enabled": False,
                "publication_authority": False,
                "attended_gates_satisfied": False,
                "execution_error": None,
                "policy_blockers": [],
                "runner": {},
                "provenance": provenance(ROOT, "a" * 64),
                "production_promotion_blockers": [],
                "gates": [{"name": g, "status": "pass"} for g in [
                    "rpm-build", "rpm-metadata-reproducible", "rpm-lint-policy-accepted",
                    "rpm-repository-indexing", "rpm-client-qualification",
                ]],
            }
            retain(scratch, self.inputs / f"candidate-rpm-{system}", files, receipt)

        code = summarize(ROOT, self.inputs, self.output)
        summary = json.loads((self.output / "hosted-summary.json").read_bytes())
        self.assertEqual(code, 2)
        # All required products must report missing-product despite presence of source RPMs
        for prod in ("theme-forge-stellar-burst", "theme-forge-stellar-loom", "theme-forge-solar-sail", "theme-forge-nebular-fusion"):
            self.assertIn(f"candidate-rpm-x86_64-linux:missing-product:{prod}", summary["blocking_reasons"])

    def test_absent_binary_fails_qualification(self):
        """Omitting one binary product records missing-product and fails qualification."""
        self._populate_standard_lanes()
        # Remove burst from deb amd64
        directory = self.inputs / "candidate-deb-amd64"
        manifest = json.loads((directory / "artifact-manifest.json").read_bytes())
        removed = [r for r in manifest["files"] if "stellar_burst" in r["path"] or "stellar-burst" in r["path"]]
        for r in removed:
            manifest["files"].remove(r)
            (directory / r["path"]).unlink()
        (directory / "artifact-manifest.json").write_bytes(canonical(manifest))

        code = summarize(ROOT, self.inputs, self.output)
        summary = json.loads((self.output / "hosted-summary.json").read_bytes())
        self.assertEqual(code, 2)
        self.assertIn("candidate-deb-amd64:missing-product:theme-forge-stellar-burst", summary["blocking_reasons"])

    def test_wrong_architecture_binary_rejected(self):
        """Wrong architecture binary triggers CUSTODY_ARCHITECTURE and records failure."""
        self._populate_standard_lanes()
        # Mutate stellar-burst in rpm x86_64 to noarch
        directory = self.inputs / "candidate-rpm-x86_64-linux"
        manifest = json.loads((directory / "artifact-manifest.json").read_bytes())
        for r in manifest["files"]:
            if "stellar-burst" in r["path"] and r["path"].endswith(".rpm"):
                old_p = directory / r["path"]
                new_path_str = r["path"].replace(".x86_64.rpm", ".noarch.rpm")
                new_p = directory / new_path_str
                old_p.rename(new_p)
                r["path"] = new_path_str
        (directory / "artifact-manifest.json").write_bytes(canonical(manifest))

        code = summarize(ROOT, self.inputs, self.output)
        summary = json.loads((self.output / "hosted-summary.json").read_bytes())
        self.assertEqual(code, 2)
        self.assertIn("candidate-rpm-x86_64-linux:CUSTODY_ARCHITECTURE", summary["blocking_reasons"])

    def test_role_type_mismatch_rejected(self):
        """Declared role mismatch against producer path triggers PACKAGE_ROLE."""
        self._populate_standard_lanes()
        directory = self.inputs / "candidate-rpm-x86_64-linux"
        manifest = json.loads((directory / "artifact-manifest.json").read_bytes())
        # Mislabel a binary package as source-package-evidence
        for r in manifest["files"]:
            if r.get("role") == BINARY_PACKAGE:
                r["role"] = SOURCE_PACKAGE_EVIDENCE
                break
        (directory / "artifact-manifest.json").write_bytes(canonical(manifest))

        code = summarize(ROOT, self.inputs, self.output)
        summary = json.loads((self.output / "hosted-summary.json").read_bytes())
        self.assertEqual(code, 2)
        self.assertIn("candidate-rpm-x86_64-linux:CUSTODY_ROLE", summary["blocking_reasons"])

    def test_unknown_or_malformed_package_fails_closed(self):
        """Corrupted RPM header bytes triggers PACKAGE_ROLE."""
        self._populate_standard_lanes()
        directory = self.inputs / "candidate-rpm-x86_64-linux"
        manifest = json.loads((directory / "artifact-manifest.json").read_bytes())
        for r in manifest["files"]:
            if r.get("role") == BINARY_PACKAGE:
                p = directory / r["path"]
                p.write_bytes(b"corrupted-lead-and-headers")
                r["size"] = p.stat().st_size
                r["sha256"] = digest(b"corrupted-lead-and-headers")
                break
        (directory / "artifact-manifest.json").write_bytes(canonical(manifest))

        code = summarize(ROOT, self.inputs, self.output)
        summary = json.loads((self.output / "hosted-summary.json").read_bytes())
        self.assertEqual(code, 2)
        self.assertIn("candidate-rpm-x86_64-linux:CUSTODY_ROLE", summary["blocking_reasons"])

    def test_changed_or_missing_source_evidence_fails_closed(self):
        """Changed source RPM bytes or missing source file fails role verification."""
        self._populate_standard_lanes(skip_rpm=True)

        scratch = self.root / "candidate-rpm-x86_64-linux"
        scratch.mkdir(parents=True, exist_ok=True)
        files = []

        bin_file = scratch / "unsigned/theme-forge-stellar-loom-0.6.1-1.noarch.rpm"
        bin_file.parent.mkdir(exist_ok=True)
        bin_file.write_bytes(_make_synthetic_rpm("theme-forge-stellar-loom", arch="noarch", is_source=False))
        files.append(bin_file)

        src_file = scratch / "lane-work/unsigned-source/theme-forge-stellar-loom-0.6.1-1.fc43.src.rpm"
        src_file.parent.mkdir(parents=True, exist_ok=True)
        src_file.write_bytes(_make_synthetic_rpm("theme-forge-stellar-loom", arch="src", is_source=True))
        files.append(src_file)

        # Build manifest declaring reproducibility source_rpm
        bm_path = scratch / "build/theme-forge-stellar-loom/rpm-manifest.json"
        bm_path.parent.mkdir(parents=True, exist_ok=True)
        bm_doc = {
            "schema": "rs9.rpm-candidate.v1alpha2",
            "project": "theme-forge-stellar-loom",
            "construction_witness": {
                "reproducibility": {
                    "source_rpm": {
                        "name": src_file.name,
                        "sha256": digest(src_file.read_bytes()),
                        "size": src_file.stat().st_size,
                    }
                }
            },
        }
        bm_path.write_text(json.dumps(bm_doc))
        files.append(bm_path)

        receipt = {
            "schema": "rs9.hosted-candidate-diagnostic.v1alpha2",
            "lane": "rpm",
            "system": "x86_64-linux",
            "production_enabled": False,
            "publication_authority": False,
            "attended_gates_satisfied": False,
            "execution_error": None,
            "policy_blockers": [],
            "runner": {},
            "provenance": provenance(ROOT, "a" * 64),
            "production_promotion_blockers": [],
            "gates": [],
        }
        retain(scratch, self.inputs / "candidate-rpm-x86_64-linux", files, receipt)

        # Tamper with the source RPM
        target_src = self.inputs / "candidate-rpm-x86_64-linux/objects/lane-work/unsigned-source" / src_file.name
        target_src.write_bytes(_make_synthetic_rpm("theme-forge-stellar-loom", arch="src", is_source=True, payload=b"tampered"))
        # Update manifest hash to test reproducibility check specifically
        m_path = self.inputs / "candidate-rpm-x86_64-linux/artifact-manifest.json"
        m_doc = json.loads(m_path.read_bytes())
        for r in m_doc["files"]:
            if r["path"].endswith(".src.rpm"):
                r["sha256"] = digest(target_src.read_bytes())
                r["size"] = target_src.stat().st_size
        m_path.write_bytes(canonical(m_doc))

        with self.assertRaises(ContractError) as caught:
            verify_package_roles(self.inputs / "candidate-rpm-x86_64-linux", m_doc)
        self.assertEqual(caught.exception.code, "CUSTODY_SOURCE_EVIDENCE")

    def test_fixture_only_copies_fail_binary_presence(self):
        """Fixture-only copies cannot satisfy candidate binary presence."""
        self._populate_standard_lanes(skip_rpm=True)

        scratch = self.root / "candidate-rpm-x86_64-linux"
        scratch.mkdir(parents=True, exist_ok=True)
        files = []

        # Only fixture copies in signed/
        for pid in ("theme-forge-stellar-burst", "theme-forge-stellar-loom", "theme-forge-solar-sail", "theme-forge-nebular-fusion"):
            arch = "noarch" if "loom" in pid or "sail" in pid else "x86_64"
            p = scratch / "signed" / f"{pid}-0.6.1-1.{arch}.rpm"
            p.parent.mkdir(exist_ok=True)
            p.write_bytes(_make_synthetic_rpm(pid, arch=arch, is_source=False))
            files.append(p)

        receipt = {
            "schema": "rs9.hosted-candidate-diagnostic.v1alpha2",
            "lane": "rpm",
            "system": "x86_64-linux",
            "production_enabled": False,
            "publication_authority": False,
            "attended_gates_satisfied": False,
            "execution_error": None,
            "policy_blockers": [],
            "runner": {},
            "provenance": provenance(ROOT, "a" * 64),
            "production_promotion_blockers": [],
            "gates": [],
        }
        manifest = retain(scratch, self.inputs / "candidate-rpm-x86_64-linux", files, receipt)

        # All rows should be fixture-signed-copy
        for r in manifest["files"]:
            if r.get("kind") == "custody":
                self.assertEqual(r.get("role"), FIXTURE_SIGNED_COPY)
                self.assertFalse(is_installable_binary(r))

        code = summarize(ROOT, self.inputs, self.output)
        summary = json.loads((self.output / "hosted-summary.json").read_bytes())
        self.assertEqual(code, 2)
        self.assertIn("candidate-rpm-x86_64-linux:missing-product:theme-forge-stellar-burst", summary["blocking_reasons"])

    def test_historical_run14_manifests_compatibility_without_current_authority(self):
        """Historical run-14 manifests pass architecture diagnostics but never gain current authority."""
        self.assertTrue(RUN14_FIXTURE_PATH.is_file(), f"Fixture missing: {RUN14_FIXTURE_PATH}")
        data = json.loads(RUN14_FIXTURE_PATH.read_bytes())
        self.assertEqual(data.get("schema"), "rs9.run14-rpm-manifests.v1")

        for system in ("x86_64-linux", "aarch64-linux"):
            manifest = data[system]
            lane = {
                "lane": "rpm",
                "system": system,
                "required_products": [
                    "theme-forge-stellar-burst",
                    "theme-forge-stellar-loom",
                    "theme-forge-solar-sail",
                    "theme-forge-nebular-fusion",
                ],
            }

            # 1. Historical compatibility: validate_product_architectures PASSES (defect resolved!)
            try:
                validate_product_architectures(lane, manifest["files"])
            except ContractError as err:
                self.fail(f"Historical run-14 manifest for {system} failed architecture validation: {err}")

            # 2. Strict authority: NO row in historical manifest is an installable binary
            for row in manifest["files"]:
                self.assertNotIn("role", row)  # Historical manifests have no role
                self.assertFalse(is_installable_binary(row))

            # 3. verify_package_roles REJECTS historical manifests for current qualification
            with tempfile.TemporaryDirectory() as td:
                with self.assertRaises(ContractError) as caught:
                    verify_package_roles(td, manifest)
                self.assertEqual(caught.exception.code, "CUSTODY_ROLE")

    def test_exact_run14_package_paths_through_current_retention(self):
        """Replay both historical path sets with typed test bytes, not historical hashes."""
        data = json.loads(RUN14_FIXTURE_PATH.read_bytes())
        for system in ("x86_64-linux", "aarch64-linux"):
            with self.subTest(system=system):
                scratch = self.root / system
                scratch.mkdir()
                historical = [r for r in data[system]["files"] if r["kind"] == "custody"]
                products = next(r["required_products"] for r in required(ROOT)
                                if r["lane"] == "rpm" and r["system"] == system)
                files = []
                for row in historical:
                    source = scratch / row["path"].removeprefix("objects/")
                    source.parent.mkdir(parents=True, exist_ok=True)
                    product = next(p for p in products if source.name.startswith(p + "-"))
                    version = source.name.removeprefix(product + "-").split("-", 1)[0]
                    is_source = source.name.endswith(".src.rpm")
                    arch = source.name.rsplit(".", 2)[-2]
                    source.write_bytes(_make_synthetic_rpm(product, arch=arch,
                        version=version, is_source=is_source))
                    files.append(source)
                    if is_source:
                        build = scratch / "lane-work/build" / product / "rpm-manifest.json"
                        build.parent.mkdir(parents=True)
                        build.write_bytes(canonical({"project": product, "reproducibility": {
                            "source_rpm": {"name": source.name, "size": source.stat().st_size,
                                           "sha256": digest(source.read_bytes())}}}))
                        files.append(build)
                record = {"lane": "rpm", "system": system, "runner": {},
                          "provenance": provenance(ROOT, "a" * 64), "execution_error": None}
                output = self.root / (system + "-retained")
                manifest = retain(scratch, output, files, record)
                verify_set(output)
                verified = verify_package_roles(output, manifest)
                retained = {r["path"]: r for r in manifest["files"] if r["kind"] == "custody"}
                self.assertEqual(set(retained), {r["path"] for r in historical})
                for row in historical:
                    current = retained[row["path"]]
                    expected_role = (SOURCE_PACKAGE_EVIDENCE if row["path"].endswith(".src.rpm")
                        else FIXTURE_SIGNED_COPY if row["promotion"] == "fixture-test-only"
                        else BINARY_PACKAGE)
                    self.assertEqual(current["promotion"], row["promotion"])
                    self.assertEqual(current["role"], expected_role)
                    self.assertEqual(producer_role("rpm", row["path"]), expected_role)
                    self.assertEqual(verified["verified_roles"][row["path"]], expected_role)
                validate_product_architectures({"lane": "rpm", "system": system,
                                               "required_products": products}, manifest["files"])

    def test_unknown_package_retains_other_objects_and_causal_failure(self):
        for primary in (None, "PRIMARY_BUILD_FAILURE"):
            with self.subTest(primary=primary):
                scratch = self.root / (primary or "no-primary")
                scratch.mkdir()
                known = scratch / "lane-work/unsigned/theme-forge-stellar-burst-0.6.1-1.x86_64.rpm"
                unknown = scratch / "lane-work/unsigned/unexpected.src.rpm"
                diagnostic = scratch / "diagnostics/result.json"
                known.parent.mkdir(parents=True)
                diagnostic.parent.mkdir()
                known.write_bytes(_make_synthetic_rpm("theme-forge-stellar-burst", arch="x86_64"))
                unknown.write_bytes(_make_synthetic_rpm("unexpected", is_source=True))
                diagnostic.write_bytes(b'{"status":"retained"}')
                record = {"lane": "rpm", "system": "x86_64-linux", "runner": {},
                          "provenance": provenance(ROOT, "a" * 64), "execution_error": primary}
                output = scratch / "output"
                manifest = retain(scratch, output, [known, unknown, diagnostic], record)
                self.assertEqual(verify_set(output), manifest)
                self.assertEqual(len(manifest["files"]), 3)
                self.assertEqual(record["execution_error"], primary or "CUSTODY_ROLE")
                self.assertEqual(record["custody_role_failures"], [{
                    "path": "objects/lane-work/unsigned/unexpected.src.rpm", "code": "CUSTODY_ROLE"}])
                self.assertEqual(json.loads((output / "rpm-x86_64-linux.json").read_bytes()), record)
                row = next(r for r in manifest["files"] if r["path"].endswith("unexpected.src.rpm"))
                self.assertEqual(row["role"], UNCLASSIFIED_PACKAGE)
                self.assertFalse(is_installable_binary(row))
                self.assertEqual((output / row["path"]).read_bytes(), unknown.read_bytes())
                with self.assertRaises(ContractError) as caught:
                    verify_package_roles(output, manifest)
                self.assertEqual(caught.exception.code, "CUSTODY_ROLE")

    def test_wrong_architecture_fixture_copies_block_actual_summary(self):
        self._populate_standard_lanes()
        for family, relative, body in (
            ("rpm", "lane-work/rpm/fedora/43/x86_64/Packages/theme-forge-stellar-burst-0.6.1-1.aarch64.rpm",
             _make_synthetic_rpm("theme-forge-stellar-burst", arch="aarch64")),
            ("pacman", "lane-work/pacman/theme-forge-stellar-burst-0.6.1-1-aarch64.pkg.tar.zst", b"fixture-copy"),
        ):
            directory = self.inputs / ("candidate-" + family + "-x86_64-linux")
            scratch = self.root / directory.name
            manifest = json.loads((directory / "artifact-manifest.json").read_bytes())
            files = [scratch / r["path"].removeprefix("objects/") for r in manifest["files"]]
            fixture = scratch / relative
            fixture.parent.mkdir(parents=True)
            fixture.write_bytes(body)
            files.append(fixture)
            receipt = json.loads((directory / (family + "-x86_64-linux.json")).read_bytes())
            retained = retain(scratch, directory, files, receipt)
            row = next(r for r in retained["files"] if r["path"] == "objects/" + relative)
            self.assertEqual(row["role"], FIXTURE_SIGNED_COPY)
            self.assertFalse(is_installable_binary(row))
        self.assertEqual(summarize(ROOT, self.inputs, self.output), 2)
        summary = json.loads((self.output / "hosted-summary.json").read_bytes())
        for family in ("rpm", "pacman"):
            self.assertIn("candidate-" + family + "-x86_64-linux:CUSTODY_ARCHITECTURE",
                          summary["blocking_reasons"])

    def test_promotion_restrictions_conservative_accumulation(self):
        """Promotion restrictions accumulate conservatively even when lane checks fail."""
        # Test missing linux wheel blocker
        tokens, errors = promotion_restrictions(
            {"lane": "wheels", "system": "x86_64-linux"},
            {"production_promotion_blockers": []},
        )
        self.assertIn(LINUX_WHEEL_PROMOTION_BLOCKER, tokens)
        self.assertIn("HOSTED_POLICY", errors)

        # Test missing rpm lint blocker with accepted findings
        tokens, errors = promotion_restrictions(
            {"lane": "rpm", "system": "x86_64-linux"},
            {
                "production_promotion_blockers": [],
                "details": {
                    "rpm_lint_policy": {
                        "p1": {"accepted_findings": [{"code": "x"}]},
                    }
                },
            },
        )
        self.assertIn(RPM_POLICY_PROMOTION_BLOCKER, tokens)
        self.assertIn("HOSTED_POLICY", errors)

        # Test malformed rpm_lint_policy non-dict
        tokens, errors = promotion_restrictions(
            {"lane": "rpm", "system": "x86_64-linux"},
            {
                "production_promotion_blockers": [],
                "details": {"rpm_lint_policy": "malformed-non-dict"},
            },
        )
        self.assertIn(RPM_POLICY_PROMOTION_BLOCKER, tokens)
        self.assertIn("HOSTED_POLICY", errors)

        # Test malformed production_promotion_blockers
        tokens, errors = promotion_restrictions(
            {"lane": "deb", "system": "amd64"},
            {"production_promotion_blockers": "not-a-list"},
        )
        self.assertEqual(tokens, [])
        self.assertIn("HOSTED_POLICY", errors)

        # Test that in summarize, a lane with architecture failure STILL retains promotion blockers
        self._populate_standard_lanes()
        # Add an RPM promotion blocker to receipt
        directory = self.inputs / "candidate-rpm-x86_64-linux"
        receipt_path = directory / "rpm-x86_64-linux.json"
        rec = json.loads(receipt_path.read_bytes())
        rec["production_promotion_blockers"] = [RPM_POLICY_PROMOTION_BLOCKER]
        receipt_path.write_bytes(canonical(rec))
        # Update manifest receipt hash
        m_path = directory / "artifact-manifest.json"
        m_doc = json.loads(m_path.read_bytes())
        m_doc["qualification_receipt_hashes"]["rpm-x86_64-linux.json"] = digest(canonical(rec))
        # Cause an architecture failure in this lane
        for r in m_doc["files"]:
            if "stellar-burst" in r["path"] and r["path"].endswith(".rpm"):
                old_p = directory / r["path"]
                new_path_str = r["path"].replace(".x86_64.rpm", ".noarch.rpm")
                new_p = directory / new_path_str
                old_p.rename(new_p)
                r["path"] = new_path_str
        m_path.write_bytes(canonical(m_doc))

        code = summarize(ROOT, self.inputs, self.output)
        summary = json.loads((self.output / "hosted-summary.json").read_bytes())
        self.assertEqual(code, 2)
        # Architecture failure is recorded
        self.assertIn("candidate-rpm-x86_64-linux:CUSTODY_ARCHITECTURE", summary["blocking_reasons"])
        # BUT promotion blocker from the failing lane is STILL retained!
        self.assertIn(RPM_POLICY_PROMOTION_BLOCKER, summary["production_promotion_blockers"])
        self.assertIn(LINUX_WHEEL_PROMOTION_BLOCKER, summary["production_promotion_blockers"])


if __name__ == "__main__":
    unittest.main()
