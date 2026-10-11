"""Complete Foundation 3 integration tests across 16 planning paths and canonical adapters.

Exercises:
- Complete real Foundation 3 execute for four products x PyPI/APT/DNF/pacman (16 paths).
- Canonical publication adapter gate reconciliation (apt, dnf, pacman, pypi).
- Disabled destination policy, in-process verifier, and retained artifacts.
- Strict missing/unknown adverse cases and role enforcement.
- Earlier evidence retention when subsequent products fail.
- Bounded product/adapter/substage failure records.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from rs9.errors import ContractError
from rs9.adapter_gates import ADAPTER_GATES, mandatory_gates
from rs9.gates import derive_gates
from rs9.hosted_custody import provenance, retain, verify_set
from rs9.hosted_foundation3 import (
    FoundationExecutionError,
    execute,
    publication_policy,
    resolve_destination_binding,
    verify_candidate_files,
    wheel_architecture_set,
)
from rs9.package_roles import BINARY_PACKAGE, is_installable_binary, verify_package_roles
from rs9.product_classes import (
    NATIVE_PACKAGING_MAPPINGS,
    get_native_packaging_mapping,
    resolve_canonical_publication_adapter,
    resolve_native_revision_scheme,
    resolve_qualification_gate,
    resolve_qualification_scope,
    supported_architectures,
)
from rs9.profiles import (
    PACKAGE_PROFILE,
    TAURI_AUTHORITY_PROFILE,
    evaluate_profile,
    selection_for_intent,
)
from rs9.release_core import authenticate_release
from rs9.rpm_evidence import CURRENT_RPM_EVIDENCE_CONTRACT, write_policy_evidence
from rs9.rpm_evidence import durable_lint_projection
from rs9.rpm_lint import build_rpmlint_evidence
from rs9.rpm_lint_policy import evaluate_policy
from rs9.build_native import CommandReceipt
from rs9.scratch import canonical
from rs9.wheel import format_record, verify_wheel_record_bidirectional
import lzma
import struct
from rs9.rpm_header import RPM_LEAD_MAGIC, RPM_HEADER_MAGIC
from tests.publication_fixtures import authorize_fixture_configuration
from tests.shadow_fixtures import fixture_evidence
from tests.test_build_native import create_cli_fixture
from tests.test_pages import cpio_newc, make_xz_deb


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures/run10/rpm"


def make_test_rpm(product: str, arch: str, *, files: dict[str, bytes] | None = None, is_source: bool = False) -> bytes:
    if files is None:
        files = {"usr/bin/tool": b"#!/bin/sh\n"}
    lead_type = 1 if is_source else 0
    lead = (RPM_LEAD_MAGIC + b"\x03\x00" + struct.pack(">HH", lead_type, 1) + product.encode().ljust(66, b"\0")
            + struct.pack(">HH", 1, 5) + b"\0" * 16)

    sig_store = b"sig\0"
    sig_entry = struct.pack(">IIII", 1000, 7, 0, len(sig_store))
    signature = RPM_HEADER_MAGIC + b"\0\0\0\0" + struct.pack(">II", 1, len(sig_store)) + sig_entry + sig_store
    signature += b"\0" * (-len(signature) % 8)

    store = bytearray()
    entries = []

    off = len(store)
    store.extend((product + "\0").encode("utf-8"))
    entries.append(struct.pack(">IIII", 1000, 6, off, 1))

    off = len(store)
    store.extend((arch + "\0").encode("utf-8"))
    entries.append(struct.pack(">IIII", 1022, 6, off, 1))

    if is_source:
        off = len(store)
        store.extend(struct.pack(">I", 1))
        entries.append(struct.pack(">IIII", 1106, 4, off, 1))

    header = RPM_HEADER_MAGIC + b"\0\0\0\0" + struct.pack(">II", len(entries), len(store)) + b"".join(entries) + bytes(store)
    payload = cpio_newc(files)
    compressed = lzma.compress(payload, check=lzma.CHECK_CRC32)
    return lead + signature + header + compressed


def make_test_wheel(dest_dir: Path, product: str, version: str, platform_tag: str) -> Path:
    stem = product.replace("-", "_")
    filename = f"{stem}-{version}-py3-none-{platform_tag}.whl"
    dist_info = f"{stem}-{version}.dist-info"
    entries = {
        f"{dist_info}/METADATA": f"Metadata-Version: 2.1\nName: {product}\nVersion: {version}\n".encode("utf-8"),
        f"{dist_info}/WHEEL": f"Wheel-Version: 1.0\nRoot-Is-Purelib: {str(platform_tag == 'any').lower()}\nTag: py3-none-{platform_tag}\n".encode("utf-8"),
        f"{stem}/__init__.py": b"# pure test code\n",
    }
    entries[f"{dist_info}/RECORD"] = format_record(entries, dist_info)
    target = dest_dir / filename
    with zipfile.ZipFile(target, "w") as zf:
        for name, content in entries.items():
            zf.writestr(name, content)
    return target


def make_test_pacman(payload_files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:xz") as tar:
        pkginfo = b"pkgname = test\npkgver = 1.0\n"
        ti = tarfile.TarInfo(".PKGINFO")
        ti.size = len(pkginfo)
        tar.addfile(ti, io.BytesIO(pkginfo))
        for p, data in payload_files.items():
            item = tarfile.TarInfo(p)
            item.size = len(data)
            tar.addfile(item, io.BytesIO(data))
    return buf.getvalue()


class Foundation3AdaptersTests(unittest.TestCase):
    def setUp(self):
        env = patch.dict(
            "os.environ",
            {
                "GITHUB_SHA": "0" * 40,
                "GITHUB_REF": "refs/heads/main",
                "GITHUB_EVENT_NAME": "push",
                "GITHUB_RUN_ATTEMPT": "1",
            },
        )
        env.start()
        self.addCleanup(env.stop)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.scratch = self.root / "scratch"
        self.scratch.mkdir()
        self.inputs = self.root / "inputs"
        self.inputs.mkdir()

    def _build_captures(self):
        captures = []

        # 1. Stellar Loom (pure-js-cli)
        c_loom, i_loom, _ = create_cli_fixture(self.root / "loom", "theme-forge-stellar-loom")
        p_loom = evaluate_profile(c_loom, PACKAGE_PROFILE, i_loom)
        captures.append((c_loom, i_loom, p_loom))

        # 2. Stellar Burst (native-node-cli)
        c_burst, i_burst, _ = create_cli_fixture(self.root / "burst", "theme-forge-stellar-burst")
        p_burst = evaluate_profile(c_burst, PACKAGE_PROFILE, i_burst)
        captures.append((c_burst, i_burst, p_burst))

        # 3. Solar Sail (pure-js-cli)
        c_sail, i_sail, _ = create_cli_fixture(self.root / "sail", "theme-forge-solar-sail")
        p_sail = evaluate_profile(c_sail, PACKAGE_PROFILE, i_sail)
        captures.append((c_sail, i_sail, p_sail))

        # 4. Nebular Fusion (native-desktop)
        p_neb_dir = self.root / "nebular"
        p_neb_dir.mkdir()
        i_neb = fixture_evidence(p_neb_dir)
        i_neb["targets"].append({
            "adapter": "pypi",
            "destination": "pypi",
            "package": "theme-forge-nebular-fusion",
            "mode": "direct",
            "name": "theme-forge-nebular-fusion",
        })
        i_neb["release"]["evidence"]["profile"] = TAURI_AUTHORITY_PROFILE
        c_neb = authenticate_release(selection_for_intent(i_neb), p_neb_dir)
        authorize_fixture_configuration(p_neb_dir, i_neb, c_neb)
        p_neb = evaluate_profile(c_neb, TAURI_AUTHORITY_PROFILE, i_neb)
        captures.append((c_neb, i_neb, p_neb))

        return captures

    def _populate_all_inputs(self, *, include_typed_rpm_evidence: bool = True):
        # 1. Wheels
        whl_dir = self.inputs / "wheels"
        whl_dir.mkdir(exist_ok=True)
        make_test_wheel(whl_dir, "theme-forge-stellar-loom", "0.4.0", "any")
        for tag in ("linux_x86_64", "linux_aarch64", "macosx_13_0_arm64"):
            make_test_wheel(whl_dir, "theme-forge-stellar-burst", "0.6.1", tag)
        make_test_wheel(whl_dir, "theme-forge-solar-sail", "0.2.1", "any")
        for tag in ("linux_x86_64", "linux_aarch64", "macosx_13_0_arm64"):
            make_test_wheel(whl_dir, "theme-forge-nebular-fusion", "0.6.1", tag)

        prov = provenance(ROOT, "a" * 64)

        # 2. DEB set
        work_deb = self.root / "work-deb"
        work_deb.mkdir(exist_ok=True)
        (work_deb / "custody").mkdir(parents=True, exist_ok=True)
        deb_files = []
        for p, ver, archs in [
            ("theme-forge-stellar-loom", "0.4.0", ["all"]),
            ("theme-forge-stellar-burst", "0.6.1", ["amd64", "arm64"]),
            ("theme-forge-solar-sail", "0.2.1", ["all"]),
            ("theme-forge-nebular-fusion", "0.6.1", ["amd64", "arm64"]),
        ]:
            for a in archs:
                fn = f"{p}_{ver}-1_{a}.deb"
                raw = make_xz_deb("./usr/bin/tool", b"#!/bin/sh\n")
                target = work_deb / "custody" / fn
                target.write_bytes(raw)
                deb_files.append(target)
        record_deb = {
            "schema": "rs9.hosted-candidate-diagnostic.v1alpha2",
            "lane": "deb",
            "system": "all",
            "production_enabled": False,
            "publication_authority": False,
            "runner": {"os": "Linux"},
            "provenance": prov,
            "gates": [],
        }
        out_deb = self.inputs / "candidate-deb"
        retain(work_deb, out_deb, deb_files, record_deb)

        # 3. Pacman set
        work_pac = self.root / "work-pac"
        work_pac.mkdir(exist_ok=True)
        (work_pac / "custody").mkdir(parents=True, exist_ok=True)
        pac_files = []
        for p, ver, archs in [
            ("theme-forge-stellar-loom", "0.4.0", ["any"]),
            ("theme-forge-stellar-burst", "0.6.1", ["x86_64"]),
            ("theme-forge-solar-sail", "0.2.1", ["any"]),
            ("theme-forge-nebular-fusion", "0.6.1", ["x86_64"]),
        ]:
            for a in archs:
                fn = f"{p}-{ver}-1-{a}.pkg.tar.xz"
                raw = make_test_pacman({"usr/bin/tool": b"#!/bin/sh\n"})
                target = work_pac / "custody" / fn
                target.write_bytes(raw)
                pac_files.append(target)
        record_pac = {
            "schema": "rs9.hosted-candidate-diagnostic.v1alpha2",
            "lane": "pacman",
            "system": "x86_64",
            "production_enabled": False,
            "publication_authority": False,
            "runner": {"os": "Linux"},
            "provenance": prov,
            "gates": [],
        }
        out_pac = self.inputs / "candidate-pacman"
        retain(work_pac, out_pac, pac_files, record_pac)

        # 4. RPM sets (two systems: x86_64-linux and aarch64-linux)
        rpm_specs = {
            "x86_64-linux": [
                ("theme-forge-stellar-loom", "0.4.0", "noarch"),
                ("theme-forge-stellar-burst", "0.6.1", "x86_64"),
                ("theme-forge-solar-sail", "0.2.1", "noarch"),
                ("theme-forge-nebular-fusion", "0.6.1", "x86_64"),
            ],
            "aarch64-linux": [
                ("theme-forge-stellar-loom", "0.4.0", "noarch"),
                ("theme-forge-stellar-burst", "0.6.1", "aarch64"),
                ("theme-forge-solar-sail", "0.2.1", "noarch"),
                ("theme-forge-nebular-fusion", "0.6.1", "aarch64"),
            ],
        }

        for system, packages in rpm_specs.items():
            work_rpm = self.root / f"work-rpm-{system}"
            work_rpm.mkdir(exist_ok=True)
            lane = work_rpm / "lane-work"
            (lane / "unsigned").mkdir(parents=True)
            (lane / "unsigned-custody" / "files").mkdir(parents=True)
            files = []
            for p, ver, arch in packages:
                fn = f"{p}-{ver}-1.fc43.{arch}.rpm"
                raw = make_test_rpm(p, arch)
                target = lane / "unsigned" / fn
                target.write_bytes(raw)
                copy = lane / "unsigned-custody" / "files" / fn
                copy.write_bytes(raw)
                files.extend([target, copy])

            receipt_rpm_details = {
                "rpm_evidence_contract": CURRENT_RPM_EVIDENCE_CONTRACT,
                "rpm_lint_raw": {},
                "rpm_lint_policy": {},
            }
            if include_typed_rpm_evidence:
                diag_dir = lane / "diagnostics"
                diag_dir.mkdir(parents=True, exist_ok=True)
                for p, ver, arch in packages:
                    target = lane / "unsigned" / f"{p}-{ver}-1.fc43.{arch}.rpm"
                    spec = lane / (p + ".spec")
                    spec.write_bytes(b"fixture spec\n")
                    tool = CommandReceipt(["rpmlint", spec.name, target.name], 64,
                        (p + "." + arch + ": E: fixture-unaccepted-error\n"
                         "1 packages and 1 specfiles checked; 1 errors, 0 warnings, 0 filtered.\n").encode(),
                        b"", executed=True)
                    raw_lint = build_rpmlint_evidence(tool, spec, target, p,
                        rpm_identity={"name": p, "version": ver, "release": "1.fc43", "arch": arch})
                    # Real current producer shapes, deliberately blocked policy:
                    # native structure verification must not import lint authority.
                    evaluation = evaluate_policy(raw_lint, {},
                        {"project_id": p, "version": ver, "arch": arch, "system": system})
                    summary, diag_files = write_policy_evidence(diag_dir, evaluation)
                    raw_path = diag_dir / ("rpmlint-" + p + ".json")
                    raw_path.write_bytes(canonical(raw_lint))
                    derivation = {"project": p, "adapter": "rpm",
                        "artifact": {"sha256": raw_lint["package_sha256"]},
                        "evidence": {"rpmlint": durable_lint_projection(raw_lint)}}
                    rpm_manifest = {"schema": "rs9.rpm-candidate.v1alpha2", "project": p,
                        "architecture": arch, "package_file": "unsigned/" + target.name,
                        "package_sha256": raw_lint["package_sha256"], "package_size": target.stat().st_size,
                        "rpmlint": raw_lint, "derivation": derivation}
                    if arch == "noarch":
                        source = lane / "unsigned-source" / f"{p}-{ver}-1.fc43.src.rpm"
                        source.parent.mkdir(exist_ok=True)
                        source.write_bytes(make_test_rpm(p, "noarch", is_source=True))
                        rpm_manifest["reproducibility"] = {"source_rpm": {"name": source.name,
                            "sha256": hashlib.sha256(source.read_bytes()).hexdigest(), "size": source.stat().st_size}}
                        files.append(source)
                    manifest_path = lane / "build" / p / "rpm-manifest.json"
                    manifest_path.parent.mkdir(parents=True)
                    manifest_path.write_bytes(canonical(rpm_manifest))
                    files.extend([*diag_files, raw_path, manifest_path])
                    receipt_rpm_details["rpm_lint_raw"][p] = raw_lint
                    receipt_rpm_details["rpm_lint_policy"][p] = summary

            record_rpm = {
                "schema": "rs9.hosted-candidate-diagnostic.v1alpha2",
                "lane": "rpm",
                "system": system,
                "production_enabled": False,
                "publication_authority": False,
                "runner": {"os": "Linux"},
                "provenance": prov,
                "gates": [{"name": "rpm-lint-policy-accepted", "status": "fail"}],
                "details": receipt_rpm_details,
            }
            out_rpm = self.inputs / f"candidate-rpm-{system}"
            retain(work_rpm, out_rpm, files, record_rpm)

    def test_complete_sixteen_integrated_planning_paths(self):
        """Exercise complete real Foundation3 execute for four products x PyPI/APT/DNF/pacman (16)."""
        captures = self._build_captures()
        self._populate_all_inputs(include_typed_rpm_evidence=True)

        context = {
            "inputs": str(self.inputs),
            "scratch": self.scratch,
            "captures": captures,
        }
        result = execute(context)

        # 1. Gates evaluated
        gate_names = [g["name"] for g in result["gates"]]
        self.assertIn("foundation3-plan-assembly", gate_names)
        self.assertIn("publication-readiness-evaluation", gate_names)

        assembly_gate = next(g for g in result["gates"] if g["name"] == "foundation3-plan-assembly")
        self.assertEqual(assembly_gate["status"], "pass")
        self.assertEqual(assembly_gate["reason"], "fresh-in-process-verification")

        readiness_gate = next(g for g in result["gates"] if g["name"] == "publication-readiness-evaluation")
        self.assertEqual(readiness_gate["status"], "pass")
        self.assertEqual(readiness_gate["reason"], "evaluated-as-disabled-attended-gates-unsatisfied")

        # 2. Empty missing_inputs and failed_records
        self.assertEqual(result["details"]["missing_inputs"], [])
        self.assertEqual(result["details"].get("failed_records", []), [])

        # 3. Exactly 16 records
        records = result["details"]["records"]
        self.assertEqual(len(records), 16)

        adapter_counts = Counter(r["adapter"] for r in records)
        self.assertEqual(adapter_counts, {"pypi": 4, "apt": 4, "dnf": 4, "pacman": 4})

        # All 16 outcomes must be 'block' due to disabled destination policy
        outcomes = [r["outcome"] for r in records]
        self.assertEqual(outcomes, ["block"] * 16)

        # 4. Serialized and retained artifacts
        foundation_doc_path = self.scratch / "foundation3.json"
        self.assertTrue(foundation_doc_path.is_file())
        foundation_doc = json.loads(foundation_doc_path.read_bytes())
        self.assertFalse(foundation_doc["production_enabled"])
        self.assertFalse(foundation_doc["attended_gates_satisfied"])
        self.assertEqual(len(foundation_doc["qualification_records"]), 16)
        self.assertEqual(foundation_doc["missing_inputs"], [])
        self.assertEqual(foundation_doc.get("failed_records", []), [])

        # Verify typed RPM policy evidence for both systems in doc
        rpm_results = foundation_doc.get("rpm_lint_results", [])
        self.assertEqual(len(rpm_results), 8)
        self.assertEqual({r["system"] for r in rpm_results}, {"x86_64-linux", "aarch64-linux"})
        self.assertTrue(all(r["raw_status"] == "fail" and r["raw_exit_code"] == 64 for r in rpm_results))
        self.assertTrue(all(r["policy"]["accepted"] is False for r in rpm_results))

        # Verify each of the 16 paths wrote qualification-record.json and publication-plan.json
        expected_products = [
            "theme-forge-stellar-loom",
            "theme-forge-stellar-burst",
            "theme-forge-solar-sail",
            "theme-forge-nebular-fusion",
        ]
        for prod in expected_products:
            # PyPI artifacts in scratch / prod
            pypi_dir = self.scratch / prod
            self.assertTrue((pypi_dir / "qualification-record.json").is_file())
            self.assertTrue((pypi_dir / "publication-plan.json").is_file())
            qrec_pypi = json.loads((pypi_dir / "qualification-record.json").read_bytes())
            plan_pypi = json.loads((pypi_dir / "publication-plan.json").read_bytes())
            self.assertEqual(qrec_pypi["gate"], "pypi.wheel-record")
            self.assertEqual(qrec_pypi["trust_root"], "hosted-candidate-unattested")
            self.assertEqual(qrec_pypi["commands"][0]["exit_code"], 0)
            self.assertEqual(plan_pypi["outcome"], "block")
            self.assertEqual(plan_pypi["reasons"], ["destination-disabled"])

            # Native artifacts in scratch / (family - prod)
            for family in ("deb", "rpm", "pacman"):
                native_dir = self.scratch / f"{family}-{prod}"
                self.assertTrue((native_dir / "qualification-record.json").is_file())
                self.assertTrue((native_dir / "publication-plan.json").is_file())
                qrec_native = json.loads((native_dir / "qualification-record.json").read_bytes())
                plan_native = json.loads((native_dir / "publication-plan.json").read_bytes())
                self.assertEqual(qrec_native["gate"], resolve_qualification_scope(family))
                self.assertEqual(qrec_native["trust_root"], "hosted-candidate-unattested")
                self.assertEqual(qrec_native["commands"][0]["exit_code"], 0)
                self.assertEqual(plan_native["outcome"], "block")
                self.assertEqual(plan_native["reasons"], ["destination-disabled"])

    def test_missing_candidate_custody_inputs(self):
        """Missing candidate custody inputs directory is explicitly recorded."""
        captures = self._build_captures()[:1]
        context = {
            "inputs": str(self.root / "nonexistent-dir"),
            "scratch": self.scratch,
            "captures": captures,
        }
        result = execute(context)
        self.assertIn("candidate-custody-inputs", result["details"]["missing_inputs"])
        self.assertEqual(result["gates"][0]["status"], "fail")

    def test_missing_wheel_custody_and_architecture_adverse_cases(self):
        """Missing wheel custody or architecture reported explicitly."""
        captures = self._build_captures()[:2]  # loom and burst
        # Empty inputs directory
        context = {
            "inputs": str(self.inputs),
            "scratch": self.scratch,
            "captures": captures,
        }
        result = execute(context)
        missing = result["details"]["missing_inputs"]
        self.assertIn("theme-forge-stellar-loom:wheel-custody", missing)
        self.assertIn("theme-forge-stellar-burst:wheel-custody", missing)

        # Populate partial wheel for burst (only 1 arch)
        whl_dir = self.inputs / "wheels"
        whl_dir.mkdir(parents=True, exist_ok=True)
        make_test_wheel(whl_dir, "theme-forge-stellar-burst", "0.6.1", "linux_x86_64")
        result2 = execute(context)
        missing2 = result2["details"]["missing_inputs"]
        self.assertIn("theme-forge-stellar-burst:wheel:linux_aarch64:custody", missing2)
        self.assertIn("theme-forge-stellar-burst:wheel:macosx_13_0_arm64:custody", missing2)

    def test_source_rpm_only_does_not_satisfy_presence(self):
        """Source RPM alone does not satisfy binary package presence and cannot be installable binary."""
        captures = self._build_captures()[:1]  # loom
        # Build wheel so PyPI passes
        whl_dir = self.inputs / "wheels"
        whl_dir.mkdir(parents=True, exist_ok=True)
        make_test_wheel(whl_dir, "theme-forge-stellar-loom", "0.4.0", "any")

        # Create RPM candidate with ONLY a source RPM in lane-work/unsigned-source
        rpm_cand = self.inputs / "candidate-rpm"
        rpm_cand.mkdir()
        srpm_dir = rpm_cand / "objects" / "lane-work" / "unsigned-source"
        srpm_dir.mkdir(parents=True)
        srpm_name = "theme-forge-stellar-loom-0.4.0-1.fc43.src.rpm"
        srpm_path = srpm_dir / srpm_name
        srpm_bytes = make_test_rpm("theme-forge-stellar-loom", "x86_64", is_source=True)
        srpm_path.write_bytes(srpm_bytes)
        srpm_sha = hashlib.sha256(srpm_bytes).hexdigest()
        srpm_size = len(srpm_bytes)

        repro = {"source_rpm": {"name": srpm_name, "sha256": srpm_sha, "size": srpm_size}}
        bm = {
            "project": "theme-forge-stellar-loom",
            "reproducibility": repro,
            "construction_witness": {"reproducibility": repro},
            "derivation": {"evidence": {"reproducibility": repro}},
        }
        build_raw = canonical(bm)
        (rpm_cand / "objects" / "build" / "theme-forge-stellar-loom").mkdir(parents=True)
        (rpm_cand / "objects" / "build" / "theme-forge-stellar-loom" / "rpm-manifest.json").write_bytes(build_raw)

        receipt = canonical({
            "schema": "rs9.hosted-candidate-diagnostic.v1alpha2",
            "lane": "rpm",
            "system": "x86_64-linux",
            "production_enabled": False,
            "publication_authority": False,
            "gates": [],
            "details": {"rpm_evidence_contract": CURRENT_RPM_EVIDENCE_CONTRACT, "rpm_lint_raw": {}, "rpm_lint_policy": {}},
        })
        (rpm_cand / "rpm-x86_64-linux.json").write_bytes(receipt)

        srpm_row = {
            "path": f"objects/lane-work/unsigned-source/{srpm_name}",
            "size": srpm_size,
            "sha256": srpm_sha,
            "kind": "custody",
            "role": "source-package-evidence",
            "promotion": "candidate-only",
        }
        build_row = {
            "path": "objects/build/theme-forge-stellar-loom/rpm-manifest.json",
            "size": len(build_raw),
            "sha256": hashlib.sha256(build_raw).hexdigest(),
            "kind": "evidence",
        }
        # verify predicate directly
        self.assertFalse(is_installable_binary(srpm_row))

        manifest = {
            "schema": "rs9.hosted-artifact-set.v1alpha2",
            "lane": "rpm",
            "system": "x86_64-linux",
            "production_enabled": False,
            "publication_authority": False,
            "runner": "ubuntu24",
            "files": [srpm_row, build_row],
            "qualification_receipt_hashes": {"rpm-x86_64-linux.json": hashlib.sha256(receipt).hexdigest()},
        }
        (rpm_cand / "artifact-manifest.json").write_bytes(canonical(manifest))

        context = {
            "inputs": str(self.inputs),
            "scratch": self.scratch,
            "captures": captures,
        }
        result = execute(context)
        missing = result["details"]["missing_inputs"]
        # Source-only does not satisfy binary presence:
        self.assertIn("rpm:theme-forge-stellar-loom:custody", missing)

    def test_unqualified_architecture_in_native_custody_raises(self):
        """Unqualified architecture in native custody raises CUSTODY_ARCHITECTURE with bounded error."""
        captures = self._build_captures()[:1]  # loom (expects 'all' for deb, 'noarch' for rpm)
        whl_dir = self.inputs / "wheels"
        whl_dir.mkdir(parents=True, exist_ok=True)
        make_test_wheel(whl_dir, "theme-forge-stellar-loom", "0.4.0", "any")

        deb_cand = self.inputs / "candidate-deb"
        deb_cand.mkdir(parents=True)
        (deb_cand / "objects" / "custody").mkdir(parents=True)
        # Give Loom an unqualified deb architecture: 'mips'
        fn = "theme-forge-stellar-loom_0.4.0-1_mips.deb"
        raw = make_xz_deb("./usr/bin/tool", b"#!/bin/sh\n")
        (deb_cand / "objects" / "custody" / fn).write_bytes(raw)
        receipt = canonical({"schema": "rs9.hosted-receipt.v1alpha1", "lane": "deb", "system": "all"})
        (deb_cand / "deb-all.json").write_bytes(receipt)
        manifest = {
            "schema": "rs9.hosted-artifact-set.v1alpha2",
            "lane": "deb",
            "system": "all",
            "production_enabled": False,
            "publication_authority": False,
            "runner": "ubuntu24",
            "files": [
                {
                    "path": f"objects/custody/{fn}",
                    "size": len(raw),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "kind": "custody",
                    "role": "binary-package",
                    "promotion": "candidate-only",
                }
            ],
            "qualification_receipt_hashes": {"deb-all.json": hashlib.sha256(receipt).hexdigest()},
        }
        (deb_cand / "artifact-manifest.json").write_bytes(canonical(manifest))

        context = {
            "inputs": str(self.inputs),
            "scratch": self.scratch,
            "captures": captures,
        }
        with self.assertRaises(FoundationExecutionError) as caught:
            execute(context)
        self.assertEqual(caught.exception.code, "CUSTODY_ARCHITECTURE")
        self.assertEqual(caught.exception.substage, "architecture")
        self.assertEqual(caught.exception.product, "theme-forge-stellar-loom")
        self.assertEqual(caught.exception.adapter, "apt")

    def test_earlier_evidence_retained_on_later_failure(self):
        """When an earlier product succeeds and a later product fails, prior records are retained."""
        captures = self._build_captures()[:3]  # loom, burst, solar-sail
        # Populate wheels for loom and burst, but corrupt solar-sail wheel RECORD
        whl_dir = self.inputs / "wheels"
        whl_dir.mkdir(parents=True, exist_ok=True)
        make_test_wheel(whl_dir, "theme-forge-stellar-loom", "0.4.0", "any")
        for tag in ("linux_x86_64", "linux_aarch64", "macosx_13_0_arm64"):
            make_test_wheel(whl_dir, "theme-forge-stellar-burst", "0.6.1", tag)

        # Corrupted solar-sail wheel: invalid content mismatching RECORD
        corrupted_whl = whl_dir / "theme_forge_solar_sail-0.2.1-py3-none-any.whl"
        corrupted_whl.write_bytes(b"PK\x03\x04corrupted-wheel-data")

        context = {
            "inputs": str(self.inputs),
            "scratch": self.scratch,
            "captures": captures,
        }
        with self.assertRaises(FoundationExecutionError) as caught:
            execute(context)

        # 1. Caught exception contains bounded details and partial result
        exc = caught.exception
        self.assertEqual(exc.product, "theme-forge-solar-sail")
        self.assertEqual(exc.adapter, "pypi")
        self.assertIsNotNone(exc.partial_result)

        # Prior records for loom and burst must be retained in partial_result
        partial_records = exc.partial_result["details"]["records"]
        self.assertEqual(len(partial_records), 2)
        self.assertEqual(partial_records[0]["project"], "theme-forge-stellar-loom")
        self.assertEqual(partial_records[0]["adapter"], "pypi")
        self.assertEqual(partial_records[1]["project"], "theme-forge-stellar-burst")
        self.assertEqual(partial_records[1]["adapter"], "pypi")

        # 2. Retained foundation3.json on disk must also retain prior records
        foundation3_doc = json.loads((self.scratch / "foundation3.json").read_bytes())
        self.assertEqual(len(foundation3_doc["qualification_records"]), 2)
        self.assertEqual(len(foundation3_doc["failed_records"]), 1)
        self.assertEqual(foundation3_doc["failed_records"][0]["product"], "theme-forge-solar-sail")
        self.assertEqual(foundation3_doc["failed_records"][0]["adapter"], "pypi")

    def test_package_roles_verification_and_effective_role(self):
        """Strict package roles are verified across custody manifests and historical diagnostics."""
        from rs9.package_roles import effective_role

        # 1. is_installable_binary requires binary-package role and nonfixture
        valid_binary_row = {"kind": "custody", "role": "binary-package", "promotion": "candidate-only", "path": "objects/custody/pkg.deb"}
        self.assertTrue(is_installable_binary(valid_binary_row))

        source_row = {"kind": "custody", "role": "source-package-evidence", "promotion": "candidate-only", "path": "objects/unsigned-source/pkg.src.rpm"}
        self.assertFalse(is_installable_binary(source_row))

        fixture_row = {"kind": "custody", "role": "binary-package", "promotion": "fixture-test-only", "path": "objects/custody/pkg.deb"}
        self.assertFalse(is_installable_binary(fixture_row))

        unclassified_row = {"kind": "custody", "role": "unclassified-package", "promotion": "candidate-only", "path": "objects/custody/pkg.deb"}
        self.assertFalse(is_installable_binary(unclassified_row))

        # 2. effective_role for historical diagnostics
        self.assertEqual(effective_role("rpm", valid_binary_row), "binary-package")
        self.assertEqual(effective_role("rpm", source_row), "source-package-evidence")
        self.assertEqual(effective_role("deb", {"kind": "evidence", "path": "diag.json"}), "unclassified-package")

    def test_adverse_unknown_adapter(self):
        """Unknown native packaging identifier fails closed with UNKNOWN_ADAPTER."""
        for bad in ("unknown", "invented", "invalid", "pypi", ""):
            with self.subTest(bad=bad), self.assertRaises(ContractError) as caught:
                get_native_packaging_mapping(bad)
            self.assertEqual(caught.exception.code, "UNKNOWN_ADAPTER")

            with self.assertRaises(ContractError) as caught:
                resolve_canonical_publication_adapter(bad)
            self.assertEqual(caught.exception.code, "UNKNOWN_ADAPTER")

            with self.assertRaises(ContractError) as caught:
                resolve_qualification_gate(bad)
            self.assertEqual(caught.exception.code, "UNKNOWN_ADAPTER")

            with self.assertRaises(ContractError) as caught:
                resolve_qualification_scope(bad)
            self.assertEqual(caught.exception.code, "UNKNOWN_ADAPTER")

        with self.assertRaises(ContractError) as caught:
            mandatory_gates({"runtime": {"kind": "cli"}}, "unknown-adapter")
        self.assertEqual(caught.exception.code, "ADAPTER_GATES")

    def test_adverse_role_type_mismatch(self):
        """Role and binary header ARCH mismatch fails verify_package_roles, excluded from selection, assembly fails."""
        captures = self._build_captures()[:1]  # loom
        whl_dir = self.inputs / "wheels"
        whl_dir.mkdir(parents=True, exist_ok=True)
        make_test_wheel(whl_dir, "theme-forge-stellar-loom", "0.4.0", "any")

        rpm_cand = self.inputs / "candidate-rpm"
        rpm_cand.mkdir()
        (rpm_cand / "objects" / "custody").mkdir(parents=True)
        # Create an RPM file with arch 'aarch64' in headers, but filename claims 'x86_64'
        fn = "theme-forge-stellar-loom-0.4.0-1.fc43.x86_64.rpm"
        raw = make_test_rpm("theme-forge-stellar-loom", "aarch64")  # header arch mismatch!
        (rpm_cand / "objects" / "custody" / fn).write_bytes(raw)

        receipt = canonical({
            "schema": "rs9.hosted-candidate-diagnostic.v1alpha2",
            "lane": "rpm",
            "system": "x86_64-linux",
            "production_enabled": False,
            "publication_authority": False,
            "gates": [],
            "details": {"rpm_evidence_contract": CURRENT_RPM_EVIDENCE_CONTRACT, "rpm_lint_raw": {}, "rpm_lint_policy": {}},
        })
        (rpm_cand / "rpm-x86_64-linux.json").write_bytes(receipt)
        manifest = {
            "schema": "rs9.hosted-artifact-set.v1alpha2",
            "lane": "rpm",
            "system": "x86_64-linux",
            "production_enabled": False,
            "publication_authority": False,
            "runner": "ubuntu24",
            "files": [
                {
                    "path": f"objects/custody/{fn}",
                    "size": len(raw),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "kind": "custody",
                    "role": "binary-package",
                    "promotion": "candidate-only",
                }
            ],
            "qualification_receipt_hashes": {"rpm-x86_64-linux.json": hashlib.sha256(receipt).hexdigest()},
        }
        (rpm_cand / "artifact-manifest.json").write_bytes(canonical(manifest))

        context = {
            "inputs": str(self.inputs),
            "scratch": self.scratch,
            "captures": captures,
        }
        result = execute(context)
        missing = result["details"]["missing_inputs"]
        self.assertIn("package-roles-invalid:CUSTODY_ARCHITECTURE", missing)
        self.assertIn("rpm:theme-forge-stellar-loom:custody", missing)
        self.assertEqual(result["gates"][0]["status"], "fail")
        self.assertEqual(result["gates"][0]["reason"], "missing-custody-inputs")

    def test_adverse_destination_binding_absent_and_ambiguous_targets(self):
        """Destination binding preserves LIVE1 target IDs and raises OUTPUT_BINDING when absent/ambiguous."""
        capture, intent, _ = self._build_captures()[0]
        payloads = {p["name"]: p["sha256"] for p in (capture.record.get("payloads") or capture.record.get("assets") or [])}

        # 1. Preserves real destination ID kfa-apt
        intent_valid = dict(intent)
        intent_valid["targets"] = [
            {"adapter": "apt", "destination": "kfa-apt", "name": "theme-forge-stellar-loom", "mode": "direct"},
            {"adapter": "dnf", "destination": "kfa-rpm", "name": "theme-forge-stellar-loom", "mode": "direct"},
            {"adapter": "pacman", "destination": "kfa-pacman", "name": "theme-forge-stellar-loom", "mode": "direct"},
        ]
        dest_apt, _, _ = resolve_destination_binding(
            intent_valid, capture, "apt", "deb", "theme-forge-stellar-loom", {}, payloads
        )
        self.assertEqual(dest_apt["id"], "kfa-apt")
        self.assertEqual(dest_apt["adapter"], "apt")

        dest_dnf, _, _ = resolve_destination_binding(
            intent_valid, capture, "dnf", "rpm", "theme-forge-stellar-loom", {}, payloads
        )
        self.assertEqual(dest_dnf["id"], "kfa-rpm")
        self.assertEqual(dest_dnf["adapter"], "dnf")

        dest_pac, _, _ = resolve_destination_binding(
            intent_valid, capture, "pacman", "pacman", "theme-forge-stellar-loom", {}, payloads
        )
        self.assertEqual(dest_pac["id"], "kfa-pacman")
        self.assertEqual(dest_pac["adapter"], "pacman")

        # 2. Absent target when targets list is present
        intent_absent = dict(intent)
        intent_absent["targets"] = [
            {"adapter": "dnf", "destination": "kfa-rpm", "name": "theme-forge-stellar-loom", "mode": "direct"},
        ]
        with self.assertRaises(ContractError) as caught_absent:
            resolve_destination_binding(intent_absent, capture, "apt", "deb", "theme-forge-stellar-loom", {}, payloads)
        self.assertEqual(caught_absent.exception.code, "OUTPUT_BINDING")

        # 3. Ambiguous multiple targets for adapter
        intent_ambiguous = dict(intent)
        intent_ambiguous["targets"] = [
            {"adapter": "apt", "destination": "kfa-apt-1", "name": "theme-forge-stellar-loom", "mode": "direct"},
            {"adapter": "apt", "destination": "kfa-apt-2", "name": "theme-forge-stellar-loom", "mode": "direct"},
        ]
        with self.assertRaises(ContractError) as caught_ambiguous:
            resolve_destination_binding(intent_ambiguous, capture, "apt", "deb", "theme-forge-stellar-loom", {}, payloads)
        self.assertEqual(caught_ambiguous.exception.code, "OUTPUT_BINDING")

    def test_raise_on_error_false_returns_normal_failed_result(self):
        """When raise_on_error=False, execute returns partial_result with failed gates, bounded error, and retains artifacts."""
        captures = self._build_captures()[:1]
        whl_dir = self.inputs / "wheels"
        whl_dir.mkdir(parents=True, exist_ok=True)
        # Corrupted wheel file
        bad_whl = whl_dir / "theme_forge_stellar_loom-0.4.0-py3-none-any.whl"
        bad_whl.write_bytes(b"corrupt-wheel-bytes")

        context = {
            "inputs": str(self.inputs),
            "scratch": self.scratch,
            "captures": captures,
            "raise_on_error": False,
        }
        result = execute(context)
        self.assertEqual(result["gates"][0]["status"], "fail")
        self.assertEqual(result["gates"][1]["status"], "fail")
        self.assertIn("failed_records", result["details"])
        failed = result["details"]["failed_records"]
        self.assertEqual(len(failed), 1)
        self.assertEqual(failed[0]["product"], "theme-forge-stellar-loom")
        self.assertEqual(failed[0]["adapter"], "pypi")
        self.assertEqual(failed[0]["substage"], "qualification")
        self.assertTrue((self.scratch / "foundation3.json").is_file())


if __name__ == "__main__":
    unittest.main()
