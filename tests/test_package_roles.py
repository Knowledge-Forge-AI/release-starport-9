"""Tests for shared package roles, producer retention, and header verification."""

import copy
import json
from pathlib import Path
import struct
import tempfile
import unittest

from rs9.errors import ContractError
from rs9.package_roles import (
    BINARY_PACKAGE,
    SOURCE_PACKAGE_EVIDENCE,
    FIXTURE_SIGNED_COPY,
    UNCLASSIFIED_PACKAGE,
    producer_role,
    effective_role,
    is_installable_binary,
    verify_package_roles,
)
from rs9.rpm_header import RPM_LEAD_MAGIC, RPM_HEADER_MAGIC


def _make_synthetic_rpm(
    name: str = "test-pkg",
    arch: str = "noarch",
    version: str = "1.0.0",
    release: str = "1.fc43",
    is_source: bool = False,
    sourcerpm: str | None = None,
    payload: bytes = b"rpm-payload-data",
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


class PackageRolesTests(unittest.TestCase):
    def test_unknown_format_and_source_suffix_never_become_binaries(self):
        self.assertEqual(producer_role("rpm", "unsigned/pkg.nosrc.rpm"), UNCLASSIFIED_PACKAGE)
        self.assertEqual(producer_role("rpm", "unsigned/pkg.deb"), UNCLASSIFIED_PACKAGE)
        self.assertFalse(is_installable_binary({"kind": "custody", "role": BINARY_PACKAGE,
                                               "path": "unsigned/pkg.nosrc.rpm"}))

    def test_native_binary_header_architecture_cannot_hide_behind_filename(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "unsigned/pkg-1.0.0-1.fc43.x86_64.rpm"
            path.parent.mkdir()
            path.write_bytes(_make_synthetic_rpm("pkg", arch="aarch64"))
            manifest = {"lane": "rpm", "files": [{"path": path.relative_to(root).as_posix(),
                "kind": "custody", "role": BINARY_PACKAGE, "promotion": "candidate-only"}]}
            with self.assertRaises(ContractError) as caught:
                verify_package_roles(root, manifest)
            self.assertEqual(caught.exception.code, "CUSTODY_ARCHITECTURE")

    def test_producer_role_pinned_source_rpm(self):
        # Pinned source RPM paths
        self.assertEqual(
            producer_role("rpm", "lane-work/unsigned-source/theme-forge-stellar-loom-0.4.0-1.fc43.src.rpm"),
            SOURCE_PACKAGE_EVIDENCE,
        )
        self.assertEqual(
            producer_role("rpm", "objects/lane-work/unsigned-source/theme-forge-solar-sail-0.2.1-1.fc43.src.rpm"),
            SOURCE_PACKAGE_EVIDENCE,
        )
        self.assertEqual(
            producer_role("rpm", "unsigned-source/theme-forge-solar-sail-0.2.1-1.fc43.src.rpm"),
            UNCLASSIFIED_PACKAGE,
        )

        # Unpinned source RPM paths must fail closed as unclassified
        self.assertEqual(
            producer_role("rpm", "unsigned/theme-forge-stellar-loom-0.4.0-1.fc43.src.rpm"),
            UNCLASSIFIED_PACKAGE,
        )
        self.assertEqual(
            producer_role("rpm", "other-dir/theme-forge-stellar-loom-0.4.0-1.fc43.src.rpm"),
            UNCLASSIFIED_PACKAGE,
        )
        self.assertEqual(
            producer_role("deb", "lane-work/unsigned-source/theme-forge-stellar-loom-0.4.0-1.fc43.src.rpm"),
            UNCLASSIFIED_PACKAGE,
        )
        self.assertEqual(
            producer_role("rpm", "unsigned-source/not-an-rpm.txt"),
            UNCLASSIFIED_PACKAGE,
        )
        self.assertEqual(
            producer_role("rpm", "unsigned-source/theme-forge-stellar-loom-0.4.0-1.fc43.rpm"),
            UNCLASSIFIED_PACKAGE,
        )

    def test_producer_role_binary_and_fixture(self):
        self.assertEqual(
            producer_role("rpm", "lane-work/quarantine/theme-forge-stellar-burst-0.6.1-1.fc43.x86_64.rpm"),
            BINARY_PACKAGE,
        )
        self.assertEqual(
            producer_role("rpm", "signed/unsigned-name-0.6.1-1.fc43.x86_64.rpm"),
            FIXTURE_SIGNED_COPY,
        )
        # Binary packages in unsigned
        self.assertEqual(
            producer_role("rpm", "lane-work/unsigned/theme-forge-stellar-burst-0.6.1-1.fc43.x86_64.rpm"),
            BINARY_PACKAGE,
        )
        self.assertEqual(
            producer_role("rpm", "unsigned/theme-forge-stellar-burst-0.6.1-1.fc43.x86_64.rpm"),
            BINARY_PACKAGE,
        )
        self.assertEqual(
            producer_role("deb", "lane-work/unsigned/theme-forge-stellar-burst_0.6.1_amd64.deb"),
            BINARY_PACKAGE,
        )
        self.assertEqual(
            producer_role("pacman", "unsigned/theme-forge-stellar-burst-0.6.1-1-x86_64.pkg.tar.zst"),
            BINARY_PACKAGE,
        )
        self.assertEqual(
            producer_role("wheels", "unsigned/theme_forge_stellar_burst-0.6.1-py3-none-any.whl"),
            BINARY_PACKAGE,
        )

        # Bare package filename is never fixture-reclassified
        self.assertEqual(
            producer_role("rpm", "theme-forge-stellar-burst-0.6.1-1.fc43.x86_64.rpm"),
            BINARY_PACKAGE,
        )

        # Fixture copies (outside unsigned and custody, with directory parts)
        self.assertEqual(
            producer_role("rpm", "signed/theme-forge-stellar-burst-0.6.1-1.fc43.x86_64.rpm"),
            FIXTURE_SIGNED_COPY,
        )
        self.assertEqual(
            producer_role("pacman", "fixtures/theme-forge-stellar-burst-0.6.1-1-x86_64.pkg.tar.zst"),
            FIXTURE_SIGNED_COPY,
        )

        # Unknown lane or non-package
        self.assertEqual(producer_role("unknown-lane", "unsigned/pkg.rpm"), UNCLASSIFIED_PACKAGE)
        self.assertEqual(producer_role("rpm", "unsigned/report.json"), UNCLASSIFIED_PACKAGE)

    def test_effective_role_historical_diagnostic_only(self):
        # Explicit role takes precedence
        self.assertEqual(effective_role("rpm", {"role": BINARY_PACKAGE}), BINARY_PACKAGE)
        self.assertEqual(effective_role("rpm", {"role": SOURCE_PACKAGE_EVIDENCE}), SOURCE_PACKAGE_EVIDENCE)
        self.assertEqual(effective_role("rpm", {"role": "invalid-role"}), UNCLASSIFIED_PACKAGE)

        # Historical row without role: inferred for diagnostics only
        row_src = {
            "kind": "custody",
            "path": "objects/lane-work/unsigned-source/theme-forge-solar-sail-0.2.1-1.fc43.src.rpm",
            "promotion": "candidate-only",
        }
        self.assertEqual(effective_role("rpm", row_src), SOURCE_PACKAGE_EVIDENCE)

        row_bin = {
            "kind": "custody",
            "path": "objects/lane-work/unsigned/theme-forge-solar-sail-0.2.1-1.fc43.noarch.rpm",
            "promotion": "candidate-only",
        }
        self.assertEqual(effective_role("rpm", row_bin), BINARY_PACKAGE)

        row_fixture = {
            "kind": "custody",
            "path": "objects/signed/theme-forge-solar-sail-0.2.1-1.fc43.noarch.rpm",
            "promotion": "fixture-test-only",
        }
        self.assertEqual(effective_role("rpm", row_fixture), FIXTURE_SIGNED_COPY)

        # Non-custody row
        self.assertEqual(effective_role("rpm", {"kind": "evidence", "path": "objects/diag.json"}), UNCLASSIFIED_PACKAGE)

    def test_is_installable_binary_predicate(self):
        # Valid installable binary: explicit verified role, custody, nonfixture
        valid_row = {
            "kind": "custody",
            "role": BINARY_PACKAGE,
            "promotion": "candidate-only",
            "path": "objects/unsigned/theme-forge-stellar-burst-0.6.1-1.fc43.x86_64.rpm",
        }
        self.assertTrue(is_installable_binary(valid_row))

        # Source RPM is never installable binary
        source_row = {
            "kind": "custody",
            "role": SOURCE_PACKAGE_EVIDENCE,
            "promotion": "candidate-only",
            "path": "objects/lane-work/unsigned-source/theme-forge-solar-sail-0.2.1-1.fc43.src.rpm",
        }
        self.assertFalse(is_installable_binary(source_row))

        # Fixture copy is never installable binary
        fixture_row = {
            "kind": "custody",
            "role": FIXTURE_SIGNED_COPY,
            "promotion": "fixture-test-only",
            "path": "objects/signed/theme-forge-stellar-burst-0.6.1-1.fc43.x86_64.rpm",
        }
        self.assertFalse(is_installable_binary(fixture_row))

        # Historical row without role NEVER has current authority
        historical_row = {
            "kind": "custody",
            "promotion": "candidate-only",
            "path": "objects/unsigned/theme-forge-stellar-burst-0.6.1-1.fc43.x86_64.rpm",
        }
        self.assertFalse(is_installable_binary(historical_row))

        # Non-custody row
        evidence_row = {"kind": "evidence", "role": BINARY_PACKAGE, "promotion": "candidate-only"}
        self.assertFalse(is_installable_binary(evidence_row))

        # Suffix .src.rpm even if misdeclared
        misdeclared = {
            "kind": "custody",
            "role": BINARY_PACKAGE,
            "promotion": "candidate-only",
            "path": "objects/unsigned/foo.src.rpm",
        }
        self.assertFalse(is_installable_binary(misdeclared))

    def test_verify_package_roles_bounded_rpm_verification(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bin_dir = root / "objects/unsigned"
            src_dir = root / "objects/lane-work/unsigned-source"
            bin_dir.mkdir(parents=True, exist_ok=True)
            src_dir.mkdir(parents=True, exist_ok=True)

            bin_path = bin_dir / "theme-forge-stellar-burst-0.6.1-1.fc43.x86_64.rpm"
            src_path = src_dir / "theme-forge-stellar-loom-0.4.0-1.fc43.src.rpm"

            bin_bytes = _make_synthetic_rpm(
                "theme-forge-stellar-burst", arch="x86_64", is_source=False, payload=b"X" * 1024
            )
            src_bytes = _make_synthetic_rpm(
                "theme-forge-stellar-loom", arch="src", is_source=True, payload=b"Y" * 1024
            )

            bin_path.write_bytes(bin_bytes)
            src_path.write_bytes(src_bytes)

            manifest = {
                "lane": "rpm",
                "files": [
                    {
                        "path": bin_path.relative_to(root).as_posix(),
                        "kind": "custody",
                        "role": BINARY_PACKAGE,
                        "promotion": "candidate-only",
                        "size": len(bin_bytes),
                    },
                    {
                        "path": src_path.relative_to(root).as_posix(),
                        "kind": "custody",
                        "role": SOURCE_PACKAGE_EVIDENCE,
                        "promotion": "candidate-only",
                        "size": len(src_bytes),
                    },
                ],
            }

            from rs9.release_core import digest
            manifest["files"][1]["sha256"] = digest(src_bytes)
            build = root / "objects/lane-work/build/theme-forge-stellar-loom/rpm-manifest.json"
            build.parent.mkdir(parents=True)
            build.write_text(json.dumps({"project": "theme-forge-stellar-loom", "reproducibility": {
                "source_rpm": {"name": src_path.name, "sha256": digest(src_bytes), "size": len(src_bytes)}}}))
            manifest["files"].append({"path": build.relative_to(root).as_posix(), "kind": "evidence"})
            result = verify_package_roles(root, manifest)
            self.assertEqual(len(result["verified_roles"]), 2)

    def test_verify_package_roles_wrong_arch_binary_cannot_declare_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src_dir = root / "objects/lane-work/unsigned-source"
            src_dir.mkdir(parents=True, exist_ok=True)

            # An x86_64 binary RPM written with .src.rpm name into unsigned-source
            fake_src = src_dir / "theme-forge-stellar-burst-0.6.1-1.fc43.src.rpm"
            binary_bytes = _make_synthetic_rpm("theme-forge-stellar-burst", arch="x86_64", is_source=False)
            fake_src.write_bytes(binary_bytes)

            manifest = {
                "lane": "rpm",
                "files": [
                    {
                        "path": fake_src.relative_to(root).as_posix(),
                        "kind": "custody",
                        "role": SOURCE_PACKAGE_EVIDENCE,
                        "promotion": "candidate-only",
                        "size": len(binary_bytes),
                    }
                ],
            }

            with self.assertRaises(ContractError) as caught:
                verify_package_roles(root, manifest)
            self.assertEqual(caught.exception.code, "CUSTODY_ROLE")

    def test_verify_package_roles_role_mismatch_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bin_dir = root / "objects/unsigned"
            bin_dir.mkdir(parents=True, exist_ok=True)

            bin_path = bin_dir / "pkg-0.1.0-1.fc43.x86_64.rpm"
            bin_path.write_bytes(_make_synthetic_rpm("pkg", arch="x86_64", is_source=False))

            # Claims source-package-evidence for unsigned/ binary path
            manifest = {
                "lane": "rpm",
                "files": [
                    {
                        "path": bin_path.relative_to(root).as_posix(),
                        "kind": "custody",
                        "role": SOURCE_PACKAGE_EVIDENCE,
                        "promotion": "candidate-only",
                    }
                ],
            }
            with self.assertRaises(ContractError) as caught:
                verify_package_roles(root, manifest)
            self.assertEqual(caught.exception.code, "CUSTODY_ROLE")

    def test_verify_package_roles_malformed_package_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bin_dir = root / "objects/unsigned"
            bin_dir.mkdir(parents=True, exist_ok=True)

            bin_path = bin_dir / "corrupted-pkg-0.1.0-1.fc43.x86_64.rpm"
            bin_path.write_bytes(b"not-an-rpm-header-corrupted-bytes")

            manifest = {
                "lane": "rpm",
                "files": [
                    {
                        "path": bin_path.relative_to(root).as_posix(),
                        "kind": "custody",
                        "role": BINARY_PACKAGE,
                        "promotion": "candidate-only",
                    }
                ],
            }
            with self.assertRaises(ContractError) as caught:
                verify_package_roles(root, manifest)
            self.assertEqual(caught.exception.code, "CUSTODY_ROLE")

    def test_verify_package_roles_missing_explicit_role_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bin_dir = root / "objects/unsigned"
            bin_dir.mkdir(parents=True, exist_ok=True)

            bin_path = bin_dir / "pkg-0.1.0-1.fc43.x86_64.rpm"
            bin_path.write_bytes(_make_synthetic_rpm("pkg", arch="x86_64", is_source=False))

            # Missing "role" in custody row
            manifest = {
                "lane": "rpm",
                "files": [
                    {
                        "path": bin_path.relative_to(root).as_posix(),
                        "kind": "custody",
                        "promotion": "candidate-only",
                    }
                ],
            }
            with self.assertRaises(ContractError) as caught:
                verify_package_roles(root, manifest)
            self.assertEqual(caught.exception.code, "CUSTODY_ROLE")

    def test_verify_package_roles_declared_source_rpm_binding(self):
        from rs9.release_core import digest
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_dir = root / "objects/lane-work/build/theme-forge-stellar-loom"
            src_dir = root / "objects/lane-work/unsigned-source"
            build_dir.mkdir(parents=True, exist_ok=True)
            src_dir.mkdir(parents=True, exist_ok=True)

            src_path = src_dir / "theme-forge-stellar-loom-0.4.0-1.fc43.src.rpm"
            src_bytes = _make_synthetic_rpm("theme-forge-stellar-loom", arch="src", is_source=True)
            src_path.write_bytes(src_bytes)
            srpm_hash = digest(src_bytes)

            build_manifest = {
                "schema": "rs9.rpm-candidate.v1alpha2",
                "project": "theme-forge-stellar-loom",
                "construction_witness": {
                    "reproducibility": {
                        "source_rpm": {
                            "name": src_path.name,
                            "sha256": srpm_hash,
                            "size": len(src_bytes),
                        }
                    }
                },
            }
            bm_path = build_dir / "rpm-manifest.json"
            bm_path.write_text(json.dumps(build_manifest))

            manifest = {
                "lane": "rpm",
                "files": [
                    {
                        "path": bm_path.relative_to(root).as_posix(),
                        "kind": "evidence",
                        "size": bm_path.stat().st_size,
                        "sha256": digest(bm_path.read_bytes()),
                    },
                    {
                        "path": src_path.relative_to(root).as_posix(),
                        "kind": "custody",
                        "role": SOURCE_PACKAGE_EVIDENCE,
                        "promotion": "candidate-only",
                        "size": len(src_bytes),
                        "sha256": srpm_hash,
                    },
                ],
            }

            # Should succeed with matching source RPM
            res = verify_package_roles(root, manifest)
            self.assertIn(src_path.name, res["declared_sources"])

            # Changed hash fails closed
            bad_hash_manifest = copy.deepcopy(manifest)
            bad_hash_manifest["files"][1]["sha256"] = "0" * 64
            with self.assertRaises(ContractError) as caught:
                verify_package_roles(root, bad_hash_manifest)
            self.assertEqual(caught.exception.code, "CUSTODY_SOURCE_EVIDENCE")

            # Missing source RPM fails closed
            missing_src_manifest = copy.deepcopy(manifest)
            missing_src_manifest["files"] = [missing_src_manifest["files"][0]]
            with self.assertRaises(ContractError) as caught:
                verify_package_roles(root, missing_src_manifest)
            self.assertEqual(caught.exception.code, "CUSTODY_SOURCE_EVIDENCE")


if __name__ == "__main__":
    unittest.main()
