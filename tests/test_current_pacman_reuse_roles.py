"""Raw reuse roles never confer construction or fixture promotion."""
import unittest
from rs9.current_generation import CURRENT_GENERATION, HISTORICAL_GENERATION
from rs9.errors import ContractError
from rs9.package_roles import (producer_role, validate_role_declarations, is_installable_binary,
                               RAW_REUSE_REPLICA, BINARY_PACKAGE, FIXTURE_SIGNED_COPY, UNCLASSIFIED_PACKAGE)

NAME = "theme-forge-stellar-loom-0.5.0-1-any.pkg.tar.zst"


class CurrentPacmanReuseRoleTests(unittest.TestCase):
    def manifest(self, path, role=RAW_REUSE_REPLICA, generation=CURRENT_GENERATION, system="aarch64-linux", promotion="candidate-only"):
        return {"generation":generation, "system":system, "lane":"pacman",
                "files":[{"path":path, "role":role, "kind":"custody", "promotion":promotion}]}

    def test_only_current_arm_declared_raw_replica_paths_have_reuse_role(self):
        for directory in ("canonical-any/files",):
            path = "objects/lane-work/" + directory + "/" + NAME
            manifest = self.manifest(path)
            self.assertEqual(validate_role_declarations(manifest)[path], RAW_REUSE_REPLICA)
            self.assertFalse(is_installable_binary(manifest["files"][0]))
            self.assertEqual(producer_role("pacman", path, generation=CURRENT_GENERATION, system="aarch64-linux"), RAW_REUSE_REPLICA)

    def test_unsigned_arm_any_second_construction_is_refused(self):
        path = "objects/lane-work/unsigned/" + NAME
        self.assertEqual(producer_role("pacman", path, generation=CURRENT_GENERATION, system="aarch64-linux"), UNCLASSIFIED_PACKAGE)
        with self.assertRaises(ContractError):
            validate_role_declarations(self.manifest(path, role=BINARY_PACKAGE))

    def test_fixture_copy_cannot_be_promoted_to_raw_reuse_or_binary(self):
        path = "objects/lane-work/pacman/aarch64/" + NAME
        manifest = self.manifest(path, role=FIXTURE_SIGNED_COPY, promotion="fixture-test-only")
        self.assertEqual(validate_role_declarations(manifest)[path], FIXTURE_SIGNED_COPY)
        self.assertFalse(is_installable_binary(manifest["files"][0]))
        for role in (BINARY_PACKAGE, RAW_REUSE_REPLICA):
            with self.subTest(role=role), self.assertRaises(ContractError):
                validate_role_declarations(self.manifest(path, role=role))

    def test_reuse_role_cannot_claim_x64_historical_or_other_product(self):
        path = "objects/lane-work/canonical-any/files/" + NAME
        for generation, system in ((HISTORICAL_GENERATION,"aarch64-linux"), (CURRENT_GENERATION,"x86_64-linux")):
            with self.subTest(generation=generation,system=system), self.assertRaises(ContractError):
                validate_role_declarations(self.manifest(path,generation=generation,system=system))
        with self.assertRaises(ContractError):
            validate_role_declarations(self.manifest(path.replace("stellar-loom-0.5.0","stellar-burst-0.7.0")))

    def test_x64_and_historical_constructor_roles_preserved(self):
        for generation in (HISTORICAL_GENERATION,CURRENT_GENERATION):
            for directory in ("unsigned","unsigned-custody"):
                path = "objects/lane-work/" + directory + "/" + NAME
                self.assertEqual(producer_role("pacman",path,generation=generation,system="x86_64-linux"), BINARY_PACKAGE)
