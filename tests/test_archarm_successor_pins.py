"""Pure exact-identity checks for the admitted ArchARM successor pin profile.

These tests read only public pin/key bytes.  They do not invoke GPG, Docker,
network transports, Git, or any protected fixture state.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import shutil
import tempfile
import unittest

from rs9._archarm_support import origin
from rs9._archarm_support import pins as historical
from rs9._archarm_support import successor_20261109 as successor
from rs9._archarm_support.refusal import SdkRefusal


class SuccessorPinsTest(unittest.TestCase):
    def assertPinFile(self, loader, root):
        with self.assertRaises(SdkRefusal) as caught:
            loader(root)
        self.assertEqual(caught.exception.label, "PIN_FILE")

    def copy_pin_dir(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name) / "pins"
        shutil.copytree(historical.PIN_DIR, root)
        return root

    def test_historical_loader_and_origin_remain_byte_exact(self):
        bundle = historical.load_qualified_pins()
        self.assertTrue(bundle.qualified)
        self.assertEqual(bundle.expect["packageBytes"], historical.REAL_EXPECT["packageBytes"])
        self.assertEqual(bundle.digests["packagePinsSha256"],
                         "53c812397e73cdb16c80cd5cd72b6ed66889817d8aa79b075034434895da2987")
        self.assertEqual(origin.ORIGIN_FILES["PACKAGE-PINS.json"]["sha256"],
                         "53c812397e73cdb16c80cd5cd72b6ed66889817d8aa79b075034434895da2987")
        self.assertEqual(origin.ORIGIN_FILES["ROOTFS-PIN.json"]["sha256"], successor.INPUTS["rootfs_pin_sha256"])
        self.assertFalse(origin.MODULE_NATIVE_QUALIFIED)

    def test_successor_profile_and_public_proof_are_immutable(self):
        self.assertEqual(successor.PROFILE, "successor-20261109")
        self.assertEqual(successor.EXPECT["packageCount"], 139)
        self.assertEqual(successor.EXPECT["packageBytes"], 201488096)
        self.assertEqual(successor.INPUTS["qualified_probe_run"], 42653433050)
        self.assertEqual(successor.INPUTS["qualified_source"],
                         "0407736e2cf542a25cf521a45fbe95f11f30ccb6")
        self.assertEqual(successor.PROOF["workflow_sha256"],
                         "ada652d68d4ee9108f80469358729528b9ec83a09855badac1d20b544c01dd54")
        self.assertEqual(successor.PROOF["controller_sha256"],
                         "4a08a35b6fb2cb3f1c88fa4329362676982f38281ea9c3be74eb5d6cb0b6f4cb")
        self.assertFalse(successor.PROOF["assertions"]["moduleNativeQualified"])
        self.assertFalse(successor.PROOF["assertions"]["productQualification"])
        with self.assertRaises(TypeError):
            successor.INPUTS["package_pins_sha256"] = "0" * 64
        with self.assertRaises(TypeError):
            successor.PROOF["run_id"] = 1
        with self.assertRaises(TypeError):
            successor.PROOF["digests"]["packagePinsSha256"] = "0" * 64

    def test_successor_loader_reuses_historical_rootfs_and_certificate(self):
        bundle = successor.load_successor_pins()
        self.assertTrue(bundle.qualified)
        self.assertEqual(len(bundle.packages), 139)
        self.assertEqual(bundle.expect["packageBytes"], 201488096)
        self.assertEqual(bundle.digests, {
            "rootfsSha256": successor.INPUTS["rootfs_sha256"],
            "rootfsPinSha256": successor.INPUTS["rootfs_pin_sha256"],
            "packagePinsSha256": successor.INPUTS["package_pins_sha256"],
            "publicKeySha256": "4e4202772328674af68f90f675e077d192337fc8ced15cddcd35875a9de5b5f9",
            "publicKeyFingerprint": "68B3537F39A313B3E574D06777193F152BDBE6A6",
        })
        package_path = Path(historical.PIN_DIR) / successor.PACKAGE_PINS_NAME
        self.assertEqual(package_path.stat().st_size, 78588)
        self.assertEqual(hashlib.sha256(package_path.read_bytes()).hexdigest(),
                         successor.INPUTS["package_pins_sha256"])
        self.assertEqual(bundle.certificate.name, historical.CERT_NAME)

    def test_missing_wrong_and_cross_profile_files_refuse(self):
        root = self.copy_pin_dir()
        successor_path = root / successor.PACKAGE_PINS_NAME
        successor_path.unlink()
        self.assertPinFile(successor.load_successor_pins, root)

        root = self.copy_pin_dir()
        shutil.copyfile(root / historical.PACKAGE_PINS_NAME, root / successor.PACKAGE_PINS_NAME)
        self.assertPinFile(successor.load_successor_pins, root)

        root = self.copy_pin_dir()
        shutil.copyfile(root / successor.PACKAGE_PINS_NAME, root / historical.PACKAGE_PINS_NAME)
        self.assertPinFile(historical.load_qualified_pins, root)

        root = self.copy_pin_dir()
        rootfs = root / historical.ROOTFS_PIN_NAME
        rootfs.write_bytes(rootfs.read_bytes() + b"\n")
        self.assertPinFile(successor.load_successor_pins, root)


if __name__ == "__main__":
    unittest.main()
