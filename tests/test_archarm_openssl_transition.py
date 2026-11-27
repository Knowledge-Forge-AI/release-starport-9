"""Source qualification for the qualified OpenSSL inventory transplant."""
from dataclasses import replace
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from rs9 import archarm_sdk
from rs9._archarm_support import successor_20261120 as successor
from rs9._archarm_support import successor_20261126 as graphics
from rs9._archarm_support import successor_20261127 as libcups
from rs9._archarm_support.refusal import SdkRefusal
from rs9._archarm_support.scripts import render_install_script


class OpenSSLTransitionTest(unittest.TestCase):
    def test_exact_profile_admits_only_qualified_pin_bundle(self):
        bundle = archarm_sdk._real_seams(successor.PROFILE).pins_loader()
        self.assertTrue(bundle.qualified)
        self.assertEqual(bundle.digests["packagePinsSha256"], successor.PACKAGE_PINS_SHA256)
        self.assertEqual(len(bundle.packages), 141)
        self.assertEqual(sum(pkg["bytes"] for pkg in bundle.packages), 210600960)
        self.assertEqual(bundle.package_pins["basePackageUpgrade"],
                         {"name": "openssl", "from": "3.6.3-1", "to": "4.1.0-1"})
        for rejected in (replace(bundle, qualified=False), archarm_sdk._real_seams().pins_loader()):
            with patch.object(successor, "load_successor_pins", return_value=rejected):
                with self.assertRaisesRegex(SdkRefusal, "PIN_FILE"):
                    archarm_sdk._real_seams(successor.PROFILE).pins_loader()

    def test_graphics_profile_closes_the_eight_row_delta(self):
        previous = archarm_sdk._real_seams(successor.PROFILE).pins_loader()
        current = archarm_sdk._real_seams(graphics.PROFILE).pins_loader()
        old = {row["name"]: row for row in previous.packages}
        new = {row["name"]: row for row in current.packages}
        self.assertEqual(old.keys(), new.keys())
        self.assertEqual({name for name in old if old[name] != new[name]}, {
            "at-spi2-core", "glycin", "gtk-update-icon-cache", "harfbuzz",
            "harfbuzz-icu", "libjxl", "mesa", "webkit2gtk-4.1",
        })
        self.assertEqual(current.digests["packagePinsSha256"], graphics.PACKAGE_PINS_SHA256)
        self.assertEqual(sum(row["bytes"] for row in current.packages), 210849784)
        self.assertEqual(current.package_pins["basePackageUpgrade"],
                         previous.package_pins["basePackageUpgrade"])
        with patch.object(graphics, "load_successor_pins", return_value=previous):
            with self.assertRaisesRegex(SdkRefusal, "PIN_FILE"):
                archarm_sdk._real_seams(graphics.PROFILE).pins_loader()

    def test_libcups_profile_requires_the_exact_single_package_delta(self):
        previous = archarm_sdk._real_seams(graphics.PROFILE).pins_loader()
        current = archarm_sdk._real_seams(libcups.PROFILE).pins_loader()
        old = {row["name"]: row for row in previous.packages}
        new = {row["name"]: row for row in current.packages}
        self.assertEqual(old.keys(), new.keys())
        self.assertEqual({name for name in old if old[name] != new[name]}, {"libcups"})
        self.assertEqual(new["libcups"]["version"], "2:2.4.20-2")
        self.assertEqual(current.digests["packagePinsSha256"], libcups.PACKAGE_PINS_SHA256)
        self.assertEqual(sum(row["bytes"] for row in current.packages), 210849968)
        with patch.object(libcups, "load_successor_pins", return_value=previous):
            with self.assertRaisesRegex(SdkRefusal, "PIN_FILE"):
                archarm_sdk._real_seams(libcups.PROFILE).pins_loader()

    def test_inventory_proves_exact_transition(self):
        script = render_install_script(count=141, uid=1001, gid=118, openssl_transition=True)
        self.assertLess(script.index('\nplan_inventory\n'), script.index(' -U --noconfirm'))
        self.assertLess(script.index(' -U --noconfirm'), script.index('\ncheck_inventory\n'))
        functions = script[script.index("plan_inventory()"):script.index('test "$(id -u)')]
        retained = ["archlinuxarm-keyring 1.0-1", "libc 2.0-1"]
        before = retained + ["openssl 3.6.3-1"]
        selected = ["openssl 4.1.0-1", "openssl-3 3.5.9-2"]
        selected += [f"pkg-{i:03} 1.0-1" for i in range(139)]
        after = retained + selected
        cases = (
            (before, selected, after, "ok"),
            (retained + ["openssl 3.6.3-2"], selected, after, "base_changed"),
            (before, ["openssl 4.1.0-2"] + selected[1:], after, "delta"),
            (before, selected[:1] + ["openssl-3 3.5.9-3"] + selected[2:], after, "delta"),
            (before, selected[:-1], after, "delta"),
            (before, selected[:-1] + selected[-2:-1], after, "delta"),
            (before, selected[:-1] + ["libc 3.0-1"], after, "base_changed"),
            (before, selected, after[1:], "base_changed"),
            (before, selected, after + ["unexpected 1.0-1"], "base_changed"),
            (before, selected, after + ["openssl 3.6.3-1"], "base_changed"),
        )
        body = ('set -euo pipefail\nT=$1\nfail() { printf "%s" "$1"; exit 1; }\n'
                + functions + 'plan_inventory\ncheck_inventory\nprintf ok\n')
        with tempfile.TemporaryDirectory(prefix="rs9-openssl-") as directory:
            for i, (base, archives, installed, result) in enumerate(cases):
                with self.subTest(case=i):
                    for name, rows in (("before", base), ("selected", archives), ("after", installed)):
                        (Path(directory) / name).write_text("\n".join(sorted(rows)) + "\n")
                    receipt = subprocess.run(["bash", "-c", body, "test", directory],
                                             capture_output=True, text=True, check=False)
                    self.assertEqual((receipt.returncode, receipt.stdout, receipt.stderr),
                                     (int(result != "ok"), result, ""))

    def test_legacy_inventory_rejects_upgrades_and_new_count_is_fixed(self):
        ordinary = render_install_script(count=141, uid=1001, gid=118)
        self.assertIn('comm -23 "$T/before" "$T/after"', ordinary)
        self.assertNotIn("plan_inventory", ordinary)
        with self.assertRaisesRegex(SdkRefusal, "INSTALL_SCRIPT"):
            render_install_script(count=139, uid=1001, gid=118, openssl_transition=True)
