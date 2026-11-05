"""Current two-architecture Pages assembly stays byte-bound to canonical any."""
import hashlib
from pathlib import Path
import unittest
from rs9.current_generation import CURRENT_GENERATION, HISTORICAL_GENERATION
from rs9.current_pacman_reuse import repository_package_sets
from rs9.errors import ContractError
from rs9.pages_candidate import REQUIRED_PAGES_FILES, verify_pages_completeness, render_install_docs
from tests import test_current_pacman_reuse_join as joins


class CurrentPagesPacmanTests(unittest.TestCase):
    def setUp(self):
        f = self.fixture = joins.ReuseJoinTests()
        f.setUp()
        self.addCleanup(f.doCleanups)
        self.reuse=f.candidate()
        x64={}
        for product,item in self.reuse["canonical"]["products"].items():
            x64[item["name"]]=item["path"]
        arm={}
        for product,version in (("theme-forge-stellar-burst","0.7.0"),("theme-forge-nebular-fusion","0.7.1")):
            for arch,packages in (("x86_64",x64),("aarch64",arm)):
                p=f.f.root/(product+"-"+version+"-1-"+arch+".pkg.tar.zst")
                p.write_bytes(b"inert native archive " + arch.encode())
                packages[p.name]=p
        self.bundles={("pacman","x86_64-linux"):{"packages":x64},
                      ("pacman","aarch64-linux"):{"packages":arm}}

    def test_both_views_reuse_exact_canonical_any_paths(self):
        result=repository_package_sets(self.bundles,self.reuse)
        self.assertEqual(set(result),{"x86_64","aarch64"})
        self.assertEqual([len(result[a]) for a in result],[4,4])
        for product,item in self.reuse["canonical"]["products"].items():
            self.assertEqual(result["x86_64"][item["name"]],Path(item["path"]))
            self.assertEqual(result["aarch64"][item["name"]],Path(item["path"]))
            self.assertNotIn("candidate-pacman-aarch64",str(result["aarch64"][item["name"]]))

    def test_arm_any_construction_in_native_bundle_is_refused(self):
        item=next(iter(self.reuse["canonical"]["products"].values()))
        self.bundles[("pacman","aarch64-linux")]["packages"][item["name"]]=item["path"]
        with self.assertRaises(ContractError):
            repository_package_sets(self.bundles,self.reuse)

    def test_missing_native_or_substituted_canonical_bytes_refuse(self):
        arm=self.bundles[("pacman","aarch64-linux")]["packages"]
        arm.pop(next(iter(arm)))
        with self.assertRaises(ContractError):
            repository_package_sets(self.bundles,self.reuse)
        # No generic filename deduplication may select a replacement constructor.
        item=next(iter(self.reuse["canonical"]["products"].values()))
        Path(item["path"]).write_bytes(b"changed original")
        with self.assertRaises(ContractError):
            repository_package_sets(self.bundles,self.reuse)

    def test_current_completeness_requires_arm_but_historical_keeps_its_shape(self):
        inventory={name:"0"*64 for name in REQUIRED_PAGES_FILES}
        for name in ("rs9.db.tar.gz","rs9.db.tar.gz.sig"):
            inventory["pacman/x86_64/"+name]="1"*64
        verify_pages_completeness(inventory, families=("pacman",))
        with self.assertRaises(ContractError):
            verify_pages_completeness(inventory, families=("pacman",), qualification_generation=CURRENT_GENERATION)
        for name in ("rs9.db.tar.gz","rs9.db.tar.gz.sig"):
            inventory["pacman/aarch64/"+name]="1"*64
        verify_pages_completeness(inventory, families=("pacman",), qualification_generation=CURRENT_GENERATION)

    def test_current_docs_mention_archarm_and_unknown_generation_refuses(self):
        old=render_install_docs()
        self.assertEqual(old,render_install_docs(qualification_generation=HISTORICAL_GENERATION))
        self.assertIn("Arch Linux ARM aarch64",render_install_docs(qualification_generation=CURRENT_GENERATION)["docs/install/README.md"])
        for fn,args in ((render_install_docs,()),(verify_pages_completeness,({},))):
            with self.assertRaises(ContractError):
                fn(*args,qualification_generation="latest")
