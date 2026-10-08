"""Run-8 stderr through the real tamper path; fixture transport, no native credit."""
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

from rs9 import hosted_deb as backend
from rs9.apt_diagnostics import build_positive_control, trust_identity
from rs9.build_native import CommandReceipt, MockCommandRunner
from tests.test_repo_apt import FixtureSigner

WRONGKEY = ('error: rs9: key "6F3F25BA5FD8853E81F8FF50D3C6424FD7907037" is unknown\n'
            'error: key "6F3F25BA5FD8853E81F8FF50D3C6424FD7907037" could not be looked up remotely\n'
            'error: failed to synchronize all databases (invalid or corrupted database (PGP signature))\n')
SIGNATURE = ('error: rs9: signature from "RS9 NON-PRODUCTION CANDIDATE FIXTURE <nonproduction@invalid>" is invalid\n'
             'error: failed to synchronize all databases (invalid or corrupted database (PGP signature))\n')


class PacmanReplayTests(unittest.TestCase):
    def replay(self, *, control_kind="valid", accepted=False, sample=WRONGKEY, kind="wrongkey"):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            repo = root/"pacman"
            base = repo/"x86_64"
            base.mkdir(parents=True)
            for name in ("rs9.db", "rs9.db.tar.gz", "fixture-1.pkg.tar.zst"):
                (base/name).write_bytes(b"repository-fixture")
                (base/(name+".sig")).write_bytes(b"signature-fixture")
            def spec_for(dirs):
                return {"family":"pacman", "mounts":[(dirs["pacman"],"/srv/pacman",False)],
                        "configure":[["fixture","configure"]], "refresh":["fixture","refresh"],
                        "install":lambda p:["fixture","install",p], "query":lambda p:["fixture","query",p]}
            dirs = {"pacman":repo}
            host = backend.RecordingRunner(MockCommandRunner())
            control = build_positive_control(family="pacman",image="pinned-image",platform="linux/amd64",
                product="fixture",setup_sha256=trust_identity(spec_for(dirs)),success=True,
                receipts={s:CommandReceipt(["fixture",s],0,b"",b"",executed=True)
                          for s in ("configure","refresh","install","query")})
            if control_kind == "missing":control=None
            elif control_kind == "failed":control["success"]=False
            elif control_kind == "unexecuted":control["stages"]["install"][0]["executed"]=False
            elif control_kind != "valid":control[control_kind]="drift"
            class Client:
                def __init__(self,*args):pass
                def __enter__(self):return self
                def __exit__(self,*args):pass
                def exec(self,command):
                    stage=command[1]
                    code=0 if stage=="configure" or accepted else 1
                    err=sample.encode() if stage=="refresh" and code else b""
                    receipt=CommandReceipt(command,code,b"",err,executed=True)
                    host.receipts.append(receipt)
                    return receipt
            with patch.object(backend,"ClientContainer",Client):
                rows=backend.tamper_cycle(host,spec_for,"pacman",dirs,image="pinned-image",
                    platform="linux/amd64",product="fixture",work=root,arch="x86_64",
                    wrong_signer=FixtureSigner("B"*40),kinds=[kind],prefix="pacman-trust",
                    positive_control=control)
            return rows[0]

    def test_exact_samples_preserve_wrongkey_and_corrupt_signature_distinction(self):
        row=self.replay()
        self.assertEqual(row["status"],"pass") # Executed-receipt folding only; fixture transport.
        self.assertEqual(row["rejection_category"],"KEY_MISMATCH")
        self.assertEqual(row["qualifying_stage"],"refresh")
        row=self.replay(kind="signature",sample=SIGNATURE)
        self.assertEqual(row["status"],"pass")
        self.assertEqual(row["rejection_category"],"SIGNATURE_REJECTED")
        self.assertEqual(self.replay(sample=SIGNATURE)["status"],"fail")

    def test_same_image_platform_product_setup_and_executed_control_required(self):
        for kind in ("missing","failed","unexecuted","family","image_sha256","platform","product","setup_sha256"):
            with self.subTest(control=kind):
                self.assertEqual(self.replay(control_kind=kind)["status"],"not-run")

    def test_accepted_tampering_fails_without_positive_control(self):
        for kind in ("valid","missing","failed","unexecuted"):
            row=self.replay(control_kind=kind,accepted=True)
            self.assertEqual(row["status"],"fail")
            self.assertEqual(row["reason"],"tampered-content-accepted")

    def test_other_causes_do_not_qualify_wrongkey(self):
        for sample in ("Permission denied", "Network is unreachable", "target not found: fixture",
                       'error: rs9: key "malformed" is unknown'):
            self.assertEqual(self.replay(sample=sample)["status"],"fail")
