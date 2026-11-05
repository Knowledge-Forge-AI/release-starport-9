"""Pure tests: ArchARM SDK lease preparation, identity/account order, readback and cleanup.

No real process, network, Docker, GPG, pacman or database is used; see
``tests.test_archarm_sdk_harness`` for the fakes. Passing these tests is not
native evidence and never qualifies the SDK module.
"""
from __future__ import annotations

import copy
import hashlib
import io
import json
import pickle
import unittest

from rs9 import archarm_sdk
from rs9.build_native import MockCommandRunner
from rs9.current_generation import HISTORICAL_GENERATION
from rs9._archarm_support import origin, pins as pins_module
from rs9._archarm_support.fetch import AnonymousFetcher
from rs9._archarm_support.profiles import CAP_ADD, HOSTNAME
from rs9._archarm_support.refusal import SdkRefusal
from rs9._archarm_support.scripts import (GUEST_ACCOUNT, INSTALL_STAGES, MAX_ID,
                                          render_install_script)
from tests.test_archarm_sdk_harness import CONTEXT, NONCE, ROLE_LABEL, Harness, install_tokens


class RefusalMixin:
    def assertRefused(self, label, function, *args, **kwargs):
        with self.assertRaises(SdkRefusal) as caught:
            function(*args, **kwargs)
        self.assertEqual(caught.exception.label, label)
        self.assertEqual(caught.exception.code, "ARCHARM_" + label)
        return caught.exception


class LeasePreparationTest(RefusalMixin, unittest.TestCase):
    def setUp(self):
        self.h = Harness(self)

    def test_eager_preparation_commits_once_after_account_and_cleans_up(self):
        lease = self.h.lease()
        self.assertEqual(self.h.engine.calls, [])  # nothing happens before __enter__
        with lease:
            self.assertEqual(lease.state, "ready")
            self.assertEqual(lease.platform, "linux/arm64")
            self.assertEqual((lease.uid, lease.gid), (self.h.uid, self.h.gid))
            self.assertRegex(lease.image, r"^sha256:[0-9a-f]{64}$")
            records = lease.records
            self.assertTrue(all(records["flags"].values()), records["flags"])
            self.assertTrue(records["flags"]["guestAccountCreated"])
            self.assertFalse(records["pinsMatchQualifiedOrigin"])
            self.assertFalse(records["assertions"]["moduleNativeQualified"])
            self.assertFalse(any(records["assertions"].values()))
            commits = self.h.engine.docker_calls(["commit"])
            self.assertEqual(len(commits), 1)
            verbs = [c[0] for c in self.h.engine.docker_calls()]
            self.assertLess(verbs.index("start"), verbs.index("commit"))
            self.assertEqual(self.h.engine.role_docs("installer"), [])  # removed after commit
        self.assertEqual(lease.state, "closed")
        self.assertTrue(lease.records["cleanupComplete"])
        self.assertFalse((self.h.root / "work").exists())
        self.assertEqual(self.h.engine.images, {})
        self.assertEqual(self.h.engine.containers, {})

    def test_records_carry_no_host_paths_or_names(self):
        with self.h.lease() as lease:
            text = json.dumps(lease.records)
        self.assertNotIn(str(self.h.root), text)
        self.assertNotIn("rs9-archarm-sdk:", text)
        self.assertNotIn("rs9-archarm-installer", text)
        self.assertEqual(set(json.loads(text)["identity"]), {"uid", "gid", "guestAccount", "guestHome"})

    def test_installer_profile_is_exact_and_read_back_before_start(self):
        with self.h.lease():
            create = self.h.engine.created("installer")[0]
            self.assertEqual(create.count("--cap-drop"), 1)
            self.assertEqual([create[i + 1] for i, a in enumerate(create) if a == "--cap-add"],
                             list(CAP_ADD))
            for flag, value in (("--network", "none"), ("--ipc", "none"), ("--user", "0:0"),
                                ("--hostname", HOSTNAME), ("--pids-limit", "256"),
                                ("--memory", "3221225472"), ("--cpus", "2"),
                                ("--security-opt", "no-new-privileges=true"),
                                ("--pull", "never"), ("--platform", "linux/arm64")):
                self.assertEqual(create[create.index(flag) + 1], value, flag)
            mounts = [create[i + 1] for i, a in enumerate(create) if a == "--mount"]
            self.assertEqual(len(mounts), 1)
            self.assertTrue(mounts[0].endswith(",target=/run/rs9-inputs,readonly"))
            self.assertNotIn("--tmpfs", create)
            verbs = [c[0] for c in self.h.engine.docker_calls()]
            create_at = verbs.index("create")
            self.assertEqual(self.h.engine.docker_calls()[create_at + 1][:3],
                             ["container", "inspect", "--format"])

    def test_installer_readback_mutations_refuse_before_start(self):
        mutations = {
            "extra capability": lambda d: d["Host"].update(CapAdd=[*CAP_ADD, "SYS_CHROOT"]),
            "privileged": lambda d: d["Host"].update(Privileged=True),
            "network": lambda d: d["Host"].update(NetworkMode="bridge"),
            "ipc": lambda d: d["Host"].update(IpcMode="shareable"),
            "nnp": lambda d: d["Host"].update(SecurityOpt=[]),
            "memory": lambda d: d["Host"].update(Memory=4294967296),
            "pids": lambda d: d["Host"].update(PidsLimit=512),
            "rw input": lambda d: d["Mounts"][0].update(RW=True),
            "extra bind": lambda d: d["Host"].update(Binds=["/:/host"]),
            "hostname": lambda d: d.update(Hostname="other"),
            "user": lambda d: d.update(User="1000:1000"),
            "image": lambda d: d.update(Image="sha256:" + "f" * 64),
            "group add": lambda d: d["Host"].update(GroupAdd=["0"]),
        }
        for name, mutation in mutations.items():
            with self.subTest(name):
                h = Harness(self)
                h.engine.mutate = lambda role, doc, m=mutation: role == "installer" and m(doc)
                lease = h.lease()
                self.assertRefused("INSTALLER_HOST_CONFIG", lease.__enter__)
                self.assertEqual(h.engine.docker_calls(["start"]), [])
                self.assertEqual(h.engine.docker_calls(["commit"]), [])
                self.assertEqual(lease.state, "failed")
                self.assertEqual(h.engine.containers, {})
                self.assertFalse((h.root / "work").exists())

    def test_account_collisions_and_failures_prevent_commit(self):
        for failure in ("account_uid_collision", "account_gid_collision",
                        "account_name_collision", "account_create", "account_verify"):
            with self.subTest(failure):
                h = Harness(self)
                h.engine.install_output = install_tokens(INSTALL_STAGES[:6], failure)
                h.engine.install_code = 1
                lease = h.lease()
                self.assertRefused("INSTALL_" + failure.upper(), lease.__enter__)
                self.assertEqual(h.engine.docker_calls(["commit"]), [])
                self.assertFalse(lease.records["flags"]["guestAccountCreated"])
                self.assertTrue(lease.records["cleanupComplete"])

    def test_incomplete_or_noisy_installer_output_refuses(self):
        cases = {"INSTALL_INCOMPLETE": install_tokens(INSTALL_STAGES[:-1]),
                 "INSTALL_OUTPUT": b"RSI inputs\nRSI pacman\n"}
        for label, output in cases.items():
            with self.subTest(label):
                h = Harness(self)
                h.engine.install_output = output
                self.assertRefused(label, h.lease().__enter__)
                self.assertEqual(h.engine.docker_calls(["commit"]), [])

    def test_account_stage_order_in_installer_script(self):
        text = render_install_script(count=139, uid=1001, gid=118)
        order = [text.index(marker) for marker in (
            "mark ptpcaps", "account_uid_collision", "account_gid_collision",
            "account_name_collision", "groupadd --gid", "useradd --no-log-init --no-create-home "
            "--no-user-group --uid", "mark account", "mark done")]
        self.assertEqual(order, sorted(order))
        self.assertIn("U=1001\nV=118\nN=rs9builder\nH=/tmp/home\n", text)
        self.assertIn('--home-dir "$H" "$N"', text)
        self.assertNotIn("usermod", text)
        self.assertNotIn("--non-unique", text)
        self.assertNotIn("chpasswd", text)
        self.assertIn('test "$#" -eq 139', text)
        self.assertIn("-eq 278", text)
        self.assertEqual(GUEST_ACCOUNT, "rs9builder")

    def test_runner_identity_bounds_and_actual_identity(self):
        for uid, gid in ((0, self.h.gid), (self.h.uid, 0), (MAX_ID + 1, self.h.gid),
                         (True, self.h.gid), (str(self.h.uid), self.h.gid)):
            with self.subTest(uid=uid, gid=gid):
                self.assertRefused("RUNNER_IDENTITY", self.h.lease, uid=uid, gid=gid)
        self.assertRefused("RUNNER_IDENTITY", self.h.lease,
                           runner_identity=lambda: (self.h.uid + 1, self.h.gid))
        self.assertRefused("RUNNER_IDENTITY", render_install_script, count=1, uid=MAX_ID + 1, gid=1)
        render_install_script(count=1, uid=MAX_ID, gid=MAX_ID)

    def test_context_is_closed_and_current_only(self):
        cases = {"CONTEXT_KEYS": {**CONTEXT, "extra": 1},
                 "CONTEXT_GENERATION": {**CONTEXT, "generation": HISTORICAL_GENERATION},
                 "CONTEXT_RUN_ATTEMPT": {**CONTEXT, "runAttempt": "2"},
                 "CONTEXT_RUN_ID": {**CONTEXT, "runId": "0"},
                 "CONTEXT_SOURCE_SHA": {**CONTEXT, "sourceSha": "A" * 40},
                 "CONTEXT_PRIVATE_ROOTS": {**CONTEXT, "privateRoots": ["relative"]}}
        for label, context in cases.items():
            with self.subTest(label):
                self.assertRefused(label, self.h.lease, context=context)
        private = {**CONTEXT, "privateRoots": [str(self.h.root)]}
        self.assertRefused("PRIVATE_MOUNT", self.h.lease, context=private)

    def test_lease_is_typed_immutable_and_not_serializable(self):
        lease = self.h.lease()
        self.assertRefused("LEASE_IMMUTABLE", setattr, lease, "_s", None)
        self.assertRefused("LEASE_NOT_SERIALIZABLE", copy.copy, lease)
        self.assertRefused("LEASE_NOT_SERIALIZABLE", copy.deepcopy, lease)
        self.assertRefused("LEASE_NOT_SERIALIZABLE", pickle.dumps, lease)
        self.assertRefused("LEASE_CONSTRUCTION", archarm_sdk.ArchArmSDK, object(),
                           host=self.h.engine, workspace=self.h.root / "w", context=CONTEXT,
                           uid=self.h.uid, gid=self.h.gid, seams=self.h.seams())
        self.assertRefused("LEASE_CONSTRUCTION", archarm_sdk.ArchArmBuilderRunner, object(),
                           dict(lease.records), self.h.root, [])
        self.assertRefused("LEASE_STATE", lease.builder_runner, self.h.root, [])
        self.assertRefused("LEASE_STATE", lambda: lease.image)
        self.assertRefused("HOST_RUNNER", self.h.lease, host=object())

    def test_missing_host_tools_fail_without_install_or_workspace(self):
        for tool in ("docker", "gpgv", "uname"):
            with self.subTest(tool):
                h = Harness(self)
                h.engine.tools.discard(tool)
                lease = h.lease()
                with self.assertRaises(archarm_sdk.NativePrerequisiteUnavailable) as caught:
                    lease.__enter__()
                self.assertEqual(caught.exception.missing_tools, [tool])
                self.assertEqual(h.engine.calls, [])
                self.assertFalse((h.root / "work").exists())

    def test_non_native_host_or_engine_refuses(self):
        for attribute, value, label in (("uname", b"Linux x86_64\n", "NATIVE_ARM_HOST"),
                                        ("server", b"linux/amd64\n", "NATIVE_ARM_ENGINE"),
                                        ("info", b"linux/x86_64\n", "NATIVE_ARM_ENGINE")):
            with self.subTest(label=label, attribute=attribute):
                h = Harness(self)
                setattr(h.engine, attribute, value)
                lease = h.lease()
                self.assertRefused(label, lease.__enter__)
                self.assertTrue(lease.records["cleanupComplete"])
                self.assertFalse((h.root / "work").exists())

    def test_synthetic_receipts_never_confer_authority(self):
        h = Harness(self)
        h.engine.executed = False
        self.assertRefused("SYNTHETIC_RECEIPT", h.lease().__enter__)
        mock = MockCommandRunner(available_tools={t: "/usr/bin/" + t for t in ("docker", "gpgv", "uname")})
        lease = Harness(self).lease(host=mock)
        self.assertRefused("SYNTHETIC_RECEIPT", lease.__enter__)

    def test_missing_input_signature_or_rootfs_inventory_refuses(self):
        h = Harness(self)
        h.fetcher.blobs.pop(next(u for u in h.fetcher.blobs if u.endswith("gtk3-3.24.51-1-aarch64.pkg.tar.xz")))
        self.assertRefused("INPUT_TRANSPORT", h.lease().__enter__)
        self.assertEqual(h.engine.docker_calls(["import"]), [])
        h = Harness(self)
        h.engine.gpg_status = h.engine.gpg_status.replace(b"VALIDSIG 68B3", b"VALIDSIG 00B3")
        self.assertRefused("ROOTFS_SIGNATURE", h.lease().__enter__)
        h = Harness(self)
        h.engine.gpg_status += b"[GNUPG:] BADSIG x\n"
        self.assertRefused("ROOTFS_SIGNATURE", h.lease().__enter__)

        def bad_inventory(path, pin):
            raise SdkRefusal("SETID_INVENTORY")
        h = Harness(self)
        self.assertRefused("SETID_INVENTORY", h.lease(inspect_rootfs=bad_inventory).__enter__)
        self.assertEqual(h.engine.docker_calls(["import"]), [])

    def test_owned_name_collision_refuses_before_import(self):
        h = Harness(self)
        suffix = f"r{CONTEXT['runId']}-a1-{CONTEXT['sourceSha'][:12]}-{NONCE}"
        h.engine.tags["rs9-archarm-sdk:" + suffix] = "sha256:" + "e" * 64
        h.engine.images["sha256:" + "e" * 64] = {"tags": {"rs9-archarm-sdk:" + suffix}, "env": [], "labels": {}}
        lease = h.lease()
        self.assertRefused("OWNED_NAME_COLLISION", lease.__enter__)
        self.assertEqual(h.engine.docker_calls(["import"]), [])
        self.assertEqual(h.engine.docker_calls(["image", "rm"]), [])  # foreign tag untouched
        self.assertIn("sha256:" + "e" * 64, h.engine.images)


class CleanupTest(RefusalMixin, unittest.TestCase):
    def setUp(self):
        self.h = Harness(self)

    def test_cleanup_is_identity_bound_without_force_or_prune(self):
        with self.h.lease():
            pass
        for call in self.h.engine.docker_calls():
            self.assertNotIn("-f", call)
            self.assertNotIn("--force", call)
            self.assertNotIn("prune", call)
            self.assertNotEqual(call[:1], ["rmi"])
            self.assertNotEqual(call[:1], ["rm"])
        removed = self.h.engine.docker_calls(["image", "rm"])
        self.assertEqual(len(removed), 2)
        self.assertTrue(all(call[2] == "--no-prune" for call in removed))
        self.assertTrue(all(len(call[3]) > 0 and not call[3].startswith("sha256:") for call in removed))

    def test_retagged_sdk_image_is_retained_and_reported(self):
        lease = self.h.lease()
        lease.__enter__()
        sdk_tag = next(t for t in self.h.engine.tags if t.startswith("rs9-archarm-sdk:"))
        foreign = "sha256:" + "d" * 64
        self.h.engine.images[foreign] = {"tags": {sdk_tag}, "env": [], "labels": {}}
        self.h.engine.tags[sdk_tag] = foreign
        self.assertRefused("CLEANUP_INCOMPLETE", lease.close)
        self.assertEqual(lease.state, "retained")
        self.assertFalse(lease.records["cleanupComplete"])
        self.assertEqual(self.h.engine.docker_calls(["image", "rm"]), [])
        self.assertTrue((self.h.root / "work").exists())  # retained for VM teardown

    def test_container_identity_mismatch_is_not_removed(self):
        lease = self.h.lease()
        lease.__enter__()
        product = self.h.directory("product")
        runner = lease.builder_runner(product, [])
        self.h.engine.fail_rm.add("builder")
        self.assertRefused("CLEANUP_INCOMPLETE", runner.run, ["makepkg", "-f"])
        self.assertEqual(lease.state, "poisoned")
        doc = self.h.engine.role_docs("builder")[0]
        doc["Labels"] = {**doc["Labels"], ROLE_LABEL: "client"}  # identity drift
        self.h.engine.fail_rm.clear()
        rm_before = len(self.h.engine.docker_calls(["container", "rm"]))
        self.assertRefused("CLEANUP_INCOMPLETE", lease.close)
        self.assertEqual(len(self.h.engine.docker_calls(["container", "rm"])), rm_before)
        self.assertEqual(self.h.engine.docker_calls(["image", "rm"]), [])
        self.assertEqual(lease.state, "retained")

    def test_unknown_workspace_entry_is_retained(self):
        lease = self.h.lease()
        lease.__enter__()
        (self.h.root / "work" / "inputs" / "unexpected").write_bytes(b"x")
        self.assertRefused("CLEANUP_INCOMPLETE", lease.close)
        self.assertTrue((self.h.root / "work" / "inputs" / "unexpected").exists())

    def test_close_retry_after_transient_failure(self):
        lease = self.h.lease()
        lease.__enter__()
        product = self.h.directory("product")
        runner = lease.builder_runner(product, [])
        self.h.engine.fail_rm.add("builder")
        self.assertRefused("CLEANUP_INCOMPLETE", runner.run, ["true"])
        self.assertRefused("CLEANUP_INCOMPLETE", lease.close)
        self.h.engine.fail_rm.clear()
        lease.close()
        self.assertEqual(lease.state, "closed")
        self.assertEqual(self.h.engine.containers, {})


class PinsAndFetchTest(RefusalMixin, unittest.TestCase):
    def setUp(self):
        self.h = Harness(self)

    def test_qualified_pins_absent_or_different_refuse(self):
        empty = self.h.directory("nopins")
        self.assertRefused("PIN_FILE", pins_module.load_qualified_pins, empty)
        for name in ("PACKAGE-PINS.json", "ROOTFS-PIN.json", "archlinuxarm-builder-public.gpg"):
            (empty / name).write_bytes(b"{}")
        self.assertRefused("PIN_FILE", pins_module.load_qualified_pins, empty)

    def test_origin_identities_and_transforms_are_recorded(self):
        self.assertFalse(origin.MODULE_NATIVE_QUALIFIED)
        self.assertEqual(origin.ORIGIN_FILES["PACKAGE-PINS.json"]["sha256"],
                         "53c812397e73cdb16c80cd5cd72b6ed66889817d8aa79b075034434895da2987")
        self.assertEqual(origin.ORIGIN_FILES["ROOTFS-PIN.json"]["sha256"],
                         "0d92f648e1f9bc2ef29846b7f37d7fae99ccbb4adc6fd918d797c2ac9054edff")
        self.assertIn("archarm_runtime_probe.run_probe", origin.NOT_PORTED)
        self.assertIn("archarm_runtime_probe.main", origin.NOT_PORTED)
        self.assertEqual(pins_module.REAL_EXPECT["packageCount"], 139)
        self.assertEqual(pins_module.REAL_EXPECT["packageBytes"], 201499452)
        self.assertEqual(pins_module.REAL_EXPECT["rootfsSha256"],
                         "42a4eeaa038994ffd31fa173256ef2f0ef511358eeb41b9ea1f8626391b9b319")
        self.assertTrue(len(origin.NAMESPACE_TRANSFORMS) >= 8)

    def test_package_pin_validation_is_unchanged(self):
        doc = copy.deepcopy(dict(self.h.bundle.package_pins))
        expect = dict(self.h.bundle.expect)
        doc["packages"][1]["version"] = "3.14.10-1"  # python pin
        doc["packages"][1]["filename"] = "python-3.14.10-1-aarch64.pkg.tar.xz"
        doc["packages"][1]["url"] = ("https://fl.us.mirror.archlinuxarm.org/aarch64/extra/"
                                     "python-3.14.10-1-aarch64.pkg.tar.xz")
        self.assertRefused("PIN_VERSION", pins_module.validate_package_pins, doc, expect)
        doc = copy.deepcopy(dict(self.h.bundle.package_pins))
        doc["packages"][0]["url"] = doc["packages"][0]["url"].replace("fl.us.", "de.")
        self.assertRefused("PIN_URL", pins_module.validate_package_pins, doc, expect)

    def test_anonymous_fetcher_refuses_redirect_size_and_foreign_urls(self):
        body = b"payload"
        url = "https://fl.us.mirror.archlinuxarm.org/aarch64/core/x-1-1-aarch64.pkg.tar.xz"
        rootfs = pins_module.REAL_EXPECT["rootfsUrl"]

        class Response(io.BytesIO):
            def __init__(self, data, *, status=200, final=url, length=None):
                super().__init__(data)
                self.status, self._final = status, final
                self.headers = {"Content-Length": str(len(data) if length is None else length)}

            def geturl(self):
                return self._final

        def opener(response):
            class Opener:
                def open(self, requested, timeout):
                    self.requested = requested
                    return response
            return lambda: Opener()

        target = self.h.directory("dl")
        fetcher = AnonymousFetcher(opener_factory=opener(Response(body)))
        fetcher.fetch(url, target / "ok", len(body), hashlib.sha256(body).hexdigest(),
                      10 ** 12, rootfs_url=rootfs)
        self.assertEqual((target / "ok").read_bytes(), body)
        cases = {
            "INPUT_URL": (AnonymousFetcher(opener_factory=opener(Response(body))),
                          "https://example.invalid/x.pkg.tar.xz", len(body)),
            "INPUT_TRANSPORT": (AnonymousFetcher(opener_factory=opener(
                Response(body, final="https://other.invalid/"))), url, len(body)),
            "INPUT_SIZE": (AnonymousFetcher(opener_factory=opener(Response(body, length=99))),
                           url, len(body)),
        }
        for index, (label, (fetch, address, size)) in enumerate(cases.items()):
            with self.subTest(label):
                self.assertRefused(label, fetch.fetch, address, target / f"bad{index}", size,
                                   "0" * 64, 10 ** 12, rootfs_url=rootfs)


if __name__ == "__main__":
    unittest.main()
