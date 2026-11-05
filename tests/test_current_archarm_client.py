"""Pure tests for the current ArchARM (pacman/aarch64-linux) shared client integration.

No Docker, GPG, pacman database, network or native application runs. The SDK lease
is a genuine ``rs9.archarm_sdk.ArchArmSDK`` built through the SDK's own internal seam
constructor; its state is then forced to ``ready`` with fixed image IDs (it never
prepared anything). Client objects are genuine ``ArchArmClient`` instances, so the
SDK's real mount admission, owner-only probe-output checks and held no-follow
ingestion all run. Only container lifecycle/exec/inventory are scripted. A scripted
"guest" writes into the real host probe-output directory exactly as a live writer would.
"""
from __future__ import annotations

import contextlib
import inspect
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from rs9 import archarm_sdk
from rs9 import current_archarm_packaging as cap
from rs9 import hosted_burst_clients as hbc
from rs9 import hosted_container_smoke as hcs
from rs9 import hosted_deb as hd
from rs9._archarm_support import scripts as sdk_scripts
from rs9.build_native import CommandReceipt, MockCommandRunner
from rs9.current_generation import CURRENT_GENERATION, HISTORICAL_GENERATION
from rs9.errors import ContractError
from rs9.release_core import digest
from rs9.scratch import canonical

FPR = "A" * 40
BURST = "theme-forge-stellar-burst"
LOOM = "theme-forge-stellar-loom"
IMAGE = "sha256:" + "c" * 64
LOADER = {"loaded": True, "artifact": "linux-arm64-gnu"}
BURST_RECORD = {"platform_specific": True, "target_system": "aarch64-linux",
                "target_native_addon": {"path": "package/prebuilds/linux-arm64-gnu/addon.node", "sha256": "e" * 64}}
POSIX_NONROOT = (os.name == "posix" and hasattr(os, "getuid")
                 and os.getuid() != 0 and os.getgid() != 0)


def make_lease(root: Path, host) -> archarm_sdk.ArchArmSDK:
    """Genuine lease through the SDK's internal seam constructor, then forced ``ready``."""
    seams = archarm_sdk._Seams(fetcher=None, inspect_rootfs=lambda *a: {}, pins_loader=lambda: None,
                               runner_identity=lambda: (os.getuid(), os.getgid()),
                               nonce=lambda: "0123456789ab")
    lease = archarm_sdk._acquire(host=host, workspace=root / "sdk-workspace",
                                 context={"runId": "4242", "runAttempt": "1", "sourceSha": "a" * 40,
                                          "generation": CURRENT_GENERATION},
                                 uid=os.getuid(), gid=os.getgid(), seams=seams)
    state = lease._s
    state.records["sdk"].id = IMAGE
    state.records["base"].id = "sha256:" + "d" * 64
    state.state = "ready"
    return lease


class Workspace:
    def __init__(self, test: unittest.TestCase) -> None:
        tmp = tempfile.TemporaryDirectory()
        test.addCleanup(tmp.cleanup)
        self.root = Path(os.path.realpath(tmp.name))
        probe = self.root / "gid-probe"
        probe.mkdir()
        if os.lstat(probe).st_gid != os.getgid():
            test.skipTest("temporary directory group differs from the process gid")
        probe.rmdir()
        self.pacman = self.root / "pacman"
        (self.pacman / "aarch64").mkdir(parents=True)
        (self.pacman / "aarch64" / "rs9.db").write_bytes(b"database")
        (self.pacman / "aarch64" / "rs9.db.sig").write_bytes(b"signature")
        self.keys = self.root / "keys"
        self.keys.mkdir()
        (self.keys / "rs9-candidate-fixture-NONPRODUCTION.asc").write_bytes(b"public certificate")
        self.repository = self.root / "r"
        (self.repository / "src" / "rs9").mkdir(parents=True)
        (self.repository / "src" / "rs9" / "__init__.py").write_text("")
        (self.root / "work").mkdir()
        self.probe_root = self.root / "work" / "archarm-probe-output"
        self.host = hd.RecordingRunner(MockCommandRunner())
        self.lease = make_lease(self.root, self.host)
        self.user = f"{os.getuid()}:{os.getgid()}"

    def spec(self, architecture: str = "aarch64", pacman: Path | None = None):
        return hd.pacman_spec(pacman or self.pacman, self.keys, FPR, architecture=architecture)


def default_burst(out: Path):
    loader = out / hbc.ARCHARM_BURST_OUTPUT
    loader.mkdir(mode=0o700)
    for name in hbc.ARCHARM_BURST_FILES:
        fd = os.open(loader / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(b"// loader harness\n")
    return 0, json.dumps({"status": "pass", "proof": "installed-released-loader-self-test", "loaded": True}).encode()


class ScriptedGuest:
    """Scripted container behaviour on genuine ArchArmClient objects."""

    def __init__(self, ws: Workspace, *, install_code=0, burst=default_burst, live_writer=None,
                 quiesce=True, refresh_code=0):
        self.ws, self.install_code, self.burst = ws, install_code, burst
        self.live_writer, self.quiesce, self.refresh_code = live_writer, quiesce, refresh_code
        self.events: list[tuple] = []
        self.clients: list[archarm_sdk.ArchArmClient] = []
        self.installed: set[str] = set()

    def respond(self, client, argv, user):
        if user is None:
            tool = argv[0]
            if tool == "pacman" and "-Sy" in argv:
                return self.refresh_code, b""
            if tool == "pacman" and "-S" in argv:
                if self.install_code == 0:
                    self.installed.add(argv[-1].split("/", 1)[-1])
                return self.install_code, b""
            if tool == "pacman" and "-R" in argv:
                self.installed.discard(argv[-1])
                return 0, b""
            if tool == "pacman" and "-Q" in argv:
                return (0 if argv[-1] in self.installed else 1), b""
            return 0, b""
        if argv[0] == "python3" and "verify_burst_payload" in argv[2]:
            return self.burst(client._output)
        return 0, b""

    def patches(self):
        guest, real_ingest = self, archarm_sdk.ArchArmClient.ingest_output

        def enter(client):
            client._phase = "running"
            guest.clients.append(client)
            guest.events.append(("enter", client, None))
            return client

        def exit_(client, exc_type, exc, tb):
            if guest.live_writer is not None:
                guest.live_writer(client._output)
            guest.events.append(("exit", client, None))
            if guest.quiesce:
                client._phase = "quiesced"
            return False

        def exec_(client, argv, *, user=None, env=None):
            guest.events.append(("exec", client, (user, list(argv))))
            code, out = guest.respond(client, list(argv), user)
            receipt = CommandReceipt(list(argv), code, out, b"", tool_name=argv[0], executed=True)
            guest.ws.host.receipts.append(receipt)
            return receipt

        def verify(client):
            guest.events.append(("verify-identity", client, None))
            client._identity_verified = True
            return True

        def inventory(client, stage=None):
            client.last_inventory_stage, client.last_diagnostics = stage, {}
            return {"usr/bin/base-tool": "file"}

        def ingest(client, declared, required=()):
            guest.events.append(("ingest", client, client._phase))
            return real_ingest(client, declared, required)

        cls = archarm_sdk.ArchArmClient
        return [patch.object(cls, "__enter__", enter), patch.object(cls, "__exit__", exit_),
                patch.object(cls, "exec", exec_), patch.object(cls, "verify_unprivileged_identity", verify),
                patch.object(cls, "inventory", inventory), patch.object(cls, "ingest_output", ingest),
                patch.object(cls, "unprivileged_prefix", property(lambda client: ["scripted-unprivileged-prefix"]))]


def run_arm_cycle(ws: Workspace, guest: ScriptedGuest, products, *, spec=None, **overrides):
    kwargs = dict(image=IMAGE, platform="linux/arm64", products=list(products), repository=ws.repository,
                  prefix="pacman-client", system="aarch64-linux", burst_record=BURST_RECORD,
                  burst_scratch=ws.probe_root, generation=CURRENT_GENERATION, sdk_lease=ws.lease)
    kwargs.update(overrides)
    with contextlib.ExitStack() as stack:
        for item in guest.patches():
            stack.enter_context(item)
        stack.enter_context(patch("rs9.hosted_deb.execute_probes", return_value=[]))
        stack.enter_context(patch("rs9.hosted_burst_clients.validate_load_receipt", return_value=dict(LOADER)))
        stack.enter_context(patch.object(hd, "ClientContainer", side_effect=AssertionError("generic client used")))
        return hd.client_cycle(ws.host, spec or ws.spec(), **kwargs)


def statuses(rows):
    return {row["name"]: row["status"] for row in rows}


def walk_modes(root: Path):
    for current, dirs, files in os.walk(root):
        for name in [*dirs, *files]:
            yield Path(current) / name, os.lstat(Path(current) / name)


@unittest.skipUnless(POSIX_NONROOT, "POSIX nonroot numeric identity required")
class SharedApiTests(unittest.TestCase):
    def test_sdk_lease_is_an_optional_keyword_on_both_cycles_and_the_producer_preflight_sees_it(self):
        for function in (hd.client_cycle, hd.tamper_cycle):
            parameter = inspect.signature(function).parameters["sdk_lease"]
            self.assertEqual(parameter.kind, inspect.Parameter.KEYWORD_ONLY)
            self.assertIsNone(parameter.default)
        self.assertEqual(cap.shared_api_gaps(hd), [])

    def test_guest_constants_match_the_sdk(self):
        self.assertEqual(hcs.ARCHARM_PROBE_OUTPUT_GUEST, archarm_sdk.PROBE_OUTPUT_TARGET)
        self.assertEqual(hcs.ARCHARM_GUEST_HOME, sdk_scripts.GUEST_HOME)
        self.assertTrue(hcs.ARCHARM_GUEST_SOURCE.startswith("/srv/rs9/"))


@unittest.skipUnless(POSIX_NONROOT, "POSIX nonroot numeric identity required")
class LeaseRequirementTests(unittest.TestCase):
    def setUp(self):
        self.ws = Workspace(self)

    def refused(self, reason, **overrides):
        guest = ScriptedGuest(self.ws)
        with self.assertRaises(ContractError) as caught:
            run_arm_cycle(self.ws, guest, [LOOM], **overrides)
        self.assertEqual(caught.exception.code, "ARCHARM_CLIENT_LEASE")
        self.assertEqual(caught.exception.details.get("reason"), reason)
        self.assertEqual(self.ws.host.receipts, [])
        self.assertEqual(guest.clients, [])
        return caught.exception

    def test_current_pacman_aarch64_without_a_lease_is_refused_before_any_command(self):
        self.refused("lease-missing", sdk_lease=None)
        self.assertFalse(self.ws.probe_root.exists())

    def test_forged_leases_are_refused(self):
        lease = self.ws.lease
        namespace = SimpleNamespace(image=lease.image, platform=lease.platform, uid=lease.uid, gid=lease.gid,
                                    user=lease.user, state="ready", records=lease.records,
                                    client=lambda *a, **k: None)

        class Subclass(archarm_sdk.ArchArmSDK):
            __slots__ = ()

        subclass = object.__new__(Subclass)
        for forged in ({"image": lease.image, "platform": "linux/arm64"}, json.dumps({"image": lease.image}),
                       namespace, subclass, lease.records):
            with self.subTest(type=type(forged).__name__):
                self.refused("lease-type", sdk_lease=forged)

    def test_unready_or_foreign_identity_leases_are_refused(self):
        self.ws.lease._s.state = "new"
        self.refused("lease-not-ready")
        self.ws.lease._s.state = "ready"
        self.ws.lease._s.uid = os.getuid() + 1
        self.refused("runner-identity")

    def test_generation_system_platform_image_and_spec_must_join_the_lease(self):
        writable = self.ws.spec()
        writable["mounts"] = [(*writable["mounts"][0][:2], True), writable["mounts"][1]]
        cases = [
            {"generation": HISTORICAL_GENERATION}, {"platform": "linux/amd64"}, {"system": "x86_64-linux"},
            {"image": "sha256:" + "e" * 64}, {"spec": self.ws.spec("x86_64")}, {"spec": writable},
            {"burst_scratch": None},
        ]
        for overrides in cases:
            with self.subTest(overrides=sorted(overrides)):
                self.refused("route-join", **overrides)

    def test_route_helper_keeps_every_other_lane_on_the_legacy_path(self):
        for family, platform, system, generation in (
                ("pacman", "linux/amd64", "x86_64-linux", CURRENT_GENERATION),
                ("pacman", "linux/arm64", "aarch64-linux", HISTORICAL_GENERATION),
                ("dnf", "linux/arm64", "aarch64-linux", CURRENT_GENERATION),
                ("apt", "linux/arm64", "aarch64-linux", CURRENT_GENERATION)):
            with self.subTest(family=family, platform=platform, generation=generation):
                self.assertIsNone(hd._archarm_client_route(
                    None, family=family, spec={"family": family}, image="img", platform=platform, system=system,
                    generation=generation, probe_root=None, client_outputs=True))


@unittest.skipUnless(POSIX_NONROOT, "POSIX nonroot numeric identity required")
class ArmClientCycleTests(unittest.TestCase):
    def setUp(self):
        self.ws = Workspace(self)

    def test_fresh_sdk_client_per_product_with_one_owner_only_writable_bind(self):
        guest = ScriptedGuest(self.ws)
        rows, evidence = run_arm_cycle(self.ws, guest, [LOOM, BURST])
        names = statuses(rows)
        self.assertEqual(set(names.values()), {"pass"}, names)
        for name in ("network-denial", "install", "uninstall", "inventory", "cleanup",
                     "burst-native-addon-target", "burst-native-addon-load"):
            self.assertEqual(names[f"pacman-client.{BURST}.{name}"], "pass")
        self.assertEqual(len(guest.clients), 2)
        for client, product in zip(guest.clients, (LOOM, BURST)):
            writable = [bind for bind in client._binds if not bind.readonly]
            self.assertEqual(len(writable), 1)
            self.assertEqual((writable[0].source, writable[0].target),
                             (str(self.ws.probe_root / product), archarm_sdk.PROBE_OUTPUT_TARGET))
            readonly = {bind.target: bind.source for bind in client._binds if bind.readonly}
            self.assertEqual(readonly, {"/srv/rs9/pacman": str(self.ws.pacman), "/srv/rs9/keys": str(self.ws.keys),
                                        hcs.ARCHARM_GUEST_SOURCE: str(self.ws.repository / "src")})
            self.assertNotIn(str(self.ws.root / "work"), [bind.source for bind in client._binds])
        self.assertEqual(evidence[BURST]["native_loader"], LOADER)
        self.assertEqual(evidence[BURST]["archarm_client"]["uid"], os.getuid())
        files = [row["path"] for row in evidence[BURST]["archarm_probe_output"]["files"]]
        self.assertEqual(files, sorted(f"{hbc.ARCHARM_BURST_OUTPUT}/{n}" for n in hbc.ARCHARM_BURST_FILES))
        self.assertIs(evidence[BURST]["archarm_probe_output"]["authority"], False)
        self.assertEqual(evidence[LOOM]["archarm_probe_output"]["files"], [])

    def test_probes_enter_as_verified_runner_after_identity_check_never_65534(self):
        guest = ScriptedGuest(self.ws)
        run_arm_cycle(self.ws, guest, [BURST])
        users = [detail[0] for kind, _, detail in guest.events if kind == "exec" and detail[0] is not None]
        self.assertTrue(users)
        self.assertEqual(set(users), {self.ws.user})
        self.assertNotIn(hd.CLIENT_USER, users)
        kinds = [kind if kind != "exec" else ("user-exec" if detail[0] else "root-exec")
                 for kind, _, detail in guest.events]
        self.assertLess(kinds.index("verify-identity"), kinds.index("user-exec"))
        burst_exec = next(detail[1] for kind, _, detail in guest.events
                          if kind == "exec" and detail[0] and "verify_burst_payload" in detail[1][2])
        self.assertIn(repr(hcs.ARCHARM_GUEST_SOURCE), burst_exec[2])
        self.assertEqual(burst_exec[-1], archarm_sdk.PROBE_OUTPUT_TARGET + "/" + hbc.ARCHARM_BURST_OUTPUT)

    def test_no_world_writable_mode_anywhere_on_the_arm_route(self):
        run_arm_cycle(self.ws, ScriptedGuest(self.ws), [LOOM, BURST])
        self.assertEqual(stat.S_IMODE(os.lstat(self.ws.probe_root).st_mode), 0o700)
        entries = list(walk_modes(self.ws.probe_root))
        self.assertTrue(entries)
        for path, info in entries:
            with self.subTest(path=path.name):
                self.assertEqual(info.st_mode & 0o077, 0)
                self.assertEqual((info.st_uid, info.st_gid), (os.getuid(), os.getgid()))

    def test_output_is_ingested_only_after_the_client_exited_quiesced(self):
        guest = ScriptedGuest(self.ws)
        run_arm_cycle(self.ws, guest, [LOOM, BURST])
        for client in guest.clients:
            sequence = [(kind, detail) for kind, owner, detail in guest.events if owner is client]
            kinds = [kind for kind, _ in sequence]
            self.assertEqual(kinds.count("ingest"), 1)
            self.assertLess(kinds.index("exit"), kinds.index("ingest"))
            self.assertEqual(sequence[kinds.index("ingest")][1], "quiesced")

    def test_live_writer_output_is_never_accepted_even_after_the_probe_command_returned(self):
        guest = ScriptedGuest(self.ws, quiesce=False)
        rows, evidence = run_arm_cycle(self.ws, guest, [BURST])
        names = statuses(rows)
        self.assertEqual(names[f"pacman-client.{BURST}.burst-native-addon-target"], "fail")
        self.assertEqual(names[f"pacman-client.{BURST}.burst-native-addon-load"], "fail")
        client_row = next(row for row in rows if row["name"].endswith(".client"))
        self.assertEqual(client_row["reason"], "ARCHARM_EVIDENCE_NOT_QUIESCED")
        self.assertEqual(client_row["stage"], "probe-output-custody")
        self.assertNotIn("native_loader", evidence[BURST])

    def test_unsafe_probe_output_fails_the_loader_gates(self):
        def extra(out):
            (out / "undeclared.json").write_bytes(b"{}")

        def symlink(out):
            os.symlink("/etc/passwd", out / hbc.ARCHARM_BURST_OUTPUT / "linked")

        def world_writable(out):
            os.chmod(out / hbc.ARCHARM_BURST_OUTPUT / hbc.ARCHARM_BURST_FILES[0], 0o606)

        def hard_link(out):
            # Both names are declared, so only the link count can refuse it.
            loader = out / hbc.ARCHARM_BURST_OUTPUT
            (loader / hbc.ARCHARM_BURST_FILES[1]).unlink()
            os.link(loader / hbc.ARCHARM_BURST_FILES[0], loader / hbc.ARCHARM_BURST_FILES[1])

        for writer, reason in ((extra, "ARCHARM_EVIDENCE_UNDECLARED"), (symlink, "ARCHARM_EVIDENCE_UNSAFE"),
                               (world_writable, "ARCHARM_EVIDENCE_OWNER"), (hard_link, "ARCHARM_EVIDENCE_UNSAFE")):
            with self.subTest(writer=writer.__name__):
                ws = Workspace(self)
                rows, _ = run_arm_cycle(ws, ScriptedGuest(ws, live_writer=writer), [BURST])
                names = statuses(rows)
                self.assertEqual(names[f"pacman-client.{BURST}.burst-native-addon-load"], "fail")
                client_row = next(row for row in rows if row["name"].endswith(".client"))
                self.assertEqual(client_row["reason"], reason)

    def test_products_without_declared_output_must_leave_the_tree_empty(self):
        rows, _ = run_arm_cycle(self.ws, ScriptedGuest(
            self.ws, live_writer=lambda out: (out / "result.json").write_bytes(b"{}")), [LOOM])
        client_row = next(row for row in rows if row["name"].endswith(".client"))
        self.assertEqual((client_row["status"], client_row["reason"]), ("fail", "ARCHARM_EVIDENCE_UNDECLARED"))

    def test_install_loader_and_refresh_failures_still_fail(self):
        rows, evidence = run_arm_cycle(self.ws, ScriptedGuest(self.ws, install_code=1), [BURST])
        names = statuses(rows)
        self.assertEqual(names[f"pacman-client.{BURST}.install"], "fail")
        self.assertEqual(names[f"pacman-client.{BURST}.client"], "fail")
        self.assertEqual(names[f"pacman-client.{BURST}.burst-native-addon-load"], "fail")
        self.assertNotIn(f"pacman-client.{BURST}.uninstall", names)
        self.assertEqual(evidence[BURST]["error"], "CLIENT_INSTALL_FAILED")

        ws = Workspace(self)
        failing = lambda out: (2, b'{"loaded":false,"phase":"load","error_name":"Error"}')
        rows, _ = run_arm_cycle(ws, ScriptedGuest(ws, burst=failing), [BURST])
        names = statuses(rows)
        self.assertEqual(names[f"pacman-client.{BURST}.burst-native-addon-target"], "fail")
        self.assertEqual(names[f"pacman-client.{BURST}.client"], "fail")
        self.assertEqual(names[f"pacman-client.{BURST}.uninstall"], "pass")  # cleanup still ran

        ws = Workspace(self)
        rows, evidence = run_arm_cycle(ws, ScriptedGuest(ws, refresh_code=1), [LOOM])
        self.assertEqual(statuses(rows)[f"pacman-client.{LOOM}.client"], "fail")
        self.assertEqual(evidence[LOOM]["error"], "CLIENT_REFRESH_FAILED")

    def test_unexecuted_receipts_cannot_pass_on_the_arm_route(self):
        guest = ScriptedGuest(self.ws)
        original = guest.patches

        def synthetic_patches():
            items = original()
            cls = archarm_sdk.ArchArmClient

            def exec_(client, argv, *, user=None, env=None):
                code, out = guest.respond(client, list(argv), user)
                return CommandReceipt(list(argv), code, out, b"", tool_name=argv[0], executed=False)
            return [*items[:2], patch.object(cls, "exec", exec_), *items[3:]]

        guest.patches = synthetic_patches
        rows, _ = run_arm_cycle(self.ws, guest, [LOOM])
        self.assertNotIn("pass", set(statuses(rows).values()))


@unittest.skipUnless(POSIX_NONROOT, "POSIX nonroot numeric identity required")
class ProbeOutputCustodyTests(unittest.TestCase):
    def setUp(self):
        self.ws = Workspace(self)
        self.identity = hcs.archarm_lease_identity(self.ws.lease)

    def test_probe_root_is_fresh_owner_only_or_an_existing_empty_owner_only_root(self):
        created = hcs.archarm_probe_root(self.ws.probe_root, self.identity)
        self.assertEqual(stat.S_IMODE(os.lstat(created).st_mode), 0o700)
        created.rmdir()
        os.mkdir(self.ws.probe_root, 0o700)
        os.chmod(self.ws.probe_root, 0o700)
        self.assertEqual(hcs.archarm_probe_root(self.ws.probe_root, self.identity), self.ws.probe_root)

    def test_unsafe_probe_roots_are_refused(self):
        target = self.ws.root / "elsewhere"
        target.mkdir(mode=0o700)
        cases = []
        open_root = self.ws.root / "work" / "open"
        open_root.mkdir()
        os.chmod(open_root, 0o755)
        cases.append(open_root)
        full = self.ws.root / "work" / "full"
        full.mkdir(mode=0o700)
        (full / "stale").write_bytes(b"x")
        cases.append(full)
        link = self.ws.root / "work" / "link"
        link.symlink_to(target)
        cases.append(link)
        cases.append(self.ws.root / "missing-parent" / "root")
        for path in cases:
            with self.subTest(path=path.name), self.assertRaises(ContractError) as caught:
                hcs.archarm_probe_root(path, self.identity)
            self.assertEqual(caught.exception.code, "ARCHARM_PROBE_OUTPUT")

    def test_sdk_client_refuses_extra_writable_or_whole_scratch_mounts(self):
        out = hcs.archarm_product_output(hcs.archarm_probe_root(self.ws.probe_root, self.identity), LOOM,
                                         self.identity)
        with self.assertRaises(ContractError) as caught:
            self.ws.lease.client([(str(self.ws.pacman), "/srv/rs9/pacman", True)], out)
        self.assertEqual(caught.exception.code, "ARCHARM_CLIENT_MOUNT_WRITABLE")
        with self.assertRaises(ContractError):
            self.ws.lease.client([(str(self.ws.root / "work"), "/srv/rs9/scratch", False)], out)

    def test_ingestion_requires_quiescence_and_rejects_undeclared_entries(self):
        out = hcs.archarm_product_output(hcs.archarm_probe_root(self.ws.probe_root, self.identity), LOOM,
                                         self.identity)
        client = self.ws.lease.client([], out)
        client._phase = "running"
        with self.assertRaises(ContractError) as caught:
            hcs.archarm_ingest_output(client, self.ws.lease, {})
        self.assertEqual(caught.exception.code, "ARCHARM_EVIDENCE_NOT_QUIESCED")
        client._phase = "quiesced"
        self.assertEqual(hcs.archarm_ingest_output(client, self.ws.lease, {}).files, {})
        (out / hcs._ARCHARM_NO_OUTPUT).write_bytes(b"planted")
        with self.assertRaises(ContractError) as caught:
            hcs.archarm_ingest_output(client, self.ws.lease, {})
        self.assertEqual(caught.exception.code, "ARCHARM_EVIDENCE_SCHEMA")

    def test_a_foreign_client_is_not_joined_to_the_lease(self):
        out = hcs.archarm_product_output(hcs.archarm_probe_root(self.ws.probe_root, self.identity), LOOM,
                                         self.identity)
        other = make_lease(Path(tempfile.mkdtemp(dir=self.ws.root)), self.ws.host)
        foreign = other.client([], out)
        for client in (foreign, SimpleNamespace(image=IMAGE, platform="linux/arm64",
                                                probe_output_target=archarm_sdk.PROBE_OUTPUT_TARGET)):
            with self.subTest(client=type(client).__name__), self.assertRaises(ContractError) as caught:
                hcs.archarm_lease_identity(self.ws.lease, client)
            self.assertEqual(caught.exception.details["reason"], "client-join")


@unittest.skipUnless(POSIX_NONROOT, "POSIX nonroot numeric identity required")
class ContainerSmokeTests(unittest.TestCase):
    def setUp(self):
        self.ws = Workspace(self)
        identity = hcs.archarm_lease_identity(self.ws.lease)
        self.out = hcs.archarm_product_output(hcs.archarm_probe_root(self.ws.probe_root, identity),
                                              "theme-forge-nebular-fusion", identity)
        self.client = self.ws.lease.client([], self.out)
        self.records = [{"source": "authenticated"}]
        self.binding = {"archarm_result": hcs.ARCHARM_RESULT, "family": "pacman", "system": "aarch64-linux",
                        "request_sha256": "b" * 64, "request": {"records": self.records}, "prepared": {}}
        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(patch.object(hcs, "_current_binding", return_value=True))
        stack.enter_context(patch.object(hcs, "_recheck_current_binding", return_value="f" * 64))

    def doc(self, **changes):
        doc = {"schema": hcs.SCHEMA, "request_sha256": "b" * 64, "family": "pacman", "system": "aarch64-linux",
               "uid": os.getuid(), "gid": os.getgid(), "status": "pass", "source_readback_sha256": "f" * 64,
               "result": {"sidecar": {"verified": True},
                          "scenarios": [{"scenario": "B", "receipt_sha256": "1" * 64, "executable_sha256": "2" * 64}],
                          "source_bindings_sha256": digest(canonical(self.records))}}
        doc.update(changes)
        return doc

    def ingest(self, doc):
        smoke = self.out / hcs.ARCHARM_SMOKE_OUTPUT
        smoke.mkdir(mode=0o700)
        fd = os.open(smoke / "result.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(canonical(doc))
        self.client._phase = "quiesced"
        return hcs.archarm_ingest_output(self.client, self.ws.lease, hcs.archarm_smoke_declarations())

    def accept(self, evidence, receipt_code=0):
        receipt = CommandReceipt(["python3"], receipt_code, b"", b"", executed=True)
        return hcs.accept_archarm_container_nebular(self.binding, receipt, evidence, lease=self.ws.lease)

    def test_result_is_accepted_only_from_held_post_quiescence_evidence(self):
        accepted = self.accept(self.ingest(self.doc()))
        self.assertEqual(accepted["filesystem"], "installed-client")
        self.assertEqual(accepted["source_readback_sha256"], "f" * 64)

    def test_legacy_uid_or_foreign_gid_in_the_receipt_is_refused(self):
        for changes in ({"uid": 65534}, {"gid": os.getgid() + 1}, {"uid": str(os.getuid())}):
            with self.subTest(changes=changes):
                ws_out = self.out / hcs.ARCHARM_SMOKE_OUTPUT
                if ws_out.exists():
                    (ws_out / "result.json").unlink()
                    ws_out.rmdir()
                with self.assertRaises(ContractError) as caught:
                    self.accept(self.ingest(self.doc(**changes)))
                self.assertEqual(caught.exception.code, "SMOKE_OUTPUT")

    def test_unheld_evidence_missing_result_and_failed_receipt_still_fail(self):
        with self.assertRaises(ContractError) as caught:
            self.accept({hcs.ARCHARM_RESULT: {"value": canonical(self.doc())}})
        self.assertEqual(caught.exception.code, "SMOKE_OUTPUT")
        self.client._phase = "quiesced"
        empty = hcs.archarm_ingest_output(self.client, self.ws.lease, hcs.archarm_smoke_declarations())
        with self.assertRaises(ContractError) as caught:
            self.accept(empty)
        self.assertEqual(caught.exception.details.get("missing_path"), "output/result.json")
        self.client._phase = "running"
        with self.assertRaises(ContractError) as caught:
            self.accept(self.ingest(self.doc()), receipt_code=2)
        self.assertEqual(caught.exception.details.get("exit_code"), 2)

    def test_run_refuses_a_legacy_writable_output_binding(self):
        legacy = {**self.binding, "output": self.out}
        with self.assertRaises(ContractError) as caught:
            hcs.run_archarm_container_nebular(self.client, legacy, lease=self.ws.lease)
        self.assertEqual(caught.exception.code, "SMOKE_INPUT")

    def test_legacy_output_configuration_is_unchanged_and_refuses_the_runner_identity(self):
        fake = SimpleNamespace(exec=lambda argv, **kw: CommandReceipt(argv, 0, b"", b""))
        hcs.configure_container_output(fake, user="65534:65534")
        with self.assertRaises(ContractError):
            hcs.configure_container_output(fake, user=self.ws.user)


@unittest.skipUnless(POSIX_NONROOT, "POSIX nonroot numeric identity required")
class GuestMainTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(os.path.realpath(tmp.name))
        (self.root / "guest").mkdir()
        (self.root / "probe").mkdir(mode=0o700)
        (self.root / "home").mkdir(mode=0o700)
        previous = os.umask(0o022)
        os.umask(previous)
        self.addCleanup(os.umask, previous)
        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(patch.object(hcs, "GUEST", self.root / "guest"))
        stack.enter_context(patch.object(hcs, "ARCHARM_PROBE_OUTPUT_GUEST", str(self.root / "probe")))
        stack.enter_context(patch.object(hcs, "ARCHARM_GUEST_WORK", str(self.root / "home" / "rs9-smoke")))

    def test_identity_mismatch_writes_nothing(self):
        identity = (os.getuid() + 1, os.getgid())
        self.assertEqual(hcs.guest_main(expected_request_sha256="b" * 64, archarm_identity=identity), 2)
        self.assertEqual(os.listdir(self.root / "probe"), [])
        self.assertEqual(hcs.guest_main(expected_request_sha256=None,
                                        archarm_identity=(os.getuid(), os.getgid())), 2)
        self.assertEqual(os.listdir(self.root / "probe"), [])

    def test_verified_identity_writes_an_owner_only_result_with_uid_and_gid(self):
        code = hcs.guest_main(expected_request_sha256="b" * 64, archarm_identity=(os.getuid(), os.getgid()))
        self.assertEqual(code, 2)  # no request input: still a failure
        smoke = self.root / "probe" / hcs.ARCHARM_SMOKE_OUTPUT
        self.assertEqual(stat.S_IMODE(os.lstat(smoke).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.lstat(smoke / "result.json").st_mode), 0o600)
        doc = json.loads((smoke / "result.json").read_bytes())
        self.assertEqual((doc["uid"], doc["gid"], doc["status"], doc["code"]),
                         (os.getuid(), os.getgid(), "fail", "SMOKE_RESOURCE"))
        self.assertEqual(sorted(os.listdir(self.root / "probe")), [hcs.ARCHARM_SMOKE_OUTPUT])


@unittest.skipUnless(POSIX_NONROOT, "POSIX nonroot numeric identity required")
class BurstClientTests(unittest.TestCase):
    def setUp(self):
        self.ws = Workspace(self)

    def test_legacy_burst_proof_is_unchanged(self):
        calls = []

        def exec_(argv, *, user=None):
            calls.append((argv, user))
            return CommandReceipt(argv, 0, json.dumps({"status": "pass", "proof": "installed-released-loader-self-test",
                                                       "loaded": True}).encode(), b"", executed=True)

        scratch = self.ws.root / "legacy" / BURST
        with patch("rs9.hosted_burst_clients.validate_load_receipt", return_value=dict(LOADER)):
            hbc.verify_client_burst(SimpleNamespace(exec=exec_), BURST_RECORD, "x86_64-linux", scratch,
                                    user=hd.CLIENT_USER)
        self.assertEqual(stat.S_IMODE(os.lstat(scratch).st_mode), 0o777)
        argv, user = calls[0]
        self.assertEqual(user, "65534:65534")
        self.assertIn("sys.path.insert(0,'/rs9-source');", argv[2])
        self.assertEqual(argv[-1], str(scratch))

    def test_arm_burst_proof_has_no_host_directory_and_runs_as_the_runner(self):
        identity = hcs.archarm_lease_identity(self.ws.lease)
        out = hcs.archarm_product_output(hcs.archarm_probe_root(self.ws.probe_root, identity), BURST, identity)
        client = self.ws.lease.client([], out)
        calls = []

        def exec_(client_self, argv, *, user=None, env=None):
            calls.append((argv, user))
            return CommandReceipt(argv, 0, json.dumps({"status": "pass", "proof": "installed-released-loader-self-test",
                                                       "loaded": True}).encode(), b"", executed=True)

        with patch.object(archarm_sdk.ArchArmClient, "exec", exec_), \
                patch("rs9.hosted_burst_clients.validate_load_receipt", return_value=dict(LOADER)):
            self.assertEqual(hbc.run_archarm_client_burst(client, BURST_RECORD, "aarch64-linux", lease=self.ws.lease),
                             LOADER)
            with self.assertRaises(ContractError) as caught:
                hbc.run_archarm_client_burst(client, BURST_RECORD, "x86_64-linux", lease=self.ws.lease)
            self.assertEqual(caught.exception.code, "BURST_NATIVE_TARGET")
            with self.assertRaises(ContractError) as caught:
                hbc.run_archarm_client_burst(SimpleNamespace(exec=exec_), BURST_RECORD, "aarch64-linux",
                                             lease=self.ws.lease)
            self.assertEqual(caught.exception.code, "ARCHARM_CLIENT_LEASE")
        argv, user = calls[0]
        self.assertEqual(user, self.ws.user)
        self.assertIn("sys.path.insert(0,'/srv/rs9/rs9-source');", argv[2])
        self.assertEqual(argv[-1], "/srv/rs9/probe-output/" + hbc.ARCHARM_BURST_OUTPUT)
        self.assertEqual(os.listdir(out), [])
        self.assertEqual(len(calls), 1)


@unittest.skipUnless(POSIX_NONROOT, "POSIX nonroot numeric identity required")
class LegacyDefaultTests(unittest.TestCase):
    def test_x86_64_pacman_default_route_is_unchanged(self):
        ws = Workspace(self)
        (ws.pacman / "x86_64").mkdir()
        host = hd.RecordingRunner(MockCommandRunner(available_tools={"docker": "/usr/bin/docker"}))
        probe = ws.root / "legacy-probe"
        with patch("rs9.hosted_deb.execute_probes", return_value=[]), \
                patch.object(hd.ClientContainer, "inventory", return_value={}), \
                patch("rs9.hosted_burst_clients.verify_client_burst", return_value={"artifact": "linux-x64-gnu"}) as burst, \
                patch.object(archarm_sdk.ArchArmSDK, "client", side_effect=AssertionError("sdk used")):
            rows, evidence = hd.client_cycle(
                host, hd.pacman_spec(ws.pacman, ws.keys, FPR), image="img", platform="linux/amd64", products=[BURST],
                repository=ws.repository, prefix="pacman-client", system="x86_64-linux", burst_record=BURST_RECORD,
                burst_scratch=probe, generation=CURRENT_GENERATION)
        calls = [call["argv"] for call in host.inner.calls]
        started = next(argv for argv in calls if argv[:3] == ["docker", "run", "-d"])
        self.assertIn(f"{ws.repository / 'src'}:/rs9-source:ro", started)
        self.assertIn(f"{probe}:{probe}", started)
        network = next(argv for argv in calls if argv[:2] == ["docker", "exec"] and "socket" in argv[-1])
        self.assertEqual(network[network.index("--user") + 1], "65534:65534")
        self.assertEqual(burst.call_args.kwargs["user"], hd.CLIENT_USER)
        self.assertEqual(burst.call_args.args[3], probe / BURST)
        self.assertEqual(stat.S_IMODE(os.lstat(probe).st_mode), 0o755)
        self.assertNotIn("archarm_client", evidence[BURST])
        self.assertEqual(calls[-1][:3], ["docker", "rm", "-f"])
        self.assertNotIn("pass", set(statuses(rows).values()))  # synthetic receipts never pass


@unittest.skipUnless(POSIX_NONROOT, "POSIX nonroot numeric identity required")
class TamperCycleTests(unittest.TestCase):
    KINDS = ("package", "index", "signature", "wrongkey")

    def setUp(self):
        self.ws = Workspace(self)
        self.tamper = self.ws.root / "tamper"
        self.tamper.mkdir()
        os.chmod(self.tamper, 0o755)

    def run_tamper(self, guest, **overrides):
        kwargs = dict(image=self.ws.lease.image, platform="linux/arm64", product=LOOM, work=self.tamper,
                      arch="aarch64", wrong_signer=SimpleNamespace(), kinds=self.KINDS, prefix="pacman-trust",
                      positive_control={"stages": {}}, sdk_lease=self.ws.lease)
        kwargs.update(overrides)
        spec_for = lambda dirs: self.ws.spec(pacman=dirs["pacman"])
        with contextlib.ExitStack() as stack:
            for item in guest.patches():
                stack.enter_context(item)
            stack.enter_context(patch("rs9.hosted_deb.validate_positive_control", return_value=(True, None)))
            stack.enter_context(patch.object(hd, "ClientContainer", side_effect=AssertionError("generic client used")))
            return hd.tamper_cycle(self.ws.host, spec_for, "pacman", {"pacman": self.ws.pacman}, **kwargs)

    def test_lease_is_required_for_aarch64_pacman_tamper(self):
        with self.assertRaises(ContractError) as caught:
            self.run_tamper(ScriptedGuest(self.ws), sdk_lease=None)
        self.assertEqual(caught.exception.details["reason"], "lease-missing")
        self.assertEqual(self.ws.host.receipts, [])
        with self.assertRaises(ContractError) as caught:
            self.run_tamper(ScriptedGuest(self.ws), sdk_lease={"image": IMAGE})
        self.assertEqual(caught.exception.details["reason"], "lease-type")

    def test_shared_x86_64_tamper_copy_cannot_pass_on_arm(self):
        def wrong_arch(family, kind, dirs, dest, **kwargs):
            import shutil
            copy = dest / "pacman"
            shutil.copytree(dirs["pacman"], copy)
            target = copy / "x86_64" / "rs9.db"
            target.parent.mkdir(exist_ok=True)
            target.write_bytes(b"inert wrong-architecture metadata")
            return {"pacman":copy}
        guest = ScriptedGuest(self.ws)
        with patch("rs9.hosted_deb.tamper_family_copy", side_effect=wrong_arch):
            rows = self.run_tamper(guest)
        self.assertEqual([row["status"] for row in rows], ["fail"] * 4)
        self.assertTrue(all(row["reason"] == "ARCHARM_TAMPER_MUTATION" for row in rows))
        self.assertEqual(guest.clients, [])

    def test_actual_tamper_helper_changes_only_the_requested_architecture(self):
        signer = SimpleNamespace(detach_sign=lambda data, **kwargs: b"inert wrong-key signature")
        arm = self.ws.pacman / "aarch64"
        for name in (LOOM + "-0.5.0-1-any.pkg.tar.zst", "rs9.db.tar.gz", "rs9.db.tar.gz.sig"):
            (arm / name).write_bytes(b"inert public fixture bytes")
        (self.ws.pacman / "x86_64").mkdir()
        (self.ws.pacman / "x86_64" / "reference.txt").write_bytes(b"unchanged")
        original = {p.relative_to(self.ws.pacman).as_posix():p.read_bytes()
                    for p in self.ws.pacman.rglob("*") if p.is_file()}
        for kind in self.KINDS:
            target = self.tamper / kind
            target.mkdir()
            changed = hd.tamper_family_copy("pacman", kind, {"pacman":self.ws.pacman}, target,
                                           arch="aarch64", wrong_signer=signer, product=LOOM)["pacman"]
            after = {p.relative_to(changed).as_posix():p.read_bytes()
                     for p in changed.rglob("*") if p.is_file()}
            differences = {name for name in set(original) | set(after) if original.get(name) != after.get(name)}
            self.assertTrue(differences)
            self.assertTrue(all(name.startswith("aarch64/") for name in differences))

    def test_each_kind_uses_a_fresh_sdk_client_with_read_only_tampered_inputs(self):
        def aarch64_copy(family, kind, dirs, dest, *, arch, wrong_signer, product):
            copy = dest / "pacman"
            import shutil
            shutil.copytree(dirs["pacman"], copy)
            target = copy / arch / "rs9.db"
            target.write_bytes(target.read_bytes() + b"\x00")
            return {"pacman": copy}

        guest = ScriptedGuest(self.ws, refresh_code=1, install_code=1)
        with patch("rs9.hosted_deb.tamper_family_copy", side_effect=aarch64_copy):
            rows = self.run_tamper(guest)
        self.assertEqual(len(rows), 4)
        self.assertEqual(len(guest.clients), 4)
        for client, kind in zip(guest.clients, self.KINDS):
            writable = [bind for bind in client._binds if not bind.readonly]
            probe = self.tamper / f"tamper-pacman-{kind}-probe-output"
            self.assertEqual([(b.source, b.target) for b in writable], [(str(probe), archarm_sdk.PROBE_OUTPUT_TARGET)])
            self.assertEqual(stat.S_IMODE(os.lstat(probe).st_mode), 0o700)
            readonly = {bind.target: bind.source for bind in client._binds if bind.readonly}
            self.assertEqual(readonly["/srv/rs9/pacman"], str(self.tamper / f"tamper-pacman-{kind}" / "pacman"))
        self.assertTrue(all(detail[0] is None for kind, _, detail in guest.events if kind == "exec"))

    def test_mutation_outside_the_aarch64_tree_is_refused(self):
        def wrong_copy(family, kind, dirs, dest, *, arch, wrong_signer, product):
            copy = dest / "pacman"
            import shutil
            shutil.copytree(dirs["pacman"], copy)
            (copy / "x86_64").mkdir()
            (copy / "x86_64" / "rs9.db").write_bytes(b"tampered elsewhere")
            return {"pacman": copy}

        guest = ScriptedGuest(self.ws)
        with patch("rs9.hosted_deb.tamper_family_copy", side_effect=wrong_copy):
            rows = self.run_tamper(guest)
        self.assertEqual({row["reason"] for row in rows}, {"ARCHARM_TAMPER_MUTATION"})
        self.assertEqual(guest.clients, [])


if __name__ == "__main__":
    unittest.main()
