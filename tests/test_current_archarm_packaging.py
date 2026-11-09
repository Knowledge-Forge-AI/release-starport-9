"""Pure control-flow tests for rs9.current_archarm_packaging.

Every SDK, canonical-any, builder, fixture and client seam is a fake shaped like
the peer contracts (``rs9.archarm_sdk`` records/lifecycle, ``rs9.current_pacman_any``
held token and canonical witness bytes). No process, container, GnuPG, pacman or
network operation runs. Passing gates here prove only the producer's sequencing
and fail-closed policy, never native qualification.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

from rs9 import current_archarm_packaging as arm
from rs9.build_native import CommandReceipt, CommandRunner
from rs9.current_generation import CURRENT_GENERATION, HISTORICAL_GENERATION
from rs9.errors import ContractError
from rs9.release_core import digest
from rs9.scratch import canonical

BURST, LOOM, SOLAR, NEBULAR = arm.BURST, arm.LOOM, arm.SOLAR, arm.NEBULAR
VERSIONS = {BURST: "0.6.2", LOOM: "0.4.1", SOLAR: "0.2.2", NEBULAR: "0.7.1"}
# The exact argv build_pacman.build_pacman_candidate issues today (build_pacman.py makepkg_cmd).
LEGACY_MAKEPKG = ["makepkg", "--nodeps", "--noextract", "--force", "--clean"]
POLICY_MAKEPKG = ["makepkg", "--noextract", "--force", "--clean"]
REPO_ROOT = Path(__file__).resolve().parents[1]
RUN_ID = 4242


def receipt(argv, harness, exit_code=0, out=b""):
    return CommandReceipt(argv, exit_code, out, b"", tool_name=argv[0], executed=harness.executed)


class FakeHost(CommandRunner):
    def __init__(self, harness):
        self.h, self.calls = harness, []

    def which(self, tool_name):
        return "/usr/bin/" + tool_name

    def run(self, argv, *, cwd=None, env=None):
        self.calls.append(list(argv))
        out = str(self.h.socketdir).encode() + b"\n" if Path(argv[0]).name == "gpgconf" and "--list-dirs" in argv else b""
        return receipt(argv, self.h, out=out)


class FakeBuilderRunner(CommandRunner):
    def __init__(self, harness, product_dir):
        self.h, self.product_dir = harness, Path(product_dir)

    def which(self, tool_name):
        return "/usr/bin/" + tool_name

    def run(self, argv, *, cwd=None, env=None):
        if argv[0] == "repo-add":
            raise AssertionError("SDK builder role refuses repo-add (BUILDER_DENIED_TOOLS)")
        self.h.builder_argv.append((self.product_dir.name, list(argv)))
        return receipt(argv, self.h)


class FakeRepoRunner(CommandRunner):
    def __init__(self, harness, assembly):
        self.h, self.assembly = harness, Path(assembly)

    def which(self, tool_name):
        return "/usr/bin/" + tool_name

    def run(self, argv, *, cwd=None, env=None):
        assert env is None
        self.h.repo_argv.append(list(argv))
        database = Path(argv[1])
        base = database.name[: -len(".db.tar.gz")]
        for suffix in ("db", "files"):
            archive = database.parent / f"{base}.{suffix}.tar.gz"
            archive.write_bytes(b"repo-" + suffix.encode())
            os.chmod(archive, 0o644)
            link = database.parent / f"{base}.{suffix}"
            if not link.is_symlink():
                link.symlink_to(archive.name)
        return receipt(argv, self.h, exit_code=self.h.repo_exit if base == "rs9" else 0)


class FakeLease:
    """Shaped like archarm_sdk.ArchArmSDK: eager __enter__, strict __exit__, closed records."""

    platform = "linux/arm64"

    def __init__(self, harness, uid, gid):
        self.h, self.uid, self.gid = harness, uid, gid
        self.state, self.cleanup_complete, self.host_receipts = "new", None, 0
        self.builder_calls, self.repository_calls = [], []

    @property
    def image(self):
        assert self.state == "ready", "image is readable only while the lease is ready"
        return "sha256:" + "c" * 64

    @property
    def records(self):
        if self.h.records_unreadable:
            raise ContractError("ARCHARM_LEASE_STATE", "unreadable")
        return {"schema": "rs9.archarm-sdk-lease.v1", "generation": CURRENT_GENERATION, "platform": self.platform,
                "state": self.state, "runId": str(RUN_ID), "runAttempt": 1, "sourceSha": "a" * 40,
                "identity": {"uid": self.uid, "gid": self.gid, "guestAccount": "rs9builder", "guestHome": "/tmp/home"},
                "flags": {"nativeArmHost": True, "sdkImageCommitted": True, "installerRemoved": True},
                "digests": {"rootfsSha256": self.h.selected_inputs["rootfs_sha256"],
                            "rootfsPinSha256": self.h.selected_inputs["rootfs_pin_sha256"],
                            "packagePinsSha256": (self.h.reported_pin_digest
                                or self.h.selected_inputs["package_pins_sha256"])},
                "pinsMatchQualifiedOrigin": self.h.pins_qualified, "hostReceiptCount": self.host_receipts,
                "cleanupComplete": self.cleanup_complete,
                "assertions": {"signingSecretsUsed": False, "publicationAuthority": False,
                               "productionKeysAuthorized": False, "productQualification": False}}

    def __enter__(self):
        self.h.events.append("sdk-enter")
        if self.h.host.run(["docker", "version"]).executed:
            self.host_receipts += 1
        if self.h.sdk_enter_error is not None:
            self.state, self.cleanup_complete = "failed", True
            raise self.h.sdk_enter_error
        self.state = "ready"
        return self

    def __exit__(self, *exc):
        self.h.events.append("sdk-exit")
        self.cleanup_complete = self.h.sdk_cleanup_complete
        self.state = "closed" if self.cleanup_complete else "retained"
        if self.h.sdk_exit_error is not None:
            raise self.h.sdk_exit_error
        return False

    def builder_runner(self, product_dir, public_sources):
        self.builder_calls.append((Path(product_dir), tuple(public_sources)))
        return FakeBuilderRunner(self.h, product_dir)

    def repository_runner(self, assembly):
        self.repository_calls.append(Path(assembly))
        return FakeRepoRunner(self.h, assembly)

    def client(self, mounts, probe_output):
        raise AssertionError("client containers are driven only through client_cycle/tamper_cycle")


class FakeReader:
    def __init__(self, root, *, runner=None):
        self.root = Path(root)


class FakeAny:
    """Shaped like current_pacman_any.CanonicalAny: re-verified files, witness bytes."""

    def __init__(self, harness, files):
        self.h, self._files, self.closed = harness, files, False

    @property
    def files(self):
        return types.MappingProxyType(dict(self._files))

    def verify(self):
        for pid, path in self._files.items():
            if digest(path.read_bytes()) != self.h.imported[pid]:
                raise ContractError("CANONICAL_ANY_REPLICA", "Imported replica bytes or identity changed")

    def witness_record(self):
        return self.h.witness_factory(self._files)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.closed = True
        self.h.events.append("any-exit")


class FakeFixture:
    harness = None

    def __init__(self, *, scratch_dir=None, user_id="", gpg_binary=None):
        h = FakeFixture.harness
        role = "wrong" if "WRONG" in user_id else "primary"
        h.events.append("fixture:" + role)
        self.homedir = Path(scratch_dir)
        self.gpg = str(h.tools / "gpg")
        self.primary_fingerprint = ("B" if role == "wrong" else "A") * 40
        self.public_key_bytes = b"-----BEGIN PGP PUBLIC KEY BLOCK-----\nfixture\n-----END PGP PUBLIC KEY BLOCK-----\n"
        self.public_key_binary = b"\x99fixture-public"
        h.fixtures.append(self)

    def detach_sign(self, data, *, armor=True):
        return b"SIG:" + self.primary_fingerprint.encode() + b":" + digest(data).encode()

    def verify(self, data, signature):
        if signature != self.detach_sign(data):
            raise ContractError("VERIFICATION_FAILED", "Fake signature rejected")
        return {"status": "valid"}

    def close(self):
        FakeFixture.harness.events.append("fixture-close")


def default_witness(files):
    return canonical({
        "schema": "rs9.current-pacman-any-reuse-witness.v1alpha1", "role": "reuse-witness",
        "derivation": "none-original-bytes-reused", "construction_authority": "pacman/x86_64-linux",
        "production_enabled": False, "publication_authority": False,
        "files": {pid: {"name": path.name, "sha256": digest(path.read_bytes()), "size": len(path.read_bytes()),
                        "architecture": "any", "replica_path": "canonical-any/files/" + path.name}
                  for pid, path in files.items()}})


class Harness:
    def __init__(self, test):
        self.test = test
        previous_umask = os.umask(0o022)
        test.addCleanup(os.umask, previous_umask)
        tmp = tempfile.TemporaryDirectory()
        test.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name).resolve()
        self.repository = self.root / "repo"
        (self.repository / "src").mkdir(parents=True)
        self.scratch = self.root / "lane-work"
        self.scratch.mkdir()
        self.tools = self.root / "tools"
        self.tools.mkdir()
        (self.tools / "gpg").write_bytes(b"")
        (self.tools / "gpgconf").write_bytes(b"")
        self.socketdir = self.root / "sockets"
        self.socketdir.mkdir()
        self.events, self.fixtures, self.imported = [], [], {}
        self.builder_argv, self.repo_argv, self.build_calls, self.npm_calls = [], [], [], []
        self.spec_calls, self.client_kwargs, self.tamper_kwargs = [], None, None
        self.sdk_calls = []
        self.selected_inputs = dict(arm.QUALIFIED_INPUTS)
        self.reported_pin_digest = None
        self.executed = True
        self.repo_exit = 0
        self.makepkg_argv = POLICY_MAKEPKG
        self.package_mode = 0o644
        self.any_error = None
        self.files_factory = None
        self.witness_factory = default_witness
        self.pins_qualified = True
        self.records_unreadable = False
        self.sdk_enter_error = None
        self.sdk_exit_error = None
        self.sdk_cleanup_complete = True
        self.client_hook = None
        self.lease = None
        self.host = FakeHost(self)
        self.captures = [(types.SimpleNamespace(pid=pid), {"project": {"id": pid}, "version": VERSIONS[pid]}, None)
                         for pid in (BURST, LOOM, SOLAR, NEBULAR)]
        self.context = {
            "generation": CURRENT_GENERATION, "family": "pacman", "system": "aarch64-linux",
            "repository": self.repository, "scratch": self.scratch, "captures": self.captures,
            "client": object(), "binding": {"source_commit": "a" * 40, "checkout_binding": "hosted:" + "a" * 40},
            "pins": {}, "authentication_sha256": "b" * 64, "upstream": {},
            "producer_provenance": {"source_commit": "a" * 40, "run_id": RUN_ID, "attempt": 1},
            "runner": self.host}

    # ---- peer fakes

    def acquire_sdk(self, *, host, workspace, context, uid, gid, input_profile):
        self.sdk_calls.append({"workspace": Path(workspace), "existed": Path(workspace).exists(),
                               "context": dict(context), "uid": uid, "gid": gid, "host": host,
                               "input_profile": input_profile})
        if input_profile == "successor-20261109":
            from rs9._archarm_support.successor_20261109 import INPUTS
            self.selected_inputs = dict(INPUTS)
        else:
            self.test.assertEqual(input_profile, "historical")
        self.lease = FakeLease(self, uid, gid)
        return self.lease

    def acquire_any(self, context, client, workspace):
        self.events.append("any-acquire")
        self.test.assertIs(type(client), FakeReader)
        self.test.assertEqual(client.root, self.repository)
        self.test.assertEqual(Path(workspace), self.scratch)
        self.test.assertEqual(list(Path(workspace).iterdir()), [])
        if self.any_error is not None:
            raise self.any_error
        output = Path(workspace) / "canonical-any/files"
        output.mkdir(parents=True)
        files = {}
        for pid in (LOOM, SOLAR):
            path = output / f"{pid}-{VERSIONS[pid]}-1-any.pkg.tar.zst"
            path.write_bytes(b"canonical-x86_64-any:" + pid.encode())
            files[pid] = path
            self.imported[pid] = digest(path.read_bytes())
        if self.files_factory is not None:
            return self.files_factory(files, output)
        return FakeAny(self, files)

    def fake_build(self, capture, intent, arch, scratch_dir, *, distro="arch", revision=1,
                   offline_npm_archives=None, runner=None, generation=HISTORICAL_GENERATION):
        pid, version, work = intent["project"]["id"], intent["version"], Path(scratch_dir)
        self.build_calls.append({"product": pid, "arch": arch, "generation": generation, "work": work})
        self.test.assertEqual(list(work.iterdir()), [])
        pkg_work = work / "pacman" / pid
        pkg_work.mkdir(parents=True)
        self.test.assertIsNotNone(runner.which("makepkg"))
        self.test.assertIsNotNone(runner.which("repo-add"))
        if pid == BURST:
            runner.run(["pacman", "-Qo", "--quiet", "/usr/lib/libc.so.6"])
        made = runner.run(list(self.makepkg_argv), cwd=pkg_work,
                          env={"SOURCE_DATE_EPOCH": "1767225600", "PKGEXT": ".pkg.tar.zst"})
        if made.exit_code:
            raise ContractError("BUILD_FAILED", "makepkg failed")
        repo_dir = work / "repo" / arch
        repo_dir.mkdir(parents=True)
        package = repo_dir / f"{pid}-{version}-1-{arch}.pkg.tar.zst"
        package.write_bytes(b"native-aarch64:" + pid.encode())
        os.chmod(package, self.package_mode)
        runner.run(["repo-add", str(repo_dir / "custom.db.tar.gz"), str(package)], cwd=repo_dir)
        data = package.read_bytes()
        manifest = {"project": pid, "version": version, "architecture": arch,
                    "package_sha256": digest(data), "package_size": len(data)}
        (work / "pacman-manifest.json").write_bytes(json.dumps(manifest).encode())
        return {"manifest": manifest, "package_path": package}

    def fake_npm(self, capture, product_id, scratch, inputs=None, client=None):
        self.npm_calls.append((product_id, Path(scratch)))
        return None

    def fake_smoke(self, capture, captures, client, scratch, label=None):
        return {"prepared": True}

    def fake_pacman_spec(self, pacman_dir, keys_dir, fingerprint, *, architecture="x86_64"):
        self.spec_calls.append({"dir": Path(pacman_dir), "keys": Path(keys_dir), "architecture": architecture})
        return {"family": "pacman", "mounts": [(str(pacman_dir), "/srv/rs9/pacman", False),
                                               (str(keys_dir), "/srv/rs9/keys", False)]}

    def fake_client_cycle(self, host, spec, *, image, platform, products, repository, prefix, smoke=None,
                          system=None, burst_record=None, burst_scratch=None, generation=HISTORICAL_GENERATION,
                          sdk_lease=None):
        self.client_kwargs = {"image": image, "platform": platform, "products": list(products), "spec": spec,
                              "prefix": prefix, "system": system, "generation": generation, "sdk_lease": sdk_lease}
        host.run(["docker", "exec", "fake-sdk-client", "true"])
        rows = [{"name": f"{prefix}.{p}.install", "status": "pass"} for p in products]
        rows += [{"name": f"{prefix}.{BURST}.burst-native-addon-target", "status": "pass"},
                 {"name": f"{prefix}.{BURST}.burst-native-addon-load", "status": "pass"}]
        if self.client_hook is not None:
            self.client_hook(rows)
        return rows, {products[0]: {"positive_control": {"stages": {}}}}

    def fake_tamper_cycle(self, host, spec_for, family, dirs, *, image, platform, product, work, arch,
                          wrong_signer, kinds, prefix, positive_control=None, sdk_lease=None):
        self.tamper_kwargs = {"family": family, "dirs": dict(dirs), "arch": arch, "product": product,
                              "wrong": wrong_signer, "kinds": tuple(kinds), "sdk_lease": sdk_lease,
                              "spec": spec_for(dirs)}
        return [{"name": f"{prefix}.tamper.{kind}", "status": "pass"} for kind in kinds]

    # ---- activation

    def start(self, *, spec=None):
        sdk_module = types.ModuleType("rs9.archarm_sdk")
        sdk_module.acquire_sdk = self.acquire_sdk
        any_module = types.ModuleType("rs9.current_pacman_any")
        any_module.acquire_canonical_any = self.acquire_any
        any_module.ActionsArtifactReader = FakeReader
        FakeFixture.harness = self
        self.legacy = []

        def legacy(name):
            def refuse(*args, **kwargs):
                self.legacy.append(name)
                raise AssertionError("legacy route used: " + name)
            return refuse

        patches = [
            patch.dict(sys.modules, {"rs9.archarm_sdk": sdk_module, "rs9.current_pacman_any": any_module}),
            patch("rs9.hosted_deb.client_cycle", self.fake_client_cycle),
            patch("rs9.hosted_deb.tamper_cycle", self.fake_tamper_cycle),
            patch("rs9.hosted_deb.pacman_spec", spec or self.fake_pacman_spec),
            patch("rs9.hosted_deb._burst_release_record", lambda captures, system: {"system": system}),
            patch("rs9.hosted_deb.provision_image", legacy("provision_image")),
            patch("rs9.hosted_deb.ContainerRunner", legacy("ContainerRunner")),
            patch("rs9.hosted_native.provision", legacy("provision")),
            patch("rs9.build_pacman.build_pacman_candidate", self.fake_build),
            patch("rs9.npm_deps.resolve_offline_npm_archives", self.fake_npm),
            patch("rs9.hosted_smoke.prepare_smoke", self.fake_smoke),
            patch("rs9.release_core.authenticated_record_hash", lambda capture: "0" * 64),
            patch("rs9.signing_fixture.SigningFixture", FakeFixture),
            patch.object(arm, "runner_identity", lambda: (os.getuid(), os.getgid())),
            patch.object(arm, "QUIESCENCE_POLLS", 1),
        ]
        for item in patches:
            item.start()
            self.test.addCleanup(item.stop)
        return self


def gate(result, name):
    return next(row for row in result["gates"] if row["name"] == name)


class CurrentArchArmProducerTests(unittest.TestCase):
    def required(self, result):
        return {name: gate(result, name)["status"] for name in arm.REQUIRED_GATES}

    def test_nebular080_selects_exact_successor_and_records_its_input_identity(self):
        from rs9._archarm_support.successor_20261109 import INPUTS, PROFILE
        h = Harness(self).start()
        next(intent for _, intent, _ in h.captures if intent["project"]["id"] == NEBULAR)["version"] = "0.8.0"
        result = arm.execute(h.context)
        self.assertEqual(set(self.required(result).values()), {"pass"}, self.required(result))
        self.assertEqual(h.sdk_calls[0]["input_profile"], PROFILE)
        self.assertEqual(result["details"]["environment"]["qualified_inputs"], dict(INPUTS))
        self.assertFalse(result["details"]["environment"]["qualified_inputs"]["refresh_allowed"])

    def test_unknown_or_missing_nebular_version_refuses_before_any_sdk_acquisition(self):
        for version in (None, "0.9.0", "0.8", "0.8.1"):
            with self.subTest(version=version):
                h = Harness(self).start()
                intent = next(intent for _, intent, _ in h.captures if intent["project"]["id"] == NEBULAR)
                intent["version"] = version
                with self.assertRaises(ContractError) as caught:
                    arm.execute(h.context)
                self.assertEqual(caught.exception.code, "CONTEXT_INVALID")
                self.assertEqual(h.sdk_calls, [])
                self.assertEqual(h.events, [])

    def test_successor_cannot_accept_historical_or_unknown_package_digest(self):
        for digest in (arm.QUALIFIED_INPUTS["package_pins_sha256"], "f" * 64):
            with self.subTest(digest=digest):
                h = Harness(self).start()
                next(intent for _, intent, _ in h.captures if intent["project"]["id"] == NEBULAR)["version"] = "0.8.0"
                h.reported_pin_digest = digest
                result = arm.execute(h.context)
                self.assertEqual(gate(result, arm.ENV_GATE)["status"], "fail")
                self.assertEqual(h.build_calls, [])
                self.assertIn("sdk-exit", h.events)

    def test_required_gate_names_match_the_source_contract(self):
        lanes = json.loads((REPO_ROOT / "operators/theme-forge-current-202610/hosted-lanes.json").read_bytes())
        row = next(l for l in lanes["lanes"] if (l["lane"], l["system"]) == ("pacman", "aarch64-linux"))
        self.assertEqual(tuple(row["required_gates"]), arm.REQUIRED_GATES)

    def test_success_builds_two_natives_and_reuses_canonical_any(self):
        h = Harness(self).start()
        result = arm.execute(h.context)
        self.assertEqual(set(self.required(result).values()), {"pass"}, self.required(result))
        names = [row["name"] for row in result["gates"]]
        self.assertEqual(len(names), len(set(names)))
        # Exactly two native builds, current generation, aarch64; never Loom/Solar.
        self.assertEqual([c["product"] for c in h.build_calls], [BURST, NEBULAR])
        self.assertEqual({(c["arch"], c["generation"]) for c in h.build_calls}, {("aarch64", CURRENT_GENERATION)})
        self.assertEqual(h.npm_calls, [(p, h.scratch / "npm-input" / p) for p in (BURST, NEBULAR)])
        # Closed SDK context: fresh workspace, run/source identity, fixture homes private.
        self.assertEqual(len(h.sdk_calls), 1)
        call = h.sdk_calls[0]
        self.assertEqual(call["input_profile"], "historical")
        self.assertFalse(call["existed"])
        self.assertEqual(call["workspace"], h.scratch / "archarm-sdk")
        self.assertEqual(call["context"], {"runId": str(RUN_ID), "runAttempt": 1, "sourceSha": "a" * 40,
                                           "generation": CURRENT_GENERATION,
                                           "privateRoots": [str(h.scratch / "fixture"),
                                                            str(h.scratch / "fixture-wrong")]})
        self.assertEqual((call["uid"], call["gid"]), (os.getuid(), os.getgid()))
        # Per-product narrow binds: product tree only; repo-add only in repository runners.
        works = [h.scratch / "build" / p for p in (BURST, NEBULAR)]
        self.assertEqual(h.lease.builder_calls, [(w, ()) for w in works])
        self.assertEqual(h.lease.repository_calls, [*(w / "repo/aarch64" for w in works), h.scratch / "pacman"])
        self.assertFalse([argv for _, argv in h.builder_argv if argv[0] == "repo-add"])
        self.assertEqual(len(h.repo_argv), 3)
        for argv in h.repo_argv:
            self.assertEqual(argv[0], "repo-add")
            self.assertFalse(set(argv) & {"-s", "--sign", "-k", "--key", "-v", "--verify"})
        # No legacy provisioner, whole-scratch ContainerRunner or online refresh.
        self.assertEqual(h.legacy, [])
        flat = [" ".join(c) for c in h.host.calls] + [" ".join(a) for _, a in h.builder_argv]
        self.assertFalse([c for c in flat if "-Fy" in c or "-Sy" in c or "--nodeps" in c])
        # Order: canonical origin before SDK; fixtures closed before SDK exit; token released last.
        ev = h.events
        self.assertLess(ev.index("any-acquire"), ev.index("sdk-enter"))
        self.assertLess(ev.index("sdk-enter"), ev.index("fixture:primary"))
        self.assertLess(ev.index("fixture-close"), ev.index("sdk-exit"))
        self.assertLess(ev.index("sdk-exit"), ev.index("any-exit"))
        # Shared client interfaces receive the held lease and the architecture-aware spec.
        self.assertIs(h.client_kwargs["sdk_lease"], h.lease)
        self.assertIs(h.tamper_kwargs["sdk_lease"], h.lease)
        self.assertEqual((h.client_kwargs["image"], h.client_kwargs["platform"]),
                         ("sha256:" + "c" * 64, "linux/arm64"))
        self.assertEqual(h.client_kwargs["products"], [BURST, LOOM, SOLAR, NEBULAR])
        self.assertEqual({c["architecture"] for c in h.spec_calls}, {"aarch64"})
        self.assertEqual((h.tamper_kwargs["arch"], h.tamper_kwargs["kinds"]),
                         ("aarch64", ("package", "index", "signature", "wrongkey")))
        mounts = [m for spec in (h.client_kwargs["spec"], h.tamper_kwargs["spec"]) for m in spec["mounts"]]
        self.assertTrue(all(not writable for _, _, writable in mounts))
        self.assertFalse([m for m in mounts if "fixture" in m[0]])
        # Construction custody holds only the two native constructions.
        custody = json.loads((h.scratch / "unsigned-custody/custody-manifest.json").read_bytes())
        self.assertEqual(sorted(custody["files"]),
                         sorted(f"{p}-{VERSIONS[p]}-1-aarch64.pkg.tar.zst" for p in (BURST, NEBULAR)))
        self.assertEqual(custody["system"], "aarch64-linux")
        # Reuse replicas are the importer's held copies, re-exported with its exact witness.
        reuse = result["details"]["canonical_any_reuse"]
        self.assertFalse(reuse["construction_on_this_lane"])
        self.assertEqual(reuse["construction_authority"], {"family": "pacman", "system": "x86_64-linux"})
        for pid in (LOOM, SOLAR):
            replica = h.scratch / reuse["replicas"][pid]["file"]
            self.assertEqual(replica.parent, h.scratch / "canonical-any/files")
            self.assertEqual(replica.read_bytes(), b"canonical-x86_64-any:" + pid.encode())
            self.assertIn(replica, result["artifacts"])
            self.assertEqual(result["details"]["products"][pid]["role"], "canonical-any-reuse-replica")
        witness = h.scratch / arm.WITNESS_FILE
        self.assertIn(witness, result["artifacts"])
        self.assertEqual(witness.read_bytes(), default_witness({p: h.scratch / reuse["replicas"][p]["file"]
                                                                for p in (LOOM, SOLAR)}))
        # Host-side detached signatures for every package plus DB/files; no symlinked DB.
        repo = h.scratch / "pacman/aarch64"
        self.assertEqual(len(list(repo.glob("*.pkg.tar.zst.sig"))), 4)
        for name in ("rs9.db", "rs9.db.tar.gz", "rs9.files", "rs9.files.tar.gz"):
            self.assertFalse((repo / name).is_symlink())
            self.assertTrue((repo / (name + ".sig")).is_file())
        # Fixture private homes were cleaned up, removed and never retained.
        self.assertEqual(result["details"]["cleanup_evidence"]["fixture"]["status"], "pass")
        self.assertFalse((h.scratch / "fixture").exists())
        self.assertFalse((h.scratch / "fixture-wrong").exists())
        self.assertFalse([p for p in result["artifacts"] if p.relative_to(h.scratch).parts[0].startswith("fixture")])
        self.assertEqual(len([c for c in h.host.calls if Path(c[0]).name == "gpgconf"]), 4)
        # Closed environment schema; no world-writable retained object.
        environment = result["details"]["environment"]
        self.assertEqual(set(environment), arm.ENVIRONMENT_KEYS)
        self.assertEqual((environment["architecture"], environment["platform"]), ("aarch64", "linux/arm64"))
        self.assertEqual(environment["canonical_any_witness_sha256"], reuse["witness_sha256"])
        self.assertEqual(environment["cleanup"], {"canonical_any": "pass", "sdk": "pass", "fixture": "pass"})
        for path in result["artifacts"]:
            self.assertFalse(path.stat().st_mode & 0o002, path)

    def test_legacy_nodeps_makepkg_fails_build_before_custody_and_fixture(self):
        h = Harness(self).start()
        h.makepkg_argv = LEGACY_MAKEPKG
        result = arm.execute(h.context)
        status = self.required(result)
        self.assertEqual(status[arm.BUILD_GATE], "fail")
        self.assertEqual(result["details"]["build_errors"],
                         {BURST: "ARCHARM_FORBIDDEN_COMMAND", NEBULAR: "ARCHARM_FORBIDDEN_COMMAND"})
        self.assertFalse([argv for _, argv in h.builder_argv if argv[0] == "makepkg"])
        for name in (arm.INDEX_GATE, arm.CLIENT_GATE, arm.BURST_TARGET_GATE, arm.BURST_LOAD_GATE):
            self.assertEqual(status[name], "not-run")
            self.assertEqual(gate(result, name)["reason"], "blocked-by:" + arm.BUILD_GATE)
        self.assertFalse((h.scratch / "unsigned-custody").exists())
        self.assertEqual(h.fixtures, [])
        self.assertIsNone(h.client_kwargs)
        self.assertEqual(status[arm.CLEANUP_GATE], "pass")
        self.assertIn(h.scratch / "diagnostics/build-errors.json", result["artifacts"])

    def test_invalid_canonical_origin_fails_before_sdk_fixture_and_custody(self):
        h = Harness(self).start()
        h.any_error = ContractError("CANONICAL_ANY_RUN", "Original x86_64 run differs")
        result = arm.execute(h.context)
        status = self.required(result)
        self.assertEqual(status[arm.ANY_GATE], "fail")
        self.assertEqual(gate(result, arm.ANY_GATE)["reason"], "CANONICAL_ANY_RUN")
        self.assertEqual((h.sdk_calls, h.build_calls, h.fixtures), ([], [], []))
        self.assertFalse((h.scratch / "unsigned-custody").exists())
        for name in set(arm.REQUIRED_GATES) - {arm.ANY_GATE}:
            self.assertEqual(status[name], "not-run")
            self.assertEqual(gate(result, name)["reason"], "blocked-by:" + arm.ANY_GATE)

    def test_canonical_token_refusals(self):
        def serialized(files, output):
            return {"files": files}

        def extra_product(files, output):
            extra = output / f"{BURST}-{VERSIONS[BURST]}-1-any.pkg.tar.zst"
            extra.write_bytes(b"second-constructor")
            return FakeAny(h, {**files, BURST: extra})

        def symlinked(files, output):
            link = output / "link.pkg.tar.zst"
            link.symlink_to(files[LOOM].name)
            return FakeAny(h, {**files, LOOM: link})

        def wrong_version(files, output):
            other = output / f"{LOOM}-9.9.9-1-any.pkg.tar.zst"
            other.write_bytes(files[LOOM].read_bytes())
            return FakeAny(h, {**files, LOOM: other})

        def outside_output(files, output):
            elsewhere = output.parent / files[LOOM].name
            elsewhere.write_bytes(files[LOOM].read_bytes())
            return FakeAny(h, {**files, LOOM: elsewhere})

        for factory in (serialized, extra_product, symlinked, wrong_version, outside_output):
            with self.subTest(factory.__name__):
                h = Harness(self).start()
                h.files_factory = factory
                result = arm.execute(h.context)
                self.assertEqual(self.required(result)[arm.ANY_GATE], "fail")
                self.assertEqual((h.sdk_calls, h.fixtures), ([], []))

    def test_witness_must_be_canonical_bytes_binding_the_exact_files(self):
        def unbound(files):
            return canonical({"role": "reuse-witness", "construction_authority": "pacman/x86_64-linux",
                              "files": {p: {"name": f.name, "sha256": "0" * 64, "size": 1} for p, f in files.items()}})

        def second_constructor(files):
            doc = json.loads(default_witness(files))
            doc["construction_authority"] = "pacman/aarch64-linux"
            return canonical(doc)

        def not_canonical(files):
            return json.dumps(json.loads(default_witness(files)), indent=2).encode()

        def host_path(files):
            doc = json.loads(default_witness(files))
            doc["files"][LOOM]["replica_path"] = str(files[LOOM])
            return canonical(doc)

        for factory in (unbound, second_constructor, not_canonical, host_path,
                        lambda files: json.loads(default_witness(files))):
            with self.subTest(getattr(factory, "__name__", "dict")):
                h = Harness(self).start()
                h.witness_factory = factory
                result = arm.execute(h.context)
                self.assertEqual(self.required(result)[arm.ANY_GATE], "fail")
                self.assertEqual(h.sdk_calls, [])

    def test_missing_peer_providers_fail_before_any_acquisition(self):
        for module in ("rs9.archarm_sdk", "rs9.current_pacman_any"):
            with self.subTest(module):
                h = Harness(self).start()
                with patch.dict(sys.modules, {module: None}):
                    with self.assertRaises(ContractError) as caught:
                        arm.execute(h.context)
                self.assertIn(caught.exception.code, {"ARCHARM_SDK_UNAVAILABLE", "CANONICAL_ANY_UNAVAILABLE"})
                self.assertEqual(h.events, [])
                self.assertEqual(list(h.scratch.iterdir()), [])

    def test_missing_shared_keyword_fails_closed_before_providers(self):
        def x64_only_spec(pacman_dir, keys_dir, fingerprint):
            raise AssertionError("must not be called")

        h = Harness(self).start(spec=x64_only_spec)
        with self.assertRaises(ContractError) as caught:
            arm.execute(h.context)
        self.assertEqual(caught.exception.code, "ARCHARM_SHARED_API")
        self.assertEqual(caught.exception.details["reason"], "pacman_spec.architecture")
        self.assertEqual(h.events, [])

    def test_route_and_context_refusals(self):
        cases = (("generation", HISTORICAL_GENERATION), ("family", "rpm"), ("system", "x86_64-linux"),
                 ("producer_provenance", {"source_commit": "c" * 40, "run_id": RUN_ID, "attempt": 1}),
                 ("producer_provenance", {"source_commit": "a" * 40}),
                 ("authentication_sha256", "x"), ("captures", "two"))
        for key, value in cases:
            with self.subTest(key=key, value=value):
                h = Harness(self).start()
                context = dict(h.context)
                context[key] = h.captures[:2] if value == "two" else value
                with self.assertRaises(ContractError):
                    arm.execute(context)
                self.assertEqual(h.events, [])

    def test_runner_identity_refuses_root_and_out_of_range(self):
        for uid, gid in ((0, 1000), (1000, 0), (2147483648, 1000)):
            with self.subTest(uid=uid, gid=gid), patch("os.getuid", return_value=uid), \
                    patch("os.getgid", return_value=gid):
                with self.assertRaises(ContractError) as caught:
                    arm.runner_identity()
                self.assertEqual(caught.exception.code, "ARCHARM_RUNNER_IDENTITY")

    def test_capture_authentication_failure_stops_before_providers(self):
        h = Harness(self).start()

        def refuse(capture):
            raise ContractError("RELEASE_CAPTURE", "Fresh in-process byte authentication required")

        with patch("rs9.release_core.authenticated_record_hash", refuse):
            with self.assertRaises(ContractError):
                arm.execute(h.context)
        self.assertEqual(h.events, [])

    def test_sdk_not_from_qualified_origin_fails_environment_before_builds(self):
        h = Harness(self).start()
        h.pins_qualified = False
        result = arm.execute(h.context)
        status = self.required(result)
        self.assertEqual(status[arm.ENV_GATE], "fail")
        self.assertEqual(h.build_calls, [])
        self.assertEqual(status[arm.CLEANUP_GATE], "pass")

    def test_sdk_entry_failure_uses_the_lease_cleanup_readback(self):
        h = Harness(self).start()
        h.sdk_enter_error = ContractError("ARCHARM_PIN_ORIGIN", "Exact-origin pins refused")
        result = arm.execute(h.context)
        status = self.required(result)
        self.assertEqual(status[arm.ENV_GATE], "fail")
        self.assertEqual(status[arm.CLEANUP_GATE], "pass")
        self.assertEqual(h.build_calls, [])

    def test_failed_client_row_remains_lane_failure(self):
        h = Harness(self).start()
        h.client_hook = lambda rows: rows.append({"name": f"pacman-client.{NEBULAR}.application-smoke",
                                                  "status": "fail", "reason": "SMOKE"})
        result = arm.execute(h.context)
        self.assertEqual(self.required(result)[arm.CLIENT_GATE], "fail")
        from rs9.hosted_summary import gate_blockers
        lane = {"lane": "pacman", "system": "aarch64-linux", "required_gates": list(arm.REQUIRED_GATES)}
        blockers = gate_blockers(lane, result, generation=CURRENT_GENERATION)
        self.assertIn("fail:" + arm.CLIENT_GATE, blockers)
        self.assertIn(f"failed-gate:pacman-client.{NEBULAR}.application-smoke", blockers)

    def test_sdk_cleanup_failure_or_unproven_readback_fails_cleanup_gate(self):
        for name, setup in (
                ("exit-raises", lambda h: setattr(h, "sdk_exit_error",
                                                  ContractError("ARCHARM_CLEANUP_INCOMPLETE", "Tag retained"))),
                ("incomplete", lambda h: setattr(h, "sdk_cleanup_complete", False)),
                ("unreadable", lambda h: setattr(h, "records_unreadable", True))):
            with self.subTest(name):
                h = Harness(self).start()
                setup(h)
                result = arm.execute(h.context)
                status = self.required(result)
                self.assertEqual(status[arm.CLEANUP_GATE], "fail")
                if name != "unreadable":
                    self.assertEqual(status[arm.CLIENT_GATE], "pass")

    def test_lingering_fixture_agent_socket_fails_cleanup_and_retains_homes(self):
        h = Harness(self).start()
        (h.socketdir / "S.gpg-agent").write_bytes(b"")
        result = arm.execute(h.context)
        fixture = result["details"]["cleanup_evidence"]["fixture"]
        self.assertEqual(fixture["status"], "fail")
        self.assertEqual(fixture["roles"]["fixture"]["reason"], "lingering-agent-socket")
        self.assertFalse(fixture["private_state_removed"])
        self.assertEqual(self.required(result)[arm.CLEANUP_GATE], "fail")
        self.assertFalse([p for p in result["artifacts"] if p.relative_to(h.scratch).parts[0].startswith("fixture")])

    def test_unavailable_gpgconf_is_unknown_cleanup_and_fails(self):
        h = Harness(self).start()
        (h.tools / "gpgconf").unlink()
        result = arm.execute(h.context)
        self.assertEqual(result["details"]["cleanup_evidence"]["fixture"]["roles"]["wrong"]["reason"],
                         "gpgconf-unavailable")
        self.assertEqual(self.required(result)[arm.CLEANUP_GATE], "fail")

    def test_synthetic_receipts_never_pass(self):
        h = Harness(self).start()
        h.executed = False
        result = arm.execute(h.context)
        status = self.required(result)
        self.assertEqual(status[arm.ENV_GATE], "not-run")
        self.assertNotIn("pass", {status[n] for n in arm.REQUIRED_GATES if n != arm.ANY_GATE})
        self.assertEqual(h.build_calls, [])

    def test_world_writable_build_output_fails_before_custody(self):
        h = Harness(self).start()
        h.package_mode = 0o666
        result = arm.execute(h.context)
        self.assertEqual(self.required(result)[arm.BUILD_GATE], "fail")
        self.assertEqual(set(result["details"]["build_errors"].values()), {"ARCHARM_OUTPUT_POLICY"})
        self.assertFalse((h.scratch / "unsigned-custody").exists())

    def test_failed_repo_add_fails_indexing_and_blocks_client(self):
        h = Harness(self).start()
        h.repo_exit = 1
        result = arm.execute(h.context)
        status = self.required(result)
        self.assertEqual(status[arm.INDEX_GATE], "fail")
        self.assertEqual(status[arm.CLIENT_GATE], "not-run")
        self.assertIsNone(h.client_kwargs)
        self.assertEqual(result["details"]["cleanup_evidence"]["fixture"]["status"], "pass")

    def test_replica_mutation_during_client_fails_reuse_gate(self):
        h = Harness(self).start()

        def mutate(rows):
            replica = next((h.scratch / "canonical-any/files").glob(LOOM + "-*"))
            replica.write_bytes(b"mutated")
        h.client_hook = mutate
        result = arm.execute(h.context)
        self.assertEqual(self.required(result)[arm.ANY_GATE], "fail")


class CommandPolicyTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name).resolve() / "product"
        self.root.mkdir()

    def refused(self, role, argv, **kwargs):
        with self.assertRaises(ContractError) as caught:
            arm.admit_command(role, self.root, argv, **kwargs)
        self.assertEqual(caught.exception.code, "ARCHARM_FORBIDDEN_COMMAND")

    def test_policy_bypass_flags_and_refresh_are_refused(self):
        for argv in (LEGACY_MAKEPKG, ["makepkg", "-d"], ["makepkg", "-cfd"], ["makepkg", "--skipinteg"],
                     ["makepkg", "--skippgpcheck"], ["makepkg", "--skipchecksums"], ["makepkg", "-A"],
                     ["makepkg", "--ignorearch"], ["makepkg", "-s"], ["makepkg", "--syncdeps"], ["makepkg", "-i"],
                     ["pacman", "-Fy"], ["pacman", "-F", "-y", "libc.so.6"],
                     ["pacman", "-F", "--machinereadable", "libgtk-3.so.0"], ["pacman", "-Sy"],
                     ["pacman", "-S", "base-devel"], ["pacman", "-U", "x"], ["pacman", "-Qo", "--dbpath", "/x"],
                     ["sudo", "makepkg"], ["/usr/bin/makepkg"], ["gpg", "--version"]):
            with self.subTest(argv=argv):
                self.refused("builder", argv)

    def test_repo_add_signing_and_scope_are_refused(self):
        db, pkg = str(self.root / "aarch64/rs9.db.tar.gz"), str(self.root / "aarch64/p.pkg.tar.zst")
        for argv in (["repo-add", "-s", db, pkg], ["repo-add", "--sign", db, pkg], ["repo-add", "-k", "K", db, pkg],
                     ["repo-add", "-v", db, pkg], ["repo-add", "-sv", db, pkg],
                     ["repo-add", "/elsewhere/x.db.tar.gz", pkg], ["repo-add", db], ["makepkg", "--noextract"]):
            with self.subTest(argv=argv):
                self.refused("repository", argv)

    def test_environment_and_cwd_outside_bind_are_refused(self):
        self.refused("builder", POLICY_MAKEPKG, cwd=str(self.root.parent))
        self.refused("builder", POLICY_MAKEPKG, env={"PKGEXT": ".pkg.tar.xz"})
        self.refused("builder", POLICY_MAKEPKG, env={"MAKEPKG_CONF": "/x"})

    def test_exact_current_builder_and_repository_commands_are_admitted(self):
        work = self.root / "pacman/theme-forge-stellar-burst"
        arm.admit_command("builder", self.root, POLICY_MAKEPKG, cwd=work,
                          env={"SOURCE_DATE_EPOCH": "1767225600", "PKGEXT": ".pkg.tar.zst"})
        arm.admit_command("builder", self.root, ["pacman", "-Qo", "--quiet", "/usr/lib/libgtk-3.so.0"])
        arm.admit_command("builder", self.root, ["repo-add", str(self.root / "repo/aarch64/custom.db.tar.gz"),
                                                 str(self.root / "repo/aarch64/p.pkg.tar.zst")])
        arm.admit_command("repository", self.root, ["repo-add", str(self.root / "aarch64/rs9.db.tar.gz"),
                                                    str(self.root / "aarch64/p.pkg.tar.zst")])

    def test_guarded_runner_refusal_and_repo_add_dispatch(self):
        class Inner(CommandRunner):
            def __init__(self):
                self.calls = []

            def which(self, name):
                return "/usr/bin/" + name

            def run(self, argv, *, cwd=None, env=None):
                self.calls.append((list(argv), cwd, env))
                return CommandReceipt(argv, 0, b"", b"", executed=True)

        builder, repositories = Inner(), []

        def factory(directory):
            inner = Inner()
            repositories.append((directory, inner))
            return arm.GuardedRunner(inner, role="repository", root=directory)

        runner = arm.GuardedRunner(builder, role="builder", root=self.root, repository_factory=factory)
        with self.assertRaises(ContractError):
            runner.run(LEGACY_MAKEPKG, cwd=self.root)
        self.assertEqual(builder.calls, [])
        self.assertIsNone(runner.which("gpg"))
        self.assertEqual(runner.which("makepkg"), "/usr/bin/makepkg")
        directory = self.root / "repo/aarch64"
        argv = ["repo-add", str(directory / "custom.db.tar.gz"), str(directory / "p.pkg.tar.zst")]
        runner.run(argv, cwd=directory)
        runner.run(argv, cwd=directory)
        self.assertEqual(builder.calls, [])
        self.assertEqual(len(repositories), 1)
        self.assertEqual(repositories[0][0], directory)
        self.assertEqual(repositories[0][1].calls, [(argv, directory, None), (argv, directory, None)])
        bare = arm.GuardedRunner(Inner(), role="builder", root=self.root)
        with self.assertRaises(ContractError):
            bare.run(argv, cwd=directory)


class SharedApiTests(unittest.TestCase):
    def test_var_keyword_is_not_acceptance(self):
        module = types.SimpleNamespace(client_cycle=lambda host, spec, **kwargs: None,
                                       tamper_cycle=lambda host, *, sdk_lease=None: None,
                                       pacman_spec=lambda d, k, f, *, architecture="x86_64": None)
        self.assertEqual(arm.shared_api_gaps(module), ["client_cycle.sdk_lease"])


if __name__ == "__main__":
    unittest.main()
