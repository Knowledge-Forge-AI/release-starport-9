"""Pure tests: ArchARM role adapters (builder, repo-add, client), preamble and evidence.

Fakes only (``tests.test_archarm_sdk_harness``); no process, Docker, GPG or pacman.
"""
from __future__ import annotations

import json
import os
import unittest

from rs9 import archarm_sdk
from rs9.build_native import CommandReceipt
from rs9.client_inventory import FRAME_SCHEMA, FRAME_VERSION, frame_payload
from rs9._archarm_support.profiles import CAP_ADD, TMPFS_OPTIONS
from rs9._archarm_support.refusal import SdkRefusal
from rs9._archarm_support.scripts import (PREAMBLE_OK, SEVEN_CAPS_MASK, ZERO_CAPS, render_preamble,
                                          strip_attestation)
from tests.test_archarm_sdk import RefusalMixin
from tests.test_archarm_sdk_harness import CONTEXT, Harness


def option_values(argv, flag):
    return [argv[i + 1] for i, a in enumerate(argv) if a == flag]


class RoleTestBase(RefusalMixin, unittest.TestCase):
    def setUp(self):
        self.h = Harness(self)
        self.lease = self.h.lease()
        self.lease.__enter__()
        self.addCleanup(self._close)

    def _close(self):
        try:
            self.lease.close()
        except SdkRefusal:
            pass


class BuilderRunnerTest(RoleTestBase):
    def setUp(self):
        super().setUp()
        self.product = self.h.directory("product")
        self.source = self.h.directory("public-src")
        (self.source / "package.json").write_text("{}")

    def test_builder_profile_binds_and_receipt(self):
        seen = []
        self.h.engine.worker = lambda role, argv: seen.append((role, argv)) or (3, b"built", b"warn")
        runner = self.lease.builder_runner(self.product, [self.source])
        receipt = runner.run(["makepkg", "--force", "--clean"], cwd=self.product,
                             env={"SOURCE_DATE_EPOCH": "1767225600", "PKGEXT": ".pkg.tar.zst"})
        self.assertIsInstance(receipt, CommandReceipt)
        self.assertTrue(receipt.executed)
        self.assertEqual((receipt.exit_code, receipt.stdout_bytes, receipt.stderr_bytes),
                         (3, b"built", b"warn"))
        self.assertEqual(seen, [("builder", ["makepkg", "--force", "--clean"])])
        create = self.h.engine.created("builder")[0]
        self.assertIn("--read-only", create)
        self.assertEqual(option_values(create, "--cap-drop"), ["ALL"])
        self.assertEqual(option_values(create, "--cap-add"), [])
        self.assertEqual(option_values(create, "--user"), [self.lease.user])
        self.assertEqual(option_values(create, "--memory"), ["2147483648"])
        self.assertEqual(option_values(create, "--tmpfs"), ["/tmp:" + TMPFS_OPTIONS])
        self.assertEqual(option_values(create, "--network"), ["none"])
        self.assertEqual(option_values(create, "--ipc"), ["none"])
        mounts = option_values(create, "--mount")
        self.assertEqual(mounts, [f"type=bind,source={self.product},target={self.product}",
                                  f"type=bind,source={self.source},target={self.source},readonly"])
        self.assertIn("--env", create)
        self.assertIn("SOURCE_DATE_EPOCH=1767225600", create)
        self.assertEqual(create[create.index(self.lease.image) - 1], str(self.product))
        self.assertEqual(self.h.engine.role_docs("builder"), [])  # removed after the command

    def test_builder_readback_mutations_refuse_and_poison(self):
        mutations = {
            "capability": lambda d: d["Host"].update(CapAdd=["DAC_OVERRIDE"]),
            "writable root": lambda d: d["Host"].update(ReadonlyRootfs=False),
            "source writable": lambda d: d["Mounts"][1].update(RW=True),
            "extra mount": lambda d: d["Mounts"].append({"Type": "bind", "Source": "/",
                                                         "Destination": "/host", "RW": False}),
            "no tmpfs": lambda d: d["Host"].update(Tmpfs=None),
            "root user": lambda d: d.update(User="0:0"),
            "network": lambda d: d["Host"].update(NetworkMode="host"),
            "label": lambda d: d["Labels"].update({"other": "x"}),
        }
        for name, mutation in mutations.items():
            with self.subTest(name):
                h = Harness(self)
                lease = h.lease()
                lease.__enter__()
                product, source = h.directory("product"), h.directory("src")
                h.engine.mutate = lambda role, doc, m=mutation: role == "builder" and m(doc)
                runner = lease.builder_runner(product, [source])
                self.assertRefused("BUILDER_HOST_CONFIG", runner.run, ["makepkg", "-f"])
                self.assertEqual(h.engine.docker_calls(["start", "--attach"])[1:], [])
                self.assertEqual(lease.state, "poisoned")
                self.assertRefused("LEASE_STATE", runner.run, ["makepkg", "-f"])
                if name == "label":
                    # Label drift is an identity mismatch: retained, never removed by name.
                    self.assertRefused("CLEANUP_INCOMPLETE", lease.close)
                    self.assertEqual(lease.state, "retained")
                    self.assertEqual(len(h.engine.role_docs("builder")), 1)
                else:
                    lease.close()
                    self.assertEqual(h.engine.containers, {})

    def test_provider_bypass_and_signing_tools_are_refused_before_docker(self):
        runner = self.lease.builder_runner(self.product, [self.source])
        before = len(self.h.engine.calls)
        for argv, label in ((["makepkg", "--nodeps"], "PROVIDER_BYPASS"),
                            (["makepkg", "-d"], "PROVIDER_BYPASS"),
                            (["makepkg", "-fd"], "PROVIDER_BYPASS"),
                            (["makepkg", "-A"], "PROVIDER_BYPASS"),
                            (["makepkg", "--skippgpcheck"], "PROVIDER_BYPASS"),
                            (["makepkg", "--skipinteg"], "PROVIDER_BYPASS"),
                            (["makepkg", "--skipchecksums"], "PROVIDER_BYPASS"),
                            (["makepkg", "--ignorearch"], "PROVIDER_BYPASS"),
                            (["makepkg", "-s"], "PROVIDER_BYPASS"),
                            (["makepkg", "--sign"], "PROVIDER_BYPASS"),
                            (["gpg", "--detach-sign"], "ROLE_TOOL"),
                            (["/usr/bin/pacman-key", "--init"], "ROLE_TOOL"),
                            (["repo-add", "x.db.tar.gz"], "ROLE_TOOL"),
                            (["sudo", "id"], "ROLE_TOOL")):
            with self.subTest(argv=argv):
                self.assertRefused(label, runner.run, argv)
        self.assertEqual(len(self.h.engine.calls), before)
        self.assertEqual(self.lease.state, "ready")

    def test_env_cwd_and_mount_admission(self):
        runner = self.lease.builder_runner(self.product, [self.source])
        self.assertRefused("WORKER_ENV", runner.run, ["true"], env={"PATH": "/tmp"})
        self.assertRefused("WORKER_ENV", runner.run, ["true"], env={"LD_PRELOAD": "x"})
        self.assertRefused("WORKER_ENV", runner.run, ["true"],
                           env={"npm_config_cache": str(self.source / "cache")})
        self.assertRefused("WORKDIR", runner.run, ["true"], cwd=str(self.h.root))
        runner.run(["true"], env={"npm_config_cache": str(self.product / "npm-cache")})
        overlap = self.product / "nested"
        overlap.mkdir()
        self.assertRefused("MOUNT_OVERLAP", self.lease.builder_runner, self.product, [overlap])
        git = self.h.directory("with-git")
        (git / ".git").mkdir()
        self.assertRefused("PUBLIC_SOURCE", self.lease.builder_runner, self.product, [git])
        link = self.h.root / "link"
        link.symlink_to(self.product)
        self.assertRefused("PRODUCT_DIR", self.lease.builder_runner, link, [])
        loose = self.h.directory("loose", 0o777)
        self.assertRefused("PRODUCT_DIR", self.lease.builder_runner, loose, [])
        self.assertRefused("MOUNT_PATH", self.lease.builder_runner, self.product,
                           [self.h.root / "missing"])

    def test_private_roots_are_never_mounted(self):
        h = Harness(self)
        fixture = h.directory("fixture-home")
        product = h.directory("product")
        context = {**CONTEXT, "privateRoots": [str(fixture)]}
        lease = h.lease(context=context)
        with lease:
            self.assertRefused("PRIVATE_MOUNT", lease.builder_runner, product, [fixture])
            self.assertRefused("PRIVATE_MOUNT", lease.repository_runner, fixture)
            out = h.directory("probe-out")
            self.assertRefused("PRIVATE_MOUNT", lease.client, [(str(fixture), "/srv/rs9/keys", False)], out)

    def test_preamble_refusal_withholds_output(self):
        runner = self.lease.builder_runner(self.product, [])
        self.h.engine.preamble_ok = False
        self.assertRefused("PREAMBLE_IDENTITY", runner.run, ["makepkg", "-f"])
        self.assertEqual(self.h.engine.role_docs("builder"), [])  # still cleaned up

    def test_which_runs_inside_the_builder_profile(self):
        self.h.engine.worker = lambda role, argv: (0, b"/usr/bin/makepkg\n", b"")
        runner = self.lease.builder_runner(self.product, [])
        self.assertEqual(runner.which("makepkg"), "/usr/bin/makepkg")
        self.assertRefused("ARGV", runner.which, "make;pkg")


class RepositoryRunnerTest(RoleTestBase):
    def setUp(self):
        super().setUp()
        self.assembly = self.h.directory("assembly")
        (self.assembly / "aarch64").mkdir()

    def test_repo_add_sole_writable_assembly_bind(self):
        runner = self.lease.repository_runner(self.assembly)
        db = str(self.assembly / "aarch64" / "rs9.db.tar.gz")
        pkg = str(self.assembly / "aarch64" / "p-1-1-aarch64.pkg.tar.zst")
        receipt = runner.run(["repo-add", "-q", "--include-sigs", db, pkg])
        self.assertTrue(receipt.executed)
        create = self.h.engine.created("repository")[0]
        self.assertEqual(option_values(create, "--mount"),
                         [f"type=bind,source={self.assembly},target={self.assembly}"])
        self.assertIn("--read-only", create)
        self.assertEqual(option_values(create, "--cap-add"), [])
        self.assertEqual(option_values(create, "--user"), [self.lease.user])

    def test_signing_flags_paths_env_and_tools_refused(self):
        runner = self.lease.repository_runner(self.assembly)
        db = str(self.assembly / "rs9.db.tar.gz")
        before = len(self.h.engine.calls)
        for argv, label in ((["repo-add", "-s", db], "REPO_ADD_SIGNING"),
                            (["repo-add", "--sign", db], "REPO_ADD_SIGNING"),
                            (["repo-add", "-k", "ABC", db], "REPO_ADD_SIGNING"),
                            (["repo-add", "--key", "ABC", db], "REPO_ADD_SIGNING"),
                            (["repo-add", "-v", db], "REPO_ADD_SIGNING"),
                            (["repo-add", "-qs", db], "REPO_ADD_SIGNING"),
                            (["repo-add", str(self.h.root / "elsewhere.db.tar.gz")], "REPO_ADD_PATH"),
                            (["repo-add", "relative.db.tar.gz"], "REPO_ADD_PATH"),
                            (["makepkg"], "ROLE_TOOL"),
                            (["gpg", "--sign"], "ROLE_TOOL")):
            with self.subTest(argv=argv):
                self.assertRefused(label, runner.run, argv)
        self.assertRefused("WORKER_ENV", runner.run, ["repo-add", db], env={"GNUPGHOME": "/x"})
        self.assertEqual(len(self.h.engine.calls), before)

    def test_product_runner_dispatches_by_role(self):
        product = self.h.directory("product")
        runner = self.lease.product_runner(product, [], self.assembly)
        runner.run(["makepkg", "-f"], cwd=product)
        runner.run(["repo-add", str(self.assembly / "custom.db.tar.gz")], cwd=self.assembly)
        self.assertEqual(len(self.h.engine.created("builder")), 1)
        self.assertEqual(len(self.h.engine.created("repository")), 1)


class ClientTest(RoleTestBase):
    def setUp(self):
        super().setUp()
        self.repo = self.h.directory("repo")
        self.keys = self.h.directory("keys")
        (self.keys / "fixture-public.asc").write_text("public")
        self.out = self.h.directory("probe-out")
        self.mounts = [(str(self.repo), "/srv/rs9/pacman", False),
                       (str(self.keys), "/srv/rs9/keys", False)]

    def test_client_profile_and_root_exec(self):
        calls = []
        self.h.engine.client_exec = lambda user, argv: calls.append((user, argv)) or (0, b"ok", b"")
        with self.lease.client(self.mounts, self.out) as client:
            create = self.h.engine.created("client")[0]
            self.assertEqual(option_values(create, "--cap-add"), list(CAP_ADD))
            self.assertEqual(option_values(create, "--user"), ["0:0"])
            self.assertNotIn("--read-only", create)
            self.assertEqual(option_values(create, "--memory"), ["3221225472"])
            self.assertEqual(option_values(create, "--mount"), [
                f"type=bind,source={self.repo},target=/srv/rs9/pacman,readonly",
                f"type=bind,source={self.keys},target=/srv/rs9/keys,readonly",
                f"type=bind,source={self.out},target={archarm_sdk.PROBE_OUTPUT_TARGET}"])
            receipt = client.exec(["pacman", "--config", "/etc/rs9-pacman.conf", "-S",
                                   "--noconfirm", "rs9/theme-forge-solar-sail"])
            self.assertTrue(receipt.executed)
            self.assertEqual(calls[-1][0], "0:0")
            self.assertEqual(client.platform, "linux/arm64")
        self.assertEqual(self.h.engine.role_docs("client"), [])
        stops = self.h.engine.docker_calls(["container", "stop"])
        self.assertTrue(stops and all(call[2:4] == ["--time", "10"] for call in stops))

    def test_client_mount_restrictions(self):
        cases = {
            "CLIENT_MOUNT_WRITABLE": ([(str(self.repo), "/srv/rs9/pacman", True)], self.out),
            "CLIENT_MOUNTS": ([(str(self.repo), "/opt/repo", False)], self.out),
        }
        for label, (mounts, out) in cases.items():
            with self.subTest(label):
                self.assertRefused(label, self.lease.client, mounts, out)
        nested = [(str(self.repo), "/srv/rs9/pacman", False), (str(self.keys), "/srv/rs9/pacman/k", False)]
        self.assertRefused("CLIENT_MOUNTS", self.lease.client, nested, self.out)
        shadow = [(str(self.repo), archarm_sdk.PROBE_OUTPUT_TARGET, False)]
        self.assertRefused("CLIENT_MOUNTS", self.lease.client, shadow, self.out)
        (self.out / "stale").write_text("x")
        self.assertRefused("PROBE_OUTPUT", self.lease.client, self.mounts, self.out)
        loose = self.h.directory("loose-out", 0o777)
        self.assertRefused("PROBE_OUTPUT", self.lease.client, self.mounts, loose)
        self.assertRefused("MOUNT_OVERLAP", self.lease.client,
                           [(str(self.h.root), "/srv/rs9/all", False)], self.h.directory("o2"))

    def test_client_readback_mutation_refuses(self):
        self.h.engine.mutate = lambda role, doc: role == "client" and doc["Mounts"][2].update(RW=False)
        client = self.lease.client(self.mounts, self.out)
        self.assertRefused("CLIENT_HOST_CONFIG", client.__enter__)
        self.assertEqual(self.lease.state, "poisoned")
        self.assertEqual(len(self.h.engine.docker_calls(["start"])), 1)  # installer only

    def test_root_provider_bypass_and_network_trust_refused(self):
        with self.lease.client(self.mounts, self.out) as client:
            for argv, label in ((["pacman", "-Sdd", "x"], "PROVIDER_BYPASS"),
                                (["pacman", "-S", "--nodeps", "x"], "PROVIDER_BYPASS"),
                                (["pacman", "-Rdd", "x"], "PROVIDER_BYPASS"),
                                (["pacman", "-Fy"], "PROVIDER_BYPASS"),
                                (["pacman", "-U", "--overwrite", "*", "x"], "PROVIDER_BYPASS"),
                                (["pacman-key", "--recv-keys", "ABC"], "CLIENT_TRUST_SCOPE"),
                                (["pacman-key", "--populate"], "CLIENT_TRUST_SCOPE")):
                with self.subTest(argv=argv):
                    self.assertRefused(label, client.exec, argv)
            self.assertRefused("CLIENT_USER", client.exec, ["true"], user="65534:65534")
            self.assertRefused("CLIENT_ENV", client.exec, ["true"], env={"LD_PRELOAD": "x"})

    def test_unprivileged_entry_requires_attested_preamble(self):
        seen = []
        self.h.engine.client_exec = lambda user, argv: seen.append((user, argv)) or (0, b"", b"")
        with self.lease.client(self.mounts, self.out) as client:
            self.assertRefused("PREAMBLE_IDENTITY", lambda: client.unprivileged_prefix)
            self.assertTrue(client.verify_unprivileged_identity())
            self.assertEqual(seen[-1], (self.lease.user, ["/usr/bin/true"]))
            prefix = client.unprivileged_prefix
            self.assertEqual(prefix[:1], ["docker"])
            self.assertIn("exec", prefix)
            self.assertEqual(prefix[prefix.index("--user") + 1], self.lease.user)
            self.assertEqual(prefix[-4:-2], ["/usr/bin/bash", "-c"])
            self.assertEqual(prefix[-1], "rs9-preamble")
            script = prefix[-2]
            self.assertIn(SEVEN_CAPS_MASK, script)
            self.assertNotIn("PREAMBLE-OK", script)
            exec_call = [c for c in self.h.engine.docker_calls(["exec"])
                         if "--user" in c and c[c.index("--user") + 1] != "0:0"][-1]
            self.assertIn("HOME=/tmp/home", exec_call)

    def test_failed_preamble_never_reaches_the_probe(self):
        seen = []
        self.h.engine.client_exec = lambda user, argv: seen.append(argv) or (0, b"", b"")
        with self.lease.client(self.mounts, self.out) as client:
            self.h.engine.preamble_ok = False
            self.assertRefused("PREAMBLE_IDENTITY", client.verify_unprivileged_identity)
            self.assertRefused("PREAMBLE_IDENTITY", client.exec, ["/usr/bin/tfss", "--version"],
                               user=self.lease.user)
            self.assertEqual(seen, [])
            self.assertRefused("PREAMBLE_IDENTITY", lambda: client.unprivileged_prefix)

    def test_inventory_runs_as_root_through_exec(self):
        payload = {"diagnostics": {"counters": {k: 0 for k in (
            "dir_count", "entries", "file_count", "hardlink_count", "special_count",
            "symlink_count", "total_hashed_bytes", "scanned_entries", "excluded_files")},
            "max": {k: 0 for k in ("depth", "file_bytes", "path_bytes", "symlink_bytes",
                                   "directory_entries")}},
            "entries": [], "entry_count": 0, "schema": FRAME_SCHEMA, "total_hashed_bytes": 0,
            "version": FRAME_VERSION}
        users = []
        self.h.engine.client_exec = lambda user, argv: users.append(user) or (0, frame_payload(payload), b"")
        with self.lease.client(self.mounts, self.out) as client:
            self.assertEqual(client.inventory("pre-install"), {})
        self.assertEqual(users, ["0:0"])

    def test_evidence_ingestion_after_quiescence_only(self):
        declared = {"result.json": lambda data: json.loads(data)["status"],
                    "logs/receipt.json": lambda data: json.loads(data)}
        with self.lease.client(self.mounts, self.out) as client:
            (self.out / "result.json").write_text('{"status": "pass"}')
            self.assertRefused("EVIDENCE_NOT_QUIESCED", client.ingest_output, declared)
            client.quiesce()
            self.assertRefused("CLIENT_STATE", client.exec, ["true"])
            evidence = client.ingest_output(declared, required=["result.json"])
        self.assertFalse(evidence.authority)
        self.assertEqual(evidence.files["result.json"]["value"], "pass")
        record = evidence.record()
        self.assertEqual([row["path"] for row in record["files"]], ["result.json"])
        self.assertNotIn(str(self.out), json.dumps(record))
        self.assertEqual(self.h.engine.role_docs("client"), [])

    def test_unsafe_probe_output_is_rejected(self):
        declared = {"result.json": lambda data: json.loads(data)}

        def run_case(prepare, label, required=()):
            out = self.h.directory("out-" + label.lower() + str(len(os.listdir(self.h.root))))
            with self.lease.client(self.mounts, out) as client:
                prepare(out)
                client.quiesce()
                self.assertRefused(label, client.ingest_output, declared, required)

        run_case(lambda o: (o / "result.json").symlink_to("/etc/passwd"), "EVIDENCE_UNSAFE")
        run_case(lambda o: os.mkfifo(o / "result.json"), "EVIDENCE_UNSAFE")
        run_case(lambda o: (o / "extra.bin").write_bytes(b"x"), "EVIDENCE_UNDECLARED")

        def hardlink(o):
            (o / "result.json").write_text("{}")
            os.link(o / "result.json", self.h.root / f"alias{len(os.listdir(self.h.root))}")
        run_case(hardlink, "EVIDENCE_UNSAFE")

        def world_writable(o):
            (o / "result.json").write_text("{}")
            (o / "result.json").chmod(0o666)
        run_case(world_writable, "EVIDENCE_OWNER")

        def setuid(o):
            (o / "result.json").write_text("{}")
            (o / "result.json").chmod(0o4644)
        run_case(setuid, "EVIDENCE_OWNER")
        run_case(lambda o: (o / "result.json").write_text("not json"), "EVIDENCE_SCHEMA")
        run_case(lambda o: None, "EVIDENCE_MISSING", required=["result.json"])


class PreambleTest(RefusalMixin, unittest.TestCase):
    def test_preamble_verifies_everything_before_exec_and_never_transitions(self):
        for bounding in (ZERO_CAPS, SEVEN_CAPS_MASK):
            script = render_preamble(uid=1001, gid=118, bounding=bounding, umask="022", attest=True)
            self.assertIn("done < /proc/self/status", script)
            self.assertIn("printf '1001\\t1001\\t1001\\t1001'", script)
            self.assertIn("printf '118\\t118\\t118\\t118'", script)
            self.assertIn("''|118) ;;", script)
            for field in ("CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:", "NoNewPrivs:"):
                self.assertIn(field, script)
            self.assertIn(f'test "$cb" = {bounding} || fail', script)
            self.assertIn('test "$nnp" = 1 || fail', script)
            self.assertIn('test "$v" = 0000000000000000 || fail', script)
            last_check = script.index('test "$nnp" = 1 || fail')
            self.assertLess(last_check, script.index("PREAMBLE-OK"))
            self.assertLess(script.index("PREAMBLE-OK"), script.index('exec "$@"'))
            self.assertTrue(script.rstrip().endswith('exec "$@"'))
            for transition in ("setpriv", "capsh", "sudo", "su ", "runuser", "chroot", "nsenter"):
                self.assertNotIn(transition, script)
        self.assertEqual(SEVEN_CAPS_MASK, "00000000800000db")
        self.assertRefused("RUNNER_IDENTITY", render_preamble, uid=0, gid=1, bounding=ZERO_CAPS,
                           umask="022", attest=True)
        self.assertRefused("PREAMBLE", render_preamble, uid=1, gid=1, bounding="ffffffffffffffff",
                           umask="022", attest=True)

    def test_attestation_token_is_required_and_stripped(self):
        self.assertEqual(strip_attestation(0, PREAMBLE_OK + b"tool stderr"), b"tool stderr")
        self.assertRefused("PREAMBLE_IDENTITY", strip_attestation, 213, b"")
        self.assertRefused("PREAMBLE_IDENTITY", strip_attestation, 0, b"tool output first\n" + PREAMBLE_OK)


if __name__ == "__main__":
    unittest.main()
