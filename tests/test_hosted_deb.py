"""Source tests for the hosted Ubuntu 26.04 APT and Pages candidate lanes (rs9.hosted_deb).

No Docker, network or production credential is needed. ``ScriptedDocker`` is a control-flow
double: its receipts are never marked executed, so every lane must report ``not-run`` for
command-dependent gates (never ``pass``). Real GnuPG is used only where available.
"""

from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path
import re
import shutil
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from rs9 import hosted_deb as hd
from rs9.build_native import CommandReceipt, MockCommandRunner
from rs9.errors import ContractError
from rs9.hosted_contract import REQUIRED_GATES, validate_execution_result
from rs9.pages import merkle_inventory, scan_pages_tree
from rs9.pages_candidate import CLIENT_KEYRING_PATH, load_custody_bundle, write_custody_bundle
from rs9.release_core import digest
from rs9.repo_apt import build_apt_repository, verify_apt_signatures
from rs9.signing_fixture import SigningFixture, find_gpg_binary
from tests.test_build_native import create_cli_fixture
from tests.test_pages import make_rpm, zstd_raw_frame
from tests.test_pages_candidate import TRUTHFUL_ARMOR_PUBLIC_KEY
from tests.test_repo_apt import FixtureSigner, build_minimal_deb

TRUTHFUL_BINARY_PUBLIC_KEY = bytes([0xC0 | 6, 2, 10, 20])
DIGEST = "ab" * 32
AUTH = "d" * 64
MAINTAINER = "Theme Forge Lead <maintainer@example.com>"
OS_RELEASE = 'PRETTY_NAME="Ubuntu 26.04 LTS"\nVERSION_ID="26.04"\nVERSION_CODENAME=resolute\nID=ubuntu\n'
BASE_INVENTORY = b"D ./usr\nD ./etc\nL ./bin -> usr/bin\n" + ("a" * 64 + "  ./etc/hostname\n").encode()
LEFTOVER = ("b" * 64 + "  ./usr/bin/tfsl\n").encode()
PRODUCTS = hd.REQUIRED_PRODUCTS


class ScriptedDocker:
    """Records docker calls and models install, remove, tamper rejection and tool output."""

    def __init__(self, system="amd64", *, accept_tampered=False, fail_build=False, dirty_uninstall=False,
                 fail_install=False, fail_provision=False, os_release=OS_RELEASE, arch_label=None,
                 inspect_out=None, pull_code=0):
        self.system, self.arch_label = system, arch_label or system
        self.accept_tampered, self.fail_build, self.dirty_uninstall = accept_tampered, fail_build, dirty_uninstall
        self.fail_install, self.fail_provision = fail_install, fail_provision
        self.os_release, self.inspect_out, self.pull_code = os_release, inspect_out, pull_code
        self.calls: list[list[str]] = []
        self.containers: dict[str, dict] = {}

    @staticmethod
    def receipt(argv, code=0, out=b"", err=b""):
        return CommandReceipt(argv, code, out, err, tool_name="docker")

    def __call__(self, argv, cwd=None, env=None):
        self.calls.append(list(argv))
        verb = argv[1]
        if verb == "pull":
            return self.receipt(argv, self.pull_code)
        if verb == "image":
            out = self.inspect_out if self.inspect_out is not None else f"ubuntu@sha256:{DIGEST}|{self.arch_label}"
            return self.receipt(argv, out=out.encode())
        if verb == "run":
            return self._run(argv)
        if verb == "exec":
            return self._exec(argv)
        return self.receipt(argv)

    def _run(self, a):
        if a[-1:] == ["--version"]:
            return self.receipt(a, out=b"synthetic builder tool version\n")
        if "-d" in a:
            name = a[a.index("--name") + 1]
            sources = [a[i + 1].split(":")[0] for i, x in enumerate(a) if x == "-v"]
            self.containers[name] = {"installed": False, "dirty": False,
                                     "tampered": any("tamper-" in s for s in sources)}
            return self.receipt(a)
        script = a[-1] if a[-3:-1] == ["sh", "-c"] else ""
        if "cat /etc/os-release" in script:
            if any("registry.fedoraproject.org/fedora@" in arg for arg in a):
                return self.receipt(a, out=b'ID=fedora\nVERSION_ID="43"\nx86_64\n')
            if any("docker.io/library/archlinux@" in arg for arg in a):
                return self.receipt(a, out=b'ID=arch\nx86_64\n')
            return self.receipt(a, out=(self.os_release + self.arch_label + "\n").encode())
        if script.startswith("command -v "):
            return self.receipt(a, out=f"/usr/bin/{script.split()[-1]}\n".encode())
        if self.fail_provision and ("apt-get update" in script or "dnf -y install" in script):
            return self.receipt(a, 100, b"", b"E: provisioning failed")
        if "rpmsign" in a:
            target = Path(a[-1])
            data = target.read_bytes()
            # Synthetic signature-header mutation preserves the archive format.
            self_sig = b"sig\0"
            assert data[128:132] == self_sig
            target.write_bytes(data[:128] + b"fix\0" + data[132:])
            return self.receipt(a)
        if "rpmkeys" in a:
            return self.receipt(a, out=b"test.rpm: digests signatures OK\n")
        if "repo-add" in script:
            directory = Path(re.search(r"cd (\S+) &&", script).group(1))
            for name in ("rs9.db.tar.gz", "rs9.files.tar.gz", "rs9.db", "rs9.files"):
                (directory / name).write_bytes(gzip.compress(b"db:" + name.encode(), mtime=0))
            return self.receipt(a)
        if "dpkg-deb" in a:
            if self.fail_build:
                return self.receipt(a, 1, b"", b"dpkg-deb: error")
            output = Path(a[-1])
            package, revisioned, arch = output.name[:-4].split("_")
            output.write_bytes(build_minimal_deb(package, revisioned.rsplit("-", 1)[0], arch,
                                                 maintainer=MAINTAINER, depends="nodejs (>= 22)"))
            return self.receipt(a)
        if "createrepo_c" in a:
            repodata = Path(a[-1]) / "repodata"
            repodata.mkdir(exist_ok=True)
            (repodata / "repomd.xml").write_bytes(b"<repomd/>\n")
            (repodata / "primary.xml.gz").write_bytes(gzip.compress(b"<metadata/>", mtime=0))
            return self.receipt(a)
        return self.receipt(a)

    def _exec(self, a):
        i = 2
        while not a[i].startswith("rs9-client-"):
            i += 2 if a[i] in ("--user", "-e") else 1
        state, cmd = self.containers[a[i]], a[i + 1:]
        joined = " ".join(cmd)
        if cmd[:2] == ["sh", "-c"]:
            if cmd[2] == hd.INVENTORY_SCRIPT:
                return self.receipt(a, out=BASE_INVENTORY + (LEFTOVER if state["dirty"] else b""))
            return self.receipt(a)
        tool = cmd[0]
        if tool == "apt-get":
            verb = "install" if " install " in joined else "remove" if " purge " in joined else "refresh"
        elif tool == "dnf":
            verb = "install" if " install " in joined else "remove" if " remove " in joined else "refresh"
        elif tool == "pacman":
            verb = "query" if "-Q" in cmd else "install" if "-S" in cmd else "remove" if "-R" in cmd else "refresh"
        elif tool in ("dpkg-query", "rpm"):
            verb = "query"
        else:
            return self.receipt(a)
        if verb == "install":
            if self.fail_install or (state["tampered"] and not self.accept_tampered):
                return self.receipt(a, 100, b"", b"E: install rejected")
            state["installed"] = True
        elif verb == "remove":
            state["installed"], state["dirty"] = False, self.dirty_uninstall
        elif verb == "query":
            return self.receipt(a, 0 if state["installed"] else 1)
        return self.receipt(a)

    def containers_started(self):
        return len(self.containers)

    def calls_containing(self, *words):
        return [c for c in self.calls if all(w in c for w in words)]


class ExecutedMock(MockCommandRunner):
    """Marks receipts executed, modelling real subprocesses ONLY to exercise pass folding in tests."""

    def run(self, argv, *, cwd=None, env=None):
        receipt = super().run(argv, cwd=cwd, env=env)
        receipt.executed = True
        return receipt


def host_runner(docker, cls=MockCommandRunner):
    return cls(available_tools={"docker": "/usr/bin/docker"} if docker else {},
               handlers={"docker": docker} if docker else {})


def stub_probes(command, path, repository=None, prefix=None, env=None, runner=None):
    return [{"name": f"command.{command}.supported-behavior", "status": "not-run",
             "reason": "released-command-contract-unbound"}]


def usable_gpg():
    binary = find_gpg_binary()
    if not binary:
        return None
    try:
        with SigningFixture(gpg_binary=binary):
            pass
    except ContractError as error:
        if error.code == "GPG_AGENT_UNAVAILABLE":
            return None
        raise
    return binary


class HermeticFixtureSigner(FixtureSigner):
    """Key-bound fixture-signer double with truthful OpenPGP public key packets for candidate tests."""

    def __init__(self, fingerprint: str = "A" * 40, homedir: Path | None = None) -> None:
        super().__init__(fingerprint)
        self.homedir = homedir
        self.gpg = "gpg"
        self.public_key_armor = TRUTHFUL_ARMOR_PUBLIC_KEY
        self.public_key_bytes = TRUTHFUL_ARMOR_PUBLIC_KEY.encode("utf-8")
        self.public_key_binary = TRUTHFUL_BINARY_PUBLIC_KEY

    def close(self) -> None:
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


def fake_sign_rpm(runner, path, fixture):
    before = digest(path.read_bytes())
    homedir = getattr(fixture, "homedir", None) or ""
    gpg_bin = getattr(fixture, "gpg", "gpg")
    runner.run(["rpmsign", "--define", "_gpg_name " + fixture.primary_fingerprint,
                "--define", "_gpg_path " + str(homedir),
                "--define", "__gpg " + gpg_bin, "--addsign", str(path)])
    after = digest(path.read_bytes())
    if before == after:
        data = path.read_bytes()
        if data[128:132] == b"sig\0":
            path.write_bytes(data[:128] + b"fix\0" + data[132:])
            after = digest(path.read_bytes())
    if homedir:
        db = Path(homedir) / "fixture-rpmdb"
        db.mkdir(parents=True, exist_ok=True)
        public = Path(homedir) / "rs9-candidate-fixture-NONPRODUCTION.asc"
        armor = getattr(fixture, "public_key_bytes", None)
        if armor is None:
            armor = getattr(fixture, "public_key_armor", "").encode("utf-8")
        public.write_bytes(armor)
        runner.run(["rpmkeys", "--dbpath", str(db), "--import", str(public)])
        runner.run(["rpmkeys", "--dbpath", str(db), "--checksig", str(path)])
    return {
        "unsigned_sha256": before,
        "fixture_signed_sha256": after,
        "fixture_fingerprint": fixture.primary_fingerprint,
        "production": False,
    }


class StatusTests(unittest.TestCase):
    def test_pass_requires_a_satisfied_assertion_and_real_execution(self):
        self.assertEqual(hd._status(True, True), ("pass", None))
        self.assertEqual(hd._status(True, False), ("not-run", "synthetic-command-seam"))
        self.assertEqual(hd._status(False, True), ("fail", None))
        self.assertEqual(hd._status(False, False), ("fail", None))

    def test_fold_is_fail_dominant_and_never_passes_empty_or_unrun_sets(self):
        row = lambda s: {"name": "n", "status": s}
        self.assertEqual(hd._fold([row("pass"), row("pass")]), "pass")
        self.assertEqual(hd._fold([row("pass"), row("not-run")]), "not-run")
        self.assertEqual(hd._fold([row("not-run"), row("fail"), row("pass")]), "fail")
        self.assertEqual(hd._fold([]), "not-run")

    def test_recording_runner_requires_every_receipt_since_the_mark_to_be_executed(self):
        host = hd.RecordingRunner(host_runner(ScriptedDocker()))
        mark = host.mark()
        self.assertFalse(host.real_since(mark))  # nothing ran
        host.run(["docker", "pull", "x"])
        self.assertFalse(host.real_since(mark))  # synthetic receipt
        real = hd.RecordingRunner(host_runner(ScriptedDocker(), ExecutedMock))
        mark = real.mark()
        real.run(["docker", "pull", "x"])
        self.assertTrue(real.real_since(mark))
        self.assertEqual(real.records_since(mark)[0]["tool"], "docker")


class ContainerRunnerTests(unittest.TestCase):
    def test_docker_argv_is_network_disconnected_with_explicit_mounts_user_and_env(self):
        runner = hd.ContainerRunner(host_runner(None), "img@sha256:x", platform="linux/arm64",
                                    mounts=[("/a", "/a", True), ("/b", "/srv/b", False)], user="1000:1000")
        self.assertEqual(
            runner.docker_argv(["dpkg-deb", "--build"], cwd="/a/work", env={"B": "2", "A": "1"}),
            ["docker", "run", "--rm", "--platform", "linux/arm64", "--network", "none", "--user", "1000:1000", "-e", "HOME=/tmp",
             "-v", "/a:/a", "-v", "/b:/srv/b:ro", "-w", "/a/work", "-e", "A=1", "-e", "B=2",
             "img@sha256:x", "dpkg-deb", "--build"])
        online = hd.ContainerRunner(host_runner(None), "img", platform="linux/amd64", network=True)
        self.assertNotIn("--network", online.docker_argv(["true"]))

    def test_receipts_keep_inner_tool_identity_and_the_execution_flag(self):
        seen = []

        def docker(argv, cwd=None, env=None):
            seen.append(argv)
            return CommandReceipt(argv, 3, b"out", b"err", tool_name="docker", executed=True)

        runner = hd.ContainerRunner(host_runner(docker), "img", platform="linux/amd64")
        receipt = runner.run(["dpkg-deb", "--build"])
        self.assertEqual((receipt.exit_code, receipt.command, receipt.tool_name), (3, ["dpkg-deb", "--build"], "dpkg-deb"))
        self.assertEqual((receipt.stdout_bytes, receipt.stderr_bytes, receipt.executed), (b"out", b"err", True))
        self.assertEqual(receipt.tool_path, "container:img")
        self.assertEqual(receipt.to_record()["tool"], "dpkg-deb")
        self.assertEqual(seen[0][-2:], ["dpkg-deb", "--build"])
        synthetic = hd.ContainerRunner(host_runner(ScriptedDocker()), "img", platform="linux/amd64").run(["true"])
        self.assertFalse(synthetic.executed)
        with self.assertRaises(ContractError):
            runner.run([])

    def test_which_probes_inside_the_container_and_rejects_unsafe_names(self):
        runner = hd.ContainerRunner(host_runner(ScriptedDocker()), "img", platform="linux/amd64")
        self.assertEqual(runner.which("dpkg-deb"), "/usr/bin/dpkg-deb")

        def missing(argv, cwd=None, env=None):
            return CommandReceipt(argv, 1, b"", b"")

        self.assertIsNone(hd.ContainerRunner(host_runner(missing), "img", platform="linux/amd64").which("dpkg-deb"))
        for bad in ("x; rm -rf /", "a b", "$(id)", ""):
            with self.subTest(name=bad), self.assertRaises(ContractError):
                runner.which(bad)


class InventoryTests(unittest.TestCase):
    SAMPLE = (b"D .\nD ./usr\nL ./bin -> usr/bin\n" + ("a" * 64 + "  ./etc/hostname\n").encode()
              + b"D ./var/lib/dpkg\n" + ("b" * 64 + "  ./var/lib/dpkg/status\n").encode()
              + ("c" * 64 + "  ./usr/share/icons/hicolor/icon-theme.cache\n").encode()
              + b"D ./var/cache/apt\n" + ("d" * 64 + "  ./var/lib/dnf/history.sqlite\n").encode()
              + ("e" * 64 + "  ./etc/pacman.d/gnupg/pubring.gpg\n").encode())

    def test_parse_reads_files_dirs_and_symlinks_and_drops_only_documented_state(self):
        apt = hd.parse_inventory(self.SAMPLE, "apt")
        self.assertEqual(apt["usr"], "dir")
        self.assertEqual(apt["bin"], "symlink:usr/bin")
        self.assertEqual(apt["etc/hostname"], "a" * 64)
        for excluded in ("var/lib/dpkg", "var/lib/dpkg/status", "var/cache/apt",
                         "usr/share/icons/hicolor/icon-theme.cache", ""):
            self.assertNotIn(excluded, apt)
        self.assertIn("var/lib/dnf/history.sqlite", apt)  # another family's state is not excused for apt
        self.assertNotIn("var/lib/dnf/history.sqlite", hd.parse_inventory(self.SAMPLE, "dnf"))
        self.assertNotIn("etc/pacman.d/gnupg/pubring.gpg", hd.parse_inventory(self.SAMPLE, "pacman"))
        self.assertIn("etc/pacman.d/gnupg/pubring.gpg", apt)

    def test_unparseable_lines_fail_closed(self):
        for bad in (b"not an inventory line\n", b"\\" + b"a" * 64 + b"  ./escaped\n", b"short  ./x\n"):
            with self.subTest(bad=bad), self.assertRaises(ContractError) as caught:
                hd.parse_inventory(bad, "apt")
            self.assertEqual(caught.exception.code, "INVENTORY_PARSE")

    def test_exclusions_are_state_only_not_user_content(self):
        for path in ("var/lib/dpkg/info/x.list", "var/log/apt/history.log", "etc/ld.so.cache", "tmp/x", "run/x"):
            self.assertTrue(hd.inventory_excluded("apt", path), path)
        for path in ("usr/bin/tfsl", "usr/lib/theme-forge-stellar-loom/bin/run.js", "etc/hostname", "var/lib/other"):
            self.assertFalse(hd.inventory_excluded("apt", path), path)


class ClientSpecTests(unittest.TestCase):
    def test_apt_spec_trusts_only_the_nonproduction_keyring_and_the_local_repository(self):
        spec = hd.apt_spec(Path("/srv/a"), Path("/k/key.gpg"), "arm64")
        self.assertEqual(spec["mounts"], [("/srv/a", "/srv/rs9/apt", False), ("/k/key.gpg", CLIENT_KEYRING_PATH, False)])
        line = f"deb [signed-by={CLIENT_KEYRING_PATH} arch=arm64] file:/srv/rs9/apt resolute main"
        self.assertEqual(spec["configure"], [["sh", "-c", f"printf '%s\\n' '{line}' > /etc/apt/rs9-nonproduction.list"]])
        for option in ("Dir::Etc::sourceparts=-", "APT::Get::AllowUnauthenticated=false",
                       "Acquire::AllowInsecureRepositories=false"):
            self.assertTrue(any(option in part for part in spec["refresh"]), option)
        self.assertEqual(spec["refresh"][-1], "update")
        self.assertEqual(spec["install"]("pkg")[-4:], ["install", "-y", "--no-install-recommends", "pkg"])
        self.assertEqual(spec["remove"]("pkg")[-3:], ["purge", "-y", "pkg"])
        self.assertEqual(spec["query"]("pkg")[0], "dpkg-query")

    def test_dnf_spec_verifies_signed_metadata_from_the_local_tree_only(self):
        spec = hd.dnf_spec(Path("/t/rpm"), Path("/t/keys"), "aarch64")
        text = spec["configure"][0][2]
        for expected in ("baseurl=file:///srv/rs9/rpm/fedora/43/aarch64", "repo_gpgcheck=1", "gpgcheck=1",
                         "gpgkey=file:///srv/rs9/keys/rs9-candidate-fixture-NONPRODUCTION.asc", "[rs9-fedora-nonproduction]"):
            self.assertIn(expected, text)
        self.assertIn("--disablerepo=*", spec["install"]("pkg"))
        self.assertIn("--enablerepo=rs9-fedora-nonproduction", spec["install"]("pkg"))
        self.assertIn("--setopt=clean_requirements_on_remove=False", spec["remove"]("pkg"))
        with self.assertRaises(ContractError):
            hd.dnf_spec(Path("/t/rpm"), Path("/t/keys"), "i686")

    def test_pacman_spec_requires_signed_databases_and_a_pinned_fixture_key(self):
        fingerprint = "0123456789ABCDEF0123456789ABCDEF01234567"
        spec = hd.pacman_spec(Path("/t/pacman"), Path("/t/keys"), fingerprint)
        self.assertIn("SigLevel = Required DatabaseRequired", spec["configure"][0][2])
        self.assertIn("Server = file:///srv/rs9/pacman/$arch", spec["configure"][0][2])
        self.assertIn(["pacman-key", "--lsign-key", fingerprint], spec["configure"])
        self.assertEqual(spec["install"]("pkg")[-1], "rs9/pkg")
        for bad in ("", "abc", fingerprint.lower(), fingerprint + "0"):
            with self.subTest(bad=bad), self.assertRaises(ContractError):
                hd.pacman_spec(Path("/t/pacman"), Path("/t/keys"), bad)

    def test_client_configuration_lines_cannot_carry_quotes_or_newlines(self):
        for bad in ("a'b", "a\nb"):
            with self.assertRaises(ContractError):
                hd._printf_file("/etc/x", [bad])


class EnvironmentTests(unittest.TestCase):
    def test_unpinned_base_image_is_resolved_and_verified_at_run_time(self):
        docker = ScriptedDocker()
        env = hd.prepare_environment(host_runner(docker), "amd64", {})
        self.assertEqual((env["unpinned"], env["source_pinned"]), (True, False))
        self.assertEqual(env["digest"], f"sha256:{DIGEST}")
        self.assertEqual(env["image_ref"], f"ubuntu@sha256:{DIGEST}")
        self.assertEqual((env["version_id"], env["codename"], env["dpkg_architecture"]), ("26.04", "resolute", "amd64"))
        self.assertEqual(docker.calls[0], ["docker", "pull", "--platform", "linux/amd64", "ubuntu:26.04"])

    def test_pinned_digest_must_match_what_was_pulled(self):
        pins = {"deb": {"container_digests": {"amd64": f"sha256:{DIGEST}"}}}
        docker = ScriptedDocker()
        env = hd.prepare_environment(host_runner(docker), "amd64", pins)
        self.assertTrue(env["source_pinned"])
        self.assertEqual(docker.calls[0][-1], f"ubuntu@sha256:{DIGEST}")
        other = {"deb": {"container_digests": {"amd64": "sha256:" + "cd" * 32}}}
        with self.assertRaises(ContractError) as caught:
            hd.prepare_environment(host_runner(ScriptedDocker()), "amd64", other)
        self.assertEqual(caught.exception.code, "CONTAINER_DIGEST_MISMATCH")

    def test_wrong_architecture_distribution_or_unresolvable_digest_fail_closed(self):
        cases = [
            (ScriptedDocker(arch_label="arm64"), "INVALID_ARCHITECTURE"),
            (ScriptedDocker(os_release=OS_RELEASE.replace("26.04", "24.04")), "UNSUPPORTED_PLATFORM"),
            (ScriptedDocker(os_release=OS_RELEASE.replace("resolute", "noble")), "UNSUPPORTED_PLATFORM"),
            (ScriptedDocker(inspect_out="|amd64"), "CONTAINER_DIGEST_UNRESOLVED"),
            (ScriptedDocker(pull_code=1), "CONTAINER_PULL_FAILED"),
        ]
        for docker, code in cases:
            with self.subTest(code=code), self.assertRaises(ContractError) as caught:
                hd.prepare_environment(host_runner(docker), "amd64", {})
            self.assertEqual(caught.exception.code, code)

    def test_provisioning_commits_a_local_image_and_always_removes_the_container(self):
        docker = ScriptedDocker()
        tag = hd.provision_image(host_runner(docker), "apt", "ubuntu@sha256:x", "linux/amd64", "rs9-test:1",
                                 ["dpkg-dev", "libgtk-3-0t64", "libc6:amd64"])
        self.assertEqual(tag, "rs9-test:1")
        verbs = [call[1] for call in docker.calls]
        self.assertEqual(verbs, ["run", "commit", "rm"])
        self.assertIn("apt-get install -y --no-install-recommends dpkg-dev libgtk-3-0t64 libc6:amd64", docker.calls[0][-1])
        failing = ScriptedDocker(fail_provision=True)
        with self.assertRaises(ContractError) as caught:
            hd.provision_image(host_runner(failing), "apt", "ubuntu@sha256:x", "linux/amd64", "rs9-test:2", ["libc6"])
        self.assertEqual(caught.exception.code, "PROVISION_FAILED")
        self.assertEqual([call[1] for call in failing.calls], ["run", "rm"])

    def test_provisioning_rejects_shell_metacharacters_before_running_anything(self):
        docker = ScriptedDocker()
        for bad in ("nodejs; rm -rf /", "$(id)", "a b", "", "-oops"):
            with self.subTest(bad=bad), self.assertRaises(ContractError):
                hd.provision_image(host_runner(docker), "apt", "ubuntu@sha256:x", "linux/amd64", "t:1", [bad])
        self.assertEqual(docker.calls, [])


class ClientCycleTests(unittest.TestCase):
    def test_burst_client_proof_is_required_unprivileged_and_synthetic_cannot_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            host = hd.RecordingRunner(host_runner(ScriptedDocker()))
            record = {"authenticated-test-seam": True}
            with patch("rs9.hosted_deb.execute_probes", side_effect=stub_probes), patch(
                    "rs9.hosted_burst_clients.verify_client_burst", return_value={"status": "pass", "artifact": "linux-x64-gnu"}) as probe:
                rows, evidence = hd.client_cycle(host, hd.apt_spec(root / "apt", root / "key", "amd64"),
                    image="img", platform="linux/amd64", products=["theme-forge-stellar-burst"], repository=root,
                    prefix="deb-client", system="x86_64-linux", burst_record=record, burst_scratch=root / "probe")
            self.assertEqual(probe.call_args.args[1:3], (record, "x86_64-linux"))
            self.assertEqual(probe.call_args.kwargs["user"], hd.CLIENT_USER)
            self.assertEqual(evidence["theme-forge-stellar-burst"]["native_loader"]["artifact"], "linux-x64-gnu")
            self.assertEqual({row["status"] for row in hd.burst_client_gates(rows)}, {"not-run"})
            # The container receives source read-only, never the capture directory.
            started = next(r.command for r in host.receipts if r.command[:3] == ["docker", "run", "-d"])
            self.assertIn(str(root / "src") + ":/rs9-source:ro", started)

    def cycle(self, docker, *, cls=MockCommandRunner, products=("theme-forge-stellar-loom",), probes=stub_probes):
        host = hd.RecordingRunner(host_runner(docker, cls))
        spec = hd.apt_spec(Path("/x/apt"), Path("/x/key.gpg"), "amd64")
        with patch("rs9.hosted_deb.execute_probes", side_effect=probes):
            return hd.client_cycle(host, spec, image="img", platform="linux/amd64", products=products,
                                   repository=Path("."), prefix="deb-client")

    def statuses(self, gates):
        return {g["name"]: g["status"] for g in gates}

    def test_synthetic_receipts_never_produce_a_pass(self):
        docker = ScriptedDocker()
        gates, evidence = self.cycle(docker)
        names = self.statuses(gates)
        for suffix in ("install", "uninstall", "inventory"):
            self.assertEqual(names[f"deb-client.theme-forge-stellar-loom.{suffix}"], "not-run")
        self.assertEqual(set(names.values()), {"not-run"})
        self.assertIn("deb-client.theme-forge-stellar-loom.command.tfsl.supported-behavior", names)
        self.assertTrue(evidence["theme-forge-stellar-loom"]["inventory_clean"])
        started = docker.calls_containing("run", "-d")[0]
        self.assertEqual(started[started.index("--network") + 1], "none")
        verbs = [c for c in docker.calls if c[1] == "exec"]
        joined = [" ".join(c) for c in verbs]
        self.assertTrue(any(" install -y " in j for j in joined))
        self.assertTrue(any(" purge -y " in j for j in joined))
        self.assertEqual(docker.calls[-1][:3], ["docker", "rm", "-f"])  # container always removed

    def test_executed_receipts_pass_only_the_gates_whose_assertions_hold(self):
        # ExecutedMock models real subprocesses solely to exercise the pass branch.
        gates, _ = self.cycle(ScriptedDocker(), cls=ExecutedMock)
        names = self.statuses(gates)
        for suffix in ("install", "uninstall", "inventory"):
            self.assertEqual(names[f"deb-client.theme-forge-stellar-loom.{suffix}"], "pass")
        # Unbound probes stay not-run: a missing behavioural check is never promoted to pass.
        self.assertEqual(names["deb-client.theme-forge-stellar-loom.command.tfsl.supported-behavior"], "not-run")

    def test_leftover_files_after_purge_fail_the_inventory_gate(self):
        for cls in (MockCommandRunner, ExecutedMock):
            gates, evidence = self.cycle(ScriptedDocker(dirty_uninstall=True), cls=cls)
            row = next(g for g in gates if g["name"].endswith(".inventory"))
            self.assertEqual(row["status"], "fail")
            self.assertIn("usr/bin/tfsl", row["leftover"])
            self.assertFalse(evidence["theme-forge-stellar-loom"]["inventory_clean"])

    def test_install_failure_is_a_fail_and_stops_that_product(self):
        gates, evidence = self.cycle(ScriptedDocker(fail_install=True))
        names = self.statuses(gates)
        self.assertEqual(names["deb-client.theme-forge-stellar-loom.install"], "fail")
        self.assertEqual(names["deb-client.theme-forge-stellar-loom.client"], "fail")
        self.assertNotIn("deb-client.theme-forge-stellar-loom.uninstall", names)
        self.assertEqual(evidence["theme-forge-stellar-loom"]["error"], "CLIENT_INSTALL_FAILED")

    def test_probe_failures_and_missing_docker_are_reported_truthfully(self):
        def broken(command, path, **kwargs):
            raise ContractError("COMMAND_BEHAVIOR", "Released command expectation failed")

        gates, _ = self.cycle(ScriptedDocker(), cls=ExecutedMock, probes=broken)
        probe = [g for g in gates if ".probe." in g["name"]]
        self.assertEqual({g["status"] for g in probe}, {"fail"})
        self.assertEqual({g["reason"] for g in probe}, {"COMMAND_BEHAVIOR"})
        host = hd.RecordingRunner(host_runner(None))
        gates, _ = hd.client_cycle(host, hd.apt_spec(Path("/x"), Path("/k"), "amd64"), image="i", platform="p",
                                   products=("theme-forge-stellar-loom",), repository=Path("."), prefix="c")
        self.assertEqual([(g["status"], g["reason"]) for g in gates], [("not-run", "tool-unavailable:docker")])


class TamperTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.signer = FixtureSigner()
        self.wrong = FixtureSigner("B" * 40)

    def apt_tree(self):
        root = self.root / "apt-source"
        repo = build_apt_repository(root, packages_bytes=[
            build_minimal_deb("theme-forge-stellar-loom", "0.4.0", "all", payload_content=b"loom"),
            build_minimal_deb("theme-forge-solar-sail", "0.2.1", "all", payload_content=b"sail")])
        repo.sign_with_fixture(self.signer)
        return root

    def snapshot(self, root: Path) -> dict:
        return {p.relative_to(root).as_posix(): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()}

    def test_apt_copy_is_tampered_per_kind_and_the_source_is_untouched(self):
        source = self.apt_tree()
        before = self.snapshot(source)
        for kind in hd.TAMPER_KINDS_ALL:
            with self.subTest(kind=kind):
                dest = self.root / f"tamper-apt-{kind}"
                dest.mkdir()
                dirs = hd.tamper_family_copy("apt", kind, {"apt": source}, dest, arch="amd64",
                                             wrong_signer=self.wrong, product="theme-forge-solar-sail")
                self.assertEqual(dirs["apt"], dest / "apt")
                with self.assertRaises(ContractError):
                    verify_apt_signatures(dirs["apt"], self.signer)
                self.assertEqual(self.snapshot(source), before)
        # The tampered package is the product that will be installed, not an arbitrary one.
        pool = self.root / "tamper-apt-package/apt/pool"
        changed = [p.name for p in pool.rglob("*.deb")
                   if p.read_bytes() != next(q for q in (source / "pool").rglob(p.name)).read_bytes()]
        self.assertEqual(changed, ["theme-forge-solar-sail_0.2.1_all.deb"])

    def rpm_tree(self):
        base = self.root / "rpm-source/fedora/43/x86_64"
        (base / "Packages").mkdir(parents=True)
        (base / "repodata").mkdir()
        (base / "Packages/theme-forge-solar-sail-0.2.1-1.noarch.rpm").write_bytes(b"sail-rpm")
        (base / "Packages/theme-forge-stellar-loom-0.4.0-1.noarch.rpm").write_bytes(b"loom-rpm")
        (base / "repodata/repomd.xml").write_bytes(b"<repomd/>\n")
        (base / "repodata/repomd.xml.asc").write_bytes(self.signer.detach_sign(b"<repomd/>\n"))
        return self.root / "rpm-source"

    def test_rpm_copy_tampering_per_kind(self):
        source = self.rpm_tree()
        original = self.snapshot(source)
        for kind in hd.TAMPER_KINDS_ALL:
            with self.subTest(kind=kind):
                dest = self.root / f"tamper-dnf-{kind}"
                dest.mkdir()
                out = hd.tamper_family_copy("dnf", kind, {"rpm": source}, dest, arch="x86_64",
                                            wrong_signer=self.wrong, product="theme-forge-solar-sail")["rpm"]
                now, diff = self.snapshot(out), []
                for path, data in now.items():
                    if data != original[path]:
                        diff.append(Path(path).name)
                expected = {"package": ["theme-forge-solar-sail-0.2.1-1.noarch.rpm"], "index": ["repomd.xml"],
                            "signature": ["repomd.xml.asc"], "wrongkey": ["repomd.xml.asc"]}[kind]
                self.assertEqual(sorted(diff), expected)
                if kind == "wrongkey":
                    asc = (out / "fedora/43/x86_64/repodata/repomd.xml.asc").read_bytes()
                    self.wrong.verify(b"<repomd/>\n", asc)
                    with self.assertRaises(ContractError):
                        self.signer.verify(b"<repomd/>\n", asc)
                self.assertEqual(self.snapshot(source), original)

    def pacman_tree(self):
        base = self.root / "pacman-source/x86_64"
        base.mkdir(parents=True)
        for name, data in {"theme-forge-solar-sail-0.2.1-1-any.pkg.tar.zst": b"pkg", "rs9.db.tar.gz": b"db",
                           "rs9.db": b"db", "rs9.files.tar.gz": b"files", "rs9.files": b"files"}.items():
            (base / name).write_bytes(data)
            (base / f"{name}.sig").write_bytes(self.signer.detach_sign(data, armor=False))
        return self.root / "pacman-source"

    def test_pacman_copy_tampering_per_kind(self):
        source = self.pacman_tree()
        original = self.snapshot(source)
        for kind in hd.TAMPER_KINDS_ALL:
            with self.subTest(kind=kind):
                dest = self.root / f"tamper-pacman-{kind}"
                dest.mkdir()
                out = hd.tamper_family_copy("pacman", kind, {"pacman": source}, dest, arch="x86_64",
                                            wrong_signer=self.wrong, product="theme-forge-solar-sail")["pacman"]
                changed = {p for p, data in self.snapshot(out).items() if data != original[p]}
                self.assertTrue(changed, kind)
                if kind == "package":
                    self.assertEqual({Path(p).name for p in changed}, {"theme-forge-solar-sail-0.2.1-1-any.pkg.tar.zst"})
                if kind == "wrongkey":
                    for sig in (out / "x86_64").glob("*.sig"):
                        data = (out / "x86_64" / sig.name[:-4]).read_bytes()
                        self.wrong.verify(data, sig.read_bytes())

    def test_invalid_requests_fail_closed(self):
        dest = self.root / "dest"
        dest.mkdir()
        source = self.rpm_tree()
        with self.assertRaises(ContractError) as kind:
            hd.tamper_family_copy("dnf", "other", {"rpm": source}, dest, arch="x86_64", wrong_signer=self.wrong, product="p")
        self.assertEqual(kind.exception.code, "INVALID_ARGUMENT")
        with self.assertRaises(ContractError) as family:
            hd.tamper_family_copy("zypper", "package", {}, dest, arch="x86_64", wrong_signer=self.wrong, product="p")
        self.assertEqual(family.exception.code, "INVALID_ARGUMENT")
        with self.assertRaises(ContractError) as missing:
            hd.tamper_family_copy("dnf", "package", {"rpm": source}, dest, arch="x86_64", wrong_signer=self.wrong,
                                  product="theme-forge-nebular-fusion")
        self.assertEqual(missing.exception.code, "MISSING_PACKAGE")

    def cycle(self, docker, kinds=hd.TAMPER_KINDS_ALL):
        source = self.apt_tree()
        host = hd.RecordingRunner(host_runner(docker))
        work = self.root / "work"
        work.mkdir()
        keyring = self.root / "key.gpg"
        keyring.write_bytes(b"key")
        return hd.tamper_cycle(
            host, lambda dirs: hd.apt_spec(dirs["apt"], keyring, "amd64"), "apt", {"apt": source},
            image="img", platform="linux/amd64", product="theme-forge-solar-sail", work=work, arch="amd64",
            wrong_signer=self.wrong, kinds=kinds, prefix="deb-client")

    def test_rejected_tampering_is_not_run_when_synthetic_and_installation_is_never_a_pass(self):
        gates = self.cycle(ScriptedDocker())
        self.assertEqual([g["name"] for g in gates], [f"deb-client.tamper.{k}" for k in hd.TAMPER_KINDS_ALL])
        self.assertEqual({(g["status"], g["reason"]) for g in gates}, {("not-run", "synthetic-command-seam")})

    def test_a_client_that_installs_tampered_content_fails_every_tamper_gate(self):
        gates = self.cycle(ScriptedDocker(accept_tampered=True))
        self.assertEqual({g["status"] for g in gates}, {"fail"})

    def test_pages_cycle_requires_corrupted_signature_rejection(self):
        gates = self.cycle(ScriptedDocker(accept_tampered=True), kinds=hd.TAMPER_KINDS_PAGES)
        signature = next(g for g in gates if g["name"].endswith(".tamper.signature"))
        self.assertEqual(signature["status"], "fail")
        self.assertEqual({g["status"] for g in gates}, {"fail"})

    def test_executed_rejection_passes(self):
        source = self.apt_tree()
        host = hd.RecordingRunner(host_runner(ScriptedDocker(), ExecutedMock))
        work = self.root / "work-real"
        work.mkdir()
        gates = hd.tamper_cycle(
            host, lambda dirs: hd.apt_spec(dirs["apt"], self.root / "key.gpg", "amd64"), "apt", {"apt": source},
            image="img", platform="linux/amd64", product="theme-forge-solar-sail", work=work, arch="amd64",
            wrong_signer=self.wrong, kinds=("package",), prefix="p")
        self.assertEqual([g["status"] for g in gates], ["pass"])


class DebLaneTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.loom = self.root / "loom_input"
        self.capture, self.intent, _ = create_cli_fixture(self.loom)
        self.repository = self.root / "repo"
        self.repository.mkdir()
        self.scratch = self.root / "scratch"
        self.scratch.mkdir()

    def context(self, docker, **extra):
        context = {
            "repository": self.repository, "scratch": self.scratch,
            "captures": [(self.capture, self.intent, {})], "client": None,
            "binding": {"source_commit": "c" * 40}, "system": "amd64", "inputs": self.loom / "npm_archives",
            "pins": {}, "authentication_sha256": AUTH, "family": "deb", "maintainer": MAINTAINER,
            "runner": host_runner(docker), "required_products": ("theme-forge-stellar-loom",),
            "signing_fixture": FixtureSigner(), "wrong_signing_fixture": FixtureSigner("B" * 40),
        }
        context.update(extra)
        return context

    def run_lane(self, docker, probes=stub_probes, **extra):
        with patch("rs9.hosted_deb.execute_probes", side_effect=probes):
            return hd.execute(self.context(docker, **extra))

    def by_name(self, result):
        return {g["name"]: g for g in result["gates"]}

    def test_complete_synthetic_run_reports_every_required_gate_but_passes_none(self):
        docker = ScriptedDocker()
        result = self.run_lane(docker)
        validate_execution_result(result)
        gates = self.by_name(result)
        for name in REQUIRED_GATES["deb"]:
            if name in ("burst-native-addon-target", "burst-native-addon-load"):
                continue
            self.assertIn(name, gates)
        self.assertEqual({g["status"] for g in result["gates"]}, {"not-run"})
        self.assertEqual(gates["deb-package-build"]["reason"], "synthetic-command-seam")
        for kind in hd.TAMPER_KINDS_ALL:
            self.assertIn(f"deb-client.tamper.{kind}", gates)
        self.assertIn("deb-client.theme-forge-stellar-loom.inventory", gates)

        details = result["details"]
        self.assertEqual(details["status"], "incomplete")
        self.assertEqual(details["apt_repository"]["verified_packages"], 1)
        self.assertEqual(details["apt_repository"]["verified_indices"], 6)
        self.assertRegex(details["apt_repository"]["merkle_root"], r"^[0-9a-f]{64}$")
        self.assertFalse(Path(details["manifest_path"]).is_absolute())
        manifest = json.loads((self.scratch / details["manifest_path"]).read_bytes())
        self.assertEqual((manifest["schema"], manifest["family"], manifest["nonproduction"]),
                         (hd.SCHEMA_DEB, "deb", True))
        self.assertEqual(manifest["authentication_sha256"], AUTH)
        self.assertTrue(manifest["receipts"])

        # The apt tree is the signed assembled repository the client was pointed at.
        apt_root = self.scratch / "apt"
        verify_apt_signatures(apt_root, FixtureSigner())
        self.assertTrue((apt_root / "dists/resolute/InRelease").is_file())
        bundle = load_custody_bundle(self.scratch / details["custody"]["directory"], expected_family="deb",
                                     expected_authentication_sha256=AUTH)
        self.assertEqual(list(bundle["packages"]), ["theme-forge-stellar-loom_0.4.0-1_all.deb"])
        self.assertEqual(bundle["manifest"]["merkle"]["root"], details["custody"]["merkle_root"])
        # Provisioned images are removed again.
        removed = [c[-1] for c in docker.calls if c[1] == "rmi"]
        provisioned = [c[c.index("commit") + 2] for c in docker.calls if "commit" in c[:2]]
        self.assertEqual(sorted(removed), sorted(provisioned))
        self.assertEqual(len(provisioned), 2)
        # No production credential or production key path appears anywhere in the retained manifest.
        text = (self.scratch / details["manifest_path"]).read_text("utf-8")
        self.assertNotIn("PRIVATE KEY", text)

    def test_debian_builder_real_signature_and_hosted_autospec_call(self):
        import inspect
        from rs9.build_deb import build_deb_candidate
        self.assertIn("maintainer", inspect.signature(build_deb_candidate).parameters)
        with patch("rs9.hosted_deb.build_deb_candidate", autospec=True,
                   side_effect=build_deb_candidate) as builder:
            result = self.run_lane(ScriptedDocker())
        self.assertEqual(builder.call_count, 1)
        call = builder.call_args
        self.assertEqual(call.args[2], "all")
        self.assertEqual(call.kwargs["maintainer"], MAINTAINER)
        self.assertEqual(result["details"]["products"]["theme-forge-stellar-loom"]["architecture"], "all")

    def test_build_filesystem_failure_has_stable_safe_code(self):
        with patch("rs9.hosted_deb.build_deb_candidate", autospec=True,
                   side_effect=OSError("private filesystem error")):
            result = self.run_lane(ScriptedDocker())
        self.assertEqual(result["details"]["build_errors"]["theme-forge-stellar-loom"], "PACKAGE_FILESYSTEM")
        self.assertNotIn("private filesystem error", json.dumps(result["details"]))

    def test_every_container_is_network_disconnected_after_provisioning(self):
        docker = ScriptedDocker()
        self.run_lane(docker)
        started = docker.calls_containing("run", "-d")
        self.assertTrue(started)
        for call in started:
            self.assertEqual(call[call.index("--network") + 1], "none")
        builds = [call for call in docker.calls_containing("dpkg-deb") if "--build" in call]
        self.assertTrue(builds)
        for call in builds:
            self.assertEqual(call[call.index("--network") + 1], "none")
            self.assertIn("SOURCE_DATE_EPOCH=1767225600", call)
        provisions = [c for c in docker.calls if c[1] == "run" and "--name" in c and "-d" not in c]
        self.assertTrue(provisions)

    def test_missing_docker_is_not_run_and_blocks_downstream_gates(self):
        result = self.run_lane(None)
        validate_execution_result(result)
        gates = self.by_name(result)
        self.assertEqual((gates["deb-container-environment"]["status"], gates["deb-container-environment"]["reason"]),
                         ("not-run", "tool-unavailable:docker"))
        for name in ("deb-package-build", "deb-shlibdeps-closure", "deb-apt-repository-indexing", "deb-client-qualification"):
            self.assertEqual((gates[name]["status"], gates[name]["reason"]),
                             ("not-run", "blocked-by:deb-container-environment"))
        self.assertNotIn("custody", result["details"])

    def test_unassigned_maintainer_blocks_the_build_without_inventing_one(self):
        result = self.run_lane(ScriptedDocker(), maintainer=None)
        gates = self.by_name(result)
        for name in ("deb-package-build", "deb-shlibdeps-closure", "deb-apt-repository-indexing", "deb-client-qualification"):
            self.assertEqual(gates[name]["reason"], "maintainer-unassigned")
        self.assertNotIn("apt_repository", result["details"])
        (self.repository / "operators/live1").mkdir(parents=True)
        (self.repository / "operators/live1/targets.json").write_bytes(json.dumps({"maintainer": MAINTAINER}).encode())
        self.scratch = self.root / "scratch2"
        self.scratch.mkdir()
        self.assertEqual(self.by_name(self.run_lane(ScriptedDocker(), maintainer=None))["deb-package-build"]["reason"],
                         "maintainer-unassigned")

    def test_build_failure_is_a_fail_and_blocks_repository_and_clients(self):
        result = self.run_lane(ScriptedDocker(fail_build=True))
        gates = self.by_name(result)
        self.assertEqual(gates["deb-package-build"]["status"], "fail")
        self.assertIn("theme-forge-stellar-loom:BUILD_FAILED", gates["deb-package-build"]["reason"])
        self.assertEqual(gates["deb-shlibdeps-closure"]["status"], "fail")
        for name in ("deb-apt-repository-indexing", "deb-client-qualification"):
            self.assertEqual(gates[name]["reason"], "blocked-by:deb-package-build")
        self.assertNotIn("custody", result["details"])

    def test_missing_capture_is_a_fail_not_a_skipped_product(self):
        result = self.run_lane(ScriptedDocker(), captures=[])
        gate = self.by_name(result)["deb-package-build"]
        self.assertEqual(gate["status"], "fail")
        self.assertIn("theme-forge-stellar-loom:capture-missing", gate["reason"])

    def test_unavailable_gnupg_blocks_signing_and_clients_but_keeps_custody(self):
        with patch("rs9.signing_fixture.find_gpg_binary", return_value=None):
            result = self.run_lane(ScriptedDocker(), signing_fixture=None)
        gates = self.by_name(result)
        for name in ("deb-apt-repository-indexing", "deb-client-qualification"):
            self.assertEqual((gates[name]["status"], gates[name]["reason"]), ("not-run", "gpg-unavailable"))
        self.assertIn("custody", result["details"])

    def test_client_accepting_tampered_content_fails_qualification(self):
        gates = self.by_name(self.run_lane(ScriptedDocker(accept_tampered=True)))
        for kind in hd.TAMPER_KINDS_ALL:
            self.assertEqual(gates[f"deb-client.tamper.{kind}"]["status"], "fail")
        self.assertEqual(gates["deb-client-qualification"]["status"], "fail")

    def test_leftover_files_and_probe_failures_fail_qualification(self):
        gates = self.by_name(self.run_lane(ScriptedDocker(dirty_uninstall=True)))
        self.assertEqual(gates["deb-client.theme-forge-stellar-loom.inventory"]["status"], "fail")
        self.assertEqual(gates["deb-client-qualification"]["status"], "fail")

        def broken(command, path, **kwargs):
            raise ContractError("COMMAND_BEHAVIOR", "Released command expectation failed")

        self.scratch = self.root / "scratch-probe"
        self.scratch.mkdir()
        gates = self.by_name(self.run_lane(ScriptedDocker(), probes=broken))
        self.assertEqual(gates["deb-client-qualification"]["status"], "fail")

    def test_invalid_system_and_family_are_rejected_up_front(self):
        with self.assertRaises(ContractError) as system:
            hd.execute(self.context(ScriptedDocker(), system="x86_64-linux"))
        self.assertEqual(system.exception.code, "INVALID_ARCHITECTURE")
        with self.assertRaises(ContractError) as family:
            hd.execute(self.context(ScriptedDocker(), family="nix"))
        self.assertEqual(family.exception.code, "UNSUPPORTED_PLATFORM")

    def test_arm64_lane_uses_the_arm64_platform(self):
        docker = ScriptedDocker(system="arm64")
        result = self.run_lane(docker, system="arm64")
        self.assertEqual(result["details"]["container"]["platform"], "linux/arm64")
        self.assertEqual(docker.calls[0], ["docker", "pull", "--platform", "linux/arm64", "ubuntu:26.04"])
        started = docker.calls_containing("run", "-d")
        self.assertTrue(all(c[c.index("--platform") + 1] == "linux/arm64" for c in started))

    def test_container_commands_mount_lane_work_only_never_orchestration_paths(self):
        outer = self.root / "orchestration-outer"
        outer.mkdir()
        capture_dir = outer / "capture"
        capture_dir.mkdir()
        (capture_dir / "test.txt").write_bytes(b"captured")
        auth_file = outer / "authentication.json"
        auth_file.write_bytes(b"auth-secret")
        inputs_dir = outer / "inputs"
        inputs_dir.mkdir()
        lane_scratch = outer / "lane-work"
        lane_scratch.mkdir()

        docker = ScriptedDocker()
        result = self.run_lane(docker, scratch=lane_scratch, inputs=inputs_dir)
        validate_execution_result(result)

        mount_calls = docker.calls_containing("-v")
        self.assertTrue(mount_calls)
        for call in mount_calls:
            for idx, arg in enumerate(call):
                if arg == "-v":
                    mount_spec = call[idx + 1]
                    source = Path(mount_spec.split(":")[0]).resolve()
                    # Source must be inside lane_scratch (lane-work) or inside fixture homedir
                    is_lane_work = source == lane_scratch.resolve() or lane_scratch.resolve() in source.parents
                    is_fixture = self.root.resolve() in source.parents and "fixture" in str(source)
                    self.assertTrue(
                        is_lane_work or is_fixture,
                        f"Mount source {source} is outside lane-work scratch and fixture homedir",
                    )
                    # Never mount outer orchestration paths
                    self.assertNotEqual(source, outer.resolve())
                    self.assertNotEqual(source, capture_dir.resolve())
                    self.assertNotEqual(source, inputs_dir.resolve())
                    self.assertNotEqual(source, auth_file.resolve())

    def test_deb_build_errors_diagnostics_emitted(self):
        docker = ScriptedDocker(fail_build=True)
        result = self.run_lane(docker)
        details = result["details"]
        self.assertIn("build_errors", details)
        diag_path = self.scratch / "diagnostics" / "build-errors.json"
        self.assertTrue(diag_path.is_file())
        self.assertIn(diag_path, result["artifacts"])

    def test_empty_architecture_output_in_deb_environment_raises_clean_contract_error(self):
        class EmptyArchDocker(ScriptedDocker):
            def _run(self, a):
                script = a[-1] if a[-3:-1] == ["sh", "-c"] else ""
                if "cat /etc/os-release" in script:
                    return self.receipt(a, out=b"   \n\n")
                return super()._run(a)

        docker = EmptyArchDocker()
        with self.assertRaises(ContractError) as caught:
            hd.prepare_environment(host_runner(docker), "amd64", {})
        self.assertIn(caught.exception.code, ("UNSUPPORTED_PLATFORM", "INVALID_ARCHITECTURE"))
        self.assertIn("substage", caught.exception.details)


class PagesLaneTests(unittest.TestCase):
    CLI = ("theme-forge-stellar-loom", "theme-forge-solar-sail")
    NATIVE = hd.NATIVE_PRODUCT

    def setUp(self):
        # Client orchestration uses synthetic package bytes and command receipts.
        loader_record = patch("rs9.hosted_deb._burst_release_record", return_value={"synthetic": True})
        loader_probe = patch("rs9.hosted_burst_clients.verify_client_burst", return_value={"status": "pass"})
        loader_record.start()
        loader_probe.start()
        self.addCleanup(loader_record.stop)
        self.addCleanup(loader_probe.stop)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.repository = self.root / "repo"
        self.repository.mkdir()
        self.scratch = self.root / "scratch"
        self.scratch.mkdir()
        self.inputs = self.root / "inputs"
        self.inputs.mkdir()

    def context(self, docker=None, **extra):
        context = {"repository": self.repository, "scratch": self.scratch, "system": "generation", "family": "pages",
                   "inputs": self.inputs, "pins": {
                       "pacman": {"container_digest": "docker.io/library/archlinux@sha256:" + DIGEST},
                       "rpm": {"container_digests": {"x86_64": "registry.fedoraproject.org/fedora@sha256:" + DIGEST}}},
                   "authentication_sha256": AUTH, "captures": [(None, {"project": {"id": self.NATIVE}}, {})],
                   "client": None, "runner": host_runner(docker),
                   "wrong_signing_fixture": FixtureSigner("B" * 40)}
        context.update(extra)
        return context

    def bundle(self, name, family, system, packages, auth=AUTH):
        target = self.inputs / name
        target.mkdir()
        write_custody_bundle(target, family=family, system=system, packages=packages,
                             authentication_sha256=auth, source_commit="c" * 40)
        return target

    def deb_packages(self, arch):
        packages = {}
        for product in PRODUCTS:
            deb_arch = "all" if product in self.CLI else arch
            packages[f"{product}_1.0.0_{deb_arch}.deb"] = build_minimal_deb(
                product, "1.0.0", deb_arch, depends="nodejs (>= 22)", payload_content=f"{product}-{deb_arch}".encode())
        return packages

    def rpm_packages(self, arch):
        return {f"{p}-1.0.0-1.fc43.{'noarch' if p in self.CLI else arch}.rpm": make_rpm({f"usr/bin/{p}": p.encode()})
                for p in PRODUCTS}

    def pacman_packages(self):
        return {f"{p}-1.0.0-1-{'any' if p in self.CLI else 'x86_64'}.pkg.tar.zst": zstd_raw_frame(b"pkg:" + p.encode())
                for p in PRODUCTS}

    def all_bundles(self):
        self.bundle("deb-amd64", "deb", "amd64", self.deb_packages("amd64"))
        self.bundle("deb-arm64", "deb", "arm64", self.deb_packages("arm64"))
        self.bundle("rpm-x86", "rpm", "x86_64-linux", self.rpm_packages("x86_64"))
        self.bundle("rpm-arm", "rpm", "aarch64-linux", self.rpm_packages("aarch64"))
        self.bundle("pacman", "pacman", "x86_64-linux", self.pacman_packages())

    def by_name(self, result):
        return {g["name"]: g for g in result["gates"]}

    def test_missing_custody_blocks_all_pages_gates_and_names_what_is_missing(self):
        self.bundle("deb-amd64", "deb", "amd64", self.deb_packages("amd64"))
        result = hd.execute(self.context(ScriptedDocker()))
        validate_execution_result(result)
        gates = self.by_name(result)
        self.assertEqual(set(gates), set(hd.PAGES_GATES))
        for name in REQUIRED_GATES["pages"]:
            self.assertEqual(gates[name]["status"], "not-run")
            self.assertEqual(gates[name]["reason"],
                             "custody-missing:deb-arm64,rpm-x86_64-linux,rpm-aarch64-linux,pacman-x86_64-linux")
        self.assertEqual(result["details"]["status"], "incomplete")

    def test_no_inputs_at_all_is_not_run(self):
        result = hd.execute(self.context(None, inputs=None))
        self.assertEqual({g["status"] for g in result["gates"]}, {"not-run"})
        self.assertTrue((self.scratch / result["details"]["manifest_path"]).is_file())

    def test_pages_with_custody_and_unavailable_package_tools_is_not_run(self):
        self.all_bundles()
        home = self.root / "fixture-home"
        home.mkdir()
        fixture = HermeticFixtureSigner(homedir=home)
        result = hd.execute(self.context(None, signing_fixture=fixture))
        self.assertEqual({g["status"] for g in result["gates"]}, {"not-run"})
        self.assertTrue(all("docker" in g["reason"] for g in result["gates"]))
        self.assertTrue((self.scratch / result["details"]["manifest_path"]).is_file())

    def test_custody_that_is_not_exact_or_not_from_this_run_is_rejected_fail_closed(self):
        target = self.bundle("deb-amd64", "deb", "amd64", self.deb_packages("amd64"))
        next(iter((target / "files").iterdir())).write_bytes(b"tampered")
        gates = self.by_name(hd.execute(self.context(None)))
        self.assertEqual({g["reason"] for g in gates.values()}, {"custody-invalid:TAMPER_DETECTED"})

        self.scratch = self.root / "scratch-b"
        self.scratch.mkdir()
        shutil.rmtree(self.inputs)
        self.inputs.mkdir()
        self.bundle("deb-amd64", "deb", "amd64", self.deb_packages("amd64"), auth="e" * 64)
        gates = self.by_name(hd.execute(self.context(None)))
        self.assertEqual({g["reason"] for g in gates.values()}, {"custody-invalid:HOSTED_PROVENANCE"})

        self.scratch = self.root / "scratch-c"
        self.scratch.mkdir()
        shutil.rmtree(self.inputs)
        self.inputs.mkdir()
        self.bundle("one", "deb", "amd64", self.deb_packages("amd64"))
        self.bundle("two", "deb", "amd64", self.deb_packages("amd64"))
        gates = self.by_name(hd.execute(self.context(None)))
        self.assertEqual({g["reason"] for g in gates.values()}, {"custody-invalid:CUSTODY_CONFLICT"})

    def test_pages_scratch_repair_returns_exact_upstream_missing_custody_not_output_not_empty(self):
        outer = self.root / "orchestration-pages"
        outer.mkdir()
        (outer / "capture").mkdir()
        (outer / "authentication.json").write_bytes(b"auth")
        lane_scratch = outer / "lane-work"
        lane_scratch.mkdir()
        empty_inputs = outer / "inputs"
        empty_inputs.mkdir()

        result = hd.execute(self.context(None, scratch=lane_scratch, inputs=empty_inputs))
        validate_execution_result(result)
        gates = self.by_name(result)
        for name in REQUIRED_GATES["pages"]:
            self.assertEqual(gates[name]["status"], "not-run")
            self.assertEqual(
                gates[name]["reason"],
                "custody-missing:deb-amd64,deb-arm64,rpm-x86_64-linux,rpm-aarch64-linux,pacman-x86_64-linux",
            )
        self.assertEqual(result["details"]["status"], "incomplete")
        self.assertTrue((lane_scratch / "hosted-pages-manifest.json").is_file())

    def test_architecture_all_packages_that_differ_between_lanes_fail_closed(self):
        amd64, arm64 = self.deb_packages("amd64"), self.deb_packages("arm64")
        pure = self.CLI[0]
        arm64[f"{pure}_1.0.0_all.deb"] = build_minimal_deb(pure, "1.0.0", "all", payload_content=b"other")
        self.bundle("deb-amd64", "deb", "amd64", amd64)
        self.bundle("deb-arm64", "deb", "arm64", arm64)
        self.bundle("rpm-x86", "rpm", "x86_64-linux", self.rpm_packages("x86_64"))
        self.bundle("rpm-arm", "rpm", "aarch64-linux", self.rpm_packages("aarch64"))
        self.bundle("pacman", "pacman", "x86_64-linux", self.pacman_packages())
        result = hd.execute(self.context(ScriptedDocker(), signing_fixture=FixtureSigner()))
        gates = self.by_name(result)
        for name in hd.PAGES_GATES:
            self.assertEqual((gates[name]["status"], gates[name]["reason"]), ("fail", "CUSTODY_CONFLICT"))

    def test_assembled_tree_is_exact_scanned_signed_and_client_tested_per_family(self):
        binary = usable_gpg()
        if not binary:
            self.skipTest("GnuPG binary not available")
        self.all_bundles()
        docker = ScriptedDocker()
        with SigningFixture(gpg_binary=binary) as fixture, patch("rs9.hosted_deb.execute_probes", side_effect=stub_probes), patch(
                "rs9.hosted_smoke.prepare_smoke", return_value=None), patch(
                "rs9.hosted_packaging.sign_rpm", side_effect=fake_sign_rpm):
            result = hd.execute(self.context(docker, signing_fixture=fixture))
            self.assertTrue((self.scratch / "pages-tree").is_dir(), str(result["gates"]))
            # Apt metadata in the assembled tree is signed by this lane's real fixture key.
            verified = verify_apt_signatures(self.scratch / "pages-tree/apt", fixture)
            self.assertTrue(verified["signature_authenticated"])
            self.assertEqual(verified["verified_issuer"], fixture.primary_fingerprint)
        validate_execution_result(result)
        self._assert_assembled_tree_coverage(result, fixture, docker)

    def test_assembled_tree_is_exact_scanned_signed_and_client_tested_hermetic(self):
        self.all_bundles()
        docker = ScriptedDocker()
        home = self.root / "fixture-home"
        home.mkdir(parents=True, exist_ok=True)
        fixture = HermeticFixtureSigner(homedir=home)
        with patch("rs9.hosted_deb.execute_probes", side_effect=stub_probes), patch(
                "rs9.hosted_smoke.prepare_smoke", return_value=None), patch(
                "rs9.hosted_packaging.sign_rpm", side_effect=fake_sign_rpm):
            result = hd.execute(self.context(docker, signing_fixture=fixture))
            self.assertTrue((self.scratch / "pages-tree").is_dir(), str(result["gates"]))
            verified = verify_apt_signatures(self.scratch / "pages-tree/apt", fixture)
            self.assertTrue(verified["signature_authenticated"])
            self.assertEqual(verified["verified_issuer"], fixture.primary_fingerprint)
        validate_execution_result(result)
        self._assert_assembled_tree_coverage(result, fixture, docker)

    def _assert_assembled_tree_coverage(self, result, fixture, docker):
        gates = self.by_name(result)
        self.assertEqual([g for g in result["gates"] if g["status"] == "fail"], [])
        self.assertNotIn("pass", {g["status"] for n, g in gates.items() if n.startswith("pages-client.")})
        self.assertEqual(gates["pages-repository-objects"]["status"], "not-run")  # synthetic metadata tools
        self.assertEqual(gates["pages-inventory-integrity"]["status"], "pass")      # exact bytes and Merkle root
        self.assertIn(gates["pages-privacy-scan"]["status"], {"pass", "not-run"})
        if gates["pages-privacy-scan"]["status"] == "not-run":
            self.assertTrue(gates["pages-privacy-scan"]["reason"].startswith("format-scan-incomplete:"))

        tree = self.scratch / "pages-tree"
        self.assertEqual((tree / "CNAME").read_text(), "rs9.knowledge-forge.ai\n")
        for path in ("keys/rs9-candidate-fixture-NONPRODUCTION.asc", "keys/rs9-candidate-fixture-NONPRODUCTION.gpg", "docs/install/index.html", "rpm/rs9.repo",
                     "apt/dists/resolute/InRelease", "apt/dists/resolute/Release.gpg",
                     "rpm/fedora/43/x86_64/repodata/repomd.xml.asc", "rpm/fedora/43/aarch64/repodata/repomd.xml.asc",
                     "pacman/x86_64/rs9.db.tar.gz.sig"):
            self.assertTrue((tree / path).is_file(), path)
        # Packages in the tree are byte-identical to the downloaded custody files.
        for bundle in self.inputs.iterdir():
            for package in (bundle / "files").iterdir():
                if package.name.endswith(".pkg.tar.zst"):
                    found = list((tree / "pacman").rglob(package.name))
                    self.assertEqual({p.read_bytes() for p in found}, {package.read_bytes()}, package.name)
                elif package.name.endswith(".rpm"):
                    found = list((tree / "rpm").rglob(package.name))
                    self.assertTrue(found)
                    expected = package.read_bytes()[:128] + b"fix\0" + package.read_bytes()[132:]
                    self.assertTrue(all(p.read_bytes() == expected for p in found))
        # The committed Merkle root is the root of what is actually on disk, and the tree rescans clean.
        disk = {p.relative_to(tree).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in tree.rglob("*") if p.is_file()}
        self.assertEqual(result["details"]["pages"]["merkle_root"], merkle_inventory(disk)["root"])
        self.assertEqual(scan_pages_tree(tree, manifest=disk)["file_count"], len(disk))

        for family in ("apt", "dnf", "pacman"):
            for tamper in ("package", "index", "signature", "wrongkey"):
                self.assertIn(f"pages-client.{family}.tamper.{tamper}", gates)
            for product in PRODUCTS:
                for step in ("install", "uninstall", "inventory"):
                    self.assertIn(f"pages-client.{family}.{product}.{step}", gates)
        started = docker.calls_containing("run", "-d")
        self.assertTrue(started)
        self.assertTrue(all(c[c.index("--network") + 1] == "none" for c in started))
        # No secret material in any retained evidence.
        text = (self.scratch / result["details"]["manifest_path"]).read_text("utf-8")
        self.assertNotIn("PRIVATE KEY", text)
        self.assertNotIn("SECRET KEY", text)


    def test_rpm_noarch_conflict_stops_pages_before_fixture_repositories(self):
        self.bundle("deb-amd64", "deb", "amd64", self.deb_packages("amd64"))
        self.bundle("deb-arm64", "deb", "arm64", self.deb_packages("arm64"))
        rpm_x86, rpm_arm = self.rpm_packages("x86_64"), self.rpm_packages("aarch64")
        name = f"{self.CLI[0]}-1.0.0-1.fc43.noarch.rpm"
        rpm_arm[name] = make_rpm({f"usr/bin/{self.CLI[0]}": b"conflicting"})
        self.bundle("rpm-x86", "rpm", "x86_64-linux", rpm_x86)
        self.bundle("rpm-arm", "rpm", "aarch64-linux", rpm_arm)
        self.bundle("pacman", "pacman", "x86_64-linux", self.pacman_packages())
        result = hd.execute(self.context(ScriptedDocker(), signing_fixture=FixtureSigner()))
        self.assertEqual({(g["status"], g["reason"]) for g in result["gates"]},
                         {("fail", "CUSTODY_CONFLICT")})
        self.assertFalse((self.scratch / "pages-tree").exists())

    def test_pages_setup_errors_report_all_required_client_gates(self):
        for index, error in enumerate((ContractError("PROVISION_FAILED", "fixture failure"),
                                       hd.NativePrerequisiteUnavailable(["docker"]))):
            scratch = self.root / ("setup-" + str(index))
            scratch.mkdir()
            gates = []
            with patch("rs9.hosted_deb.prepare_environment", side_effect=error):
                hd._pages_client_tests(self.context(), hd.RecordingRunner(host_runner(ScriptedDocker())),
                    self.repository, scratch, {}, self.root, {}, FixtureSigner(), gates, {}, [], [], "rpm-test")
            required = {g["name"]: g for g in gates}
            expected_status = "not-run" if isinstance(error, hd.NativePrerequisiteUnavailable) else "fail"
            for name in ("pages-client.apt", "pages-client.dnf", "pages-client.pacman"):
                self.assertEqual(required[name]["status"], expected_status)
                self.assertEqual(required[name]["reason"], hd._family_error(error))


class RpmCustodyTests(unittest.TestCase):
    def test_pages_custody_rejects_burst_any_noarch_all(self):
        product = "theme-forge-stellar-burst"
        for family, system, name in (("rpm", "x86_64-linux", product + "-0.6.1-1.noarch.rpm"),
                                    ("pacman", "x86_64-linux", product + "-0.6.1-1-any.pkg.tar.zst"),
                                    ("deb", "amd64", product + "_0.6.1-1_all.deb")):
            with self.subTest(family=family), self.assertRaises(ContractError) as caught:
                hd._validate_bundle_architectures({"manifest": {"family": family, "system": system}, "packages": {name: None}})
            self.assertEqual(caught.exception.code, "CUSTODY_ARCHITECTURE")

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()

    def make_bundle(self, family: str, system: str, pkgs: dict[str, bytes]) -> dict[str, Any]:
        pkg_paths = {}
        for name, data in pkgs.items():
            p = self.root / f"{system}_{name}"
            p.write_bytes(data)
            pkg_paths[name] = p
        return {"manifest": {"family": family, "system": system}, "packages": pkg_paths}

    def test_rpm_custody_unique_allows_identical_noarch_bytes(self):
        b1 = self.make_bundle("rpm", "x86_64-linux", {
            "theme-forge-stellar-loom-1.0.0-1.fc43.noarch.rpm": b"exact-noarch-bytes",
            "theme-forge-nebular-fusion-1.0.0-1.fc43.x86_64.rpm": b"native-x86",
        })
        b2 = self.make_bundle("rpm", "aarch64-linux", {
            "theme-forge-stellar-loom-1.0.0-1.fc43.noarch.rpm": b"exact-noarch-bytes",
            "theme-forge-nebular-fusion-1.0.0-1.fc43.aarch64.rpm": b"native-arm",
        })
        result = hd._rpm_custody_unique([b1, b2])
        self.assertIn("theme-forge-stellar-loom-1.0.0-1.fc43.noarch.rpm", result)
        self.assertEqual(result["theme-forge-stellar-loom-1.0.0-1.fc43.noarch.rpm"].read_bytes(), b"exact-noarch-bytes")

    def test_rpm_custody_unique_rejects_conflicting_noarch_bytes_for_same_filename(self):
        b1 = self.make_bundle("rpm", "x86_64-linux", {
            "theme-forge-stellar-loom-1.0.0-1.fc43.noarch.rpm": b"bytes-from-x86",
        })
        b2 = self.make_bundle("rpm", "aarch64-linux", {
            "theme-forge-stellar-loom-1.0.0-1.fc43.noarch.rpm": b"bytes-from-arm-differ",
        })
        with self.assertRaises(ContractError) as caught:
            hd._rpm_custody_unique([b1, b2])
        self.assertEqual(caught.exception.code, "CUSTODY_CONFLICT")

    def test_rpm_custody_unique_rejects_conflicting_noarch_packages_for_same_product(self):
        b1 = self.make_bundle("rpm", "x86_64-linux", {
            "theme-forge-stellar-loom-1.0.0-1.fc43.noarch.rpm": b"bytes-v1",
        })
        b2 = self.make_bundle("rpm", "aarch64-linux", {
            "theme-forge-stellar-loom-1.0.1-1.fc43.noarch.rpm": b"bytes-v2",
        })
        with self.assertRaises(ContractError) as caught:
            hd._rpm_custody_unique([b1, b2])
        self.assertEqual(caught.exception.code, "CUSTODY_CONFLICT")

    def test_rpm_custody_unique_allows_different_native_packages(self):
        b1 = self.make_bundle("rpm", "x86_64-linux", {
            "theme-forge-nebular-fusion-1.0.0-1.fc43.x86_64.rpm": b"x86-elf",
        })
        b2 = self.make_bundle("rpm", "aarch64-linux", {
            "theme-forge-nebular-fusion-1.0.0-1.fc43.aarch64.rpm": b"arm-elf",
        })
        result = hd._rpm_custody_unique([b1, b2])
        self.assertIn("theme-forge-nebular-fusion-1.0.0-1.fc43.x86_64.rpm", result)
        self.assertIn("theme-forge-nebular-fusion-1.0.0-1.fc43.aarch64.rpm", result)

    def test_targets_maintainer_returns_valid_reserved_maintainer(self):
        repo_root = Path(__file__).resolve().parents[1]
        maintainer = hd._targets_maintainer(repo_root)
        self.assertEqual(maintainer, "Knowledge Forge AI <nonproduction@knowledge-forge.invalid>")
        from rs9.build_native import validate_maintainer
        self.assertEqual(validate_maintainer(maintainer), maintainer)

    def test_hosted_deb_offline_npm_archives_delegates_to_shared_helper(self):
        scratch = self.root / "scratch"
        scratch.mkdir()
        # Native desktop returns None even with dependencies
        neb_capture = SimpleNamespace(
            source={"package.json": json.dumps({"dependencies": {"react": "18.0.0"}})}
        )
        self.assertIsNone(hd._offline_npm_archives(neb_capture, "theme-forge-nebular-fusion", None, None, scratch))

        # Native node cli resolves closure
        burst_capture, burst_intent, offline_npm = create_cli_fixture(
            scratch / "burst_fix", product="theme-forge-stellar-burst"
        )
        inputs = scratch / "burst_fix/npm_archives"
        archives = hd._offline_npm_archives(burst_capture, "theme-forge-stellar-burst", inputs, None, scratch)
        self.assertIsNotNone(archives)
        self.assertIn("node_modules/min-dep", archives)


if __name__ == "__main__":
    unittest.main()
