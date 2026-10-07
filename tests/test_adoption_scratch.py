"""Real-Git scratch custody and attended run-8/shared-adoption regressions.

Only fixture fetch/push and GitHub collection cross a test seam. Inventory,
filesystem reads, staging checks and local fixture commits use the live source.
"""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

from rs9 import adopt_candidate as backend
from rs9.candidate_inventory import MANIFEST, candidate_paths, file_inventory, product_delta, verify_inventory
from rs9.candidate_readiness import readiness_record
from rs9.errors import ContractError

SOURCE = Path(__file__).resolve().parents[1]
GIT_OVERRIDES = {
    "GIT_INDEX_FILE", "GIT_DIR", "GIT_WORK_TREE", "GIT_OBJECT_DIRECTORY",
    "GIT_COMMON_DIR", "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_CONFIG_PARAMETERS",
}


@contextlib.contextmanager
def local_umask(mask):
    previous = os.umask(mask)
    try:
        yield
    finally:
        os.umask(previous)


def index_state(root):
    """Content/staged state; Git may refresh stat metadata without changing it."""
    return tuple(subprocess.check_output(["git", "-C", str(root), *args]) for args in (
        ["ls-files", "-s", "-z"], ["diff", "--cached", "--name-only", "-z"]))


class BeforeMutation(Exception):
    pass


class GitCandidate:
    def __init__(self, base):
        self.base = base
        self.root = base / "repo"
        self.root.mkdir()
        self.output = base / "home/Documents/agent/outbox/release-starport-9_dev/packet"
        self.output.mkdir(parents=True)
        self.calls = []
        self.ignored_listings = []
        self.stop_before_add = True
        self.git("init", "-b", "main")
        self.git("remote", "add", "origin", "https://github.com/" + backend.REPOSITORY + ".git")
        for relative in (".gitignore", "operators/live1/hosted-lanes.json",
                         "operators/live1/adopt-and-qualify.py", "operators/live1/run-hosted8.py"):
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(SOURCE / relative, target)
        self.write("src/fixture_pkg/a.py", b"value = 'parent'\n")
        self.write("src/fixture_pkg/unchanged.py", b"pass\n")
        self.write("src/fixture_pkg/deleted.py", b"pass\n")
        self.write(MANIFEST, b"{}\n")
        self.git("add", "-A")
        self.git("commit", "-m", "Local adoption fixture parent")
        self.parent = self.git("rev-parse", "HEAD")
        self.git("update-ref", "refs/remotes/origin/main", self.parent)
        self.write("src/fixture_pkg/a.py", b"value = 'candidate'\n")
        self.write("src/fixture_pkg/new.py", b"pass\n")
        self.write("src/fixture_pkg/.scratch/nested.py", b"nested = True\n")
        (self.root / "src/fixture_pkg/deleted.py").unlink()
        self.manifest = {
            "parent": self.parent, "candidate_adoption_ready": False,
            "production_enabled": False, "publication_authority": False,
            "adoption_scope": "partial-diagnostic", "readiness": readiness_record(),
            "deleted_paths": ["src/fixture_pkg/deleted.py"],
        }
        self.refresh()

    def git(self, *args):
        return backend.run(self.root, ["git", *args])

    def write(self, relative, data, mode=None):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        if mode is not None:
            path.chmod(mode)
        return path

    def refresh(self):
        self.manifest["changed_paths"] = sorted(set(product_delta(self.root, self.parent)) | {MANIFEST})
        self.manifest["files"] = file_inventory(self.root, [p for p in candidate_paths(self.root) if p != MANIFEST])
        self.seal()

    def seal(self):
        self.write(MANIFEST, (json.dumps(self.manifest, indent=2) + "\n").encode())
        self.digest = hashlib.sha256((self.root / MANIFEST).read_bytes()).hexdigest()
        # A malformed reviewed manifest still needs a matching external binding
        # to exercise the actual inventory boundary through adopt().
        from rs9.candidate_inventory import source_tree
        self.tree = source_tree(file_inventory(self.root, [r["path"] for r in self.manifest["files"]] + [MANIFEST]))
        self.attestation = self.base / "manager-attestation.json"
        self.attestation.write_text(json.dumps({
            "schema": "rs9.manager-source-adoption-attestation.v1alpha1",
            "decision": "accept", "source_adoption_scope": "partial-diagnostic",
            "reviewed_parent": self.parent, "reviewed_tree": self.tree,
            "manifest_sha256": self.digest, "full_live1_qualification": False,
            "production_enabled": False, "publication_authority": False,
        }))
        self.attestation_digest = hashlib.sha256(self.attestation.read_bytes()).hexdigest()

    def kwargs(self):
        return dict(reviewed_parent=self.parent, reviewed_tree=self.tree,
                    manifest_sha256=self.digest, manager_attestation=self.attestation,
                    manager_attestation_sha256=self.attestation_digest)

    def operational_files(self):
        paths = (
            ".scratch/cont9/validation.json", ".scratch/cont9/logs/λ\n log.txt",
            ".serena/state.json", ".pytest_cache/cache.json",
            "other/__pycache__/module.pyc", "outer/.pytest_cache/cache.json", "src/fixture_pkg/old.pyc",
        )
        for path in paths:
            self.write(path, b"retained-local-fixture\n", 0o600)
        return {p: ((self.root / p).read_bytes(), stat.S_IMODE((self.root / p).stat().st_mode)) for p in paths}

    def boundary(self, original):
        def run(root, argv):
            if Path(root) != self.root or not argv or argv[0] != "git":
                raise AssertionError("Fixture Git boundary escaped")
            self.calls.append(argv)
            if argv[1] in {"fetch", "push"}:
                return ""
            if argv[1] == "add" and self.stop_before_add:
                raise BeforeMutation()
            result = original(root, argv)
            if argv[1] == "ls-files" and "--ignored" in argv:
                self.ignored_listings.append(set(result.split(chr(0))) - {""})
            return result
        return run


class AdoptionScratchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which("git"):
            raise unittest.SkipTest("Git is required for local adoption integration")
        version = subprocess.check_output(["git", "--version"]).decode()
        match = re.search(r"(\d+)\.(\d+)", version)
        if not match or tuple(map(int, match.groups())) < (2, 32):
            raise unittest.SkipTest("Git >= 2.32 required for isolated fixture configuration")

    @contextlib.contextmanager
    def fixture(self, mask=0o022):
        with local_umask(mask), tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            hooks = base / "hooks"
            hooks.mkdir()
            environment = {k: v for k, v in os.environ.items()
                           if k not in GIT_OVERRIDES and not k.startswith(("GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_"))}
            environment.update({
                "HOME": str(base / "home"), "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_COUNT": "2",
                "GIT_CONFIG_KEY_0": "commit.gpgsign", "GIT_CONFIG_VALUE_0": "false",
                "GIT_CONFIG_KEY_1": "core.hooksPath", "GIT_CONFIG_VALUE_1": str(hooks),
                "GIT_AUTHOR_NAME": "Fixture", "GIT_COMMITTER_NAME": "Fixture",
                "GIT_AUTHOR_EMAIL": "fixture@example.invalid", "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
            })
            with patch.dict(os.environ, environment, clear=True):
                yield GitCandidate(base)

    def assert_preserved(self, fixture, snapshot):
        for relative, state in snapshot.items():
            path = fixture.root / relative
            self.assertEqual((path.read_bytes(), stat.S_IMODE(path.stat().st_mode)), state)

    def assert_stop(self, fixture, codes=None):
        before = index_state(fixture.root)
        original = backend.run
        with patch.object(backend, "run", side_effect=fixture.boundary(original)):
            with self.assertRaises(ContractError) as caught:
                backend.adopt(fixture.root, fixture.output, **fixture.kwargs())
        if codes:
            self.assertIn(caught.exception.code, codes)
        self.assertFalse(any(c[1] in {"add", "commit", "push"} for c in fixture.calls))
        self.assertEqual(index_state(fixture.root), before)
        return caught.exception.code

    def test_ignored_root_scratch_reaches_real_pre_mutation_boundary(self):
        for mask in (0o022, 0o077):
            with self.subTest(umask=oct(mask)), self.fixture(mask) as f:
                snapshot = f.operational_files()
                before = index_state(f.root)
                selected = backend.staging_paths(f.root, f.manifest, f.git)
                self.assertEqual(selected, sorted({r["path"] for r in f.manifest["files"]}
                                                 | {MANIFEST} | set(f.manifest["deleted_paths"])))
                self.assertFalse(any(p == ".scratch" or p.startswith(".scratch/") for p in selected))
                original = backend.run
                with patch.object(backend, "run", side_effect=f.boundary(original)), self.assertRaises(BeforeMutation):
                    backend.adopt(f.root, f.output, **f.kwargs())
                self.assertTrue(any(c[1] == "add" for c in f.calls))
                self.assertFalse(any(c[1] in {"commit", "push"} for c in f.calls))
                self.assertTrue(f.ignored_listings)
                self.assertIn(".scratch/", f.ignored_listings[0])
                for listing in f.ignored_listings:
                    self.assertFalse(any(p.startswith(".scratch/cont9/") for p in listing))
                self.assertEqual(index_state(f.root), before)
                self.assert_preserved(f, snapshot)

    def test_scratch_log_leaves_tree_delta_and_index_contents_identical(self):
        for mask in (0o022, 0o077):
            with self.subTest(umask=oct(mask)), self.fixture(mask) as f:
                before = index_state(f.root)
                tree = verify_inventory(f.root, f.manifest, parent=f.parent)
                delta = product_delta(f.root, f.parent)
                f.write(".scratch/cont9/new.log", b"new diagnostic\n", 0o600)
                self.assertEqual(verify_inventory(f.root, f.manifest, parent=f.parent), tree)
                self.assertEqual(product_delta(f.root, f.parent), delta)
                self.assertEqual(index_state(f.root), before)

    def test_live_checkout_verification_preserves_real_index_contents(self):
        manifest = json.loads((SOURCE / MANIFEST).read_bytes())
        parent = manifest["parent"]
        if subprocess.run(["git", "-C", str(SOURCE), "cat-file", "-e", parent + "^{commit}"],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
            self.skipTest("public parent object absent in shallow checkout")
        before = index_state(SOURCE)
        verify_inventory(SOURCE, manifest, parent=parent)
        self.assertEqual(index_state(SOURCE), before)

    def test_unignored_source_and_unrelated_ignored_state_still_stop(self):
        for relative, ignored in (("stray.py", False), (".env", True), ("build/out.bin", True),
                                  (".scratch-old/x", True), (".scratchpad/x", True),
                                  ("outer/.env", True), ("src/x/.scratch/y.py", True)):
            with self.subTest(path=relative), self.fixture() as f:
                f.operational_files()
                if ignored:
                    (f.root / ".git/info/exclude").write_text(relative + "\n")
                f.write(relative, b"unexpected\n")
                self.assert_stop(f, {"ADOPTION_INVENTORY", "CANDIDATE_CHANGED"})

    def test_unignored_root_scratch_file_symlink_and_negated_child_stop(self):
        for kind in ("file", "ignored-file", "symlink", "negated-child", "unignored-directory", "unignored-cache"):
            with self.subTest(kind=kind), self.fixture() as f:
                if kind in {"file", "ignored-file"}:
                    f.write(".scratch", b"unexpected\n")
                    if kind == "ignored-file":
                        (f.root / ".git/info/exclude").write_text("/.scratch\n")
                elif kind == "symlink":
                    (f.root / ".scratch").symlink_to("src/fixture_pkg", target_is_directory=True)
                else:
                    ignore = f.root / ".gitignore"
                    ignore.write_text((".pytest_cache/\n" if kind == "unignored-cache" else "__pycache__/\n*.pyc\n.pytest_cache/\n") +
                                      ("/.scratch/*\n!/.scratch/keep.py\n" if kind == "negated-child" else ""))
                    f.refresh()
                    f.write(".scratch/keep.pyc" if kind == "unignored-cache" else ".scratch/keep.py", b"unexpected\n")
                with self.assertRaises(ContractError) as caught:
                    backend.staging_paths(f.root, f.manifest, f.git)
                self.assertEqual(caught.exception.code, "ADOPTION_INVENTORY")
                self.assert_stop(f)

    def test_source_manifest_attestation_and_index_mismatches_stop(self):
        for kind in ("source", "unchanged-tracked", "manifest", "attestation", "index", "parent", "tree"):
            with self.subTest(kind=kind), self.fixture() as f:
                if kind in {"source", "unchanged-tracked"}:
                    f.write("src/fixture_pkg/" + ("a.py" if kind == "source" else "unchanged.py"), b"drift\n")
                elif kind == "manifest":
                    f.write(MANIFEST, (f.root / MANIFEST).read_bytes() + b" ")
                elif kind == "attestation":
                    doc = json.loads(f.attestation.read_bytes())
                    doc["reviewed_tree"] = "0" * 40
                    f.attestation.write_text(json.dumps(doc))
                    f.attestation_digest = hashlib.sha256(f.attestation.read_bytes()).hexdigest()
                elif kind == "index":
                    f.git("add", "src/fixture_pkg/new.py")
                elif kind == "parent":
                    f.manifest["parent"] = "0" * 40
                    f.seal()
                else:
                    f.tree = "0" * 40
                    doc = json.loads(f.attestation.read_bytes())
                    doc["reviewed_tree"] = f.tree
                    f.attestation.write_text(json.dumps(doc))
                    f.attestation_digest = hashlib.sha256(f.attestation.read_bytes()).hexdigest()
                self.assert_stop(f)

    def test_tracked_root_scratch_cannot_be_hidden_even_if_reviewed(self):
        for deleted in (False, True):
            with self.subTest(deleted=deleted), self.fixture() as f:
                f.write(".scratch/tracked.py", b"parent\n")
                f.git("add", "-f", ".scratch/tracked.py")
                f.git("commit", "-m", "Local fixture with tracked scratch")
                f.parent = f.git("rev-parse", "HEAD")
                f.manifest["parent"] = f.parent
                f.git("update-ref", "refs/remotes/origin/main", f.parent)
                if deleted:
                    (f.root / ".scratch/tracked.py").unlink()
                    f.manifest["deleted_paths"].append(".scratch/tracked.py")
                else:
                    f.write(".scratch/tracked.py", b"changed\n")
                    self.assertIn(".scratch/tracked.py", candidate_paths(f.root))
                self.assertIn(".scratch/tracked.py", product_delta(f.root, f.parent))
                f.refresh()
                with self.assertRaises(ContractError) as caught:
                    backend.staging_paths(f.root, f.manifest, f.git)
                self.assertEqual(caught.exception.code, "ADOPTION_SCRATCH")
                self.assert_stop(f, {"ADOPTION_SCRATCH"})

    def test_root_scratch_reviewed_input_is_rejected(self):
        for field in ("files", "changed_paths", "deleted_paths"):
            with self.subTest(field=field), self.fixture() as f:
                f.write(".scratch/cont9/validation.json", b"{}\n")
                if field == "files":
                    f.manifest[field] = file_inventory(f.root, [r["path"] for r in f.manifest[field]]
                                                     + [".scratch/cont9/validation.json"])
                else:
                    f.manifest[field].append(".scratch/cont9/validation.json")
                f.seal()
                with self.assertRaises(ContractError) as caught:
                    backend.staging_paths(f.root, f.manifest, f.git)
                self.assertEqual(caught.exception.code, "ADOPTION_SCRATCH")
                self.assert_stop(f, {"ADOPTION_SCRATCH", "CANDIDATE_CHANGED"})

    def test_nested_scratch_is_product_source_and_legacy_caches_are_preserved(self):
        with self.fixture() as f:
            snapshot = f.operational_files()
            nested = "src/fixture_pkg/.scratch/nested.py"
            self.assertIn(nested, product_delta(f.root, f.parent))
            self.assertIn(nested, candidate_paths(f.root))
            self.assertIn(nested, backend.staging_paths(f.root, f.manifest, f.git))
            self.assertEqual(verify_inventory(f.root, f.manifest, parent=f.parent), f.tree)
            self.assert_preserved(f, snapshot)

    def test_new_directory_with_only_ignored_python_cache_is_preserved(self):
        for mask in (0o022, 0o077):
            for directory, ignore in (("new-cache-only", "/new-cache-only/"), ("cache[1]", "/cache\\[1\\]/")):
                with self.subTest(umask=oct(mask), directory=directory), self.fixture(mask) as f:
                    snapshot = f.operational_files()
                    (f.root / ".git/info/exclude").write_text(ignore + "\n")
                    relative = directory + "/module.pyc"
                    path = f.write(relative, b"local-cache\n", 0o600)
                    snapshot[relative] = (path.read_bytes(), 0o600)
                    before = index_state(f.root)
                    self.assertNotIn(relative, backend.staging_paths(f.root, f.manifest, f.git))
                    self.assertEqual(index_state(f.root), before)
                    self.assert_preserved(f, snapshot)
                    f.write(directory + "/.env", b"unrelated-state\n")
                    self.assert_stop(f, {"ADOPTION_INVENTORY"})

    def test_run_hosted8_to_shared_adoption_with_existing_empty_packet(self):
        for mask in (0o022, 0o077):
            with self.subTest(umask=oct(mask)), self.fixture(mask) as f:
                snapshot = f.operational_files()
                self.assertEqual(list(f.output.iterdir()), [])
                self.assertFalse(f.attestation.is_relative_to(f.output))
                spec = importlib.util.spec_from_file_location("rs9_scratch_run8", SOURCE / "operators/live1/run-hosted8.py")
                operator = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(operator)
                f.stop_before_add = False
                original = backend.run
                child_calls = []

                def child(command, **kwargs):
                    child_calls.append(command)
                    self.assertEqual(command[:3], [sys.executable, str(f.root / "operators/live1/adopt-and-qualify.py"), "adopt"])
                    self.assertEqual(kwargs["cwd"], f.root)
                    self.assertEqual(kwargs["env"]["PYTHONDONTWRITEBYTECODE"], "1")
                    self.assertIs(kwargs["stdout"], kwargs["stderr"])
                    stream = io.TextIOWrapper(kwargs["stdout"], encoding="utf-8", write_through=True)
                    try:
                        with contextlib.redirect_stdout(stream), contextlib.redirect_stderr(stream):
                            code = backend.main(command[2:])
                    finally:
                        stream.flush()
                        stream.detach()
                    return subprocess.CompletedProcess(command, code)

                packet = {"status": "not-qualified", "run_id": 999, "production_enabled": False,
                          "publication_authority": False, "validation": {"status": "fail"}}
                stdout = io.StringIO()
                with patch.object(operator, "ROOT", f.root), \
                        patch.object(operator, "subprocess", SimpleNamespace(run=child)), \
                        patch.object(sys, "path", sys.path.copy()), \
                        patch.object(backend, "run", side_effect=f.boundary(original)), \
                        patch("rs9.collect_candidate.collect", return_value=packet) as collect, \
                        contextlib.redirect_stdout(stdout):
                    rc = operator.main(["--reviewed-parent", f.parent, "--reviewed-tree", f.tree,
                                        "--manifest-sha256", f.digest, "--output", str(f.output),
                                        "--manager-attestation", str(f.attestation),
                                        "--manager-attestation-sha256", f.attestation_digest])
                self.assertEqual(rc, 2)  # Simulated hosted diagnostics fail, after adoption.
                self.assertEqual(len(child_calls), 1)
                self.assertEqual(f.git("rev-parse", "HEAD^{tree}"), f.tree)
                self.assertEqual(f.git("rev-parse", "HEAD^"), f.parent)
                self.assertEqual([c[1] for c in f.calls].count("push"), 1)
                self.assertEqual([c[1] for c in f.calls].count("commit"), 1)
                collect.assert_called_once()
                self.assertEqual(collect.call_args.kwargs["commit"], f.git("rev-parse", "HEAD"))
                self.assertIsNotNone(collect.call_args.kwargs["started_at"].tzinfo)
                self.assertFalse(any("rerun" in c for c in f.calls))
                selected = set(f.git("ls-tree", "-r", "--name-only", "HEAD").splitlines())
                self.assertIn("src/fixture_pkg/.scratch/nested.py", selected)
                self.assertFalse(any(p.startswith(".scratch/") for p in selected))
                self.assertEqual(f.git("diff", "--cached", "--name-only"), "")
                self.assert_preserved(f, snapshot)
                result = json.loads((f.output / "manager-packet.json").read_bytes())
                self.assertEqual(result["reviewed_tree"], f.tree)
                self.assertEqual(result["manager_attestation_sha256"], f.attestation_digest)
                self.assertIs(f.manifest["candidate_adoption_ready"], False)
                fields = dict(line.split("=", 1) for line in stdout.getvalue().splitlines())
                self.assertEqual(list(fields), ["LOG", "RC", "MANAGER_PACKET", "UPLOAD"])
                self.assertEqual(fields["RC"], "2")
                log = Path(fields["LOG"])
                self.assertEqual(log.parent, f.output.parent)
                self.assertIn('"status": "not-qualified"', log.read_text())
                with zipfile.ZipFile(fields["UPLOAD"]) as archive:
                    self.assertEqual(set(archive.namelist()), {"manager-packet.json", "result-selection.json"})


if __name__ == "__main__":
    unittest.main()
