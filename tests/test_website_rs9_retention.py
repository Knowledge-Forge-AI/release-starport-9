import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch


ASSEMBLER = Path(__file__).resolve().parents[1] / "website/tools/assemble-pages.py"
SPEC = importlib.util.spec_from_file_location("website_assembler", ASSEMBLER)
assert SPEC is not None and SPEC.loader is not None
pages = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pages)


class Rs9RetentionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.site = self.root / "website"
        self.site.mkdir()
        for name in pages.WEBSITE_FILES:
            (self.site / name).write_bytes(b"site fixture\n")
        (self.site / "CNAME").write_bytes(b"rs9.knowledge-forge.ai\n")
        self.outputs = self.root / "output"
        self.archive = self.root / "pages.tar"
        self.files = {
            "packages/rs9/apt/dists/stable/InRelease": b"apt fixture\n",
            "packages/rs9/rpm/repodata/repomd.xml.asc": b"rpm fixture\n",
            "packages/rs9/pacman/x86_64/rs9.db.sig": b"x86_64 db fixture\n",
            "packages/rs9/pacman/aarch64/rs9.db.sig": b"aarch64 db fixture\n",
            "packages/rs9/keys/rs9.asc": b"key fixture\n",
        }
        self.inventory = self.site / pages.RS9_INVENTORY_FILE
        self.metadata = {
            "schema": "knowledge-forge.rs9-pages-inventory.v1",
            "files": {name: {"bytes": len(body), "sha256": pages.sha256(body)} for name, body in self.files.items()},
        }
        self.write_inventory()
        self.previous = {"previousDeployment": 42, "sourceCommit": "7" * 40}
        self.workflow_identity = {
            "GITHUB_REPOSITORY": "Knowledge-Forge-AI/release-starport-9",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_SHA": "9" * 40,
        }
        self.live_receipt = {
            "schema": "knowledge-forge.website-preservation.v1",
            "repository": "Knowledge-Forge-AI/release-starport-9",
            "websiteSourceCommit": self.previous["sourceCommit"],
            "protectedInventorySha256": pages.sha256(self.inventory.read_bytes()),
            "protectedFileCount": len(self.files),
            "protectedPublicBytes": sum(map(len, self.files.values())),
        }

    def write_inventory(self):
        self.inventory.write_text(json.dumps(self.metadata), encoding="utf-8")

    def run_assembler(self, fetch, *, initial_rs9_tree=None):
        def read_public(url, limit):
            if url == "https://rs9.knowledge-forge.ai/site-preservation.json":
                return json.dumps(self.live_receipt).encode()
            return fetch(url, limit)

        with patch.dict(os.environ, self.workflow_identity), \
                patch.object(pages, "admit_previous_deployment", return_value=self.previous), \
                patch.object(pages, "fetch", side_effect=read_public):
            return pages.assemble("release-starport-9", self.site, self.outputs, self.archive,
                                  initial_rs9_tree=initial_rs9_tree)

    def fetch(self, url, limit):
        self.assertTrue(url.startswith("https://rs9.knowledge-forge.ai/"))
        body = self.files[url.removeprefix("https://rs9.knowledge-forge.ai/")]
        self.assertEqual(limit, len(body))
        return body

    def test_site_only_build_retains_exact_repository_members(self):
        receipt = self.run_assembler(self.fetch)
        self.assertEqual(receipt["websiteSourceCommit"], self.workflow_identity["GITHUB_SHA"])
        self.assertEqual(receipt["protectedFileCount"], len(self.files))
        self.assertEqual(receipt["protectedInventorySha256"], pages.sha256(self.inventory.read_bytes()))
        self.assertEqual(receipt["protectedPublicBytes"], sum(map(len, self.files.values())))
        self.assertEqual(receipt["previousHosting"], self.previous)
        with tarfile.open(self.archive, "r:") as archive:
            members = archive.getmembers()
            self.assertEqual(members[0].name, ".")
            self.assertTrue(members[0].isdir())
            directories = {"."}
            for member in members[1:]:
                self.assertTrue(member.name.startswith("./"))
                self.assertIn(member.name.rsplit("/", 1)[0], directories)
                self.assertIn(member.mode, (0o644, 0o755))
                if member.isdir():
                    directories.add(member.name)
            self.assertEqual({member.name.removeprefix("./") for member in members if member.isfile()},
                             {*self.files, *pages.WEBSITE_FILES, "site-preservation.json"})
            for name, body in self.files.items():
                self.assertEqual(archive.extractfile("./" + name).read(), body)

    def test_non_main_workflow_ref_cannot_assemble_the_site(self):
        identity = self.workflow_identity | {"GITHUB_REF": "refs/heads/candidate"}
        with patch.dict(os.environ, identity), \
                patch.object(pages, "admit_previous_deployment") as admit, \
                patch.object(pages, "fetch") as fetch:
            with self.assertRaisesRegex(pages.Refused, "WORKFLOW_REPOSITORY"):
                pages.assemble("release-starport-9", self.site, self.outputs, self.archive)
        admit.assert_not_called()
        fetch.assert_not_called()
        self.assertFalse(self.outputs.exists())
        self.assertFalse(self.archive.exists())

    def test_missing_inventory_cannot_produce_a_website_only_archive(self):
        self.inventory.unlink()
        with self.assertRaises(FileNotFoundError):
            self.run_assembler(self.fetch)
        self.assertFalse(self.outputs.exists())
        self.assertFalse(self.archive.exists())

    def test_changed_or_missing_public_members_refuse_the_archive(self):
        with self.assertRaisesRegex(pages.Refused, "PUBLIC_MEMBER_CHANGED"):
            self.run_assembler(lambda _url, limit: b"!" * limit)
        self.assertFalse(self.archive.exists())
        self.outputs = self.root / "refused-output"
        with self.assertRaises(FileNotFoundError):
            self.run_assembler(lambda _url, _limit: self.inventory.with_suffix(".absent").read_bytes())
        self.assertFalse(self.archive.exists())

    def test_outside_scope_collisions_and_missing_channel_are_refused(self):
        original = self.metadata["files"].copy()
        record = next(iter(original.values()))
        for name, error in (
            ("apt/dists/stable/InRelease", "RS9_INVENTORY_ROOT"),
            ("packages/rs9/apt/../keys/key", "MEMBER_PATH"),
            ("packages/rs9/apt/dists/stable/inrelease", "RS9_INVENTORY_CASE_COLLISION"),
            ("packages/rs9/apt/dists/stable", "RS9_INVENTORY_PATH_COLLISION"),
        ):
            with self.subTest(name=name):
                self.metadata["files"] = dict(original, **{name: record})
                self.write_inventory()
                with self.assertRaisesRegex(pages.Refused, error):
                    self.run_assembler(self.fetch)
        self.metadata["files"] = {name: value for name, value in original.items() if "/keys/" not in name}
        self.write_inventory()
        with self.assertRaisesRegex(pages.Refused, "RS9_INVENTORY_CHANNELS"):
            self.run_assembler(self.fetch)

    def test_duplicate_inventory_key_refuses(self):
        self.inventory.write_text('{"schema":"ignored",' + json.dumps(self.metadata)[1:], encoding="utf-8")
        with self.assertRaisesRegex(pages.Refused, "RS9_INVENTORY_DUPLICATE"):
            self.run_assembler(self.fetch)

    def test_locally_deleted_package_cannot_shrink_live_inventory(self):
        self.metadata["files"].pop("packages/rs9/pacman/aarch64/rs9.db.sig")
        self.write_inventory()
        with self.assertRaisesRegex(pages.Refused, "RS9_LIVE_INVENTORY_MISMATCH"):
            self.run_assembler(self.fetch)
        self.assertFalse(self.outputs.exists())

    def test_stale_live_receipt_cannot_authorize_output(self):
        self.live_receipt["websiteSourceCommit"] = "8" * 40
        with self.assertRaisesRegex(pages.Refused, "RS9_LIVE_RECEIPT_IDENTITY"):
            self.run_assembler(self.fetch)
        self.assertFalse(self.outputs.exists())

    def stage_initial_tree(self):
        self.live_receipt.update(protectedInventorySha256=None, protectedFileCount=0, protectedPublicBytes=0)
        tree = self.root / "staged"
        tree.mkdir()
        for name, content in self.files.items():
            pages.write_new(tree, name, content)
        return tree

    def test_initial_artifact_bootstraps_the_exact_inventory_for_website_updates(self):
        staged = self.stage_initial_tree()
        receipt = self.run_assembler(self.fetch, initial_rs9_tree=staged)
        first_bytes = self.archive.read_bytes()
        self.assertTrue(receipt["packageBodiesChanged"])
        self.live_receipt = receipt | {"websiteSourceCommit": self.previous["sourceCommit"]}
        self.outputs, self.archive = self.root / "next-output", self.root / "next.tar"
        successor = self.run_assembler(self.fetch)
        self.assertFalse(successor["packageBodiesChanged"])
        self.assertEqual(receipt["protectedInventorySha256"], successor["protectedInventorySha256"])
        with tarfile.open(self.archive, "r:") as current:
            with tarfile.open(fileobj=io.BytesIO(first_bytes), mode="r:") as original:
                for name in self.files:
                    self.assertEqual(current.extractfile("./" + name).read(), original.extractfile("./" + name).read())

    def test_initial_cannot_replace_a_published_inventory(self):
        staged = self.stage_initial_tree()
        self.live_receipt["protectedFileCount"] = 1
        with self.assertRaisesRegex(pages.Refused, "RS9_LIVE_INVENTORY_MISMATCH"):
            self.run_assembler(self.fetch, initial_rs9_tree=staged)
        self.assertFalse(self.archive.exists())

    def test_initial_rejects_unlisted_link_and_changed_bytes(self):
        staged = self.stage_initial_tree()
        extra = staged / "unlisted"
        extra.write_bytes(b"unlisted")
        with self.assertRaisesRegex(pages.Refused, "RS9_INITIAL_INVENTORY_MISMATCH"):
            self.run_assembler(self.fetch, initial_rs9_tree=staged)
        extra.unlink()
        first_name, body = next(iter(self.files.items()))
        first = staged / first_name
        first.unlink()
        first.symlink_to(self.inventory)
        with self.assertRaisesRegex(pages.Refused, "RS9_INITIAL_LINK"):
            self.run_assembler(self.fetch, initial_rs9_tree=staged)
        first.unlink()
        first.write_bytes(b"!" * len(body))
        with self.assertRaisesRegex(pages.Refused, "RS9_INITIAL_MEMBER_CHANGED"):
            self.run_assembler(self.fetch, initial_rs9_tree=staged)
        self.assertFalse(self.archive.exists())


    def test_initial_recovery_requires_exact_failed_run_and_last_live_site(self):
        repo = "release-starport-9"
        prefix = f"https://github.com/Knowledge-Forge-AI/{repo}/actions/runs/"
        failed = {"id": 7946354757, "sha": "4edd8de4e20e2bd539897b5bf6a26c1ae17c4c2a", "ref": "main"}
        live = {"id": 7713538844, "sha": "0f717d1ff8d2ce9b3db675b76ac268335af91b52", "ref": "main"}
        history = [failed, live]
        routes = {
            "deployments?environment=github-pages&per_page=1": [failed],
            "deployments?environment=github-pages&per_page=2": history,
        }
        evidence = ((failed, 44768889552, 136404470822, "failure", "rs9-cli-linux-publish-v010.yml"),
                    (live, 43044444717, 130604674307, "success", "project-pages.yml"))
        for row, run, job, result, workflow in evidence:
            routes[f"deployments/{row['id']}/statuses"] = [
                {"state": result, "log_url": f"{prefix}{run}/job/{job}"}
            ]
            routes[f"actions/runs/{run}"] = {
                "id": run, "path": ".github/workflows/" + workflow, "head_sha": row["sha"],
                "head_branch": "main", "run_attempt": 1, "status": "completed", "conclusion": result,
            }
        with patch.object(pages, "api", side_effect=lambda _repo, route: routes[route]):
            with self.assertRaisesRegex(pages.Refused, "PREVIOUS_DEPLOYMENT_NOT_SUCCESSFUL"):
                pages.admit_previous_deployment(repo)
            self.assertEqual(pages.admit_previous_deployment(repo, recover_rs9=True)["sourceCommit"], live["sha"])
            routes["actions/runs/44768889552"]["run_attempt"] = 2
            with self.assertRaisesRegex(pages.Refused, "RS9_INITIAL_RECOVERY_RUN"):
                pages.admit_previous_deployment(repo, recover_rs9=True)
            routes["actions/runs/44768889552"]["run_attempt"] = 1
            history.reverse()
            with self.assertRaisesRegex(pages.Refused, "RS9_INITIAL_RECOVERY_HISTORY"):
                pages.admit_previous_deployment(repo, recover_rs9=True)
