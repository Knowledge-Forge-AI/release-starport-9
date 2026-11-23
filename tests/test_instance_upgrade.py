"""Local registration upgrade and interruption coverage."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from rs9 import instance as instance_module
from rs9.errors import ContractError
from rs9.instance import (
    TRANSACTION_FILE,
    apply_consumer_upgrade,
    init_instance,
    plan_instance,
    register_consumer,
)

ROOT = Path(__file__).resolve().parents[1]
TF_PROJECT = ROOT / "examples" / "theme-forge" / "theme-forge-nebular-fusion"
DESTINATIONS = ROOT / "examples" / "destinations.example.toml"


class InstanceUpgradeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="rs9-instance-")
        self.addCleanup(self.temp.cleanup)
        self.publisher = Path(self.temp.name) / "publisher"
        self.publisher.mkdir()

    def init(self) -> dict:
        return dict(init_instance(
            self.publisher,
            instance_id="example-publisher",
            publisher_repository="Example/rs9-publisher",
            publisher_branch="main",
            engine_version="unreleased",
        ))

    def register_tf(self, *, consumer_id: str = "nebular", project: Path = TF_PROJECT,
                    destinations: Path = DESTINATIONS, version_provider=None) -> dict:
        return dict(register_consumer(
            self.publisher,
            consumer_id=consumer_id,
            project=project,
            destinations=destinations,
            destination_id="kfa-homebrew-tap",
            package_id="main",
            version_provider=version_provider,
        ))

    def test_upgrade_recovers_between_registration_and_state_replacement(self) -> None:
        self.init()
        project = Path(self.temp.name) / "proposed-consumer"
        shutil.copytree(TF_PROJECT, project)
        self.register_tf(project=project)
        self.register_tf(consumer_id="unrelated")
        neighbor = self.publisher / ".rs9-instance/consumers/unrelated.toml"
        unchanged_neighbor = neighbor.read_bytes()
        homebrew = project / ".rs9/homebrew.toml"
        homebrew.write_bytes(homebrew.read_bytes() + b"\n# reviewed upgrade\n")
        args = dict(consumer_id="nebular", project=project, destinations=DESTINATIONS, version="0.6.1")
        reviewed = plan_instance(self.publisher, **args, review_upgrade=True)

        def apply(reviewed_plan=reviewed, *, dry_run=False):
            return apply_consumer_upgrade(
                self.publisher, **args, reviewed_plan=reviewed_plan, runtime_version="unreleased",
                dry_run=dry_run,
            )

        reject = dict(reviewed, normalizedIntentSha256="0" * 64)
        with self.assertRaisesRegex(ContractError, "UPGRADE_PLAN_CHANGED"):
            apply(reject)
        self.assertFalse((self.publisher / TRANSACTION_FILE).exists())

        replace = instance_module._atomic_replace_control
        foreign_staging = self.publisher / ".rs9-instance-upgrade-unrelated"
        foreign_staging.write_bytes(b"operator-owned staging-looking file")
        foreign_inode = foreign_staging.stat().st_ino

        def fail_second(root, stage, path, digest):
            if path == instance_module.STATE_FILE:
                raise RuntimeError("simulated interruption")
            return replace(root, stage, path, digest)

        with mock.patch.object(instance_module, "_atomic_replace_control", side_effect=fail_second):
            with self.assertRaisesRegex(RuntimeError, "simulated interruption"):
                apply()
        self.assertEqual(list(self.publisher.glob(".rs9-instance-upgrade-*")), [foreign_staging])
        self.assertFalse(list(self.publisher.glob(".rs9-instance-stage-*")))
        marker = self.publisher / TRANSACTION_FILE
        self.assertEqual(json.loads(marker.read_bytes())["operation"], "upgrade")
        self.assertEqual(plan_instance(self.publisher, **args)["local"]["state"], "drift")
        changed_paths = [self.publisher / row["path"] for row in reviewed["changes"]]
        observed = (*changed_paths, marker, neighbor)
        preflight_before = [(path.read_bytes(), path.stat().st_ino) for path in observed]
        self.assertEqual(apply(dry_run=True)["outcome"], "resume")
        self.assertEqual([(path.read_bytes(), path.stat().st_ino) for path in observed], preflight_before)

        neighbor.write_bytes(unchanged_neighbor + b"\n# competing edit\n")
        with self.assertRaisesRegex(ContractError, "UPGRADE_PLAN_CHANGED"):
            apply(dry_run=True)
        with self.assertRaisesRegex(ContractError, "UPGRADE_PLAN_CHANGED"):
            apply()
        self.assertTrue(marker.exists())
        self.assertNotEqual(neighbor.read_bytes(), unchanged_neighbor)
        neighbor.write_bytes(unchanged_neighbor)
        with mock.patch.object(instance_module, "_unlink_marker", side_effect=RuntimeError("before cleanup")):
            with self.assertRaisesRegex(RuntimeError, "before cleanup"):
                apply()
        self.assertTrue(marker.is_file())
        completed_inodes = [path.stat().st_ino for path in changed_paths]
        self.assertEqual(apply(dry_run=True)["outcome"], "resume")
        self.assertTrue(marker.exists())
        self.assertEqual(apply()["outcome"], "applied")
        self.assertEqual([path.stat().st_ino for path in changed_paths], completed_inodes)
        self.assertEqual(apply()["outcome"], "noop")
        self.assertEqual(apply(dry_run=True)["outcome"], "noop")
        self.assertFalse(marker.exists())
        self.assertEqual(neighbor.read_bytes(), unchanged_neighbor)
        self.assertEqual(foreign_staging.read_bytes(), b"operator-owned staging-looking file")
        self.assertEqual(foreign_staging.stat().st_ino, foreign_inode)
        self.assertEqual(plan_instance(self.publisher, **args)["local"]["state"], "noop")
        self.assertEqual(apply(plan_instance(self.publisher, **args, review_upgrade=True))["changes"], [])
        fresh = plan_instance(self.publisher, **args, review_upgrade=True)
        self.assertTrue(apply(fresh, dry_run=True)["dryRun"])

    def test_upgrade_uses_one_inspected_publisher_directory(self) -> None:
        self.init()
        project = Path(self.temp.name) / "proposed-consumer"
        shutil.copytree(TF_PROJECT, project)
        self.register_tf(project=project)
        homebrew = project / ".rs9/homebrew.toml"
        homebrew.write_bytes(homebrew.read_bytes() + b"\n# reviewed upgrade\n")
        args = dict(consumer_id="nebular", project=project, destinations=DESTINATIONS, version="0.6.1")
        reviewed = plan_instance(self.publisher, **args, review_upgrade=True)

        with mock.patch.object(instance_module, "_open_root", wraps=instance_module._open_root) as opened:
            result = apply_consumer_upgrade(
                self.publisher, **args, reviewed_plan=reviewed, runtime_version="unreleased",
            )
        self.assertEqual(result["outcome"], "applied")
        opened.assert_called_once()
        self.assertEqual(plan_instance(self.publisher, **args)["local"]["state"], "noop")

    def test_upgrade_cleanup_preserves_a_replaced_staging_name(self) -> None:
        self.init()
        project = Path(self.temp.name) / "proposed-consumer"
        shutil.copytree(TF_PROJECT, project)
        self.register_tf(project=project)
        homebrew = project / ".rs9/homebrew.toml"
        homebrew.write_bytes(homebrew.read_bytes() + b"\n# reviewed upgrade\n")
        args = dict(consumer_id="nebular", project=project, destinations=DESTINATIONS, version="0.6.1")
        reviewed = plan_instance(self.publisher, **args, review_upgrade=True)

        def replace_stage(root_fd, stage, path, digest):
            self.assertEqual(Path(stage).name, stage)
            old_inode = os.stat(stage, dir_fd=root_fd, follow_symlinks=False).st_ino
            os.unlink(stage, dir_fd=root_fd)
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
            with os.fdopen(os.open(stage, flags, 0o644, dir_fd=root_fd), "wb") as writer:
                self.assertNotEqual(os.fstat(writer.fileno()).st_ino, old_inode)
                writer.write(b"replacement from another writer")
            return "drift"

        with mock.patch.object(instance_module, "_atomic_replace_control", side_effect=replace_stage):
            with self.assertRaisesRegex(ContractError, "UPGRADE_PUBLISHER_STATE"):
                apply_consumer_upgrade(self.publisher, **args, reviewed_plan=reviewed, runtime_version="unreleased")
        (stage,) = self.publisher.glob(".rs9-instance-upgrade-*")
        self.assertEqual(stage.read_bytes(), b"replacement from another writer")
        self.assertTrue((self.publisher / TRANSACTION_FILE).is_file())
        result = apply_consumer_upgrade(
            self.publisher, **args, reviewed_plan=reviewed, runtime_version="unreleased",
        )
        self.assertEqual(result["outcome"], "applied")
        self.assertEqual(stage.read_bytes(), b"replacement from another writer")
