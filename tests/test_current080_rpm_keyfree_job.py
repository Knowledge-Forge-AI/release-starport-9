"""Pure dispatch-boundary tests for the executable OS080 proposal driver."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

from rs9.build_native import CommandReceipt


HERE = Path(__file__).resolve()
ROOT = HERE.parents[1]
SOURCE_ROOT = ROOT
BASE_SOURCE = SOURCE_ROOT / "src"
BASE_WORKFLOW = Path(
    os.environ.get(
        "RS9_BASE_WORKFLOW",
        str(SOURCE_ROOT / ".github" / "workflows" / "rs9-current-distribution-tests.yml"),
    )
)
if str(BASE_SOURCE) not in sys.path:
    sys.path.insert(0, str(BASE_SOURCE))


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


adapter = _load(
    "rs9.current080_rpm_keyfree",
    SOURCE_ROOT / "src" / "rs9" / "current080_rpm_keyfree.py",
)
job = _load(
    "current080_rpm_keyfree_job_candidate",
    SOURCE_ROOT / "src" / "rs9" / "current080_rpm_keyfree_job.py",
)
VALID_COMMIT = "1" * 40
VALID_TREE = "2" * 40
HELD_POLICY_FIXTURE = ROOT / "tests" / "fixtures" / "current080-rpm-policy-held.json"


def _fixture_requests() -> list[dict]:
    fixture_root = ROOT / "fixtures" if (ROOT / "fixtures").is_dir() else ROOT / "tests" / "fixtures"
    with (fixture_root / "current080-rpm-keyfree-request.json").open(encoding="utf-8") as stream:
        return json.load(stream)


def _held_policy(request: dict) -> tuple[dict, dict]:
    """Keep the key-free driver test on the exact pre-candidate policy bytes."""
    with tempfile.TemporaryDirectory(prefix="nebular080-held-policy-") as directory:
        repository = Path(directory)
        path = repository / adapter.POLICY_PATH
        path.parent.mkdir(parents=True)
        path.write_bytes(HELD_POLICY_FIXTURE.read_bytes())
        return job._load_policy(repository, request)


def _capture(request: dict) -> tuple[types.SimpleNamespace, dict]:
    asset = request["raw_asset"]
    record = {
        "release": {"id": request["source"]["release_id"], "tag": request["source"]["tag"]},
        "tag": {"commit": request["source"]["commit"], "tree": request["source"]["tree"]},
        "payloads": [
            {
                "id": "package",
                "github_asset_id": asset["github_asset_id"],
                "payload_manifest_sha256": asset["release_payload_manifest_sha256"],
                "member_count": asset["release_payload_member_count"],
            }
        ],
    }
    capture = types.SimpleNamespace(
        record=record,
        asset_metadata={
            asset["name"]: {
                "github_asset_id": asset["github_asset_id"],
                "size": asset["bytes"],
                "sha256": asset["sha256"],
            }
        },
        archives={"package": object()},
    )
    intent = {"project": {"id": request["project"]}}
    return capture, intent


class Current080KeyfreeJobTests(unittest.TestCase):
    def test_cli_dispatch_binds_exact_checkout_and_generation(self) -> None:
        args = job.parse_args(
            [
                "--repository",
                ".",
                "--scratch",
                "scratch",
                "--receipts",
                "receipts",
                "--system",
                "x86_64-linux",
                "--source-commit",
                VALID_COMMIT,
                "--source-tree",
                VALID_TREE,
                "--generation",
                job.GENERATION,
            ]
        )
        with patch.dict(os.environ, {}, clear=True):
            job._validate_checkout(args)
            args.source_commit = VALID_COMMIT[:-1]
            with self.assertRaisesRegex(Exception, "KEYFREE_SOURCE"):
                job._validate_checkout(args)
            args.source_commit = VALID_COMMIT
            args.source_tree = "0" * 40
            with self.assertRaisesRegex(Exception, "KEYFREE_SOURCE"):
                job._validate_checkout(args)
            args.source_tree = VALID_TREE
            args.source_commit = "0" * 40
            with self.assertRaisesRegex(Exception, "KEYFREE_SOURCE"):
                job._validate_checkout(args)

    def test_cli_context_rejects_mismatched_github_source_attempt_and_repository(self) -> None:
        args = types.SimpleNamespace(
            generation=job.GENERATION,
            source_commit=VALID_COMMIT,
            source_tree=VALID_TREE,
            repository=".",
        )
        with patch.dict(
            os.environ,
            {
                "GITHUB_ACTIONS": "true",
                "GITHUB_SHA": "3" * 40,
                "GITHUB_REPOSITORY": job.EXPECTED_REPOSITORY,
                "GITHUB_RUN_ATTEMPT": "1",
            },
            clear=False,
        ):
            with self.assertRaisesRegex(Exception, "KEYFREE_SOURCE"):
                job._validate_checkout(args)
        with patch.dict(
            os.environ,
            {
                "GITHUB_ACTIONS": "true",
                "GITHUB_SHA": VALID_COMMIT,
                "GITHUB_REPOSITORY": "other/repository",
                "GITHUB_RUN_ATTEMPT": "1",
            },
            clear=False,
        ):
            with self.assertRaisesRegex(Exception, "KEYFREE_SOURCE"):
                job._validate_checkout(args)
        with patch.dict(
            os.environ,
            {
                "GITHUB_ACTIONS": "true",
                "GITHUB_SHA": VALID_COMMIT,
                "GITHUB_REPOSITORY": job.EXPECTED_REPOSITORY,
                "GITHUB_RUN_ATTEMPT": "2",
            },
            clear=False,
        ):
            with self.assertRaisesRegex(Exception, "KEYFREE_SOURCE"):
                job._validate_checkout(args)

    def test_actual_checkout_tree_is_verified_before_native_work(self) -> None:
        calls = []
        def run(argv, **kwargs):
            calls.append(argv)
            expected = VALID_COMMIT if argv[-1] == "HEAD" else VALID_TREE
            self.assertEqual(kwargs["timeout"], 10)
            self.assertEqual(kwargs["stderr"], job.subprocess.DEVNULL)
            return types.SimpleNamespace(returncode=0, stdout=(expected + "\n").encode("ascii"))
        job._verify_checkout_identity(Path("/public-checkout"), VALID_COMMIT, VALID_TREE, run=run)
        self.assertEqual([argv[-1] for argv in calls], ["HEAD", "HEAD^{tree}"])
        self.assertTrue(all(argv[1] == "--no-optional-locks" for argv in calls))
        def wrong_tree(argv, **kwargs):
            value = VALID_COMMIT if argv[-1] == "HEAD" else "3" * 40
            return types.SimpleNamespace(returncode=0, stdout=(value + "\n").encode("ascii"))
        with self.assertRaisesRegex(Exception, "KEYFREE_SOURCE"):
            job._verify_checkout_identity(Path("/public-checkout"), VALID_COMMIT, VALID_TREE, run=wrong_tree)
        def refused(*args, **kwargs):
            raise OSError("not retained")
        with self.assertRaisesRegex(Exception, "KEYFREE_SOURCE"):
            job._verify_checkout_identity(Path("/public-checkout"), VALID_COMMIT, VALID_TREE, run=refused)

    def test_request_factory_matches_both_closed_fixture_lanes(self) -> None:
        fixture = {row["system"]: row for row in _fixture_requests()}
        for system in ("x86_64-linux", "aarch64-linux"):
            self.assertEqual(job.request_for_system(system), fixture[system])

    def test_held_policy_fixture_binding_is_unpatched_and_blocked_for_both_systems(self) -> None:
        for system in ("x86_64-linux", "aarch64-linux"):
            request = job.request_for_system(system)
            raw_policy, summary = _held_policy(request)
            self.assertEqual(summary["sha256"], "6e0f66ab486b09992343ff32ff812b3eb51958daf5c1bd68b27cfa17e5781649")
            self.assertEqual(raw_policy["status"], "blocked")
            self.assertFalse(raw_policy["production_enabled"])

    def test_real_builder_inventory_retention_marker_is_present_unpatched(self) -> None:
        job._require_inventory_retention(SOURCE_ROOT)

    def test_real_dnf_provisioner_binds_pinned_image_and_platform(self) -> None:
        from rs9.hosted_deb import provision_image

        class FakeHost:
            def __init__(self) -> None:
                self.calls: list[list[str]] = []

            def run(self, argv, **_kwargs):
                self.calls.append(list(argv))
                return CommandReceipt(argv, 0, b"", b"", executed=True)

        host = FakeHost()
        pins = job._load_pins(SOURCE_ROOT, "x86_64-linux")
        image = pins["rpm"]["container_digests"]["x86_64"]
        result = provision_image(
            host,
            "dnf",
            image,
            "linux/amd64",
            "rs9-rpm-keyfree-x86_64-linux",
            ["rpm-build"],
            recorder=host,
            substage_prefix="test-",
        )
        self.assertEqual(result, "rs9-rpm-keyfree-x86_64-linux")
        run = next(argv for argv in host.calls if len(argv) > 1 and argv[1] == "run")
        self.assertIn("--platform", run)
        self.assertEqual(run[run.index("--platform") + 1], "linux/amd64")
        self.assertIn(image, run)
        self.assertIn("dnf -y install rpm-build", run[-1])

    def test_real_target_pin_feeds_provision_with_full_immutable_image_refs(self) -> None:
        from rs9.hosted_native import provision

        class FakeRunner:
            def __init__(self, architecture: str) -> None:
                self.architecture = architecture
                self.calls: list[list[str]] = []

            def run(self, argv, **_kwargs):
                self.calls.append(list(argv))
                if argv[1:2] == ["pull"]:
                    return CommandReceipt(argv, 0, b"", b"", executed=True)
                self.assert_run = True
                output = b'NAME="Fedora Linux"\nVERSION_ID="43"\n' + self.architecture.encode("ascii") + b"\n"
                return CommandReceipt(argv, 0, output, b"", executed=True)

        for system, arch in (("x86_64-linux", "x86_64"), ("aarch64-linux", "aarch64")):
            pins = job._load_pins(SOURCE_ROOT, system)
            runner = FakeRunner(arch)
            result = provision("rpm", system, pins, runner=runner)
            image = pins["rpm"]["container_digests"][arch]
            self.assertRegex(image, r"^registry\.fedoraproject\.org/fedora@sha256:[0-9a-f]{64}$")
            self.assertEqual(result["image_ref"], image)
            platform = "linux/arm64" if arch == "aarch64" else "linux/amd64"
            self.assertEqual(runner.calls[0][2:4], ["--platform", platform])
            self.assertEqual(runner.calls[0][-1], image)
            self.assertEqual(runner.calls[1][5:7], ["--platform", platform])
            self.assertIn(image, runner.calls[1])

    def test_capture_verification_rejects_manifest_or_identity_drift(self) -> None:
        request = _fixture_requests()[0]
        capture, intent = _capture(request)
        job.verify_capture(request, capture, intent)
        capture.record["payloads"][0]["member_count"] += 1
        with self.assertRaisesRegex(Exception, "KEYFREE_CAPTURE"):
            job.verify_capture(request, capture, intent)

    def test_capture_verification_rejects_native_manifest_in_release_slot(self) -> None:
        request = _fixture_requests()[0]
        capture, intent = _capture(request)
        capture.record["payloads"][0]["payload_manifest_sha256"] = request["raw_asset"][
            "native_package_manifest_sha256"
        ]
        with self.assertRaisesRegex(Exception, "KEYFREE_CAPTURE"):
            job.verify_capture(request, capture, intent)

    def test_capture_verification_accepts_real_authenticated_release_fixture_shape(self) -> None:
        from tests.test_sidecar_harness_closure import current_import_fixture

        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            capture, captures, _client, _contract, _sources, _fixtures = current_import_fixture(
                Path(directory), "0.7.1"
            )
            fixture_intent = captures[0][1]
            intent = {
                **fixture_intent,
                "project": {**fixture_intent["project"], "id": job.PROJECT},
            }
            payload = capture.record["payloads"][0]
            metadata = capture.asset_metadata[payload["name"]]
            request = {
                "project": job.PROJECT,
                "source": {
                    "release_id": capture.record["release"]["id"],
                    "tag": capture.record["release"]["tag"],
                    "commit": capture.record["tag"]["commit"],
                    "tree": capture.record["tag"]["tree"],
                },
                "raw_asset": {
                    "github_asset_id": metadata["github_asset_id"],
                    "name": metadata["name"],
                    "bytes": metadata["size"],
                    "sha256": metadata["sha256"],
                    "native_package_manifest_sha256": _fixture_requests()[0]["raw_asset"][
                        "native_package_manifest_sha256"
                    ],
                    "release_payload_manifest_sha256": payload["payload_manifest_sha256"],
                    "native_package_member_count": _fixture_requests()[0]["raw_asset"][
                        "native_package_member_count"
                    ],
                    "release_payload_member_count": payload["member_count"],
                },
            }
            job.verify_capture(request, capture, intent)

    def test_run_lane_dispatches_existing_apis_without_native_execution(self) -> None:
        request = _fixture_requests()[0]
        capture, intent = _capture(request)
        calls: list[str] = []

        def capture_factory(*_args, **_kwargs):
            calls.append("capture")
            return [(capture, intent, {})]

        def provisioner(*_args, **_kwargs):
            calls.append("provision")
            return {
                "image_ref": "registry.fedoraproject.org/fedora@sha256:" + "c" * 64,
                "platform": "linux/amd64",
                "preprovisioned_packages": ["nodejs"],
            }

        def image_provisioner(*_args, **_kwargs):
            calls.append("image")
            return "rs9-rpm-keyfree-x86_64-linux"

        def adapter_call(build, request_value, *_args, **kwargs):
            calls.append("adapter")
            self.assertIs(build, job.build_rpm_candidate)
            self.assertEqual(request_value, request)
            self.assertEqual(kwargs["policy"]["status"], "blocked")
            self.assertEqual(kwargs["builder_policy"]["schema"], "rs9.rpm-lint-policy.v1")
            return {"schema": "rs9.current080-rpm-keyfree-readback.v1", "accepted": False}

        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            repository = root / "repository"
            scratch = root / "scratch"
            receipts = root / "receipts"
            repository.mkdir()
            scratch.mkdir()
            receipts.mkdir()
            args = types.SimpleNamespace(
                repository=str(repository),
                scratch=str(scratch),
                receipts=str(receipts),
                system="x86_64-linux",
                source_commit=VALID_COMMIT,
                source_tree=VALID_TREE,
                generation=job.GENERATION,
            )
            raw_policy = {"schema": "rs9.rpm-lint-policy.v1"}
            summary_policy = request["policy"]
            with patch.dict(os.environ, {}, clear=True):
                with (
                    patch.object(job, "_verify_checkout_identity"),
                    patch.object(job, "_load_policy", return_value=(raw_policy, summary_policy)),
                    patch.object(job, "_load_pins", return_value={"rpm": {}}),
                    patch.object(job, "_require_inventory_retention"),
                    patch.object(job, "_cleanup_step", return_value="complete"),
                ):
                    receipt = job.run_lane(
                        args,
                        capture_factory=capture_factory,
                        provisioner=provisioner,
                        image_provisioner=image_provisioner,
                        adapter=adapter_call,
                        host_factory=lambda: object(),
                    )
            self.assertEqual(calls, ["capture", "provision", "image", "adapter"])
            self.assertEqual(receipt["status"], "policy-held")
            output = next((receipts).iterdir())
            self.assertEqual(json.loads(output.read_text(encoding="utf-8"))["accepted"], False)

    def test_workflow_is_manual_two_lane_and_key_free(self) -> None:
        workflow = (
            ROOT / ".github" / "workflows" / "nebular080-rpm-keyfree-construction.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("workflow_dispatch:", workflow)
        self.assertNotIn("push:", workflow)
        self.assertNotIn("default:", workflow)
        self.assertIn("source_commit:", workflow)
        self.assertIn("source_tree:", workflow)
        self.assertEqual(workflow.count("required: true"), 2)
        self.assertIn("ubuntu-24.04", workflow)
        self.assertIn("ubuntu-24.04-arm", workflow)
        self.assertIn("rs9.current080_rpm_keyfree_job", workflow)
        self.assertIn("contents: read", workflow)
        self.assertIn("git rev-parse --verify HEAD", workflow)
        self.assertIn("HEAD^{tree}", workflow)
        self.assertIn("GITHUB_SHA", workflow)
        self.assertIn("GITHUB_RUN_ATTEMPT", workflow)
        self.assertIn("GITHUB_REPOSITORY", workflow)
        self.assertIn("python3 -B", workflow)
        self.assertIn("python3 -B -m rs9.current080_rpm_keyfree_job", workflow)
        self.assertNotIn("command -v python3", workflow)
        self.assertNotIn("hosted_packaging.execute", workflow)
        self.assertNotIn("sign_rpm", workflow)
        self.assertNotIn("rpm-sign", workflow)
        self.assertIn("actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09", workflow)
        self.assertIn("actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09", BASE_WORKFLOW.read_text(encoding="utf-8"))
        self.assertIn("actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02", workflow)
        self.assertIn("actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02", BASE_WORKFLOW.read_text(encoding="utf-8"))
        self.assertIn("python3 -m rs9.hosted_pipeline", BASE_WORKFLOW.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
