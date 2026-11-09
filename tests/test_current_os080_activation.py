"""Pure route/data checks for the isolated Nebular 0.8 RS9 candidate."""
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = ROOT
BASE_FIXTURE = SOURCE_ROOT / "tests" / "fixtures" / "current071-source"
CANDIDATE_EXPECTATIONS = ROOT / "operators/theme-forge-current-202610/expectations.json"
HELD_POLICY_FIXTURE = SOURCE_ROOT / "tests" / "fixtures" / "current080-rpm-policy-held.json"
sys.path.insert(0, str(SOURCE_ROOT / "src"))
import rs9  # noqa: E402

from rs9 import application_smoke_diagnostic, current_generation, hosted_smoke, rpm_lint_policy, smoke_source_envelope  # noqa: E402
from rs9.errors import ContractError  # noqa: E402
from rs9.current_os080 import (  # noqa: E402
    CURRENT080_COMMIT,
    CURRENT080_GITHUB_ASSETS,
    CURRENT080_RAW_ASSETS,
    CURRENT080_RELEASE_ID,
    CURRENT080_REPLAY_PROGRESS_PROFILE,
    CURRENT080_SOURCE_FIXTURE_BINDING,
    CURRENT080_TAG,
    CURRENT080_TREE,
    CURRENT080_VERIFIER_FILES,
)
from rs9.current_os071 import CURRENT071_REPLAY_PROGRESS_PROFILE  # noqa: E402
from rs9.profiles import selection_for_intent  # noqa: E402


def _load(relative):
    path = CANDIDATE_EXPECTATIONS if relative == "operators/theme-forge-current-202610/expectations.json" else SOURCE_ROOT / relative
    return json.loads(path.read_bytes())


def _digest(value):
    return hashlib.sha256(value).hexdigest()


def _canonical(value):
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()


class CurrentOs080ActivationTests(unittest.TestCase):
    def test_exact_release_rows_bind_authenticated_public_identity(self):
        manifest = _load("bootstrap/pre-rs9/theme-forge-current-202610/manifest.json")
        row = next(item for item in manifest["projects"] if item["configuration"] == "theme-forge-nebular-fusion")
        self.assertEqual(
            {row[key] for key in ("release_id", "tag", "tag_commit", "tag_tree", "version")},
            {CURRENT080_RELEASE_ID, CURRENT080_TAG, CURRENT080_COMMIT, CURRENT080_TREE, "0.8.0"},
        )
        config = SOURCE_ROOT / "bootstrap/pre-rs9/theme-forge-current-202610/theme-forge-nebular-fusion"
        inventory = [
            {"path": path.relative_to(config).as_posix(), "sha256": _digest(path.read_bytes())}
            for path in sorted(config.rglob("*"))
            if path.is_file()
        ]
        self.assertEqual(row["config_sha256"], _digest(_canonical(inventory)))

        expectations = _load("operators/theme-forge-current-202610/expectations.json")
        expected = next(item for item in expectations["projects"] if item["project"] == "theme-forge-nebular-fusion")
        self.assertEqual(expected["release_id"], CURRENT080_RELEASE_ID)
        self.assertEqual(expected["published_at"], "2026-11-08T01:18:04Z")
        expected_assets = [
            {"id": row["github_asset_id"], "name": row["name"],
             "sha256": row["sha256"], "size": row["bytes"]}
            for row in sorted(CURRENT080_GITHUB_ASSETS, key=lambda row: row["name"])
        ]
        self.assertEqual(expected["release_asset_inventory"]["schema"], "rs9.release-asset-inventory.v1alpha1")
        self.assertEqual(
            sorted(expected["release_asset_inventory"]["assets"], key=lambda row: row["name"]),
            expected_assets,
        )
        intent = _load("bootstrap/pre-rs9/theme-forge-current-202610/theme-forge-nebular-fusion/intent.json")
        selection = selection_for_intent(intent)
        selected_names = {
            *(asset["name"] for asset in selection["payload_assets"]),
            *(asset["name"] for asset in selection["evidence_assets"]),
            selection["checksums"],
        }
        selected_assets = [asset for asset in expected_assets if asset["name"] in selected_names]
        self.assertEqual(len(selected_assets), 8)
        self.assertEqual(expected["assets"], selected_assets)
        self.assertEqual([row["name"] for row in expected["assets"]],
                         sorted(row["name"] for row in expected["assets"]))

    def test_nix_and_launcher_rows_bind_three_platforms_without_touching_other_products(self):
        base_catalog = json.loads(
            (BASE_FIXTURE / "nix/theme-forge-current-202610-products.json").read_bytes()
        )
        catalog = _load("nix/theme-forge-current-202610-products.json")
        product = catalog["products"]["theme-forge-nebular-fusion"]
        self.assertEqual(set(product["assets"]), {"aarch64-darwin", "aarch64-linux", "x86_64-linux"})
        self.assertEqual(product["version"], "0.8.0")
        self.assertEqual(product["assets"]["aarch64-darwin"]["launcher"], "Contents/Resources/bin/tfnf")
        self.assertEqual(product["assets"]["x86_64-linux"]["launcher"], "bin/tfnf")
        self.assertEqual(product["assets"]["x86_64-linux"]["executable_sha256"],
                         "61773740d5a165ccbf287ba8eaa175470d7288d23bd6c332e209e6cc07a7d8b1")
        for name in ("theme-forge-stellar-burst", "theme-forge-stellar-loom", "theme-forge-solar-sail"):
            self.assertEqual(catalog["products"][name], base_catalog["products"][name])

        commands = _load("operators/theme-forge-current-202610/command-contracts.json")
        base_commands = json.loads(
            (BASE_FIXTURE / "operators/theme-forge-current-202610/command-contracts.json").read_bytes()
        )
        tfnf = commands["commands"]["tfnf"]
        self.assertEqual(tfnf["evidence"]["commit"], CURRENT080_COMMIT)
        self.assertEqual(tfnf["implementation_sha256"]["bin/tfnf"],
                         "330ad3ef1156065bc7da49cbfac6222e1cbe8fab5c6ac288f68c4ee3509f33ad")
        self.assertEqual(tfnf["probes"][0]["stdout_contains"], ["0.8.0"])
        for name in ("tfsb", "tfsb-studio-service", "tfsl", "tfsl-batch", "tfss"):
            self.assertEqual(commands["commands"][name], base_commands["commands"][name])

    def test_source_envelope_and_profile_are_version_isolated(self):
        records, producers = smoke_source_envelope._expectations(CURRENT080_COMMIT)
        self.assertEqual(len(CURRENT080_VERIFIER_FILES), 15)
        self.assertEqual(len(records), 15 + len(hosted_smoke.CURRENT070_FIXTURE_FILES))
        self.assertEqual(producers["nebular"]["tag"], CURRENT080_TAG)
        self.assertEqual(producers["nebular"]["tree"], CURRENT080_TREE)
        self.assertEqual(CURRENT080_REPLAY_PROGRESS_PROFILE["id"], "nebular080")
        self.assertEqual(CURRENT080_REPLAY_PROGRESS_PROFILE["modules"]["native-rc-smoke.mjs"],
                         CURRENT080_VERIFIER_FILES["tools/native-rc-smoke.mjs"])
        expected_execution_modules = {
            "appearance-matrix-prep1/generate.mjs",
            "candidate-provenance.mjs",
            "fs-snapshot.mjs",
            "native-launcher.mjs",
            "native-rc-package.mjs",
            "native-rc-smoke.mjs",
            "native-runtime.mjs",
            "platform-targets.mjs",
        }
        self.assertEqual(set(CURRENT080_REPLAY_PROGRESS_PROFILE["execution_modules"]),
                         expected_execution_modules)
        self.assertEqual(
            CURRENT080_REPLAY_PROGRESS_PROFILE["execution_modules"],
            {name: CURRENT080_REPLAY_PROGRESS_PROFILE["modules"][name]
             for name in expected_execution_modules},
        )
        observation_profile = application_smoke_diagnostic._initial_observation_profile(
            CURRENT080_REPLAY_PROGRESS_PROFILE
        )
        self.assertEqual(set(observation_profile["closure_sha256s"]), expected_execution_modules)
        self.assertEqual(
            set(observation_profile["source_closure_sha256s"]),
            set(CURRENT080_REPLAY_PROGRESS_PROFILE["modules"]),
        )
        old_records, old_producers = smoke_source_envelope._expectations(hosted_smoke.CURRENT071_COMMIT)
        self.assertNotEqual(records, old_records)
        self.assertEqual(old_producers["nebular"]["tag"], "v0.7.1")
        self.assertEqual(producers["fixture"], {
            "repository": "Knowledge-Forge-AI/theme-forge-stellar-burst",
            "tag": "v0.7.0",
            "commit": CURRENT080_SOURCE_FIXTURE_BINDING["fixture"]["commit"],
            "tree": CURRENT080_SOURCE_FIXTURE_BINDING["fixture"]["tree"],
        })

    def test_current080_policy_candidate_is_authorized_and_other_rows_unchanged(self):
        policy = rpm_lint_policy.load_policy(
            generation=current_generation.CURRENT_GENERATION,
            policy_variant="current080",
        )
        self.assertEqual(policy["status"], "authorized")
        self.assertFalse(policy["blocking"])
        self.assertFalse(policy["production_enabled"])
        self.assertFalse(policy["publication_authority"])
        self.assertEqual(policy["projects"]["theme-forge-nebular-fusion"]["version"], "0.8.0")
        policy_bytes = (SOURCE_ROOT / current_generation.rpm_policy_path(
            current_generation.CURRENT_GENERATION, policy_variant="current080"
        )).read_bytes()
        self.assertEqual(_digest(policy_bytes),
                         "18beff59e710b79c5ea21eed9831010fd144cdab57e20db0e5a9e9efb7ceacb4")
        self.assertEqual(_digest(_canonical(policy)),
                         "18beff59e710b79c5ea21eed9831010fd144cdab57e20db0e5a9e9efb7ceacb4")
        baseline = rpm_lint_policy.load_policy(
            generation=current_generation.CURRENT_GENERATION,
            policy_variant="current071",
        )
        for project in ("theme-forge-stellar-burst", "theme-forge-stellar-loom", "theme-forge-solar-sail"):
            self.assertEqual(policy["projects"][project], baseline["projects"][project], project)
        caller_rules = [
            rule
            for code, rules in policy["projects"]["theme-forge-nebular-fusion"]["exceptions"].items()
            if code != "files-duplicated-waste"
            for rule in rules.values()
        ]
        self.assertEqual(len(caller_rules), 8)
        # Six rules are genuine caller contracts; the two .d.ts rows are the
        # only data-only exceptions. The historical default-policy tests cover
        # the shared serialized path; the dedicated current080 test module
        # proves these rules fail closed without caller evidence.
        self.assertEqual(
            sum(rule.get("intent") != "typescript-declaration-data" for rule in caller_rules),
            6,
        )
        self.assertEqual(
            current_generation.rpm_policy_path(
                current_generation.CURRENT_GENERATION,
                policy_variant="current080",
            ),
            "operators/theme-forge-current-202610/rpm-lint-policy-nebular080.json",
        )
        with self.assertRaises(ContractError):
            current_generation.rpm_policy_path(
                current_generation.CURRENT_GENERATION,
                policy_variant="future-version",
            )

    def test_held_policy_fixture_remains_blocked_and_is_not_selected(self):
        policy = json.loads(HELD_POLICY_FIXTURE.read_bytes())
        self.assertEqual(policy["status"], "blocked")
        self.assertTrue(policy["blocking"])
        self.assertIn("not yet derived", policy["policy_authority"])
        self.assertEqual(_digest(HELD_POLICY_FIXTURE.read_bytes()),
                         "6e0f66ab486b09992343ff32ff812b3eb51958daf5c1bd68b27cfa17e5781649")
        selected = rpm_lint_policy.load_policy(
            generation=current_generation.CURRENT_GENERATION,
            policy_variant="current080",
        )
        self.assertEqual(selected["status"], "authorized")

    def test_os080_initial_observation_argv_uses_only_fixed_execution_closure(self):
        profile = CURRENT080_REPLAY_PROGRESS_PROFILE
        initial = {
            "wrapper": Path("/tmp/rs9-wrapper.mjs"),
            "harness": Path("/tmp/tools/native-rc-smoke.mjs"),
            "progress": Path("/tmp/evidence/initial-progress.jsonl"),
            "path": Path("/tmp/evidence/initial-observation.json"),
            "profile": profile,
            "harness_timeout_ms": 210_000,
        }
        command = application_smoke_diagnostic._command(
            {"source": Path("/tmp/source"), "tools": Path("/tmp/tools")},
            "linux-x64", "C", Path("/tmp/launch"), Path("/tmp/evidence"),
            extras=[], initial_observation=initial,
        )
        closure_values = [
            command[index + 1]
            for index, value in enumerate(command[:-1])
            if value == "--rs9-replay-progress-closure-member"
        ]
        closure_names = {value.split("=", 1)[0] for value in closure_values}
        self.assertEqual(closure_names, set(profile["execution_modules"]))
        self.assertNotIn("build-inputs.mjs", closure_names)
        self.assertNotIn("sidecar-common.mjs", closure_names)

    def test_rpm_readback_binds_raw_assets_but_stays_non_authorizing(self):
        self.assertEqual(CURRENT080_SOURCE_FIXTURE_BINDING["nebular"],
                         {"commit": CURRENT080_COMMIT, "tree": CURRENT080_TREE})
        icon = _load("nix/theme-forge-current-202610-products.json")["products"][
            "theme-forge-nebular-fusion"]["icon"]
        self.assertEqual(icon["path"], CURRENT080_SOURCE_FIXTURE_BINDING["icon"]["path"])
        self.assertEqual(icon["sha256"], CURRENT080_SOURCE_FIXTURE_BINDING["icon"]["sha256"])
        self.assertEqual(icon["size"], CURRENT080_SOURCE_FIXTURE_BINDING["icon"]["size"])
        self.assertEqual(
            icon["url"],
            "https://raw.githubusercontent.com/Knowledge-Forge-AI/theme-forge-nebular-fusion/"
            + CURRENT080_COMMIT + "/" + CURRENT080_SOURCE_FIXTURE_BINDING["icon"]["path"],
        )
        self.assertEqual(CURRENT080_SOURCE_FIXTURE_BINDING["fixture"]["tag"], "v0.7.0")
        self.assertEqual(CURRENT080_SOURCE_FIXTURE_BINDING["fixture"]["commit"], hosted_smoke.CURRENT080_FIXTURE_COMMIT)
        self.assertEqual(CURRENT080_SOURCE_FIXTURE_BINDING["fixture"]["tree"], hosted_smoke.CURRENT080_FIXTURE_TREE)
        result = rpm_lint_policy.evaluate_policy(
            {}, {}, {"project_id": "theme-forge-nebular-fusion", "version": "0.8.0",
                     "arch": "x86_64", "system": "x86_64-linux"},
            policy=json.loads(HELD_POLICY_FIXTURE.read_bytes()),
            generation=current_generation.CURRENT_GENERATION,
            policy_variant="current080",
        )
        self.assertEqual(result["status"], "blocked")
        self.assertIn("current-generation-diagnostic-only", result["blockers"])

    def test_os080_initial_observation_uses_exact_transform_and_rejects_071_profile(self):
        diagnostic = application_smoke_diagnostic
        original = diagnostic._resolve_initial_observation_source
        diagnostic._resolve_initial_observation_source = (
            lambda prepared, system, *, environment_transform=False:
            (Path("/tmp/rs9-wrapper.mjs"), CURRENT080_REPLAY_PROGRESS_PROFILE)
        )
        try:
            descriptor = diagnostic._build_initial_observation_descriptor(
                {"tools": Path("/tmp")}, "x86_64-linux", "linux-x64", "C", Path("/tmp"),
                enabled=True, environment_transform=True,
            )
            self.assertEqual(
                descriptor["environment_transform"],
                diagnostic.CURRENT080_NIX_ENVIRONMENT_TRANSFORM_ID,
            )
            self.assertEqual(
                diagnostic._initial_observation_transform_args(
                    descriptor, CURRENT080_REPLAY_PROGRESS_PROFILE, "linux-x64", "C",
                ),
                ["--rs9-current-nix-environment-transform", diagnostic.CURRENT080_NIX_ENVIRONMENT_TRANSFORM_ID],
            )
            with self.assertRaises(ContractError):
                diagnostic._initial_observation_transform_args(
                    descriptor, CURRENT071_REPLAY_PROGRESS_PROFILE, "linux-x64", "C",
                )
        finally:
            diagnostic._resolve_initial_observation_source = original

    def test_os080_timeout_parity_and_mixed_profile_tuples_fail_closed(self):
        diagnostic = application_smoke_diagnostic
        self.assertEqual(diagnostic._current080_initial_timeout_ms("linux-arm64", "B"), 210_000)
        self.assertEqual(diagnostic._current080_initial_timeout_ms("linux-x64", "C"), 210_000)
        self.assertEqual(diagnostic._current080_initial_timeout_ms("linux-x64", "C-signal"), 180_000)
        profile = diagnostic._initial_observation_profile(CURRENT080_REPLAY_PROGRESS_PROFILE)
        value = {
            "source_profile": {**profile, "id": "nebular071"},
            "execution_transform": {
                **diagnostic.CURRENT080_EXECUTION_TRANSFORM,
            },
        }
        with self.assertRaises(ValueError):
            diagnostic._validate_initial_execution_transform(value, None, True)

    def test_hosted_nix_observation_requirement_keeps_known_071_fallback(self):
        from rs9 import hosted_nix

        with tempfile.TemporaryDirectory(prefix="nebular080-nix-profile-") as temporary:
            source = Path(temporary)
            package = source / "package.json"
            prepared = {"source_generation": current_generation.CURRENT_GENERATION, "source": source}
            package.write_text('{"version":"0.7.1"}\n', encoding="utf-8")
            self.assertFalse(hosted_nix._current080_observation_required(
                current_generation.CURRENT_GENERATION, "x86_64-linux", prepared
            ))
            package.write_text('{"version":"0.8.0"}\n', encoding="utf-8")
            self.assertTrue(hosted_nix._current080_observation_required(
                current_generation.CURRENT_GENERATION, "x86_64-linux", prepared
            ))

    def test_current071_policy_and_nonnebular_rows_remain_byte_identical(self):
        pairs = (
            "operators/theme-forge-current-202610/rpm-lint-policy-nebular071.json",
            "operators/theme-forge-current-202610/rpm-lint-policy.json",
        )
        for relative in pairs:
            candidate = (SOURCE_ROOT / relative).read_bytes()
            base = (BASE_FIXTURE / relative).read_bytes()
            self.assertEqual(candidate, base, relative)
        candidate_manifest = _load("bootstrap/pre-rs9/theme-forge-current-202610/manifest.json")
        base_manifest = json.loads((BASE_FIXTURE / "bootstrap/pre-rs9/theme-forge-current-202610/manifest.json").read_bytes())
        for candidate, base in zip(candidate_manifest["projects"], base_manifest["projects"]):
            if candidate["configuration"] != "theme-forge-nebular-fusion":
                self.assertEqual(candidate, base)


class CurrentOs080InitialWrapperBoundaryTests(unittest.TestCase):
    """Exercise the real Python producer and Node parser without a GUI launch."""

    def _run_wrapper(self, root, platform, scenario, profile, transform, mutate=None):
        diagnostic = application_smoke_diagnostic
        wrapper = Path(diagnostic.__file__).with_name("replay_progress_wrapper.mjs")
        # A missing harness is intentional: accepted CLI input must reach the
        # unchanged authenticated-source guard, without importing product code.
        tools = root / "missing-tools"
        tools.mkdir(exist_ok=True)
        evidence = root / "evidence"
        initial = {
            "wrapper": wrapper, "harness": tools / "native-rc-smoke.mjs",
            "progress": evidence / "progress.jsonl",
            "path": evidence / "initial-observation.json",
            "profile": profile,
            "harness_timeout_ms": diagnostic._current_initial_timeout_ms(profile, platform, scenario),
            "environment_transform": transform,
        }
        command = diagnostic._command(
            {"source": root / "source", "tools": tools},
            platform, scenario, root / "launch", evidence,
            extras=False, initial_observation=initial,
        )
        command = command[command.index("node"):]
        command[0] = shutil.which("node")
        self.assertIsNotNone(command[0], "The existing pinned Node toolchain is required")
        if mutate is not None:
            command = mutate(command)
        env = {key: os.environ[key] for key in ("PATH", "TMPDIR", "LANG", "LC_ALL") if key in os.environ}
        result = subprocess.run(command, env=env, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b"")
        self.assertFalse(evidence.exists())
        return result.stderr

    def test_current080_generated_arguments_reach_authenticated_source_guard(self):
        diagnostic = application_smoke_diagnostic
        with tempfile.TemporaryDirectory(prefix="rs9-transform-parser-") as temporary:
            for platform, scenario in (("linux-arm64", "B"), ("linux-x64", "C"), ("linux-x64", "C-signal")):
                with self.subTest(platform=platform, scenario=scenario):
                    stderr = self._run_wrapper(
                        Path(temporary), platform, scenario, CURRENT080_REPLAY_PROGRESS_PROFILE,
                        diagnostic.CURRENT080_NIX_ENVIRONMENT_TRANSFORM_ID,
                    )
                    self.assertEqual(stderr, b"Authenticated replay source is unavailable\n")

    def test_current071_generated_arguments_retain_authenticated_source_guard(self):
        diagnostic = application_smoke_diagnostic
        with tempfile.TemporaryDirectory(prefix="rs9-transform-parser-") as temporary:
            for platform, scenario in (("linux-arm64", "B"), ("linux-x64", "C"), ("linux-x64", "C-signal")):
                with self.subTest(platform=platform, scenario=scenario):
                    stderr = self._run_wrapper(
                        Path(temporary), platform, scenario, CURRENT071_REPLAY_PROGRESS_PROFILE,
                        diagnostic.CURRENT_NIX_ENVIRONMENT_TRANSFORM_ID,
                    )
                    self.assertEqual(stderr, b"Authenticated replay source is unavailable\n")

    def test_transform_parser_still_rejects_unknown_missing_and_duplicate_values(self):
        diagnostic = application_smoke_diagnostic
        flag = "--rs9-current-nix-environment-transform"
        def unknown(command):
            command[command.index(flag) + 1] = "current999-nix-inherited-xdg-fontconfig-v1"
            return command
        def missing(command):
            index = command.index(flag)
            return [*command[:index], *command[index + 2:], flag]
        def duplicate(command):
            return [*command, flag, diagnostic.CURRENT080_NIX_ENVIRONMENT_TRANSFORM_ID]
        with tempfile.TemporaryDirectory(prefix="rs9-transform-parser-") as temporary:
            for mutation in (unknown, missing, duplicate):
                with self.subTest(mutation=mutation.__name__):
                    stderr = self._run_wrapper(
                        Path(temporary), "linux-x64", "C", CURRENT080_REPLAY_PROGRESS_PROFILE,
                        diagnostic.CURRENT080_NIX_ENVIRONMENT_TRANSFORM_ID, mutation,
                    )
                    self.assertEqual(stderr, b"Current Nix environment transform argument is invalid\n")

    def test_transform_parser_still_requires_initial_observation(self):
        diagnostic = application_smoke_diagnostic
        def omit_initial(command):
            for flag in ("--rs9-initial-observation-kind", "--rs9-initial-observation-file"):
                index = command.index(flag)
                del command[index:index + 2]
            return command
        with tempfile.TemporaryDirectory(prefix="rs9-transform-parser-") as temporary:
            stderr = self._run_wrapper(
                Path(temporary), "linux-x64", "C", CURRENT080_REPLAY_PROGRESS_PROFILE,
                diagnostic.CURRENT080_NIX_ENVIRONMENT_TRANSFORM_ID, omit_initial,
            )
            self.assertEqual(stderr, b"Current Nix environment transform requires initial observation\n")


if __name__ == "__main__":
    unittest.main()
