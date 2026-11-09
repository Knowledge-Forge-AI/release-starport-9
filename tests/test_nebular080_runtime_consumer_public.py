from __future__ import annotations

import ast
import hashlib
import importlib
import json
import subprocess
import sys
import tempfile
import unittest
import venv
from collections import Counter
from pathlib import Path
from unittest.mock import patch


# This test is intentionally repository-relative. A published source tree has
# one package root rather than multiple assembly-only source roots.
REPOSITORY = Path(__file__).resolve().parents[1]
SOURCE_ROOT = REPOSITORY / "src"
SRC = SOURCE_ROOT / "rs9"
sys.path.insert(0, str(SOURCE_ROOT))

ACTIVE_MODULES = (
    "nebular080_consumer_core",
    "nebular080_installed_smoke",
    "nebular080_darwin_harness",
    "nebular080_system_webkit",
    "nebular080_host_observation",
    "nebular080_payload",
    "nebular080_pip",
    "nebular080_manylinux",
    "nebular080_release",
    "nebular080_universal_missing",
    "nebular080_system_wheel",
)
MECHANICAL_MODULES = (
    "consumer_core",
    "installed_smoke",
    "darwin_harness",
    "system_webkit",
    "host_observation",
    "payload",
    "pip",
    "manylinux",
    "release",
    "universal_missing",
)
INTENTIONAL_TOP_LEVEL_ADDITIONS = {
    "consumer_core": frozenset({
        "_nebular_authenticated_darwin_payload_floor",
        "_nebular_python_version",
    }),
    "darwin_harness": frozenset({
        "_derive_darwin_pgrep_source",
        "prepare_darwin_installed_harness",
        "validate_darwin_installed_harness",
    }),
}
INTENTIONAL_SHAPE_CHANGES = {
    "consumer_core": {
        "_nebular_installed_consumer": (
            (("ExceptHandler", 3), ("If", 29), ("Return", 1), ("Try", 4)),
            (("ExceptHandler", 3), ("If", 31), ("Return", 1), ("Try", 4)),
        ),
    },
    "installed_smoke": {
        "_native_execution_failure_code": (
            (("ExceptHandler", 1), ("For", 3), ("If", 15), ("Return", 13), ("Try", 1)),
            (("ExceptHandler", 1), ("For", 4), ("If", 16), ("Return", 14), ("Try", 1)),
        ),
        "run_installed_smoke": (
            (("ExceptHandler", 2), ("For", 1), ("If", 27), ("Return", 1), ("Try", 2)),
            (("ExceptHandler", 2), ("For", 1), ("If", 34), ("Return", 1), ("Try", 2)),
        ),
        "validate_installed_smoke_summary": (
            (("For", 2), ("If", 13), ("Return", 1)),
            (("For", 3), ("If", 16), ("Return", 1)),
        ),
    },
    "darwin_harness": {
        "prepare_darwin_harness": (
            (("If", 4), ("Return", 1), ("With", 1)),
            (("If", 3), ("Return", 1), ("With", 1)),
        ),
    },
}
PREPARED_MODULES = {
    "nebular080_universal_profile",
    "nebular080_universal_fetch",
    "nebular080_universal_launcher",
    "wheel_nebular080_universal",
    "nebular080_smoke_support",
    "nebular080_universal_consumer",
    "nebular080_product_native",
}
GENERIC_MODULES = {
    "archives",
    "elf",
    "errors",
    "github",
    "hosted_commands",
    "materialize",
    "release_core",
    "scratch",
    "tf_pypi_archive",
    "tf_pypi_launcher",
    "tf_pypi_model",
    "tf_pypi_platform",
    "tf_pypi_probes",
    "tf_pypi_remote",
    "tf_pypi_verify",
    "verify_wheel",
    "wheel",
    "wheel_native",
    "bounded_process",
}



def _module_ast(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _rs9_import_roots(tree: ast.Module) -> set[str]:
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name for alias in node.names if alias.name.startswith("rs9."))
        elif isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("rs9."):
            roots.add(node.module)
    return roots


def _top_level_names(tree: ast.Module) -> set[str]:
    return {
        node.name
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    }


def _function_shapes(tree: ast.Module) -> dict[str, tuple[tuple[str, int], ...]]:
    functions = {
        node.name: node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    normalized: dict[str, tuple[tuple[str, int], ...]] = {}
    control_nodes = {
        "Assert", "AsyncFor", "AsyncWith", "ExceptHandler", "For", "If", "Raise",
        "Return", "Try", "While", "With", "Yield", "YieldFrom",
    }
    for name, node in functions.items():
        normalized_name = name.replace("nebular071", "nebular080").replace("NEBULAR071", "NEBULAR080")
        counts = Counter(type(item).__name__ for item in ast.walk(node) if type(item).__name__ in control_nodes)
        normalized[normalized_name] = tuple(sorted(counts.items()))
    return normalized






def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Nebular080RuntimeConsumerPublicTests(unittest.TestCase):
    def test_public_tree_has_one_repository_relative_package_root(self) -> None:
        self.assertEqual(SRC, REPOSITORY / "src" / "rs9")
        self.assertTrue((SOURCE_ROOT / "rs9" / "__init__.py").is_file())
        self.assertTrue((SRC / "bounded_process.py").is_file())
        self.assertTrue(all((SRC / f"{module}.py").is_file() for module in ACTIVE_MODULES))

    def test_active_sources_are_parseable_and_have_closed_namespace(self) -> None:
        for module in ACTIVE_MODULES:
            path = SRC / f"{module}.py"
            source = path.read_text(encoding="utf-8")
            _module_ast(path)
            self.assertNotIn("nebular071", source, module)
            self.assertNotIn("NEBULAR071", source, module)
            self.assertNotIn("tf_pypi_nebular071", source, module)
            self.assertNotIn("_071", source, module)
            self.assertNotIn("0.7.1", source, module)

    def test_runtime_import_closure_uses_only_package_siblings_or_allowlist(self) -> None:
        allowed = {f"rs9.{name}" for name in set(ACTIVE_MODULES) | PREPARED_MODULES}
        allowed |= {f"rs9.{name}" for name in GENERIC_MODULES}
        for module in ACTIVE_MODULES:
            roots = _rs9_import_roots(_module_ast(SRC / f"{module}.py"))
            unexpected = sorted(root for root in roots if root not in allowed)
            self.assertEqual(unexpected, [], module)

    def test_active_modules_import_without_route_execution(self) -> None:
        for module in ACTIVE_MODULES:
            imported = importlib.import_module(f"rs9.{module}")
            self.assertIsNotNone(imported)

    def test_core_profile_and_native_family_facts_are_separate(self) -> None:
        profile = importlib.import_module("rs9.nebular080_universal_profile")
        layout = importlib.import_module("rs9.wheel_nebular080_universal")
        core = importlib.import_module("rs9.nebular080_consumer_core")
        payload = importlib.import_module("rs9.nebular080_payload")
        smoke = importlib.import_module("rs9.nebular080_installed_smoke")
        native = importlib.import_module("rs9.nebular080_product_native")

        self.assertEqual(profile.VERSION, "0.8.0")
        self.assertEqual(set(core.NEBULAR080_TARGET_SYSTEMS), set(profile.TARGETS))
        self.assertEqual(core._NEBULAR_DARWIN_FLOOR, {"major": 13, "minor": 3})
        self.assertEqual(core._NEBULAR_LINUX_GLIBC_FLOOR, "2.36")
        self.assertEqual(payload.CLAIM, "manylinux_2_36")
        self.assertEqual(set(payload.LINUX_TARGETS), set(profile.LINUX_TARGETS))
        self.assertEqual(
            core._NEBULAR_EXPECTED_WHEEL_TAGS["darwin-arm64"],
            "py3-none-macosx_13_3_arm64",
        )
        self.assertEqual(set(smoke._SCENARIOS), set(profile.TARGETS))
        self.assertEqual(set(smoke._SYSTEM_WEBKIT_HOST_CLASSES), {"floor", "newer"})
        self.assertEqual(set(native._SMOKE_KINDS), {"npm-package", "raw-archive", "appearance-pair", "paired-v2"})
        self.assertEqual(set(layout.LAYOUTS), set(profile.TARGETS))
        self.assertNotIn("appearance-pair", core._NEBULAR_NATIVE_RC_SCENARIOS)

    def test_system_wheel_fail_closed_without_a_valid_wheel(self) -> None:
        system_wheel = importlib.import_module("rs9.nebular080_system_wheel")
        from rs9.errors import ContractError
        from rs9.tf_pypi_archive import AdmissionError

        with self.assertRaises((ContractError, AdmissionError)):
            system_wheel._system_wheel(b"", "linux-arm64-gnu")
        with self.assertRaises(ContractError):
            system_wheel._validate_system_webkit_archive(
                {"members": []},
                payload_name="runtime-manylinux.tar.gz",
                system="aarch64-linux",
                profile_id=system_wheel.NEBULAR080_SYSTEM_WEBKIT_PROFILE_ID,
            )

    def test_mechanical_siblings_keep_top_level_contract(self) -> None:
        base_dir = SRC
        for suffix in MECHANICAL_MODULES:
            old_tree = _module_ast(base_dir / f"nebular071_{suffix}.py")
            new_tree = _module_ast(base_dir / f"nebular080_{suffix}.py")
            old_names = {name.replace("nebular071", "nebular080") for name in _top_level_names(old_tree)}
            expected_names = old_names | INTENTIONAL_TOP_LEVEL_ADDITIONS.get(suffix, frozenset())
            self.assertEqual(expected_names, _top_level_names(new_tree), suffix)

    def test_mechanical_function_shapes_preserve_control_flow(self) -> None:
        base_dir = SRC
        for suffix in MECHANICAL_MODULES:
            old_shapes = _function_shapes(_module_ast(base_dir / f"nebular071_{suffix}.py"))
            new_shapes = _function_shapes(_module_ast(base_dir / f"nebular080_{suffix}.py"))
            allowed = INTENTIONAL_SHAPE_CHANGES.get(suffix, {})
            for name, (old_expected, new_expected) in allowed.items():
                self.assertEqual(old_expected, old_shapes.get(name), f"{suffix}:{name}:old")
                self.assertEqual(new_expected, new_shapes.get(name), f"{suffix}:{name}:new")
            intentional_names = set(INTENTIONAL_TOP_LEVEL_ADDITIONS.get(suffix, frozenset()))
            intentional_names.update(allowed)
            unchanged_old = {
                name: shape for name, shape in old_shapes.items() if name not in intentional_names
            }
            unchanged_new = {
                name: shape for name, shape in new_shapes.items() if name not in intentional_names
            }
            self.assertEqual(unchanged_old, unchanged_new, suffix)

    def test_system_wheel_does_not_reach_broad_consumer_or_legacy_owner(self) -> None:
        roots = _rs9_import_roots(_module_ast(SRC / "nebular080_system_wheel.py"))
        self.assertNotIn("rs9.nebular080_wheel_successor", roots)
        self.assertNotIn("rs9.nebular080_public_consumers", roots)
        self.assertFalse(any("nebular071" in root for root in roots))

    def test_bounded_process_is_available_as_the_generic_runtime_helper(self) -> None:
        helper = importlib.import_module("rs9.bounded_process")
        self.assertTrue(callable(helper.run_bounded))
        self.assertEqual(Path(helper.__file__).resolve().parent, SRC)

    def test_pip_default_command_preserves_the_stdlib_route(self) -> None:
        pip = importlib.import_module("rs9.nebular080_pip")
        command = pip._nebular_pip_command(Path("python"), ["--version"], None)
        self.assertEqual(command, [Path("python"), "-I", "-B", "-m", "pip", "--version"])

    def test_python_receipt_version_is_validated_against_coordinate_floor(self) -> None:
        consumer = importlib.import_module("rs9.nebular080_universal_consumer")
        coordinates = importlib.import_module("rs9.nebular080_publication_coordinates")
        actual = consumer._runtime_python_version({
            "major": sys.version_info.major,
            "minor": sys.version_info.minor,
        })
        self.assertEqual(consumer._minimum_python_version(), (3, 11))
        self.assertEqual(coordinates.EXPECTED_REQUIRES_PYTHON, ">=3.11")
        self.assertEqual(consumer._validate_python_version(actual), actual)

    def test_python_receipt_version_comes_from_created_venv_interpreter(self) -> None:
        core = importlib.import_module("rs9.nebular080_consumer_core")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            venv_root = root / "venv"
            venv.EnvBuilder(with_pip=False).create(venv_root)
            interpreter = venv_root / "bin/python"
            value = core._nebular_python_version(
                interpreter, {"HOME": str(root), "PATH": str(interpreter.parent)}, root, (),
                runner=subprocess.Popen,
            )
            self.assertEqual(value, {
                "major": sys.version_info.major,
                "minor": sys.version_info.minor,
            })

    def test_python_probe_uses_discriminating_interpreter_stub(self) -> None:
        core = importlib.import_module("rs9.nebular080_consumer_core")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            different_minor = 1 if sys.version_info.minor != 1 else 2
            interpreter = root / "stub-python"
            interpreter.write_text(f"#!/bin/sh\nprintf '3.{different_minor}'\n", encoding="utf-8")
            interpreter.chmod(0o755)
            value = core._nebular_python_version(
                interpreter, {"HOME": str(root), "PATH": "/bin:/usr/bin"}, root, (),
                runner=subprocess.Popen,
            )
            self.assertEqual(value, {"major": 3, "minor": different_minor})
            self.assertNotEqual(value["minor"], sys.version_info.minor)

    def test_python_probe_rejects_closed_abi_failures(self) -> None:
        core = importlib.import_module("rs9.nebular080_consumer_core")
        from rs9.tf_pypi_archive import AdmissionError
        cases = {
            "trailing-newline": "#!/bin/sh\nprintf '3.12\\n'\n",
            "stderr": "#!/bin/sh\nprintf '3.12'\nprintf 'noise' >&2\n",
            "nonzero": "#!/bin/sh\nprintf '3.12'\nexit 1\n",
            "invalid-utf8": "#!/bin/sh\nprintf '\\377'\n",
            "missing-minor": "#!/bin/sh\nprintf '3'\n",
            "extra-component": "#!/bin/sh\nprintf '3.1.2'\n",
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            for name, script in cases.items():
                with self.subTest(name=name):
                    interpreter = root / name
                    interpreter.write_text(script, encoding="utf-8")
                    interpreter.chmod(0o755)
                    with self.assertRaisesRegex(AdmissionError, "NEBULAR_PYTHON_VERSION"):
                        core._nebular_python_version(
                            interpreter, {"HOME": str(root), "PATH": "/bin:/usr/bin"}, root, (),
                            runner=subprocess.Popen,
                        )

    def test_python_receipt_rejects_tampered_bool_and_below_floor_versions(self) -> None:
        consumer = importlib.import_module("rs9.nebular080_universal_consumer")
        from rs9.errors import ContractError
        for tampered in (
            {"major": True, "minor": 13},
            {"major": 3, "minor": 9},
            {"major": 4, "minor": 0},
            {"major": 3, "minor": 100},
        ):
            with self.subTest(tampered=tampered), self.assertRaises(ContractError):
                consumer._validate_python_version(tampered)

    def test_python_version_is_joined_into_each_matrix_lane(self) -> None:
        matrix_source = (SRC / "tf_pypi_nebular080_universal.py").read_text(encoding="utf-8")
        consumer_source = (SRC / "nebular080_universal_consumer.py").read_text(encoding="utf-8")
        missing_source = (SRC / "nebular080_universal_missing.py").read_text(encoding="utf-8")
        core_source = (SRC / "nebular080_consumer_core.py").read_text(encoding="utf-8")
        self.assertIn('"python_version": _runtime_python_version(installed.get("python_version"))', consumer_source)
        self.assertIn('**installed,\n        "python_version": _runtime_python_version', consumer_source)
        self.assertIn('"python_version",', consumer_source)
        self.assertIn('"python_version": value["python_version"]', matrix_source)
        self.assertIn('"missing_runtime_python_version"] = negative["python_version"]', matrix_source)
        self.assertIn('"python_version": python_version', missing_source)
        self.assertIn('consumer._validate_python_version(value["python_version"])', missing_source)
        self.assertIn('"python_version": python_version', core_source)
        self.assertIn('if runtime_setup is not None:\n            # Only the 0.8 universal consumer supplies this hook.', core_source)

    def test_python_probe_hook_has_only_the_universal_080_caller(self) -> None:
        callers = []
        for path in sorted(SRC.glob("*.py")):
            if "nebular080_consumer_core" not in path.read_text(encoding="utf-8"):
                continue
            tree = _module_ast(path)
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                if not (isinstance(node.func, ast.Attribute)
                        and node.func.attr == "_nebular_installed_consumer"):
                    continue
                if any(keyword.arg == "runtime_setup" for keyword in node.keywords):
                    callers.append(path.name)
        self.assertEqual(callers, ["nebular080_universal_consumer.py"])

    def test_matrix_validation_propagates_positive_and_floor_python_versions(self) -> None:
        universal = importlib.import_module("rs9.tf_pypi_nebular080_universal")
        profile = importlib.import_module("rs9.nebular080_universal_profile")
        builder = importlib.import_module("rs9.wheel_nebular080_universal")
        source = {"commit": "a" * 40, "tree": "b" * 40}
        snapshot = {
            "wheel": {"filename": "held.whl", "sha256": "c" * 64},
            "runtime_inputs_sha256": "d" * 64,
            "runtime_index_sha256": "e" * 64,
        }
        captures = {
            target: {"payload_sha256": f"{index:064x}", "manifest_sha256": f"{index + 10:064x}"}
            for index, target in enumerate(builder.LAYOUTS, 1)
        }
        lanes = {(target, "newer") for target in builder.LAYOUTS} | {
            (target, "floor") for target in profile.LINUX_TARGETS
        }
        positives = {lane: {} for lane in lanes}
        negatives = {target: {} for target in profile.LINUX_TARGETS}
        minimum_python = importlib.import_module(
            "rs9.nebular080_universal_consumer")._minimum_python_version()
        exact_version = {"major": minimum_python[0], "minor": minimum_python[1]}
        positive_version = {"major": minimum_python[0], "minor": minimum_python[1] + 2}
        floor_version = {"major": minimum_python[0], "minor": minimum_python[1] + 1}
        positive_versions = {lane: dict(positive_version) for lane in lanes}
        positive_versions[sorted(lanes)[0]] = exact_version

        def fake_consumer(*_args, target, role, **_kwargs):
            return {
                "identity": "f" * 64,
                "python_version": dict(positive_versions[target, role]),
                "host_observation": {"identity": "1" * 64},
            }

        def fake_missing(*_args, **_kwargs):
            return {"identity": "0" * 64, "python_version": dict(floor_version)}

        with patch.object(universal.consumer, "validate_universal_consumer", side_effect=fake_consumer), \
                patch("rs9.nebular080_universal_missing.validate_missing_runtime", side_effect=fake_missing):
            result = universal.validate_matrix_receipts(
                snapshot, captures, positives, negatives,
                source=source, run_id="1", run_attempt="1",
            )

        self.assertEqual(len(result["lanes"]), 5)
        self.assertNotEqual(positive_version, floor_version)
        for row in result["lanes"]:
            self.assertEqual(row["python_version"], positive_versions[row["target"], row["role"]])
            if row["role"] == "floor":
                self.assertEqual(row["missing_runtime_python_version"], floor_version)
            else:
                self.assertNotIn("missing_runtime_python_version", row)

    def test_schema_registry_matches_owner_constants_and_has_no_dead_receipt(self) -> None:
        profile = importlib.import_module("rs9.nebular080_universal_profile")
        coordinates = importlib.import_module("rs9.nebular080_publication_coordinates")
        smoke = importlib.import_module("rs9.nebular080_installed_smoke")
        self.assertEqual(profile.SCHEMAS["consumer"], "rs9.nebular080-universal-native-consumer.v1")
        self.assertEqual(profile.SCHEMAS["runtime_setup"], "rs9.nebular080-universal-runtime-setup.v1")
        self.assertEqual(profile.SCHEMAS["system_webkit"], coordinates.SYSTEM_WEBKIT_INPUT_SCHEMA)
        self.assertEqual(profile.SCHEMAS["system_native"], smoke.SYSTEM_WEBKIT_NATIVE_INPUT_SCHEMA)
        self.assertNotIn("native_receipt", profile.SCHEMAS)

    def test_nested_raw_release_descriptor_uses_path_or_name_filename(self) -> None:
        consumer = importlib.import_module("rs9.nebular080_universal_consumer")
        from rs9.errors import ContractError
        self.assertEqual(
            consumer._descriptor_asset_name({"path": "nested/runtime.tar.gz", "name": "other"}),
            "runtime.tar.gz",
        )
        self.assertEqual(consumer._descriptor_asset_name({"name": "runtime.tar.gz"}), "runtime.tar.gz")
        with self.assertRaises(ContractError):
            consumer._descriptor_asset_name({"path": ""})
        bundle_source = (SRC / "tf_pypi_nebular080_universal.py").read_text(encoding="utf-8")
        self.assertIn("_descriptor_asset_name(row)", bundle_source)


    def test_runtime_setup_binds_exact_cold_download_and_offline_process_bytes(self) -> None:
        consumer = importlib.import_module("rs9.nebular080_universal_consumer")
        missing = importlib.import_module("rs9.nebular080_universal_missing")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            body = b"bounded runtime archive fixture"
            asset = {"size": len(body), "sha256": _sha(body)}
            spec = {"asset": asset, "manifest_sha256": "a" * 64}
            env = {"XDG_CACHE_HOME": str(root / "home" / ".cache")}
            archive = Path(env["XDG_CACHE_HOME"]) / "rs9/theme-forge-nebular-fusion/archives" / (asset["sha256"] + ".tgz")
            calls = []

            def result(code=0, stdout=b"", stderr=b""):
                return {
                    "exit_code": code, "signal": None,
                    "stdout_token": stdout.decode("utf-8"), "stderr_token": stderr.decode("utf-8"),
                    "stdout_sha256": _sha(stdout), "stderr_sha256": _sha(stderr),
                    "cleanup_known": True, "output_complete": True, "forced_cleanup": False,
                    "timed_out": False, "output_limit_exceeded": False, "duration_ms": 1,
                }

            def fake_run(argv, _env, _work, prefix, _timeout, *, runner):
                del runner
                calls.append((list(argv), tuple(prefix)))
                command = root / "tfnf"
                if list(argv) == [command]:
                    return result(1, stderr=missing.MISSING_LINE.encode("utf-8"))
                downloaded = not archive.exists()
                if downloaded:
                    archive.parent.mkdir(parents=True)
                    archive.write_bytes(body)
                receipt = {
                    "schema": "theme-forge-nebular-fusion.runtime-install.v1",
                    "version": "0.8.0", "target": "linux-x64-gnu",
                    "archive_sha256": asset["sha256"], "archive_bytes": asset["size"],
                    "manifest_sha256": "a" * 64, "downloaded": downloaded,
                    "redirect_hosts": ["release-assets.githubusercontent.com"] if downloaded else [],
                }
                encoded = (json.dumps(receipt, sort_keys=True) + "\n").encode("utf-8")
                return result(stdout=encoded)

            with patch("rs9.nebular080_consumer_core._nebular_run", side_effect=fake_run):
                value = consumer.install_runtime_for_consumer(
                    spec=spec, target="linux-x64-gnu", command=root / "tfnf",
                    python=root / "python", env=env, work=root,
                    prefix=("network-denial",), runner=object(),
                )
            self.assertEqual([prefix for _argv, prefix in calls],
                             [("network-denial",), (), ("network-denial",)])
            self.assertEqual(value["archive_sha256"], asset["sha256"])
            self.assertFalse(value["publication_admitted"])

    def test_runtime_setup_rejects_tampered_process_hash(self) -> None:
        consumer = importlib.import_module("rs9.nebular080_universal_consumer")
        missing = importlib.import_module("rs9.nebular080_universal_missing")
        from rs9.errors import ContractError
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            body = b"bounded runtime archive fixture"
            asset = {"size": len(body), "sha256": _sha(body)}
            spec = {"asset": asset, "manifest_sha256": "a" * 64}
            env = {"XDG_CACHE_HOME": str(root / "home" / ".cache")}
            archive = Path(env["XDG_CACHE_HOME"]) / "rs9/theme-forge-nebular-fusion/archives" / (asset["sha256"] + ".tgz")
            calls = []

            def fake_run(argv, _env, _work, _prefix, _timeout, *, runner):
                del runner
                calls.append(list(argv))
                if len(calls) == 1:
                    return {
                        "exit_code": 1, "signal": None, "stdout_token": "", "stderr_token": missing.MISSING_LINE,
                        "stdout_sha256": _sha(b""), "stderr_sha256": _sha(missing.MISSING_LINE.encode()),
                        "cleanup_known": True, "output_complete": True, "forced_cleanup": False,
                        "timed_out": False, "output_limit_exceeded": False, "duration_ms": 1,
                    }
                archive.parent.mkdir(parents=True, exist_ok=True)
                archive.write_bytes(body)
                receipt = {
                    "schema": "theme-forge-nebular-fusion.runtime-install.v1", "version": "0.8.0",
                    "target": "linux-x64-gnu", "archive_sha256": asset["sha256"],
                    "archive_bytes": asset["size"], "manifest_sha256": "a" * 64,
                    "downloaded": True, "redirect_hosts": ["release-assets.githubusercontent.com"],
                }
                encoded = (json.dumps(receipt, sort_keys=True) + "\n").encode()
                return {
                    "exit_code": 0, "signal": None, "stdout_token": encoded.decode(), "stderr_token": "",
                    "stdout_sha256": "0" * 64, "stderr_sha256": _sha(b""),
                    "cleanup_known": True, "output_complete": True, "forced_cleanup": False,
                    "timed_out": False, "output_limit_exceeded": False, "duration_ms": 1,
                }

            with patch("rs9.nebular080_consumer_core._nebular_run", side_effect=fake_run):
                with self.assertRaises(ContractError):
                    consumer.install_runtime_for_consumer(
                        spec=spec, target="linux-x64-gnu", command=root / "tfnf",
                        python=root / "python", env=env, work=root,
                        prefix=("network-denial",), runner=object(),
                    )


if __name__ == "__main__":
    unittest.main()
