"""Pure guarded tests for current-generation Linux Nix FHS graphics runtime.

Note: The Nix recipe evaluations in this module use `nix-instantiate --store dummy://
--option eval-cache false --eval --strict --json` with inert temporary capture/catalog
fixtures and package stubs. They verify the real `nix/nebular.nix` predicate,
short-circuiting, `targetPkgs` arguments, and deterministic dummy `.drvPath` outputs
only; they do not perform real Nixpkgs rootfs realization or native GUI qualification.
"""
from __future__ import annotations

import ast
import copy
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from rs9 import hosted_nix
from rs9.current_generation import (
    CURRENT_GENERATION,
    HISTORICAL_GENERATION,
    bind_catalog_product,
    catalog_path,
)
from rs9.errors import ContractError
from rs9.product_classes import get_product_class as package_class
from rs9.profiles import selection_for_intent
from rs9.release_core import authenticate_release, digest
from rs9.scratch import canonical
from tests.test_current_generation import current_fixture
from tests.test_hygiene import bounded_text, scan_text

ROOT = Path(__file__).resolve().parents[1]

PINNED_NIX_BINARY = Path(
    "/nix/store/744byzkhlxx5lam43g62wrrmzcksjsd8-nix-2.31.5/bin/nix"
)
PINNED_NIX_INSTANTIATE = PINNED_NIX_BINARY.with_name("nix-instantiate")
PINNED_NIX_SHA256 = (
    "a8d74ac44bf53f6bcb4bf6866eb321fb0e07dab172e4bc61481957877b844f55"
)
MANDATORY_NIX_EVAL_ARGS = (
    "--store",
    "dummy://",
    "--option",
    "eval-cache",
    "false",
    "--eval",
    "--strict",
    "--json",
)

NEBULAR_NIX_ADDED_BLOCK = """\
  # Proposed current-generation Linux graphics userspace (unactivated). Empty
  # unless prepare_input set source_generation on a current Linux lane AND the
  # capture matches the in-tree current catalog coordinates and archive digest.
  currentCatalog = builtins.fromJSON
    (builtins.readFile ./theme-forge-current-202610-products.json);
  currentRow = currentCatalog.products.${product.pname} or { };
  currentAsset = (currentRow.assets or { }).${stdenv.hostPlatform.system} or null;
  currentLinuxGraphics =
    stdenv.hostPlatform.isLinux
    && (product ? source_generation)
    && product.source_generation == currentCatalog.generation
    && currentAsset != null
    && product.version == (currentRow.version or null)
    && (product.commit or null) == (currentRow.commit or null)
    && (product.asset_sha256 or null) == currentAsset.sha256
    && builtins.hashFile "sha256"
         (capture + "/payloads/${product.pname}/payload.tar.gz") == currentAsset.sha256;
  # Existing-pin Mesa runtime output and libglvnd only; explicit outputs exclude
  # opencl/spirv2dxil/cross_tools/debug/dev. includeClosures remains false.
  currentGraphicsPackages = pkgs:
    lib.optionals currentLinuxGraphics [ pkgs.mesa.out pkgs.libglvnd.out ];
"""
NEBULAR_NIX_PATCHED_TARGET_PKGS_LINE = (
    "    targetPkgs = pkgs: runtimePackages pkgs ++ currentGraphicsPackages pkgs;\n"
)
NEBULAR_NIX_BASELINE_TARGET_PKGS_LINE = "    targetPkgs = runtimePackages;\n"

HOSTED_NIX_ADDED_BLOCK = """\
        if native and _current_linux_lane(generation, context["system"]):
            # Explicit authenticated discriminator for the shared Nebular recipe;
            # historical and Darwin rows remain byte-identical.
            row["source_generation"] = CURRENT_GENERATION
"""

EXPECTED_BASELINE_TARGET_PKGS = [
    "glibc-1.0.out",
    "gtk3-1.0.out",
    "webkitgtk_4_1-1.0.out",
    "glib-1.0.out",
    "cairo-1.0.out",
    "pango-1.0.out",
    "gdk-pixbuf-1.0.out",
    "libsoup_3-1.0.out",
    "atk-1.0.out",
    "dbus-1.0.out",
    "openssl-1.0.out",
    "zlib-1.0.out",
    "gcc-lib-1.0.out",
    "nodejs_22-1.0.out",
    "python3-1.0.out",
    "binutils-1.0.out",
    "xvfb-run-1.0.out",
    "dbus-1.0.out",
    "libX11-1.0.out",
    "libXcomposite-1.0.out",
    "libXdamage-1.0.out",
    "libXext-1.0.out",
    "libXfixes-1.0.out",
    "libXrandr-1.0.out",
    "libXrender-1.0.out",
    "libXtst-1.0.out",
    "libxcb-1.0.out",
]
EXPECTED_GRAPHICS_ADDITIONS = [
    "mesa-25.2.6.out",
    "libglvnd-1.7.0.out",
]


def _baseline_nebular_nix_bytes() -> bytes:
    current_text = (ROOT / "nix/nebular.nix").read_text()
    if NEBULAR_NIX_ADDED_BLOCK in current_text:
        if current_text.count(NEBULAR_NIX_ADDED_BLOCK) != 1:
            raise AssertionError("Expected exactly one currentLinuxGraphics block")
        if current_text.count(NEBULAR_NIX_PATCHED_TARGET_PKGS_LINE) != 1:
            raise AssertionError("Expected exactly one patched targetPkgs line")
        reconstructed = current_text.replace(NEBULAR_NIX_ADDED_BLOCK, "", 1).replace(
            NEBULAR_NIX_PATCHED_TARGET_PKGS_LINE,
            NEBULAR_NIX_BASELINE_TARGET_PKGS_LINE,
            1,
        )
    else:
        reconstructed = current_text
    if "currentLinuxGraphics" in reconstructed or "currentGraphicsPackages" in reconstructed:
        raise AssertionError("Baseline nix/nebular.nix reconstruction retained graphics block")
    return reconstructed.encode("utf-8")


def _baseline_hosted_nix_py_bytes() -> bytes:
    current_text = (ROOT / "src/rs9/hosted_nix.py").read_text()
    if HOSTED_NIX_ADDED_BLOCK in current_text:
        if current_text.count(HOSTED_NIX_ADDED_BLOCK) != 1:
            raise AssertionError("Expected exactly one source_generation discriminator block")
        reconstructed = current_text.replace(HOSTED_NIX_ADDED_BLOCK, "", 1)
    else:
        reconstructed = current_text
    if 'row["source_generation"]' in reconstructed:
        raise AssertionError("Baseline src/rs9/hosted_nix.py reconstruction retained discriminator")
    return reconstructed.encode("utf-8")


def _load_baseline_prepare_input():
    source_bytes = _baseline_hosted_nix_py_bytes()
    namespace = dict(hosted_nix.__dict__)
    exec(compile(source_bytes, "baseline_hosted_nix.py", "exec"), namespace)
    namespace["stage_payload"] = lambda *args, **kwargs: None
    namespace["_resolve_offline_npm_archives"] = lambda *args, **kwargs: []
    namespace["stage_offline_npm_closure"] = lambda *args, **kwargs: None
    return namespace["prepare_input"]


def _verified_nix_instantiate_cmd() -> list[str]:
    if not PINNED_NIX_BINARY.exists() and not PINNED_NIX_INSTANTIATE.is_symlink():
        raise unittest.SkipTest(
            "Pinned local nix-instantiate evaluator unavailable on this runner "
            "(e.g., Nix-less CI unit job); dummy-store Nix evaluations skipped"
        )
    if not PINNED_NIX_BINARY.is_file() or PINNED_NIX_BINARY.is_symlink():
        raise AssertionError("Pinned local nix binary unavailable")
    if hashlib.sha256(PINNED_NIX_BINARY.read_bytes()).hexdigest() != PINNED_NIX_SHA256:
        raise AssertionError("Pinned local nix binary SHA-256 mismatch")
    if (
        not PINNED_NIX_INSTANTIATE.is_symlink()
        or PINNED_NIX_INSTANTIATE.resolve() != PINNED_NIX_BINARY
    ):
        raise AssertionError("Pinned nix-instantiate symlink target mismatch")
    popen_code = getattr(subprocess.Popen, "__code__", None)
    if (
        getattr(subprocess.Popen, "__name__", "") == "guarded"
        and popen_code is not None
        and "verified_nix_eval" not in popen_code.co_names
    ):
        raise unittest.SkipTest(
            "Active subprocess guard does not permit verified nix-instantiate "
            "dummy-store evaluator; skipping dummy-store Nix evaluations"
        )
    return [str(PINNED_NIX_INSTANTIATE), *MANDATORY_NIX_EVAL_ARGS]


def _evaluate_nebular_recipe_dummy_store(
    recipe_path: Path,
    system: str,
    product: dict,
    capture_dir: Path,
) -> subprocess.CompletedProcess[str]:
    """Evaluate exact recipe bytes in Nix dummy store with dependency stubs.

    Explicitly exercises predicate, short-circuiting, targetPkgs arguments, and
    deterministic dummy .drvPath computation only; not real Nixpkgs rootfs or
    native qualification.
    """
    cmd_prefix = _verified_nix_instantiate_cmd()
    expr = f"""
let
  system = {json.dumps(system)};
  recipePath = {json.dumps(str(recipe_path))};
  capture = {json.dumps(str(capture_dir))};
  product = builtins.fromJSON {json.dumps(json.dumps(product))};
  plain = builtins.unsafeDiscardStringContext;
  mkPkg = name: version: output:
    let
      id = "${{name}}-${{version}}.${{output}}";
      drv = derivation {{
        name = "${{name}}-${{version}}" + (if output == "out" then "" else "-${{output}}");
        inherit system id;
        builder = "/bin/sh";
        args = [ "-c" ":" ];
      }};
    in drv // {{
      inherit id;
      pkgName = name;
      pkgVersion = version;
      pkgOutput = output;
    }};
  mkSimplePkg = name: mkPkg name "1.0" "out";
  lib = {{
    unique = builtins.foldl' (acc: x: if builtins.elem x acc then acc else acc ++ [ x ]) [ ];
    makeLibraryPath = pkgsList: builtins.concatStringsSep ":" (map (p: "${{p}}/lib") pkgsList);
    optionals = cond: list: if cond then list else [ ];
  }};
  stdenv = {{
    isDarwin = system == "aarch64-darwin";
    shell = "/bin/sh";
    hostPlatform = {{
      inherit system;
      isLinux = system == "x86_64-linux" || system == "aarch64-linux";
      isAarch64 = system == "aarch64-linux" || system == "aarch64-darwin";
    }};
    cc = {{ cc = {{ lib = mkSimplePkg "gcc-lib"; }}; }};
  }};
  stdenvNoCC = {{
    mkDerivation = attrs:
      derivation {{
        name = "${{attrs.pname}}-${{attrs.version}}";
        inherit system;
        builder = "/bin/sh";
        args = [ "-c" (attrs.installPhase or "") ];
        src = toString attrs.src;
        dontConfigure = attrs.dontConfigure or false;
        dontBuild = attrs.dontBuild or false;
        dontFixup = attrs.dontFixup or false;
      }};
  }};
  python3 = mkSimplePkg "python3";
  pkgs = {{
    inherit stdenv python3;
    glibc = mkSimplePkg "glibc";
    gtk3 = mkSimplePkg "gtk3";
    webkitgtk_4_1 = mkSimplePkg "webkitgtk_4_1";
    glib = mkSimplePkg "glib";
    cairo = mkSimplePkg "cairo";
    pango = mkSimplePkg "pango";
    gdk-pixbuf = mkSimplePkg "gdk-pixbuf";
    libsoup_3 = mkSimplePkg "libsoup_3";
    atk = mkSimplePkg "atk";
    dbus = mkSimplePkg "dbus";
    openssl = mkSimplePkg "openssl";
    zlib = mkSimplePkg "zlib";
    nodejs_22 = mkSimplePkg "nodejs_22";
    binutils = mkSimplePkg "binutils";
    xvfb-run = mkSimplePkg "xvfb-run";
    xorg = {{
      libX11 = mkSimplePkg "libX11";
      libXcomposite = mkSimplePkg "libXcomposite";
      libXdamage = mkSimplePkg "libXdamage";
      libXext = mkSimplePkg "libXext";
      libXfixes = mkSimplePkg "libXfixes";
      libXrandr = mkSimplePkg "libXrandr";
      libXrender = mkSimplePkg "libXrender";
      libXtst = mkSimplePkg "libXtst";
      libxcb = mkSimplePkg "libxcb";
    }};
    mesa = (mkPkg "mesa" "25.2.6" "default") // {{
      out = mkPkg "mesa" "25.2.6" "out";
      opencl = mkPkg "mesa" "25.2.6" "opencl";
      spirv2dxil = mkPkg "mesa" "25.2.6" "spirv2dxil";
      cross_tools = mkPkg "mesa" "25.2.6" "cross_tools";
      debug = mkPkg "mesa" "25.2.6" "debug";
      dev = mkPkg "mesa" "25.2.6" "dev";
    }};
    libglvnd = (mkPkg "libglvnd" "1.7.0" "default") // {{
      out = mkPkg "libglvnd" "1.7.0" "out";
      dev = mkPkg "libglvnd" "1.7.0" "dev";
    }};
  }};
  writeText = name: text:
    (derivation {{
      inherit name system text;
      builder = "/bin/sh";
      args = [ "-c" ":" ];
    }}) // {{ inherit text; }};
  writeShellScript = name: text:
    (derivation {{
      inherit name system text;
      builder = "/bin/sh";
      args = [ "-c" ":" ];
    }}) // {{ inherit text; }};
  buildFHSEnv = args@{{ name, targetPkgs, runScript, includeClosures ? false, ... }}:
    let
      selected = targetPkgs pkgs;
      targetPkgIds = map (p: p.id) selected;
      targetOutPaths = map (p: "${{p}}") selected;
      drv = derivation {{
        inherit name system includeClosures;
        builder = "/bin/sh";
        args = [ "-c" ":" ];
        runScript = "${{runScript}}";
        targetPkgIdsJson = builtins.toJSON targetPkgIds;
        targetOutPathsJoined = builtins.concatStringsSep ":" targetOutPaths;
      }};
    in drv // {{
      inherit includeClosures targetPkgIds;
      extraArgs = builtins.sort builtins.lessThan
        (builtins.attrNames (builtins.removeAttrs args [ "name" "targetPkgs" "runScript" ]));
    }};
  runCommand = name: attrs: buildCommand:
    let
      passthru = attrs.passthru or {{ }};
      drv = derivation ({{
        inherit name system buildCommand;
        builder = "/bin/sh";
        args = [ "-c" buildCommand ];
      }} // builtins.removeAttrs attrs [ "passthru" ]);
    in drv // {{ inherit passthru buildCommand; }};
  recipe = import (builtins.toPath recipePath) {{
    inherit lib stdenvNoCC runCommand writeShellScript writeText buildFHSEnv python3 stdenv pkgs;
  }};
  result = recipe {{ inherit product capture; }};
in {{
  evaluationKind = "stubbed-dummy-store-predicate-and-targetPkgs-only";
  nativeQualificationClaimed = false;
  drvPath = plain result.drvPath;
  candidateOutPath = plain result.outPath;
  runtimeDrvPath = plain result.passthru.runtime.drvPath;
  runtimeOutPath = plain result.passthru.runtime.outPath;
  payloadDrvPath = plain result.passthru.payload.drvPath;
  targetPkgs = result.passthru.runtime.targetPkgIds;
  includeClosures = result.passthru.runtime.includeClosures;
  fhsExtraArgs = result.passthru.runtime.extraArgs;
  runtimeFacts = builtins.fromJSON (plain result.passthru.runtimeFacts.text);
}}
"""
    return subprocess.run(
        [*cmd_prefix, "--expr", expr],
        capture_output=True,
        text=True,
        timeout=30,
    )


def _recapture_payloads(capture, intent, payloads):
    """Authenticate synthetic multi-platform archives through the real release boundary."""
    selected = []
    for index, (data, platforms, commands, launchers) in enumerate(payloads):
        name = f"synthetic-{index}.tgz"
        (capture.root / "assets" / name).write_bytes(data)
        selected.append(
            {
                "id": f"payload-{index}",
                "name": name,
                "format": "tar.gz",
                "platforms": platforms,
                "commands": commands,
                "launchers": launchers,
            }
        )
    intent["assets"] = selected
    assets = {
        path.name: path.read_bytes()
        for path in (capture.root / "assets").iterdir()
        if path.name != "SHA256SUMS"
    }
    (capture.root / "assets/SHA256SUMS").write_bytes(
        "".join(
            digest(data) + "  " + name + "\n"
            for name, data in sorted(assets.items())
        ).encode("utf-8")
    )
    assets["SHA256SUMS"] = (capture.root / "assets/SHA256SUMS").read_bytes()
    path = capture.root / "api/release.json"
    release = json.loads(path.read_bytes())
    release["assets"] = [
        {
            "id": index + 1,
            "name": name,
            "size": len(data),
            "digest": "sha256:" + digest(data),
            "state": "uploaded",
        }
        for index, (name, data) in enumerate(sorted(assets.items()))
    ]
    path.write_bytes(canonical(release))
    selection = selection_for_intent(intent)
    for asset in selection["payload_assets"]:
        if asset["launchers"]:
            asset["command_policy"] = "native-executable"
    return authenticate_release(selection, capture.root)


def _build_synthetic_repository_and_captures(work_root: Path):
    """Build real authenticated synthetic captures for all 4 products across 3 systems."""
    repo_dir = work_root / "synthetic-repo"
    repo_dir.mkdir(parents=True)
    shutil.copyfile(ROOT / "flake.nix", repo_dir / "flake.nix")
    shutil.copytree(ROOT / "nix", repo_dir / "nix")

    current_doc = json.loads((ROOT / catalog_path(CURRENT_GENERATION)).read_bytes())
    historical_doc = json.loads((ROOT / catalog_path(HISTORICAL_GENERATION)).read_bytes())

    captures = []
    for short_name in ("stellar-burst", "stellar-loom", "solar-sail"):
        sub_root = work_root / f"cap-{short_name}"
        sub_root.mkdir()
        capture, intent, _ = current_fixture(sub_root, short_name, engine=">=22")
        pid = intent["project"]["id"]
        intent["commands"] = [{"name": "second", "interface": "cli"}]
        payload = capture.record["payloads"][0]

        cur_row = copy.deepcopy(current_doc["products"][pid])
        cur_row.update(
            commit=capture.record["tag"]["commit"],
            commands=["second"],
            command_paths={"second": "bin/run.js"},
            node_engine=">=22",
        )
        cur_row["asset"] = {key: payload[key] for key in ("name", "sha256", "size", "root")}
        cur_row["asset"]["url"] = (
            "https://github.com/"
            + cur_row["repository"]
            + "/releases/download/"
            + cur_row["tag"]
            + "/"
            + payload["name"]
        )
        current_doc["products"][pid] = cur_row
        bind_catalog_product(cur_row, capture, intent, generation=CURRENT_GENERATION)
        captures.append((capture, intent, {}))

    neb_root = work_root / "cap-nebular"
    neb_root.mkdir()
    neb_base_capture, neb_intent, _ = current_fixture(neb_root, "stellar-loom", engine=">=22")
    raw_archive = neb_base_capture.archives["package"].read_bytes()
    neb_pid = "theme-forge-nebular-fusion"
    neb_repo = "Knowledge-Forge-AI/theme-forge-nebular-fusion"
    neb_version = "0.7.1"
    neb_tag = "v0.7.1"
    neb_commit = current_doc["products"][neb_pid]["commit"]

    api_dir = neb_base_capture.root / "api"
    (api_dir / "repository.json").write_bytes(
        canonical({"id": 1358643872, "full_name": neb_repo})
    )
    (api_dir / "ref.json").write_bytes(
        canonical({"ref": "refs/tags/" + neb_tag, "object": {"type": "commit", "sha": neb_commit}})
    )
    commit_doc = json.loads((api_dir / "commit.json").read_bytes())
    commit_doc["sha"] = neb_commit
    (api_dir / "commit.json").write_bytes(canonical(commit_doc))
    rel_doc = json.loads((api_dir / "release.json").read_bytes())
    rel_doc.update(id=429782340, tag_name=neb_tag, target_commitish=neb_commit)
    (api_dir / "release.json").write_bytes(canonical(rel_doc))

    neb_intent.update(
        project={"id": neb_pid, "repository": neb_repo},
        version=neb_version,
        tag=neb_tag,
    )
    neb_capture = _recapture_payloads(
        neb_base_capture,
        neb_intent,
        [
            (
                raw_archive + f"-{sys_name}".encode("utf-8"),
                [sys_name],
                {"tfnf": "package/bin/run.js"},
                {"tfnf": "package/bin/run.js"},
            )
            for sys_name in ("aarch64-darwin", "x86_64-linux", "aarch64-linux")
        ],
    )
    neb_intent["commands"] = [{"name": "tfnf", "interface": "gui"}]
    neb_intent["desktop"] = {"icon": {"path": "package.json"}}

    neb_row = copy.deepcopy(current_doc["products"][neb_pid])
    neb_row.update(
        version=neb_version,
        tag=neb_tag,
        commit=neb_commit,
        kind="materialized-desktop",
        commands=["tfnf"],
        assets={},
    )
    for payload in neb_capture.record["payloads"]:
        sys_name = payload["platforms"][0]
        asset = {key: payload[key] for key in ("name", "sha256", "size", "root")}
        asset.update(
            url="https://github.com/"
            + neb_repo
            + "/releases/download/"
            + neb_tag
            + "/"
            + payload["name"],
            executable_path=payload["commands"]["tfnf"]["path"],
            executable_sha256=payload["commands"]["tfnf"]["sha256"],
            launcher="bin/run.js",
        )
        neb_row["assets"][sys_name] = asset
    icon_bytes = neb_capture.source["package.json"]
    neb_row["icon"] = {
        "path": "package.json",
        "sha256": digest(icon_bytes),
        "size": len(icon_bytes),
        "url": "https://raw.githubusercontent.com/"
        + neb_repo
        + "/"
        + neb_commit
        + "/package.json",
    }
    current_doc["products"][neb_pid] = neb_row
    bind_catalog_product(neb_row, neb_capture, neb_intent, generation=CURRENT_GENERATION)
    captures.append((neb_capture, neb_intent, {}))

    (repo_dir / catalog_path(CURRENT_GENERATION)).write_bytes(canonical(current_doc))
    (repo_dir / catalog_path(HISTORICAL_GENERATION)).write_bytes(canonical(historical_doc))
    return repo_dir, captures, current_doc, historical_doc


class CurrentNixGraphicsRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmpdir = tempfile.TemporaryDirectory()
        cls.work_root = Path(cls._tmpdir.name).resolve()
        (
            cls.repo_dir,
            cls.captures,
            cls.current_catalog,
            cls.historical_catalog,
        ) = _build_synthetic_repository_and_captures(cls.work_root)
        cls.baseline_prepare_input = staticmethod(_load_baseline_prepare_input())

    @classmethod
    def tearDownClass(cls):
        cls._tmpdir.cleanup()

    def _run_prepare_input_pair(self, system: str, generation: str | None):
        scratch_actual = tempfile.mkdtemp(dir=self.work_root, prefix="prep-actual-")
        scratch_base = tempfile.mkdtemp(dir=self.work_root, prefix="prep-base-")
        base_ctx = {
            "system": system,
            "repository": self.repo_dir,
            "captures": self.captures,
            "client": Mock(),
        }
        if generation is not None:
            base_ctx["generation"] = generation
        ctx_actual = {**base_ctx, "scratch": Path(scratch_actual)}
        ctx_baseline = {**base_ctx, "scratch": Path(scratch_base)}

        with patch("rs9.hosted_nix.stage_payload"), patch(
            "rs9.hosted_nix._resolve_offline_npm_archives", return_value=[]
        ), patch("rs9.hosted_nix.stage_offline_npm_closure"):
            actual_source, actual_capture_dir, actual_products = hosted_nix.prepare_input(
                ctx_actual
            )
            _, base_capture_dir, base_products = self.baseline_prepare_input(ctx_baseline)
        return (
            actual_source,
            actual_capture_dir,
            actual_products,
            base_capture_dir,
            base_products,
        )

    def test_prepare_input_sets_source_generation_only_on_current_linux_nebular_and_preserves_bytes(
        self,
    ):
        cli_pids = (
            "theme-forge-stellar-burst",
            "theme-forge-stellar-loom",
            "theme-forge-solar-sail",
        )
        neb_pid = "theme-forge-nebular-fusion"

        lanes = [
            (CURRENT_GENERATION, "x86_64-linux", True),
            (CURRENT_GENERATION, "aarch64-linux", True),
            (CURRENT_GENERATION, "aarch64-darwin", False),
            (HISTORICAL_GENERATION, "x86_64-linux", False),
            (HISTORICAL_GENERATION, "aarch64-linux", False),
            (HISTORICAL_GENERATION, "aarch64-darwin", False),
            (None, "x86_64-linux", False),
            (None, "aarch64-linux", False),
            (None, "aarch64-darwin", False),
        ]
        for generation, system, eligible in lanes:
            with self.subTest(generation=generation, system=system):
                (
                    _,
                    actual_capture_dir,
                    actual_products,
                    base_capture_dir,
                    base_products,
                ) = self._run_prepare_input_pair(system, generation)
                actual_bytes = (actual_capture_dir / "products.json").read_bytes()
                base_bytes = (base_capture_dir / "products.json").read_bytes()

                for pid in cli_pids:
                    self.assertNotIn("source_generation", actual_products[pid])
                    self.assertEqual(
                        canonical(actual_products[pid]),
                        canonical(base_products[pid]),
                    )

                if not eligible:
                    self.assertNotIn("source_generation", actual_products[neb_pid])
                    self.assertEqual(actual_products, base_products)
                    self.assertEqual(actual_bytes, base_bytes)
                else:
                    self.assertEqual(
                        actual_products[neb_pid].get("source_generation"),
                        CURRENT_GENERATION,
                    )
                    self.assertNotEqual(actual_bytes, base_bytes)
                    stripped = copy.deepcopy(actual_products)
                    stripped[neb_pid].pop("source_generation")
                    self.assertEqual(stripped, base_products)
                    self.assertEqual(canonical(stripped), base_bytes)

    def test_prepare_input_refuses_unauthenticated_incomplete_and_mismatched_captures_before_discriminator(
        self,
    ):
        for system in ("x86_64-linux", "aarch64-linux"):
            for label, bad_captures in (
                ("empty", []),
                ("three-of-four", self.captures[:3]),
                ("duplicate-id-four", [self.captures[0]] * 4),
            ):
                scratch = Path(
                    tempfile.mkdtemp(dir=self.work_root, prefix=f"neg-{label}-")
                )
                with self.subTest(system=system, case=label), self.assertRaises(
                    ContractError
                ) as caught:
                    hosted_nix.prepare_input(
                        {
                            "generation": CURRENT_GENERATION,
                            "system": system,
                            "repository": self.repo_dir,
                            "scratch": scratch,
                            "captures": bad_captures,
                            "client": Mock(),
                        }
                    )
                self.assertEqual(caught.exception.code, "NIX_CAPTURE")
                self.assertFalse((scratch / "nix-capture/products.json").exists())

            # Unauthenticated or tampered capture must refuse in bind_catalog_product before staging.
            from rs9.release_core import ReleaseCapture

            unproven_real = [
                (
                    ReleaseCapture(
                        cap.record,
                        cap.archives,
                        cap.source,
                        cap.manifests,
                        cap.asset_metadata,
                        cap.evidence_bytes,
                        cap.root,
                    )
                    if intent["project"]["id"] == "theme-forge-nebular-fusion"
                    else cap,
                    intent,
                    profile,
                )
                for cap, intent, profile in self.captures
            ]
            tampered_record_real = []
            for cap, intent, profile in self.captures:
                if intent["project"]["id"] == "theme-forge-nebular-fusion":
                    tampered_cap = copy.copy(cap)
                    tampered_cap.record = {
                        **cap.record,
                        "tag": {**cap.record["tag"], "commit": "0" * 40},
                    }
                    tampered_record_real.append((tampered_cap, intent, profile))
                else:
                    tampered_record_real.append((cap, intent, profile))

            for unauth_label, unauth_captures, expected_code in (
                (
                    "unauthenticated-mock",
                    [(Mock(), intent, profile) for _, intent, profile in self.captures],
                    "RELEASE_CAPTURE",
                ),
                ("unproven-real-capture", unproven_real, "RELEASE_CAPTURE"),
                ("tampered-authenticated-record", tampered_record_real, "INPUT_CHANGED"),
            ):
                scratch_unauth = Path(
                    tempfile.mkdtemp(dir=self.work_root, prefix=f"neg-{unauth_label}-")
                )
                with self.subTest(system=system, case=unauth_label), self.assertRaises(
                    ContractError
                ) as caught:
                    hosted_nix.prepare_input(
                        {
                            "generation": CURRENT_GENERATION,
                            "system": system,
                            "repository": self.repo_dir,
                            "scratch": scratch_unauth,
                            "captures": unauth_captures,
                            "client": Mock(),
                        }
                    )
                self.assertEqual(caught.exception.code, expected_code)
                self.assertFalse((scratch_unauth / "nix-capture/products.json").exists())

            # Catalog and archive coordinate mismatches refuse before staging or discriminator.
            for field, bad_val in (
                ("version", "0.0.0-mismatch"),
                ("tag", "v0.0.0-mismatch"),
                ("commands", [{"name": "wrong", "interface": "gui"}]),
            ):
                mismatched = [
                    (
                        cap,
                        {**intent, field: bad_val}
                        if intent["project"]["id"] == "theme-forge-nebular-fusion"
                        else intent,
                        prof,
                    )
                    for cap, intent, prof in self.captures
                ]
                scratch_mis = Path(
                    tempfile.mkdtemp(dir=self.work_root, prefix=f"neg-mis-{field}-")
                )
                with self.subTest(system=system, mismatch=field), self.assertRaises(
                    ContractError
                ) as caught:
                    hosted_nix.prepare_input(
                        {
                            "generation": CURRENT_GENERATION,
                            "system": system,
                            "repository": self.repo_dir,
                            "scratch": scratch_mis,
                            "captures": mismatched,
                            "client": Mock(),
                        }
                    )
                self.assertEqual(caught.exception.code, "NIX_CATALOG_BINDING")
                self.assertFalse((scratch_mis / "nix-capture/products.json").exists())

            for cat_label, mutator in (
                (
                    "catalog-commit",
                    lambda neb: neb.update(commit="0" * 40),
                ),
                (
                    "catalog-asset-sha256",
                    lambda neb, s=system: neb["assets"][s].update(sha256="0" * 64),
                ),
                (
                    "catalog-executable-sha256",
                    lambda neb, s=system: neb["assets"][s].update(
                        executable_sha256="0" * 64
                    ),
                ),
                (
                    "catalog-icon-sha256",
                    lambda neb: neb["icon"].update(sha256="0" * 64),
                ),
            ):
                bad_repo = Path(
                    tempfile.mkdtemp(dir=self.work_root, prefix=f"repo-{cat_label}-")
                )
                shutil.copyfile(self.repo_dir / "flake.nix", bad_repo / "flake.nix")
                shutil.copytree(self.repo_dir / "nix", bad_repo / "nix")
                bad_cat = copy.deepcopy(self.current_catalog)
                mutator(bad_cat["products"]["theme-forge-nebular-fusion"])
                (bad_repo / catalog_path(CURRENT_GENERATION)).write_bytes(
                    canonical(bad_cat)
                )
                scratch_cat = Path(
                    tempfile.mkdtemp(dir=self.work_root, prefix=f"neg-{cat_label}-")
                )
                with self.subTest(system=system, mismatch=cat_label), self.assertRaises(
                    ContractError
                ) as caught:
                    hosted_nix.prepare_input(
                        {
                            "generation": CURRENT_GENERATION,
                            "system": system,
                            "repository": bad_repo,
                            "scratch": scratch_cat,
                            "captures": self.captures,
                            "client": Mock(),
                        }
                    )
                self.assertEqual(caught.exception.code, "NIX_CATALOG_BINDING")
                self.assertFalse((scratch_cat / "nix-capture/products.json").exists())

            # Tampered archive bytes on disk after ReleaseCapture authentication.
            tampered_arch_file = Path(
                tempfile.mkdtemp(dir=self.work_root, prefix="neg-arch-tamper-")
            ) / "tampered.tgz"
            tampered_arch_file.write_bytes(b"corrupted-post-auth-archive-bytes")
            tampered_arch_captures = []
            for cap, intent, profile in self.captures:
                if intent["project"]["id"] == "theme-forge-nebular-fusion":
                    t_cap = copy.copy(cap)
                    t_cap.archives = {
                        k: tampered_arch_file for k in cap.archives
                    }
                    tampered_arch_captures.append((t_cap, intent, profile))
                else:
                    tampered_arch_captures.append((cap, intent, profile))
            scratch_arch = Path(
                tempfile.mkdtemp(dir=self.work_root, prefix="neg-arch-bytes-")
            )
            with self.subTest(
                system=system, mismatch="tampered-archive-bytes"
            ), self.assertRaises(ContractError) as caught:
                hosted_nix.prepare_input(
                    {
                        "generation": CURRENT_GENERATION,
                        "system": system,
                        "repository": self.repo_dir,
                        "scratch": scratch_arch,
                        "captures": tampered_arch_captures,
                        "client": Mock(),
                    }
                )
            self.assertEqual(caught.exception.code, "NIX_CATALOG_BINDING")
            self.assertFalse((scratch_arch / "nix-capture/products.json").exists())

    def test_nebular_nix_dummy_store_predicate_positive_current_linux_only(self):
        _verified_nix_instantiate_cmd()
        baseline_recipe_bytes = _baseline_nebular_nix_bytes()
        candidate_recipe_bytes = (ROOT / "nix/nebular.nix").read_bytes()

        for system in ("x86_64-linux", "aarch64-linux"):
            with self.subTest(system=system):
                (
                    _,
                    actual_capture_dir,
                    actual_products,
                    _,
                    _,
                ) = self._run_prepare_input_pair(system, CURRENT_GENERATION)
                neb_product = actual_products["theme-forge-nebular-fusion"]

                eval_dir = Path(
                    tempfile.mkdtemp(dir=self.work_root, prefix=f"nix-pos-{system}-")
                )
                base_dir = eval_dir / "baseline"
                cand_dir = eval_dir / "candidate"
                base_dir.mkdir()
                cand_dir.mkdir()
                (base_dir / "nebular.nix").write_bytes(baseline_recipe_bytes)
                (cand_dir / "nebular.nix").write_bytes(candidate_recipe_bytes)
                for directory in (base_dir, cand_dir):
                    (
                        directory / "theme-forge-current-202610-products.json"
                    ).write_bytes(canonical(self.current_catalog))

                base_proc = _evaluate_nebular_recipe_dummy_store(
                    base_dir / "nebular.nix", system, neb_product, actual_capture_dir
                )
                cand_proc = _evaluate_nebular_recipe_dummy_store(
                    cand_dir / "nebular.nix", system, neb_product, actual_capture_dir
                )
                repeat_proc = _evaluate_nebular_recipe_dummy_store(
                    cand_dir / "nebular.nix", system, neb_product, actual_capture_dir
                )
                self.assertEqual(base_proc.returncode, 0, base_proc.stderr)
                self.assertEqual(cand_proc.returncode, 0, cand_proc.stderr)
                self.assertEqual(repeat_proc.returncode, 0, repeat_proc.stderr)

                base_out = json.loads(base_proc.stdout)
                cand_out = json.loads(cand_proc.stdout)
                repeat_out = json.loads(repeat_proc.stdout)

                self.assertEqual(
                    cand_out["evaluationKind"],
                    "stubbed-dummy-store-predicate-and-targetPkgs-only",
                )
                self.assertIs(cand_out["nativeQualificationClaimed"], False)
                self.assertEqual(base_out["targetPkgs"], EXPECTED_BASELINE_TARGET_PKGS)
                self.assertEqual(
                    cand_out["targetPkgs"],
                    EXPECTED_BASELINE_TARGET_PKGS + EXPECTED_GRAPHICS_ADDITIONS,
                )
                for forbidden_output in (
                    "mesa-25.2.6.default",
                    "mesa-25.2.6.opencl",
                    "mesa-25.2.6.spirv2dxil",
                    "mesa-25.2.6.cross_tools",
                    "mesa-25.2.6.debug",
                    "mesa-25.2.6.dev",
                    "libglvnd-1.7.0.default",
                    "libglvnd-1.7.0.dev",
                ):
                    self.assertNotIn(forbidden_output, cand_out["targetPkgs"])

                self.assertIs(cand_out["includeClosures"], False)
                self.assertEqual(cand_out["fhsExtraArgs"], [])
                self.assertEqual(cand_out["runtimeFacts"], base_out["runtimeFacts"])
                self.assertTrue(cand_out["drvPath"].startswith("/nix/store/"))
                self.assertTrue(cand_out["drvPath"].endswith(".drv"))
                self.assertTrue(cand_out["runtimeDrvPath"].startswith("/nix/store/"))
                self.assertTrue(cand_out["runtimeDrvPath"].endswith(".drv"))
                self.assertNotEqual(cand_out["drvPath"], base_out["drvPath"])
                self.assertNotEqual(
                    cand_out["runtimeDrvPath"], base_out["runtimeDrvPath"]
                )
                self.assertEqual(cand_out["drvPath"], repeat_out["drvPath"])
                self.assertEqual(
                    cand_out["runtimeDrvPath"], repeat_out["runtimeDrvPath"]
                )

                # Control checks: when positive guards pass, missing catalog or missing archive MUST fail,
                # proving the positive path actually reads the catalog and hashes the archive.
                ctrl_dir = Path(
                    tempfile.mkdtemp(dir=self.work_root, prefix=f"nix-ctrl-{system}-")
                )
                (ctrl_dir / "nebular.nix").write_bytes(candidate_recipe_bytes)
                missing_cat_proc = _evaluate_nebular_recipe_dummy_store(
                    ctrl_dir / "nebular.nix", system, neb_product, actual_capture_dir
                )
                self.assertNotEqual(missing_cat_proc.returncode, 0)

                (ctrl_dir / "theme-forge-current-202610-products.json").write_bytes(
                    canonical(self.current_catalog)
                )
                missing_arch_capture = Path(
                    tempfile.mkdtemp(dir=self.work_root, prefix=f"cap-no-arch-pos-{system}-")
                )
                missing_arch_proc = _evaluate_nebular_recipe_dummy_store(
                    ctrl_dir / "nebular.nix", system, neb_product, missing_arch_capture
                )
                self.assertNotEqual(missing_arch_proc.returncode, 0)

    def test_nebular_nix_dummy_store_negative_and_ineligible_matrix_matches_baseline_and_short_circuits(
        self,
    ):
        _verified_nix_instantiate_cmd()
        baseline_recipe_bytes = _baseline_nebular_nix_bytes()
        candidate_recipe_bytes = (ROOT / "nix/nebular.nix").read_bytes()

        # Part 1: Historical/default Linux and current/historical Darwin from actual prepare_input,
        # evaluated with BOTH catalog and archive absent to prove early short-circuiting.
        for generation, system, inject_darwin_discriminator in (
            (HISTORICAL_GENERATION, "x86_64-linux", False),
            (HISTORICAL_GENERATION, "aarch64-linux", False),
            (HISTORICAL_GENERATION, "aarch64-darwin", False),
            (None, "x86_64-linux", False),
            (None, "aarch64-linux", False),
            (CURRENT_GENERATION, "aarch64-darwin", False),
            (CURRENT_GENERATION, "aarch64-darwin", True),
        ):
            with self.subTest(
                generation=generation,
                system=system,
                inject_darwin_discriminator=inject_darwin_discriminator,
            ):
                (
                    _,
                    actual_capture_dir,
                    actual_products,
                    _,
                    _,
                ) = self._run_prepare_input_pair(system, generation)
                neb_product = copy.deepcopy(
                    actual_products["theme-forge-nebular-fusion"]
                )
                if inject_darwin_discriminator:
                    neb_product["source_generation"] = CURRENT_GENERATION

                archive_file = (
                    actual_capture_dir
                    / "payloads/theme-forge-nebular-fusion/payload.tar.gz"
                )
                archive_file.unlink()
                self.assertFalse(archive_file.exists())

                eval_dir = Path(
                    tempfile.mkdtemp(dir=self.work_root, prefix="nix-inel-")
                )
                base_dir = eval_dir / "baseline"
                cand_dir = eval_dir / "candidate"
                base_dir.mkdir()
                cand_dir.mkdir()
                (base_dir / "nebular.nix").write_bytes(baseline_recipe_bytes)
                (cand_dir / "nebular.nix").write_bytes(candidate_recipe_bytes)
                # Deliberately do NOT write theme-forge-current-202610-products.json!
                self.assertFalse(
                    (cand_dir / "theme-forge-current-202610-products.json").exists()
                )

                base_proc = _evaluate_nebular_recipe_dummy_store(
                    base_dir / "nebular.nix", system, neb_product, actual_capture_dir
                )
                cand_proc = _evaluate_nebular_recipe_dummy_store(
                    cand_dir / "nebular.nix", system, neb_product, actual_capture_dir
                )
                self.assertEqual(base_proc.returncode, 0, base_proc.stderr)
                self.assertEqual(cand_proc.returncode, 0, cand_proc.stderr)
                base_out = json.loads(base_proc.stdout)
                cand_out = json.loads(cand_proc.stdout)
                self.assertEqual(cand_out["targetPkgs"], EXPECTED_BASELINE_TARGET_PKGS)
                self.assertEqual(cand_out, base_out)

        # Part 2: Coordinate, catalog, and archive digest negative matrix on both Linux systems.
        for system in ("x86_64-linux", "aarch64-linux"):
            (
                _,
                pos_capture_dir,
                pos_products,
                _,
                _,
            ) = self._run_prepare_input_pair(system, CURRENT_GENERATION)
            valid_product = copy.deepcopy(pos_products["theme-forge-nebular-fusion"])
            valid_product["source_generation"] = CURRENT_GENERATION

            ctrl_dir = Path(
                tempfile.mkdtemp(dir=self.work_root, prefix=f"nix-ctrl-{system}-")
            )
            (ctrl_dir / "nebular.nix").write_bytes(candidate_recipe_bytes)
            (ctrl_dir / "theme-forge-current-202610-products.json").write_bytes(
                canonical(self.current_catalog)
            )
            missing_arch_capture = Path(
                tempfile.mkdtemp(dir=self.work_root, prefix=f"cap-no-arch-{system}-")
            )

            # Unauthenticated or non-desktop product fails top-level recipe assertion.
            for bad_product in (
                {**valid_product, "authenticated": False},
                {**valid_product, "kind": "node-cli"},
            ):
                bad_proc = _evaluate_nebular_recipe_dummy_store(
                    ctrl_dir / "nebular.nix", system, bad_product, pos_capture_dir
                )
                self.assertNotEqual(bad_proc.returncode, 0)

            # Short-circuiting negative cases where archive is missing on disk and must NOT be read.
            no_gen_product = copy.deepcopy(valid_product)
            no_gen_product.pop("source_generation", None)
            no_commit_product = copy.deepcopy(valid_product)
            no_commit_product.pop("commit", None)
            no_asset_sha_product = copy.deepcopy(valid_product)
            no_asset_sha_product.pop("asset_sha256", None)

            catalog_missing_system_asset = copy.deepcopy(self.current_catalog)
            catalog_missing_system_asset["products"]["theme-forge-nebular-fusion"][
                "assets"
            ].pop(system, None)
            catalog_missing_product = copy.deepcopy(self.current_catalog)
            catalog_missing_product["products"].pop("theme-forge-nebular-fusion", None)

            short_circuit_cases = [
                ("missing-source-generation", no_gen_product, None),
                (
                    "wrong-source-generation-historical",
                    {**valid_product, "source_generation": HISTORICAL_GENERATION},
                    self.current_catalog,
                ),
                (
                    "wrong-source-generation-null",
                    {**valid_product, "source_generation": None},
                    self.current_catalog,
                ),
                (
                    "missing-system-asset-in-catalog",
                    valid_product,
                    catalog_missing_system_asset,
                ),
                (
                    "missing-product-in-catalog",
                    valid_product,
                    catalog_missing_product,
                ),
                (
                    "wrong-version",
                    {**valid_product, "version": "0.6.1"},
                    self.current_catalog,
                ),
                ("missing-commit", no_commit_product, self.current_catalog),
                (
                    "wrong-commit",
                    {
                        **valid_product,
                        "commit": "49e2c4919b6b4ec9bd4ed5d7e7ced90921e00f5e",
                    },
                    self.current_catalog,
                ),
                (
                    "missing-declared-asset-sha",
                    no_asset_sha_product,
                    self.current_catalog,
                ),
                (
                    "wrong-declared-asset-sha",
                    {**valid_product, "asset_sha256": "0" * 64},
                    self.current_catalog,
                ),
            ]
            for label, case_product, case_catalog in short_circuit_cases:
                with self.subTest(system=system, negative_case=label):
                    case_dir = Path(
                        tempfile.mkdtemp(
                            dir=self.work_root, prefix=f"nix-neg-{label}-"
                        )
                    )
                    base_dir = case_dir / "baseline"
                    cand_dir = case_dir / "candidate"
                    base_dir.mkdir()
                    cand_dir.mkdir()
                    (base_dir / "nebular.nix").write_bytes(baseline_recipe_bytes)
                    (cand_dir / "nebular.nix").write_bytes(candidate_recipe_bytes)
                    if case_catalog is not None:
                        for directory in (base_dir, cand_dir):
                            (
                                directory / "theme-forge-current-202610-products.json"
                            ).write_bytes(canonical(case_catalog))

                    base_proc = _evaluate_nebular_recipe_dummy_store(
                        base_dir / "nebular.nix",
                        system,
                        case_product,
                        missing_arch_capture,
                    )
                    cand_proc = _evaluate_nebular_recipe_dummy_store(
                        cand_dir / "nebular.nix",
                        system,
                        case_product,
                        missing_arch_capture,
                    )
                    self.assertEqual(base_proc.returncode, 0, base_proc.stderr)
                    self.assertEqual(cand_proc.returncode, 0, cand_proc.stderr)
                    base_out = json.loads(base_proc.stdout)
                    cand_out = json.loads(cand_proc.stdout)
                    self.assertEqual(
                        cand_out["targetPkgs"], EXPECTED_BASELINE_TARGET_PKGS
                    )
                    self.assertEqual(cand_out, base_out)

            # Archive content SHA mismatch when all earlier guards pass.
            with self.subTest(system=system, negative_case="wrong-archive-content-sha"):
                tampered_capture = Path(
                    tempfile.mkdtemp(dir=self.work_root, prefix=f"cap-tampered-{system}-")
                )
                tampered_pay = (
                    tampered_capture / "payloads/theme-forge-nebular-fusion"
                )
                tampered_pay.mkdir(parents=True)
                (tampered_pay / "payload.tar.gz").write_bytes(
                    b"tampered-archive-bytes-mismatching-catalog-sha256"
                )

                case_dir = Path(
                    tempfile.mkdtemp(dir=self.work_root, prefix="nix-neg-archsha-")
                )
                base_dir = case_dir / "baseline"
                cand_dir = case_dir / "candidate"
                base_dir.mkdir()
                cand_dir.mkdir()
                (base_dir / "nebular.nix").write_bytes(baseline_recipe_bytes)
                (cand_dir / "nebular.nix").write_bytes(candidate_recipe_bytes)
                for directory in (base_dir, cand_dir):
                    (
                        directory / "theme-forge-current-202610-products.json"
                    ).write_bytes(canonical(self.current_catalog))

                base_proc = _evaluate_nebular_recipe_dummy_store(
                    base_dir / "nebular.nix", system, valid_product, tampered_capture
                )
                cand_proc = _evaluate_nebular_recipe_dummy_store(
                    cand_dir / "nebular.nix", system, valid_product, tampered_capture
                )
                self.assertEqual(base_proc.returncode, 0, base_proc.stderr)
                self.assertEqual(cand_proc.returncode, 0, cand_proc.stderr)
                base_out = json.loads(base_proc.stdout)
                cand_out = json.loads(cand_proc.stdout)
                self.assertEqual(
                    cand_out["targetPkgs"], EXPECTED_BASELINE_TARGET_PKGS
                )
                self.assertEqual(cand_out, base_out)

    def test_policy_document_and_preserved_source_invariants(self):
        policy_path = (
            ROOT / "docs/evaluations/current-nix-graphics-runtime-policy.md"
        )
        self.assertTrue(policy_path.is_file())
        self.assertFalse(policy_path.is_symlink())
        text = bounded_text(policy_path.read_bytes())
        scan_text(text)

        for required_token in (
            "OWNER-APPROVED-SOURCE-POLICY",
            "Mesa 25.2.6",
            "pkgs.mesa.out",
            "libglvnd 1.7.0",
            "pkgs.libglvnd.out",
            "0921fdb3e13e40fe25fbc52b89661a9d6d32ac68",
            "theme-forge-current-202610",
            "41358481637",
            "f710c3879b08b22bed5a71bbfa6c049c69cb5efd",
            "not-qualified",
            "nativeCauseProven=false",
            "PlatformDisplayDefault::create()",
            "2.52.4",
            "2.54.0",
            "Xvfb",
            "includeClosures",
            "source_generation",
            "builtins.hashFile",
            "sha256-erfvNR1Yor3k8gVVClyiBJsgyaOv7BMFd1NSgieTY5I=",
            "sha256-2U9JtpGyP4lbxtVJeP5GUgh5XthloPvFIw28+nldYx8=",
            "rpm-lint-policy-exceptions-not-raw-clean-not-fedora-qualified",
            "correctiveRetryOrDuplicateAuthorized=false",
        ):
            self.assertIn(required_token, text)

        pins_text = (ROOT / "nix/pins.nix").read_text()
        self.assertIn(
            'nixpkgs_revision = "0921fdb3e13e40fe25fbc52b89661a9d6d32ac68";',
            pins_text,
        )
        self.assertIn('installer_version = "2.31.2";', pins_text)

        # Verify reversible fragment structure and AST delta isolation to prepare_input
        # without brittle whole-file SHA-256 pins on nix/nebular.nix or src/rs9/hosted_nix.py.
        nebular_text = (ROOT / "nix/nebular.nix").read_text()
        self.assertEqual(nebular_text.count(NEBULAR_NIX_ADDED_BLOCK), 1)
        self.assertEqual(
            nebular_text.count(NEBULAR_NIX_PATCHED_TARGET_PKGS_LINE), 1
        )
        base_nebular_text = _baseline_nebular_nix_bytes().decode("utf-8")
        self.assertNotIn("currentLinuxGraphics", base_nebular_text)
        self.assertNotIn("currentGraphicsPackages", base_nebular_text)
        self.assertEqual(
            base_nebular_text.count(NEBULAR_NIX_BASELINE_TARGET_PKGS_LINE), 1
        )

        hosted_text = (ROOT / "src/rs9/hosted_nix.py").read_text()
        self.assertEqual(hosted_text.count(HOSTED_NIX_ADDED_BLOCK), 1)
        base_hosted_text = _baseline_hosted_nix_py_bytes().decode("utf-8")
        self.assertNotIn('row["source_generation"]', base_hosted_text)

        base_tree = ast.parse(base_hosted_text)
        cand_tree = ast.parse(hosted_text)
        base_funcs = {
            node.name: ast.dump(node)
            for node in base_tree.body
            if isinstance(node, ast.FunctionDef)
        }
        cand_funcs = {
            node.name: ast.dump(node)
            for node in cand_tree.body
            if isinstance(node, ast.FunctionDef)
        }
        self.assertEqual(set(base_funcs), set(cand_funcs))
        for name in base_funcs:
            if name != "prepare_input":
                self.assertEqual(cand_funcs[name], base_funcs[name], name)
        self.assertNotEqual(cand_funcs["prepare_input"], base_funcs["prepare_input"])

        # Verify Nix-less CI unit runner skips cleanly when pinned evaluator is absent,
        # while tampered present binary still fails closed with AssertionError.
        absent_bin = self.work_root / "absent-nix-store-bin/nix"
        absent_inst = absent_bin.with_name("nix-instantiate")
        with patch.multiple(
            __name__,
            PINNED_NIX_BINARY=absent_bin,
            PINNED_NIX_INSTANTIATE=absent_inst,
        ), self.assertRaises(unittest.SkipTest):
            _verified_nix_instantiate_cmd()

        tampered_dir = Path(
            tempfile.mkdtemp(dir=self.work_root, prefix="tampered-nix-bin-")
        )
        tampered_bin = tampered_dir / "nix"
        tampered_bin.write_bytes(b"wrong-nix-binary-bytes")
        tampered_inst = tampered_dir / "nix-instantiate"
        tampered_inst.symlink_to(tampered_bin)
        with patch.multiple(
            __name__,
            PINNED_NIX_BINARY=tampered_bin,
            PINNED_NIX_INSTANTIATE=tampered_inst,
        ), self.assertRaises(AssertionError):
            _verified_nix_instantiate_cmd()


if __name__ == "__main__":
    unittest.main()
