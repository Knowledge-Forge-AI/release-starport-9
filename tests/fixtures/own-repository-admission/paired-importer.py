"""Current-only unsigned import and APT indexing. No signing/deployment API."""
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re

from rs9.errors import ContractError
from rs9.hosted_custody import source_tree_identity
from rs9.qualified_distribution_inputs import SourceBoundConfiguration, qualified_theme_forge_packages_inputs
from rs9.repo_apt import AptRepositoryCandidate, parse_deb_control, validate_apt_repository
from rs9.scratch import canonical, physical_directory

VERSIONS = {"theme-forge-stellar-burst": "0.7.0", "theme-forge-stellar-loom": "0.5.0",
            "theme-forge-solar-sail": "0.3.0", "theme-forge-nebular-fusion": "0.7.0"}
KEY_SHA256 = "6931a99cf38e204c0adc75dd868f8c0e79d68e58e2644f575d4be1da2ea18d95"
SOURCE_FILES = frozenset({"release-lock.json", "flake.nix", "flake.lock", "package-matrix.json",
    "keys/knowledge-forge-ai-packages.asc", ".github/workflows/publish.yml",
    "tools/verification/generate-publication-provenance.mjs",
    "tools/verification/verify-publication-provenance.mjs",
    "tools/verification/current_import_routing.py", "tools/verification/current-rs9-inputs.json"})
SYSTEMS = {"deb": {"amd64", "arm64"}, "rpm": {"x86_64-linux", "aarch64-linux"},
           "pacman": {"x86_64-linux"}}
MODULE_ENTRY = "tools/verification/current_import_routing.py"
ARCH_SYSTEM = {"deb": {"amd64": "amd64", "arm64": "arm64"},
               "rpm": {"x86_64": "x86_64-linux", "aarch64": "aarch64-linux"},
               "pacman": {"x86_64": "x86_64-linux"}}
MAX_PACKAGE = 512 * 1024 * 1024


def fail(message):
    raise ContractError("CURRENT_IMPORT_ROUTING", message)


def _stable(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_mode


def held_bytes(path, maximum=MAX_PACKAGE):
    path = Path(path)
    if any(p.is_symlink() for p in (path, *path.parents)):
        fail("Aliased input forbidden")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        import stat
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
            fail("Bounded regular input required")
        data = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    if len(data) != before.st_size or len(data) > maximum or _stable(before) != _stable(after) or _stable(path.stat()) != _stable(after) or any(p.is_symlink() for p in (path, *path.parents)):
        fail("Input changed during read")
    return data


def sha(data):
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class ProductionSource:
    root: Path
    commit: str
    tree: str
    files: dict

    def verify(self):
        root = physical_directory(self.root)
        if any(not re.fullmatch(r"[0-9a-f]{40}", x or "") for x in (self.commit, self.tree)):
            fail("Exact P source coordinates required")
        if set(self.files) != SOURCE_FILES or any(not re.fullmatch(r"[0-9a-f]{64}", h or "") for h in self.files.values()):
            fail("Source-owned P file inventory required")
        if source_tree_identity(root, self.commit) != self.tree:
            fail("P source tree differs")
        bodies = {}
        for name, expected in self.files.items():
            from rs9.security import validate_safe_relative_posix_path
            validate_safe_relative_posix_path(name)
            data = held_bytes(root / name, 2 * 1024 * 1024)
            if sha(data) != expected:
                fail("P source file differs")
            bodies[name] = data
        if sha(held_bytes(Path(__file__), 2 * 1024 * 1024)) != self.files[MODULE_ENTRY]:
            fail("Executing routing module differs from P inventory")
        lock = json.loads(bodies["release-lock.json"])
        if {p: v.get("version") for p, v in lock.get("products", {}).items()} != VERSIONS:
            fail("P lock is not the exact current four")
        if sha(bodies["keys/knowledge-forge-ai-packages.asc"]) != KEY_SHA256:
            fail("P public key continuity differs")
        return {"repository": "Knowledge-Forge-AI/theme-forge-packages", "commit": self.commit,
                "tree": self.tree, "files": self.files, "inventory_sha256": sha(canonical(self.files))}


def _plan_inputs(inventory, collection):
    """Physical routing only; caller must obtain inventory freshly from facade."""
    plan, names, coverage, independent, architectures = [], {}, {f: {p: set() for p in VERSIONS} for f in SYSTEMS}, {}, {}
    for row in inventory["binaries"]:
        family, product, name = row["family"], row["product"], row["name"]
        if family not in SYSTEMS or product not in VERSIONS or row["version"] != VERSIONS[product] or Path(name).name != name:
            fail("Unexpected binary identity")
        separator = "_" if family == "deb" else "-"
        if not name.startswith(product + separator + VERSIONS[product] + "-"):
            fail("Binary basename version differs")
        prior = names.setdefault(name, (family, row["sha256"], row["size"]))
        if prior != (family, row["sha256"], row["size"]):
            fail("Same basename differs")
        if any(item[0]["family"] == family and item[0]["name"] == name for item in plan):
            fail("Duplicate binary row")
        bodies = []
        for origin in row["origins"]:
            if origin["system"] not in SYSTEMS[family]:
                fail("Unsupported native system")
            from rs9.security import validate_safe_relative_posix_path
            for field in ("artifact", "path"):
                validate_safe_relative_posix_path(origin[field])
            body = held_bytes(collection / origin["artifact"] / origin["path"])
            if len(body) != row["size"] or sha(body) != row["sha256"]:
                fail("Original unsigned package changed")
            bodies.append(body)
            coverage[family][product].add(origin["system"])
        if not bodies or any(body != bodies[0] for body in bodies):
            fail("Duplicate origins differ")
        arch = row["architecture"]
        allowed = {"deb": {"all", "amd64", "arm64"}, "rpm": {"noarch", "x86_64", "aarch64"}, "pacman": {"any", "x86_64"}}
        if architectures.setdefault((family, product, arch), name) != name:
            fail("Same product architecture has differing package versions/revisions")
        if arch not in allowed[family]:
            fail("Unsupported package architecture")
        origins = [origin["system"] for origin in row["origins"]]
        is_independent = arch in {"all", "any", "noarch"}
        expected_systems = SYSTEMS[family] if is_independent else {ARCH_SYSTEM[family][arch]}
        if set(origins) != expected_systems or len(origins) != len(expected_systems):
            fail("Package architecture disagrees with exact origin systems")
        product_architectures = {a for f, p, a in architectures if (f, p) == (family, product)}
        if product_architectures & {"all", "any", "noarch"} and product_architectures - {"all", "any", "noarch"}:
            fail("Independent and specific packages cannot mix")
        if is_independent:
            identity = (name, row["sha256"], row["size"])
            if independent.setdefault((family, product), identity) != identity:
                fail("Architecture-independent package differs")
        if family == "deb":
            control = parse_deb_control(bodies[0])
            if (control["Package"], control["Version"], control["Architecture"]) != (product, name.split("_")[1], arch):
                fail("DEB control disagrees with routing identity")
        destinations = ([f"unsigned/rpm/{destination_arch}/{name}" for destination_arch in (sorted(ARCH_SYSTEM[family]) if is_independent else [arch])]
                        if family == "rpm" else [f"unsigned/{family}/{name}"])
        plan.append((row, bodies[0], destinations))
    if any(systems != SYSTEMS[family] for family, products in coverage.items() for systems in products.values()):
        fail("All four products and native systems required")
    return plan


def _write_unsigned(plan, stage, release_date):
    apt = AptRepositoryCandidate(stage / "apt", distribution="resolute",
                                 origin="Knowledge Forge AI", label="Knowledge Forge AI")
    objects = []
    for row, data, destinations in plan:
        for relative in destinations:
            target = stage / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("xb") as stream:
                stream.write(data)
            if sha(held_bytes(target)) != row["sha256"]:
                fail("Staged unsigned bytes differ")
        if row["family"] == "deb":
            package = apt.add_package(deb_bytes=data)
            if package.sha256 != row["sha256"]:
                fail("APT pool changed DEB bytes")
        objects.append({**row, "destinations": destinations})
    indices = apt.build_indices(release_date=release_date)
    validate_apt_repository(stage / "apt", "resolute")
    return objects, {k: v for k, v in indices.items() if k != "release_bytes"}


def prepare_unsigned(config, production, collection, stage, *, release_date, zip_transport="actions", timeout=7200):
    """Fresh original-run admission precedes selection; no saved-result input."""
    if type(config) is not SourceBoundConfiguration or type(production) is not ProductionSource:
        fail("Explicit source-bound RS9 and P configurations required")
    collection, stage = physical_directory(collection), physical_directory(stage)
    if any(collection.iterdir()) or any(stage.iterdir()) or collection == stage or collection in stage.parents or stage in collection.parents:
        fail("Distinct empty collection and stage roots required")
    try:
        source_roots = (physical_directory(production.root), physical_directory(config.repository))
    except (TypeError, ValueError, OSError) as error:
        fail("Physical source directories required")
    if any(target == root or root in target.parents for target in (stage, collection)
           for root in source_roots):
        fail("Staging cannot mutate either source checkout")
    p_source = production.verify()
    inventory = qualified_theme_forge_packages_inputs(config, collection, consumer_repository=production.root,
        consumer_commit=production.commit, consumer_tree=production.tree, zip_transport=zip_transport, timeout=timeout)
    if production.verify() != p_source:
        fail("P source changed during original-run admission")
    plan = _plan_inputs(inventory, collection)
    objects, apt_indices = _write_unsigned(plan, stage, release_date)
    if production.verify() != p_source:
        fail("P source changed during unsigned routing")
    original = {key: inventory[key] for key in config.expected()}
    result = {"schema": "theme-forge.current-unsigned-routing.v1", "p_source": p_source, "rs9_original": original,
              "own_repository_admission": inventory["own_repository_admission"],
              "objects": objects, "apt_indices": apt_indices, "signed": False, "assembly_ready": False,
              "production_enabled": False, "publication_authority": False,
              "pending": ["Gate3-P-native-three", "APT4-real-GPG-and-SignedStore", "RPM-signature-preservation",
                          "protected-signing", "production-client-checks", "signed-assembly-and-provenance"]}
    with (stage / "unsigned-routing.json").open("xb") as stream:
        stream.write(canonical(result))
    return result
