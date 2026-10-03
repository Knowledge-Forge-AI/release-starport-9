"""Tests for .rs9 contract validation, normalization, and security rules."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
import tempfile
import unittest

from rs9.contract import (
    ContractError,
    load_destinations,
    load_project,
    normalize,
)


def _create_minimal_project(
    root: Path,
    *,
    license_expr: str = "MIT",
    asset_platforms: list[str] | None = None,
    tag_template: str = "v{version}",
    extra_files: dict[str, str] | None = None,
) -> Path:
    rs9_dir = root / ".rs9"
    rs9_dir.mkdir(parents=True, exist_ok=True)

    plats = asset_platforms or ["x86_64-linux", "aarch64-linux"]
    plats_str = json.dumps(plats)

    proj_content = f"""schema = "rs9.project.v1alpha1"

[project]
id = "my-app"
name = "My Application"
repository = "example-org/my-app"

[license]
expression = "{license_expr}"
files = ["LICENSE"]
source = "tagged-repository"

[[commands]]
name = "my-cli"
interface = "cli"

[[checks]]
id = "version-check"
argv = ["my-cli", "--version"]
expect-exit = 0
expect-stdout-contains = "my-cli {{version}}"
requires-display = false
"""
    (rs9_dir / "project.toml").write_text(proj_content, encoding="utf-8")

    releases_content = f"""schema = "rs9.releases.v1alpha1"

[release]
tag = "{tag_template}"
prerelease = "reject"

[[assets]]
id = "app-bin"
name = "my-app-{{version}}-dist.tar.gz"
format = "tar.gz"
platforms = {plats_str}

[assets.commands]
my-cli = "bin/my-cli"
"""
    (rs9_dir / "releases.toml").write_text(releases_content, encoding="utf-8")

    if extra_files:
        for fname, fcontent in extra_files.items():
            (rs9_dir / fname).write_text(fcontent, encoding="utf-8")

    return root


def _create_destinations(root: Path, content: str | None = None) -> Path:
    dest_path = root / "destinations.toml"
    if content is None:
        content = """schema = "rs9.destinations.v1alpha1"

[[destinations]]
id = "hosted-pacman"
adapter = "pacman"
mode = "direct"
platforms = ["x86_64-linux", "aarch64-linux"]
status = "live"
base-url = "https://pkg.example.com/pacman"
repository = "example-org/pacman-repo"
"""
    dest_path.write_text(content, encoding="utf-8")
    return dest_path


class ContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.tmp_path = Path(self.temp.name)

    def test_explicit_evidence_amendment_and_version_template(self):
        _create_minimal_project(self.tmp_path)
        path = self.tmp_path / ".rs9/releases.toml"
        original = path.read_text()
        policy = '''
[evidence]
profile = "npm-package-archive.v1alpha1"
checksums = "SHA256SUMS"
assets = [{role="notice", name="NOTICE"}, {role="provenance", name="PROVENANCE-{version}.json"}]
'''
        path.write_text(original + policy)
        destination = _create_destinations(self.tmp_path)
        result = json.loads(normalize(self.tmp_path, destination, "1.2.3"))
        self.assertEqual(result["release"]["evidence"]["assets"][1]["name"], "PROVENANCE-1.2.3.json")
        for before, after in (("npm-package-archive.v1alpha1", "arbitrary-hook"),
                              ('role="notice"', 'role="unknown"'),
                              ('name="NOTICE"', 'name="../NOTICE"'),
                              ("{version}", "{commit}")):
            path.write_text(original + policy.replace(before, after))
            with self.assertRaises(ContractError):
                load_project(self.tmp_path)

    def test_valid_minimal_project_and_destinations(self) -> None:
        tmp_path = self.tmp_path
        pacman_toml = """schema = "rs9.pacman.v1alpha1"

    [[packages]]
    id = "my-app-pkg"
    name = "my-app"
    assets = ["app-bin"]

    [[publish]]
    package = "my-app-pkg"
    destination = "hosted-pacman"
    """
        _create_minimal_project(tmp_path, extra_files={"pacman.toml": pacman_toml})
        dest_path = _create_destinations(tmp_path)

        proj_map = load_project(tmp_path)
        assert "project.toml" in proj_map
        assert "releases.toml" in proj_map
        assert "pacman.toml" in proj_map

        dest_doc = load_destinations(dest_path)
        assert dest_doc["schema"] == "rs9.destinations.v1alpha1"

        out_bytes = normalize(tmp_path, dest_path, "1.2.3")
        doc = json.loads(out_bytes.decode("utf-8"))

        assert doc["schema"] == "rs9.normalized-tenant.v1alpha1"
        assert doc["project"]["id"] == "my-app"
        assert doc["license"]["expression"] == "MIT"
        assert doc["license"]["source"] == "tagged-repository"
        assert doc["version"] == "1.2.3"
        assert doc["tag"] == "v1.2.3"
        assert doc["release"]["version"] == "1.2.3"
        assert doc["release"]["tag"] == "v1.2.3"
        assert len(doc["assets"]) == 1
        assert doc["assets"][0]["name"] == "my-app-1.2.3-dist.tar.gz"
        assert len(doc["targets"]) == 1
        target = doc["targets"][0]
        assert target["adapter"] == "pacman"
        assert target["destination"] == "hosted-pacman"
        assert target["mode"] == "direct"
        assert target["name"] == "my-app"
        assert target["package"] == "my-app-pkg"
        assert target["effective-platforms"] == ["aarch64-linux", "x86_64-linux"]
        assert target["ecosystem-architectures"] == ["aarch64", "x86_64"]

        assert "evidence" in doc
        inputs = doc["evidence"]["inputs"]
        filenames = [item["filename"] for item in inputs]
        assert filenames == sorted(filenames)
        assert "project.toml" in filenames
        assert "releases.toml" in filenames
        assert "pacman.toml" in filenames
        assert "destinations.toml" in filenames


    def test_license_mit_preserved_and_spdx_syntax(self) -> None:
        tmp_path = self.tmp_path
        # 1. Complex valid SPDX expression
        complex_spdx = "(MIT OR Apache-2.0) AND LicenseRef-Custom"
        _create_minimal_project(tmp_path, license_expr=complex_spdx)
        dest_path = _create_destinations(tmp_path)

        out_bytes = normalize(tmp_path, dest_path, "1.0.0")
        doc = json.loads(out_bytes.decode("utf-8"))
        assert doc["license"]["expression"] == complex_spdx

        # Syntax screening preserves an unresolved tenant expression verbatim.
        provisional_license = "AGPL-3.0-or-later OR Commercial"
        provisional = tmp_path / "provisional-license"
        _create_minimal_project(provisional, license_expr=provisional_license)
        self.assertEqual(json.loads(normalize(provisional, dest_path, "1.0.0"))["license"]["expression"], provisional_license)

        # 2. Non-NFC license expression rejected
        non_nfc_expr = "MIT AND \u0041\u030a"  # A + combining ring above != Å
        p_non_nfc = tmp_path / "proj_non_nfc"
        _create_minimal_project(p_non_nfc, license_expr=non_nfc_expr)
        with self.assertRaises(ContractError) as exc_info:
            load_project(p_non_nfc)
        assert exc_info.exception.code == "NON_NFC_LICENSE_EXPRESSION"

        # 3. Syntax error in SPDX expression
        p_bad = tmp_path / "proj_bad_spdx"
        _create_minimal_project(p_bad, license_expr="MIT OR")
        with self.assertRaises(ContractError) as exc_info2:
            load_project(p_bad)
        assert exc_info2.exception.code == "INVALID_SPDX_EXPRESSION"


    def test_determinism_same_bytes(self) -> None:
        tmp_path = self.tmp_path
        _create_minimal_project(tmp_path)
        dest_path = _create_destinations(tmp_path)

        out1 = normalize(tmp_path, dest_path, "2.0.0")
        out2 = normalize(tmp_path, dest_path, "2.0.0")
        assert out1 == out2
        assert out1.endswith(b"\n")


    def test_reorder_semantics_vs_evidence_difference(self) -> None:
        tmp_path = self.tmp_path
        p1 = tmp_path / "p1"
        p2 = tmp_path / "p2"
        _create_minimal_project(p1)
        _create_minimal_project(p2)
        dest_path = _create_destinations(tmp_path)

        # In p2, reorder keys in project.toml
        reordered_toml = """schema = "rs9.project.v1alpha1"

    [license]
    source = "tagged-repository"
    files = ["LICENSE"]
    expression = "MIT"

    [project]
    repository = "example-org/my-app"
    name = "My Application"
    id = "my-app"

    [[commands]]
    interface = "cli"
    name = "my-cli"

    [[checks]]
    requires-display = false
    expect-stdout-contains = "my-cli {version}"
    id = "version-check"
    argv = ["my-cli", "--version"]
    """
        (p2 / ".rs9" / "project.toml").write_text(reordered_toml, encoding="utf-8")

        out1 = normalize(p1, dest_path, "1.0.0")
        out2 = normalize(p2, dest_path, "1.0.0")

        doc1 = json.loads(out1.decode("utf-8"))
        doc2 = json.loads(out2.decode("utf-8"))

        # Semantic portions match exactly
        assert doc1["project"] == doc2["project"]
        assert doc1["license"] == doc2["license"]
        assert doc1["commands"] == doc2["commands"]
        assert doc1["checks"] == doc2["checks"]
        assert doc1["version"] == doc2["version"]
        assert doc1["assets"] == doc2["assets"]
        assert doc1["targets"] == doc2["targets"]

        # Evidence hashes differ because raw file bytes differ
        assert doc1["evidence"]["inputs"] != doc2["evidence"]["inputs"]
        assert out1 != out2


    def test_arch_independent_any_semantics(self) -> None:
        tmp_path = self.tmp_path
        pacman_toml = """schema = "rs9.pacman.v1alpha1"

    [[packages]]
    id = "my-app-any"
    name = "my-app"
    assets = ["app-bin"]

    [[publish]]
    package = "my-app-any"
    destination = "hosted-pacman"
    """
        dnf_toml = """schema = "rs9.dnf.v1alpha1"

    [[packages]]
    id = "my-app-dnf"
    name = "my-app"
    assets = ["app-bin"]

    [[publish]]
    package = "my-app-dnf"
    destination = "hosted-dnf"
    """
        apt_toml = """schema = "rs9.apt.v1alpha1"

    [[packages]]
    id = "my-app-apt"
    name = "my-app"
    assets = ["app-bin"]

    [[publish]]
    package = "my-app-apt"
    destination = "hosted-apt"
    """
        _create_minimal_project(
            tmp_path,
            asset_platforms=["any"],
            extra_files={
                "pacman.toml": pacman_toml,
                "dnf.toml": dnf_toml,
                "apt.toml": apt_toml,
            },
        )

        dest_content = """schema = "rs9.destinations.v1alpha1"

    [[destinations]]
    id = "hosted-pacman"
    adapter = "pacman"
    mode = "direct"
    platforms = ["x86_64-linux", "aarch64-linux"]
    status = "live"

    [[destinations]]
    id = "hosted-dnf"
    adapter = "dnf"
    mode = "direct"
    platforms = ["x86_64-linux", "aarch64-linux"]
    status = "live"

    [[destinations]]
    id = "hosted-apt"
    adapter = "apt"
    mode = "direct"
    platforms = ["x86_64-linux", "aarch64-linux"]
    status = "live"
    """
        dest_path = _create_destinations(tmp_path, dest_content)
        out_bytes = normalize(tmp_path, dest_path, "1.0.0")
        doc = json.loads(out_bytes.decode("utf-8"))

        targets_by_adapter = {t["adapter"]: t for t in doc["targets"]}
        assert targets_by_adapter["pacman"]["ecosystem-architectures"] == ["any"]
        assert targets_by_adapter["dnf"]["ecosystem-architectures"] == ["noarch"]
        assert targets_by_adapter["apt"]["ecosystem-architectures"] == ["all"]
        assert targets_by_adapter["pacman"]["effective-platforms"] == ["aarch64-linux", "x86_64-linux"]


    def test_unsupported_os_and_empty_intersection(self) -> None:
        tmp_path = self.tmp_path
        # Pacman destination with Darwin platform
        dest_content = """schema = "rs9.destinations.v1alpha1"

    [[destinations]]
    id = "bad-pacman"
    adapter = "pacman"
    mode = "direct"
    platforms = ["x86_64-darwin"]
    status = "live"
    """
        pacman_toml = """schema = "rs9.pacman.v1alpha1"

    [[packages]]
    id = "my-app-pkg"
    name = "my-app"
    assets = ["app-bin"]

    [[publish]]
    package = "my-app-pkg"
    destination = "bad-pacman"
    """
        _create_minimal_project(tmp_path, asset_platforms=["any"], extra_files={"pacman.toml": pacman_toml})
        dest_path = _create_destinations(tmp_path, dest_content)

        with self.assertRaises(ContractError) as exc_info:
            normalize(tmp_path, dest_path, "1.0.0")
        assert exc_info.exception.code == "UNSUPPORTED_OS"


    def test_empty_platform_intersection(self) -> None:
        tmp_path = self.tmp_path
        # Package restricts platforms to darwin, destination is linux
        pacman_toml = """schema = "rs9.pacman.v1alpha1"

    [[packages]]
    id = "my-app-pkg"
    name = "my-app"
    assets = ["app-bin"]
    platforms = ["x86_64-darwin"]

    [[publish]]
    package = "my-app-pkg"
    destination = "hosted-pacman"
    """
        _create_minimal_project(tmp_path, asset_platforms=["any"], extra_files={"pacman.toml": pacman_toml})
        dest_path = _create_destinations(tmp_path)

        with self.assertRaises(ContractError) as exc_info:
            normalize(tmp_path, dest_path, "1.0.0")
        assert exc_info.exception.code == "EMPTY_PLATFORM_INTERSECTION"


    def test_types_and_unknown_keys(self) -> None:
        tmp_path = self.tmp_path
        # 1. expect-exit as bool
        _create_minimal_project(tmp_path)
        (tmp_path / ".rs9" / "project.toml").write_text(
            (tmp_path / ".rs9" / "project.toml").read_text().replace("expect-exit = 0", "expect-exit = true")
        )
        with self.assertRaises(ContractError) as exc_info1:
            load_project(tmp_path)
        assert exc_info1.exception.code == "INVALID_TYPE"

        # 2. Unknown key in project.toml
        p2 = tmp_path / "p2"
        _create_minimal_project(p2)
        (p2 / ".rs9" / "project.toml").write_text(
            (p2 / ".rs9" / "project.toml").read_text() + "\nunknown_field = 123\n"
        )
        with self.assertRaises(ContractError) as exc_info2:
            load_project(p2)
        assert exc_info2.exception.code == "UNKNOWN_KEY"


    def test_unsafe_paths_and_directory_traversal(self) -> None:
        tmp_path = self.tmp_path
        # Traversal in license files
        _create_minimal_project(tmp_path)
        (tmp_path / ".rs9" / "project.toml").write_text(
            (tmp_path / ".rs9" / "project.toml").read_text().replace('files = ["LICENSE"]', 'files = ["../LICENSE"]')
        )
        with self.assertRaises(ContractError) as exc_info:
            load_project(tmp_path)
        assert exc_info.exception.code == "UNSAFE_PATH"


    def test_credentials_and_tokens_rejected(self) -> None:
        tmp_path = self.tmp_path
        # 1. PGP Private key block
        p1 = tmp_path / "p1"
        _create_minimal_project(p1)
        (p1 / ".rs9" / "project.toml").write_text(
            (p1 / ".rs9" / "project.toml").read_text() + "\n# -----" + "BEGIN PGP PRIVATE KEY BLOCK-----\n"
        )
        with self.assertRaises(ContractError) as exc_info1:
            load_project(p1)
        assert exc_info1.exception.code == "CREDENTIAL_DETECTED"

        # 2. Token pattern
        p2 = tmp_path / "p2"
        _create_minimal_project(p2)
        (p2 / ".rs9" / "project.toml").write_text(
            (p2 / ".rs9" / "project.toml").read_text() + '\nname = "ghp_' + '123456789012345678901234567890123456"\n'
        )
        with self.assertRaises(ContractError) as exc_info2:
            load_project(p2)
        assert exc_info2.exception.code == "CREDENTIAL_DETECTED"

        # 3. Credential-like key
        p3 = tmp_path / "p3"
        _create_minimal_project(p3)
        (p3 / ".rs9" / "project.toml").write_text(
            (p3 / ".rs9" / "project.toml").read_text() + '\ntoken = "some-value"\n'
        )
        with self.assertRaises(ContractError) as exc_info3:
            load_project(p3)
        assert exc_info3.exception.code == "CREDENTIAL_DETECTED"


    def test_version_and_template_safety(self) -> None:
        tmp_path = self.tmp_path
        _create_minimal_project(tmp_path)
        dest_path = _create_destinations(tmp_path)

        # 1. Unsafe version with traversal
        with self.assertRaises(ContractError) as exc_info1:
            normalize(tmp_path, dest_path, "../1.0.0")
        assert exc_info1.exception.code == "INVALID_VERSION"

        with self.assertRaises(ContractError) as unsafe_tag:
            normalize(tmp_path, dest_path, "1.0.0-candidate.lock")
        self.assertEqual(unsafe_tag.exception.code, "UNSAFE_PATH")

        # 2. Malformed template with extra braces
        p2 = tmp_path / "p2"
        _create_minimal_project(p2, tag_template="v{version}-{commit}")
        with self.assertRaises(ContractError) as exc_info2:
            load_project(p2)
        assert exc_info2.exception.code == "MALFORMED_TEMPLATE"


    def test_unknown_files_and_symlinks(self) -> None:
        tmp_path = self.tmp_path
        _create_minimal_project(tmp_path)
        rs9_dir = tmp_path / ".rs9"

        # Unknown file
        (rs9_dir / "unknown.toml").write_text("a = 1", encoding="utf-8")
        with self.assertRaises(ContractError) as exc_info1:
            load_project(tmp_path)
        assert exc_info1.exception.code == "UNKNOWN_FILE"

        (rs9_dir / "unknown.toml").unlink()

        # Symlink
        real_file = tmp_path / "real_file.toml"
        real_file.write_text("a = 1", encoding="utf-8")
        symlink_file = rs9_dir / "pypi.toml"
        symlink_file.symlink_to(real_file)
        with self.assertRaises(ContractError) as exc_info2:
            load_project(tmp_path)
        assert exc_info2.exception.code == "SYMLINK_REJECTED"


    def test_error_messages_do_not_echo_input_values(self) -> None:
        tmp_path = self.tmp_path
        sensitive_value = "SUPER_SECRET_VALUE_DO_NOT_LEAK"
        _create_minimal_project(tmp_path)
        (tmp_path / ".rs9" / "project.toml").write_text(
            (tmp_path / ".rs9" / "project.toml").read_text().replace('name = "My Application"', f'name = "{sensitive_value}"')
            .replace('expression = "MIT"', f'expression = "{sensitive_value} & MIT"')
        )
        with self.assertRaises(ContractError) as failure:
            load_project(tmp_path)
        self.assertNotIn(sensitive_value, str(failure.exception))
        self.assertNotIn(sensitive_value, failure.exception.message)


    def test_subprocess_cli_validate_and_normalize(self) -> None:
        tmp_path = self.tmp_path
        _create_minimal_project(tmp_path)
        dest_path = _create_destinations(tmp_path)
        source = Path(__file__).resolve().parents[1] / "src"
        env = {**os.environ, "PYTHONPATH": str(source), "PYTHONDONTWRITEBYTECODE": "1"}

        # 1. CLI validate project
        res_val = subprocess.run(
            [sys.executable, "-m", "rs9.contract", "validate", str(tmp_path)],
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )
        assert res_val.returncode == 0, res_val.stderr

        # 2. CLI validate with destinations
        res_val_dest = subprocess.run(
            [sys.executable, "-m", "rs9.contract", "validate", str(tmp_path), "--destinations", str(dest_path)],
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )
        assert res_val_dest.returncode == 0, res_val_dest.stderr

        # 3. CLI normalize
        res_norm = subprocess.run(
            [
                sys.executable,
                "-m",
                "rs9.contract",
                "normalize",
                str(tmp_path),
                "--destinations",
                str(dest_path),
                "--version",
                "1.2.3",
            ],
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )
        assert res_norm.returncode == 0, res_norm.stderr
        parsed = json.loads(res_norm.stdout)
        assert parsed["version"] == "1.2.3"
        assert parsed["tag"] == "v1.2.3"

        # 4. CLI validate failure exits 1
        (tmp_path / ".rs9" / "extra.txt").write_text("forbidden", encoding="utf-8")
        res_fail = subprocess.run(
            [sys.executable, "-m", "rs9.contract", "validate", str(tmp_path)],
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )
        assert res_fail.returncode == 1
        assert "UNKNOWN_FILE" in res_fail.stderr


    def test_ambiguity_rejection(self) -> None:
        tmp_path = self.tmp_path
        # Duplicate command platform coverage across assets
        _create_minimal_project(tmp_path)
        releases_content = """schema = "rs9.releases.v1alpha1"

    [release]
    tag = "v{version}"
    prerelease = "reject"

    [[assets]]
    id = "asset-1"
    name = "my-app-{version}-x64.tar.gz"
    format = "tar.gz"
    platforms = ["x86_64-linux"]
    [assets.commands]
    my-cli = "bin/my-cli"

    [[assets]]
    id = "asset-2"
    name = "my-app-{version}-all.tar.gz"
    format = "tar.gz"
    platforms = ["x86_64-linux"]
    [assets.commands]
    my-cli = "bin/my-cli"
    """
        (tmp_path / ".rs9" / "releases.toml").write_text(releases_content, encoding="utf-8")

        with self.assertRaises(ContractError) as exc_info:
            load_project(tmp_path)
        assert exc_info.exception.code == "AMBIGUOUS_COVERAGE"


    def test_format_restrictions(self) -> None:
        tmp_path = self.tmp_path
        # NPM adapter package references tar.gz instead of npm-tarball
        npm_toml = """schema = "rs9.npm.v1alpha1"

    [[packages]]
    id = "my-npm-pkg"
    name = "@scope/my-app"
    assets = ["app-bin"]
    """
        _create_minimal_project(tmp_path, extra_files={"npm.toml": npm_toml})

        with self.assertRaises(ContractError) as exc_info:
            load_project(tmp_path)
        assert exc_info.exception.code == "FORMAT_RESTRICTION"

        # PyPI adapter package references tar.gz instead of wheel or sdist
        p2 = tmp_path / "p2"
        pypi_toml = """schema = "rs9.pypi.v1alpha1"

    [[packages]]
    id = "my-pypi-pkg"
    name = "my_app"
    assets = ["app-bin"]
    """
        _create_minimal_project(p2, extra_files={"pypi.toml": pypi_toml})
        with self.assertRaises(ContractError) as exc_pypi:
            load_project(p2)
        assert exc_pypi.exception.code == "FORMAT_RESTRICTION"


    def test_invalid_destination_base_urls(self) -> None:
        tmp_path = self.tmp_path
        for bad_url in [
            "http://pkg.example.com",
            "https://user:pass@pkg.example.com",
            "https://pkg.example.com/repo?query=1",
            "https://pkg.example.com/repo#frag",
        ]:
            dest_content = f"""schema = "rs9.destinations.v1alpha1"

    [[destinations]]
    id = "my-dest"
    adapter = "pacman"
    mode = "direct"
    platforms = ["x86_64-linux"]
    status = "live"
    base-url = "{bad_url}"
    """
            dfile = tmp_path / "bad_dest.toml"
            dfile.write_text(dest_content, encoding="utf-8")
            with self.assertRaises(ContractError) as exc_info:
                load_destinations(dfile)
            assert exc_info.exception.code == "INVALID_URL"


    def test_undeclared_command_and_missing_requires_display(self) -> None:
        tmp_path = self.tmp_path
        _create_minimal_project(tmp_path)
        p_toml = tmp_path / ".rs9" / "project.toml"

        # 1. Undeclared command in check
        p_toml.write_text(p_toml.read_text().replace('argv = ["my-cli", "--version"]', 'argv = ["undeclared-cmd"]'))
        with self.assertRaises(ContractError) as exc1:
            load_project(tmp_path)
        assert exc1.exception.code == "UNKNOWN_REFERENCE"

        # 2. Missing requires-display
        _create_minimal_project(tmp_path)
        p_toml.write_text(p_toml.read_text().replace("requires-display = false", ""))
        with self.assertRaises(ContractError) as exc2:
            load_project(tmp_path)
        assert exc2.exception.code == "MISSING_REQUIRED_KEY"


    def test_destination_adapter_mismatch(self) -> None:
        tmp_path = self.tmp_path
        npm_toml = """schema = "rs9.npm.v1alpha1"

    [[packages]]
    id = "my-npm-pkg"
    name = "@scope/my-app"
    assets = ["app-tarball"]

    [[publish]]
    package = "my-npm-pkg"
    destination = "hosted-pacman"
    """
        _create_minimal_project(
            tmp_path,
            extra_files={"npm.toml": npm_toml},
        )
        # Add an npm-tarball asset
        releases_path = tmp_path / ".rs9" / "releases.toml"
        releases_path.write_text(
            releases_path.read_text()
            + """
    [[assets]]
    id = "app-tarball"
    name = "my-app-{version}.tgz"
    format = "npm-tarball"
    platforms = ["any"]
    commands = {}
    """
        )
        dest_path = _create_destinations(tmp_path)  # hosted-pacman has adapter = "pacman"

        with self.assertRaises(ContractError) as exc:
            normalize(tmp_path, dest_path, "1.0.0")
        assert exc.exception.code == "ADAPTER_MISMATCH"
