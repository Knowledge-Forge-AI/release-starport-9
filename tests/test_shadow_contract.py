"""Positive and adverse contract tests for F2 amendments: summary, desktop, and destination profile."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from rs9.contract import (
    ContractError,
    load_destinations,
    load_project,
    normalize,
)
from rs9.releases import validate_asset


def _create_test_project(
    root: Path,
    *,
    summary: str | None = None,
    desktop_table: str | None = None,
    extra_commands: str = "",
    extra_files: dict[str, str] | None = None,
) -> Path:
    rs9_dir = root / ".rs9"
    rs9_dir.mkdir(parents=True, exist_ok=True)

    summary_line = f'summary = "{summary}"\n' if summary is not None else ""
    desktop_section = desktop_table if desktop_table is not None else ""

    proj_content = f"""schema = "rs9.project.v1alpha1"

[project]
id = "shadow-app"
name = "Shadow Application"
repository = "example-org/shadow-app"
{summary_line}
[license]
expression = "MIT"
files = ["LICENSE"]
source = "tagged-repository"

[[commands]]
name = "shadow-cli"
interface = "cli"

[[commands]]
name = "shadow-gui"
interface = "gui"
{extra_commands}
[[checks]]
id = "version-check"
argv = ["shadow-cli", "--version"]
expect-exit = 0
expect-stdout-contains = "shadow-app {{version}}"
requires-display = false

{desktop_section}
"""
    (rs9_dir / "project.toml").write_text(proj_content, encoding="utf-8")

    releases_content = """schema = "rs9.releases.v1alpha1"

[release]
tag = "v{version}"
prerelease = "reject"

[[assets]]
id = "app-bin"
name = "shadow-app-{version}-dist.tar.gz"
format = "tar.gz"
platforms = ["x86_64-linux", "aarch64-linux"]

[assets.commands]
shadow-cli = "bin/shadow-cli"
shadow-gui = "bin/shadow-gui"
"""
    (rs9_dir / "releases.toml").write_text(releases_content, encoding="utf-8")

    if extra_files:
        for fname, fcontent in extra_files.items():
            (rs9_dir / fname).write_text(fcontent, encoding="utf-8")

    return root


def _create_test_destinations(root: Path, content: str | None = None) -> Path:
    dest_path = root / "destinations.toml"
    if content is None:
        content = """schema = "rs9.destinations.v1alpha1"

[[destinations]]
id = "aur-dest"
adapter = "pacman"
mode = "projection"
platforms = ["x86_64-linux", "aarch64-linux"]
status = "candidate"
profile = "aur"

[[destinations]]
id = "plain-pacman-projection"
adapter = "pacman"
mode = "projection"
platforms = ["x86_64-linux", "aarch64-linux"]
status = "candidate"
"""
    dest_path.write_text(content, encoding="utf-8")
    return dest_path


class ShadowContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.tmp_path = Path(self.temp.name)

    def test_unresolved_license_is_explicit_in_normalized_intent(self):
        root = _create_test_project(self.tmp_path)
        path = root / ".rs9/project.toml"
        path.write_text(path.read_text().replace('[license]\n', '[license]\nstatus = "unresolved"\n'))
        destinations = _create_test_destinations(self.tmp_path)
        first = normalize(root, destinations, "1.2.3")
        self.assertEqual(json.loads(first)["license"], {
            "expression": "MIT", "files": ["LICENSE"],
            "source": "tagged-repository", "status": "unresolved",
        })
        self.assertEqual(first, normalize(root, destinations, "1.2.3"))

    def test_license_status_cannot_claim_resolution(self):
        for value in ('"resolved"', '"accepted"', '""', 'true', '[]', '1'):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as temporary:
                root = _create_test_project(Path(temporary))
                path = root / ".rs9/project.toml"
                path.write_text(path.read_text().replace('[license]\n', '[license]\nstatus = ' + value + '\n'))
                with self.assertRaises(ContractError):
                    load_project(root)

    def test_release_launcher_selection_validation_and_normalization(self):
        asset = {"id": "linux", "name": "app-{version}.tar.gz", "format": "tar.gz",
                 "platforms": ["x86_64-linux"], "commands": {"gui": "app/bin/native"},
                 "launchers": {"gui": "app/bin/gui"}}
        validate_asset(asset, {"gui"})
        from rs9.normalizer import normalized_asset
        self.assertEqual(normalized_asset(asset, "1.0.0")["launchers"], asset["launchers"])
        for launchers in ({}, {"other": "app/bin/other"}, {"gui": "../escape"}, {"gui": "/absolute"}, {"gui": "app/\nfile"}, {"gui": "app/A\u030a"}, []):
            with self.subTest(launchers=launchers), self.assertRaises(ContractError):
                validate_asset({**asset, "launchers": launchers}, {"gui"})

    def test_category_prerequisites(self):
        from rs9.project import validate_desktop
        commands = [{"name": "gui", "interface": "gui"}]
        for categories in (["Audio"], ["Video"], ["IDE", "Graphics"]):
            with self.assertRaises(ContractError):
                validate_desktop({"command": "gui", "categories": categories,
                                  "icon": {"source": "tagged-repository", "path": "icon.png"}}, commands)

    def test_positive_summary_and_desktop_normalization(self):
        desktop = """
[desktop]
command = "shadow-gui"
categories = ["Utility", "Development", "IDE"]

[desktop.icon]
source = "tagged-repository"
path = "icons/app.png"
"""
        pacman_toml = """schema = "rs9.pacman.v1alpha1"

[[packages]]
id = "pkg-aur"
name = "shadow-app-aur"
assets = ["app-bin"]

[[packages]]
id = "pkg-plain"
name = "shadow-app-plain"
assets = ["app-bin"]

[[publish]]
package = "pkg-aur"
destination = "aur-dest"

[[publish]]
package = "pkg-plain"
destination = "plain-pacman-projection"
"""
        root = _create_test_project(
            self.tmp_path,
            summary="A deterministic shadow test application",
            desktop_table=desktop,
            extra_files={"pacman.toml": pacman_toml},
        )
        dest_path = _create_test_destinations(self.tmp_path)

        out_bytes = normalize(root, dest_path, "1.2.3")
        manifest = json.loads(out_bytes.decode("utf-8"))

        self.assertEqual(manifest["project"]["summary"], "A deterministic shadow test application")
        self.assertEqual(manifest["desktop"]["command"], "shadow-gui")
        # Categories must be sorted in normalized output
        self.assertEqual(manifest["desktop"]["categories"], ["Development", "IDE", "Utility"])
        self.assertEqual(
            manifest["desktop"]["icon"],
            {"path": "icons/app.png", "source": "tagged-repository"},
        )

        targets = {t["destination"]: t for t in manifest["targets"]}
        self.assertEqual(targets["aur-dest"]["profile"], "aur")
        # Ensure AUR profile is never inferred just from mode projection
        self.assertNotIn("profile", targets["plain-pacman-projection"])

        # Determinism check
        out_bytes_2 = normalize(root, dest_path, "1.2.3")
        self.assertEqual(out_bytes, out_bytes_2)
        self.assertTrue(out_bytes.endswith(b"\n"))

    def test_adverse_summary_validation(self):
        cases = [
            ("summary = 123", "INVALID_TYPE"),
            ("summary = true", "INVALID_TYPE"),
            ("summary = []", "INVALID_TYPE"),
            ('summary = ""', "INVALID_CONFIG"),
            (f'summary = "{"a" * 161}"', "INVALID_CONFIG"),
            ('summary = """line one\nline two"""', "INVALID_CONFIG"),
            (r'summary = "line one\u000dline two"', "INVALID_CONFIG"),
            (r'summary = "hello\u0000world"', "INVALID_CONFIG"),
            (r'summary = "hello\u001fworld"', "INVALID_CONFIG"),
            (r'summary = "hello\u007fworld"', "INVALID_CONFIG"),
            (r'summary = "Theme\u0041\u030aForge"', "NON_NFC_STRING"),
            ('summary = "token ' + 'ghp_' + 'a' * 36 + '"', "CREDENTIAL_DETECTED"),
            ('summary = "' + '-----' + 'BEGIN PRIVATE KEY-----"', "CREDENTIAL_DETECTED"),
        ]

        for setting, expected_code in cases:
            with self.subTest(setting=setting, code=expected_code), tempfile.TemporaryDirectory() as temp:
                root = _create_test_project(Path(temp))
                path = root / ".rs9/project.toml"
                text = path.read_text(encoding="utf-8")
                path.write_text(text.replace('id = "shadow-app"', f'id = "shadow-app"\n{setting}'), encoding="utf-8")
                with self.assertRaises(ContractError) as ctx:
                    load_project(root)
                self.assertEqual(ctx.exception.code, expected_code)

    def test_adverse_desktop_unknown_keys_and_missing_keys(self):
        unknown_cases = [
            ("terminal = false", "UNKNOWN_KEY"),
            ("size = 128", "UNKNOWN_KEY"),
            ("comment = 'Description'", "UNKNOWN_KEY"),
        ]
        for extra, expected_code in unknown_cases:
            with self.subTest(extra=extra), tempfile.TemporaryDirectory() as temp:
                desktop = f"""
[desktop]
command = "shadow-gui"
categories = ["Development"]
{extra}

[desktop.icon]
source = "tagged-repository"
path = "icons/app.png"
"""
                root = _create_test_project(Path(temp), desktop_table=desktop)
                with self.assertRaises(ContractError) as ctx:
                    load_project(root)
                self.assertEqual(ctx.exception.code, expected_code)

        missing_cases = [
            ("""
[desktop]
categories = ["Development"]
[desktop.icon]
source = "tagged-repository"
path = "icons/app.png"
""", "MISSING_REQUIRED_KEY"),
            ("""
[desktop]
command = "shadow-gui"
[desktop.icon]
source = "tagged-repository"
path = "icons/app.png"
""", "MISSING_REQUIRED_KEY"),
            ("""
[desktop]
command = "shadow-gui"
categories = ["Development"]
""", "MISSING_REQUIRED_KEY"),
        ]
        for desktop, expected_code in missing_cases:
            with self.subTest(desktop=desktop), tempfile.TemporaryDirectory() as temp:
                root = _create_test_project(Path(temp), desktop_table=desktop)
                with self.assertRaises(ContractError) as ctx:
                    load_project(root)
                self.assertEqual(ctx.exception.code, expected_code)

    def test_adverse_desktop_non_gui_command(self):
        # desktop.command references a CLI command
        desktop_cli = """
[desktop]
command = "shadow-cli"
categories = ["Development"]

[desktop.icon]
source = "tagged-repository"
path = "icons/app.png"
"""
        with tempfile.TemporaryDirectory() as temp:
            root = _create_test_project(Path(temp), desktop_table=desktop_cli)
            with self.assertRaises(ContractError) as ctx:
                load_project(root)
            self.assertEqual(ctx.exception.code, "INVALID_CONFIG")

        # desktop.command references an undeclared command
        desktop_undeclared = """
[desktop]
command = "unknown-command"
categories = ["Development"]

[desktop.icon]
source = "tagged-repository"
path = "icons/app.png"
"""
        with tempfile.TemporaryDirectory() as temp:
            root = _create_test_project(Path(temp), desktop_table=desktop_undeclared)
            with self.assertRaises(ContractError) as ctx:
                load_project(root)
            self.assertEqual(ctx.exception.code, "UNKNOWN_REFERENCE")

    def test_adverse_desktop_categories(self):
        cases = [
            ('categories = ["InvalidCategory"]', "INVALID_CONFIG"),
            ('categories = ["Games"]', "INVALID_CONFIG"),  # Game is singular
            ('categories = ["Development", "Development"]', "DUPLICATE_IDENTIFIER"),
            ('categories = []', "INVALID_CONFIG"),
            ('categories = "Development"', "INVALID_TYPE"),
            ('categories = [123]', "INVALID_TYPE"),
            ('categories = ["IDE"]', "INVALID_CONFIG"),  # IDE allowed only with main category
        ]
        for cats, expected_code in cases:
            with self.subTest(cats=cats, code=expected_code), tempfile.TemporaryDirectory() as temp:
                desktop = f"""
[desktop]
command = "shadow-gui"
{cats}

[desktop.icon]
source = "tagged-repository"
path = "icons/app.png"
"""
                root = _create_test_project(Path(temp), desktop_table=desktop)
                with self.assertRaises(ContractError) as ctx:
                    load_project(root)
                self.assertEqual(ctx.exception.code, expected_code)

    def test_adverse_desktop_icon_traversal_non_png_and_size_unknown(self):
        cases = [
            # Traversal in icon path
            ('path = "../icons/icon.png"', 'source = "tagged-repository"', "UNSAFE_PATH"),
            ('path = "icons/../../icon.png"', 'source = "tagged-repository"', "UNSAFE_PATH"),
            ('path = "/icons/icon.png"', 'source = "tagged-repository"', "UNSAFE_PATH"),
            # Non-PNG source
            ('path = "icons/icon.svg"', 'source = "tagged-repository"', "INVALID_CONFIG"),
            ('path = "icons/icon.ico"', 'source = "tagged-repository"', "INVALID_CONFIG"),
            ('path = "icons/icon.jpg"', 'source = "tagged-repository"', "INVALID_CONFIG"),
            ('path = "icons/icon"', 'source = "tagged-repository"', "INVALID_CONFIG"),
            # Invalid source
            ('path = "icons/icon.png"', 'source = "release-asset"', "INVALID_CONFIG"),
            ('path = "icons/icon.png"', 'source = "url"', "INVALID_CONFIG"),
            # Size unknown: NO icon.size field allowed
            ('path = "icons/icon.png"\nsource = "tagged-repository"\nsize = 48', "", "UNKNOWN_KEY"),
            ('path = "icons/icon.png"\nsource = "tagged-repository"\nsize = "48x48"', "", "UNKNOWN_KEY"),
        ]
        for path_entry, source_entry, expected_code in cases:
            with self.subTest(path=path_entry, source=source_entry, code=expected_code), tempfile.TemporaryDirectory() as temp:
                lines = [path_entry]
                if source_entry:
                    lines.append(source_entry)
                icon_body = "\n".join(lines)
                desktop = f"""
[desktop]
command = "shadow-gui"
categories = ["Development"]

[desktop.icon]
{icon_body}
"""
                root = _create_test_project(Path(temp), desktop_table=desktop)
                with self.assertRaises(ContractError) as ctx:
                    load_project(root)
                self.assertEqual(ctx.exception.code, expected_code)

    def test_adverse_destination_profile_misuse_and_determinism(self):
        cases = [
            # Unknown profile value
            ("""
[[destinations]]
id = "aur-dest"
adapter = "pacman"
mode = "projection"
platforms = ["x86_64-linux"]
status = "candidate"
profile = "debian"
""", "INVALID_CONFIG"),
            # Profile aur on non-pacman adapter
            ("""
[[destinations]]
id = "dnf-dest"
adapter = "dnf"
mode = "projection"
platforms = ["x86_64-linux"]
status = "candidate"
profile = "aur"
""", "INVALID_CONFIG"),
            # Profile aur on direct mode pacman
            ("""
[[destinations]]
id = "pacman-direct"
adapter = "pacman"
mode = "direct"
platforms = ["x86_64-linux"]
status = "candidate"
profile = "aur"
""", "INVALID_CONFIG"),
            # Unknown key in destination
            ("""
[[destinations]]
id = "aur-dest"
adapter = "pacman"
mode = "projection"
platforms = ["x86_64-linux"]
status = "candidate"
profile = "aur"
unknown_dest_key = true
""", "UNKNOWN_KEY"),
        ]

        for dest_toml, expected_code in cases:
            with self.subTest(code=expected_code), tempfile.TemporaryDirectory() as temp:
                dpath = Path(temp) / "destinations.toml"
                dpath.write_text('schema = "rs9.destinations.v1alpha1"\n' + dest_toml, encoding="utf-8")
                with self.assertRaises(ContractError) as ctx:
                    load_destinations(dpath)
                self.assertEqual(ctx.exception.code, expected_code)
