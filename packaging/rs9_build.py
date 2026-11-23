"""Curate the offline CLI closure, then delegate packaging protocols to Flit.

Historical operator modules and private/untracked workspace additions must not
be swept into a wheel by recursive package discovery. The sdist contains the
same curated sources and a direct Flit backend, so it builds independently.
"""
import os
import stat
import tempfile
from contextlib import contextmanager
from pathlib import Path

MODULES = (
    "__init__", "__main__", "adapters", "bounded_process", "cli", "constants", "contract",
    "cross_validator", "destinations", "errors", "evidence_profile_roles", "fields",
    "bootstrap_binding",
    "instance", "normalizer", "project", "releases", "security", "spdx", "validator",
    "instance_github", "instance_github_apply", "github_reader", "github_writer",
    "remote_journal", "instance_github_resume", "engine_binding", "github_cli",
    "homebrew_renderer", "installed_homebrew", "provision_cli", "instance_provision",
    "provision_journal", "github_provision_reader", "instance_github_bootstrap",
    "github_provision",
    "archives", "command_policies", "github", "python_cli_release", "release_core",
    "scratch", "tf_pypi_archive", "wheel_evidence",
)
RESOURCES = ("README.md", "consumer/project.toml", "consumer/releases.toml")
INSTANCE_RESOURCES = (
    "instance-templates/github-homebrew-projection/v1alpha1/template.json",
    "instance-templates/github-homebrew-projection/v1alpha1/review-checklist.md",
    "instance-templates/github-homebrew-projection/v1alpha1/publisher-registration.json",
)
LEGAL = ("LICENSE", "NOTICE", "COMMERCIAL-LICENSE.md")


def _copy(source, destination):
    root = Path(__file__).resolve().parents[1]
    parent = source.parent
    while parent != root:
        if not parent.is_relative_to(root) or not stat.S_ISDIR(parent.lstat().st_mode):
            raise ValueError("RS9_BUILD_SOURCE_INVALID")
        parent = parent.parent
    observed = source.lstat()
    if not stat.S_ISREG(observed.st_mode) or observed.st_size > 1_048_576:
        raise ValueError("RS9_BUILD_SOURCE_INVALID")
    def identity(value):
        return (value.st_dev, value.st_ino, value.st_mode, value.st_size,
                value.st_mtime_ns, value.st_ctime_ns)
    with os.fdopen(os.open(source, os.O_RDONLY | os.O_NOFOLLOW), "rb") as handle:
        opened = os.fstat(handle.fileno())
        if identity(opened) != identity(observed):
            raise ValueError("RS9_BUILD_SOURCE_CHANGED")
        data = handle.read(1_048_577)
        after = os.fstat(handle.fileno())
    if len(data) != observed.st_size or identity(after) != identity(observed) or identity(source.lstat()) != identity(observed):
        raise ValueError("RS9_BUILD_SOURCE_CHANGED")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(data)


@contextmanager
def _staged_source():
    root = Path(__file__).resolve().parents[1]
    previous = Path.cwd()
    with tempfile.TemporaryDirectory(prefix="rs9-cli-build-") as directory:
        stage = Path(directory)
        for module in MODULES:
            _copy(root / "src/rs9" / (module + ".py"), stage / "src/rs9" / (module + ".py"))
        for resource in RESOURCES:
            _copy(root / "src/rs9/_resources" / resource, stage / "src/rs9/_resources" / resource)
        for resource in INSTANCE_RESOURCES:
            _copy(root / "src/rs9/_resources" / resource, stage / "src/rs9/_resources" / resource)
        for name in (*LEGAL, "docs/rs9-cli.md"):
            _copy(root / name, stage / name)
        _copy(root / "pyproject.toml", stage / "pyproject.toml")
        config = (stage / "pyproject.toml").read_text(encoding="utf-8")
        expected = 'build-backend = "rs9_build"\nbackend-path = ["packaging"]'
        if config.count(expected) != 1:
            raise ValueError("RS9_BUILD_CONFIG_INVALID")
        config = config.replace(expected, 'build-backend = "flit_core.buildapi"')
        (stage / "pyproject.toml").write_text(config, encoding="utf-8")
        try:
            os.chdir(stage)
            yield
        finally:
            os.chdir(previous)


def get_requires_for_build_wheel(config_settings=None):
    return []


def get_requires_for_build_sdist(config_settings=None):
    return []


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    from flit_core import buildapi
    output = str(Path(wheel_directory).resolve())
    metadata = str(Path(metadata_directory).resolve()) if metadata_directory else None
    with _staged_source():
        return buildapi.build_wheel(output, config_settings, metadata)


def build_sdist(sdist_directory, config_settings=None):
    from flit_core import buildapi
    output = str(Path(sdist_directory).resolve())
    with _staged_source():
        return buildapi.build_sdist(output, config_settings)


def prepare_metadata_for_build_wheel(metadata_directory, config_settings=None):
    from flit_core import buildapi
    output = str(Path(metadata_directory).resolve())
    with _staged_source():
        return buildapi.prepare_metadata_for_build_wheel(output, config_settings)
