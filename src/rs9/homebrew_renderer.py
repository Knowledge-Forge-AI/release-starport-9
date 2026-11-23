"""Pure, bounded Homebrew formula rendering for selected RS9 intents.

This module deliberately stops at an unsigned in-memory formula candidate.  It
does not parse or publish tap contents, execute Homebrew/Ruby, fetch archives,
or install payloads.  The input boundary is a full normalized tenant record
plus one closed payload-facts mapping for the selected Homebrew asset.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from collections.abc import Mapping, Sequence
from typing import Any
from urllib.parse import unquote, urlsplit, urlunsplit

from rs9.errors import ContractError


SCHEMA_NORMALIZED = "rs9.normalized-tenant.v1alpha1"
SCHEMA_RENDER = "rs9.homebrew-render.v1alpha1"
SCHEMA_BUNDLE = "rs9.homebrew-bundle.v1alpha1"
TEMPLATE_VERSION = "v1alpha1"
MAX_INPUT_BYTES = 512 * 1024
MAX_PAYLOAD_BYTES = 512 * 1024 * 1024
MAX_BUNDLE_REQUESTS = 64
MAX_CANONICAL_WORK_BYTES = 4 * 1024 * 1024
MAX_CANONICAL_NODES = 1_000_000

VARIANT_CLI = "cli-archive"
VARIANT_TAURI = "tauri-desktop-archive"
VARIANT_PYTHON_WHEEL = "python-wheel"
VARIANTS = frozenset({VARIANT_CLI, VARIANT_TAURI})

_SLUG = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_ASSET_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+\-]*\Z")
_PLATFORM = frozenset({"aarch64-darwin", "aarch64-linux", "x86_64-darwin", "x86_64-linux", "any"})
_LICENSES = frozenset({"MIT", "AGPL-3.0-or-later"})
_DESTINATION_STATUSES = frozenset({"illustrative", "candidate", "live"})
_CREDENTIAL_MARKER = re.compile(r"(?i)(?:ghp_[a-z0-9]{20,}|github_pat_[a-z0-9_]{20,}|npm_[a-z0-9]{20,}|pypi-[a-z0-9_-]{20,}|aki[a-z0-9]{16})")
_BIDI_FORMAT_MARKERS = frozenset({"\u061c", "\u200e", "\u200f", "\u202a", "\u202b", "\u202c", "\u202d", "\u202e", "\u2066", "\u2067", "\u2068", "\u2069"})
_PLACEHOLDER = re.compile(r"@@([A-Z]+)@@")


# These are owned source templates.  Callers supply only validated scalar
# values; they cannot supply Ruby, shell, or Homebrew control statements.
_CLI_TEMPLATE = """class @@CLASS@@ < Formula
  desc "@@DESC@@"
  homepage "@@HOMEPAGE@@"
  url "@@URL@@"
  version "@@VERSION@@"
  sha256 "@@SHA@@"
  license "@@LICENSE@@"

  depends_on arch: :arm64
  depends_on :macos

  def install
    (libexec/"payload").install Dir["*"]
    (bin/"@@COMMAND@@").write <<~SH
      #!/bin/sh
      exec "#{libexec}/payload/bin/@@COMMAND@@" "$@"
    SH
    chmod 0755, bin/"@@COMMAND@@"
  end

  test do
    assert_match "@@VERSION@@", shell_output("#{bin}/@@COMMAND@@ --version")
  end
end
"""

_PYTHON_WHEEL_TEMPLATE = """class @@CLASS@@ < Formula
  include Language::Python::Virtualenv

  desc "@@DESC@@"
  homepage "@@HOMEPAGE@@"
  url "@@SOURCEURL@@"
  version "@@VERSION@@"
  sha256 "@@SOURCESHA@@"
  license "@@LICENSE@@"

  depends_on "python@3.14"

  resource "cli-wheel" do
    url "@@WHEELURL@@"
    sha256 "@@WHEELSHA@@"
  end

  def install
    ENV["PIP_NO_INDEX"] = "1"
    wheel = buildpath/"@@WHEELNAME@@"
    cp resource("cli-wheel").cached_download, wheel
    virtualenv_create(libexec, "python3.14", system_site_packages: false)
      .pip_install_and_link(wheel, build_isolation: false)
    pkgshare.install "LICENSE", "NOTICE", "COMMERCIAL-LICENSE.md"
  end

  test do
    assert_match "@@VERSION@@", shell_output("#{bin}/@@COMMAND@@ --version")
    %w[LICENSE NOTICE COMMERCIAL-LICENSE.md].each do |file|
      assert_predicate pkgshare/file, :file?
    end
  end
end
"""

_TAURI_TEMPLATE = """class @@CLASS@@ < Formula
  desc "CLI launcher for the Nebular Fusion desktop workbench"
  homepage "@@HOMEPAGE@@"
  url "@@URL@@"
  version "@@VERSION@@"
  sha256 "@@SHA@@"
  license "@@LICENSE@@"

  depends_on arch: :arm64
  depends_on :macos

  def install
    app = "Theme Forge Nebular Fusion.app"
    # Homebrew changes into an archive's lone top-level directory before install.
    staged = (File.basename(Dir.pwd) == app) ? Pathname.pwd : Pathname(app)
    odie "Nebular Fusion application payload is missing" unless (staged/"Contents/MacOS/theme-forge-nebular-fusion").file?

    (libexec/app).install staged.children

    (bin/"tfnf").write <<~SH
      #!/bin/sh
      app="#{libexec}/Theme Forge Nebular Fusion.app"
      executable="$app/Contents/MacOS/theme-forge-nebular-fusion"

      case "$1" in
        -v|--version)
          echo "theme-forge-nebular-fusion @@VERSION@@ (aarch64-darwin)"
          exit 0
          ;;
        -h|--help)
          echo "Theme Forge Nebular Fusion CLI launcher (aarch64-darwin Homebrew Formula)"
          echo "Usage: tfnf [--help|--version|--path]"
          exit 0
          ;;
        --path)
          echo "$app"
          exit 0
          ;;
      esac

      exec "$executable" "$@"
    SH
    chmod 0755, bin/"tfnf"
  end

  def caveats
    <<~EOS
      Installs the ad-hoc-signed macOS Apple Silicon developer application used by
      the tfnf launcher. Developer ID signing, notarization, Gatekeeper qualification,
      and a Homebrew Cask are not claimed.
    EOS
  end

  test do
    assert_match "@@VERSION@@", shell_output("#{bin}/tfnf --version")
    assert_match "Nebular Fusion CLI launcher", shell_output("#{bin}/tfnf --help")
    assert_path_exists shell_output("#{bin}/tfnf --path").strip
  end
end
"""

_TEMPLATES = {
    VARIANT_CLI: ("homebrew-cli-archive", _CLI_TEMPLATE),
    VARIANT_TAURI: ("homebrew-tauri-desktop-archive", _TAURI_TEMPLATE),
}


def _fail(code: str = "HOMEBREW_RENDER_CONTRACT", field: str | None = None) -> None:
    details = {"field_path": field} if field else None
    raise ContractError(code, "Homebrew renderer input violates its closed contract", details=details)


def _mapping(value: Any, *, field: str, allowed: set[str], required: set[str]) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _fail(field=field)
    keys = set(value.keys())
    if any(not isinstance(key, str) for key in keys):
        _fail(field=field)
    if keys - allowed or required - keys:
        _fail(field=field)
    return value


class _CanonicalBudget:
    """Bound copy work before a caller-owned graph can expand in memory."""

    __slots__ = ("work_bytes", "nodes")

    def __init__(self) -> None:
        self.work_bytes = 0
        self.nodes = 0

    def charge(self, amount: int, field: str) -> None:
        self.nodes += 1
        self.work_bytes += max(1, amount)
        if self.nodes > MAX_CANONICAL_NODES or self.work_bytes > MAX_CANONICAL_WORK_BYTES:
            _fail("HOMEBREW_RENDER_LIMIT", field)


def _json_string_size(value: str, field: str) -> int:
    """Bound the UTF-8 bytes plus JSON escaping without serializing a subtree."""
    try:
        encoded_length = len(value.encode("utf-8"))
    except UnicodeError:
        _fail("HOMEBREW_RENDER_CONTRACT", field)
    return encoded_length + 2 + sum(value.count(char) for char in ('"', "\\", "\b", "\f", "\n", "\r", "\t"))


def _canonical_copy(value: Any, *, field: str, depth: int, budget: _CanonicalBudget) -> Any:
    if depth > 12:
        _fail("HOMEBREW_RENDER_LIMIT", field)
    if value is None or type(value) is bool:
        budget.charge(4, field)
        return value
    if type(value) is int:
        if abs(value) > 2**63 - 1:
            _fail("HOMEBREW_RENDER_LIMIT", field)
        budget.charge(len(str(value)), field)
        return value
    if isinstance(value, str):
        if not value or len(value) > 16 * 1024 or unicodedata.normalize("NFC", value) != value:
            _fail("HOMEBREW_RENDER_CONTRACT", field)
        if any(ord(char) < 32 or ord(char) == 127 for char in value):
            _fail("HOMEBREW_RENDER_CONTRACT", field)
        budget.charge(_json_string_size(value, field), field)
        return value
    if isinstance(value, Mapping):
        try:
            size = len(value)
            items = value.items()
        except (MemoryError, RuntimeError, TypeError):
            _fail("HOMEBREW_RENDER_LIMIT", field)
        if size > 256:
            _fail("HOMEBREW_RENDER_LIMIT", field)
        budget.charge(1, field)
        normalized = {}
        try:
            for key, item in items:
                if not isinstance(key, str) or not key or len(key) > 256:
                    _fail("HOMEBREW_RENDER_CONTRACT", field)
                budget.charge(_json_string_size(key, field) + 1, field)
                normalized[key] = _canonical_copy(item, field=field + ".<value>", depth=depth + 1, budget=budget)
        except MemoryError:
            _fail("HOMEBREW_RENDER_LIMIT", field)
        return normalized
    if isinstance(value, list):
        if len(value) > 20_000:
            _fail("HOMEBREW_RENDER_LIMIT", field)
        budget.charge(1, field)
        normalized = []
        try:
            for item in value:
                normalized.append(_canonical_copy(item, field=f"{field}[]", depth=depth + 1, budget=budget))
        except MemoryError:
            _fail("HOMEBREW_RENDER_LIMIT", field)
        return normalized
    _fail("HOMEBREW_RENDER_CONTRACT", field)


def _canonical_snapshot(value: Any) -> tuple[bytes, Any]:
    """Copy once under a work budget, then perform one canonical serialization."""
    budget = _CanonicalBudget()
    normalized = _canonical_copy(value, field="$", depth=0, budget=budget)
    try:
        encoded = json.dumps(normalized, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except MemoryError:
        _fail("HOMEBREW_RENDER_LIMIT", "$")
    except (TypeError, ValueError, UnicodeError):
        _fail("HOMEBREW_RENDER_CONTRACT", "$")
    if len(encoded) > MAX_INPUT_BYTES:
        _fail("HOMEBREW_RENDER_LIMIT", "$")
    return encoded, normalized


def _canonical_json(value: Any) -> bytes:
    return _canonical_snapshot(value)[0]


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _text(value: Any, *, field: str, max_bytes: int = 1024) -> str:
    if not isinstance(value, str) or not value:
        _fail(field=field)
    try:
        byte_length = len(value.encode("utf-8"))
    except UnicodeError:
        _fail("HOMEBREW_RENDER_CONTRACT", field)
    if byte_length > max_bytes:
        _fail(field=field)
    if (unicodedata.normalize("NFC", value) != value
            or any(unicodedata.category(char) == "Cc" or char in _BIDI_FORMAT_MARKERS for char in value)):
        _fail(field=field)
    # A double quoted Ruby string must not receive caller-controlled escaping or
    # interpolation.  Reject rather than trying to make an escaping DSL.
    if any(char in value for char in ('"', "\\", "#")):
        _fail(field=field)
    if _CREDENTIAL_MARKER.search(value) or re.search(r"~[/\\]|/(?:Users|home|root|private|tmp)/|[A-Za-z]:\\", value):
        _fail(field=field)
    return value


def _slug(value: Any, *, field: str) -> str:
    value = _text(value, field=field, max_bytes=128)
    if not _SLUG.fullmatch(value):
        _fail(field=field)
    return value


def _version(value: Any, *, field: str) -> str:
    value = _text(value, field=field, max_bytes=32)
    if not _VERSION.fullmatch(value):
        _fail(field=field)
    return value


def _hash(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        _fail(field=field)
    return value


def _relative_path(value: Any, *, field: str) -> str:
    value = _text(value, field=field, max_bytes=512)
    if value.startswith(("/", "\\")) or "//" in value:
        _fail(field=field)
    parts = value.split("/")
    if any(part in ("", ".", "..") for part in parts):
        _fail(field=field)
    if not re.fullmatch(r"[A-Za-z0-9_.+\- ]+(?:/[A-Za-z0-9_.+\- ]+)*", value):
        _fail(field=field)
    return value


def _url(value: Any, *, field: str, expected_basename: str | None = None) -> str:
    value = _text(value, field=field, max_bytes=2048)
    try:
        parts = urlsplit(value)
        hostname = parts.hostname
        port = parts.port
    except ValueError:
        _fail(field=field)
    if urlunsplit(parts) != value:
        _fail(field=field)
    if parts.scheme != "https" or not hostname or port is not None or parts.username or parts.password:
        _fail(field=field)
    if (not parts.path or parts.path.endswith("/") or parts.query or parts.fragment
            or not re.fullmatch(r"[A-Za-z0-9.-]+", parts.netloc)):
        _fail(field=field)
    if not re.fullmatch(r"(?:/[A-Za-z0-9._~+%:@-]+)*", parts.path):
        _fail(field=field)
    if re.search(r"%(?![0-9A-Fa-f]{2})", parts.path) or re.search(r"%(?:2f|5c|00)", parts.path, re.IGNORECASE):
        _fail(field=field)
    for segment in parts.path.split("/"):
        if segment in {".", ".."} or unquote(segment) in {".", ".."}:
            _fail(field=field)
    if expected_basename is not None:
        try:
            basename = unquote(parts.path.rsplit("/", 1)[-1])
        except UnicodeError:
            _fail(field=field)
        if basename != expected_basename:
            _fail("HOMEBREW_RENDER_PAYLOAD", field)
    return value


def _repository(value: Any, *, field: str) -> str:
    value = _text(value, field=field, max_bytes=256)
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", value):
        _fail(field=field)
    if any(part in (".", "..") for part in value.split("/")):
        _fail(field=field)
    return value


def _validate_license(normalized: Mapping[str, Any]) -> str:
    license_value = _mapping(
        normalized["license"],
        field="$.license",
        allowed={"expression", "files", "source", "status"},
        required={"expression", "files", "source"},
    )
    expression = license_value["expression"]
    if not isinstance(expression, str) or expression not in _LICENSES:
        _fail("HOMEBREW_RENDER_LICENSE", "$.license.expression")
    if license_value["source"] != "tagged-repository":
        _fail("HOMEBREW_RENDER_LICENSE", "$.license.source")
    files = license_value["files"]
    if not isinstance(files, list) or not files:
        _fail("HOMEBREW_RENDER_LICENSE", "$.license.files")
    for index, path in enumerate(files):
        _relative_path(path, field=f"$.license.files[{index}]")
    if "status" in license_value and license_value["status"] != "unresolved":
        _fail("HOMEBREW_RENDER_LICENSE", "$.license.status")
    return expression


def _validate_project(normalized: Mapping[str, Any]) -> tuple[Mapping[str, Any], str, str, str]:
    project = _mapping(
        normalized["project"],
        field="$.project",
        allowed={"id", "name", "repository", "family", "summary"},
        required={"id", "name", "repository"},
    )
    project_id = _slug(project["id"], field="$.project.id")
    project_name = _text(project["name"], field="$.project.name", max_bytes=512)
    repository = _repository(project["repository"], field="$.project.repository")
    summary = _text(project.get("summary", project_name), field="$.project.summary", max_bytes=512)
    if "family" in project:
        _slug(project["family"], field="$.project.family")
    return project, project_id, repository, summary


def _validate_commands(normalized: Mapping[str, Any]) -> tuple[str, str]:
    commands = normalized["commands"]
    if not isinstance(commands, list) or len(commands) != 1:
        _fail("HOMEBREW_RENDER_COMMANDS", "$.commands")
    command = _mapping(
        commands[0],
        field="$.commands[0]",
        allowed={"name", "interface"},
        required={"name", "interface"},
    )
    name = _slug(command["name"], field="$.commands[0].name")
    interface = command["interface"]
    if not isinstance(interface, str) or interface not in {"cli", "gui"}:
        _fail("HOMEBREW_RENDER_COMMANDS", "$.commands[0].interface")
    return name, interface


def _validate_assets(normalized: Mapping[str, Any]) -> Mapping[str, Mapping[str, Any]]:
    assets = normalized["assets"]
    if not isinstance(assets, list) or not assets:
        _fail("HOMEBREW_RENDER_ASSET", "$.assets")
    by_id: dict[str, Mapping[str, Any]] = {}
    for index, raw_asset in enumerate(assets):
        field = f"$.assets[{index}]"
        asset = _mapping(raw_asset, field=field, allowed={"id", "name", "format", "platforms", "commands", "launchers"}, required={"id", "name", "format", "platforms", "commands"})
        asset_id = _slug(asset["id"], field=field + ".id")
        if asset_id in by_id:
            _fail("HOMEBREW_RENDER_ASSET", field + ".id")
        name = _text(asset["name"], field=field + ".name", max_bytes=512)
        if not _ASSET_NAME.fullmatch(name):
            _fail("HOMEBREW_RENDER_ASSET", field + ".name")
        if asset["format"] != "tar.gz":
            _fail("HOMEBREW_RENDER_ASSET", field + ".format")
        platforms = asset["platforms"]
        if (not isinstance(platforms, list) or not platforms
                or any(not isinstance(platform, str) or platform not in _PLATFORM for platform in platforms)):
            _fail("HOMEBREW_RENDER_ASSET", field + ".platforms")
        if len(set(platforms)) != len(platforms):
            _fail("HOMEBREW_RENDER_ASSET", field + ".platforms")
        command_paths = asset["commands"]
        if not isinstance(command_paths, Mapping) or not command_paths or any(not isinstance(key, str) for key in command_paths):
            _fail("HOMEBREW_RENDER_ASSET", field + ".commands")
        for command_name, path in command_paths.items():
            _slug(command_name, field=field + ".commands")
            _relative_path(path, field=field + ".commands")
        if "launchers" in asset:
            launchers = asset["launchers"]
            if not isinstance(launchers, Mapping):
                _fail("HOMEBREW_RENDER_ASSET", field + ".launchers")
            for command_name, path in launchers.items():
                _slug(command_name, field=field + ".launchers")
                _relative_path(path, field=field + ".launchers")
        by_id[asset_id] = asset
    return by_id


def _selected_target(normalized: Mapping[str, Any], assets: Mapping[str, Mapping[str, Any]], command: str) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    targets = normalized["targets"]
    if not isinstance(targets, list) or not targets:
        _fail("HOMEBREW_RENDER_TARGET", "$.targets")
    homebrew = []
    for index, raw_target in enumerate(targets):
        if not isinstance(raw_target, Mapping) or raw_target.get("adapter") != "homebrew":
            continue
        field = f"$.targets[{index}]"
        target = _mapping(raw_target, field=field, allowed={"adapter", "assets", "destination", "destination-status", "ecosystem-architectures", "effective-platforms", "mode", "name", "package", "base-url", "repository", "profile"}, required={"adapter", "assets", "destination", "destination-status", "ecosystem-architectures", "effective-platforms", "mode", "name", "package"})
        homebrew.append(target)
    if len(homebrew) != 1:
        _fail("HOMEBREW_RENDER_TARGET", "$.targets")
    target = homebrew[0]
    if (target["mode"] != "projection" or not isinstance(target["destination-status"], str)
            or target["destination-status"] not in _DESTINATION_STATUSES):
        _fail("HOMEBREW_RENDER_TARGET", "$.targets[].mode")
    _slug(target["destination"], field="$.targets[].destination")
    _slug(target["name"], field="$.targets[].name")
    _slug(target["package"], field="$.targets[].package")
    if "repository" in target:
        _repository(target["repository"], field="$.targets[].repository")
    if target["effective-platforms"] != ["aarch64-darwin"] or target["ecosystem-architectures"] != ["arm64"]:
        _fail("HOMEBREW_RENDER_TARGET", "$.targets[].effective-platforms")
    selected_ids = target["assets"]
    if (not isinstance(selected_ids, list) or len(selected_ids) != 1
            or not isinstance(selected_ids[0], str) or len(set(selected_ids)) != 1):
        _fail("HOMEBREW_RENDER_TARGET", "$.targets[].assets")
    asset_id = selected_ids[0]
    if asset_id not in assets:
        _fail("HOMEBREW_RENDER_TARGET", "$.targets[].assets")
    asset = assets[asset_id]
    if asset["platforms"] != ["aarch64-darwin"] or set(asset["commands"]) != {command}:
        _fail("HOMEBREW_RENDER_TARGET", "$.assets[]")
    return target, asset


def _payload_facts(payload: Mapping[str, Any], *, license_expression: str, asset: Mapping[str, Any], version: str) -> tuple[dict[str, Any], bytes | None]:
    facts = _mapping(payload, field="$.payload", allowed={"name", "url", "sha256", "version", "platform", "license", "payload_bytes"}, required={"name", "url", "sha256", "version", "platform", "license"})
    name = _text(facts["name"], field="$.payload.name", max_bytes=512)
    if not _ASSET_NAME.fullmatch(name) or name != asset["name"]:
        _fail("HOMEBREW_RENDER_PAYLOAD", "$.payload.name")
    url = _url(facts["url"], field="$.payload.url", expected_basename=name)
    digest = _hash(facts["sha256"], field="$.payload.sha256")
    if _version(facts["version"], field="$.payload.version") != version:
        _fail("HOMEBREW_RENDER_PAYLOAD", "$.payload.version")
    if facts["platform"] != "aarch64-darwin":
        _fail("HOMEBREW_RENDER_PAYLOAD", "$.payload.platform")
    if facts["license"] != license_expression:
        _fail("HOMEBREW_RENDER_PAYLOAD", "$.payload.license")
    payload_bytes = facts.get("payload_bytes")
    if payload_bytes is not None:
        if type(payload_bytes) is not bytes or len(payload_bytes) > MAX_PAYLOAD_BYTES:
            _fail("HOMEBREW_RENDER_PAYLOAD", "$.payload.payload_bytes")
        if _sha256(payload_bytes) != digest:
            _fail("HOMEBREW_RENDER_PAYLOAD", "$.payload.payload_bytes")
    canonical_facts = {"license": license_expression, "name": name, "platform": "aarch64-darwin", "sha256": digest, "url": url, "version": version}
    return canonical_facts, payload_bytes


def _class_name(package: str) -> str:
    if not package or not package[0].isalpha():
        _fail("HOMEBREW_RENDER_CLASS", "$.targets[].name")
    result = "".join(part[:1].upper() + part[1:] for part in package.split("-"))
    if not re.fullmatch(r"[A-Z][A-Za-z0-9]*", result):
        _fail("HOMEBREW_RENDER_CLASS", "$.targets[].name")
    return result


def _render_text(template: str, values: Mapping[str, str]) -> bytes:
    def replace(match: re.Match[str]) -> str:
        key = match.group(1)
        if key not in values:
            _fail("HOMEBREW_RENDER_INTERNAL")
        return values[key]

    return _PLACEHOLDER.sub(replace, template).encode("utf-8")


def render_python_wheel_formula(plan: Mapping[str, Any]) -> tuple[str, bytes, dict[str, str]]:
    """Render the formula for an in-process plan with verified release evidence."""
    from rs9.instance import record_sha256

    intent = plan["normalizedIntent"]
    binding = plan["releaseEvidence"]
    receipt = binding["receipt"]
    if (plan["inputs"]["normalized_sha256"] != record_sha256(intent)
            or binding["normalizedSha256"] != plan["inputs"]["normalized_sha256"]):
        _fail("HOMEBREW_RENDER_PROVENANCE")
    _, _, repository, summary = _validate_project(intent)
    license_expression = _validate_license(intent)
    command, interface = _validate_commands(intent)
    version = _version(intent["version"], field="$.version")
    if (interface != "cli" or receipt["repository"] != repository or receipt["command"] != command
            or receipt["version"] != version or receipt["license"] != license_expression
            or receipt["requiresPython"] not in {">=3.11", ">=3.12", ">=3.13", ">=3.14"}
            or "status" in intent["license"]):
        _fail("HOMEBREW_RENDER_PYTHON_PROFILE")
    if not any(check["argv"] == [command, "--version"] and check["expect-exit"] == 0
               and check["requires-display"] is False and check.get("expect-stdout-contains") == version
               for check in intent["checks"]):
        _fail("HOMEBREW_RENDER_PYTHON_VERSION_CHECK")

    target, = intent["targets"]
    package = _slug(target["name"], field="$.targets[].name")
    source, wheel = binding["assets"]
    homepage = "https://github.com/" + repository
    base = homepage + "/releases/download/v" + version + "/"
    wheel_name = _text(wheel["name"], field="$.wheel.name", max_bytes=512)
    values = {
        "CLASS": _class_name(package),
        "DESC": summary,
        "HOMEPAGE": _url(homepage, field="$.project.repository"),
        "SOURCEURL": _url(base + source["name"], field="$.sdist.url", expected_basename=source["name"]),
        "SOURCESHA": _hash(source["sha256"], field="$.sdist.sha256"),
        "WHEELURL": _url(base + wheel_name, field="$.wheel.url", expected_basename=wheel_name),
        "WHEELSHA": _hash(wheel["sha256"], field="$.wheel.sha256"),
        "WHEELNAME": wheel_name,
        "VERSION": version,
        "LICENSE": license_expression,
        "COMMAND": command,
    }
    template = {"id": "homebrew-python-wheel", "version": TEMPLATE_VERSION,
                "sha256": _sha256(_PYTHON_WHEEL_TEMPLATE.encode("utf-8"))}
    return f"Formula/{package}.rb", _render_text(_PYTHON_WHEEL_TEMPLATE, values), template


def render_homebrew_formula(normalized: Mapping[str, Any], payload: Mapping[str, Any], *, variant: str) -> dict[str, Any]:
    """Render one bounded Homebrew formula and its unsigned manifest.

    ``normalized`` is the current ``rs9.normalized-tenant.v1alpha1`` record;
    ``payload`` is the selected archive's closed facts.  The return value has
    ``manifest`` and ``files`` keys.  No filesystem, network, subprocess, or
    Homebrew operation is performed.
    """
    if not isinstance(variant, str) or variant not in VARIANTS:
        _fail("HOMEBREW_RENDER_VARIANT", "$.variant")
    normalized_bytes, normalized = _canonical_snapshot(normalized)
    normalized = _mapping(normalized, field="$", allowed={"schema", "project", "license", "commands", "checks", "desktop", "runtime", "tag", "version", "release", "assets", "targets", "evidence"}, required={"schema", "project", "license", "commands", "checks", "tag", "version", "release", "assets", "targets"})
    if normalized["schema"] != SCHEMA_NORMALIZED:
        _fail("HOMEBREW_RENDER_SCHEMA", "$.schema")
    project, project_id, repository, summary = _validate_project(normalized)
    version = _version(normalized["version"], field="$.version")
    tag = _text(normalized["tag"], field="$.tag", max_bytes=128)
    release = _mapping(normalized["release"], field="$.release", allowed={"tag", "version", "prerelease", "evidence"}, required={"tag", "version", "prerelease"})
    if (release["tag"] != tag or _version(release["version"], field="$.release.version") != version
            or not isinstance(release["prerelease"], str)
            or release["prerelease"] not in {"reject", "allow"}):
        _fail("HOMEBREW_RENDER_RELEASE", "$.release")
    license_expression = _validate_license(normalized)
    license_intent_status = normalized["license"].get("status", "declared")
    command, interface = _validate_commands(normalized)
    assets = _validate_assets(normalized)
    target, asset = _selected_target(normalized, assets, command)
    facts, payload_bytes = _payload_facts(payload, license_expression=license_expression, asset=asset, version=version)
    payload_bytes_sha256 = _sha256(payload_bytes) if payload_bytes is not None else None

    if variant == VARIANT_CLI and interface != "cli":
        _fail("HOMEBREW_RENDER_VARIANT", "$.commands[0].interface")
    if variant == VARIANT_CLI and asset["commands"].get(command) != "bin/" + command:
        _fail("HOMEBREW_RENDER_ASSET", "$.assets[].commands")
    if variant == VARIANT_TAURI:
        if (project_id, version, license_expression, command, interface, target["name"]) != (
            "theme-forge-nebular-fusion", "0.6.1", "AGPL-3.0-or-later", "tfnf", "gui", "theme-forge-nebular-fusion"
        ):
            _fail("HOMEBREW_RENDER_VARIANT", "$.project")

    template_id, template = _TEMPLATES[variant]
    homepage = _url("https://github.com/" + repository, field="$.project.repository")
    values = {
        "CLASS": _class_name(target["name"]),
        "DESC": summary if variant == VARIANT_CLI else "CLI launcher for the Nebular Fusion desktop workbench",
        "HOMEPAGE": homepage,
        "URL": facts["url"],
        "SHA": facts["sha256"],
        "LICENSE": facts["license"],
        "COMMAND": command if variant == VARIANT_CLI else "tfnf",
        "VERSION": version,
    }
    formula = _render_text(template, values)
    path = "Formula/" + target["name"] + ".rb"
    manifest = {
        "schema": SCHEMA_RENDER,
        "status": "unsigned-candidate",
        "publication_enabled": False,
        "variant": variant,
        "license_intent_status": license_intent_status,
        "blockers": ["tenant-license-unresolved"] if license_intent_status == "unresolved" else [],
        "template": {"id": template_id, "version": TEMPLATE_VERSION, "sha256": _sha256(template.encode("utf-8"))},
        "inputs": {
            "normalized_sha256": _sha256(normalized_bytes),
            "payload_facts_sha256": _sha256(_canonical_json(facts)),
            "payload_bytes_sha256": payload_bytes_sha256,
        },
        "files": [{"path": path, "size": len(formula), "sha256": _sha256(formula), "mode": "100644"}],
        "qualified": False,
    }
    return {"manifest": manifest, "files": {path: formula}}


def render_homebrew_bundle(requests: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Render bounded requests and reject any deterministic output collision."""
    if isinstance(requests, (str, bytes)) or not isinstance(requests, Sequence) or not requests:
        _fail("HOMEBREW_RENDER_BUNDLE", "$.requests")
    if len(requests) > MAX_BUNDLE_REQUESTS:
        _fail("HOMEBREW_RENDER_LIMIT", "$.requests")
    files: dict[str, bytes] = {}
    manifests = []
    for index, request in enumerate(requests):
        item = _mapping(request, field=f"$.requests[{index}]", allowed={"normalized", "payload", "variant"}, required={"normalized", "payload", "variant"})
        result = render_homebrew_formula(item["normalized"], item["payload"], variant=item["variant"])
        result_files = result["files"]
        if set(files) & set(result_files):
            _fail("HOMEBREW_RENDER_COLLISION", f"$.requests[{index}]")
        files.update(result_files)
        manifests.append(result["manifest"])
    return {"schema": SCHEMA_BUNDLE, "status": "unsigned-candidate", "publication_enabled": False, "renders": manifests, "files": files}


__all__ = [
    "SCHEMA_BUNDLE",
    "SCHEMA_RENDER",
    "TEMPLATE_VERSION",
    "VARIANT_CLI",
    "VARIANT_TAURI",
    "render_homebrew_bundle",
    "render_homebrew_formula",
]
