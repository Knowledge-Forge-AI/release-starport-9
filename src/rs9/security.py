"""Security checks: credential detection, path traversal, slugs, and safe templates."""

from __future__ import annotations

import re
import unicodedata
from typing import Any

from rs9.errors import ContractError

# Slug patterns
SLUG_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
REPO_RE = re.compile(r"^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$")
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+(\.[0-9]+)?(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$")

# Ecosystem package name patterns
ECOSYSTEM_NAME_PATTERNS: dict[str, re.Pattern[str]] = {
    "npm": re.compile(r"^(@[a-z0-9][a-z0-9_.-]*/)?[a-z0-9][a-z0-9_.-]*$"),
    "pypi": re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?$"),
    "nix": re.compile(r"^[a-zA-Z0-9_.-]+$"),
    "homebrew": re.compile(r"^[a-z0-9+_-]+$"),
    "pacman": re.compile(r"^[a-z0-9][a-z0-9+._-]*$"),
    "dnf": re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9+._-]*$"),
    "apt": re.compile(r"^[a-z0-9][a-z0-9+.-]*$"),
}

# Credential patterns
CREDENTIAL_KEY_RE = re.compile(
    r"(?i)(secret|token|password|passwd|passphrase|private_key|private-key|privatekey|api_key|apikey|credential|credentials|auth|access_token|ssh_key|signing_key)"
)

PRIVATE_BLOCK_RE = re.compile(
    r"-----" r"BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY(?: BLOCK)?-----|"
    r"-----" r"BEGIN OPENSSH PRIVATE KEY-----|"
    r"-----" r"BEGIN PGP PRIVATE KEY BLOCK-----"
)

TOKEN_PATTERNS = [
    re.compile(r"ghp_[A-Za-z0-9]{36}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{82}"),
    re.compile(r"gh[orsu]_[A-Za-z0-9]{36}"),
    re.compile(r"npm_[A-Za-z0-9]{36}"),
    re.compile(r"pypi-[A-Za-z0-9_-]{50,}"),
    re.compile(r"xox[baprs]-[0-9a-zA-Z-]{10,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"ASIA[0-9A-Z]{16}"),
    re.compile(r"Bearer\s+[A-Za-z0-9._~+/-]{20,}"),
]


def scan_for_credentials(text: str) -> None:
    """Scan raw text for private key blocks and realistic tokens."""
    if PRIVATE_BLOCK_RE.search(text):
        raise ContractError(
            "CREDENTIAL_DETECTED",
            "Private key block detected in configuration",
        )
    for pattern in TOKEN_PATTERNS:
        if pattern.search(text):
            raise ContractError(
                "CREDENTIAL_DETECTED",
                "Credential token pattern detected in configuration",
            )


def scan_keys_for_credentials(data: Any, path: tuple[str, ...] = ()) -> None:
    """Screen decoded values and keys, allowing declared command identifiers."""
    if isinstance(data, dict):
        for key, value in data.items():
            if not isinstance(key, str):
                continue
            scan_for_credentials(key)
            if path != ("assets", "commands") and CREDENTIAL_KEY_RE.search(key):
                raise ContractError(
                    "CREDENTIAL_DETECTED",
                    "Credential-like key name detected in configuration",
                )
            scan_keys_for_credentials(value, path + (key,))
    elif isinstance(data, list):
        for item in data:
            scan_keys_for_credentials(item, path)
    elif isinstance(data, str):
        scan_for_credentials(data)


def validate_nfc_string(value: str) -> None:
    """Reject operational strings that normalization would silently change."""
    if unicodedata.normalize("NFC", value) != value:
        raise ContractError("NON_NFC_STRING", "Check text must use NFC normalization")


def validate_slug(value: Any, context: str = "identifier") -> None:
    """Validate that a value is a non-empty lowercase slug."""
    if not isinstance(value, str):
        raise ContractError(
            "INVALID_TYPE",
            f"Field '{context}' must be a string",
        )
    if not SLUG_RE.fullmatch(value):
        raise ContractError(
            "INVALID_SLUG",
            f"Field '{context}' must be a lowercase slug",
        )


def validate_repository(value: Any) -> None:
    """Validate that value is in Owner/Repo format."""
    if not isinstance(value, str):
        raise ContractError(
            "INVALID_TYPE",
            "Field 'repository' must be a string",
        )
    if not REPO_RE.fullmatch(value) or any(p in (".", "..") for p in value.split("/")):
        raise ContractError(
            "INVALID_REPOSITORY",
            "Field 'repository' must be in Owner/Repo format",
        )


def validate_ecosystem_name(adapter: str, name: Any) -> None:
    """Validate ecosystem package name according to adapter conventions."""
    if not isinstance(name, str):
        raise ContractError(
            "INVALID_TYPE",
            "Package name must be a string",
        )
    pattern = ECOSYSTEM_NAME_PATTERNS.get(adapter)
    if not pattern or not pattern.fullmatch(name):
        raise ContractError(
            "INVALID_ECOSYSTEM_NAME",
            "Invalid package name for adapter ecosystem",
        )


def validate_safe_relative_posix_path(path: Any, context: str = "path") -> None:
    """Validate that a path is a safe relative POSIX path."""
    if not isinstance(path, str):
        raise ContractError(
            "INVALID_TYPE",
            f"Field '{context}' must be a string",
        )
    if not path:
        raise ContractError(
            "UNSAFE_PATH",
            f"Field '{context}' must not be empty",
        )
    if unicodedata.normalize("NFC", path) != path:
        raise ContractError("NON_NFC_PATH", "Path must use NFC normalization")
    if "\\" in path:
        raise ContractError(
            "UNSAFE_PATH",
            f"Field '{context}' must not contain backslashes",
        )
    if path.startswith("/"):
        raise ContractError(
            "UNSAFE_PATH",
            f"Field '{context}' must be a relative path",
        )
    if any(ord(c) < 32 or ord(c) == 127 for c in path):
        raise ContractError(
            "UNSAFE_PATH",
            f"Field '{context}' contains control characters",
        )
    parts = path.split("/")
    for part in parts:
        if part == "" or part == "." or part == "..":
            raise ContractError(
                "UNSAFE_PATH",
                f"Field '{context}' contains invalid or directory-traversal segments",
            )


def validate_safe_basename(name: Any, context: str = "name") -> None:
    """Validate that a string is a safe basename."""
    if not isinstance(name, str):
        raise ContractError(
            "INVALID_TYPE",
            f"Field '{context}' must be a string",
        )
    if not name:
        raise ContractError(
            "UNSAFE_PATH",
            f"Field '{context}' must not be empty",
        )
    if unicodedata.normalize("NFC", name) != name:
        raise ContractError("NON_NFC_PATH", "Name must use NFC normalization")
    if "/" in name or "\\" in name:
        raise ContractError(
            "UNSAFE_PATH",
            f"Field '{context}' must not contain slashes or backslashes",
        )
    if name in (".", ".."):
        raise ContractError(
            "UNSAFE_PATH",
            f"Field '{context}' cannot be '.' or '..'",
        )
    if any(ord(c) < 32 or ord(c) == 127 for c in name):
        raise ContractError(
            "UNSAFE_PATH",
            f"Field '{context}' contains control characters",
        )


def validate_template(
    template: Any,
    required_exact_version: bool = True,
    context: str = "template",
) -> None:
    """Validate placeholder template strings."""
    if not isinstance(template, str):
        raise ContractError(
            "INVALID_TYPE",
            f"Field '{context}' must be a string",
        )
    if not template:
        raise ContractError(
            "MALFORMED_TEMPLATE",
            f"Field '{context}' must not be empty",
        )

    # Check for unmatched or malformed braces
    open_count = template.count("{")
    close_count = template.count("}")
    if open_count != close_count:
        raise ContractError(
            "MALFORMED_TEMPLATE",
            f"Field '{context}' contains unbalanced braces",
        )

    placeholders = re.findall(r"\{([^}]*)\}", template)
    remainder = template.replace("{version}", "")
    if "{" in remainder or "}" in remainder:
        raise ContractError("MALFORMED_TEMPLATE", "Malformed placeholder braces")
    for p in placeholders:
        if p != "version":
            raise ContractError(
                "MALFORMED_TEMPLATE",
                f"Field '{context}' contains unsupported placeholder",
            )

    version_count = placeholders.count("version")
    if required_exact_version and version_count != 1:
        raise ContractError(
            "MALFORMED_TEMPLATE",
            f"Field '{context}' must contain exactly one {{version}} placeholder",
        )
    if not required_exact_version and version_count > 1:
        raise ContractError(
            "MALFORMED_TEMPLATE",
            f"Field '{context}' cannot contain multiple {{version}} placeholders",
        )


def validate_version_string(version: Any) -> None:
    """Validate that version is a safe semver-like string."""
    if not isinstance(version, str):
        raise ContractError(
            "INVALID_TYPE",
            "Version must be a string",
        )
    if not version:
        raise ContractError(
            "INVALID_VERSION",
            "Version must not be empty",
        )
    if "/" in version or "\\" in version or ".." in version:
        raise ContractError(
            "INVALID_VERSION",
            "Version string cannot contain path traversal or slashes",
        )
    if "{" in version or "}" in version:
        raise ContractError(
            "INVALID_VERSION",
            "Version string cannot contain template braces",
        )
    if any(c.isspace() or ord(c) < 32 for c in version):
        raise ContractError(
            "INVALID_VERSION",
            "Version string cannot contain whitespace or control characters",
        )
    if not VERSION_RE.fullmatch(version):
        raise ContractError(
            "INVALID_VERSION",
            "Version string must be in safe semver-like format",
        )
