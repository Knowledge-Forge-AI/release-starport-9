"""Contract error definitions with stable error codes and sanitized messages."""

from __future__ import annotations

import re


def safe_details(details):
    """Closed, bounded public identifiers only; reject credentials and host paths."""
    from rs9.security import scan_for_credentials, validate_safe_relative_posix_path
    allowed = {"stage", "project", "asset", "command", "command_kind", "archive_path",
               "member_type", "mode", "size", "sha256", "reason"}
    result, dropped = {}, False
    if not isinstance(details, dict):
        return {}
    for key, value in list(details.items())[:16]:
        if key == "details_truncated" and value is True:
            dropped = True
            continue
        if key not in allowed:
            dropped = True
            continue
        if type(value) is int and key in {"mode", "size"} and 0 <= value <= 1024 ** 3:
            result[key] = value
            continue
        if (not isinstance(value, str) or not 1 <= len(value) <= 256
                or not re.fullmatch(r"[A-Za-z0-9_./:@+ -]+", value)
                or re.match(r"[A-Za-z]:", value)):
            dropped = True
            continue
        try:
            validate_safe_relative_posix_path(value)
            scan_for_credentials(value)
        except ContractError:
            dropped = True
            continue
        result[key] = value
    if dropped or len(details) > 16:
        result["details_truncated"] = True
    return result


class ContractError(Exception):
    """Exception raised for .rs9 contract validation and normalization failures.

    Contract error messages must never echo untrusted input values to avoid
    credential or sensitive data leakage in error reporting.
    """

    def __init__(self, code: str, message: str, *, details=None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = safe_details(details)

    def with_details(self, **details):
        return ContractError(self.code, self.message, details={**self.details, **details})

    def __str__(self) -> str:
        return f"[{self.code}] {self.message}"

    def __repr__(self) -> str:
        return f"ContractError(code={self.code!r}, message={self.message!r})"
