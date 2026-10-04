"""Contract error definitions with stable error codes and sanitized messages."""

from __future__ import annotations

import re


def safe_details(details):
    """Closed, bounded public identifiers only; reject credentials and host paths."""
    from rs9.security import scan_for_credentials, validate_safe_relative_posix_path
    allowed = {"stage", "project", "asset", "command", "command_kind", "archive_path",
               "member_type", "mode", "size", "sha256", "reason", "profile",
               "expected_legal_files", "observed_legal_files",
               "operation", "host", "http_status", "transport_error", "redirect_hops"}
    allowed.update({"family", "system", "product", "product_code", "underlying_code",
                    "packaging_class", "substage", "tool", "exit_code",
                    "stdout_sha256", "stderr_sha256", "diagnostic_token", "origin",
                    "target_triple", "asset_platform", "wheel_tag", "expected_digest",
                    "actual_digest", "exception_type", "module", "frame", "traceback_sha256",
                    "destination", "cleanup"})
    allowed.update({"phase", "reason_token", "preload_sha256", "harness_sha256", "root_mode_restored", "product_errors"})
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
        if key == "cleanup":
            if isinstance(value, str) and value in {"complete", "failed", "not-needed"}:
                result[key] = value
            else:
                dropped = True
            continue
        if key == "root_mode_restored":
            if type(value) is bool:
                result[key] = value
            else:
                dropped = True
            continue
        if key == "product_errors":
            from rs9.product_classes import PRODUCT_PACKAGING_CLASSES
            if (isinstance(value, dict) and len(value) <= 4
                    and all(product in PRODUCT_PACKAGING_CLASSES and isinstance(code, str)
                            and re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", code) for product, code in value.items())):
                result[key] = dict(sorted(value.items()))
            else:
                dropped = True
            continue
        if key in {"operation", "host", "transport_error", "http_status", "redirect_hops"}:
            from rs9.github import HOSTS, REQUEST_CLASSES
            valid = ((key == "operation" and isinstance(value, str) and value in REQUEST_CLASSES)
                     or (key == "host" and isinstance(value, str) and value in HOSTS)
                     or (key == "transport_error" and value in ("timeout", "tls", "dns", "connection", "protocol", "transport"))
                     or (key == "http_status" and type(value) is int and 100 <= value <= 599)
                     or (key == "redirect_hops" and type(value) is int and 0 <= value <= 5))
            if valid:
                result[key] = value
            else:
                dropped = True
            continue
        if type(value) is int and key in {"mode", "size"} and 0 <= value <= 1024 ** 3:
            result[key] = value
            continue
        if key == "exit_code":
            if type(value) is int and -128 <= value <= 255:
                result[key] = value
            else:
                dropped = True
            continue
        if key.endswith("_sha256"):
            if isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value):
                result[key] = value
            else:
                dropped = True
            continue
        if key == "exception_type":
            if isinstance(value, str) and re.fullmatch(r"[A-Za-z_]\w{0,63}", value, re.ASCII):
                result[key] = value
            else:
                dropped = True
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
