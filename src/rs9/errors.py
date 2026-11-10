"""Contract error definitions with stable error codes and sanitized messages."""

from __future__ import annotations

import re


APT_ACTIVITY_VALUES = frozenset({
    "index-hit", "fetch", "fetch-ignored", "fetched", "package-lists",
    "dependency-tree", "state-information", "download-plan", "select",
    "unpack", "configure", "triggers", "unknown",
})

APT_FETCH_ORIGINS = frozenset({"archive", "security", "ports"})
APT_FETCH_SUITES = frozenset({
    "resolute", "resolute-updates", "resolute-security", "resolute-backports",
})
APT_FETCH_COMPONENTS = frozenset({"main", "restricted", "universe", "multiverse"})
APT_FETCH_INDEX_ARCHITECTURES = frozenset({"amd64", "arm64"})
APT_FETCH_PACKAGE_ARCHITECTURES = frozenset({"amd64", "arm64", "all"})
APT_FETCH_KINDS = frozenset({"inrelease", "packages", "package"})
_APT_FETCH_PACKAGE_NAME = re.compile(r"[a-z0-9][a-z0-9+.-]{1,127}", re.ASCII)


def validate_apt_fetch(value):
    """Return one exact, closed APT fetch descriptor or ``None``."""
    if type(value) is not dict or any(type(key) is not str for key in value) or type(value.get("origin")) is not str:
        return None
    origin = value["origin"]
    suite = value.get("suite")
    kind = value.get("kind")
    if (origin not in APT_FETCH_ORIGINS or type(suite) is not str
            or suite not in APT_FETCH_SUITES or type(kind) is not str
            or kind not in APT_FETCH_KINDS):
        return None
    if kind == "inrelease":
        keys = ("origin", "suite", "kind")
    elif kind == "packages":
        keys = ("origin", "suite", "kind", "component", "architecture")
    else:
        keys = ("origin", "suite", "kind", "component", "index_architecture", "package_architecture", "package")
    if set(value) != set(keys):
        return None
    if kind != "inrelease":
        component = value.get("component")
        if type(component) is not str or component not in APT_FETCH_COMPONENTS:
            return None
    if kind == "packages":
        architecture = value.get("architecture")
        if type(architecture) is not str or architecture not in APT_FETCH_INDEX_ARCHITECTURES:
            return None
    if kind == "package":
        index_architecture = value.get("index_architecture")
        package_architecture = value.get("package_architecture")
        if (type(index_architecture) is not str or index_architecture not in APT_FETCH_INDEX_ARCHITECTURES
                or type(package_architecture) is not str or package_architecture not in APT_FETCH_PACKAGE_ARCHITECTURES):
            return None
        package = value.get("package")
        if (type(package) is not str or not _APT_FETCH_PACKAGE_NAME.fullmatch(package)):
            return None
        from rs9.security import scan_for_credentials
        try:
            scan_for_credentials(package)
        except ContractError:
            return None
        if re.fullmatch(r"[a-f0-9]{40,64}", package):
            return None
    return {key: value[key] for key in keys}


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
    allowed.update({"missing_path", "node_version", "probe_id", "expected_exit", "stdout_matches",
                    "stderr_matches", "observed_architecture", "observed_name", "observed_version",
                    "userns_policy", "code", "message_sha256"})
    allowed.update({"observed_field_count", "observed_field_tokens", "observed_fields_truncated"})
    allowed.update({"cause", "limit", "observed", "maximum", "counters", "max"})
    allowed.update({"elapsed_ms", "deadline_seconds"})
    allowed.update({"field_path", "rule", "package_sha256", "spec_sha256"})
    allowed.update({"target", "errno", "causal_code", "causal_substage",
                    "writer_is_owner", "owner_is_root", "group_matches", "target_exists",
                    "parent_mode", "target_mode"})
    allowed.update({"path", "path_sha256"})
    allowed.update({"scenario", "diagnostic_sha256"})
    allowed.add("apt_activity")
    allowed.add("apt_fetch")
    allowed.add("stream_custody")
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
        if key == "stream_custody":
            from rs9.bounded_process import valid_stream_custody
            if valid_stream_custody(value):
                result[key] = {**value, "stdout": dict(value["stdout"]), "stderr": dict(value["stderr"])}
            else:
                dropped = True
            continue
        if key == "field_path":
            # JSON pointer components name logical fields, never host locations.
            if (isinstance(value, str) and len(value) <= 1024
                    and re.fullmatch(r"(?:/[A-Za-z0-9_.~<>-]+)*|\$(?:\.[A-Za-z0-9_<>-]+|\[[0-9]+\])*", value)
                    and not re.search(r"/(?:Users|home|root|private|tmp)/", value)):
                result[key] = value
            else:
                dropped = True
            continue
        if key in {"writer_is_owner", "owner_is_root", "group_matches", "target_exists"}:
            if type(value) is bool:
                result[key] = value
            else:
                dropped = True
            continue
        if key in {"parent_mode", "target_mode"}:
            if isinstance(value, str) and re.fullmatch(r"0[0-7]{3,4}", value):
                result[key] = value
            else:
                dropped = True
            continue
        if key == "errno":
            if isinstance(value, str) and re.fullmatch(r"E[A-Z0-9_]{1,31}|unknown", value):
                result[key] = value
            else:
                dropped = True
            continue
        if key == "scenario":
            if isinstance(value, str) and value in {"A", "B", "C", "C-signal"}:
                result[key] = value
            else:
                dropped = True
            continue
        if key == "apt_activity":
            if isinstance(value, str) and value in APT_ACTIVITY_VALUES:
                result[key] = value
            else:
                dropped = True
            continue
        if key == "apt_fetch":
            descriptor = validate_apt_fetch(value)
            if descriptor is not None:
                result[key] = descriptor
            else:
                dropped = True
            continue
        if key == "elapsed_ms":
            if type(value) is int and 0 <= value <= 86400 * 1000 * 7:
                result[key] = value
            else:
                dropped = True
            continue
        if key == "deadline_seconds":
            if type(value) is int and 0 <= value <= 86400 * 7:
                result[key] = value
            else:
                dropped = True
            continue
        if key in {"observed", "maximum"}:
            if type(value) is int and 0 <= value < 2**64:
                result[key] = value
            else:
                dropped = True
            continue
        if key in {"cause", "limit"}:
            if isinstance(value, str) and re.fullmatch(r"[a-z][a-z0-9-]{0,63}", value):
                result[key] = value
            else:
                dropped = True
            continue
        if key in {"counters", "max"}:
            fields = ({"dir_count", "entries", "file_count", "hardlink_count", "special_count",
                       "symlink_count", "total_hashed_bytes", "scanned_entries", "excluded_files"}
                      if key == "counters" else
                      {"depth", "file_bytes", "path_bytes", "symlink_bytes", "directory_entries"})
            if (type(value) is dict and set(value) <= fields
                    and all(type(n) is int and 0 <= n < 2**64 for n in value.values())):
                result[key] = dict(sorted(value.items()))
            else:
                dropped = True
            continue
        if key == "observed_field_count":
            if type(value) is int and 1 <= value <= 1024 ** 3:
                result[key] = value
            else:
                dropped = True
            continue
        if key == "observed_fields_truncated":
            if type(value) is bool:
                result[key] = value
            else:
                dropped = True
            continue
        if key == "observed_field_tokens":
            if (not isinstance(value, list) or not 1 <= len(value) <= 6
                    or any(not isinstance(token, str) or len(token) > 64
                           or not re.fullmatch(r"[A-Za-z0-9_.+-]*", token) for token in value)):
                dropped = True
                continue
            try:
                for token in value:
                    if token:
                        validate_safe_relative_posix_path(token)
                        scan_for_credentials(token)
            except ContractError:
                dropped = True
                continue
            result[key] = list(value)
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
                     or (key == "operation" and isinstance(value, str) and value in {
                         "rpm-repository", "repository-metadata", "package-signing",
                         "repodata-index-read", "repodata-fixture-sign", "repodata-signature-write",
                         "repodata-signature-verify", "repodata-public-modes", "repodata-ownership-audit",
                         "repodata-format-verify"})
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
        if key in {"stdout_matches", "stderr_matches"}:
            if type(value) is bool:
                result[key] = value
            else:
                dropped = True
            continue
        if key in {"exit_code", "expected_exit"}:
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
