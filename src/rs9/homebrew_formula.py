"""Narrow deterministic static maintained-formula parser and release identity comparison.

Evaluates Homebrew formula syntax strictly without executing arbitrary Ruby.
Exact full agreement confirms live projection identity; schema or identity
mismatches produce conflict.
"""
import hashlib
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from rs9.errors import ContractError


def formula_class_name(formula_name: str) -> str:
    """Derive standard Homebrew Formula class name from package name."""
    if not isinstance(formula_name, str) or not formula_name:
        raise ContractError("HOMEBREW_FORMULA", "Non-empty formula name required")
    # CamelCase: split on hyphens and underscores, capitalize each segment
    parts = re.split(r"[-_]+", formula_name)
    return "".join(part.capitalize() for part in parts if part)


def parse_formula(content: str | bytes) -> Dict[str, Any]:
    """Deterministically parse a static maintained Homebrew formula.

    Extracts class name, desc, homepage, url, sha256, license, dependencies,
    architecture/OS restrictions, and referenced commands.
    Fails closed with ContractError on schema violation or missing required fields.
    """
    if isinstance(content, bytes):
        try:
            text = content.decode("utf-8")
        except UnicodeError:
            raise ContractError("HOMEBREW_FORMULA_SCHEMA", "Strict UTF-8 formula required") from None
    elif isinstance(content, str):
        text = content
    else:
        raise ContractError("HOMEBREW_FORMULA_SCHEMA", "Formula text required")
    if len(text.encode("utf-8")) > 64 * 1024 or "\r" in text or "\x00" in text:
        raise ContractError("HOMEBREW_FORMULA_SCHEMA", "Bounded LF formula required")
    lines = text.splitlines()
    if not lines or not re.fullmatch(r"class [A-Za-z][A-Za-z0-9]* < Formula", lines[0]) or lines[-1] != "end":
        raise ContractError("HOMEBREW_FORMULA_SCHEMA", "One maintained Formula class required")
    class_name = lines[0].split()[1]
    facts, blocks = {}, {}
    dependencies, arch_restrictions, os_restrictions = [], [], []
    current, body = None, []
    for line in lines[1:-1]:
        if current is not None:
            if line == "  end":
                blocks[current] = "\n".join(body) + "\n"
                current, body = None, []
            else:
                if line and not line.startswith("    "):
                    raise ContractError("HOMEBREW_FORMULA_SCHEMA", "Maintained block indentation required")
                body.append(line)
            continue
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        headers = {"  def install": "install", "  test do": "test", "  def caveats": "caveats"}
        if line in headers:
            current = headers[line]
            if current in blocks:
                raise ContractError("HOMEBREW_FORMULA_SCHEMA", "Duplicate formula block")
            continue
        scalar = re.fullmatch(r'  (desc|homepage|url|sha256|license|version) "([^"\\]*)"', line)
        if scalar:
            key, value = scalar.groups()
            if key in facts or not value or "#{" in value:
                raise ContractError("HOMEBREW_FORMULA_SCHEMA", "Unique static formula facts required")
            from rs9.records import validate_sanitized_string
            validate_sanitized_string(value)
            facts[key] = value
            continue
        if line == '  depends_on "node"':
            destination, value = dependencies, "node"
        elif line == "  depends_on arch: :arm64":
            destination, value = arch_restrictions, "arm64"
        elif line == "  depends_on :macos":
            destination, value = os_restrictions, "macos"
        else:
            raise ContractError("HOMEBREW_FORMULA_SCHEMA", "Unknown formula directive")
        if value in destination:
            raise ContractError("HOMEBREW_FORMULA_SCHEMA", "Duplicate formula restriction")
        destination.append(value)
    if current is not None or not {"url", "sha256", "license"} <= facts.keys() or not {"install", "test"} <= blocks.keys():
        raise ContractError("HOMEBREW_FORMULA_SCHEMA", "Required formula facts and blocks missing")
    if not re.fullmatch(r"[0-9a-f]{64}", facts["sha256"]):
        raise ContractError("HOMEBREW_FORMULA_SCHEMA", "Canonical sha256 required")
    url, sha256, license_val = facts["url"], facts["sha256"], facts["license"]
    desc, homepage = facts.get("desc"), facts.get("homepage")
    text = "\n".join(blocks.values())

    # Referenced commands
    commands: Set[str] = set()
    # (bin/"cmd").write
    for m in re.finditer(r'\(bin/["\']([^"\']+)["\']\)\.write', text):
        commands.add(m.group(1))
    # bin/"cmd"
    for m in re.finditer(r'bin/["\']([^"\']+)["\']', text):
        commands.add(m.group(1))
    # #{bin}/cmd
    for m in re.finditer(r'#\{bin\}/([a-zA-Z0-9_-]+)', text):
        commands.add(m.group(1))

    # Check for bin.install_symlink Dir["#{libexec}/bin/*"]
    has_symlink_all_bins = bool(re.search(r'bin\.install_symlink\s+Dir\[["\']#\{libexec\}/bin/\*["\']\]', text))

    return {
        "class_name": class_name,
        "desc": desc,
        "homepage": homepage,
        "url": url,
        "sha256": sha256,
        "license": license_val,
        "dependencies": sorted(set(dependencies)),
        "arch_restrictions": sorted(set(arch_restrictions)),
        "os_restrictions": sorted(set(os_restrictions)),
        "referenced_commands": sorted(commands),
        "has_symlink_all_bins": has_symlink_all_bins,
        "block_sha256": {key: hashlib.sha256(value.encode()).hexdigest() for key, value in blocks.items()},
    }


def compare_formula_identity(
    parsed_formula: Dict[str, Any],
    expected: Dict[str, Any],
) -> Tuple[bool, List[str]]:
    """Compare parsed formula attributes against authenticated release expectations.

    Returns (is_exact, reasons_for_conflict).
    Full agreement across all expected fields returns (True, []).
    Any discrepancy returns (False, [reason_descriptions...]).
    """
    reasons: List[str] = []

    # 1. Product / Class Name
    expected_project = expected.get("project")
    if expected_project:
        expected_class = formula_class_name(expected_project)
        if parsed_formula.get("class_name") != expected_class:
            reasons.append("class name identity mismatch")

    # 2. Payload URL
    expected_url = expected.get("payload_url")
    if expected_url:
        allowed_urls = {expected_url} if isinstance(expected_url, str) else set(expected_url)
        if parsed_formula.get("url") not in allowed_urls:
            reasons.append("payload URL mismatch")

    # 3. Payload SHA256
    expected_sha = expected.get("payload_sha256")
    if expected_sha:
        if parsed_formula.get("sha256", "").lower() != expected_sha.lower():
            reasons.append(f"payload SHA256 mismatch: observed {parsed_formula.get('sha256')} != expected {expected_sha}")

    # 4. License
    expected_license = expected.get("license")
    if expected_license:
        if parsed_formula.get("license") != expected_license:
            reasons.append("license mismatch")

    # 5. Restrictions (arch, OS, runtime)
    expected_restrictions = expected.get("restrictions")
    if expected_restrictions:
        if isinstance(expected_restrictions, str):
            expected_restrictions = [expected_restrictions]
        for restr in expected_restrictions:
            if restr in ("aarch64-darwin", "macos-arm64"):
                if "arm64" not in parsed_formula.get("arch_restrictions", []) or "macos" not in parsed_formula.get("os_restrictions", []):
                    reasons.append("formula lacks required macOS arm64 restrictions (depends_on arch: :arm64, :macos)")
            elif restr in ("node", "nodejs"):
                if "node" not in parsed_formula.get("dependencies", []):
                    reasons.append("formula lacks required node dependency (depends_on 'node')")

    if expected_restrictions:
        restrictions = {expected_restrictions} if isinstance(expected_restrictions, str) else set(expected_restrictions)
        if restrictions <= {"node", "nodejs"}:
            exact_restrictions = (parsed_formula.get("dependencies") == ["node"]
                                  and not parsed_formula.get("arch_restrictions") and not parsed_formula.get("os_restrictions"))
        elif restrictions <= {"aarch64-darwin", "macos-arm64"}:
            exact_restrictions = (not parsed_formula.get("dependencies")
                                  and parsed_formula.get("arch_restrictions") == ["arm64"]
                                  and parsed_formula.get("os_restrictions") == ["macos"])
        else:
            exact_restrictions = False
        if not exact_restrictions:
            reasons.append("formula restriction set mismatch")

    # 6. Commands / Binaries
    expected_commands = expected.get("commands")
    if expected_commands is not None:
        exp_cmds = set(expected_commands.keys()) if isinstance(expected_commands, dict) else set(expected_commands)
        obs_cmds = set(parsed_formula.get("referenced_commands", []))
        if parsed_formula.get("has_symlink_all_bins"):
            # All bins symlinked; if commands referenced in test, they must be part of expected
            if obs_cmds and not (obs_cmds <= exp_cmds):
                reasons.append(f"formula references unapproved commands: {sorted(obs_cmds - exp_cmds)}")
        else:
            if obs_cmds != exp_cmds:
                reasons.append(f"formula commands {sorted(obs_cmds)} != expected {sorted(exp_cmds)}")

    # 7. Git Blob SHA (if formula data and expected blob sha provided)
    data = expected.get("data")
    expected_blob_sha = expected.get("blob_sha")
    if expected_blob_sha and data is not None:
        blob_sha = hashlib.sha1(f"blob {len(data)}\0".encode() + data).hexdigest()
        if blob_sha != expected_blob_sha:
            reasons.append(f"formula git blob SHA {blob_sha} != expected {expected_blob_sha}")

    # 8. Formula SHA256 (if formula data and expected formula sha256 provided)
    expected_formula_sha256 = expected.get("formula_sha256")
    if expected_formula_sha256 and data is not None:
        actual_sha256 = hashlib.sha256(data).hexdigest()
        if actual_sha256 != expected_formula_sha256:
            reasons.append(f"formula SHA256 {actual_sha256} != expected {expected_formula_sha256}")

    return len(reasons) == 0, reasons
