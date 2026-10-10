"""Strict, bounded DNF5 client identity and causal NONPRODUCTION negatives.

Decisions consume full bounded receipt bytes, never diagnostic previews. Identity
readback precedes refresh, observes caches on both sides of config-only probes,
and retains only public candidate configuration and stream identities.
"""

from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any, Mapping, Sequence

from rs9.build_native import CommandReceipt
from rs9.errors import ContractError
from rs9.machine_stream import machine_text
from rs9.release_core import digest
from rs9.scratch import canonical

STREAM_LIMIT = 1024 * 1024
CONFIG_LIMIT = 128 * 1024
DNF_REPO_ID = "rs9-fedora-nonproduction"
KEY_URI = "file:///srv/rs9/keys/rs9-candidate-fixture-NONPRODUCTION.asc"
CACHE_ROOT = "/var/cache/libdnf5"
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_FINGERPRINT = re.compile(r"[0-9A-F]{40}\Z")

from rs9.dnf_commands import (DNF_PRESENTATION, DNF_VERSION, DNF_TOOL_VERSION,
    guest_prefix, command_matches, command_identities, stage_command)


def full_streams(receipt: CommandReceipt | None, *, limit=STREAM_LIMIT) -> tuple[str, str]:
    if receipt is None or len(receipt.stdout_bytes) + len(receipt.stderr_bytes) > limit:
        raise ContractError("DNF_STREAM_BOUND", "DNF decision stream missing or over bound")
    return tuple(machine_text(receipt, stream=name, limit=limit, code="DNF_STREAM_BOUND",
                              substage="dnf-decision", encoding="utf-8")
                 for name in ("stdout", "stderr"))


def environment_failure(receipt: CommandReceipt | None) -> str | None:
    """Veto environmental causes anywhere, including beyond preview limits."""
    try:
        out, err = full_streams(receipt)
    except ContractError:
        return "UNCLASSIFIED_FAILURE"
    combined = (out + "\n" + err).lower()
    if any(s in combined for s in ("no match for argument:", "unable to find a match", "no package matches")):
        return "PACKAGE_NOT_FOUND"
    if any(s in combined for s in ("skipping repository", "ignoring repository", "repository is disabled")):
        return "SOURCE_CONFIG_ERROR"
    if receipt.exit_code == 127 or "command not found" in combined:
        return "COMMAND_NOT_FOUND"
    if any(s in combined for s in ("permission denied", "could not open lock file", "are you root?")):
        return "PERMISSION_DENIED"
    if any(s in combined for s in ("unknown argument", "unknown option", "unrecognized option",
                                   "error in configuration", "invalid configuration", "malformed entry")):
        return "SOURCE_CONFIG_ERROR"
    if re.search(r"curl error\s*\(?37\)?\s*:", combined):
        return "SOURCE_CONFIG_ERROR"  # unavailable local file is not a trust failure
    if any(s in combined for s in ("network is unreachable", "could not connect", "couldn't connect",
                                   "cannot assign requested address", "could not resolve host",
                                   "temporary failure resolving", "name or service not known",
                                   "connection refused", "connection timed out", "network down",
                                   "curl error", "http://", "https://", "http/1.", "http/2",
                                   "<html", "<!doctype", "captive portal", "302 found",
                                   "403 forbidden", "401 unauthorized", "500 internal server error")):
        return "NETWORK_UNAVAILABLE"
    return None


def parse_repository_rejection(receipt, *, stage, context=None, repo_id=None,
                               source_uri=None, key_uri=None, fingerprint=None):
    """Qualification requires a complete fatal record under a bound identity."""
    if (stage not in {"refresh", "install"} or receipt is None or receipt.executed is not True
            or receipt.exit_code != 1 or environment_failure(receipt)):
        return None
    out, err = full_streams(receipt)
    if context is not None:
        probe = context.get("probe")
        if not valid_identity(probe) or not command_matches(receipt, stage, context.get("product", "RS9_PRODUCT")):
            return None
        from rs9.dnf_failure import terminal_failure
        return terminal_failure(out, err, probe["identity"])
    # Historical single-reason diagnostics can be labeled, never qualified here.
    reasons = re.findall(r"(?:>>> )?repomd\.xml GPG signature verification error: ([^\r\n]+)", out + "\n" + err)
    if reasons and (out + err).endswith("\n"):
        from rs9.dnf_failure import reason_category
        categories = {reason_category(r.strip()) if r.strip() != "Bad GPG signature" else "SIGNATURE_REJECTED" for r in reasons}
        if len(categories) == 1 and None not in categories:
            category = categories.pop()
            return {"category": category, "terminal_category": category, "intermediate_categories": [], "bootstrap_categories": []}
    return None


def repository_rejection(receipt: CommandReceipt | None, *, stage: str | None,
                         context: Mapping[str, Any] | None = None,
                         repo_id: str | None = None,
                         source_uri: str | None = None,
                         key_uri: str | None = None,
                         fingerprint: str | None = None) -> str | None:
    parsed = parse_repository_rejection(receipt, stage=stage, context=context,
                                        repo_id=repo_id, source_uri=source_uri,
                                        key_uri=key_uri, fingerprint=fingerprint)
    return parsed["category"] if parsed is not None else None


def package_checksum(receipt: CommandReceipt | None, *, stage: str | None) -> dict[str, str] | None:
    if stage != "install" or receipt is None or receipt.exit_code != 1 or environment_failure(receipt):
        return None
    out, err = full_streams(receipt)
    combined = out + "\n" + err
    if (any(s and not s.endswith("\n") for s in (out, err))
            or combined.count("Downloading successful, but checksum doesn't match.") != 1
            or combined.count("Calculated:") != 1 or combined.count("Expected:") != 1):
        return None
    # Librepo emits a space after each checksum, hence two before Expected.
    matches = re.findall(
        r"Downloading successful, but checksum doesn't match\. Calculated: "
        r"([0-9a-f]{64})\(sha256\) +Expected: ([0-9a-f]{64})\(sha256\)(?=[ \r\n]|\Z)",
        combined)
    if len(matches) != 1:
        return None
    actual, expected = matches[0]
    return {"calculated_sha256": actual, "expected_sha256": expected} if actual != expected else None


def classify_dnf(receipt: CommandReceipt | None, *, stage: str | None,
                 context: Mapping[str, Any] | None = None,
                 repo_id: str | None = None,
                 source_uri: str | None = None,
                 key_uri: str | None = None,
                 fingerprint: str | None = None) -> str:
    if receipt is None:
        return "UNCLASSIFIED_FAILURE"
    if receipt.exit_code == 0:
        return "COMMAND_SUCCESS"
    veto = environment_failure(receipt)
    if veto:
        return veto
    category = repository_rejection(receipt, stage=stage, context=context,
                                    repo_id=repo_id, source_uri=source_uri,
                                    key_uri=key_uri, fingerprint=fingerprint)
    if category:
        return category
    if package_checksum(receipt, stage=stage):
        return "PACKAGE_HASH_MISMATCH"
    out, err = full_streams(receipt)
    combined = (out + "\n" + err).lower()
    if "no match for argument:" in combined:
        return "PACKAGE_NOT_FOUND"
    if "repomd.xml" in combined and any(t in combined for t in ("parser error", "xml parse error", "invalid xml")):
        return "INDEX_CORRUPT"
    return "UNCLASSIFIED_FAILURE"


def dnf_absent(receipt: CommandReceipt | None, product: str) -> bool:
    return (receipt is not None and receipt.executed is True and receipt.exit_code == 1
            and receipt.stderr_bytes == b""
            and receipt.stdout_bytes == f"package {product} is not installed\n".encode("ascii"))


def record_dnf_stage(*, stage, product, arch, receipt, **kwargs) -> dict[str, Any]:
    from rs9.apt_diagnostics import record_command_diagnostics, safe_sample
    row = record_command_diagnostics(stage=stage, family="dnf", product=product, arch=arch,
                                     receipt=receipt, **kwargs)
    row["executed"] = receipt.executed
    try:
        out, err = full_streams(receipt)
        row["decision_stream_complete"] = True
    except ContractError:
        out, err = receipt.stdout_text, receipt.stderr_text
        row["decision_stream_complete"] = False
    for name, raw, text in (("stdout", receipt.stdout_bytes, out), ("stderr", receipt.stderr_bytes, err)):
        row[name + "_sample"] = safe_sample(text, 1024)
        row[name + "_truncated"] = len(raw) > 1024 or not row["stream_shapes"][name]["complete"]
    checksum = package_checksum(receipt, stage=stage)
    if checksum:
        row["checksum"] = checksum
    from rs9.dnf_failure import reason_category
    events = []
    for name, stream in (("stdout", out), ("stderr", err)):
        for match in re.finditer(r"(?m)^\s*(?:>>> )?repomd\.xml GPG signature verification error: ([^\r\n]+)", stream):
            events.append({"stream": name, "category": reason_category(match[1].strip()) or "UNCLASSIFIED_FAILURE"})
    if events:
        row["repository_diagnostic_events"] = events[:16]
        row["repository_diagnostic_events_complete"] = len(events) <= 16
    repo_diag = parse_repository_rejection(receipt, stage=stage)
    if repo_diag:
        if repo_diag.get("intermediate_categories"):
            row["intermediate_categories"] = repo_diag["intermediate_categories"]
            row["bootstrap_categories"] = repo_diag["intermediate_categories"]
        if repo_diag.get("terminal_category"):
            row["terminal_category"] = repo_diag["terminal_category"]
    row["environment_failure"] = environment_failure(receipt)
    return row


_KEY_CACHE_PROBE = r"""
import hashlib,json,os,stat,sys
key,cache,repo=sys.argv[1:]
for path in (key,cache):
    parent=os.path.dirname(path)
    while True:
        if not stat.S_ISDIR(os.lstat(parent).st_mode): raise ValueError('nonphysical-parent')
        if parent=='/': break
        parent=os.path.dirname(parent)
st=os.lstat(key)
if not stat.S_ISREG(st.st_mode) or st.st_size>1024*1024: raise ValueError('invalid-key-file')
fd=os.open(key,os.O_RDONLY|os.O_NOFOLLOW)
with os.fdopen(fd,'rb') as stream:
    data=stream.read(1024*1024+1)
    if len(data)>1024*1024: raise ValueError('key-bound')
count=0
if os.path.lexists(cache):
    if not stat.S_ISDIR(os.lstat(cache).st_mode): raise ValueError('nonphysical-cache')
    with os.scandir(cache) as entries:
        for i,entry in enumerate(entries):
            if i>=4096: raise ValueError('cache-bound')
            if entry.name==repo or entry.name.startswith(repo+'-'): count+=1
print(json.dumps({'key_sha256':hashlib.sha256(data).hexdigest(),'candidate_cache_entries':count}))
"""


def _config_sections(text: str) -> dict[str, dict[str, str | None]]:
    """Parse DNF5's banner dump; a bare option has an unreadable value.

    DNF5 5.2.18.0 dnf5/main.cpp emits these banners, not INI sections. Keep
    unreadable values distinct from empty strings and reject duplicate options
    even when their value was unreadable. Only allowlisted readback is retained.
    """
    result, current = {}, None
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        section = re.fullmatch(r'======== "([A-Za-z0-9_.+-]{1,128})" repository configuration: ========', line)
        if section or line == "======== Main configuration: ========":
            current = section[1] if section else "main"
            if current in result or len(result) >= 128:
                raise ValueError("ambiguous-config")
            result[current] = {}
            continue
        item = re.fullmatch(r"([A-Za-z0-9_]+)(?:\s*=\s*(.*))?", line)
        if current is None or item is None or item[1] in result[current]:
            raise ValueError("invalid-config-dump")
        result[current][item[1]] = item[2]
    return result


def _boolean(value: str | None) -> bool:
    if not isinstance(value, str):
        raise ValueError("unreadable-config-boolean")
    if value.lower() in {"true", "1"}:
        return True
    if value.lower() in {"false", "0"}:
        return False
    raise ValueError("invalid-config-boolean")


def probe_dnf_client(client, spec: Mapping[str, Any]) -> dict[str, Any]:
    """Config-only probes; no repo-list operation that could load metadata."""
    result: dict[str, Any] = {"schema": "rs9.dnf-client-identity.v1", "status": "fail", "receipts": []}
    receipts = {}
    try:
        probe_cmds = list(spec.get("dnf_probe_commands", []))
        if "probe" in spec and isinstance(spec["probe"], Mapping) and "presentation" in spec["probe"]:
            if not any(stage == "presentation" for stage, _ in probe_cmds):
                probe_cmds.append(("presentation", spec["probe"]["presentation"]))
        for stage, argv in probe_cmds:
            receipt = client.exec(argv)
            receipts[stage] = receipt
            result["receipts"].append(record_dnf_stage(stage=stage, product="client-identity", arch=spec["arch"],
                                                      receipt=receipt))
            if receipt.executed is not True:
                result.update(status="unavailable", reason="synthetic-command-seam")
                return result
            if receipt.exit_code != 0:
                result.update(status="unavailable" if receipt.exit_code == 127 else "fail",
                              reason="dnf-identity-command-failed", failed_stage=stage)
                return result
        if (spec["refresh"] != stage_command("refresh") or spec["install"]("RS9_PRODUCT") != stage_command("install")):
            raise ValueError("command-presentation-mismatch")
        decoded = {name: full_streams(r, limit=CONFIG_LIMIT)[0] for name, r in receipts.items()}
        image_receipt = client.dnf_image_identity_receipt()
        result["receipts"].append(record_dnf_stage(stage="container-image", product="client-identity",
                                                  arch=spec["arch"], receipt=image_receipt))
        if image_receipt.executed is not True:
            result.update(status="unavailable", reason="synthetic-image-seam")
            return result
        image_out, image_err = full_streams(image_receipt, limit=256)
        if (image_receipt.exit_code != 0 or image_err
                or not re.fullmatch(r"sha256:[0-9a-f]{64}\n", image_out)):
            raise ValueError("container-image-unproven")
        image_id = image_out.rstrip("\n")
        if client.image.startswith("sha256:") and image_id != client.image:
            raise ValueError("container-image-drift")
        before, after = (json.loads(decoded[n]) for n in ("cache-before", "cache-after"))
        if any(set(row) != {"key_sha256", "candidate_cache_entries"}
               or row["key_sha256"] != spec.get("expected_key_sha256")
               or type(row["candidate_cache_entries"]) is not int or row["candidate_cache_entries"] != 0
               for row in (before, after)):
            raise ValueError("key-or-cache-readback-mismatch")
        if not _SHA.fullmatch(spec.get("expected_key_sha256") or "") or not _FINGERPRINT.fullmatch(spec.get("public_fingerprint") or ""):
            raise ValueError("key-binding-missing")
        sections = _config_sections(decoded["repo-config"])
        enabled = {name for name, options in sections.items() if _boolean(options["enabled"])}
        if enabled != {DNF_REPO_ID}:
            raise ValueError("enabled-repository-set-mismatch")
        repo = sections[DNF_REPO_ID]
        if (repo["baseurl"] != spec["source_uri"] or repo["gpgkey"] != KEY_URI
                or repo.get("metalink", "") or repo.get("mirrorlist", "")
                or not _boolean(repo["repo_gpgcheck"]) or _boolean(repo["skip_if_unavailable"])):
            raise ValueError("repository-trust-config-mismatch")
        checks = [repo[k] for k in ("pkg_gpgcheck", "gpgcheck") if k in repo]
        if not checks or not all(_boolean(v) for v in checks):
            raise ValueError("package-authentication-disabled")
        main = _config_sections(decoded["main-config"])["main"]
        if main["system_cachedir"] != CACHE_ROOT or main["cacheonly"] != "none":
            raise ValueError("cache-config-mismatch")

        # Presentation readback check
        if "presentation" not in decoded:
            raise ValueError("presentation-missing")
        try:
            pres_readback = json.loads(decoded["presentation"])
        except (ValueError, TypeError, json.JSONDecodeError):
            raise ValueError("presentation-unreadable")
        if pres_readback != DNF_PRESENTATION or receipts["presentation"].stderr_bytes:
            raise ValueError("presentation-mismatch")

        tools = {}
        from rs9.apt_diagnostics import safe_sample
        for name in ("dnf-version", "rpm-version"):
            version = decoded[name]
            if not version or not version.splitlines()[0] or receipts[name].stderr_bytes or len(version) > 8192:
                raise ValueError("tool-identity-incomplete")
            tools[name] = {"stdout_sha256": receipts[name].stdout_sha256,
                           "version": safe_sample(version.splitlines()[0], 128)}
        if tools["dnf-version"]["version"] != f"dnf5 version {DNF_VERSION}":
            raise ValueError("dnf-version-mismatch")

        identity = {"repo_id": DNF_REPO_ID, "source_uri": spec["source_uri"], "key_uri": KEY_URI,
                    "key_sha256": before["key_sha256"], "public_fingerprint": spec["public_fingerprint"],
                    "image_id": image_id, "image_sha256": digest(image_id.encode()),
                    "image_reference_sha256": digest(client.image.encode()), "platform": client.platform,
                    "presentation": dict(DNF_PRESENTATION), "commands": command_identities(),
                    "version": DNF_VERSION,
                    "configuration": {"enabled_repositories": [DNF_REPO_ID], "gpgcheck": True,
                                      "repo_gpgcheck": True, "skip_if_unavailable": False,
                                      "system_cachedir": CACHE_ROOT, "cacheonly": "none", "locale": "C"},
                    "tools": tools}
        result.update(status="pass" if all(r.executed is True for r in receipts.values()) else "unavailable",
                      identity=identity, identity_sha256=digest(canonical(identity)),
                      candidate_cache_before=0, candidate_cache_after=0)
    except (ContractError, OSError, ValueError, KeyError, TypeError, AttributeError):
        result.update(status="fail", reason="dnf-identity-readback-unproven")
    return result


def probe_commands(base: list[str]) -> list[tuple[str, list[str]]]:
    key_cache = ["python3", "-I", "-c", _KEY_CACHE_PROBE, KEY_URI.removeprefix("file://"), CACHE_ROOT, DNF_REPO_ID]
    env_probe = [*guest_prefix(), "python3", "-I", "-c",
                 "import json, os; print(json.dumps({k: os.environ.get(k) for k in ('FORCE_COLUMNS', 'LC_ALL', 'LANG', 'DNF5_FORCE_INTERACTIVE')}))"]
    return [("cache-before", key_cache), ("presentation", env_probe),
            ("dnf-version", guest_prefix(["dnf", "--version"])),
            ("rpm-version", ["rpm", "--version"]),
            ("main-config", [*base, "--dump-main-config"]),
            ("repo-config", [*base, "--dump-repo-config=*"]), ("cache-after", key_cache)]


def valid_identity(probe) -> bool:
    try:
        return _identity_matches(probe)
    except (TypeError, ValueError, UnicodeError):
        return False


def _identity_matches(probe) -> bool:
    if not isinstance(probe, Mapping) or probe.get("status") != "pass":
        return False
    identity = probe.get("identity")
    configuration = {"enabled_repositories": [DNF_REPO_ID], "gpgcheck": True,
                     "repo_gpgcheck": True, "skip_if_unavailable": False,
                     "system_cachedir": CACHE_ROOT, "cacheonly": "none", "locale": "C"}
    return (isinstance(identity, Mapping) and probe.get("identity_sha256") == digest(canonical(identity))
            and identity.get("repo_id") == DNF_REPO_ID and _SHA.fullmatch(identity.get("key_sha256") or "") is not None
            and _FINGERPRINT.fullmatch(identity.get("public_fingerprint") or "") is not None
            and identity.get("key_uri") == KEY_URI
            and identity.get("source_uri") in {"file:///srv/rs9/rpm/fedora/43/x86_64", "file:///srv/rs9/rpm/fedora/43/aarch64"}
            and identity.get("configuration") == configuration
            and identity.get("presentation") == DNF_PRESENTATION
            and identity.get("commands") == command_identities()
            and identity.get("version") == DNF_VERSION
            and _SHA.fullmatch(identity.get("image_sha256") or "") is not None
            and re.fullmatch(r"sha256:[0-9a-f]{64}", identity.get("image_id") or "") is not None
            and identity["image_sha256"] == digest(identity["image_id"].encode())
            and _SHA.fullmatch(identity.get("image_reference_sha256") or "") is not None
            and identity.get("platform") in {"linux/amd64", "linux/arm64"}
            and isinstance(identity.get("tools"), Mapping)
            and set(identity["tools"]) == {"dnf-version", "rpm-version"}
            and all(isinstance(t, Mapping) and _SHA.fullmatch(t.get("stdout_sha256") or "")
                    and isinstance(t.get("version"), str) and 0 < len(t["version"]) <= 128
                    for t in identity["tools"].values())
            and identity["tools"]["dnf-version"]["version"] == f"dnf5 version {DNF_VERSION}")


def qualify_dnf(kind, refresh, install, query, *, configure, context):
    """Package rejection is install-only; metadata rejection is refresh-only."""
    context = context or {}
    diag = {"qualifying_stage": "install" if kind == "package" else "refresh"}
    target = install if kind == "package" else refresh
    if target is not None:
        diag["diagnostic"] = record_dnf_stage(stage=diag["qualifying_stage"], product=context.get("product", "candidate"),
                                              arch=context.get("arch", "unknown"), receipt=target)
    if any(r is not None and r.exit_code == 0 for r in (install, query)):
        return False, "COMMAND_SUCCESS", "tampered-content-accepted", diag
    if any(r is None or r.executed is not True for r in (configure, refresh, install, query)) or configure.exit_code != 0:
        return False, "UNCLASSIFIED_FAILURE", "dnf-stage-proof-incomplete", diag
    if not dnf_absent(query, context.get("product", "candidate")):
        return False, classify_dnf(query, stage="query"), "candidate-absence-unproven", diag
    probe = context.get("probe")
    if (not valid_identity(probe) or context.get("positive_control_valid") is not True
            or probe["identity_sha256"] != context.get("positive_identity_sha256")):
        return False, "UNCLASSIFIED_FAILURE", "dnf-positive-control-binding-unproven", diag
    mutation = context.get("mutation") or {}
    if (mutation.get("verified") is not True or mutation.get("kind") != kind
            or any(not _SHA.fullmatch(mutation.get(k) or "") for k in ("control_sha256", "tampered_sha256"))
            or mutation["control_sha256"] == mutation["tampered_sha256"]):
        return False, "UNCLASSIFIED_FAILURE", "dnf-mutation-unproven", diag
    arch = context.get("arch")
    if (arch not in {"x86_64", "aarch64"} or probe["identity"]["source_uri"] != f"file:///srv/rs9/rpm/fedora/43/{arch}"
            or probe["identity"]["platform"] != {"x86_64": "linux/amd64", "aarch64": "linux/arm64"}[arch]):
        return False, "UNCLASSIFIED_FAILURE", "dnf-architecture-binding-unproven", diag
    if not command_matches(refresh, "refresh") or not command_matches(install, "install", context.get("product", "")):
        return False, "UNCLASSIFIED_FAILURE", "dnf-command-binding-unproven", diag
    for r in (configure, refresh, install, query):
        if environment_failure(r):
            return False, environment_failure(r), "dnf-environment-failure", diag
    category = classify_dnf(target, stage=diag["qualifying_stage"], context=context)
    if kind == "package":
        checksum = package_checksum(install, stage="install")
        out, err = full_streams(install)
        product = context.get("product", "")
        arch = context.get("arch", "")
        combined = out + "\n" + err
        if any(t in combined.lower() for t in ("no match for argument", "unable to find a match", "no package matches", "skipping", "ignoring repository", "disabled repository", "signing key not found", "bad pgp signature")):
            return False, category, "dnf-package-rejection-unproven", diag
        target_file = mutation.get("target", "")
        prefix = f"fedora/43/{arch}/"
        relative = target_file.removeprefix(prefix) if isinstance(target_file, str) and target_file.startswith(prefix) else ""
        expected_path = probe["identity"]["source_uri"] + "/" + relative
        uris = re.findall(r"file:[^\s\"']+", combined)
        if any(uri.rstrip(":") not in {probe["identity"]["source_uri"], expected_path, KEY_URI} for uri in uris):
            return False, category, "dnf-package-source-unproven", diag
        paths = re.findall(r"(?:Librepo error: )?Cannot download ([^\s:]+|file://[^\s]+): All mirrors were tried", combined)
        has_path = (bool(relative) and re.fullmatch(r"Packages/" + re.escape(product) + r"-[A-Za-z0-9_.+-]+\.(?:" + re.escape(arch) + r"|noarch)\.rpm", relative)
                    and len(paths) == 1 and paths[0] in {relative, expected_path}
                    and probe["identity"]["source_uri"].endswith("/" + arch))
        if has_path:
            diag["failed_download_path"] = relative
            diag["failed_download_uri_sha256"] = digest(expected_path.encode())
        if (refresh.exit_code != 0 or install.exit_code != 1 or not checksum or not has_path
                or not re.search(r"(?<![A-Za-z0-9_.+-])" + re.escape(product) + r"(?=-[0-9]|[ \n:]|\Z)", combined)
                or checksum["calculated_sha256"] != mutation.get("tampered_sha256")
                or checksum["expected_sha256"] != mutation.get("control_sha256")):
            return False, category, "dnf-package-rejection-unproven", diag
        return True, category, None, diag
    if kind in {"index", "signature", "wrongkey"}:
        expected_target = f"fedora/43/{arch}/repodata/repomd.xml" + ("" if kind == "index" else ".asc")
        if mutation.get("target") != expected_target:
            return False, category, "dnf-mutation-target-unproven", diag
        if refresh.exit_code == 0:
            return False, "COMMAND_SUCCESS", f"bypassed-{kind}-verification-on-refresh", diag
        expected = "KEY_MISMATCH" if kind == "wrongkey" else "SIGNATURE_REJECTED"
        if refresh.exit_code != 1 or install.exit_code != 1 or category != expected:
            return False, category, f"wrong-tamper-rejection-reason:{category}", diag
        diag["authentication_boundary"] = "repomd-signature"
        diag["boundary_rejection_category"] = category
        repo_diag = parse_repository_rejection(refresh, stage="refresh", context=context)
        if repo_diag:
            diag["rejection_sequence"] = repo_diag.get("events", [])
        if repo_diag and repo_diag.get("intermediate_categories"):
            diag["intermediate_categories"] = repo_diag["intermediate_categories"]
            diag["bootstrap_categories"] = repo_diag["intermediate_categories"]
        if kind == "index":
            if mutation.get("authentication_boundary") != "repomd-signature":
                return False, category, "dnf-index-provenance-unproven", diag
            return True, "INDEX_CORRUPT", None, diag
        if kind == "signature":
            if (mutation.get("armor_framing_preserved") is not True
                    or type(mutation.get("packet_changed_offset")) is not int
                    or type(mutation.get("packet_length")) is not int
                    or mutation["packet_changed_offset"] < 0
                    or mutation["packet_changed_offset"] != mutation["packet_length"] - 1):
                return False, category, "dnf-signature-provenance-unproven", diag
            return True, category, None, diag
        if kind == "wrongkey" and (mutation.get("replacement_signature_verified") is not True
                or mutation.get("control_key_fingerprint") != probe["identity"]["public_fingerprint"]
                or not _FINGERPRINT.fullmatch(mutation.get("replacement_issuer") or "")
                or mutation["replacement_issuer"] == mutation["control_key_fingerprint"]):
            return False, category, "dnf-wrong-key-issuer-unproven", diag
        return True, category, None, diag
    return False, category, "unsupported-dnf-tamper-kind", diag
