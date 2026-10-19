"""Closed original installed-client smoke observations; never a retry or gate."""
import os
from pathlib import Path
import re
import uuid

from rs9.application_smoke_diagnostic import CAUSE_CATEGORIES, SAFE_LOG_CATEGORIES
from rs9.errors import ContractError
from rs9.release_core import digest
from rs9.scratch import canonical
from rs9.security import scan_for_credentials

SCENARIOS = frozenset({"A", "B", "C", "C-signal"})
RECEIPT_ERRORS = frozenset(x for x in CAUSE_CATEGORIES if x.startswith("receipt-"))
RUNTIME_PACKAGES = ("libgtk-3-0t64", "libwebkit2gtk-4.1-0", "libjavascriptcoregtk-4.1-0",
                    "libc6", "python3", "xvfb", "dbus", "dbus-x11")
_SHA = re.compile(r"[0-9a-f]{64}")


def _sha(value):
    return value if isinstance(value, str) and _SHA.fullmatch(value) else None


def _integer(value, maximum):
    return value if type(value) is int and 0 <= value <= maximum else None


def _closed(value, choices, default=None):
    return value if isinstance(value, str) and value in choices else default


def _problem_codes(raw):
    if not isinstance(raw, list):
        return []
    result = []
    for item in raw[:16]:
        try:
            if not isinstance(item, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", item):
                raise ValueError
            scan_for_credentials(item)
            result.append(item)
        except (ValueError, ContractError):
            result.append("withheld-token")
    return result


def validate_smoke_observation(raw, *, system=None):
    """Project hostile JSON with no invented hashes, counts, success or signal."""
    raw = raw if isinstance(raw, dict) else {}
    rc = raw.get("raw_returncode")
    rc = rc if type(rc) is int and -128 <= rc <= 255 else None
    counts = {k: _integer(raw.get(k), 2**63 - 1) for k in ("stdout_bytes", "stderr_bytes")}
    hashes = {k: _sha(raw.get(k)) for k in ("stdout_sha256", "stderr_sha256")}
    cause = _closed(raw.get("cause"), CAUSE_CATEGORIES, "unknown")
    complete = (raw.get("stream_capture_complete") is True and
                all(v is not None for v in (*counts.values(), *hashes.values())) and
                cause not in {"process-timeout", "process-output-limit", "harness-error"})
    categories = raw.get("log_categories")
    categories = categories[:16] if isinstance(categories, list) else []
    categories = sorted({v for v in categories if isinstance(v, str) and v in SAFE_LOG_CATEGORIES})
    scenario = _closed(raw.get("scenario"), SCENARIOS, "unknown")
    allowed = {"x86_64-linux": {"C", "C-signal"}, "aarch64-linux": {"B"}, "aarch64-darwin": {"A"}}
    mismatch = raw.get("binding_mismatch") is True or (system is not None and scenario not in allowed.get(system, set()))
    result = {"scenario": "unknown" if mismatch else scenario, "cause": cause,
            "process_scope": "outermost-smoke-process", "raw_returncode": rc,
            "exit_code": rc if rc is not None and rc >= 0 else None,
            "signal": -rc if rc is not None and rc < 0 else None,
            **counts, **hashes, "stream_capture_complete": complete,
            "log_categories": categories, "receipt_error": _closed(raw.get("receipt_error"), RECEIPT_ERRORS),
            "problem_codes": _problem_codes(raw.get("problem_codes")),
            "elapsed_ms": _integer(raw.get("elapsed_ms"), 7 * 86400 * 1000),
            "reason_token": _closed(raw.get("reason_token"), CAUSE_CATEGORIES, "unknown")}
    if mismatch:
        result["binding_mismatch"] = True
    from rs9.smoke_stream_tokens import (
        validate_inner_stream_tokens, validate_inventory, validate_run_record, validate_stream_tokens,
    )
    stream = validate_stream_tokens(raw.get("stderr_diagnostic"), sha256=hashes["stderr_sha256"],
        byte_count=counts["stderr_bytes"], complete=complete, mismatch=mismatch)
    inventory = validate_inventory(raw.get("evidence_inventory"), mismatch=mismatch)
    if stream is not None:
        result["stderr_diagnostic"] = stream
    if inventory is not None:
        result["evidence_inventory"] = inventory
    if system == "aarch64-darwin" or (system is None and (scenario == "A" or mismatch)):
        run_record = validate_run_record(raw.get("harness_run_record"), inventory=inventory, mismatch=mismatch)
        inner_stream = validate_inner_stream_tokens(
            raw.get("inner_stderr_diagnostic"), inventory=inventory, mismatch=mismatch
        )
        if run_record is not None:
            result["harness_run_record"] = run_record
        if inner_stream is not None:
            result["inner_stderr_diagnostic"] = inner_stream
    return result


def retain_host_smoke_diagnostic(directory, observation, *, family, system):
    """First-failure exclusive physical 0600 record. Optional writer cannot mask failure."""
    try:
        if family not in {"apt", "dnf", "pacman"} or system not in {"x86_64-linux", "aarch64-linux"}:
            return None
        observation = validate_smoke_observation(observation, system=system)
        record = {"schema": "rs9.application-smoke-diagnostic.v1alpha1", "family": family, "system": system,
                  "product": "theme-forge-nebular-fusion", "status": "fail", "gate_status": "fail",
                  "origin": "original-producer-attempt", "single_attempt": True, "diagnostic_replay": False,
                  "scenario": observation["scenario"], "cause": observation["cause"], "initial_run": observation}
        raw = canonical(record)
        scan_for_credentials(raw.decode())
        directory = Path(directory)
        if any(p.is_symlink() for p in (directory, *directory.parents)):
            return None
        directory.mkdir(parents=True, exist_ok=True)
        directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            fd = os.open("application-smoke-failure-" + family + ".json",
                         os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory_fd)
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
        finally:
            os.close(directory_fd)
        return digest(raw)
    except Exception:
        # This is a diagnostic boundary, never an alternative producer result.
        return None


def parse_runtime_packages(raw, platform):
    """Strict finite dpkg query projection; no arbitrary package, prose or path."""
    if not isinstance(raw, bytes) or len(raw) > 16 * 1024:
        raise ValueError
    text = raw.decode("utf-8")
    scan_for_credentials(text)
    arch = {"linux/amd64": "amd64", "linux/arm64": "arm64"}[platform]
    versions = {}
    for line in text.splitlines():
        name, version = line.split("\t")
        name = name.removesuffix(":" + arch)
        if name not in RUNTIME_PACKAGES or name in versions or not re.fullmatch(r"[0-9][A-Za-z0-9.+:~_-]{0,95}", version):
            raise ValueError
        versions[name] = version
    if set(versions) != set(RUNTIME_PACKAGES):
        raise ValueError
    return dict(sorted(versions.items()))


def probe_apt_runtime_image(host, image, *, platform="linux/amd64"):
    """Separate bounded, offline read-only image probe; excluded from gate receipt accounting."""
    from rs9.hosted_deb import _bounded_runner
    record = {"status": "unavailable", "qualification_authority": False}
    probe_name = None
    try:
        if platform not in {"linux/amd64", "linux/arm64"}:
            return record
        runner = _bounded_runner(getattr(host, "inner", host), 30)
        identity = runner.run(["docker", "image", "inspect", "--format", "{{.Id}}", image])
        raw = identity.stdout_bytes
        if identity.exit_code or not identity.executed or not re.fullmatch(rb"sha256:[0-9a-f]{64}\n?", raw):
            return record
        record["image_sha256"] = raw.decode().strip().removeprefix("sha256:")
        probe_name = "rs9-apt-image-probe-" + uuid.uuid4().hex
        query = runner.run(["docker", "run", "--name", probe_name, "--pull", "never", "--platform", platform,
            "--network", "none", "--rm", "--read-only", "--user", "65534:65534", image,
            "dpkg-query", "-W", "-f=${binary:Package}\t${Version}\n", *RUNTIME_PACKAGES])
        record.update(stdout_sha256=query.stdout_sha256, stderr_sha256=query.stderr_sha256)
        if query.exit_code or not query.executed:
            return record
        record.update(packages=parse_runtime_packages(query.stdout_bytes, platform), status="observed")
    except Exception:
        # Probe availability never influences host.real_since or qualification.
        pass
    finally:
        if probe_name is not None:
            record["cleanup"] = "unconfirmed"
            try:
                cleanup = runner.run(["docker", "rm", "-f", probe_name])
                if cleanup.executed and cleanup.exit_code == 0:
                    record["cleanup"] = "complete"
            except Exception:
                pass
    return record


def extract_smoke_context(binding):
    if not isinstance(binding, dict):
        return {}
    request = binding.get("request")
    request = request if isinstance(request, dict) else {}
    return {"request_sha256": _sha(binding.get("request_sha256")),
            "manifest_sha256": _sha(request.get("manifest_sha256")),
            "source_records_sha256": (digest(canonical(request["records"]))
                                      if isinstance(request.get("records"), list) else None),
            "family": _closed(binding.get("family"), {"apt", "dnf", "pacman"}),
            "system": _closed(binding.get("system"), {"x86_64-linux", "aarch64-linux"}),
            "timeout_seconds": 240, "display": "fresh-xvfb-run", "dbus": "fresh-dbus-run-session",
            "cache_scope": "fresh-client-container", "uid": 65534, "network": "none"}


def determine_counters_source(client, error, stage=None):
    observed = getattr(client, "last_inventory_stage", None)
    if observed in {"pre-install", "post-remove"}:
        return observed
    error_stage = error.details.get("stage") if isinstance(error, ContractError) else None
    return _closed(error_stage or stage, {"pre-install", "post-remove"})
