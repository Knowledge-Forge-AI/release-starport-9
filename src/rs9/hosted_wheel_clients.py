"""Qualify retained Linux wheels in the exact run-pinned Fedora/Ubuntu clients."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid

from rs9.current_generation import HISTORICAL_GENERATION, generation_paths
from rs9.apt_diagnostics import safe_sample
from rs9.build_native import SubprocessRunner
from rs9.errors import ContractError
from rs9.hosted_commands import _BOUND, run_probes
from rs9.hosted_deb import ContainerRunner, RecordingRunner, provision_image
from rs9.hosted_smoke import verifier_import_preflight, verify_nebular_runtime
from rs9.scratch import canonical, validate_safe_json
from rs9.verify_wheel import verify_offline_venv_lifecycle
from rs9.wheel import THEME_FORGE_PRODUCTS


CLIENT_DIAGNOSTIC_SCHEMA = "rs9.hosted-candidate-diagnostic.v1alpha2"
MAX_CHILD_DIAGNOSTIC_BYTES = 16 * 1024
_CLIENT_FAMILIES = {"wheel-client-deb", "wheel-client-rpm"}
_CLIENT_PHASES = {"venv-create", "wheel-install", "wheel-uninstall", "residual-check", "client-lifecycle"}


def _safe_hash(value):
    return value if isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) else None


def _safe_exit_code(value):
    return value if type(value) is int and -128 <= value <= 255 else None


def _receipt_record(receipt):
    """Keep only bounded command-receipt identity; never retain argv or tool paths."""
    record = {
        "executed": receipt.executed if type(getattr(receipt, "executed", None)) is bool else None,
        "exit_code": _safe_exit_code(getattr(receipt, "exit_code", None)),
    }
    for name in ("stdout_sha256", "stderr_sha256"):
        digest = _safe_hash(getattr(receipt, name, None))
        if digest is not None:
            record[name] = digest
    for name in ("stdout_bytes", "stderr_bytes"):
        stream = getattr(receipt, name, None)
        if isinstance(stream, (bytes, bytearray)):
            record[name] = len(stream)
    return record


def _stderr_tail(receipt):
    text = getattr(receipt, "stderr_text", None)
    if isinstance(text, str) and text:
        return safe_sample(text[-1024:], max_chars=1024)
    raw = getattr(receipt, "stderr_bytes", b"")
    if isinstance(raw, (bytes, bytearray)):
        return safe_sample(bytes(raw[-1024:]), max_chars=1024)
    if isinstance(text, str):
        return safe_sample(text[-1024:], max_chars=1024)
    return ""


def _failure_category(receipt, output):
    if getattr(receipt, "executed", None) is not True:
        return "container-not-executed"
    if _safe_exit_code(getattr(receipt, "exit_code", None)) not in (None, 0):
        return "child-exit-nonzero"
    if not output.is_file():
        return "child-receipt-missing"
    return "child-receipt-unavailable"


def _diagnostic_path(config):
    family = config.get("prepared", {}).get("family")
    if family not in _CLIENT_FAMILIES:
        family = "wheel-client"
    return Path(config["output"]).parent / "diagnostics" / f"{family}-lifecycle-diagnostic.json"


def _diagnostic_stamp(path):
    try:
        info = path.lstat()
    except OSError:
        return None
    if not stat.S_ISREG(info.st_mode):
        return None
    return info.st_mtime_ns, info.st_size


def _child_diagnostic_details(path):
    """Read only the child fields used for diagnosis; invalid child data cannot pass a gate."""
    descriptor = None
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        if os.fstat(descriptor).st_size > MAX_CHILD_DIAGNOSTIC_BYTES:
            return {}
        with os.fdopen(descriptor, "rb", closefd=True) as stream:
            descriptor = None
            payload = stream.read(MAX_CHILD_DIAGNOSTIC_BYTES + 1)
        if len(payload) > MAX_CHILD_DIAGNOSTIC_BYTES:
            return {}
        document = json.loads(payload)
    except (OSError, ValueError, UnicodeError, RecursionError):
        return {}
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if (not isinstance(document, dict)
            or document.get("schema") != CLIENT_DIAGNOSTIC_SCHEMA
            or not isinstance(document.get("details"), dict)):
        return {}
    source = document["details"]
    details = {}
    phase = source.get("phase")
    if phase in _CLIENT_PHASES or (isinstance(phase, str)
                                   and re.fullmatch(r"command:[A-Za-z0-9_.+-]{1,64}", phase)):
        details["phase"] = phase
    for key in ("underlying_code", "exception_type"):
        value = source.get(key)
        if isinstance(value, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.:-]{0,63}", value):
            details[key] = value
    for key in ("exit_code", "deadline_seconds"):
        value = source.get(key)
        valid = (key == "deadline_seconds" and type(value) is int and 0 <= value <= 86400 * 7
                 or key == "exit_code" and type(value) is int and -128 <= value <= 255)
        if valid:
            details[key] = value
    for key in ("stdout_sha256", "stderr_sha256"):
        value = _safe_hash(source.get(key))
        if value is not None:
            details[key] = value
    tail = source.get("stderr_tail")
    if isinstance(tail, str):
        details["child_stderr_tail"] = safe_sample(tail, max_chars=1024)
    product = document.get("product")
    if product in THEME_FORGE_PRODUCTS:
        details["child_product"] = product
    return details


def _write_failure_diagnostic(config, system, family, receipt, output):
    path = _diagnostic_path(config)
    child_details = _child_diagnostic_details(path) if path.is_file() else {}
    details = {
        **child_details,
        "phase": child_details.get("phase", "client-lifecycle"),
        "failure_category": _failure_category(receipt, output),
        "stderr_tail": _stderr_tail(receipt),
        "failed_receipt": _receipt_record(receipt),
    }
    document = {
        "schema": CLIENT_DIAGNOSTIC_SCHEMA,
        "system": system,
        "product": child_details.get("child_product", "theme-forge-nebular-fusion"),
        "substage": "client-lifecycle",
        "error_code": "CLEAN_CLIENT_LIFECYCLE_FAILED",
        "details": details,
    }
    validate_safe_json(document, lane="wheel-client", field="client_lifecycle_diagnostic")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical(document))
    return path, document


def _write_child_diagnostic(config, product, error):
    path = _diagnostic_path(config)
    source_details = dict(getattr(error, "details", {}) or {})
    phase = source_details.get("phase")
    if not (phase in _CLIENT_PHASES or (isinstance(phase, str)
                                        and re.fullmatch(r"command:[A-Za-z0-9_.+-]{1,64}", phase))):
        phase = "client-lifecycle"
    details = {"phase": phase, "failure_category": "child-exception"}
    for key in ("underlying_code", "exception_type"):
        value = source_details.get(key)
        if isinstance(value, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.:-]{0,63}", value):
            details[key] = value
    for key in ("exit_code", "deadline_seconds"):
        value = source_details.get(key)
        valid = (key == "deadline_seconds" and type(value) is int and 0 <= value <= 86400 * 7
                 or key == "exit_code" and type(value) is int and -128 <= value <= 255)
        if valid:
            details[key] = value
    for key in ("stdout_sha256", "stderr_sha256"):
        value = _safe_hash(source_details.get(key))
        if value is not None:
            details[key] = value
    tail = getattr(error, "_diagnostic_stderr_tail", "")
    if isinstance(tail, str) and tail:
        details["stderr_tail"] = safe_sample(tail, max_chars=1024)
    error_code = getattr(error, "code", "CLIENT_LIFECYCLE_FAILED")
    if not isinstance(error_code, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", error_code):
        error_code = "CLIENT_LIFECYCLE_FAILED"
    document = {
        "schema": CLIENT_DIAGNOSTIC_SCHEMA,
        "system": config["system"],
        "product": product if product in THEME_FORGE_PRODUCTS else "theme-forge-nebular-fusion",
        "substage": "client-lifecycle",
        "error_code": error_code,
        "details": details,
    }
    validate_safe_json(document, lane="wheel-client", field="client_lifecycle_diagnostic")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical(document))
    return path


def build_client_prepared_config(prepared, system):
    """Explicit producer config with source/tools/scratch strings, records/label,
    plus authenticated expected_members and bound manifest_sha256."""
    prepared_config = {
        "source": str(prepared["source"]),
        "tools": str(prepared["tools"]),
        "scratch": str(prepared["scratch"]),
        "records": list(prepared.get("records", [])),
    }
    label = prepared.get("label") or prepared.get("family")
    if label:
        prepared_config["label"] = label
        prepared_config["family"] = label

    expected_members = prepared.get("expected_members")
    manifest_sha256 = prepared.get("manifest_sha256")
    capture = prepared.get("capture")
    if capture is not None and (expected_members is None or manifest_sha256 is None):
        candidates = [p for p in capture.record.get("payloads", []) if system in p.get("platforms", [])]
        if len(candidates) == 1:
            payload_entry = candidates[0]
            manifest_entry = capture.manifests.get(payload_entry["id"], {})
            if expected_members is None:
                expected_members = manifest_entry.get("members")
            if manifest_sha256 is None:
                manifest_sha256 = manifest_entry.get("manifest_sha256") or payload_entry.get("payload_manifest_sha256")

    if expected_members is not None:
        prepared_config["expected_members"] = expected_members
    if manifest_sha256 is not None:
        prepared_config["manifest_sha256"] = manifest_sha256

    return prepared_config


def qualify(context, wheels, prepared):
    generation = context.get("generation", HISTORICAL_GENERATION)
    generation_paths(generation)
    system = context["system"]
    arch = "aarch64" if system == "aarch64-linux" else "x86_64"
    platform = "linux/arm64" if arch == "aarch64" else "linux/amd64"
    host = RecordingRunner(SubprocessRunner())
    gates, files = [], []
    for family in ("deb", "rpm"):
        key = "arm64" if arch == "aarch64" else "amd64" if family == "deb" else arch
        if family == "rpm":
            key = arch
        image = context["pins"][family]["container_digests"][key]
        tag = "rs9-wheel-client-" + family + ":" + uuid.uuid4().hex[:12]
        packages = ["python3", "python3-venv", "python3-pip", "nodejs", "xvfb", "dbus-x11", "libgtk-3-0t64", "libwebkit2gtk-4.1-0"] if family == "deb" else ["python3", "python3-pip", "nodejs", "xorg-x11-server-Xvfb", "dbus-daemon", "gtk3", "webkit2gtk4.1"]
        try:
            provision_image(host, "apt" if family == "deb" else "dnf", image, platform, tag, packages)
            cfg = context["scratch"] / ("wheel-client-" + family + ".json")
            output = context["scratch"] / ("wheel-client-" + family + "-receipt.json")
            client_prepared = build_client_prepared_config(prepared, system)
            client_prepared.update(scratch=str(context["scratch"] / ("wheel-client-smoke-" + family)),
                                   label="wheel-client-" + family, family="wheel-client-" + family)
            smoke_diagnostic = (Path(client_prepared["scratch"]).parent / "diagnostics" /
                                "application-smoke-diagnostic.json")
            prior_smoke_stamp = _diagnostic_stamp(smoke_diagnostic)
            client_config = {
                "system": system,
                "root": str(context["scratch"] / ("client-" + family)),
                "wheels": {k: str(v) for k, v in wheels.items()},
                "prepared": client_prepared,
                "bindings": _BOUND,
                "generation": generation,
                "repository": str(context["repository"]),
                "output": str(output),
            }
            validate_safe_json(client_config, lane="wheels", product="theme-forge-nebular-fusion")
            cfg.write_bytes(canonical(client_config))
            runner = ContainerRunner(host, tag, platform=platform, user=str(os.getuid()) + ":" + str(os.getgid()),
                mounts=[(str(context["scratch"]), str(context["scratch"]), True),
                        (str(context["repository"]), str(context["repository"]), False)])
            receipt = runner.run(["python3", "-m", "rs9.hosted_wheel_clients", str(cfg)],
                                 env={"PYTHONPATH": str(context["repository"] / "src"), "PYTHONDONTWRITEBYTECODE": "1"})
            if receipt.exit_code or not receipt.executed or not output.is_file():
                diagnostic_path, diagnostic = _write_failure_diagnostic(
                    {"output": output, "prepared": client_prepared}, system, family, receipt, output)
                files.append(diagnostic_path)
                current_smoke_stamp = _diagnostic_stamp(smoke_diagnostic)
                if current_smoke_stamp is not None and current_smoke_stamp != prior_smoke_stamp:
                    files.append(smoke_diagnostic)
                gates.append({"name": "wheel-client-" + family, "status": "fail",
                              "reason": "clean-client-lifecycle-failed",
                              "diagnostic": {
                                  "path": diagnostic_path.relative_to(context["scratch"]).as_posix(),
                                  "failure_category": diagnostic["details"]["failure_category"],
                              }})
            else:
                files.append(output)
                gates.append({"name": "wheel-client-" + family, "status": "pass"})
        except ContractError as err:
            gates.append({"name": "wheel-client-" + family, "status": "fail", "reason": err.code,
                          "details": err.details})
        finally:
            host.run(["docker", "rmi", "-f", tag])
    return gates, files


def child(config):
    generation = config.get("generation", HISTORICAL_GENERATION)
    generation_paths(generation)
    import socket
    probe = socket.socket()
    try:
        probe.settimeout(2)
        if os.getuid() == 0 or probe.connect_ex(("1.1.1.1", 443)) == 0:
            raise ContractError("NETWORK_DENIAL", "Nonroot disconnected runtime required")
    finally:
        probe.close()
    _BOUND.clear()
    _BOUND.update(config["bindings"])
    root = Path(config["root"])
    root.mkdir()
    prepared = {key: Path(value) if key in {"source", "tools", "scratch"} else value for key, value in config["prepared"].items()}
    prepared["scratch"].mkdir(parents=True, exist_ok=True)
    if "theme-forge-nebular-fusion" in config["wheels"]:
        expected_members = prepared.get("expected_members")
        manifest_sha256 = prepared.get("manifest_sha256")
        if not isinstance(expected_members, list) or not isinstance(manifest_sha256, str):
            raise ContractError("MANIFEST_AUTHENTICATION", "Bound runtime manifest required by the native client",
                                details={"product": "theme-forge-nebular-fusion", "substage": "client-verification"})
        validate_safe_json(expected_members, lane="wheel-client", product="theme-forge-nebular-fusion", field="expected_members")
        actual = hashlib.sha256(canonical(expected_members)).hexdigest()
        if actual != manifest_sha256:
            raise ContractError("MANIFEST_AUTHENTICATION", "Expected members hash does not match manifest SHA256",
                                details={"expected_digest": manifest_sha256, "actual_digest": actual,
                                         "product": "theme-forge-nebular-fusion", "substage": "client-verification"})
        verifier_import_preflight(prepared, config["system"])
    rows, native_smoke = {}, {}
    for product, path in config["wheels"].items():
        try:
            def verify(executable, prefix, env, name):
                gates = run_probes(name, executable, repository=Path(config["repository"]), env=env,
                                  system=config["system"], substage="wheel-client-command-probe", generation=generation)
                if any(g["status"] != "pass" for g in gates):
                    raise ContractError("COMMAND_CONTRACT", "Retained client command failed")
                if name == "tfnf":
                    roots = list(Path(env["THEME_FORGE_CACHE_DIR"]).glob("entries/*/payload/*"))
                    if len(roots) != 1:
                        raise ContractError("WHEEL_RUNTIME", "One installed native payload required")
                    import subprocess
                    count = 0
                    for file in roots[0].rglob("*"):
                        if not file.is_file() or file.is_symlink():
                            continue
                        with file.open("rb") as stream:
                            elf = stream.read(4) == bytes([127]) + b"ELF"
                        if elf:
                            result = subprocess.run(["ldd", str(file)], capture_output=True, timeout=30)
                            text = result.stdout + result.stderr
                            if b"not found" in text or (result.returncode and b"not a dynamic" not in text and b"statically linked" not in text):
                                raise ContractError("WHEEL_CLOSURE", "Native wheel has unresolved ELF dependencies")
                            count += 1
                    if not count:
                        raise ContractError("WHEEL_CLOSURE", "Actual Linux native ELF objects required")

                    native_smoke.update(verify_nebular_runtime(
                        roots[0], prepared, config["system"], env=env,
                        diagnostic_boundary_probes=config["system"].endswith("-linux")))
                    native_smoke["elf_objects_checked"] = count
                return {"status": "pass"}
            commands = {name: {"verifier": lambda p, pre, env, name=name: verify(p, pre, env, name)}
                        for name in THEME_FORGE_PRODUCTS[product]["console_scripts"]}
            rows[product] = verify_offline_venv_lifecycle(path,
                distribution_name=THEME_FORGE_PRODUCTS[product]["distribution_name"], commands_to_test=commands,
                venv_dir=root / "venvs" / product, cache_dir=root / "cache" / product)
        except Exception as error:
            _write_child_diagnostic(config, product, error)
            raise
    receipt = {"schema": "rs9.wheel-client.v1alpha1", "production": False,
        "system": config["system"], "network": "docker-network-none-negative-connectivity-probe",
        "user": "unprivileged", "products": rows, "native_smoke": native_smoke}
    validate_safe_json(receipt, lane="wheel-client", field="client_receipt")
    Path(config["output"]).write_bytes(canonical(receipt))


if __name__ == "__main__":
    import sys
    child(json.loads(Path(sys.argv[1]).read_bytes()))
