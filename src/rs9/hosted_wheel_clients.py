"""Qualify retained Linux wheels in the exact run-pinned Fedora/Ubuntu clients."""
import hashlib
import json
import os
from pathlib import Path
import uuid

from rs9.build_native import SubprocessRunner
from rs9.errors import ContractError
from rs9.hosted_commands import _BOUND, run_probes
from rs9.hosted_deb import ContainerRunner, RecordingRunner, provision_image
from rs9.hosted_smoke import verifier_import_preflight, verify_nebular_runtime
from rs9.scratch import canonical, validate_safe_json
from rs9.verify_wheel import verify_offline_venv_lifecycle
from rs9.wheel import THEME_FORGE_PRODUCTS


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
            client_config = {
                "system": system,
                "root": str(context["scratch"] / ("client-" + family)),
                "wheels": {k: str(v) for k, v in wheels.items()},
                "prepared": client_prepared,
                "bindings": _BOUND,
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
                gates.append({"name": "wheel-client-" + family, "status": "fail", "reason": "clean-client-lifecycle-failed"})
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
        def verify(executable, prefix, env, name):
            gates = run_probes(name, executable, repository=Path(config["repository"]), env=env,
                              system=config["system"], substage="wheel-client-command-probe")
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

                native_smoke.update(verify_nebular_runtime(roots[0], prepared, config["system"], env=env))
                native_smoke["elf_objects_checked"] = count
            return {"status": "pass"}
        commands = {name: {"verifier": lambda p, pre, env, name=name: verify(p, pre, env, name)}
                    for name in THEME_FORGE_PRODUCTS[product]["console_scripts"]}
        rows[product] = verify_offline_venv_lifecycle(path,
            distribution_name=THEME_FORGE_PRODUCTS[product]["distribution_name"], commands_to_test=commands,
            venv_dir=root / "venvs" / product, cache_dir=root / "cache" / product)
    receipt = {"schema": "rs9.wheel-client.v1alpha1", "production": False,
        "system": config["system"], "network": "docker-network-none-negative-connectivity-probe",
        "user": "unprivileged", "products": rows, "native_smoke": native_smoke}
    validate_safe_json(receipt, lane="wheel-client", field="client_receipt")
    Path(config["output"]).write_bytes(canonical(receipt))


if __name__ == "__main__":
    import sys
    child(json.loads(Path(sys.argv[1]).read_bytes()))
