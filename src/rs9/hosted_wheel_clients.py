"""Qualify retained Linux wheels in the exact run-pinned Fedora/Ubuntu clients."""
import json
import os
from pathlib import Path
import uuid

from rs9.build_native import SubprocessRunner
from rs9.errors import ContractError
from rs9.hosted_commands import _BOUND, run_probes
from rs9.hosted_deb import ContainerRunner, RecordingRunner, provision_image
from rs9.hosted_smoke import verify_nebular_runtime
from rs9.scratch import canonical
from rs9.verify_wheel import verify_offline_venv_lifecycle
from rs9.wheel import THEME_FORGE_PRODUCTS


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
            cfg.write_bytes(canonical({"system":system,"root":str(context["scratch"] / ("client-" + family)),
                "wheels":{key:str(value) for key,value in wheels.items()},
                "prepared":{key:str(value) if isinstance(value,Path) else value for key,value in prepared.items()},
                "bindings":_BOUND,"repository":str(context["repository"]),"output":str(output)}))
            runner = ContainerRunner(host, tag, platform=platform, user=str(os.getuid())+":"+str(os.getgid()),
                mounts=[(str(context["scratch"]),str(context["scratch"]),True),
                        (str(context["repository"]),str(context["repository"]),False)])
            receipt = runner.run(["python3","-m","rs9.hosted_wheel_clients",str(cfg)],
                                 env={"PYTHONPATH":str(context["repository"] / "src"),"PYTHONDONTWRITEBYTECODE":"1"})
            if receipt.exit_code or not receipt.executed or not output.is_file():
                raise ContractError("WHEEL_CLIENT", "Retained wheel failed pinned clean-client lifecycle")
            files.append(output)
            gates.append({"name":"wheel-client-"+family,"status":"pass"})
        finally:
            host.run(["docker","rmi","-f",tag])
    return gates, files


def child(config):
    import socket
    probe = socket.socket()
    probe.settimeout(2)
    if os.getuid() == 0 or probe.connect_ex(("1.1.1.1",443)) == 0:
        raise ContractError("NETWORK_DENIAL", "Nonroot disconnected runtime required")
    _BOUND.clear()
    _BOUND.update(config["bindings"])
    root = Path(config["root"])
    root.mkdir()
    prepared = {key:Path(value) if key in {"source","tools","scratch"} else value for key,value in config["prepared"].items()}
    rows, native_smoke = {}, {}
    for product, path in config["wheels"].items():
        def verify(executable, prefix, env, name):
            gates = run_probes(name, executable, repository=Path(config["repository"]),env=env)
            if any(g["status"] != "pass" for g in gates):
                raise ContractError("COMMAND_CONTRACT", "Retained client command failed")
            if name == "tfnf":
                roots = list(Path(env["THEME_FORGE_CACHE_DIR"]).glob("entries/*/payload/*"))
                if len(roots)!=1:
                    raise ContractError("WHEEL_RUNTIME", "One installed native payload required")
                import subprocess
                count = 0
                for file in roots[0].rglob("*"):
                    if not file.is_file() or file.is_symlink():
                        continue
                    with file.open("rb") as stream:
                        elf = stream.read(4) == bytes([127]) + b"ELF"
                    if elf:
                        result = subprocess.run(["ldd",str(file)],capture_output=True,timeout=30)
                        text = result.stdout + result.stderr
                        if b"not found" in text or (result.returncode and b"not a dynamic" not in text and b"statically linked" not in text):
                            raise ContractError("WHEEL_CLOSURE", "Native wheel has unresolved ELF dependencies")
                        count += 1
                if not count:
                    raise ContractError("WHEEL_CLOSURE", "Actual Linux native ELF objects required")
                native_smoke.update(verify_nebular_runtime(roots[0],prepared,config["system"],env=env))
                native_smoke["elf_objects_checked"] = count
            return {"status":"pass"}
        commands = {name:{"verifier":lambda p,pre,env,name=name:verify(p,pre,env,name)}
                    for name in THEME_FORGE_PRODUCTS[product]["console_scripts"]}
        rows[product] = verify_offline_venv_lifecycle(path,
            distribution_name=THEME_FORGE_PRODUCTS[product]["distribution_name"],commands_to_test=commands,
            venv_dir=root / "venvs" / product, cache_dir=root / "cache" / product)
    Path(config["output"]).write_bytes(canonical({"schema":"rs9.wheel-client.v1alpha1","production":False,
        "system":config["system"],"network":"docker-network-none-negative-connectivity-probe",
        "user":"unprivileged","products":rows,"native_smoke":native_smoke}))


if __name__ == "__main__":
    import sys
    child(json.loads(Path(sys.argv[1]).read_bytes()))
