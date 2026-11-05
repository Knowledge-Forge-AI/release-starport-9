"""Closed per-role container profiles, create argv and strict pre-start readback.

Every role: ``--cap-drop ALL``, NNP, network none, IPC none, fixed hostname,
2 CPUs, 256 PIDs, log driver none, ``--pull never``, platform linux/arm64.
Installer/client add back exactly the seven approved capabilities and run as
0:0 on a mutable layer with 3 GiB; builder/repository run as the verified
runner UID:GID with no capabilities, a read-only root and 2 GiB. Every
non-installer role has exactly one 256 MiB noexec/nosuid/nodev ``/tmp`` tmpfs.
``verify_container`` is the ported qualified readback, generalized from one
read-only bind to the closed per-role bind list.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence

from rs9._archarm_support.refusal import require
from rs9._archarm_support.scripts import INPUTS_TARGET

PLATFORM = "linux/arm64"
HOSTNAME = "rs9-current-pacman-arm"
LABEL_PREFIX = "rs9.archarm-sdk."
CAP_ADD = ("CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "SETGID", "SETUID", "SETFCAP")
INSTALLER_MEMORY = 3221225472
CLIENT_MEMORY = 3221225472
RUNTIME_MEMORY = 2147483648
CPUS = "2"
NANO_CPUS = 2000000000
PIDS_LIMIT = 256
TMPFS_OPTIONS = "rw,nosuid,nodev,noexec,size=268435456,mode=1777"
NNP_OPTION = "no-new-privileges=true"
NNP_FORMS = frozenset({"no-new-privileges", "no-new-privileges=true", "no-new-privileges:true"})
INSTALLER_ENV = ("PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "HOME=/root")
CLIENT_ENV = ("PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "HOME=/root")
WORKER_ENV = ("PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "HOME=/tmp/home", "TMPDIR=/tmp")
CLIENT_CMD = ("/usr/bin/sleep", "infinity")
ROLES = ("installer", "builder", "repository", "client")


@dataclass(frozen=True)
class Bind:
    source: str
    target: str
    readonly: bool


@dataclass(frozen=True)
class Profile:
    role: str
    user: str
    cap_add: tuple
    readonly_root: bool
    tmpfs: Mapping[str, str]
    memory: int


def profile_for(role, user):
    require(role in ROLES, "ROLE_PROFILE")
    if role in ("installer", "client"):
        require(user == "0:0", "ROLE_PROFILE")
        return Profile(role, "0:0", CAP_ADD, False,
                       {} if role == "installer" else {"/tmp": TMPFS_OPTIONS},
                       INSTALLER_MEMORY if role == "installer" else CLIENT_MEMORY)
    require(isinstance(user, str) and user != "0:0" and not user.startswith("0:")
            and not user.endswith(":0"), "ROLE_PROFILE")
    return Profile(role, user, (), True, {"/tmp": TMPFS_OPTIONS}, RUNTIME_MEMORY)


def labels(context, nonce, role):
    return {LABEL_PREFIX + "run": context["runId"],
            LABEL_PREFIX + "attempt": "1",
            LABEL_PREFIX + "source": context["sourceSha"][:12],
            LABEL_PREFIX + "lease": nonce,
            LABEL_PREFIX + "role": role}


def _label_args(values):
    args = []
    for key in sorted(values):
        args += ["--label", f"{key}={values[key]}"]
    return args


def _mount_arg(bind):
    require("," not in bind.source and "," not in bind.target
            and "=" not in bind.source and "=" not in bind.target, "MOUNT_PATH")
    text = f"type=bind,source={bind.source},target={bind.target}"
    return text + (",readonly" if bind.readonly else "")


def create_argv(*, name, image, profile, label_values, env, binds, workdir, cmd):
    argv = ["create", "--name", name, "--platform", PLATFORM, "--pull", "never",
            *_label_args(label_values),
            "--network", "none", "--ipc", "none", "--hostname", HOSTNAME, "--cap-drop", "ALL"]
    for cap in profile.cap_add:
        argv += ["--cap-add", cap]
    argv += ["--security-opt", NNP_OPTION]
    if profile.readonly_root:
        argv += ["--read-only"]
    for target in sorted(profile.tmpfs):
        argv += ["--tmpfs", f"{target}:{profile.tmpfs[target]}"]
    argv += ["--pids-limit", str(PIDS_LIMIT), "--memory", str(profile.memory),
             "--memory-swap", str(profile.memory), "--cpus", CPUS, "--log-driver", "none",
             "--user", profile.user]
    for item in env:
        argv += ["--env", item]
    for bind in binds:
        argv += ["--mount", _mount_arg(bind)]
    argv += ["--workdir", workdir, image, *cmd]
    return argv


def expected(*, name, image, profile, label_values, env, binds, workdir, cmd, container_id):
    return {"name": name, "image": image, "user": profile.user, "env": tuple(env),
            "labels": dict(label_values), "cmd": list(cmd), "workdir": workdir,
            "capAdd": tuple(profile.cap_add), "readonly": profile.readonly_root,
            "tmpfs": dict(profile.tmpfs), "binds": tuple(binds), "memory": profile.memory,
            "id": container_id}


def installer_binds(inputs_dir):
    return (Bind(str(inputs_dir), INPUTS_TARGET, True),)


def _falsy(value):
    if value is None or value is False or value == "":
        return True
    if isinstance(value, (list, tuple)):
        return len(value) == 0
    if isinstance(value, dict):
        return all(_falsy(v) for v in value.values())
    return False


def _caps(values, label):
    if values is None:
        return []
    require(isinstance(values, list) and all(isinstance(v, str) for v in values), label)
    out = []
    for value in values:
        value = value.upper()
        out.append(value[4:] if value.startswith("CAP_") else value)
    return sorted(out)


def _verify_binds(doc, host, binds, label):
    mounts = doc.get("Mounts") or []
    host_mounts = host.get("Mounts") or []
    require(isinstance(mounts, list) and isinstance(host_mounts, list), label)
    require(len(mounts) == len(binds) and len(host_mounts) == len(binds), label)
    by_target = {}
    for bind in binds:
        require(bind.target not in by_target, label)
        by_target[bind.target] = bind
    seen = set()
    for m in mounts:
        require(isinstance(m, dict), label)
        bind = by_target.get(m.get("Destination"))
        require(bind is not None and bind.target not in seen, label)
        seen.add(bind.target)
        require(set(m) <= {"Type", "Source", "Destination", "Mode", "RW", "Propagation"}
                and m.get("Type") == "bind" and m.get("Source") == bind.source
                and m.get("RW") is (not bind.readonly)
                and m.get("Mode", "") == "" and m.get("Propagation", "") in ("", "rprivate"),
                label)
    seen = set()
    for h in host_mounts:
        require(isinstance(h, dict), label)
        bind = by_target.get(h.get("Target"))
        require(bind is not None and bind.target not in seen, label)
        seen.add(bind.target)
        read_only = h.get("ReadOnly", False)
        require(h.get("Type") == "bind" and h.get("Source") == bind.source
                and read_only is bind.readonly
                and all(_falsy(v) for k, v in h.items()
                        if k not in ("Type", "Source", "Target", "ReadOnly")), label)


def verify_container(doc, exp, label):
    """Readback of the created container before it is ever started."""
    require(isinstance(doc, dict), label)
    require(doc.get("Id") == exp["id"] and doc.get("Name") == "/" + exp["name"], label)
    require(doc.get("ConfigImage") == exp["image"] and doc.get("Image") == exp["image"], label)
    require(doc.get("User") == exp["user"], label)
    env = doc.get("Env")
    require(isinstance(env, list) and len(env) == len(set(env)) and set(env) == set(exp["env"]),
            label)
    require(doc.get("Labels") == exp["labels"], label)
    require(doc.get("Cmd") == exp["cmd"] and doc.get("Entrypoint") in (None, []), label)
    require(doc.get("WorkingDir") == exp["workdir"] and doc.get("Hostname") == HOSTNAME, label)
    host = doc.get("Host")
    require(isinstance(host, dict), label)
    _verify_binds(doc, host, exp["binds"], label)
    require(host.get("NetworkMode") == "none" and host.get("IpcMode") == "none", label)
    require(all(host.get(k, "") == "" for k in ("PidMode", "UTSMode", "UsernsMode",
                                                   "CgroupParent", "VolumeDriver")), label)
    require(host.get("Privileged") is False, label)
    require(_caps(host.get("CapDrop"), label) == ["ALL"], label)
    require(_caps(host.get("CapAdd"), label) == sorted(exp["capAdd"]), label)
    security = host.get("SecurityOpt")
    require(isinstance(security, list) and len(security) == 1 and security[0] in NNP_FORMS, label)
    require(host.get("ReadonlyRootfs") is exp["readonly"], label)
    require((host.get("Tmpfs") or {}) == exp["tmpfs"], label)
    for key in ("Binds", "VolumesFrom", "Devices", "DeviceRequests", "DeviceCgroupRules",
                "PortBindings", "ExtraHosts", "Links", "GroupAdd", "Sysctls"):
        require(_falsy(host.get(key)), label)
    require(host.get("PublishAllPorts") in (None, False) and host.get("Init") in (None, False)
            and host.get("OomKillDisable") in (None, False)
            and host.get("AutoRemove") in (None, False), label)
    require(host.get("Memory") == exp["memory"] and host.get("MemorySwap") == exp["memory"]
            and host.get("NanoCpus") == NANO_CPUS and host.get("PidsLimit") == PIDS_LIMIT, label)
    log = host.get("LogConfig")
    require(isinstance(log, dict) and log.get("Type") == "none", label)
    restart = host.get("RestartPolicy") or {}
    require(isinstance(restart, dict) and restart.get("Name", "") in ("", "no"), label)
    return True


def verify_state(doc, *, state, label, exit_code=None):
    if state == "created":
        require(doc.get("Status") == "created" and doc.get("Running") is False, label)
    elif state == "running":
        require(doc.get("Status") == "running" and doc.get("Running") is True
                and doc.get("OOMKilled") is False, label)
    elif state == "stopped":
        require(doc.get("Status") == "exited" and doc.get("Running") is False
                and doc.get("OOMKilled") is False, label)
    else:
        require(state == "exited" and doc.get("Status") == "exited"
                and doc.get("Running") is False and doc.get("OOMKilled") is False
                and type(doc.get("ExitCode")) is int and doc.get("ExitCode") == exit_code, label)


def worker_env(extra: Sequence[str] = ()):
    return (*WORKER_ENV, *extra)
