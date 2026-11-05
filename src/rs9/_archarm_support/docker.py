"""Docker CLI access through the existing RS9 ``CommandRunner`` seam.

Every call goes through ``host.run`` and must return a real ``CommandReceipt``
with ``executed is True``; a synthetic receipt is refused (``SYNTHETIC_RECEIPT``)
so mocks can never manufacture SDK authority. The docker client is pinned with
global flags to a fresh lease-owned config directory and the local engine
socket. Output and per-call deadlines are enforced during capture at the real leaf;
wrapper guards and receipt storage remain on the command path.
"""
from __future__ import annotations

import copy
import json
import re

from rs9.build_native import CommandReceipt, SubprocessRunner
from rs9._archarm_support.refusal import SdkRefusal, require

DOCKER_HOST = "unix:///var/run/docker.sock"
HEX64_RE = re.compile(r"[0-9a-f]{64}")
IMAGE_ID_RE = re.compile(r"sha256:[0-9a-f]{64}")
PRESENCE_LIMIT = 262144
INSPECT_LIMIT = 65536
DEFAULT_LIMIT = 4096
IMAGE_FORMAT = "{{.Id}}|{{.Os}}|{{.Architecture}}"
# Field-selective template: no PID or other State fields are requested.
CONTAINER_FORMAT = (
    '{"Id":{{json .Id}},"Name":{{json .Name}},"Image":{{json .Image}},'
    '"ConfigImage":{{json .Config.Image}},"User":{{json .Config.User}},'
    '"Env":{{json .Config.Env}},"Labels":{{json .Config.Labels}},'
    '"Cmd":{{json .Config.Cmd}},"Entrypoint":{{json .Config.Entrypoint}},'
    '"WorkingDir":{{json .Config.WorkingDir}},"Hostname":{{json .Config.Hostname}},'
    '"Mounts":{{json .Mounts}},"Host":{{json .HostConfig}},'
    '"Status":{{json .State.Status}},"Running":{{json .State.Running}},'
    '"ExitCode":{{json .State.ExitCode}},"OOMKilled":{{json .State.OOMKilled}}}'
)
FIXED_ENV = {"LANG": "C", "LC_ALL": "C"}


def bounded_runner(host, seconds, limit=4096, *, _seen=()):
    """Copy wrapper guards and receipt storage while bounding the real leaf."""
    require(id(host) not in _seen and len(_seen) < 8, "HOST_RUNNER_CHAIN")
    seen = (*_seen, id(host))
    if isinstance(host, SubprocessRunner):
        bounded = copy.copy(host)
        bounded.timeout = seconds
        bounded._archarm_capture_limit = limit
        return bounded
    inner = getattr(host, "inner", None)
    if callable(getattr(inner, "run", None)) and callable(getattr(inner, "which", None)):
        bounded = copy.copy(host)
        bounded.inner = bounded_runner(inner, seconds, limit, _seen=seen)
        return bounded
    return host


def executed_receipt(receipt, label="SYNTHETIC_RECEIPT"):
    require(isinstance(receipt, CommandReceipt), label)
    require(receipt.executed is True, label)
    require(isinstance(receipt.stdout_bytes, bytes) and isinstance(receipt.stderr_bytes, bytes),
            label)
    return receipt


class DockerCli:
    """Lease-owned docker client. ``receipts`` keeps closed hash-only records."""

    def __init__(self, host, config_dir):
        self.host = host
        self.config_dir = str(config_dir)
        self.receipts = []

    def argv(self, args):
        return ["docker", "--config", self.config_dir, "--host", DOCKER_HOST, *args]

    def receipt(self, args, *, timeout=120, limit=DEFAULT_LIMIT):
        receipt = executed_receipt(bounded_runner(self.host, timeout, limit).run(
            self.argv(args), env=dict(FIXED_ENV)))
        self.receipts.append(receipt.to_record())
        require(len(receipt.stdout_bytes) <= limit, "COMMAND_OUTPUT_LIMIT")
        return receipt

    def __call__(self, args, *, timeout=120, limit=DEFAULT_LIMIT):
        receipt = self.receipt(args, timeout=timeout, limit=limit)
        return receipt.exit_code, receipt.stdout_bytes


def parse_id(output, pattern, label):
    try:
        text = output.decode("ascii", "strict").strip()
    except UnicodeDecodeError:
        raise SdkRefusal(label) from None
    require(pattern.fullmatch(text) is not None, label)
    return text


def presence(docker, kind, ref):
    code, out = docker([kind, "inspect", ref], limit=PRESENCE_LIMIT)
    try:
        documents = json.loads(out.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise SdkRefusal("DOCKER_READBACK") from None
    if code == 1 and documents == []:
        return False
    require(code == 0 and isinstance(documents, list) and len(documents) == 1
            and isinstance(documents[0], dict), "DOCKER_READBACK")
    return True


def image_identity(docker, ref, label):
    code, out = docker(["image", "inspect", "--format", IMAGE_FORMAT, ref])
    require(code == 0, label)
    try:
        parts = out.decode("ascii", "strict").strip().split("|")
    except UnicodeDecodeError:
        raise SdkRefusal(label) from None
    require(len(parts) == 3 and IMAGE_ID_RE.fullmatch(parts[0]) is not None
            and parts[1] == "linux" and parts[2] == "arm64", label)
    return parts[0]


def container_doc(docker, ref, label):
    code, out = docker(["container", "inspect", "--format", CONTAINER_FORMAT, ref],
                       limit=INSPECT_LIMIT)
    require(code == 0, label)
    try:
        doc = json.loads(out.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise SdkRefusal(label) from None
    require(isinstance(doc, dict), label)
    return doc
