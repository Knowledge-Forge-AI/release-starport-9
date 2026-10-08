"""Prepare an offline RPM client independently of candidate policy acceptance."""
import json
from pathlib import Path
import re
import uuid

from rs9.errors import ContractError
from rs9.release_core import digest
from rs9.scratch import canonical

CLIENT_PACKAGES = sorted(["nodejs", "gtk3", "cairo", "pango", "gdk-pixbuf2", "libsoup3",
                          "webkit2gtk4.1", "xorg-x11-server-Xvfb", "dbus-daemon", "python3"])
PROFILE = {"family": "dnf", "packages": CLIENT_PACKAGES, "preparation": "dnf -y install {packages}"}
PROFILE_SHA256 = digest(canonical(PROFILE))
NODE_QUERY_COMMAND = ["rpm", "-qf", "--queryformat",
                      "%{NAME}|%{EPOCHNUM}|%{VERSION}|%{RELEASE}|%{ARCH}\n", "/usr/bin/node"]
NODE_VERSION_COMMAND = ["/usr/bin/node", "--version"]
INSPECT_FORMAT = "{{.Id}}|{{.Architecture}}"
ARCH_PLATFORMS = {"x86_64": ("linux/amd64", "amd64"), "aarch64": ("linux/arm64", "arm64")}


def source_base_ref(arch):
    targets = json.loads((Path(__file__).resolve().parents[2] / "operators/live1/targets.json").read_bytes())["rpm"]
    return targets["container_repository"] + "@" + targets["container_digests"][arch]


def _probe_binding(evidence, command):
    return digest(canonical({"image_id": evidence["derived_image_id"], "system": evidence["system"],
                             "arch": evidence["arch"], "profile_sha256": evidence["profile_sha256"],
                             "base_image_ref": evidence["base_image_ref"], "network": "none", "command": command}))


def _receipt(receipt, command):
    return {"command_sha256": digest(canonical(command)), "executed": receipt.executed,
            "exit_code": receipt.exit_code, "stdout_sha256": receipt.stdout_sha256,
            "stderr_sha256": receipt.stderr_sha256, "stdout_bytes": len(receipt.stdout_bytes),
            "stderr_bytes": len(receipt.stderr_bytes)}


def _inspect(host, image, arch):
    command = ["docker", "image", "inspect", "--format", INSPECT_FORMAT, image]
    receipt = host.run(command)
    match = re.fullmatch(r"(sha256:[0-9a-f]{64})\|(amd64|arm64)\n?", receipt.stdout_text)
    if (not receipt.executed or receipt.exit_code != 0 or receipt.stderr_bytes or not match
            or match[2] != ARCH_PLATFORMS[arch][1]):
        raise ContractError("CLIENT_IMAGE_IDENTITY", "Prepared client image identity is unproven")
    return match[1], _receipt(receipt, command)


def prepare_client(host, environment, *, arch, system, tag):
    """Provision dependencies, inspect the derived image, and probe that exact ID."""
    from rs9.hosted_deb import provision_image
    evidence = {"schema": "rs9.rpm-client-runtime-evidence.v1", "stage": "pre-policy-preparation",
                "system": system, "arch": arch, "base_image_ref": environment.get("image_ref"),
                "base_source_pinned": environment.get("source_pinned") is True,
                "profile_sha256": PROFILE_SHA256, "packages": CLIENT_PACKAGES,
                "preparation_source_sha256": digest(Path(__file__).read_bytes()),
                "status": "unavailable", "reason": "client-preparation-unexecuted", "cleanup": "not-run"}
    name = "rs9-nodeprobe-" + uuid.uuid4().hex[:12]
    probe_attempted = False
    try:
        platform = ARCH_PLATFORMS[arch][0]
        packages = sorted(set(environment.get("preprovisioned_packages", [])) |
                          {"xorg-x11-server-Xvfb", "dbus-daemon", "python3"})
        if (system != arch + "-linux" or environment.get("platform") != platform
                or not evidence["base_source_pinned"] or packages != CLIENT_PACKAGES
                or evidence["base_image_ref"] != source_base_ref(arch)):
            raise ContractError("CLIENT_PROFILE", "Prepared client source or profile differs")
        provision_image(host, "dnf", evidence["base_image_ref"], platform, tag, packages)
        image, inspection = _inspect(host, tag, arch)
        evidence.update(derived_image_id=image, inspection=inspection)
        # The package owning the actual Node path may have a versioned name.
        for key, command in (("rpm_query", NODE_QUERY_COMMAND), ("node_version", NODE_VERSION_COMMAND)):
            outer = ["docker", "run", "--rm", "--name", name, "--network", "none",
                     "--platform", platform, image, *command]
            probe_attempted = True
            receipt = host.run(outer)
            evidence[key] = _receipt(receipt, command)
            evidence[key]["context_sha256"] = _probe_binding(evidence, command)
            if not receipt.executed or receipt.exit_code != 0 or receipt.stderr_bytes:
                raise ContractError("CLIENT_RUNTIME_PROBE", "Offline installed interpreter probe failed")
            if key == "rpm_query":
                match = re.fullmatch(r"([A-Za-z0-9_.+-]{1,64})\|([0-9]{1,9})\|([0-9]+\.[0-9]+(?:\.[0-9]+)?)\|([A-Za-z0-9_.+-]{1,64})\|(x86_64|aarch64)\n", receipt.stdout_text)
                if not match or match[5] != arch:
                    raise ContractError("CLIENT_RUNTIME_IDENTITY", "Interpreter owner RPM identity differs")
                evidence[key]["identity"] = dict(zip(("name", "epoch", "version", "release", "arch"), match.groups()))
            else:
                match = re.fullmatch(r"v([0-9]+\.[0-9]+\.[0-9]+)\n", receipt.stdout_text)
                if not match:
                    raise ContractError("CLIENT_RUNTIME_IDENTITY", "Installed Node version is unproven")
                evidence[key]["version"] = match[1]
        if _inspect(host, image, arch)[0] != image or _inspect(host, tag, arch)[0] != image:
            raise ContractError("CLIENT_IMAGE_DRIFT", "Prepared image changed during the probe")
        evidence.update(status="pass", reason=None)
    except (ContractError, OSError) as error:
        evidence.update(status="fail", reason=error.code if isinstance(error, ContractError) else "CLIENT_PREPARATION_IO")
    finally:
        evidence["cleanup"] = "complete"
        if probe_attempted:
            try:
                receipt = host.run(["docker", "rm", "-f", name])
                evidence["cleanup"] = "complete" if receipt.executed and receipt.exit_code == 0 else "failed"
            except (ContractError, OSError):
                evidence["cleanup"] = "failed"
        if evidence["cleanup"] != "complete":
            evidence.update(status="fail", reason="CLIENT_CLEANUP")
    return evidence


def validate_runtime_evidence(evidence, *, system, arch, floor):
    """Require both language version and epoch-bearing owner identity evidence."""
    if (not isinstance(evidence, dict) or not isinstance(floor, str) or len(floor) > 32
            or not re.fullmatch(r">=\s*[0-9]+(?:\.[0-9]+){0,2}", floor)):
        return False
    query = evidence.get("rpm_query", {})
    if not isinstance(query, dict):
        return False
    identity = query.get("identity", {})
    node = evidence.get("node_version", {})
    if not all(isinstance(value, dict) for value in (query, identity, node)):
        return False
    def matches(pattern, value):
        return isinstance(value, str) and re.fullmatch(pattern, value) is not None
    def version(value):
        if not matches(r"[0-9]{1,6}(?:\.[0-9]{1,6}){0,2}", value):
            return None
        parts = tuple(map(int, value.split(".")))
        return parts + (0,) * (3 - len(parts))
    minimum = version(floor.removeprefix(">=").strip())
    rpm_version, node_version = version(identity.get("version")), version(node.get("version"))
    if (evidence.get("schema") != "rs9.rpm-client-runtime-evidence.v1"
            or evidence.get("stage") != "pre-policy-preparation" or evidence.get("status") != "pass"
            or evidence.get("cleanup") != "complete" or evidence.get("system") != system or evidence.get("arch") != arch
            or system != arch + "-linux" or evidence.get("base_source_pinned") is not True
            or evidence.get("profile_sha256") != PROFILE_SHA256 or evidence.get("packages") != CLIENT_PACKAGES
            or evidence.get("preparation_source_sha256") != digest(Path(__file__).read_bytes())
            or arch not in ARCH_PLATFORMS or evidence.get("base_image_ref") != source_base_ref(arch)
            or not matches(r"sha256:[0-9a-f]{64}", evidence.get("derived_image_id"))
            or identity.get("arch") != arch or not re.fullmatch(r"[0-9]{1,9}", str(identity.get("epoch", "")))
            or not matches(r"[A-Za-z0-9_.+-]{1,64}", identity.get("name"))
            or not matches(r"[A-Za-z0-9_.+-]{1,64}", identity.get("release"))
            or minimum is None or rpm_version is None or node_version is None or rpm_version < minimum or node_version < minimum
            or rpm_version != node_version):
        return False
    # A higher RPM epoch cannot mask an older language version.
    raw = ("|".join(str(identity[k]) for k in ("name", "epoch", "version", "release", "arch")) + "\n").encode()
    for probe, command, output in ((query, NODE_QUERY_COMMAND, raw),
                                   (node, NODE_VERSION_COMMAND, ("v" + node["version"] + "\n").encode())):
        if (probe.get("command_sha256") != digest(canonical(command)) or probe.get("executed") is not True
                or probe.get("context_sha256") != _probe_binding(evidence, command)
                or probe.get("exit_code") != 0 or probe.get("stderr_bytes") != 0 or probe.get("stderr_sha256") != digest(b"")
                or probe.get("stdout_bytes") != len(output) or probe.get("stdout_sha256") != digest(output)):
            return False
    return True


def bind_engine_floors(evidence, captures):
    """Bind system-Node requirements, including preserved executable Loom capabilities."""
    from rs9.release_core import authenticated_record_hash
    from rs9.product_classes import is_native_desktop
    if evidence.get("status") != "pass":
        return evidence
    bindings = []
    try:
        for capture, intent, _ in captures:
            product = intent["project"]["id"]
            if is_native_desktop(product):
                # Embedded caller roles stay independent of system Node. The
                # preserved executable Loom capability already has RPM Requires.
                from rs9.build_native import validate_build_inputs
                from rs9.nebular_callers import FLOOR_SHA256, release_runtime_floor
                from rs9.rpm_lint_policy import load_policy
                inputs = validate_build_inputs(capture, intent, evidence["arch"], adapter="rpm")
                floor = release_runtime_floor(inputs["asset_file"], load_policy()["projects"][product])
                binding = {"product": product, "source_sha256": FLOOR_SHA256, "floor": floor,
                           "purpose": "preserved-executable-rpm-requires"}
            else:
                authenticated_record_hash(capture)
                data = capture.source["package.json"]
                floor = json.loads(data)["engines"]["node"]
                binding = {"product": product, "source_sha256": digest(data), "floor": floor}
            bindings.append(binding)
            if not validate_runtime_evidence(evidence, system=evidence["system"], arch=evidence["arch"], floor=floor):
                evidence.update(status="fail", reason="NODE_RUNTIME_FLOOR_UNMET")
                break
    except (ContractError, OSError, ValueError, KeyError, TypeError, AttributeError):
        evidence.update(status="fail", reason="NODE_ENGINE_SOURCE_UNPROVEN")
    evidence["engine_constraints"] = bindings
    return evidence


def verify_client_image(host, tag, evidence, *, environment, arch, system):
    """Reject tag, source, architecture or preparation profile drift before DNF."""
    if (not isinstance(evidence, dict) or evidence.get("status") != "pass" or evidence.get("cleanup") != "complete"
            or evidence.get("system") != system or evidence.get("arch") != arch
            or evidence.get("base_image_ref") != environment.get("image_ref")
            or environment.get("source_pinned") is not True or evidence.get("profile_sha256") != PROFILE_SHA256
            or evidence.get("preparation_source_sha256") != digest(Path(__file__).read_bytes())
            or evidence.get("packages") != CLIENT_PACKAGES
            or sorted(set(environment.get("preprovisioned_packages", [])) |
                      {"xorg-x11-server-Xvfb", "dbus-daemon", "python3"}) != CLIENT_PACKAGES
            or environment.get("platform") != ARCH_PLATFORMS.get(arch, (None,))[0]):
        raise ContractError("CLIENT_IMAGE_DRIFT", "Prepared client context differs")
    image = evidence.get("derived_image_id")
    if _inspect(host, tag, arch)[0] != image or _inspect(host, image, arch)[0] != image:
        raise ContractError("CLIENT_IMAGE_DRIFT", "Prepared client image differs")
    return image
