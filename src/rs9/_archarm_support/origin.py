"""Origin identities and namespace transforms of the ported qualified helper layer.

The qualified native runtime run (``QUALIFIED_RUN`` at ``QUALIFIED_SOURCE``)
executed the ORIGINAL probe controller. This port is new source: it is not
native-qualified, and ``MODULE_NATIVE_QUALIFIED`` is a constant ``False``.

Origin byte counts/SHA-256 values are the public P-tree identities recorded in
the composed preimage manifest for the five immutable qualified files. The
porting worker had no shell and did not recompute them; the pin loader
re-verifies the three pin/key files byte-exactly at runtime and refuses any
difference.
"""
from __future__ import annotations

from types import MappingProxyType

QUALIFIED_RUN = 42033829642
QUALIFIED_SOURCE = "bfa1a8a83c328e623692c467b84aeaf81cf546bd"
MODULE_NATIVE_QUALIFIED = False

ORIGIN_FILES = MappingProxyType({
    "archarm_base_probe.py": MappingProxyType({
        "path": "tools/verification/archarm_base_probe/archarm_base_probe.py",
        "bytes": 15435,
        "sha256": "f89f25f3ebb29f18f585b660de16b718e65dc64654b5d22d8a172b00b111d960"}),
    "archarm_runtime_probe.py": MappingProxyType({
        "path": "tools/verification/archarm_runtime_probe/archarm_runtime_probe.py",
        "bytes": 65403,
        "sha256": "f975b783fd6f10fdced613d1618dd290ae67ff1c23eb4770f809c477cf13cdfc"}),
    "ROOTFS-PIN.json": MappingProxyType({
        "path": "tools/verification/archarm_base_probe/ROOTFS-PIN.json",
        "bytes": 3408,
        "sha256": "0d92f648e1f9bc2ef29846b7f37d7fae99ccbb4adc6fd918d797c2ac9054edff"}),
    "PACKAGE-PINS.json": MappingProxyType({
        "path": "tools/verification/archarm_runtime_probe/PACKAGE-PINS.json",
        "bytes": 78585,
        "sha256": "53c812397e73cdb16c80cd5cd72b6ed66889817d8aa79b075034434895da2987"}),
    "archlinuxarm-builder-public.gpg": MappingProxyType({
        "path": "tools/verification/archarm_base_probe/archlinuxarm-builder-public.gpg",
        "bytes": 3857,
        "sha256": "4e4202772328674af68f90f675e077d192337fc8ced15cddcd35875a9de5b5f9"}),
})

# Symbols ported (copied with the transforms below); nothing else is reused.
PORTED_SYMBOLS = MappingProxyType({
    "archarm_base_probe.py": ("_relative", "_link_target", "inspect_members", "check_file",
                              "NoRedirect", "download", "remove_fresh_docker_home"),
    "archarm_runtime_probe.py": (
        "REAL_EXPECT", "FINGERPRINT", "ROOT_NAMES", "VERSION_PINS", "PACKAGE_URL_RE",
        "validate_package_pin_bytes", "read_bounded", "load_json", "validate_package_pins",
        "validate_rootfs_pin", "check_gpg_status", "download_package", "CAP_ADD",
        "INSTALLER_MEMORY", "RUNTIME_MEMORY", "NANO_CPUS", "PIDS_LIMIT", "TMPFS_OPTIONS",
        "NNP_FORMS", "CONTAINER_FORMAT", "IMAGE_FORMAT", "PACMAN_CONF", "INSTALL_SCRIPT",
        "INSTALL_STAGES", "INSTALL_FAILURES", "Layout", "Names", "Record",
        "installer_create_argv", "verify_container", "verify_state", "parse_tokens",
        "_parse_id", "presence", "image_identity", "container_doc", "cleanup_container",
        "cleanup_image", "remove_workspace"),
})

# Deliberately never ported or called.
NOT_PORTED = ("archarm_base_probe.native_probe", "archarm_base_probe.main",
              "archarm_base_probe.command", "archarm_runtime_probe.run_probe",
              "archarm_runtime_probe.main", "archarm_runtime_probe.load_base_helper",
              "archarm_runtime_probe.LocalHost", "archarm_runtime_probe.RUNTIME_SCRIPT",
              "archarm_runtime_probe.runtime_create_argv", "archarm_runtime_probe.finalize",
              "archarm_runtime_probe.write_result")

NAMESPACE_TRANSFORMS = (
    "Refusal(L) -> rs9._archarm_support.refusal.SdkRefusal(L) (ContractError code ARCHARM_L)",
    "process execution: BASE.command/LocalHost.run -> existing rs9 CommandRunner.run with real "
    "CommandReceipt; receipts with executed!=True are refused; wrapper-preserving "
    "per-call dual-pipe capture uses existing bounded-process primitives",
    "docker client: env DOCKER_CONFIG -> global flags --config <fresh lease docker-home> "
    "--host unix:///var/run/docker.sock",
    "owned names tf-archarm-runtime-probe-* -> rs9-archarm-sdk-* plus per-lease nonce; label "
    "prefix tf.archarm-runtime-probe. -> rs9.archarm-sdk. with an added lease label",
    "hostname tf-runtime-probe -> rs9-current-pacman-arm (approved policy)",
    "installer bind target /run/tf-inputs -> /run/rs9-inputs; guest keyring "
    "/var/lib/tf-runtime-probe-gnupg -> /var/lib/rs9-archarm-sdk-gnupg; installer temp "
    "/var/tmp/tf-runtime-probe-install -> /var/tmp/rs9-archarm-sdk-install",
    "installer stdout token prefix TFI -> RSI; package count 139/278 rendered from the "
    "validated pin bundle (qualified bundle is still exactly 139)",
    "installer gains one stage 'account' after ptpcaps and before done: fixed rs9builder "
    "account at the verified runner UID/GID (collision refusal, no reuse/rename)",
    "role containers are created from the verified immutable image ID instead of the tag",
    "verify_container generalized from one RO bind to the closed per-role bind list",
    "rootfs/package downloads unified behind an anonymous fetcher (no proxy, no redirect, "
    "no credentials, exact length then pinned SHA-256)",
)
