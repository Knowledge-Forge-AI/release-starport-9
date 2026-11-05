"""Current-generation-only ArchARM (pacman/aarch64-linux) SDK lease and role adapters.

Status: isolated implementation under the owner-selected narrow build/client
policy (option A). It grants no canonical-write, adoption, hosted-campaign,
signing or publication authority, and it is NOT native-qualified: the
qualified native run (see ``rs9._archarm_support.origin``) executed the
original probe controller, not this module.

``acquire_sdk(...)`` returns an unprepared :class:`ArchArmSDK`. Entering it
eagerly reconstructs the exact qualified SDK inside one disposable job:

1. exact-origin pins (139 packages, signed rootfs) or a hard refusal;
2. fixed host tools (docker, gpgv, uname) present -- never installed;
3. native ``Linux aarch64`` host and ``linux/arm64`` engine;
4. anonymous fixed downloads, exact lengths/hashes, ``gpgv`` VALIDSIG by the
   pinned fingerprint, rootfs header inventory, input re-verification;
5. ``docker import`` of the rootfs, one installer container (cap-drop ALL + the
   seven approved caps, NNP, network/IPC none, read-only public input bind)
   read back before start, offline signed install, hook/file-cap checks, then
   the fixed ``rs9builder`` account at the verified runner UID/GID;
6. the single ``docker commit`` -> SDK image (immutable ID) and identity-bound
   removal of the installer container.

Role adapters (all containers created from the immutable SDK image ID, read
back before start, removed identity-bound afterwards):

* :meth:`ArchArmSDK.builder_runner` -- CommandRunner; verified runner UID:GID,
  no capabilities, read-only root, filtered public sources read-only, the one
  product tree as the sole writable bind.
* :meth:`ArchArmSDK.repository_runner` -- CommandRunner for ``repo-add`` only;
  the assembly tree is the sole bind (writable); signing/verify flags refused.
* :meth:`ArchArmSDK.product_runner` -- dispatches ``repo-add`` to a repository
  runner and everything else to a builder runner (for single-runner callers).
* :meth:`ArchArmSDK.client` -- ClientContainer-compatible context object;
  fresh mutable SDK-derived client with the seven caps, public read-only binds
  and one writable probe-output bind; unprivileged execution only through the
  verified drop-only preamble; untrusted output ingestion after quiescence.

``ArchArmSDK.close`` performs strict cleanup: verified containers (stop without
force, rm without -f), then verified tags (``--no-prune``), then the closed
workspace. Unknown identity/state is retained and reported as a failure.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import posixpath
import re
import time
from types import MappingProxyType
from typing import Any, Callable, Mapping, Sequence
import uuid

from rs9.build_native import CommandReceipt, CommandRunner, NativePrerequisiteUnavailable
from rs9.current_generation import CURRENT_GENERATION
from rs9._archarm_support import paths as _paths
from rs9._archarm_support.cleanup import (Layout, Record, cleanup_container, cleanup_image,
                                          remove_fresh_docker_home, remove_workspace)
from rs9._archarm_support.docker import (FIXED_ENV, HEX64_RE, IMAGE_ID_RE, DockerCli,
                                         bounded_runner, container_doc, executed_receipt,
                                         image_identity, parse_id, presence)
from rs9._archarm_support.evidence import UntrustedEvidence, ingest_tree
from rs9._archarm_support.fetch import AnonymousFetcher
from rs9._archarm_support.origin import MODULE_NATIVE_QUALIFIED
from rs9._archarm_support.pins import PinBundle, load_qualified_pins
from rs9._archarm_support.profiles import (CLIENT_CMD, CLIENT_ENV, INSTALLER_ENV, PLATFORM,
                                           Bind, create_argv, expected, installer_binds,
                                           labels as role_labels, profile_for, verify_container,
                                           verify_state, worker_env)
from rs9._archarm_support.refusal import SdkRefusal, require
from rs9._archarm_support.rootfs import FINGERPRINT, check_file, check_gpg_status, inspect_members
from rs9._archarm_support.scripts import (GUEST_ACCOUNT, GUEST_HOME, INSTALL_FAILURES,
                                          INSTALL_PREFIX, INSTALL_STAGES, PACMAN_CONF,
                                          PREAMBLE_ARG0, SEVEN_CAPS_MASK, ZERO_CAPS,
                                          installer_cmd, parse_tokens, preamble_argv,
                                          render_preamble, strip_attestation, valid_id)

__all__ = ["acquire_sdk", "ArchArmSDK", "ArchArmBuilderRunner", "ArchArmRepositoryRunner",
           "ArchArmProductRunner", "ArchArmClient", "SdkRefusal", "UntrustedEvidence",
           "PROBE_OUTPUT_TARGET", "LEASE_SCHEMA"]

LEASE_SCHEMA = "rs9.archarm-sdk-lease.v1"
PROBE_OUTPUT_TARGET = "/srv/rs9/probe-output"
RUN_ID_RE = re.compile(r"[1-9][0-9]{0,19}")
SOURCE_SHA_RE = re.compile(r"[0-9a-f]{40}")
CONTEXT_REQUIRED = frozenset({"runId", "runAttempt", "sourceSha", "generation"})
CONTEXT_OPTIONAL = frozenset({"privateRoots"})
TOOL_RE = re.compile(r"[A-Za-z0-9_.+-]{1,64}")
ENV_VALUE_RE = re.compile(r"[\x20-\x7e]{0,4096}")
MAX_ARGV = 4096
MAX_ARGV_BYTES = 1024 * 1024
MAX_WORKER_OUTPUT = 8 * 1024 * 1024
MAX_CONTAINERS = 4096
BUILDER_SECONDS = 3600
REPOSITORY_SECONDS = 600
CLIENT_EXEC_SECONDS = 1800
TOOL_PATH = "container:rs9-archarm-sdk"

INSTALL_FLAGS = {"inputs": "installerInputsVisible", "keyring": "publicKeyringReady",
                 "pacman": "pacmanSignedInstall", "delta": "packageDeltaExact",
                 "hooks": "hookStateMatchesInputs", "ptpcaps": "ptpHelperFileCapsSetInInstaller",
                 "account": "guestAccountCreated", "done": "installerCompleted"}
FLAG_KEYS = ("nativeArmHost", "nativeArmEngine", "rootfsSignatureVerified",
             "rootfsHeadersInspected", "packageSignaturesVerified", "inputsReverified",
             "baseImageImported", "installerHostConfigVerified", *INSTALL_FLAGS.values(),
             "sdkImageCommitted", "installerRemoved")
COUNT_KEYS = ("packagesPinned", "packageBytesPinned", "packagesDownloaded",
              "packageSignaturesVerified")
ASSERTIONS = MappingProxyType({"signingSecretsUsed": False, "publicationAuthority": False,
                               "productionKeysAuthorized": False, "productQualification": False,
                               "moduleNativeQualified": MODULE_NATIVE_QUALIFIED})

BUILDER_DENIED_TOOLS = frozenset({"gpg", "gpg2", "gpg-agent", "gpgsm", "pacman-key", "sudo",
                                  "su", "doas", "repo-add", "repo-remove", "docker"})
MAKEPKG_DENIED_LONG = frozenset({"--nodeps", "--skipinteg", "--skippgpcheck", "--skipchecksums",
                                 "--ignorearch", "--sign", "--key", "--syncdeps", "--install",
                                 "--rmdeps", "--asdeps"})
MAKEPKG_DENIED_SHORT = frozenset("dAsir")
BUILDER_ENV_KEYS = frozenset({"SOURCE_DATE_EPOCH", "PKGEXT", "PKGDEST", "SRCDEST", "BUILDDIR",
                              "LOGDEST", "SRCPKGDEST", "npm_config_cache", "npm_config_offline",
                              "NPM_CONFIG_CACHE", "NPM_CONFIG_OFFLINE"})
BUILDER_PATH_ENV_KEYS = frozenset({"PKGDEST", "SRCDEST", "BUILDDIR", "LOGDEST", "SRCPKGDEST",
                                   "npm_config_cache", "NPM_CONFIG_CACHE"})
REPO_ADD_LONG = frozenset({"--new", "--remove", "--prevent-downgrade", "--quiet", "--nocolor",
                           "--include-sigs"})
REPO_ADD_SHORT = frozenset("nRpq")
CLIENT_ENV_KEYS = frozenset({"LANG", "LC_ALL", "TZ", "THEME_FORGE_CACHE_DIR",
                             "PYTHONDONTWRITEBYTECODE", "DISPLAY", "XAUTHORITY",
                             "DBUS_SESSION_BUS_ADDRESS", "WEBKIT_DISABLE_COMPOSITING_MODE",
                             "WEBKIT_DISABLE_DMABUF_RENDERER", "WAYLAND_DISPLAY",
                             "XDG_RUNTIME_DIR", "XDG_CONFIG_HOME", "XDG_DATA_HOME",
                             "XDG_STATE_HOME", "XDG_CACHE_HOME", "NO_AT_BRIDGE",
                             "GSETTINGS_BACKEND", "GDK_BACKEND"})
PACMAN_DENIED_LONG = frozenset({"--nodeps", "--assume-installed", "--dbonly", "--overwrite",
                                "--noscriptlet", "--files", "--refresh-keys", "--recv-keys"})
PACMAN_KEY_DENIED = frozenset({"--recv-keys", "--refresh-keys", "--keyserver", "--populate",
                               "--export", "--edit-key"})

_TOKEN = object()


# --------------------------------------------------------------------------- seams

@dataclass(frozen=True)
class _Seams:
    """Real side effects by default. Pure tests substitute fakes; such leases record
    ``pinsMatchQualifiedOrigin: False`` unless the exact-origin pins were loaded."""

    fetcher: Any
    inspect_rootfs: Callable[[Path, Mapping[str, Any]], Mapping[str, Any]]
    pins_loader: Callable[[], PinBundle]
    runner_identity: Callable[[], tuple]
    nonce: Callable[[], str]


def _real_seams():
    return _Seams(fetcher=AnonymousFetcher(), inspect_rootfs=inspect_members,
                  pins_loader=load_qualified_pins,
                  runner_identity=lambda: (os.getuid(), os.getgid()),
                  nonce=lambda: uuid.uuid4().hex[:12])


def acquire_sdk(*, host: CommandRunner, workspace: Path, context: Mapping[str, Any],
                uid: int, gid: int) -> "ArchArmSDK":
    """Return an unprepared lease; ``with`` enters (prepares eagerly) and closes strictly.

    ``context`` is closed: ``runId`` (decimal string), ``runAttempt`` (``"1"``/``1``),
    ``sourceSha`` (40 hex), ``generation`` (the current generation) and optional
    ``privateRoots`` (absolute host paths, e.g. fixture/runtime homes, that no
    worker bind may overlap). ``uid``/``gid`` must be this process's actual
    numeric identity, each in 1..2147483647.
    """
    return ArchArmSDK(_TOKEN, host=host, workspace=workspace, context=context, uid=uid,
                      gid=gid, seams=_real_seams())


def _acquire(*, host, workspace, context, uid, gid, seams):
    """Internal construction with explicit seams (pure tests only)."""
    require(isinstance(seams, _Seams), "LEASE_CONSTRUCTION")
    return ArchArmSDK(_TOKEN, host=host, workspace=workspace, context=context, uid=uid,
                      gid=gid, seams=seams)


def _validate_context(context):
    require(isinstance(context, Mapping) and type(context) is not ArchArmSDK, "CONTEXT_KEYS")
    keys = set(context)
    require(CONTEXT_REQUIRED <= keys <= CONTEXT_REQUIRED | CONTEXT_OPTIONAL, "CONTEXT_KEYS")
    run_id, attempt, sha = context["runId"], context["runAttempt"], context["sourceSha"]
    require(isinstance(run_id, str) and RUN_ID_RE.fullmatch(run_id) is not None,
            "CONTEXT_RUN_ID")
    require((type(attempt) is str and attempt == "1") or (type(attempt) is int and attempt == 1),
            "CONTEXT_RUN_ATTEMPT")
    require(isinstance(sha, str) and SOURCE_SHA_RE.fullmatch(sha) is not None,
            "CONTEXT_SOURCE_SHA")
    require(context["generation"] == CURRENT_GENERATION, "CONTEXT_GENERATION")
    roots = context.get("privateRoots", ())
    require(isinstance(roots, (list, tuple)) and len(roots) <= 32, "CONTEXT_PRIVATE_ROOTS")
    private = []
    for root in roots:
        require(isinstance(root, (str, os.PathLike)), "CONTEXT_PRIVATE_ROOTS")
        text = os.fspath(root)
        require(isinstance(text, str) and text.startswith("/") and "\x00" not in text
                and os.path.normpath(text) == text and text != "/", "CONTEXT_PRIVATE_ROOTS")
        private.append(Path(text))
    return MappingProxyType({"runId": run_id, "runAttempt": 1, "sourceSha": sha,
                             "generation": CURRENT_GENERATION}), tuple(private)


def _check_argv(argv):
    require(isinstance(argv, (list, tuple)) and 0 < len(argv) <= MAX_ARGV, "ARGV")
    require(all(type(a) is str and "\x00" not in a for a in argv), "ARGV")
    require(sum(len(a.encode("utf-8", "surrogateescape")) for a in argv) <= MAX_ARGV_BYTES, "ARGV")
    require(argv[0] != "" and TOOL_RE.fullmatch(posixpath.basename(argv[0])) is not None, "ARGV")
    return list(argv)


def _within(text, root):
    root = str(root)
    return text == root or text.startswith(root + "/")


def _guest_path(value, label):
    require(isinstance(value, (str, os.PathLike)), label)
    text = os.fspath(value)
    require(isinstance(text, str) and _paths.SAFE_PATH_RE.fullmatch(text) is not None
            and posixpath.normpath(text) == text, label)
    return text


def _check_env(env, allowed, label):
    if env is None:
        return []
    require(isinstance(env, Mapping) and len(env) <= 64, label)
    items = []
    for key in sorted(env):
        value = env[key]
        require(key in allowed and type(value) is str
                and ENV_VALUE_RE.fullmatch(value) is not None, label)
        items.append(f"{key}={value}")
    return items


def _short_clusters(argv):
    for arg in argv[1:]:
        if arg == "--":
            return
        if arg.startswith("-") and not arg.startswith("--") and len(arg) > 1:
            yield arg[1:]


def _makepkg_policy(argv):
    for arg in argv[1:]:
        require(arg.split("=", 1)[0] not in MAKEPKG_DENIED_LONG, "PROVIDER_BYPASS")
    for cluster in _short_clusters(argv):
        require(not (set(cluster) & MAKEPKG_DENIED_SHORT), "PROVIDER_BYPASS")


def _pacman_root_policy(argv):
    for arg in argv[1:]:
        require(arg.split("=", 1)[0] not in PACMAN_DENIED_LONG, "PROVIDER_BYPASS")
    for cluster in _short_clusters(argv):
        require("F" not in cluster, "PROVIDER_BYPASS")
        if cluster[:1] in ("S", "U", "R"):
            require("d" not in cluster, "PROVIDER_BYPASS")


def _pacman_key_policy(argv):
    for arg in argv[1:]:
        require(arg.split("=", 1)[0] not in PACMAN_KEY_DENIED, "CLIENT_TRUST_SCOPE")


# --------------------------------------------------------------------------- lease

class ArchArmSDK:
    """Fresh, typed, source-bound SDK lease. Not serializable, copyable or replaceable."""

    __slots__ = ("_s",)
    platform = PLATFORM
    account = GUEST_ACCOUNT

    def __init__(self, token, *, host, workspace, context, uid, gid, seams):
        if token is not _TOKEN:
            raise SdkRefusal("LEASE_CONSTRUCTION")
        require(isinstance(host, CommandRunner), "HOST_RUNNER")
        ctx, private = _validate_context(context)
        require(valid_id(uid) and valid_id(gid), "RUNNER_IDENTITY")
        require(tuple(seams.runner_identity()) == (uid, gid), "RUNNER_IDENTITY")
        work = _paths.fresh(workspace, "WORK_PATH")
        for root in private:
            require(not _paths.overlaps(work, root), "PRIVATE_MOUNT")
        nonce = seams.nonce()
        require(isinstance(nonce, str) and re.fullmatch(r"[0-9a-f]{12}", nonce) is not None,
                "LEASE_CONSTRUCTION")
        state = _State(host=host, work=work, context=ctx, private=private, uid=uid, gid=gid,
                       seams=seams, nonce=nonce)
        object.__setattr__(self, "_s", state)

    # -- immutability -------------------------------------------------------------
    def __setattr__(self, name, value):
        raise SdkRefusal("LEASE_IMMUTABLE")

    def __delattr__(self, name):
        raise SdkRefusal("LEASE_IMMUTABLE")

    def __reduce_ex__(self, protocol):
        raise SdkRefusal("LEASE_NOT_SERIALIZABLE")

    def __copy__(self):
        raise SdkRefusal("LEASE_NOT_SERIALIZABLE")

    def __deepcopy__(self, memo):
        raise SdkRefusal("LEASE_NOT_SERIALIZABLE")

    # -- public identity ----------------------------------------------------------
    @property
    def image(self) -> str:
        self._require_ready()
        return self._s.records["sdk"].id

    @property
    def uid(self) -> int:
        return self._s.uid

    @property
    def gid(self) -> int:
        return self._s.gid

    @property
    def user(self) -> str:
        return f"{self._s.uid}:{self._s.gid}"

    @property
    def state(self) -> str:
        return self._s.state

    @property
    def context(self):
        """Closed source/run readback; private host paths never leave the lease."""
        self._require_ready()
        return dict(self._s.context)

    @property
    def records(self) -> dict:
        """Closed public lease facts (no paths, names or host account data)."""
        s = self._s
        return copy.deepcopy({
            "schema": LEASE_SCHEMA, "generation": CURRENT_GENERATION, "platform": PLATFORM,
            "state": s.state, "runId": s.context["runId"], "runAttempt": 1,
            "sourceSha": s.context["sourceSha"],
            "imageId": s.records["sdk"].id, "baseImageId": s.records["base"].id,
            "identity": {"uid": s.uid, "gid": s.gid, "guestAccount": GUEST_ACCOUNT,
                         "guestHome": GUEST_HOME},
            "digests": dict(s.digests), "counts": dict(s.counts), "flags": dict(s.flags),
            "pinsMatchQualifiedOrigin": s.pins_qualified,
            # Every accepted host receipt had executed=True (others are refused).
            "hostReceiptCount": (len(s.docker.receipts) if s.docker else 0) + s.host_receipts,
            "roleContainers": len(s.role_records),
            "refusal": s.refusal,
            "cleanupComplete": s.cleanup_complete,
            "assertions": dict(ASSERTIONS),
        })

    # -- lifecycle ----------------------------------------------------------------
    def __enter__(self) -> "ArchArmSDK":
        s = self._s
        require(s.state == "new", "LEASE_STATE")
        s.state = "preparing"
        try:
            self._prepare()
        except BaseException as error:
            s.refusal = error.label if isinstance(error, SdkRefusal) else (
                error.code if hasattr(error, "code") else "UNCLASSIFIED")
            s.state = "failed" if self._cleanup() else "retained"
            raise
        s.state = "ready"
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close(_in_flight=exc_type is not None)
        return False

    def close(self, *, _in_flight=False) -> None:
        s = self._s
        if s.state in ("closed", "new"):
            s.state = "closed"
            return
        for client in list(s.clients):
            client._abandon()
        clean = self._cleanup()
        if not clean:
            s.state = "retained"
            if not _in_flight:
                raise SdkRefusal("CLEANUP_INCOMPLETE")
            return
        s.state = "closed"

    def _require_ready(self):
        require(self._s.state == "ready", "LEASE_STATE")

    # -- preparation (eager) ------------------------------------------------------
    def _prepare(self):
        s = self._s
        pins = s.seams.pins_loader()
        require(isinstance(pins, PinBundle), "PIN_FILE")
        s.pins_qualified = pins.qualified is True
        s.digests.update(pins.digests)
        packages = pins.packages
        require(len(packages) == pins.expect["packageCount"], "PIN_COUNT")
        s.counts["packagesPinned"] = len(packages)
        s.counts["packageBytesPinned"] = sum(p["bytes"] for p in packages)
        check_file(pins.certificate, pins.expect["publicKeyBytes"], pins.expect["publicKeySha256"])
        host = s.host

        missing = [tool for tool in ("docker", "gpgv", "uname") if host.which(tool) is None]
        if missing:
            raise NativePrerequisiteUnavailable("Fixed host tools are unavailable",
                                                missing_tools=missing)
        receipt = executed_receipt(bounded_runner(host, 30).run(["uname", "-s", "-m"],
                                                                env=dict(FIXED_ENV)))
        s.host_receipts += 1
        require(receipt.exit_code == 0 and receipt.stdout_bytes.strip() == b"Linux aarch64",
                "NATIVE_ARM_HOST")
        s.flags["nativeArmHost"] = True

        layout = Layout(s.work, len(packages))
        s.layout = layout
        try:
            layout.work.mkdir(mode=0o700)
        except OSError:
            raise SdkRefusal("FRESH_WORK_ROOT") from None
        s.workspace_created = True
        for directory in (layout.home, layout.docker_home, layout.rootfs_dir,
                          layout.inputs, layout.pkg_dir, layout.key_dir):
            directory.mkdir(mode=0o700)
        with (layout.home / "common.conf").open("x"):
            pass
        docker = DockerCli(host, layout.docker_home)
        s.docker = docker

        code, out = docker(["version", "--format", "{{.Server.Os}}/{{.Server.Arch}}"])
        require(code == 0 and out.strip() == b"linux/arm64", "NATIVE_ARM_ENGINE")
        code, out = docker(["info", "--format", "{{.OSType}}/{{.Architecture}}"])
        require(code == 0 and out.strip() in (b"linux/aarch64", b"linux/arm64"),
                "NATIVE_ARM_ENGINE")
        s.flags["nativeArmEngine"] = True
        for record in (s.records["base"], s.records["sdk"]):
            require(not presence(docker, "image", record.name), "OWNED_NAME_COLLISION")
        require(not presence(docker, "container", s.records["installer"].name),
                "OWNED_NAME_COLLISION")

        gpg_env = {"HOME": str(layout.home), "GNUPGHOME": str(layout.home), **FIXED_ENV}
        rootfs_pin = pins.rootfs_pin
        fetch = s.seams.fetcher.fetch
        clock = _monotonic
        deadline = clock() + 900
        fetch(rootfs_pin["rootfsUrl"], layout.rootfs, rootfs_pin["rootfsBytes"],
              rootfs_pin["rootfsSha256"], deadline, rootfs_url=rootfs_pin["rootfsUrl"])
        fetch(rootfs_pin["rootfsUrl"] + ".sig", layout.rootfs_sig, rootfs_pin["signatureBytes"],
              rootfs_pin["signatureSha256"], clock() + 300, rootfs_url=rootfs_pin["rootfsUrl"])
        self._gpgv(layout.rootfs_sig, layout.rootfs, pins.certificate, gpg_env, 600,
                   "ROOTFS_SIGNATURE")
        s.flags["rootfsSignatureVerified"] = True
        s.seams.inspect_rootfs(layout.rootfs, rootfs_pin)
        s.flags["rootfsHeadersInspected"] = True

        deadline = clock() + 1800
        for index, record in enumerate(packages):
            fetch(record["url"], layout.package(index), record["bytes"], record["sha256"],
                  deadline, rootfs_url=rootfs_pin["rootfsUrl"])
            fetch(record["url"] + ".sig", layout.signature(index), record["signatureBytes"],
                  record["signatureSha256"], deadline, rootfs_url=rootfs_pin["rootfsUrl"])
            s.counts["packagesDownloaded"] = index + 1
        for index in range(len(packages)):
            self._gpgv(layout.signature(index), layout.package(index), pins.certificate,
                       gpg_env, 300, "PACKAGE_SIGNATURE")
            s.counts["packageSignaturesVerified"] = index + 1
        s.flags["packageSignaturesVerified"] = True

        with layout.pacman_conf.open("x") as stream:
            stream.write(PACMAN_CONF)
        certificate_bytes = Path(pins.certificate).read_bytes()
        require(len(certificate_bytes) == pins.expect["publicKeyBytes"], "INPUT_FILE")
        with layout.cert_copy.open("xb") as stream:
            stream.write(certificate_bytes)
        check_file(layout.cert_copy, pins.expect["publicKeyBytes"], pins.expect["publicKeySha256"])
        for index, record in enumerate(packages):
            check_file(layout.package(index), record["bytes"], record["sha256"])
            check_file(layout.signature(index), record["signatureBytes"], record["signatureSha256"])
        require(set(os.listdir(layout.pkg_dir)) == layout.package_names()
                and set(os.listdir(layout.key_dir)) == {layout.cert_copy.name}
                and set(os.listdir(layout.inputs)) == {"pkg", "key", "pacman.conf"}, "INPUT_SET")
        for path in [layout.pacman_conf, layout.cert_copy,
                     *(layout.package(i) for i in range(len(packages))),
                     *(layout.signature(i) for i in range(len(packages)))]:
            os.chmod(path, 0o644)
        for directory in (layout.pkg_dir, layout.key_dir, layout.inputs):
            os.chmod(directory, 0o755)

        check_file(layout.rootfs, rootfs_pin["rootfsBytes"], rootfs_pin["rootfsSha256"])
        check_file(layout.rootfs_sig, rootfs_pin["signatureBytes"], rootfs_pin["signatureSha256"])
        s.flags["inputsReverified"] = True
        base = s.records["base"]
        base.requested = True
        code, out = docker(["import", "--platform", PLATFORM, str(layout.rootfs), base.name],
                           timeout=900)
        require(code == 0, "IMPORT_FAILED")
        base.id = parse_id(out, IMAGE_ID_RE, "IMPORT_FAILED")
        require(image_identity(docker, base.name, "IMAGE_IDENTITY") == base.id, "IMAGE_IDENTITY")
        s.flags["baseImageImported"] = True

        installer = s.records["installer"]
        profile = profile_for("installer", "0:0")
        spec = dict(name=installer.name, image=base.id, profile=profile,
                    label_values=installer.labels, env=INSTALLER_ENV,
                    binds=installer_binds(layout.inputs), workdir="/",
                    cmd=installer_cmd(count=len(packages), uid=s.uid, gid=s.gid))
        installer.requested = True
        code, out = docker(create_argv(**spec), timeout=180)
        require(code == 0, "INSTALLER_CREATE")
        installer.id = parse_id(out, HEX64_RE, "INSTALLER_CREATE")
        doc = container_doc(docker, installer.name, "INSTALLER_HOST_CONFIG")
        verify_container(doc, expected(**spec, container_id=installer.id), "INSTALLER_HOST_CONFIG")
        verify_state(doc, state="created", label="INSTALLER_HOST_CONFIG")
        s.flags["installerHostConfigVerified"] = True
        code, out = docker(["start", "--attach", installer.id], timeout=1800, limit=4096)
        done, failure = parse_tokens(out, INSTALL_PREFIX, INSTALL_STAGES, INSTALL_FAILURES,
                                     "INSTALL_OUTPUT")
        for stage in done:
            s.flags[INSTALL_FLAGS[stage]] = True
        if failure is not None:
            raise SdkRefusal("INSTALL_" + failure.upper())
        require(code == 0 and tuple(done) == INSTALL_STAGES, "INSTALL_INCOMPLETE")
        doc = container_doc(docker, installer.id, "INSTALL_STATE")
        require(doc.get("Id") == installer.id, "INSTALL_STATE")
        verify_state(doc, state="exited", exit_code=0, label="INSTALL_STATE")

        sdk = s.records["sdk"]
        sdk.requested = True
        code, out = docker(["commit", installer.id, sdk.name], timeout=900)
        require(code == 0, "COMMIT_FAILED")
        sdk.id = parse_id(out, IMAGE_ID_RE, "COMMIT_FAILED")
        require(image_identity(docker, sdk.name, "IMAGE_IDENTITY") == sdk.id, "IMAGE_IDENTITY")
        s.flags["sdkImageCommitted"] = True
        require(cleanup_container(docker, installer), "CLEANUP_INCOMPLETE")
        s.flags["installerRemoved"] = True

    def _gpgv(self, signature, payload, certificate, env, seconds, label):
        s = self._s
        receipt = executed_receipt(bounded_runner(s.host, seconds).run(
            ["gpgv", "--homedir", str(s.layout.home), "--keyring", str(certificate),
             "--status-fd", "1", str(signature), str(payload)], env=dict(env)))
        s.host_receipts += 1
        require(len(receipt.stdout_bytes) <= 8192, label)
        check_gpg_status(receipt.exit_code, receipt.stdout_bytes, FINGERPRINT, label)

    # -- cleanup ------------------------------------------------------------------
    def _cleanup(self):
        s = self._s
        if not s.workspace_created:
            s.cleanup_complete = True
            return True
        try:
            docker = s.docker
            if docker is not None:
                for record in [*reversed(s.role_records), s.records["installer"]]:
                    if not cleanup_container(docker, record):
                        s.cleanup_complete = False
                        return False
                for record in (s.records["sdk"], s.records["base"]):
                    if not cleanup_image(docker, record):
                        s.cleanup_complete = False
                        return False
            layout = s.layout
            if os.path.lexists(layout.docker_home):
                remove_fresh_docker_home(layout.docker_home)
            if os.path.lexists(layout.work):
                remove_workspace(layout)
            s.cleanup_complete = True
            return True
        except Exception:
            s.cleanup_complete = False
            return False

    # -- role containers ----------------------------------------------------------
    def _new_record(self, role):
        s = self._s
        self._require_ready()
        require(len(s.role_records) < MAX_CONTAINERS, "CONTAINER_LIMIT")
        name = f"rs9-archarm-{role}-{s.suffix}-{len(s.role_records):04d}"
        record = Record("container", name, role_labels(s.context, s.nonce, role))
        require(not presence(s.docker, "container", name), "OWNED_NAME_COLLISION")
        s.role_records.append(record)
        return record

    def _poison(self, error):
        """A role readback/state/cleanup refusal invalidates the lease (fail closed)."""
        s = self._s
        if s.state == "ready":
            s.state = "poisoned"
            s.refusal = error.label if isinstance(error, SdkRefusal) else "UNCLASSIFIED"

    def _create_verified(self, role, *, binds, env, workdir, cmd, label):
        try:
            return self._create_verified_inner(role, binds=binds, env=env, workdir=workdir,
                                               cmd=cmd, label=label)
        except SdkRefusal as error:
            if error.label != "LEASE_STATE":
                self._poison(error)
            raise

    def _create_verified_inner(self, role, *, binds, env, workdir, cmd, label):
        s = self._s
        record = self._new_record(role)
        profile = profile_for(role, "0:0" if role == "client" else self.user)
        spec = dict(name=record.name, image=s.records["sdk"].id, profile=profile,
                    label_values=record.labels, env=tuple(env), binds=tuple(binds),
                    workdir=workdir, cmd=tuple(cmd))
        record.requested = True
        code, out = s.docker(create_argv(**spec), timeout=180)
        require(code == 0, label + "_CREATE")
        record.id = parse_id(out, HEX64_RE, label + "_CREATE")
        doc = container_doc(s.docker, record.name, label + "_HOST_CONFIG")
        verify_container(doc, expected(**spec, container_id=record.id), label + "_HOST_CONFIG")
        verify_state(doc, state="created", label=label + "_HOST_CONFIG")
        return record

    def _run_once(self, role, *, argv, binds, env, workdir, seconds, label):
        s = self._s
        cmd = preamble_argv(argv, uid=s.uid, gid=s.gid, bounding=ZERO_CAPS, umask="022",
                            attest=True)
        record = self._create_verified(role, binds=binds, env=worker_env(env), workdir=workdir,
                                       cmd=cmd, label=label)
        try:
            outer = s.docker.receipt(["start", "--attach", record.id], timeout=seconds,
                                     limit=MAX_WORKER_OUTPUT)
            doc = container_doc(s.docker, record.id, label + "_STATE")
            require(doc.get("Id") == record.id, label + "_STATE")
            verify_state(doc, state="exited", exit_code=outer.exit_code, label=label + "_STATE")
            require(cleanup_container(s.docker, record), "CLEANUP_INCOMPLETE")
        except SdkRefusal as error:
            self._poison(error)
            raise
        stderr = strip_attestation(outer.exit_code, outer.stderr_bytes)
        return CommandReceipt(list(argv), outer.exit_code, outer.stdout_bytes, stderr,
                              tool_name=argv[0], tool_path=TOOL_PATH, executed=outer.executed)

    # -- public role adapters -----------------------------------------------------
    def builder_runner(self, product_dir: Path, public_sources: Sequence[Path]) -> "ArchArmBuilderRunner":
        self._require_ready()
        return ArchArmBuilderRunner(_TOKEN, self, product_dir, public_sources)

    def repository_runner(self, assembly: Path) -> "ArchArmRepositoryRunner":
        self._require_ready()
        return ArchArmRepositoryRunner(_TOKEN, self, assembly)

    def product_runner(self, product_dir: Path, public_sources: Sequence[Path],
                       repository_dir: Path) -> "ArchArmProductRunner":
        self._require_ready()
        return ArchArmProductRunner(_TOKEN, self.builder_runner(product_dir, public_sources),
                                    self.repository_runner(repository_dir))

    def client(self, mounts: Sequence[tuple], probe_output: Path) -> "ArchArmClient":
        self._require_ready()
        return ArchArmClient(_TOKEN, self, mounts, probe_output)

    def _admit_bind_sources(self, paths, *, allow_files):
        s = self._s
        admitted = []
        for value in paths:
            path = _paths.physical(value, "MOUNT_PATH", kind="any" if allow_files else "dir")
            admitted.append(path)
        _paths.require_disjoint([*admitted, s.work], s.private, "MOUNT_OVERLAP")
        return admitted


def _monotonic():
    return time.monotonic()


class _State:
    def __init__(self, *, host, work, context, private, uid, gid, seams, nonce):
        self.host, self.work, self.context, self.private = host, work, context, private
        self.uid, self.gid, self.seams, self.nonce = uid, gid, seams, nonce
        self.suffix = f"r{context['runId']}-a1-{context['sourceSha'][:12]}-{nonce}"
        self.state = "new"
        self.refusal = None
        self.cleanup_complete = None
        self.workspace_created = False
        self.layout = None
        self.docker = None
        self.host_receipts = 0
        self.pins_qualified = False
        self.digests = {}
        self.counts = {k: 0 for k in COUNT_KEYS}
        self.flags = {k: False for k in FLAG_KEYS}
        self.role_records = []
        self.clients = []
        self.records = {
            "base": Record("image", "rs9-archarm-sdk-base:" + self.suffix),
            "sdk": Record("image", "rs9-archarm-sdk:" + self.suffix),
            "installer": Record("container", "rs9-archarm-installer-" + self.suffix,
                                role_labels(context, nonce, "installer")),
        }


# --------------------------------------------------------------------------- runners

class _LeaseRunner(CommandRunner):
    def __reduce_ex__(self, protocol):
        raise SdkRefusal("LEASE_NOT_SERIALIZABLE")

    def _lease(self):
        lease = self._sdk
        require(type(lease) is ArchArmSDK, "LEASE_STATE")
        lease._require_ready()
        return lease

    def which(self, tool_name: str) -> str | None:
        require(isinstance(tool_name, str) and TOOL_RE.fullmatch(tool_name) is not None, "ARGV")
        receipt = self._execute(["/usr/bin/bash", "-c", 'command -v -- "$1"', "rs9-which",
                                 tool_name], cwd=None, env=None, probe=True)
        located = receipt.stdout_text.strip()
        return located if receipt.exit_code == 0 and located else None


class ArchArmBuilderRunner(_LeaseRunner):
    """CommandRunner: verified UID:GID, cap 0, RO root, RO sources, sole RW product tree."""

    def __init__(self, token, sdk, product_dir, public_sources):
        if token is not _TOKEN:
            raise SdkRefusal("LEASE_CONSTRUCTION")
        self._sdk = sdk
        s = sdk._s
        require(isinstance(public_sources, (list, tuple)) and len(public_sources) <= 32,
                "MOUNT_PATH")
        product = _paths.physical(product_dir, "PRODUCT_DIR", kind="dir")
        _paths.owned_directory(product, s.uid, s.gid, "PRODUCT_DIR", empty=False)
        sources = sdk._admit_bind_sources(public_sources, allow_files=True)
        _paths.require_disjoint([product, *sources, s.work], s.private, "MOUNT_OVERLAP")
        for source in sources:
            _paths.scan_public_tree(source, "PUBLIC_SOURCE")
        self.product_dir = product
        self._binds = (Bind(str(product), str(product), False),
                       *(Bind(str(p), str(p), True) for p in sources))

    def run(self, argv, *, cwd=None, env=None) -> CommandReceipt:
        return self._execute(argv, cwd=cwd, env=env, probe=False)

    def _execute(self, argv, *, cwd, env, probe):
        lease = self._lease()
        argv = _check_argv(argv)
        tool = posixpath.basename(argv[0])
        if not probe:
            require(tool not in BUILDER_DENIED_TOOLS, "ROLE_TOOL")
            if tool == "makepkg":
                _makepkg_policy(argv)
        workdir = str(self.product_dir) if cwd is None else _guest_path(cwd, "WORKDIR")
        require(any(_within(workdir, b.target) for b in self._binds), "WORKDIR")
        items = _check_env(env, BUILDER_ENV_KEYS, "WORKER_ENV")
        for item in items:
            key, value = item.split("=", 1)
            if key in BUILDER_PATH_ENV_KEYS:
                require(_within(_guest_path(value, "WORKER_ENV"), str(self.product_dir)),
                        "WORKER_ENV")
        return lease._run_once("builder", argv=argv, binds=self._binds, env=items,
                               workdir=workdir, seconds=BUILDER_SECONDS, label="BUILDER")


class ArchArmRepositoryRunner(_LeaseRunner):
    """CommandRunner for unsigned ``repo-add`` only; the assembly tree is the sole bind."""

    def __init__(self, token, sdk, assembly):
        if token is not _TOKEN:
            raise SdkRefusal("LEASE_CONSTRUCTION")
        self._sdk = sdk
        s = sdk._s
        root = _paths.physical(assembly, "ASSEMBLY_DIR", kind="dir")
        _paths.owned_directory(root, s.uid, s.gid, "ASSEMBLY_DIR", empty=False)
        _paths.require_disjoint([root, s.work], s.private, "MOUNT_OVERLAP")
        _paths.scan_public_tree(root, "ASSEMBLY_DIR")
        self.assembly = root
        self._binds = (Bind(str(root), str(root), False),)

    def run(self, argv, *, cwd=None, env=None) -> CommandReceipt:
        return self._execute(argv, cwd=cwd, env=env, probe=False)

    def _execute(self, argv, *, cwd, env, probe):
        lease = self._lease()
        argv = _check_argv(argv)
        root = str(self.assembly)
        if not probe:
            require(argv[0] in ("repo-add", "/usr/bin/repo-add"), "ROLE_TOOL")
            positional = False
            for arg in argv[1:]:
                if not positional and arg == "--":
                    positional = True
                elif not positional and arg.startswith("--"):
                    require(arg in REPO_ADD_LONG, "REPO_ADD_SIGNING")
                elif not positional and arg.startswith("-") and len(arg) > 1:
                    require(set(arg[1:]) <= REPO_ADD_SHORT, "REPO_ADD_SIGNING")
                else:
                    require(_within(_guest_path(arg, "REPO_ADD_PATH"), root)
                            and arg != root, "REPO_ADD_PATH")
        require(not env, "WORKER_ENV")
        workdir = root if cwd is None else _guest_path(cwd, "WORKDIR")
        require(_within(workdir, root), "WORKDIR")
        return lease._run_once("repository", argv=argv, binds=self._binds, env=(),
                               workdir=workdir, seconds=REPOSITORY_SECONDS, label="REPOSITORY")


class ArchArmProductRunner(CommandRunner):
    """Single-runner facade: ``repo-add`` -> repository role, everything else -> builder."""

    def __init__(self, token, builder, repository):
        if token is not _TOKEN:
            raise SdkRefusal("LEASE_CONSTRUCTION")
        self.builder, self.repository = builder, repository

    def __reduce_ex__(self, protocol):
        raise SdkRefusal("LEASE_NOT_SERIALIZABLE")

    def which(self, tool_name):
        return self.builder.which(tool_name)

    def run(self, argv, *, cwd=None, env=None):
        argv = _check_argv(argv)
        if posixpath.basename(argv[0]) == "repo-add":
            return self.repository.run(argv, cwd=cwd, env=env)
        return self.builder.run(argv, cwd=cwd, env=env)


# --------------------------------------------------------------------------- client

class ArchArmClient:
    """ClientContainer-compatible fresh mutable client (pacman family only).

    ``exec(argv)`` runs as 0:0 (seven caps, NNP) for install/remove/configure.
    ``exec(argv, user=lease.user)`` runs through the attested drop-only preamble.
    ``unprivileged_prefix`` is available only after ``verify_unprivileged_identity``
    succeeded and wraps every probe in the same (silent) preamble.
    """

    family = "pacman"

    def __init__(self, token, sdk, mounts, probe_output):
        if token is not _TOKEN:
            raise SdkRefusal("LEASE_CONSTRUCTION")
        self._sdk = sdk
        s = sdk._s
        require(isinstance(mounts, (list, tuple)) and len(mounts) <= 16, "CLIENT_MOUNTS")
        sources, binds, targets = [], [], []
        for item in mounts:
            require(isinstance(item, (list, tuple)) and len(item) == 3, "CLIENT_MOUNTS")
            source, target, writable = item
            require(writable is False, "CLIENT_MOUNT_WRITABLE")
            target = _paths.guest_target(target, "CLIENT_MOUNTS")
            require(not _within(target, PROBE_OUTPUT_TARGET)
                    and not _within(PROBE_OUTPUT_TARGET, target), "CLIENT_MOUNTS")
            for other in targets:
                require(not _within(target, other) and not _within(other, target),
                        "CLIENT_MOUNTS")
            targets.append(target)
            sources.append(source)
        admitted = sdk._admit_bind_sources(sources, allow_files=True)
        output = _paths.physical(probe_output, "PROBE_OUTPUT", kind="dir")
        _paths.owned_directory(output, s.uid, s.gid, "PROBE_OUTPUT", empty=True)
        _paths.require_disjoint([*admitted, output, s.work], s.private, "MOUNT_OVERLAP")
        for source in admitted:
            _paths.scan_public_tree(source, "PUBLIC_SOURCE")
        for source, target in zip(admitted, targets):
            binds.append(Bind(str(source), target, True))
        binds.append(Bind(str(output), PROBE_OUTPUT_TARGET, False))
        self._binds = tuple(binds)
        self._output = output
        self._record = None
        self._phase = "new"
        self._identity_verified = False
        self.mounts = [(str(src), tgt, False) for src, tgt in zip(admitted, targets)]
        self.last_diagnostics = {}
        self.last_inventory_stage = None

    def __reduce_ex__(self, protocol):
        raise SdkRefusal("LEASE_NOT_SERIALIZABLE")

    @property
    def image(self):
        return self._sdk.image

    @property
    def platform(self):
        return PLATFORM

    @property
    def probe_output_target(self):
        return PROBE_OUTPUT_TARGET

    def __enter__(self) -> "ArchArmClient":
        sdk = self._sdk
        sdk._require_ready()
        require(self._phase == "new", "CLIENT_STATE")
        s = sdk._s
        self._phase = "starting"
        s.clients.append(self)
        try:
            self._record = sdk._create_verified(
                "client", binds=self._binds, env=CLIENT_ENV, workdir="/", cmd=CLIENT_CMD,
                label="CLIENT")
            code, _ = s.docker(["start", self._record.id], timeout=120)
            require(code == 0, "CLIENT_START")
            doc = container_doc(s.docker, self._record.id, "CLIENT_STATE")
            require(doc.get("Id") == self._record.id, "CLIENT_STATE")
            verify_state(doc, state="running", label="CLIENT_STATE")
        except BaseException as error:
            self._phase = "failed"
            if isinstance(error, SdkRefusal) and error.label != "LEASE_STATE":
                sdk._poison(error)
            raise
        self._phase = "running"
        return self

    def __exit__(self, exc_type, exc, tb):
        clean = self._finish()
        if not clean and exc_type is None:
            raise SdkRefusal("CLEANUP_INCOMPLETE")
        return False

    def _abandon(self):
        self._finish()

    def _finish(self):
        s = self._sdk._s
        clean = True
        try:
            if self._phase == "running":
                self.quiesce()
        except Exception:
            clean = False
        try:
            if self._record is not None:
                clean = cleanup_container(s.docker, self._record) and clean
        except Exception:
            clean = False
        if self in s.clients:
            s.clients.remove(self)
        if self._phase not in ("quiesced",):
            self._phase = "closed" if clean else "retained"
        return clean

    def quiesce(self) -> None:
        """Stop the only writer (no force) and read back that it exited."""
        s = self._sdk._s
        require(self._phase == "running", "CLIENT_STATE")
        code, _ = s.docker(["container", "stop", "--time", "10", self._record.id], timeout=60)
        require(code == 0, "CLIENT_QUIESCE")
        doc = container_doc(s.docker, self._record.id, "CLIENT_QUIESCE")
        require(doc.get("Id") == self._record.id, "CLIENT_QUIESCE")
        verify_state(doc, state="stopped", label="CLIENT_QUIESCE")
        self._phase = "quiesced"

    def ingest_output(self, declared: Mapping[str, Callable[[bytes], Any]],
                      required: Sequence[str] = ()) -> UntrustedEvidence:
        """Schema-validate the probe-output tree; only after the writer was quiesced."""
        require(self._phase == "quiesced", "EVIDENCE_NOT_QUIESCED")
        s = self._sdk._s
        return ingest_tree(self._output, uid=s.uid, gid=s.gid, declared=declared,
                           required=required)

    # -- execution ----------------------------------------------------------------
    def _running(self):
        self._sdk._require_ready()
        require(self._phase == "running" and self._record is not None
                and self._record.id is not None, "CLIENT_STATE")
        return self._sdk._s

    def exec(self, argv: Sequence[str], *, user: str | None = None,
             env: Mapping[str, str] | None = None) -> CommandReceipt:
        return self._exec_with_capture(argv, user=user, env=env, output_limit=MAX_WORKER_OUTPUT)

    def _exec_with_capture(self, argv: Sequence[str], *, user: str | None = None,
                           env: Mapping[str, str] | None = None, output_limit: int) -> CommandReceipt:
        if output_limit != MAX_WORKER_OUTPUT:
            from rs9.client_inventory import MAX_STDOUT_BYTES, scanner_argv
            require(type(output_limit) is int and output_limit == MAX_STDOUT_BYTES
                    and user is None and env is None
                    and list(argv) == scanner_argv(family="pacman"), "INVENTORY_COMMAND")
        s = self._running()
        argv = _check_argv(argv)
        items = _check_env(env, CLIENT_ENV_KEYS, "CLIENT_ENV")
        env_args = [arg for item in items for arg in ("-e", item)]
        if user is None or user == "0:0":
            tool = posixpath.basename(argv[0])
            if tool == "pacman":
                _pacman_root_policy(argv)
            elif tool == "pacman-key":
                _pacman_key_policy(argv)
            outer = s.docker.receipt(["exec", "--user", "0:0", "--workdir", "/", *env_args,
                                      self._record.id, *argv],
                                     timeout=CLIENT_EXEC_SECONDS, limit=output_limit)
            return CommandReceipt(list(argv), outer.exit_code, outer.stdout_bytes,
                                  outer.stderr_bytes, tool_name=argv[0], tool_path=TOOL_PATH,
                                  executed=outer.executed)
        require(user == self._sdk.user, "CLIENT_USER")
        command = preamble_argv(argv, uid=s.uid, gid=s.gid, bounding=SEVEN_CAPS_MASK,
                                umask="077", attest=True)
        outer = s.docker.receipt(["exec", "--user", self._sdk.user, "--workdir", "/tmp",
                                  "-e", f"HOME={GUEST_HOME}", "-e", "TMPDIR=/tmp", *env_args,
                                  self._record.id, *command],
                                 timeout=CLIENT_EXEC_SECONDS, limit=output_limit)
        stderr = strip_attestation(outer.exit_code, outer.stderr_bytes)
        return CommandReceipt(list(argv), outer.exit_code, outer.stdout_bytes, stderr,
                              tool_name=argv[0], tool_path=TOOL_PATH, executed=outer.executed)

    def verify_unprivileged_identity(self) -> bool:
        """Attested preamble run; must pass before ``unprivileged_prefix`` is released."""
        receipt = self.exec(["/usr/bin/true"], user=self._sdk.user)
        require(receipt.exit_code == 0 and receipt.stdout_bytes == b""
                and receipt.stderr_bytes == b"", "PREAMBLE_IDENTITY")
        self._identity_verified = True
        return True

    @property
    def unprivileged_prefix(self) -> list[str]:
        s = self._running()
        require(self._identity_verified, "PREAMBLE_IDENTITY")
        script = render_preamble(uid=s.uid, gid=s.gid, bounding=SEVEN_CAPS_MASK, umask="077",
                                 attest=False)
        return [*s.docker.argv(["exec", "-i", "--user", self._sdk.user, "--workdir", "/tmp",
                                "-e", f"HOME={GUEST_HOME}", "-e", "TMPDIR=/tmp",
                                self._record.id]),
                "/usr/bin/bash", "-c", script, PREAMBLE_ARG0]

    def inventory(self, stage: str | None = None) -> dict[str, str]:
        from rs9.client_inventory import MAX_STDOUT_BYTES, run_and_parse
        from rs9.hosted_deb import inventory_excluded
        self._running()
        self.last_inventory_stage = stage
        self.last_diagnostics = {}
        # The unchanged shared inventory protocol permits at most 32 MiB. Only
        # its exact root scanner command receives that bound; ordinary exec
        # remains at MAX_WORKER_OUTPUT, with no caller-selectable limit.
        result = run_and_parse(lambda argv: self._exec_with_capture(argv, output_limit=MAX_STDOUT_BYTES),
                               exclusion=lambda path: inventory_excluded("pacman", path),
                               file_exclusion=None, with_modes=True, stage=stage,
                               family="pacman", return_diagnostics=True)
        if isinstance(result, tuple):
            self.last_diagnostics = result[1] or {}
            return result[0]
        return result


def module_source_sha256() -> str:
    """SHA-256 of this module's source bytes (for the parent's source binding)."""
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
