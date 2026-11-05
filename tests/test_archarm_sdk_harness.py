"""Pure fakes for the ArchARM SDK lease tests: no processes, network, crypto or packages.

``FakeEngine`` is a CommandRunner that models the small Docker CLI surface the
lease uses (create/inspect/start/exec/stop/rm/commit/import/image rm), turning
the exact create argv into an inspect document so readback is meaningful. Its
receipts claim ``executed=True`` only so the pure flow can be driven; the lease
records ``pinsMatchQualifiedOrigin: False`` for these synthetic pins and never
claims native qualification.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest

from rs9.build_native import CommandReceipt, CommandRunner
from rs9.current_generation import CURRENT_GENERATION
from rs9 import archarm_sdk
from rs9._archarm_support.docker import DOCKER_HOST
from rs9._archarm_support.pins import (FINGERPRINT, PACKAGE_PIN_SCHEMA, REAL_EXPECT, ROOT_NAMES,
                                       TOOL_NODE_VERSION, TOOL_PYTHON_VERSION, validated_bundle)
from rs9._archarm_support.refusal import SdkRefusal
from rs9._archarm_support.rootfs import check_file
from rs9._archarm_support.scripts import INSTALL_STAGES, PREAMBLE_OK

ROLE_LABEL = "rs9.archarm-sdk.role"
NONCE = "0123456789ab"
CONTEXT = {"runId": "4242", "runAttempt": "1", "sourceSha": "a" * 40,
           "generation": CURRENT_GENERATION}
VERSIONS = {"fakeroot": "1.37-1", "python": "3.14.9-1", "nodejs-lts-jod": "22.23.4-1",
            "gtk3": "3.24.51-1", "webkit2gtk-4.1": "2.54.2-1", "xorg-server-xvfb": "21.1.18-1"}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def good_status(fpr=FINGERPRINT):
    return (f"[GNUPG:] NEWSIG\n[GNUPG:] GOODSIG {fpr[-16:]} ArchARM\n"
            f"[GNUPG:] VALIDSIG {fpr} 2026-01-01 1767225600 0 4 0 1 8 00 {fpr}\n").encode()


def install_tokens(stages=INSTALL_STAGES, failure=None):
    text = "".join(f"RSI {stage}\n" for stage in stages)
    if failure:
        text += f"RSI fail {failure}\n"
    return text.encode()


def make_bundle(directory):
    """Synthetic pins with the closed qualified schema (6 packages; never qualified)."""
    directory.mkdir()
    blobs, packages, total = {}, [], 0
    for name in ROOT_NAMES:
        version = VERSIONS[name]
        filename = f"{name}-{version}-aarch64.pkg.tar.xz"
        url = "https://fl.us.mirror.archlinuxarm.org/aarch64/extra/" + filename
        body, signature = b"pkg-" + name.encode(), b"sig-" + name.encode()
        blobs[url], blobs[url + ".sig"] = body, signature
        packages.append({"name": name, "version": version, "architecture": "aarch64",
                         "url": url, "filename": filename, "bytes": len(body),
                         "sha256": sha(body), "signatureBytes": len(signature),
                         "signatureSha256": sha(signature), "licenses": ["0BSD"]})
        total += len(body)
    rootfs, rootfs_sig, cert = b"rootfs-bytes", b"rootfs-sig", b"public-cert"
    rootfs_url = REAL_EXPECT["rootfsUrl"]
    blobs[rootfs_url], blobs[rootfs_url + ".sig"] = rootfs, rootfs_sig
    (directory / "cert.gpg").write_bytes(cert)
    expect = {"packageCount": len(packages), "packageBytes": total, "rootfsUrl": rootfs_url,
              "rootfsBytes": len(rootfs), "rootfsSha256": sha(rootfs),
              "publicKeyBytes": len(cert), "publicKeySha256": sha(cert)}
    package_doc = {"schema": PACKAGE_PIN_SCHEMA, "rootNames": list(ROOT_NAMES),
                   "publicSigningFingerprint": FINGERPRINT, "packages": packages,
                   "packageCount": len(packages), "totalBytes": total,
                   "toolPythonVersion": TOOL_PYTHON_VERSION, "toolNodeVersion": TOOL_NODE_VERSION,
                   "networkDuringInstallOrProbe": False, "noBasePackageUpgrades": True}
    escapes = [{"path": f"a\\x2d{i}", "size": 1, "mode": 420, "sha256": "0" * 64} for i in range(3)]
    rootfs_doc = {"schema": "task.ArchARM-base-input-pin.v1", "rootfsUrl": rootfs_url,
                  "rootfsBytes": len(rootfs), "rootfsSha256": sha(rootfs),
                  "signatureBytes": len(rootfs_sig), "signatureSha256": sha(rootfs_sig),
                  "publicKeySha256": sha(cert), "publicKeyFingerprint": FINGERPRINT,
                  "members": 1, "declaredBytes": 1, "literalEscapes": escapes,
                  "setIdMembers": [], "rootDirectoryHeaders": 0, "literalEscapeLinks": [],
                  "declaredBytesCorrection": "synthetic", "publicKeyBytes": len(cert)}
    digests = {"rootfsSha256": sha(rootfs), "rootfsPinSha256": "1" * 64,
               "packagePinsSha256": "2" * 64, "publicKeySha256": sha(cert),
               "publicKeyFingerprint": FINGERPRINT}
    bundle = validated_bundle(package_doc=package_doc, rootfs_doc=rootfs_doc,
                              certificate=directory / "cert.gpg", expect=expect, digests=digests)
    return bundle, blobs


class FakeFetcher:
    def __init__(self, blobs):
        self.blobs = dict(blobs)
        self.urls = []

    def fetch(self, url, destination, size, sha256, deadline, *, rootfs_url):
        self.urls.append(url)
        data = self.blobs.get(url)
        if data is None:
            raise SdkRefusal("INPUT_TRANSPORT")
        with open(destination, "xb") as stream:
            stream.write(data)
        check_file(Path(destination), size, sha256)


class FakeEngine(CommandRunner):
    """Docker/gpgv/uname double driven by the exact argv the lease emits."""

    def __init__(self):
        self.tools = {"docker", "gpgv", "uname"}
        self.uname = b"Linux aarch64\n"
        self.server = b"linux/arm64\n"
        self.info = b"linux/aarch64\n"
        self.gpg_status = good_status()
        self.images, self.tags, self.containers, self.names = {}, {}, {}, {}
        self.calls = []
        self.install_output, self.install_code = install_tokens(), 0
        self.mutate = None
        self.worker = lambda role, argv: (0, b"out", b"err")
        self.client_exec = lambda user, argv: (0, b"", b"")
        self.preamble_ok = True
        self.fail_rm = set()
        self.executed = True
        self.counter = 0

    # CommandRunner seam --------------------------------------------------------
    def which(self, tool_name):
        return "/usr/bin/" + tool_name if tool_name in self.tools else None

    def run(self, argv, *, cwd=None, env=None):
        self.calls.append(list(argv))
        tool = argv[0]
        if tool == "uname":
            code, out, err = 0, self.uname, b""
        elif tool == "gpgv":
            code, out, err = 0, self.gpg_status, b""
        else:
            assert tool == "docker" and argv[1] == "--config" and argv[3:5] == ["--host", DOCKER_HOST]
            code, out, err = self.docker(argv[5:])
        return CommandReceipt(argv, code, out, err, tool_name=tool, tool_path="/usr/bin/" + tool,
                              executed=self.executed)

    # helpers -------------------------------------------------------------------
    def docker_calls(self, verb=None):
        rows = [c[5:] for c in self.calls if c[0] == "docker"]
        return [r for r in rows if verb is None or r[:len(verb)] == verb]

    def role_docs(self, role):
        return [d for d in self.containers.values() if d["Labels"].get(ROLE_LABEL) == role]

    def created(self, role):
        return [c for c in self.docker_calls(["create"])
                if f"--label" in c and f"{ROLE_LABEL}={role}" in c]

    def _new_id(self):
        self.counter += 1
        return sha(str(self.counter).encode())

    def _image(self, ref):
        return ref if ref in self.images else self.tags.get(ref)

    def _container(self, ref):
        return ref if ref in self.containers else self.names.get(ref)

    def docker(self, a):
        if a[0] == "version":
            return 0, self.server, b""
        if a[0] == "info":
            return 0, self.info, b""
        if a[:2] == ["image", "inspect"]:
            if a[2] == "--format":
                iid = self._image(a[4])
                return (0, f"{iid}|linux|arm64\n".encode(), b"") if iid else (1, b"", b"x")
            iid = self._image(a[2])
            return (0, json.dumps([{"Id": iid}]).encode(), b"") if iid else (1, b"[]\n", b"x")
        if a[:2] == ["container", "inspect"]:
            if a[2] == "--format":
                cid = self._container(a[4])
                return (0, json.dumps(self.containers[cid]).encode(), b"") if cid else (1, b"[]\n", b"x")
            cid = self._container(a[2])
            return (0, json.dumps([{"Id": cid}]).encode(), b"") if cid else (1, b"[]\n", b"x")
        if a[0] == "import":
            assert a[1:3] == ["--platform", "linux/arm64"]
            iid = "sha256:" + self._new_id()
            self.images[iid] = {"tags": {a[4]}, "env": [], "labels": {}}
            self.tags[a[4]] = iid
            return 0, (iid + "\n").encode(), b""
        if a[0] == "create":
            return self._create(a[1:])
        if a[0] == "start":
            return self._start(a[1:])
        if a[0] == "commit":
            doc = self.containers[a[1]]
            iid = "sha256:" + self._new_id()
            self.images[iid] = {"tags": {a[2]}, "env": list(doc["Env"]), "labels": dict(doc["Labels"])}
            self.tags[a[2]] = iid
            return 0, (iid + "\n").encode(), b""
        if a[:2] == ["container", "stop"]:
            assert a[2:4] == ["--time", "10"]
            doc = self.containers[self._container(a[4])]
            doc.update(Status="exited", Running=False, ExitCode=143)
            return 0, b"", b""
        if a[:2] == ["container", "rm"]:
            assert len(a) == 3
            doc = self.containers.get(a[2])
            if doc is None or doc["Running"] or doc["Labels"].get(ROLE_LABEL) in self.fail_rm:
                return 1, b"", b"refused"
            del self.containers[a[2]]
            del self.names[doc["Name"][1:]]
            return 0, b"", b""
        if a[:2] == ["image", "rm"]:
            assert a[2] == "--no-prune" and len(a) == 4
            iid = self.tags.pop(a[3])
            self.images[iid]["tags"].discard(a[3])
            if not self.images[iid]["tags"]:
                del self.images[iid]
            return 0, b"", b""
        if a[0] == "exec":
            return self._exec(a[1:])
        raise AssertionError(a)

    def _create(self, a):
        single = {"--name", "--platform", "--pull", "--network", "--ipc", "--hostname",
                  "--pids-limit", "--memory", "--memory-swap", "--cpus", "--log-driver", "--user",
                  "--workdir"}
        o = {"labels": {}, "env": [], "cap-add": [], "cap-drop": [], "mounts": [], "tmpfs": {},
             "security": []}
        readonly, i = False, 0
        while a[i].startswith("--"):
            key = a[i]
            if key == "--read-only":
                readonly, i = True, i + 1
                continue
            value, i = a[i + 1], i + 2
            if key in single:
                o[key[2:]] = value
            elif key == "--label":
                k, v = value.split("=", 1)
                o["labels"][k] = v
            elif key == "--env":
                o["env"].append(value)
            elif key in ("--cap-add", "--cap-drop"):
                o[key[2:]].append(value)
            elif key == "--security-opt":
                o["security"].append(value)
            elif key == "--mount":
                parts = [p.split("=", 1) if "=" in p else [p, True] for p in value.split(",")]
                o["mounts"].append(dict(parts))
            elif key == "--tmpfs":
                target, options = value.split(":", 1)
                o["tmpfs"][target] = options
            else:
                raise AssertionError(key)
        image_ref, cmd = a[i], a[i + 1:]
        iid = self._image(image_ref)
        if iid is None or o["name"] in self.names:
            return 1, b"", b"refused"
        env = {item.split("=", 1)[0]: item for item in self.images[iid]["env"]}
        env.update({item.split("=", 1)[0]: item for item in o["env"]})
        labels = {**self.images[iid]["labels"], **o["labels"]}
        cid = self._new_id()
        mounts = [{"Type": "bind", "Source": m["source"], "Destination": m["target"], "Mode": "",
                   "RW": not m.get("readonly", False), "Propagation": "rprivate"}
                  for m in o["mounts"]]
        host_mounts = [{"Type": "bind", "Source": m["source"], "Target": m["target"],
                        **({"ReadOnly": True} if m.get("readonly") else {})} for m in o["mounts"]]
        doc = {"Id": cid, "Name": "/" + o["name"], "Image": iid, "ConfigImage": image_ref,
               "User": o["user"], "Env": list(env.values()), "Labels": labels, "Cmd": list(cmd),
               "Entrypoint": None, "WorkingDir": o["workdir"], "Hostname": o["hostname"],
               "Mounts": mounts,
               "Host": {"Mounts": host_mounts, "NetworkMode": o["network"], "IpcMode": o["ipc"],
                        "PidMode": "", "UTSMode": "", "UsernsMode": "", "CgroupParent": "",
                        "VolumeDriver": "", "Privileged": False, "CapDrop": o["cap-drop"],
                        "CapAdd": o["cap-add"] or None, "SecurityOpt": o["security"],
                        "ReadonlyRootfs": readonly, "Tmpfs": o["tmpfs"] or None,
                        "Binds": None, "GroupAdd": None, "Devices": [], "PublishAllPorts": False,
                        "Init": None, "OomKillDisable": None, "AutoRemove": False,
                        "Memory": int(o["memory"]), "MemorySwap": int(o["memory-swap"]),
                        "NanoCpus": int(float(o["cpus"]) * 1e9), "PidsLimit": int(o["pids-limit"]),
                        "LogConfig": {"Type": o["log-driver"], "Config": {}},
                        "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0}},
               "Status": "created", "Running": False, "ExitCode": 0, "OOMKilled": False}
        if self.mutate is not None:
            self.mutate(labels.get(ROLE_LABEL), doc)
        self.containers[cid] = doc
        self.names[o["name"]] = cid
        return 0, (cid + "\n").encode(), b""

    def _start(self, a):
        if a[0] == "--attach":
            doc = self.containers[a[1]]
            role = doc["Labels"].get(ROLE_LABEL)
            if role == "installer":
                code, out, err = self.install_code, self.install_output, b""
            elif not self.preamble_ok:
                code, out, err = 213, b"", b""
            else:
                assert doc["Cmd"][:2] == ["/usr/bin/bash", "-c"] and doc["Cmd"][3] == "rs9-preamble"
                code, out, err = self.worker(role, doc["Cmd"][4:])
                err = PREAMBLE_OK + err
            doc.update(Status="exited", Running=False, ExitCode=code)
            return code, out, err
        doc = self.containers[a[0]]
        doc.update(Status="running", Running=True)
        return 0, (a[0] + "\n").encode(), b""

    def _exec(self, a):
        i, user = 0, None
        while a[i].startswith("-"):
            if a[i] == "-i":
                i += 1
                continue
            if a[i] == "--user":
                user = a[i + 1]
            i += 2
        doc = self.containers.get(a[i])
        if doc is None or not doc["Running"]:
            return 1, b"", b"not running"
        rest = a[i + 1:]
        if user != "0:0":
            assert rest[:2] == ["/usr/bin/bash", "-c"] and rest[3] == "rs9-preamble"
            if not self.preamble_ok:
                return 213, b"", b""
            code, out, err = self.client_exec(user, rest[4:])
            return code, out, PREAMBLE_OK + err
        return self.client_exec(user, rest)


class Harness:
    """Fresh physical temp root, synthetic pins, fake engine/fetcher and lease factory."""

    def __init__(self, test):
        if os.getuid() == 0:
            test.skipTest("lease refuses a root runner identity")
        self.root = Path(tempfile.mkdtemp(prefix="rs9arm")).resolve()
        test.addCleanup(shutil.rmtree, self.root, True)
        self.uid, self.gid = os.getuid(), os.stat(self.root).st_gid
        if self.gid == 0:
            test.skipTest("temporary directory group is 0")
        self.bundle, blobs = make_bundle(self.root / "pins")
        self.engine = FakeEngine()
        self.fetcher = FakeFetcher(blobs)
        self.inspected = []

    def seams(self, **overrides):
        values = dict(fetcher=self.fetcher,
                      inspect_rootfs=lambda path, pin: self.inspected.append(pin) or {"members": 1},
                      pins_loader=lambda: self.bundle,
                      runner_identity=lambda: (self.uid, self.gid), nonce=lambda: NONCE)
        values.update(overrides)
        return archarm_sdk._Seams(**values)

    def lease(self, *, context=None, uid=None, gid=None, work="work", host=None, **seams):
        return archarm_sdk._acquire(host=host or self.engine, workspace=self.root / work,
                                    context=dict(CONTEXT if context is None else context),
                                    uid=self.uid if uid is None else uid,
                                    gid=self.gid if gid is None else gid,
                                    seams=self.seams(**seams))

    def directory(self, name, mode=0o700):
        path = self.root / name
        path.mkdir(parents=True)
        path.chmod(mode)
        return path


class HarnessSanityTest(unittest.TestCase):
    def test_synthetic_bundle_is_never_qualified(self):
        harness = Harness(self)
        self.assertFalse(harness.bundle.qualified)
        self.assertEqual(harness.bundle.expect["packageCount"], len(ROOT_NAMES))


if __name__ == "__main__":
    unittest.main()
