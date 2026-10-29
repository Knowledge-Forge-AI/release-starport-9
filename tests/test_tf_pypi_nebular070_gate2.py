"""Connected Gate 2 fixtures: wheel/raw-release binding and native consumer fail-closed gates."""
import copy
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import signal
import stat
import subprocess
import sys
import tempfile
import tarfile
import unittest
from unittest.mock import patch
import zipfile

from rs9.tf_pypi_archive import AdmissionError, canonical, sha256
from rs9.tf_pypi_consumer import (
    _NEBULAR_TERMINATION_GRACE,
    _nebular_grace_deadline,
    _nebular_process_snapshot,
    _nebular_run,
    consume_nebular_candidate,
)
from rs9.tf_pypi_nebular_successor import (
    authenticate_gate1_capture,
    build_gate1_candidates,
    validate_gate1_receipt,
    write_gate1_receipt,
)
from rs9.tf_pypi_verify import read_wheel
from rs9.scratch import canonical as gate1_canonical
from rs9 import tf_pypi_hosted as hosted
from rs9.wheel import format_record
from tests.test_nebular070_gate1_roundtrip import _prepare_fixture


COMMIT = "c" * 40
TREE = "d" * 40
QUALIFY_COMMIT = "275f2378db2bed0691365e14b0c291095898e8c7"
QUALIFY_TREE = "d5fd6fa0ce41dff4005b40252dbd250468d48c6a"
PROFILE_SHA = "e" * 64
TARGETS = ("darwin-arm64", "linux-arm64-gnu", "linux-x64-gnu")
SYSTEMS = {
    "darwin-arm64": "aarch64-darwin",
    "linux-arm64-gnu": "aarch64-linux",
    "linux-x64-gnu": "x86_64-linux",
}
TAGS = {
    "darwin-arm64": "py3-none-macosx_13_0_arm64",
    "linux-arm64-gnu": "py3-none-linux_aarch64",
    "linux-x64-gnu": "py3-none-linux_x86_64",
}
LINUX_RUNTIME_POLICY = {
    "wheel_tag_policy": "generic-linux",
    "glibc_floor": "2.36",
    "glibcxx_floor": "3.4.30",
    "provider_baseline": "manylinux236-named-provenance-only",
    "manylinux_claim": False,
    "dynamic_closure": "pending",
}
RC_PLATFORMS = {
    "darwin-arm64": "darwin-arm64",
    "linux-arm64-gnu": "linux-arm64",
    "linux-x64-gnu": "linux-x64",
}
RC_TRIPLES = {
    "darwin-arm64": "aarch64-apple-darwin",
    "linux-arm64-gnu": "aarch64-unknown-linux-gnu",
    "linux-x64-gnu": "x86_64-unknown-linux-gnu",
}
RC_SCENARIOS = {
    "darwin-arm64": {"raw-archive": "A", "npm-package": "A"},
    "linux-arm64-gnu": {"raw-archive": "B", "npm-package": "B"},
    "linux-x64-gnu": {"raw-archive": "C", "npm-package": "C-signal"},
}
RC_STEPS = {
    "A": ("app-shell", "host-start", "host-status", "project-open", "brand-read", "theme-lab-compile", "app-theme-status", "app-theme-compile", "brand-system-view", "host-status-final"),
    "B": ("app-shell", "app-theme-status", "app-theme-compile", "theme-lab-compile", "brand-system-view", "host-start", "host-status", "project-open-upper", "brand-read-upper", "project-open-lower", "brand-read-lower", "host-status-final"),
    "C": ("app-shell", "host-start", "host-start-idempotent", "host-stop", "host-start-again", "host-status", "project-open-case", "derive-plan-cancel", "derive-plan-apply", "host-status-final"),
    "C-signal": ("app-shell", "host-start", "host-start-idempotent", "host-stop", "host-start-again", "host-status", "project-open-case", "derive-plan-cancel", "derive-plan-apply", "host-status-final"),
}


def _current_checkout_identity():
    """Bind the production-path negative to the checkout under test."""
    root = Path(__file__).resolve().parents[1]
    return tuple(
        subprocess.check_output(["git", "-C", str(root), "rev-parse", ref], text=True).strip()
        for ref in ("HEAD", "HEAD^{tree}")
    )


def _zip_bytes(entries: dict[str, tuple[bytes, int]]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in sorted(entries):
            info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = ((entries[name][1] | stat.S_IFREG) << 16)
            archive.writestr(info, entries[name][0], compresslevel=9)
    return output.getvalue()


def _payload_tar(entries: dict[str, tuple[bytes | None, int]]) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for name in sorted(entries):
            data, mode = entries[name]
            info = tarfile.TarInfo(name)
            info.type = tarfile.DIRTYPE if data is None else tarfile.REGTYPE
            info.mode = mode
            info.size = 0 if data is None else len(data)
            archive.addfile(info, io.BytesIO(data) if data is not None else None)
    return output.getvalue()


def _rewrite_wheel(wheel_path: Path, mutate) -> bytes:
    """Rewrite a controlled fixture wheel while retaining valid wheel modes."""
    with zipfile.ZipFile(wheel_path, "r") as archive:
        entries = {name: archive.read(name) for name in archive.namelist()}
    mutate(entries)
    record_name = next(name for name in entries if name.endswith("/RECORD"))
    records = []
    for name in sorted(entries):
        if name == record_name:
            records.append((name, "", ""))
        else:
            digest = base64.urlsafe_b64encode(hashlib.sha256(entries[name]).digest()).decode().rstrip("=")
            records.append((name, "sha256=" + digest, str(len(entries[name]))))
    text = io.StringIO(newline="")
    import csv
    csv.writer(text, lineterminator="\n").writerows(records)
    entries[record_name] = text.getvalue().encode()
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in sorted(entries):
            info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = ((0o644 | stat.S_IFREG) << 16)
            archive.writestr(info, entries[name], compresslevel=9)
    wheel_path.write_bytes(output.getvalue())
    return output.getvalue()


class NebularGate2Fixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.capture = self.root / "capture"
        self.capture.mkdir()
        self.dist = self.root / "dist"
        self.dist.mkdir()
        self.candidate, self.raw_release, self.expected, self.wheels = self._make_fixture()
        self.candidate_receipt_sha = sha256(canonical(self.candidate))

    def _make_fixture(self):
        source = {
            "status": "candidate-input",
            "binding": "explicit-reviewed-source-input",
            "commit": COMMIT,
            "tree": TREE,
            "verified": False,
        }
        identity_base = {
            "repository": "fixture/nebular-fusion",
            "tag": "v0.7.0",
            "commit": "a" * 40,
            "tree": "b" * 40,
        }
        readme_bytes = b"# Nebular Fusion 0.7.0\nPython 3 and pip fixture.\n"
        legal = {
            "LICENSE": b"AGPL-3.0-or-later fixture license\n",
            "NOTICE": b"Fixture notice\n",
            "COMMERCIAL-LICENSE.md": b"Optional companion fixture\n",
        }
        release_record = {"source_identity": identity_base}
        record_without_digest = canonical(release_record)
        identity = {**identity_base, "release_record_sha256": sha256(record_without_digest)}
        (self.capture / "release.json").write_bytes(record_without_digest)
        release_record_digest = sha256((self.capture / "release.json").read_bytes())
        self.assertEqual(release_record_digest, identity["release_record_sha256"])
        (self.capture / "README.md").write_bytes(readme_bytes)
        for name, data in legal.items():
            (self.capture / name).write_bytes(data)

        wheel_records = []
        wheels = {}
        raw_targets = {}
        for target in TARGETS:
            native_scenario = RC_SCENARIOS[target]["raw-archive"]
            sidecar_bytes = (
                "#!/bin/sh\n"
                "set -eu\n"
                f"test \"${{1:-}}\" = --nebular-release-smoke={native_scenario}\n"
                f"printf 'NEBULAR_NATIVE_SMOKE:0.7.0:{target}:{native_scenario}\\n'\n"
            ).encode()
            launcher_bytes = (
                "#!/bin/sh\n"
                f"printf 'NEBULAR_LAUNCHER:0.7.0:{target}\\n'\n"
            ).encode()
            gui_bytes = f"authenticated-gui:{target}:distinct\\n".encode()
            archive_root = (
                "Theme Forge Nebular Fusion.app"
                if target == "darwin-arm64" else "theme-forge-nebular-fusion"
            )
            role_relative = (
                {
                    "gui": "Contents/MacOS/theme-forge-nebular-fusion",
                    "launcher": "Contents/Resources/bin/tfnf",
                    "sidecar": "Contents/MacOS/tfsb-studio-service",
                }
                if target == "darwin-arm64" else
                {
                    "gui": "bin/theme-forge-nebular-fusion",
                    "launcher": "bin/tfnf",
                    "sidecar": "bin/tfsb-studio-service",
                }
            )
            role_paths = {role: f"{archive_root}/{relative}"
                          for role, relative in role_relative.items()}
            smoke_gui_path = (role_paths["gui"] if target == "darwin-arm64"
                              else role_relative["gui"])
            directory_paths = {
                archive_root,
                *(f"{archive_root}/{part}" for part in (
                    ("Contents", "Contents/MacOS", "Contents/Resources", "Contents/Resources/bin")
                    if target == "darwin-arm64" else ("bin",)
                )),
            }
            payload_entries = {
                role_paths["launcher"]: (launcher_bytes, 0o755),
                role_paths["gui"]: (gui_bytes, 0o755),
                role_paths["sidecar"]: (sidecar_bytes, 0o755),
            }
            payload_entries.update({path: (None, 0o755) for path in directory_paths})
            payload_bytes = _payload_tar(payload_entries)
            payload_name = f"nebular-{target}.tgz"
            payload_path = self.capture / payload_name
            payload_path.write_bytes(payload_bytes)
            members = [
                ({"path": path, "type": "directory", "mode": mode}
                 if data is None else
                 {"path": path, "type": "file", "mode": mode,
                  "size": len(data), "sha256": sha256(data)})
                for path, (data, mode) in sorted(payload_entries.items())
            ]
            member_by_path = {member["path"]: member for member in members}
            manifest = {
                "schema": "rs9.nebular070-payload-manifest.v1",
                "root": archive_root,
                "native_sidecars": {target: {"path": payload_name, "sha256": sha256(payload_bytes)}},
                "members": members,
                "commands": {
                    "tfnf": dict(member_by_path[role_paths["gui"]]),
                    "launcher:tfnf": dict(member_by_path[role_paths["launcher"]]),
                },
            }
            manifest["manifest_sha256"] = sha256(gate1_canonical(manifest["members"]))
            manifest_bytes = gate1_canonical(manifest["members"])
            embedded_manifest_bytes = gate1_canonical(manifest)
            manifest_path = self.capture / f"manifest-{target}.json"
            manifest_path.write_bytes(manifest_bytes)
            provenance = {
                "candidate_rs9_source": source,
                "source_identity": identity,
                "release_record_sha256": identity["release_record_sha256"],
            }
            provenance_bytes = canonical(provenance)
            provenance_path = self.capture / f"PROVENANCE-{target}.json"
            provenance_path.write_bytes(provenance_bytes)
            direct_lineage = {"provenance_sha256": sha256(provenance_bytes)}
            darwin_floor = None
            if target == "darwin-arm64":
                darwin_floor = {
                    "schema": "rs9.darwin-floor-evidence.v1alpha1",
                    "status": "cross-checked",
                    "required_floor": {"major": 13, "minor": 0},
                    "info_plist": {"major": 13, "minor": 0},
                    "macho": [{"major": 13, "minor": 0, "patch": 0,
                               "path": role_paths["gui"], "role": "macos-executable"}],
                    "scripts": [{"path": payload_name, "role": "script"}],
                }
            payload_digest = sha256(payload_bytes)
            launcher_sha = sha256(launcher_bytes)
            sidecar_sha = sha256(sidecar_bytes)
            executable_sha = sha256(gui_bytes)
            provider_observation = sha256(f"fixture-observation:{target}".encode())
            provider_detail = {
                "observationIdentity": provider_observation,
                "observedProviderRows": [{
                    "soname": "libc.so.6", "classification": "external-floor",
                    "requestedPath": "/fixture/libc.so.6", "terminalPath": "/fixture/libc.so.6",
                    "aliasChain": [], "terminalFull9": ["fixture"], "bytes": 1,
                    "sha256": "f" * 64, "elfMachine": "fixture", "elfClass": "ELF64",
                    "versionDefinitions": ["GLIBC_2.36"], "readelfEvidenceSha256": "a" * 64,
                }],
                "subjectResolutionRows": [{
                    "subjectRelativePath": "bin/theme-forge-nebular-fusion",
                    "neededSoname": "libc.so.6", "resolvedPath": "/fixture/libc.so.6",
                    "providerObservationIdentity": provider_observation,
                }],
                "toolEvidence": {
                    "readelfRole": "actual-provider-terminal-readelf",
                    "resolutionToolRole": "actual-consumer-ldd",
                    "cleanupFacts": {"allCommandsBounded": True, "noSurvivingProcessFamily": True},
                },
            }
            checks = [
                {"id": "executable-header", "ok": True, "detail": "fixture ELF64/Mach-O header"},
                {"id": "launcher", "ok": True, "detail": launcher_sha},
                {"id": "sidecar-runtime", "ok": True, "detail": f"node 22.23.3 {sidecar_sha}"},
            ]
            if target.startswith("linux"):
                checks.extend([
                    {"id": "mode:gui", "ok": True, "detail": "0755"},
                    {"id": "mode:sidecar", "ok": True, "detail": "0755"},
                    {"id": "mode:launcher", "ok": True, "detail": "0755"},
                    {"id": "glibc:gui", "ok": True, "detail": "2.36"},
                    {"id": "glibc:sidecar", "ok": True, "detail": "2.36"},
                    {"id": "glibc-floor", "ok": True, "detail": "2.36"},
                    {"id": "linkage", "ok": True, "detail": "fixture ldd closure"},
                    {"id": "private-runtime-closure", "ok": True, "detail": provider_detail},
                ])
            else:
                checks.extend([
                    {"id": "legal-notices", "ok": True, "detail": "LICENSE, NOTICE"},
                    {"id": "codesign", "ok": True, "detail": "valid · Signature=fixture"},
                ])
            qualification = {
                "schema": "nebular.native-rc-qualification-v1",
                "platform": RC_PLATFORMS[target], "status": "pass",
                "executableSha256": executable_sha, "glibcMinimum": "2.36" if target.startswith("linux") else None,
                "nativePayload": {"identity": sha256(f"fixture-payload:{target}".encode()), "files": 1},
                "materialDigest": sha256(f"fixture-material:{target}".encode()), "checks": checks,
            }
            qualification_bytes = canonical(qualification)
            qualification_path = self.capture / f"qualification-{target}.json"
            qualification_path.write_bytes(qualification_bytes)
            smoke = {}
            for smoke_source, smoke_scenario in RC_SCENARIOS[target].items():
                smoke_receipt = {
                    "schema": "nebular.release-smoke-receipt-v1", "scenario": smoke_scenario,
                    "status": "pass", "target": RC_TRIPLES[target],
                    "awaitingSignal": smoke_scenario == "C-signal",
                    "executable": {"sha256": executable_sha},
                    "driver": {"steps": [{"id": step, "ok": True, "via": "fixture", "ms": 1}
                                             for step in RC_STEPS[smoke_scenario]]},
                }
                receipt_bytes = canonical(smoke_receipt)
                receipt_path = self.capture / f"smoke-receipt-{target}-{smoke_source}.json"
                receipt_path.write_bytes(receipt_bytes)
                receipt_digest = sha256(receipt_bytes)
                smoke_run = {
                    "schema": "nebular.native-rc-smoke-run-v1", "label": f"{target}-{smoke_source}",
                    "platform": RC_PLATFORMS[target], "scenario": smoke_scenario,
                    "source": smoke_source, "status": "pass", "problems": [],
                    "executable": {
                        "path": smoke_gui_path,
                        "sha256": executable_sha,
                        "size": len(gui_bytes),
                    },
                    "checks": {"orphans": [], "persistentUserState": {"locations": 3, "changed": []},
                               "scratchHomeWrites": 1},
                    "finalization": {"schema": "nebular.native-rc-finalization-v1", "status": "complete",
                                      "exitObserved": True, "applicationReceiptObservation": "present-at-read",
                                      "applicationReceiptCopy": "written"},
                    "receipt": {"sha256": receipt_digest, "status": "pass",
                                 "steps": [{"id": step, "ok": True, "via": "fixture", "ms": 1}
                                           for step in RC_STEPS[smoke_scenario]]},
                }
                run_bytes = canonical(smoke_run)
                run_path = self.capture / f"smoke-run-{target}-{smoke_source}.json"
                run_path.write_bytes(run_bytes)
                smoke[smoke_source] = {
                    "run": {"path": run_path.name, "size": len(run_bytes), "sha256": sha256(run_bytes)},
                    "receipt": {"path": receipt_path.name, "size": len(receipt_bytes), "sha256": receipt_digest},
                }
            provider_check_id = "private-runtime-closure" if target.startswith("linux") else "sidecar-runtime"
            provider_detail_for_digest = provider_detail if target.startswith("linux") else f"node 22.23.3 {sidecar_sha}"
            provider_evidence = {
                "qualification_sha256": sha256(qualification_bytes), "qualification_check_id": provider_check_id,
                "qualification_detail_sha256": sha256(canonical(provider_detail_for_digest)),
                "smoke_receipts": {name: smoke[name]["receipt"]["sha256"] for name in sorted(smoke)},
            }
            raw_targets[target] = {
                "payload": {"path": payload_name, "name": payload_name,
                            "size": len(payload_bytes), "sha256": payload_digest},
                "manifest": {"path": manifest_path.name, "size": len(manifest_bytes),
                             "sha256": sha256(manifest_bytes)},
                "provenance": {"path": provenance_path.name, "size": len(provenance_bytes),
                               "sha256": sha256(provenance_bytes)},
                "native_consumer": {
                    "command": "tfnf",
                    "protocol": "nebular.native-rc-smoke", "platform": RC_PLATFORMS[target],
                    "scenario": native_scenario, "argv": [f"--nebular-release-smoke={native_scenario}"],
                    "timeout_seconds": 20,
                    "state_paths": ["state/nebular"],
                    "user_state_protocol": {"schema": "nebular.native-rc-persistent-user-state-v1",
                                             "method": "native-rc-smoke.persistentStateLocations+snapshotLocations",
                                             "scope": "real-user-state"},
                    "qualification": {"path": qualification_path.name, "size": len(qualification_bytes),
                                       "sha256": sha256(qualification_bytes)},
                    "smoke": smoke,
                    "loader": {"status": "verified", "path": role_paths["launcher"], "sha256": launcher_sha,
                               "qualification_check_id": "launcher"},
                    "provider_closure": {
                        "status": "verified", "target": target, "mode": "controlled-fixture",
                        "emulated": False, "qualification_check_id": provider_check_id,
                        "evidence_sha256": sha256(canonical(provider_evidence)),
                    },
                },
                "darwin_floor_evidence": darwin_floor,
            }

            distribution = "theme_forge_nebular_fusion"
            info = f"theme_forge_nebular_fusion-0.7.0.dist-info"
            launcher = (
                "import hashlib, json, os, sys, tarfile\n"
                "from pathlib import Path\n"
                "PACKAGE_ROOT = Path(__file__).resolve().parent\n"
                f"PAYLOAD = PACKAGE_ROOT / 'payload' / {payload_name!r}\n"
                f"ARCHIVE_ROOT = {archive_root!r}\n"
                f"GUI_RELATIVE = {role_relative['gui']!r}\n"
                "def _materialize():\n"
                "    manifest = json.loads((PACKAGE_ROOT / 'payload' / 'manifest.json').read_bytes())\n"
                "    manifest_sha = manifest.get('manifest_sha256')\n"
                "    if not isinstance(manifest_sha, str):\n"
                "        raise RuntimeError('embedded manifest digest missing')\n"
                "    cache_home = Path(os.environ.get('XDG_CACHE_HOME', str(Path.home() / '.cache')))\n"
                "    cache_root = cache_home / 'rs9' / 'theme-forge-nebular-fusion'\n"
                "    payload_root = cache_root / 'entries' / manifest_sha / 'payload'\n"
                "    root = payload_root / ARCHIVE_ROOT\n"
                "    gui = root / GUI_RELATIVE\n"
                "    if not gui.is_file():\n"
                "        members = {entry['path']: entry for entry in manifest['members']}\n"
                "        payload_root.mkdir(parents=True, exist_ok=True)\n"
                "        with tarfile.open(PAYLOAD, 'r:gz') as archive:\n"
                "            for item in archive:\n"
                "                expected = members.get(item.name)\n"
                "                if expected is None:\n"
                "                    raise RuntimeError('unexpected embedded payload member')\n"
                "                destination = payload_root / item.name\n"
                "                if item.isdir():\n"
                "                    destination.mkdir(parents=True, exist_ok=True)\n"
                "                    destination.chmod(expected['mode'])\n"
                "                    continue\n"
                "                if not item.isfile():\n"
                "                    raise RuntimeError('non-file embedded payload member')\n"
                "                destination.parent.mkdir(parents=True, exist_ok=True)\n"
                "                stream = archive.extractfile(item)\n"
                "                data = stream.read() if stream is not None else b''\n"
                "                if (len(data) != expected['size']\n"
                "                        or hashlib.sha256(data).hexdigest() != expected['sha256']):\n"
                "                    raise RuntimeError('embedded payload member digest mismatch')\n"
                "                destination.write_bytes(data)\n"
                "                destination.chmod(expected['mode'])\n"
                "    expected_gui = next(entry for entry in manifest['members']\n"
                "                        if entry.get('path') == ARCHIVE_ROOT + '/' + GUI_RELATIVE)\n"
                "    if (not gui.is_file()\n"
                "            or hashlib.sha256(gui.read_bytes()).hexdigest() != expected_gui['sha256']):\n"
                "        raise RuntimeError('materialized GUI digest mismatch')\n"
                "    return gui\n"
                "def main_tfnf():\n"
                "    args = sys.argv[1:]\n"
                "    if args == ['--version']:\n"
                "        print('theme-forge-nebular-fusion 0.7.0')\n"
                "        return\n"
                "    if args == ['--path']:\n"
                "        print(_materialize())\n"
                "        return\n"
                "    if args and args[0].startswith('--nebular-release-smoke='):\n"
                "        _materialize()\n"
                "        print('NEBULAR_NATIVE_SMOKE:0.7.0:' + args[0].split('=', 1)[1])\n"
                "        return\n"
                "    print('NEBULAR_LAUNCHER:0.7.0')\n"
            ).encode()
            metadata = (
                "Metadata-Version: 2.4\n"
                "Name: theme-forge-nebular-fusion\n"
                "Version: 0.7.0\n"
                "License-Expression: AGPL-3.0-or-later\n"
                "License-File: LICENSE\nLicense-File: NOTICE\nLicense-File: COMMERCIAL-LICENSE.md\n"
                "Requires-Python: >=3.10\n\n"
            ).encode() + readme_bytes
            wheel_info = (
                "Wheel-Version: 1.0\nGenerator: gate2-fixture\nRoot-Is-Purelib: false\n"
                f"Tag: {TAGS[target]}\n"
            ).encode()
            wheel_provenance = {
                "rs9_source": source,
                **provenance,
                "forward_lineage": direct_lineage,
                "payload_archive_sha256": payload_digest,
                "manifest_sha256": sha256(manifest_bytes),
                "license_expression": "AGPL-3.0-or-later",
                "wheel_tag": TAGS[target],
                "linux_runtime_policy": LINUX_RUNTIME_POLICY,
                "darwin_floor_evidence": darwin_floor,
            }
            entries = {
                f"{distribution}/__init__.py": (b"__version__ = '0.7.0'\n", 0o644),
                f"{distribution}/launcher.py": (launcher, 0o644),
                f"{distribution}/payload/{payload_name}": (payload_bytes, 0o644),
                f"{distribution}/payload/manifest.json": (embedded_manifest_bytes, 0o644),
                f"{distribution}/_rs9/provenance.json": (canonical(wheel_provenance), 0o644),
                f"{info}/METADATA": (metadata, 0o644),
                f"{info}/WHEEL": (wheel_info, 0o644),
                f"{info}/entry_points.txt": (b"[console_scripts]\ntfnf = theme_forge_nebular_fusion.launcher:main_tfnf\n", 0o644),
                f"{info}/licenses/LICENSE": (legal["LICENSE"], 0o644),
                f"{info}/licenses/NOTICE": (legal["NOTICE"], 0o644),
                f"{info}/licenses/COMMERCIAL-LICENSE.md": (legal["COMMERCIAL-LICENSE.md"], 0o644),
            }
            record_map = {name: data for name, (data, _mode) in entries.items()}
            entries[f"{info}/RECORD"] = (format_record(record_map, info), 0o644)
            wheel_bytes = _zip_bytes(entries)
            filename = f"theme_forge_nebular_fusion-0.7.0-{TAGS[target]}.whl"
            wheel_path = self.dist / filename
            wheel_path.write_bytes(wheel_bytes)
            wheel = {"target": target, "filename": filename, "size": len(wheel_bytes),
                     "sha256": sha256(wheel_bytes), "tag": TAGS[target], "version": "0.7.0"}
            wheel_records.append(wheel)
            wheels[target] = wheel_path

        legal_rows = {
            name: {"path": name, "size": len(data), "sha256": sha256(data)}
            for name, data in legal.items()
        }
        candidate = {
            "schema": "rs9.nebular-successor-candidate.v2alpha1",
            "application_version": "0.7.0",
            "distribution_version": "0.7.0",
            "source_identity": identity,
            "candidate_rs9_source": source,
            "direct_lineage": direct_lineage,
            "qualification_rs9_source": {"status": "not-run", "reason": "gate1-only"},
            "profile": {
                "license_expression": "AGPL-3.0-or-later",
                "darwin_floor": {"major": 13, "minor": 0},
                "linux_runtime_policy": LINUX_RUNTIME_POLICY,
            },
            "linux_runtime_policy": LINUX_RUNTIME_POLICY,
            "darwin_floor_evidence": next(
                raw_targets[target]["darwin_floor_evidence"]
                for target in TARGETS if target == "darwin-arm64"
            ),
            "readme": {"path": "README.md", "sha256": sha256(readme_bytes)},
            "legal_files": legal_rows,
            "license": {"expression": "AGPL-3.0-or-later", "files": legal_rows},
            "flags": {"candidate_only": True, "builder_can_publish": False, "can_publish": False,
                      "publication_admitted": False, "manylinux_proven": False},
            "rows": [],
        }
        for target in TARGETS:
            row = {
                "system": SYSTEMS[target], "target_triple": target,
                "wheel": {key: value for key, value in wheel_records[TARGETS.index(target)].items()
                           if key != "target"},
                "source_identity": identity, "candidate_rs9_source": source,
                "payload_archive_name": raw_targets[target]["payload"]["name"],
                "payload_archive_sha256": raw_targets[target]["payload"]["sha256"],
                "manifest_sha256": raw_targets[target]["manifest"]["sha256"],
                "forward_lineage": direct_lineage,
                "candidate_profile": candidate["profile"],
                "source_legal_profile": {
                    "expression": "AGPL-3.0-or-later",
                    "required_files": ["LICENSE", "NOTICE"],
                    "optional_files": ["COMMERCIAL-LICENSE.md"],
                    "observed_files": ["COMMERCIAL-LICENSE.md", "LICENSE", "NOTICE"],
                },
                "linux_runtime_policy": LINUX_RUNTIME_POLICY,
                "darwin_floor_evidence": raw_targets[target]["darwin_floor_evidence"],
                "launcher_path": raw_targets[target]["native_consumer"]["loader"]["path"],
                "gui_path": (
                    ("Theme Forge Nebular Fusion.app/Contents/MacOS/theme-forge-nebular-fusion"
                     if target == "darwin-arm64" else
                     "theme-forge-nebular-fusion/bin/theme-forge-nebular-fusion")
                ),
            }
            candidate["rows"].append(row)
        expected_rows = sorted(wheel_records, key=lambda row: row["target"])
        expected = {
            "schema": hosted.NEBULAR070_EXPECTED_ARTIFACT_SCHEMA,
            "candidate_rs9_source": source,
            "wheels": expected_rows,
            "record_sha256": sha256(canonical(expected_rows)),
        }
        raw = {
            "root": str(self.capture),
            "record": {"path": "release.json", "size": len((self.capture / "release.json").read_bytes()),
                        "sha256": sha256((self.capture / "release.json").read_bytes())},
            "readme": {"path": "README.md", "size": len(readme_bytes), "sha256": sha256(readme_bytes)},
            "legal_files": legal_rows,
            "payload": raw_targets[TARGETS[0]]["payload"],
            "manifest": raw_targets[TARGETS[0]]["manifest"],
            "provenance": raw_targets[TARGETS[0]]["provenance"],
            "native_consumer": {target: raw_targets[target]["native_consumer"] for target in TARGETS},
        }
        # The raw payload/manifest/provenance are target-specific; each target
        # test receives its target descriptors without changing the candidate.
        raw["per_target"] = raw_targets
        return candidate, raw, expected, wheels

    def raw_for(self, target):
        raw = copy.deepcopy(self.raw_release)
        for key in ("payload", "manifest", "provenance"):
            raw[key] = raw["per_target"][target][key]
        return raw

    def sandbox_probe(self, _env, _prefix):
        return {"network_disabled": True, "method": "controlled-fixture-sandbox",
                "proof_sha256": sha256(b"controlled-fixture-sandbox")}

    def real_user_state_snapshot(self, phase, target):
        return {
            "schema": "nebular.native-rc-persistent-user-state-v1",
            "method": "native-rc-smoke.persistentStateLocations+snapshotLocations",
            "scope": "real-user-state", "target": target, "phase": phase,
            "locations": 21, "snapshot_sha256": sha256(b"controlled-real-user-state"), "changed": [],
        }

    def identity(self, target):
        return {"source": "controlled-fixture", "system": SYSTEMS[target],
                "machine": "fixture", "target": target}

    def consume_direct(self, candidate, target, *, raw=None, label="direct-consumer"):
        """Call the consumer boundary without hosted expected-artifact short-circuiting."""
        return consume_nebular_candidate(
            candidate,
            self.wheels[target],
            self.raw_for(target) if raw is None else raw,
            self.root / label,
            target=target,
            sandbox_probe=self.sandbox_probe,
            host_identity=self.identity(target),
            fixture_only=True,
            real_user_state_snapshot=self.real_user_state_snapshot,
        )

    def test_connected_fixture_runs_post_path_native_probe_for_three_targets(self):
        receipts = self.root / "receipts"
        for target in TARGETS:
            result = hosted.qualify_nebular070(
                self.candidate, self.wheels[target], self.raw_for(target),
                self.root / f"work-{target}", expected_artifacts=self.expected,
                expected_commit=QUALIFY_COMMIT, expected_tree=QUALIFY_TREE,
                profile_sha256=PROFILE_SHA, candidate_receipt_sha256=self.candidate_receipt_sha,
                target=target, run_id="700", run_attempt="1", sandbox_probe=self.sandbox_probe,
                host_identity=self.identity(target), fixture_only=True,
                real_user_state_snapshot=self.real_user_state_snapshot,
            )
            self.assertEqual(result["status"], "fixture-native-consumer-passed")
            self.assertTrue(result["fixture_only"])
            self.assertFalse(result["native_qualified"])
            self.assertEqual(result["candidate_rs9_source"]["commit"], COMMIT)
            self.assertNotEqual(result["candidate_rs9_source"], result["qualification_rs9_source"])
            self.assertEqual(result["consumer"]["probes"]["native"]["exit_code"], 0)
            self.assertEqual(result["consumer"]["process_observer"]["orphan_count"], 0)
            self.assertTrue(result["consumer"]["user_state"]["unchanged"])
            self.assertFalse(result["publication_admitted"])
            target_dir = receipts / target
            target_dir.mkdir(parents=True)
            (target_dir / "result.json").write_bytes(canonical(result))
        with self.assertRaises(AdmissionError) as caught:
            hosted.admit_nebular070_matrix(
                self.candidate, self.expected, receipts,
                expected_commit=QUALIFY_COMMIT, expected_tree=QUALIFY_TREE,
                profile_sha256=PROFILE_SHA, candidate_receipt_sha256=self.candidate_receipt_sha,
                run_id="700", run_attempt="1",
            )
        self.assertEqual(caught.exception.code, "TF_PYPI_NEBULAR_MATRIX_RECEIPT")

    @unittest.skipUnless(
        platform.system() == "Darwin" and platform.machine().lower() in {"arm64", "aarch64"},
        "requires the current Darwin ARM64 consumer target",
    )
    def test_real_consumer_requires_authenticated_smoke_support_before_native(self):
        target = "darwin-arm64"
        raw = self.raw_for(target)
        raw["native_consumer"][target]["provider_closure"]["mode"] = "host-observed"
        with self.assertRaises(AdmissionError) as caught:
            consume_nebular_candidate(
                self.candidate,
                self.wheels[target],
                raw,
                self.root / "work-real-without-smoke-support",
                target=target,
                sandbox_probe=self.sandbox_probe,
                real_user_state_snapshot=self.real_user_state_snapshot,
            )
        self.assertEqual(caught.exception.code, "TF_PYPI_NEBULAR_SMOKE_CLOSURE")

    def test_actual_consumer_path_and_digest_mismatches_fail_closed(self):
        target = "darwin-arm64"
        wheel_path = self.wheels[target]
        baseline_wheel = wheel_path.read_bytes()
        baseline_row = copy.deepcopy(self._candidate_row_for(target)["wheel"])
        cases = (
            ("wrong-path", b"        print('/wrong-nebular-gui')\n"),
            ("wrong-digest", b"        path = _materialize()\n        path.write_bytes(b'forged-gui')\n        print(path)\n"),
        )
        for label, replacement in cases:
            wheel_path.write_bytes(baseline_wheel)
            self._candidate_row_for(target)["wheel"] = copy.deepcopy(baseline_row)

            def mutate(entries, replacement=replacement):
                name = next(item for item in entries if item.endswith("/launcher.py"))
                source = entries[name]
                needle = b"        print(_materialize())\n"
                self.assertIn(needle, source)
                entries[name] = source.replace(needle, replacement, 1)

            self._rewrite_target_wheel(target, mutate)
            with self.assertRaises(AdmissionError) as caught:
                self.consume_direct(copy.deepcopy(self.candidate), target, label=f"consumer-{label}")
            self.assertEqual(caught.exception.code, "TF_PYPI_NEBULAR_COMMAND_CONTRACT")

    def test_actual_consumer_rejects_payload_bytes_role_swaps_and_nonfile_members(self):
        target = "darwin-arm64"

        changed = copy.deepcopy(self.candidate)
        raw = self.raw_for(target)
        payload_descriptor = raw["payload"]
        payload_path = self.capture / payload_descriptor["path"]
        original_payload = payload_path.read_bytes()
        rewritten = io.BytesIO()
        with tarfile.open(fileobj=io.BytesIO(original_payload), mode="r:gz") as source_archive, tarfile.open(
            fileobj=rewritten, mode="w:gz"
        ) as target_archive:
            for member in source_archive:
                item = copy.copy(member)
                data = source_archive.extractfile(member).read() if member.isfile() else b""
                if member.name.endswith("/Contents/MacOS/theme-forge-nebular-fusion"):
                    data += b"\nRAW-PAYLOAD-TAMPER\n"
                item.size = len(data) if item.isfile() else 0
                target_archive.addfile(item, io.BytesIO(data) if item.isfile() else None)
        payload_bytes = rewritten.getvalue()
        payload_path.write_bytes(payload_bytes)
        raw["payload"]["size"] = len(payload_bytes)
        raw["payload"]["sha256"] = sha256(payload_bytes)
        next(row for row in changed["rows"] if row["system"] == SYSTEMS[target])["payload_archive_sha256"] = sha256(payload_bytes)
        with self.assertRaises(AdmissionError) as caught:
            self.consume_direct(changed, target, raw=raw, label="consumer-payload-bytes")
        self.assertEqual(caught.exception.code, "TF_PYPI_NEBULAR_NATIVE_CONTRACT")
        payload_path.write_bytes(original_payload)

        changed = copy.deepcopy(self.candidate)
        raw = self.raw_for(target)
        qualification = raw["native_consumer"][target]["qualification"]
        qualification_path = self.capture / qualification["path"]
        qualification_before = qualification_path.read_bytes()
        qualification_value = json.loads(qualification_before)
        # The maintained qualification's executable digest is the GUI digest;
        # replace it with the authenticated launcher digest to exercise the
        # consumer's connected native-evidence join.
        members = json.loads((self.capture / self.raw_for(target)["manifest"]["path"]).read_bytes())
        launcher_member_sha = next(item["sha256"] for item in members if item["path"].endswith("/Contents/Resources/bin/tfnf"))
        qualification_value["executableSha256"] = launcher_member_sha
        qualification_updated = canonical(qualification_value)
        qualification_path.write_bytes(qualification_updated)
        raw["native_consumer"][target]["qualification"]["size"] = len(qualification_updated)
        raw["native_consumer"][target]["qualification"]["sha256"] = sha256(qualification_updated)
        with self.assertRaises(AdmissionError) as caught:
            self.consume_direct(changed, target, raw=raw, label="consumer-role-digest-swap")
        self.assertEqual(caught.exception.code, "TF_PYPI_NEBULAR_NATIVE_EVIDENCE")
        qualification_path.write_bytes(qualification_before)

        changed = copy.deepcopy(self.candidate)
        raw = self.raw_for(target)
        qualification = raw["native_consumer"][target]["qualification"]
        qualification_path = self.capture / qualification["path"]
        qualification_before = qualification_path.read_bytes()
        qualification_value = json.loads(qualification_before)
        launcher_member_sha = next(
            item["sha256"] for item in members
            if item["path"].endswith("/Contents/Resources/bin/tfnf")
        )
        next(row for row in qualification_value["checks"] if row["id"] == "sidecar-runtime")["detail"] = (
            "node 22.23.3 " + launcher_member_sha
        )
        qualification_updated = canonical(qualification_value)
        qualification_path.write_bytes(qualification_updated)
        raw["native_consumer"][target]["qualification"]["size"] = len(qualification_updated)
        raw["native_consumer"][target]["qualification"]["sha256"] = sha256(qualification_updated)
        with self.assertRaises(AdmissionError) as caught:
            self.consume_direct(changed, target, raw=raw, label="consumer-sidecar-check-swap")
        self.assertEqual(caught.exception.code, "TF_PYPI_NEBULAR_NATIVE_EVIDENCE")
        qualification_path.write_bytes(qualification_before)

        changed = copy.deepcopy(self.candidate)
        raw = self.raw_for(target)
        manifest = raw["manifest"]
        manifest_path = self.capture / manifest["path"]
        manifest_before = manifest_path.read_bytes()
        members = json.loads(manifest_before)
        member = next(item for item in members if item["path"].endswith("/Contents/MacOS/tfsb-studio-service"))
        member["type"] = "directory"
        manifest_updated = gate1_canonical(members)
        manifest_path.write_bytes(manifest_updated)
        raw["manifest"]["size"] = len(manifest_updated)
        raw["manifest"]["sha256"] = sha256(manifest_updated)
        next(row for row in changed["rows"] if row["system"] == SYSTEMS[target])["manifest_sha256"] = sha256(manifest_updated)
        with self.assertRaises(AdmissionError) as caught:
            self.consume_direct(changed, target, raw=raw, label="consumer-nonfile-role")
        self.assertEqual(caught.exception.code, "TF_PYPI_NEBULAR_NATIVE_CONTRACT")
        manifest_path.write_bytes(manifest_before)

    def test_actual_consumer_profile_floor_tag_policy_and_license_gates(self):
        target = "darwin-arm64"
        row_index = next(index for index, row in enumerate(self.candidate["rows"])
                         if row["system"] == SYSTEMS[target])
        cases = (
            ("darwin-floor", lambda candidate: candidate["rows"][row_index]["darwin_floor_evidence"]["required_floor"].update(major=12),
             "TF_PYPI_NEBULAR_FLOOR_BINDING"),
            ("wheel-tag", lambda candidate: candidate["rows"][row_index]["wheel"].update(tag="py3-none-any"),
             "TF_PYPI_NEBULAR_WHEEL_BINDING"),
            ("linux-policy", lambda candidate: candidate["profile"]["linux_runtime_policy"].update(glibc_floor="2.35"),
             "TF_PYPI_NEBULAR_LICENSE"),
            ("license-only", lambda candidate: candidate["license"].update(expression="AGPL-3.0-only"),
             "TF_PYPI_NEBULAR_LICENSE"),
            ("license-commercial", lambda candidate: candidate["license"].update(expression="AGPL-3.0-or-later OR Commercial"),
             "TF_PYPI_NEBULAR_LICENSE"),
        )
        for label, mutate, expected_code in cases:
            candidate = copy.deepcopy(self.candidate)
            mutate(candidate)
            with self.assertRaises(AdmissionError) as caught:
                self.consume_direct(candidate, target, label=f"consumer-{label}")
            self.assertEqual(caught.exception.code, expected_code)

    def test_cross_binding_provider_and_production_identity_fail_closed(self):
        changed = copy.deepcopy(self.candidate)
        changed["rows"][0]["candidate_rs9_source"] = {
            **changed["rows"][0]["candidate_rs9_source"], "tree": "f" * 40,
        }
        changed_expected = copy.deepcopy(self.expected)
        changed_expected["candidate_rs9_source"] = changed["candidate_rs9_source"]
        with self.assertRaises(AdmissionError) as caught:
            hosted.qualify_nebular070(
                changed, self.wheels["darwin-arm64"], self.raw_for("darwin-arm64"),
                self.root / "cross-source", expected_artifacts=changed_expected,
                expected_commit=QUALIFY_COMMIT, expected_tree=QUALIFY_TREE,
                profile_sha256=PROFILE_SHA, candidate_receipt_sha256=self.candidate_receipt_sha,
                target="darwin-arm64", sandbox_probe=self.sandbox_probe,
                host_identity=self.identity("darwin-arm64"), fixture_only=True,
                real_user_state_snapshot=self.real_user_state_snapshot,
            )
        self.assertEqual(caught.exception.code, "TF_PYPI_NEBULAR_CANDIDATE_ROWS")

        changed_raw = self.raw_for("darwin-arm64")
        changed_raw["native_consumer"]["darwin-arm64"]["provider_closure"]["status"] = "pending"
        with self.assertRaises(AdmissionError) as caught:
            hosted.qualify_nebular070(
                self.candidate, self.wheels["darwin-arm64"], changed_raw,
                self.root / "cross-provider", expected_artifacts=self.expected,
                expected_commit=QUALIFY_COMMIT, expected_tree=QUALIFY_TREE,
                profile_sha256=PROFILE_SHA, candidate_receipt_sha256=self.candidate_receipt_sha,
                target="darwin-arm64", sandbox_probe=self.sandbox_probe,
                host_identity=self.identity("darwin-arm64"), fixture_only=True,
            )
        self.assertEqual(caught.exception.code, "TF_PYPI_NEBULAR_PROVIDER_CLOSURE")

        wrong_target = "linux-x64-gnu" if platform.system() == "Darwin" else "darwin-arm64"
        production_commit, production_tree = _current_checkout_identity()
        with self.assertRaises(AdmissionError) as caught:
            hosted.qualify_nebular070(
                self.candidate, self.wheels[wrong_target], self.raw_for(wrong_target),
                self.root / "production-identity", expected_artifacts=self.expected,
                expected_commit=production_commit, expected_tree=production_tree,
                profile_sha256=PROFILE_SHA, candidate_receipt_sha256=self.candidate_receipt_sha,
                target=wrong_target, sandbox_probe=self.sandbox_probe, fixture_only=False,
            )
        self.assertEqual(caught.exception.code, "TF_PYPI_NEBULAR_HOST_IDENTITY")

        changed_state = self.raw_for("darwin-arm64")

        def changed_real_state(phase, target):
            observed = self.real_user_state_snapshot(phase, target)
            if phase == "after":
                observed["changed"] = ["/fixture-home/Library/Application Support/ai.knowledgeforge.themeforge.nebularfusion"]
            return observed

        with self.assertRaises(AdmissionError) as caught:
            hosted.qualify_nebular070(
                self.candidate, self.wheels["darwin-arm64"], changed_state,
                self.root / "changed-user-state", expected_artifacts=self.expected,
                expected_commit=QUALIFY_COMMIT, expected_tree=QUALIFY_TREE,
                profile_sha256=PROFILE_SHA, candidate_receipt_sha256=self.candidate_receipt_sha,
                target="darwin-arm64", sandbox_probe=self.sandbox_probe,
                host_identity=self.identity("darwin-arm64"), fixture_only=True,
                real_user_state_snapshot=changed_real_state,
            )
        self.assertEqual(caught.exception.code, "TF_PYPI_NEBULAR_USER_STATE_GUARD")

        changed_evidence = self.raw_for("darwin-arm64")
        changed_evidence["native_consumer"]["darwin-arm64"]["provider_closure"]["evidence_sha256"] = "0" * 64
        with self.assertRaises(AdmissionError) as caught:
            hosted.qualify_nebular070(
                self.candidate, self.wheels["darwin-arm64"], changed_evidence,
                self.root / "changed-evidence", expected_artifacts=self.expected,
                expected_commit=QUALIFY_COMMIT, expected_tree=QUALIFY_TREE,
                profile_sha256=PROFILE_SHA, candidate_receipt_sha256=self.candidate_receipt_sha,
                target="darwin-arm64", sandbox_probe=self.sandbox_probe,
                host_identity=self.identity("darwin-arm64"), fixture_only=True,
                real_user_state_snapshot=self.real_user_state_snapshot,
            )
        self.assertEqual(caught.exception.code, "TF_PYPI_NEBULAR_PROVIDER_CLOSURE")

    def test_streaming_probe_bounds_flood_timeout_and_process_group_cleanup(self):
        flood_work = self.root / "flood-work"
        flood_work.mkdir()
        flood = _nebular_run(
            [sys.executable, "-c", "import sys,time;sys.stdout.write('x'*5000000);sys.stdout.flush();time.sleep(30)"],
            {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}, flood_work, (), 2,
        )
        self.assertTrue(flood["bounded"])
        self.assertTrue(flood["output_limit_exceeded"])
        self.assertTrue(flood["forced_cleanup"])
        self.assertTrue(flood["cleanup_known"])
        self.assertFalse(flood["output_complete"])
        self.assertEqual(_nebular_process_snapshot(flood_work)["orphan_count"], 0)

        timeout_work = self.root / "timeout-work"
        timeout_work.mkdir()
        marker = str(timeout_work / "orphan-marker")
        timeout = _nebular_run(
            [sys.executable, "-c", "import subprocess,sys,time;subprocess.Popen([sys.executable,'-c','import time,sys;time.sleep(30)',sys.argv[1]]);time.sleep(30)", marker],
            {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}, timeout_work, (), 1,
        )
        self.assertTrue(timeout["bounded"])
        self.assertTrue(timeout["timed_out"])
        self.assertTrue(timeout["forced_cleanup"])
        self.assertTrue(timeout["cleanup_known"])
        self.assertEqual(_nebular_process_snapshot(timeout_work)["orphan_count"], 0)

    def test_termination_grace_deadline_is_not_postponed_by_repeated_checks(self):
        initial_now = 10.0
        first_deadline = _nebular_grace_deadline(None, initial_now)
        repeated_now = initial_now + 0.25
        legacy_repeated_deadline = repeated_now + _NEBULAR_TERMINATION_GRACE

        # The former assignment on every request would postpone escalation;
        # the bounded state transition retains the first deadline instead.
        self.assertGreater(legacy_repeated_deadline, first_deadline)
        self.assertEqual(
            _nebular_grace_deadline(first_deadline, repeated_now),
            first_deadline,
        )

    def test_term_ignoring_leader_reaches_sigkill_and_exact_group_is_absent(self):
        work = self.root / "term-ignoring-leader-work"
        work.mkdir()
        captured_child = None
        identity = None

        def capture_runner(command, **kwargs):
            nonlocal captured_child
            captured_child = subprocess.Popen(command, **kwargs)
            return captured_child

        try:
            result = _nebular_run(
                [
                    sys.executable,
                    "-c",
                    (
                        "import os,signal,time;"
                        "signal.signal(signal.SIGTERM, signal.SIG_IGN);"
                        "print(f'{os.getpid()}:{os.getpgrp()}', flush=True);"
                        "time.sleep(30)"
                    ),
                ],
                {"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
                work,
                (),
                1,
                runner=capture_runner,
            )
            fields = result["stdout_token"].strip().split(":")
            self.assertEqual(len(fields), 2)
            identity = tuple(int(field) for field in fields)
            leader_pid, group_id = identity
            self.assertIsNotNone(captured_child)
            self.assertEqual(leader_pid, captured_child.pid)
            self.assertEqual(leader_pid, group_id)
            self.assertTrue(result["timed_out"])
            self.assertTrue(result["forced_cleanup"])
            self.assertEqual(result["signal"], signal.SIGKILL)
            self.assertTrue(result["cleanup_known"])
            self.assertLess(result["duration_ms"], 5000)
            with self.assertRaises(ProcessLookupError):
                os.killpg(group_id, 0)
        finally:
            if captured_child is not None and captured_child.poll() is None:
                try:
                    owned_group = os.getpgid(captured_child.pid)
                except ProcessLookupError:
                    owned_group = None
                if owned_group == captured_child.pid:
                    try:
                        os.killpg(owned_group, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    try:
                        captured_child.wait(timeout=_NEBULAR_TERMINATION_GRACE)
                    except subprocess.TimeoutExpired:
                        if captured_child.poll() is None:
                            try:
                                if os.getpgid(captured_child.pid) == captured_child.pid:
                                    os.killpg(captured_child.pid, signal.SIGKILL)
                            except ProcessLookupError:
                                pass
                            if captured_child.poll() is None:
                                captured_child.wait(timeout=_NEBULAR_TERMINATION_GRACE)

    def test_leader_exit_waits_for_group_observation_and_fails_closed_on_retained_group(self):
        """Leader EOF must not bypass the owned-group cleanup observation."""
        clean_work = self.root / "leader-exit-cleanup-work"
        clean_work.mkdir()
        clean_signals = []

        def clean_signal(_child, signal_number):
            clean_signals.append(signal_number)
            return True

        def clean_group_exists(_pid):
            # The group remains present until the existing TERM then KILL
            # sequence has completed.  This makes the regression independent
            # of scheduler timing while exercising the real loop deadlines.
            return len(clean_signals) < 2

        with patch("rs9.tf_pypi_consumer._nebular_group_exists", side_effect=clean_group_exists), \
                patch("rs9.tf_pypi_consumer._nebular_signal_group", side_effect=clean_signal):
            clean = _nebular_run(
                [sys.executable, "-c", "pass"],
                {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}, clean_work, (), 1,
            )
        self.assertTrue(clean["cleanup_known"])
        self.assertGreaterEqual(len(clean_signals), 2)

        retained_work = self.root / "leader-exit-retained-group-work"
        retained_work.mkdir()
        retained_signals = []

        def retained_signal(_child, signal_number):
            retained_signals.append(signal_number)
            return True

        with patch("rs9.tf_pypi_consumer._nebular_group_exists", return_value=True), \
                patch("rs9.tf_pypi_consumer._nebular_signal_group", side_effect=retained_signal):
            retained = _nebular_run(
                [sys.executable, "-c", "pass"],
                {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}, retained_work, (), 1,
            )
        self.assertFalse(retained["cleanup_known"])
        self.assertGreaterEqual(len(retained_signals), 2)

        unknown_work = self.root / "leader-exit-unknown-group-work"
        unknown_work.mkdir()
        unknown_signals = []

        def unknown_signal(_child, signal_number):
            unknown_signals.append(signal_number)
            return True

        with patch("rs9.tf_pypi_consumer.os.killpg", side_effect=PermissionError), \
                patch("rs9.tf_pypi_consumer._nebular_signal_group", side_effect=unknown_signal):
            unknown = _nebular_run(
                [sys.executable, "-c", "pass"],
                {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}, unknown_work, (), 1,
            )
        self.assertFalse(unknown["cleanup_known"])
        self.assertGreaterEqual(len(unknown_signals), 2)

    def test_nebular_wheel_member_cap_is_scoped_and_total_cap_remains_64m(self):
        over_legacy_member = b"x" * (8 * 1024 * 1024 + 1)
        wheel = _zip_bytes({"package/payload.bin": (over_legacy_member, 0o644)})
        with self.assertRaises(AdmissionError):
            read_wheel(wheel)
        accepted = read_wheel(
            wheel,
            max_total_bytes=64 * 1024 * 1024,
            max_member_bytes=64 * 1024 * 1024,
        )
        self.assertEqual(accepted["package/payload.bin"][0], over_legacy_member)

        over_nebular_cap = b"x" * (64 * 1024 * 1024 + 1)
        oversized = _zip_bytes({"package/payload.bin": (over_nebular_cap, 0o644)})
        with self.assertRaises(AdmissionError):
            read_wheel(
                oversized,
                max_total_bytes=64 * 1024 * 1024,
                max_member_bytes=64 * 1024 * 1024,
            )

    def _candidate_row_for(self, target):
        system = SYSTEMS[target]
        return next(row for row in self.candidate["rows"] if row["system"] == system)

    def _expected_with_current_wheel(self, target):
        expected = copy.deepcopy(self.expected)
        wheel = self._candidate_row_for(target)["wheel"]
        expected_row = next(row for row in expected["wheels"] if row["target"] == target)
        expected_row.update({key: wheel[key] for key in ("filename", "size", "sha256", "tag", "version")})
        expected["record_sha256"] = sha256(canonical(sorted(expected["wheels"], key=lambda row: row["target"])))
        return expected

    def _rewrite_target_wheel(self, target, mutate_entries):
        wheel_path = self.wheels[target]
        data = _rewrite_wheel(wheel_path, mutate_entries)
        row = self._candidate_row_for(target)
        row["wheel"]["size"] = len(data)
        row["wheel"]["sha256"] = sha256(data)
        return self._expected_with_current_wheel(target)

    def _embedded_manifest_name(self, entries):
        return next(name for name in entries if name.endswith("/payload/manifest.json"))

    def _provenance_name(self, entries):
        return next(name for name in entries if name.endswith("/_rs9/provenance.json"))

    def _sync_embedded_manifest(self, entries, members, manifest_sha):
        manifest_name = self._embedded_manifest_name(entries)
        embedded = json.loads(entries[manifest_name])
        embedded["members"] = members
        embedded["manifest_sha256"] = manifest_sha
        entries[manifest_name] = gate1_canonical(embedded)
        provenance_name = self._provenance_name(entries)
        provenance = json.loads(entries[provenance_name])
        provenance["manifest_sha256"] = manifest_sha
        entries[provenance_name] = canonical(provenance)

    def test_gate1_lineage_and_gui_digest_tampering_fail_closed(self):
        target = "darwin-arm64"
        changed = copy.deepcopy(self.candidate)
        changed["direct_lineage"]["provenance_sha256"] = "0" * 64
        with self.assertRaises(AdmissionError) as caught:
            hosted.qualify_nebular070(
                changed, self.wheels[target], self.raw_for(target),
                self.root / "tampered-lineage", expected_artifacts=self.expected,
                expected_commit=QUALIFY_COMMIT, expected_tree=QUALIFY_TREE,
                profile_sha256=PROFILE_SHA, candidate_receipt_sha256=self.candidate_receipt_sha,
                target=target, sandbox_probe=self.sandbox_probe,
                host_identity=self.identity(target), fixture_only=True,
                real_user_state_snapshot=self.real_user_state_snapshot,
            )
        self.assertEqual(caught.exception.code, "TF_PYPI_NEBULAR_PROVENANCE_BINDING")

        changed = copy.deepcopy(self.candidate)
        changed["rows"][0]["gui_path"] = changed["rows"][0]["launcher_path"]
        with self.assertRaises(AdmissionError) as caught:
            hosted.qualify_nebular070(
                changed, self.wheels[target], self.raw_for(target),
                self.root / "tampered-gui", expected_artifacts=self.expected,
                expected_commit=QUALIFY_COMMIT, expected_tree=QUALIFY_TREE,
                profile_sha256=PROFILE_SHA, candidate_receipt_sha256=self.candidate_receipt_sha,
                target=target, sandbox_probe=self.sandbox_probe,
                host_identity=self.identity(target), fixture_only=True,
                real_user_state_snapshot=self.real_user_state_snapshot,
            )
        self.assertEqual(caught.exception.code, "TF_PYPI_NEBULAR_NATIVE_CONTRACT")

    def test_actual_embedded_manifest_and_native_type_tampering_fail_closed(self):
        target = "darwin-arm64"

        def tamper_embedded(entries):
            name = self._embedded_manifest_name(entries)
            embedded = json.loads(entries[name])
            embedded["members"][0]["mode"] = 0o644
            entries[name] = gate1_canonical(embedded)

        expected = self._rewrite_target_wheel(target, tamper_embedded)
        with self.assertRaises(AdmissionError) as caught:
            hosted.qualify_nebular070(
                self.candidate, self.wheels[target], self.raw_for(target), self.root / "tampered-embedded",
                expected_artifacts=expected, expected_commit=QUALIFY_COMMIT, expected_tree=QUALIFY_TREE,
                profile_sha256=PROFILE_SHA, candidate_receipt_sha256=self.candidate_receipt_sha, target=target,
                sandbox_probe=self.sandbox_probe, host_identity=self.identity(target), fixture_only=True,
                real_user_state_snapshot=self.real_user_state_snapshot,
            )
        self.assertEqual(caught.exception.code, "TF_PYPI_NEBULAR_WHEEL_BINDING")

        for role in ("launcher", "gui"):
            fixture = self.raw_for(target)
            manifest_path = self.capture / fixture["manifest"]["path"]
            members = json.loads(manifest_path.read_bytes())
            role_suffix = {
                "launcher": "/Contents/Resources/bin/tfnf",
                "gui": "/Contents/MacOS/theme-forge-nebular-fusion",
            }[role]
            member = next(item for item in members if item["path"].endswith(role_suffix))
            member["mode"] = 0o644
            manifest_sha = sha256(gate1_canonical(members))
            manifest_path.write_bytes(gate1_canonical(members))
            fixture["manifest"]["size"] = manifest_path.stat().st_size
            fixture["manifest"]["sha256"] = manifest_sha
            self._candidate_row_for(target)["manifest_sha256"] = manifest_sha

            def sync(entries, members=members, manifest_sha=manifest_sha):
                self._sync_embedded_manifest(entries, members, manifest_sha)

            expected = self._rewrite_target_wheel(target, sync)
            with self.assertRaises(AdmissionError) as caught:
                hosted.qualify_nebular070(
                    self.candidate, self.wheels[target], fixture, self.root / f"tampered-{role}",
                    expected_artifacts=expected, expected_commit=QUALIFY_COMMIT, expected_tree=QUALIFY_TREE,
                    profile_sha256=PROFILE_SHA, candidate_receipt_sha256=self.candidate_receipt_sha, target=target,
                    sandbox_probe=self.sandbox_probe, host_identity=self.identity(target), fixture_only=True,
                    real_user_state_snapshot=self.real_user_state_snapshot,
                )
            self.assertEqual(caught.exception.code, "TF_PYPI_NEBULAR_NATIVE_CONTRACT")
            for item in members:
                if item["path"].endswith(role_suffix):
                    item["mode"] = 0o755
            restored_sha = sha256(gate1_canonical(members))
            manifest_path.write_bytes(gate1_canonical(members))
            fixture["manifest"]["size"] = manifest_path.stat().st_size
            fixture["manifest"]["sha256"] = restored_sha
            self._candidate_row_for(target)["manifest_sha256"] = restored_sha
            self._rewrite_target_wheel(
                target,
                lambda entries, members=members, manifest_sha=restored_sha:
                    self._sync_embedded_manifest(entries, members, manifest_sha),
            )

    def test_profile_tag_linux_policy_and_license_tampering_fail_closed(self):
        cases = [
            ("darwin-floor", lambda candidate: candidate["profile"]["darwin_floor"].update(major=12), "TF_PYPI_NEBULAR_EXPECTED_ARTIFACTS"),
            ("wheel-tag", lambda candidate: candidate["rows"][0]["wheel"].update(tag="py3-none-any"), "TF_PYPI_NEBULAR_EXPECTED_ARTIFACTS"),
            ("linux-policy", lambda candidate: candidate["profile"]["linux_runtime_policy"].update(glibc_floor="2.35"), "TF_PYPI_NEBULAR_EXPECTED_ARTIFACTS"),
            ("license-only", lambda candidate: candidate["license"].update(expression="AGPL-3.0-only"), "TF_PYPI_NEBULAR_EXPECTED_ARTIFACTS"),
            ("license-commercial", lambda candidate: candidate["license"].update(expression="AGPL-3.0-or-later OR Commercial"), "TF_PYPI_NEBULAR_EXPECTED_ARTIFACTS"),
        ]
        for label, mutate, expected_code in cases:
            candidate = copy.deepcopy(self.candidate)
            mutate(candidate)
            with self.assertRaises(AdmissionError) as caught:
                hosted.qualify_nebular070(
                    candidate, self.wheels["darwin-arm64"], self.raw_for("darwin-arm64"),
                    self.root / f"tampered-{label}", expected_artifacts=self.expected,
                    expected_commit=QUALIFY_COMMIT, expected_tree=QUALIFY_TREE,
                    profile_sha256=PROFILE_SHA, candidate_receipt_sha256=self.candidate_receipt_sha,
                    target="darwin-arm64", sandbox_probe=self.sandbox_probe,
                    host_identity=self.identity("darwin-arm64"), fixture_only=True,
                    real_user_state_snapshot=self.real_user_state_snapshot,
                )
            self.assertEqual(caught.exception.code, expected_code)


class NebularGate1ToGate2Fixture(unittest.TestCase):
    """Connect the maintained Gate 1 receipt to the controlled Gate 2 consumer."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(
            prefix="rs9-nebular070-gate2-gate1-handoff-",
            dir=str(Path(__file__).resolve().parents[1]),
        )
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.repository, self.evidence, _intent, self.binding = _prepare_fixture(self.root / "gate1")
        self._reseed_native_payloads(_intent)
        expectations_path = self.repository / "operators/tf-pypi/nebular-0.7.0/expectations.json"
        expectations = json.loads(expectations_path.read_bytes())
        for project in expectations.get("projects", []):
            for asset in project.get("assets", []):
                path = self.evidence / "assets" / asset["name"]
                if path.is_file():
                    data = path.read_bytes()
                    asset["size"] = len(data)
                    asset["sha256"] = sha256(data)
        expectations_path.write_bytes(canonical(expectations))
        self.binding["expected"]["expectations_sha256"] = sha256(expectations_path.read_bytes())
        self.authenticated = authenticate_gate1_capture(
            self.repository,
            self.evidence,
            release_binding=self.binding,
            approved_bootstrap_sha256=self.binding["expected"]["bootstrap_sha256"],
        )
        self.output = self.root / "gate1-candidates"
        self.candidate = build_gate1_candidates(
            self.authenticated,
            self.output,
            rs9_source_commit="c" * 40,
            rs9_source_tree="d" * 40,
            deterministic_timestamp=(2026, 10, 1, 0, 0, 0),
        )
        validate_gate1_receipt(self.candidate, self.authenticated, output_dir=self.output)
        self.receipt_path = self.root / "gate1-receipt.json"
        write_gate1_receipt(
            self.receipt_path,
            self.candidate,
            authenticated=self.authenticated,
            output_dir=self.output,
        )
        self.candidate_receipt_sha = sha256(canonical(self.candidate))
        self.handoffs = {
            target: self._make_handoff_fixture(target)
            for target in ("darwin-arm64", "linux-x64-gnu")
        }
        self.expected, self.raw_release, self.wheel = self.handoffs["darwin-arm64"]

    def _reseed_native_payloads(self, intent):
        """Make the Gate 1 payloads match the maintained three-role contract.

        The historical Gate 1 fixture intentionally used one Darwin Mach-O
        byte string for GUI and sidecar and omitted Linux's sidecar.  Gate 2
        must consume the actual maintained member paths with independent
        authenticated digests, so update only this temporary evidence copy.
        """
        assets_dir = self.evidence / "assets"
        changed = {}
        for asset in intent["assets"]:
            target = asset.get("id")
            if target not in {"darwin-arm64", "linux-arm64", "linux-x64"}:
                continue
            name = asset["name"]
            source = (assets_dir / name).read_bytes()
            root = ("Theme Forge Nebular Fusion.app"
                    if target == "darwin-arm64" else "theme-forge-nebular-fusion")
            gui_suffix = ("/Contents/MacOS/theme-forge-nebular-fusion"
                          if target == "darwin-arm64" else "/bin/theme-forge-nebular-fusion")
            launcher_suffix = ("/Contents/Resources/bin/tfnf"
                               if target == "darwin-arm64" else "/bin/tfnf")
            sidecar_suffix = ("/Contents/MacOS/tfsb-studio-service"
                              if target == "darwin-arm64" else "/bin/tfsb-studio-service")
            output = io.BytesIO()
            found_sidecar = False
            with tarfile.open(fileobj=io.BytesIO(source), mode="r:gz") as source_archive, tarfile.open(
                fileobj=output, mode="w:gz"
            ) as target_archive:
                for member in source_archive:
                    item = copy.copy(member)
                    data = source_archive.extractfile(member).read() if member.isfile() else b""
                    if member.name.endswith(gui_suffix):
                        data = data + b"\nGATE2-GUI-DISTINCT\n"
                    elif member.name.endswith(launcher_suffix):
                        data = data + b"# GATE2-LAUNCHER-DISTINCT\n"
                    elif member.name.endswith(sidecar_suffix):
                        data = data + b"\nGATE2-SIDECAR-DISTINCT\n"
                        found_sidecar = True
                    item.size = len(data) if item.isfile() else 0
                    target_archive.addfile(item, io.BytesIO(data) if item.isfile() else None)
                if not found_sidecar:
                    sidecar_path = root + sidecar_suffix
                    data = b"#!/bin/sh\nprintf 'GATE2-SIDECAR-DISTINCT\\n'\n"
                    item = tarfile.TarInfo(sidecar_path)
                    item.mode = 0o755
                    item.type = tarfile.REGTYPE
                    item.size = len(data)
                    target_archive.addfile(item, io.BytesIO(data))
            rewritten = output.getvalue()
            path = assets_dir / name
            path.write_bytes(rewritten)
            changed[name] = rewritten

        # Rebuild the authenticated checksum asset and synchronize the API
        # release metadata that Gate 1 validates before reading payloads.
        sums = b"".join(
            f"{sha256(path.read_bytes())}  {path.name}\n".encode()
            for path in sorted(assets_dir.iterdir(), key=lambda item: item.name)
            if path.is_file() and path.name != "SHA256SUMS"
        )
        (assets_dir / "SHA256SUMS").write_bytes(sums)
        release_path = self.evidence / "api" / "release.json"
        release = json.loads(release_path.read_bytes())
        for asset in release.get("assets", []):
            path = assets_dir / asset["name"]
            if path.is_file():
                data = path.read_bytes()
                asset["size"] = len(data)
                asset["digest"] = "sha256:" + sha256(data)
        release_path.write_bytes(canonical(release))

    def _write_raw(self, relative: str, data: bytes) -> dict[str, object]:
        target = self.raw_root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        return {"path": relative, "size": len(data), "sha256": sha256(data)}

    def _make_handoff_fixture(self, target):
        system = SYSTEMS[target]
        row = next(item for item in self.candidate["rows"] if item["system"] == system)
        self.raw_root = self.root / f"raw-release-{target}"
        self.raw_root.mkdir()

        record_bytes = gate1_canonical(self.authenticated.capture.record)
        record_descriptor = self._write_raw("release-record.json", record_bytes)
        readme_path = self.candidate["readme"]["path"]
        readme_bytes = (Path(__file__).resolve().parents[1] / readme_path).read_bytes()
        readme_descriptor = self._write_raw(readme_path, readme_bytes)
        legal_descriptors = {
            name: self._write_raw(name, data)
            for name, data in self.authenticated.capture.source.items()
            if name in self.candidate["legal_files"]
        }
        provenance_bytes = self.authenticated.capture.evidence_bytes["PROVENANCE.json"]
        provenance_descriptor = self._write_raw("PROVENANCE.json", provenance_bytes)

        payload_path = self.authenticated.capture.archives[row["selected_asset_id"]]
        payload_bytes = payload_path.read_bytes()
        payload_descriptor = self._write_raw(row["payload_archive_name"], payload_bytes)
        manifest = self.authenticated.capture.manifests[row["selected_asset_id"]]
        manifest_bytes = gate1_canonical(manifest["members"])
        manifest_descriptor = self._write_raw(f"manifest-{target}.json", manifest_bytes)
        loader = manifest["commands"]["launcher:tfnf"]
        gui = manifest["commands"]["tfnf"]
        sidecar_relative = (
            "Theme Forge Nebular Fusion.app/Contents/MacOS/tfsb-studio-service"
            if target == "darwin-arm64" else "theme-forge-nebular-fusion/bin/tfsb-studio-service"
        )
        sidecar = next(member for member in manifest["members"] if member["path"] == sidecar_relative)
        executable_sha = gui["sha256"]
        loader_sha = loader["sha256"]
        sidecar_sha = sidecar["sha256"]
        runtime_gui_path = (
            "Theme Forge Nebular Fusion.app/Contents/MacOS/theme-forge-nebular-fusion"
            if target == "darwin-arm64" else "bin/theme-forge-nebular-fusion"
        )
        provider_check_id = "private-runtime-closure" if target.startswith("linux") else "sidecar-runtime"
        if target.startswith("linux"):
            provider_detail = {
                "observationIdentity": sha256(f"handoff-observation:{target}".encode()),
                "observedProviderRows": [{
                    "soname": "libc.so.6", "classification": "external-floor",
                    "requestedPath": "/fixture/libc.so.6", "terminalPath": "/fixture/libc.so.6",
                    "aliasChain": [], "terminalFull9": ["fixture"], "bytes": 1,
                    "sha256": "f" * 64, "elfMachine": "fixture", "elfClass": "ELF64",
                    "versionDefinitions": ["GLIBC_2.36"], "readelfEvidenceSha256": "a" * 64,
                }],
                "subjectResolutionRows": [{
                    "subjectRelativePath": runtime_gui_path,
                    "neededSoname": "libc.so.6", "resolvedPath": "/fixture/libc.so.6",
                    "providerObservationIdentity": sha256(f"handoff-observation:{target}".encode()),
                }],
                "toolEvidence": {
                    "readelfRole": "actual-provider-terminal-readelf",
                    "resolutionToolRole": "actual-consumer-ldd",
                    "cleanupFacts": {"allCommandsBounded": True, "noSurvivingProcessFamily": True},
                },
            }
        else:
            provider_detail = "node 22.23.3 " + sidecar_sha
        checks = [
            {"id": "executable-header", "ok": True, "detail": "controlled executable header"},
            {"id": "launcher", "ok": True, "detail": loader_sha},
            {"id": "sidecar-runtime", "ok": True,
             "detail": provider_detail if target == "darwin-arm64" else "node 22.23.3 " + sidecar_sha},
        ]
        if target.startswith("linux"):
            checks.extend([
                {"id": "mode:gui", "ok": True, "detail": "0755"},
                {"id": "mode:sidecar", "ok": True, "detail": "0755"},
                {"id": "mode:launcher", "ok": True, "detail": "0755"},
                {"id": "glibc:gui", "ok": True, "detail": "2.36"},
                {"id": "glibc:sidecar", "ok": True, "detail": "2.36"},
                {"id": "glibc-floor", "ok": True, "detail": "2.36"},
                {"id": "linkage", "ok": True, "detail": "controlled ldd closure"},
                {"id": "private-runtime-closure", "ok": True, "detail": provider_detail},
            ])
        else:
            checks.extend([
                {"id": "legal-notices", "ok": True, "detail": "LICENSE, NOTICE"},
                {"id": "codesign", "ok": True, "detail": "valid controlled fixture signature"},
            ])
        qualification = {
            "schema": "nebular.native-rc-qualification-v1",
            "platform": RC_PLATFORMS[target], "status": "pass",
            "executableSha256": executable_sha,
            "glibcMinimum": "2.36" if target.startswith("linux") else None,
            "nativePayload": {"identity": sha256(payload_bytes), "files": len(manifest["members"])},
            "materialDigest": sha256(f"controlled-gate2-material:{target}".encode()),
            "checks": checks,
        }
        qualification_bytes = canonical(qualification)
        qualification_descriptor = self._write_raw(f"qualification-{target}.json", qualification_bytes)

        smoke = {}
        provider_receipts = {}
        for source_name, scenario in RC_SCENARIOS[target].items():
            smoke_receipt = {
                "schema": "nebular.release-smoke-receipt-v1", "scenario": scenario,
                "status": "pass", "target": RC_TRIPLES[target],
                "awaitingSignal": scenario == "C-signal", "executable": {"sha256": executable_sha},
                "driver": {"steps": [{"id": step, "ok": True, "via": "controlled-fixture", "ms": 1}
                                      for step in RC_STEPS[scenario]]},
            }
            receipt_bytes = canonical(smoke_receipt)
            receipt_descriptor = self._write_raw(f"smoke-receipt-{target}-{source_name}.json", receipt_bytes)
            provider_receipts[source_name] = receipt_descriptor["sha256"]
            smoke_run = {
                "schema": "nebular.native-rc-smoke-run-v1", "label": f"{target}-{source_name}",
                "platform": RC_PLATFORMS[target], "scenario": scenario, "source": source_name,
                "status": "pass", "problems": [],
                "executable": {"path": runtime_gui_path, "sha256": executable_sha, "size": gui["size"]},
                "checks": {"orphans": [], "persistentUserState": {"locations": 3, "changed": []},
                           "scratchHomeWrites": 1},
                "finalization": {"schema": "nebular.native-rc-finalization-v1", "status": "complete",
                                  "exitObserved": True, "applicationReceiptObservation": "present-at-read",
                                  "applicationReceiptCopy": "written"},
                "receipt": {"sha256": receipt_descriptor["sha256"], "status": "pass",
                             "steps": smoke_receipt["driver"]["steps"]},
            }
            run_bytes = canonical(smoke_run)
            run_descriptor = self._write_raw(f"smoke-run-{target}-{source_name}.json", run_bytes)
            smoke[source_name] = {"run": run_descriptor, "receipt": receipt_descriptor}

        provider_evidence = {
            "qualification_sha256": qualification_descriptor["sha256"],
            "qualification_check_id": provider_check_id,
            "qualification_detail_sha256": sha256(canonical(provider_detail)),
            "smoke_receipts": provider_receipts,
        }
        provider = {
            "status": "verified", "target": target, "mode": "controlled-fixture",
            "emulated": False, "qualification_check_id": provider_check_id,
            "evidence_sha256": sha256(canonical(provider_evidence)),
        }
        native = {
            "command": "tfnf", "protocol": "nebular.native-rc-smoke",
            "platform": RC_PLATFORMS[target], "scenario": RC_SCENARIOS[target]["raw-archive"],
            "argv": [f"--nebular-release-smoke={RC_SCENARIOS[target]['raw-archive']}"],
            "timeout_seconds": 20, "state_paths": ["state/nebular"],
            "user_state_protocol": {"schema": "nebular.native-rc-persistent-user-state-v1",
                                     "method": "native-rc-smoke.persistentStateLocations+snapshotLocations",
                                     "scope": "real-user-state"},
            "qualification": qualification_descriptor, "smoke": smoke,
            "loader": {"status": "verified", "path": loader["path"], "sha256": loader_sha,
                        "qualification_check_id": "launcher"},
            "sidecar": {"status": "verified", "path": sidecar["path"], "sha256": sidecar_sha},
            "provider_closure": provider,
        }
        raw_release = {
            "root": str(self.raw_root), "record": record_descriptor, "readme": readme_descriptor,
            "legal_files": legal_descriptors, "payload": payload_descriptor,
            "manifest": manifest_descriptor, "provenance": provenance_descriptor,
            "native_consumer": {target: native},
        }

        wheels = [{"target": target_name, **candidate_row["wheel"]}
                  for target_name, candidate_row in (
                      ("darwin-arm64", next(item for item in self.candidate["rows"] if item["system"] == "aarch64-darwin")),
                      ("linux-arm64-gnu", next(item for item in self.candidate["rows"] if item["system"] == "aarch64-linux")),
                      ("linux-x64-gnu", next(item for item in self.candidate["rows"] if item["system"] == "x86_64-linux")),
                  )]
        expected = {"schema": hosted.NEBULAR070_EXPECTED_ARTIFACT_SCHEMA,
                    "candidate_rs9_source": self.candidate["candidate_rs9_source"],
                    "wheels": wheels,
                    "record_sha256": sha256(canonical(sorted(wheels, key=lambda item: item["target"])))}
        wheel_path = self.output / system / row["wheel"]["filename"]
        return expected, raw_release, wheel_path

    def sandbox_probe(self, _env, _prefix):
        return {
            "network_disabled": True,
            "method": "controlled-fixture-sandbox",
            "proof_sha256": sha256(b"controlled-fixture-sandbox"),
        }

    def real_user_state_snapshot(self, phase, target):
        return {
            "schema": "nebular.native-rc-persistent-user-state-v1",
            "method": "native-rc-smoke.persistentStateLocations+snapshotLocations",
            "scope": "real-user-state",
            "target": target,
            "phase": phase,
            "locations": 21,
            "snapshot_sha256": sha256(b"controlled-real-user-state"),
            "changed": [],
        }

    def fixture_runner(self, target):
        """Run the actual wheel entry point with its fixture-only host guard bypassed.

        Each synthetic Gate 1 wheel is authenticated and exercised on a
        diagnostic host that may differ from its target platform.  The
        temporary fixture-only bypass leaves materialization, executable-path
        resolution, hashes, and the native command intact; it never pretends
        to establish native qualification.
        """
        def runner(argv, **kwargs):
            if "--path" in [str(value) for value in argv]:
                work = Path(argv[0]).resolve().parent.parent
                launcher = next(work.joinpath("site").glob("theme_forge_nebular_fusion/launcher.py"))
                source = launcher.read_text(encoding="utf-8")
                marker = "# gate2 fixture foreign-platform guard"
                if marker not in source:
                    source = source.replace(
                        "def _platform_check() -> None:\n",
                        "def _platform_check() -> None:\n    # gate2 fixture foreign-platform guard\n    return\n",
                        1,
                    )
                    launcher.write_text(source, encoding="utf-8")
            return subprocess.Popen(argv, **kwargs)
        return runner

    def mutate_handoff_json_descriptor(self, raw, descriptor, mutate):
        path = Path(raw["root"]) / descriptor["path"]
        before = path.read_bytes()
        value = json.loads(before)
        mutate(value)
        updated = canonical(value)
        path.write_bytes(updated)
        descriptor["size"] = len(updated)
        descriptor["sha256"] = sha256(updated)
        return path, before, descriptor.copy()

    def test_actual_gate1_receipt_hands_off_to_controlled_gate2_consumer(self):
        self.assertEqual(
            self.candidate["readme"],
            {
                "path": "operators/tf-pypi/descriptions/nebular-fusion-0.7.0.md",
                "sha256": "6bd13e05b0ad87ef1c1c9635a320f2e1b9341577e81c42d78e61b6cb94a72dc3",
            },
        )
        for target, (expected, raw_release, wheel) in self.handoffs.items():
            result = hosted.qualify_nebular070(
                self.candidate,
                wheel,
                raw_release,
                self.root / f"gate2-work-{target}",
                expected_artifacts=expected,
                expected_commit=self.candidate["candidate_rs9_source"]["commit"],
                expected_tree=self.candidate["candidate_rs9_source"]["tree"],
                profile_sha256=self.candidate["profile_result_sha256"],
                candidate_receipt_sha256=self.candidate_receipt_sha,
                target=target,
                run_id="700",
                run_attempt="1",
                sandbox_probe=self.sandbox_probe,
                host_identity={"source": "controlled-fixture", "system": SYSTEMS[target], "machine": "fixture"},
                fixture_only=True,
                runner=self.fixture_runner(target),
                real_user_state_snapshot=self.real_user_state_snapshot,
            )
            self.assertEqual(result["status"], "fixture-native-consumer-passed")
            self.assertTrue(result["fixture_only"])
            self.assertFalse(result["native_qualified"])
            self.assertEqual(result["candidate_rs9_source"], self.candidate["candidate_rs9_source"])
            self.assertTrue(result["consumer"]["user_state"]["unchanged"])
            self.assertEqual(result["consumer"]["process_observer"]["orphan_count"], 0)
            target_row = next(row for row in self.candidate["rows"] if row["system"] == SYSTEMS[target])
            self.assertEqual(result["consumer"]["wheel"]["sha256"], target_row["wheel"]["sha256"])
            self.assertFalse(result["publication_admitted"])

    def test_actual_gate1_handoff_path_and_digest_swaps_fail_closed(self):
        target = "darwin-arm64"
        expected, raw_release, wheel = self.handoffs[target]
        raw = copy.deepcopy(raw_release)
        smoke_run = raw["native_consumer"][target]["smoke"]["raw-archive"]["run"]
        smoke_path, smoke_before, _ = self.mutate_handoff_json_descriptor(
            raw, smoke_run, lambda value: value["executable"].update(
                path="Contents/MacOS/theme-forge-nebular-fusion"
            ),
        )
        with self.assertRaises(AdmissionError) as caught:
            hosted.qualify_nebular070(
                self.candidate, wheel, raw, self.root / "gate1-wrong-smoke-path",
                expected_artifacts=expected,
                expected_commit=self.candidate["candidate_rs9_source"]["commit"],
                expected_tree=self.candidate["candidate_rs9_source"]["tree"],
                profile_sha256=self.candidate["profile_result_sha256"],
                candidate_receipt_sha256=self.candidate_receipt_sha,
                target=target, run_id="700", run_attempt="1", sandbox_probe=self.sandbox_probe,
                host_identity={"source": "controlled-fixture", "system": SYSTEMS[target], "machine": "fixture"},
                fixture_only=True, runner=self.fixture_runner(target),
                real_user_state_snapshot=self.real_user_state_snapshot,
            )
        self.assertEqual(caught.exception.code, "TF_PYPI_NEBULAR_NATIVE_EVIDENCE")
        smoke_path.write_bytes(smoke_before)
        smoke_run["size"] = len(smoke_before)
        smoke_run["sha256"] = sha256(smoke_before)

        qualification = raw["native_consumer"][target]["qualification"]
        qualification_path, qualification_before, _ = self.mutate_handoff_json_descriptor(
            raw, qualification,
            lambda value: next(
                row for row in value["checks"] if row["id"] == "sidecar-runtime"
            ).update(detail="node 22.23.3 " + raw["native_consumer"][target]["loader"]["sha256"]),
        )
        with self.assertRaises(AdmissionError) as caught:
            hosted.qualify_nebular070(
                self.candidate, wheel, raw, self.root / "gate1-swapped-sidecar-digest",
                expected_artifacts=expected,
                expected_commit=self.candidate["candidate_rs9_source"]["commit"],
                expected_tree=self.candidate["candidate_rs9_source"]["tree"],
                profile_sha256=self.candidate["profile_result_sha256"],
                candidate_receipt_sha256=self.candidate_receipt_sha,
                target=target, run_id="700", run_attempt="1", sandbox_probe=self.sandbox_probe,
                host_identity={"source": "controlled-fixture", "system": SYSTEMS[target], "machine": "fixture"},
                fixture_only=True, runner=self.fixture_runner(target),
                real_user_state_snapshot=self.real_user_state_snapshot,
            )
        self.assertEqual(caught.exception.code, "TF_PYPI_NEBULAR_NATIVE_EVIDENCE")
        qualification_path.write_bytes(qualification_before)
        qualification["size"] = len(qualification_before)
        qualification["sha256"] = sha256(qualification_before)


if __name__ == "__main__":
    unittest.main(verbosity=2)
