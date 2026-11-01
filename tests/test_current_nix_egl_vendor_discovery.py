"""Pure synthetic tests for optional fixed EGL guest metadata discovery."""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from rs9.current_generation import CURRENT_GENERATION, HISTORICAL_GENERATION
from rs9.errors import ContractError
from rs9.hosted_custody import diagnostic_bytes
from rs9 import hosted_nix
from rs9.nix_gui_discovery import (
    EGL_SCHEMA,
    NODE_FS_EGL_METADATA_SOURCE,
    NODE_FS_SOURCE,
    SCHEMA,
    _EGL_GUEST_IDS,
    _EGL_GUEST_PATHS,
    _NODE_EGL_FRAGMENTS,
    _discovery_request,
    _validate_observation,
    _validated_egl,
    record_fhs_gui_discovery,
)
from rs9.scratch import canonical
from tests.test_nix_gui_discovery import _entry, _facts, _fixture_model

EXPECTED_NODE_FS_SOURCE_SHA256 = (
    "72f295144b4a4c547b1e0f8e2282ab78d0b59201bd90fae6a1ebe05aa258ab39"
)
GUEST_PATH_BY_ID = dict(_EGL_GUEST_PATHS)
GUEST_PATHS = set(GUEST_PATH_BY_ID.values())


def _run_node_variant(
    request,
    store_model,
    guest_model=None,
    *,
    source_code=NODE_FS_EGL_METADATA_SOURCE,
):
    node = shutil.which("node")
    if node is None:
        raise AssertionError("qualified Node executable required")
    guest_spec = guest_model or {}
    wrapper = f"""
const vm = require('node:vm');
const path = require('node:path');
const crypto = require('node:crypto');
const request = {json.dumps(request)};
const storeModel = {json.dumps(store_model)};
const guestSpec = {json.dumps(guest_spec)};
const guestSet = new Set({json.dumps(sorted(GUEST_PATHS))});
const guestCalls = [];
const opened = new Map();

function makeError(code) {{
  if (code === 'THROWING_CODE_GETTER') {{
    return Object.defineProperty({{}}, 'code', {{
      get() {{ throw new Error('hostile code getter'); }}
    }});
  }}
  if (code === 'NO_CODE') {{
    return new Error('synthetic without code');
  }}
  const err = new Error('synthetic');
  if (code !== null && code !== undefined) err.code = code;
  return err;
}}

function guestStatFor(name) {{
  const spec = guestSpec[name];
  if (!spec || spec.lstatError) {{
    throw makeError(spec ? spec.lstatError : 'ENOENT');
  }}
  if (spec.throwingStatMethod) {{
    return {{
      isSymbolicLink: () => {{ throw new Error('broken stat'); }},
      isFile: () => false,
      isDirectory: () => false,
    }};
  }}
  return {{
    dev: 99n, ino: 999n, size: 1234n, mode: 33188n,
    mtimeNs: 1n, ctimeNs: 1n, uid: 0n, gid: 0n, nlink: 1n,
    isDirectory: () => spec.kind === 'directory',
    isFile: () => spec.kind === 'regular',
    isSymbolicLink: () => spec.kind === 'symlink',
  }};
}}

function storeStatFor(name) {{
  const value = storeModel[name];
  if (!value) {{
    const error = new Error('missing');
    error.code = 'ENOENT';
    throw error;
  }}
  const reads = opened.get(name);
  const tick = BigInt(value.tick) + (value.unstable && reads !== undefined ? BigInt(reads) : 0n);
  return {{
    dev: 1n, ino: BigInt(value.ino), size: BigInt(value.size), mode: BigInt(value.mode),
    mtimeNs: tick, ctimeNs: tick, uid: 501n, gid: 0n, nlink: 1n,
    isDirectory: () => value.kind === 'dir',
    isFile: () => value.kind === 'file',
    isSymbolicLink: () => value.kind === 'link',
  }};
}}

function dirents(name) {{
  const prefix = name.endsWith('/') ? name : name + '/';
  const values = new Map();
  for (const key of Object.keys(storeModel)) {{
    if (!key.startsWith(prefix)) continue;
    const tail = key.slice(prefix.length);
    if (!tail || tail.includes('/')) continue;
    values.set(tail, storeModel[key]);
  }}
  return [...values.entries()].map(([entry, value]) => ({{
    name: entry,
    isDirectory: () => value.kind === 'dir',
    isFile: () => value.kind === 'file',
    isSymbolicLink: () => value.kind === 'link',
  }}));
}}

function forbidGuest(op, name) {{
  if (guestSet.has(name) || (typeof name === 'string' && !name.startsWith('/nix/store/'))) {{
    guestCalls.push({{op, path: name, forbidden: true}});
    throw new Error('forbidden guest operation: ' + op);
  }}
}}

const fs = {{
  constants: {{O_RDONLY: 1, O_NOFOLLOW: 2, O_NONBLOCK: 4}},
  lstatSync: (name, options) => {{
    if (guestSet.has(name) || !String(name).startsWith('/nix/store/')) {{
      guestCalls.push({{op: 'lstat', path: name}});
      return guestStatFor(name);
    }}
    return storeStatFor(name);
  }},
  fstatSync: (fd) => {{
    forbidGuest('fstat', fd);
    const value = storeStatFor(fd);
    if (opened.has(fd)) opened.set(fd, opened.get(fd) + 1);
    return value;
  }},
  readdirSync: (name) => {{
    forbidGuest('readdir', name);
    return dirents(name);
  }},
  readlinkSync: (name, options) => {{
    if (guestSet.has(name) || !String(name).startsWith('/nix/store/')) {{
      guestCalls.push({{
        op: 'readlink',
        path: name,
        encoding: options && typeof options === 'object' ? options.encoding : null,
      }});
      const spec = guestSpec[name];
      if (!spec || spec.readlinkError) {{
        throw makeError(spec ? spec.readlinkError : 'ENOENT');
      }}
      if (spec.targetHex !== undefined) {{
        return Buffer.from(spec.targetHex, 'hex');
      }}
      if (spec.targetRaw !== undefined) {{
        return spec.targetRaw;
      }}
      if (options && options.encoding === 'buffer' && typeof spec.target === 'string') {{
        return Buffer.from(spec.target, 'utf8');
      }}
      return spec.target;
    }}
    return storeModel[name].target;
  }},
  readFileSync: (fd, encoding) => {{
    if (fd === 0) return JSON.stringify(request);
    forbidGuest('readFile', fd);
    return storeModel[fd].data;
  }},
  openSync: (name) => {{
    forbidGuest('open', name);
    opened.set(name, 0);
    return name;
  }},
  readSync: (fd, buffer, offset, length, position) => {{
    forbidGuest('read', fd);
    const bytes = Buffer.from(storeModel[fd].data || '');
    if (position >= bytes.length) return 0;
    const count = Math.min(length, bytes.length - position);
    bytes.copy(buffer, offset, position, position + count);
    return count;
  }},
  closeSync: () => undefined,
  statSync: (name) => {{ forbidGuest('stat', name); }},
  realpathSync: (name) => {{ forbidGuest('realpath', name); }},
  existsSync: (name) => {{ forbidGuest('exists', name); }},
  accessSync: (name) => {{ forbidGuest('access', name); }},
}};

let captured = '';
const context = {{
  Buffer,
  __RS9_FS_DOUBLE__: {{
    fs, path, crypto,
    output: {{write: (value) => {{ captured += value; }}}},
  }},
}};
vm.runInNewContext({json.dumps(source_code)}, context);
process.stdout.write(JSON.stringify({{
  result: JSON.parse(captured),
  guestCalls,
}}));
"""
    completed = subprocess.run(
        [node, "--input-type=commonjs"],
        input=wrapper.encode("utf-8"),
        capture_output=True,
        timeout=15,
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stderr.decode("utf-8", "replace"))
    payload = json.loads(completed.stdout)
    return payload["result"], payload["guestCalls"]


class CurrentNixEglVendorDiscoveryTests(unittest.TestCase):
    def test_node_fs_source_bytes_pinned_and_variant_fragments_reversible(self):
        actual_sha = hashlib.sha256(NODE_FS_SOURCE.encode("utf-8")).hexdigest()
        self.assertEqual(actual_sha, EXPECTED_NODE_FS_SOURCE_SHA256)
        self.assertNotEqual(NODE_FS_EGL_METADATA_SOURCE, NODE_FS_SOURCE)
        reconstructed = NODE_FS_EGL_METADATA_SOURCE
        for fragment in reversed(_NODE_EGL_FRAGMENTS):
            self.assertEqual(reconstructed.count(fragment), 1)
            reconstructed = reconstructed.replace(fragment, "", 1)
        self.assertEqual(reconstructed, NODE_FS_SOURCE)
        for fragment in _NODE_EGL_FRAGMENTS:
            for forbidden in (
                "require", "process", "child_process", "node:net",
                "node:http", "node:dns", "fetch(",
            ):
                self.assertNotIn(forbidden, fragment)
        for forbidden in (
            "child_process", "process.env", "node:net",
            "node:http", "node:dns", "fetch(",
        ):
            self.assertNotIn(forbidden, NODE_FS_EGL_METADATA_SOURCE)

    def test_all_eight_fixed_ids_statuses_kinds_target_classes_and_fs_call_bounds(self):
        facts = _facts()
        request = _discovery_request(facts)
        store_model = _fixture_model(facts)
        store_target = "/nix/store/" + "d" * 32 + "-mesa-drivers/share/glvnd/50_mesa.json"

        # Scenario 1: exercise all 8 IDs with mixed present/missing/inaccessible/error/symlink classes
        guest_1 = {
            GUEST_PATH_BY_ID["usr-share-mesa"]: {
                "kind": "symlink",
                "target": store_target,
            },
            GUEST_PATH_BY_ID["etc-mesa"]: {
                "kind": "symlink",
                "target": "/usr/share/glvnd/egl_vendor.d/50_mesa.json",
            },
            GUEST_PATH_BY_ID["usr-lib-egl"]: {
                "kind": "symlink",
                "target": "libEGL_mesa.so.0",
            },
            GUEST_PATH_BY_ID["usr-lib64-egl"]: {
                "kind": "symlink",
                "target": "../lib/libEGL.so.1",
            },
            GUEST_PATH_BY_ID["usr-lib-mesa"]: {
                "kind": "regular",
            },
            GUEST_PATH_BY_ID["usr-lib64-mesa"]: {
                "kind": "directory",
            },
            GUEST_PATH_BY_ID["usr-lib-swrast"]: {
                "kind": "fifo",
            },
            GUEST_PATH_BY_ID["usr-lib64-swrast"]: {
                "lstatError": "ENOENT",
            },
        }
        result_1, calls_1 = _run_node_variant(request, store_model, guest_1)
        egl_1 = result_1["egl_metadata"]
        self.assertEqual(_validated_egl(egl_1), egl_1)
        self.assertEqual(egl_1["schema"], EGL_SCHEMA)
        self.assertEqual(egl_1["status"], "observed")
        self.assertEqual(tuple(egl_1["entries"].keys()), _EGL_GUEST_IDS)
        self.assertEqual(
            egl_1["entries"],
            {
                "usr-share-mesa": {
                    "status": "present",
                    "kind": "symlink",
                    "target_class": "public-nix-store",
                },
                "etc-mesa": {
                    "status": "present",
                    "kind": "symlink",
                    "target_class": "fixed-guest-path",
                },
                "usr-lib-egl": {
                    "status": "present",
                    "kind": "symlink",
                    "target_class": "fixed-guest-path",
                },
                "usr-lib64-egl": {
                    "status": "present",
                    "kind": "symlink",
                    "target_class": "other",
                },
                "usr-lib-mesa": {
                    "status": "present",
                    "kind": "regular",
                },
                "usr-lib64-mesa": {
                    "status": "present",
                    "kind": "directory",
                },
                "usr-lib-swrast": {
                    "status": "present",
                    "kind": "other",
                },
                "usr-lib64-swrast": {
                    "status": "missing",
                },
            },
        )
        lstat_paths = [c["path"] for c in calls_1 if c["op"] == "lstat"]
        readlink_calls = [c for c in calls_1 if c["op"] == "readlink"]
        self.assertEqual(lstat_paths, [p for _, p in _EGL_GUEST_PATHS])
        self.assertEqual(
            [c["path"] for c in readlink_calls],
            [
                GUEST_PATH_BY_ID["usr-share-mesa"],
                GUEST_PATH_BY_ID["etc-mesa"],
                GUEST_PATH_BY_ID["usr-lib-egl"],
                GUEST_PATH_BY_ID["usr-lib64-egl"],
            ],
        )
        self.assertTrue(all(c["encoding"] == "buffer" for c in readlink_calls))
        self.assertEqual(len(calls_1), 8 + 4)

        # Ensure no raw guest paths, target strings, or stat numbers leak into egl_metadata
        serialized_egl = json.dumps(egl_1)
        for forbidden_text in (
            "/usr/", "/etc/", "50_mesa.json", "libEGL", "swrast_dri",
            store_target, "999", "33188",
        ):
            self.assertNotIn(forbidden_text, serialized_egl)

        # Scenario 2: EACCES, EPERM, ELOOP, ENOTDIR, EIO, readlink errors, and UTF-8 / NUL / byte bounds
        exact_4096_euro = (
            "/nix/store/" + "a" * 32 + "-pkg/" + ("\u20ac" * 1348) + ("a" * 4)
        )
        self.assertEqual(len(exact_4096_euro.encode("utf-8")), 4096)
        over_4098_euro = "\u20ac" * 1366
        self.assertEqual(len(over_4098_euro.encode("utf-8")), 4098)

        guest_2 = {
            GUEST_PATH_BY_ID["usr-share-mesa"]: {"lstatError": "EACCES"},
            GUEST_PATH_BY_ID["etc-mesa"]: {"lstatError": "EPERM"},
            GUEST_PATH_BY_ID["usr-lib-egl"]: {"lstatError": "ELOOP"},
            GUEST_PATH_BY_ID["usr-lib64-egl"]: {"lstatError": "ENOTDIR"},
            GUEST_PATH_BY_ID["usr-lib-mesa"]: {
                "kind": "symlink",
                "target": exact_4096_euro,
            },
            GUEST_PATH_BY_ID["usr-lib64-mesa"]: {
                "kind": "symlink",
                "target": over_4098_euro,
            },
            GUEST_PATH_BY_ID["usr-lib-swrast"]: {
                "kind": "symlink",
                "target": "a" * 4097,
            },
            GUEST_PATH_BY_ID["usr-lib64-swrast"]: {
                "kind": "symlink",
                "readlinkError": "EACCES",
            },
        }
        result_2, calls_2 = _run_node_variant(request, store_model, guest_2)
        egl_2 = result_2["egl_metadata"]
        self.assertEqual(_validated_egl(egl_2), egl_2)
        self.assertEqual(
            egl_2["entries"],
            {
                "usr-share-mesa": {"status": "inaccessible"},
                "etc-mesa": {"status": "inaccessible"},
                "usr-lib-egl": {"status": "error"},
                "usr-lib64-egl": {"status": "error"},
                "usr-lib-mesa": {
                    "status": "present",
                    "kind": "symlink",
                    "target_class": "public-nix-store",
                },
                "usr-lib64-mesa": {
                    "status": "bounded",
                    "kind": "symlink",
                    "target_class": "unavailable",
                },
                "usr-lib-swrast": {
                    "status": "bounded",
                    "kind": "symlink",
                    "target_class": "unavailable",
                },
                "usr-lib64-swrast": {
                    "status": "error",
                    "kind": "symlink",
                    "target_class": "unavailable",
                },
            },
        )
        self.assertEqual(len([c for c in calls_2 if c["op"] == "lstat"]), 8)
        self.assertEqual(len([c for c in calls_2 if c["op"] == "readlink"]), 4)

        # Scenario 3: NUL byte, invalid UTF-8 buffer, non-string target, empty target, store escape with .., other path
        guest_3 = {
            GUEST_PATH_BY_ID["usr-share-mesa"]: {
                "kind": "symlink",
                "targetHex": "2f757372006d657361",  # /usr\0mesa
            },
            GUEST_PATH_BY_ID["etc-mesa"]: {
                "kind": "symlink",
                "targetHex": "fffefd",  # invalid UTF-8 within 4096 bytes
            },
            GUEST_PATH_BY_ID["usr-lib-egl"]: {
                "kind": "symlink",
                "targetRaw": 12345,
            },
            GUEST_PATH_BY_ID["usr-lib64-egl"]: {
                "kind": "symlink",
                "target": "",
            },
            GUEST_PATH_BY_ID["usr-lib-mesa"]: {
                "kind": "symlink",
                "target": "/nix/store/" + "f" * 32 + "-mesa/../escape",
            },
            GUEST_PATH_BY_ID["usr-lib64-mesa"]: {
                "kind": "symlink",
                "target": "/opt/vendor/libEGL_mesa.so.0",
            },
            GUEST_PATH_BY_ID["usr-lib-swrast"]: {
                "lstatError": "NO_CODE",  # error object without .code
            },
            GUEST_PATH_BY_ID["usr-lib64-swrast"]: {
                "kind": "symlink",
                "target": "/usr/lib/swrast\x00bad",
            },
        }
        result_3, _ = _run_node_variant(request, store_model, guest_3)
        egl_3 = result_3["egl_metadata"]
        self.assertEqual(_validated_egl(egl_3), egl_3)
        self.assertEqual(
            egl_3["entries"],
            {
                "usr-share-mesa": {
                    "status": "bounded",
                    "kind": "symlink",
                    "target_class": "unavailable",
                },
                "etc-mesa": {
                    "status": "bounded",
                    "kind": "symlink",
                    "target_class": "unavailable",
                },
                "usr-lib-egl": {
                    "status": "bounded",
                    "kind": "symlink",
                    "target_class": "unavailable",
                },
                "usr-lib64-egl": {
                    "status": "bounded",
                    "kind": "symlink",
                    "target_class": "unavailable",
                },
                "usr-lib-mesa": {
                    "status": "present",
                    "kind": "symlink",
                    "target_class": "other",
                },
                "usr-lib64-mesa": {
                    "status": "present",
                    "kind": "symlink",
                    "target_class": "other",
                },
                "usr-lib-swrast": {
                    "status": "error",
                },
                "usr-lib64-swrast": {
                    "status": "bounded",
                    "kind": "symlink",
                    "target_class": "unavailable",
                },
            },
        )

    def test_strict_literal_true_opt_in_and_script_sha256_provenance(self):
        from subprocess import CompletedProcess

        class TruthySwitch:
            def __bool__(self):
                return True

        facts = _facts()
        request = _discovery_request(facts)
        store_model = _fixture_model(facts)
        default_node_out, _ = _run_node_variant(
            request, store_model, source_code=NODE_FS_SOURCE
        )
        variant_node_out, _ = _run_node_variant(
            request, store_model, source_code=NODE_FS_EGL_METADATA_SOURCE
        )
        default_stdout = json.dumps(default_node_out).encode("utf-8")
        variant_stdout = json.dumps(variant_node_out).encode("utf-8")
        expected_default_sha = hashlib.sha256(NODE_FS_SOURCE.encode("utf-8")).hexdigest()
        expected_variant_sha = hashlib.sha256(
            NODE_FS_EGL_METADATA_SOURCE.encode("utf-8")
        ).hexdigest()
        expected_input = canonical(request)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            baseline_dest = root / "baseline.json"
            with patch(
                "rs9.nix_gui_discovery.subprocess.run",
                return_value=CompletedProcess([], 0, default_stdout, b""),
            ) as base_run:
                baseline_record = record_fhs_gui_discovery(
                    facts, ["pfx"], ["rt"], {"K": "V"}, baseline_dest
                )
            baseline_bytes = baseline_dest.read_bytes()
            base_run.assert_called_once()
            self.assertEqual(base_run.call_args.args[0][-2:], ["-e", NODE_FS_SOURCE])
            self.assertEqual(base_run.call_args.kwargs["input"], expected_input)
            self.assertEqual(base_run.call_args.kwargs["timeout"], 30)
            self.assertEqual(baseline_record["script_sha256"], expected_default_sha)
            self.assertNotIn("egl_metadata", baseline_record)

            for index, flag in enumerate(
                (False, None, 0, 1, 1.0, "true", "True", [True], {"v": True}, TruthySwitch())
            ):
                with self.subTest(flag=repr(flag)):
                    dest = root / f"non-true-{index}.json"
                    with patch(
                        "rs9.nix_gui_discovery.subprocess.run",
                        return_value=CompletedProcess([], 0, default_stdout, b""),
                    ) as mock_run:
                        rec = record_fhs_gui_discovery(
                            facts,
                            ["pfx"],
                            ["rt"],
                            {"K": "V"},
                            dest,
                            current_linux_egl_metadata=flag,
                        )
                    mock_run.assert_called_once()
                    self.assertEqual(mock_run.call_args.args[0], base_run.call_args.args[0])
                    self.assertEqual(mock_run.call_args.kwargs["input"], expected_input)
                    self.assertEqual(mock_run.call_args.kwargs["timeout"], 30)
                    self.assertEqual(rec, baseline_record)
                    self.assertEqual(dest.read_bytes(), baseline_bytes)

            opt_in_dest = root / "opt-in.json"
            with patch(
                "rs9.nix_gui_discovery.subprocess.run",
                return_value=CompletedProcess([], 0, variant_stdout, b""),
            ) as opt_run:
                opt_record = record_fhs_gui_discovery(
                    facts,
                    ["pfx"],
                    ["rt"],
                    {"K": "V"},
                    opt_in_dest,
                    current_linux_egl_metadata=True,
                )
            opt_run.assert_called_once()
            self.assertEqual(opt_run.call_args.args[0][:-1], base_run.call_args.args[0][:-1])
            self.assertEqual(opt_run.call_args.args[0][-1], NODE_FS_EGL_METADATA_SOURCE)
            self.assertEqual(opt_run.call_args.kwargs["input"], expected_input)
            self.assertEqual(opt_run.call_args.kwargs["timeout"], 30)
            self.assertEqual(opt_record["script_sha256"], expected_variant_sha)
            self.assertEqual(opt_record["result"], baseline_record["result"])
            self.assertNotIn("egl_metadata", opt_record["result"])
            self.assertIn("egl_metadata", opt_record)
            self.assertEqual(opt_record["egl_metadata"]["status"], "observed")
            self.assertEqual(
                diagnostic_bytes(opt_in_dest), opt_in_dest.read_bytes()
            )

    def test_closed_reason_mapping_and_forged_egl_metadata_rejection(self):
        from subprocess import CompletedProcess

        facts = _facts()
        request = _discovery_request(facts)
        store_model = _fixture_model(facts)
        default_out, _ = _run_node_variant(
            request, store_model, source_code=NODE_FS_SOURCE
        )
        variant_out, _ = _run_node_variant(
            request, store_model, source_code=NODE_FS_EGL_METADATA_SOURCE
        )
        expected_variant_sha = hashlib.sha256(
            NODE_FS_EGL_METADATA_SOURCE.encode("utf-8")
        ).hexdigest()

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            # 1. invalid-source-bound-facts -> discovery-unavailable
            bad_facts_dest = root / "bad-facts.json"
            bad_facts_rec = record_fhs_gui_discovery(
                {}, [], [], {}, bad_facts_dest, current_linux_egl_metadata=True
            )
            self.assertEqual(bad_facts_rec["status"], "fail")
            self.assertEqual(bad_facts_rec["reason"], "invalid-source-bound-facts")
            self.assertEqual(bad_facts_rec["script_sha256"], expected_variant_sha)
            self.assertEqual(
                bad_facts_rec["egl_metadata"],
                {
                    "schema": EGL_SCHEMA,
                    "status": "unavailable",
                    "reason": "discovery-unavailable",
                },
            )

            # 2. bounded-observation-unavailable -> discovery-unavailable
            for sub_case, side_effect in (
                ("oserror", OSError("spawn failed")),
                ("bad-json", CompletedProcess([], 0, b"{not-json", b"")),
                (
                    "oversize-stderr",
                    CompletedProcess([], 0, json.dumps(variant_out).encode(), b"e" * 65537),
                ),
            ):
                with self.subTest(sub_case=sub_case), patch(
                    "rs9.nix_gui_discovery.subprocess.run",
                    side_effect=side_effect
                    if isinstance(side_effect, Exception)
                    else lambda *a, **k: side_effect,
                ):
                    rec = record_fhs_gui_discovery(
                        facts,
                        [],
                        [],
                        {},
                        root / f"unavail-{sub_case}.json",
                        current_linux_egl_metadata=True,
                    )
                self.assertEqual(rec["status"], "fail")
                self.assertEqual(rec["reason"], "bounded-observation-unavailable")
                self.assertEqual(rec["script_sha256"], expected_variant_sha)
                self.assertEqual(
                    rec["egl_metadata"],
                    {
                        "schema": EGL_SCHEMA,
                        "status": "unavailable",
                        "reason": "discovery-unavailable",
                    },
                )

            # 3. Fatal old failure (inner status 'fail', even with forged well-formed egl_metadata,
            #    empty stdout, nonzero exit, or non-empty stderr) -> discovery-failed
            fail_node, _ = _run_node_variant(
                request, _fixture_model(facts, missing="pixbuf")
            )
            self.assertEqual(fail_node["status"], "fail")
            self.assertNotIn("egl_metadata", fail_node)
            forged_fail_node = {
                **fail_node,
                "egl_metadata": copy.deepcopy(variant_out["egl_metadata"]),
            }
            for fail_case, proc in (
                ("node-fail", CompletedProcess([], 0, json.dumps(fail_node).encode(), b"")),
                (
                    "node-fail-with-forged-egl",
                    CompletedProcess([], 0, json.dumps(forged_fail_node).encode(), b""),
                ),
                ("empty-stdout", CompletedProcess([], 0, b"", b"")),
                (
                    "nonzero-exit",
                    CompletedProcess([], 1, json.dumps(variant_out).encode(), b""),
                ),
                (
                    "stderr-present",
                    CompletedProcess([], 0, json.dumps(variant_out).encode(), b"warn"),
                ),
            ):
                with self.subTest(fail_case=fail_case), patch(
                    "rs9.nix_gui_discovery.subprocess.run", return_value=proc
                ):
                    rec = record_fhs_gui_discovery(
                        facts,
                        [],
                        [],
                        {},
                        root / f"disc-fail-{fail_case}.json",
                        current_linux_egl_metadata=True,
                    )
                self.assertEqual(rec["status"], "fail")
                self.assertNotIn("egl_metadata", rec["result"])
                self.assertEqual(
                    rec["egl_metadata"],
                    {
                        "schema": EGL_SCHEMA,
                        "status": "unavailable",
                        "reason": "discovery-failed",
                    },
                )

            # 4. Injected guest fault inside Node -> observation-failed while old result matches default
            fault_guest = {
                GUEST_PATH_BY_ID["usr-share-mesa"]: {
                    "lstatError": "THROWING_CODE_GETTER",
                }
            }
            fault_out, _ = _run_node_variant(request, store_model, fault_guest)
            self.assertEqual(
                fault_out["egl_metadata"],
                {
                    "schema": EGL_SCHEMA,
                    "status": "unavailable",
                    "reason": "observation-failed",
                },
            )
            fault_without_egl = dict(fault_out)
            fault_without_egl.pop("egl_metadata")
            self.assertEqual(fault_without_egl, default_out)

            # 5. Missing egl_metadata on valid Node output -> not-returned, old result preserved
            with patch(
                "rs9.nix_gui_discovery.subprocess.run",
                return_value=CompletedProcess([], 0, json.dumps(default_out).encode(), b""),
            ):
                missing_egl_rec = record_fhs_gui_discovery(
                    facts,
                    [],
                    [],
                    {},
                    root / "not-returned.json",
                    current_linux_egl_metadata=True,
                )
            self.assertEqual(missing_egl_rec["status"], default_out["status"])
            self.assertEqual(missing_egl_rec["result"], default_out)
            self.assertEqual(
                missing_egl_rec["egl_metadata"],
                {
                    "schema": EGL_SCHEMA,
                    "status": "unavailable",
                    "reason": "not-returned",
                },
            )

            # 6. Malformed or forged egl_metadata -> validation-failed, old result preserved
            valid_entries = copy.deepcopy(variant_out["egl_metadata"]["entries"])
            malformed_payloads = [
                None,
                "invalid",
                [],
                {"schema": "wrong.schema.v1", "status": "observed", "entries": valid_entries},
                {
                    "schema": EGL_SCHEMA,
                    "status": "observed",
                    "entries": valid_entries,
                    "extra": True,
                },
                {
                    "schema": EGL_SCHEMA,
                    "status": "observed",
                    "entries": {k: v for k, v in valid_entries.items() if k != "etc-mesa"},
                },
                {
                    "schema": EGL_SCHEMA,
                    "status": "observed",
                    "entries": {**valid_entries, "extra-id": {"status": "missing"}},
                },
                {
                    "schema": EGL_SCHEMA,
                    "status": "observed",
                    "entries": {
                        **valid_entries,
                        "/usr/lib/libEGL.so.1": {"status": "missing"},
                    },
                },
                {
                    "schema": EGL_SCHEMA,
                    "status": "observed",
                    "entries": {
                        **valid_entries,
                        "etc-mesa": {"status": "present", "kind": "fifo"},
                    },
                },
                {
                    "schema": EGL_SCHEMA,
                    "status": "observed",
                    "entries": {
                        **valid_entries,
                        "etc-mesa": {
                            "status": "present",
                            "kind": "symlink",
                            "target_class": "unavailable",
                        },
                    },
                },
                {
                    "schema": EGL_SCHEMA,
                    "status": "observed",
                    "entries": {
                        **valid_entries,
                        "etc-mesa": {
                            "status": "present",
                            "kind": "regular",
                            "target_class": "other",
                        },
                    },
                },
                {
                    "schema": EGL_SCHEMA,
                    "status": "observed",
                    "entries": {
                        **valid_entries,
                        "etc-mesa": {
                            "status": "bounded",
                            "kind": "symlink",
                            "target_class": "other",
                        },
                    },
                },
                {
                    "schema": EGL_SCHEMA,
                    "status": "observed",
                    "entries": {
                        **valid_entries,
                        "etc-mesa": {"status": "missing", "kind": "regular"},
                    },
                },
                {
                    "schema": EGL_SCHEMA,
                    "status": "observed",
                    "entries": {
                        **valid_entries,
                        "etc-mesa": {"status": "inaccessible", "kind": "regular"},
                    },
                },
                {
                    "schema": EGL_SCHEMA,
                    "status": "observed",
                    "entries": {
                        **valid_entries,
                        "etc-mesa": {"status": "error", "kind": "regular"},
                    },
                },
                {
                    "schema": EGL_SCHEMA,
                    "status": "observed",
                    "entries": {**valid_entries, "etc-mesa": {"status": True}},
                },
                # Forged Python-only reasons sent from Node must be rejected
                {"schema": EGL_SCHEMA, "status": "omitted", "reason": "custody-bound"},
                {"schema": EGL_SCHEMA, "status": "omitted", "reason": "custody-withheld"},
                {"schema": EGL_SCHEMA, "status": "unavailable", "reason": "not-returned"},
                {"schema": EGL_SCHEMA, "status": "unavailable", "reason": "validation-failed"},
                {"schema": EGL_SCHEMA, "status": "unavailable", "reason": "discovery-failed"},
                {
                    "schema": EGL_SCHEMA,
                    "status": "unavailable",
                    "reason": "discovery-unavailable",
                },
                {
                    "schema": EGL_SCHEMA,
                    "status": "unavailable",
                    "reason": "output-unavailable",
                },
            ]
            for idx, bad_egl in enumerate(malformed_payloads):
                with self.subTest(bad_egl_index=idx):
                    payload = {**copy.deepcopy(default_out), "egl_metadata": bad_egl}
                    with patch(
                        "rs9.nix_gui_discovery.subprocess.run",
                        return_value=CompletedProcess(
                            [], 0, json.dumps(payload).encode("utf-8"), b""
                        ),
                    ):
                        rec = record_fhs_gui_discovery(
                            facts,
                            [],
                            [],
                            {},
                            root / f"malformed-{idx}.json",
                            current_linux_egl_metadata=True,
                        )
                    self.assertEqual(rec["status"], default_out["status"])
                    self.assertEqual(rec["result"], default_out)
                    self.assertEqual(
                        rec["egl_metadata"],
                        {
                            "schema": EGL_SCHEMA,
                            "status": "unavailable",
                            "reason": "validation-failed",
                        },
                    )

            # 7. diagnostic-custody-withheld -> omitted / custody-withheld
            private_out = copy.deepcopy(variant_out)
            private_out["records"][0]["path"] = "libexec/private/synthetic-item"
            with patch(
                "rs9.nix_gui_discovery.subprocess.run",
                return_value=CompletedProcess(
                    [], 0, json.dumps(private_out).encode("utf-8"), b""
                ),
            ):
                withheld_rec = record_fhs_gui_discovery(
                    facts,
                    [],
                    [],
                    {},
                    root / "withheld.json",
                    current_linux_egl_metadata=True,
                )
            self.assertEqual(withheld_rec["status"], "fail")
            self.assertEqual(withheld_rec["reason"], "diagnostic-custody-withheld")
            self.assertEqual(
                withheld_rec["egl_metadata"],
                {
                    "schema": EGL_SCHEMA,
                    "status": "omitted",
                    "reason": "custody-withheld",
                },
            )

            # 8. diagnostic-output-unavailable -> unavailable / output-unavailable
            unavail_out_rec = record_fhs_gui_discovery(
                {},
                [],
                [],
                {},
                root / "missing-dir/output.json",
                current_linux_egl_metadata=True,
            )
            self.assertEqual(unavail_out_rec["status"], "fail")
            self.assertEqual(unavail_out_rec["reason"], "diagnostic-output-unavailable")
            self.assertEqual(
                unavail_out_rec["egl_metadata"],
                {
                    "schema": EGL_SCHEMA,
                    "status": "unavailable",
                    "reason": "output-unavailable",
                },
            )

    def test_stdout_4mib_bound_sheds_egl_metadata_first_then_preserves_old_drop(self):
        # Part A: calibrate model so default output is just under 4 MiB, while
        # observed egl_metadata pushes it over 4 MiB; shedding egl_metadata keeps old records.
        facts = _facts(max_entries=4096)
        request = _discovery_request(facts)
        probe_model = _fixture_model(facts)
        glib = facts["gui_discovery"]["roots"]["glib"]
        dependency = facts["gui_discovery"]["closure_roots"][-1]
        final_target = dependency + "/libexec/helper-target"
        # Place intermediate symlink hops in dependency (inside closure_roots, not walked as a root)
        # so each symlink in glib/libexec carries a multi-hop chain (~2500 bytes per record)
        # and reaches 4 MiB well within the 4096 max_entries bound.
        hop2 = dependency + "/libexec/hop2-" + ("h" * 450)
        hop1 = dependency + "/libexec/hop1-" + ("h" * 450)
        probe_model[hop2] = _entry("link", target=final_target)
        probe_model[hop1] = _entry("link", target=hop2)
        limit = 4 * 1024 * 1024

        # Measure exact bytes added by one padded link record starting from a small model
        pad_name = "x" * 490
        for idx in range(10):
            probe_model[f"{glib}/libexec/p{idx:04d}-{pad_name}"] = _entry(
                "link", target=hop1
            )
        measured_out, _ = _run_node_variant(
            request, probe_model, source_code=NODE_FS_SOURCE
        )
        self.assertEqual(measured_out["status"], "partial")
        current_bytes = len(
            json.dumps(measured_out, separators=(",", ":")).encode("utf-8")
        )
        probe_model[f"{glib}/libexec/p0010-{pad_name}"] = _entry(
            "link", target=hop1
        )
        measured_one_more, _ = _run_node_variant(
            request, probe_model, source_code=NODE_FS_SOURCE
        )
        per_record = (
            len(json.dumps(measured_one_more, separators=(",", ":")).encode("utf-8"))
            - current_bytes
        )
        self.assertGreater(per_record, 2000)
        del probe_model[f"{glib}/libexec/p0010-{pad_name}"]

        target_without_egl = limit - 180
        needed = target_without_egl - current_bytes
        extra_full = (needed // per_record) + 1
        adjustable = 6
        for idx in range(extra_full):
            initial_pad = "x" * 10 if idx < adjustable else pad_name
            probe_model[f"{glib}/libexec/q{idx:04d}-{initial_pad}"] = _entry(
                "link", target=hop1
            )
        measured_out2, _ = _run_node_variant(
            request, probe_model, source_code=NODE_FS_SOURCE
        )
        current_bytes2 = len(
            json.dumps(measured_out2, separators=(",", ":")).encode("utf-8")
        )
        deficit_chars = max(0, (target_without_egl - current_bytes2) // 2)
        for idx in range(adjustable):
            grow = min(480, deficit_chars)
            if grow <= 0:
                break
            del probe_model[f"{glib}/libexec/q{idx:04d}-{'x' * 10}"]
            grown_pad = "x" * (10 + grow)
            probe_model[f"{glib}/libexec/q{idx:04d}-{grown_pad}"] = _entry(
                "link", target=hop1
            )
            deficit_chars -= grow

        # Part A: calibrate canonical custody record to fit <= 64 KiB after shedding egl_metadata,
        # but exceed 64 KiB while egl_metadata is 'observed'.

        default_near, _ = _run_node_variant(
            request, probe_model, source_code=NODE_FS_SOURCE
        )
        default_near_bytes = len(
            json.dumps(default_near, separators=(",", ":")).encode("utf-8")
        )
        self.assertLessEqual(default_near_bytes, limit)
        self.assertGreater(default_near_bytes, limit - 250)
        self.assertGreater(len(default_near["records"]), 900)

        variant_near, _ = _run_node_variant(
            request, probe_model, source_code=NODE_FS_EGL_METADATA_SOURCE
        )
        variant_near_bytes = len(
            json.dumps(variant_near, separators=(",", ":")).encode("utf-8")
        )
        self.assertLessEqual(variant_near_bytes, limit)
        self.assertEqual(
            variant_near["egl_metadata"],
            {
                "schema": EGL_SCHEMA,
                "status": "omitted",
                "reason": "output-bound",
            },
        )
        self.assertEqual(len(variant_near["records"]), len(default_near["records"]))
        self.assertEqual(variant_near["status"], default_near["status"])
        self.assertEqual(variant_near.get("truncated"), default_near.get("truncated"))

        # Part B: when old records themselves exceed 4 MiB, EGL is shed and old drop runs unchanged
        over_model = copy.deepcopy(probe_model)
        for idx in range(10):
            over_model[f"{glib}/libexec/over{idx:04d}-{pad_name}"] = _entry(
                "link", target=hop1
            )
        over_default, _ = _run_node_variant(
            request, over_model, source_code=NODE_FS_SOURCE
        )
        over_variant, _ = _run_node_variant(
            request, over_model, source_code=NODE_FS_EGL_METADATA_SOURCE
        )
        self.assertEqual(over_default["truncated"]["reason"], "output-bound")
        self.assertEqual(
            over_variant["egl_metadata"],
            {"schema": EGL_SCHEMA, "status": "omitted", "reason": "output-bound"},
        )
        over_variant_without_egl = dict(over_variant)
        over_variant_without_egl.pop("egl_metadata")
        self.assertEqual(over_variant_without_egl, over_default)

    def test_custody_64kib_bound_sheds_egl_metadata_first_then_halves_records(self):
        from subprocess import CompletedProcess

        facts = _facts()
        request = _discovery_request(facts)
        store_model = _fixture_model(facts)
        variant_good, _ = _run_node_variant(request, store_model)
        default_good = copy.deepcopy(variant_good)
        default_good.pop("egl_metadata")

        # Part A: calibrate canonical custody record to fit <= 64 KiB after shedding egl_metadata,
        # but exceed 64 KiB while egl_metadata is 'observed'.
        template_row = copy.deepcopy(
            next(r for r in default_good["records"] if r["type"] == "directory")
        )
        base_pad = 3000
        template_row["path"] = "libexec/" + ("a" * base_pad)
        calibrated = copy.deepcopy(variant_good)
        calibrated["records"] = [copy.deepcopy(template_row) for _ in range(17)]
        for root_obj in calibrated["roots"].values():
            root_obj["records"] = 0
        calibrated["roots"][template_row["role"]]["records"] = len(calibrated["records"])

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # Measure exact canonical size with omitted egl_metadata and adjust record paths within 4096 cap
            probe_dest = root / "probe.json"
            probe_payload = copy.deepcopy(calibrated)
            probe_payload["egl_metadata"] = {
                "schema": EGL_SCHEMA,
                "status": "omitted",
                "reason": "output-bound",
            }
            with patch(
                "rs9.nix_gui_discovery.subprocess.run",
                return_value=CompletedProcess(
                    [], 0, json.dumps(probe_payload).encode("utf-8"), b""
                ),
            ):
                record_fhs_gui_discovery(
                    facts,
                    [],
                    [],
                    {},
                    probe_dest,
                    current_linux_egl_metadata=True,
                )
            current_custody_size = probe_dest.stat().st_size
            delta = (65536 - 120) - current_custody_size
            self.assertGreater(delta, 0)
            for idx in range(4):
                add = min(900, delta)
                if add <= 0:
                    break
                calibrated["records"][idx]["path"] = "libexec/" + ("a" * (base_pad + add))
                delta -= add
            self.assertEqual(delta, 0)
            _validate_observation(
                {k: v for k, v in calibrated.items() if k != "egl_metadata"}
            )

            custody_near_dest = root / "custody-near.json"
            with patch(
                "rs9.nix_gui_discovery.subprocess.run",
                return_value=CompletedProcess(
                    [], 0, json.dumps(calibrated).encode("utf-8"), b""
                ),
            ):
                near_rec = record_fhs_gui_discovery(
                    facts,
                    [],
                    [],
                    {},
                    custody_near_dest,
                    current_linux_egl_metadata=True,
                )
            self.assertLessEqual(custody_near_dest.stat().st_size, 65536)
            self.assertGreater(custody_near_dest.stat().st_size, 65536 - 250)
            self.assertEqual(
                near_rec["egl_metadata"],
                {
                    "schema": EGL_SCHEMA,
                    "status": "omitted",
                    "reason": "custody-bound",
                },
            )
            self.assertEqual(len(near_rec["result"]["records"]), 17)
            self.assertEqual(
                near_rec["result"]["truncated"]["reason"], "category-pruned"
            )
            self.assertEqual(
                diagnostic_bytes(custody_near_dest), custody_near_dest.read_bytes()
            )

            # Part B: when old records exceed 64 KiB even after shedding egl_metadata,
            # halving runs unchanged and produces the same reduced result as without EGL.
            huge_default = copy.deepcopy(default_good)
            huge_row = copy.deepcopy(template_row)
            huge_row["path"] = "libexec/" + ("x" * 4000)
            huge_default["records"] = [huge_row] * 960
            for root_obj in huge_default["roots"].values():
                root_obj["records"] = 0
            huge_default["roots"][huge_row["role"]]["records"] = 960
            huge_variant = copy.deepcopy(huge_default)
            huge_variant["egl_metadata"] = copy.deepcopy(variant_good["egl_metadata"])

            dest_no_egl = root / "huge-no-egl.json"
            dest_with_egl = root / "huge-with-egl.json"
            with patch(
                "rs9.nix_gui_discovery.subprocess.run",
                return_value=CompletedProcess(
                    [],
                    0,
                    json.dumps(huge_default, separators=(",", ":")).encode("utf-8"),
                    b"",
                ),
            ):
                rec_no_egl = record_fhs_gui_discovery(
                    facts, [], [], {}, dest_no_egl
                )
            with patch(
                "rs9.nix_gui_discovery.subprocess.run",
                return_value=CompletedProcess(
                    [],
                    0,
                    json.dumps(huge_variant, separators=(",", ":")).encode("utf-8"),
                    b"",
                ),
            ):
                rec_with_egl = record_fhs_gui_discovery(
                    facts,
                    [],
                    [],
                    {},
                    dest_with_egl,
                    current_linux_egl_metadata=True,
                )
            self.assertLessEqual(dest_with_egl.stat().st_size, 65536)
            self.assertEqual(
                rec_with_egl["egl_metadata"],
                {
                    "schema": EGL_SCHEMA,
                    "status": "omitted",
                    "reason": "custody-bound",
                },
            )
            self.assertEqual(rec_with_egl["status"], "partial")
            self.assertEqual(rec_with_egl["result"], rec_no_egl["result"])
            self.assertEqual(
                diagnostic_bytes(dest_with_egl), dest_with_egl.read_bytes()
            )

    def test_hosted_nix_caller_eligibility_and_prepare_input_gate(self):
        for system in ("x86_64-linux", "aarch64-linux"):
            self.assertTrue(
                hosted_nix._current_linux_lane(CURRENT_GENERATION, system)
            )
            self.assertFalse(
                hosted_nix._current_linux_lane(HISTORICAL_GENERATION, system)
            )
        self.assertFalse(
            hosted_nix._current_linux_lane(CURRENT_GENERATION, "aarch64-darwin")
        )

        # Verify unpatched prepare_input and bind_catalog_product reject incomplete,
        # unauthenticated, or coordinate-mismatched current captures before execute
        # ever reaches record_fhs_gui_discovery.
        from tests.test_current_smoke_source_transport import CurrentSourceTransportTests

        fixture = CurrentSourceTransportTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        authenticated_capture = fixture.prepared["capture"]

        with tempfile.TemporaryDirectory() as td:
            scratch = Path(td) / "scratch"
            scratch.mkdir()
            runner_temp = Path(td) / "runner_temp"
            install_dir = runner_temp / "rs9-nix-install"
            install_dir.mkdir(parents=True)
            pin_val = "d1f67c86eed016214864ba08bfb9529c307aea7e8fafb74853f96fcc3bfd8a60"
            (install_dir / "installer-identity.json").write_bytes(
                canonical(
                    {
                        "version": "2.31.2",
                        "system": "x86_64-linux",
                        "sha256": pin_val,
                        "pin_provenance": "source-pinned",
                        "status": "pass",
                    }
                )
            )
            base_context = {
                "generation": CURRENT_GENERATION,
                "system": "x86_64-linux",
                "repository": Path(__file__).resolve().parents[1],
                "scratch": scratch,
                "pins": {
                    "nix": {
                        "installer_version": "2.31.2",
                        "installer_sha256_by_system": {
                            "aarch64-darwin": "3baa0af88a1ef4e2cc82cb64cd384b1805ecc3771b574e97277ae213d52711d8",
                            "x86_64-linux": pin_val,
                            "aarch64-linux": "64db528412096d718b4bf8f78f85e5ac2b714b774e5005500dee37d23f560456",
                        },
                        "nixpkgs_revision": "0" * 40,
                        "nixpkgs_nar_hash": "sha256-hash",
                    }
                },
                "client": Mock(),
            }
            unauthenticated_captures = [
                (
                    Mock(),
                    {"project": {"id": pid, "repository": f"theme-forge/{pid}"}},
                    {},
                )
                for pid in hosted_nix.PRODUCTS
            ]
            mismatched_catalog_captures = [
                (
                    authenticated_capture,
                    {
                        "project": {
                            "id": pid,
                            "repository": authenticated_capture.record["repository"][
                                "full_name"
                            ],
                        },
                        "version": "0.0.0-mismatch",
                        "tag": "v0.0.0-mismatch",
                        "commands": [],
                    },
                    {},
                )
                for pid in hosted_nix.PRODUCTS
            ]
            for label, captures, expected_code in (
                ("incomplete-captures", [], "NIX_CAPTURE"),
                ("unauthenticated-capture", unauthenticated_captures, "RELEASE_CAPTURE"),
                (
                    "catalog-coordinate-mismatch",
                    mismatched_catalog_captures,
                    "NIX_CATALOG_BINDING",
                ),
            ):
                with self.subTest(case=label), patch.dict(
                    os.environ, {"RUNNER_TEMP": str(runner_temp)}
                ), patch("rs9.hosted_nix.record_fhs_gui_discovery") as discover:
                    with self.assertRaises(ContractError) as caught:
                        hosted_nix.execute({**base_context, "captures": captures})
                self.assertEqual(caught.exception.code, expected_code)
                discover.assert_not_called()


if __name__ == "__main__":
    unittest.main()
