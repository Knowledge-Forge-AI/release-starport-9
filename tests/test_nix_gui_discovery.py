"""Pure Node fs-double coverage for the bounded Nix GUI discovery script."""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import unittest

from rs9.nix_gui_discovery import (
    NODE_FS_SOURCE,
    SCHEMA,
    _discovery_request,
    _validate_observation,
)


ROLES = ("glib", "gtk", "webkit", "pixbuf")
CATEGORIES = [
    "helper", "libexec", "gio-module", "gsettings-schema",
    "pixbuf-loader", "font", "data",
]


def _facts(*, character="a", max_entries=4096, max_bytes=64 * 1024 * 1024):
    roots = {
        role: "/nix/store/" + character * 32 + "-" + role for role in ROLES
    }
    closure = list(roots.values()) + [
        "/nix/store/" + character * 31 + "b-dependency",
    ]
    return {
        "node": "/nix/store/" + character * 32 + "-node/bin/node",
        "gui_discovery": {
            "schema": "rs9.nix-fhs-gui-discovery.v1",
            "roots": roots,
            "closure_roots": closure,
            "max_entries": max_entries,
            "max_bytes": max_bytes,
            "max_file_bytes": 4 * 1024 * 1024,
            "max_symlink_hops": 16,
            "categories": CATEGORIES,
        },
    }


def _entry(kind, *, data="", mode=0o755, target=None, size=None, ino=1, tick=1):
    return {
        "kind": kind, "data": data, "mode": mode, "target": target,
        "size": len(data) if size is None else size, "ino": ino, "tick": tick,
    }


def _fixture_model(facts, *, cycle=False, escape=False, unstable=False, missing=None):
    roots = facts["gui_discovery"]["roots"]
    dependency = facts["gui_discovery"]["closure_roots"][-1]
    model = {}
    serial = 1

    def add(path, value):
        nonlocal serial
        value = dict(value)
        value.setdefault("ino", serial)
        serial += 1
        model[path] = value

    for role, root in roots.items():
        if role == missing:
            continue
        add(root, _entry("dir", mode=0o755))
    glib = roots["glib"]
    add(glib + "/libexec", _entry("dir", mode=0o755))
    add(glib + "/libexec/helper", _entry("file", data="helper", mode=0o755))
    add(glib + "/lib", _entry("dir", mode=0o755))
    add(glib + "/lib/webkit", _entry("dir", mode=0o755))
    add(glib + "/lib/webkit/libwebkitgtk-4.1.so", _entry(
        "file", data="", mode=0o755, size=8 * 1024 * 1024))
    add(glib + "/lib/gio", _entry("dir", mode=0o755))
    add(glib + "/lib/gio/modules", _entry("dir", mode=0o755))
    add(glib + "/lib/gio/modules/module.so", _entry("file", data="gio", mode=0o644))
    add(glib + "/share", _entry("dir", mode=0o755))
    add(glib + "/share/locale", _entry("dir", mode=0o755))
    # This is intentionally larger than max_file_bytes but uncategorized as a
    # regular data file; discovery must not read/hash broad locale trees.
    add(glib + "/share/locale/messages.mo", _entry(
        "file", data="", mode=0o644, size=8 * 1024 * 1024))
    target = dependency + "/libexec/helper-target"
    add(dependency, _entry("dir", mode=0o755))
    add(dependency + "/libexec", _entry("dir", mode=0o755))
    add(target, _entry("file", data="target", mode=0o755))
    if cycle:
        add(glib + "/libexec/a", _entry("link", target="b"))
        add(glib + "/libexec/b", _entry("link", target="a"))
    elif escape:
        add(glib + "/libexec/escape", _entry(
            "link", target="/nix/store/" + "c" * 32 + "-outside/libexec/helper"))
    else:
        add(glib + "/libexec/alias", _entry("link", target=target))
    if unstable:
        model[glib + "/libexec/helper"]["unstable"] = True
    return model


def _run_script(request, model, *, stat_times=None):
    node = shutil.which("node")
    if node is None:
        raise unittest.SkipTest("qualified Node executable unavailable")
    source = json.dumps(NODE_FS_SOURCE)
    request_json = json.dumps(request)
    model_json = json.dumps(model)
    wrapper = f"""
const vm = require('node:vm');
const path = require('node:path');
const crypto = require('node:crypto');
const request = {request_json};
const model = {model_json};
const opened = new Map();
function statFor(name) {{
  const value = model[name];
  if (!value) {{ const error = new Error('missing'); error.code = 'ENOENT'; throw error; }}
  const reads = opened.get(name);
  const tick = BigInt(value.tick) + (value.unstable && reads !== undefined ? BigInt(reads) : 0n);
  const times = {stat_times or "{mtimeNs: tick, ctimeNs: tick}"};
  return {{dev: 1n, ino: BigInt(value.ino), size: BigInt(value.size), mode: BigInt(value.mode),
    ...times, uid: 501n, gid: 0n, nlink: 1n,
    isDirectory: () => value.kind === 'dir', isFile: () => value.kind === 'file',
    isSymbolicLink: () => value.kind === 'link'}};
}}
function dirents(name) {{
  const prefix = name.endsWith('/') ? name : name + '/';
  const values = new Map();
  for (const key of Object.keys(model)) {{
    if (!key.startsWith(prefix)) continue;
    const tail = key.slice(prefix.length);
    if (!tail || tail.includes('/')) continue;
    values.set(tail, model[key]);
  }}
  return [...values.entries()].map(([entry, value]) => ({{name: entry,
    isDirectory: () => value.kind === 'dir', isFile: () => value.kind === 'file',
    isSymbolicLink: () => value.kind === 'link'}}));
}}
const fs = {{
  constants: {{O_RDONLY: 1, O_NOFOLLOW: 2, O_NONBLOCK: 4}},
  lstatSync: (name) => statFor(name),
  fstatSync: (fd) => {{ const value = statFor(fd); if (opened.has(fd)) opened.set(fd, opened.get(fd) + 1); return value; }},
  readdirSync: (name) => dirents(name), readlinkSync: (name) => model[name].target,
  readFileSync: (fd, encoding) => fd === 0 ? JSON.stringify(request) : model[fd].data,
  openSync: (name) => {{ opened.set(name, 0); return name; }},
  readSync: (fd, buffer, offset, length, position) => {{
    const bytes = Buffer.from(model[fd].data || '');
    if (position >= bytes.length) return 0;
    const count = Math.min(length, bytes.length - position);
    bytes.copy(buffer, offset, position, position + count);
    return count;
  }},
  closeSync: () => undefined,
}};
let output = '';
const context = {{Buffer, __RS9_FS_DOUBLE__: {{fs, path, crypto, output: {{write: (value) => {{ output += value; }}}}}}}};
vm.runInNewContext({source}, context);
process.stdout.write(output);
"""
    completed = subprocess.run([node, "--input-type=commonjs"],
                               input=wrapper.encode(), capture_output=True, timeout=10)
    if completed.returncode != 0:
        raise AssertionError(completed.stderr.decode("utf-8", "replace"))
    return json.loads(completed.stdout)


class NixGuiDiscoveryNodeTests(unittest.TestCase):
    def test_selected_members_and_large_uncategorized_files(self):
        facts = _facts()
        request = _discovery_request(facts)
        result = _run_script(request, _fixture_model(facts))
        self.assertEqual(result["schema"], SCHEMA)
        self.assertEqual(result["status"], "pass")
        paths = [record["path"] for record in result["records"]]
        self.assertIn("libexec/helper", paths)
        self.assertIn("lib/gio/modules/module.so", paths)
        self.assertNotIn("lib/webkit/libwebkitgtk-4.1.so", paths)
        self.assertNotIn("share/locale/messages.mo", paths)
        self.assertEqual(result["totals"]["read_bytes"], len("helper") + len("gio"))

    def test_bounds_retain_typed_partial_facts(self):
        facts = _facts(max_bytes=1)
        result = _run_script(_discovery_request(facts), _fixture_model(facts))
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["truncated"]["reason"], "read-byte-bound")
        self.assertTrue(any(record.get("reason") == "read-byte-bound"
                            for record in result["records"]))
        _validate_observation(result)

    def test_missing_cycle_escape_and_unstable_inputs_fail_closed(self):
        for name, kwargs, reason in (
            ("missing", {"missing": "pixbuf"}, "root-missing"),
            ("cycle", {"cycle": True}, "symlink-cycle"),
            ("escape", {"escape": True}, "symlink-closure-escape"),
            ("unstable", {"unstable": True}, "file-changed"),
        ):
            with self.subTest(name=name):
                facts = _facts()
                result = _run_script(_discovery_request(facts), _fixture_model(facts, **kwargs))
                self.assertEqual(result["status"], "fail")
                self.assertEqual(result["reason"], reason)

    def test_script_has_no_environment_network_or_child_execution_surface(self):
        for forbidden in ("child_process", "process.env", "node:net", "node:http",
                          "node:dns", "fetch("):
            self.assertNotIn(forbidden, NODE_FS_SOURCE)
        self.assertIn("__RS9_FS_DOUBLE__", NODE_FS_SOURCE)
        self.assertIn("node:fs", NODE_FS_SOURCE)
        self.assertIn("node:crypto", NODE_FS_SOURCE)

    def test_modern_ns_are_exact_and_submillisecond_change_refuses(self):
        facts = _facts(); request = _discovery_request(facts)
        model = _fixture_model(facts)
        for value in model.values(): value["tick"] = "1700000000000123456"
        result = _run_script(request, model)
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["roots"]["glib"]["full9"]["ctimeNs"], "1700000000000123456")
        _validate_observation(result)
        model[facts["gui_discovery"]["roots"]["glib"] + "/libexec/helper"]["unstable"] = True
        result = _run_script(request, model)
        self.assertEqual(result["reason"], "file-changed")

    def test_timestamp_fallback_and_malformed_out_of_range_refuse(self):
        facts = _facts(); request = _discovery_request(facts); model = _fixture_model(facts)
        result = _run_script(request, model, stat_times="{mtimeMs:1700000000000.125,ctimeMs:1700000000000.125}")
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["roots"]["glib"]["full9"]["mtimeNs"], "1700000000000125000")
        for expression in ("{mtimeNs:NaN,ctimeNs:1n}", "{mtimeNs:-1n,ctimeNs:1n}",
                "{mtimeNs:9223372036854775808n,ctimeNs:1n}", "{mtimeNs:'1',ctimeNs:1n}",
                "{mtimeMs:Infinity,ctimeMs:0}", "{mtimeMs:1e20,ctimeMs:0}"):
            with self.subTest(expression=expression):
                result = _run_script(request, model, stat_times=expression)
                self.assertEqual(result["status"], "fail")
                self.assertEqual(result["reason"], "invalid-stat-time")

    def test_output_bound_is_partial_and_dropped_record_counts_are_zero(self):
        facts = _facts(); request = _discovery_request(facts); model = _fixture_model(facts)
        root = facts["gui_discovery"]["roots"]["glib"]
        target = facts["gui_discovery"]["closure_roots"][-1] + "/libexec/helper-target"
        for index in range(3000):
            model[root + "/libexec/" + str(index).zfill(4) + "x" * 400] = _entry("link", target=target)
        result = _run_script(request, model)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["truncated"]["reason"], "output-bound")
        self.assertEqual(result["records"], [])
        self.assertTrue(all(row["records"] == 0 for row in result["roots"].values()))
        _validate_observation(result)

    def test_optional_output_failure_is_contained_and_does_not_follow_links(self):
        from rs9.nix_gui_discovery import record_fhs_gui_discovery
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = record_fhs_gui_discovery({}, [], [], {}, root / "absent/output.json")
            self.assertEqual(result["reason"], "diagnostic-output-unavailable")
            outside = root / "outside.json"; outside.write_text("original")
            alias = root / "alias.json"; alias.symlink_to(outside)
            result = record_fhs_gui_discovery({}, [], [], {}, alias)
            self.assertEqual(result["reason"], "diagnostic-output-unavailable")
            self.assertEqual(outside.read_text(), "original")

    def test_canonical_envelope_size_bound_retains_typed_partial(self):
        from subprocess import CompletedProcess
        from unittest.mock import patch
        from rs9.nix_gui_discovery import record_fhs_gui_discovery
        import copy
        import tempfile
        facts=_facts();good=_run_script(_discovery_request(facts),_fixture_model(facts))
        row=copy.deepcopy(next(x for x in good['records'] if x['type']=='directory'))
        row['path']='libexec/'+'x'*4000
        good['records']=[row]*960
        for root in good['roots'].values():root['records']=0
        good['roots'][row['role']]['records']=960
        raw=json.dumps(good,separators=(',',':')).encode()
        self.assertLess(len(raw),4*1024*1024)
        with tempfile.TemporaryDirectory() as tmp, patch('rs9.nix_gui_discovery.subprocess.run',
                return_value=CompletedProcess([],0,raw,b'')):
            destination=Path(tmp)/'diagnostic.json'
            result=record_fhs_gui_discovery(facts,[],[],{},destination)
            self.assertEqual(result['status'],'partial')
            self.assertEqual(result['result']['truncated']['reason'],'output-bound')
            self.assertLess(len(result['result']['records']),960)
            self.assertLessEqual(destination.stat().st_size,64*1024)
            from rs9.hosted_custody import diagnostic_bytes
            self.assertEqual(diagnostic_bytes(destination),destination.read_bytes())

    def test_existing_custody_privacy_rejection_becomes_safe_optional_record(self):
        from subprocess import CompletedProcess
        from unittest.mock import patch
        from rs9.nix_gui_discovery import record_fhs_gui_discovery
        from rs9.hosted_custody import diagnostic_bytes
        import tempfile
        facts=_facts();good=_run_script(_discovery_request(facts),_fixture_model(facts))
        # A relative name passes the producer's structural validator but the
        # established custody policy must still reject this private-path form.
        good['records'][0]['path']='libexec/private/synthetic-name'
        with tempfile.TemporaryDirectory() as tmp, patch('rs9.nix_gui_discovery.subprocess.run',
                return_value=CompletedProcess([],0,json.dumps(good).encode(),b'')):
            destination=Path(tmp)/'diagnostic.json'
            result=record_fhs_gui_discovery(facts,[],[],{},destination)
            self.assertEqual(result['reason'],'diagnostic-custody-withheld')
            self.assertEqual(result['custody_reason'],'PRIVATE_PATH')
            data=diagnostic_bytes(destination)
            self.assertNotIn(b'libexec/private',data)
            self.assertFalse(list(Path(tmp).glob('.rs9-gui-discovery-*')))

    def test_malformed_record_is_typed_failure_and_never_escapes(self):
        from subprocess import CompletedProcess
        from unittest.mock import patch
        from rs9.nix_gui_discovery import record_fhs_gui_discovery
        import copy
        import tempfile
        facts=_facts();good=_run_script(_discovery_request(facts),_fixture_model(facts))
        values=[]
        missing=copy.deepcopy(good);missing['records'][0].pop('type');missing['records'][0]['extra']=True;values.append(missing)
        for categories in ([{}], ['helper',{}], [1,'helper']):
            value=copy.deepcopy(good);value['records'][0]['categories']=categories;values.append(value)
        with tempfile.TemporaryDirectory() as tmp:
            for value in values:
                with self.subTest(value=value['records'][0].get('categories')), patch(
                        'rs9.nix_gui_discovery.subprocess.run',return_value=CompletedProcess([],0,json.dumps(value).encode(),b'')):
                    result=record_fhs_gui_discovery(facts,[],[],{},Path(tmp)/'diagnostic.json')
                self.assertEqual(result['status'],'fail')
                self.assertEqual(result['reason'],'bounded-observation-unavailable')

    def test_python_validator_rejects_malformed_or_private_metadata(self):
        with self.assertRaises(ValueError):
            _validate_observation({"schema": SCHEMA, "status": "pass", "records": []})
        with self.assertRaises(ValueError):
            _validate_observation({"schema": SCHEMA, "status": "fail",
                                   "reason": "ok", "token": "forbidden"})


if __name__ == "__main__":
    unittest.main()
