"""Focused adversarial and contract tests for bounded fail-closed guest D-Bus config audit repair (CONT20).

All test fixtures here are synthetic unit fixtures; they make no native qualification claims.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

from rs9.nix_proot_dbus import (
    DBUS_AUDIT_SOURCE,
    DBUS_SESSION_CONFIG_SHA256,
    audit_dbus_config,
)

# Exact 3,561-byte fixture, verified against the run-18 digest on both architectures.
REAL_PINNED_SESSION_CONF_BYTES = base64.b64decode(
    'PCEtLSBUaGlzIGNvbmZpZ3VyYXRpb24gZmlsZSBjb250cm9scyB0aGUgcGVyLXVzZXItbG9naW4tc2Vzc2lvbiBtZXNzYWdlIGJ1cy4KICAgICBBZGQgYSBz'
    'ZXNzaW9uLWxvY2FsLmNvbmYgYW5kIGVkaXQgdGhhdCByYXRoZXIgdGhhbiBjaGFuZ2luZyB0aGlzIAogICAgIGZpbGUgZGlyZWN0bHkuIC0tPgoKPCFET0NU'
    'WVBFIGJ1c2NvbmZpZyBQVUJMSUMgIi0vL2ZyZWVkZXNrdG9wLy9EVEQgRC1CdXMgQnVzIENvbmZpZ3VyYXRpb24gMS4wLy9FTiIKICJodHRwOi8vd3d3LmZy'
    'ZWVkZXNrdG9wLm9yZy9zdGFuZGFyZHMvZGJ1cy8xLjAvYnVzY29uZmlnLmR0ZCI+CjxidXNjb25maWc+CiAgPCEtLSBPdXIgd2VsbC1rbm93biBidXMgdHlw'
    'ZSwgZG9uJ3QgY2hhbmdlIHRoaXMgLS0+CiAgPHR5cGU+c2Vzc2lvbjwvdHlwZT4KCiAgPCEtLSBJZiB3ZSBmb3JrLCBrZWVwIHRoZSB1c2VyJ3Mgb3JpZ2lu'
    'YWwgdW1hc2sgdG8gYXZvaWQgYWZmZWN0aW5nCiAgICAgICB0aGUgYmVoYXZpb3Igb2YgY2hpbGQgcHJvY2Vzc2VzLiAtLT4KICA8a2VlcF91bWFzay8+Cgog'
    'IDxsaXN0ZW4+dW5peDp0bXBkaXI9L3RtcDwvbGlzdGVuPgoKICA8IS0tIE9uIFVuaXggc3lzdGVtcywgdGhlIG1vc3Qgc2VjdXJlIGF1dGhlbnRpY2F0aW9u'
    'IG1lY2hhbmlzbSBpcwogIEVYVEVSTkFMLCB3aGljaCB1c2VzIGNyZWRlbnRpYWwtcGFzc2luZyBvdmVyIFVuaXggc29ja2V0cy4KCiAgVGhpcyBhdXRoZW50'
    'aWNhdGlvbiBtZWNoYW5pc20gaXMgbm90IGF2YWlsYWJsZSBvbiBXaW5kb3dzLAogIGlzIG5vdCBzdWl0YWJsZSBmb3IgdXNlIHdpdGggdGhlIHRjcDogb3Ig'
    'bm9uY2UtdGNwOiB0cmFuc3BvcnRzLAogIGFuZCB3aWxsIG5vdCB3b3JrIG9uIG9ic2N1cmUgZmxhdm91cnMgb2YgVW5peCB0aGF0IGRvIG5vdCBoYXZlCiAg'
    'YSBzdXBwb3J0ZWQgY3JlZGVudGlhbHMtcGFzc2luZyBtZWNoYW5pc20uIE9uIHRob3NlIHBsYXRmb3Jtcy90cmFuc3BvcnRzLAogIGNvbW1lbnQgb3V0IHRo'
    'ZSA8YXV0aD4gZWxlbWVudCB0byBhbGxvdyBmYWxsYmFjayB0byBEQlVTX0NPT0tJRV9TSEExLiAtLT4KICA8YXV0aD5FWFRFUk5BTDwvYXV0aD4KCiAgPHN0'
    'YW5kYXJkX3Nlc3Npb25fc2VydmljZWRpcnMgLz4KCiAgPHBvbGljeSBjb250ZXh0PSJkZWZhdWx0Ij4KICAgIDwhLS0gQWxsb3cgZXZlcnl0aGluZyB0byBi'
    'ZSBzZW50IC0tPgogICAgPGFsbG93IHNlbmRfZGVzdGluYXRpb249IioiIGVhdmVzZHJvcD0idHJ1ZSIvPgogICAgPCEtLSBBbGxvdyBldmVyeXRoaW5nIHRv'
    'IGJlIHJlY2VpdmVkIC0tPgogICAgPGFsbG93IGVhdmVzZHJvcD0idHJ1ZSIvPgogICAgPCEtLSBBbGxvdyBhbnlvbmUgdG8gb3duIGFueXRoaW5nIC0tPgog'
    'ICAgPGFsbG93IG93bj0iKiIvPgogIDwvcG9saWN5PgoKICA8IS0tIEluY2x1ZGUgbGVnYWN5IGNvbmZpZ3VyYXRpb24gbG9jYXRpb24gLS0+CiAgPGluY2x1'
    'ZGUgaWdub3JlX21pc3Npbmc9InllcyI+L2V0Yy9kYnVzLTEvc2Vzc2lvbi5jb25mPC9pbmNsdWRlPgoKICA8IS0tIENvbmZpZyBmaWxlcyBhcmUgcGxhY2Vk'
    'IGhlcmUgdGhhdCBhbW9uZyBvdGhlciB0aGluZ3MsIAogICAgICAgZnVydGhlciByZXN0cmljdCB0aGUgYWJvdmUgcG9saWN5IGZvciBzcGVjaWZpYyBzZXJ2'
    'aWNlcy4gLS0+CiAgPGluY2x1ZGVkaXI+c2Vzc2lvbi5kPC9pbmNsdWRlZGlyPgoKICA8aW5jbHVkZWRpcj4vZXRjL2RidXMtMS9zZXNzaW9uLmQ8L2luY2x1'
    'ZGVkaXI+CgogIDwhLS0gVGhpcyBpcyBpbmNsdWRlZCBsYXN0IHNvIGxvY2FsIGNvbmZpZ3VyYXRpb24gY2FuIG92ZXJyaWRlIHdoYXQncyAKICAgICAgIGlu'
    'IHRoaXMgc3RhbmRhcmQgZmlsZSAtLT4KICA8aW5jbHVkZSBpZ25vcmVfbWlzc2luZz0ieWVzIj4vZXRjL2RidXMtMS9zZXNzaW9uLWxvY2FsLmNvbmY8L2lu'
    'Y2x1ZGU+CgogIDxpbmNsdWRlIGlmX3NlbGludXhfZW5hYmxlZD0ieWVzIiBzZWxpbnV4X3Jvb3RfcmVsYXRpdmU9InllcyI+Y29udGV4dHMvZGJ1c19jb250'
    'ZXh0czwvaW5jbHVkZT4KCiAgPCEtLSBGb3IgdGhlIHNlc3Npb24gYnVzLCBvdmVycmlkZSB0aGUgZGVmYXVsdCByZWxhdGl2ZWx5LWxvdyBsaW1pdHMgCiAg'
    'ICAgICB3aXRoIGVzc2VudGlhbGx5IGluZmluaXRlIGxpbWl0cywgc2luY2UgdGhlIGJ1cyBpcyBqdXN0IHJ1bm5pbmcgCiAgICAgICBhcyB0aGUgdXNlciBh'
    'bnl3YXksIHVzaW5nIHVwIGJ1cyByZXNvdXJjZXMgaXMgbm90IHNvbWV0aGluZyB3ZSBuZWVkIAogICAgICAgdG8gd29ycnkgYWJvdXQuIEluIHNvbWUgY2Fz'
    'ZXMsIHdlIGRvIHNldCB0aGUgbGltaXRzIGxvd2VyIHRoYW4gCiAgICAgICAiYWxsIGF2YWlsYWJsZSBtZW1vcnkiIGlmIGV4Y2VlZGluZyB0aGUgbGltaXQg'
    'aXMgYWxtb3N0IGNlcnRhaW5seSBhIGJ1ZywgCiAgICAgICBoYXZpbmcgdGhlIGJ1cyBlbmZvcmNlIGEgbGltaXQgaXMgbmljZXIgdGhhbiBhIGh1Z2UgbWVt'
    'b3J5IGxlYWsuIEJ1dCB0aGUgCiAgICAgICBpbnRlbnQgaXMgdGhhdCB0aGVzZSBsaW1pdHMgc2hvdWxkIG5ldmVyIGJlIGhpdC4gLS0+CgogIDwhLS0gdGhl'
    'IG1lbW9yeSBsaW1pdHMgYXJlIDFHIGluc3RlYWQgb2Ygc2F5IDRHIGJlY2F1c2UgdGhleSBjYW4ndCBleGNlZWQgMzItYml0IHNpZ25lZCBpbnQgbWF4IC0t'
    'PgogIDxsaW1pdCBuYW1lPSJtYXhfaW5jb21pbmdfYnl0ZXMiPjEwMDAwMDAwMDA8L2xpbWl0PgogIDxsaW1pdCBuYW1lPSJtYXhfaW5jb21pbmdfdW5peF9m'
    'ZHMiPjI1MDAwMDAwMDwvbGltaXQ+CiAgPGxpbWl0IG5hbWU9Im1heF9vdXRnb2luZ19ieXRlcyI+MTAwMDAwMDAwMDwvbGltaXQ+CiAgPGxpbWl0IG5hbWU9'
    'Im1heF9vdXRnb2luZ191bml4X2ZkcyI+MjUwMDAwMDAwPC9saW1pdD4KICA8bGltaXQgbmFtZT0ibWF4X21lc3NhZ2Vfc2l6ZSI+MTAwMDAwMDAwMDwvbGlt'
    'aXQ+CiAgPCEtLSBXZSBkbyBub3Qgb3ZlcnJpZGUgbWF4X21lc3NhZ2VfdW5peF9mZHMgaGVyZSBzaW5jZSB0aGUgaW4ta2VybmVsCiAgICAgICBsaW1pdCBp'
    'cyBhbHNvIHJlbGF0aXZlbHkgbG93IC0tPgogIDxsaW1pdCBuYW1lPSJzZXJ2aWNlX3N0YXJ0X3RpbWVvdXQiPjEyMDAwMDwvbGltaXQ+ICAKICA8bGltaXQg'
    'bmFtZT0iYXV0aF90aW1lb3V0Ij4yNDAwMDA8L2xpbWl0PgogIDxsaW1pdCBuYW1lPSJwZW5kaW5nX2ZkX3RpbWVvdXQiPjE1MDAwMDwvbGltaXQ+CiAgPGxp'
    'bWl0IG5hbWU9Im1heF9jb21wbGV0ZWRfY29ubmVjdGlvbnMiPjEwMDAwMDwvbGltaXQ+ICAKICA8bGltaXQgbmFtZT0ibWF4X2luY29tcGxldGVfY29ubmVj'
    'dGlvbnMiPjEwMDAwPC9saW1pdD4KICA8bGltaXQgbmFtZT0ibWF4X2Nvbm5lY3Rpb25zX3Blcl91c2VyIj4xMDAwMDA8L2xpbWl0PgogIDxsaW1pdCBuYW1l'
    'PSJtYXhfcGVuZGluZ19zZXJ2aWNlX3N0YXJ0cyI+MTAwMDA8L2xpbWl0PgogIDxsaW1pdCBuYW1lPSJtYXhfbmFtZXNfcGVyX2Nvbm5lY3Rpb24iPjUwMDAw'
    'PC9saW1pdD4KICA8bGltaXQgbmFtZT0ibWF4X21hdGNoX3J1bGVzX3Blcl9jb25uZWN0aW9uIj41MDAwMDwvbGltaXQ+CiAgPGxpbWl0IG5hbWU9Im1heF9y'
    'ZXBsaWVzX3Blcl9jb25uZWN0aW9uIj41MDAwMDwvbGltaXQ+Cgo8L2J1c2NvbmZpZz4K'
)

class DBusConfigAuditCont20Tests(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.base = Path(self._tmp.name).resolve()
        self.dbus_store = "/nix/store/" + "d" * 32 + "-dbus-1.14.10"
        self.closure = [self.dbus_store]
        self.session_conf_store = self.dbus_store + "/share/dbus-1/session.conf"
        self.dbus_daemon_store = self.dbus_store + "/bin/dbus-daemon"
        Path(self.host("/etc")).mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        self._tmp.cleanup()

    def host(self, path):
        path = str(path)
        return path if path.startswith(str(self.base)) else str(self.base / path.lstrip("/"))

    def guest(self, path):
        path = str(path)
        return path[len(str(self.base)):] if path.startswith(str(self.base)) else path

    def write_file(self, path, content, mode=0o644):
        target = Path(self.host(path))
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, str):
            target.write_text(content, encoding="utf-8")
        else:
            target.write_bytes(content)
        target.chmod(mode)

    def symlink(self, target, link_path):
        lp = Path(self.host(link_path))
        lp.parent.mkdir(parents=True, exist_ok=True)
        lp.symlink_to(self.host(target))

    def setup_daemon(self):
        self.write_file(self.dbus_daemon_store, b"#!/bin/sh\nexit 0\n", 0o755)

    def run_audit(self, spec=None, _expected_sha256=None):
        if spec is None:
            spec = {
                "closure": self.closure,
                "dbus_session_config": self.session_conf_store,
                "dbus_daemon": self.dbus_daemon_store,
            }
        originals = {
            k: getattr(os.path, k)
            for k in ("exists", "isfile", "isdir", "islink", "realpath", "lexists")
        }
        orig_stat = os.stat
        orig_lstat = os.lstat
        orig_scandir = os.scandir
        which = shutil.which
        open_file = open
        open_fd = os.open

        def resolve_daemon(cmd, path=None):
            if cmd == "dbus-daemon":
                target = Path(self.host(self.dbus_daemon_store))
                return self.guest(str(target)) if target.exists() else None
            return which(cmd, path=path)

        with patch("os.path.exists", side_effect=lambda p: originals["exists"](self.host(p))), \
                patch("os.path.lexists", side_effect=lambda p: originals["lexists"](self.host(p))), \
                patch("os.path.isfile", side_effect=lambda p: originals["isfile"](self.host(p))), \
                patch("os.path.isdir", side_effect=lambda p: originals["isdir"](self.host(p))), \
                patch("os.path.islink", side_effect=lambda p: originals["islink"](self.host(p))), \
                patch("os.path.realpath", side_effect=lambda p: self.guest(originals["realpath"](self.host(p)))), \
                patch("os.stat", side_effect=lambda p, *a, **k: orig_stat(self.host(p), *a, **k)), \
                patch("os.lstat", side_effect=lambda p, *a, **k: orig_lstat(self.host(p), *a, **k)), \
                patch("os.scandir", side_effect=lambda p: orig_scandir(self.host(p))), \
                patch("os.open", side_effect=lambda p, *a, **k: open_fd(self.host(p), *a, **k)), \
                patch("shutil.which", side_effect=resolve_daemon), \
                patch("builtins.open", side_effect=lambda p, *a, **k: open_file(self.host(p), *a, **k)):
            # Fixture digest changes exist only in the test-compiled namespace.
            namespace = {}
            exec(compile(DBUS_AUDIT_SOURCE, 'fixture-audit', 'exec'), namespace)
            if _expected_sha256 is not None:
                namespace['DBUS_SESSION_CONFIG_SHA256'] = _expected_sha256
            return namespace['audit_dbus_config'](spec)

    def test_cycle_direct_self_include(self):
        self.setup_daemon()
        xml = f'<busconfig><include>{self.session_conf_store}</include></busconfig>'
        self.write_file(self.session_conf_store, xml)
        expected_sha = hashlib.sha256(xml.encode()).hexdigest()
        res = self.run_audit(_expected_sha256=expected_sha)
        self.assertEqual(res["status"], "fail")
        self.assertEqual(res["reason"], "config-cycle-detected")
        self.assertEqual(res["failing_path"], self.session_conf_store)

    def test_cycle_aba_recursion(self):
        self.setup_daemon()
        path_b = self.dbus_store + "/share/dbus-1/b.conf"
        xml_a = f'<busconfig><include>{path_b}</include></busconfig>'
        xml_b = f'<busconfig><include>{self.session_conf_store}</include></busconfig>'
        self.write_file(self.session_conf_store, xml_a)
        self.write_file(path_b, xml_b)
        expected_sha = hashlib.sha256(xml_a.encode()).hexdigest()
        res = self.run_audit(_expected_sha256=expected_sha)
        self.assertEqual(res["status"], "fail")
        self.assertEqual(res["reason"], "config-cycle-detected")
        self.assertEqual(res["failing_path"], self.session_conf_store)

    def test_cycle_recursion_alias_symlink(self):
        self.setup_daemon()
        symlink_path = self.dbus_store + "/share/dbus-1/alias-to-root.conf"
        xml_a = f'<busconfig><include>{symlink_path}</include></busconfig>'
        self.write_file(self.session_conf_store, xml_a)
        self.symlink(self.session_conf_store, symlink_path)
        expected_sha = hashlib.sha256(xml_a.encode()).hexdigest()
        res = self.run_audit(_expected_sha256=expected_sha)
        self.assertEqual(res["status"], "fail")
        self.assertEqual(res["reason"], "config-cycle-detected")
        self.assertEqual(res["failing_path"], symlink_path)

    def test_cycle_relative_alias(self):
        self.setup_daemon()
        xml_a = '<busconfig><include>./session.conf</include></busconfig>'
        self.write_file(self.session_conf_store, xml_a)
        expected_sha = hashlib.sha256(xml_a.encode()).hexdigest()
        res = self.run_audit(_expected_sha256=expected_sha)
        self.assertEqual(res["status"], "fail")
        self.assertEqual(res["reason"], "config-cycle-detected")
        self.assertEqual(res["failing_path"], self.session_conf_store)

    def test_cycle_branch_local_aba(self):
        self.setup_daemon()
        path_b = self.dbus_store + "/share/dbus-1/b.conf"
        path_c = self.dbus_store + "/share/dbus-1/c.conf"
        xml_a = f'<busconfig><include>{path_b}</include></busconfig>'
        xml_b = f'<busconfig><include>{path_c}</include></busconfig>'
        xml_c = f'<busconfig><include>{path_b}</include></busconfig>'
        self.write_file(self.session_conf_store, xml_a)
        self.write_file(path_b, xml_b)
        self.write_file(path_c, xml_c)
        expected_sha = hashlib.sha256(xml_a.encode()).hexdigest()
        res = self.run_audit(_expected_sha256=expected_sha)
        self.assertEqual(res["status"], "fail")
        self.assertEqual(res["reason"], "config-cycle-detected")
        self.assertEqual(res["failing_path"], path_b)

    def test_sibling_duplicate_allowed_clean_pass(self):
        self.setup_daemon()
        path_b = self.dbus_store + "/share/dbus-1/b.conf"
        path_c = self.dbus_store + "/share/dbus-1/c.conf"
        path_d = self.dbus_store + "/share/dbus-1/common_d.conf"
        xml_a = f'<busconfig><include>{path_b}</include><include>{path_c}</include></busconfig>'
        xml_b = f'<busconfig><include>{path_d}</include></busconfig>'
        xml_c = f'<busconfig><include>{path_d}</include></busconfig>'
        xml_d = '<busconfig><type>session</type><listen>unix:tmpdir=/tmp</listen></busconfig>'
        self.write_file(self.session_conf_store, xml_a)
        self.write_file(path_b, xml_b)
        self.write_file(path_c, xml_c)
        self.write_file(path_d, xml_d)
        expected_sha = hashlib.sha256(xml_a.encode()).hexdigest()
        res = self.run_audit(_expected_sha256=expected_sha)
        self.assertEqual(res["status"], "pass")
        self.assertIsNone(res["reason"])
        self.assertTrue(res["audit_complete"])
        self.assertEqual(len(res["files"]), 5)
        self.assertEqual(len(res["includes"]), 4)

    def test_sibling_duplicate_with_policy_accumulation(self):
        self.setup_daemon()
        path_b = self.dbus_store + "/share/dbus-1/b.conf"
        path_c = self.dbus_store + "/share/dbus-1/c.conf"
        path_d = self.dbus_store + "/share/dbus-1/common_d.conf"
        xml_a = f'<busconfig><include>{path_b}</include><include>{path_c}</include></busconfig>'
        xml_b = f'<busconfig><policy context="default"><allow send_destination="b"/></policy><include>{path_d}</include></busconfig>'
        xml_c = f'<busconfig><policy context="default"><allow send_destination="c"/></policy><include>{path_d}</include></busconfig>'
        xml_d = '<busconfig><policy context="default"><deny send_destination="d"/></policy></busconfig>'
        self.write_file(self.session_conf_store, xml_a)
        self.write_file(path_b, xml_b)
        self.write_file(path_c, xml_c)
        self.write_file(path_d, xml_d)
        expected_sha = hashlib.sha256(xml_a.encode()).hexdigest()
        res = self.run_audit(_expected_sha256=expected_sha)
        self.assertEqual(res["status"], "pass")
        self.assertEqual(res["policy_count"], 4)
        self.assertEqual(res["policy_rule_count"], 4)
        self.assertEqual(res["policy_element_count"], 8)

    def test_sibling_duplicate_cycle_in_one_branch_fails_closed(self):
        self.setup_daemon()
        path_b = self.dbus_store + "/share/dbus-1/b.conf"
        path_c = self.dbus_store + "/share/dbus-1/c.conf"
        path_d = self.dbus_store + "/share/dbus-1/common_d.conf"
        xml_a = f'<busconfig><include>{path_b}</include><include>{path_c}</include></busconfig>'
        xml_b = f'<busconfig><include>{path_d}</include></busconfig>'
        xml_c = f'<busconfig><include>{path_d}</include></busconfig>'
        xml_d = f'<busconfig><include>{path_b}</include></busconfig>'
        self.write_file(self.session_conf_store, xml_a)
        self.write_file(path_b, xml_b)
        self.write_file(path_c, xml_c)
        self.write_file(path_d, xml_d)
        expected_sha = hashlib.sha256(xml_a.encode()).hexdigest()
        res = self.run_audit(_expected_sha256=expected_sha)
        self.assertEqual(res["status"], "fail")
        self.assertEqual(res["reason"], "config-cycle-detected")
        self.assertEqual(res["failing_path"], path_b)

    def test_traversal_depth_boundary_depth_4_passes(self):
        self.setup_daemon()
        paths = [self.dbus_store + f"/share/dbus-1/d{i}.conf" for i in range(4)]
        xml_root = f'<busconfig><include>{paths[0]}</include></busconfig>'
        self.write_file(self.session_conf_store, xml_root)
        for i in range(3):
            self.write_file(paths[i], f'<busconfig><include>{paths[i+1]}</include></busconfig>')
        self.write_file(paths[3], '<busconfig/>')
        expected_sha = hashlib.sha256(xml_root.encode()).hexdigest()
        res = self.run_audit(_expected_sha256=expected_sha)
        self.assertEqual(res["status"], "pass")
        self.assertEqual([f["depth"] for f in res["files"]], [0, 1, 2, 3, 4])

    def test_traversal_depth_boundary_depth_5_fails(self):
        self.setup_daemon()
        paths = [self.dbus_store + f"/share/dbus-1/d{i}.conf" for i in range(5)]
        xml_root = f'<busconfig><include>{paths[0]}</include></busconfig>'
        self.write_file(self.session_conf_store, xml_root)
        for i in range(4):
            self.write_file(paths[i], f'<busconfig><include>{paths[i+1]}</include></busconfig>')
        self.write_file(paths[4], '<busconfig/>')
        expected_sha = hashlib.sha256(xml_root.encode()).hexdigest()
        res = self.run_audit(_expected_sha256=expected_sha)
        self.assertEqual(res["status"], "fail")
        self.assertEqual(res["reason"], "config-audit-limit")

    def test_traversal_max_files_limit_fails(self):
        self.setup_daemon()
        includes_xml = "".join(
            f'<include>{self.dbus_store}/share/dbus-1/f{i}.conf</include>'
            for i in range(32)
        )
        xml_root = f'<busconfig>{includes_xml}</busconfig>'
        self.write_file(self.session_conf_store, xml_root)
        for i in range(32):
            self.write_file(self.dbus_store + f"/share/dbus-1/f{i}.conf", '<busconfig/>')
        expected_sha = hashlib.sha256(xml_root.encode()).hexdigest()
        res = self.run_audit(_expected_sha256=expected_sha)
        self.assertEqual(res["status"], "fail")
        self.assertEqual(res["reason"], "config-audit-limit")

    def test_traversal_max_includes_limit_fails(self):
        self.setup_daemon()
        includes_xml = '<include ignore_missing="yes">missing.conf</include>' * 129
        xml_root = f'<busconfig>{includes_xml}</busconfig>'
        self.write_file(self.session_conf_store, xml_root)
        expected_sha = hashlib.sha256(xml_root.encode()).hexdigest()
        res = self.run_audit(_expected_sha256=expected_sha)
        self.assertEqual(res["status"], "fail")
        self.assertEqual(res["reason"], "config-audit-limit")

    def test_traversal_max_policies_limit_fails(self):
        self.setup_daemon()
        policies_xml = '<policy context="default"><allow send_destination="*"/></policy>' * 129
        xml_root = f'<busconfig>{policies_xml}</busconfig>'
        self.write_file(self.session_conf_store, xml_root)
        expected_sha = hashlib.sha256(xml_root.encode()).hexdigest()
        res = self.run_audit(_expected_sha256=expected_sha)
        self.assertEqual(res["status"], "fail")
        self.assertEqual(res["reason"], "config-audit-limit")

    def test_traversal_max_services_limit_fails(self):
        self.setup_daemon()
        services_xml = '<servicedir>/nix/store/dummy</servicedir>' * 129
        xml_root = f'<busconfig>{services_xml}</busconfig>'
        self.write_file(self.session_conf_store, xml_root)
        expected_sha = hashlib.sha256(xml_root.encode()).hexdigest()
        res = self.run_audit(_expected_sha256=expected_sha)
        self.assertEqual(res["status"], "fail")
        self.assertEqual(res["reason"], "config-audit-limit")

    def test_legacy_directory_present_rejected(self):
        self.setup_daemon()
        self.write_file(self.session_conf_store, '<busconfig/>')
        Path(self.host("/etc/dbus-1")).mkdir(parents=True, exist_ok=True)
        res = self.run_audit(_expected_sha256=hashlib.sha256(b'<busconfig/>').hexdigest())
        self.assertEqual(res["status"], "fail")
        self.assertEqual(res["reason"], "legacy-dbus-directory-present")
        self.assertEqual(res["failing_path"], "/etc/dbus-1")
        self.assertFalse(res["legacy_absence"]["absent"])

    def test_legacy_directory_symlink_rejected(self):
        self.setup_daemon()
        self.write_file(self.session_conf_store, '<busconfig/>')
        Path(self.host("/etc/dbus-1")).symlink_to(self.host("/tmp"))
        res = self.run_audit(_expected_sha256=hashlib.sha256(b'<busconfig/>').hexdigest())
        self.assertEqual(res["status"], "fail")
        self.assertEqual(res["reason"], "legacy-dbus-symlink")
        self.assertEqual(res["failing_path"], "/etc/dbus-1")

    def test_legacy_directory_dangling_symlink_rejected(self):
        self.setup_daemon()
        self.write_file(self.session_conf_store, '<busconfig/>')
        Path(self.host("/etc/dbus-1")).symlink_to(self.host("/nonexistent/target"))
        res = self.run_audit(_expected_sha256=hashlib.sha256(b'<busconfig/>').hexdigest())
        self.assertEqual(res["status"], "fail")
        self.assertEqual(res["reason"], "legacy-dbus-symlink")
        self.assertEqual(res["failing_path"], "/etc/dbus-1")

    def test_legacy_session_conf_file_rejected(self):
        self.setup_daemon()
        self.write_file(self.session_conf_store, '<busconfig/>')
        self.write_file("/etc/dbus-1/session.conf", '<busconfig/>')
        res = self.run_audit(_expected_sha256=hashlib.sha256(b'<busconfig/>').hexdigest())
        self.assertEqual(res["status"], "fail")
        self.assertEqual(res["reason"], "legacy-session-config-present")
        self.assertEqual(res["failing_path"], "/etc/dbus-1/session.conf")

    def test_legacy_session_conf_symlink_rejected(self):
        self.setup_daemon()
        self.write_file(self.session_conf_store, '<busconfig/>')
        Path(self.host("/etc/dbus-1")).mkdir(parents=True, exist_ok=True)
        self.symlink(self.session_conf_store, "/etc/dbus-1/session.conf")
        res = self.run_audit(_expected_sha256=hashlib.sha256(b'<busconfig/>').hexdigest())
        self.assertEqual(res["status"], "fail")
        self.assertEqual(res["reason"], "legacy-session-config-symlink")
        self.assertEqual(res["failing_path"], "/etc/dbus-1/session.conf")

    def test_legacy_session_conf_dangling_symlink_rejected(self):
        self.setup_daemon()
        self.write_file(self.session_conf_store, '<busconfig/>')
        Path(self.host("/etc/dbus-1")).mkdir(parents=True, exist_ok=True)
        Path(self.host("/etc/dbus-1/session.conf")).symlink_to(self.host("/nonexistent/target"))
        res = self.run_audit(_expected_sha256=hashlib.sha256(b'<busconfig/>').hexdigest())
        self.assertEqual(res["status"], "fail")
        self.assertEqual(res["reason"], "legacy-session-config-symlink")
        self.assertEqual(res["failing_path"], "/etc/dbus-1/session.conf")

    def test_legacy_ancestor_symlink_rejected(self):
        self.setup_daemon()
        self.write_file(self.session_conf_store, '<busconfig/>')
        Path(self.host("/etc")).rmdir()
        Path(self.host("/etc")).symlink_to(self.host("/nonexistent"))
        res = self.run_audit(_expected_sha256=hashlib.sha256(b'<busconfig/>').hexdigest())
        self.assertEqual(res["status"], "fail")
        self.assertEqual(res["reason"], "legacy-ancestor-symlink")
        self.assertEqual(res["failing_path"], "/etc")

    def test_legacy_clean_absent_passes(self):
        self.setup_daemon()
        self.write_file(self.session_conf_store, '<busconfig/>')
        res = self.run_audit(_expected_sha256=hashlib.sha256(b'<busconfig/>').hexdigest())
        self.assertEqual(res["status"], "pass")
        self.assertTrue(res["legacy_absence"]["absent"])
        self.assertFalse(res["singleton_directory"]["present"])
        self.assertTrue(res["singleton_directory"]["absent"])

    def test_config_outside_closure_rejected(self):
        self.setup_daemon()
        self.write_file("/var/dbus/session.conf", '<busconfig/>')
        spec = {
            "closure": self.closure,
            "dbus_session_config": "/var/dbus/session.conf",
            "dbus_daemon": self.dbus_daemon_store,
        }
        res = self.run_audit(spec)
        self.assertEqual(res["status"], "fail")
        self.assertEqual(res["reason"], "config-outside-closure")
        self.assertEqual(res["failing_path"], "<withheld-path>")

    def test_config_not_in_closure_list_rejected(self):
        self.setup_daemon()
        other_store = "/nix/store/" + "9" * 32 + "-other-dbus/share/dbus-1/session.conf"
        self.write_file(other_store, '<busconfig/>')
        spec = {
            "closure": self.closure,
            "dbus_session_config": other_store,
            "dbus_daemon": self.dbus_daemon_store,
        }
        res = self.run_audit(spec)
        self.assertEqual(res["status"], "fail")
        self.assertEqual(res["reason"], "config-outside-closure")
        self.assertEqual(res["failing_path"], other_store)

    def test_config_unnormalized_path_rejected(self):
        self.setup_daemon()
        self.write_file(self.session_conf_store, '<busconfig/>')
        unnorm_cases = [
            self.dbus_store + "/share/../share/dbus-1/session.conf",
            self.dbus_store + "/share//dbus-1/session.conf",
            self.session_conf_store + "/",
        ]
        for unnorm in unnorm_cases:
            spec = {
                "closure": self.closure,
                "dbus_session_config": unnorm,
                "dbus_daemon": self.dbus_daemon_store,
            }
            res = self.run_audit(spec)
            self.assertEqual(res["status"], "fail")
            self.assertEqual(res["reason"], "config-not-normalized")

    def test_config_symlinked_component_rejected(self):
        self.setup_daemon()
        share_real = self.dbus_store + "/real_share/dbus-1/session.conf"
        self.write_file(share_real, '<busconfig/>')
        self.symlink(self.dbus_store + "/real_share", self.dbus_store + "/share")
        spec = {
            "closure": self.closure,
            "dbus_session_config": self.session_conf_store,
            "dbus_daemon": self.dbus_daemon_store,
        }
        res = self.run_audit(spec)
        self.assertEqual(res["status"], "fail")
        self.assertEqual(res["reason"], "config-symlinked-component")

    def test_config_itself_symlink_rejected(self):
        self.setup_daemon()
        real_target = self.dbus_store + "/share/dbus-1/real_session.conf"
        self.write_file(real_target, '<busconfig/>')
        self.symlink(real_target, self.session_conf_store)
        spec = {
            "closure": self.closure,
            "dbus_session_config": self.session_conf_store,
            "dbus_daemon": self.dbus_daemon_store,
        }
        res = self.run_audit(spec)
        self.assertEqual(res["status"], "fail")
        self.assertEqual(res["reason"], "config-symlinked-component")

    def test_config_sha256_mismatch_rejected(self):
        self.setup_daemon()
        self.write_file(self.session_conf_store, '<busconfig><type>session</type></busconfig>')
        res = self.run_audit()
        self.assertEqual(res["status"], "fail")
        self.assertEqual(res["reason"], "dbus-session-config-mismatch")
        self.assertEqual(res["failing_path"], self.session_conf_store)

    def test_no_caller_digest_override_in_spec(self):
        self.setup_daemon()
        synthetic_xml = '<busconfig><type>session</type></busconfig>'
        tampered_sha = hashlib.sha256(synthetic_xml.encode()).hexdigest()
        self.write_file(self.session_conf_store, synthetic_xml)
        spec = {
            "closure": self.closure,
            "dbus_session_config": self.session_conf_store,
            "dbus_daemon": self.dbus_daemon_store,
            "sha256": tampered_sha,
            "expected_sha256": tampered_sha,
            "dbus_session_config_sha256": tampered_sha,
        }
        res = self.run_audit(spec)
        self.assertEqual(res["status"], "fail")
        self.assertEqual(res["reason"], "dbus-session-config-mismatch")

    def test_config_file_missing_rejected(self):
        self.setup_daemon()
        res = self.run_audit()
        self.assertEqual(res["status"], "fail")
        self.assertEqual(res["reason"], "dbus-session-config-missing")

    def test_config_directory_rejected(self):
        self.setup_daemon()
        Path(self.host(self.session_conf_store)).mkdir(parents=True, exist_ok=True)
        res = self.run_audit(_expected_sha256="dummy")
        self.assertEqual(res["status"], "fail")
        self.assertEqual(res["reason"], "config-not-regular")

    def test_config_fifo_rejected_without_blocking(self):
        self.setup_daemon()
        path = Path(self.host(self.session_conf_store))
        path.parent.mkdir(parents=True, exist_ok=True)
        os.mkfifo(path)
        res = self.run_audit(_expected_sha256="dummy")
        self.assertEqual(res["status"], "fail")
        self.assertEqual(res["reason"], "config-not-regular")

    def test_config_oversize_rejected(self):
        self.setup_daemon()
        oversize_xml = "<busconfig><!-- " + ("A" * 65536) + " --></busconfig>"
        self.write_file(self.session_conf_store, oversize_xml)
        res = self.run_audit(_expected_sha256="dummy")
        self.assertEqual(res["status"], "fail")
        self.assertEqual(res["reason"], "config-oversize")

    def test_included_file_missing_required_fails(self):
        self.setup_daemon()
        missing_target = self.dbus_store + "/share/dbus-1/missing.conf"
        xml_root = f'<busconfig><include>{missing_target}</include></busconfig>'
        self.write_file(self.session_conf_store, xml_root)
        expected_sha = hashlib.sha256(xml_root.encode()).hexdigest()
        res = self.run_audit(_expected_sha256=expected_sha)
        self.assertEqual(res["status"], "fail")
        self.assertEqual(res["reason"], "missing-required-include")
        self.assertEqual(res["failing_path"], missing_target)

    def test_included_file_fifo_rejected(self):
        self.setup_daemon()
        fifo_path = self.dbus_store + "/share/dbus-1/sub_fifo.conf"
        xml_root = f'<busconfig><include>{fifo_path}</include></busconfig>'
        self.write_file(self.session_conf_store, xml_root)
        os.mkfifo(Path(self.host(fifo_path)))
        expected_sha = hashlib.sha256(xml_root.encode()).hexdigest()
        res = self.run_audit(_expected_sha256=expected_sha)
        self.assertEqual(res["status"], "fail")
        self.assertEqual(res["reason"], "config-not-regular")

    def test_included_file_oversize_rejected(self):
        self.setup_daemon()
        big_path = self.dbus_store + "/share/dbus-1/big.conf"
        xml_root = f'<busconfig><include>{big_path}</include></busconfig>'
        self.write_file(self.session_conf_store, xml_root)
        self.write_file(big_path, "<busconfig><!-- " + ("X" * 65536) + " --></busconfig>")
        expected_sha = hashlib.sha256(xml_root.encode()).hexdigest()
        res = self.run_audit(_expected_sha256=expected_sha)
        self.assertEqual(res["status"], "fail")
        self.assertEqual(res["reason"], "config-oversize")

    def test_entity_declaration_rejected(self):
        self.setup_daemon()
        xml = '<!DOCTYPE busconfig [<!ENTITY test "val">]><busconfig>&test;</busconfig>'
        self.write_file(self.session_conf_store, xml)
        expected_sha = hashlib.sha256(xml.encode()).hexdigest()
        res = self.run_audit(_expected_sha256=expected_sha)
        self.assertEqual(res["status"], "fail")
        self.assertEqual(res["reason"], "config-entities-rejected")

    def test_parameter_entity_rejected(self):
        self.setup_daemon()
        xml = '<!DOCTYPE busconfig [<!ENTITY % pe "val">]><busconfig/>'
        self.write_file(self.session_conf_store, xml)
        expected_sha = hashlib.sha256(xml.encode()).hexdigest()
        res = self.run_audit(_expected_sha256=expected_sha)
        self.assertEqual(res["status"], "fail")
        self.assertEqual(res["reason"], "config-entities-rejected")

    def test_external_entity_rejected(self):
        self.setup_daemon()
        xml = '<!DOCTYPE busconfig [<!ENTITY ext SYSTEM "file:///etc/passwd">]><busconfig>&ext;</busconfig>'
        self.write_file(self.session_conf_store, xml)
        expected_sha = hashlib.sha256(xml.encode()).hexdigest()
        res = self.run_audit(_expected_sha256=expected_sha)
        self.assertEqual(res["status"], "fail")
        self.assertEqual(res["reason"], "config-entities-rejected")

    def test_entity_in_nested_include_rejected(self):
        self.setup_daemon()
        sub_path = self.dbus_store + "/share/dbus-1/sub_ent.conf"
        xml_root = f'<busconfig><include>{sub_path}</include></busconfig>'
        xml_sub = '<!DOCTYPE busconfig [<!ENTITY bomb "boom">]><busconfig>&bomb;</busconfig>'
        self.write_file(self.session_conf_store, xml_root)
        self.write_file(sub_path, xml_sub)
        expected_sha = hashlib.sha256(xml_root.encode()).hexdigest()
        res = self.run_audit(_expected_sha256=expected_sha)
        self.assertEqual(res["status"], "fail")
        self.assertEqual(res["reason"], "config-entities-rejected")

    def test_genuine_standard_doctype_accepted(self):
        self.setup_daemon()
        xml = (
            '<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"\n'
            ' "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">\n'
            '<busconfig><type>session</type></busconfig>'
        )
        self.write_file(self.session_conf_store, xml)
        expected_sha = hashlib.sha256(xml.encode()).hexdigest()
        res = self.run_audit(_expected_sha256=expected_sha)
        self.assertEqual(res["status"], "pass")
        self.assertIsNone(res["reason"])

    def test_include_host_path_present_rejected(self):
        self.setup_daemon()
        self.write_file("/etc/host_secret", "secret")
        xml_root = '<busconfig><include>/etc/host_secret</include></busconfig>'
        self.write_file(self.session_conf_store, xml_root)
        expected_sha = hashlib.sha256(xml_root.encode()).hexdigest()
        res = self.run_audit(_expected_sha256=expected_sha)
        self.assertEqual(res["status"], "fail")
        self.assertEqual(res["reason"], "symlink-outside-closure")
        self.assertEqual(res["failing_path"], "<withheld-path>")

    def test_include_host_path_traversal_rejected(self):
        self.setup_daemon()
        self.write_file("/etc/target", "data")
        xml_root = '<busconfig><include>../../../../etc/target</include></busconfig>'
        self.write_file(self.session_conf_store, xml_root)
        expected_sha = hashlib.sha256(xml_root.encode()).hexdigest()
        res = self.run_audit(_expected_sha256=expected_sha)
        self.assertEqual(res["status"], "fail")
        self.assertEqual(res["reason"], "symlink-outside-closure")
        self.assertEqual(res["failing_path"], "<withheld-path>")

    def test_include_absent_host_path_rejected(self):
        self.setup_daemon()
        xml_root = '<busconfig><include ignore_missing="yes">/host/escape/missing.conf</include></busconfig>'
        self.write_file(self.session_conf_store, xml_root)
        expected_sha = hashlib.sha256(xml_root.encode()).hexdigest()
        res = self.run_audit(_expected_sha256=expected_sha)
        self.assertEqual(res["status"], "fail")
        self.assertEqual(res["reason"], "symlink-outside-closure")
        self.assertEqual(res["failing_path"], "<withheld-path>")

    def test_malformed_xml_rejected(self):
        self.setup_daemon()
        xml = '<busconfig><unclosed>'
        self.write_file(self.session_conf_store, xml)
        expected_sha = hashlib.sha256(xml.encode()).hexdigest()
        res = self.run_audit(_expected_sha256=expected_sha)
        self.assertEqual(res["status"], "fail")
        self.assertEqual(res["reason"], "config-malformed")

    def test_wrong_root_element_rejected(self):
        self.setup_daemon()
        xml = '<configuration><type>session</type></configuration>'
        self.write_file(self.session_conf_store, xml)
        expected_sha = hashlib.sha256(xml.encode()).hexdigest()
        res = self.run_audit(_expected_sha256=expected_sha)
        self.assertEqual(res["status"], "fail")
        self.assertEqual(res["reason"], "config-malformed")

    def test_empty_include_text_rejected(self):
        self.setup_daemon()
        xml = '<busconfig><include>   </include></busconfig>'
        self.write_file(self.session_conf_store, xml)
        expected_sha = hashlib.sha256(xml.encode()).hexdigest()
        res = self.run_audit(_expected_sha256=expected_sha)
        self.assertEqual(res["status"], "fail")
        self.assertEqual(res["reason"], "config-malformed")

    def test_daemon_identity_failures(self):
        self.write_file(self.session_conf_store, '<busconfig/>')
        spec = {"closure": self.closure, "dbus_session_config": self.session_conf_store, "dbus_daemon": self.dbus_daemon_store}
        res = self.run_audit(spec)
        self.assertEqual(res["status"], "fail")
        self.assertEqual(res["reason"], "dbus-daemon-missing")

        self.setup_daemon()
        other_daemon = self.dbus_store + "/bin/other-daemon"
        spec["dbus_daemon"] = other_daemon
        res2 = self.run_audit(spec)
        self.assertEqual(res2["status"], "fail")
        self.assertEqual(res2["reason"], "dbus-daemon-mismatch")

        spec["dbus_daemon"] = self.dbus_daemon_store
        spec["closure"] = []
        res3 = self.run_audit(spec)
        self.assertEqual(res3["status"], "fail")
        self.assertEqual(res3["reason"], "daemon-outside-closure")

    def test_real_pinned_session_conf_happy_path(self):
        self.setup_daemon()
        self.write_file(self.session_conf_store, REAL_PINNED_SESSION_CONF_BYTES)
        self.assertEqual(hashlib.sha256(REAL_PINNED_SESSION_CONF_BYTES).hexdigest(), DBUS_SESSION_CONFIG_SHA256)
        res = self.run_audit()
        self.assertEqual(res["status"], "pass")
        self.assertIsNone(res["reason"])
        self.assertTrue(res["audit_complete"])
        self.assertTrue(res["daemon_identity"]["same_real_file"])
        self.assertTrue(res["legacy_absence"]["absent"])
        self.assertEqual(len(res["files"]), 1)
        self.assertEqual(res["files"][0]["bytes"], 3561)
        self.assertEqual(res["files"][0]["sha256"], DBUS_SESSION_CONFIG_SHA256)
        self.assertEqual(res["listen_classes"], ["unix:tmpdir"])
        self.assertEqual(res["auth_mechanisms"], ["EXTERNAL"])
        self.assertEqual(res["service_directories"], [{"kind": "standard-session"}])

    def test_production_adapter_has_no_digest_override(self):
        import inspect
        self.assertEqual(list(inspect.signature(audit_dbus_config).parameters), ['spec'])

    def test_utf16_entity_include_and_dangling_escape_fail_closed(self):
        self.setup_daemon()
        target = self.dbus_store + '/share/dbus-1/hostile.conf'
        xml = '<busconfig><include>' + target + '</include></busconfig>'
        self.write_file(self.session_conf_store, xml)
        self.write_file(target, '<!DOCTYPE busconfig [<!ENTITY a "x">]><busconfig>&a;</busconfig>'.encode('utf-16'))
        digest = hashlib.sha256(xml.encode()).hexdigest()
        self.assertEqual(self.run_audit(_expected_sha256=digest)['reason'], 'config-malformed')
        Path(self.host(target)).unlink()
        self.symlink('/host/private/missing.conf', target)
        self.assertEqual(self.run_audit(_expected_sha256=digest)['reason'], 'symlink-outside-closure')

    def test_malicious_spec_is_closed_and_paths_are_withheld(self):
        for spec in (None, [], {'closure': ['/host/private']},
                     {'closure': [], 'dbus_daemon': True, 'dbus_session_config': '\x00'}):
            result = audit_dbus_config(spec)
            self.assertEqual(result['reason'], 'config-input-invalid')
            self.assertNotIn('/host/private', json.dumps(result))

    def test_real_pinned_session_conf_includes_recorded(self):
        self.setup_daemon()
        self.write_file(self.session_conf_store, REAL_PINNED_SESSION_CONF_BYTES)
        res = self.run_audit()
        self.assertEqual(res["status"], "pass")
        inc_resolved = [i["resolved"] for i in res["includes"]]
        self.assertIn("/etc/dbus-1/session.conf", inc_resolved)
        self.assertIn("/etc/dbus-1/session.d", inc_resolved)
        self.assertIn("/etc/dbus-1/session-local.conf", inc_resolved)
        for inc in res["includes"]:
            if inc["resolved"] == "/etc/dbus-1/session.conf":
                self.assertFalse(inc["present"])
                self.assertTrue(inc["ignore_missing"])
            elif inc["resolved"] == "/etc/dbus-1/session-local.conf":
                self.assertFalse(inc["present"])
                self.assertTrue(inc["ignore_missing"])
            elif inc["tag"] == "includedir":
                self.assertFalse(inc["present"])

    def test_real_pinned_session_conf_policy_diagnostics(self):
        self.setup_daemon()
        self.write_file(self.session_conf_store, REAL_PINNED_SESSION_CONF_BYTES)
        res = self.run_audit()
        self.assertEqual(res["status"], "pass")
        self.assertEqual(res["policy_count"], 1)
        self.assertEqual(res["policy_rule_count"], 3)
        self.assertEqual(res["policy_element_count"], 4)
        policy = res["policies"][0]
        self.assertEqual(policy["context"], "default")
        self.assertEqual(policy["allow_count"], 3)

    def test_real_pinned_session_conf_fails_closed_when_legacy_present(self):
        self.setup_daemon()
        self.write_file(self.session_conf_store, REAL_PINNED_SESSION_CONF_BYTES)
        Path(self.host("/etc/dbus-1")).mkdir(parents=True, exist_ok=True)
        res = self.run_audit()
        self.assertEqual(res["status"], "fail")
        self.assertEqual(res["reason"], "legacy-dbus-directory-present")
        self.assertEqual(res["failing_path"], "/etc/dbus-1")
        self.assertFalse(res["audit_complete"])

    def test_real_pinned_session_conf_fails_closed_on_legacy_symlink(self):
        self.setup_daemon()
        self.write_file(self.session_conf_store, REAL_PINNED_SESSION_CONF_BYTES)
        Path(self.host("/etc/dbus-1")).mkdir(parents=True, exist_ok=True)
        self.symlink(self.session_conf_store, "/etc/dbus-1/session.conf")
        res = self.run_audit()
        self.assertEqual(res["status"], "fail")
        self.assertEqual(res["reason"], "legacy-session-config-symlink")
        self.assertEqual(res["failing_path"], "/etc/dbus-1/session.conf")

if __name__ == "__main__":
    unittest.main()
