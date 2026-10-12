"""Exact guest audit source against an explicitly mapped disposable filesystem."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from rs9.nix_proot_audit import GUEST_AUDIT_SOURCE, audit_dbus_config, guest_audit
from rs9.nix_proot import Run
from rs9.nix_proot_dbus import DBUS_AUDIT_SOURCE, DBUS_SESSION_CONFIG_SHA256


class GuestAuditTests(unittest.TestCase):
    def test_actual_script_follows_wrapper_shebang_path_helper_and_elf_interpreter(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            display = "/nix/store/" + "0" * 32 + "-display"
            tools = "/nix/store/" + "1" * 32 + "-tools"
            python = "/nix/store/" + "2" * 32 + "-python"
            paths = [display, tools, python]

            def host(path):
                path = str(path)
                return path if path.startswith(str(base)) else str(base / path.lstrip("/"))

            def guest(path):
                path = str(path)
                return path[len(str(base)):] if path.startswith(str(base)) else path

            def write(path, content):
                target = Path(host(path))
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content)
                target.chmod(0o755)

            write(display + "/bin/xvfb-run", ("#!" + tools + "/bin/sh\nexport PATH=" + tools +
                  "/bin:$PATH\nexec " + display + "/bin/.xvfb-run-wrapped \"$@\"\n").encode())
            write(display + "/bin/.xvfb-run-wrapped", ("#!/bin/sh\ngetopt --help\nxauth --help\n/usr/bin/getopt --help\n").encode())
            write(tools + "/bin/sh", b"#!/bin/sh\nexit 0\n")
            write(tools + "/bin/getopt", b"#!/bin/sh\nexit 0\n")
            raw = bytearray(160)
            raw[:16] = b"\x7fELF\x02\x01\x01" + b"\0" * 9
            struct.pack_into("<Q", raw, 32, 64)
            struct.pack_into("<HH", raw, 54, 56, 1)
            struct.pack_into("<I", raw, 64, 3)
            struct.pack_into("<Q", raw, 72, 120)
            loader = (tools + "/lib/ld.so").encode() + b"\0"
            struct.pack_into("<Q", raw, 96, len(loader))
            raw[120:120 + len(loader)] = loader
            write(python + "/bin/python3", bytes(raw) + b"/etc/dbus-1/session.conf\0/usr/bin/dbus-daemon\0")
            write(tools + "/lib/ld.so", b"loader")
            Path(host("/tmp")).mkdir()
            originals = {key: getattr(os.path, key) for key in ("exists", "isfile", "isdir", "realpath")}
            open_file, access_file, which = os.open, os.access, shutil.which

            def resolve(command, path=None):
                candidate = which(command, path=":".join(host(p) for p in (path or os.environ["PATH"]).split(":")))
                return guest(candidate) if candidate else None

            spec = {"roots": {"display": display + "/bin/xvfb-run", "python": python + "/bin/python3"},
                    "names": {"display": "xvfb-run", "python": "python3"}, "closure": paths,
                    "host_binds": ["/bound/work"], "foreign_interpreter": "/lib64/ld-linux-x86-64.so.2"}
            output = io.StringIO()
            with patch.dict(os.environ, {"PATH": display + "/bin:" + python + "/bin"}), \
                    patch.object(sys, "argv", ["audit", json.dumps(spec)]), \
                    patch("os.path.exists", side_effect=lambda p: originals["exists"](host(p))), \
                    patch("os.path.isfile", side_effect=lambda p: originals["isfile"](host(p))), \
                    patch("os.path.isdir", side_effect=lambda p: originals["isdir"](host(p))), \
                    patch("os.path.realpath", side_effect=lambda p: guest(originals["realpath"](host(p)))), \
                    patch("os.open", side_effect=lambda p, *a, **k: open_file(host(p), *a, **k)), \
                    patch("os.access", side_effect=lambda p, *a, **k: access_file(host(p), *a, **k)), \
                    patch("os.getcwd", return_value="/tmp"), \
                    patch("shutil.which", side_effect=resolve), contextlib.redirect_stdout(output):
                exec(compile(GUEST_AUDIT_SOURCE, "guest-audit", "exec"), {})
            record = json.loads(output.getvalue())
            files = record["files"]
            self.assertTrue(record["references_are_candidates"])
            self.assertTrue(any(r.get("path") == display + "/bin/.xvfb-run-wrapped" for r in files))
            self.assertTrue(any(r.get("path") == tools + "/bin/getopt" for r in files))
            self.assertTrue(any(ref.get("role") == "ELF-PT_INTERP" and ref.get("present")
                                for row in files for ref in row["references"]))
            self.assertTrue(any(c["tool"] == "xauth" and not c["present"]
                                for row in files for c in row.get("PATH_candidates", [])))
            self.assertTrue(any(ref.get("path") == "/usr/bin/getopt" and not ref["present"]
                                for row in files for ref in row["references"]))
            self.assertTrue(any(ref.get("path") == "/etc/dbus-1/session.conf" and ref["role"] == "ELF-runtime-candidate"
                                for row in files for ref in row["references"]))
            self.assertTrue(any(ref.get("path") == "/usr/bin/dbus-daemon" and not ref["present"]
                                and ref["role"] == "ELF-absolute-command-candidate"
                                for row in files for ref in row["references"]))
            self.assertEqual(record["status"], "observed")
            self.assertNotIn(str(base), output.getvalue())

    def test_guest_boundary_and_outer_failures_are_retained(self):
        calls = []
        failure = Run(127, b"", b"getopt: command not found", 0.3, None)
        rt = SimpleNamespace(facts={k: "/nix/store/" + "0" * 32 + "-tools/bin/" + k
                                   for k in ("xvfb_run", "dbus_run_session", "python", "node")}, closure=[],
                             layout=SimpleNamespace(tmp_dir=Path("/bound/tmp"), cache_dir=Path("/bound/cache"),
                                                    loader_tmp=Path("/bound/loader"), etc_dir=Path("/bound/etc"),
                                                    workspaces=()),
                             run=lambda *a, **k: (calls.append((a, k)) or failure))
        rt.facts["foreign_interpreter"] = "/lib64/ld-linux-x86-64.so.2"
        record = guest_audit(rt)
        self.assertEqual(record["status"], "unobserved")
        self.assertEqual(record["exit_code"], 127)
        self.assertEqual(record["stderr_bytes"], len(failure.stderr))
        self.assertEqual(calls[0][1]["cwd"], "/tmp")
        self.assertIn(GUEST_AUDIT_SOURCE, calls[0][0][1])


class DBusConfigAuditTests(unittest.TestCase):
    """Focused synthetic unit tests for bounded recursive D-Bus XML config audit.

    All test fixtures here are synthetic unit fixtures; they make no native qualification claims.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.base = Path(self._tmp.name).resolve()
        self.dbus_store = "/nix/store/" + "d" * 32 + "-dbus-1.14.10"
        self.closure = [self.dbus_store]
        self.session_conf_store = self.dbus_store + "/share/dbus-1/session.conf"
        self.dbus_daemon_store = self.dbus_store + "/bin/dbus-daemon"

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

    def setup_happy_path(self, extra_xml=""):
        self.write_file(self.dbus_daemon_store, b"#!/bin/sh\nexit 0\n", 0o755)
        xml = f"""<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>session</type>
  <listen>unix:tmpdir=/tmp</listen>
  <include ignore_missing="yes">/etc/dbus-1/session.conf</include>
  <includedir>session.d</includedir>
  <include ignore_missing="yes">/etc/dbus-1/session-local.conf</include>
  {extra_xml}
</busconfig>
"""
        self.write_file(self.session_conf_store, xml)

    def run_audit(self, spec=None, full_guest=False):
        if spec is None:
            spec = {
                "closure": self.closure,
                "dbus_session_config": self.session_conf_store,
                "dbus_daemon": self.dbus_daemon_store,
            }
        originals = {k: getattr(os.path, k) for k in ("exists", "isfile", "isdir", "islink", "realpath", "lexists")}
        orig_stat = os.stat
        orig_listdir = os.listdir
        orig_scandir = os.scandir
        which = shutil.which

        def resolve_daemon(cmd, path=None):
            if cmd == "dbus-daemon":
                target = Path(self.host(self.dbus_daemon_store))
                return self.guest(str(target)) if target.exists() else None
            return which(cmd, path=path)

        open_file = open
        open_fd = os.open
        fixture_path = Path(self.host(self.session_conf_store))
        fixture_digest = hashlib.sha256(fixture_path.read_bytes()).hexdigest() if fixture_path.is_file() else DBUS_SESSION_CONFIG_SHA256
        source = DBUS_AUDIT_SOURCE.replace(repr(DBUS_SESSION_CONFIG_SHA256), repr(fixture_digest), 1)
        with patch("os.path.exists", side_effect=lambda p: originals["exists"](self.host(p))), \
                patch("os.path.lexists", side_effect=lambda p: originals["lexists"](self.host(p))), \
                patch("os.path.isfile", side_effect=lambda p: originals["isfile"](self.host(p))), \
                patch("os.path.isdir", side_effect=lambda p: originals["isdir"](self.host(p))), \
                patch("os.path.islink", side_effect=lambda p: originals["islink"](self.host(p))), \
                patch("os.path.realpath", side_effect=lambda p: self.guest(originals["realpath"](self.host(p)))), \
                patch("os.stat", side_effect=lambda p, *a, **k: orig_stat(self.host(p), *a, **k)), \
                patch("os.listdir", side_effect=lambda p: orig_listdir(self.host(p))), \
                patch("os.scandir", side_effect=lambda p: orig_scandir(self.host(p))), \
                patch("os.open", side_effect=lambda p, *a, **k: open_fd(self.host(p), *a, **k)), \
                patch("shutil.which", side_effect=resolve_daemon), \
                patch("builtins.open", side_effect=lambda p, *a, **k: open_file(self.host(p), *a, **k)):
            if full_guest:
                full_spec = {**spec, "roots": {"dbus": self.dbus_daemon_store},
                             "names": {"dbus": "dbus-daemon"}, "host_binds": [],
                             "foreign_interpreter": "/lib64/ld-linux-x86-64.so.2"}
                output = io.StringIO()
                with patch.object(sys, "argv", ["audit", json.dumps(full_spec)]), \
                        contextlib.redirect_stdout(output), patch("os.getcwd", return_value="/tmp"):
                    guest_source = GUEST_AUDIT_SOURCE.replace(repr(DBUS_SESSION_CONFIG_SHA256), repr(fixture_digest), 1)
                    exec(compile(guest_source, "guest-audit", "exec"), {})
                return json.loads(output.getvalue())["dbus_config"]
            with patch('rs9.nix_proot_dbus.DBUS_AUDIT_SOURCE', source):
                return audit_dbus_config(spec)

    def test_complete_guest_source_records_same_dbus_config(self):
        self.setup_happy_path('<auth>EXTERNAL</auth><standard_session_servicedirs/>')
        standalone = self.run_audit()
        guest = self.run_audit(full_guest=True)
        self.assertEqual(guest, standalone)
        self.assertEqual(guest["listen_classes"], ["unix:tmpdir"])
        self.assertEqual(guest["auth_mechanisms"], ["EXTERNAL"])
        self.assertEqual(guest["service_directories"], [{"kind": "standard-session"}])

    def test_fifo_config_is_rejected_without_blocking(self):
        self.setup_happy_path()
        path = Path(self.host(self.session_conf_store))
        path.unlink()
        os.mkfifo(path)
        self.assertEqual(self.run_audit()["reason"], "config-not-regular")

    def test_include_count_and_directory_entries_are_bounded(self):
        self.setup_happy_path('<include ignore_missing="yes">missing.conf</include>' * 129)
        self.assertEqual(self.run_audit()["reason"], "config-audit-limit")
        self.write_file(self.session_conf_store, '<busconfig><includedir>session.d</includedir></busconfig>')
        for index in range(129):
            self.write_file(self.dbus_store + '/share/dbus-1/session.d/extra-%d' % index, '')
        result = self.run_audit()
        self.assertEqual(result["reason"], "config-audit-limit")
        self.assertNotIn('extra-128', json.dumps(result))

    def test_happy_path_synthetic(self):
        self.setup_happy_path()
        res = self.run_audit()
        self.assertEqual(res["status"], "pass")
        self.assertTrue(res["legacy_absence"]["absent"])
        self.assertEqual(res["session_config_identity"]["real_path"], self.session_conf_store)
        self.assertTrue(res["daemon_identity"]["same_real_file"])
        self.assertTrue(res["audit_complete"])
        self.assertEqual(len(res["files"]), 1)
        self.assertEqual(len(res["includes"]), 3)

    def test_missing_directory_synthetic(self):
        self.write_file(self.dbus_daemon_store, b"#!/bin/sh\nexit 0\n", 0o755)
        self.write_file(self.session_conf_store, "<busconfig/>")
        res = self.run_audit()
        self.assertEqual(res["status"], "pass")
        self.assertTrue(res["legacy_absence"]["absent"])

    def test_non_singleton_directory_synthetic(self):
        self.setup_happy_path()
        self.write_file("/etc/dbus-1/extra.conf", "<busconfig/>")
        res = self.run_audit()
        self.assertEqual(res["status"], "fail")
        self.assertEqual(res["reason"], "legacy-dbus-directory-present")

    def test_missing_session_conf_synthetic(self):
        self.write_file(self.dbus_daemon_store, b"#!/bin/sh\nexit 0\n", 0o755)
        Path(self.host("/etc/dbus-1")).mkdir(parents=True, exist_ok=True)
        res = self.run_audit()
        self.assertEqual(res["status"], "fail")
        self.assertEqual(res["reason"], "legacy-dbus-directory-present")

    def test_session_conf_mismatch_synthetic(self):
        self.setup_happy_path()
        other_store = "/nix/store/" + "e" * 32 + "-other-dbus/share/dbus-1/session.conf"
        spec = {
            "closure": self.closure,
            "dbus_session_config": other_store,
            "dbus_daemon": self.dbus_daemon_store,
        }
        res = self.run_audit(spec)
        self.assertEqual(res["status"], "fail")
        self.assertEqual(res["reason"], "config-outside-closure")

    def test_daemon_missing_and_mismatch_synthetic(self):
        self.setup_happy_path()
        spec = {
            "closure": self.closure,
            "dbus_session_config": self.session_conf_store,
            "dbus_daemon": self.dbus_store + "/bin/other-daemon",
        }
        res = self.run_audit(spec)
        self.assertEqual(res["status"], "fail")
        self.assertEqual(res["reason"], "dbus-daemon-mismatch")

    def test_daemon_outside_closure_synthetic(self):
        self.setup_happy_path()
        spec = {
            "closure": [],
            "dbus_session_config": self.session_conf_store,
            "dbus_daemon": self.dbus_daemon_store,
        }
        res = self.run_audit(spec)
        self.assertEqual(res["status"], "fail")
        self.assertEqual(res["reason"], "daemon-outside-closure")

    def test_missing_required_include_fails_synthetic(self):
        self.setup_happy_path(extra_xml='<include>/etc/dbus-1/nonexistent.conf</include>')
        res = self.run_audit()
        self.assertEqual(res["status"], "fail")
        self.assertEqual(res["reason"], "missing-required-include")

    def test_ignore_missing_include_passes_synthetic(self):
        self.setup_happy_path(extra_xml='<include ignore_missing="yes">/etc/dbus-1/nonexistent.conf</include>')
        res = self.run_audit()
        self.assertEqual(res["status"], "pass")
        rec = next(inc for inc in res["includes"] if inc["resolved"] == "/etc/dbus-1/nonexistent.conf")
        self.assertTrue(rec["ignore_missing"])
        self.assertFalse(rec["present"])

    def test_malformed_xml_fails_synthetic(self):
        self.write_file(self.dbus_daemon_store, b"#!/bin/sh\nexit 0\n", 0o755)
        self.write_file(self.session_conf_store, "<busconfig><unclosed>")
        res = self.run_audit()
        self.assertEqual(res["status"], "fail")
        self.assertEqual(res["reason"], "config-malformed")

    def test_oversize_file_fails_synthetic(self):
        self.write_file(self.dbus_daemon_store, b"#!/bin/sh\nexit 0\n", 0o755)
        oversize_xml = "<busconfig><!-- " + ("A" * 65536) + " --></busconfig>"
        self.write_file(self.session_conf_store, oversize_xml)
        res = self.run_audit()
        self.assertEqual(res["status"], "fail")
        self.assertEqual(res["reason"], "config-oversize")

    def test_symlink_outside_closure_fails_synthetic(self):
        self.write_file(self.dbus_daemon_store, b"#!/bin/sh\nexit 0\n", 0o755)
        outside_store = "/nix/store/" + "9" * 32 + "-outside/sub.conf"
        self.write_file(outside_store, "<busconfig/>")
        self.write_file(self.session_conf_store, f'<busconfig><include>{outside_store}</include></busconfig>')
        res = self.run_audit()
        self.assertEqual(res["status"], "fail")
        self.assertEqual(res["reason"], "symlink-outside-closure")
        self.assertEqual(res["failing_path"], outside_store)

    def test_relative_include_resolves_from_guest_filename_synthetic(self):
        self.write_file(self.dbus_daemon_store, b"#!/bin/sh\nexit 0\n", 0o755)
        self.write_file(self.session_conf_store, '<busconfig><include ignore_missing="yes">sub.conf</include></busconfig>')
        res = self.run_audit()
        self.assertEqual(res["status"], "pass")
        inc = next(i for i in res["includes"] if i["raw"] == "sub.conf")
        self.assertEqual(inc["resolved"], self.dbus_store + "/share/dbus-1/sub.conf")

    def test_recursion_depth_bounded_synthetic(self):
        self.write_file(self.dbus_daemon_store, b"#!/bin/sh\nexit 0\n", 0o755)
        for i in range(5):
            next_target = self.dbus_store + f"/share/dbus-1/conf{i+1}.conf"
            content = f'<busconfig><include ignore_missing="yes">{next_target}</include></busconfig>'
            if i == 0:
                self.write_file(self.session_conf_store, content)
            else:
                self.write_file(self.dbus_store + f"/share/dbus-1/conf{i}.conf", content)
        self.write_file(self.dbus_store + "/share/dbus-1/conf5.conf", "<busconfig/>")
        res = self.run_audit()
        self.assertEqual(res["status"], "fail")
        self.assertEqual(res["reason"], "config-audit-limit")
        depths = [f["depth"] for f in res["files"]]
        self.assertEqual(depths, [0, 1, 2, 3, 4])

    def test_includedir_traversal_synthetic(self):
        dir_store = self.dbus_store + "/share/dbus-1/session.d"
        conf_in_dir = dir_store + "/10-test.conf"
        self.write_file(conf_in_dir, '<busconfig><type>session</type></busconfig>')
        self.setup_happy_path(extra_xml=f'<includedir>{dir_store}</includedir>')
        res = self.run_audit()
        self.assertEqual(res["status"], "pass")
        inc = next(i for i in res["includes"] if i["tag"] == "includedir" and i["resolved"] == dir_store)
        self.assertTrue(inc["present"])
        self.assertTrue(any(f["real_path"] == conf_in_dir for f in res["files"]))
