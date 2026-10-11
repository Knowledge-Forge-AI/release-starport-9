"""Exact guest audit source against an explicitly mapped disposable filesystem."""
import contextlib
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

from rs9.nix_proot_audit import GUEST_AUDIT_SOURCE, guest_audit
from rs9.nix_proot import Run


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
