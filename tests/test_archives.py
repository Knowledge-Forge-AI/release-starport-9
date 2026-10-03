import io
from pathlib import Path
import tarfile
import tempfile
import unittest

from rs9.archives import inspect_archive
from rs9.errors import ContractError
from tests.shadow_fixtures import tar_bytes


class ArchiveTests(unittest.TestCase):
    def inspect(self, entries, **kwargs):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp).resolve() / "input.tar.gz"
            path.write_bytes(tar_bytes(entries))
            return inspect_archive(path, {"app": "app/bin/app"}, **kwargs)

    def base(self):
        return [("app/bin/app", b"upstream executable", 0o755, tarfile.REGTYPE, "")]

    def test_valid_safe_symlink_and_visitor(self):
        seen = []
        entries = self.base() + [("app/current", b"", 0o777, tarfile.SYMTYPE, "bin/app")]
        result = self.inspect(entries, on_file=lambda p, b, m: seen.append(p))
        self.assertEqual(result["root"], "app")
        self.assertEqual(seen, ["app/bin/app"])
        self.assertEqual(result, self.inspect(entries))

    def test_unsafe_names(self):
        for name in ("/app/file", "app/../file", "app/./file", "app//file", "app/\\file", "app/\nfile", "app/A\u030a", "other/file"):
            with self.subTest(name=name), self.assertRaises(ContractError):
                self.inspect(self.base() + [(name, b"x", 0o644, tarfile.REGTYPE, "")])

    def test_duplicate_special_privileged_limits(self):
        for entry in [("app/bin/app", b"x", 0o755, tarfile.REGTYPE, ""), ("app/fifo", b"", 0o644, tarfile.FIFOTYPE, ""), ("app/device", b"", 0o644, tarfile.CHRTYPE, ""), ("app/setuid", b"x", 0o4755, tarfile.REGTYPE, "")]:
            with self.subTest(entry=entry[0]), self.assertRaises(ContractError):
                self.inspect(self.base() + [entry])
        for limits in ({"max_members": 0}, {"max_member_bytes": 1}, {"max_total_bytes": 1}, {"max_ratio": 0}):
            with self.assertRaises(ContractError):
                self.inspect(self.base(), **limits)

    def test_symlink_and_hardlink_escapes_cycles_ancestors(self):
        for extra in [[("app/link", b"", 0o777, tarfile.SYMTYPE, "../../escape")], [("app/link", b"", 0o777, tarfile.LNKTYPE, "other/file")], [("app/a", b"", 0o777, tarfile.SYMTYPE, "b"), ("app/b", b"", 0o777, tarfile.SYMTYPE, "a")], [("app/link", b"", 0o777, tarfile.SYMTYPE, "bin"), ("app/link/file", b"x", 0o644, tarfile.REGTYPE, "")], [("app/link", b"", 0o777, tarfile.SYMTYPE, "/etc/passwd")], [("app/link", b"", 0o777, tarfile.SYMTYPE, "a/../../outside")]]:
            with self.subTest(extra=extra), self.assertRaises(ContractError):
                self.inspect(self.base() + extra)

    def test_command_requires_regular_executable(self):
        for entry in [("app/bin/app", b"x", 0o644, tarfile.REGTYPE, ""), ("app/bin/app", b"", 0o755, tarfile.SYMTYPE, "other")]:
            with self.assertRaises(ContractError):
                self.inspect([entry])

    def test_visitor_not_called_before_validation(self):
        seen = []
        with self.assertRaises(ContractError):
            self.inspect(self.base() + [("app/link", b"", 0o777, tarfile.SYMTYPE, "../../x")], on_file=lambda *args: seen.append(args))
        self.assertEqual(seen, [])
