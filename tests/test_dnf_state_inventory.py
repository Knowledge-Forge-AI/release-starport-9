"""Source-owned synthetic replay of run-12 paths; real filesystem controls.

These tests establish inventory contracts, never native DNF qualification.
"""
import base64
from pathlib import Path
import tempfile
import unittest

from rs9 import client_inventory as ci, dnf_state as ds, hosted_deb as hd
from rs9.build_native import CommandReceipt
from rs9.errors import ContractError
from rs9.hosted_native import compare_inventories
from rs9.rpm_lint_policy import evaluate_policy
from tests.test_client_inventory import _make_framed_payload
from tests.test_rpm_lint_policy import complete_case

# Independent transcription of the exact observed set, not invented database names.
OBSERVED = (
    "usr/lib/sysimage/libdnf5/system.toml",
    "usr/lib/sysimage/libdnf5/transaction_history.sqlite",
    "usr/lib/sysimage/libdnf5/transaction_history.sqlite-shm",
    "usr/lib/sysimage/libdnf5/transaction_history.sqlite-wal",
    "usr/lib/sysimage/rpm/rpmdb.sqlite",
    "usr/lib/sysimage/rpm/rpmdb.sqlite-shm",
)


def entry(path, kind="file", sha="a" * 64, mode=0o644):
    row = {"path": base64.b64encode(path.encode("utf-8", "surrogateescape")).decode(),
           "kind": kind, "mode": mode}
    if kind == "file": row.update(sha256=sha, size=4)
    if kind == "symlink": row["target"] = base64.b64encode(b"/unrelated").decode()
    if kind in {"char", "block"}: row["rdev"] = 2
    return row


class DnfStateInventoryTests(unittest.TestCase):
    def test_exact_six_regular_files_and_foreign_families(self):
        self.assertEqual(ds.CANONICAL_SIX_PATHS, OBSERVED)
        for path in OBSERVED:
            for family in ("apt", "pacman", "dnf"):
                self.assertEqual(hd.inventory_excluded(family, path, kind="file"), family == "dnf")
            for kind in ("dir", "symlink", "fifo", "socket", "char", "block", "mount"):
                self.assertFalse(hd.inventory_excluded("dnf", path, kind=kind))
                parsed = hd.parse_inventory(_make_framed_payload([entry(path, kind)]), "dnf")
                self.assertIn(path, parsed)
            self.assertNotIn(path, hd.parse_inventory(_make_framed_payload([entry(path)]), "dnf"))
        for path in ("var/lib/dnf/history.sqlite", "var/cache/libdnf5/cache", "var/lib/rpm/rpmdb.sqlite",
                     "var/cache/dnf/cache", "var/lib/rpm-state/state"):
            self.assertTrue(hd.inventory_excluded("dnf", path))

    def test_component_boundaries_and_lossless_malicious_names(self):
        paths = ("usr", "usr/lib", "usr/lib/sysimage", *ds.DNF_STATE_ROOTS,
                 "usr/lib/sysimage/rpm2/rpmdb.sqlite", "usr/lib/sysimage/rpmdb.sqlite",
                 "usr/lib/sysimage/libdnf5x/system.toml", "usr/lib/sysimage/libdnf/system.toml",
                 "usr/lib/sysimage/rpm\n/rpmdb.sqlite", "usr/lib/sysimage/rpm/a\n",
                 "usr/lib/sysimage/rpm/a\\b", "usr\\lib/sysimage/rpm/rpmdb.sqlite",
                 "usr/lib/sysimage/rpm/../elsewhere", "usr/lib/sysimage/rpm/./a",
                 "/usr/lib/sysimage/rpm/a", "./usr/lib/sysimage/rpm/a", "usr/lib/sysimage/rpm//a")
        for path in paths:
            self.assertFalse(ds.is_dnf_state_file(path), repr(path))
        for path in paths:
            if any(component in {"", ".", ".."} for component in path.split("/")):
                with self.assertRaises(ContractError):
                    hd.parse_inventory(_make_framed_payload([entry(path)]), "dnf")
            else:
                parsed = hd.parse_inventory(_make_framed_payload([entry(path)]), "dnf")
                self.assertIn(path, parsed)
        opaque = "usr/lib/sysimage/rpm/\udcff"
        self.assertTrue(ds.is_dnf_state_file(opaque))
        # Byte transport and validation apply before exclusions, including duplicates.
        with self.assertRaises(ContractError):
            hd.parse_inventory(_make_framed_payload([entry(OBSERVED[0]), entry(OBSERVED[0])]), "dnf")

    def test_labeled_synthetic_observed_replay_before_six_after_zero(self):
        before = _make_framed_payload([entry(p) for p in OBSERVED])
        after = _make_framed_payload([entry(p, sha="b" * 64) for p in OBSERVED])
        baseline = lambda raw: ci.parse_inventory(raw, exclusion=lambda p: hd.inventory_excluded("dnf", p), with_modes=True)
        diff = compare_inventories(baseline(before), baseline(after))
        self.assertEqual(diff["added"], [])
        self.assertEqual(diff["removed"], [])
        self.assertEqual(sorted(diff["modified"]), sorted(OBSERVED))
        diff = compare_inventories(hd.parse_inventory(before, "dnf"), hd.parse_inventory(after, "dnf"))
        self.assertTrue(diff["clean"])
        for key in ("added", "removed", "modified"): self.assertEqual(diff[key], [])
        for extra in (entry("usr/lib/theme-forge-stellar-loom/leftover.js"),
                      entry("usr/lib/sysimage/rpm2/rpmdb.sqlite"), entry(OBSERVED[0], "symlink")):
            dirty = hd.parse_inventory(_make_framed_payload([entry(p) for p in OBSERVED
                if base64.b64encode(p.encode()).decode() != extra["path"]] + [extra]), "dnf")
            self.assertFalse(compare_inventories(hd.parse_inventory(before, "dnf"), dirty)["clean"])
        root = ds.DNF_STATE_ROOTS[0]
        self.assertFalse(compare_inventories(
            hd.parse_inventory(_make_framed_payload([entry(root, "dir", mode=0o755)]), "dnf"),
            hd.parse_inventory(_make_framed_payload([entry(root, "dir", mode=0o700)]), "dnf"))["clean"])

    def test_real_scanner_and_real_package_leftover_control(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for path in OBSERVED:
                file = root / path; file.parent.mkdir(parents=True, exist_ok=True); file.write_bytes(b"old")
            before, stats = ci.run_and_parse(root=root, family="dnf", exclusion="dnf", file_exclusion="dnf", with_modes=True, return_diagnostics=True)
            self.assertEqual(stats["counters"]["excluded_files"], 6)
            for path in OBSERVED: (root / path).write_bytes(b"new")
            after = ci.run_and_parse(root=root, family="dnf", exclusion="dnf", file_exclusion="dnf", with_modes=True)
            self.assertTrue(compare_inventories(before, after)["clean"])
            leftover = root / "usr/lib/theme-forge-stellar-loom/leftover.js"
            leftover.parent.mkdir(parents=True); leftover.write_text("package payload")
            dirty = ci.run_and_parse(root=root, family="dnf", exclusion="dnf", file_exclusion="dnf", with_modes=True)
            self.assertIn("usr/lib/theme-forge-stellar-loom/leftover.js", compare_inventories(before, dirty)["added"])
            leftover.unlink()
            state = root / OBSERVED[0]; state.unlink(); state.symlink_to("/never-follow-this-target")
            symlink = ci.run_and_parse(root=root, family="dnf", exclusion="dnf", file_exclusion="dnf", with_modes=True)
            self.assertIn(OBSERVED[0], symlink)
            self.assertTrue(symlink[OBSERVED[0]].startswith("symlink:"))
            self.assertLessEqual(len(__import__("json").loads(ci.scanner_argv(family="dnf")[-1])), 32)

    def test_clean_inventory_never_replaces_exact_absence_query(self):
        product = "theme-forge-stellar-loom"
        class Client:
            last_diagnostics = {"counters": {"excluded_files": 6}}
            def exec(self, argv): return self.query if argv[0] == "rpm" else CommandReceipt(argv, 0, b"", b"", executed=True)
            def inventory(self, stage): return {}
        client = Client()
        for code, text, err, expected in (
                (1, f"package {product} is not installed\n".encode(), b"", "pass"),
                (2, b"rpmdb error\n", b"", "fail"), (1, b"wrong text\n", b"", "fail"),
                (0, b"0.4.0\n", b"", "fail"), (1, f"package {product} is not installed\n".encode(), b"permission denied", "fail")):
            client.query = CommandReceipt(["rpm", "-q"], code, text, err, executed=True)
            gates, evidence = hd._cleanup_installed_client(client, {"arch": "x86_64", "remove": lambda p: ["dnf", "remove", p], "query": lambda p: ["rpm", "-q", p]}, product, "client", {}, "dnf")
            self.assertEqual(gates[0]["status"], expected)
            self.assertEqual(gates[1]["status"], "pass")
            self.assertEqual(evidence["inventory_policy"]["classification"], "package-manager-state")
            self.assertEqual(evidence["inventory_policy"]["roots"], list(ds.DNF_STATE_ROOTS))
            if expected == "fail": self.assertEqual(gates[0]["reason"], "candidate-absence-unproven")

    def test_payload_policy_rejects_canonical_and_legacy_state_members(self):
        for root in ds.DNF_STATE_ROOTS + ds.LEGACY_DNF_ROOTS:
            for kind in ("file", "directory", "symlink"):
                raw, inventory, inputs, policy = complete_case()
                self.assertTrue(evaluate_policy(raw, inventory, inputs, policy)["accepted"])
                path = "/" + root + "/hidden-project-file"
                inventory["files"][path] = {"type": kind, "mode": 0o755, "size": 4, "sha256": "a" * 64}
                result = evaluate_policy(raw, inventory, inputs, policy)
                self.assertFalse(result["accepted"])
                self.assertIn("unexpected-payload-member", result["blockers"])
