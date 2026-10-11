"""Adversarial and bounded fake-proc tests for nix_proot_layers.py."""
import hashlib
from pathlib import Path
import tempfile
import unittest
import json
from unittest.mock import patch

from rs9.nix_proot_layers import (
    ALLOWED_CLASSES,
    capture_bounded_stderr,
    categorize_stderr,
    check_layer_survival,
    classify_process_basename,
    observe_descendant_layers,
    parse_proc_stat,
    parse_proc_status,
    parse_sigterm_bits,
    read_process_layer,
)


def make_stat_line(pid: int, comm: str, state: str, ppid: int, pgid: int, sid: int, starttime: int) -> str:
    """Create a syntactically valid /proc/[pid]/stat line with field 22 starttime."""
    # 22 fields: pid (comm) state ppid pgid sid tty tpgid flags minflt cminflt majflt cmajflt utime stime cutime cstime prio nice threads itreal starttime
    rest = [state, str(ppid), str(pgid), str(sid), "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "20", "0", "1", "0", str(starttime)]
    return f"{pid} ({comm}) " + " ".join(rest) + " 0 0 0 0\n"


def make_status_text(sigblk: str = "0000000000000000", sigign: str = "0000000000000000", sigcgt: str = "0000000000000000") -> str:
    return f"Name:\ttest\nState:\tS (sleeping)\nSigBlk:\t{sigblk}\nSigIgn:\t{sigign}\nSigCgt:\t{sigcgt}\n"


class NixProotLayersTests(unittest.TestCase):
    def test_missing_masks_and_private_read_errors_are_unobserved(self):
        self.assertEqual(parse_sigterm_bits({}), {"ignored":None,"caught":None,"blocked":None})
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            with patch("rs9.nix_proot_layers._read_text",side_effect=OSError("private-path-and-user")):
                result=read_process_layer(root,42)
            self.assertEqual(result["status"],"unreadable")
            self.assertNotIn("private-path",json.dumps(result))
            self.assertNotIn(str(root),json.dumps(result))

    def test_anonymous_stderr_and_missing_file_do_not_claim_completeness(self):
        with tempfile.TemporaryFile() as stream:
            stream.write(b"dbus-run-session: unknown message\n");stream.flush()
            result=capture_bounded_stderr(stream)
            self.assertEqual(result["stderr_diagnostic"]["cause_token"],"unclassified")
            self.assertNotIn("excerpt",result["stderr_diagnostic"])
        with tempfile.TemporaryDirectory() as temp:
            self.assertFalse(capture_bounded_stderr(Path(temp)/"missing")["completed"])
    def test_classify_process_basename(self):
        self.assertEqual(classify_process_basename("/usr/bin/sudo"), "sudo")
        self.assertEqual(classify_process_basename("unshare"), "unshare")
        self.assertEqual(classify_process_basename("/bin/setpriv"), "setpriv")
        self.assertEqual(classify_process_basename("/usr/bin/env"), "env")
        self.assertEqual(classify_process_basename("proot"), "proot")
        self.assertEqual(classify_process_basename("python"), "guest-python")
        self.assertEqual(classify_process_basename("/nix/store/.../bin/python3"), "guest-python")
        self.assertEqual(classify_process_basename("python3.12"), "guest-python")
        self.assertEqual(classify_process_basename("bash"), "other")
        self.assertEqual(classify_process_basename("/bin/sh"), "other")
        for cls in ("sudo", "unshare", "setpriv", "env", "proot", "guest-python", "other"):
            self.assertIn(cls, ALLOWED_CLASSES)

    def test_parse_proc_stat_with_special_comm(self):
        line = make_stat_line(42, "python (worker)", "S", 1, 42, 42, 12345)
        parsed = parse_proc_stat(line)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["pid"], 42)
        self.assertEqual(parsed["comm"], "python (worker)")
        self.assertEqual(parsed["state"], "S")
        self.assertEqual(parsed["ppid"], 1)
        self.assertEqual(parsed["pgid"], 42)
        self.assertEqual(parsed["sid"], 42)
        self.assertEqual(parsed["starttime"], 12345)

    def test_parse_proc_stat_malformed(self):
        self.assertIsNone(parse_proc_stat("invalid stat format"))
        self.assertIsNone(parse_proc_stat("1 (comm) S 1 2"))  # too short

    def test_parse_sigterm_bits(self):
        # Bit 14 (SIGTERM) is 1 << 14 = 0x4000
        status = parse_proc_status(make_status_text(sigign="0000000000004000", sigcgt="0000000000004000", sigblk="0000000000000000"))
        bits = parse_sigterm_bits(status)
        self.assertTrue(bits["ignored"])
        self.assertTrue(bits["caught"])
        self.assertFalse(bits["blocked"])

        none_status = parse_proc_status(make_status_text())
        none_bits = parse_sigterm_bits(none_status)
        self.assertFalse(none_bits["ignored"])
        self.assertFalse(none_bits["caught"])
        self.assertFalse(none_bits["blocked"])

    def test_descendant_observation_across_sudo_session_changes(self):
        with tempfile.TemporaryDirectory() as temp:
            proc_root = Path(temp)
            # Root: sudo (pid 1000, ppid 1, sid 1000)
            p1000 = proc_root / "1000"
            p1000.mkdir()
            (p1000 / "stat").write_text(make_stat_line(1000, "sudo", "S", 1, 1000, 1000, 100))
            (p1000 / "status").write_text(make_status_text())

            # Child: unshare in a NEW session (pid 1001, ppid 1000, sid 1001)
            p1001 = proc_root / "1001"
            p1001.mkdir()
            (p1001 / "stat").write_text(make_stat_line(1001, "unshare", "S", 1000, 1001, 1001, 105))
            (p1001 / "status").write_text(make_status_text())

            # Grandchild: proot (pid 1002, ppid 1001, sid 1001)
            p1002 = proc_root / "1002"
            p1002.mkdir()
            (p1002 / "stat").write_text(make_stat_line(1002, "proot", "S", 1001, 1001, 1001, 110))
            (p1002 / "status").write_text(make_status_text(sigign="0000000000004000"))

            # Great-grandchild: python (pid 1003, ppid 1002, sid 1001)
            p1003 = proc_root / "1003"
            p1003.mkdir()
            (p1003 / "stat").write_text(make_stat_line(1003, "python3", "S", 1002, 1001, 1001, 115))
            (p1003 / "status").write_text(make_status_text(sigcgt="0000000000004000"))

            # Unrelated process: pid 9999 (ppid 1, sid 9999)
            p9999 = proc_root / "9999"
            p9999.mkdir()
            (p9999 / "stat").write_text(make_stat_line(9999, "other", "S", 1, 9999, 9999, 50))
            (p9999 / "status").write_text(make_status_text())

            obs = observe_descendant_layers(proc_root, 1000)
            self.assertEqual(obs["status"], "observed")
            self.assertEqual(obs["count"], 4)
            self.assertEqual([p["pid"] for p in obs["layers"]], [1000, 1001, 1002, 1003])
            self.assertEqual([p["basename_class"] for p in obs["layers"]], ["sudo", "unshare", "proot", "guest-python"])
            self.assertEqual(obs["sessions"], [1000, 1001])
            self.assertTrue(obs["separate_sessions"])
            self.assertFalse(obs["limit_exceeded"])

            # Verify no cmdline content was exposed or stored
            for p in obs["layers"]:
                self.assertNotIn("cmdline", p)

            # Check signal bits recorded
            self.assertTrue(obs["layers"][2]["sigterm"]["ignored"])  # proot
            self.assertTrue(obs["layers"][3]["sigterm"]["caught"])   # python3

    def test_survival_recheck_detects_pid_reuse_and_zombies(self):
        with tempfile.TemporaryDirectory() as temp:
            proc_root = Path(temp)
            # Create process 2000
            p2000 = proc_root / "2000"
            p2000.mkdir()
            (p2000 / "stat").write_text(make_stat_line(2000, "proot", "S", 1, 2000, 2000, 500))
            (p2000 / "status").write_text(make_status_text())

            # Create process 2001
            p2001 = proc_root / "2001"
            p2001.mkdir()
            (p2001 / "stat").write_text(make_stat_line(2001, "python3", "S", 2000, 2000, 2000, 505))
            (p2001 / "status").write_text(make_status_text())

            # Observe before delivery
            obs = observe_descendant_layers(proc_root, 2000)
            self.assertEqual(obs["count"], 2)

            # Simulate: 2000 terminates (stat removed)
            (p2000 / "stat").unlink()

            # Simulate: 2001 PID is reused with a different starttime (600 != 505)
            (p2001 / "stat").write_text(make_stat_line(2001, "unrelated", "S", 1, 2001, 2001, 600))

            survival = check_layer_survival(proc_root, obs)
            self.assertEqual(survival["status"], "completed")
            self.assertEqual(survival["survivors"], [])
            self.assertEqual(survival["survivor_count"], 0)

            rec_map = {r["pid"]: r for r in survival["records"]}
            self.assertFalse(rec_map[2000]["survived"])
            self.assertEqual(rec_map[2000]["reason"], "terminated")
            self.assertFalse(rec_map[2001]["survived"])
            self.assertEqual(rec_map[2001]["reason"], "pid-reused")
            self.assertEqual(rec_map[2001]["expected_starttime"], 505)
            self.assertEqual(rec_map[2001]["observed_starttime"], 600)

    def test_survival_recheck_identifies_zombie_as_terminated(self):
        with tempfile.TemporaryDirectory() as temp:
            proc_root = Path(temp)
            p3000 = proc_root / "3000"
            p3000.mkdir()
            (p3000 / "stat").write_text(make_stat_line(3000, "python3", "S", 1, 3000, 3000, 700))
            (p3000 / "status").write_text(make_status_text())

            obs = observe_descendant_layers(proc_root, 3000)
            # Process enters zombie state
            (p3000 / "stat").write_text(make_stat_line(3000, "python3", "Z", 1, 3000, 3000, 700))

            survival = check_layer_survival(proc_root, obs)
            self.assertEqual(survival["survivors"], [])
            self.assertEqual(survival["records"][0]["reason"], "zombie")
            self.assertFalse(survival["records"][0]["survived"])

    def test_unreadable_proc_entries_retained_as_errors(self):
        with tempfile.TemporaryDirectory() as temp:
            proc_root = Path(temp)
            p4000 = proc_root / "4000"
            p4000.mkdir()
            # Malformed stat line that cannot be parsed
            (p4000 / "stat").write_text("corrupted content without parens")
            (p4000 / "status").write_text(make_status_text())

            obs = observe_descendant_layers(proc_root, 4000)
            self.assertEqual(obs["layers"][0]["status"], "unreadable")
            self.assertEqual(obs["layers"][0]["error"], "stat-parse-failed")

            survival = check_layer_survival(proc_root, obs)
            self.assertEqual(len(survival["errors"]), 1)
            self.assertIn("initially unreadable", survival["errors"][0])
            self.assertEqual(survival["status"],"unobserved")
            self.assertIsNone(survival["records"][0]["survived"])

    def test_empty_or_incomplete_layers_cannot_prove_zero_survivors(self):
        for observation in ({}, {"status":"unavailable","layers":[]},
                            {"status":"observed","layers":[],"scan_incomplete":True}):
            with self.subTest(observation=observation):
                result=check_layer_survival(Path("/unavailable-proc"),observation)
                self.assertEqual(result["status"],"unobserved")

    def test_bounded_settle_distinguishes_exiting_and_persistent_layers(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);proc=root/"42";proc.mkdir()
            stat_path=proc/"stat"
            stat_path.write_text(make_stat_line(42,"proot","S",1,42,42,5))
            obs=observe_descendant_layers(root,42)
            sleeps=[]
            def exit_during_settle(seconds):
                sleeps.append(seconds)
                stat_path.unlink()
            result=check_layer_survival(root,obs,sleep=exit_during_settle)
            self.assertEqual(result["status"],"completed")
            self.assertEqual(result["survivor_count"],0)
            self.assertEqual(result["settle_checks"],2)
            self.assertEqual(sleeps,[.1])
            stat_path.write_text(make_stat_line(42,"proot","S",1,42,42,5))
            result=check_layer_survival(root,obs,sleep=sleeps.append)
            self.assertEqual(result["survivors"],[42])
            self.assertEqual(result["settle_checks"],10)
            self.assertEqual(result["observation_phase"],"after-delivery-before-forced-cleanup")

    def test_descendant_count_bound_enforced(self):
        with tempfile.TemporaryDirectory() as temp:
            proc_root = Path(temp)
            # Create a chain of 10 descendants
            for i in range(1, 11):
                p = proc_root / str(i)
                p.mkdir()
                ppid = i - 1 if i > 1 else 1
                (p / "stat").write_text(make_stat_line(i, f"proc{i}", "S", ppid, 1, 1, 100 + i))
                (p / "status").write_text(make_status_text())

            obs = observe_descendant_layers(proc_root, 1, max_descendants=4)
            self.assertEqual(obs["count"], 4)
            self.assertTrue(obs["limit_exceeded"])

    def test_stderr_bounded_capture_and_categorization(self):
        with tempfile.TemporaryDirectory() as temp:
            log_file = Path(temp) / "stderr.log"
            text = (
                "proot info: vpid 1: sysenter\n"
                "proot ERROR: ptrace(PTRACE_ATTACH): Operation not permitted\n"
                "bwrap: No permissions to create new namespace\n"
                "can't chdir to /root: Permission denied\n"
            )
            raw = text.encode("utf-8")
            log_file.write_bytes(raw)

            # Test full capture
            summary = capture_bounded_stderr(log_file, max_bytes=1024)
            self.assertEqual(summary["raw_length"], len(raw))
            self.assertEqual(summary["sha256"], hashlib.sha256(raw).hexdigest())
            self.assertTrue(summary["completed"])
            self.assertFalse(summary["truncated"])
            cats = summary["diagnostic_categories"]
            self.assertEqual(cats, ["conflicting"])
            self.assertNotIn("excerpt", summary["stderr_diagnostic"])

            # Test truncated capture
            trunc_summary = capture_bounded_stderr(log_file, max_bytes=30)
            self.assertEqual(trunc_summary["raw_length"], len(raw))
            self.assertEqual(trunc_summary["sha256"], hashlib.sha256(raw[:30]).hexdigest())
            self.assertEqual(trunc_summary["sha256_scope"], "captured-prefix")
            self.assertEqual(trunc_summary["diagnostic_categories"], ["stream-incomplete"])
            self.assertFalse(trunc_summary["completed"])
            self.assertTrue(trunc_summary["truncated"])


if __name__ == "__main__":
    unittest.main()
