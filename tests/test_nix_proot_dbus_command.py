"""Tests for pinned D-Bus session command generation and validation.

Unit tests verify exact four-argument pinned command structure, strict store
regex validation, co-root identity enforcement, and fail-closed handling of
malicious or malformed inputs. Synthetic representations only; no native runtime
claims are made.
"""
from __future__ import annotations

from types import SimpleNamespace
import unittest

from rs9.errors import ContractError
from rs9.nix_proot_dbus_command import dbus_session_command, validate_session_bus_argv


class NixProotDbusCommandTests(unittest.TestCase):
    """Test suite for dbus_session_command and validate_session_bus_argv."""

    def setUp(self):
        self.store_hash = "00000000000000000000000000001023"
        self.root = f"/nix/store/{self.store_hash}-dbus-1.14.10"
        self.run_session = f"{self.root}/bin/dbus-run-session"
        self.daemon = f"{self.root}/bin/dbus-daemon"
        self.config = f"{self.root}/share/dbus-1/session.conf"
        self.facts_dict = {
            "dbus_run_session": self.run_session,
            "dbus_daemon": self.daemon,
            "dbus_session_config": self.config,
        }
        self.facts_obj = SimpleNamespace(**self.facts_dict)
        self.expected_argv = [
            self.run_session,
            f"--dbus-daemon={self.daemon}",
            f"--config-file={self.config}",
            "--",
        ]

    def test_valid_dict_facts_produces_exact_four_arg_command(self):
        cmd = dbus_session_command(self.facts_dict)
        self.assertEqual(cmd, self.expected_argv)
        self.assertEqual(len(cmd), 4)
        self.assertEqual(cmd[0], self.run_session)
        self.assertEqual(cmd[1], f"--dbus-daemon={self.daemon}")
        self.assertEqual(cmd[2], f"--config-file={self.config}")
        self.assertEqual(cmd[3], "--")

    def test_valid_object_facts_produces_exact_four_arg_command(self):
        cmd = dbus_session_command(self.facts_obj)
        self.assertEqual(cmd, self.expected_argv)

    def test_validate_session_bus_argv_accepts_valid_four_arg_list(self):
        validated = validate_session_bus_argv(self.expected_argv)
        self.assertEqual(validated, self.expected_argv)
        self.assertIsNot(validated, self.expected_argv)  # new list returned

    def test_validate_session_bus_argv_accepts_valid_four_arg_tuple(self):
        validated = validate_session_bus_argv(tuple(self.expected_argv))
        self.assertEqual(validated, self.expected_argv)
        self.assertIsInstance(validated, list)

    def test_missing_facts_object_rejected(self):
        with self.assertRaises(ContractError) as caught:
            dbus_session_command(None)
        self.assertEqual(caught.exception.code, "NIX_PROOT_DBUS")

    def test_empty_facts_rejected(self):
        with self.assertRaises(ContractError) as caught:
            dbus_session_command({})
        self.assertEqual(caught.exception.code, "NIX_PROOT_DBUS")

    def test_facts_missing_individual_keys_rejected(self):
        for missing_key in ("dbus_run_session", "dbus_daemon", "dbus_session_config"):
            with self.subTest(missing_key=missing_key):
                bad_facts = dict(self.facts_dict)
                del bad_facts[missing_key]
                with self.assertRaises(ContractError) as caught:
                    dbus_session_command(bad_facts)
                self.assertEqual(caught.exception.code, "NIX_PROOT_DBUS")

    def test_facts_non_string_values_rejected(self):
        for bad_val in (123, None, ["path"], {"a": 1}):
            with self.subTest(bad_val=bad_val):
                bad_facts = dict(self.facts_dict)
                bad_facts["dbus_daemon"] = bad_val
                with self.assertRaises(ContractError) as caught:
                    dbus_session_command(bad_facts)
                self.assertEqual(caught.exception.code, "NIX_PROOT_DBUS")

    def test_co_root_daemon_mismatch_rejected(self):
        other_root = f"/nix/store/{'a'*32}-dbus-1.14.10"
        bad_facts = dict(self.facts_dict)
        bad_facts["dbus_daemon"] = f"{other_root}/bin/dbus-daemon"
        with self.assertRaises(ContractError) as caught:
            dbus_session_command(bad_facts)
        self.assertEqual(caught.exception.code, "NIX_PROOT_DBUS")

    def test_co_root_config_mismatch_rejected(self):
        other_root = f"/nix/store/{'b'*32}-dbus-1.14.10"
        bad_facts = dict(self.facts_dict)
        bad_facts["dbus_session_config"] = f"{other_root}/share/dbus-1/session.conf"
        with self.assertRaises(ContractError) as caught:
            dbus_session_command(bad_facts)
        self.assertEqual(caught.exception.code, "NIX_PROOT_DBUS")

    def test_host_daemon_path_rejected(self):
        bad_facts = dict(self.facts_dict)
        bad_facts["dbus_daemon"] = "/usr/bin/dbus-daemon"
        with self.assertRaises(ContractError) as caught:
            dbus_session_command(bad_facts)
        self.assertEqual(caught.exception.code, "NIX_PROOT_DBUS")

    def test_host_config_path_rejected(self):
        bad_facts = dict(self.facts_dict)
        bad_facts["dbus_session_config"] = "/etc/dbus-1/session.conf"
        with self.assertRaises(ContractError) as caught:
            dbus_session_command(bad_facts)
        self.assertEqual(caught.exception.code, "NIX_PROOT_DBUS")

    def test_wrong_binary_subpath_rejected(self):
        bad_facts = dict(self.facts_dict)
        bad_facts["dbus_run_session"] = f"{self.root}/bin/dbus-daemon"
        with self.assertRaises(ContractError) as caught:
            dbus_session_command(bad_facts)
        self.assertEqual(caught.exception.code, "NIX_PROOT_DBUS")

    def test_wrong_daemon_subpath_rejected(self):
        bad_facts = dict(self.facts_dict)
        bad_facts["dbus_daemon"] = f"{self.root}/bin/other-daemon"
        with self.assertRaises(ContractError) as caught:
            dbus_session_command(bad_facts)
        self.assertEqual(caught.exception.code, "NIX_PROOT_DBUS")

    def test_wrong_config_subpath_rejected(self):
        bad_facts = dict(self.facts_dict)
        bad_facts["dbus_session_config"] = f"{self.root}/etc/dbus-1/session.conf"
        with self.assertRaises(ContractError) as caught:
            dbus_session_command(bad_facts)
        self.assertEqual(caught.exception.code, "NIX_PROOT_DBUS")

    def test_noncanonical_paths_with_traversal_rejected(self):
        traversals = [
            f"{self.root}/bin/../bin/dbus-run-session",
            f"/nix/store/../nix/store/{self.store_hash}-dbus-1.14.10/bin/dbus-run-session",
            f"{self.root}/bin/./dbus-run-session",
            f"//{self.root}/bin/dbus-run-session",
            f"{self.root}/bin/dbus-run-session/",
        ]
        for bad_path in traversals:
            with self.subTest(bad_path=bad_path):
                bad_facts = dict(self.facts_dict)
                bad_facts["dbus_run_session"] = bad_path
                with self.assertRaises(ContractError) as caught:
                    dbus_session_command(bad_facts)
                self.assertEqual(caught.exception.code, "NIX_PROOT_DBUS")

    def test_store_hash_validation_rejected_non_base32_and_lengths(self):
        invalid_hashes = [
            "0000000000000000000000000000102",    # 31 chars
            "000000000000000000000000000010234",  # 33 chars
            "0000000000000000000000000000102e",   # 'e' not in nix base32
            "0000000000000000000000000000102o",   # 'o' not in nix base32
            "0000000000000000000000000000102u",   # 'u' not in nix base32
            "0000000000000000000000000000102t",   # 't' not in nix base32
            "0000000000000000000000000000102A",   # uppercase 'A'
        ]
        for bad_hash in invalid_hashes:
            with self.subTest(bad_hash=bad_hash):
                bad_root = f"/nix/store/{bad_hash}-dbus-1.14.10"
                bad_facts = {
                    "dbus_run_session": f"{bad_root}/bin/dbus-run-session",
                    "dbus_daemon": f"{bad_root}/bin/dbus-daemon",
                    "dbus_session_config": f"{bad_root}/share/dbus-1/session.conf",
                }
                with self.assertRaises(ContractError) as caught:
                    dbus_session_command(bad_facts)
                self.assertEqual(caught.exception.code, "NIX_PROOT_DBUS")

    def test_control_and_shell_injection_rejected(self):
        malicious_vectors = [
            f"{self.root}/bin/dbus-run-session;rm -rf /",
            f"{self.root}/bin/dbus-run-session && true",
            f"{self.root}/bin/dbus-run-session | sh",
            f"{self.root}/bin/dbus-run-session `id`",
            f"{self.root}/bin/dbus-run-session $(whoami)",
            f"{self.root}/bin/dbus-run-session\x00",
            f"{self.root}/bin/dbus-run-session\n",
            f"{self.root}/bin/dbus-run-session\r",
            f"{self.root}/bin/dbus-run-session\t",
            f"{self.root}/bin/dbus-run-session --bad",
            f"{self.root}/bin/dbus-run-session'quoted'",
            f'{self.root}/bin/dbus-run-session"double"',
            f"{self.root}/bin/dbus-run-session\\escape",
            f"{self.root}/bin/dbus-run-session*glob",
            f"{self.root}/bin/dbus-run-session?glob",
        ]
        for vector in malicious_vectors:
            with self.subTest(vector=vector):
                bad_facts = dict(self.facts_dict)
                bad_facts["dbus_run_session"] = vector
                with self.assertRaises(ContractError) as caught:
                    dbus_session_command(bad_facts)
                self.assertEqual(caught.exception.code, "NIX_PROOT_DBUS")

    def test_validate_session_bus_argv_strict_argument_count(self):
        counts = [
            [],
            [self.run_session],
            [self.run_session, f"--dbus-daemon={self.daemon}"],
            ["dbus-run-session", "--"],  # legacy 2-arg default
            [self.run_session, f"--dbus-daemon={self.daemon}", f"--config-file={self.config}"],  # 3 args, missing --
            [*self.expected_argv, "--extra-flag"],  # 5 args
        ]
        for argv in counts:
            with self.subTest(argv=argv):
                with self.assertRaises(ContractError) as caught:
                    validate_session_bus_argv(argv)
                self.assertEqual(caught.exception.code, "NIX_PROOT_DBUS")

    def test_validate_session_bus_argv_flag_structure(self):
        bad_flags = [
            # Wrong flag name for daemon
            [self.run_session, f"--daemon={self.daemon}", f"--config-file={self.config}", "--"],
            # Daemon without '='
            [self.run_session, f"--dbus-daemon", f"--config-file={self.config}", "--"],
            # Wrong flag name for config
            [self.run_session, f"--dbus-daemon={self.daemon}", f"--config={self.config}", "--"],
            # Config without '='
            [self.run_session, f"--dbus-daemon={self.daemon}", f"--config-file", "--"],
            # 4th argument not '--'
            [self.run_session, f"--dbus-daemon={self.daemon}", f"--config-file={self.config}", "--sh-syntax"],
            [self.run_session, f"--dbus-daemon={self.daemon}", f"--config-file={self.config}", "node"],
        ]
        for argv in bad_flags:
            with self.subTest(argv=argv):
                with self.assertRaises(ContractError) as caught:
                    validate_session_bus_argv(argv)
                self.assertEqual(caught.exception.code, "NIX_PROOT_DBUS")


if __name__ == "__main__":
    unittest.main()
