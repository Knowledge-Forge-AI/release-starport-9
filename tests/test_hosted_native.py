"""Native preparation cannot manufacture a container digest or signing proof."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from rs9.errors import ContractError
from rs9.hosted_native import provision, get_signing_authority, compare_inventories, execute_probes, is_excluded_inventory_path
from rs9.build_native import CommandReceipt

class NativeHelpersTests(unittest.TestCase):
    def test_exclusions_do_not_fold_backslashes_into_separators(self):
        self.assertTrue(is_excluded_inventory_path("var/log"))
        self.assertFalse(is_excluded_inventory_path("var\\log"))
        self.assertFalse(is_excluded_inventory_path("tmp\\package-owned-leftover"))

    def test_exclusions_newline_descendants_trailing_newlines_and_nonutf8(self):
        # Preserve inherited regex semantics for embedded newline descendants
        self.assertFalse(is_excluded_inventory_path("var/log/file\nwith\nnewlines.log"))
        self.assertFalse(is_excluded_inventory_path("tmp/sub/file\nname"))
        # Inherited dollar anchor accepts one trailing newline
        self.assertTrue(is_excluded_inventory_path("var/log\n"))
        self.assertTrue(is_excluded_inventory_path("tmp\n"))
        self.assertTrue(is_excluded_inventory_path("run\n"))
        self.assertTrue(is_excluded_inventory_path("etc/ld.so.cache\n"))
        # Non-UTF8 surrogateescape
        raw_excluded = b"var/log/raw_\xff\xfe.log".decode("utf-8", errors="surrogateescape")
        raw_non_excluded = b"var/log\xff".decode("utf-8", errors="surrogateescape")
        self.assertTrue(is_excluded_inventory_path(raw_excluded))
        self.assertFalse(is_excluded_inventory_path(raw_non_excluded))

    def test_systematic_exclusion_equivalence_and_newline_descendant_matching(self):
        """Systematically verify every pattern in EXCLUDED_INVENTORY_PATTERNS without sampled guessing."""
        import re
        from rs9.hosted_native import EXCLUDED_INVENTORY_PATTERNS

        legacy_patterns = [
            r"^var/lib/pacman(/.*)?$",
            r"^var/cache/pacman(/.*)?$",
            r"^var/lib/rpm(/.*)?$",
            r"^var/cache/dnf(/.*)?$",
            r"^var/cache/yum(/.*)?$",
            r"^var/cache/ldconfig(/.*)?$",
            r"^etc/ld\.so\.cache$",
            r"^var/log(/.*)?$",
            r"^tmp(/.*)?$",
            r"^run(/.*)?$",
            r"^var/tmp(/.*)?$",
        ]
        legacy_compiled = [re.compile(p) for p in legacy_patterns]

        def legacy_matcher(path: str) -> bool:
            clean = path.lstrip("/").replace("\\", "/")
            return any(p.search(clean) is not None for p in legacy_compiled)

        for pat in EXCLUDED_INVENTORY_PATTERNS:
            base = pat.removeprefix("^").removesuffix("$").replace(r"(/.*)?", "").replace(r"\.", ".")
            has_descendants = r"(/.*)?" in pat

            # 1. Base path itself matches both
            self.assertTrue(is_excluded_inventory_path(base), f"Base path {base} should be excluded")
            self.assertTrue(legacy_matcher(base), f"Legacy base path {base} should match")

            # 2. Strict prefix non-match: base + suffix must NOT match
            suffix_path = base + "_extra"
            self.assertFalse(is_excluded_inventory_path(suffix_path), f"Suffix {suffix_path} must not be excluded")
            self.assertFalse(legacy_matcher(suffix_path), f"Legacy suffix {suffix_path} must not match")

            # 3. Leading directory non-match: prefix + base must NOT match
            prefix_path = "prefix/" + base
            self.assertFalse(is_excluded_inventory_path(prefix_path), f"Prefix path {prefix_path} must not be excluded")
            self.assertFalse(legacy_matcher(prefix_path), f"Legacy prefix path {prefix_path} must not match")

            # 4. Trailing newline: base + '\n' must NOT match
            trailing_nl = base + "\n"
            self.assertTrue(is_excluded_inventory_path(trailing_nl), f"Trailing newline {trailing_nl!r} must not be excluded")

            # 5. Backslash path: backslash is a valid Linux filename character, not a separator
            if "/" in base:
                bs_path = base.replace("/", "\\")
                self.assertFalse(is_excluded_inventory_path(bs_path), f"Backslash path {bs_path} must not be excluded")
                self.assertTrue(legacy_matcher(bs_path))

            if has_descendants:
                # 6. Standard descendant matches both
                child = base + "/child.txt"
                self.assertTrue(is_excluded_inventory_path(child))
                self.assertTrue(legacy_matcher(child))

                # 7. Embedded newline descendants preserve the inherited predicate
                nl_child = base + "/dir\nwith\nnewline/file.txt"
                self.assertFalse(is_excluded_inventory_path(nl_child), f"Newline child {nl_child!r} must be excluded")
                self.assertFalse(legacy_matcher(nl_child), f"Legacy should have failed on newline child {nl_child!r}")

                # 8. Descendant with carriage returns and tabs
                special_child = base + "/dir\r\t/file\r.log"
                self.assertTrue(is_excluded_inventory_path(special_child))

                # 9. Descendant with non-UTF8 surrogate bytes
                raw_surrogate = (base.encode("ascii") + b"/raw_\xff\xfe_data").decode("utf-8", errors="surrogateescape")
                self.assertTrue(is_excluded_inventory_path(raw_surrogate))
            else:
                child = base + "/child.txt"
                self.assertFalse(is_excluded_inventory_path(child))
                self.assertFalse(legacy_matcher(child))

    def test_missing_digest_refused_before_tool_execution(self):
        with self.assertRaises(ContractError):
            provision("rpm","x86_64-linux",{"rpm":{}},runner=object())

    def test_unsigned_inventory_difference_detected(self):
        self.assertTrue(compare_inventories({"file":"a"},{"file":"a"})["clean"])
        self.assertFalse(compare_inventories({"file":"a"},{"file":"b"})["clean"])

    def test_signing_failure_has_no_synthetic_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("rs9.signing_fixture.SigningFixture",side_effect=ContractError("GPG_NOT_AVAILABLE","Unavailable")):
                with self.assertRaises(ContractError):
                    get_signing_authority({},Path(tmp))

    def test_service_uses_protocol_implementation_with_runner_wrapper(self):
        with patch("rs9.hosted_commands.run_probes",return_value=[{"status":"pass"}]) as probe:
            execute_probes("tfsb-studio-service","/usr/bin/tfsb-studio-service",prefix=["docker","exec","-i"],runner=object())
            self.assertEqual(probe.call_args.kwargs["prefix"],["docker","exec","-i"])

    def test_empty_architecture_output_raises_contract_error_not_index_error(self):
        class EmptyArchRunner:
            def run(self, argv, **kw):
                if argv[1] == "pull":
                    return CommandReceipt(argv, 0, b"", b"", executed=True)
                if argv[1] == "run":
                    # Empty output or whitespace-only output must fail closed with CONTAINER_ARCH, never IndexError
                    return CommandReceipt(argv, 0, b"   \n\n", b"", executed=True)
                return CommandReceipt(argv, 0, b"", b"", executed=True)

        pins = {"pacman": {"container_digest": "docker.io/library/archlinux@sha256:" + "a" * 64}}
        with self.assertRaises(ContractError) as caught:
            provision("pacman", "x86_64-linux", pins, runner=EmptyArchRunner())
        self.assertEqual(caught.exception.code, "CONTAINER_ARCH")
        self.assertEqual(caught.exception.details.get("substage"), "architecture")
        self.assertEqual(caught.exception.details.get("tool"), "uname")

    def test_container_provision_failures_have_safe_context_details(self):
        from rs9.errors import safe_details
        class FailingPullRunner:
            def run(self, argv, **kw):
                if argv[1] == "pull":
                    return CommandReceipt(argv, 1, b"error stdout", b"pull failed", executed=True)
                return CommandReceipt(argv, 0, b"", b"", executed=True)

        pins = {"pacman": {"container_digest": "docker.io/library/archlinux@sha256:" + "b" * 64}}
        with self.assertRaises(ContractError) as caught:
            provision("pacman", "x86_64-linux", pins, runner=FailingPullRunner())
        self.assertEqual(caught.exception.code, "CONTAINER_PULL")
        details = caught.exception.details
        self.assertEqual(details.get("substage"), "pull")
        self.assertEqual(details.get("tool"), "docker")
        self.assertEqual(details.get("exit_code"), 1)
        safe = safe_details(details)
        self.assertEqual(safe.get("substage"), "pull")
        self.assertEqual(safe.get("tool"), "docker")
        self.assertEqual(safe.get("exit_code"), 1)
