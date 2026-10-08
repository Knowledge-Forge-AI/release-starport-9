"""Typed projection and complete bounded chunks reject changed contracts."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from rs9.errors import ContractError
from rs9.records import snapshot
from rs9.release_core import digest
from rs9.rpm_evidence import (durable_lint_projection, validate_durable_lint, policy_chunks,
    policy_summary, assemble_policy_evaluation, write_policy_evidence, verify_policy_custody,
    encode_package_member_paths, decode_package_member_paths)
from rs9.hosted_custody import retain, verify_set, diagnostic_bytes
from rs9.scratch import canonical

FIXTURES = Path(__file__).parent / "fixtures/run10/rpm"


class TestRpmEvidence(unittest.TestCase):
    def inputs(self, system="x86_64-linux"):
        return (json.loads((FIXTURES / system / "raw-lint.json").read_bytes()),
                json.loads((FIXTURES / system / "policy-evaluation.json").read_bytes()))

    def test_raw_failure_exact_reference_and_generic_boundary_unchanged(self):
        for system in ("x86_64-linux", "aarch64-linux"):
            raw, _ = self.inputs(system)
            before = canonical(raw)
            with self.assertRaises(ContractError) as caught:
                snapshot({"evidence": {"rpmlint": raw}})
            self.assertEqual(caught.exception.details["field_path"], "$.evidence.rpmlint.findings[14].message")
            projection = durable_lint_projection(raw)
            snapshot(projection)
            self.assertTrue(validate_durable_lint(projection, raw))
            self.assertEqual(projection["raw_evidence"]["sha256"], digest(before))
            self.assertEqual(projection["raw_evidence"]["size"], len(before))
            self.assertEqual(projection["error_records"], raw["error_records"])
            self.assertEqual(len(projection["error_records"]), 9)
            self.assertFalse(projection["clean"])
            self.assertEqual(projection["tool_receipt"]["exit_code"], 64)
            self.assertNotIn("findings", projection)
            self.assertEqual(canonical(raw), before)

    def test_empty_error_message_requires_exact_argument_hash(self):
        raw, _ = self.inputs()
        record = raw["error_records"][0]
        record["message"] = ""
        with self.assertRaises(ContractError):
            durable_lint_projection(raw)
        record["arguments_sha256"] = digest(b"")
        projection = durable_lint_projection(raw)
        self.assertIsNone(projection["error_records"][0]["message"])
        self.assertEqual(raw["error_records"][0]["message"], "")
        changed = copy.deepcopy(projection)
        changed["clean"] = True
        with self.assertRaises(ContractError):
            validate_durable_lint(changed, raw)

    def test_unknown_raw_nested_and_projection_fields_rejected(self):
        raw, _ = self.inputs()
        for field in ("root", "error", "tool"):
            changed = copy.deepcopy(raw)
            target = changed if field == "root" else changed["error_records"][0] if field == "error" else changed["tool_receipt"]
            target["unknown"] = "unapproved"
            with self.subTest(field=field), self.assertRaises(ContractError):
                durable_lint_projection(changed)
        projection = durable_lint_projection(raw)
        projection["unknown"] = "unapproved"
        with self.assertRaises(ContractError):
            validate_durable_lint(projection, raw)

    def test_full_accepted_and_blocked_evaluations_round_trip_all_sections(self):
        raw, original = self.inputs()
        for accepted in (False, True):
            evaluation = copy.deepcopy(original)
            if accepted:
                evaluation.update(accepted=True, status="accepted", blockers=[],
                    accepted_findings=raw["error_records"], member_proofs=original["observed_error_members"],
                    duplicate_groups=original["observed_duplicate_groups"])
            chunks = policy_chunks(evaluation)
            summary = policy_summary(evaluation, chunks)
            self.assertEqual(assemble_policy_evaluation(summary, chunks), evaluation)
            snapshot(summary)
            self.assertLess(len(canonical(summary)), 16 * 1024)
            self.assertGreater(len(canonical(evaluation)), 64 * 1024)
            self.assertTrue(all(len(canonical(c)) <= 48 * 1024 for c in chunks))
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve()
                scratch = root / "scratch"; scratch.mkdir()
                written, files = write_policy_evidence(scratch, evaluation)
                record = {"lane": "rpm", "system": "x86_64-linux", "runner": {}, "provenance": {}}
                manifest = retain(scratch, root / "custody", files, record)
                self.assertEqual(verify_set(root / "custody"), manifest)
                self.assertEqual(verify_policy_custody(root / "custody", manifest, written), evaluation)
                self.assertNotIn("diagnostic_scan_failures", record)
                for path in files:
                    self.assertEqual(diagnostic_bytes(path), path.read_bytes())

    def test_chunk_and_summary_counterexamples(self):
        _, evaluation = self.inputs()
        chunks = policy_chunks(evaluation)
        summary = policy_summary(evaluation, chunks)
        _, cross_system = self.inputs("aarch64-linux")
        variants = [chunks[:-1], [chunks[1], chunks[0], *chunks[2:]],
                    [*chunks, chunks[-1]], policy_chunks(cross_system)]
        changed = copy.deepcopy(chunks); changed[-1]["items"].append({"forged": True}); variants.append(changed)
        changed = copy.deepcopy(chunks); changed[0]["unknown"] = True; variants.append(changed)
        changed = copy.deepcopy(chunks); changed[0]["part"] = True; variants.append(changed)
        for variant in variants:
            with self.subTest(parts=len(variant)), self.assertRaises(ContractError):
                assemble_policy_evaluation(summary, variant)
        for field, value in (("accepted", True), ("status", "accepted"), ("evaluation_size", 1),
                             ("chunk_count", 1), ("product", "other"), ("chunks", [])):
            changed = copy.deepcopy(summary); changed[field] = value
            with self.subTest(field=field), self.assertRaises(ContractError):
                assemble_policy_evaluation(changed, chunks)

    def test_private_paths_and_credentials_are_never_hidden_by_encoding(self):
        good = {"members": ["/usr/lib/theme-forge-nebular-fusion/node_modules/tmp/index.js"]}
        encoded = encode_package_member_paths(good)
        self.assertEqual(decode_package_member_paths(encoded), good)
        host_path = "/" + "home" + "/" + "person" + "/file"
        for value in ({"path": host_path}, {"path": "/usr/lib/../.." + host_path},
                      {"description": good["members"][0]}, {"path": "/usr/lib/" + "ghp_" + "A" * 36}):
            with self.subTest(keys=list(value)), self.assertRaises(ContractError):
                encode_package_member_paths(value)
        encoded["members"][0]["unknown"] = True
        with self.assertRaises(ContractError):
            decode_package_member_paths(encoded)

    def test_single_over_budget_item_fails_without_truncation(self):
        _, evaluation = self.inputs()
        evaluation["member_proofs"] = [{"path": "/usr/lib/theme-forge-nebular-fusion/" + "a" * 50000}]
        with self.assertRaises(ContractError) as caught:
            policy_chunks(evaluation)
        self.assertEqual(caught.exception.code, "POLICY_CHUNK_LIMIT")
