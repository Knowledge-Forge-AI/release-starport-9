"""Non-admitting matrix fixtures, including real Darwin receipt readback."""
import copy
import unittest
from unittest.mock import patch

from rs9 import tf_pypi_nebular070_universal as frontend
from rs9 import nebular070_universal_consumer as consumer
from rs9.errors import ContractError
import tests.test_nebular070_universal_receipts as fixtures


class UniversalMatrixTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.UniversalConsumerReceiptTests()
        self.fixture.setUp()
        self.source = self.fixture.source
        self.snapshot = self.fixture.snapshot
        self.captures = {target: copy.deepcopy(self.fixture.capture) for target in frontend.builder.LAYOUTS}
        self.positives = {("darwin-arm64", "newer"): self.fixture.value}
        for number, target in enumerate(frontend.LINUX_TARGETS, 1):
            for role in ("floor", "newer"):
                self.positives[target, role] = {
                    "identity": str(number) * 64, "target": target, "role": role,
                    "host_observation": {"identity": str(number + 2) * 64},
                }
        self.negatives = {target: {"identity": "8" * 64} for target in frontend.LINUX_TARGETS}

    def validate(self, captures=None, positives=None, negatives=None):
        return frontend.validate_matrix_receipts(
            self.snapshot, self.captures if captures is None else captures,
            self.positives if positives is None else positives,
            self.negatives if negatives is None else negatives,
            source=self.source, run_id="17", run_attempt="1")

    def reader(self, value, snapshot, capture, **options):
        # Darwin exercises the genuine reader. Synthetic Linux rows test only
        # orchestration; they are explicitly not Linux qualification evidence.
        if options["target"] == "darwin-arm64":
            return self.original(value, snapshot, capture, **options)
        return value

    def test_every_lane_is_revalidated_and_negative_proof_joins_its_floor_host(self):
        self.original = consumer.validate_universal_consumer
        with patch.object(consumer, "validate_universal_consumer", side_effect=self.reader) as read, patch(
                "rs9.nebular070_universal_missing.validate_missing_runtime",
                side_effect=lambda value, **_options: value) as negative:
            result = self.validate()
        self.assertEqual(read.call_count, 5)
        self.assertEqual(negative.call_count, 2)
        self.assertEqual(len(result["lanes"]), 5)
        self.assertFalse(result["publication_admitted"])
        for call in read.call_args_list:
            self.assertEqual(call.args[2], self.captures[call.kwargs["target"]])
            self.assertEqual(call.kwargs["source"], self.source)
            self.assertEqual(call.kwargs["run_id"], "17")
        for call in negative.call_args_list:
            target = call.kwargs["target"]
            self.assertEqual(call.kwargs["host_identity"],
                             self.positives[target, "floor"]["host_observation"]["identity"])

    def test_reauthenticated_darwin_payload_and_resigned_receipt_cannot_be_substituted(self):
        self.original = consumer.validate_universal_consumer
        for mutation in ("payload", "wheel", "source"):
            captures, positives = copy.deepcopy(self.captures), copy.deepcopy(self.positives)
            value = positives["darwin-arm64", "newer"]
            if mutation == "payload": captures["darwin-arm64"]["payload_sha256"] = "0" * 64
            elif mutation == "wheel": value["wheel"]["tag"] = "py3-none-macosx_13_0_arm64"
            else: value["source"]["commit"] = "c" * 40
            positives["darwin-arm64", "newer"] = self.fixture.sign(value)
            with self.subTest(mutation=mutation), patch.object(
                    consumer, "validate_universal_consumer", side_effect=self.reader), patch(
                    "rs9.nebular070_universal_missing.validate_missing_runtime",
                    side_effect=lambda value, **_options: value), self.assertRaises(ContractError):
                self.validate(captures=captures, positives=positives)

    def test_missing_or_surplus_lane_input_is_refused_before_individual_readers(self):
        for mutation in ("capture", "positive", "negative", "extra"):
            captures, positives, negatives = map(copy.deepcopy, (self.captures, self.positives, self.negatives))
            if mutation == "capture": captures.pop("darwin-arm64")
            elif mutation == "positive": positives.pop(("linux-arm64-gnu", "floor"))
            elif mutation == "negative": negatives.pop("linux-x64-gnu")
            else: positives["darwin-arm64", "floor"] = {}
            with self.subTest(mutation=mutation), patch.object(consumer, "validate_universal_consumer") as reader:
                with self.assertRaises(ContractError):
                    self.validate(captures=captures, positives=positives, negatives=negatives)
                reader.assert_not_called()
