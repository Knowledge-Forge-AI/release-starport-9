"""Opt-in byte reauthentication of the real second release, without a renderer."""
import json
import os
from pathlib import Path
import unittest
import tempfile
from urllib.parse import unquote

from rs9.profiles import evaluate_profile, PACKAGE_PROFILE, selection_for_intent
from rs9.release_core import authenticate_release, capture_release, read_evidence
from rs9.normalizer import normalize
from rs9.scratch import canonical
from tests.shadow_fixtures import ROOT


@unittest.skipUnless(os.environ.get("RS9_STELLAR_BURST_EVIDENCE_DIR"), "live capture directory not supplied")
class LiveStellarTests(unittest.TestCase):
    def test_reauthenticate_live_bytes_and_deterministic_records(self):
        fixture = ROOT / "tests/fixtures/stellar-burst-0.6.1"
        selection = json.loads((fixture / "selection.json").read_bytes())
        capture = authenticate_release(selection, os.environ["RS9_STELLAR_BURST_EVIDENCE_DIR"])
        profile = evaluate_profile(capture, PACKAGE_PROFILE, {"version": "0.6.1", "tag": "v0.6.1", "assets": selection["payload_assets"]},
                                   roles={row["role"]: row["name"] for row in selection["evidence_assets"]})
        self.assertEqual(canonical(capture.record), (fixture / "release-record.json").read_bytes())
        self.assertEqual(canonical(profile), (fixture / "profile-result.json").read_bytes())
        self.assertEqual(capture.record["release"]["id"], 399542205)
        payload = capture.record["payloads"][0]
        self.assertEqual(payload["github_asset_id"], 599265851)
        self.assertEqual(payload["size"], 644313)
        self.assertEqual(payload["sha256"], "53ef41a3de3335e042f2c4b1d299b1155b64bfc6556a84baf6a62cb28bcca209")


@unittest.skipUnless(os.environ.get("RS9_NEBULAR_EVIDENCE_DIR") and os.environ.get("RS9_STELLAR_BURST_EVIDENCE_DIR"), "both live capture directories required")
class LiveCoreCaptureTests(unittest.TestCase):
    def test_both_real_release_captures_replay_through_same_core(self):
        # Replay authenticated public capture bytes at the transport seam. This
        # test performs no network I/O and creates no mutating publisher.
        nebular = json.loads(normalize(ROOT / "examples/theme-forge/theme-forge-nebular-fusion", ROOT / "examples/destinations.example.toml", "0.6.1"))
        stellar = json.loads((ROOT / "tests/fixtures/stellar-burst-0.6.1/selection.json").read_bytes())
        for selection, root in ((selection_for_intent(nebular), Path(os.environ["RS9_NEBULAR_EVIDENCE_DIR"])),
                                (stellar, Path(os.environ["RS9_STELLAR_BURST_EVIDENCE_DIR"]))):
            commit = json.loads(read_evidence(root, "api/commit.json"))
            base = "https://api.github.com/repos/" + selection["repository"]
            endpoints = {base: "repository", base + "/git/ref/tags/" + selection["tag"]: "ref",
                         base + "/git/commits/" + commit["sha"]: "commit",
                         base + "/git/trees/" + commit["tree"]["sha"] + "?recursive=1": "tree",
                         base + "/releases/tags/" + selection["tag"]: "release"}

            class CapturedClient:
                receipts = []

                def json(self, url, **kwargs):
                    return json.loads(read_evidence(root, "api/" + endpoints[url] + ".json"))

                def get(self, url, **kwargs):
                    if url.startswith("https://raw.githubusercontent.com/"):
                        relative = "source/" + unquote(url.split("/" + commit["sha"] + "/", 1)[1])
                    else:
                        relative = "assets/" + unquote(url.rsplit("/", 1)[1])
                    return read_evidence(root, relative, limit=kwargs.get("limit", 16 * 1024 ** 2))

            with tempfile.TemporaryDirectory() as tmp:
                output = Path(tmp).resolve()
                capture_release(selection, output, client=CapturedClient())
                self.assertEqual(canonical(authenticate_release(selection, output).record),
                                 canonical(authenticate_release(selection, root).record))
