"""Forward Nebular provenance reconciliation tests.

The fixtures authenticate real ReleaseCapture objects.  Only the module's
internal reviewed pins are patched for the small synthetic asset bytes; no
public bypass or production selector is introduced.
"""

import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import rs9.nebular_lineage as lineage
from rs9.errors import ContractError
from rs9.profiles import PACKAGE_PROFILE, evaluate_profile, selection_for_intent
from rs9.release_core import authenticate_release, digest
from rs9.scratch import canonical
from tests.shadow_fixtures import fixture_evidence

ROOT = Path(__file__).resolve().parents[1]
FORWARD_RECORD = ROOT / lineage.FORWARD_RECORD_PATH


class NebularLineageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self._fixture_counter = 0
        self.fixture = self._make_fixture()

    def _make_fixture(self):
        self._fixture_counter += 1
        evidence = self.root / ("evidence-" + str(self._fixture_counter))
        intent = fixture_evidence(evidence)
        config = json.loads(FORWARD_RECORD.read_bytes())
        current = config["current"]["commit"]
        tree = config["current"]["tree"]
        historical = config["historical"]["commit"]

        provenance_path = evidence / "assets" / lineage.PROVENANCE_NAME
        provenance = json.loads(provenance_path.read_bytes())
        provenance["release"] = {
            "repository": lineage.CURRENT_REPOSITORY,
            "tag": lineage.CURRENT_TAG,
            "tagTarget": historical,
            "mergedMainCommit": historical,
            "mergedMainTree": tree,
        }
        provenance_path.write_bytes(canonical(provenance))

        assets_dir = evidence / "assets"
        checksum_names = sorted(path.name for path in assets_dir.iterdir()
                                if path.name != "SHA256SUMS")
        (assets_dir / "SHA256SUMS").write_bytes(
            "".join(digest((assets_dir / name).read_bytes()) + "  " + name + "\n"
                    for name in checksum_names).encode()
        )
        asset_names = sorted(path.name for path in assets_dir.iterdir())

        api_repo = json.loads((evidence / "api/repository.json").read_bytes())
        api_repo.update(full_name=lineage.CURRENT_REPOSITORY, id=lineage.CURRENT_REPOSITORY_ID)
        (evidence / "api/repository.json").write_bytes(canonical(api_repo))

        api_ref = json.loads((evidence / "api/ref.json").read_bytes())
        api_ref["object"] = {"type": "commit", "sha": current}
        (evidence / "api/ref.json").write_bytes(canonical(api_ref))
        api_commit = json.loads((evidence / "api/commit.json").read_bytes())
        api_commit["sha"] = current
        api_commit["tree"]["sha"] = tree
        (evidence / "api/commit.json").write_bytes(canonical(api_commit))
        api_tree = json.loads((evidence / "api/tree.json").read_bytes())
        api_tree["sha"] = tree
        (evidence / "api/tree.json").write_bytes(canonical(api_tree))

        api_release = json.loads((evidence / "api/release.json").read_bytes())
        api_release.update(
            id=lineage.CURRENT_RELEASE_ID,
            tag_name=lineage.CURRENT_TAG,
            target_commitish=current,
            published_at="2026-09-30T22:54:44Z",
            draft=False,
            prerelease=False,
        )
        inventory_by_name = {row["name"]: row for row in config["asset_inventory"]}
        selected_names = set(asset_names)
        release_assets = []
        for name in asset_names:
            data = (assets_dir / name).read_bytes()
            expected = inventory_by_name[name]
            release_assets.append({
                "id": expected["id"],
                "name": name,
                "size": len(data),
                "digest": "sha256:" + digest(data),
                "state": "uploaded",
            })
        for expected in config["asset_inventory"]:
            if expected["name"] in selected_names:
                continue
            release_assets.append({
                "id": expected["id"],
                "name": expected["name"],
                "size": 101,
                "digest": "sha256:" + ("0" * 64),
                "state": "uploaded",
            })
        api_release["assets"] = release_assets
        (evidence / "api/release.json").write_bytes(canonical(api_release))

        capture = authenticate_release(selection_for_intent(intent), evidence)
        actual_rows = {
            row["name"]: {
                "id": row["github_asset_id"],
                "name": row["name"],
                "size": row["size"],
                "sha256": row["sha256"],
            }
            for row in capture.record["assets"]
        }
        record = copy.deepcopy(config)
        record["asset_inventory"] = sorted(
            [
                actual_rows[name]
                if name in actual_rows
                else {
                    "id": row["id"],
                    "name": row["name"],
                    "size": 101,
                    "sha256": "0" * 64,
                }
                for name, row in ((row["name"], row) for row in config["asset_inventory"])
            ],
            key=lambda row: row["name"],
        )
        record["provenance_asset"] = next(
            row for row in record["asset_inventory"] if row["name"] == lineage.PROVENANCE_NAME
        )
        repo = self.root / ("repository-" + str(self._fixture_counter))
        record_path = repo / lineage.FORWARD_RECORD_PATH
        record_path.parent.mkdir(parents=True)
        record_path.write_bytes(canonical(record))
        return {
            "evidence": evidence,
            "intent": intent,
            "capture": capture,
            "repo": repo,
            "record": record,
            "record_sha": digest(canonical(record)),
            "provenance_sha": digest(provenance_path.read_bytes()),
            "provenance_size": provenance_path.stat().st_size,
        }


    def _rebind_provenance(self, fixture, mutate):
        provenance_path = fixture["evidence"] / "assets" / lineage.PROVENANCE_NAME
        document = json.loads(provenance_path.read_bytes())
        mutate(document)
        raw = canonical(document)
        provenance_path.write_bytes(raw)

        assets_dir = fixture["evidence"] / "assets"
        checksum_names = sorted(
            path.name for path in assets_dir.iterdir()
            if path.name != "SHA256SUMS"
        )
        (assets_dir / "SHA256SUMS").write_bytes(
            "".join(
                digest((assets_dir / name).read_bytes()) + "  " + name + "\n"
                for name in checksum_names
            ).encode()
        )

        release_path = fixture["evidence"] / "api/release.json"
        release = json.loads(release_path.read_bytes())
        for row in release["assets"]:
            asset_path = assets_dir / row["name"]
            if asset_path.is_file():
                data = asset_path.read_bytes()
                row["size"] = len(data)
                row["digest"] = "sha256:" + digest(data)
        release_path.write_bytes(canonical(release))

        capture = authenticate_release(
            selection_for_intent(fixture["intent"]), fixture["evidence"]
        )
        actual_rows = {
            row["name"]: {
                "id": row["github_asset_id"],
                "name": row["name"],
                "size": row["size"],
                "sha256": row["sha256"],
            }
            for row in capture.record["assets"]
        }
        record = copy.deepcopy(fixture["record"])
        prior_rows = {row["name"]: row for row in record["asset_inventory"]}
        record["asset_inventory"] = sorted(
            [
                actual_rows[name] if name in actual_rows else row
                for name, row in prior_rows.items()
            ],
            key=lambda row: row["name"],
        )
        record["provenance_asset"] = next(
            row for row in record["asset_inventory"]
            if row["name"] == lineage.PROVENANCE_NAME
        )
        record_path = fixture["repo"] / lineage.FORWARD_RECORD_PATH
        record_bytes = canonical(record)
        record_path.write_bytes(record_bytes)
        fixture.update(
            capture=capture,
            record=record,
            record_sha=digest(record_bytes),
            provenance_sha=digest(raw),
            provenance_size=len(raw),
        )
        return fixture

    def _rewrite_record(self, fixture, mutate):
        record = copy.deepcopy(fixture["record"])
        mutate(record)
        record_path = fixture["repo"] / lineage.FORWARD_RECORD_PATH
        record_bytes = canonical(record)
        record_path.write_bytes(record_bytes)
        fixture.update(record=record, record_sha=digest(record_bytes))
        return fixture

    def _pins(self, fixture=None):
        fixture = self.fixture if fixture is None else fixture
        return patch.object(
            lineage,
            "FORWARD_RECORD_SHA256",
            fixture["record_sha"],
        ), patch.object(
            lineage,
            "PROVENANCE_SHA256",
            fixture["provenance_sha"],
        ), patch.object(
            lineage,
            "PROVENANCE_SIZE",
            fixture["provenance_size"],
        )

    def _proof(self):
        capture = self.fixture["capture"]
        with self._pins()[0], self._pins()[1], self._pins()[2]:
            return lineage.build_forward_lineage_proof(
                capture, self.fixture["intent"], self.fixture["repo"]
            )

    def test_reviewed_configuration_loads_unpatched_record(self):
        loaded_root, raw, record = lineage._load_record(ROOT)
        self.assertEqual(loaded_root, ROOT.resolve())
        self.assertEqual(digest(raw), lineage.FORWARD_RECORD_SHA256)
        self.assertEqual(
            record["provenance_asset"],
            {
                "id": lineage.PROVENANCE_ASSET_ID,
                "name": lineage.PROVENANCE_NAME,
                "sha256": lineage.PROVENANCE_SHA256,
                "size": lineage.PROVENANCE_SIZE,
            },
        )

    def test_current_capture_stays_strict_without_proof_and_passes_with_proof(self):
        capture, intent = self.fixture["capture"], self.fixture["intent"]
        profile = intent["release"]["evidence"]["profile"]
        with self.assertRaises(ContractError) as caught:
            evaluate_profile(capture, profile, intent)
        self.assertEqual(caught.exception.code, "PROVENANCE_MISMATCH")

        with self._pins()[0], self._pins()[1], self._pins()[2]:
            proof = lineage.build_forward_lineage_proof(capture, intent, self.fixture["repo"])
            result = evaluate_profile(capture, profile, intent, lineage_correction=proof)
        facts = result["sections"]["forward_lineage"]
        self.assertEqual(facts["current"]["commit"], lineage.CURRENT_COMMIT)
        self.assertEqual(facts["historical"]["commit"], lineage.HISTORICAL_COMMIT)
        self.assertEqual(facts["tree_relation"], "equal")
        self.assertEqual(facts["tree_relation_basis"], "reviewed-record")
        self.assertEqual(len(facts["byte_verified_assets"]), 8)
        self.assertEqual(len(facts["api_digest_only_assets"]), 5)

    def test_historical_capture_keeps_the_unchanged_strict_path(self):
        evidence = self.root / "historical"
        intent = fixture_evidence(evidence)
        capture = authenticate_release(selection_for_intent(intent), evidence)
        self.assertIsNone(lineage.select_forward_lineage_proof(self.root, capture, intent))
        result = evaluate_profile(capture, intent["release"]["evidence"]["profile"], intent)
        self.assertNotIn("forward_lineage", result["sections"])

    def test_proof_is_bound_to_capture_and_rechecks_provenance_bytes(self):
        proof = self._proof()
        capture = self.fixture["capture"]
        with self._pins()[0], self._pins()[1], self._pins()[2]:
            capture.evidence_bytes[lineage.PROVENANCE_NAME] = b"changed"
            with self.assertRaises(ContractError) as caught:
                lineage.verify_forward_lineage_proof(capture, proof, intent=self.fixture["intent"])
        self.assertEqual(caught.exception.code, "LINEAGE_PROVENANCE")

        other = self._make_fixture()
        with self._pins(other)[0], self._pins(other)[1], self._pins(other)[2]:
            other_proof = lineage.build_forward_lineage_proof(
                other["capture"], other["intent"], other["repo"]
            )
            with self.assertRaises(ContractError) as caught:
                lineage.verify_forward_lineage_proof(capture, other_proof, intent=self.fixture["intent"])
        self.assertEqual(caught.exception.code, "LINEAGE_PROOF")

    def test_configuration_mutation_and_inventory_mutation_fail_closed(self):
        proof = self._proof()
        record_path = self.fixture["repo"] / lineage.FORWARD_RECORD_PATH
        record_path.write_bytes(record_path.read_bytes() + b"\n")
        with self._pins()[0], self._pins()[1], self._pins()[2], self.assertRaises(ContractError) as caught:
            lineage.verify_forward_lineage_proof(
                self.fixture["capture"], proof, intent=self.fixture["intent"]
            )
        self.assertEqual(caught.exception.code, "LINEAGE_RECORD")

        broken = self._make_fixture()
        release_path = broken["evidence"] / "api/release.json"
        release = json.loads(release_path.read_bytes())
        release["assets"].append({
            "id": 999999,
            "name": "unexpected.tgz",
            "size": 1,
            "digest": "sha256:" + ("1" * 64),
            "state": "uploaded",
        })
        release_path.write_bytes(canonical(release))
        with self._pins(broken)[0], self._pins(broken)[1], self._pins(broken)[2]:
            broken_capture = authenticate_release(
                selection_for_intent(broken["intent"]), broken["evidence"]
            )
            with self.assertRaises(ContractError) as caught:
                lineage.build_forward_lineage_proof(
                    broken_capture, broken["intent"], broken["repo"]
                )
        self.assertEqual(caught.exception.code, "LINEAGE_CAPTURE")

    def test_package_profile_cannot_consume_forward_proof(self):
        proof = self._proof()
        with self._pins()[0], self._pins()[1], self._pins()[2], self.assertRaises(ContractError) as caught:
            evaluate_profile(
                self.fixture["capture"],
                PACKAGE_PROFILE,
                self.fixture["intent"],
                lineage_correction=proof,
            )
        self.assertEqual(caught.exception.code, "LINEAGE_PROFILE")


    def test_corrected_path_rejects_each_publisher_assertion_mismatch(self):
        for key in ("tagTarget", "mergedMainCommit", "mergedMainTree"):
            with self.subTest(key=key):
                fixture = self._make_fixture()

                def mutate(document, key=key):
                    document["release"][key] = "0" * 40

                self._rebind_provenance(fixture, mutate)
                with (
                    self._pins(fixture)[0],
                    self._pins(fixture)[1],
                    self._pins(fixture)[2],
                    self.assertRaises(ContractError) as caught,
                ):
                    lineage.build_forward_lineage_proof(
                        fixture["capture"], fixture["intent"], fixture["repo"]
                    )
                self.assertEqual(caught.exception.code, "LINEAGE_PROVENANCE")

    def test_corrected_path_requires_each_publisher_assertion(self):
        for key in ("tagTarget", "mergedMainCommit", "mergedMainTree"):
            with self.subTest(key=key):
                fixture = self._make_fixture()

                def mutate(document, key=key):
                    del document["release"][key]

                self._rebind_provenance(fixture, mutate)
                with (
                    self._pins(fixture)[0],
                    self._pins(fixture)[1],
                    self._pins(fixture)[2],
                    self.assertRaises(ContractError) as caught,
                ):
                    lineage.build_forward_lineage_proof(
                        fixture["capture"], fixture["intent"], fixture["repo"]
                    )
                self.assertEqual(caught.exception.code, "LINEAGE_PROVENANCE")

    def test_proof_rejects_same_size_disk_provenance_tamper(self):
        proof = self._proof()
        provenance_path = self.fixture["evidence"] / "assets" / lineage.PROVENANCE_NAME
        original = provenance_path.read_bytes()
        tampered = bytearray(original)
        tampered[0] ^= 1
        self.assertEqual(len(tampered), len(original))
        provenance_path.write_bytes(bytes(tampered))
        with (
            self._pins()[0],
            self._pins()[1],
            self._pins()[2],
            self.assertRaises(ContractError) as caught,
        ):
            lineage.verify_forward_lineage_proof(
                self.fixture["capture"], proof, intent=self.fixture["intent"]
            )
        self.assertEqual(caught.exception.code, "LINEAGE_PROVENANCE")

    def test_corrected_path_preserves_raw_and_executable_checks(self):
        for kind in ("raw", "executable"):
            with self.subTest(kind=kind):
                fixture = self._make_fixture()
                asset_name = fixture["intent"]["assets"][0]["name"]
                selected = next(
                    row for row in fixture["capture"].record["assets"]
                    if row["name"] == asset_name
                )

                def mutate(document, kind=kind, asset_name=asset_name, selected=selected):
                    candidate = {
                        "raw": {
                            "name": asset_name,
                            "sha256": selected["sha256"],
                            "size": selected["size"],
                        },
                        "executableSha256": "0" * 64,
                    }
                    if kind == "raw":
                        candidate["raw"]["sha256"] = "0" * 64
                        candidate["raw"]["size"] = 1
                    document["candidates"] = [candidate]

                self._rebind_provenance(fixture, mutate)
                with self._pins(fixture)[0], self._pins(fixture)[1], self._pins(fixture)[2]:
                    proof = lineage.build_forward_lineage_proof(
                        fixture["capture"], fixture["intent"], fixture["repo"]
                    )
                    with self.assertRaises(ContractError) as caught:
                        evaluate_profile(
                            fixture["capture"],
                            fixture["intent"]["release"]["evidence"]["profile"],
                            fixture["intent"],
                            lineage_correction=proof,
                        )
                self.assertEqual(caught.exception.code, "PROVENANCE_MISMATCH")

    def test_corrected_proof_rechecks_live_bindings(self):
        for case in ("published_at", "api_placeholder"):
            with self.subTest(case=case):
                fixture = self._make_fixture()
                if case == "published_at":
                    def mutate(record):
                        record["release"]["published_at"] = "2026-09-30T22:54:45Z"
                else:
                    selected_names = {
                        row["name"] for row in fixture["capture"].record["assets"]
                    }
                    placeholder_name = next(
                        row["name"]
                        for row in fixture["record"]["asset_inventory"]
                        if row["name"] not in selected_names
                    )

                    def mutate(record, placeholder_name=placeholder_name):
                        row = next(
                            row for row in record["asset_inventory"]
                            if row["name"] == placeholder_name
                        )
                        row["size"] += 1

                self._rewrite_record(fixture, mutate)
                with (
                    self._pins(fixture)[0],
                    self._pins(fixture)[1],
                    self._pins(fixture)[2],
                    self.assertRaises(ContractError) as caught,
                ):
                    lineage.build_forward_lineage_proof(
                        fixture["capture"], fixture["intent"], fixture["repo"]
                    )
                self.assertEqual(caught.exception.code, "LINEAGE_CAPTURE")

        for case in ("intent_tag", "selected_asset", "asset_metadata"):
            with self.subTest(case=case):
                fixture = self._make_fixture()
                with self._pins(fixture)[0], self._pins(fixture)[1], self._pins(fixture)[2]:
                    proof = lineage.build_forward_lineage_proof(
                        fixture["capture"], fixture["intent"], fixture["repo"]
                    )
                    bad_intent = fixture["intent"]
                    if case == "intent_tag":
                        bad_intent = copy.deepcopy(fixture["intent"])
                        bad_intent["tag"] = "v0.6.2"
                    elif case == "selected_asset":
                        fixture["capture"].record["assets"][0]["size"] += 1
                    else:
                        name = fixture["capture"].record["assets"][0]["name"]
                        fixture["capture"].asset_metadata[name]["sha256"] = "0" * 64
                    with self.assertRaises(ContractError) as caught:
                        lineage.verify_forward_lineage_proof(
                            fixture["capture"],
                            proof,
                            intent=bad_intent,
                        )
                expected_code = "INPUT_CHANGED" if case == "selected_asset" else "LINEAGE_CAPTURE"
                self.assertEqual(caught.exception.code, expected_code)


    def test_candidate_capture_generation_emits_forward_lineage_and_hash(self):
        from rs9 import candidate

        fixture = self.fixture
        repo = fixture["repo"]
        (repo / candidate.BOOTSTRAP).parent.mkdir(parents=True, exist_ok=True)
        (repo / candidate.BOOTSTRAP).write_bytes(b"bootstrap-fixture")
        (repo / candidate.EXPECTATIONS).parent.mkdir(parents=True, exist_ok=True)
        (repo / candidate.EXPECTATIONS).write_bytes(
            canonical({"projects": [{"repository": lineage.CURRENT_REPOSITORY}]})
        )
        output = self.root / "candidate-output"
        output.mkdir()
        client = object()
        seen_clients = []

        def fake_capture(selection, target, *, client):
            seen_clients.append(client)

        with (
            self._pins()[0],
            self._pins()[1],
            self._pins()[2],
            patch.object(
                candidate,
                "configuration_rows",
                return_value=[
                    ({"repository": lineage.CURRENT_REPOSITORY}, fixture["intent"])
                ],
            ),
            patch.object(candidate, "capture_release", side_effect=fake_capture),
            patch.object(candidate, "authenticate_release", return_value=fixture["capture"]),
            patch.object(candidate, "assert_release_expectations"),
            patch.object(candidate, "load_bootstrap", return_value=fixture["intent"]),
            patch.object(candidate, "require_configuration_authority"),
            patch.object(candidate, "capture_supplemental"),
        ):
            results = candidate.capture_generation(
                repo,
                output,
                project=fixture["intent"]["project"]["id"],
                client=client,
            )

        profile = results[0][2]
        self.assertIn("forward_lineage", profile["sections"])
        self.assertEqual(seen_clients, [client])
        summary = json.loads(
            (output / "summary" / "authentication.json").read_bytes()
        )
        self.assertEqual(
            summary["projects"][0]["profile_result_sha256"],
            digest(canonical(profile)),
        )

    def test_candidate_capture_generation_omits_empty_lineage_kw(self):
        from rs9 import candidate

        fixture = self.fixture
        repo = fixture["repo"]
        (repo / candidate.BOOTSTRAP).parent.mkdir(parents=True, exist_ok=True)
        (repo / candidate.BOOTSTRAP).write_bytes(b"bootstrap-fixture")
        (repo / candidate.EXPECTATIONS).parent.mkdir(parents=True, exist_ok=True)
        (repo / candidate.EXPECTATIONS).write_bytes(
            canonical({"projects": [{"repository": lineage.CURRENT_REPOSITORY}]})
        )
        output = self.root / "candidate-ordinary-output"
        output.mkdir()
        observed = {}

        def fake_capture(selection, target, *, client):
            observed["client"] = client

        def ordinary_profile(capture, profile, intent, *, corroboration=None):
            observed["corroboration"] = corroboration
            return {"sections": {}}

        with (
            patch.object(
                candidate,
                "configuration_rows",
                return_value=[
                    ({"repository": lineage.CURRENT_REPOSITORY}, fixture["intent"])
                ],
            ),
            patch.object(candidate, "capture_release", side_effect=fake_capture),
            patch.object(candidate, "authenticate_release", return_value=fixture["capture"]),
            patch.object(candidate, "assert_release_expectations"),
            patch.object(candidate, "load_bootstrap", return_value=fixture["intent"]),
            patch.object(candidate, "require_configuration_authority"),
            patch.object(candidate, "select_forward_lineage_proof", return_value=None),
            patch.object(candidate, "capture_supplemental"),
            patch.object(candidate, "evaluate_profile", side_effect=ordinary_profile),
        ):
            candidate.capture_generation(
                repo,
                output,
                project=fixture["intent"]["project"]["id"],
                client=object(),
            )

        self.assertIn("corroboration", observed)

    def test_selector_rejects_current_identity_with_invalid_record(self):
        fixture = self._make_fixture()
        record_path = fixture["repo"] / lineage.FORWARD_RECORD_PATH
        record_path.write_bytes(record_path.read_bytes() + b"\n")
        with (
            self._pins(fixture)[0],
            self._pins(fixture)[1],
            self._pins(fixture)[2],
            self.assertRaises(ContractError) as caught,
        ):
            lineage.select_forward_lineage_proof(
                fixture["repo"], fixture["capture"], fixture["intent"]
            )
        self.assertEqual(caught.exception.code, "LINEAGE_RECORD")


if __name__ == "__main__":
    unittest.main()
