"""Explicit offline audit of genuine Nebular 071 public-input evidence.

Required roots contain genuine held product/native data and the released
current source proof. No fixture path, network fallback, native launch, skip or discovery
policy is supplied here. The ten evidence checks complement 27 ordinary unit
checks; neither set is hosted native qualification.
"""
from __future__ import annotations
import argparse
import copy
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests")]
from rs9 import nebular071_product_capture as product
from rs9 import nebular071_product_native as native
from rs9 import nebular071_smoke_support as support
from rs9 import nebular071_consumer_core as core
from rs9 import nebular071_universal_consumer as consumer
from rs9 import nebular071_universal_workflow as workflow
from rs9 import nebular071_public_inputs as transport
from rs9 import tf_pypi_nebular071_publish as publisher
from rs9 import tf_pypi_nebular071_universal as universal
from rs9.errors import ContractError
from rs9.materialize import validate_ancestry_not_symlink
from rs9.release_core import read_evidence
from rs9.scratch import canonical, physical_directory
from rs9.tf_pypi_archive import AdmissionError
from rs9.tf_pypi_model import strict_json
from test_nebular071_product_native import metadata
from test_nebular071_complete_owner_chain import (_build_complete_fixture, _git_output_stub,
                                                _generated_command, _SyntheticGitHubClient)

INRUN_ROOT = GENUINE_CAPTURE = FIXTURE = PUBLIC_ASSETS_ROOT = SOURCE_PROOF_ROOT = None
smoke_support = support


def genuine_capture():
    if INRUN_ROOT is None:
        raise RuntimeError("Explicit validated in-run evidence is required")
    # Replay the real held selection/API/seven-body authenticator. A summary
    # dictionary, caller-asserted pass or persisted frame is never a capability.
    return product.load_held_product_capture(INRUN_ROOT)


def api_bodies():
    return [strict_json(read_evidence(FIXTURE, "api/" + n, limit=1024 * 1024)) for n in
            ("run.json", "jobs.json", "compiler-commit.json", "artifacts.json")]


def sha(body):
    return hashlib.sha256(body).hexdigest()


def entry(path, body):
    return {"path": path, "size": len(body), "sha256": sha(body)}


def genuine_boundary_fixture(base):
    fx = _build_complete_fixture(base)
    capture = genuine_capture()
    frame = consumer.authenticated_product_release(capture)
    source = frame["source"]
    repo = fx["repo_dir"]
    api_root = GENUINE_CAPTURE / "evidence/api"
    asset_root = GENUINE_CAPTURE / "evidence/assets"
    api = {n: json.loads((api_root / (n + ".json")).read_bytes())
           for n in ("repository", "release", "ref", "tags", "commit", "tree")}
    prefix = "https://api.github.com/repos/" + product.PRODUCT_REPOSITORY
    fx["api_map"] = {prefix: api["repository"], prefix + "/releases/tags/v0.7.1": api["release"],
                     prefix + "/git/ref/tags/v0.7.1": api["ref"],
                     prefix + "/git/commits/" + source["commit"]: api["commit"],
                     prefix + "/git/trees/" + source["tree"] + "?recursive=1": api["tree"]}
    for tag in api["tags"]:
        fx["api_map"][prefix + "/git/tags/" + tag["sha"]] = tag
    native_api = {n: json.loads((FIXTURE / "api" / n).read_bytes()) for n in native._API_PINS}
    fx["api_map"].update({prefix + "/actions/runs/41176311998/attempts/1": native_api["run.json"],
        prefix + "/actions/runs/41176311998/attempts/1/jobs?per_page=100": native_api["jobs.json"],
        prefix + "/git/commits/" + native.reference()["tested_commit"]: native_api["compiler-commit.json"],
        prefix + "/actions/runs/41176311998/artifacts?per_page=100": native_api["artifacts.json"]})
    fx["asset_map"] = {}
    assets = {a["name"]: a for a in api["release"]["assets"]}
    def asset_body(n):
        path = asset_root / n
        if not path.is_file():
            path = PUBLIC_ASSETS_ROOT / n
        body = path.read_bytes()
        a = assets[n]
        assert len(body) == a["size"] and sha(body) == a["digest"].removeprefix("sha256:")
        fx["asset_map"][a["browser_download_url"]] = body
        fx["asset_map"][a["url"]] = body
        return body
    bodies = {n: asset_body(n) for n in product.expected_asset_names()}
    wrapper_name = "knowledge-forge-ai-theme-forge-nebular-fusion-0.7.1.tgz"
    wrapper = asset_body(wrapper_name)
    notices_name = "nebular-v0.7.1-third-party-notices.tar.gz"
    notices = asset_body(notices_name)
    source_name = "theme-forge-nebular-fusion-v0.7.1-source.tar.gz"
    authority_name = "nebular-compiled-public-build-source-authority-v0.7.1.json"
    prov_name = "nebular-v0.7.1-native-ci-provenance.json"
    source_bodies = {}
    tool_paths = {"tools/" + n for n in support._REQUIRED_TOOLS}
    closure_paths = tool_paths | support._REQUIRED_FIXTURES | {"package.json"}
    needed = closure_paths | {"LICENSE", "NOTICE", "COMMERCIAL-LICENSE.md"}
    with tarfile.open(fileobj=io.BytesIO(bodies[source_name]), mode="r:gz") as archive:
        for member in archive:
            if member.name in needed:
                source_bodies[member.name] = archive.extractfile(member).read()
    assert set(source_bodies) == needed
    raw_names = {r["name"] for r in product.product_selection()["payload_assets"]}
    evidence = {"api/" + n + ".json": (api_root / (n + ".json")).read_bytes() for n in api}
    evidence.update({"assets/" + n: b for n, b in bodies.items() if n not in raw_names})
    evidence["assets/PROVENANCE.json"] = bodies[prov_name]
    evidence["assets/" + notices_name] = notices
    # Preserve the genuine transported wrapper-registry body in real fixture mode.
    evidence["npm/metadata.json"] = read_evidence(INRUN_ROOT, "evidence/public-release/npm/metadata.json", limit=8 * 1024 * 1024)
    for n, b in source_bodies.items():
        evidence["source-files/" + n] = b
    for n in ("LICENSE", "NOTICE", "COMMERCIAL-LICENSE.md"):
        evidence["source/" + n] = source_bodies[n]
    names = ["rc-index-original.zip", "native-reference.json", "artifact-metadata.json"]
    names += ["api/" + n for n in native._API_PINS] + list(native._ORIGINAL_PINS)
    for n in names:
        evidence["native-ci/" + n] = (FIXTURE / n).read_bytes()
    ev_files = {n: entry(n, b) for n, b in evidence.items()}
    ev_files["npm/package.tgz"] = entry("npm/package.tgz", wrapper)
    ev_files["assets/" + wrapper_name] = entry("assets/" + wrapper_name, wrapper)
    raw = {"record.json": canonical(capture.record), "README.md": b"Public release input fixture.\n",
           "PROVENANCE.json": bodies[prov_name],
           **{n: source_bodies[n] for n in ("LICENSE", "NOTICE", "COMMERCIAL-LICENSE.md")}}
    descriptor = copy.deepcopy(fx["descriptor_doc"])
    binding = descriptor["release_binding"]
    binding["expected"].update(repository_id=frame["repository"]["id"], release_id=frame["release_id"],
                               tag_commit=source["commit"], tag_tree=source["tree"])
    descriptor["release_binding_sha256"] = sha(publisher.canonical(binding))
    descriptor["evidence"]["files"] = ev_files
    pins_path = repo / universal.RUNTIME_INPUTS
    pins = json.loads(pins_path.read_bytes())
    pins["upstream_release"].update(commit=source["commit"], tree=source["tree"])
    for target, triple in product.RAW_PAYLOAD_TRIPLES.items():
        n = "theme-forge-nebular-fusion-v0.7.1-" + triple + ".tar.gz"
        a = assets[n]
        manifest = capture.manifests[target]
        raw_manifest = canonical(manifest["members"])
        raw[target + "-manifest.json"] = raw_manifest
        spec = pins["targets"][target]
        spec["asset"] = {"id": a["id"], "name": n, "size": a["size"],
                         "sha256": a["digest"].removeprefix("sha256:"), "url": a["browser_download_url"]}
        spec["manifest_sha256"] = manifest["manifest_sha256"]
        row = descriptor["raw_release"]["targets"][target]
        row.update(product_source=source, record=entry("record.json", raw["record.json"]),
                   readme=entry("README.md", raw["README.md"]), provenance=entry("PROVENANCE.json", raw["PROVENANCE.json"]),
                   payload={**entry("assets/" + n, bodies[n]), "name": n},
                   manifest=entry(target + "-manifest.json", raw_manifest),
                   legal_files={k: entry(k, source_bodies[k]) for k in ("LICENSE", "NOTICE", "COMMERCIAL-LICENSE.md")})
        nc = row["native_consumer"][target]
        closure = nc["smoke_support"]
        closure["source"] = source
        closure["files"] = [{"path": k, "size": len(b), "sha256": sha(b),
                             "blob": hashlib.sha1(b"blob " + str(len(b)).encode() + b"\0" + b).hexdigest(),
                             "role": support._expected_role(k, tool_root="tools", fixture_root="docs/examples/v0.4/brand-system/core-minimal"),
                             "evidence_path": "source-files/" + k}
                            for k, b in sorted(source_bodies.items()) if k in closure_paths]
        closure["source_binding"] = {kind: {**entry(k, bodies[k]), "evidence_path": "assets/" + k}
                                     for kind, k in (("archive", source_name), ("authority", authority_name))}
        closure["closure_sha256"] = support._closure_digest(closure)
        by_path = {r["path"]: r for r in manifest["members"]}
        roles = core._nebular_native_role_paths(target, manifest)
        if target == "darwin-arm64":
            qbody = (FIXTURE / "darwin-arm64/qualification.json").read_bytes()
            q = json.loads(qbody)
            raw["darwin-qualification.json"] = qbody
            nc["qualification"] = entry("darwin-qualification.json", qbody)
            nc["loader"].update(path=roles["launcher"], sha256=by_path[roles["launcher"]]["sha256"])
            receipts = {}
            for channel in ("raw-archive", "npm-package"):
                label = "darwin-arm64-A-" + channel
                for kind in ("run", "receipt"):
                    b = (FIXTURE / ("darwin-arm64/smoke/" + label + "." + kind + ".json")).read_bytes()
                    path = "darwin-" + channel + "-" + kind + ".json"
                    raw[path] = b
                    nc["smoke"][channel][kind] = entry(path, b)
                    if kind == "receipt":
                        receipts[channel] = sha(b)
            detail = next(r["detail"] for r in q["checks"] if r["id"] == "sidecar-runtime")
            pe = {"qualification_sha256": sha(qbody), "qualification_check_id": "sidecar-runtime",
                  "qualification_detail_sha256": sha(publisher.canonical(detail)), "smoke_receipts": receipts}
            nc["provider_closure"]["evidence_sha256"] = sha(publisher.canonical(pe))
        else:
            nc["archive"] = {"payload": {"name": n, "size": a["size"], "sha256": spec["asset"]["sha256"]},
                             "manifest": entry(target + "-manifest.json", raw_manifest)}
            nc["members"] = {r: {k: by_path[roles[r]][k] for k in ("path", "size", "mode", "sha256")}
                             for r in ("gui", "launcher", "sidecar")}
    pins_path.write_bytes(canonical(pins))
    files = {"qualification-inputs.json": canonical(descriptor),
             **{"evidence/public-release/" + n: b for n, b in evidence.items()},
             **{"raw-release/" + n: b for n, b in raw.items()}}
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for n, b in sorted(files.items()):
            info = tarfile.TarInfo(n)
            info.size, info.mode = len(b), 0o644
            archive.addfile(info, io.BytesIO(b))
    metadata_body = gzip.compress(stream.getvalue(), mtime=0)
    manifest = fx["manifest_doc"]
    manifest["release_id"] = frame["release_id"]
    # Future additive metadata delivery is simulated only in this temporary
    # test. No operator manifest, metadata asset or qualification is minted.
    meta = manifest["metadata"]
    meta.update(bytes=len(metadata_body), sha256=sha(metadata_body))
    fx["asset_map"][meta["url"]] = metadata_body
    manifest["payloads"] = [{"asset_id": assets[n]["id"], "name": n,
        "url": assets[n]["browser_download_url"], "bytes": len(bodies[n]),
        "sha256": sha(bodies[n]), "path": "raw-release/assets/" + n} for n in sorted(raw_names)]
    wa = assets[wrapper_name]
    manifest["payloads"].append({"asset_id": wa["id"], "name": wrapper_name,
        "url": wa["browser_download_url"], "bytes": len(wrapper), "sha256": sha(wrapper),
        "path": "evidence/public-release/assets/" + wrapper_name})
    (repo / fx["manifest_rel"]).write_bytes(canonical(manifest))
    return fx


class BeforeNative(Exception):
    pass


class GenuineBoundary071Tests(unittest.TestCase):
    def test_prepare_real_typed_replay_capture_and_rendered_qualify_native_boundary(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            fx = genuine_boundary_fixture(base)
            runner = base / "runner"
            runner.mkdir()
            repo = fx["repo_dir"]
            rendered = workflow.qualify_jobs_text()
            def argv(marker, mode):
                tokens = _generated_command(rendered, marker)
                result = []
                for token in tokens:
                    for old, new in (("${{ runner.temp }}", str(runner)),
                                     ("${{ steps.rs9_source.outputs.commit }}", fx["rs9_source"]["commit"]),
                                     ("${{ steps.rs9_source.outputs.tree }}", fx["rs9_source"]["tree"]),
                                     ("${{ github.sha }}", fx["rs9_source"]["commit"]),
                                     ("${{ github.run_id }}", fx["run_id"]), ("${{ github.run_attempt }}", "1"),
                                     ("$(git rev-parse --verify HEAD^{tree})", fx["rs9_source"]["tree"]),
                                     ("$(git rev-parse --verify 'HEAD^{tree}')", fx["rs9_source"]["tree"]),
                                     ("$GITHUB_WORKSPACE", str(repo))):
                        token = token.replace(old, new)
                    result.append(token)
                return result[result.index(mode):]
            client = _SyntheticGitHubClient(fx["api_map"], fx["asset_map"])
            env = {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": universal.REPOSITORY,
                   "GITHUB_REF": "refs/heads/main", "GITHUB_SHA": fx["rs9_source"]["commit"],
                   "GITHUB_RUN_ID": fx["run_id"], "GITHUB_RUN_ATTEMPT": "1"}
            observed = []
            real_capture = consumer.capture_universal_runtime
            def capture_spy(*args, **kwargs):
                result = real_capture(*args, **kwargs)
                observed.append(result)
                return result
            with mock.patch.object(publisher, "_git_output", side_effect=_git_output_stub(fx["rs9_source"])), \
                 mock.patch.object(product, "public_client", return_value=client), \
                 mock.patch.object(Path, "cwd", return_value=repo), mock.patch.dict(os.environ, env), \
                 mock.patch("sys.stdout", new_callable=io.StringIO), \
                 mock.patch.object(consumer, "capture_universal_runtime", side_effect=capture_spy):
                self.assertEqual(publisher.main(argv("-m rs9.tf_pypi_nebular071_publish prepare-public-inputs-071", "prepare-public-inputs-071")), 0)
                buf = mock.Mock()
                buf.buffer = io.BytesIO()
                with mock.patch("sys.stdout", buf):
                    self.assertEqual(universal.main(argv("-m rs9.tf_pypi_nebular071_universal build-bundle", "build-bundle")), 0)
                with mock.patch.object(core, "_nebular_identity_observed", side_effect=BeforeNative("stop before host/native work")):
                    with self.assertRaises(BeforeNative):
                        universal.main(argv("-m rs9.tf_pypi_nebular071_universal qualify-native", "qualify-native"))
            self.assertEqual(len(observed), 1)
            joined = observed[0]["release_join"]
            self.assertEqual(joined["product"]["commit"], native.FINAL_COMMIT)
            self.assertEqual(joined["product_native"]["reference"]["run_id"], 41176311998)
            self.assertNotIn("rs9_qualification", joined)
            self.assertEqual(joined["compiler"]["relation"], "authenticated-equal-tree")
            held = Path(observed[0]["product_capture"].root).parent.parent
            active = product.load_held_product_capture(held)
            descriptor = json.loads((held / publisher.PUBLIC_INPUTS_DESCRIPTOR).read_bytes())
            native.replay_descriptor_native(descriptor, held, active)
            for change in ("missing", "hash"):
                broken = copy.deepcopy(descriptor)
                key = "native-ci/linux-x64/qualification.json"
                if change == "missing":
                    del broken["evidence"]["files"][key]
                else:
                    broken["evidence"]["files"][key]["sha256"] = "0" * 64
                from rs9.errors import ContractError
                with self.assertRaises(ContractError):
                    native.replay_descriptor_native(broken, held, active)


_sha = sha

class NativeCatalog071Checks(unittest.TestCase):
    def test_original_catalog_exact_single_member(self):
        body = (FIXTURE / "rc-index-original.zip").read_bytes()
        index = native.catalog_index(body)
        self.assertEqual(index["source"]["runId"], "41176311998")
        self.assertEqual(index["selected"], ["macos-arm64", "linux-arm64", "linux-x64"])
        for bad in (body + b"x", bytes([body[0] ^ 1]) + body[1:]):
            with self.assertRaises(ContractError):
                native.catalog_index(bad)
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("rc-index.json", canonical(index))
            archive.writestr("extra.json", b"{}")
        with self.assertRaises(ContractError):
            native.catalog_index(stream.getvalue())

    def test_actual_official_api_context_and_simulated_negative_responses(self):
        values = api_bodies()
        self.assertEqual(set(native._apis(*values)), {13032699957, 13032957569, 13033139137, 13033108750})
        mutations = (
            lambda v: v[0].update(run_attempt=2),
            lambda v: v[0].update(run_attempt=True),
            lambda v: v[0].update(workflow_id=1),
            lambda v: v[0].update(path=".github/workflows/other.yml"),
            lambda v: v[0]["repository"].update(full_name="Knowledge-Forge-AI/release-starport-9"),
            lambda v: v[1]["jobs"][1].update(conclusion="failure"),
            lambda v: v[1]["jobs"].pop(),
            lambda v: v[2]["tree"].update(sha="0" * 40),
            lambda v: v[3]["artifacts"][0].update(expired=True),
            lambda v: v[3]["artifacts"][0].update(digest="sha256:" + "0" * 64),
            lambda v: v[3]["artifacts"][0].update(expires_at="2000-01-01T00:00:00Z"),
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                bad = copy.deepcopy(values)
                mutate(bad)
                with self.assertRaises(ContractError):
                    native._apis(*bad)

    def test_catalog_transport_only_exact_role_bytes_and_descriptor(self):
        body = (FIXTURE / "rc-index-original.zip").read_bytes()
        entries = transport._archive_members(metadata({transport.CATALOG_PATH: body}))
        self.assertEqual(next(r["body"] for r in entries if r["path"] == transport.CATALOG_PATH), body)
        for path, data in (("evidence/public-release/native-ci/other.zip", body),
                           (transport.CATALOG_PATH, body + b"x")):
            with self.assertRaises(ContractError):
                transport._archive_members(metadata({path: data}))


class GenuineProductNative071Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.capture = genuine_capture()

    def test_actual_source_parity7_positive_and_exact_bounds(self):
        path = GENUINE_CAPTURE / "evidence/assets/theme-forge-nebular-fusion-v0.7.1-source.tar.gz"
        data = path.read_bytes()
        members = support._source_archive_members(data, expected_size=12289441,
                    expected_sha256=transport.SOURCE_ARCHIVE_SHA256)
        self.assertEqual(len(members), 2162)
        self.assertEqual(sum(row[0] for row in members.values()), 34280236)
        self.assertEqual(support.MAX_SOURCE_ARCHIVE_TOTAL_BYTES, 32 * 1024 * 1024)
        source = consumer.authenticated_product_source(self.capture)
        self.assertEqual(source["commit"], native.FINAL_COMMIT)
        self.assertEqual(source["authority_identity"], native.AUTHORITY_IDENTITY)
        for size, sha in ((12289440, transport.SOURCE_ARCHIVE_SHA256), (12289441, "0" * 64)):
            with self.assertRaises(AdmissionError):
                support._source_archive_members(data, expected_size=size, expected_sha256=sha)
        # Simulate an incomplete parser inventory over the genuine body. Both
        # exact postconditions must still hold after its ordinary safety loop.
        real_open = support.tarfile.open
        class MissingLast:
            def __enter__(self):
                self.archive = real_open(fileobj=io.BytesIO(data), mode="r:gz")
                return self
            def __exit__(self, *args):
                self.archive.close()
            def __iter__(self):
                import itertools
                return itertools.islice(iter(self.archive), 2161)
            def extractfile(self, member):
                return self.archive.extractfile(member)
        with mock.patch.object(support.tarfile, "open", return_value=MissingLast()):
            with self.assertRaises(AdmissionError):
                support._source_archive_members(data, expected_size=12289441,
                                               expected_sha256=transport.SOURCE_ARCHIVE_SHA256)

    def test_actual_source_transport_exception_remains_descriptor_bound(self):
        data = (GENUINE_CAPTURE / "evidence/assets/theme-forge-nebular-fusion-v0.7.1-source.tar.gz").read_bytes()
        entries = transport._archive_members(metadata({transport.SOURCE_ARCHIVE_PATH: data}))
        self.assertEqual(len(next(r["body"] for r in entries if r["path"] == transport.SOURCE_ARCHIVE_PATH)), 12289441)
        with self.assertRaises(ContractError):
            transport._validate_opaque_metadata(entries, {"evidence": {"source_root": "evidence/public-release", "files": {}}})

    def test_original_body_substitution_raw_and_manifest_mutation_refuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "native-ci"
            shutil.copytree(FIXTURE, root)
            for relative in ("api/run.json", "api/jobs.json", "api/compiler-commit.json",
                             "api/artifacts.json", "artifact-metadata.json", "rc-index-original.zip",
                             "linux-arm64/rc-evidence.json", "darwin-arm64/qualification.json",
                             "linux-x64/smoke/linux-x64-C-signal-npm-package.run.json"):
                with self.subTest(path=relative):
                    path = root / relative
                    original = path.read_bytes()
                    replacement = original + b" "
                    if relative == "artifact-metadata.json":
                        altered = json.loads(original)
                        altered["digest"] = "sha256:" + "0" * 64
                        replacement = canonical(altered)
                    path.write_bytes(replacement)
                    try:
                        with self.assertRaises(ContractError):
                            native.replay_native_admission(root, self.capture)
                    finally:
                        path.write_bytes(original)
            target = "darwin-arm64"
            original_path = self.capture.archives[target]
            replaced = Path(temporary) / "substituted-public-payload.tar.gz"
            replaced.write_bytes(b"substituted inert bytes")
            self.capture.archives[target] = replaced
            try:
                with self.assertRaises(ContractError):
                    native.replay_native_admission(root, self.capture)
            finally:
                self.capture.archives[target] = original_path
            original_manifest = self.capture.manifests[target]
            changed = copy.deepcopy(original_manifest)
            next(row for row in changed["members"] if row["type"] == "file")["sha256"] = "0" * 64
            self.capture.manifests[target] = changed
            try:
                with self.assertRaises(ContractError):
                    native.replay_native_admission(root, self.capture)
            finally:
                self.capture.manifests[target] = original_manifest

    def test_genuine_typed_replay_binds_source_assets_and_cannot_be_reused_or_resealed(self):
        admission = native.replay_native_admission(FIXTURE, self.capture)
        frame = native.require_native_admission(admission, self.capture, native.reference())
        self.assertEqual(frame["product_source"]["commit"], native.FINAL_COMMIT)
        self.assertEqual(len(frame["assets"]), 3)
        self.assertEqual(frame["compiler_relation"], "authenticated-equal-tree")
        self.assertNotIn("rs9_qualification", frame)
        with self.assertRaises(ContractError):
            native.require_native_admission(frame, self.capture, native.reference())
        with self.assertRaises(ContractError):
            native.require_native_admission(admission, genuine_capture(), native.reference())
        with mock.patch.object(native.os, "getpid", return_value=os.getpid() + 1):
            with self.assertRaises(ContractError):
                native.require_native_admission(admission, self.capture, native.reference())

    def test_genuine_replay_rechecks_custody_and_simulated_fresh_api_failures(self):
        api = dict(zip(("run.json", "jobs.json", "compiler-commit.json", "artifacts.json"), api_bodies()))
        class SimulatedOfficialClient:
            def __init__(self):
                self.calls = []
            def json(self, url, **kwargs):
                self.calls.append(url)
                key = ("jobs.json" if "/jobs?" in url else "artifacts.json" if "/artifacts?" in url
                       else "compiler-commit.json" if "/git/commits/" in url else "run.json")
                return copy.deepcopy(api[key])
        client = SimulatedOfficialClient()
        native.replay_native_admission(FIXTURE, self.capture, client=client)
        self.assertEqual(len(client.calls), 4)
        api["run.json"]["run_attempt"] = 2
        with self.assertRaises(ContractError):
            native.replay_native_admission(FIXTURE, self.capture, client=SimulatedOfficialClient())
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "native-ci"
            shutil.copytree(FIXTURE, root)
            admission = native.replay_native_admission(root, self.capture)
            path = root / "linux-x64/smoke/linux-x64-C-raw-archive.receipt.json"
            path.write_bytes(path.read_bytes() + b" ")
            with self.assertRaises(ContractError):
                native.require_native_admission(admission, self.capture, native.reference())
            with self.assertRaises(ContractError):
                native.replay_native_admission(root, self.capture)


class SourceOffer071Checks(unittest.TestCase):
    def test_actual_071_source_authority_and_archive_inventory_join(self):
        source_dir = SOURCE_PROOF_ROOT
        archive_path = source_dir / "source.tar.gz"
        authority_path = source_dir / "public-build-source-authority.json"
        parity_path = source_dir / "source-proof.json"
        archive_body = archive_path.read_bytes()
        authority_body = authority_path.read_bytes()
        authority = json.loads(authority_body)
        members = smoke_support._source_archive_members(
            archive_body,
            expected_size=12289441,
            expected_sha256="4ed41eaf2bcf29eae1d6dc0b2eb85f0dc70cb65fc9bef816f522db63304b9171",
        )
        source_files = []
        required = sorted(
            {f"tools/{name}" for name in smoke_support._REQUIRED_TOOLS}
            | smoke_support._REQUIRED_FIXTURES
        )
        for path in required:
            size, digest, blob, _mode = members[path]
            source_files.append({
                "path": path,
                "size": size,
                "sha256": digest,
                "blob": blob,
                "role": "application-smoke" if path == "tools/native-rc-smoke.mjs"
                else "verifier-module" if path.startswith("tools/") else "fixture",
            })
        source = consumer.authenticated_product_source(genuine_capture())
        self.assertEqual(source["commit"], native.FINAL_COMMIT)
        self.assertEqual(source["tree"], native.reference()["tested_tree"])
        self.assertEqual(source["authority_identity"], native.AUTHORITY_IDENTITY)
        self.assertEqual(authority["identity"], native.AUTHORITY_IDENTITY)
        self.assertEqual(sum(row[0] for row in members.values()), 34280236)
        proof = strict_json(parity_path.read_bytes())
        self.assertEqual(proof["schema"], "nebular071.current-source-offer-proof-v1")
        self.assertEqual(proof["repository"], source["repository"])
        self.assertEqual(proof["version"], "0.7.1")
        self.assertEqual(proof["archiveBytes"], len(archive_body))
        self.assertEqual(proof["archiveSha256"], _sha(archive_body))
        self.assertEqual(proof["publicTree"]["commit"], source["commit"])
        self.assertEqual(proof["publicTree"]["tree"], source["tree"])

        archive_name = "theme-forge-nebular-fusion-v0.7.1-source.tar.gz"
        authority_name = "nebular-compiled-public-build-source-authority-v0.7.1.json"
        support = {
            "schema": smoke_support.SMOKE_SUPPORT_SCHEMA,
            "target": "linux-x64-gnu",
            "source": source,
            "root": "source",
            "tool_root": "tools",
            "fixture_root": "docs/examples/v0.4/brand-system/core-minimal",
            "files": source_files,
            "source_binding": {
                "archive": {"path": archive_name, "size": len(archive_body), "sha256": _sha(archive_body)},
                "authority": {"path": authority_name, "size": len(authority_body), "sha256": _sha(authority_body)},
            },
        }
        support["closure_sha256"] = smoke_support._closure_digest(support)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "inputs"
            source_root = root / "source"
            source_root.mkdir(parents=True)
            (source_root / archive_name).write_bytes(archive_body)
            (source_root / authority_name).write_bytes(authority_body)
            result = smoke_support.verify_source_binding(
                root, support, expected_source=source,
            )
        self.assertEqual(result["member_count"], 2162)
        self.assertEqual(result["composition"], authority["composition"])
        self.assertEqual(result["archive_sha256"], "4ed41eaf2bcf29eae1d6dc0b2eb85f0dc70cb65fc9bef816f522db63304b9171")
        self.assertEqual(result["authority_sha256"], "82ac724968602490d4259697a0d40e0b3217f3d47a0d352593f8eb4691be108e")


def _physical_root(value):
    path = Path(value).absolute()
    validate_ancestry_not_symlink(path)
    return physical_directory(path)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inrun-root", type=Path, required=True,
                        help="Prepared output or explicit data-layout-only custody including product-capture and the selected descriptor role")
    parser.add_argument("--source-root", type=Path, required=True,
                        help="Retained source proof: source.tar.gz, public-build-source-authority.json and source-proof.json")
    parser.add_argument("--assets-root", type=Path, required=True,
                        help="Explicit separately transported public release-assets directory, including wrapper/source metadata roles")
    parser.add_argument("--descriptor", choices=("qualification-inputs-prep.json", "qualification-inputs.json"), required=True,
                        help="Explicit prepared or data-layout-only descriptor role; neither filename creates a preparation receipt")
    args = parser.parse_args(argv)
    global INRUN_ROOT, GENUINE_CAPTURE, FIXTURE, PUBLIC_ASSETS_ROOT, SOURCE_PROOF_ROOT
    try:
        INRUN_ROOT = _physical_root(args.inrun_root)
        GENUINE_CAPTURE = _physical_root(INRUN_ROOT / "product-capture")
        FIXTURE = _physical_root(INRUN_ROOT / "evidence/public-release/native-ci")
        SOURCE_PROOF_ROOT = _physical_root(args.source_root)
        PUBLIC_ASSETS_ROOT = _physical_root(args.assets_root)
        for name, limit in (("source.tar.gz", 12289441),
                            ("public-build-source-authority.json", 1024 * 1024),
                            ("source-proof.json", 1024 * 1024)):
            if not read_evidence(SOURCE_PROOF_ROOT, name, limit=limit):
                raise ValueError("Source proof body missing")
        capture = genuine_capture()
        descriptor = strict_json(read_evidence(INRUN_ROOT, args.descriptor, limit=4 * 1024 * 1024))
        native.replay_descriptor_native(descriptor, INRUN_ROOT, capture)
    except (ContractError, AdmissionError, OSError, ValueError, TypeError, KeyError):
        parser.error("Required evidence roots are missing, unsafe or fail genuine capture/native replay")
    suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(case) for case in
        (NativeCatalog071Checks, GenuineProductNative071Tests, GenuineBoundary071Tests, SourceOffer071Checks))
    if suite.countTestCases() != 10:
        raise RuntimeError("The explicit ten-check genuine evidence audit is incomplete")
    return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
