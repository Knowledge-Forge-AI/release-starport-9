"""Offline PyPI projection tests: record, scope, capture, lineage, approval and provenance.

Captures are real authenticated ReleaseCapture objects. Only module-internal reviewed
pins (the projection record digest and the existing Nebular lineage pins) are patched
for synthetic bytes; capability validation is never patched away. Nothing here reads
a registry, builds a distribution or claims a live observation.
"""
import contextlib
import copy
import hashlib
import io
import json
import pickle
import stat
import subprocess
import sys
import tarfile
import tempfile
import types
import unittest
import warnings
import zipfile
from pathlib import Path
from unittest.mock import patch

import tests.test_nebular_lineage as nebular_lineage_tests
from rs9 import nebular_lineage as lineage
from rs9 import pypi_observe
from rs9.errors import ContractError
from rs9.profiles import PACKAGE_PROFILE, evaluate_profile, selection_for_intent
from rs9.records import record_sha256
from rs9.release_core import authenticate_release, authenticated_record_hash, digest
from rs9.scratch import canonical
from rs9.tf_pypi_archive import canonical as compact_canonical
from rs9.tf_pypi_backend import write_tar, write_zip
from rs9.tf_pypi_model import DISTRIBUTIONS, TARGETS, build_pin
from rs9.tf_pypi_platform import EXPECTED_TAGS
from tests.shadow_fixtures import fixture_evidence, tar_bytes

ROOT = Path(__file__).resolve().parents[1]
RECORD_BYTES = (ROOT / pypi_observe.PROJECTION_RECORD_PATH).read_bytes()
REAL_RECORD = json.loads(RECORD_BYTES)
REAL_ROWS = {row["project"]: row for row in REAL_RECORD["rows"]}
NEBULAR = "theme-forge-nebular-fusion"
SOLAR, BURST, LOOM = "theme-forge-solar-sail", "theme-forge-stellar-burst", "theme-forge-stellar-loom"
NEBULAR_WHEEL = "theme_forge_nebular_fusion-0.6.1-py3-none-macosx_13_0_arm64.whl"
NEBULAR_PACKAGE = "theme_forge_nebular_fusion"
COMMANDS = {BURST: ("tfsb", "dist/cli.js"), LOOM: ("tfsl", "bin/tfsl.js"), SOLAR: ("tfss", "bin/tfss.js")}
MANIFESTS = (pypi_observe.HISTORICAL_MANIFEST_PATH, pypi_observe.CURRENT_MANIFEST_PATH)


def write(root, relative, data):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return data


def row_of(record, project):
    return next(row for row in record["rows"] if row["project"] == project)


def zip_bytes(entries, *, compression=zipfile.ZIP_DEFLATED, comment=b""):
    """Raw ZIP writer for hostile shapes; entries are (name, data[, full st_mode])."""
    output = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        with zipfile.ZipFile(output, "w") as archive:
            for name, data, *mode in entries:
                info = zipfile.ZipInfo(name, (2026, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.external_attr = (mode[0] if mode else stat.S_IFREG | 0o644) << 16
                info.compress_type = compression
                archive.writestr(info, data)
            archive.comment = comment
    return output.getvalue()


def authenticated_package(evidence, project, *, commit=None, tree=None, release_id=None, binding_id=None):
    """Real authenticated npm-package-archive capture and profile at the projected release identity."""
    row = REAL_ROWS[project]
    application, current = row["application"], row["lineage"]["current"]
    commit, tree = commit or current["commit"], tree or current["tree"]
    tag, version = application["tag"], application["version"]
    command, target = COMMANDS[project]
    package_json = canonical({"name": "@knowledge-forge-ai/" + project, "version": version,
                              "license": "AGPL-3.0-or-later", "bin": {command: target}})
    sources = {"package.json": package_json}
    if project == BURST:
        sources["package-lock.json"] = canonical({"lockfileVersion": 3, "name": "@knowledge-forge-ai/" + project})
    payload = tar_bytes([("package/package.json", package_json, 0o644, tarfile.REGTYPE, ""),
                         ("package/" + target, b"#!/usr/bin/env node\n", 0o755, tarfile.REGTYPE, "")])
    binding = row["binding_asset"]["name"]
    assets = {binding: payload, "NOTICE": b"Synthetic AGPL-3.0-or-later declaration.\n",
              "PROVENANCE.json": canonical({"release": {"repository": application["repository"], "tag": tag}})}
    assets["SHA256SUMS"] = "".join(digest(data) + "  " + name + "\n" for name, data in sorted(assets.items())).encode()
    ids = {binding: binding_id or row["binding_asset"]["github_asset_id"], "NOTICE": 11,
           "PROVENANCE.json": 12, "SHA256SUMS": 13}
    blobs = [{"path": path, "type": "blob", "mode": "100644",
              "sha": hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()}
             for path, data in sorted(sources.items())]
    api = {"repository": {"id": application["repository_id"], "full_name": application["repository"]},
           "ref": {"ref": "refs/tags/" + tag, "object": {"type": "commit", "sha": commit}}, "tags": [],
           "commit": {"sha": commit, "tree": {"sha": tree}},
           "tree": {"sha": tree, "truncated": False, "tree": blobs},
           "release": {"id": release_id or application["release_id"], "tag_name": tag, "target_commitish": commit,
                       "draft": False, "prerelease": False,
                       "assets": [{"id": ids[name], "name": name, "size": len(data), "digest": "sha256:" + digest(data),
                                   "state": "uploaded"} for name, data in sorted(assets.items())]}}
    for name, value in api.items():
        write(evidence, "api/" + name + ".json", canonical(value))
    for name, data in assets.items():
        write(evidence, "assets/" + name, data)
    for path, data in sources.items():
        write(evidence, "source/" + path, data)
    intent = {"project": {"repository": application["repository"], "id": project}, "tag": tag, "version": version,
              "release": {"prerelease": "reject", "evidence": {
                  "profile": PACKAGE_PROFILE, "checksums": "SHA256SUMS",
                  "assets": [{"role": "notice", "name": "NOTICE"}, {"role": "provenance", "name": "PROVENANCE.json"}]}},
              "assets": [{"id": "package", "name": binding, "format": "tar.gz",
                          "commands": {command: "package/" + target}, "platforms": ["any"]}],
              "license": {"files": [], "expression": "AGPL-3.0-or-later"}}
    capture = authenticate_release(selection_for_intent(intent), evidence)
    return intent, capture, evaluate_profile(capture, PACKAGE_PROFILE, intent), payload


def first_wave_bodies(project, pin, row, payload, *, wheel=None, sdist=None):
    """Synthetic approved wheel/sdist bytes embedding the reviewed provenance; hooks drift them first."""
    package, dv = project.replace("-", "_"), pin["distribution_version"]
    info, stem = package + "-" + dv + ".dist-info", package + "-" + dv
    base = "https://github.com/" + row["application"]["repository"]
    bodies = {}
    for target in TARGETS:
        tag = EXPECTED_TAGS[project][target]
        parts = {
            "metadata": [("Name", project), ("Version", dv),
                         ("Project-URL", "Source, " + base + "/tree/" + pin["source_commit"]),
                         ("Project-URL", "Release, " + base + "/releases/tag/v" + pin["version"])],
            "tag": "py3-none-" + tag,
            "transform": {"target_key": target, "omissions": [], "source_sha256": pin["sha256"],
                          "dependencies": {dep["asset"]: dep["sha256"] for dep in pin.get("dependencies", [])}},
            "extra": {},
        }
        if wheel is not None:
            wheel(target, parts)
        text = "Metadata-Version: 2.4\n" + "".join(key + ": " + value + "\n" for key, value in parts["metadata"])
        entries = {package + "/__init__.py": (b"", 0o644),
                   info + "/METADATA": ((text + "\nSynthetic description.\n").encode(), 0o644),
                   info + "/WHEEL": (("Wheel-Version: 1.0\nGenerator: rs9-tf-pypi\nRoot-Is-Purelib: false\nTag: "
                                      + parts["tag"] + "\n").encode(), 0o644),
                   info + "/rs9-tf-transform.json": (compact_canonical(parts["transform"]), 0o644),
                   **parts["extra"]}
        bodies[stem + "-py3-none-" + tag + ".whl"] = (parts["raw"] if "raw" in parts else write_zip(entries), target)
    parts = {"upstream": payload, "pins": compact_canonical(build_pin(pin))}
    if sdist is not None:
        sdist(parts)
    files = {"PKG-INFO": (b"Metadata-Version: 2.4\n", 0o644), "upstream/" + pin["asset"]: (parts["upstream"], 0o644),
             "_rs9_build/rs9/pins.json": (parts["pins"], 0o644)}
    bodies[stem + ".tar.gz"] = (write_tar(files, stem), None)
    return bodies


def aggregate_approval(project, pin, bodies):
    files = [{"filename": name, "logical_sha256": digest(b"logical:" + name.encode()), "sha256": digest(body),
              "size": len(body), "target": target} for name, (body, target) in sorted(bodies.items())]
    return {"files": files, "project": project, "publication_admitted": True,
            "schema": "rs9.tf-pypi-candidate-aggregate.v1", "set_sha256": digest(compact_canonical(files)),
            "targets": list(TARGETS), "upstream_version": pin["version"], "version": pin["distribution_version"]}


def nebular_wheel(real_approval, binding, payload, capture, *, wheel=None):
    """Synthetic 17-member Nebular wheel plus the approval rows recomputed from its exact bytes."""
    from rs9.tf_pypi_nebular import compute_set_sha256
    info = NEBULAR_PACKAGE + "-0.6.1.dist-info"
    helpers = {relative: ("# synthetic " + relative + "\n").encode() for relative in sorted(real_approval["embedded_helpers"])}
    manifest_sha = real_approval["payload_asset"]["payload_manifest_sha256"]
    parts = {
        "entries": {
            info + "/METADATA": b"Metadata-Version: 2.4\nName: theme-forge-nebular-fusion\nVersion: 0.6.1\n",
            info + "/RECORD": b"synthetic\n",
            info + "/WHEEL": b"Wheel-Version: 1.0\nRoot-Is-Purelib: false\nTag: py3-none-macosx_13_0_arm64\n",
            info + "/entry_points.txt": b"[console_scripts]\n",
            info + "/licenses/LICENSE": b"Synthetic license.\n",
            info + "/licenses/NOTICE": b"Synthetic notice.\n",
            NEBULAR_PACKAGE + "/__init__.py": b"",
            NEBULAR_PACKAGE + "/launcher.py": b"# synthetic launcher\n",
            NEBULAR_PACKAGE + "/payload/manifest.json": canonical({"manifest_sha256": manifest_sha}),
            NEBULAR_PACKAGE + "/payload/" + binding["name"]: payload,
            **{NEBULAR_PACKAGE + "/_isolated/" + relative: data for relative, data in helpers.items()},
        },
        "provenance": {
            "schema": "rs9.wheel-provenance.v1alpha1", "product_id": NEBULAR, "distribution_name": NEBULAR,
            "version": "0.6.1", "wheel_tag": "py3-none-macosx_13_0_arm64",
            "release_record_sha256": real_approval["authentication"]["nebular"]["release_record_sha256"],
            "fixture_only": False, "candidate_only": False, "can_publish": False,
            "candidate_status": "candidate", "promotability": "candidate", "manylinux_proven": False,
            "helper_source_sha256": {relative: digest(data) for relative, data in helpers.items()},
            "payload_archive_sha256": digest(payload), "manifest_sha256": manifest_sha,
        },
    }
    if wheel is not None:
        wheel(parts, capture)
    parts["entries"][NEBULAR_PACKAGE + "/_rs9/provenance.json"] = canonical(parts["provenance"])
    body = zip_bytes(sorted(parts["entries"].items()))
    with zipfile.ZipFile(io.BytesIO(body)) as archive:
        members = [{"compressed_size": item.compress_size, "mode": 0o644, "path": item.filename,
                    "sha256": digest(archive.read(item)), "size": item.file_size}
                   for item in sorted(archive.infolist(), key=lambda item: item.filename)]
    approval = copy.deepcopy(real_approval)
    approval["payload_asset"].update(size=binding["size"], sha256=binding["sha256"])
    approval["embedded_helpers"] = {relative: digest(data) for relative, data in helpers.items()}
    approval["members"] = members
    approval["files"] = [{"filename": NEBULAR_WHEEL, "logical_sha256": real_approval["files"][0]["logical_sha256"],
                          "sha256": digest(body), "size": len(body)}]
    approval["set_sha256"] = compute_set_sha256(approval)
    return body, approval


def fake_fetch(project, version, bodies, *, listed=None, served=None, missing=()):
    """Injected fetch(url, limit) over exact PyPI JSON and file URLs; missing URLs are exact-URL 404s.

    missing may name "project" (project 404) or "version" (version absent from a present project).
    """
    from rs9.tf_pypi_remote import _ObserverAdmissionError
    base = "https://pypi.org/pypi/" + project
    project_url, version_url = base + "/json", base + "/" + version + "/json"
    listed = sorted(bodies) if listed is None else listed
    urls = {name: "https://files.pythonhosted.org/packages/0a/1b/" + name for name in bodies}
    releases = {} if "version" in missing else {version: [{}]}
    responses = {
        project_url: compact_canonical({"info": {"name": project, "version": version}, "releases": releases}),
        version_url: compact_canonical({"info": {"name": project, "version": version}, "urls": [
            {"filename": name, "size": len(bodies[name]), "digests": {"sha256": digest(bodies[name])},
             "yanked": False, "url": urls[name]} for name in listed]}),
    }
    responses.update({urls[name]: (served or {}).get(name, body) for name, body in bodies.items()})
    if "project" in missing:
        del responses[project_url]
    if "version" in missing:
        del responses[version_url]
    calls = []

    def fetch(url, limit):
        calls.append(url)
        if url not in responses:
            raise _ObserverAdmissionError("TF_PYPI_REMOTE_ABSENT", "http-404")
        if len(responses[url]) > limit:
            raise _ObserverAdmissionError("TF_PYPI_REMOTE_UNKNOWN", "limit")
        return responses[url]
    fetch.responses = responses
    return fetch, calls


class ProjectionFixtures:
    """Reusable authenticated fixtures; not a TestCase, so importing it adds no tests."""

    def fixture_dir(self):
        if not hasattr(self, "_projection_tmp"):
            self._projection_tmp = tempfile.TemporaryDirectory()
            self.addCleanup(self._projection_tmp.cleanup)
            self._projection_count = 0
        self._projection_count += 1
        path = Path(self._projection_tmp.name).resolve() / ("case-" + str(self._projection_count))
        path.mkdir()
        return path

    def write_record(self, case, mutate=None, raw=None):
        record = copy.deepcopy(REAL_RECORD)
        record["rows"] = [copy.deepcopy(case["row"]) if row["project"] == case["project"] else row
                          for row in record["rows"]]
        if mutate is not None:
            mutate(record)
        data = canonical(record) if raw is None else raw
        write(case["repo"], pypi_observe.PROJECTION_RECORD_PATH, data)
        case.update(record=record, record_sha=digest(data))
        return case

    def first_wave_case(self, project=SOLAR, *, wheel=None, sdist=None, approval=None, pin=None, **capture_options):
        base = self.fixture_dir()
        intent, capture, profile, payload = authenticated_package(base / "evidence", project, **capture_options)
        real = REAL_ROWS[project]
        pin_doc = json.loads((ROOT / real["intake"]["pin_path"]).read_bytes())
        pin_doc.update(size=len(payload), sha256=digest(payload))
        if pin is not None:
            pin(pin_doc)
        row = copy.deepcopy(real)
        row["binding_asset"].update(size=len(payload), sha256=digest(payload))
        bodies = first_wave_bodies(project, pin_doc, row, payload, wheel=wheel, sdist=sdist)
        approval_doc = aggregate_approval(project, pin_doc, bodies)
        if approval is not None:
            approval(approval_doc)
        repo = base / "repository"
        pin_bytes = write(repo, real["intake"]["pin_path"], canonical(pin_doc))
        approval_bytes = write(repo, real["distribution"]["approval_path"], canonical(approval_doc))
        for path in MANIFESTS:
            write(repo, path, (ROOT / path).read_bytes())
        row["intake"]["pin_sha256"] = digest(pin_bytes)
        row["distribution"].update(approval_sha256=digest(approval_bytes), set_sha256=approval_doc["set_sha256"])
        case = {"project": project, "repo": repo, "evidence": base / "evidence", "intent": intent, "capture": capture,
                "profile": profile, "pin": pin_doc, "approval": approval_doc, "row": row, "payload": payload,
                "bodies": {name: body for name, (body, _target) in bodies.items()}, "lineage_pins": ()}
        return self.write_record(case)

    def nebular_case(self, *, wheel=None, approval=None, reseal=True):
        from rs9.tf_pypi_nebular import compute_set_sha256
        base = self.fixture_dir()
        holder = types.SimpleNamespace(root=base, _fixture_counter=0)
        fixture = nebular_lineage_tests.NebularLineageTests._make_fixture(holder)
        lineage_pins = (("FORWARD_RECORD_SHA256", fixture["record_sha"]),
                        ("PROVENANCE_SHA256", fixture["provenance_sha"]),
                        ("PROVENANCE_SIZE", fixture["provenance_size"]))
        capture, intent, repo = fixture["capture"], fixture["intent"], fixture["repo"]
        with contextlib.ExitStack() as stack:
            for name, value in lineage_pins:
                stack.enter_context(patch.object(lineage, name, value))
            proof = lineage.build_forward_lineage_proof(capture, intent, repo)
            profile = evaluate_profile(capture, intent["release"]["evidence"]["profile"], intent,
                                       lineage_correction=proof)
        real = REAL_ROWS[NEBULAR]
        binding = dict(capture.asset_metadata[real["binding_asset"]["name"]])
        payload = (fixture["evidence"] / "assets" / binding["name"]).read_bytes()
        real_approval = json.loads((ROOT / real["distribution"]["approval_path"]).read_bytes())
        body, approval_doc = nebular_wheel(real_approval, binding, payload, capture, wheel=wheel)
        if approval is not None:
            approval(approval_doc)
            if reseal:
                approval_doc["set_sha256"] = compute_set_sha256(approval_doc)
        approval_bytes = write(repo, real["distribution"]["approval_path"], canonical(approval_doc))
        for path in MANIFESTS:
            write(repo, path, (ROOT / path).read_bytes())
        row = copy.deepcopy(real)
        row["binding_asset"] = binding
        row["distribution"].update(approval_sha256=digest(approval_bytes), set_sha256=approval_doc["set_sha256"])
        case = {"project": NEBULAR, "repo": repo, "evidence": fixture["evidence"], "intent": intent,
                "capture": capture, "profile": profile, "proof": proof, "approval": approval_doc, "row": row,
                "payload": payload, "bodies": {NEBULAR_WHEEL: body}, "lineage_pins": lineage_pins,
                "fixture": fixture}
        return self.write_record(case)

    @contextlib.contextmanager
    def pinned(self, case):
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(pypi_observe, "PROJECTION_RECORD_SHA256", case["record_sha"]))
            for name, value in case["lineage_pins"]:
                stack.enter_context(patch.object(lineage, name, value))
            yield

    def build(self, case):
        with self.pinned(case):
            return pypi_observe.build_pypi_projection(case["repo"], case["capture"], case["intent"], case["profile"])

    def assert_refused(self, code, case, **overrides):
        inputs = {key: overrides.get(key, case[key]) for key in ("repo", "capture", "intent", "profile")}
        with self.pinned(case), self.assertRaises(ContractError) as caught:
            pypi_observe.build_pypi_projection(inputs["repo"], inputs["capture"], inputs["intent"], inputs["profile"])
        self.assertEqual(caught.exception.code, code)
        return caught.exception

    def fetch_for(self, case, **options):
        row = case["row"]
        return fake_fetch(row["distribution"]["name"], row["distribution"]["version"], case["bodies"], **options)


class ProjectionRecordTests(ProjectionFixtures, unittest.TestCase):
    def record_repo(self, record=None, raw=None):
        repo = self.fixture_dir()
        data = canonical(record if record is not None else REAL_RECORD) if raw is None else raw
        write(repo, pypi_observe.PROJECTION_RECORD_PATH, data)
        return repo, digest(data)

    def assert_record_refused(self, repo, sha):
        with patch.object(pypi_observe, "PROJECTION_RECORD_SHA256", sha), self.assertRaises(ContractError) as caught:
            pypi_observe.load_projection_record(repo)
        self.assertEqual(caught.exception.code, "PYPI_PROJECTION_RECORD")

    def test_committed_record_is_the_exact_reviewed_canonical_bytes(self):
        root, raw, record = pypi_observe.load_projection_record(ROOT)
        self.assertEqual(root, ROOT.resolve())
        self.assertEqual(raw, RECORD_BYTES)
        self.assertEqual(raw, canonical(record))
        self.assertEqual(digest(raw), pypi_observe.PROJECTION_RECORD_SHA256)
        self.assertEqual([row["project"] for row in record["rows"]], [NEBULAR, SOLAR, BURST, LOOM])

    def test_committed_record_matches_the_reviewed_identity_table(self):
        expected = {
            BURST: (399542205, "a3e89683", "9f0bb67a", "158bd6d0", 599265851, 644313, "0.6.1.post1"),
            LOOM: (399542451, "d6f3cc45", "85e42645", "9388e305", 599266537, 273462, "0.4.0.post1"),
            SOLAR: (399542664, "68e3f95a", "17883c16", "35a865bd", 599267369, 110658, "0.2.1.post1"),
            NEBULAR: (400494635, "49e2c491", "75bc4125", "203a80b3", 601953438, 47079690, "0.6.1"),
        }
        for project, values in expected.items():
            row = REAL_ROWS[project]
            with self.subTest(project=project):
                lineage_row, binding = row["lineage"], row["binding_asset"]
                self.assertEqual((row["application"]["release_id"], lineage_row["historical"]["commit"][:8],
                                  lineage_row["current"]["commit"][:8], lineage_row["current"]["tree"][:8],
                                  binding["github_asset_id"], binding["size"], row["distribution"]["version"]), values)
                self.assertEqual(lineage_row["current"]["tree"], lineage_row["historical"]["tree"])
                self.assertNotEqual(lineage_row["current"]["commit"], lineage_row["historical"]["commit"])
        nebular = REAL_ROWS[NEBULAR]
        self.assertEqual((nebular["distribution"]["kind"], nebular["intake"]), ("nebular-native-wheel", None))
        self.assertNotIn("post1", nebular["distribution"]["version"])
        for project in (BURST, LOOM, SOLAR):
            self.assertEqual(REAL_ROWS[project]["distribution"]["version"], DISTRIBUTIONS[project])
        self.assertEqual(REAL_RECORD["historical_manifest"]["sha256"],
                         "93081d30cb2eedb88eb6248653177ab03570dbd51f7047293e25670d860b8e64")
        self.assertEqual(REAL_RECORD["current_manifest"]["sha256"],
                         "f31bd4ddc1caf0f591b1d8447c1bf694ffa822994fc5f88bb346a3292227bf78")

    def test_static_reconciliation_against_committed_sources(self):
        root, _raw, record = pypi_observe.load_projection_record(ROOT)
        for row in record["rows"]:
            with self.subTest(project=row["project"]):
                offline = pypi_observe._offline_inputs(root, record, row)
                approved = offline["approved"]
                self.assertEqual(len(approved), 1 if row["project"] == NEBULAR else 4)
                identity = pypi_observe._desired_identity(row, approved)
                self.assertEqual(identity, record_sha256({
                    "schema": "rs9.pypi-distribution-identity.v1alpha1", "project": row["project"],
                    "application_version": row["application"]["version"],
                    "distribution": {"name": row["project"], "version": row["distribution"]["version"]},
                    "approval_sha256": row["distribution"]["approval_sha256"],
                    "set_sha256": row["distribution"]["set_sha256"],
                    "files": {name: value[1] for name, value in approved.items()}}))
        self.assertEqual(list(pypi_observe._offline_inputs(root, record, row_of(record, NEBULAR))["approved"]),
                         [NEBULAR_WHEEL])

    def test_record_byte_and_shape_drift_is_refused(self):
        repo, sha = self.record_repo(raw=RECORD_BYTES + b"\n")
        self.assert_record_refused(repo, pypi_observe.PROJECTION_RECORD_SHA256)
        repo, sha = self.record_repo(raw=json.dumps(REAL_RECORD, sort_keys=True).encode())
        self.assert_record_refused(repo, sha)
        duplicate = RECORD_BYTES.replace(b'  "schema"', b'  "reason": "x",\n  "schema"')
        repo, sha = self.record_repo(raw=duplicate)
        self.assert_record_refused(repo, sha)

        def extra(record):
            record["extra"] = 1

        def missing(record):
            del record["reason"]

        def missing_row(record):
            record["rows"] = record["rows"][:3]

        def fifth_row(record):
            record["rows"].append(copy.deepcopy(record["rows"][-1]))

        def unsorted(record):
            record["rows"] = list(reversed(record["rows"]))

        def unsafe(record):
            row_of(record, SOLAR)["distribution"]["approval_path"] = "operators/tf-pypi/../x.json"

        def row_field(record):
            row_of(record, SOLAR)["binding_asset"]["extra"] = True

        def nebular_intake(record):
            row_of(record, NEBULAR)["intake"] = copy.deepcopy(REAL_ROWS[SOLAR]["intake"])

        def wrong_basis(record):
            row_of(record, NEBULAR)["lineage"]["basis"] = "observer-equal-tree"

        for mutate in (extra, missing, missing_row, fifth_row, unsorted, unsafe, row_field, nebular_intake, wrong_basis):
            record = copy.deepcopy(REAL_RECORD)
            mutate(record)
            repo, sha = self.record_repo(record)
            with self.subTest(mutation=mutate.__name__):
                self.assert_record_refused(repo, sha)


class ProjectionScopeTests(ProjectionFixtures, unittest.TestCase):
    def intent(self, project, version, repository=None):
        return {"project": {"id": project, "repository": repository or "Knowledge-Forge-AI/" + project},
                "version": version, "tag": "v" + version}

    def assert_scope(self, intent, repo=ROOT, sha=None):
        with patch.object(pypi_observe, "PROJECTION_RECORD_SHA256", sha or pypi_observe.PROJECTION_RECORD_SHA256), self.assertRaises(ContractError) as caught:
            pypi_observe.build_pypi_projection(repo, object(), intent, {})
        self.assertEqual(caught.exception.code, "PYPI_PROJECTION_SCOPE")

    def test_intent_selects_exactly_one_reviewed_row(self):
        for intent in (self.intent(NEBULAR, "0.6.1.post1"), self.intent("theme-forge-unknown", "1.0.0"),
                       self.intent(SOLAR, "0.2.0"), self.intent(SOLAR, "0.2.1.post1"),
                       self.intent(SOLAR, "0.2.1", "Knowledge-Forge-AI/elsewhere"), {"project": "x"}):
            with self.subTest(intent=intent):
                self.assert_scope(intent)

    def test_record_successor_and_kind_mismatch_rows_are_refused(self):
        def successor(record):
            row_of(record, NEBULAR)["distribution"]["version"] = "0.6.1.post1"

        def first_wave_successor(record):
            row_of(record, SOLAR)["distribution"]["version"] = "0.2.1.post2"

        def kind(record):
            row = row_of(record, SOLAR)
            row["distribution"]["kind"] = "nebular-native-wheel"
            row["lineage"]["basis"] = "nebular-forward-lineage"
            row["intake"] = None

        for mutate, intent in ((successor, self.intent(NEBULAR, "0.6.1")),
                               (first_wave_successor, self.intent(SOLAR, "0.2.1")),
                               (kind, self.intent(SOLAR, "0.2.1"))):
            record = copy.deepcopy(REAL_RECORD)
            mutate(record)
            repo = self.fixture_dir()
            data = write(repo, pypi_observe.PROJECTION_RECORD_PATH, canonical(record))
            with self.subTest(mutation=mutate.__name__):
                self.assert_scope(intent, repo, digest(data))


class ProjectionCaptureTests(ProjectionFixtures, unittest.TestCase):
    def test_first_wave_projection_binds_fresh_capture_and_exposes_only_public_facts(self):
        for project in (SOLAR, BURST, LOOM):
            case = self.first_wave_case(project)
            projection = self.build(case)
            with self.subTest(project=project):
                facts = projection.public_facts()
                self.assertEqual(set(facts), {"schema", "record_sha256", "row", "files", "desired_identity_sha256"})
                self.assertEqual(facts["row"], case["row"])
                self.assertEqual(facts["files"], {name: digest(body) for name, body in sorted(case["bodies"].items())})
                self.assertEqual(projection.identity, pypi_observe._desired_identity(
                    case["row"], {name: (len(body), digest(body)) for name, body in case["bodies"].items()}))
                serialized = canonical(facts).decode()
                for forbidden in ("capture", "token", "ownership", "upload", "bodies", str(case["evidence"])):
                    self.assertNotIn(forbidden, serialized)
                with self.pinned(case):
                    inputs = pypi_observe.verify_pypi_projection(projection)
                self.assertEqual((inputs.project, inputs.version), (project, DISTRIBUTIONS[project]))
                self.assertEqual(inputs.approved, {name: (len(body), digest(body)) for name, body in case["bodies"].items()})

    def test_nebular_projection_reuses_forward_lineage_unchanged(self):
        case = self.nebular_case()
        projection = self.build(case)
        self.assertEqual(projection.public_facts()["row"]["distribution"]["version"], "0.6.1")
        with self.pinned(case):
            inputs = pypi_observe.verify_pypi_projection(projection)
        self.assertEqual(inputs.approved, {NEBULAR_WHEEL: (len(case["bodies"][NEBULAR_WHEEL]),
                                                           digest(case["bodies"][NEBULAR_WHEEL]))})

    def test_object_that_only_looks_like_a_capture_is_refused(self):
        case = self.first_wave_case()
        fake = types.SimpleNamespace(record=case["capture"].record, root=case["capture"].root,
                                     asset_metadata=case["capture"].asset_metadata, _profile_results=set())
        self.assert_refused("PYPI_PROJECTION_CAPTURE", case, capture=fake)

    def test_record_changed_after_authentication_is_refused(self):
        case = self.first_wave_case()
        case["capture"].record["release"]["id"] += 1
        self.assert_refused("PYPI_PROJECTION_CAPTURE", case)

    def test_historical_unequal_tree_and_foreign_release_captures_are_refused(self):
        row = REAL_ROWS[SOLAR]
        for options in ({"commit": row["lineage"]["historical"]["commit"]}, {"tree": "c" * 40},
                        {"release_id": row["application"]["release_id"] + 1},
                        {"binding_id": row["binding_asset"]["github_asset_id"] + 1}):
            case = self.first_wave_case(**options)
            with self.subTest(options=options):
                self.assert_refused("PYPI_PROJECTION_CAPTURE", case)

    def test_tree_or_asset_evidence_changed_after_authentication_is_refused(self):
        case = self.first_wave_case()
        tree_path = case["evidence"] / "api/tree.json"
        tree = json.loads(tree_path.read_bytes())
        tree["truncated"] = True
        tree_path.write_bytes(canonical(tree))
        self.assert_refused("PYPI_PROJECTION_CAPTURE", case)

        case = self.first_wave_case()
        asset = case["evidence"] / "assets" / case["row"]["binding_asset"]["name"]
        data = bytearray(asset.read_bytes())
        data[-1] ^= 1
        asset.write_bytes(bytes(data))
        self.assert_refused("PYPI_PROJECTION_CAPTURE", case)

    def test_binding_asset_size_or_digest_drift_is_refused(self):
        for key, value in (("size", 1), ("sha256", "0" * 64)):
            case = self.first_wave_case()

            def mutate(record, key=key, value=value):
                row_of(record, SOLAR)["binding_asset"][key] = value
            self.write_record(case, mutate)
            with self.subTest(key=key):
                self.assert_refused("PYPI_PROJECTION_CAPTURE", case)

    def test_profile_must_be_a_fresh_evaluation_of_this_capture_and_intent(self):
        case = self.first_wave_case()
        forged = copy.deepcopy(case["profile"])
        forged["sections"]["extra"] = {}
        other = self.first_wave_case(BURST)
        changed_intent = copy.deepcopy(case["intent"])
        changed_intent["license"]["expression"] = "MIT"
        for overrides in ({"profile": forged}, {"profile": other["profile"]}, {"profile": None},
                          {"intent": changed_intent}):
            with self.subTest(overrides=sorted(overrides)):
                self.assert_refused("PYPI_PROJECTION_CAPTURE", case, **overrides)

    def test_nebular_historical_capture_has_no_projection(self):
        case = self.nebular_case()
        evidence = self.fixture_dir() / "historical"
        intent = fixture_evidence(evidence)
        capture = authenticate_release(selection_for_intent(intent), evidence)
        profile = evaluate_profile(capture, intent["release"]["evidence"]["profile"], intent)
        self.assert_refused("PYPI_PROJECTION_CAPTURE", case, capture=capture, intent=intent, profile=profile)


class ProjectionApprovalTests(ProjectionFixtures, unittest.TestCase):
    def test_unadmitted_or_drifted_first_wave_approvals_are_refused(self):
        def unadmitted(approval):
            approval["publication_admitted"] = False

        def set_drift(approval):
            approval["set_sha256"] = "0" * 64

        def extra_file(approval):
            approval["files"].append(dict(approval["files"][0], filename="extra.whl"))

        def wrong_target(approval):
            approval["files"][0]["target"] = "linux-x64-gnu"

        for mutate in (unadmitted, set_drift, extra_file, wrong_target):
            case = self.first_wave_case(approval=mutate)
            with self.subTest(mutation=mutate.__name__):
                self.assert_refused("PYPI_PROJECTION_APPROVAL", case)

    def test_older_unadmitted_artifact_set_is_refused(self):
        case = self.first_wave_case()
        older = "operators/tf-pypi/theme-forge-solar-sail-artifacts.json"
        data = write(case["repo"], older, (ROOT / older).read_bytes())

        def mutate(record):
            row_of(record, SOLAR)["distribution"].update(approval_path=older, approval_sha256=digest(data))
        self.write_record(case, mutate)
        self.assert_refused("PYPI_PROJECTION_APPROVAL", case)

    def test_approval_pin_and_record_digest_drift_is_refused(self):
        for relative in (REAL_ROWS[SOLAR]["distribution"]["approval_path"], REAL_ROWS[SOLAR]["intake"]["pin_path"]):
            case = self.first_wave_case()
            path = case["repo"] / relative
            path.write_bytes(path.read_bytes() + b"\n")
            with self.subTest(path=relative):
                self.assert_refused("PYPI_PROJECTION_APPROVAL", case)
        case = self.first_wave_case()

        def mutate(record):
            row_of(record, SOLAR)["distribution"]["set_sha256"] = "0" * 64
        self.write_record(case, mutate)
        self.assert_refused("PYPI_PROJECTION_APPROVAL", case)

    def test_blocked_pin_is_refused(self):
        def blocked(pin):
            pin["source_status"] = "BLOCKED"
        self.assert_refused("PYPI_PROJECTION_APPROVAL", self.first_wave_case(pin=blocked))

    def test_nebular_approval_must_be_admitted_with_its_own_set_formula(self):
        def unadmitted(approval):
            approval["publication_admitted"] = False

        def builder(approval):
            approval["builder_can_publish"] = True
        for mutate in (unadmitted, builder):
            case = self.nebular_case(approval=mutate)
            with self.subTest(mutation=mutate.__name__):
                self.assert_refused("PYPI_PROJECTION_APPROVAL", case)

        def first_wave_formula(approval):
            approval["set_sha256"] = digest(compact_canonical(approval["files"]))
        case = self.nebular_case(approval=first_wave_formula, reseal=False)
        self.assert_refused("PYPI_PROJECTION_APPROVAL", case)


class ProjectionLineageTests(ProjectionFixtures, unittest.TestCase):
    def manifest_case(self, mutate_manifest, mutate_record=None, pin=None):
        case = self.first_wave_case(pin=pin)
        path = case["repo"] / pypi_observe.HISTORICAL_MANIFEST_PATH
        document = json.loads(path.read_bytes())
        mutate_manifest(next(row for row in document["projects"] if row["repository"].endswith(SOLAR)))
        data = canonical(document)
        path.write_bytes(data)

        def mutate(record):
            record["historical_manifest"]["sha256"] = digest(data)
            if mutate_record is not None:
                mutate_record(row_of(record, SOLAR))
        return self.write_record(case, mutate)

    def test_manifest_digest_and_row_drift_are_refused(self):
        case = self.first_wave_case()
        path = case["repo"] / pypi_observe.CURRENT_MANIFEST_PATH
        path.write_bytes(path.read_bytes() + b"\n")
        self.assert_refused("PYPI_PROJECTION_LINEAGE", case)

        def commit(row):
            row["tag_commit"] = "1" * 40

        def release(row):
            row["release_id"] += 1
        for mutate in (commit, release):
            with self.subTest(mutation=mutate.__name__):
                self.assert_refused("PYPI_PROJECTION_LINEAGE", self.manifest_case(mutate))

    def test_equal_commits_or_unequal_trees_are_refused(self):
        current = REAL_ROWS[SOLAR]["lineage"]["current"]

        def same_commit(row):
            row["tag_commit"] = current["commit"]

        def record_same_commit(row):
            row["lineage"]["historical"]["commit"] = current["commit"]

        def pin_same_commit(pin):
            pin["source_commit"] = current["commit"]
        case = self.manifest_case(same_commit, record_same_commit, pin_same_commit)
        self.assert_refused("PYPI_PROJECTION_LINEAGE", case)

        def other_tree(row):
            row["tag_tree"] = "2" * 40

        def record_other_tree(row):
            row["lineage"]["historical"]["tree"] = "2" * 40
        self.assert_refused("PYPI_PROJECTION_LINEAGE", self.manifest_case(other_tree, record_other_tree))

    def test_pin_must_bind_historical_commit_and_asset_bytes(self):
        def source_commit(pin):
            pin["source_commit"] = "3" * 40

        def asset_bytes(pin):
            pin["sha256"] = "4" * 64
        for mutate in (source_commit, asset_bytes):
            with self.subTest(mutation=mutate.__name__):
                self.assert_refused("PYPI_PROJECTION_LINEAGE", self.first_wave_case(pin=mutate))

    def test_nebular_approval_authentication_must_match_historical_lineage(self):
        current = REAL_ROWS[NEBULAR]["lineage"]["current"]

        def tag_commit(approval):
            approval["authentication"]["nebular"]["tag_commit"] = current["commit"]

        def bootstrap(approval):
            approval["authentication"]["bootstrap_sha256"] = "5" * 64

        def stellar(approval):
            approval["authentication"]["stellar_fixture"]["tag_commit"] = "6" * 40

        def payload_id(approval):
            approval["payload_asset"]["github_asset_id"] = 7
        for mutate in (tag_commit, bootstrap, stellar, payload_id):
            with self.subTest(mutation=mutate.__name__):
                self.assert_refused("PYPI_PROJECTION_LINEAGE", self.nebular_case(approval=mutate))

    def test_nebular_binding_must_be_in_the_reviewed_inventory(self):
        case = self.nebular_case()
        record_path = case["repo"] / lineage.FORWARD_RECORD_PATH
        record = json.loads(record_path.read_bytes())
        row = next(row for row in record["asset_inventory"] if row["name"] == case["row"]["binding_asset"]["name"])
        row["sha256"] = "8" * 64
        data = canonical(record)
        record_path.write_bytes(data)
        case["lineage_pins"] = (("FORWARD_RECORD_SHA256", digest(data)),) + case["lineage_pins"][1:]
        self.assert_refused("PYPI_PROJECTION_LINEAGE", case)

    def test_profile_forward_lineage_facts_must_equal_the_proof(self):
        case = self.nebular_case()
        with self.pinned(case):
            root, _raw, record = pypi_observe.load_projection_record(case["repo"])
            row = row_of(record, NEBULAR)
            inventory_sha = pypi_observe._offline_inputs(root, record, row)["inventory_sha256"]
            pypi_observe._check_nebular_live_lineage(root, case["capture"], case["intent"], case["profile"], row,
                                                     inventory_sha, None)
            altered = copy.deepcopy(case["profile"])
            altered["sections"]["forward_lineage"]["tree_relation_basis"] = "live"
            with self.assertRaises(ContractError) as caught:
                pypi_observe._check_nebular_live_lineage(root, case["capture"], case["intent"], altered, row,
                                                         inventory_sha, None)
        self.assertEqual(caught.exception.code, "PYPI_PROJECTION_LINEAGE")


class ProjectionTokenTests(ProjectionFixtures, unittest.TestCase):
    def test_projection_is_module_private_opaque_and_nonserializable(self):
        case = self.first_wave_case()
        projection = self.build(case)
        with self.assertRaises(ContractError) as caught:
            pypi_observe.PypiProjection(token=object(), root=None, capture=None, intent=b"", profile=b"",
                                        proof=None, facts=b"{}", state=b"")
        self.assertEqual(caught.exception.code, "PYPI_PROJECTION_RECORD")
        for value in (object.__new__(pypi_observe.PypiProjection), projection.public_facts(), None):
            with self.subTest(value=type(value).__name__), self.pinned(case), self.assertRaises(ContractError) as caught:
                pypi_observe.verify_pypi_projection(value)
            self.assertEqual(caught.exception.code, "PYPI_PROJECTION_RECORD")
        for operation in (pickle.dumps, copy.copy, copy.deepcopy):
            with self.subTest(operation=operation.__name__), self.assertRaises(TypeError):
                operation(projection)
        with self.assertRaises(TypeError):
            json.dumps(projection)
        with self.assertRaises(AttributeError):
            projection._facts = b"{}"
        self.assertNotIn("capture", repr(projection))

    def test_caller_mutation_cannot_change_bound_facts(self):
        case = self.first_wave_case()
        projection = self.build(case)
        facts = projection.public_facts()
        facts["row"]["distribution"]["version"] = "9.9.9"
        case["intent"]["version"] = "9.9.9"
        case["profile"]["sections"]["extra"] = {}
        self.assertEqual(projection.public_facts()["row"], case["row"])
        with self.pinned(case):
            self.assertEqual(pypi_observe.verify_pypi_projection(projection).version, DISTRIBUTIONS[SOLAR])

    def test_trust_inputs_are_revalidated_at_use(self):
        case = self.first_wave_case()
        projection = self.build(case)
        case["capture"].record["tag"]["commit"] = "9" * 40
        with self.pinned(case), self.assertRaises(ContractError) as caught:
            pypi_observe.verify_pypi_projection(projection)
        self.assertEqual(caught.exception.code, "PYPI_PROJECTION_CAPTURE")

        case = self.nebular_case()
        projection = self.build(case)
        record_path = case["repo"] / lineage.FORWARD_RECORD_PATH
        record_path.write_bytes(record_path.read_bytes() + b"\n")
        with self.pinned(case), self.assertRaises(ContractError) as caught:
            pypi_observe.verify_pypi_projection(projection)
        self.assertEqual(caught.exception.code, "PYPI_PROJECTION_LINEAGE")


class ProjectionProvenanceTests(ProjectionFixtures, unittest.TestCase):
    def assert_provenance(self, case, bodies=None):
        projection = self.build(case)
        with self.pinned(case), self.assertRaises(ContractError) as caught:
            pypi_observe.verify_distribution_provenance(projection, case["bodies"] if bodies is None else bodies)
        self.assertEqual(caught.exception.code, "PYPI_PROJECTION_PROVENANCE")

    def test_exact_provenance_passes_for_each_kind(self):
        for case in (self.first_wave_case(SOLAR), self.first_wave_case(BURST), self.first_wave_case(LOOM), self.nebular_case()):
            projection = self.build(case)
            with self.subTest(project=case["project"]), self.pinned(case):
                self.assertIsNone(pypi_observe.verify_distribution_provenance(projection, case["bodies"]))

    def test_provenance_runs_only_on_bytes_matching_the_approved_digests(self):
        case = self.first_wave_case()
        name = min(case["bodies"])
        for bodies in ({**case["bodies"], name: case["bodies"][name] + b"x"},
                       {key: value for key, value in case["bodies"].items() if key != name}, None):
            with self.subTest(bodies=None if bodies is None else sorted(bodies)):
                self.assert_provenance(case, bodies if bodies is not None else [])

    def test_first_wave_wheel_provenance_drift_is_refused(self):
        current = REAL_ROWS[SOLAR]["lineage"]["current"]["commit"]

        def darwin(change):
            def hook(target, parts):
                if target == "darwin-arm64":
                    change(parts)
            return hook

        def current_source(parts):
            parts["metadata"][2] = ("Project-URL", "Source, https://github.com/Knowledge-Forge-AI/" + SOLAR
                                    + "/tree/" + current)

        def extra_url(parts):
            parts["metadata"].append(("Project-URL", "Homepage, https://example.invalid"))

        def name(parts):
            parts["metadata"][0] = ("Name", "theme-forge-other")

        def source_sha(parts):
            parts["transform"]["source_sha256"] = "0" * 64

        def target_key(parts):
            parts["transform"]["target_key"] = "linux-x64-gnu"

        def dependencies(parts):
            parts["transform"]["dependencies"] = {"extra.tgz": "0" * 64}

        def wheel_tag(parts):
            parts["tag"] = "py3-none-any"
        for change in (current_source, extra_url, name, source_sha, target_key, dependencies, wheel_tag):
            with self.subTest(change=change.__name__):
                self.assert_provenance(self.first_wave_case(wheel=darwin(change)))

        def burst_dependency(target, parts):
            first = min(parts["transform"]["dependencies"])
            parts["transform"]["dependencies"][first] = "0" * 64
        self.assert_provenance(self.first_wave_case(BURST, wheel=burst_dependency))

    def test_first_wave_sdist_provenance_drift_is_refused(self):
        def upstream(parts):
            parts["upstream"] = parts["upstream"] + b"\0"

        def raw_pin(parts):
            pin = json.loads(parts["pins"])
            pin["qualified_platforms"] = list(TARGETS)
            parts["pins"] = compact_canonical(pin)
        for change in (upstream, raw_pin):
            with self.subTest(change=change.__name__):
                self.assert_provenance(self.first_wave_case(sdist=change))

    def test_hostile_wheel_archives_are_refused(self):
        info = "theme_forge_solar_sail-0.2.1.post1.dist-info/METADATA"
        regular = [("theme_forge_solar_sail/__init__.py", b"")]
        archives = {
            "duplicate": zip_bytes(regular + [(info, b"Name: a\n"), (info, b"Name: b\n")]),
            "casefold-duplicate": zip_bytes(regular + [("theme_forge_solar_sail/A.py", b""), ("theme_forge_solar_sail/a.py", b"")]),
            "symlink": zip_bytes(regular + [("link", b"target", stat.S_IFLNK | 0o777)]),
            "traversal": zip_bytes(regular + [("../evil", b"x")]),
            "absolute": zip_bytes(regular + [("/evil", b"x")]),
            "oversize": zip_bytes(regular + [("big", bytes(8 * 1024 ** 2 + 1))]),
            "ancestor": zip_bytes(regular + [("dir", b"x"), ("dir/child", b"y")]),
            "comment": zip_bytes(regular, comment=b"c"),
            "not-zip": b"not a zip archive",
        }
        for label, raw in archives.items():
            def hook(target, parts, raw=raw):
                if target == "darwin-arm64":
                    parts["raw"] = raw
            with self.subTest(archive=label):
                self.assert_provenance(self.first_wave_case(wheel=hook))

    def test_nebular_provenance_drift_is_refused(self):
        def current_hash(parts, capture):
            parts["provenance"]["release_record_sha256"] = authenticated_record_hash(capture)

        def helper(parts, capture):
            first = min(parts["provenance"]["helper_source_sha256"])
            parts["provenance"]["helper_source_sha256"][first] = "0" * 64

        def candidate(parts, capture):
            parts["provenance"]["candidate_only"] = True

        def payload_digest(parts, capture):
            parts["provenance"]["payload_archive_sha256"] = "0" * 64

        def manifest(parts, capture):
            parts["entries"][NEBULAR_PACKAGE + "/payload/manifest.json"] = canonical({"manifest_sha256": "0" * 64})
        for change in (current_hash, helper, candidate, payload_digest, manifest):
            with self.subTest(change=change.__name__):
                self.assert_provenance(self.nebular_case(wheel=change))

        def member_table(approval):
            approval["members"][0]["sha256"] = "0" * 64
        self.assert_provenance(self.nebular_case(approval=member_table))


class ProjectionImportIsolationTests(unittest.TestCase):
    def loaded(self, module):
        code = ("import sys; sys.dont_write_bytecode = True; sys.path.insert(0, sys.argv[1]); "
                "import " + module + "; print('\\n'.join(sorted(sys.modules)))")
        result = subprocess.run([sys.executable, "-I", "-c", code, str(ROOT / "src")],
                                capture_output=True, check=True, text=True, timeout=120)
        return set(result.stdout.split())

    def test_readers_import_loads_no_candidate_or_nebular_closure(self):
        loaded = self.loaded("rs9.readers")
        self.assertTrue({"rs9.readers", "rs9.observation"} <= loaded)
        self.assertFalse(loaded & {"rs9.candidate", "rs9.tf_pypi_nebular", "rs9.pypi_observe", "rs9.operator"})

    def test_observer_import_loads_no_candidate_builder_or_publication_module(self):
        loaded = self.loaded("rs9.pypi_observe")
        self.assertIn("rs9.nebular_lineage", loaded)
        self.assertFalse(loaded & {"rs9.candidate", "rs9.tf_pypi_nebular", "rs9.operator", "rs9.hosted_commands",
                                   "rs9.hosted_observe", "rs9.tf_pypi_backend", "rs9.tf_pypi_verify",
                                   "rs9.tf_pypi_publish", "rs9.readers"})


if __name__ == "__main__":
    unittest.main()
