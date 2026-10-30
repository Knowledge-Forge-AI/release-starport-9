"""Synthetic publication custody fixtures; no native product, network, registry or upload."""
import contextlib
import copy
import hashlib
import io
import json
from pathlib import Path
import stat
import tempfile
import types
import unittest
from unittest.mock import Mock, patch
import zipfile

from rs9 import nebular070_universal_publication as publication
from rs9 import tf_pypi_nebular070_universal as frontend
from rs9.errors import ContractError
from rs9.scratch import canonical
from rs9.tf_pypi_archive import AdmissionError
import tests.test_tf_pypi_nebular070_universal as bundle_fixtures


FILENAME = publication.builder.FILENAME
RUN_ID = "4242"
CURRENT_RUN = "5151"
P_HEAD = "e" * 40
PROJECT_URL = "https://pypi.org/pypi/theme-forge-nebular-fusion/json"
VERSION_URL = "https://pypi.org/pypi/theme-forge-nebular-fusion/0.7.0/json"
FILE_URL = "https://files.pythonhosted.org/packages/aa/bb/" + FILENAME
ARTIFACT_IDS = {name: 7000 + index for index, name in enumerate(publication.ARTIFACTS)}
FAILURES = (ContractError, AdmissionError)
ORIGINAL_GIT = publication._git
ORIGINAL_PRIOR_RUNS = publication._prior_runs


def sha(data):
    return hashlib.sha256(data).hexdigest()


def record(data):
    return {"size": len(data), "sha256": sha(data)}


def zip_bytes(members, *, modes=None):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for name, data in members.items():
            info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (modes or {}).get(name, stat.S_IFREG | 0o644) << 16
            archive.writestr(info, data)
    return output.getvalue()


def reseal(value):
    unsigned = {key: item for key, item in value.items() if key != "identity"}
    return {**unsigned, "identity": sha(canonical(unsigned))}


def lane_members(bundle_files, matrix_bytes):
    members = {
        publication.PUBLIC_INPUTS: {
            "qualification-inputs-prep.json": b'{"synthetic": "descriptor"}\n',
            "raw-release/synthetic-payload.tar.gz": b"synthetic raw release bytes",
        },
        publication.BUNDLE: dict(bundle_files),
        publication.MATRIX: {publication.MATRIX_MEMBER: matrix_bytes},
    }
    for target, name in publication.QUALIFICATION.items():
        members[name] = {target + "/result.json": canonical({"target": target, "role": "newer"})}
    for target, name in publication.FLOOR.items():
        members[name] = {target + "/result.json": canonical({"target": target, "role": "floor"}),
                         target + "/missing-runtime.json": canonical({"target": target, "refused": True})}
    return members


def authority_for(members, archives, api, *, source, wheel, runtime_inputs, runtime_index, description):
    return reseal({
        "schema": publication.SCHEMA, "project": "theme-forge-nebular-fusion", "version": "0.7.0",
        "distribution": "universal-launcher", "workflow": "rs9-tfnf-pypi-publish.yml",
        "environment": "pypi", "repository": "Knowledge-Forge-AI/release-starport-9",
        "source": dict(source), "run": {"id": RUN_ID, "attempt": "1"}, "wheel": dict(wheel),
        "runtime_inputs_sha256": runtime_inputs, "runtime_index_sha256": runtime_index,
        "description_sha256": description,
        "matrix_sha256": sha(members[publication.MATRIX][publication.MATRIX_MEMBER]),
        "api": {name: record(data) for name, data in api.items()},
        "artifacts": {name: {"id": ARTIFACT_IDS[name], "size_in_bytes": len(archives[name]),
                             "archive_sha256": sha(archives[name]),
                             "files": {path: record(data) for path, data in members[name].items()}}
                      for name in publication.ARTIFACTS},
    })


def synthetic_authority():
    wheel = b"synthetic wheel bytes"
    members = lane_members({"bundle.json": b"{}\n", "universal-build-receipt.json": b"{}\n",
                            "dist/" + FILENAME: wheel}, b"{}\n")
    archives = {name: zip_bytes(files) for name, files in members.items()}
    return authority_for(
        members, archives, {name: b"{}" for name in publication.API_FILES},
        source={"commit": "a" * 40, "tree": "b" * 40},
        wheel={"filename": FILENAME, "tag": "py3-none-any", "version": "0.7.0",
               "size": len(wheel), "sha256": sha(wheel)},
        runtime_inputs="1" * 64, runtime_index="2" * 64, description="3" * 64)


class Failures:
    def assertFails(self, code, function, *args, **kwargs):
        with self.assertRaises(FAILURES) as caught:
            function(*args, **kwargs)
        if code is not None:
            self.assertEqual(caught.exception.code, "NEBULAR_UNIVERSAL_PUBLICATION_" + code)
        return caught.exception


class AuthorityTests(Failures, unittest.TestCase):
    def setUp(self):
        self.authority = synthetic_authority()

    def test_closed_authority_validates_and_binds_its_identity(self):
        self.assertEqual(publication.validate_authority(copy.deepcopy(self.authority)), self.authority)
        changed = copy.deepcopy(self.authority)
        changed["identity"] = "0" * 64
        self.assertFails("AUTHORITY_IDENTITY", publication.validate_authority, changed)

    def test_authenticated_tfsb_fixture_assets_are_valid_public_input_members(self):
        changed = copy.deepcopy(self.authority)
        path = "evidence/public-release/smoke-support/shared/docs/examples/v0.4/brand-system/core-minimal/.tfsb/brand.toml"
        changed["artifacts"][publication.PUBLIC_INPUTS]["files"][path] = record(b"synthetic fixture")
        changed = reseal(changed)
        self.assertEqual(publication.validate_authority(changed), changed)

    def test_domain_types_files_and_hash_bindings_are_closed(self):
        inputs = publication.PUBLIC_INPUTS
        darwin = publication.QUALIFICATION["darwin-arm64"]
        floor = publication.FLOOR["linux-x64-gnu"]
        def public(path):
            return lambda value: value["artifacts"][inputs]["files"].update({path: record(b"x")})
        mutations = {
            "extra-key": lambda value: value.update(extra=True),
            "project": lambda value: value.update(project="theme-forge-stellar-burst"),
            "version": lambda value: value.update(version="0.7.1"),
            "old-profile": lambda value: value.update(distribution="three-native-wheels"),
            "workflow": lambda value: value.update(workflow="other.yml"),
            "environment": lambda value: value.update(environment="testpypi"),
            "repository": lambda value: value.update(repository="other/repo"),
            "source-short": lambda value: value["source"].update(commit="a" * 39),
            "source-extra": lambda value: value["source"].update(ref="main"),
            "run-int": lambda value: value["run"].update(id=4242),
            "run-zero": lambda value: value["run"].update(id="0"),
            "run-padded": lambda value: value["run"].update(id="04242"),
            "attempt": lambda value: value["run"].update(attempt="2"),
            "wheel-platform": lambda value: value["wheel"].update(
                filename="theme_forge_nebular_fusion-0.7.0-py3-none-manylinux_2_36_x86_64.whl"),
            "wheel-tag": lambda value: value["wheel"].update(tag="py3-none-macosx_13_0_arm64"),
            "wheel-size-bool": lambda value: value["wheel"].update(size=True),
            "wheel-size-large": lambda value: value["wheel"].update(size=4 * 1024 * 1024 + 1),
            "wheel-unbound": lambda value: value["wheel"].update(sha256="9" * 64),
            "hash-upper": lambda value: value.update(runtime_index_sha256="A" * 64),
            "matrix-unbound": lambda value: value.update(matrix_sha256="9" * 64),
            "api-missing": lambda value: value["api"].pop("jobs.json"),
            "api-size-float": lambda value: value["api"]["run.json"].update(size=2.0),
            "artifact-missing": lambda value: value["artifacts"].pop(publication.MATRIX),
            "artifact-extra": lambda value: value["artifacts"].update(
                {"tfnf-070-universal-diagnostic": copy.deepcopy(value["artifacts"][darwin])}),
            "artifact-id-bool": lambda value: value["artifacts"][darwin].update(id=True),
            "artifact-id-duplicate": lambda value: value["artifacts"][darwin].update(
                id=value["artifacts"][floor]["id"]),
            "artifact-key": lambda value: value["artifacts"][darwin].update(archive_download_url="x"),
            "archive-large": lambda value: value["artifacts"][darwin].update(
                size_in_bytes=16 * 1024 * 1024 + 1),
            "member-empty": lambda value: value["artifacts"][darwin]["files"][
                "darwin-arm64/result.json"].update(size=0),
            "traversal": public("../escape"),
            "absolute": public("/absolute"),
            "empty-segment": public("raw-release//x"),
            "hidden": public(".git/config"),
            "backslash": public("raw-release\\x"),
            "case-alias": public("QUALIFICATION-INPUTS-PREP.json"),
            "file-directory-alias": public("qualification-inputs-prep.json/x"),
            "missing-descriptor": lambda value: value["artifacts"][inputs]["files"].pop(
                "qualification-inputs-prep.json"),
            "bundle-surplus": lambda value: value["artifacts"][publication.BUNDLE]["files"].update(
                {"dist/other.whl": record(b"x")}),
            "receipt-target": lambda value: value["artifacts"][darwin].update(
                files={"linux-x64-gnu/result.json": record(b"x")}),
            "floor-negative-missing": lambda value: value["artifacts"][floor]["files"].pop(
                "linux-x64-gnu/missing-runtime.json"),
        }
        for name, mutate in mutations.items():
            with self.subTest(mutation=name):
                changed = copy.deepcopy(self.authority)
                mutate(changed)
                self.assertFails("AUTHORITY", publication.validate_authority, reseal(changed))


class LineageTests(Failures, unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.publisher = self.root / "publisher"
        self.qualification = self.root / "qualification"
        (self.publisher / publication.AUTHORITY.parent).mkdir(parents=True)
        self.qualification.mkdir()
        self.authority = synthetic_authority()
        (self.publisher / publication.AUTHORITY).write_bytes(canonical(self.authority))
        self.source = self.authority["source"]
        self.state = {"p_head": P_HEAD, "p_tree": "f" * 40, "q_head": self.source["commit"],
                      "q_tree": self.source["tree"], "p_status": "", "q_status": "",
                      "q_tree_in_p": self.source["tree"], "ancestor": True,
                      "diff": [publication.AUTHORITY.as_posix()]}
        patcher = patch.object(publication, "_git", side_effect=self.git)
        patcher.start()
        self.addCleanup(patcher.stop)

    def git(self, repository, *args):
        side = "p" if Path(repository) == self.publisher else "q"
        if args[:2] == ("rev-parse", "--verify"):
            if args[2] in ("HEAD^{commit}", "HEAD^{tree}"):
                return self.state[side + ("_head" if args[2] == "HEAD^{commit}" else "_tree")]
            self.assertEqual((side, args[2]), ("p", self.source["commit"] + "^{tree}"))
            return self.state["q_tree_in_p"]
        if args[0] == "status":
            return self.state[side + "_status"]
        if args[0] == "merge-base":
            self.assertEqual((side, args[2:]), ("p", (self.source["commit"], self.state["p_head"])))
            if not self.state["ancestor"]:
                raise AdmissionError("TF_PYPI_SOURCE_LINEAGE")
            return ""
        if args[0] == "diff":
            self.assertEqual((side, args[-3:]), ("p", (self.source["commit"], self.state["p_head"], "--")))
            return "\0".join(self.state["diff"])
        raise AssertionError("unexpected git query")

    def verify(self, **kwargs):
        return publication.verify_source_lineage(self.publisher, self.qualification, **kwargs)

    def test_clean_metadata_only_successor_is_accepted(self):
        result = self.verify(publisher_revision=P_HEAD)
        self.assertEqual(result, {"publisher_commit": P_HEAD, "publisher_tree": "f" * 40,
                                  "qualification_commit": self.source["commit"],
                                  "qualification_tree": self.source["tree"],
                                  "qualification_run_id": RUN_ID})

    def test_code_diff_wrong_qualification_and_unclean_checkouts_are_refused(self):
        cases = {
            "code-diff": ("FORBIDDEN_TREE_DIFF", {"diff": [publication.AUTHORITY.as_posix(), "src/rs9/x.py"]}),
            "no-authority-change": ("FORBIDDEN_TREE_DIFF", {"diff": []}),
            "other-metadata": ("FORBIDDEN_TREE_DIFF", {"diff": ["operators/tf-pypi/other.json"]}),
            "wrong-q-head": ("QUALIFICATION_SOURCE", {"q_head": "c" * 40}),
            "wrong-q-tree": ("QUALIFICATION_SOURCE", {"q_tree": "c" * 40}),
            "q-dirty": ("SOURCE_DIRTY", {"q_status": "?? planted.py"}),
            "p-dirty": ("SOURCE_DIRTY", {"p_status": " M src/rs9/x.py"}),
            "not-ancestor": (None, {"ancestor": False}),
            "q-tree-in-p": ("SOURCE_LINEAGE", {"q_tree_in_p": "c" * 40}),
            "p-is-q": ("SOURCE_LINEAGE", {"p_head": self.source["commit"]}),
        }
        for name, (code, change) in cases.items():
            with self.subTest(case=name), patch.dict(self.state, change):
                self.assertFails(code, self.verify)
        self.assertFails("SOURCE_LINEAGE", self.verify, publisher_revision="d" * 40)
        self.assertFails("SOURCE_LINEAGE", self.verify, publisher_revision="HEAD")
        self.assertFails("SOURCE_LINEAGE", publication.verify_source_lineage, self.publisher, self.publisher)
        nested = self.publisher / "nested"
        nested.mkdir()
        self.assertFails("SOURCE_LINEAGE", publication.verify_source_lineage, self.publisher, nested)

    def test_missing_linked_or_duplicate_key_authority_fails_closed(self):
        path = self.publisher / publication.AUTHORITY
        raw = path.read_bytes()
        path.unlink()
        self.assertFails("AUTHORITY", publication.load_authority, self.publisher)
        (self.root / "elsewhere.json").write_bytes(raw)
        path.symlink_to(self.root / "elsewhere.json")
        self.assertFails("AUTHORITY", publication.load_authority, self.publisher)
        path.unlink()
        path.write_bytes(b'{"schema": "a", ' + raw.lstrip()[1:])
        self.assertFails(None, publication.load_authority, self.publisher)

    def test_git_queries_use_fixed_argv_without_optional_locks_or_fsmonitor(self):
        with patch.object(publication.legacy, "_git_output", return_value="") as output:
            ORIGINAL_GIT(self.publisher, "status", "--porcelain=v1")
        output.assert_called_once_with(
            self.publisher, ["-c", "core.fsmonitor=false", "--no-optional-locks", "status", "--porcelain=v1"],
            "SOURCE_LINEAGE")


class CaptureFixture(Failures, unittest.TestCase):
    """Real bundle bytes from the pure builder fixture; matrix reader observes extracted files."""

    def setUp(self):
        self.bundle_fixture = bundle_fixtures.UniversalBundleTests()
        self.bundle_fixture.setUp()
        self.addCleanup(self.bundle_fixture.doCleanups)
        self.bundle_fixture.build()
        self.root = self.bundle_fixture.fixture.root
        self.repository = self.bundle_fixture.repository
        self.source = dict(self.bundle_fixture.source)
        bundle = self.bundle_fixture.output
        self.bundle_value = json.loads((bundle / "bundle.json").read_bytes())
        self.wheel = (bundle / "dist" / FILENAME).read_bytes()
        self.description = self.bundle_fixture.fixture.description.read_bytes()
        self.matrix = {
            "schema": frontend.MATRIX_SCHEMA, "distribution": "universal-launcher", "version": "0.7.0",
            "status": "passed", "source": self.source, "run": {"id": RUN_ID, "attempt": "1"},
            "wheel": self.bundle_value["wheel"],
            "runtime_inputs_sha256": self.bundle_value["runtime_inputs_sha256"],
            "runtime_index_sha256": self.bundle_value["runtime_index_sha256"],
            "lanes": [{"lane": index} for index in range(5)], "native_qualified": True,
            "fixture_only": False, "publication_admitted": False, "public_writes": 0,
            "identity": "f" * 64,
        }
        self.members = lane_members(
            {name: (bundle / name).read_bytes()
             for name in ("bundle.json", "universal-build-receipt.json", "dist/" + FILENAME)},
            canonical(self.matrix))
        self.history = types.SimpleNamespace(validate_qualification_jobs=Mock(),
                                             check_prior_universal_run=Mock(return_value=True))
        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(patch.object(publication, "_history", return_value=self.history))
        self.reader = stack.enter_context(patch.object(
            frontend, "read_matrix_inputs", side_effect=self.read_matrix))
        self.count = 0
        self.write_capture()

    def read_matrix(self, bundle, qualification_inputs, inrun_root, receipts, floors, work, *,
                    repository, source, run_id, run_attempt):
        receipts, floors, inrun_root = Path(receipts), Path(floors), Path(inrun_root)
        self.assertEqual({path.name for path in receipts.iterdir()}, set(publication.builder.LAYOUTS))
        for target, name in publication.QUALIFICATION.items():
            self.assertEqual({path.name for path in (receipts / target).iterdir()}, {"result.json"})
            for member, data in self.members[name].items():
                self.assertEqual((receipts / member).read_bytes(), data)
        self.assertEqual({path.name for path in floors.iterdir()}, set(frontend.LINUX_TARGETS))
        for name in publication.FLOOR.values():
            for member, data in self.members[name].items():
                self.assertEqual((floors / member).read_bytes(), data)
        self.assertEqual(Path(qualification_inputs), inrun_root / "qualification-inputs-prep.json")
        for member, data in self.members[publication.PUBLIC_INPUTS].items():
            self.assertEqual((inrun_root / member).read_bytes(), data)
        self.assertEqual((Path(bundle) / "dist" / FILENAME).read_bytes(), self.wheel)
        self.assertFalse(Path(work).exists())
        self.assertEqual((Path(repository), source, run_id, run_attempt),
                         (self.repository, self.source, RUN_ID, "1"))
        return copy.deepcopy(self.matrix)

    def run_document(self):
        return {"id": int(RUN_ID), "run_attempt": 1, "status": "completed", "conclusion": "success",
                "event": "workflow_dispatch", "head_branch": "main", "head_sha": self.source["commit"],
                "path": ".github/workflows/rs9-tfnf-pypi-publish.yml",
                "repository": {"full_name": publication.REPOSITORY},
                "head_repository": {"full_name": publication.REPOSITORY},
                "head_commit": {"id": self.source["commit"], "tree_id": self.source["tree"]}}

    def write_capture(self, *, archives=None, run=None, artifacts=None, jobs=None):
        self.count += 1
        self.api = self.root / ("api-%d" % self.count)
        self.archives = self.root / ("archives-%d" % self.count)
        self.api.mkdir()
        self.archives.mkdir()
        raw = {name: zip_bytes(files) for name, files in self.members.items()}
        raw.update(archives or {})
        for name, data in raw.items():
            (self.archives / (name + ".zip")).write_bytes(data)
        rows = [{"id": ARTIFACT_IDS[name], "name": name, "size_in_bytes": len(raw[name]),
                 "digest": "sha256:" + sha(raw[name]), "expired": False,
                 "archive_download_url": "https://api.github.com/repos/" + publication.REPOSITORY
                 + "/actions/artifacts/%d/zip" % ARTIFACT_IDS[name],
                 "workflow_run": {"id": int(RUN_ID), "head_sha": self.source["commit"], "head_branch": "main"}}
                for name in publication.ARTIFACTS]
        documents = {"run.json": self.run_document(),
                     "artifacts.json": {"total_count": len(rows), "artifacts": rows},
                     "jobs.json": {"total_count": 1, "jobs": [{"id": 1, "name": "synthetic job"}]}}
        for key, edit in (("run.json", run), ("artifacts.json", artifacts), ("jobs.json", jobs)):
            if edit is not None:
                edit(documents[key])
        api = {name: json.dumps(value).encode() for name, value in documents.items()}
        for name, data in api.items():
            (self.api / name).write_bytes(data)
        self.authority = authority_for(
            self.members, raw, api, source=self.source, wheel=self.bundle_value["wheel"],
            runtime_inputs=self.bundle_value["runtime_inputs_sha256"],
            runtime_index=self.bundle_value["runtime_index_sha256"],
            description=self.bundle_value["description_sha256"])

    def capture(self):
        self.count += 1
        return publication.verify_capture(self.authority, self.api, self.archives,
                                          self.root / ("capture-%d" % self.count),
                                          repository=self.repository)


class CaptureTests(CaptureFixture):
    def test_complete_capture_recomputes_matrix_from_actual_extracted_artifacts(self):
        context = self.capture()
        self.assertEqual(context["wheel"], self.wheel)
        self.assertEqual(context["snapshot"]["wheel"], self.authority["wheel"])
        self.reader.assert_called_once()
        run, jobs = self.history.validate_qualification_jobs.call_args.args
        self.assertEqual((run["id"], jobs), (int(RUN_ID), [{"id": 1, "name": "synthetic job"}]))

    def test_run_metadata_must_be_the_successful_main_dispatch_of_the_source(self):
        edits = {
            "failure": lambda run: run.update(conclusion="failure"),
            "running": lambda run: run.update(status="in_progress"),
            "attempt": lambda run: run.update(run_attempt=2),
            "attempt-bool": lambda run: run.update(run_attempt=True),
            "id-string": lambda run: run.update(id=RUN_ID),
            "branch": lambda run: run.update(head_branch="rs9/nebular-pypi-qualify"),
            "event": lambda run: run.update(event="push"),
            "sha": lambda run: run.update(head_sha="c" * 40),
            "path": lambda run: run.update(path=".github/workflows/other.yml"),
            "fork": lambda run: run.update(head_repository={"full_name": "fork/release-starport-9"}),
            "tree": lambda run: run["head_commit"].update(tree_id="c" * 40),
        }
        for name, edit in edits.items():
            with self.subTest(edit=name):
                self.write_capture(run=edit)
                self.assertFails("QUALIFICATION_RUN", self.capture)
        self.reader.assert_not_called()

    def test_artifact_list_is_exact_without_diagnostics_surplus_or_expiry(self):
        def diagnostic(doc):
            doc["artifacts"].append(dict(doc["artifacts"][2], id=1, name=doc["artifacts"][2]["name"]
                                         + "-failure-diagnostic"))
            doc["total_count"] += 1
        edits = {
            "diagnostic": diagnostic,
            "missing": lambda doc: (doc["artifacts"].pop(), doc.update(total_count=7)),
            "count": lambda doc: doc.update(total_count=9),
            "closed": lambda doc: doc.update(next="page-2"),
            "expired": lambda doc: doc["artifacts"][0].update(expired=True),
            "digest": lambda doc: doc["artifacts"][1].update(digest="sha256:" + "0" * 64),
            "size": lambda doc: doc["artifacts"][1].update(size_in_bytes=1),
            "id": lambda doc: doc["artifacts"][1].update(id=str(doc["artifacts"][1]["id"])),
            "url": lambda doc: doc["artifacts"][1].update(archive_download_url="https://example.com/a.zip"),
            "other-run": lambda doc: doc["artifacts"][3]["workflow_run"].update(id=1),
            "other-sha": lambda doc: doc["artifacts"][3]["workflow_run"].update(head_sha="c" * 40),
        }
        for name, edit in edits.items():
            with self.subTest(edit=name):
                self.write_capture(artifacts=edit)
                self.assertFails("QUALIFICATION_ARTIFACTS", self.capture)

    def test_jobs_capture_is_closed_consistent_and_validated_by_history(self):
        for name, edit in {"count": lambda doc: doc.update(total_count=2),
                           "bool": lambda doc: doc.update(total_count=True),
                           "closed": lambda doc: doc.update(next="page-2"),
                           "empty": lambda doc: doc.update(total_count=0, jobs=[])}.items():
            with self.subTest(edit=name):
                self.write_capture(jobs=edit)
                self.assertFails("QUALIFICATION_JOBS", self.capture)
        self.write_capture()
        self.history.validate_qualification_jobs.side_effect = ContractError(
            "NEBULAR_UNIVERSAL_HISTORY_JOBS", "synthetic refusal")
        with self.assertRaises(ContractError) as caught:
            self.capture()
        self.assertEqual(caught.exception.code, "NEBULAR_UNIVERSAL_HISTORY_JOBS")
        self.reader.assert_not_called()

    def test_api_file_set_and_hashes_are_held(self):
        (self.api / "jobs.json").write_bytes(b'{"total_count": 0, "jobs": []}')
        self.assertFails("QUALIFICATION_API", self.capture)
        self.write_capture()
        (self.api / "extra.json").write_bytes(b"{}")
        self.assertFails("QUALIFICATION_API", self.capture)

    def test_zip_custody_refuses_tamper_surplus_links_modes_and_changed_members(self):
        darwin = publication.QUALIFICATION["darwin-arm64"]
        member = "darwin-arm64/result.json"
        held = self.members[darwin]
        cases = {
            "surplus-member": {publication.MATRIX: zip_bytes(
                {**self.members[publication.MATRIX], "extra.json": b"{}"})},
            "directory-member": {darwin: zip_bytes({"darwin-arm64/": b"", **held})},
            "symlink": {darwin: zip_bytes(held, modes={member: stat.S_IFLNK | 0o777})},
            "setuid": {darwin: zip_bytes(held, modes={member: stat.S_IFREG | 0o4755})},
            "fifo": {darwin: zip_bytes(held, modes={member: stat.S_IFIFO | 0o644})},
            "changed-member": {publication.MATRIX: zip_bytes({publication.MATRIX_MEMBER: b"{}\n"})},
            "not-zip": {darwin: b"synthetic non-archive bytes"},
        }
        for name, archives in cases.items():
            with self.subTest(case=name):
                self.write_capture(archives=archives)
                self.assertFails("ARCHIVE_MEMBERS", self.capture)
        self.write_capture()
        path = self.archives / (darwin + ".zip")
        data = bytearray(path.read_bytes())
        data[len(data) // 2] ^= 1
        path.write_bytes(bytes(data))
        self.assertFails("QUALIFICATION_ARCHIVE", self.capture)
        self.write_capture()
        (self.archives / "diagnostic.zip").write_bytes(b"x")
        self.assertFails("QUALIFICATION_ARCHIVE", self.capture)
        self.write_capture()
        path = self.archives / (darwin + ".zip")
        (self.root / "moved.zip").write_bytes(path.read_bytes())
        path.unlink()
        path.symlink_to(self.root / "moved.zip")
        self.assertFails("QUALIFICATION_ARCHIVE", self.capture)
        self.reader.assert_not_called()

    def test_recomputed_matrix_must_equal_held_matrix_and_authority(self):
        self.reader.side_effect = lambda *args, **kwargs: {**self.matrix, "status": "failed"}
        self.assertFails("MATRIX", self.capture)
        self.reader.side_effect = lambda *args, **kwargs: {**self.matrix, "lanes": self.matrix["lanes"][:3]}
        self.assertFails("MATRIX", self.capture)

    def test_current_qualification_readme_and_fresh_output_are_required(self):
        output = self.root / "existing"
        output.mkdir()
        self.assertFails("OUTPUT", publication.verify_capture, self.authority, self.api,
                         self.archives, output, repository=self.repository)
        self.assertFails("OUTPUT", publication.verify_capture, self.authority, self.api,
                         self.archives, self.repository / "build" / "capture", repository=self.repository)
        self.bundle_fixture.fixture.description.write_bytes(b"# Changed README\n")
        self.assertFails(None, self.capture)
        self.reader.assert_not_called()


class OperationTests(CaptureFixture):
    def setUp(self):
        super().setUp()
        self.publisher = self.root / "publisher"
        (self.publisher / publication.AUTHORITY.parent).mkdir(parents=True)
        (self.publisher / publication.AUTHORITY).write_bytes(canonical(self.authority))
        self.lineage = {"publisher_commit": P_HEAD, "publisher_tree": "f" * 40,
                        "qualification_commit": self.source["commit"],
                        "qualification_tree": self.source["tree"], "qualification_run_id": RUN_ID}
        self.env = {
            "GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": publication.REPOSITORY,
            "GITHUB_REF": "refs/heads/main", "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_WORKFLOW_REF": publication.REPOSITORY
            + "/.github/workflows/rs9-tfnf-pypi-publish.yml@refs/heads/main",
            "GITHUB_RUN_ATTEMPT": "1", "GITHUB_SHA": P_HEAD, "GITHUB_RUN_ID": CURRENT_RUN,
        }
        self.work = self.root / "work"
        self.upload = self.root / "upload"
        self.marker = self.root / "upload-attempt.json"
        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        self.lineage_check = stack.enter_context(patch.object(
            publication, "verify_source_lineage", return_value=self.lineage))
        self.prior = stack.enter_context(patch.object(publication, "_prior_runs"))

    def pypi(self, mode, **metadata):
        calls = []
        def fetch(url, limit):
            calls.append(url)
            if mode == "unknown":
                raise AdmissionError("TF_PYPI_REMOTE_UNKNOWN")
            if mode == "absent" or (mode == "version-absent" and url != PROJECT_URL):
                raise AdmissionError("TF_PYPI_REMOTE_ABSENT")
            if url == PROJECT_URL:
                releases = {} if mode == "version-absent" else {"0.7.0": []}
                return json.dumps({"info": {"name": "theme-forge-nebular-fusion"}, "releases": releases}).encode()
            if url == VERSION_URL:
                row = {"filename": FILENAME, "yanked": False, "size": len(self.wheel), "url": FILE_URL,
                       "digests": {"sha256": "0" * 64 if mode == "conflict" else sha(self.wheel)}}
                rows = [row]
                if mode == "surplus":
                    rows.append(dict(row, filename="theme_forge_nebular_fusion-0.7.0-py3-none-macosx_13_0_arm64.whl"))
                info = {"name": "theme-forge-nebular-fusion", "version": "0.7.0",
                        "license_expression": "AGPL-3.0-or-later", "requires_python": ">=3.10",
                        "description": self.description.decode(), "description_content_type": "text/markdown",
                        "yanked": False, **metadata}
                return json.dumps({"info": info, "urls": rows}).encode()
            if url == FILE_URL:
                return self.wheel
            raise AssertionError("unexpected index URL")
        fetch.calls = calls
        return fetch

    def select(self, fetch, *, work=None, env=None):
        return publication.select_missing(
            self.publisher, self.repository, self.api, self.archives, work or self.work, self.upload,
            self.marker, publisher_revision=P_HEAD, fetch=fetch, api_get=Mock(),
            environ=self.env if env is None else env)

    def verify(self, fetch, *, work, env=None):
        return publication.verify_upload(
            self.publisher, self.repository, self.api, self.archives, work, self.upload,
            self.marker, publisher_revision=P_HEAD, fetch=fetch, api_get=Mock(),
            environ=self.env if env is None else env)

    def readback(self, fetch, **kwargs):
        self.count += 1
        return publication.readback(self.publisher, self.repository, self.api, self.archives,
                                    self.root / ("readback-%d" % self.count), fetch=fetch, **kwargs)

    def expected_marker(self, run_id=CURRENT_RUN):
        return {"schema": publication.MARKER_SCHEMA, "project": "theme-forge-nebular-fusion",
                "version": "0.7.0", "distribution": "universal-launcher",
                "authority_identity": self.authority["identity"], "qualification_run_id": RUN_ID,
                "publisher_commit": P_HEAD, "publisher_run_id": run_id, "filename": FILENAME,
                "size": len(self.wheel), "sha256": sha(self.wheel)}

    def test_absent_index_stages_exact_single_wheel_after_history_and_marker(self):
        def history_guard(api_get, environ):
            self.assertFalse(self.marker.exists())
            self.assertFalse(self.upload.exists())
            self.assertEqual(environ, self.env)
        self.prior.side_effect = history_guard
        self.assertEqual(self.select(self.pypi("absent")), {"upload": True, "state": "absent"})
        self.prior.assert_called_once()
        self.assertEqual([path.name for path in self.upload.iterdir()], [FILENAME])
        self.assertEqual((self.upload / FILENAME).read_bytes(), self.wheel)
        self.assertEqual(json.loads(self.marker.read_bytes()), self.expected_marker())
        self.lineage_check.assert_called_once()
        self.assertEqual(self.lineage_check.call_args.kwargs["publisher_revision"], P_HEAD)

    def test_version_absent_also_stages(self):
        self.assertEqual(self.select(self.pypi("version-absent")), {"upload": True, "state": "version-absent"})

    def test_existing_attempt_marker_refuses_before_index_history_or_staging(self):
        self.marker.write_bytes(b"{}")
        fetch = self.pypi("absent")
        self.assertFails("OUTPUT", self.select, fetch)
        self.assertEqual(fetch.calls, [])
        self.prior.assert_not_called()
        self.assertFalse(self.upload.exists())

    def test_published_exact_is_read_only(self):
        fetch = self.pypi("exact")
        self.assertEqual(self.select(fetch), {"upload": False, "state": "published-exact"})
        self.assertIn(FILE_URL, fetch.calls)
        self.prior.assert_not_called()
        self.assertFalse(self.marker.exists())
        self.assertFalse(self.upload.exists())

    def test_conflict_unknown_surplus_and_metadata_mismatch_refuse(self):
        cases = {
            "conflict": ("REMOTE_CONFLICT", self.pypi("conflict")),
            "unknown": ("REMOTE_UNKNOWN", self.pypi("unknown")),
            "surplus": ("REMOTE_CONFLICT", self.pypi("surplus")),
            "license": ("REMOTE_METADATA", self.pypi("exact", license_expression="MIT")),
            "python": ("REMOTE_METADATA", self.pypi("exact", requires_python=">=3.8")),
            "readme": ("REMOTE_METADATA", self.pypi("exact", description="Changed README")),
        }
        for index, (name, (code, fetch)) in enumerate(cases.items()):
            with self.subTest(case=name):
                self.assertFails(code, self.select, fetch, work=self.root / ("work-%d" % index))
        self.prior.assert_not_called()
        self.assertFalse(self.marker.exists())
        self.assertFalse(self.upload.exists())

    def test_unconfirmed_prior_upload_and_hosted_context_fail_before_effects(self):
        changes = {
            "unconfirmed": {"RS9_TFNF_PRIOR_UPLOAD_UNCONFIRMED": "1"},
            "sha": {"GITHUB_SHA": self.source["commit"]},
            "attempt": {"GITHUB_RUN_ATTEMPT": "2"},
            "ref": {"GITHUB_REF": "refs/heads/rs9/nebular-pypi-qualify"},
            "event": {"GITHUB_EVENT_NAME": "push"},
            "workflow": {"GITHUB_WORKFLOW_REF": publication.REPOSITORY + "/.github/workflows/x.yml@refs/heads/main"},
            "same-run": {"GITHUB_RUN_ID": RUN_ID},
            "run-id": {"GITHUB_RUN_ID": "0"},
            "not-actions": {"GITHUB_ACTIONS": "false"},
        }
        for name, change in changes.items():
            with self.subTest(change=name):
                fetch = self.pypi("absent")
                self.assertFails(None, self.select, fetch, env={**self.env, **change})
                self.assertFalse(self.work.exists())
                self.assertEqual(fetch.calls, [])
        self.reader.assert_not_called()
        self.prior.assert_not_called()

    def test_verify_upload_rechecks_bytes_marker_absence_and_history(self):
        self.select(self.pypi("absent"))
        self.assertEqual(self.verify(self.pypi("absent"), work=self.root / "verify"),
                         {"verified": True, "state": "absent"})
        self.assertEqual(self.prior.call_count, 2)
        self.assertFails("REMOTE_PUBLISHED_EXACT", self.verify, self.pypi("exact"), work=self.root / "verify-exact")
        self.assertFails("ATTEMPT_MARKER", self.verify, self.pypi("absent"), work=self.root / "verify-run",
                         env={**self.env, "GITHUB_RUN_ID": "6161"})
        original = self.marker.read_bytes()
        self.marker.unlink()
        self.assertFails("ATTEMPT_MARKER", self.verify, self.pypi("absent"), work=self.root / "verify-marker")
        self.marker.write_bytes(original)
        (self.upload / "extra.whl").write_bytes(b"x")
        self.assertFails("UPLOAD_DIR", self.verify, self.pypi("absent"), work=self.root / "verify-extra")
        (self.upload / "extra.whl").unlink()
        (self.upload / FILENAME).write_bytes(self.wheel[:-1] + bytes([self.wheel[-1] ^ 1]))
        self.assertFails("UPLOAD_BYTES", self.verify, self.pypi("absent"), work=self.root / "verify-bytes")

    def test_marker_ancestry_is_checked_before_normalizing_a_symlink_parent_alias(self):
        self.select(self.pypi("absent"))
        alias = self.root / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        fetch = self.pypi("absent")
        self.assertFails(None, publication.verify_upload,
                         self.publisher, self.repository, self.api, self.archives,
                         self.root / "verify-alias", self.upload,
                         alias / ".." / self.marker.name,
                         publisher_revision=P_HEAD, fetch=fetch, api_get=Mock(), environ=self.env)
        self.assertEqual(fetch.calls, [])

    def test_readback_confirms_exact_file_license_and_readme_without_upload(self):
        sleep = Mock()
        result = self.readback(self.pypi("exact"), schedule=(0, 5), sleep=sleep)
        self.assertEqual((result["state"], result["attempts"], result["wheel"]["sha256"], result["public_writes"]),
                         ("published-exact", 1, sha(self.wheel), 0))
        sleep.assert_not_called()
        self.assertNotIn(str(self.root), json.dumps(result))

    def test_readback_refuses_mismatch_conflict_and_unconfirmed_absence(self):
        self.assertFails("REMOTE_METADATA", self.readback, self.pypi("exact", license_expression="MIT"),
                         sleep=Mock())
        self.assertFails("REMOTE_METADATA", self.readback, self.pypi("exact", description="Other"),
                         sleep=Mock())
        sleep = Mock()
        self.assertFails("READBACK_CONFLICT", self.readback, self.pypi("conflict"), schedule=(0, 1), sleep=sleep)
        sleep.assert_not_called()
        self.assertFails("READBACK_ABSENT", self.readback, self.pypi("absent"), schedule=(0, 1, 2), sleep=sleep)
        self.assertEqual([call.args for call in sleep.call_args_list], [(1.0,), (2.0,)])
        self.assertFails("READBACK_SCHEDULE", self.readback, self.pypi("exact"), schedule=(0, 601))


class GuardAndCliTests(Failures, unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.publisher = self.root / "publisher"
        (self.publisher / publication.AUTHORITY.parent).mkdir(parents=True)
        self.authority = synthetic_authority()
        (self.publisher / publication.AUTHORITY).write_bytes(canonical(self.authority))

    def run_main(self, argv):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = publication.main(argv)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_prior_history_guard_keeps_legacy_reader_and_adds_universal_hook(self):
        history = types.SimpleNamespace(check_prior_universal_run=Mock())
        api_get, environ = Mock(), {"GITHUB_ACTIONS": "true"}
        with patch.object(publication, "_history", return_value=history), \
             patch.object(publication.legacy, "check_prior_publish_runs") as guard:
            ORIGINAL_PRIOR_RUNS(api_get, environ)
        guard.assert_called_once_with(api_get=api_get, environ=environ,
                                      additional_run_validator=history.check_prior_universal_run)

    def test_malformed_internal_observer_results_fail_closed_for_library_callers(self):
        for result in (None, [], {"state": []}, {"state": "unrecognized"}):
            with self.subTest(result=result), patch.object(publication.remote, "approved_state", return_value=result):
                self.assertEqual(publication.index_state(self.authority, b"fixture", b"README", Mock()), "unknown")
        with patch.object(publication.remote, "approved_state", return_value={"state": "published-exact", "bodies": []}):
            self.assertFails("REMOTE_CONFLICT", publication.index_state, self.authority, b"fixture", b"README", Mock())

    def test_resolve_outputs_only_checkout_coordinates(self):
        self.assertEqual(self.run_main(["resolve", "--publisher-dir", str(self.publisher)]),
                         (0, "qualification_commit=" + "a" * 40 + "\nqualification_run_id=" + RUN_ID + "\n", ""))

    def test_errors_are_code_only_without_private_paths(self):
        private = self.root / "private-runner-name"
        code, stdout, stderr = self.run_main(["resolve", "--publisher-dir", str(private)])
        self.assertEqual((code, stdout, stderr), (1, "", "NEBULAR_UNIVERSAL_PUBLICATION_AUTHORITY\n"))
        with patch.object(publication, "select_missing", side_effect=OSError(str(private))):
            code, stdout, stderr = self.run_main([
                "select-missing", "--publisher-dir", "p", "--qualification-dir", "q", "--api-dir", "a",
                "--archives-dir", "z", "--work", "w", "--upload-dir", "u", "--attempt-marker", "m",
                "--publisher-revision", P_HEAD])
        self.assertEqual((code, stdout, stderr), (1, "", "NEBULAR_UNIVERSAL_PUBLICATION_CONTRACT\n"))

    def test_mutation_commands_emit_machine_safe_outputs_and_require_marker(self):
        common = ["--publisher-dir", "p", "--qualification-dir", "q", "--api-dir", "a",
                  "--archives-dir", "z", "--work", "w", "--upload-dir", "u", "--publisher-revision", P_HEAD]
        with patch.object(publication, "select_missing", return_value={"upload": True, "state": "absent"}):
            self.assertEqual(self.run_main(["select-missing", *common, "--attempt-marker", "m"]),
                             (0, "upload=true\nstate=absent\n", ""))
        with patch.object(publication, "verify_upload", return_value={"verified": True, "state": "version-absent"}):
            self.assertEqual(self.run_main(["verify-upload", *common, "--attempt-marker", "m"]),
                             (0, "verified=true\nstate=version-absent\n", ""))
        for argv in (["verify-upload", *common], ["upload", *common]):
            with self.subTest(argv=argv[0]), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    publication.parser().parse_args(argv)

    def test_module_has_no_index_write_path(self):
        source = Path(publication.__file__).read_text()
        for token in ("upload.pypi.org", "twine", "legacy/", "Authorization"):
            self.assertNotIn(token, source)


if __name__ == "__main__":
    unittest.main()
