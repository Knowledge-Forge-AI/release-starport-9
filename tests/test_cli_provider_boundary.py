"""Real 0.8 parser/provider boundary checks over the retained public fixture."""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import unittest
from unittest import mock
from urllib.parse import urlsplit

from rs9.errors import ContractError
from rs9.github import PublicClient
from rs9.tf_pypi_archive import AdmissionError
from rs9.nebular080_github_provider import github_json_provider
from rs9 import nebular080_universal_publication as publication
from rs9 import tf_pypi_nebular080_publish as support


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = json.loads((ROOT / "tests/fixtures/github-history-fixture.json").read_text())
RUNS = FIXTURE["workflow_runs"]
BY_ID = {row["id"]: row for row in RUNS}
REPOSITORY = "Knowledge-Forge-AI/release-starport-9"
WORKFLOW = (ROOT / ".github/workflows/rs9-tfnf-pypi-publish.yml").read_text()


class _Response:
    status = 200

    def __init__(self, url: str, body: bytes) -> None:
        self._url = url
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def geturl(self):
        return self._url

    def read(self, _size=-1):
        body, self._body = self._body, b""
        return body


class _FixtureOpener:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def open(self, request, *, timeout):
        url = request.full_url
        self.calls.append((request.get_method(), url))
        parsed = urlsplit(url)
        if parsed.path.endswith(f"/actions/workflows/rs9-tfnf-pypi-publish.yml/runs"):
            document = {"total_count": len(RUNS), "workflow_runs": RUNS}
        elif "/actions/runs/" in parsed.path and parsed.path.endswith("/jobs"):
            run_id = int(parsed.path.split("/actions/runs/", 1)[1].split("/", 1)[0])
            document = {"total_count": len(BY_ID[run_id]["jobs"]), "jobs": BY_ID[run_id]["jobs"]}
        else:
            raise AssertionError(f"unexpected public fixture URL: {url}")
        return _Response(url, json.dumps(document, separators=(",", ":")).encode())


class CliProviderBoundaryTests(unittest.TestCase):
    def test_actual_parser_dispatches_history_through_public_client(self):
        opener = _FixtureOpener()
        client = PublicClient(opener=opener, api_token="synthetic-public-fixture-token")
        provider = github_json_provider(
            environ={"GITHUB_ACTIONS": "true", "RS9_GITHUB_READ_TOKEN": "synthetic"},
            client=client,
        )
        output = io.StringIO()
        with mock.patch.object(publication.sys, "stdout", output):
            result = publication.main(
                ["check-history"],
                api_get=provider,
                environ={"GITHUB_RUN_ATTEMPT": "1", "GITHUB_REPOSITORY": REPOSITORY},
            )
        self.assertEqual(result, 0)
        self.assertEqual(output.getvalue(), "history=verified\n")
        self.assertEqual(len(RUNS), 22)
        self.assertEqual(len(opener.calls), 23)
        self.assertTrue(all(method == "GET" for method, _ in opener.calls))
        self.assertFalse(any(method != "GET" for method, _ in opener.calls))

    def test_missing_hosted_credential_fails_closed_before_provider_call(self):
        with self.assertRaisesRegex(ContractError, "GITHUB_PROVIDER_CREDENTIALS"):
            github_json_provider(environ={"GITHUB_ACTIONS": "true"})
        with self.assertRaisesRegex(ContractError, "GITHUB_PROVIDER_UNAVAILABLE"):
            github_json_provider(environ={})
        stderr = io.StringIO()
        with mock.patch.object(publication.sys, "stderr", stderr):
            result = publication.main(["check-history"], environ={"GITHUB_ACTIONS": "true"})
        self.assertEqual(result, 1)
        self.assertEqual(stderr.getvalue().strip(), "GITHUB_PROVIDER_CREDENTIALS")

        stderr = io.StringIO()
        with mock.patch.object(support.sys, "stderr", stderr):
            result = support.main([
                "prepare-public-inputs-080",
                "--source-manifest", "TRACKED080-MANIFEST.json",
                "--release-binding", "RELEASE-BINDING.json",
                "--output", "prepared-inputs",
                "--repository", ".",
            ], environ={"GITHUB_ACTIONS": "true"})
        self.assertEqual(result, 1)
        self.assertEqual(stderr.getvalue().strip(), "GITHUB_PROVIDER_CREDENTIALS")

    def test_preparation_cli_requires_closed_manifest_and_binding(self):
        args = support.parser().parse_args([
            "prepare-public-inputs-080",
            "--source-manifest", "TRACKED080-MANIFEST.json",
            "--release-binding", "RELEASE-BINDING.json",
            "--output", "prepared-inputs",
            "--repository", ".",
        ])
        self.assertEqual(args.source_manifest, "TRACKED080-MANIFEST.json")
        self.assertEqual(args.release_binding, "RELEASE-BINDING.json")
        source = (ROOT / "src/rs9/tf_pypi_nebular080_publish.py").read_text()
        self.assertIn("acquire_public_inputs_080", source)
        self.assertNotIn("prepare_public_inputs_080(", source)
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                support.parser().parse_args([
                    "prepare-public-inputs-080",
                    "--manifest", "legacy-descriptor.json",
                    "--output", "prepared-inputs",
                ])

    def test_empty_history_fails_closed_at_route_boundary(self):
        def empty_provider(url):
            if "/actions/workflows/" in url:
                return {"total_count": 0, "workflow_runs": []}
            raise AssertionError(f"unexpected empty-history URL: {url}")

        with self.assertRaises((ContractError, AdmissionError)):
            publication._prior_runs(
                empty_provider,
                {"GITHUB_RUN_ATTEMPT": "1", "GITHUB_REPOSITORY": REPOSITORY},
            )

    def test_outside_actions_run_id_cannot_hide_a_completed_row(self):
        with self.assertRaisesRegex(ContractError, "HISTORY_CONTEXT"):
            publication._prior_runs(
                lambda _url: {"total_count": 0, "workflow_runs": []},
                {
                    "GITHUB_RUN_ATTEMPT": "1",
                    "GITHUB_REPOSITORY": REPOSITORY,
                    "GITHUB_RUN_ID": str(RUNS[0]["id"]),
                },
            )

    def test_generated_publication_workflow_uses_real_route_and_read_token(self):
        self.assertIn(
            "-m rs9.nebular080_universal_publication select-missing",
            WORKFLOW,
        )
        self.assertIn(
            "-m rs9.nebular080_universal_publication verify-upload",
            WORKFLOW,
        )
        self.assertIn("RS9_GITHUB_READ_TOKEN: ${{ github.token }}", WORKFLOW)

    def test_support_cli_registration_remains_real_and_080_closed(self):
        args = support.parser().parse_args([
            "validate-dispatch", "--release", "0.8.0", "--mode", "universal-publish",
        ])
        self.assertEqual(args.operation, "validate-dispatch")
        self.assertEqual(support.validate_workflow_dispatch(args.release, args.mode)["mode"], "universal-publish")
        self.assertEqual(publication.parser().parse_args(["check-history"]).operation, "check-history")


if __name__ == "__main__":
    unittest.main()
