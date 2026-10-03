"""Candidate capture fails closed and confines workflow API identity."""
from pathlib import Path
import tempfile
import unittest
from urllib.request import Request

from rs9.candidate import capture_generation, configuration_rows
from rs9.errors import ContractError
from rs9.github import Redirects, ScopedGitHubAuthorization


ROOT = Path(__file__).resolve().parents[1]


class CandidateCaptureTests(unittest.TestCase):
    def test_checked_generation_is_exactly_four_projects(self):
        self.assertEqual(len(configuration_rows(ROOT)), 4)

    def test_unavailable_transport_does_not_build_or_make_summary(self):
        class Unavailable:
            def json(self, *args, **kwargs):
                raise ContractError("FETCH_FAILED", "Unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            with self.assertRaises(ContractError):
                capture_generation(ROOT, root, client=Unavailable())
            self.assertFalse((root / "summary").exists())
            self.assertFalse(list(root.rglob("*.whl")))

    def test_unknown_project_never_contacts_network(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(ContractError):
                capture_generation(ROOT, Path(temporary).resolve(), project="unknown")

    def test_workflow_identity_never_copied_to_release_redirect(self):
        handler = ScopedGitHubAuthorization("test-only-identity")
        request = handler.https_request(Request("https://api.github.com/repos/example/project"))
        self.assertIsNotNone(request.get_header("Authorization"))
        redirected = Redirects().redirect_request(request, None, 302, "", {}, "https://release-assets.githubusercontent.com/file")
        self.assertIsNone(handler.https_request(redirected).get_header("Authorization"))
        self.assertIsNone(handler.https_request(Request("https://raw.githubusercontent.com/example/project/file")).get_header("Authorization"))
        self.assertIsNone(handler.https_request(Request("https://api.github.com/repos/example/project", method="POST")).get_header("Authorization"))
