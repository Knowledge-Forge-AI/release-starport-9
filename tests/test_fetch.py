import json
from pathlib import Path
import tempfile
import unittest
from urllib.parse import unquote

from rs9.errors import ContractError
from rs9.fetch import fetch
from rs9.ingestion import authenticate

from tests.shadow_fixtures import fixture_evidence


class FixtureClient:
    """A transport seam, not live authentication evidence."""
    def __init__(self, directory, normalized):
        self.root, self.n = directory, normalized
        self.receipts = []

    def json(self, url, **kwargs):
        return json.loads(self.get(url, **kwargs))

    def get(self, url, **kwargs):
        base = "https://api.github.com/repos/" + self.n["project"]["repository"]
        api = {base: "repository", base + "/git/ref/tags/v0.6.1": "ref",
               base + "/git/commits/" + "a" * 40: "commit",
               base + "/git/trees/" + "b" * 40 + "?recursive=1": "tree",
               base + "/releases/tags/v0.6.1": "release"}
        if url in api:
            data = (self.root / "api" / (api[url] + ".json")).read_bytes()
            if api[url] == "release":
                release = json.loads(data)
                for asset in release["assets"]:
                    asset["browser_download_url"] = "https://github.com/" + self.n["project"]["repository"] + "/releases/download/v0.6.1/" + asset["name"]
                return json.dumps(release).encode()
            return data
        prefix = "https://raw.githubusercontent.com/" + self.n["project"]["repository"] + "/" + "a" * 40 + "/"
        if url.startswith(prefix):
            return (self.root / "source" / unquote(url[len(prefix):])).read_bytes()
        if "/releases/download/v0.6.1/" in url:
            return (self.root / "assets" / unquote(url.rsplit("/", 1)[1])).read_bytes()
        if url == "https://registry.npmjs.org/fixture.tgz":
            return (self.root / "npm/package.tgz").read_bytes()
        if url.startswith("https://registry.npmjs.org/"):
            data = json.loads((self.root / "npm/metadata.json").read_bytes())
            data["dist"]["tarball"] = "https://registry.npmjs.org/fixture.tgz"
            return json.dumps(data).encode()
        raise ContractError("FETCH_FAILED", "Unexpected fixture transport request")


class FetchTests(unittest.TestCase):
    def test_collector_connects_to_byte_authentication_offline(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            source = root / "source"
            source.mkdir()
            normalized = fixture_evidence(source)
            output = root / "output"
            output.mkdir()
            fetch(normalized, output, client=FixtureClient(source, normalized))
            self.assertEqual(authenticate(normalized, source).record, authenticate(normalized, output).record)
            self.assertTrue((output / "fetch-receipt.json").is_file())

    def test_network_failure_never_emits_ingestion_record(self):
        class Unavailable:
            def json(self, *args, **kwargs):
                raise ContractError("FETCH_FAILED", "Fixture unavailable transport")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            source = root / "source"
            source.mkdir()
            n = fixture_evidence(source)
            output = root / "output"
            output.mkdir()
            with self.assertRaises(ContractError) as caught:
                fetch(n, output, client=Unavailable())
            self.assertEqual(caught.exception.code, "FETCH_FAILED")
            self.assertEqual(list(output.iterdir()), [])
