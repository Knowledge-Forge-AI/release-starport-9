"""LIVE1 preparation and independently downloaded registry file boundaries."""
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError
import zipfile

from rs9.bootstrap import configuration_inventory, load_bootstrap
from rs9.errors import ContractError
from rs9.operator import assert_release_expectations, authenticate_generation, main, preparation_status
from rs9.planner import adapter_output, destination_policy, plan
from rs9.readers import has_live_proof, read_pypi
from rs9.records import build_semantic_content_identity, record_sha256
from rs9.release_core import digest
from rs9.scratch import canonical
from tests.publication_fixtures import fixture

ROOT = Path(__file__).resolve().parents[1]


def registry_fixture(*, missing_provenance=False):
    identity=build_semantic_content_identity("theme-forge-stellar-loom","0.4.0","wheel","pypi",{"payload":"a"*64},{"configuration":"b"*64})
    from rs9.records import semantic_identity_sha256
    buffer=io.BytesIO()
    with zipfile.ZipFile(buffer,"w") as wheel:
        wheel.writestr("wrapper/__init__.py", "")
        if not missing_provenance:
            wheel.writestr("wrapper/_rs9/provenance.json",canonical({"content_identity_sha256":semantic_identity_sha256(identity)}))
    data=buffer.getvalue();name="theme_forge_stellar_loom-0.4.0-py3-none-any.whl";sha=hashlib.sha256(data).hexdigest()
    output=adapter_output({"id":"pypi","adapter":"pypi","mode":"direct"},
        {"package":"theme-forge-stellar-loom","version":"0.4.0","revision":None},identity,
        [{"path":name,"size":len(data),"sha256":sha}],{"purpose":"synthetic-test"},
        implementation={"id":"synthetic-test","version":"1"},source_version="test-1")
    metadata={"info":{"name":"theme_forge_stellar_loom","version":"0.4.0","license_expression":"AGPL-3.0-or-later"},"last_serial":3,
        "urls":[{"filename":name,"url":"https://files.pythonhosted.org/test/"+name,"size":len(data),"digests":{"sha256":sha}}]}
    return output,metadata,data


class ReaderOperatorTests(unittest.TestCase):
    def test_transport_failure_never_implies_name_absence(self):
        output,_,_=registry_fixture()
        with patch("rs9.readers._get",side_effect=URLError("synthetic network unavailable")):
            self.assertEqual(read_pypi(output)["state"],"unknown")
        meta_url = f"https://pypi.org/pypi/{output['subject']['package']}/{output['subject']['version']}/json"
        for code,state in ((404,"absent"),(403,"unknown"),(503,"unknown")):
            with patch("rs9.readers._get",side_effect=HTTPError(meta_url,code,"test",{},None)):
                result=read_pypi(output)
                self.assertEqual(result["state"],state)
                self.assertTrue(has_live_proof(result))
        # Response URL mismatch on 404 must not imply absence
        with patch("rs9.readers._get",side_effect=HTTPError("https://pypi.org/",404,"test",{},None)):
            result=read_pypi(output)
            self.assertEqual(result["state"],"unknown")
            self.assertTrue(has_live_proof(result))

    def test_pypi_file_404_is_unknown_and_fails_closed_in_planner(self):
        output,metadata,_=registry_fixture()
        meta_url = f"https://pypi.org/pypi/{output['subject']['package']}/{output['subject']['version']}/json"
        file_url = metadata["urls"][0]["url"]
        def fake_get_file_404(url, hosts, limit):
            if url == meta_url:
                return canonical(metadata)
            if url == file_url:
                raise HTTPError(file_url, 404, "Not Found", {}, None)
            raise ValueError(url)

        with patch("rs9.readers._get", side_effect=fake_get_file_404):
            obs = read_pypi(output)
        self.assertEqual(obs["state"], "unknown")
        self.assertEqual(obs["readback"]["presence"], "unknown")
        self.assertTrue(has_live_proof(obs))

        # Prove file 404 is fail closed in planner
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            bundle = fixture(root)
            n, c, p, _, g, _ = bundle
            config = root / "bootstrap" / "project"
            config.mkdir(parents=True)
            (config / "intent.json").write_bytes(canonical(n))
            row = {"repository": c.record["repository"]["full_name"], "repository_id": c.record["repository"]["id"],
                   "release_id": c.record["release"]["id"], "tag": n["tag"], "version": n["version"],
                   "tag_commit": c.record["tag"]["commit"], "tag_tree": c.record["tag"]["tree"],
                   "configuration": "project", "config_sha256": record_sha256(configuration_inventory(config))}
            manifest = {"schema": "rs9.bootstrap-tenant-manifest.v1alpha1", "bootstrap-pre-rs9": True,
                        "release-contains-rs9": False, "scope": "exact-generation", "future-releases": "forbidden", "projects": [row]}
            path = config.parent / "manifest.json"
            path.write_bytes(canonical(manifest))
            load_bootstrap(path, c, approved_manifests=[digest(path.read_bytes())])

            identity = build_semantic_content_identity(n["project"]["id"], n["version"], "second-project", "pypi",
                {r["name"]: r["sha256"] for r in c.record["payloads"]},
                {"configuration": record_sha256(n)})
            whl_name = "second_project-0.6.1-py3-none-any.whl"
            whl_bytes = b"fake-wheel"
            whl_sha = hashlib.sha256(whl_bytes).hexdigest()
            pypi_out = adapter_output({"id": "pypi", "adapter": "pypi", "mode": "direct"},
                {"package": "second-project", "version": "0.6.1", "revision": None},
                identity, [{"path": whl_name, "size": len(whl_bytes), "sha256": whl_sha}],
                {"purpose": "synthetic"}, implementation={"id": "test", "version": "1"}, source_version="1")
            pypi_meta = {"info": {"name": "second-project", "version": "0.6.1", "license_expression": "AGPL-3.0-or-later"},
                "last_serial": 1, "urls": [{"filename": whl_name, "url": "https://files.pythonhosted.org/packages/" + whl_name,
                                            "size": len(whl_bytes), "digests": {"sha256": whl_sha}}]}
            p_meta_url = "https://pypi.org/pypi/second-project/0.6.1/json"
            p_file_url = "https://files.pythonhosted.org/packages/" + whl_name
            def fake_get_pypi(url, hosts, limit):
                if url == p_meta_url:
                    return canonical(pypi_meta)
                if url == p_file_url:
                    raise HTTPError(p_file_url, 404, "Not Found", {}, None)
                raise ValueError(url)

            with patch("rs9.readers._get", side_effect=fake_get_pypi):
                file_obs = read_pypi(pypi_out)
            self.assertEqual(file_obs["state"], "unknown")
            self.assertEqual(file_obs["readback"]["presence"], "unknown")
            plan_res = plan(n, c, p, pypi_out, g, destination_policy(), file_obs, evaluated_at=file_obs["observed_at"])
            self.assertEqual(plan_res["outcome"], "defer-readback")
            self.assertEqual(plan_res["reasons"], ["unknown"])

    def test_every_file_metadata_and_semantic_identity_are_required(self):
        output,metadata,data=registry_fixture()
        with patch("rs9.readers._get",side_effect=[canonical(metadata),data]):
            result=read_pypi(output)
        self.assertEqual(result["state"],"exact")
        self.assertEqual(result["remote"],{"sequence":3})
        self.assertFalse(has_live_proof(json.loads(canonical(result))))
        result["remote"]["sequence"]=4
        self.assertFalse(has_live_proof(result))
        for key,value in (("name","different"),("version","0.4.1"),("license_expression","AGPL-3.0-or-later OR Commercial")):
            modified=json.loads(canonical(metadata));modified["info"][key]=value
            with patch("rs9.readers._get",return_value=canonical(modified)):
                self.assertEqual(read_pypi(output)["state"],"unknown")
        output,metadata,data=registry_fixture(missing_provenance=True)
        with patch("rs9.readers._get",side_effect=[canonical(metadata),data]):
            self.assertEqual(read_pypi(output)["state"],"incomplete")
        metadata["urls"][0]["size"]+=1
        with patch("rs9.readers._get",side_effect=[canonical(metadata),data]):
            self.assertEqual(read_pypi(output)["state"],"unknown")

    def test_operator_remains_closed_and_bootstrap_needs_reviewed_hash(self):
        self.assertFalse(preparation_status(ROOT)["production_enabled"])
        with patch("rs9.operator.checked_checkout"), patch("rs9.operator.authenticate_generation") as authentication:
            with patch("builtins.print"):
                self.assertEqual(main(["publish-pages","--repository",str(ROOT)]),2)
                self.assertEqual(main(["publish-pypi","--repository",str(ROOT)]),2)
            authentication.assert_not_called()
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ContractError) as error:
                authenticate_generation(ROOT,Path(tmp).resolve(),approved_bootstrap_sha256="a"*64)
            self.assertEqual(error.exception.code,"BOOTSTRAP_APPROVAL")

    def test_release_mismatch_is_a_hard_stop(self):
        from tests.publication_fixtures import fixture
        from rs9.release_core import authenticate_release
        from rs9.profiles import selection_for_intent
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            intent = fixture(root)[0]
            release_path = root / "api/release.json"
            release = json.loads(release_path.read_bytes())
            release.update(immutable=False, published_at="2026-10-03T12:00:00Z")
            release_path.write_bytes(canonical(release))
            capture = authenticate_release(selection_for_intent(intent), root)
            record = capture.record
            expected = {"repository": record["repository"]["full_name"], "repository_id": record["repository"]["id"],
                "tag": record["release"]["tag"], "release_id": record["release"]["id"], "commit": record["tag"]["commit"],
                "tree": record["tag"]["tree"], "immutable": False, "contains_rs9": False,
                "truncated": False, "published_at": "2026-10-03T12:00:00Z",
                "assets": [{"name": a["name"], "id": a["github_asset_id"], "size": a["size"], "sha256": a["sha256"]}
                            for a in record["assets"]]}
            assert_release_expectations(capture, expected)
            for key, value in (("release_id", expected["release_id"] + 1), ("commit", "e" * 40), ("tree", "e" * 40), ("tag", "v999.0.0"), ("immutable", True)):
                modified = {**expected, key: value}
                with self.assertRaises(ContractError): assert_release_expectations(capture, modified)
            expected["assets"][0]["sha256"] = "e" * 64
            with self.assertRaises(ContractError): assert_release_expectations(capture, expected)
