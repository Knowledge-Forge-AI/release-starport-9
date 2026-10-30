"""Real tagged sources; controlled release/tool fixtures do not claim native results."""
import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rs9 import nebular_callers as callers
from rs9.release_core import digest
from rs9.rpm_lint_policy import evaluate_policy, load_policy
from rs9.scratch import canonical

SOURCES = Path(__file__).parent / 'fixtures/nebular-0.6.1/caller-sources.json'


def attach_caller_fixture(inventory, inputs):
    """Actual source bytes plus explicit external package/manifest test doubles."""
    source_rows = json.loads(SOURCES.read_bytes())
    for row in source_rows.values():
        row['tag_commit'] = callers.TAG_COMMIT
    inventory['caller_evidence'] = dict(schema='rs9.nebular-caller-sources.v1', status='available',
        tag_commit=callers.TAG_COMMIT, tag_tree=callers.TAG_TREE, files=source_rows)
    def add(path, sha, size, mode):
        row=dict(path=path,type='file',sha256=sha,size=size,mode=mode,device=1,inode=90000+len(inventory['files']),owner='root',group='root',flags=0)
        inventory['files'][path]=row
        inventory['expected'][path]=dict(row,origin='release',input_archive_sha256=inputs['asset_sha256'],
            input_member=path.removeprefix('/usr/lib/'))
    binding=json.loads(inventory['caller_evidence']['files']['protocol/theme-lab-v2/payload-binding.json']['content'])
    for row in binding['files']:
        path=callers.PAYLOAD+'/loom-payload/'+row['path']
        if path in inventory['files']:
            inventory['files'][path]['size']=row['bytes']
            inventory['expected'][path]['size']=row['bytes']
    rt=callers.RUNTIME_PINS[inputs['system']]
    add(callers.RUNTIME,rt['sha256'],rt['size'],0o755)
    add(callers.ROOT+'/bin/'+callers.NEBULAR_PROJECT_ID,digest(b'external-main-binary-double'),37,0o755)
    members=[dict(path=p.removeprefix(callers.PAYLOAD+'/sidecar-payload/'), **{k:r[k] for k in ('sha256','size','mode')})
        for p,r in inventory['files'].items() if '/sidecar-payload/' in p and p!=callers.MANIFEST]
    manifest=dict(schema='tfsb.studio-sidecar-distribution',runtimeKind='node-runtime-payload-v1',target=rt['target'],
        entrypoint='dist/service-protocol/server-cli.js',runtime=dict(rt,mode=0o755,version='22.23.3'),files=members)
    data=canonical(manifest)
    add(callers.MANIFEST,digest(data),len(data),0o644)
    inventory.setdefault('contract_members',{})[callers.MANIFEST]=data.decode()
    metadata=json.loads(SOURCES.with_name('caller-payload-members.json').read_bytes())['loom:package/package.json']
    add(callers.FLOOR_MEMBER,metadata['sha256'],metadata['size'],metadata['mode'])
    inventory['contract_members'][callers.FLOOR_MEMBER]=metadata['content']


class NebularCallerTests(unittest.TestCase):
    def test_policy_intent_matches_authenticated_role(self):
        from rs9.errors import ContractError
        policy = load_policy()
        for rules in policy['projects'][callers.NEBULAR_PROJECT_ID]['exceptions'].values():
            for path, rule in rules.items():
                if not isinstance(rule, dict) or 'role' not in rule:
                    continue
                expected = ('internal-interpreter-mediated' if rule['role'] == 'embedded-runtime-invocation'
                            else 'typescript-declaration-data' if rule['role'] == 'typescript-declaration-data'
                            else 'internal-retained-source')
                self.assertEqual(rule['intent'], expected, path)
                changed = copy.deepcopy(rule)
                changed['intent'] = 'internal-module-data'
                with self.assertRaises(ContractError):
                    callers.validate_rule(path, changed)

    def test_hypothetical_json_caller_contract_is_rejected_for_other_products(self):
        from rs9.errors import ContractError
        from rs9.rpm_lint_policy import _validate_policy
        policy = load_policy()
        rule = copy.deepcopy(policy['projects'][callers.NEBULAR_PROJECT_ID]['exceptions']['env-script-interpreter'][
            callers.PAYLOAD + '/loom-payload/bin/tfsl.js'])
        for key in ('role', 'caller_structure'):
            rule.pop(key)
        rule.update(intent='internal-interpreter-mediated', reference_contract={
            'kind': 'json-pointer', 'pointer': '/script', 'value': {'interpreter': 'node', 'script': 'private.js'},
            'role': 'invocation'})
        entry = policy['projects']['theme-forge-stellar-burst']
        entry['exceptions']['env-script-interpreter'] = {'/usr/lib/theme-forge-stellar-burst/private.js': rule}
        with self.assertRaises(ContractError):
            _validate_policy(policy)

    def test_actual_engine_bytes_drive_versioned_requires(self):
        import io
        import tarfile
        payload=json.loads(SOURCES.with_name('caller-payload-members.json').read_bytes())
        metadata=payload['loom:package/package.json']
        self.assertEqual(digest(metadata['content'].encode()),callers.FLOOR_SHA256)
        with tempfile.TemporaryDirectory() as tmp:
            archive=Path(tmp)/'candidate.tar.gz'
            with tarfile.open(archive,'w:gz') as output:
                data=metadata['content'].encode()
                row=tarfile.TarInfo(callers.FLOOR_MEMBER.removeprefix('/usr/lib/'));row.size=len(data)
                output.addfile(row,io.BytesIO(data))
            entry=load_policy()['projects'][callers.NEBULAR_PROJECT_ID]
            self.assertEqual(callers.release_runtime_floor(archive,entry),'>= 22')
            changed=copy.deepcopy(entry);changed['runtime_requires_contract']['sha256']='0'*64
            from rs9.errors import ContractError
            with self.assertRaises(ContractError):callers.release_runtime_floor(archive,changed)

    def test_tagged_blob_bytes_and_all_roles_are_authenticated(self):
        sources=json.loads(SOURCES.read_bytes())
        self.assertEqual(set(sources),set(callers.REVIEWED_CALLER_FILES))
        for path,row in sources.items():
            self.assertTrue(callers._source_valid(path,row),path)
        self.assertEqual(len(callers.NEBULAR_MEMBER_DEFINITIONS),8)
        self.assertEqual(sum(d['role']=='embedded-runtime-invocation' for d in callers.NEBULAR_MEMBER_DEFINITIONS.values()),4)

    def test_two_architectures_real_source_relations_need_no_system_node(self):
        from tests.test_rpm_lint_policy import run10_fixture_case
        for system in callers.RUNTIME_PINS:
            raw,inventory,inputs,_,_=run10_fixture_case(system)
            attach_caller_fixture(inventory,inputs)
            value=evaluate_policy(raw,inventory,inputs,load_policy())
            self.assertTrue(value['accepted'],value['blockers'])
            self.assertFalse(raw['clean'])
            self.assertEqual(len(value['duplicate_groups']),128)
            for proof in value['member_proofs']:
                if proof.get('role')!='typescript-declaration-data':
                    self.assertFalse(proof['system_node_required'])
                    self.assertFalse(proof['native_execution_claimed'])

    def test_forged_source_tag_runtime_manifest_and_mixed_rules_fail(self):
        from tests.test_rpm_lint_policy import run10_fixture_case
        raw,inventory,inputs,_,_=run10_fixture_case('x86_64-linux')
        attach_caller_fixture(inventory,inputs)
        variants=[]
        v=copy.deepcopy(inventory);v['caller_evidence']['tag_tree']='0'*40;variants.append(v)
        v=copy.deepcopy(inventory);v['caller_evidence']['tag_commit']='a'*40;variants.append(v)
        v=copy.deepcopy(inventory);v['caller_evidence']['tag_commit']=['x'];variants.append(v)
        v=copy.deepcopy(inventory);v['caller_evidence']['tag_commit']={'commit': callers.TAG_COMMIT};variants.append(v)
        v=copy.deepcopy(inventory);v['caller_evidence']['tag_tree']=['x'];variants.append(v)
        v=copy.deepcopy(inventory);v['caller_evidence']['tag_tree']={'tree': callers.TAG_TREE};variants.append(v)
        v=copy.deepcopy(inventory);v['caller_evidence']['files']['src-tauri/src/platform.rs']['content']+='\n';variants.append(v)
        v=copy.deepcopy(inventory);v['files'][callers.RUNTIME]['sha256']='0'*64;variants.append(v)
        v=copy.deepcopy(inventory);v['contract_members'][callers.MANIFEST]='{}';variants.append(v)
        v=copy.deepcopy(inventory);v['files'].pop(callers.RUNTIME);variants.append(v)
        v=copy.deepcopy(inventory);v['requires']=['nodejs'];variants.append(v)
        for v in variants:
            result=evaluate_policy(raw,v,inputs,load_policy())
            self.assertFalse(result['accepted'])
            if result['rule_blocker_causes']:
                self.assertEqual(result['rule_blocker_causes'][0]['cause'],'identity-mismatch')
        absent=copy.deepcopy(inventory);absent['caller_evidence']=None
        result=evaluate_policy(raw,absent,inputs,load_policy())
        self.assertEqual(result['rule_blocker_causes'][0]['cause'],'content-absent')
        policy=load_policy();rule=next(iter(policy['projects'][callers.NEBULAR_PROJECT_ID]['exceptions']['env-script-interpreter'].values()))
        rule['status']='blocked';rule['missing_predicate']='caller-content-or-identity-unproven'
        self.assertFalse(evaluate_policy(raw,inventory,inputs,policy)['accepted'])
        rule.pop('status');rule.pop('missing_predicate')
        rule['caller_structure']['floor']='>=22'
        self.assertFalse(evaluate_policy(raw,inventory,inputs,policy)['accepted'])

    def test_current_tag_is_accepted_only_with_the_equal_reviewed_tree(self):
        from tests.test_rpm_lint_policy import run10_fixture_case
        raw, inventory, inputs, _, _ = run10_fixture_case('x86_64-linux')
        attach_caller_fixture(inventory, inputs)
        inventory['caller_evidence']['tag_commit'] = callers.CURRENT_TAG_COMMIT
        inventory['caller_evidence']['tag_tree'] = callers.CURRENT_TAG_TREE
        result = evaluate_policy(raw, inventory, inputs, load_policy())
        self.assertTrue(result['accepted'], result['blockers'])
        self.assertTrue(all(proof['tag_commit'] == callers.CURRENT_TAG_COMMIT
                            for proof in result['member_proofs']
                            if proof.get('role') != 'typescript-declaration-data'))

    def test_collector_authenticates_bytes_not_claimed_hashes_and_names_missing_items(self):
        sources=json.loads(SOURCES.read_bytes())
        class Capture:
            record={'tag':{'commit':callers.CURRENT_TAG_COMMIT,'tree':callers.CURRENT_TAG_TREE}}
        with tempfile.TemporaryDirectory() as tmp:
            output=Path(tmp)
            records=[]
            for path,row in sources.items():
                target=output/path;target.parent.mkdir(parents=True,exist_ok=True);target.write_text(row['content'])
                records.append({**{k:v for k,v in row.items() if k!='content'},
                                'tag_commit': callers.CURRENT_TAG_COMMIT})
            with patch('rs9.hosted_smoke.tagged_files',return_value=records):
                self.assertEqual(callers.collect_caller_sources(Capture(),object(),output)['status'],'available')
                (output/'src-tauri/src/platform.rs').write_text('forged')
                result=callers.collect_caller_sources(Capture(),object(),output)
                self.assertEqual(result['reason'],'CALLER_SOURCE_IDENTITY')
                self.assertIn('src-tauri/src/platform.rs',result['missing_items'])
            absent=callers.collect_caller_sources(Capture(),None,output)
            self.assertEqual(absent['status'],'unavailable')
            self.assertEqual(set(absent['missing_items']),set(callers.REVIEWED_CALLER_FILES))

    def test_current_and_historical_tagged_sources_have_authenticated_identity(self):
        sources = json.loads(SOURCES.read_bytes())
        for commit, tree in callers.REVIEWED_TAG_IDENTITIES.items():
            with self.subTest(commit=commit), tempfile.TemporaryDirectory() as tmp:
                output = Path(tmp)
                records = []
                for path, row in sources.items():
                    target = output / path
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text(row['content'])
                    records.append({**{k: v for k, v in row.items() if k != 'content'}, 'tag_commit': commit})

                class Capture:
                    record = {'tag': {'commit': commit, 'tree': tree}}

                with patch('rs9.hosted_smoke.tagged_files', return_value=records):
                    result = callers.collect_caller_sources(Capture(), object(), output)
                self.assertEqual(result['status'], 'available')
                self.assertEqual((result['tag_commit'], result['tag_tree']), (commit, tree))

    def test_unknown_or_wrong_tree_caller_capture_is_rejected_before_collection(self):
        for commit, tree in (('a' * 40, callers.CURRENT_TAG_TREE),
                             (callers.CURRENT_TAG_COMMIT, '0' * 40)):
            with self.subTest(commit=commit), tempfile.TemporaryDirectory() as tmp:
                class Capture:
                    record = {'tag': {'commit': commit, 'tree': tree}}

                with patch('rs9.hosted_smoke.tagged_files') as collector:
                    result = callers.collect_caller_sources(Capture(), object(), Path(tmp))
                self.assertEqual(result['status'], 'unavailable')
                self.assertEqual(result['reason'], 'CALLER_SOURCE_IDENTITY')
                collector.assert_not_called()


# Exact published Loom 0.5.0 metadata; no native fixture bytes are retained.
CURRENT_FLOOR_TEXT = '{\n  "name": "@knowledge-forge-ai/theme-forge-stellar-loom",\n  "version": "0.5.0",\n  "description": "Starlight theme-builder backend, library, and CLI",\n  "private": false,\n  "publishConfig": {\n    "access": "public",\n    "registry": "https://registry.npmjs.org/"\n  },\n  "repository": {\n    "type": "git",\n    "url": "git+https://github.com/Knowledge-Forge-AI/theme-forge-stellar-loom.git"\n  },\n  "homepage": "https://github.com/Knowledge-Forge-AI/theme-forge-stellar-loom#readme",\n  "bugs": {\n    "url": "https://github.com/Knowledge-Forge-AI/theme-forge-stellar-loom/issues"\n  },\n  "type": "module",\n  "license": "AGPL-3.0-or-later",\n  "engines": {\n    "node": ">=22"\n  },\n  "exports": {\n    ".": {\n      "types": "./dist/index-catalog.d.ts",\n      "import": "./dist/index-catalog.js"\n    },\n    "./batch": {\n      "types": "./dist/batch-catalog.d.ts",\n      "import": "./dist/batch-catalog.js"\n    },\n    "./cli": {\n      "types": "./dist/cli-catalog.d.ts",\n      "import": "./dist/cli-catalog.js"\n    },\n    "./protocol/*": "./protocol/*"\n  },\n  "bin": {\n    "tfsl": "./bin/tfsl.js",\n    "tfsl-batch": "./bin/tfsl-batch.js"\n  },\n  "files": [\n    "dist",\n    "bin",\n    "examples",\n    "protocol",\n    "LICENSE",\n    "NOTICE",\n    "COMMERCIAL-LICENSE.md",\n    "README.md"\n  ],\n  "scripts": {\n    "build": "tsc -p tsconfig.build.json",\n    "typecheck": "tsc -p tsconfig.json",\n    "test": "vitest run",\n    "test:smoke": "node tools/smoke-packed-consumer.mjs",\n    "test:smoke-plugin": "node tools/smoke-generated-plugin.mjs",\n    "test:smoke-reading": "node tools/smoke-reading-consumer.mjs",\n    "test:smoke-code": "node tools/smoke-code.mjs"\n  },\n  "devDependencies": {\n    "@playwright/test": "1.62.1",\n    "@types/node": "22.20.1",\n    "playwright": "1.62.1",\n    "typescript": "7.0.2",\n    "vitest": "4.1.12"\n  }\n}\n'


def current_caller_fixture(root, system="x86_64-linux", *, tag="v0.7.0",
                           tag_commit=callers.CURRENT070_COMMIT, tag_tree=callers.CURRENT070_TREE):
    """Real core authentication with explicit synthetic release/source inputs.

    Production contract loading is tested separately. This fixture changes only
    source/asset pins and adapter member joins to its controlled bytes. Runtime,
    sidecar manifest and floor pins use the reviewed contract. Real-pin coverage
    is separate from these synthetic unit fixtures.
    """
    import hashlib
    from rs9.release_core import authenticate_release
    from rs9.profiles import selection_for_intent
    from tests.release_fixtures import package_evidence
    capture_root = root / "capture"
    capture_root.mkdir()
    intent = package_evidence(capture_root)
    contract = copy.deepcopy(callers._load_current_contract())
    sources = {}
    for path in contract["source_files"]:
        literals = []
        for definition in contract["member_definitions"].values():
            literals.extend(definition["literals"].get(path, []))
        sources[path] = ("\n".join(dict.fromkeys(literals)) + "\n").encode()
    sources["protocol/theme-lab-v2/payload-binding.json"] = canonical({"files": [
        {"path": path.removeprefix(callers.PAYLOAD + "/loom-payload/"),
         "sha256": pin["sha256"], "bytes": pin["size"]}
        for path, pin in contract["platforms"][system]["members"].items() if "/loom-payload/" in path]})
    for path, data in sources.items():
        contract["source_files"][path] = {"blob": hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest(),
            "sha256": digest(data), "size": len(data)}
    # Synthetic adapter bytes must preserve the same source/member relationship
    # as the real contract. Actual public pins are checked separately.
    for platform in contract["platforms"].values():
        for member, source in ((callers.PAYLOAD + "/loom-adapter/theme-adapter.mjs", "src-tauri/loom-adapter/theme-adapter.mjs"),
                               (callers.PAYLOAD + "/solar-sail-adapter/solar-sail-adapter.mjs", "src-tauri/solar-sail-adapter/solar-sail-adapter.mjs")):
            platform["members"][member].update(sha256=contract["source_files"][source]["sha256"],
                                              size=contract["source_files"][source]["size"])
    intent["project"]["repository"] = "Knowledge-Forge-AI/theme-forge-nebular-fusion"
    intent["tag"] = tag
    api = capture_root / "api"
    (api / "repository.json").write_bytes(canonical({"id": 1358643872, "full_name": intent["project"]["repository"]}))
    (api / "ref.json").write_bytes(canonical({"ref": "refs/tags/" + tag, "object": {"type": "commit", "sha": tag_commit}}))
    (api / "commit.json").write_bytes(canonical({"sha": tag_commit, "tree": {"sha": tag_tree}}))
    tree = json.loads((api / "tree.json").read_bytes())
    tree["sha"] = tag_tree
    tree["tree"].extend({"path": path, "sha": row["blob"], "type": "blob", "mode": "100644"}
                         for path, row in contract["source_files"].items())
    (api / "tree.json").write_bytes(canonical(tree))
    release = json.loads((api / "release.json").read_bytes())
    release.update(id=426333162, tag_name=tag, target_commitish=tag_commit)
    (api / "release.json").write_bytes(canonical(release))
    capture = authenticate_release(selection_for_intent(intent), capture_root)
    asset = next(row for row in capture.record["assets"] if row["role"] == "payload")
    for platform in contract["platforms"].values():
        platform["asset"] = {**platform["asset"], **asset}
    class SourceClient:
        def get(self, url, **kwargs):
            prefix = "https://raw.githubusercontent.com/" + intent["project"]["repository"] + "/" + tag_commit + "/"
            if not url.startswith(prefix):
                raise AssertionError("Unexpected source URL")
            return sources[url.removeprefix(prefix)]
    platform = contract["platforms"][system]
    files = {}
    def add(path, pin):
        files[path] = dict(pin, path=path, type="file")
    for row in platform["manifest"]["content"]["files"]:
        add(callers.PAYLOAD + "/sidecar-payload/" + row["path"], row)
    for path, pin in platform["members"].items():
        add(path, pin)
    add(callers.RUNTIME, platform["runtime"])
    add(callers.ROOT + "/bin/" + callers.NEBULAR_PROJECT_ID, platform["application"])
    manifest_text = json.dumps(platform["manifest"]["content"], sort_keys=True, separators=(",", ":")) + "\n"
    add(callers.MANIFEST, {"sha256": digest(manifest_text.encode()), "size": len(manifest_text.encode()), "mode": 0o644})
    add(callers.FLOOR_MEMBER, {"sha256": digest(CURRENT_FLOOR_TEXT.encode()), "size": len(CURRENT_FLOOR_TEXT.encode()), "mode": 0o644})
    inventory = {"asset_sha256": asset["sha256"], "files": files,
        "expected": {path: dict(row, origin="release", input_archive_sha256=asset["sha256"],
                               input_member=path.removeprefix("/usr/lib/")) for path, row in files.items()},
        "contract_members": {callers.MANIFEST: manifest_text, callers.FLOOR_MEMBER: CURRENT_FLOOR_TEXT},
        "requires": ["nodejs >= 22"]}
    inputs = {"system": system, "arch": system.removesuffix("-linux"), "version": "0.7.0",
              "project_id": callers.NEBULAR_PROJECT_ID, "asset_sha256": asset["sha256"]}
    return capture, contract, SourceClient(), inventory, inputs


class CurrentNebularCallerTests(unittest.TestCase):
    def fixture(self, system="x86_64-linux"):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        capture, contract, client, inventory, inputs = current_caller_fixture(root, system)
        patcher = patch.object(callers, "_load_current_contract", return_value=contract)
        patcher.start()
        self.addCleanup(patcher.stop)
        evidence = callers.collect_caller_sources(capture, client, root / "source")
        self.assertEqual(evidence["status"], "available", evidence.get("reason"))
        inventory["caller_evidence"] = evidence
        return capture, contract, inventory, inputs

    def proof(self, contract, inventory, inputs, path=None):
        path = path or callers.PAYLOAD + "/loom-payload/bin/tfsl.js"
        definition = contract["member_definitions"][path]
        rule = {"role": definition["role"], "intent": callers.ROLE_INTENTS[definition["role"]],
                "caller_structure": definition["proof"]}
        pin = {"sha256": contract["platforms"][inputs["system"]]["members"][path]["sha256"],
               "asset_sha256": inputs["asset_sha256"], "input_member": path.removeprefix("/usr/lib/")}
        return callers.verify_nebular_caller(path, rule, pin, inventory, inputs)

    def test_current_contract_is_exact_and_historical_constants_stay_historical(self):
        from rs9.errors import ContractError
        contract = callers._load_current_contract()
        self.assertEqual(contract["identity"]["commit"], "cadb40c4972f68f314096ff60fbcfb4da950c161")
        self.assertEqual(contract["identity"]["tree"], "27c643b6375c2aafde314799c4f08e844c14992c")
        self.assertEqual(contract["floor"]["sha256"], "168b43aba5a8966b0caee78d441f4bb63787889bb2895120e44f505194b3236c")
        self.assertEqual(digest(CURRENT_FLOOR_TEXT.encode()), contract["floor"]["sha256"])
        self.assertEqual(callers.TAG_NAME, "v0.6.1")
        self.assertEqual(callers.FLOOR_SHA256, "aa3da0ab662e4205a357224e8deda8cabdec9ca6e504853cee1a8aaa989c48ad")
        self.assertIsNone(callers._reviewed_tag_identity({"commit": callers.CURRENT070_COMMIT, "tree": callers.CURRENT070_TREE}))
        class JsonCapture:
            record = {"tag": {"commit": callers.CURRENT070_COMMIT, "tree": callers.CURRENT070_TREE}}
        with self.assertRaises(ContractError):
            callers.current_contract_for_capture(JsonCapture())

    def test_current_contract_tampering_refused(self):
        from rs9.errors import ContractError
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "contract.json"
            path.write_bytes(callers.CURRENT070_CONTRACT_PATH.read_bytes() + b" ")
            with patch.object(callers, "CURRENT070_CONTRACT_PATH", path), self.assertRaises(ContractError):
                callers._load_current_contract()

    def test_exact_current_collection_and_both_platform_roles(self):
        for system in ("x86_64-linux", "aarch64-linux"):
            capture, contract, inventory, inputs = self.fixture(system)
            self.assertEqual(callers.current_contract_for_capture(capture), contract)
            for path in contract["member_definitions"]:
                proof, reason = self.proof(contract, inventory, inputs, path)
                self.assertIsNone(reason, (system, path, reason))
                self.assertEqual(proof["tag_commit"], callers.CURRENT070_COMMIT)
                self.assertFalse(proof["native_execution_claimed"])
                self.assertFalse(proof["system_node_required"])

    def test_current_json_roundtrip_and_mutated_copy_are_not_capabilities(self):
        _, contract, inventory, inputs = self.fixture()
        plain = copy.deepcopy(inventory)
        plain["caller_evidence"] = json.loads(canonical(inventory["caller_evidence"]))
        self.assertIsNone(self.proof(contract, plain, inputs)[0])
        mutation = copy.deepcopy(inventory)
        mutation["caller_evidence"]["files"]["src-tauri/src/platform.rs"]["content"] += "forged"
        copied_mutation = copy.deepcopy(mutation)
        self.assertIsNone(self.proof(contract, copied_mutation, inputs)[0])
        omitted = copy.deepcopy(inventory)
        omitted["caller_evidence"]["files"].pop("src-tauri/src/platform.rs")
        self.assertIsNone(self.proof(contract, omitted, inputs)[0])

    def test_capture_mutation_then_deepcopy_preserves_original_binding(self):
        capture, contract, inventory, inputs = self.fixture()
        original = inventory["caller_evidence"]
        capture.record["unreviewed_nonidentity_field"] = "changed"
        copied = copy.deepcopy(inventory)
        evidence = copied["caller_evidence"]
        self.assertIs(evidence._capture, original._capture)
        self.assertIs(evidence._proof, original._proof)
        self.assertIs(evidence._capture_hash, original._capture_hash)
        self.assertIs(evidence._seal, original._seal)
        self.assertIsNone(self.proof(contract, copied, inputs)[0])

    def test_historical_evidence_cannot_authorize_current_shaped_inputs(self):
        from tests.test_rpm_lint_policy import run10_fixture_case
        _, inventory, inputs, _, _ = run10_fixture_case("x86_64-linux")
        attach_caller_fixture(inventory, inputs)
        path = callers.PAYLOAD + "/solar-sail-adapter/solar-sail-adapter.mjs"
        entry = load_policy()["projects"][callers.NEBULAR_PROJECT_ID]
        rule = next(rules[path] for rules in entry["exceptions"].values() if path in rules)
        pin = rule["systems"][inputs["system"]]
        with patch.object(callers, "_load_current_contract", side_effect=OSError("not a historical dependency")):
            self.assertIsNotNone(callers.verify_nebular_caller(path, rule, pin, inventory, inputs)[0])
            self.assertIsNone(callers.verify_nebular_caller(path, rule, pin, inventory, {**inputs, "version": "0.7.0"})[0])
            for sha in callers.CURRENT070_ASSET_SHA256S:
                for position in ("inputs", "inventory", "pin"):
                    changed_inputs, changed_inventory, changed_pin = dict(inputs), copy.deepcopy(inventory), dict(pin)
                    {"inputs": changed_inputs, "inventory": changed_inventory, "pin": changed_pin}[position]["asset_sha256"] = sha
                    self.assertIsNone(callers.verify_nebular_caller(path, rule, changed_pin, changed_inventory, changed_inputs)[0])

    def test_current_adapter_member_must_equal_authenticated_source(self):
        _, contract, inventory, inputs = self.fixture()
        path = callers.PAYLOAD + "/solar-sail-adapter/solar-sail-adapter.mjs"
        contract["platforms"][inputs["system"]]["members"][path]["sha256"] = "0" * 64
        for bucket in ("files", "expected"):
            inventory[bucket][path]["sha256"] = "0" * 64
        self.assertIsNone(self.proof(contract, inventory, inputs, path)[0])

    def test_mixed_current_release_and_historical_tag_never_falls_back(self):
        class MixedCapture:
            record = {"tag": {"commit": callers.TAG_COMMIT, "tree": callers.TAG_TREE},
                      "release": {"tag": "v0.7.0"}}
        with tempfile.TemporaryDirectory() as temporary, patch("rs9.hosted_smoke.tagged_files") as collector:
            result = callers.collect_caller_sources(MixedCapture(), object(), Path(temporary))
            self.assertEqual(result["status"], "unavailable")
            collector.assert_not_called()

    def test_current_capture_cannot_mix_release_asset_inventory(self):
        from rs9.errors import ContractError
        capture, _, _, _ = self.fixture()
        # The controlled core fixture is authenticated, but its synthetic archive
        # must fail against the real reviewed public asset coordinates.
        actual = json.loads(callers.CURRENT070_CONTRACT_PATH.read_bytes())
        with patch.object(callers, "_load_current_contract", return_value=actual), self.assertRaises(ContractError):
            callers.current_contract_for_capture(capture)

    def test_wrong_tag_commit_tree_and_unauthenticated_mutation_refused(self):
        from rs9.errors import ContractError
        capture, contract, inventory, inputs = self.fixture()
        for section, field, value in (("release", "tag", "v0.6.1"), ("tag", "commit", "a" * 40),
                                      ("tag", "tree", "b" * 40), ("release", "id", 1)):
            previous = capture.record[section][field]
            capture.record[section][field] = value
            with self.assertRaises(ContractError):
                callers.current_contract_for_capture(capture)
            self.assertIsNone(self.proof(contract, inventory, inputs)[0])
            capture.record[section][field] = previous
        for field, value in (("tag_name", "v0.6.1"), ("tag_commit", "a" * 40), ("tag_tree", "b" * 40)):
            changed = copy.deepcopy(inventory)
            changed["caller_evidence"][field] = value
            self.assertIsNone(self.proof(contract, changed, inputs)[0])

    def test_authenticated_wrong_tag_commit_and_tree_are_not_current(self):
        from rs9.errors import ContractError
        from rs9.release_core import authenticated_record_hash
        for variation in ({"tag": "v0.6.1"}, {"tag_commit": "a" * 40}, {"tag_tree": "b" * 40}):
            with self.subTest(variation=variation), tempfile.TemporaryDirectory() as temporary:
                capture, contract, _, _, _ = current_caller_fixture(Path(temporary), **variation)
                self.assertTrue(authenticated_record_hash(capture))
                with patch.object(callers, "_load_current_contract", return_value=contract), self.assertRaises(ContractError) as caught:
                    callers.current_contract_for_capture(capture)
                self.assertEqual(caught.exception.code, "CALLER_SOURCE_IDENTITY")

    def test_wrong_floor_runtime_members_and_mixed_asset_refused(self):
        _, contract, inventory, inputs = self.fixture()
        variants = []
        for path, field, value in ((callers.RUNTIME, "sha256", "0" * 64), (callers.RUNTIME, "size", 1),
                                   (callers.RUNTIME, "mode", 0o644), (callers.FLOOR_MEMBER, "sha256", callers.FLOOR_SHA256),
                                   (callers.PAYLOAD + "/loom-payload/bin/tfsl.js", "sha256", "0" * 64)):
            changed = copy.deepcopy(inventory)
            changed["files"][path][field] = value
            variants.append(changed)
        changed = copy.deepcopy(inventory)
        changed["contract_members"][callers.MANIFEST] = "{}"
        variants.append(changed)
        changed = copy.deepcopy(inventory)
        changed["asset_sha256"] = "0" * 64
        variants.append(changed)
        changed = copy.deepcopy(inventory)
        changed["contract_members"][callers.FLOOR_MEMBER] += " "
        variants.append(changed)
        for changed in variants:
            self.assertIsNone(self.proof(contract, changed, inputs)[0])
        for key, value in (("version", "0.6.1"), ("asset_sha256", "0" * 64), ("arch", "aarch64")):
            self.assertIsNone(self.proof(contract, inventory, {**inputs, key: value})[0])

    def test_historical_source_bytes_cannot_satisfy_current_pins(self):
        contract = callers._load_current_contract()
        sources = json.loads(SOURCES.read_bytes())
        changed = [path for path in sources if not callers._source_valid(path, sources[path], pins=contract["source_files"])]
        self.assertEqual(len(changed), 13)

    def test_current_floor_needs_capture_and_current_policy_contract(self):
        from rs9.errors import ContractError
        import io
        import tarfile
        capture, contract, _, _ = self.fixture()
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "floor.tar.gz"
            with tarfile.open(archive, "w:gz") as output:
                data = CURRENT_FLOOR_TEXT.encode()
                row = tarfile.TarInfo(callers.FLOOR_MEMBER.removeprefix("/usr/lib/"))
                row.size = len(data)
                output.addfile(row, io.BytesIO(data))
            entry = {"runtime_requires_contract": {"member": callers.FLOOR_MEMBER,
                "sha256": contract["floor"]["sha256"], "pointer": "/engines/node"}}
            with self.assertRaises(ContractError):
                callers.release_runtime_floor(archive, entry)
            with self.assertRaises(ContractError):
                callers.release_runtime_floor(archive, entry, capture=capture)
            with patch.object(callers, "current_contract_for_capture", side_effect=KeyError("github_asset_id")):
                with self.assertRaises(ContractError) as caught:
                    callers.release_runtime_floor(archive, entry, capture=capture)
                self.assertEqual(caught.exception.code, "DEPENDENCY_DERIVATION")
            selected = copy.deepcopy(contract)
            selected["platforms"]["x86_64-linux"]["asset"]["sha256"] = digest(archive.read_bytes())
            with patch.object(callers, "current_contract_for_capture", return_value=selected):
                real_open = tarfile.open
                def change_path_after_hash(**kwargs):
                    self.assertIsInstance(kwargs.get("fileobj"), io.BytesIO)
                    archive.write_bytes(b"replaced after hashing")
                    return real_open(**kwargs)
                with patch("tarfile.open", side_effect=change_path_after_hash):
                    self.assertEqual(callers.release_runtime_floor(archive, entry, capture=capture), ">= 22")
                entry["runtime_requires_contract"]["sha256"] = callers.FLOOR_SHA256
                with self.assertRaises(ContractError):
                    callers.release_runtime_floor(archive, entry, capture=capture)
