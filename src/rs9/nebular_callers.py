"""Tag-authenticated caller relations and fresh release preservation, without native execution claims."""
import hashlib
import json
from pathlib import Path

from rs9.errors import ContractError
from rs9.release_core import digest

TAG_COMMIT = "49e2c4919b6b4ec9bd4ed5d7e7ced90921e00f5e"
TAG_TREE = "203a80b33fc94c776c9c184f8cac4f1609cb0f2b"
TAG_NAME = "v0.6.1"
NEBULAR_PROJECT_ID = "theme-forge-nebular-fusion"
ROOT = "/usr/lib/" + NEBULAR_PROJECT_ID
PAYLOAD = ROOT + "/lib/" + NEBULAR_PROJECT_ID
RUNTIME = ROOT + "/bin/tfsb-studio-service"
MANIFEST = PAYLOAD + "/sidecar-payload/manifest.json"
FLOOR_MEMBER = PAYLOAD + "/loom-payload/package.json"
FLOOR_SHA256 = "aa3da0ab662e4205a357224e8deda8cabdec9ca6e504853cee1a8aaa989c48ad"
NEBULAR_REAL_ROLES = frozenset({"typescript-declaration-data", "embedded-runtime-invocation", "retained-sidecar-source", "retained-loom-source"})
ROLE_INTENTS = {
    "typescript-declaration-data": "typescript-declaration-data",
    "embedded-runtime-invocation": "internal-interpreter-mediated",
    "retained-sidecar-source": "internal-retained-source",
    "retained-loom-source": "internal-retained-source",
}
REVIEWED_TAGGED_FILES = {'authenticated-inputs/loom-binding.json': {'blob': '0de9cd248ff80d001f2d5a824b0b3c6e6d5f0c76',
                                            'sha256': '968969f5eae4fe821805cad1af8c85c2be694d7372accb04d5d0211ee99d7b3d',
                                            'size': 2496},
 'authenticated-inputs/manifest.json': {'blob': '00abc80ce6927f53dd07846a729d60df3cfe258d',
                                        'sha256': 'c266500e778320cc9e99349d8d13a99d92583eda3f823016b85d0238a47f6ebc',
                                        'size': 2992},
 'authenticated-inputs/stellar-binding.json': {'blob': '233c00ec675efc13938dded45390e0555d377752',
                                               'sha256': 'ee497158fee5190eb9b8e67cb9a536c6298a08574fbcb66eabd4c110794962ff',
                                               'size': 6631},
 'protocol/theme-lab-v2/payload-binding.json': {'blob': '68c538b462270b0681077c68233743e110a4d13f',
                                                'sha256': 'f7424a65b6e3cdf43feb2f15c8c4a1579bfcb6553ee67ebf4360741a55226018',
                                                'size': 55841},
 'src-tauri/Cargo.toml': {'blob': '39005325fb71fc9b535bcdee6e79537e688fb761',
                          'sha256': '92cdd31067282e3c2c9ef1bce89fd706b0f975750282a8552a5705a129bb0f4c',
                          'size': 1177},
 'src-tauri/build.rs': {'blob': '66392f6cfcf803f73701916023024789b19c238a',
                        'sha256': '91fa78fd6c097847733522a8b4fee42e0ee7d58c169cc0f6a6393398f5cb6419',
                        'size': 8992},
 'src-tauri/loom-adapter/theme-adapter.mjs': {'blob': '7fcc9eeeab6d962788659f9c751eb0ab854fa9c9',
                                              'sha256': '35b7a9c9b0ca863a11819759168150bd0f7d3900bb1cade7666d0414afc6ae2d',
                                              'size': 6453},
 'src-tauri/solar-sail-adapter/solar-sail-adapter.mjs': {'blob': 'c1f1469724f80031873e62b98c6fcaa107798b8d',
                                                         'sha256': '2085c3abd23821962a0d3f0e8b6d452a4e020c393bbf132e094aa153f3c8a12e',
                                                         'size': 10998},
 'src-tauri/src/app_theme/runner.rs': {'blob': '21cc8c084cbb25a3f7603e5ed61df6dd23505bc4',
                                       'sha256': '864c4689e0831ed4ea8e8cc675fdb75163536fc28e030e1f5a0e7177e0624f4f',
                                       'size': 19035},
 'src-tauri/src/lib.rs': {'blob': 'c95262e90d206778f5f58dea3a358732ee03e3fa',
                          'sha256': 'b8f7a51ff11606a65162545a20b5d12bbbf76f9a94c2c849ed2fea9992e13b57',
                          'size': 20378},
 'src-tauri/src/platform.rs': {'blob': '7e22505a105335837eb8e4c57f46355815e2396f',
                               'sha256': '9ae8772be82a57f3d15c1df40581ebb5bd9c0c52bfc1300d59c03b548b621809',
                               'size': 10419},
 'src-tauri/src/sidecar/artifact.rs': {'blob': '5f81805a823fe682d4df589fd598b2a0a5644625',
                                       'sha256': 'b30b2ac17f22577534d2700dddd2e674fed6d48c3c3334d35630d7a8d74b4050',
                                       'size': 53187},
 'src-tauri/src/sidecar/process.rs': {'blob': '594916c451722524be7b2c5c296e1283ea22bd3a',
                                      'sha256': '71cfc25d009fa21851510c771dc97f6fa6bb271cc18fdb076420f29e19d52277',
                                      'size': 13132},
 'src-tauri/src/sidecar/scene_artifact.rs': {'blob': '9d8c33948f9155ab764b81bf3a2a872f1b44344c',
                                             'sha256': '1d59f320ec3dfcaa50865af3d2df83efe8990c53834f0b8bb5a31c9e65306089',
                                             'size': 8107},
 'src-tauri/src/theme_lab/runner.rs': {'blob': '180f88e797f3755a3b157c37511d66e828f99320',
                                       'sha256': '63ecf0e3582638742e592a2bb3847582e081a7f50eaf4d22338db95fc576eb82',
                                       'size': 32460},
 'src-tauri/tauri.conf.json': {'blob': '9bfcaee943475b36d04bffa1a1d22bf92da4222c',
                               'sha256': '8421ddc3414c95258dc7a1d131121b141b0cf965805062f62429e7847ad1951d',
                               'size': 1530},
 'tools/node-runtime-authority.mjs': {'blob': '7a3e6afd79f472f81de5ce7b4509e78cb3649df8',
                                      'sha256': '5bef23e0fea39c9a08177a3c33d380b96a043a9c0045823b4d88d2986ddf55ec',
                                      'size': 34288},
 'tools/sidecar-common.mjs': {'blob': 'bb2d8bcbe9dbec8e3b7770f55484403ecc5419d8',
                              'sha256': '67d45471554906b989ea6d01bfae93dba88b247090307201da14f2db9f8db3c1',
                              'size': 67256},
 'tools/sidecar-verify.mjs': {'blob': 'a456da327097d26bec9a41fdfaf288af57f38657',
                              'sha256': 'fba7f292b3c01ed062f4727e0c22912bc269b6ca76fca8328fb5329c098aac77',
                              'size': 1906}}
REVIEWED_CALLER_FILES = tuple(REVIEWED_TAGGED_FILES)
NEBULAR_MEMBER_DEFINITIONS = {'/usr/lib/theme-forge-nebular-fusion/lib/theme-forge-nebular-fusion/loom-adapter/theme-adapter.mjs': {'literals': {'src-tauri/src/platform.rs': ['parent.join("tfsb-studio-service")',
                                                                                                                                                  'if '
                                                                                                                                                  'packaged '
                                                                                                                                                  '|| '
                                                                                                                                                  '!cfg!(debug_assertions) '
                                                                                                                                                  '{',
                                                                                                                                                  'packaged_runtime(executable)'],
                                                                                                                    'src-tauri/src/theme_lab/runner.rs': ['crate::platform::select_runtime(',
                                                                                                                                                          'resource_dir.join("loom-adapter").join("theme-adapter.mjs")',
                                                                                                                                                          'Command::new(&self.node_binary)',
                                                                                                                                                          '.arg(script_path)']},
                                                                                                       'proof': {'kind': 'embedded-runtime-invocation',
                                                                                                                 'manifest_member': '/usr/lib/theme-forge-nebular-fusion/lib/theme-forge-nebular-fusion/sidecar-payload/manifest.json',
                                                                                                                 'runtime_member': '/usr/lib/theme-forge-nebular-fusion/bin/tfsb-studio-service'},
                                                                                                       'requires_runtime': False,
                                                                                                       'role': 'embedded-runtime-invocation'},
 '/usr/lib/theme-forge-nebular-fusion/lib/theme-forge-nebular-fusion/loom-payload/bin/tfsl-batch.js': {'literals': {'src-tauri/src/platform.rs': ['parent.join("tfsb-studio-service")',
                                                                                                                                                  'if '
                                                                                                                                                  'packaged '
                                                                                                                                                  '|| '
                                                                                                                                                  '!cfg!(debug_assertions) '
                                                                                                                                                  '{',
                                                                                                                                                  'packaged_runtime(executable)'],
                                                                                                                    'src-tauri/src/theme_lab/runner.rs': ['crate::platform::select_runtime(',
                                                                                                                                                          'self.execute_process(request, '
                                                                                                                                                          '&self.batch_adapter)',
                                                                                                                                                          'Command::new(&self.node_binary)',
                                                                                                                                                          '.arg(script_path)']},
                                                                                                       'proof': {'kind': 'embedded-runtime-invocation',
                                                                                                                 'manifest_member': '/usr/lib/theme-forge-nebular-fusion/lib/theme-forge-nebular-fusion/sidecar-payload/manifest.json',
                                                                                                                 'runtime_member': '/usr/lib/theme-forge-nebular-fusion/bin/tfsb-studio-service'},
                                                                                                       'requires_runtime': False,
                                                                                                       'role': 'embedded-runtime-invocation'},
 '/usr/lib/theme-forge-nebular-fusion/lib/theme-forge-nebular-fusion/loom-payload/bin/tfsl.js': {'literals': {'protocol/theme-lab-v2/payload-binding.json': ['"path": '
                                                                                                                                                             '"bin/tfsl.js"']},
                                                                                                 'proof': {'kind': 'retained-loom-source',
                                                                                                           'manifest_member': '/usr/lib/theme-forge-nebular-fusion/lib/theme-forge-nebular-fusion/sidecar-payload/manifest.json',
                                                                                                           'runtime_member': '/usr/lib/theme-forge-nebular-fusion/bin/tfsb-studio-service'},
                                                                                                 'requires_runtime': False,
                                                                                                 'role': 'retained-loom-source'},
 '/usr/lib/theme-forge-nebular-fusion/lib/theme-forge-nebular-fusion/sidecar-payload/dist/cli.d.ts': {'literals': {},
                                                                                                      'proof': {'kind': 'typescript-declaration-data'},
                                                                                                      'requires_runtime': False,
                                                                                                      'role': 'typescript-declaration-data'},
 '/usr/lib/theme-forge-nebular-fusion/lib/theme-forge-nebular-fusion/sidecar-payload/dist/cli.js': {'literals': {'tools/sidecar-common.mjs': ['manifest.json']},
                                                                                                    'proof': {'kind': 'retained-sidecar-source',
                                                                                                              'manifest_member': '/usr/lib/theme-forge-nebular-fusion/lib/theme-forge-nebular-fusion/sidecar-payload/manifest.json',
                                                                                                              'runtime_member': '/usr/lib/theme-forge-nebular-fusion/bin/tfsb-studio-service'},
                                                                                                    'requires_runtime': False,
                                                                                                    'role': 'retained-sidecar-source'},
 '/usr/lib/theme-forge-nebular-fusion/lib/theme-forge-nebular-fusion/sidecar-payload/dist/service-protocol/server-cli.d.ts': {'literals': {},
                                                                                                                              'proof': {'kind': 'typescript-declaration-data'},
                                                                                                                              'requires_runtime': False,
                                                                                                                              'role': 'typescript-declaration-data'},
 '/usr/lib/theme-forge-nebular-fusion/lib/theme-forge-nebular-fusion/sidecar-payload/dist/service-protocol/server-cli.js': {'literals': {'src-tauri/src/sidecar/process.rs': ['verified.revalidate_for_spawn()?;',
                                                                                                                                                                              'verified.payload.join("dist/service-protocol/server-cli.js")',
                                                                                                                                                                              'Command::new(&verified.binary)',
                                                                                                                                                                              '.arg(&entrypoint)']},
                                                                                                                            'proof': {'kind': 'embedded-runtime-invocation',
                                                                                                                                      'manifest_member': '/usr/lib/theme-forge-nebular-fusion/lib/theme-forge-nebular-fusion/sidecar-payload/manifest.json',
                                                                                                                                      'runtime_member': '/usr/lib/theme-forge-nebular-fusion/bin/tfsb-studio-service'},
                                                                                                                            'requires_runtime': False,
                                                                                                                            'role': 'embedded-runtime-invocation'},
 '/usr/lib/theme-forge-nebular-fusion/lib/theme-forge-nebular-fusion/solar-sail-adapter/solar-sail-adapter.mjs': {'literals': {'src-tauri/src/app_theme/runner.rs': ['crate::platform::select_runtime(',
                                                                                                                                                                     'resource.join("solar-sail-adapter/solar-sail-adapter.mjs")',
                                                                                                                                                                     'Command::new(&self.node_binary)',
                                                                                                                                                                     '.arg(&self.adapter_path)'],
                                                                                                                               'src-tauri/src/platform.rs': ['parent.join("tfsb-studio-service")',
                                                                                                                                                             'if '
                                                                                                                                                             'packaged '
                                                                                                                                                             '|| '
                                                                                                                                                             '!cfg!(debug_assertions) '
                                                                                                                                                             '{',
                                                                                                                                                             'packaged_runtime(executable)']},
                                                                                                                  'proof': {'kind': 'embedded-runtime-invocation',
                                                                                                                            'manifest_member': '/usr/lib/theme-forge-nebular-fusion/lib/theme-forge-nebular-fusion/sidecar-payload/manifest.json',
                                                                                                                            'runtime_member': '/usr/lib/theme-forge-nebular-fusion/bin/tfsb-studio-service'},
                                                                                                                  'requires_runtime': False,
                                                                                                                  'role': 'embedded-runtime-invocation'}}
NEBULAR_MEMBER_ROLES = {p:d["role"] for p,d in NEBULAR_MEMBER_DEFINITIONS.items()}
RUNTIME_PINS = {
    "x86_64-linux": {"sha256": "fde6a4bf8d0562f7751d1a2d6cb9b417c4cfe107bbcb0aa3e9a24e125e348f48", "size": 124827920, "target": "x86_64-unknown-linux-gnu"},
    "aarch64-linux": {"sha256": "d09e299258c24f7cdf6f5d5ec185e3a56512b27a697113735dac909f1cac7b8d", "size": 122179336, "target": "aarch64-unknown-linux-gnu"},
}


def _source_valid(path, record):
    pin = REVIEWED_TAGGED_FILES[path]
    if not isinstance(record, dict) or not isinstance(record.get("content"), str):
        return False
    data = record["content"].encode()
    return (len(data) == pin["size"] and digest(data) == pin["sha256"]
            and hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest() == pin["blob"]
            and all(record.get(k) == pin[k] for k in ("blob", "sha256", "size")))


def collect_caller_sources(capture, client, scratch, entry=None):
    """Use the existing bounded tag collector independently of policy acceptance."""
    output = Path(scratch)
    output.mkdir(parents=True, exist_ok=True)
    missing = list(REVIEWED_CALLER_FILES)
    try:
        if client is None:
            raise ContractError("CALLER_CLIENT_UNAVAILABLE", "Authenticated source client unavailable")
        tag = capture.record["tag"]
        if tag.get("commit") != TAG_COMMIT or tag.get("tree") != TAG_TREE:
            raise ContractError("CALLER_SOURCE_IDENTITY", "Caller tag/tree differs from reviewed release")
        from rs9.hosted_smoke import tagged_files
        records = tagged_files(capture, client, output, (), paths=REVIEWED_CALLER_FILES, role="caller-source")
        files = {}
        for record in records:
            path = record["path"]
            if path not in REVIEWED_TAGGED_FILES:
                raise ContractError("CALLER_SOURCE_IDENTITY", "Unselected source returned")
            record = dict(record, content=(output / path).read_text(encoding="utf-8"))
            if not _source_valid(path, record):
                raise ContractError("CALLER_SOURCE_IDENTITY", "Caller bytes differ from authenticated tag")
            files[path] = record
            missing.remove(path)
        if missing:
            raise ContractError("CALLER_SOURCE_MISSING", "Selected source absent")
        return dict(schema="rs9.nebular-caller-sources.v1", status="available", tag_commit=TAG_COMMIT,
                    tag_tree=TAG_TREE, files=files, records=records)
    except (ContractError, OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        return dict(schema="rs9.nebular-caller-sources.v1", status="unavailable", reason=getattr(error, "code", "CALLER_SOURCE_UNAVAILABLE"),
                    missing_items=missing, collection_path="execute -> collect_caller_sources -> tagged_files", files={}, records=[])


def _preserved(path, inventory):
    expected, actual = inventory.get("expected", {}).get(path, {}), inventory.get("files", {}).get(path, {})
    return (expected.get("origin") == "release" and expected.get("type") == "file" and actual.get("type") == "file"
            and expected.get("input_archive_sha256") == inventory.get("asset_sha256")
            and all(actual.get(k) == expected.get(k) for k in ("sha256", "size", "mode")))


def _text(member, inventory):
    text = inventory.get("contract_members", {}).get(member)
    if (not isinstance(text, str) or len(text.encode()) > 256 * 1024 or not _preserved(member, inventory)
            or digest(text.encode()) != inventory["expected"][member]["sha256"]):
        return None
    return text


def validate_rule(path, rule):
    definition = NEBULAR_MEMBER_DEFINITIONS.get(path)
    if (not definition or rule.get("role") != definition["role"]
            or rule.get("intent") != ROLE_INTENTS[definition["role"]]
            or rule.get("caller_structure") != definition["proof"]
            or any(k in rule for k in ("reference_contract", "caller_member", "floor_source"))):
        raise ContractError("INVALID_POLICY", "Mixed or unauthenticated Nebular caller discriminator")


def release_runtime_floor(archive, entry):
    """Read only the product-declared, hash-bound engine member."""
    import re
    import tarfile
    contract = entry.get("runtime_requires_contract", {})
    if (contract.get("member") != FLOOR_MEMBER or contract.get("sha256") != FLOOR_SHA256
            or contract.get("pointer") != "/engines/node"):
        raise ContractError("DEPENDENCY_DERIVATION", "Exact runtime Requires source contract missing")
    name = FLOOR_MEMBER.removeprefix("/usr/lib/")
    with tarfile.open(archive, "r:*") as archive_file:
        members = [m for m in archive_file.getmembers() if m.name == name]
        if len(members) != 1 or not members[0].isfile() or members[0].size > 256 * 1024:
            raise ContractError("DEPENDENCY_DERIVATION", "Bounded runtime engine member missing")
        with archive_file.extractfile(members[0]) as stream:
            data = stream.read(256 * 1024 + 1)
    if digest(data) != FLOOR_SHA256:
        raise ContractError("DEPENDENCY_DERIVATION", "Runtime engine source changed")
    floor = json.loads(data).get("engines", {}).get("node")
    if not isinstance(floor, str) or not re.fullmatch(r">=\s*([0-9]{1,6}(?:\.[0-9]{1,6}){0,2})", floor):
        raise ContractError("DEPENDENCY_DERIVATION", "Unsupported runtime engine floor")
    return ">= " + floor.removeprefix(">=").strip()


def verify_nebular_caller(path, rule, pin, inventory, inputs, *, caller_evidence=None, client_runtime=None):
    """Verify a source relationship and byte preservation; no system Node inference."""
    try:
        validate_rule(path, rule)
    except ContractError:
        return None, "caller-content-or-identity-unproven"
    definition = NEBULAR_MEMBER_DEFINITIONS[path]
    if rule.get("status") == "blocked":
        return None, rule.get("missing_predicate", "caller-content-or-identity-unproven")
    if not _preserved(path, inventory):
        return None, "script-preservation-unproven"
    evidence = caller_evidence if caller_evidence is not None else inventory.get("caller_evidence")
    if (not isinstance(evidence, dict) or evidence.get("schema") != "rs9.nebular-caller-sources.v1"
            or evidence.get("status") != "available" or evidence.get("tag_commit") != TAG_COMMIT or evidence.get("tag_tree") != TAG_TREE):
        return None, "caller-content-or-identity-unproven"
    sources = evidence.get("files", {})
    if set(sources) != set(REVIEWED_CALLER_FILES) or not all(_source_valid(p, sources[p]) for p in REVIEWED_CALLER_FILES):
        return None, "caller-content-or-identity-unproven"
    for source, literals in definition["literals"].items():
        if any(literal not in sources[source]["content"] for literal in literals):
            return None, "caller-content-or-identity-unproven"
    runtime = RUNTIME_PINS.get(inputs.get("system"))
    if (not runtime or inputs.get("arch") != inputs["system"].removesuffix("-linux")
            or not _preserved(RUNTIME, inventory) or not _preserved(ROOT + "/bin/" + NEBULAR_PROJECT_ID, inventory)):
        return None, "caller-member-missing"
    installed = inventory["files"][RUNTIME]
    if any(installed.get(k) != runtime[k] for k in ("sha256", "size")) or installed.get("mode") != 0o755:
        return None, "caller-content-or-identity-unproven"
    manifest_text = _text(MANIFEST, inventory)
    if manifest_text is None:
        return None, "caller-content-or-identity-unproven"
    try:
        manifest = json.loads(manifest_text)
        if (manifest.get("schema") != "tfsb.studio-sidecar-distribution" or manifest.get("runtimeKind") != "node-runtime-payload-v1"
                or manifest.get("target") != runtime["target"] or manifest.get("entrypoint") != "dist/service-protocol/server-cli.js"
                or any(manifest.get("runtime", {}).get(k) != runtime[k] for k in ("sha256", "size"))
                or manifest["runtime"].get("mode") != installed["mode"]
                or manifest["runtime"].get("version") != "22.23.3"):
            return None, "caller-content-or-identity-unproven"
        members = manifest["files"]
        if not isinstance(members, list) or not members or len(members) > 100000:
            return None, "caller-content-or-identity-unproven"
        names = [row["path"] for row in members]
        released_names = {p.removeprefix(PAYLOAD + "/sidecar-payload/") for p, row in inventory["expected"].items()
                          if p.startswith(PAYLOAD + "/sidecar-payload/") and row.get("type") == "file" and p != MANIFEST}
        if len(names) != len(set(names)) or set(names) != released_names:
            return None, "caller-content-or-identity-unproven"
        for row in members:
            member = PAYLOAD + "/sidecar-payload/" + row["path"]
            if not _preserved(member, inventory) or any(inventory["files"][member].get(k) != row.get(k) for k in ("sha256", "size", "mode")):
                return None, "caller-content-or-identity-unproven"
        if "/loom-payload/" in path:
            floor_text = _text(FLOOR_MEMBER, inventory)
            if floor_text is None or digest(floor_text.encode()) != FLOOR_SHA256:
                return None, "engine-floor-unproven"
            import re
            engine = json.loads(floor_text).get("engines", {}).get("node")
            if not isinstance(engine, str) or not re.fullmatch(r">=\s*[0-9]{1,6}(?:\.[0-9]{1,6}){0,2}", engine):
                return None, "engine-floor-unmet"
            if "nodejs >= " + engine.removeprefix(">=").strip() not in inventory.get("requires", []):
                return None, "engine-floor-unmet"
            binding = json.loads(sources["protocol/theme-lab-v2/payload-binding.json"]["content"])
            selected = [r for r in binding["files"] if r["path"] == path.removeprefix(PAYLOAD + "/loom-payload/")]
            if len(selected) != 1 or selected[0]["sha256"] != pin["sha256"] or selected[0]["bytes"] != inventory["files"][path]["size"]:
                return None, "caller-content-or-identity-unproven"
    except (ValueError, KeyError, TypeError, AttributeError):
        return None, "caller-content-or-identity-unproven"
    return dict(path=path, role=definition["role"], intent=rule["intent"], sha256=pin["sha256"], mode=inventory["files"][path]["mode"],
                input_member=pin["input_member"], input_archive_sha256=pin["asset_sha256"],
                proof_model="authenticated-source-relation-and-release-preservation", tag_commit=TAG_COMMIT, tag_tree=TAG_TREE,
                runtime_member=RUNTIME, runtime_sha256=runtime["sha256"], manifest_sha256=digest(manifest_text.encode()),
                native_execution_claimed=False, system_node_required=False), None
