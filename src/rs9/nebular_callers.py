"""Tag-authenticated caller relations and fresh release preservation, without native execution claims."""
import hashlib
import json
from pathlib import Path

from rs9.errors import ContractError
from rs9.nebular_lineage import (
    CURRENT_COMMIT,
    CURRENT_TREE,
    HISTORICAL_COMMIT,
    HISTORICAL_TREE,
)
from rs9.release_core import (digest, authenticated_record_hash, authenticated_tree,
                              authenticated_release_metadata)

TAG_COMMIT = HISTORICAL_COMMIT
TAG_TREE = HISTORICAL_TREE
CURRENT_TAG_COMMIT = CURRENT_COMMIT
CURRENT_TAG_TREE = CURRENT_TREE
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
# The retained caller rows are the exact historical-tree bytes. The current
# tag is admitted only because the reviewed lineage proves the trees equal.
REVIEWED_SOURCE_TREE = HISTORICAL_TREE
REVIEWED_TAG_IDENTITIES = {
    HISTORICAL_COMMIT: HISTORICAL_TREE,
    CURRENT_COMMIT: CURRENT_TREE,
}
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


CURRENT070_CONTRACT_PATH = Path(__file__).resolve().parents[2] / "operators/theme-forge-current-202610/nebular-callers.json"
CURRENT070_CONTRACT_SHA256 = "db10b939421dc56d4011dcb3a52a659f0c0e8f73e33439cd88173e3b85fe90a8"
CURRENT070_COMMIT = "cadb40c4972f68f314096ff60fbcfb4da950c161"
CURRENT070_TREE = "27c643b6375c2aafde314799c4f08e844c14992c"
CURRENT070_ASSET_SHA256S = frozenset({
    "eb15e92e2c6c893748612c3e1e3910acbc57e8e990a4d4d1c89f958e330ce17c",
    "4a4035797ac591854e362404d32e8acc38f79ccdccf7696b31f24060f0b55c27",
})
_CURRENT_CALLER_PROOF = object()


def _load_current_contract():
    path = CURRENT070_CONTRACT_PATH
    if path.is_symlink() or path.stat().st_size > 512 * 1024:
        raise ContractError("CALLER_SOURCE_IDENTITY", "Bounded current caller contract required")
    raw = path.read_bytes()
    if digest(raw) != CURRENT070_CONTRACT_SHA256:
        raise ContractError("CALLER_SOURCE_IDENTITY", "Current caller contract bytes differ")
    contract = json.loads(raw)
    if (set(contract) != {"schema", "identity", "source_files", "member_definitions", "floor", "platforms"}
            or contract["schema"] != "rs9.nebular-current-caller-contract.v1"):
        raise ContractError("CALLER_SOURCE_IDENTITY", "Closed current caller contract required")
    return contract


def current_contract_for_capture(capture):
    """Select the current contract only from a real, exact authenticated release.

    Returned JSON describes expectations. It is not a caller-proof capability.
    """
    authenticated_record_hash(capture)
    authenticated_tree(capture)
    release = authenticated_release_metadata(capture)
    record = capture.record
    identity = (record["repository"]["full_name"], record["repository"]["id"],
                record["release"]["id"], record["release"]["tag"],
                record["tag"]["commit"], record["tag"]["tree"])
    if (identity != ("Knowledge-Forge-AI/theme-forge-nebular-fusion", 1358643872,
                     426333162, "v0.7.0", CURRENT070_COMMIT, CURRENT070_TREE)
            or release.get("id") != 426333162 or release.get("tag_name") != "v0.7.0"):
        raise ContractError("CALLER_SOURCE_IDENTITY", "Exact current authenticated Nebular release required")
    contract = _load_current_contract()
    for platform in contract["platforms"].values():
        asset = platform["asset"]
        selected = [row for row in record["assets"] if row["name"] == asset["name"]]
        if (len(selected) != 1 or any(selected[0][key] != asset[key] for key in ("sha256", "size"))
                or selected[0]["github_asset_id"] != asset["github_asset_id"]):
            raise ContractError("CALLER_SOURCE_IDENTITY", "Current caller release asset differs")
    return contract


class _CurrentCallerEvidence(dict):
    """JSON-compatible audit data with an unpersistable current-capture binding."""
    def __init__(self, capture, value, *, _proof=None):
        if _proof is not _CURRENT_CALLER_PROOF:
            raise ContractError("CALLER_SOURCE_IDENTITY", "Fresh current source collection required")
        super().__init__(value)
        self._capture = capture
        self._capture_hash = authenticated_record_hash(capture)
        self._seal = digest(_canonical_evidence(self))
        self._proof = _proof

    def __deepcopy__(self, memo):
        import copy
        # Copying is not authentication; preserve both original binding seals.
        result = type(self).__new__(type(self))
        memo[id(self)] = result
        dict.update(result, copy.deepcopy(dict(self), memo))
        result._capture = self._capture
        result._capture_hash = self._capture_hash
        result._seal = self._seal
        result._proof = self._proof
        return result


def _canonical_evidence(value):
    from rs9.scratch import canonical
    return canonical(dict(value))


def _current_evidence_contract(evidence):
    if (not isinstance(evidence, _CurrentCallerEvidence) or evidence._proof is not _CURRENT_CALLER_PROOF
            or digest(_canonical_evidence(evidence)) != evidence._seal
            or authenticated_record_hash(evidence._capture) != evidence._capture_hash):
        raise ContractError("CALLER_SOURCE_IDENTITY", "Current caller evidence lost its live capture binding")
    contract = current_contract_for_capture(evidence._capture)
    if (evidence.get("tag_commit") != CURRENT070_COMMIT or evidence.get("tag_tree") != CURRENT070_TREE
            or evidence.get("tag_name") != "v0.7.0"):
        raise ContractError("CALLER_SOURCE_IDENTITY", "Current caller evidence identity differs")
    return contract


def _source_valid(path, record, *, pins=None):
    pin = (REVIEWED_TAGGED_FILES if pins is None else pins)[path]
    if not isinstance(record, dict) or not isinstance(record.get("content"), str):
        return False
    data = record["content"].encode()
    return (record.get("path") == path and len(data) == pin["size"] and digest(data) == pin["sha256"]
            and hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest() == pin["blob"]
            and all(record.get(k) == pin[k] for k in ("blob", "sha256", "size")))


def _reviewed_tag_identity(tag):
    if not isinstance(tag, dict):
        return None
    commit, tree = tag.get("commit"), tag.get("tree")
    if not isinstance(commit, str) or not isinstance(tree, str):
        return None
    if tree != REVIEWED_SOURCE_TREE or REVIEWED_TAG_IDENTITIES.get(commit) != tree:
        return None
    return commit, tree


def collect_caller_sources(capture, client, scratch, entry=None):
    """Use the existing bounded tag collector independently of policy acceptance."""
    output = Path(scratch)
    output.mkdir(parents=True, exist_ok=True)
    missing = list(REVIEWED_CALLER_FILES)
    current = False
    pins = REVIEWED_TAGGED_FILES
    try:
        if client is None:
            raise ContractError("CALLER_CLIENT_UNAVAILABLE", "Authenticated source client unavailable")
        tag = capture.record.get("tag") if isinstance(capture.record, dict) else None
        release = capture.record.get("release", {})
        current = ((isinstance(tag, dict) and (tag.get("commit") == CURRENT070_COMMIT
                    or tag.get("tree") == CURRENT070_TREE))
                   or isinstance(release, dict) and release.get("tag") == "v0.7.0")
        if current:
            contract = current_contract_for_capture(capture)
            pins = contract["source_files"]
            missing = list(pins)
            identity = (CURRENT070_COMMIT, CURRENT070_TREE)
        else:
            identity = _reviewed_tag_identity(tag)
        if identity is None:
            raise ContractError("CALLER_SOURCE_IDENTITY", "Caller tag/tree differs from reviewed release")
        tag_commit, tag_tree = identity
        from rs9.hosted_smoke import tagged_files
        records = tagged_files(capture, client, output, (), paths=tuple(pins), role="caller-source")
        files = {}
        for record in records:
            path = record["path"]
            if path not in pins:
                raise ContractError("CALLER_SOURCE_IDENTITY", "Unselected source returned")
            if record.get("tag_commit") != tag_commit:
                raise ContractError("CALLER_SOURCE_IDENTITY", "Caller source record is bound to another tag")
            record = dict(record, content=(output / path).read_text(encoding="utf-8"))
            if not _source_valid(path, record, pins=pins):
                raise ContractError("CALLER_SOURCE_IDENTITY", "Caller bytes differ from authenticated tag")
            files[path] = record
            missing.remove(path)
        if missing:
            raise ContractError("CALLER_SOURCE_MISSING", "Selected source absent")
        result = dict(schema="rs9.nebular-caller-sources.v1", status="available", tag_commit=tag_commit,
                      tag_tree=tag_tree, files=files, records=records)
        if current:
            result["tag_name"] = "v0.7.0"
            return _CurrentCallerEvidence(capture, result, _proof=_CURRENT_CALLER_PROOF)
        return result
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


def release_runtime_floor(archive, entry, *, capture=None):
    """Read only the product-declared, hash-bound engine member."""
    import re
    import tarfile
    import io
    floor_sha256 = FLOOR_SHA256
    archive_bytes = None
    if capture is not None:
        try:
            selected = current_contract_for_capture(capture)
            floor_sha256 = selected["floor"]["sha256"]
            archive_path = Path(archive)
            assets = [row["asset"] for row in selected["platforms"].values()]
            if (archive_path.is_symlink() or not archive_path.is_file()
                    or archive_path.stat().st_size > 256 * 1024 * 1024):
                raise ValueError("archive binding")
            archive_bytes = archive_path.read_bytes()
            archive_sha256 = digest(archive_bytes)
            if not any(archive_sha256 == asset["sha256"] for asset in assets):
                raise ValueError("archive binding")
        except (ContractError, OSError, ValueError, KeyError, TypeError, AttributeError):
            raise ContractError("DEPENDENCY_DERIVATION", "Current runtime floor needs an exact authenticated archive") from None
    contract = entry.get("runtime_requires_contract", {})
    if (contract.get("member") != FLOOR_MEMBER or contract.get("sha256") != floor_sha256
            or contract.get("pointer") != "/engines/node"):
        raise ContractError("DEPENDENCY_DERIVATION", "Exact runtime Requires source contract missing")
    name = FLOOR_MEMBER.removeprefix("/usr/lib/")
    archive_input = ({"fileobj": io.BytesIO(archive_bytes), "mode": "r:*"} if archive_bytes is not None
                     else {"name": archive, "mode": "r:*"})
    with tarfile.open(**archive_input) as archive_file:
        members = [m for m in archive_file.getmembers() if m.name == name]
        if len(members) != 1 or not members[0].isfile() or members[0].size > 256 * 1024:
            raise ContractError("DEPENDENCY_DERIVATION", "Bounded runtime engine member missing")
        with archive_file.extractfile(members[0]) as stream:
            data = stream.read(256 * 1024 + 1)
    if digest(data) != floor_sha256:
        raise ContractError("DEPENDENCY_DERIVATION", "Runtime engine source changed")
    floor = json.loads(data).get("engines", {}).get("node")
    if not isinstance(floor, str) or not re.fullmatch(r">=\s*([0-9]{1,6}(?:\.[0-9]{1,6}){0,2})", floor):
        raise ContractError("DEPENDENCY_DERIVATION", "Unsupported runtime engine floor")
    return ">= " + floor.removeprefix(">=").strip()


def verify_nebular_caller(path, rule, pin, inventory, inputs, *, caller_evidence=None, client_runtime=None):
    """Verify a source relationship and byte preservation; no system Node inference."""
    evidence = caller_evidence if caller_evidence is not None else inventory.get("caller_evidence")
    if (isinstance(evidence, _CurrentCallerEvidence)
            or isinstance(evidence, dict) and (evidence.get("tag_commit") == CURRENT070_COMMIT
                                               or evidence.get("tag_tree") == CURRENT070_TREE
                                               or evidence.get("tag_name") == "v0.7.0")):
        return _verify_current_caller(path, rule, pin, inventory, inputs, evidence)
    if (inputs.get("version") == "0.7.0"
            or any(isinstance(value, str) and value in CURRENT070_ASSET_SHA256S
                   for value in (inputs.get("asset_sha256"), inventory.get("asset_sha256"), pin.get("asset_sha256")))):
        return None, "caller-content-or-identity-unproven"
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
    evidence_identity = _reviewed_tag_identity({
        "commit": evidence.get("tag_commit") if isinstance(evidence, dict) else None,
        "tree": evidence.get("tag_tree") if isinstance(evidence, dict) else None,
    })
    if (not isinstance(evidence, dict) or evidence.get("schema") != "rs9.nebular-caller-sources.v1"
            or evidence.get("status") != "available" or evidence_identity is None):
        return None, "caller-content-or-identity-unproven"
    evidence_commit, evidence_tree = evidence_identity
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
                proof_model="authenticated-source-relation-and-release-preservation", tag_commit=evidence_commit, tag_tree=evidence_tree,
                runtime_member=RUNTIME, runtime_sha256=runtime["sha256"], manifest_sha256=digest(manifest_text.encode()),
                native_execution_claimed=False, system_node_required=False), None


def _verify_current_caller(path, rule, pin, inventory, inputs, evidence):
    """Current static caller proof requires the live authenticated source result."""
    failure = "caller-content-or-identity-unproven"
    try:
        contract = _current_evidence_contract(evidence)
        definition = contract["member_definitions"].get(path)
        if (not definition or rule.get("role") != definition["role"]
                or rule.get("intent") != ROLE_INTENTS[definition["role"]]
                or rule.get("caller_structure") != definition["proof"]
                or any(key in rule for key in ("reference_contract", "caller_member", "floor_source"))):
            return None, failure
        if rule.get("status") == "blocked":
            return None, rule.get("missing_predicate", failure)
        sources = evidence["files"]
        if (set(sources) != set(contract["source_files"])
                or not all(_source_valid(name, sources[name], pins=contract["source_files"])
                           for name in contract["source_files"])):
            return None, failure
        for source, literals in definition["literals"].items():
            if any(literal not in sources[source]["content"] for literal in literals):
                return None, failure
        system = inputs.get("system")
        platform = contract["platforms"].get(system)
        if (platform is None or inputs.get("arch") != system.removesuffix("-linux")
                or inputs.get("project_id") != NEBULAR_PROJECT_ID
                or inputs.get("version") != "0.7.0"):
            return None, failure
        asset = platform["asset"]
        if (inputs.get("asset_sha256") != asset["sha256"]
                or inventory.get("asset_sha256") != asset["sha256"]
                or pin.get("asset_sha256") != asset["sha256"]
                or pin.get("input_member") != path.removeprefix("/usr/lib/")):
            return None, failure
        member_pin = platform["members"][path]
        adapter_source = {
            PAYLOAD + "/loom-adapter/theme-adapter.mjs": "src-tauri/loom-adapter/theme-adapter.mjs",
            PAYLOAD + "/solar-sail-adapter/solar-sail-adapter.mjs": "src-tauri/solar-sail-adapter/solar-sail-adapter.mjs",
        }.get(path)
        if adapter_source and member_pin["sha256"] != contract["source_files"][adapter_source]["sha256"]:
            return None, failure
        if (not _preserved(path, inventory) or pin.get("sha256") != member_pin["sha256"]
                or any(inventory["files"][path].get(key) != member_pin[key] for key in ("sha256", "size", "mode"))):
            return None, "script-preservation-unproven"
        runtime = platform["runtime"]
        application_path = ROOT + "/bin/" + NEBULAR_PROJECT_ID
        for member, expected in ((RUNTIME, runtime), (application_path, platform["application"])):
            if not _preserved(member, inventory):
                return None, "caller-member-missing"
            if any(inventory["files"][member].get(key) != expected[key] for key in ("sha256", "size", "mode")):
                return None, failure
        text = _text(MANIFEST, inventory)
        manifest_pin = platform["manifest"]
        if text is None or len(text.encode()) != manifest_pin["size"] or digest(text.encode()) != manifest_pin["sha256"]:
            return None, failure
        manifest = json.loads(text)
        if manifest != manifest_pin["content"] or manifest["runtime"] != runtime:
            return None, failure
        members = manifest["files"]
        names = [row["path"] for row in members]
        released_names = {name.removeprefix(PAYLOAD + "/sidecar-payload/")
                          for name, row in inventory["expected"].items()
                          if name.startswith(PAYLOAD + "/sidecar-payload/")
                          and name != MANIFEST and row.get("type") == "file"}
        if len(names) != len(set(names)) or set(names) != released_names:
            return None, failure
        for row in members:
            member = PAYLOAD + "/sidecar-payload/" + row["path"]
            if (not _preserved(member, inventory)
                    or any(inventory["files"][member].get(key) != row[key] for key in ("sha256", "size", "mode"))):
                return None, failure
        floor = contract["floor"]
        floor_text = _text(FLOOR_MEMBER, inventory)
        if (floor_text is None or digest(floor_text.encode()) != floor["sha256"]
                or len(floor_text.encode()) != floor["size"]
                or json.loads(floor_text).get("engines", {}).get("node") != floor["value"]):
            return None, "engine-floor-unproven"
        if "/loom-payload/" in path:
            if "nodejs >= 22" not in inventory.get("requires", []):
                return None, "engine-floor-unmet"
            binding = json.loads(sources["protocol/theme-lab-v2/payload-binding.json"]["content"])
            selected = [row for row in binding["files"] if row["path"] == path.removeprefix(PAYLOAD + "/loom-payload/")]
            if (len(selected) != 1 or selected[0]["sha256"] != member_pin["sha256"]
                    or selected[0]["bytes"] != member_pin["size"]):
                return None, failure
        return dict(path=path, role=definition["role"], intent=rule["intent"], sha256=member_pin["sha256"],
                    mode=member_pin["mode"], input_member=pin["input_member"], input_archive_sha256=asset["sha256"],
                    proof_model="authenticated-source-relation-and-release-preservation",
                    tag_commit=CURRENT070_COMMIT, tag_tree=CURRENT070_TREE,
                    runtime_member=RUNTIME, runtime_sha256=runtime["sha256"], manifest_sha256=manifest_pin["sha256"],
                    native_execution_claimed=False, system_node_required=False), None
    except (ContractError, OSError, ValueError, KeyError, TypeError, AttributeError):
        return None, failure
