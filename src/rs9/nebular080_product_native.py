"""Version-isolated product/native admission owner for Nebular Fusion 0.8.

The fixed NativeRC/API/body shape is authenticated first.  A capability is
then minted only by joining that evidence to a genuine, same-process
``ReleaseCapture`` supplied by the product-capture owner.  Product source
authority remains derived from that capture; this module does not freeze a
release ID or source-authority fingerprint while those records are still
late-bound.
"""
from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import weakref
import zipfile
from typing import Any

from rs9.errors import ContractError


VERSION = "0.8.0"
REPOSITORY = "Knowledge-Forge-AI/theme-forge-nebular-fusion"
WORKFLOW = ".github/workflows/native-rc.yml"
RUN_ID = 42418673472
RUN_ATTEMPT = 1
TESTED_COMMIT = "516f5a7d8a449946a0246ea23d37991f586dfc2c"
TESTED_TREE = "907163a09d2995c9080074294db54c54af626563"
MERGE_COMMIT = "6a6ef6621abe77d2391dc2ec1f0a317e62e7599f"
REPOSITORY_ID = 1358643872
WORKFLOW_ID = 371104521
INDEX_ARTIFACT_ID = 13593057759
INDEX_ARTIFACT_NAME = "nebular-rc-index-42418673472-a1"
INDEX_ARTIFACT_BYTES = 3076
INDEX_ARTIFACT_SHA256 = "1c5ce07befdb8907a36e808f55d7c43f9f5efef7ba33a3f1371d227e5a853d26"
INDEX_MEMBER_BYTES = 13991
INDEX_MEMBER_SHA256 = "a20866338376073f05fc8de2fa2de223c2a679903429f993c061313a05a32b39"

LANES = ("macos-arm64", "linux-arm64", "linux-x64")
_HEX40 = re.compile(r"[0-9a-f]{40}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_SCENARIOS = frozenset({"A", "B", "C", "C-signal"})
_SMOKE_KINDS = frozenset({"npm-package", "raw-archive", "appearance-pair", "paired-v2"})
_PAIRED_V2_STEPS = (
    "app-shell", "paired-app-theme", "paired-open-developer", "paired-brief",
    "paired-three-edits", "paired-compile-both", "paired-preview-acks",
    "paired-create-candidate", "paired-review-association", "paired-select-candidate",
    "paired-appearance-dark", "paired-apply-detached", "paired-save-as",
    "paired-reopen", "paired-appearance-matrix",
)


def _pin(bytes_: int, sha256: str) -> dict[str, Any]:
    return {"bytes": bytes_, "sha256": sha256}


_API_PINS = {
    "run.json": _pin(14753, "f70fb843dfa85122f3c8f93ffecd47e222301200e83e2b7672acc25ed69ea4f1"),
    "jobs.json": _pin(21787, "5a54788d18dd8645ed8e746a1dcfe3ff019b2d5bf4cb16040cbce9049b9c107e"),
    "compiler-commit.json": _pin(1300, "14848f5af08b753c6c4cc011f723f7497544991dab979a200f5e061ff725f271"),
    "artifacts.json": _pin(3126, "c7566e7b039a87a00d2aa3875c1749ddc71b6888d8f875a26741e447d3b1cb05"),
}

_SOURCE_CI_RUN_ID = 42418673471
_SOURCE_CI_RUN_ATTEMPT = 1
_SOURCE_CI_WORKFLOW = ".github/workflows/ci.yml"
_SOURCE_CI_WORKFLOW_ID = 351229988
_SOURCE_CI_PIN = _pin(
    14723,
    "1246db2a43f8b72e8a0339d24bd216e67038e3e3a86d3ed2831c65fd50fc5f06",
)

_JOB_NAMES = {
    128542183437: "Select native release-candidate lanes",
    128542217238: "Linux arm64 release candidate (scenario B)",
    128542217254: "Linux x64 release candidate (scenario C + C-signal)",
    128542217321: "macOS arm64 release candidate (scenario A)",
    128546502256: "Release-candidate catalog",
}

_LANE_REFERENCE = {
    "macos-arm64": {
        "lane": "macos-arm64", "platform": "darwin-arm64", "artifact_id": 13592882995,
        "artifact_name": "nebular-rc-0.8.0-macos-arm64-516f5a7d8a44-r42418673472-a1",
        "artifact_sha256": "2a2e0592002d0e647c582789495c332daf148da1ebe580fe8a3f9bb8347b29a3",
        "artifact_bytes": 100033007,
        "evidence_sha256": "14ae45f18c4fbb6fbf9999fe2064cc1efe6d060614f4b0c2c8895e96ea80c3d6",
        "manual_confirmation_required": True,
        "package_members": 1689,
        "package_manifest_sha256": "2004bbac8b7f879000233497c95f5079a7f5a71b0d3d9f17b15152947a59ca95",
        "raw": {"filename": "theme-forge-nebular-fusion-v0.8.0-aarch64-apple-darwin.app.tar.gz",
                "bytes": 49769994, "sha256": "0a7ab188afc4660f68bd6dabfda96309a348108a8d77a4786df1731cddaf6896",
                "members": 1689, "executable_sha256": "dabf051f09fbe1ca2cf5ec5fd9e2f4d9972fba868d061e1286a79ac1d7eaabfb"},
        "npm": {"filename": "knowledge-forge-ai-theme-forge-nebular-fusion-darwin-arm64-0.8.0.tgz",
                "bytes": 49765857, "sha256": "de475f7571c0f6b37e7bf9f1b96d3f3f67db08eb4df3c8640a5236d2305cd659"},
        "glibc_minimum": None,
    },
    "linux-arm64": {
        "lane": "linux-arm64", "platform": "linux-arm64", "artifact_id": 13592304126,
        "artifact_name": "nebular-rc-0.8.0-linux-arm64-516f5a7d8a44-r42418673472-a1",
        "artifact_sha256": "13a042bbdd234c3f115d5d01af5643da191ff8f2edbac646120ce3cf1d9f261f",
        "artifact_bytes": 114520052,
        "evidence_sha256": "8f173238488204a9e475c85a2ecde8c1e4b79aa3c679eee4fb06cfd7d9b38309",
        "manual_confirmation_required": False,
        "package_members": 1782,
        "package_manifest_sha256": "aaaf6f47d9a2aec517ff721f1eccb598804596185aec76ab6b607c37037bbeab",
        "raw": {"filename": "theme-forge-nebular-fusion-v0.8.0-aarch64-unknown-linux-gnu.tar.gz",
                "bytes": 57038323, "sha256": "4bbc40f180d954e1ca496606da9b63d7ce0f49dd29e802893aabc4aa0e859e94",
                "members": 1785, "executable_sha256": "65cbd19123ace49cd45de5b812506ed6c085350105ea6eaffff2b6191091a1fc"},
        "npm": {"filename": "knowledge-forge-ai-theme-forge-nebular-fusion-linux-arm64-0.8.0.tgz",
                "bytes": 56975011, "sha256": "a254369453facc0cbaa32a3d8ed0230bfc7eee29549854e9bc94d6bcdf2f47a7"},
        "glibc_minimum": "2.34",
    },
    "linux-x64": {
        "lane": "linux-x64", "platform": "linux-x64", "artifact_id": 13593195732,
        "artifact_name": "nebular-rc-0.8.0-linux-x64-516f5a7d8a44-r42418673472-a1",
        "artifact_sha256": "d4e9007775926f92ffde6d409f80883485c1b84d4434fd5de1444aa22414d242",
        "artifact_bytes": 114094109,
        "evidence_sha256": "dc59ce280cf353cdb9c11e75c04dacd97e4b2210e718248e68e064a55b200016",
        "manual_confirmation_required": False,
        "package_members": 1782,
        "package_manifest_sha256": "fb2b250b354949fd704e0901bde79ff60ec66b92577a08d1b299945f02fef19d",
        "raw": {"filename": "theme-forge-nebular-fusion-v0.8.0-x86_64-unknown-linux-gnu.tar.gz",
                "bytes": 56825312, "sha256": "498f0f6ff81c32200843e04016f86f7733905df0b0712c3f3639162ad5655abc",
                "members": 1785, "executable_sha256": "61773740d5a165ccbf287ba8eaa175470d7288d23bd6c332e209e6cc07a7d8b1"},
        "npm": {"filename": "knowledge-forge-ai-theme-forge-nebular-fusion-linux-x64-0.8.0.tgz",
                "bytes": 56762984, "sha256": "27fac4293d90e0198797aaa0627d254ffb9aa35a18de91b92ee1c4c1ab79c53d"},
        "glibc_minimum": "2.34",
    },
}

_REFERENCE = {
    "schema": "rs9.nebular080-product-native-reference.v1",
    "repository": REPOSITORY,
    "workflow": WORKFLOW,
    "run_id": RUN_ID,
    "run_attempt": RUN_ATTEMPT,
    # Keep the established 071 reference field names at this boundary.
    "tested_commit": TESTED_COMMIT,
    "tested_tree": TESTED_TREE,
    "catalog": {
        "id": INDEX_ARTIFACT_ID,
        "name": INDEX_ARTIFACT_NAME,
        "size": INDEX_ARTIFACT_BYTES,
        "sha256": INDEX_ARTIFACT_SHA256,
        "member": {"path": "rc-index.json", "size": INDEX_MEMBER_BYTES, "sha256": INDEX_MEMBER_SHA256},
    },
    "lanes": [copy.deepcopy(_LANE_REFERENCE[lane]) for lane in LANES],
}

# Every JSON body retained under the three original artifact evidence roots.
# The names are relative to ``<lane>/evidence`` and the values are the exact
# bounded bytes/hash pins; logs, archives, and private transport envelopes are
# intentionally not part of this owner.
_EVIDENCE_PINS = {
    "macos-arm64": {
        "build-receipt.json": _pin(2014, "704f265694899f8d52778f4f873fb89eee7460442902c310c593f9f8abf30590"),
        "node-authenticity.json": _pin(1171, "8ac235e8011b7b10f79924487107bd9f0c33801e621deca8333b2e2c6231c12b"),
        "package-manifest.json": _pin(437637, "2004bbac8b7f879000233497c95f5079a7f5a71b0d3d9f17b15152947a59ca95"),
        "package-record.json": _pin(910, "dc9f8402bdf334eb92a4a7aef023d2e3973f0d46e4d055da2a70327a02210b59"),
        "plan.json": _pin(1462, "a71e89a451369ae78fbda2cfd571906b912491c3b2ba19eb7eeb15b6dc49a285"),
        "qualification.json": _pin(1997, "546d4d5dc83bed94158a0a894791e8ec1fa37ee93a53fdc77a1c1cede0d9e394"),
        "rc-evidence.json": _pin(11746, "14ae45f18c4fbb6fbf9999fe2064cc1efe6d060614f4b0c2c8895e96ea80c3d6"),
        "smoke/darwin-arm64-A-npm-package.receipt.json": _pin(2845, "9a05282c75b8b2c7970bc78a51d19eb6a36f2b012b484bf8cd29797f9e6fbfad"),
        "smoke/darwin-arm64-A-npm-package.run.json": _pin(2350, "27560f96fcb8518fe772ce2175318475ac0e462ef940a7568696e798f607d753"),
        "smoke/darwin-arm64-A-raw-archive.receipt.json": _pin(2829, "78b3724ad8880a87812b78c3d037f6b7bebcc3c1434559fa9345efd66942d13e"),
        "smoke/darwin-arm64-A-raw-archive.run.json": _pin(2350, "4df7134cf7a17da77fc26f15db49ab20b22c5605c47bc2ed826476d2c0cc3011"),
        "smoke/darwin-arm64-appearance-pair-raw-view-a.receipt.json": _pin(739, "2a6278e81f7cdad9a0a91251d9d2daa9390385ef0548ca8133f3c0933ffb009c"),
        "smoke/darwin-arm64-appearance-pair-raw-view-b.receipt.json": _pin(438, "d88f1af5a182cbbec76099780316ceeccc4825f01f8d071e1985f60a05825b04"),
        "smoke/darwin-arm64-appearance-pair-raw.pair.run.json": _pin(3101, "6d9e66745754f585bfae0a0198da492227023fd159514c435c3ef747e3c41618"),
        "smoke/darwin-arm64-appearance-pair-raw.phases/darwin-arm64-P-restart-raw.receipt.json": _pin(1936, "1b7f67f30ff340a5bdb145519bfe87f870ce3375d62fbe17ab2b684970c8ed68"),
        "smoke/darwin-arm64-appearance-pair-raw.phases/darwin-arm64-P-restart-raw.run.json": _pin(1492, "109eb22df747db90a169a3bde5b4f3ae237e92e44fe51fa396b87c789783ca63"),
        "smoke/darwin-arm64-appearance-pair-raw.phases/darwin-arm64-P-save-raw.receipt.json": _pin(2604, "297981808fc283207c35d763c853743658aec1f9d1305488be2078753f0c8756"),
        "smoke/darwin-arm64-appearance-pair-raw.phases/darwin-arm64-P-save-raw.run.json": _pin(1823, "b99963ebd94e7d643ac5c57cbbfb1d2c02d59b84b1ca4356ba78df8ae8cd4b46"),
        "smoke/darwin-arm64-paired-v2-raw-archive.receipt.json": _pin(7625, "5eaab40d6fd42e1f73e1cfac16b5523f09eccdeea687a4c900363dcc862f8079"),
        "smoke/darwin-arm64-paired-v2-raw-archive.run.json": _pin(3052, "43dd8e50c8d71f357cd49e6e874e419fc87d3ae04e903b81e9941f65082fe005"),
    },
    "linux-arm64": {
        "build-receipt.json": _pin(2157, "58c0c3d46bc71f57dc3df20d4c56a116b9ea3063f2084a8e3f32e9d855471faf"),
        "node-authenticity.json": _pin(850, "00d5766f8e73286d1788afc6e21661a6130d5692180f02d1df64c4086f9563a5"),
        "package-manifest.json": _pin(425531, "aaaf6f47d9a2aec517ff721f1eccb598804596185aec76ab6b607c37037bbeab"),
        "package-record.json": _pin(911, "d932bca0009d138b354ef771db257697489a78451130f3616b271562bc720209"),
        "plan.json": _pin(1462, "a71e89a451369ae78fbda2cfd571906b912491c3b2ba19eb7eeb15b6dc49a285"),
        "qualification.json": _pin(2744, "9e8a3c437e2b7257e77343cc3e643e795c3073d7261e28cc6fc6a633f3d660a8"),
        "rc-evidence.json": _pin(13087, "8f173238488204a9e475c85a2ecde8c1e4b79aa3c679eee4fb06cfd7d9b38309"),
        "smoke/linux-arm64-appearance-pair-raw-view-a.receipt.json": _pin(740, "fc4ffb53005af34cc46585f239140e023d146170158b1fce3f73804b71c9b032"),
        "smoke/linux-arm64-appearance-pair-raw-view-b.receipt.json": _pin(437, "756a24fe069749f2cf74220b7116070ba8d9d23ab6bcb316f89e1883aba87194"),
        "smoke/linux-arm64-appearance-pair-raw.pair.run.json": _pin(3056, "7f044dc4b6f434fb97adc3fb72fd6bd95a18a908bbadb456243770e0a68eb0c3"),
        "smoke/linux-arm64-appearance-pair-raw.phases/linux-arm64-P-restart-raw.receipt.json": _pin(1907, "3f40318d0b07449a2685620a46b3497cd65071aec52a0deab3b07ba96fbaf3e2"),
        "smoke/linux-arm64-appearance-pair-raw.phases/linux-arm64-P-restart-raw.run.json": _pin(1447, "89c5f6fb29c37ceed7b241a3173536b5ffd20a79783e6e99a7767f09c4bc6755"),
        "smoke/linux-arm64-appearance-pair-raw.phases/linux-arm64-P-save-raw.receipt.json": _pin(2577, "b613a1edbe0c5f84ca190d537cb8ee69f2af53799496581e04a8e060134369a7"),
        "smoke/linux-arm64-appearance-pair-raw.phases/linux-arm64-P-save-raw.run.json": _pin(1780, "095456bf9356e9a2af76d6c45f6d43235de94a375ea8b1af9c5038fc9d4a1132"),
        "smoke/linux-arm64-B-npm-package.receipt.json": _pin(3148, "1eab46b89a1711e73f64e72c8352bb06753cc812412574b4b6901fec33151242"),
        "smoke/linux-arm64-B-npm-package.run.json": _pin(2652, "e3158b9e92417db8080f75b7fae720da1237794b46553f981e25e51c5a3a8b33"),
        "smoke/linux-arm64-B-raw-archive.receipt.json": _pin(3159, "4f1a8b1783ed5615511c49a8033bd53fa0eecccc505fdb02ae7e3d6b00b44d2d"),
        "smoke/linux-arm64-B-raw-archive.run.json": _pin(2652, "10f7f2e97fa0614f35e218f00500d17d0821d186c334a3d44af9dc2a9d063bcb"),
        "smoke/linux-arm64-paired-v2-raw-archive.receipt.json": _pin(7598, "a75f745747b3720f7c8cd68920bc875da4e4c01fa612fd5de7db7f3317bb8402"),
        "smoke/linux-arm64-paired-v2-raw-archive.run.json": _pin(3009, "a4324c2585563b6dd68ff356a63f55788149ab70d3f2db25ea3f41e82465e610"),
    },
    "linux-x64": {
        "build-receipt.json": _pin(2151, "6307c2a72ca5da52d326b23a2a91fbdde6a8117335eb2e588a8f80aa5492a31a"),
        "node-authenticity.json": _pin(847, "ed28783d541a39b126dfb63e7f7d6b6aac3d71c3dfa718a7ca63896e7514ec26"),
        "package-manifest.json": _pin(425521, "fb2b250b354949fd704e0901bde79ff60ec66b92577a08d1b299945f02fef19d"),
        "package-record.json": _pin(906, "f73cfbc9abd72d6db960b3e6ecb9a9399797a74cd753d880d51049d31484c2ff"),
        "plan.json": _pin(1462, "a71e89a451369ae78fbda2cfd571906b912491c3b2ba19eb7eeb15b6dc49a285"),
        "qualification.json": _pin(2723, "70cedd0890b70d44d4eabd2c4ccfefbf8affbb9c6323a1ce872a7d28b1197256"),
        "rc-evidence.json": _pin(12632, "dc59ce280cf353cdb9c11e75c04dacd97e4b2210e718248e68e064a55b200016"),
        "smoke/linux-x64-appearance-pair-raw-view-a.receipt.json": _pin(740, "c5ee3d19bce4300a2dd6f54d98ea409e438637be0cdfb7194f7816b2dd364be9"),
        "smoke/linux-x64-appearance-pair-raw-view-b.receipt.json": _pin(437, "6c3efc322cd83f92b8120b834f2e47b3c23cd013bcefa6ed7e5577a917931686"),
        "smoke/linux-x64-appearance-pair-raw.pair.run.json": _pin(3050, "294f40f7bd72b9a168e52fd68cb474ae161edaf841db0b7594ebe3e70116acd1"),
        "smoke/linux-x64-appearance-pair-raw.phases/linux-x64-P-restart-raw.receipt.json": _pin(1907, "3caee9cbb7e21fc19cb8f5e450b5eca302ee930fead674ddcd784b446bc82760"),
        "smoke/linux-x64-appearance-pair-raw.phases/linux-x64-P-restart-raw.run.json": _pin(1443, "2c60cdeca11be692e7879db61e57f8446b378729aba748368bae7d6b83b969e2"),
        "smoke/linux-x64-appearance-pair-raw.phases/linux-x64-P-save-raw.receipt.json": _pin(2577, "4dfe13f4a7bb2a92fe171a87f680648ecce2e70a044bfa2c9502c6b715b43c94"),
        "smoke/linux-x64-appearance-pair-raw.phases/linux-x64-P-save-raw.run.json": _pin(1776, "8e86b8de7b0af1ed20d62177f092b629436b1b4e99cb90d1459ebafb631e2c72"),
        "smoke/linux-x64-C-raw-archive.receipt.json": _pin(2842, "cb319c63afc192e455897e7c2de0570f81d66cf3f211ab1c79d22f1a7acc99cf"),
        "smoke/linux-x64-C-raw-archive.run.json": _pin(2580, "6ecd20b71d509bd7cfe3fd3aea5062535d89bb85cb24eaed4030d87b790590a9"),
        "smoke/linux-x64-C-signal-npm-package.receipt.json": _pin(2844, "a0e867b1200d0cb4abaeb4619672c8d6e570e15af923831f393e0a8c925ba47f"),
        "smoke/linux-x64-C-signal-npm-package.run.json": _pin(2973, "783851c3902a2d6e97d21589463da23158175869229addb4fa4e5f771bbc843f"),
        "smoke/linux-x64-paired-v2-raw-archive.receipt.json": _pin(7594, "060163273a7194bc9603cd5e258c99939a43b7290f6850aa4d6f3a75e9d09bfd"),
        "smoke/linux-x64-paired-v2-raw-archive.run.json": _pin(3000, "87dd7754b8665b549f9c03fc98befe00fdff60072b0b7917a38668eab8689782"),
    },
}


def _fail(reason: str = "NativeRC evidence is unavailable or disagrees") -> None:
    raise ContractError("NEBULAR080_PRODUCT_NATIVE", reason)


def _canonical(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _receipt_digest_matches(body: bytes, expected: Any) -> bool:
    """Accept the producer receipt hash and the retained LF-only copy."""
    if not isinstance(body, bytes) or not _is_hex(expected, _HEX64):
        return False
    return _sha(body) == expected or (body.endswith(b"\n") and _sha(body[:-1]) == expected)


def _is_hex(value: Any, pattern: re.Pattern[str]) -> bool:
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _positive_int(value: Any) -> bool:
    return type(value) is int and value > 0


def _copy_json(value: Any) -> Any:
    try:
        return json.loads(json.dumps(value, ensure_ascii=False))
    except (TypeError, ValueError):
        _fail("Reference must be JSON data")


def reference() -> dict[str, Any]:
    """Return a detached 0.8 reference; this ordinary data is not a capability."""
    return _copy_json(_REFERENCE)


def validate_reference(value: Any) -> dict[str, Any]:
    """Require exact fixed 0.8 identities, including the established catalog shape."""
    try:
        if not isinstance(value, Mapping) or _canonical(dict(value)) != _canonical(_REFERENCE):
            _fail("Reference does not equal the fixed 0.8 NativeRC record")
    except (TypeError, ValueError):
        _fail("Reference does not equal the fixed 0.8 NativeRC record")
    return reference()


def api_pins() -> dict[str, dict[str, Any]]:
    """Return detached public API body pins for source-preparation receipts."""
    return _copy_json(_API_PINS)


def evidence_pins() -> dict[str, dict[str, dict[str, Any]]]:
    """Return detached per-lane JSON evidence pins; logs and archives are excluded."""
    return _copy_json(_EVIDENCE_PINS)


def _check_source(value: Any, *, merge: bool = False) -> None:
    if not isinstance(value, Mapping):
        _fail("Lane source relation is not an object")
    required = {"commit", "tree"} | ({"mergeCommit", "mergeTree"} if merge else set())
    if set(value) != required:
        _fail("Lane source relation is not closed")
    if not _is_hex(value.get("commit"), _HEX40) or value["commit"] != TESTED_COMMIT:
        _fail("Lane source commit disagrees")
    if not _is_hex(value.get("tree"), _HEX40) or value["tree"] != TESTED_TREE:
        _fail("Lane source tree disagrees")
    if merge and (value.get("mergeCommit") != MERGE_COMMIT or value.get("mergeTree") != TESTED_TREE):
        _fail("Lane merge source relation disagrees")


def validate_api_snapshots(
    run: Mapping[str, Any], jobs: Mapping[str, Any], compiler: Mapping[str, Any],
    artifacts: Mapping[str, Any],
    *, now: datetime | None = None, check_expiry: bool = True,
) -> dict[int, Mapping[str, Any]]:
    """Validate the exact five-job/four-artifact public API snapshot join."""
    if (not isinstance(run, Mapping)
            or type(run.get("id")) is not int or run.get("id") != RUN_ID
            or type(run.get("run_attempt")) is not int
            or run.get("run_attempt") != RUN_ATTEMPT
            or run.get("head_sha") != TESTED_COMMIT or run.get("path") != WORKFLOW
            or type(run.get("workflow_id")) is not int or run.get("workflow_id") != WORKFLOW_ID
            or run.get("event") != "pull_request"
            or run.get("status") != "completed" or run.get("conclusion") != "success"):
        _fail("Workflow API snapshot disagrees")
    for key in ("repository", "head_repository"):
        row = run.get(key)
        if (not isinstance(row, Mapping) or type(row.get("id")) is not int
                or row.get("full_name") != REPOSITORY or row.get("id") != REPOSITORY_ID):
            _fail("Workflow repository identity disagrees")
    if (not isinstance(compiler, Mapping) or compiler.get("sha") != TESTED_COMMIT
            or not isinstance(compiler.get("tree"), Mapping)
            or compiler["tree"].get("sha") != TESTED_TREE):
        _fail("Compiler source relation disagrees")
    rows = jobs.get("jobs") if isinstance(jobs, Mapping) else None
    if (not isinstance(jobs, Mapping) or type(jobs.get("total_count")) is not int
            or jobs.get("total_count") != len(_JOB_NAMES)):
        _fail("Job count disagrees")
    if (not isinstance(rows, list) or len(rows) != len(_JOB_NAMES)
            or any(not isinstance(row, Mapping) or type(row.get("id")) is not int for row in rows)
            or {row["id"] for row in rows} != set(_JOB_NAMES)):
        _fail("Job identity set disagrees")
    for row in rows:
        if (type(row.get("id")) is not int
                or type(row.get("run_id")) is not int
                or row.get("name") != _JOB_NAMES.get(row.get("id"))
                or row.get("run_id") != RUN_ID
                or type(row.get("run_attempt")) is not int
                or row.get("run_attempt") != RUN_ATTEMPT or row.get("head_sha") != TESTED_COMMIT
                or row.get("status") != "completed" or row.get("conclusion") != "success"):
            _fail("Job API snapshot disagrees")
    rows = artifacts.get("artifacts") if isinstance(artifacts, Mapping) else None
    expected = {lane["artifact_id"]: lane for lane in _LANE_REFERENCE.values()}
    expected[INDEX_ARTIFACT_ID] = {"artifact_sha256": INDEX_ARTIFACT_SHA256, "artifact_bytes": INDEX_ARTIFACT_BYTES}
    if (not isinstance(artifacts, Mapping) or type(artifacts.get("total_count")) is not int
            or artifacts.get("total_count") != len(expected)):
        _fail("Artifact count disagrees")
    if (not isinstance(rows, list) or len(rows) != len(expected)
            or any(not isinstance(row, Mapping) or type(row.get("id")) is not int for row in rows)
            or {row["id"] for row in rows} != set(expected)):
        _fail("Artifact identity set disagrees")
    result: dict[int, Mapping[str, Any]] = {}
    for row in rows:
        ident = row.get("id")
        pin = expected.get(ident)
        if pin is None or type(ident) is not int:
            _fail("Unknown artifact identity")
        try:
            expires = datetime.fromisoformat(str(row["expires_at"]).replace("Z", "+00:00"))
        except (KeyError, TypeError, ValueError):
            _fail("Artifact expiry is malformed")
        if (row.get("expired") is not False or expires.tzinfo is None
                or (check_expiry and expires <= (now or datetime.now(timezone.utc)))
                or (ident != INDEX_ARTIFACT_ID and row.get("name") != pin["artifact_name"])
                or (ident == INDEX_ARTIFACT_ID and row.get("name") != INDEX_ARTIFACT_NAME)
                or type(row.get("size_in_bytes")) is not int
                or row.get("size_in_bytes") != pin["artifact_bytes"]
                or row.get("digest") != "sha256:" + pin["artifact_sha256"]):
            _fail("Artifact custody metadata disagrees")
        ctx = row.get("workflow_run")
        if (not isinstance(ctx, Mapping) or type(ctx.get("id")) is not int
                or type(ctx.get("repository_id")) is not int
                or type(ctx.get("head_repository_id")) is not int
                or ctx.get("id") != RUN_ID
                or ctx.get("repository_id") != REPOSITORY_ID
                or ctx.get("head_repository_id") != REPOSITORY_ID
                or ctx.get("head_sha") != TESTED_COMMIT):
            _fail("Artifact workflow relation disagrees")
        result[ident] = row
    return result


def validate_source_ci_run(run: Any) -> dict[str, Any]:
    """Validate the byte-pinned qualified SourceCI workflow run identity."""
    if not isinstance(run, Mapping):
        _fail("SourceCI run snapshot is malformed")
    if (type(run.get("id")) is not int or run.get("id") != _SOURCE_CI_RUN_ID
            or type(run.get("run_attempt")) is not int
            or run.get("run_attempt") != _SOURCE_CI_RUN_ATTEMPT
            or run.get("head_sha") != TESTED_COMMIT
            or run.get("path") != _SOURCE_CI_WORKFLOW
            or type(run.get("workflow_id")) is not int
            or run.get("workflow_id") != _SOURCE_CI_WORKFLOW_ID
            or run.get("status") != "completed"
            or run.get("conclusion") != "success"):
        _fail("SourceCI run identity or status disagrees")
    for key in ("repository", "head_repository"):
        row = run.get(key)
        if (not isinstance(row, Mapping) or type(row.get("id")) is not int
                or row.get("id") != REPOSITORY_ID or row.get("full_name") != REPOSITORY):
            _fail("SourceCI repository identity disagrees")
    head_commit = run.get("head_commit")
    if (not isinstance(head_commit, Mapping)
            or head_commit.get("id") != TESTED_COMMIT
            or head_commit.get("tree_id") != TESTED_TREE):
        _fail("SourceCI head tree disagrees")
    return _copy_json(dict(run))


def _zip_member_mode(info: zipfile.ZipInfo) -> int:
    return info.external_attr >> 16


def validate_index(
    index: Any, *, now: datetime | None = None, check_expiry: bool = True,
) -> dict[str, Any]:
    """Validate the index without inventing a top-level tree field."""
    required = {"schema", "status", "eventName", "releaseCandidate", "retentionDays", "source",
                "selected", "passed", "failed", "skipped", "appleManualConfirmationRequired", "lanes"}
    if not isinstance(index, Mapping) or set(index) != required:
        _fail("Native index schema is not closed")
    if (index["schema"] != "nebular.native-rc-index-v1" or index["status"] != "pass"
            or index["eventName"] != "pull_request" or index["releaseCandidate"] is not False
            or index["retentionDays"] != 14 or index["appleManualConfirmationRequired"] is not True):
        _fail("Native index status disagrees")
    source = index["source"]
    if (not isinstance(source, Mapping) or set(source) != {"sha", "runId", "runAttempt", "version"}
            or source["sha"] != TESTED_COMMIT or source["runId"] != str(RUN_ID)
            or source["runAttempt"] != str(RUN_ATTEMPT) or source["version"] != VERSION):
        _fail("Native index source disagrees")
    selected = list(LANES)
    if (index["selected"] != selected or index["passed"] != selected
            or index["failed"] != [] or index["skipped"] != []):
        _fail("Native index lane selection disagrees")
    rows = index["lanes"]
    if (not isinstance(rows, list) or len(rows) != len(LANES)
            or any(not isinstance(row, Mapping) for row in rows)):
        _fail("Native index lane count disagrees")
    for row in rows:
        lane_name = row.get("lane") if isinstance(row, Mapping) else None
        expected = _LANE_REFERENCE.get(lane_name)
        if expected is None:
            _fail("Native index contains an unknown lane")
        _validate_index_lane(row, expected, now=now, check_expiry=check_expiry)
    if {row["lane"] for row in rows} != set(LANES):
        _fail("Native index lane set disagrees")
    return _copy_json(dict(index))


def _validate_index_lane(
    row: Mapping[str, Any], expected: Mapping[str, Any], *,
    now: datetime | None = None, check_expiry: bool = True,
) -> None:
    required = {"lane", "platform", "runner", "selected", "jobResult", "manualConfirmationRequired", "problems",
                "artifact", "evidenceSha256", "source", "candidate", "smoke", "status"}
    if (set(row) != required or row["lane"] != expected["lane"]
            or row["platform"] != expected["platform"] or row["selected"] is not True):
        _fail("Native index lane record is not closed")
    if (row["jobResult"] != "success" or row["status"] != "qualified-automated"
            or row["problems"] != [] or row["manualConfirmationRequired"] is not expected["manual_confirmation_required"]
            or row["evidenceSha256"] != expected["evidence_sha256"]):
        _fail("Native index lane status disagrees")
    _check_source(row["source"], merge=True)
    artifact = row["artifact"]
    if (not isinstance(artifact, Mapping)
            or set(artifact) != {"name", "id", "digest", "expiresAt", "apiDigest", "retentionDaysObserved"}
            or artifact["name"] != expected["artifact_name"]
            or artifact["id"] != str(expected["artifact_id"])
            or artifact["digest"] != expected["artifact_sha256"]
            or artifact["apiDigest"] != "sha256:" + artifact["digest"]
            or artifact["retentionDaysObserved"] != 14):
        _fail("Native index artifact relation disagrees")
    try:
        expires = datetime.fromisoformat(str(artifact["expiresAt"]).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        _fail("Native index artifact expiry is malformed")
    if (expires.tzinfo is None
            or (check_expiry and expires <= (now or datetime.now(timezone.utc)))):
        _fail("Native index artifact has expired")
    _validate_candidate(row["candidate"], expected)
    _validate_smoke_summaries(row["smoke"], expected)


def _validate_candidate(candidate: Any, expected: Mapping[str, Any]) -> None:
    required = {"files", "version", "packageManifestSha256", "executableSha256", "glibcMinimum", "npm", "raw"}
    if not isinstance(candidate, Mapping) or set(candidate) != required or candidate["version"] != VERSION:
        _fail("Native candidate record is not closed")
    if (candidate["packageManifestSha256"] != expected["package_manifest_sha256"]
            or candidate["executableSha256"] != expected["raw"]["executable_sha256"]
            or candidate["glibcMinimum"] != expected["glibc_minimum"]):
        _fail("Native candidate identity disagrees")
    files = candidate["files"]
    expected_files = [{"name": expected["npm"]["filename"], "sha256": expected["npm"]["sha256"]},
                      {"name": expected["raw"]["filename"], "sha256": expected["raw"]["sha256"]}]
    if files != expected_files:
        _fail("Native candidate file set disagrees")
    for kind in ("npm", "raw"):
        row = candidate[kind]
        if not isinstance(row, Mapping) or not isinstance(row.get("filename"), str):
            _fail("Native candidate payload record is malformed")
        for key in ("sha256",):
            if row.get(key) != expected[kind][key]:
                _fail("Native candidate payload digest disagrees")
        if row.get("size") != expected[kind]["bytes"]:
            _fail("Native candidate payload size disagrees")
        if kind == "raw" and row.get("members") != expected["raw"]["members"]:
            _fail("Native raw member count disagrees")
        if kind == "npm" and (row.get("npmVersion") != "10.9.9" or not _positive_int(row.get("entryCount"))):
            _fail("Native npm metadata disagrees")
    if any(not isinstance(row, Mapping) or set(row) != {"name", "sha256"} for row in files):
        _fail("Native candidate file records are not closed")


def _validate_smoke_summaries(smoke: Any, expected: Mapping[str, Any]) -> None:
    if not isinstance(smoke, list) or len(smoke) != 4:
        _fail("Native smoke family count disagrees")
    kinds: dict[str, Mapping[str, Any]] = {}
    ordinary_scenarios = {
        "macos-arm64": {"A"},
        "linux-arm64": {"B"},
        "linux-x64": {"C", "C-signal"},
    }.get(expected.get("lane"), set())
    for row in smoke:
        if not isinstance(row, Mapping) or row.get("status") != "pass":
            _fail("Native smoke summary is malformed")
        source = row.get("source")
        scenario = row.get("scenario")
        if source in {"npm-package", "raw-archive"} and scenario in ordinary_scenarios:
            kind = source
        elif source == "raw-archive" and scenario == "appearance-pair":
            kind = "appearance-pair"
        elif source == "raw-archive" and scenario == "paired-v2":
            kind = "paired-v2"
        else:
            kind = None
        if kind is None or kind in kinds:
            _fail("Native smoke family is missing, duplicated, or unknown")
        kinds[kind] = row
    if set(kinds) != set(_SMOKE_KINDS):
        _fail("Native smoke family set disagrees")
    for kind in ("npm-package", "raw-archive"):
        row = kinds[kind]
        if (not isinstance(row.get("label"), str) or row.get("receiptSha256") is None
                or not _is_hex(row.get("receiptSha256"), _HEX64)):
            _fail("Ordinary smoke receipt identity is malformed")
    pair = kinds["appearance-pair"]
    if (not isinstance(pair.get("label"), str)
            or pair.get("receiptSha256") is not None or not isinstance(pair.get("pairIdentity"), Mapping)
            or not isinstance(pair.get("appearancePair"), Mapping)
            or pair["appearancePair"].get("status") != "pass"
            or pair["appearancePair"].get("phases") != ["P-save", "P-restart"]
            or pair["appearancePair"].get("evidence") != "sealed-with-lane-evidence"
            or not isinstance(pair.get("observedPreference"), Mapping)):
        _fail("Appearance-pair summary is incomplete")
    pair_id = pair["pairIdentity"]
    if (pair_id.get("schema") != "nebular.appearance-pair-v1"
            or pair_id.get("rawExecutableSha256") != expected["raw"]["executable_sha256"]
            or pair_id.get("npmExecutableSha256") != expected["raw"]["executable_sha256"]):
        _fail("Appearance-pair executable relation disagrees")
    observed = pair["observedPreference"]
    if (not _is_hex(observed.get("sha256"), _HEX64) or observed.get("bytes") != 66):
        _fail("Appearance-pair preference digest is malformed")
    paired = kinds["paired-v2"]
    if (not isinstance(paired.get("label"), str)
            or not _is_hex(paired.get("receiptSha256"), _HEX64)
            or paired.get("appearanceMatrix") != {"status": "pass", "cells": 12}
            or paired.get("appearanceMatrixEditorPreserved") is not True):
        _fail("Paired-v2 summary is incomplete")


def catalog_index(
    data: bytes, *, now: datetime | None = None, check_expiry: bool = True,
) -> dict[str, Any]:
    """Validate the exact catalog ZIP and return its index JSON."""
    if (not isinstance(data, bytes) or len(data) != INDEX_ARTIFACT_BYTES
            or _sha(data) != INDEX_ARTIFACT_SHA256):
        _fail("Native index artifact bytes disagree")
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            rows = archive.infolist()
            if len(rows) != 1 or rows[0].filename != "rc-index.json":
                _fail("Native index archive member set disagrees")
            row = rows[0]
            mode = _zip_member_mode(row)
            if (row.is_dir() or row.file_size != INDEX_MEMBER_BYTES or row.flag_bits & 1
                    or row.extra or stat.S_ISLNK(mode) or mode & 0o7111
                    or stat.S_IFMT(mode) not in (0, stat.S_IFREG)):
                _fail("Native index archive member is unsafe")
            body = archive.read(row)
    except (OSError, ValueError, RuntimeError, zipfile.BadZipFile):
        _fail("Native index archive is unreadable")
    if len(body) != INDEX_MEMBER_BYTES or _sha(body) != INDEX_MEMBER_SHA256:
        _fail("Native index member bytes disagree")
    try:
        index = json.loads(body)
    except (TypeError, ValueError, UnicodeError):
        _fail("Native index JSON is malformed")
    return validate_index(index, now=now, check_expiry=check_expiry)


def _json_bytes(data: bytes, label: str) -> Any:
    try:
        return json.loads(data)
    except (TypeError, ValueError, UnicodeError):
        _fail(label + " JSON is malformed")


def _validate_run(run: Any, expected: Mapping[str, Any], *, scenario: str, source: str) -> None:
    if (not isinstance(run, Mapping) or run.get("schema") != "nebular.native-rc-smoke-run-v1"
            or run.get("status") != "pass" or run.get("platform") != expected["platform"]
            or run.get("scenario") != scenario or run.get("source") != source
            or run.get("problems") != []):
        _fail("Smoke run body disagrees")
    label = run.get("label")
    if not isinstance(label, str) or not isinstance(run.get("exit"), Mapping):
        _fail("Smoke run body is malformed")
    exit_row = run["exit"]
    expected_signal = scenario == "C-signal"
    if ((expected_signal and (exit_row.get("code") is not None
                              or exit_row.get("signal") != "SIGTERM"
                              or not isinstance(exit_row.get("signalSent"), Mapping)
                              or exit_row["signalSent"].get("signal") != "SIGTERM"))
            or (not expected_signal and (exit_row.get("code") != 0 or exit_row.get("signal") is not None))
            or not isinstance(run.get("finalization"), Mapping)
            or run["finalization"].get("status") != "complete"
            or run["finalization"].get("exitObserved") is not True):
        _fail("Smoke run did not complete successfully")
    checks = run.get("checks")
    if (not isinstance(checks, Mapping)
            or checks.get("orphans") != []
            or not isinstance(checks.get("persistentUserState"), Mapping)
            or checks["persistentUserState"].get("changed") != []):
        _fail("Smoke run custody checks disagree")


def _validate_receipt(receipt: Any, expected: Mapping[str, Any], *, scenario: str) -> None:
    if (not isinstance(receipt, Mapping) or receipt.get("schema") != "nebular.release-smoke-receipt-v1"
            or receipt.get("status") != "pass" or receipt.get("applicationVersion") != VERSION
            or receipt.get("scenario") != scenario or not isinstance(receipt.get("driver"), Mapping)):
        _fail("Smoke receipt body disagrees")
    driver = receipt["driver"]
    steps = driver.get("steps")
    if driver.get("status") != "pass" or driver.get("scenario") != scenario:
        _fail("Smoke receipt driver disagrees")
    if (not isinstance(steps, list) or not steps
            or any(not isinstance(step, Mapping) or step.get("ok") is not True for step in steps)):
        _fail("Smoke receipt steps are incomplete")


def _validate_view_receipt(receipt: Any) -> None:
    if (not isinstance(receipt, Mapping) or receipt.get("status") != "pass"
            or not isinstance(receipt.get("steps"), list) or not receipt["steps"]
            or any(not isinstance(step, Mapping) or step.get("ok") is not True
                   for step in receipt["steps"])):
        _fail("Appearance-pair view receipt disagrees")


def _validate_pair_run(run: Any, expected: Mapping[str, Any], row: Mapping[str, Any]) -> None:
    if (not isinstance(run, Mapping) or run.get("schema") != "nebular.native-rc-smoke-run-v1"
            or run.get("status") != "pass" or run.get("platform") != expected["platform"]
            or run.get("scenario") != "appearance-pair" or run.get("source") != "raw-archive"
            or run.get("problems") != [] or run.get("label") != row["label"]
            or run.get("pairIdentity") != row.get("pairIdentity")
            or run.get("observedPreference") != row.get("observedPreference")
            or not isinstance(run.get("appearancePair"), Mapping)
            or run["appearancePair"].get("status") != "pass"):
        _fail("Appearance-pair run body disagrees")


def _validate_pair_bodies(bodies: Mapping[str, bytes], expected: Mapping[str, Any], row: Mapping[str, Any]) -> None:
    prefix = row["label"]
    pair_run_path = "smoke/" + prefix + ".pair.run.json"
    pair_run = _json_bytes(bodies[pair_run_path], "Appearance-pair run")
    _validate_pair_run(pair_run, expected, row)
    for view in ("view-a", "view-b"):
        path = "smoke/" + prefix + "-" + view + ".receipt.json"
        _validate_view_receipt(_json_bytes(bodies[path], "Appearance-pair view"))
    for phase in ("P-save", "P-restart"):
        phase_prefix = "smoke/" + prefix + ".phases/" + expected["platform"] + "-" + phase + "-raw"
        phase_run = _json_bytes(bodies[phase_prefix + ".run.json"], "Appearance-pair phase run")
        _validate_run(phase_run, expected, scenario=phase, source="raw-archive")
        _validate_receipt(_json_bytes(bodies[phase_prefix + ".receipt.json"], "Appearance-pair phase receipt"), expected, scenario=phase)


def validate_evidence_bodies(bodies: Mapping[str, bytes]) -> dict[str, Any]:
    """Validate every pinned JSON body and all four smoke-family body joins."""
    if not isinstance(bodies, Mapping):
        _fail("Evidence bodies must be a mapping")
    if set(bodies) != {lane + "/" + path for lane, pins in _EVIDENCE_PINS.items() for path in pins}:
        _fail("Evidence body set is not the fixed 0.8 set")
    parsed: dict[str, dict[str, Any]] = {}
    for lane, pins in _EVIDENCE_PINS.items():
        expected = _LANE_REFERENCE[lane]
        lane_rows: dict[str, Any] = {}
        for path, pin in pins.items():
            body = bodies[lane + "/" + path]
            if not isinstance(body, bytes) or len(body) != pin["bytes"] or _sha(body) != pin["sha256"]:
                _fail("Evidence body bytes disagree")
            lane_rows[path] = _json_bytes(body, "Evidence")
        rc = lane_rows["rc-evidence.json"]
        required = {"schema", "lane", "platform", "runner", "status", "problems", "source", "plan",
                    "candidate", "buildReceiptSha256", "build", "qualification", "payloadBinding", "smoke",
                    "manualConfirmationRequired"}
        if not isinstance(rc, Mapping) or set(rc) != required or rc["lane"] != lane:
            _fail("Lane evidence record is not closed")
        if (rc["schema"] != "nebular.native-rc-evidence-v1" or rc["status"] != "pass"
                or rc["problems"] != [] or rc["manualConfirmationRequired"] is not expected["manual_confirmation_required"]):
            _fail("Lane evidence status disagrees")
        _check_source(rc["source"], merge=True)
        _validate_candidate(rc["candidate"], expected)
        _validate_smoke_summaries(rc["smoke"], expected)
        if rc["buildReceiptSha256"] != _sha(bodies[lane + "/build-receipt.json"]):
            _fail("Lane build receipt digest does not match body")
        for summary in rc["smoke"]:
            scenario = summary["scenario"]
            if scenario in _SCENARIOS or scenario == "paired-v2":
                receipt_path = lane + "/smoke/" + summary["label"] + ".receipt.json"
                receipt_body = bodies[receipt_path]
                if not _receipt_digest_matches(receipt_body, summary.get("receiptSha256")):
                    _fail("Smoke receipt digest does not match body")
                if scenario in _SCENARIOS or scenario == "paired-v2":
                    run = lane_rows["smoke/" + summary["label"] + ".run.json"]
                    run_receipt = run.get("receipt") if isinstance(run, Mapping) else None
                    if (not isinstance(run_receipt, Mapping)
                            or run_receipt.get("sha256") != summary.get("receiptSha256")
                            or run_receipt.get("status") != "pass"
                            or run_receipt.get("steps") != summary.get("steps")):
                        _fail("Smoke run receipt summary disagrees")
        qualification = lane_rows["qualification.json"]
        if (not isinstance(qualification, Mapping) or qualification.get("schema") != "nebular.native-rc-qualification-v1"
                or qualification.get("platform") != expected["platform"] or qualification.get("status") != "pass"
                or qualification.get("executableSha256") != expected["raw"]["executable_sha256"]
                or not isinstance(qualification.get("checks"), list)
                or any(not isinstance(row, Mapping) or row.get("ok") is not True for row in qualification["checks"])):
            _fail("Qualification evidence disagrees")
        if qualification.get("glibcMinimum") != expected["glibc_minimum"]:
            _fail("Measured producer glibc evidence disagrees")
        manifest = lane_rows["package-manifest.json"]
        if (not isinstance(manifest, Mapping) or manifest.get("schema") != "tfsb.nebular-package-manifest-v1"
                or manifest.get("fileCount") != expected["package_members"] if isinstance(manifest, Mapping) else True):
            _fail("Package manifest evidence disagrees")
        for row in rc["smoke"]:
            if row["scenario"] in _SCENARIOS and row["scenario"] not in {"appearance-pair", "paired-v2"}:
                run_path = "smoke/" + row["label"] + ".run.json"
                receipt_path = "smoke/" + row["label"] + ".receipt.json"
                _validate_run(lane_rows[run_path], expected, scenario=row["scenario"], source=row["source"])
                _validate_receipt(lane_rows[receipt_path], expected, scenario=row["scenario"])
            elif row["scenario"] == "appearance-pair":
                _validate_pair_bodies({path.removeprefix(lane + "/"): body for path, body in bodies.items() if path.startswith(lane + "/")}, expected, row)
            elif row["scenario"] == "paired-v2":
                run = lane_rows["smoke/" + row["label"] + ".run.json"]
                _validate_run(run, expected, scenario="paired-v2", source="raw-archive")
                if run.get("appearanceMatrix") != {"status": "pass", "cells": 12} or run.get("appearanceMatrixEditorPreserved") is not True:
                    _fail("Paired-v2 run matrix disagrees")
                receipt = run.get("receipt")
                if not isinstance(receipt, Mapping):
                    _fail("Paired-v2 run receipt is malformed")
                steps = receipt.get("steps")
                if (not isinstance(steps, list)
                        or any(not isinstance(step, Mapping) for step in steps)
                        or [step.get("id") for step in steps] != list(_PAIRED_V2_STEPS)
                        or any(step.get("ok") is not True for step in steps)):
                    _fail("Paired-v2 run steps disagree")
                _validate_receipt(lane_rows["smoke/" + row["label"] + ".receipt.json"], expected, scenario="paired-v2")
                receipt_steps = lane_rows["smoke/" + row["label"] + ".receipt.json"].get("driver", {}).get("steps")
                if (not isinstance(receipt_steps, list)
                        or any(not isinstance(step, Mapping) for step in receipt_steps)
                        or [step.get("id") for step in receipt_steps] != list(_PAIRED_V2_STEPS)):
                    _fail("Paired-v2 receipt steps disagree")
            else:
                _fail("Unknown smoke scenario")
        parsed[lane] = {"rc": rc, "qualification": qualification, "package_manifest": manifest}
    return parsed


def validate_native_evidence(
    *, run: Mapping[str, Any], jobs: Mapping[str, Any], compiler: Mapping[str, Any],
    artifacts: Mapping[str, Any], index_bytes: bytes, evidence_bodies: Mapping[str, bytes],
    now: datetime | None = None, check_expiry: bool = True,
) -> dict[str, Any]:
    """Validate the API/catalog/index/body boundary without release admission."""
    api_artifacts = validate_api_snapshots(
        run, jobs, compiler, artifacts, now=now, check_expiry=check_expiry,
    )
    index = catalog_index(index_bytes, now=now, check_expiry=check_expiry)
    parsed = validate_evidence_bodies(evidence_bodies)
    for row in index["lanes"]:
        expected = _LANE_REFERENCE[row["lane"]]
        if row["evidenceSha256"] != _sha(evidence_bodies[row["lane"] + "/rc-evidence.json"]):
            _fail("Index evidence digest disagrees")
        if row["artifact"]["id"] != str(expected["artifact_id"]):
            _fail("Index/API artifact relation disagrees")
        api_artifact = api_artifacts[expected["artifact_id"]]
        if row["artifact"]["expiresAt"] != api_artifact.get("expires_at"):
            _fail("Index/API artifact expiry disagrees")
    return {
        "schema": "rs9.nebular080-native-evidence-frame.v1",
        "repository": REPOSITORY,
        "version": VERSION,
        "tested_commit": TESTED_COMMIT,
        "tested_tree": TESTED_TREE,
        "run_id": RUN_ID,
        "run_attempt": RUN_ATTEMPT,
        "index_sha256": INDEX_ARTIFACT_SHA256,
        "artifact_ids": [api_artifacts[int(row["artifact"]["id"])] ["id"] for row in index["lanes"]],
        "lanes": [row["lane"] for row in index["lanes"]],
        "evidence": parsed,
        "release_join": "held-until-authenticated-product-capture",
    }


def _file_identity(info: os.stat_result) -> tuple[int, int, int, int, int, int, int, int, int]:
    return (
        info.st_dev, info.st_ino, info.st_size, info.st_mode,
        info.st_mtime_ns, info.st_ctime_ns, info.st_uid, info.st_gid, info.st_nlink,
    )


def _read_regular(root: Path, relative: str, limit: int) -> bytes:
    if (not isinstance(relative, str) or not relative or "\x00" in relative
            or relative.startswith("/") or "\\" in relative
            or any(part in ("", ".", "..") for part in relative.split("/"))):
        _fail("Descriptor path is not a safe fixed relative path")
    from rs9.materialize import validate_ancestry_not_symlink
    current = validate_ancestry_not_symlink(root.absolute())
    if not current.is_dir() or current.is_symlink():
        _fail("Evidence root is not a physical directory")
    for part in relative.split("/")[:-1]:
        current = current / part
        try:
            st = current.lstat()
        except OSError:
            _fail("Required evidence file is unavailable")
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            _fail("Evidence ancestor is unsafe")
    path = current / relative.split("/")[-1]
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            if (not stat.S_ISREG(before.st_mode)
                    or before.st_size <= 0 or before.st_size > limit):
                _fail("Evidence file is not bounded regular data")
            data = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
            try:
                named = path.lstat()
            except OSError:
                _fail("Evidence file disappeared during read")
    except OSError:
        _fail("Required evidence file is unavailable")
    if (len(data) != before.st_size
            or _file_identity(before) != _file_identity(after)
            or _file_identity(before) != _file_identity(named)):
        _fail("Evidence file changed during read")
    return data


def _body(root: Path, relative: str, pin: Mapping[str, Any]) -> bytes:
    """Read one fixed body and enforce its exact byte count and SHA-256 first."""
    data = _read_regular(root, relative, pin["bytes"])
    if len(data) != pin["bytes"] or _sha(data) != pin["sha256"]:
        _fail("Fixed evidence body bytes disagree")
    return data


def _read_capture_archive(path: str | Path, limit: int) -> bytes:
    """Read one already-authenticated payload again with no-follow identity checks."""
    try:
        from rs9.materialize import validate_ancestry_not_symlink
        path = validate_ancestry_not_symlink(Path(path))
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_size <= 0
                    or before.st_size > limit):
                _fail("Captured payload is not bounded regular data")
            data = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
            try:
                named = path.lstat()
            except OSError:
                _fail("Captured payload disappeared during replay")
            if (len(data) != before.st_size
                    or _file_identity(before) != _file_identity(after)
                    or _file_identity(before) != _file_identity(named)):
                _fail("Captured payload changed during replay")
            return data
    except (OSError, TypeError, ValueError):
        _fail("Captured payload is unavailable")


def _authenticate(
    root: str | Path, product_capture: Any, *, client: Any = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Authenticate native evidence and join it to a real 0.8 product capture.

    ``client`` is optional. When supplied, the same fixed public API endpoints
    are re-read and their immutable custody fields are compared to the retained
    snapshot; this is a caller-owned read-only client, never a release writer.
    """
    from rs9.release_core import ReleaseCapture

    if not isinstance(product_capture, ReleaseCapture):
        _fail("A genuine authenticated product capture is required")
    from rs9.nebular080_universal_consumer import authenticated_product_release

    product = authenticated_product_release(product_capture)
    if (product.get("tag") != "v0.8.0" or product.get("tree") != TESTED_TREE
            or product.get("source", {}).get("tree") != TESTED_TREE):
        _fail("Product release tree does not equal the authenticated NativeRC tree")
    provenance = product.get("provenance")
    if (not isinstance(provenance, Mapping)
            or provenance.get("schema") != "nebular.public-native-ci-release-provenance.v1"
            or provenance.get("repository") != REPOSITORY
            or provenance.get("version") != VERSION
            or provenance.get("release") != product.get("release_id")
            or provenance.get("releaseCommit") != product.get("commit")
            or provenance.get("testedCommit") != TESTED_COMMIT
            or provenance.get("testedTree") != TESTED_TREE
            or provenance.get("nativeCiRun") != RUN_ID
            or provenance.get("nativeCiAttempt") != RUN_ATTEMPT
            or provenance.get("nativeIndexSha256") != INDEX_MEMBER_SHA256
            or provenance.get("sourceCiRun") != _SOURCE_CI_RUN_ID):
        _fail("Product provenance does not bind the authenticated NativeRC")

    evidence_root = Path(root)
    validate_reference(_json_bytes(
        _read_regular(evidence_root, "native-reference.json", 65536),
        "Native reference",
    ))
    api = {
        name: _json_bytes(
            _body(evidence_root, "api/" + name, pin),
            "Native API",
        )
        for name, pin in _API_PINS.items()
    }
    artifacts = validate_api_snapshots(
        api["run.json"], api["jobs.json"],
        api["compiler-commit.json"], api["artifacts.json"],
        check_expiry=False,
    )
    source_ci = _json_bytes(
        _body(evidence_root, "api/source-run.json", _SOURCE_CI_PIN),
        "SourceCI run",
    )
    validate_source_ci_run(source_ci)
    if client is not None:
        prefix = "https://api.github.com/repos/" + REPOSITORY
        urls = {
            "run.json": prefix + f"/actions/runs/{RUN_ID}/attempts/{RUN_ATTEMPT}",
            "jobs.json": prefix + f"/actions/runs/{RUN_ID}/attempts/{RUN_ATTEMPT}/jobs?per_page=100",
            "compiler-commit.json": prefix + "/git/commits/" + TESTED_COMMIT,
            "artifacts.json": prefix + f"/actions/runs/{RUN_ID}/artifacts?per_page=100",
        }
        fresh = {
            name: client.json(url, request_class="github-api", limit=1024 * 1024)
            for name, url in urls.items()
        }
        fresh_artifacts = validate_api_snapshots(
            fresh["run.json"], fresh["jobs.json"],
            fresh["compiler-commit.json"], fresh["artifacts.json"],
            now=now, check_expiry=True,
        )
        fresh_source_ci = client.json(
            f"{prefix}/actions/runs/{_SOURCE_CI_RUN_ID}/attempts/{_SOURCE_CI_RUN_ATTEMPT}",
            request_class="github-api", limit=1024 * 1024,
        )
        validate_source_ci_run(fresh_source_ci)
        for key in ("id", "run_attempt", "head_sha", "path", "workflow_id",
                    "status", "conclusion"):
            if fresh_source_ci.get(key) != source_ci.get(key):
                _fail("Fresh SourceCI identity disagrees")
        for key in ("repository", "head_repository"):
            fresh_repo = fresh_source_ci.get(key)
            retained_repo = source_ci.get(key)
            if (not isinstance(fresh_repo, Mapping) or not isinstance(retained_repo, Mapping)
                    or fresh_repo.get("id") != retained_repo.get("id")
                    or fresh_repo.get("full_name") != retained_repo.get("full_name")):
                _fail("Fresh SourceCI repository identity disagrees")
        fresh_head = fresh_source_ci.get("head_commit")
        retained_head = source_ci.get("head_commit")
        if (not isinstance(fresh_head, Mapping) or not isinstance(retained_head, Mapping)
                or fresh_head.get("id") != retained_head.get("id")
                or fresh_head.get("tree_id") != retained_head.get("tree_id")):
            _fail("Fresh SourceCI head tree disagrees")
        for ident, row in artifacts.items():
            if any(
                fresh_artifacts[ident].get(key) != row.get(key)
                for key in ("name", "size_in_bytes", "digest", "workflow_run",
                            "expires_at", "expired")
            ):
                _fail("Fresh API artifact custody disagrees")
    catalog = _json_bytes(
        _read_regular(evidence_root, "artifact-metadata.json", 65536),
        "Catalog metadata",
    )
    if catalog != artifacts[INDEX_ARTIFACT_ID] or catalog.get("name") != INDEX_ARTIFACT_NAME:
        _fail("Catalog artifact metadata does not match the authenticated API")
    index_bytes = _read_regular(evidence_root, "rc-index-original.zip", INDEX_ARTIFACT_BYTES)
    evidence_bodies = {
        lane + "/" + relative: _read_regular(
            evidence_root, lane + "/" + relative, pin["bytes"],
        )
        for lane, pins in _EVIDENCE_PINS.items()
        for relative, pin in pins.items()
    }
    native_frame = validate_native_evidence(
        run=api["run.json"], jobs=api["jobs.json"],
        compiler=api["compiler-commit.json"], artifacts=api["artifacts.json"],
        index_bytes=index_bytes, evidence_bodies=evidence_bodies,
        check_expiry=False,
    )

    # Tie every native raw asset to the product capture's authenticated bytes,
    # archive manifest and release provenance.  The release ID/authority
    # identity remain capture-derived and are intentionally not hard-coded.
    raw_assets: list[dict[str, Any]] = []
    target_for_lane = {
        "macos-arm64": "darwin-arm64",
        "linux-arm64": "linux-arm64-gnu",
        "linux-x64": "linux-x64-gnu",
    }
    for lane in LANES:
        expected = _LANE_REFERENCE[lane]
        raw = expected["raw"]
        selected = product["assets_by_name"].get(raw["filename"])
        if (not isinstance(selected, Mapping) or selected.get("role") != "payload"
                or selected.get("size") != raw["bytes"]
                or selected.get("sha256") != raw["sha256"]
                or selected.get("checksum_covered") is not True):
            _fail("Product payload metadata does not match NativeRC raw asset")
        target = target_for_lane[lane]
        manifest = product_capture.manifests.get(target)
        archive = product_capture.archives.get(target)
        if (not isinstance(manifest, Mapping) or archive is None
                or len(manifest.get("members", [])) != raw["members"]
                or manifest.get("manifest_sha256") != _sha(_canonical(manifest.get("members")))):
            _fail("Product payload archive manifest disagrees")
        payload = _read_capture_archive(archive, raw["bytes"])
        if len(payload) != raw["bytes"] or _sha(payload) != raw["sha256"]:
            _fail("Product payload bytes disagree with NativeRC raw asset")
        if not any(
            row.get("sha256") == raw["executable_sha256"] and row.get("type") == "file"
            for row in manifest.get("members", [])
        ):
            _fail("Product payload executable does not match NativeRC manifest")
        provenance_rows = [
            row for row in provenance.get("assets", [])
            if isinstance(row, Mapping) and row.get("name") == raw["filename"]
        ]
        if (len(provenance_rows) != 1
                or provenance_rows[0].get("role") != "raw-archive"
                or provenance_rows[0].get("id") != selected.get("github_asset_id")
                or provenance_rows[0].get("sha256") != raw["sha256"]
                or provenance_rows[0].get("bytes") != raw["bytes"]):
            _fail("Product provenance does not cover NativeRC raw asset")
        raw_assets.append({
            "id": selected["github_asset_id"],
            "name": raw["filename"],
            "size": raw["bytes"],
            "sha256": raw["sha256"],
            "manifest_sha256": manifest["manifest_sha256"],
        })
    return {
        "schema": "rs9.nebular080-product-native-admission-frame.v1",
        "reference": reference(),
        "product_source": product["source"],
        "product_release": {
            "release_id": product["release_id"],
            "tag": product["tag"],
            "commit": product["commit"],
            "tree": product["tree"],
            "record_sha256": product["record_sha256"],
        },
        "assets": raw_assets,
        "provenance": {
            "nativeCiRun": provenance["nativeCiRun"],
            "nativeCiAttempt": provenance["nativeCiAttempt"],
            "sourceCiRun": provenance["sourceCiRun"],
            "testedCommit": provenance["testedCommit"],
            "testedTree": provenance["testedTree"],
        },
        "compiler_relation": (
            "release-commit" if product["commit"] == TESTED_COMMIT
            else "authenticated-equal-tree"
        ),
        "native_evidence": native_frame,
    }


def _descriptor_names() -> frozenset[str]:
    names = {"rc-index-original.zip", "native-reference.json", "artifact-metadata.json"}
    names.update("api/" + name for name in _API_PINS)
    names.add("api/source-run.json")
    names.update(lane + "/" + path for lane, pins in _EVIDENCE_PINS.items() for path in pins)
    return frozenset(names)


def _resolve_descriptor_native_root(
    descriptor: Mapping[str, Any], inrun_root: str | Path,
    *, repository: str | Path | None = None,
) -> Path:
    """Resolve the same artifact/source-root boundary used by the materializer.

    The production owner may pass its repository root to invoke the maintained
    ``_resolve_inrun_artifact_root``/``_resolve_repo_contained_dir`` pair.  The
    existing consumer ABI passes only ``inrun_root``; in that route the caller
    has already supplied the owner-resolved artifact root, so only the fixed
    descriptor evidence root is appended here.
    """
    from rs9.materialize import validate_ancestry_not_symlink

    evidence = descriptor.get("evidence")
    source_root = evidence.get("source_root") if isinstance(evidence, Mapping) else None
    if source_root != "evidence/public-release":
        _fail("Native descriptor source root is not fixed")
    if not isinstance(inrun_root, (str, Path)):
        _fail("Native descriptor artifact root is malformed")
    candidate = validate_ancestry_not_symlink(Path(inrun_root))
    if repository is not None:
        try:
            from rs9 import tf_pypi_nebular080_publish as owner
            artifact_root = owner._resolve_inrun_artifact_root(
                Path(repository), descriptor.get("manylinux"), candidate,
                system_webkit_spec=descriptor.get("system_webkit"),
            )
            evidence_root = owner._resolve_repo_contained_dir(
                artifact_root, source_root,
                symlink_code="RAW_RELEASE_SYMLINK",
                missing_code="RAW_RELEASE_HANDOFF_PENDING",
                containment_code="QUALIFICATION_INPUTS_EVIDENCE",
            )
            return validate_ancestry_not_symlink(evidence_root / "native-ci")
        except (AttributeError, ImportError, OSError, TypeError, ValueError):
            _fail("Native descriptor artifact root cannot be resolved")
    evidence_root = candidate / source_root
    if not evidence_root.is_dir() or evidence_root.is_symlink():
        _fail("Native descriptor evidence root is unavailable")
    return validate_ancestry_not_symlink(evidence_root / "native-ci")


def replay_descriptor_native(
    descriptor: Mapping[str, Any], inrun_root: str | Path, product_capture: Any,
    *, client: Any = None, repository: str | Path | None = None,
) -> Any:
    """Check fixed descriptor custody, then replay a real product/native join."""
    if not isinstance(descriptor, Mapping) or not isinstance(descriptor.get("evidence"), Mapping):
        _fail("Native descriptor is malformed")
    evidence = descriptor["evidence"]
    if evidence.get("source_root") != "evidence/public-release" or not isinstance(evidence.get("files"), Mapping):
        _fail("Native descriptor source root is not fixed")
    declared = evidence["files"]
    names = _descriptor_names()
    native_declared = {
        key: value for key, value in declared.items()
        if isinstance(key, str) and key.startswith("native-ci/")
    }
    if set(native_declared) != {"native-ci/" + name for name in names}:
        _fail("Native descriptor file set is not fixed")
    root = _resolve_descriptor_native_root(
        descriptor, inrun_root, repository=repository,
    )
    for relative, row in native_declared.items():
        if (not isinstance(row, Mapping) or set(row) != {"path", "size", "sha256"}
                or row.get("path") != relative or not _positive_int(row.get("size"))
                or not _is_hex(row.get("sha256"), _HEX64)):
            _fail("Native descriptor row is malformed")
        body = _read_regular(root, relative.removeprefix("native-ci/"), min(row["size"], 512 * 1024 * 1024))
        if len(body) != row["size"] or _sha(body) != row["sha256"]:
            _fail("Native descriptor custody digest disagrees")
    return replay_native_admission(root, product_capture, client=client)


class _NativePayloadAdmission:
    __slots__ = ("__weakref__",)

    def __init__(self, seal: object) -> None:
        if seal is not _SEAL:
            _fail("Native admission is not privately sealed")


_SEAL = object()
_ISSUED: weakref.WeakKeyDictionary[
    _NativePayloadAdmission, tuple[int, Path, object, bytes]
] = weakref.WeakKeyDictionary()


def replay_native_admission(
    root: str | Path, product_capture: Any, *, client: Any = None,
    now: datetime | None = None,
) -> _NativePayloadAdmission:
    """Mint only an ephemeral capability from a real product/native join."""
    frame = _authenticate(root, product_capture, client=client, now=now)
    admission = _NativePayloadAdmission(_SEAL)
    _ISSUED[admission] = (
        os.getpid(), Path(root), product_capture, _canonical(frame),
    )
    return admission


def require_native_admission(
    admission: Any, product_capture: Any, reference_value: Any, asset: Any = None,
    *, now: datetime | None = None,
) -> dict[str, Any]:
    """Require same-process capability and replay unchanged held bytes."""
    validate_reference(reference_value)
    if type(admission) is not _NativePayloadAdmission:
        _fail("Native capability must be minted in this process")
    state = _ISSUED.get(admission)
    if state is None or state[0] != os.getpid() or state[2] is not product_capture:
        _fail("Native capability is not registered for this capture")
    frame = _authenticate(state[1], product_capture, now=now)
    if _canonical(frame) != state[3]:
        _fail("Native admission frame changed during replay")
    if asset is not None and not any(
        all(row.get(key) == asset.get(key) for key in ("id", "name", "size", "sha256"))
        for row in frame["assets"]
    ):
        _fail("Native admission asset is not part of the authenticated frame")
    return frame


__all__ = [
    "VERSION", "LANES", "reference", "validate_reference", "api_pins", "evidence_pins",
    "validate_api_snapshots", "validate_source_ci_run", "catalog_index", "validate_index", "validate_evidence_bodies",
    "validate_native_evidence", "replay_descriptor_native", "replay_native_admission",
    "require_native_admission",
]
