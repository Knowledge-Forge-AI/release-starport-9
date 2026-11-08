"""Exact Nebular 0.8.0 source and native identities; these constants confer no authority.

This is a version-isolated successor to :mod:`rs9.current_os071`.  The
release rows are public readback facts and are deliberately data-only: this
module does not authenticate a capture, read a checkout, execute a runtime,
or authorize a package or publication.
"""

CURRENT080_VERSION = "0.8.0"
CURRENT080_TAG = "v0.8.0"
CURRENT080_REPOSITORY = "Knowledge-Forge-AI/theme-forge-nebular-fusion"
CURRENT080_REPOSITORY_ID = 1358643872
CURRENT080_RELEASE_ID = 437909062
CURRENT080_COMMIT = "516f5a7d8a449946a0246ea23d37991f586dfc2c"
CURRENT080_TREE = "907163a09d2995c9080074294db54c54af626563"

# The fixture is the separately admitted Stellar Burst v0.7.0 test product;
# only the icon below is a Nebular v0.8.0 source-tree member.  Keeping both
# identities explicit prevents a fixture row from becoming an accidental
# Nebular source claim.
CURRENT080_SOURCE_FIXTURE_BINDING = {
    "nebular": {"commit": CURRENT080_COMMIT, "tree": CURRENT080_TREE},
    "icon": {
        "path": "src-tauri/icons/icon.png",
        "blob": "ae7ebf4396e0d7aed6e15e5a5f0e123787cd9a35",
        "size": 8814,
        "sha256": "2d65e8c69a675b6c939ac11757c6a47a123f63b3f83b6d58305aaf7231aca160",
        "source_commit": CURRENT080_COMMIT,
        "source_tree": CURRENT080_TREE,
    },
    "fixture": {
        "repository": "Knowledge-Forge-AI/theme-forge-stellar-burst",
        "tag": "v0.7.0",
        "commit": "3edb9d2c40dd19a2b7d97d9309bc210e7fed711c",
        "tree": "4be1551c49b15dff788d07ed1fb00ddcd8839a76",
    },
}

CURRENT080_SOURCE_ARCHIVE = {
    "github_asset_id": 722429152,
    "name": "theme-forge-nebular-fusion-v0.8.0-source.tar.gz",
    "bytes": 6725884,
    "sha256": "9eb30214158d1bfaf2d7d4c2b5311ed43e02a26e455239b1873abb11353c63b6",
    "member_count": 1664,
    "uncompressed_bytes": 24536455,
}

CURRENT080_SOURCE_AUTHORITY = {
    "github_asset_id": 722429154,
    "name": "nebular-compiled-public-build-source-authority-v0.8.0.json",
    "bytes": 1767,
    "sha256": "53dea0e5ca138616a94d351e2490f94aa34de74d2665fd62119034ca1fb58dcf",
    "sha512": "47149a5a8aa4b5791ded2eab971c1d53b1fc240cd5c504c46543800d64dab27bed3d69688506e6d17e0b7b057f4aeeeb9414d6a8c91360ee803ef225c79ddd19",
    "identity": "9e9f8c17a982d4e825d44a82e7b70ebeb8697a0e9e36a7d1cf348bad38ec04f1",
}

CURRENT080_SOURCE_MANIFEST = {
    "github_asset_id": 722469273,
    "name": "nebular-v0.8.0-source-manifest.json",
    "bytes": 951107,
    "sha256": "8898ee256dcf60bb0793d23eb70e3c15bc1e623b9bea40a1785ec25d6c4ecb8d",
}

CURRENT080_SOURCE_REBUILD_INPUTS = {
    "github_asset_id": 722469271,
    "name": "nebular-v0.8.0-source-rebuild-inputs.json",
    "bytes": 15658,
    "sha256": "73741d6d5b369ac5d2bca52080cb5800df8620284447fc7a7281ca8790a8e091",
}

CURRENT080_NATIVE_PROVENANCE = {
    "github_asset_id": 722499032,
    "name": "nebular-v0.8.0-native-ci-provenance.json",
    "bytes": 14439,
    "sha256": "736defe9853e0a9aaaae3e5dfe54d46fa562cac233b73b0053ddbc7ae4ebef5a",
    "schema": "nebular.public-native-ci-release-provenance.v1",
    "source_candidate_identity": "da260bbedebf23c99bf6ca75055a60f263ce2096a65df5113e6159b65500dfee",
    "source_ci_run": 42418673471,
    "native_ci_run": 42418673472,
    "native_index_sha256": "a20866338376073f05fc8de2fa2de223c2a679903429f993c061313a05a32b39",
}

# The complete public release asset inventory is retained so tuple selection
# can be audited against all 18 GitHub rows rather than only the three raw
# archives used by the package lanes.
CURRENT080_GITHUB_ASSETS = (
    {"github_asset_id": 722265755, "name": "knowledge-forge-ai-theme-forge-nebular-fusion-0.8.0.tgz", "bytes": 22813, "sha256": "41792773942cc9b039ce8b26114152396c950e43a897a14bc778a3be07d2d81f"},
    {"github_asset_id": 722264634, "name": "knowledge-forge-ai-theme-forge-nebular-fusion-darwin-arm64-0.8.0.tgz", "bytes": 49765857, "sha256": "de475f7571c0f6b37e7bf9f1b96d3f3f67db08eb4df3c8640a5236d2305cd659"},
    {"github_asset_id": 722264639, "name": "knowledge-forge-ai-theme-forge-nebular-fusion-linux-arm64-0.8.0.tgz", "bytes": 56975011, "sha256": "a254369453facc0cbaa32a3d8ed0230bfc7eee29549854e9bc94d6bcdf2f47a7"},
    {"github_asset_id": 722264635, "name": "knowledge-forge-ai-theme-forge-nebular-fusion-linux-x64-0.8.0.tgz", "bytes": 56762984, "sha256": "27fac4293d90e0198797aaa0627d254ffb9aa35a18de91b92ee1c4c1ab79c53d"},
    {"github_asset_id": 722429154, "name": "nebular-compiled-public-build-source-authority-v0.8.0.json", "bytes": 1767, "sha256": "53dea0e5ca138616a94d351e2490f94aa34de74d2665fd62119034ca1fb58dcf"},
    {"github_asset_id": 722333765, "name": "nebular-v0.8.0-legal-assets-manifest.json", "bytes": 5050, "sha256": "d3b01883ae40433af201830afbf65d15dc2525fe0458ee91f30fd0a7af4e1b79"},
    {"github_asset_id": 722499032, "name": "nebular-v0.8.0-native-ci-provenance.json", "bytes": 14439, "sha256": "736defe9853e0a9aaaae3e5dfe54d46fa562cac233b73b0053ddbc7ae4ebef5a"},
    {"github_asset_id": 722333761, "name": "nebular-v0.8.0-sbom-inputs.tar.gz", "bytes": 126834, "sha256": "bf262a8b1009b8497a7fbc82c8e9d77aa9f5cca17c5106bbdc2efa1a78100049"},
    {"github_asset_id": 722333764, "name": "nebular-v0.8.0-sbom.spdx.json", "bytes": 63796, "sha256": "26da7f1f69f8823e807290d3f8dab2a8b2e97e158f1503efee0222ef21feb103"},
    {"github_asset_id": 722469273, "name": "nebular-v0.8.0-source-manifest.json", "bytes": 951107, "sha256": "8898ee256dcf60bb0793d23eb70e3c15bc1e623b9bea40a1785ec25d6c4ecb8d"},
    {"github_asset_id": 722469271, "name": "nebular-v0.8.0-source-rebuild-inputs.json", "bytes": 15658, "sha256": "73741d6d5b369ac5d2bca52080cb5800df8620284447fc7a7281ca8790a8e091"},
    {"github_asset_id": 722333763, "name": "nebular-v0.8.0-third-party-notices.tar.gz", "bytes": 687484, "sha256": "bf4c26e9527ea58f08b3064cb42608d3ed3533c9d4449790fdff2627fbbf8f60"},
    {"github_asset_id": 722499035, "name": "SHA256SUMS", "bytes": 1972, "sha256": "52901ccad88c2a003ea1f9413062ffe314ed03f8410abe77a30f09e6a85a643f"},
    {"github_asset_id": 722469272, "name": "SOURCE-REBUILD.md", "bytes": 7716, "sha256": "eeedba349181e11bb4d45296ad6bc4c1cf1f9cf551cd25955983574133c1746a"},
    {"github_asset_id": 722264631, "name": "theme-forge-nebular-fusion-v0.8.0-aarch64-apple-darwin.app.tar.gz", "bytes": 49769994, "sha256": "0a7ab188afc4660f68bd6dabfda96309a348108a8d77a4786df1731cddaf6896"},
    {"github_asset_id": 722265731, "name": "theme-forge-nebular-fusion-v0.8.0-aarch64-unknown-linux-gnu.tar.gz", "bytes": 57038323, "sha256": "4bbc40f180d954e1ca496606da9b63d7ce0f49dd29e802893aabc4aa0e859e94"},
    {"github_asset_id": 722429152, "name": "theme-forge-nebular-fusion-v0.8.0-source.tar.gz", "bytes": 6725884, "sha256": "9eb30214158d1bfaf2d7d4c2b5311ed43e02a26e455239b1873abb11353c63b6"},
    {"github_asset_id": 722264633, "name": "theme-forge-nebular-fusion-v0.8.0-x86_64-unknown-linux-gnu.tar.gz", "bytes": 56825312, "sha256": "498f0f6ff81c32200843e04016f86f7733905df0b0712c3f3639162ad5655abc"},
)

CURRENT080_RAW_ASSETS = {
    "darwin-arm64": {
        "github_asset_id": 722264631,
        "name": "theme-forge-nebular-fusion-v0.8.0-aarch64-apple-darwin.app.tar.gz",
        "bytes": 49769994,
        "sha256": "0a7ab188afc4660f68bd6dabfda96309a348108a8d77a4786df1731cddaf6896",
        "executable_sha256": "dabf051f09fbe1ca2cf5ec5fd9e2f4d9972fba868d061e1286a79ac1d7eaabfb",
        "package_manifest_sha256": "2004bbac8b7f879000233497c95f5079a7f5a71b0d3d9f17b15152947a59ca95",
        "sidecar_manifest_sha256": "f18840e8a2f2adfa96efdb32a5003208858063b24552538d08e5f108976999d7",
        "members": 1689,
        "native_payload_identity": "f595ad5ddb8cbc14c75232f6d62bf21b70237f1d759fb868f94c07d0d8300933",
        "build_receipt_sha256": "704f265694899f8d52778f4f873fb89eee7460442902c310c593f9f8abf30590",
    },
    "linux-arm64": {
        "github_asset_id": 722265731,
        "name": "theme-forge-nebular-fusion-v0.8.0-aarch64-unknown-linux-gnu.tar.gz",
        "bytes": 57038323,
        "sha256": "4bbc40f180d954e1ca496606da9b63d7ce0f49dd29e802893aabc4aa0e859e94",
        "executable_sha256": "65cbd19123ace49cd45de5b812506ed6c085350105ea6eaffff2b6191091a1fc",
        "package_manifest_sha256": "aaaf6f47d9a2aec517ff721f1eccb598804596185aec76ab6b607c37037bbeab",
        "sidecar_manifest_sha256": "8b275de7becbcd47886ebdfb1e156a64b3a5991cf181b34b8ce126af44df0eb4",
        "members": 1785,
        "native_payload_identity": "9282510839f55142ae5f41030413707f6926be14f79aa31dc3f6541a36fc070f",
        "build_receipt_sha256": "58c0c3d46bc71f57dc3df20d4c56a116b9ea3063f2084a8e3f32e9d855471faf",
    },
    "linux-x64": {
        "github_asset_id": 722264633,
        "name": "theme-forge-nebular-fusion-v0.8.0-x86_64-unknown-linux-gnu.tar.gz",
        "bytes": 56825312,
        "sha256": "498f0f6ff81c32200843e04016f86f7733905df0b0712c3f3639162ad5655abc",
        "executable_sha256": "61773740d5a165ccbf287ba8eaa175470d7288d23bd6c332e209e6cc07a7d8b1",
        "package_manifest_sha256": "fb2b250b354949fd704e0901bde79ff60ec66b92577a08d1b299945f02fef19d",
        "sidecar_manifest_sha256": "5caf3591b05181a5c605e6d9929ed6660e2ca073359eeae8d42fc7a1c6253160",
        "members": 1785,
        "native_payload_identity": "b8b740609b13f310fc79240d2413f3e150253acc70603f7168319ea8dee3d1ea",
        "build_receipt_sha256": "6307c2a72ca5da52d326b23a2a91fbdde6a8117335eb2e588a8f80aa5492a31a",
    },
}

CURRENT080_ASSET_SHA256S = frozenset(row["sha256"] for row in CURRENT080_RAW_ASSETS.values())

CURRENT080_NATIVE_BUILD_BINDINGS = (
    {
        "platform": "darwin-arm64",
        "source_commit": CURRENT080_COMMIT,
        "source_tree": CURRENT080_TREE,
        "executable_sha256": CURRENT080_RAW_ASSETS["darwin-arm64"]["executable_sha256"],
        "embedded_node_executable_sha256": "2cc28a1880d0774616959f2210ee739bffa6ac695c887e8988a496a21271f6c0",
        "embedded_node_version": "22.23.4",
        "toolchain_versions": {"cargo": "1.98.0", "node": "22.23.4", "npm": "10.9.9", "rustc": "1.98.0"},
        "build_receipt_sha256": CURRENT080_RAW_ASSETS["darwin-arm64"]["build_receipt_sha256"],
    },
    {
        "platform": "linux-arm64",
        "source_commit": CURRENT080_COMMIT,
        "source_tree": CURRENT080_TREE,
        "executable_sha256": CURRENT080_RAW_ASSETS["linux-arm64"]["executable_sha256"],
        "embedded_node_executable_sha256": "7e48183361053f039294fbbc3ba586722fe756bf296d6cb8195356d10819cd16",
        "embedded_node_version": "22.23.4",
        "toolchain_versions": {"cargo": "1.98.0", "node": "22.23.4", "npm": "10.9.9", "rustc": "1.98.0"},
        "build_receipt_sha256": CURRENT080_RAW_ASSETS["linux-arm64"]["build_receipt_sha256"],
    },
    {
        "platform": "linux-x64",
        "source_commit": CURRENT080_COMMIT,
        "source_tree": CURRENT080_TREE,
        "executable_sha256": CURRENT080_RAW_ASSETS["linux-x64"]["executable_sha256"],
        "embedded_node_executable_sha256": "94efd062ed066c1a0b332e18249859c905e920eeada5df55d24c99b919629a90",
        "embedded_node_version": "22.23.4",
        "toolchain_versions": {"cargo": "1.98.0", "node": "22.23.4", "npm": "10.9.9", "rustc": "1.98.0"},
        "build_receipt_sha256": CURRENT080_RAW_ASSETS["linux-x64"]["build_receipt_sha256"],
    },
)

# The current verifier import closure is a static source contract.  Every row
# is taken from the accepted v0.8.0 source-manifest readback; no 0.7.1 row is
# forward-reused and no checkout is consulted at runtime.
CURRENT080_VERIFIER_FILES = {
    "package.json": {"blob": "1001d40761261042da55c19e02874deb0c0002b5", "sha256": "64df6f25e3fee6d56d31afdeefa6da1fdb4ebdf7d79033195caecb6fb2ed6be9", "size": 1833},
    "tools/build-inputs.mjs": {"blob": "2415e54e5f06cbb3b4a19cb713037238a07d5895", "sha256": "cdb80c1a9742a8632a5eb9284d970669714340daf809c0368095658e38c65154", "size": 16400},
    "tools/build-settings.mjs": {"blob": "87b69b40534ef60f1895bdd866ce7e74fa581dae", "sha256": "f7578fccf935e14aee190a2de4378a986a182b038e41b261f3f9355e33449cd0", "size": 24182},
    "tools/candidate-provenance.mjs": {"blob": "129b0da16329d07697daab619f8fdbc5690f72fa", "sha256": "20244b6765d6e7d0ee5fd86452096a4546f189103b0acb9f065c4a1479c23155", "size": 15484},
    "tools/darwin-linkage-validator.mjs": {"blob": "3ca8ede088162f10d922b9cbec1d091daa052c33", "sha256": "67073d25aa00bc6c8086e8d10a2bd7302cc46c6416894bcba553880edf83f0f9", "size": 7678},
    "tools/fs-snapshot.mjs": {"blob": "841cfecd874517d0c619cf9a3866c2697e12ecd6", "sha256": "30ad6c3f0394126a7d3e5534507fe46c78c34946edd15bd5c91b36e2b36df351", "size": 13794},
    "tools/native-launcher.mjs": {"blob": "9c84fff880957edcb98925bbaea941fc0f7e66fe", "sha256": "3595cfaf0a2f1ac51a48862dc5f6aa842db6d3431a62159bcb93cb0abc812f2d", "size": 7193},
    "tools/native-rc-package.mjs": {"blob": "570d4d2b6cee8551bb0d77417e54ee4a0d308ca8", "sha256": "0ef948c2f9f45a9343586288681ae5ed6f6527b85912a52bd8c37aa50e3682c6", "size": 33102},
    "tools/native-rc-smoke.mjs": {"blob": "4adeae77bb147cf7969054695a8af6dfeb335736", "sha256": "ee2a26e00522f27d49550d3931cdd25e0f9956a0786d487f9af89755cf8bff39", "size": 65040},
    "tools/native-runtime.mjs": {"blob": "333192471147289f232bd915c6813ae23b39f1bb", "sha256": "a9d6c8e885b9db41877c5d2d79efe48f2e47daf791e0f1ad1ca06636d37d962e", "size": 118749},
    "tools/node-runtime-authority.mjs": {"blob": "dfb5fb377c66463ec54ba81c87d1424857548436", "sha256": "5495e291131a963c3e9bc9730aacb108d770954ce88f397e0f4a3c9ce768635e", "size": 37973},
    "tools/platform-targets.mjs": {"blob": "ebe518bbf27856c496541bca46bf13066805a606", "sha256": "35321c7e888038210589612873136c96bf697789f6f4e90918442faa41e13aec", "size": 7292},
    "tools/sidecar-common.mjs": {"blob": "a79812c8b47bb9a0a34c341261c49f7c1060d12e", "sha256": "e0ca4d4a4bba4abd756f1399e31a768a20873eefb6c50ac26a75adddccc1978c", "size": 81902},
    "tools/sidecar-verify.mjs": {"blob": "a456da327097d26bec9a41fdfaf288af57f38657", "sha256": "fba7f292b3c01ed062f4727e0c22912bc269b6ca76fca8328fb5329c098aac77", "size": 1906},
    "tools/appearance-matrix-prep1/generate.mjs": {"blob": "34f4072cf61c7f7d49b4120684f7f5379bf60b0c", "sha256": "2472f6ede72c17152d51410146d126251a26821815111b6c1b214308484ad67d", "size": 17120},
}

CURRENT080_VERIFIER_IMPORTS = {
    "tools/build-inputs.mjs": ["tools/build-settings.mjs", "tools/candidate-provenance.mjs", "tools/platform-targets.mjs"],
    "tools/build-settings.mjs": ["tools/candidate-provenance.mjs", "tools/fs-snapshot.mjs"],
    "tools/candidate-provenance.mjs": ["tools/platform-targets.mjs"],
    "tools/darwin-linkage-validator.mjs": [],
    "tools/fs-snapshot.mjs": [],
    "tools/native-launcher.mjs": ["tools/platform-targets.mjs"],
    "tools/native-rc-package.mjs": ["tools/fs-snapshot.mjs", "tools/native-launcher.mjs", "tools/native-runtime.mjs", "tools/platform-targets.mjs"],
    "tools/native-rc-smoke.mjs": ["tools/appearance-matrix-prep1/generate.mjs", "tools/fs-snapshot.mjs", "tools/native-launcher.mjs", "tools/native-rc-package.mjs", "tools/native-runtime.mjs"],
    "tools/native-runtime.mjs": ["tools/candidate-provenance.mjs"],
    "tools/node-runtime-authority.mjs": ["tools/darwin-linkage-validator.mjs"],
    "tools/platform-targets.mjs": [],
    "tools/sidecar-common.mjs": ["tools/build-inputs.mjs", "tools/candidate-provenance.mjs", "tools/darwin-linkage-validator.mjs", "tools/node-runtime-authority.mjs", "tools/platform-targets.mjs"],
    "tools/sidecar-verify.mjs": ["tools/build-inputs.mjs", "tools/platform-targets.mjs", "tools/sidecar-common.mjs"],
    "tools/appearance-matrix-prep1/generate.mjs": [],
}

# The optional RS9 replay/initial-observation path retains the complete
# authenticated 15-file source inventory: fourteen tools modules plus
# package.json as the separately pinned support member.  Execution is a
# separate fixed eight-module entry closure proven from native-rc-smoke.mjs;
# the six remaining authenticated source members are inventory-only for this
# entry point.  Relative names are rooted at the released tools directory,
# matching replay_progress_wrapper.mjs.
_CURRENT080_REPLAY_MODULES = tuple(
    sorted(path.removeprefix("tools/") for path in CURRENT080_VERIFIER_FILES if path != "package.json")
)
_CURRENT080_EXECUTION_MODULES = (
    "appearance-matrix-prep1/generate.mjs",
    "candidate-provenance.mjs",
    "fs-snapshot.mjs",
    "native-launcher.mjs",
    "native-rc-package.mjs",
    "native-rc-smoke.mjs",
    "native-runtime.mjs",
    "platform-targets.mjs",
)
CURRENT080_REPLAY_PROGRESS_PROFILE = {
    "id": "nebular080",
    "commit": CURRENT080_COMMIT,
    "tree": CURRENT080_TREE,
    "modules": {
        name: CURRENT080_VERIFIER_FILES["tools/" + name]
        for name in _CURRENT080_REPLAY_MODULES
    },
    "execution_modules": {
        name: CURRENT080_VERIFIER_FILES["tools/" + name]
        for name in _CURRENT080_EXECUTION_MODULES
    },
    "support": CURRENT080_VERIFIER_FILES["package.json"],
}
