"""Explicit platform policy shared by the offline backend and qualification tools."""
import platform

from rs9.tf_pypi_archive import fail


KEYS = {("Darwin", "arm64"): "darwin-arm64", ("Darwin", "x86_64"): "darwin-x64",
        ("Linux", "aarch64"): "linux-arm64-gnu", ("Linux", "arm64"): "linux-arm64-gnu",
        ("Linux", "x86_64"): "linux-x64-gnu"}
PURE_TAGS = {
    "darwin-arm64": "macosx_11_0_arm64",
    "darwin-x64": "macosx_11_0_x86_64",
    "linux-arm64-gnu": "manylinux_2_28_aarch64",
    "linux-x64-gnu": "manylinux_2_28_x86_64",
}
EXPECTED_TAGS = {
    "theme-forge-stellar-burst": {
        "darwin-arm64": "macosx_13_0_arm64",
        "linux-arm64-gnu": "manylinux_2_33_aarch64",
        "linux-x64-gnu": "manylinux_2_33_x86_64",
    },
    "theme-forge-stellar-loom": {
        "darwin-arm64": "macosx_11_0_arm64",
        "linux-arm64-gnu": "manylinux_2_28_aarch64",
        "linux-x64-gnu": "manylinux_2_28_x86_64",
    },
    "theme-forge-solar-sail": {
        "darwin-arm64": "macosx_11_0_arm64",
        "linux-arm64-gnu": "manylinux_2_28_aarch64",
        "linux-x64-gnu": "manylinux_2_28_x86_64",
    },
}


def host_key():
    key = KEYS.get((platform.system(), platform.machine().lower()))
    if not key or (key.startswith("linux") and platform.libc_ver()[0] != "glibc"):
        fail("UNSUPPORTED_PLATFORM")
    return key


def build_target(pin, target=None):
    """Explicit cross-target dist builds are distinct from host PEP 517 builds."""
    target = host_key() if target is None else target
    if target not in pin.get("candidate_platforms", []):
        fail("UNSUPPORTED_PLATFORM")
    return target


def pure_tag(key):
    if key not in PURE_TAGS:
        fail("UNSUPPORTED_PLATFORM")
    return PURE_TAGS[key]


def check_tag(pin, target, derived):
    expected = EXPECTED_TAGS.get(pin.get("project"), {}).get(target)
    if not expected or derived != expected:
        fail("PLATFORM_TAG")
    return derived
