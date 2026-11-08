"""Bound the Darwin process observer to an authenticated released harness."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from rs9.tf_pypi_archive import fail, physical_bytes, sha256


_PS_SNAPSHOT = r'''    const listing = spawnSync("ps", ["-axww", "-o", "pid=,command="], { encoding: "utf8" });
    for (const line of listing.stdout.split("\n")) {
      const match = /^\s*(\d+)\s+(.*)$/.exec(line);
      if (match && (match[2].startsWith(root + sep) || match[2].includes(` ${root}${sep}`))) found.push({ pid: Number(match[1]), exe: match[2] });
    }'''

_PGREP_SNAPSHOT = r'''    // Apple's -a retains ancestors; -f -l returns full arguments like ps.
    // Escape every POSIX ERE metacharacter in the authenticated candidate path.
    const escapeERE = (text) => Array.from(text, (ch) =>
      "\\.^$|?*+()[{".includes(ch) ? "\\" + ch : ch).join("");
    const witness = realpathSync(process.argv[1]);
    const pattern = "(^| )" + escapeERE(root + sep) + "|(^| )" + escapeERE(witness) + "( |$)";
    const listing = spawnSync("/usr/bin/pgrep", ["-a", "-f", "-l", "--", pattern],
      { encoding: "utf8", timeout: 2000, maxBuffer: 65536 });
    const invalid = () => { throw new Error("candidate process snapshot failed"); };
    if (listing.error || listing.status !== 0 ||
        typeof listing.stdout !== "string" || typeof listing.stderr !== "string" ||
        listing.stderr !== "" || !listing.stdout.endsWith("\n")) invalid();
    const lines = listing.stdout.slice(0, -1).split("\n");
    let witnessed = false;
    for (const line of lines) {
      const match = /^\s*(\d+)\s+(.*)$/.exec(line);
      if (!match || !Number.isSafeInteger(Number(match[1])) || Number(match[1]) <= 0 ||
          line.includes("\0")) invalid();
      if (Number(match[1]) === process.pid && (match[2] === witness ||
          match[2].startsWith(witness + " ") || match[2].includes(" " + witness + " ") ||
          match[2].endsWith(" " + witness))) witnessed = true;
      if (match[2].startsWith(root + sep) || match[2].includes(` ${root}${sep}`)) found.push({ pid: Number(match[1]), exe: match[2] });
    }
    if (!witnessed) invalid();'''


def validate_darwin_harness(value: Any) -> dict[str, Any]:
    """Validate the closed source/derived identity carrier, never a pass receipt."""
    if (not isinstance(value, Mapping) or set(value) != {
            "schema", "source_sha256", "derived_sha256", "transform", "process_tool"}
            or value.get("schema") != "rs9.nebular080-darwin-process-harness.v1"
            or value.get("transform") != "authenticated-darwin-pgrep-snapshot-v1"
            or value.get("process_tool") != "/usr/bin/pgrep"):
        fail("NEBULAR_DARWIN_HARNESS")
    for name in ("source_sha256", "derived_sha256"):
        digest = value.get(name)
        if (not isinstance(digest, str) or len(digest) != 64
                or any(ch not in "0123456789abcdef" for ch in digest)):
            fail("NEBULAR_DARWIN_HARNESS")
    if value.get("source_sha256") != "ee2a26e00522f27d49550d3931cdd25e0f9956a0786d487f9af89755cf8bff39":
        fail("NEBULAR_DARWIN_HARNESS")
    if value.get("derived_sha256") != "1e668b19dab99482665ce29f7cbd8596c9f29ae161c43158651f9d6eaa003f3f":
        fail("NEBULAR_DARWIN_HARNESS")
    return dict(value)


def require_release_darwin_harness(value: Any) -> dict[str, Any]:
    """Require a current authenticated 080 source-bound derivation."""
    return validate_darwin_harness(value)


def _derive_darwin_pgrep_source(raw: bytes) -> bytes:
    """Apply the fixed pgrep substitution to one already-authenticated script."""
    try:
        source = raw.decode("utf-8")
    except UnicodeDecodeError:
        fail("NEBULAR_DARWIN_HARNESS_SOURCE")
    if source.count(_PS_SNAPSHOT) != 1:
        fail("NEBULAR_DARWIN_HARNESS_SOURCE")
    return source.replace(_PS_SNAPSHOT, _PGREP_SNAPSHOT).encode("utf-8")


def prepare_darwin_harness(prepared: Mapping[str, Any]) -> tuple[Path, dict[str, Any]]:
    """Replace only the ps snapshot; retain fixture, orphan and receipt gates.

    Public Darwin CI establishes that setuid ps cannot spawn under the existing
    sandbox, while ordinary child execution works. The built-in non-setuid
    pgrep observes the same candidate argument boundaries without a policy
    exception. Any failed or incomplete snapshot remains a harness failure.
    """
    tools = Path(prepared["tools"])
    records = prepared.get("records")
    if not isinstance(records, list):
        fail("NEBULAR_SMOKE_CLOSURE")
    name = f"{prepared.get('tool_root', 'tools')}/native-rc-smoke.mjs"
    matches = [row for row in records if isinstance(row, Mapping) and row.get("path") == name]
    raw = physical_bytes(tools / "native-rc-smoke.mjs", limit=2 * 1024 * 1024)
    if len(matches) != 1 or sha256(raw) != matches[0].get("sha256"):
        fail("NEBULAR_SMOKE_CLOSURE")
    derived = _derive_darwin_pgrep_source(raw)
    output = tools / "native-rc-smoke-darwin.mjs"
    if output.exists() or output.is_symlink():
        fail("NEBULAR_DARWIN_HARNESS_OUTPUT")
    with output.open("xb") as stream:
        stream.write(derived)
    output.chmod(0o600)
    return output, validate_darwin_harness({
        "schema": "rs9.nebular080-darwin-process-harness.v1",
        "source_sha256": sha256(raw), "derived_sha256": sha256(derived),
        "transform": "authenticated-darwin-pgrep-snapshot-v1",
        "process_tool": "/usr/bin/pgrep",
    })


def validate_darwin_installed_harness(value: Any) -> dict[str, Any]:
    """Validate the chained Darwin pgrep + installed-entrypoint derivation."""
    keys = {
        "schema", "source_sha256", "derived_sha256", "entrypoint_sha256",
        "entrypoint_bytes", "cache_root_sha256", "process_source_sha256",
        "process_derived_sha256", "transform",
    }
    if (not isinstance(value, Mapping) or set(value) != keys
            or value.get("schema") != "rs9.nebular080-darwin-installed-launcher-harness.v1"
            or value.get("transform") != "authenticated-installed-entrypoint+darwin-pgrep-v1"):
        fail("NEBULAR_DARWIN_HARNESS")
    for name in (
        "source_sha256", "derived_sha256", "entrypoint_sha256", "cache_root_sha256",
        "process_source_sha256", "process_derived_sha256",
    ):
        digest = value.get(name)
        if (not isinstance(digest, str) or len(digest) != 64
                or any(ch not in "0123456789abcdef" for ch in digest)):
            fail("NEBULAR_DARWIN_HARNESS")
    if (type(value.get("entrypoint_bytes")) is not int
            or not 0 < value["entrypoint_bytes"] <= 1024 * 1024):
        fail("NEBULAR_DARWIN_HARNESS")
    validate_darwin_harness({
        "schema": "rs9.nebular080-darwin-process-harness.v1",
        "source_sha256": value["process_source_sha256"],
        "derived_sha256": value["process_derived_sha256"],
        "transform": "authenticated-darwin-pgrep-snapshot-v1",
        "process_tool": "/usr/bin/pgrep",
    })
    return dict(value)


def prepare_darwin_installed_harness(
    prepared: Mapping[str, Any], installed_command: Path, *, cache_root: Path,
) -> tuple[Path, dict[str, Any], dict[str, Any]]:
    """Compose the maintained launcher adapter with the Darwin pgrep adapter.

    ``prepare_installed_harness`` is the existing source/launcher adaptation
    mechanism used by the Linux system-WebKit lane.  Darwin reuses it first,
    then applies the already-authenticated pgrep substitution.  The ordinary
    Darwin harness identity is returned separately so its historical receipt
    contract remains intact; the chained identity records both transforms.
    """
    from rs9.nebular080_system_webkit import prepare_installed_harness

    _darwin_source, process_harness = prepare_darwin_harness(prepared)
    installed_source, installed_adapter = prepare_installed_harness(
        prepared, installed_command, cache_root=cache_root,
    )
    raw = physical_bytes(installed_source, limit=2 * 1024 * 1024)
    if sha256(raw) != installed_adapter.get("derived_sha256"):
        fail("NEBULAR_DARWIN_HARNESS")
    derived = _derive_darwin_pgrep_source(raw)
    output = Path(prepared["tools"]) / "native-rc-smoke-darwin-installed.mjs"
    if output.exists() or output.is_symlink():
        fail("NEBULAR_DARWIN_HARNESS_OUTPUT")
    with output.open("xb") as stream:
        stream.write(derived)
    output.chmod(0o600)
    return output, process_harness, validate_darwin_installed_harness({
        "schema": "rs9.nebular080-darwin-installed-launcher-harness.v1",
        "source_sha256": sha256(raw), "derived_sha256": sha256(derived),
        "entrypoint_sha256": installed_adapter["entrypoint_sha256"],
        "entrypoint_bytes": installed_adapter["entrypoint_bytes"],
        "cache_root_sha256": installed_adapter["cache_root_sha256"],
        "process_source_sha256": process_harness["source_sha256"],
        "process_derived_sha256": process_harness["derived_sha256"],
        "transform": "authenticated-installed-entrypoint+darwin-pgrep-v1",
    })
