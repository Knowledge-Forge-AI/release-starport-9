"""Run released Nebular verifiers against the actual installed runtime tree."""
import hashlib
import json
from pathlib import Path
import subprocess

from rs9.errors import ContractError
from rs9.hosted_commands import runtime_environment
from rs9.release_core import authenticated_tree, authenticated_record_hash, digest
from rs9.scratch import canonical
from rs9.security import validate_safe_relative_posix_path


def tagged_files(capture, client, output, prefixes):
    """Supplement a fresh capture with bounded blobs authenticated by its Git tree."""
    authenticated_record_hash(capture)
    records, total = [], 0
    for entry in authenticated_tree(capture)["tree"]:
        name = entry["path"]
        if entry.get("type") != "blob" or not any(name.startswith(p) for p in prefixes):
            continue
        validate_safe_relative_posix_path(name)
        if entry.get("mode") not in ("100644", "100755") or entry.get("size", 0) > 2 * 1024 ** 2:
            raise ContractError("SMOKE_SOURCE", "Bounded regular tagged source required")
        data = client.get("https://raw.githubusercontent.com/" + capture.record["repository"]["full_name"]
                          + "/" + capture.record["tag"]["commit"] + "/" + name, limit=2 * 1024 ** 2)
        total += len(data)
        blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        if blob != entry["sha"] or total > 32 * 1024 ** 2 or len(records) >= 1000:
            raise ContractError("SMOKE_SOURCE", "Tagged source identity or bounds failed")
        target = output / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        records.append({"path": name, "blob": blob, "sha256": digest(data), "size": len(data)})
    return records


def prepare_smoke(capture, captures, client, scratch):
    scratch.mkdir(parents=True, exist_ok=True)
    source = scratch / "source"
    source.mkdir()
    records = tagged_files(capture, client, source, ("tools/", "apps/studio/tools/"))
    tools = source / "tools"
    if not (tools / "native-rc-smoke.mjs").is_file():
        tools = source / "apps/studio/tools"
    if not all((tools / p).is_file() for p in ("native-rc-smoke.mjs", "sidecar-common.mjs")):
        raise ContractError("SMOKE_SOURCE", "Released application-aware harness is unavailable")
    fixture = next(c for c, intent, _ in captures if intent["project"]["id"] == "theme-forge-stellar-burst")
    records += tagged_files(fixture, client, source, ("docs/examples/v0.4/brand-system/core-minimal/",))
    if not (source / "docs/examples/v0.4/brand-system/core-minimal").is_dir():
        raise ContractError("SMOKE_FIXTURE", "Authenticated released fixture required")
    (scratch / "source-bindings.json").write_bytes(canonical(records))
    return {"source": source, "tools": tools, "records": records, "scratch": scratch}


def verify_nebular_runtime(runtime_root, prepared, system, prefix=(), env=None, discovered=None):
    """No extraction here: runtime_root is the wheel cache, Nix cache, or installed package."""
    env = runtime_environment(env)
    root = Path(runtime_root)
    darwin = system == "aarch64-darwin"
    if darwin:
        launch_root = root.parent
        sidecar = root / "Contents/MacOS/tfsb-studio-service"
        payload = root / "Contents/Resources/sidecar-payload"
    else:
        launch_root = root
        sidecar = root / "bin/tfsb-studio-service"
        payload = root / "lib/sidecar-payload"
    # Resolve the release's payload representation by its canonical manifest, not guessed flags.
    manifests = [Path(p) for p in discovered["manifests"]] if discovered else list(root.rglob("sidecar-payload/manifest.json"))
    binaries = [Path(p) for p in discovered["binaries"]] if discovered else [p for p in root.rglob("tfsb-studio-service*") if p.is_file() and p.parent.name in ("bin", "MacOS")]
    if len(manifests) != 1 or len(binaries) != 1:
        raise ContractError("SIDECAR_REPRESENTATION", "One released sidecar and payload required")
    sidecar, payload = binaries[0], manifests[0].parent
    script = prepared["scratch"] / "verify-runtime.mjs"
    script.write_text("import { verifyDistribution } from " + json.dumps((prepared["tools"] / "sidecar-common.mjs").as_uri())
                      + ";\nconsole.log(JSON.stringify(await verifyDistribution({binaryPath:process.argv[2],payloadRoot:process.argv[3]})));\n")
    result = subprocess.run([*prefix, "node", str(script), str(sidecar), str(payload)],
                            env=env, capture_output=True, timeout=180)
    if result.returncode:
        raise ContractError("SIDECAR_VERIFIER", "Released sidecar verifier rejected actual runtime representation")
    verification = json.loads(result.stdout)
    platform = "darwin-arm64" if darwin else "linux-arm64" if system == "aarch64-linux" else "linux-x64"
    scenarios = ["A"] if darwin else ["B"] if platform == "linux-arm64" else ["C", "C-signal"]
    evidence = prepared["scratch"] / "evidence"
    evidence.mkdir(exist_ok=True)
    evidence.chmod(0o777)
    runs = []
    for scenario in scenarios:
        command = ["node", str(prepared["tools"] / "native-rc-smoke.mjs"), "--platform", platform,
                   "--scenario", scenario, "--launch-root", str(launch_root), "--checkout", str(prepared["source"]),
                   "--evidence", str(evidence), "--label", platform + "-" + scenario]
        if not darwin:
            command = ["xvfb-run", "-a", "dbus-run-session", "--", *command]
        result = subprocess.run([*prefix, *command], env=env, capture_output=True, timeout=240)
        path = evidence / (platform + "-" + scenario + ".run.json")
        if result.returncode or not path.is_file():
            raise ContractError("APPLICATION_SMOKE", "Released application-aware smoke failed")
        record = json.loads(path.read_bytes())
        if record.get("status") != "pass" or record.get("problems"):
            raise ContractError("APPLICATION_SMOKE", "Released smoke receipt failed")
        runs.append({"scenario": scenario, "receipt_sha256": digest(path.read_bytes()),
                     "executable_sha256": record["executable"]["sha256"]})
    # Raw harness logs can contain ephemeral paths. Keep only bounded public identities.
    return {"sidecar": {"verifier_stdout_sha256": digest(canonical(verification)), "verified": True},
            "scenarios": runs, "source_bindings": prepared["records"]}
