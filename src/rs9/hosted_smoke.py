"""Run released Nebular verifiers against the actual installed runtime tree."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

from rs9.errors import ContractError, safe_details
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
                          + "/" + capture.record["tag"]["commit"] + "/" + name,
                          request_class="github-source", limit=2 * 1024 ** 2)
        total += len(data)
        blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        if blob != entry["sha"] or total > 32 * 1024 ** 2 or len(records) >= 1000:
            raise ContractError("SMOKE_SOURCE", "Tagged source identity or bounds failed")
        target = output / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        records.append({"path": name, "blob": blob, "sha256": digest(data), "size": len(data)})
    return records


def _safe_label(value):
    if not value or not isinstance(value, str):
        return None
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", value):
        return value
    return None


def prepare_smoke(capture, captures, client, scratch, label=None):
    scratch = Path(scratch)
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
    if label is None and scratch.name.startswith("smoke-"):
        label = scratch.name[len("smoke-"):]
    safe = _safe_label(label)
    result = {"source": source, "tools": tools, "records": records, "scratch": scratch, "capture": capture}
    if safe:
        result["label"] = safe
        result["family"] = safe
    return result


def _file_hash(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        hasher = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


KNOWN_FLAG_NAMES = frozenset({
    "UF_NODUMP", "UF_IMMUTABLE", "UF_APPEND", "UF_OPAQUE", "UF_HIDDEN",
    "UF_COMPRESSED", "UF_TRACKED", "UF_DATAVAULT",
    "SF_ARCHIVED", "SF_IMMUTABLE", "SF_APPEND", "SF_RESTRICTED", "SF_NOUNLINK",
})

KNOWN_XATTR_NAMES = frozenset({
    "com.apple.quarantine",
    "com.apple.FinderInfo",
    "com.apple.macl",
    "com.apple.provenance",
})


def _bound_path(path, max_len=120):
    if len(path) <= max_len:
        return path
    h = digest(path.encode("utf-8"))[:12]
    prefix_len = (max_len - 18) // 2
    suffix_len = max_len - 18 - prefix_len
    return f"{path[:prefix_len]}...[{h}]...{path[-suffix_len:]}"


def _inventory_runtime(root):
    root = Path(root)
    rows = []
    seen_flags = set()
    seen_xattrs = set()
    flags_count = 0
    xattrs_count = 0
    condition_samples = {"flags": [], "xattrs": []}
    members_map = {}
    for directory, dirs, files in os.walk(root, followlinks=False):
        for path in [Path(directory), *(Path(directory) / p for p in sorted(dirs + files))]:
            # Each physical directory is inventoried when visited, not twice.
            info = path.lstat()
            if path != Path(directory) and stat.S_ISDIR(info.st_mode):
                continue
            relative = path.relative_to(root.parent).as_posix()
            try:
                validate_safe_relative_posix_path(relative)
            except ContractError:
                relative = "unsafe-name-" + digest(relative.encode())
            kind = "file" if stat.S_ISREG(info.st_mode) else "directory" if stat.S_ISDIR(info.st_mode) else "symlink" if stat.S_ISLNK(info.st_mode) else "special"
            mode = stat.S_IMODE(info.st_mode)
            row = {"path": relative, "type": kind, "mode": mode}
            if kind == "file":
                row.update(size=info.st_size, sha256=_file_hash(path))
            elif kind == "symlink":
                row["target_sha256"] = digest(os.readlink(path).encode())
            rows.append(row)
            members_map[relative] = row

            st_flags = getattr(info, "st_flags", 0)
            if st_flags:
                flags_count += 1
                if len(condition_samples["flags"]) < 10:
                    condition_samples["flags"].append({"path": _bound_path(relative), "st_flags": st_flags})
                rem = st_flags
                for fname in sorted(KNOWN_FLAG_NAMES):
                    bit = getattr(stat, fname, 0)
                    if bit and (st_flags & bit):
                        seen_flags.add(fname)
                        rem &= ~bit
                if rem:
                    seen_flags.add("hash:" + digest(str(rem).encode("utf-8")))

            if hasattr(os, "listxattr"):
                try:
                    attrs = os.listxattr(path, follow_symlinks=False)
                    xattrs_count += len(attrs)
                    safe_names = sorted(a if a in KNOWN_XATTR_NAMES else "hash:" + digest(a.encode()) for a in attrs)
                    if attrs and len(condition_samples["xattrs"]) < 10:
                        condition_samples["xattrs"].append({"path": _bound_path(relative), "names": safe_names[:10]})
                    for attr in attrs:
                        if attr in KNOWN_XATTR_NAMES:
                            seen_xattrs.add(attr)
                        else:
                            seen_xattrs.add("hash:" + digest(attr.encode("utf-8")))
                except OSError:
                    pass
    rows.sort(key=lambda r: r["path"])
    return rows, flags_count, xattrs_count, sorted(seen_flags)[:20], sorted(seen_xattrs)[:20], members_map, condition_samples


def classify_diagnostic(identity, verifier=None, drift=None):
    """Classify diagnostic according to strict precedence rules:
    harness/import/execution -> causal drift -> manifest -> bytes -> file_mode -> dir_mode ->
    symlink -> ancestry -> flags/xattr -> non-causal drift -> verifier-rejected
    """
    # 1. harness/import/execution
    if verifier and verifier.get("status") != "pass":
        phase = verifier.get("phase")
        token = verifier.get("reason_token")
        code = verifier.get("code")
        if (phase in ("import", "execution", "unavailable", "unknown")
                or token in ("tool-timeout", "tool-unavailable")
                or code in ("ERR_MODULE_NOT_FOUND", "ENOENT", "EACCES", "ERR_UNKNOWN_FILE_EXTENSION")
                or (verifier.get("exit_code") not in (0, None) and phase != "verify")):
            return "harness/import/execution"

    counts = identity.get("mismatch_counts", {}) if identity else {}
    v_token = verifier.get("reason_token") if verifier else None
    verifier_failed = bool(verifier and verifier.get("status") != "pass")

    drift_counts = drift.get("drift_counts", {}) if drift else {}
    has_drift = bool(
        drift and (drift.get("has_drift") or any(v > 0 for v in drift_counts.values()))
    )
    drift_paths = {
        item["path"]
        for sample_list in drift.get("drift_samples", {}).values()
        for item in sample_list
        if isinstance(item, dict) and "path" in item
    } if drift else set()
    mismatch_paths = {
        item["path"]
        for k, sample_list in identity.get("mismatch_samples", {}).items()
        if k != "dir_mode"
        for item in sample_list
        if isinstance(item, dict) and "path" in item
    } if identity else set()

    mismatch_total = sum(counts.get(k, 0) for k in ("missing", "extra", "type", "bytes", "file_mode", "directory_mode", "symlink"))
    sampled_mismatch_total = sum(len(samples) for kind, samples in identity.get("mismatch_samples", {}).items()
                                if kind != "dir_mode") if identity else 0
    drift_total = sum(drift_counts.values())

    has_intersection = bool(drift_paths & mismatch_paths)
    has_unrelated_mismatch = (bool(mismatch_paths - drift_paths)
                              or mismatch_total > drift_total
                              or mismatch_total > sampled_mismatch_total
                              or any(value > 0 for value in drift.get("baseline_mismatch_counts", {}).values())) if drift else False
    manifest_tokens = {"manifest-not-canonical", "manifest-self-digest", "manifest-fixed-identity"}
    if v_token in manifest_tokens and not any("manifest" in p for p in drift_paths):
        has_unrelated_mismatch = True

    # Causal drift before manifest/bytes/modes/flags when drift explains failures/mismatches
    if has_drift and has_intersection and not has_unrelated_mismatch:
        return "post-probe-drift"

    # 2. manifest
    if (
        counts.get("missing", 0) > 0
        or counts.get("extra", 0) > 0
        or counts.get("type", 0) > 0
        or (identity.get("expected_member_count") is not None
            and identity.get("actual_member_count") != identity.get("expected_member_count"))
        or v_token in ("manifest-not-canonical", "manifest-self-digest", "manifest-fixed-identity",
                       "payload-inventory", "payload-totals", "actual-input-identity")
    ):
        return "manifest"

    # 3. bytes
    if counts.get("bytes", 0) > 0:
        return "bytes"

    # 4. file_mode
    if counts.get("file_mode", 0) > 0:
        return "file_mode"

    # 5. dir_mode
    if counts.get("directory_mode", 0) > 0 or counts.get("dir_mode", 0) > 0:
        return "dir_mode"

    # 6. symlink
    if counts.get("symlink", 0) > 0:
        return "symlink"

    # 7. ancestry
    ancestors = identity.get("ancestor_modes", []) if identity else []
    if v_token == "symlink-ancestor" or any(a.get("symlink") or a.get("ancestry_unsafe") for a in ancestors):
        return "ancestry"

    has_flags = bool(
        identity.get("nonzero_file_flags_count", 0) > 0
        or identity.get("extended_attribute_count", 0) > 0
        or identity.get("file_flags")
        or identity.get("extended_attributes")
    )

    # 8. flags/xattr
    if has_flags:
        return "flags/xattr"

    # 9. post-probe-drift
    if has_drift and not verifier_failed:
        return "post-probe-drift"

    # 10. dedicated verifier-rejected when verify failed no specific cause
    if verifier_failed:
        return "verifier-rejected"

    if verifier is None and any(counts.get(k, 0) > 0 for k in counts):
        return "unclassified"

    return None


def runtime_evidence(root, sidecar, manifest, expected_members=None, return_members=False):
    """Bounded identities and mismatch samples, without retaining runtime paths."""
    root = Path(root)
    rows, flags, xattrs, file_flags, ext_attrs, members_map, conditions = _inventory_runtime(root)
    expected, metadata = expected_members or [], {}
    entry = root.parent.parent
    if not expected and (entry / "manifest.json").is_file() and not (entry / "manifest.json").is_symlink():
        expected = json.loads((entry / "manifest.json").read_bytes())
    if (entry / "meta.json").is_file() and not (entry / "meta.json").is_symlink():
        metadata = json.loads((entry / "meta.json").read_bytes())
    actual = {r["path"]: r for r in rows}
    samples = {k: [] for k in ("missing", "extra", "bytes", "file_mode", "directory_mode", "dir_mode", "symlink", "type")}
    counts = {k: 0 for k in samples}
    def mismatch(kind, path, **extra):
        counts[kind] += 1
        if len(samples[kind]) < 10:
            item = {"path": _bound_path(path)}
            item.update(extra)
            samples[kind].append(item)
    expected_by_path = {r["path"]: r for r in expected}
    for name, row in expected_by_path.items():
        observed = actual.get(name)
        if observed is None:
            mismatch("missing", name)
        elif observed["type"] != row["type"]:
            mismatch("type", name)
        elif row["type"] == "file":
            if (observed["size"], observed["sha256"]) != (row["size"], row["sha256"]):
                mismatch("bytes", name, expected_size=row["size"], actual_size=observed["size"],
                         expected_sha256=row["sha256"], actual_sha256=observed["sha256"])
            if observed["mode"] != row["mode"]:
                mismatch("file_mode", name, expected_mode=row["mode"], actual_mode=observed["mode"],
                         expected=row["mode"], observed=observed["mode"])
        elif row["type"] == "directory" and observed["mode"] != row["mode"]:
            mismatch("directory_mode", name, expected_mode=row["mode"], actual_mode=observed["mode"],
                     expected=row["mode"], observed=observed["mode"])
        elif row["type"] == "symlink" and observed["target_sha256"] != digest(row["target"].encode()):
            mismatch("symlink", name)
    if expected:
        for name in sorted(actual.keys() - expected_by_path.keys()):
            mismatch("extra", name)
    counts["dir_mode"] = counts["directory_mode"]
    samples["dir_mode"] = samples["directory_mode"]

    ancestors = []
    my_uid = os.getuid() if hasattr(os, "getuid") else None
    for path in (root, *root.parents)[:32]:
        info = path.lstat()
        mode = stat.S_IMODE(info.st_mode)
        raw_mode = info.st_mode
        is_symlink = stat.S_ISLNK(raw_mode)
        is_sticky = bool(raw_mode & stat.S_ISVTX)
        uid = info.st_uid
        uid_is_self = (uid == my_uid) if my_uid is not None else True
        is_root_uid = (uid == 0)
        group_writable = bool(mode & 0o020)
        other_writable = bool(mode & 0o002)
        ancestry_unsafe = is_symlink or (other_writable and not is_sticky) or (not uid_is_self and not is_root_uid)
        ancestors.append({
            "symlink": is_symlink,
            "mode": mode,
            "uid_is_self": uid_is_self,
            "group_writable": group_writable,
            "other_writable": other_writable,
            "group_or_other_writable": group_writable or other_writable,
            "writable_by_group_or_other": group_writable or other_writable,
            "is_sticky": is_sticky,
            "is_root": is_root_uid,
            "ancestry_unsafe": ancestry_unsafe,
        })
    evidence = {"runtime_root_sha256": digest(canonical(rows)), "actual_member_count": len(rows),
                "expected_member_count": len(expected) if expected else None,
                "expected_manifest_sha256": metadata.get("manifest_sha256"),
                "materializer_source": "nix-store-tree" if metadata.get("source_is_store") else "compressed-release-archive" if metadata else "installed-package",
                "mismatch_counts": counts, "mismatch_samples": samples, "ancestor_modes": ancestors,
                "nonzero_file_flags_count": flags, "extended_attribute_count": xattrs,
                "condition_samples": conditions,
                "file_flags": file_flags, "extended_attributes": ext_attrs,
                "file_flag_names": file_flags, "extended_attribute_names": ext_attrs,
                "flag_names": file_flags, "xattr_names": ext_attrs,
                "sidecar_binary_sha256": _file_hash(sidecar), "sidecar_manifest_sha256": _file_hash(manifest)}
    evidence["classification"] = classify_diagnostic(evidence)
    if return_members:
        return evidence, members_map
    return evidence


def _verifier_script(module):
    # Error text is hashed; only released, fixed messages become public tokens.
    reasons = {"sidecar path has a symlinked ancestor": "symlink-ancestor",
               "manifest bytes are not canonical": "manifest-not-canonical",
               "manifest self-digest is invalid": "manifest-self-digest",
               "sidecar runtime is invalid": "runtime-identity",
               "sidecar payload inventory is invalid": "payload-inventory",
               "sidecar payload totals are invalid": "payload-totals",
               "sidecar actual input identity is invalid": "actual-input-identity",
               "manifest fixed identity is invalid": "manifest-fixed-identity"}
    return ("import {createHash} from 'node:crypto';\nlet phase='import';\ntry {\n"
            "const {verifyDistribution}=await import(" + json.dumps(module.as_uri()) + ");\n"
            "phase='verify'; const result=await verifyDistribution({binaryPath:process.argv[2],payloadRoot:process.argv[3]});\n"
            "phase='output'; console.log(JSON.stringify({status:'pass',result}));\n"
            "} catch(e) { const reasons=" + json.dumps(reasons) + ";\n"
            "console.log(JSON.stringify({status:'fail',phase,"
            "name:['Error','TypeError','SyntaxError','RangeError','ReferenceError'].includes(e.name)?e.name:'Error',"
            "code:['ERR_MODULE_NOT_FOUND','ENOENT','EACCES','ERR_UNKNOWN_FILE_EXTENSION'].includes(e.code)?e.code:null,"
            "message_sha256:createHash('sha256').update(String(e.message)).digest('hex'),"
            "reason_token:reasons[e.message]??'unclassified-released-verifier-error'})); process.exitCode=2; }\n")


def _run_verifier(script, sidecar, payload, prefix, env):
    try:
        result = subprocess.run([*prefix, "node", str(script), str(sidecar), str(payload)],
                                env=env, capture_output=True, timeout=180)
    except subprocess.TimeoutExpired as error:
        return {"status": "fail", "phase": "execution", "reason_token": "tool-timeout",
                "stdout_sha256": digest(error.stdout or b""), "stderr_sha256": digest(error.stderr or b"")}, None
    except OSError:
        return {"status": "fail", "phase": "execution", "reason_token": "tool-unavailable"}, None
    stdout, stderr = getattr(result, "stdout", b""), getattr(result, "stderr", b"")
    evidence = {"exit_code": result.returncode, "stdout_sha256": digest(stdout), "stderr_sha256": digest(stderr)}
    try:
        doc = json.loads(stdout)
    except (ValueError, UnicodeError):
        doc = {}
    if result.returncode == 0 and isinstance(doc, dict) and doc.get("status") == "pass" and isinstance(doc.get("result"), dict):
        return {**evidence, "status": "pass"}, doc["result"]
    phases = {"import", "verify", "output", "execution", "unavailable", "unknown"}
    raw_phase = doc.get("phase") if isinstance(doc, dict) and doc.get("phase") in phases else "unknown"
    evidence.update(status="fail", phase=raw_phase,
                    reason_token="unclassified-released-verifier-error")
    if isinstance(doc, dict):
        if doc.get("name") in {"Error", "TypeError", "SyntaxError", "RangeError", "ReferenceError"}:
            evidence["exception_type"] = doc["name"]
        if doc.get("code") in {"ERR_MODULE_NOT_FOUND", "ENOENT", "EACCES", "ERR_UNKNOWN_FILE_EXTENSION"}:
            evidence["code"] = doc["code"]
        if doc.get("reason_token") in {"symlink-ancestor", "manifest-not-canonical", "manifest-self-digest", "runtime-identity", "payload-inventory", "payload-totals", "actual-input-identity", "manifest-fixed-identity"}:
            evidence["reason_token"] = doc["reason_token"]
        from rs9.errors import safe_details
        checksum = safe_details({"stderr_sha256": doc.get("message_sha256")}).get("stderr_sha256")
        if checksum:
            evidence["message_sha256"] = checksum
    return evidence, None


def _control_verifier(capture, system, prepared, script, prefix, env, runtime_identity=None):
    """Independent raw archive control; its result never satisfies the runtime gate."""
    from rs9.materialize import materialize_payload
    candidates = [p for p in capture.record["payloads"] if system in p["platforms"]]
    if len(candidates) != 1:
        return {"status": "not-run", "reason": "control-asset-selection"}
    asset = candidates[0]
    archive, manifest = capture.archives[asset["id"]], capture.manifests[asset["id"]]
    if _file_hash(archive) != asset["sha256"]:
        return {"status": "fail", "reason": "control-archive-identity"}
    try:
        cache = prepared["scratch"] / "control-cache"
        root = materialize_payload(archive, cache, manifest,
                                   expected_manifest_sha256=asset["payload_manifest_sha256"])
        # Only cache administration ancestors change; released payload modes stay exact.
        for path in (cache, cache / "entries", root.parent.parent, root.parent):
            path.chmod(0o755)
        manifests = list(root.rglob("sidecar-payload/manifest.json"))
        binaries = [p for p in root.rglob("tfsb-studio-service*") if p.is_file() and p.parent.name in {"bin", "MacOS"}]
        if len(manifests) != 1 or len(binaries) != 1:
            return {"status": "fail", "reason": "control-sidecar-representation"}
        evidence, _ = _run_verifier(script, binaries[0], manifests[0].parent, prefix, env)
        expected_members = manifest.get("members") if isinstance(manifest, dict) else manifest if isinstance(manifest, list) else None
        control_identity = runtime_evidence(root, binaries[0], manifests[0], expected_members=expected_members)
        comparison = {
            "mismatch_count_deltas": {k: control_identity["mismatch_counts"].get(k, 0) - runtime_identity.get("mismatch_counts", {}).get(k, 0)
                                      for k in control_identity["mismatch_counts"]} if runtime_identity else None,
            "counts_equal": bool(runtime_identity and control_identity["actual_member_count"] == runtime_identity.get("actual_member_count")),
            "hash_equal": bool(runtime_identity and control_identity["runtime_root_sha256"] == runtime_identity.get("runtime_root_sha256")),
            "actual_member_counts": {
                "control": control_identity["actual_member_count"],
                "runtime": runtime_identity.get("actual_member_count") if runtime_identity else None,
            },
            "runtime_root_sha256": {
                "control": control_identity["runtime_root_sha256"],
                "runtime": runtime_identity.get("runtime_root_sha256") if runtime_identity else None,
            },
        }
        return {
            **evidence,
            "archive_sha256": asset["sha256"],
            "manifest_sha256": asset["payload_manifest_sha256"],
            "runtime_identity": control_identity,
            "comparison_to_runtime": comparison,
            "satisfies_installed_gate": False,
        }
    except (ContractError, OSError) as error:
        return {"status": "fail", "reason": error.code if isinstance(error, ContractError) else "control-io"}


def compare_drift(baseline, root, current_identity, current_members=None):
    """Compare post-probe runtime against captured baseline."""
    if not baseline:
        return None
    baseline_root_sha256 = baseline.get("runtime_root_sha256")
    baseline_member_count = baseline.get("actual_member_count")
    current_root_sha256 = current_identity.get("runtime_root_sha256")
    current_member_count = current_identity.get("actual_member_count")

    baseline_members = baseline.get("members")
    drift_counts = {"modified": 0, "added": 0, "removed": 0, "mode": 0}
    drift_samples = {"modified": [], "added": [], "removed": [], "mode": []}

    def record_drift(kind, path, **extra):
        drift_counts[kind] += 1
        if len(drift_samples[kind]) < 10:
            item = {"path": _bound_path(path)}
            item.update(extra)
            drift_samples[kind].append(item)

    if baseline_members is not None:
        if current_members is None:
            _, _, _, _, _, current_members, _ = _inventory_runtime(root)

        for path, b_row in baseline_members.items():
            c_row = current_members.get(path)
            if c_row is None:
                record_drift("removed", path)
            else:
                if b_row["type"] != c_row["type"]:
                    record_drift("modified", path, reason="type_changed")
                elif b_row["type"] == "file":
                    if (b_row.get("size"), b_row.get("sha256")) != (c_row.get("size"), c_row.get("sha256")):
                        record_drift("modified", path)
                    if b_row["mode"] != c_row["mode"]:
                        record_drift("mode", path, expected_mode=b_row["mode"], actual_mode=c_row["mode"],
                                     baseline_mode=b_row["mode"], current_mode=c_row["mode"])
                elif b_row["type"] == "directory":
                    if b_row["mode"] != c_row["mode"]:
                        record_drift("mode", path, expected_mode=b_row["mode"], actual_mode=c_row["mode"],
                                     baseline_mode=b_row["mode"], current_mode=c_row["mode"])
                elif b_row["type"] == "symlink":
                    if b_row.get("target_sha256") != c_row.get("target_sha256"):
                        record_drift("modified", path)

        for path in sorted(current_members.keys() - baseline_members.keys()):
            record_drift("added", path)

    has_drift = (
        baseline_root_sha256 != current_root_sha256
        or any(v > 0 for v in drift_counts.values())
        or baseline_member_count != current_member_count
    )

    return {
        "has_drift": has_drift,
        "baseline_runtime_root_sha256": baseline_root_sha256,
        "current_runtime_root_sha256": current_root_sha256,
        "baseline_member_count": baseline_member_count,
        "current_member_count": current_member_count,
        "baseline_mismatch_counts": baseline.get("evidence", {}).get("mismatch_counts", {}),
        "drift_counts": drift_counts,
        "drift_samples": drift_samples,
    }


def snapshot_nebular_runtime(runtime_root, prepared, system, discovered=None):
    """Snapshot Nebular baseline after first launcher materialization and before remaining command probes."""
    root = Path(runtime_root)
    manifests = [Path(p) for p in discovered["manifests"]] if discovered else list(root.rglob("sidecar-payload/manifest.json"))
    binaries = [Path(p) for p in discovered["binaries"]] if discovered else [p for p in root.rglob("tfsb-studio-service*") if p.is_file() and p.parent.name in ("bin", "MacOS")]
    if len(manifests) != 1 or len(binaries) != 1:
        raise ContractError("SIDECAR_REPRESENTATION", "One released sidecar and payload required")
    sidecar = binaries[0]
    capture = prepared.get("capture") if prepared else None
    expected = None
    if capture:
        candidates = [p for p in capture.record["payloads"] if system in p["platforms"]]
        if len(candidates) == 1:
            expected = capture.manifests[candidates[0]["id"]]["members"]
    identity, members_map = runtime_evidence(root, sidecar, manifests[0], expected, return_members=True)
    return {
        "schema": "rs9.nebular-runtime-baseline.v1alpha1",
        "system": system,
        "runtime_root_sha256": identity["runtime_root_sha256"],
        "actual_member_count": identity["actual_member_count"],
        "sidecar_binary_sha256": identity.get("sidecar_binary_sha256"),
        "sidecar_manifest_sha256": identity.get("sidecar_manifest_sha256"),
        "evidence": identity,
        "members": members_map,
    }


def bound_diagnostic(diagnostic, max_bytes=60 * 1024):
    """Bound every nested sample, including the archive control, then enforce a hard cap."""
    def project(value, sample_limit=10, depth=0):
        if depth > 12:
            return {"omitted": True}
        if isinstance(value, dict):
            return {k: project(v, sample_limit, depth + 1) for k, v in list(value.items())[:64]}
        if isinstance(value, list):
            return [project(v, sample_limit, depth + 1) for v in value[:sample_limit]]
        if isinstance(value, str) and len(value) > 256:
            return "sha256:" + digest(value.encode())
        return value
    for limit in (10, 3, 1, 0):
        result = project(diagnostic, limit)
        if result != diagnostic:
            result["diagnostic_truncated"] = True
        if len(canonical(result)) <= max_bytes:
            return result
    result = {"schema": "rs9.sidecar-verifier-diagnostic.v1alpha1", "diagnostic_truncated": True,
              "classification": diagnostic.get("classification"),
              "verifier": safe_details({key: value for key, value in diagnostic.get("verifier", {}).items()
                                        if key in {"phase", "reason_token", "exit_code", "stdout_sha256", "stderr_sha256"}}),
              "mismatch_counts": {k: v for k, v in diagnostic.get("mismatch_counts", {}).items()
                                  if k in {"missing", "extra", "type", "bytes", "file_mode", "directory_mode", "dir_mode", "symlink"}
                                  and type(v) is int and 0 <= v < 2 ** 63},
              "diagnostic_sha256": digest(canonical(diagnostic))}
    for key in ("system", "product", "substage", "family", "invocation"):
        if key in diagnostic:
            result[key] = diagnostic[key]
    if len(canonical(result)) > max_bytes:
        raise ContractError("SIDECAR_DIAGNOSTIC_LIMIT", "Diagnostic bound cannot retain classification")
    return result


def verify_nebular_runtime(runtime_root, prepared, system, prefix=(), env=None, discovered=None, baseline=None, label=None):
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
    script.write_text(_verifier_script(prepared["tools"] / "sidecar-common.mjs"))
    capture = prepared.get("capture")
    expected = None
    if capture:
        candidates = [p for p in capture.record["payloads"] if system in p["platforms"]]
        if len(candidates) == 1:
            expected = capture.manifests[candidates[0]["id"]]["members"]
    identity, current_members = runtime_evidence(root, sidecar, manifests[0], expected, return_members=True)
    verifier, verification = _run_verifier(script, sidecar, payload, prefix, env)
    drift = compare_drift(baseline, root, identity, current_members=current_members) if baseline else None
    classification = classify_diagnostic(identity, verifier=verifier, drift=drift)

    inv_label = _safe_label(label or (prepared.get("label") if prepared else None) or (prepared.get("family") if prepared else None))
    if not inv_label and prepared and "scratch" in prepared:
        scratch_path = Path(prepared["scratch"])
        if scratch_path.name.startswith("smoke-"):
            inv_label = _safe_label(scratch_path.name[len("smoke-"):])

    diagnostic = {"schema": "rs9.sidecar-verifier-diagnostic.v1alpha1", "system": system,
                  "product": "theme-forge-nebular-fusion", "substage": "released-sidecar-verifier",
                  **identity, "classification": classification, "verifier": verifier}
    if inv_label:
        diagnostic["family"] = inv_label
        diagnostic["invocation"] = inv_label
    if drift is not None:
        diagnostic["drift"] = drift
    diagnostic["archive_control"] = (_control_verifier(capture, system, prepared, script, prefix, env, runtime_identity=identity)
                                         if capture else {"status": "not-run", "reason": "capture-unavailable"})
    diagnostic = bound_diagnostic(diagnostic, max_bytes=60 * 1024)
    diagnostics = prepared["scratch"].parent / "diagnostics"
    diagnostics.mkdir(exist_ok=True)
    filename = f"sidecar-verifier-{inv_label}.json" if inv_label else "sidecar-verifier.json"
    (diagnostics / filename).write_bytes(canonical(diagnostic))
    if verification is None:
        raise ContractError("SIDECAR_VERIFIER", "Released sidecar verifier rejected actual runtime representation",
                            details={"product": "theme-forge-nebular-fusion", "substage": "released-sidecar-verifier",
                                     "system": system, "reason": verifier["reason_token"],
                                     **{k: v for k, v in verifier.items() if k in {"exit_code", "stdout_sha256", "stderr_sha256", "exception_type", "phase"}}})
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
    res = {"sidecar": {"verifier_stdout_sha256": digest(canonical(verification)), "verified": True},
           "scenarios": runs, "source_bindings": prepared["records"]}
    if drift is not None:
        res["drift"] = drift
    return res
