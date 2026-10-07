"""Unsigned custody plus real fixture-signed pacman and RPM client qualification."""
import json
import os
from pathlib import Path
import re
import shutil
import uuid

from rs9.build_native import SubprocessRunner, REQUIRED_COMMANDS
from rs9.build_pacman import build_pacman_candidate
from rs9.build_rpm import build_rpm_candidate
from rs9.errors import ContractError, safe_details
from rs9.hosted_native import provision, container_tool_facts
from rs9.npm_deps import resolve_offline_npm_archives as _resolve_offline_npm_archives, resolve_offline_npm_archives
from rs9.release_core import digest
from rs9.pages_candidate import _fixture_public_armor
from rs9.rpm_query import query_rpm_identity, query_rpm_payload_digest, query_rpm_package, IDENTITY_QUERYFORMAT, rpm_isolation_args
from rs9.scratch import canonical
from rs9.signing_fixture import SigningFixture

FIXTURE_ARMOR = "rs9-candidate-fixture-NONPRODUCTION.asc"
FIXTURE_KEYRING = "rs9-candidate-fixture-NONPRODUCTION.gpg"


def _capped_redacted_text(text, max_chars=1024):
    if not isinstance(text, str):
        text = text.decode("ascii", errors="replace")
    # Streams are untrusted: retain printable ASCII only and replace complete
    # absolute path tokens, including quoted/space-bearing paths, before capping.
    if any(c not in "\n\r\t" and not 32 <= ord(c) < 127 for c in text):
        return "non-printable-stream-withheld"
    sanitized = re.sub(r"(?<![A-Za-z0-9])/(?:[^\n\r|]*)", "[PATH]", text)
    return sanitized[:max_chars]


def _receipt_summary(receipt, max_chars=1024):
    return {"executed": receipt.executed, "exit_code": receipt.exit_code,
            "stdout_sha256": receipt.stdout_sha256, "stderr_sha256": receipt.stderr_sha256,
            "stdout_bytes": len(receipt.stdout_bytes), "stderr_bytes": len(receipt.stderr_bytes),
            "stdout_text": _capped_redacted_text(receipt.stdout_text, max_chars),
            "stderr_text": _capped_redacted_text(receipt.stderr_text, max_chars),
            "text_limit": max_chars}


def _write_probe_diagnostic(diag_dir, probe_record, package_name):
    diag_path = Path(diag_dir)
    diag_path.mkdir(parents=True, exist_ok=True)
    name = "rpm-signed-query-probe-" + digest(package_name.encode())[:16] + ".json"
    raw = canonical(probe_record)
    if len(raw) > 64 * 1024:
        raise ContractError("RPM_PROBE_LIMIT", "Bounded signed query diagnostic exceeded")
    (diag_path / name).write_bytes(raw)
    return name


def checked(runner, argv, **kwargs):
    substage = kwargs.pop("substage", "native-tool")
    receipt = runner.run(argv, **kwargs)
    if receipt.exit_code or not receipt.executed:
        tool_name = Path(argv[0]).name if argv else "tool"
        details = {
            "substage": substage,
            "tool": tool_name,
            "exit_code": receipt.exit_code,
            "stdout_sha256": receipt.stdout_sha256,
            "stderr_sha256": receipt.stderr_sha256,
        }
        raise ContractError("NATIVE_TOOL", "Actual native command failed: " + argv[0], details=details)
    return receipt


def sign_rpm(runner, path, fixture, *, expected=None, wrong_fixture=None, diagnostics_dir=None):
    """Sign only a retained copy; production-candidate bytes stay unsigned."""
    path = Path(path)
    before = digest(path.read_bytes())
    class ActualQueries:
        def run(self, argv, **kwargs):
            return checked(runner, argv, substage="rpm-query", **kwargs)

    queries = ActualQueries()
    diag_dir = diagnostics_dir or (fixture.homedir / "diagnostics")
    db = fixture.homedir / "fixture-rpmdb"
    db.mkdir(exist_ok=True)
    keyring_dir = fixture.homedir / "fixture-keyring"
    keyring_dir.mkdir(exist_ok=True)
    keyring_type = "rpmdb"

    empty_db = fixture.homedir / "empty-rpmdb"
    empty_db.mkdir(exist_ok=True)
    empty_keyring = fixture.homedir / "empty-keyring"
    empty_keyring.mkdir(exist_ok=True)

    wrong_db = fixture.homedir / "wrong-rpmdb"
    wrong_db.mkdir(exist_ok=True)
    wrong_keyring = fixture.homedir / "wrong-keyring"
    wrong_keyring.mkdir(exist_ok=True)

    probe_record = {
        "production_enabled": False, "publication_authority": False,
        "schema": "rs9.rpm6-probe.v1alpha1",
        "status": "pending",
        "rpm_version": {},
        "macros": {},
        "transcripts": {},
        "negatives": {},
        "checks": {},
    }

    try:
        probe_record["rpm_version"] = _receipt_summary(runner.run(["rpm", "--version"]))
        isolated = rpm_isolation_args(dbpath=db, keyring=keyring_type, keyringpath=keyring_dir)
        for label, query in (("unsigned_preflight_identity", IDENTITY_QUERYFORMAT),
                             ("unsigned_preflight_payload", "%{PAYLOADSHA256}|%{PAYLOADSHA256ALGO}\n")):
            probe_record["transcripts"][label] = _receipt_summary(runner.run(
                ["rpm", *isolated, "-qp", "--queryformat", query, str(path)]))
        intended = (expected or {}).get("rpm_identity")
        if expected is not None and before != expected["package_sha256"]:
            raise ContractError("RPM_SIGNING", "Unsigned copy differs from custody bytes",
                                details={"substage": "rpm-sign-preservation"})

        # Isolate RPM6 keyring configuration on unsigned query
        if intended is None and expected is not None:
            unsigned_identity, unsigned_payload_digest, _ = query_rpm_package(
                queries, path, product=expected["name"], version=expected["version"],
                architecture=expected["arch"], revision=expected["revision"],
                dbpath=db, keyring=keyring_type, keyringpath=keyring_dir)
        else:
            unsigned_identity, _ = query_rpm_identity(
                queries, path, dbpath=db, keyring=keyring_type, keyringpath=keyring_dir)
            unsigned_payload_digest, _ = query_rpm_payload_digest(
                queries, path, dbpath=db, keyring=keyring_type, keyringpath=keyring_dir)
        if intended is not None and (unsigned_identity != intended or
                unsigned_payload_digest != expected["rpm_payload_digest"]):
            raise ContractError("RPM_SIGNING", "Unsigned readback differs from build manifest",
                                details={"substage": "rpm-sign-preservation"})

        # Preserve supported tags and PAYLOADSHA256 algo 8
        supported_tag = unsigned_payload_digest.get("tag") in ("PAYLOADSHA256", "PAYLOADDIGEST")
        algo8 = (unsigned_payload_digest.get("algorithm_numeric") == 8
                 and unsigned_payload_digest.get("algorithm") == "sha256")
        if not supported_tag:
            raise ContractError("RPM_PAYLOAD_DIGEST_UNSUPPORTED", "Unsupported RPM payload digest tag",
                                details={"substage": "rpm-sign", "tag": unsigned_payload_digest.get("tag")})
        if not algo8:
            raise ContractError("INVALID_ALGORITHM", "Payload algorithm differs from SHA256 numeric identifier 8",
                                details={"substage": "rpm-sign", "algorithm": unsigned_payload_digest.get("algorithm_numeric")})

        probe_record["checks"]["supported_tags"] = supported_tag
        probe_record["checks"]["algo8"] = algo8

        unsigned_copy = fixture.homedir / (path.name + ".unsigned")
        unsigned_copy.write_bytes(path.read_bytes())
        fmt = "%{" + unsigned_payload_digest["tag"] + "}|%{" + unsigned_payload_digest["algo_tag"] + "}\n"

        def transcript(prefix, package, trust_db, trust_keyring):
            for label, query in (("identity", IDENTITY_QUERYFORMAT), ("payload", fmt)):
                argv = ["rpm", *rpm_isolation_args(dbpath=trust_db, keyring=keyring_type, keyringpath=trust_keyring),
                        "-qp", "--queryformat", query, str(package)]
                probe_record["transcripts"][prefix + "_" + label] = _receipt_summary(runner.run(argv))

        transcript("unsigned_empty_trust", unsigned_copy, empty_db, empty_keyring)
        transcript("unsigned_keyed_trust", unsigned_copy, db, keyring_dir)

        if wrong_fixture is None or wrong_fixture.primary_fingerprint == fixture.primary_fingerprint:
            raise ContractError("RPM_SIGNING", "A distinct wrong-key fixture is required")

        # Sign the RPM package
        checked(runner, ["rpmsign", "--define", "_gpg_name " + fixture.primary_fingerprint,
                        "--define", "_gpg_path " + str(fixture.homedir),
                        "--define", "__gpg " + fixture.gpg, "--addsign", str(path)],
                substage="rpm-sign")
        after = digest(path.read_bytes())
        if before == after:
            raise ContractError("RPM_SIGNING", "Fixture RPM header was not signed",
                                details={"substage": "rpm-sign", "tool": "rpmsign"})
        probe_record["checks"]["whole_file_sha_changed"] = True

        # Import public key into isolated trust database and keyring directory
        public = fixture.homedir / FIXTURE_ARMOR
        public_bytes = _fixture_public_armor(fixture)
        public.write_bytes(public_bytes)
        (keyring_dir / FIXTURE_ARMOR).write_bytes(public_bytes)

        checked(runner, ["rpmkeys", "--dbpath", str(db),
                        "--define", f"_keyring {keyring_type}",
                        "--define", f"_keyringpath {keyring_dir}",
                        "--import", str(public)],
                substage="rpm-import")

        wrong_public = fixture.homedir / "wrong-fixture.asc"
        wrong_public.write_bytes(_fixture_public_armor(wrong_fixture))
        checked(runner, ["rpmkeys", *rpm_isolation_args(dbpath=wrong_db, keyring=keyring_type,
                        keyringpath=wrong_keyring), "--import", str(wrong_public)], substage="rpm-wrong-import")

        # Retain RPM6 keyless/keyed streams before any operation can hide them.
        probe_record["rpm_version"] = _receipt_summary(runner.run(["rpm", "--version"]))
        macro_argv = ["rpm", *rpm_isolation_args(dbpath=db, keyring=keyring_type, keyringpath=keyring_dir),
                      "--eval", "%{_keyring}|%{_keyringpath}|%{_dbpath}"]
        macro = runner.run(macro_argv)
        probe_record["macros"] = _receipt_summary(macro)
        macro_expected = keyring_type + "|" + str(keyring_dir) + "|" + str(db) + "\n"
        probe_record["checks"]["isolated_macros"] = "pass" if (macro.executed and macro.exit_code == 0
            and not macro.stderr_bytes and macro.stdout_text == macro_expected) else "fail"
        transcript("signed_empty_trust", path, empty_db, empty_keyring)
        transcript("signed_keyed_trust", path, db, keyring_dir)
        if probe_record["checks"]["isolated_macros"] != "pass":
            raise ContractError("RPM_SIGNING", "Effective RPM trust macros differ from fixture isolation")

        # 4. Checksig validation (real checksig)
        result = runner.run(["rpmkeys", *rpm_isolation_args(dbpath=db, keyring=keyring_type, keyringpath=keyring_dir), "--checksig", str(path)])
        probe_record["checks"]["real_checksig_receipt"] = _receipt_summary(result)
        if not result.executed:
            raise ContractError("NATIVE_TOOL", "Actual native command failed: rpmkeys",
                                details={"substage": "rpm-checksig", "tool": "rpmkeys"})
        if (result.exit_code != 0 or result.stderr_bytes
                or re.search(r": digests signatures OK\n?\Z", result.stdout_text) is None):
            raise ContractError("RPM_SIGNING", "Fixture RPM signature validation failed",
                                details={"substage": "rpm-checksig", "tool": "rpmkeys",
                                         "exit_code": result.exit_code,
                                         "stdout_sha256": result.stdout_sha256, "stderr_sha256": result.stderr_sha256})
        probe_record["checks"]["real_checksig"] = "pass"

        # 5. Checksig negatives (nonraising runner!)
        # (a) Wrong-key rejection requires a real distinct imported fixture.
        wrong_result = runner.run(["rpmkeys", *rpm_isolation_args(dbpath=wrong_db, keyring=keyring_type,
                                  keyringpath=wrong_keyring), "--checksig", str(path)])
        probe_record["negatives"]["wrong_key_checksig"] = _receipt_summary(wrong_result)
        if not wrong_result.executed or wrong_result.exit_code == 0:
            raise ContractError("RPM_SIGNING", "Signed RPM accepted by wrong key or check did not execute")
        probe_record["checks"]["wrong_key_rejection"] = "pass"

        # (b) Empty-trust rejection
        empty_result = runner.run(["rpmkeys", *rpm_isolation_args(dbpath=empty_db, keyring=keyring_type, keyringpath=empty_keyring), "--checksig", str(path)])
        probe_record["negatives"]["empty_trust_checksig"] = _receipt_summary(empty_result)
        if not empty_result.executed or empty_result.exit_code == 0:
            raise ContractError("RPM_SIGNING", "Signed RPM accepted by empty trust database",
                                details={"substage": "rpm-checksig-empty-trust", "tool": "rpmkeys"})
        probe_record["checks"]["empty_trust_rejection"] = "pass"

        # (c) Tamper rejection
        tamper_path = fixture.homedir / (path.name + ".tampered")
        raw_signed = path.read_bytes()
        tampered_bytes = bytearray(raw_signed)
        tampered_bytes[-1] ^= 0x01
        tamper_path.write_bytes(bytes(tampered_bytes))
        tamper_result = runner.run(["rpmkeys", *rpm_isolation_args(dbpath=db, keyring=keyring_type, keyringpath=keyring_dir), "--checksig", str(tamper_path)])
        probe_record["negatives"]["tamper_checksig"] = _receipt_summary(tamper_result)
        if not tamper_result.executed or tamper_result.exit_code == 0:
            raise ContractError("RPM_SIGNING", "Tampered RPM accepted by checksig",
                                details={"substage": "rpm-checksig-tamper", "tool": "rpmkeys"})
        probe_record["checks"]["tamper_rejection"] = "pass"

        # NOW: THE GATING QUERY
        signed_identity, _ = query_rpm_identity(
            queries, path, dbpath=db, keyring=keyring_type, keyringpath=keyring_dir)
        signed_payload_digest, _ = query_rpm_payload_digest(
            queries, path, capability=unsigned_payload_digest["capability"],
            dbpath=db, keyring=keyring_type, keyringpath=keyring_dir)

        if unsigned_identity != signed_identity:
            raise ContractError(
                "RPM_SIGNING",
                "Fixture RPM identity changed after signing",
                details={
                    "substage": "rpm-sign",
                    "tool": "rpm",
                    "unsigned_identity": unsigned_identity,
                    "signed_identity": signed_identity,
                },
            )
        if unsigned_payload_digest != signed_payload_digest:
            raise ContractError(
                "RPM_SIGNING",
                "Fixture RPM payload digest changed after signing",
                details={
                    "substage": "rpm-sign",
                    "tool": "rpm",
                    "unsigned_payload_digest": unsigned_payload_digest,
                    "signed_payload_digest": signed_payload_digest,
                },
            )

        probe_record["checks"]["identity_preserved"] = True
        probe_record["checks"]["payload_digest_preserved"] = True
        probe_record["status"] = "pass"
    except Exception as exc:
        probe_record["status"] = "fail"
        probe_record["error_code"] = getattr(exc, "code", type(exc).__name__)
        raise
    finally:
        _write_probe_diagnostic(diag_dir, probe_record, path.name)

    return {
        "unsigned_sha256": before,
        "fixture_signed_sha256": after,
        "fixture_fingerprint": fixture.primary_fingerprint,
        "production": False,
        "rpm_identity": signed_identity,
        "rpm_payload_digest": signed_payload_digest,
        "unsigned_identity": unsigned_identity,
        "fixture_signed_identity": signed_identity,
        "unsigned_payload_digest": unsigned_payload_digest,
        "fixture_signed_payload_digest": signed_payload_digest,
        "identity_preserved": True,
        "payload_digest_preserved": True,
        "probe": probe_record,
    }


def write_keys(directory, fixture):
    directory.mkdir(parents=True, exist_ok=True)
    (directory / FIXTURE_ARMOR).write_bytes(_fixture_public_armor(fixture))
    (directory / FIXTURE_KEYRING).write_bytes(fixture.public_key_binary)
    (directory / "KEY-METADATA.json").write_bytes(canonical({"production": False, "fixture": True,
        "fingerprint": fixture.primary_fingerprint, "purpose": "NON-PRODUCTION CANDIDATE TEST ONLY"}))


def execute(context):
    # Import lazily: the APT/Pages module shares these native client primitives.
    from rs9.hosted_deb import (ContainerRunner, RecordingRunner, provision_image, client_cycle,
                                tamper_cycle, dnf_spec, pacman_spec, _fold, _burst_release_record, burst_client_gates)
    from rs9.pages_candidate import write_custody_bundle
    family, system = context["family"], context["system"]
    repository, scratch, pins = context["repository"], context["scratch"], context["pins"]
    host = RecordingRunner(context.get("runner") or SubprocessRunner(timeout=1800))
    environment = provision(family, system, pins, runner=host)
    architectures = {"aarch64-linux": "aarch64", "x86_64-linux": "x86_64"}
    if system not in architectures:
        raise ContractError("INVALID_ARCHITECTURE", "Hosted native package system is unsupported")
    platform, arch = environment["platform"], architectures[system]
    tag = "rs9-" + family + "-builder:" + uuid.uuid4().hex[:12]
    tools = ["base-devel", "binutils", "pacman-contrib", "gnupg", "findutils", "python"] if family == "pacman" else ["rpm-build", "rpm-sign", "gnupg2", "rpmlint", "createrepo_c", "binutils", "findutils", "python3"]
    client_tools = ["xorg-server-xvfb", "dbus", "python"] if family == "pacman" else ["xorg-x11-server-Xvfb", "dbus-daemon", "python3"]
    gates = [{"name": family + "-container-environment", "status": "pass"}]
    client_tag = "rs9-" + family + "-client:" + uuid.uuid4().hex[:12]
    artifacts, identities = [], []
    try:
        provision_image(host, "pacman" if family == "pacman" else "dnf", environment["image_ref"],
                        platform, tag, [*tools, *environment["preprovisioned_packages"], *client_tools])
        # A persistent passwd identity and HOME are needed by makepkg; builders are not root.
        checked(host, ["docker", "run", "--rm", "--network", "none", tag, "true"], substage="builder-check")
        builder = RecordingRunner(ContainerRunner(host, tag, platform=platform,
                    mounts=[(str(scratch), str(scratch), True)], user=str(os.getuid()) + ":" + str(os.getgid())))
        environment["tools"] = container_tool_facts(builder, ["python3", "node", "gpg", *(["pacman", "makepkg", "repo-add"] if family == "pacman" else ["rpm", "rpmbuild", "rpmsign", "createrepo_c"])])
        unsigned = scratch / "unsigned"
        unsigned.mkdir()
        products, errors, failures, product_metadata = {}, {}, {}, {}
        for capture, intent, _ in context["captures"]:
            pid = intent["project"]["id"]
            work = scratch / "build" / pid
            work.mkdir(parents=True)
            mark = builder.mark()
            try:
                npm = _resolve_offline_npm_archives(capture, pid, scratch, None, context["client"])
                build = build_pacman_candidate if family == "pacman" else build_rpm_candidate
                from rs9.product_classes import is_pure_js_cli, get_product_class
                target = ("any" if family == "pacman" else "noarch") if is_pure_js_cli(pid) else arch
                result = build(capture, intent, target, work,
                               offline_npm_archives=npm, runner=builder)
                path = result["package_path"] if family == "pacman" else result["rpm_path"]
                dest = unsigned / path.name
                shutil.copyfile(path, dest)
                products[pid] = dest
                product_metadata[pid] = {"package_class": get_product_class(pid), "architecture": target,
                                         "package_file": dest.name, "sha256": digest(dest.read_bytes())}
                if family == "rpm":
                    product_metadata[pid].update(rpm_identity=result["manifest"]["rpm_identity"],
                        rpm_payload_digest=result["manifest"]["rpm_payload_digest"])
                artifacts += [dest, work / ("pacman-manifest.json" if family == "pacman" else "rpm-manifest.json")]
            except (ContractError, OSError) as error:
                errors[pid] = error.code if isinstance(error, ContractError) else "PACKAGE_FILESYSTEM"
                receipts = builder.receipts[mark:]
                failed = (next((r for r in reversed(receipts) if Path(r.tool_name or r.argv[0]).name == "rpmlint" and "--version" not in r.argv), None)
                          if errors[pid] == "RPMLINT_FAILED" else
                          next((r for r in receipts if r.exit_code), receipts[-1] if receipts else None))
                details = {"product": pid, "family": family, "system": system, "substage": "package-build"}
                if failed:
                    details.update(tool=Path(failed.tool_name or failed.argv[0]).name, exit_code=failed.exit_code,
                                   stdout_sha256=failed.stdout_sha256, stderr_sha256=failed.stderr_sha256)
                if isinstance(error, ContractError):
                    details.update(error.details)
                failures[pid] = {"code": errors[pid], **safe_details(details)}
                if family == "rpm" and isinstance(error, ContractError) and error.code == "RPMLINT_FAILED":
                    pkg_path = getattr(error, "package_path", None) or error.details.get("package_path")
                    if pkg_path and Path(pkg_path).is_file():
                        quarantine = scratch / "quarantine"
                        quarantine.mkdir(exist_ok=True)
                        shutil.copyfile(pkg_path, quarantine / Path(pkg_path).name)
                    spec_path = getattr(error, "spec_path", None) or error.details.get("spec_path") or (work / "rpmbuild" / "SPECS" / f"{pid}.spec")
                    if Path(spec_path).is_file():
                        diag_spec_dir = scratch / "diagnostics"
                        diag_spec_dir.mkdir(exist_ok=True)
                        # Diagnostic custody is bounded JSON. Keep the exact
                        # generated spec in a typed record, rather than a raw
                        # .spec that custody would necessarily withhold.
                        spec_bytes = Path(spec_path).read_bytes()
                        diag_spec = diag_spec_dir / f"{pid}.spec.json"
                        diag_spec.write_bytes(canonical({
                            "schema": "rs9.generated-rpm-spec.v1", "product": pid,
                            "system": system, "spec_sha256": digest(spec_bytes),
                            "spec_bytes": len(spec_bytes), "spec": spec_bytes.decode("utf-8"),
                        }))
                        artifacts.append(diag_spec)
                    ev = getattr(error, "evidence", None) or error.details.get("evidence")
                    if ev is not None:
                        diag_ev_dir = scratch / "diagnostics"
                        diag_ev_dir.mkdir(exist_ok=True)
                        diag_ev = diag_ev_dir / f"rpmlint-{pid}.json"
                        diag_ev.write_bytes(canonical(ev))
                        artifacts.append(diag_ev)
        if family == "rpm":
            build_failures = {k: v for k, v in errors.items() if v != "RPMLINT_FAILED"}
            total_built = len(products) + len([k for k, v in errors.items() if v == "RPMLINT_FAILED"])
            build_pass = (total_built == 4 and not build_failures)
            lint_pass = (len(products) == 4 and not errors)
            gates.append({"name": "rpm-package-build", "status": "pass" if build_pass else "fail"})
            gates.append({"name": "rpm-rpmlint-clean", "status": "pass" if lint_pass else "fail"})
        else:
            gates.append({"name": family + "-package-build", "status": "pass" if len(products) == 4 and not errors else "fail"})
        if errors:
            diag_dir = scratch / "diagnostics"
            diag_dir.mkdir(exist_ok=True)
            diag_file = diag_dir / "build-errors.json"
            diag_file.write_bytes(canonical({"schema": "rs9.build-errors.v1alpha1", "family": family, "system": system,
                                            "errors": errors, "product_failures": failures, "gates": gates}))
            artifacts.append(diag_file)
        if family == "rpm" and errors and not build_failures:
            # Construction succeeded, but candidate lint failures stop custody,
            # indexing/signing and DNF. Return the actual distinct gates.
            reason="blocked-by:rpm-rpmlint-clean"
            gates.extend({"name":n,"status":"not-run","reason":reason}
                         for n in ("rpm-repository-indexing","rpm-client-qualification",
                                   "burst-native-addon-target","burst-native-addon-load"))
            gates.extend({"name":"rpm-trust.tamper."+kind,"status":"not-run","reason":reason}
                         for kind in ("package","index","signature","wrongkey"))
            return {"gates":gates,"artifacts":artifacts,
                    "details":{"environment":environment,"build_errors":errors,"product_failures":failures,
                               "diagnostic_scope":"candidate-only-lint-failures"}}
        if len(products) != 4 or errors:
            first_product = sorted(errors.keys())[0] if errors else "unknown"
            first_failure = failures.get(first_product, {})
            product_code = errors.get(first_product) or first_failure.get("code") or "build-error"
            raise ContractError(
                "NATIVE_BUILD",
                "One or more required product builds failed",
                details={
                    "substage": "package-build",
                    "family": family,
                    "system": system,
                    "product": first_product,
                    "product_code": product_code,
                    "underlying_code": product_code,
                    "product_errors": errors,
                    **{k: v for k, v in first_failure.items() if k != "code"},
                },
            )
        bundle = scratch / "unsigned-custody"
        bundle.mkdir()
        write_custody_bundle(bundle, packages={p.name:p.read_bytes() for p in products.values()}, family=family, system=system,
                             authentication_sha256=context["authentication_sha256"], source_commit=context["binding"]["source_commit"])
        artifacts.extend(p for p in bundle.rglob("*") if p.is_file())
        fixture_dir = scratch / "fixture"
        fixture_dir.mkdir()
        with SigningFixture(scratch_dir=fixture_dir) as fixture, SigningFixture() as wrong:
            (scratch / "fixture-identity.json").write_bytes(canonical({"used": True, "production": False,
                "purpose": "NON-PRODUCTION CANDIDATE TEST ONLY", "fingerprint": fixture.primary_fingerprint,
                "wrong_key_fingerprint": wrong.primary_fingerprint}))
            keys = scratch / "keys"
            write_keys(keys, fixture)
            repo = scratch / family
            directory = repo / ("x86_64" if family == "pacman" else "fedora/43/" + arch)
            package_directory = directory if family == "pacman" else directory / "Packages"
            package_directory.mkdir(parents=True)
            for pid, path in products.items():
                testcopy = package_directory / path.name
                shutil.copyfile(path, testcopy)
                if family == "rpm":
                    signer = ContainerRunner(host,tag,platform=platform,mounts=[(str(scratch),str(scratch),True)])
                    metadata = product_metadata[pid]
                    identities.append(sign_rpm(signer, testcopy, fixture, expected={
                        "package_sha256": metadata["sha256"], "rpm_identity": metadata["rpm_identity"],
                        "rpm_payload_digest": metadata["rpm_payload_digest"]},
                        wrong_fixture=wrong,
                        diagnostics_dir=scratch / "diagnostics"))
                else:
                    (package_directory / (path.name + ".sig")).write_bytes(fixture.detach_sign(path.read_bytes(), armor=False))
                    fixture.verify(path.read_bytes(), (package_directory / (path.name + ".sig")).read_bytes())
            tool = ContainerRunner(host, tag, platform=platform, mounts=[(str(scratch), str(scratch), True)])
            if family == "rpm":
                checked(tool, ["createrepo_c", "--no-database", "--compress-type", "gz", str(directory)])
                index = directory / "repodata/repomd.xml"
                (directory / "repodata/repomd.xml.asc").write_bytes(fixture.detach_sign(index.read_bytes(), armor=True))
                fixture.verify(index.read_bytes(), (directory / "repodata/repomd.xml.asc").read_bytes())
                spec_for = lambda dirs: dnf_spec(dirs["rpm"], keys, arch)
            else:
                checked(tool, ["repo-add", str(directory / "rs9.db.tar.gz"), *[str(p) for p in sorted(package_directory.glob("*.pkg.tar.*")) if not p.name.endswith(".sig")]])
                for suffix in ("db", "files"):
                    link = directory / ("rs9." + suffix)
                    if link.is_symlink():
                        link.unlink()
                    shutil.copyfile(directory / ("rs9." + suffix + ".tar.gz"), link)
                    for name in (link, directory / ("rs9." + suffix + ".tar.gz")):
                        name.with_name(name.name + ".sig").write_bytes(fixture.detach_sign(name.read_bytes(), armor=False))
                spec_for = lambda dirs: pacman_spec(dirs["pacman"], keys, fixture.primary_fingerprint)
            gates.append({"name": family + "-repository-indexing", "status": "pass"})
            dirs = {family: repo}
            from rs9.hosted_smoke import prepare_smoke
            neb = next(c for c,i,_ in context["captures"] if i["project"]["id"] == "theme-forge-nebular-fusion")
            prepared = prepare_smoke(neb, context["captures"], context["client"], scratch / "application-smoke")
            provision_image(host, "pacman" if family == "pacman" else "dnf", environment["image_ref"],
                            platform, client_tag, [*environment["preprovisioned_packages"], *client_tools])
            spec = spec_for(dirs)
            rows, evidence = client_cycle(host, spec, image=client_tag, platform=platform,
                       products=list(products), repository=repository, prefix=family + "-client", smoke=prepared, system=system,
                       burst_record=_burst_release_record(context["captures"], system),
                       burst_scratch=scratch / "burst-native-probe")
            (scratch / "tamper").mkdir()
            rows += tamper_cycle(host, spec_for, "dnf" if family == "rpm" else "pacman", dirs,
                    image=client_tag, platform=platform, product=list(products)[0], work=scratch / "tamper", wrong_signer=wrong, arch=arch,
                    kinds=("package","index","signature","wrongkey"), prefix=family+"-trust",
                    positive_control=evidence.get(list(products)[0],{}).get("positive_control"))
            gates.extend(rows)
            gates.extend(burst_client_gates(rows))
            gates.append({"name": family + "-client-qualification", "status": _fold(rows)})
            artifacts.extend(p for p in [*repo.rglob("*"), *keys.rglob("*")] if p.is_file() and not p.is_symlink())
            manifest = scratch / "native-qualification.json"
            manifest.write_bytes(canonical({"schema": "rs9.native-hosted.v1alpha1", "production": False,
                "environment": environment, "fixture_fingerprint": fixture.primary_fingerprint,
                "rpm_identities": identities, "products": product_metadata, "client": evidence, "build_errors": errors}))
            artifacts.append(manifest)
            artifacts.extend(sorted((scratch / "diagnostics").glob("rpm-signed-query-probe-*.json")))
    finally:
        try:
            host.run(["docker", "rmi", "-f", tag, client_tag])
        except (ContractError, OSError):
            pass
    details = {"environment": environment}
    if errors:
        details["build_errors"] = errors
    return {"gates": gates, "artifacts": artifacts, "details": details}
