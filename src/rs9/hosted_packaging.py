"""Unsigned custody plus real fixture-signed pacman and RPM client qualification."""
from contextlib import ExitStack, contextmanager
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
from rs9.rpm_client_runtime import prepare_client, verify_client_image
from rs9.rpm_repository import command_tool

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
        tool_name = command_tool(argv)
        details = {
            "substage": substage,
            "tool": tool_name,
            "exit_code": receipt.exit_code,
            "stdout_sha256": receipt.stdout_sha256,
            "stderr_sha256": receipt.stderr_sha256,
        }
        raise ContractError("NATIVE_TOOL", "Actual native command failed: " + tool_name, details=details)
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

    primary_error = None
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
        from rs9.machine_stream import machine_records
        checksig_lines = machine_records(result, limit=4096, code="RPM_SIGNING",
                                         substage="rpm-checksig", encoding="utf-8")
        if (result.exit_code != 0 or result.stderr_bytes or len(checksig_lines) != 1
                or re.search(r": digests signatures OK\Z", checksig_lines[0]) is None):
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
        primary_error = exc
        probe_record["status"] = "fail"
        probe_record["error_code"] = getattr(exc, "code", type(exc).__name__)
        raise
    finally:
        try:
            _write_probe_diagnostic(diag_dir, probe_record, path.name)
        except Exception as secondary:
            if primary_error is None:
                primary_error = ContractError("RPM_PROBE_CUSTODY", "Signing probe retention failed",
                    details={"substage": "package-signing-probe-retention", "target": path.name,
                             "causal_code": getattr(secondary, "code", type(secondary).__name__)})
                primary_error.rpm_probe_record = probe_record
                raise primary_error from secondary
            primary_error.rpm_probe_record = probe_record
            primary_error.secondary_diagnostics = [{"operation": "signing-probe-write",
                "code": getattr(secondary, "code", type(secondary).__name__)}]

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


def write_keys(directory, fixture, write_file=None):
    writer = write_file or (lambda p, d: Path(p).write_bytes(d))
    directory.mkdir(parents=True, exist_ok=True)
    if write_file is not None:
        directory.chmod(0o755)
    writer(directory / FIXTURE_ARMOR, _fixture_public_armor(fixture))
    writer(directory / FIXTURE_KEYRING, fixture.public_key_binary)
    writer(directory / "KEY-METADATA.json", canonical({"production": False, "fixture": True,
        "fingerprint": fixture.primary_fingerprint, "purpose": "NON-PRODUCTION CANDIDATE TEST ONLY"}))


def verify_construction_witness(witness, package, product):
    """A typed failure or an existing file alone is never a build witness."""
    if not isinstance(witness, dict) or witness.get("schema") != "rs9.rpm-construction-witness.v1":
        return False
    build = witness.get("rpmbuild_receipt", {})
    identity = witness.get("rpm_identity", {})
    payload = witness.get("rpm_payload_digest", {})
    if not all(isinstance(value, dict) for value in (build, identity, payload)):
        return False
    def hash_value(value):
        return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None
    if (build.get("executed") is not True or build.get("exit_code") != 0
            or build.get("tool") != "rpmbuild" or identity.get("name") != product
            or not all(isinstance(identity.get(k), str) and identity[k] for k in ("version", "release", "arch"))
            or not isinstance(payload, dict) or payload.get("payload_digest_algo") != "sha256"
            or not hash_value(payload.get("payload_digest"))
            or not all(hash_value(build.get(k)) for k in ("stdout_sha256", "stderr_sha256", "command_sha256"))
            or not hash_value(witness.get("spec_sha256"))):
        return False
    try:
        path = Path(package)
        return (not path.is_symlink() and path.is_file() and path.stat().st_size == witness.get("package_size")
                and digest(path.read_bytes()) == witness.get("package_sha256"))
    except (OSError, TypeError):
        return False


def rpm_stage_gates(required_products, constructed, completed, failures):
    """Fold separately witnessed construction and completed durable boundaries."""
    stages = [("rpm-package-build", "construction"), ("rpm-derivation-record", "derivation"),
              ("rpm-manifest-record", "manifest"), ("rpm-policy-custody", "custody")]
    causal = {"RPM_DERIVATION_RECORD": "derivation", "RPM_MANIFEST_RECORD": "manifest", "RPM_POLICY_CUSTODY": "custody"}
    rows = []
    for name, stage in stages:
        passed = constructed if stage == "construction" else completed.get(stage, set())
        direct = {p: f["code"] for p, f in failures.items() if causal.get(f["code"]) == stage}
        status = "pass" if set(passed) == set(required_products) and len(required_products) == 4 else "fail" if stage == "construction" or direct else "not-run"
        row = {"name": name, "status": status}
        if status != "pass":
            row["products"] = sorted(set(required_products) - set(passed))
            if direct:
                row.update(causal_substage=stage, product_codes=direct)
        rows.append(row)
    return rows


def caller_diagnostic(evidence):
    """Retain source identities separately from the full verified caller input."""
    if not isinstance(evidence, dict):
        return None
    return {"schema": evidence.get("schema", "rs9.nebular-caller-sources.v1"),
            "status": evidence.get("status"), "reason": evidence.get("reason"),
            "tag_commit": evidence.get("tag_commit"), "tag_tree": evidence.get("tag_tree"),
            "evidence_sha256": digest(canonical(evidence)),
            "files": {path: {k: row[k] for k in ("path", "blob", "sha256", "size") if k in row}
                      for path, row in evidence.get("files", {}).items()},
            "missing_items": evidence.get("missing_items", [])}


@contextmanager
def _fixture_scope(directory, secondary, *, preserve_cleanup=False):
    """Close both fixtures while preserving an operation's original exception."""
    if preserve_cleanup:
        with SigningFixture(scratch_dir=directory) as fixture, SigningFixture() as wrong:
            yield fixture, wrong
        return
    def close(fixture):
        try:
            fixture.__exit__(None, None, None)
        except Exception as error:
            secondary.append({"operation": "fixture-cleanup", "code": getattr(error, "code", type(error).__name__)})
    with ExitStack() as stack:
        fixture = SigningFixture(scratch_dir=directory)
        stack.callback(close, fixture)
        fixture.__enter__()
        wrong = SigningFixture()
        stack.callback(close, wrong)
        wrong.__enter__()
        yield fixture, wrong


def _verify_unsigned_products(products, metadata, bundle):
    for product, path in products.items():
        expected = metadata[product]["sha256"]
        for candidate in (path, bundle / "files" / path.name):
            if candidate.is_symlink() or digest(candidate.read_bytes()) != expected:
                raise ContractError("CUSTODY_HASH", "Unsigned candidate changed during fixture operations",
                                    details={"product": product, "target": candidate.name,
                                             "substage": "unsigned-custody-verification"})


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
    client_runtime, caller_evidence, preservation_policy = None, None, None
    return_result = None
    current_substage = "builder-provision"
    failed_product = None
    from rs9.hosted_deb import _user
    from rs9.rpm_repository import (sign_metadata, prepare_public_directory, write_public_file,
                                    audit_owned_tree, metadata_command)
    late_phase = False
    secondary_diagnostics = []
    completed_operations = {}
    repository_reports = {}
    repo = bundle = keys = None
    try:
        provision_image(host, "pacman" if family == "pacman" else "dnf", environment["image_ref"],
                        platform, tag, [*tools, *environment["preprovisioned_packages"], *client_tools])
        # A persistent passwd identity and HOME are needed by makepkg; builders are not root.
        checked(host, ["docker", "run", "--rm", "--network", "none", tag, "true"], substage="builder-check")
        if family == "rpm":
            # Dependency preparation precedes all candidate builds and policy decisions.
            # It does not install, sign or qualify any candidate product.
            client_runtime = prepare_client(host, environment, arch=arch, system=system, tag=client_tag)
            from rs9.rpm_client_runtime import bind_engine_floors
            client_runtime = bind_engine_floors(client_runtime, context["captures"])
            diagnostics = scratch / "diagnostics"
            diagnostics.mkdir(exist_ok=True)
            runtime_path = diagnostics / ("rpm-client-runtime-" + system + ".json")
            runtime_path.write_bytes(canonical(client_runtime))
            artifacts.append(runtime_path)
            from rs9.rpm_lint_policy import load_policy
            try:
                preservation_policy = load_policy(repository / "operators/live1/rpm-lint-policy.json")
            except (ContractError, OSError):
                preservation_policy = {}  # Explicit invalid input cannot confer acceptance.
            nebular = next((capture for capture, intent, _ in context["captures"]
                            if intent["project"]["id"] == "theme-forge-nebular-fusion"), None)
            if nebular is not None:
                from rs9.nebular_callers import collect_caller_sources
                try:
                    caller_evidence = collect_caller_sources(nebular, context["client"], scratch / "caller-sources",
                                                            preservation_policy.get("projects", {}).get("theme-forge-nebular-fusion", {}))
                except (ContractError, OSError, AttributeError, TypeError) as cause:
                    caller_evidence = {"status": "unavailable", "reason": getattr(cause, "code", "CALLER_SOURCE_UNAVAILABLE")}
                caller_path = diagnostics / ("nebular-caller-sources-" + system + ".json")
                caller_path.write_bytes(canonical(caller_diagnostic(caller_evidence)))
                artifacts.append(caller_path)
        builder = RecordingRunner(ContainerRunner(host, tag, platform=platform,
                    mounts=[(str(scratch), str(scratch), True)], user=str(os.getuid()) + ":" + str(os.getgid())))
        environment["tools"] = container_tool_facts(builder, ["python3", "node", "gpg", *(["pacman", "makepkg", "repo-add"] if family == "pacman" else ["rpm", "rpmbuild", "rpmsign", "createrepo_c"])])
        unsigned = scratch / "unsigned"
        unsigned.mkdir()
        products, errors, failures, product_metadata = {}, {}, {}, {}
        construction_witnesses = {}
        completed_records = {"derivation": set(), "manifest": set(), "custody": set()}
        lint_evidence, lint_policy = {}, {}
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
                               offline_npm_archives=npm, runner=builder,
                               **({"builder_system": system, "policy": preservation_policy,
                                   "client_runtime": client_runtime, "caller_evidence": caller_evidence}
                                  if family == "rpm" else {}))
                path = result["package_path"] if family == "pacman" else result["rpm_path"]
                dest = unsigned / path.name
                shutil.copyfile(path, dest)
                if family == "rpm":
                    witness = result.get("construction_witness")
                    if isinstance(witness, dict) and isinstance(witness.get("reproducibility"), dict):
                        witness["reproducibility"]["observed_hosted_environment"] = {
                            "system": system, "platform": platform, "image_ref": environment["image_ref"]}
                    if verify_construction_witness(witness, dest, pid):
                        construction_witnesses[pid] = witness
                    completed_records["derivation"].add(pid)
                    completed_records["manifest"].add(pid)
                products[pid] = dest
                product_metadata[pid] = {"package_class": get_product_class(pid), "architecture": target,
                                         "package_file": dest.name, "sha256": digest(dest.read_bytes())}
                if family == "rpm":
                    lint_evidence[pid] = result["manifest"].get("rpmlint", {})
                    from rs9.rpm_evidence import write_policy_evidence
                    evaluation = result.get("policy_evaluation", result["manifest"].get("rpmlint_policy", {}))
                    lint_policy[pid] = {}
                    if evaluation:
                        try:
                            lint_policy[pid], policy_paths = write_policy_evidence(scratch / "diagnostics", evaluation)
                        except (ContractError, OSError) as cause:
                            error = ContractError("RPM_POLICY_CUSTODY", "Candidate policy evidence retention failed",
                                details={"substage": "rpm-policy-custody", "product": pid,
                                         "underlying_code": cause.code if isinstance(cause, ContractError) else "PACKAGE_FILESYSTEM",
                                         "field_path": getattr(cause, "field_path", "$"),
                                         "rule": getattr(cause, "rule", getattr(cause, "code", "PACKAGE_FILESYSTEM"))})
                            error.causal_receipt = None
                            error.rpmlint_evidence, error.rpmlint_policy = lint_evidence[pid], evaluation
                            error.package_path, error.package_sha256 = str(dest), digest(dest.read_bytes())
                            error.spec_sha256 = lint_evidence[pid].get("spec_sha256")
                            error.construction_witness = result.get("construction_witness")
                            error.completed_records = ["derivation", "manifest"]
                            raise error from cause
                        artifacts.extend(policy_paths)
                        completed_records["custody"].add(pid)
                    diagnostics = scratch / "diagnostics"
                    diagnostics.mkdir(exist_ok=True)
                    diagnostic = diagnostics / f"rpmlint-{pid}.json"
                    diagnostic.write_bytes(canonical(lint_evidence[pid]))
                    artifacts.append(diagnostic)
                    product_metadata[pid].update(rpm_identity=result["manifest"]["rpm_identity"],
                        rpm_payload_digest=result["manifest"]["rpm_payload_digest"])
                artifacts += [dest, work / ("pacman-manifest.json" if family == "pacman" else "rpm-manifest.json")]
                if family == "rpm" and result.get("srpm_path") is not None:
                    # Small noarch SRPM retained for exact SOURCEPKGID diagnosis.
                    srpm = Path(result["srpm_path"])
                    expected = result["construction_witness"]["reproducibility"]["source_rpm"]["sha256"]
                    if srpm.is_symlink() or digest(srpm.read_bytes()) != expected:
                        raise ContractError("CUSTODY_HASH", "Noarch source RPM differs from construction witness",
                                            details={"product": pid, "target": srpm.name})
                    source_dir = scratch / "unsigned-source"
                    source_dir.mkdir(exist_ok=True)
                    source_copy = source_dir / srpm.name
                    write_public_file(source_copy, srpm.read_bytes())
                    artifacts.append(source_copy)
            except (ContractError, OSError) as error:
                errors[pid] = error.code if isinstance(error, ContractError) else "PACKAGE_FILESYSTEM"
                receipts = builder.receipts[mark:]
                if hasattr(error, "causal_receipt"):
                    failed = error.causal_receipt
                elif isinstance(error, ContractError) and error.details.get("substage"):
                    failed = getattr(error, "receipt", None)
                elif errors[pid] == "RPM_INVENTORY_FAILED":
                    failed = getattr(error, "receipt", None)
                elif errors[pid] == "RPMLINT_FAILED":
                    failed = (getattr(error, "receipt", None) or
                              next((r for r in reversed(receipts) if Path(r.tool_name or (r.command[0] if r.command else "")).name == "rpmlint" and "--version" not in r.command), None))
                else:
                    failed = (getattr(error, "receipt", None) or
                              next((r for r in receipts if r.exit_code), receipts[-1] if receipts else None))
                details = {"product": pid, "family": family, "system": system, "substage": "package-build"}
                if failed:
                    tool_cmd = failed.tool_name or (failed.command[0] if failed.command else "")
                    tool_name = Path(tool_cmd).name if tool_cmd else "tool"
                    details.update(tool=tool_name, exit_code=failed.exit_code,
                                   stdout_sha256=failed.stdout_sha256, stderr_sha256=failed.stderr_sha256)
                if isinstance(error, ContractError):
                    details.update(error.details)
                failures[pid] = {"code": errors[pid], **safe_details(details)}
                if family == "rpm":
                    witness = getattr(error, "construction_witness", None)
                    pkg = getattr(error, "package_path", None)
                    secondary = failures[pid].setdefault("diagnostics", {})
                    if witness is not None:
                        try:
                            quarantine = scratch / "quarantine"
                            quarantine.mkdir(exist_ok=True)
                            retained = quarantine / Path(pkg).name
                            shutil.copyfile(pkg, retained)
                            if verify_construction_witness(witness, retained, pid):
                                construction_witnesses[pid] = witness
                                failures[pid]["construction_witness"] = witness
                                failures[pid]["quarantine_sha256"] = witness["package_sha256"]
                                secondary["construction"] = "verified-retained"
                                artifacts.append(retained)
                            else:
                                secondary["construction"] = "invalid-witness"
                        except (OSError, TypeError):
                            secondary["construction"] = "retention-failed"
                    for stage in getattr(error, "completed_records", []):
                        if stage in completed_records:
                            completed_records[stage].add(pid)
                inventory_diagnostic = getattr(error, "inventory_diagnostic", None)
                if family == "rpm" and inventory_diagnostic is not None:
                    secondary = failures[pid].setdefault("diagnostics", {})
                    try:
                        diagnostics = scratch / "diagnostics"
                        diagnostics.mkdir(exist_ok=True)
                        path = diagnostics / f"rpm-inventory-{pid}.json"
                        path.write_bytes(canonical(dict(inventory_diagnostic, product=pid)))
                        artifacts.append(path)
                        secondary["inventory"] = "retained"
                    except OSError:
                        secondary["inventory"] = "failed"
                coverage = getattr(error, "dependency_coverage", None)
                if family == "rpm" and coverage is not None:
                    diagnostics = scratch / "diagnostics"
                    diagnostics.mkdir(exist_ok=True)
                    path = diagnostics / f"rpm-dependency-coverage-{pid}.json"
                    path.write_bytes(canonical(coverage))
                    artifacts.append(path)
                if family == "rpm" and isinstance(error, ContractError) and (error.code == "RPMLINT_FAILED" or getattr(error,"rpmlint_evidence",None) is not None):
                    secondary = failures[pid].setdefault("diagnostics", {})
                    ev = getattr(error, "rpmlint_evidence", None) or getattr(error, "evidence", None)
                    if ev is not None:
                        lint_evidence[pid] = ev
                    failures[pid]["identities"] = {
                        "package_sha256": getattr(error, "package_sha256", "") or None,
                        "spec_sha256": getattr(error, "spec_sha256", "") or None,
                    }
                    try:
                        pkg_path = getattr(error, "package_path", None) or error.details.get("package_path")
                        if pkg_path and Path(pkg_path).is_file():
                            quarantine = scratch / "quarantine"
                            quarantine.mkdir(exist_ok=True)
                            quarantined = quarantine / Path(pkg_path).name
                            shutil.copyfile(pkg_path, quarantined)
                            if quarantined not in artifacts:
                                artifacts.append(quarantined)
                            secondary["quarantine"] = "retained"
                            failures[pid]["quarantine_sha256"] = digest(quarantined.read_bytes())
                        else:
                            secondary["quarantine"] = "unavailable"
                    except OSError:
                        secondary["quarantine"] = "failed"
                    try:
                        spec_path = getattr(error, "spec_path", None) or error.details.get("spec_path") or (work / "rpmbuild" / "SPECS" / f"{pid}.spec")
                        if spec_path and Path(spec_path).is_file():
                            diag_spec_dir = scratch / "diagnostics"
                            diag_spec_dir.mkdir(exist_ok=True)
                            spec_bytes = Path(spec_path).read_bytes()
                            diag_spec = diag_spec_dir / f"{pid}.spec.json"
                            diag_spec.write_bytes(canonical({
                                "schema": "rs9.generated-rpm-spec.v1", "product": pid,
                                "system": system, "spec_sha256": digest(spec_bytes),
                                "spec_bytes": len(spec_bytes), "spec": spec_bytes.decode("utf-8", errors="replace"),
                            }))
                            artifacts.append(diag_spec)
                            secondary["spec"] = "retained"
                        else:
                            secondary["spec"] = "unavailable"
                    except OSError:
                        secondary["spec"] = "failed"
                    try:
                        ev = getattr(error, "rpmlint_evidence", None) or getattr(error, "evidence", None) or error.details.get("evidence")
                        if ev is not None:
                            diag_ev_dir = scratch / "diagnostics"
                            diag_ev_dir.mkdir(exist_ok=True)
                            diag_ev = diag_ev_dir / f"rpmlint-{pid}.json"
                            diag_ev.write_bytes(canonical(ev))
                            artifacts.append(diag_ev)
                            secondary["findings"] = "retained"
                        else:
                            secondary["findings"] = "unavailable"
                    except OSError:
                        secondary["findings"] = "failed"
                    try:
                        policy = (getattr(error, "rpmlint_policy", None)
                                  or error.details.get("rpmlint_policy"))
                        if policy is not None:
                            from rs9.rpm_evidence import write_policy_evidence
                            lint_policy[pid], policy_paths = write_policy_evidence(scratch / "diagnostics", policy)
                            artifacts.extend(policy_paths)
                            secondary["policy"] = "retained"
                        else:
                            secondary["policy"] = "unavailable"
                    except (OSError, ContractError) as secondary_error:
                        secondary["policy"] = "failed"
                        secondary["policy_error"] = secondary_error.code if isinstance(secondary_error, ContractError) else "PACKAGE_FILESYSTEM"
        if family == "rpm":
            required_products = [intent["project"]["id"] for _, intent, _ in context["captures"]]
            build_failures = set(required_products) - set(construction_witnesses)
            lint_pass = (len(products) == 4 and not errors and len(lint_policy) == 4
                         and all(p.get("accepted") is True for p in lint_policy.values()))
            record_gates = rpm_stage_gates(required_products, construction_witnesses, completed_records, failures)
            gates.extend(record_gates)
            gates.append({"name": "rpm-lint-policy-accepted", "status": "pass" if lint_pass else "fail"})
        else:
            gates.append({"name": family + "-package-build", "status": "pass" if len(products) == 4 and not errors else "fail"})
        if errors:
            try:
                diag_dir = scratch / "diagnostics"
                diag_dir.mkdir(exist_ok=True)
                diag_file = diag_dir / "build-errors.json"
                diag_file.write_bytes(canonical({"schema": "rs9.build-errors.v1alpha1", "family": family, "system": system,
                                                "errors": errors, "product_failures": failures, "gates": gates}))
                artifacts.append(diag_file)
            except OSError:
                for failure in failures.values():
                    failure.setdefault("diagnostics", {})["lane_record"] = "failed"
        if family == "rpm":
            preparation_pass = client_runtime.get("status") == "pass"
            gates.append({"name": "rpm-client-preparation", "status": "pass" if preparation_pass else "fail",
                          "reason": client_runtime.get("reason")})
            if preparation_pass and lint_pass:
                try:
                    verify_client_image(host, client_tag, client_runtime, environment=environment, arch=arch, system=system)
                except ContractError as cause:
                    preparation_pass = False
                    gates[-1].update(status="fail", reason=cause.code, causal_substage="client-image-verification")
        if family == "rpm" and (errors or not lint_pass or not preparation_pass or any(g["status"] != "pass" for g in record_gates)):
            # Retained package identities prove construction independently of lint.
            # Either failure stops custody, indexing/signing and DNF.
            failed_record = next((g["name"] for g in record_gates if g["status"] == "fail"), None)
            reason = ("blocked-by:" + failed_record if failed_record else
                      "blocked-by:rpm-lint-policy-accepted" if not lint_pass else
                      "blocked-by:rpm-client-preparation" if not preparation_pass else "blocked-by:rpm-policy-custody")
            gates.extend({"name":n,"status":"not-run","reason":reason}
                         for n in ("rpm-repository-indexing","rpm-client-qualification",
                                   "burst-native-addon-target","burst-native-addon-load"))
            gates.extend({"name":"rpm-trust.tamper."+kind,"status":"not-run","reason":reason}
                         for kind in ("package","index","signature","wrongkey"))
            return_result = {"gates":gates,"artifacts":artifacts,
                    "production_promotion_blockers": ["rpm-lint-policy-exceptions-not-raw-clean-not-fedora-qualified"]
                        if any(p.get("accepted_findings") for p in lint_policy.values()) else [],
                    "details":{"environment":environment,"build_errors":errors,"product_failures":failures,
                               "rpm_evidence_contract": "rs9.rpm-evidence-contract.v2",
                               "client_runtime_evidence": client_runtime,
                               "caller_source_evidence": caller_diagnostic(caller_evidence),
                               "construction_witnesses": construction_witnesses,
                               "lint_evidence":lint_evidence, "rpm_lint_raw":lint_evidence,
                               "rpm_lint_policy":lint_policy,
                               "diagnostic_scope":"candidate-only-build-and-lint-failures"}}
            return return_result
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
        late_phase = family == "rpm"
        current_substage = "custody-bundle"
        bundle = scratch / "unsigned-custody"
        bundle.mkdir()
        write_custody_bundle(bundle, packages={p.name:p.read_bytes() for p in products.values()}, family=family, system=system,
                             authentication_sha256=context["authentication_sha256"], source_commit=context["binding"]["source_commit"])
        artifacts.extend(p for p in bundle.rglob("*") if p.is_file())
        if family == "rpm":
            custody_manifest = bundle / "custody-manifest.json"
            completed_operations["unsigned_custody"] = {"manifest_sha256": digest(custody_manifest.read_bytes()),
                                                       "merkle": json.loads(custody_manifest.read_bytes())["merkle"]}
            _verify_unsigned_products(products, product_metadata, bundle)
        current_substage = "fixture-preparation"
        fixture_dir = scratch / "fixture"
        fixture_dir.mkdir()
        with _fixture_scope(fixture_dir, secondary_diagnostics, preserve_cleanup=family != "rpm") as (fixture, wrong):
            (scratch / "fixture-identity.json").write_bytes(canonical({"used": True, "production": False,
                "purpose": "NON-PRODUCTION CANDIDATE TEST ONLY", "fingerprint": fixture.primary_fingerprint,
                "wrong_key_fingerprint": wrong.primary_fingerprint}))
            keys = scratch / "keys"
            write_keys(keys, fixture, write_file=write_public_file if family == "rpm" else None)
            repo = scratch / family
            directory = repo / ("x86_64" if family == "pacman" else "fedora/43/" + arch)
            package_directory = directory if family == "pacman" else directory / "Packages"
            if family == "rpm":
                prepare_public_directory(package_directory, repo)
            else:
                package_directory.mkdir(parents=True)
            current_substage = "package-signing"
            for pid, path in products.items():
                testcopy = package_directory / path.name
                if family == "rpm":
                    write_public_file(testcopy, path.read_bytes())
                else:
                    shutil.copyfile(path, testcopy)
                if family == "rpm":
                    failed_product = pid
                    signer = ContainerRunner(host,tag,platform=platform,mounts=[(str(scratch),str(scratch),True)], user=_user())
                    metadata = product_metadata[pid]
                    identities.append(sign_rpm(signer, testcopy, fixture, expected={
                        "package_sha256": metadata["sha256"], "rpm_identity": metadata["rpm_identity"],
                        "rpm_payload_digest": metadata["rpm_payload_digest"]},
                        wrong_fixture=wrong,
                        diagnostics_dir=scratch / "diagnostics"))
                    failed_product = None
                else:
                    (package_directory / (path.name + ".sig")).write_bytes(fixture.detach_sign(path.read_bytes(), armor=False))
                    fixture.verify(path.read_bytes(), (package_directory / (path.name + ".sig")).read_bytes())
            current_substage = "repository-metadata"
            if family == "rpm":
                tool = ContainerRunner(host, tag, platform=platform, mounts=[(str(scratch), str(scratch), True)], user=_user())
                meta_receipt = checked(tool, metadata_command(directory), substage="repository-metadata")
                repository_reports[arch] = sign_metadata(fixture, directory, receipt=meta_receipt)
                public_report = audit_owned_tree(repo)
                if public_report["status"] != "pass":
                    raise ContractError("RPM_REPOSITORY_OPERATION", "Public repository audit failed",
                                        details={"operation": "repodata-ownership-audit", "substage": "ownership-audit",
                                                 "target": ".", "causal_code": "AUDIT_FAILED"})
                for home in (fixture.homedir, wrong.homedir):
                    report = audit_owned_tree(home, expected_file_mode=None, expected_dir_mode=None)
                    if report["status"] != "pass":
                        raise ContractError("RPM_REPOSITORY_OPERATION", "Fixture writer ownership audit failed",
                                            details={"operation": "package-signing", "substage": "fixture-ownership-audit",
                                                     "target": "fixture", "causal_code": "AUDIT_FAILED"})
                completed_operations["repository"] = {"metadata": repository_reports, "public_tree": public_report}
                _verify_unsigned_products(products, product_metadata, bundle)
                spec_for = lambda dirs: dnf_spec(dirs["rpm"], keys, arch)
            else:
                tool = ContainerRunner(host, tag, platform=platform, mounts=[(str(scratch), str(scratch), True)])
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
            current_substage = "client-preparation"
            neb = next(c for c,i,_ in context["captures"] if i["project"]["id"] == "theme-forge-nebular-fusion")
            prepared = prepare_smoke(neb, context["captures"], context["client"], scratch / "application-smoke")
            current_substage = "client-cycle"
            if family == "rpm":
                client_image = verify_client_image(host, client_tag, client_runtime,
                                                   environment=environment, arch=arch, system=system)
            else:
                provision_image(host, "pacman", environment["image_ref"], platform, client_tag,
                                [*environment["preprovisioned_packages"], *client_tools])
                client_image = client_tag
            spec = spec_for(dirs)
            rows, evidence = client_cycle(host, spec, image=client_image, platform=platform,
                       products=list(products), repository=repository, prefix=family + "-client", smoke=prepared, system=system,
                       burst_record=_burst_release_record(context["captures"], system),
                       burst_scratch=scratch / "burst-native-probe")
            gates.extend(rows)
            gates.extend(burst_client_gates(rows))
            current_substage = "tamper-cycle"
            (scratch / "tamper").mkdir()
            if family == "rpm":
                verify_client_image(host, client_tag, client_runtime, environment=environment, arch=arch, system=system)
            tamper_rows = tamper_cycle(host, spec_for, "dnf" if family == "rpm" else "pacman", dirs,
                    image=client_image, platform=platform, product=list(products)[0], work=scratch / "tamper", wrong_signer=wrong, arch=arch,
                    kinds=("package","index","signature","wrongkey"), prefix=family+"-trust",
                    positive_control=evidence.get(list(products)[0],{}).get("positive_control"))
            gates.extend(tamper_rows)
            gates.append({"name": family + "-client-qualification", "status": _fold([*rows, *tamper_rows])})
            artifacts.extend(p for p in [*repo.rglob("*"), *keys.rglob("*")] if p.is_file() and not p.is_symlink())
            manifest = scratch / "native-qualification.json"
            manifest.write_bytes(canonical({"schema": "rs9.native-hosted.v1alpha1", "production": False,
                "environment": environment, "fixture_fingerprint": fixture.primary_fingerprint,
                "rpm_identities": identities, "products": product_metadata, "client": evidence, "build_errors": errors}))
            artifacts.append(manifest)
            artifacts.extend(sorted((scratch / "diagnostics").glob("rpm-signed-query-probe-*.json")))
    except Exception as error:
        if family != "rpm" or not late_phase:
            raise
        secondary_diagnostics.extend(getattr(error, "secondary_diagnostics", []))
        if hasattr(error, "rpm_probe_record"):
            completed_operations["unwritten_signing_probe"] = error.rpm_probe_record
        causal = dict(error.details) if isinstance(error, ContractError) else {}
        code = error.code if isinstance(error, ContractError) else type(error).__name__
        substage = causal.get("substage", current_substage)
        if code in {"CLIENT_IMAGE_DRIFT", "CLIENT_IMAGE_IDENTITY"}:
            failed_gate = "rpm-client-preparation"
            substage = "client-image-verification"
        elif current_substage in {"client-preparation", "client-cycle", "tamper-cycle"}:
            failed_gate = "rpm-client-qualification"
        else:
            failed_gate = "rpm-repository-indexing"
        failure = {"operation": causal.get("operation", current_substage), "code": code,
                   "causal_substage": current_substage, **safe_details(causal)}
        gate = next((g for g in gates if g["name"] == failed_gate), None)
        if gate is None:
            gate = {"name": failed_gate}
            gates.append(gate)
        gate.update(status="fail", reason=code, causal_substage=substage)
        pending = ["rpm-repository-indexing", "rpm-client-qualification", "burst-native-addon-target",
                   "burst-native-addon-load", *["rpm-trust.tamper." + kind for kind in
                                                ("package", "index", "signature", "wrongkey")]]
        present = {g["name"] for g in gates}
        gates.extend({"name": name, "status": "not-run", "reason": "blocked-by:" + failed_gate}
                     for name in pending if name not in present)
        try:
            diagnostic = scratch / "diagnostics" / ("rpm-repository-failure-" + system + ".json")
            diagnostic.parent.mkdir(exist_ok=True)
            diagnostic.write_bytes(canonical({"schema": "rs9.rpm-late-failure.v1alpha1", "system": system,
                                              "failed_gate": failed_gate, **failure}))
            artifacts.append(diagnostic)
        except Exception as secondary:
            secondary_diagnostics.append({"operation": "failure-diagnostic-write",
                                          "code": getattr(secondary, "code", type(secondary).__name__)})
        return_result = {"gates": gates, "artifacts": artifacts,
            "details": {"environment": environment, "rpm_evidence_contract": "rs9.rpm-evidence-contract.v2",
                        "rpm_lint_raw": lint_evidence, "rpm_lint_policy": lint_policy,
                        "construction_witnesses": construction_witnesses,
                        "client_runtime_evidence": client_runtime, "caller_source_evidence": caller_diagnostic(caller_evidence),
                        "operation_failure": failure, "repository_failure": failure,
                        "completed_operations": completed_operations, "rpm_metadata_reports": repository_reports,
                        "secondary_diagnostics": secondary_diagnostics,
                        "completed_evidence_identities": {
                            "construction_witnesses": {pid: w.get("package_sha256") for pid, w in construction_witnesses.items()},
                            **{k: sorted(v) for k, v in completed_records.items()}}},
            "production_promotion_blockers": ["rpm-lint-policy-exceptions-not-raw-clean-not-fedora-qualified"]
                if any(p.get("accepted_findings") for p in lint_policy.values()) else []}
        if failed_product:
            return_result["details"]["product_failures"] = {failed_product: failure}
        error.partial_result = return_result
        if not isinstance(error, (ContractError, OSError)):
            raise
        return return_result
    finally:
        if family == "rpm" and late_phase:
            # Retain only public objects and bounded probe diagnostics, including on failure.
            for tree in (repo, keys):
                if tree is not None:
                    try:
                        artifacts.extend(p for p in tree.rglob("*") if p.is_file() and not p.is_symlink() and p not in artifacts)
                    except OSError as secondary:
                        secondary_diagnostics.append({"operation": "public-artifact-retention", "code": type(secondary).__name__})
            try:
                probes = sorted((scratch / "diagnostics").glob("rpm-signed-query-probe-*.json"))
                probe_hashes = {}
                completed_operations["package_signing"] = {"identities": identities, "probes": probe_hashes}
                for probe in probes:
                    try:
                        probe_hashes[probe.name] = digest(probe.read_bytes())
                        if probe not in artifacts:
                            artifacts.append(probe)
                    except OSError as secondary:
                        artifacts[:] = [p for p in artifacts if p != probe]
                        secondary_diagnostics.append({"operation": "signing-probe-read", "target": probe.name,
                                                      "code": type(secondary).__name__})
            except OSError as secondary:
                secondary_diagnostics.append({"operation": "signing-probe-selection", "code": type(secondary).__name__})
            try:
                _verify_unsigned_products(products, product_metadata, bundle)
                completed_operations["unsigned_custody_unchanged"] = "pass"
            except Exception as secondary:
                # Failed reads or absent bundles do not prove custody mutation.
                completed_operations["unsigned_custody_unchanged"] = (
                    "fail" if isinstance(secondary, ContractError) and secondary.code == "CUSTODY_HASH"
                    else "not-run")
                secondary_diagnostics.append({"operation": "custody-verification", "code": getattr(secondary, "code", type(secondary).__name__)})
        cleanup_evidence = {}
        try:
            cleanup_receipt = host.run(["docker", "rmi", "-f", tag, client_tag])
            cleanup_evidence = {
                "status": ("not-run" if not cleanup_receipt.executed else
                           "pass" if cleanup_receipt.exit_code == 0 else "fail"),
                "receipt": _receipt_summary(cleanup_receipt),
            }
        except Exception as cleanup_err:
            cleanup_evidence = {
                "status": "fail",
                "error": getattr(cleanup_err, "code", type(cleanup_err).__name__),
            }
        if return_result is not None and isinstance(return_result.get("details"), dict):
            return_result["details"]["cleanup_evidence"] = cleanup_evidence
    details = {"environment": environment, "cleanup_evidence": cleanup_evidence,
               "secondary_diagnostics": secondary_diagnostics}
    promotion = []
    if family == "rpm":
        details.update(completed_operations=completed_operations, rpm_metadata_reports=repository_reports,
                       rpm_lint_raw=lint_evidence, rpm_lint_policy=lint_policy,
                       rpm_evidence_contract="rs9.rpm-evidence-contract.v2",
                       client_runtime_evidence=client_runtime, caller_source_evidence=caller_diagnostic(caller_evidence),
                       construction_witnesses=construction_witnesses)
        if any(p.get("accepted_findings") for p in lint_policy.values()):
            promotion.append("rpm-lint-policy-exceptions-not-raw-clean-not-fedora-qualified")
    if errors:
        details["build_errors"] = errors
    return_result = {"gates": gates, "artifacts": artifacts, "details": details,
            "production_promotion_blockers": promotion}
    return return_result
