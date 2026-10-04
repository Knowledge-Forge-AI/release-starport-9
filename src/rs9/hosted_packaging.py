"""Unsigned custody plus real fixture-signed pacman and RPM client qualification."""
import json
import os
from pathlib import Path
import shutil
import uuid

from rs9.build_native import SubprocessRunner, REQUIRED_COMMANDS
from rs9.build_pacman import build_pacman_candidate
from rs9.build_rpm import build_rpm_candidate
from rs9.errors import ContractError, safe_details
from rs9.hosted_native import provision, container_tool_facts
from rs9.hosted_wheels import _resolve_offline_npm_archives
from rs9.release_core import digest
from rs9.pages_candidate import _fixture_public_armor
from rs9.scratch import canonical
from rs9.signing_fixture import SigningFixture

FIXTURE_ARMOR = "rs9-candidate-fixture-NONPRODUCTION.asc"
FIXTURE_KEYRING = "rs9-candidate-fixture-NONPRODUCTION.gpg"


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


def sign_rpm(runner, path, fixture):
    """Sign only a retained copy; production-candidate bytes stay unsigned."""
    before = digest(path.read_bytes())
    checked(runner, ["rpmsign", "--define", "_gpg_name " + fixture.primary_fingerprint,
                    "--define", "_gpg_path " + str(fixture.homedir),
                    "--define", "__gpg " + fixture.gpg, "--addsign", str(path)],
            substage="rpm-sign")
    after = digest(path.read_bytes())
    if before == after:
        raise ContractError("RPM_SIGNING", "Fixture RPM header was not signed",
                            details={"substage": "rpm-sign", "tool": "rpmsign"})
    # rpmkeys uses an isolated RPM trust database, never the operator's database.
    db = fixture.homedir / "fixture-rpmdb"
    db.mkdir(exist_ok=True)
    public = fixture.homedir / FIXTURE_ARMOR
    public.write_bytes(_fixture_public_armor(fixture))
    checked(runner, ["rpmkeys", "--dbpath", str(db), "--import", str(public)],
            substage="rpm-import")
    result = checked(runner, ["rpmkeys", "--dbpath", str(db), "--checksig", str(path)],
                     substage="rpm-checksig")
    if "OK" not in result.stdout_text or "NOT OK" in result.stdout_text:
        raise ContractError("RPM_SIGNING", "Fixture RPM signature validation failed",
                            details={"substage": "rpm-checksig", "tool": "rpmkeys",
                                     "stdout_sha256": result.stdout_sha256, "stderr_sha256": result.stderr_sha256})
    return {"unsigned_sha256": before, "fixture_signed_sha256": after,
            "fixture_fingerprint": fixture.primary_fingerprint, "production": False}


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
    platform, arch = environment["platform"], "aarch64" if "aarch64" in system else "x86_64"
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
                artifacts += [dest, work / ("pacman-manifest.json" if family == "pacman" else "rpm-manifest.json")]
            except (ContractError, OSError) as error:
                errors[pid] = error.code if isinstance(error, ContractError) else "PACKAGE_FILESYSTEM"
                receipts = builder.receipts[mark:]
                failed = next((r for r in receipts if r.exit_code), receipts[-1] if receipts else None)
                details = {"product": pid, "family": family, "system": system, "substage": "package-build"}
                if failed:
                    details.update(tool=Path(failed.tool_name or failed.argv[0]).name, exit_code=failed.exit_code,
                                   stdout_sha256=failed.stdout_sha256, stderr_sha256=failed.stderr_sha256)
                if isinstance(error, ContractError):
                    details.update(error.details)
                failures[pid] = {"code": errors[pid], **safe_details(details)}
        gates.append({"name": family + "-package-build", "status": "pass" if len(products) == 4 and not errors else "fail"})
        if family == "rpm":
            gates.append({"name": "rpm-rpmlint-clean", "status": "pass" if len(products) == 4 and not errors else "fail"})
        if errors:
            diag_dir = scratch / "diagnostics"
            diag_dir.mkdir(exist_ok=True)
            diag_file = diag_dir / "build-errors.json"
            diag_file.write_bytes(canonical({"schema": "rs9.build-errors.v1alpha1", "family": family, "system": system,
                                            "errors": errors, "product_failures": failures}))
            artifacts.append(diag_file)
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
                    identities.append(sign_rpm(signer, testcopy, fixture))
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
            spec["mounts"].append((str(scratch),str(scratch),True))
            rows, evidence = client_cycle(host, spec, image=client_tag, platform=platform,
                       products=list(products), repository=repository, prefix=family + "-client", smoke=prepared, system=system,
                       burst_record=_burst_release_record(context["captures"], system),
                       burst_scratch=scratch / "burst-native-probe")
            (scratch / "tamper").mkdir()
            rows += tamper_cycle(host, spec_for, "dnf" if family == "rpm" else "pacman", dirs,
                    image=client_tag, platform=platform, product=list(products)[0], work=scratch / "tamper", wrong_signer=wrong, arch=arch,
                    kinds=("package","index","signature","wrongkey"), prefix=family+"-trust")
            gates.extend(rows)
            gates.extend(burst_client_gates(rows))
            gates.append({"name": family + "-client-qualification", "status": _fold(rows)})
            artifacts.extend(p for p in [*repo.rglob("*"), *keys.rglob("*")] if p.is_file() and not p.is_symlink())
            manifest = scratch / "native-qualification.json"
            manifest.write_bytes(canonical({"schema": "rs9.native-hosted.v1alpha1", "production": False,
                "environment": environment, "fixture_fingerprint": fixture.primary_fingerprint,
                "rpm_identities": identities, "products": product_metadata, "client": evidence, "build_errors": errors}))
            artifacts.append(manifest)
    finally:
        try:
            host.run(["docker", "rmi", "-f", tag, client_tag])
        except (ContractError, OSError):
            pass
    details = {"environment": environment}
    if errors:
        details["build_errors"] = errors
    return {"gates": gates, "artifacts": artifacts, "details": details}
