"""Narrow helper functions for safe public RPM repository tree creation and signing.

Provides safe directory creation, file writing, compatible writer ownership audit,
and metadata signing with substage error diagnostics.
"""

from __future__ import annotations

import errno
import hashlib
import os
from pathlib import Path
import stat
from typing import Any, Mapping

from rs9.errors import ContractError


def metadata_command(directory: Path | str, *, sha256: bool = False) -> list[str]:
    """Set the creator's umask inside the container without interpolating paths."""
    return ["sh", "-c", 'umask 022; exec "$@"', "rs9-rpm-metadata",
            "createrepo_c", "--no-database", "--compress-type", "gz",
            *(["-s", "sha256"] if sha256 else []), str(directory)]


def command_tool(argv: list[str]) -> str:
    """Name the metadata tool behind only the exact owned umask wrapper."""
    if argv[:5] == metadata_command(".")[:5]:
        return "createrepo_c"
    return Path(argv[0]).name if argv else "tool"


def _relationships(path: Path) -> dict[str, Any]:
    """Observed inode relationships only; unavailable stats are not guessed."""
    result = {}
    parent = target = None
    try:
        parent = path.parent.lstat()
        result["parent_mode"] = f"0{stat.S_IMODE(parent.st_mode):03o}"
    except OSError:
        pass
    try:
        target = path.lstat()
        result.update(target_exists=True, target_mode=f"0{stat.S_IMODE(target.st_mode):03o}")
    except FileNotFoundError:
        result["target_exists"] = False
    except OSError:
        pass
    owner = target or parent
    if owner is not None:
        result.update(writer_is_owner=owner.st_uid == os.geteuid(), owner_is_root=owner.st_uid == 0,
                      group_matches=owner.st_gid == os.getegid())
    return result


def _build_details(
    operation: str,
    substage: str,
    target: str,
    *,
    errno_val: int | str | None = None,
    causal_code: str | None = None,
    writer_is_owner: bool | None = None,
    owner_is_root: bool | None = None,
    target_mode: str | int | None = None,
    parent_mode: str | int | None = None,
    target_exists: bool | None = None,
    receipt: Any = None,
    extra: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if isinstance(errno_val, int):
        errno_str = errno.errorcode.get(errno_val, "unknown")
    elif isinstance(errno_val, str):
        errno_str = errno_val
    else:
        errno_str = None

    if isinstance(target_mode, int):
        t_mode_str = f"0{target_mode:03o}"
    elif isinstance(target_mode, str):
        t_mode_str = target_mode
    else:
        t_mode_str = None

    if isinstance(parent_mode, int):
        p_mode_str = f"0{parent_mode:03o}"
    elif isinstance(parent_mode, str):
        p_mode_str = parent_mode
    else:
        p_mode_str = None

    valid_operations = {
        "rpm-repository", "repository-metadata", "package-signing",
        "repodata-index-read", "repodata-fixture-sign", "repodata-signature-write",
        "repodata-signature-verify", "repodata-public-modes", "repodata-ownership-audit"
    }
    op_val = operation if operation in valid_operations else "repository-metadata"

    details: dict[str, Any] = {
        "operation": op_val,
        "substage": substage,
        "target": target,
        "errno": errno_str,
        "causal_code": causal_code,
        "writer_is_owner": writer_is_owner,
        "owner_is_root": owner_is_root,
        "target_mode": t_mode_str,
        "parent_mode": p_mode_str,
        "target_exists": target_exists,
    }
    if receipt is not None:
        details["stdout_sha256"] = getattr(receipt, "stdout_sha256", None)
        details["stderr_sha256"] = getattr(receipt, "stderr_sha256", None)
        details["exit_code"] = getattr(receipt, "exit_code", None)
        details["tool"] = command_tool(receipt.command)
    if extra:
        details.update(extra)
    return {k: v for k, v in details.items() if v is not None}


def prepare_public_directory(directory: Path | str, root: Path | str) -> Path:
    """Prepares directory ensuring explicit levels under root exist with mode 0o755.

    Operates strictly within root and never modifies ancestors above root.
    Rejects symlinks and traversal escaping root.
    """
    raw_root = Path(root)
    raw_dir = Path(directory)

    if raw_root.is_symlink():
        raise ContractError(
            "RPM_REPOSITORY_OPERATION",
            f"Repository root cannot be a symlink: {raw_root.name}",
            details=_build_details(
                "rpm-repository",
                "directory-preparation",
                raw_root.name or ".",
                causal_code="SYMLINK_REJECTED",
            ),
        )

    root_resolved = raw_root.resolve()

    # Determine unresolved relative parts if possible to detect symlinks in the path
    try:
        rel_unresolved = raw_dir.relative_to(raw_root)
    except ValueError:
        try:
            rel_unresolved = raw_dir.resolve().relative_to(root_resolved)
        except ValueError:
            raise ContractError(
                "RPM_REPOSITORY_OPERATION",
                f"Directory {raw_dir.name} escapes repository root",
                details=_build_details(
                    "rpm-repository",
                    "directory-preparation",
                    raw_dir.name,
                    causal_code="ESCAPE_DETECTED",
                ),
            )

    # Check resolved escape as well
    if ".." in rel_unresolved.parts:
        raise ContractError("RPM_REPOSITORY_OPERATION", "Repository traversal refused",
                            details={"operation": "rpm-repository", "substage": "directory-preparation",
                                     "causal_code": "ESCAPE_DETECTED"})
    resolved_dir = (root_resolved / rel_unresolved).resolve()
    try:
        resolved_dir.relative_to(root_resolved)
    except ValueError:
        raise ContractError(
            "RPM_REPOSITORY_OPERATION",
            f"Directory {raw_dir.name} escapes repository root",
            details=_build_details(
                "rpm-repository",
                "directory-preparation",
                raw_dir.name,
                causal_code="ESCAPE_DETECTED",
            ),
        )

    if not root_resolved.exists():
        root_resolved.mkdir(mode=0o755)
    os.chmod(root_resolved, 0o755)

    current = root_resolved
    current_unresolved = raw_root
    for part in rel_unresolved.parts:
        current_unresolved = current_unresolved / part
        if current_unresolved.is_symlink():
            raise ContractError(
                "RPM_REPOSITORY_OPERATION",
                f"Symlink rejected in public tree path: {current_unresolved.name}",
                details=_build_details(
                    "rpm-repository",
                    "directory-preparation",
                    rel_unresolved.as_posix(),
                    causal_code="SYMLINK_REJECTED",
                ),
            )
        current = current / part
        if current.is_symlink():
            raise ContractError(
                "RPM_REPOSITORY_OPERATION",
                f"Symlink rejected in public tree path: {current.name}",
                details=_build_details(
                    "rpm-repository",
                    "directory-preparation",
                    rel_unresolved.as_posix(),
                    causal_code="SYMLINK_REJECTED",
                ),
            )
        if not current.exists():
            current.mkdir(mode=0o755)
        elif not current.is_dir():
            raise ContractError(
                "RPM_REPOSITORY_OPERATION",
                f"Path component is not a directory: {current.name}",
                details=_build_details(
                    "rpm-repository",
                    "directory-preparation",
                    rel_unresolved.as_posix(),
                    causal_code="NOT_A_DIRECTORY",
                ),
            )
        os.chmod(current, 0o755)

    return current


def write_public_file(path: Path | str, data: bytes) -> Path:
    """Writes data to path with public mode 0o644 independently of umask.

    Rejects symlinks and never modifies parent directories recursively.
    """
    p = Path(path)
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise ContractError(
            "RPM_REPOSITORY_OPERATION",
            "File data must be bytes",
            details=_build_details(
                "rpm-repository",
                "file-write",
                p.name,
                causal_code="INVALID_DATA",
            ),
        )

    if p.is_symlink():
        raise ContractError(
            "RPM_REPOSITORY_OPERATION",
            f"Symlink target rejected: {p.name}",
            details=_build_details(
                "rpm-repository",
                "file-write",
                p.name,
                causal_code="SYMLINK_REJECTED",
            ),
        )
    parent = p.parent
    if parent.is_symlink():
        raise ContractError(
            "RPM_REPOSITORY_OPERATION",
            f"Symlink parent rejected: {parent.name}",
            details=_build_details(
                "rpm-repository",
                "file-write",
                p.name,
                causal_code="SYMLINK_REJECTED",
            ),
        )
    if not parent.is_dir():
        raise ContractError(
            "RPM_REPOSITORY_OPERATION",
            f"Parent directory is missing or not a directory: {parent.name}",
            details=_build_details(
                "rpm-repository",
                "file-write",
                p.name,
                causal_code="MISSING_PARENT",
            ),
        )

    tmp_path = parent / f".tmp_{p.name}_{os.urandom(8).hex()}"
    try:
        flags = os.O_CREAT | os.O_WRONLY | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(tmp_path, flags, 0o644)
        try:
            os.fchmod(fd, 0o644)
            stream = os.fdopen(fd, "wb")
            fd = None
            with stream as f:
                f.write(data)
        finally:
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
        os.replace(tmp_path, p)
        os.chmod(p, 0o644)
    except OSError as err:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise ContractError(
            "RPM_REPOSITORY_OPERATION",
            "Public repository file write failed",
            details=_build_details(
                "rpm-repository",
                "file-write",
                p.name,
                errno_val=err.errno,
                causal_code=type(err).__name__,
                extra=_relationships(p),
            ),
        ) from err
    return p


def audit_owned_tree(
    root: Path | str,
    *,
    expected_file_mode: int | None = 0o644,
    expected_dir_mode: int | None = 0o755,
) -> dict[str, Any]:
    """Audits ownership and public modes of a repository tree.

    Verifies that all files and directories are owned by a compatible writer,
    have explicit public modes (0o755 for dirs, 0o644 for files), and contain no symlinks.
    Output contains NO absolute paths and NO numeric IDs.
    """
    root_path = Path(root)
    if root_path.is_symlink() or not root_path.exists():
        return {
            "status": "fail",
            "compatible": False,
            "total_files": 0,
            "total_directories": 0,
            "writer": "root" if os.getuid() == 0 else "self",
            "owner_summary": {"self": 0, "root": 0, "other": 0},
            "violations": [{"path": "", "issue": "missing-root", "owner": "none", "mode": None}],
        }

    current_uid = os.geteuid()
    writer_is_root = current_uid == 0
    writer_label = "root" if writer_is_root else "self"

    violations: list[dict[str, Any]] = []
    owner_counts = {"self": 0, "root": 0, "other": 0}
    total_files = 0
    total_dirs = 0

    def check_node(p: Path, rel_path: str) -> None:
        nonlocal total_files, total_dirs
        try:
            st = os.lstat(p)
        except OSError:
            violations.append({"path": rel_path, "issue": "stat-error", "owner": "unknown", "mode": None})
            return

        is_symlink = stat.S_ISLNK(st.st_mode)
        is_dir = stat.S_ISDIR(st.st_mode)
        is_reg = stat.S_ISREG(st.st_mode)

        if st.st_uid == 0:
            owner_label = "root"
        elif st.st_uid == current_uid:
            owner_label = "self"
        else:
            owner_label = "other"

        owner_counts[owner_label] += 1
        mode_val = stat.S_IMODE(st.st_mode)
        mode_str = oct(mode_val)

        if not writer_is_root and owner_label != "self":
            violations.append({
                "path": rel_path,
                "issue": f"incompatible-owner:{owner_label}",
                "owner": owner_label,
                "mode": mode_str,
            })

        if is_symlink:
            violations.append({
                "path": rel_path,
                "issue": "symlink-rejected",
                "owner": owner_label,
                "mode": mode_str,
            })
            return

        if is_dir:
            total_dirs += 1
            if expected_dir_mode is not None and mode_val != expected_dir_mode:
                violations.append({
                    "path": rel_path,
                    "issue": "directory-mode-mismatch",
                    "owner": owner_label,
                    "mode": mode_str,
                    "expected_mode": oct(expected_dir_mode),
                })
        elif is_reg:
            total_files += 1
            if expected_file_mode is not None and mode_val != expected_file_mode:
                violations.append({
                    "path": rel_path,
                    "issue": "file-mode-mismatch",
                    "owner": owner_label,
                    "mode": mode_str,
                    "expected_mode": oct(expected_file_mode),
                })
        elif expected_dir_mode is not None or expected_file_mode is not None:
            violations.append({
                "path": rel_path,
                "issue": "special-file-rejected",
                "owner": owner_label,
                "mode": mode_str,
            })

    check_node(root_path, "")

    def walk_error(error):
        # The diagnostic cannot contain the absolute path from OSError.filename.
        violations.append({"path": "", "issue": "walk-error", "owner": "unknown",
                           "mode": None, "errno": errno.errorcode.get(error.errno, "unknown")})

    for dirpath, dirnames, filenames in os.walk(root_path, onerror=walk_error):
        dp = Path(dirpath)
        try:
            rel_dir = dp.relative_to(root_path).as_posix()
        except ValueError:
            rel_dir = ""
        if rel_dir == ".":
            rel_dir = ""

        for d in sorted(dirnames):
            sub = dp / d
            rel = f"{rel_dir}/{d}" if rel_dir else d
            check_node(sub, rel)

        for f in sorted(filenames):
            sub = dp / f
            rel = f"{rel_dir}/{f}" if rel_dir else f
            check_node(sub, rel)

    is_compatible = not any("incompatible-owner" in v.get("issue", "") for v in violations)
    status = "pass" if (is_compatible and not violations) else "fail"

    return {
        "status": status,
        "compatible": is_compatible,
        "total_files": total_files,
        "total_directories": total_dirs,
        "writer": writer_label,
        "owner_summary": owner_counts,
        "violations": violations[:40],
    }


def sign_metadata(fixture: Any, directory: Path | str, receipt: Any = None) -> dict[str, Any]:
    """Signs repodata/repomd.xml in directory, verifies signature, and audits public tree modes.

    Splits index read, fixture sign, signature write (0644), verify, public modes and ownership audit.
    Raises ContractError('RPM_REPOSITORY_OPERATION', ..., details=...) on any failure.
    """
    dir_path = Path(directory)
    if not dir_path.is_dir() or dir_path.is_symlink():
        raise ContractError(
            "RPM_REPOSITORY_OPERATION",
            f"Invalid repository directory: {dir_path.name or str(dir_path)}",
            details=_build_details(
                "repodata-index-read",
                "index-read",
                dir_path.name or ".",
                causal_code="INVALID_DIRECTORY",
                receipt=receipt,
            ),
        )

    # Substage 1: Index read; stat and open failures share the same causal boundary.
    index_file = dir_path / "repodata" / "repomd.xml"
    try:
        if index_file.is_symlink() or index_file.parent.is_symlink():
            raise ContractError("RPM_REPOSITORY_OPERATION", "Linked metadata index refused",
                                details=_build_details("repodata-index-read", "index-read",
                                    "repodata/repomd.xml", causal_code="SYMLINK_REJECTED", receipt=receipt))
        index_bytes = index_file.read_bytes()
    except OSError as err:
        raise ContractError("RPM_REPOSITORY_OPERATION", "Repository metadata index read failed",
                            details=_build_details("repodata-index-read", "index-read",
                                "repodata/repomd.xml", errno_val=err.errno, causal_code=type(err).__name__,
                                extra=_relationships(index_file), receipt=receipt)) from err

    # Substage 2: Fixture sign
    if fixture is None:
        raise ContractError(
            "RPM_REPOSITORY_OPERATION",
            "Signing fixture unavailable",
            details=_build_details(
                "repodata-fixture-sign",
                "fixture-sign",
                "repodata/repomd.xml.asc",
                causal_code="FIXTURE_UNAVAILABLE",
                receipt=receipt,
            ),
        )
    try:
        sig_bytes = fixture.detach_sign(index_bytes, armor=True)
    except Exception as err:
        code = err.code if isinstance(err, ContractError) else type(err).__name__
        raise ContractError(
            "RPM_REPOSITORY_OPERATION",
            "Fixture metadata signing failed",
            details=_build_details(
                "repodata-fixture-sign",
                "fixture-sign",
                "repodata/repomd.xml.asc",
                causal_code=code,
                errno_val=err.errno if isinstance(err, OSError) else None,
                receipt=receipt,
                extra=_relationships(index_file),
            ),
        ) from err

    # Substage 3: Signature write (0644)
    sig_file = dir_path / "repodata" / "repomd.xml.asc"
    try:
        write_public_file(sig_file, sig_bytes)
    except ContractError as err:
        det = dict(err.details or {})
        det["substage"] = "signature-write"
        det["operation"] = "repodata-signature-write"
        det["target"] = "repodata/repomd.xml.asc"
        if receipt is not None:
            det["stdout_sha256"] = getattr(receipt, "stdout_sha256", None)
            det["stderr_sha256"] = getattr(receipt, "stderr_sha256", None)
            det["exit_code"] = getattr(receipt, "exit_code", None)
            det["tool"] = command_tool(receipt.command)
        raise ContractError(
            "RPM_REPOSITORY_OPERATION",
            "Metadata signature write failed",
            details=det,
        ) from err
    except OSError as err:
        raise ContractError(
            "RPM_REPOSITORY_OPERATION",
            "Metadata signature write failed",
            details=_build_details(
                "repodata-signature-write",
                "signature-write",
                "repodata/repomd.xml.asc",
                errno_val=err.errno,
                causal_code=type(err).__name__,
                receipt=receipt,
                extra=_relationships(sig_file),
            ),
        ) from err

    # Substage 4: Verify
    try:
        retained_index = index_file.read_bytes()
        retained_signature = sig_file.read_bytes()
        if retained_index != index_bytes or retained_signature != sig_bytes:
            raise ContractError("REPOSITORY_CHANGED", "Metadata changed during fixture signing")
        verification = fixture.verify(retained_index, retained_signature)
    except Exception as err:
        code = err.code if isinstance(err, ContractError) else type(err).__name__
        raise ContractError(
            "RPM_REPOSITORY_OPERATION",
            "Metadata signature verification failed",
            details=_build_details(
                "repodata-signature-verify",
                "signature-verify",
                "repodata/repomd.xml.asc",
                causal_code=code,
                errno_val=err.errno if isinstance(err, OSError) else None,
                receipt=receipt,
                extra=_relationships(sig_file),
            ),
        ) from err

    if verification is False or (isinstance(verification, dict) and verification.get("status") == "fail"):
        raise ContractError(
            "RPM_REPOSITORY_OPERATION",
            "Metadata signature verification returned fail status",
            details=_build_details(
                "repodata-signature-verify",
                "signature-verify",
                "repodata/repomd.xml.asc",
                causal_code="VERIFICATION_FAILED",
                receipt=receipt,
            ),
        )

    # Substage 5: Public modes and ownership audit
    audit = audit_owned_tree(dir_path)
    if audit.get("status") != "pass" or not audit.get("compatible", True):
        first_violation = audit.get("violations", [{}])[0]
        raise ContractError(
            "RPM_REPOSITORY_OPERATION",
            f"Repository ownership and public mode audit failed: {first_violation.get('issue', 'audit-failed')}",
            details=_build_details(
                "repodata-public-modes" if "mode-mismatch" in first_violation.get("issue", "") else "repodata-ownership-audit",
                "public-modes" if "mode-mismatch" in first_violation.get("issue", "") else "ownership-audit",
                first_violation.get("path") or "repodata",
                causal_code="AUDIT_FAILED",
                target_mode=first_violation.get("mode"),
                receipt=receipt,
                extra=_relationships(dir_path / (first_violation.get("path") or ".")),
            ),
        )

    index_sha = hashlib.sha256(index_bytes).hexdigest()
    sig_sha = hashlib.sha256(sig_bytes).hexdigest()
    verified_issuer = getattr(fixture, "primary_fingerprint", None)
    if isinstance(verification, dict) and not verified_issuer:
        verified_issuer = verification.get("verified_issuer")

    report: dict[str, Any] = {
        "status": "pass",
        "operation": "repository-metadata",
        "index_path": "repodata/repomd.xml",
        "signature_path": "repodata/repomd.xml.asc",
        "index_sha256": index_sha,
        "signature_sha256": sig_sha,
        "verified_issuer": verified_issuer,
        "verification": verification,
        "ownership_audit": audit,
    }
    if receipt is not None:
        report["receipt_stdout_sha256"] = getattr(receipt, "stdout_sha256", None)
        report["receipt_stderr_sha256"] = getattr(receipt, "stderr_sha256", None)
        report["receipt_exit_code"] = getattr(receipt, "exit_code", None)

    return report
