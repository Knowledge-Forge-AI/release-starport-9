"""Ephemeral GPG signing fixture for RS9 candidate testing.

Generates an ephemeral key pair in scratch, refuses production fingerprints,
and provides actual GPG detached/clearsign signing and validation using
VALIDSIG pinned fixture signer verification. Strictly refuses production
key operations and provides SignedStore-compatible validator interfaces.
"""

from __future__ import annotations

import glob
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
from typing import Any

from rs9.errors import ContractError
from rs9.records import snapshot
from rs9.scratch import physical_directory
from rs9.signed_store import (
    PRODUCTION_PRIMARY_FINGERPRINT,
    PRODUCTION_SIGNING_SUBKEY,
    _matches_pin,
)


def _normalize_fp(value: str) -> str:
    return value.strip().replace(" ", "").upper().removeprefix("0X")


def is_production_fingerprint(fp: str) -> bool:
    """Check if fingerprint matches protected production keys."""
    if not fp:
        return False
    return _matches_pin(fp, PRODUCTION_PRIMARY_FINGERPRINT) or _matches_pin(
        fp, PRODUCTION_SIGNING_SUBKEY
    )


def find_gpg_binary() -> str | None:
    """Locate a functional GnuPG executable on the current system."""
    candidates = []
    which_gpg = shutil.which("gpg")
    if which_gpg:
        candidates.append(which_gpg)
    which_gpg2 = shutil.which("gpg2")
    if which_gpg2:
        candidates.append(which_gpg2)

    # Nix store paths fallback (ordered by discovery)
    for pattern in ("/nix/store/*-gnupg-*/bin/gpg", "/nix/store/*gnupg*/bin/gpg"):
        for path in sorted(glob.glob(pattern), reverse=True):
            if path not in candidates and os.path.isfile(path) and os.access(path, os.X_OK):
                candidates.append(path)

    for candidate in candidates:
        try:
            res = subprocess.run(
                [candidate, "--version"],
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )
            if res.returncode == 0 and "GnuPG" in res.stdout:
                return candidate
        except (OSError, subprocess.SubprocessError):
            continue
    return None


class SigningFixture:
    """Ephemeral GPG key and validator fixture in empty scratch.

    Generates temporary key pairs, executes actual GPG sign and verify commands,
    enforces pinned fixture signer VALIDSIG assertions, and refuses production
    fingerprint operations fail-closed.
    """

    def __init__(
        self,
        *,
        scratch_dir: str | Path | None = None,
        user_id: str = "RS9 Fixture Signer <fixture@example.com>",
        gpg_binary: str | None = None,
    ) -> None:
        if gpg_binary is not None:
            if not (os.path.isfile(gpg_binary) and os.access(gpg_binary, os.X_OK)):
                raise ContractError("GPG_NOT_AVAILABLE", f"Specified GPG binary not executable: {gpg_binary}")
            gpg_path = gpg_binary
        else:
            gpg_path = find_gpg_binary()
        if not gpg_path:
            raise ContractError("GPG_NOT_AVAILABLE", "Functional GPG binary not found on system")
        self.gpg = gpg_path

        self._owns_temp = scratch_dir is None
        if scratch_dir is None:
            tmp_root = "/private/tmp" if os.path.isdir("/private/tmp") else tempfile.gettempdir()
            self.scratch_dir = Path(tempfile.mkdtemp(prefix="rs9_g_", dir=tmp_root))
        else:
            self.scratch_dir = physical_directory(scratch_dir)
            if any(self.scratch_dir.iterdir()):
                raise ContractError("OUTPUT_NOT_EMPTY", "Fixture signing requires empty owned scratch")

        os.chmod(self.scratch_dir, 0o700)
        self.homedir = self.scratch_dir

        try:
            self._generate_ephemeral_key(user_id)
        except Exception:
            self.close()
            raise

    def _generate_ephemeral_key(self, user_id: str) -> None:
        cmd = [
            self.gpg,
            "--homedir",
            str(self.homedir),
            "--batch",
            "--passphrase",
            "",
            "--quick-generate-key",
            user_id,
            "default",
            "default",
            "0",
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=60)
        if res.returncode != 0:
            if "No agent running" in res.stderr or "failed to start gpg-agent" in res.stderr:
                raise ContractError("GPG_AGENT_UNAVAILABLE", "Fixture agent unavailable in execution environment")
            raise ContractError(
                "KEY_GENERATION_FAILED",
                "Ephemeral fixture key generation failed",
            )

        list_cmd = [
            self.gpg,
            "--homedir",
            str(self.homedir),
            "--batch",
            "--with-colons",
            "--list-secret-keys",
        ]
        list_res = subprocess.run(list_cmd, capture_output=True, text=True, check=False)
        if list_res.returncode != 0:
            raise ContractError(
                "KEY_GENERATION_FAILED",
                f"Failed listing generated fixture key: {list_res.stderr.strip()}",
            )

        primary_fp = None
        subkeys: list[str] = []
        last_type = None

        for line in list_res.stdout.splitlines():
            fields = line.split(":")
            if not fields:
                continue
            record_type = fields[0]
            if record_type in ("sec", "pub"):
                last_type = "primary"
            elif record_type in ("ssb", "sub"):
                last_type = "sub"
            elif record_type == "fpr":
                fp = _normalize_fp(fields[9])
                if last_type == "primary" and primary_fp is None:
                    primary_fp = fp
                elif last_type == "sub":
                    subkeys.append(fp)

        if not primary_fp or len(primary_fp) != 40:
            raise ContractError(
                "KEY_GENERATION_FAILED",
                "Could not extract primary fingerprint from ephemeral key",
            )

        if is_production_fingerprint(primary_fp) or any(
            is_production_fingerprint(sk) for sk in subkeys
        ):
            raise ContractError(
                "PRODUCTION_KEY_FORBIDDEN",
                "Generated ephemeral key matches production fingerprint pin",
            )

        self.primary_fingerprint = primary_fp
        self.signing_subkeys = subkeys
        self.key_id = primary_fp[-16:]
        self.issuer = primary_fp

        armor_cmd = [
            self.gpg,
            "--homedir",
            str(self.homedir),
            "--batch",
            "--armor",
            "--export",
            self.primary_fingerprint,
        ]
        armor_res = subprocess.run(armor_cmd, capture_output=True, text=True, check=False)
        if armor_res.returncode != 0 or not armor_res.stdout:
            raise ContractError(
                "KEY_EXPORT_FAILED", "Failed exporting armored fixture public key"
            )
        self.public_key_armor = armor_res.stdout
        self.public_key_bytes = self.public_key_armor.encode("utf-8")

        bin_cmd = [
            self.gpg,
            "--homedir",
            str(self.homedir),
            "--batch",
            "--export",
            self.primary_fingerprint,
        ]
        bin_res = subprocess.run(bin_cmd, capture_output=True, check=False)
        if bin_res.returncode != 0 or not bin_res.stdout:
            raise ContractError(
                "KEY_EXPORT_FAILED", "Failed exporting binary fixture public key"
            )
        self.public_key_binary = bin_res.stdout

        self.trust_config = {
            "primary_fingerprint": self.primary_fingerprint,
            "allowed_keys": {self.primary_fingerprint, *self.signing_subkeys},
        }

    def detach_sign(self, data: bytes, *, armor: bool = True) -> bytes:
        """Create a detached OpenPGP signature using the ephemeral fixture key."""
        in_file = self.scratch_dir / "sign_input.tmp"
        out_file = self.scratch_dir / "sign_output.tmp"
        try:
            in_file.write_bytes(data)
            cmd = [
                self.gpg,
                "--homedir",
                str(self.homedir),
                "--batch",
                "--yes",
                "--detach-sign",
            ]
            if armor:
                cmd.append("--armor")
            cmd.extend(["--output", str(out_file), str(in_file)])

            res = subprocess.run(cmd, capture_output=True, check=False)
            if res.returncode != 0 or not out_file.exists():
                raise ContractError(
                    "SIGNING_FAILED",
                    f"Fixture detached signing failed: {res.stderr.decode('utf-8', errors='replace').strip()}",
                )
            return out_file.read_bytes()
        finally:
            if in_file.exists():
                in_file.unlink()
            if out_file.exists():
                out_file.unlink()

    def clearsign(self, data: bytes) -> bytes:
        """Create a clearsigned OpenPGP document using the ephemeral fixture key."""
        in_file = self.scratch_dir / "clearsign_input.tmp"
        out_file = self.scratch_dir / "clearsign_output.tmp"
        try:
            in_file.write_bytes(data)
            cmd = [
                self.gpg,
                "--homedir",
                str(self.homedir),
                "--batch",
                "--yes",
                "--clearsign",
                "--output",
                str(out_file),
                str(in_file),
            ]
            res = subprocess.run(cmd, capture_output=True, check=False)
            if res.returncode != 0 or not out_file.exists():
                raise ContractError(
                    "SIGNING_FAILED",
                    f"Fixture clearsigning failed: {res.stderr.decode('utf-8', errors='replace').strip()}",
                )
            return out_file.read_bytes()
        finally:
            if in_file.exists():
                in_file.unlink()
            if out_file.exists():
                out_file.unlink()

    def verify(
        self,
        unsigned_or_clearsigned: bytes,
        signature_bytes: bytes | None = None,
    ) -> dict[str, Any]:
        """Verify detached or clearsigned signature and check pinned fixture signer via VALIDSIG.

        Returns verified issuer and primary key evidence for SignedStore.
        """
        sig_file = self.scratch_dir / "verify_sig.tmp"
        data_file = self.scratch_dir / "verify_data.tmp"
        try:
            if signature_bytes is not None:
                # Detached verification
                sig_file.write_bytes(signature_bytes)
                data_file.write_bytes(unsigned_or_clearsigned)
                cmd = [
                    self.gpg,
                    "--homedir",
                    str(self.homedir),
                    "--batch",
                    "--status-fd",
                    "1",
                    "--verify",
                    str(sig_file),
                    str(data_file),
                ]
            else:
                # Clearsigned verification
                sig_file.write_bytes(unsigned_or_clearsigned)
                cmd = [
                    self.gpg,
                    "--homedir",
                    str(self.homedir),
                    "--batch",
                    "--status-fd",
                    "1",
                    "--verify",
                    str(sig_file),
                ]

            res = subprocess.run(cmd, capture_output=True, text=True, check=False)
            status_text = res.stdout

            validsig_match = None
            has_goodsig = False

            for line in status_text.splitlines():
                if line.startswith("[GNUPG:] GOODSIG"):
                    has_goodsig = True
                elif line.startswith("[GNUPG:] BADSIG") or line.startswith("[GNUPG:] ERRSIG"):
                    raise ContractError("VERIFICATION_FAILED", "Signature rejected by GPG status")
                elif line.startswith("[GNUPG:] VALIDSIG"):
                    # Format: [GNUPG:] VALIDSIG <fpr> <date> <timestamp> ... <primary_fpr>
                    parts = line.split()
                    if len(parts) >= 3:
                        signing_fp = _normalize_fp(parts[2])
                        primary_fp = _normalize_fp(parts[11]) if len(parts) >= 12 else signing_fp
                        validsig_match = (signing_fp, primary_fp, line)

            if res.returncode != 0 or not has_goodsig or not validsig_match:
                raise ContractError(
                    "VERIFICATION_FAILED",
                    f"Signature verification failed or missing VALIDSIG: {res.stderr.strip()}",
                )

            signer_fp, primary_fp, raw_validsig = validsig_match

            # Refuse production key operations
            if is_production_fingerprint(primary_fp) or is_production_fingerprint(signer_fp):
                raise ContractError(
                    "PRODUCTION_KEY_FORBIDDEN",
                    "Production key verification strictly forbidden in fixture context",
                )

            # Enforce pinned fixture signer
            if not _matches_pin(primary_fp, self.primary_fingerprint):
                raise ContractError(
                    "UNPINNED_TRUST",
                    f"Signature primary key {primary_fp} does not match pinned fixture signer {self.primary_fingerprint}",
                )

            evidence = {
                "verified_issuer": self.primary_fingerprint,
                "primary_key_id": self.primary_fingerprint,
                "signer_fingerprint": signer_fp,
                "status": "valid",
            }
            if signer_fp != self.primary_fingerprint:
                evidence["signing_subkey"] = signer_fp

            return evidence
        finally:
            if sig_file.exists():
                sig_file.unlink()
            if data_file.exists():
                data_file.unlink()

    def store_validator(
        self,
        unsigned_bytes: bytes,
        signed_bytes: bytes,
        evidence: dict[str, Any],
    ) -> dict[str, Any]:
        """Validator callable for SignedStore.retain integration."""
        if signed_bytes.startswith(b"-----BEGIN PGP SIGNED MESSAGE-----"):
            return self.verify(signed_bytes)
        return self.verify(unsigned_bytes, signed_bytes)

    def close(self) -> None:
        """Clean up ephemeral GPG scratch directory."""
        gpgconf = Path(self.gpg).resolve().parent / "gpgconf"
        if gpgconf.is_file():
            stopped = subprocess.run([str(gpgconf), "--homedir", str(self.homedir), "--kill", "gpg-agent"],
                                     capture_output=True, timeout=10)
            if stopped.returncode and (self.homedir / "S.gpg-agent").exists():
                raise ContractError("FIXTURE_CLEANUP", "Owned fixture agent cleanup not proven")
        elif (self.homedir / "S.gpg-agent").exists():
            raise ContractError("FIXTURE_CLEANUP", "Owned fixture agent cleanup tool unavailable")
        if self._owns_temp and self.scratch_dir.exists():
            shutil.rmtree(self.scratch_dir)

    def __enter__(self) -> SigningFixture:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()
