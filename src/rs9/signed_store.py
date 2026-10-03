"""Deterministic retain-once signed object store.

Persists signed object bytes content-addressed, binds unsigned sha and signed sha
with public issuer verification evidence. Retain-once: never re-signs on replay,
never overwrites exact objects. Atomic directory/file operations without symlinks.

Release update path index retention supports generations root per snapshot:
retained objects and manifests can be rooted per release generation or snapshot,
ensuring historical generations remain intact and content-addressed without
clobbering prior snapshots or removing prior objects without explicit reviewed rollback.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
import re
from pathlib import Path
import stat
import tempfile
from typing import Any, Callable

from rs9.errors import ContractError
from rs9.records import (
    Record,
    closed,
    parse_rfc3339_utc,
    record_sha256,
    snapshot,
    validate_bounded_int,
    validate_sanitized_string,
    validate_sha256,
)
from rs9.scratch import ConfinedWriter, canonical, physical_directory
from rs9.security import validate_safe_relative_posix_path

SCHEMA_SIGNED_OBJECT = "rs9.signed-object.v1alpha1"
SCHEMA_STORE_MANIFEST = "rs9.signed-store-manifest.v1alpha1"

PRODUCTION_PRIMARY_FINGERPRINT = "7D03EE84F8C7025FD2F3D772BF89DF6643C2F1AF"
PRODUCTION_SIGNING_SUBKEY = "C021E00EE3D37C459B0E1CB3199F8028126E8A8C"


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _matches_pin(value: str, target: str) -> bool:
    if value == target:
        return True
    v = value.strip().replace(" ", "").lower().removeprefix("0x")
    t = target.strip().replace(" ", "").lower().removeprefix("0x")
    return v == t


def _validate_trust(
    valid_result: dict[str, Any],
    evidence: dict[str, Any],
    trust_config: dict[str, Any] | set[str] | list[str] | tuple[str, ...] | None,
) -> None:
    primary = valid_result.get("primary_key_id") or valid_result.get("primary_fingerprint")
    if not primary:
        raise ContractError("UNPINNED_TRUST", "Validator result missing primary key identifier")

    subkey = (
        valid_result.get("signing_subkey")
        or valid_result.get("subkey_id")
        or evidence.get("signing_subkey")
        or evidence.get("subkey_id")
    )

    if trust_config is None:
        # Real production mode: require independently approved public production fingerprint pin
        if not _matches_pin(str(primary), PRODUCTION_PRIMARY_FINGERPRINT):
            raise ContractError("UNPINNED_TRUST", "Primary fingerprint does not match approved production pin")
        if subkey is not None and not _matches_pin(str(subkey), PRODUCTION_SIGNING_SUBKEY):
            raise ContractError("UNPINNED_TRUST", "Signing subkey does not match approved production pin")
        return

    # Explicit synthetic trust configuration
    if isinstance(trust_config, (set, list, tuple)):
        allowed = {str(k) for k in trust_config}
        if not any(_matches_pin(str(primary), a) for a in allowed):
            raise ContractError("UNPINNED_TRUST", "Primary key not in approved synthetic trust configuration")
        if subkey is not None and not any(_matches_pin(str(subkey), a) for a in allowed):
            raise ContractError("UNPINNED_TRUST", "Signing subkey not in approved synthetic trust configuration")
        return

    if isinstance(trust_config, dict):
        allowed_primaries: set[str] = set()
        if "primary_fingerprint" in trust_config:
            allowed_primaries.add(str(trust_config["primary_fingerprint"]))
        if "primary_key_id" in trust_config:
            allowed_primaries.add(str(trust_config["primary_key_id"]))
        if "allowed_primary_keys" in trust_config:
            allowed_primaries.update(str(x) for x in trust_config["allowed_primary_keys"])
        if "allowed_keys" in trust_config:
            allowed_primaries.update(str(x) for x in trust_config["allowed_keys"])

        allowed_subkeys: set[str] = set()
        if "signing_subkey" in trust_config:
            allowed_subkeys.add(str(trust_config["signing_subkey"]))
        if "subkey_id" in trust_config:
            allowed_subkeys.add(str(trust_config["subkey_id"]))
        if "allowed_subkeys" in trust_config:
            allowed_subkeys.update(str(x) for x in trust_config["allowed_subkeys"])
        if "allowed_keys" in trust_config:
            allowed_subkeys.update(str(x) for x in trust_config["allowed_keys"])

        if allowed_primaries:
            if not any(_matches_pin(str(primary), a) for a in allowed_primaries):
                raise ContractError("UNPINNED_TRUST", "Primary key does not match approved synthetic trust configuration")
        elif not allowed_subkeys:
            raise ContractError("UNPINNED_TRUST", "No approved keys in synthetic trust configuration")

        if subkey is not None and allowed_subkeys:
            if not any(_matches_pin(str(subkey), a) for a in allowed_subkeys):
                raise ContractError("UNPINNED_TRUST", "Signing subkey does not match approved synthetic trust configuration")
        return

    raise ContractError("INVALID_CONFIG", "Invalid trust configuration format")


def _validate_public_evidence(value, depth=0):
    """Keep retained verifier summaries bounded and free of private operational data."""
    if depth > 3:
        raise ContractError("EVIDENCE_LIMIT", "Evidence nesting exceeds bound")
    if isinstance(value, dict):
        if len(value) > 32:
            raise ContractError("EVIDENCE_LIMIT", "Evidence field count exceeds bound")
        for key, child in value.items():
            validate_sanitized_string(key, max_length=96)
            if re.search(r"secret|token|password|passphrase|cookie|credential|private|username|hostname|connection|dump", key, re.I):
                raise ContractError("EVIDENCE_PRIVATE", "Private field families forbidden in retained evidence")
            _validate_public_evidence(child, depth + 1)
    elif isinstance(value, list):
        if len(value) > 32:
            raise ContractError("EVIDENCE_LIMIT", "Evidence item count exceeds bound")
        for child in value:
            _validate_public_evidence(child, depth + 1)
    elif isinstance(value, str):
        validate_sanitized_string(value)
    elif value is not None and type(value) not in {int, bool}:
        raise ContractError("EVIDENCE_TYPE", "Only public bounded metadata is permitted")
    if depth == 0 and len(canonical(value)) > 8192:
        raise ContractError("EVIDENCE_LIMIT", "Evidence bytes exceed bound")


def _check_no_symlinks(path: Path) -> None:
    if path.is_symlink():
        raise ContractError("SYMLINK_REJECTED", "Path is a symlink")
    for parent in (path, *path.parents):
        if parent.is_symlink():
            raise ContractError("SYMLINK_REJECTED", "Path ancestry contains a symlink")


def _safe_read_file(path: Path, max_bytes: int = 512 * 1024 * 1024) -> bytes:
    _check_no_symlinks(path)
    try:
        descriptor = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise ContractError("INVALID_FILE", "Regular file required")
            if info.st_size > max_bytes:
                raise ContractError("FILE_LIMIT", "File size exceeds limit")
            data = stream.read(max_bytes + 1)
            if len(data) > max_bytes:
                raise ContractError("FILE_LIMIT", "File size exceeds limit")
            return data
    except OSError as err:
        if isinstance(err, ContractError):
            raise
        raise ContractError("IO_ERROR", "Failed reading file") from None


def _safe_write_file(target: Path, content: bytes) -> None:
    _check_no_symlinks(target.parent)
    target.parent.mkdir(parents=True, exist_ok=True)
    _check_no_symlinks(target.parent)

    temp_prefix = f".tmp_{target.name}_"
    try:
        fd, temp_path = tempfile.mkstemp(prefix=temp_prefix, dir=str(target.parent))
        with os.fdopen(fd, "wb") as f:
            f.write(content)
        os.replace(temp_path, str(target))
    except Exception:
        if "temp_path" in locals() and os.path.exists(temp_path):
            try:
                os.unlink(temp_path)
            except OSError:
                pass
        raise ContractError("WRITE_ERROR", "Atomic write failed") from None


class SignedStore:
    """Retain-once content-addressed signed object store.

    Release update path index retention supports generations root per snapshot.
    """

    def __init__(
        self,
        root: str | Path,
        *,
        generation: str | None = None,
        trust_config: dict[str, Any] | set[str] | list[str] | tuple[str, ...] | None = None,
    ) -> None:
        p = Path(root).absolute()
        if any(parent.is_symlink() for parent in (p, *p.parents)):
            raise ContractError("SYMLINK_REJECTED", "Path ancestry contains a symlink")
        if p.is_symlink():
            raise ContractError("SYMLINK_REJECTED", "Path is a symlink")
        p.mkdir(parents=True, exist_ok=True)
        self.root = physical_directory(p)
        _check_no_symlinks(self.root)

        if generation is not None:
            validate_sanitized_string(generation, max_length=96)
            validate_safe_relative_posix_path(generation)
            if "/" in generation or "\\" in generation or ".." in generation:
                raise ContractError("UNSAFE_PATH", "Generation must be a simple identifier")

        self.generation = generation
        self.trust_config = trust_config

        self.objects_dir = self.root / "objects"
        self.records_dir = self.root / "records"
        self.generations_dir = self.root / "generations"

        if self.generation is not None:
            self.manifest_file = self.generations_dir / self.generation / "manifest.json"
        else:
            self.manifest_file = self.root / "manifest.json"
        self.lock_file = self.root / ".store.lock"

        self.objects_dir.mkdir(parents=True, exist_ok=True)
        self.records_dir.mkdir(parents=True, exist_ok=True)
        _check_no_symlinks(self.objects_dir)
        _check_no_symlinks(self.records_dir)

        if self.generations_dir.exists():
            _check_no_symlinks(self.generations_dir)
        if self.generation is not None:
            gen_dir = self.generations_dir / self.generation
            gen_dir.mkdir(parents=True, exist_ok=True)
            _check_no_symlinks(gen_dir)

        self._index: dict[str, str] = {}  # rel_path -> signed_sha256
        self._record_hashes: dict[str, str] = {}  # rel_path -> record_sha256
        self._records: dict[str, Record] = {}  # rel_path -> Record

        with self._lock(shared=True):
            self._load_manifest()

    @contextmanager
    def _lock(self, shared: bool = False):
        """Serialize store operations across handles and processes."""
        _check_no_symlinks(self.root)
        flags = os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW
        fd = os.open(str(self.lock_file), flags, 0o600)
        lock_mode = fcntl.LOCK_SH if shared else fcntl.LOCK_EX
        try:
            fcntl.flock(fd, lock_mode)
            yield
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)

    def _load_manifest(self) -> None:
        """Load and strictly validate store manifest and all record/object hashes."""
        if not self.manifest_file.exists():
            self._index.clear()
            self._record_hashes.clear()
            self._records.clear()
            return

        _check_no_symlinks(self.manifest_file)
        try:
            content = _safe_read_file(self.manifest_file)
            data = json.loads(content.decode("utf-8"))
        except (ValueError, UnicodeError):
            raise ContractError("INVALID_MANIFEST", "Corrupted store manifest") from None

        allowed_manifest_keys = {"schema", "entries"}
        if "generation" in data:
            allowed_manifest_keys.add("generation")
        closed(data, allowed_manifest_keys)
        if data.get("schema") != SCHEMA_STORE_MANIFEST:
            raise ContractError("RECORD_SCHEMA", "Manifest schema mismatch")

        if self.generation is not None:
            if data.get("generation") != self.generation:
                raise ContractError("TAMPER_DETECTED", "Manifest generation mismatch")

        entries = data.get("entries", {})
        if not isinstance(entries, dict):
            raise ContractError("RECORD_SCHEMA", "Entries must be a dictionary")

        new_index: dict[str, str] = {}
        new_record_hashes: dict[str, str] = {}
        new_records: dict[str, Record] = {}

        for rel_path, entry_info in entries.items():
            validate_safe_relative_posix_path(rel_path)
            if isinstance(entry_info, dict):
                closed(entry_info, {"signed_sha256", "record_sha256"})
                signed_sha = entry_info.get("signed_sha256")
                rec_sha = entry_info.get("record_sha256")
            else:
                raise ContractError("RECORD_SCHEMA", "Invalid manifest entry format")

            validate_sha256(signed_sha)
            validate_sha256(rec_sha)
            rec_file = self.records_dir / f"{rec_sha}.json"

            if not rec_file.exists():
                raise ContractError("MISSING_RECORD", "Record file referenced in manifest is missing")

            rec_bytes = _safe_read_file(rec_file)
            try:
                rec_data = json.loads(rec_bytes.decode("utf-8"))
            except (ValueError, UnicodeError):
                raise ContractError("INVALID_RECORD", "Corrupted record json") from None

            self._validate_record_structure(rec_data)

            # Startup validation: rel_path and signed_sha must match manifest index
            if rec_data.get("rel_path") != rel_path:
                raise ContractError("TAMPER_DETECTED", "Record rel_path mismatch")
            if rec_data.get("signed_sha256") != signed_sha:
                raise ContractError("TAMPER_DETECTED", "Record signed sha mismatch")
            if self.generation is not None and "generation" in rec_data and rec_data.get("generation") != self.generation:
                raise ContractError("TAMPER_DETECTED", "Record generation mismatch")

            # Tampered record unsigned hash / issuer / evidence detected against manifest record hash
            computed_rec_sha = record_sha256(rec_data)
            if computed_rec_sha != rec_sha:
                raise ContractError("TAMPER_DETECTED", "Record content tampered on disk")
            if rec_data["issuer"] != rec_data["evidence"].get("verified_issuer"):
                raise ContractError("ISSUER_MISMATCH", "Stored issuer differs from verified issuer")
            _validate_trust(rec_data["evidence"], {}, self.trust_config)

            # All bytes integrity before any get/replay
            obj_file = self.objects_dir / signed_sha
            if not obj_file.exists():
                raise ContractError("TAMPER_DETECTED", "Content-addressed object file missing on disk")
            disk_bytes = _safe_read_file(obj_file)
            if _digest(disk_bytes) != signed_sha:
                raise ContractError("TAMPER_DETECTED", "Stored object content tampered on disk")

            new_index[rel_path] = signed_sha
            new_record_hashes[rel_path] = rec_sha
            new_records[rel_path] = Record(rec_data)

        self._index = new_index
        self._record_hashes = new_record_hashes
        self._records = new_records

    def _save_manifest(self) -> None:
        entries_data: dict[str, Any] = {}
        for rel_path in sorted(self._index):
            entries_data[rel_path] = {
                "record_sha256": self._record_hashes[rel_path],
                "signed_sha256": self._index[rel_path],
            }
        manifest_data: dict[str, Any] = {
            "schema": SCHEMA_STORE_MANIFEST,
            "entries": entries_data,
        }
        if self.generation:
            manifest_data["generation"] = self.generation
        _safe_write_file(self.manifest_file, canonical(manifest_data))

    @staticmethod
    def _validate_record_structure(data: Any) -> None:
        allowed = {
            "schema",
            "rel_path",
            "unsigned_sha256",
            "signed_sha256",
            "issuer",
            "evidence",
            "retained_at",
            "byte_size",
        }
        if "generation" in data:
            allowed.add("generation")
        closed(data, allowed)
        if data.get("schema") != SCHEMA_SIGNED_OBJECT:
            raise ContractError("RECORD_SCHEMA", "Signed object record schema mismatch")
        validate_safe_relative_posix_path(data["rel_path"])
        validate_sha256(data["unsigned_sha256"])
        validate_sha256(data["signed_sha256"])
        validate_sanitized_string(data["issuer"])
        if "generation" in data:
            validate_sanitized_string(data["generation"], max_length=96)
        parse_rfc3339_utc(data["retained_at"])
        validate_bounded_int(data["byte_size"], max_val=512 * 1024 * 1024)
        if not isinstance(data.get("evidence"), dict):
            raise ContractError("RECORD_SCHEMA", "Evidence must be a dictionary")
        _validate_public_evidence(data["evidence"])

    def for_generation(self, generation: str) -> SignedStore:
        validate_sanitized_string(generation, max_length=96)
        validate_safe_relative_posix_path(generation)
        if "/" in generation or "\\" in generation or ".." in generation:
            raise ContractError("UNSAFE_PATH", "Generation must be a simple identifier")
        if generation == self.generation:
            return self
        return SignedStore(
            self.root,
            generation=generation,
            trust_config=self.trust_config,
        )

    def list_generations(self) -> list[str]:
        with self._lock(shared=True):
            generations: list[str] = []
            if self.generations_dir.exists():
                _check_no_symlinks(self.generations_dir)
                for entry in sorted(self.generations_dir.iterdir()):
                    if entry.is_dir() and not entry.is_symlink():
                        manifest = entry / "manifest.json"
                        if manifest.exists() and not manifest.is_symlink():
                            generations.append(entry.name)
            return generations

    def has_generation(self, generation: str) -> bool:
        validate_sanitized_string(generation, max_length=96)
        validate_safe_relative_posix_path(generation)
        if "/" in generation or "\\" in generation or ".." in generation:
            raise ContractError("UNSAFE_PATH", "Generation must be a simple identifier")
        gen_manifest = self.generations_dir / generation / "manifest.json"
        return gen_manifest.exists()

    def retain(
        self,
        rel_path: str,
        signed_bytes: bytes,
        unsigned_bytes: bytes,
        issuer: str,
        evidence: dict[str, Any],
        validator: Callable[[bytes, bytes, dict[str, Any]], bool | dict[str, Any]] | None = None,
        *,
        generation: str | None = None,
        trust_config: dict[str, Any] | set[str] | list[str] | tuple[str, ...] | None = None,
    ) -> Record:
        """Retain-once a signed object.

        Records keyed by record hash (unique per rel_path and signed content).
        Same signed bytes retained for two paths will not overwrite records rel_path.
        Replay is byte-stable; exact objects are never re-signed or overwritten.
        """
        if generation is not None and generation != self.generation:
            target_store = self.for_generation(generation)
            return target_store.retain(
                rel_path=rel_path,
                signed_bytes=signed_bytes,
                unsigned_bytes=unsigned_bytes,
                issuer=issuer,
                evidence=evidence,
                validator=validator,
                trust_config=trust_config,
            )

        validate_safe_relative_posix_path(rel_path)
        if not isinstance(signed_bytes, bytes) or not isinstance(unsigned_bytes, bytes):
            raise ContractError("INVALID_TYPE", "Payloads must be bytes")
        if not signed_bytes or not unsigned_bytes:
            raise ContractError("INVALID_CONTENT", "Payloads must be non-empty")
        validate_sanitized_string(issuer)
        if not isinstance(evidence, dict):
            raise ContractError("INVALID_TYPE", "Evidence must be a dictionary")
        _validate_public_evidence(evidence)

        unsigned_sha = _digest(unsigned_bytes)
        signed_sha = _digest(signed_bytes)

        with self._lock(shared=False):
            # Reload manifest inside exclusive lock to prevent clobbering by concurrent handles
            self._load_manifest()

            # Check replay / conflict for existing object at rel_path
            if rel_path in self._index:
                existing_sha = self._index[rel_path]
                existing_rec = self._records[rel_path]
                if existing_sha == signed_sha and existing_rec["unsigned_sha256"] == unsigned_sha:
                    # Replay must reject mismatched supplied issuer/evidence claim
                    if existing_rec["issuer"] != issuer:
                        raise ContractError("OBJECT_CONFLICT", "Replay claim mismatch for issuer")
                    for k, v in evidence.items():
                        if k in existing_rec.get("evidence", {}) and existing_rec["evidence"][k] != v:
                            raise ContractError("OBJECT_CONFLICT", "Replay claim mismatch for evidence")

                    # Verify disk integrity on replay
                    obj_file = self.objects_dir / signed_sha
                    if not obj_file.exists():
                        raise ContractError("TAMPER_DETECTED", "Content-addressed object file missing on replay")
                    disk_bytes = _safe_read_file(obj_file)
                    if _digest(disk_bytes) != signed_sha:
                        raise ContractError("TAMPER_DETECTED", "Stored object content tampered on disk")
                    # Never re-sign or re-verify on replay; return immutable original
                    return existing_rec
                else:
                    # Conflict: different bytes or unsigned sha for the same destination path
                    raise ContractError("OBJECT_CONFLICT", "Conflicting signed object already retained for path")

            # Independent verification trust gate
            if validator is None:
                raise ContractError("VALIDATOR_REQUIRED", "Independent validator required")

            try:
                valid_result = validator(unsigned_bytes, signed_bytes, evidence)
            except Exception:
                raise ContractError("VERIFICATION_FAILED", "Signature verification error") from None

            if (not isinstance(valid_result, dict)
                    or not {"verified_issuer", "primary_key_id"} <= set(valid_result)):
                raise ContractError("VERIFICATION_FAILED", "Independent validator rejected signature")

            # Bind caller issuer to validator verified_issuer on first retain
            if valid_result["verified_issuer"] != issuer:
                raise ContractError("ISSUER_MISMATCH", "Caller issuer does not match validator verified_issuer")

            # Validate trust pin (production or synthetic)
            effective_trust = self.trust_config if trust_config is None else trust_config
            _validate_trust(valid_result, evidence, effective_trust)

            # Persist retained signature issuer independently from validator-return verified info
            final_evidence = snapshot(evidence)
            for key, value in valid_result.items():
                validate_sanitized_string(key)
                validate_sanitized_string(value)
            _validate_public_evidence(valid_result)
            final_evidence.update(snapshot(valid_result))
            persisted_issuer = valid_result["verified_issuer"]
            final_evidence["verified_primary_key"] = valid_result["primary_key_id"]
            if "signing_subkey" in valid_result:
                final_evidence["verified_signing_subkey"] = valid_result["signing_subkey"]
            elif "subkey_id" in valid_result:
                final_evidence["verified_signing_subkey"] = valid_result["subkey_id"]

            validate_sanitized_string(persisted_issuer)

            # Persist content-addressed object bytes
            obj_file = self.objects_dir / signed_sha
            if obj_file.exists():
                disk_bytes = _safe_read_file(obj_file)
                if _digest(disk_bytes) != signed_sha:
                    raise ContractError("TAMPER_DETECTED", "Existing object content tampered on disk")
            else:
                _safe_write_file(obj_file, signed_bytes)

            # Build and persist record keyed by record hash
            retained_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            record_data: dict[str, Any] = {
                "schema": SCHEMA_SIGNED_OBJECT,
                "rel_path": rel_path,
                "unsigned_sha256": unsigned_sha,
                "signed_sha256": signed_sha,
                "issuer": persisted_issuer,
                "evidence": final_evidence,
                "retained_at": retained_at,
                "byte_size": len(signed_bytes),
            }
            if self.generation is not None:
                record_data["generation"] = self.generation

            self._validate_record_structure(record_data)
            record = Record(snapshot(record_data))
            rec_sha = record.sha256

            rec_file = self.records_dir / f"{rec_sha}.json"
            _safe_write_file(rec_file, canonical(record.to_dict()))

            # Update index and manifest
            self._index[rel_path] = signed_sha
            self._record_hashes[rel_path] = rec_sha
            self._records[rel_path] = record
            self._save_manifest()

            return record

    def get(self, rel_path: str, *, generation: str | None = None) -> tuple[Record, bytes]:
        """Retrieve retained signed object record and bytes, checking disk integrity."""
        if generation is not None and generation != self.generation:
            return self.for_generation(generation).get(rel_path)

        validate_safe_relative_posix_path(rel_path)
        with self._lock(shared=True):
            if rel_path not in self._index:
                raise ContractError("MISSING_OBJECT", "Object not found in store")
            signed_sha = self._index[rel_path]
            record = self._records[rel_path]
            obj_file = self.objects_dir / signed_sha
            if not obj_file.exists():
                raise ContractError("TAMPER_DETECTED", "Object file missing from store")
            bytes_data = _safe_read_file(obj_file)
            if _digest(bytes_data) != signed_sha:
                raise ContractError("TAMPER_DETECTED", "Object file content tampered")
            return record, bytes_data

    def has(self, rel_path: str, *, generation: str | None = None) -> bool:
        if generation is not None and generation != self.generation:
            return self.for_generation(generation).has(rel_path)

        validate_safe_relative_posix_path(rel_path)
        with self._lock(shared=True):
            return rel_path in self._index

    def list_records(self, *, generation: str | None = None) -> list[Record]:
        if generation is not None and generation != self.generation:
            return self.for_generation(generation).list_records()

        with self._lock(shared=True):
            return [self._records[p] for p in sorted(self._index)]

    def verify_store_integrity(self, *, generation: str | None = None) -> None:
        """Verify all index records and content-addressed objects match."""
        if generation is not None and generation != self.generation:
            self.for_generation(generation).verify_store_integrity()
            return

        _check_no_symlinks(self.root)
        _check_no_symlinks(self.objects_dir)
        _check_no_symlinks(self.records_dir)
        if self.generations_dir.exists():
            _check_no_symlinks(self.generations_dir)
        if self.generation is not None:
            gen_dir = self.generations_dir / self.generation
            if gen_dir.exists():
                _check_no_symlinks(gen_dir)

        with self._lock(shared=True):
            self._load_manifest()
            for rel_path, signed_sha in self._index.items():
                record = self._records.get(rel_path)
                if not record:
                    raise ContractError("TAMPER_DETECTED", "Missing memory record")
                rec_sha = self._record_hashes.get(rel_path)
                if not rec_sha:
                    raise ContractError("TAMPER_DETECTED", "Missing record hash")
                rec_file = self.records_dir / f"{rec_sha}.json"
                if not rec_file.exists():
                    raise ContractError("TAMPER_DETECTED", "Missing record file")
                rec_bytes = _safe_read_file(rec_file)
                rec_json = json.loads(rec_bytes.decode("utf-8"))
                if rec_json["signed_sha256"] != signed_sha:
                    raise ContractError("TAMPER_DETECTED", "Record signed sha mismatch")
                if rec_json["rel_path"] != rel_path:
                    raise ContractError("TAMPER_DETECTED", "Record rel_path mismatch")
                if record_sha256(rec_json) != rec_sha:
                    raise ContractError("TAMPER_DETECTED", "Record content tampered")
                obj_file = self.objects_dir / signed_sha
                if not obj_file.exists():
                    raise ContractError("TAMPER_DETECTED", "Missing object file")
                obj_bytes = _safe_read_file(obj_file)
                if _digest(obj_bytes) != signed_sha:
                    raise ContractError("TAMPER_DETECTED", "Object bytes tampered")

            if self.generation is None and self.generations_dir.exists():
                for gen_name in self.list_generations():
                    self.for_generation(gen_name).verify_store_integrity()

    def assemble_deployment(
        self,
        target_dir: str | Path,
        *,
        current_objects: list[str] | set[str] | None = None,
        reviewed_rollback: bool = False,
        generation: str | None = None,
    ) -> list[Record]:
        """Assemble deployment tree from retained signed objects.

        Deployment target must be empty and uses ConfinedWriter so it never
        overwrites caller tree. Carries forward existing signed objects
        without removal unless explicitly reviewed rollback.
        """
        if generation is not None and generation != self.generation:
            return self.for_generation(generation).assemble_deployment(
                target_dir,
                current_objects=current_objects,
                reviewed_rollback=reviewed_rollback,
            )

        target = physical_directory(target_dir)
        _check_no_symlinks(target)

        with self._lock(shared=True):
            if current_objects is not None:
                retained_paths = set(self._index.keys())
                for path in current_objects:
                    validate_safe_relative_posix_path(path)
                    if path not in retained_paths and not reviewed_rollback:
                        raise ContractError(
                            "UNAUTHORIZED_ROLLBACK",
                            "Attempted removal of retained object without reviewed rollback",
                        )

            deployed_records: list[Record] = []
            with ConfinedWriter(target) as writer:
                for rel_path in sorted(self._index):
                    record, content = self.get(rel_path)
                    writer.write(rel_path, content)
                    deployed_records.append(record)

            return deployed_records
