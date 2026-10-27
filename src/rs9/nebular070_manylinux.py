"""Compatibility facade for the separated Nebular 0.7.0 admission owners.

Payload/native evidence lives in rs9.nebular070_payload; bounded wheel
readback and external release admission live in rs9.nebular070_release.
Existing import paths remain stable.
"""
from __future__ import annotations

from rs9.nebular070_payload import (
    ACTUAL_QUALIFICATION_SCHEMA,
    CLAIM,
    CONSUMER_RECEIPT_SCHEMA,
    CPU_SCHEMA,
    ELF_PORTABILITY_SCHEMA,
    HEX40,
    HEX64,
    HOST_FLOOR_SCHEMA,
    LEGACY_PORTABILITY_SCHEMA,
    LINUX_TARGETS,
    MAX_INPUT_BYTES,
    MAX_RUNTIME_FILE_BYTES,
    MAX_WHEEL_BYTES,
    MAX_WHEEL_MEMBER_BYTES,
    MAX_WHEEL_MEMBERS,
    MAX_WHEEL_TOTAL_BYTES,
    OBSERVATION_KINDS,
    OBSERVATION_SCHEMA,
    PAYLOAD_RECEIPT_SCHEMA,
    PAYLOAD_ROW_FIELDS,
    PORTABILITY_INPUT_SCHEMA,
    PORTABILITY_SCHEMA,
    RECEIPT_KINDS,
    RUNTIME_FLOOR_SCHEMA,
    RUNTIME_RECEIPT_SCHEMA,
    SONAME_RE,
    VERSION,
    ValidatedPayloadPortability,
    _admission_digest,
    _body_digest,
    _digest,
    _maintained_identity,
    load_payload_portability_bundle,
    validate_nebular070_payload_portability,
)
from rs9.nebular070_release import (
    ADMISSION_SCHEMA,
    APPROVAL_SCHEMA,
    MATRIX_SCHEMA,
    ValidatedReleaseAdmission,
    _wheel_snapshot,
    manylinux_tag_for_target,
    validate_nebular070_release_admission,
)
from rs9.scratch import canonical

__all__ = [
    "ACTUAL_QUALIFICATION_SCHEMA", "ADMISSION_SCHEMA", "APPROVAL_SCHEMA", "CLAIM",
    "CONSUMER_RECEIPT_SCHEMA", "CPU_SCHEMA", "ELF_PORTABILITY_SCHEMA", "HEX40", "HEX64",
    "HOST_FLOOR_SCHEMA", "LEGACY_PORTABILITY_SCHEMA", "LINUX_TARGETS", "MATRIX_SCHEMA",
    "MAX_INPUT_BYTES", "MAX_RUNTIME_FILE_BYTES", "MAX_WHEEL_BYTES", "MAX_WHEEL_MEMBER_BYTES",
    "MAX_WHEEL_MEMBERS", "MAX_WHEEL_TOTAL_BYTES", "OBSERVATION_KINDS", "OBSERVATION_SCHEMA",
    "PAYLOAD_RECEIPT_SCHEMA", "PAYLOAD_ROW_FIELDS", "PORTABILITY_INPUT_SCHEMA", "PORTABILITY_SCHEMA",
    "RECEIPT_KINDS", "RUNTIME_FLOOR_SCHEMA", "RUNTIME_RECEIPT_SCHEMA", "SONAME_RE", "VERSION",
    "ValidatedPayloadPortability", "ValidatedReleaseAdmission", "load_payload_portability_bundle",
    "manylinux_tag_for_target", "validate_nebular070_payload_portability",
    "validate_nebular070_release_admission",
]

# Focused synthetic tests historically used these private canonical helpers;
# retaining the aliases keeps the compatibility surface explicit and tiny.
__all__ += ["_admission_digest", "_body_digest", "_digest", "_maintained_identity", "_wheel_snapshot", "canonical"]

