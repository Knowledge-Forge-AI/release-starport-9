"""Reusable bounded machine text and record stream decoders for native receipts."""

from __future__ import annotations

import posixpath
from typing import Any

from rs9.errors import ContractError
from rs9.release_core import digest


def raise_stream_error(
    code: str,
    message: str,
    *,
    reason_token: str,
    receipt: Any,
    stream: str,
    substage: str,
    maximum: int | None = None,
) -> None:
    """Raise a sanitized ContractError with bound diagnostic details and causal receipt."""
    tool = (
        posixpath.basename(
            getattr(receipt, "tool_name", None)
            or (receipt.command[0] if getattr(receipt, "command", None) else "tool")
        )
        if receipt is not None
        else "tool"
    )
    exit_code = int(getattr(receipt, "exit_code", -1)) if receipt is not None else -1

    stdout_bytes = getattr(receipt, "stdout_bytes", b"") if receipt is not None else b""
    stderr_bytes = getattr(receipt, "stderr_bytes", b"") if receipt is not None else b""
    stdout_bytes = stdout_bytes if isinstance(stdout_bytes, (bytes, bytearray)) else b""
    stderr_bytes = stderr_bytes if isinstance(stderr_bytes, (bytes, bytearray)) else b""

    stdout_len = len(stdout_bytes)
    stderr_len = len(stderr_bytes)
    stdout_sha = getattr(receipt, "stdout_sha256", None) or digest(stdout_bytes)
    stderr_sha = getattr(receipt, "stderr_sha256", None) or digest(stderr_bytes)

    details = {
        "substage": substage,
        "tool": tool,
        "exit_code": exit_code,
        "reason_token": reason_token,
        "diagnostic_token": stream if stream in ('stdout', 'stderr') else 'invalid-stream',
        "stdout_sha256": stdout_sha,
        "stderr_sha256": stderr_sha,
        "size": stdout_len if stream == "stdout" else stderr_len,
    }
    details['observed'] = stdout_len if stream == 'stdout' else stderr_len
    if maximum is not None:
        details['maximum'] = maximum
    err = ContractError(code, message, details=details)
    err.receipt = receipt
    err.reason_token = reason_token
    err.stream = stream
    err.substage = substage
    err.tool = tool
    err.exit_code = exit_code
    err.stdout_length = stdout_len
    err.stderr_length = stderr_len
    err.stdout_sha256 = stdout_sha
    err.stderr_sha256 = stderr_sha
    raise err


def machine_text(
    receipt: Any,
    *,
    stream: str = "stdout",
    limit: int,
    code: str,
    substage: str,
    encoding: str = "utf-8",
) -> str:
    """Decode a bounded machine stream text using strict decoding after explicit bound validation."""
    if receipt is None:
        raise_stream_error(
            code=code,
            message="Command receipt is required",
            reason_token="receipt-missing",
            receipt=receipt,
            stream=stream,
            substage=substage,
        )

    if stream not in ("stdout", "stderr"):
        raise_stream_error(
            code=code,
            message="Invalid machine stream name",
            reason_token="invalid-stream",
            receipt=receipt,
            stream=stream,
            substage=substage,
        )

    raw_bytes = getattr(receipt, f"{stream}_bytes", None)
    if not isinstance(raw_bytes, bytes):
        raise_stream_error(
            code=code,
            message=f"Stream {stream} must be bytes",
            reason_token="stream-type",
            receipt=receipt,
            stream=stream,
            substage=substage,
        )

    if type(limit) is not int or limit < 0:
        raise_stream_error(
            code=code,
            message="Explicit non-negative stream limit required",
            reason_token="invalid-limit",
            receipt=receipt,
            stream=stream,
            substage=substage,
        )

    if len(raw_bytes) > limit:
        raise_stream_error(
            code=code,
            message=f"Stream {stream} exceeds limit of {limit} bytes",
            reason_token="stream-limit-exceeded",
            receipt=receipt,
            stream=stream,
            substage=substage,
            maximum=limit,
        )

    try:
        return raw_bytes.decode(encoding, errors="strict")
    except (UnicodeDecodeError, LookupError):
        raise_stream_error(
            code=code,
            message=f"Stream {stream} failed strict {encoding} decoding",
            reason_token="stream-decode-failed",
            receipt=receipt,
            stream=stream,
            substage=substage,
        )


def machine_records(
    receipt: Any,
    *,
    stream: str = "stdout",
    limit: int,
    code: str,
    substage: str,
    encoding: str = "utf-8",
) -> list[str]:
    """Decode a bounded stream requiring newline terminator, non-empty records, and ordinary splitting."""
    text = machine_text(
        receipt,
        stream=stream,
        limit=limit,
        code=code,
        substage=substage,
        encoding=encoding,
    )

    if not text.endswith("\n"):
        raise_stream_error(
            code=code,
            message=f"Stream {stream} records require newline terminator",
            reason_token="incomplete-framing",
            receipt=receipt,
            stream=stream,
            substage=substage,
        )

    records = text[:-1].split("\n")
    if not records or any(len(r) == 0 for r in records):
        raise_stream_error(
            code=code,
            message=f"Stream {stream} records must not contain empty records",
            reason_token="empty-record",
            receipt=receipt,
            stream=stream,
            substage=substage,
        )

    return records
