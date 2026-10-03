"""Contract error definitions with stable error codes and sanitized messages."""

from __future__ import annotations


class ContractError(Exception):
    """Exception raised for .rs9 contract validation and normalization failures.

    Contract error messages must never echo untrusted input values to avoid
    credential or sensitive data leakage in error reporting.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message

    def __str__(self) -> str:
        return f"[{self.code}] {self.message}"

    def __repr__(self) -> str:
        return f"ContractError(code={self.code!r}, message={self.message!r})"
