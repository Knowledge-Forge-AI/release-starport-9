"""Syntax-only SPDX expression validator."""

from __future__ import annotations

import re
import unicodedata
from typing import NamedTuple

from rs9.errors import ContractError

IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9_.-]+(\+)?$")
EXCEPTION_ID_RE = re.compile(r"^[A-Za-z0-9_.-]+$")


class Token(NamedTuple):
    kind: str
    value: str


def _tokenize(expr: str) -> list[Token]:
    tokens: list[Token] = []
    i = 0
    n = len(expr)
    while i < n:
        char = expr[i]
        if char in " \t\r\n":
            i += 1
            continue
        if char == "(":
            tokens.append(Token("LPAREN", "("))
            i += 1
            continue
        if char == ")":
            tokens.append(Token("RPAREN", ")"))
            i += 1
            continue

        # Word token (identifier or keyword)
        start = i
        while i < n and expr[i] not in " \t\r\n()":
            i += 1
        word = expr[start:i]

        if word == "AND":
            tokens.append(Token("AND", word))
        elif word == "OR":
            tokens.append(Token("OR", word))
        elif word == "WITH":
            tokens.append(Token("WITH", word))
        else:
            if not IDENTIFIER_RE.match(word):
                raise ContractError(
                    "INVALID_SPDX_EXPRESSION",
                    "Invalid identifier in SPDX license expression",
                )
            tokens.append(Token("IDENTIFIER", word))

    if not tokens:
        raise ContractError(
            "INVALID_SPDX_EXPRESSION",
            "SPDX license expression must not be empty",
        )
    return tokens


class _Parser:
    def __init__(self, tokens: list[Token]) -> None:
        self.tokens = tokens
        self.pos = 0

    @property
    def current(self) -> Token | None:
        if self.pos < len(self.tokens):
            return self.tokens[self.pos]
        return None

    def consume(self, expected_kind: str | None = None) -> Token:
        token = self.current
        if token is None:
            raise ContractError(
                "INVALID_SPDX_EXPRESSION",
                "Unexpected end of SPDX license expression",
            )
        if expected_kind and token.kind != expected_kind:
            raise ContractError(
                "INVALID_SPDX_EXPRESSION",
                "Unexpected token in SPDX license expression",
            )
        self.pos += 1
        return token

    def parse(self) -> None:
        self._parse_or()
        if self.current is not None:
            raise ContractError(
                "INVALID_SPDX_EXPRESSION",
                "Trailing tokens after SPDX license expression",
            )

    def _parse_or(self) -> None:
        self._parse_and()
        while self.current is not None and self.current.kind == "OR":
            self.consume("OR")
            self._parse_and()

    def _parse_and(self) -> None:
        self._parse_with()
        while self.current is not None and self.current.kind == "AND":
            self.consume("AND")
            self._parse_with()

    def _parse_with(self) -> None:
        grouped = self.current is not None and self.current.kind == "LPAREN"
        self._parse_simple()
        if not grouped and self.current is not None and self.current.kind == "WITH":
            self.consume("WITH")
            tok = self.consume("IDENTIFIER")
            if not EXCEPTION_ID_RE.match(tok.value):
                raise ContractError(
                    "INVALID_SPDX_EXPRESSION",
                    "Invalid exception identifier after WITH in SPDX expression",
                )

    def _parse_simple(self) -> None:
        tok = self.current
        if tok is None:
            raise ContractError(
                "INVALID_SPDX_EXPRESSION",
                "Unexpected end of SPDX license expression",
            )
        if tok.kind == "LPAREN":
            self.consume("LPAREN")
            self._parse_or()
            self.consume("RPAREN")
        elif tok.kind == "IDENTIFIER":
            self.consume("IDENTIFIER")
        else:
            raise ContractError(
                "INVALID_SPDX_EXPRESSION",
                "Expected license identifier or parenthesized expression",
            )


def validate_spdx_expression(expr: str) -> None:
    """Validate that expr is a syntax-valid SPDX expression in NFC normalized form."""
    if not isinstance(expr, str):
        raise ContractError(
            "INVALID_TYPE",
            "License expression must be a string",
        )
    if unicodedata.normalize("NFC", expr) != expr:
        raise ContractError(
            "NON_NFC_LICENSE_EXPRESSION",
            "License expression must be in NFC normalized form",
        )
    trimmed = expr.strip()
    if not trimmed:
        raise ContractError(
            "INVALID_SPDX_EXPRESSION",
            "License expression must not be empty",
        )
    if len(expr) > 4096 or expr.count("(") > 32:
        raise ContractError("INVALID_SPDX_EXPRESSION", "License expression exceeds syntax limits")
    tokens = _tokenize(trimmed)
    parser = _Parser(tokens)
    parser.parse()
