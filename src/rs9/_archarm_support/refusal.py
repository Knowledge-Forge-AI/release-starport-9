"""Closed refusal type for the ArchARM SDK lease (namespace transform of ``Refusal``).

The qualified probes raise ``Refusal(<LABEL>)``. In RS9 every gate failure is a
``ContractError``; the transform is ``Refusal(L)`` -> ``SdkRefusal(L)`` whose
stable code is ``"ARCHARM_" + L``. Messages never echo inputs, paths or names.
"""
from __future__ import annotations

import re

from rs9.errors import ContractError

_LABEL_RE = re.compile(r"[A-Z][A-Z0-9_]{0,63}")


class SdkRefusal(ContractError):
    """A failed ArchARM SDK gate. ``label`` is the closed constant gate label."""

    def __init__(self, label: str) -> None:
        if not isinstance(label, str) or _LABEL_RE.fullmatch(label) is None:
            label = "UNCLASSIFIED"
        super().__init__("ARCHARM_" + label, "ArchARM SDK lease gate refused")
        self.label = label


def require(condition: object, label: str) -> None:
    if not condition:
        raise SdkRefusal(label)
