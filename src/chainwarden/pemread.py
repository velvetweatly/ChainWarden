"""PEM reading: split a text buffer into labelled base64 blocks and decode.

A PEM block looks like:

    -----BEGIN CERTIFICATE-----
    <base64>
    -----END CERTIFICATE-----

We only decode CERTIFICATE blocks. Other labels (keys, CSRs) are skipped so a
bundle that mixes material does not crash the reader.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass

_BEGIN = "-----BEGIN "
_END = "-----END "
_SUFFIX = "-----"


class PEMError(ValueError):
    """Raised when a PEM block is malformed."""


@dataclass(frozen=True)
class PEMBlock:
    label: str
    der: bytes


def split_blocks(text: str) -> list[PEMBlock]:
    """Return every well formed PEM block in text, in file order.

    Lines outside BEGIN/END markers are ignored, which matches how real PEM
    bundles carry human readable headers between certificates.
    """
    blocks: list[PEMBlock] = []
    lines = text.splitlines()
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i].strip()
        if line.startswith(_BEGIN) and line.endswith(_SUFFIX):
            label = line[len(_BEGIN) : -len(_SUFFIX)]
            end_marker = f"{_END}{label}{_SUFFIX}"
            body: list[str] = []
            i += 1
            found_end = False
            while i < n:
                cur = lines[i].strip()
                if cur == end_marker:
                    found_end = True
                    i += 1
                    break
                body.append(cur)
                i += 1
            if not found_end:
                raise PEMError(f"unterminated PEM block for {label}")
            joined = "".join(body)
